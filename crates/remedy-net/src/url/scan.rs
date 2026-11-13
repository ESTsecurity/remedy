//! URL 을 적은 차례대로 하나씩 — 중복은 한 번, 50개까지. URL 하나에 HEAD 한 번, 서버가 HEAD 를 받지
//! 않으면(405 · 501) GET 한 번. 헤더가 알리는 버전이 영향 버전이면 *취약*, 그 밖은 *확인 필요* 다.
//!
//! 서버가 429 · 5xx 를 주거나 시간이 다 되거나 연결을 끊으면 **그 서버에는 더 요청하지 않는다** — 스킴 ·
//! 포트가 달라도, 이름이 달라도 연결한 IP 가 같으면 같은 서버다([`super::stop`]).

use super::criteria::UrlCriteria;
use super::headers::{php_hints, php_version, values};
use super::input::Input;
use super::policy::{Cancel, Gate, Halt, MAX_URLS};
use super::report::{header_caveat, Finding, FindingKind, Requests, Statuses, Target, Verdict};
use super::stop::Stopped;
use super::wire::{Failure, Method, Transport};
use remedy_sdk::i18n::Lang;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub(crate) struct Scan<'a> {
    pub(crate) transport: &'a dyn Transport,
    pub(crate) gate: &'a dyn Gate,
    pub(crate) cancel: &'a Cancel,
    pub(crate) url_timeout: Duration,
    pub(crate) lang: Lang,
    /// 서명을 확인한 url 표(데이터 룰 `remedy-net-criteria`).
    pub(crate) criteria: &'a UrlCriteria,
}

impl Scan<'_> {
    /// 다 돌고 대상 목록을 준다. `done` 은 대상 하나를 마칠 때마다 불린다(화면이 진행을 보인다).
    pub(crate) fn run(&self, urls: &[String], done: &mut dyn FnMut(&Target)) -> Vec<Target> {
        let lang = self.lang;
        let mut seen = HashSet::new();
        let mut stopped = Stopped::default();
        let mut targets = Vec::new();
        let mut unique = 0usize;
        for raw in urls {
            let parsed = Input::parse(raw);
            let key = match &parsed {
                Ok(i) => i.key(),
                Err(_) => raw.clone(),
            };
            if !seen.insert(key.clone()) {
                continue;
            }
            unique += 1;
            if unique > MAX_URLS {
                continue;
            }
            let t = match parsed {
                Ok(input) => self.one(&input, &key, &mut stopped),
                Err(e) => {
                    // 명령줄은 요청 전에 거절한다 — 여기에 닿는 것은 라이브러리로 부른 경우뿐이다.
                    let name =
                        lang.pick(format!("입력 URL {unique}"), format!("input URL {unique}"));
                    let mut t = blank(id_for(&key), name, lang);
                    t.gaps.push(e.message(lang).to_string());
                    self.gate.record(&t);
                    t
                }
            };
            done(&t);
            targets.push(t);
        }
        if unique > MAX_URLS {
            let mut t = blank(
                "url:input-limit".to_string(),
                lang.t("URL 입력 제한", "URL input limit").to_string(),
                lang,
            );
            t.reason = lang
                .t(
                    "중복을 뺀 URL 이 50개를 넘었습니다.",
                    "More than 50 distinct URLs were given.",
                )
                .to_string();
            t.gaps.push(lang.pick(
                format!("넘친 {}개 URL 에는 요청하지 않았습니다.", unique - MAX_URLS),
                format!(
                    "No requests were sent to the {} URLs over the limit.",
                    unique - MAX_URLS
                ),
            ));
            self.gate.record(&t);
            done(&t);
            targets.push(t);
        }
        targets
    }

    fn one(&self, input: &Input, key: &str, stopped: &mut Stopped) -> Target {
        let lang = self.lang;
        let mut t = blank(id_for(key), input.display(lang), lang);
        let host = input.server_host();
        if let Some(reason) = stopped.reason(&host) {
            t.gaps.push(lang.pick(
                format!("앞서 요청을 중단한 서버와 호스트 이름 또는 확인된 IP 가 같아 점검하지 않았습니다: {reason}"),
                format!("Not checked: same host name or confirmed IP as a server already stopped: {reason}"),
            ));
            self.gate.record(&t);
            return t;
        }
        if self.cancel.is_set() {
            t.gaps.push(
                lang.t(
                    "점검을 취소했거나 실행 시한이 지나 요청하지 않았습니다.",
                    "Not requested: the run was cancelled or its time limit passed.",
                )
                .to_string(),
            );
            self.gate.record(&t);
            return t;
        }
        // 이 시한은 간격을 기다리는 시간 · 이름 풀이보다 먼저 시작한다.
        let deadline = Instant::now() + self.url_timeout;
        let mut addresses: Vec<String> = Vec::new();
        let mut method = Method::Head;
        for _ in 0..2 {
            if let Err(halt) = self.gate.before_request(deadline, self.cancel) {
                t.gaps.push(match halt {
                    // 취소는 요청 상한 탓이 아니다 — 사람이 멈췄거나(Ctrl+C) 실행 시한이 지났다. 상한의
                    // 말머리를 달면 *요청 제한으로 중단했습니다: 취소했습니다* 가 되어, 누른 사람이 도구가
                    // 무슨 한도에 걸린 것으로 읽는다(2026-11-10 메뉴에서 Ctrl+C 를 눌러 본 화면).
                    Halt::Cancelled => lang
                        .t(
                            "점검을 취소했거나 실행 시한이 지나 요청을 멈췄습니다.",
                            "Stopped: the run was cancelled or its time limit passed.",
                        )
                        .to_string(),
                    _ => lang.pick(
                        format!("요청 제한으로 중단했습니다: {}", halt.message(lang)),
                        format!("Stopped by the request limits: {}", halt.message(lang)),
                    ),
                });
                if halt.stops_server() {
                    stopped.stop(&host, closed_reason(lang));
                }
                break;
            }
            t.requests.set(method, 1);
            let result = {
                let mut connected = |ip: IpAddr| {
                    let ip = ip.to_string();
                    if !addresses.contains(&ip) {
                        addresses.push(ip.clone());
                    }
                    stopped.observe(&host, &ip).is_none()
                };
                self.transport
                    .exchange(method, input, deadline, self.cancel, &mut connected)
            };
            let head = match result {
                Ok(head) => head,
                Err(f) => {
                    t.gaps.push(lang.pick(
                        format!("{} 요청 실패: {}", method.as_str(), f.message(lang)),
                        format!("{} request failed: {}", method.as_str(), f.message(lang)),
                    ));
                    if f == Failure::Stopped {
                        // 맡은 요청 수는 그대로다 — 다만 이 시도는 HTTP 바이트를 보내기 전에 닫혔다.
                        t.requests.set(method, 0);
                    } else if f.stops_server() {
                        stopped.stop(&host, closed_reason(lang));
                    }
                    break;
                }
            };
            t.status.set(method, head.status);
            collect(&mut t, method, &head.headers, self.criteria, lang);
            // GET 이 막히거나 시간을 넘겨도 HEAD 에서 본 경고는 남는다.
            self.gate.record(&t);
            if should_stop(method, head.status) {
                stopped.stop(&host, &format!("HTTP {}", head.status));
                t.gaps.push(
                    lang.t(
                        "서버가 요청 제한 또는 오류 응답을 보내 이 서버로는 더 요청하지 않았습니다.",
                        "The server answered with a rate-limit or error status, so no more requests were sent to it.",
                    )
                    .to_string(),
                );
                break;
            }
            if method == Method::Head && matches!(head.status, 405 | 501) {
                method = Method::Get;
                continue;
            }
            if (300..=399).contains(&head.status) {
                t.gaps.push(
                    lang.t(
                        "리디렉션 응답을 받았습니다. 이동할 주소에는 접속하지 않았습니다.",
                        "Got a redirect. The new location was not visited.",
                    )
                    .to_string(),
                );
            }
            break;
        }
        t.addresses = addresses;
        t.gaps.push(header_caveat(lang).to_string());
        self.gate.record(&t);
        t
    }
}

/// 이 상태를 받으면 그 서버에 더 요청하지 않는다 — 429 와 5xx. HEAD 의 501 은 "HEAD 를 모른다" 라
/// GET 으로 넘어간다.
fn should_stop(method: Method, status: u16) -> bool {
    status == 429 || ((500..=599).contains(&status) && !(method == Method::Head && status == 501))
}

fn closed_reason(lang: Lang) -> &'static str {
    lang.t(
        "시간 제한 또는 연결 종료",
        "time limit or closed connection",
    )
}

pub(crate) fn id_for(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("url:{hex}")
}

/// 아무것도 보지 못한 대상 — 헤더만으로는 패치 여부를 가릴 수 없으니 출발점이 *확인 필요* 다.
pub(crate) fn blank(id: String, url: String, lang: Lang) -> Target {
    Target {
        id,
        url,
        verdict: Verdict::ReviewRequired,
        reason: review_reason(lang).to_string(),
        action: lang
            .t(
                "그 서버에서 remedy 의 PHP2Shell 점검으로 직접 확인하십시오.",
                "Check that server directly with remedy's PHP2Shell check.",
            )
            .to_string(),
        requests: Requests::default(),
        status: Statuses::default(),
        addresses: Vec::new(),
        php_presence: false,
        findings: Vec::new(),
        gaps: Vec::new(),
    }
}

fn review_reason(lang: Lang) -> &'static str {
    lang.t(
        "응답 헤더만으로는 보안 패치 적용 여부를 확인할 수 없습니다.",
        "Response headers alone cannot show whether the security patch is applied.",
    )
}

/// `Server` · `X-Powered-By` 한 줄마다 항목 하나. 영향 버전이면 그 항목과 대상이 *취약* 이 된다.
fn collect(
    t: &mut Target,
    method: Method,
    headers: &[(String, String)],
    criteria: &UrlCriteria,
    lang: Lang,
) {
    for name in ["Server", "X-Powered-By"] {
        for (index, value) in values(headers, name).enumerate() {
            let version = php_version(value);
            let mut f = Finding {
                id: format!(
                    "header:{}:{}:{index}",
                    method.as_str().to_ascii_lowercase(),
                    name.to_ascii_lowercase()
                ),
                kind: FindingKind::Header,
                method: method.as_str().to_string(),
                evidence: format!("{name}: {value}"),
                version,
                verdict: Verdict::ReviewRequired,
                reason: review_reason(lang).to_string(),
            };
            if f.version.as_deref().and_then(|v| criteria.below_fix(v)) == Some(true) {
                let why = lang.t(
                    "헤더 기준으로 PHP2Shell 영향 버전입니다. 실제 설치 버전과 백포트 패치 적용 여부는 확인하지 못했습니다.",
                    "By its header this is a PHP2Shell-affected version. The installed version and any backported patch were not confirmed.",
                );
                f.verdict = Verdict::Vulnerable;
                f.reason = why.to_string();
                t.verdict = Verdict::Vulnerable;
                t.reason = why.to_string();
                t.action = lang
                    .t(
                        "그 서버에서 remedy 의 PHP2Shell 점검으로 직접 확인한 뒤, 패치가 빠졌으면 공급사 보안 패치를 적용하십시오.",
                        "Check that server directly with remedy's PHP2Shell check, and apply the vendor's security patch if it is missing.",
                    )
                    .to_string();
            }
            t.findings.push(f);
        }
    }
    if t.php_presence {
        return;
    }
    let hints = php_hints(headers, lang);
    if hints.is_empty() {
        return;
    }
    t.php_presence = true;
    t.findings.push(Finding {
        id: "php-presence".to_string(),
        kind: FindingKind::PhpPresence,
        method: method.as_str().to_string(),
        evidence: lang.pick(
            format!("PHP 추정 근거: {}", hints.join(", ")),
            format!("signs of PHP: {}", hints.join(", ")),
        ),
        version: None,
        verdict: Verdict::ReviewRequired,
        reason: lang
            .t(
                "응답 헤더에 PHP · PHP 프레임워크의 단서가 있어 PHP 를 쓰는 것으로 짐작됩니다. 버전과 패치 상태는 알 수 없습니다.",
                "Signs of PHP or a PHP framework in the response headers suggest PHP is in use. Its version and patch state are unknown.",
            )
            .to_string(),
    });
}
