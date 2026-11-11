//! `remedy-net url` — 웹서버가 응답 헤더로 알리는 PHP 버전을 PHP2Shell 수정 버전과 견준다.
//!
//! 사내 runtime-scanner 의 `url` 을 옮겼다(동작 · 상한 · 시험). 헤더는 남이 적은 글자라 **양호를 내지
//! 않는다** — 영향 버전이면 *취약*(2), 그 밖은 *확인 필요*(6)다. 확인은 그 서버에서 remedy 의 점검 룰로 한다.
//!
//! 차례: 명령줄 검사 → CA 파일 → 약관 → (`--ask` 면 주소 묻기) → 결과 폴더 → 점검(따로 도는 스레드) →
//! 화면 · 결과 파일. 앞 단계에서 멈추면 요청도 결과 폴더도 없다.
//!
//! 본체(`remedy`)의 메뉴는 이 명령을 `--ask` 로 띄운다 — 주소를 묻는 것부터 결과까지 이 프로그램이 하고,
//! 본체는 종료 코드만 받는다(설계-04 §1 *동반 모듈*).

mod args;
mod ask;
mod consent;
mod criteria;
mod headers;
mod input;
mod policy;
pub mod report;
mod scan;
mod stop;
mod trust;
mod wire;

#[cfg(test)]
mod tests;

use crate::output::{fail, prepare_dir, run_id};
use crate::text::ascii_safe;
use crate::{clock, Outcome};
use policy::{Budget, Cancel, SLICE, URL_TIMEOUT};
use remedy_sdk::i18n::Lang;
use report::{Report, Target, Verdict};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime};

/// 취소 · 실행 시한 뒤 점검 스레드를 기다리는 시간 — 넘으면 남긴 부분 결과로 보고한다.
const GRACE: Duration = Duration::from_millis(500);

pub fn run(args: &[String], lang: Lang) -> Outcome {
    let opts = match args::parse(args, lang) {
        Ok(args::Parsed::Help) => {
            print!("{}", ascii_safe(help(lang)));
            return Outcome::Clear;
        }
        Ok(args::Parsed::Run(o)) => o,
        Err(why) => {
            eprintln!(
                "{}",
                ascii_safe(lang.pick(
                    format!("입력 오류: {why}\n쓰는 법은 'remedy-net url --help' 로 보십시오."),
                    format!("input error: {why}\nsee 'remedy-net url --help'."),
                ))
            );
            return Outcome::BadInput;
        }
    };
    let extra = match opts.cacert.as_deref() {
        Some(p) => match trust::load_ca(Path::new(p)) {
            Ok(c) => c,
            Err(e) => return fail(lang, e.message(lang)),
        },
        None => Vec::new(),
    };
    let tls = match trust::client_config(&extra) {
        Ok(c) => c,
        Err(e) => return fail(lang, e.message(lang)),
    };
    let via = {
        let stdin = std::io::stdin();
        let mut out = std::io::stdout();
        consent::ask(opts.consent, lang, &mut stdin.lock(), &mut out)
    };
    let Some(via) = via else {
        println!("{}", lang.t("점검을 취소했습니다.", "Check cancelled."));
        return Outcome::BadInput;
    };
    let accepted_at = SystemTime::now();
    // 약관에 동의한 뒤에 묻는다 — 거절할 사람에게 주소부터 적게 하지 않는다.
    let urls = if opts.ask {
        let stdin = std::io::stdin();
        let mut out = std::io::stdout();
        let typed = ask::urls(lang, &mut stdin.lock(), &mut out);
        if typed.is_empty() {
            println!(
                "{}",
                lang.t(
                    "점검할 주소를 받지 못해 아무것도 점검하지 않았습니다.",
                    "No address was given, so nothing was checked."
                )
            );
            return Outcome::BadInput;
        }
        typed
    } else {
        opts.urls
    };
    let dir = match prepare_dir(Path::new(&opts.out_dir), lang) {
        Ok(d) => d,
        Err(why) => return fail(lang, why),
    };
    let cancel = Cancel::default();
    {
        let c = cancel.clone();
        let _ = ctrlc::set_handler(move || c.set());
    }
    let net = Arc::new(wire::Net::new(tls));
    let ctx = Run {
        urls,
        cacert: !extra.is_empty(),
        via,
        accepted_at,
        dir,
        lang,
    };
    ctx.execute(net, cancel)
}

/// 약관을 지난 한 번의 실행.
struct Run {
    urls: Vec<String>,
    cacert: bool,
    via: consent::Via,
    accepted_at: SystemTime,
    dir: PathBuf,
    lang: Lang,
}

enum Msg {
    Done(Target),
    Finished(Vec<Target>),
}

impl Run {
    fn execute(self, net: Arc<wire::Net>, cancel: Cancel) -> Outcome {
        let lang = self.lang;
        let started = SystemTime::now();
        let budget = Arc::new(Budget::new(Instant::now(), lang));
        let total = unique(&self.urls);
        println!(
            "{}",
            ascii_safe(lang.pick(
                format!("점검 시작: URL {total}개 — 요청은 2초 간격, URL 하나에 10초까지 기다립니다."),
                format!("Checking {total} URL(s) — requests are 2 seconds apart, up to 10 seconds per URL."),
            ))
        );
        let (tx, rx) = mpsc::channel::<Msg>();
        {
            let (net, budget, cancel, urls) = (
                Arc::clone(&net),
                Arc::clone(&budget),
                cancel.clone(),
                self.urls.clone(),
            );
            std::thread::spawn(move || {
                let scan = scan::Scan {
                    transport: &*net,
                    gate: &*budget,
                    cancel: &cancel,
                    url_timeout: URL_TIMEOUT,
                    lang,
                };
                let all = scan.run(&urls, &mut |t| {
                    let _ = tx.send(Msg::Done(t.clone()));
                });
                let _ = tx.send(Msg::Finished(all));
            });
        }
        let mut shown: Vec<Target> = Vec::new();
        let mut finished = None;
        let mut interrupted: Option<&'static str> = None;
        let mut grace: Option<Instant> = None;
        loop {
            match rx.recv_timeout(SLICE) {
                Ok(Msg::Done(t)) => {
                    print!(
                        "{}",
                        ascii_safe(report::render(&t, shown.len() + 1, total, lang))
                    );
                    shown.push(t);
                }
                Ok(Msg::Finished(all)) => {
                    finished = Some(all);
                    break;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if interrupted.is_none() {
                interrupted = stop_reason(&cancel, budget.run_deadline(), lang);
                if interrupted.is_some() {
                    grace = Some(Instant::now() + GRACE);
                }
            }
            if grace.is_some_and(|g| Instant::now() >= g) {
                break;
            }
        }
        // 점검 스레드가 취소 뒤 유예보다 먼저 끝나 위 줄에 닿지 못했어도, 멈춘 실행은 멈췄다고 적는다.
        if interrupted.is_none() {
            interrupted = stop_reason(&cancel, budget.run_deadline(), lang);
        }
        let targets = match (finished, interrupted) {
            (Some(all), _) => all,
            (None, None) => {
                return fail(
                    lang,
                    lang.t(
                        "점검이 끝나기 전에 멈췄습니다.",
                        "the check stopped before it finished.",
                    ),
                )
            }
            (None, Some(why)) => {
                let mut ts = shown;
                // 막힌 요청을 기다리지 않는다 — 그 대상은 마지막으로 남긴 모양으로 싣는다.
                for mut p in budget.partial() {
                    if ts.iter().any(|t| t.id == p.id) {
                        continue;
                    }
                    p.gaps.push(why.to_string());
                    print!(
                        "{}",
                        ascii_safe(report::render(&p, ts.len() + 1, total, lang))
                    );
                    ts.push(p);
                }
                let mut pending = scan::blank(
                    "url:interrupted".to_string(),
                    lang.t("점검을 마치지 못한 범위", "unfinished scope")
                        .to_string(),
                    lang,
                );
                pending.reason = why.to_string();
                pending.gaps.push(why.to_string());
                pending.action = lang
                    .t(
                        "중단한 까닭을 확인한 뒤 같은 URL 로 다시 점검하십시오.",
                        "Check why it stopped, then run the same URLs again.",
                    )
                    .to_string();
                ts.push(pending);
                ts
            }
        };
        self.finish(targets, interrupted.is_some(), started, &budget)
    }

    fn finish(
        &self,
        targets: Vec<Target>,
        interrupted: bool,
        started: SystemTime,
        budget: &Budget,
    ) -> Outcome {
        let lang = self.lang;
        let verdict = if targets.iter().any(|t| t.verdict == Verdict::Vulnerable) {
            Verdict::Vulnerable
        } else {
            Verdict::ReviewRequired
        };
        let outcome = match verdict {
            Verdict::Vulnerable => Outcome::Vulnerable,
            Verdict::ReviewRequired => Outcome::Review,
        };
        let finished = SystemTime::now();
        let report = Report {
            schema_version: report::SCHEMA_VERSION,
            tool: report::Tool {
                name: "remedy-net".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            command: "url".to_string(),
            run_id: run_id(started),
            language: lang.id().to_string(),
            started_at: clock::rfc3339(started),
            finished_at: clock::rfc3339(finished),
            consent: report::Consent {
                terms_version: consent::TERMS_VERSION.to_string(),
                accepted_at: clock::rfc3339(self.accepted_at),
                via: self.via.as_str().to_string(),
            },
            criteria: report::Criteria {
                name: "PHP2Shell".to_string(),
                cves: criteria::CVES.iter().map(|s| s.to_string()).collect(),
                checked: criteria::CHECKED.to_string(),
                same_as: criteria::SAME_AS.to_string(),
                sources: criteria::SOURCES.iter().map(|s| s.to_string()).collect(),
            },
            verdict,
            exit_code: outcome.exit().code(),
            interrupted,
            targets,
            usage: report::Usage {
                http_requests: budget.requests(),
                stops: budget.stops(),
            },
            limitations: limitations(self.cacert, lang),
        };
        println!();
        println!("{}", ascii_safe(report::header_caveat(lang).to_string()));
        println!(
            "{}",
            ascii_safe(
                lang.t(
                    "URL 점검은 '양호' 를 내지 않습니다 — 그 서버에서 remedy 의 PHP2Shell · PHP 세션 점검으로 확인하십시오.",
                    "URL checks never say \"clear\" — confirm on that server with remedy's PHP2Shell and PHP session checks.",
                )
                .to_string()
            )
        );
        println!(
            "{}",
            ascii_safe(remedy_report::result_line_for(
                outcome.exit(),
                0,
                lang,
                Some(remedy_sdk::manifest::PluginKind::Check),
                !interrupted,
            ))
        );
        match report::save(&self.dir, &report) {
            Ok(path) => {
                println!("{}: {}", lang.t("결과 파일", "Report"), path.display());
                outcome
            }
            Err(_) => fail(
                lang,
                lang.t(
                    "결과 파일을 쓰지 못했습니다.",
                    "could not write the report file.",
                ),
            ),
        }
    }
}

/// 멈춘 까닭 — 사용자의 취소(Ctrl+C) 또는 실행 시한. 시한이면 취소를 켜 점검 스레드도 멈추게 한다.
fn stop_reason(cancel: &Cancel, run_deadline: Instant, lang: Lang) -> Option<&'static str> {
    if cancel.is_set() {
        return Some(lang.t(
            "사용자가 취소해 점검을 멈췄습니다.",
            "Stopped: cancelled by the user.",
        ));
    }
    if Instant::now() >= run_deadline {
        cancel.set();
        return Some(lang.t(
            "실행 전체 10분 제한이 지나 점검을 멈췄습니다.",
            "Stopped: the 10-minute limit for the run passed.",
        ));
    }
    None
}

/// 중복을 뺀 URL 수(50개까지) — 화면의 `[i/n]`.
fn unique(urls: &[String]) -> usize {
    let mut seen = std::collections::HashSet::new();
    for raw in urls {
        let key = input::Input::parse(raw)
            .map(|i| i.key())
            .unwrap_or_else(|_| raw.clone());
        seen.insert(key);
    }
    seen.len().min(policy::MAX_URLS) + usize::from(seen.len() > policy::MAX_URLS)
}

fn limitations(cacert: bool, lang: Lang) -> Vec<String> {
    let mut v = vec![
        lang.t(
            "URL 의 취약 판정은 응답 헤더가 알리는 버전에 따른 경고입니다. 실제 설치 버전과 백포트 패치 적용 여부는 그 서버에서 직접 확인해야 하며, URL 만으로 양호를 판정하지 않습니다.",
            "A vulnerable verdict for a URL is a warning from the version the headers announce. The installed version and any backported patch must be confirmed on that server; a URL alone never yields clear.",
        ),
        lang.t(
            "CVE-2026-115560(PHP 세션 설정)은 URL 로 점검하지 않습니다. 그 서버에서 remedy 의 PHP 세션 점검으로 보십시오.",
            "CVE-2026-115560 (PHP session settings) is not checked from a URL. Use remedy's PHP session check on that server.",
        ),
        lang.t(
            "일반적인 HTTP 요청으로도 서버의 처리와 접속 기록이 생길 수 있습니다.",
            "Even ordinary HTTP requests are processed and logged by the server.",
        ),
    ];
    if cacert {
        v.push(lang.t(
            "지정한 CA 인증서 파일을 이 실행에만 추가로 신뢰했습니다. 올바른 사설 CA 인지는 사용자가 확인해야 합니다.",
            "The given CA certificate file was trusted in addition, for this run only. Whether it is the right private CA is for the user to confirm.",
        ));
    }
    v.into_iter().map(str::to_string).collect()
}

/// `remedy-net url --help`. 명령 설명은 본체의 도움말처럼 해라체다.
pub fn help(lang: Lang) -> String {
    let rule = criteria::SAME_AS;
    let checked = criteria::CHECKED;
    lang.pick(
        format!(
            "쓰는 법: remedy-net url URL [URL ...] [옵션]\n\n\
             웹서버가 응답 헤더(Server · X-Powered-By)로 알리는 PHP 버전을 PHP2Shell(CVE-2026-109618 ·\n\
             109619) 수정 버전과 견준다. 헤더만 읽으므로 '양호' 는 내지 않는다 — 취약(2) 또는 확인 필요(6).\n\n\
             옵션:\n\
             \x20 --url URL          점검할 URL. 자리 인자와 함께 모두 50개까지\n\
             \x20 --ask              점검할 URL 을 명령줄 대신 물어서 받는다 (remedy 의 메뉴가 이렇게 띄운다)\n\
             \x20 --cacert 파일     이 실행에만 더 믿을 CA 인증서(PEM). 기본 신뢰 목록은 그대로이고 검증을 끄지 않는다\n\
             \x20 --consent y|n      약관에 미리 답한다(무인 실행). 빼면 묻는다\n\
             \x20 --out-dir 폴더     결과 JSON 을 쓸 폴더 (기본: results)\n\n\
             지키는 것: 직렬 · 요청 사이 2초 · URL 하나에 HEAD 한 번(405 · 501 이면 GET 한 번) · 실행 전체 100회 ·\n\
             URL 하나에 10초 · 응답 헤더 32 KiB. 리다이렉트를 따르지 않고 프록시 · 쿠키 · 인증을 쓰지 않으며\n\
             본문을 읽지 않는다.\n\
             기준: {rule} 와 같은 수정 버전 ({checked} 확인).\n"
        ),
        format!(
            "Usage: remedy-net url URL [URL ...] [options]\n\n\
             Compares the PHP version a web server announces in its response headers (Server ·\n\
             X-Powered-By) with the PHP2Shell (CVE-2026-109618 · 109619) fixed versions. Only headers are\n\
             read, so the result is never \"clear\" — vulnerable (2) or needs review (6).\n\n\
             Options:\n\
             \x20 --url URL          a URL to check; up to 50 together with positional URLs\n\
             \x20 --ask              ask for the URLs instead of taking them from the command line (how remedy's menu starts it)\n\
             \x20 --cacert FILE     a CA certificate (PEM) to trust for this run only; the default trust list stays and verification is never turned off\n\
             \x20 --consent y|n      answer the terms in advance (unattended runs); asked if omitted\n\
             \x20 --out-dir DIR      folder for the JSON result (default: results)\n\n\
             Limits: serial · 2 seconds between requests · one HEAD per URL (one GET on 405 · 501) · 100 requests\n\
             per run · 10 seconds per URL · 32 KiB of response headers. Redirects are not followed; no proxy,\n\
             cookies or authentication; bodies are not read.\n\
             Criteria: the fixed versions of {rule} (checked {checked}).\n"
        ),
    )
}
