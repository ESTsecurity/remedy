//! 스캐너의 모의 서버 시나리오 69건(`scripts/test-local.ps1` · 지우기 직전 판)을 실제 바이너리로 돈다.
//!
//! 시나리오마다 모의 서버를 127.0.0.1 에 새로 열고 `remedy-net url` 을 띄워 — 종료 코드 · 약관과 질문의
//! 횟수 · **서버가 받은 요청의 차례 · 수 · 간격** · 결과 파일 · 화면을 스캐너 스크립트와 같은 조건으로 본다.
//!
//! 스캐너와 다른 것(결정 6 · 범위 밖): 종료 코드는 remedy 표(취약 10→2 · 확인 필요 20→6 · 입력 오류와 동의
//! 안 함 2→4) · HTML 보고서는 없다(그 단언은 옮기지 않는다) · 결과 폴더 옵션은 `--out-dir` · 언어는 한국어,
//! 기호는 UTF-8 로 고정한다(`REMEDY_LANG=ko` · `REMEDY_ASCII=0` — 기계의 로케일에 기대지 않게).

#[path = "support/mock.rs"]
mod mock;

use mock::{Event, Mock, SENSITIVE};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const PROMPT: &str = "점검 권한이 있고 위 내용에 동의하십니까? [y/n]: ";
const TERMS_HEADER: &str = "이용 조건";
/// 스캐너 스크립트의 `$phpVulnerableFixtureVersions` — 이 버전을 알린 헤더 항목만 취약이다.
const VULNERABLE: [&str; 7] = [
    "8.3.6",
    "8.2.1",
    "5.4.0",
    "5.6.40",
    "7.4.33",
    "8.1.34",
    "7.4.3-4ubuntu2.29+esm4",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    Yes,
    No,
    Eof,
}

/// 시나리오 하나 — 필드 이름은 스캐너 스크립트의 키를 따랐다.
struct Case {
    urls: Vec<String>,
    args: Option<Vec<String>>,
    requests: Vec<(&'static str, &'static str)>,
    statuses: Vec<u16>,
    responses: Option<Vec<u16>>,
    request_base: Option<SocketAddr>,
    versions: Vec<&'static str>,
    exit: i32,
    reply: Reply,
    consent_flag: Option<&'static str>,
    no_prompt: bool,
    stop: bool,
    timeout: bool,
    header_rejected: bool,
    tls_rejected: bool,
    malformed: bool,
    query: bool,
    proxy: bool,
    hidden: bool,
    fingerprint: Option<&'static str>,
    no_fingerprint: bool,
    cacert: Option<PathBuf>,
    request_budget: Option<u64>,
    positional: bool,
    late_option: bool,
    output: Option<String>,
}

impl Case {
    fn new(urls: Vec<String>) -> Case {
        Case {
            urls,
            args: None,
            requests: Vec::new(),
            statuses: Vec::new(),
            responses: None,
            request_base: None,
            versions: Vec::new(),
            exit: 6,
            reply: Reply::Yes,
            consent_flag: None,
            no_prompt: false,
            stop: false,
            timeout: false,
            header_rejected: false,
            tls_rejected: false,
            malformed: false,
            query: false,
            proxy: false,
            hidden: false,
            fingerprint: None,
            no_fingerprint: false,
            cacert: None,
            request_budget: None,
            positional: false,
            late_option: false,
            output: None,
        }
    }
    fn args(args: &[&str]) -> Case {
        let mut c = Case::new(Vec::new());
        c.args = Some(args.iter().map(|s| s.to_string()).collect());
        c.no_prompt = true;
        c
    }
    fn req(mut self, r: &[(&'static str, &'static str, u16)]) -> Case {
        self.requests = r.iter().map(|(m, p, _)| (*m, *p)).collect();
        self.statuses = r.iter().map(|(_, _, s)| *s).collect();
        self
    }
    fn responses(mut self, r: &[u16]) -> Case {
        self.responses = Some(r.to_vec());
        self
    }
    fn version(mut self, v: &'static str) -> Case {
        self.versions.push(v);
        self
    }
    fn exit(mut self, code: i32) -> Case {
        self.exit = code;
        self
    }
    fn vulnerable(self) -> Case {
        self.exit(2)
    }
    fn reply(mut self, r: Reply) -> Case {
        self.reply = r;
        self
    }
    fn flag(mut self, v: &'static str) -> Case {
        self.consent_flag = Some(v);
        self
    }
    fn no_prompt(mut self) -> Case {
        self.no_prompt = true;
        self
    }
    fn stop(mut self) -> Case {
        self.stop = true;
        self
    }
    fn timeout(mut self) -> Case {
        self.timeout = true;
        self
    }
    fn tls_rejected(mut self) -> Case {
        self.tls_rejected = true;
        self.request_budget = Some(1);
        self.responses = Some(Vec::new());
        self
    }
    fn cacert(mut self, p: PathBuf) -> Case {
        self.cacert = Some(p);
        self
    }
    fn base(mut self, a: SocketAddr) -> Case {
        self.request_base = Some(a);
        self
    }
    fn fingerprint(mut self, f: &'static str) -> Case {
        self.fingerprint = Some(f);
        self
    }
}

fn url(a: SocketAddr, path: &str) -> String {
    format!("http://{a}{path}")
}

fn tls_url(a: SocketAddr, path: &str) -> String {
    format!("https://{a}{path}")
}

/// 시나리오 하나의 작업 폴더 — 끝나면 지운다.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        Scratch(std::env::temp_dir().join(format!(
            "remedy-net-e2e-{}-{name}-{n}-{nanos}",
            std::process::id()
        )))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_case(m: &Mock, case: Case, name: &str) {
    let before = m.events().len();
    let out_dir = m.dir.join(name).join("reports");
    let mut args: Vec<String> = Vec::new();
    let has_flag = case.consent_flag.is_some();
    match &case.args {
        Some(a) => args.extend(a.iter().cloned()),
        None => {
            args.push("url".into());
            if !case.positional {
                for u in &case.urls {
                    args.push("--url".into());
                    args.push(u.clone());
                }
            }
            if let Some(ca) = &case.cacert {
                args.push("--cacert".into());
                args.push(ca.display().to_string());
            }
            if let Some(v) = case.consent_flag {
                args.push("--consent".into());
                args.push(v.into());
            }
            if !case.late_option {
                args.push("--out-dir".into());
                args.push(
                    case.output
                        .clone()
                        .unwrap_or_else(|| out_dir.display().to_string()),
                );
            }
            if case.positional {
                args.extend(case.urls.iter().cloned());
            }
            if case.late_option {
                args.push("--out-dir".into());
                args.push(out_dir.display().to_string());
            }
        }
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_remedy-net"));
    cmd.args(&args)
        .env("REMEDY_LANG", "ko")
        .env("REMEDY_ASCII", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if case.proxy {
        // 루프백으로 가는 요청도 프록시로 돌리라는 환경 — remedy-net 은 이것을 읽지 않는다.
        let proxy = format!("http://{}", m.second);
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
        ] {
            cmd.env(name, &proxy);
        }
        cmd.env("NO_PROXY", "").env("no_proxy", "");
    }
    let mut child = cmd.spawn().expect("remedy-net 을 띄우지 못했다");
    let mut stdin = child.stdin.take();
    if !case.no_prompt && !has_flag && case.reply != Reply::Eof {
        let answer = if case.reply == Reply::Yes {
            "y\n"
        } else {
            "n\n"
        };
        let _ = stdin.as_mut().unwrap().write_all(answer.as_bytes());
    }
    if !has_flag {
        // 미리 답했으면 입력을 열어 둔다 — 답을 기다리며 멈추지 않는지 본다.
        drop(stdin.take());
    }
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let err_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > Duration::from_secs(25) {
            let _ = child.kill();
            panic!("{name}: 25초 안에 끝나지 않았다");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(stdin);
    let stdout = out_reader.join().unwrap();
    let stderr = err_reader.join().unwrap();
    let ctx = format!("{name}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");
    assert_eq!(status.code(), Some(case.exit), "종료 코드: {ctx}");

    let prompts = stdout.matches(PROMPT).count();
    let terms = stdout.lines().filter(|l| *l == TERMS_HEADER).count();
    let want_prompts = usize::from(!(case.no_prompt || has_flag));
    let want_terms = usize::from(!case.no_prompt);
    assert_eq!(
        (prompts, terms),
        (want_prompts, want_terms),
        "질문 · 약관 횟수: {ctx}"
    );
    if want_prompts == 1 {
        assert!(
            stdout.find(TERMS_HEADER) < stdout.find(PROMPT),
            "약관보다 질문이 먼저: {ctx}"
        );
    }
    let markers: Vec<&str> = stdout
        .lines()
        .filter(|l| l.starts_with("약관 동의: --consent "))
        .collect();
    if has_flag && !case.no_prompt {
        let want = format!("약관 동의: --consent {}", case.consent_flag.unwrap());
        assert_eq!(markers, vec![want.as_str()], "동의 표식: {ctx}");
        assert!(
            stdout.find(TERMS_HEADER) < stdout.find(&want),
            "약관보다 표식이 먼저: {ctx}"
        );
    } else {
        assert!(markers.is_empty(), "옵션 없이 동의 표식: {ctx}");
    }
    if case.args.is_some() {
        assert!(
            !stdout.contains("약관") && !stdout.contains(TERMS_HEADER),
            "도움말에 약관: {ctx}"
        );
    }
    for s in SENSITIVE {
        assert!(
            !stdout.contains(s) && !stderr.contains(s),
            "화면에 {s}: {ctx}"
        );
    }

    let events: Vec<Event> = m.events().into_iter().skip(before).collect();
    let sequence: Vec<(String, String)> = events
        .iter()
        .map(|e| (e.method.clone(), e.path.clone()))
        .collect();
    let want_seq: Vec<(String, String)> = case
        .requests
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    assert_eq!(sequence, want_seq, "요청 차례: {ctx}");
    let authority = case.request_base.unwrap_or(m.base);
    let keys: Vec<String> = events
        .iter()
        .map(|e| {
            format!(
                "{} {}{} {} @{}",
                e.method, e.host, e.path, e.status, e.local
            )
        })
        .collect();
    let want_keys: Vec<String> = case
        .requests
        .iter()
        .zip(&case.statuses)
        .map(|((method, path), st)| format!("{method} {authority}{path} {st} @{authority}"))
        .collect();
    assert_eq!(keys, want_keys, "요청 주소 · 받은 자리 · 응답 코드: {ctx}");
    for e in &events {
        assert!(
            !e.cookie && !e.authorization && !e.proxy_authorization && e.content_length == 0,
            "보내지 않을 요청 정보: {ctx}"
        );
    }
    for w in events.windows(2) {
        let gap = w[1].at.duration_since(w[0].at);
        assert!(
            gap >= Duration::from_millis(1900),
            "요청 간격 {gap:?}: {ctx}"
        );
    }

    if matches!(case.exit, 2 | 6) {
        check_report(&case, &out_dir, &events, &stdout, &ctx);
    } else {
        assert!(
            !out_dir.exists(),
            "점검하지 않은 실행이 결과 폴더를 만들었다: {ctx}"
        );
    }
}

fn check_report(case: &Case, out_dir: &Path, events: &[Event], stdout: &str, ctx: &str) {
    let files: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .unwrap_or_else(|e| panic!("결과 폴더 {}: {e}\n{ctx}", out_dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    let json: Vec<&PathBuf> = files
        .iter()
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    assert_eq!(json.len(), 1, "결과 파일 수: {ctx}");
    let text = std::fs::read_to_string(json[0]).unwrap();
    let r: Value = serde_json::from_str(&text).unwrap();
    let vulnerable = case.exit == 2;
    let want = if vulnerable {
        "vulnerable"
    } else {
        "review_required"
    };
    assert_eq!(r["schema_version"], 1, "{ctx}");
    assert_eq!(r["tool"]["version"], env!("CARGO_PKG_VERSION"), "{ctx}");
    assert_eq!(r["verdict"], want, "전체 판정: {ctx}");
    assert_eq!(r["exit_code"], case.exit, "{ctx}");
    let limits = r["limitations"].to_string();
    if case.cacert.is_some() {
        assert!(
            limits.contains("이 실행에만 추가로 신뢰"),
            "사설 CA 의 범위 안내: {ctx}"
        );
    }
    let targets = r["targets"].as_array().unwrap();
    let unique: std::collections::HashSet<&String> = case.urls.iter().collect();
    assert_eq!(targets.len(), unique.len(), "대상 수: {ctx}");
    for t in targets {
        let mut target_want = "review_required";
        for f in t["findings"].as_array().unwrap() {
            let Some(v) = f["version"].as_str() else {
                continue;
            };
            let finding_want = if VULNERABLE.contains(&v) {
                "vulnerable"
            } else {
                "review_required"
            };
            assert_eq!(f["verdict"], finding_want, "{v} 의 판정: {ctx}");
            if finding_want == "vulnerable" {
                target_want = "vulnerable";
                let reason = f["reason"].as_str().unwrap();
                assert!(
                    reason.contains("헤더 기준")
                        && reason.contains("백포트")
                        && reason.contains("확인하지 못"),
                    "헤더 경고의 한계 안내: {ctx}"
                );
            }
        }
        assert_eq!(t["verdict"], target_want, "대상 판정: {ctx}");
        if target_want == "vulnerable" {
            assert!(t["reason"].as_str().unwrap().contains("헤더 기준"), "{ctx}");
        }
    }
    let line = if vulnerable {
        "취약합니다. 위에 적은 항목을 확인하십시오."
    } else {
        "확인이 필요합니다."
    };
    assert!(stdout.contains(line), "화면의 결과 줄: {ctx}");
    let budget = case.request_budget.unwrap_or(events.len() as u64);
    assert_eq!(r["usage"]["http_requests"], budget, "맡은 요청 수: {ctx}");
    let mut answered = Vec::new();
    for t in targets {
        for m in ["head", "get"] {
            if let Some(code) = t["status"][m].as_u64() {
                answered.push(code as u16);
            }
        }
    }
    let want_answers = case
        .responses
        .clone()
        .unwrap_or_else(|| case.statuses.clone());
    assert_eq!(answered, want_answers, "받은 응답 코드: {ctx}");
    let versions: Vec<&str> = targets
        .iter()
        .flat_map(|t| t["findings"].as_array().unwrap())
        .filter_map(|f| f["version"].as_str())
        .collect();
    for v in &case.versions {
        assert!(versions.contains(v), "{v} 를 읽지 못했다: {ctx}");
    }
    if case.hidden {
        assert!(versions.is_empty(), "없는 버전을 적었다: {ctx}");
    }
    if let Some(fp) = case.fingerprint {
        let found = targets
            .iter()
            .flat_map(|t| t["findings"].as_array().unwrap())
            .any(|f| f["kind"] == "php_presence" && f["evidence"].as_str().unwrap().contains(fp));
        assert!(
            found && versions.is_empty(),
            "흔적은 버전 없이 짐작으로만: {ctx}"
        );
    }
    if case.no_fingerprint {
        let any = targets
            .iter()
            .flat_map(|t| t["findings"].as_array().unwrap())
            .any(|f| f["kind"] == "php_presence" || f["version"].is_string());
        assert!(
            !any && targets[0]["php_presence"] == false,
            "흔한 CSRF 쿠키를 PHP 근거로: {ctx}"
        );
    }
    if case.stop {
        assert_eq!(targets.len(), 2, "{ctx}");
        assert_eq!(targets[1]["requests"]["head"], 0, "{ctx}");
        assert_eq!(targets[1]["requests"]["get"], 0, "{ctx}");
        assert!(
            !targets[1]["gaps"].as_array().unwrap().is_empty(),
            "건너뛴 까닭: {ctx}"
        );
    }
    let gaps0 = targets[0]["gaps"].to_string();
    if case.header_rejected {
        assert!(
            gaps0.contains("response headers exceeded 32768 bytes"),
            "{ctx}"
        );
    }
    if case.tls_rejected {
        assert!(gaps0.contains("certificate"), "TLS 거절 근거: {ctx}");
    }
    if case.malformed {
        assert!(gaps0.contains("HTTP 응답 형식"), "{ctx}");
    }
    if case.query {
        assert!(events[0].query_seen, "쿼리가 요청에 가지 않았다: {ctx}");
    }
    if case.timeout {
        let took = seconds(&r["finished_at"]) - seconds(&r["started_at"]);
        assert!((9.0..=12.0).contains(&took), "URL 시한 {took}초: {ctx}");
    }
    for f in &files {
        let body = std::fs::read_to_string(f).unwrap();
        for s in SENSITIVE {
            assert!(!body.contains(s), "결과 파일에 {s}: {ctx}");
        }
    }
}

/// `2026-11-10T03:10:00.123Z` → 1970 부터의 초.
fn seconds(v: &Value) -> f64 {
    let s = v.as_str().unwrap();
    let n = |a: usize, b: usize| s[a..b].parse::<i64>().unwrap();
    let (y, mo, d) = (n(0, 4), n(5, 7), n(8, 10));
    let (h, mi) = (n(11, 13), n(14, 16));
    let sec: f64 = s[17..s.len() - 1].parse().unwrap();
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (days * 86_400 + h * 3600 + mi * 60) as f64 + sec
}

macro_rules! scenario {
    ($name:ident, $label:literal, |$m:ident| $build:expr) => {
        #[doc = $label]
        #[test]
        fn $name() {
            let scratch = Scratch::new(stringify!($name));
            let $m = Mock::start(&scratch.0);
            let case: Case = $build;
            run_case(&$m, case, stringify!($name));
        }
    };
}

// ── 첫 묶음 (44) ───────────────────────────────────────────────────────────

scenario!(old_header, "구버전 헤더", |m| Case::new(vec![url(
    m.base,
    "/vulnerable"
)])
.req(&[("HEAD", "/vulnerable", 200)])
.version("8.3.6")
.vulnerable());
scenario!(fixed_header, "수정 버전 헤더", |m| Case::new(vec![
    url(m.base, "/fixed")
])
.req(&[("HEAD", "/fixed", 200)])
.version("8.3.36"));
scenario!(
    custom_version,
    "사용자 빌드 버전도 확인 필요",
    |m| Case::new(vec![url(m.base, "/custom-version")])
        .req(&[("HEAD", "/custom-version", 200)])
        .version("8.3.36-custom")
);
scenario!(
    multiple_headers,
    "서로 다른 헤더 버전 수집",
    |m| Case::new(vec![url(m.base, "/multiple-headers")])
        .req(&[("HEAD", "/multiple-headers", 200)])
        .version("8.2.1")
        .version("8.3.36")
        .vulnerable()
);
scenario!(hidden_header, "버전 헤더 없음", |m| {
    let mut c = Case::new(vec![url(m.base, "/hidden")]).req(&[("HEAD", "/hidden", 200)]);
    c.hidden = true;
    c
});
scenario!(empty204, "204 응답에 GET 없음", |m| Case::new(vec![
    url(m.base, "/empty204")
])
.req(&[("HEAD", "/empty204", 204)]));
scenario!(head405, "HEAD 405 응답 후 GET 요청", |m| Case::new(
    vec![url(m.base, "/head405")]
)
.req(&[("HEAD", "/head405", 405), ("GET", "/head405", 200)])
.version("8.3.6")
.vulnerable());
scenario!(head501, "HEAD 501 응답 후 GET 요청", |m| Case::new(
    vec![url(m.base, "/head501")]
)
.req(&[("HEAD", "/head501", 501), ("GET", "/head501", 200)])
.version("8.3.6")
.vulnerable());
scenario!(get405, "GET 405 재시도 없음", |m| Case::new(vec![
    url(m.base, "/head405-get405"),
    url(m.base, "/vulnerable")
])
.req(&[
    ("HEAD", "/head405-get405", 405),
    ("GET", "/head405-get405", 405),
    ("HEAD", "/vulnerable", 200)
])
.vulnerable());
scenario!(get501, "GET 501 응답 후 추가 요청 중단", |m| {
    Case::new(vec![
        url(m.base, "/head501-get501"),
        url(m.base, "/should-not-hit"),
    ])
    .req(&[
        ("HEAD", "/head501-get501", 501),
        ("GET", "/head501-get501", 501),
    ])
    .stop()
    .vulnerable()
});
scenario!(get429, "GET 429 응답 후 추가 요청 중단", |m| {
    Case::new(vec![
        url(m.base, "/head405-get429"),
        url(m.base, "/should-not-hit"),
    ])
    .req(&[
        ("HEAD", "/head405-get429", 405),
        ("GET", "/head405-get429", 429),
    ])
    .stop()
    .vulnerable()
});
scenario!(get503, "GET 503 응답 후 추가 요청 중단", |m| {
    Case::new(vec![
        url(m.base, "/head405-get503"),
        url(m.base, "/should-not-hit"),
    ])
    .req(&[
        ("HEAD", "/head405-get503", 405),
        ("GET", "/head405-get503", 503),
    ])
    .stop()
    .vulnerable()
});
scenario!(get403, "GET 403 인증 재시도 없음", |m| Case::new(
    vec![url(m.base, "/head405-get403"), url(m.base, "/vulnerable")]
)
.req(&[
    ("HEAD", "/head405-get403", 405),
    ("GET", "/head405-get403", 403),
    ("HEAD", "/vulnerable", 200)
])
.vulnerable());
scenario!(redirect, "리다이렉트 추적 차단", |m| Case::new(
    vec![url(m.base, "/redirect")]
)
.req(&[("HEAD", "/redirect", 302)]));
scenario!(redirect301, "301 이동 차단", |m| Case::new(vec![url(
    m.base,
    "/redirect301"
)])
.req(&[("HEAD", "/redirect301", 301)]));
scenario!(redirect307, "307 이동 차단", |m| Case::new(vec![url(
    m.base,
    "/redirect307"
)])
.req(&[("HEAD", "/redirect307", 307)]));
scenario!(redirect308, "308 이동 차단", |m| Case::new(vec![url(
    m.base,
    "/redirect308"
)])
.req(&[("HEAD", "/redirect308", 308)]));
scenario!(access_errors, "인증 · 경로 재탐색 차단", |m| {
    Case::new(vec![
        url(m.base, "/auth401"),
        url(m.base, "/forbidden403"),
        url(m.base, "/missing404"),
    ])
    .req(&[
        ("HEAD", "/auth401", 401),
        ("HEAD", "/forbidden403", 403),
        ("HEAD", "/missing404", 404),
    ])
});
scenario!(duplicate, "중복 URL 제거", |m| Case::new(vec![
    url(m.base, "/vulnerable"),
    url(m.base, "/vulnerable")
])
.req(&[("HEAD", "/vulnerable", 200)])
.vulnerable());
scenario!(stop429, "429 응답 후 추가 요청 중단", |m| {
    Case::new(vec![
        url(m.base, "/limited429"),
        url(m.base, "/should-not-hit"),
    ])
    .req(&[("HEAD", "/limited429", 429)])
    .stop()
});
scenario!(
    stop503_port,
    "503 응답 후 다른 포트에도 요청 중단",
    |m| Case::new(vec![
        url(m.base, "/unavailable503"),
        url(m.second, "/should-not-hit")
    ])
    .req(&[("HEAD", "/unavailable503", 503)])
    .stop()
);
scenario!(
    stop503_scheme,
    "503 응답 후 HTTPS 요청도 중단",
    |m| Case::new(vec![
        url(m.base, "/unavailable503"),
        tls_url(m.tls, "/should-not-hit")
    ])
    .req(&[("HEAD", "/unavailable503", 503)])
    .stop()
);
scenario!(stop500, "500 이후 추가 요청 차단", |m| Case::new(
    vec![url(m.base, "/error500"), url(m.base, "/should-not-hit")]
)
.req(&[("HEAD", "/error500", 500)])
.stop());
scenario!(
    timeout,
    "10초 제한 초과 시 후속 요청 중단",
    |m| Case::new(vec![
        url(m.base, "/timeout"),
        url(m.base, "/should-not-hit")
    ])
    .req(&[("HEAD", "/timeout", 0)])
    .responses(&[])
    .stop()
    .timeout()
);
scenario!(fallback_timeout, "HEAD · GET 합산 10초 제한", |m| {
    Case::new(vec![
        url(m.base, "/head405-timeout"),
        url(m.base, "/should-not-hit"),
    ])
    .req(&[
        ("HEAD", "/head405-timeout", 405),
        ("GET", "/head405-timeout", 0),
    ])
    .responses(&[405])
    .stop()
    .timeout()
});
scenario!(reset, "연결 초기화 · 재시도 차단", |m| {
    Case::new(vec![url(m.base, "/reset"), url(m.base, "/should-not-hit")])
        .req(&[("HEAD", "/reset", 0)])
        .responses(&[])
        .stop()
});
scenario!(large_header, "헤더 크기 제한", |m| {
    let mut c = Case::new(vec![url(m.base, "/large-header")])
        .req(&[("HEAD", "/large-header", 200)])
        .responses(&[]);
    c.header_rejected = true;
    c
});
scenario!(
    tls_untrusted,
    "신뢰하지 않는 TLS 인증서 거절",
    |m| Case::new(vec![tls_url(m.tls, "/vulnerable")]).tls_rejected()
);
scenario!(
    proxy_environment,
    "프록시 환경에서 루프백 직접 연결",
    |m| {
        let mut c = Case::new(vec![url(m.base, "/vulnerable")])
            .req(&[("HEAD", "/vulnerable", 200)])
            .vulnerable();
        c.proxy = true;
        c
    }
);
scenario!(cookie, "쿠키 재전송 차단", |m| Case::new(vec![
    url(m.base, "/cookie"),
    url(m.base, "/vulnerable")
])
.req(&[("HEAD", "/cookie", 200), ("HEAD", "/vulnerable", 200)])
.vulnerable());
scenario!(query, "쿼리 값 보고서 가림", |m| {
    let mut c = Case::new(vec![url(
        m.base,
        "/vulnerable?mock_token=MOCK_QUERY_SECRET",
    )])
    .req(&[("HEAD", "/vulnerable", 200)])
    .vulnerable();
    c.query = true;
    c
});
scenario!(no_consent, "동의 거절 시 요청 차단", |m| {
    Case::new(vec![url(m.base, "/vulnerable")])
        .reply(Reply::No)
        .exit(4)
});
scenario!(consent_eof, "동의 입력 EOF 시 요청 차단", |m| {
    Case::new(vec![url(m.base, "/vulnerable")])
        .reply(Reply::Eof)
        .exit(4)
});
scenario!(input_limit, "입력 개수 제한", |m| Case::new(
    (0..51).map(|_| url(m.base, "/vulnerable")).collect()
)
.no_prompt()
.exit(4));
scenario!(
    url_userinfo,
    "자격 정보가 있는 URL 사전 거절",
    |m| Case::new(vec![format!(
        "http://mock-user:MOCK_PASSWORD@{}/vulnerable",
        m.base
    )])
    .no_prompt()
    .exit(4)
);
scenario!(
    url_scheme,
    "허용되지 않은 URL 스킴 사전 거절",
    |_m| Case::new(vec!["file:///mock-http-only".to_string()])
        .no_prompt()
        .exit(4)
);
scenario!(url_port_zero, "포트 0 사전 거절", |_m| Case::new(
    vec!["http://127.0.0.1:0".to_string()]
)
.no_prompt()
.exit(4));
scenario!(url_port_overflow, "포트 65536 사전 거절", |_m| {
    Case::new(vec!["http://127.0.0.1:65536".to_string()])
        .no_prompt()
        .exit(4)
});
scenario!(
    url_mixed_invalid,
    "올바른 URL 과 잘못된 URL 묶음 사전 거절",
    |m| Case::new(vec![
        url(m.base, "/vulnerable"),
        "file:///mock-http-only".to_string()
    ])
    .no_prompt()
    .exit(4)
);
scenario!(empty_output, "빈 결과 경로 사전 거절", |m| {
    let mut c = Case::new(vec![url(m.base, "/vulnerable")])
        .no_prompt()
        .exit(4);
    c.output = Some(String::new());
    c
});
scenario!(bare_help, "인수 없는 도움말에 약관 없음", |_m| {
    Case::args(&[]).exit(0)
});
scenario!(explicit_help, "도움말 옵션에 약관 없음", |_m| {
    Case::args(&["--help"]).exit(0)
});
scenario!(invalid_command, "잘못된 명령에 약관 없음", |_m| {
    Case::args(&["invalid-mock-command"]).exit(4)
});
scenario!(
    missing_target,
    "대상 없는 명령에 약관 없음",
    |_m| Case::args(&["url"]).exit(4)
);

// ── 둘째 묶음 (3) — 미리 준 동의 ─────────────────────────────────────────────

scenario!(release_consent_y, "자동 동의로 점검 진행", |m| {
    Case::new(vec![url(m.base, "/vulnerable")])
        .req(&[("HEAD", "/vulnerable", 200)])
        .version("8.3.6")
        .flag("y")
        .vulnerable()
});
scenario!(
    release_consent_n,
    "자동 동의 거절 시 요청 차단",
    |m| Case::new(vec![url(m.base, "/vulnerable")])
        .flag("n")
        .exit(4)
);
scenario!(
    release_consent_invalid,
    "잘못된 자동 동의 값 사전 거절",
    |m| Case::new(vec![url(m.base, "/vulnerable")])
        .flag("invalid")
        .no_prompt()
        .exit(4)
);

// ── 셋째 묶음 (22) ──────────────────────────────────────────────────────────

scenario!(
    malformed_header,
    "손상 헤더 원문 노출 차단",
    |m| {
        let mut c = Case::new(vec![url(m.base, "/malformed-header")])
            .req(&[("HEAD", "/malformed-header", 200)])
            .responses(&[]);
        c.malformed = true;
        c
    }
);
scenario!(
    malformed_status,
    "손상 상태줄 원문 노출 차단",
    |m| {
        let mut c = Case::new(vec![url(m.base, "/malformed-status")])
            .req(&[("HEAD", "/malformed-status", 200)])
            .responses(&[]);
        c.malformed = true;
        c
    }
);
scenario!(
    unknown_version,
    "확인 범위 밖 버전은 확인 필요",
    |m| Case::new(vec![url(m.base, "/unknown-version")])
        .req(&[("HEAD", "/unknown-version", 200)])
        .version("5.3.29")
);
scenario!(
    legacy_php54,
    "PHP 5.4 헤더의 구버전 위험 경고",
    |m| Case::new(vec![url(m.base, "/legacy-php54")])
        .req(&[("HEAD", "/legacy-php54", 200)])
        .version("5.4.0")
        .vulnerable()
);
scenario!(
    legacy_php56,
    "PHP 5.6 헤더의 구버전 위험 경고",
    |m| Case::new(vec![url(m.base, "/legacy-php56")])
        .req(&[("HEAD", "/legacy-php56", 200)])
        .version("5.6.40")
        .vulnerable()
);
scenario!(
    legacy_php74,
    "PHP 7.4 헤더의 구버전 위험 경고",
    |m| Case::new(vec![url(m.base, "/legacy-php74")])
        .req(&[("HEAD", "/legacy-php74", 200)])
        .version("7.4.33")
        .vulnerable()
);
scenario!(
    legacy_php81,
    "PHP 8.1 헤더의 구버전 위험 경고",
    |m| Case::new(vec![url(m.base, "/legacy-php81")])
        .req(&[("HEAD", "/legacy-php81", 200)])
        .version("8.1.34")
        .vulnerable()
);
scenario!(
    legacy_esm_before,
    "수정 전 ESM 헤더의 구버전 위험 경고",
    |m| Case::new(vec![url(m.base, "/legacy-esm-before")])
        .req(&[("HEAD", "/legacy-esm-before", 200)])
        .version("7.4.3-4ubuntu2.29+esm4")
        .vulnerable()
);
scenario!(
    legacy_esm_fixed,
    "수정된 ESM 헤더도 실제 설치 확인 필요",
    |m| Case::new(vec![url(m.base, "/legacy-esm-fixed")])
        .req(&[("HEAD", "/legacy-esm-fixed", 200)])
        .version("7.4.3-4ubuntu2.29+esm5")
        .exit(6)
);
scenario!(
    backport_fixed,
    "백포트 수정 버전도 원격 양호 판정 금지",
    |m| Case::new(vec![url(m.base, "/backport-fixed")])
        .req(&[("HEAD", "/backport-fixed", 200)])
        .version("8.3.6-0ubuntu0.24.04.13")
);
scenario!(
    php_session,
    "PHP 세션 흔적은 사용 추정만 표시",
    |m| Case::new(vec![url(m.base, "/php-session")])
        .req(&[("HEAD", "/php-session", 200)])
        .fingerprint("PHPSESSID")
);
scenario!(laravel, "Laravel 흔적은 사용 추정만 표시", |m| {
    Case::new(vec![url(m.base, "/laravel")])
        .req(&[("HEAD", "/laravel", 200)])
        .fingerprint("Laravel")
});
scenario!(
    wordpress,
    "WordPress 흔적은 사용 추정만 표시",
    |m| Case::new(vec![url(m.base, "/wordpress")])
        .req(&[("HEAD", "/wordpress", 200)])
        .fingerprint("WordPress")
);
scenario!(
    nonphp_csrf,
    "일반 CSRF 쿠키를 PHP 근거로 사용하지 않음",
    |m| {
        let mut c =
            Case::new(vec![url(m.base, "/nonphp-csrf")]).req(&[("HEAD", "/nonphp-csrf", 200)]);
        c.no_fingerprint = true;
        c
    }
);
scenario!(tls_private_ca, "지정한 사설 CA 로 TLS 검증", |m| {
    Case::new(vec![tls_url(m.tls, "/vulnerable")])
        .req(&[("HEAD", "/vulnerable", 200)])
        .base(m.tls)
        .cacert(m.ca())
        .version("8.3.6")
        .vulnerable()
});
scenario!(
    tls_private_ca_fixed,
    "사설 CA 신뢰 후에도 헤더로 양호 판정 금지",
    |m| Case::new(vec![tls_url(m.tls, "/fixed")])
        .req(&[("HEAD", "/fixed", 200)])
        .base(m.tls)
        .cacert(m.ca())
        .version("8.3.36")
);
scenario!(
    tls_after_private_ca,
    "사설 CA 신뢰는 다음 실행에 남지 않음",
    |m| Case::new(vec![tls_url(m.tls, "/vulnerable")]).tls_rejected()
);
scenario!(
    tls_wrong_ca,
    "관련 없는 사설 CA 로 TLS 접속 거절",
    |m| Case::new(vec![tls_url(m.tls, "/vulnerable")])
        .cacert(m.wrong_ca())
        .tls_rejected()
);
scenario!(
    tls_host_mismatch,
    "사설 CA 를 신뢰해도 TLS 호스트명 검증",
    |m| Case::new(vec![tls_url(m.tls_mismatch, "/vulnerable")])
        .cacert(m.wrong_ca())
        .tls_rejected()
);
scenario!(positional_url, "URL 위치 인자와 다중 대상", |m| {
    let mut c = Case::new(vec![url(m.base, "/vulnerable"), url(m.base, "/fixed")])
        .req(&[("HEAD", "/vulnerable", 200), ("HEAD", "/fixed", 200)])
        .version("8.3.6")
        .version("8.3.36")
        .vulnerable();
    c.positional = true;
    c
});
scenario!(
    positional_option_after,
    "URL 뒤에 결과 폴더 지정",
    |m| {
        let mut c = Case::new(vec![url(m.base, "/vulnerable")])
            .req(&[("HEAD", "/vulnerable", 200)])
            .version("8.3.6")
            .vulnerable();
        c.positional = true;
        c.late_option = true;
        c
    }
);
scenario!(
    warning_fallback_timeout,
    "HEAD 경고를 GET 시간 초과 후에도 보존",
    |m| Case::new(vec![
        url(m.base, "/head405-vulnerable-timeout"),
        url(m.base, "/should-not-hit")
    ])
    .req(&[
        ("HEAD", "/head405-vulnerable-timeout", 405),
        ("GET", "/head405-vulnerable-timeout", 0)
    ])
    .responses(&[405])
    .stop()
    .timeout()
    .version("8.3.6")
    .vulnerable()
);

// ── 시나리오 밖 — Ctrl+C ────────────────────────────────────────────────────

/// Ctrl+C 는 막힌 GET 을 기다리지 않고 멈추고, HEAD 에서 본 경고와 결과 파일을 남긴다 — 스캐너 시험
/// `TestHeaderWarningSurvivesInterruptedFallback` 의 실행 파일 쪽. 신호를 보낼 길이 유닉스에만 있어
/// 리눅스에서 돈다.
#[cfg(unix)]
#[test]
fn ctrl_c_keeps_the_head_warning_and_the_report() {
    let scratch = Scratch::new("ctrl_c");
    let m = Mock::start(&scratch.0);
    let out_dir = scratch.0.join("reports");
    let mut child = Command::new(env!("CARGO_BIN_EXE_remedy-net"))
        .args([
            "url",
            &url(m.base, "/head405-vulnerable-timeout"),
            &url(m.base, "/should-not-hit"),
            "--consent",
            "y",
            "--out-dir",
        ])
        .arg(&out_dir)
        .env("REMEDY_LANG", "ko")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // HEAD 405 → 2초 뒤 GET 이 서버에 닿을 때까지 기다린다(GET 은 답을 받지 못하고 막힌다).
    let start = Instant::now();
    while m.events().len() < 2 {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "GET 이 서버에 오지 않았다"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let sent = Instant::now();
    let kill = format!("kill -INT {}", child.id());
    assert!(Command::new("sh")
        .args(["-c", &kill])
        .status()
        .unwrap()
        .success());
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(
            sent.elapsed() < Duration::from_secs(5),
            "Ctrl+C 뒤에 끝나지 않았다"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let took = sent.elapsed();
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(
        took < Duration::from_secs(2),
        "Ctrl+C 뒤 {took:?}:\n{stdout}"
    );
    assert_eq!(
        status.code(),
        Some(2),
        "HEAD 의 경고가 남아야 한다:\n{stdout}"
    );
    assert_eq!(m.events().len(), 2, "멈춘 뒤에도 요청했다");
    let file = std::fs::read_dir(&out_dir)
        .unwrap()
        .next()
        .expect("결과 파일이 없다")
        .unwrap()
        .path();
    let r: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    assert_eq!(r["interrupted"], true, "{stdout}");
    assert_eq!(r["verdict"], "vulnerable");
    assert_eq!(r["targets"][0]["verdict"], "vulnerable");
    assert_eq!(r["targets"][1]["requests"]["head"], 0);
}

// ── 시나리오 밖 — 주소를 물어서 받기(`--ask`) ─────────────────────────────────

/// 본체(`remedy`)의 메뉴가 띄우는 꼴 — 약관에 동의한 뒤 주소를 한 줄씩 받고, 잘못 적은 줄은 까닭을
/// 말하고 다시 묻는다. 받은 주소만 점검한다.
#[test]
fn ask_mode_reads_the_addresses_after_consent() {
    let scratch = Scratch::new("ask");
    let m = Mock::start(&scratch.0);
    let out_dir = scratch.0.join("reports");
    let mut child = Command::new(env!("CARGO_BIN_EXE_remedy-net"))
        .args(["url", "--ask", "--out-dir"])
        .arg(&out_dir)
        .env("REMEDY_LANG", "ko")
        .env("REMEDY_ASCII", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let typed = format!(
        "y\n{}\nnot-a-url\n{}\n\n",
        url(m.base, "/vulnerable"),
        url(m.base, "/fixed")
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(typed.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(2), "{stdout}");
    // 약관 → 동의 → 주소 차례다.
    let terms = stdout.find(TERMS_HEADER).expect("약관이 없다");
    let asked = stdout.find("주소 1: ").expect("주소를 묻지 않았다");
    assert!(terms < stdout.find(PROMPT).unwrap() && stdout.find(PROMPT).unwrap() < asked);
    // 잘못 적은 줄은 번호를 먹지 않는다 — 주소 2 를 두 번 묻는다.
    assert_eq!(stdout.matches("주소 2: ").count(), 2, "{stdout}");
    let seen: Vec<String> = m
        .events()
        .iter()
        .map(|e| format!("{} {}", e.method, e.path))
        .collect();
    assert_eq!(seen, vec!["HEAD /vulnerable", "HEAD /fixed"]);
    let file = std::fs::read_dir(&out_dir)
        .unwrap()
        .next()
        .expect("결과 파일이 없다")
        .unwrap()
        .path();
    let r: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    assert_eq!(r["targets"].as_array().unwrap().len(), 2);
    assert_eq!(r["consent"]["via"], "prompt");
}

/// 주소를 하나도 적지 않으면 점검하지 않는다 — 요청도 결과 폴더도 없다.
#[test]
fn ask_mode_with_no_address_checks_nothing() {
    let scratch = Scratch::new("ask_none");
    let m = Mock::start(&scratch.0);
    let out_dir = scratch.0.join("reports");
    let mut child = Command::new(env!("CARGO_BIN_EXE_remedy-net"))
        .args(["url", "--ask", "--out-dir"])
        .arg(&out_dir)
        .env("REMEDY_LANG", "ko")
        .env("REMEDY_ASCII", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"y\n\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert!(m.events().is_empty());
    assert!(!out_dir.exists());
}
