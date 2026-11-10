//! 결과 — 파일(JSON)과 화면. JSON 스키마는 이 타입에서 낸다(`cargo xtask schema` → `docs/remedy-net/`).
//!
//! 사람이 읽는 칸(`reason` · `action` · `gaps` · `limitations` · 단서의 이름)은 실행 언어로 적힌다. 기계가
//! 읽을 칸(`verdict` · `exit_code` · `kind` · 상태 코드 · 요청 수)은 언어와 무관하다.

use super::wire::Method;
use remedy_sdk::i18n::Lang;
use schemars::JsonSchema;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// 이 파일의 꼴 번호 — 칸의 뜻이 바뀌면 오른다.
pub const SCHEMA_VERSION: u32 = 1;

/// 판정. URL 점검은 헤더만 보므로 *양호* 가 없다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// 헤더가 알리는 버전이 영향 버전이다(설치 · 백포트는 확인하지 못했다).
    Vulnerable,
    /// 헤더로는 가릴 수 없다 — 그 서버에서 직접 점검해야 한다.
    ReviewRequired,
}

/// `remedy-net url` 한 번의 결과.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    /// `url`.
    pub command: String,
    /// `20261110T031000Z-<16자리 16진수>` — 파일 이름에도 들어간다.
    pub run_id: String,
    /// 사람이 읽는 칸의 언어 — `ko` · `en`.
    pub language: String,
    /// RFC 3339 UTC.
    pub started_at: String,
    pub finished_at: String,
    pub consent: Consent,
    pub criteria: Criteria,
    /// 대상 중 하나라도 취약이면 취약, 아니면 확인 필요.
    pub verdict: Verdict,
    /// 이 실행의 종료 코드 — 취약 2 · 확인 필요 6(본체 표).
    pub exit_code: u8,
    /// Ctrl+C 나 실행 시한으로 다 돌지 못했다.
    pub interrupted: bool,
    pub targets: Vec<Target>,
    pub usage: Usage,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Tool {
    /// `remedy-net`.
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Consent {
    pub terms_version: String,
    /// RFC 3339 UTC.
    pub accepted_at: String,
    /// `prompt`(물어서) · `flag`(`--consent y`).
    pub via: String,
}

/// 견준 기준 — 만료를 두지 않는 대신 무엇과 언제를 적는다.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Criteria {
    pub name: String,
    pub cves: Vec<String>,
    /// 기준을 다시 확인한 날(YYYY-MM-DD).
    pub checked: String,
    /// 같은 수정 버전을 쓰는 본체의 점검 룰.
    pub same_as: String,
    pub sources: Vec<String>,
}

/// URL 하나.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct Target {
    /// `url:` + 정규화한 URL 의 SHA-256 — 쿼리를 담은 원문은 싣지 않는다.
    pub id: String,
    /// 쿼리를 가린 URL.
    pub url: String,
    pub verdict: Verdict,
    pub reason: String,
    pub action: String,
    pub requests: Requests,
    pub status: Statuses,
    /// 실제로 연결한 상대 IP(차례대로).
    pub addresses: Vec<String>,
    /// 버전은 몰라도 PHP 를 쓴다고 짐작할 단서가 있었다.
    pub php_presence: bool,
    pub findings: Vec<Finding>,
    /// 보지 못한 것과 그 까닭.
    pub gaps: Vec<String>,
}

/// 보낸 요청 — 0 또는 1. 상대 IP 가 멈춘 서버라 연결만 하고 닫은 시도는 0 이다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Requests {
    pub head: u8,
    pub get: u8,
}

/// 받은 상태 코드.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Statuses {
    pub head: Option<u16>,
    pub get: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct Finding {
    /// `header:<head|get>:<헤더 이름>:<차례>` · `php-presence`.
    pub id: String,
    pub kind: FindingKind,
    /// `HEAD` · `GET` — 어느 응답에서 읽었나.
    pub method: String,
    /// `X-Powered-By: PHP/8.3.6` 처럼 받은 그대로, 또는 단서의 이름.
    pub evidence: String,
    /// 헤더에서 읽은 PHP 버전.
    pub version: Option<String>,
    pub verdict: Verdict,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// `Server` · `X-Powered-By` 헤더 한 줄.
    Header,
    /// 버전 없이 PHP 를 쓴다고 짐작할 단서.
    PhpPresence,
}

#[derive(Debug, Clone, Default, Serialize, JsonSchema)]
pub struct Usage {
    /// 맡은 HTTP 요청 수 — TLS 거절처럼 서버에 닿지 못한 시도도 센다.
    pub http_requests: u32,
    /// 상한에 걸린 것.
    pub stops: Vec<String>,
}

impl Requests {
    pub(crate) fn set(&mut self, m: Method, n: u8) {
        match m {
            Method::Head => self.head = n,
            Method::Get => self.get = n,
        }
    }
}

impl Statuses {
    pub(crate) fn set(&mut self, m: Method, code: u16) {
        match m {
            Method::Head => self.head = Some(code),
            Method::Get => self.get = Some(code),
        }
    }
}

impl Verdict {
    pub(crate) fn word(self, lang: Lang) -> &'static str {
        match self {
            Verdict::Vulnerable => lang.t("취약", "vulnerable"),
            Verdict::ReviewRequired => lang.t("확인 필요", "needs review"),
        }
    }
}

/// 화면의 한 덩이 — URL 하나.
pub(crate) fn render(t: &Target, n: usize, total: usize, lang: Lang) -> String {
    use crate::text::plain;
    let mut s = format!("[{n}/{total}] {}\n", plain(&t.url, 200));
    s.push_str(&format!("  {} — {}\n", t.verdict.word(lang), t.reason));
    let mut answered = Vec::new();
    if let Some(c) = t.status.head {
        answered.push(format!("HEAD {c}"));
    }
    if let Some(c) = t.status.get {
        answered.push(format!("GET {c}"));
    }
    if !answered.is_empty() {
        s.push_str(&format!(
            "  {}: {}\n",
            lang.t("응답", "response"),
            answered.join(" → ")
        ));
    }
    // HEAD · GET 둘 다 받았으면 같은 헤더가 두 번 나온다 — 어느 응답의 것인지 붙인다.
    let both = t.status.head.is_some() && t.status.get.is_some();
    for f in &t.findings {
        let from = if both {
            format!(" ({})", f.method)
        } else {
            String::new()
        };
        let mark = match f.verdict {
            Verdict::Vulnerable => lang.t(" — 영향 버전", " — affected version"),
            Verdict::ReviewRequired => "",
        };
        s.push_str(&format!("  · {}{from}{mark}\n", plain(&f.evidence, 160)));
    }
    // 마지막 한 줄(헤더는 설치와 다를 수 있다)은 모든 대상에 같아 화면에는 끝에 한 번만 낸다.
    let common = header_caveat(lang);
    for g in t.gaps.iter().filter(|g| g.as_str() != common) {
        s.push_str(&format!("  · {g}\n"));
    }
    s.push_str(&format!("  {}: {}\n", lang.t("할 일", "next"), t.action));
    s
}

pub(crate) fn header_caveat(lang: Lang) -> &'static str {
    lang.t(
        "응답 헤더가 알리는 정보는 실제 설치 상태와 다를 수 있습니다.",
        "What the headers say may differ from what is installed.",
    )
}

/// 결과 파일을 쓴다 — 같은 이름이 있으면 덮지 않는다.
pub(crate) fn save(dir: &Path, report: &Report) -> std::io::Result<PathBuf> {
    crate::output::save_json(dir, "url", &report.run_id, report)
}
