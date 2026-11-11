//! `image` · `container` 의 결과 — 파일(JSON)과 화면. JSON 스키마는 이 타입에서 낸다(`cargo xtask schema` →
//! `docs/remedy-net/scan-report.schema.json`).
//!
//! 사람이 읽는 칸(`reason` · `action` · `gaps` · `scope` · 발견의 `name` · `limitations`)은 실행 언어로 적힌다.
//! 기계가 읽을 칸(`verdict` · `status` · `exit_code` · `kind` · `products` · `usage` 의 수)은 언어와 무관하다.

use super::budget::Usage;
use super::model::{Finding, Product, Status, Target};
use super::phpconfig;
use super::rules::RuleSet;
use crate::text::plain;
use remedy_sdk::i18n::Lang;
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::BTreeMap;

/// 이 파일의 꼴 번호 — 칸의 뜻이 바뀌면 오른다.
pub const SCHEMA_VERSION: u32 = 1;

/// 화면에 내는 발견 · *보지 못한 것* 의 수 — 나머지는 결과 파일에 있다.
const SHOWN_FINDINGS: usize = 8;
const SHOWN_GAPS: usize = 5;

/// `remedy-net image` · `remedy-net container` 한 번의 결과.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    /// `image` · `container`.
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
    /// 고른 제품(`--runtime`).
    pub products: Vec<Product>,
    /// 대상 중 하나라도 취약이면 취약, 하나라도 다 보지 못했거나 확인 필요면 확인 필요, 그 밖에는 양호. 대상이
    /// 없으면 확인 필요다.
    pub verdict: Status,
    /// 이 실행의 종료 코드 — 양호 0 · 취약 2 · 확인 필요 6(본체 표).
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

/// 견준 기준 — 만료를 두지 않는 대신 무엇을 언제 낸 것인지 적는다.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Criteria {
    /// 기준 데이터의 판(발행일 · 기준 번호).
    pub version: String,
    /// 기준을 낸 시각(RFC 3339 UTC).
    pub issued_at: String,
    /// 내장 기준 데이터의 SHA-256 — 사내 runtime-scanner 가 같은 기준에 적는 값과 같다.
    pub sha256: String,
    /// 고른 제품마다 보는 CVE. PHP 에는 세션 설정(CVE-2026-115560)도 든다.
    pub cves: BTreeMap<Product, Vec<String>>,
}

impl Criteria {
    pub fn of(rules: &RuleSet, products: &[Product]) -> Criteria {
        let mut cves = BTreeMap::new();
        for p in products {
            let mut list: Vec<String> = rules.cves(*p).to_vec();
            if *p == Product::Php && !list.iter().any(|c| c == phpconfig::CVE) {
                list.push(phpconfig::CVE.to_string());
            }
            cves.insert(*p, list);
        }
        Criteria {
            version: rules.version().to_string(),
            issued_at: rules.issued_at().to_string(),
            sha256: rules.sha256().to_string(),
            cves,
        }
    }
}

/// 화면의 한 덩이 — 대상 하나. 발견은 나쁜 것부터 [`SHOWN_FINDINGS`] 개, *보지 못한 것* 은 [`SHOWN_GAPS`] 개까지
/// 내고 나머지는 결과 파일에 있다고 적는다.
pub(crate) fn render(t: &Target, n: usize, lang: Lang) -> String {
    let mut s = format!("[{n}] {}\n", plain(&t.name, 200));
    s.push_str(&format!("  {} — {}\n", t.status.label(lang), t.reason));
    if !t.products.is_empty() {
        let parts: Vec<String> = t
            .products
            .iter()
            .map(|(p, c)| format!("{} {}", p.name(), c.status.label(lang)))
            .collect();
        s.push_str(&format!("  {}\n", parts.join(" · ")));
    }
    let mut findings: Vec<&Finding> = t.findings.iter().collect();
    // 같은 판정 안에서는 찾은 차례를 지킨다.
    findings.sort_by_key(|f| std::cmp::Reverse(f.status));
    for f in findings.iter().take(SHOWN_FINDINGS) {
        s.push_str(&finding_line(f, lang));
    }
    if findings.len() > SHOWN_FINDINGS {
        s.push_str(&more_line(findings.len() - SHOWN_FINDINGS, lang));
    }
    let gaps = all_gaps(t);
    if !gaps.is_empty() {
        s.push_str(&format!("  {}:\n", lang.t("보지 못한 것", "not seen")));
        for g in gaps.iter().take(SHOWN_GAPS) {
            s.push_str(&format!("  · {}\n", plain(g, 300)));
        }
        if gaps.len() > SHOWN_GAPS {
            s.push_str(&more_line(gaps.len() - SHOWN_GAPS, lang));
        }
    }
    s.push_str(&format!("  {}: {}\n", lang.t("할 일", "next"), t.action));
    s
}

fn finding_line(f: &Finding, lang: Lang) -> String {
    let mut line = format!("  · {} — {}", f.status.label(lang), plain(&f.name, 80));
    if let Some(p) = &f.path {
        line.push_str(&format!(" {}", plain(p, 200)));
    }
    if let Some(v) = &f.version {
        line.push_str(&format!(" ({})", plain(v, 60)));
    }
    line.push('\n');
    // 취약한 발견은 까닭(어느 수정 버전에 못 미치는지)까지 낸다 — 확인 필요는 수가 많아 결과 파일에 둔다.
    if f.status == Status::Vulnerable && !f.reason.is_empty() {
        line.push_str(&format!("    {}\n", plain(&f.reason, 300)));
    }
    line
}

fn more_line(n: usize, lang: Lang) -> String {
    lang.pick(
        format!("  · 그 밖에 {n}개 — 결과 파일에 있습니다\n"),
        format!("  · {n} more — see the report file\n"),
    )
}

/// 대상과 제품의 *보지 못한 것* 을 한 번씩 — 대상의 것은 올릴 때 제품마다 복사되므로 겹친다.
fn all_gaps(t: &Target) -> Vec<&String> {
    let mut seen: Vec<&String> = Vec::new();
    for g in t
        .gaps
        .iter()
        .chain(t.products.values().flat_map(|c| c.gaps.iter()))
    {
        if !seen.contains(&g) {
            seen.push(g);
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::model::{Evidence, TargetKind};

    fn finding(status: Status, name: &str, path: &str) -> Finding {
        Finding {
            product: Product::Php,
            id: format!("t:{path}"),
            name: name.to_string(),
            path: Some(path.to_string()),
            version: Some("8.3.35".to_string()),
            package: None,
            vendor: Some("upstream".to_string()),
            runtime: Some("cli".to_string()),
            cves: vec!["CVE-2026-109618".to_string()],
            status,
            reason: "수정 버전 8.3.36 보다 낮습니다.".to_string(),
            action: String::new(),
            evidence: vec![Evidence::new("시험", "시험")],
        }
    }

    #[test]
    fn the_worst_findings_come_first_and_the_rest_is_counted() {
        let mut t = Target::new(
            "image-1",
            TargetKind::Image,
            "app.tar [linux/amd64]",
            &[Product::Php],
        );
        for i in 0..10 {
            t.findings.push(finding(
                Status::ReviewRequired,
                "PHP 이미지 파일",
                &format!("/usr/bin/php{i}"),
            ));
        }
        t.findings.push(finding(
            Status::Vulnerable,
            "PHP 이미지 파일",
            "/usr/local/bin/php",
        ));
        t.add_gap("레이어 한도");
        t.finalize(Lang::Ko);
        let s = render(&t, 1, Lang::Ko);
        let first = s.lines().position(|l| l.contains("· 취약 —")).unwrap();
        let review = s.lines().position(|l| l.contains("· 확인 필요 —")).unwrap();
        assert!(first < review, "{s}");
        assert!(s.contains("수정 버전 8.3.36 보다 낮습니다."), "{s}");
        assert!(s.contains("그 밖에 3개"), "{s}");
        assert!(s.contains("보지 못한 것:"));
        assert_eq!(
            s.matches("레이어 한도").count(),
            1,
            "대상 · 제품에 같은 것이 겹쳐 나왔다: {s}"
        );
        assert!(s.starts_with("[1] app.tar [linux/amd64]\n  취약 — "), "{s}");
        assert!(s.contains("PHP 취약"), "{s}");
    }

    #[test]
    fn terminal_control_characters_in_names_are_not_printed() {
        let mut t = Target::new("image-2", TargetKind::Image, "a\u{1b}[2Jb.tar", &[]);
        t.finalize(Lang::En);
        let s = render(&t, 2, Lang::En);
        assert!(!s.contains('\u{1b}'), "{s:?}");
        assert!(s.contains("next: "));
    }

    #[test]
    fn criteria_carry_the_session_cve_for_php_only() {
        let rules = RuleSet::builtin();
        let c = Criteria::of(rules, &[Product::Php, Product::Node]);
        assert!(c.cves[&Product::Php].iter().any(|v| v == phpconfig::CVE));
        assert!(!c.cves[&Product::Node].iter().any(|v| v == phpconfig::CVE));
        assert_eq!(c.version, rules.version());
        assert_eq!(c.sha256.len(), 64);
        let only_node = Criteria::of(rules, &[Product::Node]);
        assert!(!only_node.cves.contains_key(&Product::Php));
    }
}
