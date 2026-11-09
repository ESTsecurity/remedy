//! 스키마 검증 — 형태는 serde 가 보고, **의미**는 여기서 본다.
//!
//! P1 이 책임지는 것은 두 가지다.
//!
//! 1. 스키마에 없는 필드를 쓴 `plugin.yaml` 거부 → `deny_unknown_fields` 가 처리한다
//! 2. 아직 구현되지 않은 항목을 쓴 룰이 **예정 Phase 를 포함한 오류**를 받는다
//!
//! 2번이 여기 있는 이유: "지금은 안 된다" 와 "영원히 안 된다" 는 작성자에게
//! 완전히 다른 정보다. 앞의 것은 기다리면 되고 뒤의 것은 설계를 바꿔야 한다.
//! 구분해 주지 않으면 작성자가 우회로를 만들기 시작한다.

use crate::catalog::{Phase, Subject};
use crate::manifest::PluginManifest;
use crate::{IMPLEMENTED_THROUGH, SCHEMA_VERSION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaIssue {
    /// 문제가 있는 위치. 예: `detect[1].subject`
    pub at: String,
    pub message: String,
    /// 기다리면 해결되는 문제라면 그 Phase.
    pub available_in: Option<Phase>,
    /// 무엇을 쓸 수 있는지. **유효값을 전수로 준다** (설계-09 P3).
    ///
    /// 알려 주지 않으면 작성자는 문서를 뒤지거나 추측한다. 추측이 한 번 통과하면
    /// 그 추측이 다음 룰에도 쓰인다. 이 검증은 코어가 매니페스트를 로드할 때마다
    /// 도는 쪽이라, 여기서 답을 주지 않으면 실기기에서 막힌 사람이 답을 얻을
    /// 곳이 없다.
    pub valid: Option<String>,
    /// 근거 문서 앵커. 예: `설계-02 §2`
    pub doc: Option<&'static str>,
}

impl SchemaIssue {
    fn new(at: impl Into<String>, message: impl Into<String>, doc: &'static str) -> Self {
        Self {
            at: at.into(),
            message: message.into(),
            available_in: None,
            valid: None,
            doc: Some(doc),
        }
    }

    fn with_valid(mut self, valid: impl Into<String>) -> Self {
        self.valid = Some(valid.into());
        self
    }

    fn available(mut self, p: Phase) -> Self {
        self.available_in = Some(p);
        self
    }
}

impl std::fmt::Display for SchemaIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.at, self.message)?;
        if let Some(p) = self.available_in {
            write!(f, " ({} 에서 사용 가능해진다)", p.as_str())?;
        }
        if let Some(v) = &self.valid {
            write!(
                f,
                "
      쓸 수 있는 것: {v}"
            )?;
        }
        if let Some(d) = self.doc {
            write!(
                f,
                "
      근거: {d}"
            )?;
        }
        Ok(())
    }
}

/// 매니페스트의 의미 검증. 형태 검증은 역직렬화가 이미 끝냈다.
///
/// 여기서 보는 것은 P1 범위에 한정된다. 참조 무결성·정규식 유효성·범위 검사는
/// `plugin lint`(P3) 가 맡는다.
pub fn validate(m: &PluginManifest) -> Vec<SchemaIssue> {
    let mut issues = Vec::new();

    if m.schema_version != SCHEMA_VERSION {
        issues.push(
            SchemaIssue::new(
                "schema_version",
                format!(
                    "이 코어는 schema_version {SCHEMA_VERSION} 만 이해한다 (선언: {})",
                    m.schema_version
                ),
                "설계-02 §8",
            )
            .with_valid(SCHEMA_VERSION.to_string()),
        );
    }

    check_min_core(m, &mut issues);

    if m.scan_roots.is_empty() {
        issues.push(SchemaIssue::new(
            "scan_roots",
            "비어 있다. scan_roots 는 읽기 권한 상한이므로 최소 하나가 있어야 한다",
            "설계-02 §2",
        ));
    }

    // **점검이라고 선언했으면 바꾸지 않는다.** 둘을 함께 적으면 코어는 점검
    // 어휘로 보고하면서 파괴를 계획한다 — 고객은 *취약* 이라고 읽고 기계는
    // 지워진다. 경고가 아니라 오류다: 사람이 판단할 재료가 아니라 모순이다.
    if m.kind == Some(crate::manifest::PluginKind::Check) && m.remediate.is_some() {
        issues.push(
            SchemaIssue::new(
                "remediate",
                "kind: check 는 바꾸지 않는다고 선언한 것인데 remediate 가 있다",
                "설계-02 §2",
            )
            .with_valid("remediate 를 빼거나 kind 를 빼라".to_string()),
        );
    }

    check_unconfirmed(m, &mut issues);

    if m.detect.is_empty() {
        issues.push(SchemaIssue::new(
            "detect",
            "규칙이 하나도 없다",
            "설계-02 §4",
        ));
    }

    // subjects 선언과 실제 사용의 일치. "선언한 것만 볼 수 있다" (설계-02 §4).
    for (i, rule) in m.detect.iter().enumerate() {
        if !m.subjects.contains(&rule.subject) {
            issues.push(
                SchemaIssue::new(
                    format!("detect[{i}].subject"),
                    format!(
                        "'{}' 를 쓰려면 최상위 subjects 에 선언해야 한다",
                        rule.subject.id()
                    ),
                    "설계-02 §4",
                )
                .with_valid(if m.subjects.is_empty() {
                    "(subjects 가 비어 있다)".to_string()
                } else {
                    m.subjects
                        .iter()
                        .map(|s| s.id())
                        .collect::<Vec<_>>()
                        .join(" · ")
                }),
            );
        }
    }

    // 아직 구현되지 않은 subject. 예정 Phase 를 반드시 함께 알려 준다.
    for (i, subject) in m.subjects.iter().enumerate() {
        if let Some(phase) = pending(*subject) {
            issues.push(
                SchemaIssue::new(
                    format!("subjects[{i}]"),
                    format!(
                        "'{}' 의 수집기는 아직 없다 (현재 코어: {})",
                        subject.id(),
                        IMPLEMENTED_THROUGH.as_str()
                    ),
                    "설계-09 §3.3",
                )
                .with_valid(implemented_subjects())
                .available(phase),
            );
        }
    }

    // 재귀 삭제는 guard 없이 계획에 들어갈 수 없다 (설계-03 §4).
    // 문법 수준에서 막는 편이 계획기까지 가서 거부되는 것보다 낫다.
    if let Some(rem) = &m.remediate {
        for (i, t) in rem.remove.iter().enumerate() {
            if let crate::manifest::RemoveTarget::Path(p) = t {
                if p.recursive && p.guard.is_none() {
                    issues.push(
                        SchemaIssue::new(
                            format!("remediate.remove[{i}]"),
                            "recursive: true 는 guard 를 요구한다. guard 는 그 디렉터리 안에서 악성으로 판정된 파일 증거를 가리켜야 한다",
                            "설계-03 §4",
                        )
                        .with_valid(rule_ids(m)),
                    );
                }
            }
        }
    }

    // 서명된 악성코드 예외는 주체를 특정해야 한다. 빈 항목은 포괄적 무시가 된다.
    for (i, sm) in m.signed_malware.iter().enumerate() {
        if sm.subject.is_none() && sm.thumbprint.is_none() {
            issues.push(
                SchemaIssue::new(
                    format!("signed_malware[{i}]"),
                    "subject 또는 thumbprint 중 하나는 있어야 한다. 둘 다 없으면 포괄적 무시가 된다",
                    "설계-03 §3 2층",
                )
                .with_valid("subject: '<서명 주체>' 또는 thumbprint: '<지문>'"),
            );
        }
    }

    issues
}

/// `verdict.unconfirmed` 를 쓸 수 있는 룰인가 (2026-11-09 · 코어 1.3.0).
///
/// - **점검(`kind: check`)만 쓴다.** 치료 룰의 6 은 *"다 보지 못했다"* 하나이고, 치료 룰이 *"찾았지만
///   모른다"* 를 말하면 계획은 서지 않는데 판정 화면은 위협을 말한다 — 둘 중 하나는 거짓이다.
/// - **까닭은 두 언어로.** 사유 줄이 결론의 유일한 설명이다 — 한쪽이 비면 그 언어로 돌린 무인
///   배포는 6 의 까닭을 읽지 못한다(2026-09-14 의 영어 화면과 같은 결함).
/// - **`min_core` 는 1.3.0 이상.** 낮은 코어는 이 칸을 모른다 — 매니페스트를 읽다 멈추거나(모르는 칸
///   거부) 그보다 낮으면 칸을 버리고 *확인 필요* 를 0 으로 낸다. 요구 판을 적어야 로드 단계가 그 차이를
///   말한다([`check_min_core`]).
fn check_unconfirmed(m: &PluginManifest, issues: &mut Vec<SchemaIssue>) {
    if m.verdict.unconfirmed.is_empty() {
        return;
    }
    if m.kind != Some(crate::manifest::PluginKind::Check) {
        issues.push(
            SchemaIssue::new(
                "verdict.unconfirmed",
                "점검 룰(kind: check)만 쓸 수 있다 — 치료 룰의 6 은 '다 보지 못했다' 하나다",
                "docs/plugin-guide/24-check-plugins.md",
            )
            .with_valid("kind: check 를 적거나 verdict.unconfirmed 를 빼라".to_string()),
        );
    }
    for (i, u) in m.verdict.unconfirmed.iter().enumerate() {
        for lang in ["ko", "en"] {
            if u.why.get(lang).is_none_or(|t| t.trim().is_empty()) {
                issues.push(
                    SchemaIssue::new(
                        format!("verdict.unconfirmed[{i}].why"),
                        format!("'{lang}' 까닭이 없다 — 사유 줄이 6 의 유일한 설명이다"),
                        "docs/plugin-guide/24-check-plugins.md",
                    )
                    .with_valid("why: { ko: '…', en: '…' }".to_string()),
                );
            }
        }
    }
    const SINCE: (u64, u64, u64) = (1, 3, 0);
    if semver3(&m.min_core).is_some_and(|v| v < SINCE) {
        issues.push(
            SchemaIssue::new(
                "min_core",
                format!(
                    "verdict.unconfirmed 는 코어 1.3.0 부터 있다 — min_core '{}' 로는 낮은 코어가 이 룰을 \
                     받아 확인 필요를 내지 못한다",
                    m.min_core
                ),
                "설계-02 §10",
            )
            .with_valid("min_core: \"1.3.0\" 이상".to_string()),
        );
    }
}

/// 이 코어가 플러그인이 요구하는 버전을 만족하는가 (설계-02 §10 — `schema_version`
/// 과 `min_core` 둘 다 만족해야 로드된다).
///
/// # 무엇이 조용히 깨지는가
///
/// 미래 코어를 요구하는 플러그인이 낡은 코어에서 **그냥 돈다.** 그 플러그인이
/// 기대하는 Op·필드·캡처가 없으면 탐지가 0건이 되고, 작성자도 운영자도 룰이 도는
/// 줄 안다 — [`Subject::NOT_POPULATED_YET`](crate::catalog::Subject::NOT_POPULATED_YET)
/// 이 막으려는 실패 방식과 같은 모양이다.
///
/// # 왜 여기 있는가
///
/// 2026-08-28 에 `min_core: "99.0.0"` 이 린트도 실행도 통과하는 것을 실측하고
/// **린트에만** 이 검사를 더했다. 검사·치료가 룰을 읽는 이 자리에는 빠졌다 —
/// 2026-11-08 에 공개된 1.1.3 이 `min_core: "1.2.0"` 인 룰을 거절하지 않고 평가하는
/// 것을 실측했다. 형제 필드인 `schema_version` 처럼 **로드할 때마다** 본다.
/// 린트는 `validate` 의 결과를 그대로 담으므로 작성자도 같은 오류를 본다.
///
/// # 세 자리 수만 본다
///
/// SemVer 전체를 구현하지 않는다. 사전 배포 태그(`-rc.1`)나 빌드 메타(`+abc`)를
/// 다루기 시작하면 비교 규칙이 이 파일의 주제와 무관하게 커진다. **파싱되지 않는
/// 값은 오류다** — 조용히 통과시키면 오타 하나가 검사를 통째로 끈다.
fn check_min_core(m: &PluginManifest, issues: &mut Vec<SchemaIssue>) {
    let core = env!("CARGO_PKG_VERSION");
    let Some(want) = semver3(&m.min_core) else {
        issues.push(
            SchemaIssue::new(
                "min_core",
                format!("'{}' 을 버전으로 읽지 못했다", m.min_core),
                "설계-02 §10",
            )
            .with_valid("`주.부.수` 세 자리 수 — 예: 1.0.0"),
        );
        return;
    };
    // 코어 버전은 우리가 짓는 값이다. 여기서 파싱이 실패하면 그것은 플러그인의
    // 문제가 아니라 이 저장소의 문제이므로 검사를 건너뛰지 않고 드러낸다.
    let have = semver3(core).expect("코어 버전이 세 자리 수가 아니다");
    if want > have {
        issues.push(
            SchemaIssue::new(
                "min_core",
                format!(
                    "이 룰은 코어 {} 이상을 요구하는데 이 코어는 {core} 다. 낮은 코어에서 \
                     돌리면 모르는 Op·필드를 쓴 룰이 조용히 0건을 보고한다",
                    m.min_core
                ),
                "설계-02 §10",
            )
            .with_valid(format!(
                "이 코어가 만족하는 min_core: {core} 이하 — 받은 룰이면 같은 릴리스의 \
                 remedy 로 돌린다"
            )),
        );
    }
}

/// `주.부.수` 세 자리. 그 밖의 모양은 `None`.
fn semver3(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((a, b, c))
}

/// 지금 코어가 실제로 수집할 수 있는 subject.
fn implemented_subjects() -> String {
    Subject::ALL
        .iter()
        .filter(|s| s.info().implemented_in <= IMPLEMENTED_THROUGH)
        .map(|s| s.id())
        .collect::<Vec<_>>()
        .join(" · ")
}

fn rule_ids(m: &PluginManifest) -> String {
    if m.detect.is_empty() {
        return "(규칙이 없다)".to_string();
    }
    m.detect
        .iter()
        .map(|r| r.id.as_str())
        .collect::<Vec<_>>()
        .join(" · ")
}

/// 아직 구현되지 않았다면 예정 Phase 를 돌려준다.
fn pending(s: Subject) -> Option<Phase> {
    let p = s.info().implemented_in;
    if p > IMPLEMENTED_THROUGH {
        Some(p)
    } else {
        None
    }
}

#[cfg(test)]
mod min_core_tests {
    use super::*;

    fn min_core_issues(v: &str) -> Vec<SchemaIssue> {
        let y = format!(
            "schema_version: 1\nid: x\nversion: 0.1.0\nmin_core: '{v}'\nplatforms: [linux]\n\
             name: {{ ko: 'x', en: 'x' }}\nscan_roots: ['/opt/x']\nsubjects: [file]\n\
             detect:\n  - id: a\n    subject: file\n    where:\n      \
             - {{ field: path, op: ends_with, value: 'x' }}\nverdict: {{ require: 'a' }}\n"
        );
        let m: PluginManifest = serde_yaml_ng::from_str(&y).expect("시험 매니페스트");
        validate(&m)
            .into_iter()
            .filter(|i| i.at == "min_core")
            .collect()
    }

    /// 이 자리가 **검사·치료가 룰을 읽는 자리**다 — 막는 문제(`available_in` 없음)여야
    /// `load_manifest` 가 시작 전에 멈춘다.
    #[test]
    fn a_rule_that_needs_a_newer_core_does_not_load() {
        let (a, b, c) = semver3(env!("CARGO_PKG_VERSION")).expect("코어 버전");
        for newer in [
            format!("{a}.{b}.{}", c + 1),
            format!("{a}.{}.0", b + 1),
            format!("{}.0.0", a + 1),
        ] {
            let found = min_core_issues(&newer);
            assert_eq!(found.len(), 1, "{newer}: {found:?}");
            assert!(
                found[0].available_in.is_none(),
                "기다리면 풀리는 문제가 아니라 막는 문제다"
            );
        }
    }

    #[test]
    fn this_core_or_an_older_one_loads() {
        for v in [env!("CARGO_PKG_VERSION"), "1.0.0", "0.1.0"] {
            assert!(min_core_issues(v).is_empty(), "{v}");
        }
    }

    #[test]
    fn a_version_that_does_not_parse_is_an_error_not_a_pass() {
        for v in ["P10", "1.2", "1.2.0-rc.1", "1.2.0.0", ""] {
            assert_eq!(min_core_issues(v).len(), 1, "{v}");
        }
    }
}
