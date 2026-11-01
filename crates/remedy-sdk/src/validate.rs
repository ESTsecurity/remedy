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
