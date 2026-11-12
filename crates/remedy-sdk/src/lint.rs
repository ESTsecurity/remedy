//! `plugin lint` — 참조·범위·방향 제약·정규식·과광범위 (설계-09 P3).
//!
//! `validate` 와 나눈 기준은 **언제 발견되어야 하는가**다.
//!
//! - `validate` 는 코어가 매니페스트를 **로드할 때마다** 돈다. 여기서 막지 않으면
//!   잘못된 룰이 실기기에서 돈다. 그래서 값이 싸야 하고 확실한 것만 본다.
//! - `lint` 는 작성자가 **손에 들고 있을 때** 돈다. 정규식 컴파일처럼 비싼 검사와,
//!   "틀렸다" 가 아니라 "이래도 되겠는가" 인 경고를 여기서 낸다.
//!
//! # 경고를 오류와 섞지 않는다
//!
//! 과광범위 경고는 **오경보를 낸다.** 실제로 넓은 범위가 필요한 플러그인이 있고,
//! 그것을 오류로 막으면 작성자는 우회로를 만든다. 경고는 사람이 판단할 재료이고,
//! 오류는 기계가 막는 선이다. 섞으면 둘 다 무뎌진다.

use crate::catalog::{Op, Operator, Subject, RESTORE_DEFAULTS};
use crate::manifest::{
    CollectExtra, Condition, PluginManifest, Predicate, RemoveTarget, RestoreTarget,
};
use crate::validate::SchemaIssue;
use std::collections::BTreeSet;

/// 얼마나 심각한가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// 이 플러그인은 로드되지 않는다.
    Error,
    /// 로드되지만 작성자가 봐야 한다. **오경보가 있을 수 있다.**
    Warning,
}

impl Severity {
    pub const fn label(self) -> &'static str {
        match self {
            Severity::Error => "오류",
            Severity::Warning => "경고",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintIssue {
    pub severity: Severity,
    /// 문제가 있는 위치. 예: `detect[1].where[0].value`
    pub at: String,
    pub message: String,
    /// 무엇을 쓸 수 있는지. **유효값을 전수로 준다** (설계-09 P3).
    ///
    /// 유효값을 알려 주지 않으면 작성자는 문서를 뒤지거나 추측한다. 추측이
    /// 통과하면 그 추측이 다음 룰에도 쓰인다.
    pub valid: Option<String>,
    /// 근거 문서 앵커. 예: `설계-03 §3`
    pub doc: Option<&'static str>,
}

impl std::fmt::Display for LintIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.severity.label(), self.at, self.message)?;
        if let Some(v) = &self.valid {
            write!(f, "\n      쓸 수 있는 것: {v}")?;
        }
        if let Some(d) = self.doc {
            write!(f, "\n      근거: {d}")?;
        }
        Ok(())
    }
}

fn err(at: impl Into<String>, message: impl Into<String>, doc: &'static str) -> LintIssue {
    LintIssue {
        severity: Severity::Error,
        at: at.into(),
        message: message.into(),
        valid: None,
        doc: Some(doc),
    }
}

fn warn(at: impl Into<String>, message: impl Into<String>, doc: &'static str) -> LintIssue {
    LintIssue {
        severity: Severity::Warning,
        at: at.into(),
        message: message.into(),
        valid: None,
        doc: Some(doc),
    }
}

/// 매니페스트 전체를 검사한다. `validate` 의 결과도 함께 담는다 — 작성자가 두
/// 명령을 기억해야 한다면 하나는 안 돌린다.
pub fn lint(m: &PluginManifest) -> Vec<LintIssue> {
    let mut out: Vec<LintIssue> = crate::validate(m).iter().map(from_schema).collect();

    let ids: BTreeSet<&str> = m.detect.iter().map(|r| r.id.as_str()).collect();
    check_duplicate_rule_ids(m, &mut out);
    check_references(m, &ids, &mut out);
    check_fields(m, &mut out);
    check_unpopulated_fields(m, &mut out);
    check_package_fields(m, &mut out);
    check_enumerated_values(m, &mut out);
    check_sha256_literals(m, &mut out);
    check_version_literals(m, &mut out);
    check_subject_reachability(m, &mut out);
    check_subject_roots(m, &mut out);
    check_text_config_dirs(m, &mut out);
    check_regexes(m, &mut out);
    check_reputation_direction(m, &mut out);
    check_remediate_refs(m, &ids, &mut out);
    check_collect_extra_refs(m, &ids, &mut out);
    check_collect_extra_globs(m, &mut out);
    check_yara_without_content(m, &mut out);
    check_restore_named(m, &mut out);
    check_from_subject(m, &mut out);
    check_restore_defaults(m, &ids, &mut out);
    check_overbroad(m, &mut out);
    check_recursive_scope(m, &mut out);
    check_subject_platform(m, &mut out);
    check_edit_platform(m, &mut out);
    check_name(m, &mut out);
    out
}

/// `name` 은 **고객 화면의 첫 줄**이다 (2026-09-06 부터). 두 언어가 다 있어야
/// 한다 — `ko` 만 있으면 영어 화면에 한국어 이름이 나오고, 비어 있으면 위협
/// 이름 줄이 조용히 빠진다. 둘 다 실측했다.
fn check_name(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    for lang in ["ko", "en"] {
        let blank = m
            .name
            .get(lang)
            .map(|v| v.trim().is_empty())
            .unwrap_or(true);
        if blank {
            out.push(LintIssue {
                severity: Severity::Error,
                at: format!("name.{lang}"),
                message: format!(
                    "'{lang}' 표시명이 없다. name 은 고객 화면의 첫 줄이라 두 언어가 다 있어야 한다"
                ),
                valid: Some("name: { ko: \"<위협> 제거\", en: \"<Threat> removal\" }".into()),
                doc: Some("10-manifest.md"),
            });
        }
    }
}

/// 선언한 subject 를 **그 플랫폼에서 실제로 수집할 수 있는가** (설계-09 P12).
///
/// # 왜 필요한가
///
/// `SubjectInfo` 의 `windows`/`linux` 는 오래 **문서 생성에만** 쓰였다. 그래서
/// 아래가 오류 0 · 경고 0 으로 통과했다 — 실측이다.
///
/// ```yaml
/// platforms: [linux]
/// subjects: [autorun, service, av_exclusion]
/// ```
///
/// 셋 다 수집기가 `RegistryRead` 전용이다. Linux 에서 돌리면 수집이 통째로
/// `Unsupported` 로 죽거나, 백엔드가 빈 값을 내면 **0건을 조용히 보고한다.**
/// 어느 쪽이든 작성자는 룰이 왜 안 맞는지 모른다.
///
/// # 오류와 경고를 가르는 것
///
/// **그 플랫폼**이 전부인 플러그인은 아무 데서도 동작하지 못하므로 오류다.
/// 교차 플랫폼 플러그인은 Windows 에서 동작하므로 경고다 — 오류로 막으면
/// `platforms` 에 linux 를 더하는 것만으로 멀쩡한 Windows 룰이 거부된다.
///
/// # 메시지가 두 가지를 구분한다
///
/// 개념이 없는 것(`registry_value`)과 수집기가 없는 것(`service`)은 작성자가
/// 할 일이 다르다. 앞은 룰을 다시 짜야 하고, 뒤는 요청하면 된다.
fn check_subject_platform(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    use crate::catalog::Platform;
    if !m.platforms.contains(&Platform::Linux) {
        return;
    }
    let only_linux = m.platforms.len() == 1;
    for s in &m.subjects {
        let i = s.info();
        if i.linux_from.is_some() {
            continue;
        }
        let why = if i.linux {
            format!(
                "Linux 에 개념은 있으나 이 코어의 '{}' 수집기가 Windows 전용이다",
                i.id
            )
        } else {
            format!("'{}' 는 Linux 에 개념이 없다", i.id)
        };
        let issue = LintIssue {
            severity: if only_linux {
                Severity::Error
            } else {
                Severity::Warning
            },
            at: format!("subjects.{}", i.id),
            message: if only_linux {
                format!("{why}. 이 플러그인은 Linux 전용이므로 아무것도 수집하지 못한다")
            } else {
                format!("{why}. Windows 에서는 동작하지만 **Linux 에서는 0건**이 된다")
            },
            valid: Some(linux_collectable()),
            doc: Some("설계-09 P12"),
        };
        out.push(issue);
    }
}

/// `edit` 가 Linux 에서 설 자리가 있는가 (설계-09 P12).
///
/// 계획기가 `edit` 로 세우는 Op 은 둘이다 — 검색 경로면 `env.strip_path`, 아니면
/// `registry.strip_value`(`remedy-plan` derive.rs 의 edit 절). 둘 다 Linux 칸이
/// 비어 있으면 계획기는 그 edit 를 **보류**로 빼고, 사유는 *"이 Op 은 지금 수행할
/// 수 없다"* 뿐이다 (2026-09-28 npm-r1 사전 기준의 변형). 오류와 경고를 가르는
/// 것은 `check_subject_platform` 과 같다.
fn check_edit_platform(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    use crate::catalog::Platform;
    const EDIT_OPS: [Op; 2] = [Op::RegistryStripValue, Op::EnvStripPath];
    let Some(rem) = &m.remediate else { return };
    if rem.edit.is_empty()
        || !m.platforms.contains(&Platform::Linux)
        || EDIT_OPS.iter().any(|o| o.info().linux_from.is_some())
    {
        return;
    }
    let only_linux = m.platforms.len() == 1;
    let ops = EDIT_OPS.map(|o| o.id()).join(" · ");
    for i in 0..rem.edit.len() {
        out.push(LintIssue {
            severity: if only_linux {
                Severity::Error
            } else {
                Severity::Warning
            },
            at: format!("remediate.edit[{i}]"),
            message: if only_linux {
                format!(
                    "부분 편집 Op({ops})이 Linux 에 없다. 이 플러그인은 Linux 전용이므로 \
                     이 edit 는 늘 보류된다"
                )
            } else {
                format!(
                    "부분 편집 Op({ops})이 Linux 에 없다. Windows 에서는 동작하지만 \
                     **Linux 에서는 보류**된다"
                )
            },
            valid: None,
            doc: Some("설계-09 P12"),
        });
    }
}

/// Linux 에서 지금 수집되는 subject 목록. 린트가 대안을 제시할 때 쓴다.
fn linux_collectable() -> String {
    let ids: Vec<&str> = crate::catalog::Subject::ALL
        .iter()
        .map(|s| s.info())
        .filter(|i| i.linux_from.is_some())
        .map(|i| i.id)
        .collect();
    format!("Linux 에서 수집되는 subject: {}", ids.join(" · "))
}

/// `restore` 의 참조와 `to: default` 의 대상 (설계-03 §2).
///
/// # 두 가지를 본다
///
/// **없는 규칙을 가리키는 것.** `check_remediate_refs` 는 `remove` 와 `edit` 만
/// 보고 `restore` 를 보지 않았다.
///
/// **카탈로그에 없는 대상을 되돌리려는 것.** `restore_default` 는 코어가 내장한
/// 값만 쓸 수 있다 — 플러그인이 임의 값을 지정할 수 있으면 서명된 도구가 임의
/// 레지스트리 값을 쓸 수 있는 것이고, 그 자체가 공격 도구다.
///
/// 규칙이 대상을 리터럴로 고정했을 때만 여기서 판단할 수 있다. 그러지 않은
/// 규칙은 대상이 증거에 따라 달라지므로 **계획 단계가 본다** — 그 사실을
/// 경고로 남긴다. 조용히 통과시키면 "린트 통과" 가 거짓말이 된다.
fn check_restore_defaults(m: &PluginManifest, ids: &BTreeSet<&str>, out: &mut Vec<LintIssue>) {
    let Some(rem) = &m.remediate else { return };
    let known_rules = ids.iter().cloned().collect::<Vec<_>>().join(" · ");
    let known_targets = RESTORE_DEFAULTS
        .iter()
        .map(|(t, _)| *t)
        .collect::<Vec<_>>()
        .join(" · ");

    for (i, r) in rem.restore.iter().enumerate() {
        let RestoreTarget::ToDefault(d) = r else {
            continue;
        };
        let at = format!("remediate.restore[{i}].ref");
        let Some(rule) = m.detect.iter().find(|x| x.id == d.rule_ref) else {
            out.push(LintIssue {
                severity: Severity::Error,
                at,
                message: format!("없는 규칙 '{}' 를 가리킨다", d.rule_ref),
                valid: Some(known_rules.clone()),
                doc: Some("설계-02 §6"),
            });
            continue;
        };
        match pinned_registry_target(rule) {
            Some(target) if crate::catalog::restore_default_for(&target).is_some() => {}
            Some(target) => out.push(LintIssue {
                severity: Severity::Error,
                at: format!("remediate.restore[{i}]"),
                message: format!(
                    "'{target}' 은 OS 기본값 카탈로그에 없다. \
                     값 하나로 복원이 완결되는 대상만 담는다 — 구조 전체가 필요한 것은 \
                     탐지·보고만 하고 OS 복구 도구로 넘긴다"
                ),
                valid: Some(known_targets.clone()),
                doc: Some("설계-03 §2"),
            }),
            None => out.push(warn(
                format!("remediate.restore[{i}]"),
                format!(
                    "'{}' 이 대상을 리터럴로 고정하지 않아 여기서 확인하지 못했다. \
                     계획 단계에서 카탈로그에 없으면 그 Action 은 만들어지지 않는다",
                    d.rule_ref
                ),
                "설계-03 §2",
            )),
        }
    }
}

/// 규칙이 레지스트리 대상을 **리터럴로 고정했는가.**
///
/// `hive` · `key` · `name` 을 전부 `equals` 로 못박았을 때만 대상이 정해진다.
/// `glob` 이나 `contains` 면 증거마다 달라지므로 여기서는 알 수 없다.
fn pinned_registry_target(rule: &crate::manifest::DetectRule) -> Option<String> {
    if rule.subject != Subject::RegistryValue {
        return None;
    }
    let mut preds = Vec::new();
    flatten_condition(&rule.condition, "", &mut preds);
    let pick = |want: &str| -> Option<String> {
        preds.iter().find_map(|(_, p)| match p {
            Predicate::Field(f) if f.field == want && f.op == Operator::Equals => f
                .value
                .as_ref()
                .and_then(|v| v.as_str())
                .map(str::to_string),
            _ => None,
        })
    };
    Some(format!(
        "{}\\{}\\{}",
        pick("hive")?,
        pick("key")?,
        pick("name")?
    ))
}

/// `collect_extra` 의 `ref` 가 실재하는 규칙을 가리키는가 (설계-02 §6-1).
///
/// **없는 규칙을 가리키면 그 항목은 영영 해소되지 않는다.** 해소는 평가 뒤에
/// 일어나므로 작성자가 그 사실을 아는 것은 실행 뒤이고, 그때 나오는 것은
/// "미해소" 한 줄이다. 룰을 고칠 수 있는 자리에서 미리 말해 주는 편이 낫다.
fn check_collect_extra_refs(m: &PluginManifest, ids: &BTreeSet<&str>, out: &mut Vec<LintIssue>) {
    let known = ids.iter().cloned().collect::<Vec<_>>().join(" · ");
    for (i, item) in m.collect_extra.iter().enumerate() {
        let CollectExtra::Ref(r) = item else { continue };
        if ids.contains(r.rule_ref.as_str()) {
            continue;
        }
        out.push(LintIssue {
            severity: Severity::Error,
            at: format!("collect_extra[{i}].ref"),
            message: format!("없는 규칙 '{}' 를 가리킨다", r.rule_ref),
            valid: Some(known.clone()),
            doc: Some("설계-02 §6-1"),
        });
    }
}

/// `restore` 의 이름 지정이 **되돌릴 증거를 가질 수 있는가** (설계-03 §2).
///
/// `restore: [av_exclusions]` 는 `av_exclusion` subject 의 **증거**를 되돌린다.
/// 그 subject 를 탐지하는 규칙이 하나도 없으면 되돌릴 것이 영영 잡히지 않고,
/// **Action 이 조용히 안 나온다** — `deferred` 에도 걸리지 않으므로 사용자는
/// 치료가 끝난 줄 안다.
///
/// AI 합격 시험 r0 이 이 결함을 안은 채 세 판정을 전부 통과했다. Defender
/// 제외 경로가 그대로 남는 계획이었다.
///
/// # 이름이 표에 없으면 — 한 걸음 앞의 같은 결함
///
/// `RESTORE_NAMED` 는 **넷뿐인 닫힌 집합**이다(`av_exclusions` · `hosts` ·
/// `proxy` · `firewall`). 그 밖의 이름을 적으면 `restore_op` 이
/// `.unwrap_or(Op::RegistryRestoreDefault)` 로 받아 **엉뚱한 Op 이 된다.**
///
/// 2026-09-03 Linux 하네스가 이것을 밟았다 — 규칙 id 를 적었고
/// (`restore: [hostline]`), 린트는 **오류 0 · 경고 0** 을 냈으며, 계획은
/// `registry.restore_default` 를 만들어 *"linux 에는 개념이 없다"* 며 미뤘다.
/// hosts 줄은 영영 되돌아오지 않는데 작성자에게 그 사실을 말해 주는 것이
/// 아무 데도 없었다.
///
/// 값 어휘·판정 문법·subject 도달성과 같은 부류다 — **닫힌 집합이 소스에만
/// 있으면 작성자는 그것을 지킬 방법이 없다.**
fn check_restore_named(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    let Some(rem) = &m.remediate else { return };
    let known_names = crate::catalog::RESTORE_NAMED
        .iter()
        .map(|(n, _, _)| *n)
        .collect::<Vec<_>>()
        .join(" · ");
    for (i, r) in rem.restore.iter().enumerate() {
        let RestoreTarget::Named(n) = r else { continue };
        let Some(subject) = crate::catalog::restore_named_subject(n) else {
            out.push(LintIssue {
                severity: Severity::Error,
                at: format!("remediate.restore[{i}]"),
                message: format!(
                    "'{n}' 은 이름으로 지정할 수 있는 원복이 아니다. \
                     여기는 규칙 id 를 적는 자리가 아니라 **되돌릴 대상의 이름**을 \
                     적는 자리이고, 모르는 이름은 조용히 엉뚱한 Op 이 되어 \
                     되돌리기가 통째로 빠진다"
                ),
                valid: Some(known_names.clone()),
                doc: Some("설계-03 §2"),
            });
            continue;
        };
        if m.detect.iter().any(|d| d.subject == subject) {
            continue;
        }
        out.push(LintIssue {
            severity: Severity::Error,
            at: format!("remediate.restore[{i}]"),
            message: format!(
                "'{n}' 은 {} 증거를 되돌리는데 그 subject 를 탐지하는 규칙이 없다 \
                 — 되돌릴 것이 잡히지 않아 Action 이 만들어지지 않는다",
                subject.id()
            ),
            valid: Some(format!(
                "subject: {} 규칙을 하나 두고 우리 경로를 짚는다",
                subject.id()
            )),
            doc: Some("설계-03 §2"),
        });
    }
}

/// `from` 이 **통할 수 있는 subject 인가** (설계-02 §4).
///
/// `from` 은 레코드의 `path` 필드를 읽어 그 디렉터리 안인지 본다
/// (`remedy-detect/src/eval.rs`). `path` 가 없는 subject 는 빈 문자열과
/// 비교되어 **모든 레코드가 걸러진다** — 그 규칙은 영영 매치되지 않는다.
///
/// **오류로 잡는 이유**: 미매치는 "안 맞았다" 와 구분되지 않는다. 린트가
/// 아니면 아무 데서도 드러나지 않고, 그 규칙이 제거 대상이었다면 조용히
/// 빠진다.
///
/// AI 합격 시험 r0 이 `autorun` 규칙에 `from` 을 걸어 Run 값 제거를 통째로
/// 잃었다. 그러고도 세 판정을 전부 통과했다 — 위협 설명이 *"둘 중 하나만
/// 지우면 나머지가 다시 살린다"* 고 경고한 바로 그 항목이다.
fn check_from_subject(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    let usable: Vec<&str> = crate::catalog::Subject::ALL
        .iter()
        .filter(|s| s.fields().contains(&"path"))
        .map(|s| s.id())
        .collect();
    for r in &m.detect {
        if r.from.is_none() || r.subject.fields().contains(&"path") {
            continue;
        }
        out.push(LintIssue {
            severity: Severity::Error,
            at: format!("detect[{}].from", r.id),
            message: format!(
                "subject '{}' 에는 path 필드가 없어 from 이 통하지 않는다 \
                 — 이 규칙은 아무 레코드도 매치하지 못한다",
                r.subject.id()
            ),
            valid: Some(format!(
                "from 을 쓸 수 있는 subject: {} · 그 밖에는 where 값에 \
                 ${{다른규칙.capture}} 를 넣어 묶는다",
                usable.join(" · ")
            )),
            doc: Some("설계-02 §4"),
        });
    }
}

/// `collect_extra` 의 `glob` 이 **고를 수 있는 자리**를 가리키는가.
///
/// 글롭은 주 수집이 걸은 `file` 레코드에서 고른다. 그래서 셋 중 하나라도 어긋나면
/// 오류 없이 **조용히 0건**이고, 그 본문에 걸린 YARA 는 "안 맞았다" 로 나간다 —
/// 와일드카드가 폴더 쪽에 있다(한 폴더만 고른다) · 폴더가 `scan_roots` 밖이다(레코드가
/// 없다) · `file` 이 `subjects` 에 없다(레코드가 없다).
fn check_collect_extra_globs(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    for (i, item) in m.collect_extra.iter().enumerate() {
        let CollectExtra::Glob(g) = item else {
            continue;
        };
        let at = format!("collect_extra[{i}].glob");
        let cut = g.glob.rfind(['/', '\\']);
        let dir = cut.map(|c| &g.glob[..c]).unwrap_or("");
        let name = cut.map(|c| &g.glob[c + 1..]).unwrap_or(g.glob.as_str());
        if dir.is_empty() || name.is_empty() || dir.contains(['*', '?']) {
            out.push(LintIssue {
                severity: Severity::Error,
                at,
                message: format!(
                    "'{}' 가 `<폴더>/<이름 꼴>` 이 아니다. 와일드카드(`*` · `?`)는 마지막 \
                     성분에만 둔다 — 한 폴더 안만 고르므로 담는 범위가 선언에서 바로 읽힌다",
                    g.glob
                ),
                valid: Some("예: `/usr/lib64/libkeyutils*`".into()),
                doc: Some("설계-02 §6-1"),
            });
            continue;
        }
        if !m.scan_roots.iter().any(|top| root_covers(top, dir)) {
            out.push(LintIssue {
                severity: Severity::Error,
                at: at.clone(),
                message: format!(
                    "'{dir}' 가 `scan_roots` 밖이다. 글롭은 주 수집이 걸은 레코드에서 고르므로 \
                     그 폴더에는 고를 것이 없고, 결과는 조용한 0건이다"
                ),
                valid: Some(format!(
                    "`scan_roots` 안의 폴더로 적을 것 — 지금 상한: {}",
                    m.scan_roots.join(" · ")
                )),
                doc: Some("설계-02 §2"),
            });
        }
        if !m.subjects.contains(&Subject::File) {
            out.push(LintIssue {
                severity: Severity::Error,
                at,
                message: "`subjects` 에 `file` 이 없다. 글롭은 `file` 레코드에서 고르므로 \
                          고를 것이 없고, 결과는 조용한 0건이다"
                    .into(),
                valid: Some("`subjects` 에 `file` 을 넣을 것".into()),
                doc: Some("설계-02 §6-1"),
            });
        }
    }
}

/// YARA 를 쓰는데 **본문을 수집하지 않는가** (설계-02 §6-1 · 설계-06 §6).
///
/// YARA 술어는 레코드의 `content_ref` 가 가리키는 본문을 훑는다. 그 본문은
/// `collect_extra` 가 선언해야 스냅샷에 담긴다. 선언이 없으면 평가기는
/// **"안 맞았다" 가 아니라 "재지 못했다"** 를 내고, 그 규칙이 든 판정은 영영
/// 서지 않는다.
///
/// **감염 코퍼스는 이 결함을 가린다.** 코퍼스 스냅샷에는 본문이 이미 담겨
/// 있어 룰이 정상으로 보이고, 실기기 `scan` 에서야 미평가로 드러난다 —
/// P9 5번과 같은 은폐 구조다. 실제로 AI 합격 시험 2 회차가 이 결함을 가진
/// 채 세 판정을 전부 통과했다.
///
/// **정확히 재지는 못한다.** 어느 `collect_extra` 항목이 어느 레코드의 본문을
/// 담는지는 평가 시점에 정해지므로, 여기서는 *본문을 담는 선언이 하나라도
/// 있는가*만 본다. 확실히 틀린 경우만 잡고 애매한 것은 통과시킨다.
fn check_yara_without_content(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    let yara_at = m.detect.iter().find_map(|r| {
        let mut preds = Vec::new();
        flatten_condition(&r.condition, &format!("detect[{}].where", r.id), &mut preds);
        preds.into_iter().find_map(|(at, p)| match p {
            Predicate::Yara(_) => Some(at),
            Predicate::Field(f) if f.op.id() == "yara" => Some(at),
            _ => None,
        })
    });
    let Some(at) = yara_at else { return };

    // 본문을 담는 선언 — `ref` 는 `content: true` 일 때만이고, `path` 와
    // `subject` 는 본문을 담는 것 자체가 그 형의 목적이다.
    let collects_content = m.collect_extra.iter().any(|c| match c {
        CollectExtra::Ref(r) => r.content,
        CollectExtra::Path(_) | CollectExtra::Glob(_) => true,
        // `subject` 형은 **본문을 담지 않는다.** "이 경로를 이 subject 로도
        // 보라" 는 뜻이고, 실제 수집은 그 subject 의 수집기가 한다
        // (remedy-collect/src/extra.rs). 여기서 본문으로 세면 YARA 가 실기기에서
        // 미평가인 매니페스트가 그대로 통과한다.
        CollectExtra::Subject(_) => false,
    });
    if collects_content {
        return;
    }

    out.push(LintIssue {
        severity: Severity::Error,
        at,
        message: "YARA 를 쓰는데 collect_extra 가 본문을 담지 않는다 — \
                  실기기에서 이 규칙은 미평가가 되고 판정이 서지 않는다"
            .into(),
        valid: Some(
            "collect_extra 에 `{ ref: <경로로 매치되는 규칙>, content: true }` 를 둔다".into(),
        ),
        doc: Some("설계-06 §6"),
    });
}

fn from_schema(i: &SchemaIssue) -> LintIssue {
    LintIssue {
        severity: Severity::Error,
        at: i.at.clone(),
        message: match i.available_in {
            Some(p) => format!("{} ({} 에서 사용 가능해진다)", i.message, p.as_str()),
            None => i.message.clone(),
        },
        valid: i.valid.clone(),
        doc: i.doc,
    }
}

/// 같은 id 가 둘이면 `${a.x}` 가 어느 것을 가리키는지 알 수 없다.
fn check_duplicate_rule_ids(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (i, r) in m.detect.iter().enumerate() {
        if !seen.insert(r.id.as_str()) {
            out.push(err(
                format!("detect[{i}].id"),
                format!(
                    "규칙 id '{}' 가 중복이다. 참조가 어느 것을 가리키는지 알 수 없다",
                    r.id
                ),
                "설계-02 §4",
            ));
        }
    }
}

/// `${rule.capture}` 참조가 실재하는가.
///
/// 없는 규칙을 가리키면 그 조건은 영원히 해소되지 않고, **조용히 미매치가 된다.**
/// 작성자는 룰이 안 맞는 이유를 찾느라 시간을 버린다.
fn check_references(m: &PluginManifest, ids: &BTreeSet<&str>, out: &mut Vec<LintIssue>) {
    let known = || ids.iter().cloned().collect::<Vec<_>>().join(" · ");

    for (i, rule) in m.detect.iter().enumerate() {
        let mut refs: Vec<(String, String)> = Vec::new();
        if let Some(f) = &rule.from {
            collect_refs(f, &format!("detect[{i}].from"), &mut refs);
        }
        for (name, expr) in &rule.capture {
            collect_refs(expr, &format!("detect[{i}].capture.{name}"), &mut refs);
        }
        collect_condition_refs(&rule.condition, &format!("detect[{i}].where"), &mut refs);

        for (at, key) in refs {
            // `${name}` 은 같은 규칙 안의 capture 다. `${rule.name}` 만 규칙 참조다.
            let Some((rule_id, capture)) = key.split_once('.') else {
                if !rule.capture.contains_key(&key) {
                    out.push(LintIssue {
                        severity: Severity::Error,
                        at,
                        message: format!("'${{{key}}}' 는 이 규칙의 capture 가 아니다"),
                        valid: Some(if rule.capture.is_empty() {
                            "(이 규칙에는 capture 가 없다)".into()
                        } else {
                            rule.capture.keys().cloned().collect::<Vec<_>>().join(" · ")
                        }),
                        doc: Some("설계-02 §4"),
                    });
                }
                continue;
            };
            if rule_id == rule.id {
                continue;
            }
            if !ids.contains(rule_id) {
                out.push(LintIssue {
                    severity: Severity::Error,
                    at,
                    message: format!("'${{{key}}}' 가 없는 규칙 '{rule_id}' 를 가리킨다"),
                    valid: Some(known()),
                    doc: Some("설계-02 §4"),
                });
                continue;
            }
            let target = m.detect.iter().find(|r| r.id == rule_id);
            if let Some(t) = target {
                if !t.capture.contains_key(capture) {
                    out.push(LintIssue {
                        severity: Severity::Error,
                        at,
                        message: format!("규칙 '{rule_id}' 에 capture '{capture}' 가 없다"),
                        valid: Some(if t.capture.is_empty() {
                            format!("(규칙 '{rule_id}' 에는 capture 가 없다)")
                        } else {
                            t.capture.keys().cloned().collect::<Vec<_>>().join(" · ")
                        }),
                        doc: Some("설계-02 §4"),
                    });
                }
            }
        }
    }

    // verdict 가 없는 규칙을 참조하면 판정이 영원히 성립하지 않는다.
    for token in verdict_tokens(&m.verdict.require) {
        if !ids.contains(token.as_str()) {
            out.push(LintIssue {
                severity: Severity::Error,
                at: "verdict.require".into(),
                message: format!("없는 규칙 '{token}' 를 참조한다"),
                valid: Some(known()),
                doc: Some("설계-02 §5"),
            });
        }
    }
    // `verdict.unconfirmed` 도 같다 — 서지 않는 줄은 *확인 필요* 를 조용히 0 으로 만든다.
    for (i, u) in m.verdict.unconfirmed.iter().enumerate() {
        for token in verdict_tokens(&u.when) {
            if !ids.contains(token.as_str()) {
                out.push(LintIssue {
                    severity: Severity::Error,
                    at: format!("verdict.unconfirmed[{i}].when"),
                    message: format!("없는 규칙 '{token}' 를 참조한다"),
                    valid: Some(known()),
                    doc: Some("docs/plugin-guide/24-check-plugins.md"),
                });
            }
        }
    }
}

/// 필드 이름이 그 subject 에 **실재하는가** (설계-06 §6·§7).
///
/// 사람은 모르면 묻지만 AI 는 지어낸다. 없는 필드를 쓴 룰은 조용히 아무것도
/// 매치하지 않고, 작성자는 룰이 틀렸다고 생각한다.
///
/// `unknown field "cmdline"` 만 주면 다시 지어낸다. **유효 필드 전수**를 함께
/// 줘야 그 자리에서 고친다 — 그것이 이 검사의 본체다.
fn check_fields(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    let mut unknown_subjects: BTreeSet<&str> = BTreeSet::new();

    for (i, rule) in m.detect.iter().enumerate() {
        let known = rule.subject.fields();
        let mut preds = Vec::new();
        flatten_condition(&rule.condition, &format!("detect[{i}].where"), &mut preds);
        for p in &rule.exclude {
            preds.push((format!("detect[{i}].exclude"), p));
        }

        for (at, p) in preds {
            let Predicate::Field(f) = p else { continue };

            // `file(command).signature.subject` 처럼 다른 subject 로 건너뛰는
            // 참조는 P4 의 표면이다. 여기서 없는 필드로 잡으면 안 된다.
            if f.field.contains('(') {
                continue;
            }

            if known.is_empty() {
                // **건너뛴 사실을 남긴다.** 조용히 통과시키면 "린트 통과" 가
                // 거짓말이 된다.
                unknown_subjects.insert(rule.subject.id());
                continue;
            }

            if !known.contains(&f.field.as_str()) {
                out.push(LintIssue {
                    severity: Severity::Error,
                    at: format!("{at}.field"),
                    message: format!(
                        "'{}' 는 subject '{}' 에 없는 필드다",
                        f.field,
                        rule.subject.id()
                    ),
                    valid: Some(known.join(" · ")),
                    doc: Some("설계-02 §3"),
                });
            }

            // `win.*` 를 쓰면서 windows 를 선언하지 않으면 조용히 아무것도
            // 매치하지 않는 "크로스플랫폼인 척하는 룰" 이 된다 (설계-02 §3).
            if f.field.starts_with("win.")
                && !m.platforms.contains(&crate::catalog::Platform::Windows)
            {
                out.push(LintIssue {
                    severity: Severity::Error,
                    at: format!("{at}.field"),
                    message: format!(
                        "'{}' 는 Windows 고유 필드인데 platforms 에 windows 가 없다",
                        f.field
                    ),
                    valid: Some("platforms: [windows]".into()),
                    doc: Some("설계-02 §3"),
                });
            }
        }
    }

    for s in unknown_subjects {
        out.push(warn(
            format!("subject '{s}'"),
            format!(
                "'{s}' 의 필드 목록이 아직 정의되지 않아 필드 이름을 검사하지 못했다.                  오타나 없는 필드가 있어도 여기서 걸리지 않는다"
            ),
            "설계-02 §3",
        ));
    }
}

/// **정의는 됐는데 아직 채워지지 않는 필드**를 쓰고 있는가.
///
/// `check_fields` 는 "없는 필드" 를 잡는다. 이것은 **있는데 언제나 비어 있는
/// 필드**를 잡는다 — 이름이 맞으므로 거기서는 통과하고, 룰은 조용히 거짓이
/// 된다.
///
/// **`exclude` 에 있으면 더 무겁다.** 제외가 일어나지 않으므로 조용히 더
/// 공격적인 쪽으로 무너진다. 그래서 자리(`at`)에 어느 절인지가 드러나야 한다.
///
/// 다른 subject 로 건너뛰는 참조(`file(command).signature.subject`)도 본다 —
/// `check_fields` 는 그것을 건너뛰지만, **채워지지 않는다는 사실은 건너뛴
/// 자리에서도 그대로다.** EvilAI 초안의 오탐 방어가 정확히 그 모양이었다.
/// 매니페스트가 채워지지 않는 필드를 쓰는 자리 하나.
#[derive(Debug, Clone)]
pub struct UnpopulatedUse {
    /// 그 술어가 있는 규칙 id.
    pub rule: String,
    /// `detect[0].exclude` 처럼 자리 표기.
    pub at: String,
    /// 매니페스트에 적힌 그대로의 필드 표기.
    pub field: String,
    /// 왜 아직 비어 있는가.
    pub why: &'static str,
    /// `exclude` 절인가. **여기면 더 무겁다** — 제외가 일어나지 않으므로
    /// 조용히 더 공격적인 쪽으로 무너진다.
    pub in_exclude: bool,
    /// **어느 플랫폼에서** 비는가. `None` 은 어디서나.
    ///
    /// 메시지가 이것을 말해야 한다. "채우지 않는다" 와 "Linux 에서는 채우지
    /// 않는다" 는 작성자가 할 일이 다르다 — 앞은 룰을 다시 짜야 하고, 뒤는
    /// 플랫폼을 좁히거나 그 플랫폼에서 0건임을 받아들이면 된다.
    pub only_on: Option<crate::catalog::Platform>,
}

/// 매니페스트가 **아직 채워지지 않는 필드**를 쓰는 자리 전부.
///
/// # 왜 린트 밖으로 뺐는가
///
/// 린트와 평가기가 같은 사실을 말해야 하는데, 판단을 두 자리에 적으면
/// 갈라진다. 린트는 작성 시점에 경고하고 평가기는 `scan.json` 의 `issues` 에
/// 남긴다 — **린트는 건너뛸 수 있고, 실행하는 사람은 매니페스트를 읽지 않는다.**
/// `platforms` 는 **어느 플랫폼을 두고 묻는가**다. 부르는 쪽이 다르다 —
/// 린트는 매니페스트가 선언한 것을 주고, 평가기는 **스냅샷이 뜬 기계** 하나를
/// 준다. 같은 매니페스트라도 Windows 스냅샷에서는 `file.signature` 가 살아
/// 있고 Linux 스냅샷에서는 죽어 있다.
pub fn unpopulated_field_uses(
    m: &PluginManifest,
    platforms: &[crate::catalog::Platform],
) -> Vec<UnpopulatedUse> {
    let mut out = Vec::new();
    for (i, rule) in m.detect.iter().enumerate() {
        let mut preds = Vec::new();
        flatten_condition(&rule.condition, &format!("detect[{i}].where"), &mut preds);
        for p in &rule.exclude {
            preds.push((format!("detect[{i}].exclude"), p));
        }
        for (at, p) in preds {
            let Predicate::Field(f) = p else { continue };
            // **건너뛰는 참조도 본다.** `check_fields` 는 그것을 건너뛰지만,
            // 채워지지 않는다는 사실은 건너뛴 자리에서도 그대로다.
            let Some((subject, path)) = field_target(rule.subject, &f.field) else {
                continue;
            };
            for (s, field, only_on, why) in crate::catalog::Subject::NOT_POPULATED_YET {
                // `signature` 는 `signature.subject` 도 덮는다.
                if s != subject || !(path == field || path.starts_with(&format!("{field}."))) {
                    continue;
                }
                // **묻는 플랫폼에서 비는가.** 한 플랫폼에서만 비는 필드는 그
                // 플랫폼을 묻지 않는 쪽에게 말할 것이 없다 — 말하면 거짓이다.
                if let Some(p) = only_on {
                    if !platforms.contains(&p) {
                        break;
                    }
                }
                out.push(UnpopulatedUse {
                    rule: rule.id.clone(),
                    in_exclude: at.ends_with("exclude"),
                    at,
                    field: f.field.clone(),
                    why,
                    only_on,
                });
                break;
            }
        }
    }
    out
}

/// **정의는 됐는데 아직 채워지지 않는 필드**를 쓰고 있는가.
///
/// `check_fields` 는 "없는 필드" 를 잡는다. 이것은 **있는데 언제나 비어 있는
/// 필드**를 잡는다 — 이름이 맞으므로 거기서는 통과하고, 룰은 조용히 거짓이
/// 된다. EvilAI 초안의 첫 오탐 방어가 정확히 그 모양이었다 (설계-09 P9).
fn check_unpopulated_fields(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    for u in unpopulated_field_uses(m, &m.platforms) {
        let clause = if u.in_exclude {
            "exclude 라 제외가 일어나지 않는다. 걸러 내려던 것이 그대로 남는다"
        } else {
            "이 술어는 언제나 거짓이라 규칙이 매치되지 않는다"
        };
        out.push(LintIssue {
            severity: Severity::Warning,
            at: format!("{}.field", u.at),
            message: format!(
                "'{}' 는 {}아직 채우지 않는 필드다 — {clause}. {}",
                u.field,
                // **어디서 비는지를 말한다.** 한 플랫폼에서만 비는 것을
                // 뭉뚱그리면 다른 플랫폼 작성자에게 거짓이 된다.
                match u.only_on {
                    Some(p) => format!("이 코어가 {} 에서 ", p.id()),
                    None => "이 코어가 ".to_string(),
                },
                u.why
            ),
            valid: None,
            doc: Some("설계-02 §3"),
        });
    }
}

/// `file.package` · `file.package_match` 는 **`package` subject 를 함께 선언한 리눅스 룰에서만** 채운다(코어 1.7.0).
///
/// 패키지 DB 는 그 subject 의 고정 자리라 선언하지 않은 룰에서는 읽지 않고, Windows 에는 패키지 DB 가 없다. 그
/// 자리에서 두 칸을 보는 술어는 늘 거짓이라 — 바뀐 파일을 잡으려던 규칙이 조용히 서지 않는다.
fn check_package_fields(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    use crate::catalog::{Platform, Subject};
    let declared = m.subjects.contains(&Subject::Package);
    let linux_only = m.platforms.iter().all(|p| *p == Platform::Linux);
    if declared && linux_only {
        return;
    }
    for (i, rule) in m.detect.iter().enumerate() {
        let mut preds = Vec::new();
        flatten_condition(&rule.condition, &format!("detect[{i}].where"), &mut preds);
        for p in &rule.exclude {
            preds.push((format!("detect[{i}].exclude"), p));
        }
        for (at, p) in preds {
            let Predicate::Field(f) = p else { continue };
            let Some((s, path)) = field_target(rule.subject, &f.field) else {
                continue;
            };
            if s != Subject::File || !matches!(path, "package" | "package_match") {
                continue;
            }
            let why = if declared {
                "이 룰은 Windows 도 대상인데 Windows 에는 패키지 DB 가 없다"
            } else {
                "이 룰은 `package` subject 를 선언하지 않았다 — 패키지 DB 는 그 subject 의 고정 자리라 읽지 않는다"
            };
            out.push(LintIssue {
                severity: Severity::Warning,
                at: format!("{at}.field"),
                message: format!(
                    "'{}' 는 `package` subject 를 함께 선언한 리눅스 룰에서만 채운다 — {why}. 이 술어는 \
                     언제나 거짓이다",
                    f.field
                ),
                valid: None,
                doc: Some("설계-02 §3"),
            });
        }
    }
}

/// 술어의 필드 표기가 **어느 subject 의 어느 경로**를 가리키는가 — `file(command).signature.subject` 는
/// `(file, "signature.subject")`, 괄호가 없으면 그 규칙의 subject 다. 괄호 안이 모르는 subject 면 `None`.
fn field_target(
    rule_subject: crate::catalog::Subject,
    field: &str,
) -> Option<(crate::catalog::Subject, &str)> {
    let Some((head, rest)) = field.split_once('(') else {
        return Some((rule_subject, field));
    };
    let (_, tail) = rest.split_once(')')?;
    let s = crate::catalog::Subject::ALL
        .into_iter()
        .find(|s| s.id() == head)?;
    Some((s, tail.trim_start_matches('.')))
}

/// 이 매니페스트의 규칙이 `subject` 의 칸 `fields` 가운데 하나라도 쓰는가 — `where` 와 `exclude` 의 술어를
/// 본다(건너뛰는 참조 `process(...).modules` 도). 수집기가 값이 큰 칸을 **룰이 쓸 때만** 모으는 데 쓴다 —
/// Windows 의 프로세스 모듈 목록이 그렇다(`Scope::process_modules` · 2026-11-12).
pub fn uses_field(m: &PluginManifest, subject: crate::catalog::Subject, fields: &[&str]) -> bool {
    m.detect.iter().any(|rule| {
        let mut preds = Vec::new();
        flatten_condition(&rule.condition, "", &mut preds);
        preds.extend(rule.exclude.iter().map(|p| (String::new(), p)));
        preds.into_iter().any(|(_, p)| {
            let Predicate::Field(f) = p else {
                return false;
            };
            field_target(rule.subject, &f.field)
                .is_some_and(|(s, path)| s == subject && fields.contains(&path))
        })
    })
}

/// **선언한 subject 를 실제로 모을 수 있는가.**
///
/// `subjects` 에 적는 것과 그것이 모이는 것은 다르다. `scan_roots` 를 보는
/// subject 는 그 종류의 루트가 하나도 없으면 **언제나 0건**이고, 그 위에서
/// 도는 룰은 아무것도 맞히지 못한 채 초록이 된다. 실패가 "위협 없음" 과
/// 구분되지 않는다.
///
/// # 왜 스냅샷 시험이 이것을 못 잡는가
///
/// 예제와 코퍼스 시험은 **이미 뜬 스냅샷**으로 돈다. 수집이 끝난 자료라
/// "그 스냅샷을 뜰 수 있는가" 를 묻지 않는다. 우리 예제 `ex02` 가 정확히 그
/// 상태로 배포되고 있었다 — 부모 규칙이 `registry_value` 인데 `scan_roots`
/// 에 레지스트리 루트가 없어 실기기에서는 한 건도 모으지 못하는데, 번들
/// 스냅샷에는 레코드가 들어 있어 시험이 계속 초록이었다 (2026-09-02).
/// `subject_roots` 가 **좁히기만 하는가.**
///
/// # 넓히는 길이 없어야 한다
///
/// `scan_roots` 는 읽기 권한의 상한이다(설계-02 §2). `subject_roots` 가 그
/// 밖을 가리킬 수 있으면 상한이 둘이 되고, 서명 검토자는 두 곳을 다 읽어야
/// 무엇을 읽는 플러그인인지 안다. **안에 있어야 한다**는 규칙 하나로 상한을
/// 계속 한 곳에 둔다.
///
/// # 셋을 본다
///
/// - 선언하지 않은 subject 를 좁히는 것 — 아무 효과가 없고, 작성자는 좁혔다고
///   믿는다.
/// - 빈 목록 — "아무 데도 보지 않는다" 이고 결과는 조용한 0건이다.
/// - `scan_roots` 밖 — 위의 이유.
///
/// # 자리가 정해진 subject 에는 뜻이 없다
///
/// `Scoping::Fixed` 인 subject(`persistence`·`service`·`cert_store` 등)는
/// `scan_roots` 와 무관하게 정해진 자리를 본다. 그것을 좁혀 적으면 아무 일도
/// 일어나지 않으므로 경고한다 — 좁혔다고 믿게 두는 것이 이 린트가 막으려는
/// 것이다.
fn check_subject_roots(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    use crate::catalog::Scoping;
    for (s, roots) in &m.subject_roots {
        let at = format!("subject_roots.{}", s.id());

        if !m.subjects.contains(s) {
            out.push(LintIssue {
                severity: Severity::Error,
                at: at.clone(),
                message: format!(
                    "'{}' 가 `subjects` 에 없다. 선언하지 않은 subject 를 좁히는 것은 \
                     아무 효과가 없고, 작성자는 좁혔다고 믿는다",
                    s.id()
                ),
                valid: Some(format!(
                    "`subjects` 에 '{}' 를 넣거나 이 줄을 지울 것",
                    s.id()
                )),
                doc: Some("설계-02 §2"),
            });
            continue;
        }

        if roots.is_empty() {
            out.push(LintIssue {
                severity: Severity::Error,
                at: at.clone(),
                message: "빈 목록이다. 그것은 '이 subject 는 아무 데도 보지 않는다' 이고, \
                          결과는 조용한 0건이다"
                    .into(),
                valid: Some("좁힐 경로를 하나 이상 적거나 이 줄을 지울 것".into()),
                doc: Some("설계-02 §2"),
            });
            continue;
        }

        if s.info().scoping == Scoping::Fixed {
            out.push(LintIssue {
                severity: Severity::Warning,
                at: at.clone(),
                message: format!(
                    "'{}' 는 자리가 정해진 subject 라 `scan_roots` 를 보지 않는다. \
                     여기 적어도 아무 일도 일어나지 않는다",
                    s.id()
                ),
                valid: Some("이 줄을 지울 것".into()),
                doc: Some("설계-02 §3"),
            });
        }

        for (i, r) in roots.iter().enumerate() {
            let inside = m.scan_roots.iter().any(|top| root_covers(top, r));
            if !inside {
                out.push(LintIssue {
                    severity: Severity::Error,
                    at: format!("{at}[{i}]"),
                    message: format!(
                        "'{r}' 가 `scan_roots` 밖이다. `subject_roots` 는 **좁히기만** \
                         한다 — 넓힐 수 있으면 읽기 권한의 상한이 두 곳이 되고, \
                         서명 검토자가 한 곳만 읽으면 실제로 무엇을 읽는지 모른다"
                    ),
                    valid: Some(format!(
                        "`scan_roots` 안의 경로로 적을 것 — 지금 상한: {}",
                        m.scan_roots.join(" · ")
                    )),
                    doc: Some("설계-02 §2"),
                });
            }
        }
    }
}

/// 확장자 밖의 설정 디렉터리를 **상한 안에서만** 열었는가 (C-5).
///
/// `check_subject_roots` 와 같은 규율이고 방향만 반대다 — 그쪽은 좁히는 선언이고
/// 이쪽은 **같은 상한 안에서 읽는 것을 넓히는** 선언이다. 그래서 `scan_roots`
/// 밖은 똑같이 오류다: 넓힐 수 있으면 읽기 권한의 상한이 두 곳이 되고, 서명
/// 검토자가 `scan_roots` 만 읽으면 실제로 무엇을 읽는지 모른다.
fn check_text_config_dirs(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    if m.text_config_dirs.is_empty() {
        return;
    }
    // 선언하지 않은 subject 를 위한 디렉터리는 **조용한 0건**이다.
    if !m.subjects.contains(&Subject::TextConfig) {
        out.push(LintIssue {
            severity: Severity::Error,
            at: "text_config_dirs".into(),
            message: "`subjects` 에 'text_config' 가 없다. 그 subject 를 모으지 않으면 \
                      여기 적은 디렉터리는 아무도 읽지 않고, 작성자는 읽힌다고 믿는다"
                .into(),
            valid: Some("`subjects` 에 'text_config' 를 넣거나 이 줄을 지울 것".into()),
            doc: Some("설계-02 §2"),
        });
    }
    for (i, d) in m.text_config_dirs.iter().enumerate() {
        let at = format!("text_config_dirs[{i}]");
        if crate::catalog::is_registry_root(d) {
            out.push(LintIssue {
                severity: Severity::Error,
                at: at.clone(),
                message: format!(
                    "'{d}' 는 레지스트리 경로다. 여기는 **파일 디렉터리**를 적는 자리이고, \
                     레지스트리는 디렉터리로 훑을 수 없다"
                ),
                valid: Some("파일 디렉터리를 적을 것".into()),
                doc: Some("설계-02 §3"),
            });
            continue;
        }
        if !m.scan_roots.iter().any(|top| root_covers(top, d)) {
            out.push(LintIssue {
                severity: Severity::Error,
                at: at.clone(),
                message: format!(
                    "'{d}' 가 `scan_roots` 밖이다. 이 선언은 **같은 상한 안에서** 확장자 \
                     밖의 파일까지 읽는 것이고, 상한을 넓히는 길이 아니다 — 넓힐 수 \
                     있으면 읽기 권한의 상한이 두 곳이 된다"
                ),
                valid: Some(format!(
                    "`scan_roots` 안의 경로로 적을 것 — 지금 상한: {}",
                    m.scan_roots.join(" · ")
                )),
                doc: Some("설계-02 §2"),
            });
            continue;
        }
        // **상한 자체를 적는 것은 다른 이야기다.** `/etc` 를 적으면 그 아래
        // 직접 자식 전부가 줄 단위로 들어온다 — `passwd` · `shadow` · `group`
        // 이 거기 있다(실측: 리눅스 `/etc` 직접 자식 중 확장자 없는 것이
        // 기계마다 100~540건). 막지는 않는다. 드롭인 디렉터리를 겨누라고 말한다.
        if m.scan_roots.iter().any(|top| {
            top.trim_end_matches(['\\', '/'])
                .eq_ignore_ascii_case(d.trim_end_matches(['\\', '/']))
        }) {
            out.push(LintIssue {
                severity: Severity::Warning,
                at,
                message: format!(
                    "'{d}' 는 `scan_roots` 자체다. 그 아래 **모든** 파일이 확장자와 무관하게 \
                     줄 단위로 스냅샷에 들어온다 — 자격증명과 개인정보가 함께 들어올 수 있다"
                ),
                valid: Some("드롭인 디렉터리 하나를 적을 것 — '/etc/pam.d' 처럼".into()),
                doc: Some("설계-02 §3"),
            });
        }
    }
}

/// `top` 이 `inner` 를 덮는가. **전개 전 문자열로 본다.**
///
/// 린트는 기계 위가 아니라 작성 시점에 돈다 — `%PROGRAMDATA%` 가 무엇으로
/// 펼쳐지는지 여기서는 모른다. 그래서 토큰을 그대로 둔 채 성분 경계로 비교한다.
/// 같은 토큰으로 시작하는 더 긴 경로면 덮는 것이 맞고, 다른 토큰이면 판단할 수
/// 없으므로 **덮지 않는 것으로** 본다 — 모르는 것을 통과시키면 이 검사가 없는
/// 것과 같다.
fn root_covers(top: &str, inner: &str) -> bool {
    let t = top.trim_end_matches(['\\', '/']);
    let i = inner.trim_end_matches(['\\', '/']);
    if t.eq_ignore_ascii_case(i) {
        return true;
    }
    let Some(rest) = i.get(..t.len()) else {
        return false;
    };
    rest.eq_ignore_ascii_case(t) && matches!(i.as_bytes().get(t.len()), Some(b'\\') | Some(b'/'))
}

fn check_subject_reachability(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    use crate::catalog::Scoping;
    let has_registry = m
        .scan_roots
        .iter()
        .any(|r| crate::catalog::is_registry_root(r));
    let has_path = m
        .scan_roots
        .iter()
        .any(|r| !crate::catalog::is_registry_root(r));

    for s in &m.subjects {
        let (need, what, example) = match s.info().scoping {
            Scoping::Fixed => continue,
            Scoping::Path if has_path => continue,
            Scoping::Registry if has_registry => continue,
            Scoping::Path => (
                "경로 루트",
                "지금 `scan_roots` 에는 레지스트리 루트뿐이다",
                "%LOCALAPPDATA%\\Programs",
            ),
            Scoping::Registry => (
                "레지스트리 루트",
                "지금 `scan_roots` 에는 경로뿐이다",
                "HKLM\\SOFTWARE\\...",
            ),
        };
        out.push(LintIssue {
            severity: Severity::Error,
            at: format!("subjects.{}", s.id()),
            message: format!(
                "이 subject 는 {need}가 `scan_roots` 에 하나라도 있어야 모인다 — {what}. \
                 그대로 두면 **언제나 0건**이고, 그 위에서 도는 룰은 아무것도 맞히지 \
                 못한 채 초록이 된다"
            ),
            valid: Some(format!(
                "`{example}` 같은 {need}를 `scan_roots` 에 하나 이상"
            )),
            doc: Some("설계-02 §3"),
        });
    }
}
/// 값이 **닫힌 필드에 없는 값**을 적었는가.
///
/// `check_fields` 는 없는 이름을, `check_unpopulated_fields` 는 언제나 비어
/// 있는 이름을 잡는다. 이것은 **이름은 맞고 값만 틀린** 자리를 잡는다 —
/// 셋 중 가장 조용한 부류다. 앞의 둘은 규칙이 안 맞으면 작성자가 이름을
/// 의심하기라도 하는데, 값이 틀린 술어는 문법도 이름도 멀쩡해서 의심할
/// 자리가 없다. 시험 회차 하나가 정확히 그렇게 무너졌다
/// (`Subject::ENUMERATED_FIELDS` 의 주석).
///
/// **`equals`·`not_equals` 만 본다.** `contains` 로 `"In"` 을 찾는 것은
/// 부분 일치라 전수 밖의 값도 뜻이 있을 수 있다.
///
/// **`${...}` 는 건너뛴다.** 값이 실행 시점에 정해지므로 지금 알 수 없다.
fn check_enumerated_values(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    for (i, rule) in m.detect.iter().enumerate() {
        let mut preds = Vec::new();
        flatten_condition(&rule.condition, &format!("detect[{i}].where"), &mut preds);
        for p in &rule.exclude {
            preds.push((format!("detect[{i}].exclude"), p));
        }
        for (at, p) in preds {
            let Predicate::Field(f) = p else { continue };
            if !matches!(f.op, Operator::Equals | Operator::NotEquals) {
                continue;
            }
            let Some(v) = f.value.as_ref().and_then(|v| v.as_str()) else {
                continue;
            };
            if v.contains("${") {
                continue;
            }
            // `file(command).path` 형태면 괄호 안이 subject 다 —
            // `unpopulated_field_uses` 와 같은 규약이다.
            let (subject, path) = match f.field.split_once('(') {
                Some((head, rest)) => {
                    let Some((_, tail)) = rest.split_once(')') else {
                        continue;
                    };
                    let Some(s) = crate::catalog::Subject::from_id(head) else {
                        continue;
                    };
                    (s, tail.trim_start_matches('.'))
                }
                None => (rule.subject, f.field.as_str()),
            };
            let Some(e) = crate::catalog::EnumeratedField::lookup(subject, path) else {
                continue;
            };
            if e.accepts(v) {
                continue;
            }
            // 우리가 만드는 값이면 다른 것이 나올 수 없으니 오류,
            // OS 표기를 통과시키는 자리면 아는 만큼이므로 경고다.
            let (severity, head) = if e.defined {
                (
                    Severity::Error,
                    "이 필드에 그 값은 어느 기계에서도 나오지 않는다",
                )
            } else {
                (Severity::Warning, "이 필드에서 지금까지 관측된 값이 아니다")
            };
            out.push(LintIssue {
                severity,
                at: format!("{at}.value"),
                message: format!(
                    "'{}' 의 값 '{v}' — {head}. 술어가 언제나 {}이라 규칙이 조용히 \
                     0건을 보고한다. {}",
                    f.field,
                    if matches!(f.op, Operator::Equals) {
                        "거짓"
                    } else {
                        "참"
                    },
                    e.why
                ),
                valid: Some(match e.values {
                    [only] => format!("'{only}' 뿐이다"),
                    v => format!("{} 중 하나", v.join(" · ")),
                }),
                doc: Some("설계-02 §3"),
            });
        }
    }
}

/// `sha256` 의 리터럴은 **소문자 16진 64자**여야 한다.
///
/// 수집은 지문을 소문자 64자로 적는다. 다른 모양의 값은 어느 기계에서도 같을
/// 수 없어 그 항목은 조용히 아무것도 맞히지 않는다 — 문법은 통과하고 규칙만
/// 0건이 되는 자리다. AI 합격 시험에서 두 번 지나갔다: `worm-r3` 가 값을 몰라
/// `FILL_IN_…` 자리 표시를 두었고(2026-10-01), `worm-r1` 은 0 을 64개 적었다
/// (2026-09-22). 둘 다 린트가 조용했고, 판정이 서지 않은 뒤에야 보였다.
///
/// 형식이 틀리면 **오류**(그 값은 영영 맞지 않는다), 한 글자의 반복이면
/// **경고**(실제 지문일 수 없지만 "틀렸다" 가 아니라 "자리 표시로 보인다" 다).
/// `${…}` 로 풀리는 값은 리터럴이 아니다 — 값을 모르면 그 길이 맞다
/// (`20-detect` §값을 모르는 지문).
fn check_sha256_literals(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    fn tail(field: &str) -> &str {
        // `file(x).sha256` 이면 괄호 뒤가 필드다 — `unpopulated_field_uses` 와 같은 규약.
        match field.split_once(')') {
            Some((_, rest)) => rest.trim_start_matches('.'),
            None => field,
        }
    }
    fn well_formed(v: &str) -> bool {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn one_repeated(v: &str) -> bool {
        v.bytes().all(|b| Some(b) == v.bytes().next())
    }
    for (i, rule) in m.detect.iter().enumerate() {
        let mut preds = Vec::new();
        flatten_condition(&rule.condition, &format!("detect[{i}].where"), &mut preds);
        for (at, p) in preds {
            let Predicate::Field(f) = p else { continue };
            if tail(&f.field) != "sha256"
                || !matches!(f.op, Operator::Equals | Operator::NotEquals | Operator::In)
            {
                continue;
            }
            let literals: Vec<(String, &str)> = match &f.value {
                Some(serde_json::Value::String(s)) => vec![(format!("{at}.value"), s.as_str())],
                Some(serde_json::Value::Array(xs)) => xs
                    .iter()
                    .enumerate()
                    .filter_map(|(k, x)| x.as_str().map(|s| (format!("{at}.value[{k}]"), s)))
                    .collect(),
                _ => continue,
            };
            for (at, v) in literals {
                if v.contains("${") {
                    continue;
                }
                if !well_formed(v) {
                    out.push(LintIssue {
                        severity: Severity::Error,
                        at,
                        message: format!(
                            "'sha256' 의 값 '{v}' 는 소문자 16진 64자가 아니다. 수집은 지문을 \
                             그 모양으로 적으므로 이 항목은 어느 기계에서도 아무것도 맞히지 \
                             않는다 — 자리 표시를 두어도 문법은 통과한다"
                        ),
                        valid: Some(
                            "0-9 · a-f 로만 64자. 값을 모르면 적지 말고, 아는 자리(정기 작업이 \
                             부르는 파일)에서 sha256 을 capture 해 `${규칙.capture}` 로 모을 것"
                                .into(),
                        ),
                        doc: Some("설계-02 §3"),
                    });
                } else if one_repeated(v) {
                    out.push(LintIssue {
                        severity: Severity::Warning,
                        at,
                        message: format!(
                            "'sha256' 의 값 '{v}' 는 한 글자의 반복이다 — 실제 지문일 수 없고 \
                             자리 표시로 보인다. 이 항목은 아무것도 맞히지 않는다"
                        ),
                        valid: Some(
                            "위협 정보가 준 지문을 그대로 붙이거나, 값을 모르면 아는 자리에서 \
                             sha256 을 capture 해 `${규칙.capture}` 로 모을 것"
                                .into(),
                        ),
                        doc: Some("설계-02 §3"),
                    });
                }
            }
        }
    }
}

/// 버전 비교의 리터럴을 거른다 — **두 방향 모두**.
///
/// 1. `version_lt`·`version_gt` 의 값이 버전이 아니면 **오류**다. `8.2.x` 나
///    `8.2.29-1ubuntu1` 을 적으면 그 항목은 어느 기계에서도 판정을 세우지 못하고
///    *"버전으로 읽지 못했습니다"* 진단만 남긴다.
/// 2. `gt`·`lt` 의 값이 **버전처럼 생겼으면 경고**다. 그쪽은 수와 RFC3339 시각만
///    보므로 `8.2.29` 는 조용히 거짓이 된다. PHP 대응 자료 §8 ④ 가 이 자리를
///    짚었고, 그래서 연산자를 더했다 — 그런데 **연산자가 생겼다는 사실을 아무도
///    알려 주지 않으면** 작성자는 같은 실수를 같은 방식으로 한다.
///
/// `${…}` 로 풀리는 값은 리터럴이 아니다 — 지금 알 수 없다.
fn check_version_literals(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    for (i, rule) in m.detect.iter().enumerate() {
        let mut preds = Vec::new();
        flatten_condition(&rule.condition, &format!("detect[{i}].where"), &mut preds);
        for p in &rule.exclude {
            preds.push((format!("detect[{i}].exclude"), p));
        }
        for (at, p) in preds {
            let Predicate::Field(f) = p else { continue };
            // **셋이 따옴표 사고를 함께 당하고, 모양 규칙만 갈린다.**
            // `version_lt`·`version_gt` 는 점숫자만 받고 `pkg_version_lt` 는
            // 배포판 판을 받는다 — 둘을 한 자리에서 보되 판정은 나눈다.
            let pkg_op = matches!(f.op, Operator::PkgVersionLt);
            let rpm_op = matches!(f.op, Operator::RpmVersionLt);
            let version_op =
                pkg_op || rpm_op || matches!(f.op, Operator::VersionLt | Operator::VersionGt);
            if !version_op && !matches!(f.op, Operator::Gt | Operator::Lt) {
                continue;
            }
            // **평가기와 같은 방식으로 읽는다.** YAML 은 `value: 8.2` 를 수로
            // 주지만 평가기는 `to_string()` 으로 펴서 견준다. 린트가 다르게
            // 읽으면 통과한 룰이 평가에서 갈리거나 그 반대가 된다 —
            // [`crate::catalog::is_version`] 을 한 자리에 둔 것과 같은 까닭이다.
            let v = match &f.value {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                // 값이 **없다**. `exists` 를 뺀 모든 연산자가 값을 요구한다.
                None => String::new(),
            };
            // 따옴표 없이 적은 실수는 **여기 도착하기 전에 이미 망가져 있다** —
            // 원문을 복원할 길이 없으므로 `f.value` 의 형을 본다.
            let unquoted = f
                .value
                .as_ref()
                .is_some_and(crate::catalog::unquoted_version_number);
            if v.contains("${") {
                continue;
            }
            if version_op {
                // **따옴표 없이 적은 실수가 먼저다.** `8.10` 은 `is_version` 이
                // 참인 `"8.1"` 로 도착하므로 아래 검사로는 잡히지 않는다.
                if unquoted {
                    out.push(version_unquoted(&at, &f.field, &v, f.op.id()));
                } else {
                    let ok = if pkg_op {
                        crate::catalog::is_pkg_version(&v)
                    } else if rpm_op {
                        crate::catalog::is_rpm_version(&v)
                    } else {
                        crate::catalog::is_version(&v)
                    };
                    if !ok {
                        // 값이 없으면 빈 문자열을 그대로 보이지 않는다 — 진단의
                        // 끝이 빈 채로 나가면 무엇이 문제인지 읽을 수 없다.
                        let shown = if v.trim().is_empty() { "(없음)" } else { &v };
                        if pkg_op {
                            out.push(pkg_version_error(&at, &f.field, shown));
                        } else if rpm_op {
                            out.push(rpm_version_error(&at, &f.field, shown));
                        } else {
                            out.push(version_error(&at, &f.field, shown, f.op.id()));
                        }
                    }
                }
            } else if looks_like_a_version(&v) {
                out.push(version_hint(&at, &f.field, &v, f.op.id()));
            }
        }
    }
}

/// `gt`·`lt` 에 적힌 이 값이 **버전처럼 보이는가.**
///
/// 수로도 읽히는 값은 그쪽의 정상 입력이다 — `8` 도 `8.2` 도 수다. 수로도 시각
/// 으로도 읽히지 않으면서 **숫자로 시작하고 점이 든** 값만 잘못 고른 연산자의
/// 증거다.
///
/// **꼬리 붙은 값도 든다**(2026-10-27 적대 검증). 전에는 `is_version` 이 참인
/// 값만 봐서 `8.2.29-1ubuntu1` 에 한 글자도 말하지 않았다 — 배포판이 패치한
/// 버전이 바로 그 모양이라 **가장 흔한 경우**가 조용히 지나갔다.
fn looks_like_a_version(v: &str) -> bool {
    let v = v.trim();
    v.parse::<f64>().is_err()
        // **시각에는 쌍점이 있다.** `2026-08-21T00:00:00Z` 는 `lt` 의 정상
        // 입력이고, 그것에 `version_lt` 를 권하면 엉뚱한 곳으로 보낸다.
        && !v.contains(':')
        && v.starts_with(|c: char| c.is_ascii_digit())
        && v.contains('.')
}

fn version_error(at: &str, field: &str, v: &str, op: &str) -> LintIssue {
    LintIssue {
        severity: Severity::Error,
        at: format!("{at}.value"),
        message: format!(
            "'{field}' 에 걸린 {op} 의 값 '{v}' {} 버전으로 읽지 못했다. 이 항목은 \
             어느 기계에서도 판정을 세우지 못하고 진단만 남긴다",
            crate::i18n::particle(v, "을", "를")
        ),
        valid: Some(
            "점으로 나눈 숫자만 — 예: 8.2.29. 사전 배포 꼬리(RC1 · -dev)와 패키지 \
             개정(-1ubuntu1)은 순서가 서로 반대여서 받지 않는다. 계열을 좁히려면 \
             `version` 에 `starts_with \"8.2.\"` 를 함께 걸 것"
                .into(),
        ),
        doc: Some("24-check-plugins.md"),
    }
}

/// `pkg_version_lt` 에 적은 값이 배포판 판 모양이 아니다.
///
/// **[`version_error`] 를 쓸 수 없다.** 그쪽은 *"패키지 개정은 받지 않는다"* 고
/// 가르치는데 이 연산자는 그것을 받는다 — 그 문구를 내보내면 작성자가 맞게
/// 적은 룰을 지우게 된다.
fn pkg_version_error(at: &str, field: &str, v: &str) -> LintIssue {
    LintIssue {
        severity: Severity::Error,
        at: format!("{at}.value"),
        message: format!(
            "'{field}' 에 걸린 pkg_version_lt 의 값 '{v}' {} 배포판 판으로 읽지 못했다. \
             이 항목은 어느 기계에서도 판정을 세우지 못하고 진단만 남긴다",
            crate::i18n::particle(v, "을", "를")
        ),
        valid: Some(
            "배포판이 적는 그대로 — 예: 8.1.2-1ubuntu2.28 · 1:2.38.1-5+deb12u3 · 3.6.8-r1. \
             숫자로 시작해야 하고 `_` 는 받지 않는다(apk 는 `_alpha` 를 낮게, dpkg 의 \
             규칙은 높게 읽어 순서가 반대다). 상류 판만 보려면 \
             `upstream_version` 에 `version_lt` 를 걸 것"
                .into(),
        ),
        doc: Some("24-check-plugins.md"),
    }
}

/// `rpm_version_lt` 에 적은 값이 RPM 판 모양이 아니다 (2026-11-09).
fn rpm_version_error(at: &str, field: &str, v: &str) -> LintIssue {
    LintIssue {
        severity: Severity::Error,
        at: format!("{at}.value"),
        message: format!(
            "'{field}' 에 걸린 rpm_version_lt 의 값 '{v}' {} RPM 판으로 읽지 못했다. \
             이 항목은 어느 기계에서도 판정을 세우지 못하고 진단만 남긴다",
            crate::i18n::particle(v, "을", "를")
        ),
        valid: Some(
            "RPM 이 적는 그대로 — 예: 0:8.0.30-8.el9_8.1 · 7.4.33-8.module+el8.10.0+25117+30337cca. \
             숫자로 시작해야 한다. 배포판(dpkg · apk) 판은 pkg_version_lt 를 쓸 것"
                .into(),
        ),
        doc: Some("24-check-plugins.md"),
    }
}

/// 따옴표 없이 적은 버전. **원문을 복원할 길이 없으므로 오류다.**
fn version_unquoted(at: &str, field: &str, degraded: &str, op: &str) -> LintIssue {
    LintIssue {
        severity: Severity::Error,
        at: format!("{at}.value"),
        message: format!(
            "'{field}' 에 걸린 {op} 의 값을 YAML 이 **실수로** 읽었다 — 따옴표가 없다. \
             엔진에 도착한 값은 '{degraded}' 이고 **뒤의 0 은 돌아오지 않는다**: \
             `8.10` 을 적으면 `8.1` 과 견주게 되어 `8.9` 를 양호로 본다"
        ),
        valid: Some(
            "따옴표로 감싼다 — `value: \"8.10\"`. 정수(`value: 8`)는 왕복하므로 \
             그대로 둬도 된다"
                .into(),
        ),
        doc: Some("24-check-plugins.md"),
    }
}

fn version_hint(at: &str, field: &str, v: &str, op: &str) -> LintIssue {
    LintIssue {
        severity: Severity::Warning,
        at: format!("{at}.value"),
        message: format!(
            "'{field}' 에 걸린 {op} 의 값 '{v}' {} 버전처럼 보인다. {op} 는 수와 \
             RFC3339 시각만 견주므로 이 항목은 **판정을 세우지 못하고** 진단만 남긴다",
            crate::i18n::particle(v, "은", "는")
        ),
        // `op` 는 `gt` 아니면 `lt` 다 — 그대로 이어 붙이면 새 연산자 이름이 된다.
        valid: Some(format!("버전을 견주려면 version_{op} 를 쓸 것")),
        doc: Some("24-check-plugins.md"),
    }
}

/// `matches` 의 값을 **실제로 컴파일한다.**
///
/// 문법이 틀린 정규식은 평가 시점에야 드러나는데, 그때는 이미 고객 PC 다.
/// RE2 계열이라 역참조·전방탐색이 없다 — 그것도 여기서 걸린다.
fn check_regexes(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    for (i, rule) in m.detect.iter().enumerate() {
        let mut preds = Vec::new();
        flatten_condition(&rule.condition, &format!("detect[{i}].where"), &mut preds);
        // **`exclude` 도 본다.** 거기서 깨진 정규식은 평가 때도 말이 없다 — 제외의
        // 문제는 버려지고(전부터 그렇다) 제외가 조용히 꺼진다. 치료 플러그인이면
        // 걸러 내려던 정상 파일이 증거로 남는다(2026-10-26 적대 검증).
        for p in &rule.exclude {
            preds.push((format!("detect[{i}].exclude"), p));
        }
        for (at, p) in preds {
            let Predicate::Field(f) = p else { continue };
            if f.op != Operator::Matches {
                continue;
            }
            let Some(serde_json::Value::String(pattern)) = &f.value else {
                continue;
            };
            // `${...}` 가 든 패턴은 해소 전이라 컴파일할 수 없다. 건너뛴 사실을
            // 조용히 두지 않는다 — 검사되지 않았다는 것이 보여야 한다.
            if pattern.contains("${") {
                out.push(warn(
                    format!("{at}.value"),
                    "capture 참조가 들어 있어 정규식을 미리 컴파일할 수 없다. 평가 시점에 확인된다",
                    "설계-02 §4",
                ));
                continue;
            }
            if let Err(e) = regex::Regex::new(pattern) {
                out.push(LintIssue {
                    severity: Severity::Error,
                    at: format!("{at}.value"),
                    message: format!("정규식을 컴파일할 수 없다: {e}"),
                    valid: Some(
                        "RE2 계열이다 — 역참조(\\1)와 전방탐색((?=...))은 쓸 수 없다".into(),
                    ),
                    doc: Some("설계-02 §4"),
                });
            }
        }
    }
}

/// **방향 제약** — `remediate` 에서 `reputation` 을 참조할 수 없다 (설계-03 §3 5층).
///
/// 감염 호스트의 네트워크는 신뢰할 수 없다. 조회 응답을 근거로 파괴를 늘리면
/// **공격자가 응답을 조작해 정상 파일을 지우게 만들 수 있다.** 반대 방향으로
/// 조작되면 결과는 "치료 안 함" 이고, 그것은 도구를 실행하지 않은 것과 같다.
fn check_reputation_direction(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    let Some(rem) = &m.remediate else { return };
    let mut hits: Vec<(String, String)> = Vec::new();
    for (i, t) in rem.remove.iter().enumerate() {
        match t {
            RemoveTarget::Ref(r) => {
                hits.push((format!("remediate.remove[{i}].ref"), r.rule_ref.clone()))
            }
            RemoveTarget::Path(p) => {
                hits.push((format!("remediate.remove[{i}].path"), p.path.clone()));
                if let Some(g) = &p.guard {
                    hits.push((format!("remediate.remove[{i}].guard"), g.clone()));
                }
            }
        }
    }
    for (i, e) in rem.edit.iter().enumerate() {
        hits.push((format!("remediate.edit[{i}].ref"), e.rule_ref.clone()));
        hits.push((format!("remediate.edit[{i}].value"), e.value.clone()));
    }

    for (at, text) in hits {
        if text.contains("reputation") {
            out.push(err(
                at,
                "remediate 에서 reputation 을 참조할 수 없다. 조회 결과는 파괴 대상을 \
                 만들 수 없다 — 감염 호스트의 네트워크가 조작되면 정상 파일이 지워진다. \
                 화이트리스트 태그로 **제외**하는 방향만 허용된다",
                "설계-03 §3 5층",
            ));
        }
    }
}

/// `remediate` 의 `ref` 가 실재하는 규칙인가.
fn check_remediate_refs(m: &PluginManifest, ids: &BTreeSet<&str>, out: &mut Vec<LintIssue>) {
    let Some(rem) = &m.remediate else { return };
    let known = ids.iter().cloned().collect::<Vec<_>>().join(" · ");
    let check = |at: String, name: &str, out: &mut Vec<LintIssue>| {
        if name.contains("${") || ids.contains(name) {
            return;
        }
        out.push(LintIssue {
            severity: Severity::Error,
            at,
            message: format!("없는 규칙 '{name}' 를 가리킨다"),
            valid: Some(known.clone()),
            doc: Some("설계-02 §6"),
        });
    };
    for (i, t) in rem.remove.iter().enumerate() {
        match t {
            RemoveTarget::Ref(r) => {
                check(format!("remediate.remove[{i}].ref"), &r.rule_ref, out);
                // **`descendants` 는 프로세스에만 뜻이 있다.** 다른 subject 에
                // 붙으면 계획기가 조용히 무시하고, 작성자는 계보까지 지운 줄
                // 안다 (설계-03 §2).
                if r.descendants {
                    let subject = m
                        .detect
                        .iter()
                        .find(|x| x.id == r.rule_ref)
                        .map(|x| x.subject);
                    if subject.is_some_and(|s| s != Subject::Process) {
                        out.push(LintIssue {
                            severity: Severity::Error,
                            at: format!("remediate.remove[{i}].descendants"),
                            message: format!(
                                "'{}' 는 subject '{}' 인데 descendants 는 프로세스에만 쓴다. \
                                 디렉터리 하위는 `path` 항목의 `recursive` 다",
                                r.rule_ref,
                                subject.map(|s| s.id()).unwrap_or_default()
                            ),
                            valid: Some("subject: process".into()),
                            doc: Some("설계-03 §2"),
                        });
                    }
                }
            }
            RemoveTarget::Path(p) => {
                if let Some(g) = &p.guard {
                    check(format!("remediate.remove[{i}].guard"), g, out);
                }
            }
        }
    }
    for (i, e) in rem.edit.iter().enumerate() {
        check(format!("remediate.edit[{i}].ref"), &e.rule_ref, out);
        // **`edit` 는 레지스트리 값만 고친다.** 계획기는 대상을 보지 않고
        // `registry.strip_value`(검색 경로면 `env.strip_path`)를 세운다 — 바로가기에
        // 걸면 백업이 `.lnk` 를 레지스트리로 읽지 못해 치료가 guard 정지로 끝났다
        // (2026-09-28 `shortcut-r1` 실기기). `autorun` 도 값 하나다 — Winlogon 의
        // `Userinit` 이 그 자리로 모인다(설계-02 §6-1).
        let subject = m
            .detect
            .iter()
            .find(|x| x.id == e.rule_ref)
            .map(|x| x.subject);
        if let Some(s) = subject.filter(|s| !matches!(s, Subject::RegistryValue | Subject::Autorun))
        {
            out.push(LintIssue {
                severity: Severity::Error,
                at: format!("remediate.edit[{i}].ref"),
                message: format!(
                    "'{}' 는 subject '{}' 인데 edit 는 레지스트리 값만 고친다. {}",
                    e.rule_ref,
                    s.id(),
                    edit_instead(s)
                ),
                valid: Some("subject: registry_value · autorun".into()),
                doc: Some("설계-02 §6"),
            });
        }
    }
}

/// `edit` 를 쓸 수 없는 subject 에서 대신 쓰는 것. 부분 제거가 필요한 자리는
/// `remove` 가 subject 에 맞는 Op 을 고른다(`22-remediate-recipes.md`).
fn edit_instead(s: Subject) -> &'static str {
    match s {
        Subject::Shortcut => {
            "바로가기 인자는 `remove` 로 뗀다 — 계획기가 `shortcut.strip_args` 를 고른다"
        }
        Subject::StructuredConfig => {
            "설정 항목은 `remove` 로 뺀다 — 계획기가 `structured_config.remove_key` 로 그 키 하나만 뺀다"
        }
        _ => "그 subject 는 `remove` 가 맞는 Op 을 고른다",
    }
}

/// 환경 변수가 실제로 가리키는 자리의 **깊이**.
///
/// 문자열의 세그먼트를 세면 안 된다. `%LOCALAPPDATA%` 는 한 덩어리지만 실제로는
/// `C:\Users\<사용자>\AppData\Local` 이라 다섯 단계 깊고, `C:\Users` 는 두 조각인데
/// 전 사용자를 품는다. 세그먼트만 세면 **좁은 쪽이 경고를 맞고 넓은 쪽이 통과한다** —
/// 관측 01 D1 에서 실제로 그랬다.
///
/// 값을 실행 시점에 읽지 않는 이유는, 그러면 같은 플러그인이 기계마다 다르게
/// 린트되기 때문이다. 관례적 깊이를 표로 못 박는다.
fn token_depth(token: &str) -> Option<usize> {
    let t = token.trim_matches('%').to_ascii_uppercase();
    Some(match t.as_str() {
        "SYSTEMDRIVE" => 1,                        // C:\
        "SYSTEMROOT" | "WINDIR" => 2,              // C:\Windows
        "PROGRAMDATA" => 2,                        // C:\ProgramData
        "PROGRAMFILES" | "PROGRAMFILES(X86)" => 2, // C:\Program Files
        "PUBLIC" => 3,                             // C:\Users\Public
        "ALLUSERPROFILES" => 2,                    // 모든 프로필 = C:\Users 급
        "USERPROFILE" | "HOME" => 3,               // C:\Users\<u>
        "APPDATA" | "LOCALAPPDATA" => 5,           // …\AppData\Roaming|Local
        "TEMP" | "TMP" => 6,                       // …\AppData\Local\Temp
        "REMOVABLE" => 1,                          // 이동식 매체 루트
        _ => return None,
    })
}

/// 이 루트가 얼마나 깊은가. 앞머리가 모르는 토큰이면 `None`.
///
/// # 두 플랫폼을 같은 자로 잰다
///
/// Windows 경로는 드라이브 문자가 한 칸을 차지하지만 POSIX 경로는 `/` 로
/// 시작할 뿐이라 그 칸이 없다. 그대로 세면 **구조가 같은 자리가 리눅스에서만
/// 한 단계 얕게** 나온다.
///
/// | 자리 | Windows | POSIX |
/// |---|---|---|
/// | 루트 | `C:\\` | `/` |
/// | 루트 바로 아래 | `C:\\Users` | `/home` |
/// | 그 아래 | `C:\\Users\\<u>` | `/home/<u>` |
///
/// 세 줄이 같은 넓이인데 보정 전에는 오른쪽이 각각 1씩 작았다. 그래서 파일
/// 넷짜리 `/etc/ld.so.conf.d` 가 `C:\\Windows` 와 같은 깊이 2로 계산되어
/// *"사실상 전체를 훑는다"* 는 경고를 맞았다 (2026-09-01 AI 시험 ldso-r1 실측).
///
/// **POSIX 절대 경로에 한 칸을 더해** 루트가 드라이브 문자와 같은 자리를
/// 차지하게 한다. `%HOME%` 토큰이 3이고 `/home/<u>` 도 3이 되는 것이 이 보정의
/// 확인이다 — 같은 자리를 토큰으로 쓰나 리터럴로 쓰나 값이 같아야 한다.
fn root_depth(root: &str) -> Option<usize> {
    let t = root.trim_end_matches(['\\', '/']);
    // `/` 로 시작하면 POSIX 절대 경로다. 그 `/` 가 드라이브 문자 자리를 대신한다.
    let posix_root = usize::from(root.starts_with('/'));
    let mut parts = t.split(['\\', '/']).filter(|s| !s.is_empty());
    let Some(first) = parts.next() else {
        // 루트 그 자체. `C:\\` 는 1, `/` 도 1이다.
        return Some(posix_root);
    };
    let rest = parts.count();
    if first.starts_with('%') {
        return token_depth(first).map(|d| d + rest);
    }
    // 리터럴 경로. `C:` 도 한 단계로 센다.
    Some(rest + 1 + posix_root)
}

/// 과광범위 경고. **오경보를 낸다** — 그래서 오류가 아니라 경고다.
///
/// 오경보율은 표본이 쌓이는 P4·P9 에서 재확인한다. P3 에는 표본이 없다.
/// **재귀 삭제 대상이 사용자 홈 직하인가** (설계-06 §7 다섯 번째 검사).
///
/// 홈 직하는 `Documents` · `Desktop` · `Downloads` 가 있는 자리다. 그것을 통째로
/// 지우면 위협 하나를 없애려다 **사람의 자료를 없앤다.** 되돌릴 수 있다 해도
/// 되돌리기 전까지는 없어진 것이고, 그 사이에 신고가 들어온다.
///
/// # 보간 경로는 값을 알 수 없다 — 그래서 상한을 본다
///
/// `${task.payload_dir}` 같은 대상은 증거에서 파생되므로 매니페스트만 보고는
/// 무엇이 될지 모른다. 다만 **파생 경로의 상한은 `scan_roots`** 다(설계-02 §4,
/// 계획기 G6). 그 상한 안에 홈 직하가 들어갈 수 있으면 이 재귀 삭제도 거기에
/// 닿을 수 있다.
///
/// 모르는 것을 통과로 읽지 않는다 — 이 파일의 다른 검사들과 같은 규칙이다.
fn check_recursive_scope(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    let Some(rem) = &m.remediate else {
        return;
    };
    for (i, t) in rem.remove.iter().enumerate() {
        let RemoveTarget::Path(p) = t else {
            continue;
        };
        if !p.recursive {
            continue;
        }
        let at = format!("remediate.remove[{i}].path");

        if p.path.contains("${") {
            // 파생 경로. 상한 안에 홈 직하가 들어갈 수 있는지 본다.
            let risky: Vec<&String> = m
                .scan_roots
                .iter()
                .filter(|r| may_contain_home_child(r))
                .collect();
            if !risky.is_empty() {
                out.push(warn(
                    at,
                    format!(
                        "재귀 삭제 대상 '{}' 이 사용자 홈 직하에 놓일 수 있다 — \
                         scan_roots 의 {} 아래에는 Documents·Desktop·Downloads 가 있다. \
                         파생 경로가 그중 하나가 되면 사용자 자료를 통째로 지운다",
                        p.path,
                        risky
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(" · ")
                    ),
                    "docs/plugin-guide/30-antipatterns.md#재귀-삭제",
                ));
            }
        } else if is_directly_under_home(&p.path) {
            out.push(warn(
                at,
                format!(
                    "재귀 삭제 대상 '{}' 이 사용자 홈 직하다. \
                     그 자리는 Documents·Desktop·Downloads 가 있는 곳이다",
                    p.path
                ),
                "docs/plugin-guide/30-antipatterns.md#재귀-삭제",
            ));
        }
    }
}

/// 홈 계열 루트 토큰. **깊이만으로는 가릴 수 없다** — `%SYSTEMROOT%` 도 깊이 2
/// 지만 그 아래에 사용자 홈은 없다.
fn home_family(token: &str) -> bool {
    matches!(
        token.trim_matches('%').to_ascii_uppercase().as_str(),
        "USERPROFILE" | "HOME" | "ALLUSERPROFILES" | "PUBLIC"
    )
}

/// 경로를 세그먼트로 자른다. 드라이브 문자(`C:`)도 한 칸으로 센다.
fn segments(path: &str) -> Vec<&str> {
    path.trim_end_matches(['\\', '/'])
        .split(['\\', '/'])
        .filter(|s| !s.is_empty())
        .collect()
}

/// 이 루트 **아래에** 사용자 홈 직하가 있을 수 있는가.
fn may_contain_home_child(root: &str) -> bool {
    let seg = segments(root);
    let Some(first) = seg.first() else {
        // 루트 그 자체(`/`). 그 아래 전부가 들어온다.
        return true;
    };
    if first.starts_with('%') {
        // `%USERPROFILE%` 이하만 위험하다. `%LOCALAPPDATA%`(홈 3칸 아래)처럼
        // 깊은 것은 그 아래에 홈 직하가 없다.
        return home_family(first) && seg.len() <= 1;
    }
    // 리터럴. `C:\` · `C:\Users` · `C:\Users\<u>` · `/home` · `/home/<u>` 까지가
    // 홈 직하를 품는다.
    match seg.len() {
        1 => true, // `C:` — 드라이브 전체
        2 | 3 => seg[..2].iter().any(|s| is_home_root(s)),
        _ => false,
    }
}

/// `Users` · `home` 처럼 홈들이 모여 있는 이름인가.
fn is_home_root(s: &str) -> bool {
    s.eq_ignore_ascii_case("Users") || s.eq_ignore_ascii_case("home")
}

/// 이 경로가 **사용자 홈 바로 아래 한 칸**인가.
fn is_directly_under_home(path: &str) -> bool {
    let seg = segments(path);
    let Some(first) = seg.first() else {
        return false;
    };
    if first.starts_with('%') {
        // `%USERPROFILE%\Downloads` — 토큰 뒤 정확히 한 칸.
        return home_family(first) && seg.len() == 2;
    }
    // `C:\Users\<u>\Downloads` (4칸) · `/home/<u>/Documents` (3칸).
    match seg.len() {
        4 => is_home_root(seg[1]),
        3 => is_home_root(seg[0]),
        _ => false,
    }
}

fn check_overbroad(m: &PluginManifest, out: &mut Vec<LintIssue>) {
    for (i, r) in m.scan_roots.iter().enumerate() {
        let at = format!("scan_roots[{i}]");

        // 와일드카드는 **파일 경로에서는** 문법이 아니다. 그대로 넘어가 존재하지
        // 않는 디렉터리가 되고, 수집은 0건이 된다. 관측 01 에서 이 경고가
        // 작성자를 정확히 그 함정으로 몰았다 — "좁혀라" 는 말에 `\*` 를 붙였고,
        // 린트는 초록이 됐고, 탐지는 0 이 됐다.
        //
        // **레지스트리 루트는 다르다.** 값 수집은 재귀하지 않아 선언한 키의
        // 직속 값만 읽는데, 하위 키 이름이 미리 정해지지 않는 자리가 있다
        // (IFEO 는 하이재킹당한 실행 파일 이름마다 키를 하나씩 둔다). 그래서
        // **한 칸 전체인 `\*` 하나**를 받아 그 키의 직속 하위 키로 펼친다.
        //
        // 하나로 제한하는 이유가 둘이다. 하나는 전개기가 **첫 번째** `\*` 만
        // 펼쳐서 둘을 쓰면 뒤엣것이 리터럴로 남아 조용히 0건이 되는 것이고,
        // 다른 하나는 `scan_roots` 가 읽기 권한 상한이라 한 단계보다 넓히면
        // 그만큼 서명된 플러그인이 읽는 범위가 커지는 것이다.
        // **파일 경로에 열지 않은 것은 결정이다** (2026-09-02).
        //
        // **가운데의 `\*` 하나도 받는다** (2026-11-12 · 목표 결정 28). 전개기는 별표 뒤의 꼬리를
        // 그대로 붙여(`<머리>\<하위 키>\<꼬리>`) 리터럴이 남지 않고, 읽는 키 수는 끝의 별표와 같다 —
        // `Services\*\Parameters` 는 서비스마다 `Parameters` 키 하나만 읽고 서비스 키 자체의 값은
        // 읽지 않는다. NSSM 이 감싸 띄우는 프로그램의 자리(`Parameters\Application`)가 그 꼴이다.
        // 없는 하위 키는 거부가 아니라 '없음' 이다(`registry_values` 의 `deny_if_unreadable`).
        //
        // 필요는 실재한다 — 브라우저 프로필처럼 경로 한 조각이 기계마다 다른
        // 자리가 있고, `hijack-r1` 과 `hijack-r2` 가 그 앞에서 갈렸다. 한쪽은
        // `User Data\Default\Extensions` 로 좁히고 다른 프로필을 놓았고, 다른
        // 쪽은 `User Data` 로 넓히고 쿠키·기록을 상한에 들였다. 둘 다 근거가
        // 있었다.
        //
        // 그런데 **실측이 값을 뒤집었다** (Win10x64-Test): `User Data` 아래
        // 디렉터리가 Edge 53 · Chrome 35 개인데 그중 프로필은 각각 하나였다.
        // `\*` 를 열면 88갈래로 펼쳐지고 그중 둘만 쓸모가 있다. 그리고
        // 쓸모 있는 형태(`%ALLUSERPROFILES%\…\User Data\*\Extensions`)는
        // **확장을 둘 겹쳐야** 한다 — 지금 `expand_roots` 는 토큰 하나를 펴고
        // 곧바로 돌아간다. 권한 상한을 다루는 자리에 곱셈과 상한을 새로 들이는
        // 일이라, **근거가 얇은 채로 하지 않는다.**
        //
        // 여는 조건: 실기기에서 프로필이 여럿인 것을 관측했을 때. 그때 다시
        // 잰다. 지금은 10-manifest.md 가 그 갈림과 권하는 쪽을 적어 둔다.
        //
        // **마지막 칸의 이름 꼴은 연다** (2026-11-08 · 코어 1.2.0). 위 결정이 막은 것은
        // 폴더 칸의 `*` — 뿌리를 여러 갈래로 **넓히는** 것이다. 마지막 칸의
        // `*.js` 는 반대로 **좁힌다**: 그 폴더 바로 아래에서 이름이 맞는 파일만
        // 고르고, 하위 폴더도 폴더 자체도 고르지 않는다(`normalize::glob_root`).
        // `collect_extra` 가 같은 꼴을 이미 쓴다. 연 까닭은 실측이다 — EvilAI 의
        // 보도 꼴은 페이로드를 `TEMP` 바로 아래에 두는데, `TEMP` 를 뿌리로 적으면
        // 재귀로 걸으며 파일마다 해시한다(개발 기계 하나에 6만 개 · 16 GB).
        //
        // **이름 칸이 와일드카드뿐이면 여전히 오류다**(`…\*`). 관측 01 의 함정이
        // 바로 그것이었다 — "좁혀라" 에 `\*` 를 붙이면 재귀로 다 본다고 읽히는데,
        // 글롭 뿌리는 바로 아래만 본다. 글자가 섞인 꼴(`*.js`)만 받으면 그 오독이
        // 생길 자리가 없다.
        //
        // 파일 뿌리는 **지정 토큰을 뗀 나머지**에서 와일드카드를 본다. 전에는 토큰이
        // 하나라도 있으면 이 검사를 통째로 건너뛰어 `%ALLUSERPROFILES%\a\*\b` 가
        // 지나갔다(같은 날 짚었다).
        let star_ok = if crate::catalog::is_registry_root(r) {
            !r.contains('*')
                || crate::catalog::DESIGNATED_TOKENS
                    .iter()
                    .any(|d| r.contains(d.token))
                || (r.matches('*').count() == 1 && (r.ends_with("\\*") || r.contains("\\*\\")))
        } else {
            let body = crate::catalog::DESIGNATED_TOKENS
                .iter()
                .fold(r.to_string(), |s, d| s.replace(d.token, ""));
            !body.contains(['*', '?'])
                || crate::normalize::glob_root(&body)
                    .is_some_and(|(_, name)| name.chars().any(|c| c != '*' && c != '?'))
        };
        if !star_ok {
            let mut issue = err(
                at.clone(),
                if crate::catalog::is_registry_root(r) {
                    format!(
                        "'{r}' 의 `*` 자리가 맞지 않는다. 레지스트리 루트는 **한 칸 전체인 \
                         `\\*` 하나**만 받는다(맨 끝 `…\\*` 또는 가운데 `…\\*\\…`) — 그 키의 \
                         직속 하위 키로 펼쳐지고 뒤의 칸은 하위 키마다 그대로 붙는다. 둘 이상 \
                         쓰면 첫 번째만 펼쳐지고 나머지는 리터럴로 남아 조용히 0건이 되고, \
                         `Run*` 처럼 이름에 섞인 별표는 펼치지 않는다"
                    )
                } else {
                    format!(
                        "'{r}' 의 와일드카드 자리가 맞지 않는다. **파일 경로는** 마지막 칸의 \
                         이름 꼴(`*.js` 처럼 글자가 섞인 것)만 받는다 — 그 폴더 바로 아래에서 \
                         이름이 맞는 파일만 고르고 하위 폴더는 보지 않는다. 폴더 칸의 \
                         와일드카드는 펼치지 않아 수집이 0건이 되고, 이름 칸의 맨 `*` 는 \
                         '재귀로 다 본다' 로 읽히지만 그렇게 돌지 않는다. 폴더 아래를 다 보려면 \
                         와일드카드 없이 폴더를 적는다"
                    )
                },
                "설계-02 §2",
            );
            issue.valid = Some(
                "실제 디렉터리 경로 · 지정 토큰 · 마지막 칸의 이름 꼴(`…\\*.js`) · 한 칸 \
                 전체인 `\\*` 하나를 둔 레지스트리 키(`…\\*` · `…\\*\\…`)"
                    .into(),
            );
            out.push(issue);
            continue;
        }

        // **끝의 `\*` 는 좁히는 것이 아니라 넓히는 것이다.** 세그먼트가 하나
        // 늘었다고 깊이를 더 세면 `HKLM\SOFTWARE` 는 경고를 맞고
        // `HKLM\SOFTWARE\*` 는 지나간다 — 뒤엣것이 더 넓은데도. 그 앞자리로 잰다.
        //
        // **글롭 뿌리는 재지 않는다** — 바로 아래의 이름 목록만 읽으므로 얕은 자리여도
        // 전 디스크를 훑지 않는다.
        if crate::normalize::glob_root(r).is_some() {
            continue;
        }
        // **가운데 별표도 한 단계를 사지 않는다** (2026-11-12) — 그 칸을 빼고 잰다.
        // `HKLM\*\X` 는 `HKLM\*` 만큼의 키를 읽는다. 지정 토큰(`HKU\*`)은 전처럼 잰다.
        let measured = match r.strip_suffix("\\*") {
            Some(head) => head.to_string(),
            None if !crate::catalog::DESIGNATED_TOKENS
                .iter()
                .any(|d| r.contains(d.token)) =>
            {
                r.replacen("\\*\\", "\\", 1)
            }
            None => r.to_string(),
        };
        match root_depth(&measured) {
            // `C:\` · `/` · `C:\Users` 처럼 얕은 루트는 사실상 전 디스크다.
            // **`structured_config` 가 함께 선언되면 폭이 상한 문제가 된다.**
            //
            // 그 수집기는 JSON 하나를 잎 단위로 편다. 넓은 경로에 걸면 잎 수가
            // `scope.max_files`(5만)를 넘고, 그러면 스냅샷이 잘려 **스캔이 통째로
            // 종료 코드 6(관측 불완전)** 이 된다 — 그 결과 위에서는 "위협 없음"
            // 을 말할 수 없으므로 룰이 맞았는지조차 알 수 없다.
            //
            // 실측(Win10, 2026-09-04): `C:\ProgramData` 로 뜨자 Windows 자신의
            // 원격 분석 설정 하나가 그것을 삼켰다 —
            // `Microsoft\Diagnosis\DownloadedSettings\utc.privacy.json` 4.0 MB ·
            // `utc.allow.json` 2.4 MB. 벤더 폴더 하나까지 좁히면 사라진다.
            Some(d) if d <= 2 => out.push(warn(
                at,
                // **`subject_roots` 로 옮겼으면 이 말을 하지 않는다.** 작성자가
                // 이미 푼 문제를 계속 지적하면 그 경고는 곧 무시된다 — 그리고
                // 무시되는 경고는 정말 필요한 자리에서도 읽히지 않는다.
                if m.subjects.contains(&Subject::StructuredConfig)
                    && !m.subject_roots.contains_key(&Subject::StructuredConfig)
                {
                    format!(
                        "'{r}' 은 사실상 전체를 훑는다(깊이 {d}). scan_roots 는 성능이 아니라 \
                         **읽기 권한 상한**이므로 좁을수록 좋다. \
                         **여기에 structured_config 가 함께 선언돼 있다** — JSON 을 잎 \
                         단위로 펴므로 넓은 경로에서는 상한(5만)에 걸려 스캔이 종료 코드 \
                         6 이 된다. 실측: C:\\ProgramData 에서 Windows 원격 분석 설정 \
                         하나(utc.privacy.json 4 MB)가 그것을 삼켰다. \
                         `subject_roots.structured_config` 로 그 subject 만 좁히면 된다"
                    )
                } else {
                    format!(
                        "'{r}' 은 사실상 전체를 훑는다(깊이 {d}). scan_roots 는 성능이 아니라 \
                         **읽기 권한 상한**이므로 좁을수록 좋다"
                    )
                },
                "설계-02 §2",
            )),
            Some(_) => {}
            // **모르는 토큰의 폭은 잴 수 없다.** 통과시키면 "검사했다" 가 거짓이 된다.
            None => out.push(warn(
                at,
                format!(
                    "'{r}' 의 폭을 재지 못했다. 앞머리의 환경 변수가 어디를 가리키는지 \
                     이 코어가 모르므로 과광범위 검사를 건너뛰었다"
                ),
                "설계-02 §2",
            )),
        }
    }

    for (i, rule) in m.detect.iter().enumerate() {
        let mut preds = Vec::new();
        flatten_condition(&rule.condition, &format!("detect[{i}].where"), &mut preds);

        // 조건이 하나뿐이고 그것이 넓은 비교면, 그 룰은 사실상 필터가 없다.
        if preds.len() == 1 {
            if let Predicate::Field(f) = preds[0].1 {
                let wide = matches!(f.op, Operator::Contains | Operator::Exists);
                let short = match &f.value {
                    Some(serde_json::Value::String(s)) => s.len() <= 3,
                    None => true,
                    _ => false,
                };
                // **`from` 을 그대로 되뇌는 술어도 필터가 아니다.**
                //
                // 연산자만 보면 `path exists` 는 걸리고
                // `path starts_with "${x.dir}"` 는 지나간다 — 그런데
                // `from: "${x.dir}"` 아래에서 **둘은 같은 말**이다. 그러면
                // 말하는 대로 적은 쪽이 경고를 맞고 돌려 적은 쪽이 조용히
                // 지나가며, 작성자가 배우는 것은 좁히는 법이 아니라
                // **경고를 끄는 철자법**이 된다.
                //
                // 2026-09-01 AI 시험(ldso-r1)에서 그 갈림이 실제로 나왔다 —
                // 응시자는 `path exists` 로 경고를 맞았고, 같은 자리에
                // `starts_with "${conf.dir}"` 를 쓴 우리 정답 플러그인은
                // 맞지 않았다. 위험은 둘 다 똑같이 갖고 있다: `from` 은
                // **어디**를 좁히지 **몇 개**를 좁히지 않는다.
                let restates_from = rule.from.as_deref().is_some_and(|from| {
                    matches!(
                        f.op,
                        Operator::StartsWith | Operator::Equals | Operator::Contains
                    ) && matches!(&f.value, Some(serde_json::Value::String(s)) if s == from)
                });
                if wide && short {
                    out.push(warn(
                        format!("detect[{i}].where"),
                        format!(
                            "조건이 '{} {}' 하나뿐이다. 증거 그룹이 폭증해 계획 단계 상한(50)에 \
                             걸릴 수 있다",
                            f.field,
                            f.op.id()
                        ),
                        "설계-03 §4",
                    ));
                } else if restates_from {
                    out.push(warn(
                        format!("detect[{i}].where"),
                        format!(
                            "조건이 '{} {}' 하나뿐인데 그것은 `from` 이 이미 정한 범위다. \
                             좁히는 것이 없으므로 증거 그룹이 폭증해 계획 단계 상한(50)에 \
                             걸릴 수 있다",
                            f.field,
                            f.op.id()
                        ),
                        "설계-03 §4",
                    ));
                }
            }
        }
    }

    // 판정이 규칙 하나에만 걸려 있으면 그 규칙의 오탐이 곧바로 삭제가 된다.
    let tokens = verdict_tokens(&m.verdict.require);
    if tokens.len() == 1 && m.detect.len() > 1 {
        out.push(warn(
            "verdict.require",
            format!(
                "판정이 규칙 '{}' 하나에만 걸려 있다. 독립적인 두 근거의 논리곱이라야 \
                 룰 하나의 오탐이 곧바로 삭제로 이어지지 않는다",
                tokens[0]
            ),
            "설계-02 §5",
        ));
    }
}

// ─────────────────────────────────────────────────────── 보조

fn collect_refs(template: &str, at: &str, out: &mut Vec<(String, String)>) {
    let mut keys = Vec::new();
    crate::manifest::references(template, &mut keys);
    for k in keys {
        out.push((at.to_string(), k));
    }
}

fn collect_condition_refs(c: &Condition, at: &str, out: &mut Vec<(String, String)>) {
    let mut preds = Vec::new();
    flatten_condition(c, at, &mut preds);
    for (p_at, p) in preds {
        if let Predicate::Field(f) = p {
            if let Some(serde_json::Value::String(s)) = &f.value {
                collect_refs(s, &format!("{p_at}.value"), out);
            }
        }
    }
}

fn flatten_condition<'a>(c: &'a Condition, at: &str, out: &mut Vec<(String, &'a Predicate)>) {
    match c {
        Condition::One(p) => out.push((at.to_string(), p)),
        Condition::All(a) => {
            for (i, x) in a.all.iter().enumerate() {
                flatten_condition(x, &format!("{at}.all[{i}]"), out);
            }
        }
        Condition::Any(a) => {
            for (i, x) in a.any.iter().enumerate() {
                flatten_condition(x, &format!("{at}.any[{i}]"), out);
            }
        }
        Condition::List(l) => {
            for (i, x) in l.iter().enumerate() {
                flatten_condition(x, &format!("{at}[{i}]"), out);
            }
        }
    }
}

/// `verdict.require` 에서 규칙 id 로 보이는 토큰을 뽑는다.
///
/// 문법 검사는 평가기가 한다. 여기서는 **참조 무결성**만 본다.
fn verdict_tokens(expr: &str) -> Vec<String> {
    const KEYWORDS: [&str; 4] = ["and", "or", "not", "count"];
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in expr.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '-' {
            cur.push(ch);
        } else {
            if !cur.is_empty()
                && !KEYWORDS.contains(&cur.as_str())
                && !cur.chars().all(|c| c.is_ascii_digit())
            {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if !cur.is_empty()
        && !KEYWORDS.contains(&cur.as_str())
        && !cur.chars().all(|c| c.is_ascii_digit())
    {
        out.push(cur);
    }
    out
}

/// 이 매니페스트를 로드할 수 있는가. 경고는 로드를 막지 않는다.
pub fn blocking(issues: &[LintIssue]) -> usize {
    issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .count()
}

/// 카탈로그의 유효값 전수. 오류 메시지가 추측을 없애기 위해 쓴다.
pub fn valid_values() -> String {
    format!(
        "subject {}종: {}\nOp {}종: {}\n연산자 {}종: {}",
        Subject::ALL.len(),
        Subject::ALL
            .iter()
            .map(|s| s.id())
            .collect::<Vec<_>>()
            .join(" · "),
        Op::ALL.len(),
        Op::ALL
            .iter()
            .map(|o| o.id())
            .collect::<Vec<_>>()
            .join(" · "),
        Operator::ALL.len(),
        Operator::ALL
            .iter()
            .map(|o| o.id())
            .collect::<Vec<_>>()
            .join(" · "),
    )
}

/// 형태가 깨진 매니페스트에서 **틀린 술어를 이름으로** 짚는다 (2026-11-12 · 기준 7).
///
/// 조건식(`Condition`)과 술어(`Predicate`)는 꼴로 갈리는 enum(`untagged`)이라, 모르는 연산자 하나가
/// serde 에서 *"data did not match any variant of untagged enum Condition at line 11 column 5"* 로만
/// 나온다 — 무엇이 틀렸는지 말하지 않는다(1.10.0 실측 — `op: zip_contains`). 줄 · 열은 그 묶음의
/// 시작이라 술어가 여럿이면 어느 것인지도 모른다. 그래서 serde 가 실패한 **뒤에** 원문을 일반 YAML
/// 로 한 번 더 읽어, `detect[*].where` · `exclude` 의 술어마다 칸 이름과 연산자를 견준다.
///
/// 형태가 맞는 매니페스트에서는 빈 목록이다. YAML 자체가 깨졌어도 빈 목록이다 — 그때는 serde 의
/// 줄 · 열이 이미 정확하다.
pub fn schema_hints(text: &str) -> Vec<String> {
    let Ok(doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let Some(rules) = doc.get("detect").and_then(|d| d.as_sequence()) else {
        return out;
    };
    for (i, rule) in rules.iter().enumerate() {
        let id = rule.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let at = format!("detect[{i}] ('{id}')");
        if let Some(w) = rule.get("where") {
            condition_hints(w, &format!("{at}.where"), &mut out);
        }
        if let Some(seq) = rule.get("exclude").and_then(|v| v.as_sequence()) {
            for (j, p) in seq.iter().enumerate() {
                predicate_hints(p, &format!("{at}.exclude[{j}]"), &mut out);
            }
        }
    }
    out
}

fn condition_hints(v: &serde_yaml_ng::Value, at: &str, out: &mut Vec<String>) {
    use serde_yaml_ng::Value;
    match v {
        Value::Sequence(items) => {
            for (k, c) in items.iter().enumerate() {
                condition_hints(c, &format!("{at}[{k}]"), out);
            }
        }
        Value::Mapping(m) if m.len() == 1 && (m.contains_key("all") || m.contains_key("any")) => {
            for key in ["all", "any"] {
                match m.get(key) {
                    Some(inner @ Value::Sequence(_)) => {
                        condition_hints(inner, &format!("{at}.{key}"), out)
                    }
                    Some(_) => out.push(format!("{at}.{key}: 조건의 목록이어야 한다")),
                    None => {}
                }
            }
        }
        _ => predicate_hints(v, at, out),
    }
}

fn predicate_hints(v: &serde_yaml_ng::Value, at: &str, out: &mut Vec<String>) {
    let Some(m) = v.as_mapping() else {
        out.push(format!(
            "{at}: 술어가 아니다 — `{{ field, op, value }}` · `{{ yara }}` · `all` · `any` 중 하나다"
        ));
        return;
    };
    let keys: Vec<String> = m
        .keys()
        .map(|k| {
            k.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("{k:?}"))
        })
        .collect();
    if keys.iter().any(|k| k == "yara") {
        for k in keys.iter().filter(|k| *k != "yara") {
            out.push(format!(
                "{at}: yara 술어에 모르는 칸 '{k}' — `yara` 하나만 쓴다"
            ));
        }
        return;
    }
    if keys.iter().any(|k| k == "all" || k == "any") {
        out.push(format!("{at}: `all` · `any` 는 그 칸 하나만 가진 묶음이다"));
        return;
    }
    for k in keys
        .iter()
        .filter(|k| !["field", "op", "value"].contains(&k.as_str()))
    {
        out.push(format!(
            "{at}: 모르는 칸 '{k}' — 필드 술어는 field · op · value 만 쓴다"
        ));
    }
    if !keys.iter().any(|k| k == "field") {
        out.push(format!("{at}: `field` 가 없다"));
    }
    match m.get("op") {
        None => out.push(format!("{at}: `op` 가 없다")),
        Some(op) => match op.as_str() {
            Some(name) if Operator::ALL.iter().any(|o| o.id() == name) => {}
            Some(name) => out.push(format!(
                "{at}: 모르는 연산자 '{name}' — 쓸 수 있는 연산자 {}종: {}",
                Operator::ALL.len(),
                Operator::ALL
                    .iter()
                    .map(|o| o.id())
                    .collect::<Vec<_>>()
                    .join(" · ")
            )),
            None => out.push(format!("{at}: `op` 가 글자가 아니다")),
        },
    }
}

#[cfg(test)]
mod schema_hint_tests {
    use super::schema_hints;

    fn manifest(where_: &str, exclude: &str) -> String {
        format!(
            r#"
schema_version: 1
id: t
version: 1.0.0
min_core: "1.0.0"
platforms: [linux]
kind: check
name: {{ ko: "t", en: "t" }}
scan_roots: ["/opt"]
subjects: [file]
detect:
  - id: r
    subject: file
    where:
{where_}
{exclude}
verdict: {{ require: "r" }}
"#
        )
    }

    #[test]
    fn an_unknown_operator_is_named_with_its_place_and_the_valid_ones() {
        // 1.10.0 에서 이 룰은 `untagged enum Condition at line 11 column 5` 로만 나왔다.
        let y = manifest(
            "      - { field: path, op: ends_with, value: '.jar' }\n      - { field: path, op: zip_contains, value: 'x' }",
            "",
        );
        assert!(serde_yaml_ng::from_str::<crate::manifest::PluginManifest>(&y).is_err());
        let h = schema_hints(&y);
        assert_eq!(h.len(), 1, "{h:?}");
        assert!(h[0].contains("detect[0] ('r').where[1]"), "{h:?}");
        assert!(h[0].contains("모르는 연산자 'zip_contains'"), "{h:?}");
        assert!(
            h[0].contains("ends_with"),
            "쓸 수 있는 것을 말하지 않았다: {h:?}"
        );
    }

    #[test]
    fn nested_groups_exclude_and_unknown_keys_are_reached() {
        let y = manifest(
            "      - any:\n          - { field: path, op: ends_with, valu: '.jar' }\n          - { yara: 'rules/a.yar:x', op: equals }",
            "    exclude:\n      - { field: path, op: inside }",
        );
        let h = schema_hints(&y).join("\n");
        assert!(h.contains("where[0].any[0]: 모르는 칸 'valu'"), "{h}");
        assert!(
            h.contains("where[0].any[1]: yara 술어에 모르는 칸 'op'"),
            "{h}"
        );
        assert!(h.contains("exclude[0]: 모르는 연산자 'inside'"), "{h}");
    }

    #[test]
    fn a_manifest_that_parses_has_no_hints() {
        let y = manifest("      - { field: path, op: ends_with, value: '.jar' }", "");
        assert!(serde_yaml_ng::from_str::<crate::manifest::PluginManifest>(&y).is_ok());
        assert!(schema_hints(&y).is_empty());
    }
}

#[cfg(test)]
mod depth_tests {
    use super::root_depth;

    /// **구조가 같은 자리는 두 플랫폼에서 같은 깊이여야 한다.**
    ///
    /// 이것이 어긋나 있어서 파일 넷짜리 `/etc/ld.so.conf.d` 가 `C:\\Windows` 와
    /// 같은 깊이로 계산됐고, 리눅스 플러그인이 근거 없는 폭 경고를 안고
    /// 다녔다 (2026-09-01 AI 시험 ldso-r1).
    #[test]
    fn the_same_place_has_the_same_depth_on_both_platforms() {
        let pairs = [
            ("C:\\", "/"),               // 루트
            ("C:\\Users", "/home"),      // 루트 바로 아래
            ("C:\\Users\\u", "/home/u"), // 그 아래
            // 루트에서 두 칸 아래끼리. `/usr/local/lib` 은 세 칸이라 짝이 아니다.
            ("C:\\Windows\\System32", "/usr/lib"),
        ];
        for (win, posix) in pairs {
            assert_eq!(
                root_depth(win),
                root_depth(posix),
                "{win} 과 {posix} 는 같은 자리인데 깊이가 다르다"
            );
        }
    }

    /// 토큰과 리터럴이 같은 자리를 가리키면 값도 같아야 한다.
    ///
    /// `%HOME%` 은 표에 3으로 못 박혀 있다. 리터럴 `/home/u` 도 3이어야
    /// 같은 자리를 어떻게 적었는지에 따라 경고가 갈리지 않는다.
    #[test]
    fn a_token_and_the_literal_it_stands_for_agree() {
        assert_eq!(root_depth("%HOME%"), Some(3));
        assert_eq!(root_depth("/home/u"), Some(3));
        assert_eq!(root_depth("%USERPROFILE%"), root_depth("C:\\Users\\u"));
    }

    /// 경고 문턱(깊이 2 이하)의 양쪽.
    #[test]
    fn the_warning_threshold_falls_where_it_should() {
        // 넓다 — 경고를 맞아야 한다.
        for wide in ["/", "/etc", "/home", "C:\\", "C:\\Users"] {
            assert!(
                root_depth(wide).is_some_and(|d| d <= 2),
                "{wide} 이 넓은 것으로 잡히지 않는다"
            );
        }
        // 좁다 — 맞으면 안 된다. 첫 줄이 이 회차가 드러낸 자리다.
        for narrow in [
            "/etc/ld.so.conf.d",
            "/usr/local/lib",
            "/usr/share/applications",
            "C:\\Windows\\System32",
        ] {
            assert!(
                root_depth(narrow).is_some_and(|d| d > 2),
                "{narrow} 이 넓은 것으로 잡힌다"
            );
        }
    }
}

#[cfg(test)]
mod enumerated_tests {
    use super::{check_sha256_literals, lint, Severity};
    use crate::catalog::{EnumeratedField, Subject};
    use crate::manifest::PluginManifest;

    /// 매니페스트 하나. `<PRED>` 자리에 술어를 끼운다.
    fn with(subject: &str, pred: &str) -> PluginManifest {
        let y = format!(
            "schema_version: 1\n\
             id: enum-probe\n\
             version: 1.0.0\n\
             min_core: '1.0.0'\n\
             platforms: [windows]\n\
             name: {{ en: 'enum probe' }}\n\
             scan_roots: ['%LOCALAPPDATA%\\Programs']\n\
             subjects: [{subject}]\n\
             detect:\n\
             \x20 - id: r\n\
             \x20   subject: {subject}\n\
             \x20   where:\n\
             \x20     - {pred}\n\
             verdict: {{ require: 'r' }}\n"
        );
        serde_yaml_ng::from_str(&y).unwrap_or_else(|e| panic!("{e}\n{y}"))
    }

    fn issues(subject: &str, pred: &str) -> Vec<(Severity, String)> {
        lint(&with(subject, pred))
            .into_iter()
            .filter(|i| i.at.ends_with(".value"))
            .map(|i| (i.severity, i.message))
            .collect()
    }

    /// **우리가 만드는 전수**를 벗어나면 오류다. 다른 값이 나올 수 없으므로
    /// 그 술어는 어느 기계에서도 참이 되지 않는다.
    #[test]
    fn a_value_our_collector_never_writes_is_an_error() {
        let got = issues("service", "{ field: state, op: equals, value: 'running' }");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Error);
        assert!(got[0].1.contains("running"), "{}", got[0].1);
    }

    /// **OS 표기를 그대로 통과시키는 자리**는 경고에 그친다. 전수의 주인이
    /// 우리가 아니라서, 새 값이 나타났을 때 맞는 룰을 막으면 안 된다.
    #[test]
    fn a_value_the_os_owns_is_only_a_warning() {
        let got = issues(
            "firewall_rule",
            "{ field: direction, op: equals, value: 'inbound' }",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Warning);
    }

    /// `package.manager` 는 셋이다 — 코어 1.3.0 에서 `rpm` 이 들어왔다. 수집이 적는 값을 전수가
    /// 모르면 **RPM 줄이 전부 린트 오류**가 된다(2026-11-09 · 룰을 쓰다 드러났다).
    #[test]
    fn every_package_manager_the_collector_writes_is_known() {
        for m in ["dpkg", "apk", "rpm"] {
            let got = issues(
                "package",
                &format!("{{ field: manager, op: equals, value: '{m}' }}"),
            );
            assert!(got.is_empty(), "{m}: {got:?}");
        }
        let got = issues("package", "{ field: manager, op: equals, value: 'yum' }");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Error);
    }

    /// `sha256` 리터럴 — 자리 표시·대문자는 오류, 한 글자의 반복은 경고, 실제
    /// 지문과 `${…}` 는 조용하다 (`check_sha256_literals`, 2026-10-02).
    #[test]
    fn a_sha256_placeholder_is_an_error_and_a_repeated_digit_is_a_warning() {
        let got = issues(
            "file",
            "{ field: sha256, op: equals, value: 'FILL_IN_sha256_of_the_sample' }",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Error);
        assert!(got[0].1.contains("64자"), "{}", got[0].1);

        let upper = "A".repeat(64);
        let got = issues(
            "file",
            &format!("{{ field: sha256, op: equals, value: '{upper}' }}"),
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(
            got[0].0,
            Severity::Error,
            "대문자는 수집이 적는 모양이 아니다"
        );

        let zeros = "0".repeat(64);
        let got = issues(
            "file",
            &format!("{{ field: sha256, op: equals, value: '{zeros}' }}"),
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(
            got[0].0,
            Severity::Warning,
            "모양은 맞되 자리 표시로 보인다"
        );

        let real = "311778aeaef745dbff90e62bc6b368eb209f87e83132328e54ad565dc2ff9411";
        assert!(issues(
            "file",
            &format!("{{ field: sha256, op: equals, value: '{real}' }}")
        )
        .is_empty());
        // `${…}` 는 리터럴이 아니다 — 참조 검사는 따로 울리므로 이 검사만 부른다.
        let mut out = Vec::new();
        check_sha256_literals(
            &with(
                "file",
                "{ field: sha256, op: equals, value: '${seed.digest}' }",
            ),
            &mut out,
        );
        assert!(out.is_empty(), "{out:?}");
    }

    /// `in` 목록은 항목마다 본다 — 자리를 `value[k]` 로 짚는다.
    #[test]
    fn each_sha256_list_entry_is_checked_on_its_own() {
        let real = "311778aeaef745dbff90e62bc6b368eb209f87e83132328e54ad565dc2ff9411";
        let m = with(
            "file",
            &format!("{{ field: sha256, op: in, value: ['{real}', 'FILL_IN'] }}"),
        );
        let got: Vec<_> = lint(&m)
            .into_iter()
            .filter(|i| i.at.contains(".value["))
            .collect();
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].at.ends_with(".value[1]"), "{}", got[0].at);
        assert_eq!(got[0].severity, Severity::Error);
    }

    /// 대소문자는 접는다. Windows 평가가 접으므로 표기 차이로 막으면
    /// **맞는 룰이 막힌다** — 시험 회차 하나가 `allow` 로 정확히 맞혔다.
    #[test]
    fn case_alone_is_not_a_complaint() {
        assert!(issues(
            "firewall_rule",
            "{ field: action, op: equals, value: 'allow' }"
        )
        .is_empty());
    }

    /// 값이 실행 시점에 정해지는 자리와 부분 일치는 재지 않는다.
    #[test]
    fn interpolation_and_partial_matches_are_left_alone() {
        assert!(issues(
            "firewall_rule",
            "{ field: direction, op: equals, value: '${r.x}' }"
        )
        .is_empty());
        assert!(issues(
            "firewall_rule",
            "{ field: direction, op: contains, value: 'bound' }"
        )
        .is_empty());
    }

    /// **전수가 실재하는 필드에 붙어 있는가.** `fields()` 에서 이름이 사라지면
    /// 이 표는 아무것도 막지 않으면서 남는다.
    #[test]
    fn every_enumerated_field_is_a_field_of_that_subject() {
        for e in Subject::ENUMERATED_FIELDS {
            assert!(
                e.subject.fields().contains(&e.field),
                "{}.{} 는 그 subject 의 필드가 아니다",
                e.subject.id(),
                e.field
            );
            assert!(
                !e.values.is_empty(),
                "{}.{} 의 전수가 비었다",
                e.subject.id(),
                e.field
            );
            assert!(
                EnumeratedField::lookup(e.subject, e.field).is_some(),
                "{}.{} 를 lookup 이 못 찾는다",
                e.subject.id(),
                e.field
            );
        }
    }
}

#[cfg(test)]
mod wildcard_tests {
    use super::{lint, Severity};
    use crate::manifest::PluginManifest;

    const IFEO: &str =
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

    fn roots(rs: &[&str]) -> PluginManifest {
        let list = rs
            .iter()
            .map(|r| format!("  - '{r}'"))
            .collect::<Vec<_>>()
            .join("\n");
        let y = format!(
            r#"schema_version: 1
id: star-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: {{ en: 'star probe' }}
scan_roots:
{list}
subjects: [registry_value]
detect:
  - id: r
    subject: registry_value
    where:
      - {{ field: name, op: equals, value: 'Debugger' }}
verdict: {{ require: 'r' }}
"#
        );
        serde_yaml_ng::from_str(&y).unwrap_or_else(|e| panic!("{e}\n{y}"))
    }

    /// `scan_roots[..]` 자리의 진단만.
    fn at_roots(rs: &[&str]) -> Vec<(Severity, String)> {
        lint(&roots(rs))
            .into_iter()
            .filter(|i| i.at.starts_with("scan_roots["))
            .map(|i| (i.severity, i.message))
            .collect()
    }

    /// **값 수집은 재귀하지 않는다.** 하위 키 이름이 미리 정해지지 않는 자리는
    /// 끝의 별표 없이는 도달할 수 없다 — IFEO 가 그렇다.
    #[test]
    fn a_registry_root_may_end_in_a_star() {
        let got = at_roots(&[&format!("{IFEO}\\*")]);
        assert!(got.is_empty(), "{got:?}");
    }

    /// 파일 경로는 그대로 막는다. 전개되지 않아 없는 디렉터리가 되고 0건이 된다.
    #[test]
    fn a_file_root_may_not() {
        let got = at_roots(&["%LOCALAPPDATA%\\*"]);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Error);
    }

    /// 마지막 칸의 이름 꼴은 받는다 — 그 폴더 바로 아래의 맞는 파일만 고른다(코어 1.2.0).
    /// 얕은 목록이라 깊이 경고도 없다.
    #[test]
    fn a_file_root_may_end_in_a_name_pattern() {
        for r in [
            "%ALLUSERPROFILES%\\AppData\\Local\\Temp\\*.js",
            "C:\\x\\a?.js",
            "C:\\*.lnk",
        ] {
            let got = at_roots(&[r]);
            assert!(got.is_empty(), "{r}: {got:?}");
        }
    }

    /// 이름 칸이 와일드카드뿐이면 '재귀로 다 본다' 로 읽힌다 — 받지 않는다. 폴더 칸의
    /// 와일드카드는 지정 토큰이 함께 있어도 받지 않는다(전에는 토큰이 검사를 건너뛰게 했다).
    #[test]
    fn a_bare_star_or_a_folder_wildcard_is_still_an_error() {
        for r in [
            "C:\\x\\*",
            "C:\\x\\??",
            "C:\\x\\*\\a.js",
            "%ALLUSERPROFILES%\\AppData\\*\\Temp",
        ] {
            let got = at_roots(&[r]);
            assert_eq!(got.len(), 1, "{r}: {got:?}");
            assert_eq!(got[0].0, Severity::Error, "{r}");
        }
    }

    /// 전개기가 **첫 번째** 별표만 펼친다. 둘 이상 쓰면 나머지가 리터럴로 남아 조용히
    /// 0건이 되고, 이름에 섞인 별표(`Run*`)는 펼치지 않는다.
    #[test]
    fn a_second_star_or_a_star_inside_a_name_is_an_error() {
        for r in [
            format!("{IFEO}\\*\\*"),
            "HKLM\\SOFTWARE\\*\\*\\Windows".to_string(),
            "HKLM\\SOFTWARE\\Microsoft\\Run*".to_string(),
            "HKLM\\SOFTWARE\\*x\\Windows".to_string(),
        ] {
            let got = at_roots(&[&r]);
            assert_eq!(got.len(), 1, "{r}: {got:?}");
            assert_eq!(got[0].0, Severity::Error, "{r}");
        }
    }

    /// **가운데의 한 칸 별표는 받는다** (2026-11-12). 전개기가 꼬리를 하위 키마다 붙이므로
    /// 리터럴이 남지 않는다 — NSSM 이 감싸 띄우는 프로그램이 `Services\*\Parameters` 에 있다.
    #[test]
    fn a_registry_root_may_hold_one_star_in_the_middle() {
        for r in [
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*\\Parameters",
            "HKLM\\SOFTWARE\\*\\Windows",
        ] {
            let got = at_roots(&[r]);
            assert!(got.is_empty(), "{r}: {got:?}");
        }
    }

    /// 가운데 별표도 깊이를 사지 않는다 — `HKLM\*\X` 는 `HKLM\*` 만큼의 키를 읽는다.
    #[test]
    fn a_middle_star_does_not_buy_a_depth_level() {
        let got = at_roots(&["HKLM\\*\\Parameters"]);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Warning);
    }

    /// 지정 토큰은 그대로 통한다. 이쪽은 별표가 중간에 온다.
    #[test]
    fn the_designated_user_hive_token_still_passes() {
        let got = at_roots(&["HKU\\*\\Software\\Acme\\Thing"]);
        assert!(got.is_empty(), "{got:?}");
    }

    /// **별표는 좁히는 것이 아니라 넓히는 것이다.** 세그먼트가 하나 늘었다고
    /// 깊이를 더 세면 더 넓은 쪽이 조용히 폭 경고를 피한다.
    #[test]
    fn a_trailing_star_does_not_buy_a_depth_level() {
        let bare = at_roots(&["HKLM\\SOFTWARE"]);
        let starred = at_roots(&["HKLM\\SOFTWARE\\*"]);
        assert_eq!(bare.len(), 1, "{bare:?}");
        assert_eq!(bare[0].0, Severity::Warning);
        assert_eq!(
            starred.len(),
            1,
            "별표를 붙였다고 폭 경고가 사라지면 안 된다: {starred:?}"
        );
        assert_eq!(starred[0].0, Severity::Warning);
    }
}

#[cfg(test)]
mod reachability_tests {
    use super::{lint, Severity};
    use crate::catalog::{Scoping, Subject};
    use crate::manifest::PluginManifest;

    fn probe(roots: &[&str], subjects: &str, subject: &str) -> PluginManifest {
        let list = roots
            .iter()
            .map(|r| format!("  - '{r}'"))
            .collect::<Vec<_>>()
            .join("\n");
        let y = format!(
            r#"schema_version: 1
id: reach-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: {{ en: 'reach probe' }}
scan_roots:
{list}
subjects: [{subjects}]
detect:
  - id: r
    subject: {subject}
    where:
      - {{ field: name, op: equals, value: 'x' }}
verdict: {{ require: 'r' }}
"#
        );
        serde_yaml_ng::from_str(&y).unwrap_or_else(|e| panic!("{e}\n{y}"))
    }

    fn subject_errors(roots: &[&str], subjects: &str, subject: &str) -> Vec<String> {
        lint(&probe(roots, subjects, subject))
            .into_iter()
            .filter(|i| i.severity == Severity::Error && i.at.starts_with("subjects."))
            .map(|i| i.at)
            .collect()
    }

    /// 선언만으로는 모이지 않는다. 레지스트리 루트가 없으면 **언제나 0건**이다.
    #[test]
    fn a_registry_subject_without_a_registry_root_is_an_error() {
        let got = subject_errors(
            &["%LOCALAPPDATA%\\Programs"],
            "registry_value",
            "registry_value",
        );
        assert_eq!(got, vec!["subjects.registry_value".to_string()], "{got:?}");
    }

    /// 반대쪽도 같다 — 레지스트리 루트만 있으면 파일 계열이 0건이다.
    #[test]
    fn a_path_subject_without_a_path_root_is_an_error() {
        let got = subject_errors(&["HKLM\\SOFTWARE\\Acme"], "file", "file");
        assert_eq!(got, vec!["subjects.file".to_string()], "{got:?}");
    }

    /// 둘 다 있으면 조용하다.
    #[test]
    fn both_kinds_present_is_clean() {
        let got = subject_errors(
            &["%LOCALAPPDATA%\\Programs", "HKLM\\SOFTWARE\\Acme"],
            "file, registry_value",
            "file",
        );
        assert!(got.is_empty(), "{got:?}");
    }

    /// **자리가 정해진 subject 는 묻지 않는다.** 물으면 방화벽 규칙 하나를
    /// 보려고 없는 파일 루트를 적게 만든다 — 상한이 넓어질 뿐이다.
    #[test]
    fn a_fixed_subject_is_never_asked_for_a_root() {
        let got = subject_errors(&["HKLM\\SOFTWARE\\Acme"], "firewall_rule", "firewall_rule");
        assert!(got.is_empty(), "{got:?}");
    }

    /// 열아홉이 전부 갈려 있는가. 새 subject 가 기본값으로 조용히 `Fixed` 가
    /// 되면 이 검사가 그 자리를 영영 보지 않는다.
    ///
    /// **못박은 수가 사람을 멈추게 하는 자리다.** 2026-10-27 에 `package` 를
    /// 더하며 여기서 멈췄고, 멈춰서 보고 `Fixed` 를 골랐다 — 패키지 DB 는
    /// `/var/lib/dpkg/status` · `/lib/apk/db/installed` 로 **자리가 정해져
    /// 있어** `scan_roots` 를 보지 않는다.
    #[test]
    fn every_subject_declares_how_it_is_scoped() {
        let n = Subject::ALL.len();
        let fixed = Subject::ALL
            .into_iter()
            .filter(|s| matches!(s.info().scoping, Scoping::Fixed))
            .count();
        assert_eq!(n, 20);
        // 전부 Fixed 면 이 검사는 아무것도 막지 못한다.
        assert!(fixed < n, "scan_roots 를 받는 subject 가 하나도 없다");
    }
}

#[cfg(test)]
mod subject_roots_tests {
    use super::{lint, Severity};
    use crate::manifest::PluginManifest;

    /// `subject_roots` 를 붙인 탐침. `narrow` 는 YAML 조각이다.
    fn probe(narrow: &str) -> PluginManifest {
        let y = format!(
            r#"schema_version: 1
id: narrow-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: {{ en: 'narrow probe' }}
scan_roots:
  - 'C:\PROGRAMDATA'
subjects: [file, structured_config]
{narrow}
detect:
  - id: r
    subject: file
    where:
      - {{ field: path, op: exists }}
verdict: {{ require: r }}
"#
        );
        serde_yaml_ng::from_str(&y).expect("탐침 매니페스트")
    }

    fn errors(m: &PluginManifest) -> Vec<String> {
        lint(m)
            .into_iter()
            .filter(|i| i.severity == Severity::Error && i.at.starts_with("subject_roots"))
            .map(|i| format!("{}: {}", i.at, i.message))
            .collect()
    }

    #[test]
    fn a_narrowing_inside_the_ceiling_is_accepted() {
        let m = probe("subject_roots:\n  structured_config: ['C:\\PROGRAMDATA\\Acme']");
        assert!(errors(&m).is_empty(), "{:?}", errors(&m));
    }

    /// **넓히는 길이 없어야 한다.** 이것이 이 기능의 안전 성질 전부다 —
    /// 읽기 권한의 상한이 `scan_roots` 하나로 남는다.
    #[test]
    fn a_narrowing_outside_the_ceiling_is_an_error() {
        let m = probe("subject_roots:\n  structured_config: ['C:\\Windows\\System32']");
        let e = errors(&m);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("밖이다"), "{e:?}");
    }

    /// 접두가 같아도 **성분 경계**가 아니면 밖이다.
    /// `C:\\ProgramDataX` 는 `C:\\ProgramData` 안이 아니다.
    #[test]
    fn a_sibling_that_merely_shares_a_prefix_is_outside() {
        let m = probe("subject_roots:\n  structured_config: ['C:\\PROGRAMDATAX']");
        assert_eq!(errors(&m).len(), 1, "{:?}", errors(&m));
    }

    #[test]
    fn narrowing_a_subject_that_was_never_declared_is_an_error() {
        let m = probe("subject_roots:\n  text_config: ['C:\\PROGRAMDATA\\Acme']");
        let e = errors(&m);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("`subjects` 에 없다"), "{e:?}");
    }

    /// 빈 목록은 "아무 데도 보지 않는다" 이고 결과는 조용한 0건이다.
    #[test]
    fn an_empty_narrowing_is_an_error() {
        let m = probe("subject_roots:\n  structured_config: []");
        let e = errors(&m);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("빈 목록"), "{e:?}");
    }

    /// 자리가 정해진 subject 를 좁혀도 아무 일이 없다. 좁혔다고 믿게 두지 않는다.
    #[test]
    fn narrowing_a_fixed_place_subject_warns() {
        let y = "subject_roots:\n  persistence: ['C:\\PROGRAMDATA\\Acme']";
        let m: PluginManifest = serde_yaml_ng::from_str(&format!(
            r#"schema_version: 1
id: fixed-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: {{ en: 'fixed probe' }}
scan_roots:
  - 'C:\PROGRAMDATA'
subjects: [file, persistence]
{y}
detect:
  - id: r
    subject: file
    where:
      - {{ field: path, op: exists }}
verdict: {{ require: r }}
"#
        ))
        .expect("탐침");
        let w: Vec<String> = lint(&m)
            .into_iter()
            .filter(|i| i.severity == Severity::Warning && i.at.starts_with("subject_roots"))
            .map(|i| i.message)
            .collect();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("자리가 정해진"), "{w:?}");
    }

    /// 넓은 루트 경고가 **이미 푼 문제를 지적하지 않는다.**
    ///
    /// 무시되는 경고는 정말 필요한 자리에서도 읽히지 않는다.
    #[test]
    fn the_wide_root_warning_stops_naming_structured_config_once_it_is_narrowed() {
        let wide = probe("");
        let narrowed = probe("subject_roots:\n  structured_config: ['C:\\PROGRAMDATA\\Acme']");
        let says = |m: &PluginManifest| {
            lint(m)
                .into_iter()
                .any(|i| i.message.contains("structured_config 가 함께 선언돼 있다"))
        };
        assert!(says(&wide), "좁히지 않았는데 말하지 않는다");
        assert!(
            !says(&narrowed),
            "이미 좁혔는데 계속 지적한다 — 늑대소년이다"
        );
    }
}

/// **문서가 진단 전부를 덮는가.**
///
/// # 왜 필요한가
///
/// `32-lint-errors.md` 는 `generate.rs` 의 **손으로 적은 사례**를 린트에 태워
/// 만든다. 그래서 진단을 더하면서 사례를 넣지 않으면 **문서만 조용히
/// 침묵한다.** 2026-09-04 에 그랬다 — `check_subject_roots` 로 오류 넷을
/// 더했는데 사례가 없었고, 회차를 준비하다 우연히 발견했다. 그때 응시자에게
/// 가는 꾸러미에는 그 진단의 설명이 없는 채였다.
///
/// # 무엇을 세는가
///
/// **검사 함수**를 센다. 메시지를 세는 것이 더 촘촘하지만, 그러려면 진단마다
/// 안정된 이름을 붙여야 하고 그것은 34곳을 고치는 일이다. 검사 하나가 여러
/// 메시지를 내므로 이 게이트는 *"그 검사를 다루는 사례가 하나는 있다"* 까지만
/// 보증한다 — 그 한계를 여기 적어 둔다.
///
/// # 어떻게 세는가
///
/// 진단은 자기가 어느 검사에서 나왔는지 말하지 않는다. 그래서 **검사를 사례에
/// 직접 태운다.** 제품 코드를 하나도 바꾸지 않고 정확히 셀 수 있는 길이다.
#[cfg(test)]
mod doc_coverage_tests {
    use super::*;
    use crate::manifest::PluginManifest;

    /// `lint()` 이 부르는 검사 전부. **표가 곧 닫힌 집합이다.**
    ///
    /// `ids` 를 더 받는 넷은 클로저로 모양을 맞춘다.
    #[allow(clippy::type_complexity)]
    fn checks() -> Vec<(
        &'static str,
        Box<dyn Fn(&PluginManifest, &mut Vec<LintIssue>)>,
    )> {
        fn with_ids(
            f: fn(&PluginManifest, &BTreeSet<&str>, &mut Vec<LintIssue>),
        ) -> Box<dyn Fn(&PluginManifest, &mut Vec<LintIssue>)> {
            Box::new(move |m, out| {
                let ids: BTreeSet<&str> = m.detect.iter().map(|r| r.id.as_str()).collect();
                f(m, &ids, out)
            })
        }
        vec![
            (
                "check_duplicate_rule_ids",
                Box::new(check_duplicate_rule_ids),
            ),
            ("check_references", with_ids(check_references)),
            ("check_fields", Box::new(check_fields)),
            (
                "check_unpopulated_fields",
                Box::new(check_unpopulated_fields),
            ),
            ("check_package_fields", Box::new(check_package_fields)),
            ("check_enumerated_values", Box::new(check_enumerated_values)),
            ("check_sha256_literals", Box::new(check_sha256_literals)),
            ("check_version_literals", Box::new(check_version_literals)),
            (
                "check_subject_reachability",
                Box::new(check_subject_reachability),
            ),
            ("check_subject_roots", Box::new(check_subject_roots)),
            ("check_text_config_dirs", Box::new(check_text_config_dirs)),
            ("check_regexes", Box::new(check_regexes)),
            (
                "check_reputation_direction",
                Box::new(check_reputation_direction),
            ),
            ("check_remediate_refs", with_ids(check_remediate_refs)),
            (
                "check_collect_extra_refs",
                with_ids(check_collect_extra_refs),
            ),
            (
                "check_collect_extra_globs",
                Box::new(check_collect_extra_globs),
            ),
            (
                "check_yara_without_content",
                Box::new(check_yara_without_content),
            ),
            ("check_restore_named", Box::new(check_restore_named)),
            ("check_from_subject", Box::new(check_from_subject)),
            ("check_restore_defaults", with_ids(check_restore_defaults)),
            ("check_overbroad", Box::new(check_overbroad)),
            ("check_recursive_scope", Box::new(check_recursive_scope)),
            ("check_subject_platform", Box::new(check_subject_platform)),
            ("check_edit_platform", Box::new(check_edit_platform)),
            ("check_name", Box::new(check_name)),
        ]
    }

    /// 위 표가 `lint()` 과 갈라지지 않았는가.
    ///
    /// 검사를 새로 더하고 표에 넣지 않으면 그 검사는 아래 시험을 지나가지
    /// 못한다 — 그러면 이 게이트 자체가 조용히 느슨해진다. **소스를 읽어
    /// 대조한다.**
    #[test]
    fn the_check_table_matches_what_lint_calls() {
        let src = include_str!("lint.rs");
        let body = src
            .split("pub fn lint(")
            .nth(1)
            .expect("lint() 를 찾지 못했다");
        let body = &body[..body.find("\n}\n").expect("lint() 의 끝")];

        let mut called: Vec<&str> = Vec::new();
        for line in body.lines() {
            if let Some(i) = line.find("check_") {
                let rest = &line[i..];
                let end = rest.find('(').unwrap_or(rest.len());
                called.push(&rest[..end]);
            }
        }
        called.sort();
        called.dedup();

        let mut listed: Vec<&str> = checks().iter().map(|(n, _)| *n).collect();
        listed.sort();

        assert_eq!(
            called, listed,
            "검사 표가 lint() 과 갈라졌다. 새 검사를 더했다면 `checks()` 에도 넣을 것 — \
             넣지 않으면 그 검사에 사례가 없어도 아무도 말하지 않는다"
        );
    }

    /// **검사마다 사례가 하나는 있는가.**
    ///
    /// 없으면 `32-lint-errors.md` 가 그 진단을 설명하지 않는다. 응시자에게 가는
    /// 꾸러미가 그 문서를 싣고 있으므로, 빠진 검사는 **설명 없는 오류**가 된다.
    #[test]
    fn every_check_has_a_case_in_the_generated_document() {
        let cases: Vec<PluginManifest> = crate::generate::lint_cases()
            .iter()
            .filter_map(|c| serde_yaml_ng::from_str(&c.yaml).ok())
            .collect();
        assert!(
            cases.len() >= 10,
            "파싱된 사례가 {}개뿐이다 — 사례 YAML 이 깨졌나",
            cases.len()
        );

        let mut naked = Vec::new();
        for (name, f) in checks() {
            let fires = cases.iter().any(|m| {
                let mut out = Vec::new();
                f(m, &mut out);
                !out.is_empty()
            });
            if !fires {
                naked.push(name);
            }
        }

        assert!(
            naked.is_empty(),
            "이 검사들을 다루는 사례가 `generate.rs` 에 없다: {}\n\
             그러면 `32-lint-errors.md` 가 그 진단을 설명하지 않고, 그 문서는 \
             응시자에게 가는 꾸러미에 실린다 — **설명 없는 오류**가 된다.\n\
             `lint_cases()` 에 `case(...)` 나 `append(...)` 를 하나 더할 것.",
            naked.join(" · ")
        );
    }
}

/// **한 플랫폼에서만 비는 필드를 다른 플랫폼에 대고 말하지 않는다.**
///
/// 2026-09-05 까지 `NOT_POPULATED_YET` 에 플랫폼 축이 없어서, Windows 플러그인이
/// `signature.trusted` 를 쓰면 *"이 술어는 언제나 거짓이다"* 라는 경고를 받았다.
/// 거짓이었다 — `remedy-wintrust` 가 채우고 청정 코퍼스에 6,689건이 있다.
/// 하필 `22-remediate-recipes.md` 가 **신뢰 서명이 재귀 삭제를 막는다**고
/// 가르치는 바로 그 필드였다.
#[cfg(test)]
mod signature_platform_tests {
    use super::*;
    use crate::catalog::Platform;
    use crate::manifest::PluginManifest;

    fn probe(platforms: &str, field: &str) -> PluginManifest {
        let y = format!(
            r#"schema_version: 1
id: sig-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [{platforms}]
name: {{ en: 'sig probe' }}
scan_roots: ['%LOCALAPPDATA%\\Programs']
subjects: [file]
detect:
  - id: payload
    subject: file
    where:
      - {{ field: {field}, op: exists }}
verdict: {{ require: payload }}
"#
        );
        serde_yaml_ng::from_str(&y).expect("탐침")
    }

    fn says(m: &PluginManifest, needle: &str) -> bool {
        lint(m).iter().any(|i| i.message.contains(needle))
    }

    #[test]
    fn windows_is_not_told_that_signature_is_dead() {
        let m = probe("windows", "signature.trusted");
        assert!(
            !says(&m, "채우지 않는 필드"),
            "Windows 에서 채워지는 필드를 죽었다고 말한다: {:?}",
            lint(&m).iter().map(|i| &i.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn linux_is_still_told() {
        let m = probe("linux", "signature.trusted");
        let msgs: Vec<String> = lint(&m).into_iter().map(|i| i.message).collect();
        assert!(
            msgs.iter().any(|x| x.contains("채우지 않는 필드")),
            "Linux 에서는 정말 비는데 말하지 않는다: {msgs:?}"
        );
        assert!(
            msgs.iter().any(|x| x.contains("linux 에서")),
            "어느 플랫폼인지 말하지 않는다 — '채우지 않는다' 와 'Linux 에서는 \
             채우지 않는다' 는 작성자가 할 일이 다르다: {msgs:?}"
        );
    }

    /// 겸용 플러그인은 **듣는 편이 낫다.** 한쪽에서 죽는다는 사실이 여전히
    /// 그 플러그인의 사실이다.
    #[test]
    fn a_cross_platform_plugin_is_told() {
        let m = probe("windows, linux", "signature.trusted");
        assert!(says(&m, "채우지 않는 필드"), "겸용에게 말하지 않는다");
    }

    /// 어디서나 비는 필드는 플랫폼과 무관하게 말한다.
    #[test]
    fn a_field_empty_everywhere_is_told_on_windows_too() {
        let m = probe("windows", "streams");
        assert!(
            says(&m, "채우지 않는 필드"),
            "어디서나 비는 필드를 말하지 않는다"
        );
    }

    /// 평가기도 같은 사실을 말한다 — **스냅샷이 뜬 기계**를 기준으로.
    #[test]
    fn the_evaluator_asks_about_the_snapshot_platform() {
        let m = probe("windows, linux", "signature.trusted");
        let win = unpopulated_field_uses(&m, &[Platform::Windows]);
        let lin = unpopulated_field_uses(&m, &[Platform::Linux]);
        assert!(win.is_empty(), "Windows 스냅샷에서 죽었다고 한다: {win:?}");
        assert_eq!(lin.len(), 1, "Linux 스냅샷에서 말하지 않는다: {lin:?}");
        assert_eq!(lin[0].only_on, Some(Platform::Linux));
    }

    #[test]
    fn a_name_in_one_language_only_is_an_error() {
        // name 은 고객 화면의 첫 줄이다. `ko` 만 있으면 영어 화면에 한국어
        // 이름이 나오고, 비어 있으면 위협 이름 줄이 조용히 빠진다 (2026-09-06 실측).
        let base: PluginManifest =
            serde_yaml_ng::from_str(crate::generate::LINT_BASE).expect("기준 매니페스트");
        assert!(
            lint(&base).iter().all(|i| !i.at.starts_with("name.")),
            "기준이 걸린다"
        );

        let mut ko_only = base.clone();
        ko_only.name.remove("en");
        let issues: Vec<_> = lint(&ko_only)
            .into_iter()
            .filter(|i| i.at == "name.en")
            .collect();
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].severity, Severity::Error);

        let mut empty = base.clone();
        empty.name.clear();
        let ats: Vec<String> = lint(&empty)
            .into_iter()
            .filter(|i| i.at.starts_with("name."))
            .map(|i| i.at)
            .collect();
        assert_eq!(ats, vec!["name.ko".to_string(), "name.en".to_string()]);

        let mut blank = base.clone();
        blank.name.insert("en".into(), "   ".into());
        assert!(
            lint(&blank).iter().any(|i| i.at == "name.en"),
            "빈 문자열은 없는 것과 같다"
        );
    }
}

#[cfg(test)]
mod glob_tests {
    use super::{lint, Severity};
    use crate::manifest::PluginManifest;

    fn probe(subjects: &str, glob: &str) -> PluginManifest {
        let y = format!(
            r#"schema_version: 1
id: glob-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
name: {{ ko: '글롭 탐침', en: 'glob probe' }}
scan_roots: ['/usr/lib64']
subjects: [{subjects}]
detect:
  - id: r
    subject: file
    where:
      - {{ field: path, op: ends_with, value: '/x' }}
verdict: {{ require: 'r' }}
collect_extra:
  - {{ glob: '{glob}' }}
"#
        );
        serde_yaml_ng::from_str(&y).unwrap_or_else(|e| panic!("{e}\n{y}"))
    }

    fn glob_errors(subjects: &str, glob: &str) -> usize {
        lint(&probe(subjects, glob))
            .into_iter()
            .filter(|i| i.severity == Severity::Error && i.at == "collect_extra[0].glob")
            .count()
    }

    #[test]
    fn a_glob_in_one_folder_inside_the_roots_is_quiet() {
        assert_eq!(glob_errors("file", "/usr/lib64/libkeyutils*"), 0);
    }

    /// 셋 다 오류 없이 **조용한 0건**이 되는 자리다 — 린트가 아니면 아무도 모른다.
    #[test]
    fn a_glob_that_can_pick_nothing_is_an_error() {
        assert_eq!(
            glob_errors("file", "/usr/*/libkeyutils*"),
            1,
            "폴더 쪽 와일드카드"
        );
        assert_eq!(glob_errors("file", "/etc/libkeyutils*"), 1, "scan_roots 밖");
        assert_eq!(glob_errors("file", "libkeyutils*"), 1, "폴더가 없다");
        assert_eq!(
            glob_errors("process", "/usr/lib64/libkeyutils*"),
            1,
            "file 이 없다"
        );
    }
}
