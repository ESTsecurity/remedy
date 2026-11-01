//! Evidence -> Action.
//!
//! 가드(P3)와 격리·복원(P5)이 먼저 들어온 뒤에야 파괴가 계획된다. **격리와 복원이
//! 첫 파괴보다 먼저** 라는 순서 자체가 안전 장치다 (설계-09 §2). 그 순서를 지켰기에
//! 지금 Action 을 만들어도 되돌리는 길이 이미 있다.
//!
//! 도출 규칙은 [`derive`] 에 있고, 만들어진 계획은 예외 없이 [`guard`] 를 지난다.
//! **가드는 Action 이 0건이어도 돈다** — 배선을 Op 가 붙는 시점까지 미루면 가드가
//! 파괴 경로 위에서 처음 도는 것이 되고, 그때 드러나는 결함은 이미 늦다.
#![forbid(unsafe_code)]

pub mod derive;
pub mod guard;
pub mod limits;
pub mod protect;

pub use guard::Violation;
pub use limits::Limits;
/// 조직 허용 목록을 계획기가 받는 모양 — `소문자 sha256 → 사유` (설계-03 §3 5층).
///
/// **계획기는 서명을 모른다.** 검증은 `remedy-trust` 의 일이고 조립은
/// `remedy-core` 가 한다. 그렇게 갈라 두면 계획기 시험이 minisign 키 없이 돌고,
/// 계획기가 파일을 읽지 않는다는 성질도 유지된다.
///
/// 빈 지도는 **면제 없음**이다 — 목록이 없거나 비었을 때의 안전한 방향이다.
pub type Allowed = std::collections::BTreeMap<String, String>;

pub use protect::Protected;

use remedy_sdk::artifact::{Envelope, PlanBody, PlanEnvelope, ScanEnvelope};
use remedy_sdk::manifest::PluginManifest;

pub const CRATE_NAME: &str = "remedy-plan";

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("{0}")]
    Invalid(String),
    /// 상한 설정이 스스로 모순이다. **기동을 거부한다** (설계-03 §4).
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("상한 설정이 잘못됐습니다", "invalid limit configuration"))]
    LimitConfig(limits::LimitConfigError),
    /// 안전 가드가 계획을 거부했다. 종료 코드 5 (설계-02 §8).
    #[error("{msg} ({n}):
{list}", msg = remedy_sdk::i18n::t("안전 가드가 계획을 거부했습니다", "the safety guard rejected the plan"), n = .0.len(), list =
            .0.iter().map(|v| format!("  {v}")).collect::<Vec<_>>().join("
"))]
    Guard(Vec<Violation>),
}

/// 이 실행에 **사람이 있는가.**
///
/// 계획이 모드를 알아야 하는 것은 지금 한 자리뿐이다 — 이동식 매체다. 읽어도
/// 좋다는 매니페스트 선언(`allow_removable`)과 **부숴도 좋다**는 판단은 다른
/// 것이고, 후자는 눈앞의 매체를 보는 사람만 할 수 있다 (설계-03 §4).
///
/// 실행 시점이 아니라 **계획 시점**에 갈라지는 이유: 드라이런이 정확해야
/// 한다. 계획에 넣어 두고 수행 때 건너뛰면 사람이 본 것과 일어난 일이 다르다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// 화면 앞에 사람이 있다. 물어볼 수 있다.
    #[default]
    Interactive,
    /// 무인 배포. 물어볼 사람이 없다.
    Unattended,
}

/// 판정 결과에서 계획을 만든다.
///
/// P2 의 계획은 "무엇이 감염으로 판정되었는가" 만 담는다. 이 단계가 존재하는
/// 이유는 파이프라인의 파일 경계를 지금 확정해 두기 위해서다 — `scan.json` 과
/// `plan.json` 을 나눠 두면 나중에 Action 이 붙어도 앞 단계는 그대로다.
pub fn plan(
    scan: &ScanEnvelope,
    manifest: Option<&PluginManifest>,
) -> Result<PlanEnvelope, PlanError> {
    plan_with(
        scan,
        manifest,
        // **면제 없음이 기본이다.** 목록을 읽는 것은 `remedy-core` 의 일이고,
        // 이 진입점은 그것 없이 도는 자리다 (시험·문서 예제).
        &Allowed::new(),
        &Limits::default(),
        &Protected::new(snapshot_platform(&scan.host), expand_env_for_protection),
        Mode::default(),
    )
}

pub fn host_platform() -> remedy_sdk::catalog::Platform {
    if cfg!(windows) {
        remedy_sdk::catalog::Platform::Windows
    } else {
        remedy_sdk::catalog::Platform::Linux
    }
}

/// **스냅샷을 뜬 기계**의 플랫폼. 계획의 경로 비교는 이것을 따른다.
///
/// 여기서 실행 중인 OS 를 쓰면 같은 스냅샷이 기계마다 다른 계획을 낸다. 리눅스에서
/// Windows 스냅샷을 분석하면 `C:\a\evil.exe` 가 `C:\a` 안에 있다는 것조차 판정하지
/// 못한다 — `\` 가 구분자가 아니기 때문이다. 지원 엔지니어가 고객 PC 에서
/// `collect` 만 하고 분석은 사내에서 한다는 설계-03 §1 (4) 가 여기에 달려 있다.
///
/// **이 결함은 세 번 나왔다** — 평가기, 보호 목록, 그리고 여기. 셋 다 "지금 도는
/// 기계" 와 "스냅샷을 뜬 기계" 를 같은 것으로 다뤄서 생겼다.
pub fn snapshot_platform(host: &remedy_sdk::artifact::HostInfo) -> remedy_sdk::catalog::Platform {
    if host.os.eq_ignore_ascii_case("windows") {
        remedy_sdk::catalog::Platform::Windows
    } else {
        remedy_sdk::catalog::Platform::Linux
    }
}

/// 보호 목록의 `%NAME%` 전개. 전개하지 못한 변수는 **그대로 둔다** — 조용히 빈
/// 문자열이 되면 `%SystemRoot%\System32` 가 `\System32` 가 되어 보호 범위가
/// 엉뚱해진다.
pub fn expand_env_for_protection(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            None => {
                out.push_str(&rest[i..]);
                return out;
            }
            Some(j) => {
                let name = &after[..j];
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[j + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// 상한과 보호 목록을 명시해 계획을 만든다. 시험이 조작 입력을 넣는 길이다.
///
/// `manifest` 는 `remediate` 때문에 필요하다 — 그것은 매니페스트에 있고
/// `scan.json` 에는 없다 (설계-03 §2). `None` 이면 Action 을 도출하지 않고
/// 가드만 돈다.
pub fn plan_with(
    scan: &ScanEnvelope,
    manifest: Option<&PluginManifest>,
    allow: &Allowed,
    limits: &Limits,
    protected: &Protected,
    mode: Mode,
) -> Result<PlanEnvelope, PlanError> {
    if scan.kind != remedy_sdk::artifact::ArtifactKind::Scan {
        return Err(PlanError::Invalid(format!(
            "scan 봉투가 아닙니다: {}",
            scan.kind.id()
        )));
    }

    // 상한이 스스로 모순이면 **아무것도 계획하기 전에** 멈춘다. 개별 상한이
    // 총계를 넘으면 어느 쪽이 먼저 걸리는지가 계획 순서에 따라 달라져 재현되지
    // 않는다 (설계-03 §4).
    limits.check().map_err(PlanError::LimitConfig)?;

    // 가드는 **매 실행에서 실제로 돈다** — Action 이 0건이어도 그렇다. 배선을
    // Op 가 붙는 시점까지 미루면 가드가 파괴 경로 위에서 처음 도는 것이 되고,
    // 그때 드러나는 결함은 이미 늦다.
    let derived = manifest
        .map(|m| derive::derive(scan, m, mode, allow))
        .unwrap_or(derive::Derived {
            actions: Vec::new(),
            deferred: Vec::new(),
        });
    let mut actions = derived.actions;
    // **술어당 대상 수 상한은 실행 시점에야 판정된다.** 술어가 몇 개를 지목할지
    // 계획 시점에 알 수 없기 때문이다 (설계-03 §4). 그래서 상한을 계획에
    // 각인해 두고, 실행기가 백업과 파괴 **이전에** 그것으로 판정한다.
    //
    // 계획에 적히지 않으면 실행기가 무엇을 기준으로 막았는지 감사 로그만 보고는
    // 알 수 없고, 설정을 바꾸면 같은 계획이 다른 상한으로 수행된다.
    for a in &mut actions {
        if a.op == remedy_sdk::catalog::Op::ProcessKill && a.max_targets.is_none() {
            a.max_targets = Some(limits.kill_targets);
        }
        // 재귀 삭제도 같다. **하위 항목 수와 깊이는 계획 시점에 알 수 없다** —
        // 계획기는 파일 시스템을 열거하지 않는다(설계-03 §1). 상한만 각인하고
        // 실행기가 백업·파괴 **이전에** 그것으로 판정한다.
        if a.op == remedy_sdk::catalog::Op::DirDeleteRecursive {
            if a.max_children.is_none() {
                a.max_children = Some(limits.recursive_children);
            }
            if a.max_depth.is_none() {
                a.max_depth = Some(limits.recursive_depth);
            }
        }
    }
    let violations = guard::check(
        &actions,
        &guard::Context {
            limits,
            protected,
            group_count: scan.body.groups.len(),
            derived_paths: derived_paths(scan),
            evidence_path: evidence_paths(scan),
            scan_roots: scan.body.scan_roots.clone(),
            platform: snapshot_platform(&scan.host),
        },
    );
    if !violations.is_empty() {
        return Err(PlanError::Guard(violations));
    }

    Ok(Envelope {
        schema_version: scan.schema_version,
        kind: remedy_sdk::artifact::ArtifactKind::Plan,
        run_id: scan.run_id.clone(),
        created: scan.created.clone(),
        host: scan.host.clone(),
        core: scan.core.clone(),
        plugins: scan.plugins.clone(),
        body: PlanBody {
            actions,
            verdicts: scan.body.verdicts.clone(),
            // 관측의 완전성은 계획까지 따라간다. 계획서만 받아 든 사람이
            // "이 계획의 전제가 온전했는가" 를 물을 수 있어야 한다.
            observation: scan.body.observation.clone(),
            // 계획의 완전성도 같이 간다. 못 넣은 항목을 조용히 빼면 이 계획이
            // 치료의 전부인 것처럼 읽힌다 (설계-03 §2).
            verify_after_reboot: manifest
                .and_then(|m| m.remediate.as_ref())
                .and_then(|r| r.verify.as_ref())
                .is_some_and(|v| v.after_reboot),
            deferred: derived.deferred,
            // **손으로 올리는 사람이 볼 것**이다 (설계-09 "제출을 제품 밖으로").
            // 계획이 나르므로 `support-bundle` 이 `--run` 만으로 보여 준다.
            submit_hint: manifest.and_then(|m| m.submit_hint.clone()),
        },
    })
}

/// 증거 id → 그 증거가 가리키는 경로.
///
/// 재귀 삭제의 `guard` 조건이 이것을 요구한다 — 근거가 **그 디렉터리 안**을
/// 가리켜야 한다 (설계-03 §4). `target` 은 subject 마다 모양이 달라, 경로로 읽을
/// 수 있는 자리만 꺼낸다. 못 꺼낸 증거는 **넣지 않는다** — 모르는 것을 아는 척하면
/// 가드가 통과시킨다.
fn evidence_paths(scan: &ScanEnvelope) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for e in &scan.body.evidence {
        // `file` 은 `path`, `persistence` 는 정의 파일의 `source` 가 경로다.
        let p = e
            .target
            .get("path")
            .or_else(|| e.target.get("source"))
            .and_then(|v| v.as_str());
        if let Some(p) = p {
            out.insert(e.id.clone(), p.to_string());
        }
    }
    out
}

/// 증거에서 파생된 경로. 재귀 삭제는 **여기 있는 것만** 겨눌 수 있다.
///
/// capture 값 전부를 경로 후보로 본다. 경로가 아닌 capture 가 섞여도 무해하다 —
/// 이 목록은 허용을 좁히는 데만 쓰이고, 넓히는 데는 쓰이지 않는다.
fn derived_paths(scan: &ScanEnvelope) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for g in &scan.body.groups {
        out.extend(g.captures.values().cloned());
    }
    for e in &scan.body.evidence {
        out.extend(e.captures.values().cloned());
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_sdk::artifact::{ArtifactKind, CoreInfo, HostInfo, ScanBody};

    /// 매니페스트 없이 계획한다 — 가드만 돌고 Action 은 도출되지 않는다.
    fn plan_none(scan: &ScanEnvelope) -> Result<PlanEnvelope, PlanError> {
        plan(scan, None)
    }

    fn scan_env(verdicts: Vec<String>) -> ScanEnvelope {
        Envelope {
            schema_version: 1,
            kind: ArtifactKind::Scan,
            run_id: "r".into(),
            created: "t".into(),
            host: HostInfo {
                hostname: "h".into(),
                os: "windows".into(),
                version: "10".into(),
                arch: "amd64".into(),
            },
            core: CoreInfo {
                version: "0".into(),
                build: "d".into(),
            },
            plugins: Vec::new(),
            body: ScanBody {
                evidence: Vec::new(),
                groups: Vec::new(),
                removable_roots: Vec::new(),
                verdicts,
                issues: Vec::new(),
                observation: Default::default(),
                scan_roots: Vec::new(),
            },
        }
    }

    #[test]
    fn plan_carries_verdicts_and_no_actions() {
        let p = plan_none(&scan_env(vec!["g0".into()])).unwrap();
        assert_eq!(p.kind, ArtifactKind::Plan);
        assert_eq!(p.body.verdicts, vec!["g0"]);
        assert!(
            p.body.actions.is_empty(),
            "P2 의 표면은 Op 0종이다. 가드(P3)와 복원(P5) 전에 파괴가 계획되면 안 된다"
        );
    }

    #[test]
    fn run_id_is_carried_through() {
        // 한 번의 실행을 네 파일에 걸쳐 이을 수 있어야 한다.
        let p = plan_none(&scan_env(Vec::new())).unwrap();
        assert_eq!(p.run_id, "r");
        assert_eq!(p.created, "t");
    }

    /// 도출된 Action 은 **예외 없이 가드를 지난다.**
    ///
    /// 도출과 가드가 따로 놀면, 플러그인이 시키는 대로 만든 Action 이 검사 없이
    /// 계획에 들어간다. 그 순간 상한도 보호 목록도 읽기 상한도 없는 것과 같다.
    fn scan_with_evidence(path: &str, root: &str) -> ScanEnvelope {
        use remedy_sdk::artifact::{Evidence, EvidenceGroup};
        let mut s = scan_env(vec!["g0".into()]);
        s.body.scan_roots = vec![root.to_string()];
        s.body.evidence = vec![Evidence {
            id: "payload#0".into(),
            rule: "payload".into(),
            subject: remedy_sdk::catalog::Subject::File,
            score: None,
            target: serde_json::json!({ "path": path }),
            captures: Default::default(),
            matched: Vec::new(),
        }];
        s.body.groups = vec![EvidenceGroup {
            id: "g0".into(),
            evidence: vec!["payload#0".into()],
            captures: Default::default(),
            verdict: true,
            excluded_reason: None,
        }];
        s
    }

    fn removing_manifest() -> PluginManifest {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": "x", "version": "0.1.0", "min_core": "1.0.0",
            "platforms": ["windows"], "name": {"en": "x"},
            "scan_roots": ["C:\\a"], "subjects": ["file"],
            "detect": [{"id": "payload", "subject": "file",
                        "where": [{"field": "path", "op": "contains", "value": "evil"}]}],
            "verdict": {"require": "payload"},
            "remediate": { "remove": [{ "ref": "payload" }] }
        }))
        .expect("매니페스트")
    }

    /// **같은 스냅샷은 어느 기계에서 계획해도 같은 계획을 낸다.**
    ///
    /// 이 결함은 세 번 나왔다 — 평가기, 보호 목록, 그리고 계획기의 경로 비교.
    /// 셋 다 "지금 도는 기계" 와 "스냅샷을 뜬 기계" 를 같은 것으로 다뤄서 생겼고,
    /// 셋 다 **리눅스 검사에서만** 드러났다. 그래서 여기서는 호스트와 무관하게
    /// 판정되는지를 값으로 확인한다.
    #[test]
    fn planning_follows_the_snapshot_not_the_running_host() {
        use remedy_sdk::catalog::Platform;
        let win = HostInfo {
            hostname: "W".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        };
        assert_eq!(snapshot_platform(&win), Platform::Windows);
        assert_eq!(
            snapshot_platform(&HostInfo {
                os: "linux".into(),
                ..win.clone()
            }),
            Platform::Linux
        );

        // Windows 스냅샷이면 `C:\a\evil.exe` 가 `C:\a` 안이라고 판정돼야 한다 —
        // 리눅스에서 계획하더라도. `\` 를 구분자로 보지 않으면 상한 밖으로
        // 읽히고 계획이 통째로 거부된다.
        let s = scan_with_evidence(r"C:\a\evil.exe", r"C:\a");
        assert_eq!(s.host.os, "windows");
        let p = plan(&s, Some(&removing_manifest())).expect("Windows 스냅샷이 계획돼야 한다");
        assert_eq!(p.body.actions.len(), 1);
    }

    /// **`registry.delete_key` 는 매니페스트로 도달할 수 없다** —
    /// `derive::PLANNED_BUT_GUARDED` 가 적은 그 자리를 여기서 고정한다.
    ///
    /// 계획기는 이 Op 을 만들어 낸다(subject→Op 표에 있다). 그런데 G6 가
    /// 재귀 삭제로 다루어 대상이 capture 값이기를 요구하고, 레지스트리 키의
    /// 자리는 `hive`+`key` 를 이어 붙인 것이라 어떤 capture 도 그 문자열을
    /// 내지 못한다.
    ///
    /// **이 시험이 깨지면 좋은 일이다.** 가드에 길이 생겼다는 뜻이고, 그때
    /// `PLANNED_BUT_GUARDED` 에서 그 줄을 지우면 된다. 시험이 없으면 그
    /// 목록이 조용히 낡는다.
    #[test]
    fn a_registry_key_delete_cannot_get_past_the_guard() {
        use remedy_sdk::artifact::{Evidence, EvidenceGroup};
        let key = r"HKLM\SOFTWARE\Evil";
        let mut s = scan_env(vec!["g0".into()]);
        // 키를 모으려면 상한에 적어야 한다. 그것이 곧 조건 5 에 걸리는 이유다.
        s.body.scan_roots = vec![key.to_string()];
        s.body.evidence = vec![Evidence {
            id: "badkey#0".into(),
            rule: "badkey".into(),
            subject: remedy_sdk::catalog::Subject::RegistryKey,
            score: None,
            target: serde_json::json!({ "hive": "HKLM", "key": r"SOFTWARE\Evil" }),
            captures: Default::default(),
            matched: Vec::new(),
        }];
        s.body.groups = vec![EvidenceGroup {
            id: "g0".into(),
            evidence: vec!["badkey#0".into()],
            captures: Default::default(),
            verdict: true,
            excluded_reason: None,
        }];

        let m: PluginManifest = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": "x", "version": "0.1.0", "min_core": "1.0.0",
            "platforms": ["windows"], "name": {"en": "x"},
            "scan_roots": [key], "subjects": ["registry_key"],
            "detect": [{"id": "badkey", "subject": "registry_key",
                        "where": [{"field": "key", "op": "contains", "value": "Evil"}]}],
            "verdict": {"require": "badkey"},
            "remediate": { "remove": [{ "ref": "badkey" }] }
        }))
        .expect("매니페스트");

        let err = plan(&s, Some(&m)).expect_err("G6 가 거부해야 한다");
        let PlanError::Guard(v) = err else {
            panic!("가드 거부가 아니다: {err:?}");
        };
        assert!(
            v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                "파생된 경로가 아니다",
                "not a path derived from evidence"
            ))),
            "capture 파생이 아니라는 이유가 나와야 한다: {v:?}"
        );
        assert!(
            v.iter().any(|x| x
                .message
                .contains(remedy_sdk::i18n::t("상한 자체", "ceiling itself"))),
            "상한에 적어야 모이고 적으면 걸린다는 것이 이 자리의 핵심이다: {v:?}"
        );
    }

    #[test]
    fn a_derived_action_inside_the_ceiling_is_planned() {
        let s = scan_with_evidence(r"C:\a\evil.exe", r"C:\a");
        let p = plan(&s, Some(&removing_manifest())).expect("계획");
        assert_eq!(p.body.actions.len(), 1, "{:?}", p.body.actions);
        assert!(p.body.is_complete(), "{:?}", p.body.deferred);
    }

    #[test]
    fn a_derived_action_outside_the_ceiling_is_refused_by_the_guard() {
        // 읽기 상한 밖은 **지울 수도 없다** (설계-02 §2). 도출이 만들어 냈더라도
        // 가드가 막아야 한다.
        let s = scan_with_evidence(r"C:\somewhere-else\evil.exe", r"C:\a");
        match plan(&s, Some(&removing_manifest())) {
            Err(PlanError::Guard(v)) => assert!(
                v.iter()
                    .any(|x| x.message.contains(remedy_sdk::i18n::t("상한", "ceiling"))),
                "읽기 상한 위반이어야 한다: {v:?}"
            ),
            other => panic!("가드가 막지 않았다: {other:?}"),
        }
    }

    fn fixed_protected() -> Protected {
        Protected::new(remedy_sdk::catalog::Platform::Windows, |s: &str| {
            s.replace("%SystemRoot%", "C:\\Windows")
                .replace("%ProgramFiles(x86)%", "C:\\Program Files (x86)")
                .replace("%ProgramFiles%", "C:\\Program Files")
        })
    }

    fn manifest_removing(path_target: Option<&str>) -> PluginManifest {
        let remove = match path_target {
            Some(p) => serde_json::json!([{ "path": p }]),
            None => serde_json::json!([{ "ref": "payload" }]),
        };
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": "x", "version": "0.1.0", "min_core": "1.0.0",
            "platforms": ["windows"], "name": {"en": "x"},
            "scan_roots": ["C:\\Windows\\System32"], "subjects": ["file"],
            "detect": [{"id": "payload", "subject": "file",
                        "where": [{"field": "path", "op": "contains", "value": "evil"}]}],
            "verdict": {"require": "payload"},
            "remediate": { "remove": remove }
        }))
        .expect("매니페스트")
    }

    #[test]
    fn an_individual_file_inside_a_protected_directory_is_still_treatable() {
        // **설계상 허용이다** (설계-03 §3). 악성코드는 실제로 System32 에 파일을
        // 떨어뜨리고, 그것을 못 건드리면 도구가 쓸모없어진다. 막는 것은 디렉터리
        // 자체와 재귀 삭제다.
        let s = scan_with_evidence(r"C:\Windows\System32\evil.dll", r"C:\Windows\System32");
        let p = plan_with(
            &s,
            Some(&manifest_removing(None)),
            &Allowed::new(),
            &Limits::default(),
            &fixed_protected(),
            Mode::default(),
        )
        .expect("개별 파일은 계획될 수 있어야 한다");
        assert_eq!(p.body.actions.len(), 1);
    }

    #[test]
    fn a_derived_action_on_the_protected_directory_itself_is_refused() {
        // 디렉터리 자체를 겨누면 어떤 Op 이든 거부된다.
        use remedy_sdk::artifact::EvidenceGroup;
        let mut s = scan_with_evidence(r"C:\Windows\System32\evil.dll", r"C:\Windows\System32");
        s.body.groups = vec![EvidenceGroup {
            id: "g0".into(),
            evidence: vec!["payload#0".into()],
            captures: [(
                "payload.dir".to_string(),
                r"C:\Windows\System32".to_string(),
            )]
            .into_iter()
            .collect(),
            verdict: true,
            excluded_reason: None,
        }];

        match plan_with(
            &s,
            Some(&manifest_removing(Some("${payload.dir}"))),
            &Allowed::new(),
            &Limits::default(),
            &fixed_protected(),
            Mode::default(),
        ) {
            Err(PlanError::Guard(v)) => assert!(
                v.iter()
                    .any(|x| x.message.contains(remedy_sdk::i18n::t("보호", "protected"))),
                "보호 디렉터리 자체를 막아야 한다: {v:?}"
            ),
            other => panic!("보호 디렉터리가 계획됐다: {other:?}"),
        }
    }

    #[test]
    fn wrong_envelope_is_rejected() {
        let mut e = scan_env(Vec::new());
        e.kind = ArtifactKind::Artifacts;
        assert!(plan_none(&e).is_err(), "봉투 종류를 확인해야 한다");
    }
}
