//! 네 단계를 잇는다 — `collect → evaluate → plan`.
//!
//! 단계 사이의 경계는 **파일**이다 (설계-03 §1). 그래서 각 단계는 앞 단계의 봉투를
//! 입력으로 받고, 중간에 시스템을 다시 보지 않는다. 이 성질이 없으면 스냅샷 기반
//! 회귀 검증도, 결정성 검증도 성립하지 않는다.

// `Observations` 는 Windows 수집 경로에서만 쓴다. 여기서 가져오면 백엔드가 없는
// 플랫폼에서 미사용 경고가 나고, CI 의 `clippy -D warnings` 가 그것을 오류로 만든다.
use remedy_artifacts::Scope;
pub use remedy_collect::extra::RefPolicy;
use remedy_sdk::artifact::{
    ArtifactsEnvelope, CoreInfo, Envelope, HostInfo, PlanEnvelope, ScanEnvelope,
};
use remedy_sdk::catalog::{Platform, Subject};
use remedy_sdk::manifest::PluginManifest;

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("수집 실패", "collection failed"))]
    Collect(#[from] remedy_artifacts::CollectError),
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("평가 실패", "evaluation failed"))]
    Evaluate(String),
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("계획 실패", "planning failed"))]
    Plan(#[from] remedy_plan::PlanError),
    #[error("{msg}", msg = remedy_sdk::i18n::t("이 플랫폼에는 수집 백엔드가 없습니다", "no collection backend on this platform"))]
    NoBackend,
    #[error("{0}")]
    Invalid(String),
}

impl PipelineError {
    /// 이 실패가 나가야 할 종료 코드 (설계-02 §8).
    ///
    /// 매핑을 오류 정의 옆에 둔다. CLI 로 흩어지면 새 오류가 늘 때 조용히
    /// 기본값(사용법 오류)으로 떨어지고, 그러면 무인 배포가 "가드가 막았다" 를
    /// "내가 잘못 불렀다" 로 읽는다.
    pub fn exit_code(&self) -> remedy_sdk::artifact::ExitCode {
        use remedy_sdk::artifact::ExitCode;
        match self {
            // 가드가 계획을 거부했다. 무인 모드는 프롬프트 없이 중단한다.
            PipelineError::Plan(remedy_plan::PlanError::Guard(_)) => ExitCode::GuardStop,
            // 상한 설정이 스스로 모순이다. 위협이 아니라 설정 문제이므로
            // 사용법 오류다 — 5 로 내면 사람이 감염을 찾으러 간다.
            _ => ExitCode::UsageError,
        }
    }
}

/// 한 번의 실행을 식별하는 값. **호출자가 준다.**
///
/// 파이프라인이 시계나 난수를 직접 읽으면 같은 입력에 대해 다른 출력이 나오고,
/// 결정성 검증(설계-09 P2)이 불가능해진다.
#[derive(Debug, Clone)]
pub struct RunMeta {
    pub run_id: String,
    /// RFC3339 UTC.
    pub created: String,
    pub host: HostInfo,
    pub core: CoreInfo,
}

impl RunMeta {
    /// 실제 실행용. 시계와 호스트 정보를 여기서 한 번만 읽는다.
    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        Self {
            // ULID 대신 시각 기반 식별자. P5 의 저널이 들어올 때 형식을 확정한다.
            //
            // **초 단위만으로는 충돌한다.** 실측으로 연속 4회 실행이 같은 run_id 를
            // 받았다. 설계-02 §5 의 격리소는 실행 1회당 `<run_id>.rq` 파일 하나를
            // 만들므로, 충돌하면 두 실행이 같은 격리 파일을 쓰고 **복원 데이터가
            // 사라진다.** 프로세스 id 와 나노초를 섞어 같은 초 안의 실행을 가른다.
            run_id: format!("run-{secs}-{:04x}-{:x}", std::process::id() & 0xffff, nanos),
            created: rfc3339(secs),
            host: HostInfo {
                // **환경 변수만 보면 Linux 에서 언제나 `unknown` 이다** —
                // `HOSTNAME` 은 export 되지 않는 셸 변수다 (설계-09 P12 실측).
                hostname: remedy_platform::hostname(),
                os: std::env::consts::OS.to_string(),
                version: String::new(),
                arch: std::env::consts::ARCH.to_string(),
            },
            core: CoreInfo {
                version: env!("CARGO_PKG_VERSION").to_string(),
                build: env!("REMEDY_TARGET").to_string(),
            },
        }
    }
}

/// 지금 시각, RFC 3339 UTC. 회차 로그의 줄마다 붙는다.
pub fn now_rfc3339() -> String {
    rfc3339(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// 매니페스트에서 수집 범위를 만든다. **선언한 것만 볼 수 있다.**
///
/// 루트 하나가 **여럿이 될 수 있다.** `%ALLUSERPROFILES%` 는 사용자 수만큼,
/// `%REMOVABLE%` 는 꽂힌 매체 수만큼이다 (설계-02 §4). 1:1 로 다루면 그
/// 토큰들이 전개되지 않은 채 경로로 쓰이고, 존재하지 않는 경로가 되어 **조용히
/// 0건**이 된다 — 다중 사용자 환경에서 현재 로그온 사용자만 치료되는 그 사고다.
///
/// 두 번째 반환값은 범위를 정하는 동안 알게 된 사실이다. 삼키면 안 된다.
pub fn scope_from_manifest(
    m: &PluginManifest,
    platform: Platform,
    expand: impl Fn(&str) -> remedy_platform::read::RootExpansion,
) -> Result<(Scope, Vec<remedy_collect::extra::Unresolved>), PipelineError> {
    if m.scan_roots.is_empty() {
        return Err(PipelineError::Invalid(
            "scan_roots 가 비어 있습니다. 읽기 상한이 없으면 아무것도 볼 수 없습니다".into(),
        ));
    }
    let mut roots = Vec::new();
    let mut removable = Vec::new();
    let mut notes: Vec<remedy_collect::extra::Unresolved> = Vec::new();
    for r in &m.scan_roots {
        let e = expand(r);
        // **어느 토큰에서 나왔는지는 여기서만 안다.** `expand_roots` 는 경로
        // 목록만 돌려주므로, 이 자리를 지나면 `E:\` 가 이동식이었다는 사실이
        // 사라진다 — 그리고 계획 시점에 다시 물으면 스냅샷을 뜬 기계와 다른
        // 답이 나온다.
        if r.to_ascii_uppercase().contains("%REMOVABLE%") {
            removable.extend(e.roots.iter().cloned());
        }
        roots.extend(e.roots);
        notes.extend(
            e.notes
                .into_iter()
                .map(|reason| remedy_collect::extra::Unresolved {
                    at: "scan_roots".into(),
                    reason,
                }),
        );
    }
    removable.sort();
    removable.dedup();
    // 순서를 고정하고 겹치는 것을 없앤다. 두 토큰이 같은 곳으로 펼쳐지면
    // 같은 파일이 두 번 수집되고, 그러면 스냅샷이 실행마다 달라진다.
    roots.sort();
    roots.dedup();

    // **전부 펼쳐지지 못했으면 볼 수 있는 곳이 없다.** 그 상태로 도는 실행은
    // 파일 0건을 "위협 없음" 으로 보고한다 (관측 01 D2).
    if roots.is_empty() {
        return Err(PipelineError::Invalid(format!(
            "scan_roots {}개가 하나도 펼쳐지지 않았습니다: {}",
            m.scan_roots.len(),
            notes
                .iter()
                .map(|u| u.reason.as_str())
                .collect::<Vec<_>>()
                .join(" · ")
        )));
    }

    // **이 플랫폼에서 수집기가 없는 subject 는 범위에서 뺀다** (설계-09 P12).
    //
    // 남겨 두면 수집기가 `Unsupported` 를 내 **수집 전체가 죽거나**, 빈 값을 내
    // 0건이 조용히 지나간다. 어느 쪽도 "선언한 것을 못 봤다" 로 읽히지 않는다.
    //
    // 린트가 작성 시점에 같은 것을 잡는다. 그래도 여기서 다시 보는 이유는
    // **서명이 끝난 뒤에도 카탈로그가 바뀌기 때문**이다 — 어제 통과한 플러그인이
    // 오늘 이 코어에서 수집되지 못할 수 있고, 그 사실은 그 실행에서 드러나야 한다.
    let mut subjects = Vec::new();
    for s in &m.subjects {
        let i = s.info();
        let collectable = match platform {
            Platform::Windows => i.windows,
            Platform::Linux => i.linux_from.is_some(),
            // 모르는 플랫폼에서 수집하지 않는다. 빈 관측이 "위협 없음" 이 된다.
            Platform::Darwin => false,
        };
        if collectable {
            subjects.push(*s);
        } else {
            notes.push(remedy_collect::extra::Unresolved {
                at: format!("subjects.{}", i.id),
                reason: format!(
                    "{} 에서는 '{}' 를 수집하지 못합니다 — 이 subject 에 걸린 규칙은 전부 미평가입니다",
                    platform.id(),
                    i.id
                ),
            });
        }
    }

    // 하나도 남지 않으면 그 실행은 아무것도 볼 수 없다. `roots` 가 전부 어긋난
    // 것과 같은 사고이고, 같은 자리에서 막는다.
    if subjects.is_empty() {
        return Err(PipelineError::Invalid(format!(
            "선언한 subject {}개가 {} 에서 하나도 수집되지 않습니다: {}",
            m.subjects.len(),
            platform.id(),
            notes
                .iter()
                .map(|u| u.reason.as_str())
                .collect::<Vec<_>>()
                .join(" · ")
        )));
    }

    // **좁힘도 전개해야 한다.** `%PROGRAMDATA%\Acme` 를 그대로 두면 존재하지
    // 않는 경로가 되고, 그 subject 는 조용히 0건이 된다.
    //
    // 그리고 전개가 **전부** 실패하면 오류로 막는다. 빈 목록을 그대로 두면
    // `roots_for` 가 무엇을 돌려주든 잘못이다 — `scan_roots` 로 물러나면
    // 작성자가 좁히려던 것이 조용히 넓어지고(권한이 놀랍게 늘어난다), 빈
    // 목록을 돌려주면 조용히 0건이다. 어느 쪽도 말없이 일어나서는 안 된다.
    let mut expanded_subject_roots: std::collections::BTreeMap<Subject, Vec<String>> =
        std::collections::BTreeMap::new();
    for (s, raw) in &m.subject_roots {
        let mut out = Vec::new();
        for r in raw {
            let e = expand(r);
            out.extend(e.roots);
            notes.extend(
                e.notes
                    .into_iter()
                    .map(|reason| remedy_collect::extra::Unresolved {
                        at: format!("subject_roots.{}", s.id()),
                        reason,
                    }),
            );
        }
        out.sort();
        out.dedup();
        if out.is_empty() {
            return Err(PipelineError::Invalid(format!(
                "subject_roots.{} 의 경로 {}개가 하나도 펼쳐지지 않았습니다. \
                 좁히려던 것이 조용히 넓어지거나 조용히 0건이 됩니다",
                s.id(),
                raw.len()
            )));
        }
        expanded_subject_roots.insert(*s, out);
    }

    // **옵트인 디렉터리도 전개한다.** `%ProgramData%\Acme\conf.d` 를 그대로
    // 두면 존재하지 않는 경로가 되고, 그 디렉터리는 조용히 0건이 된다 —
    // `subject_roots` 와 같은 자리다.
    //
    // 전부 실패해도 **오류로 막지 않는다.** 여기는 좁힘이 아니라 넓힘이라
    // 실패의 결과가 "조용히 넓어진다" 가 아니고, 경로 토큰이 그 플랫폼에
    // 없는 것(Windows 에 `/etc/pam.d`)이 정상이다. 대신 **말한다** — 이유가
    // `notes` 로 남아 화면과 `scan.json` 을 지난다.
    let mut expanded_config_dirs = Vec::new();
    for d in &m.text_config_dirs {
        let e = expand(d);
        expanded_config_dirs.extend(e.roots);
        notes.extend(
            e.notes
                .into_iter()
                .map(|reason| remedy_collect::extra::Unresolved {
                    at: "text_config_dirs".into(),
                    reason,
                }),
        );
    }
    expanded_config_dirs.sort();
    expanded_config_dirs.dedup();

    Ok((
        Scope {
            scan_roots: roots,
            removable_roots: removable,
            subjects,
            subject_roots: expanded_subject_roots,
            text_config_dirs: expanded_config_dirs,
            platform: host_platform(),
            max_hash_bytes: 32 * 1024 * 1024,
            max_files: 500_000,
        },
        notes,
    ))
}

/// **수집** 시점의 플랫폼. 지금 도는 기계가 곧 대상 기계다.
fn host_platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

/// **평가** 시점의 플랫폼 — 스냅샷이 만들어진 곳을 따른다.
///
/// 여기서 실행 중인 OS 를 쓰면 **같은 스냅샷이 기계마다 다른 판정을 낸다.**
/// 경로 대소문자 규칙은 대상 파일 시스템의 성질이고, `evaluate` 의 대상은 지금
/// 이 기계가 아니라 **스냅샷을 뜬 그 기계**다. 지원 엔지니어가 고객 PC 에서
/// `collect` 만 하고 분석은 사내에서 한다는 설계-03 §1 (4) 가 성립하려면
/// 분석 기계의 OS 가 결과를 바꾸면 안 된다.
///
/// 실제로 그렇게 갈라져 있었다. Windows 에서 ex01 예제는 판정 1건, 리눅스에서는
/// 0건이었다 — 스냅샷의 `scan_roots` 는 `C:\Users\...` 인데 파생 경로는
/// 소문자라, 대소문자를 가리는 쪽에서는 상한 밖으로 판정돼 그룹이 통째로
/// 제외됐다. P4 에서 가이드 예제 테스트가 들어온 뒤로 리눅스 검사를 돌리지
/// 않아 드러나지 않았다.
fn snapshot_platform(host: &HostInfo) -> Platform {
    if host.os.eq_ignore_ascii_case("windows") {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

/// 진단 모드 — **플러그인 없이** 수집만 한다 (설계-00 §5).
///
/// 이 경로에는 룰도, 판정도, 파괴 코드도 없다. 고객 PC 에서 이것만 돌리고 분석은
/// 사내에서 한다 (설계-03 §1).
pub fn collect_only(
    roots: Vec<String>,
    meta: &RunMeta,
) -> Result<ArtifactsEnvelope, PipelineError> {
    let backend = remedy_platform::live().ok_or(PipelineError::NoBackend)?;
    let expanded: Vec<String> = {
        use remedy_platform::read::EnvRead;
        roots.iter().map(|r| backend.expand(r)).collect()
    };
    let scope = Scope::diagnostic(
        expanded,
        if cfg!(windows) {
            Platform::Windows
        } else {
            Platform::Linux
        },
    );
    collect_with(backend, &scope, meta)
}

/// 매니페스트가 선언한 범위로 수집한다.
pub fn collect(
    manifest: &PluginManifest,
    meta: &RunMeta,
) -> Result<ArtifactsEnvelope, PipelineError> {
    collect_declared(manifest, meta, RefPolicy::ReportNow).map(|(env, _)| env)
}

/// 수집 + `collect_extra`. 해소하지 못한 추가 수집 항목을 함께 돌려준다.
///
/// **미해소를 조용히 버리지 않는다.** 담기지 않은 본문에 걸린 YARA 규칙은
/// 영영 미평가인데, 그 사실을 아무도 모르면 판정은 "안 맞았다" 로 나간다.
///
/// `refs` 로 `ref` 형의 처리를 가른다. `collect` 단독은 증거가 없어 풀 수 없으니
/// [`RefPolicy::ReportNow`], 평가가 뒤따르는 경로는 [`RefPolicy::ResolveLater`] 다.
pub fn collect_declared(
    manifest: &PluginManifest,
    meta: &RunMeta,
    refs: RefPolicy,
) -> Result<(ArtifactsEnvelope, Vec<remedy_collect::extra::Unresolved>), PipelineError> {
    let backend = remedy_platform::live().ok_or(PipelineError::NoBackend)?;
    let (scope, notes) = {
        use remedy_platform::read::ExpandRoots;
        scope_from_manifest(manifest, host_platform(), |s| {
            backend.expand_roots(s, manifest.allow_removable)
        })?
    };
    let (env, mut unresolved) = collect_with_extra(backend, &scope, meta, Some(manifest), refs)?;
    // 토큰이 아무것도 되지 못한 사실과 이 플랫폼에서 수집기가 없는 subject 는
    // `collect_extra` 미해소와 **같은 자리**에서 보고한다 — 셋 다 "선언한 것을 못
    // 봤다" 이고, 사람이 볼 곳은 하나여야 한다.
    unresolved.extend(notes);
    Ok((env, unresolved))
}

fn collect_with<P: Backend>(
    backend: P,
    scope: &Scope,
    meta: &RunMeta,
) -> Result<ArtifactsEnvelope, PipelineError> {
    collect_with_extra(backend, scope, meta, None, RefPolicy::ReportNow).map(|(env, _)| env)
}

/// 수집이 요구하는 읽기 능력 전부.
///
/// **백엔드 타입을 여기 적지 않는다.** 적으면 `#[cfg(windows)]` 가 파이프라인
/// 본문까지 번지고, 그러면 Linux 에서 컴파일되는지 아무도 모르게 된다 — P2 에서
/// 실제로 그렇게 깨졌고 CI 가 한 번도 돌지 않아 드러나지 않았다 (설계-09 P12).
trait Backend:
    remedy_platform::read::FsRead
    + remedy_platform::read::RegistryRead
    + remedy_platform::read::EnvRead
    + remedy_platform::read::ProcessRead
{
}

impl<T> Backend for T where
    T: remedy_platform::read::FsRead
        + remedy_platform::read::RegistryRead
        + remedy_platform::read::EnvRead
        + remedy_platform::read::ProcessRead
{
}

fn collect_with_extra<P: Backend>(
    backend: P,
    scope: &Scope,
    meta: &RunMeta,
    manifest: Option<&PluginManifest>,
    refs: RefPolicy,
) -> Result<(ArtifactsEnvelope, Vec<remedy_collect::extra::Unresolved>), PipelineError> {
    use remedy_artifacts::Observations;

    let collector = remedy_collect::Collector::new(backend);
    let mut obs: Observations = remedy_collect::collect_all(&collector, scope)?;

    // **추가 수집은 관찰이 끝난 뒤다.** 본문을 담는 것은 파괴가 아니지만
    // 스냅샷을 키우므로, 무엇이 이미 담겼는지 안 뒤에 붙인다.
    let unresolved = match manifest {
        Some(m) if !m.collect_extra.is_empty() => {
            remedy_platform::progress::set_stage("extra");
            remedy_collect::extra::collect_extra(collector.platform(), m, scope, &mut obs, refs)
        }
        _ => Vec::new(),
    };

    Ok((
        remedy_artifacts::assemble(
            meta.run_id.clone(),
            meta.created.clone(),
            meta.host.clone(),
            meta.core.clone(),
            scope,
            obs,
        ),
        unresolved,
    ))
}

/// 스냅샷을 뜬 기계의 범위를 봉투에서 되읽는다.
///
/// 매니페스트를 다시 읽어 넓히면 스냅샷에 없는 곳을 봤다고 말하는 셈이 된다.
///
/// **공개인 이유**: 압력 측정(`remedy_detect::pressure`)이 평가와 *같은* 상한을
/// 써야 한다. 재는 쪽이 상한을 따로 만들면 그 둘이 갈라지는 날 압력 수치가
/// 조용히 거짓이 된다 — 이 게이트가 막으려는 것이 정확히 그런 침묵이다.
pub fn scope_of(artifacts: &ArtifactsEnvelope) -> Scope {
    Scope {
        scan_roots: artifacts.body.scope.scan_roots.clone(),
        removable_roots: artifacts.body.scope.removable_roots.clone(),
        subjects: artifacts.body.scope.subjects.clone(),
        subject_roots: artifacts.body.scope.subject_roots.clone(),
        // 봉투에 적힌 것을 그대로 되읽는다. 매니페스트를 다시 읽으면 스냅샷을
        // 뜰 때 읽지 않은 디렉터리를 읽었다고 말하게 된다.
        text_config_dirs: artifacts.body.scope.text_config_dirs.clone(),
        platform: snapshot_platform(&artifacts.host),
        max_hash_bytes: 0,
        max_files: 0,
    }
}

/// `ref` 형 해소 — 증거가 생긴 뒤에 한 번 더 읽는다.
fn resolve_refs_pass(
    artifacts: &mut ArtifactsEnvelope,
    scan: &ScanEnvelope,
    manifest: &PluginManifest,
) -> Result<remedy_collect::extra::RefPass, PipelineError> {
    let backend = remedy_platform::live().ok_or(PipelineError::NoBackend)?;
    let scope = scope_of(artifacts);
    Ok(remedy_collect::extra::resolve_refs(
        &backend,
        manifest,
        &scope,
        &scan.body.evidence,
        artifacts,
    ))
}

/// 스냅샷을 평가한다. **시스템을 다시 보지 않는다.**
pub fn evaluate(
    artifacts: &ArtifactsEnvelope,
    manifest: &PluginManifest,
) -> Result<ScanEnvelope, PipelineError> {
    evaluate_with_rules(artifacts, manifest, &[])
}

/// 평가하되 플러그인의 YARA 룰을 함께 준다.
///
/// 룰을 스냅샷과 따로 받는 이유: 룰은 **플러그인의 것**이고 스냅샷은 관찰이다.
/// 같은 스냅샷을 다른 플러그인으로 평가할 수 있어야 한다.
pub fn evaluate_with_rules(
    artifacts: &ArtifactsEnvelope,
    manifest: &PluginManifest,
    rules: &[(String, String)],
) -> Result<ScanEnvelope, PipelineError> {
    // 평가 범위는 **스냅샷이 실제로 담고 있는 범위**다.
    let scope = scope_of(artifacts);
    // 플러그인이 실은 `.yar` 을 붙인다. 없으면 YARA 규칙은 전부 미평가다.
    let snapshot = remedy_detect::Snapshot::from_envelope(artifacts).with_rules(rules);
    let mut body = remedy_detect::evaluate(&snapshot, manifest, &scope)
        .map_err(|e| PipelineError::Evaluate(e.to_string()))?;

    // 스냅샷이 불완전했다는 사실을 평가 결과에 실어 보낸다. 평가기는 이것을
    // 판단할 위치가 아니고, 봉투를 조립하는 여기가 두 쪽을 다 보는 유일한 자리다.
    //
    // **평가기가 아는 둘은 지키며 합친다** — 재지 못한 YARA 규칙(결정 2026-10-26)
    // 과 견주지 못한 버전(2026-10-27 · C-1). 스냅샷의 관측으로 통째로 덮으면
    // 그것이 지워지고, 판정이 없을 때 종료 코드 0 "위협 없음" 이 다시 나간다.
    // 룰이 선언한 확인 필요(`verdict.unconfirmed` · 2026-11-09)도 평가기만 안다 — 같은 이유로 지킨다.
    let unevaluated = std::mem::take(&mut body.observation.unevaluated_rules);
    let unreadable = std::mem::take(&mut body.observation.unreadable_versions);
    let unconfirmed = std::mem::take(&mut body.observation.unconfirmed);
    body.observation = artifacts.body.observation();
    body.observation.unevaluated_rules = unevaluated;
    body.observation.unreadable_versions = unreadable;
    body.observation.unconfirmed = unconfirmed;
    body.scan_roots = artifacts.body.scope.scan_roots.clone();
    body.removable_roots = artifacts.body.scope.removable_roots.clone();

    Ok(Envelope {
        schema_version: artifacts.schema_version,
        kind: remedy_sdk::artifact::ArtifactKind::Scan,
        run_id: artifacts.run_id.clone(),
        created: artifacts.created.clone(),
        host: artifacts.host.clone(),
        core: artifacts.core.clone(),
        plugins: artifacts.plugins.clone(),
        body,
    })
}

pub fn plan(
    scan: &ScanEnvelope,
    manifest: Option<&PluginManifest>,
) -> Result<PlanEnvelope, PipelineError> {
    Ok(remedy_plan::plan(scan, manifest)?)
}

/// 상한을 명시해 계획을 만든다. 설정 파일에서 읽은 값이 여기로 들어온다.
///
/// **보호 목록은 스냅샷을 뜬 기계의 것이어야 한다.** 지원 엔지니어가 고객 PC 에서
/// `collect` 만 하고 분석은 사내에서 한다(설계-03 §1 (4)). 그 사내 기계가
/// 리눅스면, 실행 중인 OS 를 따랐을 때 Windows 보호 경로가 목록에서 통째로
/// 빠지고 `C:\Windows\System32` 를 겨눈 계획이 통과한다. 그 계획은 나중에
/// Windows 기계에서 수행된다.
pub fn plan_with(
    scan: &ScanEnvelope,
    manifest: Option<&PluginManifest>,
    // 조직 허용 목록 (설계-03 §3 5층). 비어 있으면 면제가 없다.
    allow: &remedy_plan::Allowed,
    limits: &remedy_plan::Limits,
    mode: remedy_plan::Mode,
) -> Result<PlanEnvelope, PipelineError> {
    Ok(remedy_plan::plan_with(
        scan,
        manifest,
        allow,
        limits,
        &protected_for(&scan.host),
        mode,
    )?)
}

/// 스냅샷을 뜬 기계의 보호 목록.
///
/// 대상 플랫폼과 실행 플랫폼이 다르면 `%SystemRoot%` 같은 토큰은 전개되지
/// 않는다. 전개하지 못한 항목을 **버리지 않는 것**이 `Protected` 의 규약이지만,
/// 그러면 그 경로는 실질적으로 보호받지 못한다. 그래서 여기서 대상 플랫폼의
/// 관례적 위치로 채워 준다 — 스냅샷에 그 값이 실려 오기 전까지의 임시 조치이며,
/// 실제 값이 다른 기계(예: `D:\Windows`)에서는 여전히 어긋난다.
pub fn protected_for(host: &HostInfo) -> remedy_plan::Protected {
    let platform = snapshot_platform(host);
    if platform == host_platform() {
        return remedy_plan::Protected::new(platform, remedy_plan::expand_env_for_protection);
    }
    remedy_plan::Protected::new(platform, |s| match platform {
        Platform::Windows => s
            .replace("%SystemRoot%", "C:\\Windows")
            .replace("%ProgramFiles(x86)%", "C:\\Program Files (x86)")
            .replace("%ProgramFiles%", "C:\\Program Files"),
        _ => remedy_plan::expand_env_for_protection(s),
    })
}

/// `scan` = collect + evaluate (설계-09 §3.4).
pub fn scan(
    manifest: &PluginManifest,
    meta: &RunMeta,
) -> Result<(ArtifactsEnvelope, ScanEnvelope), PipelineError> {
    scan_with_rules(manifest, meta, &[]).map(|(a, s, _)| (a, s))
}

/// 수집 + 평가. 플러그인의 YARA 룰과 미해소 `collect_extra` 를 함께 다룬다.
///
/// # 왜 평가가 두 번 나오는가
///
/// `collect_extra` 의 `ref` 형은 **증거를 가리키고 증거는 평가가 만든다.**
/// 그래서 순서가 `수집 → 평가 → ref 해소 → 재평가` 다. 재평가는 새 본문이
/// 실제로 담겼을 때만 한다.
///
/// **결정성은 유지된다.** 저장되는 `artifacts.json` 은 해소가 끝난 것이므로
/// `evaluate(저장된 artifacts.json)` 이 저장된 `scan.json` 을 재현한다
/// (설계-01 D9 결정 2). 청정 코퍼스(G1)도 같은 이유로 성립한다.
///
/// **한 번만 더 돈다.** 재평가가 만든 증거로 또 풀면 패스 수가 데이터에
/// 좌우되고, 그러면 이 실행이 무엇을 읽는지 미리 말할 수 없다.
pub fn scan_with_rules(
    manifest: &PluginManifest,
    meta: &RunMeta,
    rules: &[(String, String)],
) -> Result<
    (
        ArtifactsEnvelope,
        ScanEnvelope,
        Vec<remedy_collect::extra::Unresolved>,
    ),
    PipelineError,
> {
    let has_ref = manifest
        .collect_extra
        .iter()
        .any(|e| matches!(e, remedy_sdk::manifest::CollectExtra::Ref(_)));
    let policy = if has_ref {
        RefPolicy::ResolveLater
    } else {
        RefPolicy::ReportNow
    };

    let (mut artifacts, mut unresolved) = collect_declared(manifest, meta, policy)?;
    remedy_platform::progress::set_stage("evaluate");
    let mut s = evaluate_with_rules(&artifacts, manifest, rules)?;

    if has_ref {
        let pass = resolve_refs_pass(&mut artifacts, &s, manifest)?;
        if pass.taken > 0 {
            // 훑을 바이트가 생겼다. 다시 평가하지 않으면 그 본문에 걸린 YARA
            // 규칙이 미평가인 채로 남는다.
            s = evaluate_with_rules(&artifacts, manifest, rules)?;
        }
        unresolved.extend(pass.unresolved);
    }
    Ok((artifacts, s, unresolved))
}

/// 전 단계를 한 번에. P6 에서 `apply` 가 붙으면 여기에 이어진다.
pub struct Pipeline;

impl Pipeline {
    pub fn read_only(
        manifest: &PluginManifest,
        meta: &RunMeta,
    ) -> Result<(ArtifactsEnvelope, ScanEnvelope, PlanEnvelope), PipelineError> {
        let (artifacts, s) = scan(manifest, meta)?;
        remedy_platform::progress::set_stage("plan");
        let p = plan(&s, Some(manifest))?;
        Ok((artifacts, s, p))
    }

    /// subject 가 선언되었지만 아직 수집기가 없는 경우를 알린다.
    ///
    /// 조용히 빈 배열을 담으면 "없다" 와 "못 봤다" 가 구분되지 않고, 그 스냅샷으로
    /// "위협 없음" 이라는 결론이 나온다.
    pub fn unsupported_subjects(m: &PluginManifest) -> Vec<(Subject, &'static str)> {
        m.subjects
            .iter()
            .filter(|s| s.info().implemented_in > remedy_sdk::IMPLEMENTED_THROUGH)
            .map(|s| (*s, s.info().implemented_in.as_str()))
            .collect()
    }
}

// ────────────────────────────────────────────── verify (P9)

/// 재판정 결과 (설계-03 §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// 같은 플러그인이 더 이상 판정하지 않는다.
    Clean,
    /// 다시 판정됐다. **자동으로 재치료하지 않는다** — 같은 치료를 반복해도
    /// 같은 결과가 나올 가능성이 높고, 재발은 우리가 놓친 지속성 경로가
    /// 있다는 신호이므로 사람의 판단이 필요하다.
    Recurred,
    /// 판정은 서지 않는데 원래 증거의 일부가 남아 있다.
    Partial,
    /// 판정도 남은 증거도 없지만 **다 보지 못했다** — 잘림 · 접근 거부 · 미수집
    /// subject · 선언한 자리 전부 없음 · YARA 미평가(`Observation::is_complete`).
    /// "치료 성공" 을 말할 수 없다(결정 2026-10-26). 그 전에는 여기서 `Clean` 이
    /// 나가, 재부팅 뒤 자동 재검사가 다 보지 못하고도 "치료가 유지됐다" 고 적었다.
    Incomplete,
}

impl VerifyOutcome {
    pub const fn id(&self) -> &'static str {
        match self {
            VerifyOutcome::Clean => "clean",
            VerifyOutcome::Recurred => "recurred",
            VerifyOutcome::Partial => "partial",
            VerifyOutcome::Incomplete => "incomplete",
        }
    }
}

/// 재수집 + 재평가.
///
/// # 경로 확인이 아니다
///
/// "제거한 경로가 여전히 비어 있는가" 만 보면 **랜덤 이름을 쓰는 위협 앞에서
/// 무력하다.** 페이로드가 `%LOCALAPPDATA%\Programs\<랜덤>` 에 있었다면 재감염
/// 시 **다른 랜덤 이름**으로 생기고 원래 경로는 계속 비어 있다. 그래서 수집과
/// 평가를 다시 돌려 **판정이 재현되는지**를 본다 (설계-03 §8).
///
/// # `resume` 과 정반대다
///
/// `resume` 은 이미 승인된 계획을 이어 실행하며 **절대 재스캔하지 않는다** —
/// 사용자가 승인한 것과 다른 일이 벌어지면 안 되기 때문이다. `verify` 는
/// 반대로 **반드시 재평가한다** — 같은 결과가 나오는지가 질문이기 때문이다.
/// 두 명령을 분리한 것이 이 때문이다.
///
/// `baseline` 은 치료 전 `scan.json` 의 증거 id 다. 주면 "일부만 잔존" 을
/// 가려낼 수 있고, 주지 않으면 재발 여부와 관측 완전성만 답한다 — **없는 것을
/// 있는 척하지 않는다.**
///
/// 해소하지 못한 선언도 `scan_with_rules` 처럼 돌려준다. 재검사가 다 보지 못했을 때
/// **왜 못 봤는지**(본문 상한 등)가 거기 있다 — 2026-10-26 전에는 여기서 버렸다.
pub fn verify(
    manifest: &PluginManifest,
    meta: &RunMeta,
    rules: &[(String, String)],
    baseline: &[String],
) -> Result<
    (
        ArtifactsEnvelope,
        ScanEnvelope,
        Vec<remedy_collect::extra::Unresolved>,
        VerifyOutcome,
    ),
    PipelineError,
> {
    let (artifacts, scan, unresolved) = scan_with_rules(manifest, meta, rules)?;
    let outcome = classify(&scan, baseline);
    Ok((artifacts, scan, unresolved, outcome))
}

/// 재평가 결과를 네 갈래로 가른다.
///
/// **판정이 먼저다.** 증거가 남아 있어도 판정이 서지 않으면 재발이 아니다 —
/// 판정 게이트는 독립적인 두 근거의 논리곱이고, 한쪽만 남은 것은 치료가
/// 무너뜨린 것이 그 곱이라는 뜻이다.
///
/// **관측 완전성은 마지막이다** — `scan` 의 종료 코드와 같은 규칙이다. 다 보지
/// 못한 것은 "없다" 만 뒤집는다: 다시 선 판정과 남은 증거는 그래도 유효하다.
fn classify(scan: &ScanEnvelope, baseline: &[String]) -> VerifyOutcome {
    if !scan.body.verdicts.is_empty() {
        return VerifyOutcome::Recurred;
    }
    let still = scan
        .body
        .evidence
        .iter()
        .any(|e| baseline.iter().any(|b| b == &e.id));
    if still {
        VerifyOutcome::Partial
    } else if !scan.body.observation.is_complete() {
        VerifyOutcome::Incomplete
    } else {
        VerifyOutcome::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_is_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_771_500_600), "2026-02-19T11:30:00Z");
    }

    /// **평가기가 아는 둘이 합치는 과정에서 살아남는가.**
    ///
    /// `body.observation = artifacts.body.observation()` 한 줄이 스냅샷의 관측으로
    /// 통째로 덮으므로, 꺼내 두고 다시 넣는 두 줄을 지우면 **종료 0 "위협 없음"
    /// 이 그대로 돌아온다**. 그 두 줄을 지켜 보는 시험이 없었다
    /// (2026-10-27 적대 검증).
    #[test]
    fn the_evaluator_facts_survive_the_merge() {
        use remedy_sdk::artifact::{CoreInfo, HostInfo};

        let m: PluginManifest = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": "x", "version": "0.1.0", "min_core": "1.0.0",
            "platforms": ["linux"], "name": {"en": "x"}, "kind": "check",
            "scan_roots": ["/etc/x"], "subjects": ["browser_extension"],
            "detect": [{"id": "a", "subject": "browser_extension",
                        "where": [{"field": "version", "op": "version_lt",
                                   "value": "8.2.29"}]}],
            "verdict": {"require": "a"}
        }))
        .unwrap();

        // 꼬리 붙은 버전 하나. 평가기는 이것을 **견주지 못했다**고 적는다.
        let mut obs = remedy_artifacts::Observations::default();
        obs.put(
            Subject::BrowserExtension,
            &[remedy_artifacts::BrowserExtensionRecord {
                browser: "chrome".into(),
                profile: "Default".into(),
                ext_id: "abc".into(),
                name: "X".into(),
                version: "8.2.28-1ubuntu1".into(),
                path: "/etc/x/abc".into(),
            }],
        );
        let mut scope = remedy_artifacts::Scope::diagnostic(vec!["/etc/x".into()], Platform::Linux);
        scope.subjects = vec![Subject::BrowserExtension];
        let env = remedy_artifacts::assemble(
            "r".into(),
            "2026-10-27T00:00:00Z".into(),
            HostInfo {
                hostname: "H".into(),
                os: "linux".into(),
                version: "1".into(),
                arch: "x86_64".into(),
            },
            CoreInfo {
                version: "1.0.0".into(),
                build: "t".into(),
            },
            &scope,
            obs,
        );

        let scan = evaluate(&env, &m).expect("평가");
        assert_eq!(
            scan.body.observation.unreadable_versions,
            vec!["8.2.28-1ubuntu1".to_string()],
            "합치면서 지워졌다 — 종료 0 이 돌아온다"
        );
        assert!(
            !scan.body.observation.is_complete(),
            "{:?}",
            scan.body.observation
        );
        // 스냅샷의 사실도 함께 실려 와야 한다 — 한쪽만 남으면 다른 쪽이 지워진다.
        assert_eq!(scan.body.observation.declared_roots, 1);
    }

    #[test]
    fn empty_scan_roots_is_rejected() {
        // 상한이 없으면 아무것도 볼 수 없다. 조용히 통과시키면 룰이 안 맞는
        // 이유를 찾느라 시간을 버린다.
        let m: PluginManifest = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": "x", "version": "0.1.0", "min_core": "1.0.0",
            "platforms": ["windows"], "name": {"en": "x"},
            "scan_roots": [], "subjects": ["file"],
            "detect": [{"id": "a", "subject": "file",
                        "where": [{"field": "path", "op": "contains", "value": "x"}]}],
            "verdict": {"require": "a"}
        }))
        .unwrap();
        assert!(scope_from_manifest(&m, Platform::Windows, one_to_one).is_err());
    }

    /// 시험용 1:1 전개. 토큰을 펴지 않는다.
    fn one_to_one(s: &str) -> remedy_platform::read::RootExpansion {
        remedy_platform::read::RootExpansion {
            roots: vec![s.to_string()],
            notes: Vec::new(),
        }
    }

    fn manifest_with_roots(roots: &[&str]) -> PluginManifest {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": "x", "version": "0.1.0", "min_core": "1.0.0",
            "platforms": ["windows"], "name": {"en": "x"},
            "scan_roots": roots, "subjects": ["file"],
            "detect": [{"id": "a", "subject": "file",
                        "where": [{"field": "path", "op": "contains", "value": "x"}]}],
            "verdict": {"require": "a"}
        }))
        .unwrap()
    }

    #[test]
    fn one_root_can_expand_into_several() {
        // `%ALLUSERPROFILES%` 가 사용자 수만큼 펼쳐지지 않으면, 다중 사용자
        // 환경에서 현재 로그온 사용자만 치료되고 나머지는 감염 상태로 남는다.
        let m = manifest_with_roots(&["%ALLUSERPROFILES%\\AppData"]);
        let (scope, notes) = scope_from_manifest(&m, Platform::Windows, |_| {
            remedy_platform::read::RootExpansion {
                roots: vec![
                    "c:\\users\\a\\appdata".into(),
                    "c:\\users\\b\\appdata".into(),
                ],
                notes: vec!["둘만 봤다".into()],
            }
        })
        .expect("펼쳐졌다");
        assert_eq!(scope.scan_roots.len(), 2);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].at, "scan_roots");
        assert_eq!(notes[0].reason, "둘만 봤다");
    }

    fn manifest_for(platforms: &[&str], subjects: &[&str]) -> PluginManifest {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": "x", "version": "0.1.0", "min_core": "1.0.0",
            "platforms": platforms, "name": {"en": "x"},
            "scan_roots": ["/tmp"], "subjects": subjects,
            "detect": [{"id": "a", "subject": subjects[0],
                        "where": [{"field": "path", "op": "contains", "value": "x"}]}],
            "verdict": {"require": "a"}
        }))
        .unwrap()
    }

    #[test]
    fn a_subject_with_no_collector_on_this_platform_leaves_the_scope() {
        // **조용히 0건이 되면 안 된다.** `firewall_rule` 의 수집기는 레지스트리
        // 전용이라 Linux 에서는 아무것도 낼 수 없다. 범위에 남겨 두면 수집이
        // `Unsupported` 로 죽거나 빈 값이 "규칙이 없다" 로 읽힌다.
        let m = manifest_for(&["windows", "linux"], &["file", "firewall_rule"]);
        let (scope, notes) =
            scope_from_manifest(&m, Platform::Linux, one_to_one).expect("file 이 남는다");
        assert_eq!(scope.subjects, vec![Subject::File], "file 만 남아야 한다");

        let note = notes
            .iter()
            .find(|u| u.at == "subjects.firewall_rule")
            .unwrap_or_else(|| panic!("firewall_rule 이 빠진 사실이 보고되지 않았다: {notes:?}"));
        assert!(
            note.reason.contains("미평가"),
            "그 subject 에 걸린 규칙이 어떻게 되는지 말해야 한다: {}",
            note.reason
        );
    }

    #[test]
    fn the_same_subject_stays_on_windows() {
        // 위 시험이 통과하는 방법 중 하나는 그 subject 를 어디서도 안 넣는 것이다.
        // 그러면 Windows 가 조용히 망가진다.
        let m = manifest_for(&["windows", "linux"], &["file", "firewall_rule"]);
        let (scope, notes) =
            scope_from_manifest(&m, Platform::Windows, one_to_one).expect("둘 다 남는다");
        assert_eq!(scope.subjects, vec![Subject::File, Subject::FirewallRule]);
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn a_run_that_can_collect_nothing_stops() {
        // `scan_roots` 가 전부 어긋난 것과 같은 사고다 — 볼 수 있는 것이 없는
        // 실행이 "위협 없음" 을 내면 안 된다 (관측 01 D2).
        let m = manifest_for(&["linux"], &["registry_value"]);
        let e = scope_from_manifest(&m, Platform::Linux, one_to_one).expect_err("멈춰야 한다");
        assert!(e.to_string().contains("registry_value"), "{e}");
    }

    #[test]
    fn an_unknown_platform_collects_nothing() {
        // 모르는 플랫폼에서 빈 관측이 "위협 없음" 이 되면 안 된다.
        let m = manifest_for(&["windows", "linux"], &["file"]);
        let e = scope_from_manifest(&m, Platform::Darwin, one_to_one).expect_err("멈춰야 한다");
        assert!(e.to_string().contains("darwin"), "{e}");
    }

    #[test]
    fn roots_that_expand_to_the_same_place_are_counted_once() {
        // 같은 곳을 두 번 훑으면 같은 파일이 두 번 담기고, 스냅샷이 실행마다
        // 달라진다.
        let m = manifest_with_roots(&["%A%", "%B%"]);
        let (scope, _) = scope_from_manifest(&m, Platform::Windows, |_| {
            remedy_platform::read::RootExpansion {
                roots: vec!["c:\\같은곳".into()],
                notes: Vec::new(),
            }
        })
        .expect("펼쳐졌다");
        assert_eq!(scope.scan_roots, vec!["c:\\같은곳".to_string()]);
    }

    #[test]
    fn a_root_that_expands_to_nothing_stops_the_run() {
        // **아무 곳도 볼 수 없는 실행이 "위협 없음" 을 내면 안 된다** (관측 01 D2).
        // 이유도 함께 나와야 한다 — 그러지 않으면 작성자는 왜 안 도는지 모른다.
        let m = manifest_with_roots(&["%REMOVABLE%"]);
        let e = scope_from_manifest(&m, Platform::Windows, |_| {
            remedy_platform::read::RootExpansion {
                roots: Vec::new(),
                notes: vec!["allow_removable 을 선언하지 않아 펼치지 않았다".into()],
            }
        })
        .expect_err("멈춰야 한다");
        assert!(e.to_string().contains("allow_removable"), "{e}");
    }

    #[test]
    fn evaluation_platform_comes_from_the_snapshot_not_the_host() {
        // **같은 스냅샷은 어느 기계에서 평가해도 같은 답을 내야 한다.**
        // 지원 엔지니어가 고객 PC 에서 `collect` 만 하고 분석은 사내에서 한다는
        // 설계-03 §1 (4) 가 이것에 달려 있다.
        //
        // 이 함수가 실행 중인 OS 를 보던 동안, Windows 스냅샷을 리눅스에서
        // 평가하면 경로 비교가 대소문자를 가려 판정이 사라졌다. ex01 예제가
        // Windows 에서 1건, 리눅스에서 0건이었다.
        let win = HostInfo {
            hostname: "W".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        };
        let lin = HostInfo {
            os: "linux".into(),
            ..win.clone()
        };
        assert_eq!(snapshot_platform(&win), Platform::Windows);
        assert_eq!(snapshot_platform(&lin), Platform::Linux);

        // 대소문자가 섞여 와도 스냅샷이 말한 것을 따른다.
        let mixed = HostInfo {
            os: "Windows".into(),
            ..win.clone()
        };
        assert_eq!(snapshot_platform(&mixed), Platform::Windows);

        // 그리고 **호스트와 무관해야 한다** — 이 검사가 두 OS 에서 같은 값을 낸다.
        assert_eq!(snapshot_platform(&win), Platform::Windows);
    }

    #[test]
    fn the_protected_list_follows_the_snapshot_not_the_host() {
        // **리눅스에서 Windows 스냅샷을 분석하는 경로가 실재한다** — 고객 PC 에서
        // collect 만 하고 분석은 사내에서 한다(설계-03 §1 (4)). 실행 중인 OS 를
        // 따르면 Windows 보호 경로가 목록에서 통째로 빠지고, `C:\Windows\System32`
        // 를 겨눈 계획이 통과한 뒤 나중에 Windows 기계에서 수행된다.
        let win = HostInfo {
            hostname: "W".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        };
        let p = protected_for(&win);
        assert!(
            p.check("C:\\Windows\\System32\\kernel32.dll").is_some(),
            "Windows 스냅샷인데 System32 가 보호되지 않는다"
        );
        assert!(p.check("C:\\Windows\\WinSxS\\x").is_some());
        assert!(p.check("C:\\Users\\a\\Downloads\\x.exe").is_none());

        let lin = HostInfo {
            os: "linux".into(),
            ..win.clone()
        };
        let p = protected_for(&lin);
        assert!(p.check("/usr/bin/ls").is_some());
        assert!(p.check("/home/a/x").is_none());
    }

    #[test]
    fn subjects_from_a_later_phase_are_reported() {
        // **카탈로그와 같은 곳을 본다**는 것이 여기서 재는 것이다. 게이트가
        // 올라가면 보고할 것이 없어지고 그것도 사실이지만, 기대 목록을 손으로
        // 적어 두면 게이트를 올릴 때마다 이 시험이 거짓말을 하기 시작한다.
        let subjects: Vec<serde_json::Value> = Subject::ALL
            .iter()
            .map(|s| serde_json::Value::String(s.id().to_string()))
            .collect();
        let m: PluginManifest = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": "x", "version": "0.1.0", "min_core": "1.0.0",
            "platforms": ["windows"], "name": {"en": "x"},
            "scan_roots": ["C:\\x"], "subjects": subjects,
            "detect": [{"id": "a", "subject": "file",
                        "where": [{"field": "path", "op": "contains", "value": "x"}]}],
            "verdict": {"require": "a"}
        }))
        .unwrap();

        let expected: Vec<Subject> = Subject::ALL
            .into_iter()
            .filter(|s| s.info().implemented_in > remedy_sdk::IMPLEMENTED_THROUGH)
            .collect();
        let got: Vec<Subject> = Pipeline::unsupported_subjects(&m)
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        assert_eq!(got, expected);
    }
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use remedy_sdk::artifact::{Evidence, EvidenceGroup, Observation, ScanBody};
    use remedy_sdk::catalog::Subject;

    fn ev(id: &str) -> Evidence {
        Evidence {
            id: id.into(),
            rule: "r".into(),
            subject: Subject::File,
            score: None,
            target: serde_json::json!({ "path": r"C:\a\x" }),
            captures: Default::default(),
            matched: Vec::new(),
        }
    }

    fn scan_of(evidence: Vec<Evidence>, verdicts: Vec<String>) -> ScanEnvelope {
        Envelope {
            schema_version: 1,
            kind: remedy_sdk::artifact::ArtifactKind::Scan,
            run_id: "v".into(),
            created: "2026-08-23T00:00:00Z".into(),
            host: HostInfo {
                hostname: "h".into(),
                os: "windows".into(),
                version: "10".into(),
                arch: "x86_64".into(),
            },
            core: CoreInfo {
                version: "0".into(),
                build: "t".into(),
            },
            plugins: Vec::new(),
            body: ScanBody {
                evidence,
                groups: vec![EvidenceGroup {
                    id: "g0".into(),
                    evidence: Vec::new(),
                    captures: Default::default(),
                    verdict: !verdicts.is_empty(),
                    excluded_reason: None,
                }],
                verdicts,
                issues: Vec::new(),
                observation: Observation::default(),
                scan_roots: vec![r"C:".into()],
                removable_roots: Vec::new(),
            },
        }
    }

    #[test]
    fn nothing_found_is_treatment_success() {
        assert_eq!(
            classify(&scan_of(Vec::new(), Vec::new()), &["e#0".into()]),
            VerifyOutcome::Clean
        );
    }

    #[test]
    fn a_verdict_again_is_recurrence_even_with_new_evidence_ids() {
        // **랜덤 이름을 쓰는 위협이 이 자리를 시험한다.** 재감염은 다른 경로에
        // 다른 증거 id 로 생기므로, 원래 증거와 대조하는 방식으로는 잡지
        // 못한다. 판정이 다시 섰는가가 질문이다 (설계-03 §8).
        let s = scan_of(vec![ev("완전히#다른#id")], vec!["g0".into()]);
        assert_eq!(classify(&s, &["e#0".into()]), VerifyOutcome::Recurred);
        // 치료 전 증거를 몰라도 재발은 재발이다.
        assert_eq!(classify(&s, &[]), VerifyOutcome::Recurred);
    }

    #[test]
    fn surviving_original_evidence_without_a_verdict_is_partial() {
        // 판정 게이트는 독립적인 두 근거의 논리곱이다. 한쪽만 남은 것은 그
        // 곱이 무너졌다는 뜻이지 아무것도 안 남았다는 뜻이 아니다.
        let s = scan_of(vec![ev("payload#0")], Vec::new());
        assert_eq!(
            classify(&s, &["payload#0".into(), "task#0".into()]),
            VerifyOutcome::Partial
        );
    }

    #[test]
    fn evidence_unrelated_to_the_treatment_is_not_partial() {
        // 위 시험이 "증거가 있으면 언제나 부분" 으로 통과하면 안 된다. 치료와
        // 무관한 증거가 남아 있는 것은 부분 치료가 아니다.
        let s = scan_of(vec![ev("남의#증거")], Vec::new());
        assert_eq!(classify(&s, &["payload#0".into()]), VerifyOutcome::Clean);
    }

    #[test]
    fn without_a_baseline_partial_cannot_be_claimed() {
        // **없는 것을 있는 척하지 않는다.** 치료 전 증거를 모르면 "일부만
        // 잔존" 을 가려낼 수 없고, 그때는 재발 여부와 관측 완전성까지만 답한다.
        let s = scan_of(vec![ev("payload#0")], Vec::new());
        assert_eq!(classify(&s, &[]), VerifyOutcome::Clean);
    }

    // ───────── 관측이 불완전한 재평가 (결정 2026-10-26)
    //
    // 재평가가 다 보지 못했으면 "치료 성공" 을 말할 수 없다 — 재부팅 뒤 자동
    // 재검사가 잘리거나 막힌 채 "치료가 유지됐다" 고 거짓으로 말하던 자리다.
    // `scan` 과 같은 규칙이다: 찾은 것(재발 · 잔존)은 불완전보다 우선한다.

    /// 잘린 관측. 원인은 다섯 가지 중 무엇이든 같다(`Observation::is_complete`).
    fn incomplete(mut s: ScanEnvelope) -> ScanEnvelope {
        s.body.observation.truncated = true;
        s
    }

    #[test]
    fn an_incomplete_re_evaluation_is_not_treatment_success() {
        let s = incomplete(scan_of(Vec::new(), Vec::new()));
        assert_eq!(classify(&s, &["e#0".into()]), VerifyOutcome::Incomplete);
        // 치료 전 증거를 몰라도 다 보지 못한 것은 다 보지 못한 것이다.
        assert_eq!(classify(&s, &[]), VerifyOutcome::Incomplete);
    }

    #[test]
    fn a_verdict_beats_an_incomplete_observation() {
        let s = incomplete(scan_of(vec![ev("새#증거")], vec!["g0".into()]));
        assert_eq!(classify(&s, &["e#0".into()]), VerifyOutcome::Recurred);
    }

    #[test]
    fn surviving_evidence_beats_an_incomplete_observation() {
        // 남은 것은 남은 것이다 — 불완전은 "없다" 만 뒤집는다.
        let s = incomplete(scan_of(vec![ev("payload#0")], Vec::new()));
        assert_eq!(classify(&s, &["payload#0".into()]), VerifyOutcome::Partial);
    }

    #[test]
    fn unrelated_evidence_does_not_hide_an_incomplete_observation() {
        // 불완전은 **증거가 0건일 때만**의 이야기가 아니다. 치료와 무관한 증거(약한
        // 지표 하나)가 남았는데 다 보지 못했어도 "치료 성공" 이 아니다 — 0건으로만
        // 재면 "증거가 없을 때만 완전성을 본다" 로 줄인 구현을 놓친다(적대 검증).
        let s = incomplete(scan_of(vec![ev("남의#증거")], Vec::new()));
        assert_eq!(
            classify(&s, &["payload#0".into()]),
            VerifyOutcome::Incomplete
        );
        assert_eq!(classify(&s, &[]), VerifyOutcome::Incomplete);
    }

    #[test]
    fn the_outcome_names_are_a_closed_set_with_incomplete() {
        // 재검사 기록(`verify/<run>.jsonl`)의 `outcome` 이 이 이름이다 — 넷이고 서로
        // 다르다. 갈래를 더하며 이웃 이름을 복사하면 기록이 두 결과를 섞는다.
        let all = [
            VerifyOutcome::Clean,
            VerifyOutcome::Recurred,
            VerifyOutcome::Partial,
            VerifyOutcome::Incomplete,
        ];
        let ids: Vec<&str> = all.iter().map(VerifyOutcome::id).collect();
        assert_eq!(ids, ["clean", "recurred", "partial", "incomplete"]);
    }
}
