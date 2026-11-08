//! 아티팩트 스냅샷 포맷 + 수집 trait (설계-09 P2).
//!
//! `collect` 가 만드는 것은 **판단이 섞이지 않은 원본 관찰**이다. 어떤 룰도 여기에
//! 개입하지 않는다. 수집 범위는 플러그인의 `scan_roots`/`subjects` 선언에서 오지만,
//! 무엇이 악성인지에 대한 판단은 들어가지 않는다 (설계-02 §8).
//!
//! 이 분리가 설계 전체의 지지대다 (설계-03 §1). 스냅샷이 있으면 VM 없이 CI 에서
//! 수백 개 청정 환경을 초 단위로 돌릴 수 있고, 그것이 오탐 방지의 실질적 사거리다.
#![forbid(unsafe_code)]

pub mod record;
pub mod scope;

pub use record::{
    AutorunRecord, AvExclusionRecord, BootConfigRecord, BrowserExtensionRecord, CertStoreRecord,
    FileRecord, FirewallRuleRecord, HostsEntryRecord, IndicatorRecord, PackageRecord,
    PersistenceRecord, ProcessRecord, ProxyConfigRecord, RegistryKeyRecord, RegistryValueRecord,
    ServiceRecord, ShortcutRecord, Signature, StructuredConfigRecord, TextConfigRecord,
    UnixSocketRecord, WinTask, Zone,
};
pub use scope::Scope;

use remedy_sdk::artifact::{
    ArtifactsBody, ArtifactsEnvelope, CollectScope, CollectorInfo, CoreInfo, Envelope, HostInfo,
    SecurityProduct,
};
use remedy_sdk::catalog::Subject;
use std::collections::BTreeMap;

/// 크레이트가 링크되었음을 확인하는 표식 (P0 의 의존 그래프 검증용).
pub const CRATE_NAME: &str = "remedy-artifacts";

#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error("{msg} ({subject}): {source}", msg = remedy_sdk::i18n::t("수집 실패", "collection failed"))]
    Subject {
        subject: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Other(String),
}

// ─────────────────────────────────────────────────────── 수집 trait
//
// subject 마다 따로 둔다. 한 덩어리 trait 이면 P4 에서 16종이 늘 때 구현체가
// 전부 깨지고, Linux 백엔드(P12)가 지원하지 못하는 subject 를 빈 구현으로
// 채워 넣게 된다 — 그러면 "수집하지 못했다" 와 "없다" 가 구분되지 않는다.

/// 수집 결과와 **그 완전성**.
///
/// 레코드만 돌려주면 "없다" 와 "못 봤다" 가 뭉뚱그려진다. 관리자 권한 없이 돌리면
/// 예약 작업 디렉터리를 못 읽는데, 그것을 "예약 작업 없음" 으로 보고하면 그 스냅샷
/// 위에서 "위협 없음" 이라는 결론이 난다.
#[derive(Debug, Clone)]
pub struct Harvest<T> {
    pub records: Vec<T>,
    /// 상한에 걸려 잘렸는가.
    pub truncated: bool,
    /// 접근이 거부되어 열지 못한 디렉터리 수. **전부 센다.**
    pub denied_dirs: usize,
    /// 그중 **앞의 몇 개** 경로 (`remedy_platform::read::DENIED_SAMPLE` 까지).
    ///
    /// 전수가 아니다 — 길이가 `denied_dirs` 보다 작으면 표본이라는 뜻이다.
    /// 개수만으로는 회차가 끝난 뒤 원인에 닿을 수 없어 더했다(2026-09-14).
    pub denied_paths: Vec<String>,
}

/// 거부된 경로를 몇 개까지 담는가.
///
/// `remedy_platform::read::DENIED_SAMPLE` 과 같은 값이어야 한다 — 이 크레이트는
/// 플랫폼에 의존하지 않으므로 상수를 공유할 수 없고, 대신 두 곳의 시험이
/// 같은 수를 단정한다.
pub const DENIED_SAMPLE: usize = 32;

impl<T> Harvest<T> {
    /// 거부 하나를 센다 — **개수는 언제나, 경로는 상한까지.**
    ///
    /// 부르는 자리가 스물이 넘는다. 각자 `denied_dirs += 1` 과 상한 검사를
    /// 적으면 언젠가 한쪽만 고쳐지고, 그러면 개수와 목록이 조용히 갈라진다.
    pub fn deny(&mut self, path: impl Into<String>) {
        self.denied_dirs += 1;
        if self.denied_paths.len() < DENIED_SAMPLE {
            self.denied_paths.push(path.into());
        }
    }

    /// 걷기 결과의 거부를 합친다. `paths` 는 그쪽의 표본이다.
    pub fn absorb_denied(&mut self, denied: usize, paths: Vec<String>) {
        self.denied_dirs += denied;
        for p in paths {
            if self.denied_paths.len() >= DENIED_SAMPLE {
                break;
            }
            self.denied_paths.push(p);
        }
    }
}

// derive(Default) 는 `T: Default` 를 요구하는데 레코드에는 의미 있는 기본값이
// 없다. 빈 Vec 은 T 와 무관하게 만들 수 있으므로 직접 구현한다.
impl<T> Default for Harvest<T> {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            truncated: false,
            denied_dirs: 0,
            denied_paths: Vec::new(),
        }
    }
}

pub trait FileCollector {
    fn collect_files(&self, scope: &Scope) -> Result<Harvest<FileRecord>, CollectError>;
}

pub trait PersistenceCollector {
    fn collect_persistence(
        &self,
        scope: &Scope,
    ) -> Result<Harvest<PersistenceRecord>, CollectError>;
}

/// 보안 제품 목록. 판단이 아니라 **실패 원인 진단**을 위한 것이다 (설계-00 §5-1).
///
/// 주 배포 환경은 자사 제품이 이미 설치된 PC 다. "왜 이 파일이 안 지워졌는가" 의
/// 답이 대개 여기 있다.
pub trait SecurityProductCollector {
    fn collect_security_products(&self) -> Result<Vec<SecurityProduct>, CollectError>;
}

// ─────────────────────────────────────────────────────── 스냅샷 조립

/// 수집 결과.
///
/// subject 별 레코드를 **타입이 아니라 subject 키로** 들고 있다. P4 에서 16종이
/// 늘어나는데 필드를 그만큼 두면 `assemble` 도 평가기도 같은 목록을 따라 늘어야
/// 하고, 세 곳 중 하나만 빠뜨리면 **수집은 됐는데 평가되지 않는** 조용한 구멍이
/// 생긴다. 봉투의 `observations` 가 이미 이 모양이므로 여기서도 같은 모양을 쓴다.
#[derive(Debug, Default, Clone)]
pub struct Observations {
    pub records: BTreeMap<Subject, serde_json::Value>,
    /// 스냅샷에 담은 본문 바이트. 키는 `sha256:<16진>`, 값은 base64 다.
    ///
    /// `collect_extra` 로 **선언한 것만** 들어온다 (설계-02 §6-1).
    pub blobs: BTreeMap<String, String>,
    pub security_products: Vec<SecurityProduct>,
    /// 상한에 걸려 수집이 잘렸는가.
    ///
    /// **잘린 스냅샷으로 "위협 없음" 을 결론짓지 않기 위한 필수 정보다.**
    pub truncated: bool,
    /// 접근이 거부되어 열지 못한 디렉터리 수.
    pub denied_dirs: usize,
    /// 거부된 디렉터리 중 **앞의 몇 개** 경로.
    ///
    /// 전수가 아니다 — 길이가 `denied_dirs` 보다 작으면 표본이라는 뜻이다.
    /// 개수만으로는 회차가 끝난 뒤 원인에 닿을 수 없어 더했다(2026-09-14).
    pub denied_paths: Vec<String>,
    /// 존재하지 않아 한 번도 열리지 않은 scan_root.
    ///
    /// `denied_dirs` 와 나누는 이유는 의미가 다르기 때문이다 — 거부는 언제나
    /// 이상 징후지만, 없는 루트는 설치되지 않은 제품이라 정상일 수 있다.
    /// **전부 없을 때만** 관측이 불완전해진다 (설계-02 §8).
    pub missing_roots: Vec<String>,
    /// 선언했으나 **있는지조차 묻지 못한** scan_root (B-9 · 2026-10-27).
    ///
    /// `missing_roots` 와 나누는 이유는 *"없다"* 와 *"못 물었다"* 가 다른 말이기
    /// 때문이다. 하나라도 있으면 **언제나** 관측이 불완전하다 — 전부일 필요가
    /// 없다. `denied_dirs` 와도 나눈다: 그쪽 사유 줄이 *"관리자 권한으로 다시
    /// 돌리십시오"* 라고 말하는데, 도달 불가 UNC 에는 틀린 안내다.
    pub unreadable_roots: Vec<String>,
}

impl Observations {
    /// 수확 하나의 관측 사실을 합친다 — 잘림·거부 개수·거부 경로.
    ///
    /// **셋을 한 자리에 둔다.** subject 마다 세 줄을 적으면 새 subject 가
    /// 늘 때 하나를 빠뜨리고, 그러면 그 subject 의 불완전이 조용히 사라진다.
    pub fn absorb<T>(&mut self, h: &Harvest<T>) {
        self.truncated |= h.truncated;
        self.denied_dirs += h.denied_dirs;
        for p in &h.denied_paths {
            if self.denied_paths.len() >= DENIED_SAMPLE {
                break;
            }
            self.denied_paths.push(p.clone());
        }
    }

    /// subject 하나의 레코드를 담는다. **빈 목록도 담는다** — "찾아봤는데
    /// 없었다" 와 "보지 않았다" 는 다르고, 뒤의 것은 `uncollected_subjects` 로
    /// 보고된다 (설계-02 §8).
    pub fn put<T: serde::Serialize>(&mut self, subject: Subject, recs: &[T]) {
        self.records.insert(
            subject,
            serde_json::to_value(recs).expect("레코드 직렬화는 실패할 수 없다"),
        );
    }

    /// 담아 둔 레코드를 타입으로 다시 읽는다. 시험과 파이프라인 안쪽이 쓴다.
    pub fn get<T: serde::de::DeserializeOwned>(&self, subject: Subject) -> Vec<T> {
        self.records
            .get(&subject)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    pub fn files(&self) -> Vec<FileRecord> {
        self.get(Subject::File)
    }

    pub fn persistence(&self) -> Vec<PersistenceRecord> {
        self.get(Subject::Persistence)
    }
}

/// 수집기 자신에 대한 정보. 비트수를 남기는 이유는 WOW64 다.
///
/// 32비트 수집기가 만든 스냅샷을 64비트 기준으로 해석하면 `System32` 가
/// `SysWOW64` 였다는 사실이 사라진다 (설계-02 §4).
pub fn collector_info() -> CollectorInfo {
    CollectorInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        bitness: if cfg!(target_pointer_width = "64") {
            64
        } else {
            32
        },
        os_bitness: os_bitness(),
    }
}

#[cfg(windows)]
fn os_bitness() -> u8 {
    if cfg!(target_pointer_width = "64") {
        // 64비트 프로세스는 64비트 OS 에서만 돈다.
        64
    } else if std::env::var_os("PROCESSOR_ARCHITEW6432").is_some() {
        // 32비트 프로세스가 64비트 Windows 에서 돌 때만 이 변수가 있다 (WOW64).
        64
    } else {
        32
    }
}

#[cfg(not(windows))]
fn os_bitness() -> u8 {
    if cfg!(target_pointer_width = "64") {
        64
    } else {
        32
    }
}

/// 관찰을 봉투에 담는다.
///
/// `run_id` 와 `created` 는 호출자가 준다 — 이 함수가 시계를 읽으면 같은 입력에
/// 대해 다른 출력이 나오고, 결정성 검증(설계-09 P2)이 불가능해진다.
#[allow(clippy::too_many_arguments)]
pub fn assemble(
    run_id: String,
    created: String,
    host: HostInfo,
    core: CoreInfo,
    scope: &Scope,
    obs: Observations,
) -> ArtifactsEnvelope {
    // **선언한 것만 나간다.** 수집기가 이미 같은 판단을 하지만 여기서 한 번 더
    // 거른다 — 선언하지 않은 subject 가 스냅샷에 담기면 "선언한 것만 본다" 가
    // 무너지고, 그것은 플러그인이 볼 수 있는 범위의 상한이다 (설계-02 §8).
    //
    // 담기지 않은 subject 를 빈 목록으로 채우지는 않는다. 그러면 "보지 않았다"
    // 가 "없었다" 로 바뀌고 `observation()` 의 `uncollected_subjects` 가 영영 빈다.
    let observations: BTreeMap<String, serde_json::Value> = obs
        .records
        .into_iter()
        .filter(|(s, _)| scope.subjects.contains(s))
        .map(|(s, v)| (s.id().to_string(), v))
        .collect();

    Envelope {
        schema_version: remedy_sdk::SCHEMA_VERSION,
        kind: remedy_sdk::artifact::ArtifactKind::Artifacts,
        run_id,
        created: created.clone(),
        host,
        core,
        plugins: Vec::new(),
        body: ArtifactsBody {
            collected_at: created,
            collector: collector_info(),
            scope: CollectScope {
                scan_roots: scope.scan_roots.clone(),
                removable_roots: scope.removable_roots.clone(),
                subjects: scope.subjects.clone(),
                subject_roots: scope.subject_roots.clone(),
                text_config_dirs: scope.text_config_dirs.clone(),
                truncated: obs.truncated,
                denied_dirs: obs.denied_dirs,
                denied_paths: obs.denied_paths,
                missing_roots: obs.missing_roots,
                unreadable_roots: obs.unreadable_roots,
            },
            security_products: obs.security_products,
            blobs: obs.blobs,
            observations,
        },
    }
}

/// 스냅샷에서 subject 레코드를 꺼낸다. 평가기가 쓴다.
pub fn files_of(env: &ArtifactsEnvelope) -> Vec<FileRecord> {
    take(env, Subject::File)
}

pub fn persistence_of(env: &ArtifactsEnvelope) -> Vec<PersistenceRecord> {
    take(env, Subject::Persistence)
}

fn take<T: serde::de::DeserializeOwned>(env: &ArtifactsEnvelope, s: Subject) -> Vec<T> {
    env.body
        .observations
        .get(s.id())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}
