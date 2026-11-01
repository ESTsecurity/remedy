//! 격리 컨테이너의 엔트리 종류 — **닫힌 집합이다** (설계-02 §9).
//!
//! # 왜 지금 전부 열거하는가
//!
//! 컨테이너 포맷은 P5 에서 정해지는데 격리물은 **자동 삭제하지 않는다**
//! (설계-03 §5 보존 정책). P5·P6 에서 만든 컨테이너가 P7·P8 에서도, v1 이후에도
//! 열려야 한다는 뜻이고, 따라서 **포맷 실수는 영구적이다.**
//!
//! 실제로 그럴 뻔했다. 설계-02 §9 의 엔트리 표는 8종이었는데 28개 Op 중 11개가
//! 담길 자리가 없었다 — `registry.delete_key` 는 키 트리를, `cert_store.remove` 는
//! 인증서를, `boot.restore_default` 는 부트 설정을 어디에도 넣을 수 없었다.
//! 그대로 갔다면 P7 에서 포맷 버전을 올리고 파서를 두 벌 유지해야 했다.
//!
//! 그래서 이 프로젝트가 subject 18종·Op 28종에 쓴 방식을 그대로 쓴다 —
//! **정의는 전부, 구현은 점진적으로.** 종류는 지금 다 열거하고 직렬화는
//! Phase 별로 들어온다.
//!
//! # 종류를 늘리지 않은 자리
//!
//! `hosts.restore_line` · `text_config.remove_line` · 셸 자동실행 라인은 저장할
//! 바이트가 같다 — 원본 줄, 파일 경로, 파일 내 위치, 파일 권한. 그래서 셋을
//! [`EntryKind::TextLine`] 하나로 담는다. **컨테이너는 저장 포맷이지 복원 로직이
//! 아니다.** 되돌릴 때의 처리가 다른 것은 Op 의 몫이고, 종류를 나누면 포맷만
//! 넓어진다.
//!
//! 반대로 [`Op::backup_kinds`] 가 여러 종류를 반환하는 Op 이 있다.
//! `autorun.remove` 는 Run 키면 레지스트리 값, 시작 폴더면 파일, `.bashrc` 면
//! 텍스트 줄, systemd 면 유닛이다. 무엇을 담을지는 **실제 대상을 보는 실행
//! 시점**에 정해지며, 이것은 불변식 P 와 무관하다 — 어떤 Op 이 무엇에 대해
//! 도는지는 계획이 이미 고정했고, 백업 종류는 그 대상의 성질에서 나온다.

use crate::catalog::{Op, Phase};
use serde::{Deserialize, Serialize};

/// 격리 컨테이너에 담기는 항목의 종류.
///
/// 각 종류가 실제로 무엇을 저장하는지는 설계-02 §9 "엔트리 종류별 저장 항목"에
/// 있고, `xtask trace` 가 그 표와 이 열거를 대조한다.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// 파일 본문과 메타데이터.
    File,
    /// 대체 데이터 스트림(ADS) 하나. 호스트 파일은 그대로 두고 스트림만 지우는
    /// `file.delete_stream` 을 위한 것이라 파일 전체 백업과 다르다.
    FileStream,
    /// 디렉터리 자체의 존재와 메타데이터. 본문은 없다.
    ///
    /// `dir.delete_recursive` 를 되돌리려면 파일만으로는 부족하다 — 빈 디렉터리와
    /// 디렉터리 권한이 복원되지 않는다.
    Directory,
    /// 레지스트리 값 하나 (타입 + 원본 바이트).
    RegistryValue,
    /// 레지스트리 키와 그 하위 트리 전체.
    RegistryKey,
    /// 예약 작업 정의.
    Task,
    /// 서비스 설정 전체.
    Service,
    /// cron 줄과 소속 파일.
    Cron,
    /// systemd 유닛 파일과 enable 상태.
    Unit,
    /// 텍스트 파일 안의 한 줄 — 셸 자동실행 · hosts · 임의 텍스트 설정.
    TextLine,
    /// 구조적 설정(JSON·XML·YAML) 안의 키와 원본 값.
    StructuredConfig,
    /// 보안 제품 예외 목록 **전체** (부분 diff 가 아니다 — 설계-03 §2).
    AvExclusion,
    /// 인증서 저장소의 인증서 하나.
    CertStore,
    /// 부트 설정 항목.
    BootConfig,
}

/// 엔트리 종류의 메타데이터.
pub struct EntryKindInfo {
    /// 컨테이너에 적히는 이름.
    pub id: &'static str,
    /// 이 종류의 **직렬화가 실제로 들어오는** Phase. 종류 자체는 P5 에서 전부
    /// 정의되지만, 그것을 쓰는 Op 이 P6~P8 에 흩어져 있다.
    pub implemented_in: Phase,
}

impl EntryKind {
    pub const ALL: [EntryKind; 14] = [
        EntryKind::File,
        EntryKind::FileStream,
        EntryKind::Directory,
        EntryKind::RegistryValue,
        EntryKind::RegistryKey,
        EntryKind::Task,
        EntryKind::Service,
        EntryKind::Cron,
        EntryKind::Unit,
        EntryKind::TextLine,
        EntryKind::StructuredConfig,
        EntryKind::AvExclusion,
        EntryKind::CertStore,
        EntryKind::BootConfig,
    ];

    pub const fn info(self) -> EntryKindInfo {
        match self {
            EntryKind::File => EntryKindInfo {
                id: "file",
                implemented_in: Phase::P6,
            },
            EntryKind::FileStream => EntryKindInfo {
                id: "file_stream",
                implemented_in: Phase::P7,
            },
            EntryKind::Directory => EntryKindInfo {
                id: "directory",
                implemented_in: Phase::P7,
            },
            EntryKind::RegistryValue => EntryKindInfo {
                id: "registry_value",
                implemented_in: Phase::P7,
            },
            EntryKind::RegistryKey => EntryKindInfo {
                id: "registry_key",
                implemented_in: Phase::P8,
            },
            EntryKind::Task => EntryKindInfo {
                id: "task",
                implemented_in: Phase::P7,
            },
            EntryKind::Service => EntryKindInfo {
                id: "service",
                implemented_in: Phase::P8,
            },
            EntryKind::Cron => EntryKindInfo {
                id: "cron",
                implemented_in: Phase::P7,
            },
            EntryKind::Unit => EntryKindInfo {
                id: "unit",
                implemented_in: Phase::P7,
            },
            EntryKind::TextLine => EntryKindInfo {
                id: "text_line",
                implemented_in: Phase::P7,
            },
            EntryKind::StructuredConfig => EntryKindInfo {
                id: "structured_config",
                implemented_in: Phase::P7,
            },
            EntryKind::AvExclusion => EntryKindInfo {
                id: "av_exclusion",
                implemented_in: Phase::P7,
            },
            EntryKind::CertStore => EntryKindInfo {
                id: "cert_store",
                implemented_in: Phase::P8,
            },
            EntryKind::BootConfig => EntryKindInfo {
                id: "boot_config",
                implemented_in: Phase::P8,
            },
        }
    }

    pub fn from_id(id: &str) -> Option<EntryKind> {
        EntryKind::ALL.into_iter().find(|k| k.info().id == id)
    }

    pub const fn id(self) -> &'static str {
        self.info().id
    }
}

impl Op {
    /// 이 Op 이 파괴하기 전에 무엇을 담아야 하는가.
    ///
    /// **빈 배열은 "되돌릴 수 없다"** 는 뜻이지 "백업을 생략한다"가 아니다.
    /// `OpInfo::reversible` 과 정확히 반대로 대응하며, 그 대응은
    /// [`super::catalog`] 의 테스트가 강제한다 — 되돌릴 수 있다고 선언해 놓고
    /// 담을 자리가 없으면 그 Op 은 복원 불가능한 파괴가 된다.
    ///
    /// 여러 종류를 반환하는 Op 은 대상의 성질에 따라 실행 시점에 하나를 고른다.
    pub const fn backup_kinds(self) -> &'static [EntryKind] {
        match self {
            // ── 파일 계열 ────────────────────────────────────────────
            Op::FileQuarantineOnly | Op::FileDelete | Op::FileDeleteOnReboot => &[EntryKind::File],
            // 호스트 파일은 남고 스트림만 사라진다.
            Op::FileDeleteStream => &[EntryKind::FileStream],
            // 파일만 담으면 빈 디렉터리와 디렉터리 권한이 복원되지 않는다.
            Op::DirDeleteRecursive => &[EntryKind::Directory, EntryKind::File],
            // .lnk 는 파일이다. 인자만 고치더라도 백업은 파일 전체다
            // (설계-03 §2 "부분 편집의 백업은 값 전체다").
            Op::ShortcutStripArgs => &[EntryKind::File],

            // ── 레지스트리 ───────────────────────────────────────────
            Op::RegistryDeleteValue | Op::RegistryStripValue | Op::RegistryRestoreDefault => {
                &[EntryKind::RegistryValue]
            }
            Op::RegistryDeleteKey => &[EntryKind::RegistryKey],

            // ── 지속성 ───────────────────────────────────────────────
            // 예약 작업(Windows) · systemd 유닛 · cron 줄이 같은 subject 다.
            // **대상의 모양이 담을 종류를 고른다** — 라벨이 틀리면 격리함을 여는
            // 사람이 systemd 유닛을 Windows 예약 작업으로 읽는다.
            Op::PersistenceDisable | Op::PersistenceDelete => {
                &[EntryKind::Task, EntryKind::Unit, EntryKind::Cron]
            }
            Op::ServiceDisable | Op::ServiceDelete | Op::ServiceClearRecovery => {
                &[EntryKind::Service, EntryKind::Unit]
            }
            // 정지는 되돌릴 수 없다 (설계-03 §2). 빈 배열은 "백업을
            // 생략한다" 가 아니라 **"되돌릴 수 없다"** 는 뜻이고,
            // `OpInfo::reversible` 과 정확히 대응한다.
            Op::ServiceStop => &[],
            // 자동실행은 플랫폼마다 사는 곳이 다르다.
            Op::AutorunRemove => &[
                EntryKind::RegistryValue,
                EntryKind::File,
                EntryKind::TextLine,
                EntryKind::Unit,
                EntryKind::Cron,
            ],

            // ── 설정 ─────────────────────────────────────────────────
            Op::HostsRestoreLine | Op::TextConfigRemoveLine => &[EntryKind::TextLine],
            Op::StructuredConfigRemoveKey | Op::StructuredConfigRestoreDefault => {
                &[EntryKind::StructuredConfig]
            }
            // PATH 는 Windows 에서 레지스트리 값, Linux 에서 프로필 줄이다.
            Op::EnvStripPath => &[EntryKind::RegistryValue, EntryKind::TextLine],
            // 프록시는 레지스트리·환경·PAC 파일에 흩어져 있다.
            Op::ProxyRestore => &[
                EntryKind::RegistryValue,
                EntryKind::TextLine,
                EntryKind::File,
            ],
            Op::AvRestoreExclusions => &[EntryKind::AvExclusion],
            // 방화벽 규칙에 전용 EntryKind 를 두지 않는 이유: Windows 에서 규칙
            // 하나는 **레지스트리 값 하나**이고 그 바이트를 되돌리면 규칙이
            // 그대로 돌아온다. Linux 는 ruleset 파일의 한 줄이다. `AvExclusion`
            // 이 전용인 것은 제외 목록이 값 하나로 환원되지 않아서다.
            Op::FirewallRestoreRule => &[EntryKind::RegistryValue, EntryKind::TextLine],
            // 확장 디렉터리와 브라우저 프로필의 등록 항목을 함께 담아야 한다.
            Op::BrowserExtRemove => &[
                EntryKind::Directory,
                EntryKind::File,
                EntryKind::StructuredConfig,
            ],
            Op::CertStoreRemove => &[EntryKind::CertStore],
            Op::BootRestoreDefault => &[EntryKind::BootConfig],

            // ── 되돌릴 수 없는 것 ────────────────────────────────────
            // 죽은 프로세스는 되살릴 수 없다. 그래서 이 Op 은 되돌릴 수 있는
            // Action 보다 **먼저** 배치되고 멱등하게 설계된다 (설계-03 §5).
            Op::ProcessKill => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reversible_and_backup_kinds_agree() {
        // **되돌릴 수 있다고 선언해 놓고 담을 자리가 없으면** 그 Op 은 실제로는
        // 복원 불가능한 파괴다. 이 대응이 어긋나면 격리소가 있다는 말이 거짓이 된다.
        for op in Op::ALL {
            let info = op.info();
            assert_eq!(
                info.reversible,
                !op.backup_kinds().is_empty(),
                "Op '{}' — reversible={} 인데 backup_kinds 는 {:?}",
                info.id,
                info.reversible,
                op.backup_kinds()
            );
        }
    }

    #[test]
    fn every_entry_kind_is_used_by_some_op() {
        // 아무 Op 도 쓰지 않는 종류는 포맷만 넓힌다. 실제로 정리 전 표에는
        // 그런 항목이 있었다.
        for kind in EntryKind::ALL {
            let used = Op::ALL.iter().any(|op| op.backup_kinds().contains(&kind));
            assert!(used, "엔트리 종류 '{}' 를 쓰는 Op 이 없다", kind.id());
        }
    }

    #[test]
    fn entry_kind_arrives_no_later_than_the_op_that_needs_it() {
        // 종류의 직렬화가 그것을 쓰는 Op 보다 늦게 오면, 그 Phase 는 백업 없이
        // 파괴하게 된다.
        for op in Op::ALL {
            for kind in op.backup_kinds() {
                assert!(
                    kind.info().implemented_in <= op.info().implemented_in,
                    "'{}' 는 {} 에 오는데 그 백업 종류 '{}' 는 {} 에 온다",
                    op.info().id,
                    op.info().implemented_in.as_str(),
                    kind.id(),
                    kind.info().implemented_in.as_str()
                );
            }
        }
    }

    #[test]
    fn ids_round_trip() {
        for kind in EntryKind::ALL {
            assert_eq!(EntryKind::from_id(kind.id()), Some(kind));
        }
        assert_eq!(EntryKind::from_id("없는종류"), None);
    }
}
