//! 파이프라인 조립 + 정책. CLI/GUI 공용 진입점 (설계-04 §1).
//!
//! 조립 로직이 `remedy-cli` 안으로 들어가면 나중에 GUI 셸이 얹힐 자리가 없어지고,
//! GUI 가 CLI 를 **프로세스로 호출**하는 구조가 되어 진행률·취소·오류 전달이 전부
//! 텍스트 파싱이 된다. 여기를 라이브러리로 두면 GUI 는 이것을 링크하면 된다.
//!
//! # 진단 모드 (설계-00 §5)
//!
//! `collect` 단독 실행에는 **플러그인이 필요 없고 파괴 동작이 그 코드 경로에
//! 없다.** `collect_only` 가 그 경로다.
//!
//! 링크 수준의 보장은 **여기가 아니라 `remedy-collect`** 에 있다 — 그 크레이트가
//! `remedy-apply` 를 의존하지 않고, 설계-04 §1 의 금지 의존 표에 올라 있어
//! `xtask arch` 가 강제한다. 이 크레이트는 조립기라 양쪽을 다 의존하며, 그것을
//! "여기도 의존하지 않는다" 고 적어 두었던 주석은 사실이 아니었다.
#![forbid(unsafe_code)]

pub mod config;
pub mod lock;
pub mod pipeline;
pub mod restore;

pub use config::{Config, ConfigError};
pub use lock::{LockError, RunLock};
pub use restore::RestoreError;

/// CLI 가 쓰라고 내보내는 것들. **CLI 는 하위 크레이트를 직접 의존하지 않는다**
/// — 인자 파싱과 출력만 하고 조립은 여기가 맡는다 (설계-04 §1).
pub mod quarantine {
    pub use remedy_quarantine::{ContentKey, Header, WrapKind, WrapSlot};
}
pub mod apply {
    pub use remedy_apply::{
        plan_path, Event, Executor, KeyPolicy, Progress, Report, Resume, ScheduledVerify,
        VerifyRequest,
    };

    /// 아직 끝나지 않은 실행의 `run_id`.
    ///
    /// `resume` 이 인자 없이 불렸을 때 무엇을 이어받을지 정하는 자리다.
    pub fn unfinished_runs(state_dir: &std::path::Path) -> std::io::Result<Vec<String>> {
        Ok(remedy_journal::unfinished(state_dir)?
            .into_iter()
            .map(|(id, _)| id)
            .collect())
    }
}
/// 사람이 읽는 출력. **CLI 가 문자열을 직접 만들지 않는다** — 만들면 그
/// 문구가 사실상 API 가 되고, 고칠 때마다 파싱하는 쪽이 깨진다 (설계-01 D5).
pub mod report {
    pub use remedy_report::{
        brand, check_findings, evidence_label, impact_line, no_target, op_label, pad, pretty_time,
        render_banner, render_closing, render_plan, render_result, render_self_sufficiency,
        result_line, result_line_for, review_line, self_sufficiency, threat_findings,
        unconfirmed_findings, AfterReboot, Banner, Closing, Lang, SelfSufficiency, Shortfall,
        FINDINGS_SHOWN,
    };
}
pub mod platform {
    pub use remedy_platform::progress;
    pub use remedy_platform::read::{BootHealth, SafeBoot};
    /// 복원 정보 폴더 잠금 — **CLI 가 플랫폼을 직접 의존하지 않게** 여기로 낸다
    /// (`remedy-cli` 는 `remedy-core`·`remedy-trust`·`remedy-sdk` 만 쓴다).
    pub use remedy_platform::statedir;
    /// 대화형 세션이 켠다 — 콘솔의 Ctrl+C 가 치료 중인 자식 도구에 닿지 않게.
    pub use remedy_platform::tool::shield_from_ctrl_c;
    pub use remedy_platform::write::{FileMeta, LostItem, PlatformWrite, RestoreReport};
}

/// 이 기계의 부팅 건전성 (설계-00 §6).
///
/// **재시작을 권하기 전에 읽는다.** 악성코드가 `SafeBoot` 키를 지워 두었으면
/// "안전 모드로 재시작하세요" 가 부팅되지 않는 컴퓨터를 만든다.
///
/// 읽을 수 없는 플랫폼에서는 `None` 이다 — **모르는 것을 괜찮은 것으로 접지
/// 않는다.** 접는 자리가 곧 사고다.
pub fn boot_health() -> Option<remedy_platform::read::BootHealth> {
    remedy_platform::live().map(|reg| remedy_platform::read::boot_health(&reg))
}

/// OS 가 말하는 사용자 로케일 (Windows `ko-KR`, 그 밖은 `None`).
///
/// CLI 가 언어를 정할 때 `remedy_sdk::i18n::Lang::detect_with` 에 넘긴다.
/// SDK 는 레지스트리를 읽지 않으므로 이 값은 여기서 건너간다.
pub fn user_locale() -> Option<String> {
    remedy_platform::user_locale()
}

/// 이 실행이 기계를 고칠 수 있는 권한을 가졌는가 (설계-00 §5).
///
/// **CLI 는 `remedy-platform` 을 직접 의존하지 않는다** (설계-04 §1 — 조립은
/// core 가 맡는다). `None` 은 재지 못했다는 뜻이고, 부르는 쪽이 거절한다.
pub fn elevated() -> Option<bool> {
    remedy_platform::read::elevated()
}
// CLI 는 remedy-plan 을 직접 의존하지 않는다 (설계-04 §1 — 조립은 core 가 맡는다).
// 상한 타입은 계획기의 것이지만 CLI 가 설정에서 만들어 넘겨야 하므로 여기서 재수출한다.
pub mod integrity;
pub mod restart;
pub mod runlog;
pub mod support;
pub mod verify_log;

pub use pipeline::{
    collect_only, evaluate, plan, plan_with, scan, Pipeline, PipelineError, RunMeta,
};
pub use remedy_plan::{Allowed, Limits, Mode};

/// 해소하지 못한 `collect_extra` 항목.
///
/// CLI 는 `remedy-collect` 를 직접 의존하지 않는다 (설계-04 §1 — 조립은 core 가
/// 맡는다). 그래서 여기서 재수출한다.
pub use remedy_collect::extra::Unresolved;

/// 자체 점검. 링크 그래프와 **엔진이 실제로 도는가**를 확인한다.
pub struct SelfTest {
    pub linked: Vec<&'static str>,
    pub yara: remedy_detect::YaraSelfTest,
    pub target: &'static str,
}

impl SelfTest {
    pub fn ok(&self) -> bool {
        self.yara.ok()
    }
}

pub fn self_test() -> SelfTest {
    SelfTest {
        linked: vec![
            remedy_sdk::CRATE_NAME,
            remedy_artifacts::CRATE_NAME,
            remedy_collect::CRATE_NAME,
            remedy_detect::CRATE_NAME,
            remedy_plan::CRATE_NAME,
            remedy_apply::CRATE_NAME,
            remedy_quarantine::CRATE_NAME,
            remedy_journal::CRATE_NAME,
            remedy_platform::CRATE_NAME,
            remedy_trust::CRATE_NAME,
            remedy_report::CRATE_NAME,
            remedy_detect::yara_crate_name(),
        ],
        yara: remedy_detect::yara_self_test(),
        target: env!("REMEDY_TARGET"),
    }
}
