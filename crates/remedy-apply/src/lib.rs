//! 실행기 — **계획에 있는 것만, 백업이 끝난 뒤에** (설계-09 P6).
//!
//! 여기가 이 프로젝트에서 처음으로 시스템을 바꾸는 코드다. 그래서 지키는 것이
//! 세 가지고, 셋 다 순서에 대한 것이다.
//!
//! # 1. 백업이 전부 끝난 뒤에 파괴가 시작된다
//!
//! 설계-03 §2 의 실행 순서에서 백업은 **4단계**이고 파괴는 5·6단계다. 항목마다
//! "백업하고 지우고" 를 반복하지 않는다는 뜻이다. 그래야 설계-03 §5 의 실패 정책이
//! 성립한다 — **"백업 중 실패 → 즉시 중단. 아직 아무것도 파괴되지 않았다."**
//!
//! 섞어서 돌면 세 번째 파일의 백업이 실패했을 때 앞의 둘은 이미 사라진 뒤다.
//!
//! # 2. 파괴 중 실패해도 되돌리지 않는다
//!
//! 로더는 지워졌고 페이로드 삭제가 실패했다면, 여기서 롤백하면 **로더가 복원되어
//! 위협이 재무장된다.** 절반만 제거된 상태가 위험한 것은 사실이지만 온전한
//! 악성코드로 되돌리는 것보다는 낫다 (설계-03 §5). 나머지 계획을 계속 수행한다.
//!
//! # 3. 계획에 없는 것은 하지 않는다
//!
//! 실행기는 `plan.json` 의 Action 만 본다. 매니페스트도, 스냅샷도, 파일 시스템도
//! 다시 보지 않는다 (불변식 P). 그래서 이 크레이트는 `remedy-detect` 도
//! `remedy-collect` 도 의존하지 않는다.
//!
//! # 4. 크래시는 실행 도중에 온다
//!
//! 전원이 나가거나 프로세스가 죽으면 저널만 남는다. 다시 부르면 실행기는 그
//! 저널을 읽고 **어디서부터 이어야 하는지** 판단한다 — 처음부터 다시 돌면 이미
//! 지운 파일을 다시 백업하려 들다 실패하고, 사용자는 나머지를 영영 수행할 수
//! 없다. 판단 규칙은 [`Resume`] 에 있다.
#![forbid(unsafe_code)]

use remedy_journal::{Journal, Outcome as JOutcome, Reading, Record};
use remedy_platform::write::{PlatformWrite, RegistryValueBackup, RemovedBy, VerifySite};
use remedy_platform::PlatformError;
use remedy_quarantine::{Builder, ContentKey, Entry, Header, MachineKey, WrapSlot};
use remedy_sdk::artifact::{Action, ActionOutcome, ActionResult, PlanEnvelope, ResultBody};
use remedy_sdk::catalog::Op;
use remedy_sdk::EntryKind;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const CRATE_NAME: &str = "remedy-apply";

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("{0}")]
    Platform(#[from] remedy_platform::PlatformError),
    #[error("{0}")]
    Quarantine(#[from] remedy_quarantine::QuarantineError),
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("저널을 쓸 수 없습니다", "cannot write the journal"))]
    Journal(std::io::Error),
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("plan 봉투가 아닙니다", "not a plan envelope"))]
    NotAPlan(String),
    /// **백업이 끝나기 전에 멈췄다. 아무것도 파괴되지 않았다** (설계-03 §5).
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("백업 단계에서 중단했습니다. 아무것도 바꾸지 않았습니다", "stopped during backup. Nothing was changed"))]
    StoppedBeforeDestruction(String),
    /// 계획이 요구하는 것을 **하지 않기로 했다.**
    ///
    /// 입출력 실패와 나눈다. 실패는 다시 해 볼 수 있지만 이것은 계획이나
    /// 카탈로그를 고쳐야 하고, 무엇보다 **이 Action 은 아무것도 바꾸지 않았다.**
    #[error("{0}")]
    ActionRefused(String),
    /// 같은 `run_id` 인데 **내용이 다른 계획**으로 이어받으려 했다.
    #[error("{msg} (run {0})", msg = remedy_sdk::i18n::t("저널에 남은 계획과 다른 계획입니다. 이어받지 않습니다. 새로 계획하십시오", "this plan differs from the one in the journal. Not resuming; plan again"))]
    PlanChanged(String),
    /// 이 계획은 이미 끝까지 수행됐다.
    #[error("{msg} (run {0})", msg = remedy_sdk::i18n::t("이미 수행된 계획입니다. 다시 수행하려면 새로 계획하십시오", "this plan was already applied. Plan again to run it once more"))]
    AlreadyApplied(String),
    /// 저널은 백업이 끝났다고 하는데 격리 컨테이너가 없다.
    #[error("{msg} (run {run_id}, {path})", msg = remedy_sdk::i18n::t("격리 컨테이너가 없습니다. 이어서 삭제하면 되돌릴 수 없습니다", "quarantine container is missing. Continuing would be irreversible"))]
    ContainerMissing { run_id: String, path: String },
    /// 자기 상태 디렉터리에 쓰지 못했다.
    ///
    /// **파괴를 시작하기 전에 막는다.** 계획을 남기지 못하면 재부팅 뒤에
    /// 이어받을 것이 없고, 그러면 "재개는 저장된 계획으로" 라는 약속이
    /// 깨진다 (설계-00 §6).
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("상태 디렉터리에 쓰지 못했습니다", "cannot write to the state directory"))]
    State(String),
}

impl ApplyError {
    /// 무인 배포는 종료 코드만 본다 (설계-02 §8).
    pub fn exit_code(&self) -> remedy_sdk::artifact::ExitCode {
        use remedy_sdk::artifact::ExitCode;
        match self {
            // 백업 전 중단은 가드가 막은 것이다. 파괴는 시작되지 않았다.
            ApplyError::StoppedBeforeDestruction(_) => ExitCode::GuardStop,
            ApplyError::Platform(remedy_platform::PlatformError::NoSpace(_)) => ExitCode::GuardStop,
            // 셋 다 **막은 것**이지 실패한 것이 아니다. 그대로 진행했다면
            // 두 번 파괴하거나(AlreadyApplied), 승인받지 않은 것을
            // 파괴하거나(PlanChanged), 되돌릴 수 없게(ContainerMissing) 됐다.
            ApplyError::PlanChanged(_)
            | ApplyError::AlreadyApplied(_)
            | ApplyError::ContainerMissing { .. } => ExitCode::GuardStop,
            _ => ExitCode::UsageError,
        }
    }
}

/// 이 실행의 계획이 놓이는 곳.
///
/// **경로를 규약으로 못 박는다** — `journal_path` 와 같은 이유다. 이어서 수행하는
/// `resume` 은 `--plan` 을 받지 않고 run_id 로 이 자리를 찾는다 — 크래시나 재부팅
/// 뒤에 그것을 부르는 사람이나 배포 도구가 계획 파일을 들고 있으리라 기대할 수
/// 없다. 찾을 자리가 정해져 있어야 한다 (설계-00 §6).
///
/// **RunOnce 가 부르는 것이 아니다.** RunOnce 가 심는 것은 `verify` 뿐이고
/// (`scheduled_verify_command`), 설계-00 §6 의 재개용 자동실행 항목을 등록하는
/// 코드는 없다.
pub fn plan_path(state_dir: &std::path::Path, run_id: &str) -> PathBuf {
    state_dir.join("plan").join(format!("{run_id}.json"))
}

/// 재부팅 뒤 재검사 예약에 필요한 것 (설계-03 §8).
///
/// **계획에 없는 것들이다** — 실행 파일과 플러그인 경로는 부른 쪽만 안다. 계획은
/// 원하는지(`verify_after_reboot`)만 싣는다.
#[derive(Debug, Clone)]
pub struct VerifyRequest {
    pub exe: PathBuf,
    pub plugin: PathBuf,
    pub state_dir: Option<PathBuf>,
    pub lang: remedy_sdk::i18n::Lang,
}

/// 재부팅 뒤 재검사 예약의 결과. 저널에 남기고 보고에도 싣는다 — 화면이 이것을
/// 말한다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduledVerify {
    /// 걸었다. 자리와 지우는 주체는 백엔드가 말한 그대로다.
    Scheduled {
        site: Option<VerifySite>,
        command: String,
    },
    /// 걸지 못했다 — 그 이유.
    NotScheduled { reason: String },
}

impl ScheduledVerify {
    fn record(&self) -> Record {
        match self {
            ScheduledVerify::Scheduled { site, command } => Record::VerifyScheduled {
                location: site.as_ref().map(|s| s.location.clone()),
                removed_by: site.as_ref().map(|s| {
                    match s.removed_by {
                        RemovedBy::Os => "os",
                        RemovedBy::Itself => "itself",
                    }
                    .to_string()
                }),
                command: command.clone(),
            },
            ScheduledVerify::NotScheduled { reason } => Record::VerifyNotScheduled {
                reason: reason.clone(),
            },
        }
    }
}

/// 실행 결과.
#[derive(Debug)]
pub struct Report {
    pub body: ResultBody,
    /// 만들어진 격리 컨테이너. **복원의 유일한 입구다.**
    pub container: Option<PathBuf>,
    pub journal: PathBuf,
    /// 크래시한 실행을 이어받았다면 어디서부터였는가. 처음 도는 실행이면 `None`.
    pub resumed: Option<Resume>,
    /// 이전 시도가 이미 끝내 **이 실행이 다시 수행하지 않은** Action 수.
    ///
    /// `results` 는 run 전체를 담으므로, 이 숫자가 없으면 "10건 중 3건만 돌았는데
    /// 왜 10건이 보고되는가" 를 설명할 길이 없다.
    pub carried: usize,
    /// 재부팅 뒤 재검사 예약의 결과. 계획이 원하지 않았거나 부른 쪽이 요청을
    /// 넘기지 않았으면 `None` ([`Executor::with_verify_after_reboot`]).
    pub scheduled_verify: Option<ScheduledVerify>,
}

impl Report {
    pub fn failed(&self) -> usize {
        self.body
            .results
            .iter()
            .filter(|r| r.outcome == ActionOutcome::Failed)
            .count()
    }
    pub fn done(&self) -> usize {
        self.body
            .results
            .iter()
            .filter(|r| r.outcome == ActionOutcome::Done)
            .count()
    }
}

/// 진행 이벤트 — **GUI 셸과 무인 배포가 읽는 것**이다 (설계-01 D3).
///
/// 사람이 읽는 출력과 분리한다. 한 스트림에 섞으면 기계가 파싱할 수 없고,
/// 파싱하려고 사람 쪽 문구를 건드리면 그 문구가 사실상 API 가 된다.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event<'a> {
    Started {
        run_id: &'a str,
        actions: usize,
    },
    /// 크래시한 실행을 **이어받았다.** 이 실행이 처음이 아니라는 뜻이다.
    ///
    /// 이것 없이 `Started { actions: 10 }` 뒤에 `Action` 이 3건만 오면, 읽는
    /// 쪽은 7건이 조용히 빠졌다고 읽는다.
    Resumed {
        /// 이전 시도가 이미 끝낸 Action.
        already: usize,
        /// 이 실행이 수행할 Action.
        remaining: usize,
        /// 백업부터 다시 도는가. 그렇다면 아직 아무것도 파괴되지 않았다.
        redo_backup: bool,
    },
    /// 백업 단계가 끝났다. **여기부터 파괴가 시작된다.**
    BackedUp {
        entries: usize,
        container: Option<String>,
    },
    Action {
        seq: u32,
        op: &'a str,
        target: &'a str,
        outcome: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<&'a str>,
    },
    Finished {
        done: usize,
        failed: usize,
    },
    /// 파괴를 시작하기 전에 멈췄다. **이 실행은 아무것도 파괴하지 않았다.**
    ///
    /// 이어받은 실행이라면 이전 시도가 파괴한 것은 그대로 남아 있다. 그것까지
    /// 없던 일이 됐다고 읽으면 안 된다.
    Stopped {
        reason: &'a str,
    },
    /// **Action 에 붙지 않는 사실.** 하려 했으나 하지 못한 것이 여기 남는다.
    ///
    /// 저널의 [`Record::Note`](remedy_journal::Record::Note) 와 짝이다.
    ///
    /// # 왜 `Action` 을 쓰면 안 되는가
    ///
    /// 복원 지점 생성 실패가 한동안 `Action { seq: 0, outcome: "skipped" }` 로
    /// 나갔다. **불변식 P 는 "계획에 없는 변경이 있었는가" 이고, 그것을 재는
    /// 소비자는 `action` 이벤트를 센다** — 그래서 하네스가 계획 밖 Action 1건을
    /// 보고했다(2026-08-28 P9). 아무것도 바뀌지 않았는데 위반으로 읽힌 것이다.
    ///
    /// `--events` 는 GUI 셸과 무인 배포가 읽는 **제품 인터페이스**다. 계획에
    /// 없는 것이 Action 으로 나가면 우리 하네스만 틀리는 것이 아니다.
    Note {
        text: &'a str,
    },
}

/// 저널이 말해 주는, **어디서부터 이어야 하는가**.
///
/// # 무엇에 기대고 있는가
///
/// 이 판단은 실행기의 순서 불변식 하나에 전적으로 기댄다 — **모든 `Backup` 이
/// 저널에 적힌 뒤에야 첫 파괴가 시작된다.** 그래서 필요한 `Backup` 이 하나라도
/// 모자라면 "아직 아무것도 파괴되지 않았다" 고 **단정**할 수 있고, 백업 단계를
/// 통째로 다시 돌아도 안전하다.
///
/// 순서가 바뀌면 이 판단은 조용히 거짓이 된다. 백업과 파괴를 항목마다 번갈아
/// 하도록 고치는 순간, `Backup` 이 모자란 저널이 "앞의 것들은 이미 지워졌다" 를
/// 뜻하게 되고 재기동이 그것들을 다시 백업하려 든다. 그래서 그 순서를 지키는
/// 시험이 이 판단과 같은 곳에 있다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resume {
    /// 저널이 없다. 처음부터 돈다.
    Fresh,
    /// 백업이 끝나기 전에 멈췄다. **아무것도 파괴되지 않았다** — 백업부터 다시 돈다.
    Restart,
    /// 백업은 끝났다. 결과가 남지 않은 Action 부터 이어서 파괴한다.
    Continue,
    /// 모든 Action 에 결과가 남았는데 `End` 가 없다 — **꼬리에서 멈췄다.**
    ///
    /// 마지막 결과를 적은 뒤, 재부팅 뒤 재검사 예약(7단계)과 `End` 사이에서 멈춘
    /// 것이다. 파괴는 끝났으므로 **아무것도 다시 하지 않고**(복원 지점도, 백업도)
    /// 그 둘만 마저 한다. 한동안 이것을 [`Resume::Complete`] 로 읽어 거부했고, 그러면
    /// 이 회차는 영영 끝나지 않는다 — `resume` 이 매번 거부하고(종료 코드 5), 인자
    /// 없는 `resume` 은 그 뒤 회차까지 멈춘다 (2026-09-29 실측).
    Tail,
    /// 계획의 모든 Action 에 결과가 남았고 **`End` 도 있다.** 다시 돌면 **두 번
    /// 수행**하는 것이다.
    Complete,
}

/// 저널을 읽고 [`Resume`] 을 정한다.
fn where_to_resume(plan: &PlanEnvelope, reading: &Reading) -> Resume {
    if reading.records.is_empty() {
        return Resume::Fresh;
    }
    let needs: BTreeSet<u32> = plan
        .body
        .actions
        .iter()
        .filter(|a| !a.op.backup_kinds().is_empty())
        .map(|a| a.seq)
        .collect();
    if !needs.is_subset(&reading.backed_up()) {
        return Resume::Restart;
    }
    let decided = reading.decided();
    if plan
        .body
        .actions
        .iter()
        .all(|a| decided.contains_key(&a.seq))
    {
        // `End` 까지 적혔으면 끝난 회차다. 없으면 꼬리에서 멈춘 것이다.
        return if reading.finished() {
            Resume::Complete
        } else {
            Resume::Tail
        };
    }
    Resume::Continue
}

/// 진행 이벤트를 받는 곳.
pub trait Progress {
    fn emit(&self, event: &Event<'_>);
}

/// 아무 데도 보내지 않는다. 이벤트를 요구하지 않은 실행의 기본값이다.
pub struct Silent;
impl Progress for Silent {
    fn emit(&self, _event: &Event<'_>) {}
}

/// 어떻게 감쌀 것인가.
///
/// 로컬 키는 언제나 들어간다. 패스프레이즈·조직 키는 있으면 **더한다** — 하나라도
/// 열리면 컨테이너가 열리고, 많을수록 복원 불가 상태가 될 확률이 낮아진다.
#[derive(Default)]
pub struct KeyPolicy {
    pub passphrase: Option<String>,
    pub org_public: Option<[u8; 32]>,
}

/// 계획을 수행한다.
pub struct Executor<'a> {
    backend: &'a dyn PlatformWrite,
    state_dir: PathBuf,
    keys: KeyPolicy,
    progress: &'a dyn Progress,
    now: Option<String>,
    /// 이 실행을 수행하는 바이너리의 자기무결성 (`SelfIntegrity::id`).
    ///
    /// **값을 받아 적을 뿐 판단하지 않는다.** 검사는 `remedy-core` 가 하고
    /// 이 크레이트는 그것을 의존하지 않는다 — 여기서 다시 재면 판단이 두 곳에
    /// 살게 되고, 시작할 때 한 번만 검사한다는 규칙도 깨진다.
    self_integrity: Option<String>,
    /// 재부팅 뒤 재검사 요청 ([`Self::with_verify_after_reboot`]).
    verify: Option<Result<VerifyRequest, String>>,
}

impl<'a> Executor<'a> {
    pub fn new(backend: &'a dyn PlatformWrite, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            backend,
            state_dir: state_dir.into(),
            keys: KeyPolicy::default(),
            progress: &Silent,
            now: None,
            self_integrity: None,
            verify: None,
        }
    }

    /// 계획이 원하면 **`End` 직전에** 재부팅 뒤 재검사를 건다 (설계-03 §8 · P12).
    ///
    /// # 왜 실행기가 거는가
    ///
    /// 우리가 심은 자동실행은 **감사 로그(저널)에 남아야 한다** (자기 흔적 규칙 3).
    /// 그런데 저널은 마지막 줄이 `End` 여야 끝난 회차다. 실행기가 돌려준 뒤에
    /// 걸면 `End` 뒤에 적어야 하고, 그러면 끝난 회차가 이어받기 대상으로
    /// 되살아난다. 한동안 CLI 가 그렇게 걸었고, 그래서 그 사실은 화면에만 있었다.
    ///
    /// `Err` 는 부른 쪽이 요청을 만들지 못한 이유다(플러그인 경로를 모른다 등).
    /// **그것도 저널에 남긴다** — 계획이 원했는데 걸리지 않은 것도 이 회차가 한
    /// 일의 일부다. 주지 않으면 걸지도 적지도 않는다.
    pub fn with_verify_after_reboot(mut self, request: Result<VerifyRequest, String>) -> Self {
        self.verify = Some(request);
        self
    }

    /// 건다. 실패는 치료의 실패가 아니므로 오류로 올리지 않고 결과로 돌려준다 —
    /// 예약 실패로 종료 코드를 바꾸면 무인 배포가 성공한 치료를 실패로 읽는다.
    fn schedule_verify(
        &self,
        run_id: &str,
        request: &Result<VerifyRequest, String>,
    ) -> ScheduledVerify {
        let r = match request {
            Ok(r) => r,
            Err(reason) => {
                return ScheduledVerify::NotScheduled {
                    reason: reason.clone(),
                }
            }
        };
        let state_dir = r.state_dir.as_deref();
        match self
            .backend
            .schedule_verify_after_reboot(run_id, &r.exe, &r.plugin, state_dir, r.lang)
        {
            Ok(()) => ScheduledVerify::Scheduled {
                site: self.backend.scheduled_verify_site(),
                command: remedy_platform::write::scheduled_verify_command(
                    &r.exe, run_id, &r.plugin, state_dir, r.lang,
                ),
            },
            Err(e) => ScheduledVerify::NotScheduled {
                reason: e.to_string(),
            },
        }
    }

    /// 이 실행을 수행하는 바이너리가 무엇인지 저널에 적는다.
    ///
    /// 주지 않으면 그 줄이 없다 — **모르는 것을 `unknown` 으로 적지 않는다.**
    /// 그쪽은 "검사했는데 알 수 없었다" 는 다른 사실이다.
    pub fn with_self_integrity(mut self, id: impl Into<String>) -> Self {
        self.self_integrity = Some(id.into());
        self
    }

    pub fn with_keys(mut self, keys: KeyPolicy) -> Self {
        self.keys = keys;
        self
    }

    pub fn with_progress(mut self, progress: &'a dyn Progress) -> Self {
        self.progress = progress;
        self
    }

    /// 저널에 적을 시각. RFC3339 UTC.
    ///
    /// **호출자가 준다.** 여기서 시계를 읽으면 같은 입력이 매번 다른 저널을
    /// 만들어 시험이 재현되지 않는다 — `assemble` 이 시계를 받는 것과 같은
    /// 이유다.
    ///
    /// 주지 않으면 계획의 생성 시각을 쓴다. 이어받은 실행에서는 그것이 **이전
    /// 시도의 시각**이므로, 감사 로그가 "언제 이어받았는가" 를 말하려면 넣어야
    /// 한다.
    pub fn with_clock(mut self, now: impl Into<String>) -> Self {
        self.now = Some(now.into());
        self
    }

    fn stamp(&self, plan: &PlanEnvelope) -> String {
        self.now.clone().unwrap_or_else(|| plan.created.clone())
    }

    fn container_path(&self, run_id: &str) -> PathBuf {
        self.state_dir
            .join("quarantine")
            .join(format!("{run_id}.rq"))
    }

    /// 승인된 계획을 상태 디렉터리에 남긴다.
    ///
    /// **덮어쓰지 않는다.** 같은 `run_id` 로 다시 왔다면 저널의 `plan_sha256`
    /// 검사가 이미 통과한 뒤이므로 내용이 같다 — 다시 쓸 이유가 없고, 쓰다
    /// 죽으면 이어받을 것이 사라진다.
    fn save_plan(&self, plan: &PlanEnvelope) -> Result<(), ApplyError> {
        let path = plan_path(&self.state_dir, &plan.run_id);
        if path.exists() {
            return Ok(());
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| ApplyError::State(e.to_string()))?;
        }
        let json = serde_json::to_vec_pretty(plan).map_err(|e| ApplyError::State(e.to_string()))?;
        std::fs::write(&path, json).map_err(|e| ApplyError::State(e.to_string()))
    }

    /// 계획을 수행한다. **백업 → 파괴** 순서로 한 번씩만 돈다.
    ///
    /// 저널이 이미 있으면 [`where_to_resume`] 이 정한 자리부터 이어서 돈다.
    pub fn apply(&self, plan: &PlanEnvelope) -> Result<Report, ApplyError> {
        if plan.kind != remedy_sdk::artifact::ArtifactKind::Plan {
            return Err(ApplyError::NotAPlan(plan.kind.id().to_string()));
        }
        let journal_path = remedy_journal::journal_path(&self.state_dir, &plan.run_id);
        let reading = Journal::read(&journal_path).map_err(ApplyError::Journal)?;
        let digest = plan_digest(plan);

        // **다른 계획으로 이어받지 않는다.** run_id 가 같아도 내용이 다르면,
        // 이어서 수행한 결과는 사용자가 승인한 어느 계획과도 다른 것이 된다.
        if reading.plan_sha256().is_some_and(|prev| prev != digest) {
            return Err(ApplyError::PlanChanged(plan.run_id.clone()));
        }

        let resume = where_to_resume(plan, &reading);
        if resume == Resume::Complete {
            return Err(ApplyError::AlreadyApplied(plan.run_id.clone()));
        }

        // 잘린 꼬리를 잘라 내고 이어 쓴다. 그대로 덧붙이면 이어서 수행한 기록이
        // 통째로 읽히지 않는다.
        let mut journal = Journal::resume(&journal_path, &reading).map_err(ApplyError::Journal)?;

        self.progress.emit(&Event::Started {
            run_id: &plan.run_id,
            actions: plan.body.actions.len(),
        });

        // **계획을 곁에 남긴다** (설계-00 §6).
        //
        // 이어서 수행하는 `resume` 은 `--plan` 을 받지 않는다 — 크래시나 재부팅
        // 뒤에 사람이나 배포 도구가 run_id 만으로 부른다(RunOnce 가 심는 것은
        // `verify` 뿐이다). "저장된 plan.json 으로 재개(재스캔 안 함)" 가
        // 성립하려면 그 저장이 여기서 일어나야 한다.
        //
        // 저널의 `plan_sha256` 이 이 파일과 짝이 맞는지는 읽는 쪽이 본다.
        // 파일이 바뀌어 있으면 사용자가 승인한 것과 다른 계획이 된다.
        self.save_plan(plan)?;

        let decided = reading.decided();
        if resume == Resume::Fresh {
            journal
                .append(&Record::Start {
                    run_id: plan.run_id.clone(),
                    plugin_id: plan
                        .plugins
                        .first()
                        .map(|p| p.id.clone())
                        .unwrap_or_default(),
                    plan_sha256: digest,
                    created: plan.created.clone(),
                    self_integrity: self.self_integrity.clone(),
                })
                .map_err(ApplyError::Journal)?;
        } else {
            journal
                .append(&Record::Resumed {
                    run_id: plan.run_id.clone(),
                    at: self.stamp(plan),
                    after_records: reading.records.len(),
                })
                .map_err(ApplyError::Journal)?;
            self.progress.emit(&Event::Resumed {
                already: decided.len(),
                remaining: plan.body.actions.len() - decided.len(),
                redo_backup: resume == Resume::Restart,
            });
        }

        // 무엇을 하려는지 **먼저** 전부 적는다. 크래시가 어디서 오든 "무엇을
        // 하려던 참이었는가" 가 남는다.
        //
        // 이미 적힌 것은 다시 적지 않는다. 계획이 같음을 위에서 확인했으므로 그
        // 줄들은 지금 쓸 것과 한 글자도 다르지 않고, 400건짜리 계획을 이어받을
        // 때마다 400번을 fsync 하는 것은 그저 느려지는 일이다. 그런데 크래시가
        // `Start` 와 첫 `Intent` 사이에 왔다면 **하나도 적히지 않았다** — 그때는
        // 여기서 채워야 저널이 "무엇을 하려던 참이었는가" 를 말할 수 있다.
        let intended = reading.intended();
        for a in &plan.body.actions {
            if intended.contains(&a.seq) {
                continue;
            }
            journal
                .append(&Record::Intent {
                    seq: a.seq,
                    op: a.op,
                    target: a.target.clone().unwrap_or_default(),
                })
                .map_err(ApplyError::Journal)?;
        }

        // ── 복원 지점 (P8) ─────────────────────────────────────
        //
        // **대체재가 아니라 추가 안전망이다** (설계-00 §5-2). 격리 컨테이너가
        // 본래의 되돌리기 수단이고, 이것은 그 위에 얹는다 — 고위험 Op 은
        // 격리로 되돌릴 수 없는 부수 효과(서비스 등록 해제, 인증서 신뢰 변화)를
        // 남기고, 그때 사람이 기댈 곳이 하나 더 있어야 한다.
        //
        // **실패해도 진행한다.** 치명적으로 다루면 복원 지점을 만들 수 없는
        // 환경(보호 꺼짐·서비스 정지·비 Windows)에서 치료 자체가 막힌다.
        //
        // **꼬리만 남은 회차는 만들지 않는다** — 파괴가 이미 끝나, 치료 뒤의
        // 상태를 담는 쓸모없는 지점이 하나 늘 뿐이다 ([`Resume::Tail`]).
        if resume != Resume::Tail
            && plan
                .body
                .actions
                .iter()
                .any(|a| a.op.info().risk == remedy_sdk::catalog::Risk::High)
        {
            let label = format!("remedy-{}", plan.run_id);
            if let Err(e) = self.backend.create_restore_point(&label) {
                let reason = format!("복원 지점을 만들지 못했습니다 (치료는 진행합니다): {e}");
                // **Action 이 아니다.** 복원 지점은 계획에 없고, 만들지
                // 못했으므로 시스템도 바뀌지 않았다 — 불변식 P 를 세는 쪽이
                // 이것을 계획 밖 Action 으로 읽으면 안 된다.
                self.progress.emit(&Event::Note { text: &reason });
                journal
                    .append(&Record::Note {
                        text: reason.clone(),
                    })
                    .map_err(ApplyError::Journal)?;
            }
        }

        // ── 4단계. 백업 ────────────────────────────────────────
        let container = match self.secure_backup(plan, &mut journal, resume) {
            Ok(v) => v,
            Err(e) => {
                // 여기서 멈추면 **아직 아무것도 파괴되지 않았다.**
                let reason = e.to_string();
                self.progress.emit(&Event::Stopped { reason: &reason });
                journal
                    .append(&Record::End {
                        run_id: plan.run_id.clone(),
                        at: self.stamp(plan),
                    })
                    .map_err(ApplyError::Journal)?;
                return Err(e);
            }
        };

        self.progress.emit(&Event::BackedUp {
            entries: plan
                .body
                .actions
                .iter()
                .filter(|a| !a.op.backup_kinds().is_empty())
                .count(),
            container: container.as_ref().map(|p| p.to_string_lossy().to_string()),
        });

        // ── 5·6단계. 파괴 ──────────────────────────────────────
        //
        // 결과는 **이 실행이 한 것만이 아니라 이 run 전체**를 담는다. 이어받은
        // 실행이 제가 한 3건만 보고하면, `result.json` 을 읽는 사람은 계획의
        // 나머지가 조용히 빠졌다고 읽는다.
        let mut results: Vec<ActionResult> = Vec::new();
        let mut carried = 0usize;
        for a in &plan.body.actions {
            if let Some(prev) = decided.get(&a.seq) {
                results.push(carried_over(a, prev));
                carried += 1;
                continue;
            }
            // **감사 로그에 사유를 남긴다** (설계-03 §7, 설계-09 P8).
            //
            // 진행 이벤트만으로는 부족하다. 그것은 화면과 무인 배포가 읽는
            // 스트림이고 저장되지 않는다 — "왜 이 프로세스는 살아남았는가" 를
            // 나중에 물으면 답할 곳이 저널뿐이다.
            let mut notes: Vec<String> = Vec::new();
            let r = self.perform(a, &mut notes);
            for text in notes {
                journal
                    .append(&Record::Note { text })
                    .map_err(ApplyError::Journal)?;
            }
            let (outcome, error) = match &r {
                Ok(()) => (ActionOutcome::Done, None),
                Err(e) => (ActionOutcome::Failed, Some(e.to_string())),
            };
            journal
                .append(&Record::Outcome {
                    seq: a.seq,
                    outcome: match &r {
                        Ok(()) => JOutcome::Done,
                        Err(e) => JOutcome::Failed {
                            reason: e.to_string(),
                        },
                    },
                })
                .map_err(ApplyError::Journal)?;
            self.progress.emit(&Event::Action {
                seq: a.seq,
                op: a.op.info().id,
                target: a.target.as_deref().unwrap_or(""),
                outcome: if outcome == ActionOutcome::Done {
                    "done"
                } else {
                    "failed"
                },
                error: error.as_deref(),
            });
            results.push(ActionResult {
                seq: a.seq,
                op: a.op,
                outcome,
                error,
            });
            // **롤백하지 않는다.** 나머지 계획을 계속 수행한다 (설계-03 §5).
        }

        // ── 7단계. 재부팅 뒤 재검사 예약 (설계-03 §8) ─────────────────
        //
        // **`End` 앞이다** — `with_verify_after_reboot` 의 설명. 실패한 Action 이
        // 있어도 건다: 재검사가 그것까지 다시 본다.
        let scheduled_verify = match (&self.verify, plan.body.verify_after_reboot) {
            (Some(request), true) => {
                let s = self.schedule_verify(&plan.run_id, request);
                journal.append(&s.record()).map_err(ApplyError::Journal)?;
                Some(s)
            }
            _ => None,
        };

        journal
            .append(&Record::End {
                run_id: plan.run_id.clone(),
                at: self.stamp(plan),
            })
            .map_err(ApplyError::Journal)?;

        // **예약은 파괴가 아니다.** 예약에 성공한 Action 이 하나라도 있으면 그
        // 파일은 아직 그 자리에 있고, 사라지는 것은 다음 부팅이다. 이것을
        // 말하지 않으면 사용자는 치료가 끝났다고 읽는다.
        let reboot_required = results.iter().any(|r| {
            r.outcome == ActionOutcome::Done
                && plan
                    .body
                    .actions
                    .iter()
                    .any(|a| a.seq == r.seq && a.op == Op::FileDeleteOnReboot)
        });

        let report = Report {
            body: ResultBody {
                results,
                quarantine: container.as_ref().map(|p| p.to_string_lossy().to_string()),
                reboot_required,
            },
            container,
            journal: journal_path,
            resumed: (resume != Resume::Fresh).then_some(resume),
            carried,
            scheduled_verify,
        };
        self.progress.emit(&Event::Finished {
            done: report.done(),
            failed: report.failed(),
        });
        Ok(report)
    }

    /// 백업 단계. 이어받은 실행에서는 **이미 끝난 백업을 다시 하지 않는다.**
    ///
    /// 다시 하면 이미 지운 파일을 읽으려다 실패한다. 그리고 그 실패는
    /// "아무것도 바꾸지 않았습니다" 는 문구를 달고 나오는데, 그것은 **거짓말**이다 —
    /// 이전 시도가 이미 바꿨다.
    fn secure_backup(
        &self,
        plan: &PlanEnvelope,
        journal: &mut Journal,
        resume: Resume,
    ) -> Result<Option<PathBuf>, ApplyError> {
        // 꼬리만 남은 회차([`Resume::Tail`])도 다시 백업하지 않는다 — 원본은 이미
        // 지워졌고, 다시 읽으려 들면 "아무것도 바꾸지 않았습니다" 는 거짓 중단이 난다.
        if !matches!(resume, Resume::Continue | Resume::Tail) {
            return self.back_up(plan, journal);
        }
        let needs = plan
            .body
            .actions
            .iter()
            .any(|a| !a.op.backup_kinds().is_empty());
        if !needs {
            return Ok(None);
        }
        // 저널은 백업이 끝났다는데 컨테이너가 없다. 그 상태로 이어서 파괴하면
        // **되돌릴 길이 없다.** 파괴를 시작하기 전에 멈춘다.
        let path = self.container_path(&plan.run_id);
        if !path.exists() {
            return Err(ApplyError::ContainerMissing {
                run_id: plan.run_id.clone(),
                path: path.display().to_string(),
            });
        }
        Ok(Some(path))
    }

    /// 파괴될 모든 대상을 격리소에 기록하고 **디스크에 내린다.**
    ///
    /// 반환 전에 컨테이너가 파일로 존재해야 한다. 메모리에만 있는 백업은 백업이
    /// 아니다 — 그 상태에서 파괴가 시작되면 크래시 한 번에 원본이 사라진다.
    fn back_up(
        &self,
        plan: &PlanEnvelope,
        journal: &mut Journal,
    ) -> Result<Option<PathBuf>, ApplyError> {
        let needs: Vec<&Action> = plan
            .body
            .actions
            .iter()
            .filter(|a| !a.op.backup_kinds().is_empty())
            .collect();
        if needs.is_empty() {
            return Ok(None);
        }

        let key = ContentKey::generate()?;
        let mk = MachineKey::load_or_create(&self.state_dir.join("machine.key"))?;
        let mut wraps: Vec<WrapSlot> = vec![mk.wrap(&key)?];
        if let Some(p) = &self.keys.passphrase {
            wraps.push(remedy_quarantine::wrap_with_passphrase(p, &key)?);
        }
        if let Some(pk) = &self.keys.org_public {
            wraps.push(remedy_quarantine::wrap_with_org_key(pk, &key)?);
        }

        let header = Header {
            run_id: plan.run_id.clone(),
            created: plan.created.clone(),
            core_version: plan.core.version.clone(),
            cipher: remedy_quarantine::key::CIPHER_ID.into(),
            wraps,
        };
        let mut builder = Builder::new(
            header,
            plan.plugins
                .first()
                .map(|p| p.id.clone())
                .unwrap_or_default(),
        );

        let mut entry_of = Vec::new();
        for (i, a) in needs.iter().enumerate() {
            let Some(target) = a.target.as_deref() else {
                return Err(ApplyError::StoppedBeforeDestruction(format!(
                    "seq {}: {}",
                    a.seq,
                    remedy_sdk::i18n::t(
                        "백업할 대상 경로가 계획에 없습니다",
                        "the plan has no target path to back up",
                    )
                )));
            };
            // **모양 검사는 읽기보다도 먼저다.** 뒤에 두면 계획에 적힌 임의
            // 디렉터리를 통째로 컨테이너에 담고 나서야 거부하게 되고, 그것은
            // 파괴는 아니어도 "계획이 지시하는 아무 곳이나 읽는다" 다.
            if let Some(why) = refusal_before_backup(self.backend, a, target) {
                return Err(ApplyError::StoppedBeforeDestruction(format!(
                    "seq {}: {why}",
                    a.seq
                )));
            }
            let entry = self
                .capture(a, target)
                .map_err(|e| ApplyError::StoppedBeforeDestruction(format!("seq {}: {e}", a.seq)))?;
            builder.add(entry);
            entry_of.push((a.seq, format!("e{i}")));
        }

        // **여유 공간을 백업 전에 확인한다** (설계-00 §5-2). 백업 도중 디스크가
        // 차면 그때는 이미 원본을 읽어 둔 상태이고, 다음 단계가 파괴다.
        let path = self.container_path(&plan.run_id);
        remedy_platform::disk::require(&[(
            path.to_string_lossy().to_string(),
            builder.estimated_size(),
        )])
        .map_err(|e| ApplyError::StoppedBeforeDestruction(e.to_string()))?;

        let bytes = builder.seal(&key)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(ApplyError::Journal)?;
        }
        write_and_sync(&path, &bytes).map_err(|e| {
            ApplyError::StoppedBeforeDestruction(format!("{}: {e}", path.display()))
        })?;

        // 컨테이너가 디스크에 내려간 **뒤에** 백업 완료를 적는다. 순서가 반대면
        // 저널은 백업이 있다고 하는데 파일은 없는 상태가 생긴다.
        for (seq, entry) in &entry_of {
            journal
                .append(&Record::Backup {
                    seq: *seq,
                    entry_id: entry.clone(),
                })
                .map_err(ApplyError::Journal)?;
        }
        Ok(Some(path))
    }

    /// 술어가 지목하는 프로세스를 종료한다.
    ///
    /// # 세 가지가 여기서 정해진다
    ///
    /// **무엇을** — 술어다. PID 는 계획 시점과 실행 시점 사이에 바뀌므로 계획에
    /// 들어갈 자리가 없다 (설계-03 §1).
    ///
    /// **몇 개까지** — `max_targets` 다. 술어가 몇 개를 지목할지는 실행 시점에야
    /// 알 수 있으므로 이 상한만은 계획 단계에서 판정할 수 없다. 넘으면 **하나도
    /// 죽이지 않고** 멈춘다 (설계-03 §4).
    ///
    /// **몇 번까지** — `max_retries` 다. 그래도 남아 있으면 실패로 기록하고
    /// 넘어간다. **무한 재시도로 악성코드와 경쟁하지 않는다** (설계-00 §2).
    ///
    /// # 정지 단계는 돌지 않는다. 그 사실을 적는다
    ///
    /// 설계-03 §2 가 고정한 규칙은 `해소 → 전부 정지 → 전부 종료 → 재평가`
    /// 인데 이 코어는 정지를 못 한다 (설계-01 D13). **말하지 않으면 저널은
    /// 규칙이 다 돈 것처럼 읽힌다** — 관측이 불완전할 수 있듯 실행도 불완전할
    /// 수 있고, 둘 다 말하지 않으면 완전한 것으로 읽힌다.
    fn kill_matching(&self, a: &Action, notes: &mut Vec<String>) -> Result<(), ApplyError> {
        let p = kill_predicate(a);
        if p.is_empty() {
            return Err(refused(
                "process.kill 에 대상 술어가 없습니다".into(),
                "process.kill has no target predicate".into(),
            ));
        }
        notes.push(format!(
            "seq {}: 정지(suspend) 단계를 건너뛰었습니다 — 이 코어는 프로세스를 \
             정지시키지 못합니다(설계-01 D13). 집합 종료로 진행했습니다",
            a.seq
        ));
        let tries = a.max_retries.unwrap_or(1).clamp(1, 8);
        let mut last_alive: Vec<String> = Vec::new();
        for _ in 0..tries {
            let found = self.backend.processes_matching(&p)?;
            // **보호 대상은 술어가 무엇을 지목했든 제외한다.** 계획기는 술어에
            // 적힌 이미지 경로만 볼 수 있었고, 실제로 무엇이 걸리는지는 지금
            // 처음 안다 (설계-03 §3).
            let (skip, mut kill): (Vec<_>, Vec<_>) = found
                .into_iter()
                .partition(|t| protected_process(t.pid, &t.image_path));
            for t in &skip {
                let why = format!(
                    "seq {}: PID {} '{}' 은 보호 대상이라 종료하지 않았습니다",
                    a.seq, t.pid, t.image_path
                );
                self.progress.emit(&Event::Action {
                    seq: a.seq,
                    op: a.op.info().id,
                    target: &t.image_path,
                    outcome: "skipped",
                    error: Some(&why),
                });
                // 같은 술어를 여러 번 돌 수 있다(`max_retries`). 같은 줄을
                // 두 번 적지 않는다 — 저널을 읽는 사람이 두 번 걸렀다고 읽는다.
                if !notes.contains(&why) {
                    notes.push(why);
                }
            }
            if kill.is_empty() {
                return Ok(());
            }
            // **자손은 술어가 아니라 계보로 들어온다** (설계-03 §2).
            //
            // 뿌리는 **보호 대상을 걸러 낸 뒤**의 집합이다. 술어가 보호 대상을
            // 지목했다면 그것은 술어가 빗나간 것이고, 빗나간 자리에서 계보를
            // 펼치면 실수가 트리 하나만큼 커진다.
            let matched = kill.len();
            if a.include_descendants == Some(true) {
                let roots: Vec<u32> = kill.iter().map(|t| t.pid).collect();
                let kin = self.backend.process_descendants(&roots)?;
                let (kin_skip, kin_kill): (Vec<_>, Vec<_>) = kin
                    .into_iter()
                    .filter(|t| !kill.iter().any(|k| k.pid == t.pid))
                    .partition(|t| protected_process(t.pid, &t.image_path));
                for t in &kin_skip {
                    let why = format!(
                        "seq {}: 자손 PID {} '{}' 은 보호 대상이라 종료하지 않았습니다",
                        a.seq, t.pid, t.image_path
                    );
                    if !notes.contains(&why) {
                        notes.push(why);
                    }
                }
                if !kin_kill.is_empty() {
                    let why = format!(
                        "seq {}: 계보로 자손 {}개를 집합에 더했습니다 — {}",
                        a.seq,
                        kin_kill.len(),
                        kin_kill
                            .iter()
                            .map(|t| format!("PID {} '{}'", t.pid, t.image_path))
                            .collect::<Vec<_>>()
                            .join(" · ")
                    );
                    if !notes.contains(&why) {
                        notes.push(why);
                    }
                }
                kill.extend(kin_kill);
            }
            // **상한을 넘으면 하나도 죽이지 않는다.** 몇 개를 죽인 뒤 멈추면
            // 폭주를 막은 것이 아니라 절반만 폭주한 것이다.
            if let Some(max) = a.max_targets {
                if kill.len() as u32 > max {
                    // **어디서 온 몇 개인지 말한다.** 계보 확장이 켜진 계획에서
                    // "술어가 5개를 지목했다" 만 읽으면 술어를 고치러 가는데,
                    // 실제로 넘긴 것은 자손일 수 있다.
                    //
                    // **문장을 통째로 가른다.** 앞 조각(`from`)이 뒤 문장의
                    // 주어 자리에 들어가는데 그 자리가 언어마다 달라, 조각만
                    // 번역하면 어느 한쪽이 반드시 어그러진다.
                    let kin = kill.len() - matched;
                    let ko = {
                        let from = if kill.len() > matched {
                            format!("술어 {matched}개 + 자손 {kin}개")
                        } else {
                            format!("술어가 {matched}개를")
                        };
                        format!("{from} 지목했습니다. 상한은 {max}개입니다 — 하나도 종료하지 않았습니다")
                    };
                    let en = {
                        let from = if kill.len() > matched {
                            format!("{matched} by predicate + {kin} descendant(s)")
                        } else {
                            format!("{matched} by predicate")
                        };
                        format!(
                            "{from} would be targeted; the limit is {max} — nothing was terminated"
                        )
                    };
                    return Err(refused(ko, en));
                }
            }
            last_alive = kill.iter().map(|t| t.image_path.clone()).collect();
            // **한 번에 넘긴다.** 하나씩 부르면 그 사이가 곧 워치독이 끼어들
            // 창이다 (설계-03 §2).
            let pids: Vec<u32> = kill.iter().map(|t| t.pid).collect();
            self.backend.process_kill(&pids)?;
        }
        // 마지막 시도 뒤에도 남아 있는지 다시 본다.
        //
        // **한 박자 쉬고 본다.** 곧바로 세면 되살리기가 아직 도착하지 않아
        // 언제나 비어 있고, 그러면 실패를 성공으로 보고한다 — 워치독 쌍
        // 하네스에서 실제로 그랬다. 종료 직후 0건을 보고 `exit=1`("치료했다")
        // 을 냈는데 33ms 뒤 둘 다 살아 있었다.
        //
        // 300ms 는 실측 소생 간격(33ms)의 열 배다. 그보다 느린 소생은 이
        // 자리에서 잡지 않는다 — 무한 재시도로 악성코드와 경쟁하지 않는다
        // (설계-00 §2, 설계-03 §2). 남은 것은 실패로 적어 부분 치료로 보고하고,
        // 재부팅 뒤 재시도는 v1 에 없다.
        //
        // **이 재평가는 술어가 지목하는 것만 본다.** 뿌리가 모두 죽고 나면
        // 자손은 계보로 다시 찾을 수 없다 — 부모가 없으므로. 그래서
        // `include_descendants` 로 더해진 것들은 위 note 에 PID 로 남는다.
        // 재평가로 확인한 것과 기록만 한 것을 섞지 않는다.
        //
        // **여기서 "안전 모드에서 다시 시도하라" 고 말하지 않는다.** 그것이
        // 설계-00 §6 이 지목한 결함이다 — 악성코드가 `SafeBoot` 키를 지워
        // 두었으면 그 안내가 부팅되지 않는 컴퓨터를 만든다. 실행기는 무슨 일이
        // 있었는지만 적고, **재시작을 권할지는 부팅 건전성을 읽은 뒤에** CLI 가
        // 정한다.
        std::thread::sleep(SETTLE);
        let left = self.backend.processes_matching(&p)?;
        if left
            .iter()
            .any(|t| !protected_process(t.pid, &t.image_path))
        {
            let alive = last_alive.join(" · ");
            return Err(refused(
                format!(
                    "{tries}회 시도했으나 아직 돌고 있습니다: {alive}. \
                     무한 재시도로 악성코드와 경쟁하지 않습니다"
                ),
                format!(
                    "still running after {tries} attempt(s): {alive}. We do not race malware \
                     with endless retries"
                ),
            ));
        }
        Ok(())
    }

    /// 이 Action 이 파괴할 것을 **읽어 낸다. 아직 바꾸지 않는다.**
    ///
    /// # 무엇으로 담는가는 Op 이 정한다
    ///
    /// `backup_kinds()` 가 그 Op 이 담을 수 있는 종류를 말하고, 대상의 모양이
    /// 그중 하나를 고른다. 종류를 여기서 추측하면 카탈로그와 갈라지고, 그러면
    /// **복원이 백업과 다른 것을 되돌린다.**
    fn capture(&self, a: &Action, target: &str) -> Result<Entry, PlatformError> {
        let kinds = a.op.backup_kinds();
        // **예외 목록은 항목 하나가 아니라 전체다** (설계-02 §9). 부분 diff 로
        // 담으면 복원이 "지금 목록에 이것을 더한다" 가 되는데, 복원을 요청했다는
        // 것은 우리 판정이 틀렸다고 본다는 뜻이라 우리가 손댄 뒤의 목록을
        // 기준으로 삼을 이유가 없다.
        if kinds.contains(&EntryKind::AvExclusion) {
            let list = self.backend.av_exclusions_read()?;
            return Ok(Entry {
                kind: EntryKind::AvExclusion,
                origin: remedy_platform::write::AV_EXCLUSIONS_ORIGIN.to_string(),
                // 어느 항목 때문에 담았는지는 남긴다. 목록만 있으면 나중에
                // "왜 이 백업이 있는가" 에 답할 수 없다.
                meta: serde_json::json!({ "because": target }),
                content: serde_json::to_vec(&list).unwrap_or_default(),
            });
        }
        // 레지스트리 키 하위 트리 — **네 Op 이 같은 문을 쓴다.**
        // `registry.delete_key` 는 키를, `cert_store.remove` 는 인증서 하나가
        // 사는 키를, `service.*` 는 서비스 정의 키를 담는다. 담는 방식이 같으니
        // 정확성도 한 곳에서만 지키면 된다. 라벨만 Op 이 정한다.
        for kind in [
            EntryKind::RegistryKey,
            EntryKind::CertStore,
            EntryKind::Service,
        ] {
            // **모양이 고른다.** `service.*` 는 Windows 에서 레지스트리 키이고
            // Linux 에서 systemd 유닛 파일이다 — 아래 `Unit` 가지가 그쪽을 맡는다.
            if !kinds.contains(&kind) || !is_registry_target(target) {
                continue;
            }
            let (content, index) = self.backend.registry_key_read(target)?;
            return Ok(Entry {
                kind,
                origin: target.to_string(),
                meta: serde_json::to_value(&index).unwrap_or(serde_json::Value::Null),
                content,
            });
        }
        // Linux 인증서는 **파일**이다. 위 가지가 레지스트리 모양만 받으므로
        // 여기로 떨어진다 — `service.*` 를 Windows/Linux 로 가른 것과 같은 규칙이다
        // (설계-09 P12 후속).
        //
        // 목차가 없다. 인증서 파일은 바이트가 전부이고, 되돌릴 때 다시 만드는
        // 것은 번들이지 이 파일의 메타데이터가 아니다.
        // **담는 규칙과 지우는 규칙이 같은 술어를 써야 한다.** 갈라지면
        // 한쪽만 Linux 로 가고, 백업 없이 지우거나 지우지 않을 것을 담는다.
        if kinds.contains(&EntryKind::CertStore) && !is_registry_target(target) {
            return Ok(Entry {
                kind: EntryKind::CertStore,
                origin: target.to_string(),
                meta: serde_json::Value::Null,
                content: self.backend.cert_read(target)?,
            });
        }
        // 부팅 구성은 값 하나다. **`SafeBoot` 하위처럼 구조 전체가 필요한
        // 대상은 담지 않는다** — 어설픈 부분 복원이 손상을 키운다 (설계-03 §2).
        if kinds.contains(&EntryKind::BootConfig) {
            let v = self.backend.registry_read(target)?;
            return Ok(Entry {
                kind: EntryKind::BootConfig,
                origin: target.to_string(),
                meta: serde_json::json!({ "vtype": v.vtype }),
                content: v.bytes,
            });
        }
        // 작업의 정체성은 파일이 아니라 **등록 경로**다. 대상이 그 모양이면
        // 정의를 담는다.
        //
        // **곁가지도 함께 담는다.** systemd 의 활성화는 유닛 파일 안에 없고
        // `<target>.wants/` 아래의 링크다 — 유닛만 되살리면 그 유닛은 꺼진 채로
        // 돌아온다 (설계-09 P12 결정 5). 디렉터리 백업이 목차를 `meta` 에 싣는
        // 것과 같은 자리다.
        //
        // **라벨을 대상의 모양이 고른다.** Windows 예약 작업은 `\` 로 시작하는
        // 등록 경로, cron 은 `<파일>:<줄>`, systemd 는 유닛 파일 경로다. 셋을 한
        // 라벨로 담으면 격리함을 여는 사람이 systemd 유닛을 예약 작업으로 읽는다
        // (설계-09 P12 순서 9).
        for kind in [EntryKind::Task, EntryKind::Cron, EntryKind::Unit] {
            if !kinds.contains(&kind) || !persistence_shape_is(kind, target) {
                continue;
            }
            let (content, index) = self.backend.persistence_read(target)?;
            return Ok(Entry {
                kind,
                origin: target.to_string(),
                meta: serde_json::to_value(&index).unwrap_or(serde_json::Value::Null),
                content,
            });
        }
        // 디렉터리는 **하위 전체**가 하나의 엔트리다. 목차가 meta 로 가고 본문은
        // 이어 붙인 바이트다 (설계-02 §9).
        if kinds.contains(&EntryKind::Directory) && self.backend.is_dir(target) {
            let (content, index) = self.backend.dir_read(target)?;
            return Ok(Entry {
                kind: EntryKind::Directory,
                origin: target.to_string(),
                meta: serde_json::to_value(&index).unwrap_or(serde_json::Value::Null),
                content,
            });
        }
        // 대체 스트림은 **호스트 파일이 아니다.** 파일 전체를 담으면 스트림
        // 하나를 지우고 파일 전체를 되돌리는 꼴이 되고, 그 사이 파일에 일어난
        // 변경이 사라진다.
        if kinds.contains(&EntryKind::FileStream) {
            let content = self.backend.stream_read(target)?;
            return Ok(Entry {
                kind: EntryKind::FileStream,
                origin: target.to_string(),
                meta: serde_json::Value::Null,
                content,
            });
        }
        // 줄 하나만 담는다. 파일 전체를 담으면 한 줄을 되돌릴 때 **그 사이 파일에
        // 일어난 다른 변경까지 되돌린다.** 줄을 종단 문자까지 그대로 들고 있다가
        // 같은 자리에 넣으면 나머지 바이트는 손대지 않는다 (설계-02 §9).
        // 레지스트리 대상을 걸러 내는 이유: `env.strip_path` 와
        // `firewall.restore_rule` 은 담을 종류가 **둘**이다 — 같은 것이 Windows
        // 에서는 레지스트리 값이고 다른 곳에서는 텍스트 줄이다. 대상의 모양이
        // 그중 하나를 고른다.
        // **줄 자리를 계획이 말했을 때만** 이 가지다. `autorun.remove` 처럼 담을
        // 종류가 여럿인 Op 은 대상이 파일 하나일 수 있고, 그때 줄 번호를 요구하면
        // 파괴 전에 멈춘다 — 안전하지만 틀린 멈춤이다.
        if kinds.contains(&EntryKind::TextLine)
            && !is_registry_target(target)
            && (kinds.len() == 1 || match_u32(a, "line_no").is_some())
        {
            let line_no = match_u32(a, "line_no").ok_or(PlatformError::refused(
                "계획에 줄 번호가 없습니다".into(),
                "the plan has no line number".into(),
            ))?;
            let line = self.backend.text_line_read(target, line_no)?;
            return Ok(Entry {
                kind: EntryKind::TextLine,
                origin: target.to_string(),
                meta: serde_json::json!({ "line_no": line_no }),
                content: line.into_bytes(),
            });
        }
        // 구조적 설정은 **파일 원본 전체**다. 파싱해 고쳐 쓰면 들여쓰기와 키
        // 순서가 바뀌므로, 값만 담아 두면 복원이 원본 바이트로 돌아가지 못한다
        // (설계-02 §9 · 설계-03 §2).
        if kinds.contains(&EntryKind::StructuredConfig) {
            let (content, meta) = self.backend.quarantine_read(target)?;
            return Ok(Entry {
                kind: EntryKind::StructuredConfig,
                origin: target.to_string(),
                meta: serde_json::json!({
                    "file": meta,
                    "key_path": a.r#match.as_ref().and_then(|m| m.get("key_path")).cloned(),
                }),
                content,
            });
        }
        if kinds.contains(&EntryKind::RegistryValue) && is_registry_target(target) {
            let v = self.backend.registry_read(target)?;
            return Ok(Entry {
                kind: EntryKind::RegistryValue,
                origin: target.to_string(),
                // 타입 번호를 함께 담는다. 바이트만으로는 되돌릴 때 무엇으로
                // 쓸지 알 수 없다.
                meta: serde_json::json!({ "vtype": v.vtype }),
                content: v.bytes,
            });
        }
        if !kinds.contains(&EntryKind::File) {
            return Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
                "이 Op 의 대상 모양을 담을 방법이 없습니다",
                "there is no way to capture the target shape of this Op",
            )));
        }
        let (content, meta) = self.backend.quarantine_read(target)?;
        Ok(Entry {
            kind: EntryKind::File,
            origin: target.to_string(),
            meta: serde_json::to_value(&meta).unwrap_or(serde_json::Value::Null),
            content,
        })
    }

    /// 레지스트리 값을 바꾸기 전에 **백업이 그것이었는지** 확인한다.
    ///
    /// 부분 편집은 지금 있는 값을 읽어 고쳐 쓴다. 그 사이에 값이 달라졌다면
    /// 우리가 백업한 것과 다른 것을 편집하는 것이고, 복원해도 그 변경은
    /// 되돌아오지 않는다.
    /// **읽기는 한 번뿐이다.** 두 번 읽으면 그 사이에 값이 달라질 수 있고,
    /// 그러면 백업한 것과 다른 것을 고친다.
    ///
    /// 편집기가 `None` 을 내면 **쓰지 않는다** — 지울 것이 이미 없다는 뜻이고,
    /// 목표 상태가 이루어졌으므로 성공이다 (재기동에서 흔하다).
    ///
    /// # 타입 판단을 편집기에 맡기는 이유
    ///
    /// Op 마다 받아들이는 타입이 다르다. `registry.strip_value` 는 문자열과
    /// `REG_MULTI_SZ` 를 함께 다루고, `env.strip_path` 는 문자열만 다룬다 —
    /// 경로 변수가 목록 타입인 자리는 없고, 있다고 가정하면 `;` 로 가르는
    /// 규칙이 뜻을 잃는다. 여기서 `as_string()` 하나로 못박고 있던 동안
    /// **목록 타입은 어느 Op 으로도 고칠 수 없었다** (아래 `RegistryStripValue`).
    fn registry_edit(
        &self,
        a: &Action,
        edit: impl FnOnce(&RegistryValueBackup) -> Result<Option<RegistryValueBackup>, ApplyError>,
    ) -> Result<(), ApplyError> {
        let target = a.target.as_deref().unwrap_or_default();
        let before = self.backend.registry_read(target)?;
        let Some(after) = edit(&before)? else {
            return Ok(());
        };
        self.backend.registry_write(target, &after)?;
        Ok(())
    }

    /// Action 하나를 수행한다. **여기서는 백업하지 않는다** — 이미 끝났다.
    fn perform(&self, a: &Action, notes: &mut Vec<String>) -> Result<(), ApplyError> {
        match a.op {
            // ── 레지스트리 값을 지운다 (P7) ─────────────────────────
            //
            // 다섯 Op 이 같은 일을 한다. 무엇을 지우는가는 계획기가 정했고,
            // 실행기는 그 대상 하나를 지운다.
            // **자동실행은 플랫폼마다 사는 곳이 다르다.** Windows 에서 레지스트리
            // 값 하나이고 Linux 에서 `.desktop` 파일 하나다 — 그 사실은 카탈로그의
            // `backup_kinds` 가 이미 다섯 종류로 적어 두었다 (설계-09 P12 순서 9).
            Op::AutorunRemove if !is_registry_target(a.target.as_deref().unwrap_or_default()) => {
                let target = a.target.as_deref().unwrap_or_default();
                if !self.backend.exists(target) {
                    return Ok(());
                }
                self.backend.destroy_file(target)?;
                Ok(())
            }
            // ── 보안 제품 예외 목록에서 한 항목을 뺀다 ─────────────
            //
            // **레지스트리 값 하나로 다루면 안 된다.** 이 Op 은 한동안 위의
            // 일반 갈래에 얹혀 있었는데, 제외 항목의 **값 이름 자체가 경로**라
            // 역슬래시를 품는다. `split_value_name` 이 마지막 역슬래시에서
            // 자르면 없는 키를 열게 되고, 없으니 `registry_exists` 가 거짓이
            // 되고, 아래 크래시 안전 장치가 그것을 *"이미 지워졌다"* 로 읽어
            // **조용히 성공으로 넘겼다.** `apply` 는 완전 치료(1)로 끝나는데
            // 악성코드가 등록한 예외는 그대로 남았다 (2026-08-31 실기기 실측).
            //
            // 카탈로그는 처음부터 이것을 값 하나로 보지 않았다 —
            // `backup_kinds` 가 `AvExclusion` 전용 종류를 주고, 백업도
            // 목록 전체를 담는다(`capture`). 지우는 쪽만 갈라져 있었다.
            Op::AvRestoreExclusions => {
                let target = a.target.as_deref().unwrap_or_default();
                let Some((kind, value)) = remedy_platform::write::split_av_exclusion(target) else {
                    return Err(refused(
                        format!("'{target}' 는 예외 목록 항목의 모양이 아닙니다"),
                        format!("'{target}' is not shaped like an exclusion entry"),
                    ));
                };
                let now = self.backend.av_exclusions_read()?;
                let want: Vec<_> = now
                    .iter()
                    .filter(|x| !(x.kind == kind && x.value.eq_ignore_ascii_case(value)))
                    .cloned()
                    .collect();
                // 크래시가 파괴와 기록 사이에 왔다면 이미 없다. 다시 지우려
                // 들면 거짓 실패가 "부분 실패" 로 올라간다.
                if want.len() == now.len() {
                    return Ok(());
                }
                self.backend.av_exclusions_write(&want)?;
                Ok(())
            }

            Op::RegistryDeleteValue
            | Op::AutorunRemove
            | Op::ProxyRestore
            | Op::FirewallRestoreRule => {
                let target = a.target.as_deref().unwrap_or_default();
                // 크래시가 파괴와 기록 사이에 왔다면 이미 없다. 다시 지우려
                // 들면 거짓 실패가 "부분 실패" 로 올라간다.
                if !self.backend.registry_exists(target) {
                    return Ok(());
                }
                self.backend.registry_delete(target)?;
                Ok(())
            }

            // ── 값의 일부만 지운다 (P7) ────────────────────────────
            //
            // **타입이 자르는 방법을 정한다.**
            //
            //  - `REG_SZ`·`REG_EXPAND_SZ` — 문자열 하나. 검체가 덧붙인 조각을
            //    부분 문자열로 뺀다 (`Userinit` 의 `,C:\evil.exe`).
            //  - `REG_MULTI_SZ` — **항목의 목록이다.** 부분 문자열로 자르면
            //    `alyac.exe` 를 지우려다 정상 보안 제품의 `bootalyac.exe` 까지
            //    잘린다. `env.strip_path` 에 이미 적어 둔 것과 같은 이유다.
            //
            // 목록 타입을 받지 못하던 동안 `BootExecute` 같은 부팅 지속성을
            // **고칠 방법이 아예 없었다** — `remove` 는 값을 통째로 지워
            // `autocheck autochk *` 까지 없애고, `to: default` 는 카탈로그에
            // 그 자리가 없다. 정답 플러그인조차 실기기에서 종료 코드 3 을
            // 내고 부팅 지속성을 남겼다 (2026-09-05 실측).
            Op::RegistryStripValue => {
                let needle = needle_of(a)?;
                let target = a.target.as_deref().unwrap_or_default();
                self.registry_edit(a, |before| {
                    if let Some(items) = before.as_multi() {
                        let kept: Vec<String> = items
                            .iter()
                            .filter(|it| !multi_item_is(it, needle))
                            .cloned()
                            .collect();
                        // **남은 것이 없어도 값을 지우지 않는다.** 계획이
                        // 승인받은 것은 `strip` 이지 `delete` 가 아니고,
                        // 저널이 "일부를 뺐다" 고 적는데 값 자체가 사라지면
                        // 승인한 것과 한 것이 달라진다.
                        return Ok((kept.len() != items.len())
                            .then(|| RegistryValueBackup::from_multi(&kept)));
                    }
                    let Some(text) = before.as_string() else {
                        return Err(refused(
                            format!("'{target}' 는 문자열도 목록도 아니라 부분 편집할 수 없습니다"),
                            format!("'{target}' is neither a string nor a list, so it cannot be edited in part"),
                        ));
                    };
                    Ok(text.contains(needle).then(|| {
                        RegistryValueBackup::from_string(
                            before.vtype,
                            text.replace(needle, "").trim(),
                        )
                    }))
                })
            }

            // PATH 는 `;` 로 이어진 목록이다. **부분 문자열로 자르면 안 된다** —
            // `C:\a` 를 지우려다 `C:\ab` 까지 잘린다.
            //
            // 목록 타입(`REG_MULTI_SZ`)은 받지 않는다. 경로 변수가 그 타입인
            // 자리는 없고, 있다고 가정하면 `;` 규칙이 뜻을 잃는다.
            Op::EnvStripPath => {
                let needle = needle_of(a)?;
                let target = a.target.as_deref().unwrap_or_default();
                self.registry_edit(a, |before| {
                    let Some(text) = before.as_string() else {
                        return Err(refused(
                            format!("'{target}' 는 문자열 값이 아니라 부분 편집할 수 없습니다"),
                            format!(
                                "'{target}' is not a string value, so it cannot be edited in part"
                            ),
                        ));
                    };
                    // **구분자를 달고 온 needle 을 받아들인다.** 항목 하나를
                    // 통째로 견주는 지금 방식에서 `C:\x;` 는 어느 항목과도
                    // 같지 않아 **아무것도 지우지 않고 성공으로 끝난다.**
                    // 정답 플러그인이 실제로 그렇게 적혀 있었다 (2026-09-05).
                    // `;` 는 어떤 경로에도 들어갈 수 없는 글자라 떼어 내는 것이
                    // 모호하지 않고, 이 정규화는 항목 하나보다 넓게 맞히지도
                    // 않는다.
                    let needle = needle.trim().trim_end_matches(';').trim();
                    if needle.is_empty() {
                        return Err(refused(
                            "지울 것이 구분자뿐입니다".into(),
                            "what would be stripped is only a separator".into(),
                        ));
                    }
                    let kept: Vec<&str> = text
                        .split(';')
                        .filter(|e| !e.trim().eq_ignore_ascii_case(needle))
                        .collect();
                    Ok((kept.len() != text.split(';').count())
                        .then(|| RegistryValueBackup::from_string(before.vtype, &kept.join(";"))))
                })
            }

            // ── 코어가 아는 값으로 되돌린다 (P7) ────────────────────
            //
            // **값의 출처는 카탈로그뿐이다.** 계획에 적힌 값을 쓰면 서명된
            // 도구가 임의 레지스트리 값을 쓸 수 있는 것이고, 그 자체가 공격
            // 도구다 (설계-03 §2).
            Op::RegistryRestoreDefault => {
                let target = a.target.as_deref().unwrap_or_default();
                let Some(default) = remedy_sdk::catalog::restore_default_for(target) else {
                    return Err(refused(
                        format!("'{target}' 는 OS 기본값 카탈로그에 없습니다"),
                        format!("'{target}' is not in the OS-default catalog"),
                    ));
                };
                let before = self.backend.registry_read(target)?;
                self.backend
                    .registry_write(target, &default_as_value(default, before.vtype))?;
                Ok(())
            }

            // ── 파일 계열 (P7) ─────────────────────────────────────
            //
            // **잠긴 파일을 만나도 여기서 Op 을 바꾸지 않는다.** 실패는 실패로
            // 기록하고 부분 치료로 보고한다 (설계-03 §5 — 재부팅 뒤 재시도는 v1 에
            // 없다). 조건 분기로 동작을
            // 추가하면 드라이런이 보여준 것과 실행한 것이 달라진다 — 불변식 P 가
            // 사는 값이 정확히 그것이다.
            Op::FileDelete => {
                let target = a.target.as_deref().unwrap_or_default();
                if !self.backend.exists(target) {
                    return Ok(());
                }
                self.backend.destroy_file(target)?;
                Ok(())
            }

            // 예약은 파괴가 아니다. 파일은 아직 그 자리에 있고, 지워지는 것은
            // 다음 부팅이다 — 그래서 `exists` 로 건너뛰지 않는다.
            Op::FileDeleteOnReboot => {
                let target = a.target.as_deref().unwrap_or_default();
                self.backend.schedule_delete_on_reboot(target)?;
                Ok(())
            }

            Op::FileDeleteStream => {
                let target = a.target.as_deref().unwrap_or_default();
                if !self.backend.exists(target) {
                    return Ok(());
                }
                self.backend.stream_delete(target)?;
                Ok(())
            }

            // 인자만 뺀다. **백업은 파일 전체**다 (설계-03 §2) — 부분 편집을
            // 되돌릴 때 우리가 옳다고 생각한 부분만 남겨서는 안 된다.
            // **계획이 본 인자를 함께 넘긴다.** 없으면 거절한다 — 무엇을 뗄지
            // 계획이 말하지 않은 채로 파일을 고치는 것은 `text_config` 와
            // `structured_config` 가 이미 막고 있는 것과 같은 일이다.
            Op::ShortcutStripArgs => {
                let target = a.target.as_deref().unwrap_or_default();
                let Some(args) = match_str(a, "args") else {
                    return Err(refused(
                        "계획에 바로가기 인자가 없습니다".into(),
                        "the plan has no shortcut arguments".into(),
                    ));
                };
                self.backend.shortcut_strip_args(target, args)?;
                Ok(())
            }

            // ── 설정 계열 (P7) ─────────────────────────────────────
            //
            // **번호와 내용이 둘 다 맞아야 지운다.** 번호만 보면 수집과 실행
            // 사이에 파일이 바뀌었을 때 엉뚱한 줄을 지우고, 내용만 보면 같은
            // 줄이 여럿일 때 어느 것인지 정해지지 않는다. 어긋나면 아무것도
            // 하지 않고 실패한다 — 설정 파일에서 그것이 옳은 실패다.
            Op::TextConfigRemoveLine | Op::HostsRestoreLine => {
                let target = a.target.as_deref().unwrap_or_default();
                let (Some(line_no), Some(line)) = (match_u32(a, "line_no"), match_str(a, "line"))
                else {
                    return Err(refused(
                        "계획에 줄 번호나 내용이 없습니다".into(),
                        "the plan has no line number or line content".into(),
                    ));
                };
                self.backend.text_line_remove(target, line_no, line)?;
                Ok(())
            }

            Op::StructuredConfigRemoveKey => {
                let target = a.target.as_deref().unwrap_or_default();
                let Some(key) = match_str(a, "key_path") else {
                    return Err(refused(
                        "계획에 키 경로가 없습니다".into(),
                        "the plan has no key path".into(),
                    ));
                };
                self.backend.structured_remove_key(target, key)?;
                Ok(())
            }

            // 여기도 **값의 출처는 카탈로그뿐이다** (설계-03 §2). 대상 표기는
            // `<파일>#<키 경로>` 이며, 레지스트리와 같은 목록을 쓴다.
            Op::StructuredConfigRestoreDefault => {
                let target = a.target.as_deref().unwrap_or_default();
                let Some(key) = match_str(a, "key_path") else {
                    return Err(refused(
                        "계획에 키 경로가 없습니다".into(),
                        "the plan has no key path".into(),
                    ));
                };
                let full = format!("{target}#{key}");
                let Some(default) = remedy_sdk::catalog::restore_default_for(&full) else {
                    return Err(refused(
                        format!("'{full}' 는 OS 기본값 카탈로그에 없습니다"),
                        format!("'{full}' is not in the OS-default catalog"),
                    ));
                };
                // **수를 문자열로 늘어놓지 않는다.** `structured_set_key` 는
                // 문자열만 받으므로 `"0"` 을 넘기면 JSON 에 수가 아니라 문자열이
                // 들어가고, 그것은 되돌린 것이 아니다. 지금 그런 항목은 없지만
                // 생기면 조용히 틀린 값을 쓰는 대신 여기서 멈춘다.
                let Some(text) = default.as_text() else {
                    return Err(refused(
                        format!(
                            "'{full}' 의 기본값은 수인데 구조적 설정에 수를 쓸 방법이 없습니다"
                        ),
                        format!(
                            "the default for '{full}' is a number, and there is no way to write a \
                             number into structured config"
                        ),
                    ));
                };
                self.backend.structured_set_key(target, key, text)?;
                Ok(())
            }

            // ── 예약 작업 (P7) ─────────────────────────────────────
            //
            // 둘 다 같은 문을 쓴다. 정의를 남기고 끄는 것과 등록을 지우는 것의
            // 차이일 뿐이며, **어느 쪽을 할지는 계획이 이미 정했다.**
            Op::PersistenceDisable | Op::PersistenceDelete => {
                let target = a.target.as_deref().unwrap_or_default();
                // 재기동한 실행기가 "내가 이미 지웠나" 를 묻는 자리.
                if !self.backend.persistence_exists(target) {
                    return Ok(());
                }
                // 항목이 **파일 안의 줄**이면(cron) 계획이 그 자리를 말한다.
                // 번호만으로 고치면 그 사이에 파일이 바뀌었을 때 정상 작업을
                // 멈춘다 — `text_config.remove_line` 과 같은 규약이다.
                let at = match (match_u32(a, "line_no"), match_str(a, "line")) {
                    (Some(line_no), Some(line)) => Some(remedy_platform::write::LineAt {
                        line_no,
                        line: line.to_string(),
                    }),
                    _ => None,
                };
                if a.op == Op::PersistenceDisable {
                    self.backend.persistence_disable(target, at.as_ref())?;
                } else {
                    self.backend.persistence_delete(target, at.as_ref())?;
                }
                Ok(())
            }

            // ── 브라우저 확장 (P7) ─────────────────────────────────
            //
            // 확장 하나는 디렉터리 하나다. **재귀 삭제이지만
            // `dir.delete_recursive`(P8)가 아니다** — 지울 수 있는 모양이
            // `.../Extensions/<확장 id>` 로 고정되어 있고, 그 검사를 쓰기
            // 경계가 한다. 계획에 임의 경로를 적어 넣어도 통과하지 못한다.
            Op::BrowserExtRemove => {
                let target = a.target.as_deref().unwrap_or_default();
                if !self.backend.exists(target) {
                    return Ok(());
                }
                self.backend.dir_destroy(target)?;
                Ok(())
            }

            // ── 프로세스 (P8) ──────────────────────────────────────
            //
            // **되돌릴 수 없다.** 그래서 되돌릴 수 있는 Action 보다 먼저 놓이고
            // (2단계), 멱등하게 설계된다 (설계-03 §5).
            Op::ProcessKill => self.kill_matching(a, notes),

            // ── 서비스 (P8) ────────────────────────────────────────
            //
            // 대상은 정의 키다. 무엇을 할지는 계획이 이미 정했다.
            Op::ServiceClearRecovery => {
                let target = a.target.as_deref().unwrap_or_default();
                self.backend.service_clear_recovery(target)?;
                Ok(())
            }
            Op::ServiceStop => {
                let target = a.target.as_deref().unwrap_or_default();
                // 이미 멈춰 있으면 목표 상태는 이루어졌다. 재기동한 실행기가
                // 같은 Action 을 다시 만난다.
                if !self.backend.service_running(target) {
                    return Ok(());
                }
                self.backend.service_stop(target)?;
                Ok(())
            }
            Op::ServiceDisable => {
                let target = a.target.as_deref().unwrap_or_default();
                self.backend.service_disable(target)?;
                Ok(())
            }
            Op::ServiceDelete => {
                let target = a.target.as_deref().unwrap_or_default();
                if !self.backend.registry_key_exists(target) {
                    return Ok(());
                }
                self.backend.service_delete(target)?;
                Ok(())
            }

            // ── 레지스트리 키 · 인증서 (P8) ────────────────────────
            //
            // 둘 다 키 하나를 통째로 지운다. **보호 목록이 여기서 처음
            // 필요해진다** — 값 하나를 지우는 것과 키 아래 전부를 지우는 것은
            // 되돌릴 수 있느냐가 아니라 **무엇이 함께 사라지느냐**가 다르다.
            Op::RegistryDeleteKey | Op::CertStoreRemove => {
                let target = a.target.as_deref().unwrap_or_default();
                // **Linux 인증서는 파일이고, 지워도 신뢰가 사라지지 않는다.**
                // `/etc/ssl/certs/ca-certificates.crt` 번들에 내용이 남는다 —
                // 백엔드의 `cert_delete` 가 번들을 다시 만드는 일까지 한다
                // (설계-09 P12 후속).
                if a.op == Op::CertStoreRemove && !is_registry_target(target) {
                    if !self.backend.cert_exists(target) {
                        return Ok(());
                    }
                    self.backend.cert_delete(target)?;
                    return Ok(());
                }
                if let Some(p) = remedy_sdk::catalog::protected_registry_key(target) {
                    return Err(refused(
                        format!("'{p}' 는 키 자체를 지울 수 없습니다. 그 아래 개별 키는 지울 수 있습니다"),
                        format!("'{p}' itself cannot be deleted; individual keys below it can"),
                    ));
                }
                if !self.backend.registry_key_exists(target) {
                    return Ok(());
                }
                self.backend.registry_key_delete(target)?;
                Ok(())
            }

            // ── 재귀 삭제 (P8) ─────────────────────────────────────
            //
            // 계획기가 이미 세 가지를 확인했다 — 증거에서 파생된 경로인가,
            // 그 안에서 악성으로 판정된 것이 있는가, 보호 디렉터리인가
            // (설계-03 §4). 여기서 보는 것은 **계획이 알 수 없는 것**이다.
            Op::DirDeleteRecursive => {
                let target = a.target.as_deref().unwrap_or_default();
                // 서명 확인은 `refusal_before_backup` 이 한다 — **담기 전에**
                // 막아야 하고, 여기 겹쳐 두면 실행되지 않는 죽은 코드가 된다.
                if !self.backend.exists(target) {
                    return Ok(());
                }
                self.backend.dir_destroy(target)?;
                Ok(())
            }

            // ── 부팅 구성 (P8) ─────────────────────────────────────
            //
            // `registry.restore_default` 와 같은 규칙이다 — **값의 출처는
            // 카탈로그뿐이다.** 계획에 적힌 값을 쓰면 서명된 도구가 부팅 구성을
            // 임의로 쓸 수 있는 것이고, 그 자체가 공격 도구다.
            Op::BootRestoreDefault => {
                let target = a.target.as_deref().unwrap_or_default();
                let Some(default) = remedy_sdk::catalog::restore_default_for(target) else {
                    return Err(refused(
                        format!("'{target}' 는 OS 기본값 카탈로그에 없습니다"),
                        format!("'{target}' is not in the OS-default catalog"),
                    ));
                };
                let before = self.backend.registry_read(target)?;
                self.backend
                    .registry_write(target, &default_as_value(default, before.vtype))?;
                Ok(())
            }

            Op::FileQuarantineOnly => {
                let target = a.target.as_deref().unwrap_or_default();
                // **크래시가 파괴와 기록 사이에 왔다면 이미 없다.** 그것을 다시
                // 지우려 들면 "없는 파일" 오류가 나고 실패로 기록되는데, 실제로는
                // 성공한 것이다. 무인 배포는 종료 코드만 보므로 그 거짓 실패가
                // 그대로 "부분 실패" 로 올라간다.
                //
                // 첫 실행에서 이 분기가 설 일은 드물다 — 백업 단계의
                // `quarantine_read` 가 방금 그 파일을 읽어 냈기 때문이다. 그
                // 사이에 사라졌다면 목표 상태는 이미 이루어졌고 백업도 손에
                // 있으므로, 그때도 답은 같다.
                if !self.backend.exists(target) {
                    return Ok(());
                }
                self.backend.destroy_file(target)?;
                Ok(())
            } // **catch-all 이 없다.** P8 이 마지막 Op 을 채우면서 29종이 전부
              // 여기 있고, 남겨 두면 도달할 수 없는 코드가 된다.
              //
              // 없는 편이 낫다. Op 을 새로 정의하면 이 `match` 가 컴파일되지 않고,
              // 그것이 "실행기에 그 Op 을 붙이라" 는 가장 확실한 알림이다.
              // catch-all 이 있으면 그 Op 은 조용히 "수행할 수 없다" 로 실패하고,
              // 계획기 게이트가 올라간 뒤에야 실기기에서 드러난다 —
              // `default_backend()` 가 그렇게 갈라져 있었다.
              //
              // 같은 이유로 `ApplyError::UnsupportedOp` 도 함께 지웠다. 만들
              // 자리가 없는 오류는 오류가 아니라 **없는 상태에 대한 거짓말**이다.
        }
    }
}

/// 계획의 술어에서 수 하나를 꺼낸다.
///
/// **파일 안의 한 줄은 실행 시점에 해소되는 대상**이라 `match` 에 담긴다 —
/// 프로세스를 술어로 고정하는 것과 같은 자리다 (설계-03 §1). 계획이 무엇을
/// 찾을지 전부 정하고, 실행기는 그것을 찾을 뿐이다.
fn match_u32(a: &Action, key: &str) -> Option<u32> {
    a.r#match
        .as_ref()?
        .get(key)?
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
}

fn match_str<'a>(a: &'a Action, key: &str) -> Option<&'a str> {
    a.r#match.as_ref()?.get(key)?.as_str()
}

/// 종료 뒤 **되살아나는지 지켜보는** 시간.
///
/// 0 이면 재평가가 아니라 착시다. 소생은 감시자의 폴링 주기 + 프로세스 생성
/// 시간이고, 실측(설계-09 P8 하네스)에서 33ms 였다. 그 열 배를 기다린다.
const SETTLE: std::time::Duration = std::time::Duration::from_millis(300);

/// 계획의 술어에서 종료 대상 술어를 꺼낸다.
fn kill_predicate(a: &Action) -> remedy_platform::write::KillPredicate {
    remedy_platform::write::KillPredicate {
        image_path: match_str(a, "image_path").map(str::to_string),
        cmdline_contains: match_str(a, "cmdline_contains")
            .or_else(|| match_str(a, "cmdline"))
            .map(str::to_string),
    }
}

/// 이 프로세스는 종료 대상에서 **언제나** 빠진다.
///
/// # 계획기의 검사와 겹치는 것이 아니다
///
/// 계획기는 술어에 **적힌** 이미지 경로를 본다. 여기서는 술어가 **실제로
/// 지목한 것**을 본다. 술어가 `cmdline_contains` 하나뿐이면 계획 시점에는
/// 어느 이미지가 걸릴지 알 수 없고, `csrss.exe` 가 그 문자열을 갖고 있을 수도
/// 있다. 둘은 서로를 대체하지 않는다 (설계-03 §3).
fn protected_process(pid: u32, image_path: &str) -> bool {
    use remedy_sdk::catalog::{PROTECTED_PIDS, WINDOWS_CRITICAL_PROCESSES};
    if PROTECTED_PIDS.contains(&pid) {
        return true;
    }
    let lower = image_path.to_lowercase().replace('/', "\\");
    let name = lower.rsplit('\\').next().unwrap_or("");
    if !WINDOWS_CRITICAL_PROCESSES.contains(&name) {
        return false;
    }
    // **이름이 맞아도 시스템 디렉터리에서 돌지 않으면 위장이다.** 보호하면
    // 악성코드가 이름 하나로 치료를 회피한다 — 보호 목록이 공격자의 도구가
    // 된다 (설계-03 §3).
    lower.contains("\\system32\\") || lower.contains("\\syswow64\\")
}

/// 백업을 시작하기 전에 이 Action 을 거부할 이유가 있는가.
///
/// # 왜 `perform` 이 아니라 여기인가
///
/// `perform` 에 두면 **이미 컨테이너에 담긴 뒤**다. 파괴는 막히지만, 그때까지
/// 계획이 지시한 디렉터리를 통째로 읽어 격리소에 넣은 상태다 — 프로필 전체를
/// 가리키는 계획 하나로 브라우저 데이터가 격리소에 복사된다.
///
/// `perform` 쪽에 같은 검사를 겹쳐 두지 않는 이유: 이 Op 은 담을 것이 있어
/// 백업 단계를 **반드시** 지나므로, 뒤쪽 검사는 실행되지 않는 죽은 코드가 된다.
fn refusal_before_backup(backend: &dyn PlatformWrite, a: &Action, target: &str) -> Option<String> {
    let lang = remedy_sdk::i18n::current();
    // ── 재귀 삭제: 신뢰 서명 (P8) ─────────────────────────────
    //
    // 신뢰 서명된 파일이 하나라도 있으면 그 디렉터리는 통째로 지울 것이 아니다.
    // 노리는 실패는 "악성코드가 정상 프로그램 폴더에 떨어졌고, 그 폴더를 통째로
    // 지워 정상 프로그램을 부수는 것" 이다 (설계-09 P8).
    //
    // **확인하지 못한 것을 통과로 읽지 않는다.** 그러면 가드가 없는 것과 같다 —
    // `FileRecord.signature` 도 같은 논리로 `None` 을 "서명 없음" 으로 읽지
    // 말라고 적어 두었다.
    if a.op == Op::DirDeleteRecursive {
        // **상한이 계획에 없으면 거부한다.** 재귀 삭제가 상한 없이 도는 것은
        // 그 Op 의 정상 상태가 아니다 — 계획기가 언제나 각인하므로 없다는 것은
        // 낡은 계획이거나 손댄 계획이다 (설계-03 §4).
        let (Some(max_children), Some(max_depth)) = (a.max_children, a.max_depth) else {
            return Some(lang.pick(
                format!(
                    "'{target}' 재귀 삭제에 규모 상한이 각인되어 있지 않습니다 — 계획을 다시 \
                     만들어야 합니다 (설계-03 §4)"
                ),
                format!(
                    "'{target}' has no size ceiling stamped on the recursive delete — the plan \
                     must be made again (design-03 §4)"
                ),
            ));
        };
        return match backend.survey_recursive_target(target, max_children, max_depth) {
            Ok(found) if found.is_empty() => None,
            Ok(found) => {
                let list = found.join(" · ");
                Some(lang.pick(
                    format!("'{target}' 안에 신뢰 서명된 파일이 있습니다: {list}"),
                    format!("'{target}' contains trust-signed files: {list}"),
                ))
            }
            // 상한 초과도 여기로 온다 — **재지 못한 것과 넘은 것 둘 다 거부**다.
            Err(e) => Some(lang.pick(
                format!("'{target}' 를 통째로 지울 수 없습니다: {e}"),
                format!("'{target}' cannot be deleted as a whole: {e}"),
            )),
        };
    }
    if a.op != Op::BrowserExtRemove {
        return None;
    }
    if let Some(why) = browser_ext_shape_problem(target) {
        return Some(format!("'{target}': {why}"));
    }
    // 모양이 맞아도 디렉터리가 아니면 이 Op 이 할 일이 아니다. 그대로 두면
    // 백업이 다른 종류로 담기고 파괴가 엉뚱한 문을 두드린다.
    if !backend.is_dir(target) {
        return Some(lang.pick(
            format!("'{target}': 확장 디렉터리가 아닙니다"),
            format!("'{target}': not an extension directory"),
        ));
    }
    None
}

/// 브라우저 확장 디렉터리의 **모양**이 맞는가. 아니면 그 이유.
///
/// # 왜 실행기가 다시 보는가
///
/// 계획기가 이 모양으로만 대상을 만들지만, **실행기는 계획을 믿지 않는다** —
/// `plan.json` 은 텍스트 파일이고 손으로 고칠 수 있다. 여기서 보지 않으면
/// `browser_ext.remove` 는 임의 경로 재귀 삭제가 되고, 그것은 P8 의
/// `dir.delete_recursive` 가 `guard` 를 요구하며 막아 둔 바로 그 동작이다.
///
/// 요구하는 모양은 `.../Extensions/<확장 id>` — `Extensions` 조각 **바로 밑
/// 한 칸**이다. 두 칸 밑(버전 디렉터리)이면 다른 버전이 남고, 위쪽이면
/// 프로필 전체를 지운다.
fn browser_ext_shape_problem(target: &str) -> Option<&'static str> {
    use remedy_sdk::i18n::t;
    if target.contains("..") {
        return Some(t("경로에 '..' 가 있습니다", "the path contains '..'"));
    }
    let parts: Vec<&str> = target
        .split(['\\', '/'])
        .filter(|p| !p.is_empty())
        .collect();
    // **찾지 못하면 문제다.** `?` 로 흘려보내면 `Extensions` 가 아예 없는
    // 임의 경로가 "문제 없음" 으로 통과한다.
    let Some(i) = parts
        .iter()
        .rposition(|p| p.eq_ignore_ascii_case("Extensions"))
    else {
        return Some(t(
            "경로에 'Extensions' 조각이 없습니다",
            "the path has no 'Extensions' segment",
        ));
    };
    if i + 2 != parts.len() {
        return Some(t(
            "'Extensions' 바로 밑의 확장 디렉터리가 아닙니다",
            "not an extension directory directly under 'Extensions'",
        ));
    }
    // 확장 id 는 Chromium 이 만드는 32자 소문자다. 여기서 길이를 재지 않는
    // 이유: Edge·Brave 도 같은 자리를 쓰고 개발자 모드 확장은 규칙이 다르다.
    // 모양 검사가 하는 일은 **어느 칸인가**를 고정하는 것이다.
    if parts[i + 1].is_empty() {
        return Some(t("확장 id 가 비어 있습니다", "the extension id is empty"));
    }
    None
}

/// 이 대상이 레지스트리인가.
///
/// 계획기가 합치는 모양(`<하이브>\<키>\<값 이름>`)의 앞머리를 본다. 파일 경로와
/// 섞이지 않는 이유는 Windows 파일 경로가 드라이브 문자로 시작하기 때문이다.
///
/// **`autorun.remove` 처럼 한 Op 이 레지스트리에도 파일에도 걸리는 자리가 있다.**
/// 그때 무엇으로 담을지는 대상의 모양이 정한다.
/// 지속성 대상의 **모양**이 어느 백업 종류인가 (설계-09 P12 순서 9).
///
/// 셋이 한 subject 를 나눠 갖는다 — Windows 예약 작업은 `\` 로 시작하는 등록
/// 경로, cron 은 `<파일>:<줄>`, systemd 는 유닛 파일 경로다.
/// systemd 유닛 파일의 접미. 우리가 수집하는 둘과 그 이웃이다.
const UNIT_SUFFIXES: [&str; 4] = [".service", ".timer", ".socket", ".path"];

fn persistence_shape_is(kind: EntryKind, target: &str) -> bool {
    let cron = target
        .rsplit_once(':')
        .is_some_and(|(f, n)| !f.is_empty() && n.parse::<u32>().is_ok_and(|v| v > 0));
    match kind {
        EntryKind::Task => remedy_platform::write::is_task_target(target),
        EntryKind::Cron => cron,
        // 유닛은 **접미가 말한다.** "cron 이 아닌 경로" 로 두면 `.desktop`
        // 자동실행까지 유닛으로 잡혀 격리함의 라벨이 거짓이 된다.
        EntryKind::Unit => !cron && UNIT_SUFFIXES.iter().any(|x| target.ends_with(x)),
        _ => false,
    }
}

fn is_registry_target(target: &str) -> bool {
    let head = target.split('\\').next().unwrap_or("").to_ascii_uppercase();
    matches!(
        head.as_str(),
        "HKLM" | "HKCU" | "HKU" | "HKEY_LOCAL_MACHINE" | "HKEY_CURRENT_USER" | "HKEY_USERS"
    )
}

/// 이전 시도가 이미 끝낸 Action 의 결과.
///
/// 다시 수행하지 않고 **저널에 적힌 그대로** 보고한다. 그것이 이 run 에 실제로
/// 일어난 일이고, 다시 물어봐야 할 것도 없다.
fn carried_over(a: &Action, prev: &JOutcome) -> ActionResult {
    let (outcome, error) = match prev {
        JOutcome::Done => (ActionOutcome::Done, None),
        JOutcome::Failed { reason } => (ActionOutcome::Failed, Some(reason.clone())),
    };
    ActionResult {
        seq: a.seq,
        op: a.op,
        outcome,
        error,
    }
}

/// 카탈로그의 기본값을 레지스트리에 쓸 값으로 옮긴다.
///
/// **문자열과 수의 타입 규칙이 다르다.**
///
/// - 문자열은 **지금 있는 값의 타입**을 따른다. 같은 자리가 `REG_SZ` 일 수도
///   `REG_EXPAND_SZ` 일 수도 있고, 카탈로그가 타입까지 정하면 `%SystemRoot%`
///   가 전개되지 않는 문자열로 남는다.
/// - 수는 **카탈로그가 타입을 정한다.** 수에는 보존할 형제 타입이 없고,
///   검체가 타입까지 바꿔 놓았다면 그것도 되돌려야 한다.
fn default_as_value(
    d: remedy_sdk::catalog::DefaultValue,
    before_vtype: u32,
) -> RegistryValueBackup {
    use remedy_sdk::catalog::DefaultValue;
    match d {
        DefaultValue::Text(s) => RegistryValueBackup::from_string(before_vtype, s),
        DefaultValue::Dword(n) => RegistryValueBackup::from_dword(n),
    }
}

/// 계획이 적은 "무엇을 지울지". **비어 있으면 거부한다.**
///
/// 빈 needle 은 조용한 오작동 둘을 만든다. 문자열에서는 `"".contains("")` 가
/// 참이라 값을 `trim` 만 해서 다시 쓰고, 목록에서는 빈 항목만 골라 없앤다 —
/// 둘 다 **"치료했다" 고 보고된다.** `strip` 이 비는 것은 계획기의
/// `interpolate` 가 빈 capture 를 해소했을 때 실제로 일어날 수 있다.
/// 거절 사유를 **두 언어로만** 만들 수 있게 한다 (2026-09-16).
///
/// # 왜 시험 래퍼가 아니라 생성자인가
///
/// `remedy-plan` 에서는 시험이 `src` 안에 있어 같은 이름의 래퍼가 진짜 함수를
/// 가릴 수 있었다. 이 크레이트는 통합 시험뿐이라 그 수가 통하지 않는다.
///
/// 대신 **만드는 자리**를 좁혔다. 이 문 하나만 쓰면 한 언어로 거절을 만들 길이
/// 없고, 새 거절이 생겨도 같은 문을 지난다 — 시험이 그 갈래를 밟아 주기를
/// 기다리지 않아도 된다.
///
/// 거절 사유는 종료 코드 3(부분 실패)으로 **고객에게 간다.** 콘솔 캡처의
/// 부분 실패 절은 OS 오류(`Read-only file system`)를 일으킬 뿐이라 이 열일곱
/// 줄을 한 번도 밟지 않는다.
fn refused(ko: String, en: String) -> ApplyError {
    ApplyError::ActionRefused(remedy_sdk::i18n::current().pick(ko, en))
}

fn needle_of(a: &Action) -> Result<&str, ApplyError> {
    match a.strip.as_deref() {
        Some(n) if !n.trim().is_empty() => Ok(n),
        Some(_) => Err(refused(
            "지울 것이 빈 문자열입니다".into(),
            "what would be stripped is an empty string".into(),
        )),
        None => Err(refused(
            "무엇을 지울지가 계획에 없습니다".into(),
            "the plan does not say what to strip".into(),
        )),
    }
}

/// `REG_MULTI_SZ` 항목 하나가 needle 이 가리키는 것인가.
///
/// **부분 문자열로 보지 않는다.** `BootExecute` 에는 정상 보안 제품의
/// `bootalyac.exe` 가 있고, `alyac.exe` 를 지우라는 지시가 그것에 걸리면
/// 부팅 항목을 잘못 없앤다. `env.strip_path` 가 `;` 로 가른 항목을 통째로
/// 견주는 것과 같은 이유다.
///
/// 다만 이 목록의 항목은 **명령줄일 수 있다** — `autocheck autochk *` 가 그
/// 모양이다. 그래서 항목 전체가 같은 경우와, needle 바로 뒤에 **공백이 오는**
/// 경우까지 본다. 접두사인 것만으로는 맞히지 않으므로 `alyac.exe` 는
/// `bootalyac.exe` 에 걸리지 않는다.
///
/// 빈 항목은 어떤 needle 에도 걸리지 않는다. 그것이 맞다 — 재부팅 큐처럼
/// **빈 항목이 뜻을 갖는** 목록이 있고, 걸러 내면 그 뒤 항목이 통째로
/// 어긋난다 (`RegistryValueBackup::as_multi` 의 같은 이유).
fn multi_item_is(item: &str, needle: &str) -> bool {
    let item = item.trim();
    let needle = needle.trim();
    if item.eq_ignore_ascii_case(needle) {
        return true;
    }
    // `get` 을 쓴다 — 글자 경계가 아닌 자리에서 자르면 패닉이다.
    match item.get(..needle.len()) {
        Some(head) => {
            head.eq_ignore_ascii_case(needle)
                && item[needle.len()..].starts_with(char::is_whitespace)
        }
        None => false,
    }
}

/// 계획 파일의 해시. **승인한 계획과 수행한 계획이 같은가**를 나중에 물을 수 있어야 한다.
fn plan_digest(plan: &PlanEnvelope) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(plan).unwrap_or_default());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// 쓰고 **디스크까지 내린다.** OS 버퍼에 있는 백업은 백업이 아니다.
fn write_and_sync(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// **종료 코드 5 의 사유가 영어 회차에서 한글로 나오지 않는가.**
///
/// 이 크레이트의 통합 시험 셋은 `StoppedBeforeDestruction` 을 **패턴으로만**
/// 본다(`matches!(e, ApplyError::StoppedBeforeDestruction(_))`). 그래서 사유
/// 문자열은 아무도 재지 않고 있었다. 무인 배포가 5 를 받고 왜 막혔는지 읽지
/// 못하면 그 코드는 반만 쓸모 있다.
#[cfg(test)]
mod reason_tests {
    use super::*;
    use remedy_platform::write::{FileMeta, FsRestore, RestoreReport};

    fn 한글이_있는가(s: &str) -> bool {
        s.chars().any(|c| ('가'..='힣').contains(&c))
    }

    fn act(op: Op, target: &str, ceiling: bool) -> Action {
        Action {
            seq: 1,
            op,
            target: Some(target.into()),
            r#match: None,
            max_targets: None,
            max_retries: None,
            max_children: ceiling.then_some(64),
            max_depth: ceiling.then_some(4),
            include_descendants: None,
            sha256: None,
            size: None,
            strip: None,
            because: vec!["e#0".into()],
            backup: None,
            reversible: true,
            risk: remedy_sdk::catalog::Risk::Low,
            user_impact: None,
        }
    }

    /// `survey_recursive_target` **하나만** 갈아 끼운다 — 나머지는 트레이트의
    /// 기본 구현이 채운다. `FsRestore` 로는 `Ok(비지 않음)` 갈래를 못 밟는다.
    struct Signed;

    impl PlatformWrite for Signed {
        fn backend_name(&self) -> &'static str {
            "signed"
        }
        fn plan_restore(&self, _dest: &str, _meta: &FileMeta) -> RestoreReport {
            RestoreReport::default()
        }
        fn quarantine_read(&self, _path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
            unreachable!("이 시험은 백업 단계에 닿지 않는다")
        }
        fn restore_file(
            &self,
            _dest: &str,
            _bytes: &[u8],
            _meta: &FileMeta,
        ) -> Result<RestoreReport, PlatformError> {
            unreachable!("이 시험은 복원하지 않는다")
        }
        fn destroy_file(&self, _path: &str) -> Result<(), PlatformError> {
            unreachable!("이 시험은 파괴하지 않는다")
        }
        fn exists(&self, _path: &str) -> bool {
            false
        }
        fn survey_recursive_target(
            &self,
            _dir: &str,
            _max_children: u32,
            _max_depth: u32,
        ) -> Result<Vec<String>, PlatformError> {
            Ok(vec![r"C:\Program Files\Good\good.exe".into()])
        }
    }

    #[test]
    fn 백업_전에_멈춘_사유에는_한글이_없다() {
        let cases: Vec<(&dyn PlatformWrite, Action, &str)> = vec![
            // 상한이 계획에 없다 — 백엔드를 보기도 전에 거절한다.
            (
                &FsRestore,
                act(Op::DirDeleteRecursive, r"C:\x", false),
                "상한 없음",
            ),
            // **재지 못했다.** 여기서 `{e}` 로 `PlatformError` 가 실려 온다 —
            // 리눅스는 `survey_recursive_target` 을 구현하지 않으므로 실제로
            // 밟는 갈래다.
            (
                &FsRestore,
                act(Op::DirDeleteRecursive, r"C:\x", true),
                "재지 못함",
            ),
            (
                &Signed,
                act(Op::DirDeleteRecursive, r"C:\x", true),
                "신뢰 서명 있음",
            ),
            // 모양은 맞는데 그 자리가 디렉터리가 아니다.
            (
                &FsRestore,
                act(
                    Op::BrowserExtRemove,
                    r"C:\u\Default\Extensions\abcdefgh",
                    true,
                ),
                "디렉터리 아님",
            ),
        ];
        for (backend, a, what) in cases {
            let target = a.target.clone().expect("대상");
            let why = refusal_before_backup(backend, &a, &target)
                .unwrap_or_else(|| panic!("{what}: 거절하지 않았다"));
            assert!(!한글이_있는가(&why), "{what}: {why}");
        }
    }

    /// 모양 사유는 위 함수가 `'{target}': {why}` 로 그대로 실어 나른다.
    #[test]
    fn 확장_모양_사유에는_한글이_없다() {
        for t in [
            r"C:\u\Default\Extensions\..\x",
            r"C:\u\Default\NotExtensions\x",
            r"C:\u\Default\Extensions",
        ] {
            let why = browser_ext_shape_problem(t).unwrap_or_else(|| panic!("{t}: 통과했다"));
            assert!(!한글이_있는가(why), "{t}: {why}");
        }
    }

    /// 사유를 감싸는 **틀**도 같은 화면에 나간다.
    #[test]
    fn 가드가_막은_오류의_틀에는_한글이_없다() {
        use remedy_sdk::artifact::ExitCode;
        for e in [
            ApplyError::StoppedBeforeDestruction("seq 1: blocked".into()),
            ApplyError::PlanChanged("r1".into()),
            ApplyError::AlreadyApplied("r1".into()),
            ApplyError::ContainerMissing {
                run_id: "r1".into(),
                path: "/tmp/x".into(),
            },
        ] {
            assert_eq!(e.exit_code(), ExitCode::GuardStop, "{e}");
            let line = e.to_string();
            assert!(!한글이_있는가(&line), "{line}");
        }
    }
}
