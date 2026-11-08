//! 작업 메뉴 — **인자 없이 띄웠을 때 무엇을 할지 고른다** (목표 `remedy_cli` ①).
//!
//! # 왜 안내 모드 앞에 서는가
//!
//! [`crate::guided`] 는 *"옆의 꾸러미로 검사하고 치료한다"* 하나만 했다. 받은
//! 사람이 할 일은 그것만이 아니다 — 되돌리기 · 신고 · 재검사가 전부 명령줄에만
//! 있었고, 그것을 칠 수 있는 사람은 애초에 메뉴가 필요 없다.
//!
//! # 아무것도 내놓을 것이 없으면 사용법이다 — **바꾸지 않는다**
//!
//! 이 규칙이 세 가지를 한꺼번에 지킨다.
//!
//! | 지키는 것 | 왜 |
//! |---|---|
//! | 오늘의 시연 | 시연 1단계가 인자 없이 부르고 게이트가 *"사용법 다섯 줄"* 을 판정한다 (`Invoke-DemoVerify.ps1`). 데모 폴더는 탐색 두 자리 어느 쪽도 아니고(`<exe>\evilai\plugin.yaml`) 회차도 없으니 **그 화면이 한 글자도 안 바뀐다** |
//! | 개발 빌드 | `cargo run` 으로 그냥 띄우면 옆에 아무것도 없다. 거기서 메뉴가 뜨면 잡음이다 |
//! | 불변식 I7 | 터미널이 아니면 **묻지 않는다** — 물을 수 없는 자리에서 임의로 고르지 않는다 |
//!
//! # 기본 화면은 받은 사람의 일만 — 그 일이 있을 때만 선다 (목표 remedy_사용자메뉴)
//!
//! 명령 표면은 **20개**(최상위 14 + 하위 6)이고 메뉴 줄은 21개다(`restore` 가 목록 보기와
//! 되돌리기 둘). 그중 전용백신을 받은 사람의 일은 여섯이고 **기본 화면**에 선다 — 다만
//! **그 일이 있을 때만**이다([`screens`]).
//!
//! | 줄 | 서는 때 |
//! |---|---|
//! | 검사하고 치료하기 | 치료하는 룰을 골랐다 |
//! | 검사만 하기 | 룰을 골랐다 |
//! | 치료가 유지됐는지 다시 보기 | 치료하는 룰 · 치료한 기록이 있다 |
//! | 치료 전으로 복원하기 | 치료한 기록이 있다(권한으로 못 읽으면 그 까닭과 함께) |
//! | 신고에 붙일 것 모으기 | 치료한 기록이 있다 |
//! | 중단된 작업 이어서 하기 | 끝나지 않은 치료가 있다 |
//!
//! 나머지 열다섯 — 기록 보기 · 프로그램 정보 · 룰 작성자 · 운영자 명령 — 은 기본 화면의 마지막 줄
//! *더 보기* 한 곳에서 닿는다.
//!
//! **전에는 스물한 줄이 늘 같은 번호로 섰다**(목표 remedy_제품화 기준 5 · remedy_출시_20261111
//! 기준 4 — 첫 화면 열셋 + 접은 한 줄). 그러자 치료할 것이 없는 깨끗한 PC 의 첫 화면이 14줄이 되어
//! 다섯 줄이 *"치료한 기록이 없습니다"* 를 달고 흐렸고, 일곱 줄(룰 서명 확인 · 룰 검사 · 자체 점검 ·
//! 버전 · 명령줄 사용법 · 모든 명령과 옵션 · 작성자·운영자 명령 보기)이 받은 사람의 일이 아니었다
//! (v1.2.0 실측 · 2026-11-08). 찾기만 하는 룰에서는 1번 *검사하고 치료하기* 부터 흐렸다.
//!
//! **번호는 이제 상태마다 다르다.** 숨기면 번호가 움직인다는 것이 전의 까닭이었는데, 그 걱정은
//! 두 자리가 받는다 — 치료하는 룰의 1 · 2번은 늘 그 줄이고(README 가 그 번호를 적는다), 작업 뒤
//! *다음 할 일* 은 **돌아갈 그 화면에서** 번호를 센다([`line`]).
//!
//! # 더 보기 — 늘 같은 차례, 못 고르는 줄은 까닭과 함께
//!
//! 개발자 · 룰 작성자 · 운영자의 자리라 전의 규칙을 그대로 쓴다 — 열다섯 줄이 묶음 제목 넷
//! (기록 · 프로그램 · 룰 작성자 · 운영자) 아래 기계 상태와 상관없이 같은 차례로 서고, 지금 입력이
//! 없는 줄은 흐리게 그리고 까닭을 단다(고르기는 그 줄을 받지 않는다). 줄이 창보다 높으면 방향키
//! 화면은 번호 줄과 묶음 제목만 창 안에서 넘긴다(`term::view` · `Row::Group`).
//!
//! # 방향키와 숫자 — 고르는 자리는 [`crate::term::choose`] 하나다
//!
//! 처음에는 숫자만이었다(목표 `remedy_cli` 결정 9) — 방향키가 원시 모드를 들고, 그것이
//! 새 외부 의존과 `unsafe` 를 뜻했기 때문이다. 목표 `remedy_제품화` 결정 6(2026-11-05)이
//! 그것을 다시 열었다: 원시 모드는 crossterm 이 `unsafe` 를 크레이트 안에 가둔 채
//! 들고(우리 코드는 `forbid` 그대로), 그 의존은 `deny` · `arch` 를 지났다.
//!
//! **숫자는 그대로 받는다.** 그리는 자리가 아니면(stdout 이 파일 · `NO_COLOR` ·
//! `TERM=dumb`) 지금까지의 글자 그대로 번호 한 줄을 받는다 — `WriteConsoleInput`
//! 하네스가 보내는 숫자+Enter 가 두 길 모두에서 통한다.

use crate::term::{Answer, Row};
use crate::ui;

/// 메뉴가 고른 것. **여기서 실행하지 않는다** — `main` 이 같은 `cmd_*` 로 보낸다.
/// 화면과 안전 가드를 두 벌 갖지 않기 위해서다([`crate::guided`] 와 같은 이유).
pub enum Pick {
    /// 아무것도 내놓을 것이 없다 — 부르는 쪽이 사용법을 보인다. **지금까지의 동작.**
    ShowUsage,
    /// 물었고 사용자가 그만두었다.
    Stopped,
    /// 하위 화면(회차 · 파일)에서 `0` — 메뉴로 돌아간다.
    Back,
    /// Ctrl+C 두 번 — 세션을 끝낸다.
    End,
    /// 이 플러그인으로 무엇을 한다 (묶음 B).
    WithPlugin(WithPlugin),
    /// 인자가 없는 명령을 그대로 돈다 (묶음 A).
    Plain(Plain),
    /// 회차를 골라 그 명령을 돈다 (묶음 C).
    WithRun(WithRun),
    /// 파일을 골라 그 명령을 돈다 (묶음 D·E). 플러그인이 드는 셋은 **그 경로를
    /// 함께** 들고 간다 — 메뉴가 고른 것을 `main` 이 따로 알 길이 없다.
    WithFile(WithFile, Option<std::path::PathBuf>),
    /// 입력이 없는 수집 — 결과 파일은 부르는 쪽이 정한다 (묶음 A 성격). 고른 플러그인을
    /// 함께 들고 간다 — `collect` 는 그 플러그인이 정한 자리를 본다(`--plugin` 이 없으면
    /// 입력 오류다).
    Collect(std::path::PathBuf),
}

/// 플러그인 하나가 드는 명령 — 묶음 B. 고른 플러그인 경로를 함께 들고 간다.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WithPlugin {
    /// `run --plugin <경로>` — 검사하고 치료한다.
    Run(std::path::PathBuf),
    /// `scan --plugin <경로> --out-dir <...>` — 검사만 한다.
    Scan(std::path::PathBuf),
    /// `verify --plugin <경로>` — 치료가 유지됐는지 재평가한다.
    Verify(std::path::PathBuf),
    /// `plugin lint <경로>` — 룰이 규칙을 지키는지 본다.
    Lint(std::path::PathBuf),
    /// `plugin verify --dir <폴더>` — 이 꾸러미가 우리 것인지 확인한다.
    VerifyBundle(std::path::PathBuf),
}

/// 입력 **파일** 하나가 드는 명령 — 묶음 D·E. 번호로 고른 경로를 들고 간다.
///
/// # 왜 이 묶음이 ⓪ 뒤에 왔나
///
/// 이 명령들은 **폴더에 놓인 파일**을 입력으로 받는다. 메뉴가 그 폴더를 읽어
/// 목록으로 보이면 **그 폴더를 쓸 수 있는 누구든 고를 거리를 놓을 수 있다.**
/// 그래서 복원 정보 폴더를 관리자 전용으로 잠그는 ⓪ 이 먼저였다
/// (`remedy_platform::statedir`).
///
/// 그래도 **계획은 한 겹 더 본다** — [`WithFile::Apply`] 의 주석에.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WithFile {
    /// `apply --plan <파일> --plugin <경로>` — 이미 승인된 계획을 수행한다.
    ///
    /// **저널과 짝이 맞는 계획만 고를 거리에 올린다.** `apply` 는 저널의
    /// `plan_sha256` 과 대조하므로 짝이 안 맞으면 거절하지만, 거절될 것을
    /// 목록에 올리면 사용자는 자기가 무엇을 잘못했는지 알 수 없다.
    Apply(std::path::PathBuf),
    /// `evaluate --artifacts <파일> --plugin <경로> --out <생성>`
    Evaluate(std::path::PathBuf),
    /// `plan --scan <파일> --plugin <경로> --out <생성>`
    Plan(std::path::PathBuf),
    /// `allowlist verify --file <목록>`
    AllowVerify(std::path::PathBuf),
    /// `allowlist import --file <목록>`
    AllowImport(std::path::PathBuf),
    /// `revocation verify --file <목록>`
    RevokeVerify(std::path::PathBuf),
    /// `revocation import --file <목록>`
    RevokeImport(std::path::PathBuf),
}

/// 회차 하나가 드는 명령 — 묶음 C. 번호로 고른 `run_id` 를 함께 들고 간다.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WithRun {
    /// `restore --run <id> --state-dir <그 회차의 폴더>`
    Restore(Run),
    /// `support-bundle --run <id> --state-dir <그 회차의 폴더>`
    Support(Run),
    /// `resume --run <id> --state-dir <그 회차의 폴더>`
    Resume(Run),
}

/// 되돌릴 수 있는 한 회차 — **어느 폴더의 것인지 함께 든다** (결정 3 ·
/// 2026-10-30 확정).
///
/// 메뉴는 **두 자리를 다 읽는다** — 인자 없이 띄운 경로가 쓰는 `<exe>\state\` 와,
/// 전부터 쓰던 기계 공용 자리(`%PROGRAMDATA%\remedy` · `/var/lib/remedy`). 회차 번호만 들고
/// 가면 고른 뒤 **어느 폴더에 묻는지** 알 수 없고, 이미 있는 격리물이 메뉴에서
/// 사라지는 것은 이 목표의 멈출 조건 5 다.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Run {
    pub id: String,
    pub state: std::path::PathBuf,
}

/// 입력이 없는 명령 — 묶음 A.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Plain {
    /// `selftest`
    SelfTest,
    /// `--version`
    Version,
    /// `--help`
    Help,
    /// `--help-all`
    HelpAll,
    /// `restore --list`
    RestoreList,
}

/// 메뉴 한 줄 — **무엇을 고른 것인지만 들고 있다.** 실행은 `main` 이 한다.
enum Tag {
    /// 고른 플러그인으로 무엇을 한다.
    NeedsPlugin(MakeWithPlugin),
    /// 치료한 회차를 한 번 더 물어야 한다.
    NeedsRun(MakeWithRun),
    /// **끝나지 않은** 회차를 한 번 더 물어야 한다 — 이어서 하기. 끝난 회차를 고르게 하면
    /// '이미 적용됨'(5)으로 거절된다(2026-11-07 적대적 검토).
    NeedsUnfinished(MakeWithRun),
    /// 파일을 한 번 더 물어야 한다.
    NeedsFile(Candidates, MakeWithFile),
    /// 입력이 없는 수집.
    Collect,
    /// 그대로 돈다.
    Plain(Plain),
}

struct Item {
    label: &'static str,
    tag: Tag,
    /// 지금 고를 수 없으면 그 까닭 — 더 보기의 줄과, 기록을 권한으로 못 읽었을 때의 복원 줄.
    off: Option<&'static str>,
    /// 기본 화면의 줄이면 그 일 — *다음 할 일* 이 그것으로 줄을 찾는다([`line`]).
    main: Option<Main>,
}

/// 기본 화면에 설 수 있는 줄 — **받은 사람의 일** 여섯. 서는 줄만 차례대로 번호를 받는다.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Main {
    /// 검사하고 치료하기 — 치료하는 룰을 골랐다.
    Treat,
    /// 검사만 하기 — 룰을 골랐다.
    Scan,
    /// 치료가 유지됐는지 다시 보기 — 치료하는 룰 · 치료한 기록이 있다.
    Verify,
    /// 치료 전으로 복원하기 — 치료한 기록이 있다.
    Restore,
    /// 신고에 붙일 것 모으기 — 치료한 기록이 있다.
    Support,
    /// 중단된 작업 이어서 하기 — 끝나지 않은 치료가 있다.
    Resume,
}

impl Main {
    fn tag(self) -> Tag {
        match self {
            Self::Treat => Tag::NeedsPlugin(WithPlugin::Run),
            Self::Scan => Tag::NeedsPlugin(WithPlugin::Scan),
            Self::Verify => Tag::NeedsPlugin(WithPlugin::Verify),
            Self::Restore => Tag::NeedsRun(WithRun::Restore),
            Self::Support => Tag::NeedsRun(WithRun::Support),
            Self::Resume => Tag::NeedsUnfinished(WithRun::Resume),
        }
    }
}

/// 지금 이 기계가 **내놓을 수 있는 것**. 비어 있으면 메뉴를 열지 않는다.
pub struct Offer {
    /// 쓸 수 있는 플러그인 (검증을 통과한 것만).
    pub plugin: Option<std::path::PathBuf>,
    /// 그 플러그인이 **찾기만 하는가**(`remediate` 가 없다) — 치료를 약속하는 줄을 끈다.
    pub detect_only: bool,
    /// 그 플러그인의 이름 — 머리말에 적는다. 항목이 여럿인 꾸러미에서 고른 뒤 메뉴만 보면
    /// 어느 것을 골랐는지 알 수 없었다(2026-11-06 리눅스 통합 꾸러미 화면).
    pub name: Option<String>,
    /// 복원 정보 폴더에서 읽은 회차 — **이름순.** 비어 있으면 회차 줄(복원 · 유지 확인 · 신고)은
    /// 기본 화면에 서지 않는다.
    pub runs: Vec<Run>,
    /// 끝나지 않은 치료(저널에 끝이 없다) — **이름순.** 있을 때만 *이어서 하기* 가 선다.
    pub unfinished: Vec<Run>,
    /// 복원 정보 폴더가 **있는데 권한 때문에 읽지 못했다** — 그때 회차 줄의 까닭은 '기록이 없다'
    /// 가 아니라 '권한을 올려 실행' 이다. 관리자로 치료한 뒤 권한 없이 다시 띄우면 기록이 사라진
    /// 것으로 읽혔다(2026-11-08 적대적 검토 4바퀴 — 리눅스 실측).
    pub runs_locked: bool,
    /// 후보 파일 — 종류마다 **이름순.** 비어 있는 종류의 줄은 까닭을 달고 흐리게 선다.
    /// 부르는 쪽이 폴더를 읽어 채운다(메뉴는 실행 파일 자리를 모른다).
    pub files: std::collections::BTreeMap<Candidates, Vec<std::path::PathBuf>>,
}

impl Offer {
    /// **내놓을 것이 없으면 메뉴를 열지 않는다.** 이 함수가 §3-00 의 규칙이다 —
    /// 오늘의 시연 1단계가 그 화면을 판정한다.
    ///
    /// 후보 파일도 센다(묶음 D·E). 데모 폴더는 셋 다 비어 있다 — 루트에
    /// `remedy.exe` 뿐이고 `out`·`state` 는 재감염이 지운다(실측 2026-10-29 ·
    /// `New-DemoMachine.ps1:230`).
    pub fn is_empty(&self) -> bool {
        self.plugin.is_none()
            && self.runs.is_empty()
            && self.unfinished.is_empty()
            && self.files.is_empty()
    }

    fn has_runs(&self) -> bool {
        !self.runs.is_empty()
    }

    fn files_of(&self, c: Candidates) -> &[std::path::PathBuf] {
        self.files.get(&c).map_or(&[], Vec::as_slice)
    }
}

/// 고른 회차를 명령으로 만드는 함수 — 복원 · 신고 · 이어서 하기([`Main::tag`]).
type MakeWithRun = fn(Run) -> WithRun;

/// 고른 파일을 명령으로 만드는 함수 — [`FILE_ITEMS`] 의 네 번째 칸.
type MakeWithFile = fn(std::path::PathBuf) -> WithFile;

/// 파일이 드는 명령 일곱 — 묶음 D·E. (한국어 · 영어 · **어떤 후보를 보일지** · 무엇이 되는가)
///
/// 세 번째 칸이 [`Candidates`] 다 — 메뉴가 **어느 폴더에서 무엇을 찾을지**를
/// 그 값이 정한다. 요구사항(*"필요한 정보가 있는 폴더를 자동으로 읽어서
/// 거기 있는 모든 항목을 보여주고 선택"*)이 이 칸이다.
const FILE_ITEMS: &[(&str, &str, Candidates, MakeWithFile)] = &[
    (
        "승인한 계획을 수행하기",
        "Apply an approved plan",
        Candidates::Plans,
        WithFile::Apply,
    ),
    (
        "수집 결과를 평가하기",
        "Evaluate a collected snapshot",
        Candidates::Artifacts,
        WithFile::Evaluate,
    ),
    (
        "평가 결과로 계획 세우기",
        "Plan from an evaluation",
        Candidates::Scans,
        WithFile::Plan,
    ),
    (
        "조직 허용 목록 확인",
        "Verify an org allowlist",
        Candidates::Lists,
        WithFile::AllowVerify,
    ),
    (
        "조직 허용 목록 반입",
        "Import an org allowlist",
        Candidates::Lists,
        WithFile::AllowImport,
    ),
    (
        "폐기 목록 확인",
        "Verify a revocation list",
        Candidates::Lists,
        WithFile::RevokeVerify,
    ),
    (
        "폐기 목록 반입",
        "Import a revocation list",
        Candidates::Lists,
        WithFile::RevokeImport,
    ),
];

/// 메뉴가 어느 폴더에서 무엇을 찾아 보일지.
///
/// **깊이 뒤지지 않는다.** `discover::beside` 가 두 자리만 보는 것과 같은
/// 까닭이다 — 깊이 뒤질수록 *"놓기만 하면 된다"* 는 자리가 넓어진다.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Candidates {
    /// 결과 폴더의 `plan*.json` — **저널과 짝이 맞는 것만** 부르는 쪽이 걸러 준다.
    Plans,
    /// 결과 폴더의 `artifacts*.json`.
    Artifacts,
    /// 결과 폴더의 `scan*.json`.
    Scans,
    /// 실행 파일 옆의 `*.signed` — 서명된 목록은 그 꼴로 온다.
    Lists,
}

impl Candidates {
    /// 이 후보가 보는 폴더와 고를 꼴. 폴더는 **부르는 쪽이 준다** — 메뉴는
    /// 실행 파일 자리를 모른다(그것을 아는 곳은 `main` 이다).
    pub fn matches(self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        match self {
            Self::Plans => lower.starts_with("plan") && lower.ends_with(".json"),
            Self::Artifacts => lower.starts_with("artifacts") && lower.ends_with(".json"),
            Self::Scans => lower.starts_with("scan") && lower.ends_with(".json"),
            Self::Lists => lower.ends_with(".signed"),
        }
    }

    /// 이 종류의 후보가 하나도 없을 때 메뉴 줄에 다는 까닭 — 어느 자리에 무엇이 없는지.
    /// 자리는 `guided::candidate_files` 가 보는 곳이다(목록은 실행 파일 옆, 나머지는 `out`).
    fn missing(self, lang: remedy_sdk::i18n::Lang) -> &'static str {
        match self {
            Self::Plans => lang.t(
                "out 폴더에 승인한 계획(plan*.json)이 없습니다",
                "no approved plan (plan*.json) in out",
            ),
            Self::Artifacts => lang.t(
                "out 폴더에 수집 결과(artifacts*.json)가 없습니다",
                "no collected snapshot (artifacts*.json) in out",
            ),
            Self::Scans => lang.t(
                "out 폴더에 평가 결과(scan*.json)가 없습니다",
                "no evaluation (scan*.json) in out",
            ),
            Self::Lists => lang.t(
                "실행 파일 옆에 서명된 목록(*.signed)이 없습니다",
                "no signed list (*.signed) next to the program",
            ),
        }
    }
}

/// 고른 플러그인을 명령으로 만드는 함수 — 검사 · 치료 · 유지 확인([`Main::tag`])과 [`AUTHOR_ITEMS`].
type MakeWithPlugin = fn(std::path::PathBuf) -> WithPlugin;

/// 기본 화면의 줄 여섯 — (한국어 · 영어 · 그 일). **차례가 번호다** — 서는 줄만 센다. 검사 ·
/// 치료가 맨 위다: 받아서 띄운 사람의 목적이 그것이고, 치료하는 룰에서 1 · 2번은 늘 그 둘이다
/// (README 와 피드백 문안이 그 번호를 적는다). 치료 뒤의 셋은 *다음 할 일* 의 차례와 같다 —
/// 유지 확인이 먼저, 되돌리기와 신고가 뒤(되돌리기가 첫 줄이면 할 일 목록으로 읽힌다).
const MAIN_ITEMS: &[(&str, &str, Main)] = &[
    ("검사하고 치료하기", "Scan and treat", Main::Treat),
    (
        "검사만 하기 (아무것도 바꾸지 않습니다)",
        "Scan only (changes nothing)",
        Main::Scan,
    ),
    (
        "치료가 유지됐는지 다시 보기",
        "Re-check that the treatment held",
        Main::Verify,
    ),
    ("치료 전으로 복원하기", "Undo a treatment", Main::Restore),
    (
        "신고에 붙일 것 모으기",
        "Collect what to attach to a report",
        Main::Support,
    ),
    (
        "중단된 작업 이어서 하기",
        "Resume an interrupted run",
        Main::Resume,
    ),
];

/// 더 보기의 묶음 제목 넷 — (한국어 · 영어). 차례가 화면의 차례다.
const GROUPS: [(&str, &str); 4] = [
    ("기록", "Records"),
    ("프로그램", "Program"),
    ("룰 작성자", "Rule authors"),
    (
        "운영자 (사내 평가 · 조직 목록)",
        "Operators (in-house evaluation, org lists)",
    ),
];

/// 더 보기 · 기록 — 되돌릴 수 있는 회차 목록. *치료 전으로 복원하기* 가 같은 목록을 먼저 보이므로
/// 받은 사람의 일로 두지 않는다.
const RECORD_ITEM: (&str, &str, Plain) = (
    "복원할 수 있는 치료 기록 보기",
    "Show treatments that can be undone",
    Plain::RestoreList,
);

/// 더 보기 · 프로그램 — 입력이 없어 어느 기계에서나 뜻이 있다. 버전은 머리말이 이미 보이고,
/// 자체 점검과 명령줄 안내는 지원 · 운영자의 일이다.
const PROGRAM_ITEMS: &[(&str, &str, Plain)] = &[
    ("프로그램 자체 점검", "Self-test", Plain::SelfTest),
    ("버전 보기", "Version", Plain::Version),
    ("명령줄 사용법", "Command-line usage", Plain::Help),
    (
        "모든 명령과 옵션",
        "Every command and option",
        Plain::HelpAll,
    ),
];

/// 더 보기 · 룰 작성자 — 고른 룰로 본다. 서명은 프로그램이 룰을 쓰기 전에 스스로 확인한다
/// (`discover::usable`) — 받은 사람이 따로 고를 일이 아니다.
const AUTHOR_ITEMS: &[(&str, &str, MakeWithPlugin)] = &[
    (
        "룰 검사 (작성자용)",
        "Lint the rule (for authors)",
        WithPlugin::Lint,
    ),
    (
        "룰 서명 확인",
        "Verify the rule signatures",
        WithPlugin::VerifyBundle,
    ),
];

/// 회차 줄의 까닭 — 기록은 있을지 모르나 **이 권한으로는 읽지 못한다.** 머리말의 권한 줄과 같은
/// 낱말을 쓴다(Windows 는 관리자, 리눅스는 root).
fn runs_locked_reason(lang: remedy_sdk::i18n::Lang) -> &'static str {
    if cfg!(windows) {
        lang.t(
            "관리자 권한으로 실행해야 기록이 보입니다",
            "run as administrator to see the records",
        )
    } else {
        lang.t(
            "root 권한으로 실행해야 기록이 보입니다",
            "run as root to see the records",
        )
    }
}

/// 더 보기의 한 묶음 — 제목과 줄.
struct Group {
    title: &'static str,
    items: Vec<Item>,
}

/// 지금 상태의 메뉴 — 기본 화면에 서는 줄과 더 보기의 묶음 넷.
struct Screens {
    main: Vec<Item>,
    more: Vec<Group>,
}

/// 이 상태에서 설 줄. 기본 화면은 **그 일이 있을 때만** 줄을 세운다 — 깨끗한 PC 에 *"치료한
/// 기록이 없습니다"* 를 단 줄을 늘어놓지 않는다(목표 remedy_사용자메뉴 기준 1 · 2). 더 보기는
/// 늘 같은 열다섯 줄이고 못 고르는 줄은 까닭을 단다(그 목표의 결정 2).
fn screens(offer: &Offer, lang: remedy_sdk::i18n::Lang) -> Screens {
    let ko = lang == remedy_sdk::i18n::Lang::Ko;
    let pick = |k: &'static str, e: &'static str| -> &'static str {
        if ko {
            k
        } else {
            e
        }
    };
    let plugin = offer.plugin.is_some();
    let treats = plugin && !offer.detect_only;
    let runs = offer.has_runs();
    // 기록이 있을지 모르는데 이 권한으로 못 읽었다 — 그때만 복원 한 줄이 그 까닭과 함께 선다.
    // 숨기면 관리자(root)로 치료한 뒤 권한 없이 다시 띄운 사람이 기록이 사라진 것으로 읽는다.
    let locked = (!runs && offer.runs_locked).then(|| runs_locked_reason(lang));

    // ── 기본 화면 — 받은 사람의 일 ──────────────────────────────────
    let mut main = Vec::new();
    for (k, e, m) in MAIN_ITEMS {
        let (shown, off) = match m {
            Main::Treat => (treats, None),
            Main::Scan => (plugin, None),
            // 치료가 유지됐는지는 **치료한 기록이 있어야** 묻는다 — 없을 때 고르면 치료한 적 없는
            // 기계에 *"치료 성공"* 이 떴다(v1.1.0 적대적 검토 · 2026-11-07 실측).
            Main::Verify => (treats && runs, None),
            Main::Restore => (runs || locked.is_some(), locked),
            Main::Support => (runs, None),
            Main::Resume => (!offer.unfinished.is_empty(), None),
        };
        if shown {
            main.push(Item {
                label: pick(k, e),
                tag: m.tag(),
                off,
                main: Some(*m),
            });
        }
    }

    // ── 더 보기 — 늘 같은 열다섯 줄 ─────────────────────────────────
    let no_plugin = (!plugin).then(|| {
        lang.t(
            "쓸 수 있는 플러그인 번들이 없습니다",
            "no usable plugin bundle",
        )
    });
    let no_runs = (!runs).then(|| {
        locked.unwrap_or_else(|| lang.t("치료한 기록이 없습니다", "no treatment recorded yet"))
    });
    // 찾기만 하는 룰 — 치료를 약속하는 줄(승인한 계획을 수행하기)은 까닭을 단다.
    let detect_only = (offer.detect_only && plugin).then(|| {
        lang.t(
            "이 룰은 찾기만 하고 치료하지 않습니다",
            "this rule only detects; it does not treat",
        )
    });
    let more_item = |label: &'static str, tag: Tag, off: Option<&'static str>| Item {
        label,
        tag,
        off,
        main: None,
    };
    let (rk, re, rp) = RECORD_ITEM;
    let records = vec![more_item(pick(rk, re), Tag::Plain(rp), no_runs)];
    let program = PROGRAM_ITEMS
        .iter()
        .map(|(k, e, p)| more_item(pick(k, e), Tag::Plain(*p), None))
        .collect();
    let authors = AUTHOR_ITEMS
        .iter()
        .map(|(k, e, mk)| more_item(pick(k, e), Tag::NeedsPlugin(*mk), no_plugin))
        .collect();
    let p = std::path::PathBuf::new();
    let mut operators = vec![more_item(
        lang.t(
            "수집만 하기 (평가는 사내에서)",
            "Collect only (evaluate in-house)",
        ),
        Tag::Collect,
        no_plugin,
    )];
    for (k, e, cand, mk) in FILE_ITEMS {
        // 계획·평가는 플러그인이 함께 들어야 한다 — 그 까닭이 먼저다.
        let needs_plugin = matches!(
            cand,
            Candidates::Plans | Candidates::Artifacts | Candidates::Scans
        );
        let off = if needs_plugin && no_plugin.is_some() {
            no_plugin
        } else if detect_only.is_some() && matches!(mk(p.clone()), WithFile::Apply(_)) {
            detect_only
        } else if offer.files_of(*cand).is_empty() {
            Some(cand.missing(lang))
        } else {
            None
        };
        operators.push(more_item(pick(k, e), Tag::NeedsFile(*cand, *mk), off));
    }
    let more = [records, program, authors, operators]
        .into_iter()
        .zip(GROUPS)
        .map(|(items, (k, e))| Group {
            title: pick(k, e),
            items,
        })
        .collect();
    Screens { main, more }
}

/// 작업 뒤의 *다음 할 일* 이 가리키는 기본 화면의 줄(목표 remedy_제품화 기준 6(d)).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Line {
    /// 검사하고 치료하기
    Treat,
    /// 치료가 유지됐는지 다시 보기
    Verify,
    /// 치료 전으로 복원하기
    Undo,
    /// 신고에 붙일 것 모으기
    Report,
}

/// 그 줄의 번호와 이름 — **돌아갈 그 화면에서** 센다(목표 remedy_사용자메뉴 기준 4). 기본 화면은
/// 일이 있을 때만 줄을 세우므로 번호가 상태마다 다르다 — 부르는 쪽이 작업 **뒤**의 상태로 `offer` 를
/// 만든다(`guided::next_offer`). 그 화면에 서지 않거나 고를 수 없는 줄이면 `None` — 없는 줄을
/// 가리키지 않는다.
pub fn line(which: Line, offer: &Offer) -> Option<(usize, String)> {
    let want = match which {
        Line::Treat => Main::Treat,
        Line::Verify => Main::Verify,
        Line::Undo => Main::Restore,
        Line::Report => Main::Support,
    };
    let main = screens(offer, ui().lang).main;
    let pos = main
        .iter()
        .position(|it| it.main == Some(want) && it.off.is_none())?;
    Some((pos + 1, main[pos].label.to_string()))
}

/// 기본 화면의 마지막 줄 — 더 보기를 연다.
fn more_label(lang: remedy_sdk::i18n::Lang) -> &'static str {
    lang.t(
        "더 보기 (기록 · 프로그램 정보 · 관리자 · 룰 작성자)",
        "More (records, program info, admin, rule authors)",
    )
}

/// 기본 화면의 `0.` 줄. 명령줄 안내는 더 보기의 머리말로 갔다 — 받은 사람의 첫 화면에
/// `remedy --help` 를 적지 않는다.
fn quit_label(lang: remedy_sdk::i18n::Lang) -> &'static str {
    lang.t("그만두기", "Quit")
}

/// 더 보기의 머리말.
fn more_head(lang: remedy_sdk::i18n::Lang) -> &'static str {
    lang.t(
        "더 보기 — 관리자 · 룰 작성자 · 문제 확인용 명령입니다 (명령줄로 쓰려면 remedy --help)",
        "More - commands for administrators, rule authors and troubleshooting (for the command line, see remedy --help)",
    )
}

/// 메뉴 줄을 화면 줄로 — 못 고르는 줄은 까닭과 함께.
fn rows_of(items: &[Item]) -> impl Iterator<Item = Row> + '_ {
    items.iter().map(|it| match it.off {
        Some(why) => Row::Off(it.label.to_string(), why.to_string()),
        None => Row::Item(it.label.to_string()),
    })
}

/// 메뉴를 보이고 하나를 받는다.
///
/// **터미널이 아니면 열지 않는다** — 불변식 I7. 부르는 쪽이 이미 터미널만
/// 통과시키지만, 물어보는 함수가 스스로 그것을 확인하는 편이 안전하다.
pub fn run(offer: &Offer) -> Pick {
    if offer.is_empty() {
        return Pick::ShowUsage;
    }
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Pick::ShowUsage;
    }

    let lang = ui().lang;
    let Screens { main, more } = screens(offer, lang);

    // **머리말 한 덩어리** — 제품 이름 · 판 · 권한(목표 remedy_제품화 기준 3(a) ·
    // 벤치마크 축 2 · 3). 권한은 고른 뒤에 거절당하지 않게 먼저 보인다.
    let mut rows = vec![
        Row::Blank,
        Row::Text(format!(
            "{} {}",
            remedy_core::report::brand::product(lang),
            env!("CARGO_PKG_VERSION")
        )),
    ];
    if let Some(name) = &offer.name {
        rows.push(Row::Text(
            lang.pick(format!("검사 항목: {name}"), format!("Rule: {name}")),
        ));
    }
    if let Some(line) = privilege_line(lang) {
        rows.push(Row::Text(line));
    }
    rows.extend([
        Row::Blank,
        Row::Text(
            lang.t("무엇을 할까요?", "What would you like to do?")
                .to_string(),
        ),
        Row::Blank,
    ]);
    // 받은 사람의 일 — 그 일이 있을 때만 선다. 나머지는 마지막 한 줄(더 보기)이 연다.
    rows.extend(rows_of(&main));
    rows.push(Row::Item(more_label(lang).to_string()));
    let zero = quit_label(lang);

    // 이 세션에서 작업을 한 뒤 그만두면 "아무것도 하지 않았습니다" 가 거짓이다.
    let quit = || -> Pick {
        outln!();
        if crate::term::tasks_ran() {
            outln!("{}", lang.t("끝냅니다.", "Exiting."));
        } else {
            outln!(
                "{}",
                lang.t("아무것도 하지 않았습니다.", "Nothing was done.")
            );
        }
        Pick::Stopped
    };

    // 더 보기의 `0` 은 **이 메뉴로** 돌아온다 — 룰을 고르는 화면까지 물러나지 않는다.
    let it = loop {
        let n = match crate::term::choose(&rows, Some(zero)) {
            Answer::Num(0) | Answer::Invalid => return quit(),
            Answer::End => return Pick::End,
            Answer::Num(n) => n,
        };
        if n <= main.len() {
            break &main[n - 1];
        }
        match choose_more(&more) {
            Sub::Got((g, i)) => break &more[g].items[i],
            Sub::Back => {}
            Sub::Stop => return quit(),
            Sub::End => return Pick::End,
        }
    };

    match &it.tag {
        Tag::NeedsPlugin(mk) => offer
            .plugin
            .clone()
            .map_or(Pick::ShowUsage, |p| Pick::WithPlugin(mk(p))),
        Tag::Plain(p) => Pick::Plain(*p),
        // **회차를 한 번 더 묻는다.** 작업을 먼저 고르고 대상을 고르는 순서다 —
        // 회차를 먼저 물으면 되돌리기만 생각한 사람에게 신고가 안 보인다.
        Tag::NeedsRun(mk) => match choose_run(&offer.runs) {
            Sub::Got(id) => Pick::WithRun(mk(id)),
            Sub::Back => Pick::Back,
            Sub::Stop => quit(),
            Sub::End => Pick::End,
        },
        // 이어서 하기는 **끝나지 않은 회차만** 고를 거리로 올린다.
        Tag::NeedsUnfinished(mk) => match choose_run(&offer.unfinished) {
            Sub::Got(id) => Pick::WithRun(mk(id)),
            Sub::Back => Pick::Back,
            Sub::Stop => quit(),
            Sub::End => Pick::End,
        },
        Tag::Collect => offer.plugin.clone().map_or(Pick::ShowUsage, Pick::Collect),
        Tag::NeedsFile(cand, mk) => match choose_file(offer.files_of(*cand)) {
            Sub::Got(path) => Pick::WithFile(mk(path), offer.plugin.clone()),
            Sub::Back => Pick::Back,
            Sub::Stop => quit(),
            Sub::End => Pick::End,
        },
    }
}

/// 하위 화면의 답. `0` 은 그만두기가 아니라 **메뉴로 돌아가기**다 — 메뉴가 작업 뒤에도
/// 이어지므로, 하위 화면에서 잘못 들어온 사람이 세션을 잃지 않는다.
enum Sub<T> {
    Got(T),
    Back,
    /// 읽지 못했다 — 지금까지처럼 그만둔다(되묻지 않는다 · 불변식 I7).
    Stop,
    End,
}

fn sub_answer<T: Clone>(a: Answer, list: &[T]) -> Sub<T> {
    match a {
        Answer::Num(0) => Sub::Back,
        Answer::Num(n) => list.get(n - 1).cloned().map_or(Sub::Stop, Sub::Got),
        Answer::Invalid => Sub::Stop,
        Answer::End => Sub::End,
    }
}

fn back_label() -> &'static str {
    ui().lang.t("메뉴로 돌아가기", "Back to the menu")
}

/// 더 보기 — 묶음 제목 넷 아래 열다섯 줄. 고른 줄의 (묶음, 차례 — 0 부터)를 돌려준다. 제목은
/// 번호가 없는 글줄이고(`Row::Group`), 번호는 묶음을 건너 이어진다.
fn choose_more(groups: &[Group]) -> Sub<(usize, usize)> {
    let lang = ui().lang;
    let mut rows = vec![Row::Blank, Row::Text(more_head(lang).to_string())];
    let mut at = Vec::new();
    for (g, group) in groups.iter().enumerate() {
        rows.push(Row::Blank);
        rows.push(Row::Group(group.title.to_string()));
        rows.extend(rows_of(&group.items));
        at.extend((0..group.items.len()).map(|i| (g, i)));
    }
    sub_answer(crate::term::choose(&rows, Some(back_label())), &at)
}

/// 머리말의 권한 줄. 재지 못했으면 내지 않는다 — 모르는 것을 말하지 않는다.
/// 룰을 고르는 화면(`guided::choose`)도 같은 줄을 쓴다.
pub(crate) fn privilege_line(lang: remedy_sdk::i18n::Lang) -> Option<String> {
    let who = if cfg!(windows) {
        lang.t("관리자", "administrator")
    } else {
        "root"
    };
    Some(if remedy_core::elevated()? {
        lang.pick(
            format!("{who} 권한으로 실행 중입니다."),
            format!("Running with {who} rights."),
        )
    } else {
        lang.pick(
            format!("{who} 권한이 없습니다 — 검사 · 치료는 {who} 권한으로 다시 실행해야 합니다."),
            format!("No {who} rights — run again as {who} to scan or treat."),
        )
    })
}

/// 회차를 번호로 고르게 한다. **이름순으로 그대로 보인다** — 같은 폴더에서 늘
/// 같은 차례가 나와야 사람이 고른 번호가 뜻을 갖는다(`guided::choose` 와 같은 규칙).
fn choose_run(runs: &[Run]) -> Sub<Run> {
    let lang = ui().lang;
    let mut rows = vec![
        Row::Blank,
        Row::Text(lang.pick(
            format!("어느 작업입니까? ({}건)", runs.len()),
            format!("Which run? ({})", runs.len()),
        )),
    ];
    rows.extend(runs.iter().map(|r| Row::Item(r.id.clone())));
    sub_answer(crate::term::choose(&rows, Some(back_label())), runs)
}

/// 후보 파일을 번호로 고르게 한다.
///
/// **부모 폴더까지 보인다.** 전에는 파일 이름만 적었고 *"폴더는 모두 같다"* 는
/// 전제가 그 주석에 있었다. 결정 4(2026-10-30)로 결과가 `<exe>\out\<스탬프>\`
/// 로 가면서 **그 전제가 깨졌다** — 회차가 둘이면 `plan.json` 이 두 줄로 똑같이
/// 보여 고를 수가 없다. 전체 경로는 줄마다 넘치므로 **두 토막**만 적는다.
/// 고른 뒤 그 명령의 배너가 전체 경로를 적는다.
fn choose_file(files: &[std::path::PathBuf]) -> Sub<std::path::PathBuf> {
    let lang = ui().lang;
    let mut rows = vec![
        Row::Blank,
        Row::Text(lang.pick(
            format!("어느 파일입니까? ({}개)", files.len()),
            format!("Which file? ({})", files.len()),
        )),
    ];
    rows.extend(files.iter().map(|f| Row::Item(two_parts(f))));
    sub_answer(crate::term::choose(&rows, Some(back_label())), files)
}

/// 경로의 **마지막 두 토막** — `<부모>/<이름>`. 부모가 없으면 이름만.
///
/// 구분자는 플랫폼의 것을 쓴다. 화면에 `out/20261030T113100Z` 가 섞여 나오면
/// 받는 사람이 그것을 자기 기계의 경로로 읽지 못한다.
fn two_parts(p: &std::path::Path) -> String {
    let name = p.file_name().unwrap_or_default().to_string_lossy();
    match p.parent().and_then(|d| d.file_name()) {
        Some(up) => format!(
            "{}{}{name}",
            up.to_string_lossy(),
            std::path::MAIN_SEPARATOR
        ),
        None => name.into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        line, screens, Candidates, Line, Main, Offer, Plain, Run, Tag, WithFile, WithPlugin,
        WithRun, AUTHOR_ITEMS, FILE_ITEMS, GROUPS, MAIN_ITEMS, PROGRAM_ITEMS, RECORD_ITEM,
    };
    use remedy_sdk::i18n::Lang;

    fn a_run(id: &str) -> Run {
        Run {
            id: id.into(),
            state: std::path::PathBuf::from("s"),
        }
    }

    /// 플러그인 · 치료한 기록 · 끝나지 않은 치료가 있는지로 만든 상태.
    fn state(plugin: bool, runs: bool, unfinished: bool) -> Offer {
        Offer {
            plugin: plugin.then(|| std::path::PathBuf::from("p.yaml")),
            detect_only: false,
            name: None,
            runs: if runs {
                vec![a_run("run-1")]
            } else {
                Vec::new()
            },
            unfinished: if unfinished {
                vec![a_run("run-2")]
            } else {
                Vec::new()
            },
            runs_locked: false,
            files: std::collections::BTreeMap::new(),
        }
    }

    fn offer(plugin: bool, runs: bool) -> Offer {
        state(plugin, runs, false)
    }

    /// 기본 화면의 줄 이름 — 화면 차례대로.
    fn main_labels(o: &Offer) -> Vec<&'static str> {
        screens(o, Lang::Ko).main.iter().map(|i| i.label).collect()
    }

    const TREAT: &str = "검사하고 치료하기";
    const SCAN: &str = "검사만 하기 (아무것도 바꾸지 않습니다)";
    const VERIFY: &str = "치료가 유지됐는지 다시 보기";
    const UNDO: &str = "치료 전으로 복원하기";
    const REPORT: &str = "신고에 붙일 것 모으기";
    const RESUME: &str = "중단된 작업 이어서 하기";

    /// **이것이 오늘의 시연을 지키는 규칙이다.** 내놓을 것이 없으면 메뉴를 열지
    /// 않는다 — 시연 1단계가 인자 없이 부르고 게이트가 *"사용법 다섯 줄"* 을
    /// 판정한다. 데모 폴더는 플러그인도 회차도 없다.
    #[test]
    fn nothing_to_offer_is_not_a_menu() {
        assert!(offer(false, false).is_empty());
        assert!(!offer(true, false).is_empty());
        assert!(!offer(false, true).is_empty());
        assert!(!offer(true, true).is_empty());
        assert!(!state(false, false, true).is_empty());
    }

    /// 기준 1 — **깨끗한 PC 의 기본 화면은 받은 사람의 일만** 보인다. 치료하는 룰은 둘, 찾기만 하는
    /// 룰은 하나(그 뒤에 *더 보기*). 까닭을 단 흐린 줄은 없다 — v1.2.0 은 열넷 중 다섯(찾기만 하는
    /// 룰은 여섯)이 흐렸다(2026-11-08 실측).
    #[test]
    fn a_clean_pc_shows_only_what_the_user_does() {
        assert_eq!(main_labels(&offer(true, false)), [TREAT, SCAN]);
        let mut detect = offer(true, false);
        detect.detect_only = true;
        assert_eq!(main_labels(&detect), [SCAN]);
        for o in [offer(true, false), detect] {
            assert!(screens(&o, Lang::Ko).main.iter().all(|i| i.off.is_none()));
        }
    }

    /// 기준 2 — **일이 생기면 그 줄이 선다.** 치료한 기록이 있으면 유지 확인(치료하는 룰만) · 복원 ·
    /// 신고, 끝나지 않은 치료가 있으면 이어서 하기.
    #[test]
    fn lines_appear_when_their_work_exists() {
        assert_eq!(
            main_labels(&offer(true, true)),
            [TREAT, SCAN, VERIFY, UNDO, REPORT]
        );
        assert_eq!(
            main_labels(&state(true, true, true)),
            [TREAT, SCAN, VERIFY, UNDO, REPORT, RESUME]
        );
        // 격리 전에 끊긴 치료 — 되돌릴 것은 없고 이어서 할 것만 있다.
        assert_eq!(
            main_labels(&state(true, false, true)),
            [TREAT, SCAN, RESUME]
        );
        // 찾기만 하는 룰 — 치료를 약속하는 둘(치료 · 유지 확인)은 서지 않는다. 기록은 기계의 것이라
        // 다른 룰로 치료한 기록의 복원 · 신고는 선다.
        let mut detect = offer(true, true);
        detect.detect_only = true;
        assert_eq!(main_labels(&detect), [SCAN, UNDO, REPORT]);
        // 룰 없이 기록만 — 꾸러미를 지운 뒤 되돌리려는 사람이 여기 온다.
        assert_eq!(main_labels(&offer(false, true)), [UNDO, REPORT]);
        assert!(main_labels(&offer(false, false)).is_empty());
    }

    /// 기준 2(c) — 기록 폴더를 **권한 때문에 못 읽었으면** 복원 한 줄이 권한을 올리라는 까닭과 함께
    /// 선다. 숨기면 관리자(root)로 치료한 뒤 권한 없이 다시 띄운 사람이 기록이 사라진 것으로 읽는다
    /// (2026-11-08 리눅스 실측). 더 보기의 기록 보기도 같은 까닭이다.
    #[test]
    fn unreadable_runs_ask_for_the_right_privilege_instead_of_hiding() {
        let locked = Offer {
            runs_locked: true,
            ..offer(true, false)
        };
        let s = screens(&locked, Lang::Ko);
        let shown: Vec<_> = s.main.iter().map(|i| (i.label, i.off.is_some())).collect();
        assert_eq!(shown, [(TREAT, false), (SCAN, false), (UNDO, true)]);
        let why = s.main[2].off.unwrap_or_default();
        assert!(why.contains("권한으로 실행해야 기록이 보입니다"), "{why}");
        assert_eq!(s.more[0].items[0].off, Some(why));
        // 고를 수 없는 줄은 다음 할 일이 가리키지 않는다.
        assert_eq!(line(Line::Undo, &locked), None);
    }

    /// 기준 3 — **명령 전수(`main.rs` 분기)와 메뉴를 맞댄다.** 분기에 명령을 더하고
    /// 메뉴에 줄을 더하지 않으면 여기서 깨진다. 분기는 `let outcome = match cmd {` 부터
    /// 인자 없는 `None =>` 까지이고, 들여쓰기 여덟 칸이 명령 · 열두 칸이 하위 명령이다.
    ///
    /// 일이 다 있는 상태에서 기본 화면 + 더 보기가 스무 명령에 닿는다. 깨끗한 PC 에서 서지 않는 것은
    /// **입력이 없는 셋**(유지 확인 · 신고 · 이어서 하기)뿐이다 — `restore` 는 더 보기의 기록 보기로 닿는다.
    #[test]
    fn every_command_has_a_menu_line() {
        let src = include_str!("main.rs");
        let from = src.find("let outcome = match cmd {").expect("분기 머리");
        let to = src[from..].find("\n        None =>").expect("분기 끝") + from;
        let mut dispatched = std::collections::BTreeSet::new();
        let mut parent: Option<&str> = None;
        for line in src[from..to].lines() {
            if let Some(r) = line.strip_prefix("        Some(\"") {
                let name = r.split('"').next().unwrap_or_default();
                // 하위 명령을 받는 갈래는 그 자체로는 명령이 아니다.
                parent = line.contains("match rest.first()").then_some(name);
                if parent.is_none() {
                    dispatched.insert(name.to_string());
                }
            } else if let Some(r) = line.strip_prefix("            Some(\"") {
                let sub = r.split('"').next().unwrap_or_default();
                let p = parent.expect("하위 갈래 앞에는 그 명령이 있다");
                dispatched.insert(format!("{p} {sub}"));
            }
        }
        assert_eq!(dispatched.len(), 20, "명령 전수: {dispatched:?}");

        let reach = |o: &Offer| -> std::collections::BTreeSet<String> {
            let s = screens(o, Lang::Ko);
            s.main
                .iter()
                .chain(s.more.iter().flat_map(|g| g.items.iter()))
                .map(|i| command(&i.tag).to_string())
                .collect()
        };
        assert_eq!(
            reach(&state(true, true, true)),
            dispatched,
            "메뉴에 없는 명령 · 분기에 없는 줄"
        );
        let hidden: Vec<String> = dispatched
            .difference(&reach(&offer(true, false)))
            .cloned()
            .collect();
        assert_eq!(hidden, ["resume", "support-bundle", "verify"]);
    }

    /// 더 보기는 **묶음 넷 · 열다섯 줄**이고 기계 상태와 상관없이 같은 차례로 선다(목표
    /// remedy_사용자메뉴 결정 2). 기본 화면의 여섯과 합쳐 스물한 줄 — 명령 스물(`restore` 가 둘)이다.
    #[test]
    fn more_is_fifteen_lines_in_four_groups_in_a_fixed_order() {
        let shape = |o: &Offer| -> Vec<(&'static str, Vec<&'static str>)> {
            screens(o, Lang::Ko)
                .more
                .iter()
                .map(|g| (g.title, g.items.iter().map(|i| i.label).collect()))
                .collect()
        };
        let base = shape(&offer(true, false));
        let sizes: Vec<usize> = base.iter().map(|(_, v)| v.len()).collect();
        assert_eq!(sizes, [1, 4, 2, 8]);
        let titles: Vec<&str> = base.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            titles,
            [
                "기록",
                "프로그램",
                "룰 작성자",
                "운영자 (사내 평가 · 조직 목록)"
            ]
        );
        for o in [
            offer(true, true),
            offer(false, true),
            offer(false, false),
            state(true, true, true),
        ] {
            assert_eq!(shape(&o), base);
        }
        assert_eq!(MAIN_ITEMS.len() + sizes.iter().sum::<usize>(), 21);
    }

    /// 더 보기에서 지금 못 고르는 줄은 **까닭을 단다** — 새로 받은 꾸러미(플러그인만)에서 기록 보기와
    /// 운영자의 일곱이 그렇다(수집만은 고를 수 있다). v1.2.0 의 접은 화면과 같은 값이다.
    #[test]
    fn more_says_why_a_line_cannot_be_picked() {
        for lang in [Lang::Ko, Lang::En] {
            let s = screens(&offer(true, false), lang);
            let off: Vec<usize> = s
                .more
                .iter()
                .map(|g| g.items.iter().filter(|i| i.off.is_some()).count())
                .collect();
            assert_eq!(off, [1, 0, 0, 7]);
            assert!(s
                .more
                .iter()
                .flat_map(|g| g.items.iter())
                .all(|i| i.off.is_none_or(|w| !w.is_empty())));
        }
        let s = screens(&offer(true, false), Lang::Ko);
        assert_eq!(s.more[0].items[0].off, Some("치료한 기록이 없습니다"));
    }

    /// 두 언어가 **같은 명령을 같은 차례로** 낸다. 어긋나면 한 언어로 돌린
    /// 사람만 다른 줄을 고른다 — 번호가 뜻을 잃는다.
    #[test]
    fn both_languages_offer_the_same_commands_in_the_same_order() {
        for o in [
            offer(true, false),
            state(true, true, true),
            offer(false, true),
        ] {
            let cmds = |lang: Lang| -> Vec<&'static str> {
                let s = screens(&o, lang);
                s.main
                    .iter()
                    .chain(s.more.iter().flat_map(|g| g.items.iter()))
                    .map(|i| command(&i.tag))
                    .collect()
            };
            assert_eq!(cmds(Lang::Ko), cmds(Lang::En));
        }
    }

    /// 기준 4 — *다음 할 일* 이 적는 번호는 **돌아갈 그 화면의** 번호이고, 서지 않는 줄은 가리키지
    /// 않는다.
    #[test]
    fn next_step_lines_point_at_lines_that_are_shown() {
        let n = |l: Line, o: &Offer| line(l, o).map(|(n, _)| n);
        // 치료한 뒤 — 유지 확인 3 · 복원 4 · 신고 5. README 가 적은 *3. 치료가 유지됐는지 다시 보기* 가
        // 그 줄이다.
        let after = offer(true, true);
        assert_eq!(n(Line::Treat, &after), Some(1));
        assert_eq!(n(Line::Verify, &after), Some(3));
        assert_eq!(n(Line::Undo, &after), Some(4));
        assert_eq!(n(Line::Report, &after), Some(5));
        // 깨끗한 PC — 치료만 있다.
        let clean = offer(true, false);
        assert_eq!(n(Line::Treat, &clean), Some(1));
        for l in [Line::Verify, Line::Undo, Line::Report] {
            assert_eq!(n(l, &clean), None);
        }
        // 찾기만 하는 룰 · 기록 있음 — 검사만 1 · 복원 2 · 신고 3.
        let mut detect = offer(true, true);
        detect.detect_only = true;
        assert_eq!(n(Line::Treat, &detect), None);
        assert_eq!(n(Line::Undo, &detect), Some(2));
        assert_eq!(n(Line::Report, &detect), Some(3));
        // 룰 없이 기록만 — 복원 1 · 신고 2.
        assert_eq!(n(Line::Undo, &offer(false, true)), Some(1));
        assert_eq!(n(Line::Treat, &offer(false, true)), None);
    }

    /// 치료하는 룰에서 **1 · 2번은 늘 그 둘이다** — README 4단계와 팀원 피드백 문안이 그 번호를 적는다.
    #[test]
    fn treat_and_scan_keep_their_numbers_in_every_state() {
        for runs in [false, true] {
            for unfinished in [false, true] {
                for locked in [false, true] {
                    let o = Offer {
                        runs_locked: locked,
                        ..state(true, runs, unfinished)
                    };
                    assert_eq!(main_labels(&o)[..2], [TREAT, SCAN]);
                }
            }
        }
    }

    /// 기준 1(d) — 그만두기 줄에 명령 안내를 적지 않는다. 명령줄을 쓸 사람의 안내는 더 보기의 머리말이다.
    #[test]
    fn the_quit_line_does_not_teach_commands() {
        for lang in [Lang::Ko, Lang::En] {
            assert!(!super::quit_label(lang).contains("--help"));
            assert!(super::more_head(lang).contains("remedy --help"));
        }
    }

    /// 찾기만 하는 룰 — 더 보기의 *승인한 계획을 수행하기* 는 계획이 있어도 그 까닭을 단다. 플러그인이
    /// 없다는 까닭이 먼저다.
    #[test]
    fn a_detect_only_rule_does_not_offer_treatment() {
        let apply = |o: &Offer| -> Option<&'static str> {
            screens(o, Lang::Ko)
                .more
                .into_iter()
                .flat_map(|g| g.items)
                .find(|i| match i.tag {
                    Tag::NeedsFile(_, mk) => {
                        matches!(mk(std::path::PathBuf::new()), WithFile::Apply(_))
                    }
                    _ => false,
                })
                .expect("계획 수행 줄")
                .off
        };
        let mut o = offer(true, true);
        o.files.insert(
            Candidates::Plans,
            vec![std::path::PathBuf::from("plan.json")],
        );
        assert_eq!(apply(&o), None);
        o.detect_only = true;
        assert_eq!(apply(&o), Some("이 룰은 찾기만 하고 치료하지 않습니다"));
        let mut none = offer(false, false);
        none.detect_only = true;
        assert_eq!(apply(&none), Some("쓸 수 있는 플러그인 번들이 없습니다"));
    }

    /// 치료가 유지됐는지는 **치료한 기록이 있어야** 묻는다 — 없을 때 고르면 치료한 적 없는
    /// 기계에 *"치료 성공"* 이 떴다(v1.1.0 적대적 검토 · 2026-11-07 실측). 이제는 그 줄이 서지 않는다.
    #[test]
    fn verify_needs_a_treatment_record() {
        assert!(!main_labels(&offer(true, false)).contains(&VERIFY));
        assert!(main_labels(&offer(true, true)).contains(&VERIFY));
    }

    /// 메뉴 줄이 부르는 명령 — `main.rs` 의 분기 낱말로.
    fn command(t: &Tag) -> &'static str {
        let p = std::path::PathBuf::from("x");
        match t {
            Tag::NeedsPlugin(mk) => match mk(p) {
                WithPlugin::Run(_) => "run",
                WithPlugin::Scan(_) => "scan",
                WithPlugin::Verify(_) => "verify",
                WithPlugin::Lint(_) => "plugin lint",
                WithPlugin::VerifyBundle(_) => "plugin verify",
            },
            Tag::NeedsRun(mk) | Tag::NeedsUnfinished(mk) => match mk(a_run("r")) {
                WithRun::Restore(_) => "restore",
                WithRun::Support(_) => "support-bundle",
                WithRun::Resume(_) => "resume",
            },
            Tag::NeedsFile(_, mk) => match mk(p) {
                WithFile::Apply(_) => "apply",
                WithFile::Evaluate(_) => "evaluate",
                WithFile::Plan(_) => "plan",
                WithFile::AllowVerify(_) => "allowlist verify",
                WithFile::AllowImport(_) => "allowlist import",
                WithFile::RevokeVerify(_) => "revocation verify",
                WithFile::RevokeImport(_) => "revocation import",
            },
            Tag::Collect => "collect",
            Tag::Plain(Plain::SelfTest) => "selftest",
            Tag::Plain(Plain::Version) => "--version",
            Tag::Plain(Plain::Help) => "--help",
            Tag::Plain(Plain::HelpAll) => "--help-all",
            Tag::Plain(Plain::RestoreList) => "restore",
        }
    }

    /// 기본 화면의 여섯은 **받은 사람의 일**이고 검사 · 치료가 맨 위다 — 받아서 띄운 사람의 목적이
    /// 그것이고, 번호 1 이 그 뜻이다. 이어서 하기만 끝나지 않은 회차를 묻는다.
    #[test]
    fn the_main_lines_are_the_users_six_and_treat_is_first() {
        let cmds: Vec<&str> = MAIN_ITEMS
            .iter()
            .map(|(_, _, m)| command(&m.tag()))
            .collect();
        assert_eq!(
            cmds,
            [
                "run",
                "scan",
                "verify",
                "restore",
                "support-bundle",
                "resume"
            ]
        );
        assert_eq!(MAIN_ITEMS[0].2, Main::Treat);
        assert!(matches!(Main::Resume.tag(), Tag::NeedsUnfinished(_)));
        assert!(matches!(Main::Restore.tag(), Tag::NeedsRun(_)));
    }

    /// 파일이 드는 일곱이다. 넷은 목록(`*.signed`)이고 셋은 결과 폴더의 산출물이다.
    #[test]
    fn group_de_carries_seven_commands() {
        assert_eq!(FILE_ITEMS.len(), 7);
        let f = std::path::PathBuf::from("x");
        let made: Vec<WithFile> = FILE_ITEMS.iter().map(|(_, _, _, m)| m(f.clone())).collect();
        assert_eq!(
            made,
            vec![
                WithFile::Apply(f.clone()),
                WithFile::Evaluate(f.clone()),
                WithFile::Plan(f.clone()),
                WithFile::AllowVerify(f.clone()),
                WithFile::AllowImport(f.clone()),
                WithFile::RevokeVerify(f.clone()),
                WithFile::RevokeImport(f),
            ]
        );
    }

    /// **후보를 가리는 규칙이 섞이지 않는가.** `plan.json` 이 `scan*` 에 걸리거나
    /// 그 반대가 되면 메뉴가 엉뚱한 파일을 고르게 한다.
    #[test]
    fn candidate_patterns_do_not_overlap() {
        let cases = [
            ("plan.json", Candidates::Plans),
            ("plan-run-1.json", Candidates::Plans),
            ("scan.json", Candidates::Scans),
            ("artifacts.json", Candidates::Artifacts),
            ("allow.signed", Candidates::Lists),
        ];
        for (name, want) in cases {
            for c in [
                Candidates::Plans,
                Candidates::Artifacts,
                Candidates::Scans,
                Candidates::Lists,
            ] {
                assert_eq!(c.matches(name), c == want, "{name} 이 {c:?} 에 잘못 걸린다");
            }
        }
        // 엉뚱한 것은 어디에도 안 걸린다.
        for c in [
            Candidates::Plans,
            Candidates::Artifacts,
            Candidates::Scans,
            Candidates::Lists,
        ] {
            assert!(!c.matches("remedy.exe"), "{c:?}");
            assert!(!c.matches("README.txt"), "{c:?}");
            assert!(!c.matches("plugin.yaml"), "{c:?}");
        }
    }

    /// **후보 파일만 있어도 메뉴를 연다** — 목록을 반입하려는 운영자가 꾸러미
    /// 없이 올 수 있다. 그리고 셋이 다 비면 열지 않는다(시연 1단계).
    #[test]
    fn files_alone_are_enough_to_open_the_menu() {
        let mut o = offer(false, false);
        assert!(o.is_empty());
        o.files.insert(
            Candidates::Lists,
            vec![std::path::PathBuf::from("a.signed")],
        );
        assert!(!o.is_empty());
    }

    /// 이름이 비어 있으면 번호만 남은 줄이 된다.
    #[test]
    fn every_item_has_a_label() {
        let filled = |k: &str, e: &str| !k.trim().is_empty() && !e.trim().is_empty();
        assert!(MAIN_ITEMS.iter().all(|(k, e, _)| filled(k, e)));
        assert!(GROUPS.iter().all(|(k, e)| filled(k, e)));
        assert!(filled(RECORD_ITEM.0, RECORD_ITEM.1));
        assert!(PROGRAM_ITEMS.iter().all(|(k, e, _)| filled(k, e)));
        assert!(AUTHOR_ITEMS.iter().all(|(k, e, _)| filled(k, e)));
        assert!(FILE_ITEMS.iter().all(|(k, e, _, _)| filled(k, e)));
    }
}
