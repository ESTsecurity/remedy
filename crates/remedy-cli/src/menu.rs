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
//! # 묶음으로 나눈다
//!
//! 명령 표면은 **20개**(최상위 14 + 하위 6)이고 메뉴 줄은 21개다(`restore` 가
//! 목록 보기와 되돌리기 둘). 입력이 무엇이냐로 묶고, 작성자·운영자용은 뒤에 둔다.
//!
//! | 묶음 | 입력 | 그 입력이 없을 때 줄에 다는 까닭 |
//! |---|---|---|
//! | A | 없다 — 바로 돈다 | — (목록 보기만 회차가 든다) |
//! | B | 옆 폴더의 플러그인 | 쓸 수 있는 플러그인 번들이 없습니다 |
//! | C | 복원 정보 폴더의 회차 | 이 PC 에 치료한 기록이 없습니다 |
//! | D | 결과 폴더의 계획 · 수집 결과 · 평가 결과 | out 폴더에 … 이 없습니다 |
//! | E | 실행 파일 옆의 서명된 목록 (작성자·운영자) | 실행 파일 옆에 … 이 없습니다 |
//!
//! # 늘 전부 선다 — 못 고르는 줄은 까닭과 함께 (목표 remedy_제품화 기준 5)
//!
//! 줄은 기계 상태와 상관없이 **같은 차례 · 같은 번호**로 선다. 지금 입력이 없는 줄은
//! 흐리게 그리고 까닭을 단다 — 고르기는 그 줄을 받지 않는다([`items`]). 줄이
//! 창보다 높으면 방향키 화면은 번호 줄만 창 안에서 넘긴다(`term::view`).
//!
//! # 작성자·운영자 명령은 접는다 (목표 remedy_출시_20261111 기준 4)
//!
//! 첫 화면은 일반 작업 열셋과 *작성자·운영자 명령 보기* 한 줄이다 — 그 줄을 고르면 나머지
//! 여덟이 한 화면 더 선다. 스물한 줄이 한 화면에 서던 때는 처음 온 사람이 무엇을 누를지
//! 몰랐다. 명령 전부에 **닿는다**는 것은 그대로다(`every_command_has_a_menu_line`).
//!
//! 찾기만 하는 룰(`remediate` 가 없다)에서는 치료를 약속하는 줄 — 검사하고 치료하기 ·
//! 치료가 유지됐는지 다시 보기 · 승인한 계획을 수행하기 — 이 까닭을 달고 흐리게 선다.
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
    /// 묶음 B — 고른 플러그인으로 무엇을 한다.
    NeedsPlugin(MakeWithPlugin),
    /// 묶음 C — 회차를 한 번 더 물어야 한다.
    NeedsRun(MakeWithRun),
    /// 묶음 D·E — 파일을 한 번 더 물어야 한다.
    NeedsFile(Candidates, MakeWithFile),
    /// 입력이 없는 수집.
    Collect,
    /// 묶음 A — 그대로 돈다.
    Plain(Plain),
}

struct Item {
    label: &'static str,
    tag: Tag,
    /// 지금 고를 수 없으면 그 까닭. 줄은 그래도 선다(목표 remedy_제품화 기준 5).
    off: Option<&'static str>,
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
    /// 복원 정보 폴더에서 읽은 회차 — **이름순.** 비어 있으면 회차 줄은 까닭을 달고 흐리게 선다.
    pub runs: Vec<Run>,
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
        self.plugin.is_none() && self.runs.is_empty() && self.files.is_empty()
    }

    fn has_runs(&self) -> bool {
        !self.runs.is_empty()
    }

    fn files_of(&self, c: Candidates) -> &[std::path::PathBuf] {
        self.files.get(&c).map_or(&[], Vec::as_slice)
    }
}

/// 고른 회차를 명령으로 만드는 함수 — [`RUN_ITEMS`] 의 세 번째 칸.
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

/// 고른 플러그인을 명령으로 만드는 함수 — [`PLUGIN_ITEMS`] 의 세 번째 칸.
type MakeWithPlugin = fn(std::path::PathBuf) -> WithPlugin;

/// 플러그인이 드는 명령 다섯 — 묶음 B. **검사·치료가 맨 위다** — 꾸러미를 받아서
/// 띄운 사람의 목적이 그것이다. 작성자용 둘(`lint`·`plugin verify`)은 아래.
const PLUGIN_ITEMS: &[(&str, &str, MakeWithPlugin)] = &[
    ("검사하고 치료하기", "Scan and treat", WithPlugin::Run),
    (
        "검사만 하기 (아무것도 바꾸지 않습니다)",
        "Scan only (changes nothing)",
        WithPlugin::Scan,
    ),
    (
        "치료가 유지됐는지 다시 보기",
        "Re-check that the treatment held",
        WithPlugin::Verify,
    ),
    (
        "이 플러그인 번들이 우리 것인지 확인",
        "Verify this plugin bundle",
        WithPlugin::VerifyBundle,
    ),
    (
        "룰 검사 (작성자용)",
        "Lint the rule (for authors)",
        WithPlugin::Lint,
    ),
];

/// 회차가 드는 명령 셋 — 묶음 C. (한국어 · 영어 · 무엇이 되는가)
const RUN_ITEMS: &[(&str, &str, MakeWithRun)] = &[
    ("치료를 되돌리기", "Undo a treatment", WithRun::Restore),
    (
        "신고에 붙일 것 모으기",
        "Collect what to attach to a report",
        WithRun::Support,
    ),
    (
        "중단된 작업 이어서 하기",
        "Resume an interrupted run",
        WithRun::Resume,
    ),
];

/// 묶음 A — 입력이 없어 어느 기계에서나 뜻이 있다.
const PLAIN_ITEMS: &[(&str, Plain)] = &[
    ("이 PC 에서 되돌릴 수 있는 것 보기", Plain::RestoreList),
    ("프로그램 자체 점검", Plain::SelfTest),
    ("판 보기", Plain::Version),
    ("쓰는 법", Plain::Help),
    ("모든 명령과 옵션", Plain::HelpAll),
];

const PLAIN_ITEMS_EN: &[(&str, Plain)] = &[
    ("Show what can be undone on this PC", Plain::RestoreList),
    ("Self-test", Plain::SelfTest),
    ("Version", Plain::Version),
    ("How to use", Plain::Help),
    ("Every command and option", Plain::HelpAll),
];

/// 메뉴에 설 줄 전부 — **명령 스무 개가 늘 같은 차례 · 같은 번호로 선다**(목표
/// remedy_제품화 기준 5 · 벤치마크 축 3). 둘째 값은 작성자·운영자 묶음이 시작하는 자리다.
///
/// 전에는 지금 고를 수 없는 줄을 아예 내지 않았다 — 고르면 *"없습니다"* 가 나오는
/// 줄을 두면 사용자가 자기가 잘못한 것으로 읽기 때문이었다. 그 걱정은 **까닭을 줄에
/// 다는 것**으로 푼다: 무엇이 어디에 없어서 못 고르는지가 줄에 보이고, 그 줄은 고르기가
/// 받지 않는다(`term::Row::Off`). 숨기면 받은 사람이 그 기능이 있는지조차 모르고,
/// 번호가 기계 상태마다 움직인다('전' 이미지에서 10 → 17).
///
/// 작성자·운영자 명령은 **뒤에 둔다** — `--help-all` 이 *"플러그인 작성자와 운영자가
/// 보는 자리이고 고객 화면이 아니다"* 라고 스스로 적어 둔 것과 같은 선이다.
fn items(offer: &Offer, lang: remedy_sdk::i18n::Lang) -> (Vec<Item>, usize) {
    let ko = lang == remedy_sdk::i18n::Lang::Ko;
    let no_plugin = offer.plugin.is_none().then(|| {
        lang.t(
            "쓸 수 있는 플러그인 번들이 없습니다",
            "no usable plugin bundle",
        )
    });
    let no_runs = (!offer.has_runs()).then(|| {
        lang.t(
            "이 PC 에 치료한 기록이 없습니다",
            "no treatment on this PC yet",
        )
    });
    // 찾기만 하는 룰 — 치료를 약속하는 줄은 까닭을 단다. 플러그인이 없다는 까닭이 먼저다.
    let detect_only = (offer.detect_only && no_plugin.is_none()).then(|| {
        lang.t(
            "이 룰은 찾기만 하고 치료하지 않습니다",
            "this rule only detects; it does not treat",
        )
    });
    let p = std::path::PathBuf::new();
    let mut items: Vec<Item> = Vec::new();

    // ── 묶음 B — 플러그인이 드는 다섯 ──────────────────────────
    for (k, e, mk) in PLUGIN_ITEMS {
        let treats = matches!(mk(p.clone()), WithPlugin::Run(_) | WithPlugin::Verify(_));
        items.push(Item {
            label: if ko { k } else { e },
            tag: Tag::NeedsPlugin(*mk),
            off: no_plugin.or(if treats { detect_only } else { None }),
        });
    }

    // ── 묶음 C — 회차가 드는 셋 ─────────────────────────────────
    for (k, e, mk) in RUN_ITEMS {
        items.push(Item {
            label: if ko { k } else { e },
            tag: Tag::NeedsRun(*mk),
            off: no_runs,
        });
    }

    // ── 묶음 A — 입력이 없는 다섯 ───────────────────────────────
    for (label, p) in if ko { PLAIN_ITEMS } else { PLAIN_ITEMS_EN } {
        items.push(Item {
            label,
            tag: Tag::Plain(*p),
            off: if *p == Plain::RestoreList {
                no_runs
            } else {
                None
            },
        });
    }

    // ── 작성자·운영자 명령 — 묶음 D·E ───────────────────────────
    let author_from = items.len();
    items.push(Item {
        label: lang.t(
            "수집만 하기 (평가는 사내에서)",
            "Collect only (evaluate in-house)",
        ),
        tag: Tag::Collect,
        off: no_plugin,
    });
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
        items.push(Item {
            label: if ko { k } else { e },
            tag: Tag::NeedsFile(*cand, *mk),
            off,
        });
    }
    (items, author_from)
}

/// 작업 뒤의 *다음 할 일* 이 가리키는 메뉴 줄(목표 remedy_제품화 기준 6(d)).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Line {
    /// 검사하고 치료하기
    Treat,
    /// 치료가 유지됐는지 다시 보기
    Verify,
    /// 치료를 되돌리기
    Undo,
    /// 신고에 붙일 것 모으기
    Report,
    /// 중단된 작업 이어서 하기
    Resume,
    /// 승인한 계획을 수행하기
    Apply,
}

/// 그 줄의 번호와 이름. 번호는 기계 상태와 상관없다([`items`]) — 안내에 적은 번호가
/// 다음 메뉴에서도 그 줄이다. 접어 둔 줄은 **두 걸음으로** 적는다 — 첫 화면의 번호와
/// 그 아래 화면의 번호(`14. 작성자·운영자 명령 보기 → 2. 승인한 계획을 수행하기`).
pub fn line(which: Line) -> Option<(usize, String)> {
    let p = std::path::PathBuf::new();
    let run = Run {
        id: String::new(),
        state: p.clone(),
    };
    let probe = Offer {
        plugin: Some(p.clone()),
        detect_only: false,
        name: None,
        runs: Vec::new(),
        files: std::collections::BTreeMap::new(),
    };
    let lang = ui().lang;
    let (all, author_from) = items(&probe, lang);
    let pos = all.iter().position(|it| match (&it.tag, which) {
        (Tag::NeedsPlugin(mk), Line::Treat) => matches!(mk(p.clone()), WithPlugin::Run(_)),
        (Tag::NeedsPlugin(mk), Line::Verify) => matches!(mk(p.clone()), WithPlugin::Verify(_)),
        (Tag::NeedsRun(mk), Line::Undo) => matches!(mk(run.clone()), WithRun::Restore(_)),
        (Tag::NeedsRun(mk), Line::Report) => matches!(mk(run.clone()), WithRun::Support(_)),
        (Tag::NeedsRun(mk), Line::Resume) => matches!(mk(run.clone()), WithRun::Resume(_)),
        (Tag::NeedsFile(_, mk), Line::Apply) => matches!(mk(p.clone()), WithFile::Apply(_)),
        _ => false,
    })?;
    if pos < author_from {
        return Some((pos + 1, all[pos].label.to_string()));
    }
    Some((
        author_from + 1,
        format!(
            "{} {} {}. {}",
            author_label(lang),
            remedy_sdk::i18n::deco().arrow(),
            pos - author_from + 1,
            all[pos].label
        ),
    ))
}

/// 첫 화면의 마지막 줄 — 접어 둔 작성자·운영자 명령을 연다.
fn author_label(lang: remedy_sdk::i18n::Lang) -> &'static str {
    lang.t(
        "작성자·운영자 명령 보기",
        "Commands for authors and operators",
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
    let (items, author_from) = items(offer, lang);

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
    // 작성자·운영자 명령은 접어 둔다 — 마지막 한 줄이 그 화면을 연다(기준 4).
    rows.extend(rows_of(&items[..author_from]));
    rows.push(Row::Item(author_label(lang).to_string()));
    let zero = lang.t(
        "그만두기 (명령으로 쓰려면 remedy --help)",
        "Quit (for commands, run remedy --help)",
    );

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

    // 접어 둔 화면의 `0` 은 **이 메뉴로** 돌아온다 — 룰을 고르는 화면까지 물러나지 않는다.
    let it = loop {
        let n = match crate::term::choose(&rows, Some(zero)) {
            Answer::Num(0) | Answer::Invalid => return quit(),
            Answer::End => return Pick::End,
            Answer::Num(n) => n,
        };
        if n <= author_from {
            break &items[n - 1];
        }
        match choose_author(&items[author_from..]) {
            Sub::Got(i) => break &items[author_from + i],
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

/// 접어 둔 작성자·운영자 명령 — 고른 줄의 차례(0 부터)를 돌려준다.
fn choose_author(list: &[Item]) -> Sub<usize> {
    let lang = ui().lang;
    let mut rows = vec![
        Row::Blank,
        Row::Text(
            lang.t(
                "작성자·운영자 명령 — 룰을 만들거나 조직의 목록을 다루는 사람이 씁니다:",
                "Commands for authors and operators - for people who write rules or manage org lists:",
            )
            .to_string(),
        ),
    ];
    rows.extend(rows_of(list));
    let at: Vec<usize> = (0..list.len()).collect();
    sub_answer(crate::term::choose(&rows, Some(back_label())), &at)
}

/// 머리말의 권한 줄. 재지 못했으면 내지 않는다 — 모르는 것을 말하지 않는다.
fn privilege_line(lang: remedy_sdk::i18n::Lang) -> Option<String> {
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
        items, Candidates, Offer, Plain, Run, Tag, WithFile, WithPlugin, WithRun, FILE_ITEMS,
        PLAIN_ITEMS, PLAIN_ITEMS_EN, PLUGIN_ITEMS, RUN_ITEMS,
    };

    fn offer(plugin: bool, runs: bool) -> Offer {
        Offer {
            plugin: plugin.then(|| std::path::PathBuf::from("p.yaml")),
            detect_only: false,
            name: None,
            runs: if runs {
                vec![Run {
                    id: "run-1".into(),
                    state: std::path::PathBuf::from("s"),
                }]
            } else {
                Vec::new()
            },
            files: std::collections::BTreeMap::new(),
        }
    }

    /// **이것이 오늘의 시연을 지키는 규칙이다.** 내놓을 것이 없으면 메뉴를 열지
    /// 않는다 — 시연 1단계가 인자 없이 부르고 게이트가 *"사용법 다섯 줄"* 을
    /// 판정한다. 데모 폴더는 플러그인도 회차도 없다.
    #[test]
    fn nothing_to_offer_is_not_a_menu() {
        assert!(offer(false, false).is_empty());
        assert!(!offer(true, false).is_empty());
        assert!(!offer(false, true).is_empty());
        assert!(!offer(true, true).is_empty());
    }

    /// 묶음 A 는 **입력이 없는 명령 다섯**이다. 수가 줄면 메뉴에서 고를 수 있는
    /// 명령이 줄었다는 뜻이고, 그것은 완료 기준 1 의 분자다.
    #[test]
    fn group_a_carries_five_commands() {
        assert_eq!(PLAIN_ITEMS.len(), 5, "{PLAIN_ITEMS:?}");
        assert_eq!(PLAIN_ITEMS_EN.len(), PLAIN_ITEMS.len());
    }

    /// 두 언어가 **같은 명령을 같은 차례로** 낸다. 어긋나면 한 언어로 돌린
    /// 사람만 다른 줄을 고른다 — 번호가 뜻을 잃는다.
    #[test]
    fn both_languages_offer_the_same_commands_in_the_same_order() {
        let ko: Vec<Plain> = PLAIN_ITEMS.iter().map(|(_, p)| *p).collect();
        let en: Vec<Plain> = PLAIN_ITEMS_EN.iter().map(|(_, p)| *p).collect();
        assert_eq!(ko, en);
    }

    /// 묶음 C 는 **회차가 드는 셋**이다. 완료 기준 1 의 분자 넷 중 셋이 여기다
    /// (`restore --list` 는 묶음 A).
    #[test]
    fn group_c_carries_three_commands() {
        assert_eq!(RUN_ITEMS.len(), 3);
        let r = Run {
            id: "r".into(),
            state: std::path::PathBuf::from("s"),
        };
        let made: Vec<WithRun> = RUN_ITEMS.iter().map(|(_, _, f)| f(r.clone())).collect();
        assert_eq!(
            made,
            vec![
                WithRun::Restore(r.clone()),
                WithRun::Support(r.clone()),
                WithRun::Resume(r.clone())
            ]
        );
    }

    /// **회차가 없으면 묶음 C 와 목록 보기는 까닭을 달고 흐리게 선다** — 숨기지 않는다.
    /// 고르면 "없습니다" 가 나오는 줄을 그냥 두면 사용자가 자기가 잘못한 것으로 읽으므로,
    /// 까닭이 줄에 보이고 고르기가 그 줄을 받지 않는다.
    #[test]
    fn no_runs_turns_run_items_off_with_a_reason() {
        let ko = remedy_sdk::i18n::Lang::Ko;
        let needs_run = |t: &Tag| matches!(t, Tag::NeedsRun(_) | Tag::Plain(Plain::RestoreList));
        let (none, _) = items(&offer(true, false), ko);
        let (some, _) = items(&offer(true, true), ko);
        for it in none.iter().filter(|i| needs_run(&i.tag)) {
            assert_eq!(
                it.off,
                Some("이 PC 에 치료한 기록이 없습니다"),
                "{}",
                it.label
            );
        }
        assert!(some
            .iter()
            .filter(|i| needs_run(&i.tag))
            .all(|i| i.off.is_none()));
        assert_eq!(none.iter().filter(|i| needs_run(&i.tag)).count(), 4);
    }

    /// 기준 5 — **명령 전수(`main.rs` 분기)와 메뉴를 맞댄다.** 분기에 명령을 더하고
    /// 메뉴에 줄을 더하지 않으면 여기서 깨진다. 분기는 `let outcome = match cmd {` 부터
    /// 인자 없는 `None =>` 까지이고, 들여쓰기 여덟 칸이 명령 · 열두 칸이 하위 명령이다.
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

        let (all, _) = items(&offer(true, false), remedy_sdk::i18n::Lang::Ko);
        let shown: std::collections::BTreeSet<String> =
            all.iter().map(|i| command(&i.tag).to_string()).collect();
        assert_eq!(shown, dispatched, "메뉴에 없는 명령 · 분기에 없는 줄");
    }

    /// 기준 5(a) — **새로 받은 꾸러미의 메뉴**(플러그인만 있고 회차 · 결과 파일이 없다)에
    /// 스물한 줄이 다 서고(여덟은 접은 화면에), 지금 못 고르는 열한 줄은 까닭을 단다.
    #[test]
    fn a_fresh_bundle_shows_every_line_and_says_why() {
        for lang in [remedy_sdk::i18n::Lang::Ko, remedy_sdk::i18n::Lang::En] {
            let (all, _) = items(&offer(true, false), lang);
            assert_eq!(all.len(), 21);
            assert_eq!(all.iter().filter(|i| i.off.is_none()).count(), 10);
            assert!(all.iter().all(|i| i.off.is_none_or(|w| !w.is_empty())));
        }
    }

    /// **번호가 기계 상태마다 움직이지 않는다** — 플러그인 · 회차가 있든 없든 줄 차례가
    /// 같다('전' 이미지에서 회차가 생기자 10 → 17 로 바뀌었다).
    #[test]
    fn numbers_do_not_move_with_state() {
        let ko = remedy_sdk::i18n::Lang::Ko;
        let labels = |o: &Offer| -> Vec<&str> { items(o, ko).0.iter().map(|i| i.label).collect() };
        let base = labels(&offer(true, false));
        for (p, r) in [(true, true), (false, true), (false, false)] {
            assert_eq!(labels(&offer(p, r)), base, "플러그인 {p} · 치료 기록 {r}");
        }
    }

    /// 기준 6(d) — *다음 할 일* 이 적는 번호가 메뉴의 그 줄이다(번호는 상태와 상관없다).
    /// 접어 둔 줄은 첫 화면의 *작성자·운영자 명령 보기* 번호와 그 아래 화면의 번호로 적는다.
    #[test]
    fn next_step_lines_point_at_fixed_numbers() {
        use super::{line, Line};
        let n = |l| line(l).map(|(n, _)| n);
        assert_eq!(n(Line::Treat), Some(1));
        assert_eq!(n(Line::Verify), Some(3));
        assert_eq!(n(Line::Undo), Some(6));
        assert_eq!(n(Line::Report), Some(7));
        assert_eq!(n(Line::Resume), Some(8));
        assert_eq!(n(Line::Apply), Some(14));
        // 화면 언어는 시험을 돌리는 기계를 따른다 — 두 언어 다 받는다.
        let (_, apply) = line(Line::Apply).expect("승인한 계획을 수행하기");
        assert!(
            apply.ends_with("2. 승인한 계획을 수행하기")
                || apply.ends_with("2. Apply an approved plan"),
            "{apply}"
        );
    }

    /// 기준 4 — **첫 화면은 일반 작업 열셋 + 접은 한 줄**이다. 나머지 여덟은 그 한 줄 아래에
    /// 있고, 명령 전부에 닿는 것은 `every_command_has_a_menu_line` 이 본다.
    #[test]
    fn the_first_screen_is_thirteen_lines_and_one_more() {
        let (all, author_from) = items(&offer(true, false), remedy_sdk::i18n::Lang::Ko);
        assert_eq!(author_from, 13, "일반 작업");
        assert_eq!(all.len() - author_from, 8, "접어 둔 작성자·운영자 명령");
        assert_eq!(super::rows_of(&all[..author_from]).count() + 1, 14);
    }

    /// 기준 4 — **찾기만 하는 룰에서는 치료를 약속하는 줄이 까닭을 달고 흐리게 선다.**
    /// 번호는 그대로다(줄을 빼지 않는다) — 안내에 적은 번호가 룰마다 바뀌면 안 된다.
    #[test]
    fn a_detect_only_rule_does_not_offer_treatment() {
        let ko = remedy_sdk::i18n::Lang::Ko;
        let mut o = offer(true, false);
        o.files.insert(
            Candidates::Plans,
            vec![std::path::PathBuf::from("plan.json")],
        );
        let treating = |o: &Offer| -> Vec<(&'static str, Option<&'static str>)> {
            items(o, ko).0.iter().map(|i| (i.label, i.off)).collect()
        };
        let before = treating(&o);
        o.detect_only = true;
        let after = treating(&o);
        let why = Some("이 룰은 찾기만 하고 치료하지 않습니다");
        for ((label, was), (same, now)) in before.iter().zip(&after) {
            assert_eq!(label, same, "번호가 움직였다");
            let promises = matches!(
                *label,
                "검사하고 치료하기" | "치료가 유지됐는지 다시 보기" | "승인한 계획을 수행하기"
            );
            if promises {
                assert_eq!(*was, None, "{label}");
                assert_eq!(*now, why, "{label}");
            } else {
                assert_eq!(was, now, "{label}");
            }
        }
        // 플러그인이 없다는 까닭이 먼저다.
        let mut none = offer(false, false);
        none.detect_only = true;
        assert!(items(&none, ko).0.iter().all(|i| i.off != why));
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
            Tag::NeedsRun(mk) => match mk(Run {
                id: "r".into(),
                state: p,
            }) {
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

    /// 묶음 B 는 **플러그인이 드는 다섯**이다. 검사·치료가 **맨 위**여야 한다 —
    /// 꾸러미를 받아서 띄운 사람의 목적이 그것이고, 번호 1 이 그 뜻이다.
    #[test]
    fn group_b_carries_five_commands_and_treat_is_first() {
        assert_eq!(PLUGIN_ITEMS.len(), 5);
        let p = std::path::PathBuf::from("p.yaml");
        let made: Vec<WithPlugin> = PLUGIN_ITEMS.iter().map(|(_, _, f)| f(p.clone())).collect();
        assert_eq!(
            made[0],
            WithPlugin::Run(p.clone()),
            "검사·치료가 맨 위가 아니다"
        );
        assert_eq!(
            made,
            vec![
                WithPlugin::Run(p.clone()),
                WithPlugin::Scan(p.clone()),
                WithPlugin::Verify(p.clone()),
                WithPlugin::VerifyBundle(p.clone()),
                WithPlugin::Lint(p),
            ]
        );
    }

    /// **메뉴가 내는 줄의 수.** 완료 기준 1 이 세는 것은 *명령* 이고 이 수는
    /// *줄* 이다 — 둘이 다른 이유는 `restore` 가 두 줄에 나뉘기 때문이다
    /// (`--list` 는 묶음 A, `--run` 은 묶음 C). 줄이 줄면 고를 수 있는 것이
    /// 줄었다는 뜻이므로 수로 잠근다.
    ///
    /// **줄 21 · 명령 20.** 묶음 B 5 + C 3 + A 5 + D·E 7 = 20 줄에 `수집만` 한
    /// 줄을 더해 21 이고, `restore` 가 두 줄이라 명령은 20 이다.
    #[test]
    fn the_menu_offers_twenty_one_lines() {
        assert_eq!(PLUGIN_ITEMS.len(), 5, "묶음 B");
        assert_eq!(RUN_ITEMS.len(), 3, "묶음 C");
        assert_eq!(PLAIN_ITEMS.len(), 5, "묶음 A");
        assert_eq!(FILE_ITEMS.len(), 7, "묶음 D·E");
        // `수집만` 은 상수 표에 없다(입력이 없어 항목이 하나뿐이다) — 그 한 줄을 더한다.
        assert_eq!(
            PLUGIN_ITEMS.len() + RUN_ITEMS.len() + PLAIN_ITEMS.len() + FILE_ITEMS.len() + 1,
            21
        );
    }

    /// 묶음 D·E 는 **파일이 드는 일곱**이다. 넷은 목록(`*.signed`)이고 셋은
    /// 결과 폴더의 산출물이다.
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
        for (label, p) in PLAIN_ITEMS.iter().chain(PLAIN_ITEMS_EN) {
            assert!(!label.trim().is_empty(), "{p:?}");
        }
        for (k, e, _) in RUN_ITEMS {
            assert!(!k.trim().is_empty() && !e.trim().is_empty());
        }
        for (k, e, _) in PLUGIN_ITEMS {
            assert!(!k.trim().is_empty() && !e.trim().is_empty());
        }
        for (k, e, _, _) in FILE_ITEMS {
            assert!(!k.trim().is_empty() && !e.trim().is_empty());
        }
    }
}
