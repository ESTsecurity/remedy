//! 화면 공통 층 — 그리는 자리의 판정 · 고르기 · Ctrl+C 두 번 (목표 remedy_제품화 ③).
//!
//! # 그리는가 — [`fancy`]
//!
//! **사람이 앞에 있고 그 화면이 VT 를 알아들을 때만** 이 층이 그린다. stdin ·
//! stdout 이 둘 다 터미널이고, `TERM` 이 `dumb` 이 아니고, `NO_COLOR` 가 없고,
//! Windows 에서는 콘솔의 VT 처리를 켤 수 있어야 한다. 하나라도 아니면 지금까지의
//! 글자 그대로다 — 이스케이프를 한 바이트도 내지 않는다(기준 3(b)). 파이프 · 파일로
//! 받는 출력은 바뀌지 않고(불변식 I1), stdout 을 파일로 받는 랩 메뉴 하네스도 지금
//! 글자를 읽는다.
//!
//! # 원시 모드는 고르는 동안만
//!
//! 목록에서 고르는 동안만 원시 모드로 키를 읽고 곧바로 되돌린다. 작업은 줄 입력
//! 모드에서 돈다 — 리눅스의 원시 모드는 출력 후처리를 꺼서 줄바꿈이 줄 처음으로
//! 돌아가지 않는다. 그래서 고르는 화면은 줄마다 `\r\n` 으로 쓴다.
//!
//! **다시 그리기는 화면 아래만 지운다**(`CSI J`). 스크롤백을 지우는 `CSI 3J` 와 스크롤
//! 영역은 쓰지 않는다 — 인라인 화면에서 스크롤백을 깨뜨린 사례가 둘 있다(벤치마크
//! 2026-11-05 · Gemini · Codex).
//!
//! # Ctrl+C — [`press`]
//!
//! 원시 모드에서는 키로, 줄 입력 모드에서는 신호로 온다. 두 길 모두 [`press`] 를
//! 지나 **정한 시간 안의 두 번째**에만 끝낸다(Claude Code · Gemini CLI · Copilot CLI
//! 의 결). 신호 처리기는 인자 없는 대화형 세션에만 건다([`arm`]) — 인자가 있는
//! 호출과 무인 회차는 지금처럼 한 번에 끝난다(기준 4(d)).

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use remedy_sdk::artifact::ExitCode as Code;

use crate::ui;

/// 두 번째 Ctrl+C 를 기다리는 시간. Copilot CLI 2초 · Gemini CLI 3초 가운데 짧은
/// 쪽이다 — 길면 한 번 누르고 한참 뒤에 누른 것까지 끝내기가 된다.
pub const DOUBLE_PRESS: Duration = Duration::from_millis(2000);

/// ESC. 글자로 적지 않는다 — 소스에 보이지 않는 바이트를 두지 않으려는 것이다.
const ESC: char = 27u8 as char;

const TASK_NONE: u8 = 0;
const TASK_READS: u8 = 1;
const TASK_CHANGES: u8 = 2;

static LAST_PRESS_MS: AtomicU64 = AtomicU64::new(0);
/// 지금 도는 작업 — 없음 · 읽기만 · 시스템을 변경한다. 강제로 끝낼 때의 종료 코드를 정한다.
static TASK: AtomicU8 = AtomicU8::new(TASK_NONE);
/// 끝난 작업의 종료 코드. 음수면 이 세션에서 아직 작업이 없다.
static LAST_CODE: AtomicI32 = AtomicI32::new(-1);
/// 이 세션에서 시작한 작업의 차례 — 작업마다 하나씩 는다. 작업 하나에 결과 폴더
/// 하나를 주는 데 쓴다(`main::menu_out`).
static TASK_SEQ: AtomicU64 = AtomicU64::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
static FANCY: OnceLock<bool> = OnceLock::new();

/// 이 층이 그리는가. 한 번 정하면 프로세스 끝까지 같다.
pub fn fancy() -> bool {
    *FANCY.get_or_init(|| {
        decide(
            std::io::stdin().is_terminal(),
            std::io::stdout().is_terminal(),
            term_ok(std::env::var("TERM").ok().as_deref()),
            std::env::var_os("NO_COLOR").as_deref(),
            vt_ready,
        )
    })
}

/// 조건 넷을 값으로 판정한다. **VT 는 마지막에 묻는다** — Windows 에서 그 물음이
/// 콘솔 모드를 바꾸므로, 파이프로 받는 회차에서는 묻지도 않는다.
fn decide(
    stdin_tty: bool,
    stdout_tty: bool,
    term_ok: bool,
    no_color: Option<&std::ffi::OsStr>,
    vt: impl FnOnce() -> bool,
) -> bool {
    stdin_tty && stdout_tty && term_ok && no_color.is_none_or(|v| v.is_empty()) && vt()
}

/// Windows 콘솔은 `TERM` 을 두지 않는다 — `dumb` 만 아니면 VT 판정에 맡긴다.
#[cfg(windows)]
fn term_ok(term: Option<&str>) -> bool {
    term != Some("dumb")
}

/// 리눅스는 **`TERM` 이 있어야** 그린다. 없으면 무엇을 알아듣는 화면인지 모른다 —
/// 컨테이너 안의 pty(`docker run` 에 `-t` 가 없을 때 · 기준선 캡처의 `script`)가 그렇다.
#[cfg(not(windows))]
fn term_ok(term: Option<&str>) -> bool {
    term.is_some_and(|t| !t.is_empty() && t != "dumb")
}

#[cfg(windows)]
fn vt_ready() -> bool {
    crossterm::ansi_support::supports_ansi()
}

#[cfg(not(windows))]
fn vt_ready() -> bool {
    true
}

// ── Ctrl+C ──────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    // 0 은 "누른 적 없음" 이라 1 부터 센다.
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX) + 1
}

/// Ctrl+C 한 번. 정한 시간 안의 두 번째면 `true` — 끝낸다.
pub fn press() -> bool {
    let now = now_ms();
    second_press(LAST_PRESS_MS.swap(now, Ordering::SeqCst), now)
}

fn second_press(prev: u64, now: u64) -> bool {
    let window = u64::try_from(DOUBLE_PRESS.as_millis()).unwrap_or(u64::MAX);
    prev != 0 && now.saturating_sub(prev) <= window
}

/// 대화형 세션의 Ctrl+C 처리기를 건다 — 한 번만.
///
/// **자식 도구도 지킨다.** 콘솔의 Ctrl+C 는 같은 콘솔의 프로세스 전부에 간다. 이
/// 프로세스는 처리기로 버텨도 치료 중에 띄운 도구(`sc.exe` · `systemctl` …)는 첫
/// 번째에 끝나 버린다. 그래서 세션 동안 도구를 새 프로세스 그룹으로 띄우게 한다.
pub fn arm() {
    if ARMED.swap(true, Ordering::SeqCst) {
        return;
    }
    remedy_core::platform::shield_from_ctrl_c(true);
    let _ = ctrlc::set_handler(|| {
        if press() {
            let _ = crossterm::terminal::disable_raw_mode();
            if fancy() {
                print!("{ESC}[?25h");
            }
            eprintln!();
            std::process::exit(i32::from(forced_exit_code()));
        }
        eprintln!();
        let hint = hint_again(TASK.load(Ordering::SeqCst) != TASK_NONE);
        eprintln!("{}", crate::tee::ascii_safe(hint));
    });
}

/// 사람이 앞에 있는 메뉴 세션인가 — 신호 처리기를 건 세션이 곧 그것이다([`arm`]).
/// 인자를 준 명령줄 호출에서는 늘 거짓이다.
pub fn in_session() -> bool {
    ARMED.load(Ordering::SeqCst)
}

/// 작업 하나가 시작한다. `changes_system` 은 강제로 끝날 때의 종료 코드를 가른다.
pub fn task_begin(changes_system: bool) {
    let t = if changes_system {
        TASK_CHANGES
    } else {
        TASK_READS
    };
    TASK.store(t, Ordering::SeqCst);
    TASK_SEQ.fetch_add(1, Ordering::SeqCst);
}

/// 지금 작업의 차례 — 작업이 시작할 때마다 바뀐다.
pub fn task_seq() -> u64 {
    TASK_SEQ.load(Ordering::SeqCst)
}

/// 작업 하나가 끝났다.
pub fn task_end(code: Code) {
    TASK.store(TASK_NONE, Ordering::SeqCst);
    LAST_CODE.store(i32::from(code.code()), Ordering::SeqCst);
}

/// 이 세션에서 작업이 하나라도 끝났는가.
pub fn tasks_ran() -> bool {
    LAST_CODE.load(Ordering::SeqCst) >= 0
}

/// Ctrl+C 두 번으로 끝낼 때의 종료 코드. **새 코드를 만들지 않는다**(불변식 I3) —
/// 시스템을 바꾸던 작업이 끊기면 부분(3), 읽기만 하던 작업이 끊기면 "위협 없음" 을
/// 말할 수 없음(6), 작업 사이라면 마지막 작업의 코드다.
fn forced_exit_code() -> u8 {
    exit_code_for(
        TASK.load(Ordering::SeqCst),
        LAST_CODE.load(Ordering::SeqCst),
    )
}

fn exit_code_for(task: u8, last: i32) -> u8 {
    match task {
        TASK_CHANGES => Code::PartialFailure.code(),
        TASK_READS => Code::IncompleteObservation.code(),
        _ => u8::try_from(last).unwrap_or(Code::NoThreat.code()),
    }
}

fn hint_again(during_task: bool) -> String {
    let lang = ui().lang;
    let secs = DOUBLE_PRESS.as_secs();
    if during_task {
        lang.pick(
            format!("Ctrl+C 를 한 번 더 누르면 끝납니다 ({secs}초 안에). 누르지 않으면 지금 하는 일을 이어 갑니다."),
            format!("Press Ctrl+C again within {secs} seconds to quit. Otherwise the current task keeps going."),
        )
    } else {
        lang.pick(
            format!("Ctrl+C 를 한 번 더 누르면 끝납니다 ({secs}초 안에)."),
            format!("Press Ctrl+C again within {secs} seconds to quit."),
        )
    }
}

// ── 색 — 화면으로 나가는 줄에만 얹는다 ──────────────────────────────

/// 역할 색 다섯 — 4비트 ANSI 라 사용자 터미널의 테마를 따른다(벤치마크 축 4).
const GOOD: &str = "32";
const BAD: &str = "1;31";
const WARN: &str = "33";
const DIM: &str = "2";
const BRAND: &str = "1;36";

/// 찍기 직전의 줄 하나에 역할 색을 얹는다. 그리는 자리가 아니면 `None` — 그대로다.
///
/// **렌더러는 글자만 만든다.** 색은 여기서, 화면으로 나가는 줄에만 얹는다 — 회차
/// 로그 · 파이프 · 렌더러 시험은 한 글자도 바뀌지 않는다(불변식 I1). **줄 전체를**
/// 감싼다 — 하네스가 읽는 문구(`진행하려면` · `검사 완료` …) 가운데를 쪼개지 않는다
/// (불변식 I4). stderr 줄은 stderr 도 터미널일 때만 칠한다.
pub fn paint(line: &str, stderr: bool) -> Option<String> {
    if !fancy() || (stderr && !std::io::stderr().is_terminal()) {
        return None;
    }
    let brand = remedy_core::report::brand::product(ui().lang);
    style_of(line, brand).map(|s| marked(line, s))
}

/// 줄 하나를 칠한다. 좋음 · 나쁨 · 주의 줄은 **들여쓰기 뒤에 표시**(✓ ✗ !)를 얹는다 —
/// 색을 가려 보는 사람에게도 역할이 모양으로 남는다(목표 remedy_제품화 기준 3(a) ·
/// 벤치마크 축 4). 표시는 문구 앞에 붙을 뿐 문구를 쪼개지 않는다(불변식 I4).
fn marked(line: &str, s: &str) -> String {
    let d = remedy_sdk::i18n::deco();
    let mark = match s {
        GOOD => d.good(),
        BAD => d.bad(),
        WARN => d.warn(),
        _ => return format!("{ESC}[{s}m{line}{ESC}[0m"),
    };
    let body = line.trim_start();
    let indent = &line[..line.len() - body.len()];
    format!("{indent}{ESC}[{s}m{mark} {body}{ESC}[0m")
}

/// 제자리 진행 줄 — 창 폭에 맞춰 자르고(꺾이면 제자리가 아니다) 역할대로 칠한다.
pub fn live_line(text: &str) -> String {
    let cols = crossterm::terminal::size().map_or(80, |(c, _)| usize::from(c));
    let cut = clip(text, cols.saturating_sub(1));
    paint(&cut, false).unwrap_or(cut)
}

/// 폭 `max` 칸에 들어가게 자른다 — 넘치면 끝을 줄임표로. 폭은 [`width`] 로 센다.
fn clip(s: &str, max: usize) -> String {
    if width(s) <= max {
        return s.to_string();
    }
    let ell = if remedy_sdk::i18n::deco().ascii {
        "..."
    } else {
        "…"
    };
    let room = max.saturating_sub(width(ell));
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = if c.is_ascii() { 1 } else { 2 };
        if w + cw > room {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push_str(ell);
    out
}

/// 여러 줄 덩어리(렌더러가 만든 화면)를 줄마다 칠한다. 바뀐 줄이 없으면 `None`.
pub fn paint_block(text: &str) -> Option<String> {
    if !fancy() {
        return None;
    }
    let mut changed = false;
    let mut out = String::with_capacity(text.len());
    for piece in text.split_inclusive('\n') {
        let body = piece.trim_end_matches(['\n', '\r']);
        let end = &piece[body.len()..];
        match paint(body, false) {
            Some(p) => {
                changed = true;
                out.push_str(&p);
                out.push_str(end);
            }
            None => out.push_str(piece),
        }
    }
    changed.then_some(out)
}

/// 줄의 역할. **문구로 가른다** — 문구가 바뀌면 그 줄은 색 없이 나갈 뿐이고 정보는
/// 그대로 남는다(색은 정보를 더하지 않는다 — 기준 3(b)).
fn style_of(line: &str, brand: &str) -> Option<&'static str> {
    let t = line.trim_start();
    if t.is_empty() {
        return None;
    }
    let starts = |ps: &[&str]| ps.iter().any(|p| t.starts_with(p));
    let has = |ps: &[&str]| ps.iter().any(|p| t.contains(p));
    if starts(&["실패:", "Error:"]) {
        return Some(BAD);
    }
    if starts(&["알림:", "Notice:", "주의", "Warning"])
        || has(&[
            "권한이 없습니다",
            "No administrator rights",
            "No root rights",
        ])
    {
        return Some(WARN);
    }
    if is_rule(t)
        || starts(&[
            "검사 중",
            "Scanning",
            "치료 중",
            "Treating",
            "메뉴로 돌아갑니다",
            "Back to the menu",
        ])
    {
        return Some(DIM);
    }
    if starts(&["위협이 발견되지 않았습니다", "No threat was found"]) {
        return Some(GOOD);
    }
    if starts(&["검사 완료", "Scan done"]) {
        let clean = has(&["위협 0건", "취약 0건", " 0 threat", " 0 vulnerable"]);
        return Some(if clean { GOOD } else { BAD });
    }
    if starts(&["결과", "Result"]) {
        if has(&[
            "치료 완료",
            "treated (",
            "발견되지 않았",
            "No threat",
            "복원 완료",
            "restored",
        ]) {
            return Some(GOOD);
        }
        if has(&[
            "치료하지 않았",
            "not treated",
            "내부 오류",
            "internal error",
        ]) {
            return Some(BAD);
        }
        if has(&[
            "일부 실패",
            "Partial",
            "가드",
            "guard",
            "불완전",
            "incomplete",
            "다 보지 못해",
            "입력 오류",
            "Usage error",
        ]) {
            return Some(WARN);
        }
    }
    if t.starts_with(brand) {
        return Some(BRAND);
    }
    None
}

/// 가르는 줄 — `────` 또는 `----` 만으로 된 줄.
fn is_rule(t: &str) -> bool {
    let t = t.trim_end();
    t.chars().count() >= 8 && t.chars().all(|c| c == '─' || c == '-')
}

// ── 고르기 ──────────────────────────────────────────────────────────

/// 고르는 화면의 한 줄.
pub enum Row {
    Blank,
    /// 그대로 쓰는 줄 — 머리말 · 구분선.
    Text(String),
    /// 번호가 붙는 줄. 번호는 1 부터 차례로 매긴다.
    Item(String),
    /// 번호는 붙지만 지금은 고를 수 없는 줄 — 이름과 그 까닭. 흐리게 그리고, 그 번호를
    /// 고르면 까닭을 보인다. 번호를 비워 두지 않는 것은 **번호가 기계 상태마다 움직이지
    /// 않게** 하려는 것이다(목표 remedy_제품화 기준 5 — '전' 이미지에서 10 → 17).
    Off(String, String),
}

/// 고른 답.
pub enum Answer {
    /// 고른 번호. `0` 은 그만두기 줄이다.
    Num(usize),
    /// 읽지 못했다 — 범위 밖 · 숫자가 아님 · 입력이 닫혔다. **다시 묻지 않는다** —
    /// 되묻는 고리는 터미널이 아닌 자리에서 영원히 돌 수 있다(불변식 I7).
    Invalid,
    /// Ctrl+C 두 번 — 세션을 끝낸다.
    End,
}

/// 목록을 보이고 하나를 고르게 한다. `zero` 는 `0.` 줄의 글이고, 없으면 1 부터다.
///
/// 그리는 자리이고 목록이 창에 들어가면 **방향키 + 숫자**로 고른다(결정 6). 아니면
/// 지금까지의 글자 그대로 번호 한 줄을 받는다.
pub fn choose(rows: &[Row], zero: Option<&str>) -> Answer {
    let n = numbered(rows).count();
    if fancy() && fits(rows, zero) {
        if let Some(a) = choose_keys(rows, zero, n) {
            return a;
        }
    }
    choose_line(rows, zero, n)
}

/// 번호가 붙는 줄들 — 화면 차례대로. `v` 번은 `(v - 1)` 째다.
fn numbered(rows: &[Row]) -> impl Iterator<Item = &Row> {
    rows.iter()
        .filter(|r| matches!(r, Row::Item(_) | Row::Off(..)))
}

/// `v` 번이 고를 수 없는 줄이면 그 까닭을 담은 한 줄.
fn off_note(rows: &[Row], v: usize) -> Option<String> {
    match numbered(rows).nth(v.checked_sub(1)?)? {
        Row::Off(label, why) => Some(off_line(v, label, why)),
        _ => None,
    }
}

fn off_line(v: usize, label: &str, why: &str) -> String {
    format!("{v}. {label}{}{why}", remedy_sdk::i18n::deco().dash())
}

/// 지금까지의 화면 — 줄 입력. 랩 메뉴 하네스가 이 줄들을 읽는다(라벨 → 번호). 고를 수
/// 없는 줄은 `N. 이름 — 까닭` 이고, 그 번호를 고르면 까닭을 보이고 다시 묻는다.
fn choose_line(rows: &[Row], zero: Option<&str>, n: usize) -> Answer {
    let mut i = 0;
    for r in rows {
        match r {
            Row::Blank => outln!(),
            Row::Text(t) => outln!("{t}"),
            Row::Item(label) => {
                i += 1;
                outln!("  {i}. {label}");
            }
            Row::Off(label, why) => {
                i += 1;
                outln!("  {}", off_line(i, label, why));
            }
        }
    }
    if let Some(z) = zero {
        outln!("  0. {z}");
    }
    let lang = ui().lang;
    let lo = usize::from(zero.is_none());
    loop {
        eprintln!();
        eprint!(
            "{}",
            lang.pick(
                format!("번호를 고르십시오 ({lo}-{n}): "),
                format!("Choose a number ({lo}-{n}): ")
            )
        );
        std::io::stderr().flush().ok();
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) | Err(_) => return Answer::Invalid,
            Ok(_) => {}
        }
        let v = match line.trim().parse::<usize>() {
            Ok(v) if v >= lo && v <= n => v,
            _ => return Answer::Invalid,
        };
        // 고를 수 없는 줄 — 까닭을 보이고 다시 묻는다. 읽을 줄이 없으면 위에서 끝난다.
        match off_note(rows, v) {
            Some(note) => eprintln!("{}", crate::tee::ascii_safe(note)),
            None => return Answer::Num(v),
        }
    }
}

/// 방향키 + 숫자. 원시 모드를 켤 수 없으면 `None` — 부르는 쪽이 줄 입력으로 간다.
fn choose_keys(rows: &[Row], zero: Option<&str>, n: usize) -> Option<Answer> {
    use crossterm::event::{read, Event, KeyCode, KeyEventKind, KeyModifiers};

    // 강조가 서는 자리를 화면 차례대로 — 1..=n 다음에 0. **고를 수 없는 줄에도 선다** —
    // 건너뛰면 창 밖으로 넘긴 그 줄들을 넘겨 볼 길이 없다(새 꾸러미에서 아래 여섯 줄이
    // 전부 그랬다 · 2026-11-06 이미지). 그 줄에서 Enter 는 고르지 않고 까닭을 보인다.
    let order: Vec<usize> = (1..=n).chain(zero.map(|_| 0)).collect();
    if order.is_empty() {
        return None;
    }
    crossterm::terminal::enable_raw_mode().ok()?;
    let mut out = std::io::stdout();
    // 고르는 동안 커서를 숨긴다 — 목록 아래에서 깜빡이면 입력 칸처럼 읽힌다.
    let _ = write!(out, "{ESC}[?25l");
    // 처음 강조는 고를 수 있는 첫 줄이다.
    let mut at = order
        .iter()
        .position(|v| off_note(rows, *v).is_none())
        .unwrap_or(0);
    // 창이 목록보다 낮을 때 넘긴 자리 — 첫 번호 줄에서 몇 줄 아래부터 보이는가.
    let mut top = 0usize;
    let mut typed = String::new();
    let mut note: Option<String> = None;
    let first = lines(rows, zero, order[at], Some(&hint(&typed, None)));
    let mut drawn = draw(&mut out, &view(&first, &mut top, room()), 0);

    let answer = loop {
        let Ok(ev) = read() else {
            break Answer::End;
        };
        let key = match ev {
            Event::Key(k) if k.kind != KeyEventKind::Release => k,
            Event::Resize(..) => {
                let f = lines(rows, zero, order[at], Some(&hint(&typed, note.as_deref())));
                drawn = draw(&mut out, &view(&f, &mut top, room()), drawn);
                continue;
            }
            _ => continue,
        };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c' | 'C') if ctrl => {
                if press() {
                    break Answer::End;
                }
                note = Some(hint_again(false));
            }
            KeyCode::Up => {
                at = (at + order.len() - 1) % order.len();
                typed.clear();
                note = None;
            }
            KeyCode::Down | KeyCode::Tab => {
                at = (at + 1) % order.len();
                typed.clear();
                note = None;
            }
            KeyCode::Home => at = 0,
            KeyCode::End => at = order.len() - 1,
            KeyCode::Char(d) if d.is_ascii_digit() && !ctrl => {
                typed.push(d);
                if typed.len() > digits(n) {
                    typed = d.to_string();
                }
                note = None;
                if let Some(pos) = typed
                    .parse::<usize>()
                    .ok()
                    .and_then(|v| order.iter().position(|o| *o == v))
                {
                    at = pos;
                    // 고를 수 없는 번호면 그 줄로 가고 까닭을 안내 줄에.
                    note = off_note(rows, order[at]);
                }
            }
            KeyCode::Backspace => {
                typed.pop();
            }
            KeyCode::Esc if zero.is_some() => break Answer::Num(0),
            KeyCode::Enter => {
                let v = if typed.is_empty() {
                    Some(order[at])
                } else {
                    typed.parse::<usize>().ok().filter(|v| order.contains(v))
                };
                typed.clear();
                match v {
                    Some(v) => match off_note(rows, v) {
                        None => break Answer::Num(v),
                        Some(why) => note = Some(why),
                    },
                    None => note = Some(range_hint(zero.is_some(), n)),
                }
            }
            _ => {}
        }
        let f = lines(rows, zero, order[at], Some(&hint(&typed, note.as_deref())));
        drawn = draw(&mut out, &view(&f, &mut top, room()), drawn);
    };

    // 안내 줄을 걷고 고른 줄만 표시해 둔다 — 스크롤백에 남는 모양이다.
    let chosen = match answer {
        Answer::Num(v) => v,
        _ => usize::MAX,
    };
    let last = lines(rows, zero, chosen, None);
    draw(&mut out, &view(&last, &mut top, room()), drawn);
    let _ = write!(out, "{ESC}[?25h");
    let _ = out.flush();
    let _ = crossterm::terminal::disable_raw_mode();
    Some(answer)
}

/// 줄들을 그린다. `prev` 는 앞서 그린 줄 수 — 그만큼 올라가 화면 아래를 지우고 다시
/// 쓴다. 돌려주는 것은 이번에 그린 줄 수다.
fn draw(out: &mut impl Write, shown: &[String], prev: usize) -> usize {
    let mut s = String::new();
    if prev > 0 {
        s.push_str(&format!("{ESC}[{prev}A\r{ESC}[J"));
    }
    for l in shown {
        // 라벨 · 까닭 · 머리말의 문구도 ASCII 모드면 접는다(`tee::ascii_safe`).
        s.push_str(&crate::tee::ascii_safe(l.clone()));
        s.push_str("\r\n");
    }
    let _ = out.write_all(s.as_bytes());
    let _ = out.flush();
    shown.len()
}

/// 고르는 화면 한 장 — 줄들과, 창이 모자랄 때 어디를 넘길지 셀 값.
struct Frame {
    lines: Vec<String>,
    /// 맨 위에서 넘기지 않는 줄 수 — 첫 번호 줄 앞(머리말 · 물음).
    head: usize,
    /// 맨 아래에서 넘기지 않는 줄 수 — `0.` 줄과 안내.
    foot: usize,
    /// 강조한 줄의 자리.
    sel: Option<usize>,
    /// 줄마다 번호가 붙었는가 — 가린 자리의 "N개 더" 를 센다.
    numbered: Vec<bool>,
}

impl Frame {
    fn push(&mut self, line: String, numbered: bool) {
        self.lines.push(line);
        self.numbered.push(numbered);
    }
}

/// 고르는 화면의 줄들. `sel` 은 강조할 번호(없으면 `usize::MAX`), `hint` 는 맨 아래 줄.
fn lines(rows: &[Row], zero: Option<&str>, sel: usize, hint: Option<&str>) -> Frame {
    let mut f = Frame {
        lines: Vec::new(),
        head: rows
            .iter()
            .take_while(|r| matches!(r, Row::Blank | Row::Text(_)))
            .count(),
        foot: 0,
        sel: None,
        numbered: Vec::new(),
    };
    let mut i = 0;
    for r in rows {
        match r {
            Row::Blank => f.push(String::new(), false),
            // 이 길은 그리는 자리에서만 온다 — 글줄에도 역할 색을 얹는다(머리말 · 권한).
            Row::Text(t) => f.push(paint(t, false).unwrap_or_else(|| t.clone()), false),
            Row::Item(label) => {
                i += 1;
                if i == sel {
                    f.sel = Some(f.lines.len());
                }
                f.push(item_line(i, label, i == sel), true);
            }
            Row::Off(label, why) => {
                i += 1;
                let text = off_line(i, label, why);
                if i == sel {
                    f.sel = Some(f.lines.len());
                    f.push(format!("{ESC}[7m> {text}{ESC}[0m"), true);
                } else {
                    f.push(format!("{ESC}[2m  {text}{ESC}[0m"), true);
                }
            }
        }
    }
    let body_end = f.lines.len();
    if let Some(z) = zero {
        if sel == 0 {
            f.sel = Some(f.lines.len());
        }
        f.push(item_line(0, z, sel == 0), false);
    }
    if let Some(h) = hint {
        f.push(String::new(), false);
        f.push(format!("{ESC}[2m{h}{ESC}[0m"), false);
    }
    f.foot = f.lines.len() - body_end;
    f
}

/// 창에 들어갈 만큼만 — 목록이 창보다 높으면 머리말과 `0.` · 안내 줄은 두고 **번호
/// 줄들만 넘긴다**(gh 가 한 화면 20개로 넘기는 것과 같은 결 · 벤치마크 축 3). 다시
/// 그리는 줄이 창 높이를 넘으면 스크롤백이 무너진다. `max` 는 그릴 수 있는 줄 수다.
fn view(f: &Frame, top: &mut usize, max: usize) -> Vec<String> {
    if f.lines.len() <= max {
        *top = 0;
        return f.lines.clone();
    }
    let (start, end) = (f.head, f.lines.len() - f.foot);
    // 위아래 "N개 더" 두 줄은 늘 둔다 — 그린 줄 수가 넘길 때마다 바뀌지 않게.
    let rows = max.saturating_sub(f.head + f.foot + 2).max(1);
    if let Some(s) = f.sel.filter(|s| (start..end).contains(s)) {
        let s = s - start;
        if s < *top {
            *top = s;
        }
        if s >= *top + rows {
            *top = s + 1 - rows;
        }
    }
    *top = (*top).min((end - start).saturating_sub(rows));
    let (from, to) = (start + *top, (start + *top + rows).min(end));
    let hidden = |r: std::ops::Range<usize>| f.numbered[r].iter().filter(|b| **b).count();
    let mut v = f.lines[..start].to_vec();
    v.push(more_line(hidden(start..from), true));
    v.extend_from_slice(&f.lines[from..to]);
    v.push(more_line(hidden(to..end), false));
    v.extend_from_slice(&f.lines[end..]);
    v
}

/// 다시 그릴 수 있는 줄 수 — 창 높이에서 두 줄을 남긴다(커서가 선 줄 · 꺾임 여유).
fn room() -> usize {
    crossterm::terminal::size().map_or(usize::MAX, |(_, h)| usize::from(h).saturating_sub(2))
}

/// 넘겨서 가린 번호 줄이 몇 개인가. 없으면 빈 줄이다.
fn more_line(n: usize, up: bool) -> String {
    if n == 0 {
        return String::new();
    }
    let arrow = match (up, remedy_sdk::i18n::deco().ascii) {
        (true, false) => "↑",
        (false, false) => "↓",
        (true, true) => "^",
        (false, true) => "v",
    };
    let text = ui().lang.pick(
        format!("  {arrow} {}에 {n}개 더", if up { "위" } else { "아래" }),
        format!("  {arrow} {n} more {}", if up { "above" } else { "below" }),
    );
    format!("{ESC}[2m{text}{ESC}[0m")
}

/// 번호 줄. 강조는 반전이고, 표시 글자는 ASCII `>` 다 — `▶` 는 폭이 모호해 콘솔
/// 호스트는 두 칸, Windows Terminal · xterm 은 한 칸으로 그려 줄이 어긋난다.
fn item_line(n: usize, label: &str, on: bool) -> String {
    if on {
        format!("{ESC}[7m> {n}. {label}{ESC}[0m")
    } else {
        format!("  {n}. {label}")
    }
}

fn hint(typed: &str, note: Option<&str>) -> String {
    if let Some(n) = note {
        return n.to_string();
    }
    let lang = ui().lang;
    // 줄표 · 점도 장식 층에서 받는다 — `--ascii` 에서는 ASCII 로 간다(기준 3(c)).
    let d = remedy_sdk::i18n::deco();
    let (dot, dash) = (d.dot(), d.dash());
    if !typed.is_empty() {
        return lang.pick(
            format!("번호 {typed}{dash}Enter 를 누르면 고릅니다"),
            format!("Number {typed}{dash}press Enter to choose"),
        );
    }
    let arrows = if d.ascii { "Up/Down" } else { "↑↓" };
    lang.pick(
        format!("{arrows} 로 고르고 Enter{dot}번호를 쳐도 됩니다{dot}Ctrl+C 두 번이면 끝납니다"),
        format!("{arrows} to move, Enter to choose{dot}type a number{dot}Ctrl+C twice to quit"),
    )
}

fn range_hint(zero: bool, n: usize) -> String {
    let lo = usize::from(!zero);
    ui().lang.pick(
        format!("{lo}-{n} 사이의 번호를 고르십시오."),
        format!("Choose a number from {lo} to {n}."),
    )
}

fn digits(n: usize) -> usize {
    n.to_string().len()
}

/// 다시 그릴 수 있는가. 줄이 창보다 넓으면 꺾여 올라갈 줄 수를 셀 수 없고, 창이 머리말
/// · 아래 줄에 번호 줄 셋도 못 담을 만큼 낮으면 넘겨 보일 자리가 없다 — 그러면
/// 지금까지의 글자로 묻는다. 목록이 창보다 높은 것만으로는 물러나지 않는다([`view`]).
fn fits(rows: &[Row], zero: Option<&str>) -> bool {
    let Ok((cols, height)) = crossterm::terminal::size() else {
        return false;
    };
    let f = lines(rows, zero, usize::MAX, Some(&hint("", None)));
    let max = usize::from(height).saturating_sub(2);
    let tall_ok = f.lines.len() <= max || f.head + f.foot + 2 + MIN_ROWS <= max;
    tall_ok && f.lines.iter().all(|l| width(l) < usize::from(cols))
}

/// 넘겨 보일 때 최소한 보여야 하는 번호 줄 수.
const MIN_ROWS: usize = 3;

/// 화면 폭. **ASCII 가 아닌 글자는 두 칸으로 센다** — 한글은 두 칸이고, 폭이 모호한
/// 기호(`·` `—` `↑`)를 한국어 콘솔 호스트가 두 칸으로 그린다(2026-11-05 이미지).
/// 넘치게 세면 다시 그리기를 덜 쓸 뿐이고, 모자라게 세면 줄이 꺾여 화면이 무너진다.
/// 이스케이프는 세지 않는다.
fn width(s: &str) -> usize {
    let mut w = 0;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ESC {
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        w += if c.is_ascii() { 1 } else { 2 };
    }
    w
}

#[cfg(test)]
mod tests {
    use super::{
        clip, decide, exit_code_for, lines, marked, numbered, off_note, second_press, term_ok,
        view, width, Row, BAD, DIM, ESC, GOOD, TASK_CHANGES, TASK_NONE, TASK_READS, WARN,
    };
    use std::ffi::OsStr;

    /// 기준 3(b) 의 조건 넷 — 하나라도 서면 그리지 않는다(이스케이프 0 바이트).
    #[test]
    fn any_one_of_the_four_conditions_turns_drawing_off() {
        let on = |t: Option<&str>, nc: Option<&OsStr>, out: bool, vt: bool| {
            decide(true, out, term_ok(t), nc, || vt)
        };
        assert!(on(Some("xterm"), None, true, true));
        assert!(
            !on(Some("xterm"), Some(OsStr::new("1")), true, true),
            "NO_COLOR"
        );
        assert!(!on(Some("xterm"), None, false, true), "파이프 · 파일");
        assert!(!on(Some("dumb"), None, true, true), "TERM=dumb");
        assert!(!on(Some("xterm"), None, true, false), "VT 를 못 켬");
        // NO_COLOR 가 빈 값이면 없는 것으로 본다(no-color.org).
        assert!(on(Some("xterm"), Some(OsStr::new("")), true, true));
        assert!(
            !decide(false, true, true, None, || true),
            "stdin 이 터미널이 아님"
        );
    }

    /// `TERM` 이 없을 때 — Windows 콘솔은 원래 없고, 리눅스에서는 모르는 화면이다.
    #[test]
    fn a_missing_term_means_windows_console_or_unknown_screen() {
        #[cfg(windows)]
        assert!(term_ok(None));
        #[cfg(not(windows))]
        assert!(!term_ok(None));
    }

    /// **VT 는 마지막에 묻는다** — 파이프로 받는 회차에서 콘솔 모드를 바꾸지 않는다.
    #[test]
    fn vt_is_not_asked_when_output_is_a_pipe() {
        let mut asked = false;
        assert!(!decide(true, false, true, None, || {
            asked = true;
            true
        }));
        assert!(!asked);
    }

    #[test]
    fn only_a_second_press_inside_the_window_quits() {
        assert!(!second_press(0, 5_000), "처음 누름");
        assert!(second_press(5_000, 6_500), "1.5초 뒤");
        assert!(second_press(5_000, 7_000), "딱 2초");
        assert!(!second_press(5_000, 7_001), "2초를 넘김");
    }

    /// 새 종료 코드를 만들지 않는다(I3).
    #[test]
    fn forced_exit_uses_existing_codes() {
        assert_eq!(exit_code_for(TASK_CHANGES, 0), 3);
        assert_eq!(exit_code_for(TASK_READS, 0), 6);
        assert_eq!(
            exit_code_for(TASK_NONE, 2),
            2,
            "작업 사이면 마지막 작업의 코드"
        );
        assert_eq!(exit_code_for(TASK_NONE, -1), 0, "작업이 없었다");
    }

    /// 역할 색은 문구로 가른다 — 녹(좋음) · 적(나쁨) · 황(주의) · 흐림 · 제품명.
    #[test]
    fn roles_follow_the_words_of_the_line() {
        use super::{style_of, BAD, BRAND, DIM, GOOD, WARN};
        let b = "ESTsecurity 전용백신";
        assert_eq!(style_of("검사 완료 : 흔적 0건 · 위협 0건", b), Some(GOOD));
        assert_eq!(style_of("검사 완료 : 흔적 5건 · 위협 1건", b), Some(BAD));
        assert_eq!(
            style_of(" 결과      : 위협 발견, 치료 완료 (6건 수행 완료)", b),
            Some(GOOD)
        );
        assert_eq!(
            style_of(" 결과      : 위협 발견, 치료하지 않았습니다.", b),
            Some(BAD)
        );
        assert_eq!(
            style_of(" 결과      : 일부 실패 (3건 수행 완료)", b),
            Some(WARN)
        );
        assert_eq!(style_of(" 결과      : 6건 복원 완료.", b), Some(GOOD));
        assert_eq!(style_of("위협이 발견되지 않았습니다.", b), Some(GOOD));
        assert_eq!(
            style_of("결과 폴더 : C:\\remedy\\out", b),
            None,
            "결과 폴더는 결과가 아니다"
        );
        assert_eq!(
            style_of(
                "알림: 코드서명이 없어 공식 배포본인지 스스로 확인하지 못합니다.",
                b
            ),
            Some(WARN)
        );
        assert_eq!(style_of("실패: 관리자 권한이 필요합니다", b), Some(BAD));
        assert_eq!(style_of("────────────────────", b), Some(DIM));
        assert_eq!(style_of(" ESTsecurity 전용백신 1.0.0", b), Some(BRAND));
        assert_eq!(style_of("  1. 검사하고 치료하기", b), None);
        assert_eq!(style_of("", b), None);
    }

    #[test]
    fn width_counts_wide_and_skips_escapes() {
        assert_eq!(width("  1. abc"), 8);
        assert_eq!(width("검사"), 4);
        assert_eq!(width(&format!("{ESC}[7m> 1. 검사{ESC}[0m")), 9);
        assert_eq!(width("a · b"), 6, "폭이 모호한 기호는 두 칸");
    }

    /// 제자리 진행 줄은 창 폭 안에 든다 — 넘치면 줄임표로 끝난다. 짧으면 그대로다.
    #[test]
    fn a_live_line_is_clipped_to_the_window() {
        assert_eq!(clip("short", 20), "short");
        for (s, max) in [
            ("abcdefghij", 6),
            ("검사 중 · 폴더 1155개 · 항목 9104개", 20),
        ] {
            let c = clip(s, max);
            assert!(width(&c) <= max, "{c:?} 가 {max} 칸을 넘는다");
            assert!(c.len() < s.len(), "{c:?}");
        }
    }

    /// 좋음 · 나쁨 · 주의 줄은 들여쓰기 뒤에 표시를 얹고, 문구는 끊기지 않고 이어 있다
    /// (불변식 I4). 흐림 · 제품명 줄에는 표시가 없다.
    #[test]
    fn role_lines_carry_a_mark_after_the_indent() {
        let d = remedy_sdk::i18n::deco();
        let good = marked("  위협이 발견되지 않았습니다.", GOOD);
        assert!(
            good.starts_with(&format!(
                "  {ESC}[32m{} 위협이 발견되지 않았습니다.",
                d.good()
            )),
            "{good:?}"
        );
        let bad = marked("실패: 내부 오류", BAD);
        assert!(
            bad.contains(&format!("{} 실패: 내부 오류", d.bad())),
            "{bad:?}"
        );
        assert!(marked("알림: x", WARN).contains("! 알림: x"));
        assert_eq!(
            marked("메뉴로 돌아갑니다.", DIM),
            format!("{ESC}[2m메뉴로 돌아갑니다.{ESC}[0m")
        );
    }

    /// 고를 수 없는 줄도 번호를 받는다 — 그 번호는 고르지 않고 까닭을 낸다.
    #[test]
    fn an_off_row_keeps_its_number_and_tells_why() {
        let rows = vec![
            Row::Item("a".into()),
            Row::Off("b".into(), "why".into()),
            Row::Item("c".into()),
        ];
        assert_eq!(numbered(&rows).count(), 3);
        let note = off_note(&rows, 2).expect("2번은 고를 수 없는 줄이다");
        assert!(note.starts_with("2. b") && note.ends_with("why"), "{note}");
        for v in [0, 1, 3, 4] {
            assert_eq!(off_note(&rows, v), None, "{v}번");
        }
    }

    /// 창이 목록보다 낮으면 번호 줄만 넘긴다 — 머리말과 아래 줄은 그대로, 강조한 줄은
    /// 늘 보이고, 그린 줄 수는 창을 넘지 않으며, 가린 번호 줄 수를 위아래에 적는다.
    #[test]
    fn a_tall_list_scrolls_inside_the_window() {
        let mut rows = vec![Row::Blank, Row::Text("head".into()), Row::Blank];
        rows.extend((1..=20).map(|i| Row::Item(format!("item {i}"))));
        let max = 12;
        let mut top = 0;

        // 머리 3 + 아래 3(0. 줄 · 빈 줄 · 안내) + 위아래 두 줄 = 8 → 번호 줄 넷이 보인다.
        let v = view(&lines(&rows, Some("quit"), 1, Some("hint")), &mut top, max);
        assert_eq!(v.len(), max);
        assert_eq!(&v[..3], ["", "head", ""]);
        assert!(v.iter().any(|l| l.contains("> 1. item 1")));
        assert_eq!(v[3], "", "위로 가린 것이 없다");
        assert!(v[8].contains("16"), "아래로 가린 번호 줄 16: {:?}", v[8]);
        assert!(v[9].contains("0. quit") && v[11].contains("hint"));

        // 맨 아래 항목을 고르면 그 줄이 보이게 넘어간다.
        let v = view(&lines(&rows, Some("quit"), 20, Some("hint")), &mut top, max);
        assert_eq!(v.len(), max);
        assert!(v.iter().any(|l| l.contains("> 20. item 20")));
        assert!(v[3].contains("16"), "위로 가린 번호 줄 16: {:?}", v[3]);
        assert_eq!(v[8], "", "아래로 가린 것이 없다");

        // 창이 넉넉하면 그대로다.
        let all = lines(&rows, Some("quit"), 1, Some("hint"));
        assert_eq!(view(&all, &mut top, 100), all.lines);
        assert_eq!(top, 0);

        // 가린 줄이 전부 고를 수 없는 줄이어도 그 줄에 서서 넘겨 볼 수 있다 — 새
        // 꾸러미의 첫 메뉴가 그렇다(아래 여섯 줄이 모두 까닭을 단다).
        let mut off = vec![Row::Blank, Row::Text("head".into()), Row::Blank];
        off.extend((1..=5).map(|i| Row::Item(format!("item {i}"))));
        off.extend((6..=20).map(|i| Row::Off(format!("item {i}"), "why".into())));
        let v = view(&lines(&off, Some("quit"), 20, Some("hint")), &mut top, max);
        assert!(
            v.iter()
                .any(|l| l.contains("> 20. item 20") && l.contains("why")),
            "{v:?}"
        );
    }
}
