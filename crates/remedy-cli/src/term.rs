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
            eprintln!();
            std::process::exit(i32::from(forced_exit_code()));
        }
        eprintln!();
        eprintln!("{}", hint_again(TASK.load(Ordering::SeqCst) != TASK_NONE));
    });
}

/// 작업 하나가 시작한다. `changes_system` 은 강제로 끝날 때의 종료 코드를 가른다.
pub fn task_begin(changes_system: bool) {
    let t = if changes_system {
        TASK_CHANGES
    } else {
        TASK_READS
    };
    TASK.store(t, Ordering::SeqCst);
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

// ── 고르기 ──────────────────────────────────────────────────────────

/// 고르는 화면의 한 줄.
pub enum Row {
    Blank,
    /// 그대로 쓰는 줄 — 머리말 · 구분선.
    Text(String),
    /// 번호가 붙는 줄. 번호는 1 부터 차례로 매긴다.
    Item(String),
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
    let n = rows.iter().filter(|r| matches!(r, Row::Item(_))).count();
    if fancy() && fits(rows, zero) {
        if let Some(a) = choose_keys(rows, zero, n) {
            return a;
        }
    }
    choose_line(rows, zero, n)
}

/// 지금까지의 화면. **한 글자도 바꾸지 않는다** — 랩 메뉴 하네스가 이 줄들을 읽는다.
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
        }
    }
    if let Some(z) = zero {
        outln!("  0. {z}");
    }
    let lang = ui().lang;
    let lo = usize::from(zero.is_none());
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
    match line.trim().parse::<usize>() {
        Ok(v) if v >= lo && v <= n => Answer::Num(v),
        _ => Answer::Invalid,
    }
}

/// 방향키 + 숫자. 원시 모드를 켤 수 없으면 `None` — 부르는 쪽이 줄 입력으로 간다.
fn choose_keys(rows: &[Row], zero: Option<&str>, n: usize) -> Option<Answer> {
    use crossterm::event::{read, Event, KeyCode, KeyEventKind, KeyModifiers};

    // 고를 수 있는 번호를 화면 차례대로 — 1..=n 다음에 0.
    let order: Vec<usize> = (1..=n).chain(zero.map(|_| 0)).collect();
    if order.is_empty() {
        return None;
    }
    crossterm::terminal::enable_raw_mode().ok()?;
    let mut out = std::io::stdout();
    let mut at = 0usize;
    let mut typed = String::new();
    let mut note: Option<String> = None;
    let mut drawn = draw(
        &mut out,
        &lines(rows, zero, order[at], Some(&hint(&typed, None))),
        0,
    );

    let answer = loop {
        let Ok(ev) = read() else {
            break Answer::End;
        };
        let key = match ev {
            Event::Key(k) if k.kind != KeyEventKind::Release => k,
            Event::Resize(..) => {
                let shown = lines(rows, zero, order[at], Some(&hint(&typed, note.as_deref())));
                drawn = draw(&mut out, &shown, drawn);
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
                if let Some(pos) = typed
                    .parse::<usize>()
                    .ok()
                    .and_then(|v| order.iter().position(|o| *o == v))
                {
                    at = pos;
                }
                note = None;
            }
            KeyCode::Backspace => {
                typed.pop();
            }
            KeyCode::Esc if zero.is_some() => break Answer::Num(0),
            KeyCode::Enter => {
                if typed.is_empty() {
                    break Answer::Num(order[at]);
                }
                match typed.parse::<usize>().ok().filter(|v| order.contains(v)) {
                    Some(v) => break Answer::Num(v),
                    None => {
                        note = Some(range_hint(zero.is_some(), n));
                        typed.clear();
                    }
                }
            }
            _ => {}
        }
        let shown = lines(rows, zero, order[at], Some(&hint(&typed, note.as_deref())));
        drawn = draw(&mut out, &shown, drawn);
    };

    // 안내 줄을 걷고 고른 줄만 표시해 둔다 — 스크롤백에 남는 모양이다.
    let chosen = match answer {
        Answer::Num(v) => v,
        _ => usize::MAX,
    };
    draw(&mut out, &lines(rows, zero, chosen, None), drawn);
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
        s.push_str(l);
        s.push_str("\r\n");
    }
    let _ = out.write_all(s.as_bytes());
    let _ = out.flush();
    shown.len()
}

/// 고르는 화면의 줄들. `sel` 은 강조할 번호(없으면 `usize::MAX`), `hint` 는 맨 아래 줄.
fn lines(rows: &[Row], zero: Option<&str>, sel: usize, hint: Option<&str>) -> Vec<String> {
    let mut v = Vec::new();
    let mut i = 0;
    for r in rows {
        match r {
            Row::Blank => v.push(String::new()),
            Row::Text(t) => v.push(t.clone()),
            Row::Item(label) => {
                i += 1;
                v.push(item_line(i, label, i == sel));
            }
        }
    }
    if let Some(z) = zero {
        v.push(item_line(0, z, sel == 0));
    }
    if let Some(h) = hint {
        v.push(String::new());
        v.push(format!("{ESC}[2m{h}{ESC}[0m"));
    }
    v
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
    if !typed.is_empty() {
        return lang.pick(
            format!("번호 {typed} — Enter 를 누르면 고릅니다"),
            format!("Number {typed} — press Enter to choose"),
        );
    }
    let arrows = if remedy_sdk::i18n::deco().ascii {
        "Up/Down"
    } else {
        "↑↓"
    };
    lang.pick(
        format!("{arrows} 로 고르고 Enter · 번호를 쳐도 됩니다 · Ctrl+C 두 번이면 끝납니다"),
        format!("{arrows} to move, Enter to choose · type a number · Ctrl+C twice to quit"),
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

/// 다시 그릴 수 있는가. 목록이 창보다 높거나 줄이 창보다 넓으면 줄이 꺾여, 올라갈 줄
/// 수를 셀 수 없다 — 그러면 지금까지의 글자로 묻는다.
fn fits(rows: &[Row], zero: Option<&str>) -> bool {
    let Ok((cols, height)) = crossterm::terminal::size() else {
        return false;
    };
    let shown = lines(rows, zero, usize::MAX, Some(&hint("", None)));
    shown.len() + 1 < usize::from(height) && shown.iter().all(|l| width(l) < usize::from(cols))
}

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
        decide, exit_code_for, second_press, term_ok, width, ESC, TASK_CHANGES, TASK_NONE,
        TASK_READS,
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

    #[test]
    fn width_counts_wide_and_skips_escapes() {
        assert_eq!(width("  1. abc"), 8);
        assert_eq!(width("검사"), 4);
        assert_eq!(width(&format!("{ESC}[7m> 1. 검사{ESC}[0m")), 9);
        assert_eq!(width("a · b"), 6, "폭이 모호한 기호는 두 칸");
    }
}
