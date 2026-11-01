//! 전역 계수기를 만지는 진행 표시 시험 — **별도 프로세스로 돈다.**
//!
//! # 왜 `src` 가 아니라 여기인가
//!
//! `progress` 는 전역 `static` 에 쌓는다. 그런데 그 계수기를 올리는 것은 이
//! 모듈만이 아니다 — `local::walk` 이 순회하며 `enter_dir`·`tick_entry` 를
//! 부른다. `src` 안에 두면 `walk` 을 쓰는 다른 시험과 **같은 프로세스에서 병렬로**
//! 돌고, `reset()` 뒤의 관측에 남의 순회가 섞인다.
//!
//! 실제로 그랬다 — `counts_and_remembers_the_last_dir` 가 세 번에 한 번
//! `(2, 4) != (2, 3)` 으로 깨졌다(2026-09-18).
//!
//! 모듈 안의 `SERIAL` 로는 막지 못한다. 그것은 이 시험들끼리의 약속이고
//! `walk` 을 부르는 쪽은 그 락을 모른다. **통합 시험은 자기 프로세스에서 돌므로
//! 격리가 구조로 보장된다** — 새 시험을 쓰는 사람이 무엇을 잊어도 깨지지 않는다.

use std::sync::Mutex;
use std::time::Duration;

// 이 파일 안에서도 하나씩 돈다 — 서로의 reset 이 끼어들지 않게.
static SERIAL: Mutex<()> = Mutex::new(());
use remedy_platform::progress::*;

/// **상한을 넘겼는가**는 심장박동이 숫자에 뜻을 붙이는 근거다.
///
/// 넘겨도 끊지 않기로 했으므로(결정 2026-09-07) 이 값이 하는 일은 *말하는*
/// 것뿐이다. 그런데 말하지 않으면 화면의 `70초` 는 정상인지 넘긴 것인지
/// 구분되지 않는다 — 2026-09-11 까지 실제로 그랬다.
#[test]
fn tool_over_says_whether_the_mark_was_passed() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert_eq!(snapshot().tool, "");
    assert!(!snapshot().tool_over, "도구가 없으면 넘긴 것도 없다");

    // 상한 0 — 시작하자마자 넘긴 것이다.
    tool_started("sc.exe stop", Duration::from_secs(0));
    let s = snapshot();
    assert_eq!(s.tool, "sc.exe stop");
    assert!(s.tool_over, "{s:?}");
    assert_eq!(s.tool_warn_secs, 0);

    // 넉넉한 상한 — 아직 정상이다.
    tool_started("sc.exe stop", Duration::from_secs(3600));
    let s = snapshot();
    assert!(!s.tool_over, "{s:?}");
    assert_eq!(s.tool_warn_secs, 3600);

    // 끝나면 둘 다 사라진다 — 끝난 도구를 화면이 계속 말하면 안 된다.
    tool_finished();
    let s = snapshot();
    assert_eq!(s.tool, "");
    assert!(!s.tool_over);
    assert_eq!(s.tool_warn_secs, 0);
}

#[test]
fn counts_and_remembers_the_last_dir() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    enter_dir("a");
    tick_entry();
    tick_entry();
    enter_dir("a/b");
    tick_entry();
    let s = snapshot();
    assert_eq!((s.dirs, s.entries), (2, 3));
    assert_eq!(s.current, "a/b");
    set_stage("extra");
    assert_eq!(snapshot().stage, "extra");
    note_item("a/b/x.exe");
    let s = snapshot();
    assert_eq!((s.processed, s.current.as_str()), (1, "a/b/x.exe"));
    reset();
    assert_eq!(snapshot(), Snapshot::default());
}

/// 루트 하나를 걷고 처리하는 흉내. `files` 개의 파일과 `dirs` 개의 폴더.
fn walk_root(idx: usize, total: usize, dirs: usize, files: usize) {
    begin_root(idx, total);
    for i in 0..dirs {
        enter_dir(&format!("d{i}"));
        tick_entry(); // 폴더 자신도 항목이다
    }
    for _ in 0..files {
        tick_entry();
    }
    root_walked();
}

#[test]
fn the_denominator_is_this_roots_files_not_everything_seen() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    walk_root(1, 2, 3, 10);
    let s = snapshot();
    assert_eq!(s.root_idx, 1);
    assert_eq!(s.root_total, 2);
    // 항목 13(폴더 3 + 파일 10)에서 폴더를 뺀 것이 처리 대상이다.
    assert_eq!(s.entries, 13, "{s:?}");
    assert_eq!(s.root_files, 10, "{s:?}");
    assert_eq!(s.root_processed, 0, "{s:?}");

    for i in 0..4 {
        note_item(&format!("f{i}"));
    }
    let s = snapshot();
    assert_eq!(s.root_processed, 4, "{s:?}");
    assert_eq!(s.processed, 4, "{s:?}");
}

#[test]
fn the_ratio_never_goes_backwards_when_the_next_root_is_walked() {
    // **이것이 루트 단위로 세는 이유다.** 전역 항목 수를 분모로 쓰면 두 번째
    // 루트를 걷는 순간 분모가 커져 화면의 비율이 뒤로 간다.
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    walk_root(1, 2, 1, 10);
    for i in 0..10 {
        note_item(&format!("a{i}"));
    }
    let first = snapshot();
    assert_eq!(
        (first.root_processed, first.root_files),
        (10, 10),
        "{first:?}"
    );

    walk_root(2, 2, 1, 4);
    let second = snapshot();
    // 두 번째 루트는 자기 분모로 다시 센다. 앞 루트의 10 이 섞이지 않는다.
    assert_eq!(second.root_files, 4, "{second:?}");
    assert_eq!(second.root_processed, 0, "{second:?}");
    assert_eq!(second.root_idx, 2, "{second:?}");
    // 전역 계수는 계속 쌓인다 — 두 값은 서로 다른 물음에 답한다.
    assert_eq!(second.processed, 10, "{second:?}");
    assert_eq!(second.entries, 16, "{second:?}");
}

#[test]
fn while_walking_the_denominator_is_not_known_yet() {
    // 걷는 중에 잠정 분모를 보이면 그 수가 곧 커지고, 사용자는 진행이 뒤로
    // 갔다고 읽는다. 0 이 "아직 모른다" 를 뜻한다.
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    begin_root(1, 1);
    enter_dir("d");
    tick_entry();
    tick_entry();
    let s = snapshot();
    assert_eq!(s.root_idx, 1, "{s:?}");
    assert_eq!(s.root_files, 0, "걷는 중인데 분모를 안다고 말했다: {s:?}");
    root_walked();
    assert_eq!(snapshot().root_files, 1);
}

#[test]
fn leaving_the_file_stage_turns_root_progress_off() {
    // 뒤 단계(자동실행·레지스트리…)에는 루트가 없다. 남겨 두면 그 단계가
    // 파일 단계인 것처럼 읽힌다.
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    walk_root(1, 1, 0, 3);
    assert_eq!(snapshot().root_idx, 1);
    end_roots();
    let s = snapshot();
    assert_eq!(s.root_idx, 0, "{s:?}");
    assert_eq!(s.root_files, 0, "{s:?}");
}

#[test]
fn reset_clears_the_root_counters_too() {
    // 새 상태를 reset 에 빠뜨리면 한 프로세스의 두 검사가 서로 오염된다.
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    walk_root(2, 5, 1, 7);
    note_item("x");
    reset();
    assert_eq!(snapshot(), Snapshot::default());
}

#[test]
fn timing_accumulates_and_resets() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    add_walk(Duration::from_millis(5));
    add_read(Duration::from_millis(7), 1000);
    add_read(Duration::from_millis(1), 24);
    add_hash(Duration::from_millis(9));
    add_sign(Duration::from_millis(11));
    skip_big();
    let t = timing();
    assert_eq!(t.walk, Duration::from_millis(5));
    assert_eq!((t.read, t.read_bytes), (Duration::from_millis(8), 1024));
    assert_eq!((t.hashed_files, t.sign_checked, t.skipped_big), (1, 1, 1));
    reset();
    assert_eq!(timing(), Timing::default());
}
