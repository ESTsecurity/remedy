//! 재귀 삭제 직전 점검 (설계-03 §4).
//!
//! **이 함수가 `Ok(빈 목록)` 을 내면 실행기는 지워도 된다고 읽는다.** 그래서
//! 시험이 묻는 것은 셋이다 — 신뢰 서명을 찾는가(조건 3), **확인하지 못한 것을
//! "없다" 로 흘리지 않는가**, 그리고 **규모 상한을 넘는 것을 막는가**.

#![cfg(windows)]

use std::path::PathBuf;

use remedy_platform::write::PlatformWrite;

fn lab(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("remedy-trusted-in-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("실험 디렉터리");
    d
}

fn system32(name: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join(name)
}

fn platform() -> impl PlatformWrite {
    remedy_platform::live().expect("이 플랫폼에는 live 백엔드가 있다")
}

/// **이 거절 사유는 종료 코드 5 로 고객 화면에 나간다.**
///
/// `survey_recursive_target` 의 답은 `refusal_before_backup` 의 `{e}` 에 실려
/// `StoppedBeforeDestruction` 이 되고, 그것이 가드 중단(5)이다 — 14회차가 그
/// 경로를 실측했다. 무인 배포가 5 를 받고 왜 막혔는지 읽지 못하면 그 코드는
/// 반만 쓸모 있다.
fn 사유가_영어인가(e: &remedy_platform::PlatformError) {
    let line = e.to_string();
    assert!(
        !line.chars().any(|c| ('가'..='힣').contains(&c)),
        "재귀 삭제 거절 사유가 영어 회차에서 한글로 나온다: {line}"
    );
}

#[test]
fn 정상_프로그램이_섞인_폴더는_통째로_지울_수_없다() {
    // **노리는 실패가 이것이다** — 악성코드가 정상 프로그램 폴더에 떨어졌고,
    // 그 폴더를 통째로 지워 정상 프로그램을 부수는 것 (설계-09 P8).
    let d = lab("mixed");
    std::fs::copy(system32("notepad.exe"), d.join("notepad.exe")).expect("복사");
    std::fs::write(d.join("payload.js"), b"evil").expect("쓰기");

    let found = platform()
        .survey_recursive_target(d.to_str().unwrap(), 500, 8)
        .expect("확인하지 못했다");
    assert_eq!(found.len(), 1, "신뢰 서명을 찾지 못했다: {found:?}");
    assert!(found[0].contains("notepad.exe"), "{found:?}");
    // 누구 서명인지도 함께 나와야 보고가 선다.
    assert!(found[0].contains("Microsoft"), "{found:?}");

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn 하위_디렉터리도_본다() {
    // 재귀 삭제이므로 확인도 재귀여야 한다. 한 칸만 보면 그 아래 정상 프로그램이
    // 그대로 지워진다.
    let d = lab("nested");
    let sub = d.join("a").join("b");
    std::fs::create_dir_all(&sub).expect("하위");
    std::fs::copy(system32("notepad.exe"), sub.join("notepad.exe")).expect("복사");

    let found = platform()
        .survey_recursive_target(d.to_str().unwrap(), 500, 8)
        .expect("확인하지 못했다");
    assert_eq!(found.len(), 1, "하위를 보지 않았다: {found:?}");

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn 서명이_없는_것만_있으면_빈_목록이다() {
    // 여기서 빈 목록을 내지 못하면 재귀 삭제가 영영 열리지 않는다 — 늘 거부하는
    // 가드는 없는 가드만큼 쓸모없다.
    let d = lab("clean");
    std::fs::write(d.join("payload.js"), b"evil").expect("쓰기");
    std::fs::write(d.join("readme.txt"), b"x").expect("쓰기");
    std::fs::create_dir_all(d.join("sub")).expect("하위");
    std::fs::write(d.join("sub").join("more.js"), b"evil").expect("쓰기");

    let found = platform()
        .survey_recursive_target(d.to_str().unwrap(), 500, 8)
        .expect("확인하지 못했다");
    assert!(found.is_empty(), "없는 것을 찾았다: {found:?}");

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn 서명되지_않은_실행_파일은_막지_않는다() {
    // 확장자가 대상이어도 서명이 없으면 통과다. 그러지 않으면 악성 exe 가 든
    // 폴더를 지울 수 없다 — 정확히 이 도구가 해야 할 일이 막힌다.
    let d = lab("unsigned-exe");
    std::fs::write(d.join("dropper.exe"), b"MZ not really").expect("쓰기");

    let found = platform()
        .survey_recursive_target(d.to_str().unwrap(), 500, 8)
        .expect("확인하지 못했다");
    assert!(found.is_empty(), "{found:?}");

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn 없는_디렉터리는_빈_목록이_아니라_오류다() {
    // "확인하지 못했다" 를 "없다" 로 읽으면 이 가드는 존재하지 않는 것이다.
    let d = std::env::temp_dir().join("remedy-trusted-in-그런디렉터리없다");
    let _ = std::fs::remove_dir_all(&d);

    let r = platform().survey_recursive_target(d.to_str().unwrap(), 500, 8);
    assert!(r.is_err(), "없는 디렉터리에 판정을 냈다: {r:?}");
}

// ─────────────────────────────── 규모 상한 (설계-03 §4)

#[test]
fn 하위_항목이_상한을_넘으면_지울_수_없다() {
    // **"어디를" 이 아니라 "얼마나" 를 막는 자리다.** 조건 1~5 는 대상 경로를
    // 좁히지만 그 안에 무엇이 얼마나 있는지는 보지 않는다.
    let d = lab("too-many");
    for i in 0..12 {
        std::fs::write(d.join(format!("f{i}.dat")), b"x").expect("쓰기");
    }

    // 상한 10 — 12 개가 있으므로 넘는다.
    let e = platform()
        .survey_recursive_target(d.to_str().unwrap(), 10, 8)
        .expect_err("상한을 넘었는데 통과시켰다");
    assert!(e.to_string().contains("10"), "{e}");
    사유가_영어인가(&e);

    // 상한 20 이면 통과한다. **경계가 실제로 그 값에 있다.**
    platform()
        .survey_recursive_target(d.to_str().unwrap(), 20, 8)
        .expect("상한 안인데 거부했다");

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn 트리가_상한보다_깊으면_지울_수_없다() {
    let d = lab("too-deep");
    let mut p = d.clone();
    for i in 0..6 {
        p = p.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&p).expect("깊은 트리");
    std::fs::write(p.join("x.dat"), b"x").expect("쓰기");

    let e = platform()
        .survey_recursive_target(d.to_str().unwrap(), 500, 3)
        .expect_err("깊이 상한을 넘었는데 통과시켰다");
    assert!(e.to_string().contains("3"), "{e}");
    사유가_영어인가(&e);

    platform()
        .survey_recursive_target(d.to_str().unwrap(), 500, 8)
        .expect("상한 안인데 거부했다");

    let _ = std::fs::remove_dir_all(&d);
}
