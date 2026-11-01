//! **관리자 문** — 기계를 만지는 명령은 권한 없이는 시작하지 않는다.
//!
//! 왜 이 시험이 있는가. 권한이 모자란 채로 돌면 예약 작업 디렉터리가 열리지
//! 않고, 감염된 기계에서 **증거 0건**이 나온다(실측 2026-08-31). 그 자리에서도
//! "위협 없음" 이라 말하지 않도록 관측 완전성 장치가 `exit 6` 을 내지만, 그것은
//! 마지막 방어선이다. 할 수 없는 일이면 **첫 줄에서** 거절해야 한다.
//!
//! 여기서 `REMEDY_ELEVATION` 으로 권한을 양방향으로 고정한다. 그렇게 하지
//! 않으면 이 시험의 결과가 *누가 돌렸는가* 에 따라 달라진다 — 관리자 셸에서
//! 돌리면 거절 시험이 통과하지 못한다. 재현되지 않는 시험은 시험이 아니다.

use std::path::PathBuf;
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_remedy");

fn work() -> PathBuf {
    let d = std::env::temp_dir().join("remedy-cli-admin-gate");
    std::fs::create_dir_all(&d).expect("작업 디렉터리");
    d
}

/// 권한을 `elevation` 으로 고정하고 부른다.
fn run_as(elevation: &str, args: &[&str]) -> (i32, String) {
    let out = Command::new(EXE)
        .args(args)
        .env("REMEDY_ELEVATION", elevation)
        .env("REMEDY_LANG", "ko")
        .output()
        .expect("실행");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// 기계를 만지는 명령 **전부**. 하나라도 빠지면 그 명령은 권한 없이 반쯤 돈다.
const TOUCHES_THE_MACHINE: &[&[&str]] = &[
    &["collect", "--out", "x.json", "--root", "."],
    &["scan", "--plugin", "p.yaml", "--out-dir", "o"],
    &["run", "--plugin", "p.yaml", "--out-dir", "o"],
    &["apply", "--plan", "p.json"],
    &["resume"],
    &["restore", "--run", "r"],
    &["verify", "--plugin", "p.yaml"],
];

#[test]
fn every_machine_touching_command_refuses_without_privilege() {
    for args in TOUCHES_THE_MACHINE {
        let (code, text) = run_as("no", args);
        assert_eq!(
            code, 5,
            "`{}` 가 권한 없이 시작했다 (가드 중단이어야 한다)\n{text}",
            args[0]
        );
        // **무엇을 하라고 말하는가.** 코드만으로는 사람이 움직이지 못한다.
        assert!(
            text.contains("권한이 필요합니다"),
            "`{}` 의 거절이 이유를 말하지 않는다:\n{text}",
            args[0]
        );
        assert!(
            text.contains("다시 부르십시오"),
            "`{}` 의 거절이 다음 행동을 말하지 않는다:\n{text}",
            args[0]
        );
    }
}

#[test]
fn the_refusal_comes_before_the_arguments_are_judged() {
    // 인자가 틀렸든 맞든 **먼저** 권한을 말한다. 사람이 인자를 고쳐 다시
    // 돌린 뒤에야 권한을 알게 되면 왕복이 한 번 더 는다.
    let (code, text) = run_as("no", &["apply"]);
    assert_eq!(code, 5, "인자 오류가 권한 부족을 가렸다\n{text}");
    assert!(text.contains("권한이 필요합니다"), "{text}");
}

/// **주어진 파일만 만지는 명령은 걸리지 않는다.**
///
/// 분석가는 사내에서 스냅샷으로 룰을 만들고(설계-00 §5), 룰 작성자는 자기
/// PC 에서 `plugin lint` 를 돌린다. 거기에 관리자를 요구하면 그 두 흐름이
/// 통째로 막힌다.
#[test]
fn commands_that_only_touch_given_files_are_not_gated() {
    let missing = work().join("없는파일.yaml");
    let m = missing.to_string_lossy().to_string();
    let cases: Vec<Vec<&str>> = vec![
        vec!["--version"],
        vec!["selftest"],
        vec!["evaluate", "--artifacts", &m, "--plugin", &m, "--out", &m],
        vec!["plan", "--scan", &m, "--plugin", &m, "--out", &m],
        vec!["plugin", "lint", &m],
        vec!["revocation", "verify", "--file", &m],
        vec!["allowlist", "verify", "--file", &m],
    ];
    for args in &cases {
        let (code, text) = run_as("no", args);
        assert_ne!(
            code,
            5,
            "`{}` 가 권한을 요구했다 — 이 명령은 준 파일만 만진다\n{text}",
            args.join(" ")
        );
        assert!(
            !text.contains("권한이 필요합니다"),
            "`{}` 가 권한을 말했다\n{text}",
            args.join(" ")
        );
    }
}

#[test]
fn with_privilege_the_gate_is_out_of_the_way() {
    // 문을 지나면 평소의 실패(인자·파일)가 그대로 나온다. 5 가 아니다.
    let (code, text) = run_as("yes", &["apply", "--plan", "없는계획.json"]);
    assert_ne!(code, 5, "권한이 있는데도 가드가 막았다\n{text}");
}
