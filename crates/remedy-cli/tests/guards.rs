//! 가드가 **조작 입력**을 막는가 (설계-09 P3 검증, 설계-03 §10 G5).
//!
//! P3 에는 Op 가 없으므로(Op 첫 등장은 P6) 정상 경로로는 파괴 계획이 만들어지지
//! 않는다. 설계-09 §3.5 가 G5·G6·G7 의 최초 의미 Phase 를 P3 으로 두고 비고에
//! **"조작 입력"** 이라 적은 이유가 이것이다.
//!
//! 그래서 여기서는 `scan.json` 을 손으로 지어 `plan` 에 먹인다. 계획기가 무엇을
//! 받든 가드를 통과해야 산출물이 나온다는 성질을 CLI 끝까지 확인한다.

use std::path::PathBuf;
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_remedy");

fn work() -> PathBuf {
    let d = std::env::temp_dir().join("remedy-cli-guards");
    std::fs::create_dir_all(&d).expect("작업 디렉터리");
    d
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(EXE)
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        // 시험은 한국어 문구를 단정한다. 기본 언어는 영어다 (2026-09-06).
        .env("REMEDY_LANG", "ko")
        .output()
        .expect("실행");
    let code = out.status.code().unwrap_or(-1);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (code, text)
}

/// 증거 그룹 `count` 개짜리 scan 봉투를 짓는다.
fn crafted_scan(count: usize) -> serde_json::Value {
    let groups: Vec<serde_json::Value> = (0..count)
        .map(|i| {
            serde_json::json!({
                "id": format!("g{i}"),
                "evidence": [],
                "captures": {},
                "verdict": false
            })
        })
        .collect();
    serde_json::json!({
        "schema_version": 1,
        "kind": "remedy.scan",
        "run_id": "crafted",
        "created": "2026-08-21T00:00:00Z",
        "host": { "hostname": "h", "os": "windows", "version": "10", "arch": "x86_64" },
        "core": { "version": "0.0.0", "build": "test" },
        "plugins": [],
        "evidence": [],
        "groups": groups,
        "verdicts": []
    })
}

fn write_scan(name: &str, v: &serde_json::Value) -> PathBuf {
    let p = work().join(name);
    let mut s = serde_json::to_string_pretty(v).expect("직렬화");
    s.push('\n');
    std::fs::write(&p, s).expect("쓰기");
    p
}

#[test]
fn a_plan_within_limits_is_produced() {
    // 가드가 정상 입력까지 막으면 도구가 아무 쓸모가 없다. 거부 검사보다
    // 이쪽이 먼저다 — 늘 거부하는 가드는 늘 통과하는 가드만큼 쓸모없다.
    let scan = write_scan("ok.json", &crafted_scan(3));
    let out = work().join("ok-plan.json");
    let (code, text) = run(&[
        "plan",
        "--scan",
        scan.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{text}");
    assert!(out.exists(), "계획이 나와야 한다");
}

#[test]
fn g5_group_limit_stops_the_plan_with_exit_five() {
    // 설계-03 §4 의 증거 그룹 상한은 50 이다. 51 개를 만들어 먹인다.
    //
    // **종료 코드가 5 여야 한다.** 4(사용법 오류)로 나가면 무인 배포가
    // "내가 잘못 불렀다" 로 읽고, 실제로는 룰이 과광범위해 폭주 직전이었다는
    // 사실이 묻힌다.
    let scan = write_scan("too-many-groups.json", &crafted_scan(51));
    let out = work().join("blocked-plan.json");
    let (code, text) = run(&[
        "plan",
        "--scan",
        scan.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);

    assert_eq!(code, 5, "안전 가드에 의한 중단이어야 한다. 출력:\n{text}");
    assert!(text.contains("G5"), "어느 게이트인지 말해야 한다:\n{text}");
    assert!(
        text.contains("과광범위"),
        "무엇을 의심해야 하는지 말해야 한다:\n{text}"
    );
    assert!(
        !out.exists(),
        "거부된 계획은 파일로 남으면 안 된다 — 남으면 누군가 그것을 실행한다"
    );
}

#[test]
fn a_non_scan_envelope_is_refused_as_usage_error() {
    // 봉투 종류가 틀린 것은 가드가 막은 것이 아니라 잘못 부른 것이다.
    // 둘을 같은 코드로 내면 구분이 사라진다.
    let mut v = crafted_scan(1);
    v["kind"] = serde_json::json!("remedy.artifacts");
    let scan = write_scan("wrong-kind.json", &v);
    let out = work().join("wrong-kind-plan.json");
    let (code, text) = run(&[
        "plan",
        "--scan",
        scan.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 4, "{text}");
}

// ─────────────────────────────────────────────── 상한 설정 (설계-03 §4)

fn write_config(name: &str, body: &str) -> PathBuf {
    let p = work().join(name);
    std::fs::write(&p, body).expect("설정 쓰기");
    p
}

#[test]
fn a_self_contradictory_config_refuses_to_start() {
    // **기동 거부.** 개별 Action 상한이 실행 전체 상한을 넘으면 총계가
    // 무의미해지고, 어느 쪽이 먼저 걸리는지가 계획 순서에 따라 달라져
    // 재현되지 않는다. 재현되지 않는 안전장치는 안전장치가 아니다.
    let cfg = write_config(
        "contradictory.yaml",
        "limits:\n  total_files: 100\n  recursive_children: 500\n",
    );
    let scan = write_scan("cfg-ok.json", &crafted_scan(1));
    let out = work().join("cfg-plan.json");
    let (code, text) = run(&[
        "plan",
        "--scan",
        scan.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--config",
        cfg.to_str().unwrap(),
    ]);

    // 위협이 아니라 설정 문제다. 5 로 내면 사람이 감염을 찾으러 간다.
    assert_eq!(code, 4, "설정 오류는 사용법 오류다:\n{text}");
    assert!(
        text.contains("재현되지 않습니다"),
        "이유를 말해야 한다:\n{text}"
    );
    assert!(!out.exists(), "거부됐는데 계획이 남으면 안 된다");
}

#[test]
fn a_config_typo_is_refused_rather_than_ignored() {
    // 조용히 무시하면 운영자는 값을 바꿨다고 믿는데 아무것도 바뀌지 않는다.
    let cfg = write_config("typo.yaml", "limits:\n  total_file: 250\n");
    let scan = write_scan("cfg-typo.json", &crafted_scan(1));
    let out = work().join("typo-plan.json");
    let (code, text) = run(&[
        "plan",
        "--scan",
        scan.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--config",
        cfg.to_str().unwrap(),
    ]);
    assert_eq!(code, 4, "{text}");
}

#[test]
fn a_config_can_tighten_a_limit_and_the_guard_uses_it() {
    // 설정이 실제로 가드에 도달하는지 본다. 읽기만 하고 쓰지 않으면
    // "설정을 지원한다" 가 거짓말이 된다.
    let cfg = write_config("tight.yaml", "limits:\n  evidence_groups: 2\n");
    let scan = write_scan("cfg-three-groups.json", &crafted_scan(3));
    let out = work().join("tight-plan.json");
    let (code, text) = run(&[
        "plan",
        "--scan",
        scan.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--config",
        cfg.to_str().unwrap(),
    ]);

    // 기본 상한(50)이었다면 통과했을 입력이다.
    assert_eq!(code, 5, "설정한 상한이 걸려야 한다:\n{text}");
    assert!(
        text.contains("상한은 2개"),
        "설정값이 쓰였는지 보인다:\n{text}"
    );
}

#[test]
fn without_a_config_the_defaults_apply() {
    let scan = write_scan("cfg-none.json", &crafted_scan(3));
    let out = work().join("default-plan.json");
    let (code, text) = run(&[
        "plan",
        "--scan",
        scan.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{text}");
}
