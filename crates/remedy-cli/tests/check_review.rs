//! 점검 룰의 *확인 필요* — `verdict.unconfirmed` (2026-11-09 · 코어 1.3.0).
//!
//! 바이너리를 실제로 띄운다. 평가기 · 관측 · 종료 코드 · 화면이 **한 줄로 이어져야** 뜻이 있다 —
//! 평가기가 사유를 실어도 합치는 자리(`remedy-core`)가 버리면 0 이 나가고, 종료 코드가 6 이어도
//! 화면이 *"다 보지 못해"* 라고 하면 다 본 사람에게 틀린 말을 한다.

use std::path::{Path, PathBuf};
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_remedy");

const WHY_KO: &str = "앱이 고친 판인지 가릴 근거가 없습니다";

fn work(name: &str) -> PathBuf {
    let d = std::env::temp_dir()
        .join("remedy-cli-check-review")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("작업 디렉터리");
    d
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let out = Command::new(EXE)
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        // 시험은 한국어 문구를 단정한다. 기본 언어는 영어다 (2026-09-06).
        .env("REMEDY_LANG", "ko")
        .output()
        .unwrap_or_else(|e| panic!("{EXE} 실행 실패: {e}"));
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// 앱 하나가 깔린 자리. `old` 면 *고치기 전* 표식도 함께 둔다.
fn tree(base: &Path, old: bool) -> PathBuf {
    let root = base.join("tree");
    std::fs::create_dir_all(&root).expect("트리");
    std::fs::write(root.join("app.bin"), b"APP").expect("app");
    if old {
        std::fs::write(root.join("old.flag"), b"OLD").expect("old");
    }
    root
}

/// 점검 룰 — 고치기 전 표식이 있으면 취약, 앱만 있으면 `review` 일 때 확인 필요.
fn plugin(base: &Path, root: &Path, review: bool) -> PathBuf {
    let dir = base.join("plug");
    std::fs::create_dir_all(&dir).expect("플러그인 디렉터리");
    let unconfirmed = if review {
        format!(
            "  unconfirmed:\n    - when: 'present'\n      why: {{ ko: '{WHY_KO}', en: 'no basis to tell whether the app is fixed' }}\n"
        )
    } else {
        String::new()
    };
    let p = dir.join("plugin.yaml");
    std::fs::write(
        &p,
        format!(
            r#"schema_version: 1
id: check-review-test
version: 1.0.0
min_core: '1.3.0'
platforms: [windows, linux]
kind: check
name: {{ ko: '확인 필요 시험', en: 'review test' }}
scan_roots: ['{root}']
subjects: [file]
detect:
  - id: present
    subject: file
    where:
      - {{ field: path, op: ends_with, value: 'app.bin' }}
  - id: old
    subject: file
    where:
      - {{ field: path, op: ends_with, value: 'old.flag' }}
verdict:
  require: 'old'
{unconfirmed}"#,
            root = root.display()
        ),
    )
    .expect("plugin.yaml");
    p
}

fn scan(base: &Path, plugin: &Path) -> (Run, serde_json::Value) {
    let out = base.join("out");
    std::fs::create_dir_all(&out).expect("out");
    let r = run(&[
        "scan",
        "--plugin",
        &plugin.display().to_string(),
        "--out-dir",
        &out.display().to_string(),
    ]);
    let p = out.join("scan.json");
    let s = serde_json::from_slice(&std::fs::read(&p).unwrap_or_else(|e| {
        panic!(
            "{} 를 읽지 못했다: {e}\n{}\n{}",
            p.display(),
            r.stdout,
            r.stderr
        )
    }))
    .expect("json");
    (r, s)
}

#[test]
fn an_app_with_no_fix_evidence_is_review_needed_not_clean() {
    let base = work("review");
    let root = tree(&base, false);
    let (r, s) = scan(&base, &plugin(&base, &root, true));
    assert_eq!(r.code, 6, "{}\n{}", r.stdout, r.stderr);
    // 무엇을 확인할지 — 항목은 표준 출력에 번호와 함께, 까닭은 `주의` 아래 룰의 말로.
    assert!(r.stdout.contains("확인이 필요한 항목:"), "{}", r.stdout);
    assert!(r.stdout.contains("app.bin"), "{}", r.stdout);
    assert!(
        r.stderr
            .contains(&format!("확인이 필요합니다 — {WHY_KO} (1곳)")),
        "{}",
        r.stderr
    );
    // 다 **보았다** — 결과 줄이 *"다 보지 못해"* 라고 하지 않는다.
    assert!(
        r.stdout.contains("확인이 필요합니다. 위에 적은 항목은"),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("다 보지 못해"), "{}", r.stdout);
    // 산출물이 홀로 읽힌다 — 까닭과 그룹이 `scan.json` 에 있다(봉투는 본문을 펴서 싣는다).
    let notes = &s["observation"]["unconfirmed"];
    assert_eq!(notes[0]["why"]["ko"], WHY_KO, "{s}");
    assert_eq!(notes[0]["groups"][0], "g0", "{s}");
}

#[test]
fn a_vulnerable_app_is_still_vulnerable() {
    // **찾은 것이 모르는 것보다 앞선다** — 고치기 전 표식이 있으면 2 다.
    let base = work("found");
    let root = tree(&base, true);
    let (r, s) = scan(&base, &plugin(&base, &root, true));
    assert_eq!(r.code, 2, "{}\n{}", r.stdout, r.stderr);
    assert!(r.stdout.contains("취약합니다."), "{}", r.stdout);
    assert!(
        s["observation"].is_object() && s["observation"]["unconfirmed"].is_null(),
        "판정이 선 그룹을 확인 필요로 셌다: {s}"
    );
}

#[test]
fn without_the_field_the_same_rule_says_what_it_said_before() {
    // 이 칸이 없으면 전과 같다 — 앱만 있는 자리는 0 이고, 산출물에 키조차 없다(불변식 I1).
    let base = work("plain");
    let root = tree(&base, false);
    let (r, s) = scan(&base, &plugin(&base, &root, false));
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("취약한 곳을 찾지 못했습니다."),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("확인이 필요"), "{}", r.stdout);
    assert!(
        s["observation"].is_object() && s["observation"]["unconfirmed"].is_null(),
        "{s}"
    );
}

#[test]
fn run_closes_with_the_review_line_too() {
    // `run` 은 마무리 화면(`render_closing`)이 결과 줄을 짓는다 — 그 길도 같은 말을 해야 한다.
    let base = work("run");
    let root = tree(&base, false);
    let p = plugin(&base, &root, true);
    let out = base.join("out");
    std::fs::create_dir_all(&out).expect("out");
    let state = base.join("state");
    let r = run(&[
        "run",
        "--plugin",
        &p.display().to_string(),
        "--out-dir",
        &out.display().to_string(),
        "--state-dir",
        &state.display().to_string(),
        "--yes",
    ]);
    assert_eq!(r.code, 6, "{}\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("확인이 필요합니다. 위에 적은 항목은"),
        "{}",
        r.stdout
    );
}
