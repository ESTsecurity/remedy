//! `restore --list` — 창을 닫아도 되돌릴 회차를 다시 찾을 수 있다.
//!
//! 마무리 표가 알려 준 실행 번호를 사람이 옮겨 적어야 했고, 창을 닫으면 그것을
//! 다시 찾을 길이 없었다. 오탐을 되돌리는 것은 이 도구가 가장 확실하게 잘해야
//! 하는 일이라, 그 능력이 화면을 닫는 순간 사라지면 안 된다.
//!
//! **인자 없는 `restore` 의 의미는 바뀌지 않는다** — 지금까지처럼 사용법 오류(4)다.
//! 무인 배포가 읽는 계약이라 새 기능이 그것을 건드리면 안 된다.

use std::path::{Path, PathBuf};
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_remedy");

fn work(name: &str) -> PathBuf {
    let d = std::env::temp_dir()
        .join("remedy-cli-restore-list")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("작업 디렉터리");
    d
}

/// stdout + stderr + 종료 코드.
fn run(args: &[&str]) -> (String, i32) {
    let out = Command::new(EXE)
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        // 시험은 한국어 문구를 단정한다. 기본 언어는 영어다.
        .env("REMEDY_LANG", "ko")
        .output()
        .unwrap_or_else(|e| panic!("{EXE} 실행 실패: {e}"));
    (
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        out.status.code().unwrap_or(-1),
    )
}

/// `.evil` 하나를 겨누는 최소 플러그인. 경로는 대상 트리다.
fn plugin(dir: &Path, tree: &Path) -> PathBuf {
    let p = dir.join("plugin.yaml");
    // YAML 작은따옴표는 역슬래시를 그대로 둔다 — Windows 경로가 그대로 들어간다.
    let body = format!(
        "schema_version: 1\n\
         id: restore-list-demo\n\
         version: 1.0.0\n\
         min_core: '1.0.0'\n\
         platforms: [windows, linux]\n\
         name: {{ ko: '목록 시험', en: 'list demo' }}\n\
         scan_roots: ['{}']\n\
         subjects: [file]\n\
         detect:\n\
         \x20 - id: junk\n\
         \x20   subject: file\n\
         \x20   where:\n\
         \x20     - {{ field: path, op: ends_with, value: '.evil' }}\n\
         verdict:\n\
         \x20 require: 'junk'\n\
         remediate:\n\
         \x20 remove:\n\
         \x20   - {{ ref: junk }}\n",
        tree.display()
    );
    std::fs::write(&p, body).expect("플러그인");
    p
}

/// 치료를 한 번 돌려 격리물 하나를 만든다. 그 실행 번호를 돌려준다.
fn treat_once(dir: &Path, state: &Path, n: usize) -> String {
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).expect("트리");
    std::fs::write(tree.join(format!("a{n}.evil")), format!("junk-{n}")).expect("검체");
    let p = plugin(dir, &tree);
    let out_dir = dir.join(format!("out{n}"));
    let (text, code) = run(&[
        "run",
        "--plugin",
        p.to_str().unwrap(),
        "--out-dir",
        out_dir.to_str().unwrap(),
        "--yes",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "치료가 서지 않았다:\n{text}");
    let plan = std::fs::read_to_string(out_dir.join("plan.json")).expect("계획");
    let v: serde_json::Value = serde_json::from_str(&plan).expect("JSON");
    v["run_id"].as_str().expect("run_id").to_string()
}

#[test]
fn the_list_names_every_run_that_can_be_undone() {
    let dir = work("two");
    let state = dir.join("state");
    let a = treat_once(&dir, &state, 1);
    let b = treat_once(&dir, &state, 2);
    assert_ne!(a, b, "두 회차가 같은 번호를 받았다");

    let (text, code) = run(&["restore", "--list", "--state-dir", state.to_str().unwrap()]);
    assert_eq!(code, 0, "목록은 읽기만 한다:\n{text}");
    for id in [&a, &b] {
        assert!(text.contains(id.as_str()), "{id} 가 목록에 없다:\n{text}");
    }
    assert!(text.contains("되돌릴 수 있는 회차 2건"), "{text}");
    // 목록이 곧바로 다음 명령을 준다 — 사람이 번호를 옮겨 적지 않아도 된다.
    assert!(text.contains("remedy restore --run "), "{text}");
}

#[test]
fn an_empty_place_is_not_an_error() {
    // 치료한 적 없는 기계다. 되돌릴 것이 없는 것은 실패가 아니다.
    let dir = work("empty");
    let state = dir.join("state");
    let (text, code) = run(&["restore", "--list", "--state-dir", state.to_str().unwrap()]);
    assert_eq!(code, 0, "빈 자리를 오류로 냈다:\n{text}");
    assert!(text.contains("되돌릴 수 있는 회차가 없습니다"), "{text}");
    // **뒷문장까지 본다** (2026-10-28). 캡처 시나리오는 치료를 먼저 하므로 이
    // 화면이 기준선에 없고, 머리말만 보던 이 단정은 뒤를 고쳐도 통과했다 —
    // 실제로 그날 `이 자리에` 를 `이 폴더에` 로 고치는데 아무것도 울지 않았다.
    assert!(
        text.contains("이 폴더에 격리물이 하나도 없습니다"),
        "{text}"
    );
}

#[test]
fn one_broken_container_does_not_hide_the_others() {
    // **깨진 것 하나 때문에 멀쩡한 나머지를 되돌리지 못하면 안 된다.**
    let dir = work("broken");
    let state = dir.join("state");
    let good = treat_once(&dir, &state, 1);
    std::fs::write(
        state
            .join("quarantine")
            .join("run-9999999999-dead-beefcafe.rq"),
        b"not a container at all",
    )
    .expect("깨진 격리물");

    let (text, code) = run(&["restore", "--list", "--state-dir", state.to_str().unwrap()]);
    assert_eq!(code, 0, "깨진 것 하나가 목록을 세웠다:\n{text}");
    assert!(
        text.contains(good.as_str()),
        "멀쩡한 것이 사라졌다:\n{text}"
    );
    // 조용히 빠지지 않는다 — 못 읽었으면 못 읽었다고 말한다.
    assert!(text.contains("읽지 못한 격리물"), "{text}");
    assert!(text.contains("run-9999999999-dead-beefcafe.rq"), "{text}");
}

#[test]
fn calling_restore_with_no_arguments_still_means_usage_error() {
    // **계약을 바꾸지 않는다.** 무인 배포가 4 를 "내가 잘못 불렀다" 로 읽는다.
    let dir = work("noargs");
    let state = dir.join("state");
    let (text, code) = run(&["restore", "--state-dir", state.to_str().unwrap()]);
    assert_eq!(
        code, 4,
        "인자 없는 restore 의 종료 코드가 바뀌었다:\n{text}"
    );
    // 다만 어디로 가면 되는지는 말해 준다.
    assert!(text.contains("restore --list"), "{text}");
}
