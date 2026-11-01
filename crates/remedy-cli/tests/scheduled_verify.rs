//! 재부팅 뒤 예약되는 명령이 **실제로 실행 가능한가** (설계-03 §8, P10-F).
//!
//! # 왜 이 시험이 뒤늦게 생겼는가
//!
//! P10-F 의 단위 시험은 `schedule_verify_after_reboot` 가 레지스트리 값을
//! **쓰는지**를 쟀다. 그 값이 **실행 가능한 명령인지**는 아무도 묻지 않았고,
//! 그래서 `--plugin` 이 빠진 채 P10 이 닫혔다.
//!
//! 실측(2026-08-28 v1 점검): 예약되던 것은 `"<exe>" verify --run <id>` 였고,
//! `verify` 는 `--plugin` 을 필수로 받는다. 재부팅 뒤 그 명령은
//! **사용법 오류로 즉시 끝난다.** RunOnce 는 콘솔 없이 돌고 OS 가 항목을 먼저
//! 지우므로 아무 흔적도 남지 않는다 — 두 달을 그 상태로 보낼 수 있었다.
//!
//! # 무엇을 재는가
//!
//! **문자열을 만들어 그대로 실행한다.** 인자 목록을 손으로 다시 적으면 그것은
//! 예약되는 것과 다른 것을 재는 시험이 된다.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    // 통합 시험 바이너리 옆에 제품 바이너리가 선다.
    let mut p = std::env::current_exe().expect("내 경로");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(format!("remedy{}", std::env::consts::EXE_SUFFIX))
}

/// 따옴표를 아는 최소 분해기. `RunOnce` 에 들어가는 명령줄과 같은 규칙이다 —
/// 큰따옴표로 감싼 조각은 공백을 품는다.
fn split_command(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[test]
fn the_scheduled_command_splits_back_into_the_exe_and_its_arguments() {
    // 공백이 든 경로가 이 검사의 요점이다. 따옴표가 빠지면 RunOnce 가 첫
    // 공백에서 잘라 읽고, 그러면 아무것도 실행되지 않는다.
    let cmd = remedy_core::restart::scheduled_verify_command(
        Path::new(r"C:\Program Files\remedy\remedy.exe"),
        "run-1",
        Path::new(r"C:\my rules\plugin.yaml"),
        Some(Path::new(r"D:\lab state")),
        remedy_sdk::i18n::Lang::Ko,
    );
    let parts = split_command(&cmd);
    assert_eq!(parts[0], r"C:\Program Files\remedy\remedy.exe", "{cmd}");
    assert_eq!(parts[1], "verify");
    assert!(parts.contains(&"--plugin".to_string()), "{cmd}");
    assert!(
        parts.contains(&r"C:\my rules\plugin.yaml".to_string()),
        "{cmd}"
    );
    assert!(parts.contains(&r"D:\lab state".to_string()), "{cmd}");
    // **언어를 싣는다.** 재부팅 회차는 환경을 물려받지 못하므로, 싣지 않으면
    // 한 회차의 로그가 앞은 한국어 뒤는 영어가 된다 (실측 2026-09-07 P10-F).
    assert!(parts.contains(&"--lang".to_string()), "{cmd}");
    assert!(parts.contains(&"ko".to_string()), "{cmd}");
}

#[test]
fn the_scheduled_command_names_the_language_it_was_run_in() {
    for (lang, id) in [
        (remedy_sdk::i18n::Lang::Ko, "ko"),
        (remedy_sdk::i18n::Lang::En, "en"),
    ] {
        let cmd = remedy_core::restart::scheduled_verify_command(
            Path::new(r"C:\remedy\remedy.exe"),
            "run-1",
            Path::new(r"C:\p\plugin.yaml"),
            None,
            lang,
        );
        let parts = split_command(&cmd);
        let i = parts.iter().position(|p| p == "--lang").expect(&cmd);
        assert_eq!(parts[i + 1], id, "{cmd}");
    }
}

#[test]
fn the_scheduled_command_actually_runs() {
    // **예약된 문자열을 그대로 실행한다.**
    //
    // 여기서 재는 것은 치료 결과가 아니라 *"이 명령이 CLI 에 받아들여지는가"* 다.
    // 없는 run 을 주므로 실패하는 것이 정상이고, **그 실패가 사용법 오류이면
    // 안 된다** — 사용법 오류는 재부팅 뒤 아무 검증도 일어나지 않는다는 뜻이다.
    let plugin = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("저장소 루트")
        .join("testbed/harness/guest/lab-plugin.yaml");
    assert!(
        plugin.is_file(),
        "실험용 플러그인이 없다: {}",
        plugin.display()
    );

    let cmd = remedy_core::restart::scheduled_verify_command(
        &bin(),
        "run-does-not-exist",
        &plugin,
        None,
        remedy_sdk::i18n::Lang::Ko,
    );
    let parts = split_command(&cmd);
    let out = Command::new(&parts[0])
        .args(&parts[1..])
        .env("REMEDY_ELEVATION", "yes")
        // **환경변수를 주지 않는다.** 재부팅 회차가 그렇다 — 언어는 명령에 실린
        // `--lang` 만으로 정해져야 한다. 아래 단정은 한국어 문구를 본다.
        .env_remove("REMEDY_LANG")
        .output()
        .expect("실행");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !text.contains("옵션이 필요합니다"),
        "예약되는 명령이 사용법 오류로 끝난다 — 재부팅 뒤 아무것도 검증되지 않는다:\n\
         명령: {cmd}\n출력: {text}"
    );
    // 없는 run 이므로 승인된 계획을 못 찾는 것이 정상이다. 그 자리까지
    // 갔다는 것이 곧 인자가 전부 받아들여졌다는 뜻이다.
    assert!(
        text.contains("승인된 계획") || text.contains("plan"),
        "인자는 통과했는데 예상과 다른 곳에서 끝났다:\n명령: {cmd}\n출력: {text}"
    );
}
