//! 진입 대기의 불변식 (사용자 친화성 회차 Phase 0).
//!
//! 앞으로 **인자 없이 + stdin 이 터미널이면** 사용법 뒤에 키 입력을 기다리게 된다 —
//! 더블클릭한
//! 사람이 검은 창의 깜빡임만 보고 끝나지 않게. 그 변경이 지켜야 하는 것을
//! **지금 코드에서 먼저 잠근다.**
//!
//! - stdin 이 터미널이 아니면 인자가 없어도 기다리지 않는다. 무인 배포·시험·
//!   `Command::output()` 이 그 조건이다.
//! - 인자가 하나라도 있으면 stdin 이 무엇이든 기다리지 않는다. RunOnce 의
//!   `verify …` 가 그 조건이고, 거기서 기다리면 재부팅 뒤 창이 영원히 떠 있다
//!   (불변식 I6).
//!
//! `Stdio::null()` 로는 못 잰다 — 닫힌 stdin 에서 `read_line` 은 곧바로 0 을
//! 돌려주므로 **기다리는 코드도 통과한다.** 열어 둔 파이프라야 걸린다: 터미널이
//! 아니면서 EOF 도 오지 않으므로, 게이트 없이 읽는 코드는 여기서 선다.

use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const EXE: &str = env!("CARGO_BIN_EXE_remedy");

/// 자기무결성 확인(실행 파일 읽기)과 플러그인 적재를 넉넉히 덮는다. 기다리는 코드는
/// 이 안에 끝나지 않는다 — 그것이 잰다는 것의 전부다.
const DEADLINE: Duration = Duration::from_secs(30);

/// stdin 을 파이프로 열고 **닫지 않는다.** 돌려받은 핸들을 살려 두는 동안 자식은
/// EOF 를 받지 못한다.
fn spawn_with_open_stdin(args: &[&str]) -> (Child, ChildStdin) {
    let mut child = Command::new(EXE)
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        .env("REMEDY_LANG", "ko")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("{EXE} 실행 실패: {e}"));
    let stdin = child.stdin.take().expect("파이프");
    (child, stdin)
}

/// 기한 안에 끝나면 그 상태를, 아니면 죽이고 `None`.
fn wait_until(child: &mut Child, deadline: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            return Some(st);
        }
        if start.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn no_arguments_exit_at_once_when_stdin_is_not_a_terminal() {
    let (mut child, stdin) = spawn_with_open_stdin(&[]);
    let st = wait_until(&mut child, DEADLINE);
    drop(stdin);
    let st =
        st.expect("인자 없는 실행이 터미널 아닌 stdin 앞에서 기다린다 — 무인 배포가 여기서 선다");
    assert_eq!(
        st.code(),
        Some(0),
        "인자 없이 부르면 사용법을 보이고 0 이다"
    );
}

#[test]
fn the_reboot_verify_shape_never_waits() {
    // RunOnce 가 심는 명령의 모양이다 (`scheduled_verify.rs` 가 그 문자열 자체를
    // 잰다). 없는 run 이라 실패하는 것이 정상이고, 여기서 재는 것은 **끝난다**는
    // 사실뿐이다 — 종료 코드는 그 시험의 몫이다.
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
    let plugin = plugin.to_string_lossy().to_string();

    let (mut child, stdin) = spawn_with_open_stdin(&[
        "verify",
        "--run",
        "run-does-not-exist",
        "--plugin",
        &plugin,
        "--lang",
        "ko",
    ]);
    let st = wait_until(&mut child, DEADLINE);
    drop(stdin);
    let st =
        st.expect("재부팅 회차의 verify 가 stdin 앞에서 기다린다 — 재부팅 뒤 창이 영원히 떠 있다");
    assert!(st.code().is_some(), "시그널로 죽었다: {st}");
}

#[test]
fn version_and_help_never_wait() {
    // 인자가 있는 가장 흔한 두 호출. 안내 모드의 게이트가 "인자 0개" 라는 사실을
    // 이 둘이 지킨다.
    for args in [&["--version"][..], &["--help"][..]] {
        let (mut child, stdin) = spawn_with_open_stdin(args);
        let st = wait_until(&mut child, DEADLINE);
        drop(stdin);
        let st = st.unwrap_or_else(|| panic!("{args:?} 가 stdin 앞에서 기다린다"));
        assert_eq!(st.code(), Some(0), "{args:?}");
    }
}
