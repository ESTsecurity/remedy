//! 외부 도구를 부르고 **실패 사유를 잃지 않는다** — 그리고 **끊지 않는다**.
//!
//! # 왜 필요한가
//!
//! `sc.exe stop`·`taskkill`·`Checkpoint-Computer`·`update-ca-certificates` 는
//! `.status()` 로 불렸고 stderr 는 `null` 이었다. 실패하면 `종료 코드 1053` 만 남고
//! **1053 이 무슨 뜻인지는 도구가 적었는데 버렸다** (2026-09-06 관측성 검토 §3).
//!
//! # 무엇을 하는가
//!
//! - stdin 은 `null`, stdout 은 `null`, **stderr 는 받는다** — 별도 스레드가
//!   비워 주므로 자식이 파이프가 차서 멈추는 일은 없다.
//! - 도는 동안 [`crate::progress`] 에 "지금 이 도구가 돌고 있다" 를 적어 둔다.
//!   CLI 의 심장박동이 그것을 읽어 `치료 중 · sc.exe stop · 65초` 로 보인다.
//! - 부르는 쪽은 [`Outcome::reason`] 으로 사람이 읽는 사유를 얻는다: 종료 코드와
//!   stderr 의 첫 200자.
//!
//! # 끊지 않는다 (결정 2026-09-07)
//!
//! 처음(Phase 1)에는 60초·300초를 넘기면 자식을 죽였다. 그러나 `sc.exe` 는 요청을
//! SCM 에 넘기고 기다리는 껍데기라 **죽여도 서비스는 멈추는 중**이고, 70초 뒤에
//! 멈췄을 수 있다. 그때 저널에는 "실패" 가 남는다 — 기계는 치료됐는데 도구는
//! 실패라고 말하는 것. 원칙은 "1분만 더 돌면 끝나는 일을 타임아웃으로 끊는 일은
//! 절대로 없어야 한다" 이다. 그래서 상한은 **알리는 시점**이 됐다.
//! 진짜 멈춘 도구는 사람이 끊는다.
//!
//! # 누가 그것을 말하는가 (2026-09-11 에 바로잡았다)
//!
//! 이 주석은 *"[`Outcome::slow`] 가 참이 되고 심장박동이 그 사실을 화면과 회차
//! 로그에 적는다"* 고 적고 있었다. **앞 절반만 참이었다** — `slow` 를 읽는
//! 곳이 이 파일의 시험 말고는 하나도 없었고, 심장박동은 도구 이름과 초만
//! 찍어 `70초` 가 정상인지 넘긴 것인지 구분하지 못했다.
//!
//! 지금은 [`crate::progress::tool_started`] 가 상한을 함께 들고, 심장박동이
//! `Snapshot::tool_over` 를 읽어 `(상한 60초 넘음 — 끊지 않습니다)` 를 붙인다.
//! **끊지 않는다는 말을 같은 줄에 둔다** — 그러지 않으면 사람이 먼저 끊고,
//! 그것이 이 결정이 막으려던 바로 그 일이다.
//!
//! [`Outcome::slow`] 는 **끝난 뒤의 사실**로 남는다. 같은 상한에서 나오므로
//! 둘은 어긋나지 않는다.
//!
//! | 도구 | 알리는 시점 |
//! |---|---|
//! | **`sc.exe`** | **30초** — OS 가 60초에 포기하므로 (아래) |
//! | `taskkill.exe` · `schtasks.exe` · `update-ca-certificates` | 60초 |
//! | `powershell.exe` (`Checkpoint-Computer` 는 정상일 때도 수십 초~분) | 300초 |
//!
//! # `sc.exe` 만 30초인 까닭 (2026-09-12 실측 · 09-13 결정)
//!
//! 정지 제어 핸들러를 70초·150초 붙드는 서비스를 세워 재 보니 **둘 다
//! `sc.exe stop` 이 60.1초에 돌아왔다.** `ControlService` 가 60초에
//! 포기하고 오류 1053(*"빠르게 응답하지 않았습니다"*)을 낸다 — 그리고
//! 그 60초가 [`WARN_SHORT`] 와 **같은 값**이었다. 즉 그 경고는 **영영
//! 뜨지 않았다**: `치료 중 · sc.exe stop · 65초` 는 일어날 수 없는
//! 화면이고 실제 최대는 `59초` 다.
//!
//! 그래서 이 도구만 [`WARN_SC`] (30초)를 쓴다. **SCM 이 손을 떼기
//! 30초 전에** 말해 주고, 뒤따라올 1053 을 예고한다. 실측 화면:
//!
//! ```text
//! 치료 중 · 도구 sc.exe stop 30초 (상한 30초 넘음 — 끊지 않습니다) · 경과 30초
//! ```
//!
//! **끊지 않는다는 결정 자체도 그 회차가 실증했다** — 도구가 60초를
//! 채우는 동안 실행기가 기다렸고, 회차는 60.3초에 끝났으며 서비스는
//! 그 뒤 스스로 멈췄다. `Invoke-SlowStopVerify.ps1` 이 고정한다.
//!
//! # 손자 프로세스
//!
//! 자식이 끝나도 손자가 물려받은 stderr 파이프를 붙들면 배수 스레드는 손자가
//! 끝날 때까지 돌아오지 않는다. 자식의 종료 코드를 받은 뒤 배수 스레드를 **기다리지
//! 않고** 그때까지 모인 것만 쓴다 (시험 `timeout_kills_the_child` 가 처음에 29초
//! 걸려 알게 됐다 — 지금은 죽이지 않지만 같은 이유로 기다리지 않는다).

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 알리는 시점을 시험에서 낮춘다 — `REMEDY_TOOL_WARN_SECS`.
///
/// # 왜 손잡이가 필요한가
///
/// 이 화면은 **상한을 넘겨야만** 나오는데, 랩에서 그것을 진짜로 넘길 수단이
/// 없다. `sc.exe stop` 은 요청을 SCM 에 넘기고 곧 돌아오는 껍데기라 60초를
/// 채우지 못하고, `powershell.exe` 의 상한은 300초다. 재지 못하는 화면은
/// 곧 낡는다 — `REMEDY_HEARTBEAT_SECS` 를 둔 것과 같은 이유다.
///
/// **동작은 바뀌지 않는다.** 이 값은 *말하는 시점*만 앞당긴다. 어떤 값에도
/// 도구를 끊지 않는다(결정 2026-09-07).
fn warn_override() -> Option<Duration> {
    std::env::var("REMEDY_TOOL_WARN_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// 짧은 도구가 이 시간을 넘기면 알린다.
pub const WARN_SHORT: Duration = Duration::from_secs(60);
/// `sc.exe` 만 더 이르다 — **OS 가 60초에 먼저 포기하기 때문이다.**
///
/// `ControlService` 는 서비스의 제어 핸들러를 60초까지만 기다리고 오류
/// 1053 을 낸다(2026-09-12 실측: 정지를 70초·150초 붙들어도 둘 다 60.1초에
/// 돌아왔다). [`WARN_SHORT`] 와 같은 값이라 **그 경고는 영영 뜨지 않았다.**
///
/// 30초면 SCM 이 손을 떼기 **30초 전에** 말해 준다 — 사람이 아직 무엇인가
/// 할 수 있는 시점이고, 그 뒤에 올 1053 을 예고하는 자리이기도 하다.
/// 다른 짧은 도구는 그대로 60초다: 그쪽에는 OS 의 상한이 없다.
pub const WARN_SC: Duration = Duration::from_secs(30);
/// 복원 지점처럼 원래 오래 걸리는 도구가 이 시간을 넘기면 알린다.
pub const WARN_LONG: Duration = Duration::from_secs(300);

/// 자식이 어떻게 끝났는가.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// 종료 코드. 시그널로 죽었으면 `None`.
    pub code: Option<i32>,
    /// 알리는 시점을 넘겼다 — 끝나긴 했다.
    pub slow: bool,
    /// 자식이 stderr 에 적은 것 (UTF-8 이 아니면 대체 문자).
    pub stderr: String,
    /// 걸린 시간.
    pub elapsed: Duration,
}

impl Outcome {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// 사람이 읽는 실패 사유. `what` 은 `sc.exe stop` 처럼 무엇을 불렀는지다.
    pub fn reason(&self, what: &str) -> String {
        let tail = stderr_excerpt(&self.stderr);
        let tail = if tail.is_empty() {
            String::new()
        } else {
            format!(": {tail}")
        };
        match self.code {
            Some(c) => format!(
                "{what} {} {c}){tail}",
                remedy_sdk::i18n::t("가 실패했습니다 (종료 코드", "failed (exit code"),
            ),
            None => format!(
                "{what} {}{tail}",
                remedy_sdk::i18n::t("가 종료 코드 없이 끝났습니다", "ended without an exit code"),
            ),
        }
    }
}

/// stderr 의 첫 200자. 줄바꿈과 겹친 공백은 한 칸으로.
pub fn stderr_excerpt(s: &str) -> String {
    let collapsed: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= 200 {
        return collapsed;
    }
    let cut: String = collapsed.chars().take(200).collect();
    format!("{cut}…")
}

/// `cmd` 를 돌리고 끝날 때까지 기다린다. `label` 은 심장박동이 보일 이름
/// (`sc.exe stop`), `warn_after` 는 알리는 시점. 스폰 자체가 실패하면 `Err`.
pub fn run_tool(mut cmd: Command, label: &str, warn_after: Duration) -> std::io::Result<Outcome> {
    let warn_after = warn_override().unwrap_or(warn_after);
    let started = Instant::now();
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    crate::progress::tool_started(label, warn_after);
    let collected: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    if let Some(mut pipe) = child.stderr.take() {
        let sink = Arc::clone(&collected);
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut b) = sink.lock() {
                            if b.len() < 64 * 1024 {
                                b.extend_from_slice(&chunk[..n]);
                            }
                        }
                    }
                }
            }
        });
    }
    // 끝날 때까지 기다린다 — 죽이지 않는다. 오래 걸리는 것은 심장박동이 말한다.
    let status = child.wait();
    crate::progress::tool_finished();
    let status = status?;
    // 손자가 파이프를 붙들고 있을 수 있어 배수 스레드는 기다리지 않는다. 자식이
    // 끝난 뒤 잠깐 두면 정상 경로의 마지막 조각은 들어온다.
    std::thread::sleep(Duration::from_millis(20));
    let stderr = collected
        .lock()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let elapsed = started.elapsed();
    Ok(Outcome {
        code: status.code(),
        slow: elapsed > warn_after,
        stderr,
        elapsed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    fn shell(script: &str) -> Command {
        let mut c = Command::new("cmd.exe");
        c.args(["/d", "/c", script]);
        c
    }

    #[cfg(unix)]
    fn shell(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.args(["-c", script]);
        c
    }

    #[test]
    fn exit_code_and_stderr_survive() {
        #[cfg(windows)]
        let out = run_tool(shell("echo oops 1>&2 & exit 3"), "t", WARN_SHORT).unwrap();
        #[cfg(unix)]
        let out = run_tool(shell("echo oops 1>&2; exit 3"), "t", WARN_SHORT).unwrap();
        assert_eq!(out.code, Some(3), "{out:?}");
        assert!(!out.slow);
        assert!(out.stderr.contains("oops"), "{:?}", out.stderr);
        let r = out.reason("tool verb");
        assert!(r.contains("3") && r.contains("oops"), "{r}");
    }

    #[test]
    fn success_is_zero() {
        let out = run_tool(shell("exit 0"), "t", WARN_SHORT).unwrap();
        assert!(out.success(), "{out:?}");
    }

    #[test]
    fn a_slow_tool_is_waited_for_not_killed() {
        // 알리는 시점(300ms)을 넘겨도 끝까지 기다린다 — 종료 코드가 온다.
        #[cfg(windows)]
        let cmd = shell("ping -n 3 127.0.0.1 > nul & exit 0");
        #[cfg(unix)]
        let cmd = shell("sleep 1; exit 0");
        let out = run_tool(cmd, "slow", Duration::from_millis(300)).unwrap();
        assert!(out.success(), "{out:?}");
        assert!(out.slow, "{out:?}");
        assert!(
            out.elapsed >= Duration::from_millis(900),
            "{:?}",
            out.elapsed
        );
        // 끝났으니 진행에는 도구가 남아 있지 않다.
        assert!(crate::progress::snapshot().tool.is_empty());
    }

    #[test]
    fn excerpt_is_bounded_and_flat() {
        let long = "a\n".repeat(500);
        let e = stderr_excerpt(&long);
        assert!(e.chars().count() <= 201, "{}", e.len());
        assert!(!e.contains('\n'));
        assert!(e.ends_with('…'));
        assert_eq!(stderr_excerpt("  x \r\n y  "), "x y");
    }
}
