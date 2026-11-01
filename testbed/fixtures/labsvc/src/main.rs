//! SCM 복구 동작 픽스처 — **진짜로 도는 서비스** (설계-09 P8).
//!
//! # 왜 진짜 서비스여야 하는가
//!
//! 재려는 것은 *"서비스 복구 동작을 남긴 채 종료하면 SCM 이 되살리는 것"* 이다
//! (설계-09 P8). 되살릴 대상이 있으려면 서비스가 **RUNNING 에 도달해야** 하고,
//! 그러려면 SCM 핸드셰이크를 해야 한다.
//!
//! 처음 판은 `binPath = cmd.exe /c exit 1` 이었다. 그것은 핸드셰이크를 하지
//! 않아 1053 으로 시작에 실패하고, **되살릴 것이 애초에 없다.** 그래서 그때의
//! 검사는 "복구 동작이 설정돼 있다" 까지만 볼 수 있었고 — 그것은 전제이지
//! 재현이 아니다.
//!
//! # `forbid(unsafe_code)` 가 없는 유일한 자리
//!
//! `define_windows_service!` 가 SCM 이 부르는 `extern "system"` 진입점을
//! 만들어 내고, 그 안에서 raw argv 를 다룬다. **제품 크레이트 18종은 전부
//! `forbid` 를 유지한다** — 이것은 워크스페이스 밖의 실험 픽스처다.
//!
//! # 남지 않는다
//!
//! 서비스는 기계에 등록되는 것이라 프로세스보다 오래 남을 수 있다. 두 겹으로
//! 묶는다.
//!
//! 1. **마감 시각** — 넘기면 스스로 STOPPED 를 보고하고 나간다. *깨끗하게*
//!    나가는 것이 요점이다 — 보고 없이 죽으면 SCM 이 크래시로 보고 되살린다
//! 2. **표식** — 로그 파일 이름에 표식이 들어가 정리가 정확하다
//!
//! 등록 자체를 지우는 것은 하네스의 몫이다(`sc delete`, `finally` 블록).

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

const NAME: &str = "remedy-lab-p8";

define_windows_service!(ffi_service_main, service_main);

fn main() -> Result<(), windows_service::Error> {
    // **SCM 이 부른 것이 아니면 여기서 거절당한다** (오류 1063). 그 거절이
    // "이것은 진짜 서비스다" 의 증거이고, 하네스가 관리자 권한 없이도 확인할
    // 수 있는 유일한 성질이다.
    service_dispatcher::start(NAME, ffi_service_main)
}

fn service_main(_args: Vec<OsString>) {
    // 여기서 실패해도 알릴 곳이 없다 — SCM 은 상태로만 듣는다. 그래서
    // `run` 안에서 상태를 먼저 세우고 시작한다.
    let _ = run();
}

struct Args {
    dir: PathBuf,
    marker: String,
    deadline: u64,
    /// 정지 요청을 받고 **핸들러 안에서** 이만큼 붙든다 (초). 0 이면 즉시.
    ///
    /// # 무엇을 재려고 두는가
    ///
    /// remedy 는 오래 도는 외부 도구를 **끊지 않는다**(결정 2026-09-07). 상한
    /// (`sc.exe` 60초)은 죽이는 시점이 아니라 **알리는 시점**이다. 그 자리를
    /// 재려면 `sc.exe stop` 이 60초를 넘겨야 하는데, 정상 서비스는 즉시
    /// 멈추므로 랩에서 그 상황이 생기지 않는다.
    ///
    /// **`ControlService` 는 서비스의 제어 핸들러가 돌아올 때까지 막힌다.**
    /// 그래서 핸들러 안에서 자면 `sc.exe stop` 이 그만큼 붙들린다 — 그것이
    /// 악성 서비스나 망가진 드라이버가 실제로 만드는 모양이기도 하다.
    stop_delay: u64,
}

/// 명령줄에서 인자를 읽는다.
///
/// SCM 이 `service_main` 에 넘기는 인자가 아니라 **프로세스 명령줄**을 본다 —
/// `binPath` 에 적은 것이 그대로 여기 있고, 복구 동작으로 다시 뜰 때도 같다.
fn parse() -> Option<Args> {
    let a: Vec<String> = std::env::args().collect();
    let get = |k: &str| -> Option<String> {
        a.iter()
            .position(|x| x == k)
            .and_then(|i| a.get(i + 1))
            .cloned()
    };
    Some(Args {
        dir: PathBuf::from(get("--dir")?),
        marker: get("--marker")?,
        deadline: get("--deadline")?.parse().ok()?,
        // 없으면 0 — 기존 하네스는 이 인자를 주지 않는다.
        stop_delay: get("--stop-delay-secs")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn run() -> Result<(), windows_service::Error> {
    let (tx, rx) = mpsc::channel::<()>();
    // **인자를 핸들러보다 먼저 읽는다.** 핸들러는 SCM 스레드에서 돌고, 거기서
    // 다시 명령줄을 파싱하면 그 비용이 정지 시간에 섞인다.
    let stop_delay = parse().map(|a| a.stop_delay).unwrap_or(0);
    let handle = service_control_handler::register(NAME, move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop => {
            // **여기서 자는 것이 요점이다.** `ControlService`(= `sc.exe stop`)는
            // 이 함수가 돌아올 때까지 막힌다. 밖에서 자면 `sc.exe stop` 은 곧
            // 돌아오고 서비스만 천천히 멈춘다 — 그러면 아무것도 재지 못한다.
            //
            // Windows 는 제어 핸들러가 30초 안에 돌아오기를 권하지만 강제하지
            // 않는다. 여기서 넘기는 것은 **일부러 만든 병든 서비스**이고,
            // 재려는 것은 remedy 가 그것을 죽이지 않고 기다리는가다.
            if stop_delay > 0 {
                std::thread::sleep(Duration::from_secs(stop_delay));
            }
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    let status = |state: ServiceState, accept: ServiceControlAccept| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };

    handle.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP))?;

    // **시작을 한 줄 남긴다.** 하네스는 이 줄이 늘어나는 것으로 "SCM 이
    // 되살렸다" 를 판정한다 — 서비스 상태만 보면 재시작을 놓칠 수 있다.
    if let Some(a) = parse() {
        let _ = std::fs::create_dir_all(&a.dir);
        let line = format!("{} pid={}\n", now_ms(), std::process::id());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(a.dir.join(format!("{}-service.log", a.marker)))
        {
            let _ = f.write_all(line.as_bytes());
        }
        while now() < a.deadline {
            if rx.recv_timeout(Duration::from_millis(200)).is_ok() {
                break;
            }
        }
    } else {
        // 인자가 없으면 오래 붙들고 있을 이유가 없다. 곧 STOPPED 를 보고한다.
        let _ = rx.recv_timeout(Duration::from_secs(5));
    }

    // **깨끗하게 나간다.** 보고 없이 죽으면 SCM 이 크래시로 보고 복구 동작을
    // 건다 — 마감으로 나가는 것이 되살림을 유발하면 안 된다.
    handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))?;
    Ok(())
}
