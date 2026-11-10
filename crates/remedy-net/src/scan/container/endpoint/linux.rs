//! 리눅스 — 소켓을 쥔 프로세스로 엔진을 가린다. `/proc` 의 뿌리는 바꿔 끼울 수 있다([`super::Host`]).
//!
//! 차례는 스캐너와 같다: 소켓 경로의 링크를 따르고 → 소켓 파일인지 보고 → `/proc/net/unix` 에서 그 경로로 연결을
//! **받고 있는** 소켓(`00010000` · `0001`)의 inode 를 모으고 → `/proc` 의 프로세스 목록 → `/proc/mounts` 에
//! `hidepid` 가 켜져 있으면 멈춘다(숨은 프로세스가 소켓을 쥐고 있을 수 있다) → 모든 프로세스의 파일 디스크립터에서
//! 그 inode 를 쥔 프로세스를 찾는다. 읽지 못한 프로세스가 하나라도 있으면 멈추고(다른 프로세스의 디스크립터는
//! root 만 읽는다), 디스크립터 100,000개를 넘으면 멈춘다. 연결을 맺을 때마다 이 확인을 다시 한다.
//!
//! # 접속하는 조건 (2026-11-10 사용자 결정 — 스캐너와 다른 단 하나)
//!
//! 그 inode 를 쥔 프로세스 가운데
//!
//! 1. 엔진이 하나 있다 — 실행 파일 이름이 정확히 `dockerd`(Docker), 또는 `podman` 이고 인자에 `system` `service` 가
//!    잇달아 있다(Podman). 그리고
//! 2. 엔진 밖의 프로세스는 모두 실행 파일 이름이 정확히 `systemd` 다(PID 1 또는 사용자 관리자).
//!
//! 엔진이 쥐지 않았으면(systemd 만 쥐었거나 아무도 쥐지 않았으면) *"엔진이 실행 중이 아니고, 접속하면 엔진이 시작될
//! 수 있어 접속하지 않았다"* 로 멈춘다. 그 밖의 프로세스가 쥐었으면 멈춘다.
//!
//! **까닭.** 스캐너는 소켓 활성화를 쓰는 엔진(인자의 `fd://` · 0 이 아닌 `LISTEN_FDS`)과, 다른 프로세스와 함께 쥔
//! 소켓을 모두 거절했다. 그런데 표준 설치가 바로 그 모양이다 — moby 의 `contrib/init/systemd/docker.service` 는
//! `ExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock` 에 `Requires=docker.socket`
//! 이고 docker.socket 은 `ListenStream=/run/docker.sock` 이다. Podman 은 `podman.socket` 과 `podman ... system
//! service` 를 돌리는 `podman.service` 다. 그대로 두면 표준 설치를 모두 거절한다. systemd 가 함께 쥐는 것은 그
//! 활성화 소켓이고, 엔진이 그 소켓을 쥐고 있으면 엔진은 이미 떠 있다 — 접속이 엔진을 띄우지 않는다.
//!
//! **받아들인 남은 위험.** 확인과 연결 사이에 엔진이 죽으면, 그 연결이 systemd 의 활성화로 엔진을 다시 띄울 수
//! 있다. 연결마다 확인을 다시 하지만 그 틈은 닫지 못한다.

use super::{EngineKind, Host};
use crate::scan::container::failure::{EndpointFailure, Failure};
use crate::scan::slashpath;
use std::collections::BTreeSet;
use std::io;

/// 모든 프로세스를 합친 파일 디스크립터 수의 상한.
const MAX_FDS: usize = 100_000;

/// 그 소켓에서 독립적으로 떠 있는 엔진의 종류.
pub(crate) fn verify(path: &str, host: &dyn Host) -> Result<EngineKind, Failure> {
    let name = host
        .resolve(path)
        .map_err(|_| EndpointFailure::SocketMissing)?;
    if !host.is_socket(&name).unwrap_or(false) {
        return Err(EndpointFailure::NotSocket.into());
    }
    let inodes = listening_inodes(host, &name)?;
    let pids = process_ids(host)?;
    check_hidepid(host)?;
    let holders = holders(host, &pids, &inodes)?;
    decide(host, &holders)
}

/// `/proc/net/unix` 에서 그 경로로 연결을 받고 있는 소켓의 `socket:[inode]`.
fn listening_inodes(host: &dyn Host, name: &str) -> Result<BTreeSet<String>, Failure> {
    let data = host
        .proc_read("net/unix")
        .map_err(|_| EndpointFailure::SocketTable)?;
    let mut inodes = BTreeSet::new();
    for line in String::from_utf8_lossy(&data).lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 8 || fields[3] != "00010000" || fields[4] != "0001" {
            continue;
        }
        if host.resolve(fields[7]).is_ok_and(|p| p == name) {
            inodes.insert(format!("socket:[{}]", fields[6]));
        }
    }
    if inodes.is_empty() {
        return Err(EndpointFailure::NotListening.into());
    }
    Ok(inodes)
}

/// `/proc` 의 숫자 이름들.
fn process_ids(host: &dyn Host) -> Result<Vec<String>, Failure> {
    let names = host.proc_list("").map_err(|_| EndpointFailure::ProcList)?;
    Ok(names
        .into_iter()
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .collect())
}

/// `/proc` 이 `hidepid` 로 걸려 있으면 다른 프로세스를 다 볼 수 없다.
fn check_hidepid(host: &dyn Host) -> Result<(), Failure> {
    let mounts = host
        .proc_read("mounts")
        .map_err(|_| EndpointFailure::ProcMounts)?;
    for line in String::from_utf8_lossy(&mounts).split('\n') {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[1] != "/proc" {
            continue;
        }
        let hidden = fields[3]
            .split(',')
            .any(|o| o.starts_with("hidepid=") && o != "hidepid=0");
        if hidden {
            return Err(EndpointFailure::HidePid.into());
        }
    }
    Ok(())
}

/// 그 inode 를 쥔 프로세스 — 사라진 프로세스는 건너뛰고, 읽지 못한 것은 멈춘다.
fn holders(
    host: &dyn Host,
    pids: &[String],
    inodes: &BTreeSet<String>,
) -> Result<Vec<String>, Failure> {
    let mut entries = 0usize;
    let mut found = Vec::new();
    for pid in pids {
        let fds = match host.proc_list(&format!("{pid}/fd")) {
            Ok(fds) => fds,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(EndpointFailure::FdPermission.into()),
        };
        let mut holds = false;
        for fd in fds {
            entries += 1;
            if entries > MAX_FDS {
                return Err(EndpointFailure::FdLimit.into());
            }
            match host.proc_link(&format!("{pid}/fd/{fd}")) {
                Ok(target) => holds |= inodes.contains(&target),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(EndpointFailure::FdUnreadable.into()),
            }
        }
        if holds {
            found.push(pid.clone());
        }
    }
    Ok(found)
}

/// 소켓을 쥔 프로세스 하나의 갈래.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holder {
    Engine(EngineKind),
    Systemd,
    /// 확인하는 사이에 끝났다 — 그 디스크립터도 닫혔다.
    Gone,
    Other,
}

/// 모듈 머리의 조건.
fn decide(host: &dyn Host, holders: &[String]) -> Result<EngineKind, Failure> {
    let mut engines = Vec::new();
    for pid in holders {
        match holder(host, pid)? {
            Holder::Engine(kind) => engines.push(kind),
            Holder::Systemd | Holder::Gone => {}
            Holder::Other => return Err(EndpointFailure::SharedListener.into()),
        }
    }
    match engines.as_slice() {
        [] => Err(EndpointFailure::EngineNotRunning.into()),
        [kind] => Ok(*kind),
        _ => Err(EndpointFailure::SharedListener.into()),
    }
}

fn holder(host: &dyn Host, pid: &str) -> Result<Holder, Failure> {
    let exe = match host.proc_link(&format!("{pid}/exe")) {
        Ok(exe) => exe,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Holder::Gone),
        Err(_) => return Err(EndpointFailure::FdUnreadable.into()),
    };
    Ok(match slashpath::base(&exe) {
        "dockerd" => Holder::Engine(EngineKind::Docker),
        "systemd" => Holder::Systemd,
        "podman" => {
            let cmdline = host
                .proc_read(&format!("{pid}/cmdline"))
                .map_err(|_| EndpointFailure::FdUnreadable)?;
            if podman_service(&cmdline) {
                Holder::Engine(EngineKind::Podman)
            } else {
                Holder::Other
            }
        }
        _ => Holder::Other,
    })
}

/// `podman ... system service ...` — NUL 로 가른 인자에 `system` `service` 가 잇달아 있다.
fn podman_service(cmdline: &[u8]) -> bool {
    let text = String::from_utf8_lossy(cmdline);
    let text = text.strip_suffix('\0').unwrap_or(&text);
    let args: Vec<&str> = text.split('\0').collect();
    args.windows(2).any(|w| w == ["system", "service"])
}

/// 컨테이너의 주 프로세스가 고른 제품의 실행 파일인가 — 엔진이 알린 PID 의 cgroup 에 컨테이너 ID 가 있고, 그 실행
/// 파일 이름이 PHP · Node.js 의 꼴이면 그 경로(스캐너 `process_unix.go`).
pub(crate) fn main_process_exe(host: &dyn Host, id: &str, pid: i64) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    let cgroup = host.proc_read(&format!("{pid}/cgroup")).ok()?;
    if !String::from_utf8_lossy(&cgroup).contains(id) {
        return None;
    }
    host.proc_link(&format!("{pid}/exe")).ok()
}
