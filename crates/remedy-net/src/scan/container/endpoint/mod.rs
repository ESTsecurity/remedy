//! 엔진 주소와 엔진 확인 — 접속하기 **전에**, 그리고 연결을 맺을 때마다 다시 본다.
//!
//! 스캐너 `endpoint_unix.go` · `endpoint_windows.go` 를 옮겼다. 주소는 이 OS 의 로컬 자리 하나뿐이다 — 리눅스는
//! `unix:///…` 의 깨끗한 절대 경로, Windows 는 Docker 의 기본 네임드 파이프. TCP · SSH · 원격 파이프는 받지 않는다.
//!
//! **꺼져 있는 엔진을 띄우지 않는다.** 소켓 활성화(systemd 가 소켓을 쥐고 첫 연결에 엔진을 띄움)를 쓰는 기계에서는
//! 접속 자체가 엔진을 띄울 수 있다. 그래서 리눅스는 접속 전에 `/proc` 으로 그 소켓을 쥔 프로세스를 가린다
//! ([`linux`] — 조건과 그렇게 정한 까닭은 그 머리말). Windows 는 파이프 목록에 `docker_engine` 이 있을 때만 연다 —
//! 파이프를 여는 것은 아무것도 띄우지 않고, 파이프는 엔진이 떠 있는 동안에만 있다.
//!
//! 스캐너의 Windows 사전 확인(Toolhelp 로 `com.docker.backend.exe` · `dockerd.exe` 프로세스를 찾음)은 옮기지 않았다.
//! Win32 호출은 `remedy-wintrust` 만 할 수 있는데(이 크레이트는 `unsafe` 를 쓰지 않는다) 그 크레이트에 그 함수가 없다.
//! 대신 파이프 목록(`\\.\pipe\`)을 std 로 읽는다 — 연결하지 않는 확인이다.

pub(crate) mod linux;

use super::failure::{EndpointFailure, Failure};
use crate::scan::slashpath;
use std::io;
use std::path::PathBuf;

/// Windows 의 Docker 기본 파이프.
pub(crate) const PIPE: &str = r"\\.\pipe\docker_engine";
const PIPE_URL: &str = "npipe:////./pipe/docker_engine";
const PIPE_NAME: &str = "docker_engine";

/// 꼴을 확인한 엔진 주소.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Endpoint {
    /// Unix 소켓의 경로(링크를 따르기 전, 적힌 그대로).
    Unix(String),
    /// Windows 의 Docker 기본 파이프.
    Pipe,
}

/// 엔진의 종류 — API 판의 상한이 다르다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineKind {
    Docker,
    Podman,
}

/// 이 OS 의 주소 꼴 — 엔진에 닿지 않는다.
pub(crate) fn parse(endpoint: &str) -> Result<Endpoint, Failure> {
    if cfg!(windows) {
        parse_pipe(endpoint)
    } else {
        parse_unix(endpoint)
    }
}

/// `unix:///` 로 시작하는 깨끗한 절대 경로 — 쿼리 · 조각 · NUL · 줄바꿈이 없다.
pub(crate) fn parse_unix(endpoint: &str) -> Result<Endpoint, Failure> {
    if !endpoint.starts_with("unix:///") || endpoint.contains(['?', '#', '\0', '\r', '\n']) {
        return Err(EndpointFailure::UnixOnly.into());
    }
    let name = &endpoint["unix://".len()..];
    if slashpath::clean(name) != name {
        return Err(EndpointFailure::UnixPath.into());
    }
    Ok(Endpoint::Unix(name.to_string()))
}

/// Docker 의 기본 파이프 하나 — 두 가지 적는 법만 받는다.
pub(crate) fn parse_pipe(endpoint: &str) -> Result<Endpoint, Failure> {
    if endpoint != PIPE_URL && endpoint != PIPE {
        return Err(EndpointFailure::PipeOnly.into());
    }
    Ok(Endpoint::Pipe)
}

/// 지금 그 주소에서 엔진이 독립적으로 떠 있는가 — 접속은 하지 않는다.
pub(crate) fn engine_kind(endpoint: &Endpoint, host: &dyn Host) -> Result<EngineKind, Failure> {
    match endpoint {
        Endpoint::Unix(path) if cfg!(target_os = "linux") => linux::verify(path, host),
        Endpoint::Unix(_) => Err(EndpointFailure::NoProc.into()),
        Endpoint::Pipe => pipe_engine(host),
    }
}

/// 파이프 목록에 Docker 의 파이프가 있다. 파이프 이름은 대소문자를 가리지 않는다.
fn pipe_engine(host: &dyn Host) -> Result<EngineKind, Failure> {
    let pipes = host.pipes().map_err(|_| EndpointFailure::PipeList)?;
    if pipes.iter().any(|p| p.eq_ignore_ascii_case(PIPE_NAME)) {
        Ok(EngineKind::Docker)
    } else {
        Err(EndpointFailure::PipeMissing.into())
    }
}

/// 엔진 확인이 읽는 이 기계의 것 — 실제로는 파일 시스템과 `/proc` 이고, 시험은 지은 나무를 준다.
pub(crate) trait Host: Sync {
    /// 링크를 모두 따른 절대 경로(Go 의 `filepath.EvalSymlinks`).
    fn resolve(&self, path: &str) -> io::Result<String>;
    /// 링크를 따라간 끝이 소켓 파일인가.
    fn is_socket(&self, path: &str) -> io::Result<bool>;
    /// `/proc` 아래 파일(`net/unix` · `mounts` · `<pid>/cmdline` 꼴의 상대 경로).
    fn proc_read(&self, rel: &str) -> io::Result<Vec<u8>>;
    /// `/proc` 아래 디렉터리의 이름들(빈 글은 `/proc` 자신).
    fn proc_list(&self, rel: &str) -> io::Result<Vec<String>>;
    /// `/proc` 아래 링크의 대상(`<pid>/exe` · `<pid>/fd/<n>`).
    fn proc_link(&self, rel: &str) -> io::Result<String>;
    /// Windows 의 네임드 파이프 이름들.
    fn pipes(&self) -> io::Result<Vec<String>>;
}

/// 이 기계. `/proc` 의 뿌리를 바꿔 끼울 수 있다.
pub(crate) struct RealHost {
    proc: PathBuf,
}

impl RealHost {
    pub(crate) fn new() -> RealHost {
        RealHost::with_proc(PathBuf::from("/proc"))
    }

    pub(crate) fn with_proc(proc: PathBuf) -> RealHost {
        RealHost { proc }
    }
}

impl Host for RealHost {
    fn resolve(&self, path: &str) -> io::Result<String> {
        let full = std::fs::canonicalize(path)?;
        full.into_os_string()
            .into_string()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    }

    fn is_socket(&self, path: &str) -> io::Result<bool> {
        let meta = std::fs::metadata(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            Ok(meta.file_type().is_socket())
        }
        #[cfg(not(unix))]
        {
            let _ = meta;
            Ok(false)
        }
    }

    fn proc_read(&self, rel: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.proc.join(rel))
    }

    fn proc_list(&self, rel: &str) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(self.proc.join(rel))? {
            names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        Ok(names)
    }

    fn proc_link(&self, rel: &str) -> io::Result<String> {
        Ok(std::fs::read_link(self.proc.join(rel))?
            .to_string_lossy()
            .into_owned())
    }

    fn pipes(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(r"\\.\pipe\")? {
            names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        Ok(names)
    }
}

#[cfg(test)]
pub(crate) mod fake;

#[cfg(test)]
mod tests;
