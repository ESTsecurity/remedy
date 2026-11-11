//! 이 기계의 엔진 — 연결을 맺을 때마다 엔진을 다시 확인하고, 요청 하나에 연결 하나를 쓴다(이어 쓰지 않는다).

use super::endpoint::{self, Endpoint, EngineKind, Host};
use super::failure::{EndpointFailure, Failure, Wire};
use super::wire::http;
use super::wire::link::Link;
use super::wire::{Call, Reply, Transport, Watch};
use crate::scan::budget::Budget;

/// 확인을 마친 엔진 주소.
pub(crate) struct Local {
    endpoint: Endpoint,
    kind: EngineKind,
    host: Box<dyn Host>,
}

impl Local {
    /// 주소의 꼴을 보고 엔진을 확인한다 — 아직 접속하지 않는다.
    pub(crate) fn open(endpoint: &str, host: Box<dyn Host>) -> Result<Local, Failure> {
        let endpoint = endpoint::parse(endpoint)?;
        let kind = endpoint::engine_kind(&endpoint, &*host)?;
        Ok(Local {
            endpoint,
            kind,
            host,
        })
    }

    pub(crate) fn kind(&self) -> EngineKind {
        self.kind
    }

    /// 주 프로세스를 찾을 `/proc` — 리눅스의 Unix 소켓 엔진일 때만 쓴다.
    pub(crate) fn host(&self) -> &dyn Host {
        &*self.host
    }
}

impl Transport for Local {
    fn round_trip<'a>(&'a self, call: &Call<'_>, budget: &'a Budget) -> Result<Reply<'a>, Failure> {
        // 확인과 연결 사이에도 엔진이 바뀔 수 있다 — 연결마다 다시 본다.
        let current = endpoint::engine_kind(&self.endpoint, &*self.host)?;
        if current != self.kind {
            return Err(EndpointFailure::EngineChanged.into());
        }
        let watch = Watch {
            deadline: call.deadline,
            budget,
        };
        let link = match &self.endpoint {
            Endpoint::Unix(path) => unix(path, &watch)?,
            Endpoint::Pipe => pipe(&watch)?,
        };
        http::exchange(link, call, watch)
    }
}

#[cfg(unix)]
fn unix<'a>(path: &str, watch: &Watch<'_>) -> Result<Box<dyn Link + 'a>, Failure> {
    Ok(Box::new(super::wire::link::UnixLink::connect(path, watch)?))
}

#[cfg(not(unix))]
fn unix<'a>(_path: &str, _watch: &Watch<'_>) -> Result<Box<dyn Link + 'a>, Failure> {
    Err(Wire::Other.into())
}

#[cfg(windows)]
fn pipe<'a>(watch: &Watch<'_>) -> Result<Box<dyn Link + 'a>, Failure> {
    Ok(Box::new(super::wire::link::open_pipe(
        endpoint::PIPE,
        watch,
    )?))
}

#[cfg(not(windows))]
fn pipe<'a>(_watch: &Watch<'_>) -> Result<Box<dyn Link + 'a>, Failure> {
    Err(Wire::Other.into())
}
