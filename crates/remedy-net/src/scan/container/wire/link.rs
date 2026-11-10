//! 연결 하나 — 리눅스는 Unix 소켓, Windows 는 네임드 파이프.
//!
//! **Unix 소켓**은 읽기 · 쓰기마다 시한을 건다(남은 시간과 [`SLICE`] 가운데 짧은 것) — 그 사이사이 취소를 본다.
//! 연결 맺기에는 std 가 시한을 주지 않으므로(수신 대기열이 차면 막힌다) 따로 도는 스레드에서 맺고 시한까지만 기다린다.
//!
//! **네임드 파이프**는 std 의 `File` 로 연다. 동기 핸들이라 읽기에 시한을 걸 수 없고, `unsafe` 없이는 막힌 읽기를
//! 깨울 수도 없다. 그래서 연결을 따로 도는 스레드([`PumpLink`])에 맡긴다 — 그 스레드가 요청을 쓰고 응답을 조각으로
//! 읽어 넘기고, 이쪽은 시한까지만 기다린다. 시한이 지나면 이쪽은 그 요청을 버리고 다음으로 간다. 엔진이 아무것도
//! 보내지 않아 막힌 읽기는 그 스레드에 남는다 — 엔진이 연결을 닫거나 프로그램이 끝날 때 풀린다(요청은 128개까지라
//! 남는 스레드도 그만큼까지다). 실행 전체는 시한(10분)과 실행 고리의 0.5초 유예가 묶는다.
//!
//! 파이프는 `SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS` 로 연다 — go-winio 의 `DialPipe` 와 같은 값이다. 파이프의
//! 서버가 이 프로세스로 가장(impersonation)하지 못한다.

use super::{Watch, SLICE};
use crate::scan::container::failure::{Failure, Wire};
use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::time::Duration;

/// 읽기 · 쓰기 시한의 하한 — 0 은 시한 없음으로 읽힌다.
const MIN_TIMEOUT: Duration = Duration::from_millis(1);
/// 파이프 스레드가 한 번에 읽는 양.
#[cfg(any(windows, test))]
const PUMP_CHUNK: usize = 32 << 10;

/// 연결 하나의 읽기 · 쓰기.
pub(crate) trait Link {
    fn send(&mut self, bytes: &[u8], watch: &Watch<'_>) -> Result<(), Failure>;
    /// 받은 바이트 수. 0 은 엔진이 연결을 닫은 것이다.
    fn recv(&mut self, buf: &mut [u8], watch: &Watch<'_>) -> Result<usize, Failure>;
}

/// 입출력 오류를 갈래로만 — OS 의 글은 버린다.
pub(crate) fn classify(e: &io::Error) -> Failure {
    let wire = match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Wire::Timeout,
        io::ErrorKind::NotFound => Wire::Missing,
        io::ErrorKind::PermissionDenied => Wire::Denied,
        io::ErrorKind::ConnectionRefused => Wire::Refused,
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::NotConnected => Wire::Closed,
        // ERROR_NETNAME_DELETED · ERROR_NO_DATA · ERROR_PIPE_NOT_CONNECTED — Windows 가 끊긴 파이프를 이 번호로도 알린다.
        _ if cfg!(windows) && matches!(e.raw_os_error(), Some(64 | 232 | 233)) => Wire::Closed,
        _ => Wire::Other,
    };
    Failure::Wire(wire)
}

/// 시한이 끝났을 뿐인 오류(Unix 는 `WouldBlock`, Windows 는 `TimedOut`)와 끼어든 신호.
#[cfg(unix)]
fn waiting(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn slice(watch: &Watch<'_>) -> Result<Duration, Failure> {
    Ok(watch.left()?.min(SLICE).max(MIN_TIMEOUT))
}

/// Unix 소켓 하나.
#[cfg(unix)]
pub(crate) struct UnixLink(std::os::unix::net::UnixStream);

#[cfg(unix)]
impl UnixLink {
    /// 맺는다 — 따로 도는 스레드에서 맺고 시한까지만 기다린다.
    pub(crate) fn connect(path: &str, watch: &Watch<'_>) -> Result<UnixLink, Failure> {
        let (tx, rx) = mpsc::channel();
        let path = path.to_string();
        std::thread::spawn(move || {
            let _ = tx.send(std::os::unix::net::UnixStream::connect(path));
        });
        loop {
            match rx.recv_timeout(slice(watch)?) {
                Ok(Ok(stream)) => return Ok(UnixLink(stream)),
                Ok(Err(e)) => return Err(classify(&e)),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Wire::Other.into()),
            }
        }
    }
}

#[cfg(unix)]
impl Link for UnixLink {
    fn send(&mut self, bytes: &[u8], watch: &Watch<'_>) -> Result<(), Failure> {
        let mut sent = 0;
        while sent < bytes.len() {
            let wait = slice(watch)?;
            self.0
                .set_write_timeout(Some(wait))
                .map_err(|e| classify(&e))?;
            match self.0.write(&bytes[sent..]) {
                Ok(0) => return Err(Wire::Closed.into()),
                Ok(n) => sent += n,
                Err(e) if waiting(&e) => {}
                Err(e) => return Err(classify(&e)),
            }
        }
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8], watch: &Watch<'_>) -> Result<usize, Failure> {
        loop {
            let wait = slice(watch)?;
            self.0
                .set_read_timeout(Some(wait))
                .map_err(|e| classify(&e))?;
            match self.0.read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if waiting(&e) => {}
                Err(e) => return Err(classify(&e)),
            }
        }
    }
}

/// 따로 도는 스레드가 맡은 연결 — 이쪽은 요청을 넘기고, 응답 조각을 시한까지만 기다린다. Windows 파이프가 쓰고,
/// 시험은 지은 연결로 어느 OS 에서든 쓴다.
#[cfg(any(windows, test))]
pub(crate) struct PumpLink {
    request: Option<mpsc::Sender<Vec<u8>>>,
    chunks: mpsc::Receiver<io::Result<Vec<u8>>>,
    pending: Vec<u8>,
    pos: usize,
    ended: bool,
}

#[cfg(any(windows, test))]
impl PumpLink {
    /// 연결을 스레드에 넘긴다. 그 스레드는 요청을 받아 쓰고, 끝까지 읽어 조각으로 넘긴다 — 이쪽이 받지 않으면
    /// 두 조각에서 멈추고, 이쪽이 그만두면 다음 조각을 넘기지 못해 끝난다(연결도 닫힌다).
    pub(crate) fn start<S: Read + Write + Send + 'static>(stream: S) -> PumpLink {
        let (request, requests) = mpsc::channel::<Vec<u8>>();
        let (out, chunks) = mpsc::sync_channel::<io::Result<Vec<u8>>>(2);
        std::thread::spawn(move || pump(stream, &requests, &out));
        PumpLink {
            request: Some(request),
            chunks,
            pending: Vec::new(),
            pos: 0,
            ended: false,
        }
    }

    fn take_pending(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.pending.len() - self.pos);
        buf[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
        self.pos += n;
        n
    }
}

#[cfg(any(windows, test))]
fn pump<S: Read + Write>(
    mut stream: S,
    requests: &mpsc::Receiver<Vec<u8>>,
    out: &mpsc::SyncSender<io::Result<Vec<u8>>>,
) {
    let Ok(request) = requests.recv() else {
        return;
    };
    if let Err(e) = stream.write_all(&request).and_then(|()| stream.flush()) {
        let _ = out.send(Err(e));
        return;
    }
    loop {
        let mut chunk = vec![0u8; PUMP_CHUNK];
        match stream.read(&mut chunk) {
            Ok(n) => {
                chunk.truncate(n);
                if out.send(Ok(chunk)).is_err() || n == 0 {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                let _ = out.send(Err(e));
                return;
            }
        }
    }
}

#[cfg(any(windows, test))]
impl Link for PumpLink {
    fn send(&mut self, bytes: &[u8], _watch: &Watch<'_>) -> Result<(), Failure> {
        let request = self.request.take().ok_or(Failure::Wire(Wire::Other))?;
        request
            .send(bytes.to_vec())
            .map_err(|_| Failure::Wire(Wire::Closed))
    }

    fn recv(&mut self, buf: &mut [u8], watch: &Watch<'_>) -> Result<usize, Failure> {
        if self.pos < self.pending.len() {
            return Ok(self.take_pending(buf));
        }
        if self.ended || buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.chunks.recv_timeout(slice(watch)?) {
                Ok(Ok(chunk)) if chunk.is_empty() => {
                    self.ended = true;
                    return Ok(0);
                }
                Ok(Ok(chunk)) => {
                    self.pending = chunk;
                    self.pos = 0;
                    return Ok(self.take_pending(buf));
                }
                Ok(Err(e)) => return Err(classify(&e)),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Wire::Closed.into()),
            }
        }
    }
}

/// Docker 의 네임드 파이프를 연다 — 다른 요청이 쥐고 있으면(`ERROR_PIPE_BUSY`) 10 ms 마다 다시, 시한까지.
#[cfg(windows)]
pub(crate) fn open_pipe(path: &str, watch: &Watch<'_>) -> Result<PumpLink, Failure> {
    use std::os::windows::fs::OpenOptionsExt;
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
    const SECURITY_ANONYMOUS: u32 = 0;
    const ERROR_PIPE_BUSY: i32 = 231;
    loop {
        watch.left()?;
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS)
            .open(path);
        match opened {
            Ok(file) => return Ok(PumpLink::start(file)),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(classify(&e)),
        }
    }
}
