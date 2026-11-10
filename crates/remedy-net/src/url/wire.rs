//! 요청 한 번 — 연결을 새로 맺고, 요청 줄과 헤더 셋을 보내고, 응답 머리(상태 줄 · 헤더)만 읽고 닫는다.
//!
//! **처음부터 없는 것**: 리다이렉트 따라가기 · 프록시(환경 변수를 읽지 않는다) · 재시도 · 연결 재사용 ·
//! HTTP/2 · 압축 · 쿠키 · 인증 헤더 · 본문 읽기. 범용 클라이언트였다면 하나씩 꺼야 했을 것들이다.
//!
//! TCP 연결 직후 상대 IP 를 묻고(`connected`), 이미 멈춘 서버의 IP 면 **TLS · HTTP 바이트를 한 바이트도
//! 보내기 전에** 닫는다. 오류 문장은 분류만 한다 — 서버가 보낸 글자(깨진 헤더 · 인증서 내용)를 옮기지 않는다.

use super::input::{canonical, Input};
use super::policy::{Cancel, MAX_HEADER_BYTES, SLICE};
use remedy_sdk::i18n::Lang;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Head,
    Get,
}

impl Method {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Method::Head => "HEAD",
            Method::Get => "GET",
        }
    }
}

/// 받은 응답의 머리.
#[derive(Debug, Clone)]
pub(crate) struct Head {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
}

/// 요청이 응답 머리까지 가지 못한 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// 상대 IP 가 이미 멈춘 서버다 — 아무것도 보내지 않고 닫았다.
    Stopped,
    Cancelled,
    Timeout,
    Dns,
    Refused,
    Certificate,
    Tls,
    /// 응답 머리를 다 받기 전에 연결이 끊겼다(EOF · RST).
    Closed,
    Malformed,
    TooLarge,
    Other,
}

impl Failure {
    pub(crate) fn message(self, lang: Lang) -> &'static str {
        match self {
            Failure::Stopped => lang.t(
                "앞서 요청을 중단한 서버와 IP 가 같아 HTTP 요청 전에 연결을 닫았습니다.",
                "closed the connection before any HTTP request: the IP belongs to a server already stopped.",
            ),
            Failure::Cancelled => lang.t("요청이 취소됐습니다.", "the request was cancelled."),
            Failure::Timeout => lang.t("요청 제한 시간을 초과했습니다.", "the request timed out."),
            Failure::Dns => lang.t(
                "호스트 이름을 주소로 바꾸지 못했습니다 (DNS).",
                "could not resolve the host name (DNS).",
            ),
            Failure::Refused => lang.t(
                "서버가 연결을 거부했습니다.",
                "the server refused the connection.",
            ),
            Failure::Certificate => lang.t(
                "TLS 인증서 검증에 실패했습니다 (certificate verification failed).",
                "TLS certificate verification failed.",
            ),
            Failure::Tls => lang.t("TLS 연결을 맺지 못했습니다.", "the TLS handshake failed."),
            Failure::Closed => lang.t(
                "서버가 연결을 종료했습니다.",
                "the server closed the connection.",
            ),
            Failure::Malformed => lang.t(
                "HTTP 응답 형식이 올바르지 않습니다.",
                "the HTTP response is malformed.",
            ),
            Failure::TooLarge => lang.t(
                "HTTP 응답 헤더 크기 제한을 초과했습니다 (response headers exceeded 32768 bytes).",
                "the HTTP response headers exceeded the size limit (response headers exceeded 32768 bytes).",
            ),
            Failure::Other => lang.t(
                "서버와 HTTP 통신을 완료할 수 없습니다.",
                "could not complete the HTTP exchange with the server.",
            ),
        }
    }

    /// 이 서버로 더 요청하지 않을 까닭인가 — 시간이 다 됐거나 연결이 끊긴 것(스캐너와 같다).
    pub(crate) fn stops_server(self) -> bool {
        matches!(self, Failure::Timeout | Failure::Closed)
    }
}

/// 요청 한 번. 시험은 서버 없이 응답을 지어 넣는다.
pub(crate) trait Transport {
    /// `connected` 는 TCP 연결을 맺을 때마다 상대 IP 로 불린다. 거짓이면 아무것도 보내지 않고 닫는다.
    fn exchange(
        &self,
        method: Method,
        input: &Input,
        deadline: Instant,
        cancel: &Cancel,
        connected: &mut dyn FnMut(IpAddr) -> bool,
    ) -> Result<Head, Failure>;
}

/// 이름 풀이 — 실제로는 OS 의 것(`getaddrinfo`)이고, 시험은 모든 이름을 시험 서버로 돌린다.
pub(crate) type Resolve = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// 실제 통신.
pub(crate) struct Net {
    tls: Arc<ClientConfig>,
    resolve: Resolve,
}

const USER_AGENT: &str = concat!("remedy-net/", env!("CARGO_PKG_VERSION"));
/// 32 KiB 안에 들어갈 수 있는 헤더 줄의 최대 수(`a:` + CRLF = 4바이트) — 넘침 오류가 상한보다 먼저 나지 않게.
const MAX_HEADERS: usize = MAX_HEADER_BYTES / 4 + 1;
const MIN_TIMEOUT: Duration = Duration::from_millis(1);

impl Net {
    pub(crate) fn new(tls: Arc<ClientConfig>) -> Net {
        Net::resolving(
            tls,
            Arc::new(|host, port| Ok((host, port).to_socket_addrs()?.collect())),
        )
    }

    pub(crate) fn resolving(tls: Arc<ClientConfig>, resolve: Resolve) -> Net {
        Net { tls, resolve }
    }

    fn addresses(
        &self,
        input: &Input,
        deadline: Instant,
        cancel: &Cancel,
    ) -> Result<Vec<SocketAddr>, Failure> {
        if let Some(ip) = input.ip {
            return Ok(vec![SocketAddr::new(ip, input.port)]);
        }
        // OS 의 이름 풀이는 시한을 받지 않는다 — 따로 돌리고 시한까지만 기다린다.
        let (tx, rx) = mpsc::channel();
        let resolve = Arc::clone(&self.resolve);
        let (host, port) = (input.host.clone(), input.port);
        std::thread::spawn(move || {
            let _ = tx.send(resolve(&host, port));
        });
        loop {
            if cancel.is_set() {
                return Err(Failure::Cancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Failure::Timeout);
            }
            match rx.recv_timeout((deadline - now).min(SLICE)) {
                Ok(Ok(list)) if !list.is_empty() => return Ok(list),
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Failure::Dns),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn over_tls(
        &self,
        sock: &TcpStream,
        input: &Input,
        request: &[u8],
        deadline: Instant,
        cancel: &Cancel,
    ) -> Result<Head, Failure> {
        let name = match input.ip {
            Some(ip) => ServerName::from(ip),
            None => ServerName::try_from(input.host.trim_end_matches('.').to_string())
                .map_err(|_| Failure::Tls)?,
        };
        let mut conn =
            ClientConnection::new(Arc::clone(&self.tls), name).map_err(|_| Failure::Tls)?;
        let mut io = sock;
        while conn.is_handshaking() {
            arm(sock, deadline, cancel)?;
            match conn.complete_io(&mut io) {
                Ok(_) => {}
                Err(e) if waiting(&e) => {}
                Err(e) => return Err(classify(&e)),
            }
        }
        conn.writer().write_all(request).map_err(|e| classify(&e))?;
        while conn.wants_write() {
            arm(sock, deadline, cancel)?;
            match conn.write_tls(&mut io) {
                Ok(_) => {}
                Err(e) if waiting(&e) => {}
                Err(e) => return Err(classify(&e)),
            }
        }
        read_head(
            sock,
            &mut |buf| tls_read(&mut conn, &mut io, buf),
            deadline,
            cancel,
        )
    }
}

impl Transport for Net {
    fn exchange(
        &self,
        method: Method,
        input: &Input,
        deadline: Instant,
        cancel: &Cancel,
        connected: &mut dyn FnMut(IpAddr) -> bool,
    ) -> Result<Head, Failure> {
        let addrs = self.addresses(input, deadline, cancel)?;
        let sock = connect(&addrs, deadline, cancel)?;
        let peer = sock.peer_addr().map_err(|e| classify(&e))?;
        if !connected(canonical(peer.ip())) {
            return Err(Failure::Stopped);
        }
        let _ = sock.set_nodelay(true);
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n",
            method.as_str(),
            input.target,
            input.authority()
        );
        if input.https {
            return self.over_tls(&sock, input, request.as_bytes(), deadline, cancel);
        }
        arm(&sock, deadline, cancel)?;
        (&sock)
            .write_all(request.as_bytes())
            .map_err(|e| classify(&e))?;
        let mut io = &sock;
        read_head(&sock, &mut |buf| io.read(buf), deadline, cancel)
    }
}

/// 주소를 차례로 — 남은 시간을 남은 주소에 나눠 준다(한 번에 2초는 넘게).
fn connect(addrs: &[SocketAddr], deadline: Instant, cancel: &Cancel) -> Result<TcpStream, Failure> {
    let mut first = None;
    for (i, addr) in addrs.iter().enumerate() {
        if cancel.is_set() {
            return Err(Failure::Cancelled);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(Failure::Timeout);
        }
        let left = deadline - now;
        let share = left / (addrs.len() - i) as u32;
        const SANE: Duration = Duration::from_secs(2);
        let per = if share < SANE { left.min(SANE) } else { share };
        match TcpStream::connect_timeout(addr, per.max(MIN_TIMEOUT)) {
            Ok(s) => return Ok(s),
            Err(e) => {
                first.get_or_insert(classify(&e));
            }
        }
    }
    Err(first.unwrap_or(Failure::Other))
}

/// 다음 읽기 · 쓰기의 시한 — 읽기는 [`SLICE`] 씩 끊어 취소를 본다.
fn arm(sock: &TcpStream, deadline: Instant, cancel: &Cancel) -> Result<(), Failure> {
    if cancel.is_set() {
        return Err(Failure::Cancelled);
    }
    let now = Instant::now();
    if now >= deadline {
        return Err(Failure::Timeout);
    }
    let left = deadline - now;
    sock.set_read_timeout(Some(left.min(SLICE).max(MIN_TIMEOUT)))
        .and_then(|()| sock.set_write_timeout(Some(left.max(MIN_TIMEOUT))))
        .map_err(|e| classify(&e))
}

/// 응답 머리를 다 받을 때까지 읽는다 — 32 KiB 를 넘으면 그만둔다. 1xx 안내 응답은 건너뛴다(다섯 번까지).
fn read_head(
    sock: &TcpStream,
    fill: &mut dyn FnMut(&mut [u8]) -> io::Result<usize>,
    deadline: Instant,
    cancel: &Cancel,
) -> Result<Head, Failure> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut informational = 0;
    loop {
        match parse(&buf)? {
            Some((len, _)) if len > MAX_HEADER_BYTES => return Err(Failure::TooLarge),
            Some((len, head)) if (100..200).contains(&head.status) && head.status != 101 => {
                informational += 1;
                if informational > 5 {
                    return Err(Failure::Malformed);
                }
                buf.drain(..len);
                continue;
            }
            Some((_, head)) => return Ok(head),
            None if buf.len() > MAX_HEADER_BYTES => return Err(Failure::TooLarge),
            None => {}
        }
        arm(sock, deadline, cancel)?;
        let room = (MAX_HEADER_BYTES + 1 - buf.len()).min(chunk.len());
        match fill(&mut chunk[..room]) {
            Ok(0) => return Err(Failure::Closed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if waiting(&e) || e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(classify(&e)),
        }
    }
}

/// 다 받았으면 (머리 길이, 머리). 아직이면 `None`.
fn parse(buf: &[u8]) -> Result<Option<(usize, Head)>, Failure> {
    if buf.is_empty() {
        return Ok(None);
    }
    let mut headers = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf) {
        Ok(httparse::Status::Partial) => Ok(None),
        Ok(httparse::Status::Complete(len)) => {
            let status = resp.code.ok_or(Failure::Malformed)?;
            let headers = resp
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).into_owned(),
                    )
                })
                .collect();
            Ok(Some((len, Head { status, headers })))
        }
        Err(_) => Err(Failure::Malformed),
    }
}

/// TLS 위의 평문을 읽는다 — 소켓 읽기의 시한 만료는 `WouldBlock` · `TimedOut` 으로 돌려준다.
fn tls_read(conn: &mut ClientConnection, io: &mut &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match conn.reader().read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        conn.read_tls(io)?;
        if let Err(e) = conn.process_new_packets() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e));
        }
    }
}

/// 읽기 시한이 끝났을 뿐이다(Unix 는 `WouldBlock`, Windows 는 `TimedOut`).
fn waiting(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// 입출력 오류를 갈래로만 — 글자는 버린다.
pub(crate) fn classify(e: &io::Error) -> Failure {
    if let Some(tls) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        return match tls {
            rustls::Error::InvalidCertificate(_) => Failure::Certificate,
            _ => Failure::Tls,
        };
    }
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Failure::Timeout,
        io::ErrorKind::ConnectionRefused => Failure::Refused,
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected => Failure::Closed,
        // ERROR_NETNAME_DELETED — Windows 가 끊긴 연결을 이 번호로도 알린다.
        _ if cfg!(windows) && e.raw_os_error() == Some(64) => Failure::Closed,
        _ => Failure::Other,
    }
}
