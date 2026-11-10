//! 시험용 모의 서버 — 스캐너의 `tools/mockserver` 를 옮겼다(지우기 직전 판의 경로 · 응답 그대로).
//!
//! 127.0.0.1 에만 연다. HTTP 응답만 흉내 내고 PHP 실행 · 공격 코드는 없다. 받은 요청을 모두 적어 두어,
//! 시험이 **요청 수 · 차례 · 간격을 서버 쪽 기록으로** 단언한다. TLS 인증서는 그 자리에서 만들고 공개 CA
//! 인증서만 파일로 쓴다(비밀키는 메모리에만 있다).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 본문 · 숨은 헤더 · 쿼리 · 계정 · 깨진 응답 · 쿠키에 넣은 표식 — 결과 파일과 화면에 나오면 안 된다.
pub const BODY_MARKER: &str = "ESTSECURITY_MOCK_BODY_MUST_NOT_APPEAR_IN_SCAN_REPORT";
pub const SENSITIVE: [&str; 7] = [
    BODY_MARKER,
    "MOCK_PRIVATE_HEADER_MUST_NOT_BE_REPORTED",
    "MOCK_QUERY_SECRET",
    "MOCK_PASSWORD",
    "MOCK_MALFORMED_HEADER_SECRET",
    "MOCK_MALFORMED_STATUS_SECRET",
    "MOCK_COOKIE_SECRET",
];

/// 받은 요청 하나.
#[derive(Debug, Clone)]
pub struct Event {
    pub at: Instant,
    pub method: String,
    pub path: String,
    pub host: String,
    pub local: SocketAddr,
    /// 보내려던 상태 코드. 답하지 않은 요청(시간 초과 · 끊기)은 0.
    pub status: u16,
    pub cookie: bool,
    pub authorization: bool,
    pub proxy_authorization: bool,
    pub query_seen: bool,
    pub content_length: u64,
}

pub struct Mock {
    pub base: SocketAddr,
    pub second: SocketAddr,
    pub tls: SocketAddr,
    pub tls_mismatch: SocketAddr,
    pub dir: PathBuf,
    events: Arc<Mutex<Vec<Event>>>,
    stop: Arc<AtomicBool>,
}

enum Action {
    Respond,
    Malformed(&'static str),
    Hang,
    Reset,
}

struct Route {
    status: u16,
    headers: Vec<(&'static str, String)>,
    action: Action,
}

impl Mock {
    /// 네 자리 — HTTP 둘 · TLS(127.0.0.1 인증서) · TLS(127.0.0.2 인증서 — 호스트 이름 불일치).
    pub fn start(dir: &Path) -> Mock {
        std::fs::create_dir_all(dir).unwrap();
        let (ca, ca_key, ca_cert) = new_ca("ESTsecurity local mock CA");
        let (wrong, wrong_key, wrong_cert) = new_ca("ESTsecurity local mock wrong CA");
        std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
        std::fs::write(dir.join("wrong-ca.pem"), wrong_cert.pem()).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let open = |tls: Option<Arc<rustls::ServerConfig>>| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let (events, stop) = (Arc::clone(&events), Arc::clone(&stop));
            std::thread::spawn(move || accept(listener, tls, events, stop));
            addr
        };
        let base = open(None);
        let second = open(None);
        let tls = open(Some(server_config(&ca, &ca_key, "127.0.0.1")));
        let tls_mismatch = open(Some(server_config(&wrong, &wrong_key, "127.0.0.2")));
        Mock {
            base,
            second,
            tls,
            tls_mismatch,
            dir: dir.to_path_buf(),
            events,
            stop,
        }
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    pub fn ca(&self) -> PathBuf {
        self.dir.join("ca.pem")
    }

    pub fn wrong_ca(&self) -> PathBuf {
        self.dir.join("wrong-ca.pem")
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // 막힌 accept 를 깨운다.
        for a in [self.base, self.second, self.tls, self.tls_mismatch] {
            let _ = TcpStream::connect_timeout(&a, Duration::from_millis(200));
        }
    }
}

fn new_ca(name: &str) -> (rcgen::CertificateParams, rcgen::KeyPair, rcgen::Certificate) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params.self_signed(&key).unwrap();
    (params, key, cert)
}

fn server_config(
    ca: &rcgen::CertificateParams,
    ca_key: &rcgen::KeyPair,
    ip: &str,
) -> Arc<rustls::ServerConfig> {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![ip.to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ESTsecurity local mock");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let issuer = rcgen::Issuer::from_params(ca, ca_key);
    let leaf = params.signed_by(&key, &issuer).unwrap();
    let der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], der)
        .unwrap(),
    )
}

fn accept(
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    events: Arc<Mutex<Vec<Event>>>,
    stop: Arc<AtomicBool>,
) {
    for stream in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = stream else { continue };
        let (tls, events) = (tls.clone(), Arc::clone(&events));
        std::thread::spawn(move || {
            let local = stream.local_addr().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            // 소켓 핸들을 복제하지 않는다 — Windows 에서 복제한 핸들에 준 읽기 시한이 원래 핸들의 읽기에
            // 걸리지 않았다(2026-11-10 실측: 15초를 주어도 3초에 끊겼다). SO_LINGER 도 닫는 그 핸들에 준다.
            let mut sock = &stream;
            match tls {
                None => serve(&mut sock, &stream, local, &events),
                Some(cfg) => {
                    let mut conn = rustls::ServerConnection::new(cfg).unwrap();
                    serve(
                        &mut rustls::Stream::new(&mut conn, &mut sock),
                        &stream,
                        local,
                        &events,
                    );
                }
            }
        });
    }
}

trait Io: Read + Write {}
impl<T: Read + Write> Io for T {}

fn serve(io: &mut dyn Io, raw: &TcpStream, local: SocketAddr, events: &Mutex<Vec<Event>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match io.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if buf.len() > 8 << 10 {
            return;
        }
    }
    let arrived = Instant::now();
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(req.parse(&buf), Ok(httparse::Status::Complete(_))) {
        return;
    }
    let method = req.method.unwrap_or("").to_string();
    let target = req.path.unwrap_or("").to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let header = |name: &str| {
        req.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).into_owned())
    };
    let route = route(&method, &path);
    events.lock().unwrap().push(Event {
        at: arrived,
        method: method.clone(),
        path: path.clone(),
        host: header("Host").unwrap_or_default(),
        local,
        status: route.status,
        cookie: header("Cookie").is_some(),
        authorization: header("Authorization").is_some(),
        proxy_authorization: header("Proxy-Authorization").is_some(),
        query_seen: query
            .split('&')
            .any(|kv| kv == "mock_token=MOCK_QUERY_SECRET"),
        content_length: header("Content-Length")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
    });
    match route.action {
        Action::Malformed(response) => {
            let _ = io.write_all(response.as_bytes());
            let _ = io.flush();
        }
        Action::Hang => {
            // 답하지 않는다 — 상대가 끊을 때까지(길어야 15초). 3초 읽기 시한은 넘기고 계속 기다린다.
            let until = Instant::now() + Duration::from_secs(15);
            while Instant::now() < until {
                match io.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => break,
                }
            }
        }
        Action::Reset => {
            // SO_LINGER 0 으로 닫아 FIN 이 아니라 RST 가 간다.
            let _ = socket2::SockRef::from(raw).set_linger(Some(Duration::ZERO));
        }
        Action::Respond => {
            let mut s = format!("HTTP/1.1 {} {}\r\n", route.status, reason(route.status));
            for (n, v) in &route.headers {
                s.push_str(&format!("{n}: {v}\r\n"));
            }
            let body = if method == "GET" {
                format!("{BODY_MARKER}\n")
            } else {
                String::new()
            };
            s.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            s.push_str(&format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            ));
            s.push_str(&body);
            let _ = io.write_all(s.as_bytes());
            let _ = io.flush();
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

const MALFORMED_HEADER: &str =
    "HTTP/1.1 200 OK\r\nMOCK_MALFORMED_HEADER_SECRET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const MALFORMED_STATUS: &str =
    "HTTP/1.1 MOCK_MALFORMED_STATUS_SECRET invalid\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// 스캐너 모의 서버의 경로표.
fn route(method: &str, path: &str) -> Route {
    let head = method == "HEAD";
    let mut status = 200;
    let mut version: Option<&str> = None;
    let mut headers: Vec<(&'static str, String)> = Vec::new();
    let mut action = Action::Respond;
    let cookie = |name: &str| format!("{name}=MOCK_COOKIE_SECRET; Path=/; HttpOnly");
    match path {
        "/vulnerable" | "/cookie" | "/should-not-hit" => version = Some("8.3.6"),
        "/fixed" => version = Some("8.3.36"),
        "/custom-version" => version = Some("8.3.36-custom"),
        "/unknown-version" => version = Some("5.3.29"),
        "/legacy-php54" => version = Some("5.4.0"),
        "/legacy-php56" => version = Some("5.6.40"),
        "/legacy-php74" => version = Some("7.4.33"),
        "/legacy-php81" => version = Some("8.1.34"),
        "/legacy-esm-before" => version = Some("7.4.3-4ubuntu2.29+esm4"),
        "/legacy-esm-fixed" => version = Some("7.4.3-4ubuntu2.29+esm5"),
        "/backport-fixed" => version = Some("8.3.6-0ubuntu0.24.04.13"),
        "/php-session" => {
            headers.push(("Set-Cookie", cookie("PHPSESSID")));
            headers.push(("Expires", "Thu, 19 Nov 1981 08:52:00 GMT".to_string()));
        }
        "/laravel" => headers.push(("Set-Cookie", cookie("laravel_session"))),
        "/wordpress" => {
            headers.push((
                "Link",
                "<https://example.invalid/wp-json/>; rel=\"https://api.w.org/\"".to_string(),
            ));
            headers.push(("X-Redirect-By", "WordPress".to_string()));
        }
        "/nonphp-csrf" => {
            headers.push(("X-Powered-By", "Express".to_string()));
            headers.push(("Set-Cookie", "_csrf=MOCK_COOKIE_SECRET; Path=/".to_string()));
            headers.push((
                "Set-Cookie",
                "_csrf-frontend=MOCK_COOKIE_SECRET; Path=/".to_string(),
            ));
        }
        "/multiple-headers" => {
            version = Some("8.3.36");
            headers.push(("Server", "PHP/8.2.1".to_string()));
        }
        "/empty204" => status = 204,
        "/hidden" => {}
        "/malformed-header" => action = Action::Malformed(MALFORMED_HEADER),
        "/malformed-status" => action = Action::Malformed(MALFORMED_STATUS),
        "/head405"
        | "/head501"
        | "/head405-timeout"
        | "/head405-vulnerable-timeout"
        | "/head405-get405"
        | "/head501-get501"
        | "/head405-get429"
        | "/head405-get503"
        | "/head405-get403" => {
            if head {
                status = if path.starts_with("/head501") {
                    501
                } else {
                    405
                };
                if path == "/head405-vulnerable-timeout" {
                    version = Some("8.3.6");
                }
            } else {
                version = Some("8.3.6");
                match path {
                    "/head405-timeout" | "/head405-vulnerable-timeout" => {
                        status = 0;
                        action = Action::Hang;
                    }
                    "/head405-get405" => status = 405,
                    "/head501-get501" => status = 501,
                    "/head405-get429" => status = 429,
                    "/head405-get503" => status = 503,
                    "/head405-get403" => status = 403,
                    _ => {}
                }
            }
        }
        "/redirect" | "/redirect301" | "/redirect307" | "/redirect308" => {
            status = match path {
                "/redirect301" => 301,
                "/redirect307" => 307,
                "/redirect308" => 308,
                _ => 302,
            };
            headers.push(("Location", "/should-not-hit".to_string()));
        }
        "/auth401" => {
            status = 401;
            headers.push(("WWW-Authenticate", "Basic realm=\"mock-only\"".to_string()));
        }
        "/forbidden403" => status = 403,
        "/missing404" => status = 404,
        "/limited429" => {
            status = 429;
            headers.push(("Retry-After", "60".to_string()));
        }
        "/unavailable503" => status = 503,
        "/error500" => status = 500,
        "/large-header" => headers.push(("X-Mock-Large", "x".repeat(40 << 10))),
        "/timeout" => {
            status = 0;
            action = Action::Hang;
        }
        "/reset" => {
            status = 0;
            action = Action::Reset;
        }
        _ => status = 404,
    }
    if method != "HEAD" && method != "GET" {
        status = 405;
    }
    if let Some(v) = version {
        headers.push(("X-Powered-By", format!("PHP/{v}")));
    }
    headers.push((
        "X-Mock-Secret",
        "MOCK_PRIVATE_HEADER_MUST_NOT_BE_REPORTED".to_string(),
    ));
    if path == "/cookie" {
        headers.push((
            "Set-Cookie",
            "mock_session=MOCK_COOKIE_SECRET; Path=/".to_string(),
        ));
    }
    Route {
        status,
        headers,
        action,
    }
}
