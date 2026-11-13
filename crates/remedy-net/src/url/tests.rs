//! 스캐너 `internal/remote` 의 시험 19함수를 옮겼다. 각 시험의 이름 위에 원래 이름을 적는다.
//!
//! 입력 검증(`TestInputValidation`)은 [`super::input`], 단서(`TestPHPFingerprintsIdentifyPresenceOnly`)는
//! [`super::headers`] 의 시험에 있다. 나머지는 여기 — 서버 없이 응답을 지어 넣는 시험과, 127.0.0.1 에 연
//! 시험 서버로 실제 전송을 보는 시험이다.

use super::input::Input;
use super::policy::{wait_until, Budget, Cancel, Gate, Halt};
use super::report::{Target, Verdict};
use super::scan::Scan;
use super::trust;
use super::wire::{classify, Failure, Head, Method, Net, Transport};
use remedy_sdk::i18n::Lang;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── 지어 넣는 전송 · 상한 ────────────────────────────────────────────────

struct Fake<F> {
    calls: AtomicUsize,
    f: F,
}

fn fake<F>(f: F) -> Fake<F>
where
    F: Fn(Method, &Input, &mut dyn FnMut(IpAddr) -> bool) -> Result<Head, Failure>,
{
    Fake {
        calls: AtomicUsize::new(0),
        f,
    }
}

impl<F> Transport for Fake<F>
where
    F: Fn(Method, &Input, &mut dyn FnMut(IpAddr) -> bool) -> Result<Head, Failure>,
{
    fn exchange(
        &self,
        method: Method,
        input: &Input,
        _deadline: Instant,
        _cancel: &Cancel,
        connected: &mut dyn FnMut(IpAddr) -> bool,
    ) -> Result<Head, Failure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.f)(method, input, connected)
    }
}

impl<F> Fake<F> {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// 스캐너 `fakeBudget` — 맡은 수를 세고, 정한 만큼 기다린다(URL 시한 안에서).
#[derive(Default)]
struct Count {
    calls: AtomicUsize,
    wait: Duration,
    recorded: Mutex<Vec<Target>>,
}

impl Gate for Count {
    fn before_request(&self, url_deadline: Instant, cancel: &Cancel) -> Result<(), Halt> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.wait.is_zero() {
            return if cancel.is_set() {
                Err(Halt::Cancelled)
            } else {
                Ok(())
            };
        }
        let far = Instant::now() + Duration::from_secs(600);
        wait_until(Instant::now() + self.wait, url_deadline, far, cancel)
    }

    fn record(&self, t: &Target) {
        let mut r = self.recorded.lock().unwrap();
        match r.iter_mut().find(|x| x.id == t.id) {
            Some(slot) => *slot = t.clone(),
            None => r.push(t.clone()),
        }
    }
}

impl Count {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn head(status: u16, headers: &[(&str, &str)]) -> Head {
    Head {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
    }
}

fn scan(t: &dyn Transport, g: &dyn Gate, urls: &[&str], timeout: Duration) -> Vec<Target> {
    let cancel = Cancel::default();
    let urls: Vec<String> = urls.iter().map(|s| s.to_string()).collect();
    Scan {
        transport: t,
        gate: g,
        cancel: &cancel,
        url_timeout: timeout,
        lang: Lang::Ko,
        criteria: super::criteria::fixture(),
    }
    .run(&urls, &mut |_| {})
}

const SECOND: Duration = Duration::from_secs(1);

/// `TestQuerySecretsAreRequestedButNeverReported`
#[test]
fn query_secrets_are_requested_but_never_reported() {
    const TOKEN: &str = "do-not-store-this-token";
    for fail in [false, true] {
        let t = fake(|_, input, _| {
            assert!(
                input.target.contains(&format!("token={TOKEN}")),
                "요청에서 쿼리가 빠졌다"
            );
            if fail {
                return Err(Failure::Other);
            }
            Ok(head(
                200,
                &[
                    ("Server", "fixture"),
                    ("X-Generator", TOKEN),
                    ("X-Php-Version", TOKEN),
                ],
            ))
        });
        let url = format!("https://example.com/path?token={TOKEN}");
        let out = scan(&t, &Count::default(), &[&url], SECOND);
        let json = serde_json::to_string(&out).unwrap();
        assert!(!json.contains(TOKEN), "결과에 쿼리가 실렸다: {json}");
        assert_eq!(out[0].url, "https://example.com/path?[가림]");
        assert_eq!(out[0].id.len(), "url:".len() + 64);
    }
}

/// `TestFallbackClosesBodyAndDeduplicates` — 본문은 처음부터 읽지 않는다(전송이 머리만 읽고 닫는다).
#[test]
fn fallback_goes_head_then_get_and_duplicates_collapse() {
    let methods = Mutex::new(Vec::new());
    let t = fake(|m, _, connected| {
        methods.lock().unwrap().push(m);
        let (status, ip) = match m {
            Method::Head => (405, "192.0.2.1"),
            Method::Get => (200, "192.0.2.2"),
        };
        assert!(connected(ip.parse().unwrap()));
        Ok(head(status, &[("X-Powered-By", "PHP/8.3.36")]))
    });
    let g = Count::default();
    let out = scan(
        &t,
        &g,
        &["http://EXAMPLE.com", "http://example.com:80/"],
        SECOND,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(*methods.lock().unwrap(), vec![Method::Head, Method::Get]);
    assert_eq!(g.calls(), 2);
    assert_eq!(g.recorded.lock().unwrap().len(), 1);
    assert_eq!(g.recorded.lock().unwrap()[0].id, out[0].id);
    assert_eq!(out[0].addresses, vec!["192.0.2.1", "192.0.2.2"]);
    assert_eq!((out[0].requests.head, out[0].requests.get), (1, 1));
    // 헤더는 끝까지 미확인이다 — 고친 버전을 알려도 양호가 아니다.
    assert_eq!(out[0].verdict, Verdict::ReviewRequired);
    assert!(out[0]
        .findings
        .iter()
        .all(|f| f.verdict == Verdict::ReviewRequired));
}

/// `TestHostStopAcrossSchemesPortsAndHead501Exception`
#[test]
fn a_stopped_host_stays_stopped_across_schemes_and_ports() {
    for first in [429, 500, 502, 503, 599] {
        let requested = Mutex::new(Vec::new());
        let t = fake(|_, input, _| {
            requested.lock().unwrap().push(input.key());
            Ok(head(first, &[]))
        });
        let g = Count::default();
        let out = scan(
            &t,
            &g,
            &[
                "https://example.com/a",
                "http://EXAMPLE.com:8080/b",
                "https://example.com:8443/c",
                "http://example.com./d",
                "https://other.example/",
            ],
            SECOND,
        );
        assert_eq!(requested.lock().unwrap().len(), 2, "{first}: {requested:?}");
        assert_eq!((g.calls(), out.len()), (2, 5), "{first}");
        for target in &out[1..4] {
            assert_eq!(target.requests.head, 0, "{first}: {target:?}");
            assert!(!target.gaps.is_empty());
        }
    }
    let methods = Mutex::new(Vec::new());
    let t = fake(|m, _, _| {
        methods.lock().unwrap().push(m);
        Ok(head(501, &[]))
    });
    scan(
        &t,
        &Count::default(),
        &["https://example.com/a", "https://example.com/b"],
        SECOND,
    );
    // HEAD 의 501 은 "HEAD 를 모른다" — GET 으로 넘어가고, GET 의 501 이 서버를 멈춘다.
    assert_eq!(*methods.lock().unwrap(), vec![Method::Head, Method::Get]);
}

/// `TestConnectionFailureStopsOtherSchemesAndPorts`
#[test]
fn a_connection_failure_stops_the_host() {
    for failure in [Failure::Closed, Failure::Timeout] {
        let t = fake(|_, _, _| Err(failure));
        let out = scan(
            &t,
            &Count::default(),
            &[
                "http://example.com/a",
                "https://EXAMPLE.com:8443/b",
                "http://other.example/",
            ],
            SECOND,
        );
        assert_eq!(t.calls(), 2, "{failure:?}");
        assert_eq!(out[1].requests.head, 0, "{failure:?}");
    }
}

/// `TestFallbackFailureStopsEveryObservedIP`
#[test]
fn a_failed_fallback_stops_every_ip_it_saw() {
    let t = fake(|m, _, connected| {
        let (status, ip) = match m {
            Method::Head => (501, "192.0.2.1"),
            Method::Get => (503, "192.0.2.2"),
        };
        if !connected(ip.parse().unwrap()) {
            return Err(Failure::Stopped);
        }
        Ok(head(status, &[]))
    });
    let g = Count::default();
    let out = scan(
        &t,
        &g,
        &[
            "http://example.com/",
            "https://192.0.2.1:8443/a",
            "http://192.0.2.2:8080/b",
        ],
        SECOND,
    );
    assert_eq!(g.calls(), 2);
    assert_eq!(out[0].addresses, vec!["192.0.2.1", "192.0.2.2"]);
    for target in &out[1..] {
        assert_eq!(target.requests.head, 0, "{target:?}");
    }
}

/// `TestURLDeadlineIncludesWaiting`
#[test]
fn the_url_deadline_covers_waiting_for_the_interval() {
    let t = fake(|_, _, _| panic!("요청을 보냈다"));
    let g = Count {
        wait: SECOND,
        ..Count::default()
    };
    let start = Instant::now();
    let out = scan(
        &t,
        &g,
        &["http://example.com/a", "http://example.com/b"],
        Duration::from_millis(20),
    );
    assert_eq!(t.calls(), 0);
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
    assert!(!out[1].gaps.is_empty());
}

/// `TestLimitFiftyUniqueURLsAndHundredRequests`
#[test]
fn fifty_unique_urls_and_a_hundred_requests_at_most() {
    let urls: Vec<String> = (0..55)
        .map(|i| format!("http://example.com/{}", "x".repeat(i)))
        .collect();
    let urls: Vec<&str> = urls.iter().map(String::as_str).collect();
    let t = fake(|_, _, _| Ok(head(405, &[])));
    let g = Count::default();
    let out = scan(&t, &g, &urls, SECOND);
    assert_eq!(g.calls(), 100);
    assert_eq!(out.len(), 51);
    assert_eq!(out[50].id, "url:input-limit");
}

/// `TestHeaderVersionWarningsRetainPatchUncertainty`
#[test]
fn header_versions_warn_but_never_clear() {
    for (version, want) in [
        ("8.3.2", Verdict::Vulnerable),
        ("8.3.36", Verdict::ReviewRequired),
        ("8.3.6-0ubuntu0.24.04.13", Verdict::ReviewRequired),
        ("8.2.35-1~deb12u1", Verdict::ReviewRequired),
        ("8.5.9-0ubuntu2.0", Verdict::Vulnerable),
        ("8.3.6-custom", Verdict::ReviewRequired),
        ("5.4.0", Verdict::Vulnerable),
        ("5.6.40", Verdict::Vulnerable),
        ("7.4.33", Verdict::Vulnerable),
        ("8.0.30", Verdict::Vulnerable),
        ("8.1.34", Verdict::Vulnerable),
        ("5.3.29", Verdict::ReviewRequired),
        ("5.6.40-custom", Verdict::ReviewRequired),
        ("7.4.33RC1", Verdict::ReviewRequired),
        ("7.4.3-4ubuntu2.29+esm4", Verdict::Vulnerable),
        ("7.4.3-4ubuntu2.29+esm5", Verdict::ReviewRequired),
        ("5.5.9+dfsg-1ubuntu4.29+esm17", Verdict::Vulnerable),
        ("5.5.9+dfsg-1ubuntu4.29+esm18", Verdict::ReviewRequired),
    ] {
        let banner = format!("PHP/{version}");
        let t = fake(|m, _, _| {
            assert_eq!(m, Method::Head, "{version}");
            Ok(head(200, &[("X-Powered-By", banner.as_str())]))
        });
        let g = Count::default();
        let out = scan(&t, &g, &["https://example.com/"], SECOND);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].verdict, want, "{version}");
        assert_eq!(g.calls(), 1, "{version}");
        if want == Verdict::Vulnerable {
            for reason in [&out[0].reason, &out[0].findings[0].reason] {
                assert!(
                    reason.contains("헤더 기준")
                        && reason.contains("백포트 패치 적용 여부는 확인하지 못했습니다"),
                    "{version}: 경고가 한계를 잃었다 — {reason}"
                );
            }
        }
    }
}

/// `TestHeaderWarningSurvivesInterruptedFallback`
#[test]
fn a_head_warning_survives_an_interrupted_fallback() {
    let get_started = AtomicBool::new(false);
    let cancel = Cancel::default();
    let t = fake(|m, _, _| match m {
        Method::Head => Ok(head(405, &[("X-Powered-By", "PHP/8.3.2")])),
        Method::Get => {
            get_started.store(true, Ordering::SeqCst);
            while !cancel.is_set() {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(Failure::Cancelled)
        }
    });
    let budget = Budget::with(
        Duration::ZERO,
        100,
        Instant::now() + Duration::from_secs(60),
        Lang::Ko,
    );
    std::thread::scope(|s| {
        let job = s.spawn(|| {
            Scan {
                transport: &t,
                gate: &budget,
                cancel: &cancel,
                url_timeout: Duration::from_secs(5),
                lang: Lang::Ko,
                criteria: super::criteria::fixture(),
            }
            .run(&["https://example.com/".to_string()], &mut |_| {})
        });
        let start = Instant::now();
        while !get_started.load(Ordering::SeqCst) {
            assert!(start.elapsed() < SECOND, "GET 이 시작하지 않았다");
            std::thread::sleep(Duration::from_millis(5));
        }
        let partial = budget.partial();
        assert_eq!(partial.len(), 1);
        assert_eq!(partial[0].verdict, Verdict::Vulnerable);
        assert!(partial[0].findings[0].reason.contains("헤더 기준"));
        cancel.set();
        let start = Instant::now();
        let out = job.join().unwrap();
        assert!(start.elapsed() < SECOND, "취소한 GET 이 끝나지 않았다");
        assert_eq!(out[0].verdict, Verdict::Vulnerable);
    });
}

/// `TestRequestErrorUsesOnlySafeClassifications` — 오류의 글자는 분류에 쓰지도 옮기지도 않는다.
#[test]
fn errors_are_classified_without_their_text() {
    const SECRET: &str = "MOCK_RAW_ERROR_OR_CERTIFICATE_SECRET";
    let certificate = rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
        rustls::OtherError(Arc::new(io::Error::other(SECRET))),
    ));
    for (err, want) in [
        (io::Error::other(SECRET), "HTTP 통신을 완료할 수 없습니다"),
        (io::Error::new(io::ErrorKind::TimedOut, SECRET), "제한 시간"),
        (
            io::Error::new(io::ErrorKind::ConnectionReset, SECRET),
            "연결을 종료",
        ),
        (
            io::Error::new(io::ErrorKind::UnexpectedEof, SECRET),
            "연결을 종료",
        ),
        (
            io::Error::new(io::ErrorKind::InvalidData, certificate),
            "certificate",
        ),
    ] {
        let got = classify(&err).message(Lang::Ko);
        assert!(!got.contains(SECRET) && got.contains(want), "{got}");
    }
    for (f, want) in [
        (Failure::TooLarge, "response headers exceeded 32768 bytes"),
        (Failure::Malformed, "HTTP 응답 형식"),
        (Failure::Stopped, "HTTP 요청 전에"),
        (Failure::Cancelled, "취소"),
    ] {
        assert!(f.message(Lang::Ko).contains(want), "{f:?}");
    }
}

/// `TestWindowsResetErrorsStopOrigin`
#[cfg(windows)]
#[test]
fn windows_reset_errors_stop_the_server() {
    // WSAECONNRESET · WSAECONNABORTED · ERROR_NETNAME_DELETED
    for code in [10054, 10053, 64] {
        let e = io::Error::from_raw_os_error(code);
        assert!(classify(&e).stops_server(), "{code}: {:?}", classify(&e));
    }
}

// ── 127.0.0.1 의 시험 서버 ─────────────────────────────────────────────────

enum Reply {
    Bytes(Vec<u8>),
    /// 요청을 읽고 아무 말 없이 닫는다.
    Close,
    /// 요청을 읽고 답하지 않는다(상대가 닫을 때까지).
    Hang,
}

struct Server {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
}

type Handler = dyn Fn(&str, &str, &[(String, String)]) -> Reply + Send + Sync;

fn serve(
    tls: Option<Arc<rustls::ServerConfig>>,
    f: impl Fn(&str, &str, &[(String, String)]) -> Reply + Send + Sync + 'static,
) -> Server {
    let handler: Arc<Handler> = Arc::new(f);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(AtomicUsize::new(0));
    let (r, c) = (Arc::clone(&requests), Arc::clone(&connections));
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            c.fetch_add(1, Ordering::SeqCst);
            let (tls, handler, r) = (tls.clone(), Arc::clone(&handler), Arc::clone(&r));
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                match tls {
                    None => talk(&mut &stream, &*handler, &r),
                    Some(cfg) => {
                        let conn = rustls::ServerConnection::new(cfg).unwrap();
                        talk(&mut rustls::StreamOwned::new(conn, stream), &*handler, &r);
                    }
                }
            });
        }
    });
    Server {
        addr,
        requests,
        connections,
    }
}

fn talk(io: &mut dyn ReadWrite, handler: &Handler, requests: &AtomicUsize) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match io.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if buf.len() > 8192 {
            return;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(req.parse(&buf), Ok(httparse::Status::Complete(_))) {
        return;
    }
    requests.fetch_add(1, Ordering::SeqCst);
    let hs: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    match handler(req.method.unwrap_or(""), req.path.unwrap_or(""), &hs) {
        Reply::Bytes(b) => {
            let _ = io.write_all(&b);
            let _ = io.flush();
        }
        Reply::Close => {}
        Reply::Hang => {
            let _ = io.read(&mut chunk);
        }
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn reply(status: u16, headers: &[(&str, &str)]) -> Reply {
    let mut s = format!("HTTP/1.1 {status} X\r\n");
    for (n, v) in headers {
        s.push_str(&format!("{n}: {v}\r\n"));
    }
    s.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    Reply::Bytes(s.into_bytes())
}

/// 루트가 없는 클라이언트 — TLS 를 쓰지 않는 시험용.
fn plain_net() -> Net {
    Net::new(trust::client_config_with(rustls::RootCertStore::empty()).unwrap())
}

/// 시험 CA 하나와, 그 CA 가 127.0.0.1 에 서명한 서버 설정.
struct TestCa {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    cert: rcgen::Certificate,
}

fn test_ca() -> TestCa {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "remedy-net unit test CA");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params.self_signed(&key).unwrap();
    TestCa { params, key, cert }
}

fn tls_server_config(ca: &TestCa) -> Arc<rustls::ServerConfig> {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key);
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

fn exchange(net: &Net, method: Method, url: &str, timeout: Duration) -> Result<Head, Failure> {
    let input = Input::parse(url).unwrap();
    net.exchange(
        method,
        &input,
        Instant::now() + timeout,
        &Cancel::default(),
        &mut |_| true,
    )
}

/// `TestTransportStopsObservedIPBeforeSending`
#[test]
fn a_stopped_ip_gets_no_bytes_even_under_a_new_name() {
    let server = serve(None, |_, path, _| {
        if path == "/unavailable" {
            reply(503, &[])
        } else {
            reply(200, &[])
        }
    });
    let addr = server.addr;
    let lookups = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&lookups);
    // 모든 이름을 시험 서버로 — 이름 풀이 없이 연결 검사를 지난다.
    let net = Net::resolving(
        trust::client_config_with(rustls::RootCertStore::empty()).unwrap(),
        Arc::new(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(vec![addr])
        }),
    );
    let g = Count::default();
    let literal = format!("http://{addr}/ip-literal");
    let out = scan(
        &net,
        &g,
        &[
            "http://known.example/healthy",
            "http://stopped.example/unavailable",
            "https://known.example:9443/after",
            "http://fresh.example/after",
            "https://fresh.example:8443/again",
            &literal,
        ],
        SECOND,
    );
    assert_eq!(
        server.requests.load(Ordering::SeqCst),
        2,
        "멈춘 IP 가 요청을 받았다"
    );
    assert_eq!(lookups.load(Ordering::SeqCst), 3);
    assert_eq!(g.calls(), 3);
    for target in &out[2..] {
        assert_eq!(
            (target.requests.head, target.requests.get),
            (0, 0),
            "{target:?}"
        );
    }
    assert_eq!(out[3].addresses, vec!["127.0.0.1"]);
    assert!(
        out[3].gaps.iter().any(|g| g.contains("HTTP 요청 전에")),
        "{:?}",
        out[3].gaps
    );
}

/// `TestTransportDoesNotFollowRedirectOrUseProxy` — 프록시는 읽는 코드가 없다(환경 변수는 명령줄 시험
/// `proxy-environment` 가 실제 프로세스로 본다).
#[test]
fn redirects_are_reported_not_followed_and_no_credentials_are_sent() {
    let server = serve(None, |_, _, headers| {
        for (n, _) in headers {
            assert!(
                !["cookie", "authorization", "proxy-authorization"]
                    .contains(&n.to_ascii_lowercase().as_str()),
                "보내지 않을 헤더 {n}"
            );
        }
        reply(302, &[("Location", "/followed")])
    });
    let out = scan(
        &plain_net(),
        &Count::default(),
        &[&format!("http://{}/", server.addr)],
        SECOND,
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    assert_eq!(out[0].status.head, Some(302));
    assert_eq!(out[0].requests.get, 0);
    assert_eq!(out[0].addresses, vec!["127.0.0.1"]);
    assert!(out[0].gaps.iter().any(|g| g.contains("리디렉션")));
}

/// `TestTransportMakesNoHiddenRetry`
#[test]
fn a_dropped_connection_is_not_retried() {
    let first = Arc::new(AtomicBool::new(true));
    let server = serve(None, move |_, _, _| {
        if first.swap(false, Ordering::SeqCst) {
            reply(200, &[])
        } else {
            Reply::Close
        }
    });
    let net = plain_net();
    let url = format!("http://{}/", server.addr);
    assert!(exchange(&net, Method::Head, &url, SECOND).is_ok());
    assert_eq!(
        exchange(&net, Method::Head, &url, SECOND).unwrap_err(),
        Failure::Closed
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        2,
        "연결을 다시 썼다"
    );
}

/// `TestTransportEnforcesTLSAndHeaderLimit`
#[test]
fn untrusted_tls_and_oversized_headers_are_refused() {
    let ca = test_ca();
    let tls = serve(Some(tls_server_config(&ca)), |_, _, _| reply(200, &[]));
    let err = exchange(
        &Net::new(trust::client_config(&[]).unwrap()),
        Method::Head,
        &format!("https://{}/", tls.addr),
        SECOND,
    )
    .unwrap_err();
    assert_eq!(err, Failure::Certificate);
    assert_eq!(tls.requests.load(Ordering::SeqCst), 0);

    let large = "x".repeat(super::policy::MAX_HEADER_BYTES + 1);
    let plain = serve(None, move |_, _, _| {
        reply(200, &[("X-Large", large.as_str())])
    });
    let err = exchange(
        &plain_net(),
        Method::Head,
        &format!("http://{}/", plain.addr),
        SECOND,
    )
    .unwrap_err();
    assert_eq!(err, Failure::TooLarge);
}

/// `TestTransportTrustsOnlyProvidedCACert`
#[test]
fn a_given_ca_is_trusted_for_this_run_only() {
    let ca = test_ca();
    let tls = serve(Some(tls_server_config(&ca)), |_, _, _| reply(200, &[]));
    let url = format!("https://{}/", tls.addr);
    let trusted = Net::new(trust::client_config(&[ca.cert.der().clone()]).unwrap());
    assert_eq!(
        exchange(&trusted, Method::Head, &url, SECOND)
            .unwrap()
            .status,
        200
    );
    let other = test_ca();
    let wrong = Net::new(trust::client_config(&[other.cert.der().clone()]).unwrap());
    assert_eq!(
        exchange(&wrong, Method::Head, &url, SECOND).unwrap_err(),
        Failure::Certificate
    );
}

/// `TestMalformedHTTPResponseNeverReportsServerText`
#[test]
fn a_malformed_response_never_reaches_the_report() {
    for (response, secret) in [
        (
            "HTTP/1.1 200 OK\r\nMOCK_MALFORMED_HEADER_SECRET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "MOCK_MALFORMED_HEADER_SECRET",
        ),
        (
            "HTTP/1.1 MOCK_MALFORMED_STATUS_SECRET invalid\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "MOCK_MALFORMED_STATUS_SECRET",
        ),
    ] {
        let server = serve(
            None,
            move |_, _, _| Reply::Bytes(response.as_bytes().to_vec()),
        );
        let g = Count::default();
        let out = scan(&plain_net(), &g, &[&format!("http://{}/", server.addr)], SECOND);
        let json = serde_json::to_string(&out).unwrap();
        assert!(!json.contains(secret), "서버의 글자가 결과에 실렸다: {json}");
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
        assert_eq!(g.calls(), 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].verdict, Verdict::ReviewRequired);
        assert_eq!((out[0].requests.head, out[0].requests.get), (1, 0));
        assert!(out[0].gaps.iter().any(|g| g.contains("HTTP 응답 형식")), "{:?}", out[0].gaps);
    }
}

/// 실제 전송의 시한 — 답하지 않는 서버는 URL 시한에 끊고, 그 서버를 멈춘다(스캐너 시험 `timeout` 의 아래층).
#[test]
fn a_silent_server_times_out_at_the_deadline() {
    let server = serve(None, |_, _, _| Reply::Hang);
    let start = Instant::now();
    let err = exchange(
        &plain_net(),
        Method::Head,
        &format!("http://{}/", server.addr),
        Duration::from_millis(300),
    )
    .unwrap_err();
    assert_eq!(err, Failure::Timeout);
    assert!(err.stops_server());
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_secs(2),
        "{took:?}"
    );
}

/// 1xx 안내 응답은 건너뛰고 그 뒤의 응답 머리를 읽는다.
#[test]
fn informational_responses_are_skipped() {
    let server = serve(None, |_, _, _| {
        Reply::Bytes(
                b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.3.36\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            )
    });
    let h = exchange(
        &plain_net(),
        Method::Head,
        &format!("http://{}/", server.addr),
        SECOND,
    )
    .unwrap();
    assert_eq!(h.status, 200);
    assert!(h
        .headers
        .iter()
        .any(|(n, v)| n == "X-Powered-By" && v == "PHP/8.3.36"));
}

/// 요청 줄과 헤더 — 정해 둔 셋 말고는 보내지 않는다(쿠키 · 인증 · 압축 · 프록시 헤더 없음).
#[test]
fn only_host_user_agent_and_connection_are_sent() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&seen);
    let server = serve(None, move |method, path, headers| {
        keep.lock().unwrap().push((
            method.to_string(),
            path.to_string(),
            headers
                .iter()
                .map(|(n, _)| n.to_ascii_lowercase())
                .collect::<Vec<_>>(),
        ));
        reply(200, &[])
    });
    let url = format!("http://{}/a%20b?x=1", server.addr);
    exchange(&plain_net(), Method::Get, &url, SECOND).unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].0, "GET");
    assert_eq!(seen[0].1, "/a%20b?x=1");
    assert_eq!(seen[0].2, vec!["host", "user-agent", "connection"]);
}

/// 요청마다 연결을 새로 맺는다 — HEAD 405 뒤의 GET 도 새 연결이다.
#[test]
fn each_request_opens_its_own_connection() {
    let server = serve(None, |_, _, _| reply(405, &[]));
    let g = Count::default();
    scan(
        &plain_net(),
        &g,
        &[&format!("http://{}/", server.addr)],
        SECOND,
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 2, "HEAD 405 → GET");
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
}
