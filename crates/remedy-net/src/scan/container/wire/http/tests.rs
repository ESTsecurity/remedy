//! HTTP 틀의 시험 — 지은 연결로 틀을 보고, 파이프 스레드와(유닉스면) 실제 소켓으로 시한 · 취소를 본다.

use super::*;
use crate::scan::budget::{Budget, Cancel, Halt};
use crate::scan::container::wire::link::PumpLink;
use crate::scan::model::TargetKind;
use remedy_sdk::i18n::Lang;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 받을 바이트를 정해 둔 연결 — `chunk` 바이트씩 준다.
struct Script {
    input: Vec<u8>,
    pos: usize,
    chunk: usize,
    sent: Arc<Mutex<Vec<u8>>>,
}

impl Link for Script {
    fn send(&mut self, bytes: &[u8], _: &Watch<'_>) -> Result<(), Failure> {
        self.sent.lock().unwrap().extend_from_slice(bytes);
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8], _: &Watch<'_>) -> Result<usize, Failure> {
        let n = buf.len().min(self.chunk).min(self.input.len() - self.pos);
        buf[..n].copy_from_slice(&self.input[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn budget() -> Budget {
    Budget::new(TargetKind::Container, Cancel::default(), Lang::Ko)
}

fn call(method: Method, deadline: Instant) -> Call<'static> {
    Call {
        method,
        path: "/v1.44/containers/json",
        query: "",
        deadline,
    }
}

/// 응답을 받고 본문을 끝까지 읽는다 — (상태, Content-Length, 본문).
fn fetch(
    response: &[u8],
    method: Method,
    chunk: usize,
) -> Result<(u16, Option<u64>, Vec<u8>), Failure> {
    let b = budget();
    let link = Script {
        input: response.to_vec(),
        pos: 0,
        chunk,
        sent: Arc::default(),
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let watch = Watch {
        deadline,
        budget: &b,
    };
    let mut reply = exchange(Box::new(link), &call(method, deadline), watch)?;
    let mut body = Vec::new();
    reply
        .body
        .read_to_end(&mut body)
        .map_err(|e| Failure::from_io(&e))?;
    Ok((reply.status, reply.content_length, body))
}

fn get(response: &str) -> Result<(u16, Option<u64>, Vec<u8>), Failure> {
    // 한 바이트씩 받아도 같은 답이어야 한다.
    let whole = fetch(response.as_bytes(), Method::Get, 1 << 16);
    assert_eq!(
        whole,
        fetch(response.as_bytes(), Method::Get, 1),
        "{response:?}"
    );
    whole
}

#[test]
fn the_request_carries_only_the_four_headers() {
    let b = budget();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let link = Script {
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        pos: 0,
        chunk: 64,
        sent: sent.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let c = Call {
        method: Method::Head,
        path: "/v1.44/containers/abc/archive",
        query: "path=%2Fetc%2Fos-release",
        deadline,
    };
    exchange(
        Box::new(link),
        &c,
        Watch {
            deadline,
            budget: &b,
        },
    )
    .unwrap();
    let text = String::from_utf8(sent.lock().unwrap().clone()).unwrap();
    assert_eq!(
        text,
        format!(
            "HEAD /v1.44/containers/abc/archive?path=%2Fetc%2Fos-release HTTP/1.1\r\nHost: local-engine\r\n\
             User-Agent: {USER_AGENT}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        )
    );
}

#[test]
fn content_length_bodies_stop_at_the_length() {
    let got = get("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA").unwrap();
    assert_eq!(got, (200, Some(5), b"hello".to_vec()));
    let same = get("HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length:  2\r\n\r\nok").unwrap();
    assert_eq!(same.2, b"ok");
    for bad in [
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\nok",
    ] {
        assert_eq!(get(bad), Err(Failure::Wire(Wire::Framing)), "{bad:?}");
    }
    assert_eq!(
        get("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"),
        Err(Failure::Wire(Wire::Closed))
    );
}

#[test]
fn chunked_bodies_are_decoded_and_held_to_go_rules() {
    let ok = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n\
              5;ext=1\r\nhello\r\n6 \r\n world\r\n0\r\nX-Trailer: a\r\n\r\n";
    assert_eq!(get(ok).unwrap(), (200, None, b"hello world".to_vec()));
    let upper = "HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n";
    assert_eq!(get(upper).unwrap().2, b"0123456789");
    for bad in [
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n00000000000000005\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nxx",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    ] {
        assert_eq!(get(bad), Err(Failure::Wire(Wire::Framing)), "{bad:?}");
    }
    let long = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;{}\r\nx\r\n0\r\n\r\n",
        "e".repeat(5000)
    );
    assert_eq!(get(&long), Err(Failure::Wire(Wire::Framing)));
    // 1 바이트 조각마다 긴 확장 — 데이터보다 덧붙은 글자가 16 KiB 넘게 쌓인다.
    let mut noisy = String::from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    for _ in 0..200 {
        noisy.push_str(&format!("1;{}\r\nx\r\n", "e".repeat(100)));
    }
    noisy.push_str("0\r\n\r\n");
    assert_eq!(get(&noisy), Err(Failure::Wire(Wire::Framing)));
    let cut = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
    assert_eq!(get(cut), Err(Failure::Wire(Wire::Closed)));
    // HTTP/1.0 은 Transfer-Encoding 을 보지 않는다.
    let old = "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello";
    assert_eq!(get(old).unwrap().2, b"5\r\nhello");
}

#[test]
fn bodies_without_length_end_when_the_engine_closes() {
    assert_eq!(
        get("HTTP/1.1 200 OK\r\n\r\nabc").unwrap(),
        (200, None, b"abc".to_vec())
    );
}

#[test]
fn head_204_and_304_carry_no_body() {
    let head = fetch(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\nNOT A BODY",
        Method::Head,
        64,
    )
    .unwrap();
    assert_eq!(head, (200, Some(1234), Vec::new()));
    let bad_head = fetch(
        b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
        Method::Head,
        64,
    );
    assert_eq!(bad_head, Err(Failure::Wire(Wire::Framing)));
    assert_eq!(
        get("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello")
            .unwrap()
            .2,
        b""
    );
    assert_eq!(
        get("HTTP/1.1 304 Not Modified\r\n\r\nhello").unwrap().2,
        b""
    );
}

#[test]
fn informational_responses_are_skipped_five_times_at_most() {
    let ok = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    assert_eq!(get(ok).unwrap(), (200, Some(2), b"ok".to_vec()));
    let many = format!(
        "{}HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 100 Continue\r\n\r\n".repeat(6)
    );
    assert_eq!(get(&many), Err(Failure::Wire(Wire::Malformed)));
}

#[test]
fn a_bad_or_oversized_head_is_refused() {
    assert_eq!(
        get("SSH-2.0-OpenSSH\r\n\r\n"),
        Err(Failure::Wire(Wire::Malformed))
    );
    let big = format!("HTTP/1.1 200 OK\r\nX-Big: {}\r\n\r\n", "a".repeat(33 << 10));
    assert_eq!(get(&big), Err(Failure::Wire(Wire::HeaderTooLarge)));
    assert_eq!(
        get("HTTP/1.1 200 OK\r\nContent-Le"),
        Err(Failure::Wire(Wire::Closed))
    );
    let headers = get("HTTP/1.1 404 Not Found\r\nX-Docker-Container-Path-Stat:  abc \r\nContent-Length: 0\r\n\r\n");
    assert_eq!(headers.unwrap().0, 404);
}

/// 받은 만큼을 주고 나면 풀릴 때까지 막히는 연결 — 파이프 스레드가 읽는다.
struct Stall {
    script: Vec<u8>,
    pos: usize,
    release: Arc<AtomicBool>,
}

impl std::io::Read for Stall {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.script.len() {
            let n = buf.len().min(self.script.len() - self.pos);
            buf[..n].copy_from_slice(&self.script[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        while !self.release.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(0)
    }
}

impl std::io::Write for Stall {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 막힌 파이프에서 읽기 — 시한에 끝나고, 취소되면 그 까닭으로 끝난다(본문을 읽는 중에도).
#[test]
fn a_stalled_pump_link_ends_at_the_deadline_or_on_cancel() {
    let release = Arc::new(AtomicBool::new(false));
    let stall = |script: &[u8]| Stall {
        script: script.to_vec(),
        pos: 0,
        release: release.clone(),
    };
    let b = budget();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(300);
    let watch = Watch {
        deadline,
        budget: &b,
    };
    let link = PumpLink::start(stall(b""));
    let got = exchange(Box::new(link), &call(Method::Get, deadline), watch);
    assert_eq!(got.err(), Some(Failure::Wire(Wire::Timeout)));
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(290) && elapsed < Duration::from_secs(3),
        "{elapsed:?}"
    );
    // 머리는 왔고 본문에서 막혔다 — 취소가 읽기를 끝낸다.
    let cancel = Cancel::default();
    let b = Budget::new(TargetKind::Container, cancel.clone(), Lang::Ko);
    let deadline = Instant::now() + Duration::from_secs(30);
    let link = PumpLink::start(stall(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n"));
    let mut reply = exchange(
        Box::new(link),
        &call(Method::Get, deadline),
        Watch {
            deadline,
            budget: &b,
        },
    )
    .unwrap();
    let trigger = cancel.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        trigger.set();
    });
    let started = Instant::now();
    let mut body = Vec::new();
    let err = reply.body.read_to_end(&mut body).unwrap_err();
    assert_eq!(Failure::from_io(&err), Failure::Halt(Halt::Cancelled));
    assert!(started.elapsed() < Duration::from_secs(3));
    canceller.join().unwrap();
    release.store(true, Ordering::SeqCst);
}

#[test]
fn a_pump_link_reports_a_failed_write_and_reads_to_the_close() {
    struct Broken;
    impl std::io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let b = budget();
    let deadline = Instant::now() + Duration::from_secs(5);
    let watch = Watch {
        deadline,
        budget: &b,
    };
    let got = exchange(
        Box::new(PumpLink::start(Broken)),
        &call(Method::Get, deadline),
        watch,
    );
    assert_eq!(got.err(), Some(Failure::Wire(Wire::Closed)));
    let done = Stall {
        script: b"HTTP/1.1 200 OK\r\n\r\nall".to_vec(),
        pos: 0,
        release: Arc::new(AtomicBool::new(true)),
    };
    let mut reply = exchange(
        Box::new(PumpLink::start(done)),
        &call(Method::Get, deadline),
        watch,
    )
    .unwrap();
    let mut body = Vec::new();
    reply.body.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"all");
}

/// 실제 Unix 소켓 — 틀과 시한을 커널의 소켓으로 본다.
#[cfg(unix)]
mod unix {
    use super::*;
    use crate::scan::container::wire::link::UnixLink;
    use std::io::Write as _;
    use std::os::unix::net::UnixListener;

    fn socket_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("remedy-net-ctr-{name}-{}.sock", std::process::id()))
    }

    /// 요청을 다 받은 뒤 `script` 를 쓰고, `hold` 면 풀릴 때까지 연결을 쥔다.
    fn serve(
        name: &str,
        script: Vec<u8>,
        hold: Arc<AtomicBool>,
    ) -> (std::path::PathBuf, std::thread::JoinHandle<Vec<u8>>) {
        let path = socket_path(name);
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            s.write_all(&script).unwrap();
            while !hold.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
            request
        });
        (path, handle)
    }

    #[test]
    fn a_real_socket_carries_a_chunked_response() {
        let release = Arc::new(AtomicBool::new(true));
        let script =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n".to_vec();
        let (path, server) = serve("chunked", script, release);
        let b = budget();
        let deadline = Instant::now() + Duration::from_secs(10);
        let watch = Watch {
            deadline,
            budget: &b,
        };
        let link = UnixLink::connect(path.to_str().unwrap(), &watch).unwrap();
        let mut reply = exchange(Box::new(link), &call(Method::Get, deadline), watch).unwrap();
        let mut body = Vec::new();
        reply.body.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"abc");
        let request = String::from_utf8(server.join().unwrap()).unwrap();
        assert!(
            request.starts_with("GET /v1.44/containers/json HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains("Connection: close\r\n"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_real_socket_times_out_before_and_after_the_head() {
        for (name, script) in [
            ("before", Vec::new()),
            (
                "after",
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n".to_vec(),
            ),
        ] {
            let release = Arc::new(AtomicBool::new(false));
            let (path, server) = serve(name, script, release.clone());
            let b = budget();
            let started = Instant::now();
            let deadline = started + Duration::from_millis(400);
            let watch = Watch {
                deadline,
                budget: &b,
            };
            let link = UnixLink::connect(path.to_str().unwrap(), &watch).unwrap();
            let got =
                exchange(Box::new(link), &call(Method::Get, deadline), watch).and_then(|mut r| {
                    let mut body = Vec::new();
                    r.body
                        .read_to_end(&mut body)
                        .map_err(|e| Failure::from_io(&e))?;
                    Ok(body)
                });
            assert_eq!(got, Err(Failure::Wire(Wire::Timeout)), "{name}");
            let elapsed = started.elapsed();
            assert!(
                elapsed >= Duration::from_millis(390) && elapsed < Duration::from_secs(3),
                "{name}: {elapsed:?}"
            );
            release.store(true, Ordering::SeqCst);
            server.join().unwrap();
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn a_missing_socket_is_reported_without_waiting() {
        let b = budget();
        let deadline = Instant::now() + Duration::from_secs(5);
        let path = socket_path("missing");
        let _ = std::fs::remove_file(&path);
        let got = UnixLink::connect(
            path.to_str().unwrap(),
            &Watch {
                deadline,
                budget: &b,
            },
        );
        assert_eq!(got.err(), Some(Failure::Wire(Wire::Missing)));
    }
}
