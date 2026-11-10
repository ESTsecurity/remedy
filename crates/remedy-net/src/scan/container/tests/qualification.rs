//! 자격 시험 — 스캐너 `qualification_test.go` · `qualification_integration_test.go`.
//!
//! 통합 시험(실제 HTTP 서버 · 30초 시한 · 127 MiB 흐름)도 옮겼다. 실제 HTTP 는 파이프 스레드 위의 HTTP/1.1
//! ([`Wired`])로 돌고, 시한은 짧게 바꿔 끼워(요청 0.3초 · 아카이브 0.9초) 실제 시각으로 잰다. 초당 10 MiB 맞춤은
//! 시계를 바꿔 끼운 예산이 시각으로만 지나간다.

use super::support::*;
use crate::scan::budget::{Halt, CONTAINER_LIMIT};
use crate::scan::container::client::{Timeouts, BINARY_PREFIX};
use crate::scan::container::failure::{Failure, FileFailure, Policy, Wire};
use crate::scan::container::wire::{Call, Method};
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 원본 `TestQualificationDeniedAPIsNeverReachEngine`.
#[test]
fn denied_apis_never_reach_the_engine() {
    let (b, _, _) = budget();
    let engine = Engine::new(|_| Ok(Answer::status(500)));
    let mut c = client(&b, &engine, "linux");
    let archive = format!("/containers/{TEST_ID}/archive");
    let cases: Vec<Api> = vec![
        ("POST", "/containers/create".into(), vec![]),
        ("POST", format!("/containers/{TEST_ID}/exec"), vec![]),
        ("POST", format!("/containers/{TEST_ID}/start"), vec![]),
        ("POST", format!("/containers/{TEST_ID}/stop"), vec![]),
        ("DELETE", format!("/containers/{TEST_ID}"), vec![]),
        ("GET", format!("/containers/{TEST_ID}/top"), vec![]),
        ("GET", format!("/containers/{TEST_ID}/export"), vec![]),
        ("PUT", archive.clone(), vec![("path", "/usr/bin/node")]),
        ("GET", archive.clone(), vec![("path", "/")]),
        ("GET", archive.clone(), vec![("path", "/usr/bin/")]),
        ("GET", archive.clone(), vec![("path", "/usr/../node")]),
        (
            "GET",
            archive.clone(),
            vec![("path", "/usr/bin/node"), ("path", "/etc/shadow")],
        ),
    ];
    for (method, route, query) in &cases {
        assert!(c.request(method, route, query).is_err(), "{method} {route}");
    }
    assert_eq!(engine.count(), 0);
    assert_eq!(b.usage().container_requests, 0);
}

/// 원본 `TestQualificationDirectoryHEADNeverStartsArchiveGET`.
#[test]
fn a_directory_head_never_starts_an_archive_get() {
    let (b, _, _) = budget();
    let engine = Engine::new(|_| {
        Ok(Answer::ok(Vec::new()).stat(&encoded_stat("bin", 0, MODE_DIR | 0o755, "")))
    });
    let mut c = client(&b, &engine, "linux");
    assert!(c.read_binary(TEST_ID, "/usr/bin").is_err());
    let methods: Vec<Method> = engine.calls().iter().map(|s| s.method).collect();
    assert_eq!(methods, [Method::Head]);
    assert_eq!(b.usage().container_requests, 1);
}

/// 원본 `TestQualificationBinaryStreamRejectsAdditionalAndUnsafeMembers` — 받지 않는 흐름은 해시를 남기지 않고, 읽은
/// 바이트는 모두 센다. 압축 응답과 크기 상한을 넘는 `Content-Length` 는 본문을 읽지 않는다.
#[test]
fn a_binary_stream_rejects_additional_and_unsafe_members() {
    let valid = make_archive(&[Entry::xs("node", 3).mode(0o755)]);
    // gzip 의 마법 글자로 시작하는 tar 가 아닌 바이트 — 압축을 풀지 않으므로 내용은 상관없다.
    let mut zipped = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff];
    zipped.extend_from_slice(&valid[..64]);
    let twice = [valid.clone(), valid.clone()].concat();
    let cases: Vec<(&str, Vec<u8>, &str, Option<u64>)> = vec![
        (
            "extra_member_after_hashed_file",
            make_archive(&[Entry::xs("node", 3).mode(0o755), Entry::xs("extra", 1)]),
            "",
            None,
        ),
        ("second_archive_after_terminator", twice, "", None),
        (
            "parent_path",
            make_archive(&[Entry::xs("../node", 3)]),
            "",
            None,
        ),
        (
            "absolute_path",
            make_archive(&[Entry::xs("/node", 3)]),
            "",
            None,
        ),
        (
            "hardlink",
            make_archive(&[Entry::special("node", b'1', "other")]),
            "",
            None,
        ),
        (
            "symlink",
            make_archive(&[Entry::special("node", b'2', "/outside")]),
            "",
            None,
        ),
        (
            "hidden_pax",
            make_archive(&[Entry::xs("node", 3).pax("comment", "unreviewed")]),
            "",
            None,
        ),
        ("compressed_http_response", zipped.clone(), "gzip", None),
        ("compressed_body_without_encoding", zipped, "", None),
        (
            "content_length_exceeds_wire_budget",
            valid.clone(),
            "",
            Some((1 << 20) + 4),
        ),
    ];
    for (name, body, encoding, length) in cases {
        let (b, _, _) = budget();
        let read = Arc::new(Mutex::new(0u64));
        let counter = read.clone();
        let engine = Engine::new(move |s| {
            let stat = encoded_stat("node", 3, 0o755, "");
            if s.method != Method::Get {
                return Ok(Answer::ok(Vec::new()).stat(&stat));
            }
            let counted = Counting {
                inner: io::Cursor::new(body.clone()),
                n: counter.clone(),
            };
            let mut a = Answer::reader(counted).stat(&stat);
            if !encoding.is_empty() {
                a = a.header("Content-Encoding", encoding);
            }
            a.content_length = length;
            Ok(a)
        });
        let mut c = client(&b, &engine, "linux");
        assert!(
            c.read_binary(TEST_ID, "/usr/local/bin/node").is_err(),
            "{name}"
        );
        let read = *read.lock().unwrap();
        if !encoding.is_empty() || length.is_some() {
            assert_eq!(read, 0, "{name}: 거절한 응답의 본문을 읽었다");
        }
        assert_eq!(b.usage().container_bytes, read, "{name}");
    }
}

/// 원본 `TestQualificationCancellationAfterHTTPHeadersDiscardsHash` — 응답 머리 뒤의 취소는 막힌 본문 읽기를 끝내고
/// 해시를 남기지 않는다.
#[test]
fn a_cancel_after_the_http_head_discards_the_hash() {
    let (b, _, cancel) = budget();
    let release = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicBool::new(false));
    let (hold, flag) = (release.clone(), started.clone());
    let stat = encoded_stat("node", 4096, 0o755, "");
    let wired = Wired::new(move |call: &Call<'_>| -> Box<dyn Read + Send> {
        let headers = [("X-Docker-Container-Path-Stat", stat.clone())];
        if call.method == Method::Head {
            return Box::new(io::Cursor::new(head("200 OK", &headers)));
        }
        flag.store(true, Ordering::SeqCst);
        Box::new(io::Cursor::new(head("200 OK", &headers)).chain(Hold(hold.clone())))
    });
    let canceller = std::thread::spawn(move || {
        while !started.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(100));
        cancel.set();
    });
    let mut c = client(&b, &wired, "linux");
    let begun = Instant::now();
    assert_eq!(
        c.read_binary(TEST_ID, "/usr/bin/node").err(),
        Some(Failure::Halt(Halt::Cancelled))
    );
    assert!(
        begun.elapsed() < Duration::from_secs(5),
        "취소한 응답이 멈추지 않았다"
    );
    canceller.join().unwrap();
    release.store(true, Ordering::SeqCst);
    assert_eq!(b.usage().container_requests, 2);
}

/// 원본 `TestQualificationCanceledReadNeverStartsHEAD`.
#[test]
fn a_cancelled_read_never_starts_the_head() {
    let (b, _, cancel) = budget();
    cancel.set();
    let engine = Engine::unreachable();
    let mut c = client(&b, &engine, "linux");
    assert_eq!(
        c.read_binary(TEST_ID, "/usr/bin/node").err(),
        Some(Failure::Halt(Halt::Cancelled))
    );
    assert_eq!(b.usage().container_requests, 0);
    assert_eq!(b.usage().container_bytes, 0);
}

/// 원본 `TestQualificationActualCumulativeWireBudgetStopsNextGET`(통합 시험) — 실제 HTTP 로 아카이브 둘을 흘리면
/// JSON 과 TAR 의 바이트가 쌓이고, 셋째 파일은 아카이브 부가 정보의 자리가 모자라 GET 을 시작하지 않는다.
///
/// 원본은 127 MiB 둘이다. 그만큼을 해시하는 시간(디버그 빌드에서 10초 남짓)을 줄이려고 둘의 118 MiB 씩은 같은
/// 예산에서 해시 없이 먼저 덜고 9 MiB 둘을 흘린다 — 셋째 앞에 남는 양은 원본과 같다(2 MiB 에서 3,093 바이트 모자람).
#[test]
fn the_actual_cumulative_wire_budget_stops_the_next_get() {
    const SIZE: u64 = 9 * MIB;
    const SPENT: u64 = 2 * (127 * MIB - SIZE);
    let (b, _, _) = budget();
    let mut ahead = b.wrap_reader(
        io::repeat(0).take(SPENT),
        crate::scan::budget::ReadKind::Container,
    );
    assert_eq!(io::copy(&mut ahead, &mut io::sink()).unwrap(), SPENT);
    let heads = Arc::new(Mutex::new(0u32));
    let gets = Arc::new(Mutex::new(0u32));
    let (h, g) = (heads.clone(), gets.clone());
    let wired = Wired::new(move |call: &Call<'_>| -> Box<dyn Read + Send> {
        if call.path.ends_with("/json") {
            let body = r#"{"Version":"fixture"}"#;
            let length = [("Content-Length", body.len().to_string())];
            return Box::new(io::Cursor::new(
                [head("200 OK", &length), body.as_bytes().to_vec()].concat(),
            ));
        }
        let name = if call.query.ends_with("third") {
            "third"
        } else {
            "node"
        };
        let size = if name == "third" { MIB } else { SIZE };
        let headers = [(
            "X-Docker-Container-Path-Stat",
            encoded_stat(name, size as i64, 0o755, ""),
        )];
        if call.method == Method::Head {
            *h.lock().unwrap() += 1;
            return Box::new(io::Cursor::new(head("200 OK", &headers)));
        }
        *g.lock().unwrap() += 1;
        Box::new(io::Cursor::new(head("200 OK", &headers)).chain(Streamed::new(name, size, b'x')))
    });
    let mut c = client(&b, &wired, "linux");
    c.json(&format!("/containers/{TEST_ID}/json")).unwrap();
    for name in ["/usr/bin/node", "/usr/local/bin/node"] {
        let file = c.read_binary(TEST_ID, name).unwrap();
        assert_eq!(file.size, SIZE);
        assert_eq!(file.prefix.len() as u64, BINARY_PREFIX);
    }
    let expected = SPENT + 2 * (SIZE + 1536) + r#"{"Version":"fixture"}"#.len() as u64;
    assert_eq!(b.usage().container_bytes, expected);
    let err = c.read_binary(TEST_ID, "/usr/bin/third").unwrap_err();
    assert!(err.is_limit(), "{err:?}");
    assert_eq!((*heads.lock().unwrap(), *gets.lock().unwrap()), (3, 2));
    assert_eq!(b.usage().container_requests, 6);
    assert_eq!(b.usage().container_bytes, expected);
    assert!(CONTAINER_LIMIT - expected < 2 * MIB);
}

/// 원본 `TestQualificationRealHTTPDeadlines`(통합 시험) — 실제 HTTP 에서 아카이브 GET 은 머리 앞에서도 뒤에서도
/// 아카이브 시한에, JSON · HEAD 는 요청 시한에 끝난다. 시한은 0.9초 · 0.3초로 바꿔 끼웠다(실제는 30초 · 10초).
#[test]
fn real_http_requests_end_at_their_deadlines() {
    let timeouts = Timeouts {
        request: Duration::from_millis(300),
        archive: Duration::from_millis(900),
    };
    let cases = [
        (
            "archive_before_headers",
            Method::Get,
            "/archive",
            false,
            timeouts.archive,
        ),
        (
            "archive_after_headers",
            Method::Get,
            "/archive",
            true,
            timeouts.archive,
        ),
        (
            "json_before_headers",
            Method::Get,
            "/json",
            false,
            timeouts.request,
        ),
        (
            "head_before_headers",
            Method::Head,
            "/archive",
            false,
            timeouts.request,
        ),
    ];
    for (name, stalled, route, flush, limit) in cases {
        let (b, _, _) = budget();
        let release = Arc::new(AtomicBool::new(false));
        let hold = release.clone();
        let stat = encoded_stat("node", 4096, 0o755, "");
        let wired = Wired::new(move |call: &Call<'_>| -> Box<dyn Read + Send> {
            let headers = [
                ("X-Docker-Container-Path-Stat", stat.clone()),
                ("Content-Length", "5632".to_string()),
            ];
            if call.method == Method::Head && stalled != Method::Head {
                return Box::new(io::Cursor::new(head("200 OK", &headers[..1])));
            }
            let first = if flush {
                head("200 OK", &headers)
            } else {
                Vec::new()
            };
            Box::new(io::Cursor::new(first).chain(Hold(hold.clone())))
        });
        let mut c = client(&b, &wired, "linux");
        c.timeouts = timeouts;
        let begun = Instant::now();
        let got = if route == "/json" {
            c.json(&format!("/containers/{TEST_ID}/json")).map(|_| ())
        } else {
            c.read_binary(TEST_ID, "/usr/bin/node").map(|_| ())
        };
        let elapsed = begun.elapsed();
        release.store(true, Ordering::SeqCst);
        assert_eq!(got, Err(Failure::Wire(Wire::Timeout)), "{name}");
        assert!(
            elapsed >= limit - Duration::from_millis(50),
            "{name}: {elapsed:?}"
        );
        assert!(
            elapsed <= limit + Duration::from_secs(3),
            "{name}: {elapsed:?}"
        );
        let expect_requests = if route == "/json" || stalled == Method::Head {
            1
        } else {
            2
        };
        assert_eq!(wired.methods().len(), expect_requests, "{name}");
    }
}

/// 압축 응답은 상태와 상관없이 본문을 읽기 전에 거절한다.
#[test]
fn a_compressed_json_response_is_refused() {
    let (b, _, _) = budget();
    let engine = Engine::new(|_| Ok(Answer::ok("{}").header("Content-Encoding", "gzip")));
    let mut c = client(&b, &engine, "linux");
    assert_eq!(c.json("/version"), Err(Failure::Policy(Policy::Compressed)));
    let engine = Engine::new(|_| Ok(Answer::ok("{}").header("content-encoding", "Identity")));
    let mut c = client(&b, &engine, "linux");
    assert!(c.json("/version").is_ok());
    let engine = Engine::new(|_| Ok(Answer::ok(vec![b'['; 9 << 20])));
    let mut c = client(&b, &engine, "linux");
    assert!(c.json("/version").unwrap_err().is_limit());
    let truncated = Engine::new(|s| {
        let stat = encoded_stat("status", 3, 0o644, "");
        // 내용 셋째 바이트 앞에서 끊겼다.
        let body = if s.method == Method::Get {
            make_archive(&[Entry::xs("status", 3)])[..514].to_vec()
        } else {
            Vec::new()
        };
        Ok(Answer::ok(body).stat(&stat))
    });
    let mut c = client(&b, &truncated, "linux");
    assert_eq!(
        c.read_file(TEST_ID, "/var/lib/dpkg/status"),
        Err(Failure::File(FileFailure::ArchiveFormat))
    );
}
