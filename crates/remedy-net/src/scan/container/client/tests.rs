//! 클라이언트의 시험 — 스캐너 `client_test.go` · `deadline_integration_test.go` 와 `windows_container_test.go` 의
//! 클라이언트 부분. 엔진은 지은 것이다([`crate::scan::container::tests::support`]).

use super::*;
use crate::scan::binary::fixtures::{container_pe, minimal_elf64};
use crate::scan::budget::{Halt, CONTAINER_LIMIT};
use crate::scan::container::failure::Wire;
use crate::scan::container::inspect::Mount;
use crate::scan::container::tests::support::*;
use std::sync::Mutex;

fn file_stat(name: &str, size: i64, mode: u32) -> String {
    encoded_stat(name, size, mode, "")
}

/// 원본 `TestAPIWhitelist`.
#[test]
fn api_allow_list() {
    let image = format!("/images/sha256:{TEST_ID}/json");
    let inspect = format!("/containers/{TEST_ID}/json");
    let archive = format!("/containers/{TEST_ID}/archive");
    let allowed: Vec<Api> = vec![
        ("GET", "/version".into(), vec![]),
        ("GET", "/containers/json".into(), vec![]),
        ("GET", inspect, vec![]),
        ("GET", image, vec![]),
        ("HEAD", archive.clone(), vec![("path", "/etc/os-release")]),
        ("GET", archive.clone(), vec![("path", "/usr/local/bin/php")]),
    ];
    for (method, route, query) in &allowed {
        assert!(
            allowed_api(method, route, query).is_some(),
            "거절했다: {method} {route}"
        );
    }
    let denied: Vec<Api> = vec![
        ("POST", format!("/containers/{TEST_ID}/exec"), vec![]),
        ("POST", format!("/containers/{TEST_ID}/start"), vec![]),
        ("GET", format!("/containers/{TEST_ID}/top"), vec![]),
        ("GET", format!("/containers/{TEST_ID}/export"), vec![]),
        ("DELETE", format!("/containers/{TEST_ID}"), vec![]),
        ("GET", format!("/images/sha256:{TEST_ID}/get"), vec![]),
        ("GET", "/containers/json".into(), vec![("all", "true")]),
        ("HEAD", "/version".into(), vec![]),
        ("GET", "/containers/name/json".into(), vec![]),
        ("GET", archive.clone(), vec![("path", "/")]),
        ("GET", archive.clone(), vec![("path", "/etc/../")]),
        ("GET", archive.clone(), vec![("path", "/etc/")]),
        ("GET", archive.clone(), vec![("path", "/a"), ("path", "/b")]),
        (
            "GET",
            archive.clone(),
            vec![("path", "/etc/os-release"), ("followLink", "1")],
        ),
    ];
    for (method, route, query) in &denied {
        assert!(
            allowed_api(method, route, query).is_none(),
            "받았다: {method} {route} {query:?}"
        );
    }
}

/// 원본 `TestFileStatRejectsDirectoriesSymlinksAndOversize`.
#[test]
fn file_stat_rejects_directories_symlinks_and_oversize() {
    for (name, size, mode, link) in [
        ("status", 1, MODE_DIR | 0o755, ""),
        ("status", 1, MODE_SYMLINK | 0o777, ""),
        ("status", 1, 0o644, "/secret"),
        ("different", 1, 0o644, ""),
        ("status", MAX_FILE as i64 + 1, 0o644, ""),
        ("status", -1, 0o644, ""),
    ] {
        let raw = encoded_stat(name, size, mode, link);
        assert!(
            decode_stat(&raw, "/var/lib/dpkg/status").is_err(),
            "{name} {size} {mode:o} {link}"
        );
    }
    for raw in ["", "e30=", "not base64"] {
        assert!(decode_stat(raw, "/var/lib/dpkg/status").is_err(), "{raw:?}");
    }
    let ok = decode_stat(&file_stat("status", 0, 0o644), "/var/lib/dpkg/status").unwrap();
    assert_eq!((ok.size, ok.mode), (0, 0o644));
    // URL 알파벳 · 대소문자만 다른 칸 · 형이 틀린 칸.
    let url_safe =
        base64(br#"{"name":"status","size":1,"mode":420,"linkTarget":""}"#).replace('+', "-");
    assert!(decode_stat(&url_safe, "/var/lib/dpkg/status").is_ok());
    for raw in [
        r#"{"name":"status","size":1,"mode":420,"LinkTarget":"/x"}"#,
        r#"{"name":"status","size":1.5,"mode":420}"#,
        r#"{"name":"status","size":1,"mode":-1}"#,
        r#"{"name":"status","Name":"other","size":1,"mode":420}"#,
        r#"{"size":1,"mode":420}"#,
    ] {
        assert!(
            decode_stat(&base64(raw.as_bytes()), "/var/lib/dpkg/status").is_err(),
            "{raw}"
        );
    }
    assert_eq!(
        decode_stat(&"A".repeat(16 << 10 | 4), "/var/lib/dpkg/status"),
        Err(Failure::File(FileFailure::StatTooLarge))
    );
    // Windows 링크 파일(원본 `TestWindowsArchivesRetainSingleRegularFileGate`).
    let link = encoded_stat("PHP.EXE", 3, MODE_SYMLINK | 0o777, "");
    assert!(decode_stat(&link, r"C:\php\php.exe").is_err());
    assert!(decode_stat(&file_stat("PHP.EXE", 3, 0o644), r"C:\php\php.exe").is_ok());
}

/// 원본 `TestDirectoryDoesNotTriggerGET`.
#[test]
fn a_directory_does_not_trigger_get() {
    let (b, _, _) = budget();
    let engine = Engine::new(|s| {
        assert_eq!(s.method, Method::Head, "디렉터리에 GET 을 보냈다");
        Ok(Answer::ok(Vec::new()).stat(&file_stat("status", 0, MODE_DIR | 0o755)))
    });
    let mut c = client(&b, &engine, "");
    assert!(c.read_file(TEST_ID, "/var/lib/dpkg/status").is_err());
    assert_eq!(engine.count(), 1);
}

/// 원본 `TestIndividualFileReadAndBudget`.
#[test]
fn an_individual_file_read_counts_two_requests_and_the_archive_bytes() {
    let (b, _, _) = budget();
    let archive = make_archive(&[Entry::xs("status", 3)]);
    let body = archive.clone();
    let engine = Engine::new(move |s| {
        assert_eq!(s.file, "/var/lib/dpkg/status");
        assert_eq!(s.raw_query, "path=%2Fvar%2Flib%2Fdpkg%2Fstatus");
        let data = if s.method == Method::Get {
            body.clone()
        } else {
            Vec::new()
        };
        Ok(Answer::ok(data).stat(&file_stat("status", 3, 0o644)))
    });
    let mut c = client(&b, &engine, "");
    assert_eq!(
        c.read_file(TEST_ID, "/var/lib/dpkg/status").unwrap(),
        b"xxx"
    );
    let methods: Vec<&str> = engine.calls().iter().map(|s| s.method.as_str()).collect();
    assert_eq!(methods, ["HEAD", "GET"]);
    let usage = b.usage();
    assert_eq!(usage.container_requests, 2);
    assert_eq!(usage.container_bytes, archive.len() as u64);
}

/// 원본 `TestEngineRequestBudgetAndDeniedRoutes`.
#[test]
fn engine_requests_stop_at_128_and_denied_routes_never_reach_the_engine() {
    let (b, _, _) = budget();
    let engine = Engine::new(|_| Ok(Answer::ok("{}")));
    let mut c = client(&b, &engine, "");
    let exec = format!("/containers/{TEST_ID}/exec");
    assert!(c.request("POST", &exec, &[]).is_err());
    assert_eq!(engine.count(), 0);
    for _ in 0..128 {
        drop(c.request("GET", "/version", &[]).unwrap());
    }
    let err = c.request("GET", "/version", &[]).err().unwrap();
    assert!(err.is_limit(), "{err:?}");
    assert_eq!(engine.count(), 128);
}

/// 원본 `TestAPIVersionIntersection`.
#[test]
fn api_version_intersection() {
    let engine = |max: &str, min: &str, os: &str| EngineVersion {
        version: "fixture".into(),
        api_version: max.into(),
        min_api_version: min.into(),
        os: os.into(),
    };
    use EngineKind::{Docker, Podman};
    for (kind, max, min, want) in [
        (Docker, "1.40", "1.12", "1.40"),
        (Docker, "1.44", "1.24", "1.44"),
        (Docker, "1.55", "1.44", "1.44"),
        (Podman, "1.41", "1.24", "1.40"),
        (Docker, "1.39", "1.24", ""),
        (Docker, "1.55", "1.45", ""),
        (Podman, "1.44", "1.41", ""),
        (Docker, "1.44", "", ""),
        (Docker, "1.44", "1.45", ""),
        (Docker, "2.0", "1.24", ""),
    ] {
        let got = select_api_version(&engine(max, min, "linux"), Some(kind));
        match want {
            "" => assert!(got.is_err(), "{kind:?} {max} {min}"),
            want => assert_eq!(got.as_deref(), Ok(want), "{kind:?} {max} {min}"),
        }
    }
    assert_eq!(
        select_api_version(&engine("1.44", "1.24", "windows"), Some(Docker)).as_deref(),
        Ok("1.44")
    );
    for os in ["", "darwin", "Windows"] {
        assert!(
            select_api_version(&engine("1.44", "1.24", os), Some(Docker)).is_err(),
            "{os:?}"
        );
    }
    assert!(select_api_version(&engine("1.44", "1.24", "windows"), Some(Podman)).is_err());
    assert_eq!(
        select_api_version(&engine("1.44", "1.24", "linux"), None),
        Err(Failure::Version(Version::Kind))
    );
    assert_eq!(
        select_api_version(&engine("1.044", "1.24", "linux"), Some(Docker)),
        Err(Failure::Version(Version::Range))
    );
}

/// 원본 `TestRequestsUseNegotiatedAPIVersion`.
#[test]
fn requests_use_the_negotiated_api_version() {
    let (b, _, _) = budget();
    let engine = Engine::new(|s| {
        let body = if s.path == "/version" {
            r#"{"Version":"29.0.0","ApiVersion":"1.52","MinAPIVersion":"1.44","Os":"linux"}"#
        } else {
            "[]"
        };
        Ok(Answer::ok(body))
    });
    let mut c = Client::new(&b, &engine, Lang::Ko);
    c.kind = Some(EngineKind::Docker);
    assert_eq!(
        c.request("GET", "/containers/json", &[]).err(),
        Some(Failure::Policy(Policy::NotNegotiated))
    );
    c.negotiate().unwrap();
    c.json("/containers/json").unwrap();
    let paths: Vec<String> = engine.calls().iter().map(|s| s.path.clone()).collect();
    assert_eq!(paths, ["/version", "/v1.44/containers/json"]);
}

/// 원본 `TestWindowsEngineNegotiationRetainsOS`.
#[test]
fn a_windows_engine_keeps_its_os_after_negotiation() {
    let (b, _, _) = budget();
    let engine = Engine::new(|s| {
        assert_eq!(s.path, "/version", "판을 맞추기 전의 요청");
        Ok(Answer::ok(
            r#"{"Version":"fixture","ApiVersion":"1.52","MinAPIVersion":"1.24","Os":"windows"}"#,
        ))
    });
    let mut c = Client::new(&b, &engine, Lang::Ko);
    c.kind = Some(EngineKind::Docker);
    c.negotiate().unwrap();
    assert_eq!(
        (c.engine_os.as_str(), c.api_version.as_str()),
        ("windows", "1.44")
    );
}

/// 원본 `TestChangedStatRejectsGETBodyBeforeRead`.
#[test]
fn a_changed_stat_rejects_the_get_body_before_reading_it() {
    let (b, _, _) = budget();
    let reads = Arc::new(Mutex::new(0u64));
    let counter = reads.clone();
    let engine = Engine::new(move |s| {
        let size = if s.method == Method::Get { 4 } else { 3 };
        let body = Counting {
            inner: io::Cursor::new(b"anything".to_vec()),
            n: counter.clone(),
        };
        Ok(Answer::reader(body).stat(&file_stat("status", size, 0o644)))
    });
    let mut c = client(&b, &engine, "");
    assert_eq!(
        c.read_file(TEST_ID, "/var/lib/dpkg/status"),
        Err(Failure::File(FileFailure::StatChanged))
    );
    assert_eq!(*reads.lock().unwrap(), 0);
}

/// 원본 `TestBinaryStreamFailureAfterTarEndDiscardsHash`.
#[test]
fn a_stream_failure_after_the_tar_end_discards_the_hash() {
    let (b, _, _) = budget();
    let archive = make_archive(&[Entry::xs("node", 3).mode(0o755)]);
    let engine = Engine::new(move |s| {
        let stat = file_stat("node", 3, 0o755);
        if s.method == Method::Get {
            return Ok(Answer::reader(io::Cursor::new(archive.clone()).chain(Failing)).stat(&stat));
        }
        Ok(Answer::ok(Vec::new()).stat(&stat))
    });
    let mut c = client(&b, &engine, "");
    assert!(c.read_binary(TEST_ID, "/usr/bin/node").is_err());
}

/// 원본 `TestLargeBinaryStreamRetainsOnlyPrefixAndFullHash` — 121 MiB 를 흘려 앞부분 8 MiB 와 전체 해시만 남긴다.
/// 시계를 바꿔 끼워 초당 10 MiB 맞춤은 기다리지 않는다. HEAD 의 시한은 10초, 아카이브 GET 은 30초다. 기대 해시는
/// `x` 121 MiB 의 SHA-256 이다(.NET 의 SHA256 으로 따로 잰 값과 같다).
#[test]
fn a_large_binary_keeps_only_its_prefix_and_the_full_hash() {
    const SIZE: u64 = 121 * MIB;
    const SHA256: &str = "191501c8e2009a3b14b4888f4b7533e77e20e649eeaacb1e01d9cd6033367708";
    let (b, clock, _) = budget();
    let now = clock.clone();
    let engine = Engine::new(move |s| {
        let left = s
            .deadline
            .saturating_duration_since(crate::scan::budget::Clock::now(&*now));
        let stat = file_stat("node", SIZE as i64, 0o755);
        if s.method == Method::Get {
            assert!(
                left >= Duration::from_secs(29),
                "아카이브 GET 의 시한이 30초가 아니다: {left:?}"
            );
            return Ok(Answer::reader(Streamed::new("node", SIZE, b'x')).stat(&stat));
        }
        assert!(
            left <= Duration::from_secs(10),
            "HEAD 의 시한이 10초를 넘는다: {left:?}"
        );
        Ok(Answer::ok(Vec::new()).stat(&stat))
    });
    let mut c = client(&b, &engine, "").with_clock(clock.clone());
    let data = c.read_binary(TEST_ID, "/usr/local/bin/node").unwrap();
    assert_eq!(data.size, SIZE);
    assert_eq!(data.prefix.len() as u64, BINARY_PREFIX);
    assert!(data.prefix.iter().all(|b| *b == b'x'));
    assert_eq!(data.sha256, SHA256);
    let usage = b.usage();
    assert_eq!(usage.container_requests, 2);
    assert_eq!(usage.container_bytes, SIZE + 1536);
}

/// 원본 `TestArchiveGETRequiresRemainingWireBudget`.
#[test]
fn an_archive_get_needs_room_for_its_overhead_in_the_wire_budget() {
    let (b, _, _) = budget();
    b.read(&b"json"[..], 4, ReadKind::Container).unwrap();
    let engine = Engine::new(|s| {
        assert_eq!(
            s.method,
            Method::Head,
            "부가 정보 자리 없이 GET 을 시작했다"
        );
        let size = (CONTAINER_LIMIT - MIB) as i64;
        Ok(Answer::ok(Vec::new()).stat(&file_stat("node", size, 0o755)))
    });
    let mut c = client(&b, &engine, "");
    let err = c.read_binary(TEST_ID, "/usr/local/bin/node").unwrap_err();
    assert!(err.is_limit(), "{err:?}");
    assert_eq!(engine.count(), 1);
    assert_eq!(b.usage().container_bytes, 4);
}

/// 원본 `TestArchiveThirtySecondDeadline`(통합 시험) — GET 이 시한까지 막히면 30초에 끝나고 해시는 남지 않는다.
/// 시계를 바꿔 끼워 기다림을 시각으로만 옮긴다.
#[test]
fn an_archive_get_ends_at_its_thirty_second_deadline() {
    let (b, clock, _) = budget();
    let now = clock.clone();
    let engine = Engine::new(move |s| {
        if s.method == Method::Get {
            // 응답 없이 시한까지 막힌 엔진.
            let wait = s
                .deadline
                .saturating_duration_since(crate::scan::budget::Clock::now(&*now));
            now.advance(wait);
            return Err(Failure::Wire(Wire::Timeout));
        }
        Ok(Answer::ok(Vec::new()).stat(&file_stat("node", 8, 0o755)))
    });
    let mut c = client(&b, &engine, "").with_clock(clock.clone());
    let started = clock.elapsed();
    let got = c.read_binary(TEST_ID, "/usr/bin/node");
    let elapsed = clock.elapsed() - started;
    assert_eq!(got, Err(Failure::Wire(Wire::Timeout)));
    assert!(
        elapsed >= Duration::from_secs(29) && elapsed <= Duration::from_secs(35),
        "{elapsed:?}"
    );
    assert_eq!(b.usage().container_requests, 2);
}

/// 원본 `TestContainerArchivePathsMatchNegotiatedOS`.
#[test]
fn archive_paths_must_match_the_negotiated_os() {
    for (os, name) in [
        ("linux", r"C:\php\php.exe"),
        ("windows", "/usr/local/bin/php"),
    ] {
        let (b, _, _) = budget();
        let engine = files_engine(Vec::new());
        let mut c = client(&b, &engine, os);
        let route = format!("/containers/{TEST_ID}/archive");
        assert!(
            c.request("HEAD", &route, &[("path", name)]).is_err(),
            "{os}"
        );
        assert_eq!(engine.count(), 0);
        assert_eq!(b.usage().container_requests, 0);
    }
}

/// 원본 `TestContainerMountBoundariesBlockFileRequests`.
#[test]
fn mount_boundaries_block_file_requests() {
    for (os, mount, blocked, allowed) in [
        (
            "linux",
            "/usr/local",
            "/usr/local/bin/php",
            "/usr/local-other/php",
        ),
        ("linux", "/", "/usr/bin/php", ""),
        (
            "windows",
            r"C:\PHP",
            "c:/php/php.exe",
            r"C:\PHP-other\php.exe",
        ),
        ("windows", r"C:\", "c:/php/php.exe", r"D:\php\php.exe"),
    ] {
        let (b, _, _) = budget();
        let engine = files_engine(Vec::new());
        let mut c = client(&b, &engine, os);
        let bind = Mount {
            kind: "bind".into(),
            destination: mount.into(),
        };
        c.mounts.insert(TEST_ID.to_string(), vec![bind]);
        assert!(c.read_file(TEST_ID, blocked).is_err(), "{blocked}");
        assert_eq!(engine.count(), 0);
        assert_eq!(b.usage().container_requests, 0);
        if !allowed.is_empty() {
            assert!(!c.mounted_path(TEST_ID, allowed), "{allowed}");
        }
    }
    // 알아보지 못한 경계는 넘지 않고, 이름 있는 파이프 마운트는 경계가 아니다.
    let (b, _, _) = budget();
    let engine = files_engine(Vec::new());
    let mut c = client(&b, &engine, "linux");
    let odd = Mount {
        kind: "bind".into(),
        destination: "relative/dir".into(),
    };
    let pipe = Mount {
        kind: "npipe".into(),
        destination: "/usr".into(),
    };
    c.mounts.insert(TEST_ID.to_string(), vec![pipe]);
    assert!(!c.mounted_path(TEST_ID, "/usr/bin/php"));
    c.mounts.insert(TEST_ID.to_string(), vec![odd]);
    assert!(c.mounted_path(TEST_ID, "/usr/bin/php"));
}

/// 원본 `TestWindowsBinaryRequiresValidatedPEAndFullHash`.
#[test]
fn a_windows_binary_needs_a_validated_pe_and_its_full_hash() {
    let good = container_pe("\0PHP/8.3.36\0");
    for content in [
        good.clone(),
        b"MZ fake PHP/8.3.36".to_vec(),
        minimal_elf64(),
        b"#!/bin/sh\nphp app.php".to_vec(),
    ] {
        let (b, _, _) = budget();
        let engine = files_engine(vec![("c:/php/php.exe", content.clone())]);
        let mut c = client(&b, &engine, "windows");
        let got = c.read_binary(TEST_ID, r"C:\php\php.exe");
        if content == good {
            assert_eq!(got.unwrap().sha256, sha256_hex(&good));
        } else {
            assert_eq!(got, Err(Failure::File(FileFailure::NotPe)));
        }
    }
}

#[test]
fn a_windows_5xx_on_file_reads_stops_further_reads_of_that_container() {
    let (b, _, _) = budget();
    let engine = Engine::new(|_| Ok(Answer::status(500)));
    let mut c = client(&b, &engine, "windows");
    assert_eq!(
        c.read_file(TEST_ID, r"C:\php\php.exe"),
        Err(Failure::Policy(Policy::WindowsArchive(500)))
    );
    assert_eq!(
        c.read_file(TEST_ID, r"C:\php\php.ini"),
        Err(Failure::Policy(Policy::WindowsArchive(500)))
    );
    assert_eq!(engine.count(), 1);
    assert_eq!(c.archive_failure(TEST_ID), Some(500));
    // 리눅스 엔진의 5xx 는 그 요청의 상태일 뿐이다.
    let (b, _, _) = budget();
    let engine = Engine::new(|_| Ok(Answer::status(503)));
    let mut c = client(&b, &engine, "linux");
    let err = c.read_file(TEST_ID, "/etc/os-release").unwrap_err();
    assert!(
        matches!(err, Failure::Policy(Policy::Status { status: 503, .. })),
        "{err:?}"
    );
    assert!(c.read_file(TEST_ID, "/etc/os-release").is_err());
    assert_eq!(engine.count(), 2);
}

#[test]
fn a_cancelled_budget_stops_before_the_request() {
    let (b, _, cancel) = budget();
    cancel.set();
    let engine = Engine::unreachable();
    let mut c = client(&b, &engine, "");
    assert_eq!(c.json("/version"), Err(Failure::Halt(Halt::Cancelled)));
    assert_eq!(b.usage().container_requests, 0);
}
