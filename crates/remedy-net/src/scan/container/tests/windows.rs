//! Windows 엔진 — 스캐너 `windows_container_test.go` · `php_windows_legacy_test.go`.

use super::support::*;
use crate::scan::binary::fixtures::container_pe;
use crate::scan::container::files::{scan_container_files, Subject};
use crate::scan::container::inspect::Inspect;
use crate::scan::container::paths::{self, search_path, valid_file_path, valid_windows_file_path};
use crate::scan::container::php::{scan_php_container, scan_windows_php_core};
use crate::scan::container::phpconf::php_config_paths;
use crate::scan::container::record::finalize_container_target;
use crate::scan::model::{Product, Status, Target, TargetKind};
use crate::scan::phpconfig;
use crate::scan::rules::{Component, RuleSet};
use remedy_sdk::i18n::Lang;
use std::collections::BTreeMap;

fn target(products: &[Product]) -> Target {
    Target::new(
        format!("container:{TEST_ID}"),
        TargetKind::Container,
        TEST_ID,
        products,
    )
}

fn inspect(path: &str, cmd: &[&str], env: &[&str]) -> Inspect {
    Inspect {
        path: path.to_string(),
        cmd: cmd.iter().map(|s| s.to_string()).collect(),
        env: env.iter().map(|s| s.to_string()).collect(),
        ..Inspect::default()
    }
}

/// 원본 `TestWindowsHyperVIsolationStaysReviewWithoutArchiveRequests`.
#[test]
fn hyperv_isolation_stays_review_without_archive_requests() {
    let (b, _, _) = budget();
    let engine = files_engine(Vec::new());
    let mut c = client(&b, &engine, "windows");
    let inspected = Inspect {
        path: r"C:\php\php.exe".into(),
        isolation: "hyperv".into(),
        ..Inspect::default()
    };
    let mut t = target(&[]);
    scan_container_files(
        &mut c,
        &mut t,
        TEST_ID,
        &inspected,
        &blank_rules(),
        &[Product::Php, Product::Node],
    );
    finalize_container_target(&mut t, Lang::Ko);
    assert_eq!(t.status, Status::ReviewRequired);
    assert_eq!(engine.count(), 0);
    assert_eq!(b.usage().container_requests, 0);
    assert_eq!(t.products[&Product::Php].gaps.len(), 1);
    assert_eq!(t.products[&Product::Node].gaps.len(), 1);
    assert_eq!(t.metadata["container_isolation"], "hyperv");
}

/// 원본 `TestWindowsArchiveServerErrorStopsFurtherFileRequests`.
#[test]
fn a_windows_archive_server_error_stops_further_file_requests() {
    let (b, _, _) = budget();
    let engine = Engine::new(|_| Ok(Answer::status(500)));
    let mut c = client(&b, &engine, "windows");
    let inspected = inspect(
        "php.exe",
        &[],
        &[r"Path=C:\php;C:\Windows", "PHP_VERSION=8.3.36"],
    );
    let mut t = target(&[]);
    scan_container_files(
        &mut c,
        &mut t,
        TEST_ID,
        &inspected,
        &blank_rules(),
        &[Product::Php, Product::Node],
    );
    finalize_container_target(&mut t, Lang::Ko);
    let json = serde_json::to_string(&t).unwrap();
    assert_eq!(engine.count(), 1, "{:?}", engine.lines());
    assert_eq!(b.usage().container_requests, 1);
    assert_eq!(t.status, Status::ReviewRequired);
    assert!(json.contains("HTTP 500"), "{json}");
}

/// 원본 `TestWindowsFilePathsRejectDevicesTraversalAndAlternateStreams`.
#[test]
fn windows_file_paths_reject_devices_traversal_and_alternate_streams() {
    for name in [
        r"C:\php\php.exe",
        "c:/Program Files/nodejs/node.exe",
        r"D:\PHP\php.ini",
        r"C:\한글\php.exe",
    ] {
        assert!(
            valid_file_path(name) && valid_windows_file_path(name),
            "{name}"
        );
    }
    for name in [
        r"C:\",
        "C:/",
        "C:php.exe",
        r"\php\php.exe",
        r"\\server\share\php.exe",
        r"\\?\C:\php\php.exe",
        r"\\.\pipe\php",
        r"C:\php\..\php.exe",
        r"C:\php\.\php.exe",
        r"C:\php\\php.exe",
        r"C:\php\php.exe:stream",
        r"C:\php\*.exe",
        r"C:\php\php.exe.",
        r"C:\php\php.exe ",
        r"C:\php\NUL",
        r"C:\php\CON.txt",
        r"C:\php\COM¹.exe",
        r"C:\php\LPT9",
        r"C:\php\CONIN$",
        "C:\\php\\php.exe\0",
    ] {
        assert!(
            !valid_file_path(name) && !valid_windows_file_path(name),
            "{name:?}"
        );
    }
    let env = vec![r"Path=C:\php;C:\Program Files\nodejs;relative;C:\php;C:\".to_string()];
    assert_eq!(
        search_path(&env, true),
        [r"C:\php", r"C:\Program Files\nodejs", r"C:\"]
    );
}

/// 원본 `TestWindowsPHPCoreAndConfigurationAreCollectedWithoutLinuxReads` — 수정된 실행 파일 옆의 미수정 코어 DLL 은
/// 취약이고, 설정은 Windows 자리에서만 읽는다(원문은 남기지 않는다).
#[test]
fn windows_php_core_and_configuration_are_collected_without_linux_reads() {
    let php = container_pe("\0PHP/8.3.36\0");
    let core = container_pe("\0PHP/8.3.35\0core");
    let rules = hash_rules(
        vec![
            hash_row(&php, "8.3.36", false),
            hash_row(&core, "8.3.35", false),
        ],
        Vec::new(),
    );
    let (b, _, _) = budget();
    let engine = files_engine(vec![
        ("c:/php/php.exe", php),
        ("c:/php/php8.dll", core),
        (
            "c:/php/php.ini",
            b"session.upload_progress.enabled=Off\nsession.serialize_handler=php_serialize\npassword=PRIVATE_WINDOWS_CONFIG".to_vec(),
        ),
    ]);
    let mut c = client(&b, &engine, "windows");
    let inspected = inspect(
        "php.exe",
        &["php.exe"],
        &[r"Path=C:\php;C:\Windows\System32", r"PHPRC=C:\php\php.ini"],
    );
    let mut t = target(&[]);
    scan_container_files(&mut c, &mut t, TEST_ID, &inspected, &rules, &[Product::Php]);
    finalize_container_target(&mut t, Lang::Ko);
    assert_eq!(t.status, Status::Vulnerable);
    assert_eq!(t.metadata["distribution"], "windows");
    let core_vulnerable = t
        .findings
        .iter()
        .any(|f| f.path.as_deref() == Some(r"C:\php\php8.dll") && f.status == Status::Vulnerable);
    let config = t.findings.iter().any(|f| {
        f.id.ends_with(&format!(":{}", phpconfig::CVE)) && f.status == Status::ReviewRequired
    });
    let json = serde_json::to_string(&t).unwrap();
    assert!(core_vulnerable && config, "{json}");
    assert!(
        json.contains("session.upload_progress.enabled=Off"),
        "{json}"
    );
    assert!(!json.contains("PRIVATE_WINDOWS_CONFIG"));
    for call in engine.calls() {
        assert!(
            !call.file.starts_with('/'),
            "Windows 엔진에서 리눅스 경로를 읽었다: {}",
            call.line()
        );
    }
}

/// 원본 `TestWindowsPHPVersionAloneAndMissingCoreRemainReview` — 직접 지은 빌드의 버전 글자도, 코어 DLL 을 확인하지
/// 못한 공식 실행 파일도 확정하지 않는다.
#[test]
fn a_windows_version_string_alone_or_a_missing_core_stays_review() {
    let php = container_pe("\0PHP/8.3.1\0");
    for known in [false, true] {
        let hashes = if known {
            vec![hash_row(&php, "8.3.36", false)]
        } else {
            Vec::new()
        };
        let rules = hash_rules(hashes, Vec::new());
        let (b, _, _) = budget();
        let engine = files_engine(vec![("c:/custom/php.exe", php.clone())]);
        let mut c = client(&b, &engine, "windows");
        let inspected = inspect(r"C:\custom\php.exe", &[], &[]);
        let mut t = target(&[Product::Php]);
        let s = Subject {
            id: TEST_ID,
            inspected: &inspected,
            rules: &rules,
            packages: &[],
            package_data: &[],
            distro: "windows",
            rpm: None,
        };
        scan_php_container(&mut c, &mut t, &s);
        finalize_container_target(&mut t, Lang::Ko);
        assert_eq!(t.status, Status::ReviewRequired, "known={known}");
        for f in &t.findings {
            assert_eq!(f.status, Status::ReviewRequired, "known={known}: {f:?}");
        }
    }
}

/// 원본 `TestWindowsNodeResolvesPATHAndUsesHashWithoutRuntimeAssumption`.
#[test]
fn windows_node_resolves_path_and_uses_the_hash() {
    let node = container_pe("\0node.js/v22.22.0\0");
    for known in [false, true] {
        let hashes = if known {
            vec![hash_row(&node, "22.22.0", true)]
        } else {
            Vec::new()
        };
        let rules = hash_rules(Vec::new(), hashes);
        let (b, _, _) = budget();
        let engine = files_engine(vec![("c:/program files/nodejs/node.exe", node.clone())]);
        let mut c = client(&b, &engine, "windows");
        let inspected = inspect(
            "node",
            &[],
            &[
                r"Path=C:\Program Files\nodejs;C:\Windows\System32",
                "NODE_VERSION=22.22.0",
            ],
        );
        let mut t = target(&[]);
        scan_container_files(
            &mut c,
            &mut t,
            TEST_ID,
            &inspected,
            &rules,
            &[Product::Node],
        );
        finalize_container_target(&mut t, Lang::Ko);
        let found = runtime_findings(&t);
        let want = if known {
            Status::Vulnerable
        } else {
            Status::ReviewRequired
        };
        assert_eq!(found.len(), 1, "known={known}");
        assert_eq!(
            found[0].path.as_deref(),
            Some(r"C:\Program Files\nodejs\node.exe")
        );
        assert_eq!(found[0].status, want, "known={known}");
        assert!(!t.products[&Product::Node].complete);
        assert_eq!(engine.count(), 2, "{:?}", engine.lines());
        if known {
            let gaps = &t.products[&Product::Node].gaps;
            assert!(
                gaps.iter().all(|g| !g.contains("Brotli 의 연결 관계")),
                "{gaps:?}"
            );
        }
    }
}

/// 원본 `TestWindowsPHPConfigPathsRejectUnsafeAndUseObservedExecutable`.
#[test]
fn windows_php_config_paths_reject_unsafe_values_and_use_the_observed_executable() {
    let inspected = inspect(
        r"D:\runtime\php.exe",
        &[],
        &[r"PHPRC=C:\config", r"PHP_INI_DIR=..\private"],
    );
    let (found, omitted) = php_config_paths(&inspected, &[], "windows", &[]);
    assert!(omitted);
    assert_eq!(
        found,
        [
            r"C:\config\php.ini",
            r"D:\runtime\php.ini",
            r"C:\php\php.ini"
        ]
    );
    for name in &found {
        assert!(
            valid_windows_file_path(name) && !name.contains("private"),
            "{name}"
        );
    }
}

/// 원본 `TestWindowsPHPLegacyCoreFilesReachSignedHashRules` — 버전 글자가 없는 코어 DLL 도 해시로 기준과 이어지고,
/// 실행 파일과 같은 폴더의 정해진 이름만 묻는다.
#[test]
fn windows_php_legacy_core_files_reach_the_hash_rules() {
    for (filename, version) in [
        ("php5.dll", "5.6.40"),
        ("php5ts.dll", "5.6.40"),
        ("php7.dll", "7.4.33"),
        ("php7ts.dll", "7.4.33"),
        ("php8.dll", "8.3.35"),
        ("php8ts.dll", "8.3.35"),
    ] {
        let core = container_pe(&format!("static core fixture {filename}"));
        let hash = hash_row(&core, version, false);
        let rules = hash_rules(vec![hash], Vec::new());
        let (b, _, _) = budget();
        let path = format!(r"C:\php\{filename}");
        let engine = files_engine(vec![(path.as_str(), core.clone())]);
        let mut c = client(&b, &engine, "windows");
        let mut t = target(&[Product::Php]);
        let mut seed = Component::new(Product::Php);
        seed.path = r"C:\php\php.exe".into();
        t.findings
            .push(RuleSet::builtin().evaluate(&seed, Lang::Ko));
        let executables: BTreeMap<String, Vec<usize>> =
            [(r"C:\php".to_string(), vec![0])].into_iter().collect();
        scan_windows_php_core(&mut c, &mut t, TEST_ID, &rules, &executables);
        assert_eq!(t.findings.len(), 2, "{filename}");
        let f = &t.findings[1];
        let mut probe = Component::new(Product::Php);
        probe.sha256 = sha256_hex(&core);
        let want = rules.evaluate(&probe, Lang::Ko);
        assert_eq!(f.path.as_deref(), Some(path.as_str()));
        assert_eq!(f.version.as_deref(), Some(version), "{filename}");
        assert_eq!(f.status, want.status, "{filename}");
        assert_eq!(engine.count(), 7, "{filename}: {:?}", engine.lines());
        assert_eq!(b.usage().container_requests, 7);
        for call in engine.calls() {
            assert_eq!(paths::dir(&call.file), r"C:\php", "{}", call.line());
        }
    }
}
