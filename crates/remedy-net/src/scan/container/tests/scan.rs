//! 컨테이너 하나의 차례와 점검 전체 — 스캐너 `scan_test.go` · `linux_legacy_test.go` · `node_test.go` ·
//! `phpconfig_test.go` 의 시험과, 엔진 확인 · 판 맞추기에서 멈춘 대상.

use super::support::*;
use crate::scan::binary::fixtures::{minimal_elf32, minimal_elf64};
use crate::scan::budget::Halt;
use crate::scan::container::client::Client;
use crate::scan::container::endpoint::EngineKind;
use crate::scan::container::failure::Failure;
use crate::scan::container::files::{scan_container_files, Subject};
use crate::scan::container::inspect::Inspect;
use crate::scan::container::node::node_file_owners;
use crate::scan::container::packages::parse_dpkg;
use crate::scan::container::phpconf::{php_config_paths, scan_php_configuration};
use crate::scan::container::record::finalize_container_target;
use crate::scan::container::rpm::read_rpm_packages;
use crate::scan::container::wire::Method;
use crate::scan::container::{paths, scan, scan_with, Request};
use crate::scan::model::{Finding, Product, Status, Target, TargetKind};
use crate::scan::phpconfig;
use crate::scan::rules::{Component, RuleSet};
use remedy_sdk::i18n::Lang;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const UBUNTU_PHP: &str = "Package: php8.1-cli\nStatus: install ok installed\nVersion: 8.1.2-1ubuntu2.27\nMaintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n";

fn target(products: &[Product]) -> Target {
    Target::new(
        format!("container:{TEST_ID}"),
        TargetKind::Container,
        TEST_ID,
        products,
    )
}

fn inspect_path(path: &str) -> Inspect {
    Inspect {
        path: path.to_string(),
        ..Inspect::default()
    }
}

/// 원본 `TestConfirmedPackageIsRecordedBeforeNextFileRead` — 다음 파일을 읽기 전에 확인된 취약 패키지가 남아 있다.
#[test]
fn a_confirmed_package_is_recorded_before_the_next_file_read() {
    let (b, _, cancel) = budget();
    let b = Arc::new(b);
    let watched = b.clone();
    let checked = Arc::new(Mutex::new(false));
    let seen = checked.clone();
    let files: HashMap<&str, &str> = [
        ("/etc/os-release", "ID=ubuntu\nVERSION_ID=22.04\n"),
        ("/var/lib/dpkg/status", UBUNTU_PHP),
    ]
    .into_iter()
    .collect();
    let files: HashMap<String, Vec<u8>> = files
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
        .collect();
    let engine = Engine::new(move |s| {
        if s.file == "/usr/local/bin/php" {
            *seen.lock().unwrap() = true;
            let partial = watched.partial_targets("fixture timeout");
            assert_eq!(partial.len(), 1);
            assert_eq!(partial[0].status, Status::Vulnerable);
            assert_eq!(runtime_findings(&partial[0]).len(), 1);
            assert!(!partial[0].complete);
            cancel.set();
            return Err(Failure::Halt(Halt::Cancelled));
        }
        let content = files
            .get(&s.file)
            .unwrap_or_else(|| panic!("모르는 요청: {}", s.file));
        Ok(file_answer(s, &paths::base(&s.file), content, 0o644))
    });
    let mut c = client(&b, &engine, "linux");
    let mut t = target(&[Product::Php]);
    // PID 0 — 시험 기계의 프로세스 정보를 읽지 않는다.
    scan_container_files(
        &mut c,
        &mut t,
        TEST_ID,
        &inspect_path("/usr/local/bin/php"),
        RuleSet::fixture(),
        &[],
    );
    assert!(*checked.lock().unwrap(), "다음 파일 요청에 닿지 않았다");
    let partial = b.partial_targets("fixture timeout");
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].status, Status::Vulnerable);
    assert_eq!(
        partial[0].findings[0].package.as_deref(),
        Some("php8.1-cli")
    );
    assert!(
        t.reason.is_empty() && t.action.is_empty(),
        "남긴 사본이 쓰던 대상의 요약을 바꿨다"
    );
}

/// 원본 `TestContainerUsesKnownLegacyReleaseFallback`.
#[test]
fn a_known_legacy_release_record_is_the_fallback() {
    let (b, _, _) = budget();
    let engine = files_engine(vec![
        (
            "/etc/lsb-release",
            b"DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=12.04\n".to_vec(),
        ),
        ("/var/lib/dpkg/status", Vec::new()),
        ("/usr/bin/node", minimal_elf32()),
    ]);
    let mut c = client(&b, &engine, "linux");
    let mut t = target(&[]);
    scan_container_files(
        &mut c,
        &mut t,
        TEST_ID,
        &inspect_path("/usr/bin/node"),
        &blank_rules(),
        &[Product::Node],
    );
    assert_eq!(t.metadata["distribution"], "ubuntu");
    assert_eq!(t.metadata["distribution_version"], "12.04");
    assert!(engine
        .calls()
        .iter()
        .all(|s| matches!(s.method, Method::Head | Method::Get)));
}

/// 원본 `TestContainerReleaseSizeLimitStopsBeforeGET`.
#[test]
fn an_oversized_release_record_stops_before_get() {
    let (b, _, _) = budget();
    let engine = files_engine(vec![("/etc/os-release", vec![b'#'; (64 << 10) + 1])]);
    let mut c = client(&b, &engine, "linux");
    assert!(c
        .read_metadata(TEST_ID, "/etc/os-release", 64 << 10)
        .is_err());
    assert_eq!(engine.lines(), ["HEAD /etc/os-release"]);
}

/// 원본 `TestContainerDPKGMultiArchOwnershipRemainsSeparate`.
#[test]
fn dpkg_multiarch_ownership_stays_separate() {
    let status = "Package: libbrotli1\nStatus: install ok installed\nVersion: 1.2.0-1\nArchitecture: i386\n\nPackage: libbrotli1\nStatus: install ok installed\nVersion: 1.1.0-1\nArchitecture: amd64\n";
    let packages = parse_dpkg(
        status.as_bytes(),
        "debian",
        "7",
        "fixture",
        &[Product::Node],
        Lang::Ko,
    );
    assert_eq!(packages.len(), 2);
    assert_ne!(packages[0].id, packages[1].id);
    let (b, _, _) = budget();
    let engine = files_engine(vec![
        (
            "/var/lib/dpkg/info/libbrotli1:i386.list",
            b"/usr/lib/i386-linux-gnu/libbrotlidec.so.1\n".to_vec(),
        ),
        (
            "/var/lib/dpkg/info/libbrotli1:amd64.list",
            b"/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1\n".to_vec(),
        ),
        (
            "/var/lib/dpkg/info/libbrotli1.list",
            b"/usr/lib/wrong/libbrotlidec.so.1\n".to_vec(),
        ),
    ]);
    let mut c = client(&b, &engine, "linux");
    let mut t = target(&[]);
    let owners = node_file_owners(
        &mut c,
        &mut t,
        TEST_ID,
        &packages,
        status.as_bytes(),
        "debian",
    );
    assert_eq!(owners.len(), 2);
    assert_eq!(
        owners["/usr/lib/i386-linux-gnu/libbrotlidec.so.1"].architecture,
        "i386"
    );
    assert_eq!(
        owners["/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1"].architecture,
        "amd64"
    );
    assert!(
        engine
            .lines()
            .iter()
            .all(|l| !l.ends_with("/libbrotli1.list")),
        "아키텍처 목록 대신 공용 목록을 읽었다"
    );
}

/// 원본 `TestContainerRPMReadFailureDoesNotSelectStaleFallback`.
#[test]
fn an_rpm_read_failure_does_not_fall_back_to_an_older_database() {
    let (b, _, _) = budget();
    let engine = Engine::new(|_| Ok(Answer::status(403)));
    let mut c = client(&b, &engine, "linux");
    let mut t = target(&[]);
    let (packages, _) =
        read_rpm_packages(&mut c, &mut t, TEST_ID, "centos", "6.10", &[Product::Php]);
    assert!(packages.is_empty());
    assert_eq!(t.gaps.len(), 1);
    let files: Vec<String> = engine.calls().iter().map(|s| s.file.clone()).collect();
    assert_eq!(files, ["/usr/lib/sysimage/rpm/rpmdb.sqlite"]);
}

/// 원본 `TestCombinedContainerProductsReadCommonMetadataOnce` — 두 제품이 함께 쓰는 기록과 실행 파일은 한 번씩만
/// 읽고, PHP 설정 조회는 Node.js 를 다 읽은 뒤에 한다.
#[test]
fn combined_products_read_common_metadata_once() {
    let (b, _, _) = budget();
    let status = format!("{UBUNTU_PHP}\nPackage: nodejs\nStatus: install ok installed\nVersion: 22.22.0-1\nMaintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n");
    let files: HashMap<String, Vec<u8>> = [
        ("/etc/os-release", b"ID=ubuntu\nVERSION_ID=22.04\n".to_vec()),
        ("/var/lib/dpkg/status", status.into_bytes()),
        (
            "/var/lib/dpkg/info/nodejs.list",
            b"/usr/bin/node\n".to_vec(),
        ),
        ("/usr/bin/node", minimal_elf64()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let gets: Arc<Mutex<HashMap<String, u32>>> = Arc::default();
    let counted = gets.clone();
    let engine = Engine::new(move |s| {
        let Some(content) = files.get(&s.file) else {
            let config = s.file.ends_with(".ini") || s.file.ends_with(".conf");
            let node_read = counted.lock().unwrap().get("/usr/bin/node").copied() == Some(1);
            assert!(
                !config || node_read,
                "Node.js 실행 파일을 읽기 전에 PHP 설정 조회를 시작했다"
            );
            return Ok(Answer::status(404));
        };
        if s.method == Method::Get {
            *counted.lock().unwrap().entry(s.file.clone()).or_default() += 1;
        }
        Ok(file_answer(s, &paths::base(&s.file), content, 0o644))
    });
    let mut c = client(&b, &engine, "linux");
    let mut t = target(&[]);
    scan_container_files(
        &mut c,
        &mut t,
        TEST_ID,
        &inspect_path("/usr/bin/node"),
        RuleSet::fixture(),
        &[Product::Php, Product::Node],
    );
    t.finalize(Lang::Ko);
    let gets = gets.lock().unwrap();
    for name in ["/etc/os-release", "/var/lib/dpkg/status", "/usr/bin/node"] {
        assert_eq!(gets.get(name), Some(&1), "{name}: {gets:?}");
    }
    assert_eq!(t.products[&Product::Php].status, Status::Vulnerable);
    assert_eq!(t.products[&Product::Node].status, Status::ReviewRequired);
    let runtime = runtime_findings(&t);
    let node: Vec<&&Finding> = runtime
        .iter()
        .filter(|f| f.product == Product::Node)
        .collect();
    assert_eq!(node.len(), 1);
    assert_eq!(node[0].id, "node-container-file:/usr/bin/node");
    assert_eq!(node[0].package.as_deref(), Some("nodejs"));
    for f in runtime.iter().filter(|f| f.product == Product::Php) {
        assert_eq!(f.id, "container-package:php8.1-cli");
    }
}

/// 원본 `TestPHPConfigurationUsesBoundedIndividualFilesAndStaysReview`.
#[test]
fn php_configuration_uses_bounded_individual_files_and_stays_review() {
    struct Case {
        name: &'static str,
        content: &'static str,
        want: &'static str,
        status: u16,
        size: i64,
    }
    let cases = [
        Case { name: "off", content: "session.upload_progress.enabled=Off\nsession.serialize_handler=php_serialize\npassword=PRIVATE_CONFIG_SENTINEL", want: "session.upload_progress.enabled=Off", status: 0, size: 0 },
        Case { name: "on", content: "session.upload_progress.enabled=On\nsession.serialize_handler=php", want: "session.upload_progress.enabled=On", status: 0, size: 0 },
        Case { name: "missing", content: "", want: "설정 미확인", status: 404, size: 0 },
        Case { name: "permission", content: "", want: "HTTP 403", status: 403, size: 0 },
        Case { name: "oversized", content: "", want: "크기 제한", status: 0, size: (4 << 20) + 1 },
    ];
    for tc in cases {
        let (b, _, _) = budget();
        let heads: Arc<Mutex<HashMap<String, u32>>> = Arc::default();
        let gets: Arc<Mutex<HashMap<String, u32>>> = Arc::default();
        let (h, g) = (heads.clone(), gets.clone());
        let route = format!("/v1.44/containers/{TEST_ID}/archive");
        let engine = Engine::new(move |s| {
            assert!(
                s.path == route && paths::valid_file_path(&s.file),
                "범위 밖의 설정 조회: {}",
                s.path
            );
            let counter = if s.method == Method::Head { &h } else { &g };
            *counter.lock().unwrap().entry(s.file.clone()).or_default() += 1;
            if s.file != "/custom/php.ini" || tc.status != 0 {
                return Ok(Answer::status(if s.file == "/custom/php.ini" {
                    tc.status
                } else {
                    404
                }));
            }
            let size = if tc.size != 0 {
                tc.size
            } else {
                tc.content.len() as i64
            };
            let stat = encoded_stat("php.ini", size, 0o644, "");
            let body = if s.method == Method::Get {
                make_archive(&[Entry::file("php.ini", tc.content.as_bytes().to_vec())])
            } else {
                Vec::new()
            };
            Ok(Answer::ok(body).stat(&stat))
        });
        let mut c = client(&b, &engine, "linux");
        let inspected = Inspect {
            env: vec!["PHPRC=/custom/php.ini".into(), "PHP_VERSION=8.3.36".into()],
            ..Inspect::default()
        };
        let mut t = target(&[Product::Php]);
        let mut seed = Component::new(Product::Php);
        seed.id = "php-runtime".into();
        let mut first = RuleSet::fixture().evaluate(&seed, Lang::Ko);
        first.status = Status::Clear;
        t.findings.push(first);
        let s = Subject {
            id: TEST_ID,
            inspected: &inspected,
            rules: RuleSet::fixture(),
            packages: &[],
            package_data: &[],
            distro: "ubuntu",
            rpm: None,
        };
        scan_php_configuration(&mut c, &mut t, &s);
        t.finalize(Lang::Ko);
        assert_eq!(t.findings.len(), 2, "{}", tc.name);
        assert_eq!(t.findings[1].id, format!("{}:{}", t.id, phpconfig::CVE));
        assert_eq!(t.findings[1].status, Status::ReviewRequired);
        assert_eq!(t.status, Status::ReviewRequired);
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains(tc.want), "{}: {json}", tc.name);
        assert!(!json.contains("PRIVATE_CONFIG_SENTINEL"));
        if tc.name == "on" || tc.name == "off" {
            let from_file: String = t.findings[1]
                .evidence
                .iter()
                .filter(|e| e.source == "/custom/php.ini")
                .map(|e| e.detail.clone())
                .collect();
            assert!(from_file.contains(tc.want), "{from_file}");
        }
        assert!(heads.lock().unwrap().len() <= 8);
        assert!(b.usage().container_requests <= 16);
        let custom_gets = gets
            .lock()
            .unwrap()
            .get("/custom/php.ini")
            .copied()
            .unwrap_or(0);
        let expected = if tc.status != 0 || tc.size != 0 { 0 } else { 1 };
        assert_eq!(custom_gets, expected, "{}", tc.name);
    }
}

/// 원본 `TestPHPConfigurationPathsRejectRelativeAndDirectoryRequests`.
#[test]
fn php_configuration_paths_reject_relative_and_directory_requests() {
    let inspected = Inspect {
        env: vec![
            "PHPRC=/config".into(),
            "PHP_INI_DIR=../../private".into(),
            "PHP_VERSION=8.5.12".into(),
        ],
        ..Inspect::default()
    };
    let (paths_found, omitted) = php_config_paths(&inspected, &[], "alpine", &[]);
    assert!(omitted);
    assert_eq!(paths_found[0], "/config/php.ini");
    for name in &paths_found {
        assert!(
            paths::valid_file_path(name) && name != "/config" && !name.contains("private"),
            "{name}"
        );
    }
    assert!(
        paths_found.contains(&"/etc/php85/php.ini".to_string()),
        "{paths_found:?}"
    );
}

/// 원본 `TestAllProductsWithoutPHPDoNotProbeConfiguration`.
#[test]
fn without_php_the_configuration_is_not_probed() {
    let (b, _, _) = budget();
    let files: HashMap<String, Vec<u8>> = [
        ("/etc/os-release", "ID=ubuntu\nVERSION_ID=24.04\n"),
        ("/var/lib/dpkg/status", ""),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
    .collect();
    let engine = Engine::new(move |s| {
        let content = files
            .get(&s.file)
            .unwrap_or_else(|| panic!("PHP 가 없는 대상에서 조회했다: {}", s.file));
        Ok(file_answer(s, &paths::base(&s.file), content, 0o644))
    });
    let mut c = client(&b, &engine, "linux");
    let mut t = target(&[]);
    scan_container_files(
        &mut c,
        &mut t,
        TEST_ID,
        &Inspect::default(),
        &blank_rules(),
        &[Product::Php, Product::Node],
    );
    assert!(t.findings.is_empty());
    assert_eq!(b.usage().container_requests, 4);
}

// ── 점검 전체 ────────────────────────────────────────────────────────────────────────────────

fn version_answer(os: &str) -> Answer {
    Answer::ok(format!(
        r#"{{"Version":"29.0.0","ApiVersion":"1.52","MinAPIVersion":"1.24","Os":"{os}"}}"#
    ))
}

fn run(
    engine: &Engine,
    ids: &[&str],
    products: &[Product],
) -> (Vec<Target>, Vec<String>, crate::scan::budget::Usage) {
    let (b, _, _) = budget();
    let ids: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
    let req = Request {
        endpoint: "unix:///var/run/docker.sock",
        ids: &ids,
        products,
        rules: RuleSet::fixture(),
        lang: Lang::Ko,
    };
    let mut c = Client::new(&b, engine, Lang::Ko);
    c.kind = Some(EngineKind::Docker);
    let mut done = Vec::new();
    let targets = scan_with(&mut c, &req, &mut |t: &Target| done.push(t.id.clone()));
    (targets, done, b.usage())
}

#[test]
fn an_endpoint_that_fails_its_check_becomes_one_target() {
    let (b, _, _) = budget();
    let ids = vec![TEST_ID.to_string()];
    let req = Request {
        endpoint: "tcp://localhost:2375",
        ids: &ids,
        products: &[Product::Php, Product::Node],
        rules: RuleSet::fixture(),
        lang: Lang::Ko,
    };
    let mut done = 0;
    let targets = scan(&req, &b, &mut |_| done += 1);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].id, "container:endpoint");
    assert_eq!(targets[0].status, Status::ReviewRequired);
    assert!(
        targets[0].gaps[0].contains("Unix") || targets[0].gaps[0].contains("파이프"),
        "{:?}",
        targets[0].gaps
    );
    assert_eq!(done, 1);
    assert_eq!(b.usage().container_requests, 0);
    assert_eq!(b.partial_targets("x").len(), 1);
}

#[test]
fn an_unsupported_engine_becomes_the_api_version_target() {
    let engine = Engine::new(|s| {
        assert_eq!(s.path, "/version");
        Ok(version_answer("darwin"))
    });
    let (targets, done, usage) = run(&engine, &[TEST_ID], &[Product::Php]);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].id, "container:api-version");
    assert_eq!(targets[0].status, Status::ReviewRequired);
    assert_eq!(done, ["container:api-version"]);
    assert_eq!(usage.container_requests, 1);
}

#[test]
fn no_selected_container_becomes_the_selection_target() {
    let engine = Engine::new(|_| Ok(version_answer("linux")));
    let (targets, _, _) = run(&engine, &[], &[]);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].id, "container:selection");
    assert!(
        targets[0].products.contains_key(&Product::Php),
        "제품을 고르지 않으면 PHP 다"
    );
}

#[test]
fn each_id_is_checked_once_and_a_stopped_or_unknown_container_is_named() {
    let short = &TEST_ID[..12];
    let stopped = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let engine = Engine::new(move |s| {
        if s.path == "/version" {
            return Ok(version_answer("linux"));
        }
        if s.path.ends_with(&format!("{short}/json")) {
            return Ok(Answer::ok(format!(
                r#"{{"Id":"{stopped}","State":{{"Running":true}}}}"#
            )));
        }
        if s.path.ends_with(&format!("{stopped}/json")) {
            return Ok(Answer::ok(format!(
                r#"{{"Id":"{stopped}","State":{{"Running":false}}}}"#
            )));
        }
        Ok(Answer::status(404))
    });
    let (targets, done, _) = run(
        &engine,
        &[short, short, "NOT-AN-ID", stopped, "0123456789aa"],
        &[Product::Php],
    );
    assert_eq!(
        targets.len(),
        4,
        "{:?}",
        targets.iter().map(|t| &t.id).collect::<Vec<_>>()
    );
    assert_eq!(done.len(), 4);
    for t in &targets {
        assert_eq!(t.status, Status::ReviewRequired, "{}", t.id);
        assert!(!t.reason.is_empty() && !t.action.is_empty());
    }
    assert!(
        targets[0]
            .gaps
            .iter()
            .any(|g| g.contains("실행 중 컨테이너")),
        "{:?}",
        targets[0].gaps
    );
    assert!(targets[1]
        .gaps
        .iter()
        .any(|g| g.contains("목록에서 확인한 ID")));
    assert!(targets[3].gaps.iter().any(|g| g.contains("HTTP 404")));
}

/// 실행 중인 컨테이너 하나를 처음부터 끝까지 — 이미지 ID 확인, 배포판, 패키지, 세션 설정, 대상의 마무리.
#[test]
fn a_running_container_is_checked_end_to_end_and_never_reaches_clear() {
    let image = format!("sha256:{}", "a".repeat(64));
    let files: HashMap<String, Vec<u8>> = [
        ("/etc/os-release", "ID=ubuntu\nVERSION_ID=22.04\n"),
        ("/var/lib/dpkg/status", UBUNTU_PHP),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
    .collect();
    let image_for_engine = image.clone();
    let engine = Engine::new(move |s| match s.path.as_str() {
        "/version" => Ok(version_answer("linux")),
        p if p.ends_with(&format!("{TEST_ID}/json")) => Ok(Answer::ok(format!(
            r#"{{"Id":"{TEST_ID}","Name":"/web","Image":"{image_for_engine}","State":{{"Running":true,"Pid":0}},"Config":{{"Env":["PATH=/usr/bin"]}}}}"#
        ))),
        p if p.starts_with("/v1.44/images/") => {
            Ok(Answer::ok(format!(r#"{{"Id":"{image_for_engine}"}}"#)))
        }
        _ => match files.get(&s.file) {
            Some(content) => Ok(file_answer(s, &paths::base(&s.file), content, 0o644)),
            None => Ok(Answer::status(404)),
        },
    });
    let (targets, done, usage) = run(&engine, &[TEST_ID], &[Product::Php, Product::Node]);
    let t = &targets[0];
    assert_eq!(done, [format!("container:{TEST_ID}")]);
    assert_eq!(t.name, "web");
    assert_eq!(t.metadata["image_id"], image);
    assert_eq!(t.metadata["engine_api_version"], "1.44");
    assert_eq!(t.status, Status::Vulnerable);
    assert_eq!(t.products[&Product::Node].status, Status::ReviewRequired);
    assert!(t.findings.iter().any(|f| f.id.ends_with(phpconfig::CVE)));
    assert!(usage.container_requests <= 128);
    let mut clean = t.clone();
    clean.findings.clear();
    finalize_container_target(&mut clean, Lang::Ko);
    assert_ne!(clean.status, Status::Clear, "컨테이너가 양호에 닿았다");
}
