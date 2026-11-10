//! RPM — 스캐너 `rpm_files_test.go` 와, 실제 RPM DB 를 `read_untrusted` 로 읽는 길.

use super::support::*;
use crate::scan::binary::fixtures::minimal_elf32;
use crate::scan::binary::inspect_node_binary;
use crate::scan::container::client::BinaryFile;
use crate::scan::container::files::Subject;
use crate::scan::container::inspect::Inspect;
use crate::scan::container::node::{node_container_dependencies, Walk};
use crate::scan::container::php::scan_php_container;
use crate::scan::container::rpm::{
    convert, read_rpm_packages, rpm_file_owners, RpmPackage, RpmProblem, RpmRecords,
};
use crate::scan::model::{Product, Status, Target, TargetKind};
use crate::scan::rules::{Component, PackageManager};
use remedy_rpmdb::{DigestAlgorithm, FileDigests, Package, RpmDbError, RpmHeader};
use remedy_sdk::i18n::Lang;
use std::collections::{HashMap, HashSet};

const TINY: &[u8] = include_bytes!("../../../../../remedy-rpmdb/src/testdata/tiny-rpmdb.sqlite");

fn target(products: &[Product]) -> Target {
    Target::new(
        format!("container:{TEST_ID}"),
        TargetKind::Container,
        TEST_ID,
        products,
    )
}

/// `PHP <버전>` 글자를 담은 작은 ELF.
fn php_elf(core: &str) -> Vec<u8> {
    let mut body = minimal_elf32();
    let text = format!("PHP {core}\0");
    body[100..100 + text.len()].copy_from_slice(text.as_bytes());
    body
}

fn records(id: &str, file: &str, algorithm: &str, digest: &str) -> RpmRecords {
    let mut checksums = HashMap::new();
    checksums.insert(file.to_string(), digest.to_string());
    let p = RpmPackage {
        files: vec![file.to_string()],
        checksum_algorithm: algorithm.to_string(),
        checksums,
        ..RpmPackage::default()
    };
    [(id.to_string(), p)].into_iter().collect()
}

/// 원본 `TestContainerRPMManagerCannotInheritDebianFamilyVersions` — RPM 이 소유한 파일은 dpkg 줄의 수정을 물려받지
/// 않는다(배포판 이름이 Ubuntu · Debian 이어도).
#[test]
fn an_rpm_owner_cannot_inherit_debian_family_versions() {
    for (distro, release, pkg, version, core) in [
        (
            "ubuntu",
            "24.04",
            "php8.3-cli",
            "8.3.6-0ubuntu0.24.04.13",
            "8.3.6",
        ),
        ("debian", "12", "php8.2-cli", "8.2.29-1~deb12u9", "8.2.29"),
    ] {
        let body = php_elf(core);
        let (b, _, _) = budget();
        let engine = files_engine(vec![("/usr/bin/php", body.clone())]);
        let mut c = client(&b, &engine, "linux");
        let mut component = Component::new(Product::Php);
        component.id = "rpm-foreign".into();
        component.package = pkg.into();
        component.version = version.into();
        component.distribution = distro.into();
        component.distribution_version = release.into();
        component.architecture = "i686".into();
        component.package_vendor = "Third-party RPM".into();
        component.source = "/var/lib/rpm/Packages".into();
        let rules = rpm_rules(Some(distro));
        let mut control = component.clone();
        control.trusted = true;
        assert_eq!(
            rules.evaluate(&control, Lang::Ko).status,
            Status::Clear,
            "dpkg 줄 대조의 시험 오류"
        );
        let recs = records("rpm-foreign", "usr/bin/php", "md5", &md5_hex(&body));
        let mut t = target(&[Product::Php]);
        let inspected = Inspect::default();
        let packages = [component];
        let s = Subject {
            id: TEST_ID,
            inspected: &inspected,
            rules: &rules,
            packages: &packages,
            package_data: &[],
            distro,
            rpm: Some(&recs),
        };
        scan_php_container(&mut c, &mut t, &s);
        let file = t
            .findings
            .iter()
            .find(|f| f.id == "container-file:/usr/bin/php")
            .expect("실제 파일 판정이 없다");
        assert_eq!(file.status, Status::ReviewRequired, "{distro}: {file:?}");
        assert_eq!(file.vendor.as_deref(), Some(distro));
    }
}

/// 원본 `TestContainerRPMFileHashControlsVendorVerdict` — 실제 파일의 다이제스트가 RPM 기록과 같을 때만 그 패키지의
/// 공급사 판정이 실제 파일에 붙는다.
#[test]
fn the_rpm_file_hash_controls_the_vendor_verdict() {
    let body = php_elf("8.3.6");
    let (md5, sha) = (md5_hex(&body), sha256_hex(&body));
    let cases = [
        (
            "unfixed_md5",
            "md5",
            "8.3.6-1.fc40",
            md5.clone(),
            false,
            Status::Vulnerable,
        ),
        (
            "fixed_sha256",
            "sha256",
            "8.3.6-2.fc40",
            sha,
            false,
            Status::Clear,
        ),
        (
            "changed_file",
            "md5",
            "8.3.6-1.fc40",
            md5,
            true,
            Status::ReviewRequired,
        ),
        (
            "missing_checksum",
            "md5",
            "8.3.6-1.fc40",
            String::new(),
            false,
            Status::ReviewRequired,
        ),
        (
            "unsupported_hash",
            "sha1",
            "8.3.6-1.fc40",
            "a".repeat(40),
            false,
            Status::ReviewRequired,
        ),
    ];
    for (name, algorithm, version, digest, changed, want) in cases {
        let mut actual = body.clone();
        if changed {
            actual.push(b'x');
        }
        let (b, _, _) = budget();
        let engine = files_engine(vec![("/usr/bin/php", actual)]);
        let mut c = client(&b, &engine, "linux");
        let mut component = Component::new(Product::Php);
        component.id = "rpm:php-cli:i686".into();
        component.package = "php-cli".into();
        component.version = version.into();
        component.architecture = "i686".into();
        component.package_vendor = "Fedora Project".into();
        component.distribution = "fedora".into();
        component.distribution_version = "40".into();
        component.source = "RPM fixture".into();
        let recs = records("rpm:php-cli:i686", "usr/bin/php", algorithm, &digest);
        let rules = rpm_rules(None);
        let mut t = target(&[Product::Php]);
        let inspected = Inspect::default();
        let packages = [component];
        let s = Subject {
            id: TEST_ID,
            inspected: &inspected,
            rules: &rules,
            packages: &packages,
            package_data: &[],
            distro: "fedora",
            rpm: Some(&recs),
        };
        scan_php_container(&mut c, &mut t, &s);
        let file = t
            .findings
            .iter()
            .find(|f| f.id == "container-file:/usr/bin/php")
            .expect("실제 파일 판정이 없다");
        assert_eq!(file.status, want, "{name}: {}", file.reason);
        t.finalize(Lang::Ko);
        let target_want = if want == Status::Vulnerable {
            Status::Vulnerable
        } else {
            Status::ReviewRequired
        };
        assert_eq!(t.status, target_want, "{name}");
        assert_eq!(engine.count(), 2, "{name}: {:?}", engine.lines());
    }
}

/// 원본 `TestContainerRPMBrotliVulnerabilitySurvivesOtherDependencyGap` — 다른 의존을 정하지 못해도 RPM 기록과 맞는
/// 공유 Brotli 의 취약은 남는다.
#[test]
fn an_rpm_brotli_vulnerability_survives_another_dependency_gap() {
    let body = minimal_elf32();
    let (b, _, _) = budget();
    let engine = files_engine(vec![("/usr/lib32/libbrotlidec.so.1", body.clone())]);
    let mut c = client(&b, &engine, "linux");
    let mut component = Component::new(Product::Brotli);
    component.id = "rpm:brotli:i686".into();
    component.package = "brotli".into();
    component.version = "1.0.6-2.el8_10".into();
    component.architecture = "i686".into();
    component.package_vendor = "Red Hat, Inc.".into();
    component.distribution = "rhel".into();
    component.distribution_version = "8.10".into();
    component.source = "RPM fixture".into();
    let recs = records(
        "rpm:brotli:i686",
        "usr/lib32/libbrotlidec.so.1",
        "sha256",
        &sha256_hex(&body),
    );
    let (owners, checks) = rpm_file_owners(&c, &[component], Some(&recs));
    let mut root = inspect_node_binary(&body, body.len() as u64);
    root.needed = vec!["libbrotlidec.so.1".into(), "libnode.so.999".into()];
    let node = BinaryFile {
        prefix: Vec::new(),
        sha256: String::new(),
        md5: String::new(),
        size: 128,
        info: root,
    };
    let walk = Walk {
        owners: &owners,
        checks: Some(&checks),
        lang: Lang::Ko,
    };
    let mut read = |name: &str| c.read_binary(TEST_ID, name);
    let (mode, deps, complete) = node_container_dependencies(
        "/usr/bin/node",
        &node,
        &walk,
        &mut read,
        &mut HashSet::new(),
        0,
    );
    let mut probe = Component::new(Product::Node);
    probe.dependency_mode = mode;
    probe.dependencies = deps.clone();
    probe.dependencies_complete = complete;
    let finding = rpm_rules(None).evaluate(&probe, Lang::Ko);
    assert!(!complete);
    assert_eq!(deps.len(), 1);
    assert!(deps[0].trusted);
    assert_eq!(deps[0].package_manager, PackageManager::Rpm);
    assert_eq!(finding.status, Status::Vulnerable, "{finding:?}");
}

fn package(files: &[&str], digests: Result<FileDigests, RpmDbError>) -> Package {
    Package {
        header: RpmHeader {
            name: "php-cli".into(),
            epoch: Some(2),
            version: "8.3.6".into(),
            release: "1.fc40".into(),
            arch: "x86_64".into(),
            vendor: "Fedora Project".into(),
            sourcerpm: String::new(),
        },
        modularity_label: Some("php:8.3:4020:abc".into()),
        files: files.iter().map(|f| f.to_string()).collect(),
        digests,
    }
}

/// `read_untrusted` 의 패키지를 스캐너의 꼴로 — epoch · 정리한 상대 경로 · 경로에 붙은 다이제스트.
#[test]
fn untrusted_packages_take_the_scanner_shape() {
    let sha = "a".repeat(64);
    let digests = |d: &[&str]| {
        Ok(FileDigests {
            algorithm: DigestAlgorithm::Sha256,
            digests: d.iter().map(|s| s.to_string()).collect(),
        })
    };
    let p = convert(package(
        &["/", "/usr/bin/php", "/usr//bin/php"],
        digests(&["", &sha, &sha]),
    ))
    .unwrap();
    assert_eq!(p.version, "2:8.3.6-1.fc40");
    assert_eq!(p.module, "php:8.3:4020:abc");
    assert_eq!(p.files, ["usr/bin/php", "usr/bin/php"]);
    assert_eq!(p.checksum_algorithm, "sha256");
    assert_eq!(p.checksums["usr/bin/php"], sha);
    assert_eq!(p.checksum_error, None);
    let other = "b".repeat(64);
    let conflict = convert(package(
        &["/usr/bin/php", "/usr/bin/php"],
        digests(&[&sha, &other]),
    ))
    .unwrap();
    assert_eq!(conflict.checksum_error, Some(RpmProblem::Conflicting));
    assert!(conflict.checksums.is_empty());
    let unsupported = convert(package(
        &["/usr/bin/php"],
        Err(RpmDbError::Format("읽지 않는 파일 다이제스트 알고리즘이다")),
    ))
    .unwrap();
    assert_eq!(unsupported.checksum_error, Some(RpmProblem::Unsupported));
    let malformed = convert(package(
        &["/usr/bin/php"],
        Err(RpmDbError::Format("파일 수와 다이제스트 수가 다르다")),
    ))
    .unwrap();
    assert_eq!(malformed.checksum_error, Some(RpmProblem::Malformed));
    assert!(convert(package(&["/usr/../etc/shadow"], digests(&[""]))).is_none());
}

/// 실제 SQLite RPM DB — 쓰기 로그 둘이 없을 때 고른 제품의 패키지를 RPM 패키지로 싣는다.
#[test]
fn a_real_sqlite_database_is_read_after_the_write_log_checks() {
    let (b, _, _) = budget();
    let engine = files_engine(vec![("/usr/lib/sysimage/rpm/rpmdb.sqlite", TINY.to_vec())]);
    let mut c = client(&b, &engine, "linux");
    let mut t = target(&[Product::Php]);
    let (packages, recs) =
        read_rpm_packages(&mut c, &mut t, TEST_ID, "rocky", "9", &[Product::Php]);
    let names: Vec<&str> = packages.iter().map(|p| p.package.as_str()).collect();
    assert_eq!(names, ["php-cli", "php-fpm"], "{names:?}");
    assert!(packages
        .iter()
        .all(|p| p.package_manager == PackageManager::Rpm && !p.trusted));
    assert!(packages
        .iter()
        .all(|p| p.name == "RPM 패키지" && p.distribution == "rocky"));
    assert_eq!(recs.len(), 2);
    assert!(t.gaps.is_empty(), "{:?}", t.gaps);
    assert!(t
        .scope
        .contains(&"/usr/lib/sysimage/rpm/rpmdb.sqlite".to_string()));
    assert_eq!(
        engine.lines(),
        [
            "HEAD /usr/lib/sysimage/rpm/rpmdb.sqlite",
            "GET /usr/lib/sysimage/rpm/rpmdb.sqlite",
            "HEAD /usr/lib/sysimage/rpm/rpmdb.sqlite-wal",
            "HEAD /usr/lib/sysimage/rpm/rpmdb.sqlite-journal",
        ]
    );
}

#[test]
fn a_pending_write_log_or_a_broken_database_is_a_gap() {
    let (b, _, _) = budget();
    let engine = files_engine(vec![
        ("/usr/lib/sysimage/rpm/rpmdb.sqlite", TINY.to_vec()),
        ("/usr/lib/sysimage/rpm/rpmdb.sqlite-wal", vec![1, 2, 3]),
    ]);
    let mut c = client(&b, &engine, "linux");
    let mut t = target(&[Product::Php]);
    let (packages, _) = read_rpm_packages(&mut c, &mut t, TEST_ID, "rocky", "9", &[Product::Php]);
    assert!(packages.is_empty());
    assert!(t.gaps[0].contains("쓰기 로그"), "{:?}", t.gaps);

    // 옛 자리 · 다른 이름 — 앞의 것이 없으면(404) 다음으로 간다. 깨진 DB 는 해석 실패다.
    let (b, _, _) = budget();
    let engine = files_engine(vec![("/var/lib/rpm/Packages", b"not a database".to_vec())]);
    let mut c = client(&b, &engine, "linux");
    let mut t = target(&[Product::Php]);
    let (packages, _) = read_rpm_packages(&mut c, &mut t, TEST_ID, "centos", "7", &[Product::Php]);
    assert!(packages.is_empty());
    assert!(t.gaps[0].contains("해석하지 못했습니다"), "{:?}", t.gaps);
    // 새 자리의 세 이름(HEAD 404) · 옛 자리의 rpmdb.sqlite(HEAD 404) · Packages(HEAD · GET).
    assert_eq!(engine.count(), 3 + 1 + 2);
}
