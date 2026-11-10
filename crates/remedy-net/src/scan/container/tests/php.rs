//! PHP — 스캐너 `php_legacy_test.go` · `qualification_test.go` · `windows_container_test.go` 의 리눅스 PHP 시험과
//! `client_test.go` 의 패키지 신뢰 시험.

use super::support::*;
use crate::scan::binary::fixtures::minimal_elf64;
use crate::scan::container::files::{scan_container_files, Subject};
use crate::scan::container::inspect::{Inspect, Mount};
use crate::scan::container::packages::{parse_apk, parse_dpkg};
use crate::scan::container::paths;
use crate::scan::container::php::scan_php_container;
use crate::scan::container::record::finalize_container_target;
use crate::scan::container::wire::Method;
use crate::scan::model::{Product, Status, Target, TargetKind};
use crate::scan::rules::RuleSet;
use remedy_sdk::i18n::Lang;
use std::collections::HashMap;

fn target(products: &[Product]) -> Target {
    Target::new(
        format!("container:{TEST_ID}"),
        TargetKind::Container,
        TEST_ID,
        products,
    )
}

fn php_binary(version: &str) -> Vec<u8> {
    let mut data = minimal_elf64();
    data.extend_from_slice(format!("\0PHP/{version}\0").as_bytes());
    data
}

fn subject<'x>(inspected: &'x Inspect, rules: &'x RuleSet) -> Subject<'x> {
    Subject {
        id: TEST_ID,
        inspected,
        rules,
        packages: &[],
        package_data: &[],
        distro: "",
        rpm: None,
    }
}

/// 원본 `TestPackageRecordsDoNotTrustCustomVendor`.
#[test]
fn package_records_do_not_trust_a_custom_vendor() {
    let data = "Package: php8.2-cli\nStatus: install ok installed\nVersion: 8.2.0-1\nMaintainer: Custom Builder <builder@example.com>\n\nPackage: php8.2-fpm\nStatus: deinstall ok config-files\nVersion: 8.2.0-1\n";
    let items = parse_dpkg(
        data.as_bytes(),
        "debian",
        "12",
        "fixture",
        &[Product::Php],
        Lang::Ko,
    );
    assert_eq!(items.len(), 1);
    assert!(!items[0].trusted);
    assert_eq!(items[0].package, "php8.2-cli");
    let apk = parse_apk(
        b"P:php83\nV:8.3.1-r0\n",
        "3.20",
        "fixture",
        &[Product::Php],
        Lang::Ko,
    );
    assert_eq!(apk.len(), 1);
    assert!(!apk[0].trusted);
}

/// 원본 `TestLegacyUbuntuPHPBackportsPreserveContainerPackageEvidence` — Ubuntu 의 PHP 5 · 7 백포트 패키지가 공급사
/// 기준과 이어지고, 수집한 뒤에도 그 판정을 잃지 않는다. 고친 패키지 기록은 실제 파일과 잇지 못해 *확인 필요* 다.
#[test]
fn legacy_ubuntu_php_backports_keep_their_package_evidence() {
    let rules = RuleSet::builtin();
    let releases = [
        (
            "14.04",
            "php5",
            "5.5.9+dfsg-1ubuntu4.29+esm17",
            "5.5.9+dfsg-1ubuntu4.29+esm18",
        ),
        (
            "16.04",
            "php7.0",
            "7.0.33-0ubuntu0.16.04.16+esm21",
            "7.0.33-0ubuntu0.16.04.16+esm22",
        ),
        (
            "18.04",
            "php7.2",
            "7.2.24-0ubuntu0.18.04.17+esm13",
            "7.2.24-0ubuntu0.18.04.17+esm14",
        ),
        (
            "20.04",
            "php7.4",
            "7.4.3-4ubuntu2.29+esm4",
            "7.4.3-4ubuntu2.29+esm5",
        ),
    ];
    let ubuntu = "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>";
    for (release, prefix, before, fixed) in releases {
        for pkg in [
            format!("{prefix}-cli"),
            format!("{prefix}-fpm"),
            format!("{prefix}-cgi"),
            format!("libapache2-mod-{prefix}"),
        ] {
            let fixed_ppa = format!("{fixed}+ppa1");
            for (name, version, maintainer, want) in [
                ("before_fix", before, ubuntu, Status::Vulnerable),
                ("fixed", fixed, ubuntu, Status::Clear),
                (
                    "unknown_supplier",
                    fixed,
                    "Custom Builder <builder@example.invalid>",
                    Status::ReviewRequired,
                ),
                (
                    "unknown_suffix",
                    fixed_ppa.as_str(),
                    ubuntu,
                    Status::ReviewRequired,
                ),
            ] {
                let case = format!("{release}/{pkg}/{name}");
                let status = format!("Package: {pkg}\nStatus: install ok installed\nVersion: {version}\nMaintainer: {maintainer}\n\n");
                let packages = parse_dpkg(
                    status.as_bytes(),
                    "ubuntu",
                    release,
                    "fixture dpkg status",
                    &[Product::Php],
                    Lang::Ko,
                );
                assert_eq!(packages.len(), 1, "{case}");
                assert_eq!(
                    rules.evaluate(&packages[0], Lang::Ko).status,
                    want,
                    "{case}"
                );
                let (b, _, _) = budget();
                let engine = files_engine(vec![
                    (
                        "/etc/os-release",
                        format!("ID=ubuntu\nVERSION_ID={release}\n").into_bytes(),
                    ),
                    ("/var/lib/dpkg/status", status.into_bytes()),
                ]);
                let mut c = client(&b, &engine, "linux");
                let mut t = target(&[]);
                scan_container_files(
                    &mut c,
                    &mut t,
                    TEST_ID,
                    &Inspect::default(),
                    rules,
                    &[Product::Php],
                );
                finalize_container_target(&mut t, Lang::Ko);
                let found = runtime_findings(&t);
                let expected = if want == Status::Clear {
                    Status::ReviewRequired
                } else {
                    want
                };
                assert_eq!(found.len(), 1, "{case}");
                assert_eq!(found[0].status, expected, "{case}");
                assert_eq!(found[0].package.as_deref(), Some(pkg.as_str()), "{case}");
                assert_eq!(t.status, expected, "{case}");
                if want == Status::Clear {
                    assert!(
                        found[0].reason.contains("실제 파일"),
                        "{case}: {}",
                        found[0].reason
                    );
                }
            }
        }
    }
}

/// 원본 `TestQualificationContainerPHPPackageNeedsLinkedFileForClear` — 패키지 기록만으로는 양호가 아니고, 미수정
/// 기록의 취약은 남는다. 관리자 꼬리를 속인 기록 · 겹친 버전 · 깨진 줄은 판정하지 않는다.
#[test]
fn a_php_package_needs_a_linked_file_for_clear() {
    let ubuntu = "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>";
    let spoofed = format!("{ubuntu} Custom <builder@example.invalid>");
    let cases = [
        (
            "official_vulnerable_package_preserved",
            "8.3.6-0ubuntu0.24.04.12",
            ubuntu,
            "",
            Status::Vulnerable,
        ),
        (
            "official_fixed_package_record_only",
            "8.3.6-0ubuntu0.24.04.13",
            ubuntu,
            "",
            Status::ReviewRequired,
        ),
        (
            "spoofed_maintainer_suffix",
            "8.3.6-0ubuntu0.24.04.12",
            spoofed.as_str(),
            "",
            Status::ReviewRequired,
        ),
        (
            "conflicting_version_records",
            "8.3.6-0ubuntu0.24.04.13",
            ubuntu,
            "Version: 8.3.6-0ubuntu0.24.04.12\n",
            Status::ReviewRequired,
        ),
        (
            "malformed_control_record",
            "8.3.6-0ubuntu0.24.04.12",
            ubuntu,
            "broken control row\n",
            Status::ReviewRequired,
        ),
    ];
    for (name, version, maintainer, extra, want) in cases {
        let (b, _, _) = budget();
        let status = format!("Package: php8.3-cli\nStatus: install ok installed\nVersion: {version}\nMaintainer: {maintainer}\n{extra}");
        let files: HashMap<String, Vec<u8>> = [
            (
                "/etc/os-release".to_string(),
                b"ID=ubuntu\nVERSION_ID=24.04\n".to_vec(),
            ),
            ("/var/lib/dpkg/status".to_string(), status.into_bytes()),
        ]
        .into_iter()
        .collect();
        let engine = Engine::new(move |s| match files.get(&s.file) {
            Some(content) => Ok(file_answer(s, &paths::base(&s.file), content, 0o644)),
            None => {
                assert_eq!(
                    s.method,
                    Method::Head,
                    "HEAD 확인 없이 GET 을 보냈다: {}",
                    s.file
                );
                Ok(Answer::status(404))
            }
        });
        let mut c = client(&b, &engine, "linux");
        let mut t = target(&[]);
        scan_container_files(
            &mut c,
            &mut t,
            TEST_ID,
            &Inspect::default(),
            RuleSet::builtin(),
            &[Product::Php],
        );
        t.finalize(Lang::Ko);
        assert_eq!(runtime_findings(&t).len(), 1, "{name}");
        assert_eq!(t.findings[0].status, want, "{name}");
        if name == "official_fixed_package_record_only" {
            assert!(t.findings[0].reason.contains("실제 파일"), "{name}");
            assert!(t.findings[0].evidence.len() >= 2, "{name}");
        }
        assert!(engine.count() <= 4 + 8, "{name}: {:?}", engine.lines());
        assert_eq!(b.usage().container_requests as usize, engine.count());
        if want == Status::ReviewRequired {
            assert_eq!(
                t.products[&Product::Php].status,
                Status::ReviewRequired,
                "{name}"
            );
        }
    }
}

/// 원본 `TestOfficialPHPEntrypointCollectsKnownRuntimeFiles` — 공식 PHP 이미지의 진입점이면 알려진 자리를 읽는다.
#[test]
fn the_official_php_entrypoint_collects_known_runtime_files() {
    for command in ["php-fpm", "apache2-foreground", "php"] {
        let php = php_binary("8.3.35");
        let mut fpm = php.clone();
        fpm.push(b'f');
        let (b, _, _) = budget();
        let engine = files_engine(vec![
            ("/usr/local/bin/php", php.clone()),
            ("/usr/local/sbin/php-fpm", fpm),
        ]);
        let mut c = client(&b, &engine, "linux");
        let inspected = Inspect {
            path: "docker-php-entrypoint".into(),
            entrypoint: vec!["docker-php-entrypoint".into()],
            cmd: vec![command.into()],
            env: vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin".into(),
                "PHP_VERSION=8.3.35".into(),
            ],
            ..Inspect::default()
        };
        let rules = hash_rules(vec![hash_row(&php, "8.3.35", false)], Vec::new());
        let mut t = target(&[Product::Php]);
        scan_php_container(&mut c, &mut t, &subject(&inspected, &rules));
        t.finalize(Lang::Ko);
        let found = runtime_findings(&t).iter().any(|f| {
            f.path.as_deref() == Some("/usr/local/bin/php") && f.status == Status::Vulnerable
        });
        assert!(found, "{command}: {:?}", t.findings);
        assert_eq!(t.status, Status::Vulnerable);
        assert!(engine.count() <= 20, "{command}: {:?}", engine.lines());
    }
}

/// 원본 `TestOfficialPHPFixedCLIAndVulnerableApacheModuleRemainVulnerable`.
#[test]
fn a_fixed_cli_does_not_hide_a_vulnerable_apache_module() {
    let cli = php_binary("8.3.36");
    let mut module = php_binary("8.3.35");
    module.extend_from_slice(b"module");
    let rules = hash_rules(
        vec![
            hash_row(&cli, "8.3.36", false),
            hash_row(&module, "8.3.35", false),
        ],
        Vec::new(),
    );
    let (b, _, _) = budget();
    let engine = files_engine(vec![
        ("/usr/local/bin/php", cli),
        ("/usr/lib/apache2/modules/libphp.so", module),
    ]);
    let mut c = client(&b, &engine, "linux");
    let inspected = Inspect {
        path: "docker-php-entrypoint".into(),
        cmd: vec!["apache2-foreground".into()],
        env: vec!["PHP_VERSION=8.3.36".into()],
        ..Inspect::default()
    };
    let mut t = target(&[Product::Php]);
    scan_php_container(&mut c, &mut t, &subject(&inspected, &rules));
    finalize_container_target(&mut t, Lang::Ko);
    let module_vulnerable = runtime_findings(&t).iter().any(|f| {
        f.path.as_deref() == Some("/usr/lib/apache2/modules/libphp.so")
            && f.runtime.as_deref() == Some("mod_php")
            && f.status == Status::Vulnerable
    });
    assert!(module_vulnerable, "{:?}", t.findings);
    assert_eq!(t.status, Status::Vulnerable);
}

/// 원본 `TestContainerLateRuntimeArgumentsAreStillCollected` — 평범한 인자 80개 뒤의 실행 파일도 한 번씩 읽는다.
#[test]
fn runtimes_named_late_in_the_arguments_are_still_collected() {
    let php = php_binary("8.3.35");
    let mut node = minimal_elf64();
    node.extend_from_slice(b"\0node.js/v22.22.0\0");
    let rules = hash_rules(
        vec![hash_row(&php, "8.3.35", false)],
        vec![hash_row(&node, "22.22.0", true)],
    );
    let (b, _, _) = budget();
    let engine = files_engine(vec![
        ("/etc/os-release", b"ID=debian\nVERSION_ID=13\n".to_vec()),
        ("/var/lib/dpkg/status", Vec::new()),
        ("/usr/local/bin/php", php),
        ("/usr/local/bin/node", node),
    ]);
    let mut c = client(&b, &engine, "linux");
    let mut cmd: Vec<String> = vec!["ordinary-argument".into(); 80];
    cmd.extend([
        "/usr/local/bin/php".to_string(),
        "/usr/local/bin/node".to_string(),
    ]);
    let inspected = Inspect {
        path: "launcher".into(),
        entrypoint: vec!["launcher".into()],
        cmd,
        ..Inspect::default()
    };
    let mut t = target(&[]);
    scan_container_files(
        &mut c,
        &mut t,
        TEST_ID,
        &inspected,
        &rules,
        &[Product::Php, Product::Node],
    );
    finalize_container_target(&mut t, Lang::Ko);
    for p in [Product::Php, Product::Node] {
        assert_eq!(
            t.products[&p].status,
            Status::Vulnerable,
            "{p:?}: {:?}",
            t.findings
        );
    }
    for name in ["/usr/local/bin/php", "/usr/local/bin/node"] {
        let gets = engine
            .lines()
            .iter()
            .filter(|l| **l == format!("GET {name}"))
            .count();
        assert_eq!(gets, 1, "{name}: {:?}", engine.lines());
    }
}

/// 원본 `TestContainerMountUncertaintyPreservesExactHashVulnerability` — 마운트를 다 알 수 없다는 한계가 실제 파일의
/// 해시로 확인한 취약을 가리지 않고, 마운트 자리는 묻지 않는다.
#[test]
fn mount_uncertainty_keeps_an_exact_hash_vulnerability() {
    let php = php_binary("8.3.35");
    let rules = hash_rules(vec![hash_row(&php, "8.3.35", false)], Vec::new());
    let (b, _, _) = budget();
    let engine = files_engine(vec![
        ("/etc/os-release", b"ID=debian\nVERSION_ID=13\n".to_vec()),
        ("/var/lib/dpkg/status", Vec::new()),
        ("/usr/local/bin/php", php),
    ]);
    let mut c = client(&b, &engine, "linux");
    let inspected = Inspect {
        path: "/usr/local/bin/php".into(),
        mounts: vec![Mount {
            kind: "bind".into(),
            destination: "/data".into(),
        }],
        ..Inspect::default()
    };
    let mut t = target(&[]);
    scan_container_files(
        &mut c,
        &mut t,
        TEST_ID,
        &inspected,
        &rules,
        &[Product::Php, Product::Node],
    );
    finalize_container_target(&mut t, Lang::Ko);
    assert_eq!(t.status, Status::Vulnerable);
    assert_eq!(t.products[&Product::Php].status, Status::Vulnerable);
    for p in [Product::Php, Product::Node] {
        let noted = t.products[&p]
            .gaps
            .iter()
            .any(|g| g.contains("디렉터리 링크를 거친 마운트"));
        assert!(noted, "{p:?}: {:?}", t.products[&p].gaps);
    }
    for line in engine.lines() {
        assert!(
            !line.starts_with("HEAD /data")
                && !line.starts_with("GET /data")
                && line != "HEAD /usr/local",
            "{line}"
        );
    }
}
