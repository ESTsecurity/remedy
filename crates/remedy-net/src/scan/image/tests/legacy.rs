//! 스캐너 `linux_legacy_test.go` · `php_legacy_test.go` · `php_windows_test.go` · `verdict_review_regression_test.go`
//! — 옛 배포판 · 다중 아키텍처 · 32비트 ELF · 백포트 · Windows 이미지 · 지원하지 않는 연결.

use super::fixtures::*;
use crate::scan::binary::fixtures::php_core_pe;
use crate::scan::image::node::{Links, Owner, Owners};
use crate::scan::image::packages::{parse_dpkg, DpkgInfo};
use crate::scan::image::rootfs::{capture_limit, RootFs};
use crate::scan::model::{Product, Status};
use crate::scan::rules::{Component, DependencyMode, RuleSet};
use remedy_sdk::i18n::Lang;
use serde_json::json;
use std::collections::BTreeSet;
use Packing::Raw;
use Status::{Clear, ReviewRequired as Review, Vulnerable};

/// `TestImageLegacyReleaseFallbackIsCaptured`
#[test]
fn image_legacy_release_fallback_is_captured() {
    let entries = [
        reg("etc/redhat-release", "CentOS release 6.10 (Final)\n"),
        reg("var/lib/dpkg/status", ""),
        reg("usr/local/bin/php", elf32(&[])),
    ];
    let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
    let targets = run(dir.path(), &[Product::Php], &node_rules(None));
    assert_eq!(targets.len(), 1);
    let meta = &targets[0].metadata;
    assert_eq!(
        meta.get("distribution").map(String::as_str),
        Some("centos"),
        "{meta:?}"
    );
    assert_eq!(
        meta.get("distribution_version").map(String::as_str),
        Some("6.10"),
        "{meta:?}"
    );
    for name in [
        "var/lib/rpm/Packages",
        "var/lib/rpm/Packages.db",
        "usr/lib/sysimage/rpm/Packages",
    ] {
        assert_eq!(capture_limit(name, &[Product::Php]), 64 << 20, "{name}");
    }
}

/// `TestDPKGMultiArchOwnershipAndChecksumsStaySeparate`
#[test]
fn dpkg_multi_arch_ownership_and_checksums_stay_separate() {
    let status = b"Package: libbrotli1\nStatus: install ok installed\nVersion: 1.2.0-1\nArchitecture: i386\n\nPackage: libbrotli1\nStatus: install ok installed\nVersion: 1.1.0-1\nArchitecture: amd64\n";
    let packages = parse_dpkg(status, Lang::Ko).unwrap();
    assert_eq!(packages.len(), 2);
    let mut fs = RootFs::default();
    let cases = [
        ("i386", "usr/lib/i386-linux-gnu/libbrotlidec.so.1", "a"),
        ("amd64", "usr/lib/x86_64-linux-gnu/libbrotlidec.so.1", "b"),
    ];
    for (arch, file, digit) in cases {
        let info = format!("var/lib/dpkg/info/libbrotli1:{arch}");
        put(
            &mut fs,
            &format!("{info}.list"),
            format!("/{file}\n").into_bytes(),
        );
        put(
            &mut fs,
            &format!("{info}.md5sums"),
            format!("{}  {file}\n", digit.repeat(32)).into_bytes(),
        );
    }
    let info = DpkgInfo::index(&fs);
    for p in &packages {
        let files = info.files(&p.name, &p.architecture, Lang::Ko).unwrap();
        let sums = info
            .checksums(&p.name, &p.architecture, Lang::Ko)
            .unwrap()
            .unwrap();
        assert_eq!((files.len(), sums.len()), (1, 1), "{p:?}");
        assert!(sums.get(&files[0]).is_some_and(|s| !s.is_empty()), "{p:?}");
        let marker = if p.architecture == "i386" {
            "/i386-"
        } else {
            "/x86_64-"
        };
        assert!(
            files[0].contains(marker),
            "다른 아키텍처의 목록을 합쳤다: {p:?} {files:?}"
        );
    }
}

/// `TestImageELF32LibraryResolutionUsesClassAndMachine`
#[test]
fn image_elf32_library_resolution_uses_class_and_machine() {
    let mut fs = RootFs::default();
    put(&mut fs, "usr/bin/node", elf32(&["libbrotlidec.so.1"]));
    put(&mut fs, "usr/lib32/libbrotlidec.so.1", elf32(&[]));
    put(&mut fs, "usr/lib64/libbrotlidec.so.1", elf(&[]));
    let mut arm = elf32(&[]);
    arm[18..20].copy_from_slice(&40u16.to_le_bytes());
    put(
        &mut fs,
        "usr/lib/arm-linux-gnueabihf/libbrotlidec.so.1",
        arm,
    );
    let mut owners = Owners::default();
    let owner = Owner {
        name: "libbrotli1".into(),
        version: "1.2.0-1".into(),
        architecture: "i386".into(),
        trusted: true,
        ..Owner::default()
    };
    owners
        .by_file
        .insert("usr/lib32/libbrotlidec.so.1".into(), owner);
    let deps = |fs: &RootFs| {
        let links = Links {
            fs,
            owners: &owners,
            os: ("debian", "7"),
            lang: Lang::Ko,
        };
        links.deps("usr/bin/node", &mut BTreeSet::new(), 0)
    };
    let (mode, found, complete) = deps(&fs);
    assert_eq!(
        (mode, complete, found.len()),
        (DependencyMode::Shared, true, 1),
        "{found:#?}"
    );
    assert_eq!(found[0].path, "/usr/lib32/libbrotlidec.so.1");
    assert_eq!(found[0].architecture, "i386");
    put(&mut fs, "usr/lib/libbrotlidec.so.1", elf32(&[]));
    let (_, _, complete) = deps(&fs);
    assert!(!complete, "같은 ABI 의 라이브러리 둘을 하나로 정했다");
}

/// `TestLegacyUbuntuPHPBackportsUseFinalImagePackageFiles` — 내장 기준(`RuleSet::builtin`)으로 본다.
#[test]
fn legacy_ubuntu_php_backports_use_final_image_package_files() {
    let releases = [
        (
            "14.04",
            "php5",
            "5.5.9",
            "5.5.9+dfsg-1ubuntu4.29+esm17",
            "5.5.9+dfsg-1ubuntu4.29+esm18",
        ),
        (
            "16.04",
            "php7.0",
            "7.0.33",
            "7.0.33-0ubuntu0.16.04.16+esm21",
            "7.0.33-0ubuntu0.16.04.16+esm22",
        ),
        (
            "18.04",
            "php7.2",
            "7.2.24",
            "7.2.24-0ubuntu0.18.04.17+esm13",
            "7.2.24-0ubuntu0.18.04.17+esm14",
        ),
        (
            "20.04",
            "php7.4",
            "7.4.3",
            "7.4.3-4ubuntu2.29+esm4",
            "7.4.3-4ubuntu2.29+esm5",
        ),
    ];
    for (release, prefix, core, before, fixed) in releases {
        let runtimes = [
            (format!("{prefix}-cli"), format!("usr/bin/{prefix}")),
            (format!("{prefix}-fpm"), format!("usr/sbin/{prefix}-fpm")),
            (format!("{prefix}-cgi"), format!("usr/bin/{prefix}-cgi")),
            (
                format!("libapache2-mod-{prefix}"),
                format!("usr/lib/apache2/modules/lib{prefix}.so"),
            ),
        ];
        let suffixed = format!("{fixed}+ppa1");
        let cases = [
            ("before_fix", before, UBUNTU_MAINTAINER, Vulnerable),
            ("fixed", fixed, UBUNTU_MAINTAINER, Clear),
            (
                "unknown_supplier",
                fixed,
                "Custom Builder <builder@example.invalid>",
                Review,
            ),
            (
                "unknown_suffix",
                suffixed.as_str(),
                UBUNTU_MAINTAINER,
                Review,
            ),
        ];
        for (pkg, file) in &runtimes {
            for (case, version, maintainer, want) in cases {
                let name = format!("{release}/{pkg}/{case}");
                let owned = (pkg.as_str(), file.as_str());
                backport_case(&name, (release, core), owned, (version, maintainer), want);
            }
        }
    }
}

fn backport_case(
    name: &str,
    os: (&str, &str),
    owned: (&str, &str),
    record: (&str, &str),
    want: Status,
) {
    let ((release, core), (pkg, file), (version, maintainer)) = (os, owned, record);
    let mut data = elf(&[]);
    data[2048..].fill(0);
    let text = format!("\0PHP/{core}\0");
    data[2048..2048 + text.len()].copy_from_slice(text.as_bytes());
    let entries = [
        reg("etc/os-release", format!("ID=ubuntu\nVERSION_ID={release}\n")),
        reg(
            "var/lib/dpkg/status",
            format!("Package: {pkg}\nStatus: install ok installed\nVersion: {version}\nMaintainer: {maintainer}\n\n"),
        ),
        reg(&format!("var/lib/dpkg/info/{pkg}.list"), format!("/{file}\n")),
        checksum(pkg, file, &data),
        reg(file, &data),
    ];
    let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
    let targets = run(dir.path(), &[Product::Php], RuleSet::builtin());
    assert_eq!(targets.len(), 1, "{name}");
    let found = runtime(&targets[0]);
    assert_eq!(found.len(), 1, "{name}: {:#?}", targets[0]);
    assert_eq!(found[0].status, want, "{name}: {:#?}", found[0]);
    assert_eq!(
        found[0].path.as_deref(),
        Some(format!("/{file}").as_str()),
        "{name}"
    );
    if !name.ends_with("unknown_supplier") {
        assert_eq!(found[0].package.as_deref(), Some(pkg), "{name}");
    }
    let target_want = if want == Vulnerable {
        Vulnerable
    } else {
        Review
    };
    assert_eq!(targets[0].status, target_want, "{name}");
}

/// Windows 이미지의 OCI 폴더 — 레이어마다 raw tar.
fn windows_oci(layers: &[Vec<u8>]) -> Scratch {
    let dir = scratch();
    write(
        dir.path(),
        "oci-layout",
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    );
    let diffs: Vec<String> = layers.iter().map(|l| sha(l)).collect();
    let descs: Vec<_> = layers
        .iter()
        .map(|l| blob(dir.path(), l, RAW_LAYER))
        .collect();
    let cfg = json!({"os": "windows", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": diffs}});
    let config = blob(dir.path(), &bytes(&cfg), OCI_CONFIG);
    let manifest =
        json!({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": config, "layers": descs});
    let mut d = blob(dir.path(), &bytes(&manifest), OCI_MANIFEST);
    d["platform"] = json!({"os": "windows", "architecture": "amd64"});
    write_index(dir.path(), &[d]);
    dir
}

/// `TestWindowsImagePHPCoreUsesFinalLayerHash` — 대소문자를 가리지 않는 이름 · 화이트아웃.
#[test]
fn windows_image_php_core_uses_final_layer_hash() {
    let (old, fixed) = (php_core_pe("8.3.35"), php_core_pe("8.3.36"));
    let rules = php_hash_rules(&old, &fixed);
    let custom = [fixed.as_slice(), b"custom"].concat();
    let cases: [(&str, &str, Vec<Item>, Option<Status>); 6] = [
        ("vulnerable_core", "php8.dll", vec![], Some(Vulnerable)),
        (
            "vulnerable_thread_safe_core",
            "php8ts.dll",
            vec![],
            Some(Vulnerable),
        ),
        (
            "patched_upper_layer",
            "php8.dll",
            vec![reg("Files/PHP/php8.dll", &fixed)],
            Some(Clear),
        ),
        (
            "patched_upper_layer_case_change",
            "php8.dll",
            vec![reg("FILES/php/PHP8.DLL", &fixed)],
            Some(Clear),
        ),
        (
            "deleted_with_different_case",
            "php8.dll",
            vec![reg("files/php/.wh.PHP8.DLL", "")],
            None,
        ),
        (
            "unknown_build",
            "php8.dll",
            vec![reg("Files/PHP/php8.dll", &custom)],
            Some(Review),
        ),
    ];
    for (name, file, upper, want) in cases {
        let mut layers = vec![tar(&[reg(&format!("Files/PHP/{file}"), &old)])];
        if !upper.is_empty() {
            layers.push(tar(&upper));
        }
        let dir = windows_oci(&layers);
        let targets = run(dir.path(), &[Product::Php], &rules);
        assert_eq!(targets.len(), 1, "{name}");
        let found = runtime(&targets[0]);
        let Some(want) = want else {
            assert!(
                found.is_empty() && targets[0].status != Vulnerable,
                "{name}: {:#?}",
                targets[0]
            );
            continue;
        };
        assert_eq!(found.len(), 1, "{name}: {:#?} {:?}", found, targets[0].gaps);
        assert_eq!(found[0].status, want, "{name}: {:#?}", found[0]);
        assert!(
            want != Vulnerable || targets[0].status == Vulnerable,
            "{name}: 취약 DLL 이 가려졌다"
        );
    }
}

/// `TestReviewImageUnsupportedImportNeverClaimsPatched` — DT_NEEDED 가 경로이면 연결을 확정하지 않는다.
#[test]
fn review_image_unsupported_import_never_claims_patched() {
    for needed in ["libbrotlidec.so.1", "/usr/lib/libbrotlidec.so.1"] {
        let mut fs = RootFs::default();
        put(&mut fs, "usr/bin/node", elf(&[needed]));
        put(&mut fs, "usr/lib/libbrotlidec.so.1", elf(&[]));
        let mut owners = Owners::default();
        let owner = Owner {
            name: "libbrotli1".into(),
            version: "1.2.0-1ubuntu0.24.04.0".into(),
            source: "independent package fixture".into(),
            trusted: true,
            ..Owner::default()
        };
        owners
            .by_file
            .insert("usr/lib/libbrotlidec.so.1".into(), owner);
        let links = Links {
            fs: &fs,
            owners: &owners,
            os: ("ubuntu", "24.04"),
            lang: Lang::Ko,
        };
        let (mode, deps, complete) = links.deps("usr/bin/node", &mut BTreeSet::new(), 0);
        let mut c = Component::new(Product::Node);
        (c.dependency_mode, c.dependencies, c.dependencies_complete) =
            (mode, deps.clone(), complete);
        let f = node_rules(None).evaluate(&c, Lang::Ko);
        if needed != "libbrotlidec.so.1" {
            assert!(
                !complete && f.status == Review,
                "{needed}: {f:#?} complete={complete}"
            );
            continue;
        }
        assert_eq!(
            (mode, complete, deps.len()),
            (DependencyMode::Shared, true, 1),
            "{deps:#?}"
        );
        assert_eq!(f.status, Vulnerable, "{f:#?}");
    }
}
