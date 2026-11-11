//! 스캐너 `node_test.go` — 제품 고르기 · 해시 · 공유 Brotli · 로더. `TestStaticELFDependenciesRequireCompleteDynamicData`
//! 는 `scan::binary` 에 있다.

use super::fixtures::*;
use crate::scan::binary::inspect_node_binary;
use crate::scan::image::node::{self, Links, Owner, Owners};
use crate::scan::image::rootfs::RootFs;
use crate::scan::image::Cx;
use crate::scan::model::{Product, Status, Target, TargetKind};
use crate::scan::rules::DependencyMode;
use remedy_sdk::i18n::Lang;
use std::collections::BTreeSet;
use Packing::Raw;
use Status::{Clear, ReviewRequired as Review, Vulnerable};

/// `TestImageProductSelectionAndUnknownNodeDoNotChangePHPCoverage`
#[test]
fn image_product_selection_and_unknown_node_do_not_change_php_coverage() {
    let mut entries = php_entries(FIXED);
    entries.push(reg("usr/local/bin/node", elf(&[])));
    let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
    let rules = node_rules(None);
    let targets = run(dir.path(), &PN, &rules);
    single(&targets, Review);
    let t = &targets[0];
    assert_eq!(t.products[&Product::Php].status, Review);
    assert_eq!(t.products[&Product::Node].status, Review);
    let found = runtime(t);
    assert_eq!(found.len(), 2, "{:#?}", t.findings);
    for f in found {
        match f.product {
            Product::Node => assert_eq!(f.id, format!("node:{}:usr/local/bin/node", t.id)),
            Product::Php => assert_eq!(f.id, format!("{}:usr/bin/php8.3", t.id)),
            Product::Brotli => panic!("{f:#?}"),
        }
    }
    let only = run(dir.path(), &[Product::Node], &rules);
    assert_eq!(only[0].products.len(), 1, "{:#?}", only[0]);
    assert_eq!(only[0].findings.len(), 1, "{:#?}", only[0]);
    assert_eq!(only[0].findings[0].product, Product::Node);
}

/// `TestNodeHashIncludesBytesAfterCapturedPrefix`
#[test]
fn node_hash_includes_bytes_after_captured_prefix() {
    let mut data = elf(&[]);
    data.resize(data.len() + (8 << 20) + 512, b'x');
    let dynamic = (8 << 20) + 128;
    data.copy_within(256..304, dynamic);
    data[128..136].copy_from_slice(&(dynamic as u64).to_le_bytes());
    let len = data.len() as u64;
    data[96..104].copy_from_slice(&len.to_le_bytes());
    *data.last_mut().unwrap() = b'z';
    assert!(!inspect_node_binary(&data[..8 << 20], len).dependencies_complete);
    let entries = [
        reg("etc/os-release", "ID=ubuntu\nVERSION_ID=24.04\n"),
        reg("var/lib/dpkg/status", ""),
        reg("usr/local/bin/node", &data),
    ];
    let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
    let targets = run(dir.path(), &[Product::Node], &node_rules(Some(&data)));
    single(&targets, Clear);
    let found = runtime(&targets[0]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].product, Product::Node);
}

fn deps(
    fs: &RootFs,
    owners: &Owners,
) -> (DependencyMode, Vec<crate::scan::rules::Component>, bool) {
    let links = Links {
        fs,
        owners,
        os: ("ubuntu", "24.04"),
        lang: Lang::Ko,
    };
    links.deps("usr/bin/node", &mut BTreeSet::new(), 0)
}

/// `TestSharedNodeRequiresActualFinalLinkedBrotli`
#[test]
fn shared_node_requires_actual_final_linked_brotli() {
    let mut fs = RootFs::default();
    put(&mut fs, "usr/bin/node", elf(&["libnode.so.115"]));
    put(
        &mut fs,
        "usr/lib/libnode.so.115",
        elf(&["libbrotlidec.so.1"]),
    );
    put(&mut fs, "usr/lib/libbrotlidec.so.1", elf(&["libc.so.6"]));
    let mut owners = Owners::default();
    let owner = Owner {
        name: "libbrotli1".into(),
        version: "1.2.0-1".into(),
        source: "/var/lib/dpkg/status".into(),
        trusted: true,
        ..Owner::default()
    };
    owners
        .by_file
        .insert("usr/lib/libbrotlidec.so.1".into(), owner);
    let (mode, found, complete) = deps(&fs, &owners);
    assert_eq!(
        (mode, complete, found.len()),
        (DependencyMode::Shared, true, 1),
        "{found:#?}"
    );
    assert_eq!(found[0].package, "libbrotli1");
    assert_eq!(found[0].path, "/usr/lib/libbrotlidec.so.1");
    put(
        &mut fs,
        "usr/bin/node",
        elf(&["libnode.so.999", "libbrotlidec.so.1"]),
    );
    let (mode, found, complete) = deps(&fs, &owners);
    assert_eq!(
        (mode, complete, found.len()),
        (DependencyMode::Shared, false, 1),
        "{found:#?}"
    );
    put(&mut fs, "usr/bin/node", elf(&["libnode.so.115"]));
    fs.entries.remove("usr/lib/libbrotlidec.so.1");
    let (mode, _, complete) = deps(&fs, &owners);
    assert_eq!((mode, complete), (DependencyMode::Shared, false));
}

/// `TestNodeWhiteoutAndOverrideUseFinalFileHash` — 스캐너는 덮인 아래 파일의 해시 판정 글(`포함된 버전`)이 없는지
/// 보았다. 여기서는 그 판정이면 양호가 되므로 판정이 *확인 필요* 인지 본다.
#[test]
fn node_whiteout_and_override_use_final_file_hash() {
    let lower_node = elf(&[]);
    let mut upper_node = lower_node.clone();
    upper_node[2048..2058].copy_from_slice(b"\x00v22.98.0\x00");
    let lower = [
        reg("etc/os-release", "ID=ubuntu\nVERSION_ID=24.04\n"),
        reg("var/lib/dpkg/status", ""),
        reg("usr/local/bin/node", &lower_node),
    ];
    for deleted in [false, true] {
        let mut upper = vec![reg("usr/local/bin/.wh.node", "")];
        if !deleted {
            upper.push(reg("usr/local/bin/node", &upper_node));
        }
        let (dir, _) = oci(&[tar(&lower), tar(&upper)], Raw, &[]);
        let targets = run(dir.path(), &[Product::Node], &node_rules(Some(&lower_node)));
        let found = runtime(&targets[0]);
        if deleted {
            single(&targets, Clear);
            assert!(found.is_empty(), "{found:#?}");
        } else {
            single(&targets, Review);
            assert_eq!(found.len(), 1, "{found:#?}");
            assert_eq!(found[0].status, Review, "{found:#?}");
        }
    }
}

/// `TestNodeImageSharedBrotliUsesConnectedPackageVerdict`
#[test]
fn node_image_shared_brotli_uses_connected_package_verdict() {
    for version in ["1.2.0-1ubuntu0.24.04.0", "1.2.0-1ubuntu0.24.04.1"] {
        let entries = shared_entries(&["libbrotlidec.so.1"], version);
        let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
        let targets = run(dir.path(), &[Product::Node], &node_rules(None));
        let want = if version.ends_with(".0") {
            Vulnerable
        } else {
            Clear
        };
        single(&targets, want);
        let found = runtime(&targets[0]);
        assert_eq!(found.len(), 1, "{version}: {found:#?}");
        assert_eq!(found[0].status, want);
    }
}

/// `TestKnownNodeHashKeepsExplicitSharedAndLoaderGaps`
#[test]
fn known_node_hash_keeps_explicit_shared_and_loader_gaps() {
    for loader_override in [false, true] {
        let body = if loader_override {
            elf(&[])
        } else {
            elf(&["libbrotlidec.so.1"])
        };
        let mut fs = RootFs {
            loader_override,
            ..RootFs::default()
        };
        put(&mut fs, "usr/bin/node", body.clone());
        let mut t = Target::new(
            "known-hash",
            TargetKind::Image,
            "known-hash",
            &[Product::Node],
        );
        let (rules, b) = (node_rules(Some(&body)), budget());
        let cx = Cx {
            budget: &b,
            rules: &rules,
            lang: Lang::Ko,
            products: &[Product::Node],
        };
        node::inspect(&fs, &mut t, &cx, &[], ("ubuntu", "24.04"));
        t.finalize(Lang::Ko);
        assert_eq!(t.status, Review, "{loader_override}: {t:#?}");
        assert!(
            !t.products[&Product::Node].gaps.is_empty(),
            "{loader_override}: {t:#?}"
        );
    }
}
