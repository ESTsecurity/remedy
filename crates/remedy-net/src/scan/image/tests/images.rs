//! 스캐너 `images_test.go` — 레이아웃 · 압축 · 화이트아웃 · 손상 · 한도.

use super::fixtures::*;
use crate::scan::budget::{Budget, Cancel, IMAGE_LIMIT, MAX_ENTRIES, MAX_LAYERS};
use crate::scan::image::packages::parse_apk;
use crate::scan::model::{Product, Status, TargetKind};
use remedy_sdk::i18n::Lang;
use serde_json::{json, Value};
use Packing::{Gzip, Raw, Zstd};
use Status::{Clear, ReviewRequired as Review, Vulnerable};

/// `TestOCILayoutCompressionAndPackageVerdict`
#[test]
fn oci_layout_compression_and_package_verdict() {
    for packing in [Raw, Gzip, Zstd] {
        let (dir, _) = oci(&[tar(&php_entries(FIXED))], packing, &[]);
        let targets = php_scan(dir.path());
        single(&targets, Review);
        let found = runtime(&targets[0]);
        assert_eq!(found.len(), 1, "{:#?}", targets[0]);
        assert_eq!(found[0].package.as_deref(), Some("php8.3-cli"));
        assert_eq!(found[0].status, Clear);
    }
    let (dir, _) = oci(&[tar(&php_entries(BEFORE))], Gzip, &[]);
    single(&php_scan(dir.path()), Vulnerable);
}

/// `TestWhiteoutOrderAndOpaqueUseFinalFilesystem`
#[test]
fn whiteout_order_and_opaque_use_final_filesystem() {
    for opaque in [false, true] {
        for marker_first in [false, true] {
            let mut lower = php_entries(BEFORE);
            if opaque {
                lower.push(reg("usr/bin/php8.2", "\x7fELFPHP 8.2.1"));
            }
            let mut upper = php_entries(FIXED);
            let marker = reg(
                if opaque {
                    "usr/bin/.wh..wh..opq"
                } else {
                    "usr/bin/.wh.php8.3"
                },
                "",
            );
            if marker_first {
                upper.insert(0, marker);
            } else {
                upper.push(marker);
            }
            let (dir, _) = oci(&[tar(&lower), tar(&upper)], Gzip, &[]);
            let targets = php_scan(dir.path());
            single(&targets, Review);
            let found = runtime(&targets[0]);
            assert_eq!(
                found.len(),
                1,
                "opaque {opaque} first {marker_first}: {found:#?}"
            );
            assert_eq!(found[0].version.as_deref(), Some(FIXED));
            assert_eq!(found[0].status, Clear);
        }
    }
}

/// `TestDeletedPHPIsNotReported`
#[test]
fn deleted_php_is_not_reported() {
    let upper = [
        reg("usr/bin/.wh.php8.3", ""),
        reg("var/lib/dpkg/status", ""),
    ];
    let (dir, _) = oci(&[tar(&php_entries(BEFORE)), tar(&upper)], Raw, &[]);
    let targets = php_scan(dir.path());
    single(&targets, Clear);
    assert!(runtime(&targets[0]).is_empty());
}

/// `TestCorruptUpperLayerDiscardsLowerFindings`
#[test]
fn corrupt_upper_layer_discards_lower_findings() {
    let (dir, layers) = oci(
        &[tar(&php_entries(BEFORE)), tar(&php_entries(FIXED))],
        Raw,
        &[],
    );
    let path = blob_path(dir.path(), layers[1]["digest"].as_str().unwrap());
    let mut data = std::fs::read(&path).unwrap();
    *data.last_mut().unwrap() = 1;
    std::fs::write(&path, data).unwrap();
    let targets = php_scan(dir.path());
    single(&targets, Review);
    assert!(runtime(&targets[0]).is_empty(), "{:#?}", targets[0]);
}

fn read_index(dir: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap()
}

/// `TestMetadataDigestAndPlatformMismatch`
#[test]
fn metadata_digest_and_platform_mismatch() {
    let (dir, _) = oci(&[tar(&php_entries(FIXED))], Raw, &[]);
    let mut index = read_index(dir.path());
    index["manifests"][0]["platform"]["architecture"] = json!("arm64");
    write(dir.path(), "index.json", &bytes(&index));
    single(&php_scan(dir.path()), Review);
    index["manifests"][0]["platform"]["architecture"] = json!("amd64");
    write(dir.path(), "index.json", &bytes(&index));
    let path = blob_path(
        dir.path(),
        index["manifests"][0]["digest"].as_str().unwrap(),
    );
    let mut blob = std::fs::read(&path).unwrap();
    *blob.last_mut().unwrap() = b' ';
    std::fs::write(&path, blob).unwrap();
    single(&php_scan(dir.path()), Review);
}

/// `TestMultiPlatformScansEachExplicitImage`
#[test]
fn multi_platform_scans_each_explicit_image() {
    let (dir, _) = oci(&[tar(&php_entries(FIXED))], Gzip, &["amd64", "arm64"]);
    let b = budget();
    let targets = run_with(dir.path(), &[Product::Php], &php_rules(), &b);
    assert_eq!(targets.len(), 2, "{targets:#?}");
    assert!(targets.iter().all(|t| t.status == Review));
    assert_ne!(
        targets[0].metadata["platform"],
        targets[1].metadata["platform"]
    );
    assert_eq!(b.usage().layers, 2);
}

/// `TestArchiveAndDockerSaveGzip`
#[test]
fn archive_and_docker_save_gzip() {
    let layer = tar(&php_entries(FIXED));
    let cfg = bytes(
        &json!({"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": [sha(&layer)]}}),
    );
    let config_name = format!("{}.json", &sha(&cfg)[7..]);
    let manifest = bytes(
        &json!([{"Config": config_name, "RepoTags": ["synthetic:test"], "Layers": ["layer/layer.tar"]}]),
    );
    let outer = tar(&[
        reg("layer/layer.tar", &layer),
        reg(&config_name, &cfg),
        reg("manifest.json", &manifest),
    ]);
    let compressed = gzip(&outer);
    let dir = scratch();
    write(dir.path(), "image.tar.gz", &compressed);
    let b = budget();
    let targets = run_with(&dir.join("image.tar.gz"), &[Product::Php], &php_rules(), &b);
    single(&targets, Review);
    assert_eq!(targets[0].metadata["reference"], "synthetic:test");
    let want = (compressed.len() + layer.len() + cfg.len() + manifest.len()) as u64;
    assert_eq!(b.usage().image_input_bytes, want, "{:?}", b.usage());
    // 같은 이미지를 OCI tar 아카이브로 — 이것도 불투명한 블롭 저장소에만 푼다.
    let (layout, _) = oci(&[layer], Gzip, &[]);
    let mut items = Vec::new();
    collect(layout.path(), layout.path(), &mut items);
    write(dir.path(), "oci.tar", &tar(&items));
    single(&php_scan(&dir.join("oci.tar")), Review);
}

fn collect(root: &std::path::Path, dir: &std::path::Path, items: &mut Vec<Item>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(root, &path, items);
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        items.push(reg(&rel, std::fs::read(&path).unwrap()));
    }
}

/// `TestUnsafeAndMalformedLayersAreRejected`
#[test]
fn unsafe_and_malformed_layers_are_rejected() {
    let mut huge = reg("huge", "");
    huge.size = Some(IMAGE_LIMIT + 1);
    let cases: Vec<(&str, Vec<Item>)> = vec![
        ("traversal", vec![reg("../escape", "x")]),
        ("absolute", vec![reg("/escape", "x")]),
        ("drive", vec![reg("C:/escape", "x")]),
        ("symlink_escape", vec![kind("link", b'2', "../escape")]),
        (
            "hardlink_cycle",
            vec![kind("a", b'1', "b"), kind("b", b'1', "a")],
        ),
        ("device", vec![kind("dev/example", b'3', "")]),
        ("malformed_size", vec![huge]),
        (
            "symlink_parent",
            vec![kind("dir", b'2', "other"), reg("dir/php", "x")],
        ),
    ];
    for (name, items) in cases {
        let (dir, _) = oci(&[tar(&items)], Raw, &[]);
        let targets = php_scan(dir.path());
        single(&targets, Review);
        assert!(
            targets[0].gaps.iter().any(|g| g.starts_with("레이어 ")),
            "{name}: {:?}",
            targets[0].gaps
        );
    }
}

/// `TestLimitsAndCancellationCannotBecomeClear`
#[test]
fn limits_and_cancellation_cannot_become_clear() {
    let (dir, _) = oci(&[tar(&php_entries(FIXED))], Raw, &[]);
    for kind in ["layers", "entries", "cancel"] {
        let cancel = Cancel::default();
        let b = Budget::new(TargetKind::Image, cancel.clone(), Lang::Ko);
        match kind {
            "layers" => (0..MAX_LAYERS).for_each(|_| b.count_layer().unwrap()),
            "entries" => (0..MAX_ENTRIES).for_each(|_| b.count_entry().unwrap()),
            _ => cancel.set(),
        }
        let targets = run_with(dir.path(), &[Product::Php], &php_rules(), &b);
        single(&targets, Review);
    }
}

/// `TestBinaryStringsAndUnownedPackageAreNotTrusted`
#[test]
fn binary_strings_and_unowned_package_are_not_trusted() {
    let mut items = php_entries(FIXED);
    items[2].body = b"/usr/bin/unrelated\n".to_vec();
    items.last_mut().unwrap().body = b"\x7fELF\x00PHP 8.3.36\x00".to_vec();
    let (dir, _) = oci(&[tar(&items)], Raw, &[]);
    let targets = php_scan(dir.path());
    single(&targets, Review);
    let found = runtime(&targets[0]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].status, Review);
}

/// `TestAPKPackageFilesAndTraversal`
#[test]
fn apk_package_files_and_traversal() {
    let packages = parse_apk(b"P:php83\nV:8.3.36-r0\nF:usr/bin\nR:php83\n\n", Lang::Ko).unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].files, ["usr/bin/php83"]);
    assert!(!packages[0].trusted);
    assert!(parse_apk(b"P:php83\nV:8.3.36-r0\nF:usr/bin\nR:..\n", Lang::Ko).is_err());
}
