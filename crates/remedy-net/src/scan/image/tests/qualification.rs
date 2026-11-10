//! 스캐너 `qualification_test.go` — 패키지 무결성 · 문서 자리 · 최종 레이어 · 공유 Brotli · 압축.

use super::fixtures::*;
use crate::scan::model::{Product, Status};
use serde_json::json;
use Packing::{Gzip, Raw, Zstd};
use Status::{Clear, ReviewRequired as Review, Vulnerable};

fn php(version: &str, package_version: &str) -> Vec<Item> {
    qualification_php(version, package_version, UBUNTU_MAINTAINER)
}

/// 같은 길이의 바이트열을 모두 바꾼다.
fn replace_all(data: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut i = 0;
    while i + from.len() <= out.len() {
        if &out[i..i + from.len()] == from {
            out[i..i + from.len()].copy_from_slice(to);
            i += from.len();
        } else {
            i += 1;
        }
    }
    out
}

/// `TestQualificationPackageIntegrityFailuresHaveDistinctReasons` — 스캐너의 `dpkg 필드 형식 오류` 는 이 크레이트의
/// `dpkg 필드 형식이 잘못됐습니다` 로, `패키지 DB를` 은 띄어 쓴 `패키지 DB 를` 로 본다.
#[test]
fn qualification_package_integrity_failures_have_distinct_reasons() {
    type Mutate = fn(&mut Vec<Item>);
    let cases: [(&str, &str, Mutate); 9] = [
        (
            "missing_database",
            "패키지 DB 를 찾지 못했습니다",
            |es| drop(es.remove(1)),
        ),
        (
            "damaged_database",
            "dpkg 필드 형식이 잘못됐습니다",
            |es| es[1].body = b"not a package database".to_vec(),
        ),
        (
            "missing_file_list",
            "파일 목록(.list)이 없습니다",
            |es| drop(es.remove(2)),
        ),
        ("damaged_file_list", "상위 경로", |es| {
            es[2].body = b"../../outside/php\n".to_vec()
        }),
        (
            "missing_checksums",
            "파일 검증 기록(.md5sums)이 없습니다",
            |es| drop(es.remove(3)),
        ),
        (
            "empty_checksum_file",
            "실행 파일 경로가 없습니다",
            |es| es[3].body.clear(),
        ),
        (
            "damaged_checksum_file",
            "형식이 잘못됐습니다",
            |es| es[3].body = b"not a checksum".to_vec(),
        ),
        ("conflicting_checksum_records", "서로 다릅니다", |es| {
            let line = format!("{}  usr/bin/php8.3\n", "0".repeat(32));
            es[3].body.extend_from_slice(line.as_bytes());
        }),
        (
            "runtime_changed_without_version_change",
            "실제 파일 내용이 일치하지 않습니다",
            |es| es[4].body[3000] ^= 1,
        ),
    ];
    for (name, reason, mutate) in cases {
        let mut entries = php("8.3.6", FIXED);
        mutate(&mut entries);
        let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
        let targets = php_scan(dir.path());
        single(&targets, Review);
        let found = gaps(&targets[0], Product::Php);
        assert!(found.contains(reason), "{name}: {reason:?} 없음\n{found}");
    }
}

/// `TestQualificationPackageDocumentationDoesNotBecomeRuntime`
#[test]
fn qualification_package_documentation_does_not_become_runtime() {
    let node = elf(&[]);
    let mut fixed = node.clone();
    fixed.push(b'f');
    let rules = qualification_rules(&node, &fixed);
    for executable_in_docs in [false, true] {
        let mut entries = php("8.3.6", FIXED);
        entries[2]
            .body
            .extend_from_slice(b"/usr/share/lintian/overrides/php8.3-cli\n");
        entries.extend([
            reg(
                "usr/share/lintian/overrides/php8.3-cli",
                "php8.3-cli: hardening-no-bindnow\n",
            ),
            reg(
                "usr/share/lintian/overrides/nodejs",
                "nodejs: custom-library-search-path\n",
            ),
            reg("usr/share/doc/node", "Node.js package documentation\n"),
            reg("usr/share/man/php", "manual page\n"),
            reg("etc/cron.d/php", "# PHP session cleanup\n"),
            reg("var/lib/apache2/module/enabled_by_admin/php", ""),
            reg(
                "var/lib/dpkg/alternatives/php",
                "auto\n/usr/bin/php\n\n/usr/bin/php8.3\n83\n",
            ),
            kind("usr/share/doc/php-common", b'5', ""),
            kind("usr/share/doc/php8.3-cli", b'2', "php-common"),
        ]);
        if executable_in_docs {
            entries.push(reg("usr/share/doc/tool/node", &node));
        }
        let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
        let targets = run(dir.path(), &PN, &rules);
        single(
            &targets,
            if executable_in_docs {
                Vulnerable
            } else {
                Review
            },
        );
        let count = runtime(&targets[0]).len();
        assert_eq!(
            count,
            1 + usize::from(executable_in_docs),
            "{:#?}",
            targets[0]
        );
    }
}

/// `TestQualificationDocumentationExclusionRequiresCompletePlainText`
#[test]
fn qualification_documentation_exclusion_requires_complete_plain_text() {
    let node = elf(&[]);
    let mut fixed = node.clone();
    fixed.push(b'f');
    let rules = qualification_rules(&node, &fixed);
    let damaged = with(node.clone(), 0, node[0] ^ 1);
    let cases: Vec<(&str, Vec<u8>, u32, Status)> = vec![
        (
            "ordinary_description",
            b"Node.js package notes\n".to_vec(),
            0o644,
            Clear,
        ),
        (
            "executable_shell_wrapper",
            b"#!/bin/sh\nexec /opt/runtime/node \"$@\"\n".to_vec(),
            0o755,
            Review,
        ),
        (
            "nonexecutable_shebang",
            b"#!/bin/sh\nexec /opt/runtime/node\n".to_vec(),
            0o644,
            Review,
        ),
        ("damaged_magic", damaged, 0o644, Review),
        (
            "binary_NUL",
            b"notes\x00hidden binary".to_vec(),
            0o644,
            Review,
        ),
        (
            "invalid_UTF8",
            vec![b'n', b'o', b'd', b'e', 0xff],
            0o644,
            Review,
        ),
        ("actual_vulnerable_ELF", node.clone(), 0o755, Vulnerable),
        (
            "uncaptured_text_suffix",
            vec![b'x'; (8 << 20) + 1],
            0o644,
            Review,
        ),
    ];
    for (name, body, m, want) in cases {
        let mut entries = php("8.3.6", FIXED);
        entries.push(mode(reg("usr/share/doc/tool/node", body), m));
        let (dir, _) = oci(&[tar(&entries)], Gzip, &[]);
        let targets = run(dir.path(), &PN, &rules);
        single(&targets, if want == Clear { Review } else { want });
        assert_eq!(
            targets[0].products[&Product::Node].status,
            want,
            "{name}: {:#?}",
            targets[0].products
        );
    }
}

/// `TestQualificationPHPImagePackageCannotHideDamagedOrConflictingBinary`
#[test]
fn qualification_php_image_package_cannot_hide_damaged_or_conflicting_binary() {
    let cases = [
        ("truncated_ELF", "8.3.6", UBUNTU_MAINTAINER, true),
        (
            "different_runtime_version",
            "8.3.1",
            UBUNTU_MAINTAINER,
            false,
        ),
        (
            "custom_package_maintainer",
            "8.3.6",
            "Custom Builder <builder@example.invalid>",
            false,
        ),
    ];
    for (name, version, maintainer, broken) in cases {
        let mut entries = qualification_php(version, FIXED, maintainer);
        if broken {
            entries.last_mut().unwrap().body = b"\x7fELF".to_vec();
        }
        let (dir, _) = oci(&[tar(&entries)], Gzip, &[]);
        let targets = php_scan(dir.path());
        single(&targets, Review);
        let found = runtime(&targets[0]);
        assert_eq!(found.len(), 1, "{name}: {found:#?}");
        assert_eq!(found[0].status, Review, "{name}: {found:#?}");
    }
}

/// `TestQualificationVulnerableNodeRemovedOrOverriddenByFinalLayer`
#[test]
fn qualification_vulnerable_node_removed_or_overridden_by_final_layer() {
    let (before, fixed) = (with(elf(&[]), 3000, b'v'), with(elf(&[]), 3000, b'f'));
    let rules = qualification_rules(&before, &fixed);
    let mut lower = php("8.3.6", FIXED);
    lower.push(reg("opt/app/bin/node", &before));
    let (base, _) = oci(&[tar(&lower)], Raw, &[]);
    let targets = run(base.path(), &PN, &rules);
    single(&targets, Vulnerable);
    assert_eq!(targets[0].products[&Product::Node].status, Vulnerable);
    let cases = [
        (
            "fixed_overwrite",
            vec![reg("opt/app/bin/node", &fixed)],
            false,
        ),
        ("whiteout", vec![reg("opt/app/bin/.wh.node", "")], false),
        (
            "opaque_directory",
            vec![reg("opt/app/bin/.wh..wh..opq", "")],
            false,
        ),
        (
            "damaged_upper_after_fixed",
            vec![reg("opt/app/bin/node", &fixed)],
            true,
        ),
    ];
    for (name, upper, corrupt) in cases {
        let (dir, descs) = oci(&[tar(&lower), tar(&upper)], Gzip, &[]);
        if corrupt {
            let path = blob_path(dir.path(), descs[1]["digest"].as_str().unwrap());
            std::fs::write(path, b"damaged upper layer").unwrap();
        }
        let targets = run(dir.path(), &PN, &rules);
        single(&targets, Review);
        for f in runtime(&targets[0]) {
            assert!(
                f.product != Product::Node || f.status == Clear,
                "{name}: {f:#?}"
            );
        }
        assert!(
            !corrupt || runtime(&targets[0]).is_empty(),
            "{name}: {:#?}",
            targets[0]
        );
    }
}

/// `TestQualificationBothProductsFindIndependentInstallations`
#[test]
fn qualification_both_products_find_independent_installations() {
    let (before, fixed) = (with(elf(&[]), 3000, b'v'), with(elf(&[]), 3000, b'f'));
    let mut entries = php("8.3.6", BEFORE);
    let legacy = replace_all(&entries.last().unwrap().body, b"PHP 8.3.6", b"PHP 8.3.1");
    entries.extend([
        reg("opt/legacy/bin/php", legacy),
        reg("usr/local/bin/node", &fixed),
        reg("opt/legacy/bin/node", &before),
    ]);
    let (dir, _) = oci(&[tar(&entries)], Zstd, &[]);
    let targets = run(dir.path(), &PN, &qualification_rules(&before, &fixed));
    single(&targets, Vulnerable);
    let t = &targets[0];
    let count = |p: Product| runtime(t).iter().filter(|f| f.product == p).count();
    assert_eq!(
        (count(Product::Php), count(Product::Node)),
        (2, 2),
        "{t:#?}"
    );
    assert_eq!(t.products[&Product::Php].status, Vulnerable);
    assert_eq!(t.products[&Product::Node].status, Vulnerable);
}

/// `TestQualificationNodeLinksRemainVirtualAndRequireEvidence`
#[test]
fn qualification_node_links_remain_virtual_and_require_evidence() {
    let node = elf(&[]);
    let rules = node_rules(Some(&node));
    let cases = [
        (
            "absolute_virtual_symlink",
            kind("usr/local/bin/node", b'2', "/opt/runtime/node"),
            Clear,
        ),
        (
            "hardlink_needs_verification",
            kind("usr/local/bin/node", b'1', "opt/runtime/node"),
            Review,
        ),
        (
            "dangling_symlink",
            kind("usr/local/bin/node", b'2', "/missing/node"),
            Review,
        ),
    ];
    for (name, link, want) in cases {
        let mut entries = php("8.3.6", FIXED);
        entries.push(reg("opt/runtime/node", &node));
        entries.push(link);
        let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
        let targets = run(dir.path(), &[Product::Node], &rules);
        assert_eq!(targets.len(), 1, "{name}");
        assert_eq!(targets[0].status, want, "{name}: {:#?}", targets[0]);
    }
}

/// `TestQualificationSharedBrotliAmbiguityAndIntegrityCannotBecomeClear`
#[test]
fn qualification_shared_brotli_ambiguity_and_integrity_cannot_become_clear() {
    type Mutate = Option<fn(&mut Vec<Item>)>;
    let mut changed = elf(&[]);
    changed.push(b'x');
    let cases: [(&str, Mutate, Vec<Item>); 5] = [
        (
            "same_soname_different_standard_paths",
            Some(|es| {
                es.push(reg(
                    "lib/x86_64-linux-gnu/libbrotlidec.so.1",
                    with(elf(&[]), 3000, b'x'),
                ));
            }),
            vec![],
        ),
        (
            "conflicting_package_owners",
            Some(|es| {
                let extra = format!("Package: brotli-libs\nStatus: install ok installed\nVersion: 1.0.9-1\nMaintainer: {UBUNTU_MAINTAINER}\n\n");
                es[1].body.extend_from_slice(extra.as_bytes());
                let sums = checksum("brotli-libs", "usr/lib/libbrotlidec.so.1", &es[5].body);
                es.push(reg(
                    "var/lib/dpkg/info/brotli-libs.list",
                    "/usr/lib/libbrotlidec.so.1\n",
                ));
                es.push(sums);
            }),
            vec![],
        ),
        (
            "decoder_changed_without_package_change",
            None,
            vec![reg("usr/lib/libbrotlidec.so.1", changed)],
        ),
        (
            "decoder_removed_by_whiteout",
            None,
            vec![reg("usr/lib/.wh.libbrotlidec.so.1", "")],
        ),
        (
            "decoder_is_truncated_ELF",
            None,
            vec![reg("usr/lib/libbrotlidec.so.1", "\x7fELF")],
        ),
    ];
    for (name, mutate, upper) in cases {
        let mut entries = shared_entries(&["libbrotlidec.so.1"], "1.2.0-1ubuntu0.24.04.1");
        if let Some(mutate) = mutate {
            mutate(&mut entries);
        }
        let mut layers = vec![tar(&entries)];
        if !upper.is_empty() {
            layers.push(tar(&upper));
        }
        let (dir, _) = oci(&layers, Gzip, &[]);
        let targets = run(dir.path(), &[Product::Node], &node_rules(None));
        assert_eq!(targets.len(), 1, "{name}");
        assert_eq!(targets[0].status, Review, "{name}: {:#?}", targets[0]);
        for f in runtime(&targets[0]) {
            assert_ne!(f.status, Clear, "{name}: {f:#?}");
        }
    }
}

/// `TestQualificationConfirmedVulnerableSharedBrotliSurvivesOtherMissingDependency`
#[test]
fn qualification_confirmed_vulnerable_shared_brotli_survives_other_missing_dependency() {
    for needed in [
        ["libbrotlidec.so.1", "libnode.so.115"],
        ["libnode.so.115", "libbrotlidec.so.1"],
    ] {
        let entries = shared_entries(&needed, "1.2.0-1ubuntu0.24.04.0");
        let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
        let b = budget();
        let targets = run_with(dir.path(), &[Product::Node], &node_rules(None), &b);
        single(&targets, Vulnerable);
        let partial = b.partial_targets("다른 이미지 수집이 중단됐습니다");
        single(&partial, Vulnerable);
        let found = runtime(&partial[0]);
        assert_eq!(found.len(), 1, "{needed:?}: {found:#?}");
        assert_eq!(found[0].status, Vulnerable);
        assert!(!partial[0].products[&Product::Node].complete, "{needed:?}");
    }
}

/// `TestQualificationOneChangedPackageFileCannotHideOtherVulnerableDecoder`
#[test]
fn qualification_one_changed_package_file_cannot_hide_other_vulnerable_decoder() {
    for bad_first in [true, false] {
        let mut entries = shared_entries(&["libbrotlidec.so.1"], "1.2.0-1ubuntu0.24.04.0");
        let (good, bad) = (
            "/usr/lib/libbrotlidec.so.1\n",
            "/usr/lib/libbrotlidec.so.2\n",
        );
        entries[3].body = if bad_first {
            format!("{bad}{good}")
        } else {
            format!("{good}{bad}")
        }
        .into_bytes();
        let original = elf(&[]);
        let mut changed = original.clone();
        changed.push(b'x');
        entries.push(reg("usr/lib/libbrotlidec.so.2", changed));
        let line = format!("{}  usr/lib/libbrotlidec.so.2\n", md5_hex(&original));
        entries[7].body.extend_from_slice(line.as_bytes());
        let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
        let targets = run(dir.path(), &[Product::Node], &node_rules(None));
        single(&targets, Vulnerable);
        let found = runtime(&targets[0]);
        assert_eq!(found.len(), 1, "{bad_first}: {found:#?}");
        assert_eq!(found[0].status, Vulnerable);
        assert!(gaps(&targets[0], Product::Node).contains("실제 파일 내용이 일치하지 않습니다"));
    }
}

/// 스캐너 `qualificationEncodedLayer` — 레이어 하나를 주어진 바이트 · 형식 · diffID 로.
fn encoded_layer(encoded: &[u8], media: &str, diff: &str) -> Scratch {
    let dir = scratch();
    write(
        dir.path(),
        "oci-layout",
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    );
    let layer = blob(dir.path(), encoded, media);
    let cfg = json!({"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": [diff]}});
    let config = blob(dir.path(), &bytes(&cfg), OCI_CONFIG);
    let manifest =
        json!({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": config, "layers": [layer]});
    let mut d = blob(dir.path(), &bytes(&manifest), OCI_MANIFEST);
    d["platform"] = json!({"os": "linux", "architecture": "amd64"});
    write_index(dir.path(), &[d]);
    dir
}

/// `TestQualificationCompressionCannotHideIntegrityFailure` — zstd 창 한도의 글은 고정 문장이고 `window` 를 담는다.
#[test]
fn qualification_compression_cannot_hide_integrity_failure() {
    let raw = tar(&php_entries(FIXED));
    let compressed = gzip(&raw);
    let mut bad_crc = compressed.clone();
    let at = bad_crc.len() - 8;
    bad_crc[at] ^= 1;
    let gz = format!("{RAW_LAYER}+gzip");
    let zst = format!("{RAW_LAYER}+zstd");
    let twice = [raw.clone(), raw.clone()].concat();
    let cases: [(&str, &str, String, Vec<u8>, bool); 4] = [
        (
            "valid_TAR_then_gzip_checksum_failure",
            &gz,
            sha(&raw),
            bad_crc,
            false,
        ),
        (
            "second_TAR_in_concatenated_gzip",
            &gz,
            sha(&twice),
            [compressed.clone(), compressed.clone()].concat(),
            false,
        ),
        (
            "declared_gzip_contains_raw_TAR",
            &gz,
            sha(&raw),
            raw.clone(),
            true,
        ),
        (
            "zstd_window_above_64MiB",
            &zst,
            sha(&[]),
            vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x88, 1, 0, 0],
            true,
        ),
    ];
    for (name, media, diff, encoded, want_expanded_zero) in cases {
        let input = encoded_layer(&encoded, media, &diff);
        let b = budget();
        let targets = run_with(input.path(), &[Product::Php], &php_rules(), &b);
        single(&targets, Review);
        assert!(runtime(&targets[0]).is_empty(), "{name}: {:#?}", targets[0]);
        if want_expanded_zero {
            assert_eq!(b.usage().image_expanded_bytes, 0, "{name}");
        }
        if name == "zstd_window_above_64MiB" {
            assert!(
                targets[0].gaps.join("\n").contains("window"),
                "{name}: {:?}",
                targets[0].gaps
            );
        }
    }
}
