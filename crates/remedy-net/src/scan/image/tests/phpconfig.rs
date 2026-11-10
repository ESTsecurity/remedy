//! 스캐너 `phpconfig_test.go` — 이미지의 PHP 세션 설정과 그 수집 한도.

use super::fixtures::*;
use crate::scan::image::config::{CONFIG_DATA_LIMIT, CONFIG_FILE_LIMIT, MAX_CONFIG_FILES};
use crate::scan::image::layer::{self, LayerSpec};
use crate::scan::image::meta::digest_path;
use crate::scan::image::rootfs::{RootFs, SELECTED_DATA_LIMIT};
use crate::scan::image::source::Source;
use crate::scan::image::Cx;
use crate::scan::model::{Finding, Product, Status};
use crate::scan::phpconfig::CVE;
use remedy_sdk::i18n::Lang;
use serde_json::Value;
use std::path::Path;
use Packing::Raw;
use Status::{Clear, ReviewRequired as Review, Vulnerable};

/// 근거 가운데 `source` 가 맞는 줄의 글을 잇는다.
fn evidence(f: &Finding, pick: impl Fn(&str) -> bool) -> String {
    f.evidence
        .iter()
        .filter(|e| pick(&e.source))
        .map(|e| e.detail.as_str())
        .collect()
}

/// `TestPHPImageConfigurationUsesFinalLayersAndPreservesVersionVerdict`
#[test]
fn php_image_configuration_uses_final_layers_and_preserves_version_verdict() {
    let cases = [
        ("off", "session.upload_progress.enabled=Off", vec![]),
        (
            "overwrite_on",
            "session.upload_progress.enabled=On",
            vec![reg(
                "usr/local/etc/php/php.ini",
                "session.upload_progress.enabled=On\nsession.serialize_handler=php",
            )],
        ),
        (
            "whiteout",
            "설정 미확인",
            vec![reg("usr/local/etc/php/.wh.php.ini", "")],
        ),
        (
            "opaque",
            "설정 미확인",
            vec![reg("usr/local/etc/php/.wh..wh..opq", "")],
        ),
    ];
    for (name, want, upper) in cases {
        let mut lower = php_entries(FIXED);
        lower.push(reg(
            "usr/local/etc/php/php.ini",
            "session.upload_progress.enabled=Off\nsession.serialize_handler=php_serialize\npassword=PRIVATE_IMAGE_SENTINEL",
        ));
        let mut layers = vec![tar(&lower)];
        if !upper.is_empty() {
            layers.push(tar(&upper));
        }
        let (dir, _) = oci(&layers, Raw, &[]);
        let targets = php_scan(dir.path());
        single(&targets, Review);
        let t = &targets[0];
        assert_eq!(t.findings.len(), 2, "{name}: {:#?}", t.findings);
        assert_eq!(t.findings[0].status, Clear, "{name}");
        assert_eq!(
            t.findings[0].package.as_deref(),
            Some("php8.3-cli"),
            "{name}"
        );
        let f = &t.findings[1];
        assert_eq!(f.id, format!("{}:{CVE}", t.id));
        assert_eq!(f.status, Review);
        let data = serde_json::to_string(f).unwrap();
        assert!(data.contains(want), "{name}: {data}");
        assert!(!data.contains("PRIVATE_IMAGE_SENTINEL"), "{name}: {data}");
        let file = evidence(f, |s| s == "/usr/local/etc/php/php.ini");
        if matches!(name, "whiteout" | "opaque") {
            assert_eq!(file, "", "{name}: 지운 아래 레이어의 설정이 남았다");
        } else {
            assert!(file.contains(want), "{name}: {file}");
        }
    }
}

/// `TestPHPImageFPMAndApacheConfigurationAndVulnerablePriority`
#[test]
fn php_image_fpm_and_apache_configuration_and_vulnerable_priority() {
    let mut entries = php_entries(BEFORE);
    entries.push(reg(
        "etc/php/8.3/fpm/pool.d/www.conf",
        "[www]\nphp_admin_flag[session.upload_progress.enabled] = Off\n",
    ));
    entries.push(reg(
        "etc/apache2/conf-enabled/php.conf",
        "php_admin_value session.serialize_handler php_serialize\n",
    ));
    let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
    let targets = php_scan(dir.path());
    single(&targets, Vulnerable);
    let t = &targets[0];
    assert_eq!(t.findings.len(), 2, "{:#?}", t.findings);
    assert_eq!(
        (t.findings[0].status, t.findings[1].status),
        (Vulnerable, Review)
    );
    let file = evidence(&t.findings[1], |s| s.starts_with("/etc/"));
    assert!(
        file.contains("session.upload_progress.enabled=Off"),
        "{file}"
    );
    assert!(
        file.contains("session.serialize_handler=php_serialize"),
        "{file}"
    );
}

/// `TestPHPImageConfigurationFileAndAggregateLimits`
#[test]
fn php_image_configuration_file_and_aggregate_limits() {
    let conf = |i: usize, body: Vec<u8>| reg(&format!("etc/php/8.3/conf.d/{i:03}.ini"), body);
    let file = CONFIG_FILE_LIMIT as usize;
    let cases: [(&str, Vec<Item>); 3] = [
        ("file_size", vec![reg("etc/php.ini", vec![b'x'; file + 1])]),
        (
            "file_count",
            (0..=MAX_CONFIG_FILES)
                .map(|i| conf(i, b"session.upload_progress.enabled=Off\n".to_vec()))
                .collect(),
        ),
        (
            "aggregate_size",
            (0..5).map(|i| conf(i, vec![b'x'; file])).collect(),
        ),
    ];
    for (name, extra) in cases {
        let mut entries = php_entries(FIXED);
        entries.extend(extra);
        let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
        let targets = php_scan(dir.path());
        single(&targets, Review);
        let data = serde_json::to_string(&targets[0]).unwrap();
        assert!(
            data.contains("수집 한도"),
            "{name}: 설정 파일 수집 한도 고지가 없다"
        );
    }
}

/// `TestNodeOnlyImageDoesNotCaptureOrAssessPHPConfiguration`
#[test]
fn node_only_image_does_not_capture_or_assess_php_configuration() {
    let entries = [
        reg("etc/php.ini", "session.upload_progress.enabled=On\n"),
        reg("var/lib/dpkg/status", ""),
    ];
    let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
    let targets = run(dir.path(), &[Product::Node], &node_rules(None));
    assert_eq!(targets.len(), 1);
    assert!(targets[0].findings.is_empty(), "{:#?}", targets[0]);
    assert_eq!(targets[0].products.len(), 1);
    assert!(!RootFs::default().selected_config("etc/php.ini", &[Product::Node]));
}

/// 레이어 하나를 이 가상 뿌리에 바로 덮는다(스캐너 시험의 `newSource` + `applyLayer`).
fn apply_one(dir: &Path, d: &Value, raw: &[u8], fs: &mut RootFs, products: &[Product]) {
    let (b, rules) = (budget(), php_rules());
    let cx = Cx {
        budget: &b,
        rules: &rules,
        lang: Lang::Ko,
        products,
    };
    let src = Source::open(&dir.to_string_lossy(), Path::new(""), &b, Lang::Ko).unwrap();
    let digest = d["digest"].as_str().unwrap();
    let spec = LayerSpec {
        name: digest_path(digest, Lang::Ko).unwrap(),
        digest: digest.to_string(),
        media_type: d["mediaType"].as_str().unwrap().to_string(),
        diff_id: sha(raw),
        size: d["size"].as_i64().unwrap(),
    };
    layer::apply(&src, fs, &spec, &cx).unwrap();
}

/// `TestPHPConfigurationQuotaDoesNotConsumeRuntimeCaptureBudget`
#[test]
fn php_configuration_quota_does_not_consume_runtime_capture_budget() {
    let raw = tar(&[
        reg("etc/php.ini", "session.upload_progress.enabled=Off\n"),
        reg("usr/bin/php", elf(&[])),
    ]);
    let (dir, descs) = oci(std::slice::from_ref(&raw), Raw, &[]);
    for configuration_full in [true, false] {
        let mut fs = RootFs::default();
        if configuration_full {
            fs.config_bytes = CONFIG_DATA_LIMIT;
        } else {
            fs.captured = SELECTED_DATA_LIMIT;
        }
        apply_one(dir.path(), &descs[0], &raw, &mut fs, &[Product::Php]);
        let probe = if configuration_full {
            "usr/bin/php"
        } else {
            "etc/php.ini"
        };
        let e = &fs.entries[probe];
        assert!(
            !e.truncated && !e.data.is_empty(),
            "{probe}: 한쪽 한도가 다른 쪽 수집을 막았다"
        );
    }
}

/// `TestEightMiBConfigurationBeforeRuntimePreservesOriginalCapture`
#[test]
fn eight_mib_configuration_before_runtime_preserves_original_capture() {
    let mut binary = vec![0u8; 8 << 20];
    let head = elf(&[]);
    binary[..head.len()].copy_from_slice(&head);
    let config = vec![b' '; CONFIG_FILE_LIMIT as usize];
    for name in ["php", "node"] {
        let path = format!("usr/bin/{name}");
        let raw = tar(&[
            reg("etc/php/8.3/conf.d/00.ini", &config),
            reg("etc/php/8.3/conf.d/01.ini", &config),
            reg(&path, &binary),
        ]);
        let (dir, descs) = oci(std::slice::from_ref(&raw), Raw, &[]);
        let mut fs = RootFs {
            captured: SELECTED_DATA_LIMIT - binary.len() as i64,
            ..RootFs::default()
        };
        apply_one(dir.path(), &descs[0], &raw, &mut fs, &PN);
        let e = &fs.entries[path.as_str()];
        assert!(
            !e.truncated && e.data == binary,
            "{name}: 담은 {} 바이트",
            e.data.len()
        );
        assert_eq!(
            (fs.config_bytes, fs.captured),
            (8 << 20, SELECTED_DATA_LIMIT),
            "{name}"
        );
    }
}
