//! 스캐너 `attestation_test.go` — SBOM · 빌드 증명 매니페스트를 확인하고 뺀다.

use super::fixtures::*;
use crate::scan::model::{aggregate, Product, Status, Target};
use serde_json::{json, Value};
use std::path::Path;
use Packing::Raw;
use Status::{Clear, ReviewRequired as Review};

const ATTESTATION_ARTIFACT: &str = "application/vnd.docker.attestation.manifest.v1+json";
const ATTESTATION_LAYER: &str = "application/vnd.in-toto+json";
const EMPTY_CONFIG: &str = "application/vnd.oci.empty.v1+json";

/// 스캐너 `fixtureAttestation` 이 주는 넷.
struct Fixture {
    dir: Scratch,
    runtime: Value,
    attestation: Value,
    manifest: Value,
}

/// 표준 base64(채움 있음).
fn b64(data: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | (u32::from(b) << (16 - 8 * i)));
        for i in 0..4 {
            let c = if i <= chunk.len() {
                ABC[((n >> (18 - 6 * i)) & 63) as usize]
            } else {
                b'='
            };
            out.push(char::from(c));
        }
    }
    out
}

/// 스캐너 `fixtureAttestation` — Node.js 실행 이미지 하나와, 그것을 가리키는 SPDX attestation 하나.
fn fixture(format: &str) -> Fixture {
    let entries = [
        reg("etc/os-release", "ID=ubuntu\nVERSION_ID=24.04\n"),
        reg("var/lib/dpkg/status", ""),
        reg("usr/local/bin/node", elf(&[])),
    ];
    let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
    let index: Value =
        serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
    let runtime = index["manifests"][0].clone();
    let digest = runtime["digest"].as_str().unwrap().to_string();
    let statement = json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": "image", "digest": {"sha256": &digest[7..]}}],
        "predicateType": "https://spdx.dev/Document", "predicate": {"spdxVersion": "SPDX-2.3"},
    });
    let mut layer = blob(dir.path(), &bytes(&statement), ATTESTATION_LAYER);
    layer["annotations"] = json!({"in-toto.io/predicate-type": "https://spdx.dev/Document"});
    let config = unknown_config(dir.path(), json!({}), &layer);
    let mut manifest =
        json!({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": config, "layers": [layer]});
    if format.starts_with("modern") {
        manifest["artifactType"] = json!(ATTESTATION_ARTIFACT);
        manifest["subject"] = runtime.clone();
        manifest["config"] = blob(dir.path(), b"{}", EMPTY_CONFIG);
        if format == "modern-inline" {
            std::fs::remove_file(blob_path(
                dir.path(),
                manifest["config"]["digest"].as_str().unwrap(),
            ))
            .unwrap();
            manifest["config"]["data"] = json!(b64(b"{}"));
        }
    }
    let mut attestation = blob(dir.path(), &bytes(&manifest), OCI_MANIFEST);
    match format {
        "legacy" => {
            attestation["platform"] = json!({"os": "unknown", "architecture": "unknown"});
            attestation["annotations"] = json!({
                "vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": digest,
            });
        }
        "docker-save" => {
            attestation["annotations"] = json!({"io.containerd.manifest.subject": digest})
        }
        _ => {}
    }
    write_index(dir.path(), &[runtime.clone(), attestation.clone()]);
    Fixture {
        dir,
        runtime,
        attestation,
        manifest,
    }
}

/// 플랫폼이 `unknown` 이고 diffID 가 그 JSON 자료인 설정 블롭.
fn unknown_config(dir: &Path, run: Value, layer: &Value) -> Value {
    let cfg = json!({
        "os": "unknown", "architecture": "unknown", "config": run,
        "rootfs": {"type": "layers", "diff_ids": [layer["digest"]]},
    });
    blob(dir, &bytes(&cfg), OCI_CONFIG)
}

/// 스캐너 `rewrittenAttestation` — 고친 매니페스트를 새 블롭으로, 주석 · 플랫폼은 그대로.
fn rewritten(dir: &Path, old: &Value, manifest: &Value) -> Value {
    let mut d = blob(dir, &bytes(manifest), OCI_MANIFEST);
    for key in ["annotations", "platform"] {
        if let Some(v) = old.get(key) {
            d[key] = v.clone();
        }
    }
    d
}

fn scan_fixture(dir: &Path) -> Vec<Target> {
    run(dir, &[Product::Node], &node_rules(Some(&elf(&[]))))
}

fn excluded(t: &Target) -> Option<&str> {
    t.metadata.get("excluded_attestations").map(String::as_str)
}

/// `TestVerifiedNonRuntimeAttestationIsExcluded`
#[test]
fn verified_non_runtime_attestation_is_excluded() {
    for format in ["legacy", "docker-save", "modern", "modern-inline"] {
        let f = fixture(format);
        let targets = scan_fixture(f.dir.path());
        single(&targets, Clear);
        let t = &targets[0];
        assert_eq!(excluded(t), Some("1"), "{format}: {:?}", t.metadata);
        assert!(t
            .metadata
            .get("excluded_attestation_reason")
            .is_some_and(|r| !r.is_empty()));
        assert_eq!(t.findings.len(), 1, "{format}: {:#?}", t.findings);
        assert_eq!(t.findings[0].product, Product::Node);
    }
}

/// `TestAttestationDoesNotHideMissingPlatformFiles`
#[test]
fn attestation_does_not_hide_missing_platform_files() {
    let f = fixture("legacy");
    let media = f.runtime["mediaType"].clone();
    let missing = json!({
        "mediaType": media, "digest": format!("sha256:{}", "a".repeat(64)), "size": 100,
        "platform": {"os": "linux", "architecture": "arm64"},
    });
    let missing_attestation = json!({
        "mediaType": media, "digest": format!("sha256:{}", "b".repeat(64)), "size": 100,
        "platform": {"os": "unknown", "architecture": "unknown"},
        "annotations": {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": missing["digest"]},
    });
    write_index(
        f.dir.path(),
        &[
            f.runtime.clone(),
            f.attestation.clone(),
            missing,
            missing_attestation,
        ],
    );
    let targets = scan_fixture(f.dir.path());
    let statuses: Vec<Status> = targets.iter().map(|t| t.status).collect();
    assert_eq!(statuses, [Clear, Review, Review], "{targets:#?}");
    assert_eq!(aggregate(&targets), Review);
    assert_eq!(excluded(&targets[0]), Some("1"));
}

/// `TestAttestationOnlyInputRetainsReviewProductCoverage`
#[test]
fn attestation_only_input_retains_review_product_coverage() {
    for format in ["legacy", "docker-save", "modern"] {
        let f = fixture(format);
        write_index(f.dir.path(), std::slice::from_ref(&f.attestation));
        let targets = scan_fixture(f.dir.path());
        single(&targets, Review);
        let t = &targets[0];
        let coverage = &t.products[&Product::Node];
        assert!(
            !coverage.complete && coverage.status == Review,
            "{format}: {coverage:#?}"
        );
        assert_eq!(excluded(t), Some("1"), "{format}");
        assert!(
            coverage.gaps.join(" ").contains("실행 이미지가 없습니다"),
            "{format}: {:?}",
            coverage.gaps
        );
    }
}

/// 블롭의 마지막 바이트를 뒤집는다.
fn flip_last(dir: &Path, digest: &str) {
    let path = blob_path(dir, digest);
    let mut data = std::fs::read(&path).unwrap();
    *data.last_mut().unwrap() ^= 1;
    std::fs::write(path, data).unwrap();
}

/// 문제 하나를 심는다(스캐너 시험의 `switch problem`).
fn spoil(f: &mut Fixture, problem: &str) {
    let dir = f.dir.path().to_path_buf();
    match problem {
        "manifest-hash" => return flip_last(&dir, f.attestation["digest"].as_str().unwrap()),
        "config-hash" => return flip_last(&dir, f.manifest["config"]["digest"].as_str().unwrap()),
        "payload-hash" => {
            return flip_last(&dir, f.manifest["layers"][0]["digest"].as_str().unwrap())
        }
        "runtime-layer" => f.manifest["layers"][0]["mediaType"] = json!(RAW_LAYER),
        "runtime-config" => {
            let layer = f.manifest["layers"][0].clone();
            f.manifest["config"] = unknown_config(&dir, json!({"Entrypoint": ["node"]}), &layer);
        }
        "runtime-platform" => {
            f.attestation["platform"] = json!({"os": "linux", "architecture": "amd64"});
            return write_index(&dir, &[f.runtime.clone(), f.attestation.clone()]);
        }
        _ => {
            let kind = if problem == "invalid-statement" {
                "runtime-image"
            } else {
                "https://in-toto.io/Statement/v1"
            };
            let statement = json!({
                "_type": kind, "subject": [{"digest": {"sha256": "c".repeat(64)}}],
                "predicateType": "https://spdx.dev/Document", "predicate": {},
            });
            let layer = blob(&dir, &bytes(&statement), ATTESTATION_LAYER);
            f.manifest["config"] = unknown_config(&dir, json!({}), &layer);
            f.manifest["layers"] = json!([layer]);
        }
    }
    f.attestation = rewritten(&dir, &f.attestation, &f.manifest);
    write_index(&dir, &[f.runtime.clone(), f.attestation.clone()]);
}

/// `TestAttestationCorruptionAndRuntimeDisguiseRequireReview`
#[test]
fn attestation_corruption_and_runtime_disguise_require_review() {
    let problems = [
        "manifest-hash",
        "config-hash",
        "payload-hash",
        "runtime-layer",
        "runtime-config",
        "runtime-platform",
        "wrong-subject",
        "invalid-statement",
    ];
    for problem in problems {
        let mut f = fixture("docker-save");
        spoil(&mut f, problem);
        let targets = scan_fixture(f.dir.path());
        let statuses: Vec<Status> = targets.iter().map(|t| t.status).collect();
        assert_eq!(statuses, [Clear, Review], "{problem}: {targets:#?}");
        assert_eq!(aggregate(&targets), Review);
        assert_eq!(
            excluded(&targets[0]),
            None,
            "{problem}: 확인하지 못한 attestation 을 뺐다"
        );
    }
}

/// `TestAttestationReferencesStillCountAgainstManifestLimit`
#[test]
fn attestation_references_still_count_against_manifest_limit() {
    let f = fixture("docker-save");
    let mut manifests = vec![f.runtime.clone()];
    manifests.extend(std::iter::repeat_n(f.attestation.clone(), 256));
    write_index(f.dir.path(), &manifests);
    let targets = scan_fixture(f.dir.path());
    assert_eq!(aggregate(&targets), Review);
    assert_eq!(targets.len(), 2, "{targets:#?}");
    assert_eq!(excluded(&targets[0]), Some("255"));
}

/// `TestAttestationRejectsCorruptInlineConfigEvenWithValidBlob`
#[test]
fn attestation_rejects_corrupt_inline_config_even_with_valid_blob() {
    let mut f = fixture("modern");
    f.manifest["config"]["data"] = json!(b64(br#"{"Entrypoint":["node"]}"#));
    let attestation = rewritten(f.dir.path(), &f.attestation, &f.manifest);
    write_index(f.dir.path(), &[f.runtime.clone(), attestation]);
    let targets = scan_fixture(f.dir.path());
    assert_eq!(targets.len(), 2, "{targets:#?}");
    assert_eq!(targets[1].status, Review);
    assert_eq!(aggregate(&targets), Review);
}

#[test]
fn b64_matches_the_standard_alphabet() {
    assert_eq!(b64(b"{}"), "e30=");
    assert_eq!(b64(b"abc"), "YWJj");
    assert_eq!(b64(b"ab"), "YWI=");
    assert_eq!(b64(b"a"), "YQ==");
}
