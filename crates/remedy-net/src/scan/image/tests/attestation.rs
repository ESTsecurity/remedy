//! 스캐너 `attestation_test.go` — SBOM · 빌드 증명 매니페스트를 구조로 확인하고 뺀다(2026-11-11 부터 in-toto
//! 내용은 읽지 않는다).

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

/// `TestAttestationOnlyInputRetainsReviewProductCoverage` — 스캐너는 attestation 을 빼고 *실행 이미지가 없다* 고
/// 했다. 지금은 대상이 같은 인덱스에 없으면 빼지 않으므로 그 attestation 이 *확인 필요* 대상으로 남는다.
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
        assert_eq!(excluded(t), None, "{format}");
        assert!(
            coverage.gaps.join(" ").contains("같은 인덱스에 없습니다"),
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

/// 인덱스의 attestation 서술자 주석을 바꾼다 — 매니페스트 블롭은 그대로.
fn annotate(f: &mut Fixture, annotations: Value) {
    f.attestation["annotations"] = annotations;
    write_index(f.dir.path(), &[f.runtime.clone(), f.attestation.clone()]);
}

/// in-toto 자료 하나를 새로 싣고 설정의 diffID 도 맞춘다.
fn replace_payload(f: &mut Fixture, statement: &Value) {
    let dir = f.dir.path().to_path_buf();
    let layer = blob(&dir, &bytes(statement), ATTESTATION_LAYER);
    f.manifest["config"] = unknown_config(&dir, json!({}), &layer);
    f.manifest["layers"] = json!([layer]);
}

/// 문제 하나를 심는다(스캐너 시험의 `switch problem`). 구조로만 빼므로 in-toto 내용의 문제는 여기 없다.
fn spoil(f: &mut Fixture, problem: &str) {
    let dir = f.dir.path().to_path_buf();
    let own = f.attestation["digest"].clone();
    match problem {
        "manifest-hash" => return flip_last(&dir, f.attestation["digest"].as_str().unwrap()),
        "config-hash" => return flip_last(&dir, f.manifest["config"]["digest"].as_str().unwrap()),
        "runtime-layer" => f.manifest["layers"][0]["mediaType"] = json!(RAW_LAYER),
        "runtime-config" => {
            let layer = f.manifest["layers"][0].clone();
            f.manifest["config"] = unknown_config(&dir, json!({"Entrypoint": ["node"]}), &layer);
        }
        "no-layers" => f.manifest["layers"] = json!([]),
        "runtime-platform" => {
            f.attestation["platform"] = json!({"os": "linux", "architecture": "amd64"});
            return write_index(&dir, &[f.runtime.clone(), f.attestation.clone()]);
        }
        "missing-subject" => {
            return annotate(
                f,
                json!({"vnd.docker.reference.type": "attestation-manifest"}),
            )
        }
        "self-subject" => return annotate(f, json!({"io.containerd.manifest.subject": own})),
        "invalid-subject" => {
            return annotate(
                f,
                json!({"io.containerd.manifest.subject": "sha256:runtime"}),
            )
        }
        "subject-not-in-index" => {
            let other = format!("sha256:{}", "c".repeat(64));
            return annotate(f, json!({"io.containerd.manifest.subject": other}));
        }
        _ => {
            let other = json!({"mediaType": OCI_MANIFEST, "digest": format!("sha256:{}", "d".repeat(64)), "size": 10});
            f.manifest["subject"] = other;
        }
    }
    f.attestation = rewritten(&dir, &f.attestation, &f.manifest);
    write_index(&dir, &[f.runtime.clone(), f.attestation.clone()]);
}

/// `TestAttestationCorruptionAndRuntimeDisguiseRequireReview` — 스캐너의 `payload-hash` · `wrong-subject` ·
/// `invalid-statement` 는 in-toto 내용의 문제라 구조로만 빼는 지금은 빠지는 쪽이다(아래
/// `attestation_contents_are_not_read`). 그 자리에 대상 · 레이어의 구조 문제를 더했다.
#[test]
fn attestation_corruption_and_runtime_disguise_require_review() {
    let problems = [
        "manifest-hash",
        "config-hash",
        "runtime-layer",
        "runtime-config",
        "no-layers",
        "runtime-platform",
        "missing-subject",
        "self-subject",
        "invalid-subject",
        "subject-not-in-index",
        "subjects-disagree",
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
            "{problem}: 구조를 확인하지 못한 attestation 을 뺐다"
        );
    }
}

/// 대상이 실행 이미지가 아니고 다른 attestation 이면 빼지 않는다 — 빼는 것은 실행 이미지를 가리키는 쪽뿐이다.
#[test]
fn attestation_pointing_at_another_attestation_stays_for_review() {
    let f = fixture("docker-save");
    // 같은 바이트면 다이제스트가 같아지므로 주석 하나로 다른 매니페스트를 만든다.
    let manifest = json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST, "annotations": {"note": "second"},
        "config": f.manifest["config"], "layers": f.manifest["layers"],
    });
    let mut second = rewritten(f.dir.path(), &f.attestation, &manifest);
    second["annotations"] = json!({"io.containerd.manifest.subject": f.attestation["digest"]});
    write_index(
        f.dir.path(),
        &[f.runtime.clone(), f.attestation.clone(), second],
    );
    let targets = scan_fixture(f.dir.path());
    let statuses: Vec<Status> = targets.iter().map(|t| t.status).collect();
    assert_eq!(statuses, [Clear, Review], "{targets:#?}");
    assert_eq!(excluded(&targets[0]), Some("1"));
}

/// 구조로만 뺀다 — in-toto 자료가 메타데이터 한도 4 MiB 를 넘고 대상(`subject`)이 비어 있어도(실제 BuildKit
/// 이미지의 꼴), 자료 블롭이 손상돼도 뺀다. 자료는 읽지 않는다.
#[test]
fn attestation_contents_are_not_read() {
    for case in ["oversized-empty-subject", "unreadable-payload"] {
        let mut f = fixture("docker-save");
        if case == "oversized-empty-subject" {
            let statement = json!({
                "_type": "https://in-toto.io/Statement/v0.1", "subject": [],
                "predicateType": "https://spdx.dev/Document",
                "predicate": {"spdxVersion": "SPDX-2.3", "packages": "x".repeat(5 << 20)},
            });
            replace_payload(&mut f, &statement);
            let dir = f.dir.path().to_path_buf();
            f.attestation = rewritten(&dir, &f.attestation, &f.manifest);
            write_index(&dir, &[f.runtime.clone(), f.attestation.clone()]);
        } else {
            flip_last(
                f.dir.path(),
                f.manifest["layers"][0]["digest"].as_str().unwrap(),
            );
        }
        let targets = scan_fixture(f.dir.path());
        single(&targets, Clear);
        assert_eq!(excluded(&targets[0]), Some("1"), "{case}");
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
