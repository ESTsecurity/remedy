//! attestation 제외 — SBOM · 빌드 증명을 담은 매니페스트를 실행 이미지로 점검하지 않는다. 스캐너의
//! `internal/images/attestation.go` 에서 출발했다.
//!
//! **구조로만 뺀다(2026-11-11).** 실행할 플랫폼이 없고 레이어가 모두 in-toto JSON 인 매니페스트는 컨테이너로 실행될
//! 수 없다 — tar 레이어가 없어 파일 시스템이 생기지 않는다. 그래서 실행 파일을 숨길 수 없고, 그것을 알려고 SBOM ·
//! 빌드 증명의 내용을 읽을 필요가 없다. 스캐너는 내용까지 읽었는데, 실제 BuildKit 이미지는 그 내용이 메타데이터
//! 한도(4 MiB)를 넘고 in-toto 문서의 대상(`subject`)이 비어 있어 늘 *확인 필요* 로 남았다. 레이어 블롭은 읽지 않는다.
//!
//! 빼는 조건 — 주석(annotation)은 *살펴볼 까닭* 일 뿐이고, 하나라도 어긋나면 실행 이미지 후보로 남아 *확인 필요* 로
//! 간다.
//! - 인덱스가 서술한 OCI 이미지 매니페스트다(산출물 꼴이면 그 종류가 attestation 이다).
//! - 플랫폼이 없거나 `unknown/unknown` 이고 변형(variant)이 없다.
//! - 레이어가 1~256개이고 모두 `application/vnd.in-toto+json` 이다.
//! - 설정이 OCI 빈 설정(인라인 또는 블롭 — 블롭이 있으면 크기 · 해시를 본다)이거나 옛 꼴의 `unknown/unknown`
//!   설정이다.
//! - 주석(`vnd.docker.reference.digest` · `io.containerd.manifest.subject`)과 `subject` 가 말하는 다이제스트가
//!   하나로 모이고, 올바른 sha256 이며, 자기 자신이 아니고, 같은 인덱스의 실행 이미지 매니페스트를 가리킨다.

use super::json::KeySet;
use super::meta::{
    decode, digest_path, read_descriptor, verify_digest, AttestationConfig, Descriptor, Manifest,
    METADATA_LIMIT,
};
use super::source::Source;
use crate::scan::budget::MAX_LAYERS;
use remedy_sdk::i18n::Lang;
use std::collections::BTreeMap;

const ATTESTATION_ARTIFACT: &str = "application/vnd.docker.attestation.manifest.v1+json";
const ATTESTATION_LAYER: &str = "application/vnd.in-toto+json";
const EMPTY_CONFIG: &str = "application/vnd.oci.empty.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const REFERENCE_TYPE: &str = "vnd.docker.reference.type";
const REFERENCE_DIGEST: &str = "vnd.docker.reference.digest";
const SUBJECT: &str = "io.containerd.manifest.subject";

type Res<T> = Result<T, String>;

/// 살펴볼 attestation 인가.
pub(super) fn candidate(d: &Descriptor, m: &Manifest) -> bool {
    m.artifact_type == ATTESTATION_ARTIFACT
        || d.annotations.get(REFERENCE_TYPE) == "attestation-manifest"
        || !d.annotations.get(SUBJECT).is_empty()
}

/// 실행할 수 없는 attestation 임을 구조로 확인한다. `siblings` 는 이 매니페스트를 서술한 인덱스의 매니페스트들
/// (다이제스트 → 서술자).
pub(super) fn verify(
    src: &Source<'_>,
    d: &Descriptor,
    m: &Manifest,
    siblings: &BTreeMap<String, Descriptor>,
    lang: Lang,
) -> Res<()> {
    let fail = |ko: &'static str, en: &'static str| -> Res<()> { Err(lang.t(ko, en).to_string()) };
    let artifact_ok = m.artifact_type.is_empty() || m.artifact_type == ATTESTATION_ARTIFACT;
    if m.media_type != OCI_MANIFEST || m.media_type != d.media_type || !artifact_ok {
        return fail(
            "알 수 없는 attestation 매니페스트 형식입니다",
            "unknown attestation manifest format",
        );
    }
    let p = &d.platform;
    let unknown = |v: &str| v.is_empty() || v == "unknown";
    if !unknown(&p.os) || !unknown(&p.architecture) || !p.variant.is_empty() {
        return fail(
            "attestation 에 실행 플랫폼이 지정돼 있습니다",
            "the attestation names a runtime platform",
        );
    }
    let subject = subject_of(d, m, lang)?;
    check_target(&subject, m, siblings, lang)?;
    if m.layers.is_empty() || m.layers.len() > MAX_LAYERS as usize {
        return fail(
            "attestation JSON 자료의 개수가 잘못됐습니다",
            "the attestation has a wrong number of JSON payloads",
        );
    }
    if m.layers.iter().any(|l| l.media_type != ATTESTATION_LAYER) {
        return fail(
            "attestation 에 실행 레이어 또는 알 수 없는 자료가 들어 있습니다",
            "the attestation contains a runtime layer or unknown payload",
        );
    }
    verify_config(src, m, lang)
}

/// 연결 대상 — 주석 둘과 `subject` 가 말하는 다이제스트가 하나로 모여야 한다.
fn subject_of(d: &Descriptor, m: &Manifest, lang: Lang) -> Res<String> {
    let differ = || {
        lang.t(
            "attestation 의 연결 대상이 서로 다릅니다",
            "the attestation's subjects disagree",
        )
        .to_string()
    };
    let mut subject = String::new();
    for candidate in [
        d.annotations.get(REFERENCE_DIGEST),
        d.annotations.get(SUBJECT),
    ] {
        if candidate.is_empty() {
            continue;
        }
        if !subject.is_empty() && subject != candidate {
            return Err(differ());
        }
        subject = candidate.to_string();
    }
    if let Some(s) = &m.subject {
        if !subject.is_empty() && subject != s.digest {
            return Err(differ());
        }
        subject = s.digest.clone();
    }
    if digest_path(&subject, lang).is_err() || subject == d.digest {
        return Err(lang
            .t(
                "attestation 의 대상 이미지 해시가 잘못됐습니다",
                "the attestation's target image digest is invalid",
            )
            .to_string());
    }
    Ok(subject)
}

/// 대상이 같은 인덱스의 실행 이미지 매니페스트이고, `subject` 서술자가 인덱스의 것과 맞는가.
fn check_target(
    subject: &str,
    m: &Manifest,
    siblings: &BTreeMap<String, Descriptor>,
    lang: Lang,
) -> Res<()> {
    let image_manifest = |media: &str| media == OCI_MANIFEST || media == DOCKER_MANIFEST;
    let Some(target) = siblings.get(subject) else {
        return Err(lang
            .t(
                "attestation 의 대상 이미지가 같은 인덱스에 없습니다",
                "the attestation's target image is not in the same index",
            )
            .to_string());
    };
    let marked = target.annotations.get(REFERENCE_TYPE) == "attestation-manifest"
        || !target.annotations.get(SUBJECT).is_empty();
    let unknown = target.platform.os == "unknown" || target.platform.architecture == "unknown";
    if !image_manifest(&target.media_type) || unknown || marked {
        return Err(lang
            .t(
                "attestation 이 실행 이미지가 아닌 대상을 가리킵니다",
                "the attestation points at something other than a runtime image",
            )
            .to_string());
    }
    let Some(s) = &m.subject else {
        return Ok(());
    };
    let mismatch = s.media_type != target.media_type || s.size != target.size;
    if !image_manifest(&s.media_type) || s.size <= 0 || s.size as u64 > METADATA_LIMIT || mismatch {
        return Err(lang
            .t(
                "attestation 의 대상 서술이 잘못됐거나 인덱스와 다릅니다",
                "the attestation's subject descriptor is invalid or differs from the index",
            )
            .to_string());
    }
    Ok(())
}

/// 설정이 실행할 것을 말하지 않는가(스캐너의 `verifyAttestationConfig`).
fn verify_config(src: &Source<'_>, m: &Manifest, lang: Lang) -> Res<()> {
    if m.artifact_type == ATTESTATION_ARTIFACT {
        return verify_empty_config(src, m, lang);
    }
    if m.config.media_type != OCI_CONFIG {
        return Err(lang
            .t(
                "알 수 없는 attestation 설정 형식입니다",
                "unknown attestation config format",
            )
            .to_string());
    }
    let data = read_descriptor(src, &m.config, lang).map_err(|why| {
        lang.pick(
            format!("attestation 설정: {why}"),
            format!("attestation config: {why}"),
        )
    })?;
    let runnable = || {
        lang.t(
            "attestation 에 실행 설정이 있거나 실행하지 않는 설정임을 확인하지 못했습니다",
            "the attestation has a runtime config, or its config could not be confirmed as non-runtime",
        )
        .to_string()
    };
    let cfg: AttestationConfig = decode(&data, lang).map_err(|_| runnable())?;
    let empty = cfg.config.0.as_ref().is_none_or(|keys| keys.is_empty());
    let sound = cfg.os == "unknown"
        && cfg.architecture == "unknown"
        && cfg.variant.is_empty()
        && empty
        && cfg.rootfs.kind == "layers"
        && cfg.rootfs.diff_ids.len() == m.layers.len();
    if !sound {
        return Err(runnable());
    }
    for (digest, layer) in cfg.rootfs.diff_ids.iter().zip(&m.layers) {
        if *digest != layer.digest || !digest.starts_with("sha256:") {
            return Err(lang
                .t(
                    "attestation 설정의 JSON 자료 해시가 일치하지 않습니다",
                    "the attestation config's payload digests do not match",
                )
                .to_string());
        }
    }
    Ok(())
}

/// 산출물 꼴의 attestation — 설정은 빈 객체(`{}`)여야 한다. 안에 실은 설정(`data`)이 있으면 크기와 해시를 보고, 같은
/// 블롭이 있거나 실은 것이 없으면 블롭을 읽는다.
fn verify_empty_config(src: &Source<'_>, m: &Manifest, lang: Lang) -> Res<()> {
    if m.config.media_type != EMPTY_CONFIG {
        return Err(lang
            .t(
                "attestation 산출물에 실행 이미지 설정이 들어 있습니다",
                "the attestation artifact contains a runtime image config",
            )
            .to_string());
    }
    let mut data = Vec::new();
    if !m.config.data.is_empty() {
        data = inline_config(m, lang).map_err(|why| {
            lang.pick(
                format!("attestation 인라인 설정: {why}"),
                format!("attestation inline config: {why}"),
            )
        })?;
    }
    let damaged = || {
        lang.t(
            "attestation 산출물의 빈 설정이 손상됐습니다",
            "the attestation artifact's empty config is damaged",
        )
        .to_string()
    };
    let path = digest_path(&m.config.digest, lang);
    if path.as_ref().map_or(true, |name| src.has(name)) || m.config.data.is_empty() {
        data = read_descriptor(src, &m.config, lang).map_err(|_| damaged())?;
    }
    let object: KeySet = decode(&data, lang).map_err(|_| damaged())?;
    match object.0 {
        Some(keys) if keys.is_empty() => Ok(()),
        _ => Err(damaged()),
    }
}

fn inline_config(m: &Manifest, lang: Lang) -> Res<Vec<u8>> {
    let data = base64_std(&m.config.data).ok_or_else(|| {
        lang.t("base64 형식이 잘못됐습니다", "invalid base64")
            .to_string()
    })?;
    if data.len() as i64 != m.config.size || m.config.size as u64 > METADATA_LIMIT {
        return Err(lang
            .t(
                "attestation 인라인 설정 크기가 다릅니다",
                "the attestation inline config size differs",
            )
            .to_string());
    }
    verify_digest(&data, &m.config.digest, lang)?;
    Ok(data)
}

/// Go 의 `base64.StdEncoding.DecodeString` — 줄바꿈(`\r` · `\n`)은 건너뛰고, 채움(`=`)이 있는 4글자 단위여야 하며,
/// 남는 비트는 보지 않는다.
fn base64_std(text: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = text
        .bytes()
        .filter(|b| *b != b'\r' && *b != b'\n')
        .collect();
    if !clean.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    let quanta = clean.len() / 4;
    for (i, q) in clean.chunks_exact(4).enumerate() {
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != quanta) || q[..4 - pad].contains(&b'=') {
            return None;
        }
        let mut n = 0u32;
        for &c in &q[..4 - pad] {
            n = n << 6 | value(c)?;
        }
        n <<= 6 * pad as u32;
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_follows_go_std_encoding() {
        assert_eq!(base64_std("e30="), Some(b"{}".to_vec()));
        assert_eq!(base64_std("e30\r\n="), Some(b"{}".to_vec()));
        assert_eq!(base64_std(""), Some(Vec::new()));
        assert_eq!(base64_std("e30"), None);
        assert_eq!(base64_std("e3=0"), None);
        assert_eq!(base64_std("e30=e30="), None);
        // 남는 비트는 보지 않는다(Go 의 엄격하지 않은 모드).
        assert_eq!(base64_std("e31="), Some(b"{}".to_vec()));
    }
}
