//! attestation 제외 — SBOM · 빌드 증명을 담은 매니페스트를 실행 이미지로 점검하지 않는다. 스캐너의
//! `internal/images/attestation.go` 를 옮겼다.
//!
//! 주석(annotation)은 *살펴볼 까닭* 일 뿐이다. 빼려면 가리키는 자료가 모두 온전한 in-toto JSON 이고, 설정이 실행할
//! 파일 시스템이나 명령을 말하지 않아야 한다. 하나라도 어긋나면 실행 이미지 후보로 남아 *확인 필요* 로 간다.

use super::json::KeySet;
use super::meta::{
    decode, digest_path, read_descriptor, verify_digest, AttestationConfig, Descriptor, Manifest,
    Statement, METADATA_LIMIT,
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

/// 실행하지 않는 attestation 임을 확인한다. `claims` 는 인덱스들이 서술한 매니페스트(다이제스트 → 서술자).
pub(super) fn verify(
    src: &Source<'_>,
    d: &Descriptor,
    m: &Manifest,
    claims: &BTreeMap<String, Descriptor>,
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
    check_target(&subject, m, claims, lang)?;
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
    verify_config(src, m, lang)?;
    for layer in &m.layers {
        verify_statement(src, layer, &subject, lang)?;
    }
    Ok(())
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

/// 대상이 실행 이미지 매니페스트이고, `subject` 서술자가 인덱스의 것과 맞는가.
fn check_target(
    subject: &str,
    m: &Manifest,
    claims: &BTreeMap<String, Descriptor>,
    lang: Lang,
) -> Res<()> {
    let image_manifest = |media: &str| media == OCI_MANIFEST || media == DOCKER_MANIFEST;
    let target = claims.get(subject);
    if let Some(t) = target {
        let marked = t.annotations.get(REFERENCE_TYPE) == "attestation-manifest"
            || !t.annotations.get(SUBJECT).is_empty();
        let unknown = t.platform.os == "unknown" || t.platform.architecture == "unknown";
        if !image_manifest(&t.media_type) || unknown || marked {
            return Err(lang
                .t(
                    "attestation 이 실행 이미지가 아닌 대상을 가리킵니다",
                    "the attestation points at something other than a runtime image",
                )
                .to_string());
        }
    }
    let Some(s) = &m.subject else {
        return Ok(());
    };
    let mismatch = target.is_some_and(|t| s.media_type != t.media_type || s.size != t.size);
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

/// in-toto 문서 하나 — 형식 · 종류 · 대상 다이제스트.
fn verify_statement(src: &Source<'_>, layer: &Descriptor, subject: &str, lang: Lang) -> Res<()> {
    let data = read_descriptor(src, layer, lang).map_err(|why| {
        lang.pick(
            format!("attestation JSON 자료: {why}"),
            format!("attestation JSON payload: {why}"),
        )
    })?;
    let bad = |ko: &'static str, en: &'static str| lang.t(ko, en).to_string();
    let statement: Statement = decode(&data, lang).map_err(|_| {
        bad(
            "in-toto attestation 문서 형식이 잘못됐습니다",
            "invalid in-toto attestation document",
        )
    })?;
    let known_type = statement.kind == "https://in-toto.io/Statement/v0.1"
        || statement.kind == "https://in-toto.io/Statement/v1";
    if !known_type || statement.subjects.is_empty() || statement.subjects.len() > 1024 {
        return Err(bad(
            "in-toto attestation 문서 형식이 잘못됐습니다",
            "invalid in-toto attestation document",
        ));
    }
    let predicate = statement.predicate.0.trim_ascii_start();
    if !https_url(&statement.predicate_type) || !predicate.starts_with(b"{") {
        return Err(bad(
            "attestation 종류 또는 본문이 잘못됐습니다",
            "invalid attestation type or body",
        ));
    }
    let claimed = layer.annotations.get("in-toto.io/predicate-type");
    if !claimed.is_empty() && claimed != statement.predicate_type {
        return Err(bad(
            "attestation 자료의 종류가 선언과 다릅니다",
            "the attestation payload type differs from its declaration",
        ));
    }
    let mut matched = false;
    for entry in &statement.subjects {
        let digest = format!("sha256:{}", entry.digest.get("sha256"));
        if digest_path(&digest, lang).is_err() {
            return Err(bad(
                "attestation 문서의 대상 해시가 잘못됐습니다",
                "invalid target digest in the attestation document",
            ));
        }
        matched |= digest == subject;
    }
    if !matched {
        return Err(bad(
            "attestation 문서의 대상과 연결된 이미지가 다릅니다",
            "the attestation document's target differs from the linked image",
        ));
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

/// `https://호스트/…` 로 읽히는가 — Go 의 `url.Parse` 가 `https` · 호스트 · 사용자 정보 없음으로 읽는 것의
/// 부분집합만 받는다(더 좁다). 호스트는 글자 · 숫자 · `.-_~` 에 `:포트`, 나머지는 제어 문자 · 공백 · 역슬래시 없이
/// `%` 뒤에 16진수 두 자리.
fn https_url(text: &str) -> bool {
    let Some(rest) = text
        .get(..8)
        .filter(|s| s.eq_ignore_ascii_case("https://"))
        .map(|_| &text[8..])
    else {
        return false;
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (host, port) = authority.split_once(':').unwrap_or((authority, ""));
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
    let port_ok = port.bytes().all(|b| b.is_ascii_digit());
    host_ok && port_ok && clean_tail(tail)
}

fn clean_tail(tail: &str) -> bool {
    let b = tail.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b.get(i + 1..i + 3);
                if !hex.is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) {
                    return false;
                }
                i += 3;
                continue;
            }
            c if c <= b' ' || c == 0x7f || c == b'\\' || c >= 0x80 => return false,
            _ => {}
        }
        i += 1;
    }
    true
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

    #[test]
    fn only_plain_https_urls_with_a_host_pass() {
        for ok in [
            "https://spdx.dev/Document",
            "HTTPS://slsa.dev/provenance/v0.2",
            "https://in-toto.io:443/attestation/vulns/v0.1?x=1#y",
        ] {
            assert!(https_url(ok), "{ok}");
        }
        for bad in [
            "http://spdx.dev/Document",
            "https:///Document",
            "https://user@spdx.dev/",
            "https://spdx.dev:x/",
            "https://spdx.dev/a b",
            "https://spdx.dev/%zz",
            "https://[::1]/",
            "spdx.dev/Document",
        ] {
            assert!(!https_url(bad), "{bad}");
        }
    }
}
