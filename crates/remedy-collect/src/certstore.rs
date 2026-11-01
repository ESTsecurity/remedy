//! 인증서 저장소 (설계-09 P4).
//!
//! **가짜 루트 인증서는 조용한 위협이다.** 신뢰 루트에 자기 CA 를 넣어 두면
//! 모든 TLS 검사가 통과하고, 서명 검사를 근거로 삼는 우리 예외 규칙(설계-03 §3
//! 2층)까지 함께 무력해진다. 그래서 저장소를 **관찰**한다.
//!
//! # 왜 레지스트리를 읽는가
//!
//! `CertOpenStore` 는 `crypt32` 를 끌어오고 unsafe 가 필요하다. 저장소는
//! `HKLM\SOFTWARE\Microsoft\SystemCertificates\<저장소>\Certificates\<지문>`
//! 에 그대로 있고, 키 이름이 곧 SHA-1 지문이다.
//!
//! # DER 을 직접 읽는다
//!
//! `Blob` 값은 속성 목록이고 그중 하나가 DER 인증서다. 주체·발급자·만료를
//! 얻으려면 그 안을 봐야 한다. 남이 만든 이진 데이터이므로 **모든 읽기가
//! 경계를 확인하고, 어긋나면 그 항목 하나만 버린다** — 패닉하면 조작된
//! 인증서 하나로 수집 전체를 멈출 수 있다는 뜻이 된다.

use remedy_artifacts::{CertStoreRecord, CollectError, Harvest, Scope};
use remedy_platform::read::{FsRead, RegistryRead};

const STORE_ROOT: &str = "HKLM\\SOFTWARE\\Microsoft\\SystemCertificates";

/// 볼 저장소. 신뢰가 걸린 것만 본다 — `Disallowed` 처럼 큰 저장소까지 담으면
/// 스냅샷이 수천 건으로 불어나고 정작 봐야 할 것이 묻힌다.
const STORES: [&str; 4] = ["ROOT", "CA", "TrustedPublisher", "TrustedPeople"];

/// `Blob` 안에서 DER 인증서를 담고 있는 속성 id (`CERT_CERT_PROP_ID`).
const CERT_PROP_ID: u32 = 32;

pub fn cert_stores<R: RegistryRead>(reg: &R) -> Result<Harvest<CertStoreRecord>, CollectError> {
    let mut h = Harvest::default();
    for store in STORES {
        let key = format!("{STORE_ROOT}\\{store}\\Certificates");
        if !reg.key_exists(&key) {
            continue;
        }
        let thumbprints = reg.subkeys(&key).unwrap_or_default();
        for tp in thumbprints {
            let blob = reg
                .value(&format!("{key}\\{tp}"), "Blob")
                .ok()
                .flatten()
                .and_then(|v| v.bytes().map(|b| b.to_vec()));
            let (subject, issuer, not_after) = blob
                .as_deref()
                .and_then(der_of_blob)
                .and_then(parse_certificate)
                .unwrap_or_default();
            h.records.push(CertStoreRecord {
                store: store.to_string(),
                subject,
                issuer,
                thumbprint: tp.to_ascii_uppercase(),
                // Windows 인증서는 레지스트리 값이라 파일 경로가 없다.
                linux: None,
                not_after,
            });
        }
    }
    h.records
        .sort_by(|a, b| (&a.store, &a.thumbprint).cmp(&(&b.store, &b.thumbprint)));
    Ok(h)
}

/// `Blob` 속성 목록에서 DER 인증서를 꺼낸다.
///
/// 각 항목은 `propId(4) flags(4) cbData(4) data[cbData]` 다.
pub fn der_of_blob(blob: &[u8]) -> Option<&[u8]> {
    let mut off = 0usize;
    while off + 12 <= blob.len() {
        let id = u32::from_le_bytes(blob[off..off + 4].try_into().ok()?);
        let len = u32::from_le_bytes(blob[off + 8..off + 12].try_into().ok()?) as usize;
        let start = off + 12;
        let end = start.checked_add(len)?;
        if end > blob.len() {
            return None;
        }
        if id == CERT_PROP_ID {
            return Some(&blob[start..end]);
        }
        off = end;
    }
    None
}

// ─────────────────────────────────────────────────────────── DER

/// 태그 하나를 읽고 `(태그, 내용, 남은 것)` 을 돌려준다.
fn der_read(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first_len = *b.get(1)? as usize;
    let (len, hdr) = if first_len < 0x80 {
        (first_len, 2)
    } else {
        let n = first_len & 0x7F;
        // 길이의 길이가 4를 넘으면 우리가 다룰 크기가 아니다.
        if n == 0 || n > 4 {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | *b.get(2 + i)? as usize;
        }
        (v, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    Some((tag, &b[hdr..end], &b[end..]))
}

/// DER 인증서에서 `(주체, 발급자, 만료)` 를 뽑는다.
fn parse_certificate(der: &[u8]) -> Option<(String, String, String)> {
    let (tag, cert, _) = der_read(der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs, _) = der_read(cert)?;
    if tag != 0x30 {
        return None;
    }

    let mut rest = tbs;
    // `[0] EXPLICIT version` 은 선택 항목이다. 있으면 건너뛴다.
    let (tag, _, after) = der_read(rest)?;
    if tag == 0xA0 {
        rest = after;
    }
    // serialNumber
    let (_, _, rest) = der_read(rest)?;
    // signature AlgorithmIdentifier
    let (_, _, rest) = der_read(rest)?;
    // issuer Name
    let (_, issuer_raw, rest) = der_read(rest)?;
    // validity
    let (_, validity, rest) = der_read(rest)?;
    // subject Name
    let (_, subject_raw, _) = der_read(rest)?;

    // validity ::= SEQUENCE { notBefore, notAfter }
    let (_, _, after_before) = der_read(validity)?;
    let (tag, not_after, _) = der_read(after_before)?;

    Some((
        render_name(subject_raw),
        render_name(issuer_raw),
        render_time(tag, not_after).unwrap_or_default(),
    ))
}

/// 잘 알려진 속성 OID 만 이름을 붙인다. 나머지는 담지 않는다 — OID 숫자를
/// 그대로 늘어놓으면 룰 작성자가 읽을 수 없다.
fn attr_name(oid: &[u8]) -> Option<&'static str> {
    match oid {
        [0x55, 0x04, 0x03] => Some("CN"),
        [0x55, 0x04, 0x0A] => Some("O"),
        [0x55, 0x04, 0x0B] => Some("OU"),
        [0x55, 0x04, 0x06] => Some("C"),
        [0x55, 0x04, 0x08] => Some("ST"),
        [0x55, 0x04, 0x07] => Some("L"),
        _ => None,
    }
}

/// `Name` 을 `CN=..., O=...` 로 편다.
///
/// **순서를 DER 그대로 둔다.** 정렬하면 같은 인증서가 다른 문자열이 되어,
/// 룰이 적은 주체 이름과 어긋난다.
fn render_name(name: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut rest = name;
    while let Some((tag, rdn, next)) = der_read(rest) {
        rest = next;
        if tag != 0x31 {
            continue;
        }
        let mut inner = rdn;
        while let Some((tag, atv, n2)) = der_read(inner) {
            inner = n2;
            if tag != 0x30 {
                continue;
            }
            let Some((_, oid, after_oid)) = der_read(atv) else {
                continue;
            };
            let Some((_, value, _)) = der_read(after_oid) else {
                continue;
            };
            if let Some(key) = attr_name(oid) {
                parts.push(format!("{key}={}", String::from_utf8_lossy(value)));
            }
        }
    }
    parts.join(", ")
}

/// UTCTime(`YYMMDDHHMMSSZ`) 또는 GeneralizedTime(`YYYYMMDDHHMMSSZ`) 을
/// RFC3339 UTC 로 옮긴다.
///
/// UTCTime 의 두 자리 연도는 **RFC 5280 규칙**으로 편다 — 50 이상이면 19xx,
/// 아니면 20xx. 뒤집으면 2049년에 만료되는 인증서가 1949년으로 읽혀 `lt` 비교가
/// 통째로 거짓말을 한다.
fn render_time(tag: u8, v: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(v).ok()?;
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    let (year, rest) = match tag {
        0x17 if digits.len() >= 12 => {
            let yy: u32 = digits[0..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..12])
        }
        0x18 if digits.len() >= 14 => (digits[0..4].parse().ok()?, &digits[4..14]),
        _ => return None,
    };
    Some(format!(
        "{year:04}-{}-{}T{}:{}:{}Z",
        &rest[0..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        &rest[8..10]
    ))
}

// ─────────────────────────────────────────────────────────── Linux

/// 인증서 **파일**이 사는 자리 (설계-09 P12 후속).
///
/// # `/etc/ssl/certs` 를 보지 않는다
///
/// 그 아래는 거의 전부 심볼릭 링크(실측 243개)이고, 실제 파일 둘 중 하나는
/// **번들**(`ca-certificates.crt`)이라 같은 인증서를 다시 담는다. 원본이 사는
/// 자리를 보는 편이 중복도 없고 지울 대상도 정확하다.
///
/// # rpm 계열은 자리가 다르다 — 2026-09-05 에 더했다
///
/// 앞의 두 자리는 **Debian 계열의 것**이다. rpm 계열(Fedora·RHEL·Rocky·
/// openSUSE)에는 그 두 디렉터리가 아예 없다.
///
/// 실측(fedora:41 + `dnf install ca-certificates`):
///
/// ```text
///   /usr/local/share/ca-certificates          없음
///   /usr/share/ca-certificates                없음
///   /etc/pki/ca-trust/source/anchors          있음 (비어 있음)  ← 손으로 더하는 자리
///   /usr/share/pki/ca-trust-source/anchors    있음 (비어 있음)
///   /usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit   2.4 MB
/// ```
///
/// **그래서 rpm 계열에서 `cert_store` 가 구조적으로 0건이었다.** 신뢰 저장소에
/// 심어진 루트 CA 를 겨누는 룰이 그 배포판 전체에서 조용히 아무것도 맞히지
/// 못한다는 뜻이다 — 청정 코퍼스를 Fedora 로 넓히면서 드러났다.
///
/// `update-ca-trust` 는 [`SYSTEM_TOOLS`] 에 이미 있었다. **지울 줄은 아는데
/// 볼 줄을 몰랐다.**
///
/// # 번들은 여전히 보지 않는다
///
/// rpm 계열의 배포판 루트는 개별 파일이 아니라 `ca-bundle.trust.p11-kit`
/// 한 덩이에 들어 있다(2.4 MB). 위 `/etc/ssl/certs` 와 같은 이유로 읽지
/// 않는다 — 그리고 `MAX_CERT_BYTES` 를 넘는다.
///
/// **그래서 rpm 기계에서는 배포판 루트가 관측되지 않는다.** 그것이 이
/// 결정의 대가이고, 겨누는 것(심어진 CA)은 anchors 자리에 오므로 목적은
/// 달성된다 — 다만 "이 기계의 신뢰 루트 전부" 를 묻는 데는 쓸 수 없다.
pub(crate) const CERT_DIRS: [(&str, &str); 4] = [
    // 손으로 더한 CA. **악성 루트 CA 가 들어오는 자리**다.
    ("local", "/usr/local/share/ca-certificates"),
    ("system", "/usr/share/ca-certificates"),
    // rpm 계열의 같은 두 자리.
    ("local", "/etc/pki/ca-trust/source/anchors"),
    ("system", "/usr/share/pki/ca-trust-source/anchors"),
];

/// PEM 한 덩이에서 DER 을 꺼낸다. PEM 이 아니면 DER 로 본다.
///
/// 파일 하나에 인증서가 여럿일 수 있어 전부 돌려준다 — 번들을 보지 않기로 했어도
/// 배포판이 여러 개를 한 파일에 넣는 경우가 있고, **하나만 읽으면 나머지가 조용히
/// 빠진다.**
fn ders_of(bytes: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let Ok(text) = std::str::from_utf8(bytes) else {
        // UTF-8 이 아니면 PEM 이 아니다. DER 로 본다.
        return vec![bytes.to_vec()];
    };
    if !text.contains(BEGIN) {
        return vec![bytes.to_vec()];
    }
    let mut out = Vec::new();
    for chunk in text.split(BEGIN).skip(1) {
        let Some((body, _)) = chunk.split_once(END) else {
            continue;
        };
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        use base64::Engine;
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&b64) {
            out.push(der);
        }
    }
    out
}

/// SHA-1 지문. **보안 속성이 아니라 식별자다.**
///
/// Windows 는 신뢰 저장소의 레지스트리 키 이름으로 이 값을 쓴다 — 그래서 그쪽은
/// 공짜로 얻는다. Linux 에서 다른 해시를 쓰면 **같은 인증서가 플랫폼마다 다른
/// 지문을 갖고**, 악성 루트 CA 하나를 잡는 룰이 값을 둘 적어야 한다.
///
/// 인증서의 신뢰를 이 해시가 결정하지 않는다. 충돌 내성이 필요한 자리가 아니다.
fn thumbprint_of(der: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(der);
    h.finalize()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>()
}

/// Linux 신뢰 저장소.
pub fn cert_stores_linux<P: FsRead>(
    fs: &P,
    scope: &Scope,
) -> Result<Harvest<CertStoreRecord>, CollectError> {
    let mut h = Harvest::default();
    for (store, dir) in CERT_DIRS {
        if !fs.exists(dir) {
            // 없는 자리는 정상이다 — 배포판마다 다르고, 로컬 CA 를 한 번도 더하지
            // 않은 기계에는 `local` 폴더가 비어 있거나 없다.
            continue;
        }
        let w = fs
            .walk(dir, scope.max_files.max(1))
            .map_err(|e| CollectError::Other(e.to_string()))?;
        h.truncated |= w.truncated;
        h.absorb_denied(w.denied, w.denied_paths);
        for e in w.entries {
            if e.is_dir || e.is_reparse {
                continue;
            }
            let Ok(Some(bytes)) = fs.read_file(&e.path, MAX_CERT_BYTES) else {
                continue;
            };
            for der in ders_of(&bytes) {
                let (subject, issuer, not_after) = parse_certificate(&der).unwrap_or_default();
                h.records.push(CertStoreRecord {
                    store: store.to_string(),
                    subject,
                    issuer,
                    thumbprint: thumbprint_of(&der),
                    not_after,
                    linux: Some(remedy_artifacts::record::LinuxCert {
                        path: e.path.clone(),
                    }),
                });
            }
        }
    }
    h.records
        .sort_by(|a, b| (&a.store, &a.thumbprint).cmp(&(&b.store, &b.thumbprint)));
    Ok(h)
}

/// 인증서 파일 하나의 크기 상한. 번들이 아니라면 이보다 클 이유가 없다.
const MAX_CERT_BYTES: u64 = 1 << 20;

#[cfg(test)]
mod tests {
    use super::*;

    /// 길이를 DER 로 적는다.
    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            let n = body.len();
            let bytes = n.to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
            let used = &bytes[first..];
            out.push(0x80 | used.len() as u8);
            out.extend_from_slice(used);
        }
        out.extend_from_slice(body);
        out
    }

    fn name(cn: &str, o: &str) -> Vec<u8> {
        let mut rdns = Vec::new();
        for (oid, val) in [([0x55u8, 0x04, 0x03], cn), ([0x55u8, 0x04, 0x0A], o)] {
            let mut atv = der(0x06, &oid);
            atv.extend_from_slice(&der(0x0C, val.as_bytes()));
            rdns.extend_from_slice(&der(0x31, &der(0x30, &atv)));
        }
        der(0x30, &rdns)
    }

    fn certificate(cn: &str, issuer_cn: &str, not_after: &[u8], time_tag: u8) -> Vec<u8> {
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&der(0xA0, &der(0x02, &[2]))); // version
        tbs.extend_from_slice(&der(0x02, &[0x01])); // serial
        tbs.extend_from_slice(&der(0x30, &der(0x06, &[0x2A, 0x86, 0x48]))); // sigalg
        tbs.extend_from_slice(&name(issuer_cn, "발급자"));
        let mut validity = der(0x17, b"260101000000Z");
        validity.extend_from_slice(&der(time_tag, not_after));
        tbs.extend_from_slice(&der(0x30, &validity));
        tbs.extend_from_slice(&name(cn, "주체"));
        let mut cert = der(0x30, &tbs);
        cert.extend_from_slice(&der(0x03, &[0, 1])); // signature
        der(0x30, &cert)
    }

    fn blob(der_cert: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // 앞에 다른 속성 하나를 둔다 — 첫 항목만 보는 구현을 걸러 낸다.
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&[9, 9, 9, 9]);
        out.extend_from_slice(&CERT_PROP_ID.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(der_cert.len() as u32).to_le_bytes());
        out.extend_from_slice(der_cert);
        out
    }

    #[test]
    fn subject_issuer_and_expiry_come_out_of_the_der() {
        let cert = certificate("악성 루트", "악성 루트", b"301231235959Z", 0x17);
        let raw = blob(&cert);
        let der_cert = der_of_blob(&raw).expect("blob 안의 인증서");
        let (subject, issuer, not_after) = parse_certificate(der_cert).expect("파싱");
        assert_eq!(subject, "CN=악성 루트, O=주체");
        assert_eq!(issuer, "CN=악성 루트, O=발급자");
        assert_eq!(not_after, "2030-12-31T23:59:59Z");
    }

    #[test]
    fn a_two_digit_year_follows_rfc5280_not_the_obvious_guess() {
        // 뒤집으면 2049년 만료가 1949년으로 읽혀 `lt` 비교가 거짓말을 한다.
        assert_eq!(
            render_time(0x17, b"490101000000Z").unwrap(),
            "2049-01-01T00:00:00Z"
        );
        assert_eq!(
            render_time(0x17, b"500101000000Z").unwrap(),
            "1950-01-01T00:00:00Z"
        );
    }

    #[test]
    fn a_generalized_time_keeps_its_four_digit_year() {
        let cert = certificate("X", "Y", b"20501231235959Z", 0x18);
        let (_, _, not_after) = parse_certificate(&cert[..]).expect("파싱");
        assert_eq!(not_after, "2050-12-31T23:59:59Z");
    }

    #[test]
    fn the_certificate_property_is_found_even_when_it_is_not_first() {
        let cert = certificate("A", "B", b"301231235959Z", 0x17);
        assert!(der_of_blob(&blob(&cert)).is_some());
    }

    #[test]
    fn a_lying_length_in_the_blob_is_refused() {
        let mut b = Vec::new();
        b.extend_from_slice(&CERT_PROP_ID.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        b.extend_from_slice(&[1, 2, 3]);
        assert!(der_of_blob(&b).is_none(), "거짓말한 길이를 그대로 믿었다");
    }

    #[test]
    fn both_distro_families_have_a_place_a_hand_added_ca_lands() {
        // **`local` 이 없는 계열이 있으면 그 배포판 전체가 안 보인다.**
        //
        // 2026-09-05 까지 `CERT_DIRS` 는 Debian 계열의 두 자리뿐이었고,
        // rpm 계열(Fedora·RHEL·Rocky·openSUSE)에는 그 두 디렉터리가 아예
        // 없다. 신뢰 저장소에 심어진 루트 CA 를 겨누는 룰이 그 배포판에서
        // 조용히 0건이 됐다 — 청정 코퍼스를 Fedora 로 넓히며 드러났다.
        //
        // 계열이 늘면 여기가 먼저 깨지며 자리를 더하라고 말한다.
        let local: Vec<&str> = CERT_DIRS
            .iter()
            .filter(|(s, _)| *s == "local")
            .map(|(_, d)| *d)
            .collect();
        assert!(
            local
                .iter()
                .any(|d| d.contains("/usr/local/share/ca-certificates")),
            "Debian 계열의 손으로 더한 CA 자리가 없다: {local:?}"
        );
        assert!(
            local.iter().any(|d| d.contains("/etc/pki/ca-trust")),
            "rpm 계열의 손으로 더한 CA 자리가 없다 — 그 배포판 전체가 보이지 않는다: {local:?}"
        );
        // 지울 줄만 알고 볼 줄 모르면 "제거했다" 가 거짓이 된다. 그 반대도 같다.
        assert!(
            crate::certstore::CERT_DIRS
                .iter()
                .any(|(_, d)| d.contains("pki")),
            "update-ca-trust 는 부르면서 그 계열의 자리는 보지 않는다"
        );
    }

    #[test]
    fn every_store_name_we_emit_is_in_the_catalog() {
        // **닫힌 집합이 두 군데에 있으면 갈라진다.**
        //
        // 저장소 이름을 정하는 것은 이 파일의 `STORES` 와 `CERT_DIRS` 인데,
        // 작성자가 보는 값 전수는 SDK 카탈로그의 `ENUMERATED_FIELDS` 다.
        // 그 둘을 맞춰 주는 것이 없었고, 그래서 **`local` 이 빠져 있었다.**
        //
        // 빠진 값이 하필 `/usr/local/share/ca-certificates` — 소스가
        // *"악성 루트 CA 가 들어오는 자리"* 라 부르는 그곳이었다.
        // `defined: true` 라 그 값을 쓰면 **린트 오류**가 났고, 대신 목록에
        // 있던 `system` 을 쓰면 조용히 0건이 됐다. 우리 `tls-intercept` 정답
        // 플러그인이 정확히 그 길로 갔고, 합성 스냅샷이 같은 거짓 값을 담고
        // 있어 2026-09-04 실기기 스냅샷으로 바꾸기 전까지 드러나지 않았다.
        let f = remedy_sdk::catalog::EnumeratedField::lookup(
            remedy_sdk::catalog::Subject::CertStore,
            "store",
        )
        .expect("cert_store.store 는 값 전수가 있는 필드다");
        for name in STORES.iter().chain(CERT_DIRS.iter().map(|(n, _)| n)) {
            assert!(
                f.values.contains(name),
                "수집기가 내는 store 값 '{name}' 이 카탈로그에 없다. \
                 작성자가 그 값을 쓰면 린트가 막고, 목록에 있는 다른 값을 쓰면 \
                 조용히 0건이 된다"
            );
        }
    }

    #[test]
    fn a_truncated_certificate_is_dropped_not_a_panic() {
        // 조작된 인증서 하나로 수집이 멈추면 안 된다.
        let cert = certificate("A", "B", b"301231235959Z", 0x17);
        for cut in 0..cert.len() {
            let _ = parse_certificate(&cert[..cut]);
        }
        for cut in 0..40 {
            let _ = der_of_blob(&blob(&cert)[..cut]);
        }
    }
}
