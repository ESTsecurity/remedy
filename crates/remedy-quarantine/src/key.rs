//! 콘텐츠 키와 그것을 감싸는 세 가지 방법 (설계-03 §5).
//!
//! # 왜 감싸는가
//!
//! 로컬 키 하나로 암호화하면 **머신을 재설치하는 순간 격리물이 영구히 열리지
//! 않는다.** 오탐으로 격리된 사용자 문서가 그대로 소실된다는 뜻이고, 이는 도구가
//! 존재하는 이유와 정면으로 충돌한다.
//!
//! 그래서 컨테이너마다 무작위 **콘텐츠 키**를 만들고, 그 키를 여러 방법으로 감싸
//! 헤더에 함께 둔다. 하나라도 열리면 컨테이너가 열린다.
//!
//! ```text
//!   content_key (컨테이너마다 무작위)
//!      +-- local : 이 머신의 키          -> 같은 머신에서 즉시 (기본)
//!      +-- pass  : 사용자 패스프레이즈   -> 머신과 무관
//!      +-- org   : 조직 복구 공개키      -> 재설치 후에도 (기업 배포)
//! ```
//!
//! # 정직한 한계
//!
//! 패스프레이즈 wrap 을 쓸 때만 실질적 기밀성이 생긴다. 그 외에는 **봉인**이다 —
//! 감염 호스트에서 관리자 권한을 가진 악성코드는 로컬 키 파일에 접근할 수 있다.
//! 설계-03 §5 가 이것을 문서와 UI 에 그대로 쓰라고 요구한다.

use crate::QuarantineError;
use base64::Engine;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// XChaCha20-Poly1305 의 논스 길이. 192비트라 **컨테이너마다 난수로 뽑아도
/// 재사용 위험이 없다** — AEAD 사고의 대부분이 논스 재사용이고, 카운터를
/// 관리하는 설계는 재설치·복원·병렬 실행에서 그 관리가 깨진다.
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

pub const CIPHER_ID: &str = "xchacha20poly1305";

/// 컨테이너 하나를 여는 대칭 키. **쓰고 나면 지운다.**
///
/// `Drop` 만으로는 컴파일러가 지우기를 없앨 수 있어 `zeroize` 를 쓴다.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ContentKey([u8; KEY_LEN]);

impl ContentKey {
    /// 새 콘텐츠 키. 컨테이너마다 새로 만든다.
    pub fn generate() -> Result<Self, QuarantineError> {
        let mut k = [0u8; KEY_LEN];
        fill_random(&mut k)?;
        Ok(Self(k))
    }

    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&self.0).into())
    }

    /// 봉인. `aad` 는 인증만 되고 암호화되지 않는다 — 평문 헤더를 여기 넣어
    /// 헤더 변조가 인증을 통과하지 못하게 한다.
    pub fn seal(&self, plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, QuarantineError> {
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;
        let ct = self
            .cipher()
            .encrypt(&XNonce::from(nonce), Payload { msg: plain, aad })
            .map_err(|_| QuarantineError::crypto("봉인 실패", "sealing failed"))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// 개봉. 인증에 실패하면 **내용을 돌려주지 않는다.**
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, QuarantineError> {
        if sealed.len() < NONCE_LEN {
            return Err(QuarantineError::corrupt(
                "봉인 블록이 논스보다 짧습니다",
                "the sealed block is shorter than the nonce",
            ));
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| {
            QuarantineError::corrupt("논스 길이가 다릅니다", "the nonce length differs")
        })?;
        self.cipher()
            .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad })
            .map_err(|_| {
                QuarantineError::crypto(
                    "개봉 실패 — 키가 다르거나 변조됐습니다",
                    "opening failed — wrong key, or tampered",
                )
            })
    }
}

/// 콘텐츠 키를 감싼 슬롯 하나. **평문 헤더에 있다** — 키 없이도 "내가 이것을
/// 열 수 있는가" 를 판단해야 하기 때문이다 (설계-02 §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapSlot {
    pub kind: WrapKind,
    /// 어느 키로 감쌌는가. **사람이 읽는 이름이 아니라 지문이다** — 호스트
    /// 이름을 평문에 두지 않기 위해서다 (설계-03 §5).
    pub key_id: String,
    pub alg: String,
    /// 종류마다 다른 공개 파라미터 (salt · eph_pk). 전부 base64.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    /// 감싼 콘텐츠 키. base64.
    pub ct: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WrapKind {
    /// 이 머신의 키. 기본 경로이고, **이것만 있으면 재설치 시 열 수 없다.**
    Local,
    /// 사용자 패스프레이즈. 실질적 기밀성이 생기는 유일한 경로.
    Pass,
    /// 조직 복구 공개키. 감염 호스트에 개인키가 없으므로 훔칠 것이 없다.
    Org,
}

impl WrapKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WrapKind::Local => "local",
            WrapKind::Pass => "pass",
            WrapKind::Org => "org",
        }
    }
}

fn kek_seal(kek: &[u8; KEY_LEN], content: &ContentKey) -> Result<String, QuarantineError> {
    // wrap 은 헤더가 아직 없는 시점에 만들어지므로 AAD 가 없다. 대신 wrap 자체가
    // 컨테이너 밖에서는 의미가 없고, 헤더 변조는 본문 AEAD 가 잡는다.
    let sealed = ContentKey(*kek).seal(&content.0, b"remedy.wrap.v1")?;
    Ok(B64.encode(sealed))
}

fn kek_open(kek: &[u8; KEY_LEN], ct_b64: &str) -> Result<ContentKey, QuarantineError> {
    let sealed = B64.decode(ct_b64).map_err(|_| {
        QuarantineError::corrupt("wrap 이 base64 가 아닙니다", "the wrap is not base64")
    })?;
    let plain = ContentKey(*kek).open(&sealed, b"remedy.wrap.v1")?;
    let arr: [u8; KEY_LEN] = plain.as_slice().try_into().map_err(|_| {
        QuarantineError::corrupt(
            "wrap 안의 키 길이가 다릅니다",
            "the key length inside the wrap differs",
        )
    })?;
    Ok(ContentKey(arr))
}

fn fingerprint(material: &[u8], domain: &str) -> String {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(material);
    hex16(&h.finalize())
}

fn hex16(bytes: &[u8]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

// ────────────────────────────────────────────────── local

/// 이 머신의 키. 없으면 만든다.
///
/// 설계-03 §5 는 기본 모드를 **기밀성이 아니라 봉인**으로 규정한다 — 감염
/// 호스트의 관리자 권한 악성코드는 이 파일에 닿을 수 있다. 그것을 감추려 하지
/// 않고 문서에 그대로 쓴다. 봉인의 목적은 (1) 격리물 재실행 방지, (2) 타 백신의
/// 재탐지 혼선 방지, (3) 우발적 유출 완화다.
pub struct MachineKey([u8; KEY_LEN]);

impl Drop for MachineKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl MachineKey {
    pub fn load_or_create(path: &std::path::Path) -> Result<Self, QuarantineError> {
        if let Ok(b) = std::fs::read(path) {
            if b.len() == KEY_LEN {
                let mut k = [0u8; KEY_LEN];
                k.copy_from_slice(&b);
                return Ok(Self(k));
            }
            // 길이가 다르면 덮어쓰지 않는다. 덮어쓰면 **기존 격리물이 전부
            // 열리지 않게 된다** — 조용히 복구 불가를 만드는 것보다 멈추는 편이 낫다.
            return Err(QuarantineError::corrupt(
                "머신 키 파일의 길이가 다릅니다. 덮어쓰면 기존 격리물을 열 수 없습니다",
                "the machine key file has a different length; overwriting it would make existing quarantines unopenable",
            ));
        }
        let mut k = [0u8; KEY_LEN];
        fill_random(&mut k)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(QuarantineError::Io)?;
        }
        std::fs::write(path, k).map_err(QuarantineError::Io)?;
        Ok(Self(k))
    }

    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }

    pub fn key_id(&self) -> String {
        fingerprint(&self.0, "remedy.machine")
    }

    pub fn wrap(&self, content: &ContentKey) -> Result<WrapSlot, QuarantineError> {
        Ok(WrapSlot {
            kind: WrapKind::Local,
            key_id: self.key_id(),
            alg: CIPHER_ID.into(),
            params: BTreeMap::new(),
            ct: kek_seal(&self.0, content)?,
        })
    }

    pub fn unwrap(&self, slot: &WrapSlot) -> Result<ContentKey, QuarantineError> {
        kek_open(&self.0, &slot.ct)
    }
}

// ────────────────────────────────────────────────── pass

/// Argon2id 파라미터. 메모리 하드라 GPU 대량 시도에 강하다.
pub const KDF_ID: &str = "argon2id";

pub fn wrap_with_passphrase(
    passphrase: &str,
    content: &ContentKey,
) -> Result<WrapSlot, QuarantineError> {
    let mut salt = [0u8; 16];
    fill_random(&mut salt)?;
    let kek = derive_kek(passphrase, &salt)?;
    let mut params = BTreeMap::new();
    params.insert("salt".to_string(), B64.encode(salt));
    Ok(WrapSlot {
        kind: WrapKind::Pass,
        // 패스프레이즈에서 유도한 지문을 두면 사전 공격의 표적이 된다.
        // salt 지문이면 슬롯을 식별하되 비밀은 새지 않는다.
        key_id: fingerprint(&salt, "remedy.pass"),
        alg: format!("{KDF_ID}+{CIPHER_ID}"),
        params,
        ct: kek_seal(&kek, content)?,
    })
}

pub fn unwrap_with_passphrase(
    passphrase: &str,
    slot: &WrapSlot,
) -> Result<ContentKey, QuarantineError> {
    let salt_b64 = slot.params.get("salt").ok_or(QuarantineError::corrupt(
        "pass wrap 에 salt 가 없습니다",
        "the pass wrap has no salt",
    ))?;
    let salt = B64.decode(salt_b64).map_err(|_| {
        QuarantineError::corrupt("salt 가 base64 가 아닙니다", "the salt is not base64")
    })?;
    let kek = derive_kek(passphrase, &salt)?;
    kek_open(&kek, &slot.ct)
}

fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], QuarantineError> {
    let mut kek = [0u8; KEY_LEN];
    argon2::Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|_| {
            QuarantineError::crypto("패스프레이즈 유도 실패", "passphrase derivation failed")
        })?;
    Ok(kek)
}

// ────────────────────────────────────────────────── org

/// 조직 복구 키쌍. **공개키만 배포한다** — 감염 호스트에 개인키가 없으므로
/// 악성코드가 훔칠 것이 없다 (설계-03 §5).
///
/// RSA 를 쓰지 않는 이유는 `deny.toml` 의 RUSTSEC-2023-0071 예외가 "코어가 RSA
/// 개인키를 다루게 되면 즉시 재평가" 를 조건으로 달고 있어서다. 설계-01 미결 5의
/// 서명 후보도 Ed25519 계열이라 같은 곡선군으로 맞춘다.
pub const ORG_ALG: &str = "x25519+hkdf-sha256+xchacha20poly1305";

pub fn wrap_with_org_key(
    org_public: &[u8; 32],
    content: &ContentKey,
) -> Result<WrapSlot, QuarantineError> {
    let eph_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let eph_public = x25519_dalek::PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&x25519_dalek::PublicKey::from(*org_public));

    let kek = hkdf_kek(shared.as_bytes(), eph_public.as_bytes(), org_public)?;
    let mut params = BTreeMap::new();
    params.insert("eph_pk".to_string(), B64.encode(eph_public.as_bytes()));
    Ok(WrapSlot {
        kind: WrapKind::Org,
        key_id: fingerprint(org_public, "remedy.org"),
        alg: ORG_ALG.into(),
        params,
        ct: kek_seal(&kek, content)?,
    })
}

pub fn unwrap_with_org_key(
    org_secret: &[u8; 32],
    slot: &WrapSlot,
) -> Result<ContentKey, QuarantineError> {
    let eph_b64 = slot.params.get("eph_pk").ok_or(QuarantineError::corrupt(
        "org wrap 에 eph_pk 가 없습니다",
        "the org wrap has no eph_pk",
    ))?;
    let eph_bytes: [u8; 32] = B64
        .decode(eph_b64)
        .map_err(|_| {
            QuarantineError::corrupt("eph_pk 가 base64 가 아닙니다", "eph_pk is not base64")
        })?
        .as_slice()
        .try_into()
        .map_err(|_| {
            QuarantineError::corrupt("eph_pk 길이가 다릅니다", "the eph_pk length differs")
        })?;

    let secret = x25519_dalek::StaticSecret::from(*org_secret);
    let org_public = x25519_dalek::PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(eph_bytes));

    let kek = hkdf_kek(shared.as_bytes(), &eph_bytes, org_public.as_bytes())?;
    kek_open(&kek, &slot.ct)
}

/// 조직 키쌍을 만든다. **개인키는 조직이 보관하고 배포하지 않는다.**
pub fn generate_org_keypair() -> Result<([u8; 32], [u8; 32]), QuarantineError> {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok((secret.to_bytes(), public.to_bytes()))
}

fn hkdf_kek(
    shared: &[u8],
    eph_public: &[u8],
    org_public: &[u8],
) -> Result<[u8; KEY_LEN], QuarantineError> {
    // 두 공개키를 info 에 넣어, 같은 shared 가 다른 문맥에서 같은 키를 내지 않게 한다.
    let mut info = Vec::with_capacity(eph_public.len() + org_public.len() + 16);
    info.extend_from_slice(b"remedy.org.wrap.v1");
    info.extend_from_slice(eph_public);
    info.extend_from_slice(org_public);

    let hk = hkdf::Hkdf::<Sha256>::new(None, shared);
    let mut kek = [0u8; KEY_LEN];
    hk.expand(&info, &mut kek)
        .map_err(|_| QuarantineError::crypto("HKDF 확장 실패", "HKDF expand failed"))?;
    Ok(kek)
}

// ────────────────────────────────────────────────── 난수

fn fill_random(buf: &mut [u8]) -> Result<(), QuarantineError> {
    use rand_core::RngCore;
    rand_core::OsRng
        .try_fill_bytes(buf)
        .map_err(|_| QuarantineError::crypto("난수 생성 실패", "random generation failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ck() -> ContentKey {
        ContentKey::from_bytes([7u8; KEY_LEN])
    }

    #[test]
    fn seal_open_round_trips() {
        let k = ck();
        let sealed = k.seal(b"secret", b"aad").unwrap();
        assert_eq!(k.open(&sealed, b"aad").unwrap(), b"secret");
    }

    #[test]
    fn aad_mismatch_is_rejected() {
        // 헤더를 AAD 로 묶는 이유가 이것이다. AAD 가 다르면 열리지 않는다.
        let k = ck();
        let sealed = k.seal(b"secret", b"aad").unwrap();
        assert!(k.open(&sealed, "다른aad".as_bytes()).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let k = ck();
        let mut sealed = k.seal(b"secret", b"aad").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(k.open(&sealed, b"aad").is_err());
    }

    #[test]
    fn nonces_do_not_repeat() {
        // 논스 재사용은 XChaCha 에서도 치명적이다. 난수원이 실제로 도는지 본다.
        let k = ck();
        let a = k.seal(b"x", b"").unwrap();
        let b = k.seal(b"x", b"").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }

    #[test]
    fn machine_key_round_trips() {
        let mk = MachineKey::from_bytes([3u8; KEY_LEN]);
        let content = ContentKey::generate().unwrap();
        let slot = mk.wrap(&content).unwrap();
        assert_eq!(slot.kind, WrapKind::Local);
        let back = mk.unwrap(&slot).unwrap();
        assert_eq!(back.0, content.0);
    }

    #[test]
    fn a_different_machine_key_cannot_open_it() {
        let mk = MachineKey::from_bytes([3u8; KEY_LEN]);
        let other = MachineKey::from_bytes([4u8; KEY_LEN]);
        let content = ContentKey::generate().unwrap();
        let slot = mk.wrap(&content).unwrap();
        assert!(other.unwrap(&slot).is_err());
        assert_ne!(mk.key_id(), other.key_id(), "지문이 키를 구분해야 한다");
    }

    #[test]
    fn passphrase_round_trips() {
        let content = ContentKey::generate().unwrap();
        let slot = wrap_with_passphrase("올바른 말 네 개", &content).unwrap();
        assert_eq!(
            unwrap_with_passphrase("올바른 말 네 개", &slot).unwrap().0,
            content.0
        );
        assert!(unwrap_with_passphrase("틀린 말", &slot).is_err());
    }

    #[test]
    fn passphrase_slot_leaks_nothing_about_the_passphrase() {
        // 같은 패스프레이즈라도 salt 가 달라 슬롯이 달라야 한다. 지문이 패스프레이즈
        // 에서 나오면 사전 공격의 표적이 된다.
        let c = ContentKey::generate().unwrap();
        let a = wrap_with_passphrase("같은 말", &c).unwrap();
        let b = wrap_with_passphrase("같은 말", &c).unwrap();
        assert_ne!(a.key_id, b.key_id);
        assert_ne!(a.ct, b.ct);
    }

    #[test]
    fn org_key_round_trips() {
        let (sk, pk) = generate_org_keypair().unwrap();
        let content = ContentKey::generate().unwrap();
        let slot = wrap_with_org_key(&pk, &content).unwrap();
        assert_eq!(slot.kind, WrapKind::Org);
        assert_eq!(unwrap_with_org_key(&sk, &slot).unwrap().0, content.0);
    }

    #[test]
    fn a_different_org_key_cannot_open_it() {
        let (_, pk) = generate_org_keypair().unwrap();
        let (other_sk, _) = generate_org_keypair().unwrap();
        let content = ContentKey::generate().unwrap();
        let slot = wrap_with_org_key(&pk, &content).unwrap();
        assert!(unwrap_with_org_key(&other_sk, &slot).is_err());
    }

    #[test]
    fn the_org_public_key_alone_cannot_open_it() {
        // 감염 호스트에는 공개키만 있다. 그것으로 열 수 있으면 배포 자체가
        // 위험해진다 — 이 성질이 "공개키만 배포한다" 를 성립시킨다.
        let (_, pk) = generate_org_keypair().unwrap();
        let content = ContentKey::generate().unwrap();
        let slot = wrap_with_org_key(&pk, &content).unwrap();
        // 공개키를 개인키 자리에 넣어 본다.
        assert!(unwrap_with_org_key(&pk, &slot).is_err());
    }
}
