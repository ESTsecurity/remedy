//! remedy-trust — 플러그인 서명 검증 (설계-03 §10 G8 · 설계-09 P10).
//!
//! # 판정은 파일을 읽지 않는다
//!
//! 서명 검증은 **판정**이고, 판정은 재현 가능해야 한다. `verify_manifest` 와
//! `check_tree` 가 `std::fs` 를 쓰면 "어느 파일을 읽었는가" 가 판정의 일부가
//! 되어, 시험에서 통과한 것과 현장에서 도는 것이 갈릴 수 있다. 그래서
//! 호출자가 바이트를 가져오고 판정은 **주어진 바이트에 대해서만** 답한다.
//!
//! 디렉터리를 훑는 편의 함수(`collect`)는 따로 있다. 서명하는 쪽과 검증하는
//! 쪽이 트리를 **같은 규칙으로** 읽어야 하기 때문에 같은 크레이트에 둔다
//! (`tree` 모듈 문서).
//!
//! # 무엇을 서명하는가
//!
//! 플러그인은 파일 하나가 아니라 디렉터리다(`plugin.yaml` + `rules/*.yar`).
//! 파일마다 서명하면 **파일을 하나 더 넣는 공격**을 막지 못하므로, 트리 전체를
//! 적은 목록(`MANIFEST`)을 서명하고 목록과 실제 트리를 대조한다.
//!
//! 그래서 이 크레이트가 거부하는 것은 세 가지다 — **바뀐 파일**·**없어진
//! 파일**·**목록에 없는 파일**. 마지막 것이 없으면 서명이 트리를 덮지 못한다.
//!
//! # 서명 방식
//!
//! minisign 포맷이다 (설계-01 미결 5). 검증기
//! (`minisign-verify`)는 **의존성이 0 개**이고, `trusted_comment` 가 서명
//! 대상에 포함되어 플러그인 id·버전·발행시각을 서명 안에 넣을 수 있다.

#![forbid(unsafe_code)]

/// 이 크레이트가 실제로 링크되었음을 확인하는 표식.
///
/// `remedy-core` 의 자기점검이 모든 크레이트에서 이것을 모은다. **서명 검증
/// 크레이트가 빠진 빌드**는 서명을 확인하지 않는 빌드이므로, 그 사실이
/// 자기점검 출력에 드러나야 한다.
pub const CRATE_NAME: &str = "remedy-trust";

use std::collections::BTreeMap;
use std::fmt;

pub mod allowlist;
mod manifest;
pub mod revocation;
mod tree;
pub mod version;

pub use manifest::{Manifest, ManifestEntry};
pub use revocation::{RevocationList, TrustState};
pub use tree::{collect, TreeError, MANIFEST_NAME, SIGNATURE_NAME};
pub use version::Version;

/// 검증에 쓰는 신뢰 앵커. minisign 공개키 하나다.
///
/// **여러 개를 담지 않는다.** 앵커가 여럿이면 "어느 키로 통과했는가" 를 함께
/// 보고해야 하고, 그 보고를 빠뜨리면 폐기된 키로 통과한 것을 알아채지 못한다.
/// 키 교체는 앵커를 바꾸는 일이지 늘리는 일이 아니다.
#[derive(Clone)]
pub struct Anchor {
    key: minisign_verify::PublicKey,
}

impl Anchor {
    /// `minisign.pub` 파일 내용(2줄: 주석 + base64)에서 읽는다.
    pub fn from_public_key_file(text: &str) -> Result<Self, TrustError> {
        let key = minisign_verify::PublicKey::decode(text).map_err(TrustError::Key)?;
        Ok(Self { key })
    }

    /// base64 한 줄에서 읽는다. 바이너리에 내장할 때 쓰는 형태다.
    pub fn from_base64(b64: &str) -> Result<Self, TrustError> {
        let key = minisign_verify::PublicKey::from_base64(b64.trim()).map_err(TrustError::Key)?;
        Ok(Self { key })
    }
}

impl fmt::Debug for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 공개키라 숨길 것은 없지만, 로그에 통째로 찍혀 "어느 키였는지" 를
        // 사람이 눈으로 대조하기 어려워지는 것을 막는다.
        f.write_str("Anchor(minisign)")
    }
}

/// 서명이 확인된 매니페스트.
///
/// **이 값이 존재한다는 것 자체가 서명이 통과했다는 뜻이다.** 실패 경로에서는
/// 만들어지지 않으므로, 호출자가 검증 여부를 따로 기억할 필요가 없다.
#[derive(Debug, Clone)]
pub struct Verified {
    comment: TrustedComment,
    manifest: Manifest,
}

impl Verified {
    /// 서명 안에 들어 있던 주석. **검증을 통과한 뒤에만 읽을 수 있다** —
    /// minisign 은 `trusted_comment` 를 서명 대상에 포함하므로, 여기 담긴
    /// 버전·발행시각은 서명자가 말한 그대로다.
    pub fn comment(&self) -> &TrustedComment {
        &self.comment
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// 실제 트리와 대조한다. `actual` 은 경로 → sha256(소문자 hex).
    ///
    /// 경로는 플러그인 디렉터리 기준 상대경로이고 구분자는 `/` 다 — 같은
    /// 플러그인이 Windows 와 Linux 에서 **같은 서명으로** 통과해야 하기
    /// 때문이다.
    pub fn check_tree(&self, actual: &BTreeMap<String, String>) -> Result<(), TrustError> {
        let mut diffs = Vec::new();

        for e in self.manifest.entries() {
            match actual.get(&e.path) {
                None => diffs.push(TreeDiff::Missing {
                    path: e.path.clone(),
                }),
                Some(got) if !got.eq_ignore_ascii_case(&e.sha256) => {
                    diffs.push(TreeDiff::Modified {
                        path: e.path.clone(),
                        expected: e.sha256.clone(),
                        actual: got.clone(),
                    })
                }
                Some(_) => {}
            }
        }

        for path in actual.keys() {
            if !self.manifest.contains(path) {
                diffs.push(TreeDiff::Extra { path: path.clone() });
            }
        }

        if diffs.is_empty() {
            Ok(())
        } else {
            Err(TrustError::TreeMismatch(diffs))
        }
    }
}

/// 서명에 실려 온 주석. 형식은 우리가 정한다.
///
/// ```text
/// remedy-plugin id=<id> version=<semver> signed=<RFC3339>
/// ```
///
/// **형식을 강제하는 이유**: 이 값으로 역행 금지(낮은 버전 거부)를 판정할
/// 것이기 때문이다. 자유 문자열이면 그 판정이 서지 않는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedComment {
    pub id: String,
    pub version: String,
    pub signed_at: String,
    raw: String,
}

impl TrustedComment {
    /// 서명 주석을 만든다. 서명 도구가 쓴다.
    pub fn render(id: &str, version: &str, signed_at: &str) -> String {
        format!("remedy-plugin id={id} version={version} signed={signed_at}")
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    fn parse(raw: &str) -> Result<Self, TrustError> {
        let body = raw
            .strip_prefix("remedy-plugin ")
            .ok_or_else(|| TrustError::Comment(format!("remedy 서명이 아니다: {raw:?}")))?;

        let mut id = None;
        let mut version = None;
        let mut signed_at = None;
        for tok in body.split_whitespace() {
            let Some((k, v)) = tok.split_once('=') else {
                return Err(TrustError::Comment(format!(
                    "키=값 이 아닌 토큰이 있다: {tok:?}"
                )));
            };
            match k {
                "id" => id = Some(v.to_string()),
                "version" => version = Some(v.to_string()),
                "signed" => signed_at = Some(v.to_string()),
                other => {
                    return Err(TrustError::Comment(format!("모르는 키: {other:?}")));
                }
            }
        }

        let missing = |what: &str| TrustError::Comment(format!("{what} 이(가) 없다: {raw:?}"));
        Ok(Self {
            id: id.ok_or_else(|| missing("id"))?,
            version: version.ok_or_else(|| missing("version"))?,
            signed_at: signed_at.ok_or_else(|| missing("signed"))?,
            raw: raw.to_string(),
        })
    }
}

/// 트리 대조에서 어긋난 자리. **하나만 보고하지 않는다** — 한 건씩 고치며
/// 다시 도는 것보다 전부 보는 편이 낫다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeDiff {
    /// 서명된 목록에 있는데 실제로 없다.
    Missing { path: String },
    /// 내용이 다르다.
    Modified {
        path: String,
        expected: String,
        actual: String,
    },
    /// 실제로 있는데 서명된 목록에 없다 — **파일을 몰래 넣은 경우다.**
    Extra { path: String },
}

impl fmt::Display for TreeDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreeDiff::Missing { path } => write!(f, "{path}: 서명된 파일이 없습니다"),
            TreeDiff::Modified { path, .. } => write!(f, "{path}: 서명 이후 내용이 바뀌었습니다"),
            TreeDiff::Extra { path } => write!(f, "{path}: 서명되지 않은 파일이 들어 있습니다"),
        }
    }
}

#[derive(Debug)]
pub enum TrustError {
    /// 공개키를 읽지 못했다.
    Key(minisign_verify::Error),
    /// 서명 파일을 읽지 못했거나 검증에 실패했다.
    Signature(minisign_verify::Error),
    /// 서명 주석이 우리 형식이 아니다.
    Comment(String),
    /// 매니페스트 본문을 읽지 못했다.
    Manifest(String),
    /// 폐기 목록을 읽지 못했다.
    Revocation(String),
    /// 서명은 맞지만 트리가 다르다.
    TreeMismatch(Vec<TreeDiff>),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // **이 틀은 허용 목록 경로가 함께 쓴다.** `main.rs` 의 `load_allowed` 가
        // `scan`·`run` 에서 앵커를 읽고 목록 서명을 검증하므로, 틀이 한국어면
        // 사유만 영어인 반쪽이 된다.
        use remedy_sdk::i18n::t;
        match self {
            TrustError::Key(e) => write!(
                f,
                "{}: {e}",
                t(
                    "신뢰 앵커(공개키)를 읽지 못했습니다",
                    "the trust anchor (public key) could not be read"
                )
            ),
            TrustError::Signature(e) => write!(
                f,
                "{}: {e}",
                t("서명 검증 실패", "signature verification failed")
            ),
            TrustError::Comment(m) => write!(
                f,
                "{}: {m}",
                t(
                    "서명 주석이 형식에 맞지 않습니다",
                    "the signature comment does not match the format"
                )
            ),
            TrustError::Manifest(m) => write!(
                f,
                "{}: {m}",
                t(
                    "매니페스트를 읽지 못했습니다",
                    "the manifest could not be read"
                )
            ),
            TrustError::Revocation(m) => write!(
                f,
                "{}: {m}",
                t(
                    "폐기 목록을 읽지 못했습니다",
                    "the revocation list could not be read"
                )
            ),
            TrustError::TreeMismatch(diffs) => {
                let n = diffs.len();
                write!(
                    f,
                    "{}",
                    remedy_sdk::i18n::current().pick(
                        format!("서명과 실제 파일이 다릅니다 ({n}건)"),
                        format!("the signature and the actual files differ ({n})"),
                    )
                )?;
                for d in diffs {
                    write!(f, "\n  - {d}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for TrustError {}

/// 매니페스트와 그 서명을 앵커로 검증한다.
///
/// 통과하면 `Verified` 가 나오고, 그것으로만 트리를 대조할 수 있다.
///
pub fn verify_manifest(
    anchor: &Anchor,
    manifest_bytes: &[u8],
    signature_text: &str,
) -> Result<Verified, TrustError> {
    let raw = verify_signed(anchor, manifest_bytes, signature_text)?;
    let comment = TrustedComment::parse(&raw)?;
    let manifest = Manifest::parse(manifest_bytes)?;

    Ok(Verified { comment, manifest })
}

/// 서명을 확인하고 **주석 원문**을 돌려준다.
///
/// 플러그인 매니페스트와 폐기 목록이 같은 문을 쓴다. 서명 검증을 두 번 적으면
/// 한쪽만 고쳐지는 날이 오고, 그날 어느 쪽이 느슨한지 아무도 모른다.
///
/// 돌아온 문자열은 **신뢰할 수 있다** — minisign 은 서명 값과 주석을 함께 다시
/// 서명하고(global signature) `verify` 가 그것까지 확인한다. 확인 전에 읽으면
/// 공격자가 쓴 문자열을 읽는 것이다.
///
/// **레거시 서명은 받지 않는다.** `allow_legacy=false` 로 고정하므로 예전
/// minisign 의 비-prehashed 서명은 거부된다 — 받아 두면 그것이 우회 경로가 된다.
pub(crate) fn verify_signed(
    anchor: &Anchor,
    bytes: &[u8],
    signature_text: &str,
) -> Result<String, TrustError> {
    let sig = minisign_verify::Signature::decode(signature_text).map_err(TrustError::Signature)?;
    anchor
        .key
        .verify(bytes, &sig, false)
        .map_err(TrustError::Signature)?;
    Ok(sig.trusted_comment().to_string())
}

/// sha256 을 소문자 hex 로. 매니페스트가 쓰는 형식이며, 호출자가 트리를
/// 해싱할 때 **같은 함수를 쓰도록** 여기서 내준다.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
