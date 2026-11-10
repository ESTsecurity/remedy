//! 이미지 메타데이터 — OCI 인덱스 · 매니페스트 · 설정과 docker save 의 `manifest.json`, 그리고 sha256 다이제스트.
//!
//! 칸과 JSON 이름은 스캐너의 Go 구조체 그대로이고, 읽는 규칙은 [`super::json`] 이 Go 의 판독기를 따른다.

use super::json::{self, fields, record, Decode, JResult, Json, JsonError, KeySet, Raw, StrMap};
use super::source::Source;
use remedy_sdk::i18n::Lang;
use sha2::{Digest, Sha256};

/// 메타데이터 파일 하나의 상한.
pub(super) const METADATA_LIMIT: u64 = 4 << 20;

type Res<T> = Result<T, String>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Platform {
    pub(super) os: String,
    pub(super) architecture: String,
    pub(super) variant: String,
}

impl Decode for Platform {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(
            j,
            |j, k| fields!(j, k, "os" => self.os, "architecture" => self.architecture, "variant" => self.variant),
        )
    }
}

/// OCI 서술자.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Descriptor {
    pub(super) media_type: String,
    pub(super) data: String,
    pub(super) digest: String,
    pub(super) size: i64,
    pub(super) platform: Platform,
    pub(super) annotations: StrMap,
}

impl Decode for Descriptor {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(j, |j, k| {
            fields!(j, k,
                "mediaType" => self.media_type,
                "data" => self.data,
                "digest" => self.digest,
                "size" => self.size,
                "platform" => self.platform,
                "annotations" => self.annotations,
            )
        })
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct Index {
    pub(super) schema_version: i64,
    pub(super) media_type: String,
    pub(super) manifests: Vec<Descriptor>,
}

impl Decode for Index {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(j, |j, k| {
            fields!(j, k,
                "schemaVersion" => self.schema_version,
                "mediaType" => self.media_type,
                "manifests" => self.manifests,
            )
        })
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct Manifest {
    pub(super) schema_version: i64,
    pub(super) media_type: String,
    pub(super) artifact_type: String,
    pub(super) subject: Option<Box<Descriptor>>,
    pub(super) config: Descriptor,
    pub(super) layers: Vec<Descriptor>,
}

impl Decode for Manifest {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(j, |j, k| {
            fields!(j, k,
                "schemaVersion" => self.schema_version,
                "mediaType" => self.media_type,
                "artifactType" => self.artifact_type,
                "subject" => self.subject,
                "config" => self.config,
                "layers" => self.layers,
            )
        })
    }
}

/// 이미지 설정 가운데 보는 칸.
#[derive(Debug, Clone, Default)]
pub(super) struct ImageConfig {
    pub(super) config: RunConfig,
    pub(super) os: String,
    pub(super) architecture: String,
    pub(super) variant: String,
    pub(super) rootfs: RootFsSection,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RunConfig {
    pub(super) env: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RootFsSection {
    pub(super) kind: String,
    pub(super) diff_ids: Vec<String>,
}

impl Decode for ImageConfig {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(j, |j, k| {
            fields!(j, k,
                "config" => self.config,
                "os" => self.os,
                "architecture" => self.architecture,
                "variant" => self.variant,
                "rootfs" => self.rootfs,
            )
        })
    }
}

impl Decode for RunConfig {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(j, |j, k| fields!(j, k, "Env" => self.env))
    }
}

impl Decode for RootFsSection {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(
            j,
            |j, k| fields!(j, k, "type" => self.kind, "diff_ids" => self.diff_ids),
        )
    }
}

/// docker save 의 `manifest.json` 한 줄(Go 구조체에 꼬리표가 없어 칸 이름이 곧 키다).
#[derive(Debug, Clone, Default)]
pub(super) struct DockerManifest {
    pub(super) config: String,
    pub(super) repo_tags: Vec<String>,
    pub(super) layers: Vec<String>,
}

impl Decode for DockerManifest {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(
            j,
            |j, k| fields!(j, k, "Config" => self.config, "RepoTags" => self.repo_tags, "Layers" => self.layers),
        )
    }
}

/// `oci-layout`.
#[derive(Debug, Clone, Default)]
pub(super) struct Layout {
    pub(super) version: String,
}

impl Decode for Layout {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(
            j,
            |j, k| fields!(j, k, "imageLayoutVersion" => self.version),
        )
    }
}

/// in-toto 문서 가운데 보는 칸.
#[derive(Debug, Clone, Default)]
pub(super) struct Statement {
    pub(super) kind: String,
    pub(super) predicate_type: String,
    pub(super) predicate: Raw,
    pub(super) subjects: Vec<Subject>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct Subject {
    pub(super) digest: StrMap,
}

impl Decode for Statement {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(j, |j, k| {
            fields!(j, k,
                "_type" => self.kind,
                "predicateType" => self.predicate_type,
                "predicate" => self.predicate,
                "subject" => self.subjects,
            )
        })
    }
}

impl Decode for Subject {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(j, |j, k| fields!(j, k, "digest" => self.digest))
    }
}

/// attestation 의 설정 — Go 구조체의 칸 이름(`OS` · `Architecture` · `Variant` · `Config`)이 곧 키다.
#[derive(Debug, Clone, Default)]
pub(super) struct AttestationConfig {
    pub(super) os: String,
    pub(super) architecture: String,
    pub(super) variant: String,
    pub(super) config: KeySet,
    pub(super) rootfs: RootFsSection,
}

impl Decode for AttestationConfig {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        record(j, |j, k| {
            fields!(j, k,
                "OS" => self.os,
                "Architecture" => self.architecture,
                "Variant" => self.variant,
                "Config" => self.config,
                "rootfs" => self.rootfs,
            )
        })
    }
}

/// JSON 값 하나(스캐너의 `decodeJSON`). 오류는 종류만 문장으로 남긴다.
pub(super) fn decode<T: Decode + Default>(data: &[u8], lang: Lang) -> Res<T> {
    json::decode(data).map_err(|e| {
        let (ko, en) = match e {
            JsonError::Syntax => (
                "이미지 JSON 의 문법이 올바르지 않습니다",
                "the image JSON is malformed",
            ),
            JsonError::Type => (
                "이미지 JSON 칸의 값 형식이 올바르지 않습니다",
                "a field in the image JSON has the wrong type",
            ),
            JsonError::Trailing => (
                "이미지 JSON 뒤에 추가 데이터가 있습니다",
                "there is extra data after the image JSON",
            ),
        };
        lang.t(ko, en).to_string()
    })
}

/// `sha256:<소문자 16진수 64자>` 의 블롭 경로(스캐너의 `digestPath`).
pub(super) fn digest_path(digest: &str, lang: Lang) -> Res<String> {
    let Some(hex) = digest
        .strip_prefix("sha256:")
        .filter(|_| digest.len() == 71)
    else {
        return Err(lang
            .t(
                "sha256 형식이 아닌 이미지 해시는 지원하지 않습니다",
                "image digests other than sha256 are not supported",
            )
            .to_string());
    };
    if !hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(lang
            .t(
                "sha256 이미지 해시가 잘못됐습니다",
                "invalid sha256 image digest",
            )
            .to_string());
    }
    Ok(format!("blobs/sha256/{hex}"))
}

/// `sha256:<16진수>` 다이제스트.
pub(super) fn sha256_digest(data: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(data)))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 내용이 그 다이제스트인가(스캐너의 `verifyDigest`).
pub(super) fn verify_digest(data: &[u8], digest: &str, lang: Lang) -> Res<()> {
    digest_path(digest, lang)?;
    if sha256_digest(data) != digest {
        return Err(lang
            .t(
                "이미지 sha256 해시가 일치하지 않습니다",
                "the image sha256 digest does not match",
            )
            .to_string());
    }
    Ok(())
}

/// 서술자가 가리키는 메타데이터 — 크기와 해시가 서술자와 같아야 한다(스캐너의 `readDescriptor`).
pub(super) fn read_descriptor(src: &Source<'_>, d: &Descriptor, lang: Lang) -> Res<Vec<u8>> {
    let name = digest_path(&d.digest, lang)?;
    let too_big = || {
        lang.t(
            "이미지 메타데이터 크기 제한을 넘었습니다",
            "image metadata exceeds the size limit",
        )
        .to_string()
    };
    if d.size < 0 || d.size as u64 > METADATA_LIMIT {
        return Err(too_big());
    }
    let data = src.read(&name, METADATA_LIMIT)?;
    if data.len() as i64 != d.size {
        return Err(lang
            .t(
                "이미지 메타데이터 크기가 선언과 다릅니다",
                "the image metadata size differs from its declaration",
            )
            .to_string());
    }
    verify_digest(&data, &d.digest, lang)?;
    Ok(data)
}
