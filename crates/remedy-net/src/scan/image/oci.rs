//! OCI 레이아웃 — `oci-layout` · `index.json` 에서 매니페스트를 따라가 실행 이미지마다 대상 하나를 낸다(스캐너의
//! `scanOCI`).
//!
//! 플랫폼을 고르지 않는다 — 인덱스가 서술한 실행 이미지를 모두 본다. 하위 인덱스는 8 단까지 따라가고 순환하면
//! 멈춘다. 매니페스트는 대상과 제외한 attestation 을 합쳐 256개까지다. 읽지 못하거나 해시 · 크기 · 플랫폼이 맞지
//! 않는 매니페스트는 그 다이제스트의 실패 대상이 된다.

use super::layer::LayerSpec;
use super::meta::{
    decode, digest_path, read_descriptor, Descriptor, ImageConfig, Index, Layout, Manifest,
    METADATA_LIMIT,
};
use super::source::Source;
use super::{attest, failed_target, record, Cx};
use crate::scan::budget::IMAGE_LIMIT;
use crate::scan::model::Target;
use std::collections::{BTreeMap, BTreeSet};

const MAX_MANIFESTS: usize = 256;
const MAX_INDEX_DEPTH: usize = 8;

pub(super) fn scan(src: &Source<'_>, input: &str, cx: &Cx<'_>) -> Vec<Target> {
    let lang = cx.lang;
    let one = |why: String| vec![failed_target(input, "", why, lang)];
    let layout = match src.read("oci-layout", METADATA_LIMIT) {
        Ok(data) => data,
        Err(why) => return one(why),
    };
    if !decode::<Layout>(&layout, lang).is_ok_and(|l| l.version == "1.0.0") {
        return one(lang
            .t(
                "지원하지 않거나 손상된 OCI 레이아웃 버전입니다",
                "unsupported or damaged OCI layout version",
            )
            .to_string());
    }
    let data = match src.read("index.json", METADATA_LIMIT) {
        Ok(data) => data,
        Err(why) => return one(why),
    };
    let index = match decode::<Index>(&data, lang) {
        Ok(i) if i.schema_version == 2 && !i.manifests.is_empty() => i,
        _ => {
            return one(lang
                .t(
                    "OCI index.json 이 비어 있거나 손상됐습니다",
                    "the OCI index.json is empty or damaged",
                )
                .to_string())
        }
    };
    let mut walk = Walk {
        src,
        input,
        cx,
        targets: Vec::new(),
        excluded: 0,
        limited: false,
        active: BTreeSet::new(),
        claims: BTreeMap::new(),
    };
    for d in &index.manifests {
        walk.claims.insert(d.digest.clone(), d.clone());
    }
    for d in &index.manifests {
        walk.visit(d, 0);
    }
    walk.finish()
}

struct Walk<'s, 'b> {
    src: &'s Source<'b>,
    input: &'s str,
    cx: &'s Cx<'s>,
    targets: Vec<Target>,
    excluded: usize,
    limited: bool,
    /// 지금 따라가는 하위 인덱스(순환 검사).
    active: BTreeSet<String>,
    /// 인덱스들이 서술한 매니페스트 — attestation 의 대상을 확인할 때 쓴다.
    claims: BTreeMap<String, Descriptor>,
}

impl Walk<'_, '_> {
    fn fail(&mut self, digest: &str, why: String) {
        self.targets
            .push(failed_target(self.input, digest, why, self.cx.lang));
    }

    fn visit(&mut self, d: &Descriptor, depth: usize) {
        let lang = self.cx.lang;
        if self.targets.len() + self.excluded >= MAX_MANIFESTS {
            self.limited = true;
            return;
        }
        if depth > MAX_INDEX_DEPTH || self.active.contains(&d.digest) {
            let why = lang.t(
                "OCI 인덱스가 순환하거나 깊이 제한을 넘었습니다",
                "the OCI index loops or exceeds the depth limit",
            );
            return self.fail(&d.digest, why.to_string());
        }
        let data = match read_descriptor(self.src, d, lang) {
            Ok(data) => data,
            Err(why) => return self.fail(&d.digest, why),
        };
        match d.media_type.as_str() {
            "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json" => {
                self.sub_index(d, &data, depth)
            }
            "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json" => self.manifest(d, &data),
            other => {
                let why = lang.pick(
                    format!("지원하지 않는 OCI 매니페스트 형식입니다: {other}"),
                    format!("unsupported OCI manifest format: {other}"),
                );
                self.fail(&d.digest, why)
            }
        }
    }

    fn sub_index(&mut self, d: &Descriptor, data: &[u8], depth: usize) {
        let lang = self.cx.lang;
        let sub = match decode::<Index>(data, lang) {
            Ok(i) if i.schema_version == 2 && !i.manifests.is_empty() => i,
            _ => {
                let why = lang.t(
                    "하위 OCI 인덱스가 손상됐습니다",
                    "a nested OCI index is damaged",
                );
                return self.fail(&d.digest, why.to_string());
            }
        };
        self.active.insert(d.digest.clone());
        for child in &sub.manifests {
            self.claims.insert(child.digest.clone(), child.clone());
        }
        for child in &sub.manifests {
            self.visit(child, depth + 1);
        }
        self.active.remove(&d.digest);
    }

    fn manifest(&mut self, d: &Descriptor, data: &[u8]) {
        let lang = self.cx.lang;
        let m = match decode::<Manifest>(data, lang) {
            Ok(m) if m.schema_version == 2 => m,
            _ => {
                let why = lang.t(
                    "OCI 이미지 매니페스트가 손상됐습니다",
                    "an OCI image manifest is damaged",
                );
                return self.fail(&d.digest, why.to_string());
            }
        };
        if attest::candidate(d, &m) {
            match attest::verify(self.src, d, &m, &self.claims, lang) {
                Ok(()) => self.excluded += 1,
                Err(why) => {
                    let why = lang.pick(
                        format!("attestation 검증 실패: {why}"),
                        format!("attestation check failed: {why}"),
                    );
                    self.fail(&d.digest, why);
                }
            }
            return;
        }
        match self.image(d, &m) {
            Ok(t) => {
                record(self.cx, &t);
                self.targets.push(t);
            }
            Err(why) => self.fail(&d.digest, why),
        }
    }

    /// 실행 이미지의 설정과 레이어를 확인하고 짓는다.
    fn image(&self, d: &Descriptor, m: &Manifest) -> Result<Target, String> {
        let lang = self.cx.lang;
        let config_type = m.config.media_type.as_str();
        if config_type != "application/vnd.oci.image.config.v1+json"
            && config_type != "application/vnd.docker.container.image.v1+json"
        {
            return Err(lang
                .t(
                    "실행 이미지가 아닌 OCI 산출물이거나 알 수 없는 설정 형식입니다",
                    "an OCI artifact that is not a runtime image, or an unknown config format",
                )
                .to_string());
        }
        let cfg_data = read_descriptor(self.src, &m.config, lang)?;
        let cfg: ImageConfig = decode(&cfg_data, lang)?;
        let p = &d.platform;
        let differs = (!p.os.is_empty() && p.os != cfg.os)
            || (!p.architecture.is_empty() && p.architecture != cfg.architecture)
            || (!p.variant.is_empty() && p.variant != cfg.variant);
        if differs {
            return Err(lang
                .t(
                    "OCI 인덱스와 설정의 플랫폼 정보가 다릅니다",
                    "the platform in the OCI index differs from the config",
                )
                .to_string());
        }
        let layers = layer_specs(m, &cfg, lang)?;
        let mut t = super::assemble::run(self.src, self.input, &d.digest, &cfg, &layers, self.cx);
        t.metadata
            .insert("manifest_digest".into(), d.digest.clone());
        let reference = d.annotations.get("org.opencontainers.image.ref.name");
        if !reference.is_empty() {
            t.metadata.insert("reference".into(), reference.to_string());
        }
        Ok(t)
    }

    fn finish(mut self) -> Vec<Target> {
        let lang = self.cx.lang;
        if self.limited {
            let why = lang.t(
                "이미지 매니페스트 256개 제한에 닿았습니다",
                "the limit of 256 image manifests was reached",
            );
            self.fail("index-limit", why.to_string());
        }
        if self.targets.is_empty() {
            let why = lang.t(
                "점검할 실행 이미지가 없습니다",
                "there is no runtime image to check",
            );
            self.fail("no-runtime", why.to_string());
        }
        if self.excluded > 0 {
            let reason = lang.t(
                "해시와 in-toto 내용, 실행하지 않는 설정을 확인한 SBOM · 빌드 증명 자료는 런타임 점검 대상에서 뺐습니다",
                "SBOM and build provenance data whose digests, in-toto content and non-runtime config were checked were left out of the runtime check",
            );
            for t in &mut self.targets {
                t.metadata
                    .insert("excluded_attestations".into(), self.excluded.to_string());
                t.metadata
                    .insert("excluded_attestation_reason".into(), reason.to_string());
            }
        }
        self.targets
    }
}

/// 매니페스트의 레이어 — 다이제스트 · 크기 · 형식을 확인하고 설정의 diffID 를 차례로 붙인다.
fn layer_specs(
    m: &Manifest,
    cfg: &ImageConfig,
    lang: remedy_sdk::i18n::Lang,
) -> Result<Vec<LayerSpec>, String> {
    let mut layers = Vec::with_capacity(m.layers.len());
    for (i, layer) in m.layers.iter().enumerate() {
        let name = digest_path(&layer.digest, lang)?;
        if layer.size < 0 || layer.size as u64 > IMAGE_LIMIT || !supported_layer(&layer.media_type)
        {
            return Err(lang
                .t(
                    "지원하지 않는 레이어 형식이거나 크기가 잘못됐습니다",
                    "an unsupported layer format or an invalid size",
                )
                .to_string());
        }
        layers.push(LayerSpec {
            name,
            digest: layer.digest.clone(),
            media_type: layer.media_type.clone(),
            diff_id: cfg.rootfs.diff_ids.get(i).cloned().unwrap_or_default(),
            size: layer.size,
        });
    }
    Ok(layers)
}

fn supported_layer(media: &str) -> bool {
    matches!(
        media,
        "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.oci.image.layer.v1.tar+zstd"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
            | "application/vnd.docker.image.rootfs.diff.tar"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip"
            | "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
    )
}
