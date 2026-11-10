//! docker save — `manifest.json` 의 이미지마다 대상 하나(스캐너의 `scanDocker`).
//!
//! 설정 파일은 이름이 곧 다이제스트다(`<sha256>.json` · `blobs/sha256/<sha256>`). 그 다이제스트로 내용을 대조한다.
//! 레이어에는 압축 다이제스트 · 크기 · 형식이 적혀 있지 않아 푼 다이제스트(diffID)만 대조하고 압축은 머리로 가린다.

use super::layer::LayerSpec;
use super::meta::{decode, verify_digest, DockerManifest, ImageConfig, METADATA_LIMIT};
use super::source::Source;
use super::{failed_target, record, Cx};
use crate::scan::model::Target;
use crate::scan::slashpath;

const MAX_MANIFESTS: usize = 256;

pub(super) fn scan(src: &Source<'_>, input: &str, cx: &Cx<'_>) -> Vec<Target> {
    let lang = cx.lang;
    let data = match src.read("manifest.json", METADATA_LIMIT) {
        Ok(data) => data,
        Err(why) => return vec![failed_target(input, "", why, lang)],
    };
    let manifests = match decode::<Vec<DockerManifest>>(&data, lang) {
        Ok(m) if !m.is_empty() => m,
        _ => {
            let why = lang.t(
                "Docker manifest.json 이 비어 있거나 손상됐습니다",
                "the Docker manifest.json is empty or damaged",
            );
            return vec![failed_target(input, "", why.to_string(), lang)];
        }
    };
    let mut targets = Vec::new();
    for (i, m) in manifests.iter().enumerate() {
        let id = i.to_string();
        if i >= MAX_MANIFESTS {
            let why = lang.t(
                "이미지 매니페스트 256개 제한을 넘었습니다",
                "the image exceeds the limit of 256 manifests",
            );
            targets.push(failed_target(input, &id, why.to_string(), lang));
            break;
        }
        match image(src, input, &id, m, cx) {
            Ok(t) => {
                record(cx, &t);
                targets.push(t);
            }
            Err(why) => targets.push(failed_target(input, &id, why, lang)),
        }
    }
    targets
}

fn image(
    src: &Source<'_>,
    input: &str,
    id: &str,
    m: &DockerManifest,
    cx: &Cx<'_>,
) -> Result<Target, String> {
    let lang = cx.lang;
    let data = src.read(&m.config, METADATA_LIMIT)?;
    let base = slashpath::base(&m.config);
    let digest = format!("sha256:{}", base.strip_suffix(".json").unwrap_or(base));
    verify_digest(&data, &digest, lang).map_err(|why| {
        lang.pick(
            format!("Docker 설정 파일 해시 확인: {why}"),
            format!("checking the Docker config file digest: {why}"),
        )
    })?;
    let cfg: ImageConfig = decode(&data, lang)?;
    let layers: Vec<LayerSpec> = m
        .layers
        .iter()
        .enumerate()
        .map(|(j, name)| LayerSpec {
            name: name.clone(),
            diff_id: cfg.rootfs.diff_ids.get(j).cloned().unwrap_or_default(),
            size: -1,
            ..LayerSpec::default()
        })
        .collect();
    let mut t = super::assemble::run(src, input, id, &cfg, &layers, cx);
    t.metadata.insert("config_digest".into(), digest);
    if !m.repo_tags.is_empty() {
        t.metadata
            .insert("reference".into(), m.repo_tags.join(", "));
    }
    Ok(t)
}
