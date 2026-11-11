//! 실행 이미지 하나 — 설정과 레이어로 최종 파일 구성을 짓고 판정한다(스캐너의 `runImage`).
//!
//! 설정이 플랫폼 · 레이어 해시를 다 말하지 않거나 레이어 하나라도 대조에 실패하면, 그 이미지에서는 아무것도
//! 판정하지 않는다 — 덜 덮인 아래 레이어는 최종 구성이 아니다. Linux 가 아닌 이미지는 패키지 정보를 다 확인할 수
//! 없어 늘 *보지 못한 것* 이 하나 붙고, 판정은 공식 빌드의 해시로만 나온다.

use super::config;
use super::layer::{self, LayerSpec};
use super::meta::ImageConfig;
use super::rootfs::RootFs;
use super::source::Source;
use super::{base_target, record, Cx};
use crate::scan::budget::MAX_LAYERS;
use crate::scan::model::Target;

/// 이미지 하나를 짓고 판정한다. `id` 는 대상 번호의 꼬리(매니페스트 다이제스트 · docker save 의 차례).
pub(super) fn run(
    src: &Source<'_>,
    input: &str,
    id: &str,
    cfg: &ImageConfig,
    layers: &[LayerSpec],
    cx: &Cx<'_>,
) -> Target {
    let lang = cx.lang;
    let mut t = base_target(input, id, lang);
    t.init_products(cx.products);
    let mut platform = format!("{}/{}", cfg.os, cfg.architecture);
    if !cfg.variant.is_empty() {
        platform = format!("{platform}/{}", cfg.variant);
    }
    t.metadata.insert("platform".into(), platform.clone());
    t.metadata.insert("layers".into(), layers.len().to_string());
    t.name = format!("{input} [{platform}]");
    t.add_scope(lang.pick(
        format!("플랫폼: {platform}"),
        format!("platform: {platform}"),
    ));
    build(src, &mut t, cfg, layers, cx);
    config::append_finding(
        &mut t,
        &[],
        &[lang
            .t(
                "최종 이미지 구성을 읽지 못해 설정을 확인하지 못했습니다.",
                "The final image layout could not be read, so the settings were not checked.",
            )
            .to_string()],
        false,
        lang,
    );
    t.finalize(lang);
    t
}

fn build(src: &Source<'_>, t: &mut Target, cfg: &ImageConfig, layers: &[LayerSpec], cx: &Cx<'_>) {
    let lang = cx.lang;
    let incomplete = cfg.os.is_empty()
        || cfg.architecture.is_empty()
        || cfg.rootfs.kind != "layers"
        || cfg.rootfs.diff_ids.len() != layers.len();
    if incomplete {
        t.add_gap(lang.t(
            "플랫폼 또는 레이어 해시 정보가 빠졌거나 서로 맞지 않습니다",
            "the platform or layer digest information is missing or inconsistent",
        ));
        return;
    }
    if layers.len() > MAX_LAYERS as usize {
        t.add_gap(lang.t(
            "이미지 레이어 256개 제한을 넘었습니다",
            "the image exceeds the limit of 256 layers",
        ));
        return;
    }
    let mut fs = RootFs {
        case_insensitive: cfg.os == "windows",
        ..RootFs::default()
    };
    config::configure_paths(&mut fs, &cfg.config.env);
    fs.loader_override = cfg.config.env.iter().any(|v| {
        ["LD_LIBRARY_PATH=", "LD_PRELOAD=", "LD_AUDIT="]
            .iter()
            .any(|p| v.starts_with(p))
    });
    // 레이어를 덮는 동안 멈추면 이 대상은 *끝내지 못함* 으로 보고된다 — 아래 레이어의 판정은 싣지 않는다.
    record(cx, t);
    for spec in layers {
        if let Err(halt) = cx.budget.count_layer() {
            t.add_gap(halt.message(lang));
            return;
        }
        if let Err(why) = layer::apply(src, &mut fs, spec, cx) {
            t.add_gap(lang.pick(
                format!("레이어 {}: {why}", spec.name),
                format!("layer {}: {why}", spec.name),
            ));
            return;
        }
    }
    if cfg.os != "linux" {
        t.add_gap(lang.t(
            "Linux 가 아닌 이미지의 패키지 정보는 완전하게 확인할 수 없습니다",
            "package information of a non-Linux image cannot be fully confirmed",
        ));
    }
    super::packages::inspect(&fs, t, cx);
    if let Err(halt) = cx.budget.check() {
        t.add_gap(halt.message(lang));
    }
}
