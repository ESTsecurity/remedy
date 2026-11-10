//! 이미지 파일 점검 — OCI 레이아웃 · OCI 아카이브 · docker save 의 최종 파일 구성에서 PHP · Node.js 를 찾아
//! 판정한다.
//!
//! 사내 runtime-scanner 의 `internal/images` 를 옮겼다(HEAD d3acb38). 이미지를 실행하지 않고 레지스트리에 닿지
//! 않는다. 입력마다(다중 플랫폼이면 플랫폼마다) 대상 하나를 낸다.
//!
//! # 엄격하다
//!
//! 이미지는 남이 만든 바이트다. 꼴이 하나라도 어긋나면 그 이미지에서는 아무것도 판정하지 않고 *확인 필요* 로
//! 남긴다 — 역슬래시가 든 이름, 장치 · FIFO, 전역 PAX 머리, 희소 파일, 대상이 지워진 하드 링크, 폴더가 아닌 조상,
//! tar 끝 뒤의 0 이 아닌 바이트, 크기 · 해시가 서술과 다른 블롭. 덜 읽은 파일 구성은 최종 구성이 아니어서, 거기서
//! 찾은 옛 PHP 를 취약으로 보고하지 않는다.
//!
//! # 갈래
//!
//! - 입력: [`source`](경로 규칙은 [`input`]) — 폴더는 그 자리에서, 파일은 작업 폴더 아래에 잠시 풀어서.
//! - 메타데이터: [`oci`] · [`docker`] · [`attest`] · [`meta`](JSON 은 Go 의 규칙대로 [`json`]).
//! - 레이어: [`layer`](tar 는 [`tarball`], 압축은 [`expand`] · [`zstd`]) → [`rootfs`].
//! - 판정: [`packages`](RPM 은 [`rpm`]) → [`php`] · [`node`] · [`config`].

mod assemble;
mod attest;
mod config;
mod docker;
mod expand;
mod fault;
mod input;
mod json;
mod layer;
mod links;
mod meta;
#[cfg(target_os = "linux")]
mod mounts;
mod names;
mod node;
mod oci;
mod packages;
mod php;
mod rootfs;
mod rpm;
mod source;
mod tarball;
mod zstd;

#[cfg(test)]
mod tests;

use super::budget::Budget;
use super::model::{Product, Target, TargetKind};
use super::rules::RuleSet;
use remedy_sdk::i18n::Lang;
use sha2::{Digest, Sha256};
use source::Source;
use std::path::Path;

/// 점검 한 번의 조건.
pub struct Request<'a> {
    /// 사용자가 준 이 기계의 경로들(적은 차례). 명령줄이 비어 있지 않음과 50개 상한은 이미 확인했다.
    pub inputs: &'a [String],
    /// 결과 폴더 — 파일 하나로 받은 이미지는 이 아래 `images-<32자리 16진수>` 에 잠시 풀었다가 돌아가기 전에 지운다.
    pub work_dir: &'a Path,
    /// 고른 제품(`Php` · `Node`).
    pub products: &'a [Product],
    pub rules: &'a RuleSet,
    pub lang: Lang,
}

/// 점검 안에서 함께 쓰는 것.
pub(super) struct Cx<'a> {
    budget: &'a Budget,
    rules: &'a RuleSet,
    lang: Lang,
    products: &'a [Product],
}

/// 입력마다(다중 플랫폼이면 플랫폼마다) 대상 하나. 끝낸 대상은 `done` 으로 바로 넘기고, 끝내지 못한 대상의 지금
/// 모양은 [`Budget::record_target`] 으로 남긴다. 돌려주는 대상은 모두 `finalize` 를 마친 것이다.
pub fn scan(req: &Request<'_>, budget: &Budget, done: &mut dyn FnMut(&Target)) -> Vec<Target> {
    // 스캐너는 제품을 고르지 않은 호출을 PHP 로 본다.
    let products = if req.products.is_empty() {
        vec![Product::Php]
    } else {
        req.products.to_vec()
    };
    let cx = Cx {
        budget,
        rules: req.rules,
        lang: req.lang,
        products: &products,
    };
    let mut out = Vec::new();
    for input in req.inputs {
        for mut t in scan_input(input, req.work_dir, &cx) {
            finish(&mut t, &cx);
            budget.record_target(&t);
            done(&t);
            out.push(t);
        }
    }
    out
}

/// 입력 하나 — 연 뒤 꼴을 가려 읽고, 풀어 둔 것은 돌아가기 전에 지운다.
fn scan_input(input: &str, work_dir: &Path, cx: &Cx<'_>) -> Vec<Target> {
    let lang = cx.lang;
    if let Err(halt) = cx.budget.check() {
        return vec![failed_target(input, "", halt.message(lang), lang)];
    }
    let src = match Source::open(input, work_dir, cx.budget, lang) {
        Ok(src) => src,
        Err(why) => return vec![failed_target(input, "", why, lang)],
    };
    if src.has("oci-layout") || src.has("index.json") {
        oci::scan(&src, input, cx)
    } else if src.has("manifest.json") {
        docker::scan(&src, input, cx)
    } else {
        let why = lang.t(
            "OCI 레이아웃이나 Docker save 의 manifest.json 을 찾지 못했습니다",
            "neither an OCI layout nor a Docker save manifest.json was found",
        );
        vec![failed_target(input, "", why.to_string(), lang)]
    }
}

/// 돌려주기 전 — 고른 제품을 채우고, PHP 가 있는데 세션 설정 항목이 없으면 *확인하지 못함* 으로 더하고, 판정을
/// 낸다.
fn finish(t: &mut Target, cx: &Cx<'_>) {
    let lang = cx.lang;
    t.init_products(cx.products);
    let issue = lang.t(
        "이미지 구성을 끝까지 읽지 못해 설정을 확인하지 못했습니다.",
        "The image layout could not be read to the end, so the settings were not checked.",
    );
    config::append_finding(t, &[], &[issue.to_string()], false, lang);
    t.finalize(lang);
    tidy(t);
}

/// 대상 번호 — `image-` 와 (입력 · 꼬리)의 SHA-256 앞 8바이트.
fn target_id(input: &str, suffix: &str) -> String {
    let h = Sha256::digest(format!("{input}\0{suffix}").as_bytes());
    format!("image-{}", meta::hex(&h[..8]))
}

/// 빈 대상 — 제품은 끝에 채운다.
fn base_target(input: &str, suffix: &str, lang: Lang) -> Target {
    let mut t = Target::new(target_id(input, suffix), TargetKind::Image, input, &[]);
    t.add_scope(lang.t(
        "지정한 로컬 이미지의 최종 파일 구성 및 패키지 정보",
        "the final file layout and package records of the given local image",
    ));
    t
}

/// 이미지 · 매니페스트 하나를 읽지 못한 대상.
fn failed_target(input: &str, suffix: &str, why: String, lang: Lang) -> Target {
    let mut t = base_target(input, suffix, lang);
    t.add_gap(why);
    t.finalize(lang);
    t
}

/// 끝내지 못했을 때 보고할 지금 모양.
fn record(cx: &Cx<'_>, t: &Target) {
    let mut copy = t.clone();
    copy.finalize(cx.lang);
    tidy(&mut copy);
    cx.budget.record_target(&copy);
}

/// 결과에 싣는 글 — 이름에서 옮긴 바이트를 U+FFFD 로([`names`]).
fn tidy(t: &mut Target) {
    let fix = |s: &mut String| *s = names::shown(s);
    let fix_all = |v: &mut Vec<String>| v.iter_mut().for_each(fix);
    fix(&mut t.name);
    fix_all(&mut t.gaps);
    fix_all(&mut t.scope);
    for c in t.products.values_mut() {
        fix_all(&mut c.gaps);
        fix_all(&mut c.scope);
    }
    for f in &mut t.findings {
        fix(&mut f.id);
        for field in [&mut f.path, &mut f.version, &mut f.package] {
            if let Some(s) = field.as_mut() {
                fix(s);
            }
        }
        for e in &mut f.evidence {
            fix(&mut e.source);
            fix(&mut e.detail);
        }
    }
    t.metadata.values_mut().for_each(fix);
}
