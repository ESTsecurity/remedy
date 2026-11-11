//! 컨테이너 점검 — 이 기계의 컨테이너 엔진(Docker · Podman)에 읽기 요청만 보내 실행 중인 컨테이너의 파일에서
//! PHP · Node.js 를 찾아 판정한다.
//!
//! 사내 runtime-scanner(`d3acb38`)의 `internal/containers` 를 옮겼다. 스캐너와 다른 것은 하나다 — 리눅스에서 소켓
//! 활성화로 띄운 표준 설치에 접속하는 조건([`endpoint::linux`] 의 머리말, 2026-11-10 결정).
//!
//! **엔진에 닿는 길은 다섯뿐이다**([`client`]): `GET /version` · `GET /containers/json` ·
//! `GET /containers/{id}/json` · `GET /images/{id}/json` · 파일 하나의 `HEAD`/`GET /containers/{id}/archive`.
//! 명령을 실행하거나 무엇을 바꾸는 API 는 허용 목록에 없다. 엔진이 꺼져 있으면 띄우지 않는다([`endpoint`]).
//!
//! 차례는 엔진 확인 → API 판 맞추기 → 컨테이너마다(정보 → 이미지 ID → 배포판 → 패키지 기록 → PHP → Node.js →
//! 세션 설정)다. 끝낸 컨테이너는 바로 넘기고(`done`), 길게 읽는 일 앞에서는 지금 모양을 예산에 남긴다 — 실행 시한 ·
//! Ctrl+C 로 멈춰도 확인된 취약은 보고된다.
//!
//! **양호를 내지 않는다.** 읽을 수 있는 파일만 보므로 다른 설치 자리 · 실행 중인 모든 프로세스를 다 보았다고 할 수
//! 없다 — 제품마다 그 한계를 늘 *보지 못한 것* 으로 적고, 그래서 결과는 많아야 *확인 필요* 다.
//!
//! 한도: 요청 128회 · 받는 양 256 MiB(초당 10 MiB) · JSON 하나 8 MiB · 파일 하나 256 MiB(앞부분 8 MiB 만 남김) ·
//! 패키지 DB 64 MiB · 배포판 기록 64 KiB · `.list` · 설정 파일 4 MiB · RPM 쓰기 로그 0 바이트 · 후보 PHP 64 ·
//! Node.js 4096 · PATH 디렉터리 32 · 설정 파일 8개. 이 모듈은 파일을 쓰지 않는다.

mod archive;
mod client;
mod codec;
mod endpoint;
mod failure;
mod files;
mod gostr;
mod inspect;
mod local;
mod node;
mod packages;
mod paths;
mod php;
mod phpconf;
mod process;
mod record;
mod rpm;
mod wire;

#[cfg(test)]
pub(crate) mod tests;

use super::budget::Budget;
use super::model::{Product, Target, TargetKind};
use super::rules::RuleSet;
use client::Client;
use endpoint::{Endpoint, RealHost};
use failure::Failure;
use local::Local;
use record::{finalize_container_target, record_partial};
use remedy_sdk::i18n::Lang;
use std::collections::HashSet;

/// 점검 한 번의 조건.
pub struct Request<'a> {
    /// 엔진 주소 — [`validate_selection`] 을 지난 글 그대로.
    pub endpoint: &'a str,
    /// 사용자가 준 컨테이너 ID(적은 차례 · 16진수 12~64자). 50개 상한은 이미 확인했다.
    pub ids: &'a [String],
    /// 고른 제품(`Php` · `Node`).
    pub products: &'a [Product],
    pub rules: &'a RuleSet,
    pub lang: Lang,
}

/// `--list` 의 한 줄.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// 전체 ID(16진수 64자).
    pub id: String,
    pub name: String,
}

/// 이 OS 의 기본 엔진 주소.
pub fn default_endpoint() -> &'static str {
    if cfg!(windows) {
        "npipe:////./pipe/docker_engine"
    } else {
        "unix:///var/run/docker.sock"
    }
}

/// 엔진에 닿기 전에 하는 꼴 검사 — 엔진 주소의 꼴과 ID 의 꼴. 거절 문장은 실행 언어로.
pub fn validate_selection(endpoint: &str, ids: &[String], lang: Lang) -> Result<(), String> {
    endpoint::parse(endpoint).map_err(|f| f.message(lang))?;
    if ids.iter().any(|id| !paths::container_id(id)) {
        return Err(lang
            .t(
                "컨테이너 ID 는 목록에 나온 값(소문자 16진수)의 앞 12자리 이상을 적으십시오.",
                "give at least the first 12 characters of a container ID as listed (lowercase hex).",
            )
            .to_string());
    }
    Ok(())
}

/// 실행 중인 컨테이너 목록 — 점검하지 않는다.
pub fn list(endpoint: &str, budget: &Budget, lang: Lang) -> Result<Vec<Listed>, String> {
    let local = Local::open(endpoint, Box::new(RealHost::new())).map_err(|f| f.message(lang))?;
    let mut c = Client::new(budget, &local, lang);
    c.kind = Some(local.kind());
    discover(&mut c).map_err(|f| f.message(lang))
}

/// 판을 맞추고 목록을 읽는다 — 실행 중이고 ID 의 꼴이 맞는 것만(줄마다 항목 하나를 센다).
fn discover(c: &mut Client<'_>) -> Result<Vec<Listed>, Failure> {
    c.negotiate()?;
    let listed = inspect::summaries(&c.json("/containers/json")?)?;
    let mut out = Vec::new();
    for item in listed {
        c.budget.count_entry()?;
        if item.state != "running" || !paths::container_id(&item.id) {
            continue;
        }
        let name = match item.names.first() {
            Some(n) => n.strip_prefix('/').unwrap_or(n).to_string(),
            None => item.id.clone(),
        };
        out.push(Listed { id: item.id, name });
    }
    Ok(out)
}

/// ID 마다 대상 하나(엔진에 닿지 못하면 그 까닭을 단 대상 하나). 끝낸 대상은 `done` 으로 바로 넘기고, 끝내지 못한
/// 대상의 지금 모양은 [`Budget::record_target`] 으로 남긴다. 돌려주는 대상은 모두 `finalize` 를 마친 것이다.
pub fn scan(req: &Request<'_>, budget: &Budget, done: &mut dyn FnMut(&Target)) -> Vec<Target> {
    let products = selected_products(req.products);
    let local = match Local::open(req.endpoint, Box::new(RealHost::new())) {
        Ok(local) => local,
        Err(f) => {
            let mut t = Target::new(
                "container:endpoint",
                TargetKind::Container,
                req.endpoint,
                products,
            );
            t.add_gap(f.message(req.lang));
            t.add_scope(req.lang.t(
                "명시한 로컬 컨테이너 엔진",
                "the given local container engine",
            ));
            return vec![finish(budget, t, req.lang, done)];
        }
    };
    let mut c = Client::new(budget, &local, req.lang);
    c.kind = Some(local.kind());
    if matches!(endpoint::parse(req.endpoint), Ok(Endpoint::Unix(_))) {
        c.host = Some(local.host());
    }
    scan_with(&mut c, req, done)
}

fn selected_products(products: &[Product]) -> &[Product] {
    if products.is_empty() {
        &[Product::Php]
    } else {
        products
    }
}

/// 엔진을 확인한 뒤의 점검 — 시험은 지은 엔진을 넣는다.
pub(crate) fn scan_with(
    c: &mut Client<'_>,
    req: &Request<'_>,
    done: &mut dyn FnMut(&Target),
) -> Vec<Target> {
    let (lang, products) = (req.lang, selected_products(req.products));
    if let Err(f) = c.negotiate() {
        let mut t = Target::new(
            "container:api-version",
            TargetKind::Container,
            req.endpoint,
            products,
        );
        t.add_gap(f.message(lang));
        return vec![finish(c.budget, t, lang, done)];
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for id in req.ids {
        if !seen.insert(id.as_str()) {
            continue;
        }
        let t = scan_one(c, req.rules, products, id);
        out.push(finish(c.budget, t, lang, done));
    }
    if out.is_empty() {
        let mut t = Target::new(
            "container:selection",
            TargetKind::Container,
            lang.t("컨테이너 선택", "container selection"),
            products,
        );
        t.add_gap(lang.t(
            "선택한 실행 중 컨테이너가 없습니다.",
            "No running container was selected.",
        ));
        out.push(finish(c.budget, t, lang, done));
    }
    out
}

/// 대상을 올리고 남기고 넘긴다.
fn finish(budget: &Budget, mut t: Target, lang: Lang, done: &mut dyn FnMut(&Target)) -> Target {
    finalize_container_target(&mut t, lang);
    budget.record_target(&t);
    done(&t);
    t
}

/// 컨테이너 하나 — 정보를 읽고, 실행 중인 그 컨테이너인지 확인하고, 파일을 읽는다.
fn scan_one(c: &mut Client<'_>, rules: &RuleSet, products: &[Product], id: &str) -> Target {
    let lang = c.lang;
    let mut t = Target::new(
        format!("container:{id}"),
        TargetKind::Container,
        id,
        products,
    );
    t.add_scope(lang.t(
        "실행 중 컨테이너의 개별 패키지 정보 파일과 확인된 실행 파일 경로",
        "individual package record files and confirmed executable paths of the running container",
    ));
    if !paths::container_id(id) {
        let (ko, en) = (
            "컨테이너는 목록에서 확인한 ID 로만 고를 수 있습니다.",
            "A container can be chosen only by an ID confirmed in the list.",
        );
        t.add_gap(lang.t(ko, en));
        return t;
    }
    let inspected = match c
        .json(&format!("/containers/{id}/json"))
        .and_then(|v| inspect::inspect(&v))
    {
        Ok(i) => i,
        Err(f) => {
            let why = f.message(lang);
            t.add_gap(lang.pick(
                format!("컨테이너 정보를 읽지 못했습니다: {why}"),
                format!("The container information could not be read: {why}"),
            ));
            return t;
        }
    };
    let matches = inspected.id.starts_with(id) && paths::container_id(&inspected.id);
    if !matches || !inspected.running {
        let (ko, en) = (
            "고른 ID 와 맞는 실행 중 컨테이너를 확인하지 못했습니다.",
            "No running container matching the chosen ID was confirmed.",
        );
        t.add_gap(lang.t(ko, en));
        return t;
    }
    let id = inspected.id.clone();
    identify(c, &mut t, &id, &inspected);
    record_partial(c, &t);
    check_image(c, &mut t, &inspected.image);
    files::scan_container_files(c, &mut t, &id, &inspected, rules, products);
    t
}

/// 확인한 컨테이너의 이름과 알아보는 값.
fn identify(c: &Client<'_>, t: &mut Target, id: &str, inspected: &inspect::Inspect) {
    t.id = format!("container:{id}");
    t.name = inspected
        .name
        .strip_prefix('/')
        .unwrap_or(&inspected.name)
        .to_string();
    if t.name.is_empty() {
        t.name = id.to_string();
    }
    let m = &mut t.metadata;
    m.insert("container_id".into(), id.to_string());
    m.insert("engine_api_version".into(), c.api_version.clone());
    m.insert("engine_os".into(), c.engine_os.clone());
    m.insert("image_id".into(), inspected.image.clone());
}

/// 컨테이너가 적은 이미지 ID 를 엔진에 다시 묻는다 — 꼴이 맞을 때만.
fn check_image(c: &mut Client<'_>, t: &mut Target, image: &str) {
    let lang = c.lang;
    if !paths::image_id(image) {
        let (ko, en) = (
            "이미지의 SHA-256 ID 를 확인하지 못했습니다.",
            "The image's SHA-256 ID was not confirmed.",
        );
        t.add_gap(lang.t(ko, en));
        return;
    }
    match c
        .json(&format!("/images/{image}/json"))
        .and_then(|v| inspect::image_id(&v))
    {
        Err(f) => {
            let why = f.message(lang);
            t.add_gap(lang.pick(
                format!("이미지 식별 정보를 확인하지 못했습니다: {why}"),
                format!("The image identity could not be confirmed: {why}"),
            ));
        }
        Ok(found) if found != image => {
            let (ko, en) = (
                "컨테이너에 기록된 이미지 ID 와 조회한 이미지 ID 가 다릅니다.",
                "The image ID recorded for the container differs from the image ID returned.",
            );
            t.add_gap(lang.t(ko, en));
        }
        Ok(_) => {}
    }
}
