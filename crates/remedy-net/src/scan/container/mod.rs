//! 컨테이너 점검 — 이 기계의 컨테이너 엔진(Docker · Podman)에 읽기 요청만 보내 실행 중인 컨테이너의 파일에서
//! PHP · Node.js 를 찾아 판정한다.
//!
//! 사내 runtime-scanner 의 `internal/containers` 를 옮기는 자리다. 이 뼈대는 명령(`remedy-net container`)이 부르는
//! 꼴만 정한다 — 몸은 옮기는 중이고, 그 전에는 부르면 멈춘다.

use super::budget::Budget;
use super::model::{Product, Target};
use super::rules::RuleSet;
use remedy_sdk::i18n::Lang;

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
    let _ = (endpoint, ids, lang);
    unimplemented!("remedy-net container 의 몸은 옮기는 중이다")
}

/// 실행 중인 컨테이너 목록 — 점검하지 않는다.
pub fn list(endpoint: &str, budget: &Budget, lang: Lang) -> Result<Vec<Listed>, String> {
    let _ = (endpoint, budget, lang);
    unimplemented!("remedy-net container 의 몸은 옮기는 중이다")
}

/// ID 마다 대상 하나(엔진에 닿지 못하면 그 까닭을 단 대상 하나). 끝낸 대상은 `done` 으로 바로 넘기고, 끝내지 못한
/// 대상의 지금 모양은 [`Budget::record_target`] 으로 남긴다. 돌려주는 대상은 모두 `finalize` 를 마친 것이다.
pub fn scan(req: &Request<'_>, budget: &Budget, done: &mut dyn FnMut(&Target)) -> Vec<Target> {
    let _ = (req, budget, done);
    unimplemented!("remedy-net container 의 몸은 옮기는 중이다")
}
