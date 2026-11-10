//! 이미지 파일 점검 — OCI 레이아웃 · OCI 아카이브 · docker save 의 최종 파일 구성에서 PHP · Node.js 를 찾아
//! 판정한다.
//!
//! 사내 runtime-scanner 의 `internal/images` 를 옮기는 자리다. 이 뼈대는 명령(`remedy-net image`)이 부르는 꼴만
//! 정한다 — 몸은 옮기는 중이고, 그 전에는 부르면 멈춘다.

use super::budget::Budget;
use super::model::{Product, Target};
use super::rules::RuleSet;
use remedy_sdk::i18n::Lang;
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

/// 입력마다(다중 플랫폼이면 플랫폼마다) 대상 하나. 끝낸 대상은 `done` 으로 바로 넘기고, 끝내지 못한 대상의 지금
/// 모양은 [`Budget::record_target`] 으로 남긴다. 돌려주는 대상은 모두 `finalize` 를 마친 것이다.
pub fn scan(req: &Request<'_>, budget: &Budget, done: &mut dyn FnMut(&Target)) -> Vec<Target> {
    let _ = (req, budget, done);
    unimplemented!("remedy-net image 의 몸은 옮기는 중이다")
}
