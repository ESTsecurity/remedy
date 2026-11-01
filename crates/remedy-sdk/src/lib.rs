//! remedy-sdk — **스키마 단일 소스** (설계-09 P1).
//!
//! subject 19종 · Op 29종 · 연산자 15종 · 매니페스트 키 · 아티팩트 봉투 4종 ·
//! 종료 코드 7종이 여기서 한 번만 정의되고, `plugin.schema.json` 과 카탈로그는
//! 여기서 **생성된다.**
//!
//! # 정의는 전부, 구현은 점진적으로
//!
//! 모든 항목에 `implemented_in` 이 붙는다. 설계-09 §3 의 매트릭스와 같은 값이어야
//! 하고, `cargo xtask trace` 가 그 일치를 검사한다. 정의를 미루면 나중에 스키마를
//! 바꾸게 되고, 스키마가 바뀌면 이미 작성된 플러그인이 깨진다.
#![forbid(unsafe_code)]

pub mod artifact;
pub mod catalog;
pub mod generate;
pub mod i18n;
pub mod lint;
pub mod manifest;
pub mod normalize;
pub mod quarantine;
pub mod validate;

pub use artifact::{
    Action, ActionOutcome, ActionResult, ArtifactKind, ArtifactsBody, ArtifactsEnvelope, Envelope,
    Evidence, ExitCode, PlanBody, PlanEnvelope, ResultBody, ResultEnvelope, ScanBody, ScanEnvelope,
    UserImpact, UserImpactKind,
};
pub use catalog::{
    CaptureFn, DesignatedToken, Op, OpInfo, Operator, OperatorInfo, Phase, Platform, Risk, Subject,
    SubjectInfo, DESIGNATED_TOKENS,
};
pub use lint::{lint, LintIssue, Severity};
pub use manifest::PluginManifest;
pub use quarantine::{EntryKind, EntryKindInfo};
pub use validate::{validate, SchemaIssue};

/// 이 SDK 가 이해하는 `plugin.yaml` 의 `schema_version`.
pub const SCHEMA_VERSION: u32 = 1;

/// 크레이트가 링크되었음을 확인하는 표식 (P0 의 의존 그래프 검증용).
pub const CRATE_NAME: &str = "remedy-sdk";

/// 현재 코어가 실제로 구현한 Phase.
///
/// 이 값보다 뒤 Phase 의 항목을 쓴 플러그인은 "아직 구현되지 않았다" 는 오류를
/// 받는다. 값을 올리는 것은 해당 Phase 의 완료 조건이다.
///
/// # 여기 하나뿐이어야 한다
///
/// 계획기가 같은 뜻의 상수를 따로 들고 있었고(`CURRENT_PHASE`), **실제로
/// 갈라졌다** — 실행기가 `file.quarantine_only` 를 수행하는데 SDK 는 P4 라고
/// 말했다. 그러면 생성물(`catalog.json`·`REFERENCE.md`)이 작성자에게 도구를
/// **실제보다 못하다고** 광고한다. `remedy-plan` 이 이 값을 직접 쓴다.
///
/// # 이 값은 "Phase 가 끝났다" 가 아니다
///
/// 2026-08-25 (P10-C) 에 P8 → P10 으로 올렸다. **P10 이 끝나서가 아니라**
/// P10 에 속한 Op 이 `dir.delete_recursive` 하나뿐이고 그것을 안전하게 만드는
/// 조건(설계-03 §4 조건 3 — 하위 신뢰 서명)이 채워졌기 때문이다. 이 상수가
/// 게이트하는 것은 **Op 카탈로그의 가용성**이지 Phase 의 산출 전체가 아니다.
///
/// **P10 에 Op 을 새로 넣을 때 이 값을 함께 본다.** 넣기만 하면 그 Op 이
/// 곧바로 계획에 들어간다 — 준비되지 않은 채로.
pub const IMPLEMENTED_THROUGH: Phase = Phase::P12;
