//! `image` · `container` 가 함께 쓰는 판정 기반 — 결과 모델 · 한도 · 판정 규칙 · 배포판 식별 · 세션 설정.
//!
//! 사내 runtime-scanner(`d3acb38` · 기준 2026-10-30.12)의 `internal/{model,control,rules,linuxmeta,phpconfig}` 를
//! 옮겼다. 호스트는 본체의 점검 룰이 보고, 여기는 이미지 파일과 컨테이너만 본다 — 같은 기계를 두 도구가 보지
//! 않는다. 그래서 판정 규칙과 기준 데이터가 이 크레이트 안에 따로 있고, 호스트 룰과 겹치는 값(수정 버전 · 공식
//! 빌드 해시)은 시험이 룰 파일과 대조한다.

pub mod budget;
pub mod linuxmeta;
pub mod model;
pub mod phpconfig;
pub mod rules;
