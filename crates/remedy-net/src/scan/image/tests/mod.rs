//! 사내 runtime-scanner `internal/images` 의 시험을 옮겼다. 시험마다 doc 주석에 원래 이름을 적는다.
//!
//! - 서명한 기준 대신 JSON 기준을 [`crate::scan::rules::RuleSet::from_json`] 으로 읽는다. 스캐너의 옛 형식(PHP 만
//!   있던 1판) 픽스처는 같은 줄을 2판에 옮겼다.
//! - 판정 글은 이 크레이트의 규칙이 낸다 — 스캐너의 글귀를 찾던 자리는 같은 뜻의 이 크레이트 글귀나 판정으로 본다.
//! - `TestStaticELFDependenciesRequireCompleteDynamicData` 는 실행 파일 머리 해석과 함께 `scan::binary` 에 옮겨 있다.
//! - 스캐너의 SQLite · 헤더 판독기 안쪽을 부르던 RPM 시험은 같은 DB 를 지어 이미지 쪽 입구(`rpm::parse`)로 본다.

mod attestation;
mod fixtures;
mod images;
mod legacy;
mod node;
mod phpconfig;
mod qualification;
mod rpm;
mod rpm_limits;
mod source;
mod units;
