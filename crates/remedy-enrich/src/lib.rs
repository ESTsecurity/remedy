//! remedy-enrich — P0 골격. 구현은 설계-09 §3.1의 소유 Phase에서 이뤄진다.
#![forbid(unsafe_code)]

/// 크레이트가 링크되었음을 확인하는 표식. P0의 의존 그래프 검증용이다.
pub const CRATE_NAME: &str = "remedy-enrich";
