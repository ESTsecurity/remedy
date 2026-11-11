//! 스캐너 `internal/containers` 의 시험을 옮겼다 — 각 시험의 이름 위에 원래 이름을 적는다.
//!
//! 엔진은 지은 것이다([`support::Engine`] — 스캐너 시험의 `testRoundTrip`). 시계를 바꿔 끼운 예산이라 초당 10 MiB
//! 맞춤과 30초 시한은 시각으로만 지나간다. 실제 HTTP 가 필요한 시험은 파이프 스레드([`super::wire::link::PumpLink`])
//! 위의 HTTP 로, 시한은 짧게 바꿔 끼워 잰다. 아카이브 · HTTP 틀 · 엔진 확인 · 클라이언트의 시험은 그 모듈 옆에 있다.

pub(crate) mod support;

mod node;
mod php;
mod qualification;
mod rpm;
mod scan;
mod windows;
