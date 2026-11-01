//! remedy-detect — 룰 평가.
//!
//! 입력은 아티팩트 스냅샷뿐이다. `remedy-platform` 을 의존하지 않으며, 그 금지가
//! **플러그인 룰은 시스템에 접근할 수 없다**를 구조적으로 보장한다 (설계-03 §1).
//!
//! YARA 통합을 소유하는 것도 이 크레이트다 — `remedy-yara` 는 여기서만 쓰인다
//! (설계-04 §1). 실제 구현은 P2에서 시작해 P4에서 넓어진다.
#![forbid(unsafe_code)]

pub mod compare;
pub mod eval;
pub mod expr;
pub mod verdict;

pub use eval::{evaluate, pressure, EvalError, RulePressure, Snapshot};

pub const CRATE_NAME: &str = "remedy-detect";

pub use remedy_yara::{RuleRef, RuleSet, YaraError};

/// 링크된 YARA 래퍼의 이름.
pub fn yara_crate_name() -> &'static str {
    remedy_yara::CRATE_NAME
}

/// 엔진이 살아 있는가. `selftest` 가 쓴다.
///
/// P0 에서는 "링크되는가" 를 재는 스파이크였고, P4 에서 실제 룰을 컴파일해
/// 스캔하는 것으로 바뀌었다. 목적은 같다 — **이 바이너리에서 YARA 가 실제로
/// 도는가.** 링크만 확인하면 데드코드 제거가 엔진을 통째로 걷어낸 바이너리도
/// 통과한다.
pub fn yara_self_test() -> YaraSelfTest {
    const RULE: &str = r#"
        rule remedy_self_test {
            strings:
                $marker = "REMEDY-SELF-TEST" ascii
            condition:
                $marker
        }
    "#;
    let rs = RuleSet::compile(&[("selftest.yar".into(), RULE.into())]);
    let r = RuleRef {
        file: "selftest.yar".into(),
        rule: "remedy_self_test".into(),
    };
    YaraSelfTest {
        compiled: rs.failed.is_empty(),
        matched: rs
            .matches(&r, b"payload containing REMEDY-SELF-TEST marker")
            .unwrap_or(false),
        // 맞지 않아야 하는 입력에도 맞으면 엔진이 아니라 상수를 보고 있는 것이다.
        rejected_other: rs.matches(&r, b"nothing here").map(|m| !m).unwrap_or(false),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YaraSelfTest {
    pub compiled: bool,
    pub matched: bool,
    pub rejected_other: bool,
}

impl YaraSelfTest {
    pub fn ok(&self) -> bool {
        self.compiled && self.matched && self.rejected_other
    }
}
