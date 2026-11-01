//! 플러그인 버전 — 비교할 수 있는 형태로만 받는다.
//!
//! # 왜 엄격한가
//!
//! 이 값으로 **폐기와 역행 금지를 판정한다.** 비교가 애매하면 폐기가 빗나가고,
//! 빗나간 폐기는 아무도 알아채지 못한다 — 폐기된 플러그인이 그대로 돌 뿐이다.
//!
//! 그래서 `x.y.z` 세 부분, 전부 10진수만 받는다. `1.2.0-rc1` · `v1.2.0` ·
//! `1.2` 는 전부 거부다. **거부는 판정 불가이고, 판정 불가는 거부로 이어진다**
//! (설계-03 §6 — 확인하지 못한 것을 통과로 읽지 않는다).

use std::cmp::Ordering;
use std::fmt;

/// `major.minor.patch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// `x.y.z` 만 받는다. 다른 것은 전부 `None`.
    pub fn parse(s: &str) -> Option<Self> {
        let mut it = s.split('.');
        let major = part(it.next()?)?;
        let minor = part(it.next()?)?;
        let patch = part(it.next()?)?;
        if it.next().is_some() {
            return None; // 네 번째 조각이 있다
        }
        Some(Self::new(major, minor, patch))
    }
}

/// 한 조각. **빈 문자열과 앞자리 0 을 거부한다** — `1.02.0` 과 `1.2.0` 이 같은
/// 버전으로 읽히면 폐기 목록이 무엇을 가리키는지 사람이 확신할 수 없다.
fn part(s: &str) -> Option<u32> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// 폐기가 겨누는 버전 범위.
///
/// **범위 문법(`>=1.2, <2.0`)을 만들지 않는다.** 파서를 하나 더 두면 그것이
/// 틀릴 자리가 되고, 폐기가 틀리면 조용하다. 실제로 필요한 두 모양만 둔다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    /// 이 버전 하나만.
    Exact(Version),
    /// 이 버전 **미만** 전부. 결함이 어느 판에서 고쳐졌는지 아는 보통의 경우다.
    Below(Version),
}

impl Range {
    pub fn covers(&self, v: Version) -> bool {
        match self {
            Range::Exact(x) => v == *x,
            Range::Below(x) => v.cmp(x) == Ordering::Less,
        }
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Range::Exact(v) => write!(f, "{v}"),
            Range::Below(v) => write!(f, "{v} 미만"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 세_조각_십진수만_받는다() {
        assert_eq!(Version::parse("1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(Version::parse("0.0.0"), Some(Version::new(0, 0, 0)));
        assert_eq!(Version::parse("10.20.30"), Some(Version::new(10, 20, 30)));

        for bad in [
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            "1.2.3-rc1",
            "1.2.3+build",
            "1..3",
            "",
            "1.2.x",
            "1.2.03",
            " 1.2.3",
            "1.2.3 ",
        ] {
            assert!(Version::parse(bad).is_none(), "받아들이면 안 된다: {bad:?}");
        }
    }

    #[test]
    fn 자리마다_비교한다() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(v("1.0.0") < v("1.0.1"));
        assert!(v("1.0.9") < v("1.1.0"));
        assert!(v("1.9.9") < v("2.0.0"));
        // **문자열 비교였다면 뒤집혔을 자리다.** "10" < "9" 이므로 사전순으로는
        // 1.10.0 이 1.9.0 보다 작다고 나온다.
        assert!(v("1.9.0") < v("1.10.0"));
    }

    #[test]
    fn 범위가_겨누는_것() {
        let v = |s: &str| Version::parse(s).unwrap();

        let exact = Range::Exact(v("1.2.0"));
        assert!(exact.covers(v("1.2.0")));
        assert!(!exact.covers(v("1.2.1")));
        assert!(!exact.covers(v("1.1.9")));

        let below = Range::Below(v("1.2.0"));
        assert!(below.covers(v("1.1.9")));
        assert!(below.covers(v("0.0.1")));
        // **경계는 포함하지 않는다.** "1.2.0 에서 고쳤다" 가 곧 "1.2.0 은
        // 괜찮다" 이므로, 여기서 한 칸 틀리면 고친 판까지 폐기한다.
        assert!(!below.covers(v("1.2.0")));
        assert!(!below.covers(v("1.2.1")));
    }
}
