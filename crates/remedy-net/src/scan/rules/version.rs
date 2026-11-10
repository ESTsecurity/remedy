//! 버전 비교 — 상류의 `X.Y.Z` · dpkg 의 버전 · rpm 의 버전, 그리고 *그 공급사의 줄인가* 를 보는 두 규칙.
//!
//! 숫자를 기계 정수로 바꾸지 않는다. 앞의 `0` 을 떼고 길이와 글자로 견주므로 자릿수에 상한이 없고 넘치지
//! 않는다.
//!
//! **dpkg 쪽**(`compare_debian` · `valid_debian` · `ubuntu_line` 과 그 도우미)은 이 크레이트
//! `url/criteria.rs` 의 같은 이름 함수(그 파일의 `core` 부터 `debian_part` 까지)와 같은 구현이다. 그쪽은 URL
//! 점검의 표 안에 닫혀 있어 여기서 부르지 못한다 — 한쪽을 고치면 다른 쪽도 고친다.
//!
//! **rpm 쪽**(`rpm_version_cmp` · `split_evr` · `rpmvercmp`)은 본체 `crates/remedy-detect/src/compare.rs` 의
//! 같은 이름 함수와 같은 구현이다. 동반 모듈은 `remedy-detect` 를 링크하지 않아(설계-04 §1) 부르지 못하고
//! 옮겨 둔다. 스캐너의 rpm 비교(`rules/rpm.go`)는 옮기지 않았다 — 그래서 스캐너와 갈리는 꼴이 있고, 아래
//! 시험이 그 꼴을 하나씩 적어 둔다.

use regex::Regex;
use remedy_sdk::catalog::is_rpm_version;
use std::cmp::Ordering;
use std::sync::OnceLock;

/// 버전 문자열의 상한(바이트). 이보다 길면 견주지 않는다.
pub(super) const MAX_VERSION_BYTES: usize = 256;

// ── 상류 X.Y.Z ───────────────────────────────────────────────────────────

/// `X.Y.Z`(각 1~6자리 숫자)면 세 조각. 꼬리(`RC1` · `-custom`) · 넷째 자리 · 빈 조각이 있으면 아니다 — 사전
/// 공개와 직접 빌드를 수정 버전과 견주지 않으려는 것이다.
pub(super) fn core(v: &str) -> Option<[&str; 3]> {
    let mut it = v.split('.');
    let parts = [it.next()?, it.next()?, it.next()?];
    if it.next().is_some() {
        return None;
    }
    parts
        .iter()
        .all(|p| (1..=6).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
        .then_some(parts)
}

pub(super) fn is_core(v: &str) -> bool {
    core(v).is_some()
}

/// `X.Y.Z` 끼리. 둘 다 [`core`] 를 지난 값일 때 뜻이 있다.
pub(super) fn compare_core(a: &str, b: &str) -> Ordering {
    for (x, y) in a.split('.').zip(b.split('.')) {
        let c = compare_digits(x, y);
        if c.is_ne() {
            return c;
        }
    }
    Ordering::Equal
}

/// 앞의 0 을 떼고 길이 → 사전순으로 견준다(긴 숫자도 넘치지 않는다).
pub(super) fn compare_digits(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

pub(super) fn numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

// ── dpkg ─────────────────────────────────────────────────────────────────

/// 데비안 버전 문자열의 꼴(`[epoch:]upstream[-revision]`)인가.
pub(super) fn valid_debian(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_VERSION_BYTES {
        return false;
    }
    let mut core = s;
    if let Some(i) = core.find(':') {
        if i == 0 || !core[..i].bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        core = &core[i + 1..];
    }
    if !core.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        return false;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".+~:-".contains(&b))
    {
        return false;
    }
    if let Some(i) = core.rfind('-') {
        let revision = &core[i + 1..];
        if i == 0
            || revision.is_empty()
            || !revision
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+~".contains(&b))
        {
            return false;
        }
    }
    true
}

/// 그 버전이 Ubuntu 공지의 패키지 줄에 속하는가 — 수정 버전의 마지막 숫자만 다른 것(`…ubuntu2.27` 과
/// `…ubuntu2.28`)과 그 숫자가 아직 없는 것(`…ubuntu2`)이 같은 줄이다. 모르는 꼬리(PPA · 직접 빌드)는 Ubuntu
/// 의 수정을 물려받지 않는다. ESM 은 상류 버전을 두고 `+esmN` 을 붙이므로, ESM 공지에서만 그 꼬리를 받는다.
pub(super) fn ubuntu_line(version: &str, fixed: &str) -> bool {
    if let Some(i) = fixed.find("+esm") {
        if !numeric(&fixed[i + 4..]) {
            return false;
        }
        let base = match version.find("+esm") {
            Some(j) if numeric(&version[j + 4..]) => &version[..j],
            Some(_) => return false,
            None => version,
        };
        return ubuntu_line(base, &fixed[..i]);
    }
    let Some(i) = fixed.rfind('.') else {
        return version == fixed;
    };
    let prefix = &fixed[..=i];
    if version == &prefix[..prefix.len() - 1] {
        return true;
    }
    match version.strip_prefix(prefix) {
        Some(suffix) => numeric(suffix),
        None => false,
    }
}

/// Debian 이 내는 PHP · 라이브러리 패키지 버전의 꼴 — `[epoch:]X.Y.Z-N[~debRuK | +debRuK][+bM]`. 뒤의 `+bM` 은
/// 다시 짓기만 한 binNMU 다.
fn debian_vendor_version() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?:([0-9]+):)?([0-9]+)\.([0-9]+)\.([0-9]+)-([0-9]+)(?:(~|\+)deb([0-9]+)u([0-9]+))?(?:\+b([0-9]+))?$",
        )
        .expect("Debian 버전 줄의 정규식")
    })
}

fn group<'h>(c: &regex::Captures<'h>, i: usize) -> &'h str {
    c.get(i).map_or("", |m| m.as_str())
}

/// 그 버전이 Debian 공지의 패키지 줄에 속하는가. 패키지 체크섬과 관리자 칸은 다른 곳에서 다시 지은 빌드를
/// 가려 주지 않으므로 버전의 꼴로 줄을 지킨다 — 꼴이 다르거나, 계열(`X.Y`)이 다르거나, 배포판 표식(`debR`)이
/// 다르면 그 공지의 줄이 아니다.
///
/// epoch 이 기준보다 높아도 줄이 아니다. 검토하지 않은 새 epoch 이 옛 상류 버전을 수정 버전 위로 올려
/// *양호* 를 만들 수 있기 때문이다.
pub(super) fn debian_vendor_line(version: &str, fixed: &str) -> bool {
    let re = debian_vendor_version();
    let (Some(v), Some(f)) = (re.captures(version), re.captures(fixed)) else {
        return false;
    };
    // 없는 epoch 은 빈 문자열로 온다 — 앞의 0 을 떼고 견주므로 `0` 과 같다.
    if compare_digits(group(&v, 1), group(&f, 1)).is_gt()
        || compare_digits(group(&v, 2), group(&f, 2)).is_ne()
        || compare_digits(group(&v, 3), group(&f, 3)).is_ne()
    {
        return false;
    }
    let marked = !group(&v, 6).is_empty();
    !(marked && (group(&v, 6) != group(&f, 6) || group(&v, 7) != group(&f, 7)))
}

/// dpkg 의 버전 비교 — epoch → 상류 → 개정. `~` 는 무엇보다 앞선다.
pub(super) fn compare_debian(a: &str, b: &str) -> Ordering {
    let (ae, au, ar) = split_debian(a);
    let (be, bu, br) = split_debian(b);
    compare_digits(ae, be)
        .then_with(|| debian_part(au, bu))
        .then_with(|| debian_part(ar, br))
}

fn split_debian(s: &str) -> (&str, &str, &str) {
    let (epoch, rest) = match s.find(':') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => ("0", s),
    };
    match rest.rfind('-') {
        Some(i) => (epoch, &rest[..i], &rest[i + 1..]),
        None => (epoch, rest, "0"),
    }
}

fn order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

fn debian_part(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() || !b.is_empty() {
        while a.first().is_some_and(|c| !c.is_ascii_digit())
            || b.first().is_some_and(|c| !c.is_ascii_digit())
        {
            let c = order(a.first().copied()).cmp(&order(b.first().copied()));
            if c.is_ne() {
                return c;
            }
            a = a.get(1..).unwrap_or_default();
            b = b.get(1..).unwrap_or_default();
        }
        let i = a.iter().take_while(|c| c.is_ascii_digit()).count();
        let j = b.iter().take_while(|c| c.is_ascii_digit()).count();
        let (x, y) = (
            std::str::from_utf8(&a[..i]).unwrap_or_default(),
            std::str::from_utf8(&b[..j]).unwrap_or_default(),
        );
        let c = compare_digits(x, y);
        if c.is_ne() {
            return c;
        }
        a = &a[i..];
        b = &b[j..];
    }
    Ordering::Equal
}

// ── rpm ──────────────────────────────────────────────────────────────────

/// RPM 이 적은 버전끼리. `[epoch:]버전[-개정]` 을 셋으로 갈라 **epoch → 버전 → 개정** 순으로 [`rpmvercmp`] 로
/// 견준다. epoch 이 없으면 `0` 이고, 개정은 **둘 다 있을 때만** 견준다. 꼴이 아니면 `None` 이다
/// (`remedy_sdk::catalog::is_rpm_version`).
pub(super) fn rpm_version_cmp(a: &str, b: &str) -> Option<Ordering> {
    if !is_rpm_version(a) || !is_rpm_version(b) {
        return None;
    }
    let (ea, va, ra) = split_evr(a.trim());
    let (eb, vb, rb) = split_evr(b.trim());
    let mut ord = rpmvercmp(ea, eb).then_with(|| rpmvercmp(va, vb));
    if let (Some(ra), Some(rb)) = (ra, rb) {
        ord = ord.then_with(|| rpmvercmp(ra, rb));
    }
    Some(ord)
}

/// 개정(`-` 뒤)이 있는가 — [`rpm_version_cmp`] 가 읽는 그대로.
pub(super) fn rpm_has_release(s: &str) -> bool {
    split_evr(s.trim()).2.is_some()
}

/// `1:8.0.30-8.el9_8.1` → `("1", "8.0.30", Some("8.el9_8.1"))`. 개정은 **마지막** `-` 뒤이고, 비면 없는 것이다.
fn split_evr(s: &str) -> (&str, &str, Option<&str>) {
    let (epoch, rest) = match s.split_once(':') {
        Some((e, rest)) => (e, rest),
        None => ("0", s),
    };
    match rest.rsplit_once('-') {
        Some((v, r)) => (epoch, v, (!r.is_empty()).then_some(r)),
        None => (epoch, rest, None),
    }
}

/// rpm 의 `rpmvercmp` — 글자 · 숫자가 아닌 문자는 **구분자로만** 보고, 숫자 덩어리와 글자 덩어리를 번갈아
/// 견준다. 숫자 덩어리는 수로 보고(앞의 `0` 은 값이 아니다) **글자 덩어리보다 늘 높다.** `~` 는 무엇보다도
/// 먼저, `^` 는 끝보다는 뒤이고 다른 무엇보다는 먼저다.
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    use std::cmp::Ordering::{Equal, Greater, Less};
    if a == b {
        return Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let sep = |c: u8| !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    let (mut i, mut j) = (0usize, 0usize);
    loop {
        while i < a.len() && sep(a[i]) {
            i += 1;
        }
        while j < b.len() && sep(b[j]) {
            j += 1;
        }
        let (x, y) = (a.get(i).copied(), b.get(j).copied());
        if x == Some(b'~') || y == Some(b'~') {
            if x != Some(b'~') {
                return Greater;
            }
            if y != Some(b'~') {
                return Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if x == Some(b'^') || y == Some(b'^') {
            if x.is_none() {
                return Less;
            }
            if y.is_none() {
                return Greater;
            }
            if x != Some(b'^') {
                return Greater;
            }
            if y != Some(b'^') {
                return Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if x.is_none() || y.is_none() {
            break;
        }
        let (si, sj) = (i, j);
        let numeric = a[i].is_ascii_digit();
        let take = |c: u8| {
            if numeric {
                c.is_ascii_digit()
            } else {
                c.is_ascii_alphabetic()
            }
        };
        while i < a.len() && take(a[i]) {
            i += 1;
        }
        while j < b.len() && take(b[j]) {
            j += 1;
        }
        // 갈래가 다르다 — 한쪽은 숫자, 다른 쪽은 글자. **숫자가 높다.**
        if j == sj {
            return if numeric { Greater } else { Less };
        }
        let (mut s1, mut s2) = (&a[si..i], &b[sj..j]);
        if numeric {
            while s1.first() == Some(&b'0') {
                s1 = &s1[1..];
            }
            while s2.first() == Some(&b'0') {
                s2 = &s2[1..];
            }
            if s1.len() != s2.len() {
                return s1.len().cmp(&s2.len());
            }
        }
        match s1.cmp(s2) {
            Equal => continue,
            o => return o,
        }
    }
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Equal,
        (true, false) => Less,
        _ => Greater,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::{Equal, Greater, Less};

    #[test]
    fn only_a_plain_three_part_version_is_a_core_version() {
        for v in ["8.3.36", "0.0.0", "07.4.33", "999999.999999.999999"] {
            assert!(is_core(v), "{v:?}");
        }
        for v in [
            "",
            "8.3",
            "8.3.36.1",
            "8.3.36RC1",
            "8.3.36-custom",
            "8.3.36\n",
            "8..36",
            "8.3.9999999",
            "v8.3.36",
        ] {
            assert!(!is_core(v), "{v:?}");
        }
        assert_eq!(compare_core("8.3.9", "8.3.36"), Less);
        assert_eq!(compare_core("8.3.036", "8.3.36"), Equal);
        assert_eq!(compare_core("24.22.1", "24.22.0"), Greater);
    }

    /// `TestDebianOrdering`
    #[test]
    fn dpkg_ordering_follows_the_policy() {
        for (a, b, want) in [
            ("8.1.2-1ubuntu2.9", "8.1.2-1ubuntu2.28", Less),
            ("1:8.1.2-1", "8.5.12-1", Greater),
            ("8.3.36~rc1-1", "8.3.36-1", Less),
            ("8.3.36-1", "8.3.36-1", Equal),
            ("8.3.36-1+b2", "8.3.36-1+b10", Less),
        ] {
            assert_eq!(compare_debian(a, b), want, "{a} ? {b}");
            assert_eq!(compare_debian(b, a), want.reverse(), "{b} ? {a}");
        }
    }

    /// `TestReviewDebianOfficialRevisionAndEpochBoundaries`
    #[test]
    fn the_debian_vendor_line_holds_at_revision_and_epoch_boundaries() {
        const FIXED: &str = "8.2.35-1~deb12u1";
        const EPOCH: &str = "1:8.2.35-1~deb12u1";
        const HUGE: &str = "99999999999999999999:8.2.35-1~deb12u1";
        for (version, fixed, want) in [
            ("8.2.28-1", FIXED, Some(Less)),
            ("8.2.28-1~deb12u1", FIXED, Some(Less)),
            ("8.2.35-1~deb12u1", FIXED, Some(Equal)),
            ("8.2.35-1~deb12u1+b1", FIXED, Some(Greater)),
            ("8.2.35-1~deb12u2", FIXED, Some(Greater)),
            ("8.2.35-2~deb12u1", FIXED, Some(Greater)),
            ("8.2.36-1~deb12u1", FIXED, Some(Greater)),
            ("000:8.2.35-1~deb12u1", FIXED, Some(Equal)),
            (EPOCH, EPOCH, Some(Equal)),
            ("8.2.35-1~deb12u1", EPOCH, Some(Less)),
            (HUGE, HUGE, Some(Equal)),
            // 줄이 아닌 것 — 다른 배포판 표식 · 다른 표식 기호 · 다른 계열 · 모르는 꼬리.
            ("8.2.35-1~deb13u1", FIXED, None),
            ("8.2.35-1+deb12u1", FIXED, None),
            ("8.3.35-1~deb12u1", FIXED, None),
            ("8.2.35-1~deb12u1+b1+custom", FIXED, None),
        ] {
            let got = debian_vendor_line(version, fixed).then(|| compare_debian(version, fixed));
            assert_eq!(got, want, "{version} against {fixed}");
        }
        // 기준보다 높은 epoch 은 줄이 아니다.
        assert!(!debian_vendor_line("1:8.2.28-1~deb12u1", FIXED));
    }

    /// `TestLegacyPHPESMLineRejectsUnprovenSuffix`
    #[test]
    fn esm_suffixes_count_only_on_esm_lines() {
        const FIXED: &str = "7.4.3-4ubuntu2.29+esm5";
        for version in [
            "7.4.3-4ubuntu2",
            "7.4.3-4ubuntu2.28",
            "7.4.3-4ubuntu2.29",
            "7.4.3-4ubuntu2.29+esm4",
            FIXED,
            "7.4.3-4ubuntu2.29+esm6",
        ] {
            assert!(ubuntu_line(version, FIXED), "{version}");
        }
        for version in [
            "7.4.3-4ubuntu2.29+esm5a",
            "7.4.3-4ubuntu2.29+esm5+ppa1",
            "7.4.3-4ubuntu2.29+esm5+esm1",
            "7.4.3-4ubuntu2.29+esm",
            "7.4.3-4ubuntu3.29+esm5",
        ] {
            assert!(!ubuntu_line(version, FIXED), "{version}");
        }
        // ESM 공지가 아니면 ESM 꼬리를 받지 않는다.
        assert!(!ubuntu_line("8.1.2-1ubuntu2.28+esm1", "8.1.2-1ubuntu2.28"));
    }

    /// `TestRPMOrdering` — 스캐너의 표 21줄 가운데 20줄은 옮겨 온 구현과 답이 같다.
    #[test]
    fn rpm_ordering_agrees_with_the_scanner_table() {
        for (a, b, want) in [
            ("1.0-1", "0:1.0-1", Equal),
            ("001:1.0-1", "1:1.0-1", Equal),
            ("1:1.0-1", "0:99.0-9", Greater),
            (
                "18446744073709551616:1-1",
                "18446744073709551615:9-9",
                Greater,
            ),
            ("7.4.33-7.el8", "7.4.33-8.el8", Less),
            (
                "7.4.33-8.module+el8.10.0+9999+abc",
                "7.4.33-8.module+el8.10.0+10000+abc",
                Less,
            ),
            ("1.0~rc1-1", "1.0-1", Less),
            ("1.0~~rc1-1", "1.0~rc1-1", Less),
            ("1.0-1", "1.0^git1-1", Less),
            ("1.0^git1-1", "1.0.1-1", Less),
            ("1.0^git1-1", "1.0^git2-1", Less),
            ("1.0^git1-1", "1.0~rc1-1", Greater),
            ("1.0^git1-1", "1.0a-1", Less),
            ("1.0a-1", "1.0.0-1", Less),
            ("1.0a-1", "1.0A-1", Greater),
            ("1.0-1.09", "1.0-1.9", Equal),
            ("1.0-1+9", "1.0-1.9", Equal),
            ("1.0-1_9", "1.0-1.9", Equal),
            ("1.0000000000000000000000001-1", "1.1-1", Equal),
            (
                "1.9999999999999999999999999999-1",
                "1.10000000000000000000000000000-1",
                Less,
            ),
        ] {
            assert_eq!(rpm_version_cmp(a, b), Some(want), "{a} ? {b}");
            assert_eq!(rpm_version_cmp(b, a), Some(want.reverse()), "{b} ? {a}");
        }
    }

    /// `TestRPMOrdering` 의 남은 한 줄 — **두 구현이 갈린다.** 스캐너는 개정이 없는 쪽을 낮게 보고
    /// (`1.0` < `1.0-1`), 본체에서 옮겨 온 구현은 개정이 둘 다 있을 때만 견주어 같다고 한다. 어느 쪽도
    /// 굽히지 않았다 — 판정에서는 개정이 없는 버전을 RPM 줄과 견주지 않는다(`advisory::compare_rpm_row`).
    #[test]
    fn a_missing_release_is_where_the_two_rpm_orderings_differ() {
        assert_eq!(rpm_version_cmp("1.0", "1.0-1"), Some(Equal));
        assert_eq!(rpm_version_cmp("1.0-1", "1.0"), Some(Equal));
        assert!(!rpm_has_release("1.0"));
        assert!(!rpm_has_release("1.0-"));
        assert!(rpm_has_release("1.0-1"));
        assert!(rpm_has_release("0:7.4.33-8.module+el8.10.0+2345+abcd1234"));
    }

    /// `TestRPMRejectsInvalidEVR` — 스캐너가 거절하는 18꼴 가운데 13꼴은 옮겨 온 구현도 거절한다.
    #[test]
    fn rpm_shapes_both_implementations_refuse() {
        for version in [
            "", "x:1-1", ":1-1", "-1:1-1", "+1:1-1", "1:2:3-1", "1:", "-1", "1-1\x00", "１-1",
            "1-ö", "...", "~",
        ] {
            assert_eq!(rpm_version_cmp(version, "1-1"), None, "{version:?}");
            assert_eq!(rpm_version_cmp("1-1", version), None, "{version:?}");
        }
    }

    /// `TestRPMRejectsInvalidEVR` 의 남은 5꼴 — **스캐너는 거절하고 옮겨 온 구현은 받는다.** 앞뒤 공백을
    /// 떼고 보고, 빈 개정을 없는 것으로 읽고, 마지막 `-` 에서 가르고(스캐너는 첫 `-`), 길이 상한이 없다.
    /// 판정에서는 RPM 줄의 버전 범위(`version_pattern`)가 먼저 걸러 이 꼴들이 비교에 닿지 않는다 — 길이만은
    /// 범위가 막지 못해 [`MAX_VERSION_BYTES`] 로 따로 막는다(`advisory::compare_rpm_row`).
    #[test]
    fn rpm_shapes_the_scanner_refuses_but_the_mirrored_code_reads() {
        let long = "1".repeat(257);
        for (version, want) in [
            (" 1:1-1", Greater),
            ("1-1\n", Equal),
            ("1-", Equal),
            ("1-1-1", Greater),
            (long.as_str(), Greater),
        ] {
            assert_eq!(rpm_version_cmp(version, "1-1"), Some(want), "{version:?}");
        }
    }
}
