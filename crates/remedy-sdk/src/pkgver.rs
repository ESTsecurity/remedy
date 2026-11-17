//! 패키지 판 비교 — dpkg · rpm · apk 의 규칙 **한 벌**.
//!
//! 본체(`remedy-detect` 의 `pkg_version_lt` · `rpm_version_lt` · `apk_version_lt`)와 동반 모듈(`remedy-net` 의
//! 이미지 · 컨테이너 · url 점검)이 이것을 부른다. 2026-11-17 까지 세 벌이 따로 있었고(서로 같은 줄 198 · 60),
//! dpkg 쪽 한 벌은 **비숫자 구간의 숫자 순서가 dpkg 와 달랐다** — `1.1` 대 `1.a` 에서 dpkg 는 `1.a` 가 높고
//! 그 한 벌은 반대였다. 둘 다 이 크레이트를 링크하므로 여기 두면 의존 방향이 늘지 않는다(설계-04 §1).
//!
//! **모양 검사는 하지 않는다.** 부르는 쪽이 `catalog::is_pkg_version` · `is_rpm_version` · `is_apk_version`(또는
//! 제 규칙)으로 거른 뒤 부른다 — 여기서 거르면 두 쪽의 거절 규칙이 갈릴 때 한쪽이 조용히 바뀐다. 판 문자열은 그
//! 검사들이 ASCII 로 제한하므로 바이트와 문자가 같다.
//!
//! **숫자는 기계 정수로 바꾸지 않는다** — 앞의 `0` 을 떼고 길이와 바이트로 견주므로 자리 수에 상한이 없고 넘치지
//! 않는다.

use std::cmp::Ordering;

/// 숫자 문자열끼리 — 앞의 `0` 을 떼고 **길이 → 바이트**. 빈 문자열과 `0` 은 같다.
pub fn digits_cmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

// ── dpkg ─────────────────────────────────────────────────────────────────

/// dpkg 의 판 비교(데비안 정책 §5.6.12 · dpkg 의 `verrevcmp`) — `[epoch:]상류[-개정]` 을 **epoch → 상류 → 개정**
/// 순으로 견준다. epoch 이 없으면 `0`, 개정이 없으면 `0` 이다. 각 조각은 숫자 아닌 부분과 숫자 부분을 번갈아 견준다 —
/// 숫자 부분은 수로, 그 밖은 [`dpkg_order`] 의 차례로(`~` 가 끝보다도 먼저 · 글자 · 그 밖의 문자).
pub fn dpkg_cmp(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split_dpkg(a);
    let (eb, ub, rb) = split_dpkg(b);
    digits_cmp(ea, eb)
        .then_with(|| dpkg_part(ua, ub))
        .then_with(|| dpkg_part(ra, rb))
}

/// `1:2.38.1-5+deb12u3` → `("1", "2.38.1", "5+deb12u3")`. epoch 은 **첫** `:` 앞, 개정은 **마지막** `-` 뒤다(정책 —
/// 상류 판에 `-` 가 들어갈 수 있다).
fn split_dpkg(s: &str) -> (&str, &str, &str) {
    let (epoch, rest) = s.split_once(':').unwrap_or(("0", s));
    let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, "0"));
    (epoch, upstream, revision)
}

/// 숫자 아닌 한 문자의 차례(dpkg 의 `order()`). **`~` 는 끝보다도 먼저**이고(`1.0~rc1` < `1.0`), 글자는 제 바이트,
/// 그 밖의 문자는 `+256` 으로 글자보다 뒤다(`1.0+b1` > `1.0a`). **숫자와 끝은 `0` 이다** — 한쪽만 숫자에 닿은
/// 자리에서 숫자가 글자보다 낮다(`1.1` < `1.a`).
fn dpkg_order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

fn dpkg_part(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() || !b.is_empty() {
        while a.first().is_some_and(|c| !c.is_ascii_digit())
            || b.first().is_some_and(|c| !c.is_ascii_digit())
        {
            let c = dpkg_order(a.first().copied()).cmp(&dpkg_order(b.first().copied()));
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
        let c = digits_cmp(x, y);
        if c.is_ne() {
            return c;
        }
        a = &a[i..];
        b = &b[j..];
    }
    Ordering::Equal
}

// ── rpm ──────────────────────────────────────────────────────────────────

/// rpm 의 판 비교(`rpmverCmp`) — `[epoch:]판[-개정]` 을 **epoch → 판 → 개정** 순으로 [`rpmvercmp`] 로 견준다.
/// epoch 이 없으면 `0` 이고, 개정은 **둘 다 있을 때만** 견준다 — rpm 과 같다.
pub fn rpm_cmp(a: &str, b: &str) -> Ordering {
    let (ea, va, ra) = split_evr(a);
    let (eb, vb, rb) = split_evr(b);
    let mut ord = rpmvercmp(ea, eb).then_with(|| rpmvercmp(va, vb));
    if let (Some(ra), Some(rb)) = (ra, rb) {
        ord = ord.then_with(|| rpmvercmp(ra, rb));
    }
    ord
}

/// 개정(`-` 뒤)이 있는가 — [`rpm_cmp`] 가 읽는 그대로.
pub fn rpm_has_release(s: &str) -> bool {
    split_evr(s).2.is_some()
}

/// `1:8.0.30-8.el9_8.1` → `("1", "8.0.30", Some("8.el9_8.1"))`. 개정은 **마지막** `-` 뒤이고, 비면 없는 것이다(rpm
/// 의 `rpmverCmp` 는 빈 개정을 견주지 않는다).
fn split_evr(s: &str) -> (&str, &str, Option<&str>) {
    let (epoch, rest) = s.split_once(':').unwrap_or(("0", s));
    match rest.rsplit_once('-') {
        Some((v, r)) => (epoch, v, (!r.is_empty()).then_some(r)),
        None => (epoch, rest, None),
    }
}

/// rpm 의 `rpmvercmp` — 글자 · 숫자가 아닌 문자는 **구분자로만** 보고, 숫자 덩어리와 글자 덩어리를 번갈아
/// 견준다. 숫자 덩어리는 수로 보고(앞의 `0` 은 값이 아니다) **글자 덩어리보다 늘 높다.** `~` 는 무엇보다도 먼저,
/// `^` 는 끝보다는 뒤이고 다른 무엇보다는 먼저다.
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    use Ordering::{Equal, Greater, Less};
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

// ── apk ──────────────────────────────────────────────────────────────────

/// apk-tools 의 판 비교 — 판을 조각([`ApkPart`])으로 나눠 앞에서부터 견준다. 둘 다 `End` 로 끝나므로 길이가 달라도
/// 짧은 쪽의 `End` 자리에서 갈린다.
pub fn apk_cmp(a: &str, b: &str) -> Ordering {
    let (pa, pb) = (apk_parts(a), apk_parts(b));
    for (x, y) in pa.iter().zip(&pb) {
        let ord = apk_part_cmp(x, y);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// apk 판의 조각. **종류의 차례도 순서다** — 한쪽이 먼저 갈라지면 그 자리 조각의 종류가 정한다(앞의 종류가
/// 높고, 사전 배포 접미사는 무엇보다 낮다).
#[derive(Debug)]
enum ApkPart<'a> {
    /// 숫자 조각 — 앞의 `0` 을 뗀 수로 견준다.
    Num(&'a str),
    /// 둘째 조각부터 `0` 으로 시작하는 조각 — `0` 의 개수와 남은 숫자. **`0` 이 많을수록 낮고, 같으면 남은 숫자를
    /// 수로 견주며(없는 쪽이 가장 낮다), 어떤 `Num` 보다도 낮다**(`1.01 < 1.1` · `1.00 < 1.0` · `1.0 < 1.05` ·
    /// `1.09 < 1.010`).
    Zeros(usize, &'a str),
    Letter(u8),
    /// 접미사의 차례 — 사전 배포(`alpha` ~ `rc`)는 음수다.
    Suffix(i8),
    SuffixNo(&'a str),
    Revision(&'a str),
    End,
}

impl ApkPart<'_> {
    fn kind(&self) -> u8 {
        match self {
            ApkPart::Num(_) | ApkPart::Zeros(..) => 1,
            ApkPart::Letter(_) => 2,
            ApkPart::Suffix(_) => 3,
            ApkPart::SuffixNo(_) => 4,
            ApkPart::Revision(_) => 5,
            ApkPart::End => 6,
        }
    }

    fn pre_release(&self) -> bool {
        matches!(self, ApkPart::Suffix(r) if *r < 0)
    }
}

fn apk_part_cmp(x: &ApkPart<'_>, y: &ApkPart<'_>) -> Ordering {
    use ApkPart::{End, Letter, Num, Revision, Suffix, SuffixNo, Zeros};
    use Ordering::{Equal, Greater, Less};
    match (x, y) {
        (Num(a), Num(b)) | (SuffixNo(a), SuffixNo(b)) | (Revision(a), Revision(b)) => {
            digits_cmp(a, b)
        }
        (Zeros(ka, ra), Zeros(kb, rb)) => {
            kb.cmp(ka)
                .then_with(|| match (ra.is_empty(), rb.is_empty()) {
                    (true, true) => Equal,
                    (true, false) => Less,
                    (false, true) => Greater,
                    (false, false) => digits_cmp(ra, rb),
                })
        }
        (Zeros(..), Num(_)) => Less,
        (Num(_), Zeros(..)) => Greater,
        (Letter(a), Letter(b)) => a.cmp(b),
        (Suffix(a), Suffix(b)) => a.cmp(b),
        (End, End) => Equal,
        // 종류가 다르다 — 사전 배포 접미사가 먼저 지고, 그 밖은 앞의 종류가 이긴다.
        _ if x.pre_release() => Less,
        _ if y.pre_release() => Greater,
        _ => y.kind().cmp(&x.kind()),
    }
}

/// `is_apk_version` 을 지난 문자열을 조각낸다.
fn apk_parts(s: &str) -> Vec<ApkPart<'_>> {
    use crate::catalog::APK_SUFFIXES;
    let (body, rev) = s.rsplit_once("-r").unwrap_or((s, "0"));
    let mut sections = body.split('_');
    let head = sections.next().unwrap_or_default();
    let (nums, letter) = match head.as_bytes().last() {
        Some(&c) if c.is_ascii_lowercase() => (&head[..head.len() - 1], Some(c)),
        _ => (head, None),
    };
    let mut out = Vec::new();
    for (i, c) in nums.split('.').enumerate() {
        let rest = c.trim_start_matches('0');
        let zeros = c.len() - rest.len();
        // 첫 조각은 그냥 수다(`01` = `1`). 둘째부터 앞의 `0` 이 값을 낮춘다.
        if i == 0 || zeros == 0 {
            out.push(ApkPart::Num(c));
        } else {
            out.push(ApkPart::Zeros(zeros, rest));
        }
    }
    if let Some(c) = letter {
        out.push(ApkPart::Letter(c));
    }
    for suffix in sections {
        let n = suffix.bytes().take_while(u8::is_ascii_lowercase).count();
        let (name, num) = suffix.split_at(n);
        let place = APK_SUFFIXES.iter().position(|s| *s == name).unwrap_or(0);
        // 앞의 넷(사전 배포)이 음수가 되게 4 를 뺀다.
        out.push(ApkPart::Suffix(i8::try_from(place).unwrap_or(0) - 4));
        if !num.is_empty() {
            out.push(ApkPart::SuffixNo(num));
        }
    }
    out.push(ApkPart::Revision(rev));
    out.push(ApkPart::End);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::{Equal, Greater, Less};

    /// 답은 debian:12 의 `dpkg --compare-versions` 그대로다(2026-11-17). 비숫자 구간에서 한쪽만 숫자에 닿은 자리가
    /// 2026-11-17 까지 본체의 한 벌에서 반대로 나왔다.
    #[test]
    fn dpkg_answers_match_dpkg_itself() {
        for (a, b, want) in [
            ("1.1", "1.a", Less),
            ("1.0+1", "1.0+a", Less),
            ("1.0~1", "1.0~a", Less),
            ("1-1", "1-a", Less),
            ("2.4.1", "2.4.a", Less),
            ("1.a.1", "1.1.1", Greater),
            ("1a", "11", Less),
            ("2.4a", "2.41", Less),
            ("1:2a-1", "1:21-1", Less),
            ("1.2+b", "1.21", Less),
            ("8.2.29~rc1", "8.2.29", Less),
            ("1.0a", "1.0+b1", Less),
            ("1:0.1", "2.0", Greater),
            ("1.0", "0:1.0", Equal),
            ("1.0", "1.0-0", Equal),
            ("1.18446744073709551616", "1.18446744073709551617", Less),
        ] {
            assert_eq!(dpkg_cmp(a, b), want, "'{a}' vs '{b}'");
            assert_eq!(dpkg_cmp(b, a), want.reverse(), "'{b}' vs '{a}'");
        }
    }

    #[test]
    fn digits_compare_by_value_without_overflow() {
        assert_eq!(digits_cmp("010", "9"), Greater);
        assert_eq!(digits_cmp("", "0"), Equal);
        assert_eq!(digits_cmp("000", "0"), Equal);
        assert_eq!(
            digits_cmp("18446744073709551617", "18446744073709551616"),
            Greater
        );
    }
}
