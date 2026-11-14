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

// ── apk ──────────────────────────────────────────────────────────────────
//
// 본체 `crates/remedy-detect/src/compare.rs` 의 `apk_version_cmp` 와 같은 구현이다(코어 1.14.0 · 위 rpm 쪽과 같은
// 까닭으로 옮겨 둔다 — 한쪽을 고치면 다른 쪽도 고친다). 아래 시험의 표도 그쪽 표 그대로다(apk-tools 2.14.13 의 답).

/// apk(Alpine)가 적은 판끼리 — 판을 조각([`ApkPart`])으로 나눠 앞에서부터 견준다. 모양이 아니면 `None`
/// (`remedy_sdk::catalog::is_apk_version`).
pub(super) fn apk_version_cmp(a: &str, b: &str) -> Option<Ordering> {
    use remedy_sdk::catalog::is_apk_version;
    if !is_apk_version(a) || !is_apk_version(b) {
        return None;
    }
    let (pa, pb) = (apk_parts(a.trim()), apk_parts(b.trim()));
    // 둘 다 `End` 로 끝난다 — 길이가 달라도 짧은 쪽의 `End` 자리에서 갈린다.
    for (x, y) in pa.iter().zip(&pb) {
        let ord = apk_part_cmp(x, y);
        if ord != Ordering::Equal {
            return Some(ord);
        }
    }
    Some(Ordering::Equal)
}

/// apk 판의 조각. **종류의 차례도 순서다** — 한쪽이 먼저 갈라지면 그 자리 조각의 종류가 정한다(앞의 종류가
/// 높고, 사전 배포 접미사는 무엇보다 낮다).
#[derive(Debug)]
enum ApkPart<'a> {
    /// 숫자 조각 — 앞의 `0` 을 뗀 수로 견준다.
    Num(&'a str),
    /// 둘째 조각부터 `0` 으로 시작하는 조각 — `0` 의 개수와 남은 숫자. `0` 이 많을수록 낮고, 같으면 남은 숫자를
    /// 수로 견주며(없는 쪽이 가장 낮다), 어떤 `Num` 보다도 낮다.
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
    use std::cmp::Ordering::{Equal, Greater, Less};
    use ApkPart::{End, Letter, Num, Revision, Suffix, SuffixNo, Zeros};
    match (x, y) {
        (Num(a), Num(b)) | (SuffixNo(a), SuffixNo(b)) | (Revision(a), Revision(b)) => {
            compare_digits(a, b)
        }
        (Zeros(ka, ra), Zeros(kb, rb)) => {
            kb.cmp(ka)
                .then_with(|| match (ra.is_empty(), rb.is_empty()) {
                    (true, true) => Equal,
                    (true, false) => Less,
                    (false, true) => Greater,
                    (false, false) => compare_digits(ra, rb),
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
    use remedy_sdk::catalog::APK_SUFFIXES;
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

    /// **apk 자신의 답이다** — 본체 `remedy-detect` 의 같은 이름 시험의 표 그대로(alpine:3.22 의 apk-tools 2.14.13
    /// 에서 `apk version -t A B` 로 받은 것). 앞의 셋만 그 표에 없는 줄이다 — Apache 기준의 고친 판(`2.4.71-r0`)
    /// 둘레를 규칙대로 적었다.
    #[test]
    fn apk_versions_order_as_apk_does() {
        for (a, b, want) in [
            ("2.4.65-r1", "2.4.71-r0", Less),
            ("2.4.71-r0", "2.4.71-r0", Equal),
            ("2.4.71-r1", "2.4.71-r0", Greater),
            ("10.6_p1-r0", "10.6_p2-r0", Less),
            ("10.3_p1-r1", "10.3_p1-r2", Less),
            ("10.2_p1-r0", "10.2_p1-r1", Less),
            ("10.0_p1-r10", "10.0_p1-r11", Less),
            ("9.9_p2-r0", "9.9_p2-r1", Less),
            ("9.7_p1-r5", "9.7_p1-r6", Less),
            ("9.6_p1-r2", "9.6_p1-r3", Less),
            ("9.3_p2-r3", "9.3_p2-r4", Less),
            ("9.1_p1-r6", "9.1_p1-r7", Less),
            ("9.0_p1-r5", "9.0_p1-r6", Less),
            ("9.9_p2-r1", "10.3_p1-r2", Less),
            ("10.6_p2-r0", "10.7_p1-r0", Less),
            ("10.3_p1-r2", "10.3_p1-r10", Less),
            ("9.9_p2-r1", "9.9_p10-r0", Less),
            ("1.0_alpha-r0", "1.0_beta-r0", Less),
            ("1.0_beta-r0", "1.0_pre-r0", Less),
            ("1.0_pre-r0", "1.0_rc-r0", Less),
            ("1.0_rc1-r0", "1.0-r0", Less),
            ("1.0-r0", "1.0_cvs-r0", Less),
            ("1.0_cvs-r0", "1.0_svn-r0", Less),
            ("1.0_svn-r0", "1.0_git-r0", Less),
            ("1.0_git-r0", "1.0_hg-r0", Less),
            ("1.0_hg-r0", "1.0_p-r0", Less),
            ("1.0_p-r0", "1.0_p0-r0", Less),
            ("1.0_p1-r0", "1.0_p10-r0", Less),
            ("1.0_p9-r0", "1.0_p10-r0", Less),
            ("1.0_rc-r0", "1.0_rc1-r0", Less),
            ("1.0_alpha2-r0", "1.0_alpha10-r0", Less),
            ("1.0_p01-r0", "1.0_p1-r0", Equal),
            ("1.0_p00-r0", "1.0_p0-r0", Equal),
            ("1.0_p1_p2-r0", "1.0_p1-r0", Greater),
            ("1.0_p1_rc1-r0", "1.0_p1-r0", Less),
            ("1.0_rc1_p1-r0", "1.0_rc1-r0", Greater),
            ("1.0_rc1_p1-r0", "1.0-r0", Less),
            ("1.0_p1_p1-r0", "1.0_p1_p1-r0", Equal),
            ("1.0a-r0", "1.0-r0", Greater),
            ("1.0a-r0", "1.0b-r0", Less),
            ("1.0a-r0", "1.0_p1-r0", Greater),
            ("1.0a-r0", "1.0.1-r0", Less),
            ("1.0a_rc1-r0", "1.0a-r0", Less),
            ("1.0z-r0", "1.0.0-r0", Less),
            ("1.0-r0", "1.0.0-r0", Less),
            ("1.0.1-r0", "1.0_p1-r0", Greater),
            ("1.0.1-r0", "1.0_rc1-r0", Greater),
            ("1.10-r0", "1.9-r0", Greater),
            ("2-r0", "10-r0", Less),
            ("20240705-r0", "20230311-r0", Greater),
            ("01-r0", "1-r0", Equal),
            ("0-r0", "00-r0", Equal),
            ("00-r0", "0.0-r0", Less),
            ("1.01-r0", "1.1-r0", Less),
            ("1.01-r0", "1.001-r0", Greater),
            ("1.010-r0", "1.01-r0", Greater),
            ("1.0-r0", "1.00-r0", Greater),
            ("1.0-r0", "1.01-r0", Less),
            ("1.00-r0", "1.000-r0", Greater),
            ("1.0.0-r0", "1.00-r0", Greater),
            ("1.001-r0", "1.0-r0", Less),
            ("0.1-r0", "0.01-r0", Greater),
            ("1.02-r0", "1.1-r0", Less),
            ("1.09-r0", "1.1-r0", Less),
            ("1.1-r0", "1.10-r0", Less),
            ("2.050-r0", "2.05-r0", Greater),
            ("2.05-r0", "2.5-r0", Less),
            ("1.0a-r0", "1.00a-r0", Greater),
            ("2024.07.05-r0", "2024.7.5-r0", Less),
            ("1.09-r0", "1.010-r0", Less),
            ("1.019-r0", "1.02-r0", Greater),
            ("1.05-r0", "1.050-r0", Less),
            ("1.0010-r0", "1.002-r0", Greater),
            ("1.0.9-r0", "1.05.10-r0", Less),
            ("1.0.9-r0", "1.05-r0", Less),
            ("1.0-r0", "1.05-r0", Less),
            ("1.05-r0", "1.05.0-r0", Less),
            ("1.050.1-r0", "1.05.9-r0", Greater),
            ("1.01.5-r0", "1.01-r0", Greater),
            ("1.001-r0", "1.0.1-r0", Less),
            ("1.00.1-r0", "1.0.01-r0", Less),
            ("0.05-r0", "0.0.5-r0", Greater),
            ("01.0.9.3a_beta-r00", "001.05.10.01-r1", Less),
            ("1.0-r9", "1.0-r10", Less),
            ("1.0-r01", "1.0-r1", Equal),
            ("1.0-r00", "1.0-r0", Equal),
            ("10.3_p1-r2", "10.3_p1-r2", Equal),
        ] {
            assert_eq!(apk_version_cmp(a, b), Some(want), "'{a}' vs '{b}'");
            assert_eq!(
                apk_version_cmp(b, a),
                Some(want.reverse()),
                "'{b}' vs '{a}' (뒤집어서)"
            );
        }
    }

    /// apk 가 판으로 인정하지 않는 모양 — 추측하지 않는다(본체 시험의 표 그대로).
    #[test]
    fn a_shape_apk_does_not_write_is_not_compared() {
        for bad in [
            "",
            "1.0",
            "1.0_p1",
            "1.0_P1-r1",
            "1.0-R1",
            "1.0_foo-r0",
            "1.0~abc-r0",
            "1.0a1-r0",
            "1.0aa-r0",
            "1.0A-r0",
            "1.0_p1a-r0",
            "1.0.a-r0",
            "1.0z.1-r0",
            ".1-r0",
            "1..0-r0",
            "1.0_-r0",
            "1.0-r",
            "1.0-rx-r0",
            "v1.0-r0",
            "openssh-r0",
        ] {
            assert_eq!(apk_version_cmp(bad, "1.0-r0"), None, "{bad:?}");
            assert_eq!(apk_version_cmp("1.0-r0", bad), None, "{bad:?}");
        }
    }
}
