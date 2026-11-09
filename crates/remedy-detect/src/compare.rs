//! 연산자 의미론 (설계-02 §4, 설계-09 P4).
//!
//! 비교는 **정규화된 문자열 위에서** 일어난다. 룰이 적은 값도 관측된 값과 같은
//! 정규화를 거치므로, 작성자의 편집기가 무엇을 뱉었는지에 판정이 좌우되지 않는다.
//!
//! 여기 있는 것은 순수 함수뿐이다. 시스템에 닿지 않고, 시계를 읽지 않고,
//! 같은 입력에 언제나 같은 답을 낸다 — 그래야 같은 스냅샷을 두 번 평가한
//! 결과가 바이트까지 같다.

/// 경로 성분 구분자. 정규화된 경로는 `\` 를 쓰지만, 룰이 `/` 로 적힌
/// 비-경로 필드에 glob 을 걸 수도 있어 둘 다 구분자로 본다.
fn is_sep(c: char) -> bool {
    c == '\\' || c == '/'
}

/// glob 매칭.
///
/// - `?` — 구분자가 아닌 한 글자
/// - `*` — 구분자를 **넘지 않는** 임의 길이
/// - `**` — **성분 하나로 통째로 적었을 때만** 구분자를 넘는다
///
/// `*` 가 구분자를 넘지 않는 것이 핵심이다. 넘게 만들면
/// `C:\Users\*\Desktop` 이 `C:\Users\a\b\c\Desktop` 에도 맞고, 룰 작성자가
/// 의도한 "사용자 폴더 하나" 보다 훨씬 넓은 것을 지목하게 된다.
///
/// # 왜 성분 단위로 맞추는가
///
/// 처음에는 문자열 전체를 한 번에 훑으며 마지막 `*` 자리만 기억했다. 그
/// 방식은 `*` 가 구분자를 넘지 못하는 순간 **앞의 `**` 로 되돌아갈 수 없다** —
/// `**\*.js` 가 `c:\...\lab\payload.js` 에 맞지 않았다. `**` 가 첫 `\` 에
/// 붙박이고, 뒤의 `*` 가 `lab\` 을 넘지 못한 채 실패한다.
///
/// 성분으로 쪼개면 그 문제가 사라진다. 성분 목록끼리 맞출 때 `**` 는 **아무
/// 성분이나** 삼킬 수 있으므로 별 하나만 기억하는 방식이 완전해지고, 성분
/// 안쪽에는 구분자가 없으므로 거기서도 완전해진다.
///
/// 두 단계 모두 별마다 한 번씩만 전진하므로 입력 길이에 선형이다 — `matches`
/// 가 RE2 인 것과 같은 이유다: 룰이 스캐너를 정지시킬 수 없어야 한다.
pub fn glob(text: &str, pattern: &str) -> bool {
    let t: Vec<&str> = text.split(is_sep).collect();
    let p: Vec<&str> = pattern.split(is_sep).collect();

    let (mut ti, mut pi) = (0usize, 0usize);
    // 마지막으로 만난 `**` 성분의 자리와 그때의 입력 성분 위치.
    let mut star: Option<(usize, usize)> = None;

    while ti < t.len() {
        if pi < p.len() {
            if p[pi] == "**" {
                pi += 1;
                star = Some((pi, ti));
                continue;
            }
            if segment_matches(t[ti], p[pi]) {
                pi += 1;
                ti += 1;
                continue;
            }
        }
        match star {
            Some((sp, si)) => {
                pi = sp;
                ti = si + 1;
                star = Some((sp, si + 1));
            }
            None => return false,
        }
    }

    // 입력 성분을 다 썼다. 남은 패턴이 `**` 뿐이어야 맞는다.
    while pi < p.len() && p[pi] == "**" {
        pi += 1;
    }
    pi == p.len()
}

/// 성분 하나끼리. 여기에는 구분자가 없으므로 `*` 는 무엇이든 삼킨다.
fn segment_matches(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;

    while ti < t.len() {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    // 성분 안의 `**` 는 `*` 와 같다. 구분자를 넘는 뜻은
                    // **성분 하나로 통째로 적었을 때만** 갖는다.
                    while pi < p.len() && p[pi] == '*' {
                        pi += 1;
                    }
                    star = Some((pi, ti));
                    continue;
                }
                '?' => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                c if c == t[ti] => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((sp, si)) => {
                pi = sp;
                ti = si + 1;
                star = Some((sp, si + 1));
            }
            None => return false,
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// `gt`/`lt` 가 비교할 수 있는 값.
///
/// **크기와 시각 두 가지만 비교한다.** 문자열의 사전순 비교는 뜻이 없다 —
/// `"9" > "10"` 이 참이 되고, 룰 작성자는 그것을 알아채지 못한다.
#[derive(Debug, PartialEq, PartialOrd)]
pub enum Magnitude {
    Number(f64),
    /// RFC3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`). 고정 폭이라 **사전순이 곧 시간순**이다.
    Instant(String),
}

/// 비교 가능한 값으로 읽는다. 읽을 수 없으면 `None`.
pub fn magnitude(s: &str) -> Option<Magnitude> {
    if let Ok(n) = s.trim().parse::<f64>() {
        if n.is_finite() {
            return Some(Magnitude::Number(n));
        }
        return None;
    }
    if is_rfc3339_utc(s) {
        return Some(Magnitude::Instant(s.to_string()));
    }
    None
}

/// `YYYY-MM-DDTHH:MM:SSZ` 인가. **자리마다 확인한다** — 형태가 어긋나면
/// 사전순 비교가 조용히 거짓말을 한다.
fn is_rfc3339_utc(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20 {
        return false;
    }
    let digits = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    let dashes = [4, 7];
    digits.iter().all(|&i| b[i].is_ascii_digit())
        && dashes.iter().all(|&i| b[i] == b'-')
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
}

/// 두 값을 비교한다. 종류가 다르면 비교할 수 없다.
pub fn cmp(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    match (magnitude(a)?, magnitude(b)?) {
        (Magnitude::Number(x), Magnitude::Number(y)) => x.partial_cmp(&y),
        (Magnitude::Instant(x), Magnitude::Instant(y)) => Some(x.cmp(&y)),
        // 숫자와 시각을 견주는 것은 룰의 실수다. 조용히 false 를 내면 왜 안
        // 맞는지 알 수 없으므로 호출자가 오류로 보고한다.
        _ => None,
    }
}

/// 버전으로 읽히는 모양의 정의는 **카탈로그가 갖는다** — 린트가 룰의 리터럴을
/// 받아들이는 기준과 여기서 견주는 기준이 갈리면, 린트를 통과한 룰이 평가에서
/// 조용히 거짓이 된다.
pub use remedy_sdk::catalog::is_version;

/// 버전 비교. 둘 중 하나라도 버전이 아니면 `None`.
///
/// # 왜 `gt`·`lt` 를 고치지 않고 연산자를 더했는가
///
/// `1.10` 은 **수로도 버전으로도 읽히고 순서가 반대다** — 수로는 `1.10 < 1.9`,
/// 버전으로는 `1.10 > 1.9`. 기존 연산자에 버전 의미를 끼워 넣으면 이미 출하된
/// 룰의 뜻이 **조용히** 바뀐다. `sideload-drop` 이 `gt`·`lt` 로 시각과 크기를
/// 견주고 있다. 그래서 작성자가 **버전임을 적게** 한다.
///
/// # 성분 수가 달라도 된다
///
/// 없는 성분은 `0` 이다 — `8.2` 와 `8.2.0` 은 같다. 공급사가 수정판을 `8.2.29`
/// 로 적고 설치본이 `8.2.29.0` 으로 보고하는 자리가 있어, 그 둘이 갈리면
/// 수정된 기계가 취약으로 나간다.
///
/// # 꼬리는 받지 않는다
///
/// `8.4.0RC1`(사전 배포)과 `8.2.29-1ubuntu1`(패키지 개정)은 **모양이 같고 순서가
/// 반대다** — 앞은 `8.4.0` 보다 낮고 뒤는 `8.2.29` 보다 높다. 어느 쪽인지는
/// 문자열만 보고 정할 수 없으므로 **추측하지 않고 견줄 수 없다고 말한다**.
/// 패키지 개정은 C-2(패키지 subject)의 몫이다. `min_core` 가 세 자리 수만 보는
/// 것과 같은 규율이다 ([`crate`] 밖 · `remedy-sdk` 린트).
///
/// # 자리 수에 상한이 없다
///
/// 성분을 수로 파싱하지 않는다 — 앞의 `0` 을 떼고 길이와 바이트로 견준다.
/// u64 로 읽으면 `18446744073709551616` 이 넘쳐 조용히 거짓말을 한다.
pub fn version_cmp(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    if !is_version(a) || !is_version(b) {
        return None;
    }
    let mut xs = a.trim().split('.');
    let mut ys = b.trim().split('.');
    loop {
        let (x, y) = (xs.next(), ys.next());
        if x.is_none() && y.is_none() {
            return Some(std::cmp::Ordering::Equal);
        }
        // 없는 성분은 `0` — `8.2` 와 `8.2.0` 이 같아진다.
        let ord = component_cmp(x.unwrap_or("0"), y.unwrap_or("0"));
        if ord != std::cmp::Ordering::Equal {
            return Some(ord);
        }
    }
}

/// 배포판이 적은 판끼리 (C-2 후속 · 2026-10-27). `pkg_version_lt` 가 쓴다.
///
/// # 왜 [`version_cmp`] 로 안 되는가
///
/// 그쪽은 **꼬리를 거절한다** — 모양이 같고 순서가 반대인 두 종류를 문자열만
/// 보고 가를 수 없기 때문이다. 그래서 배포판 기계에서는 *"재지 못했다"*(종료
/// 6)로 끝났고, 그것이 백포트를 가릴 수 없던 이유의 절반이다. 여기서는
/// **dpkg 의 규칙을 그대로 쓴다** — 그 규칙이 꼬리의 순서를 정의한다.
///
/// # 규칙 (데비안 정책 §5.6.12 · dpkg 의 `verrevcmp`)
///
/// `[epoch:]상류[-개정]` 을 셋으로 갈라 **epoch → 상류 → 개정** 순으로 견준다.
/// epoch 이 없으면 `0`, 개정이 없으면 `""` 다(정책: 없는 개정은 `0` 과 같다 —
/// 아래 [`verrevcmp`] 가 빈 문자열과 `"0"` 을 같게 읽는다).
///
/// 각 조각은 **숫자 아닌 부분과 숫자 부분을 번갈아** 견준다. 숫자 부분은
/// 수로, 그 밖은 **글자가 먼저이고 `~` 는 무엇보다도 먼저**인 순서로 본다 —
/// `1.0~rc1` < `1.0` < `1.0+b1` 이 그래서 성립한다.
///
/// 모양이 아니면 `None` 이다 ([`is_pkg_version`]). 특히 **`_` 를 거절한다** —
/// dpkg 와 apk 가 그 문자를 반대로 읽는다(그쪽 doc 에 근거).
pub fn pkg_version_cmp(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use remedy_sdk::catalog::is_pkg_version;
    if !is_pkg_version(a) || !is_pkg_version(b) {
        return None;
    }
    let (ea, ra) = split_pkg(a.trim());
    let (eb, rb) = split_pkg(b.trim());
    // epoch 은 수다. 길이와 바이트로 견주어 자리 수 상한을 두지 않는다.
    let ord = component_cmp(drop_leading_zeros(ea), drop_leading_zeros(eb));
    if ord != std::cmp::Ordering::Equal {
        return Some(ord);
    }
    // 상류 판, 그다음 개정. **개정까지 봐야 백포트가 가려진다** —
    // `8.1.2-1ubuntu2.21` 과 `8.1.2-1ubuntu2.28` 은 상류가 같다.
    let (ua, va) = split_revision(ra);
    let (ub, vb) = split_revision(rb);
    Some(verrevcmp(ua, ub).then_with(|| verrevcmp(va, vb)))
}

/// `1:2.38.1-5` → `("1", "2.38.1-5")`. epoch 이 없으면 `"0"`.
fn split_pkg(s: &str) -> (&str, &str) {
    match s.split_once(':') {
        Some((e, rest)) => (e, rest),
        None => ("0", s),
    }
}

/// `2.38.1-5+deb12u3` → `("2.38.1", "5+deb12u3")`. **마지막** `-` 가 경계다
/// (정책 — 상류 판에 `-` 가 들어갈 수 있다).
fn split_revision(s: &str) -> (&str, &str) {
    match s.rsplit_once('-') {
        Some((u, r)) => (u, r),
        None => (s, ""),
    }
}

/// dpkg 의 `verrevcmp` — 숫자 아닌 부분과 숫자 부분을 번갈아 견준다.
///
/// 바이트로 돈다. 판 문자열은 [`is_pkg_version`] 이 ASCII 로 제한하므로
/// 바이트와 문자가 같고, 그래서 색인 계산이 문자 경계를 깨지 않는다.
fn verrevcmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() || j < b.len() {
        // ── 숫자 아닌 부분 ──
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let (x, y) = (order(a.get(i).copied()), order(b.get(j).copied()));
            if x != y {
                return x.cmp(&y);
            }
            i += 1;
            j += 1;
        }
        // ── 숫자 부분 ── 앞의 `0` 은 값이 아니다.
        while i < a.len() && a[i] == b'0' {
            i += 1;
        }
        while j < b.len() && b[j] == b'0' {
            j += 1;
        }
        // **긴 쪽이 크다.** 같은 길이면 처음 갈린 자리가 정한다.
        let mut first = Ordering::Equal;
        while i < a.len() && j < b.len() && a[i].is_ascii_digit() && b[j].is_ascii_digit() {
            if first == Ordering::Equal {
                first = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if i < a.len() && a[i].is_ascii_digit() {
            return Ordering::Greater;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            return Ordering::Less;
        }
        if first != Ordering::Equal {
            return first;
        }
    }
    Ordering::Equal
}

/// RPM 이 적은 판끼리 (2026-11-09) — `rpm_version_lt` 가 쓴다.
///
/// `[epoch:]판[-개정]` 을 셋으로 갈라 **epoch → 판 → 개정** 순으로 [`rpmvercmp`] 로 견준다(rpm 의
/// `rpmverCmp`). epoch 이 없으면 `0` 이고, 개정은 **둘 다 있을 때만** 견준다 — rpm 과 같다.
/// 모양이 아니면 `None` 이다(`is_rpm_version`).
pub fn rpm_version_cmp(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use remedy_sdk::catalog::is_rpm_version;
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

/// `1:8.0.30-8.el9_8.1` → `("1", "8.0.30", Some("8.el9_8.1"))`. 개정은 **마지막** `-` 뒤이고, 비면
/// 없는 것이다(rpm 의 `rpmverCmp` 는 빈 개정을 견주지 않는다).
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

/// rpm 의 `rpmvercmp` — 글자 · 숫자가 아닌 문자는 **구분자로만** 보고, 숫자 덩어리와 글자 덩어리를
/// 번갈아 견준다. 숫자 덩어리는 수로 보고(앞의 `0` 은 값이 아니다) **글자 덩어리보다 늘 높다.**
/// `~` 는 무엇보다도 먼저, `^` 는 끝보다는 뒤이고 다른 무엇보다는 먼저다.
fn rpmvercmp(a: &str, b: &str) -> std::cmp::Ordering {
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

/// 숫자 아닌 한 문자의 순서. **`~` 는 끝보다도 먼저다.**
///
/// 그래서 `1.0~rc1` 이 `1.0` 보다 낮다 — 사전 배포를 적는 dpkg 의 방식이고,
/// 이 한 함수가 그 뜻을 들고 있다. 글자는 제 바이트로, 그 밖의 문자는
/// `+256` 으로 **글자보다 뒤**에 둔다(`1.0+b1` > `1.0a`).
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(x) if x.is_ascii_alphabetic() => x as i32,
        Some(x) => x as i32 + 256,
    }
}

/// 성분 하나끼리. 숫자뿐임은 [`is_version`] 이 이미 확인했다.
fn component_cmp(x: &str, y: &str) -> std::cmp::Ordering {
    let (x, y) = (drop_leading_zeros(x), drop_leading_zeros(y));
    x.len().cmp(&y.len()).then_with(|| x.cmp(y))
}

/// 앞의 `0` 을 뗀다. 전부 `0` 이면 `"0"` 하나를 남긴다.
fn drop_leading_zeros(s: &str) -> &str {
    let t = s.trim_start_matches('0');
    if t.is_empty() {
        "0"
    } else {
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_does_not_cross_a_separator() {
        // 넘게 만들면 `C:\Users\*\Desktop` 이 훨씬 넓은 것을 지목하게 된다.
        assert!(glob("C:\\Users\\kim\\Desktop", "C:\\Users\\*\\Desktop"));
        assert!(!glob(
            "C:\\Users\\kim\\sub\\Desktop",
            "C:\\Users\\*\\Desktop"
        ));
        assert!(glob(
            "C:\\Users\\kim\\sub\\Desktop",
            "C:\\Users\\**\\Desktop"
        ));
    }

    #[test]
    fn question_matches_one_char_but_not_a_separator() {
        assert!(glob("ab", "a?"));
        assert!(!glob("a\\", "a?"));
        assert!(!glob("abc", "a?"));
    }

    #[test]
    fn a_leading_double_star_still_lets_a_later_star_work() {
        // **이 자리가 실제로 틀렸다.** 별 하나만 기억하는 방식은 뒤의 `*` 가
        // 구분자에 막히면 앞의 `**` 로 되돌아가지 못한다. 실기기 확인에서
        // `**\*.js` 가 실제 경로에 맞지 않아 드러났다.
        assert!(glob(
            "c:\\users\\t\\temp\\p4yara\\lab\\payload.js",
            "**\\*.js"
        ));
        assert!(glob("a\\b\\c\\d.js", "**\\*.js"));
        assert!(glob("d.js", "**\\*.js"), "`**` 는 0개 성분도 삼킨다");
        assert!(!glob("a\\b\\c\\d.txt", "**\\*.js"));
    }

    #[test]
    fn a_double_star_inside_a_segment_is_just_a_star() {
        // 구분자를 넘는 뜻은 **성분 하나로 통째로 적었을 때만** 갖는다.
        // 그러지 않으면 `**.js` 같은 표기가 조용히 트리 전체를 훑는다.
        assert!(glob("evil.js", "**.js"));
        assert!(!glob("a\\evil.js", "**.js"));
    }

    #[test]
    fn several_double_stars_still_match() {
        assert!(glob("a\\b\\c\\d\\e.txt", "a\\**\\d\\**"));
        assert!(!glob("a\\b\\c\\x\\e.txt", "a\\**\\d\\**"));
    }

    #[test]
    fn a_trailing_star_matches_the_rest() {
        assert!(glob("evil.exe", "evil*"));
        assert!(glob("evil", "evil*"));
        assert!(glob("a\\b\\c", "a\\**"));
        assert!(!glob("a\\b\\c", "a\\*"));
    }

    #[test]
    fn a_pathological_pattern_does_not_blow_up() {
        // `*a*a*a...` 형태에 역추적 구현은 지수 시간을 쓴다. 룰이 스캐너를
        // 정지시킬 수 있으면 그것 자체가 사고다.
        let text = "a".repeat(64);
        let pattern = "*a".repeat(32) + "b";
        let start = std::time::Instant::now();
        assert!(!glob(&text, &pattern));
        assert!(
            start.elapsed().as_millis() < 200,
            "glob 이 되돌아오지 않는다: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn empty_pattern_matches_only_empty_text() {
        assert!(glob("", ""));
        assert!(!glob("x", ""));
        assert!(glob("", "*"));
        assert!(glob("", "**"));
    }

    #[test]
    fn numbers_compare_as_numbers_not_as_text() {
        // 사전순이면 "9" > "10" 이 참이 되고, 룰 작성자는 알아채지 못한다.
        assert_eq!(cmp("9", "10"), Some(std::cmp::Ordering::Less));
        assert_eq!(cmp("4096", "1024"), Some(std::cmp::Ordering::Greater));
        assert_eq!(cmp("0", "0"), Some(std::cmp::Ordering::Equal));
    }

    #[test]
    fn instants_compare_because_the_format_is_fixed() {
        assert_eq!(
            cmp("2026-08-21T00:00:00Z", "2026-08-20T23:59:59Z"),
            Some(std::cmp::Ordering::Greater)
        );
        assert_eq!(
            cmp("2026-09-01T00:00:00Z", "2026-08-31T23:59:59Z"),
            Some(std::cmp::Ordering::Greater)
        );
    }

    #[test]
    fn a_shape_that_is_not_utc_is_not_an_instant() {
        // 형태가 어긋나면 사전순 비교가 조용히 거짓말을 한다.
        for s in [
            "2026-08-21T00:00:00+09:00",
            "2026-8-21T00:00:00Z",
            "2026-08-21 00:00:00Z",
            "2026-08-21T00:00:00",
            "",
        ] {
            assert!(magnitude(s).is_none(), "{s} 를 시각으로 읽었다");
        }
    }

    #[test]
    fn mixing_a_number_and_an_instant_is_not_comparable() {
        // 조용히 false 를 내면 룰이 왜 안 맞는지 알 수 없다.
        assert_eq!(cmp("4096", "2026-08-21T00:00:00Z"), None);
        assert_eq!(cmp("아무 문자열", "3"), None);
    }

    #[test]
    fn a_version_compares_component_by_component_not_as_a_number() {
        use std::cmp::Ordering::*;
        // **이것이 `lt` 로는 되지 않는 자리다.** 수로 읽으면 8.2.29 는 아예
        // 읽히지 않고, 두 자리로 줄여 8.10 과 8.9 를 견주면 순서가 뒤집힌다.
        assert_eq!(version_cmp("8.2.29", "8.2.30"), Some(Less));
        assert_eq!(version_cmp("8.2.10", "8.2.9"), Some(Greater));
        assert_eq!(version_cmp("8.10", "8.9"), Some(Greater));
        assert_eq!(cmp("8.10", "8.9"), Some(Less), "수로는 반대다");
    }

    #[test]
    fn a_missing_component_is_zero() {
        use std::cmp::Ordering::*;
        // 공급사가 `8.2.29` 로 적고 설치본이 `8.2.29.0` 으로 보고하는 자리가
        // 있다. 둘이 갈리면 수정된 기계가 취약으로 나간다.
        assert_eq!(version_cmp("8.2", "8.2.0"), Some(Equal));
        assert_eq!(version_cmp("8.2.0.0", "8.2"), Some(Equal));
        assert_eq!(version_cmp("8.2.1", "8.2"), Some(Greater));
        assert_eq!(version_cmp("8", "8.0.0"), Some(Equal));
    }

    #[test]
    fn leading_zeros_do_not_change_a_version() {
        use std::cmp::Ordering::*;
        assert_eq!(version_cmp("8.02.9", "8.2.9"), Some(Equal));
        assert_eq!(version_cmp("8.0", "8.00"), Some(Equal));
        assert_eq!(version_cmp("8.010", "8.9"), Some(Greater));
    }

    // ───────────────────────────── rpm_version_lt (2026-11-09)

    fn rpm_lt(a: &str, b: &str) -> bool {
        rpm_version_cmp(a, b) == Some(std::cmp::Ordering::Less)
    }

    /// rpm 이 내놓는 판 그대로 — RHEL 계열의 수정 판이 실제로 갈리는 모양들.
    #[test]
    fn rpm_versions_order_as_rpm_does() {
        // 개정의 마지막 조각 · `_` 는 구분자일 뿐이다.
        assert!(rpm_lt("8.0.30-8.el9_8", "8.0.30-8.el9_8.1"));
        assert!(rpm_lt("0:8.0.30-1.el9_2", "0:8.0.30-8.el9_8.1"));
        assert!(!rpm_lt("8.0.30-8.el9_8.1", "8.0.30-8.el9_8.1"));
        assert!(!rpm_lt("8.0.30-8.el9_8.2", "0:8.0.30-8.el9_8.1"));
        // 모듈 빌드 — 빌드 번호가 수로 갈린다.
        assert!(rpm_lt(
            "7.4.33-8.module+el8.10.0+25000+aaaa",
            "0:7.4.33-8.module+el8.10.0+25117+30337cca"
        ));
        // epoch 이 판보다 앞선다.
        assert!(rpm_lt("9.9.9-1", "1:1.0-1"));
        // 숫자 덩어리는 글자 덩어리보다 높다 · 앞의 0 은 값이 아니다.
        assert!(rpm_lt("1.a", "1.1"));
        assert_eq!(
            rpm_version_cmp("1.010-1", "1.10-1"),
            Some(std::cmp::Ordering::Equal)
        );
        // `~` 는 먼저(사전 배포) · `^` 는 끝보다 뒤(스냅숏).
        assert!(rpm_lt("1.0~rc1-1", "1.0-1"));
        assert!(rpm_lt("1.0-1", "1.0^git1-1"));
        // 개정은 둘 다 있을 때만 견준다(rpm 과 같다) — 빈 개정은 없는 것이다.
        assert_eq!(
            rpm_version_cmp("8.0.30", "8.0.30-8.el9_8.1"),
            Some(std::cmp::Ordering::Equal)
        );
        assert_eq!(
            rpm_version_cmp("8.0.30-", "8.0.30-8.el9_8.1"),
            Some(std::cmp::Ordering::Equal)
        );
    }

    #[test]
    fn a_shape_rpm_does_not_write_is_not_compared() {
        for bad in ["", "el9", "v8.0.30-1", "8.0.30 1", "x:1.0-1"] {
            assert_eq!(rpm_version_cmp(bad, "1.0-1"), None, "{bad:?}");
        }
    }

    // ───────────────────────────── pkg_version_lt (C-2 후속 · 2026-10-27)

    /// **이것이 백포트를 가리는 자리다** — 실측한 판으로 잰다.
    ///
    /// ubuntu 22.04 가 `php8.1-cli` 를 `8.1.2-1ubuntu2.28` 로 들고 있었다
    /// (C-2 측정). 상류 판은 `8.1.2` 로 고정이고 **고친 것은 개정뿐**이므로,
    /// 개정의 순서를 정하지 못하면 고친 기계도 취약으로 나간다.
    #[test]
    fn a_distro_revision_decides_the_order() {
        use std::cmp::Ordering::*;
        // 고친 판과 안 고친 판. 상류가 같다.
        assert_eq!(
            pkg_version_cmp("8.1.2-1ubuntu2.21", "8.1.2-1ubuntu2.28"),
            Some(Less)
        );
        assert_eq!(
            pkg_version_cmp("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.21"),
            Some(Greater)
        );
        assert_eq!(
            pkg_version_cmp("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.28"),
            Some(Equal)
        );
        // `2.28` 은 `2.9` 보다 크다 — 수로 견주기 때문이다(문자열로는 반대).
        assert_eq!(
            pkg_version_cmp("8.1.2-1ubuntu2.9", "8.1.2-1ubuntu2.28"),
            Some(Less)
        );
    }

    /// dpkg 자신의 규칙 (데비안 정책 §5.6.12). **`~` 가 끝보다도 먼저다.**
    #[test]
    fn the_dpkg_ordering_rules_hold() {
        use std::cmp::Ordering::*;
        for (a, b, want) in [
            // 사전 배포는 그 판보다 낮다 — `version_lt` 가 추측을 거부한 자리다.
            ("8.2.29~rc1", "8.2.29", Less),
            ("1.0~~", "1.0~", Less),
            ("1.0~", "1.0", Less),
            // 글자 아닌 문자는 글자보다 뒤다.
            ("1.0a", "1.0+b1", Less),
            // **epoch 이 가장 세다.** 상류 판이 낮아도 epoch 이 높으면 높다 —
            // 그것이 epoch 이 있는 이유다(앞서 잘못 적은 판을 뒤로 보낸다).
            ("1:0.1", "2.0", Greater),
            ("2:1.0", "1:9.9", Greater),
            // 없는 epoch 은 0, 없는 개정은 `0` 과 같다.
            ("1.0", "0:1.0", Equal),
            ("1.0", "1.0-0", Equal),
            // 개정이 있는 쪽이 높다.
            ("2.38.1-5+deb12u3", "2.38.1", Greater),
            ("2.38.1-5+deb12u3", "2.38.1-5+deb12u5", Less),
            // apk 의 `-rN` 도 같은 규칙으로 바로 선다.
            ("3.6.8-r1", "3.6.8-r2", Less),
            ("3.6.8-r10", "3.6.8-r9", Greater),
            // 앞의 0 은 값이 아니다.
            ("1.00.1", "1.0.1", Equal),
            // 자리 수가 u64 를 넘어도 넘치지 않는다.
            ("1.18446744073709551616", "1.18446744073709551617", Less),
        ] {
            assert_eq!(pkg_version_cmp(a, b), Some(want), "'{a}' vs '{b}'");
            assert_eq!(
                pkg_version_cmp(b, a),
                Some(want.reverse()),
                "'{b}' vs '{a}' (뒤집어서)"
            );
        }
    }

    /// **`_` 는 거절한다** — dpkg 와 apk 가 반대로 읽는다.
    #[test]
    fn a_shape_the_two_managers_read_differently_is_refused() {
        use remedy_sdk::catalog::is_pkg_version;
        // apk 에서 `_alpha1` 은 그 판보다 **낮고**, dpkg 의 규칙에서는 `_` 가
        // 글자보다 뒤라 **높다.** 순서가 반대이므로 추측하지 않는다.
        for s in ["1.0_alpha1", "1.0_p20240101", "8.2.29_rc1"] {
            assert!(!is_pkg_version(s), "'{s}' 를 판으로 읽었다");
            assert_eq!(pkg_version_cmp(s, "1.0"), None, "'{s}' 를 견줬다");
            assert_eq!(pkg_version_cmp("1.0", s), None, "'{s}' 를 견줬다");
        }
        // 판이 아닌 것도 거절한다.
        for s in ["", "wheezy", "v8.2.29", "-1", ":1.0", "a:1.0", "8.2 29"] {
            assert!(!is_pkg_version(s), "'{s}' 를 판으로 읽었다");
            assert_eq!(pkg_version_cmp(s, "1.0"), None, "'{s}' 를 견줬다");
        }
        // 그리고 받는 것들.
        for s in [
            "8.1.2-1ubuntu2.28",
            "1:2.38.1-5+deb12u3",
            "3.6.8-r1",
            "8.2.29~rc1",
            "3.134",
            "12.4+deb12u15",
        ] {
            assert!(is_pkg_version(s), "'{s}' 를 거절했다");
        }
    }

    /// 깨끗한 점숫자에서는 **두 연산자가 같은 답을 낸다.**
    ///
    /// 갈리면 작성자가 어느 것을 고르느냐로 판정이 달라지고, 그것은 조용하다.
    #[test]
    fn on_a_plain_dotted_version_both_operators_agree() {
        for (a, b) in [
            ("8.2.29", "8.2.30"),
            ("8.10", "8.9"),
            ("8.2.10", "8.2.9"),
            ("1.0", "1.0"),
            ("8.02.9", "8.2.9"),
        ] {
            assert_eq!(
                pkg_version_cmp(a, b),
                version_cmp(a, b),
                "'{a}' vs '{b}' 에서 두 연산자가 갈린다"
            );
        }
    }

    #[test]
    fn a_tail_is_not_a_version_because_its_order_cannot_be_guessed() {
        // `8.4.0RC1` 은 `8.4.0` 보다 **낮고** `8.2.29-1ubuntu1` 은 `8.2.29`
        // 보다 **높다**. 모양이 같고 순서가 반대라 문자열만으로 정할 수 없다.
        for s in [
            "8.4.0RC1",
            "8.2.29-1ubuntu1",
            "8.2.29-dev",
            "8.2.29+build.5",
            "v8.2.29",
            "8.2.x",
            "8.2.",
            ".8.2",
            "8..2",
            ".",
            "",
            "8.2 29",
            "８.２.２９",
        ] {
            assert!(!is_version(s), "{s} 를 버전으로 읽었다");
            assert_eq!(version_cmp(s, "8.2.29"), None, "{s} 를 견줬다");
            assert_eq!(version_cmp("8.2.29", s), None, "{s} 를 견줬다");
        }
    }

    #[test]
    fn whitespace_around_a_version_is_trimmed_like_a_magnitude() {
        use std::cmp::Ordering::*;
        // 수집기의 `value` 는 `=` 뒤를 다듬기만 한 원문이다. 같은 필드에 `lt`
        // 를 걸 때와 `version_lt` 를 걸 때 읽는 모양이 달라지면 안 된다.
        assert!(is_version(" 8.2.29 "));
        assert_eq!(version_cmp(" 8.2.29 ", "8.2.30"), Some(Less));
    }

    #[test]
    fn a_component_wider_than_u64_still_compares() {
        use std::cmp::Ordering::*;
        // 수로 파싱하면 넘쳐서 조용히 거짓말을 한다.
        let big = "18446744073709551616"; // u64::MAX + 1
        assert_eq!(version_cmp(big, "18446744073709551615"), Some(Greater));
        assert_eq!(version_cmp(&format!("1.{big}"), "1.1"), Some(Greater));
    }

    #[test]
    fn a_very_long_version_does_not_blow_up() {
        // 성분마다 한 번씩만 전진하므로 입력 길이에 선형이다 — glob 과 같은
        // 이유로 잰다: 룰이 스캐너를 정지시킬 수 없어야 한다.
        let a = "1.".repeat(20_000) + "1";
        let b = "1.".repeat(20_000) + "2";
        let start = std::time::Instant::now();
        assert_eq!(version_cmp(&a, &b), Some(std::cmp::Ordering::Less));
        assert!(
            start.elapsed().as_millis() < 200,
            "version_cmp 가 돌아오지 않는다: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn infinities_and_nan_are_not_magnitudes() {
        // `"inf".parse::<f64>()` 는 성공한다. 그것을 크기로 받아들이면
        // 어떤 비교도 참이 되는 값이 룰에 들어온다.
        for s in ["inf", "-inf", "NaN", "infinity"] {
            assert!(magnitude(s).is_none(), "{s} 를 수로 읽었다");
        }
    }
}
