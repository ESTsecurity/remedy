//! Go 문자열 함수와 같은 답 — 스캐너가 `strings` · `unicode` 로 가르던 자리.
//!
//! 엔진이 준 이름(Windows 경로 · 환경 변수 키 · 아카이브 항목 이름)을 스캐너와 같은 규칙으로 견주려고 둔다. Rust
//! 의 문자열 대소문자 변환은 특수 대응(`ß` → `SS` · 낱말 끝의 `Σ` → `ς`)을 쓰지만 Go 는 글자 하나를 글자 하나로
//! 바꾼다 — 그 차이가 경로 비교의 답을 바꾸지 않게 글자 단위로 다룬다.

use crate::scan::linuxmeta;

/// `strings.ToLower` — 글자마다 소문자 하나.
pub(crate) fn lower(s: &str) -> String {
    linuxmeta::lower(s.as_bytes())
}

/// `strings.ToUpper` — 글자마다 대문자 하나. 대응이 여러 글자(`ß` → `SS`)면 그 글자를 그대로 둔다 — Go 의 단순
/// 대응에는 그런 글자의 대문자가 없다.
pub(crate) fn upper(s: &str) -> String {
    s.chars()
        .map(|c| single(c.to_uppercase()).unwrap_or(c))
        .collect()
}

/// `strings.EqualFold` — 유니코드 단순 접기로 같은가. `K`(U+212A)는 `k` 와, `ſ`(U+017F)는 `s` 와 같다.
pub(crate) fn fold_eq(a: &str, b: &str) -> bool {
    let (mut x, mut y) = (a.chars(), b.chars());
    loop {
        match (x.next(), y.next()) {
            (None, None) => return true,
            (Some(c), Some(d)) if c == d || fold(c) == fold(d) => {}
            _ => return false,
        }
    }
}

/// 접기 궤도의 대표 글자 — 대문자로 올렸다가 소문자로 내린다. 터키어의 점 있는 `İ` 와 점 없는 `ı` 는 Go 의 단순
/// 접기에서 제 자신뿐이라 그대로 둔다.
fn fold(c: char) -> char {
    if matches!(c, '\u{130}' | '\u{131}') {
        return c;
    }
    let up = single(c.to_uppercase()).unwrap_or(c);
    single(up.to_lowercase()).unwrap_or(up)
}

/// 대응이 글자 하나일 때만 그 글자.
fn single(mut it: impl Iterator<Item = char>) -> Option<char> {
    let c = it.next()?;
    it.next().is_none().then_some(c)
}

/// `strings.Cut` — 처음 나온 `sep` 앞뒤와, 찾았는지. 못 찾으면 앞은 글 전체다.
pub(crate) fn cut<'a>(s: &'a str, sep: &str) -> (&'a str, &'a str, bool) {
    match s.split_once(sep) {
        Some((before, after)) => (before, after, true),
        None => (s, "", false),
    }
}

/// 바이트를 Go 처럼 글자로 — UTF-8 로 풀리지 않는 바이트는 하나마다 U+FFFD 다.
pub(crate) fn chars(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut rest = b;
    while let Some((c, n)) = linuxmeta::first_char(rest) {
        out.push(c);
        rest = &rest[n..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_rules_follow_go_one_character_at_a_time() {
        assert_eq!(lower("PHP.EXE"), "php.exe");
        assert_eq!(lower("İ"), "i");
        assert_eq!(upper("straße"), "STRAßE");
        assert_eq!(upper("conın$"), "CONIN$");
        assert!(fold_eq("PHP.EXE", "php.exe"));
        assert!(fold_eq("\u{212a}", "k"));
        assert!(fold_eq("ſ", "S"));
        assert!(fold_eq("ẞ", "ß"));
        assert!(!fold_eq("ı", "i"));
        assert!(!fold_eq("İ", "i"));
        assert!(!fold_eq("php", "php.exe"));
    }

    #[test]
    fn cut_and_byte_decoding_match_go() {
        assert_eq!(cut("A=1=2", "="), ("A", "1=2", true));
        assert_eq!(cut("PATH", "="), ("PATH", "", false));
        assert_eq!(chars(b"a\xffb"), "a\u{fffd}b");
    }
}
