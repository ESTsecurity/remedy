//! 화면에 내는 글자 — 기호 접기와, 남이 보낸 글자 걸러 내기.

use remedy_sdk::i18n;

/// ASCII 모드면 문장에 박힌 기호(`—` · `·`)까지 접는다 — 본체의 `ascii_safe` 와 같다.
pub fn ascii_safe(text: String) -> String {
    if !i18n::deco().ascii {
        return text;
    }
    match i18n::ascii_fold(&text) {
        std::borrow::Cow::Owned(s) => s,
        std::borrow::Cow::Borrowed(_) => text,
    }
}

/// 서버가 보낸 글자를 화면에 낼 때 — 제어 문자를 `?` 로 바꾸고 `max` 글자에서 자른다. 터미널 제어열
/// (ESC …)이 화면을 바꾸지 못하게 한다. 결과 파일에는 원문이 간다(JSON 직렬화가 이스케이프한다).
pub(crate) fn plain(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max * 4));
    for (i, c) in s.chars().enumerate() {
        if i == max {
            out.push('…');
            break;
        }
        out.push(if c.is_control() { '?' } else { c });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_text_cannot_steer_the_terminal() {
        assert_eq!(plain("PHP/8.3.6\u{1b}[2J", 80), "PHP/8.3.6?[2J");
        assert_eq!(plain("abcdef", 3), "abc…");
    }
}
