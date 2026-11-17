//! 화면에 내는 글자 — 기호 접기와, 남이 보낸 글자 걸러 내기. 화면에 쓰기([`write_screen`]).

use remedy_sdk::i18n;

/// 화면에 그대로 쓴다(줄바꿈은 `text` 가 가진다). 쓰지 못하면 버린다 — **패닉하지 않는다.** 화면을 읽는
/// 쪽이 먼저 닫힌 파이프(`remedy-net … | head`)에서도 점검과 결과 파일은 끝까지 가고 종료 코드는 그 점검의
/// 것이다(본체의 `tee::write_screen` 과 같다). 1.21.0 까지는 `println!` 이 패닉해 SIGABRT(134)로 죽었다.
pub fn write_screen(stderr: bool, text: &str) {
    use std::io::Write as _;
    let _ = if stderr {
        std::io::stderr().lock().write_all(text.as_bytes())
    } else {
        std::io::stdout().lock().write_all(text.as_bytes())
    };
}

/// `print!` 과 같되 끊긴 화면에서 패닉하지 않는다([`write_screen`]).
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::text::write_screen(false, &format!($($arg)*))
    };
}

/// `println!` 과 같되 끊긴 화면에서 패닉하지 않는다([`write_screen`]).
#[macro_export]
macro_rules! outln {
    () => {
        $crate::text::write_screen(false, "\n")
    };
    ($($arg:tt)*) => {
        $crate::text::write_screen(false, &format!("{}\n", format_args!($($arg)*)))
    };
}

/// `eprintln!` 과 같되 끊긴 화면에서 패닉하지 않는다([`write_screen`]).
#[macro_export]
macro_rules! errln {
    () => {
        $crate::text::write_screen(true, "\n")
    };
    ($($arg:tt)*) => {
        $crate::text::write_screen(true, &format!("{}\n", format_args!($($arg)*)))
    };
}

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

/// 서버가 보낸 글자를 화면에 낼 때 — 제어 문자를 `?` 로 바꾸고 `max` 글자에서 자른다. 본체가 거절한 명령줄
/// 낱말을 되풀이할 때와 같은 규칙이라 SDK 한 벌을 쓴다.
pub(crate) use remedy_sdk::i18n::plain;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_text_cannot_steer_the_terminal() {
        assert_eq!(plain("PHP/8.3.6\u{1b}[2J", 80), "PHP/8.3.6?[2J");
        assert_eq!(plain("abcdef", 3), "abc…");
    }
}
