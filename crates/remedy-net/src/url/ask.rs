//! 점검할 주소를 **물어서** 받는다(`--ask`) — 본체(`remedy`)의 메뉴가 이 프로그램을 띄울 때의 길이다.
//!
//! 본체는 주소를 다루지 않는다: 무엇을 점검할지 묻는 것부터 결과까지 이 프로그램이 한다. 한 줄에
//! 하나씩 받고 빈 줄이 끝이다. 잘못된 주소는 까닭을 말하고 같은 번호를 다시 묻는다 — 거절 문장은
//! 적은 주소를 되풀이하지 않는다([`super::input`]).

use super::input::Input;
use super::policy::MAX_URLS;
use remedy_sdk::i18n::Lang;
use std::io::{BufRead, Read, Write};

/// 한 줄의 상한 — 넘는 줄은 주소가 아니다.
const MAX_LINE: u64 = 2048;

/// 주소를 받는다. 하나도 받지 못했으면 빈 목록 — 부르는 쪽이 점검하지 않고 끝낸다.
pub(crate) fn urls(lang: Lang, input: &mut dyn BufRead, out: &mut dyn Write) -> Vec<String> {
    let _ = writeln!(
        out,
        "{}",
        lang.t(
            "점검할 주소(URL)를 한 줄에 하나씩 적으십시오. 다 적었으면 빈 줄에서 Enter 를 누릅니다 (50개까지).",
            "Type the addresses (URLs) to check, one per line. Press Enter on an empty line when done (up to 50).",
        )
    );
    let _ = writeln!(
        out,
        "{}",
        lang.t(
            "  http:// 또는 https:// 로 시작하게 적습니다 — 예: https://www.example.com/",
            "  Start each with http:// or https:// — e.g. https://www.example.com/",
        )
    );
    let mut got: Vec<String> = Vec::new();
    while got.len() < MAX_URLS {
        let _ = write!(
            out,
            "{}",
            lang.pick(
                format!("주소 {}: ", got.len() + 1),
                format!("URL {}: ", got.len() + 1)
            )
        );
        let _ = out.flush();
        let mut line = String::new();
        let n = (&mut *input)
            .take(MAX_LINE + 1)
            .read_line(&mut line)
            .unwrap_or(0);
        if n == 0 {
            // 입력이 닫혔다 — 끝난 것으로 본다.
            let _ = writeln!(out);
            break;
        }
        if n as u64 > MAX_LINE && !line.ends_with('\n') {
            discard_line(input);
            let _ = writeln!(
                out,
                "  {}",
                lang.t(
                    "너무 깁니다 — 주소 하나를 한 줄에 적으십시오.",
                    "Too long — type one address per line."
                )
            );
            continue;
        }
        let typed = line.trim();
        if typed.is_empty() {
            break;
        }
        match Input::parse(typed) {
            Ok(_) => got.push(typed.to_string()),
            Err(e) => {
                let _ = writeln!(out, "  {}", e.message(lang));
            }
        }
    }
    if got.len() == MAX_URLS {
        let _ = writeln!(
            out,
            "{}",
            lang.t(
                "50개를 다 받았습니다 — 여기까지 점검합니다.",
                "50 addresses received — checking these."
            )
        );
    }
    got
}

/// 상한을 넘은 줄의 나머지를 버린다 — 다음 물음이 그 꼬리를 답으로 읽지 않게.
fn discard_line(input: &mut dyn BufRead) {
    loop {
        let mut rest = String::new();
        let n = (&mut *input)
            .take(MAX_LINE)
            .read_line(&mut rest)
            .unwrap_or(0);
        if n == 0 || rest.ends_with('\n') {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(typed: &str) -> (Vec<String>, String) {
        let mut out = Vec::new();
        let got = urls(Lang::Ko, &mut typed.as_bytes(), &mut out);
        (got, String::from_utf8(out).unwrap())
    }

    #[test]
    fn one_address_per_line_until_an_empty_line() {
        let (got, out) =
            ask("https://a.example/\n  http://b.example:8080/x  \n\nhttps://ignored.example/\n");
        assert_eq!(got, vec!["https://a.example/", "http://b.example:8080/x"]);
        assert!(
            out.contains("주소 1: ") && out.contains("주소 3: "),
            "{out}"
        );
        assert!(!out.contains("주소 4: "));
    }

    #[test]
    fn a_bad_address_is_explained_and_asked_again() {
        let (got, out) = ask("example.com\nfile:///etc/passwd\nhttps://ok.example/\n\n");
        assert_eq!(got, vec!["https://ok.example/"]);
        // 같은 번호를 다시 묻는다 — 잘못 적은 줄이 번호를 먹지 않는다.
        assert_eq!(out.matches("주소 1: ").count(), 3, "{out}");
        assert!(out.contains("http 또는 https"), "{out}");
    }

    #[test]
    fn refusals_do_not_echo_what_was_typed() {
        let (got, out) = ask("http://user:MOCK_PASSWORD@a.example/\n\n");
        assert!(got.is_empty());
        assert!(!out.contains("MOCK_PASSWORD"), "{out}");
    }

    #[test]
    fn a_closed_input_ends_the_list() {
        assert_eq!(ask("").0, Vec::<String>::new());
        assert_eq!(ask("https://a.example/").0, vec!["https://a.example/"]);
    }

    #[test]
    fn an_overlong_line_is_dropped_whole() {
        let long = format!(
            "https://a.example/{}\nhttps://b.example/\n\n",
            "x".repeat(5000)
        );
        let (got, out) = ask(&long);
        assert_eq!(got, vec!["https://b.example/"]);
        assert!(out.contains("너무 깁니다"), "{out}");
    }

    #[test]
    fn at_most_fifty_are_taken() {
        let typed: String = (0..60)
            .map(|i| format!("https://a.example/{i}\n"))
            .collect();
        let (got, out) = ask(&typed);
        assert_eq!(got.len(), 50);
        assert!(out.contains("50개를 다 받았습니다"), "{out}");
    }
}
