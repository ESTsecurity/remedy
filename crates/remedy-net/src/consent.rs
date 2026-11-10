//! 약관 동의 — 점검을 시작하기 전에 한 번(결정 7). `url` · `image` · `container` 가 함께 쓴다 — 약관 문장과
//! 묻는 줄은 명령마다 다르고, 묻고 받는 방식은 같다.
//!
//! 무인 실행은 `--consent y|n` 으로 미리 답한다 — 그래도 약관은 화면에 낸다(무엇에 답했는지 기록에 남게).
//! 거절 · 입력 없음(EOF)은 동의가 아니다.

use crate::text::ascii_safe;
use remedy_sdk::i18n::Lang;
use std::io::{BufRead, Read, Write};

/// 미리 준 답(`--consent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    Yes,
    No,
}

impl Answer {
    /// `--consent` 의 값 — `y` · `n` 만.
    pub(crate) fn parse(value: &str, lang: Lang) -> Result<Answer, String> {
        match value {
            "y" => Ok(Answer::Yes),
            "n" => Ok(Answer::No),
            _ => Err(lang
                .t(
                    "--consent 에는 y 또는 n 만 적을 수 있습니다.",
                    "--consent takes only y or n.",
                )
                .to_string()),
        }
    }
}

/// 어떻게 동의했나 — 결과 파일의 `consent.via`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
    Prompt,
    Flag,
}

impl Via {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Via::Prompt => "prompt",
            Via::Flag => "flag",
        }
    }
}

/// 한 줄의 상한 — 넘는 입력은 답이 아니다(동의하지 않음).
const MAX_LINE: u64 = 128;

/// 약관(`terms`)을 내고 답을 받는다. 동의했으면 `Some`. `prompt` 는 묻는 줄이다.
pub(crate) fn ask(
    terms: &str,
    prompt: &str,
    preset: Option<Answer>,
    lang: Lang,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Option<Via> {
    write!(out, "{}", ascii_safe(terms.to_string())).ok()?;
    if let Some(answer) = preset {
        let v = match answer {
            Answer::Yes => "y",
            Answer::No => "n",
        };
        writeln!(out, "{} --consent {v}", lang.t("약관 동의:", "Terms:")).ok()?;
        return (answer == Answer::Yes).then_some(Via::Flag);
    }
    loop {
        write!(out, "{}", ascii_safe(prompt.to_string())).ok()?;
        out.flush().ok()?;
        let mut line = String::new();
        let n = (&mut *input)
            .take(MAX_LINE + 1)
            .read_line(&mut line)
            .unwrap_or(0);
        if n == 0 || (n as u64 > MAX_LINE && !line.ends_with('\n')) {
            let _ = writeln!(out);
            return None;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "y" => return Some(Via::Prompt),
            "n" | "" => return None,
            _ => {
                let _ = writeln!(
                    out,
                    "{}",
                    lang.t("y 또는 n 을 입력하십시오.", "Type y or n.")
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TERMS: &str = "이용 조건\n1. 시험.\n";
    const PROMPT: &str = "동의하십니까? [y/n]: ";

    fn run(preset: Option<Answer>, typed: &str) -> (Option<Via>, String) {
        let mut out = Vec::new();
        let got = ask(
            TERMS,
            PROMPT,
            preset,
            Lang::Ko,
            &mut typed.as_bytes(),
            &mut out,
        );
        (got, String::from_utf8(out).unwrap())
    }

    #[test]
    fn only_y_agrees_and_other_words_ask_again() {
        let (got, out) = run(None, "y\n");
        assert_eq!(got, Some(Via::Prompt));
        assert!(out.find("이용 조건").unwrap() < out.find(PROMPT).unwrap());
        assert_eq!(run(None, "n\n").0, None);
        assert_eq!(run(None, "\n").0, None);
        assert_eq!(run(None, "").0, None, "EOF 는 동의가 아니다");
        let (got, out) = run(None, "yes\nY\n");
        assert_eq!(got, Some(Via::Prompt));
        assert_eq!(out.matches(PROMPT).count(), 2);
        let long = format!("{}\ny\n", "y".repeat(200));
        assert_eq!(run(None, &long).0, None, "한 줄 상한을 넘는 입력");
    }

    #[test]
    fn a_preset_prints_the_terms_and_asks_nothing() {
        let (got, out) = run(Some(Answer::Yes), "");
        assert_eq!(got, Some(Via::Flag));
        assert!(out.contains("이용 조건"));
        assert!(out.contains("약관 동의: --consent y"));
        assert!(!out.contains(PROMPT));
        let (got, out) = run(Some(Answer::No), "y\n");
        assert_eq!(got, None);
        assert!(out.contains("약관 동의: --consent n"));
    }

    #[test]
    fn the_flag_value_is_only_y_or_n() {
        assert_eq!(Answer::parse("y", Lang::Ko), Ok(Answer::Yes));
        assert_eq!(Answer::parse("n", Lang::Ko), Ok(Answer::No));
        for bad in ["Y", "yes", "", " y"] {
            assert!(Answer::parse(bad, Lang::Ko).is_err(), "{bad:?}");
        }
    }
}
