//! 약관 동의 — 요청을 보내기 전에 한 번(결정 7 · 문구는 2026-11-10 카드).
//!
//! 무인 실행은 `--consent y|n` 으로 미리 답한다 — 그래도 약관은 화면에 낸다(무엇에 답했는지 기록에 남게).
//! 거절 · 입력 없음(EOF)은 동의가 아니다.

use crate::text::ascii_safe;
use remedy_sdk::i18n::Lang;
use std::io::{BufRead, Read, Write};

/// 결과 파일에 싣는 약관 판.
pub(crate) const TERMS_VERSION: &str = "2026-11-10.1";

/// 미리 준 답(`--consent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    Yes,
    No,
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

pub(crate) fn terms(lang: Lang) -> &'static str {
    lang.t(
        "이용 조건\n\
         1. 소유하거나 점검을 허락받은 서버에만 쓰십시오.\n\
         2. 적은 URL 에 HEAD 요청을 보내 응답 헤더만 읽습니다(HEAD 를 받지 않는 서버에만 GET 한 번).\n\
         \x20  공격 요청이나 자동 수정은 하지 않습니다.\n\
         3. 요청은 2초 간격으로 보내지만 서버 접속 기록에 남고 부하가 생길 수 있습니다.\n\
         4. 헤더만으로는 패치 여부를 확인할 수 없어 '양호' 를 내지 않습니다. 취약이 나오지 않아도\n\
         \x20  안전하다는 뜻이 아닙니다.\n\
         5. 결과는 지정한 폴더에 저장됩니다. 서버 주소 · 헤더 같은 내부 정보가 들어가니 공유하기 전에\n\
         \x20  확인하십시오.\n",
        "Terms of use\n\
         1. Use this only on servers you own or are authorized to check.\n\
         2. It sends a HEAD request to each URL you give and reads only the response headers (one GET\n\
         \x20  only if the server does not accept HEAD). It sends no attack requests and changes nothing.\n\
         3. Requests are 2 seconds apart, but they appear in the server's access log and add some load.\n\
         4. Headers cannot prove a patch, so the result is never \"clear\". A result without\n\
         \x20  \"vulnerable\" does not mean the server is safe.\n\
         5. Results are saved in the folder you choose. They contain internal details such as server\n\
         \x20  addresses and headers — review them before sharing.\n",
    )
}

pub(crate) fn prompt(lang: Lang) -> &'static str {
    lang.t(
        "점검 권한이 있고 위 내용에 동의하십니까? [y/n]: ",
        "Are you authorized to check these servers, and do you agree to the above? [y/n]: ",
    )
}

/// 한 줄의 상한 — 넘는 입력은 답이 아니다(동의하지 않음).
const MAX_LINE: u64 = 128;

/// 약관을 내고 답을 받는다. 동의했으면 `Some`.
pub(crate) fn ask(
    preset: Option<Answer>,
    lang: Lang,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Option<Via> {
    write!(out, "{}", ascii_safe(terms(lang).to_string())).ok()?;
    if let Some(answer) = preset {
        let v = match answer {
            Answer::Yes => "y",
            Answer::No => "n",
        };
        writeln!(out, "{} --consent {v}", lang.t("약관 동의:", "Terms:")).ok()?;
        return (answer == Answer::Yes).then_some(Via::Flag);
    }
    loop {
        write!(out, "{}", prompt(lang)).ok()?;
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

    fn run(preset: Option<Answer>, typed: &str) -> (Option<Via>, String) {
        let mut out = Vec::new();
        let got = ask(preset, Lang::Ko, &mut typed.as_bytes(), &mut out);
        (got, String::from_utf8(out).unwrap())
    }

    #[test]
    fn terms_come_before_the_question_and_only_y_agrees() {
        let (got, out) = run(None, "y\n");
        assert_eq!(got, Some(Via::Prompt));
        assert!(out.find("이용 조건").unwrap() < out.find(prompt(Lang::Ko)).unwrap());
        assert_eq!(run(None, "n\n").0, None);
        assert_eq!(run(None, "\n").0, None);
        assert_eq!(run(None, "").0, None, "EOF 는 동의가 아니다");
        let (got, out) = run(None, "yes\nY\n");
        assert_eq!(got, Some(Via::Prompt));
        assert_eq!(out.matches(prompt(Lang::Ko)).count(), 2);
        let long = format!("{}\ny\n", "y".repeat(200));
        assert_eq!(run(None, &long).0, None, "한 줄 상한을 넘는 입력");
    }

    #[test]
    fn a_preset_answer_prints_the_terms_and_asks_nothing() {
        let (got, out) = run(Some(Answer::Yes), "");
        assert_eq!(got, Some(Via::Flag));
        assert!(out.contains("약관 동의: --consent y"));
        assert!(!out.contains(prompt(Lang::Ko)));
        let (got, out) = run(Some(Answer::No), "y\n");
        assert_eq!(got, None);
        assert!(out.contains("약관 동의: --consent n"));
    }
}
