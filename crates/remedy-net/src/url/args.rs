//! `remedy-net url` 의 명령줄 — URL 은 자리 인자로도 `--url` 로도, 옵션은 URL 앞뒤 어디에나.
//!
//! 거절은 **요청 · 약관 · 결과 폴더보다 먼저** 한다. 거절 문장은 URL 을 되풀이하지 않는다.

use super::consent::Answer;
use super::input::Input;
use super::policy::MAX_URLS;
use crate::cmdline::{tokens, Arg};
use crate::output::local_path;
pub(crate) use crate::output::DEFAULT_OUT_DIR;
use remedy_sdk::i18n::Lang;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Options {
    pub(crate) urls: Vec<String>,
    pub(crate) cacert: Option<String>,
    pub(crate) consent: Option<Answer>,
    pub(crate) out_dir: String,
    /// 점검할 주소를 명령줄이 아니라 **물어서** 받는다(`--ask`) — 본체의 메뉴가 띄울 때 쓴다.
    pub(crate) ask: bool,
    pub(crate) products: Products,
}

/// url 이 견주는 제품 — `--runtime php|apache|all`, 기본은 둘 다(코어 1.19.0 · 목표 `remedy_net엔진보완` 결정 2).
/// image · container 와 같은 옵션 이름이다. 응답 헤더로 보는 것은 PHP 와 Apache 뿐이라 `node` 는 받지 않는다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Products {
    pub(crate) php: bool,
    pub(crate) apache: bool,
}

impl Products {
    pub(crate) const ALL: Products = Products {
        php: true,
        apache: true,
    };

    fn parse(value: &str, lang: Lang) -> Result<Products, String> {
        match value {
            "php" => Ok(Products {
                php: true,
                apache: false,
            }),
            "apache" => Ok(Products {
                php: false,
                apache: true,
            }),
            "all" => Ok(Products::ALL),
            _ => Err(lang
                .t(
                    "--runtime 에는 php · apache · all 만 적을 수 있습니다(url 은 Node.js 를 보지 않습니다).",
                    "--runtime takes only php, apache or all (url does not check Node.js).",
                )
                .to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    Help,
    Run(Options),
}

pub(crate) fn parse(args: &[String], lang: Lang) -> Result<Parsed, String> {
    let mut o = Options {
        urls: Vec::new(),
        cacert: None,
        consent: None,
        out_dir: DEFAULT_OUT_DIR.to_string(),
        ask: false,
        products: Products::ALL,
    };
    // 읽기는 `image` · `container` 와 한 규칙이다(`cmdline::tokens`) — 전에는 이 명령만 따로 읽어 `---url` 을
    // 받고 `--help` 뒤의 오타를 넘겼다(같은 입력에 다른 답 · 2-5). 문법을 다 본 뒤 차례로 뜻을 본다.
    let words = tokens(
        args,
        &["ask"],
        &["url", "cacert", "consent", "out-dir", "runtime"],
        lang,
    )?;
    for w in words {
        match w {
            Arg::Flag("help") => return Ok(Parsed::Help),
            Arg::Flag(_) => o.ask = true,
            Arg::Positional(u) | Arg::Value("url", u) => push_url(&mut o.urls, &u, lang)?,
            Arg::Value("cacert", v) => o.cacert = Some(local_path(v, lang)?),
            Arg::Value("out-dir", v) => o.out_dir = local_path(v, lang)?,
            Arg::Value("runtime", v) => o.products = Products::parse(&v, lang)?,
            Arg::Value(_, v) => o.consent = Some(Answer::parse(&v, lang)?),
        }
    }
    if o.ask {
        // 묻기로 했으면 명령줄의 주소와 섞지 않는다 — 어느 쪽이 대상인지 한 가지로 남게.
        if !o.urls.is_empty() {
            return Err(lang
                .t(
                    "--ask 는 주소를 물어 받습니다 — 명령줄의 URL 과 함께 쓸 수 없습니다.",
                    "--ask reads the URLs interactively — it cannot be combined with URLs on the command line.",
                )
                .to_string());
        }
        return Ok(Parsed::Run(o));
    }
    if o.urls.is_empty() {
        return Err(lang
            .t(
                "점검할 URL 을 적으십시오 — remedy-net url URL [URL ...] [옵션]",
                "give the URLs to check — remedy-net url URL [URL ...] [options]",
            )
            .to_string());
    }
    for raw in &o.urls {
        Input::parse(raw).map_err(|e| e.message(lang).to_string())?;
    }
    Ok(Parsed::Run(o))
}

fn push_url(urls: &mut Vec<String>, raw: &str, lang: Lang) -> Result<(), String> {
    if raw.trim().is_empty() || urls.len() >= MAX_URLS {
        return Err(lang
            .t(
                "URL 은 비워 둘 수 없고 50개까지 적을 수 있습니다.",
                "a URL cannot be empty, and at most 50 URLs can be given.",
            )
            .to_string());
    }
    urls.push(raw.to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Parsed, String> {
        let v: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse(&v, Lang::Ko)
    }

    #[test]
    fn ask_takes_no_urls_from_the_command_line() {
        let Ok(Parsed::Run(o)) = p(&["--ask", "--out-dir", "out"]) else {
            panic!("거절됐다");
        };
        assert!(o.ask && o.urls.is_empty());
        // 묻기와 명령줄의 주소를 섞지 않는다 — 어느 쪽이 대상인지 한 가지로 남게.
        assert!(p(&["--ask", "http://a.example/"]).is_err());
        assert!(p(&["--url", "http://a.example/", "--ask"]).is_err());
    }

    #[test]
    fn after_a_double_dash_everything_is_a_url() {
        // `--` 뒤의 `--out-dir` 은 옵션이 아니라 URL 로 읽혀 형식 검사에서 거절된다.
        assert!(p(&["http://a.example/", "--", "--out-dir"]).is_err());
        let Ok(Parsed::Run(o)) = p(&["--", "http://a.example/"]) else {
            panic!("거절됐다");
        };
        assert_eq!(o.urls, vec!["http://a.example/"]);
    }

    #[test]
    fn options_are_read_wherever_they_stand() {
        let Ok(Parsed::Run(o)) = p(&[
            "http://a.example/",
            "--out-dir",
            "out",
            "--url=http://b.example/",
            "--consent",
            "y",
            "http://c.example/",
        ]) else {
            panic!("거절됐다");
        };
        assert_eq!(
            o.urls,
            vec![
                "http://a.example/",
                "http://b.example/",
                "http://c.example/"
            ]
        );
        assert_eq!(o.out_dir, "out");
        assert_eq!(o.consent, Some(Answer::Yes));
    }

    #[test]
    fn bad_input_is_refused_before_anything_runs() {
        assert_eq!(p(&["--help"]), Ok(Parsed::Help));
        assert_eq!(p(&["http://a.example/", "-h"]), Ok(Parsed::Help));
        for bad in [
            &[][..],
            &["--consent", "invalid", "http://a.example/"][..],
            &["--consent", "Y", "http://a.example/"][..],
            &["http://a.example/", "--out-dir", ""][..],
            &["http://a.example/", "--out-dir"][..],
            &["http://a.example/", "--out-dir", "\\\\server\\share"][..],
            &["http://a.example/", "--bogus"][..],
            &["http://a.example/", "-url", "http://b.example/"][..],
            &["http://a.example/", "file:///etc/passwd"][..],
            &[""][..],
        ] {
            assert!(p(bad).is_err(), "{bad:?} 를 받았다");
        }
        let many: Vec<String> = (0..51).map(|i| format!("http://a.example/{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(p(&many).is_err(), "51개를 받았다");
        assert!(p(&many[..50]).is_ok());
    }

    #[test]
    fn runtime_picks_php_apache_or_both() {
        let run = |extra: &[&str]| {
            let mut v = vec!["http://a.example/"];
            v.extend_from_slice(extra);
            match p(&v) {
                Ok(Parsed::Run(o)) => Some(o.products),
                _ => None,
            }
        };
        let php = Products {
            php: true,
            apache: false,
        };
        let apache = Products {
            php: false,
            apache: true,
        };
        assert_eq!(run(&[]), Some(Products::ALL), "기본은 둘 다");
        assert_eq!(run(&["--runtime", "all"]), Some(Products::ALL));
        assert_eq!(run(&["--runtime=php"]), Some(php));
        assert_eq!(run(&["--runtime", "apache"]), Some(apache));
        for bad in [
            &["--runtime", "node"][..],
            &["--runtime", "PHP"][..],
            &["--runtime"][..],
            &["--runtime", ""][..],
        ] {
            assert_eq!(run(bad), None, "{bad:?} 를 받았다");
        }
    }

    #[test]
    fn the_same_words_get_the_same_answer_as_image_and_container() {
        // 전에는 이 명령만 따로 읽어 `---url` 을 받고 `--help` 뒤의 오타를 넘겼다(같은 입력에 다른 답 · 2-5).
        for bad in [
            &["---url", "http://a.example/"][..],
            &["----out-dir=o", "http://a.example/"][..],
            &["--help", "--bogus"][..],
            &["http://a.example/", "--out-dir", "--x"][..],
        ] {
            assert!(p(bad).is_err(), "{bad:?} 를 받았다");
        }
        // 문법이 맞으면 도움말이 먼저다 — 값의 뜻(`--runtime python`)은 보지 않는다.
        assert_eq!(p(&["--help", "--runtime", "python"]), Ok(Parsed::Help));
        // `--ask` 는 값을 받지 않는다.
        let e = p(&["--ask=x"]).unwrap_err();
        assert!(e.contains("--ask"), "{e}");
        // 값이 `--` 로 시작해야 하면 붙여 쓴다.
        assert!(matches!(
            p(&["http://a.example/", "--out-dir=--x"]),
            Ok(Parsed::Run(_))
        ));
    }

    #[test]
    fn refusals_do_not_repeat_secrets() {
        let e = p(&["http://user:MOCK_PASSWORD@a.example/"]).unwrap_err();
        assert!(!e.contains("MOCK_PASSWORD"), "{e}");
    }
}
