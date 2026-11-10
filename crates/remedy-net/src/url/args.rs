//! `remedy-net url` 의 명령줄 — URL 은 자리 인자로도 `--url` 로도, 옵션은 URL 앞뒤 어디에나.
//!
//! 거절은 **요청 · 약관 · 결과 폴더보다 먼저** 한다. 거절 문장은 URL 을 되풀이하지 않는다.

use super::consent::Answer;
use super::input::Input;
use super::policy::MAX_URLS;
use remedy_sdk::i18n::Lang;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Options {
    pub(crate) urls: Vec<String>,
    pub(crate) cacert: Option<String>,
    pub(crate) consent: Option<Answer>,
    pub(crate) out_dir: String,
    /// 점검할 주소를 명령줄이 아니라 **물어서** 받는다(`--ask`) — 본체의 메뉴가 띄울 때 쓴다.
    pub(crate) ask: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    Help,
    Run(Options),
}

/// 결과 폴더의 기본값 — 스캐너와 같다.
pub(crate) const DEFAULT_OUT_DIR: &str = "results";

pub(crate) fn parse(args: &[String], lang: Lang) -> Result<Parsed, String> {
    let mut o = Options {
        urls: Vec::new(),
        cacert: None,
        consent: None,
        out_dir: DEFAULT_OUT_DIR.to_string(),
        ask: false,
    };
    let mut positional_only = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if !positional_only && arg == "--" {
            positional_only = true;
            continue;
        }
        if positional_only || !arg.starts_with('-') || arg == "-" {
            push_url(&mut o.urls, arg, lang)?;
            continue;
        }
        if matches!(arg.as_str(), "-h" | "--help") {
            return Ok(Parsed::Help);
        }
        if arg == "--ask" {
            o.ask = true;
            continue;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        let key = name.trim_start_matches('-');
        if !name.starts_with("--") || !matches!(key, "url" | "cacert" | "consent" | "out-dir") {
            return Err(lang.pick(
                format!("알 수 없는 옵션입니다: {}", crate::text::plain(name, 40)),
                format!("unknown option: {}", crate::text::plain(name, 40)),
            ));
        }
        let value = match inline.or_else(|| it.next().cloned()) {
            Some(v) => v,
            None => {
                return Err(lang.pick(
                    format!("--{key} 뒤에 값을 적으십시오."),
                    format!("--{key} needs a value."),
                ))
            }
        };
        if value.trim().is_empty() {
            return Err(lang.pick(
                format!("--{key} 의 값을 비워 둘 수 없습니다."),
                format!("--{key} cannot be empty."),
            ));
        }
        match key {
            "url" => push_url(&mut o.urls, &value, lang)?,
            "cacert" => o.cacert = Some(local_path(value, lang)?),
            "out-dir" => o.out_dir = local_path(value, lang)?,
            _ => {
                o.consent = Some(match value.as_str() {
                    "y" => Answer::Yes,
                    "n" => Answer::No,
                    _ => {
                        return Err(lang
                            .t(
                                "--consent 에는 y 또는 n 만 적을 수 있습니다.",
                                "--consent takes only y or n.",
                            )
                            .to_string())
                    }
                })
            }
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

/// 이 기계의 경로만 — 네트워크 경로(`\\` · `//`)와 제어 문자는 받지 않는다.
fn local_path(value: String, lang: Lang) -> Result<String, String> {
    if value.chars().any(char::is_control) || value.starts_with("\\\\") || value.starts_with("//") {
        return Err(lang
            .t(
                "이 기계의 경로를 적으십시오(네트워크 경로는 받지 않습니다).",
                "give a local path (network paths are not accepted).",
            )
            .to_string());
    }
    Ok(value)
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
    fn refusals_do_not_repeat_secrets() {
        let e = p(&["http://user:MOCK_PASSWORD@a.example/"]).unwrap_err();
        assert!(!e.contains("MOCK_PASSWORD"), "{e}");
    }
}
