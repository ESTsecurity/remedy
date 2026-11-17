//! 명령줄 읽기 — `url` · `image` · `container` 가 함께 쓴다(같은 입력에 같은 답). 자리 인자와 옵션을 섞어 써도
//! 되고, 값은 `--이름 값` 과 `--이름=값` 둘 다(띄어 쓴 값은 `--` 로 시작할 수 없다 — 그러면 값이 빠진 것이다),
//! `--` 뒤는 모두 자리 인자다.
//!
//! 거절은 **약관 · 결과 폴더보다 먼저** 한다. 거절 문장은 받은 값을 길게 되풀이하지 않는다.

use crate::scan::model::Product;
use remedy_sdk::i18n::Lang;

/// `--runtime` 의 값 — `php` · `node` · `apache` · `all`(셋 다). `apache` 는 코어 1.18.0 에서 더했고 `all` 도 그것을
/// 본다(목표 `remedy_net아파치` 결정 4 — 새 룰이 *모두 검사* 에 드는 것과 같은 꼴).
pub(crate) fn runtime(value: &str, lang: Lang) -> Result<Vec<Product>, String> {
    match value {
        "php" => Ok(vec![Product::Php]),
        "node" => Ok(vec![Product::Node]),
        "apache" => Ok(vec![Product::Apache]),
        "all" => Ok(ALL.to_vec()),
        _ => Err(lang
            .t(
                "--runtime 에는 php · node · apache · all 만 적을 수 있습니다.",
                "--runtime takes only php, node, apache or all.",
            )
            .to_string()),
    }
}

/// `--runtime` 을 주지 않았을 때와 `all` 이 보는 제품.
pub(crate) const ALL: [Product; 3] = [Product::Php, Product::Node, Product::Apache];

/// 읽은 낱말 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Arg {
    Positional(String),
    /// 값이 없는 옵션 — `-h` 는 `help` 로 읽힌다.
    Flag(&'static str),
    Value(&'static str, String),
}

/// `flags` 는 값이 없는 옵션, `valued` 는 값을 받는 옵션의 이름(`--` 없이)이다. `help` 는 늘 받는다.
pub(crate) fn tokens(
    args: &[String],
    flags: &[&'static str],
    valued: &[&'static str],
    lang: Lang,
) -> Result<Vec<Arg>, String> {
    let mut out = Vec::with_capacity(args.len());
    let mut positional_only = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if !positional_only && arg == "--" {
            positional_only = true;
            continue;
        }
        if positional_only || !arg.starts_with('-') || arg == "-" {
            out.push(Arg::Positional(arg.clone()));
            continue;
        }
        if matches!(arg.as_str(), "-h" | "--help") {
            out.push(Arg::Flag("help"));
            continue;
        }
        // `split_global` 이 언어로 먹지 않고 남긴 `--lang` — 뒤가 옵션이었으니 값이 빠진 것이다.
        if arg == "--lang" {
            return Err(needs_value("lang", lang));
        }
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        let key = name.strip_prefix("--").unwrap_or("");
        if let Some(flag) = flags.iter().find(|f| **f == key) {
            if inline.is_some() {
                return Err(lang.pick(
                    format!("--{key} 에는 값을 적지 않습니다."),
                    format!("--{key} takes no value."),
                ));
            }
            out.push(Arg::Flag(flag));
            continue;
        }
        let Some(option) = valued.iter().find(|v| **v == key) else {
            return Err(lang.pick(
                format!("알 수 없는 옵션입니다: {}", crate::text::plain(name, 40)),
                format!("unknown option: {}", crate::text::plain(name, 40)),
            ));
        };
        // 띄어 쓴 값이 `--` 로 시작하면 값이 빠진 것이다 — 다음 옵션을 값으로 삼키지 않는다(`--out-dir --x` 가
        // `--x` 폴더에 썼다). 값 자체가 그렇게 시작해야 하면 `--이름=값` 으로 붙여 쓴다.
        let value = match inline {
            Some(v) => v,
            None => match it.next() {
                Some(v) if !v.starts_with("--") => v.clone(),
                _ => return Err(needs_value(key, lang)),
            },
        };
        if value.trim().is_empty() {
            return Err(lang.pick(
                format!("--{key} 의 값을 비워 둘 수 없습니다."),
                format!("--{key} cannot be empty."),
            ));
        }
        out.push(Arg::Value(option, value));
    }
    Ok(out)
}

fn needs_value(key: &str, lang: Lang) -> String {
    lang.pick(
        format!("--{key} 뒤에 값을 적으십시오."),
        format!("--{key} needs a value."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(args: &[&str]) -> Result<Vec<Arg>, String> {
        let v: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        tokens(&v, &["list"], &["path", "out-dir"], Lang::Ko)
    }

    #[test]
    fn options_and_positionals_mix_and_both_value_forms_work() {
        assert_eq!(
            t(&[
                "a.tar",
                "--path",
                "b.tar",
                "--out-dir=out",
                "--list",
                "c.tar"
            ])
            .unwrap(),
            vec![
                Arg::Positional("a.tar".to_string()),
                Arg::Value("path", "b.tar".to_string()),
                Arg::Value("out-dir", "out".to_string()),
                Arg::Flag("list"),
                Arg::Positional("c.tar".to_string()),
            ]
        );
    }

    #[test]
    fn after_a_double_dash_everything_is_positional() {
        assert_eq!(
            t(&["--", "--list", "-h"]).unwrap(),
            vec![
                Arg::Positional("--list".to_string()),
                Arg::Positional("-h".to_string()),
            ]
        );
        assert_eq!(t(&["-"]).unwrap(), vec![Arg::Positional("-".to_string())]);
    }

    #[test]
    fn help_is_always_understood() {
        assert_eq!(t(&["-h"]).unwrap(), vec![Arg::Flag("help")]);
        assert_eq!(t(&["x", "--help"]).unwrap()[1], Arg::Flag("help"));
    }

    #[test]
    fn bad_options_are_refused() {
        for bad in [
            &["--bogus"][..],
            &["-path", "a"][..],
            &["--path"][..],
            &["--path", ""][..],
            &["--path=  "][..],
            &["--list=yes"][..],
        ] {
            assert!(t(bad).is_err(), "{bad:?} 를 받았다");
        }
    }

    #[test]
    fn a_spaced_value_cannot_be_the_next_option() {
        // 다음 옵션을 값으로 삼키지 않는다 — `--out-dir --x` 가 `--x` 폴더에 썼다.
        assert!(t(&["--path", "--list"]).is_err());
        assert!(t(&["--out-dir", "--path", "x"]).is_err());
        // 붙여 쓰면 값이다.
        assert_eq!(
            t(&["--out-dir=--x"]).unwrap(),
            vec![Arg::Value("out-dir", "--x".to_string())]
        );
        // `split_global` 이 남긴 `--lang` 은 값이 빠진 것이다.
        assert!(t(&["--lang", "--list"]).is_err());
    }
}
