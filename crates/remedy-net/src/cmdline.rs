//! 명령줄 읽기 — `image` · `container` 가 함께 쓴다. 규칙은 `url` 과 같다: 자리 인자와 옵션을 섞어 써도 되고,
//! 값은 `--이름 값` 과 `--이름=값` 둘 다, `--` 뒤는 모두 자리 인자다.
//!
//! 거절은 **약관 · 결과 폴더보다 먼저** 한다. 거절 문장은 받은 값을 길게 되풀이하지 않는다.

use crate::scan::model::Product;
use remedy_sdk::i18n::Lang;

/// `--runtime` 의 값 — `php` · `node` · `all`(둘 다). 스캐너와 같다.
pub(crate) fn runtime(value: &str, lang: Lang) -> Result<Vec<Product>, String> {
    match value {
        "php" => Ok(vec![Product::Php]),
        "node" => Ok(vec![Product::Node]),
        "all" => Ok(vec![Product::Php, Product::Node]),
        _ => Err(lang
            .t(
                "--runtime 에는 php · node · all 만 적을 수 있습니다.",
                "--runtime takes only php, node or all.",
            )
            .to_string()),
    }
}

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
        let Some(value) = inline.or_else(|| it.next().cloned()) else {
            return Err(lang.pick(
                format!("--{key} 뒤에 값을 적으십시오."),
                format!("--{key} needs a value."),
            ));
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
}
