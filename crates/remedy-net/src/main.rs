//! `remedy-net` — ESTsecurity 전용백신의 동반 모듈. 네트워크가 필요한 점검을 맡는 별도 바이너리다.
//!
//! # 왜 본체와 따로인가
//!
//! 본체 `remedy` 는 관리자 권한으로 지우고 되돌리는 바이너리라, **통신하지 못한다는 것을 남이 확인할 수
//! 있게** 해 두었다 — 배포본의 임포트를 `cargo xtask static` 이 전수 검사한다(설계-01 D9). 원격 확인 ·
//! 이미지 · 컨테이너처럼 네트워크가 필요한 점검은 그 성질을 건드리지 않도록 이 바이너리에 둔다. 둘은
//! 서로 링크하지도 실행하지도 않고 파일로만 주고받는다. 그 선은 설계-04 §1 의 금지 표를
//! `cargo xtask arch` 가 지킨다 — 본체 → 이 크레이트 · 이 크레이트 → 파괴 경로 · 본체 → 네트워크 크레이트.
//!
//! # 결과 계약
//!
//! 종료 코드는 **본체의 표**(`docs/operator.md` §3 · [`ExitCode`])를 그대로 쓴다 — 무인 배포 스크립트가 두
//! 바이너리를 같은 코드로 읽는다. 판정 어휘는 *양호 · 취약 · 확인 필요* 이고 [`Outcome`] 이 그 대응이다.
//!
//! 이 버전에는 점검 명령이 아직 없다 — 도움말 · 버전 · 언어 · 종료 코드만 선다. 점검은 `url` → `image` →
//! `container` 차례로 더한다.
#![forbid(unsafe_code)]

use remedy_report::brand;
use remedy_sdk::artifact::ExitCode;
use remedy_sdk::i18n::{self, Lang};

/// 한 번의 실행이 끝난 모양. 숫자는 본체의 종료 코드 표([`ExitCode`])에서 온다 — 여기서 새로 정하지 않는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// 양호 — 확인한 대상이 전부 고친 버전이다. 도움말 · 버전도 이것으로 끝난다.
    Clear,
    /// 취약 — 한 항목이라도 취약이면 전체가 취약이다.
    Vulnerable,
    /// 확인 필요 — 확인하지 못한 것을 양호로 내지 않는다.
    Review,
    /// 입력 오류 · 동의하지 않음.
    BadInput,
    /// 처리 실패 — 도구가 일을 끝내지 못했다.
    Failed,
}

impl Outcome {
    /// 도움말의 종료 코드 표가 이 차례로 선다.
    const ALL: [Outcome; 5] = [
        Outcome::Clear,
        Outcome::Vulnerable,
        Outcome::Review,
        Outcome::BadInput,
        Outcome::Failed,
    ];

    /// 본체 표의 그 칸.
    fn exit(self) -> ExitCode {
        match self {
            Outcome::Clear => ExitCode::NoThreat,
            Outcome::Vulnerable => ExitCode::FoundNotRemediated,
            Outcome::Review => ExitCode::IncompleteObservation,
            Outcome::BadInput => ExitCode::UsageError,
            Outcome::Failed => ExitCode::InternalError,
        }
    }

    fn meaning(self, lang: Lang) -> &'static str {
        match self {
            Outcome::Clear => lang.t("양호 · 도움말", "clear · help"),
            Outcome::Vulnerable => lang.t("취약", "vulnerable"),
            Outcome::Review => lang.t("확인 필요", "needs review"),
            Outcome::BadInput => lang.t(
                "입력 오류 · 동의하지 않음",
                "input error · consent declined",
            ),
            Outcome::Failed => lang.t("처리 실패", "processing failure"),
        }
    }
}

/// 명령줄 어디에 와도 되는 것 — 본체(`remedy`)와 같은 규칙이다.
struct Global {
    rest: Vec<String>,
    lang: Option<String>,
    ascii: Option<bool>,
}

fn split_global(args: Vec<String>) -> Global {
    let mut rest = Vec::with_capacity(args.len());
    let mut lang = None;
    let mut ascii = None;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--lang" => lang = it.next(),
            "--ascii" => ascii = Some(true),
            _ => rest.push(a),
        }
    }
    Global { rest, lang, ascii }
}

fn main() {
    let g = split_global(std::env::args().skip(1).collect());
    // `--lang kr` 처럼 모르는 값은 무시하되 **말한다** — 조용히 영어로 가면 왜 영어인지 모른다(본체와 같다).
    let unknown_lang = g
        .lang
        .as_deref()
        .filter(|v| Lang::try_parse(v).is_none())
        .map(str::to_string);
    let lang_flag = g.lang.filter(|_| unknown_lang.is_none());
    let ascii = i18n::detect_ascii(g.ascii);
    let lang = {
        let l = Lang::detect_with(lang_flag.as_deref(), user_locale().as_deref());
        // 한글을 못 그리는 자리에 한글을 내보내지 않는다. 명시했을 때만 예외 — 본체와 같다.
        let explicit = lang_flag.is_some() || std::env::var("REMEDY_LANG").is_ok();
        if ascii && !explicit {
            Lang::En
        } else {
            l
        }
    };
    i18n::init(lang, ascii);
    if let Some(v) = unknown_lang {
        eprintln!(
            "--lang '{v}': 모르는 언어라 무시했습니다 (ko | en) / unknown language, ignored (ko | en)"
        );
    }
    let outcome = run(&g.rest, lang);
    std::process::exit(i32::from(outcome.exit().code()));
}

/// 명령 하나를 돈다. 화면은 여기서 쓰고, 끝난 모양을 돌려준다.
fn run(args: &[String], lang: Lang) -> Outcome {
    match args.first().map(String::as_str) {
        None | Some("--help" | "-h" | "help") => {
            print!("{}", ascii_safe(help(lang)));
            Outcome::Clear
        }
        Some("--version" | "-V" | "version") => {
            println!("{}", ascii_safe(version_line(lang)));
            Outcome::Clear
        }
        Some(other) => {
            let why = lang.pick(
                format!(
                    "알 수 없는 명령입니다: {other} — 쓰는 법은 'remedy-net --help' 로 보십시오."
                ),
                format!("unknown command: {other} — see 'remedy-net --help'."),
            );
            eprintln!("{}", ascii_safe(why));
            Outcome::BadInput
        }
    }
}

fn version_line(lang: Lang) -> String {
    format!(
        "{} {} (remedy-net)",
        brand::product(lang),
        env!("CARGO_PKG_VERSION")
    )
}

/// 도움말. 명령 설명은 본체의 도움말처럼 해라체다.
fn help(lang: Lang) -> String {
    let ver = env!("CARGO_PKG_VERSION");
    let mut s = String::new();
    s.push_str(&lang.pick(
        format!("{} — 동반 모듈 remedy-net {ver}\n\n", brand::product(lang)),
        format!(
            "{} — companion module remedy-net {ver}\n\n",
            brand::product(lang)
        ),
    ));
    s.push_str(lang.t(
        "네트워크가 필요한 점검을 맡는 프로그램이다. 본체 remedy 와 따로 돌고, 둘은 파일로만 주고받는다.\n\
         이 버전에는 아직 점검 명령이 없다.\n\n",
        "Runs the checks that need the network. It runs apart from the main program (remedy); the two\n\
         exchange files only. This version has no check command yet.\n\n",
    ));
    s.push_str(lang.t("쓰는 법:\n", "Usage:\n"));
    s.push_str(lang.t(
        "  remedy-net --help       이 도움말\n\
         \x20 remedy-net --version    버전\n\
         \x20 --lang ko|en            출력 언어 (REMEDY_LANG 으로도)\n\
         \x20 --ascii                 기호를 ASCII 로\n\n",
        "  remedy-net --help       this help\n\
         \x20 remedy-net --version    version\n\
         \x20 --lang ko|en            output language (REMEDY_LANG also works)\n\
         \x20 --ascii                 ASCII symbols only\n\n",
    ));
    s.push_str(lang.t(
        "종료 코드 (본체 remedy 와 같은 표):\n",
        "Exit codes (the same table as remedy):\n",
    ));
    for o in Outcome::ALL {
        s.push_str(&format!("  {}  {}\n", o.exit().code(), o.meaning(lang)));
    }
    s
}

/// ASCII 모드면 문장에 박힌 기호(`—` · `·`)까지 접는다 — 본체의 `ascii_safe` 와 같다.
fn ascii_safe(text: String) -> String {
    if !i18n::deco().ascii {
        return text;
    }
    match i18n::ascii_fold(&text) {
        std::borrow::Cow::Owned(s) => s,
        std::borrow::Cow::Borrowed(_) => text,
    }
}

/// 사용자 로케일 이름 — `HKCU\Control Panel\International\LocaleName`, 예: `ko-KR`. 본체가
/// `remedy-platform` 으로 읽는 것과 같은 값이다. 동반 모듈은 그 크레이트를 링크하지 않으므로(설계-04 §1)
/// 여기서 같은 자리를 읽기만 한다. 그 밖의 OS 는 `None` — 거기서는 `LANG` 이 같은 말을 한다.
fn user_locale() -> Option<String> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        let key = winreg::RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(r"Control Panel\International")
            .ok()?;
        let v: String = key.get_value("LocaleName").ok()?;
        let v = v.trim().to_string();
        (!v.is_empty()).then_some(v)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_sit_on_the_remedy_exit_code_table() {
        // 결과 계약 — 양호 0 · 취약 2 · 확인 필요 6 · 입력 오류와 동의 안 함 4 · 처리 실패 7.
        let codes: Vec<(Outcome, u8)> =
            Outcome::ALL.iter().map(|o| (*o, o.exit().code())).collect();
        assert_eq!(
            codes,
            vec![
                (Outcome::Clear, 0),
                (Outcome::Vulnerable, 2),
                (Outcome::Review, 6),
                (Outcome::BadInput, 4),
                (Outcome::Failed, 7),
            ]
        );
    }

    #[test]
    fn global_flags_may_stand_anywhere() {
        let g = split_global(
            ["version", "--lang", "en", "--ascii"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
        assert_eq!(g.rest, vec!["version".to_string()]);
        assert_eq!(g.lang.as_deref(), Some("en"));
        assert_eq!(g.ascii, Some(true));
    }

    #[test]
    fn help_lists_every_exit_code_in_both_languages() {
        for lang in [Lang::Ko, Lang::En] {
            let h = help(lang);
            for o in Outcome::ALL {
                let line = format!("  {}  {}\n", o.exit().code(), o.meaning(lang));
                assert!(h.contains(&line), "{lang:?} 도움말에 '{line}' 가 없다");
            }
        }
    }
}
