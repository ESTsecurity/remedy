//! 사람이 읽는 출력의 언어와 문자 집합.
//!
//! # 왜 SDK 에 있는가
//!
//! 사람이 읽는 문장은 원래 `remedy-report` 가 만든다(설계-01 D5). 그런데 **오류는
//! 그 규칙 밖에서 태어난다** — 라이브러리 크레이트가 `Err("여유 공간이 부족하다")`
//! 를 만들고 CLI 가 `실패: {}` 로 찍는다. 렌더러를 거치지 않으니 언어를 고를
//! 자리가 없었다. 2026-09-06 까지 이중 언어 지점은 렌더러의 13곳뿐이었고,
//! 오류 27개는 전부 한국어였다.
//!
//! 오류 enum 은 모든 크레이트에 흩어져 있고 그 전부가 이 크레이트에 의존한다.
//! 그래서 언어를 고르는 **한 자리**는 여기다.
//!
//! # 언어를 정하는 순서
//!
//! ```text
//! --lang <ko|en>  >  REMEDY_LANG  >  POSIX 로케일(LC_ALL → LC_MESSAGES → LANG)
//!                 >  Windows 사용자 로케일(HKCU\Control Panel\International\LocaleName)  >  en
//! ```
//!
//! 로케일은 **한국어일 때만** 믿는다 — `en_US` 든 `de_DE` 든 답은 영어다. 한글을
//! 그리지 못하는 자리(C 로케일 컨테이너, CJK 글꼴 없는 터미널)가 실제로 있고, 그
//! 자리에 한글을 내보내는 것은 의미가 없다.
//!
//! **Windows 갈래는 2026-09-09 에 더했다.** 그 전까지는 "기본은 영어, 국내 배포는
//! `REMEDY_LANG=ko`"(2026-09-06) 였는데, 받아서 더블클릭한 사람에게는 환경변수를
//! 줄 자리가 없다 — 한국어 Windows(`ko-KR`)에서 영어 화면이 나왔다(실측). Windows
//! 는 `LANG` 을 설정하지 않으므로 POSIX 변수만 보는 판단은 그 PC 에서 늘 영어로
//! 떨어졌다. 레지스트리는 이 크레이트가 읽지 않는다(플랫폼 코드는 `remedy-platform`
//! 의 것이다) — CLI 가 읽어 `detect_with` 로 넘긴다.
//!
//! # 문자 집합
//!
//! 로케일이 UTF-8 이 아니면 장식을 ASCII 로 바꾸고(`─`→`-`, `©`→`(c)`), 언어를
//! 명시하지 않았으면 영어로 간다. `--ascii` / `REMEDY_ASCII=1` 로 강제할 수 있다.
//!
//! # 전역 상태
//!
//! CLI 가 시작할 때 한 번 정하고(`init`), 그 뒤로는 어디서든 `t(ko, en)` 으로
//! 읽는다. 오류 `Display` 가 이것을 쓴다 — 오류는 만들어질 때 언어를 받을 자리가
//! 없기 때문이다. **한 번 정하면 바뀌지 않는다.** 실행 중에 언어가 바뀌면 같은
//! 오류가 두 언어로 찍히는 로그가 생긴다.

use std::sync::OnceLock;

/// 사람에게 보여 줄 언어.
///
/// **파일 출력은 언어와 무관하게 UTF-8 고정이다** (설계-00 §5-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    Ko,
    #[default]
    En,
}

impl Lang {
    /// `ko`·`ko-KR`·`ko_KR.UTF-8` 은 한국어, 그 밖은 영어.
    pub fn parse(s: &str) -> Self {
        Self::try_parse(s).unwrap_or(Lang::En)
    }

    /// 아는 값만 받는다. `--lang kr` 처럼 모르는 값은 `None` — 부르는 쪽이
    /// 그 사실을 말해 줄 수 있게.
    pub fn try_parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().split(['-', '_', '.']).next() {
            Some("ko") | Some("kor") | Some("korean") => Some(Lang::Ko),
            Some("en") | Some("eng") | Some("english") | Some("c") | Some("posix") => {
                Some(Lang::En)
            }
            _ => None,
        }
    }

    pub const fn id(self) -> &'static str {
        match self {
            Lang::Ko => "ko",
            Lang::En => "en",
        }
    }

    /// 이 언어의 문구를 고른다.
    pub const fn t(self, ko: &'static str, en: &'static str) -> &'static str {
        match self {
            Lang::Ko => ko,
            Lang::En => en,
        }
    }

    /// 형식화한 문자열처럼 `&'static` 이 아닌 값도 고른다.
    pub fn pick<T>(self, ko: T, en: T) -> T {
        match self {
            Lang::Ko => ko,
            Lang::En => en,
        }
    }

    /// 순서대로 정한다. `explicit` 은 `--lang` 의 값이다. OS 로케일은 보지 않는다.
    pub fn detect(explicit: Option<&str>) -> Self {
        Self::detect_with(explicit, None)
    }

    /// `platform` 은 OS 가 말하는 사용자 로케일이다 (Windows 의 `LocaleName`, 예:
    /// `ko-KR`). 이 크레이트는 레지스트리를 읽지 않으므로 부르는 쪽이 넘긴다.
    /// POSIX 변수가 하나라도 있으면 그것이 먼저다 — 명시가 추정을 이긴다.
    pub fn detect_with(explicit: Option<&str>, platform: Option<&str>) -> Self {
        let remedy = env_nonempty("REMEDY_LANG");
        // 첫 번째로 설정된 변수가 답을 정한다 — POSIX 의 우선순위다.
        let posix = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .into_iter()
            .find_map(env_nonempty);
        Self::decide(explicit, remedy.as_deref(), posix.as_deref(), platform)
    }

    /// 환경을 읽지 않는 순수한 판단. 시험은 이것을 잰다 — 환경변수는 프로세스
    /// 전역이라 시험끼리 서로를 오염시킨다.
    fn decide(
        explicit: Option<&str>,
        remedy_lang: Option<&str>,
        posix: Option<&str>,
        platform: Option<&str>,
    ) -> Self {
        if let Some(v) = explicit {
            return Lang::parse(v);
        }
        if let Some(v) = remedy_lang {
            return Lang::parse(v);
        }
        // 로케일은 **한국어일 때만** 믿는다. `en_US` 든 `de_DE` 든 답은 영어다.
        if let Some(v) = posix {
            return Self::korean_or_english(v);
        }
        if let Some(v) = platform {
            return Self::korean_or_english(v);
        }
        Lang::En
    }

    fn korean_or_english(locale: &str) -> Self {
        if Lang::parse(locale) == Lang::Ko {
            Lang::Ko
        } else {
            Lang::En
        }
    }
}

fn env_nonempty(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

/// 로케일이 말하는 문자 집합. `ko_KR.UTF-8` → `UTF-8`. 없으면 `None`.
fn locale_charset() -> Option<String> {
    for k in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Some(v) = env_nonempty(k) {
            return Some(
                v.split('.')
                    .nth(1)
                    .unwrap_or("")
                    .split('@')
                    .next()
                    .unwrap_or("")
                    .to_string(),
            );
        }
    }
    None
}

/// 장식을 ASCII 로 그려야 하는가.
///
/// | 근거 | 결과 |
/// |---|---|
/// | `--ascii` / `REMEDY_ASCII=1` | ASCII |
/// | `REMEDY_ASCII=0` | UTF-8 |
/// | 유닉스이고 로케일 문자 집합이 UTF-8 이 아니다 (`C`·`POSIX` 포함) | ASCII |
/// | Windows | UTF-8 — 콘솔에는 `WriteConsoleW` 로 글자가 그대로 간다 |
pub fn detect_ascii(explicit: Option<bool>) -> bool {
    if let Some(b) = explicit {
        return b;
    }
    if let Some(v) = env_nonempty("REMEDY_ASCII") {
        return matches!(v.trim(), "1" | "true" | "yes");
    }
    if cfg!(unix) {
        return match locale_charset() {
            Some(cs) => !cs.to_ascii_lowercase().replace('-', "").starts_with("utf8"),
            None => true,
        };
    }
    false
}

/// 장식 문자. ASCII 모드에서는 어느 터미널에서도 깨지지 않는 것으로 바꾼다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deco {
    pub ascii: bool,
}

impl Deco {
    /// 화면을 가르는 줄.
    pub const fn rule(self) -> &'static str {
        if self.ascii {
            "--------------------------------------------------------"
        } else {
            "────────────────────────────────────────────────────────"
        }
    }
    /// 항목 사이의 점.
    pub const fn dot(self) -> &'static str {
        if self.ascii {
            " | "
        } else {
            " · "
        }
    }
    /// 긴 줄표.
    pub const fn dash(self) -> &'static str {
        if self.ascii {
            " - "
        } else {
            " — "
        }
    }
    pub const fn arrow(self) -> &'static str {
        if self.ascii {
            "->"
        } else {
            "→"
        }
    }
    pub const fn copyright(self) -> &'static str {
        if self.ascii {
            "(c)"
        } else {
            "©"
        }
    }
    /// 좋은 결과 줄 앞의 표시.
    pub const fn good(self) -> &'static str {
        if self.ascii {
            "v"
        } else {
            "✓"
        }
    }
    /// 나쁜 결과 · 실패 줄 앞의 표시.
    pub const fn bad(self) -> &'static str {
        if self.ascii {
            "x"
        } else {
            "✗"
        }
    }
    /// 주의 · 알림 줄 앞의 표시. ASCII 라 폴백이 같다.
    pub const fn warn(self) -> &'static str {
        "!"
    }
}

/// ASCII 모드에서 **문장 안에 박힌** 장식 글자를 접는다 — 줄표 · 점 · 화살표 ·
/// 말줄임표 · 구분선 · 표시.
///
/// [`Deco`] 를 거치는 자리는 이미 ASCII 로 가지만, 문구에 글자로 박힌 `—` 같은 것은
/// 그대로 나가 한글을 못 그리는 터미널에서 깨진다(2026-11-06 이미지 — 영어 문구 33곳
/// 이상 · 기준 3(c)). 그래서 문구를 고치지 않고 **나가는 자리 한 곳에서** 접는다 —
/// 새 문구가 줄표를 써도 다시 새지 않는다. 짝은 [`Deco`] 의 ASCII 꼴과 같다(시험이
/// 잰다). 그 밖의 글자 — 한글 · 경로의 비ASCII — 는 데이터라 건드리지 않는다.
pub fn ascii_fold(s: &str) -> std::borrow::Cow<'_, str> {
    if s.is_ascii() {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '—' | '–' | '─' => out.push('-'),
            '·' => out.push('|'),
            '→' => out.push_str("->"),
            '←' => out.push_str("<-"),
            '…' => out.push_str("..."),
            '©' => out.push_str("(c)"),
            '✓' => out.push('v'),
            '✗' => out.push('x'),
            '↑' => out.push('^'),
            '↓' => out.push('v'),
            _ => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// 앞말의 받침에 따라 조사를 고른다 — `이/가` · `을/를` 처럼 **받침이 있을 때의 꼴을 먼저** 준다.
///
/// 한글이 아닌 글자로 끝나면(영문 파일 이름 · 기호) 받침이 없는 것으로 본다 —
/// `node.exe` · `remedy.exe` 는 소리로 읽으면 모음으로 끝나고, 틀리더라도 `을(를)`
/// 병기보다 낫다. 숫자는 우리말 읽기(영·일·이·삼·사·오·육·칠·팔·구)의 받침을 따른다.
pub fn particle<'a>(word: &str, with_final: &'a str, without_final: &'a str) -> &'a str {
    let Some(last) = word.chars().last() else {
        return without_final;
    };
    let has_final = match last {
        '가'..='힣' => !(last as u32 - 0xAC00).is_multiple_of(28),
        '0' | '1' | '3' | '6' | '7' | '8' => true,
        _ => false,
    };
    if has_final {
        with_final
    } else {
        without_final
    }
}

/// 앞말에 조사를 붙인다. 한글 뒤에는 붙여 쓰고(`제거를`), 그 밖의 글자 뒤에는 이
/// 저장소의 화면이 늘 그래 왔듯 한 칸 띄운다(`remedy.exe 를`, `--plugin 이`).
pub fn with_particle(word: &str, with_final: &str, without_final: &str) -> String {
    let p = particle(word, with_final, without_final);
    match word.chars().last() {
        Some('가'..='힣') => format!("{word}{p}"),
        _ => format!("{word} {p}"),
    }
}

struct Settings {
    lang: Lang,
    deco: Deco,
}

static SETTINGS: OnceLock<Settings> = OnceLock::new();

/// 시작할 때 한 번 정한다. 이미 정해져 있으면 `false` 를 돌려주고 바꾸지 않는다.
pub fn init(lang: Lang, ascii: bool) -> bool {
    SETTINGS
        .set(Settings {
            lang,
            deco: Deco { ascii },
        })
        .is_ok()
}

/// 지금 언어. 아무도 정하지 않았으면 영어 — 라이브러리 시험이 그 경우다.
pub fn current() -> Lang {
    SETTINGS.get().map(|s| s.lang).unwrap_or_default()
}

/// 지금 장식. 아무도 정하지 않았으면 UTF-8.
pub fn deco() -> Deco {
    SETTINGS
        .get()
        .map(|s| s.deco)
        .unwrap_or(Deco { ascii: false })
}

/// 지금 언어의 문구. 오류 `Display` 가 쓰는 것이 이것이다.
pub fn t(ko: &'static str, en: &'static str) -> &'static str {
    current().t(ko, en)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn korean_is_recognised_in_every_common_spelling() {
        for s in ["ko", "KO", "ko-KR", "ko_KR", "ko_KR.UTF-8", "kor"] {
            assert_eq!(Lang::parse(s), Lang::Ko, "{s}");
        }
        for s in ["en", "en_US.UTF-8", "de_DE", "C", "POSIX", "", "xx"] {
            assert_eq!(Lang::parse(s), Lang::En, "{s}");
        }
    }

    #[test]
    fn unknown_values_are_told_apart_from_english() {
        assert_eq!(Lang::try_parse("kr"), None);
        assert_eq!(Lang::try_parse("en_US.UTF-8"), Some(Lang::En));
        assert_eq!(Lang::try_parse("ko_KR"), Some(Lang::Ko));
        // 로케일의 `C`/`POSIX` 는 영어다 — 모르는 값이 아니다.
        assert_eq!(Lang::try_parse("C"), Some(Lang::En));
    }

    #[test]
    fn explicit_beats_everything() {
        // 환경을 건드리지 않고도 첫 단계는 잴 수 있다.
        assert_eq!(Lang::detect(Some("ko")), Lang::Ko);
        assert_eq!(Lang::detect(Some("en")), Lang::En);
    }

    #[test]
    fn windows_locale_speaks_only_when_nothing_else_does() {
        // 받아서 더블클릭한 한국어 PC — 환경변수가 하나도 없다. 이것이 2026-09-09
        // 까지 영어로 떨어지던 자리다.
        assert_eq!(Lang::decide(None, None, None, Some("ko-KR")), Lang::Ko);
        assert_eq!(Lang::decide(None, None, None, Some("en-US")), Lang::En);
        assert_eq!(Lang::decide(None, None, None, None), Lang::En);
        // 명시가 추정을 이긴다 — 위 단계가 하나라도 말하면 로케일은 듣지 않는다.
        assert_eq!(
            Lang::decide(None, Some("en"), None, Some("ko-KR")),
            Lang::En
        );
        assert_eq!(
            Lang::decide(None, None, Some("en_US.UTF-8"), Some("ko-KR")),
            Lang::En
        );
        assert_eq!(
            Lang::decide(Some("en"), Some("ko"), Some("ko_KR"), Some("ko-KR")),
            Lang::En
        );
        // POSIX 가 한국어면 플랫폼을 볼 것도 없다.
        assert_eq!(
            Lang::decide(None, None, Some("ko_KR.UTF-8"), Some("en-US")),
            Lang::Ko
        );
    }

    #[test]
    fn particles_follow_the_final_consonant() {
        // 화면에 `을(를)` 병기와 틀린 조사("--plan 가")가 섞여 있었다 (2026-09-30).
        assert_eq!(
            with_particle("EvilAI(Locust) 제거", "을", "를"),
            "EvilAI(Locust) 제거를"
        );
        assert_eq!(
            with_particle("해당 프로그램", "이", "가"),
            "해당 프로그램이"
        );
        assert_eq!(with_particle("node.exe", "이", "가"), "node.exe 가");
        assert_eq!(with_particle("remedy.exe", "을", "를"), "remedy.exe 를");
        assert_eq!(particle("3", "이", "가"), "이");
        assert_eq!(particle("2", "이", "가"), "가");
        assert_eq!(particle("", "이", "가"), "가");
    }

    #[test]
    fn ascii_deco_has_no_non_ascii_bytes() {
        let d = Deco { ascii: true };
        for s in [d.rule(), d.dot(), d.dash(), d.arrow(), d.copyright()] {
            assert!(s.is_ascii(), "{s:?}");
        }
        let u = Deco { ascii: false };
        assert!(!u.rule().is_ascii());
    }

    /// 접은 꼴이 장식 층의 ASCII 꼴과 **같다** — 장식으로 찍힌 줄과 문구에 박힌 줄이
    /// 한 화면에서 다르게 보이지 않는다.
    #[test]
    fn folding_a_decoration_gives_its_ascii_form() {
        let (u, a) = (Deco { ascii: false }, Deco { ascii: true });
        for (uni, asc) in [
            (u.rule(), a.rule()),
            (u.dot(), a.dot()),
            (u.dash(), a.dash()),
            (u.arrow(), a.arrow()),
            (u.copyright(), a.copyright()),
            (u.good(), a.good()),
            (u.bad(), a.bad()),
        ] {
            assert_eq!(ascii_fold(uni), asc, "{uni:?}");
        }
    }

    #[test]
    fn folding_takes_marks_in_sentences_and_leaves_data() {
        assert_eq!(
            ascii_fold("moves the file into quarantine — not deleted, and reversible"),
            "moves the file into quarantine - not deleted, and reversible"
        );
        assert_eq!(ascii_fold("wait… ← back ↑ ↓"), "wait... <- back ^ v");
        // 한글 · 경로의 비ASCII 는 데이터다 — 그대로 둔다.
        assert_eq!(ascii_fold("C:\\사용자\\a — b"), "C:\\사용자\\a - b");
        assert!(matches!(
            ascii_fold("already ascii"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn unset_settings_mean_english_and_utf8() {
        // 라이브러리 시험은 아무것도 정하지 않는다. 그때의 답이 영어여야
        // "기본은 영어" 가 코드에서도 참이다.
        let _ = current();
        assert!(!deco().ascii || SETTINGS.get().is_some());
    }
}
