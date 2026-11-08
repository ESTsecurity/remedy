//! 경로·문자열 정규화 (설계-02 §4 "경로 비교 규칙").
//!
//! **경로 비교는 오탐·미탐의 최대 원인이다.** 그래서 규칙을 스키마 수준에서
//! 고정하고, 수집기와 평가기가 같은 코드를 쓴다. 두 곳에 각자 구현하면 언젠가
//! 미세하게 갈라지고, 그 차이는 "왜 이 환경에서만 안 잡히는가" 로 나타난다.
//!
//! `remedy-detect` 는 `remedy-platform` 에 의존할 수 없으므로(설계-04 §1) 이
//! 규칙이 SDK 에 있어야 양쪽이 공유할 수 있다.

use crate::catalog::Platform;
use unicode_normalization::UnicodeNormalization;

/// 비교 전에 항상 거치는 유니코드 정규화.
///
/// 한글은 조합형(NFD)과 완성형(NFC)의 바이트열이 완전히 다르다. 외부 매체나
/// 타 OS 를 거친 파일명이 NFD 로 들어오는 경우가 실제로 있고, 정규화하지 않으면
/// **같은 이름의 폴더가 다른 문자열로 보인다.**
pub fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// 로케일에 의존하지 않는 소문자 변환.
///
/// 로케일 의존 변환은 터키어 로케일에서 `I`/`ı` 가 어긋나는 등 재현 불가능한
/// 차이를 만든다. 한글에는 대소문자가 없지만 경로에 섞인 ASCII 가 같은 함정을 밟는다.
pub fn fold_case(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect()
}

/// 저장용 경로 정규화. **대소문자를 접지 않는다.**
///
/// 레코드에 담기는 경로는 사람이 보고 계획이 지목하는 값이다. 소문자로 접어
/// 저장하면 `plan.json` 이 사용자가 Task Scheduler 나 탐색기에서 보는 것과 다른
/// 경로를 보여 주고, 감사 로그의 값이 실제 대상과 달라진다. **접는 것은 비교의
/// 몫이지 저장의 몫이 아니다.**
///
/// Windows: `/` → `\` · `\\?\` 접두 제거 · 후행 구분자 제거
/// Linux:   후행 구분자 제거
///
/// **심볼릭 링크·정션은 해석하지 않는다.** 비교 대상은 표기된 경로다. 링크를
/// 따라가면 재귀 삭제가 링크된 디렉터리로 번질 수 있다.
///
/// 환경변수 전개와 8.3 단축 이름 해석은 여기서 하지 않는다 — 실제 시스템 접근이
/// 필요하고, 이 크레이트는 시스템에 닿지 않는다. 수집기가 전개된 경로를 담는다.
pub fn for_record(p: &str, platform: Platform) -> String {
    let mut s = nfc(p);

    if platform == Platform::Windows {
        s = s.replace('/', "\\");
        // \\?\C:\x -> C:\x  /  \\?\UNC\server\share -> \\server\share
        if let Some(rest) = s.strip_prefix("\\\\?\\") {
            s = match rest.strip_prefix("UNC\\") {
                Some(unc) => format!("\\\\{unc}"),
                None => rest.to_string(),
            };
        }
    }

    trim_trailing_separators(&s, platform)
}

/// 비교용 경로 정규화. 비교의 좌우 양쪽에 같은 함수를 적용해야 의미가 있다.
///
/// `for_record` 에 더해 **Windows 에서 대소문자를 접는다.** 그러지 않으면
/// `NODE.EXE` 와 `node.exe` 가 다른 것이 되어 조용한 미탐을 만든다.
pub fn for_compare(p: &str, platform: Platform) -> String {
    let s = for_record(p, platform);
    if platform == Platform::Windows {
        fold_case(&s)
    } else {
        s
    }
}

fn trim_trailing_separators(s: &str, platform: Platform) -> String {
    let sep = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    // 루트 자체(`C:\`, `/`)는 남긴다. 전부 깎으면 `C:` 가 되어 의미가 달라진다.
    let trimmed = s.trim_end_matches(sep);
    if trimmed.is_empty() || trimmed.ends_with(':') {
        let mut out = trimmed.to_string();
        out.push(sep);
        out
    } else {
        trimmed.to_string()
    }
}

/// 룰이 적은 리터럴 값의 정규화.
///
/// 경로가 아닌 값(명령줄 조각 등)도 NFC 로 맞춘다. **룰 작성자의 편집기가 무엇을
/// 뱉었는지에 판정이 좌우되면 안 된다.**
pub fn literal(s: &str) -> String {
    nfc(s)
}

/// `<폴더>/<이름 꼴>` 로 나눈다. 와일드카드가 폴더 쪽에 있으면 `None` — 한 폴더 안만
/// 고르므로 담는 범위가 선언에서 바로 읽힌다.
///
/// `collect_extra` 의 글롭과 `scan_roots` 의 글롭 뿌리(코어 1.2.0)가 이 규칙 하나를
/// 쓴다. 이름 쪽에 와일드카드가 없어도 나눈다 — 글롭인지는 [`glob_root`] 가 가린다.
pub fn split_glob(pattern: &str) -> Option<(&str, &str)> {
    let cut = pattern.rfind(['/', '\\'])?;
    let (dir, name) = (&pattern[..cut], &pattern[cut + 1..]);
    if dir.is_empty() || name.is_empty() || dir.contains(['*', '?']) {
        return None;
    }
    Some((dir, name))
}

/// 파일 시스템 뿌리가 **글롭 뿌리**인가 — 마지막 칸에만 `*` · `?` 가 있다.
///
/// 글롭 뿌리는 그 폴더 **바로 아래**에서 이름이 맞는 파일만 고른다. 하위 폴더로
/// 내려가지 않고, **폴더 자체는 고르지 않는다.** 그래서 상한으로 읽으면 "그 폴더의
/// 이 꼴 파일들" 이고, 그 폴더를 겨눈 재귀 삭제는 상한 밖이다 — `TEMP` 를 보되
/// `TEMP` 를 지울 수는 없게 하는 것이 이 꼴이 생긴 까닭이다(2026-11-08 · EvilAI 의
/// 보도 꼴은 페이로드를 `TEMP` 바로 아래에 둔다).
///
/// **레지스트리 뿌리는 아니다.** 그쪽의 끝 `\*` 는 "직속 하위 키로 펼친다" 는 다른
/// 문법이다(린트 `check_overbroad`).
pub fn glob_root(root: &str) -> Option<(&str, &str)> {
    if crate::catalog::is_registry_root(root) {
        return None;
    }
    let (dir, name) = split_glob(root)?;
    name.contains(['*', '?']).then_some((dir, name))
}

/// 이름 하나에 `*`(아무 길이) · `?`(한 글자)를 맞춘다. 되돌아가기는 마지막 별에서만
/// 하므로 이름 길이 × 꼴 길이를 넘지 않는다 — 정규식처럼 터지지 않는다.
///
/// 대소문자는 접지 않는다 — 부르는 쪽이 [`for_compare`] 를 거친 두 값을 준다.
pub fn name_matches(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || (p[pi] != '*' && p[pi] == t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi + 1, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// `haystack` 이 `needle` 을 경로 성분 경계에서 포함하는가.
///
/// 단순 부분 문자열 비교는 `C:\Program Files\Foo` 와 `C:\Program Files\Foobar` 를
/// 구분하지 못한다. 재귀 삭제의 상한 판정에서 그 차이는 치명적이다.
///
/// `parent` 가 [`glob_root`] 면 **그 폴더 바로 아래의 이름이 맞는 파일**만 안이다 —
/// 폴더 자체와 하위 폴더는 밖이다.
pub fn is_within(child: &str, parent: &str, platform: Platform) -> bool {
    if let Some((dir, pattern)) = glob_root(parent) {
        let c = for_compare(child, platform);
        let d = for_compare(dir, platform);
        let p = for_compare(pattern, platform);
        let sep = if platform == Platform::Windows {
            '\\'
        } else {
            '/'
        };
        return c
            .rfind(sep)
            .is_some_and(|cut| c[..cut] == d && name_matches(&c[cut + 1..], &p));
    }
    let c = for_compare(child, platform);
    let p = for_compare(parent, platform);
    if c == p {
        return true;
    }
    let sep = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    let prefix = if p.ends_with(sep) {
        p
    } else {
        format!("{p}{sep}")
    };
    c.starts_with(&prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 완성형 문자열을 조합형으로 풀어 놓는다. 테스트 전제를 만들기 위한 것이다.
    fn to_nfd(s: &str) -> String {
        s.nfd().collect()
    }

    #[test]
    fn nfc_makes_decomposed_hangul_equal() {
        // 조합형으로 들어온 '한글' 과 완성형 '한글' 은 바이트열이 다르다.
        let composed = "한글";
        let decomposed = to_nfd(composed);
        assert_ne!(composed, decomposed.as_str(), "전제: 두 표기는 다르다");
        assert_eq!(nfc(&decomposed), composed, "정규화하면 같아져야 한다");
    }

    #[test]
    fn windows_paths_fold_case_and_separators() {
        let a = for_compare("C:/Users/Test/AppData/", Platform::Windows);
        let b = for_compare("c:\\users\\test\\appdata", Platform::Windows);
        assert_eq!(a, b);
    }

    #[test]
    fn windows_strips_extended_prefix() {
        assert_eq!(
            for_compare("\\\\?\\C:\\x\\y", Platform::Windows),
            for_compare("C:\\x\\y", Platform::Windows)
        );
        assert_eq!(
            for_compare("\\\\?\\UNC\\srv\\share\\f", Platform::Windows),
            for_compare("\\\\srv\\share\\f", Platform::Windows)
        );
    }

    #[test]
    fn root_keeps_its_separator() {
        assert_eq!(for_compare("C:\\", Platform::Windows), "c:\\");
        assert_eq!(for_compare("/", Platform::Linux), "/");
    }

    #[test]
    fn linux_is_case_sensitive() {
        assert_ne!(
            for_compare("/home/Test", Platform::Linux),
            for_compare("/home/test", Platform::Linux)
        );
    }

    #[test]
    fn within_respects_component_boundary() {
        let p = Platform::Windows;
        assert!(is_within("C:\\a\\b\\c.txt", "C:\\a\\b", p));
        assert!(
            is_within("C:\\a\\b", "C:\\a\\b", p),
            "자기 자신은 안에 있다"
        );
        assert!(
            !is_within("C:\\a\\bcd", "C:\\a\\b", p),
            "'b' 와 'bcd' 를 구분하지 못하면 재귀 삭제의 상한이 무너진다"
        );
        assert!(is_within("C:\\A\\B\\x", "c:\\a\\b", p), "대소문자 무시");
    }

    #[test]
    fn within_handles_decomposed_hangul() {
        let p = Platform::Windows;
        let parent = "C:\\사용자";
        let child_nfd = to_nfd("C:\\사용자\\문서");
        assert!(
            is_within(&child_nfd, parent, p),
            "NFD 로 들어온 한글 경로도 같은 트리로 인식되어야 한다"
        );
    }

    #[test]
    fn glob_root_is_a_last_segment_pattern_on_a_file_path_only() {
        let t = r"C:\Users\a\AppData\Local\Temp\*.js";
        assert_eq!(
            glob_root(t),
            Some((r"C:\Users\a\AppData\Local\Temp", "*.js"))
        );
        assert_eq!(glob_root("/tmp/*.s?"), Some(("/tmp", "*.s?")));
        assert_eq!(
            glob_root(r"C:\x\a.js"),
            None,
            "와일드카드가 없으면 글롭이 아니다"
        );
        assert_eq!(
            glob_root(r"C:\x\*\a.js"),
            None,
            "폴더 칸의 와일드카드는 받지 않는다"
        );
        assert_eq!(
            glob_root(r"HKLM\SOFTWARE\Microsoft\x\*"),
            None,
            "레지스트리의 끝 `\\*` 는 하위 키 펼치기다"
        );
    }

    /// 글롭 뿌리는 그 폴더 바로 아래의 맞는 파일만 고른다 — **폴더 자체는 밖이다.**
    /// 그래서 상한으로 쓰면 `TEMP` 의 `.js` 는 지울 수 있어도 `TEMP` 는 못 지운다.
    #[test]
    fn a_glob_root_holds_the_matching_files_but_not_the_folder() {
        let w = Platform::Windows;
        let root = r"C:\Users\a\AppData\Local\Temp\*.js";
        assert!(is_within(
            r"C:\Users\a\AppData\Local\Temp\0b3cor.js",
            root,
            w
        ));
        assert!(
            is_within(r"C:\USERS\A\APPDATA\LOCAL\TEMP\0B3COR.JS", root, w),
            "Windows 는 대소문자를 접는다 — 보도는 TEMP 로 적는다"
        );
        assert!(!is_within(r"C:\Users\a\AppData\Local\Temp", root, w));
        assert!(!is_within(r"C:\Users\a\AppData\Local\Temp\x\a.js", root, w));
        assert!(!is_within(r"C:\Users\a\AppData\Local\Temp\a.txt", root, w));
        assert!(!is_within(r"C:\Users\a\AppData\Local\Temp2\a.js", root, w));

        let l = Platform::Linux;
        assert!(is_within("/tmp/a.sh", "/tmp/*.sh", l));
        assert!(!is_within("/tmp", "/tmp/*.sh", l));
        assert!(!is_within("/tmp/x/a.sh", "/tmp/*.sh", l));
        assert!(
            !is_within("/tmp/A.SH", "/tmp/*.sh", l),
            "Linux 는 접지 않는다"
        );
    }
}
