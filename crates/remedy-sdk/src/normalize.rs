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

/// `haystack` 이 `needle` 을 경로 성분 경계에서 포함하는가.
///
/// 단순 부분 문자열 비교는 `C:\Program Files\Foo` 와 `C:\Program Files\Foobar` 를
/// 구분하지 못한다. 재귀 삭제의 상한 판정에서 그 차이는 치명적이다.
pub fn is_within(child: &str, parent: &str, platform: Platform) -> bool {
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
}
