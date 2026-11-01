//! 파일의 코드 서명을 스냅샷에 담는다 (설계-03 §3 2층).
//!
//! # 왜 수집 단계인가
//!
//! 판정 시점에 OS 에 다시 물으면 **탐지가 불활성 스냅샷 위에서만 돈다**는 성질이
//! 깨진다(설계-03 §1). 같은 스냅샷이 언제 어디서 평가되든 같은 답을 내야 하므로,
//! 신뢰 판정도 수집 시점에 굳혀 스냅샷에 넣는다.
//!
//! # 왜 전부는 아닌가
//!
//! `WinVerifyTrust` 는 파일당 **약 8 ms** 다(2026-08-25 실측, System32 DLL
//! 300개). 수집 대상 전부에 걸면 수천 개에서 수십 초가 된다.
//!
//! 설계-03 §3 2층이 말하는 것은 *"유효한 신뢰 벤더 서명이 있는 **실행 파일**"*
//! 이므로 대상을 실행 파일로 좁힌다. 나머지는 `None` 으로 남고, 그것은 **"서명이
//! 없다" 가 아니라 "확인하지 않았다"** 다 — 그 구분이 `FileRecord.signature` 의
//! 계약이다.

use remedy_artifacts::Signature;

/// 서명을 확인할 확장자.
///
/// Windows 가 Authenticode 를 실을 수 있는 형식 중 **치료 대상이 될 만한 것**만
/// 담는다. `.cat`·`.inf` 처럼 서명되지만 우리가 지우지 않는 것은 뺀다 — 확인
/// 비용만 들고 판정에 쓰이지 않는다.
const EXECUTABLE_EXT: &[&str] = &[
    "exe", "dll", "sys", "ocx", "cpl", "scr", "drv", "efi", "msi", "msp", "ax", "node",
];

/// 이 경로의 서명을 확인할 것인가.
pub fn should_check(path: &str) -> bool {
    let Some(dot) = path.rfind('.') else {
        return false;
    };
    let ext = &path[dot + 1..];
    if ext.is_empty() || ext.len() > 4 {
        return false;
    }
    let lower = ext.to_ascii_lowercase();
    EXECUTABLE_EXT.contains(&lower.as_str())
}

/// 서명을 확인해 스냅샷에 담을 값을 만든다.
///
/// `None` 은 **"확인하지 않았다"** 다 — 대상 형식이 아니었거나, 재파스 지점이거나,
/// OS 가 답하지 못했다. 이것을 "서명 없음" 으로 읽으면 2층이 조용히 무력해진다
/// (설계-03 §3).
///
/// "확인했고 서명이 없다" 는 `Some(Signature { trusted: false, subject: None, .. })`
/// 로 나온다. 두 값은 다르다.
pub fn of(path: &str, is_reparse: bool) -> Option<Signature> {
    // 재파스 지점을 따라가면 **링크가 가리키는 다른 파일**을 검증하고 그 결과를
    // 링크의 것으로 적게 된다. 해시를 같은 이유로 건너뛰는 것과 짝이다.
    if is_reparse || !should_check(path) {
        return None;
    }
    match remedy_wintrust::verify(std::path::Path::new(path)) {
        Ok(v) => Some(Signature {
            trusted: v.trusted,
            subject: v.subject,
            thumbprint: v.thumbprint,
        }),
        // 확인하지 못했다. 사유를 스냅샷에 담을 자리가 없으므로 `None` 으로
        // 남긴다 — 계약상 "확인하지 않았다" 와 같은 값이고, 둘 다 2층을
        // 통과시키지 않는다는 점에서 안전한 쪽으로 같다.
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 실행_파일만_확인_대상이다() {
        for p in [
            "C:\\x\\a.exe",
            "C:\\x\\a.DLL",
            "C:\\x\\driver.sys",
            "C:\\x\\setup.msi",
            "C:\\x\\native.node",
        ] {
            assert!(should_check(p), "확인해야 한다: {p}");
        }
        for p in [
            "C:\\x\\a.js",
            "C:\\x\\a.txt",
            "C:\\x\\a.json",
            "C:\\x\\Makefile",
            "C:\\x\\a.",
            "C:\\x\\archive.tar.gz",
        ] {
            assert!(!should_check(p), "확인 대상이 아니다: {p}");
        }
    }

    #[test]
    fn 재파스_지점은_확인하지_않는다() {
        // 링크를 따라가 다른 파일을 검증하고 그 답을 링크의 것으로 적으면 안 된다.
        assert!(of("C:\\Windows\\System32\\kernel32.dll", true).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn 시스템_실행_파일이_신뢰로_담긴다() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let p = format!("{root}\\System32\\kernel32.dll");
        if !std::path::Path::new(&p).exists() {
            return;
        }
        let s = of(&p, false).expect("서명이 담기지 않았다");
        assert!(s.trusted, "{s:?}");
        assert!(
            s.subject
                .as_deref()
                .is_some_and(|x| x.contains("O=Microsoft Corporation")),
            "{s:?}"
        );
    }

    #[test]
    fn 확인하지_않은_것과_서명_없음은_다른_값이다() {
        // `.js` 는 대상이 아니므로 `None` — "서명이 없다" 가 아니다.
        assert!(of("C:\\x\\payload.js", false).is_none());
    }
}
