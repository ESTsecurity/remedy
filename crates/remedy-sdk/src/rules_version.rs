//! 룰 버전 — 꾸러미에 든 룰 묶음의 버전. 엔진 버전(SemVer)과 따로 매긴다(`docs/개발-안내.md` "버전 번호").
//!
//! 저장소의 `plugins/RULES-VERSION` 한 줄이 출처이고, `xtask package` 가 꾸러미의 같은 자리(`plugins/`)에 옮겨
//! 담는다. 엔진은 그것을 읽어 화면 머리말과 `--version` 에 적는다 — **보여 주기만 한다.** 서명된 것은 룰마다의
//! 매니페스트이고 이 파일은 서명 밖이라, 무엇을 돌릴지 정하는 데 쓰지 않는다.
//!
//! 꼴은 날짜다 — `YYYY.MM.DD`, 같은 날 둘째부터 꼬리 `.N`(N ≥ 2). 배포 워크플로의 `ci/version-check.sh` 가 같은
//! 꼴을 본다.

/// 파일 이름 — `plugins/` 바로 아래.
pub const FILE: &str = "RULES-VERSION";

/// 그 꼴이면 그 글자를 돌려준다(앞뒤 공백 · 줄바꿈은 뗀다). 아니면 `None`.
pub fn parse(text: &str) -> Option<&str> {
    let v = text.trim();
    let parts: Vec<&str> = v.split('.').collect();
    if !(3..=4).contains(&parts.len()) {
        return None;
    }
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    let num = |s: &str| s.parse::<u32>().unwrap_or(0);
    let date = digits(parts[0], 4)
        && digits(parts[1], 2)
        && digits(parts[2], 2)
        && (1..=12).contains(&num(parts[1]))
        && (1..=31).contains(&num(parts[2]));
    // 꼬리는 2 부터 — `.1` 은 꼬리 없는 첫째와 같은 것이라 두 이름이 생긴다. 앞자리 0 도 받지 않는다.
    let tail = parts.get(3).is_none_or(|t| {
        !t.is_empty()
            && t.len() <= 3
            && t.bytes().all(|b| b.is_ascii_digit())
            && !t.starts_with('0')
            && num(t) >= 2
    });
    (date && tail).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn a_date_and_a_same_day_tail_are_versions() {
        assert_eq!(parse("2026.11.15"), Some("2026.11.15"));
        assert_eq!(parse("2026.11.15\r\n"), Some("2026.11.15"));
        assert_eq!(parse(" 2026.01.09 "), Some("2026.01.09"));
        assert_eq!(parse("2026.11.15.2"), Some("2026.11.15.2"));
        assert_eq!(parse("2026.11.15.12"), Some("2026.11.15.12"));
    }

    #[test]
    fn other_shapes_are_not() {
        for bad in [
            "",
            "1.20.0",
            "2026.11.5",
            "2026.13.01",
            "2026.00.10",
            "2026.11.32",
            "2026.11.00",
            "26.11.15",
            "2026.11.15.1",
            "2026.11.15.0",
            "2026.11.15.02",
            "2026.11.15.",
            "2026.11.15.2.3",
            "2026-11-15",
            "2026.11.15 x",
            "２026.11.15",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
