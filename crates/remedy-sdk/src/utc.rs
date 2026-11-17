//! UTC 시각 — 결과 파일 · 저널 · 회차 로그의 시각은 RFC 3339 UTC 다.
//!
//! **한 벌만 둔다.** 2026-11-17 까지 같은 계산이 네 크레이트(`remedy-journal` · `remedy-core` ·
//! `remedy-platform` · `remedy-net`)에 따로 있었고 서로를 주석으로 가리켰다. 넷 모두 이 크레이트를
//! 링크하므로 여기 두면 의존 방향이 늘지 않는다(동반 모듈은 본체 쪽 크레이트를 링크하지 않는다 — 설계-04 §1).
//! 시간대 라이브러리는 끌어오지 않는다 — 다루는 시각은 언제나 UTC 다.

/// 1970-01-01 부터의 초 → `(년, 월, 일, 시, 분, 초)`.
pub fn civil(secs: u64) -> (i64, u32, u32, u64, u64, u64) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// `2026-11-10T03:10:00Z` — 초까지.
pub fn rfc3339(secs: u64) -> String {
    let (y, m, d, h, mi, s) = civil(secs);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// 지금 시각을 [`rfc3339`] 로. 시계가 1970 년 앞이면 1970-01-01 이다.
pub fn now_rfc3339() -> String {
    rfc3339(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// 1970-01-01 부터 센 날 수 → 그레고리력 (H. Hinnant 의 days-from-civil 역함수).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants_read_the_same_as_before() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        // 네 벌이 저마다 지키던 값 — 옮긴 뒤에도 그대로여야 한다.
        assert_eq!(rfc3339(1_794_280_200), "2026-11-10T03:10:00Z");
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_709_210_096), "2024-02-29T12:34:56Z");
        assert_eq!(rfc3339(1_771_500_600), "2026-02-19T11:30:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(4_107_542_399), "2100-02-28T23:59:59Z");
        assert_eq!(civil(86_399), (1970, 1, 1, 23, 59, 59));
    }

    #[test]
    fn every_day_follows_the_one_before() {
        // 400 년(그레고리력 한 바퀴)을 하루씩 걸어 날짜가 끊기거나 겹치지 않는지 본다.
        let leap = |y: i64| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let days_in = |y: i64, m: u32| match m {
            2 if leap(y) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        let mut prev = civil_from_days(-1);
        assert_eq!(prev, (1969, 12, 31));
        for day in 0..146_097 {
            let cur = civil_from_days(day);
            let next_of_prev = if cur.2 == 1 {
                let rolled = if cur.1 == 1 {
                    cur.0 == prev.0 + 1 && prev.1 == 12
                } else {
                    cur.0 == prev.0 && cur.1 == prev.1 + 1
                };
                rolled && prev.2 == days_in(prev.0, prev.1)
            } else {
                cur.0 == prev.0 && cur.1 == prev.1 && cur.2 == prev.2 + 1
            };
            assert!(next_of_prev, "{prev:?} 다음이 {cur:?}");
            prev = cur;
        }
    }
}
