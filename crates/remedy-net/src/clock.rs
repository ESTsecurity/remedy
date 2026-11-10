//! UTC 시각 — 결과 파일의 시각은 RFC 3339 UTC 다(안내 문서 §3-3). 같은 일을 하는 함수가 본체 쪽
//! 크레이트에도 있지만(`remedy-core` · `remedy-platform`) 동반 모듈은 그것들을 링크하지 않는다(설계-04 §1).

use std::time::{SystemTime, UNIX_EPOCH};

/// `2026-11-10T03:10:00.123Z` — 밀리초까지. 시간 초과를 재는 시험이 두 시각의 차를 본다.
pub(crate) fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let (y, mo, da, h, mi, s) = civil(d.as_secs());
    format!(
        "{y:04}-{mo:02}-{da:02}T{h:02}:{mi:02}:{s:02}.{:03}Z",
        d.subsec_millis()
    )
}

/// `20261110T031000Z` — 실행 ID 의 앞머리. 파일 이름에 들어가므로 `:` 가 없다.
pub(crate) fn compact(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let (y, mo, da, h, mi, s) = civil(d.as_secs());
    format!("{y:04}{mo:02}{da:02}T{h:02}{mi:02}{s:02}Z")
}

fn civil(secs: u64) -> (i64, u32, u32, u64, u64, u64) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// 1970-01-01 부터 센 날 수 → 그레고리력 (H. Hinnant 의 방법).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe as i64 + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn utc_text_matches_known_instants() {
        let t = UNIX_EPOCH + Duration::from_millis(1_794_280_200_123);
        assert_eq!(rfc3339(t), "2026-11-10T03:10:00.123Z");
        assert_eq!(compact(t), "20261110T031000Z");
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        // 윤년의 2월 29일
        let leap = UNIX_EPOCH + Duration::from_secs(1_709_164_800);
        assert_eq!(compact(leap), "20240229T000000Z");
    }
}
