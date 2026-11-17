//! UTC 시각 — 결과 파일의 시각은 RFC 3339 UTC 다(안내 문서 §3-3). 날짜 계산은 본체와 같은 한 벌
//! (`remedy_sdk::utc`)이고, 여기는 동반 모듈의 두 꼴(밀리초까지 · 파일 이름용)만 짓는다.

use remedy_sdk::utc::civil;
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
