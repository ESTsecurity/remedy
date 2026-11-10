//! 이미지 안의 이름 — tar 머리 · 패키지 기록의 바이트를 글자로 옮긴다.
//!
//! 사내 runtime-scanner(Go)의 문자열은 UTF-8 이 아닌 바이트를 그대로 들고 다닌다. 그래서 바이트 하나만 다른 두 이름은
//! 다른 항목이고, 화이트아웃 · 패키지 목록도 바이트 그대로 맞춘다. 여기서도 같게 하려고 UTF-8 이 아닌 바이트는
//! 바이트마다 사용자 정의 글자 하나(U+10FF80~U+10FFFF)로 옮긴다 — 되돌릴 수 있고, ASCII 로 쓴 판정 규칙(파일 이름 ·
//! 경로 앞머리)에는 걸리지 않는다. 결과에 싣기 전에 [`shown`] 이 그 글자를 U+FFFD 로 바꾼다 — 스캐너의 결과 JSON
//! 이 깨진 바이트를 적는 꼴이다.
//!
//! RPM DB 의 경로는 판독기(`remedy-rpmdb`)가 이미 U+FFFD 로 바꿔 준다. 그런 경로는 이미지의 이름과 맞지 않아 패키지가
//! 소유한 파일로 잡히지 않고 *확인 필요* 쪽으로 간다.

/// 옮긴 바이트 `b` 는 `ESCAPE + b` 글자다(`b` 는 0x80 이상).
const ESCAPE: u32 = 0x10_FF00;

/// 바이트 이름을 글자로 — UTF-8 이면 그대로다.
pub(super) fn from_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            let mut out = String::with_capacity(bytes.len() + 8);
            for chunk in bytes.utf8_chunks() {
                out.push_str(chunk.valid());
                for &b in chunk.invalid() {
                    out.push(char::from_u32(ESCAPE + u32::from(b)).unwrap_or('\u{FFFD}'));
                }
            }
            out
        }
    }
}

fn escaped(c: char) -> bool {
    (ESCAPE + 0x80..=ESCAPE + 0xFF).contains(&u32::from(c))
}

/// 원래 바이트로 센 길이 — 옮긴 글자는 4바이트지만 원래는 한 바이트다.
pub(super) fn raw_len(name: &str) -> usize {
    name.len() - 3 * name.chars().filter(|c| escaped(*c)).count()
}

/// 대소문자를 가리지 않는 이미지(Windows)의 이름 — Go 의 `strings.ToLower` 와 같다. ASCII 뿐이면 A~Z 만 바꾸고,
/// 아니면 글자마다 소문자 하나로 바꾸며 깨진 바이트는 U+FFFD 가 된다(그 함수가 그렇게 한다).
pub(super) fn lower(name: &str) -> String {
    if name.is_ascii() {
        return name.to_ascii_lowercase();
    }
    name.chars()
        .map(|c| {
            if escaped(c) {
                '\u{FFFD}'
            } else {
                // Go 는 단순 대응(글자 하나)이다. Rust 의 완전 대응이 두 글자를 내는 것은 U+0130 하나이고, 그 첫
                // 글자가 Go 의 값이다.
                c.to_lowercase().next().unwrap_or(c)
            }
        })
        .collect()
}

/// 결과에 싣는 글 — 옮긴 바이트를 U+FFFD 로 되돌린다.
pub(super) fn shown(text: &str) -> String {
    if !text.chars().any(escaped) {
        return text.to_string();
    }
    text.chars()
        .map(|c| if escaped(c) { '\u{FFFD}' } else { c })
        .collect()
}
