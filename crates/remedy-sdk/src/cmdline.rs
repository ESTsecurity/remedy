//! 명령줄 낱말 — 두 실행 파일(`remedy` · `remedy-net`)이 함께 쓴다.

/// 프로그램 이름을 뺀 인자를 UTF-8 문자열로 모은다.
///
/// UTF-8 이 아닌 낱말이 있으면 그 낱말을 사람이 읽을 꼴(`"a\xFFb"` — 제어 문자도 이스케이프된다)로 돌려준다.
/// `std::env::args()` 는 그 자리에서 패닉하고, 배포 빌드는 `panic = "abort"` 라 프로세스가 그대로 죽는다 —
/// 리눅스에서 옛 인코딩 이름의 경로 하나를 넘기면 1.22.0 은 SIGABRT(종료 134 · 코어 덤프)로 끝났다(2026-11-18
/// 실측 · 본체와 `remedy-net` 둘 다). 부르는 쪽은 이것을 사용법 오류(종료 4)로 낸다.
pub fn utf8_args() -> Result<Vec<String>, String> {
    std::env::args_os()
        .skip(1)
        .map(|a| a.into_string().map_err(|bad| format!("{bad:?}")))
        .collect()
}

/// [`utf8_args`] 가 돌려준 낱말로 쓰는 한 줄. 언어를 정하기 전이라 두 언어를 함께 적는다(`--lang` 알림과 같은 꼴).
pub fn not_utf8_message(bad: &str) -> String {
    format!(
        "인자를 읽지 못했습니다 — UTF-8 이 아닌 글자가 있습니다: {bad} / an argument is not valid UTF-8: {bad}"
    )
}
