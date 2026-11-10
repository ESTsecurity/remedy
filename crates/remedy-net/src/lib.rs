//! `remedy-net` 의 라이브러리 쪽 — 실행 파일(`main.rs`)과 `xtask`(결과 JSON 스키마 생성)가 함께 쓴다.
//!
//! 통신 코드는 이 크레이트에만 있다. 본체(`remedy`)는 이것을 링크하지 않는다(설계-04 §1 ·
//! `cargo xtask arch`).
#![forbid(unsafe_code)]

pub mod schema;
pub mod text;
pub mod url;

mod clock;

use remedy_sdk::artifact::ExitCode;
use remedy_sdk::i18n::Lang;

/// 한 번의 실행이 끝난 모양. 숫자는 본체의 종료 코드 표([`ExitCode`])에서 온다 — 여기서 새로 정하지 않는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 양호 — 확인한 대상이 전부 고친 버전이다. 도움말 · 버전도 이것으로 끝난다.
    Clear,
    /// 취약 — 한 항목이라도 취약이면 전체가 취약이다.
    Vulnerable,
    /// 확인 필요 — 확인하지 못한 것을 양호로 내지 않는다.
    Review,
    /// 입력 오류 · 동의하지 않음.
    BadInput,
    /// 처리 실패 — 도구가 일을 끝내지 못했다.
    Failed,
}

impl Outcome {
    /// 도움말의 종료 코드 표가 이 차례로 선다.
    pub const ALL: [Outcome; 5] = [
        Outcome::Clear,
        Outcome::Vulnerable,
        Outcome::Review,
        Outcome::BadInput,
        Outcome::Failed,
    ];

    /// 본체 표의 그 칸.
    pub fn exit(self) -> ExitCode {
        match self {
            Outcome::Clear => ExitCode::NoThreat,
            Outcome::Vulnerable => ExitCode::FoundNotRemediated,
            Outcome::Review => ExitCode::IncompleteObservation,
            Outcome::BadInput => ExitCode::UsageError,
            Outcome::Failed => ExitCode::InternalError,
        }
    }

    pub fn meaning(self, lang: Lang) -> &'static str {
        match self {
            Outcome::Clear => lang.t("양호 · 도움말", "clear · help"),
            Outcome::Vulnerable => lang.t("취약", "vulnerable"),
            Outcome::Review => lang.t("확인 필요", "needs review"),
            Outcome::BadInput => lang.t(
                "입력 오류 · 동의하지 않음",
                "input error · consent declined",
            ),
            Outcome::Failed => lang.t("처리 실패", "processing failure"),
        }
    }
}
