//! 결과 JSON 의 스키마 — 타입에서 낸다. 손으로 쓰지 않는다(안내 문서 §3-3).
//!
//! `cargo xtask schema` 가 저장소의 생성물과 대조하고, `--write` 로 갱신한다 — 본체의 SDK 스키마와 같은 장치다.

/// 저장소 뿌리 기준.
pub const OUT_DIR: &str = "docs/remedy-net";

/// 생성물 하나.
pub struct Generated {
    /// [`OUT_DIR`] 기준 상대 경로.
    pub path: &'static str,
    pub content: String,
}

pub fn all() -> Vec<Generated> {
    let schema = schemars::schema_for!(crate::url::report::Report);
    let mut content = serde_json::to_string_pretty(&schema).expect("스키마는 JSON 으로 쓸 수 있다");
    content.push('\n');
    vec![Generated {
        path: "url-report.schema.json",
        content,
    }]
}
