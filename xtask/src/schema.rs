//! 스키마 생성물 대조 — SDK 를 고치고 생성물을 커밋하지 않으면 실패한다.
//!
//! 이것이 "스키마 단일 소스" 를 실제로 강제하는 장치다. 생성기가 없으면 사람이
//! 표를 옮겨 적게 되고, 옮겨 적는 한 언젠가 어긋난다 (설계-09 P1).
//!
//! 생성기는 둘이다 — 플러그인 SDK(`docs/plugin-guide/`)와 동반 모듈 `remedy-net` 의 결과
//! JSON(`docs/remedy-net/`).
//!
//! `cargo xtask schema`         대조만 한다 (CI)
//! `cargo xtask schema --write` 생성물을 갱신한다 (작성자)

use remedy_sdk::generate;
use std::fs;
use std::path::Path;

pub fn run(root: &Path, write: bool) -> Result<(), String> {
    let mut items: Vec<(String, String)> = generate::all()
        .into_iter()
        .map(|g| (format!("{}/{}", generate::OUT_DIR, g.path), g.content))
        .collect();
    items.extend(remedy_net::schema::all().into_iter().map(|g| {
        (
            format!("{}/{}", remedy_net::schema::OUT_DIR, g.path),
            g.content,
        )
    }));

    let mut stale = Vec::new();
    for (rel, content) in &items {
        let path = root.join(rel);

        if write {
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir).map_err(|e| format!("{} 생성 실패: {e}", dir.display()))?;
            }
            // 개행은 LF 로 고정한다. .gitattributes 가 eol=lf 이므로 CRLF 로 쓰면
            // 커밋 후 다시 대조할 때 매번 어긋난다.
            fs::write(&path, content.as_bytes())
                .map_err(|e| format!("{} 쓰기 실패: {e}", path.display()))?;
            println!("  갱신  {rel}");
            continue;
        }

        match fs::read_to_string(&path) {
            Err(_) => stale.push(format!("{rel} 가 없다")),
            Ok(on_disk) => {
                // Windows 체크아웃에서 CRLF 로 풀렸을 수 있으므로 비교 전에 맞춘다.
                if on_disk.replace("\r\n", "\n") != *content {
                    stale.push(format!("{rel} 가 생성기와 다르다"));
                }
            }
        }
    }

    if stale.is_empty() {
        println!(
            "schema OK — 생성물 {}개가 생성기(SDK · remedy-net)와 일치한다",
            items.len()
        );
        Ok(())
    } else {
        Err(format!(
            "생성물이 최신이 아니다 {}건:\n{}\n\n  cargo xtask schema --write 로 갱신하고 커밋할 것.",
            stale.len(),
            stale
                .iter()
                .map(|s| format!("  {s}"))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}
