//! 스키마 생성물 대조 — SDK 를 고치고 생성물을 커밋하지 않으면 실패한다.
//!
//! 이것이 "스키마 단일 소스" 를 실제로 강제하는 장치다. 생성기가 없으면 사람이
//! 표를 옮겨 적게 되고, 옮겨 적는 한 언젠가 어긋난다 (설계-09 P1).
//!
//! `cargo xtask schema`         대조만 한다 (CI)
//! `cargo xtask schema --write` 생성물을 갱신한다 (작성자)

use remedy_sdk::generate;
use std::fs;
use std::path::Path;

pub fn run(root: &Path, write: bool) -> Result<(), String> {
    let out_dir = root.join(generate::OUT_DIR);
    if write {
        fs::create_dir_all(&out_dir)
            .map_err(|e| format!("{} 생성 실패: {e}", out_dir.display()))?;
    }

    let mut stale = Vec::new();
    for item in generate::all() {
        let path = out_dir.join(item.path);

        if write {
            // 개행은 LF 로 고정한다. .gitattributes 가 eol=lf 이므로 CRLF 로 쓰면
            // 커밋 후 다시 대조할 때 매번 어긋난다.
            fs::write(&path, item.content.as_bytes())
                .map_err(|e| format!("{} 쓰기 실패: {e}", path.display()))?;
            println!("  갱신  {}", item.path);
            continue;
        }

        match fs::read_to_string(&path) {
            Err(_) => stale.push(format!("{} 가 없다", item.path)),
            Ok(on_disk) => {
                // Windows 체크아웃에서 CRLF 로 풀렸을 수 있으므로 비교 전에 맞춘다.
                if on_disk.replace("\r\n", "\n") != item.content {
                    stale.push(format!("{} 가 SDK 와 다르다", item.path));
                }
            }
        }
    }

    if stale.is_empty() {
        println!(
            "schema OK — 생성물 {}개가 SDK 와 일치한다",
            generate::all().len()
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
