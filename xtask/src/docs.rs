//! 설계 문서에서 인벤토리를 추출한다.
//!
//! 목록을 코드에 박지 않고 문서에서 읽는 이유는 설계-03 §9(CrowdStrike Channel
//! File 291)와 같다 — 같은 사실을 두 곳에 적으면 반드시 갈라진다.

use std::path::{Path, PathBuf};

/// `docs/design/` 에서 접두사로 문서를 찾는다. 파일명에 한글이 있어 정확 일치를 쓰지 않는다.
pub fn find(root: &Path, prefix: &str) -> Result<PathBuf, String> {
    let dir = root.join("docs/design");
    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("{} 읽기 실패: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(prefix) && name.ends_with(".md") {
            return Ok(entry.path());
        }
    }
    Err(format!("{prefix}* 문서를 찾지 못했다"))
}

pub fn read(root: &Path, prefix: &str) -> Result<String, String> {
    let path = find(root, prefix)?;
    std::fs::read_to_string(&path).map_err(|e| format!("{} 읽기 실패: {e}", path.display()))
}

/// `start` 로 시작하는 줄부터 `end` 로 시작하는 줄 직전까지를 잘라낸다.
pub fn section<'a>(text: &'a str, start: &str, end: &str) -> Result<&'a str, String> {
    let s = text
        .find(start)
        .ok_or_else(|| format!("구간 시작 '{start}' 를 찾지 못했다"))?;
    let rest = &text[s..];
    let e = rest[start.len()..]
        .find(end)
        .map(|i| i + start.len())
        .unwrap_or(rest.len());
    Ok(&rest[..e])
}

/// 한 줄에서 백틱으로 감싼 토큰을 모두 뽑는다.
pub fn backticked(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = line.char_indices();
    while let Some((i, c)) = chars.next() {
        if c != '`' {
            continue;
        }
        let rest = &line[i + 1..];
        if let Some(j) = rest.find('`') {
            let tok = rest[..j].trim();
            if !tok.is_empty() {
                out.push(tok.to_string());
            }
            // 닫는 백틱 다음으로 건너뛴다
            for _ in 0..rest[..=j].chars().count() {
                chars.next();
            }
        }
    }
    out
}

/// 표 본문 행(`| ...`)만 돌려준다. 구분선(`|---|`)은 제외한다.
pub fn table_rows(section: &str) -> impl Iterator<Item = &str> {
    section
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('|') && !l.contains("---"))
}

/// `a.b` 꼴인가.
pub fn is_op(tok: &str) -> bool {
    let mut parts = tok.splitn(2, '.');
    match (parts.next(), parts.next()) {
        (Some(a), Some(b)) => is_ident(a) && is_ident(b),
        _ => false,
    }
}

pub fn is_ident(tok: &str) -> bool {
    !tok.is_empty() && tok.chars().all(|c| c.is_ascii_lowercase() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    // 추적성 검사 전체가 이 파싱에 의존한다. 여기가 조용히 틀리면 인벤토리를
    // 빈 목록으로 읽고도 "통과" 로 보이게 된다.

    #[test]
    fn backticked_extracts_all_tokens() {
        let line = "| `persistence.disable` / `persistence.delete` | 가능 | 작업 XML | 중 |";
        assert_eq!(
            backticked(line),
            vec!["persistence.disable", "persistence.delete"]
        );
    }

    #[test]
    fn backticked_handles_korean_and_empty() {
        assert_eq!(backticked("백틱 없는 줄"), Vec::<String>::new());
        assert_eq!(backticked("`a` 그리고 `b`"), vec!["a", "b"]);
    }

    #[test]
    fn table_rows_skips_separator() {
        let sec = "| 머리 | 값 |\n|---|---|\n| `x` | 1 |\n일반 문단\n";
        let rows: Vec<&str> = table_rows(sec).collect();
        assert_eq!(rows.len(), 2, "구분선은 제외하고 본문 행만 남아야 한다");
    }

    #[test]
    fn section_cuts_between_markers() {
        let text = "## 1. 앞\n내용A\n## 2. 대상\n내용B\n## 3. 뒤\n내용C\n";
        let sec = section(text, "## 2. 대상", "\n## 3.").expect("구간을 찾아야 한다");
        assert!(sec.contains("내용B"));
        assert!(!sec.contains("내용C"));
        assert!(!sec.contains("내용A"));
    }

    #[test]
    fn section_reports_missing_marker() {
        assert!(section("아무것도 없음", "## 없는절", "\n## ").is_err());
    }

    #[test]
    fn op_and_ident_shapes() {
        assert!(is_op("file.delete"));
        assert!(is_op("registry.strip_value"));
        assert!(!is_op("file"), "점이 없으면 Op 가 아니다");
        assert!(!is_op("File.Delete"), "대문자는 Op 가 아니다");
        assert!(is_ident("registry_value"));
        assert!(!is_ident("registry.value"));
        assert!(!is_ident(""));
    }
}
