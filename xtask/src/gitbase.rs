//! git 의 바탕 — 저장소 게이트가 '전과 달라졌는가' 를 견주는 상대(2026-11-21 · 목표 remedy_하루30건_대응체계 차례 2).
//!
//! 전에는 견줄 상대를 저장소에 파일로 커밋했다(`plugins/versions.lock.json` · `plugins/RULES-VERSION`). 룰 PR 마다 그
//! 파일을 고쳐 셋이 함께 지으면 늘 충돌했다 — 이제 상대는 git 이 가진 바탕이다:
//!
//! | 자리 | 바탕 |
//! |---|---|
//! | PR 의 CI | 받는 가지와의 병합 바탕(= 병합 ref 의 첫 부모 · `origin/main` 이 없는 얕은 받기도 그 첫 부모) |
//! | main 의 push CI | 지금 Latest 의 태그(리눅스 잡이 `REMEDY_BASE` 로 준다 — 공개본 뒤의 변경 전부. 병합 커밋의 첫 부모와 견주던 판은 잇따른 병합에서 앞 실행이 취소되면 마지막 PR 만 봤다) |
//! | 로컬 가지 · 로컬 작업 트리 | `origin/main` 과의 병합 바탕 |
//! | 출시 | 지금 Latest 의 태그(배포 잡이 `--base` 로 준다) |
//!
//! 고르는 차례: `--base <ref>` → 환경 `REMEDY_BASE` → `origin/main` 과의 병합 바탕 → HEAD 가 병합 커밋이면 그 첫 부모.
//! 병합 바탕이 첫 부모보다 앞이다 — main 의 병합 커밋 위에서 고치는 로컬 작업 트리는 바탕이 HEAD 자신이어야 하는데, 첫 부모를
//! 먼저 보면 바로 앞에 병합한 PR 의 변경까지 이 작업의 것으로 센다(2026-11-21 · 그 자리에서 쟀다). 하나도 서지 않으면
//! 멈춘다 — 견줄 것 없이 '그대로다' 로 지나지 않는다.

use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))
}

fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = git(root, args)?;
    if !out.status.success() {
        return Err(format!(
            "git {} 실패: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// 커밋을 가리키는 이름인가(태그 · 가지 · 해시).
pub fn exists(root: &Path, rev: &str) -> bool {
    git(
        root,
        &["rev-parse", "-q", "--verify", &format!("{rev}^{{commit}}")],
    )
    .map(|o| o.status.success())
    .unwrap_or(false)
}

/// 견줄 바탕을 고른다(첫머리의 차례). `args` 의 `--base <ref>` 를 먼저 본다.
pub fn resolve(root: &Path, args: &[String]) -> Result<String, String> {
    if let Some(i) = args.iter().position(|a| a == "--base") {
        let b = args.get(i + 1).ok_or("--base <ref>")?;
        if !exists(root, b) {
            return Err(format!(
                "바탕 '{b}' 가 이 저장소에 없다 — git fetch --tags origin 뒤 다시"
            ));
        }
        return Ok(b.clone());
    }
    if let Ok(b) = std::env::var("REMEDY_BASE") {
        if !b.is_empty() {
            if !exists(root, &b) {
                return Err(format!("REMEDY_BASE '{b}' 가 이 저장소에 없다"));
            }
            return Ok(b);
        }
    }
    if exists(root, "origin/main") {
        let b = git_text(root, &["merge-base", "HEAD", "origin/main"])?;
        if !b.is_empty() {
            return Ok(b);
        }
    }
    // `origin/main` 이 없는 얕은 받기(CI 의 Windows 잡 — PR 의 병합 ref 를 깊이 2 로 받는다)에서 HEAD 가 병합 커밋이면 그 첫 부모.
    if exists(root, "HEAD^2") {
        return Ok("HEAD^1".into());
    }
    Err(
        "견줄 바탕을 고르지 못했다 — --base <ref>(예: origin/main · 지금 Latest 의 태그)를 줄 것"
            .into(),
    )
}

/// NUL 로 가른 이름들 — `-z` 출력. 한글 같은 비ASCII 이름을 git 이 따옴표 · 8진 표기로 바꾸지 않는다(`-z` 가 없으면
/// `"docs/changes/\355…"` 꼴로 나와 그 이름의 조각이 릴리스 본문에서 조용히 빠졌다 · 2026-11-21 반박 검토).
fn nul_names(out: &[u8]) -> Vec<String> {
    out.split(|b| *b == 0)
        .filter(|n| !n.is_empty())
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .collect()
}

/// `rev` 의 `path` 아래 파일 이름(저장소 기준 · `/` 구분). 없으면 빈 목록.
pub fn ls(root: &Path, rev: &str, path: &str) -> Result<Vec<String>, String> {
    let out = git(
        root,
        &["ls-tree", "-r", "-z", "--name-only", rev, "--", path],
    )?;
    if !out.status.success() {
        return Err(format!(
            "git ls-tree {rev} -- {path} 실패: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(nul_names(&out.stdout))
}

/// `rev` 의 `path` 의 바이트. 그 자리에 파일이 없으면 `None`.
pub fn show(root: &Path, rev: &str, path: &str) -> Result<Option<Vec<u8>>, String> {
    let names = ls(root, rev, path)?;
    if !names.iter().any(|n| n == path) {
        return Ok(None);
    }
    let out = git(root, &["show", &format!("{rev}:{path}")])?;
    if !out.status.success() {
        return Err(format!(
            "git show {rev}:{path} 실패: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(Some(out.stdout))
}

/// 추적하는 파일 가운데 `pathspec` 에 걸리는 것(작업 트리 기준).
pub fn tracked(root: &Path, pathspec: &[&str]) -> Result<Vec<String>, String> {
    let mut args = vec!["ls-files", "-z", "--"];
    args.extend_from_slice(pathspec);
    let out = git(root, &args)?;
    if !out.status.success() {
        return Err(format!(
            "git {} 실패: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(nul_names(&out.stdout))
}

/// 오늘(KST)의 날 수 — 1970-01-01 부터 센 날. 사람이 적는 날짜(`added` · 룰 버전)는 한국 날짜다.
pub fn today_kst() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + 9 * 3600;
    (secs / 86_400) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 한글 이름이 적은 그대로 돌아온다 — `-z` 없이 읽으면 따옴표 · 8진 표기라 같은 이름으로 견줄 수 없었다.
    #[test]
    fn names_with_hangul_come_back_as_written() {
        let root = crate::workspace_root();
        let names = ls(&root, "HEAD", "docs").expect("ls-tree");
        assert!(
            names.iter().any(|n| n == "docs/위협별-안내.md"),
            "{names:?}"
        );
        assert!(names.iter().all(|n| !n.starts_with('"')), "{names:?}");
        let t = tracked(&root, &["docs/위협별-안내.md"]).expect("ls-files");
        assert_eq!(t, vec!["docs/위협별-안내.md".to_string()]);
    }

    #[test]
    fn nul_separated_names_split_cleanly() {
        assert_eq!(
            nul_names(b"a/b.md\0docs/\xec\xa1\xb0\xea\xb0\x81.md\0"),
            vec!["a/b.md".to_string(), "docs/조각.md".to_string()]
        );
        assert!(nul_names(b"").is_empty());
    }
}
