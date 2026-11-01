//! 플러그인 디렉터리를 읽어 매니페스트 입력을 만든다.
//!
//! # 이것은 판정이 아니다
//!
//! 크레이트 문서가 말하는 "파일을 읽지 않는다" 는 **판정 함수**
//! (`verify_manifest` · `check_tree`)에 대한 것이다. 여기 있는 것은 그
//! 판정에 넣을 입력을 만드는 편의 함수다.
//!
//! **그런데도 같은 크레이트에 둔다.** 서명하는 쪽(`xtask`)과 검증하는
//! 쪽(CLI)이 트리를 다르게 읽으면 — 한쪽이 숨김 파일을 빼거나 심볼릭 링크를
//! 따라가면 — 정직하게 서명한 플러그인이 검증에서 떨어지거나, 더 나쁘게는
//! 서명이 덮지 못한 파일이 생긴다. 읽는 규칙은 한 곳에만 있어야 한다.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// 서명 대상 목록 파일의 이름.
pub const MANIFEST_NAME: &str = "MANIFEST";

/// 그 서명 파일의 이름. minisign 관례(`<파일>.minisig`)를 따른다 — 외부
/// `minisign` 명령으로도 확인할 수 있어야 한다.
pub const SIGNATURE_NAME: &str = "MANIFEST.minisig";

#[derive(Debug)]
pub enum TreeError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// 심볼릭 링크. 따라가면 서명이 트리 밖 내용을 덮게 되고, 따라가지 않으면
    /// 검증 기계에서 다른 것을 가리킬 수 있다. 어느 쪽도 안전하지 않아 거부한다.
    Symlink(PathBuf),
    /// 파일 이름이 UTF-8 이 아니다. 매니페스트는 텍스트이고 서명은 바이트열을
    /// 덮으므로, 표현할 수 없는 이름을 조용히 넘기면 그 파일이 서명 밖에 남는다.
    NonUtf8(PathBuf),
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreeError::Io { path, source } => {
                write!(f, "{} 를 읽지 못했습니다: {source}", path.display())
            }
            TreeError::Symlink(p) => write!(
                f,
                "{} 는 심볼릭 링크입니다 — 플러그인 트리에 담을 수 없습니다",
                p.display()
            ),
            TreeError::NonUtf8(p) => write!(f, "{} 의 이름이 UTF-8 이 아닙니다", p.display()),
        }
    }
}

impl std::error::Error for TreeError {}

/// 디렉터리를 훑어 `경로 → sha256(hex)` 를 만든다.
///
/// - 경로는 `dir` 기준 상대경로, 구분자는 `/`
/// - `MANIFEST` 와 `MANIFEST.minisig` 는 **뺀다.** 목록이 자기 자신을 담을 수
///   없고, 서명 파일은 서명 대상이 아니다
/// - **숨김 파일도 담는다.** 빼면 그 이름을 골라 서명 밖에 파일을 둘 수 있다
/// - 빈 디렉터리는 담기지 않는다 — 파일 목록이기 때문이다. 플러그인이 빈
///   디렉터리에 의미를 두지 않으므로 이것으로 충분하다
pub fn collect(dir: &Path) -> Result<BTreeMap<String, String>, TreeError> {
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

fn walk(root: &Path, cur: &Path, out: &mut BTreeMap<String, String>) -> Result<(), TreeError> {
    let entries = std::fs::read_dir(cur).map_err(|e| TreeError::Io {
        path: cur.to_path_buf(),
        source: e,
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| TreeError::Io {
            path: cur.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();

        // `symlink_metadata` 를 쓴다 — `metadata` 는 링크를 따라가므로 링크인지
        // 알 수 없다.
        let meta = std::fs::symlink_metadata(&path).map_err(|e| TreeError::Io {
            path: path.clone(),
            source: e,
        })?;
        if meta.file_type().is_symlink() {
            return Err(TreeError::Symlink(path));
        }

        if meta.is_dir() {
            walk(root, &path, out)?;
            continue;
        }

        let rel = path.strip_prefix(root).unwrap_or(&path);
        let Some(rel) = rel.to_str() else {
            return Err(TreeError::NonUtf8(path));
        };
        let rel = rel.replace('\\', "/");
        if rel == MANIFEST_NAME || rel == SIGNATURE_NAME {
            continue;
        }

        let bytes = std::fs::read(&path).map_err(|e| TreeError::Io {
            path: path.clone(),
            source: e,
        })?;
        out.insert(rel, crate::sha256_hex(&bytes));
    }
    Ok(())
}
