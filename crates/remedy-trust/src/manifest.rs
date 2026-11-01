//! 서명 대상이 되는 파일 목록.
//!
//! # 왜 별도 파일인가 — 서명을 트리에 씌우는 방법
//!
//! minisign 은 **바이트열 하나**에 서명한다. 플러그인은 디렉터리이므로,
//! 트리를 한 줄씩 적은 텍스트를 만들어 그것에 서명하고 검증 때 실제 트리와
//! 대조한다. 서명이 덮는 것은 이 텍스트이고, 이 텍스트가 트리를 덮는다.
//!
//! # 형식
//!
//! ```text
//! # remedy plugin manifest v1
//! <sha256 소문자 hex>  <상대경로>
//! ```
//!
//! - 구분자는 공백 2칸. `sha256sum` 출력과 같은 모양이라 사람이 눈으로
//!   대조할 수 있고, 필요하면 표준 도구로도 확인된다
//! - 경로 구분자는 **`/` 고정**. 같은 플러그인이 Windows 와 Linux 에서 같은
//!   서명으로 통과해야 한다
//! - 정렬은 서명자가 한다. 검증은 순서를 보지 않는다 — 다만 **같은 경로가 두
//!   번 나오면 거부**한다. 어느 쪽을 믿을지 정할 수 없기 때문이다

use std::collections::BTreeMap;

use crate::TrustError;

/// 매니페스트 첫 줄. 형식이 바뀌면 이 줄이 바뀌고, 옛 검증기는 거부한다.
pub(crate) const HEADER: &str = "# remedy plugin manifest v1";

/// 목록의 한 줄.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// 플러그인 디렉터리 기준 상대경로. 구분자는 `/`.
    pub path: String,
    /// 소문자 hex sha256.
    pub sha256: String,
}

/// 서명 대상 파일 목록.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Manifest {
    entries: Vec<ManifestEntry>,
    index: BTreeMap<String, usize>,
}

impl Manifest {
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    pub fn contains(&self, path: &str) -> bool {
        self.index.contains_key(path)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 경로 → sha256 목록으로 매니페스트 본문을 만든다. 서명 도구가 쓴다.
    ///
    /// `BTreeMap` 을 받는 것은 **정렬을 타입으로 강제**하기 위해서다. 같은
    /// 트리가 언제나 같은 바이트를 내야 서명이 재현된다.
    pub fn render(files: &BTreeMap<String, String>) -> String {
        let mut s = String::from(HEADER);
        s.push('\n');
        for (path, sha) in files {
            s.push_str(sha);
            s.push_str("  ");
            s.push_str(path);
            s.push('\n');
        }
        s
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, TrustError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| TrustError::Manifest(format!("UTF-8 이 아닙니다: {e}")))?;

        let mut lines = text.lines();
        match lines.next() {
            Some(h) if h.trim_end() == HEADER => {}
            Some(other) => {
                return Err(TrustError::Manifest(format!(
                    "첫 줄이 {HEADER:?} 가 아니다: {other:?}"
                )))
            }
            None => return Err(TrustError::Manifest("비어 있습니다".into())),
        }

        let mut entries = Vec::new();
        let mut index = BTreeMap::new();
        for (i, line) in lines.enumerate() {
            let lineno = i + 2;
            if line.trim().is_empty() {
                continue;
            }
            let Some((sha, path)) = line.split_once("  ") else {
                return Err(TrustError::Manifest(format!(
                    "{lineno}줄: '<sha256>  <경로>' 형식이 아닙니다"
                )));
            };
            let sha = sha.trim();
            if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(TrustError::Manifest(format!(
                    "{lineno}줄: sha256 이 64자리 hex 가 아닙니다"
                )));
            }
            check_path(path).map_err(|m| TrustError::Manifest(format!("{lineno}줄: {m}")))?;

            if index.insert(path.to_string(), entries.len()).is_some() {
                return Err(TrustError::Manifest(format!(
                    "{lineno}줄: 같은 경로가 두 번 나온다 — {path:?}"
                )));
            }
            entries.push(ManifestEntry {
                path: path.to_string(),
                sha256: sha.to_ascii_lowercase(),
            });
        }

        if entries.is_empty() {
            // 빈 목록에 서명하면 "어떤 트리든 통과" 가 된다. 트리 대조에서
            // 모든 실제 파일이 Extra 로 걸리므로 결과는 같지만, 여기서
            // 막아야 사유가 분명해진다.
            return Err(TrustError::Manifest("파일이 한 개도 없습니다".into()));
        }
        Ok(Self { entries, index })
    }
}

/// 매니페스트에 들어올 수 있는 경로인지 본다.
///
/// **이 검사가 없으면 서명된 목록이 트리 밖을 가리킬 수 있다.** 우리는 파일을
/// 읽지 않지만 호출자가 이 경로로 읽으므로, 여기서 막는 것이 맞는 자리다.
fn check_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("경로가 비어 있습니다".into());
    }
    if path.contains('\\') {
        return Err(format!("경로 구분자는 '/' 다 — {path:?}"));
    }
    if path.starts_with('/') {
        return Err(format!("절대경로는 담을 수 없다 — {path:?}"));
    }
    // `C:` 같은 드라이브 지정. Windows 에서만 뜻이 있지만 서명은 두 OS 가
    // 나눠 쓰므로 어느 쪽에서 만들었든 거부한다.
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        return Err(format!("드라이브 지정은 담을 수 없다 — {path:?}"));
    }
    if path
        .split('/')
        .any(|seg| seg == ".." || seg == "." || seg.is_empty())
    {
        return Err(format!("'.' · '..' · 빈 조각을 담을 수 없다 — {path:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("plugin.yaml".into(), "a".repeat(64));
        m.insert("rules/evilai.yar".into(), "b".repeat(64));
        m
    }

    #[test]
    fn 렌더와_파싱이_왕복한다() {
        let text = Manifest::render(&files());
        let m = Manifest::parse(text.as_bytes()).expect("파싱");
        assert_eq!(m.entries().len(), 2);
        assert!(m.contains("rules/evilai.yar"));
        assert_eq!(Manifest::render(&files()), text, "렌더가 결정적이지 않다");
    }

    #[test]
    fn 같은_트리는_같은_바이트를_낸다() {
        // 서명이 재현되려면 이것이 성립해야 한다.
        let a = Manifest::render(&files());
        let mut reversed: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in files().into_iter().rev() {
            reversed.insert(k, v);
        }
        assert_eq!(a, Manifest::render(&reversed));
    }

    #[test]
    fn 헤더가_다르면_거부한다() {
        let bad = format!("# something else\n{}  plugin.yaml\n", "a".repeat(64));
        assert!(Manifest::parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn 트리를_벗어나는_경로를_거부한다() {
        for p in [
            "../outside.yaml",
            "/etc/passwd",
            "C:/Windows/System32/x.dll",
            "rules\\evilai.yar",
            "./plugin.yaml",
            "rules//evilai.yar",
        ] {
            let text = format!("{HEADER}\n{}  {p}\n", "a".repeat(64));
            assert!(
                Manifest::parse(text.as_bytes()).is_err(),
                "받아들이면 안 되는 경로를 통과시켰다: {p}"
            );
        }
    }

    #[test]
    fn 같은_경로가_두_번_나오면_거부한다() {
        let text = format!(
            "{HEADER}\n{}  plugin.yaml\n{}  plugin.yaml\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        assert!(Manifest::parse(text.as_bytes()).is_err());
    }

    #[test]
    fn 빈_목록을_거부한다() {
        let text = format!("{HEADER}\n");
        assert!(Manifest::parse(text.as_bytes()).is_err());
    }

    #[test]
    fn 잘못된_해시를_거부한다() {
        for sha in ["a".repeat(63), "z".repeat(64), String::new()] {
            let text = format!("{HEADER}\n{sha}  plugin.yaml\n");
            assert!(Manifest::parse(text.as_bytes()).is_err(), "sha={sha:?}");
        }
    }
}
