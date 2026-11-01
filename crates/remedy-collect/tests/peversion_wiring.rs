//! **주 수집 루프가 버전을 실제로 꿰는가** (C-1b · 2026-10-27).
//!
//! # 왜 가짜 백엔드를 만들어서까지 재는가
//!
//! `peversion` 의 단위·합성 시험은 **파서**를 잰다. 그 파서를 부르는 한 줄이
//! 빠져도 그 시험들은 전부 초록이다 — 적대 검증이 `let version = None;` 으로
//! 바꿔도 게이트 전부가 통과하는 것을 지적했고, `missing_roots.rs` 가 같은 이유로
//! 만들어졌다(*"수집기가 실제로 무엇을 채우는지는 건드리지 않는다"*).
//!
//! 여기서는 `collect_all` 을 통째로 돌려 **레코드의 `version` 칸**을 본다.
//! 어느 플랫폼에서도 돈다 — PE 를 가짜 파일 시스템이 바이트로 준다.

use remedy_artifacts::Scope;
use remedy_collect::{collect_all, Collector};
use remedy_platform::read::{
    EnvRead, FsEntry, FsRead, ProcessRead, RawProcess, RegValue, RegistryRead, Seen, WalkResult,
};
use remedy_platform::PlatformError;
use remedy_sdk::catalog::{Platform, Subject};

/// 경로 → (바이트, 재파스인가).
struct FakeFs {
    root: String,
    files: Vec<(String, Vec<u8>, bool)>,
}

impl FsRead for FakeFs {
    fn walk(&self, root: &str, _limit: usize) -> Result<WalkResult, PlatformError> {
        if root != self.root {
            return Ok(WalkResult {
                entries: Vec::new(),
                truncated: false,
                denied: 0,
                denied_paths: Vec::new(),
            });
        }
        Ok(WalkResult {
            entries: self
                .files
                .iter()
                .map(|(p, b, reparse)| FsEntry {
                    path: p.clone(),
                    is_dir: false,
                    is_reparse: *reparse,
                    size: b.len() as u64,
                    mtime: "2026-08-21T00:00:00Z".into(),
                    ctime: None,
                    mode: None,
                })
                .collect(),
            truncated: false,
            denied: 0,
            denied_paths: Vec::new(),
        })
    }

    fn read_file(&self, path: &str, max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
        match self.files.iter().find(|(p, _, _)| p == path) {
            // 상한을 넘으면 읽지 않는다 — 실제 백엔드와 같은 규약이다.
            Some((_, b, _)) if b.len() as u64 > max => Ok(None),
            Some((_, b, _)) => Ok(Some(b.clone())),
            None => Ok(None),
        }
    }

    fn look(&self, path: &str) -> Seen {
        if path == self.root {
            Seen::Present
        } else {
            Seen::Absent
        }
    }
}

impl EnvRead for FakeFs {
    fn expand(&self, s: &str) -> String {
        s.to_string()
    }
}
impl ProcessRead for FakeFs {
    fn processes(&self) -> Result<Vec<RawProcess>, PlatformError> {
        Ok(Vec::new())
    }
}
impl RegistryRead for FakeFs {
    fn value(&self, _key: &str, _name: &str) -> Result<Option<RegValue>, PlatformError> {
        Ok(None)
    }
    fn subkeys(&self, _key: &str) -> Result<Vec<String>, PlatformError> {
        Ok(Vec::new())
    }
    fn values(&self, _key: &str) -> Result<Vec<(String, RegValue)>, PlatformError> {
        Ok(Vec::new())
    }
    fn key_exists(&self, _key: &str) -> bool {
        false
    }
}

const ROOT: &str = "c:\\app";

fn scope() -> Scope {
    let mut s = Scope::diagnostic(vec![ROOT.into()], Platform::Windows);
    s.subjects = vec![Subject::File];
    s
}

/// `peversion_synth.rs` 와 같은 PE 를 쓴다. 그 파일이 짓는 법을 갖고 있으므로
/// 여기서는 **그 결과만** 필요하다 — 바이트를 두 번 짓지 않도록 최소한으로
/// 다시 적는다(시험 사이에 코드를 공유하려면 별도 크레이트가 필요하다).
#[allow(dead_code)]
mod pe {
    include!("common/peversion_pe.rs");
}

#[test]
fn 수집기가_레코드에_버전을_꿴다() {
    let good = pe::pe_with("16.10");
    let fs = FakeFs {
        root: ROOT.into(),
        files: vec![
            ("c:\\app\\a.dll".into(), good.clone(), false),
            // PE 가 아닌 실행 파일 — 값을 지어내지 않는다.
            ("c:\\app\\b.exe".into(), b"not a pe".to_vec(), false),
            // 대상 형식이 아니다 — 읽지 않는다.
            ("c:\\app\\c.ini".into(), good.clone(), false),
        ],
    };
    let obs = collect_all(&Collector::new(fs), &scope()).expect("수집");
    let files = obs.files();
    assert_eq!(files.len(), 3, "{files:?}");

    let by = |n: &str| {
        files
            .iter()
            .find(|f| f.path.ends_with(n))
            .unwrap_or_else(|| panic!("{n} 이 없다"))
    };
    assert_eq!(
        by("a.dll").version.as_deref(),
        Some("16.10"),
        "주 수집 루프가 버전을 꿰지 않았다"
    );
    assert_eq!(by("b.exe").version, None, "PE 가 아닌데 값이 담겼다");
    assert_eq!(by("c.ini").version, None, "대상 형식이 아닌데 값이 담겼다");
    // 해시는 그대로 떠야 한다 — 본문을 한 번만 읽도록 고친 자리의 역검증이다.
    assert!(by("a.dll").sha256.is_some(), "해시가 사라졌다");
}

#[test]
fn 상한을_넘은_파일은_해시처럼_빈다() {
    // `version` 은 `sha256` 과 **같은 자리에서 같은 이유로** 빈다. 한쪽만
    // 채워지면 그 비대칭이 룰 작성자를 헷갈리게 한다.
    let mut big = pe::pe_with("16.10");
    big.resize(64 * 1024, 0);
    let fs = FakeFs {
        root: ROOT.into(),
        files: vec![("c:\\app\\big.dll".into(), big, false)],
    };
    let mut s = scope();
    s.max_hash_bytes = 1024;
    let obs = collect_all(&Collector::new(fs), &s).expect("수집");
    let f = &obs.files()[0];
    assert_eq!(f.sha256, None, "상한을 넘었는데 해시가 떴다");
    assert_eq!(f.version, None, "상한을 넘었는데 버전이 담겼다");
}

#[test]
fn 재파스_지점은_해시처럼_빈다() {
    // 링크를 따라가면 **링크가 가리킨 다른 파일**의 값을 링크의 것으로 적는다.
    let fs = FakeFs {
        root: ROOT.into(),
        files: vec![("c:\\app\\link.dll".into(), pe::pe_with("16.10"), true)],
    };
    let obs = collect_all(&Collector::new(fs), &scope()).expect("수집");
    let f = &obs.files()[0];
    assert_eq!(f.sha256, None, "재파스인데 해시가 떴다");
    assert_eq!(f.version, None, "재파스인데 버전이 담겼다");
}
