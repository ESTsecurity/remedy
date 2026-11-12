//! `file` 이 걷는 길에서 **이름 꼴로 거르고 · 아카이브 안까지 여는가** (코어 1.11.0 · `file_names` ·
//! `archive_entry`).
//!
//! 해석기의 단위 시험(`archive.rs`)은 메모리의 바이트를 준다. 여기서는 수집기가 실제로 그 길을 타는지 —
//! 거른 파일만 기록하는지, 해시하려고 든 본문을 다시 읽지 않는지, 큰 파일은 짚어 읽는지, 링크와 겹친 뿌리를
//! 어떻게 다루는지 — 를 잰다.

use remedy_artifacts::{ArchiveEntryRecord, Harvest, Scope};
use remedy_collect::Collector;
use remedy_platform::read::{FsEntry, FsRead, Seen, WalkResult};
use remedy_platform::PlatformError;
use remedy_sdk::catalog::{Platform, Subject};
use std::cell::RefCell;

/// 뿌리 하나 아래의 파일들. 통째 읽기와 짚어 읽기를 따로 센다.
struct Fs {
    root: String,
    files: Vec<(String, Vec<u8>, bool)>,
    whole: RefCell<Vec<String>>,
    ranged: RefCell<Vec<String>>,
}

impl Fs {
    fn new(root: &str, files: Vec<(&str, Vec<u8>, bool)>) -> Self {
        Self {
            root: root.to_string(),
            files: files
                .into_iter()
                .map(|(p, b, link)| (p.to_string(), b, link))
                .collect(),
            whole: RefCell::new(Vec::new()),
            ranged: RefCell::new(Vec::new()),
        }
    }
    fn body(&self, path: &str) -> Option<&Vec<u8>> {
        self.files.iter().find(|f| f.0 == path).map(|f| &f.1)
    }
}

impl FsRead for Fs {
    fn walk(&self, root: &str, _limit: usize) -> Result<WalkResult, PlatformError> {
        let entries = if root == self.root {
            self.files
                .iter()
                .map(|(p, b, link)| FsEntry {
                    path: p.clone(),
                    is_dir: false,
                    is_reparse: *link,
                    size: b.len() as u64,
                    mtime: "2026-11-12T00:00:00Z".into(),
                    ctime: None,
                    mode: None,
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(WalkResult {
            entries,
            truncated: false,
            denied: 0,
            denied_paths: Vec::new(),
        })
    }
    fn read_file(&self, path: &str, max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
        self.whole.borrow_mut().push(path.to_string());
        Ok(self.body(path).filter(|b| b.len() as u64 <= max).cloned())
    }
    fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<(u64, Vec<u8>), PlatformError> {
        self.ranged.borrow_mut().push(path.to_string());
        let b = self.body(path).cloned().unwrap_or_default();
        let s = (offset as usize).min(b.len());
        let e = s.saturating_add(len).min(b.len());
        Ok((b.len() as u64, b[s..e].to_vec()))
    }
    fn look(&self, path: &str) -> Seen {
        if path == self.root {
            Seen::Present
        } else {
            Seen::Absent
        }
    }
}

/// 저장(0) 항목만으로 된 zip — `deflate` 는 `pom.properties` 하나에 쓴다.
fn zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, data, deflated) in entries {
        let (payload, method): (Vec<u8>, u16) = if *deflated {
            use std::io::Write;
            let mut e =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            (e.finish().unwrap(), 8)
        } else {
            (data.to_vec(), 0)
        };
        let local = out.len() as u32;
        out.extend(0x0403_4b50u32.to_le_bytes());
        out.extend([20, 0, 0, 0]);
        out.extend(method.to_le_bytes());
        out.extend([0u8; 8]);
        out.extend((payload.len() as u32).to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out.extend((name.len() as u16).to_le_bytes());
        out.extend([0, 0]);
        out.extend(name.as_bytes());
        out.extend(&payload);
        cd.extend(0x0201_4b50u32.to_le_bytes());
        cd.extend([20, 0, 20, 0, 0, 0]);
        cd.extend(method.to_le_bytes());
        cd.extend([0u8; 8]);
        cd.extend((payload.len() as u32).to_le_bytes());
        cd.extend((data.len() as u32).to_le_bytes());
        cd.extend((name.len() as u16).to_le_bytes());
        cd.extend([0u8; 12]);
        cd.extend(local.to_le_bytes());
        cd.extend(name.as_bytes());
    }
    let cd_at = out.len() as u32;
    out.extend(&cd);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((cd.len() as u32).to_le_bytes());
    out.extend(cd_at.to_le_bytes());
    out.extend([0, 0]);
    out
}

const POM: &[u8] = b"artifactId=log4j-core\nversion=2.14.1\n";
const POM_PATH: &str = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties";

fn scope(root: &str) -> Scope {
    let mut s = Scope::diagnostic(vec![root.to_string()], Platform::Linux);
    s.subjects = vec![Subject::File, Subject::ArchiveEntry];
    s.file_names = vec!["*.jar".into(), "*.war".into()];
    s.archive_members = vec!["pom.properties".into(), "*.jar".into()];
    s
}

fn run(c: &Collector<Fs>, sc: &Scope) -> (Vec<String>, Harvest<ArchiveEntryRecord>) {
    let mut ah = Harvest::default();
    let h = c.files(sc, Some(&mut ah)).expect("수집");
    (h.records.into_iter().map(|r| r.path).collect(), ah)
}

#[test]
fn only_named_files_are_recorded_and_a_hashed_body_is_not_read_twice() {
    let jar = zip(&[(POM_PATH, POM, true)]);
    let fs = Fs::new(
        "/opt",
        vec![
            ("/opt/app/lib/x.jar", jar, false),
            ("/opt/app/readme.txt", b"hello".to_vec(), false),
        ],
    );
    let c = Collector::new(fs);
    let (files, ah) = run(&c, &scope("/opt"));
    let fs = c.platform();
    assert_eq!(
        files,
        ["/opt/app/lib/x.jar"],
        "이름 꼴 밖의 파일을 기록했다"
    );
    assert_eq!(ah.records.len(), 1, "{ah:?}");
    let r = &ah.records[0];
    assert_eq!(
        (r.archive.as_str(), r.path.as_str()),
        ("/opt/app/lib/x.jar", POM_PATH)
    );
    assert!(r.text.as_deref().unwrap().contains("version=2.14.1"));
    // 해시하려고 든 본문으로 열었다 — 짚어 읽기가 없다.
    assert!(fs.ranged.borrow().is_empty(), "{:?}", fs.ranged.borrow());
    assert_eq!(fs.whole.borrow().as_slice(), ["/opt/app/lib/x.jar"]);
}

#[test]
fn a_file_over_the_hash_cap_is_opened_by_ranges_and_links_are_not_opened() {
    let jar = zip(&[(POM_PATH, POM, true)]);
    let fs = Fs::new(
        "/opt",
        vec![
            ("/opt/big.jar", jar.clone(), false),
            ("/opt/link.jar", jar, true),
        ],
    );
    let mut sc = scope("/opt");
    // 해시 상한을 낮춰 본문이 들리지 않게 한다 — 큰 war 의 길이다.
    sc.max_hash_bytes = 16;
    let c = Collector::new(fs);
    let (_, ah) = run(&c, &sc);
    let fs = c.platform();
    let archives: Vec<&str> = ah.records.iter().map(|r| r.archive.as_str()).collect();
    assert_eq!(
        archives,
        ["/opt/big.jar"],
        "링크를 열었거나 큰 파일을 못 열었다: {ah:?}"
    );
    assert!(ah.records[0].text.is_some());
    assert!(fs.ranged.borrow().iter().all(|p| p == "/opt/big.jar"));
}

#[test]
fn the_same_file_under_overlapping_roots_is_opened_once() {
    let jar = zip(&[(POM_PATH, POM, true)]);
    let fs = Fs::new("/opt", vec![("/opt/x.jar", jar, false)]);
    let mut sc = scope("/opt");
    sc.scan_roots = vec!["/opt".into(), "/opt".into()];
    let (_, ah) = run(&Collector::new(fs), &sc);
    assert_eq!(ah.records.len(), 1, "{ah:?}");
}

#[test]
fn without_names_or_archive_entry_the_file_walk_is_what_it_was() {
    // 출하 룰의 꼴 — 이름 꼴도 아카이브도 없다. 기록은 전과 같아야 한다(파일 전부).
    let fs = Fs::new(
        "/opt",
        vec![
            ("/opt/a.jar", zip(&[(POM_PATH, POM, true)]), false),
            ("/opt/b.txt", b"x".to_vec(), false),
        ],
    );
    let mut sc = Scope::diagnostic(vec!["/opt".into()], Platform::Linux);
    sc.subjects = vec![Subject::File];
    let c = Collector::new(fs);
    let h = c.files(&sc, None).expect("수집");
    let files: Vec<String> = h.records.into_iter().map(|r| r.path).collect();
    assert_eq!(files, ["/opt/a.jar", "/opt/b.txt"]);
    assert!(c.platform().ranged.borrow().is_empty());
}
