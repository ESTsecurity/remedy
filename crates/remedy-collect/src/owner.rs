//! 패키지 파일 소유 — 룰이 모은 파일이 패키지(dpkg · RPM)가 깐 그대로인가 (코어 1.7.0 · 목표 remedy_PHP스캐너통합
//! 결정 24).
//!
//! # 왜 있는가
//!
//! 패키지 판으로 판정하는 점검은 *"패키지가 깐 실행 파일은 그 판의 것"* 이라는 가정 위에 선다. 그 파일을 다른 것으로
//! 바꾸면 패키지 DB 는 그대로라 판정이 그 파일을 말하지 않는다 — 실측: Oracle Linux 8 에서 패키지가 깐 `/usr/bin/php`
//! 를 바꿔도 점검이 0 이었고 `rpm -V` 만 `S.5....T.` 를 냈다. 동반 모듈의 이미지 점검은 이미 그 대조를 한다(사내
//! runtime-scanner 의 `packageFileProblem`) — 본체는 동반 모듈을 링크하지 않으므로(설계-04 §1) 여기서 따로 한다.
//!
//! # 무엇을 읽나
//!
//! | 매니저 | 기록 | 다이제스트 |
//! |---|---|---|
//! | dpkg | `/var/lib/dpkg/info/<패키지>[:<아키텍처>].md5sums` — 줄마다 `<md5>  <경로(앞의 / 없이)>` | MD5 |
//! | RPM | 패키지 헤더의 파일 목록 · 다이제스트(`remedy_rpmdb::read_host`) | 헤더가 적은 대로 SHA-256 · MD5 |
//!
//! **`package` subject 를 선언한 룰에서만 돈다**(부르는 쪽이 고른다) — 이 DB 들은 그 subject 의 고정 자리라,
//! 선언하지 않은 룰이 읽으면 선언한 범위 밖을 읽는다. 대조하는 것은 **그 룰이 이미 모은 파일 가운데 패키지가
//! 소유한 것**뿐이다 — 시스템 전체를 해시하지 않는다. apk 는 보지 않는다(Alpine 의 패키지는 점검 룰이 늘 확인
//! 필요로 낸다).
//!
//! # 값
//!
//! 소유한 파일의 `package` 에 패키지 이름, `package_match` 에 [`PACKAGE_MATCH`] 의 하나를 적는다. dpkg 는 `.md5sums`
//! 에 있는 경로만 소유로 본다(`.list` 는 읽지 않는다) — 링크와 설정 파일은 거기 없다. 두 패키지가 같은 경로를
//! 가지면 먼저 읽은 쪽이다(dpkg 가 RPM 보다 먼저 · 각자 DB 차례).

use crate::package::{rpm_db_path, wal_is_settled, MAX_RPM_DB_BYTES};
use md5::{Digest as _, Md5};
use remedy_artifacts::{FileRecord, Harvest, Scope};
use remedy_platform::read::{FsRead, Seen};
use remedy_rpmdb::DigestAlgorithm;
use remedy_sdk::catalog::PACKAGE_MATCH;
use std::collections::{HashMap, HashSet};

/// dpkg 가 패키지마다 두는 파일들의 자리.
const DPKG_INFO: &str = "/var/lib/dpkg/info";
/// `.md5sums` 하나를 읽는 상한 — 파일이 가장 많은 패키지(커널 모듈)도 수 MiB 다.
const MAX_MD5SUMS_BYTES: u64 = 16 * 1024 * 1024;
/// `/var/lib/dpkg/info` 를 훑는 항목 상한 — 패키지마다 파일 서넛이고, 가장 큰 설치본도 수만 개다.
const MAX_INFO_ENTRIES: usize = 500_000;

/// 패키지 기록이 이 파일에 대해 적은 것.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Recorded {
    Md5(String),
    Sha256(String),
    /// 목록에는 있는데 다이제스트가 없다 · 비었다 · 알고리즘을 모른다.
    Nothing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Owner {
    package: String,
    recorded: Recorded,
}

/// 모은 파일마다 소유한 패키지와 대조 결과를 적는다. 못 읽은 DB 자리는 `h` 에 거부 · 잘림으로 남긴다 — 조용히
/// 넘기면 바뀐 파일이 *"패키지가 깐 그대로"* 로 읽힌다.
pub(crate) fn annotate<P: FsRead>(fs: &P, scope: &Scope, h: &mut Harvest<FileRecord>) {
    if h.records.is_empty() {
        return;
    }
    let wanted: HashSet<String> = h.records.iter().map(|r| r.path.clone()).collect();
    let mut owners: HashMap<String, Owner> = HashMap::new();
    dpkg_owners(fs, &wanted, &mut owners, h);
    rpm_owners(fs, &wanted, &mut owners, h);
    for r in &mut h.records {
        let Some(o) = owners.get(&r.path) else {
            continue;
        };
        let Some(state) = match_state(fs, scope, r, &o.recorded) else {
            continue;
        };
        r.package = o.package.clone();
        r.package_match = state.to_string();
    }
}

/// dpkg 의 `.md5sums` 에서 모은 파일의 소유자.
fn dpkg_owners<P: FsRead>(
    fs: &P,
    wanted: &HashSet<String>,
    owners: &mut HashMap<String, Owner>,
    h: &mut Harvest<FileRecord>,
) {
    match fs.look(DPKG_INFO) {
        // dpkg 가 없는 기계(RPM · Alpine) — 정상이다.
        Seen::Absent => return,
        Seen::Locked | Seen::CannotTell => {
            h.deny(DPKG_INFO);
            return;
        }
        Seen::Present => {}
    }
    let walk = match fs.walk(DPKG_INFO, MAX_INFO_ENTRIES) {
        Ok(w) => w,
        Err(_) => {
            h.deny(DPKG_INFO);
            return;
        }
    };
    if walk.truncated {
        h.truncated = true;
    }
    h.absorb_denied(walk.denied, walk.denied_paths);
    for e in walk.entries {
        if e.is_dir {
            continue;
        }
        let name = e.path.rsplit('/').next().unwrap_or(&e.path);
        let Some(stem) = name.strip_suffix(".md5sums") else {
            continue;
        };
        // `libc6:amd64.md5sums` — 아키텍처를 뗀 것이 패키지 이름이다.
        let package = stem.split(':').next().unwrap_or(stem);
        match fs.read_file(&e.path, MAX_MD5SUMS_BYTES) {
            Ok(Some(bytes)) => {
                for (path, sum) in md5sums(&bytes) {
                    if wanted.contains(&path) {
                        owners.entry(path).or_insert_with(|| Owner {
                            package: package.to_string(),
                            recorded: Recorded::Md5(sum),
                        });
                    }
                }
            }
            // 상한을 넘었다 — 그 패키지의 파일을 대조하지 못했다.
            Ok(None) => h.truncated = true,
            Err(_) => h.deny(e.path.clone()),
        }
    }
}

/// `.md5sums` 의 줄들 — `(절대 경로, 소문자 md5)`. 꼴이 틀린 줄은 건너뛴다.
fn md5sums(bytes: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| {
            let (sum, rel) = line.split_once("  ")?;
            if sum.len() != 32 || !sum.bytes().all(|b| b.is_ascii_hexdigit()) || rel.is_empty() {
                return None;
            }
            Some((
                format!("/{}", rel.trim_start_matches('/')),
                sum.to_ascii_lowercase(),
            ))
        })
        .collect()
}

/// RPM 헤더의 파일 목록 · 다이제스트에서 모은 파일의 소유자.
fn rpm_owners<P: FsRead>(
    fs: &P,
    wanted: &HashSet<String>,
    owners: &mut HashMap<String, Owner>,
    h: &mut Harvest<FileRecord>,
) {
    let Some(path) = rpm_db_path(fs, h) else {
        return;
    };
    match fs.read_file(&path, MAX_RPM_DB_BYTES) {
        Ok(Some(bytes)) => match remedy_rpmdb::read_host(&bytes, |f| wanted.contains(f)) {
            Ok(db) => {
                // 상한에 닿았거나 WAL 에 아직 반영되지 않은 바뀜이 있다 — 본 것이 전부가 아니다.
                if db.limit.is_some()
                    || (path.ends_with("rpmdb.sqlite") && !wal_is_settled(fs, &path))
                {
                    h.truncated = true;
                }
                rpm_entries(&db, owners);
            }
            Err(_) => h.truncated = true,
        },
        Ok(None) => h.truncated = true,
        Err(_) => h.deny(path),
    }
}

/// 읽은 RPM DB 에서 소유자를 고른다 — [`rpm_owners`] 에서 떼어 DB 없이 시험한다.
fn rpm_entries(db: &remedy_rpmdb::Untrusted, owners: &mut HashMap<String, Owner>) {
    for p in &db.packages {
        for (i, file) in p.files.iter().enumerate() {
            let recorded = match &p.digests {
                Ok(d) => match d.digests.get(i).filter(|s| !s.is_empty()) {
                    Some(s) => match d.algorithm {
                        DigestAlgorithm::Sha256 => Recorded::Sha256(s.to_ascii_lowercase()),
                        DigestAlgorithm::Md5 => Recorded::Md5(s.to_ascii_lowercase()),
                    },
                    None => Recorded::Nothing,
                },
                Err(_) => Recorded::Nothing,
            };
            owners.entry(file.clone()).or_insert_with(|| Owner {
                package: p.header.name.clone(),
                recorded,
            });
        }
    }
}

/// 기록과 파일을 견준다. `None` 은 적지 않는다는 뜻이다 — 기록에 다이제스트가 없는 **링크**(해시가 없는 레코드)는
/// 견줄 내용이 없다.
fn match_state<P: FsRead>(
    fs: &P,
    scope: &Scope,
    r: &FileRecord,
    recorded: &Recorded,
) -> Option<&'static str> {
    let [same, different, unrecorded, unreadable] = PACKAGE_MATCH;
    Some(match recorded {
        Recorded::Nothing if r.sha256.is_none() => return None,
        Recorded::Nothing => unrecorded,
        Recorded::Sha256(want) => match &r.sha256 {
            Some(got) if got.eq_ignore_ascii_case(want) => same,
            Some(_) => different,
            None => unreadable,
        },
        Recorded::Md5(want) => match md5_of(fs, &r.path, scope.max_hash_bytes) {
            Some(got) if got == *want => same,
            Some(_) => different,
            None => unreadable,
        },
    })
}

/// 파일의 MD5 — 상한(`max_hash_bytes`)을 넘거나 못 읽으면 `None`. 자른 내용으로 해시하지 않는다.
fn md5_of<P: FsRead>(fs: &P, path: &str, max: u64) -> Option<String> {
    let mut hasher = Md5::new();
    match fs.read_stream(path, max, &mut |chunk| hasher.update(chunk)) {
        Ok(true) => Some(
            hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_platform::read::{FsEntry, WalkResult};
    use remedy_platform::PlatformError;
    use remedy_sdk::catalog::Platform;
    use std::collections::BTreeMap;

    /// 경로 → 내용. 훑기는 그 경로 아래의 파일을 이름순으로 낸다.
    #[derive(Default)]
    struct FakeFs {
        files: BTreeMap<String, Vec<u8>>,
        locked: Vec<String>,
    }

    impl FsRead for FakeFs {
        fn walk(&self, root: &str, _limit: usize) -> Result<WalkResult, PlatformError> {
            let prefix = format!("{root}/");
            Ok(WalkResult {
                entries: self
                    .files
                    .iter()
                    .filter(|(p, _)| p.starts_with(&prefix))
                    .map(|(p, b)| FsEntry {
                        path: p.clone(),
                        is_dir: false,
                        is_reparse: false,
                        size: b.len() as u64,
                        mtime: String::new(),
                        ctime: None,
                        mode: None,
                    })
                    .collect(),
                ..WalkResult::default()
            })
        }
        fn read_file(&self, path: &str, max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
            match self.files.get(path) {
                Some(b) if b.len() as u64 > max => Ok(None),
                Some(b) => Ok(Some(b.clone())),
                None => Err(PlatformError::Refused(path.to_string())),
            }
        }
        fn look(&self, path: &str) -> Seen {
            if self.locked.iter().any(|p| p == path) {
                Seen::Locked
            } else if self
                .files
                .keys()
                .any(|p| p == path || p.starts_with(&format!("{path}/")))
            {
                Seen::Present
            } else {
                Seen::Absent
            }
        }
    }

    fn md5_hex(b: &[u8]) -> String {
        Md5::digest(b).iter().map(|x| format!("{x:02x}")).collect()
    }

    fn record(path: &str, sha256: Option<&str>) -> FileRecord {
        FileRecord {
            path: path.into(),
            size: 0,
            mtime: String::new(),
            ctime: None,
            sha256: sha256.map(Into::into),
            signature: None,
            version: None,
            zone: None,
            streams: Vec::new(),
            content_ref: None,
            package: String::new(),
            package_match: String::new(),
        }
    }

    fn scope() -> Scope {
        Scope::diagnostic(Vec::new(), Platform::Linux)
    }

    /// 데비안 기계 — `php8.2-cli` 가 `/usr/bin/php8.2` 를 깔았다.
    fn debian(binary: &[u8], recorded: &[u8]) -> FakeFs {
        let sums = format!(
            "{}  usr/bin/php8.2\n{}  usr/share/doc/php8.2-cli/copyright\n",
            md5_hex(recorded),
            md5_hex(b"doc")
        );
        let mut files = BTreeMap::new();
        files.insert("/usr/bin/php8.2".to_string(), binary.to_vec());
        files.insert(
            format!("{DPKG_INFO}/php8.2-cli:amd64.md5sums"),
            sums.into_bytes(),
        );
        files.insert(format!("{DPKG_INFO}/php8.2-cli:amd64.list"), b"x".to_vec());
        FakeFs {
            files,
            ..FakeFs::default()
        }
    }

    fn harvest(records: Vec<FileRecord>) -> Harvest<FileRecord> {
        Harvest {
            records,
            ..Harvest::default()
        }
    }

    /// 패키지가 깐 그대로면 `same`, 바꿨으면 `different` — 소유자 이름은 아키텍처를 뗀 패키지 이름이다.
    #[test]
    fn a_dpkg_file_is_matched_against_its_md5sums_line() {
        let fs = debian(b"php-binary", b"php-binary");
        let mut h = harvest(vec![
            record("/usr/bin/php8.2", Some("aa")),
            record("/opt/custom/bin/php", Some("bb")),
        ]);
        annotate(&fs, &scope(), &mut h);
        assert_eq!(
            (
                h.records[0].package.as_str(),
                h.records[0].package_match.as_str()
            ),
            ("php8.2-cli", "same")
        );
        // 패키지가 소유하지 않은 파일은 비운다.
        assert_eq!(
            (
                h.records[1].package.as_str(),
                h.records[1].package_match.as_str()
            ),
            ("", "")
        );
        assert_eq!((h.denied_dirs, h.truncated), (0, false));

        // **바꾼 실행 파일** — 패키지 DB 는 그대로인데 내용이 다르다(OL 8 실측의 모양).
        let fs = debian(b"replaced", b"php-binary");
        let mut h = harvest(vec![record("/usr/bin/php8.2", Some("aa"))]);
        annotate(&fs, &scope(), &mut h);
        assert_eq!(h.records[0].package_match, "different");
    }

    /// 상한을 넘어 끝까지 못 읽은 파일은 같다고도 다르다고도 하지 않는다.
    #[test]
    fn a_file_over_the_hash_limit_is_unreadable_not_same() {
        let fs = debian(b"php-binary", b"php-binary");
        let mut sc = scope();
        sc.max_hash_bytes = 3;
        let mut h = harvest(vec![record("/usr/bin/php8.2", None)]);
        annotate(&fs, &sc, &mut h);
        assert_eq!(h.records[0].package_match, "unreadable");
    }

    /// dpkg 가 없는 기계는 아무것도 적지 않고 거부도 아니다 — 열리지 않는 자리는 거부로 남긴다.
    #[test]
    fn a_missing_dpkg_is_normal_and_a_locked_one_is_denied() {
        let mut fs = FakeFs::default();
        fs.files.insert("/usr/bin/php".into(), b"x".to_vec());
        let mut h = harvest(vec![record("/usr/bin/php", Some("aa"))]);
        annotate(&fs, &scope(), &mut h);
        assert_eq!((h.records[0].package.as_str(), h.denied_dirs), ("", 0));

        let mut fs = debian(b"php-binary", b"php-binary");
        fs.locked.push(DPKG_INFO.to_string());
        let mut h = harvest(vec![record("/usr/bin/php8.2", Some("aa"))]);
        annotate(&fs, &scope(), &mut h);
        assert_eq!(h.denied_paths, vec![DPKG_INFO.to_string()]);
        assert_eq!(h.records[0].package, "");
    }

    #[test]
    fn md5sums_lines_keep_spaces_in_paths_and_skip_broken_lines() {
        let sum = "0123456789abcdef0123456789ABCDEF";
        let text = format!("{sum}  usr/bin/a b\nnot a line\n{sum} one-space\n{sum}  /usr/x\n");
        assert_eq!(
            md5sums(text.as_bytes()),
            vec![
                ("/usr/bin/a b".to_string(), sum.to_ascii_lowercase()),
                ("/usr/x".to_string(), sum.to_ascii_lowercase()),
            ]
        );
    }

    /// RPM 은 헤더가 적은 알고리즘으로 — SHA-256 은 수집기가 이미 잰 해시와, 다이제스트가 없는 정규 파일은
    /// `unrecorded`, 다이제스트가 없는 링크(해시 없음)는 적지 않는다.
    #[test]
    fn rpm_files_are_matched_by_the_recorded_algorithm() {
        let header = remedy_rpmdb::RpmHeader {
            name: "php-cli".into(),
            epoch: None,
            version: "7.2.24".into(),
            release: "1.module+el8".into(),
            arch: "x86_64".into(),
            vendor: "Oracle America".into(),
            sourcerpm: "php-7.2.24-1.module+el8.src.rpm".into(),
        };
        let db = remedy_rpmdb::Untrusted {
            packages: vec![remedy_rpmdb::Package {
                header,
                modularity_label: None,
                files: vec![
                    "/usr/bin/php".into(),
                    "/usr/bin/php-cgi".into(),
                    "/usr/bin/phar".into(),
                ],
                digests: Ok(remedy_rpmdb::FileDigests {
                    algorithm: DigestAlgorithm::Sha256,
                    digests: vec!["AA".into(), "cc".into(), String::new()],
                }),
            }],
            skipped: 0,
            limit: None,
        };
        let mut owners = HashMap::new();
        rpm_entries(&db, &mut owners);
        let fs = FakeFs::default();
        let check = |path: &str, sha: Option<&str>| {
            let o = &owners[path];
            assert_eq!(o.package, "php-cli");
            match_state(&fs, &scope(), &record(path, sha), &o.recorded)
        };
        assert_eq!(check("/usr/bin/php", Some("aa")), Some("same"));
        assert_eq!(check("/usr/bin/php-cgi", Some("dd")), Some("different"));
        // 링크 — 해시가 없고 기록에도 다이제스트가 없다.
        assert_eq!(check("/usr/bin/phar", None), None);
        // 정규 파일인데 기록이 비었다.
        assert_eq!(check("/usr/bin/phar", Some("ee")), Some("unrecorded"));
    }
}
