//! 믿지 못할 RPM DB — 이미지 · 컨테이너에서 꺼낸 파일 (2026-11-10).
//!
//! # 같은 판독기, 다른 상한
//!
//! 판독기는 [`crate::headers`] 와 같다. 다른 것은 상한이고, 값과 닿았을 때 말하는 방식은 사내 runtime-scanner 를
//! 따랐다(`internal/rpmdb/limits.go` 와 그 시험).
//!
//! | 상한 | 값 | 지키는 자리 | 닿으면 |
//! |---|---|---|---|
//! | DB 파일 하나 | 64 MiB | [`read_untrusted`] 첫 줄 | DB 전체가 오류 |
//! | 기록 하나(SQLite 페이로드 · BDB 값 · NDB 블롭) | 16 MiB | 형식마다의 판독기 | DB 전체가 오류 |
//! | 기록 수 | 100,000 | 형식마다의 판독기 | DB 전체가 오류 |
//! | 꼬리표 하나의 항목 | 100,000 | 헤더 판독(`header::files`) | DB 전체가 오류 |
//! | 복사한 블롭의 합 | 64 MiB | 형식마다의 판독기 — 복사하기 전에 | 그 앞의 패키지 + [`Untrusted::limit`] |
//! | 헤더에서 꺼낸 문자열 · 경로 · 다이제스트 | 16 MiB · 100,000 항목 | 헤더 판독 — 만들기 전에 | 그 앞의 패키지 + [`Untrusted::limit`] |
//!
//! 형식이 틀린 DB(틀 · 경로의 모양 · 같은 꼬리표가 두 번 …)도 전체가 오류다. 다이제스트만 틀린 패키지는 그 패키지의
//! [`Package::digests`] 에만 오류가 붙는다.
//!
//! # 복사한 합의 상한이 막는 것
//!
//! 정상 DB 는 거기 닿지 않는다 — 블롭은 파일 안의 서로 다른 자리에 있고 파일이 쪽 머리만큼 더 크다(실측 다섯: 블롭
//! 합이 파일의 39~99.8%). 닿는 것은 슬롯 · 넘침 사슬 · 셀 여럿이 한 자리를 가리킬 때다 — 판독기는 그때마다
//! 복사하므로 1 MiB 파일이 수백 MiB 를 낼 수 있다. 사내 runtime-scanner 는 그런 공유를 형식 오류로 거부하고(쪽 ·
//! 블롭 영역의 중복), 여기서는 상한이 멈춘다.
//!
//! # 실물에서 남는 몫 (2026-11-10)
//!
//! 컨테이너에서 꺼낸 DB 다섯(Rocky 9 · Oracle Linux 8 · `python36` 모듈을 더한 AlmaLinux 8 · CentOS 7 · openSUSE Leap
//! 15.6)을 이 입구로 읽어 같은 컨테이너의 `rpm -qa --qf` 와 견줬다 — 패키지 · 경로(차례까지) · 다이제스트 · 알고리즘 ·
//! 모듈 꼬리표가 모두 같았고 오류 · 상한은 0 이었다. 쓴 몫은 헤더에서 꺼낸 정보가 16 MiB 의 10~42% · 100,000 항목의
//! 6~32%, 복사한 블롭이 64 MiB 의 6~18% 였다. 그래서 **파일이 그 세 배쯤(10만 개 안팎)인 이미지는 파생 정보 상한에
//! 닿을 수 있고**, DB 파일은 패키지 하나에 42~129 KB 였으니 **패키지가 오백 개를 넘는 BDB 이미지는 64 MiB 에 걸릴 수
//! 있다** — 둘 다 넉넉한 값이 아니다.

use crate::header::{package, Derived, DERIVED};
use crate::{read_blobs, FileDigests, Limits, RpmDbError, RpmHeader};

/// DB 파일 하나.
const MAX_DATABASE: u64 = 64 * 1024 * 1024;

/// 믿지 못할 입력에서 판독기가 지키는 상한.
const UNTRUSTED: Limits = Limits {
    record: 16 * 1024 * 1024,
    records: 100_000,
    copied: 64 * 1024 * 1024,
};

/// 믿지 못할 DB 하나를 읽은 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Untrusted {
    /// 끝까지 읽은 패키지 — DB 에 적힌 차례.
    pub packages: Vec<Package>,
    /// 헤더로 읽히지 않은 블롭 수 — rpm 이 BDB 에 함께 두는 다음 헤더 번호 같은 값.
    pub skipped: usize,
    /// 상한(복사한 블롭의 합 · 헤더에서 꺼낸 정보)에 닿아 멈췄으면 그 까닭. 그때 `packages` 는 그 앞까지이고 DB 의
    /// 전부가 아니다 — 부르는 쪽은 *다 보지 못했다* 로 말해야 한다.
    pub limit: Option<RpmDbError>,
}

/// 패키지 하나 — 이미지 점검이 쓰는 꼬리표 전부.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// 이름 · epoch · 판 · 개정 · 아키텍처 · 공급사 · 원본 패키지 — 수집기가 읽는 그것([`crate::header::parse`]).
    pub header: RpmHeader,
    /// 모듈 꼬리표(`이름:스트림:판:문맥`). 모듈에 속하지 않으면 `None`.
    pub modularity_label: Option<String>,
    /// 소유한 파일의 경로 — 헤더 차례이고 `/` 로 시작하며 적힌 그대로다(`..` · 겹친 `/` 를 풀지 않는다 — 정리는
    /// 부르는 쪽의 일이다). 뿌리를 소유하면 `/` 가 그대로 나온다.
    pub files: Vec<String>,
    /// 파일마다의 다이제스트. `Ok` 면 `files` 와 같은 차례 · 같은 길이다. 알고리즘이 MD5 · SHA-256 밖이거나 수 ·
    /// 꼴이 틀리면 이 패키지만 `Err` 다 — 경로는 그대로 믿을 수 있다.
    pub digests: Result<FileDigests, RpmDbError>,
}

/// 믿지 못할 RPM DB 하나를 읽는다 — 이미지 · 컨테이너에서 꺼낸 파일(상한과 그 자리는 모듈 머리).
///
/// `Err` 면 DB 전체를 믿지 않는다. `Ok` 여도 [`Untrusted::limit`] 가 있으면 다 읽지 못한 것이다. 파일을 여는 것 · DB
/// 자리를 고르는 것 · WAL(`-wal` 이 비어 있지 않으면 아직 DB 에 반영되지 않은 바뀜이 있다)을 보는 것은 부르는 쪽의
/// 일이다.
pub fn read_untrusted(bytes: &[u8]) -> Result<Untrusted, RpmDbError> {
    if bytes.len() as u64 > MAX_DATABASE {
        return Err(RpmDbError::Limit("RPM DB 파일이 상한(64 MiB)을 넘었다"));
    }
    let (blobs, copied) = read_blobs(bytes, UNTRUSTED)?;
    let mut budget = Derived::new();
    let mut out = Untrusted {
        packages: Vec::new(),
        skipped: 0,
        limit: None,
    };
    // 블롭은 읽는 대로 놓아준다 — 복사한 블롭과 꺼낸 정보가 함께 쌓이지 않게.
    for blob in blobs {
        match package(&blob, &mut budget) {
            Ok(Some(p)) => out.packages.push(p),
            Ok(None) => out.skipped += 1,
            Err(e) if e == DERIVED => {
                out.limit = Some(e);
                return Ok(out);
            }
            Err(e) => return Err(e),
        }
    }
    out.limit = copied;
    Ok(out)
}

/// **이 기계의** RPM DB 에서 패키지마다 소유한 파일과 다이제스트 — 본체 수집기의 패키지 파일 대조가 쓴다(코어
/// 1.7.0 · 목표 remedy_PHP스캐너통합 결정 24).
///
/// 판독기는 같다. 블롭은 이 기계의 DB 입구([`crate::blobs`] — 파일 상한은 부르는 쪽의 DB 상한)로 읽고, 꺼낸 정보는
/// 호스트 예산(`Derived::host`)에서 덜어 낸다. **`keep` 이 고른 경로만 남긴다** — 대조할 것은 룰이 모은 파일
/// 몇 개라, 나머지 경로 · 다이제스트는 패키지마다 읽는 대로 놓아준다(예산은 만든 것을 다 센다).
///
/// 반환 꼴은 [`read_untrusted`] 와 같다 — [`Untrusted::limit`] 가 있으면 그 앞의 패키지까지만 읽은 것이다.
pub fn read_host(bytes: &[u8], keep: impl Fn(&str) -> bool) -> Result<Untrusted, RpmDbError> {
    let blobs = crate::blobs(bytes)?;
    let mut budget = Derived::host();
    let mut out = Untrusted {
        packages: Vec::new(),
        skipped: 0,
        limit: None,
    };
    for blob in blobs {
        match package(&blob, &mut budget) {
            Ok(Some(mut p)) => {
                let kept: Vec<bool> = p.files.iter().map(|f| keep(f)).collect();
                if let Ok(d) = &mut p.digests {
                    let mut i = 0;
                    d.digests.retain(|_| {
                        i += 1;
                        kept[i - 1]
                    });
                }
                let mut i = 0;
                p.files.retain(|_| {
                    i += 1;
                    kept[i - 1]
                });
                out.packages.push(p);
            }
            Ok(None) => out.skipped += 1,
            Err(e) if e == DERIVED => {
                out.limit = Some(e);
                return Ok(out);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bdb::tests::{bdb, sample as bdb_sample, Val};
    use crate::header::tests::{build, digests, files_in, label, pkg, s, MD5_HEX, SHA256_HEX};
    use crate::ndb::tests::{ndb, sample as ndb_sample, share, SLOTS};
    use crate::sqlite::tests::{record, sqlite_db, Rec};
    use crate::{DigestAlgorithm, COPIED};

    const MIB: usize = 1024 * 1024;
    const TINY: &[u8] = include_bytes!("testdata/tiny-rpmdb.sqlite");

    /// `/usr/bin/php` 하나를 가진 패키지 — SHA-256 다이제스트.
    fn php() -> Vec<u8> {
        let mut tags = files_in("/usr/bin/", &["php"]);
        tags.extend(digests(&[SHA256_HEX], Some(8)));
        pkg(&tags)
    }

    /// 헤더 블롭의 자료 끝에 0 을 덧대 `len` 바이트로 늘린다 — 꼬리표는 그대로이고 자료 길이만 커진다.
    fn padded(blob: &[u8], len: usize) -> Vec<u8> {
        let il = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        let mut b = blob.to_vec();
        b.resize(len, 0);
        let dl = (len - 8 - il * 16) as u32;
        b[4..8].copy_from_slice(&dl.to_be_bytes());
        b
    }

    fn names(u: &Untrusted) -> Vec<&str> {
        u.packages.iter().map(|p| p.header.name.as_str()).collect()
    }

    /// 디렉터리 `dir` 의 파일 `n` 개 — 이름은 `f` 와 0 으로 채운 번호(`width` 자리), 다이제스트는 비었다.
    fn many(dir: &str, n: usize, width: usize) -> Vec<u8> {
        let bases: Vec<String> = (0..n).map(|i| format!("f{i:0width$}")).collect();
        let bases: Vec<&str> = bases.iter().map(String::as_str).collect();
        let mut tags = files_in(dir, &bases);
        tags.extend(digests(&vec![""; n], None));
        pkg(&tags)
    }

    #[test]
    fn valid_databases_read_as_the_collector_reads_them() {
        // 세 형식의 시험 DB — 믿는 쪽([`crate::headers`])과 헤더 · 건너뛴 수가 같고 상한에 닿지 않는다.
        for db in [
            TINY.to_vec(),
            bdb_sample(true),
            bdb_sample(false),
            ndb_sample(),
        ] {
            let (headers, skipped) = crate::headers(&db).unwrap();
            let got = read_untrusted(&db).unwrap();
            let read: Vec<&RpmHeader> = got.packages.iter().map(|p| &p.header).collect();
            assert_eq!(read, headers.iter().collect::<Vec<_>>());
            assert_eq!((got.skipped, got.limit), (skipped, None));
        }
    }

    #[test]
    fn each_package_carries_its_files_digests_and_module_label() {
        let mut tags = files_in("/usr/bin/", &["php", "phar"]);
        tags.extend(digests(&[SHA256_HEX, ""], Some(8)));
        tags.push(label("php:8.2:8100020240407123453:17efdbc7"));
        let got = read_untrusted(&ndb(&[Some((1, pkg(&tags)))])).unwrap();
        assert_eq!((got.packages.len(), got.skipped, got.limit), (1, 0, None));
        let p = &got.packages[0];
        assert_eq!(
            (p.header.name.as_str(), p.modularity_label.as_deref()),
            ("php-cli", Some("php:8.2:8100020240407123453:17efdbc7"))
        );
        assert_eq!(p.files, ["/usr/bin/php", "/usr/bin/phar"]);
        assert_eq!(
            p.digests,
            Ok(FileDigests {
                algorithm: DigestAlgorithm::Sha256,
                digests: vec![SHA256_HEX.to_string(), String::new()],
            })
        );
    }

    /// 이 기계의 DB 입구는 **고른 경로만** 남기고, 남긴 경로와 다이제스트의 차례를 함께 지킨다 — 이미지 입구와 같은
    /// 판독기다(코어 1.7.0).
    #[test]
    fn the_host_reader_keeps_only_the_paths_asked_for() {
        let mut tags = files_in("/usr/bin/", &["php", "phar"]);
        tags.extend(digests(&[SHA256_HEX, ""], Some(8)));
        let db = ndb(&[Some((1, pkg(&tags)))]);
        let got = read_host(&db, |p| p == "/usr/bin/phar").unwrap();
        assert_eq!((got.packages.len(), got.skipped, got.limit), (1, 0, None));
        let p = &got.packages[0];
        assert_eq!(p.files, ["/usr/bin/phar"]);
        assert_eq!(
            p.digests,
            Ok(FileDigests {
                algorithm: DigestAlgorithm::Sha256,
                digests: vec![String::new()],
            })
        );
        // 아무것도 고르지 않으면 패키지는 남고 파일은 빈다 — 헤더는 이미지 입구와 같다.
        let none = read_host(&db, |_| false).unwrap();
        assert_eq!(none.packages[0].files, Vec::<String>::new());
        assert_eq!(
            none.packages[0].header,
            read_untrusted(&db).unwrap().packages[0].header
        );
        // 세 형식의 시험 DB 모두 이미지 입구와 같은 헤더 · 경로를 낸다.
        for db in [TINY.to_vec(), bdb_sample(true), ndb_sample()] {
            let host = read_host(&db, |_| true).unwrap();
            let image = read_untrusted(&db).unwrap();
            assert_eq!(host.packages, image.packages);
        }
    }

    #[test]
    fn a_record_of_exactly_16_mib_is_read_and_one_byte_more_fails_the_database() {
        // 사내 runtime-scanner 의 같은 시험을 세 형식으로 — 기록 하나는 16 MiB 까지이고, 넘으면 DB 전체가 오류다. 믿는
        // 쪽([`crate::headers`])의 상한은 그대로 64 MiB 라 같은 파일을 읽는다.
        let check = |ok: Vec<u8>, bad: Vec<u8>, err: &'static str| {
            let got = read_untrusted(&ok).unwrap();
            assert_eq!(
                (names(&got), got.packages[0].files.len(), got.limit.clone()),
                (vec!["php-cli"], 1, None)
            );
            assert_eq!(read_untrusted(&bad), Err(RpmDbError::Limit(err)));
            assert_eq!(crate::headers(&bad).unwrap().0.len(), 1);
        };
        let (exact, over) = (padded(&php(), 16 * MIB), padded(&php(), 16 * MIB + 1));
        check(
            ndb(&[Some((1, exact.clone()))]),
            ndb(&[Some((1, over.clone()))]),
            "NDB 블롭 하나가 상한을 넘었다",
        );
        check(
            bdb(true, &[Val::Offpage(exact)]),
            bdb(true, &[Val::Offpage(over)]),
            "BDB 값 하나가 상한을 넘었다",
        );
        // SQLite 는 기록(페이로드)이 블롭보다 머리 6바이트만큼 크다.
        let (exact, over) = (padded(&php(), 16 * MIB - 6), padded(&php(), 16 * MIB - 5));
        assert_eq!(record(&exact).len(), 16 * MIB);
        check(
            sqlite_db(&[Rec::Own(exact)]),
            sqlite_db(&[Rec::Own(over)]),
            "SQLite 기록 하나가 상한을 넘었다",
        );
    }

    #[test]
    fn the_copy_guard_stops_shared_slots_chains_and_cells_and_keeps_what_came_before() {
        // 2026-11-10 에 잰 모양을 키웠다 — 한 블롭을 여럿이 가리키면 판독기는 그때마다 복사한다. 64 MiB 에 닿기 전에
        // 멈추고 그 앞의 패키지와 까닭을 돌려준다. 파일은 수 MiB 이고, 복사한 것은 64 MiB 를 넘지 않는다.
        let copied = |got: &Untrusted, each: usize| got.packages.len() * each;
        // NDB — 슬롯 64개면 꼭 64 MiB 라 다 읽고, 그보다 많으면 64개에서 멈춘다.
        let mut f = ndb(&[Some((1, padded(&php(), MIB)))]);
        share(&mut f, 0, 1..64);
        let got = read_untrusted(&f).unwrap();
        assert_eq!((got.packages.len(), got.limit), (64, None));
        share(&mut f, 0, 64..SLOTS);
        assert!(f.len() < 2 * MIB);
        let got = read_untrusted(&f).unwrap();
        assert_eq!((got.packages.len(), got.limit.clone()), (64, Some(COPIED)));
        assert!(copied(&got, MIB) <= 64 * MIB);
        // BDB — 항목 23개가 3 MiB 사슬 하나를 가리킨다(69 MiB) → 21개(63 MiB)에서 멈춘다.
        let mut vals = vec![Val::Offpage(padded(&php(), 3 * MIB))];
        vals.extend((1..23).map(|_| Val::Same(0)));
        let f = bdb(true, &vals);
        assert!(f.len() < 4 * MIB);
        let got = read_untrusted(&f).unwrap();
        assert_eq!((got.packages.len(), got.limit.clone()), (21, Some(COPIED)));
        assert!(copied(&got, 3 * MIB) <= 64 * MIB);
        // SQLite — 셀 8개가 9 MiB 사슬 하나를 가리킨다 → 7개에서 멈춘다(스키마 표의 기록도 센다).
        let mut recs = vec![Rec::Own(padded(&php(), 9 * MIB))];
        recs.extend((1..8).map(|_| Rec::Same(0)));
        let f = sqlite_db(&recs);
        assert!(f.len() < 10 * MIB);
        let got = read_untrusted(&f).unwrap();
        assert_eq!((got.packages.len(), got.limit.clone()), (7, Some(COPIED)));
        assert!(copied(&got, 9 * MIB + 6) <= 64 * MIB);
    }

    #[test]
    fn a_valid_database_near_the_limits_is_read_whole() {
        // 사내 runtime-scanner 의 같은 시험 — 8 MiB 기록 다섯(40 MiB)은 복사한 합의 상한 안이라 다 읽는다.
        let eight = padded(&php(), 8 * MIB);
        let f = bdb(true, &[(); 5].map(|_| Val::Offpage(eight.clone())));
        assert!(f.len() < 64 * MIB);
        let got = read_untrusted(&f).unwrap();
        assert_eq!((got.packages.len(), got.limit), (5, None));
    }

    #[test]
    fn the_derived_budget_keeps_the_packages_before_it_in_every_format() {
        // 사내 runtime-scanner 의 같은 시험 — 파일 5만 개가 900글자 디렉터리 하나를 가리키는 헤더는 블롭이 2 MiB
        // 남짓인데 꺼낼 경로는 45 MB 다. 앞의 온전한 패키지는 남고 상한을 함께 말한다.
        let a = "a".repeat(32);
        let bases: Vec<String> = (0..50_000).map(|i| format!("f{i:06}")).collect();
        let bases: Vec<&str> = bases.iter().map(String::as_str).collect();
        let mut tags = files_in(&format!("/{}/", "d".repeat(900)), &bases);
        tags.extend(digests(&vec![a.as_str(); 50_000], None));
        let (first, wide) = (php(), pkg(&tags));
        for db in [
            ndb(&[Some((1, first.clone())), Some((2, wide.clone()))]),
            bdb(
                true,
                &[Val::Offpage(first.clone()), Val::Offpage(wide.clone())],
            ),
            sqlite_db(&[Rec::Own(first.clone()), Rec::Own(wide.clone())]),
        ] {
            let got = read_untrusted(&db).unwrap();
            assert_eq!(
                (got.packages.len(), got.packages[0].files.len(), got.limit),
                (1, 1, Some(DERIVED))
            );
        }
    }

    #[test]
    fn the_derived_budget_is_shared_by_all_packages_of_one_database() {
        // 하나씩은 들어가는 패키지 둘 — 경로 8,000개 × 1,000바이트(9.3 MB 를 센다). 둘째에서 바이트가 바닥난다.
        let dir = format!("/{}/", "d".repeat(993));
        let half = many(&dir, 8_000, 4);
        assert!(read_untrusted(&ndb(&[Some((1, half.clone()))]))
            .unwrap()
            .limit
            .is_none());
        let got = read_untrusted(&ndb(&[Some((1, half.clone())), Some((2, half))])).unwrap();
        assert_eq!((got.packages.len(), got.limit), (1, Some(DERIVED)));
        // 짧은 경로 40,000개씩 셋 — 셋째는 항목(100,000)이 모자라 배열을 읽기 전에 멈춘다.
        let short = many("/", 40_000, 5);
        let three = ndb(&[1, 2, 3].map(|i| Some((i, short.clone()))));
        let got = read_untrusted(&three).unwrap();
        assert_eq!((got.packages.len(), got.limit), (2, Some(DERIVED)));
    }

    #[test]
    fn strings_sharing_one_long_value_are_counted_before_they_are_made() {
        // 사내 runtime-scanner 의 같은 시험 — 꼬리표 다섯이 3.5 MiB 문자열 하나를 가리키면 블롭은 3.5 MiB 인데 만들
        // 문자열은 17.5 MiB 다. 만들기 전에 예산에 걸린다. 꼬리표는 이름 · 판 · 개정 · 공급사 · 아키텍처 · 원본 패키지.
        let mut data = s("evil");
        let at = data.len() as u32;
        data.extend_from_slice(&s(&"7".repeat(3 * MIB + MIB / 2)));
        let tags = [
            (1000u32, 0u32),
            (1001, at),
            (1002, at),
            (1011, at),
            (1022, at),
            (1044, at),
        ];
        let mut blob = Vec::new();
        blob.extend_from_slice(&(tags.len() as u32).to_be_bytes());
        blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
        for (tag, off) in tags {
            for word in [tag, 6, off, 1] {
                blob.extend_from_slice(&word.to_be_bytes());
            }
        }
        blob.extend_from_slice(&data);
        let db = ndb(&[Some((1, php())), Some((2, blob))]);
        let got = read_untrusted(&db).unwrap();
        assert_eq!(
            (names(&got), got.limit.clone()),
            (vec!["php-cli"], Some(DERIVED))
        );
        // 믿는 쪽은 다섯을 다 만든다.
        assert_eq!(
            crate::headers(&db).unwrap().0[1].vendor.len(),
            3 * MIB + MIB / 2
        );
    }

    #[test]
    fn a_broken_record_fails_the_whole_database_even_after_good_ones() {
        let read = |second: Vec<u8>| read_untrusted(&ndb(&[Some((1, php())), Some((2, second))]));
        // 기록 하나가 16 MiB 를 넘는다.
        assert_eq!(
            read(vec![0; 16 * MIB + 1]),
            Err(RpmDbError::Limit("NDB 블롭 하나가 상한을 넘었다"))
        );
        // 같은 꼬리표가 두 번(이름) — 믿는 쪽은 뒤의 것을 쓴다.
        let twice = build(&[
            (1000, 6, s("a")),
            (1000, 6, s("b")),
            (1001, 6, s("1")),
            (1002, 6, s("1")),
        ]);
        assert_eq!(
            read(twice),
            Err(RpmDbError::Format("같은 꼬리표가 두 번 나온다"))
        );
        // 경로의 모양이 틀렸다.
        assert_eq!(
            read(pkg(&files_in("/usr/bin", &["php"]))),
            Err(RpmDbError::Format(
                "디렉터리 이름이 `/` 로 시작하고 끝나지 않는다"
            ))
        );
        // 파일 이름 꼬리표가 100,001개라고 주장한다(파일 이름 · 디렉터리 · 디렉터리 번호).
        let lying = pkg(&[
            (1117, 8, 100_001, s("php")),
            (1118, 8, 1, s("/usr/bin/")),
            (1116, 4, 1, 0u32.to_be_bytes().to_vec()),
        ]);
        assert_eq!(
            read(lying),
            Err(RpmDbError::Limit("꼬리표 하나의 항목 수가 상한을 넘었다"))
        );
        // 다이제스트만 틀리면 그 패키지에만 붙는다 — SHA-256 이라면서 MD5 길이다.
        let mut tags = files_in("/usr/bin/", &["php"]);
        tags.extend(digests(&[MD5_HEX], Some(8)));
        let got = read(pkg(&tags)).unwrap();
        assert_eq!((got.packages.len(), got.limit), (2, None));
        assert!(got.packages[0].digests.is_ok());
        assert_eq!(got.packages[1].files, ["/usr/bin/php"]);
        assert_eq!(
            got.packages[1].digests,
            Err(RpmDbError::Format(
                "파일 다이제스트가 그 알고리즘의 16진 꼴이 아니다"
            ))
        );
    }

    #[test]
    fn a_database_file_over_64_mib_is_refused_before_it_is_read() {
        let mut f = vec![0u8; 64 * MIB + 1];
        f[..4].copy_from_slice(b"RpmP");
        assert_eq!(
            read_untrusted(&f),
            Err(RpmDbError::Limit("RPM DB 파일이 상한(64 MiB)을 넘었다"))
        );
        // 꼭 64 MiB 는 읽으러 들어간다 — 이 파일은 NDB 머리가 틀렸다.
        f.pop();
        assert_eq!(
            read_untrusted(&f),
            Err(RpmDbError::Format("NDB 슬롯 쪽 수가 틀렸다"))
        );
    }

    #[test]
    fn cut_or_flipped_databases_never_panic_or_change_what_they_say() {
        // 잘린 파일은 오류이거나 온전한 파일과 같은 답이다 — 바이트를 바꾼 것은 패닉만 없으면 된다.
        let mut tags = files_in("/usr/bin/", &["php", "phar"]);
        tags.extend(digests(&[SHA256_HEX, ""], Some(8)));
        tags.push(label("php:8.2"));
        for db in [
            ndb(&[Some((1, pkg(&tags))), None, Some((7, php()))]),
            bdb(
                true,
                &[Val::Inline(vec![5, 0, 0, 0]), Val::Offpage(pkg(&tags))],
            ),
            TINY.to_vec(),
        ] {
            let full = read_untrusted(&db).unwrap();
            for cut in 0..db.len() {
                if let Ok(got) = read_untrusted(&db[..cut]) {
                    assert_eq!(got, full, "{cut} 바이트로 자른 파일이 다른 답을 냈다");
                }
            }
            let mut b = db.clone();
            for i in 0..b.len() {
                let keep = b[i];
                for v in [0x00, 0xFF, keep ^ 0x80] {
                    b[i] = v;
                    let _ = read_untrusted(&b);
                }
                b[i] = keep;
            }
        }
    }
}
