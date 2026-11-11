//! 스캐너 `rpm_limits_test.go` — RPM DB 판독 한도와, 한도에 닿아도 판정이 가려지지 않는 것.
//!
//! 옮기지 않은 시험 둘 — 판독기(`remedy-rpmdb`)의 셈이 스캐너와 다르다.
//! - `TestSQLiteStringsAndRowsShareRPMDerivedBudget`: 스캐너는 SQLite 의 행 · 열 문자열도 헤더에서 꺼낸 정보의 예산에서
//!   셌다. 판독기는 SQLite 기록을 복사한 블롭의 합(64 MiB)으로만 센다.
//! - `TestRPMOverlappingScalarFieldsChargeConcatenationBeforeAllocation`: 스캐너는 판 · 개정을 이은 버전 글자(`판-개정`)도
//!   만들기 전에 셌다. 판독기는 꺼낸 문자열을 하나씩만 센다 — 7 MiB 문자열 하나를 판 · 개정이 함께 가리키면 14 MiB 로
//!   16 MiB 안이라 읽고, 버전 글자는 이 크레이트가 만든다.
//!
//! 스캐너의 `rpmLimitCancelContext`(열 번째 확인에서 취소)도 옮기지 않았다 — 이 입구는 판독을 시작하기 전에만 취소를
//! 본다. 그 자리는 취소한 예산으로 본다.

use super::fixtures::*;
use super::rpm::{
    header_of, ndb_fixture, ndb_many, parse, parse_with, record, row, rpm_header, sqlite_base,
    sqlite_cell, sqlite_finish, sqlite_many, varint, write_cells, Col,
};
use crate::scan::budget::{Budget, Cancel};
use crate::scan::model::{Product, Status, TargetKind};
use remedy_sdk::i18n::Lang;
use Packing::Raw;
use Status::{Clear, ReviewRequired as Review, Vulnerable};

/// 스캐너 `wideRPMHeader` — 파일 `count` 개가 900글자 폴더 하나를 가리킨다(꺼낼 경로가 블롭보다 훨씬 크다).
fn wide_header(count: usize) -> Vec<u8> {
    let bases: Vec<u8> = (0..count)
        .flat_map(|i| format!("f{i:06}\0").into_bytes())
        .collect();
    let digests = format!("{}\0", "a".repeat(32)).repeat(count).into_bytes();
    let n = count as u32;
    header_of(&[
        (1000, 6, 1, b"php-cli\0".to_vec()),
        (1001, 6, 1, b"8.3.1\0".to_vec()),
        (1002, 6, 1, b"1.fc41\0".to_vec()),
        (1011, 6, 1, b"Fedora Project\0".to_vec()),
        (1022, 6, 1, b"i686\0".to_vec()),
        (1116, 4, n, vec![0; count * 4]),
        (1117, 8, n, bases),
        (1118, 8, 1, format!("/{}/\0", "d".repeat(900)).into_bytes()),
        (1035, 8, n, digests),
    ])
}

/// 헤더 블롭의 자료 끝을 0 으로 늘려 `len` 바이트로.
fn padded(len: usize) -> Vec<u8> {
    let mut blob = rpm_header();
    let index = 8 + u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize * 16;
    blob.resize(len, 0);
    let data = (len - index) as u32;
    blob[4..8].copy_from_slice(&data.to_be_bytes());
    blob
}

/// `TestRPMDerivedLimitsKeepPriorCompleteRecordsAcrossBackends`
#[test]
fn rpm_derived_limits_keep_prior_complete_records_across_backends() {
    let (first, wide) = (rpm_header(), wide_header(50_000));
    for (name, db) in [
        ("NDB", ndb_many(&[&first, &wide])),
        ("SQLite", sqlite_many(&[row(&first), row(&wide)])),
    ] {
        let (packages, limit) = parse(&db).unwrap();
        assert!(limit.is_some_and(|l| l.contains("꺼낸 정보")), "{name}");
        assert_eq!(packages.len(), 1, "{name}");
        assert_eq!(
            (packages[0].name.as_str(), packages[0].files.len()),
            ("php-cli", 1),
            "{name}"
        );
    }
}

/// `TestRPM16MiBRecordsAcrossNDBAndSQLite`
#[test]
fn rpm_16_mib_records_across_ndb_and_sqlite() {
    for sqlite in [false, true] {
        for size in [16 << 20, (16 << 20) + 1] {
            // SQLite 는 두 열의 머리(6바이트)까지 기록 하나로 센다.
            let blob = padded(if sqlite { size - 6 } else { size });
            let data = if sqlite {
                assert_eq!(row(&blob).len(), size, "SQLite 경계 시험의 본문 크기");
                sqlite_many(&[row(&blob)])
            } else {
                ndb_fixture(&blob)
            };
            if size > 16 << 20 {
                assert!(
                    parse(&data).is_err(),
                    "sqlite={sqlite}: 16 MiB 를 넘는 기록을 받았다"
                );
                continue;
            }
            let (packages, limit) = parse(&data).unwrap();
            assert_eq!((packages.len(), limit), (1, None), "sqlite={sqlite}");
            assert_eq!(
                (packages[0].name.as_str(), packages[0].files.len()),
                ("php-cli", 1)
            );
            let cancel = Cancel::default();
            let b = Budget::new(TargetKind::Image, cancel.clone(), Lang::Ko);
            cancel.set();
            assert!(
                parse_with(&data, &b, &php_rules()).is_err(),
                "sqlite={sqlite}: 취소한 읽기를 받았다"
            );
        }
    }
}

/// `TestSQLiteMaterializedLimitPreservesPriorValidatedRows` — 스캐너는 판독기의 복사 예산을 미리 채워 두고 보았다.
/// 여기서는 셀 여덟이 9 MiB 넘침 사슬 하나를 함께 가리키는 DB 로 같은 상한(복사한 블롭의 합 64 MiB)에 닿게 한다 —
/// 그 앞의 온전한 행은 남고 *다 보지 못했다* 가 붙는다.
#[test]
fn sqlite_materialized_limit_preserves_prior_validated_rows() {
    // 넘침 셀의 앞부분이 최소(489바이트)가 되는 크기 — 셀 여덟이 한 쪽에 든다.
    let blob = padded(483 + 2306 * 4092);
    let payload = row(&blob);
    let mut d = sqlite_base();
    let first = sqlite_cell(&mut d, &payload, 1);
    let lead = varint(payload.len() as u64).len();
    let cells: Vec<Vec<u8>> = (1..=8u8)
        .map(|i| {
            let mut c = first.clone();
            c[lead] = i;
            c
        })
        .collect();
    write_cells(&mut d, 2, 0, &cells);
    sqlite_finish(&mut d);
    assert!(d.len() < 10 << 20);
    let (packages, limit) = parse(&d).unwrap();
    assert!(
        limit.is_some_and(|l| l.contains("복사한")),
        "복사 한도를 말하지 않았다"
    );
    assert!(
        !packages.is_empty() && packages.len() < 8,
        "{}",
        packages.len()
    );
    assert!(packages.len() * blob.len() <= 64 << 20);
    assert!(packages
        .iter()
        .all(|p| p.name == "php-cli" && p.files.len() == 1));
}

/// `TestRPMFailureCannotMakePatchedNodeImageClear`
#[test]
fn rpm_failure_cannot_make_patched_node_image_clear() {
    let node = elf(&[]);
    let rules = node_rules(Some(&node));
    for failure in ["none", "record-size", "checksum", "metadata"] {
        let header = rpm_header();
        let db = match failure {
            "record-size" => ndb_many(&[&header, &vec![0; (16 << 20) + 1]]),
            "checksum" => {
                let mut db = ndb_many(&[&header]);
                db[4096 + 16] ^= 1;
                db
            }
            "metadata" => ndb_many(&[&header, &wide_header(50_000)]),
            _ => ndb_many(&[&header]),
        };
        let entries = [
            reg("etc/os-release", "ID=fedora\nVERSION_ID=41\n"),
            reg("var/lib/rpm/Packages.db", db),
            reg("usr/local/bin/node", &node),
        ];
        let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
        let targets = run(dir.path(), &[Product::Node], &rules);
        let ok = failure == "none";
        assert_eq!(targets.len(), 1, "{failure}");
        let t = &targets[0];
        assert_eq!(
            (t.status, t.complete),
            (if ok { Clear } else { Review }, ok),
            "{failure}: {t:#?}"
        );
        assert_eq!(t.findings.len(), 1, "{failure}: {:#?}", t.findings);
        assert_eq!(t.findings[0].status, Clear, "{failure}");
        assert_eq!(t.findings[0].path.as_deref(), Some("/usr/local/bin/node"));
    }
}

/// `TestRPMLimitCannotHideVerifiedVulnerability`
#[test]
fn rpm_limit_cannot_hide_verified_vulnerability() {
    let (mut old, mut fixed) = (elf32(&[]), elf32(&[]));
    old[2048..2059].copy_from_slice(b"PHP 8.3.35\0");
    fixed[2048..2059].copy_from_slice(b"PHP 8.3.36\0");
    let db = ndb_many(&[&rpm_header(), &wide_header(50_000)]);
    let entries = [
        reg("etc/os-release", "ID=fedora\nVERSION_ID=41\n"),
        reg("var/lib/rpm/Packages.db", db),
        reg("usr/local/bin/php", &old),
    ];
    let (dir, _) = oci(&[tar(&entries)], Raw, &[]);
    let targets = run(dir.path(), &[Product::Php], &php_hash_rules(&old, &fixed));
    assert_eq!(targets.len(), 1);
    assert_eq!(
        (targets[0].status, targets[0].complete),
        (Vulnerable, false),
        "{:#?}",
        targets[0]
    );
}

/// `TestSQLiteColumnCountIsBoundedBeforeBuildingRows` — 머리가 4096 바이트(열 4094개)인 행은 DB 오류다.
#[test]
fn sqlite_column_count_is_bounded_before_building_rows() {
    let mut data = vec![0u8; 4096];
    let head = varint(data.len() as u64);
    data[..head.len()].copy_from_slice(&head);
    assert!(parse(&sqlite_many(&[data])).is_err());
    // 열이 둘뿐인 정상 행은 읽는다 — 위의 오류가 행 꼴 때문임을 확인한다.
    let ok = record(&[Col::Null, Col::Blob(&rpm_header())]);
    assert_eq!(parse(&sqlite_many(&[ok])).unwrap().0.len(), 1);
}
