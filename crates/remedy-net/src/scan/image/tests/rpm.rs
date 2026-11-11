//! 스캐너 `rpm_test.go` · `rpm_digest_test.go` 와 `images_test.go` 의 `TestRPMSQLiteActiveRowsOnlyAndCorruption`.
//!
//! 스캐너는 SQLite · 헤더 판독기 안쪽(`sqliteRecord` · `parseRPMHeader`)을 불렀다. 여기서는 같은 바이트로 DB 를 지어
//! 이미지 쪽 입구(`rpm::parse`)로 본다 — 헤더 하나는 NDB 에 담는다.

use super::fixtures::*;
use crate::scan::image::node::{Links, Owner, Owners};
use crate::scan::image::packages::{file_problem, Record, DPKG_SOURCE};
use crate::scan::image::rootfs::RootFs;
use crate::scan::image::{php, rpm, Cx};
use crate::scan::model::{Product, Status, Target, TargetKind};
use crate::scan::rules::{Component, PackageManager};
use remedy_sdk::i18n::Lang;
use std::collections::{BTreeMap, BTreeSet};
use Status::{Clear, ReviewRequired as Review};

// ── 픽스처 — 스캐너 시험의 것과 같은 바이트 ─────────────────────────────

/// SQLite 가변 길이 정수(스캐너 `fixtureVarint` — 9바이트 꼴은 쓰지 않는다).
pub(super) fn varint(mut value: u64) -> Vec<u8> {
    if value < 128 {
        return vec![value as u8];
    }
    let mut groups = Vec::new();
    while value > 0 {
        groups.push((value & 127) as u8);
        value >>= 7;
    }
    groups.reverse();
    let last = groups.len() - 1;
    for g in &mut groups[..last] {
        *g |= 128;
    }
    groups
}

/// SQLite 기록의 열 하나.
pub(super) enum Col<'a> {
    Null,
    Text(&'a str),
    Blob(&'a [u8]),
    Int(u8),
}

/// SQLite 기록(스캐너 `fixtureRecord`).
pub(super) fn record(values: &[Col<'_>]) -> Vec<u8> {
    let (mut header, mut body) = (Vec::new(), Vec::new());
    for v in values {
        match v {
            Col::Null => header.push(0),
            Col::Text(s) => {
                header.extend(varint(s.len() as u64 * 2 + 13));
                body.extend_from_slice(s.as_bytes());
            }
            Col::Blob(b) => {
                header.extend(varint(b.len() as u64 * 2 + 12));
                body.extend_from_slice(b);
            }
            Col::Int(i) => {
                header.push(1);
                body.push(*i);
            }
        }
    }
    let mut length = header.len() + 1;
    while varint(length as u64).len() + header.len() != length {
        length = varint(length as u64).len() + header.len();
    }
    let mut out = varint(length as u64);
    out.extend(header);
    out.extend(body);
    out
}

/// RPM 헤더 꼬리표 하나 — 번호 · 형 · 개수 · 자료.
pub(super) type Tag = (u32, u32, u32, Vec<u8>);

/// 꼬리표들로 헤더 블롭을 짓는다 — 자료는 차례대로 잇는다.
pub(super) fn header_of(tags: &[Tag]) -> Vec<u8> {
    let mut h = vec![0u8; 8 + 16 * tags.len()];
    h[..4].copy_from_slice(&(tags.len() as u32).to_be_bytes());
    let mut data = Vec::new();
    for (i, (tag, kind, count, bytes)) in tags.iter().enumerate() {
        let e = 8 + 16 * i;
        for (k, v) in [*tag, *kind, data.len() as u32, *count]
            .into_iter()
            .enumerate()
        {
            h[e + 4 * k..e + 4 * k + 4].copy_from_slice(&v.to_be_bytes());
        }
        data.extend_from_slice(bytes);
    }
    h[4..8].copy_from_slice(&(data.len() as u32).to_be_bytes());
    h.extend(data);
    h
}

/// 스캐너 `fixtureRPMHeader` 의 꼬리표 — php-cli 8.3.1-1.fc41, `/usr/bin/php` 하나.
pub(super) fn base_tags() -> Vec<Tag> {
    vec![
        (1000, 6, 1, b"php-cli\0".to_vec()),
        (1001, 6, 1, b"8.3.1\0".to_vec()),
        (1002, 6, 1, b"1.fc41\0".to_vec()),
        (1116, 4, 1, vec![0, 0, 0, 0]),
        (1117, 8, 1, b"php\0".to_vec()),
        (1118, 8, 1, b"/usr/bin/\0".to_vec()),
    ]
}

/// 스캐너 `fixtureRPMHeader`.
pub(super) fn rpm_header() -> Vec<u8> {
    header_of(&base_tags())
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn le32(d: &mut [u8], at: usize, v: u32) {
    d[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// NDB 블롭 하나(머리 · 자료 · 꼬리).
fn ndb_blob(index: u32, blob: &[u8]) -> Vec<u8> {
    let blocks = (16 + blob.len() + 12).div_ceil(16);
    let mut b = vec![0u8; blocks * 16];
    b[..4].copy_from_slice(b"BlbS");
    le32(&mut b, 4, index);
    le32(&mut b, 8, 6);
    le32(&mut b, 12, blob.len() as u32);
    b[16..16 + blob.len()].copy_from_slice(blob);
    let n = b.len();
    let sum = adler32(&b[..n - 12]);
    le32(&mut b, n - 12, sum);
    le32(&mut b, n - 8, blob.len() as u32);
    b[n - 4..].copy_from_slice(b"BlbE");
    b
}

/// 스캐너 `rpmNDBMany` — 슬롯 쪽 하나 뒤에 블롭을 차례로.
pub(super) fn ndb_many(blobs: &[&[u8]]) -> Vec<u8> {
    let mut d = vec![0u8; 4096];
    d[..4].copy_from_slice(b"RpmP");
    le32(&mut d, 8, 7);
    le32(&mut d, 12, 1);
    le32(&mut d, 16, blobs.len() as u32 + 1);
    for pos in (32..4096).step_by(16) {
        d[pos..pos + 4].copy_from_slice(b"Slot");
    }
    for (i, blob) in blobs.iter().enumerate() {
        let b = ndb_blob(i as u32 + 1, blob);
        let (slot, block) = (32 + i * 16, (d.len() / 16) as u32);
        le32(&mut d, slot + 4, i as u32 + 1);
        le32(&mut d, slot + 8, block);
        le32(&mut d, slot + 12, (b.len() / 16) as u32);
        d.extend(b);
    }
    d
}

/// 스캐너 `rpmNDBFixture` — 블롭 하나(머리의 다음 번호가 2 인 것까지 같다).
pub(super) fn ndb_fixture(blob: &[u8]) -> Vec<u8> {
    ndb_many(&[blob])
}

const PAGE: usize = 4096;

/// SQLite 머리와 스키마 표(1쪽) — 2쪽은 비어 있다.
pub(super) fn sqlite_base() -> Vec<u8> {
    let mut d = vec![0u8; PAGE * 2];
    d[..16].copy_from_slice(b"SQLite format 3\0");
    d[16..18].copy_from_slice(&(PAGE as u16).to_be_bytes());
    (d[18], d[19], d[21], d[22], d[23]) = (1, 1, 64, 32, 32);
    d[56..60].copy_from_slice(&1u32.to_be_bytes());
    let schema = record(&[
        Col::Text("table"),
        Col::Text("Packages"),
        Col::Text("Packages"),
        Col::Int(2),
        Col::Text("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)"),
    ]);
    let cell = sqlite_cell(&mut d, &schema, 1);
    write_cells(&mut d, 1, 100, &[cell]);
    d
}

/// 셀 하나 — 쪽에 다 들지 않으면 넘침 쪽을 파일 끝에 잇는다(스캐너 `rpmSQLiteMany` 의 `cell`).
pub(super) fn sqlite_cell(d: &mut Vec<u8>, payload: &[u8], id: usize) -> Vec<u8> {
    let minimum = (PAGE - 12) * 32 / 255 - 23;
    let mut local = payload.len();
    if local > PAGE - 35 {
        local = minimum + (local - minimum) % (PAGE - 4);
        if local > PAGE - 35 {
            local = minimum;
        }
    }
    let mut out = varint(payload.len() as u64);
    out.extend(varint(id as u64));
    out.extend_from_slice(&payload[..local]);
    if local < payload.len() {
        let mut next = d.len() / PAGE + 1;
        out.extend_from_slice(&(next as u32).to_be_bytes());
        let mut remain = &payload[local..];
        while !remain.is_empty() {
            let mut p = vec![0u8; PAGE];
            let take = remain.len().min(PAGE - 4);
            if remain.len() > take {
                p[..4].copy_from_slice(&(next as u32 + 1).to_be_bytes());
            }
            p[4..4 + take].copy_from_slice(&remain[..take]);
            remain = &remain[take..];
            d.extend(p);
            next += 1;
        }
    }
    out
}

/// 잎 쪽 하나에 셀들을 놓는다(스캐너 `rpmSQLiteMany` 의 `write`).
pub(super) fn write_cells(d: &mut [u8], page: usize, offset: usize, cells: &[Vec<u8>]) {
    let base = (page - 1) * PAGE + offset;
    d[base] = 13;
    d[base + 3..base + 5].copy_from_slice(&(cells.len() as u16).to_be_bytes());
    let mut end = PAGE;
    for (i, c) in cells.iter().enumerate() {
        end -= c.len();
        assert!(
            end >= offset + 8 + cells.len() * 2,
            "시험 SQLite 셀 배치 오류"
        );
        d[base + 8 + i * 2..base + 10 + i * 2].copy_from_slice(&(end as u16).to_be_bytes());
        let at = (page - 1) * PAGE + end;
        d[at..at + c.len()].copy_from_slice(c);
    }
    d[base + 5..base + 7].copy_from_slice(&(end as u16).to_be_bytes());
}

/// 머리의 쪽 수를 파일 길이에 맞춘다.
pub(super) fn sqlite_finish(d: &mut [u8]) {
    let pages = (d.len() / PAGE) as u32;
    d[28..32].copy_from_slice(&pages.to_be_bytes());
}

/// 스캐너 `rpmSQLiteMany` — 기록마다 행 하나(번호 1부터). 기록은 [`record`] 로 지은 페이로드다.
pub(super) fn sqlite_many(records: &[Vec<u8>]) -> Vec<u8> {
    let mut d = sqlite_base();
    let cells: Vec<Vec<u8>> = records
        .iter()
        .enumerate()
        .map(|(i, r)| sqlite_cell(&mut d, r, i + 1))
        .collect();
    write_cells(&mut d, 2, 0, &cells);
    sqlite_finish(&mut d);
    d
}

/// 헤더 블롭 하나를 담은 행.
pub(super) fn row(blob: &[u8]) -> Vec<u8> {
    record(&[Col::Null, Col::Blob(blob)])
}

/// 스캐너 `fixtureSQLite` — 쪽 셋. 3쪽은 어디서도 가리키지 않는 옛 행이다.
fn sqlite_fixture() -> Vec<u8> {
    let mut data = vec![0u8; PAGE * 3];
    data[..16].copy_from_slice(b"SQLite format 3\0");
    data[16..18].copy_from_slice(&(PAGE as u16).to_be_bytes());
    (data[18], data[19], data[21], data[22], data[23]) = (1, 1, 64, 32, 32);
    data[28..32].copy_from_slice(&3u32.to_be_bytes());
    data[44..48].copy_from_slice(&4u32.to_be_bytes());
    data[56..60].copy_from_slice(&1u32.to_be_bytes());
    let schema = record(&[
        Col::Text("table"),
        Col::Text("Packages"),
        Col::Text("Packages"),
        Col::Int(2),
        Col::Text("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)"),
    ]);
    let header = rpm_header();
    for (page, payload) in [(1, schema), (2, row(&header)), (3, row(&header))] {
        let p = &mut data[(page - 1) * PAGE..page * PAGE];
        let off = if page == 1 { 100 } else { 0 };
        p[off] = 13;
        p[off + 3..off + 5].copy_from_slice(&1u16.to_be_bytes());
        let mut cell = varint(payload.len() as u64);
        cell.push(1);
        cell.extend(payload);
        let pos = PAGE - cell.len();
        p[pos..].copy_from_slice(&cell);
        p[off + 5..off + 7].copy_from_slice(&(pos as u16).to_be_bytes());
        p[off + 8..off + 10].copy_from_slice(&(pos as u16).to_be_bytes());
    }
    data
}

/// 이미지 쪽 입구로 DB 하나를 읽는다.
pub(super) fn parse(data: &[u8]) -> Result<(Vec<Record>, Option<String>), String> {
    let (b, rules) = (budget(), php_rules());
    parse_with(data, &b, &rules)
}

pub(super) fn parse_with(
    data: &[u8],
    b: &crate::scan::budget::Budget,
    rules: &crate::scan::rules::RuleSet,
) -> Result<(Vec<Record>, Option<String>), String> {
    let cx = Cx {
        budget: b,
        rules,
        lang: Lang::Ko,
        products: &[Product::Php],
    };
    rpm::parse(data, &cx)
}

fn find(data: &[u8], what: &[u8]) -> usize {
    data.windows(what.len()).position(|w| w == what).unwrap()
}

// ── rpm_test.go ─────────────────────────────────────────────────────────

/// `TestRPMNDBHeaderIntegration`
#[test]
fn rpm_ndb_header_integration() {
    let (packages, limit) = parse(&ndb_fixture(&rpm_header())).unwrap();
    assert_eq!((packages.len(), limit), (1, None));
    let p = &packages[0];
    assert_eq!(
        (p.name.as_str(), p.version.as_str()),
        ("php-cli", "8.3.1-1.fc41")
    );
    assert_eq!(p.files, ["usr/bin/php"]);
}

/// `TestSQLiteSerialLengthCheckedBeforeIntConversion` — 열 길이가 2^32 을 넘는 직렬 형의 행은 DB 오류다.
#[test]
fn sqlite_serial_length_checked_before_int_conversion() {
    for serial in [(1u64 << 33) + 14, (1u64 << 33) + 15] {
        let kind = varint(serial);
        let mut data = vec![kind.len() as u8 + 1];
        data.extend(&kind);
        data.push(b'x');
        assert!(parse(&sqlite_many(&[data])).is_err(), "serial={serial}");
    }
}

/// `TestRPMDatabasePreservesExistingSQLiteReader` — 취소는 판독 앞에서 본다.
#[test]
fn rpm_database_preserves_existing_sqlite_reader() {
    let (packages, _) = parse(&sqlite_fixture()).unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(
        (packages[0].name.as_str(), packages[0].version.as_str()),
        ("php-cli", "8.3.1-1.fc41")
    );
    let cancel = crate::scan::budget::Cancel::default();
    let b = crate::scan::budget::Budget::new(TargetKind::Image, cancel.clone(), Lang::Ko);
    cancel.set();
    assert!(parse_with(&sqlite_fixture(), &b, &php_rules()).is_err());
}

/// `TestRPMHeaderArchitectureVendorAndModule`
#[test]
fn rpm_header_architecture_vendor_and_module() {
    let mut tags = base_tags();
    tags.push((1022, 6, 1, b"i686\0".to_vec()));
    tags.push((1011, 6, 1, b"Red Hat, Inc.\0".to_vec()));
    tags.push((5096, 6, 1, b"php:7.4:123:abcd\0".to_vec()));
    let (packages, _) = parse(&ndb_fixture(&header_of(&tags))).unwrap();
    let p = &packages[0];
    assert_eq!(
        (
            p.architecture.as_str(),
            p.vendor.as_str(),
            p.module.as_str()
        ),
        ("i686", "Red Hat, Inc.", "php:7.4:123:abcd")
    );
    assert!(p.trusted);
}

/// `TestRPMRootDirectoryOwnership`
#[test]
fn rpm_root_directory_ownership() {
    for root_only in [false, true] {
        let mut blob = rpm_header();
        let dir = find(&blob, b"/usr/bin/\0");
        blob[dir + 1] = 0;
        if root_only {
            let base = find(&blob, b"php\0");
            blob[base] = 0;
        }
        let (packages, _) = parse(&ndb_fixture(&blob)).unwrap();
        let want: &[&str] = if root_only { &[] } else { &["php"] };
        assert_eq!(packages[0].files, want, "root_only={root_only}");
    }
    let mut blob = rpm_header();
    let base = find(&blob, b"php\0");
    blob[base..base + 4].copy_from_slice(b"..\0\0");
    assert!(
        parse(&ndb_fixture(&blob)).is_err(),
        "상위 폴더 이름을 받았다"
    );
}

/// `TestRPMSQLiteActiveRowsOnlyAndCorruption`(스캐너 `images_test.go`)
#[test]
fn rpm_sqlite_active_rows_only_and_corruption() {
    let mut data = sqlite_fixture();
    let (packages, _) = parse(&data).unwrap();
    assert_eq!(packages.len(), 1, "가리키지 않는 쪽의 옛 행을 읽었다");
    let p = &packages[0];
    assert_eq!(
        (p.name.as_str(), p.version.as_str()),
        ("php-cli", "8.3.1-1.fc41")
    );
    assert_eq!(p.files, ["usr/bin/php"]);
    // 2쪽을 자기 자신을 가리키는 안쪽 쪽으로 — B-tree 순환.
    data[PAGE] = 5;
    data[PAGE + 3..PAGE + 5].copy_from_slice(&0u16.to_be_bytes());
    data[PAGE + 8..PAGE + 12].copy_from_slice(&2u32.to_be_bytes());
    assert!(parse(&data).is_err(), "B-tree 순환을 받았다");
    let mut broken = rpm_header();
    broken[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        parse(&ndb_fixture(&broken)).is_err(),
        "꼬리표 수가 틀린 헤더를 받았다"
    );
}

// ── rpm_digest_test.go ──────────────────────────────────────────────────

/// 스캐너 `imageRPMDigestFixture` — 다이제스트 하나 · 알고리즘 · 아키텍처 · 공급사.
fn digest_header(digest: &str, algorithm: u32) -> Vec<u8> {
    let mut tags = base_tags();
    tags.push((1035, 8, 1, format!("{digest}\0").into_bytes()));
    tags.push((5011, 4, 1, algorithm.to_be_bytes().to_vec()));
    tags.push((1022, 6, 1, b"i686\0".to_vec()));
    tags.push((1011, 6, 1, b"Red Hat, Inc.\0".to_vec()));
    header_of(&tags)
}

/// `TestImageRPMManagerCannotUseUbuntuDPKGAdvisory`
#[test]
fn image_rpm_manager_cannot_use_ubuntu_dpkg_advisory() {
    let mut data = elf32(&[]);
    data[2048..2058].copy_from_slice(b"PHP 8.3.6\0");
    let mut fs = RootFs::default();
    put(&mut fs, "usr/bin/php8.3", data.clone());
    let (b, rules) = (budget(), php_rules());
    let cx = Cx {
        budget: &b,
        rules: &rules,
        lang: Lang::Ko,
        products: &[Product::Php],
    };
    for is_rpm in [false, true] {
        let p = Record {
            name: "php8.3-cli".into(),
            version: FIXED.into(),
            source: if is_rpm {
                "/var/lib/rpm/Packages.db"
            } else {
                DPKG_SOURCE
            }
            .into(),
            rpm: is_rpm,
            trusted: true,
            files: vec!["usr/bin/php8.3".into()],
            checksums: Some(BTreeMap::from([("usr/bin/php8.3".into(), md5_hex(&data))])),
            checksum_algorithm: "md5",
            vendor: "Third-party RPM".into(),
            architecture: "i686".into(),
            ..Record::default()
        };
        let mut t = Target::new(
            "manager-fixture",
            TargetKind::Image,
            "manager-fixture",
            &[Product::Php],
        );
        php::inspect(&fs, &mut t, &cx, &[p], ("ubuntu", "24.04"));
        let want = if is_rpm { Review } else { Clear };
        assert_eq!(t.findings.len(), 1, "rpm={is_rpm}: {:#?}", t.findings);
        assert_eq!(
            t.findings[0].status, want,
            "rpm={is_rpm}: {:#?}",
            t.findings[0]
        );
        assert_eq!(t.findings[0].vendor.as_deref(), Some("ubuntu"));
    }
}

/// `TestImageSharedDecoderPreservesRPMManager`
#[test]
fn image_shared_decoder_preserves_rpm_manager() {
    let mut fs = RootFs::default();
    put(&mut fs, "usr/bin/node", elf32(&["libbrotlidec.so.1"]));
    put(&mut fs, "usr/lib32/libbrotlidec.so.1", elf32(&[]));
    let mut owners = Owners::default();
    let owner = Owner {
        name: "libbrotli1".into(),
        version: "1.2.0-1ubuntu0.24.04.1".into(),
        source: "/var/lib/rpm/Packages".into(),
        trusted: true,
        manager: PackageManager::Rpm,
        architecture: "i686".into(),
        vendor: "Third-party RPM".into(),
        ..Owner::default()
    };
    owners
        .by_file
        .insert("usr/lib32/libbrotlidec.so.1".into(), owner);
    let links = Links {
        fs: &fs,
        owners: &owners,
        os: ("ubuntu", "24.04"),
        lang: Lang::Ko,
    };
    let (mode, deps, complete) = links.deps("usr/bin/node", &mut BTreeSet::new(), 0);
    let rules = node_rules(None);
    let mut c = Component::new(Product::Node);
    (c.dependency_mode, c.dependencies, c.dependencies_complete) = (mode, deps, complete);
    assert_eq!(c.dependencies.len(), 1, "{:#?}", c.dependencies);
    assert_eq!(c.dependencies[0].package_manager, PackageManager::Rpm);
    assert_eq!(rules.evaluate(&c, Lang::Ko).status, Review);
    c.dependencies[0].package_manager = PackageManager::Dpkg;
    assert_eq!(
        rules.evaluate(&c, Lang::Ko).status,
        Clear,
        "dpkg 디코더의 비교가 달라졌다"
    );
}

/// `TestImageRPMDigestMatchesFinalFileBytes`
#[test]
fn image_rpm_digest_matches_final_file_bytes() {
    let mut fs = RootFs::default();
    put(&mut fs, "usr/bin/php", elf32(&[]));
    let entry = fs.entries["usr/bin/php"].clone();
    for algorithm in [1u32, 8] {
        let digest = if algorithm == 8 {
            &entry.sha256
        } else {
            &entry.md5
        };
        let (packages, _) = parse(&ndb_fixture(&digest_header(digest, algorithm))).unwrap();
        let p = &packages[0];
        assert!(p.trusted && p.checksum_error.is_none(), "{p:#?}");
        assert_eq!(file_problem(p, "usr/bin/php", &entry, Lang::Ko), None);
        let mut changed = entry.clone();
        (changed.md5, changed.sha256) = ("0".repeat(32), "0".repeat(64));
        assert!(
            file_problem(p, "usr/bin/php", &changed, Lang::Ko).is_some(),
            "바뀐 파일을 받았다"
        );
        assert!(
            file_problem(p, "usr/bin/missing", &entry, Lang::Ko).is_some(),
            "소유하지 않은 경로를 받았다"
        );
    }
    let (packages, _) = parse(&ndb_fixture(&digest_header(&"a".repeat(40), 2))).unwrap();
    assert!(
        file_problem(&packages[0], "usr/bin/php", &entry, Lang::Ko).is_some(),
        "지원하지 않는 해시가 파일 검증을 지났다"
    );
}
