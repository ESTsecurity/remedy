//! 파일 하나짜리 아카이브의 시험 — 스캐너 `client_test.go` · `windows_container_test.go` 의 아카이브 시험과, Go
//! `archive/tar` 의 판독과 같은 답을 내는지 보는 경계.

use super::*;
use crate::scan::container::tests::support::{
    header_block, make_archive, set_checksum, Entry, Format,
};

const STATUS: &str = "/var/lib/dpkg/status";

fn extract(data: &[u8], requested: &str, size: i64) -> Result<Vec<u8>, Failure> {
    extract_regular(data, requested, size)
}

/// 원본 `TestArchiveRejectsUnexpectedEntriesAndMetadata`.
#[test]
fn archive_rejects_unexpected_entries_and_metadata() {
    let valid = make_archive(&[Entry::xs("status", 3)]);
    assert_eq!(extract(&valid, STATUS, 3).unwrap(), b"xxx");
    // Docker 가 남기는 소수 시각 PAX 는 받는다.
    let pax = make_archive(&[Entry::xs("status", 3).pax("mtime", "1.000000123")]);
    assert_eq!(extract(&pax, STATUS, 3).unwrap(), b"xxx");
    let cases = [
        vec![Entry::xs("../status", 3)],
        vec![Entry::xs("/status", 3)],
        vec![Entry::special("status", b'5', "")],
        vec![Entry::special("status", b'2', "/secret")],
        vec![Entry::special("status", b'1', "secret")],
        vec![Entry::xs("status", 3), Entry::xs("extra", 1)],
        vec![Entry::xs("status", 3).pax("comment", "hidden metadata")],
        vec![Entry::xs("status", 3).gnu()],
    ];
    for (i, entries) in cases.iter().enumerate() {
        assert!(
            extract(&make_archive(entries), STATUS, 3).is_err(),
            "받으면 안 되는 경우 {i}"
        );
    }
    assert!(extract(&valid, STATUS, 4).is_err(), "크기가 다른데 받았다");
    let mut trailing = valid.clone();
    trailing.extend_from_slice(b"hidden data");
    assert_eq!(
        extract(&trailing, STATUS, 3),
        Err(Failure::File(FileFailure::ArchiveAfterEnd))
    );
    assert!(extract(&valid, "/", 3).is_err(), "루트 아카이브를 받았다");
}

/// 원본 `TestWindowsArchivesRetainSingleRegularFileGate` 의 아카이브 부분.
#[test]
fn windows_archives_retain_the_single_regular_file_gate() {
    let name = r"C:\php\php.exe";
    let valid = make_archive(&[Entry::xs("PHP.EXE", 3)]);
    assert_eq!(extract(&valid, name, 3).unwrap(), b"xxx");
    for entries in [
        vec![Entry::xs(r"php\php.exe", 3)],
        vec![Entry::xs(r"C:\php\php.exe", 3)],
        vec![Entry::special("php.exe", b'2', r"C:\secret")],
        vec![Entry::special("php.exe", b'5', "")],
        vec![Entry::xs("php.exe", 3), Entry::xs("extra", 1)],
    ] {
        assert!(
            extract(&make_archive(&entries), name, 3).is_err(),
            "{entries:?}"
        );
    }
    let mut after = valid.clone();
    after.push(b'x');
    assert!(extract(&after, name, 3).is_err(), "끝 뒤의 데이터를 받았다");
}

/// Go 판독기의 너그러운 끝 — 끝 표시가 없거나 하나여도, 채움이 잘려도 끝이다. 0 블록 뒤의 다른 블록은 틀린 것이다.
#[test]
fn the_end_of_the_archive_follows_go() {
    let full = make_archive(&[Entry::xs("status", 3)]);
    let body = &full[..1024];
    for cut in [&full[..1024 + 512], body, &full[..512 + 3]] {
        assert_eq!(
            extract(cut, STATUS, 3).unwrap(),
            b"xxx",
            "{} 바이트",
            cut.len()
        );
    }
    let mut lone_zero = body.to_vec();
    lone_zero.extend_from_slice(&[0u8; 512]);
    lone_zero.extend_from_slice(&header_block("extra", 0o644, 0, b'0', "", Format::Ustar));
    assert!(extract(&lone_zero, STATUS, 3).is_err());
    // 내용 중간에서 끝나면 잘린 것이다.
    assert_eq!(
        extract(&full[..512 + 2], STATUS, 3),
        Err(Failure::File(FileFailure::ArchiveFormat))
    );
    // 머리 블록 중간에서 끝나도.
    assert!(extract(&full[..100], STATUS, 3).is_err());
    assert!(extract(&[], STATUS, 0).is_err(), "빈 아카이브를 받았다");
}

#[test]
fn a_header_must_carry_a_valid_checksum_and_numbers() {
    let mut bad_sum = make_archive(&[Entry::xs("status", 3)]);
    bad_sum[148] ^= 1;
    assert!(extract(&bad_sum, STATUS, 3).is_err());
    let mut bad_mode = header_block("status", 0o644, 3, b'0', "", Format::Ustar);
    bad_mode[100..108].copy_from_slice(b"00006x4\0");
    set_checksum(&mut bad_mode);
    let mut data = bad_mode.to_vec();
    data.extend_from_slice(b"xxx");
    data.resize(512 * 2, 0);
    data.extend_from_slice(&[0u8; 1024]);
    assert!(extract(&data, STATUS, 3).is_err(), "틀린 8진수 칸을 받았다");
    // 256진수 크기 칸도 읽는다.
    let mut binary = header_block("status", 0o644, 0, b'0', "", Format::Ustar);
    binary[124..136].copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
    set_checksum(&mut binary);
    let mut data = binary.to_vec();
    data.extend_from_slice(b"xxx");
    data.resize(512 * 2, 0);
    data.extend_from_slice(&[0u8; 1024]);
    assert_eq!(extract(&data, STATUS, 3).unwrap(), b"xxx");
}

#[test]
fn pax_records_may_only_carry_times() {
    for (key, value, ok) in [
        ("mtime", "1700000000", true),
        ("atime", "-12.5", true),
        ("ctime", "1.000000001", true),
        ("mtime", "1.", false),
        ("mtime", "+1", false),
        ("mtime", "99999999999999999999", false),
        ("path", "status", false),
        ("size", "3", false),
        ("SCHILY.xattr.user.x", "1", false),
        ("GNU.sparse.major", "1", false),
    ] {
        let data = make_archive(&[Entry::xs("status", 3).pax(key, value)]);
        assert_eq!(extract(&data, STATUS, 3).is_ok(), ok, "{key}={value}");
    }
    // 값은 64바이트까지 — 읽히는 수여도 그보다 길면 받지 않는다.
    for (len, ok) in [(64, true), (65, false)] {
        let data = make_archive(&[Entry::xs("status", 3).pax("mtime", &"0".repeat(len))]);
        assert_eq!(extract(&data, STATUS, 3).is_ok(), ok, "{len}");
    }
}

#[test]
fn gnu_long_names_and_global_headers_are_followed_then_refused() {
    // GNU 긴 이름 뒤의 USTAR 항목은 그 이름이 된다 — 이름이 맞으면 Go 처럼 받는다.
    let mut long = header_block("././@LongLink", 0, 7, b'L', "", Format::Gnu).to_vec();
    long.extend_from_slice(b"status\0");
    long.resize(1024, 0);
    long.extend_from_slice(&make_archive(&[Entry::xs("other", 3)]));
    assert_eq!(extract(&long, STATUS, 3).unwrap(), b"xxx");
    // 전역 머리는 항목으로 나오고, 일반 파일이 아니라 거절된다.
    let records = crate::scan::container::tests::support::pax_record("mtime", "1");
    let mut global = header_block(
        "GlobalHead.0.0",
        0,
        records.len() as u64,
        b'g',
        "",
        Format::Ustar,
    )
    .to_vec();
    global.extend_from_slice(records.as_bytes());
    global.resize(1024, 0);
    global.extend_from_slice(&make_archive(&[Entry::xs("status", 3)]));
    assert_eq!(
        extract(&global, STATUS, 3),
        Err(Failure::File(FileFailure::ArchiveMember))
    );
}

#[test]
fn old_and_non_ascii_headers_are_not_gnu() {
    // 마법 글자가 없는 V7 머리도 Go 는 읽는다.
    let mut v7 = header_block("status", 0o644, 3, b'0', "", Format::Ustar);
    v7[257..265].fill(0);
    set_checksum(&mut v7);
    let mut data = v7.to_vec();
    data.extend_from_slice(b"xxx");
    data.resize(1024, 0);
    data.extend_from_slice(&[0u8; 1024]);
    assert_eq!(extract(&data, STATUS, 3).unwrap(), b"xxx");
    let names = make_archive(&[Entry::xs("상태", 3)]);
    assert_eq!(extract(&names, "/var/lib/상태", 3).unwrap(), b"xxx");
}
