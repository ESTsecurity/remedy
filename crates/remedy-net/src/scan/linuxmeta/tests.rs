//! 스캐너 `internal/linuxmeta` 의 시험을 옮겼다. 원래 이름은 각 시험 위에 적었다.

use super::*;

fn release(file: &str, text: &str) -> Option<(String, String)> {
    parse_release(file, text.as_bytes())
}

/// 스캐너 `TestKnownReleaseRecords` 의 표.
#[test]
fn known_release_records_are_read() {
    let cases = [
        (
            "/etc/os-release",
            "ID=ubuntu\nVERSION_ID=\"14.04\"\n",
            "ubuntu",
            "14.04",
        ),
        (
            "/usr/lib/os-release",
            "ID=debian\nVERSION_ID='7'\n",
            "debian",
            "7",
        ),
        (
            "/etc/redhat-release",
            "Red Hat Enterprise Linux Server release 6.10 (Santiago)\n",
            "rhel",
            "6.10",
        ),
        (
            "/etc/redhat-release",
            "CentOS release 5.11 (Final)\n",
            "centos",
            "5.11",
        ),
        (
            "/etc/centos-release",
            "CentOS Linux release 7.9.2009 (Core)\n",
            "centos",
            "7.9.2009",
        ),
        (
            "/etc/oracle-release",
            "Oracle Linux Server release 6.10\n",
            "ol",
            "6.10",
        ),
        ("/etc/debian_version", "6.0.10\n", "debian", "6.0.10"),
        (
            "/etc/lsb-release",
            "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=12.04\nDISTRIB_CODENAME=precise\n",
            "ubuntu",
            "12.04",
        ),
        (
            "/etc/SuSE-release",
            "SUSE Linux Enterprise Server 11 SP4 (i586)\nVERSION = 11\nPATCHLEVEL = 4\n",
            "sles",
            "11.4",
        ),
        (
            "/etc/SuSE-release",
            "openSUSE 11.4 (i586)\nVERSION = 11.4\nCODENAME = Celadon\n",
            "opensuse",
            "11.4",
        ),
    ];
    for (file, text, id, version) in cases {
        assert_eq!(
            release(file, text),
            Some((id.to_string(), version.to_string())),
            "{file}: {text:?}"
        );
    }
}

/// 스캐너 `TestUnknownReleaseRecordsDoNotGuessDistribution` 의 표.
#[test]
fn unclear_records_do_not_guess_a_distribution() {
    let long = "#".repeat(65537);
    let cases = [
        ("/etc/centos-release", "Oracle Linux Server release 7.9"),
        ("/etc/oracle-release", "CentOS release 6.10 (Final)"),
        ("/etc/redhat-release", "PHP 5.3.3 (Red Hat 6.10)"),
        ("/etc/debian_version", "bookworm/sid"),
        (
            "/etc/lsb-release",
            "DISTRIB_ID=Custom\nDISTRIB_RELEASE=6.10\n",
        ),
        (
            "/etc/os-release",
            "ID=ubuntu\nID=debian\nVERSION_ID=14.04\n",
        ),
        ("/etc/os-release", "ID=ubuntu\nVERSION_ID=$(touch marker)\n"),
        ("/etc/os-release", "ID=ubuntu\nVERSION_ID=14.04\x00"),
        (
            "/etc/redhat-release",
            "CentOS release 6.10 (Final)\nexec /bin/sh",
        ),
        (
            "/etc/SuSE-release",
            "SUSE Linux Enterprise Server 11 SP4 (i586)\nVERSION = 12\nPATCHLEVEL = 4\n",
        ),
        ("/tmp/os-release", "ID=ubuntu\nVERSION_ID=14.04\n"),
        ("/etc/os-release", long.as_str()),
    ];
    for (file, text) in cases {
        assert_eq!(release(file, text), None, "{file}: 불명확한 기록을 받았다");
    }
}

#[test]
fn a_line_without_an_assignment_spoils_the_whole_file() {
    let good = "ID=ubuntu\nVERSION_ID=14.04\n";
    assert!(release("/etc/os-release", good).is_some());
    for extra in ["stray words", "=value", "ID", "ID=again"] {
        let text = format!("{good}{extra}\n");
        assert_eq!(release("/etc/os-release", &text), None, "{extra:?}");
    }
    // 빈 줄 · 주석 · 양 끝 공백은 기록이 아니다.
    let padded = "\n  # 주석\n\tID = ubuntu \r\n\n VERSION_ID = 14.04\r\n";
    assert_eq!(
        release("/etc/os-release", padded),
        Some(("ubuntu".to_string(), "14.04".to_string()))
    );
}

#[test]
fn quoted_values_must_be_one_whole_literal() {
    let read = |value: &str| {
        release(
            "/etc/os-release",
            &format!("ID=debian\nVERSION_ID={value}\n"),
        )
    };
    let version = |v: &str| Some(("debian".to_string(), v.to_string()));
    assert_eq!(read("\"12\""), version("12"));
    assert_eq!(read("'12'"), version("12"));
    // 큰따옴표 안의 이스케이프는 Go 문자열 리터럴의 것이다.
    assert_eq!(read("\"\\x31\\062\\u002e4\""), version("12.4"));
    assert_eq!(read(r#""1\U00000032""#), version("12"));
    for bad in [
        "\"12",
        "\"12\" extra",
        "\"12\"\"",
        r#""1\q2""#,
        r#""1\'2""#,
        r#""1\x3""#,
        r#""\400""#,
        r#""\ud800""#,
        "'12",
        "'1'2'",
        "'",
        "\"",
    ] {
        assert_eq!(read(bad), None, "{bad:?}");
    }
    // 다른 키의 따옴표가 어긋나도 파일 전체를 버린다.
    let other = "ID=debian\nVERSION_ID=12\nPRETTY_NAME=\"Debian\n";
    assert_eq!(release("/etc/os-release", other), None);
}

#[test]
fn the_path_decides_which_form_is_accepted() {
    let os = "ID=ubuntu\nVERSION_ID=14.04\n";
    let ubuntu = Some(("ubuntu".to_string(), "14.04".to_string()));
    assert_eq!(release("/etc//os-release", os), ubuntu);
    assert_eq!(release("/etc/./os-release/", os), ubuntu);
    assert_eq!(release("/usr/../etc/os-release", os), ubuntu);
    assert_eq!(release("etc/os-release", os), None, "상대 경로");
    assert_eq!(release("", os), None);
    assert_eq!(
        release("/etc/os-release", "CentOS release 6.10 (Final)"),
        None
    );
    assert_eq!(release("/etc/lsb-release", os), None);
    assert_eq!(RELEASE_FILES.len(), 8);
    assert_eq!(RELEASE_FILES[0], "/etc/os-release");
    assert_eq!(RELEASE_FILES[7], "/etc/SuSE-release");
    for file in RELEASE_FILES {
        assert_eq!(clean(file).as_deref(), Some(file));
    }
}

#[test]
fn legacy_forms_keep_their_own_rules() {
    let pair = |id: &str, v: &str| Some((id.to_string(), v.to_string()));
    assert_eq!(
        release("/etc/redhat-release", "Red Hat Linux release 9 (Shrike)"),
        pair("redhat", "9")
    );
    assert_eq!(
        release("/etc/redhat-release", "Oracle Linux Server release 7.9"),
        pair("ol", "7.9")
    );
    assert_eq!(
        release("/etc/redhat-release", "CentOS Stream release 9"),
        pair("centos", "9")
    );
    assert_eq!(
        release("/etc/lsb-release", "DISTRIB_ID=DEBIAN\nDISTRIB_RELEASE=7\n"),
        pair("debian", "7")
    );
    assert_eq!(
        release(
            "/etc/lsb-release",
            "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=jammy\n"
        ),
        None
    );
    // SuSE: 패치 수준 0 과 빈 값은 붙이지 않고, 첫 줄의 SP 와 어긋나면 버린다.
    let sles = |tail: &str| {
        release(
            "/etc/SuSE-release",
            &format!("SUSE Linux Enterprise Server 11 SP4 (x86_64)\r\nVERSION = 11\r\n{tail}"),
        )
    };
    assert_eq!(sles("PATCHLEVEL = 4\r\n"), pair("sles", "11.4"));
    assert_eq!(sles("PATCHLEVEL = 3\n"), None);
    assert_eq!(sles("PATCHLEVEL = 4.1\n"), None);
    assert_eq!(sles("PATCHLEVEL = 0\n"), pair("sles", "11"));
    assert_eq!(sles(""), pair("sles", "11"));
    assert_eq!(
        release(
            "/etc/SuSE-release",
            "SUSE Linux Enterprise Desktop 12 (x86_64)\nVERSION = 12\nPATCHLEVEL = 2\n"
        ),
        pair("sled", "12.2")
    );
    assert_eq!(release("/etc/SuSE-release", "openSUSE 11.4 (i586)"), None);
}

#[test]
fn package_architecture_names_have_one_shape() {
    for good in [
        "amd64", "x86_64", "aarch64", "noarch", "all", "armv7hl", "i386",
    ] {
        assert!(valid_package_architecture(good), "{good}");
    }
    let long = "a".repeat(65);
    for bad in [
        "",
        "-amd64",
        "_x",
        "AMD64",
        "amd 64",
        "amd64\n",
        "arm/v7",
        long.as_str(),
    ] {
        assert!(!valid_package_architecture(bad), "{bad:?}");
    }
    assert!(valid_package_architecture(&"a".repeat(64)));
}

/// 32비트 리틀 엔디언 i386 머리.
fn i386_header() -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    h[18..20].copy_from_slice(&3u16.to_le_bytes());
    h
}

/// 스캐너 `TestELFIdentitySeparatesWordSizeMachineAndByteOrder`.
#[test]
fn elf_identity_separates_word_size_machine_and_byte_order() {
    let header = i386_header();
    let i386 = ElfIdentity::parse(&header);
    assert!(i386.valid());
    assert!(i386.compatible(&ElfIdentity::parse(&header)));
    let mutations: [fn(&mut [u8]); 4] = [
        |b| b[4] = 2,
        |b| b[18..20].copy_from_slice(&40u16.to_le_bytes()),
        |b| {
            b[5] = 2;
            b[18..20].copy_from_slice(&3u16.to_be_bytes());
        },
        |b| b[18..20].copy_from_slice(&0u16.to_le_bytes()),
    ];
    for (i, mutate) in mutations.iter().enumerate() {
        let mut other = header.clone();
        mutate(&mut other);
        assert!(
            !i386.compatible(&ElfIdentity::parse(&other)),
            "다른 ELF ABI 를 이었다: {i}"
        );
    }
    assert!(!ElfIdentity::parse(&header[..20]).valid(), "잘린 머리");
}

/// 스캐너 `TestELFCallingConventions` 의 표.
#[test]
fn elf_calling_conventions_are_compared_per_machine() {
    let cases: [(&str, u16, u32, u32, bool); 12] = [
        ("arm-hard-soft", 40, 0x0500_0400, 0x0500_0200, false),
        ("arm-implied-soft", 40, 0x0500_0200, 0x0500_0000, true),
        ("arm-eabi-version", 40, 0x0400_0200, 0x0500_0200, false),
        ("arm-invalid-float", 40, 0x0500_0600, 0x0500_0600, false),
        ("ppc64-elfv1-v2", 21, 1, 2, false),
        ("mips-o32-o64", 8, 0x7000_1007, 0x7000_2007, false),
        ("mips-pic-compatible", 8, 0x7000_1007, 0x7000_1001, true),
        ("riscv-float", 243, 4, 2, false),
        ("riscv-compressed-compatible", 243, 4, 5, true),
        ("riscv-register-abi", 243, 4, 12, false),
        ("riscv-ilp32", 243, 4, 36, false),
        ("unknown-flags", 258, 0x43, 0x41, false),
    ];
    for (name, machine, a, b, want) in cases {
        let a = ElfIdentity {
            class: 2,
            endianness: 1,
            machine,
            flags: a,
        };
        let b = ElfIdentity { flags: b, ..a };
        assert_eq!(a.compatible(&b), want, "{name}");
        assert_eq!(b.compatible(&a), want, "{name} (뒤집어서)");
    }
}

/// 스캐너 `TestELFHeaderFlagsAndIdentity`.
#[test]
fn elf_header_fields_are_read_in_both_sizes_and_orders() {
    for class in [1u8, 2] {
        for endianness in [1u8, 2] {
            let mut h = vec![0u8; 64];
            h[..4].copy_from_slice(b"\x7fELF");
            (h[4], h[5], h[6]) = (class, endianness, 1);
            let at = if class == 2 { 48 } else { 36 };
            if endianness == 1 {
                h[18..20].copy_from_slice(&40u16.to_le_bytes());
                h[at..at + 4].copy_from_slice(&0x0500_0400u32.to_le_bytes());
            } else {
                h[18..20].copy_from_slice(&40u16.to_be_bytes());
                h[at..at + 4].copy_from_slice(&0x0500_0400u32.to_be_bytes());
            }
            let id = ElfIdentity::parse(&h);
            let want = ElfIdentity {
                class,
                endianness,
                machine: 40,
                flags: 0x0500_0400,
            };
            assert_eq!(id, want);
            assert!(id.compatible(&id));
            let other = ElfIdentity {
                endianness: 3 - endianness,
                ..id
            };
            assert!(!id.compatible(&other), "다른 바이트 순서");
            assert!(!id.compatible(&ElfIdentity::default()), "읽지 못한 파일");
        }
    }
    assert!(!ElfIdentity::parse(&[0u8; 20]).valid(), "잘린 ELF");
}

#[test]
fn a_header_that_is_not_elf_reads_as_nothing() {
    let good = i386_header();
    assert_eq!(ElfIdentity::parse(&good[..52]), ElfIdentity::parse(&good));
    assert_eq!(ElfIdentity::parse(&good[..51]), ElfIdentity::default());
    let spoil = |at: usize, value: u8| {
        let mut h = good.clone();
        h[at] = value;
        ElfIdentity::parse(&h)
    };
    assert_eq!(spoil(0, 0x7e), ElfIdentity::default(), "매직");
    assert_eq!(spoil(4, 3), ElfIdentity::default(), "모르는 워드 크기");
    assert_eq!(spoil(5, 0), ElfIdentity::default(), "모르는 바이트 순서");
    assert_eq!(spoil(6, 2), ElfIdentity::default(), "모르는 ELF 버전");
    // 64비트 머리는 64바이트가 다 있어야 한다.
    let mut wide = good.clone();
    wide[4] = 2;
    assert!(ElfIdentity::parse(&wide).valid());
    assert_eq!(ElfIdentity::parse(&wide[..63]), ElfIdentity::default());
}

#[test]
fn text_helpers_follow_the_scanner_rules() {
    // 공백은 유니코드 범위다 — NBSP · NEL · 전각 빈칸도 걷는다. 세로 탭 · 쪽 넘김도 공백이다.
    assert_eq!(trim("\u{a0}\u{3000} a b \u{85}\x0b\x0c".as_bytes()), b"a b");
    assert_eq!(trim(b" \t\r\n"), b"");
    assert_eq!(trim(b""), b"");
    // UTF-8 로 풀리지 않는 바이트는 공백이 아니다.
    assert_eq!(trim(b" \xa0 x \xa0 "), b"\xa0 x \xa0");
    assert_eq!(trim(b"x \xe2\x80"), b"x \xe2\x80");
    assert_eq!(trim_start(b" \xc2\xa0\xa0 x "), b"\xa0 x ");
    assert_eq!(first_char(b""), None);
    assert_eq!(first_char(b"a\xff"), Some(('a', 1)));
    assert_eq!(first_char("한글".as_bytes()), Some(('한', 3)));
    assert_eq!(first_char(b"\xe2\x82"), Some(('\u{fffd}', 1)));
    assert_eq!(
        first_char(b"\xed\xa0\x80"),
        Some(('\u{fffd}', 1)),
        "서로게이트"
    );
    // 소문자는 글자마다 하나 — U+0130 은 i 한 글자다.
    assert_eq!(lower("DEB\u{130}AN".as_bytes()), "debian");
    assert_eq!(lower(b"A\xff\xfeZ"), "a\u{fffd}\u{fffd}z");
    assert_eq!(lower("ÀΣ".as_bytes()), "àσ");
}

/// 스캐너(`d3acb38`)의 `ParseRelease` 에 같은 입력을 넣어 얻은 답이다. 옮긴 시험이 닿지 않는 자리 — 유니코드
/// 공백 · Latin-1 바이트 · BOM · Go 의 이스케이프 · 바이트로 견주는 키 · 유니코드 소문자 · 경로 정리 — 를
/// 스캐너와 맞춘다.
#[test]
fn edge_cases_answer_as_the_scanner_does() {
    type Row = (
        &'static str,
        &'static [u8],
        Option<(&'static str, &'static str)>,
    );
    let rows: &[Row] = &[
        ("/etc/os-release", b"ID=ubuntu\xc2\xa0\nVERSION_ID=\xe3\x80\x8014.04\n", Some(("ubuntu", "14.04"))),
        ("/etc/os-release", b"ID=ubuntu\xa0\nVERSION_ID=14.04\n", None),
        ("/etc/os-release", b"\x0bID=\x0bubuntu\x0c\n\xc2\x85VERSION_ID=1\xe2\x80\xa8\n", Some(("ubuntu", "1"))),
        ("/etc/os-release", b"ID=ubuntu\xe2\x80\xa8VERSION_ID=1", None),
        ("/etc/os-release", b"ID=ubuntu\rVERSION_ID=1", None),
        ("/etc/os-release", b"\xef\xbb\xbfID=ubuntu\nVERSION_ID=1\n", None),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=\"\\x31\\062\\u002e\\U00000034\"\n", Some(("debian", "12.4"))),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME=\"\\377\\x00\\u0000\"\n", Some(("debian", "12"))),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME=\"\\400\"\n", None),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME=\"\\ud800\"\n", None),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME=\"\\U0010FFFF\"\n", Some(("debian", "12"))),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME=\"\\U00110000\"\n", None),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME=\"it\\'s\"\n", None),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME=\"a\\\"b\"\n", Some(("debian", "12"))),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME=\"a\\\"\n", None),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME=\"caf\xe9\"\n", Some(("debian", "12"))),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME='it\\'s'\n", None),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME='a\\b'\n", Some(("debian", "12"))),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=12\nNAME=a\"b\n", Some(("debian", "12"))),
        ("/etc/os-release", b"ID=debian\nVERSION_ID=`12`\n", None),
        ("/etc/os-release", b"\xff=1\n\xfe=2\nID=a\nVERSION_ID=1\n", Some(("a", "1"))),
        ("/etc/os-release", b"\xff=1\n\xff=2\nID=a\nVERSION_ID=1\n", None),
        ("/etc/os-release", b"\xef\xbf\xbd=1\n\xff=2\n\xe2\x82=3\nID=a\nVERSION_ID=1\n", Some(("a", "1"))),
        ("/etc/os-release", b"ID =a\nID\xc2\xa0=b\nVERSION_ID=1\n", None),
        ("/etc/os-release", b"ID=a\nid=b\nVERSION_ID=1\n", Some(("a", "1"))),
        ("/etc/os-release", b"export ID=a\nVERSION_ID=1\n", None),
        ("/etc/os-release", b"ID=a=b\nVERSION_ID=1\n", None),
        ("/etc/os-release", b"ID=a.b_c-d\nVERSION_ID=00.0\n", Some(("a.b_c-d", "00.0"))),
        ("/etc/os-release", b"ID=Ubuntu\nVERSION_ID=1\n", None),
        ("/etc/os-release", b"ID=ubuntu\nVERSION_ID=1.\n", None),
        ("/etc/lsb-release", b"DISTRIB_ID=DEB\xc4\xb0AN\nDISTRIB_RELEASE=7\n", Some(("debian", "7"))),
        ("/etc/lsb-release", b"DISTRIB_ID=Deb\xc4\xb1an\nDISTRIB_RELEASE=7\n", None),
        ("/etc/lsb-release", b"DISTRIB_ID=\"Ubuntu\"\nDISTRIB_RELEASE='22.04'\nDISTRIB_DESCRIPTION=\"Ubuntu 22.04.4 LTS\"\n", Some(("ubuntu", "22.04"))),
        ("/etc/lsb-release", b"DISTRIB_ID=UBUNTU\xe2\x84\xaa\nDISTRIB_RELEASE=7\n", None),
        ("/etc/lsb-release", b"DISTRIB_ID=LinuxMint\nDISTRIB_RELEASE=21\n", None),
        ("/etc/lsb-release", b"DISTRIB_RELEASE=21\n", None),
        ("/etc/SuSE-release", b"SUSE Linux Enterprise Server 11 SP4\r\nVERSION = 11\r\nPATCHLEVEL = 4\r\n", Some(("sles", "11.4"))),
        ("/etc/SuSE-release", b"SUSE LINUX 10.1 (i586)\nVERSION = 10.1\n", Some(("opensuse", "10.1"))),
        ("/etc/SuSE-release", b"SUSE Linux Enterprise Server 11 (x86_64)\nVERSION = \"11\"\nPATCHLEVEL = '3'\n", Some(("sles", "11.3"))),
        ("/etc/SuSE-release", b"SUSE Linux Enterprise Server 11 SP4 (x86_64)\nVERSION = 11\nPATCHLEVEL = 04\n", None),
        ("/etc/SuSE-release", b"SUSE Linux Enterprise Server 11 (x86_64)\nVERSION = 11\nPATCHLEVEL = 04\n", Some(("sles", "11.04"))),
        ("/etc/SuSE-release", b"SUSE Linux Enterprise Server 11 (x86_64)\nVERSION = 11\nPATCHLEVEL = 00\n", Some(("sles", "11.00"))),
        ("/etc/SuSE-release", b"SUSE Linux Enterprise Server 11 SP0 (x86_64)\nVERSION = 11\nPATCHLEVEL = 0\n", Some(("sles", "11"))),
        ("/etc/SuSE-release", b"SUSE Linux Enterprise Server 11 SP4 (x86_64)\nVERSION = 11\n", Some(("sles", "11"))),
        ("/etc/SuSE-release", b"SUSE Linux Enterprise Server 11 SP4 (x86_64)\nPATCHLEVEL = 4\nVERSION = 11\nVERSION = 11\n", None),
        ("/etc/SuSE-release", b"\n SUSE Linux Enterprise Desktop 12 SP2 \nVERSION=12\nPATCHLEVEL=2\n", Some(("sled", "12.2"))),
        ("/etc/SuSE-release", b"openSUSE 13.2 (Harlequin)\nVERSION = 13.2\nCODENAME = Harlequin\n# /etc/SuSE-release is deprecated\n", Some(("opensuse", "13.2"))),
        ("/etc/SuSE-release", b"openSUSE 13.2\nVERSION = 13.2\nstray\n", None),
        ("/etc/redhat-release", b" \tRed Hat Enterprise Linux WS release 4 (Nahant Update 9)\r\n", Some(("rhel", "4"))),
        ("/etc/redhat-release", b"Red Hat Enterprise Linux release 8.4 (Ootpa)\n\n", Some(("rhel", "8.4"))),
        ("/etc/redhat-release", b"Red Hat Enterprise Linux release 8.4 (Ootpa) \xc2\xa0", Some(("rhel", "8.4"))),
        ("/etc/redhat-release", b"Red Hat Enterprise Linux release 8.4 ()", None),
        ("/etc/redhat-release", b"Red Hat Enterprise Linux  release 8.4", None),
        ("/etc/redhat-release", b"CentOS Linux release 8.4.2105", Some(("centos", "8.4.2105"))),
        ("/etc/centos-release", b"CentOS Stream release 9", Some(("centos", "9"))),
        ("/etc/centos-release", b"Red Hat Enterprise Linux release 8.4 (Ootpa)", None),
        ("/etc/oracle-release", b"Oracle Linux release 9.1", Some(("ol", "9.1"))),
        ("/etc/oracle-release", b"CentOS Linux release 7.9.2009 (Core)", None),
        ("/etc/debian_version", b" 12.5\r\n", Some(("debian", "12.5"))),
        ("/etc/debian_version", b"12.5\n13", None),
        ("/etc/debian_version", b"trixie/sid", None),
        ("/etc//os-release", b"ID=a\nVERSION_ID=1\n", Some(("a", "1"))),
        ("/etc/x/../os-release/.", b"ID=a\nVERSION_ID=1\n", Some(("a", "1"))),
        ("/../etc/os-release", b"ID=a\nVERSION_ID=1\n", Some(("a", "1"))),
        ("etc/os-release", b"ID=a\nVERSION_ID=1\n", None),
        ("/etc/OS-RELEASE", b"ID=a\nVERSION_ID=1\n", None),
        ("/usr/lib/os-release ", b"ID=a\nVERSION_ID=1\n", None),
        ("/etc/lsb-release", b"DISTRIB_ID=\"\\x44\\x45\\x42\\304\xb0AN\"\nDISTRIB_RELEASE=7\n", None),
        ("/etc/os-release", b"; comment\nID=a\nVERSION_ID=1\n", None),
        ("/etc/os-release", b";x=1\nID=a\nVERSION_ID=1\n", Some(("a", "1"))),
    ];
    for (file, data, want) in rows {
        let want = want.map(|(id, version)| (id.to_string(), version.to_string()));
        let text = String::from_utf8_lossy(data);
        assert_eq!(parse_release(file, data), want, "{file}: {text:?}");
    }
}
