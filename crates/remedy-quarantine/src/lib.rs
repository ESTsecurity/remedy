//! 격리 컨테이너 — **지우기 전에 되돌릴 수 있게 한다** (설계-09 P5).
//!
//! 이 크레이트가 이 프로젝트의 존재 이유에 가장 가깝다. 엔진팀이 거절한 문제가
//! "치료가 오탐이면 되돌릴 수 없다" 였고, 그 답이 여기다.
//!
//! # 무엇을 보장하고 무엇을 보장하지 않는가
//!
//! 보장한다 — 컨테이너에 들어간 것은 **바이트 단위로 그대로 나온다.** 색인의
//! 해시와 다르면 내용을 돌려주지 않는다. 변조된 헤더로는 열리지 않는다. 최소
//! 하나의 wrap 없이는 만들어지지 않는다(아무도 열 수 없는 컨테이너를 만들어
//! 두고 원본을 지우는 것이 곧 복원 불가능한 파괴다).
//!
//! 보장하지 않는다 — 기본 모드의 암호화는 **기밀성이 아니라 봉인**이다.
//! 감염 호스트에서 관리자 권한을 가진 악성코드는 로컬 키 파일에 접근할 수 있다.
//! 평문/암호 구분이 실제로 지키는 것은 **컨테이너가 그 머신 밖으로 나갔을 때**
//! 뿐이다 — 백업에 섞여 나가거나 지원팀에 전달될 때 위협 이름과 원본 경로가
//! 드러나지 않는다. 설계-03 §5 는 이것을 문서와 UI 에 그대로 쓰라고 요구한다.
//!
//! # 이 크레이트는 쓰기 경계를 지나지 않는다
//!
//! 격리소에 쓰는 것은 remedy 가 **자기 상태 디렉터리**에 쓰는 것이고 시스템
//! 변경이 아니다. `remedy-platform` 의 쓰기 경계는 시스템 경로를 위한 것이며,
//! 자기 상태 I/O 를 거기 섞으면 "시스템에 손대는 곳은 여기 하나" 라는 성질이
//! 흐려진다 (설계-03 §5).
#![forbid(unsafe_code)]

pub mod container;
pub mod key;

pub use container::{Builder, Entry, Header, Manifest, ManifestEntry, Opened, Sealed, FMT_VER};
pub use key::{
    generate_org_keypair, unwrap_with_org_key, unwrap_with_passphrase, wrap_with_org_key,
    wrap_with_passphrase, ContentKey, MachineKey, WrapKind, WrapSlot,
};

pub const CRATE_NAME: &str = "remedy-quarantine";

#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("격리 컨테이너가 손상됐습니다", "quarantine container is corrupt"))]
    Corrupt(&'static str),
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("암호 처리 실패", "cryptography failed"))]
    Crypto(&'static str),
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("직렬화 실패", "serialization failed"))]
    Encode(String),
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("입출력 실패", "I/O failed"))]
    Io(#[from] std::io::Error),
    #[error("{msg}", msg = remedy_sdk::i18n::t(
        "wrap 이 하나도 없습니다. 아무도 열 수 없는 컨테이너를 만들어 두고 원본을 지우면 \
         그것은 복원 불가능한 파괴입니다",
        "no wrap at all. A container nobody can open, with the original deleted, \
         is irreversible destruction"
    ))]
    NoWrap,
    #[error("{msg}: {0} (known: {FMT_VER})", msg = remedy_sdk::i18n::t("이 코어가 모르는 포맷 버전입니다", "unknown container format version"))]
    UnknownVersion(u16),
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("그런 엔트리가 없습니다", "no such entry"))]
    NoSuchEntry(String),
    #[error("{0}")]
    Unsupported(&'static str),
}

impl QuarantineError {
    /// 컨테이너가 깨졌다. **두 언어를 다 받는다.**
    ///
    /// 이 사유들은 `run`·`restore` 화면에 그대로 나간다 — 틀(`#[error]`)은 이미
    /// 두 언어인데 인자만 한국어면 한 줄 안에서 언어가 섞인다. 인자를 직접
    /// 넣는 대신 이 문을 쓰면 새 갈래도 두 언어를 요구받는다
    /// (`PlatformError::refused` 와 같은 수).
    pub(crate) fn corrupt(ko: &'static str, en: &'static str) -> Self {
        Self::Corrupt(remedy_sdk::i18n::t(ko, en))
    }

    /// 암호 처리가 실패했다.
    pub(crate) fn crypto(ko: &'static str, en: &'static str) -> Self {
        Self::Crypto(remedy_sdk::i18n::t(ko, en))
    }

    /// 이 코어에 그 수단이 없다.
    pub(crate) fn unsupported(ko: &'static str, en: &'static str) -> Self {
        Self::Unsupported(remedy_sdk::i18n::t(ko, en))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_sdk::EntryKind;

    fn header(wraps: Vec<WrapSlot>) -> Header {
        Header {
            run_id: "01J000000000000000000000".into(),
            created: "2026-08-21T00:00:00Z".into(),
            core_version: "0.0.0".into(),
            cipher: key::CIPHER_ID.into(),
            wraps,
        }
    }

    fn file_entry(path: &str, body: &[u8]) -> Entry {
        Entry {
            kind: EntryKind::File,
            origin: path.into(),
            meta: serde_json::json!({ "mtime": "2026-08-21T00:00:00Z" }),
            content: body.to_vec(),
        }
    }

    /// 만들고 → 열고 → 꺼낸다. 가장 자주 도는 길.
    fn round_trip(entries: Vec<Entry>) -> (Vec<u8>, MachineKey, ContentKey) {
        let mk = MachineKey::from_bytes([9u8; 32]);
        let ck = ContentKey::generate().unwrap();
        let mut b = Builder::new(header(vec![mk.wrap(&ck).unwrap()]), "evilai-locust");
        for e in entries {
            b.add(e);
        }
        (b.seal(&ck).unwrap(), mk, ck)
    }

    #[test]
    fn a_container_round_trips() {
        let (bytes, _mk, ck) = round_trip(vec![
            file_entry(
                "C:\\Users\\a\\AppData\\Local\\Programs\\x\\updater.exe",
                b"MZ\x90\x00",
            ),
            file_entry(
                "C:\\Users\\a\\AppData\\Local\\Programs\\x\\config.dat",
                b"cfg",
            ),
        ]);
        let sealed = Sealed::parse(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        assert_eq!(opened.ids(), vec!["e0", "e1"]);

        let e = opened.read("e0", &ck).unwrap();
        assert_eq!(e.content, b"MZ\x90\x00");
        assert_eq!(e.kind, EntryKind::File);
        assert!(e.origin.ends_with("updater.exe"));
    }

    #[test]
    fn the_plaintext_header_says_nothing_about_the_threat() {
        // **평문에서 위협 이름이 드러나면 안 된다.** 컨테이너가 백업에 섞여
        // 나가거나 지원팀에 전달될 때 "이 PC 는 무엇에 감염됐었다" 가 파일 하나로
        // 새는 것을 막는 것이 이 구분의 전부다 (설계-03 §5).
        let (bytes, _mk, _ck) = round_trip(vec![file_entry(
            "C:\\Users\\hong\\내문서\\세금신고.xlsx",
            b"secret",
        )]);
        let text = String::from_utf8_lossy(&bytes);
        // 헤더 길이만큼만 봐도 되지만, 파일 전체에서 없어야 더 강한 주장이다.
        assert!(!text.contains("evilai"), "플러그인 ID 가 평문에 있다");
        assert!(!text.contains("세금신고"), "원본 경로가 평문에 있다");
        assert!(!text.contains("secret"), "본문이 평문에 있다");
        // 반대로 열 수 있는지 판단할 것은 있어야 한다.
        assert!(
            text.contains("01J000000000000000000000"),
            "run_id 는 있어야 한다"
        );
    }

    #[test]
    fn the_header_is_readable_without_a_key() {
        // 복원 도구가 "내가 이것을 열 수 있는가" 를 키 없이 판단할 수 있어야 한다.
        let (bytes, mk, _ck) = round_trip(vec![file_entry("c:\\x", b"y")]);
        let sealed = Sealed::parse(&bytes).unwrap();
        assert_eq!(sealed.header.wraps.len(), 1);
        assert_eq!(sealed.header.wraps[0].key_id, mk.key_id());
        assert!(sealed.header.only_local_wrap());
    }

    #[test]
    fn a_container_without_any_wrap_is_refused() {
        // 아무도 열 수 없는 컨테이너를 만들어 두고 원본을 지우면 복원 불가능한 파괴다.
        let ck = ContentKey::generate().unwrap();
        let mut b = Builder::new(header(vec![]), "x");
        b.add(file_entry("c:\\x", b"y"));
        assert!(matches!(b.seal(&ck), Err(QuarantineError::NoWrap)));
    }

    #[test]
    fn a_tampered_header_does_not_open() {
        // 헤더를 AAD 로 묶는 이유. wrap 슬롯을 지우거나 run_id 를 바꿔치기하는
        // 변조가 인증을 통과하면 안 된다.
        let (mut bytes, _mk, ck) = round_trip(vec![file_entry("c:\\x", b"y")]);
        // 헤더 안의 run_id 한 글자를 바꾼다.
        let pos = bytes
            .windows(24)
            .position(|w| w == b"01J000000000000000000000")
            .expect("run_id 위치");
        bytes[pos] = b'9';
        let sealed = Sealed::parse(&bytes).unwrap();
        assert!(sealed.unlock(&ck).is_err(), "변조된 헤더로 색인이 열렸다");
    }

    #[test]
    fn a_swapped_entry_does_not_open() {
        // AAD 에 순번을 넣는 이유. 두 엔트리를 맞바꾸면 인증이 깨져야 한다.
        let (bytes, _mk, ck) = round_trip(vec![
            file_entry("c:\\a", b"aaaaaaaaaaaaaaaa"),
            file_entry("c:\\b", b"bbbbbbbbbbbbbbbb"),
        ]);
        let sealed = Sealed::parse(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let (o0, l0) = {
            let m = &opened.manifest.entries[0];
            (m.offset as usize, m.len as usize)
        };
        let (o1, l1) = {
            let m = &opened.manifest.entries[1];
            (m.offset as usize, m.len as usize)
        };
        assert_eq!(l0, l1, "이 시험은 두 엔트리 길이가 같을 때 성립한다");

        // 엔트리 영역의 시작을 찾아 두 블록을 맞바꾼다.
        let region = bytes.len() - (l0 + l1);
        let mut swapped = bytes.clone();
        let (a, b) = (region + o0, region + o1);
        for i in 0..l0 {
            swapped.swap(a + i, b + i);
        }
        let s2 = Sealed::parse(&swapped).unwrap();
        let o2 = s2.unlock(&ck).unwrap();
        assert!(o2.read("e0", &ck).is_err(), "바꿔치기된 엔트리가 열렸다");
    }

    #[test]
    fn a_truncated_container_is_reported_not_guessed() {
        // 잘림은 **쓰는 시점이 아니라 읽는 시점**에 드러난다. 헤더와 색인이 앞에
        // 있으므로 꼬리가 잘려도 "무엇이 들어 있었는가" 는 여전히 말할 수 있어야
        // 하고, 잘린 엔트리를 **꺼낼 때** 실패해야 한다. 조용히 짧은 바이트를
        // 돌려주면 그것을 원본 자리에 쓰게 된다.
        let (bytes, _mk, ck) = round_trip(vec![file_entry("c:\\x", b"y")]);

        // 앞부분이 잘리면 파싱 자체가 안 된다.
        for cut in [3, 8, 20] {
            assert!(
                Sealed::parse(&bytes[..cut]).is_err(),
                "{cut} 바이트짜리가 컨테이너로 파싱됐다"
            );
        }

        // 꼬리만 잘리면 색인까지는 읽히고, 엔트리에서 멈춘다.
        let part = &bytes[..bytes.len() - 1];
        let sealed = Sealed::parse(part).expect("헤더는 앞에 있으니 읽혀야 한다");
        assert_eq!(sealed.header.run_id, "01J000000000000000000000");
        let opened = sealed.unlock(&ck).expect("색인도 앞에 있으니 열려야 한다");
        assert_eq!(
            opened.manifest.entries.len(),
            1,
            "무엇이 있었는지는 말할 수 있다"
        );
        assert!(
            opened.read("e0", &ck).is_err(),
            "잘린 엔트리를 조용히 돌려줬다"
        );
    }

    #[test]
    fn an_unknown_format_version_is_refused_by_name() {
        let (mut bytes, _mk, _ck) = round_trip(vec![file_entry("c:\\x", b"y")]);
        bytes[5] = 99; // fmt_ver LE 하위 바이트
        match Sealed::parse(&bytes) {
            Err(QuarantineError::UnknownVersion(v)) => assert_eq!(v, 99),
            Err(e) => panic!("포맷 버전을 이름으로 거절해야 한다: {e}"),
            Ok(_) => panic!("모르는 포맷 버전이 통과했다"),
        }
    }

    #[test]
    fn all_three_wraps_open_the_same_container() {
        // 하나라도 열리면 컨테이너가 열린다. 이것이 "복원 불가 상태를 만들지
        // 않는다" 의 실제 모습이다.
        let mk = MachineKey::from_bytes([1u8; 32]);
        let (org_sk, org_pk) = generate_org_keypair().unwrap();
        let ck = ContentKey::generate().unwrap();
        let wraps = vec![
            mk.wrap(&ck).unwrap(),
            wrap_with_passphrase("복구 암호", &ck).unwrap(),
            wrap_with_org_key(&org_pk, &ck).unwrap(),
        ];
        let mut b = Builder::new(header(wraps), "x");
        b.add(file_entry("c:\\x", b"content"));
        let bytes = b.seal(&ck).unwrap();

        let sealed = Sealed::parse(&bytes).unwrap();
        assert!(!sealed.header.only_local_wrap());

        for (i, want) in [WrapKind::Local, WrapKind::Pass, WrapKind::Org]
            .into_iter()
            .enumerate()
        {
            let slot = &sealed.header.wraps[i];
            assert_eq!(slot.kind, want);
            let k = match want {
                WrapKind::Local => mk.unwrap(slot).unwrap(),
                WrapKind::Pass => unwrap_with_passphrase("복구 암호", slot).unwrap(),
                WrapKind::Org => unwrap_with_org_key(&org_sk, slot).unwrap(),
            };
            let opened = sealed.unlock(&k).unwrap();
            assert_eq!(opened.read("e0", &k).unwrap().content, b"content");
        }
    }

    #[test]
    fn a_container_made_on_one_machine_opens_on_another_with_the_org_key() {
        // **설계-09 P5 검증.** 머신을 재설치하면 로컬 키가 사라진다. 그때 내용을
        // 되찾는 경로가 이것이고, 그것이 조직 복구 키의 존재 이유다.
        let this_machine = MachineKey::from_bytes([0xAA; 32]);
        let (org_sk, org_pk) = generate_org_keypair().unwrap();
        let ck = ContentKey::generate().unwrap();
        let mut b = Builder::new(
            header(vec![
                this_machine.wrap(&ck).unwrap(),
                wrap_with_org_key(&org_pk, &ck).unwrap(),
            ]),
            "x",
        );
        b.add(file_entry(
            "c:\\users\\a\\문서.hwp",
            "사용자 문서".as_bytes(),
        ));
        let bytes = b.seal(&ck).unwrap();

        // 다른 머신 — 로컬 키가 다르다.
        let other_machine = MachineKey::from_bytes([0xBB; 32]);
        let sealed = Sealed::parse(&bytes).unwrap();
        let local = &sealed.header.wraps[0];
        assert!(
            other_machine.unwrap(local).is_err(),
            "다른 머신의 로컬 키로 열리면 안 된다"
        );

        let k = unwrap_with_org_key(&org_sk, &sealed.header.wraps[1]).unwrap();
        let opened = sealed.unlock(&k).unwrap();
        assert_eq!(
            opened.read("e0", &k).unwrap().content,
            "사용자 문서".as_bytes()
        );
    }

    #[test]
    fn the_estimated_size_covers_the_real_one() {
        // 여유 공간 확인이 실제보다 작게 잡히면 백업 도중 디스크가 찬다.
        // 그 시점에는 이미 파괴가 시작됐을 수 있다 (설계-00 §5-2).
        let mk = MachineKey::from_bytes([2u8; 32]);
        let ck = ContentKey::generate().unwrap();
        let mut b = Builder::new(header(vec![mk.wrap(&ck).unwrap()]), "x");
        for i in 0..8 {
            b.add(file_entry(
                &format!("c:\\some\\longer\\path\\file-{i}.bin"),
                &vec![i as u8; 4096],
            ));
        }
        let est = b.estimated_size();
        let real = b.seal(&ck).unwrap().len() as u64;
        assert!(est >= real, "추정 {est} < 실제 {real}");
    }

    #[test]
    fn a_bad_hash_in_the_index_stops_the_read() {
        // 색인과 본문이 어긋나면 둘 중 하나는 거짓이다. 잘못된 바이트를 원본
        // 자리에 쓰는 것이 아무것도 하지 않는 것보다 나쁘다.
        let mk = MachineKey::from_bytes([5u8; 32]);
        let ck = ContentKey::generate().unwrap();
        let mut b = Builder::new(header(vec![mk.wrap(&ck).unwrap()]), "x");
        b.add(file_entry("c:\\x", b"real"));
        let bytes = b.seal(&ck).unwrap();

        // 색인만 고쳐 다시 봉인한다 — 정상 경로로는 만들 수 없는 상태다.
        let sealed = Sealed::parse(&bytes).unwrap();
        let mut opened = sealed.unlock(&ck).unwrap();
        opened.manifest.entries[0].sha256 = "0".repeat(64);
        // 색인을 직접 고친 상태로 read 하면 해시 불일치가 잡혀야 한다.
        assert!(matches!(
            opened.read("e0", &ck),
            Err(QuarantineError::Corrupt(_))
        ));
    }
}

/// **깨진 컨테이너의 사유가 영어 회차에서 한글로 나오지 않는가.**
///
/// 이 문자열들은 `run`·`restore` 화면에 그대로 나간다 — 틀(`#[error]`)은 이미
/// 두 언어였고 인자만 한국어였다. 기존 시험은 성공 갈래만 밟아 아무도 재지
/// 않고 있었다.
///
/// **여기서 밟는 것이 전부는 아니다.** 나머지 갈래는 `QuarantineError::corrupt`
/// 같은 생성자가 두 언어를 요구하는 것으로 지킨다.
#[cfg(test)]
mod reason_tests {
    use super::*;

    fn has_hangul(s: &str) -> bool {
        s.chars().any(|c| ('가'..='힣').contains(&c))
    }

    fn check(what: &str, e: QuarantineError) {
        let line = e.to_string();
        assert!(!has_hangul(&line), "{what}: {line}");
    }

    #[test]
    fn a_broken_container_says_why_in_english() {
        // `Sealed` 는 `Debug` 가 아니라 `expect_err` 를 쓸 수 없다.
        for (what, bytes) in [
            ("빈 바이트", &b""[..]),
            ("magic 이 다르다", &b"NOTREMEDYCONTAINER0123456789"[..]),
        ] {
            match Sealed::parse(bytes) {
                Err(e) => check(what, e),
                Ok(_) => panic!("{what}: 열리면 안 되는 것이 열렸다"),
            }
        }
    }

    #[test]
    fn a_bad_sealed_block_says_why_in_english() {
        let ck = ContentKey::from_bytes([7u8; 32]);
        check(
            "논스보다 짧다",
            ck.open(&[0u8; 4], b"aad")
                .expect_err("짧은 것을 열면 안 된다"),
        );
        let sealed = ck.seal(b"body", b"aad").expect("봉인");
        check(
            "다른 aad",
            ck.open(&sealed, b"other")
                .expect_err("aad 가 다르면 못 연다"),
        );
    }
}
