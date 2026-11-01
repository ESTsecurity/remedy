//! 속성 기반 왕복 — **임의의 입력에서 바이트가 그대로 나오는가** (설계-09 P5 검증 1).
//!
//! 손으로 고른 예제는 손으로 고른 만큼만 확인해 준다. 격리물은 사용자 문서일 수도
//! 있고(오탐), 그것이 한 바이트라도 달라져 나오면 이 도구가 존재하는 이유가
//! 무너진다. 그래서 입력을 기계가 고르게 한다.

use proptest::prelude::*;
use remedy_quarantine::{Builder, ContentKey, Entry, Header, MachineKey, Sealed, WrapKind};
use remedy_sdk::EntryKind;

fn header(wraps: Vec<remedy_quarantine::WrapSlot>) -> Header {
    Header {
        run_id: "01J000000000000000000000".into(),
        created: "2026-08-21T00:00:00Z".into(),
        core_version: "0.0.0".into(),
        cipher: remedy_quarantine::key::CIPHER_ID.into(),
        wraps,
    }
}

/// 엔트리 한 벌을 담아 봉인하고 다시 꺼낸다.
fn round_trip(entries: &[Entry]) -> Vec<Entry> {
    let mk = MachineKey::from_bytes([0x11; 32]);
    let ck = ContentKey::generate().unwrap();
    let mut b = Builder::new(header(vec![mk.wrap(&ck).unwrap()]), "prop");
    for e in entries {
        b.add(e.clone());
    }
    let bytes = b.seal(&ck).unwrap();

    let sealed = Sealed::parse(&bytes).unwrap();
    let opened = sealed.unlock(&ck).unwrap();
    opened
        .ids()
        .iter()
        .map(|id| opened.read(id, &ck).unwrap())
        .collect()
}

prop_compose! {
    /// 경로에 어떤 문자가 오든 상관없어야 한다 — 컨테이너는 경로를 해석하지 않는다.
    fn any_entry()(
        origin in "[\\PC]{1,80}",
        content in prop::collection::vec(any::<u8>(), 0..8192),
        readonly in any::<bool>(),
        mtime in any::<i64>(),
    ) -> Entry {
        Entry {
            kind: EntryKind::File,
            origin,
            meta: serde_json::json!({ "readonly": readonly, "mtime_unix": mtime }),
            content,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// **바이트가 그대로 나온다.** 이것 하나가 이 크레이트의 전부다.
    #[test]
    fn any_entry_survives_the_round_trip(entries in prop::collection::vec(any_entry(), 1..6)) {
        let back = round_trip(&entries);
        prop_assert_eq!(back.len(), entries.len());
        for (a, b) in entries.iter().zip(back.iter()) {
            prop_assert_eq!(&a.content, &b.content, "본문이 달라졌다");
            prop_assert_eq!(&a.origin, &b.origin, "원본 경로가 달라졌다");
            prop_assert_eq!(&a.meta, &b.meta, "메타데이터가 달라졌다");
            prop_assert_eq!(a.kind, b.kind);
        }
    }

    /// 어느 한 바이트를 뒤집어도 열리지 않는다.
    #[test]
    fn flipping_any_byte_breaks_it(
        content in prop::collection::vec(any::<u8>(), 1..512),
        pos in any::<prop::sample::Index>(),
    ) {
        let mk = MachineKey::from_bytes([0x22; 32]);
        let ck = ContentKey::generate().unwrap();
        let mut b = Builder::new(header(vec![mk.wrap(&ck).unwrap()]), "prop");
        b.add(Entry {
            kind: EntryKind::File,
            origin: "c:\\x".into(),
            meta: serde_json::json!({}),
            content,
        });
        let bytes = b.seal(&ck).unwrap();

        let i = pos.index(bytes.len());
        let mut broken = bytes.clone();
        broken[i] ^= 0xFF;

        // 헤더 평문이 바뀌면 파싱이나 개봉에서, 봉인 영역이 바뀌면 인증에서 걸린다.
        // 어느 쪽이든 **원본이라고 주장하는 바이트가 나오면 안 된다.**
        let ok = match Sealed::parse(&broken) {
            Err(_) => false,
            Ok(s) => match s.unlock(&ck) {
                Err(_) => false,
                Ok(o) => o.ids().iter().all(|id| o.read(id, &ck).is_ok()),
            },
        };
        prop_assert!(!ok, "{i}번째 바이트를 뒤집었는데 그대로 열렸다");
    }

    /// 세 wrap 중 어느 것으로 열어도 같은 내용이 나온다.
    #[test]
    fn every_wrap_yields_the_same_bytes(content in prop::collection::vec(any::<u8>(), 0..2048)) {
        let mk = MachineKey::from_bytes([0x33; 32]);
        let (org_sk, org_pk) = remedy_quarantine::generate_org_keypair().unwrap();
        let ck = ContentKey::generate().unwrap();
        let wraps = vec![
            mk.wrap(&ck).unwrap(),
            remedy_quarantine::wrap_with_passphrase("p", &ck).unwrap(),
            remedy_quarantine::wrap_with_org_key(&org_pk, &ck).unwrap(),
        ];
        let mut b = Builder::new(header(wraps), "prop");
        b.add(Entry {
            kind: EntryKind::File,
            origin: "c:\\x".into(),
            meta: serde_json::json!({}),
            content: content.clone(),
        });
        let bytes = b.seal(&ck).unwrap();
        let sealed = Sealed::parse(&bytes).unwrap();

        for slot in &sealed.header.wraps {
            let k = match slot.kind {
                WrapKind::Local => mk.unwrap(slot).unwrap(),
                WrapKind::Pass => remedy_quarantine::unwrap_with_passphrase("p", slot).unwrap(),
                WrapKind::Org => remedy_quarantine::unwrap_with_org_key(&org_sk, slot).unwrap(),
            };
            let o = sealed.unlock(&k).unwrap();
            prop_assert_eq!(o.read("e0", &k).unwrap().content, content.clone());
        }
    }
}
