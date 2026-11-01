//! 서명 왕복과 **거부해야 하는 것들** (설계-03 §10 G8).
//!
//! G8 은 "미서명·변조·폐기된 플러그인 로드 → 거부" 를 요구한다. 이 파일은 그중
//! **미서명**과 **변조**를 덮는다. 폐기(revocation)는 목록 배포가 따라와야
//! 하므로 P10 의 뒤 작업이다.
//!
//! 시험이 스스로 키쌍을 만든다. 개인키를 저장소에 두지 않으면서도 "서명한
//! 것만 통과한다" 를 실제 서명으로 확인하기 위해서다 — 고정 서명 벡터를 두면
//! 그 벡터를 만든 키가 어딘가에 있어야 하고, 형식이 바뀔 때 갱신할 수 없다.

use std::collections::BTreeMap;

use minisign::KeyPair;
use remedy_trust::{Anchor, Manifest, TreeDiff, TrustError};

/// 서명할 트리. 경로 → 내용.
fn tree() -> BTreeMap<String, Vec<u8>> {
    let mut t = BTreeMap::new();
    t.insert("plugin.yaml".to_string(), b"id: evilai-locust\n".to_vec());
    t.insert(
        "rules/evilai.yar".to_string(),
        b"rule evilai_locust_js { condition: false }\n".to_vec(),
    );
    t
}

fn hashes(tree: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    tree.iter()
        .map(|(p, b)| (p.clone(), remedy_trust::sha256_hex(b)))
        .collect()
}

const COMMENT: &str = "remedy-plugin id=evilai-locust version=0.1.0 signed=2026-08-25T09:00:00Z";

struct Signed {
    anchor: Anchor,
    manifest: Vec<u8>,
    signature: String,
}

/// 트리를 서명한다. `comment` 를 바꿔 가며 부를 수 있게 열어 둔다.
fn sign_with(kp: &KeyPair, tree: &BTreeMap<String, Vec<u8>>, comment: &str) -> Signed {
    let manifest = Manifest::render(&hashes(tree)).into_bytes();
    let sig = minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        manifest.as_slice(),
        Some(comment),
        Some("remedy plugin signature"),
    )
    .expect("서명");
    let pk = kp.pk.to_box().expect("공개키 상자").to_string();
    Signed {
        anchor: Anchor::from_public_key_file(&pk).expect("앵커"),
        manifest,
        signature: sig.to_string(),
    }
}

fn sign(tree: &BTreeMap<String, Vec<u8>>) -> Signed {
    let kp = KeyPair::generate_unencrypted_keypair().expect("키쌍");
    sign_with(&kp, tree, COMMENT)
}

#[test]
fn 서명한_트리는_통과한다() {
    let t = tree();
    let s = sign(&t);

    let v = remedy_trust::verify_manifest(&s.anchor, &s.manifest, &s.signature).expect("검증");
    assert_eq!(v.comment().id, "evilai-locust");
    assert_eq!(v.comment().version, "0.1.0");
    assert_eq!(v.comment().signed_at, "2026-08-25T09:00:00Z");
    v.check_tree(&hashes(&t)).expect("트리 대조");
}

#[test]
fn 다른_키로_서명한_것은_거부한다() {
    // "서명이 있다" 와 "우리 키로 서명됐다" 는 다르다. 이것을 통과시키면
    // 누구나 자기 키로 서명해 플러그인을 넣을 수 있다.
    let t = tree();
    let ours = sign(&t);
    let theirs = sign(&t);

    let err = remedy_trust::verify_manifest(&ours.anchor, &theirs.manifest, &theirs.signature)
        .expect_err("남의 서명이 통과했다");
    assert!(matches!(err, TrustError::Signature(_)), "{err}");
}

#[test]
fn 매니페스트를_고치면_거부한다() {
    let t = tree();
    let s = sign(&t);

    let mut tampered = s.manifest.clone();
    // 해시 한 글자를 바꾼다 — 파일을 바꿔치기하고 목록을 맞춰 놓는 시도다.
    let pos = tampered
        .windows(2)
        .position(|w| w == b"\n0" || w == b"\na")
        .unwrap_or(tampered.len() - 2)
        + 1;
    tampered[pos] = if tampered[pos] == b'f' { b'e' } else { b'f' };

    let err = remedy_trust::verify_manifest(&s.anchor, &tampered, &s.signature)
        .expect_err("변조된 매니페스트가 통과했다");
    assert!(matches!(err, TrustError::Signature(_)), "{err}");
}

#[test]
fn 서명_주석을_고치면_거부한다() {
    // minisign 은 서명 값과 trusted_comment 를 함께 다시 서명한다. 그래서
    // 버전만 올려 적는 시도가 막힌다 — 이 성질이 역행 금지 판정의 근거다
    // (설계-01 미결 5).
    let t = tree();
    let s = sign(&t);

    let tampered = s.signature.replace("version=0.1.0", "version=9.9.9");
    assert_ne!(tampered, s.signature, "치환이 일어나지 않았다");

    let err = remedy_trust::verify_manifest(&s.anchor, &s.manifest, &tampered)
        .expect_err("주석을 고친 서명이 통과했다");
    assert!(matches!(err, TrustError::Signature(_)), "{err}");
}

#[test]
fn 서명이_없으면_통과할_길이_없다() {
    // 빈 서명·쓰레기 서명 어느 쪽도 파싱 단계에서 끝난다.
    let t = tree();
    let s = sign(&t);
    for bogus in ["", "not a signature", "untrusted comment: x\nAAAA\n"] {
        let err = remedy_trust::verify_manifest(&s.anchor, &s.manifest, bogus)
            .expect_err("서명이 아닌 것이 통과했다");
        assert!(matches!(err, TrustError::Signature(_)), "{err}");
    }
}

#[test]
fn 우리_형식이_아닌_주석은_거부한다() {
    // minisign 기본 주석은 `timestamp:...` 다. 서명 자체는 유효하지만 어느
    // 플러그인의 어느 버전인지 말하지 않으므로 받지 않는다.
    let kp = KeyPair::generate_unencrypted_keypair().expect("키쌍");
    let t = tree();
    let s = sign_with(&kp, &t, "timestamp:1756108800");

    let err = remedy_trust::verify_manifest(&s.anchor, &s.manifest, &s.signature)
        .expect_err("형식 밖 주석이 통과했다");
    assert!(matches!(err, TrustError::Comment(_)), "{err}");
}

#[test]
fn 파일_내용이_바뀌면_트리_대조에서_걸린다() {
    let t = tree();
    let s = sign(&t);
    let v = remedy_trust::verify_manifest(&s.anchor, &s.manifest, &s.signature).expect("검증");

    let mut actual = hashes(&t);
    actual.insert(
        "rules/evilai.yar".into(),
        remedy_trust::sha256_hex(b"rule evilai_locust_js { condition: true }"),
    );

    let err = v.check_tree(&actual).expect_err("바뀐 파일이 통과했다");
    let TrustError::TreeMismatch(diffs) = err else {
        panic!("다른 오류: {err}")
    };
    assert!(
        matches!(&diffs[..], [TreeDiff::Modified { path, .. }] if path == "rules/evilai.yar"),
        "{diffs:?}"
    );
}

#[test]
fn 파일이_없어지면_트리_대조에서_걸린다() {
    let t = tree();
    let s = sign(&t);
    let v = remedy_trust::verify_manifest(&s.anchor, &s.manifest, &s.signature).expect("검증");

    let mut actual = hashes(&t);
    actual.remove("rules/evilai.yar");

    let err = v.check_tree(&actual).expect_err("없어진 파일이 통과했다");
    let TrustError::TreeMismatch(diffs) = err else {
        panic!("다른 오류: {err}")
    };
    assert!(
        matches!(&diffs[..], [TreeDiff::Missing { path }] if path == "rules/evilai.yar"),
        "{diffs:?}"
    );
}

#[test]
fn 서명되지_않은_파일을_넣으면_걸린다() {
    // **이 시험이 이 설계의 핵심이다.** 파일마다 서명했다면 통과했을 공격이다
    // — 기존 파일을 건드리지 않고 새 파일 하나를 넣는 것.
    let t = tree();
    let s = sign(&t);
    let v = remedy_trust::verify_manifest(&s.anchor, &s.manifest, &s.signature).expect("검증");

    let mut actual = hashes(&t);
    actual.insert(
        "rules/extra.yar".into(),
        remedy_trust::sha256_hex(b"rule everything { condition: true }"),
    );

    let err = v
        .check_tree(&actual)
        .expect_err("몰래 넣은 파일이 통과했다");
    let TrustError::TreeMismatch(diffs) = err else {
        panic!("다른 오류: {err}")
    };
    assert!(
        matches!(&diffs[..], [TreeDiff::Extra { path }] if path == "rules/extra.yar"),
        "{diffs:?}"
    );
}

#[test]
fn 어긋난_자리를_한꺼번에_보고한다() {
    let t = tree();
    let s = sign(&t);
    let v = remedy_trust::verify_manifest(&s.anchor, &s.manifest, &s.signature).expect("검증");

    let mut actual = hashes(&t);
    actual.remove("plugin.yaml");
    actual.insert("rules/extra.yar".into(), remedy_trust::sha256_hex(b"x"));

    let err = v.check_tree(&actual).expect_err("통과했다");
    let TrustError::TreeMismatch(diffs) = err else {
        panic!("다른 오류: {err}")
    };
    assert_eq!(diffs.len(), 2, "한 건만 보고했다: {diffs:?}");
}

#[test]
fn 대소문자가_달라도_같은_해시로_본다() {
    // 해시를 대문자로 적는 도구가 있다. 그것 때문에 "변조" 라고 말하면
    // 오경보이고, 오경보는 검사를 무시하게 만든다.
    let t = tree();
    let s = sign(&t);
    let v = remedy_trust::verify_manifest(&s.anchor, &s.manifest, &s.signature).expect("검증");

    let upper: BTreeMap<String, String> = hashes(&t)
        .into_iter()
        .map(|(p, h)| (p, h.to_ascii_uppercase()))
        .collect();
    v.check_tree(&upper).expect("대문자 hex 를 거부했다");
}
