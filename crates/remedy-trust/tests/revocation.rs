//! 폐기와 역행 금지 (설계-03 §6 · G8 의 세 번째 조각).
//!
//! G8 은 "미서명·변조·**폐기**된 플러그인 로드 거부" 를 요구한다. 앞의 둘은
//! P10-A 가 덮었고 이 파일이 마지막 하나다.
//!
//! 시험이 스스로 키쌍을 만들고 목록을 서명한다 — `sign_verify.rs` 와 같은
//! 이유다. 개인키를 저장소에 두지 않으면서 **실제 서명으로** 확인한다.

use minisign::KeyPair;
use remedy_trust::revocation::{
    self, check_plugin, check_revocations, freshness_policy, Denial, Entry, Freshness, MinVersions,
    Policy,
};
use remedy_trust::{Anchor, TrustState, Version};

fn v(s: &str) -> Version {
    Version::parse(s).unwrap_or_else(|| panic!("버전 {s:?}"))
}

fn entry(plugin: &str, below: Option<&str>, exact: Option<&str>, reason: &str) -> Entry {
    Entry {
        plugin: plugin.into(),
        below: below.map(String::from),
        exact: exact.map(String::from),
        reason: reason.into(),
    }
}

struct Signed {
    anchor: Anchor,
    text: String,
}

/// 목록을 만들어 서명한다. **파일 하나**에 서명 4줄 + 빈 줄 + 본문이다.
fn sign_with(kp: &KeyPair, serial: u64, issued: &str, entries: &[Entry]) -> Signed {
    let body = revocation::render_body(entries).expect("본문");
    let comment = revocation::render_comment(serial, issued);
    let sig = minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        body.as_bytes(),
        Some(&comment),
        Some("remedy revocation list"),
    )
    .expect("서명");

    let mut text = sig.to_string();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push('\n'); // 빈 줄
    text.push_str(&body);

    let pk = kp.pk.to_box().expect("공개키 상자").to_string();
    Signed {
        anchor: Anchor::from_public_key_file(&pk).expect("앵커"),
        text,
    }
}

fn sign(serial: u64, entries: &[Entry]) -> Signed {
    let kp = KeyPair::generate_unencrypted_keypair().expect("키쌍");
    sign_with(&kp, serial, "2026-08-26T00:00:00Z", entries)
}

// ────────────────────────────────────────────── 목록 자체

#[test]
fn 서명된_목록을_읽는다() {
    let s = sign(
        7,
        &[entry(
            "evilai-locust",
            Some("1.2.0"),
            None,
            "오탐 — 정상 Node 환경을 겨눴다",
        )],
    );
    let list = revocation::parse_signed(&s.anchor, &s.text).expect("읽기");

    assert_eq!(list.serial(), 7);
    assert_eq!(list.issued_at(), "2026-08-26T00:00:00Z");
    assert_eq!(list.entries().count(), 1);
}

#[test]
fn 목록을_고치면_거부한다() {
    // **"폐기 목록이 없다" 와 "폐기 목록을 지웠다" 를 구분할 수 있어야 한다.**
    // 서명이 그 구분을 만든다.
    let s = sign(7, &[entry("evilai-locust", Some("1.2.0"), None, "오탐")]);

    // 본문에서 항목 하나를 빼려는 시도 — 폐기를 무력화하는 가장 곧은 길이다.
    let tampered = s.text.replace("evilai-locust", "something-else");
    assert_ne!(tampered, s.text, "치환이 일어나지 않았다");
    assert!(
        revocation::parse_signed(&s.anchor, &tampered).is_err(),
        "고친 목록이 통과했다"
    );
}

#[test]
fn serial_을_올려_적을_수_없다() {
    // serial 은 **서명 주석**에 있다. minisign 이 주석까지 다시 서명하므로
    // 값만 고치면 검증이 깨진다 — 역행 금지가 이 성질 위에 선다.
    let s = sign(7, &[entry("x", Some("1.0.0"), None, "이유")]);
    let tampered = s.text.replace("serial=7", "serial=99");
    assert_ne!(tampered, s.text);
    assert!(revocation::parse_signed(&s.anchor, &tampered).is_err());
}

#[test]
fn 다른_키로_서명한_목록은_거부한다() {
    let t = [entry("x", Some("1.0.0"), None, "이유")];
    let ours = sign(7, &t);
    let theirs = sign(7, &t);
    assert!(revocation::parse_signed(&ours.anchor, &theirs.text).is_err());
}

#[test]
fn 플러그인_서명을_폐기_목록으로_들이밀_수_없다() {
    // 주석 접두가 다르다. 같은 키로 서명됐어도 **용도가 다른 서명**은 받지 않는다.
    let kp = KeyPair::generate_unencrypted_keypair().expect("키쌍");
    let body = revocation::render_body(&[entry("x", Some("1.0.0"), None, "이유")]).expect("본문");
    let sig = minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        body.as_bytes(),
        Some("remedy-plugin id=x version=1.0.0 signed=2026-08-26T00:00:00Z"),
        Some("x"),
    )
    .expect("서명");
    let text = format!("{}\n{body}", sig.to_string().trim_end());

    let pk = kp.pk.to_box().expect("상자").to_string();
    let anchor = Anchor::from_public_key_file(&pk).expect("앵커");
    assert!(
        revocation::parse_signed(&anchor, &text).is_err(),
        "플러그인 서명이 폐기 목록으로 통과했다"
    );
}

#[test]
fn 형식이_어긋난_항목을_거부한다() {
    // below 와 exact 가 둘 다 있거나 둘 다 없으면 무엇을 겨누는지 알 수 없다.
    for e in [
        entry("x", Some("1.0.0"), Some("1.0.0"), "이유"),
        entry("x", None, None, "이유"),
        entry("x", Some("1.0"), None, "이유"),
        entry("x", Some("1.0.0"), None, "   "),
    ] {
        assert!(
            revocation::render_body(std::slice::from_ref(&e)).is_err(),
            "만들 때 걸러야 한다: {e:?}"
        );
    }
}

// ────────────────────────────────────────────── 판정

#[test]
fn 폐기된_플러그인을_거부한다() {
    let s = sign(
        1,
        &[entry("evilai-locust", Some("1.2.0"), None, "오탐 사고")],
    );
    let list = revocation::parse_signed(&s.anchor, &s.text).expect("읽기");
    let min = MinVersions::default();
    let state = TrustState::default();

    let err = check_plugin("evilai-locust", "1.1.0", Some(&list), &min, &state)
        .expect_err("폐기된 버전이 통과했다");
    assert!(
        matches!(err, Denial::Revoked { ref reason, .. } if reason.contains("오탐 사고")),
        "{err}"
    );

    // **경계 위는 통과한다.** "1.2.0 에서 고쳤다" 가 곧 "1.2.0 은 괜찮다" 다.
    check_plugin("evilai-locust", "1.2.0", Some(&list), &min, &state).expect("고친 판이 막혔다");
    // 다른 플러그인은 무관하다.
    check_plugin("other", "0.1.0", Some(&list), &min, &state).expect("남의 폐기에 걸렸다");
}

#[test]
fn 코어에_박힌_하한보다_낮으면_거부한다() {
    // 목록이 **없어도** 이 층은 작동한다 — 오프라인에서 실제로 강제되는 것이
    // 이쪽이다 (설계-01 D6).
    let min = MinVersions::from_pairs(&[("evilai-locust", "2.0.0")]).expect("표");
    let state = TrustState::default();

    let err = check_plugin("evilai-locust", "1.9.9", None, &min, &state)
        .expect_err("하한 아래가 통과했다");
    assert!(matches!(err, Denial::BelowMinimum { .. }), "{err}");

    check_plugin("evilai-locust", "2.0.0", None, &min, &state).expect("하한 자체가 막혔다");
}

#[test]
fn 전에_본_것보다_낮은_버전을_거부한다() {
    // 역행 금지가 없으면 공격자가 **알려진 결함 버전을 다시 제시**할 수 있다.
    let min = MinVersions::default();
    let mut state = TrustState::default();
    state.observe_plugin("evilai-locust", v("1.5.0"));

    let err = check_plugin("evilai-locust", "1.4.0", None, &min, &state)
        .expect_err("되돌리기가 통과했다");
    assert!(matches!(err, Denial::Rollback { .. }), "{err}");

    check_plugin("evilai-locust", "1.5.0", None, &min, &state).expect("같은 버전이 막혔다");
    check_plugin("evilai-locust", "1.6.0", None, &min, &state).expect("더 높은 버전이 막혔다");
}

#[test]
fn 관측은_낮아지지_않는다() {
    let mut state = TrustState::default();
    state.observe_plugin("x", v("1.5.0"));
    state.observe_plugin("x", v("1.2.0")); // 낮은 것을 봐도
    assert_eq!(state.seen("x"), Some(v("1.5.0")), "관측이 낮아졌다");

    state.observe_revocation(9);
    state.observe_revocation(3);
    assert_eq!(state.revocation_serial, 9);
}

#[test]
fn 옛_폐기_목록으로_되돌릴_수_없다() {
    let s = sign(3, &[entry("x", Some("1.0.0"), None, "이유")]);
    let list = revocation::parse_signed(&s.anchor, &s.text).expect("읽기");

    let mut state = TrustState::default();
    state.observe_revocation(7);

    let err = check_revocations(&list, &state).expect_err("옛 목록이 통과했다");
    assert!(matches!(err, Denial::StaleRevocations { .. }), "{err}");

    // 같은 serial 은 받는다 — 같은 목록을 다시 반입하는 것은 정상이다.
    let same = sign(7, &[entry("x", Some("1.0.0"), None, "이유")]);
    let l2 = revocation::parse_signed(&same.anchor, &same.text).expect("읽기");
    check_revocations(&l2, &state).expect("같은 serial 이 막혔다");
}

#[test]
fn 읽을_수_없는_버전은_판정_불가이므로_거부한다() {
    // 통과시키면 `1.0.0-rc1` 로 적는 것만으로 폐기를 피할 수 있다.
    let min = MinVersions::default();
    let state = TrustState::default();
    for raw in ["1.0.0-rc1", "v1.0.0", "1.0", "latest", ""] {
        let err =
            check_plugin("x", raw, None, &min, &state).expect_err("읽을 수 없는 버전이 통과했다");
        assert!(
            matches!(err, Denial::UnreadableVersion { .. }),
            "{raw}: {err}"
        );
    }
}

// ────────────────────────────────────────────── 신선도

#[test]
fn 목록이_없을_때는_모드로_가른다() {
    // 설계-03 §6. 무인 배포에서 폐기된 플러그인이 도는 것은 **조용한 오작동**
    // 이고, 대화형에서 신선도가 낡은 것은 **확신 저하**다.
    assert!(matches!(
        freshness_policy(&Freshness::Absent, true),
        Policy::Stop(_)
    ));
    assert!(matches!(
        freshness_policy(&Freshness::Absent, false),
        Policy::WarnAndProceed(_)
    ));
}

#[test]
fn 목록이_있으면_그대로_진행한다() {
    let f = Freshness::Known {
        issued_at: "2026-08-26T00:00:00Z".into(),
    };
    assert_eq!(freshness_policy(&f, true), Policy::Proceed);
    assert_eq!(freshness_policy(&f, false), Policy::Proceed);
}

#[test]
fn 무인_중단_메시지가_빠져나갈_길을_알려_준다() {
    // 막는 것이 목적이 아니라 **관리자가 신선도에 의식적으로 책임지게** 하는
    // 것이 목적이다 (설계-03 §6). 길을 알려 주지 않으면 그냥 장애물이다.
    let Policy::Stop(msg) = freshness_policy(&Freshness::Absent, true) else {
        panic!("무인에서 멈추지 않았다");
    };
    assert!(
        msg.contains("--revocations"),
        "반입 경로를 말하지 않는다: {msg}"
    );
}
