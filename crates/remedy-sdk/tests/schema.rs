//! P1 검증 — 설계-09 P1 의 "검증" 네 줄에 대응한다.
//!
//! 닫힌 집합의 개수를 시험하는 이유: 설계 문서가 "18종"·"29종" 이라고 못 박았고,
//! 그 수가 조용히 달라지면 `xtask trace` 의 개수 대조도 함께 틀어진다. 두 곳이
//! 같이 틀리면 아무도 눈치채지 못한다.

use remedy_sdk::artifact::{ArtifactKind, ExitCode};
use remedy_sdk::catalog::{
    CaptureFn, Op, Operator, Phase, Subject, DESIGNATED_TOKENS, RETIRED_SUBJECTS,
};
use remedy_sdk::manifest::{PluginManifest, RemoveTarget};
use remedy_sdk::{validate, IMPLEMENTED_THROUGH};

// ───────────────────────────────────────────── 닫힌 집합의 크기

#[test]
fn closed_sets_have_the_declared_size() {
    // D11 로 `network_conn` 을 빼 17, 그 뒤 `firewall_rule` 을 넣어 다시 18.
    // 18 → 19: `package` (2026-10-27 · C-2). 배포판 백포트를 가리는 유일한 길이고
    // **Linux 전용**이다 — dpkg·apk DB 를 파일로 읽는다.
    // 19 → 20: `unix_socket` (2026-11-08 · 코어 1.2.0). Ebury 의 현재 주 탐지법이
    // 추상 소켓 이름이다. **Linux 전용**이고 찾기 전용이다 — `/proc/net/unix` 를 파일로
    // 읽고, 닫는 Op 은 없다(설계-01 D11 의 덧붙임).
    assert_eq!(Subject::ALL.len(), 20, "설계-02 §3 은 subject 20종이다");
    assert_eq!(Op::ALL.len(), 29, "설계-03 §2 는 Op 29종이다");
    // 12 → 14. `version_lt`·`version_gt` 를 더했다 — `lt` 는 수와 RFC3339 시각만
    // 봐서 `8.2.29` 를 견주지 못했고, 고치면 `1.10` 에서 순서가 뒤집힌다.
    // 14 → 15: `pkg_version_lt` (2026-10-27 · C-2 후속). `version_lt` 가 일부러
    // 거절한 **개정 꼬리**가 그쪽의 대상이고, 순서는 dpkg 의 규칙이다. 반대
    // 방향은 두지 않았다 — `not` 이 `>=` 이므로 범위가 둘로 적힌다.
    assert_eq!(Operator::ALL.len(), 15, "설계-02 §4 는 연산자 15종이다");
    // 8 → 9: `last_path` (2026-11-08 · 코어 1.2.0). 공개 보도의 EvilAI 작업이
    // `cmd.exe /c start "" /min "…\node.exe" "…\a.js"` 라 `first_path` 가 `/c` 를 집었다.
    assert_eq!(
        CaptureFn::ALL.len(),
        9,
        "설계-02 §4 는 capture 함수 9종이다"
    );
    assert_eq!(DESIGNATED_TOKENS.len(), 3, "지정 확장 토큰은 3종이다");
    assert_eq!(ArtifactKind::ALL.len(), 4, "아티팩트 봉투는 4종이다");
    assert_eq!(
        ExitCode::ALL.len(),
        8,
        "설계-02 §8 의 종료 코드 7종 + 내부 오류 7 (2026-09-07)"
    );
}

// ───────────────────────────────── OS 기본값 카탈로그 (설계-03 §2, P7)

#[test]
fn every_default_target_is_a_full_registry_path() {
    // 대상이 하이브부터 값 이름까지 온전해야 계획기가 합친 문자열과 맞는다.
    // 한 글자만 달라도 되돌릴 수 있는 대상이 조용히 "없는 대상" 이 된다.
    use remedy_sdk::catalog::{restore_default_for, RESTORE_DEFAULTS};
    for (target, _) in RESTORE_DEFAULTS {
        assert!(
            target.starts_with("HKLM\\") || target.starts_with("HKCU\\"),
            "'{target}' 에 하이브가 없다"
        );
        assert!(
            target.matches('\\').count() >= 3,
            "'{target}' 이 값 이름까지 가리키지 않는다"
        );
        // 조회는 대소문자를 가리지 않는다. 레지스트리가 그렇다.
        assert_eq!(
            restore_default_for(&target.to_ascii_uppercase()),
            restore_default_for(target),
            "'{target}' 조회가 대소문자를 가린다"
        );
    }
    // 없는 것은 없다고 해야 한다 — 여기가 무너지면 임의 값 쓰기가 열린다.
    assert!(restore_default_for("HKLM\\SOFTWARE\\아무거나\\Shell").is_none());
}

#[test]
fn the_catalog_does_not_hold_targets_that_need_a_whole_structure() {
    // **어설픈 부분 복원이 손상을 키운다** (설계-03 §2). `SafeBoot` **하위**처럼
    // 수백 개 항목이 필요한 대상은 탐지·보고만 하고 OS 복구 도구로 넘긴다.
    //
    // 처음에는 `safeboot` 라는 글자를 통째로 막았다. 그것은 설계가 말하는 것보다
    // 넓다 — 규칙은 "구조 전체가 필요한 대상" 이지 "이름에 SafeBoot 이 들어간
    // 대상" 이 아니고, 설계-03 §2 도 담을 것으로 **부팅 구성 플래그**를
    // 명시한다. `SafeBoot\AlternateShell` 은 값 하나이고 기본값이 모든
    // Windows 에서 같다. 막아야 하는 것은 `Minimal`·`Network` 아래의 장치·서비스
    // 클래스 수백 건이다.
    use remedy_sdk::catalog::RESTORE_DEFAULTS;
    for (target, _) in RESTORE_DEFAULTS {
        let t = target.to_ascii_lowercase();
        assert!(
            !t.contains("safeboot\\minimal") && !t.contains("safeboot\\network"),
            "'{target}' 은 값 하나로 복원이 완결되지 않는다"
        );
    }
}

#[test]
fn no_catalog_target_contains_another() {
    // 하나가 다른 하나의 상위이면 앞의 것은 **값이 아니라 키**다. 키를
    // "기본값으로 되돌린다" 는 것은 그 아래 구조를 어떻게 할지 말하지 않은
    // 것이고, 그 침묵이 곧 어설픈 부분 복원이다.
    use remedy_sdk::catalog::RESTORE_DEFAULTS;
    for (a, _) in RESTORE_DEFAULTS {
        for (b, _) in RESTORE_DEFAULTS {
            if a == b {
                continue;
            }
            let (la, lb) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
            assert!(
                !lb.starts_with(&format!("{la}\\")),
                "'{a}' 가 '{b}' 를 품고 있다 — 앞의 것은 값이 아니라 키다"
            );
        }
    }
}

// ───────────────────────────────────────────── 폐기된 subject (설계-01 D11)

#[test]
fn a_retired_subject_is_refused_with_its_reason() {
    // **"모르는 subject" 로는 부족하다.** 작성자는 오타를 의심하고 철자를 고쳐
    // 보다가 결국 같은 제안을 다시 들고 온다. 뺐다는 사실과 대안이 그 자리에서
    // 나와야 한다.
    let e = serde_yaml_ng::from_str::<Subject>("network_conn")
        .expect_err("폐기된 subject 가 그대로 파싱됐다");
    let msg = e.to_string();
    assert!(
        msg.contains("카탈로그에서 빠졌다"),
        "뺐다는 말이 없다: {msg}"
    );
    assert!(msg.contains("판정 입력이 아니다"), "이유가 없다: {msg}");
    assert!(msg.contains("process"), "대안이 없다: {msg}");

    // 폐기 목록에 있는 id 는 **살아 있는 목록에 없어야** 한다. 둘 다에 있으면
    // 역직렬화가 통과시키고 폐기 안내는 영영 나오지 않는다.
    for (id, _) in RETIRED_SUBJECTS {
        assert!(
            Subject::from_id(id).is_none(),
            "'{id}' 가 폐기 목록과 ALL 에 동시에 있다"
        );
    }
}

#[test]
fn an_unknown_subject_gets_the_whole_list() {
    // 하나만 지적하면 다음 것을 지어낸다 (설계-06 §7).
    let e = serde_yaml_ng::from_str::<Subject>("netwrok_conn").expect_err("오타가 통과했다");
    let msg = e.to_string();
    assert!(msg.contains("모르는 subject"), "{msg}");
    for s in Subject::ALL {
        assert!(msg.contains(s.id()), "'{}' 가 목록에 없다: {msg}", s.id());
    }
}

#[test]
fn ids_are_unique_and_round_trip() {
    let mut ids: Vec<&str> = Subject::ALL.iter().map(|s| s.id()).collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(before, ids.len(), "subject id 가 중복된다");

    let mut ops: Vec<&str> = Op::ALL.iter().map(|o| o.id()).collect();
    ops.sort_unstable();
    let before = ops.len();
    ops.dedup();
    assert_eq!(before, ops.len(), "Op id 가 중복된다");

    // id -> 열거형 -> id 왕복.
    for s in Subject::ALL {
        assert_eq!(Subject::from_id(s.id()), Some(s));
    }
    for o in Op::ALL {
        assert_eq!(Op::from_id(o.id()), Some(o));
    }
}

#[test]
fn serde_names_match_catalog_ids() {
    // 열거형의 직렬화 이름과 카탈로그의 id 가 갈라지면 plugin.schema.json 의
    // enum 목록과 subjects.json 이 서로 다른 이름을 갖게 된다.
    for s in Subject::ALL {
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(
            json,
            format!("\"{}\"", s.id()),
            "subject 직렬화 이름 불일치"
        );
    }
    for o in Op::ALL {
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(json, format!("\"{}\"", o.id()), "Op 직렬화 이름 불일치");
    }
    for op in Operator::ALL {
        let json = serde_json::to_string(&op).unwrap();
        assert_eq!(
            json,
            format!("\"{}\"", op.id()),
            "연산자 직렬화 이름 불일치"
        );
    }
}

#[test]
fn exit_codes_are_zero_through_seven() {
    let codes: Vec<u8> = ExitCode::ALL.iter().map(|e| e.code()).collect();
    assert_eq!(
        codes,
        vec![0, 1, 2, 3, 4, 5, 6, 7],
        "설계-02 §8 의 종료 코드 + 7 내부 오류"
    );
}

#[test]
fn incomplete_observation_replaces_no_threat_only() {
    // 6 번은 0 번만 대체한다. 위협을 찾았다면 관측이 불완전해도 그 발견은
    // 유효하다 — 불완전성은 "없다" 를 뒤집을 뿐 "있다" 를 뒤집지 못한다.
    // 이 성질이 깨지면 무인 배포가 실제 감염을 "관측 불완전" 으로 흘려보낸다.
    assert_eq!(ExitCode::IncompleteObservation.code(), 6);
    assert!(
        ExitCode::IncompleteObservation.code() > ExitCode::NoThreat.code(),
        "0 을 대체하는 코드다"
    );
}

#[test]
fn observation_completeness_and_reasons() {
    use remedy_sdk::artifact::Observation;
    use remedy_sdk::catalog::Subject;
    use remedy_sdk::i18n::Lang;

    assert!(Observation::default().is_complete());
    assert!(Observation::default().reasons().is_empty());

    let truncated = Observation {
        truncated: true,
        ..Default::default()
    };
    assert!(!truncated.is_complete());

    let denied = Observation {
        denied_dirs: 2,
        ..Default::default()
    };
    assert!(!denied.is_complete());

    // 수집기가 없는 subject 도 불완전이다. 이것을 빠뜨리면 룰이 영원히
    // 매치하지 않는데 "위협 없음" 이 나온다.
    let uncollected = Observation {
        uncollected_subjects: vec![Subject::Service],
        ..Default::default()
    };
    assert!(!uncollected.is_complete());
    let r = uncollected.reasons();
    assert_eq!(r.len(), 1);
    assert!(
        r[0].contains("service"),
        "어떤 subject 인지 말해야 한다: {r:?}"
    );
    assert!(r[0].contains("P4"), "언제 들어오는지도 말해야 한다: {r:?}");

    // 선언한 루트가 **전부** 없으면 아무 곳도 열어 보지 못한 것이다 (관측 01 D2).
    let void = Observation {
        declared_roots: 2,
        missing_roots: vec!["c:\\a".into(), "c:\\b".into()],
        ..Default::default()
    };
    assert!(!void.is_complete());
    // **두 언어를 다 잰다.** 전역만 보면(라이브러리 시험은 영어다) 한국어 쪽은
    // 사람이 손으로 돌려 볼 때까지 아무도 보지 않는다 — 09-14 에 영어 화면으로
    // 한국어 사유가 나간 경위가 정확히 그것이다.
    //
    // 한국어 문구는 콘솔 기준선(`console-linux.txt`)과 하네스 셋이 읽는다.
    // 여기서 낱말 하나가 바뀌면 그 넷이 함께 흔들린다.
    assert!(void.reasons_in(Lang::Ko)[0].contains("전부 존재하지 않아"));
    assert!(void.reasons_in(Lang::En)[0].contains("missing"));

    // 일부만 없는 것은 불완전이 아니다 — 설치되지 않은 제품의 경로는 당연히 없다.
    let partial = Observation {
        declared_roots: 2,
        missing_roots: vec!["c:\\a".into()],
        ..Default::default()
    };
    assert!(partial.is_complete());
    assert!(partial.reasons().is_empty());

    // 이유는 전부 적는다. 한 줄로 뭉뚱그리면 무엇을 고쳐야 하는지 알 수 없다.
    let all = Observation {
        truncated: true,
        denied_dirs: 1,
        // 경로가 붙어도 **이유의 수는 늘지 않는다** — 이유는 개수로 말하고,
        // 경로는 그 아래에 따로 붙는다 (CLI 의 `denied_lines`).
        denied_paths: vec!["c:\\locked".into()],
        uncollected_subjects: vec![Subject::Service, Subject::Process],
        declared_roots: 1,
        missing_roots: vec!["c:\\a".into()],
        // 규칙이 둘이어도 **이유는 한 줄**이다 — 규칙 이름은 그 줄에 붙는다.
        unevaluated_rules: vec!["rules/a.yar:x".into(), "rules/b.yar:y".into()],
        unreadable_versions: vec!["8.2.29-1ubuntu1".into()],
        unreadable_roots: vec!["\\\\host\\share".into()],
    };
    assert!(!all.is_complete());
    assert_eq!(all.reasons().len(), 8);

    // **YARA 를 재지 못한 것만으로도 불완전하다** (결정 2026-10-26). 이것이
    // 빠지면 판정이 없을 때 종료 코드 0 "위협 없음" 이 나간다.
    let unevaluated = Observation {
        unevaluated_rules: vec!["rules/a.yar:x".into()],
        ..Default::default()
    };
    assert!(!unevaluated.is_complete());
    assert_eq!(unevaluated.reasons().len(), 1);

    // **버전을 견주지 못한 것도 같다** (2026-10-27 · C-1). 꼬리 붙은 버전을
    // *"안 맞았다"* 로 세면 취약한 기계가 종료 0 으로 나갔다(실측). 배포판이
    // 패치한 PHP 가 그 모양이라 가장 흔한 경우다.
    let unreadable = Observation {
        unreadable_versions: vec!["8.2.29-1ubuntu1".into()],
        ..Default::default()
    };
    assert!(!unreadable.is_complete());
    // **점검도 면제가 아니다** — 면제는 `all_roots_missing` 하나뿐이다.
    assert!(!unreadable.is_complete_for_check());
    assert_eq!(unreadable.reasons().len(), 1);
    assert!(
        unreadable.reasons()[0].contains("8.2.29-1ubuntu1"),
        "읽지 못한 값을 적지 않으면 꼬리가 개정인지 사전 배포인지 모른다: {:?}",
        unreadable.reasons()
    );

    // **못 물은 루트 하나로도 불완전하다** (B-9 · 2026-10-27). `missing_roots` 는
    // 전부일 때만 세지만 이쪽은 하나로 족하다 — 열린 루트가 함께 있어도
    // `all_roots_missing()` 이 성립하지 않을 뿐, 못 본 자리는 그대로다.
    let locked = Observation {
        declared_roots: 2,
        unreadable_roots: vec!["c:\\잠긴".into()],
        ..Default::default()
    };
    assert!(!locked.is_complete(), "못 물은 루트를 완전하다고 했다");
    // **점검도 면제가 아니다** — 범위가 이 기계에 없는 것과 못 들여다본 것은 다르다.
    assert!(!locked.is_complete_for_check());
    assert!(!locked.all_roots_missing(), "전제: 전부 없는 것이 아니다");
    assert_eq!(locked.reasons().len(), 1);
    assert!(
        locked.reasons()[0].contains("c:\\잠긴"),
        "자리를 적지 않으면 어디를 못 봤는지 알 수 없다: {:?}",
        locked.reasons()
    );

    // **이 줄만은 길이를 기계가 정한다.** 확장 500개가 전부 꼬리를 달고 있으면
    // 줄 하나가 그만큼 길어진다 — `거부된 자리` 처럼 표본과 *"외 N개"* 로 다룬다
    // (2026-10-27 적대 검증).
    let many = Observation {
        unreadable_versions: (0..9).map(|i| format!("8.2.{i}-x")).collect(),
        ..Default::default()
    };
    for (lang, more) in [
        (remedy_sdk::i18n::Lang::Ko, "외 4개"),
        (remedy_sdk::i18n::Lang::En, "and 4 more"),
    ] {
        let r = &many.reasons_in(lang)[0];
        assert!(r.contains(more), "{lang:?}: 남은 수를 적지 않았다: {r}");
        assert!(r.contains("8.2.4-x"), "{lang:?}: 표본이 다섯이 아니다: {r}");
        assert!(!r.contains("8.2.5-x"), "{lang:?}: 다섯을 넘겼다: {r}");
        // 전수는 **개수로** 말한다 — 표본 수를 전수로 읽으면 안 된다.
        assert!(r.contains('9'), "{lang:?}: 전수가 아니다: {r}");
    }

    // **못 물은 자리도 수를 기계가 정한다** (B-9 · 2026-10-27). 선언 루트는
    // 사람이 적지만 `%ALLUSERPROFILES%` 는 프로필 수만큼(상한 64) 펼쳐지고,
    // 공유가 끊긴 터미널 서버에서는 그것이 전부 이 칸으로 온다. 바로 아래
    // **결론 줄이 밀려 올라가면** 무인 배포가 읽는 것이 사라진다.
    let many_roots = Observation {
        unreadable_roots: (0..8).map(|i| format!("\\\\host{i}\\share")).collect(),
        ..Default::default()
    };
    for (lang, more) in [
        (remedy_sdk::i18n::Lang::Ko, "외 3개"),
        (remedy_sdk::i18n::Lang::En, "and 3 more"),
    ] {
        let r = &many_roots.reasons_in(lang)[0];
        assert!(r.contains(more), "{lang:?}: 남은 수를 적지 않았다: {r}");
        assert!(r.contains("host4"), "{lang:?}: 표본이 다섯이 아니다: {r}");
        assert!(!r.contains("host5"), "{lang:?}: 다섯을 넘겼다: {r}");
        assert!(r.contains('8'), "{lang:?}: 전수가 아니다: {r}");
    }

    // 값 하나가 길면 자른다 — `registry_value.data` 가 그렇게 들어온다.
    let long = Observation {
        unreadable_versions: vec!["가".repeat(200)],
        ..Default::default()
    };
    let r = &long.reasons()[0];
    assert!(r.chars().count() < 120, "줄이 화면을 먹는다: {}", r.len());
    assert!(r.ends_with('…'), "자른 것을 보이지 않았다: {r}");
}

/// 여덟 갈래가 **전부** 두 언어로 나온다.
///
/// 하나라도 한쪽 언어로만 나오면 그 화면을 받은 사람은 왜 종료 코드 6 인지
/// 읽지 못한다. 09-14 에 실제로 그랬다 — 결론 줄은 영어인데 사유는 한국어였다.
#[test]
fn every_reason_speaks_both_languages() {
    use remedy_sdk::artifact::Observation;
    use remedy_sdk::catalog::Subject;
    use remedy_sdk::i18n::Lang;

    /// 완성형 한글이 섞여 있는가. **영어 줄에 이것이 있으면 그게 이 결함이다.**
    fn has_hangul(s: &str) -> bool {
        s.chars().any(|c| ('가'..='힣').contains(&c))
    }

    let all = Observation {
        truncated: true,
        denied_dirs: 2,
        denied_paths: vec!["c:\\locked".into()],
        uncollected_subjects: vec![Subject::Service, Subject::Process],
        declared_roots: 1,
        missing_roots: vec!["c:\\a".into()],
        unevaluated_rules: vec!["rules/a.yar:x".into(), "rules/b.yar:y".into()],
        unreadable_versions: vec!["8.2.29-1ubuntu1".into()],
        unreadable_roots: vec!["\\\\host\\share".into()],
    };
    let ko = all.reasons_in(Lang::Ko);
    let en = all.reasons_in(Lang::En);
    assert_eq!(ko.len(), 8, "{ko:?}");
    assert_eq!(
        en.len(),
        ko.len(),
        "갈래 수가 언어마다 다르다\n{ko:?}\n{en:?}"
    );

    for (k, e) in ko.iter().zip(en.iter()) {
        assert!(has_hangul(k), "한국어 줄이 아니다: {k}");
        assert!(!has_hangul(e), "영어 줄에 한글이 섞였다: {e}");
    }

    // 영어는 수에 따라 낱말이 바뀐다 — 기계가 읽는 줄이 아니라 사람이 읽는
    // 줄이므로 "1 directories" 로 두지 않는다.
    let one = Observation {
        denied_dirs: 1,
        ..Default::default()
    };
    assert!(
        one.reasons_in(Lang::En)[0].contains("1 directory"),
        "{:?}",
        one.reasons_in(Lang::En)
    );
    // 여기도 번호로 짚지 않는다 — 아래 YARA 단정과 같은 이유다.
    assert!(en.iter().any(|s| s.contains("2 directories")), "{en:?}");

    // YARA 갈래도 수에 맞춘다. 그리고 **규칙 이름이 그 줄에 있어야** 사람이
    // 어느 룰의 본문이 빠졌는지 안다.
    let one_rule = Observation {
        unevaluated_rules: vec!["rules/a.yar:x".into()],
        ..Default::default()
    };
    let en1 = &one_rule.reasons_in(Lang::En)[0];
    assert!(en1.contains("1 YARA rule could"), "{en1}");
    assert!(en1.contains("rules/a.yar:x"), "{en1}");
    // 갈래를 **번호로 짚지 않는다** — 새 사유가 앞에 끼면 번호가 밀려
    // 엉뚱한 줄을 단정하게 된다(B-9 가 `unreadable_roots` 를 끼울 때 실제로 밀렸다).
    let en_yara = en
        .iter()
        .find(|s| s.contains("YARA"))
        .unwrap_or_else(|| panic!("영어 사유에 YARA 갈래가 없다: {en:?}"));
    let ko_yara = ko
        .iter()
        .find(|s| s.contains("YARA"))
        .unwrap_or_else(|| panic!("한국어 사유에 YARA 갈래가 없다: {ko:?}"));
    assert!(en_yara.contains("2 YARA rules could"), "{en_yara}");
    assert!(
        ko_yara.contains("rules/a.yar:x") && ko_yara.contains("rules/b.yar:y"),
        "{ko_yara}"
    );
}

// ───────────────────────────────────────────── 스키마에 없는 필드 거부

const MINIMAL: &str = r#"
schema_version: 1
id: sample
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name: { ko: "예시", en: "Sample" }
scan_roots: ["%LOCALAPPDATA%\\Programs"]
subjects: [file]
detect:
  - id: payload
    subject: file
    where:
      - { field: path, op: contains, value: "\\evil\\" }
verdict:
  require: "payload"
"#;

#[test]
fn minimal_manifest_parses() {
    let m: PluginManifest =
        serde_yaml_ng::from_str(MINIMAL).expect("최소 매니페스트는 통과해야 한다");
    assert_eq!(m.id, "sample");
    assert_eq!(m.detect.len(), 1);
}

#[test]
fn unknown_top_level_field_is_rejected() {
    // 오타 난 키가 조용히 무시되면 작성자는 룰이 도는 줄 알지만 실제로는
    // 아무것도 매치하지 않는다.
    let yaml = MINIMAL.replace("verdict:", "scan_root: \"C:\\\\\"\nverdict:");
    let err = serde_yaml_ng::from_str::<PluginManifest>(&yaml)
        .expect_err("스키마에 없는 필드는 거부되어야 한다");
    let msg = err.to_string();
    assert!(
        msg.contains("scan_root"),
        "오류가 문제의 필드 이름을 담아야 한다: {msg}"
    );
}

#[test]
fn unknown_rule_field_is_rejected() {
    let yaml = MINIMAL.replace("    subject: file", "    subject: file\n    scoree: 90");
    assert!(
        serde_yaml_ng::from_str::<PluginManifest>(&yaml).is_err(),
        "규칙 안의 오타도 거부되어야 한다"
    );
}

#[test]
fn unknown_predicate_field_is_rejected() {
    let yaml = MINIMAL.replace(
        "{ field: path, op: contains, value: \"\\\\evil\\\\\" }",
        "{ field: path, op: contains, value: \"x\", typo: 1 }",
    );
    assert!(
        serde_yaml_ng::from_str::<PluginManifest>(&yaml).is_err(),
        "술어 안의 오타도 거부되어야 한다"
    );
}

#[test]
fn unknown_operator_is_rejected() {
    let yaml = MINIMAL.replace("op: contains", "op: sorta_contains");
    assert!(
        serde_yaml_ng::from_str::<PluginManifest>(&yaml).is_err(),
        "닫힌 집합 밖의 연산자는 거부되어야 한다"
    );
}

#[test]
fn unknown_subject_is_rejected() {
    let yaml = MINIMAL.replace("subjects: [file]", "subjects: [registry_hive]");
    assert!(
        serde_yaml_ng::from_str::<PluginManifest>(&yaml).is_err(),
        "닫힌 집합 밖의 subject 는 거부되어야 한다"
    );
}

// ───────────────────────────────────────────── 미구현 항목은 예정 Phase 를 알린다

#[test]
fn every_item_names_the_phase_it_arrives_in() {
    // "지금은 안 된다" 와 "영원히 안 된다" 는 작성자에게 완전히 다른 정보다.
    // 그것을 가르는 것은 카탈로그가 **예정 Phase 를 이름으로** 말한다는 성질이다.
    //
    // 원래 이 시험은 **아직 오지 않은 Op** 을 하나 찾아 그것으로 쟀다. subject 는
    // P4 에서 18종이 전부 열려 쓸 수 없었고, Op 이 마지막으로 남은 축이었다.
    // 2026-08-25 (P10-C) 에 `dir.delete_recursive` 가 열리며 **그 대상마저
    // 사라졌다** — 지금은 카탈로그의 모든 항목이 게이트 안에 있다.
    //
    // 그래서 성질만 남긴다. 새 Op 을 정의하면 그것도 이 검사를 지나야 하고,
    // 그때 "예정 Phase 를 말하는가" 가 다시 실질적인 물음이 된다.
    use remedy_sdk::catalog::Op;
    for op in Op::ALL {
        assert!(
            op.info().implemented_in.as_str().starts_with('P'),
            "'{}' 이 예정 Phase 를 이름으로 말하지 않는다",
            op.id()
        );
    }

    let yaml = format!("{MINIMAL}\nremediate:\n  remove:\n    - {{ ref: payload }}\n");
    let m: PluginManifest = serde_yaml_ng::from_str(&yaml).expect("형태는 유효하다");
    let _ = validate(&m);
}

#[test]
fn the_gate_matches_what_the_catalog_says_is_implemented() {
    // 게이트를 올리는 것은 해당 Phase 의 완료 조건이다. 표면과 어긋나면
    // 작성자에게 거짓말하는 셈이 된다 — **양쪽 방향 다** 그렇다.
    //
    // P4 에 머물러 있는 동안 실행기는 이미 `file.quarantine_only`(P6)를
    // 수행하고 있었고, 가이드는 "현재 코어: P4" 라고 적혀 있었다. 도구를
    // 실제보다 못하다고 광고한 것이다.
    //
    // **손으로 적은 값이어야 한다.** 카탈로그에서 계산하면 자기 자신과 비교하는
    // 항진명제가 되고, 게이트를 올린 사람이 표면(생성물·가이드)을 함께 봤는지
    // 묻지 못한다.
    //
    // 2026-08-25 (P10-C) 에 P8 → P10.
    // 2026-08-27 (P12 마감) 에 P10 → P12 — **Linux 축을 연다.** Windows 축의
    // Op 은 전부 P10 이하라 그쪽 가용성은 바뀌지 않는다.
    assert_eq!(IMPLEMENTED_THROUGH, Phase::P12);

    // P2·P4 가 subject 19종을 전부 열었다 (설계-09 §3.3). 20번째 `unix_socket`(코어 1.2.0)도 P4 표면이다.
    let pending: Vec<&str> = Subject::ALL
        .iter()
        .filter(|s| s.info().implemented_in > IMPLEMENTED_THROUGH)
        .map(|s| s.id())
        .collect();
    assert!(pending.is_empty(), "아직 기다리는 subject: {pending:?}");

    // 연산자 15종도 마찬가지다.
    use remedy_sdk::catalog::Operator;
    let pending: Vec<&str> = Operator::ALL
        .iter()
        .filter(|o| o.info().implemented_in > IMPLEMENTED_THROUGH)
        .map(|o| o.id())
        .collect();
    assert!(pending.is_empty(), "아직 기다리는 연산자: {pending:?}");

    // Op 은 여기서 세지 않는다. **"P6 Op 인데 게이트가 P6 보다 낮은가" 는
    // 항진명제였다** — 두 조건이 서로를 부정해 어떤 카탈로그에서도 참이다.
    //
    // 실제로 재야 하는 것은 "게이트가 허용한 Op 을 실행기가 정말 수행하는가"
    // 이고, 그것은 백엔드가 있어야 잴 수 있어 여기(SDK)서는 불가능하다.
    // `remedy-core/tests/g2_roundtrip.rs` 가 게이트 이하의 모든 Op 에 대해
    // 왕복 사례를 요구하며, 사례가 없는 Op 이 생기면 그쪽이 깨진다.
}

// ───────────────────────────────────────────── 의미 검증

#[test]
fn recursive_delete_without_guard_is_flagged() {
    let yaml = format!(
        "{MINIMAL}\nremediate:\n  remove:\n    - {{ path: \"${{payload.dir}}\", recursive: true }}\n"
    );
    let m: PluginManifest = serde_yaml_ng::from_str(&yaml).expect("형태는 유효하다");
    assert!(
        matches!(
            m.remediate.as_ref().unwrap().remove[0],
            RemoveTarget::Path(_)
        ),
        "경로 대상으로 읽혀야 한다"
    );
    let issues = validate(&m);
    assert!(
        issues.iter().any(|i| i.message.contains("guard")),
        "guard 없는 재귀 삭제는 지적되어야 한다: {issues:?}"
    );
}

#[test]
fn recursive_delete_with_guard_passes() {
    let yaml = format!(
        "{MINIMAL}\nremediate:\n  remove:\n    - {{ path: \"${{payload.dir}}\", recursive: true, guard: payload }}\n"
    );
    let m: PluginManifest = serde_yaml_ng::from_str(&yaml).expect("형태는 유효하다");
    let issues = validate(&m);
    assert!(
        !issues.iter().any(|i| i.message.contains("guard")),
        "guard 가 있으면 지적하지 않아야 한다"
    );
}

#[test]
fn empty_signer_entry_is_flagged() {
    // 주체가 비어 있으면 "서명된 것은 전부 봐준다" 가 되어 2층이 무력해진다.
    let yaml = format!("{MINIMAL}\nsigned_malware:\n  - {{}}\n");
    let m: PluginManifest = serde_yaml_ng::from_str(&yaml).expect("형태는 유효하다");
    assert!(
        validate(&m)
            .iter()
            .any(|i| i.at.starts_with("signed_malware")),
        "빈 서명 주체는 지적되어야 한다"
    );
}

#[test]
fn undeclared_subject_in_rule_is_flagged() {
    let yaml = MINIMAL.replace("subjects: [file]", "subjects: [persistence]");
    let m: PluginManifest = serde_yaml_ng::from_str(&yaml).expect("형태는 유효하다");
    assert!(
        validate(&m).iter().any(|i| i.at == "detect[0].subject"),
        "선언하지 않은 subject 를 쓰면 지적되어야 한다"
    );
}

// ───────────────────────────────────────────── 아티팩트 봉투

#[test]
fn all_four_envelopes_round_trip() {
    use remedy_sdk::artifact::*;

    let header = |kind: ArtifactKind| {
        serde_json::json!({
            "schema_version": 1,
            "kind": kind.id(),
            "run_id": "01J000000000000000000000",
            "created": "2026-08-20T10:50:00Z",
            "host": { "hostname": "h", "os": "windows", "version": "10.0.19045", "arch": "amd64" },
            "core": { "version": "0.0.0", "build": "dev" },
            "plugins": []
        })
    };

    let mut a = header(ArtifactKind::Artifacts);
    a.as_object_mut().unwrap().extend(
        serde_json::json!({
            "collected_at": "2026-08-20T10:50:00Z",
            "collector": { "version": "0.0.0", "bitness": 64, "os_bitness": 64 },
            "scope": { "scan_roots": ["C:\\x"], "subjects": ["file"], "truncated": false },
            "security_products": []
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let env: ArtifactsEnvelope = serde_json::from_value(a).expect("artifacts 봉투");
    assert_eq!(env.kind, ArtifactKind::Artifacts);
    assert!(!env.body.scope.truncated);

    let mut s = header(ArtifactKind::Scan);
    s.as_object_mut().unwrap().extend(
        serde_json::json!({ "evidence": [], "verdicts": [] })
            .as_object()
            .unwrap()
            .clone(),
    );
    let env: ScanEnvelope = serde_json::from_value(s).expect("scan 봉투");
    assert_eq!(env.kind, ArtifactKind::Scan);

    let mut p = header(ArtifactKind::Plan);
    p.as_object_mut().unwrap().extend(
        serde_json::json!({ "actions": [], "verdicts": [] })
            .as_object()
            .unwrap()
            .clone(),
    );
    let env: PlanEnvelope = serde_json::from_value(p).expect("plan 봉투");
    assert_eq!(env.kind, ArtifactKind::Plan);

    let mut r = header(ArtifactKind::Result);
    r.as_object_mut().unwrap().extend(
        serde_json::json!({ "results": [], "reboot_required": false })
            .as_object()
            .unwrap()
            .clone(),
    );
    let env: ResultEnvelope = serde_json::from_value(r).expect("result 봉투");
    assert_eq!(env.kind, ArtifactKind::Result);
}

#[test]
fn action_requires_because() {
    // G7(증거 추적성)은 계획기가 강제하지만, 타입에서도 필수 필드여야 한다.
    // Option 이면 "빈 근거" 가 표현 가능해지고 그 순간 검사할 것이 늘어난다.
    let missing = serde_json::json!({
        "seq": 1, "op": "file.delete", "target": "C:\\x\\y.js",
        "reversible": true, "risk": "medium"
    });
    assert!(
        serde_json::from_value::<remedy_sdk::Action>(missing).is_err(),
        "because 없는 Action 은 역직렬화되지 않아야 한다"
    );
}

// ───────────────────────────────────────────── 생성물

// ───────────────────────────────────────────── 문서의 예시는 테스트다

/// 문서에 실린 EvilAI 예시가 실제로 이 스키마를 통과하는가.
///
/// 예제는 문서가 아니라 테스트다 (설계-06 §5). 통과하지 못하는 예시를 팀에
/// 보여 주면 그것을 따라 쓴 사람이 전부 막힌다.
#[test]
fn evilai_example_in_docs_parses() {
    let doc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/design/예시-EvilAI-플러그인.md");
    let text = std::fs::read_to_string(&doc)
        .unwrap_or_else(|e| panic!("{} 를 읽지 못했다: {e}", doc.display()));

    // 첫 ```yaml 블록이 plugin.yaml 전문이다.
    let start = text.find("```yaml").expect("yaml 블록이 있어야 한다") + "```yaml".len();
    let rest = &text[start..];
    let end = rest.find("```").expect("yaml 블록이 닫혀야 한다");
    let yaml = &rest[..end];

    let m: PluginManifest = serde_yaml_ng::from_str(yaml)
        .unwrap_or_else(|e| panic!("문서의 EvilAI 예시가 스키마를 통과하지 못한다: {e}"));

    assert_eq!(m.id, "evilai-locust");
    assert_eq!(m.detect.len(), 4, "작업·페이로드·Run키·예외목록 네 규칙");
    assert!(!m.allow_removable, "USB 웜이 아니므로 꺼져 있어야 한다");

    let rem = m.remediate.as_ref().expect("치료 절이 있어야 한다");
    let recursive_guarded = rem.remove.iter().any(|t| match t {
        RemoveTarget::Path(p) => p.recursive && p.guard.is_some(),
        _ => false,
    });
    assert!(recursive_guarded, "재귀 삭제에 guard 가 붙어 있어야 한다");

    // P1 시점에서는 모든 subject 가 미구현이므로 그 지적만 남아야 한다.
    // 그 밖의 지적이 있으면 예시 자체에 문제가 있다는 뜻이다.
    let issues = validate(&m);
    let unexpected: Vec<_> = issues.iter().filter(|i| i.available_in.is_none()).collect();
    assert!(
        unexpected.is_empty(),
        "예시에 미구현 외의 문제가 있다: {unexpected:?}"
    );
}

#[test]
fn generated_artifacts_are_deterministic() {
    // 두 번 생성해 다르면 CI 의 재생성 diff 가 매번 실패한다.
    let a = remedy_sdk::generate::all();
    let b = remedy_sdk::generate::all();
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.path, y.path);
        assert_eq!(x.content, y.content, "{} 가 결정적이지 않다", x.path);
    }
}

#[test]
fn generated_catalogs_list_every_item() {
    let all = remedy_sdk::generate::all();
    let subjects = &all
        .iter()
        .find(|g| g.path == "machine/subjects.json")
        .unwrap_or_else(|| {
            panic!(
                "생성물 목록에 machine/subjects.json 가 없다 — generate::all() 의 경로가 바뀌었나"
            )
        })
        .content;
    for s in Subject::ALL {
        assert!(
            subjects.contains(s.id()),
            "subjects.json 에 {} 가 없다",
            s.id()
        );
    }
    let ops = &all
        .iter()
        .find(|g| g.path == "machine/ops.json")
        .unwrap_or_else(|| {
            panic!("생성물 목록에 machine/ops.json 가 없다 — generate::all() 의 경로가 바뀌었나")
        })
        .content;
    for o in Op::ALL {
        assert!(ops.contains(o.id()), "ops.json 에 {} 가 없다", o.id());
    }

    // **필드 전수도 배달되어야 한다.** `00-invariants.md` 가 "subject · 필드 ·
    // 연산자 · Op 는 닫힌 집합이다. 전수는 `machine/` 에 있다" 고 약속하는데
    // 필드가 빠져 있었다. 관측 01 에서 5/5 가 이것을 최대 장애로 지목했고,
    // 없는 필드를 쓴 룰은 문법·경고를 통과하고 **동작에서 조용히 실패**했다.
    let parsed: serde_json::Value = serde_json::from_str(subjects).expect("subjects.json");
    for s in Subject::ALL {
        let entry = parsed["subjects"]
            .as_array()
            .expect("subjects 배열")
            .iter()
            .find(|e| e["id"] == s.id())
            .unwrap_or_else(|| panic!("{} 항목이 없다", s.id()));
        let listed: Vec<&str> = entry["fields"]
            .as_array()
            .unwrap_or_else(|| panic!("{} 에 fields 가 없다 — 약속이 깨졌다", s.id()))
            .iter()
            .map(|v| v.as_str().expect("필드 이름은 문자열"))
            .collect();
        assert_eq!(
            listed,
            s.fields(),
            "{} 의 필드 목록이 카탈로그와 다르다",
            s.id()
        );
    }

    // 사람이 읽는 쪽에도 있어야 한다. 기계 파일만 고치면 가이드를 읽는 사람은
    // 여전히 필드를 모른다.
    let reference = &all
        .iter()
        .find(|g| g.path == "machine/REFERENCE.md")
        .unwrap_or_else(|| {
            panic!(
                "생성물 목록에 machine/REFERENCE.md 가 없다 — generate::all() 의 경로가 바뀌었나"
            )
        })
        .content;
    for s in Subject::ALL {
        for f in s.fields() {
            assert!(
                reference.contains(f),
                "REFERENCE.md 에 {}.{} 가 없다",
                s.id(),
                f
            );
        }
    }
    let schema = &all
        .iter()
        .find(|g| g.path == "machine/plugin.schema.json")
        .unwrap_or_else(|| panic!("생성물 목록에 machine/plugin.schema.json 가 없다 — generate::all() 의 경로가 바뀌었나"))
        .content;
    assert!(
        schema.contains("PluginManifest"),
        "plugin.schema.json 이 매니페스트 타입에서 나와야 한다"
    );
}
