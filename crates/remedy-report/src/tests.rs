//! 렌더러와 자립률.
//!
//! 재는 것의 대부분은 **순서와 존재**다 — 부작용이 목록보다 앞인가, 미룸이
//! 사라지지 않는가, 재지 않은 것을 0으로 접지 않는가.

use super::*;
use remedy_sdk::artifact::{
    Action, ActionResult, ArtifactKind, CoreInfo, Envelope, HostInfo, Observation, PlanBody,
    UserImpact, UserImpactKind,
};
use remedy_sdk::catalog::{Op, Risk};

fn action(seq: u32, op: Op, target: &str) -> Action {
    Action {
        seq,
        op,
        target: Some(target.into()),
        r#match: None,
        max_targets: None,
        max_children: None,
        max_depth: None,
        max_retries: None,
        include_descendants: None,
        sha256: None,
        size: None,
        strip: None,
        because: vec!["e#0".into()],
        backup: None,
        reversible: true,
        risk: Risk::Low,
        user_impact: None,
    }
}

fn plan(actions: Vec<Action>, deferred: Vec<DeferredItem>) -> PlanEnvelope {
    Envelope {
        schema_version: 1,
        kind: ArtifactKind::Plan,
        run_id: "r".into(),
        created: "2026-08-23T00:00:00Z".into(),
        host: HostInfo {
            hostname: "h".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        core: CoreInfo {
            version: "0".into(),
            build: "t".into(),
        },
        plugins: Vec::new(),
        body: PlanBody {
            actions,
            verdicts: vec!["g0".into()],
            observation: Observation::default(),
            deferred,
            verify_after_reboot: false,
            submit_hint: None,
        },
    }
}

/// **아직 오지 않은 Op.** 게이트보다 뒤 Phase 를 가리킨다.
fn defer(op: Op, at: &str) -> DeferredItem {
    DeferredItem {
        at: at.into(),
        op,
        arrives_in: "P15".into(),
        reason: "이 Op 은 아직 이 코어에 없다".into(),
    }
}

/// **있는데 하지 않은 것.** 게이트 안의 Phase 를 가리킨다.
///
/// 2층(신뢰 서명)·5층(허용 목록)·이동식 매체가 이 모양이다. 앞엣것과 같은
/// 목록에 섞이면 운영자가 무엇을 할지 모른다 — 하나는 코어를 올리는 일이고
/// 다른 하나는 서명·목록·매체를 다루는 일이다.
fn held(op: Op, at: &str, reason: &str) -> DeferredItem {
    DeferredItem {
        at: at.into(),
        op,
        arrives_in: "P6".into(),
        reason: reason.into(),
    }
}

// ───────────────────────────────────────────────────── 계획 렌더러

#[test]
fn the_side_effect_comes_before_the_deletion_list() {
    // **설계-01 D5 의 요구다.** 삭제 목록만 보여 주고 부작용을 말하지 않으면
    // 승인은 정보에 근거한 것이 아니다. 목록을 먼저 보여 주면 읽는 사람은
    // 그것만 보고 승인한다.
    let mut a = action(1, Op::BrowserExtRemove, r"C:\ext");
    a.user_impact = Some(UserImpact {
        kind: UserImpactKind::AppTerminate,
        app: Some("Google Chrome".into()),
        note: None,
    });
    let text = render_plan(
        &plan(vec![a], Vec::new()),
        Lang::Ko,
        AfterReboot::Schedulable,
    );

    let impact = text.find("Google Chrome").expect("부작용이 없다");
    let list = text.find("브라우저 확장 제거").expect("목록이 없다");
    assert!(impact < list, "부작용이 목록보다 뒤에 있다\n{text}");
    assert!(text.contains("저장하지 않은 작업"), "{text}");
}

#[test]
fn a_plan_without_side_effects_does_not_invent_one() {
    // 위 시험이 "언제나 한 줄 낸다" 로 통과하면 안 된다.
    let text = render_plan(
        &plan(vec![action(1, Op::FileDelete, r"C:\a")], Vec::new()),
        Lang::Ko,
        AfterReboot::Schedulable,
    );
    assert!(!text.contains("부작용"), "{text}");
}

#[test]
fn deferred_items_are_never_dropped_from_the_render() {
    // **조용히 빠지면 이 계획이 치료의 전부인 것처럼 읽힌다** (설계-03 §2).
    let text = render_plan(
        &plan(
            vec![action(1, Op::FileDelete, r"C:\a")],
            vec![defer(Op::DirDeleteRecursive, "remediate.remove[1]")],
        ),
        Lang::Ko,
        AfterReboot::Schedulable,
    );
    assert!(text.contains("치료의 전부가 아닙니다"), "{text}");
    // 항목은 사람 말(`op_label`)로 나오고 카탈로그 ID 는 화면에 없다 — 매니페스트
    // 자리는 작성자가 찾을 수 있게 괄호 안에 남는다 (2026-09-30).
    assert!(text.contains("폴더 삭제"), "{text}");
    assert!(!text.contains("dir.delete_recursive"), "{text}");
    assert!(text.contains("remediate.remove[1]"), "{text}");
}

/// **위협이 없으면 미룬 것 · 재시작 안내를 말하지 않는다** (2026-11-07 결정 ②). 깨끗한
/// Windows 를 검사할 때마다 *"하지 않기로 했습니다 — 폴더 삭제 (remediate.remove[4]) —
/// capture 가 해소되지 않아"* 와 재시작 안내가 떴다(v1.1.0 기준선 A8). 계획 JSON 은 그대로다.
#[test]
fn a_plan_without_verdicts_says_nothing_about_deferred_or_reboot() {
    let mut p = plan(
        Vec::new(),
        vec![
            defer(Op::DirDeleteRecursive, "remediate.remove[1]"),
            held(
                Op::DirDeleteRecursive,
                "remediate.remove[4]",
                "capture 가 해소되지 않아 대상이 정해지지 않았습니다",
            ),
        ],
    );
    p.body.verdicts.clear();
    p.body.verify_after_reboot = true;
    let text = render_plan(&p, Lang::Ko, AfterReboot::Schedulable);
    for gone in [
        "치료의 전부가 아닙니다",
        "하지 않기로",
        "remediate.remove",
        "재시작",
    ] {
        assert!(!text.contains(gone), "'{gone}' 이 남았다:\n{text}");
    }
    // 같은 계획에 판정이 있으면 셋 다 보인다 — 치료할 때는 조용히 빠지지 않는다.
    p.body.verdicts.push("g0".into());
    let text = render_plan(&p, Lang::Ko, AfterReboot::Schedulable);
    for kept in ["치료의 전부가 아닙니다", "하지 않기로", "재시작"] {
        assert!(text.contains(kept), "'{kept}' 이 없다:\n{text}");
    }
}

/// **그 OS 에 없는 동작은 빠진 치료가 아니다** (2026-11-07 결정 ③). 리눅스에는 서비스 복구
/// 설정이 없다 — CWPdoor 제거의 계획이 그것을 *"이 계획은 치료의 전부가 아닙니다"* 로 알렸다.
/// 그 갈래만 빠지고, 정말 기다리는 것은 그대로 보인다.
#[test]
fn an_op_this_os_does_not_have_is_not_a_missing_treatment() {
    let na = DeferredItem {
        at: "remediate.remove[0]".into(),
        op: Op::ServiceClearRecovery,
        arrives_in: "linux 에는 개념이 없습니다".into(),
        reason: "subject 'service' 를 제거하는 데 필요한데 이 코어에 없습니다".into(),
    };
    let only_na = render_plan(
        &plan(
            vec![action(1, Op::FileQuarantineOnly, "/usr/local/x")],
            vec![na.clone()],
        ),
        Lang::Ko,
        AfterReboot::Schedulable,
    );
    assert!(!only_na.contains("치료의 전부가 아닙니다"), "{only_na}");
    assert!(!only_na.contains("서비스 복구 설정 해제"), "{only_na}");
    let mixed = render_plan(
        &plan(
            vec![action(1, Op::FileQuarantineOnly, "/usr/local/x")],
            vec![na, defer(Op::DirDeleteRecursive, "remediate.remove[1]")],
        ),
        Lang::Ko,
        AfterReboot::Schedulable,
    );
    assert!(mixed.contains("1건은 아직 지원하지 않는 동작"), "{mixed}");
    assert!(!mixed.contains("서비스 복구 설정 해제"), "{mixed}");
    // 개념은 있는데 닫아 둔 것(재귀 삭제 — 가드가 없다)은 같은 꼴로 미뤄도 숨기지 않는다.
    // 숨기면 덜 된 치료가 완전한 계획처럼 보인다(설계-03 §2).
    let closed = render_plan(
        &plan(
            vec![action(1, Op::FileQuarantineOnly, "/usr/local/x")],
            vec![DeferredItem {
                at: "remediate.remove[1]".into(),
                op: Op::DirDeleteRecursive,
                arrives_in: "linux 에는 개념이 없습니다".into(),
                reason: "이 Op 은 지금 수행할 수 없습니다".into(),
            }],
        ),
        Lang::Ko,
        AfterReboot::Schedulable,
    );
    assert!(closed.contains("치료의 전부가 아닙니다"), "{closed}");
    assert!(closed.contains("폴더 삭제"), "{closed}");
}

#[test]
fn 기다리는_것과_하지_않기로_한_것이_섞이지_않는다() {
    // **운영자가 할 일이 다르다.** 앞은 코어를 올리는 일이고, 뒤는 서명·허용
    // 목록·매체를 다루는 일이다.
    //
    // 한동안 섞여 있었다 — 2층(신뢰 서명)이 선 뒤로 그 항목들이 *"아직 이
    // 코어에 없는 Op 을 요구한다"* 로 보고됐는데 그 Op 은 있었다. 5층(허용
    // 목록)이 오며 같은 자리가 다시 드러났다 (2026-08-29).
    let text = render_plan(
        &plan(
            vec![action(1, Op::FileDelete, r"C:\a")],
            vec![
                defer(Op::DirDeleteRecursive, "remediate.remove[1]"),
                held(
                    Op::FileQuarantineOnly,
                    "remediate.remove[2]",
                    "설계-03 §3 5층 — 조직 허용 목록에 있어 삭제하지 않는다: 사내 빌드 도구",
                ),
            ],
        ),
        Lang::Ko,
        AfterReboot::Schedulable,
    );

    assert!(text.contains("치료의 전부가 아닙니다"), "{text}");
    assert!(text.contains("하지 않기로"), "{text}");
    // 각 항목이 **제 갈래에** 있어야 한다.
    let (waiting, rest) = text.split_once("하지 않기로").expect("두 갈래");
    assert!(
        waiting.contains("폴더 삭제") && !waiting.contains("파일 격리"),
        "기다리는 쪽에 엉뚱한 것이 있다:\n{text}"
    );
    assert!(
        rest.contains("파일 격리") && rest.contains("사내 빌드 도구"),
        "하지 않기로 한 쪽에 사유가 없다:\n{text}"
    );
}

#[test]
fn 하지_않기로_한_것만_있으면_없는_op_문구가_나오지_않는다() {
    // **없는 것을 없다고 말하지 않는다.** 허용 목록만으로 빠진 계획에
    // "이 코어에 없는 Op" 이 붙으면 운영자가 코어를 올리러 간다.
    let text = render_plan(
        &plan(
            Vec::new(),
            vec![held(
                Op::FileQuarantineOnly,
                "remediate.remove[0]",
                "설계-03 §3 5층 — 조직 허용 목록에 있어 삭제하지 않는다: 사내 빌드 도구",
            )],
        ),
        Lang::Ko,
        AfterReboot::Schedulable,
    );
    assert!(!text.contains("없는 Op"), "{text}");
    assert!(text.contains("하지 않기로"), "{text}");
}

#[test]
fn both_languages_render_and_neither_leaks_the_other() {
    // **한국어·영어 출력이 모두 나온다** (설계-09 P9). 한쪽만 고치는 사고를
    // 막으려면 둘 다 실제로 돌려 봐야 한다.
    let mut a = action(1, Op::BrowserExtRemove, r"C:\ext");
    a.user_impact = Some(UserImpact {
        kind: UserImpactKind::AppTerminate,
        app: Some("Chrome".into()),
        note: None,
    });
    let p = plan(
        vec![a],
        vec![
            defer(Op::DirDeleteRecursive, "x"),
            held(Op::FileQuarantineOnly, "y", "조직 허용 목록"),
        ],
    );

    let ko = render_plan(&p, Lang::Ko, AfterReboot::Schedulable);
    let en = render_plan(&p, Lang::En, AfterReboot::Schedulable);
    assert!(
        ko.contains("부작용") && ko.contains("치료의 전부가 아닙니다"),
        "{ko}"
    );
    assert!(
        en.contains("Side effects") && en.contains("not the whole treatment"),
        "{en}"
    );

    // **렌더러가 만든 문장은 전부 번역된다.** 산출물이 실어 온 진단문
    // (`DeferredItem.reason` 등)은 그대로 지난다 — 아래 시험이 그 경계를
    // 따로 잰다.
    let frame: String = en
        .lines()
        .filter(|l| !l.contains(" — "))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !frame.chars().any(|c| ('가'..='힣').contains(&c)),
        "렌더러가 만든 문장에 한글이 남았다:\n{frame}"
    );
}

#[test]
fn the_after_reboot_check_is_promised_only_where_it_can_be_kept() {
    // **지킬 수 없는 약속을 하지 않는다** (P12 D4). `hexcfg-r1` 채점 5 에서 리눅스
    // 컨테이너의 계획 화면이 약속하고, 실행 뒤에 "예약하지 못했다" 로 바로잡았다 —
    // 승인하는 순간에는 거짓이었다.
    let mut p = plan(vec![action(1, Op::FileDelete, r"C:\a")], Vec::new());
    p.body.verify_after_reboot = true;

    // 걸 수 있으면 약속한다 — **Windows 화면 그대로다** (화면 기준선의 네 자리).
    let ko = render_plan(&p, Lang::Ko, AfterReboot::Schedulable);
    assert!(
        ko.contains("\n  * 치료를 마친 뒤 이 PC 를 재시작하면 자동으로 한 번 더 검사합니다.\n"),
        "{ko}"
    );
    let en = render_plan(&p, Lang::En, AfterReboot::Schedulable);
    assert!(
        en.contains("\n  * After you restart this PC, one more check runs automatically.\n"),
        "{en}"
    );

    // 걸 수 없으면 약속하지 않고 이유와 할 일을 말한다. **문구는 이유를 가리지
    // 않는다** — 기계의 사실(systemd)일 수도, 부른 명령이 플러그인 경로를 몰라
    // 요청을 만들 수 없다는 사실일 수도 있다 (결정 자료 나1). "이 기계에서는"
    // 이라고 하면 뒤의 경우에 거짓이 된다.
    let why = "systemd 가 이 기계의 init 이 아니다";
    let ko = render_plan(&p, Lang::Ko, AfterReboot::Unavailable(why));
    assert!(
        !ko.contains("자동으로 한 번 더 검사합니다"),
        "걸 수 없는데 약속했다:\n{ko}"
    );
    assert!(
        ko.contains(&format!(
            "\n  * 재시작 뒤 자동 재검사를 걸 수 없습니다 ({why}).\n"
        )),
        "이유를 말하지 않았다:\n{ko}"
    );
    assert!(
        ko.contains("직접 부를 명령을 알려 드립니다"),
        "사람이 할 일을 말하지 않았다:\n{ko}"
    );

    let why = "systemd is not this machine's init";
    let en = render_plan(&p, Lang::En, AfterReboot::Unavailable(why));
    assert!(!en.contains("runs automatically"), "{en}");
    assert!(
        en.contains(&format!(
            "\n  * The automatic check after a restart cannot be scheduled ({why}).\n"
        )),
        "{en}"
    );
    assert!(
        !en.chars().any(|c| ('가'..='힣').contains(&c)),
        "영어 화면에 한글이 있다:\n{en}"
    );
}

#[test]
fn a_plan_that_does_not_ask_says_nothing_about_the_restart_check() {
    // 묻지 않은 것을 말하지 않는다 — 걸 수 없는 기계라도 계획이 원하지 않으면 조용하다.
    let p = plan(vec![action(1, Op::FileDelete, r"C:\a")], Vec::new());
    let ko = render_plan(&p, Lang::Ko, AfterReboot::Unavailable("x"));
    assert!(
        !ko.contains("재검사") && !ko.contains("한 번 더 검사"),
        "{ko}"
    );
}

#[test]
fn text_carried_by_the_artifact_passes_through_untranslated() {
    // **경계를 시험으로 못 박는다.** 렌더러는 제가 만든 문장만 번역한다.
    // `DeferredItem.reason` · `ActionResult.error` · `ScanBody.issues` 는
    // 계획기·실행기·평가기가 **쓴 그대로**의 자료이고, 임의 문자열을 번역할
    // 방법은 없다.
    //
    // 이것은 알려진 한계이고 감추지 않는다 — 진단문 전체를 구조화된 코드로
    // 바꾸는 것은 SDK 전반의 결정이라 P9 의 크기가 아니다 (설계-09 P9).
    let p = plan(Vec::new(), vec![defer(Op::DirDeleteRecursive, "x")]);
    let en = render_plan(&p, Lang::En, AfterReboot::Schedulable);
    assert!(
        en.contains("이 Op 은 아직 이 코어에 없다"),
        "산출물의 사유가 사라졌다 — 지나가되 버리지는 않는다:\n{en}"
    );

    let r = ResultBody {
        results: vec![ActionResult {
            seq: 1,
            op: Op::FileDelete,
            outcome: ActionOutcome::Failed,
            error: Some("잠겨 있다".into()),
        }],
        quarantine: None,
        reboot_required: false,
    };
    assert!(render_result(&r, Lang::En).contains("잠겨 있다"));
}

#[test]
fn every_impact_kind_has_a_sentence_in_both_languages() {
    // 새 종류가 늘면 여기서 막힌다. 문구가 없으면 사용자는 부작용을 못 본다.
    for k in UserImpactKind::ALL {
        for lang in [Lang::Ko, Lang::En] {
            let s = impact_line(
                &UserImpact {
                    kind: k,
                    app: None,
                    note: None,
                },
                lang,
            );
            assert!(s.len() > 5, "{:?}/{:?}: 문구가 비었다", k, lang.id());
        }
    }
}

#[test]
fn an_unknown_language_falls_back_instead_of_failing() {
    // 알 수 없는 로캘에 오류를 내면 로캘이 다른 기계에서 도구가 아예 안 뜬다.
    assert_eq!(Lang::parse("en-US"), Lang::En);
    assert_eq!(Lang::parse("ko_KR"), Lang::Ko);
    // 기본은 영어다 (2026-09-06 결정) — 모르는 로캘은 영어로 간다.
    assert_eq!(Lang::parse("fr"), Lang::En);
    assert_eq!(Lang::parse(""), Lang::En);
}

// ───────────────────────────────────────────────────── 결과 리포트

#[test]
fn a_failure_reason_survives_into_the_result() {
    // **왜 안 했는지가 왜 했는지보다 중요할 때가 있다** (설계-03 §7).
    let r = ResultBody {
        results: vec![ActionResult {
            seq: 1,
            op: Op::FileDelete,
            outcome: ActionOutcome::Failed,
            error: Some("잠겨 있다".into()),
        }],
        quarantine: None,
        reboot_required: false,
    };
    let text = render_result(&r, Lang::Ko);
    assert!(text.contains("잠겨 있다"), "{text}");
    assert!(text.contains("실패 1"), "{text}");
}

#[test]
fn a_scheduled_deletion_says_the_file_is_still_there() {
    // **예약은 파괴가 아니다.** 말하지 않으면 사용자는 치료가 끝났다고 읽는다.
    let r = ResultBody {
        results: Vec::new(),
        quarantine: None,
        reboot_required: true,
    };
    assert!(render_result(&r, Lang::Ko).contains("아직 그 자리에 있습니다"));
    assert!(render_result(&r, Lang::En).contains("still there"));
}

// ───────────────────────────────────────────────────── 자립률

#[test]
fn a_plan_with_no_deferrals_counts_as_self_sufficient() {
    let clean = plan(vec![action(1, Op::FileDelete, r"C:\a")], Vec::new());
    let blocked = plan(
        vec![action(1, Op::FileDelete, r"C:\a")],
        vec![defer(Op::DirDeleteRecursive, "x")],
    );
    let s = self_sufficiency([&clean, &blocked]);
    assert_eq!((s.plans, s.self_sufficient), (2, 1));
    assert_eq!(s.rate(), Some(0.5));
}

#[test]
fn nothing_measured_is_not_zero_percent() {
    // **재지 않은 것과 0인 것은 다르다** (설계-00 §5-1). 0% 로 접으면 표본이
    // 없는 실행이 "자립률 바닥" 으로 읽힌다.
    let s = self_sufficiency(std::iter::empty());
    assert_eq!(s.rate(), None);
    assert!(render_self_sufficiency(&s, Lang::Ko).contains("잰 것이 없습니다"));
}

#[test]
fn the_blocking_ops_are_ranked_so_the_next_thing_to_build_is_obvious() {
    // **다음에 무엇을 코어에 넣을지가 여기서 나온다** (설계-01 D10).
    //
    // **개수 순과 이름 순이 어긋나게 둔다.** 처음엔 많이 막은 쪽이 알파벳도
    // 앞이라 이름 순으로 정렬해도 같은 답이 나왔고, 역검증에서 그렇게 샜다 —
    // 시험이 아무것도 재지 않고 있었다.
    //
    // `dir.delete_recursive` < `file.delete_stream` 이므로, 뒤엣것을 더 많이
    // 막게 하면 두 정렬이 갈린다.
    let a = plan(Vec::new(), vec![defer(Op::FileDeleteStream, "x")]);
    let b = plan(Vec::new(), vec![defer(Op::FileDeleteStream, "y")]);
    let c = plan(Vec::new(), vec![defer(Op::DirDeleteRecursive, "z")]);
    let s = self_sufficiency([&a, &b, &c]);
    assert_eq!(
        s.blocking_ops,
        vec![
            ("file.delete_stream".to_string(), 2),
            ("dir.delete_recursive".to_string(), 1),
        ],
        "많이 막은 것이 앞이어야 한다 (이름 순이 아니라)"
    );
    assert_eq!(s.by_shortfall, vec![(Shortfall::NoOp, 3)]);
}

#[test]
fn the_render_names_the_categories_in_both_languages() {
    let p = plan(Vec::new(), vec![defer(Op::DirDeleteRecursive, "x")]);
    let s = self_sufficiency([&p]);
    let ko = render_self_sufficiency(&s, Lang::Ko);
    let en = render_self_sufficiency(&s, Lang::En);
    assert!(ko.contains("삭제·변경 동작이 없습니다"), "{ko}");
    assert!(en.contains("no removal or change action"), "{en}");
    assert!(
        !en.chars().any(|c| ('가'..='힣').contains(&c)),
        "영어 출력에 한글이 남았다:\n{en}"
    );
}

#[test]
fn every_shortfall_has_a_label_in_both_languages() {
    for k in Shortfall::ALL {
        for lang in [Lang::Ko, Lang::En] {
            assert!(k.label(lang).len() > 3, "{:?}/{}", k, lang.id());
        }
    }
}

// ─────────────────────────────────────────── 고객 화면 (2026-09-06)

#[test]
fn every_op_has_a_label_in_both_languages() {
    for op in Op::ALL {
        for lang in [Lang::Ko, Lang::En] {
            let l = op_label(op, lang);
            assert!(!l.trim().is_empty(), "{}: {lang:?}", op.id());
            assert!(
                !l.contains('.'),
                "{}: 카탈로그 ID 가 새어 나왔다: {l}",
                op.id()
            );
        }
    }
}

#[test]
fn result_line_keeps_the_phrase_the_harness_reads() {
    use remedy_sdk::artifact::ExitCode as C;
    assert!(result_line(C::Remediated, 6, Lang::Ko, None).contains("6건 수행 완료"));
    assert!(result_line(C::NoThreat, 0, Lang::En, None).contains("No threat"));
}

/// 확인 필요만 남은 점검(`verdict.unconfirmed` · 2026-11-09)은 *"다 보지 못해"* 가 아니라 *"확인이
/// 필요합니다"* 다. 그 밖의 조합은 [`result_line`] 과 **한 글자도 같다**.
#[test]
fn a_review_only_check_says_review_needed_and_nothing_else_changes() {
    use remedy_sdk::artifact::ExitCode as C;
    use remedy_sdk::manifest::PluginKind;
    let check = Some(PluginKind::Check);
    for lang in [Lang::Ko, Lang::En] {
        let review = result_line_for(C::IncompleteObservation, 0, lang, check, true);
        assert_eq!(review, review_line(lang));
        assert!(!review.contains("다 보지 못해"), "{review}");
        // 거짓이면 전과 같다.
        assert_eq!(
            result_line_for(C::IncompleteObservation, 0, lang, check, false),
            result_line(C::IncompleteObservation, 0, lang, check)
        );
        // 점검이 아니거나 6 이 아니면 `review` 를 보지 않는다.
        for (code, kind) in [
            (C::IncompleteObservation, None),
            (C::FoundNotRemediated, check),
            (C::NoThreat, check),
        ] {
            assert_eq!(
                result_line_for(code, 0, lang, kind, true),
                result_line(code, 0, lang, kind),
                "{code:?} {kind:?}"
            );
        }
    }
    assert!(review_line(Lang::Ko).starts_with("확인이 필요합니다"));
    assert!(!review_line(Lang::En)
        .chars()
        .any(|c| ('가'..='힣').contains(&c)));
}

/// 확인 필요 항목은 **사유가 짚은 그룹의 증거**만 적고, 짚은 증거가 없으면 아무것도 적지 않는다 —
/// 판정 쪽처럼 흔적 전부로 대신하면 확인할 것과 상관없는 줄이 섞인다.
#[test]
fn unconfirmed_items_list_only_the_noted_groups() {
    use remedy_sdk::artifact::{Evidence, EvidenceGroup, UnconfirmedNote};
    let ev = |id: &str, path: &str| Evidence {
        id: id.into(),
        rule: "present".into(),
        subject: remedy_sdk::catalog::Subject::File,
        score: None,
        target: serde_json::json!({ "path": path }),
        captures: Default::default(),
        matched: Vec::new(),
    };
    let group = |id: &str, evidence: &[&str]| EvidenceGroup {
        id: id.into(),
        evidence: evidence.iter().map(|s| s.to_string()).collect(),
        captures: Default::default(),
        verdict: false,
        excluded_reason: None,
    };
    let evidence = vec![ev("e0", "/usr/bin/php"), ev("e1", "/opt/other/php")];
    let groups = vec![group("g0", &["e0"]), group("g1", &["e1"])];
    let note = UnconfirmedNote {
        why: [("ko".to_string(), "까닭".to_string())].into(),
        groups: vec!["g0".to_string()],
    };
    let lines = unconfirmed_findings(&evidence, &groups, &[note], Lang::Ko, 10);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("/usr/bin/php"), "{lines:?}");
    // 짚은 그룹이 없으면 빈 목록이다 — 흔적 전부로 대신하지 않는다.
    let none = UnconfirmedNote {
        why: Default::default(),
        groups: vec!["g9".to_string()],
    };
    assert!(unconfirmed_findings(&evidence, &groups, &[none], Lang::Ko, 10).is_empty());
}

#[test]
fn a_check_plugin_says_vulnerable_not_threat() {
    use remedy_sdk::artifact::ExitCode as C;
    use remedy_sdk::manifest::PluginKind;
    let check = Some(PluginKind::Check);

    // B-2. 점검에서 2 는 *"감염됐다"* 가 아니라 *"취약하다"* 다.
    for (code, ko_has, ko_hasnt) in [
        (C::NoThreat, "취약한 곳을 찾지 못했습니다", "위협"),
        (C::FoundNotRemediated, "취약합니다", "치료"),
        (C::IncompleteObservation, "'취약하지 않다'", "위협 없음"),
    ] {
        let ko = result_line(code, 0, Lang::Ko, check);
        assert!(ko.contains(ko_has), "{code:?}: {ko}");
        assert!(
            !ko.contains(ko_hasnt),
            "{code:?} 에 치료 어휘가 남았다: {ko}"
        );
        let en = result_line(code, 0, Lang::En, check);
        assert!(
            en.to_lowercase().contains("vulnerab"),
            "{code:?} 영어가 점검 어휘가 아니다: {en}"
        );
        assert!(
            !en.contains("threat"),
            "{code:?} 영어에 threat 가 남았다: {en}"
        );
    }

    // **치료의 문구는 한 글자도 바뀌지 않는다** — 기준선 4벌과 하네스가 그 꼴이다.
    for code in [
        C::NoThreat,
        C::Remediated,
        C::FoundNotRemediated,
        C::PartialFailure,
        C::UsageError,
        C::GuardStop,
        C::IncompleteObservation,
        C::InternalError,
    ] {
        for lang in [Lang::Ko, Lang::En] {
            assert_eq!(
                result_line(code, 3, lang, None),
                result_line_before_b2(code, 3, lang),
                "{code:?} {lang:?} 의 치료 문구가 바뀌었다"
            );
        }
    }

    // 점검이 쓰지 않는 코드는 치료와 같은 문자열이다 — 갈래가 셋뿐임을 고정한다.
    for code in [
        C::Remediated,
        C::PartialFailure,
        C::UsageError,
        C::GuardStop,
        C::InternalError,
    ] {
        for lang in [Lang::Ko, Lang::En] {
            assert_eq!(
                result_line(code, 3, lang, check),
                result_line(code, 3, lang, None),
                "{code:?} {lang:?} 가 점검에서 갈라졌다"
            );
        }
    }
}

/// B-2 **전**의 문자열. 치료 경로가 바뀌지 않았음을 재는 고정 사본이다 —
/// 같은 함수를 자기 자신과 견주면 아무것도 재지 못한다.
fn result_line_before_b2(code: remedy_sdk::artifact::ExitCode, done: usize, lang: Lang) -> String {
    use remedy_sdk::artifact::ExitCode as C;
    match (code, lang) {
        (C::NoThreat, Lang::Ko) => "위협이 발견되지 않았습니다.".to_string(),
        (C::NoThreat, Lang::En) => "No threat was found.".to_string(),
        (C::Remediated, Lang::Ko) => format!("위협 발견, 치료 완료 ({done}건 수행 완료)"),
        (C::Remediated, Lang::En) => format!("Threat found, treated ({done} action(s) done)"),
        (C::FoundNotRemediated, Lang::Ko) => "위협 발견, 치료하지 않았습니다.".to_string(),
        (C::FoundNotRemediated, Lang::En) => "Threat found, not treated.".to_string(),
        (C::PartialFailure, Lang::Ko) => format!("일부 실패 ({done}건 수행 완료)"),
        (C::PartialFailure, Lang::En) => format!("Partial failure ({done} action(s) done)"),
        (C::UsageError, Lang::Ko) => "입력 오류".to_string(),
        (C::UsageError, Lang::En) => "Usage error".to_string(),
        (C::GuardStop, Lang::Ko) => "안전 가드가 중단했습니다.".to_string(),
        (C::GuardStop, Lang::En) => "Stopped by a safety guard.".to_string(),
        (C::IncompleteObservation, Lang::Ko) => {
            "관측이 불완전해 '위협 없음' 을 말할 수 없습니다.".to_string()
        }
        (C::IncompleteObservation, Lang::En) => {
            "Observation incomplete: cannot declare 'no threat'.".to_string()
        }
        (C::InternalError, Lang::Ko) => "내부 오류로 멈췄습니다.".to_string(),
        (C::InternalError, Lang::En) => "Stopped by an internal error.".to_string(),
    }
}

#[test]
fn pretty_time_is_the_alyac_shape() {
    assert_eq!(
        pretty_time("2026-09-06T08:16:06Z"),
        "2026-09-06 08:16:06 UTC"
    );
    assert_eq!(pretty_time("garbage"), "garbage");
}

#[test]
fn banner_names_the_product_and_the_plugin() {
    let b = Banner {
        core_version: "1.0.0",
        plugin_name: Some("EvilAI(Locust) 제거"),
        plugin_id: Some("evilai-locust"),
        plugin_version: Some("0.1.0"),
        started_at: "2026-09-06T08:16:06Z",
        hostname: "PC-1",
        os: "windows",
    };
    let ko = render_banner(&b, Lang::Ko);
    assert!(
        ko.contains(brand::PRODUCT_KO) && ko.contains("evilai-locust 0.1.0"),
        "{ko}"
    );
    let en = render_banner(&b, Lang::En);
    assert!(
        en.contains(brand::PRODUCT_EN) && en.contains("Machine"),
        "{en}"
    );
    assert!(!en.contains("시작"), "{en}");
}

#[test]
fn closing_carries_undo_and_copyright() {
    let c = Closing {
        code: remedy_sdk::artifact::ExitCode::Remediated,
        done: 3,
        elapsed_secs: 75,
        run_id: Some("run-1"),
        quarantine: Some("q.rq"),
        journal: None,
        kind: None,
        state_dir: None,
        review: false,
    };
    let ko = render_closing(&c, Lang::Ko);
    assert!(ko.contains("remedy restore --run run-1"), "{ko}");
    assert!(
        ko.contains("1분 15초") && ko.contains("ESTsecurity Corp."),
        "{ko}"
    );
    // 기본 자리면 상태 폴더를 붙이지 않는다 — 무인 배포 출력이 전과 같다(I1).
    assert!(!ko.contains("--state-dir"), "{ko}");
}

/// 기본이 아닌 상태 폴더(메뉴의 `<받은 폴더>/state` · `--state-dir`)면 두 안내가 그 폴더를
/// 함께 적는다 — 빼면 그 줄을 그대로 친 사람이 종료 4 로 끝난다(2026-11-07 실측).
#[test]
fn closing_names_a_non_default_state_dir_on_both_hints() {
    let c = Closing {
        code: remedy_sdk::artifact::ExitCode::Remediated,
        done: 1,
        elapsed_secs: 1,
        run_id: Some("run-1"),
        quarantine: None,
        journal: None,
        kind: None,
        state_dir: Some("\"C:\\remedy x\\state\""),
        review: false,
    };
    let ko = render_closing(&c, Lang::Ko);
    assert!(
        ko.contains("remedy restore --run run-1 --state-dir \"C:\\remedy x\\state\""),
        "{ko}"
    );
    assert!(
        ko.contains("remedy support-bundle --run run-1 --state-dir \"C:\\remedy x\\state\""),
        "{ko}"
    );
}

#[test]
fn labels_align_by_display_width_in_both_languages() {
    // 한글은 두 칸이다. 콜론이 같은 열에 오지 않으면 표가 아니다.
    let c = Closing {
        code: remedy_sdk::artifact::ExitCode::Remediated,
        done: 1,
        elapsed_secs: 1,
        run_id: Some("r"),
        quarantine: Some("q"),
        journal: Some("j"),
        kind: None,
        state_dir: None,
        review: false,
    };
    for lang in [Lang::Ko, Lang::En] {
        let text = render_closing(&c, lang);
        let cols: std::collections::BTreeSet<usize> = text
            .lines()
            .filter(|l| l.contains(" : "))
            .map(|l| {
                let head = &l[..l.find(" : ").unwrap()];
                super::display_width(head)
            })
            .collect();
        assert_eq!(cols.len(), 1, "{lang:?}: 콜론 열이 갈린다\n{text}");
    }
}

#[test]
fn sub_second_runs_do_not_say_zero() {
    let c = Closing {
        code: remedy_sdk::artifact::ExitCode::NoThreat,
        done: 0,
        elapsed_secs: 0,
        run_id: None,
        quarantine: None,
        journal: None,
        kind: None,
        state_dir: None,
        review: false,
    };
    assert!(render_closing(&c, Lang::Ko).contains("1초 미만"));
    assert!(render_closing(&c, Lang::En).contains("under 1s"));
}

// ───────────────────────────────────────── 점검 결과 항목 (2026-10-28)
//
// 점검 화면이 `취약 N건` 이라는 **수만** 내고 끝나던 자리다. 재는 것은 둘 —
// **subject 20종이 전부 이름을 낸다**(빈 줄이 나가면 사용자가 아무것도 못 한다)
// 와 **잘리는 갈래가 실제로 돈다**(안 재면 죽은 코드다).

use remedy_sdk::artifact::{Evidence, EvidenceGroup, MatchedPredicate};
use remedy_sdk::catalog::Subject;

fn ev(id: &str, subject: Subject, target: serde_json::Value) -> Evidence {
    Evidence {
        id: id.to_string(),
        rule: "r".to_string(),
        subject,
        score: None,
        target,
        captures: Default::default(),
        matched: Vec::new(),
    }
}

fn group(id: &str, evidence: &[&str], verdict: bool) -> EvidenceGroup {
    EvidenceGroup {
        id: id.to_string(),
        evidence: evidence.iter().map(|s| s.to_string()).collect(),
        captures: Default::default(),
        verdict,
        excluded_reason: None,
    }
}

/// **20종 전부가 이름을 낸다.** 카탈로그가 적은 식별 필드를 주면 그것이 나오고,
/// 모르는 모양을 주어도 subject 의 id 로 떨어진다 — 빈 줄은 없다.
#[test]
fn every_subject_names_its_target() {
    let cases: &[(Subject, serde_json::Value, &str)] = &[
        (
            Subject::File,
            serde_json::json!({"path": "C:\\a.exe"}),
            "C:\\a.exe",
        ),
        (
            Subject::Shortcut,
            serde_json::json!({"path": "/s.lnk"}),
            "/s.lnk",
        ),
        (
            Subject::StructuredConfig,
            serde_json::json!({"path": "/c.json"}),
            "/c.json",
        ),
        (
            Subject::TextConfig,
            serde_json::json!({"path": "/etc/x.conf", "line_no": 4}),
            "/etc/x.conf:4",
        ),
        (
            Subject::Package,
            serde_json::json!({"name": "php8.1-cli"}),
            "php8.1-cli",
        ),
        (Subject::Service, serde_json::json!({"name": "svc"}), "svc"),
        (
            Subject::FirewallRule,
            serde_json::json!({"name": "fw"}),
            "fw",
        ),
        (
            Subject::Persistence,
            serde_json::json!({"name": "Locust"}),
            "Locust",
        ),
        (
            Subject::Autorun,
            serde_json::json!({"name": "Updater"}),
            "Updater",
        ),
        (
            Subject::Process,
            serde_json::json!({"image_path": "/usr/bin/x"}),
            "/usr/bin/x",
        ),
        (
            Subject::Indicator,
            serde_json::json!({"value": "abc"}),
            "abc",
        ),
        (
            Subject::AvExclusion,
            serde_json::json!({"value": "C:\\lab"}),
            "C:\\lab",
        ),
        (
            Subject::RegistryValue,
            serde_json::json!({"hive": "HKCU", "key": "Software\\R", "name": "V"}),
            "HKCU\\Software\\R\\V",
        ),
        (
            Subject::RegistryKey,
            serde_json::json!({"hive": "HKLM", "key": "Software\\K"}),
            "HKLM\\Software\\K",
        ),
        (
            Subject::BootConfig,
            serde_json::json!({"entry": "{current}"}),
            "{current}",
        ),
        (
            Subject::HostsEntry,
            serde_json::json!({"hostnames": ["evil.test"]}),
            "evil.test",
        ),
        (
            Subject::CertStore,
            serde_json::json!({"subject": "CN=X"}),
            "CN=X",
        ),
        (
            Subject::ProxyConfig,
            serde_json::json!({"server": "1.2.3.4:8080"}),
            "1.2.3.4:8080",
        ),
        (
            Subject::BrowserExtension,
            serde_json::json!({"name": "Ext"}),
            "Ext",
        ),
        (
            Subject::UnixSocket,
            serde_json::json!({"name": "@/run/systemd/log", "inode": 7}),
            "@/run/systemd/log",
        ),
    ];
    // 카탈로그의 subject 가 하나도 빠지지 않았는가 — 새 subject 를 더하고 여기를
    // 잊으면 그 subject 의 화면 이름은 아무도 재지 않는다.
    assert_eq!(cases.len(), Subject::ALL.len(), "모든 subject 를 재야 한다");
    for (s, t, want) in cases {
        assert_eq!(&evidence_label(*s, t), want, "{s:?} 의 이름이 틀렸다");
    }
    // **모르는 모양이 와도 빈 줄은 없다.** 화면의 계약이 가드와 다른 자리다.
    for (s, _, _) in cases {
        let empty = evidence_label(*s, &serde_json::json!({}));
        assert!(!empty.is_empty(), "{s:?} 가 빈 이름을 냈다");
    }
}

/// 판정이 선 그룹의 증거만 적는다 — 제외된 그룹은 화면에 올리지 않는다.
#[test]
fn only_evidence_behind_a_verdict_is_listed() {
    let e = vec![
        ev(
            "e0",
            Subject::File,
            serde_json::json!({"path": "C:\\php\\php.exe"}),
        ),
        ev(
            "e1",
            Subject::File,
            serde_json::json!({"path": "C:\\other.exe"}),
        ),
    ];
    let g = vec![group("g0", &["e0"], true), group("g1", &["e1"], false)];
    let out = check_findings(&e, &g, Lang::Ko, FINDINGS_SHOWN);
    assert_eq!(out.len(), 1);
    assert!(out[0].contains("C:\\php\\php.exe"));
    assert!(!out[0].contains("other.exe"));
}

/// **찾기만 하는 위협 룰은 이름(경로)만** 적는다 — 판정을 가른 값이 내용 해시라 사람에게 뜻이
/// 없다(2026-11-08 리눅스 실측: `(sha256 4458…)`). 고르는 증거 · 중복 걸러내기는 점검과 같고,
/// 점검의 줄은 그대로다.
#[test]
fn a_threat_finding_names_only_the_thing() {
    let mut x = ev(
        "e0",
        Subject::File,
        serde_json::json!({"path": "/usr/lib64/libkeyutils.so.1.5.2", "sha256": "445810c9"}),
    );
    x.matched = vec![MatchedPredicate {
        field: "sha256".into(),
        op: "eq".into(),
        value: None,
    }];
    // 같은 레코드를 두 규칙이 짚은 모양 — 화면에는 한 번이다.
    let mut twin = ev("e1", Subject::File, x.target.clone());
    twin.matched = x.matched.clone();
    let other = ev(
        "e2",
        Subject::File,
        serde_json::json!({"path": "/usr/lib64/elsewhere.so"}),
    );
    let e = vec![x, twin, other];
    let g = vec![
        group("g0", &["e0", "e1"], true),
        group("g1", &["e2"], false),
    ];
    assert_eq!(
        threat_findings(&e, &g, Lang::Ko, FINDINGS_SHOWN),
        vec!["   1. /usr/lib64/libkeyutils.so.1.5.2".to_string()]
    );
    // 점검의 줄은 지금 그대로 — 판정을 가른 값을 함께 적는다.
    assert_eq!(
        check_findings(&e, &g, Lang::Ko, FINDINGS_SHOWN),
        vec!["   1. /usr/lib64/libkeyutils.so.1.5.2  (sha256 445810c9)".to_string()]
    );
}

/// **판정을 가른 값을 함께 적는다** — 이름만으로는 "왜" 가 없다.
#[test]
fn the_value_that_decided_it_is_shown() {
    let mut x = ev(
        "e0",
        Subject::File,
        serde_json::json!({"path": "C:\\php\\php.exe", "version": "8.2.35"}),
    );
    x.matched = vec![
        MatchedPredicate {
            field: "path".into(),
            op: "ends_with".into(),
            value: None,
        },
        MatchedPredicate {
            field: "version".into(),
            op: "version_lt".into(),
            value: None,
        },
    ];
    let out = check_findings(
        &[x],
        &[group("g0", &["e0"], true)],
        Lang::Ko,
        FINDINGS_SHOWN,
    );
    assert!(
        out[0].contains("버전 8.2.35"),
        "관측된 판이 없다: {}",
        out[0]
    );
    // 이름에 이미 쓴 `path` 는 괄호 안에 되풀이하지 않는다.
    assert_eq!(out[0].matches("C:\\php\\php.exe").count(), 1);
    // **엔진 필드 이름을 늘어놓지 않는다** — 판이 맞았으면 판 하나다.
    assert!(
        !out[0].contains("version_lt"),
        "엔진 낱말이 샜다: {}",
        out[0]
    );
    assert!(!out[0].contains("path"), "필드 이름이 샜다: {}", out[0]);
}

/// **잘리는 갈래가 실제로 돈다.** 재지 않으면 죽은 코드다.
#[test]
fn the_overflow_line_appears_and_verbose_shows_all() {
    let n = FINDINGS_SHOWN + 3;
    let e: Vec<Evidence> = (0..n)
        .map(|i| {
            ev(
                &format!("e{i}"),
                Subject::File,
                serde_json::json!({"path": format!("/f{i}")}),
            )
        })
        .collect();
    let ids: Vec<String> = (0..n).map(|i| format!("e{i}")).collect();
    let g = vec![EvidenceGroup {
        id: "g0".into(),
        evidence: ids,
        captures: Default::default(),
        verdict: true,
        excluded_reason: None,
    }];
    let cut = check_findings(&e, &g, Lang::Ko, FINDINGS_SHOWN);
    assert_eq!(cut.len(), FINDINGS_SHOWN + 1, "접은 줄이 없다");
    assert!(cut.last().unwrap().contains("그 외 3건"));
    assert!(cut.last().unwrap().contains("--verbose"));

    let all = check_findings(&e, &g, Lang::Ko, usize::MAX);
    assert_eq!(all.len(), n, "--verbose 가 전부 보이지 않는다");
    assert!(!all.last().unwrap().contains("그 외"));

    let en = check_findings(&e, &g, Lang::En, FINDINGS_SHOWN);
    assert!(en.last().unwrap().contains("and 3 more"));
}

/// **룰 둘이 같은 것을 짚으면 한 번만 적는다** (2026-10-28 리눅스 실측).
///
/// 같은 패키지 넷이 화면에 **두 번** 늘어섰다. 사용자가 볼 것은 *"무엇이
/// 취약한가"* 이지 *"룰이 몇 개 맞았는가"* 가 아니다 — 뒤의 수는 윗줄의
/// `흔적 N건` 이 이미 말한다. 다만 **적히는 값이 다르면 다른 줄로 남는다.**
#[test]
fn the_same_finding_is_listed_once() {
    let same = |id: &str| ev("x", Subject::Package, serde_json::json!({"name": id}));
    let mut a = same("php8.1-cli");
    a.id = "e0".into();
    let mut b = same("php8.1-cli");
    b.id = "e1".into();
    let mut c = ev(
        "e2",
        Subject::Package,
        serde_json::json!({"name": "php8.1-common"}),
    );
    c.id = "e2".into();
    let g = vec![group("g0", &["e0", "e1", "e2"], true)];
    let out = check_findings(&[a, b, c], &g, Lang::Ko, FINDINGS_SHOWN);
    assert_eq!(out.len(), 2, "중복이 남았다: {out:?}");
    assert!(out[0].contains("php8.1-cli"));
    assert!(out[1].contains("php8.1-common"));

    // 값이 다르면 남는다 — 같은 파일의 다른 판은 다른 사실이다.
    let mut v1 = ev(
        "e0",
        Subject::File,
        serde_json::json!({"path": "/x", "version": "1.0"}),
    );
    v1.matched = vec![MatchedPredicate {
        field: "version".into(),
        op: "version_lt".into(),
        value: None,
    }];
    let mut v2 = ev(
        "e1",
        Subject::File,
        serde_json::json!({"path": "/x", "version": "2.0"}),
    );
    v2.matched = v1.matched.clone();
    let out2 = check_findings(
        &[v1, v2],
        &[group("g0", &["e0", "e1"], true)],
        Lang::Ko,
        FINDINGS_SHOWN,
    );
    assert_eq!(out2.len(), 2, "다른 값을 접었다: {out2:?}");
}

/// 그룹이 비어 있는 플러그인도 있다 — 그때는 흔적을 그대로 쓴다.
#[test]
fn no_groups_falls_back_to_evidence() {
    let e = vec![ev(
        "e0",
        Subject::Package,
        serde_json::json!({"name": "php8.1-cli"}),
    )];
    let out = check_findings(&e, &[], Lang::Ko, FINDINGS_SHOWN);
    assert_eq!(out.len(), 1);
    assert!(out[0].contains("php8.1-cli"));
}

/// 결론 줄이 **JSON 을 가리키지 않는다** (기준 3).
#[test]
fn the_check_verdict_line_no_longer_sends_people_to_json() {
    for lang in [Lang::Ko, Lang::En] {
        let s = result_line(
            remedy_sdk::artifact::ExitCode::FoundNotRemediated,
            0,
            lang,
            Some(remedy_sdk::manifest::PluginKind::Check),
        );
        assert!(!s.contains("scan.json"), "아직 JSON 을 가리킨다: {s}");
    }
}
