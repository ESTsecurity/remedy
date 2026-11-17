//! 본체 실행 파일의 단위 시험 — 2026-11-17 에 main.rs 에서 떼어 냈다. 내용은 그대로다.

use super::*;

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// **메뉴의 기본 폴더는 전부 실행 파일 옆이다** (목표 `remedy_cli` 기준 3).
///
/// 2026-10-29 재검토에서 그 규칙이 **한 메뉴 안에서 갈려 있었다** — `scan` 은
/// `beside_exe("out")` 을 주는데 `support-bundle` 은 아무것도 주지 않아
/// 기본값 `.`(현재 폴더)로 갔다. 더블클릭으로 띄운 경로에서 그 자리는 사람이
/// 짐작할 수 없다. 두 자리가 **같은 함수**를 지나는지 여기서 잠근다.
#[test]
fn the_menu_puts_its_folders_beside_the_exe() {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(std::path::Path::to_path_buf))
        .expect("시험 바이너리의 자리는 있다");
    for name in ["out", "report"] {
        let got = beside_exe(name);
        assert_eq!(
            got.parent(),
            Some(exe_dir.as_path()),
            "{name} 이 실행 파일 옆이 아니다: {}",
            got.display()
        );
        assert_eq!(got.file_name().and_then(|s| s.to_str()), Some(name));
    }
}

/// 결정 3(2026-10-30) — 메뉴의 복원 정보 폴더는 **실행 파일 옆**이고, 회차를
/// 찾을 때는 **두 자리를 다 본다.** 하나로 줄이면 그 기계에 전부터 쌓인
/// 격리물이 메뉴에서 사라진다(멈출 조건 5).
#[test]
fn the_menu_reads_both_restore_folders_and_its_own_comes_first() {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(std::path::Path::to_path_buf))
        .expect("시험 바이너리의 자리는 있다");
    let dirs = menu_state_dirs();
    assert_eq!(dirs.len(), 2, "{dirs:?}");
    // **쓰는 자리가 먼저다** — 방금 치료한 회차가 목록 위에 와야 한다.
    assert_eq!(dirs[0], exe_dir.join("state"), "{dirs:?}");
    assert_eq!(
        dirs[1],
        remedy_core::restore::default_state_dir(),
        "{dirs:?}"
    );
    // 기계 공용 자리를 **실행 파일 옆으로 바꾸지 않았다**(불변식 I1).
    assert_ne!(dirs[0], dirs[1], "{dirs:?}");
}

/// 결정 4(2026-10-30) — 결과는 `<exe>\out\<스탬프>\` 로 간다. 한 작업 안에서는
/// **같은 폴더**여야 한다: 검사가 낸 셋(artifacts · scan · plan)이 흩어지면 사람이
/// 자기 결과를 모은 자리를 잃는다.
#[test]
fn the_menu_output_is_one_folder_per_run_under_out() {
    let a = menu_out();
    let b = menu_out();
    assert_eq!(a, b, "한 작업에 두 폴더가 생겼다");
    assert_eq!(a.parent(), Some(beside_exe("out").as_path()), "{a:?}");
    let stamp = a
        .file_name()
        .and_then(|s| s.to_str())
        .expect("스탬프")
        .to_string();
    // 경로에 쓸 수 없는 글자가 남으면 Windows 에서 폴더를 만들지 못한다.
    for bad in [':', '*', '?', '"', '<', '>', '|'] {
        assert!(!stamp.contains(bad), "스탬프에 '{bad}' 가 있다: {stamp}");
    }
    // `20261030T113100Z` 꼴 — 이름순이 곧 시간순이라야 후보 차례가 뜻을 갖는다.
    assert!(stamp.len() >= 16, "{stamp}");
    assert!(stamp.ends_with('Z'), "{stamp}");
}

/// 기준 6(d) — 치료 뒤에는 되돌리기 · 유지 확인 · 신고를, 검사가 찾았으면 치료 · 계획
/// 수행을 권한다. 고를 것이 없는 결과에는 아무것도 권하지 않는다.
#[test]
fn next_steps_follow_the_result() {
    let lines = |f, c| {
        next_steps(f, c, true)
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
    };
    use menu::Line as L;
    assert_eq!(
        lines(Flow::Treat, Code::Remediated),
        [L::Verify, L::Undo, L::Report]
    );
    assert_eq!(lines(Flow::Scan, Code::FoundNotRemediated), [L::Treat]);
    assert_eq!(lines(Flow::ScanAll, Code::FoundNotRemediated), [L::Treat]);
    // 되돌린 사람은 오탐이라고 본 사람이다 — 신고가 먼저다.
    assert_eq!(lines(Flow::Restore, Code::NoThreat), [L::Report, L::Treat]);
    assert!(lines(Flow::Scan, Code::NoThreat).is_empty());
    assert!(lines(Flow::Other, Code::PartialFailure).is_empty());
    // 일부 실패한 회차도 끝난 회차라 이어서 하기는 거절된다 — 다시 검사해 치료한다.
    assert_eq!(
        lines(Flow::Treat, Code::PartialFailure),
        [L::Treat, L::Report]
    );
    assert_eq!(lines(Flow::Restore, Code::PartialFailure), [L::Report]);
    // 찾은 것 모두 치료하기의 다음 할 일은 룰마다 `treat_all` 이 앞줄로 짓는다 — 메뉴 줄은 없다.
    assert!(lines(Flow::TreatAll, Code::Remediated).is_empty());
}

/// 기준 5 — *모두 검사만* 이 **치료하는 룰에서** 찾았을 때만 다음 할 일 첫 줄이 *찾은 것 모두
/// 치료하기* 다. 그 번호는 고르는 화면의 것이다(메뉴 줄이 아니다 — `step_line` 에 고를 룰이 없다).
#[test]
fn scan_all_leads_with_treat_everything_only_when_a_treating_rule_found_something() {
    let line = || Some((9, "찾은 것 모두 치료하기 (항목 1개)".to_string()));
    let got = scan_all_lead(Code::FoundNotRemediated, true, line());
    assert_eq!(got.len(), 1, "{got:?}");
    assert!(
        got[0].ends_with("9. 찾은 것 모두 치료하기 (항목 1개)"),
        "{got:?}"
    );
    // 찾기만 하는 룰 · 점검 룰만 찾았다 — 치료할 것이 없다.
    assert!(scan_all_lead(Code::FoundNotRemediated, false, line()).is_empty());
    // 찾은 것이 없다.
    assert!(scan_all_lead(Code::NoThreat, true, line()).is_empty());
    assert!(scan_all_lead(Code::IncompleteObservation, true, line()).is_empty());
    // 그 줄이 서지 않는다(룰이 하나인 꾸러미 — 고르는 화면이 없다).
    assert!(scan_all_lead(Code::FoundNotRemediated, true, None).is_empty());
}

/// 기준 5 — *찾은 것 모두 치료하기* 의 끝 코드는 **새 코드를 만들지 않는다**(불변식 I3). 마치지
/// 못한 룰(4 · 5 · 7 중 큰 것)이 먼저, 그다음 일부 실패 · 치료하지 않은 발견 · 치료 · 다 보지 못함.
#[test]
fn treat_all_ends_with_the_weightiest_existing_code() {
    use Code as C;
    assert_eq!(
        treat_all_code(&[C::Remediated, C::Remediated]),
        C::Remediated
    );
    assert_eq!(
        treat_all_code(&[C::Remediated, C::PartialFailure]),
        C::PartialFailure
    );
    // 승인을 거절했다 — 찾은 것이 그대로 남았다.
    assert_eq!(
        treat_all_code(&[C::FoundNotRemediated, C::FoundNotRemediated]),
        C::FoundNotRemediated
    );
    // 하나는 치료했고 하나는 바꿀 것이 없어 찾은 것이 남았다.
    assert_eq!(
        treat_all_code(&[C::Remediated, C::FoundNotRemediated]),
        C::FoundNotRemediated
    );
    assert_eq!(
        treat_all_code(&[C::PartialFailure, C::GuardStop]),
        C::GuardStop
    );
    assert_eq!(
        treat_all_code(&[C::GuardStop, C::InternalError]),
        C::InternalError
    );
    assert_eq!(
        treat_all_code(&[C::NoThreat, C::IncompleteObservation]),
        C::IncompleteObservation
    );
    assert_eq!(treat_all_code(&[C::NoThreat]), C::NoThreat);
    assert_eq!(treat_all_code(&[]), C::NoThreat);
}

/// 되돌리기 · 신고 안내의 `--state-dir` — 기본 자리면 붙이지 않고(무인 배포 출력 그대로),
/// 셸이 둘로 가를 글자가 든 경로는 따옴표로 감싼다(2026-11-07 결정 ①).
#[test]
fn state_hint_names_only_a_non_default_dir_and_quotes_what_a_shell_would_split() {
    assert_eq!(state_hint(&remedy_core::restore::default_state_dir()), None);
    assert_eq!(
        state_hint(std::path::Path::new("/opt/remedy-linux-x64/state")).as_deref(),
        Some("/opt/remedy-linux-x64/state")
    );
    for odd in [
        r"C:\Users\Kim Lee\remedy\state",
        r"D:\R&D\remedy\state",
        "/home/a;b/state",
    ] {
        assert_eq!(
            state_hint(std::path::Path::new(odd)).as_deref(),
            Some(format!("\"{odd}\"").as_str()),
            "{odd}"
        );
    }
}

/// 기준 4 — **찾기만 하는 룰이 찾았으면 치료를 권하지 않는다.** 메뉴도 그 줄을 꺼 둔다.
#[test]
fn a_detect_only_find_suggests_no_treatment_and_points_at_the_steps() {
    for f in [Flow::Scan, Flow::ScanAll] {
        assert!(next_steps(f, Code::FoundNotRemediated, false).is_empty());
        // 대신 조치 차례가 있는 곳을 가리킨다 — 다음 할 일이 비지 않는다.
        assert!(guidance(f, Code::FoundNotRemediated, false, &[])
            .is_some_and(|g| g.contains("#위협별-안내") && !g.contains("인터넷이")));
        assert!(guidance(f, Code::FoundNotRemediated, true, &[]).is_none());
    }
    // 받은 폴더의 기록이 있으면 그 경로를 그대로 적는다 — 인터넷이 막힌 서버의 몫이다.
    let note = std::path::PathBuf::from("plugins")
        .join("ebury-check")
        .join("RELEASE.md");
    let g = guidance(
        Flow::ScanAll,
        Code::FoundNotRemediated,
        false,
        std::slice::from_ref(&note),
    )
    .unwrap();
    assert!(g.contains("#위협별-안내"), "{g}");
    assert!(
        g.lines().any(|l| l.trim() == note.display().to_string()),
        "{g}"
    );
    // 리눅스 콘솔은 흔히 80칸이다 — 두 언어 모두 들여쓰기(2칸)까지 넘지 않는다. 한글은 두 칸.
    let cols = |s: &str| {
        s.chars()
            .map(|c| if ('가'..='힣').contains(&c) { 2 } else { 1 })
            .sum::<usize>()
    };
    for l in [
        CHECKER_FOUND.0,
        CHECKER_FOUND.1,
        CHECKER_OFFLINE.0,
        CHECKER_OFFLINE.1,
        TREATED_NEXT.0,
        TREATED_NEXT.1,
        SIGNED_OK.0,
        SIGNED_OK.1,
        NO_REVOCATION_YET.0,
        NO_REVOCATION_YET.1,
        CLEAN_SCOPE.0,
        CLEAN_SCOPE.1,
        CLEAN_OFFLINE.0,
        CLEAN_OFFLINE.1,
    ] {
        assert!(2 + cols(l) <= 80, "{} 칸: {l}", 2 + cols(l));
    }
}

/// 깨끗하게 끝난 결과도 **범위를 밝힌다** — 룰은 공개 보도가 밝힌 꼴을 찾고, 같은 위협의 다른 설치
/// 방법은 이름 그대로 찾지 못한다(2026-11-08 실측). 종료 코드와 결과 줄은 그대로고, 읽을 곳 한 줄을
/// 더한다. 관측 불완전(6)에는 내지 않는다 — 그쪽은 *주의* 줄이 까닭을 말한다.
#[test]
fn a_clean_result_still_says_what_it_covered() {
    let note = std::path::PathBuf::from("plugins")
        .join("ebury-check")
        .join("RELEASE.md");
    for f in [Flow::Scan, Flow::ScanAll, Flow::Treat] {
        for treats in [true, false] {
            let g = guidance(f, Code::NoThreat, treats, std::slice::from_ref(&note))
                .expect("깨끗한 결과에도 범위 한 줄");
            // 시험은 기본 언어(영어)로 돈다 — 두 판 가운데 어느 쪽이든 받는다.
            assert!(
                g.contains(CLEAN_SCOPE.0) || g.contains(CLEAN_SCOPE.1),
                "{g}"
            );
            assert!(g.contains("#위협별-안내"), "{g}");
            assert!(
                g.contains(CLEAN_OFFLINE.0) || g.contains(CLEAN_OFFLINE.1),
                "{g}"
            );
            assert!(
                g.lines().any(|l| l.trim() == note.display().to_string()),
                "{g}"
            );
        }
    }
    assert!(guidance(Flow::Scan, Code::IncompleteObservation, true, &[]).is_none());
    assert!(guidance(Flow::Restore, Code::NoThreat, true, &[]).is_none());
}

/// 신고 묶음을 만든 뒤 **보낼 곳**을 적는다 — 묶음에는 경로 · 호스트명 · 사용자명이 그대로 있어 공개 이슈에
/// 붙이면 안 되는데, 1.21.1 의 화면은 어디로 보내는지 말하지 않았다(목표 remedy_시연전_안정화 흐름 표).
/// 만들지 못했으면 실패 줄이 할 말을 한다. 줄마다 80칸 안이고 두 언어의 줄 수가 같다.
#[test]
fn a_support_bundle_says_where_to_send_it() {
    let g = guidance(Flow::Report, Code::NoThreat, true, &[]).unwrap();
    // 주소는 `SEND_TO` 한 자리에만 둔다(누출 검사의 예외가 그 파일 하나다) — 두 언어 모두 GitHub 갈래를 적는다.
    assert!(g == SEND_TO.0 || g == SEND_TO.1, "{g}");
    assert!(SEND_TO.0.contains("GitHub") && SEND_TO.1.contains("GitHub"));
    for l in [SEND_TO.0, SEND_TO.1].iter().flat_map(|s| s.lines()) {
        let w: usize = format!("  {l}")
            .chars()
            .map(|c| if c.is_ascii() { 1 } else { 2 })
            .sum();
        assert!(w <= 80, "{w}칸: {l}");
    }
    assert_eq!(SEND_TO.0.lines().count(), SEND_TO.1.lines().count());
    assert!(guidance(Flow::Report, Code::UsageError, true, &[]).is_none());
}

/// 이어서 한 치료는 치료다 — 끝나면 유지 확인 · 복원 · 신고를 가리킨다(1.21.1 까지는 다음 할 일이 비었다).
#[test]
fn a_resumed_treatment_gets_the_treatment_next_steps() {
    let run = menu::Run {
        id: "run-1".into(),
        state: std::path::PathBuf::from("state"),
    };
    let resumed = guided::Outcome::WithRun(menu::WithRun::Resume(run.clone()));
    assert!(matches!(flow_of(&resumed), Flow::Treat));
    let bundle = guided::Outcome::WithRun(menu::WithRun::Support(run));
    assert!(matches!(flow_of(&bundle), Flow::Report));
}

/// 룰 서명 확인이 **성공했을 때만** 끝줄을 풀이한다 — 실패(5)에는 화면의 거부 줄이 할 말을 한다.
#[test]
fn a_good_signature_check_explains_the_revocation_line() {
    let g = guidance(Flow::Signature, Code::NoThreat, true, &[]).unwrap();
    assert!(g.contains("폐기 목록 없음"), "{g}");
    assert!(guidance(Flow::Signature, Code::GuardStop, true, &[]).is_none());
}

/// 치료가 끝나면 위협별 안내를 가리킨다 — 패널 다시 설치 · 자격 증명 · 다시 시작 같은 일은
/// 위협마다 다르고 화면은 그것을 말하지 않았다(2026-11-08 적대적 검토 4바퀴). 일부 실패 ·
/// 복원 뒤에는 지금 그대로다.
#[test]
fn a_finished_treatment_points_at_the_per_threat_steps() {
    let note = std::path::PathBuf::from("plugins")
        .join("cwpdoor-2-clean")
        .join("RELEASE.md");
    let g = guidance(
        Flow::Treat,
        Code::Remediated,
        true,
        std::slice::from_ref(&note),
    )
    .unwrap();
    assert!(g.contains("#위협별-안내"), "{g}");
    assert!(
        g.lines().any(|l| l.trim() == note.display().to_string()),
        "{g}"
    );
    assert!(guidance(Flow::Treat, Code::PartialFailure, true, &[]).is_none());
    assert!(guidance(Flow::Restore, Code::NoThreat, true, &[]).is_none());
    assert!(guidance(Flow::Verify, Code::NoThreat, true, &[]).is_none());
}

/// 룰이 여럿인 세션의 다음 할 일 — **먼저 고를 룰**을 앞에 적는다. 작업 뒤 Enter 는 룰을
/// 고르는 화면으로 돌아가는데, 메뉴 줄의 번호는 룰을 고른 뒤에야 맞는다(리눅스 실측: 치료 뒤
/// `6` 이 고르는 화면에서 범위 밖으로 읽혀 끝났다). 룰이 하나면 지금 그대로다.
#[test]
fn next_steps_name_the_rule_to_pick_first_when_there_are_several() {
    let fancy = remedy_sdk::i18n::Deco { ascii: false };
    let ascii = remedy_sdk::i18n::Deco { ascii: true };
    assert_eq!(
        step_line("오탐이라면", None, 4, "치료 전으로 복원하기", fancy),
        "  오탐이라면 — 4. 치료 전으로 복원하기"
    );
    let pick = (3, "CWPdoor 제거".to_string());
    assert_eq!(
        step_line("오탐이라면", Some(&pick), 4, "치료 전으로 복원하기", fancy),
        "  오탐이라면 — 3. CWPdoor 제거 → 4. 치료 전으로 복원하기"
    );
    assert_eq!(
        step_line("오탐이라면", Some(&pick), 4, "치료 전으로 복원하기", ascii),
        "  오탐이라면 - 3. CWPdoor 제거 -> 4. 치료 전으로 복원하기"
    );
    // 실제로 서는 가장 긴 줄도 80칸 안이다 — 리눅스 콘솔은 흔히 80칸이다. 한글은 두 칸.
    // 이 줄이 서는 것은 치료하는 룰뿐이다(찾기만 하는 룰은 `next_steps` 가 비운다) — 리눅스
    // 배포 파일에서는 *CWPdoor 제거* 하나다.
    let cols = |s: &str| {
        s.chars()
            .map(|c| if ('가'..='힣').contains(&c) { 2 } else { 1 })
            .sum::<usize>()
    };
    for (why, label) in [
        ("까닭을 해결한 뒤 다시 검사하려면", "검사하고 치료하기"),
        ("치료가 유지되는지 보려면", "치료가 유지됐는지 다시 보기"),
        ("오탐을 신고하려면", "신고에 붙일 것 모으기"),
    ] {
        let l = step_line(why, Some(&pick), 3, label, fancy);
        assert!(cols(&l) <= 80, "{} 칸: {l}", cols(&l));
    }
}

/// 다음 할 일 덩어리 — 먼저 고를 룰은 **한 번만** 적고 메뉴 줄을 그 아래에 들인다(목표 remedy_시연전_안정화 D5).
/// 룰이 하나면 줄 꼴이 지금 그대로다.
#[test]
fn next_steps_name_the_rule_once_and_indent_its_lines() {
    let fancy = remedy_sdk::i18n::Deco { ascii: false };
    let steps = [
        (
            "치료가 유지되는지 보려면",
            3,
            "치료가 유지됐는지 다시 보기".to_string(),
        ),
        ("오탐이라면", 4, "치료 전으로 복원하기".to_string()),
    ];
    let pick = (3, "CWPdoor 제거".to_string());
    // 머리 줄의 말은 화면 언어를 따른다(시험 환경은 영어일 수 있다) — 고를 룰이 한 번 서는지만 본다.
    let block = step_block(&steps, Some(&pick), fancy);
    assert_eq!(block.len(), 3, "{block:?}");
    assert!(block[0].contains("3. CWPdoor 제거"), "{block:?}");
    assert_eq!(
        block[1..],
        [
            "    치료가 유지되는지 보려면 — 3. 치료가 유지됐는지 다시 보기",
            "    오탐이라면 — 4. 치료 전으로 복원하기",
        ]
    );
    assert_eq!(
        step_block(&steps, None, fancy),
        [
            "  치료가 유지되는지 보려면 — 3. 치료가 유지됐는지 다시 보기",
            "  오탐이라면 — 4. 치료 전으로 복원하기",
        ]
    );
    assert!(step_block(&[], Some(&pick), fancy).is_empty());
}

/// 기준 3 — 모두 검사만의 종료 코드. 찾은 것이 가장 앞서고, 검사를 마치지 못한 것이
/// 다 보지 못한 것보다 앞선다. 새 코드는 없다(불변식 I3).
#[test]
fn scanning_with_every_rule_keeps_the_eight_codes() {
    use Code as C;
    assert_eq!(all_scans_code(&[C::NoThreat, C::NoThreat]), C::NoThreat);
    assert_eq!(
        all_scans_code(&[C::NoThreat, C::IncompleteObservation]),
        C::IncompleteObservation
    );
    assert_eq!(
        all_scans_code(&[C::IncompleteObservation, C::FoundNotRemediated]),
        C::FoundNotRemediated
    );
    assert_eq!(
        all_scans_code(&[C::GuardStop, C::IncompleteObservation]),
        C::GuardStop
    );
    assert_eq!(
        all_scans_code(&[C::UsageError, C::GuardStop, C::NoThreat]),
        C::GuardStop
    );
    assert_eq!(
        all_scans_code(&[C::GuardStop, C::FoundNotRemediated]),
        C::FoundNotRemediated
    );
    assert_eq!(all_scans_code(&[]), C::NoThreat);
}

/// 선언한 자리가 전부 없으면 **그 아래를 가리킨** `collect_extra` 줄은 말하지 않는다 — 까닭은
/// 검사 끝의 *주의* 줄이 한 번 말한다. 경계가 아닌 접두 · 없는 차례 · 자리를 알 수 없는
/// 것 · 루트가 있을 때는 말한다.
#[test]
fn a_declaration_under_a_missing_root_is_not_said_twice() {
    let m: PluginManifest = serde_yaml_ng::from_str(
        r#"schema_version: 1
id: cwp-probe
version: 1.0.0
min_core: '1.0.2'
platforms: [linux]
name: { en: 'cwp probe' }
scan_roots: ['/usr/local/cwpsrv/bin']
subjects: [file]
detect:
  - id: r
    subject: file
    where:
      - { field: path, op: ends_with, value: '/cwpsrv' }
verdict: { require: 'r' }
collect_extra:
  - { path: '/usr/local/cwpsrv/bin/cwpsrv', max_size: 64MB }
  - { path: '/usr/local/cwpsrv/bin2/cwpsrv' }
  - { glob: '/usr/local/cwpsrv/bin/lib*' }
"#,
    )
    .expect("매니페스트");
    let u = |at: &str| remedy_core::Unresolved {
        at: at.into(),
        reason: String::new(),
    };
    let missing = vec!["/usr/local/cwpsrv/bin".to_string()];
    assert!(under_missing_root(&m, &u("collect_extra[0]"), &missing));
    assert!(
        !under_missing_root(&m, &u("collect_extra[1]"), &missing),
        "경계가 아닌 접두"
    );
    assert!(
        under_missing_root(&m, &u("collect_extra[2]"), &missing),
        "glob 형"
    );
    assert!(
        !under_missing_root(&m, &u("collect_extra[9]"), &missing),
        "없는 차례"
    );
    assert!(
        !under_missing_root(&m, &u("scan_roots"), &missing),
        "자리를 알 수 없는 것"
    );
    assert!(
        !under_missing_root(&m, &u("collect_extra[0]"), &[]),
        "루트가 있으면 말한다"
    );
}

/// 같은 초에 앞 작업의 폴더가 이미 있으면 번호를 붙인다 — 덮어쓰지 않는다. 붙인
/// 이름도 이름순이 곧 시간순이다(`…Z` < `…Z-2` < 다음 초).
#[test]
fn a_second_task_in_the_same_second_gets_its_own_folder() {
    let base = std::env::temp_dir().join(format!("remedy-fresh-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let a = fresh_dir(&base, "20261106T010203Z");
    std::fs::create_dir_all(&a).expect("첫 폴더");
    let b = fresh_dir(&base, "20261106T010203Z");
    let _ = std::fs::remove_dir_all(&base);
    assert_ne!(a, b);
    assert!(b.ends_with("20261106T010203Z-2"), "{b:?}");
    let names = ["20261106T010203Z", "20261106T010203Z-2", "20261106T010204Z"];
    assert!(names.windows(2).all(|w| w[0] < w[1]), "{names:?}");
}

#[test]
fn the_windows_scheduling_line_is_the_one_the_screen_baseline_holds() {
    // 위치가 호출자에 박혀 있다가 백엔드 질의로 옮겨 왔다 (P12). **Windows
    // 화면은 한 글자도 바뀌면 안 된다** — 실제 Windows 회차가 남긴 기준선에 그
    // 줄이 그대로 있는지를 잰다. 백엔드가 이 위치를 내는지는 `remedy-platform`
    // 의 `windows.rs` 시험이 잰다.
    use remedy_core::report::Lang;
    use remedy_core::restart::{RemovedBy, VerifySite};
    let site = VerifySite {
        location: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\remedy-verify".into(),
        removed_by: RemovedBy::Os,
    };
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testbed/harness/baseline/console");
    for (lang, file) in [
        (Lang::Ko, "console-win.txt"),
        (Lang::En, "console-win-en.txt"),
    ] {
        let text = std::fs::read_to_string(base.join(file)).expect("화면 기준선");
        let line = scheduled_line(Some(&site), lang);
        assert!(
            text.lines().any(|l| l == line),
            "{file} 에 없는 줄이다 — Windows 화면이 바뀌었다:\n{line}"
        );
    }
}

#[test]
fn the_not_scheduled_note_is_the_one_the_screen_baseline_holds() {
    // 예약이 CLI 에서 실행기로 옮겨 갔다 (P12 P3). **화면은 그대로여야 한다**
    // — 실제 Windows 회차가 남긴 정규화 기준선(run id -> `run-X`)에
    // `apply --plan` 의 그 안내가 글자 그대로 있는지를 잰다.
    use remedy_core::report::Lang;
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testbed/harness/baseline/console");
    for (lang, file) in [
        (Lang::Ko, "console-win.norm.txt"),
        (Lang::En, "console-win-en.norm.txt"),
    ] {
        let text = std::fs::read_to_string(base.join(file)).expect("화면 기준선");
        let line = not_scheduled_line(no_plugin_reason(lang), "run-X", None, lang);
        assert!(
            text.lines().any(|l| l == line),
            "{file} 에 없는 줄이다 — 화면이 바뀌었다:\n{line}"
        );
    }
}

#[test]
fn the_linux_scheduling_line_names_the_unit_and_does_not_credit_the_os() {
    // 리눅스는 OS 가 지우지 않는다 — 유닛이 실행 직전에 스스로 지운다.
    use remedy_core::report::Lang;
    use remedy_core::restart::{RemovedBy, VerifySite};
    let site = VerifySite {
        location: "/etc/systemd/system/remedy-verify.service".into(),
        removed_by: RemovedBy::Itself,
    };
    let ko = scheduled_line(Some(&site), Lang::Ko);
    assert!(
        ko.contains("/etc/systemd/system/remedy-verify.service")
            && ko.contains("스스로 지웁니다")
            && !ko.contains("OS"),
        "{ko}"
    );
    let en = scheduled_line(Some(&site), Lang::En);
    assert!(
        en.contains("removes itself") && !en.contains("the OS"),
        "{en}"
    );
    // 자리를 모르면 지어내지 않는다.
    assert_eq!(
        scheduled_line(None, Lang::Ko),
        "재부팅 후 재평가를 예약했습니다"
    );
}

#[test]
fn the_reboot_check_is_registered_with_absolute_paths() {
    // README 의 명령줄 예시는 상대 경로로 부른다. 재부팅 회차는 다른 현재
    // 폴더에서 돌므로 받은 값을 그대로 실으면 룰을 찾지 못한다.
    let sep = std::path::MAIN_SEPARATOR;
    let rel = format!(".{sep}plugins{sep}x{sep}plugin.yaml");
    let a = parse_args(&args(&["--plugin", &rel, "--state-dir", "st"])).unwrap();
    let r = verify_request(&a).unwrap();
    let here = std::env::current_dir().unwrap();
    assert!(r.plugin.is_absolute(), "{}", r.plugin.display());
    assert_eq!(r.plugin, here.join("plugins").join("x").join("plugin.yaml"));
    assert_eq!(r.state_dir, Some(here.join("st")));
    // 이미 절대 경로인 값(메뉴 · 운영자 예시)은 한 글자도 바뀌지 않는다.
    let abs = here.join("p.yaml");
    let b = parse_args(&args(&["--plugin", abs.to_str().unwrap()])).unwrap();
    let rb = verify_request(&b).unwrap();
    assert_eq!(rb.plugin.as_os_str(), abs.as_os_str());
    assert_eq!(rb.state_dir, None, "주지 않은 자리를 지어내지 않는다");
}

#[test]
fn repeated_key_is_a_list_and_last_wins_for_single() {
    // `--root` 는 여러 번 올 수 있고, `--out` 은 하나다. 한 파서가 둘 다
    // 답해야 하므로 두 시각을 모두 유지한다.
    let a = parse_args(&args(&["--root", "a", "--root", "b", "--out", "o"])).unwrap();
    assert_eq!(a.list("root"), vec!["a", "b"]);
    assert_eq!(a.need("out").unwrap(), "o");
    assert_eq!(a.list("없는키"), Vec::<String>::new());
}

#[test]
fn missing_value_and_bare_word_are_rejected() {
    // 조용히 넘어가면 `--out` 없이 부른 실행이 어디에 썼는지 모르게 된다.
    //
    // P5 에서 값 없는 스위치(`--yes`)가 생겼으므로 **파싱 단계에서는** 값이
    // 없어도 통과한다. 값이 필요한지 아는 것은 파서가 아니라 부르는 쪽이고,
    // `need` 가 빈 값을 거절한다. 거절되는 자리가 옮겨졌을 뿐 거절은 그대로다.
    assert!(
        parse_args(&args(&["--out"])).unwrap().need("out").is_err(),
        "값이 없는데 --out 이 받아들여졌다"
    );
    assert!(parse_args(&args(&["out", "x"])).is_err(), "'--' 가 없다");
    assert!(parse_args(&args(&[])).unwrap().need("out").is_err());
}

/// **모르는 옵션은 거절한다** — `--dryrun` 오타가 조용히 받아들여지면 `--yes` 와 함께 진짜 치료가 된다
/// (목표 remedy_시연전_안정화 · 기술부채 검토 1-6). `--help-all` 이 적은 옵션은 그대로 받는다.
#[test]
fn an_unknown_option_is_refused_instead_of_ignored() {
    let e = parse_args(&args(&["--plugin", "p", "--dryrun", "--yes"]))
        .err()
        .expect("오타 옵션이 받아들여졌다");
    assert!(e.contains("--dryrun"), "{e}");
    assert!(parse_args(&args(&["--plugin", "p", "--dry-run", "--yes"])).is_ok());
    for k in KNOWN_OPTIONS {
        let flag = format!("--{k}");
        assert!(parse_args(&args(&[flag.as_str()])).is_ok(), "{flag}");
    }
}

#[test]
fn switches_are_recognized_without_eating_the_next_argument() {
    // `--yes --out o` 에서 `--yes` 가 `--out` 을 값으로 먹으면, 산출 경로가
    // 사라진 채로 실행이 시작된다.
    let a = parse_args(&args(&["--yes", "--out", "o"])).unwrap();
    assert!(a.has("yes"));
    assert_eq!(a.need("out").unwrap(), "o");
    assert!(!a.has("없는스위치"));

    // 마지막에 온 스위치도 마찬가지다.
    let b = parse_args(&args(&["--out", "o", "--yes"])).unwrap();
    assert!(b.has("yes"));
    assert_eq!(b.need("out").unwrap(), "o");
    // 스위치는 값이 아니므로 `get` 이 주지 않는다.
    assert_eq!(b.get("yes"), None);
}

#[test]
fn outcome_lets_a_finding_beat_incompleteness() {
    let incomplete = Observation {
        denied_dirs: 1,
        ..Default::default()
    };
    let complete = Observation::default();

    assert_eq!(outcome(&[], &complete, None), Code::NoThreat);
    assert_eq!(outcome(&[], &incomplete, None), Code::IncompleteObservation);

    // **찾았으면 관측이 불완전해도 2 다.** 불완전성은 "없다" 를 뒤집을 뿐
    // "있다" 를 뒤집지 못한다 — 여기가 뒤집히면 무인 배포가 실제 감염을
    // "관측 불완전" 으로 흘려보낸다.
    let found = vec!["g0".to_string()];
    assert_eq!(outcome(&found, &complete, None), Code::FoundNotRemediated);
    assert_eq!(outcome(&found, &incomplete, None), Code::FoundNotRemediated);
}

/// 선언한 루트 `n` 개가 전부 없는 관측.
fn all_missing(n: usize) -> Observation {
    Observation {
        declared_roots: n,
        missing_roots: (0..n).map(|i| format!("/opt/none-{i}")).collect(),
        ..Default::default()
    }
}

#[test]
fn a_check_plugin_reads_all_roots_missing_as_not_applicable() {
    // B-6. **점검에서만** 루트 전부 없음이 "해당 없음" 이다.
    let gone = all_missing(2);
    let check = Some(PluginKind::Check);

    // 치료는 그대로 6 이다 — 아무 곳도 열어 보지 못한 스캔이 "위협 없음" 을
    // 내는 구멍(관측 01 D2)의 회귀 방지가 거기 걸려 있다.
    assert_eq!(outcome(&[], &gone, None), Code::IncompleteObservation);
    // 점검은 0 이다 — 미설치 기계가 가장 흔한 경우인데 6 으로 나갔다.
    assert_eq!(outcome(&[], &gone, check), Code::NoThreat);

    // **다른 사유가 섞이면 점검도 6 이다.** 면제는 `all_roots_missing`
    // 하나뿐이고, 나머지 여섯은 그대로 남는다. 갈래가 늘면 이 목록도
    // 늘린다 — 여기 없는 갈래는 점검에서 조용히 0 이 될 수 있다.
    for mixed in [
        Observation {
            truncated: true,
            ..all_missing(2)
        },
        Observation {
            denied_dirs: 1,
            ..all_missing(2)
        },
        Observation {
            unevaluated_rules: vec!["rules/a.yar:r".into()],
            ..all_missing(2)
        },
        Observation {
            uncollected_subjects: vec![remedy_sdk::catalog::Subject::Process],
            ..all_missing(2)
        },
        Observation {
            unreadable_versions: vec!["C:\\p\\php.exe".into()],
            ..all_missing(2)
        },
        Observation {
            unreadable_roots: vec!["\\\\host\\share".into()],
            ..all_missing(2)
        },
    ] {
        assert_eq!(
            outcome(&[], &mixed, check),
            Code::IncompleteObservation,
            "다른 사유가 섞였는데 0 이 나왔다: {mixed:?}"
        );
    }

    // **찾았으면 2 다** — 종류와 무관하다.
    let found = vec!["g0".to_string()];
    assert_eq!(outcome(&found, &gone, check), Code::FoundNotRemediated);

    // 루트가 하나만 없는 것은 애초에 불완전이 아니다 — 종류와 무관하게 0.
    let partial = Observation {
        declared_roots: 2,
        missing_roots: vec!["/opt/none-0".into()],
        ..Default::default()
    };
    assert_eq!(outcome(&[], &partial, None), Code::NoThreat);
    assert_eq!(outcome(&[], &partial, check), Code::NoThreat);
}

/// 거부 경로 `n` 개를 가진 관측 하나.
fn denied(dirs: usize, sample: usize) -> Observation {
    Observation {
        denied_dirs: dirs,
        denied_paths: (0..sample).map(|i| format!("C:\\d{i}")).collect(),
        ..Default::default()
    }
}

#[test]
fn the_screen_names_where_it_was_blocked() {
    use remedy_core::report::Lang;

    // **거부가 없으면 절이 통째로 나오지 않는다.** 빈 머리말은 "아무 데도
    // 안 막혔다" 로 잘못 읽힌다.
    assert!(denied_lines(&Observation::default(), Lang::Ko).is_empty());
    // 낡은 산출물에는 개수만 있고 경로가 없다 — 그때도 머리말만 띄우지 않는다.
    assert!(denied_lines(&denied(2, 0), Lang::Ko).is_empty());

    // 한 곳이면 그 한 줄이 전부다. **"외 0곳" 을 적지 않는다.**
    let one = denied_lines(&denied(1, 1), Lang::Ko);
    assert_eq!(one.len(), 2, "{one:?}");
    assert!(one[0].contains("거부된 자리"), "{one:?}");
    assert!(one[1].contains("C:\\d0"), "{one:?}");
}

/// 거부된 자리 표본은 **거부 사유 바로 아래**에 선다 — 사유가 여럿이어도(2026-11-12 · 리눅스
/// 컨테이너: 접근 거부 다음에 룰의 확인 필요 사유가 섰고, 목록이 그 밑에 붙어 그 사유의 경로로
/// 읽혔다). 잘림 사유가 앞에 있으면 그 다음 자리다.
#[test]
fn the_denied_sample_follows_the_denial_reason() {
    use remedy_core::report::Lang;
    use remedy_sdk::artifact::UnconfirmedNote;

    let note = UnconfirmedNote {
        why: [("ko".to_string(), "룰의 사유".to_string())].into(),
        groups: vec!["g0".into()],
        rules: vec!["r".into()],
    };
    for truncated in [false, true] {
        let obs = Observation {
            truncated,
            unconfirmed: vec![note.clone()],
            ..denied(1, 1)
        };
        let lines = reason_lines(&obs, Lang::Ko);
        let at = |needle: &str| {
            lines
                .iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("'{needle}' 이 없다: {lines:?}"))
        };
        let denial = at("접근이 거부된");
        assert_eq!(at("거부된 자리:"), denial + 1, "{lines:?}");
        assert_eq!(at("C:\\d0"), denial + 2, "{lines:?}");
        assert!(at("룰의 사유") > denial + 2, "{lines:?}");
    }
}

#[test]
fn the_screen_says_the_sample_is_not_the_whole() {
    use remedy_core::report::Lang;

    // 다섯 곳에서 막혔으면 **세 줄과 "외 2곳"** 이다. 보인 것이 전부로
    // 읽히면 사람은 남은 두 곳을 영영 찾지 않는다.
    let five = denied_lines(&denied(5, 5), Lang::Ko);
    assert_eq!(five.len(), 1 + DENIED_SHOWN + 1, "{five:?}");
    assert!(five[3].contains("C:\\d2"), "{five:?}");
    assert!(five[4].contains("외 2곳"), "{five:?}");

    // **표본 자체가 잘린 경우.** `denied_paths` 는 상한(32)에 걸려 32개고
    // 실제로는 40곳에서 막혔다 — 남은 수는 40-3 이지 32-3 이 아니다.
    let many = denied_lines(&denied(40, 32), Lang::Ko);
    assert!(many[4].contains("외 37곳"), "{many:?}");

    // 영어도 같은 사실을 말한다.
    let en = denied_lines(&denied(5, 5), Lang::En);
    assert!(en[0].contains("denied at"), "{en:?}");
    assert!(en[4].contains("and 2 more"), "{en:?}");
}

// ── 폐기 목록 · 내장 최소 버전의 문(`revocation_gate` · 설계-03 §6) ──────────────────────────

/// 상태 폴더 하나와 공개키 파일. `entries` 가 있으면 시험이 스스로 만든 키쌍으로 폐기 목록에 서명해 그 폴더에
/// 둔다(remedy-trust 시험과 같은 꼴 — 개인키를 저장소에 두지 않고 실제 서명으로 잰다).
fn gate_lab(
    name: &str,
    serial: u64,
    entries: Option<&[remedy_trust::revocation::Entry]>,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let d = std::env::temp_dir()
        .join("remedy-cli-revocation-gate")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    let state = d.join("state");
    std::fs::create_dir_all(&state).expect("상태 폴더");
    let kp = minisign::KeyPair::generate_unencrypted_keypair().expect("키쌍");
    if let Some(entries) = entries {
        let body = remedy_trust::revocation::render_body(entries).expect("본문");
        let comment = remedy_trust::revocation::render_comment(serial, "2026-11-17T00:00:00Z");
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
        text.push('\n');
        text.push_str(&body);
        std::fs::write(state.join(remedy_trust::revocation::LIST_FILE), text).expect("목록");
    }
    let pk = d.join("pub.key");
    std::fs::write(&pk, kp.pk.to_box().expect("공개키 상자").to_string()).expect("공개키");
    (state, pk)
}

fn revoke(plugin: &str, exact: &str, reason: &str) -> remedy_trust::revocation::Entry {
    remedy_trust::revocation::Entry {
        plugin: plugin.into(),
        below: None,
        exact: Some(exact.into()),
        reason: reason.into(),
    }
}

/// 판정에 쓰는 것은 id · version 뿐이다 — 나머지는 읽히기만 하면 된다.
fn gate_manifest(id: &str, version: &str) -> PluginManifest {
    serde_yaml_ng::from_str(&format!(
        "schema_version: 1\nid: {id}\nversion: '{version}'\nmin_core: '1.0.0'\n\
         platforms: [windows, linux]\nname: {{ en: 'gate' }}\nscan_roots: ['/nowhere']\n\
         subjects: [file]\ndetect:\n  - id: r\n    subject: file\n    where:\n\
         \x20     - {{ field: path, op: ends_with, value: '.x' }}\nverdict: {{ require: 'r' }}\n"
    ))
    .expect("매니페스트")
}

fn gate_args(state: &std::path::Path, pk: Option<&std::path::Path>) -> Args {
    let mut v = vec!["--state-dir".to_string(), state.display().to_string()];
    if let Some(pk) = pk {
        v.push("--public-key".to_string());
        v.push(pk.display().to_string());
    }
    parse_args(&v).unwrap()
}

#[test]
fn the_built_in_minimum_table_parses() {
    // 문은 이 표를 맨 앞에서 읽는다 — 꼴이 틀린 값이 들어가면 모든 검사 · 치료가 4 로 멈춘다.
    assert!(remedy_trust::revocation::MinVersions::from_pairs(MIN_PLUGIN_VERSIONS).is_ok());
}

#[test]
fn without_a_list_the_gate_reads_nothing() {
    // 목록이 없으면 앵커도 상태 파일도 버전도 보지 않는다 — 깨진 상태 파일 · 공개키 없음 · 읽을 수 없는 버전이
    // 함께 있어도 통과한다. 오늘의 모든 실행이 지나는 길이다.
    let (state, _) = gate_lab("no-list", 1, None);
    std::fs::write(state.join(remedy_trust::revocation::STATE_FILE), "{").expect("상태");
    let r = revocation_gate(&gate_args(&state, None), &gate_manifest("gate-demo", "v1"));
    assert!(
        r.is_ok(),
        "{}",
        r.err().map(|f| f.message).unwrap_or_default()
    );
}

#[test]
fn a_list_naming_the_rule_stops_it_with_five() {
    let (state, pk) = gate_lab(
        "named",
        1,
        Some(&[revoke("gate-demo", "1.0.0", "lab reason")]),
    );
    let a = gate_args(&state, Some(&pk));
    let f = revocation_gate(&a, &gate_manifest("gate-demo", "1.0.0")).unwrap_err();
    assert_eq!(f.code, Code::GuardStop, "{}", f.message);
    assert!(
        f.message.contains("gate-demo") && f.message.contains("lab reason"),
        "{}",
        f.message
    );
    // 고친 판은 지난다 — 목록은 1.0.0 만 겨눴다.
    assert!(revocation_gate(&a, &gate_manifest("gate-demo", "1.0.1")).is_ok());
}

#[test]
fn a_list_naming_other_rules_does_not_judge_this_one() {
    // 판정하면 `x.y.z` 가 아닌 버전을 쓰는 이 룰까지 5 로 멈춘다 — 겨눈 룰만 판정한다.
    let (state, pk) = gate_lab("other", 1, Some(&[revoke("other-rule", "1.0.0", "x")]));
    let r = revocation_gate(
        &gate_args(&state, Some(&pk)),
        &gate_manifest("gate-demo", "v1"),
    );
    assert!(
        r.is_ok(),
        "{}",
        r.err().map(|f| f.message).unwrap_or_default()
    );
}

#[test]
fn a_list_signed_by_another_key_stops_with_five() {
    // 목록 자체는 겨누는 룰이 없어도 확인한다 — 바꿔치기된 목록을 조용히 넘기지 않는다.
    let (state, pk) = gate_lab("other-key", 1, Some(&[revoke("other-rule", "1.0.0", "x")]));
    let (_, wrong) = gate_lab("other-key-pk", 1, None);
    std::fs::copy(&wrong, &pk).expect("다른 공개키");
    let f = revocation_gate(
        &gate_args(&state, Some(&pk)),
        &gate_manifest("gate-demo", "1.0.0"),
    )
    .unwrap_err();
    assert_eq!(f.code, Code::GuardStop, "{}", f.message);
}

#[test]
fn an_older_list_than_already_seen_stops_with_five() {
    // 반입 때 막는 옛 목록 되밀기를 파일을 직접 바꿔 넣는 길에서도 막는다(`load_allowed` 와 같다).
    let (state, pk) = gate_lab("stale", 3, Some(&[revoke("other-rule", "1.0.0", "x")]));
    std::fs::write(
        state.join(remedy_trust::revocation::STATE_FILE),
        r#"{"revocation_serial":9}"#,
    )
    .expect("상태");
    let f = revocation_gate(
        &gate_args(&state, Some(&pk)),
        &gate_manifest("gate-demo", "1.0.0"),
    )
    .unwrap_err();
    assert_eq!(f.code, Code::GuardStop, "{}", f.message);
}

#[test]
fn the_menu_folder_reads_both_places() {
    // 메뉴는 실행 파일 옆 `state` 를 넘긴다 — 문서가 안내하는 명령줄 반입(기본 자리)도 메뉴에 걸리게 두 자리를
    // 다 읽는다. 다른 폴더는 그 하나다(시험 · 하네스가 기계 공용 자리를 건드리지 않는다).
    assert_eq!(trust_dirs(&beside_exe("state")), menu_state_dirs());
    let given = std::path::Path::new("given-state");
    assert_eq!(trust_dirs(given), vec![given.to_path_buf()]);
}
