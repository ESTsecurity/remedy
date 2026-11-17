//! 작업 뒤 — 결과에 맞는 다음 할 일 · 위협별 안내 · 메뉴로 돌아가기(2026-11-17 에 main.rs 에서 옮겼다).

use super::*;

/// 고객이 보는 사용법. 명령은 둘이면 된다 — 치료와 되돌리기.
/// 창이 곧바로 닫히지 않게 한 줄을 기다린다.
///
/// # 언제 기다리는가 — **인자가 없고 사람이 앞에 있을 때만**
///
/// 이 함수는 `main` 의 `None` 갈래에서만 불린다. 인자가 하나라도 있으면 여기
/// 오지 않는다 — 그것이 불변식이고 `never_waits.rs` 가 잠근다.
///
/// | 어떻게 불렀나 | stdin | 기다리는가 |
/// |---|---|---|
/// | 탐색기에서 더블클릭 | 새 콘솔 | **예** — 그러지 않으면 화면을 못 읽는다 |
/// | 콘솔에서 `remedy` | 그 콘솔 | 예 — 사람이 앞에 있다 |
/// | 스크립트·파이프·CI | 터미널 아님 | **아니오** — 무인 배포가 여기서 선다 |
/// | RunOnce 의 `verify …` | 무엇이든 | **아니오** — 인자가 있어 이 갈래를 지나지 않는다 |
///
/// # EOF 도 끝이다
///
/// `read_line` 이 0 을 돌려주면(stdin 이 닫혔다) 곧바로 반환한다. 기다리는 것은
/// **사람의 Enter 이지 입력 자체가 아니다.**
/// 이 작업이 시스템을 바꾸는가 — Ctrl+C 두 번으로 끊기면 부분(3), 아니면 "위협 없음"
/// 을 말할 수 없음(6)이다(`term`). 목록 반입도 상태 파일을 고쳐 쓰므로 바꾸는 쪽이다.
pub(super) fn changes_system(o: &guided::Outcome) -> bool {
    match o {
        guided::Outcome::RunWith(_) | guided::Outcome::TreatAll(..) => true,
        guided::Outcome::WithPlugin(w) => matches!(w, menu::WithPlugin::Run(_)),
        guided::Outcome::WithRun(r) => {
            matches!(r, menu::WithRun::Restore(_) | menu::WithRun::Resume(_))
        }
        guided::Outcome::WithFile(f, _) => matches!(
            f,
            menu::WithFile::Apply(_)
                | menu::WithFile::AllowImport(_)
                | menu::WithFile::RevokeImport(_)
        ),
        _ => false,
    }
}

/// 작업 뒤의 *다음 할 일* 을 가르는 갈래.
#[derive(Clone, Copy)]
pub(super) enum Flow {
    Scan,
    ScanAll,
    Treat,
    /// 찾은 것 모두 치료하기 — *다음 할 일* 은 [`treat_all`] 이 룰마다 지어 앞줄로 준다.
    TreatAll,
    Restore,
    Verify,
    /// 룰 서명 확인(`plugin verify --dir`) — 성공했을 때 끝줄을 풀이한다(`guidance`).
    Signature,
    /// 신고 묶음 — 만든 뒤 보낼 곳을 적는다(`guidance` · README "지원 · 신고" 와 같은 말).
    Report,
    Other,
}

/// 고른 룰이 치료하는가 — 검사만 뒤의 안내가 이것으로 갈린다. 다른 갈래는 치료하는 룰에서만
/// 메뉴에 서므로(`menu::items`) 참이다.
pub(super) fn treats_of(p: &guided::Outcome) -> bool {
    match p {
        guided::Outcome::WithPlugin(menu::WithPlugin::Scan(path)) => guided::treats(path),
        _ => true,
    }
}

/// 고른 룰 폴더의 기록 — 찾기만 하는 룰이 찾았을 때와 치료가 끝났을 때 `guidance` 가 가리킨다.
pub(super) fn notes_of(p: &guided::Outcome) -> Vec<std::path::PathBuf> {
    match p {
        guided::Outcome::WithPlugin(menu::WithPlugin::Scan(path))
        | guided::Outcome::WithPlugin(menu::WithPlugin::Run(path))
        | guided::Outcome::RunWith(path) => notes_beside(path).into_iter().collect(),
        _ => Vec::new(),
    }
}

pub(super) fn flow_of(p: &guided::Outcome) -> Flow {
    match p {
        guided::Outcome::WithPlugin(menu::WithPlugin::Scan(_)) => Flow::Scan,
        guided::Outcome::ScanAll(..) => Flow::ScanAll,
        guided::Outcome::TreatAll(..) => Flow::TreatAll,
        guided::Outcome::WithPlugin(menu::WithPlugin::Run(_))
        | guided::Outcome::RunWith(..)
        | guided::Outcome::WithFile(menu::WithFile::Apply(_), _) => Flow::Treat,
        guided::Outcome::WithRun(menu::WithRun::Restore(_)) => Flow::Restore,
        // **이어서 한 치료는 치료다** — 끝나면 유지 확인 · 복원 · 신고를 가리킨다(1.21.1 까지는 `Other` 라
        // 다음 할 일이 비었다 · 목표 remedy_시연전_안정화 흐름 표).
        guided::Outcome::WithRun(menu::WithRun::Resume(_)) => Flow::Treat,
        guided::Outcome::WithRun(menu::WithRun::Support(_)) => Flow::Report,
        guided::Outcome::WithPlugin(menu::WithPlugin::Verify(_)) => Flow::Verify,
        guided::Outcome::WithPlugin(menu::WithPlugin::VerifyBundle(_)) => Flow::Signature,
        _ => Flow::Other,
    }
}

/// 작업 뒤에 고를 만한 메뉴 줄 — 결과에 맞는 것만(목표 remedy_제품화 기준 6(d)).
/// 전에는 다음 할 일을 명령줄로만 적었다(`remedy restore --run …`).
///
/// `treats` 가 거짓이면(찾기만 하는 룰 · 모두 검사만에서 찾은 룰이 전부 그렇다) 치료를 권하지
/// 않는다 — 메뉴도 그 줄을 꺼 둔다(목표 remedy_출시_20261111 기준 4).
pub(super) fn next_steps(flow: Flow, code: Code, treats: bool) -> Vec<(&'static str, menu::Line)> {
    let lang = ui().lang;
    match (flow, code) {
        (Flow::Scan | Flow::ScanAll, Code::FoundNotRemediated) if !treats => Vec::new(),
        // 모두 검사만 뒤에는 고르는 화면으로 돌아간다. 그 앞줄은 그 화면의 *찾은 것 모두 치료하기* 다
        // ([`scan_all_lead`] — 메뉴 줄이 아니라 고르는 화면의 줄이라 따로 짓는다). 이 줄은 하나씩
        // 치료하는 길 — 그 룰을 고른 뒤의 1 번이다.
        (Flow::ScanAll, Code::FoundNotRemediated) => vec![(
            lang.t(
                "하나씩 치료하려면 그 룰을 고른 뒤",
                "To treat one at a time, pick that rule, then",
            ),
            menu::Line::Treat,
        )],
        // 검사만 뒤에는 치료 하나만 권한다 — 접힌 운영자 명령(*승인한 계획을 수행하기*)으로
        // 보내면 승인한 적 없는 사람에게 '승인한 계획' 을 말하게 된다(v1.1.0 적대적 검토).
        (Flow::Scan, Code::FoundNotRemediated) => vec![(
            lang.t("찾은 것을 치료하려면", "To treat what was found"),
            menu::Line::Treat,
        )],
        // **유지 확인이 먼저다.** 되돌리기가 첫 줄이면 할 일 목록으로 읽혀 악성코드를 되살릴
        // 수 있다(같은 검토) — 되돌리기는 오탐일 때의 일이라 그 조건을 줄에 적는다.
        (Flow::Treat, Code::Remediated) => vec![
            (
                lang.t("치료가 유지되는지 보려면", "To check that it held"),
                menu::Line::Verify,
            ),
            (
                lang.t("오탐이라면", "If it was a false positive"),
                menu::Line::Undo,
            ),
            (
                lang.t("오탐을 신고하려면", "To report a false positive"),
                menu::Line::Report,
            ),
        ],
        (Flow::Treat | Flow::Verify, Code::FoundNotRemediated) => {
            vec![(lang.t("치료하려면", "To treat it"), menu::Line::Treat)]
        }
        // **되돌린 사람은 오탐이라고 본 사람이다** — 신고가 먼저고, 마음을 바꾼 사람의 다시 치료는 그다음이다.
        // 전에는 *치료하려면* 한 줄뿐이었다(목표 remedy_시연전_안정화 A7).
        (Flow::Restore, Code::NoThreat) => vec![
            (
                lang.t("오탐을 신고하려면", "To report a false positive"),
                menu::Line::Report,
            ),
            (
                lang.t("다시 치료하려면", "To treat it again"),
                menu::Line::Treat,
            ),
        ],
        // **이어서 하기가 아니다.** 실패한 Action 이 있어도 실행기는 모든 결과와 끝을 적으므로
        // 그 회차는 끝난 회차다 — 이어서 하기는 '이미 적용됨'(5)으로 거절한다(2026-11-07 적대적
        // 검토). 까닭을 해결한 뒤 새로 검사해 치료한다(README 결과 표 · 재시작 조언과 같은 말).
        //
        // **'남은 것을 치료' 라고 약속하지 않는다.** 판정의 근거가 이미 치워졌으면 다시 검사는
        // 위협 없음(0)으로 끝나고 실패한 항목은 그대로 남는다(rc.2 실측 — CWPdoor 바이너리는
        // 격리, 유닛 삭제만 읽기 전용으로 실패: 다시 검사 0 · 유닛 그대로).
        (Flow::Treat, Code::PartialFailure) => vec![
            (
                lang.t(
                    "까닭을 해결한 뒤 다시 검사하려면",
                    "To scan again once the cause is fixed",
                ),
                menu::Line::Treat,
            ),
            (lang.t("신고하려면", "To report it"), menu::Line::Report),
        ],
        // 복원은 이어서 할 회차를 만들지 않는다.
        (Flow::Restore, Code::PartialFailure) => {
            vec![(lang.t("신고하려면", "To report it"), menu::Line::Report)]
        }
        _ => Vec::new(),
    }
}

/// 메뉴 줄로 가리킬 수 없는 다음 할 일 — **찾기만 하는 룰이 찾았을 때** 조치 차례가 있는 곳.
///
/// 그 룰은 치료를 권하지 않으므로(`next_steps`) 전에는 *다음 할 일* 이 비었다. SSH 백도어를
/// 찾은 가장 급한 순간에 화면이 할 일을 말하지 않았다(v1.1.0 적대적 검토).
///
/// **받은 폴더 안의 기록도 적는다** (`notes` — 찾은 룰 폴더의 `RELEASE.md`). 인터넷이 막힌
/// 서버에서는 주소만으로는 차례를 볼 곳이 없었다(2026-11-07 적대적 검토). 줄은 80칸 안이다 —
/// 리눅스 콘솔(가상 콘솔 · IPMI)은 흔히 80칸이다.
///
/// **치료가 끝났을 때도 같은 곳을 가리킨다**(2026-11-08 적대적 검토 4바퀴). 치료 뒤 다음 할 일은
/// 유지 확인 · 복원 · 신고뿐이었다 — CWPdoor 는 패널을 공급사 버전으로 다시 설치하고 자격 증명을
/// 바꿔야 하고 EvilAI 는 다시 시작 · 전체 검사 · 비밀번호 변경이 남는데, 화면은 그것을 말하지 않았다.
///
/// **룰 서명 확인이 성공했을 때는 끝줄을 풀이한다**(같은 검토). 화면의 끝줄이 *"폐기 목록 없음 —
/// 폐기 여부를 확인하지 못했습니다"* 라 성공이 실패로 읽혔다 — 그 줄은 인자 실행의 출력이라 다음
/// 버전에서 고치고, 메뉴에서는 여기서 풀어 준다.
pub(super) fn guidance(
    flow: Flow,
    code: Code,
    treats: bool,
    notes: &[std::path::PathBuf],
) -> Option<String> {
    // **만든 묶음을 어디로 보내는지가 화면에 없었다**(1.21.1 · 목표 remedy_시연전_안정화 흐름 표) — 묶음에는
    // 경로 · 호스트명 · 사용자명이 그대로 들어 있어 공개 이슈에 붙이면 안 된다.
    if matches!((flow, code), (Flow::Report, Code::NoThreat)) {
        return Some(ui().lang.t(SEND_TO.0, SEND_TO.1).to_string());
    }
    if matches!((flow, code), (Flow::Signature, Code::NoThreat)) {
        let lang = ui().lang;
        return Some(format!(
            "{}\n  {}",
            lang.t(SIGNED_OK.0, SIGNED_OK.1),
            lang.t(NO_REVOCATION_YET.0, NO_REVOCATION_YET.1)
        ));
    }
    let found_by_a_checker = matches!(
        (flow, code),
        (Flow::Scan | Flow::ScanAll, Code::FoundNotRemediated)
    ) && !treats;
    let treated = matches!(
        (flow, code),
        (Flow::Treat | Flow::TreatAll, Code::Remediated)
    );
    // **깨끗하게 끝난 결과도 범위를 밝힌다**(2026-11-08 — 룰 대 공개 보도 대조). 룰은 공개 보도가
    // 밝힌 꼴을 찾는다. 같은 위협의 다른 설치 방법 · 다른 키 · 다른 자리는 이름 그대로 찾지 못하는데,
    // 화면은 *"위협이 발견되지 않았습니다"* 로만 끝나 그 결과가 기계의 무죄로 읽혔다(실측: Ebury 는
    // ESET 가 적은 설치 방법 다섯 중 하나만, CWPdoor 는 키가 다르면 0, EvilAI 는 보도의 변종에서 0).
    // 종료 코드와 결과 줄은 그대로다 — 더하는 것은 무엇을 보았는지 읽을 곳 한 줄이다.
    let clean = matches!(
        (flow, code),
        (
            Flow::Scan | Flow::ScanAll | Flow::Treat | Flow::TreatAll,
            Code::NoThreat
        )
    );
    if !found_by_a_checker && !treated && !clean {
        return None;
    }
    let lang = ui().lang;
    let head = if treated {
        TREATED_NEXT
    } else if clean {
        CLEAN_SCOPE
    } else {
        CHECKER_FOUND
    };
    let mut s = format!(
        "{}\n    https://github.com/ESTsecurity/remedy#위협별-안내",
        lang.t(head.0, head.1)
    );
    if !notes.is_empty() {
        // 깨끗한 결과에는 '같은 차례' 라고 하지 않는다 — 할 차례가 없다. 적혀 있는 것은 범위다.
        let off = if clean {
            CLEAN_OFFLINE
        } else {
            CHECKER_OFFLINE
        };
        s.push_str(&format!("\n  {}", lang.t(off.0, off.1)));
        for n in notes {
            s.push_str(&format!("\n    {}", n.display()));
        }
    }
    Some(s)
}

/// 신고 묶음을 보낼 곳 — README "지원 · 신고" 와 같은 말. 줄마다 80칸 안이다.
pub(super) const SEND_TO: (&str, &str) = (
    "보낼 곳 — 이 도구를 나눠 준 담당자입니다.\n    \
     GitHub 에서 받았다면 security@estsecurity.com 으로 보내십시오.\n    \
     공개된 곳(이슈 등)에는 올리지 마십시오.",
    "Where to send it — whoever gave you this tool.\n    \
     If you got it from GitHub, send it to security@estsecurity.com.\n    \
     Do not post it anywhere public (issues included).",
);

pub(super) const CHECKER_FOUND: (&str, &str) = (
    "이 항목은 찾기만 합니다 — 조치 차례는 README 의 '위협별 안내'에 있습니다:",
    "This rule only detects — what to do is in the README's per-threat notes:",
);
pub(super) const CLEAN_OFFLINE: (&str, &str) = (
    "인터넷이 막힌 곳이면 받은 폴더의 이 파일에 적혀 있습니다:",
    "Without internet, it is written in this file in the downloaded folder:",
);
pub(super) const CLEAN_SCOPE: (&str, &str) = (
    "'위협 없음' 은 이 항목이 아는 유형을 찾지 못했다는 뜻입니다 — 무엇을 보는지:",
    "'No threat' means this item's known shapes were not found. What it checks:",
);
pub(super) const SIGNED_OK: (&str, &str) = (
    "서명이 맞고, 룰 파일도 받은 그대로입니다.",
    "The signature matches and every rule file is as shipped.",
);
pub(super) const NO_REVOCATION_YET: (&str, &str) = (
    "'폐기 목록 없음' 은 아직 폐기한 룰이 없다는 뜻입니다.",
    "'폐기 목록 없음' (no revocation list) means nothing has been revoked yet.",
);
pub(super) const TREATED_NEXT: (&str, &str) = (
    "치료 뒤에 할 일은 위협마다 다릅니다 — README 의 '위협별 안내'에 있습니다:",
    "After-treatment steps differ by threat — see the README's per-threat notes:",
);
pub(super) const CHECKER_OFFLINE: (&str, &str) = (
    "인터넷이 막힌 곳이면 받은 폴더의 이 파일에 같은 차례가 있습니다:",
    "Without internet, the same steps are in this file in the downloaded folder:",
);

/// 작업이 끝나고 메뉴로 돌아간다. 구분선 · 다음 할 일을 남기고 **Enter 를 기다린다** —
/// 메뉴가 곧바로 다시 서면 결과 줄이 창 밖으로 밀린다(21줄 메뉴 · 30줄 창 · 2026-11-06
/// 이미지). 기다리는 줄은 화면을 붙잡는 장치라 stderr 로 낸다(`wait_before_closing` 과 같다).
pub(super) fn back_to_menu(
    flow: Flow,
    code: Code,
    treats: bool,
    notes: &[std::path::PathBuf],
    lead: &[String],
    tail: &[String],
) {
    let lang = ui().lang;
    let d = remedy_sdk::i18n::deco();
    outln!();
    outln!("{}", d.rule());
    // 번호는 **돌아갈 그 화면에서** 센다 — 기본 화면은 일이 있을 때만 줄을 세우므로(목표
    // remedy_사용자메뉴 기준 4), 이 작업이 만든 · 지운 회차를 지금 다시 읽은 모양으로 센다. 그 화면에
    // 서지 않는 줄은 적지 않는다(찾기만 하는 룰의 메뉴로 돌아가면 치료 줄을 가리키지 않는다).
    let after = guided::next_offer();
    let next: Vec<(&str, usize, String)> = next_steps(flow, code, treats)
        .into_iter()
        .filter_map(|(why, l)| menu::line(l, &after).map(|(n, label)| (why, n, label)))
        .collect();
    let read = guidance(flow, code, treats, notes);
    let pick = guided::picked_rule();
    if !lead.is_empty() || !next.is_empty() || read.is_some() || !tail.is_empty() {
        outln!("{}", lang.t("다음 할 일", "Next"));
        // **앞줄이 먼저다** — 고르는 화면의 줄(*찾은 것 모두 치료하기*)과 룰마다 먼저 고를 룰을 붙인 줄.
        for l in lead {
            outln!("{l}");
        }
        for l in step_block(&next, pick.as_ref(), d) {
            outln!("{l}");
        }
        if let Some(r) = read {
            outln!("  {r}");
        }
        // 끝줄 — 찾은 것을 다 다룬 뒤의 일(빠른 검사 뒤의 정밀 검사).
        for l in tail {
            outln!("{l}");
        }
        outln!();
    }
    screen_err!(
        "{}",
        lang.t(
            "Enter 를 누르면 메뉴로 돌아갑니다. ",
            "Press Enter to go back to the menu. "
        )
    );
    use std::io::Write;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

/// 다음 할 일 한 줄. 룰이 여럿인 세션이면 **먼저 고를 룰**(고르는 화면의 번호 · 이름)을 메뉴
/// 줄 앞에 적는다 — 작업 뒤 Enter 는 그 화면으로 돌아가고, 메뉴 줄의 번호는 룰을 고른 뒤의
/// 화면에서만 맞는다([`guided::picked_rule`] · 2026-11-08 적대적 검토 4바퀴).
pub(super) fn step_line(
    why: &str,
    pick: Option<&(usize, String)>,
    n: usize,
    label: &str,
    d: remedy_sdk::i18n::Deco,
) -> String {
    match pick {
        // 룰이 한 화면을 넘어 묶음 · 찾기로 고른 룰에는 고르는 화면의 번호가 없다(0) — 이름으로 적는다.
        Some((0, rule)) => format!("  {why}{}{rule} {} {n}. {label}", d.dash(), d.arrow()),
        Some((rn, rule)) => format!("  {why}{}{rn}. {rule} {} {n}. {label}", d.dash(), d.arrow()),
        None => format!("  {why}{}{n}. {label}", d.dash()),
    }
}

/// 한 룰의 다음 할 일 덩어리. 룰이 여럿인 세션이면 **먼저 고를 룰을 한 번만** 적고 메뉴 줄을 그 아래에 들여
/// 적는다 — 전에는 줄마다 *"3. EvilAI(Locust) 제거 → 4. …"* 로 같은 앞부분을 되풀이해 *"4 → 4"* 가 헷갈렸다
/// (처음 쓰는 사람 검토 · 목표 remedy_시연전_안정화 D5). 룰이 하나면 [`step_line`] 그대로다.
pub(super) fn step_block(
    steps: &[(&str, usize, String)],
    pick: Option<&(usize, String)>,
    d: remedy_sdk::i18n::Deco,
) -> Vec<String> {
    let Some((rn, rule)) = pick else {
        return steps
            .iter()
            .map(|(why, n, label)| step_line(why, None, *n, label, d))
            .collect();
    };
    if steps.is_empty() {
        return Vec::new();
    }
    let lang = ui().lang;
    // 묶음 · 찾기로 고른 룰에는 고르는 화면의 번호가 없다(0) — 이름으로 적는다.
    let first = match rn {
        0 => rule.clone(),
        rn => format!("{rn}. {rule}"),
    };
    let mut out = vec![lang.pick(
        format!(
            "  먼저 {} 고른 뒤:",
            remedy_sdk::i18n::with_particle(&first, "을", "를")
        ),
        format!("  First pick {first}, then:"),
    )];
    out.extend(
        steps
            .iter()
            .map(|(why, n, label)| format!("  {}", step_line(why, None, *n, label, d))),
    );
    out
}
