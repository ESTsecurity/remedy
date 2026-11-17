//! 모두 검사 · 찾은 것 모두 치료하기 — 고르는 화면 맨 위의 검사 줄과 그 뒤의 한 번 승인(2026-11-17 에 main.rs 에서 옮겼다).

use super::*;

/// 룰 폴더에 든 기록(`RELEASE.md`) — 있을 때만. 배포 파일의 룰 폴더마다 하나씩 든다.
pub(super) fn notes_beside(plugin: &std::path::Path) -> Option<std::path::PathBuf> {
    let p = plugin.parent()?.join("RELEASE.md");
    p.is_file().then_some(p)
}

/// **모두 검사만** — 룰을 고르는 화면의 첫 줄(목표 remedy_출시_20261111 기준 3).
///
/// 찾은 룰마다 메뉴의 *검사만 하기* 와 **같은 인자로** `scan` 을 차례대로 부르고, 끝에 룰마다의
/// 결과를 한 덩어리로 다시 적는다 — 룰 셋의 화면이 이어지면 앞 룰의 결과는 창 밖으로 밀린다.
/// 아무것도 바꾸지 않는다 — 치료는 끝난 뒤 고르는 화면의 *찾은 것 모두 치료하기*([`treat_all`])나
/// 룰을 골라서 한다. 무엇을 찾았는지는 [`ScanAllDone`] 이 돌려준다.
///
/// `skipped` 는 **빼 둔 룰과 그 까닭**이다 — 네트워크 점검(주소를 적어야 돈다 · 코어 1.4.0)과, 빠른 검사가 빼는
/// 디스크 전체 룰(정밀 검사가 돈다). 끝의 요약에 그 항목도 한 줄씩 적는다. `kind` 는 고른 검사의 꼴이다 — 머리줄과
/// 요약의 이름만 다르고 도는 길은 같다(목표 remedy_기본검사_룰관리 결정 ①②).
pub(super) fn scan_all(
    list: &[(String, std::path::PathBuf)],
    skipped: &[(String, guided::Skip)],
    kind: guided::ScanKind,
) -> ScanAllDone {
    let lang = ui().lang;
    let d = remedy_sdk::i18n::deco();
    // **룰이 한 화면을 넘으면 룰마다의 검사 화면을 접는다**(목표 remedy_전체검사_운영기반 D10) — 화면에는 룰마다
    // 진행 한 줄만 서고(그리는 자리면 제자리에), 그 룰의 화면은 회차 로그에 그대로 남는다. 요약은 찾은 것 · 확인
    // 필요 · 마치지 못한 룰만 줄로 적고 나머지는 수로 적는다. 룰 1,000개에서 화면이 약 1만 9천 줄이었다(벤치).
    let many = list.len() > guided::MANY_RULES;
    let n = list.len();
    // 화면에서는 '항목' 하나로 부른다 — 고르는 화면이 *검사 항목 N개* 라고 했다(처음 쓰는 사람 검토: 한 흐름에 '항목' ·
    // '룰' 이 섞였다). 80칸 안 · 괄호 하나까지(목표 remedy_시연전_안정화 D5).
    let opening = match kind {
        guided::ScanKind::All => lang.pick(
            format!("모두 검사 — 항목 {n}개를 검사합니다. 아무것도 바꾸지 않습니다."),
            format!("Scanning all {n} items — nothing is changed."),
        ),
        guided::ScanKind::Quick => lang.pick(
            format!("빠른 검사 — 항목 {n}개를 검사합니다. 아무것도 바꾸지 않습니다."),
            format!("Quick scan — {n} items. Nothing is changed."),
        ),
        guided::ScanKind::Full => lang.pick(
            format!("정밀 검사 — 항목 {n}개를 디스크 전체까지 검사합니다. 오래 걸릴 수 있습니다."),
            format!("Full scan — {n} items, whole disks too. This can take a long time."),
        ),
    };
    outln!("{opening}");
    if many {
        outln!(
            "{}",
            lang.t(
                "룰이 많아 룰마다 한 줄로 적습니다 — 룰마다의 검사 화면은 상태 폴더의 기록(logs)에 남습니다.",
                "Many rules, so one line each — each rule's scan screen stays in the run logs (logs) in the state folder."
            )
        );
    }
    let mut done: Vec<ScanAllRow> = Vec::new();
    let mut found_notes: Vec<std::path::PathBuf> = Vec::new();
    let mut treat_found: Vec<(String, std::path::PathBuf)> = Vec::new();
    let mut other_found: Vec<String> = Vec::new();
    for (i, (label, path)) in list.iter().enumerate() {
        if i > 0 {
            // 룰마다 결과 폴더와 회차 로그를 따로 둔다 — 한 폴더면 뒤 룰의 `scan.json` 이 앞
            // 룰의 것을 덮는다(`menu_out` 은 작업마다 새 폴더다).
            tee::close();
            term::task_begin(false);
        }
        let head = format!("[{}/{}] {label}", i + 1, list.len());
        if many {
            if term::fancy() {
                tee::progress(head.clone());
            }
            tee::quiet(true);
        } else {
            // 항목마다 구분선을 긋지 않는다 — 빈 줄과 `[i/N]` 머리가 가른다(구분선은 요약 앞에 한 번).
            outln!();
            outln!("{head}");
        }
        let out = menu_out();
        let args = vec![
            "--plugin".to_string(),
            path.to_string_lossy().to_string(),
            "--out-dir".to_string(),
            out.to_string_lossy().to_string(),
            "--state-dir".to_string(),
            menu_state().to_string_lossy().to_string(),
        ];
        // 결과 파일은 찾은 룰 · 확인 필요 룰의 것만 남긴다(D11) — 깨끗한 룰 · 해당 없는 룰은 요약과 회차 로그에만.
        let one = scan_one(&args, Keep::Findings);
        tee::quiet(false);
        let (code, kind, absent, review, kept, product, fixes) = match one {
            Ok(s) => (
                s.code, s.kind, s.absent, s.review, s.kept, s.product, s.fixes,
            ),
            Err(f) => {
                errln!("{}: {}", lang.t("실패", "Error"), f.message);
                let kind = load_manifest(&path.to_string_lossy())
                    .ok()
                    .and_then(|m| m.kind);
                (f.code, kind, false, false, false, None, Vec::new())
            }
        };
        if many {
            let result = scan_all_result(code, kind, absent, review);
            tee::progress(format!("{head}{}{result}", d.dash()));
        }
        let treats = guided::treats(path);
        if !treats && code == Code::FoundNotRemediated {
            found_notes.extend(notes_beside(path));
        }
        if code == Code::FoundNotRemediated {
            if treats {
                treat_found.push((label.clone(), path.clone()));
            } else {
                other_found.push(label.clone());
            }
        }
        done.push(ScanAllRow {
            label,
            code,
            kind,
            absent,
            review,
            out: kept.then_some(out),
            product,
            fixes,
        });
    }
    outln!();
    outln!("{}", d.rule());
    let title = match kind {
        guided::ScanKind::All => lang.pick(
            format!("모두 검사한 결과 — 항목 {n}개 · 아무것도 바꾸지 않았습니다"),
            format!("Results for all {n} items — nothing was changed"),
        ),
        guided::ScanKind::Quick => lang.pick(
            format!("빠른 검사 결과 — 항목 {n}개 · 아무것도 바꾸지 않았습니다"),
            format!("Quick scan results — {n} items · nothing was changed"),
        ),
        guided::ScanKind::Full => lang.pick(
            format!("정밀 검사 결과 — 항목 {n}개 · 아무것도 바꾸지 않았습니다"),
            format!("Full scan results — {n} items · nothing was changed"),
        ),
    };
    outln!("{title}");
    let (mut clean, mut not_here) = (0usize, 0usize);
    for row in &done {
        // 줄인 요약 — 깨끗한 룰 · 해당 없는 룰은 수로만 센다. 룰마다의 화면이 접혀 있으므로 남긴 결과 폴더를
        // 그 줄 밑에 적는다(찾은 것의 근거가 거기 있다).
        if many && (row.absent || row.code == Code::NoThreat) {
            if row.absent {
                not_here += 1;
            } else {
                clean += 1;
            }
            continue;
        }
        let result = scan_all_result(row.code, row.kind, row.absent, row.review);
        outln!("  {}{}{result}", row.label, d.dash());
        if many {
            if let Some(o) = &row.out {
                outln!("    {} : {}", lang.t("결과 폴더", "Output   "), o.display());
            }
        }
    }
    if many {
        outln!(
            "  {}",
            lang.pick(
                format!(
                    "나머지 {}개 — 찾은 것 없음 {clean} · 해당 없음 {not_here}",
                    clean + not_here
                ),
                format!(
                    "The other {} — nothing found {clean} · not applicable {not_here}",
                    clean + not_here
                )
            )
        );
    }
    // **빼 둔 네트워크 점검도 한 줄씩 적는다** — 적지 않으면 *모두* 가 그것까지 본 것으로 읽힌다.
    // 검사 앞이 아니라 여기 적는 까닭은 이 요약이 있는 까닭과 같다: 앞에 적은 줄은 룰마다의 화면에
    // 밀려 창 밖으로 나간다. 종료 코드에는 들지 않는다 — 돌리지 않은 것은 결과가 아니다.
    for (label, why) in skipped {
        let note = match why {
            guided::Skip::Network => lang.t(
                "돌리지 않았습니다 (네트워크 점검은 그 항목을 골라 주소를 적어야 합니다)",
                "not run (a network check: pick that item and enter the addresses)",
            ),
            guided::Skip::FullDisk => lang.t(
                "정밀 검사에서만 합니다 (디스크 전체를 봅니다)",
                "full scan only (it reads whole disks)",
            ),
        };
        outln!("  {label}{}{note}", d.dash());
    }
    // **같은 제품의 발견을 묶는다**(목표 remedy_기본검사_룰관리 결정 ③④) — 요약 밑에 빈 줄을 두고 따로 선다. 판정은
    // 룰마다 위 줄 그대로이고, 이 묶음은 '어디까지 올리면 모두 해결되는가' 를 한 번 적을 뿐이다. 룰이 선언한 확인
    // 필요만 남은 룰(PHP 세션 점검 — 판정을 세우지 않는다)도 든다 — 판으로 풀리지 않아 그 제품의 판 줄 밑에 선다.
    let found: Vec<product::Found> = done
        .iter()
        .filter(|r| r.code == Code::FoundNotRemediated || r.review)
        .filter_map(|r| {
            r.product.as_deref().map(|p| product::Found {
                label: r.label,
                product: p,
                fixes: &r.fixes,
            })
        })
        .collect();
    let by_product = product::lines(&found, lang, d.dash());
    if !by_product.is_empty() {
        outln!();
        outln!(
            "{}",
            lang.t(
                "제품마다 — 올리면 해결되는 버전",
                "By product — the version that resolves it"
            )
        );
        for l in by_product {
            outln!("{l}");
        }
    }
    let codes: Vec<Code> = done.iter().map(|r| r.code).collect();
    ScanAllDone {
        code: all_scans_code(&codes),
        treat: treat_found,
        other: other_found,
        notes: found_notes,
    }
}

/// *모두 검사만* 의 룰 하나의 결과 줄. **해당 없음** — 검사할 경로가 전부 없어 다 보지 못한 룰은 그 대상이
/// 없는 서버다(2026-11-07 결정). *"관측이 불완전해 '위협 없음' 을 말할 수 없습니다"* 로 끝나면 CWP 가 없는
/// 서버의 점검자가 '이상 없음' 으로 보고하지 못했다. 이 줄은 메뉴 화면에만 있고 종료 코드(6)와 룰마다의
/// 결과 화면은 그대로다.
pub(super) fn scan_all_result(
    code: Code,
    kind: Option<PluginKind>,
    absent: bool,
    review: bool,
) -> String {
    let lang = ui().lang;
    if absent {
        lang.t(
            "해당 없음 (검사할 경로가 이 기계에 없습니다)",
            "not applicable (the paths to scan do not exist on this machine)",
        )
        .to_string()
    } else {
        remedy_core::report::result_line_for(code, 0, lang, kind, review)
    }
}

/// *모두 검사만* 이 찾은 것 — 메뉴 고리가 *다음 할 일* 과 고르는 화면의 *찾은 것 모두 치료하기* 에 쓴다.
pub(super) struct ScanAllDone {
    pub(super) code: Code,
    /// 치료하는 룰 가운데 무언가를 찾은 것 — (이름, 경로). 비어 있지 않으면 *찾은 것 모두 치료하기* 가 선다.
    pub(super) treat: Vec<(String, std::path::PathBuf)>,
    /// 찾기만 하는 룰 · 점검 룰 가운데 찾은 것의 이름 — 바꾸지 않고 할 일만 적는다.
    pub(super) other: Vec<String>,
    /// 그 룰 폴더의 기록(`RELEASE.md`) — 찾기만 하는 룰이 찾았을 때 `guidance` 가 가리킨다.
    pub(super) notes: Vec<std::path::PathBuf>,
}

/// *모두 검사만* 뒤 *다음 할 일* 의 앞줄 — 치료하는 룰이 찾았으면 고르는 화면의 *찾은 것 모두
/// 치료하기*(그 화면의 번호 · 이름 — `line`). 그 줄이 서지 않으면 비어 있다.
pub(super) fn scan_all_lead(
    code: Code,
    treats: bool,
    line: Option<(usize, String)>,
) -> Vec<String> {
    let lang = ui().lang;
    match line {
        Some((n, label)) if treats && code == Code::FoundNotRemediated => vec![step_line(
            lang.t("찾은 것을 모두 치료하려면", "To treat everything found"),
            None,
            n,
            &label,
            remedy_sdk::i18n::deco(),
        )],
        _ => Vec::new(),
    }
}

/// 메뉴가 룰 하나를 부를 때의 인자 — 결과 폴더는 부를 때마다 새로(`menu_out`), 상태 폴더는 메뉴의 것.
pub(super) fn menu_rule_args(path: &std::path::Path) -> Vec<String> {
    vec![
        "--plugin".to_string(),
        path.to_string_lossy().to_string(),
        "--out-dir".to_string(),
        menu_out().to_string_lossy().to_string(),
        "--state-dir".to_string(),
        menu_state().to_string_lossy().to_string(),
    ]
}

/// *찾은 것 모두 치료하기* 의 룰 하나 — 계획부터 다시 검사까지.
pub(super) struct TreatAllRow<'a> {
    label: &'a str,
    path: &'a std::path::Path,
    kind: Option<PluginKind>,
    /// 바꿀 것이 있는 계획을 세웠으면 그 준비. 없으면 그 까닭이 `code` 다.
    prepared: Option<Prepared>,
    code: Code,
    /// 수행을 마친 Action 의 수.
    done: usize,
    /// 수행에 들어간 회차.
    run_id: Option<String>,
    /// 다시 검사한 결과 — 치료한 룰만.
    rescan: Option<Code>,
}

/// [`treat_all`] 의 결과 — 메뉴 고리가 끝 코드와 *다음 할 일* 에 쓴다.
pub(super) struct TreatAllDone {
    pub(super) code: Code,
    /// *다음 할 일* 의 앞줄 — 수행한 룰마다 먼저 고를 룰을 붙인 메뉴 줄, 승인을 거절했으면 고르는 화면의
    /// *찾은 것 모두 치료하기* 줄.
    pub(super) lead: Vec<String>,
    /// 수행한 룰 폴더의 기록(`RELEASE.md`) — 치료 뒤 할 일(`guidance`).
    pub(super) notes: Vec<std::path::PathBuf>,
}

/// **찾은 것 모두 치료하기** (목표 remedy_전체검사_운영기반 기준 5 · 결정 2).
///
/// *모두 검사만* 이 치료하는 룰에서 찾은 것을 한 번에 치료한다. 룰마다 *검사하고 치료하기* 와 같은
/// 길이다 — 다시 검사해 계획을 세우고([`prepare_run`]) 그 계획을 보인다. 다른 것은 둘이다: **바꿀 것을
/// 모두 보인 뒤 승인을 한 번 받는다**([`approved_all`]) · 끝에 **치료한 룰을 다시 검사해** 결과를 한
/// 덩어리로 적는다. 수행 · 격리 · 회차는 룰마다 따로다([`execute`]) — 그래서 복원 · 유지 확인 ·
/// 신고는 회차마다 지금처럼 한다.
///
/// **찾기만 하는 룰 · 점검 룰의 발견은 바꾸지 않는다**(`other`) — 끝에 할 일만 적는다. 설정을 고치는
/// 조치는 서비스를 멈출 수 있어, 점검 룰에 조치를 여는 것은 별도의 결정이다.
///
/// 화면 기록은 **로그 하나**다 — 승인 한 번이 계획 여럿을 덮으므로 회차마다 나누면 어느 로그에도 그
/// 승인의 화면이 다 남지 않는다. 다시 검사하기 전에 그 로그를 수행한 회차마다 `logs/<회차>.log` 로
/// 복사한다(신고 묶음이 그 자리를 '사람이 본 화면' 으로 담는다). 다시 검사는 [`cmd_scan`] 이라 룰마다
/// 자기 로그를 연다 — *모두 검사만* 과 같다.
pub(super) fn treat_all(
    treat: &[(String, std::path::PathBuf)],
    other: &[String],
    integrity: &remedy_core::integrity::SelfIntegrity,
) -> TreatAllDone {
    let lang = ui().lang;
    let d = remedy_sdk::i18n::deco();
    let state = menu_state();
    // 같은 세션에서 다시 돌려도 앞 회차의 화면이 이어 붙지 않게 작업 차례까지 이름에 넣는다.
    tee::open(
        &state,
        &format!("treat-all-{}-{}", std::process::id(), term::task_seq()),
    );
    outln!(
        "{}",
        lang.pick(
            format!(
                "찾은 것 모두 치료하기 — 항목 {}개를 다시 검사해 바꿀 것을 모두 보여 드린 뒤, '예' 한 번으로 \
                 치료합니다.",
                treat.len()
            ),
            format!(
                "Treat everything found — {} item(s) are scanned again and every change is shown; one 'yes' \
                 then treats them all.",
                treat.len()
            )
        )
    );

    // ── 계획 — 룰마다 다시 검사해 세운다. 아무것도 바꾸지 않는다.
    let mut rows: Vec<TreatAllRow> = Vec::new();
    for (i, (label, path)) in treat.iter().enumerate() {
        if i > 0 {
            // 룰마다 결과 폴더를 따로 둔다 — `menu_out` 은 작업 차례마다 폴더 하나라, 차례를 올리지 않으면
            // 뒤 룰의 `scan.json` · `plan.json` 이 앞 룰의 것을 덮는다(*모두 검사만* 과 같은 까닭).
            // 이 작업은 기계를 바꾸는 작업이다 — 강제로 끝나면 부분(3)이라는 뜻은 그대로 둔다.
            term::task_begin(true);
        }
        // 항목마다 구분선을 긋지 않는다 — 빈 줄과 `[i/N]` 머리가 가른다(구분선은 승인 · 결과 앞에 한 번씩).
        outln!();
        outln!("[{}/{}] {label}", i + 1, treat.len());
        let mut row = TreatAllRow {
            label,
            path,
            kind: None,
            prepared: None,
            code: Code::InternalError,
            done: 0,
            run_id: None,
            rescan: None,
        };
        match prepare_run(&menu_rule_args(path), false) {
            Ok(p) => {
                outln!();
                report_plan(&p.plan, lang, &p.a, false);
                row.kind = p.kind;
                if p.plan.body.actions.is_empty() {
                    // 다시 검사한 사이에 사라졌거나 허용 목록 · 가드가 다 걸렀다 — 한 룰의 치료와 같은 말.
                    row.code = outcome(&p.plan.body.verdicts, &p.plan.body.observation, p.kind);
                    outln!("{}", lang.t("수행할 항목이 없습니다.", "Nothing to do."));
                } else {
                    row.code = Code::FoundNotRemediated;
                    row.prepared = Some(p);
                }
            }
            Err(f) => {
                errln!("{}: {}", lang.t("실패", "Error"), f.message);
                row.code = f.code;
            }
        }
        rows.push(row);
    }

    // ── 승인 한 번
    let planned = rows.iter().any(|r| r.prepared.is_some());
    let approved = if planned {
        let plans: Vec<&remedy_sdk::artifact::PlanEnvelope> = rows
            .iter()
            .filter_map(|r| r.prepared.as_ref().map(|p| &p.plan))
            .collect();
        outln!();
        outln!("{}", d.rule());
        approved_all(&plans).unwrap_or_else(|f| {
            errln!("{}: {}", lang.t("실패", "Error"), f.message);
            false
        })
    } else {
        outln!();
        outln!(
            "{}",
            lang.t(
                "바꿀 것이 없어 아무것도 하지 않았습니다.",
                "Nothing to change, so nothing was done."
            )
        );
        false
    };

    // ── 수행 — 룰마다 지금의 치료(잠금 · 격리 · 회차 · 마무리 표)
    if approved {
        for row in rows.iter_mut() {
            let Some(p) = &row.prepared else { continue };
            outln!();
            outln!("{}", row.label);
            match execute(&p.a, &p.plan, integrity, p.started, p.kind) {
                Ok((code, done)) => {
                    row.code = code;
                    row.done = done;
                }
                Err(f) => {
                    errln!("{}: {}", lang.t("실패", "Error"), f.message);
                    row.code = f.code;
                }
            }
            row.run_id = Some(p.plan.run_id.clone());
        }
        if let Some(log) = tee::path() {
            for id in rows.iter().filter_map(|r| r.run_id.as_deref()) {
                let to = remedy_core::runlog::path(&state, id);
                if to != log {
                    let _ = std::fs::copy(&log, &to);
                }
            }
        }
        // ── 다시 검사 — 읽기만 한다. 여기서 끊기면 '위협 없음' 을 말할 수 없음(6)이다. 룰마다 차례를
        // 올려 결과 폴더도 따로 받는다.
        let treated: Vec<usize> = (0..rows.len())
            .filter(|&i| matches!(rows[i].code, Code::Remediated | Code::PartialFailure))
            .collect();
        for (k, &i) in treated.iter().enumerate() {
            tee::close();
            term::task_begin(false);
            outln!();
            outln!(
                "[{}/{}] {}{}{}",
                k + 1,
                treated.len(),
                lang.t("다시 검사", "Scan again"),
                d.dash(),
                rows[i].label
            );
            let code = cmd_scan(&menu_rule_args(rows[i].path)).unwrap_or_else(|f| {
                errln!("{}: {}", lang.t("실패", "Error"), f.message);
                f.code
            });
            rows[i].rescan = Some(code);
        }
    }

    // ── 한 덩어리
    outln!();
    outln!("{}", d.rule());
    outln!(
        "{}",
        lang.pick(
            format!("찾은 것 모두 치료한 결과 — 항목 {}개", rows.len()),
            format!(
                "Results of treating everything found — {} item(s)",
                rows.len()
            )
        )
    );
    for row in &rows {
        let result =
            remedy_core::report::result_line_for(row.code, row.done, lang, row.kind, false);
        outln!("  {}{}{result}", row.label, d.dash());
        if let Some(c) = row.rescan {
            outln!(
                "    {}{}",
                lang.t("다시 검사: ", "Scanned again: "),
                remedy_core::report::result_line_for(c, 0, lang, row.kind, false)
            );
        }
    }
    if !other.is_empty() {
        outln!(
            "  {}",
            lang.t(
                "아래 항목은 찾기만 합니다 — 바꾸지 않았습니다. 할 일은 README 의 '위협별 안내'에 있습니다:",
                "These items only detect — nothing was changed. What to do is in the README's per-threat notes:"
            )
        );
        for l in other {
            outln!("    {l}");
        }
    }

    let code = treat_all_code(&rows.iter().map(|r| r.code).collect::<Vec<_>>());
    let ran: Vec<&TreatAllRow> = rows.iter().filter(|r| r.run_id.is_some()).collect();
    let declined = planned && !approved;
    // 승인을 거절했으면 목록을 둔다 — 고르는 화면의 그 줄로 다시 고를 수 있다. 아니면 거둔다.
    if !declined {
        guided::set_found(Vec::new(), Vec::new());
    }
    let lead = if declined {
        scan_all_lead(Code::FoundNotRemediated, true, guided::treat_all_line())
    } else {
        let after = guided::next_offer();
        ran.iter()
            .flat_map(|r| {
                let pick = guided::chooser_entry(r.path);
                let steps: Vec<(&str, usize, String)> = next_steps(Flow::Treat, r.code, true)
                    .into_iter()
                    .filter_map(|(why, l)| menu::line(l, &after).map(|(n, label)| (why, n, label)))
                    .collect();
                step_block(&steps, pick.as_ref(), d)
            })
            .collect()
    };
    let notes = ran.iter().filter_map(|r| notes_beside(r.path)).collect();
    TreatAllDone { code, lead, notes }
}

/// *찾은 것 모두 치료하기* 의 끝 코드 — **새 코드를 만들지 않는다**(불변식 I3). 마치지 못한 룰(4 · 5 · 7
/// 중 큰 것)이 먼저, 그다음 일부 실패(3), 치료하지 않은 발견(2), 치료(1), 다 보지 못함(6), 없음(0).
/// 다시 검사의 결과는 들지 않는다 — 한 룰의 *검사하고 치료하기* 가 수행의 코드로 끝나는 것과 같다.
pub(super) fn treat_all_code(codes: &[Code]) -> Code {
    let worst = codes
        .iter()
        .copied()
        .filter(|c| matches!(c, Code::UsageError | Code::GuardStop | Code::InternalError))
        .max();
    if let Some(c) = worst {
        return c;
    }
    [
        Code::PartialFailure,
        Code::FoundNotRemediated,
        Code::Remediated,
        Code::IncompleteObservation,
    ]
    .into_iter()
    .find(|c| codes.contains(c))
    .unwrap_or(Code::NoThreat)
}

/// *모두 검사만* 의 룰 하나 — 요약 줄을 짓는 재료.
pub(super) struct ScanAllRow<'a> {
    label: &'a str,
    code: Code,
    kind: Option<PluginKind>,
    /// 다 보지 못한 까닭이 *검사할 경로가 전부 없음* 하나뿐 — **해당 없음**.
    absent: bool,
    /// 다 보지 못한 까닭이 *룰이 선언한 확인 필요* 하나뿐 — [`remedy_core::report::review_line`].
    review: bool,
    /// 남긴 결과 폴더 — 찾은 룰 · 확인 필요 룰만(D11).
    out: Option<std::path::PathBuf>,
    /// 같은 제품의 점검 룰을 묶는 열쇠 · 찾았을 때의 고친 판([`ScanOne`] 그대로).
    product: Option<String>,
    fixes: Vec<product::Fix>,
}

/// 모두 검사만의 종료 코드 — **새 코드를 만들지 않는다**(불변식 I3). 찾은 것이 하나라도 있으면
/// 2, 아니면 검사를 마치지 못한 룰의 코드(4 · 5 · 7 중 큰 것), 아니면 다 보지 못한 6, 모두
/// 없으면 0. 발견이 불완전함보다 앞서는 것은 `ExitCode::IncompleteObservation` 의 규칙 그대로다.
pub(super) fn all_scans_code(codes: &[Code]) -> Code {
    if codes.contains(&Code::FoundNotRemediated) {
        return Code::FoundNotRemediated;
    }
    codes
        .iter()
        .copied()
        .filter(|c| matches!(c, Code::UsageError | Code::GuardStop | Code::InternalError))
        .max()
        .unwrap_or_else(|| {
            codes
                .iter()
                .copied()
                .find(|c| *c != Code::NoThreat)
                .unwrap_or(Code::NoThreat)
        })
}
