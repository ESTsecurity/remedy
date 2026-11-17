//! 재평가(verify) · 그 기록 · 중단된 치료 이어서 하기(resume)(2026-11-17 에 main.rs 에서 옮겼다).

use super::*;

/// 재수집 + 재평가 (설계-03 §8).
///
/// **경로 확인이 아니다.** "제거한 경로가 여전히 비어 있는가" 만 보면 랜덤
/// 이름을 쓰는 위협 앞에서 무력하다 — 재감염은 다른 이름으로 생기고 원래
/// 경로는 계속 비어 있다.
pub(super) fn cmd_verify(raw: &[String]) -> Result<Code, Failure> {
    // **자기 흔적을 먼저 지운다** (설계-03 §8 규칙 2). 재평가가 어떻게 끝나든
    // 우리가 심은 자동실행은 남지 않아야 한다 — 뒤에 두면 재평가가 실패한
    // 경로에서 그것이 남는다.
    clear_scheduled_verify();

    let a = parse_args(raw)?;
    tee::open(
        &state_dir(&a),
        &a.get("run")
            .map(str::to_string)
            .unwrap_or_else(|| format!("verify-{}", std::process::id())),
    );
    banner(None);
    let m = load_local(a.need("plugin")?)?;
    warn_unsupported(&m);
    let rules = load_rules(a.need("plugin")?)?;

    // 치료 전 증거. 있으면 "일부만 잔존" 을 가려낼 수 있고, 없으면 재발 여부와
    // 관측 완전성까지만 답한다 — **없는 것을 있는 척하지 않는다.**
    // 기록할 자리를 함께 붙든다. **`--run` 이 있어야 기록이 성립한다** —
    // 어느 치료에 대한 재평가인지가 그 값이고, 없으면 붙일 곳이 없다.
    let recording = a.get("run").map(|r| (state_dir(&a), r.to_string()));
    let baseline = match a.get("run") {
        Some(run) => {
            let state = state_dir(&a);
            let p = remedy_core::apply::plan_path(&state, run);
            let text = std::fs::read_to_string(&p).map_err(|e| {
                format!(
                    "{}: {e}\n승인된 계획을 찾지 못했습니다. --run 없이 부르면 재발 여부와 관측 완전성만 답합니다.",
                    p.display()
                )
            })?;
            let plan: remedy_sdk::artifact::PlanEnvelope =
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
            plan.body
                .actions
                .iter()
                .flat_map(|x| x.because.iter().cloned())
                .collect::<Vec<_>>()
        }
        None => Vec::new(),
    };

    let meta = RunMeta::now();
    scan_started();
    let (_artifacts, scan, unresolved, outcome) =
        tee::with_heartbeat(ui().verbose, tee::Beat::Scan, || {
            remedy_core::pipeline::verify(&m, &meta, &rules, &baseline)
        })?;
    // `scan` · `run` 과 같은 자리에서 말한다 — 재검사가 6 이면 **왜 못 봤는지**(본문
    // 상한 등)가 이 블록에 있다. 재부팅 회차에는 회차 로그가 유일한 화면이다.
    warn_unresolved_extra(&unresolved, &m, Some(&scan.body.observation));
    if let Some(out) = a.get("out") {
        write_json(out, &scan)?;
        outln!("{} -> {out}", ui().lang.t("재평가", "Re-evaluation"));
    }
    report_scan(&scan, m.kind, m.remediate.is_none());

    use remedy_core::pipeline::VerifyOutcome;
    // **점검에서는 '루트 전부 없음' 이 불완전이 아니다** (B-6). `classify` 는
    // `is_complete()` 를 보므로 그 사실을 모르고 `Incomplete` 를 준다 — 고치지
    // 않으면 **같은 기계에서 `scan` 은 0, `verify` 는 6** 이 된다.
    //
    // 분류를 여기서 한 번 다시 묶는다. 아래 매핑 **앞**이라 기록의 `outcome`
    // 토큰 · `exit_code` · 프로세스 종료 코드 · 네 문구가 한꺼번에 맞는다 —
    // 그 넷이 갈리면 무인 재검사가 받는 유일한 화면인 기록이 자기모순이 된다.
    // `classify` 와 SDK 는 건드리지 않는다: 종류를 아는 것은 여기뿐이다.
    let outcome = match outcome {
        VerifyOutcome::Incomplete
            if complete_enough(&scan.body.observation, m.kind)
                && scan.body.observation.all_roots_missing() =>
        {
            VerifyOutcome::Clean
        }
        other => other,
    };

    // **매핑은 여기 한 번이다** — 기록의 `exit_code` 와 프로세스의 종료 코드가 같은
    // 값이어야 한다. 무인 재검사에서 받는 쪽은 그 기록만 본다.
    let code = match outcome {
        VerifyOutcome::Clean => Code::NoThreat,
        VerifyOutcome::Partial => Code::PartialFailure,
        VerifyOutcome::Recurred => Code::FoundNotRemediated,
        VerifyOutcome::Incomplete => Code::IncompleteObservation,
    };
    record_verify(recording.as_ref(), &m, &scan, &outcome, code, &baseline);

    match outcome {
        VerifyOutcome::Clean => {
            let lang = ui().lang;
            outln!(
                "\n{}",
                if m.kind == Some(PluginKind::Check) {
                    // **점검은 치료하지 않는다.** *"치료 성공"* 은 이 룰이 한 적
                    // 없는 일을 했다고 말하는 것이다 (B-2).
                    lang.t(
                        "다시 점검했습니다. 취약한 곳을 찾지 못했습니다.",
                        "Re-checked: no vulnerability was found.",
                    )
                } else {
                    // **받는 사람의 말로** (2026-11-12) — 전에는 *"같은 플러그인이 더 이상 판정하지
                    // 않습니다"* 라 '플러그인' · '판정' 이 고객 화면에 섰다. 하네스(`Invoke-ObsVerify`)가
                    // 읽는 앞 구절 `치료 성공. ` 은 그대로 둔다.
                    lang.t(
                        "치료 성공. 같은 검사에서 위협이 다시 나오지 않았습니다.",
                        "Treatment succeeded. The same check no longer finds the threat.",
                    )
                }
            );
        }
        VerifyOutcome::Partial => {
            // 판정은 서지 않는데 원래 증거의 일부가 남아 있다. 판정 게이트는
            // 독립적인 두 근거의 논리곱이므로, 한쪽만 남은 것은 그 곱이
            // 무너졌다는 뜻이다 — 그래도 남은 것은 남은 것이다.
            let lang = ui().lang;
            errln!(
                "\n{}",
                if m.kind == Some(PluginKind::Check) {
                    lang.t(
                        "취약 판정은 서지 않으나 원래 근거의 일부가 남아 있습니다.",
                        "No vulnerability verdict stands, but some of the original evidence remains.",
                    )
                } else {
                    lang.t(
                        "부분 치료. 판정은 서지 않으나 원래 증거의 일부가 남아 있습니다.",
                        "Partial treatment. No verdict stands, but some of the original evidence remains.",
                    )
                }
            );
        }
        VerifyOutcome::Recurred => {
            // **자동으로 다시 치료하지 않는다.** 같은 치료를 반복해도 같은
            // 결과가 나올 가능성이 높고, 재발은 우리가 놓친 지속성 경로가
            // 있다는 신호이므로 사람의 판단이 필요하다 (설계-03 §8).
            let lang = ui().lang;
            let check = m.kind == Some(PluginKind::Check);
            errln!(
                "\n{}",
                if check {
                    // 점검에 *"재발"* 은 없다 — 고친 적이 없으므로 **여전히** 취약한 것이다.
                    lang.t(
                        "여전히 취약합니다. 같은 룰이 다시 판정했습니다.",
                        "Still vulnerable. The same rule reports it again.",
                    )
                } else {
                    lang.t(
                        "재발. 같은 플러그인이 다시 판정했습니다.",
                        "Recurrence. The same plugin reports a threat again.",
                    )
                }
            );
            errln!(
                "  {}",
                if check {
                    lang.t(
                        "이 룰은 바꾸지 않습니다. 조치가 실제로 적용됐는지 확인한 뒤 다시 점검하십시오.",
                        "This rule changes nothing. Confirm the fix was actually applied, then check again.",
                    )
                } else {
                    lang.t(
                        "자동으로 다시 치료하지 않습니다. 놓친 지속성 경로가 있다는 신호이므로 새 증거를 보고 사람이 판단해야 합니다.",
                        "It is not treated again automatically. This signals a missed persistence path; a person should review the new evidence.",
                    )
                }
            );
        }
        VerifyOutcome::Incomplete => {
            // 판정도 남은 증거도 없지만 **다 보지 못했다** — 무엇을 못 봤는지는 바로
            // 위 '주의' 줄들(`report_scan`)이 말한다. "치료 성공" 을 말하지 않는다
            // (결정 2026-10-26). 재부팅 회차라면 기록에 그 관측이 함께 남는다.
            let lang = ui().lang;
            let check = m.kind == Some(PluginKind::Check);
            errln!(
                "\n{}",
                if check && scan.body.observation.only_unconfirmed() {
                    // 다 **보았다** — 룰이 *확인 필요* 를 선언했다(`verdict.unconfirmed` · 2026-11-09).
                    lang.t(
                        "다시 점검했습니다. 판정은 서지 않았지만 위에 적은 항목은 '취약하지 않다' 를 가릴 근거가 없습니다.",
                        "Re-checked: no verdict stands, but there is no basis to call the items listed above not vulnerable.",
                    )
                } else if check {
                    lang.t(
                        "점검을 마치지 못했습니다. 판정은 서지 않았지만 다 보지 못해 '취약하지 않다' 를 말할 수 없습니다.",
                        "The check could not be completed. No verdict stands, but not everything could be seen, so 'not vulnerable' cannot be declared.",
                    )
                } else {
                    lang.t(
                        "치료를 확인하지 못했습니다. 판정은 서지 않았지만 다 보지 못해 '치료 성공' 을 말할 수 없습니다.",
                        "The treatment could not be confirmed. No verdict stands, but not everything could be seen, so 'treatment succeeded' cannot be declared.",
                    )
                }
            );
        }
    }
    Ok(code)
}

/// 재평가 결과를 상태 디렉터리에 남긴다 (설계-03 §8).
///
/// # 왜 여기인가
///
/// **재부팅 뒤 예약된 실행에는 사람이 없다.** RunOnce 는 콘솔 없이 돌고, 종료
/// 코드는 그 프로세스와 함께 사라진다. 2026-08-29 실기기 측정에서 그 실행이
/// 실제로 도는 것은 확인했지만 **판정이 무엇이었는지는 어디에서도 알 수 없었다.**
///
/// # 실패해도 종료 코드를 바꾸지 않는다
///
/// 기록하지 못한 것과 판정하지 못한 것은 다르다. 여기서 코드를 바꾸면 무인
/// 배포가 성공한 치료를 실패로 읽는다 (`schedule_verify_if_asked` 와 같은 규칙).
pub(super) fn record_verify(
    where_: Option<&(std::path::PathBuf, String)>,
    m: &remedy_sdk::manifest::PluginManifest,
    scan: &remedy_sdk::artifact::ScanEnvelope,
    outcome: &remedy_core::pipeline::VerifyOutcome,
    code: Code,
    baseline: &[String],
) {
    let Some((state, run_id)) = where_ else {
        return;
    };
    let rec = remedy_core::verify_log::VerifyRecord {
        at: RunMeta::now().created,
        run_id: run_id.clone(),
        plugin_id: m.id.clone(),
        plugin_version: m.version.clone(),
        outcome: outcome.id().into(),
        exit_code: i32::from(code.code()),
        verdicts: scan.body.verdicts.clone(),
        // **왜 그렇게 판정했는가**가 함께 있어야 사람이 다음 판단을 한다.
        // 재발은 자동 재치료 대상이 아니다 (설계-03 §8).
        remaining: scan
            .body
            .evidence
            .iter()
            .filter(|e| baseline.iter().any(|b| b == &e.id))
            .map(|e| e.id.clone())
            .collect(),
        // **다 보지 못했으면 무엇을 못 봤는지도** — 재발 · 잔존과 겹쳐도 싣는다. 온전한
        // 회차의 줄에는 없다(결정 2026-10-26).
        observation: (!scan.body.observation.is_complete()).then(|| scan.body.observation.clone()),
    };
    match remedy_core::verify_log::append(state, &rec) {
        Ok(p) => outln!(
            "{} -> {}",
            ui().lang.t("재평가 기록", "Re-evaluation record"),
            p.display()
        ),
        Err(e) => errln!(
            "{}: {} ({e})",
            ui().lang.t("주의", "Note"),
            ui().lang.t(
                "재평가 결과를 남기지 못했습니다",
                "could not record the re-evaluation result"
            )
        ),
    }
}

/// 저장된 계획을 이어 실행한다. **재스캔하지 않는다** (설계-00 §6).
///
/// 재부팅 뒤에 이것을 부르는 쪽에는 사람이 없다 — 그래서 계획을 인자로 받지
/// 않고 상태 디렉터리에서 찾는다. 새로 스캔하면 환경이 달라 다른 계획이
/// 나오고, 사용자가 승인한 것과 다른 일이 벌어진다 (불변식 P 의 연장).
pub(super) fn cmd_resume(
    raw: &[String],
    integrity: &remedy_core::integrity::SelfIntegrity,
) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    tee::open(
        &state_dir(&a),
        &a.get("run")
            .map(str::to_string)
            .unwrap_or_else(|| format!("resume-{}", std::process::id())),
    );
    banner(None);
    let state = state_dir(&a);

    let runs: Vec<String> = match a.get("run") {
        Some(r) => vec![r.to_string()],
        None => remedy_core::apply::unfinished_runs(&state)
            .map_err(|e| format!("{}: {e}", state.display()))?,
    };
    if runs.is_empty() {
        // "이어서 수행할 실행이 없습니다" 는 시험이 읽는 문구다.
        outln!(
            "{}",
            ui().lang.t(
                "이어서 수행할 실행이 없습니다.",
                "There is no run to resume."
            )
        );
        return Ok(Code::NoThreat);
    }

    let mut worst = Code::NoThreat;
    for run in &runs {
        let p = remedy_core::apply::plan_path(&state, run);
        let text = std::fs::read_to_string(&p).map_err(|e| {
            format!(
                "{}: {e}\n저장된 계획이 없어 이어받을 수 없습니다.",
                p.display()
            )
        })?;
        let plan: remedy_sdk::artifact::PlanEnvelope =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        outln!(
            "\n{}",
            ui().lang.pick(
                format!("이어받습니다: {run}  ({}건)", plan.body.actions.len()),
                format!("Resuming: {run}  ({} action(s))", plan.body.actions.len())
            )
        );
        let code = run_apply(&a, &plan, integrity, std::time::Instant::now(), None, false)?;
        if code.code() > worst.code() {
            worst = code;
        }
    }
    Ok(worst)
}
