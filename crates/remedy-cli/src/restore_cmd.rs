//! 되돌리기 — 회차 목록 · 복원 계획 · 복원(2026-11-17 에 main.rs 에서 옮겼다).

use super::*;

/// 명령줄에서 열쇠를 모은다. 실제 선택은 `remedy-core` 가 한다.
pub(super) fn key_source(
    a: &Args,
    state_dir: &std::path::Path,
) -> Result<remedy_core::restore::KeySource, Failure> {
    let mut src = remedy_core::restore::KeySource {
        state_dir: Some(state_dir.to_path_buf()),
        ..Default::default()
    };
    if let Some(p) = a.get("passphrase-file") {
        let text = std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
        src.passphrase = Some(text.trim_end_matches(['\r', '\n']).to_string());
    }
    if let Some(p) = a.get("org-key-file") {
        let raw = std::fs::read(p).map_err(|e| format!("{p}: {e}"))?;
        let sk: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| format!("{p}: 조직 개인키는 32바이트여야 합니다"))?;
        src.org_secret = Some(sk);
    }
    Ok(src)
}

/// 되돌릴 수 있는 회차를 늘어놓는다 (`restore --list`).
///
/// **마무리 표가 알려 준 실행 번호를 사람이 옮겨 적어야 했다.** 창을 닫으면 그것을
/// 다시 찾을 길이 없었고, 그러면 오탐을 되돌리는 능력이 함께 사라진다 — 이 도구가
/// 가장 확실하게 잘해야 하는 일이 그것이다.
///
/// **열쇠 없이 읽는다.** 평문 헤더만 보므로(`Sealed::parse`) 실행 번호와 만든 시각은
/// 나오고, 무엇이 들었는지는 나오지 않는다. 그것을 보려면 `restore --run <번호>` 가
/// 열어야 한다.
///
/// 하나가 깨져도 목록 전체를 세우지 않는다. 못 읽은 것은 못 읽었다고 적고 넘어간다 —
/// 깨진 것 하나 때문에 멀쩡한 나머지를 되돌리지 못하면 안 된다.
pub(super) fn list_runs(state_dir: &std::path::Path) -> Result<Code, Failure> {
    let lang = ui().lang;
    let d = remedy_sdk::i18n::deco();
    let dir = state_dir.join("quarantine");

    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("rq"))
        })
        .collect();
    files.sort();

    outln!("{} : {}", lang.t("격리소", "Quarantine"), dir.display());
    if files.is_empty() {
        outln!(
            "{}",
            lang.t(
                // **`격리물` 은 그대로 둔다** (2026-10-28). 짚힌 결함은 `자리` 와
                // 영문 `place` 다. 이 낱말은 고객 화면 넷(이 파일의 '읽지 못한 격리물' 줄 ·
                // 키 안내 줄, `remedy-core` 의 `restore.rs` · `support.rs`)이 함께 쓰므로 여기만
                // 바꾸면 한 개념이 두 이름을 갖는다 — `꾸러미` 때와 같은 함정.
                "되돌릴 수 있는 회차가 없습니다. 이 폴더에 격리물이 하나도 없습니다.",
                "There is no run to undo. This folder holds no quarantine."
            )
        );
        return Ok(Code::NoThreat);
    }

    // 새 것이 위로. 되돌리려는 것은 대개 방금 한 치료다. `created` 는 초 단위라
    // 같은 초에 끝난 둘은 순서가 갈리지 않고 파일 이름 순으로 남는다 — 그때는
    // 아래 "되돌리려면" 이 둘 중 하나를 고를 뿐이고, 목록에는 둘 다 보인다.
    let mut rows: Vec<(String, String, String, u64)> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    for p in &files {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        match std::fs::read(p).map_err(|e| e.to_string()).and_then(|b| {
            remedy_core::restore::peek(&b)
                .map(|s| (s.header.run_id.clone(), s.header.created.clone()))
                .map_err(|e| e.to_string())
        }) {
            Ok((run_id, created)) => rows.push((created, run_id, name, size)),
            Err(e) => unreadable.push(format!("{name}: {e}")),
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));

    outln!();
    outln!(
        "{}",
        lang.pick(
            format!("되돌릴 수 있는 회차 {}건", rows.len()),
            format!("{} run(s) can be undone", rows.len())
        )
    );
    for (created, run_id, _, size) in &rows {
        outln!(
            "  {}  {}{}{}",
            remedy_core::report::pretty_time(created),
            run_id,
            d.dot(),
            lang.pick(format!("{size} 바이트"), format!("{size} bytes"))
        );
    }
    if !unreadable.is_empty() {
        errln!();
        for u in &unreadable {
            errln!(
                "  {} {u}",
                lang.t("읽지 못한 격리물:", "unreadable quarantine:")
            );
        }
    }
    if let Some((_, newest, _, _)) = rows.first() {
        outln!();
        // "remedy restore --run" 은 시험과 하네스가 읽는 문구다 — 상태 폴더는 그 뒤에 붙인다.
        let at = state_hint(state_dir)
            .map(|d| format!(" --state-dir {d}"))
            .unwrap_or_default();
        outln!(
            "{} : remedy restore --run {newest}{at}",
            lang.t("되돌리려면", "To undo")
        );
    }
    Ok(Code::NoThreat)
}

/// 되돌리기 · 신고 안내에 붙일 상태 폴더 — **기본 자리가 아닐 때만**(2026-11-07 결정 ①).
///
/// 메뉴는 받은 폴더의 `state` 에 쓴다(`menu_state`). 안내가 그 폴더를 빼면 그 줄을 그대로 친
/// 사람은 기본 자리(`%PROGRAMDATA%\remedy` · `/var/lib/remedy`)를 찾다 종료 4 로 끝났다
/// (v1.1.0 실측). 기본이면 `None` — 무인 배포 출력은 한 글자도 바뀌지 않는다(불변식 I1).
/// 경로 글자 밖의 것(공백 · `&` · `;` · `'` · 괄호 · 한글 …)이 들면 따옴표로 감싼다 — 그대로 쳐도
/// PowerShell · cmd · bash 가 한 인자로 읽게.
pub(super) fn state_hint(dir: &std::path::Path) -> Option<String> {
    if dir == remedy_core::restore::default_state_dir() {
        return None;
    }
    let s = dir.display().to_string();
    let plain =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '/' | '\\' | '.' | '_' | '-' | ':');
    Some(if s.is_empty() || !s.chars().all(plain) {
        format!("\"{s}\"")
    } else {
        s
    })
}

pub(super) fn cmd_restore(raw: &[String]) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    // **목록은 기계를 만지지 않는다.** 회차 로그를 열지 않는 이유가 그것이다 —
    // 읽기만 하는 명령이 로그를 남기면 무엇이 실제로 기계를 고쳤는지가 흐려진다.
    // **`get` 이 아니라 `has` 다.** `get` 은 빈 값을 걸러내므로 값 없는 스위치는
    // 언제나 `None` 이 된다 — `--yes` 가 `has` 를 쓰는 이유와 같다.
    if a.has("list") {
        banner(None);
        return list_runs(&state_dir(&a));
    }
    tee::open(
        &state_dir(&a),
        &a.get("run")
            .map(|r| format!("restore-{r}"))
            .unwrap_or_else(|| format!("restore-{}", std::process::id())),
    );
    banner(None);
    let state_dir = a
        .get("state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);

    let container_path = match (a.get("container"), a.get("run")) {
        (Some(p), _) => std::path::PathBuf::from(p),
        (None, Some(run)) => remedy_core::restore::container_path(&state_dir, run),
        (None, None) => {
            // **의미를 바꾸지 않는다** — 인자 없는 `restore` 는 지금까지처럼
            // 사용법 오류(4)다. 어디로 가면 되는지만 한 줄 덧붙인다.
            return Err(ui()
                .lang
                .t(
                    "--run 이나 --container 중 하나가 필요합니다. \
                     되돌릴 수 있는 회차는 `remedy restore --list` 로 볼 수 있습니다",
                    "either --run or --container is required. \
                     `remedy restore --list` shows the runs that can be undone",
                )
                .into());
        }
    };

    let bytes =
        std::fs::read(&container_path).map_err(|e| format!("{}: {e}", container_path.display()))?;
    let sealed = remedy_core::restore::peek(&bytes).map_err(|e| e.to_string())?;

    let lang = ui().lang;
    let d = remedy_sdk::i18n::deco();
    let w = 10;
    let pad = remedy_core::report::pad;
    outln!(
        "{} : {}",
        pad(lang.t("격리소", "Quarantine"), w),
        container_path.display()
    );
    outln!(
        "{} : {}",
        pad(lang.t("실행 번호", "Run id"), w),
        sealed.header.run_id
    );
    outln!(
        "{} : {}",
        pad(lang.t("만든 시각", "Created"), w),
        remedy_core::report::pretty_time(&sealed.header.created)
    );
    let keys: Vec<String> = sealed
        .header
        .wraps
        .iter()
        .map(|w| {
            format!(
                "{}({})",
                w.kind.as_str(),
                &w.key_id[..8.min(w.key_id.len())]
            )
        })
        .collect();
    outln!("{} : {}", pad(lang.t("키", "Keys"), w), keys.join(d.dot()));
    if sealed.header.only_local_wrap() {
        // 설계-03 §5 — 격리 시점에 경고해야 하지만, 이미 만들어진 것을 열 때도
        // 같은 사실을 말해 준다.
        // "재설치하면" 은 시험이 읽는 문구다.
        errln!(
            "  {} {}",
            ui().lang.t("주의:", "Note:"),
            // 'wrap' 은 내부 낱말이다 — 받는 사람에게는 무엇으로 열리는지와 언제 못 여는지만
            // 말한다(v1.1.0 적대적 검토).
            ui().lang.t(
                "이 격리물은 이 기계의 키로만 열립니다. 이 기계를 재설치하면 열 수 없으므로, 복원이 필요하면 그 전에 하십시오.",
                "this quarantine opens only with this machine's key. Reinstalling this machine makes it unopenable, so if it needs restoring, do it before that."
            )
        );
    }

    let src = key_source(&a, &state_dir)?;
    let key = remedy_core::restore::unlock(&sealed.header, &src).map_err(|e| {
        Failure::from(format!(
            "{e}\n  이 머신의 키로 열리지 않는다면, 다른 머신에서 만든 컨테이너입니다. \
             --org-key-file 로 열고 --extract-to 로 꺼내십시오"
        ))
    })?;
    let opened = sealed.unlock(&key).map_err(|e| e.to_string())?;

    let protected = remedy_core::restore::default_protected();
    let backend = remedy_core::restore::default_backend();
    let extract_to = a.get("extract-to");
    // **이 기계의 저널이 보호 경로 복원을 보증한다** (설계-03 §5).
    //
    // 넘겨받은 컨테이너에는 대응하는 저널이 없다 — 그때 보호 경로 항목은 막히고
    // `--extract-to` 로만 꺼낼 수 있다.
    let vouched = remedy_core::restore::vouched(&state_dir, &sealed.header.run_id);
    let plan = remedy_core::restore::plan(
        &opened,
        &sealed.header.run_id,
        &backend,
        &remedy_core::restore::Guards {
            protected: &protected,
            vouched: &vouched,
        },
        &a.list("entry"),
        extract_to,
    )
    .map_err(|e| Failure {
        code: Code::UsageError,
        message: e.to_string(),
    })?;

    // 비어 있으면 줄을 빼야 한다 — `플러그인 :` 뒤가 빈 화면을 실측했다.
    if !plan.plugin_id.trim().is_empty() {
        outln!(
            "{} : {}",
            pad(lang.t("플러그인", "Plugin"), w),
            plan.plugin_id
        );
    }
    if let Some(t) = &plan.threat {
        outln!("{} : {t}", pad(lang.t("위협", "Threat"), w));
    }
    if let Some(d) = extract_to {
        outln!(
            "{}",
            lang.pick(
                format!("꺼내기 모드입니다. 원본 자리가 아니라 {d} 로 꺼냅니다."),
                format!("Extract mode: items go to {d}, not to their original place.")
            )
        );
        outln!(
            "  {}",
            lang.t(
                "제자리 복원은 원래 머신에서만 보장됩니다.",
                "In-place restore is only guaranteed on the original machine."
            )
        );
    }
    outln!();

    outln!(
        "{}",
        lang.pick(
            format!(
                "복원할 항목 {}건{}{} 바이트",
                plan.allowed().count(),
                d.dot(),
                plan.total_bytes()
            ),
            format!(
                "{} item(s) to restore{}{} bytes",
                plan.allowed().count(),
                d.dot(),
                plan.total_bytes()
            )
        )
    );
    for i in plan.allowed() {
        outln!("  [{}] {}", i.id, i.dest);
        for l in &i.report.lost {
            outln!(
                "        {}  {}: {}",
                lang.t("복원 불가", "not restorable"),
                l.item,
                l.reason
            );
        }
    }

    // 여유 공간. **부족하면 시작하지 않는다** (설계-00 §5-2).
    for s in &plan.space {
        outln!(
            "  {} {}  {} {}{}{} {}",
            lang.t("볼륨", "Volume"),
            s.volume,
            lang.t("필요", "needs"),
            s.need,
            d.dot(),
            lang.t("여유", "free"),
            s.space.describe()
        );
    }
    let short = plan.out_of_space();
    if !short.is_empty() {
        errln!();
        for s in &short {
            errln!(
                "  {} {} {}: {} {}{}{} {}",
                lang.t("주의:", "Note:"),
                lang.t(
                    "여유 공간이 부족합니다. 볼륨",
                    "not enough free space. Volume"
                ),
                s.volume,
                lang.t("필요", "needs"),
                s.need,
                d.dot(),
                lang.t("여유", "free"),
                s.space.describe()
            );
        }
        errln!(
            "  {}",
            lang.t("아무것도 쓰지 않았습니다.", "Nothing was written.")
        );
        return Ok(Code::GuardStop);
    }
    for s in plan.space_unknown() {
        // 부족한 것과 모르는 것은 다른 사실이다. 뭉개면 "확인했다" 가 거짓이 된다.
        errln!(
            "  {} {} {}",
            ui().lang.t("주의:", "Note:"),
            ui().lang.t(
                "여유 공간을 확인하지 못했습니다. 볼륨",
                "free space could not be checked. Volume"
            ),
            s.volume
        );
    }

    let blocked: Vec<_> = plan.blocked().collect();
    if !blocked.is_empty() {
        errln!();
        errln!(
            "{}",
            lang.pick(
                format!("가드가 막은 항목 {}건:", blocked.len()),
                format!("{} item(s) held back by the guard:", blocked.len())
            )
        );
        for i in &blocked {
            errln!("  [{}] {}", i.id, i.dest);
            errln!("        {}", i.blocked.as_deref().unwrap_or(""));
        }
        errln!();
        // 끝 줄은 막은 까닭을 따른다 — 지우는 중인 서비스는 다시 시작하면 풀리고, 보호 대상은 풀리지 않는다.
        if blocked.iter().any(|i| !i.restart_first) {
            errln!(
                "  {} {}",
                lang.t("주의:", "Note:"),
                lang.t(
                    "복원도 쓰기입니다. 보호 대상에는 쓰지 않습니다.",
                    "restore is also a write; protected targets are left alone."
                )
            );
        }
        if blocked.iter().any(|i| i.restart_first) {
            errln!(
                "  {} {}",
                lang.t("주의:", "Note:"),
                lang.t(
                    "PC 를 다시 시작한 뒤 다시 복원하십시오. 아무것도 쓰지 않았습니다.",
                    "restart the PC, then restore again. Nothing was written."
                )
            );
        }
        return Ok(Code::GuardStop);
    }

    if !a.has("yes") {
        // 메뉴 세션이면 곧이어 메뉴가 묻는다(`confirm_restore`) — *"--yes 를 붙여 다시
        // 부르십시오"* 는 칠 자리가 없는 사람에게 틀린 안내였다('전' 이미지 2026-11-05 ·
        // 두 문장이 어긋났다). 명령줄 호출의 화면은 그대로다(시연 대본).
        if !term::in_session() {
            outln!();
            outln!(
                "{}",
                lang.t(
                    "아무것도 하지 않았습니다. 위 목록을 확인하고 --yes 를 붙여 다시 부르십시오.",
                    "Nothing was done. Check the list above and run again with --yes."
                )
            );
        }
        return Ok(Code::FoundNotRemediated);
    }

    outln!();
    let outcomes =
        remedy_core::restore::apply(&plan, &opened, &key, &backend).map_err(|e| Failure {
            code: e.exit_code(),
            message: e.to_string(),
        })?;
    let mut failed = 0;
    for o in &outcomes {
        match &o.result {
            // 레지스트리 값처럼 되살린 속성이 없는 항목은 괄호를 열지 않는다 —
            // 앞서는 `복원 [e0] …Locust  ()` 처럼 빈 괄호가 남았다 (2026-09-07).
            Ok(r) if r.restored.is_empty() => {
                outln!("  {} [{}] {}", lang.t("복원", "restored"), o.id, o.dest)
            }
            Ok(r) => outln!(
                "  {} [{}] {}  ({})",
                lang.t("복원", "restored"),
                o.id,
                o.dest,
                r.restored.join(d.dot())
            ),
            Err(e) => {
                failed += 1;
                errln!("  {} [{}] {}  {e}", lang.t("실패", "FAILED"), o.id, o.dest);
            }
        }
    }

    if failed > 0 {
        errln!(
            "\n{}",
            lang.pick(
                format!("{failed}건이 실패했습니다. 나머지는 복원됐습니다."),
                format!("{failed} item(s) failed. The rest were restored.")
            )
        );
        return Ok(Code::PartialFailure);
    }
    // 치료 화면과 같은 마무리 표.
    outln!();
    outln!("{}", d.rule());
    outln!(
        " {} : {}",
        pad(lang.t("결과", "Result"), w),
        lang.pick(
            format!("{}건 복원 완료.", outcomes.len()),
            format!("{} item(s) restored.", outcomes.len())
        )
    );
    outln!("{}", d.rule());
    outln!(" {}", remedy_core::report::brand::copyright());
    Ok(Code::NoThreat)
}
