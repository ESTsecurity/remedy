//! 안내 모드 — **명령을 못 치는 사람의 경로** (Phase 4-3).
//!
//! # 언제 열리는가
//!
//! `main` 의 `None` 갈래, 즉 **인자가 하나도 없고 사람이 앞에 있을 때**만이다.
//! 인자가 있는 호출은 여기 오지 않으므로 무인 배포와 RunOnce 의 `verify …` 는
//! 한 글자도 달라지지 않는다 (`never_waits.rs` 가 그 불변식을 잠근다).
//!
//! # 무엇을 하는가
//!
//! 1. 실행 파일 옆에서 꾸러미를 찾는다 ([`crate::discover::beside`])
//! 2. 그것이 우리 것인지 확인한다 ([`crate::discover::usable`])
//! 3. 관리자 권한이 있는지 본다
//! 4. `run` 과 **같은 경로**로 검사하고 계획을 보이고 승인을 받는다
//!
//! # 왜 `cmd_run` 을 그대로 부르는가
//!
//! 화면과 안전 가드를 여기 다시 적으면 두 벌이 되고, 갈라지면 안내 모드로 들어온
//! 사람만 다른 판정을 받는다. 그래서 **인자를 만들어 넘긴다** — 사람이
//! `run --plugin <찾은 것>` 을 친 것과 완전히 같은 경로로 간다.
//!
//! # 찾지 못했을 때가 흔한 경우다
//!
//! 개발 빌드를 그냥 띄우면 옆에 꾸러미가 없다. 그때는 **사용법을 보이고 끝낸다** —
//! 그것이 지금까지의 동작이고, 안내 모드가 그것을 나쁘게 만들면 안 된다.

use crate::discover::{self, Unusable};
// 화면과 적재는 `main` 의 것을 그대로 쓴다 — 여기서 다시 만들면 두 벌이 된다.
use crate::{load_manifest, ui};

/// 안내 모드가 정한 다음 행동. **여기서 치료하지 않는다** — 무엇을 할지만
/// 정하고, 실제 실행은 `main` 이 `cmd_run` 으로 보낸다. 화면과 안전 가드를 두 벌
/// 갖지 않기 위해서다.
pub enum Outcome {
    /// 옆에 아무것도 없다 — 부르는 쪽이 사용법을 보인다. 지금까지의 동작이다.
    ShowUsage,
    /// 꾸러미는 있는데 **하나도 쓸 수 없었다.** 사용법이 아니라 가드 중단이다 —
    /// 0 으로 끝나면 "이 PC 는 깨끗하다" 로 읽히는데, 검사를 한 적이 없다.
    NothingUsable,
    /// 이 플러그인으로 `run` 을 돌린다. 사람이 `run --plugin <이 경로>` 를 친
    /// 것과 완전히 같은 경로로 간다. **비터미널 경로가 쓰는 자리다** — 메뉴가
    /// 열리지 않을 때 지금까지처럼 바로 치료로 간다.
    RunWith(std::path::PathBuf),
    /// 메뉴에서 고른 **플러그인이 드는 명령**(묶음 B).
    WithPlugin(crate::menu::WithPlugin),
    /// 물었고 사용자가 그만두었다.
    Stopped,
    /// 하위 화면에서 `0` — 메뉴로 돌아간다.
    Back,
    /// Ctrl+C 두 번 — 세션을 끝낸다.
    End,
    /// 메뉴에서 고른 **입력 없는 명령**(묶음 A). `main` 이 같은 자리로 보낸다.
    Plain(crate::menu::Plain),
    /// 메뉴에서 고른 **회차가 드는 명령**(묶음 C).
    WithRun(crate::menu::WithRun),
    /// 메뉴에서 고른 **파일이 드는 명령**(묶음 D·E)과 그때 고른 플러그인.
    WithFile(crate::menu::WithFile, Option<std::path::PathBuf>),
    /// 메뉴에서 고른 **수집만** (묶음 A 성격 — 입력이 없다)과 그때 고른 플러그인.
    Collect(std::path::PathBuf),
    /// 룰을 고르는 화면의 첫 줄 — 이 기계를 보는 룰 **전부로 검사만** 한다(목표 remedy_출시_20261111
    /// 기준 3). 화면에 쓸 이름과 경로를 고르는 화면의 차례대로 든다.
    ///
    /// 둘째는 **빼 둔 네트워크 점검 룰의 이름**이다(코어 1.4.0) — 주소를 적어야 돌아 여기 들지 않는다.
    /// 끝의 요약이 그 항목을 *돌리지 않았다* 고 함께 적는다: 적지 않으면 *모두* 가 그것까지 한 것으로 읽힌다.
    ScanAll(Vec<(String, std::path::PathBuf)>, Vec<String>),
}

/// 이 룰이 치료하는가 — `remediate` 가 없으면 **찾기만 한다.** 메뉴가 치료를 약속하는 줄을
/// 끄고, 검사 뒤 *다음 할 일* 이 치료를 권하지 않는다. 읽지 못하면 치료하는 쪽으로 본다 —
/// 그 룰은 어차피 돌지 못하고, 줄을 끄는 것은 읽어서 안 것만이다.
pub(crate) fn treats(plugin: &std::path::Path) -> bool {
    load_manifest(&plugin.to_string_lossy()).map_or(true, |m| m.remediate.is_some())
}

/// 메뉴의 답을 안내 모드의 답으로 옮긴다. **두 타입을 하나로 합치지 않는 이유**는
/// 메뉴가 `discover` 를 모르고 안내 모드가 메뉴의 줄을 모르게 두는 것이다 —
/// 합치면 한쪽을 고칠 때 다른 쪽 시험이 운다.
fn to_outcome(p: crate::menu::Pick) -> Outcome {
    match p {
        crate::menu::Pick::ShowUsage => Outcome::ShowUsage,
        crate::menu::Pick::Stopped => Outcome::Stopped,
        crate::menu::Pick::Back => Outcome::Back,
        crate::menu::Pick::End => Outcome::End,
        crate::menu::Pick::WithPlugin(x) => Outcome::WithPlugin(x),
        crate::menu::Pick::Plain(x) => Outcome::Plain(x),
        crate::menu::Pick::WithRun(x) => Outcome::WithRun(x),
        crate::menu::Pick::WithFile(x, p) => Outcome::WithFile(x, p),
        crate::menu::Pick::Collect(p) => Outcome::Collect(p),
    }
}

/// **사람이 앞에 있는가.** 메뉴는 여기가 참일 때만 열린다 (불변식 I7).
///
/// 이것이 갈라 주는 것은 두 벌의 동작이 아니라 **지금까지의 동작을 그대로
/// 두는 자리**다 — 콘솔 캡처와 실기기 하네스는 `stdin` 을 닫고 부르므로
/// 거짓이 되고, 그 경로는 전과 한 글자도 다르지 않다.
pub(crate) fn interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// 메뉴가 읽는 두 폴더 — **결과 폴더와 실행 파일 폴더.**
///
/// 기본 폴더 규칙은 `main` 의 `beside_exe` 가 정한다. 여기서 다시 짜지 않고
/// 같은 모양(`<exe>/out`)을 쓴다 — 두 벌이 되면 갈라진다.
fn folders(exe: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = exe.parent().unwrap_or(std::path::Path::new("."));
    (dir.join("out"), dir.to_path_buf())
}

/// 메뉴에 보일 후보 파일을 모은다 — **종류마다 한 폴더에서, 얕게.**
///
/// 깊이 뒤지지 않는다. `discover::beside` 가 두 자리만 보는 것과 같은 까닭이다 —
/// 깊이 뒤질수록 *"놓기만 하면 된다"* 는 자리가 넓어진다.
///
/// `Plans` 는 한 겹 더 본다: **저널이 아는 회차의 계획만** 올린다. `apply` 가
/// `plan_sha256` 으로 대조해 짝이 안 맞으면 거절하지만, 거절될 것을 목록에
/// 올리면 사용자는 자기가 무엇을 잘못했는지 알 수 없다.
fn candidate_files(
    out_dir: &std::path::Path,
    exe_dir: &std::path::Path,
) -> std::collections::BTreeMap<crate::menu::Candidates, Vec<std::path::PathBuf>> {
    use crate::menu::Candidates as C;
    let mut map = std::collections::BTreeMap::new();
    let scan = |dir: &std::path::Path, c: C| -> Vec<std::path::PathBuf> {
        let mut v: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| c.matches(n))
            })
            .collect();
        v.sort();
        v
    };
    // **결과 폴더는 한 겹 더 본다** (결정 4 · 2026-10-30). 메뉴의 산출이
    // `<exe>\out\<스탬프>\` 로 가므로 한 겹만 보면 **직전 회차의 계획을 찾지
    // 못해** *승인한 계획을 수행하기* 가 메뉴에서 사라진다.
    //
    // **한 겹까지다.** `discover::beside` 가 두 자리만 보는 것과 같은 선이고,
    // 보는 자리는 우리가 만든 `out` 나무 안뿐이다. 그래도 *"놓기만 하면 된다"*
    // 는 자리가 폴더 수만큼 늘어나고, 그 대가를 셋이 받친다 — 계획은 저널이
    // 아는 회차(또는 맨 `plan.json`)만 올리고, `apply` 가 `plan_sha256` 으로
    // 다시 보고, 그 나무는 실행 파일 옆이라 이미 같은 신뢰 모델이다(`out` 한
    // 겹도 전부터 그랬다).
    let scan_out = |c: C| -> Vec<std::path::PathBuf> {
        let mut v = scan(out_dir, c);
        let mut subs: Vec<std::path::PathBuf> = std::fs::read_dir(out_dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        // 이름순이 곧 시간순이다(스탬프로 짓는다) — 같은 폴더에서 늘 같은
        // 차례가 나와야 사람이 고른 번호가 뜻을 갖는다.
        subs.sort();
        for d in subs {
            v.extend(scan(&d, c));
        }
        v
    };
    for c in [C::Artifacts, C::Scans] {
        let v = scan_out(c);
        if !v.is_empty() {
            map.insert(c, v);
        }
    }
    // 서명된 목록은 실행 파일 옆에 온다 — 받은 꾸러미의 자리다.
    let lists = scan(exe_dir, C::Lists);
    if !lists.is_empty() {
        map.insert(C::Lists, lists);
    }
    // 계획은 저널이 아는 회차만.
    let known = restorable_runs();
    let plans: Vec<std::path::PathBuf> = scan_out(C::Plans)
        .into_iter()
        .filter(|p| {
            // `plan.json` 처럼 회차 이름이 없는 것은 올린다 — 방금 이 회차가
            // 쓴 것이고, `apply` 가 저널로 다시 본다.
            let name = p
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            name == "plan" || known.iter().any(|r| name.contains(r.id.as_str()))
        })
        .collect();
    if !plans.is_empty() {
        map.insert(C::Plans, plans);
    }
    map
}

/// 되돌릴 수 있는 회차의 `run_id` 들 — 메뉴가 묶음 C 를 낼지, 무엇을 보일지 정한다.
///
/// **`list_runs` 와 같은 자리를 같은 규칙으로 본다**(`<state>/quarantine/*.rq`).
/// 여기서 세지 않고 목록을 다시 만들면 메뉴에 뜬 줄과 고른 뒤의 화면이 갈린다.
///
/// 읽지 못하면 **없는 것으로 본다** — 메뉴 한 줄을 내지 않을 뿐이고, 명령줄
/// `restore --list` 는 그대로 그 폴더를 읽어 이유를 말한다.
fn restorable_runs() -> Vec<crate::menu::Run> {
    let mut out: Vec<crate::menu::Run> = Vec::new();
    // **두 자리를 다 본다** (결정 3 · 2026-10-30). 인자 없이 띄운 경로는
    // `<exe>/state/` 를 쓰지만, 그 기계에 **전부터 쌓인 격리물**은 기계 공용
    // 자리에 있다 — 거기를 보지 않으면 되돌릴 수 있는 것이 메뉴에서 사라지고,
    // 사용자는 복원할 수 없다고 믿는다(멈출 조건 5).
    //
    // 차례도 뜻이 있다: **메뉴가 쓰는 자리를 먼저** 둔다. 방금 이 꾸러미로 치료한
    // 회차가 목록 위에 오고, 그것이 사람이 가장 자주 찾는 것이다.
    for dir in crate::menu_state_dirs() {
        let q = dir.join("quarantine");
        let mut ids: Vec<String> = std::fs::read_dir(&q)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                p.extension()
                    .and_then(|x| x.to_str())
                    .filter(|x| x.eq_ignore_ascii_case("rq"))?;
                p.file_stem().map(|s| s.to_string_lossy().into_owned())
            })
            .collect();
        ids.sort();
        out.extend(ids.into_iter().map(|id| crate::menu::Run {
            id,
            state: dir.clone(),
        }));
    }
    out
}

/// **끝나지 않은 치료** — 저널에 끝이 없는 회차. 메뉴의 *중단된 작업 이어서 하기* 는 이것이 있을 때만
/// 서고, 이것만 고를 거리로 올린다(목표 remedy_사용자메뉴 기준 2(b)). 끝난 회차를 올리면 `resume` 이
/// '이미 적용됨'(5)으로 거절한다(2026-11-07 적대적 검토). 두 자리를 [`restorable_runs`] 와 같은 차례로
/// 본다. 읽지 못하면 없는 것으로 본다 — 명령줄 `resume` 은 그 폴더를 읽어 까닭을 말한다.
fn unfinished_runs() -> Vec<crate::menu::Run> {
    let mut out = Vec::new();
    for dir in crate::menu_state_dirs() {
        let mut ids = remedy_core::apply::unfinished_runs(&dir).unwrap_or_default();
        ids.sort();
        out.extend(ids.into_iter().map(|id| crate::menu::Run {
            id,
            state: dir.clone(),
        }));
    }
    out
}

/// 지금 세션의 작업 메뉴의 모양 — (룰을 들고 섰는가, 그 룰이 찾기만 하는가). 작업 뒤 *다음 할 일* 이
/// 돌아갈 그 화면의 번호를 세는 데 쓴다([`next_offer`]). 룰 없이 기록만 있는 기계의 메뉴에는 치료 줄이
/// 없고, 찾기만 하는 룰의 메뉴에서는 1 번이 *검사만 하기* 다. *모두 검사만* 뒤의 안내는 찾은 룰 가운데
/// 치료하는 것을 고른 뒤의 메뉴를 가리키므로 (룰 있음, 치료함)이다.
static MENU_SHAPE: std::sync::Mutex<(bool, bool)> = std::sync::Mutex::new((true, false));

fn set_menu_shape(plugin: bool, detect_only: bool) {
    if let Ok(mut g) = MENU_SHAPE.lock() {
        *g = (plugin, detect_only);
    }
}

/// 작업 **뒤** 돌아갈 메뉴의 모양 — *다음 할 일* 이 그 화면에서 줄의 번호를 센다(목표 remedy_사용자메뉴
/// 기준 4). 기본 화면은 일이 있을 때만 줄을 세우므로, 치료가 만든 회차 · 복원이 지운 회차를 지금 다시
/// 읽는다. 후보 파일은 기본 화면의 번호와 상관없어 읽지 않는다.
pub(crate) fn next_offer() -> crate::menu::Offer {
    let (plugin, detect_only) = MENU_SHAPE.lock().map_or((true, false), |g| *g);
    let runs = restorable_runs();
    crate::menu::Offer {
        plugin: plugin.then(std::path::PathBuf::new),
        detect_only,
        // 네트워크 점검 뒤에는 가리킬 줄이 없다(`next_steps` 가 비어 있다) — 번호를 셀 일이 없다.
        network: false,
        companion_missing: false,
        name: None,
        runs_locked: runs.is_empty() && runs_locked(),
        runs,
        unfinished: unfinished_runs(),
        files: std::collections::BTreeMap::new(),
    }
}

/// 복원 정보 폴더가 **있는데 권한 때문에 읽지 못하는가.** [`restorable_runs`] 는 못 읽은 것을
/// 없는 것으로 세므로, 관리자(root)로 치료한 뒤 권한 없이 다시 띄우면 회차 줄이 *"치료한 기록이
/// 없습니다"* 라고 해 기록이 사라진 것으로 읽혔다(2026-11-08 적대적 검토 4바퀴 — 리눅스 실측:
/// 상태 폴더 `drwx------ root`). 폴더가 없으면 거짓이다 — 그때는 정말 없다.
fn runs_locked() -> bool {
    crate::menu_state_dirs().iter().any(|dir| {
        matches!(
            std::fs::read_dir(dir.join("quarantine")),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied
        )
    })
}

/// 인자 없이 불렸다. **내놓을 것이 있으면 메뉴를 열고, 없으면 사용법이다.**
///
/// 내놓을 것은 둘 — 쓸 수 있는 플러그인과 되돌릴 수 있는 회차다. 둘 다 없으면
/// [`Outcome::ShowUsage`] 이고 **그것이 지금까지의 동작이다**(목표 `remedy_cli`
/// §3-00: 시연 1단계가 그 화면을 판정하고, 데모 폴더는 둘 다 없다).
pub fn run(anchor: Option<&str>) -> Outcome {
    let lang = ui().lang;
    let Ok(exe) = std::env::current_exe() else {
        return Outcome::ShowUsage;
    };
    let found = discover::beside(&exe);
    if found.is_empty() {
        // **플러그인이 없어도 되돌릴 것이 있으면 메뉴를 연다.** 치료한 적이 있는
        // 기계에서 꾸러미를 지우고 되돌리려는 사람이 여기 온다 — 전에는 그
        // 사람에게 사용법만 보였다.
        //
        // 터미널일 때만이다 — 아니면 지금까지처럼 사용법이다(불변식 I7).
        if interactive() {
            let runs = restorable_runs();
            let unfinished = unfinished_runs();
            let (out_dir, exe_dir) = folders(&exe);
            let files = candidate_files(&out_dir, &exe_dir);
            // 꾸러미가 없어도 **회차나 후보 파일이 있으면** 메뉴를 연다 — 치료한
            // 적이 있는 기계에서 되돌리려는 사람, 목록을 반입하려는 운영자가
            // 여기 온다. 전에는 그 사람에게 사용법만 보였다.
            if !runs.is_empty() || !unfinished.is_empty() || !files.is_empty() {
                set_menu_shape(false, false);
                return to_outcome(crate::menu::run(&crate::menu::Offer {
                    plugin: None,
                    detect_only: false,
                    network: false,
                    companion_missing: false,
                    name: None,
                    runs_locked: runs.is_empty() && runs_locked(),
                    runs,
                    unfinished,
                    files,
                }));
            }
        }
        // 개발 빌드를 그냥 띄운 경우다. 아무 말 없이 사용법으로 간다 —
        // "찾지 못했다" 를 알리면 꾸러미가 아닌 자리에서 잡음이 된다.
        //
        // **배포 빌드면 한 줄 말한다.** zip 을 탐색기로 연 채 실행 파일을 누르면 Windows 가 그
        // 파일만 임시 폴더에 꺼내 띄워 옆에 `plugins` 가 없다 — 사용법만 뜨면 받은 사람은 무엇이
        // 잘못됐는지 모른다(v1.1.0 적대적 검토). 앵커가 없는 개발 빌드는 지금처럼 조용하다.
        if anchor.is_some() && interactive() {
            errln!(
                "{}",
                if cfg!(windows) {
                    lang.t(
                        "검사 룰 폴더(plugins)를 이 실행 파일 옆에서 찾지 못했습니다. 받은 zip 을 \
                         '모두 압축 풀기'로 푼 뒤, 풀린 폴더의 remedy.exe 를 실행하십시오.",
                        "The rule folder (plugins) is not next to this program. Extract the downloaded \
                         zip with 'Extract All', then run remedy.exe in the extracted folder.",
                    )
                } else {
                    lang.t(
                        "검사 룰 폴더(plugins)를 이 실행 파일 옆에서 찾지 못했습니다. 받은 파일을 \
                         통째로 푼 뒤, 풀린 폴더에서 sudo ./remedy 로 실행하십시오.",
                        "The rule folder (plugins) is not next to this program. Extract the whole \
                         download, then run sudo ./remedy in the extracted folder.",
                    )
                }
            );
            errln!();
        }
        return Outcome::ShowUsage;
    }

    // **배너를 여기서 내지 않는다.** 곧 `cmd_run` 이 플러그인 이름까지 담은
    // 배너를 내므로 두 번 나온다 — 실측으로 그렇게 보였다(2026-09-08). 고를
    // 거리가 여럿일 때만 머리글이 필요하고, 그것은 `choose` 가 적는다.

    // ── 쓸 수 있는 것만 남긴다 ───────────────────────────────────
    //
    // **검증을 통과한 것만 고를 거리에 올린다.** 통과하지 못한 것을 목록에 넣고
    // 고르게 하면, 사용자가 그것을 골랐을 때 거절해야 하고 그 거절은 사용자가
    // 무엇을 잘못했는지 말해 주지 못한다.
    let mut ok = Vec::new();
    let mut rejected = Vec::new();
    for f in found {
        match discover::usable(&f.dir, anchor) {
            // 데이터 룰(코어 1.12.0)은 검사 항목이 아니다 — 동반 프로그램이 읽는 기준을 담을 뿐이라
            // 고를 거리에도 개수에도 넣지 않는다. 서명이 맞지 않으면 아래처럼 거절된 것으로 말한다.
            Ok(()) if is_data(&f) => {}
            Ok(()) => ok.push(f),
            Err(why) => rejected.push((f, why)),
        }
    }

    if ok.is_empty() {
        report_rejections(&rejected);
        errln!(
            "  {}",
            lang.t(
                "쓸 수 있는 검사 항목이 없어 아무것도 검사하지 못했습니다.",
                "nothing usable was found, so nothing was checked."
            )
        );
        return Outcome::NothingUsable;
    }
    // 통과한 것이 있어도 거절된 것은 말한다 — 조용히 빼면 사용자는 자기가 받은
    // 꾸러미의 절반이 무시된 것을 모른다.
    if !rejected.is_empty() {
        report_rejections(&rejected);
    }

    let Some(choice) = choose(&ok) else {
        // 작업 뒤 메뉴로 돌아와 그만두면 "아무것도 하지 않았습니다" 가 거짓이다 — 메뉴의
        // 그만두기와 같은 말을 쓴다(`menu::run`). 비터미널에서는 작업이 돌지 않았으므로 그대로다.
        outln!(
            "{}",
            if crate::term::tasks_ran() {
                lang.t("끝냅니다.", "Exiting.")
            } else {
                lang.t("아무것도 하지 않았습니다.", "Nothing was done.")
            }
        );
        return Outcome::Stopped;
    };
    let chosen = match choice {
        Choice::One(c) => c,
        Choice::All(all, skipped) => {
            set_menu_shape(true, false);
            // 빼 둔 네트워크 점검은 **끝의 요약**이 적는다(`main` 의 `scan_all`) — 검사 앞에 적으면
            // 룰마다의 화면에 밀려 결과를 읽는 자리에서는 보이지 않는다.
            return Outcome::ScanAll(
                all.into_iter().map(|c| (c.label, c.path)).collect(),
                skipped,
            );
        }
    };

    // ── 무엇을 할지 먼저 고른다 — **터미널일 때만** ──────────────
    //
    // **전에는 여기서 곧바로 치료로 갔다.** 꾸러미를 받은 사람이 할 일이 그것
    // 하나뿐이라고 본 것인데, 되돌리기·신고·재검사가 전부 명령줄에만 있었다.
    // 이제 플러그인을 고른 뒤 **작업**을 고른다.
    //
    // **터미널이 아니면 메뉴를 열지 않고 지금까지처럼 치료로 간다.** 그 길을
    // 바꾸면 캡처가 전부 갈린다 — 콘솔 캡처의 `G` 헬퍼는 `stdin` 을 닫으므로
    // (`Capture-Console.ps1`) A8·B2 가 비터미널로 돌고, 그 두 절은 **치료까지
    // 가서** 종료 코드 2 를 낸다. 여기서 사용법으로 돌리면 그 둘이 0 이 된다.
    // 실기기 하네스도 같은 방식으로 부른다.
    if interactive() {
        let (out_dir, exe_dir) = folders(&exe);
        let runs = restorable_runs();
        let detect_only = !treats(&chosen.path);
        set_menu_shape(true, detect_only);
        let pick = crate::menu::run(&crate::menu::Offer {
            plugin: Some(chosen.path.clone()),
            detect_only,
            network: chosen.network,
            // 있는지만 본다 — 서명은 띄울 때 확인한다(`net::locate`). 없으면 그 줄이 까닭과 함께 꺼진다.
            companion_missing: chosen.network && !crate::net::present(),
            name: Some(chosen.label.clone()),
            runs_locked: runs.is_empty() && runs_locked(),
            runs,
            unfinished: unfinished_runs(),
            files: candidate_files(&out_dir, &exe_dir),
        });
        return to_outcome(pick);
    }

    // 네트워크 점검 룰은 이 길에서 돌지 않는다(주소를 물어볼 수 없다 — `main` 이 까닭을 말한다).
    // 돌리지 않을 것을 *검사합니다* 라고 적지 않는다.
    if !chosen.network {
        outln!();
        outln!(
            "{}",
            lang.pick(
                format!(
                    "{} 검사합니다.",
                    remedy_sdk::i18n::with_particle(&chosen.label, "을", "를")
                ),
                format!("Checking for {}.", chosen.label)
            )
        );
    }
    // **권한 문은 `main` 이 연다.** 여기서 따로 보면 `run` 과 두 벌이 되고,
    // 갈라지면 안내 모드로 들어온 사람만 다른 판정을 받는다.
    Outcome::RunWith(chosen.path)
}

/// 고른 것 하나 — 화면에 쓸 이름과 넘길 경로.
#[derive(Clone)]
struct Chosen {
    label: String,
    path: std::path::PathBuf,
    /// 네트워크로 점검하는 룰인가(`network`) — 이 기계를 보지 않고 동반 프로그램이 맡는다.
    network: bool,
}

/// 고르는 화면의 답 — 룰 하나, 또는 **전부로 검사만**.
enum Choice {
    One(Chosen),
    /// 이 기계를 보는 룰 전부와, **빼 둔 네트워크 점검 룰의 이름** — 그 룰은 주소를 적어야 돌아서
    /// 한꺼번에 돌릴 수 없다. 빼 두었다는 것을 말해야 *모두* 가 거짓이 되지 않는다.
    All(Vec<Chosen>, Vec<String>),
}

/// 데이터 룰(`kind: data` · 코어 1.12.0)인가 — 서명을 확인한 뒤에 부른다.
///
/// 조용히 읽는다(`load_manifest` 는 주의 줄을 찍는데, 검사 항목은 `choose` 가 다시 읽으므로 두 번
/// 찍힌다). 못 읽으면 데이터 룰이 아닌 것으로 두어 지금까지처럼 다룬다.
fn is_data(f: &discover::Found) -> bool {
    std::fs::read_to_string(&f.path)
        .ok()
        .and_then(|t| serde_yaml_ng::from_str::<remedy_sdk::manifest::PluginManifest>(&t).ok())
        .is_some_and(|m| m.kind == Some(remedy_sdk::manifest::PluginKind::Data))
}

/// 거절된 것을 화면에 적는다. **왜 못 쓰는지가 사용자의 다음 행동을 정한다.**
fn report_rejections(rejected: &[(discover::Found, Unusable)]) {
    let lang = ui().lang;
    for (f, why) in rejected {
        let what = match why {
            Unusable::NoAnchor => lang.t(
                "이 프로그램은 플러그인 번들을 검증할 수 없습니다 (배포본이 아닙니다)",
                "this build cannot verify plugin bundles (not an official release)",
            ),
            Unusable::NotSigned(_) => lang.t(
                "서명이 없습니다 — 배포처에서 받은 것이 맞는지 확인하십시오",
                "not signed — check that it came from the vendor",
            ),
            Unusable::Tampered(_) => lang.t(
                "내용이 바뀌었습니다 — 배포처에서 다시 받으십시오",
                "its contents changed — download it again from the vendor",
            ),
        };
        errln!(
            "  {} {}: {what}",
            lang.t("건너뜀", "skipped"),
            f.dir.display()
        );
    }
}

/// 하나면 그것, 여럿이면 고르게 한다 (결정 2026-09-08).
///
/// 여럿일 때 **첫 줄은 전부로 검사만**이다(목표 remedy_출시_20261111 기준 3) — 어떤 위협인지
/// 모르는 사람이 룰을 하나씩 골라 다시 띄우지 않게. 맨 위에 두어 룰이 늘어도 그 번호는
/// 1 이다. 치료는 지금처럼 룰을 골라서 한다.
fn choose(ok: &[discover::Found]) -> Option<Choice> {
    let lang = ui().lang;
    let chosen = |f: &discover::Found| -> Chosen {
        // 사람이 읽는 이름은 매니페스트에 있다. 못 읽으면 폴더 이름으로 간다 —
        // 여기서 실패해 전체를 세우지 않는다.
        let m = load_manifest(&f.path.to_string_lossy()).ok();
        let network = m.as_ref().is_some_and(|m| m.network.is_some());
        let label = m
            .and_then(|m| {
                m.name
                    .get(lang.id())
                    .or_else(|| m.name.get("en"))
                    .or_else(|| m.name.values().next())
                    .cloned()
            })
            .unwrap_or_else(|| {
                f.dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into()
            });
        Chosen {
            label,
            path: f.path.clone(),
            network,
        }
    };
    // 한 번만 읽는다 — 줄을 그릴 때와 고른 뒤가 같은 것을 본다.
    let all: Vec<Chosen> = ok.iter().map(chosen).collect();
    // **네트워크를 쓰는 항목은 고르기 전에 그렇다고 보인다** — 이름 뒤에 꼬리표로 붙인다.
    //
    // 대시로 잇지 않는다: 이 화면들에서 `이름 — 까닭` 은 **지금 고를 수 없는 줄**의 꼴이다(`Row::Off`).
    // 색이 없는 줄 입력 화면에서는 그 둘이 똑같이 보여 꺼진 항목으로 읽힌다 — 메뉴 하네스도 그 줄을
    // 꺼진 줄로 셌다(2026-11-10 랩 실측). 대괄호는 그 꼴과 겹치지 않는다.
    let shown = |c: &Chosen| -> String {
        if c.network {
            format!(
                "{} [{}]",
                c.label,
                lang.t("네트워크 사용", "uses the network")
            )
        } else {
            c.label.clone()
        }
    };
    if all.len() == 1 {
        set_picked(None);
        return all.into_iter().next().map(Choice::One);
    }
    // *모두 검사만* 은 이 기계를 보는 항목의 것이다 — 네트워크 점검은 주소를 적어야 돈다.
    let local: Vec<Chosen> = all.iter().filter(|c| !c.network).cloned().collect();
    let remote: Vec<String> = all
        .iter()
        .filter(|c| c.network)
        .map(|c| c.label.clone())
        .collect();

    use crate::term::{Answer, Row};
    use std::io::IsTerminal;
    let mut rows = vec![
        Row::Blank,
        Row::Text(lang.pick(
            format!("검사 항목 {}개를 찾았습니다:", ok.len()),
            format!("Found {} things to check:", ok.len()),
        )),
    ];
    if !std::io::stdin().is_terminal() {
        // 여기 올 일은 없다(안내 모드는 터미널에서만 열린다). 그래도 물어볼 수
        // 없는 자리에서 임의로 고르지 않는다. 목록은 지금까지처럼 보인다.
        for r in &rows {
            match r {
                Row::Blank => outln!(),
                Row::Text(t) | Row::Group(t) => outln!("{t}"),
                Row::Item(_) | Row::Off(..) => {}
            }
        }
        for (i, c) in all.iter().enumerate() {
            outln!("  {}. {}", i + 1, shown(c));
        }
        return None;
    }
    // **이 화면이 룰이 여럿인 꾸러미의 첫 화면이다**(리눅스 공식 배포가 그렇다). 작업 메뉴의
    // 머리말처럼 이름 · 버전 · 권한을 먼저 말한다 — 전에는 sudo 를 빠뜨려도 여기서는 말이 없고
    // 항목을 고른 뒤에야 알았다(README *"메뉴 맨 위에서 지금 권한을 먼저"* · v1.1.0 적대적 검토).
    let mut head = vec![Row::Text(format!(
        "{} {}",
        remedy_core::report::brand::product(lang),
        env!("CARGO_PKG_VERSION")
    ))];
    if let Some(line) = crate::menu::privilege_line(lang) {
        head.push(Row::Text(line));
    }
    head.push(Row::Blank);
    rows.splice(1..1, head);
    // 첫 줄의 수는 **이 기계를 보는 항목**의 수다. 네트워크 점검만 든 폴더에서는 돌릴 것이 없어 꺼진다 —
    // 줄을 빼지 않는 것은 항목의 번호가 2 부터라는 것이 안내문 · 하네스에 적혀 있어서다.
    let all_label = lang.pick(
        format!(
            "{}개 모두 검사만 하기 (아무것도 바꾸지 않습니다)",
            local.len()
        ),
        format!("Scan with all {} (changes nothing)", local.len()),
    );
    rows.push(if local.is_empty() {
        Row::Off(
            all_label,
            lang.t(
                "이 기계를 검사하는 항목이 없습니다",
                "nothing here scans this machine",
            )
            .to_string(),
        )
    } else {
        Row::Item(all_label)
    });
    rows.extend(all.iter().map(|c| Row::Item(shown(c))));
    // 작업 뒤에도 이 화면으로 돌아오므로 끝내는 줄이 보여야 한다 — 전에는 번호가 아닌 것을
    // 쳐야 끝났다.
    let Answer::Num(n) = crate::term::choose(&rows, Some(lang.t("그만두기", "Quit"))) else {
        return None;
    };
    if n == 1 {
        set_picked(None);
        return Some(Choice::All(local, remote));
    }
    let c = all.get(n.checked_sub(2)?)?;
    set_picked(Some((n, c.label.clone())));
    Some(Choice::One(c.clone()))
}

/// 룰이 여럿인 화면에서 고른 룰 — **그 화면의 번호와 이름.**
///
/// 작업이 끝나면 메뉴 고리가 이 화면부터 다시 세운다. 그런데 다음 할 일은 작업 메뉴의 번호를
/// 가리켜서, 리눅스에서 치료 뒤 안내대로 `6`(복원)을 누르면 이 화면이 범위 밖으로 읽고
/// 끝냈고, 검사만 뒤 `1`(치료)은 *모두 검사만* 을 돌렸다(2026-11-08 적대적 검토 4바퀴 실측).
/// 그래서 다음 할 일이 **먼저 고를 룰**을 이것으로 앞에 적는다(`back_to_menu`). 룰이 하나인
/// 꾸러미와 *모두 검사만* 뒤에는 비어 있다 — 그때의 화면은 지금 그대로다.
static PICKED: std::sync::Mutex<Option<(usize, String)>> = std::sync::Mutex::new(None);

fn set_picked(v: Option<(usize, String)>) {
    if let Ok(mut g) = PICKED.lock() {
        *g = v;
    }
}

/// 지금 세션에서 마지막으로 고른 룰(고르는 화면의 번호 · 이름). [`PICKED`] 참고.
pub(crate) fn picked_rule() -> Option<(usize, String)> {
    PICKED.lock().ok().and_then(|g| g.clone())
}
