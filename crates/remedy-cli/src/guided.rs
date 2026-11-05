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
    /// 메뉴에서 고른 **수집만** (묶음 A 성격 — 입력이 없다).
    Collect,
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
        crate::menu::Pick::Collect => Outcome::Collect,
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
            let (out_dir, exe_dir) = folders(&exe);
            let files = candidate_files(&out_dir, &exe_dir);
            // 꾸러미가 없어도 **회차나 후보 파일이 있으면** 메뉴를 연다 — 치료한
            // 적이 있는 기계에서 되돌리려는 사람, 목록을 반입하려는 운영자가
            // 여기 온다. 전에는 그 사람에게 사용법만 보였다.
            if !runs.is_empty() || !files.is_empty() {
                return to_outcome(crate::menu::run(&crate::menu::Offer {
                    plugin: None,
                    runs,
                    files,
                }));
            }
        }
        // 개발 빌드를 그냥 띄운 경우다. 아무 말 없이 사용법으로 간다 —
        // "찾지 못했다" 를 알리면 꾸러미가 아닌 자리에서 잡음이 된다.
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

    let Some(chosen) = choose(&ok) else {
        outln!(
            "{}",
            lang.t("아무것도 하지 않았습니다.", "Nothing was done.")
        );
        return Outcome::Stopped;
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
        let pick = crate::menu::run(&crate::menu::Offer {
            plugin: Some(chosen.path.clone()),
            runs: restorable_runs(),
            files: candidate_files(&out_dir, &exe_dir),
        });
        return to_outcome(pick);
    }

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
    // **권한 문은 `main` 이 연다.** 여기서 따로 보면 `run` 과 두 벌이 되고,
    // 갈라지면 안내 모드로 들어온 사람만 다른 판정을 받는다.
    Outcome::RunWith(chosen.path)
}

/// 고른 것 하나 — 화면에 쓸 이름과 넘길 경로.
struct Chosen {
    label: String,
    path: std::path::PathBuf,
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
fn choose(ok: &[discover::Found]) -> Option<Chosen> {
    let lang = ui().lang;
    let label = |f: &discover::Found| -> String {
        // 사람이 읽는 이름은 매니페스트에 있다. 못 읽으면 폴더 이름으로 간다 —
        // 여기서 실패해 전체를 세우지 않는다.
        load_manifest(&f.path.to_string_lossy())
            .ok()
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
            })
    };

    if ok.len() == 1 {
        return Some(Chosen {
            label: label(&ok[0]),
            path: ok[0].path.clone(),
        });
    }

    use crate::term::{Answer, Row};
    use std::io::IsTerminal;
    let mut rows = vec![
        Row::Blank,
        Row::Text(lang.pick(
            format!("검사 항목 {}개를 찾았습니다:", ok.len()),
            format!("Found {} things to check:", ok.len()),
        )),
    ];
    rows.extend(ok.iter().map(|f| Row::Item(label(f))));
    if !std::io::stdin().is_terminal() {
        // 여기 올 일은 없다(안내 모드는 터미널에서만 열린다). 그래도 물어볼 수
        // 없는 자리에서 임의로 고르지 않는다. 목록은 지금까지처럼 보인다.
        for r in &rows {
            match r {
                Row::Blank => outln!(),
                Row::Text(t) => outln!("{t}"),
                Row::Item(_) | Row::Off(..) => {}
            }
        }
        for (i, f) in ok.iter().enumerate() {
            outln!("  {}. {}", i + 1, label(f));
        }
        return None;
    }
    let Answer::Num(n) = crate::term::choose(&rows, None) else {
        return None;
    };
    let f = ok.get(n.checked_sub(1)?)?;
    Some(Chosen {
        label: label(f),
        path: f.path.clone(),
    })
}
