//! remedy — 멀티플랫폼 전용백신.
//!
//! 인자 파싱과 출력만 한다. 조립은 `remedy-core` 가 맡는다 (설계-04 §1).
//!
//! 표면은 두 갈래다. `collect` · `evaluate` · `plan` · `scan` 은 **읽기
//! 전용**이고, `apply` · `run` 은 시스템을 바꾼다 — 파괴가 시작되는 입구는
//! `apply` 하나뿐이다 (P6). `restore` 는 그것을 되돌린다 (P5).
#![forbid(unsafe_code)]

use remedy_core::{Pipeline, RunMeta};
use remedy_sdk::artifact::{ExitCode as Code, Observation};
use remedy_sdk::manifest::{PluginKind, PluginManifest};
use std::io::Write;
use std::process::ExitCode;

#[macro_use]
mod tee;

// **아직 아무 데서도 부르지 않는다** (Phase 4-2). 안내 모드 본체(4-3)가 이것을
// 부르고, 그 전까지 제품 동작은 한 글자도 바뀌지 않는다 — 시험만 이 모듈을
// 세운다. 탐색은 읽기 권한의 상한을 여는 일이라 검증 게이트보다 먼저 로드
// 경로에 붙이면 안 된다.
mod discover;
mod menu;

// **인자가 하나도 없을 때만 열린다** (Phase 4-3). 그 조건은 `main` 의 `None`
// 갈래 하나이고, `never_waits.rs` 가 "인자가 있으면 그 갈래에 오지 않는다" 를
// 잠근다.
mod guided;

// 화면 공통 층 — 그리는 자리의 판정 · 방향키 + 숫자로 고르기 · Ctrl+C 두 번.
mod term;

// 네트워크 점검 — 본체는 통신하지 않고, 서명이 맞는 동반 프로그램(`remedy-net`)을 띄워 맡긴다.
mod net;

// 같은 제품의 점검 발견을 묶는다 — *모두 검사* 끝 요약 밑의 '제품마다 — 올리면 해결되는 버전'.
mod all;
mod product;
mod restore_cmd;
use restore_cmd::*;
mod trust_cmd;
use trust_cmd::*;
mod recheck;
use recheck::*;
mod help;
use help::*;
mod after_task;
use after_task::*;
use all::*;

/// 화면 전체에 걸리는 설정. 시작할 때 한 번 정하고 어디서든 읽는다.
///
/// `--lang`·`--ascii`·`--verbose` 는 어느 자리에 와도 된다 — 사용자는
/// `remedy --lang en run …` 이라고도 쓰고 `remedy run … --lang en` 이라고도
/// 쓴다. 둘 다 받고 하위 명령에는 넘기지 않는다.
struct Ui {
    lang: remedy_core::report::Lang,
    verbose: bool,
}

static UI: std::sync::OnceLock<Ui> = std::sync::OnceLock::new();

fn ui() -> &'static Ui {
    UI.get_or_init(|| Ui {
        lang: remedy_sdk::i18n::Lang::En,
        verbose: false,
    })
}

/// 전역 플래그를 떼어 내고 나머지를 돌려준다. `--ascii` 는 받았는가만(`Some(true)`) — 환경과 로케일로 정하는
/// 것은 `remedy_sdk::i18n::init_from` 이다.
fn split_global(args: Vec<String>) -> (Vec<String>, Option<String>, Option<bool>, bool) {
    let mut rest = Vec::with_capacity(args.len());
    let mut lang = None;
    let mut ascii = None;
    let mut verbose = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            // 뒤가 옵션이면 값이 빠진 것이다 — 그 옵션을 언어로 먹지 않고 `--lang` 을 남겨 명령의 해석이 거절하게
            // 한다. 전에는 `run … --lang --dry-run --yes` 가 `--dry-run` 을 언어로 먹어 진짜 치료가 됐다.
            "--lang" if args.get(i + 1).is_some_and(|n| n.starts_with("--")) => {
                rest.push(args[i].clone());
                i += 1;
            }
            "--lang" => {
                lang = args.get(i + 1).cloned();
                i += 2;
            }
            "--ascii" => {
                ascii = Some(true);
                i += 1;
            }
            "--verbose" | "-v" => {
                verbose = true;
                i += 1;
            }
            _ => {
                rest.push(args[i].clone());
                i += 1;
            }
        }
    }
    (rest, lang, ascii, verbose)
}

fn main() -> ExitCode {
    // UTF-8 이 아닌 인자는 사용법 오류다 — `std::env::args()` 는 그 자리에서 패닉하고 배포 빌드는 그대로 죽는다
    // (`remedy_sdk::cmdline::utf8_args` 의 주석).
    let raw = match remedy_sdk::cmdline::utf8_args() {
        Ok(raw) => raw,
        Err(bad) => {
            errln!("{}", remedy_sdk::cmdline::not_utf8_message(&bad));
            return ExitCode::from(Code::UsageError.code());
        }
    };
    let (args, lang_flag, ascii, verbose) = split_global(raw);
    // Windows 는 `LANG` 을 설정하지 않는다 — 받아서 더블클릭한 한국어 PC 가 영어로 떨어졌다(실측
    // 2026-09-09). OS 가 말하는 로케일을 넘긴다. `--lang kr` 처럼 모르는 값은 무시하되 **말한다** —
    // 알림은 두 언어로, 어느 쪽을 읽든 이해되게.
    let (lang, unknown_lang) = remedy_sdk::i18n::init_from(
        lang_flag.as_deref(),
        ascii,
        remedy_core::user_locale().as_deref(),
    );
    let _ = UI.set(Ui { lang, verbose });
    tee::install_panic_hook();
    if let Some(v) = unknown_lang {
        errln!(
            "--lang '{v}': 모르는 언어라 무시했습니다 (ko | en) / unknown language, ignored (ko | en)"
        );
    }

    let cmd = args.first().map(String::as_str);
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };

    // ── 코어 자기무결성 (설계-01 D7) ─────────────────────────────
    //
    // **시작 시 한 번만 검사한다.** 명령마다 부르면 같은 파일을 여러 번 읽고,
    // 그 사이에 결과가 달라지면 어느 쪽이 참인지 알 수 없다.
    let integrity = remedy_core::integrity::check_self();
    // **메뉴 세션은 경고로 시작하지 않는다** — 같은 사실을 첫 화면 머리말 아래 짧은 한 줄로 한 번 말한다(목표
    // remedy_시연전_안정화 D5). 명령줄 호출은 지금처럼 첫 줄이다(무인 배포 출력 · 불변식 I1).
    let menu_note = (cmd.is_none() && guided::interactive())
        .then(|| remedy_core::integrity::header_note(&integrity))
        .flatten();
    match menu_note {
        Some(note) => term::set_notice(note),
        None => {
            if let Some(note) = remedy_core::integrity::advisory(&integrity) {
                // 막지 않는 경우에도 말한다. 조용히 넘어가면 "확인했다" 로 읽힌다.
                errln!("{}: {note}", ui().lang.t("알림", "Notice"));
            }
        }
    }

    let outcome = match cmd {
        Some("--version") | Some("-V") => {
            print_version();
            Ok(Code::NoThreat)
        }
        Some("--help") | Some("-h") | Some("help") => {
            usage(false);
            Ok(Code::NoThreat)
        }
        Some("--help-all") => {
            usage_all();
            Ok(Code::NoThreat)
        }
        Some("selftest") => Ok(selftest()),
        Some("collect") => admin_gate().and_then(|()| cmd_collect(rest)),
        Some("evaluate") => cmd_evaluate(rest),
        Some("plan") => cmd_plan(rest),
        // 네트워크 점검 룰이면 이 기계를 만지지 않는다 — 관리자 문을 지나지 않고 동반 프로그램에 맡긴다.
        Some("scan") => match network_rule(rest) {
            Some(kind) => cmd_net(kind, rest),
            None => admin_gate().and_then(|()| cmd_scan(rest)),
        },
        Some("restore") => admin_gate().and_then(|()| cmd_restore(rest)),
        Some("apply") => admin_gate()
            .and_then(|()| integrity_gate(&integrity))
            .and_then(|()| cmd_apply(rest, &integrity)),
        // 점검 룰의 `run` 은 점검이다 — 네트워크 점검 룰도 같은 자리로 간다(`scan` 과 같다).
        Some("run") => match network_rule(rest) {
            Some(kind) => cmd_net(kind, rest),
            None => admin_gate()
                .and_then(|()| integrity_gate(&integrity))
                .and_then(|()| cmd_run(rest, &integrity)),
        },
        Some("verify") => admin_gate().and_then(|()| cmd_verify(rest)),
        Some("resume") => admin_gate()
            .and_then(|()| integrity_gate(&integrity))
            .and_then(|()| cmd_resume(rest, &integrity)),
        // 신고 첨부물 (설계-04 §6). **파괴가 아니므로 자기무결성 문을 지나지
        // 않는다** — 변조된 바이너리에서도 무엇이 일어났는지 모을 수 있어야
        // 하고, 그 기록이 사고를 밝히는 재료다.
        Some("support-bundle") => cmd_support_bundle(rest),
        // `plugin <하위명령>`.
        //
        // **`sign` 은 여기 없다.** 서명은 개인키를 다루는 일이고 그 도구는
        // `cargo xtask sign` 이다 — 치료 도구가 서명 능력을 갖지 않는다
        // (`xtask/src/sign.rs` 의 근거).
        // `revocation <하위명령>` (설계-03 §6).
        //
        // **`fetch` 는 여기 없다.** 그것은 HTTP 를 이 바이너리에 링크하는 일이고,
        // 설계-01 D9 가 치료 경로에 네트워크가 들어오는 것을 막는다. 목록을
        // 어떻게 받든 들어오는 문은 `import` 하나다.
        // 조직 허용 목록 (설계-03 §3 5층). 폐기 목록과 **같은 레일**이고
        // 방향만 반대다 — 그쪽은 닫고 이쪽은 파괴 대상에서 뺀다.
        Some("allowlist") => match rest.first().map(String::as_str) {
            Some("verify") => cmd_allowlist_verify(&rest[1..]),
            Some("import") => cmd_allowlist_import(&rest[1..]),
            Some(other) => {
                errln!(
                    "{} {other}",
                    ui().lang.t(
                        "알 수 없는 하위 명령: allowlist",
                        "unknown subcommand: allowlist"
                    )
                );
                Ok(Code::UsageError)
            }
            None => {
                errln!(
                    "{}",
                    ui().lang.t(
                        "allowlist 뒤에 하위 명령이 필요합니다. 쓸 수 있는 것: verify · import",
                        "allowlist needs a subcommand. available: verify · import"
                    )
                );
                Ok(Code::UsageError)
            }
        },
        Some("revocation") => match rest.first().map(String::as_str) {
            Some("verify") => cmd_revocation_verify(&rest[1..]),
            Some("import") => cmd_revocation_import(&rest[1..]),
            Some(other) => {
                errln!(
                    "{} {other}",
                    ui().lang.t(
                        "알 수 없는 하위 명령: revocation",
                        "unknown subcommand: revocation"
                    )
                );
                Ok(Code::UsageError)
            }
            None => {
                errln!(
                    "{}",
                    ui().lang.t(
                        "revocation 뒤에 하위 명령이 필요합니다. 쓸 수 있는 것: verify · import",
                        "revocation needs a subcommand. available: verify · import"
                    )
                );
                Ok(Code::UsageError)
            }
        },
        Some("plugin") => match rest.first().map(String::as_str) {
            Some("lint") => cmd_plugin_lint(&rest[1..]),
            Some("verify") => cmd_plugin_verify(&rest[1..]),
            Some(other) => {
                errln!(
                    "{} {other}",
                    ui().lang
                        .t("알 수 없는 하위 명령: plugin", "unknown subcommand: plugin")
                );
                errln!(
                    "{}",
                    ui().lang
                        .t("쓸 수 있는 것: lint · verify", "available: lint · verify")
                );
                Ok(Code::UsageError)
            }
            None => {
                errln!(
                    "{}",
                    ui().lang.t(
                        "plugin 뒤에 하위 명령이 필요합니다. 쓸 수 있는 것: lint · verify",
                        "plugin needs a subcommand. available: lint · verify"
                    )
                );
                Ok(Code::UsageError)
            }
        },
        None => {
            // **인자가 없다 — 더블클릭했거나 콘솔에서 그냥 쳤다.**
            //
            // 옆에 검증된 꾸러미가 있으면 그것으로 간다. 없으면 지금까지처럼
            // 사용법이다. 어느 쪽이든 창을 붙잡는다 — 콘솔 서브시스템 실행
            // 파일은 프로세스가 끝나면 OS 가 창을 없애므로, 그러지 않으면
            // 화면이 검은 깜빡임 한 번으로 끝난다.
            //
            // **사람이 앞에 있으면 작업 뒤 메뉴로 돌아온다**(목표 remedy_제품화 기준
            // 4(a)). 끝내는 것은 사람이다 — `0. 그만두기` 또는 Ctrl+C 두 번. 터미널이
            // 아니면 지금까지처럼 작업 하나로 끝난다(불변식 I7).
            let session = guided::interactive();
            if session {
                term::arm();
            }
            let mut last: Option<Code> = None;
            loop {
                let picked = guided::run(EMBEDDED_ANCHOR);
                match picked {
                    // 하위 화면의 `0` — 메뉴를 다시 보인다.
                    guided::Outcome::Back => continue,
                    // **사람이 그만둔 것은 0 이다** (결정 8 · 2026-10-30 확정) — 이 세션에서
                    // 작업을 했으면 마지막 작업의 코드다. 그만두기를 고른 사람의 창은
                    // 붙잡지 않는다: 끝내기를 고른 것이다.
                    guided::Outcome::Stopped | guided::Outcome::End => {
                        break Ok(last.unwrap_or(Code::NoThreat));
                    }
                    _ => {}
                }
                let ends_here = matches!(
                    picked,
                    guided::Outcome::ShowUsage
                        | guided::Outcome::NoRulesHere
                        | guided::Outcome::NothingUsable
                );
                if !ends_here {
                    term::task_begin(changes_system(&picked));
                }
                let flow = flow_of(&picked);
                // 찾기만 하는 룰이면 치료를 말하지 않는다 — 모두 검사만은 끝난 뒤에 정한다.
                let mut treats = treats_of(&picked);
                // 그때 가리킬 받은 폴더 안의 기록 — 모두 검사만은 찾은 룰의 것으로 끝난 뒤에 정한다.
                let mut notes = notes_of(&picked);
                // *다음 할 일* 의 앞줄 — 모두 검사만 · 찾은 것 모두 치료하기가 끝난 뒤에 정한다.
                let mut lead: Vec<String> = Vec::new();
                // *다음 할 일* 의 끝줄 — 찾은 것을 다루는 줄(치료 둘 · 읽을 기록) 뒤에 선다. 빠른 검사 뒤의 정밀 검사 줄.
                let mut tail: Vec<String> = Vec::new();
                // **찾은 것 모두 치료하기의 목록은 기계를 바꾸는 작업이 돌면 비운다** — 그 목록은 지난
                // 화면의 것이다. 그 줄 자신은 끝난 뒤 스스로 정한다(승인을 거절하면 다시 고를 수 있게 둔다).
                if changes_system(&picked) && !matches!(flow, Flow::TreatAll) {
                    guided::set_found(Vec::new(), Vec::new());
                }
                // **하기 전에 무엇을 하는지** — 치료 · 복원은 목록과 승인이 그 자리다.
                // 검사만 그것이 없었다(목표 remedy_제품화 기준 6(a)).
                if session && matches!(flow, Flow::Scan) {
                    outln!(
                        "{}",
                        if treats {
                            ui().lang.t(
                                "검사만 합니다 — 아무것도 바꾸지 않습니다. 찾으면 치료할 계획을 세워 둡니다.",
                                "Scan only — nothing is changed. If something is found, a treatment plan is kept."
                            )
                        } else {
                            ui().lang.t(
                                "검사만 합니다 — 아무것도 바꾸지 않습니다.",
                                "Scan only — nothing is changed.",
                            )
                        }
                    );
                }
                let outcome = match picked {
                    guided::Outcome::ShowUsage => {
                        usage(false);
                        Ok(Code::NoThreat)
                    }
                    // 할 일은 안내 모드가 이미 말했다 — 사용법 스무 줄을 덧붙이지 않는다. 종료 코드는 사용법과 같다.
                    guided::Outcome::NoRulesHere => Ok(Code::NoThreat),
                    // **0 으로 끝내지 않는다.** 꾸러미가 있는데 하나도 못 썼다면
                    // 검사를 한 적이 없는 것이고, 0 은 "이 PC 는 깨끗하다" 로 읽힌다.
                    guided::Outcome::NothingUsable => Ok(Code::GuardStop),
                    // **사람이 그만둔 것은 0 이다** (결정 8 · 2026-10-30 확정).
                    //
                    // 전에는 바로 위 `NothingUsable` 과 같은 결로 2(발견·미치료)를
                    // 냈다. 그러나 그 둘은 다르다 — `NothingUsable` 은 **도구가**
                    // 검사하지 못한 것이고, 여기는 **사람이** 검사하지 않기로 한
                    // 것이다. 화면이 *"아무것도 하지 않았습니다"* 라고 말하고 그
                    // 사람이 그것을 읽었다.
                    //
                    // `Stopped` 가 오는 자리는 둘뿐이고 **둘 다 검사 전**이다 —
                    // 룰을 고르는 화면(`guided::choose`)과 작업 메뉴(`menu::run`,
                    // 회차·파일 하위 화면 포함). 꾸러미를 찾고 **치료 승인을
                    // 거절한** 자리는 이 갈래가 아니라 `approved()` 를 지나 2 로
                    // 끝난다 — 그쪽은 검사를 했고 발견한 것이 남아 있다.
                    //
                    // 새 종료 코드를 만들지 않는다 — 불변식 I3.
                    //
                    // 세 갈래는 위에서 이미 돌아갔다 — 여기 오지 않는다.
                    guided::Outcome::Stopped | guided::Outcome::Back | guided::Outcome::End => {
                        Ok(last.unwrap_or(Code::NoThreat))
                    }
                    // **`run` 과 같은 문을 지난다.** 안내 모드가 자기 권한 검사나
                    // 자기 화면을 갖지 않는 이유다 — 두 벌이 되면 갈라지고,
                    // 갈라지면 이 경로로 들어온 사람만 다른 판정을 받는다.
                    guided::Outcome::RunWith(plugin) => {
                        let args =
                            vec!["--plugin".to_string(), plugin.to_string_lossy().to_string()];
                        match network_rule(&args) {
                            // **네트워크 점검 룰은 이 길에서 돌지 않는다.** 여기는 물어볼 수 없는
                            // 자리(터미널이 아니다)인데 그 점검은 주소를 받아야 돈다. 관리자 문을
                            // 먼저 세우지 않는다 — 그 문에 막히면 권한이 모자란 것으로 읽히는데
                            // 이 점검에는 권한이 필요 없다. 명령줄에서 `--url` 을 빠뜨린 것과 같은 4 다.
                            Some(_) => Err(Failure::from(ui().lang.pick(
                                format!(
                                    "이 점검은 네트워크로 합니다 — 점검할 주소를 받아야 해서 여기서는 \
                                     돌리지 않았습니다 (터미널이 아닙니다).\n  \
                                     터미널에서 remedy 를 띄워 메뉴에서 고르거나, \
                                     remedy scan --plugin {} --out-dir <폴더> --url <주소> 로 실행하십시오.",
                                    args[1]
                                ),
                                format!(
                                    "This check uses the network — it needs the addresses to check, so it \
                                     was not run here (not a terminal).\n  \
                                     Start remedy in a terminal and pick it from the menu, or run \
                                     remedy scan --plugin {} --out-dir <folder> --url <address>.",
                                    args[1]
                                ),
                            ))),
                            None => admin_gate()
                                .and_then(|()| integrity_gate(&integrity))
                                .and_then(|()| cmd_run(&args, &integrity)),
                        }
                    }
                    // **모두 검사만** — 관리자 문을 한 번 지나고, 룰마다 메뉴의 *검사만 하기* 와
                    // 같은 `scan` 을 부른다(`scan_all`).
                    guided::Outcome::ScanAll(list, skipped, kind) => admin_gate().map(|()| {
                        let done = scan_all(&list, &skipped, kind);
                        treats = !done.treat.is_empty();
                        notes = done.notes;
                        // 고르는 화면이 *찾은 것 모두 치료하기* 를 세우는 근거 — 그 줄의 번호를 앞줄이 센다.
                        guided::set_found(done.treat, done.other);
                        lead = scan_all_lead(done.code, treats, guided::treat_all_line());
                        // 빠른 검사가 디스크 전체 룰을 뺐으면 정밀 검사 줄을 가리킨다 — 뺀 것을 말하고 그리로 가는
                        // 길까지 준다(목표 remedy_기본검사_룰관리 결정 ①). 끝줄이다 — 찾은 것을 다루는 줄(모두 치료 ·
                        // 하나씩 치료)이 서로 붙어 먼저 서야 한다(리눅스 메뉴 하네스 화면 · 2026-11-16).
                        let disk = skipped.iter().any(|(_, w)| *w == guided::Skip::FullDisk);
                        if kind == guided::ScanKind::Quick && disk {
                            if let Some((n, label)) = guided::full_scan_line() {
                                tail.push(step_line(
                                    ui().lang
                                        .t("디스크 전체까지 보려면", "To look at whole disks too"),
                                    None,
                                    n,
                                    &label,
                                    remedy_sdk::i18n::deco(),
                                ));
                            }
                        }
                        done.code
                    }),
                    // **찾은 것 모두 치료하기** — `run` 과 같은 두 문(관리자 · 자기무결성)을 한 번 지나고,
                    // 룰마다 *검사하고 치료하기* 와 같은 길을 지난다(`treat_all`).
                    guided::Outcome::TreatAll(treat, other) => admin_gate()
                        .and_then(|()| integrity_gate(&integrity))
                        .map(|()| {
                            let done = treat_all(&treat, &other, &integrity);
                            notes = done.notes;
                            lead = done.lead;
                            done.code
                        }),
                    // **묶음 A — 같은 자리로 보낸다.** 위 `Some("selftest")` 갈래와
                    // 똑같은 호출이다. 메뉴가 자기 화면이나 자기 가드를 갖지 않는
                    // 이유는 `RunWith` 와 같다 — 두 벌이 되면 갈라지고, 갈라지면
                    // 메뉴로 들어온 사람만 다른 답을 받는다.
                    guided::Outcome::Plain(p) => match p {
                        menu::Plain::SelfTest => Ok(selftest()),
                        menu::Plain::Version => {
                            print_version();
                            Ok(Code::NoThreat)
                        }
                        menu::Plain::Help => {
                            usage(false);
                            Ok(Code::NoThreat)
                        }
                        menu::Plain::HelpAll => {
                            usage_all();
                            Ok(Code::NoThreat)
                        }
                        // `restore --list` 는 기계를 만지는 명령이라 관리자 문을
                        // 지난다 — `Some("restore")` 갈래와 같다.
                        //
                        // **두 자리를 다 보인다** (결정 3 · 2026-10-30). 한 자리만
                        // 보이면 그 기계에 전부터 쌓인 격리물이 메뉴에서 사라지고,
                        // 사용자는 복원할 수 없다고 믿는다(멈출 조건 5). 없는
                        // 폴더는 건너뛴다 — "회차가 없습니다" 를 두 번 찍지 않는다.
                        menu::Plain::RestoreList => admin_gate().and_then(|()| {
                            let mut last = Ok(Code::NoThreat);
                            for d in menu_state_dirs() {
                                if !d.exists() {
                                    continue;
                                }
                                let args = vec![
                                    "--list".to_string(),
                                    "--state-dir".to_string(),
                                    d.to_string_lossy().to_string(),
                                ];
                                last = cmd_restore(&args);
                                if last.is_err() {
                                    break;
                                }
                            }
                            last
                        }),
                    },
                    // **묶음 B — 고른 플러그인으로 같은 명령으로 보낸다.**
                    //
                    // `scan` 은 `--out-dir` 이 필수다. 메뉴 경로에서는 **실행 파일
                    // 옆의 `out\`** 을 쓴다 — 명령줄의 기본값은 건드리지 않으므로
                    // 불변식 I1 과 부딪치지 않는다(목표 `remedy_cli` 결정 3·4).
                    guided::Outcome::WithPlugin(w) => match w {
                        menu::WithPlugin::Run(p) => {
                            let args = vec![
                                "--plugin".to_string(),
                                p.to_string_lossy().to_string(),
                                "--out-dir".to_string(),
                                menu_out().to_string_lossy().to_string(),
                                "--state-dir".to_string(),
                                menu_state().to_string_lossy().to_string(),
                            ];
                            admin_gate()
                                .and_then(|()| integrity_gate(&integrity))
                                .and_then(|()| cmd_run(&args, &integrity))
                        }
                        menu::WithPlugin::Scan(p) => {
                            let args = vec![
                                "--plugin".to_string(),
                                p.to_string_lossy().to_string(),
                                "--out-dir".to_string(),
                                menu_out().to_string_lossy().to_string(),
                                "--state-dir".to_string(),
                                menu_state().to_string_lossy().to_string(),
                            ];
                            admin_gate().and_then(|()| cmd_scan(&args))
                        }
                        menu::WithPlugin::Verify(p) => {
                            let args = vec![
                                "--plugin".to_string(),
                                p.to_string_lossy().to_string(),
                                "--state-dir".to_string(),
                                menu_state().to_string_lossy().to_string(),
                            ];
                            admin_gate().and_then(|()| cmd_verify(&args))
                        }
                        // 작성자용 둘은 **준 파일만 만지므로** 관리자 문을 지나지
                        // 않는다 — 위 `Some("plugin")` 갈래와 같다.
                        menu::WithPlugin::Lint(p) => {
                            cmd_plugin_lint(&[p.to_string_lossy().to_string()])
                        }
                        menu::WithPlugin::VerifyBundle(p) => {
                            let dir = p.parent().unwrap_or(&p).to_path_buf();
                            let args = vec!["--dir".to_string(), dir.to_string_lossy().to_string()];
                            cmd_plugin_verify(&args)
                        }
                        // **네트워크 점검 — 관리자 문을 지나지 않는다.** 이 기계를 만지지 않고, 본체가
                        // 하는 일은 서명을 확인한 동반 프로그램을 띄우고 그 종료 코드를 받는 것이다.
                        // 주소는 그 프로그램이 묻는다. 결과 폴더는 다른 메뉴 작업과 같은 자리다.
                        menu::WithPlugin::NetCheck(p) => load_manifest(&p.to_string_lossy())
                            .map_err(Failure::from)
                            .and_then(|m| {
                                m.network.ok_or_else(|| {
                                    Failure::from(ui().lang.t(
                                        "이 룰은 네트워크 점검 룰이 아닙니다",
                                        "this rule is not a network check",
                                    ))
                                })
                            })
                            .and_then(|kind| {
                                net::check(kind, &menu_out(), net::Targets::Ask, EMBEDDED_ANCHOR)
                            }),
                    },
                    // **수집만** — 입력이 없고 결과 파일은 여기서 정한다.
                    // `collect` 는 `--out <파일>` 이 필수다(폴더가 아니다). 무엇을 볼지는
                    // 플러그인이 정하므로 `--plugin` 도 넘긴다 — 빠졌던 동안 이 줄은 늘
                    // 입력 오류(4)로 끝났다(랩 메뉴 하네스 · 2026-11-06).
                    guided::Outcome::Collect(p) => {
                        let out = menu_out();
                        let args = vec![
                            "--plugin".to_string(),
                            p.to_string_lossy().to_string(),
                            "--out".to_string(),
                            out.join("artifacts.json").to_string_lossy().to_string(),
                            "--state-dir".to_string(),
                            menu_state().to_string_lossy().to_string(),
                        ];
                        make_out(&out)
                            .and_then(|()| admin_gate())
                            .and_then(|()| cmd_collect(&args))
                    }
                    // **묶음 D·E — 고른 파일을 같은 명령으로 보낸다.** 위
                    // `Some("apply")`·`Some("evaluate")`·`Some("plan")`·
                    // `Some("allowlist")`·`Some("revocation")` 갈래와 같은 함수다.
                    //
                    // 플러그인이 드는 셋(`apply`·`evaluate`·`plan`)은 메뉴가
                    // 플러그인을 고를 수 있을 때만 줄을 냈으므로 여기서 다시
                    // 비어 있을 수 없다 — 그래도 `ok_or_else` 로 말하고 끝낸다.
                    guided::Outcome::WithFile(w, guided_plugin) => {
                        let plugin = || -> Result<String, Failure> {
                            guided_plugin
                                .clone()
                                .map(|p| p.to_string_lossy().to_string())
                                .ok_or_else(|| {
                                    Failure::from(ui().lang.t(
                                        "이 명령에는 룰 파일이 필요합니다",
                                        "this command needs a rule file",
                                    ))
                                })
                        };
                        let out = menu_out();
                        match w {
                            menu::WithFile::Apply(f) => plugin().and_then(|p| {
                                let args = vec![
                                    "--plan".to_string(),
                                    f.to_string_lossy().to_string(),
                                    "--plugin".to_string(),
                                    p,
                                    "--state-dir".to_string(),
                                    menu_state().to_string_lossy().to_string(),
                                ];
                                admin_gate()
                                    .and_then(|()| integrity_gate(&integrity))
                                    .and_then(|()| cmd_apply(&args, &integrity))
                            }),
                            menu::WithFile::Evaluate(f) => plugin().and_then(|p| {
                                let args = vec![
                                    "--artifacts".to_string(),
                                    f.to_string_lossy().to_string(),
                                    "--plugin".to_string(),
                                    p,
                                    "--out".to_string(),
                                    out.join("scan.json").to_string_lossy().to_string(),
                                    "--state-dir".to_string(),
                                    menu_state().to_string_lossy().to_string(),
                                ];
                                // 결과 폴더를 먼저 짓는다 — 없으면 쓰기가 실패해
                                // 입력 오류(4)로 끝났다(랩 메뉴 하네스 · 2026-11-06).
                                make_out(&out).and_then(|()| cmd_evaluate(&args))
                            }),
                            menu::WithFile::Plan(f) => plugin().and_then(|p| {
                                let args = vec![
                                    "--scan".to_string(),
                                    f.to_string_lossy().to_string(),
                                    "--plugin".to_string(),
                                    p,
                                    "--out".to_string(),
                                    out.join("plan.json").to_string_lossy().to_string(),
                                    "--state-dir".to_string(),
                                    menu_state().to_string_lossy().to_string(),
                                ];
                                make_out(&out).and_then(|()| cmd_plan(&args))
                            }),
                            // 목록 넷은 플러그인이 들지 않는다. `verify` 는 읽기만
                            // 하고 `import` 는 복원 정보 폴더에 쓴다 — 그래서
                            // `import` 만 관리자 문을 지난다(명령줄과 같다).
                            menu::WithFile::AllowVerify(f) => cmd_allowlist_verify(&file_arg(&f)),
                            menu::WithFile::AllowImport(f) => {
                                admin_gate().and_then(|()| cmd_allowlist_import(&imported(&f)))
                            }
                            menu::WithFile::RevokeVerify(f) => cmd_revocation_verify(&file_arg(&f)),
                            menu::WithFile::RevokeImport(f) => {
                                admin_gate().and_then(|()| cmd_revocation_import(&imported(&f)))
                            }
                        }
                    }
                    // **묶음 C — 회차를 골라 같은 명령으로 보낸다.** 위
                    // `Some("restore")`·`Some("support-bundle")`·`Some("resume")`
                    // 갈래와 **같은 문·같은 함수**다. 계획을 보이고 승인을 받는
                    // 자리를 메뉴가 건너뛰지 않는다.
                    guided::Outcome::WithRun(w) => match w {
                        // **두 걸음을 걷는다 — 사람이 하는 것과 같은 순서다.**
                        // 먼저 `--yes` 없이 불러 목록을 보이고(종료 2), 그 목록을
                        // 보고 나서 묻고, `예` 면 `--yes` 로 한 번 더 부른다.
                        // 까닭은 [`confirm_restore`] 의 주석에 있다 — 명령의
                        // 화면은 한 글자도 바뀌지 않는다.
                        menu::WithRun::Restore(r) => {
                            let id = r.id.clone();
                            let state = r.state.to_string_lossy().to_string();
                            let plan = vec![
                                "--run".to_string(),
                                id.clone(),
                                "--state-dir".to_string(),
                                state.clone(),
                            ];
                            admin_gate()
                                .and_then(|()| cmd_restore(&plan))
                                .and_then(|code| {
                                    if !matches!(code, Code::FoundNotRemediated)
                                        || !confirm_restore()
                                    {
                                        return Ok(code);
                                    }
                                    let go = vec![
                                        "--run".to_string(),
                                        id,
                                        "--state-dir".to_string(),
                                        state,
                                        "--yes".to_string(),
                                    ];
                                    cmd_restore(&go)
                                })
                        }
                        // 신고는 자기무결성 문을 지나지 않는다 — 위 갈래와 같다.
                        //
                        // **`--out` 을 반드시 준다.** 주지 않으면 기본값이 `.`(현재
                        // 폴더)이고, 더블클릭으로 띄운 경로에서 그 자리는 사람이
                        // 짐작할 수 없다. `scan` 이 `menu_out()` 을 쓰는 것과
                        // 같은 규칙을 지킨다 — **한 메뉴 안에서 폴더 규칙이 갈리면
                        // 안 된다**(2026-10-29 재검토에서 갈려 있던 자리다).
                        menu::WithRun::Support(r) => {
                            let args = vec![
                                "--run".to_string(),
                                r.id,
                                "--state-dir".to_string(),
                                r.state.to_string_lossy().to_string(),
                                "--out".to_string(),
                                beside_exe("report").to_string_lossy().to_string(),
                            ];
                            cmd_support_bundle(&args)
                        }
                        menu::WithRun::Resume(r) => {
                            let args = vec![
                                "--run".to_string(),
                                r.id,
                                "--state-dir".to_string(),
                                r.state.to_string_lossy().to_string(),
                            ];
                            admin_gate()
                                .and_then(|()| integrity_gate(&integrity))
                                .and_then(|()| cmd_resume(&args, &integrity))
                        }
                    },
                };
                let code = match &outcome {
                    Ok(c) => *c,
                    Err(f) => f.code,
                };
                if let Err(f) = &outcome {
                    let lang = ui().lang;
                    errln!("{}: {}", lang.t("실패", "Error"), f.message);
                    // 메뉴 앞의 사람에게 종료 코드의 뜻 목록(상한 초과 · 보호 경로 · 서명 …)은 이 실패와 상관없는
                    // 까닭까지 늘어놓는다 — 번호만 적는다. 무인 배포가 읽는 뜻은 명령줄 실행이 그대로 적는다.
                    if session {
                        errln!("  ({} {})", lang.t("종료 코드", "exit code"), f.code.code());
                    } else {
                        errln!(
                            "  ({} {}: {})",
                            lang.t("종료 코드", "exit code"),
                            f.code.code(),
                            f.code.meaning_in(lang)
                        );
                    }
                }
                if ends_here || !session {
                    wait_before_closing();
                    break Ok(code);
                }
                // 작업 하나가 끝났다 — 로그를 닫고 메뉴로 돌아간다.
                tee::close();
                term::task_end(code);
                last = Some(code);
                back_to_menu(flow, code, treats, &notes, &lead, &tail);
            }
        }
        Some(other) => {
            errln!(
                "{}: {other}",
                ui().lang.t("알 수 없는 명령", "Unknown command")
            );
            // **여기 사용법은 오류의 일부다.** stdout 으로 보내면 무인 배포의
            // 파이프에 오류 본문이 섞인다.
            usage(true);
            Ok(Code::UsageError)
        }
    };

    match outcome {
        Ok(c) => ExitCode::from(c.code()),
        Err(f) => {
            // **무슨 종류의 실패인지는 언제나 읽힌다.** 사유가 아직 한국어인
            // 자리가 남아 있어도 프레임과 종료 코드 의미는 두 언어다.
            let lang = ui().lang;
            errln!("{}: {}", lang.t("실패", "Error"), f.message);
            errln!(
                "  ({} {}: {})",
                lang.t("종료 코드", "exit code"),
                f.code.code(),
                f.code.meaning_in(lang)
            );
            ExitCode::from(f.code.code())
        }
    }
}

/// 실패와 **그 실패가 나가야 할 종료 코드**.
///
/// 전부 사용법 오류로 뭉뚱그리면 무인 배포가 "가드가 막았다"(5)와 "내가 잘못
/// 불렀다"(4)를 구분하지 못한다. 둘은 완전히 다른 후속 조치를 요구한다.
struct Failure {
    code: Code,
    message: String,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            code: Code::UsageError,
            message,
        }
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        Failure::from(message.to_string())
    }
}

impl From<remedy_core::PipelineError> for Failure {
    fn from(e: remedy_core::PipelineError) -> Self {
        Self {
            code: e.exit_code(),
            message: e.to_string(),
        }
    }
}

/// 파괴 명령 앞의 문. 열려 있지 않으면 사유와 함께 멈춘다.
///
/// **`restore` 에는 걸지 않는다.** 복원은 파괴가 아니라 그 반대이고, 설계-03
/// §11 이 사고 대응 순서에 *"`remedy restore` 를 이용한 복구 안내 배포"* 를
/// 두었다. 변조된 바이너리로 복구하는 위험보다 **복구할 길이 끊기는 위험이
/// 크다** — 게다가 복원은 격리 컨테이너에 담긴 것을 되돌리는 것이지 임의
/// 쓰기가 아니다.
///
/// `resume` 은 파괴를 이어 하는 것이므로 걸린다.
/// 시험용 되돌림 — **배포되는 바이너리에는 없다.**
///
/// 배포물은 `cargo build --release` 로 만들어지고(`docs/operator.md` §9 의
/// 조립 차례), 거기서 `debug_assertions` 는 꺼진다.
/// 그러므로 이 문은 고객에게 가는 물건에 **존재하지 않는다** — 런타임 검사가
/// 아니라 컴파일 시점에 사라진다.
///
/// # 왜 두는가
///
/// CLI 통합 시험 60여 건이 진짜 바이너리를 띄워 `apply` · `scan` 을 **실험실
/// 폴더**에 대고 돌린다. 그 시험들은 이 기계를 고치는 것이 아니라 우리 코드를
/// 재는 것이다. 그것 때문에 개발자에게 관리자 셸을 요구하면, 요구가 지켜지지
/// 않는 날 시험이 통째로 빨개지고 사람은 시험을 끄게 된다.
///
/// **양방향인 이유**: 거절 자체를 재는 시험도 있어야 한다. 한쪽만 있으면 그
/// 시험의 결과가 *누가 돌렸는가* 에 따라 달라진다 — 재현되지 않는 시험은
/// 시험이 아니다.
///
/// `Some(_)` 은 "이 값으로 하라", `None` 은 "되돌림 없음 — 실제로 재라" 다.
#[cfg(debug_assertions)]
fn elevation_override() -> Option<bool> {
    match std::env::var("REMEDY_ELEVATION").ok()?.as_str() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

#[cfg(not(debug_assertions))]
fn elevation_override() -> Option<bool> {
    None
}

/// 권한이 모자랄 때 하는 말. **한 문장으로 무엇을 하라고 말한다.**
///
/// 고객이 가장 먼저 만나는 벽이다. 두 언어다. "관리자 권한이 필요합니다" 는
/// 시험이 읽는 문구다.
fn need_admin() -> String {
    let lang = ui().lang;
    // 화살표는 **장식**이다 — 언어가 아니라 터미널이 정한다. 앞서 한국어는 `→`,
    // 영어는 `->` 를 문자열에 박고 있어 같은 콘솔에서 둘이 달랐다 (실측 2026-09-07).
    let arrow = remedy_sdk::i18n::deco().arrow();
    let (why, how) = if cfg!(windows) {
        (
            // 한 문장이면 된다 — 예약 작업 · 레지스트리 · 다른 사용자의 파일은 관리자만 연다. 그것을 못 열면
            // 감염된 기계에서도 찾는 것이 없다는 까닭은 README 와 운영자 안내가 적는다(목표 remedy_시연전_안정화 A12).
            lang.t(
                "관리자 권한이 필요합니다 — 예약 작업 · 레지스트리 · 다른 사용자의 파일은 관리자만 열 수 있습니다.",
                "Administrator rights are required: scheduled tasks, the registry and other users' files\n  \
                 open only to an administrator.",
            ),
            // **하는 법까지 적는다.** 이 화면을 읽는 사람이 관리자 창을
            // 여는 법을 안다는 보장이 없다. 여기서 막히면 이 도구는 그 PC
            // 에서 한 번도 돌지 못한다.
            //
            // **우클릭이 먼저다** (2026-09-09). 앞서 이 자리는 "관리자 창을
            // 열고 다시 부를 것" 만 적었고, 실행 파일 우클릭은 *"인자 없이
            // 뜨면 사용법을 찍고 곧바로 닫히므로 아직 참이 아니다"* 라며
            // 미뤄 두었다. 안내 모드(`guided`)와 창 유지(`wait_before_closing`)
            // 가 서면서 그 조건이 충족됐다.
            //
            // 미룬 것을 되짚어 보니 순서까지 틀려 있었다. **이 화면을 보는
            // 사람의 다수는 아무 명령도 치지 않았다** — 꾸러미를 옆에 두고
            // 더블클릭하면 안내 모드가 열리고, 그 안에서 이 문이 닫힌다
            // (실측 2026-09-09: 서명 통과 → `admin_gate` 거절 → 창 유지).
            // 그에게 "명령 창을 열고 다시 부르라" 는 **따를 수 없는 처방**
            // 이다. 경로도 인자도 그가 친 적이 없기 때문이다.
            //
            // 실행 파일 이름은 박아 두지 않고 읽는다. 받는 사람이 화면에서
            // 보는 이름과 같아야 "그 파일" 을 집는다.
            {
                let exe = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "remedy.exe".to_string());
                lang.t(
                    concat!(
                        "{exe}{eul} 마우스 오른쪽 단추로 누르고 '관리자 권한으로 실행' 을 고르십시오.\n",
                        "     명령 창에서 부르는 중이라면 시작 단추를 오른쪽 단추로 누르고\n",
                        "     '터미널(관리자)' 또는 'Windows PowerShell(관리자)' 로 창을 연 뒤 다시 부르십시오.",
                    ),
                    concat!(
                        "Right-click {exe} and choose 'Run as administrator'.\n",
                        "     If you are calling it from a command window, right-click the Start\n",
                        "     button, choose 'Terminal (Admin)' or 'Windows PowerShell (Admin)',\n",
                        "     and run again.",
                    ),
                )
                // 조사는 파일 이름의 끝소리로 고른다 — `remedy.exe 를`. 영어 문장에는
                // `{eul}` 이 없어 그대로다.
                .replace(
                    "{eul}",
                    remedy_sdk::i18n::particle(&exe, " 을", " 를"),
                )
                .replace("{exe}", &exe)
            },
        )
    } else {
        (
            lang.t(
                "root 권한이 필요합니다 — 시스템 전역의 자동 실행 · 설정은 root 만 열 수 있습니다.",
                "root is required: system-wide autostart entries and configuration open only to root.",
            ),
            lang.t(
                "sudo ./remedy 처럼 sudo 로 다시 실행하십시오.",
                "Run again with sudo, e.g. sudo ./remedy.",
            )
            .to_string(),
        )
    };
    format!("{why}\n  {arrow} {how}")
}

/// **기계를 만지는 명령은 관리자를 요구한다** (설계-00 §5).
///
/// # 왜 반쯤 도는 것보다 거절이 나은가
///
/// 권한 없이 돌면 예약 작업 디렉터리를 열지 못한다. 그러면 감염된 기계에서
/// **증거 0건**이 나온다. 실측(2026-08-31, 감염된 실기기): 표준 사용자로
/// `scan` → 증거 0 · 판정 0 · `exit 6`.
///
/// `exit 6` 이 나오는 것 자체는 옳다 — 그 자리에서도 **"위협 없음" 이라고 말하지
/// 않는다.** 그러나 그것은 마지막 방어선이지 첫 줄이 아니다. 할 수 없는 일이면
/// **시작하기 전에** 한 문장으로 말하는 편이 낫다.
///
/// # 무엇에 걸고 무엇에 걸지 않는가
///
/// 경계는 하나다 — **이 명령이 기계를 만지는가.**
///
/// - **건다**: `collect` · `scan` · `run` · `apply` · `resume` · `restore` ·
///   `verify`. 전부 이 기계를 읽거나 쓴다.
/// - **걸지 않는다**: `evaluate` · `plan` · `plugin lint`/`verify` ·
///   `revocation`/`allowlist` 의 `verify` · `support-bundle` · `selftest` ·
///   `--version`. 이것들은 **명령줄로 받은 파일만** 만진다. 분석가가 사내에서
///   스냅샷으로 룰을 만드는 자리(설계-00 §5)와 룰 작성자가 자기 PC 에서
///   `plugin lint` 를 돌리는 자리가 거기다 — 관리자를 요구하면 그 두 흐름이
///   통째로 막힌다. `revocation import` · `allowlist import` 는 상태 디렉터리에
///   쓰지만 그것은 우리 폴더이지 기계가 아니다.
///
/// # 관리자라고 다 되는 것은 아니다
///
/// 이 문을 지나도 못 하는 일이 남는다 — 변조 방지가 막는 Defender 예외,
/// `TrustedInstaller` 소유 키, 보호 프로세스의 명령줄(실측 2026-08-31: 관리자
/// 세션에서 159개 중 19개를 읽지 못했다). **그래서 이 문이 관측 완전성 보고를
/// 대신하지 않는다.** 둘 다 있어야 한다.
fn admin_gate() -> Result<(), Failure> {
    // 되돌림이 있으면 그것을, 없으면 실제로 잰 값을. 되돌림은 배포물에 없다.
    let elevated = match elevation_override() {
        Some(forced) => {
            // **조용히 지나가지 않는다.** 무엇 때문에 이 문이 열렸는지 남는다.
            errln!(
        "{}",
        ui().lang.t(
            "알림: REMEDY_ELEVATION 이 권한 검사를 대신했습니다 (개발 빌드 전용)",
            "Notice: REMEDY_ELEVATION replaced the privilege check (development builds only)"
        )
    );
            Some(forced)
        }
        None => remedy_core::elevated(),
    };
    match elevated {
        Some(true) => Ok(()),
        // **가드 중단이지 사용법 오류가 아니다.** 명령은 옳고 환경이 모자란다 —
        // 무인 배포에서 둘은 완전히 다른 후속 조치를 요구한다.
        Some(false) => Err(Failure {
            code: Code::GuardStop,
            message: need_admin(),
        }),
        None => Err(Failure {
            code: Code::GuardStop,
            message: "권한을 확인하지 못했습니다 — 모르는 것을 '괜찮다' 로 접지 않습니다.\n  \
                      이 기계에서 무엇이 막고 있는지 확인하십시오."
                .to_string(),
        }),
    }
}

fn integrity_gate(i: &remedy_core::integrity::SelfIntegrity) -> Result<(), Failure> {
    match remedy_core::integrity::stance(i) {
        remedy_core::integrity::Stance::Full => Ok(()),
        remedy_core::integrity::Stance::ReadOnly { why } => Err(Failure {
            // **가드 중단이지 사용법 오류가 아니다.** 무인 배포에서 둘은 완전히
            // 다른 후속 조치를 요구한다.
            code: Code::GuardStop,
            message: why,
        }),
    }
}

/// `--key value` 만 받는다. P2 에 필요한 최소한이다.
struct Args {
    single: std::collections::BTreeMap<String, String>,
    multi: std::collections::BTreeMap<String, Vec<String>>,
}

/// 하위 명령이 받는 옵션 — `--help-all` 이 적은 것 전부. **모르는 옵션은 거절한다**(종료 4): 전에는 조용히
/// 받아 `run --plugin p --dryrun --yes` 의 오타가 진짜 치료가 됐다(목표 remedy_시연전_안정화 · 기술부채 검토 1-6).
/// 전역 옵션(`--lang` · `--ascii` · `--verbose`)은 `split_global` 이 먼저 걷는다.
const KNOWN_OPTIONS: &[&str] = &[
    "artifacts",
    "cacert",
    "config",
    "consent",
    "container",
    "dir",
    "dry-run",
    "entry",
    "events",
    "extract-to",
    "file",
    "key",
    "list",
    "org-key-file",
    "org-public-file",
    "out",
    "out-dir",
    "passphrase-file",
    "plan",
    "plugin",
    "public-key",
    "root",
    "run",
    "scan",
    "state-dir",
    "url",
    "yes",
];

/// 값을 받지 않는 스위치 — `has()` 로만 읽힌다. **다음 낱말을 먹지 않는다**: 전에는 다음 낱말이 `--` 로 시작하지
/// 않으면 그것을 값으로 먹어 `--yes false` 가 자동 승인이 됐다. 반대로 값을 받는 옵션 뒤에 `--` 낱말이 오면 빈
/// 값으로 두어, `--state-dir --yes` 가 '주지 않음'(기본 자리)으로 읽혔다.
const SWITCHES: &[&str] = &["dry-run", "list", "yes"];

/// 명령줄 규칙 — **낱말은 모두 `--이름` 이고, 스위치는 홀로, 그 밖의 옵션은 띄어 쓴 값 하나를 받는다.** 값이
/// 없거나 `--` 로 시작하거나 비어 있으면 그 자리에서 거절한다(종료 4). 같은 옵션을 두 번 주면 목록(`list`)에는
/// 둘 다, 하나만 읽는 자리(`get` · `need`)에는 마지막 값이 간다. 거절 문장은 받은 낱말을 [`shown`] 으로 줄여
/// 되풀이한다.
fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut single = std::collections::BTreeMap::new();
    let mut multi: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut i = 0;
    while i < raw.len() {
        let k = raw[i].strip_prefix("--").ok_or_else(|| {
            ui().lang.pick(
                format!("'--이름 값' 형태여야 합니다: {}", shown(&raw[i])),
                format!("expected '--name value', got: {}", shown(&raw[i])),
            )
        })?;
        // `split_global` 이 언어로 먹지 않고 남긴 `--lang` — 뒤가 옵션이었으니 값이 빠진 것이다.
        if k == "lang" {
            return Err(no_value(k));
        }
        if !KNOWN_OPTIONS.contains(&k) {
            return Err(ui().lang.pick(
                format!(
                    "모르는 옵션입니다: {} — 쓸 수 있는 옵션은 remedy --help-all 에 있습니다",
                    shown(&raw[i])
                ),
                format!("unknown option: {} (see remedy --help-all)", shown(&raw[i])),
            ));
        }
        let v = if SWITCHES.contains(&k) {
            i += 1;
            String::new()
        } else {
            match raw.get(i + 1) {
                Some(v) if !v.starts_with("--") && !v.trim().is_empty() => {
                    i += 2;
                    v.clone()
                }
                _ => return Err(no_value(k)),
            }
        };
        multi.entry(k.to_string()).or_default().push(v.clone());
        single.insert(k.to_string(), v);
    }
    Ok(Args { single, multi })
}

/// 값이 빠진 옵션 — 해석 단계와 [`Args::need`] 가 같은 문장을 낸다.
fn no_value(k: &str) -> String {
    ui().lang.pick(
        format!("--{k} 옵션에 값이 없습니다"),
        format!("--{k} has no value"),
    )
}

/// 거절 문장에 되풀이하는 낱말 — `=` 뒤는 값이라 `…` 로 줄이고(비밀이 든 주소 등), 제어 문자는 `?` 로 바꾸고
/// 40자에서 자른다(`remedy_sdk::i18n::plain`).
fn shown(tok: &str) -> String {
    let head = match tok.split_once('=') {
        Some((name, _)) => format!("{name}=…"),
        None => tok.to_string(),
    };
    remedy_sdk::i18n::plain(&head, 40)
}

impl Args {
    fn need(&self, k: &str) -> Result<&str, String> {
        match self.single.get(k).map(String::as_str) {
            Some("") => Err(no_value(k)),
            Some(v) => Ok(v),
            // "옵션이" — 영문 옵션 이름 뒤의 조사를 맞힐 수 없어(`--plan 가`) 우리말
            // 낱말을 하나 두고 그 뒤에 조사를 붙인다.
            None => Err(ui().lang.pick(
                format!("--{k} 옵션이 필요합니다"),
                format!("--{k} is required"),
            )),
        }
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.single
            .get(k)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
    fn has(&self, k: &str) -> bool {
        self.single.contains_key(k)
    }
    fn list(&self, k: &str) -> Vec<String> {
        self.multi.get(k).cloned().unwrap_or_default()
    }
}

/// 첫 화면. 제품명·버전·플러그인 이름·시각·기계.
fn banner(m: Option<&PluginManifest>) {
    let lang = ui().lang;
    let meta = RunMeta::now();
    let name = m.and_then(|m| {
        m.name
            .get(lang.id())
            .or_else(|| m.name.get("en"))
            .or_else(|| m.name.values().next())
            .map(String::as_str)
    });
    let b = remedy_core::report::Banner {
        core_version: env!("CARGO_PKG_VERSION"),
        plugin_name: name,
        plugin_id: m.map(|m| m.id.as_str()),
        plugin_version: m.map(|m| m.version.as_str()),
        started_at: &meta.created,
        hostname: &meta.host.hostname,
        os: &meta.host.os,
    };
    let text = remedy_core::report::render_banner(&b, lang);
    // **메뉴 세션은 작업마다 배너를 그리지 않는다** — 제품 · 버전은 첫 화면 머리말이 말했고, 그 작업의 이름은 고른
    // 사람이 안다. 시각(UTC) · 기계는 회차 로그와 신고 묶음의 `run.log` 에 그대로 남는다(목표 remedy_시연전_안정화
    // D5 · 처음 쓰는 사람 검토 — 빠른 검사에서 룰마다 같은 배너가 여덟 번 섰다). 명령줄 출력은 지금 그대로다.
    if term::in_session() {
        tee::log_only(|| out!("{text}"));
    } else {
        out!("{text}");
    }
    outln!();
}

/// 시작한 뒤 지난 시간. 마무리 화면이 적는다.
fn elapsed_since(start: std::time::Instant) -> u64 {
    start.elapsed().as_secs()
}

/// 마무리 화면 — 메뉴 세션은 결과 한 줄([`remedy_core::report::render_closing_brief`]), 명령줄은 지금의 표다.
fn closing(c: &remedy_core::report::Closing<'_>, lang: remedy_sdk::i18n::Lang) -> String {
    if term::in_session() {
        remedy_core::report::render_closing_brief(c, lang)
    } else {
        remedy_core::report::render_closing(c, lang)
    }
}

/// 검사가 시작됐다고 말한다.
///
/// **배너 다음이 곧바로 결과였다.** 심장박동은 5초를 넘겨야 나오므로 그보다 빨리
/// 끝나는 회차는 배너 → 침묵 → 결과였고, 화면 앞의 사람에게는 아무 일도 일어나지
/// 않은 것으로 보였다. 치료에는 `치료를 시작합니다.` 가 있었는데 검사에는 짝이
/// 없었다.
fn scan_started() {
    outln!("{}", ui().lang.t("검사를 시작합니다.", "Starting scan."));
}

fn load_manifest(path: &str) -> Result<PluginManifest, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let m: PluginManifest = serde_yaml_ng::from_str(&text).map_err(|e| {
        // 틀린 술어를 이름으로 짚는다 — serde 의 문구만으로는 모르는 연산자가 보이지 않는다.
        let hints = remedy_sdk::lint::schema_hints(&text);
        if hints.is_empty() {
            format!("{path}: {e}")
        } else {
            format!("{path}: {e}\n  {}", hints.join("\n  "))
        }
    })?;

    // 스키마는 통과했지만 의미가 어긋난 것들. 여기서 막지 않으면 결과가 조용히
    // 비어 있고, 작성자는 룰이 안 맞는 이유를 찾느라 시간을 버린다.
    let issues = remedy_sdk::validate(&m);
    let blocking: Vec<_> = issues.iter().filter(|i| i.available_in.is_none()).collect();
    for i in &issues {
        errln!("  주의 {i}");
    }
    if !blocking.is_empty() {
        return Err(format!("매니페스트에 문제 {}건", blocking.len()));
    }
    Ok(m)
}

/// **이 기계를 보는 룰**을 읽는다 — `collect` · `evaluate` · `plan` · `scan` · `run` · `verify` 가 쓴다.
///
/// 네트워크 점검 룰(`network`)은 이 기계에서 모으고 판정할 것이 없다. 그 룰로 이 명령들을 돌리면 빈
/// 결과가 *깨끗함* 으로 읽히므로, 어떻게 돌리는지 말하고 멈춘다(`scan` · `run` 은 `main` 이 먼저
/// 동반 프로그램 쪽으로 보낸다 — 여기 닿는 것은 그 길을 지나지 않은 호출이다).
fn load_local(path: &str) -> Result<PluginManifest, String> {
    let m = load_manifest(path)?;
    // 데이터 룰(코어 1.12.0)은 판정 기준을 담을 뿐 이 기계에서 볼 것이 없다 — 빈 결과가 *깨끗함* 으로
    // 읽히지 않게 무엇인지 말하고 멈춘다.
    if m.kind == Some(PluginKind::Data) {
        return Err(ui().lang.pick(
            format!(
                "이 룰은 동반 프로그램(remedy-net)이 읽는 판정 기준만 담았습니다 — 검사하는 룰이 아닙니다: {path}"
            ),
            format!(
                "This rule only holds the criteria the companion program (remedy-net) reads — it is not a rule that checks anything: {path}"
            ),
        ));
    }
    if m.network.is_some() {
        return Err(ui().lang.pick(
            format!(
                "이 룰은 네트워크로 점검합니다 — 이 명령으로는 돌릴 수 없습니다.\n  \
                 remedy scan --plugin {path} --out-dir <폴더> --url <주소> 로 실행하거나, \
                 인자 없이 띄워 메뉴에서 고르십시오."
            ),
            format!(
                "This rule checks over the network — this command cannot run it.\n  \
                 Use remedy scan --plugin {path} --out-dir <folder> --url <address>, \
                 or start remedy without arguments and pick it from the menu."
            ),
        ));
    }
    Ok(m)
}

/// 이 호출의 `--plugin` 이 네트워크 점검 룰이면 그 종류 — `scan` · `run` 의 갈림길이다.
///
/// 읽지 못하는 것은 여기서 말하지 않는다. 그 까닭은 명령 자신이 지금까지처럼 말한다.
fn network_rule(raw: &[String]) -> Option<remedy_sdk::manifest::NetworkCheck> {
    // 인자 전체가 해석되지 않아도 룰이 무엇인지는 안다 — 마지막 `--plugin <값>` 만 읽는다(`Args` 의 '마지막이
    // 이긴다' 와 같다). 해석 실패로 `None` 을 돌려주면 인자가 틀린 네트워크 점검이 관리자 문(5)으로 떨어지고,
    // 고칠 것을 말하는 해석 오류(4)가 가려진다.
    let plugin = raw.windows(2).rev().find(|w| w[0] == "--plugin")?[1].as_str();
    let text = std::fs::read_to_string(plugin).ok()?;
    serde_yaml_ng::from_str::<PluginManifest>(&text)
        .ok()?
        .network
}

/// 네트워크 점검 룰을 명령줄로 — `scan --plugin <룰> --out-dir <폴더> --url <주소> [--url …]`.
///
/// **관리자 문을 지나지 않는다** — 이 기계를 만지지 않는다. 주소 · 동의(`--consent y|n`) · CA 파일
/// (`--cacert`)은 풀이하지 않고 동반 프로그램에 그대로 넘긴다: 그 꼴을 보는 것은 그 프로그램이다.
fn cmd_net(kind: remedy_sdk::manifest::NetworkCheck, raw: &[String]) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    let m = load_manifest(a.need("plugin")?)?;
    let dir = a.need("out-dir")?;
    // 빈 `--url` 은 해석 단계가 거절한다 — 여기 오는 값은 비어 있지 않다.
    let urls = a.list("url");
    if urls.is_empty() {
        return Err(Failure::from(ui().lang.t(
            "점검할 주소가 필요합니다 — --url <주소> 를 하나 이상 적으십시오 (여러 번 줄 수 있습니다).",
            "an address to check is required — give --url <address> at least once (it can be repeated).",
        )));
    }
    banner(Some(&m));
    net::check(
        kind,
        std::path::Path::new(dir),
        net::Targets::Given {
            urls: &urls,
            consent: a.get("consent"),
            cacert: a.get("cacert"),
        },
        EMBEDDED_ANCHOR,
    )
}

fn write_json<T: serde::Serialize>(path: &str, value: &T) -> Result<(), String> {
    let mut s = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    s.push('\n');
    // BOM 없이 쓴다. serde_json 을 비롯한 파서가 BOM 을 거부한다.
    std::fs::write(path, s.as_bytes()).map_err(|e| format!("{path}: {e}"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
}

// ─────────────────────────────────────────────────────── 명령

fn warn_unsupported(m: &PluginManifest) {
    // 조용히 빈 배열을 담으면 "없다" 와 "못 봤다" 가 구분되지 않는다.
    for (s, phase) in Pipeline::unsupported_subjects(m) {
        let lang = ui().lang;
        errln!(
            "  {} {}",
            lang.t("주의", "Note"),
            lang.pick(
                format!("subject '{}' 의 수집기는 아직 없습니다 ({phase}). 이 대상은 스냅샷에 담기지 않습니다", s.id()),
                format!("no collector for subject '{}' yet ({phase}); it is not in the snapshot", s.id())
            )
        );
    }
}

/// 플러그인 옆의 `rules/*.yar` 을 읽는다.
///
/// 이름은 **플러그인 디렉터리 기준 상대 경로**다. 룰이 `rules/x.yar:name` 으로
/// 참조하므로 그 표기와 같아야 한다 — 절대 경로로 담으면 같은 플러그인이
/// 기계마다 다른 이름을 갖게 되고, 참조가 통째로 어긋난다.
fn load_rules(plugin_path: &str) -> Result<Vec<(String, String)>, Failure> {
    let dir = std::path::Path::new(plugin_path)
        .parent()
        .map(|p| p.join("rules"))
        .unwrap_or_else(|| std::path::PathBuf::from("rules"));
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| Failure::from(format!("{}: {e}", dir.display())))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("yar"))
        })
        .collect();
    // 이름 순으로 고정한다. 순서가 흔들리면 같은 플러그인이 실행마다 다른
    // 컴파일 오류 순서를 낸다.
    entries.sort();
    for path in entries {
        let name = format!(
            "rules/{}",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        let text = std::fs::read_to_string(&path)
            .map_err(|e| Failure::from(format!("{}: {e}", path.display())))?;
        out.push((name, text));
    }
    Ok(out)
}

/// 선언했지만 해소하지 못한 것을 사람에게 말한다.
///
/// `collect_extra` 항목과 펼쳐지지 않은 `scan_roots` 토큰이 함께 온다. 둘 다
/// **"선언한 것을 못 봤다"** 이고, 조용히 지나가면 그 대상에 걸린 룰이 영영
/// 미평가인데 판정은 "안 맞았다" 로 나간다.
///
/// **선언한 자리가 전부 없으면 그 아래를 가리킨 선언은 말하지 않는다** (2026-11-06). 하나도
/// 읽힐 수 없고, 까닭은 검사 끝의 *주의* 줄이 그 자리와 함께 한 번 말한다 — 두 번 말하면 같은
/// 사실이 `collect_extra[0]` · OS 오류 같은 낱말로 먼저 나온다(CWP 가 없는 서버에서 처음 온
/// 사람이 본 화면). 루트 밖을 가리킨 것 · 자리를 알 수 없는 것은 그대로 말한다.
fn warn_unresolved_extra(
    items: &[remedy_core::Unresolved],
    m: &PluginManifest,
    obs: Option<&Observation>,
) {
    let missing: &[String] = obs
        .filter(|o| o.all_roots_missing())
        .map_or(&[], |o| o.missing_roots.as_slice());
    let shown: Vec<&remedy_core::Unresolved> = items
        .iter()
        .filter(|u| !under_missing_root(m, u, missing))
        .collect();
    if shown.is_empty() {
        return;
    }
    let lang = ui().lang;
    errln!();
    errln!(
        "  {} {}",
        lang.t("주의:", "Note:"),
        lang.pick(
            format!("선언한 것 {}건이 해소되지 않았습니다:", shown.len()),
            format!("{} declared item(s) could not be resolved:", shown.len())
        )
    );
    // 룰의 칸 이름(`collect_extra[0]`)은 룰 작성자의 말이다 — `--verbose` 에만 싣는다.
    for u in shown {
        if ui().verbose {
            errln!("     - {}: {}", u.at, u.reason);
        } else {
            errln!("     - {}", u.reason);
        }
    }
}

/// 그 선언(`collect_extra[i]`)이 가리킨 경로가 **없는 루트 아래**인가. 알 수 없으면 거짓이다 —
/// 말하는 쪽으로 기운다.
fn under_missing_root(m: &PluginManifest, u: &remedy_core::Unresolved, missing: &[String]) -> bool {
    let Some(i) =
        u.at.strip_prefix("collect_extra[")
            .and_then(|r| r.strip_suffix(']'))
            .and_then(|n| n.parse::<usize>().ok())
    else {
        return false;
    };
    let path = match m.collect_extra.get(i) {
        Some(remedy_sdk::manifest::CollectExtra::Path(p)) => p.path.as_str(),
        Some(remedy_sdk::manifest::CollectExtra::Glob(g)) => g.glob.as_str(),
        _ => return false,
    };
    missing.iter().any(|root| {
        path.strip_prefix(root.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '\\']))
    })
}

fn cmd_collect(raw: &[String]) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    let out = a.need("out")?;
    let meta = RunMeta::now();

    // 종류는 match 밖으로 꺼낸다 — 아래 종료 코드 갈래가 그것을 본다.
    let mut kind = None;
    let env = match a.single.get("plugin") {
        Some(p) => {
            let m = load_local(p)?;
            kind = m.kind;
            warn_unsupported(&m);
            // `collect` 단독에는 증거가 없다. `ref` 형은 여기서 풀리지 않으므로
            // 그 사실을 지금 보고한다 — `scan`·`run` 은 평가 뒤에 푼다.
            let (env, unresolved) = remedy_core::pipeline::collect_declared(
                &m,
                &meta,
                remedy_core::pipeline::RefPolicy::ReportNow,
            )?;
            warn_unresolved_extra(&unresolved, &m, None);
            env
        }
        None => {
            let roots = a.list("root");
            if roots.is_empty() {
                return Err("--plugin 또는 --root 중 하나는 있어야 합니다".into());
            }
            // 진단 모드 — 플러그인도 룰도 없다.
            remedy_core::collect_only(roots, &meta)?
        }
    };

    write_json(out, &env)?;
    outln!(
        "수집 완료 -> {out}  파일 {} · 지속성 {} · 보안 제품 {}{}",
        env.body
            .observations
            .get("file")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
        env.body
            .observations
            .get("persistence")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
        env.body.security_products.len(),
        if env.body.scope.truncated {
            "  ** 상한 도달 - 잘림"
        } else {
            ""
        }
    );
    // 못 본 것을 없는 것으로 읽으면 안 된다. 수집만 한 실행도 "완전한 스냅샷을
    // 떴다" 와 "절반만 봤다" 를 종료 코드로 구분해야 한다.
    let obs = env.body.observation();
    warn_incomplete(&obs, kind);
    note_not_applicable(&obs, kind, &[]);
    note_skipped_denied(&obs, kind);
    Ok(outcome(&[], &obs, kind))
}

fn cmd_evaluate(raw: &[String]) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    let artifacts = read_json(a.need("artifacts")?)?;
    let m = load_local(a.need("plugin")?)?;
    let out = a.need("out")?;

    let rules = load_rules(a.need("plugin")?)?;
    let scan = remedy_core::pipeline::evaluate_with_rules(&artifacts, &m, &rules)?;
    write_json(out, &scan)?;
    report_scan(&scan, m.kind, m.remediate.is_none());
    Ok(outcome(&scan.body.verdicts, &scan.body.observation, m.kind))
}

/// 설정을 읽는다. **모순된 설정이면 여기서 멈춘다** (설계-03 §4).
///
/// 경로를 주지 않으면 기본값을 쓴다. 기본 경로를 두지 않는 이유는, 암묵적으로
/// 읽히는 설정이 "왜 이 값이 걸렸는가" 를 추적 불가능하게 만들기 때문이다.
fn load_limits(a: &Args) -> Result<remedy_core::Limits, Failure> {
    let Some(path) = a.single.get("config") else {
        return Ok(remedy_core::Limits::default());
    };
    let cfg = remedy_core::Config::load(std::path::Path::new(path))
        .map_err(|e| Failure::from(e.to_string()))?;
    cfg.limits().map_err(|e| Failure::from(e.to_string()))
}

fn cmd_plan(raw: &[String]) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    let limits = load_limits(&a)?;
    let scan = read_json(a.need("scan")?)?;
    let out = a.need("out")?;

    // `remediate` 는 매니페스트에 있고 scan.json 에는 없다 (설계-03 §2).
    // 주지 않으면 가드만 돌고 Action 은 도출되지 않는다 — 그 사실을 말한다.
    let m = match a.get("plugin") {
        Some(p) => Some(load_local(p)?),
        None => {
            errln!("  주의 --plugin 이 없습니다. remediate 를 읽을 수 없어 Action 을 도출하지 않습니다");
            None
        }
    };
    // 폐기된 룰로 치료 계획을 만들지 않는다 — `plan` → `apply` 가 `run` 을 돌아가는 길이 되지 않게. `plan` 은
    // 관리자 문을 지나지 않으므로 아래 `load_allowed` 가 읽는 그 상태 폴더 하나만 본다(기계 공용 자리를 새로
    // 읽으면 권한 없는 계획 세우기가 목록이 없어도 막힌다).
    if let Some(m) = &m {
        revocation_gate_at(&a, m, &[state_dir(&a)])?;
    }

    let allow = load_allowed(
        |k| a.get(k.trim_start_matches("--")).map(str::to_string),
        &state_dir(&a),
    )?;
    let p = remedy_core::plan_with(&scan, m.as_ref(), &allow, &limits, run_mode(&a))?;
    write_json(out, &p)?;
    outln!(
        "계획 완료 -> {out}  판정 그룹 {} · Action {}",
        p.body.verdicts.len(),
        p.body.actions.len()
    );
    report_plan(&p, lang(&a), &a, true);
    // 종료 코드가 건너뛴 폴더(K2)로 6 에서 0 이 되는 자리라 그 폴더를 적는다 — 이 명령은 사유 줄(`warn_incomplete`)을
    // 원래 적지 않는다.
    let kind = m.as_ref().and_then(|m| m.kind);
    note_skipped_denied(&p.body.observation, kind);
    Ok(outcome(&p.body.verdicts, &p.body.observation, kind))
}

/// 계획에 넣지 못한 것을 **반드시 말한다**.
///
/// 조용히 빠지면 이 계획이 치료의 전부인 것처럼 읽힌다. 관측이 불완전할 수 있듯
/// 계획도 불완전할 수 있고, 둘 다 말하지 않으면 완전한 것으로 읽힌다 (설계-03 §2).
/// 사람이 읽는 언어. `--lang` 이 없으면 `REMEDY_LANG`, 그것도 없으면 OS 의 로케일(한국어 PC 면 한국어),
/// 그 밖은 영어다(`remedy_sdk::i18n::Lang::detect_with`).
///
/// **파일 출력은 언어와 무관하게 UTF-8 고정이다** (설계-00 §5-2).
fn lang(_a: &Args) -> remedy_core::report::Lang {
    // `--lang` 은 `split_global` 이 어느 자리에서든 떼어 내 전역에 둔다.
    ui().lang
}

/// **문구를 여기서 만들지 않는다.** 만들면 그 문구가 사실상 API 가 된다
/// (설계-01 D5). `remedy-report` 가 만든 것을 그대로 낸다.
///
/// 재부팅 뒤 재검사는 **이 기계에 물어서** 넘긴다 (P12 D4). 계획이 원한다는
/// 것만으로 약속하면, 걸 수 없는 기계에서 승인 전에 거짓을 말한다. **부른 명령도
/// 본다** (결정 자료 나1) — 예약 요청에는 플러그인 경로가 들어가는데 `apply --plan`
/// · `resume` 은 `--plugin` 을 받지 않으면 그것을 모르므로, 기계가 걸 수 있어도
/// 이 실행은 걸지 못한다. 그때도 약속 대신 이유를 낸다.
/// 계획을 화면에 적는다. `preview` 는 **바꾸지 않는 자리**(검사만 · 계획 세우기)다 — 목록 머리가 *치료하면 …
/// (지금은 바꾸지 않습니다)* 가 된다.
fn report_plan(
    p: &remedy_sdk::artifact::PlanEnvelope,
    lang: remedy_core::report::Lang,
    a: &Args,
    preview: bool,
) {
    use remedy_core::report::AfterReboot;
    let support = p
        .body
        .verify_after_reboot
        .then(remedy_core::restart::verify_after_reboot_support);
    let after_reboot = match &support {
        Some(Err(why)) => AfterReboot::Unavailable(why),
        // 기계는 걸 수 있다 — 이 실행이 요청을 만들 수 있는가 (`verify_request`).
        Some(Ok(())) if a.get("plugin").is_none() => {
            AfterReboot::Unavailable(no_plugin_reason(lang))
        }
        None | Some(Ok(())) => AfterReboot::Schedulable,
    };
    out!(
        "{}",
        if preview {
            remedy_core::report::render_plan_preview(p, lang, after_reboot)
        } else {
            remedy_core::report::render_plan(p, lang, after_reboot)
        }
    );
}

fn cmd_scan(raw: &[String]) -> Result<Code, Failure> {
    scan_one(raw, Keep::Always).map(|s| s.code)
}

/// 결과 파일(`artifacts.json` · `scan.json` · `plan.json`)을 남기는 규칙.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keep {
    /// 늘 남긴다 — 명령줄 `scan` · 메뉴의 *검사만 하기*.
    Always,
    /// **찾은 룰 · 확인 필요 룰의 것만** 남긴다 — *모두 검사만*(목표 remedy_전체검사_운영기반 D11). 깨끗한 룰 ·
    /// 해당 없는 룰은 요약과 회차 로그에만 남는다. 룰 1,000개에서 한 번에 Windows 1.25 GB · 리눅스 284 MB 가
    /// 쌓였다(2026-11-16 벤치) — 치료 · 복원 · 신고는 상태 폴더를 쓰므로 이 파일과 상관없다.
    Findings,
}

/// `scan` 한 번 — *모두 검사만* 이 요약 줄과 결과 폴더를 정하는 재료.
struct ScanOne {
    code: Code,
    kind: Option<PluginKind>,
    /// 다 보지 못한 까닭이 *검사할 경로가 전부 없음* 하나뿐 — **해당 없음**.
    absent: bool,
    /// 다 보지 못한 까닭이 *룰이 선언한 확인 필요* 하나뿐 — [`remedy_core::report::review_line`].
    review: bool,
    /// 결과 파일을 남겼다.
    kept: bool,
    /// 같은 제품의 점검 룰을 묶는 열쇠(`product` · 코어 1.21.0).
    product: Option<String>,
    /// 점검 룰이 찾았을 때 — 판정이 선 증거의 고친 판([`product::fixes_of`]). 그 밖에는 빈다.
    fixes: Vec<product::Fix>,
}

/// [`cmd_scan`] 의 몸통. 화면과 차례는 `keep` 과 상관없이 같고, 다른 것은 결과 파일을 쓰는가와 그 폴더를 적는
/// 줄뿐이다 — 남기지 않으면 그 줄도 적지 않는다(없는 폴더를 가리키지 않게). 만들어 둔 빈 폴더는 치운다.
fn scan_one(raw: &[String], keep: Keep) -> Result<ScanOne, Failure> {
    let a = parse_args(raw)?;
    // 설정 검증을 **가장 먼저** 한다. 수집을 다 끝낸 뒤 설정이 틀렸다고
    // 말하면 그 시간이 통째로 버려진다.
    let limits = load_limits(&a)?;
    let m = load_local(a.need("plugin")?)?;
    let dir = a.need("out-dir")?;
    // 거부한 검사가 치울 것은 **이번에 만든 폴더**뿐이다 — 운영자가 미리 만든 빈 폴더나 Windows 정션 ·
    // 디렉터리 링크(`remove_dir` 는 대상과 상관없이 링크째 지운다)는 그대로 둔다.
    let made_here = std::fs::symlink_metadata(dir).is_err();
    std::fs::create_dir_all(dir).map_err(|e| format!("{dir}: {e}"))?;
    let meta = RunMeta::now();
    tee::open(&state_dir(&a), &meta.run_id);
    banner(Some(&m));
    warn_unsupported(&m);
    // 폐기된 룰로는 검사하지 않는다(설계-03 §6). 거부 사유는 회차 로그에도 남는다.
    if let Err(f) = revocation_gate(&a, &m) {
        if made_here {
            let _ = std::fs::remove_dir(dir);
        }
        return Err(f);
    }

    let rules = load_rules(a.need("plugin")?)?;
    scan_started();
    let (artifacts, scan, unresolved) = tee::with_heartbeat(ui().verbose, tee::Beat::Scan, || {
        remedy_core::pipeline::scan_with_rules(&m, &meta, &rules)
    })?;
    warn_unresolved_extra(&unresolved, &m, Some(&scan.body.observation));
    let allow = load_allowed(
        |k| a.get(k.trim_start_matches("--")).map(str::to_string),
        &state_dir(&a),
    )?;
    let plan = remedy_core::plan_with(&scan, Some(&m), &allow, &limits, run_mode(&a))?;

    let obs = &scan.body.observation;
    let code = outcome(&scan.body.verdicts, obs, m.kind);
    // 거부가 있으면 해당 없음이 아니다 — 점검이 건너뛰는 거부(K2)도 치료 룰에서는 못 본 자리다. 점검 룰은 여기 오지
    // 않는다(6 이면 `is_complete_for_check` 가 이미 거짓이다).
    let absent = code == Code::IncompleteObservation
        && obs.all_roots_missing()
        && obs.denied_dirs == 0
        && obs.is_complete_for_check();
    let review = obs.only_unconfirmed();
    let kept = keep == Keep::Always || !(code == Code::NoThreat || absent);
    if kept {
        write_json(&format!("{dir}/artifacts.json"), &artifacts)?;
        write_json(&format!("{dir}/scan.json"), &scan)?;
        write_json(&format!("{dir}/plan.json"), &plan)?;
        output_dir_line(dir);
    } else {
        // 비어 있을 때만 지운다 — 다른 무엇이 들어 있으면 그대로 둔다.
        let _ = std::fs::remove_dir(dir);
    }
    report_scan(&scan, m.kind, m.remediate.is_none());
    report_plan(&plan, lang(&a), &a, true);
    outln!();
    outln!(
        "{}",
        remedy_core::report::result_line_for(code, 0, ui().lang, m.kind, review)
    );
    let fixes = if m.kind == Some(PluginKind::Check) && code == Code::FoundNotRemediated {
        product::fixes_of(&scan.body)
    } else {
        Vec::new()
    };
    Ok(ScanOne {
        code,
        kind: m.kind,
        absent,
        review,
        kept,
        product: m.product.clone(),
        fixes,
    })
}

/// 산출 폴더. 셸 중괄호 축약(`{a,b}.json`)이나 하드코딩한 역슬래시를 쓰지
/// 않는다 — 리눅스 화면에 `run\{…}` 가 찍혔다 (2026-09-06 실측).
fn output_dir_line(dir: &str) {
    let lang = ui().lang;
    outln!(
        "{} : {dir}  (artifacts.json{}scan.json{}plan.json)",
        // **`산출 폴더` 가 아니라 `결과 폴더` 다** (2026-10-28). *산출* 은 공정
        // 쪽 말이고 보안 제품 화면에서 쓰지 않는다. 글자 수가 같아(5) 영문
        // `Output   ` 과 함께 윗줄 `검사 완료` · `Scan done` 과 계속 맞는다.
        lang.t("결과 폴더", "Output   "),
        remedy_sdk::i18n::deco().dot(),
        remedy_sdk::i18n::deco().dot()
    );
}

// ─────────────────────────────────────────────────── apply · run (P6)

/// NDJSON 진행 이벤트를 내보내는 곳.
///
/// **사람이 읽는 출력과 섞지 않는다.** 한 스트림에 섞으면 기계가 파싱할 수 없고,
/// 파싱하려고 사람 쪽 문구를 건드리는 순간 그 문구가 사실상 API 가 된다.
struct NdjsonSink {
    out: std::sync::Mutex<Box<dyn std::io::Write + Send>>,
}

impl NdjsonSink {
    /// `-` 는 표준 출력. 그 외에는 파일.
    fn open(spec: &str) -> Result<Self, String> {
        let w: Box<dyn std::io::Write + Send> = if spec == "-" {
            Box::new(std::io::stdout())
        } else {
            Box::new(std::fs::File::create(spec).map_err(|e| format!("{spec}: {e}"))?)
        };
        Ok(Self {
            out: std::sync::Mutex::new(w),
        })
    }
}

impl remedy_core::apply::Progress for NdjsonSink {
    fn emit(&self, event: &remedy_core::apply::Event<'_>) {
        // 이벤트마다 flush 한다. 진행률은 **도중에** 읽혀야 쓸모가 있고,
        // 크래시했을 때 마지막으로 무엇을 하고 있었는지도 여기 남는다.
        if let Ok(mut w) = self.out.lock() {
            if let Ok(line) = serde_json::to_string(event) {
                let _ = writeln!(w, "{line}");
                let _ = w.flush();
            }
        }
    }
}

/// 사람이 계획을 읽고 **승인**하는 자리 (설계-00 §5 대화형).
///
/// `--yes` 는 무인 배포용이다. 그것 없이 터미널이 아닌 곳에서 돌면 **거절한다** —
/// 승인할 사람이 없는 자리에서 파괴가 진행되면 안 된다. 조용히 진행하는 것보다
/// 아무것도 하지 않는 편이 낫다.
/// 이 실행에 사람이 있는가.
///
/// `--yes` 는 "묻지 말고 진행하라" 이고, 그것은 곧 **화면 앞에 사람이 없다**는
/// 선언이다. 계획기는 이 값으로 이동식 매체 대상을 가른다 (설계-03 §4).
fn run_mode(a: &Args) -> remedy_core::Mode {
    if a.has("yes") {
        remedy_core::Mode::Unattended
    } else {
        remedy_core::Mode::Interactive
    }
}

/// 이 계획에 이동식 매체 대상이 있는가. 있으면 그 Action 들의 설명.
fn removable_in(plan: &remedy_sdk::artifact::PlanEnvelope) -> Vec<String> {
    use remedy_sdk::artifact::UserImpactKind;
    plan.body
        .actions
        .iter()
        .filter(|x| {
            x.user_impact
                .as_ref()
                .is_some_and(|u| u.kind == UserImpactKind::RemovableMedia)
        })
        .map(|x| {
            format!(
                "seq {} {} {}",
                x.seq,
                x.op.info().id,
                x.target.as_deref().unwrap_or("")
            )
        })
        .collect()
}

fn approved(a: &Args, plan: &remedy_sdk::artifact::PlanEnvelope) -> Result<bool, Failure> {
    use std::io::IsTerminal;

    // **이동식 매체는 따로 묻는다.** 드라이브 문자는 재사용되므로 스냅샷을 뜬
    // 시점의 `E:` 와 지금의 `E:` 가 같은 매체라는 보장이 없다. 그것을 확인할 수
    // 있는 것은 눈앞의 사람뿐이다 (설계-03 §4).
    let removable = removable_in(plan);

    if a.has("yes") {
        if !removable.is_empty() {
            // 남의 손을 거쳐 온 계획일 수 있다. `run --yes` 는 애초에 이런
            // Action 을 만들지 않지만, `apply --plan` 은 다른 기계에서 만든
            // 계획을 받는다.
            let lang = ui().lang;
            errln!();
            errln!(
                "  {} {}",
                lang.t("주의:", "Note:"),
                lang.t(
                    "이동식 매체 대상이 계획에 들어 있습니다. 무인 모드에서는 수행하지 않습니다.",
                    "the plan touches removable media. Unattended mode does not carry that out."
                )
            );
            for r in &removable {
                errln!("     {r}");
            }
            errln!(
                "     {}",
                lang.t(
                    "매체를 확인할 사람이 있는 자리에서 --yes 없이 다시 돌리십시오.",
                    "Run again without --yes where someone can confirm the media."
                )
            );
            return Err(Failure {
                code: Code::GuardStop,
                message: "이동식 매체 대상은 무인 모드에서 승인될 수 없습니다".into(),
            });
        }
        return Ok(true);
    }
    let lang = ui().lang;
    if !std::io::stdin().is_terminal() {
        // "승인할 사람이 없습니다" · "아무것도 하지 않았습니다" 는 하네스가 읽는 문구다.
        errln!();
        errln!(
            "  {} {}",
            lang.t("주의:", "Note:"),
            lang.t(
                "승인할 사람이 없습니다 (터미널이 아닙니다).",
                "nobody is here to approve (not a terminal)."
            )
        );
        errln!(
            "     {}",
            lang.t(
                "무인 배포에서는 --yes 를 명시하십시오. 아무것도 하지 않았습니다.",
                "Pass --yes for unattended deployment. Nothing was done."
            )
        );
        return Ok(false);
    }
    if !removable.is_empty() && !confirm_removable(&removable)? {
        return Ok(false);
    }

    // "진행하려면" 은 리눅스 하네스가 읽는 문구다.
    //
    // **되돌리는 길을 메뉴의 말로도 적고, `y` 도 받는다고 적는다.** 메뉴에는 'restore' 라는
    // 낱말이 없고, 영문 입력 상태로 '예' 를 치면 `dP` 가 되어 취소된다 — 코드는 `y` 도 받는데
    // 화면은 '예' 만 적었다(v1.1.0 적대적 검토).
    //
    // **두 줄로 나눈다** — 한 줄 126칸 · 괄호 셋이었다(처음 쓰는 사람 검토 · 목표 remedy_시연전_안정화 D5). 메뉴 앞의
    // 사람에게는 메뉴의 길만, 명령줄에서는 restore 명령을 적는다.
    let undo = if term::in_session() {
        lang.t(
            "나중에 메뉴의 '치료 전으로 복원하기' 로 되돌릴 수 있습니다.",
            "You can undo it later with the menu's 'Restore to before the treatment'.",
        )
    } else {
        lang.t(
            "나중에 restore 명령으로 되돌릴 수 있습니다.",
            "You can undo it later with the restore command.",
        )
    };
    ask_yes(&format!(
        "\n{} {undo}\n{}",
        lang.t("위 계획대로 치료합니다.", "The plan above will run."),
        lang.t(
            "진행하려면 y 또는 '예'를 입력하십시오: ",
            "Type y or 'yes' to proceed: "
        )
    ))
}

/// 계획 여럿을 **한 번에** 승인받는다 — *찾은 것 모두 치료하기*([`treat_all`]). 규칙은 [`approved`]
/// 그대로다: 터미널이 아니면 하지 않고, 이동식 매체 위의 대상은 따로 묻는다(계획 모두의 것을 한 번에).
/// 다른 것은 문장이 계획의 수와 바꿀 것의 수를 말한다는 것 하나다.
fn approved_all(plans: &[&remedy_sdk::artifact::PlanEnvelope]) -> Result<bool, Failure> {
    use std::io::IsTerminal;
    let lang = ui().lang;
    if !std::io::stdin().is_terminal() {
        errln!();
        errln!(
            "  {} {}",
            lang.t("주의:", "Note:"),
            lang.t(
                "승인할 사람이 없습니다 (터미널이 아닙니다).",
                "nobody is here to approve (not a terminal)."
            )
        );
        errln!(
            "     {}",
            lang.t("아무것도 하지 않았습니다.", "Nothing was done.")
        );
        return Ok(false);
    }
    let removable: Vec<String> = plans.iter().flat_map(|p| removable_in(p)).collect();
    if !removable.is_empty() && !confirm_removable(&removable)? {
        return Ok(false);
    }
    let changes: usize = plans.iter().map(|p| p.body.actions.len()).sum();
    // "진행하려면" 은 하네스가 읽는 낱말이다 — 한 룰의 승인과 같게 둔다.
    // 앞 줄(*위 계획 N개(바꿀 것 M건)를 모두 수행합니다*)은 메뉴 하네스가 읽는다. 160칸 한 줄이었다 — 두 줄로
    // 나누고 괄호를 하나로 줄인다(목표 remedy_시연전_안정화 D5).
    let ko = format!(
        "위 계획 {}개(바꿀 것 {changes}건)를 모두 수행합니다. 항목마다 메뉴에서 되돌릴 수 있습니다.\n\
         진행하려면 y 또는 '예'를 입력하십시오: ",
        plans.len()
    );
    let en = format!(
        "The {} plans above ({changes} change(s)) will all run. Each can be undone from the menu.\n\
         Type y or 'yes' to proceed: ",
        plans.len()
    );
    ask_yes(&format!("\n{}", lang.pick(ko, en)))
}

/// 이동식 매체 위의 대상을 따로 묻는다(설계-03 §4) — 사람이 '예' 라고 하면 참.
fn confirm_removable(removable: &[String]) -> Result<bool, Failure> {
    let lang = ui().lang;
    errln!();
    errln!(
        "  {} {}",
        lang.t("주의:", "Note:"),
        lang.t(
            "이동식 매체 위의 대상이 있습니다:",
            "targets on removable media:"
        )
    );
    for r in removable {
        errln!("     {r}");
    }
    ask_yes(&format!(
        "     {}",
        lang.t(
            "지금 꽂혀 있는 매체가 맞습니까? 맞으면 y 또는 '예'를 입력하십시오: ",
            "Is the inserted media the right one? Type y or 'yes' to confirm: "
        )
    ))
}

/// 묻고 한 줄을 받는다 — '예'(또는 yes · y)면 참, 아니면 *"아무것도 하지 않았습니다"* 를 적고 거짓.
fn ask_yes(prompt: &str) -> Result<bool, Failure> {
    use std::io::Write;
    screen_err!("{prompt}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Failure::from(e.to_string()))?;
    let ok = matches!(line.trim(), "예" | "yes" | "y" | "Y");
    if !ok {
        errln!(
            "  {}",
            ui().lang
                .t("아무것도 하지 않았습니다.", "Nothing was done.")
        );
    }
    Ok(ok)
}

/// 메뉴로 들어온 사람에게 **되돌릴지 한 번 묻는다.**
///
/// # 왜 `approved` 를 쓰지 않는가
///
/// 그것은 계획 봉투(`PlanEnvelope`)를 받아 이동식 매체까지 본다 — 복원 계획은
/// 그 봉투가 아니다. 그래서 묻는 문장만 같은 꼴로 둔다.
///
/// # 왜 `restore` 자체를 고치지 않는가
///
/// `restore --run <회차>` 는 `--yes` 가 없으면 목록을 보이고 *"--yes 를 붙여
/// 다시 부르십시오"* 로 끝난다(종료 2). 명령줄 사용자는 그 목록을 읽고 다시
/// 치지만 **메뉴로 들어온 사람에게는 칠 자리가 없다** — 2026-10-29 에 진짜
/// 콘솔로 재어 보니 다섯 작업 가운데 복원만 끝까지 가지 못했다. 그래서 메뉴
/// 세션에서는 그 줄을 내지 않고(`term::in_session`) 이 함수가 곧바로 묻는다.
///
/// 그 명령에 대화형 승인을 넣는 편이 더 깔끔하지만, 그러면 **터미널에서 치는
/// 명령줄 호출의 화면이 바뀐다** — 시연 대본 6장이 그 화면을 그대로 싣고 있고
/// 불변식 I1 이 막는 자리다. 그래서 메뉴가 사람이 걷는 두 걸음을 대신 걷고,
/// 명령의 동작은 한 글자도 바꾸지 않는다.
fn confirm_restore() -> bool {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return false;
    }
    let lang = ui().lang;
    // **되돌리면 무엇이 돌아오는지 먼저 말한다.** 치료 전으로 돌아가므로 악성으로 판정해
    // 격리한 파일도 제자리로 오고, 그 자리에 지금 있는 파일(다시 설치한 정상 파일 포함)은
    // 덮어쓴다(2026-11-07 실측 — 공급사 재설치 뒤 복원). 오탐일 때의 일이다.
    // 세 줄로 나눈다 — 한 줄 약 170칸이었다(처음 쓰는 사람 검토 · 목표 remedy_시연전_안정화 D5).
    let ko = "위 목록대로 치료 전 상태로 복원합니다. 격리했던 파일이 제자리로 돌아오고,\n\
              그 자리에 지금 있는 파일은 덮어씁니다. 오탐이라고 판단했을 때만 진행하십시오.\n\
              진행하려면 y 또는 '예'를 입력하십시오: ";
    let en = "The list above will be restored to the state before treatment. Quarantined files\n\
              go back in place and overwrite whatever is there now. Proceed only for a false positive.\n\
              Type y or 'yes' to proceed: ";
    screen_err!("\n{}", lang.t(ko, en));
    std::io::stderr().flush().ok();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "예" | "yes" | "y" | "Y")
}

/// 계획을 수행한다. **여기가 파괴가 시작되는 유일한 입구다.**
fn cmd_apply(
    raw: &[String],
    integrity: &remedy_core::integrity::SelfIntegrity,
) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    tee::open(&state_dir(&a), &format!("apply-{}", std::process::id()));
    banner(None);
    let plan: remedy_sdk::artifact::PlanEnvelope = read_json(a.need("plan")?)?;
    tee::rename(&plan.run_id);
    run_apply(&a, &plan, integrity, std::time::Instant::now(), None, false)
}

/// 전 단계를 한 번에 — 수집부터 치료까지.
fn cmd_run(
    raw: &[String],
    integrity: &remedy_core::integrity::SelfIntegrity,
) -> Result<Code, Failure> {
    let p = prepare_run(raw, true)?;
    run_apply(&p.a, &p.plan, integrity, p.started, p.kind, true)
}

/// `run` 의 앞 절반 — 수집 · 평가 · 계획 · 결과 파일 · 검사 화면. **바꾸지 않는다.**
struct Prepared {
    a: Args,
    plan: remedy_sdk::artifact::PlanEnvelope,
    kind: Option<PluginKind>,
    started: std::time::Instant,
}

/// [`Prepared`] 를 만든다. `own_log` 가 참이면 회차 로그를 여기서 연다(`run`). *찾은 것 모두
/// 치료하기* 는 룰 여럿의 화면을 로그 하나에 담으므로 거짓으로 부른다 — 그 로그는 부르는 쪽이
/// 이미 열었다([`treat_all`]).
fn prepare_run(raw: &[String], own_log: bool) -> Result<Prepared, Failure> {
    let a = parse_args(raw)?;
    let limits = load_limits(&a)?;
    let m = load_local(a.need("plugin")?)?;
    let started = std::time::Instant::now();
    if own_log {
        tee::open(&state_dir(&a), &format!("run-{}", std::process::id()));
    }
    banner(Some(&m));
    warn_unsupported(&m);

    let meta = RunMeta::now();
    if own_log {
        tee::rename(&meta.run_id);
    }
    // 폐기된 룰로는 치료하지 않는다 — 검사 · 계획 · 승인보다 앞이다(설계-03 §6). `--yes` 든 아니든 같다.
    revocation_gate(&a, &m)?;
    let rules = load_rules(a.need("plugin")?)?;
    scan_started();
    let (artifacts, scan, unresolved) = tee::with_heartbeat(ui().verbose, tee::Beat::Scan, || {
        remedy_core::pipeline::scan_with_rules(&m, &meta, &rules)
    })?;
    warn_unresolved_extra(&unresolved, &m, Some(&scan.body.observation));
    let allow = load_allowed(
        |k| a.get(k.trim_start_matches("--")).map(str::to_string),
        &state_dir(&a),
    )?;
    let plan = remedy_core::plan_with(&scan, Some(&m), &allow, &limits, run_mode(&a))?;

    if let Some(dir) = a.get("out-dir") {
        std::fs::create_dir_all(dir).map_err(|e| format!("{dir}: {e}"))?;
        write_json(&format!("{dir}/artifacts.json"), &artifacts)?;
        write_json(&format!("{dir}/scan.json"), &scan)?;
        write_json(&format!("{dir}/plan.json"), &plan)?;
        if ui().verbose {
            output_dir_line(dir);
        }
    }
    report_scan(&scan, m.kind, m.remediate.is_none());
    Ok(Prepared {
        a,
        plan,
        kind: m.kind,
        started,
    })
}

/// `integrity` 는 **다시 재지 않고 받아 온다.** `main` 이 시작할 때 한 번
/// 검사하고(그 자리의 주석이 이유를 적고 있다) 그 값이 여기까지 내려온다 —
/// 도중에 다시 부르면 같은 파일을 여러 번 읽고, 결과가 갈리면 어느 쪽이
/// 참인지 알 수 없다.
/// `kind` 는 **부르는 쪽이 매니페스트를 갖고 있을 때만** 온다. `run` 은 갖고 있고,
/// `apply --plan` 은 계획 파일만 읽으므로 `None` 이다 — 계획 봉투에 플러그인 종류를
/// 싣는 것은 산출물 스키마 변경이라 B-7 로 미뤘다. 그래서 점검 플러그인의 계획을
/// `apply --plan` 으로 부으면 루트 전부 없음이 **여전히 6** 이다. 그 계획의
/// `actions` 는 비어 있으므로(점검은 바꾸지 않는다) 치료가 갈리는 일은 없다.
fn run_apply(
    a: &Args,
    plan: &remedy_sdk::artifact::PlanEnvelope,
    integrity: &remedy_core::integrity::SelfIntegrity,
    started: std::time::Instant,
    kind: Option<PluginKind>,
    scan_warned: bool,
) -> Result<Code, Failure> {
    let lang = ui().lang;

    outln!();
    // `--dry-run` 은 바꾸지 않는다 — 목록 머리도 미리보기의 말이다.
    report_plan(plan, lang, a, a.has("dry-run"));
    // `run` 은 검사 단계(`report_scan`)가 같은 관측으로 이미 말했다 — 두 번 찍지 않는다.
    // `apply --plan` · `resume` 은 검사 단계가 없으니 여기서 말한다.
    if !scan_warned {
        warn_incomplete(&plan.body.observation, kind);
        note_skipped_denied(&plan.body.observation, kind);
    }

    if plan.body.actions.is_empty() {
        let code = outcome(&plan.body.verdicts, &plan.body.observation, kind);
        outln!(
            "{}",
            if kind == Some(PluginKind::Check) {
                // 점검은 바꾸지 않는다고 선언한 것이다. *"수행할 항목이 없다"* 는
                // 할 일이 있었는데 못 했다는 뜻으로 읽힌다.
                lang.t(
                    "점검만 하는 룰이므로 바꿀 것이 없습니다.",
                    "A check-only rule: nothing to change.",
                )
            } else {
                lang.t("수행할 항목이 없습니다.", "Nothing to do.")
            }
        );
        out!(
            "{}",
            closing(
                &remedy_core::report::Closing {
                    code,
                    done: 0,
                    elapsed_secs: elapsed_since(started),
                    run_id: None,
                    quarantine: None,
                    journal: None,
                    kind,
                    state_dir: None,
                    review: plan.body.observation.only_unconfirmed(),
                },
                lang
            )
        );
        return Ok(code);
    }

    // **드라이런은 잠금도 잡지 않는다.** 아무것도 바꾸지 않으므로 다른
    // 인스턴스를 막을 이유가 없다.
    if a.has("dry-run") {
        // "아무것도 변경하지 않았습니다" 는 검증 스크립트가 읽는 문구다.
        outln!();
        outln!(
            "--dry-run{}{}",
            remedy_sdk::i18n::deco().dash(),
            lang.t("아무것도 변경하지 않았습니다.", "nothing was changed.")
        );
        return Ok(Code::FoundNotRemediated);
    }

    if !approved(a, plan)? {
        return Ok(Code::FoundNotRemediated);
    }
    execute(a, plan, integrity, started, kind).map(|(code, _)| code)
}

/// 승인을 받은 계획을 수행한다 — 잠금 · 실행 · 진행 줄 · 재시작 조언 · 마무리 표. 둘째 값은 수행을
/// 마친 Action 의 수다(*찾은 것 모두 치료하기* 의 결과 줄이 쓴다).
///
/// **승인은 여기서 묻지 않는다** — 부르는 쪽이 받았다(`run_apply` 는 계획 하나를 [`approved`] 로,
/// [`treat_all`] 은 계획 여럿을 [`approved_all`] 로 한 번에).
fn execute(
    a: &Args,
    plan: &remedy_sdk::artifact::PlanEnvelope,
    integrity: &remedy_core::integrity::SelfIntegrity,
    started: std::time::Instant,
    kind: Option<PluginKind>,
) -> Result<(Code, usize), Failure> {
    let lang = ui().lang;
    let state_dir = a
        .get("state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);

    // 승인 **뒤에** 잠근다. 사람이 화면을 보는 동안 다른 인스턴스를 막아 둘
    // 이유가 없고, 승인을 기다리는 사이 잠금을 쥐고 있으면 무인 배포가 막힌다.
    let _lock = remedy_core::RunLock::acquire(&state_dir).map_err(|e| Failure {
        code: Code::GuardStop,
        message: e.to_string(),
    })?;

    let sink = match a.get("events") {
        Some(spec) => Some(NdjsonSink::open(spec)?),
        None => None,
    };
    let backend = remedy_core::restore::default_backend();
    // 시계는 여기서 한 번 읽어 넘긴다. 실행기가 직접 읽으면 같은 입력이 매번
    // 다른 저널을 만든다. 이어받은 실행에서 이 값이 **계획의 생성 시각과 다른
    // 것**이 곧 "언제 이어받았는가" 를 말해 준다.
    // **어떤 바이너리가 이 기계를 고쳤는지 저널에 남긴다.** 서명 없는 배포
    // 빌드도 파괴를 하게 됐으므로(2026-09-02) 그 사실이 기록에 있어야 한다.
    let mut ex = remedy_core::apply::Executor::new(&backend, &state_dir)
        .with_clock(RunMeta::now().created)
        .with_self_integrity(integrity.id());
    if let Some(s) = &sink {
        ex = ex.with_progress(s);
    }
    if let Some(p) = a.get("passphrase-file") {
        let text = std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
        ex = ex.with_keys(remedy_core::apply::KeyPolicy {
            passphrase: Some(text.trim_end_matches(['\r', '\n']).to_string()),
            org_public: load_org_public(a)?,
        });
    } else if let Some(pk) = load_org_public(a)? {
        ex = ex.with_keys(remedy_core::apply::KeyPolicy {
            passphrase: None,
            org_public: Some(pk),
        });
    }
    // 재부팅 뒤 재평가는 **실행기가 `End` 앞에서** 건다 — 여기서는 요청만 만든다.
    if plan.body.verify_after_reboot {
        ex = ex.with_verify_after_reboot(verify_request(a));
    }

    outln!();
    outln!("{}", lang.t("치료를 시작합니다.", "Starting treatment."));
    // 치료도 심장박동 안에서 — 외부 도구를 죽이지 않기로 했으니 오래 도는
    // 도구는 여기서 보여야 한다 (결정 2026-09-07).
    let report =
        tee::with_heartbeat(ui().verbose, tee::Beat::Apply, || ex.apply(plan)).map_err(|e| {
            Failure {
                code: e.exit_code(),
                message: e.to_string(),
            }
        })?;

    // **이어받았다는 사실을 먼저 말한다.** 그러지 않으면 Action 10건짜리 계획에
    // "3건 수행 완료" 가 뜨고, 읽는 사람은 7건이 조용히 빠졌다고 읽는다.
    if let Some(from) = report.resumed {
        // "이전 실행을 이어받았습니다" 는 검증 스크립트가 읽는 문구다.
        outln!(
            "  {} {}",
            lang.pick(
                format!(
                    "이전 실행을 이어받았습니다. {}건은 이미 끝나 있었습니다.",
                    report.carried
                ),
                format!(
                    "Resumed the previous run. {} action(s) were already done.",
                    report.carried
                )
            ),
            match from {
                remedy_core::apply::Resume::Restart => lang.t(
                    "아직 파일을 바꾸지 않았으므로 백업부터 다시 합니다.",
                    "No files had been changed yet, so backup runs again."
                ),
                _ => lang.t(
                    "격리소는 이전 시도가 만든 것을 그대로 씁니다.",
                    "The quarantine from the previous attempt is reused."
                ),
            }
        );
    }
    let total = report.body.results.len();
    let targets: std::collections::HashMap<u32, &str> = plan
        .body
        .actions
        .iter()
        .map(|a| (a.seq, a.target.as_deref().unwrap_or("")))
        .collect();
    for r in &report.body.results {
        let label = remedy_core::report::op_label(r.op, lang);
        // 계획이 `(실행 중인 것을 찾아서)` 라고 적은 자리를 진행 줄도 그렇게 적는다.
        let target = targets
            .get(&r.seq)
            .copied()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| remedy_core::report::no_target(lang));
        match &r.error {
            // "수행 [" 과 "실패 [" 는 하네스와 검증 스크립트가 읽는 접두다.
            None => outln!(
                "  {} [{}/{total}] {label}  {target}",
                lang.t("수행", "done"),
                r.seq
            ),
            Some(e) => errln!(
                "  {} [{}/{total}] {label}  {target}  {e}",
                lang.t("실패", "FAILED"),
                r.seq
            ),
        }
        if ui().verbose {
            outln!("        {}", r.op.info().id);
        }
    }

    advise_restart(&report, &targets);
    report_scheduled_verify(report.scheduled_verify.as_ref(), &plan.run_id, a);

    let code = if report.failed() > 0 {
        // "되돌리지 않고 나머지를 수행했습니다" 는 검증 스크립트가 읽는 문구다.
        errln!();
        errln!(
            "{}",
            lang.pick(
                format!(
                    "{}건이 실패했습니다. 되돌리지 않고 나머지를 수행했습니다.",
                    report.failed()
                ),
                format!(
                    "{} action(s) failed. The rest were carried out without rolling back.",
                    report.failed()
                )
            )
        );
        Code::PartialFailure
    } else {
        Code::Remediated
    };
    let quarantine = report.container.as_ref().map(|c| c.display().to_string());
    let journal = report.journal.display().to_string();
    let at = state_hint(&state_dir);
    outln!();
    out!(
        "{}",
        closing(
            &remedy_core::report::Closing {
                code,
                done: report.done(),
                elapsed_secs: elapsed_since(started),
                run_id: Some(&plan.run_id),
                quarantine: quarantine.as_deref(),
                journal: Some(&journal),
                kind,
                state_dir: at.as_deref(),
                // 치료를 수행한 회차다 — 확인 필요는 점검(바꾸지 않는 룰)에만 있다.
                review: false,
            },
            lang
        )
    );
    Ok((code, report.done()))
}

/// 재부팅 뒤 재평가 요청 (설계-03 §8). **거는 것은 실행기다** — `End` 앞에서
/// 걸어야 감사 로그에 남는다 (`Executor::with_verify_after_reboot`).
///
/// 못 만들면 사람이 읽을 이유를 돌려준다. 실행기가 그것도 저널에 남기고, 화면은
/// [`report_scheduled_verify`] 가 말한다.
///
/// # 자기 흔적 규칙 (설계-03 §8)
///
/// 1. **고정된 식별 가능한 이름** — `SCHEDULED_VERIFY_NAME`
/// 2. **검증 직후 스스로 제거** — Windows 는 RunOnce 항목을 실행 *직전에*
///    지우고, 리눅스는 유닛이 실행 직전에 자기를 지운다(P12). 어느 쪽이든
///    `verify` 가 시작할 때 한 번 더 확인한다
/// 3. **감사 로그에 자기 항목으로 기록** — 실행기가 저널에 적는다(P12). 치료
///    도구가 정체불명의 자동실행을 남기면 그 자체가 타 백신의 탐지 대상이 된다
fn verify_request(a: &Args) -> Result<remedy_core::apply::VerifyRequest, String> {
    let lang = ui().lang;
    let Some(plugin) = a.get("plugin") else {
        return Err(no_plugin_reason(lang).to_string());
    };
    let Ok(exe) = std::env::current_exe() else {
        return Err(lang
            .t(
                "자기 경로를 얻지 못했습니다",
                "could not determine this program's path",
            )
            .to_string());
    };
    Ok(remedy_core::apply::VerifyRequest {
        exe,
        plugin: at_reboot(plugin),
        state_dir: a.get("state-dir").map(at_reboot),
        // 이 회차가 정한 언어를 그대로 싣는다 — 재부팅 회차는 환경을 물려받지
        // 못한다 (실측 2026-09-07: 한 로그가 앞은 한국어 뒤는 영어였다).
        lang: remedy_sdk::i18n::current(),
    })
}

/// 예약에 실을 경로 — 재부팅 회차는 다른 현재 폴더에서 돈다.
///
/// README 의 명령줄 예시는 `--plugin .\plugins\…` 처럼 상대 경로로 부른다.
/// 그 값을 그대로 실으면 재부팅 뒤 검사가 룰을 찾지 못하고(종료 4) 결과도
/// 남기지 못한다(2026-11-07 적대적 검토). 지금 폴더를 기준으로 절대 경로로
/// 바꾼다. 바꾸지 못하면 받은 값을 싣는다 — 예전과 같다.
fn at_reboot(p: &str) -> std::path::PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| std::path::PathBuf::from(p))
}

/// 재부팅 뒤 재평가 예약의 결과를 말한다 (설계-03 §8).
///
/// # 실패해도 치료는 끝났다
///
/// 예약이 안 된 것과 치료가 안 된 것은 다르다. 예약 실패로 종료 코드를 바꾸면
/// 무인 배포가 성공한 치료를 실패로 읽고 다시 돈다 — **경고로 말하고 사람이
/// 직접 부를 길을 알려 준다.**
fn report_scheduled_verify(
    s: Option<&remedy_core::apply::ScheduledVerify>,
    run_id: &str,
    a: &Args,
) {
    use remedy_core::apply::ScheduledVerify;
    let Some(s) = s else {
        return;
    };
    let lang = ui().lang;
    match s {
        // 메뉴 세션은 할 일만 말한다 — 예약한 자리(레지스트리 경로)는 회차 로그에 그대로 남고, 지우는 주체는 화면에
        // 남는다(자기 흔적 규칙 3 · 목표 remedy_시연전_안정화 D5). 명령줄은 지금 그대로다.
        ScheduledVerify::Scheduled { site, .. } if term::in_session() => {
            let full = scheduled_line(site.as_ref(), lang);
            tee::log_only(|| outln!("\n{full}"));
            outln!("\n{}", scheduled_line_brief(site.as_ref(), lang));
        }
        ScheduledVerify::Scheduled { site, .. } => {
            outln!("\n{}", scheduled_line(site.as_ref(), lang));
        }
        ScheduledVerify::NotScheduled { reason } => {
            errln!(
                "\n{}",
                not_scheduled_line(reason, run_id, a.get("plugin"), lang)
            );
        }
    }
}

/// 이 명령이 플러그인 경로를 모를 때의 이유. `apply --plan` 이 그 자리다 —
/// 계획 파일만 받는다. 승인 전 화면(`report_plan`)과 실행 뒤 안내
/// (`not_scheduled_line`)가 같은 문장을 쓴다.
fn no_plugin_reason(lang: remedy_core::report::Lang) -> &'static str {
    lang.t(
        "이 명령은 플러그인 경로를 모릅니다. `remedy run --plugin ...` 은 압니다",
        "this command does not know the plugin path; `remedy run --plugin ...` does",
    )
}

/// 예약하지 못했을 때의 한 줄 — 머리(`주의:`)까지. 사람이 직접 부를 명령을 준다.
///
/// 순수 함수로 둔 것은 [`scheduled_line`] 과 같은 이유다 — 예약이 실행기로
/// 옮겨 간 뒤에도(P12) 이 안내가 화면 기준선과 글자까지 같은지를 시험이 잰다.
fn not_scheduled_line(
    reason: &str,
    run_id: &str,
    plugin: Option<&str>,
    lang: remedy_core::report::Lang,
) -> String {
    let pl = plugin.unwrap_or("<plugin.yaml>");
    // "직접 부르십시오" 는 시험이 읽는 문구다.
    let hint = lang.pick(
        format!("재부팅 뒤 `remedy verify --run {run_id} --plugin {pl}` 를 직접 부르십시오"),
        format!("after the reboot, run `remedy verify --run {run_id} --plugin {pl}` yourself"),
    );
    format!(
        "{} {}",
        lang.t("주의:", "Note:"),
        lang.pick(
            format!("재평가를 예약하지 못했습니다 ({reason}). {hint}"),
            format!("re-evaluation was not scheduled ({reason}). {hint}")
        )
    )
}

/// 예약에 성공했을 때의 한 줄. **자리와 지우는 주체를 백엔드가 말한다** (자기
/// 흔적 규칙 3).
///
/// 순수 함수로 둔 것은 **Windows 문구가 화면 기준선과 글자까지 같은지**를 시험이
/// 재게 하려는 것이다 — 위치가 호출자에 박혀 있다가 백엔드 질의로 옮겨 왔다 (P12).
fn scheduled_line(
    site: Option<&remedy_core::restart::VerifySite>,
    lang: remedy_core::report::Lang,
) -> String {
    use remedy_core::restart::RemovedBy;
    let Some(s) = site else {
        // 예약한 백엔드가 자리를 말하지 않는 것은 계약 위반이다 — 모르는 자리와
        // 지우는 주체를 지어내지 않는다.
        return lang
            .t(
                "재부팅 후 재평가를 예약했습니다",
                "Re-evaluation scheduled after reboot",
            )
            .to_string();
    };
    let (ko, en) = match s.removed_by {
        RemovedBy::Os => ("실행 뒤 OS 가 지웁니다", "the OS removes it after it runs"),
        RemovedBy::Itself => (
            "실행 직전에 스스로 지웁니다",
            "it removes itself right before it runs",
        ),
    };
    let at = &s.location;
    lang.pick(
        format!("재부팅 후 재평가를 예약했습니다: {at} ({ko})"),
        format!("Re-evaluation scheduled after reboot: {at} ({en})"),
    )
}

/// 메뉴 세션의 예약 한 줄 — 무엇이 일어나는지와 지우는 주체만. 자리는 [`scheduled_line`] 이 회차 로그에 적는다.
fn scheduled_line_brief(
    site: Option<&remedy_core::restart::VerifySite>,
    lang: remedy_core::report::Lang,
) -> String {
    use remedy_core::restart::RemovedBy;
    let who = site.map(|s| match s.removed_by {
        RemovedBy::Os => lang.t("실행 뒤 OS 가 지웁니다", "the OS removes it after it runs"),
        RemovedBy::Itself => lang.t(
            "실행 직전에 스스로 지웁니다",
            "it removes itself right before it runs",
        ),
    });
    match who {
        Some(w) => lang.pick(
            format!("다시 시작하면 한 번 더 자동으로 검사합니다 (예약 — {w})."),
            format!("After a restart it scans once more automatically (scheduled — {w})."),
        ),
        None => lang
            .t(
                "다시 시작하면 한 번 더 자동으로 검사합니다.",
                "After a restart it scans once more automatically.",
            )
            .to_string(),
    }
}

/// 남아 있는 예약을 지운다 (설계-03 §8 자기 흔적 규칙 2).
///
/// **없으면 성공이다.** Windows 는 RunOnce 항목을 실행 직전에 지우므로 정상
/// 경로에서는 지울 것이 없다 — 그것을 실패로 읽으면 `verify` 가 매번 오류로
/// 끝난다. 여기서 한 번 더 부르는 이유는 **실행되지 않고 남은 경우**다
/// (사람이 재부팅 전에 직접 `verify` 를 불렀거나, RunOnce 가 돌지 않았거나).
fn clear_scheduled_verify() {
    if let Err(e) = remedy_core::restart::clear_scheduled_verify() {
        errln!(
            "{}: {} ({e})",
            ui().lang.t("주의", "Note"),
            ui().lang.t(
                "재평가 예약을 지우지 못했습니다 — 자동실행 항목이 남아 있을 수 있습니다",
                "could not clear the scheduled re-evaluation; an autorun entry may remain"
            )
        );
    }
}

/// 재시작을 권하기 **전에** 부팅 건전성을 읽는다 (설계-00 §6 · 설계-03 §8).
///
/// **판정은 `remedy_core::restart` 가 한다.** 여기 남은 것은 그 결과를 사람의
/// 말로 옮기는 일뿐이다 — 판정이 `println!` 안에 섞여 있으면 시험할 수 없고,
/// P9 이 이 경로를 실증하지 못한 이유가 그것이었다.
fn advise_restart(
    report: &remedy_core::apply::Report,
    targets: &std::collections::HashMap<u32, &str>,
) {
    use remedy_core::restart::RestartAdvice;
    let lang = ui().lang;

    let health = remedy_core::boot_health();
    // **재시작 조언은 Windows 의 것이다.** 안전 모드 · 재부팅 시 삭제가 Windows 개념이라, 리눅스에서
    // 일부가 실패하면 '안전 모드 진입 가능 여부: unknown … 복구 매체를 먼저 준비하십시오' 가 떴다 —
    // 리눅스의 부팅 건전성 자리는 대역이라 늘 unknown 이다(2026-11-07 적대적 검토 · 기준선 L 절).
    // 실패한 까닭은 위 '실패' 줄과 결과 줄이 말한다. 빠지는 줄은 stderr 뿐이다.
    let advice = if cfg!(windows) {
        remedy_core::restart::advise(
            report.body.reboot_required,
            report.failed(),
            health.as_ref(),
        )
    } else {
        RestartAdvice::Nothing
    };

    match advice {
        RestartAdvice::Nothing => {}

        RestartAdvice::CannotTell { pending_deletes } => {
            // 권하지는 않되 **남은 것은 말한다**(2026-11-25) — 이 갈래에서 '아직 그 자리에 있다' 가 사라졌었다.
            if pending_deletes {
                still_there(report, targets, false);
            }
            errln!(
                "\n{} {}",
                lang.t("주의:", "Note:"),
                lang.t(
                    "부팅 건전성을 확인할 수 없어 재시작을 권하지 않습니다.",
                    "boot health could not be checked; a restart is not advised."
                )
            );
        }

        RestartAdvice::Safe {
            pending_deletes,
            failed,
        } => {
            if pending_deletes {
                still_there(report, targets, true);
            }
            // "안전 모드" 는 검증 스크립트가 읽는 문구다 — 정상이면 이 낱말이 있어야
            // 하고(C1), SafeBoot 가 손상됐으면 "안전 모드에서 다시 시도" 가 없어야
            // 한다(항목4, `Invoke-P9Verify.ps1`). 그래서 그 구절을 남기고 뒤에 방법을
            // 잇는다 — **같은 계획은 다시 적용하지 않는다**(끝난 회차는 거부한다).
            // 다시 하는 것은 새 검사다.
            if failed > 0 {
                outln!(
                    "{}",
                    lang.t(
                        "남은 항목은 안전 모드에서 다시 시도할 수 있습니다 — 안전 모드로 재시작한 뒤 새로 검사해 치료합니다.",
                        "The remaining items can be retried in Safe Mode — restart in Safe Mode, then scan and treat again."
                    )
                );
            } else if pending_deletes {
                outln!(
                    "{}",
                    lang.t(
                        "재시작하면 정리가 끝납니다.",
                        "A restart completes the cleanup."
                    )
                );
            }
        }

        RestartAdvice::Unsafe {
            safeboot,
            pending_deletes,
        } => {
            if pending_deletes {
                still_there(report, targets, false);
            }
            errln!(
                "\n{}",
                lang.pick(
                    format!("경고: 이 기계는 재시작을 권할 수 없는 상태입니다. 안전 모드 진입 가능 여부: {}.", safeboot.id()),
                    format!("Warning: a restart cannot be recommended on this machine. Safe Mode availability: {}.", safeboot.id())
                )
            );
            // **본 것과 보지 못한 것을 같은 말로 내지 않는다** (설계-00 §5-1 —
            // 접근 거부의 원인이 보안 제품인지 악성코드인지 구분해 보고한다).
            // 잠긴 안전 모드 키는 정책이 그런 것일 수도 있고, 그 기계에
            // "악성코드가 손댔을 수 있다" 고 말하면 그것이 오탐이다.
            if safeboot.observed_damage() {
                errln!(
                    "  {}",
                    lang.t(
                        "악성코드가 안전 모드 설정을 손댔을 수 있습니다. 지금 재시작하면 부팅되지 \
                         않을 수 있으니 복구 매체를 먼저 준비한 뒤 진행하십시오. \
                         이 도구는 부팅 구성을 고치지 않습니다.",
                        "Malware may have tampered with the Safe Mode settings. Restarting now may \
                         leave the machine unbootable; prepare recovery media first. \
                         This tool does not repair the boot configuration."
                    )
                );
            } else {
                errln!(
                    "  {}",
                    lang.t(
                        "키는 있으나 읽을 수 없습니다. 권한이 막혀 있습니다. 악성코드가 잠갔을 수도, \
                         보안 정책이 그럴 수도 있습니다. 손상 여부를 확인하지 못했으므로 권하지 않습니다. \
                         재시작이 필요하면 복구 매체를 먼저 준비하십시오. 이 도구는 부팅 구성을 고치지 않습니다.",
                        "The key exists but cannot be read: access is denied. Malware may have locked it, \
                         or a security policy may. Damage could not be verified, so a restart is not advised. \
                         If you must restart, prepare recovery media first. This tool does not repair the boot configuration."
                    )
                );
            }
        }
    }
}

/// **아직 그 자리에 있는 것**을 말한다 — 재부팅 삭제 예약과, 다시 시작해야 끝나는 서비스(2026-11-25).
///
/// 머리 줄은 바이트 그대로다(파일 예약만 있는 회차의 화면이 그대로다). 서비스는 그 아래에 항목마다 한 줄을
/// 더하고, 지우는 중인 서비스가 있으면 되돌리는 차례를 한 줄 더한다 — 다시 시작하기 전에는 복원이 멈춘다.
/// `may_suggest` 는 재시작을 권해도 되는 갈래인가다. 아니면 지시 없이 사실만 말한다.
fn still_there(
    report: &remedy_core::apply::Report,
    targets: &std::collections::HashMap<u32, &str>,
    may_suggest: bool,
) {
    use remedy_core::apply::Restart;
    let lang = ui().lang;
    outln!(
        "\n{}",
        lang.t(
            "일부 항목은 다음 부팅에 사라집니다. 아직 그 자리에 있습니다.",
            "Some items disappear at the next boot. They are still there now."
        )
    );
    for (seq, what) in &report.at_restart {
        let Some(r) = report.body.results.iter().find(|r| r.seq == *seq) else {
            continue;
        };
        let label = remedy_core::report::op_label(r.op, lang);
        let target = targets.get(seq).copied().unwrap_or_default();
        let why = match what {
            Restart::DeletePending => lang.t(
                "Windows 가 지우기를 미뤘습니다. PC 를 다시 시작하면 지워집니다",
                "Windows postponed removing it; it is removed when the PC restarts",
            ),
            // 재시작을 권할 수 없는 갈래에서는 지시하지 않는다 — 바로 뒤 경고가 '권하지 않는다' 고 말한다.
            Restart::DeleteUnverified if may_suggest => lang.t(
                "지워졌는지 확인하지 못했습니다. PC 를 다시 시작한 뒤 다시 검사하십시오",
                "could not confirm it was removed; restart the PC and scan again",
            ),
            Restart::DeleteUnverified => lang.t(
                "지워졌는지 확인하지 못했습니다. 다시 시작하기 전까지 남아 있을 수 있습니다",
                "could not confirm it was removed; it may remain until the PC restarts",
            ),
            Restart::StopAtRestart => lang.t(
                "드라이버가 정지를 받지 않았습니다. 비활성화해 두었으므로 PC 를 다시 시작하면 올라오지 않습니다",
                "the driver did not accept the stop; it is disabled, so it will not load after a restart",
            ),
        };
        outln!("  [{seq}] {label}  {target} — {why}");
    }
    let removing = report
        .at_restart
        .values()
        .any(|w| matches!(w, Restart::DeletePending | Restart::DeleteUnverified));
    if removing && report.container.is_some() {
        outln!(
            "{}",
            if may_suggest {
                lang.t(
                    "오탐이라 되돌리려면 PC 를 먼저 다시 시작한 뒤 복원하십시오 — 그 전에는 복원이 멈춥니다.",
                    "If it was a false positive, restart the PC first, then restore — until then the restore stops.",
                )
            } else {
                lang.t(
                    "다시 시작하기 전에는 이 서비스를 복원할 수 없습니다 — 복원이 멈춥니다.",
                    "This service cannot be restored until the PC restarts — the restore stops.",
                )
            }
        );
    }
}

// ─────────────────────────────────────────────── verify · resume (P9)

/// 상태 디렉터리. 세 명령이 같은 규칙을 쓴다.
/// 이 회차가 쓰는 복원 정보 폴더. **고르는 동시에 잠근다.**
///
/// # 왜 여기인가
///
/// 그 폴더에는 계획·저널·**봉인 키**가 함께 있고, 권한을 세우는 코드가 없어
/// OS 기본값으로 열려 있었다(목표 `remedy_cli` 기준 8 실측: Windows 는 일반
/// 사용자가 **키를 읽고 파일을 심는다**, Linux 는 **키를 읽는다**). 만드는 자리는
/// 일곱 군데로 흩어져 있어(`journal` · `plan` · `quarantine` · `logs` · 키) 거기
/// 걸면 하나를 빠뜨린다. **쓰려면 반드시 지나는 자리**가 이 함수다.
///
/// # 프로세스당 한 번
///
/// 여러 명령이 이것을 여러 번 부른다. Windows 쪽은 `icacls.exe` 를 띄우므로
/// 매번 걸면 프로세스가 늘어난다 — [`std::sync::OnceLock`] 으로 한 번만 한다.
/// 폴더가 회차 중간에 바뀌지는 않는다.
///
/// # 실패하면 알리고 계속한다
///
/// 잠금은 더하는 안전장치다. 못 걸었다고 치료·복원을 거절하면 권한이 모자란
/// 자리에서 **치료 자체가 막히고**, 그것이 사용자에게 더 나쁘다. 그래서 한 줄
/// 알리고 간다 — 조용히 넘기지 않는다.
fn state_dir(a: &Args) -> std::path::PathBuf {
    let given = a.get("state-dir").map(std::path::PathBuf::from);
    // **운영자가 이름을 준 폴더는 잠그지 않는다** (2026-10-29 에 실측으로 배웠다).
    //
    // 처음 판은 어느 폴더든 잠갔고 **시험 아홉이 종료 5 로 떨어졌다.** 까닭이
    // 곧 제품의 결함이다: `Administrators` 만 남기면 **승격되지 않은 프로세스는
    // 자기가 쓰던 폴더를 잃는다.** 시험은 `--state-dir <임시폴더>` 를 주고
    // 승격 없이 돌므로 그 자리에서 쓰기가 막혔다.
    //
    // 잠금이 지키려는 것은 **기계 공용 자리**(`%PROGRAMDATA%\remedy` ·
    // `/var/lib/remedy`)다. 거기에는 계획·저널·봉인 키가 모이고 아무나 쓸 수
    // 있어서는 안 된다. 반면 `--state-dir` 로 이름을 준 것은 운영자의 선택이고,
    // 이 저장소의 모델은 **운영자가 준 것을 믿는다**(`run` 이 `--plugin` 의
    // 서명을 보지 않는 것과 같은 선).
    let is_default = given.is_none();
    let dir = given.unwrap_or_else(remedy_core::restore::default_state_dir);
    static LOCKED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    // 승격되지 않았으면 걸지 않는다 — 걸면 자기가 못 읽게 될 수 있고, 그 상태로
    // `support-bundle` 조차 못 모은다.
    if !(is_default && remedy_core::elevated() == Some(true)) {
        return dir;
    }
    LOCKED.get_or_init(|| {
        if let Err(e) = remedy_core::platform::statedir::secure(&dir) {
            let lang = ui().lang;
            errln!(
                "{}: {} ({e})",
                lang.t("주의", "Note"),
                lang.t(
                    "복원 정보 폴더를 관리자 전용으로 잠그지 못했습니다",
                    "could not lock the restore folder to administrators only"
                )
            );
        }
    });
    dir
}

fn load_org_public(a: &Args) -> Result<Option<[u8; 32]>, Failure> {
    let Some(p) = a.get("org-public-file") else {
        return Ok(None);
    };
    let raw = std::fs::read(p).map_err(|e| format!("{p}: {e}"))?;
    let pk: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("{p}: 조직 공개키는 32바이트여야 합니다"))?;
    Ok(Some(pk))
}

/// **작성자를 위한 명령.** 실기기가 아니라 손에서 돈다.
///
/// 경고와 오류를 나눈다. 과광범위 경고는 오경보를 내므로 로드를 막지 않는다 —
/// 오류로 막으면 넓은 범위가 실제로 필요한 작성자가 우회로를 만든다.
/// `--file <경로>` 한 쌍. 목록 명령 넷이 같은 모양을 쓴다.
fn file_arg(p: &std::path::Path) -> Vec<String> {
    vec!["--file".to_string(), p.to_string_lossy().to_string()]
}

/// 실행 파일 **옆**의 폴더 하나 — 메뉴 경로의 기본 폴더다.
///
/// # 왜 메뉴에서만 쓰나
///
/// 명령줄의 기본값은 **건드리지 않는다.** 바꾸면 불변식 I1 이 깨진다 — 무인
/// 배포가 읽는 종료 코드와 화면이 같아야 하고, 이미 `%PROGRAMDATA%` 에 격리물이
/// 있는 기계에서 `restore --list` 가 그것을 못 보게 된다. 그래서 이 함수는
/// **인자 없이 띄워 메뉴로 들어온 경로에서만** 쓴다
/// (목표 `remedy_cli` 결정 3·4).
///
/// 실행 파일 자리를 알 수 없으면 **현재 폴더**로 간다 — 거기서 멈추지 않는다.
fn beside_exe(name: &str) -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(name)))
        .unwrap_or_else(|| std::path::PathBuf::from(name))
}

/// 메뉴가 **복원 정보를 두는 자리** — `<exe>\state\` (결정 3 의 (c) ·
/// 2026-10-30 확정).
///
/// # 왜 메뉴에서만인가
///
/// 요구사항은 *"별도로 지정되지 않는 한 실행 파일이 있는 폴더 기준"* 이다.
/// 그러나 **모든 명령의 기본값을 옮기면 불변식 I1 이 깨진다** — 무인 배포와
/// RunOnce 의 재부팅 회차가 읽는 자리가 말없이 바뀌고, 이미 `%PROGRAMDATA%` 에
/// 격리물이 있는 기계에서 `restore --list` 가 그것을 못 보게 된다. 그래서
/// **인자 없이 띄운 경로에서만** 이 자리를 쓰고, 명령줄은 한 글자도 바꾸지
/// 않는다.
///
/// # 잠금은 여기서 건다
///
/// `state_dir()` 의 규칙은 *"운영자가 이름을 준 폴더는 잠그지 않는다"* 이고
/// 그것을 바꾸지 않는다 — 메뉴가 `--state-dir` 로 넘기므로 거기서는 **준
/// 폴더**로 보인다. 그래서 **고른 쪽이 잠근다**: 이 폴더는 운영자가 고른 것이
/// 아니라 **우리가** 고른 것이므로, 계획·저널·봉인 키가 모이는 자리로서
/// 잠가야 한다(기준 8 · S2).
fn imported(f: &std::path::Path) -> Vec<String> {
    let mut v = file_arg(f);
    // **반입은 복원 정보 폴더에 쓴다** — 그래서 메뉴가 쓰는 자리를 함께 준다.
    // `verify` 는 준 파일만 읽으므로 주지 않는다.
    v.push("--state-dir".to_string());
    v.push(menu_state().to_string_lossy().to_string());
    v
}

fn menu_state() -> std::path::PathBuf {
    static LOCKED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    let dir = beside_exe("state");
    // 승격되지 않았으면 걸지 않는다 — `state_dir()` 과 같은 까닭이다(걸면
    // 자기가 못 읽게 될 수 있고, 그 상태로 `support-bundle` 조차 못 모은다).
    if remedy_core::elevated() == Some(true) {
        LOCKED.get_or_init(|| {
            if let Err(e) = remedy_core::platform::statedir::secure(&dir) {
                let lang = ui().lang;
                errln!(
                    "{}: {} ({e})",
                    lang.t("주의", "Note"),
                    lang.t(
                        "복원 정보 폴더의 권한을 조이지 못했습니다",
                        "could not tighten permissions on the restore-data folder"
                    )
                );
            }
        });
    }
    dir
}

/// 메뉴가 **회차를 찾을 때 보는 두 자리** — 쓰는 자리를 먼저.
///
/// 하나로 줄이지 않는 까닭은 [`menu_state`] 의 주석에 있다. 여기서 **잠그지
/// 않는다** — 읽기만 하는 길이고, 기계 공용 자리를 잠그는 것은 `state_dir()`
/// 이 자기 자리에서 한다.
pub(crate) fn menu_state_dirs() -> Vec<std::path::PathBuf> {
    let mine = beside_exe("state");
    let shared = remedy_core::restore::default_state_dir();
    if mine == shared {
        return vec![mine];
    }
    vec![mine, shared]
}

/// 이번 메뉴 작업의 **결과 폴더** — `<exe>\out\<스탬프>\` (결정 4 · 2026-10-30 확정).
///
/// # 왜 회차마다 새 폴더인가
///
/// 전에는 `<exe>\out\` 하나였다. 그러면 **두 번째 검사가 첫 결과를 덮어쓰고**,
/// 메뉴의 *승인한 계획을 수행하기* 가 바로 그 `plan.json` 을 고르므로 사람이
/// 본 것과 수행한 것이 갈릴 수 있다. `apply` 가 `plan_sha256` 으로 봉투의
/// 자기 일관성은 보지만, **어느 회차의 계획인지는 묻지 않는다.**
///
/// # 왜 `run_id` 가 아니라 스탬프인가
///
/// `run_id` 는 `cmd_scan`·`cmd_run` 이 **자기 안에서** 만든다(`RunMeta::now`).
/// 부르는 쪽은 그 값을 알 수 없고, 폴더만 `run_id` 로 짓자고 미리 하나 만들면
/// 폴더 이름과 파일 속 회차가 **다른 값**이 된다 — 그것이 더 나쁘다. 그래서
/// 폴더는 *언제 시작한 작업인가* 로 짓고, 회차 번호는 그 안의 파일이 들고
/// 있다(화면도 `결과 폴더 :` 로 경로를 적는다).
///
/// # 한 작업에 한 폴더
///
/// 작업 차례(`term::task_seq`)가 같은 동안은 **같은 폴더**다 — 검사가 낸 셋(artifacts ·
/// scan · plan)이 한자리에 모인다. 처음에는 프로세스 하나에 폴더 하나였다(메뉴 한 번이
/// 작업 하나였다). 메뉴가 작업 뒤에 다시 뜨게 된 뒤로(목표 remedy_제품화 기준 4) 한
/// 세션에 작업이 여럿이라 **작업이 바뀌면 새 폴더를 짓는다** — 하나로 두면 뒤 작업이
/// 앞 작업의 `scan.json` · `plan.json` 을 덮어쓴다.
fn menu_out() -> std::path::PathBuf {
    static DIR: std::sync::Mutex<Option<(u64, std::path::PathBuf)>> = std::sync::Mutex::new(None);
    let task = term::task_seq();
    let mut dir = DIR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((t, p)) = dir.as_ref() {
        if *t == task {
            return p.clone();
        }
    }
    // `created` 는 RFC3339(`2026-10-30T11:31:00Z`)다. `:` 는 Windows 경로에
    // 쓸 수 없고 `-` 는 빼면 읽기 쉬워진다 — `20261030T113100Z` 가 된다.
    let stamp = remedy_core::pipeline::RunMeta::now()
        .created
        .replace([':', '-'], "");
    let p = fresh_dir(&beside_exe("out"), &stamp);
    *dir = Some((task, p.clone()));
    p
}

/// `base` 아래 `stamp` 폴더 — 같은 초에 앞 작업이 이미 지었으면 `stamp-2` · `stamp-3` …
/// 이름순이 곧 시간순이라는 규칙(`guided::candidate_files`)은 그대로 선다.
fn fresh_dir(base: &std::path::Path, stamp: &str) -> std::path::PathBuf {
    let mut p = base.join(stamp);
    let mut n = 2;
    while p.exists() {
        p = base.join(format!("{stamp}-{n}"));
        n += 1;
    }
    p
}

/// 메뉴 작업의 결과 폴더를 짓는다.
fn make_out(out: &std::path::Path) -> Result<(), Failure> {
    std::fs::create_dir_all(out).map_err(|e| Failure::from(format!("{}: {e}", out.display())))
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("        {l}"))
        .collect::<Vec<_>>()
        .join(
            "
",
        )
}

fn report_scan(
    scan: &remedy_sdk::artifact::ScanEnvelope,
    kind: Option<PluginKind>,
    detect_only: bool,
) {
    let lang = ui().lang;
    let d = remedy_sdk::i18n::deco();
    // 고객에게는 **흔적 몇 건, 위협 몇 건**이면 된다. 증거·그룹·판정 통과는
    // 룰 엔진의 낱말이고 `--verbose` 뒤에 둔다.
    outln!(
        "{} : {}{}{}",
        lang.t("검사 완료", "Scan done"),
        lang.pick(
            format!("흔적 {}건", scan.body.evidence.len()),
            format!("{} trace(s)", scan.body.evidence.len())
        ),
        d.dot(),
        // **`검사 완료` 와 `흔적` 은 바꾸지 않는다.** 하네스 둘이 이 줄로
        // *"한 회차는 한 언어"* 를 재고(`Invoke-P10FVerify` · `reboot-verify` 가
        // `검사 완료|Scan done` 줄 **수**를 센다), `trunc-verify` 가
        // `흔적 [0-9]*건` 을 읽는다. 갈라지는 것은 판정 칸 하나다 (B-2).
        if kind == Some(PluginKind::Check) {
            lang.pick(
                format!("취약 {}건", scan.body.verdicts.len()),
                format!("{} vulnerable", scan.body.verdicts.len()),
            )
        } else {
            lang.pick(
                format!("위협 {}건", scan.body.verdicts.len()),
                format!("{} threat(s)", scan.body.verdicts.len()),
            )
        }
    );
    // **점검은 수만 내고 끝났다** (2026-10-28 까지). 무엇이 취약한지는
    // `scan.json` 에만 있었고 마지막 줄이 사람에게 그 JSON 을 읽으라고 했다 —
    // 치료 쪽은 계획을 줄줄이 적는데 점검만 비어 있었다. 여기서 적는다.
    //
    // **치료 화면은 건드리지 않는다**(`kind` 가 점검일 때만) — 콘솔 기준선
    // 4벌과 하네스가 그 꼴로 돌고 있다.
    //
    // **메뉴에서는 찾기만 하는 룰이 찾은 것도 적는다**(2026-11-08 적대적 검토 4바퀴). 화면이
    // `위협 1건` 만 말하고 끝나 README 의 차례(*결과에 나온 파일* 을 확인하고 지운다)를 따를 수
    // 없었다 — 경로는 결과 폴더의 JSON 에만 있었다(Ebury 실측). 치료하는 룰은 계획이 같은 것을
    // 적으므로 그대로다. **인자로 부른 실행에서는 내지 않는다** — 그 표준 출력은 무인 배포가 읽는
    // 계약이다(불변식 I1).
    // 위협 룰은 **이름(경로)만** 적는다 — 판정을 가른 값이 내용 해시라 사람에게 뜻이 없다.
    let check = kind == Some(PluginKind::Check);
    let listed = check || (detect_only && crate::term::in_session());
    let limit = if ui().verbose {
        usize::MAX
    } else {
        remedy_core::report::FINDINGS_SHOWN
    };
    let (evidence, groups) = (&scan.body.evidence, &scan.body.groups);
    if listed && !scan.body.verdicts.is_empty() {
        let lines = if check {
            let rules = &scan.body.verdict_rules;
            remedy_core::report::check_findings(evidence, groups, rules, lang, limit)
        } else {
            remedy_core::report::threat_findings(evidence, groups, lang, limit)
        };
        for line in lines {
            outln!("{line}");
        }
    }
    // **확인이 필요한 항목**(`verdict.unconfirmed` · 2026-11-09) — 판정 항목과 같은 꼴로 적는다. 무엇을
    // 확인할지는 아래 `주의` 의 사유 줄이 룰의 말로 적는다. 이 칸이 없는 룰에서는 한 줄도 나오지 않는다.
    let notes = &scan.body.observation.unconfirmed;
    if check && !notes.is_empty() {
        let lines = remedy_core::report::unconfirmed_findings(evidence, groups, notes, lang, limit);
        if !lines.is_empty() {
            outln!(
                "  {}",
                lang.t("확인이 필요한 항목:", "Items that need review:")
            );
            for line in lines {
                outln!("{line}");
            }
        }
    }
    if ui().verbose {
        outln!(
            "  {}: evidence {}{}groups {}{}verdicts {}",
            lang.t("자세히", "detail"),
            scan.body.evidence.len(),
            d.dot(),
            scan.body.groups.len(),
            d.dot(),
            scan.body.verdicts.len()
        );
        for g in &scan.body.groups {
            if let Some(r) = &g.excluded_reason {
                outln!(
                    "  {} {} {}: {r}",
                    lang.t("그룹", "group"),
                    g.id,
                    lang.t("제외", "excluded")
                );
            }
        }
    }
    for i in &scan.body.issues {
        errln!("  {} {i}", lang.t("주의", "Note"));
    }
    warn_incomplete(&scan.body.observation, kind);
    note_not_applicable(&scan.body.observation, kind, &scan.body.verdicts);
    note_skipped_denied(&scan.body.observation, kind);
}

/// 종료 코드를 정한다 (설계-02 §8).
///
/// **관측이 불완전하면 "위협 없음" 을 말할 수 없다.** 무인 배포에서 0 은 "이 PC 는
/// 깨끗하다" 로 읽히고 그대로 종료되는데, 관리자 권한 없이 돌아 절반만 본 실행도
/// 지금까지 0 을 냈다. 경고는 stderr 로 나가고 무인 배포에서 stderr 는 버려진다.
///
/// 불완전성은 "없다" 를 뒤집을 뿐 **"있다" 를 뒤집지 못한다** — 위협을 찾았다면
/// 그 발견은 유효하므로 2 가 우선한다.
fn outcome(verdicts: &[String], obs: &Observation, kind: Option<PluginKind>) -> Code {
    if !verdicts.is_empty() {
        // P2 에는 치료가 없으므로 찾으면 항상 이 코드다.
        return Code::FoundNotRemediated;
    }
    if complete_enough(obs, kind) {
        Code::NoThreat
    } else {
        Code::IncompleteObservation
    }
}

/// 이 관측 위에서 "없다" 를 말할 수 있는가 — **플러그인 종류를 함께 본다.**
///
/// 갈래가 여기 있는 이유는 종류를 아는 것이 CLI 뿐이기 때문이다.
/// `Observation::is_complete()` 는 SDK 의 계약이라 그대로 두었다 (B-6).
///
/// `None`(치료)에는 아무 변화가 없다 — 기존 동작이 한 글자도 바뀌지 않는다.
fn complete_enough(obs: &Observation, kind: Option<PluginKind>) -> bool {
    match kind {
        Some(PluginKind::Check) => obs.is_complete_for_check(),
        // 데이터 룰은 `load_local` 이 막아 여기 오지 않는다 — 온다면 가장 엄한 쪽으로 본다.
        None | Some(PluginKind::Data) => obs.is_complete(),
    }
}

/// 점검이 **해당 없음**으로 끝난 것을 stdout 에 적는다.
///
/// # 왜 stdout 이고, 왜 `주의:` 가 아닌가
///
/// B-6 이후 종료 0 은 두 뜻을 담는다 — *"선언한 범위를 보았고 거기서 없다"* 와
/// *"그 범위가 이 기계에 아예 없다"*. 어느 쪽인지는 **결과의 일부**이므로
/// stderr 로 보내지 않는다(무인 배포는 stderr 를 버린다 — 이 저장소가 두 번
/// 적어 둔 사실이다). 그리고 불완전이 아니므로 머리말은 `주의:` 가 아니라
/// `안내:` 다 — `주의:` 는 *"다 보지 못했다"* 의 표식이다.
///
/// **경로를 반드시 적는다.** 코어는 미설치와 선언 오타를 가릴 수 없으므로
/// (`is_complete_for_check` 참조) 그 판단은 읽는 사람 몫이고, 판단할 재료가
/// 화면에 없으면 0 은 그냥 침묵이 된다.
fn note_not_applicable(obs: &Observation, kind: Option<PluginKind>, verdicts: &[String]) {
    if kind != Some(PluginKind::Check) || !obs.all_roots_missing() {
        return;
    }
    // **판정이 섰으면 해당 없음이 아니다.** 루트가 전부 없다고 적혀 있어도 다른
    // 수집기(레지스트리 · 프로세스 · 고정 자리 subject)가 증거를 냈을 수 있다 —
    // 그때 *"점검 대상이 이 기계에 없습니다"* 와 *"취약 1건"* 이 한 화면에 함께
    // 나오고 종료 코드는 2 다. 둘 중 하나는 거짓이고, 거짓인 쪽은 이 줄이다.
    if !verdicts.is_empty() {
        return;
    }
    if !complete_enough(obs, kind) {
        // 다른 사유가 섞였다 — 그쪽은 `warn_incomplete` 가 6 과 함께 말한다.
        return;
    }
    let lang = ui().lang;
    let list = obs.missing_roots.join(" · ");
    outln!(
        "  {} {}",
        lang.t("안내:", "Info:"),
        lang.pick(
            format!(
                "점검 대상이 이 기계에 없습니다 — 선언한 자리 {}곳이 전부 존재하지 않습니다: {list}",
                obs.declared_roots
            ),
            format!(
                "the subject of this check is not on this machine - all {} declared roots are absent: {list}",
                obs.declared_roots
            )
        )
    );
    outln!(
        "        {}",
        lang.t(
            "경로가 틀린 것이 아닌지도 함께 보십시오.",
            "Please also confirm the paths are not simply wrong."
        )
    );
}

/// 화면에 보이는 거부 경로의 개수.
///
/// **전수가 아니다.** 비관리자로 돌면 거부가 수십 곳이 될 수 있고, 그것을 다
/// 쏟으면 정작 읽어야 할 결론 줄이 위로 밀린다. 전수는 `denied_dirs` 가 세고,
/// 표본은 산출물에 최대 `DENIED_SAMPLE`(32)개가 실린다 — 화면은 **어디를 봐야
/// 하는가** 의 실마리만 준다.
const DENIED_SHOWN: usize = 3;

/// 관측이 불완전하면 왜 그런지 전부 적는다. 한 줄로 뭉뚱그리면 무엇을 고쳐야
/// 하는지 알 수 없다.
fn warn_incomplete(obs: &Observation, kind: Option<PluginKind>) {
    if complete_enough(obs, kind) {
        return;
    }
    let lang = ui().lang;
    errln!(
        "  {} {}",
        lang.t("주의:", "Note:"),
        if kind == Some(PluginKind::Check) {
            lang.t(
                "아래 까닭으로 '취약하지 않다' 고 판단할 수 없습니다:",
                "'not vulnerable' cannot be concluded, for these reasons:",
            )
        } else {
            lang.t(
                "아래 까닭으로 '위협 없음' 이라고 판단할 수 없습니다:",
                "'no threat' cannot be concluded, for these reasons:",
            )
        }
    );
    for l in reason_lines(obs, lang, kind == Some(PluginKind::Check)) {
        errln!("{l}");
    }
}

/// 점검이 **건너뛴** 거부된 자리를 stdout 에 적는다(결정 K2 · 2026-11-18).
///
/// 관리자로도 열리지 않는 폴더는 점검의 불완전 사유가 아니다([`Observation::check_skips_denied`]) — 사유 줄에서
/// 빠지는 대신 여기서 그 자리를 적는다. 결과의 일부라 stdout 이고, 불완전이 아니라 머리말은 `안내:` 다
/// ([`note_not_applicable`] 과 같은 까닭). **판정이 섰어도 적는다** — 그 폴더 안은 보지 않았다.
fn note_skipped_denied(obs: &Observation, kind: Option<PluginKind>) {
    if kind != Some(PluginKind::Check) {
        return;
    }
    for l in skipped_denied_lines(obs, ui().lang) {
        outln!("{l}");
    }
}

/// [`note_skipped_denied`] 의 줄 — 건너뛴 거부가 없으면 비어 있다. 출력과 나눈 까닭은 [`denied_lines`] 와 같다.
///
/// **다른 까닭으로 다 보지 못했으면 *"모두 확인했습니다"* 라고 하지 않는다** — 그때는 `주의:` 줄이 그 까닭을 말하고
/// 결과 줄이 *"다 보지 못해"* 인데, 같은 stdout 에 *"모두 확인했습니다"* 가 서면 스스로 어긋난다(2026-11-18 독립 검토).
fn skipped_denied_lines(obs: &Observation, lang: remedy_core::report::Lang) -> Vec<String> {
    if !obs.check_skips_denied() {
        return Vec::new();
    }
    // **폴더 수로 센다.** `denied_dirs` 는 열기 횟수라 같은 뿌리를 subject 마다 걷는 룰(file · text_config)에서는 한
    // 폴더를 두세 번 센다 — 그대로 적으면 *"폴더 2곳"* 아래 같은 경로가 두 줄이다(2026-11-18 독립 검토). 건너뛸 때는
    // 표본이 전수다(`check_skips_denied`).
    let mut uniq: Vec<String> = Vec::new();
    for p in &obs.denied_paths {
        if !uniq.contains(p) {
            uniq.push(p.clone());
        }
    }
    let shown = Observation {
        denied_dirs: uniq.len(),
        denied_paths: uniq,
        ..obs.clone()
    };
    let n = shown.denied_dirs;
    let folders = if n == 1 { "folder" } else { "folders" };
    let line = if obs.is_complete_for_check() {
        lang.pick(
            format!("관리자 권한으로도 열리지 않는 폴더 {n}곳을 빼고 모두 확인했습니다."),
            format!("checked all but {n} {folders}, which not even an administrator can open."),
        )
    } else {
        lang.pick(
            format!("관리자 권한으로도 열리지 않는 폴더 {n}곳은 건너뛰었습니다."),
            format!("skipped {n} {folders} that not even an administrator can open."),
        )
    };
    let mut v = vec![format!("  {} {line}", lang.t("안내:", "Info:"))];
    v.extend(denied_lines(&shown, lang));
    v
}

/// 사유 줄과 **그 사유 바로 아래의** 거부된 자리 표본.
///
/// 표본을 사유 줄 맨 끝에 붙이면, 사유가 둘일 때(접근 거부 + 룰의 확인 필요) 목록이 둘째 사유 밑에
/// 서서 그 사유의 경로로 읽혔다(2026-11-12 · 리눅스 컨테이너의 PHP 세션 점검). 거부 사유는 잘림
/// 사유 다음 자리다 — [`Observation::reasons_in`] 의 차례이고, 시험이 그것을 붙잡는다.
///
/// `check` 이고 점검이 그 거부를 건너뛰면(K2) 거부 사유와 표본을 싣지 않는다 — 그 자리는
/// [`note_skipped_denied`] 가 적는다.
fn reason_lines(obs: &Observation, lang: remedy_core::report::Lang, check: bool) -> Vec<String> {
    if check && obs.check_skips_denied() {
        return obs
            .reasons_for_check_in(lang)
            .iter()
            .map(|r| format!("     - {r}"))
            .collect();
    }
    let reasons = obs.reasons_in(lang);
    let denied_at = (obs.denied_dirs > 0).then_some(usize::from(obs.truncated));
    let mut out = Vec::new();
    for (i, r) in reasons.iter().enumerate() {
        out.push(format!("     - {r}"));
        if denied_at == Some(i) {
            out.extend(denied_lines(obs, lang));
        }
    }
    if denied_at.is_none_or(|i| i >= reasons.len()) {
        out.extend(denied_lines(obs, lang));
    }
    out
}

/// 거부된 자리 **몇 곳**을 화면에 적는다.
///
/// # 개수만으로는 다음 할 일이 정해지지 않는다
///
/// `denied_dirs` 는 *"이 스냅샷을 믿어도 되는가"* 에 답한다. 답이 "아니다" 일
/// 때 사람이 할 일은 **어디가 막혔는지** 를 보는 것인데, 그 경로는 산출물
/// (`artifacts.json` · `scan.json` · `plan.json`) 에만 있었다.
///
/// # 계획이 없는 회차에는 그 산출물도 가지 않는다 (2026-09-14 실측)
///
/// `support-bundle` 은 상태 디렉터리의 `plan.json` 을 담고, 그 계획은 `apply`
/// 가 돌아야 저장된다(`remedy-apply` 의 `save_plan`). `scan` · `--dry-run` ·
/// **종료 코드 6** 으로 끝난 회차는 계획이 없어 `run.log` 가 그 회차의 유일한
/// 기록인데, 거기에는 개수만 남았다 — 하필 관측이 불완전했던 회차에서만
/// 경로가 사라진다.
///
/// 그래서 **화면에 적는다.** `run.log` 는 화면에 나간 줄을 그대로 복사하므로
/// (`tee.rs`) 한 자리를 고치면 `scan` · `--dry-run` · 치료 회차가 전부 덮인다.
/// 거부 사유 바로 아래에 붙이는 것은 [`reason_lines`] 다.
///
/// **출력과 나눈 이유**는 시험이 문자열을 그대로 보게 하려는 것이다. `errln!`
/// 을 가로채려면 전역 상태를 건드려야 하고, 그러면 병렬로 도는 다른 시험과
/// 얽힌다 — 흔들리는 시험은 없는 시험보다 나쁘다.
fn denied_lines(obs: &Observation, lang: remedy_core::report::Lang) -> Vec<String> {
    // 낡은 산출물을 읽었거나 거부가 없었으면 이 절이 아예 나오지 않는다 —
    // 빈 머리말은 "아무 데도 안 막혔다" 로 잘못 읽힌다.
    if obs.denied_paths.is_empty() {
        return Vec::new();
    }
    let mut v = vec![format!("       {}", lang.t("거부된 자리:", "denied at:"))];
    let shown = obs.denied_paths.len().min(DENIED_SHOWN);
    for p in &obs.denied_paths[..shown] {
        v.push(format!("         {p}"));
    }
    // **표본이 전수가 아니다.** `denied_dirs` 는 전부를 세고 이 목록은 앞의 몇
    // 개다 — 그 차이를 적지 않으면 보인 줄이 전부로 읽힌다. 표본 자체가
    // 상한(`DENIED_SAMPLE`)에 걸려 잘렸다면 그 몫도 이 수에 들어간다.
    let rest = obs.denied_dirs.saturating_sub(shown);
    if rest > 0 {
        v.push(format!(
            "         {}{rest}{}",
            lang.t("외 ", "and "),
            lang.t("곳", " more")
        ));
    }
    v
}

// ─────────────────────────────────────────────────────── restore (P5)

#[cfg(test)]
mod tests;
