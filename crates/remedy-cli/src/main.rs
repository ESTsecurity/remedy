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

/// 전역 플래그를 떼어 내고 나머지를 돌려준다.
fn split_global(args: Vec<String>) -> (Vec<String>, Option<String>, bool, bool) {
    let mut rest = Vec::with_capacity(args.len());
    let mut lang = None;
    let mut ascii = None;
    let mut verbose = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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
    let ascii_on = remedy_sdk::i18n::detect_ascii(ascii);
    (rest, lang, ascii_on, verbose)
}

fn main() -> ExitCode {
    let (args, mut lang_flag, ascii, verbose) = split_global(std::env::args().skip(1).collect());
    // `--lang kr` 처럼 모르는 값은 무시하되 **말한다.** 조용히 영어로 가면 사용자는
    // 왜 영어인지 모른다. 알림은 두 언어로 — 어느 쪽을 읽든 이해되게.
    let unknown_lang = lang_flag
        .as_deref()
        .filter(|v| remedy_sdk::i18n::Lang::try_parse(v).is_none())
        .map(str::to_string);
    if unknown_lang.is_some() {
        lang_flag = None;
    }
    let lang = {
        // Windows 는 `LANG` 을 설정하지 않는다 — 받아서 더블클릭한 한국어 PC 가
        // 영어로 떨어졌다(실측 2026-09-09). OS 가 말하는 로케일을 넘긴다.
        let l = remedy_sdk::i18n::Lang::detect_with(
            lang_flag.as_deref(),
            remedy_core::user_locale().as_deref(),
        );
        // 한글을 못 그리는 자리에 한글을 내보내지 않는다. 명시했을 때만 예외.
        let explicit = lang_flag.is_some() || std::env::var("REMEDY_LANG").is_ok();
        if ascii && !explicit {
            remedy_sdk::i18n::Lang::En
        } else {
            l
        }
    };
    remedy_sdk::i18n::init(lang, ascii);
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
    if let Some(note) = remedy_core::integrity::advisory(&integrity) {
        // 막지 않는 경우에도 말한다. 조용히 넘어가면 "확인했다" 로 읽힌다.
        errln!("{}: {note}", ui().lang.t("알림", "Notice"));
    }

    let outcome = match cmd {
        Some("--version") | Some("-V") => {
            outln!(
                "{} {} (remedy)",
                remedy_core::report::brand::product(ui().lang),
                env!("CARGO_PKG_VERSION")
            );
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
        Some("scan") => admin_gate().and_then(|()| cmd_scan(rest)),
        Some("restore") => admin_gate().and_then(|()| cmd_restore(rest)),
        Some("apply") => admin_gate()
            .and_then(|()| integrity_gate(&integrity))
            .and_then(|()| cmd_apply(rest, &integrity)),
        Some("run") => admin_gate()
            .and_then(|()| integrity_gate(&integrity))
            .and_then(|()| cmd_run(rest, &integrity)),
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
                    guided::Outcome::ShowUsage | guided::Outcome::NothingUsable
                );
                if !ends_here {
                    term::task_begin(changes_system(&picked));
                }
                let flow = flow_of(&picked);
                // **하기 전에 무엇을 하는지** — 치료 · 복원은 목록과 승인이 그 자리다.
                // 검사만 그것이 없었다(목표 remedy_제품화 기준 6(a)).
                if session && matches!(flow, Flow::Scan) {
                    outln!(
                        "{}",
                        ui().lang.t(
                            "검사만 합니다 — 아무것도 바꾸지 않습니다. 찾으면 치료할 계획을 세워 둡니다.",
                            "Scan only — nothing is changed. If something is found, a treatment plan is kept."
                        )
                    );
                }
                let outcome = match picked {
                    guided::Outcome::ShowUsage => {
                        usage(false);
                        Ok(Code::NoThreat)
                    }
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
                        admin_gate()
                            .and_then(|()| integrity_gate(&integrity))
                            .and_then(|()| cmd_run(&args, &integrity))
                    }
                    // **묶음 A — 같은 자리로 보낸다.** 위 `Some("selftest")` 갈래와
                    // 똑같은 호출이다. 메뉴가 자기 화면이나 자기 가드를 갖지 않는
                    // 이유는 `RunWith` 와 같다 — 두 벌이 되면 갈라지고, 갈라지면
                    // 메뉴로 들어온 사람만 다른 답을 받는다.
                    guided::Outcome::Plain(p) => match p {
                        menu::Plain::SelfTest => Ok(selftest()),
                        menu::Plain::Version => {
                            outln!(
                                "{} {} (remedy)",
                                remedy_core::report::brand::product(ui().lang),
                                env!("CARGO_PKG_VERSION")
                            );
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
                    errln!(
                        "  ({} {}: {})",
                        lang.t("종료 코드", "exit code"),
                        f.code.code(),
                        f.code.meaning_in(lang)
                    );
                }
                if ends_here || !session {
                    wait_before_closing();
                    break Ok(code);
                }
                // 작업 하나가 끝났다 — 로그를 닫고 메뉴로 돌아간다.
                tee::close();
                term::task_end(code);
                last = Some(code);
                back_to_menu(flow, code);
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
            lang.t(
                concat!(
                    "관리자 권한이 필요합니다. 이 도구는 예약 작업, HKLM, 다른 사용자의 파일을 읽고\n",
                    "  고치며, 그것들은 관리자만 열 수 있습니다. 권한 없이 돌면 감염된 기계에서도\n",
                    "  증거가 나오지 않습니다."
                ),
                concat!(
                    "Administrator rights are required. This tool reads and fixes scheduled tasks,\n",
                    "  HKLM and other users' files, which only an administrator can open. Without\n",
                    "  them an infected machine yields no evidence."
                ),
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
                concat!(
                    "root 권한이 필요합니다. 이 도구는 시스템 전역의 지속성, 설정을 읽고 고치며,\n",
                    "  그것들은 root 만 열 수 있습니다. 권한 없이 돌면 감염된 기계에서도 증거가\n",
                    "  나오지 않습니다."
                ),
                concat!(
                    "root is required. This tool reads and fixes system-wide persistence and\n",
                    "  configuration, which only root can open. Without it an infected machine\n",
                    "  yields no evidence."
                ),
            ),
            lang.t("sudo 로 다시 부르십시오.", "Run again with sudo.")
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
fn changes_system(o: &guided::Outcome) -> bool {
    match o {
        guided::Outcome::RunWith(_) => true,
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
enum Flow {
    Scan,
    Treat,
    Restore,
    Verify,
    Other,
}

fn flow_of(p: &guided::Outcome) -> Flow {
    match p {
        guided::Outcome::WithPlugin(menu::WithPlugin::Scan(_)) => Flow::Scan,
        guided::Outcome::WithPlugin(menu::WithPlugin::Run(_))
        | guided::Outcome::RunWith(..)
        | guided::Outcome::WithFile(menu::WithFile::Apply(_), _) => Flow::Treat,
        guided::Outcome::WithRun(menu::WithRun::Restore(_)) => Flow::Restore,
        guided::Outcome::WithPlugin(menu::WithPlugin::Verify(_)) => Flow::Verify,
        _ => Flow::Other,
    }
}

/// 작업 뒤에 고를 만한 메뉴 줄 — 결과에 맞는 것만(목표 remedy_제품화 기준 6(d)).
/// 전에는 다음 할 일을 명령줄로만 적었다(`remedy restore --run …`).
fn next_steps(flow: Flow, code: Code) -> Vec<(&'static str, menu::Line)> {
    let lang = ui().lang;
    match (flow, code) {
        (Flow::Scan, Code::FoundNotRemediated) => vec![
            (
                lang.t("찾은 것을 치료하려면", "To treat what was found"),
                menu::Line::Treat,
            ),
            (
                lang.t(
                    "방금 세운 계획대로 치료하려면",
                    "To treat with the plan just made",
                ),
                menu::Line::Apply,
            ),
        ],
        (Flow::Treat, Code::Remediated) => vec![
            (lang.t("되돌리려면", "To undo it"), menu::Line::Undo),
            (
                lang.t("치료가 유지되는지 보려면", "To check that it held"),
                menu::Line::Verify,
            ),
            (
                lang.t("오탐이라 신고하려면", "To report a false positive"),
                menu::Line::Report,
            ),
        ],
        (Flow::Treat | Flow::Verify, Code::FoundNotRemediated)
        | (Flow::Restore, Code::NoThreat) => {
            vec![(lang.t("치료하려면", "To treat it"), menu::Line::Treat)]
        }
        (Flow::Treat | Flow::Restore, Code::PartialFailure) => vec![
            (
                lang.t("남은 것을 이어서 하려면", "To finish what is left"),
                menu::Line::Resume,
            ),
            (lang.t("신고하려면", "To report it"), menu::Line::Report),
        ],
        _ => Vec::new(),
    }
}

/// 작업이 끝나고 메뉴로 돌아간다. 구분선 · 다음 할 일을 남기고 **Enter 를 기다린다** —
/// 메뉴가 곧바로 다시 서면 결과 줄이 창 밖으로 밀린다(21줄 메뉴 · 30줄 창 · 2026-11-06
/// 이미지). 기다리는 줄은 화면을 붙잡는 장치라 stderr 로 낸다(`wait_before_closing` 과 같다).
fn back_to_menu(flow: Flow, code: Code) {
    let lang = ui().lang;
    let d = remedy_sdk::i18n::deco();
    outln!();
    outln!("{}", d.rule());
    let next: Vec<(&str, usize, &str)> = next_steps(flow, code)
        .into_iter()
        .filter_map(|(why, l)| menu::line(l).map(|(n, label)| (why, n, label)))
        .collect();
    if !next.is_empty() {
        outln!("{}", lang.t("다음 할 일", "Next"));
        for (why, n, label) in next {
            outln!("  {why}{}{n}. {label}", d.dash());
        }
        outln!();
    }
    eprint!(
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

fn wait_before_closing() {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return;
    }
    let lang = ui().lang;
    // stdout 은 화면의 결과이고 이 줄은 화면을 붙잡는 장치다 — stderr 로 낸다.
    // 그래야 `remedy > 화면.txt` 로 갈무리한 파일에 프롬프트가 섞이지 않는다.
    eprintln!();
    eprint!(
        "{}",
        lang.t(
            "이 창을 닫으려면 Enter 를 누르십시오. ",
            "Press Enter to close this window. "
        )
    );
    use std::io::Write;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

/// 사용법 화면.
///
/// # 왜 스트림이 인자인가
///
/// **일부러 부른 사용법은 결과이고, 오류에 딸려 나온 사용법은 오류다.**
/// `--help` 를 친 사람이 `remedy --help > 화면.txt` 로 갈무리하려 하면 stderr 로
/// 나가는 화면은 빈 파일을 남긴다 — 지원 담당자가 가장 먼저 시키는 동작이
/// 실패한다. 반대로 `알 수 없는 명령` 뒤의 사용법까지 stdout 으로 보내면
/// 무인 배포의 파이프에 오류 본문이 섞인다.
///
/// 그래서 부르는 자리가 정한다.
fn usage(stderr: bool) {
    // 본문은 `say!` 하나로만 쓴다 — 스트림은 이 매크로가 정한다.
    macro_rules! say {
        () => {
            $crate::tee::emit(stderr, String::new())
        };
        ($($arg:tt)*) => {
            $crate::tee::emit(stderr, format!($($arg)*))
        };
    }
    let lang = ui().lang;
    let d = remedy_sdk::i18n::deco();
    say!(
        "{} {}",
        remedy_core::report::brand::product(lang),
        env!("CARGO_PKG_VERSION")
    );
    say!("{}", d.rule());
    say!();
    match lang {
        remedy_sdk::i18n::Lang::Ko => {
            say!("사용법");
            say!("  remedy run --plugin <plugin.yaml> [--yes]       검사하고 치료합니다");
            say!("  remedy run --plugin <plugin.yaml> --dry-run     검사만 하고 아무것도 바꾸지 않습니다");
            say!("  remedy restore --list                            되돌릴 수 있는 회차를 보여 줍니다");
            say!("  remedy restore --run <run_id> [--yes]           치료를 되돌립니다");
            say!("  remedy --help-all                               모든 명령과 옵션");
            say!();
            if cfg!(windows) {
                say!("  관리자 권한으로 실행해야 합니다. 없으면 시작하지 않고 종료 코드 5 를 냅니다.");
            } else {
                say!(
                    "  root 권한으로 실행해야 합니다. 없으면 시작하지 않고 종료 코드 5 를 냅니다."
                );
            }
            say!("  --yes 없이 실행하면 계획을 보여 주고 승인을 기다립니다.");
            say!();
            say!("옵션");
            say!("  --lang ko|en   출력 언어 (PC 가 한국어면 한국어, 아니면 영어 · REMEDY_LANG 으로도)");
            say!("  --ascii        장식 문자를 ASCII 로 (한글을 못 그리는 터미널)");
            say!("  --verbose      자세한 진단 출력");
        }
        remedy_sdk::i18n::Lang::En => {
            say!("Usage");
            say!("  remedy run --plugin <plugin.yaml> [--yes]       scan and treat");
            say!("  remedy run --plugin <plugin.yaml> --dry-run     scan only, change nothing");
            say!("  remedy restore --list                            list the runs that can be undone");
            say!("  remedy restore --run <run_id> [--yes]           undo a treatment");
            say!("  remedy --help-all                               every command and option");
            say!();
            if cfg!(windows) {
                say!("  Run as Administrator. Without it nothing starts and the exit code is 5.");
            } else {
                say!("  Run as root. Without it nothing starts and the exit code is 5.");
            }
            say!("  Without --yes the plan is shown and approval is awaited.");
            say!();
            say!("Options");
            say!("  --lang ko|en   output language (Korean on a Korean PC, else English; REMEDY_LANG also works)");
            say!("  --ascii        ASCII-only decorations (terminals without Unicode fonts)");
            say!("  --verbose      detailed diagnostics");
        }
    }
    // ── 종료 코드는 여기 없다 ────────────────────────────────────
    //
    // **이 표의 독자는 무인 배포를 짜는 사람이다.** 첫 화면 34줄 중 9줄이 그
    // 표였고, 받아서 더블클릭한 사람에게 `6  관측 불완전 — '위협 없음' 을 말할
    // 수 없다` 는 읽을 수 없는 문장이다.
    //
    // **숨기지 않고 어디 있는지 말한다.** 조용히 빼면 그 표를 알던 사람이
    // 없어졌다고 생각한다.
    say!();
    say!(
        "{}",
        lang.t(
            "종료 코드 여덟 가지는 `remedy --help-all` 에 있습니다 (무인 배포용).",
            "The eight exit codes are in `remedy --help-all` (for unattended deployment)."
        )
    );
    say!();
    say!("{}", remedy_core::report::brand::copyright());
}

/// 전체 사용법. 개발자·운영자용 명령까지. **이 화면의 설명은 한국어다** —
/// 플러그인 작성자와 운영자가 보는 자리이고, 고객 화면이 아니다.
fn usage_all() {
    // `--help-all` 은 언제나 일부러 부르는 것이라 갈래가 없다. 스트림 규칙은
    // `usage` 의 문서에.
    macro_rules! say {
        () => {
            $crate::tee::emit(false, String::new())
        };
        ($($arg:tt)*) => {
            $crate::tee::emit(false, format!($($arg)*))
        };
    }
    let lang = ui().lang;
    say!(
        "{} {} (remedy)",
        remedy_core::report::brand::product(lang),
        env!("CARGO_PKG_VERSION")
    );
    say!();
    if cfg!(windows) {
        say!("  시스템을 변경하는 명령(collect·scan·run·apply·resume·restore·verify)은");
        say!("  관리자 권한을 요구한다. 없으면 시작하지 않고 종료 코드 5 를 낸다.");
    } else {
        say!("  시스템을 변경하는 명령(collect·scan·run·apply·resume·restore·verify)은");
        say!("  root 권한을 요구한다. 없으면 시작하지 않고 종료 코드 5 를 낸다.");
    }
    say!();
    say!("  run      --plugin <plugin.yaml> [--out-dir <디렉터리>] [apply 와 같은 옵션]");
    say!("           수집부터 치료까지 한 번에.");
    say!("  restore  --list");
    say!("           되돌릴 수 있는 회차를 보여 준다. 키 없이 헤더만 읽는다.");
    say!("  restore  (--run <run_id> | --container <파일>) [--entry <id>]... [--yes]");
    say!("           [--extract-to <디렉터리>] [--passphrase-file <파일>]");
    say!("           [--org-key-file <파일>] [--state-dir <디렉터리>]");
    say!("           --yes 없이는 계획만 보인다. 복원할 수 없는 항목을");
    say!("           복원 전에 목록으로 고지한다.");
    say!("           --extract-to 는 원래 경로가 아니라 지정한 폴더로 내보낸다.");
    say!("           제자리 복원은 원래 머신에서만 보장된다.");
    say!("  scan     --plugin <plugin.yaml> --out-dir <디렉터리> [--config <설정.yaml>]");
    say!("  apply    --plan <파일> [--yes] [--dry-run] [--events <파일|->]");
    say!(
        "           [--state-dir <디렉터리>] [--passphrase-file <파일>] [--org-public-file <파일>]"
    );
    say!("           실제로 파일을 바꾸는 명령은 이것뿐이다. --yes 없이");
    say!("           터미널이 아니면 거절한다 — 승인할 사람이 없기 때문이다.");
    say!("  verify   --plugin <plugin.yaml> [--run <run_id>] [--state-dir <디렉터리>]");
    say!("           [--out <파일>]");
    say!("           재수집 + 재평가. 경로가 비었는지가 아니라 판정이");
    say!("           다시 나오는지 확인한다.");
    say!("  resume   [--run <run_id>] [--state-dir <디렉터리>] [--yes]");
    say!("           [--plugin <plugin.yaml>]");
    say!("           저장된 계획을 이어 실행한다. 절대 재스캔하지 않는다 —");
    say!("           사용자가 승인한 것과 다른 일이 벌어지면 안 되기 때문이다.");
    say!("           계획이 재부팅 뒤 재평가를 원하면 --plugin 이 있어야 그것을 건다.");
    say!("  support-bundle --run <run_id> [--state-dir <디렉터리>] [--out <디렉터리>]");
    say!("           신고에 붙일 파일을 한 폴더로 모은다. 담은 항목과");
    say!("           '일부러 담지 않은 것' 절을 함께 표시한다. 제출은 사람이 한다.");
    say!();
    say!("  개발자·플러그인 작성자용 (설명은 한국어)");
    say!("  collect  --out <파일> [--root <경로>]... [--plugin <plugin.yaml>]");
    say!("           플러그인 없이 --root 만 주면 진단 모드다.");
    say!("  evaluate --artifacts <파일> --plugin <plugin.yaml> --out <파일>");
    say!("  plan     --scan <파일> --plugin <plugin.yaml> --out <파일> [--config <설정.yaml>]");
    say!("           --plugin 이 없으면 가드만 돌고 Action 은 도출되지 않는다.");
    say!("  plugin lint <plugin.yaml>...");
    say!("           배포 전에 작성자가 직접 돌린다. 참조·정규식·범위·방향 제약.");
    say!(
        "  plugin verify --dir <플러그인 디렉터리> [--public-key <파일>] [--state-dir <디렉터리>]"
    );
    say!("  revocation verify --file <목록> [--public-key <파일>]");
    say!("  revocation import --file <목록> [--state-dir <디렉터리>] [--public-key <파일>]");
    say!("  allowlist  verify --file <목록> [--public-key <파일>]");
    say!("  allowlist  import --file <목록> [--state-dir <디렉터리>] [--public-key <파일>]");
    say!("  selftest | --version");
    say!();
    // **위 사용법에 열 번 넘게 나오는데 설명이 한 줄도 없었다** (2026-10-28 까지).
    // 처음 받은 사람이 `--out-dir` 과 `--state-dir` 을 가르지 못한다 — 하나는
    // 이번 회차의 결과이고 하나는 **격리한 파일 원본과 복원 기록이 있는 폴더**라,
    // 섞어 쓰면 지우고 나서 복원할 수 없다. 공통 옵션 네 개를 여기서 말한다.
    //
    // **처음 쓴 설명은 *"되돌리기가 사는 곳이다"* 였다** (2026-10-28 에 고쳤다).
    // 폴더를 의인화하고(비유), 동작을 주어로 세우고(명사화), `저널` 이라는 엔진
    // 낱말을 썼다 — 업계 화면은 *"무엇이 있는 폴더"* 라고 쓴다. 사용자가 읽고
    // 짚었다: 주어는 **격리된 파일과 복원 기록**이다.
    say!("  자주 쓰는 옵션");
    say!("  --plugin <파일>     무엇을 찾을지 적은 룰 파일. 이 파일이 없으면");
    say!("                      아무것도 탐지하지 않는다 — 탐지 내용은 전부 룰에 있다.");
    say!("  --out-dir <폴더>    이번 회차의 결과를 쓸 폴더. 지워도 된다.");
    say!("  --state-dir <폴더>  격리한 파일 원본과 복원 기록이 있는 폴더. 지우면");
    say!("                      restore 로 복원할 수 없다. 회차마다 바꾸지 말고");
    say!("                      기계마다 한 곳을 정해 쓴다.");
    say!("  --run <회차 번호>   어느 회차를 가리키는지. 치료가 끝나면 화면에");
    say!("                      표시되고, restore --list 로 다시 찾을 수 있다.");
    say!();
    say!("  --lang ko|en   사람이 읽는 출력의 언어. 없으면 REMEDY_LANG, 그것도 없으면");
    say!("                 로케일, 그것도 아니면 영어. 파일 출력은 언제나 UTF-8 이다.");
    say!("  --ascii        장식 문자를 ASCII 로. UTF-8 이 아닌 로케일에서는 자동이다.");
    say!("  --verbose      룰 진단·산출 파일 경로 같은 자세한 출력.");
    say!();
    say!("종료 코드:");
    for e in remedy_sdk::artifact::ExitCode::ALL {
        say!("  {}  {}", e.code(), e.meaning_in(lang));
    }
}

fn selftest() -> Code {
    let t = remedy_core::self_test();
    outln!("링크된 크레이트 {}종", t.linked.len());
    for name in &t.linked {
        outln!("  {name}");
    }
    outln!(
        "YARA 스파이크: compiled={} matched={}",
        t.yara.compiled,
        t.yara.matched
    );
    outln!("빌드 타깃: {}", t.target);

    if t.ok() {
        outln!("selftest OK");
        Code::NoThreat
    } else {
        errln!("selftest FAILED");
        Code::PartialFailure
    }
}

// ─────────────────────────────────────────────────────── 인자

/// `--key value` 만 받는다. P2 에 필요한 최소한이다.
struct Args {
    single: std::collections::BTreeMap<String, String>,
    multi: std::collections::BTreeMap<String, Vec<String>>,
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut single = std::collections::BTreeMap::new();
    let mut multi: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut i = 0;
    while i < raw.len() {
        let k = raw[i].strip_prefix("--").ok_or_else(|| {
            ui().lang.pick(
                format!("'--이름 값' 형태여야 합니다: {}", raw[i]),
                format!("expected '--name value', got: {}", raw[i]),
            )
        })?;
        // 값 없는 스위치(`--yes`). 다음 토큰이 없거나 그것도 `--` 로 시작하면
        // 이 인자는 스위치다. 값이 필요한 인자는 `need` 가 빈 값을 거른다.
        let is_flag = match raw.get(i + 1) {
            None => true,
            Some(next) => next.starts_with("--"),
        };
        let v = if is_flag {
            String::new()
        } else {
            raw[i + 1].clone()
        };
        multi.entry(k.to_string()).or_default().push(v.clone());
        single.insert(k.to_string(), v);
        i += if is_flag { 1 } else { 2 };
    }
    Ok(Args { single, multi })
}

impl Args {
    fn need(&self, k: &str) -> Result<&str, String> {
        match self.single.get(k).map(String::as_str) {
            Some("") => Err(ui().lang.pick(
                format!("--{k} 옵션에 값이 없습니다"),
                format!("--{k} has no value"),
            )),
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
    out!("{}", remedy_core::report::render_banner(&b, lang));
    outln!();
}

/// 시작한 뒤 지난 시간. 마무리 화면이 적는다.
fn elapsed_since(start: std::time::Instant) -> u64 {
    start.elapsed().as_secs()
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
    let m: PluginManifest = serde_yaml_ng::from_str(&text).map_err(|e| format!("{path}: {e}"))?;

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
fn warn_unresolved_extra(items: &[remedy_core::Unresolved]) {
    if items.is_empty() {
        return;
    }
    let lang = ui().lang;
    errln!();
    errln!(
        "  {} {}",
        lang.t("주의:", "Note:"),
        lang.pick(
            format!("선언한 것 {}건이 해소되지 않았습니다:", items.len()),
            format!("{} declared item(s) could not be resolved:", items.len())
        )
    );
    for u in items {
        errln!("     - {}: {}", u.at, u.reason);
    }
}

fn cmd_collect(raw: &[String]) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    let out = a.need("out")?;
    let meta = RunMeta::now();

    // 종류는 match 밖으로 꺼낸다 — 아래 종료 코드 갈래가 그것을 본다.
    let mut kind = None;
    let env = match a.single.get("plugin") {
        Some(p) => {
            let m = load_manifest(p)?;
            kind = m.kind;
            warn_unsupported(&m);
            // `collect` 단독에는 증거가 없다. `ref` 형은 여기서 풀리지 않으므로
            // 그 사실을 지금 보고한다 — `scan`·`run` 은 평가 뒤에 푼다.
            let (env, unresolved) = remedy_core::pipeline::collect_declared(
                &m,
                &meta,
                remedy_core::pipeline::RefPolicy::ReportNow,
            )?;
            warn_unresolved_extra(&unresolved);
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
    Ok(outcome(&[], &obs, kind))
}

fn cmd_evaluate(raw: &[String]) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    let artifacts = read_json(a.need("artifacts")?)?;
    let m = load_manifest(a.need("plugin")?)?;
    let out = a.need("out")?;

    let rules = load_rules(a.need("plugin")?)?;
    let scan = remedy_core::pipeline::evaluate_with_rules(&artifacts, &m, &rules)?;
    write_json(out, &scan)?;
    report_scan(&scan, m.kind);
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
        Some(p) => Some(load_manifest(p)?),
        None => {
            errln!("  주의 --plugin 이 없습니다. remediate 를 읽을 수 없어 Action 을 도출하지 않습니다");
            None
        }
    };

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
    report_plan(&p, lang(&a), &a);
    Ok(outcome(
        &p.body.verdicts,
        &p.body.observation,
        m.as_ref().and_then(|m| m.kind),
    ))
}

/// 계획에 넣지 못한 것을 **반드시 말한다**.
///
/// 조용히 빠지면 이 계획이 치료의 전부인 것처럼 읽힌다. 관측이 불완전할 수 있듯
/// 계획도 불완전할 수 있고, 둘 다 말하지 않으면 완전한 것으로 읽힌다 (설계-03 §2).
/// 사람이 읽는 언어. `--lang` 이 없으면 `REMEDY_LANG`, 그것도 없으면 한국어.
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
fn report_plan(p: &remedy_sdk::artifact::PlanEnvelope, lang: remedy_core::report::Lang, a: &Args) {
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
        remedy_core::report::render_plan(p, lang, after_reboot)
    );
}

fn cmd_scan(raw: &[String]) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    // 설정 검증을 **가장 먼저** 한다. 수집을 다 끝낸 뒤 설정이 틀렸다고
    // 말하면 그 시간이 통째로 버려진다.
    let limits = load_limits(&a)?;
    let m = load_manifest(a.need("plugin")?)?;
    let dir = a.need("out-dir")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{dir}: {e}"))?;
    let meta = RunMeta::now();
    tee::open(&state_dir(&a), &meta.run_id);
    banner(Some(&m));
    warn_unsupported(&m);

    let rules = load_rules(a.need("plugin")?)?;
    scan_started();
    let (artifacts, scan, unresolved) = tee::with_heartbeat(ui().verbose, tee::Beat::Scan, || {
        remedy_core::pipeline::scan_with_rules(&m, &meta, &rules)
    })?;
    warn_unresolved_extra(&unresolved);
    let allow = load_allowed(
        |k| a.get(k.trim_start_matches("--")).map(str::to_string),
        &state_dir(&a),
    )?;
    let plan = remedy_core::plan_with(&scan, Some(&m), &allow, &limits, run_mode(&a))?;

    write_json(&format!("{dir}/artifacts.json"), &artifacts)?;
    write_json(&format!("{dir}/scan.json"), &scan)?;
    write_json(&format!("{dir}/plan.json"), &plan)?;
    output_dir_line(dir);
    report_scan(&scan, m.kind);
    report_plan(&plan, lang(&a), &a);
    let code = outcome(&scan.body.verdicts, &scan.body.observation, m.kind);
    outln!();
    outln!(
        "{}",
        remedy_core::report::result_line(code, 0, ui().lang, m.kind)
    );
    Ok(code)
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
    if !removable.is_empty() {
        errln!();
        errln!(
            "  {} {}",
            lang.t("주의:", "Note:"),
            lang.t(
                "이동식 매체 위의 대상이 있습니다:",
                "targets on removable media:"
            )
        );
        for r in &removable {
            errln!("     {r}");
        }
        eprint!(
            "     {}",
            lang.t(
                "지금 꽂혀 있는 매체가 맞는가. 맞으면 '예' 입력: ",
                "Is the inserted media the right one? Type 'yes' to confirm: "
            )
        );
        use std::io::Write;
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| Failure::from(e.to_string()))?;
        if !matches!(line.trim(), "예" | "yes" | "y" | "Y") {
            errln!(
                "  {}",
                lang.t("아무것도 하지 않았습니다.", "Nothing was done.")
            );
            return Ok(false);
        }
    }

    // "진행하려면" 은 리눅스 하네스가 읽는 문구다.
    eprint!(
        "\n{}",
        lang.t(
            "위 계획을 수행합니다. 되돌리려면 restore 를 써야 합니다. 진행하려면 '예' 입력: ",
            "The plan above will run. Use restore to undo. Type 'yes' to proceed: "
        )
    );
    use std::io::Write;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Failure::from(e.to_string()))?;
    let ok = matches!(line.trim(), "예" | "yes" | "y" | "Y");
    if !ok {
        errln!(
            "  {}",
            lang.t("아무것도 하지 않았습니다.", "Nothing was done.")
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
    let ko = "위 목록대로 되돌립니다. 되돌릴 수 없다고 적힌 항목은 그대로 \
              남습니다. 진행하려면 '예' 입력: ";
    let en = "The list above will be restored; items marked as not restorable \
              stay as they are. Type 'yes' to proceed: ";
    eprint!("\n{}", lang.t(ko, en));
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
    run_apply(&a, &plan, integrity, std::time::Instant::now(), None)
}

/// 전 단계를 한 번에 — 수집부터 치료까지.
fn cmd_run(
    raw: &[String],
    integrity: &remedy_core::integrity::SelfIntegrity,
) -> Result<Code, Failure> {
    let a = parse_args(raw)?;
    let limits = load_limits(&a)?;
    let m = load_manifest(a.need("plugin")?)?;
    let started = std::time::Instant::now();
    tee::open(&state_dir(&a), &format!("run-{}", std::process::id()));
    banner(Some(&m));
    warn_unsupported(&m);

    let meta = RunMeta::now();
    tee::rename(&meta.run_id);
    let rules = load_rules(a.need("plugin")?)?;
    scan_started();
    let (artifacts, scan, unresolved) = tee::with_heartbeat(ui().verbose, tee::Beat::Scan, || {
        remedy_core::pipeline::scan_with_rules(&m, &meta, &rules)
    })?;
    warn_unresolved_extra(&unresolved);
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
    report_scan(&scan, m.kind);
    run_apply(&a, &plan, integrity, started, m.kind)
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
) -> Result<Code, Failure> {
    let lang = ui().lang;
    let state_dir = a
        .get("state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);

    outln!();
    report_plan(plan, lang, a);
    warn_incomplete(&plan.body.observation, kind);

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
            remedy_core::report::render_closing(
                &remedy_core::report::Closing {
                    code,
                    done: 0,
                    elapsed_secs: elapsed_since(started),
                    run_id: None,
                    quarantine: None,
                    journal: None,
                    kind,
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

    advise_restart(&report);
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
    outln!();
    out!(
        "{}",
        remedy_core::report::render_closing(
            &remedy_core::report::Closing {
                code,
                done: report.done(),
                elapsed_secs: elapsed_since(started),
                run_id: Some(&plan.run_id),
                quarantine: quarantine.as_deref(),
                journal: Some(&journal),
                kind,
            },
            lang
        )
    );
    Ok(code)
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
        plugin: std::path::PathBuf::from(plugin),
        state_dir: a.get("state-dir").map(std::path::PathBuf::from),
        // 이 회차가 정한 언어를 그대로 싣는다 — 재부팅 회차는 환경을 물려받지
        // 못한다 (실측 2026-09-07: 한 로그가 앞은 한국어 뒤는 영어였다).
        lang: remedy_sdk::i18n::current(),
    })
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
fn advise_restart(report: &remedy_core::apply::Report) {
    use remedy_core::restart::RestartAdvice;
    let lang = ui().lang;

    let health = remedy_core::boot_health();
    let advice = remedy_core::restart::advise(
        report.body.reboot_required,
        report.failed(),
        health.as_ref(),
    );

    match advice {
        RestartAdvice::Nothing => {}

        RestartAdvice::CannotTell => {
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
                outln!(
                    "\n{}",
                    lang.t(
                        "일부 항목은 다음 부팅에 사라집니다. 아직 그 자리에 있습니다.",
                        "Some items disappear at the next boot. They are still there now."
                    )
                );
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
                outln!(
                    "\n{}",
                    lang.t(
                        "일부 항목은 다음 부팅에 사라집니다. 아직 그 자리에 있습니다.",
                        "Some items disappear at the next boot. They are still there now."
                    )
                );
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

// ─────────────────────────────────────────────── verify · resume (P9)

/// 재수집 + 재평가 (설계-03 §8).
///
/// **경로 확인이 아니다.** "제거한 경로가 여전히 비어 있는가" 만 보면 랜덤
/// 이름을 쓰는 위협 앞에서 무력하다 — 재감염은 다른 이름으로 생기고 원래
/// 경로는 계속 비어 있다.
fn cmd_verify(raw: &[String]) -> Result<Code, Failure> {
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
    let m = load_manifest(a.need("plugin")?)?;
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
    warn_unresolved_extra(&unresolved);
    if let Some(out) = a.get("out") {
        write_json(out, &scan)?;
        outln!("{} -> {out}", ui().lang.t("재평가", "Re-evaluation"));
    }
    report_scan(&scan, m.kind);

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
                    lang.t(
                        "치료 성공. 같은 플러그인이 더 이상 판정하지 않습니다.",
                        "Treatment succeeded. The same plugin no longer reports a threat.",
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
            errln!(
                "\n{}",
                if m.kind == Some(PluginKind::Check) {
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
fn record_verify(
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
fn cmd_resume(
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
        let code = run_apply(&a, &plan, integrity, std::time::Instant::now(), None)?;
        if code.code() > worst.code() {
            worst = code;
        }
    }
    Ok(worst)
}

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
    // 이 저장소의 모델은 **운영자가 준 것을 믿는다**(`run` 이 `--plugin` 을
    // 검증하지 않는 것과 같은 선).
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

fn cmd_plugin_lint(raw: &[String]) -> Result<Code, Failure> {
    if raw.is_empty() {
        return Err("검사할 plugin.yaml 을 하나 이상 지정하십시오".into());
    }

    let mut total_errors = 0usize;
    let mut total_warnings = 0usize;
    let mut unreadable = 0usize;

    for path in raw {
        outln!(
            "
{path}"
        );
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                outln!("  오류 읽을 수 없습니다: {e}");
                unreadable += 1;
                continue;
            }
        };
        // 형태가 깨졌으면 의미 검사까지 갈 수 없다. serde 의 메시지가 줄·열을
        // 알려 주므로 그대로 보인다.
        let m: PluginManifest = match serde_yaml_ng::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                outln!("  오류 스키마: {e}");
                outln!(
                    "      쓸 수 있는 것:
{}",
                    indent(&remedy_sdk::lint::valid_values())
                );
                total_errors += 1;
                continue;
            }
        };

        let issues = remedy_sdk::lint(&m);
        let errors = remedy_sdk::lint::blocking(&issues);
        let warnings = issues.len() - errors;
        total_errors += errors;
        total_warnings += warnings;

        if issues.is_empty() {
            outln!("  통과 — 오류 0 · 경고 0");
            continue;
        }
        for i in &issues {
            outln!("  {i}");
        }
        outln!("  오류 {errors} · 경고 {warnings}");
    }

    outln!(
        "
합계: 오류 {total_errors} · 경고 {total_warnings}{}",
        if unreadable > 0 {
            format!(" · 읽지 못한 파일 {unreadable}")
        } else {
            String::new()
        }
    );

    // **경고는 실패가 아니다.** 경고로 CI 를 막으면 사람이 경고를 끄는 법부터 배운다.
    if total_errors > 0 || unreadable > 0 {
        Ok(Code::UsageError)
    } else {
        Ok(Code::NoThreat)
    }
}

/// 배포 빌드에 박아 넣는 신뢰 앵커 — minisign 공개키 base64 한 줄.
///
/// **저장소에 파일로 두지 않고 빌드 때 주입한다.** 키가 파일이면 그 파일을 제
/// 키로 바꿔치기하는 것이 서명 우회의 첫 수가 된다. 바이너리에 박히면 바이너리를
/// 다시 만들지 않고는 바꿀 수 없다.
///
/// ```text
/// REMEDY_TRUST_ANCHOR=<base64> cargo build --release
/// ```
const EMBEDDED_ANCHOR: Option<&str> = option_env!("REMEDY_TRUST_ANCHOR");

/// 코어 바이너리에 **컴파일되는** 최소 플러그인 버전 (설계-01 D6 · 설계-03 §6).
///
/// 오프라인에서 실제로 강제되는 층이 이것이다. 네트워크가 없어도, **시계가
/// 조작돼도** 유효하다 — 만료 시각이 아니라 버전 비교이기 때문이다.
///
/// **비어 있는 것이 지금의 사실이다.** 아직 아무 플러그인도 폐기하지 않았다.
/// 값을 채우는 것은 코어 재배포이고, 설계-01 D7 이 *"코어 재배포가 곧 폐기
/// 메커니즘의 집행"* 이라고 적은 자리가 여기다.
const MIN_PLUGIN_VERSIONS: &[(&str, &str)] = &[
    // ("evilai-locust", "1.2.0"),
];

/// 플러그인 디렉터리의 서명을 확인한다 (설계-03 §10 G8).
///
/// **아직 로드 경로를 막지는 않는다.** 이 명령은 "서명이 맞는가" 를 사람이
/// 물어볼 수 있게 하는 자리이고, 서명되지 않은 플러그인의 실행을 거부하는 것은
/// 릴리스 키가 서고 저장소의 플러그인들이 서명된 뒤의 일이다. 그 순서를
/// 뒤집으면 아무 플러그인도 못 돌린 채 키 발급을 기다리게 된다.
fn cmd_plugin_verify(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw);

    let dir = arg("--dir").ok_or_else(|| {
        Failure::from(ui().lang.t(
            "--dir <플러그인 디렉터리> 옵션이 필요합니다",
            "--dir <plugin directory> is required",
        ))
    })?;
    let dir = std::path::Path::new(&dir);

    let anchor = match arg("--public-key") {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Failure::from(format!("{path} 를 읽지 못했습니다: {e}")))?;
            remedy_trust::Anchor::from_public_key_file(&text)
                .map_err(|e| Failure::from(e.to_string()))?
        }
        None => match EMBEDDED_ANCHOR {
            Some(b64) => {
                remedy_trust::Anchor::from_base64(b64).map_err(|e| Failure::from(e.to_string()))?
            }
            None => {
                return Err(Failure {
                    code: Code::UsageError,
                    message: "이 빌드에는 신뢰 앵커가 박혀 있지 않습니다. \
                              --public-key 로 공개키를 지정하거나, \
                              REMEDY_TRUST_ANCHOR 를 주고 다시 빌드하십시오"
                        .to_string(),
                })
            }
        },
    };

    let manifest_path = dir.join(remedy_trust::MANIFEST_NAME);
    let sig_path = dir.join(remedy_trust::SIGNATURE_NAME);

    // **없는 것과 틀린 것을 나눈다.** 미서명 플러그인은 "서명 파일이 없다" 로
    // 보고되어야 하고, 그것을 "검증 실패" 와 뭉뚱그리면 사람이 원인을 찾는 데
    // 시간을 쓴다.
    let manifest = std::fs::read(&manifest_path).map_err(|e| Failure {
        code: Code::GuardStop,
        message: format!(
            "{} 를 읽지 못했습니다 — 서명되지 않은 플러그인일 수 있습니다 ({e})",
            manifest_path.display()
        ),
    })?;
    let signature = std::fs::read_to_string(&sig_path).map_err(|e| Failure {
        code: Code::GuardStop,
        message: format!(
            "{} 를 읽지 못했습니다 — 서명되지 않은 플러그인일 수 있습니다 ({e})",
            sig_path.display()
        ),
    })?;

    let verified =
        remedy_trust::verify_manifest(&anchor, &manifest, &signature).map_err(|e| Failure {
            code: Code::GuardStop,
            message: e.to_string(),
        })?;

    let actual = remedy_trust::collect(dir).map_err(|e| Failure {
        code: Code::GuardStop,
        message: e.to_string(),
    })?;

    verified.check_tree(&actual).map_err(|e| Failure {
        code: Code::GuardStop,
        message: e.to_string(),
    })?;

    let c = verified.comment();
    outln!("{}", dir.display());
    outln!("  서명  {} {} ({})", c.id, c.version, c.signed_at);
    outln!("  파일  {} 개 — 매니페스트와 전부 일치", actual.len());

    // ── 폐기와 역행 금지 (설계-03 §6) ────────────────────────────
    //
    // **서명이 맞는 것과 지금 써도 되는 것은 다르다.** 폐기된 판도 서명은
    // 유효하다 — 그래서 서명 검증만으로는 킬 스위치가 서지 않는다.
    let state_dir = arg("--state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);
    let list = load_revocations(&anchor, &state_dir)?;
    let state = read_state(&state_dir)?;
    let min = remedy_trust::revocation::MinVersions::from_pairs(MIN_PLUGIN_VERSIONS)
        .map_err(|e| Failure::from(e.to_string()))?;

    remedy_trust::revocation::check_plugin(&c.id, &c.version, list.as_ref(), &min, &state)
        .map_err(|d| Failure {
            code: Code::GuardStop,
            message: d.to_string(),
        })?;

    match &list {
        Some(l) => outln!("  폐기  serial {} — 이 판을 겨누는 항목 없음", l.serial()),
        None => {
            // 목록이 없다는 사실을 **말한다.** 조용히 넘어가면 "폐기를
            // 확인했다" 로 읽힌다 (설계-03 §6 신선도 정책).
            outln!("  폐기  목록 없음 — 폐기 여부를 확인하지 못했습니다");
        }
    }
    Ok(Code::NoThreat)
}

/// 상태 디렉터리에 반입된 폐기 목록을 읽는다. 없으면 `None`.
///
/// **없는 것과 틀린 것을 나눈다.** 목록이 없는 것은 아직 반입하지 않은 것이고,
/// 서명이 맞지 않는 것은 누군가 손댄 것이다 — 뒤엣것은 오류로 나간다.
fn load_revocations(
    anchor: &remedy_trust::Anchor,
    dir: &std::path::Path,
) -> Result<Option<remedy_trust::RevocationList>, Failure> {
    let p = dir.join(remedy_trust::revocation::LIST_FILE);
    let text = match std::fs::read_to_string(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Failure::from(format!(
                "{} 를 읽지 못했습니다: {e}",
                p.display()
            )))
        }
        Ok(t) => t,
    };
    remedy_trust::revocation::parse_signed(anchor, &text)
        .map(Some)
        .map_err(|e| Failure {
            code: Code::GuardStop,
            message: format!("{}: {e}", p.display()),
        })
}

/// 서명된 허용 목록 하나를 확인한다. **상태를 바꾸지 않는다.**
fn cmd_allowlist_verify(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw);
    let path = arg("--file").ok_or_else(|| Failure::from("--file <목록> 옵션이 필요합니다"))?;
    let anchor = anchor_from(&arg)?;
    let list = read_allowlist(&anchor, &path)?;

    outln!("{path}");
    outln!("  serial  {}", list.serial());
    outln!("  발행    {}", list.issued_at());
    if list.is_empty() {
        // **빈 목록도 유효한 목록이다.** "면제한 것이 없다" 를 서명해 말하는
        // 것과, 목록이 없는 것은 다르다.
        outln!("  항목    없음 — 면제한 것이 없다고 서명해 말하는 목록입니다");
    } else {
        outln!("  항목    {} 건", list.entries().count());
        for e in list.entries() {
            outln!("    {}… — {}", &e.sha256[..16], e.reason);
        }
    }
    Ok(Code::NoThreat)
}

/// 허용 목록을 상태 디렉터리로 들인다.
///
/// **들어오는 문은 이것 하나다** (설계-01 D9 — 치료 경로에 네트워크가 없다).
/// 목록을 어떻게 받든 파일로 받아 여기서 확인한다.
fn cmd_allowlist_import(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw);
    let path = arg("--file").ok_or_else(|| Failure::from("--file <목록> 옵션이 필요합니다"))?;
    let anchor = anchor_from(&arg)?;
    let dir = arg("--state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);

    let list = read_allowlist(&anchor, &path)?;

    let mut state = read_state(&dir)?;
    // **회수된 면제가 옛 목록으로 되살아나면 안 된다.**
    remedy_trust::allowlist::check_allowlist(&list, &state).map_err(|d| Failure {
        code: Code::GuardStop,
        message: d.to_string(),
    })?;

    std::fs::create_dir_all(&dir)
        .map_err(|e| Failure::from(format!("{} 를 만들지 못했습니다: {e}", dir.display())))?;

    let dest = dir.join(remedy_trust::allowlist::LIST_FILE);
    std::fs::copy(&path, &dest)
        .map_err(|e| Failure::from(format!("{} 로 옮기지 못했습니다: {e}", dest.display())))?;

    state.observe_allowlist(list.serial());
    write_state(&dir, &state)?;

    outln!("반입했습니다: {}", dest.display());
    outln!("  serial  {} (발행 {})", list.serial(), list.issued_at());
    outln!("  항목    {} 건", list.entries().count());
    // **이 줄의 낱말은 아무도 읽지 않는다** (2026-10-28 전수 조사). 전에는
    // 주석이 *"5층 은 P10 검증 스크립트가 읽는 낱말"* 이라고 적었는데 잘못
    // 가리킨 것이었다 — `Invoke-P10Verify.ps1` 이 `5층` 을 읽는 자리는 **계획의
    // 미룸 사유**(`remedy-plan/src/derive.rs`)이고 이 안내가 아니다. 그래서
    // 화면에서 내부 층 번호를 빼도 그 판정은 흔들리지 않는다.
    outln!("\n  주의: 여기 있는 해시는 판정이 서도 삭제하지 않습니다 (조직 허용 목록).");
    outln!("     판정과 사유는 그대로 보고됩니다 — 조용히 사라지지 않습니다.");
    Ok(Code::NoThreat)
}

fn read_allowlist(
    anchor: &remedy_trust::Anchor,
    path: &str,
) -> Result<remedy_trust::allowlist::Allowlist, Failure> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Failure::from(format!("{path} 를 읽지 못했습니다: {e}")))?;
    remedy_trust::allowlist::parse_signed(anchor, &text).map_err(|e| Failure {
        code: Code::GuardStop,
        message: e.to_string(),
    })
}

/// 상태 디렉터리에 반입된 조직 허용 목록을 계획기가 쓸 모양으로 읽는다
/// (설계-03 §3 5층).
///
/// # 없으면 빈 지도다 — 그리고 그것이 안전한 방향이다
///
/// 면제가 없으면 평소대로 치료할 뿐이다. 반대(목록을 못 읽었는데 면제된 것으로
/// 치는 것)라야 위험하다. 그래서 **폐기 목록과 실패 방향이 반대다** — 그쪽은
/// 없으면 경고하지만, 이쪽은 없는 것이 기본 상태다.
///
/// # 서명이 틀리면 멈춘다
///
/// 없는 것과 **바꿔치기된 것**은 다르다. 뒤엣것을 조용히 빈 지도로 만들면
/// 공격자가 파일 하나를 망가뜨려 조직의 면제를 통째로 없앨 수 있고, 그러면
/// 정상 파일이 지워진다.
///
/// # 역행 금지
///
/// 옛 목록을 되밀어 **회수된 면제를 되살릴 수 없다.** 반입 때 한 번 보고
/// (`cmd_allowlist_import`), 여기서 읽을 때 한 번 더 본다 — 파일을 직접 바꿔
/// 넣는 길이 있기 때문이다.
fn load_allowed(
    arg: impl Fn(&str) -> Option<String>,
    dir: &std::path::Path,
) -> Result<remedy_core::Allowed, Failure> {
    let p = dir.join(remedy_trust::allowlist::LIST_FILE);
    let text = match std::fs::read_to_string(&p) {
        // **목록이 없으면 앵커도 필요 없다.** 앵커를 먼저 얻으면 신뢰 앵커가
        // 박히지 않은 개발 빌드에서 `scan` 이 통째로 멈춘다 — 허용 목록을 쓰지
        // 않는 실행까지. 실측으로 걸렸다 (2026-08-29).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(remedy_core::Allowed::new())
        }
        Err(e) => {
            return Err(Failure::from(format!(
                "{} 를 읽지 못했습니다: {e}",
                p.display()
            )))
        }
        Ok(t) => t,
    };
    let anchor = anchor_from(&arg)?;
    let list = remedy_trust::allowlist::parse_signed(&anchor, &text).map_err(|e| Failure {
        code: Code::GuardStop,
        message: format!("{}: {e}", p.display()),
    })?;
    let state = read_state(dir)?;
    remedy_trust::allowlist::check_allowlist(&list, &state).map_err(|d| Failure {
        code: Code::GuardStop,
        message: format!("{}: {d}", p.display()),
    })?;
    Ok(remedy_trust::allowlist::flatten(&list))
}

/// 인자에서 앵커를 얻는다. `plugin verify` 와 `revocation` 이 같은 규칙을 쓴다.
fn anchor_from(arg: impl Fn(&str) -> Option<String>) -> Result<remedy_trust::Anchor, Failure> {
    match arg("--public-key") {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Failure::from(format!("{path} 를 읽지 못했습니다: {e}")))?;
            remedy_trust::Anchor::from_public_key_file(&text)
                .map_err(|e| Failure::from(e.to_string()))
        }
        None => match EMBEDDED_ANCHOR {
            Some(b64) => {
                remedy_trust::Anchor::from_base64(b64).map_err(|e| Failure::from(e.to_string()))
            }
            None => Err(Failure {
                code: Code::UsageError,
                message: "이 빌드에는 신뢰 앵커가 박혀 있지 않습니다. \
                          --public-key 로 공개키를 지정하거나, \
                          REMEDY_TRUST_ANCHOR 를 주고 다시 빌드하십시오"
                    .to_string(),
            }),
        },
    }
}

fn simple_arg(raw: &[String]) -> impl Fn(&str) -> Option<String> + '_ {
    move |name: &str| {
        raw.iter()
            .position(|a| a == name)
            .and_then(|i| raw.get(i + 1))
            .cloned()
    }
}

/// 폐기 목록을 읽어 보인다. **상태를 건드리지 않는다** — 반입 전에 무엇이 담겨
/// 있는지 사람이 확인하는 자리다.
fn cmd_revocation_verify(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw);
    let path = arg("--file").ok_or_else(|| Failure::from("--file <목록> 옵션이 필요합니다"))?;
    let anchor = anchor_from(&arg)?;

    let list = read_list(&anchor, &path)?;

    outln!("{path}");
    outln!("  serial  {}", list.serial());
    outln!("  발행    {}", list.issued_at());
    if list.is_empty() {
        // **빈 목록도 유효한 목록이다.** "아직 아무것도 폐기하지 않았다" 를
        // 서명해 말하는 것과, 목록이 없는 것은 다르다.
        outln!("  항목    없음 — 폐기된 것이 없다고 서명해 말하는 목록입니다");
    } else {
        outln!("  항목    {} 건", list.entries().count());
        for e in list.entries() {
            let range = match (&e.below, &e.exact) {
                (Some(b), _) => format!("{b} 미만"),
                (_, Some(x)) => x.clone(),
                _ => "(형식 오류)".into(),
            };
            outln!("    {} {} — {}", e.plugin, range, e.reason);
        }
    }
    Ok(Code::NoThreat)
}

/// 목록을 상태 디렉터리로 반입한다.
///
/// **반입 경로가 신뢰를 낮추지 않는다** (설계-03 §6). 파일 공유나 이동식 매체로
/// 온 목록도 서명 검증과 역행 금지를 똑같이 거친다.
fn cmd_revocation_import(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw);
    let path = arg("--file").ok_or_else(|| Failure::from("--file <목록> 옵션이 필요합니다"))?;
    let anchor = anchor_from(&arg)?;
    let dir = arg("--state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);

    let list = read_list(&anchor, &path)?;

    let mut state = read_state(&dir)?;
    // 역행 금지는 목록에도 걸린다 — 옛 목록으로 되돌리면 폐기가 풀린다.
    remedy_trust::revocation::check_revocations(&list, &state).map_err(|d| Failure {
        code: Code::GuardStop,
        message: d.to_string(),
    })?;

    std::fs::create_dir_all(&dir)
        .map_err(|e| Failure::from(format!("{} 를 만들지 못했습니다: {e}", dir.display())))?;

    let dest = dir.join(remedy_trust::revocation::LIST_FILE);
    std::fs::copy(&path, &dest)
        .map_err(|e| Failure::from(format!("{} 로 옮기지 못했습니다: {e}", dest.display())))?;

    state.observe_revocation(list.serial());
    write_state(&dir, &state)?;

    outln!("반입했습니다: {}", dest.display());
    outln!("  serial  {} (발행 {})", list.serial(), list.issued_at());
    outln!("  항목    {} 건", list.entries().count());
    Ok(Code::NoThreat)
}

fn read_list(
    anchor: &remedy_trust::Anchor,
    path: &str,
) -> Result<remedy_trust::RevocationList, Failure> {
    // **없는 것과 틀린 것을 나눈다.** 목록이 없는 것은 사용법 문제일 수 있지만,
    // 서명이 맞지 않는 것은 가드가 막은 것이다.
    let text = std::fs::read_to_string(path)
        .map_err(|e| Failure::from(format!("{path} 를 읽지 못했습니다: {e}")))?;
    remedy_trust::revocation::parse_signed(anchor, &text).map_err(|e| Failure {
        code: Code::GuardStop,
        message: e.to_string(),
    })
}

fn read_state(dir: &std::path::Path) -> Result<remedy_trust::TrustState, Failure> {
    let p = dir.join(remedy_trust::revocation::STATE_FILE);
    match std::fs::read_to_string(&p) {
        // 없으면 처음 보는 기계다. 빈 상태는 "아무것도 관측하지 않았다" 이고,
        // 그 위에서도 코어 내장 하한은 그대로 작동한다.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(e) => Err(Failure::from(format!(
            "{} 를 읽지 못했습니다: {e}",
            p.display()
        ))),
        Ok(text) => serde_json::from_str(&text).map_err(|e| Failure {
            // 상태를 읽지 못하면 역행 금지를 판정할 수 없다. 빈 상태로 넘어가면
            // 그것이 곧 되돌리기 통로가 된다.
            code: Code::GuardStop,
            message: format!(
                "{} 를 읽지 못했습니다: {e} — 역행 금지를 판정할 수 없으므로 멈춥니다. \
                 상태가 손상됐다면 파일을 지우고 목록을 다시 반입하십시오",
                p.display()
            ),
        }),
    }
}

/// 신고 첨부물을 만든다 (설계-04 §6).
///
/// **오탐 대응 경로의 두 번째 칸**이다 — 복구(`restore`) 다음, 재현·판정 앞.
/// 여기서 "무엇을 보낼지" 가 막히면 뒤가 전부 늦어진다.
fn cmd_support_bundle(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw);
    let run_id = arg("--run").ok_or_else(|| {
        Failure::from(
            "--run <run_id> 옵션이 필요합니다. 실행 id 는 apply 출력과 저널 이름에 있습니다",
        )
    })?;
    let state_dir = arg("--state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);
    let out = arg("--out")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let b = remedy_core::support::build(&state_dir, &run_id, &out).map_err(Failure::from)?;
    let lang = ui().lang;
    let d = remedy_sdk::i18n::deco();
    outln!(
        "{} : {}",
        // **`꾸러미` 가 아니라 `지원 번들` 이다** (2026-10-28). 신고에 붙이는
        // 진단 모음을 업계가 그렇게 부른다.
        //
        // **다른 뜻의 `꾸러미` 는 건드리지 않았다** — `guided.rs` 의 것은 실행
        // 파일 옆의 **플러그인 꾸러미**이고(영문도 `bundles`), `lint.rs` 의 것은
        // **채점 꾸러미**다. 한 낱말이 셋을 가리키고 있었고, 싸잡아 바꾸면 두
        // 자리가 틀린 말이 된다.
        lang.t("지원 번들 폴더", "Support bundle folder"),
        b.dir.display()
    );
    outln!("\n{}", lang.t("담긴 것", "Included"));
    for i in &b.included {
        outln!(
            "  {:<18} {:>9} {}  {}",
            i.name,
            i.bytes,
            lang.t("바이트", "bytes"),
            i.what
        );
    }
    if !b.excluded.is_empty() {
        outln!(
            "\n{}",
            lang.t("일부러 담지 않은 것", "Deliberately left out")
        );
        for e in &b.excluded {
            outln!("  {}\n    {}", e.name, e.why);
        }
    }
    if let Some(h) = &b.submit_hint {
        outln!(
            "\n{}",
            lang.t(
                "플러그인이 남긴 것 (손으로 올릴 때 보십시오)",
                "Left by the plugin (for manual upload)"
            )
        );
        if !h.samples.is_empty() {
            outln!(
                "  {}: {}",
                lang.t("함께 올리면 유용한 증거", "Evidence worth attaching"),
                h.samples.join(d.dot())
            );
        }
        if let Some(c) = h.confidentiality_min {
            outln!(
                "  {}: {c}. {}",
                lang.t("기밀 등급 하한", "Minimum confidentiality"),
                lang.t(
                    "이 등급 아래로 다루지 마십시오",
                    "do not handle below this level"
                )
            );
        }
    }
    outln!(
        "\n{}",
        lang.t(
            "무엇이 담겼고 무엇이 빠졌는지는 README.txt 에 그대로 있습니다.",
            "README.txt lists exactly what is included and what is not."
        )
    );
    outln!(
        "{}",
        lang.t(
            "보내기 전에 열어 보십시오. 경로, 호스트명, 사용자명이 가려지지 않습니다.",
            "Open it before sending. Paths, host name and user name are not redacted."
        )
    );
    Ok(Code::NoThreat)
}

fn write_state(dir: &std::path::Path, state: &remedy_trust::TrustState) -> Result<(), Failure> {
    let p = dir.join(remedy_trust::revocation::STATE_FILE);
    let text = serde_json::to_string_pretty(state)
        .map_err(|e| Failure::from(format!("상태를 만들지 못했습니다: {e}")))?;
    std::fs::write(&p, text)
        .map_err(|e| Failure::from(format!("{} 를 쓰지 못했습니다: {e}", p.display())))
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

fn report_scan(scan: &remedy_sdk::artifact::ScanEnvelope, kind: Option<PluginKind>) {
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
    if kind == Some(PluginKind::Check) && !scan.body.verdicts.is_empty() {
        let limit = if ui().verbose {
            usize::MAX
        } else {
            remedy_core::report::FINDINGS_SHOWN
        };
        for line in
            remedy_core::report::check_findings(&scan.body.evidence, &scan.body.groups, lang, limit)
        {
            outln!("{line}");
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
        None => obs.is_complete(),
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
                "이 결과 위에서 '취약하지 않다' 를 말할 수 없습니다:",
                "'not vulnerable' cannot be declared on this result:",
            )
        } else {
            lang.t(
                "이 결과 위에서 '위협 없음' 을 말할 수 없습니다:",
                "'no threat' cannot be declared on this result:",
            )
        }
    );
    for r in obs.reasons() {
        errln!("     - {r}");
    }
    denied_sample(obs, lang);
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
fn denied_sample(obs: &Observation, lang: remedy_core::report::Lang) {
    for l in denied_lines(obs, lang) {
        errln!("{l}");
    }
}

/// 화면에 낼 줄을 짓는다.
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

/// 명령줄에서 열쇠를 모은다. 실제 선택은 `remedy-core` 가 한다.
fn key_source(
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
fn list_runs(state_dir: &std::path::Path) -> Result<Code, Failure> {
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
                // 영문 `place` 다. 이 낱말은 고객 화면 넷(`main.rs:3344`·`3443` ·
                // `restore.rs:299` · `support.rs:330`)이 함께 쓰므로 여기만
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
        // "remedy restore --run" 은 시험과 하네스가 읽는 문구다.
        outln!(
            "{} : remedy restore --run {newest}",
            lang.t("되돌리려면", "To undo")
        );
    }
    Ok(Code::NoThreat)
}

fn cmd_restore(raw: &[String]) -> Result<Code, Failure> {
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
            ui().lang.t(
                "로컬 wrap 뿐입니다. 이 머신을 재설치하면 이 격리물은 열 수 없습니다.",
                "only a local wrap exists. Reinstalling this machine makes the quarantine unopenable."
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
        errln!(
            "  {} {}",
            lang.t("주의:", "Note:"),
            lang.t(
                "복원도 쓰기입니다. 보호 대상에는 쓰지 않습니다.",
                "restore is also a write; protected targets are left alone."
            )
        );
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

#[cfg(test)]
mod tests {
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
            next_steps(f, c)
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>()
        };
        use menu::Line as L;
        assert_eq!(
            lines(Flow::Treat, Code::Remediated),
            [L::Undo, L::Verify, L::Report]
        );
        assert_eq!(
            lines(Flow::Scan, Code::FoundNotRemediated),
            [L::Treat, L::Apply]
        );
        assert_eq!(lines(Flow::Restore, Code::NoThreat), [L::Treat]);
        assert!(lines(Flow::Scan, Code::NoThreat).is_empty());
        assert!(lines(Flow::Other, Code::PartialFailure).is_empty());
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
            location: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\remedy-verify"
                .into(),
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
}
