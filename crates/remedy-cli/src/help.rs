//! 창을 닫기 전 기다림 · 버전 · 사용법 · 모든 명령과 옵션 · 자체 점검(2026-11-17 에 main.rs 에서 옮겼다).

use super::*;

pub(super) fn wait_before_closing() {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return;
    }
    let lang = ui().lang;
    // stdout 은 화면의 결과이고 이 줄은 화면을 붙잡는 장치다 — stderr 로 낸다.
    // 그래야 `remedy > 화면.txt` 로 갈무리한 파일에 프롬프트가 섞이지 않는다.
    screen_errln!();
    // 리눅스(SSH · 콘솔)에는 닫힐 창이 없다 — 끝낸다고 말한다.
    screen_err!(
        "{}",
        if cfg!(windows) {
            lang.t(
                "이 창을 닫으려면 Enter 를 누르십시오. ",
                "Press Enter to close this window. ",
            )
        } else {
            lang.t("끝내려면 Enter 를 누르십시오. ", "Press Enter to exit. ")
        }
    );
    use std::io::Write;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

/// `--version` — 첫 줄은 `<제품> <엔진 버전> (remedy)` 그대로이고, 꾸러미에 룰 버전이 있으면 그 아래 줄에
/// 적는다(`menu::version_rules_line`).
pub(super) fn print_version() {
    let lang = ui().lang;
    outln!(
        "{} {} (remedy)",
        remedy_core::report::brand::product(lang),
        env!("CARGO_PKG_VERSION")
    );
    if let Some(line) = menu::version_rules_line(lang) {
        outln!("{line}");
    }
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
pub(super) fn usage(stderr: bool) {
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
pub(super) fn usage_all() {
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
    say!("  scan     --plugin <네트워크 점검 룰> --out-dir <디렉터리> --url <주소>...");
    say!("           [--consent y|n] [--cacert <파일>]");
    say!("           바깥의 서버를 본다(network: url). remedy 는 통신하지 않는다 — 서명을");
    say!("           확인한 remedy-net 을 띄워 맡기고 종료 코드만 받는다. 권한이 필요 없다.");
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

pub(super) fn selftest() -> Code {
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
