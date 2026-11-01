//! 안내 모드 — 인자 없이 부른 사람이 어디로 가는가 (Phase 4-3).
//!
//! **바이너리를 실제로 띄운다.** 안내 모드는 `main` 의 `None` 갈래에서만 열리고
//! 그 조건은 인자 파싱 뒤에 정해지므로, 내부 함수를 부르면 정작 재고 싶은 것이
//! 재어지지 않는다.
//!
//! 꾸러미를 흉내 내려면 **실행 파일 옆**에 두어야 한다 — `discover::beside` 가
//! `current_exe()` 의 부모를 보기 때문이다. 그래서 시험용 바이너리를 임시 폴더에
//! 복사하고 그 옆에 꾸러미를 만든다.
//!
//! # 이 빌드에는 앵커가 없다
//!
//! 시험은 `cargo test` 가 만든 바이너리를 쓰고, 거기에는 `REMEDY_TRUST_ANCHOR` 가
//! 박혀 있지 않다. 그래서 **검증은 언제나 `NoAnchor` 로 거절된다** — 그것이 지금
//! 빌드의 사실이고, 여기서 재는 것은 *"거절이 어떤 모양인가"* 다. 서명이 실제로
//! 통과하는 경로는 앵커를 박아 빌드해야 하며 `plugin verify` 와 `xtask package`
//! 가 그것을 잰다.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const EXE: &str = env!("CARGO_BIN_EXE_remedy");

/// 시험용 바이너리를 복사한 폴더. 그 옆이 곧 탐색 범위다.
fn lab(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join("remedy-cli-guided").join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("작업 디렉터리");
    let exe = d.join(if cfg!(windows) {
        "remedy.exe"
    } else {
        "remedy"
    });
    std::fs::copy(EXE, &exe).expect("바이너리 복사");
    d
}

fn exe_in(dir: &Path) -> PathBuf {
    dir.join(if cfg!(windows) {
        "remedy.exe"
    } else {
        "remedy"
    })
}

/// 띄우되 **`ETXTBSY` 면 잠깐 기다렸다 다시 해 본다.**
///
/// 리눅스에서 한 스레드가 파일을 쓰는 동안 다른 스레드가 `fork` 하면 그 쓰기
/// fd 가 자식에게 상속되고, 자식이 `exec` 를 마칠 때까지 그 파일은 실행되지
/// 않는다(`ETXTBSY` = 26). 이 파일의 시험 여섯이 **병렬로 각자 바이너리를
/// 복사하고 띄우므로** 그 창에 걸릴 수 있다.
///
/// 2026-09-19 `cargo test --workspace --all-targets` 에서 한 번 걸렸다. 이
/// 시험만 따로 여덟 번 돌리면 나지 않는다 — 기계가 바빠야 창이 벌어진다.
/// 기다리는 시간은 `exec` 한 번의 길이라 짧다.
fn output_retrying(cmd: &mut Command) -> std::io::Result<std::process::Output> {
    for _ in 0..50 {
        match cmd.output() {
            // `ErrorKind::ExecutableFileBusy` 대신 raw 를 보는 것은 그 variant 가
            // 판에 따라 unstable 이기 때문이다. 26 은 유닉스 공통이다.
            Err(e) if e.raw_os_error() == Some(26) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => return other,
        }
    }
    cmd.output()
}

/// 인자 없이 띄운다. stdin 은 **닫아 둔다** — 터미널이 아니므로 창을 붙잡지
/// 않고, 고르기도 묻지 않는다(`never_waits.rs` 가 그 불변식을 잰다).
fn run_no_args(dir: &Path) -> (String, i32) {
    let out = output_retrying(
        Command::new(exe_in(dir))
            .env("REMEDY_ELEVATION", "yes")
            .env("REMEDY_LANG", "ko")
            .stdin(Stdio::null()),
    )
    .expect("실행");
    (
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        out.status.code().unwrap_or(-1),
    )
}

/// `plugins/<이름>/` 에 꾸러미 모양을 만든다. `signed` 가 거짓이면 서명 파일을
/// 두지 않는다.
fn put_bundle(dir: &Path, name: &str, signed: bool) {
    let p = dir.join("plugins").join(name);
    std::fs::create_dir_all(p.join("rules")).expect("폴더");
    std::fs::write(
        p.join("plugin.yaml"),
        format!(
            "schema_version: 1\nid: {name}\nversion: 1.0.0\nmin_core: '1.0.0'\n\
             platforms: [windows, linux]\nname: {{ ko: '{name} 제거', en: '{name} removal' }}\n\
             scan_roots: []\nsubjects: [file]\ndetect:\n  - id: j\n    subject: file\n    \
             where:\n      - {{ field: path, op: ends_with, value: '.evil' }}\nverdict:\n  \
             require: 'j'\n"
        ),
    )
    .expect("plugin.yaml");
    std::fs::write(p.join("rules/x.yar"), "rule x { condition: false }").expect("룰");
    if signed {
        std::fs::write(p.join("MANIFEST"), "# remedy plugin manifest v1\n").expect("매니페스트");
        std::fs::write(p.join("MANIFEST.minisig"), "untrusted comment: x\n").expect("서명");
    }
}

#[test]
fn with_nothing_beside_it_the_usage_screen_is_what_it_was() {
    // **안내 모드가 지금까지의 동작을 나쁘게 만들면 안 된다.** 개발 빌드를 그냥
    // 띄우면 옆에 꾸러미가 없고, 그때는 사용법에 종료 코드 0 이다.
    let d = lab("bare");
    let (text, code) = run_no_args(&d);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("사용법"), "{text}");
    // 찾지 못했다는 잡음을 내지 않는다 — 꾸러미가 아닌 자리에서 그 말은 방해다.
    assert!(!text.contains("건너뜀"), "{text}");
}

#[test]
fn an_unsigned_bundle_is_refused() {
    // 서명 없는 꾸러미를 쓰지 않는다. **왜 못 쓰는지가 사용자의 다음 행동을
    // 정한다** — 다만 이 빌드에는 앵커가 없어 사유는 그쪽이 먼저 잡힌다
    // (아래 시험이 그 순서를 설명한다).
    let d = lab("unsigned");
    put_bundle(&d, "demo", false);
    let (text, code) = run_no_args(&d);
    assert!(text.contains("건너뜀"), "{text}");
    // **0 으로 끝나지 않는다** — 검사를 한 적이 없는데 0 은 "깨끗하다" 로 읽힌다.
    assert_eq!(code, 5, "{text}");
}

#[test]
fn without_an_anchor_the_reason_is_the_anchor_not_the_signature() {
    // **순서가 뜻을 갖는다.** 앵커가 없으면 서명이 있든 없든 확인할 방법이
    // 없으므로, 사유는 "이 프로그램은 플러그인 번들을 검증할 수 없습니다" 이지
    // "네 번들이 잘못됐다" 가 아니다. 뒤집으면 멀쩡한 번들을 받은 사람에게
    // 그 번들을 의심하게 만든다.
    //
    // 서명된 것과 안 된 것이 **같은 사유**를 받는지 함께 본다 — 이 빌드에서는
    // 둘을 가를 수 없는 것이 사실이기 때문이다.
    for signed in [true, false] {
        let d = lab(if signed {
            "anchor-signed"
        } else {
            "anchor-unsigned"
        });
        put_bundle(&d, "demo", signed);
        let (text, code) = run_no_args(&d);
        assert!(
            // 2026-10-28 에 화면이 `확인할 수 없습니다` 에서 `검증할 수 없습니다`
            // 로 바뀌었다 — 서명 검증이라는 뜻이고 저장소가 쓰는 낱말이 `검증` 이다.
            text.contains("검증할 수 없습니다"),
            "signed={signed}: {text}"
        );
        assert!(!text.contains("서명이 없습니다"), "signed={signed}: {text}");
        assert_eq!(code, 5, "signed={signed}: {text}");
    }
}

#[test]
fn refusing_says_that_nothing_was_checked() {
    // 건너뛴 목록만 보이고 끝나면 사용자는 검사가 돌았는지 아닌지 모른다.
    let d = lab("nothing");
    put_bundle(&d, "demo", false);
    let (text, _) = run_no_args(&d);
    assert!(
        text.contains("아무것도 검사하지 못했습니다"),
        "검사하지 않았다는 사실을 말하지 않았다:\n{text}"
    );
}

#[test]
fn every_bundle_that_cannot_be_used_is_named() {
    // 조용히 빼면 사용자는 자기가 받은 것의 절반이 무시된 것을 모른다.
    let d = lab("several");
    put_bundle(&d, "alpha", false);
    put_bundle(&d, "beta", true);
    let (text, _) = run_no_args(&d);
    for name in ["alpha", "beta"] {
        assert!(text.contains(name), "{name} 이 목록에 없다:\n{text}");
    }
}

#[test]
fn arguments_still_bypass_the_guided_path_entirely() {
    // **불변식이다.** 인자가 있으면 안내 모드에 오지 않는다 — 옆에 꾸러미가
    // 있어도 `run --plugin` 없이는 지금처럼 사용법 오류(4)다.
    let d = lab("args");
    put_bundle(&d, "demo", true);
    let out = output_retrying(
        Command::new(exe_in(&d))
            .arg("run")
            .env("REMEDY_ELEVATION", "yes")
            .env("REMEDY_LANG", "ko")
            .stdin(Stdio::null()),
    )
    .expect("실행");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(4), "{text}");
    assert!(text.contains("--plugin"), "{text}");
    assert!(!text.contains("건너뜀"), "안내 모드가 새어 나왔다:\n{text}");
}
