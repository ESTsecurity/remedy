//! 지은 `remedy-net` 을 띄워 종료 코드와 화면을 잰다 — 무인 배포가 읽는 것이 이 둘이다.
//!
//! 언어는 `REMEDY_LANG` 으로, 기호는 `REMEDY_ASCII=0`(UTF-8)으로 고정한다. 시험하는 기계의 로케일
//! (Windows 는 사용자 로케일 · 리눅스는 `LANG` — 비어 있으면 ASCII 로 접힌다)에 따라 답이 달라지면 같은
//! 시험이 기계마다 다르게 돈다.

use std::process::{Command, Output};

fn run(lang: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_remedy-net"))
        .args(args)
        .env("REMEDY_LANG", lang)
        .env("REMEDY_ASCII", "0")
        .output()
        .expect("remedy-net 을 띄우지 못했다")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn help_is_the_default_and_ends_with_zero() {
    for args in [&[][..], &["--help"][..], &["-h"][..]] {
        let o = run("en", args);
        assert_eq!(o.status.code(), Some(0), "{args:?}");
        let out = stdout(&o);
        assert!(out.contains("companion module remedy-net"), "{out}");
        assert!(
            out.contains("Exit codes (the same table as remedy):"),
            "{out}"
        );
    }
}

#[test]
fn help_speaks_korean_and_lists_the_contract() {
    let o = run("ko", &["--help"]);
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    for line in [
        "종료 코드 (본체 remedy 와 같은 표):",
        "  0  양호 · 도움말",
        "  2  취약",
        "  6  확인 필요",
        "  4  입력 오류 · 동의하지 않음",
        "  7  처리 실패",
    ] {
        assert!(out.contains(line), "도움말에 '{line}' 가 없다:\n{out}");
    }
}

#[test]
fn version_names_the_product_and_the_workspace_version() {
    let o = run("ko", &["--version"]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        stdout(&o).trim(),
        format!(
            "ESTsecurity 전용백신 {} (remedy-net)",
            env!("CARGO_PKG_VERSION")
        )
    );
}

#[test]
fn an_unknown_command_is_an_input_error() {
    // 없는 명령을 있는 척 0 으로 끝내지 않는다.
    let o = run("en", &["host", "/"]);
    assert_eq!(o.status.code(), Some(4));
    assert!(stdout(&o).is_empty());
    assert!(
        stderr(&o).contains("unknown command: host"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn image_refuses_bad_input_before_the_terms_and_makes_no_folder() {
    let out = std::env::temp_dir().join(format!("remedy-net-cli-image-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let out_arg = out.to_string_lossy().into_owned();
    for args in [
        &["image"][..],
        &["image", "--runtime", "python", "a.tar"][..],
        &["image", "a.tar", "--consent", "maybe"][..],
    ] {
        let mut full: Vec<&str> = args.to_vec();
        full.extend(["--out-dir", &out_arg]);
        let o = run("ko", &full);
        assert_eq!(o.status.code(), Some(4), "{args:?}: {}", stderr(&o));
        assert!(!stdout(&o).contains("이용 조건"), "{args:?}");
        assert!(
            stderr(&o).contains("remedy-net image --help"),
            "{}",
            stderr(&o)
        );
    }
    assert!(!out.exists(), "입력 오류인데 결과 폴더가 생겼다");
}

#[test]
fn image_declined_terms_end_with_four_and_no_folder() {
    let out = std::env::temp_dir().join(format!("remedy-net-cli-decline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let o = run(
        "ko",
        &[
            "image",
            "a.tar",
            "--consent",
            "n",
            "--out-dir",
            &out.to_string_lossy(),
        ],
    );
    assert_eq!(o.status.code(), Some(4), "{}", stderr(&o));
    let text = stdout(&o);
    assert!(text.contains("이용 조건"), "{text}");
    assert!(text.contains("점검을 취소했습니다."), "{text}");
    assert!(!out.exists(), "동의하지 않았는데 결과 폴더가 생겼다");
}

#[test]
fn every_command_has_its_own_help() {
    for (cmd, line) in [
        ("url", "Usage: remedy-net url"),
        ("image", "Usage: remedy-net image"),
        ("container", "Usage: remedy-net container"),
    ] {
        let o = run("en", &[cmd, "--help"]);
        assert_eq!(o.status.code(), Some(0), "{cmd}");
        assert!(stdout(&o).starts_with(line), "{cmd}: {}", stdout(&o));
        assert!(
            !stdout(&o).contains("Terms of use"),
            "{cmd} 도움말이 약관을 냈다"
        );
    }
}

#[test]
fn an_unknown_language_is_named_and_ignored() {
    let o = Command::new(env!("CARGO_BIN_EXE_remedy-net"))
        .args(["--lang", "kr", "--version"])
        .env("REMEDY_LANG", "en")
        .output()
        .expect("remedy-net 을 띄우지 못했다");
    assert_eq!(o.status.code(), Some(0));
    assert!(stderr(&o).contains("--lang 'kr'"), "{}", stderr(&o));
    assert!(stdout(&o).starts_with("ESTsecurity Dedicated Cleaner"));
}

#[test]
fn ascii_mode_folds_the_symbols() {
    let o = run("en", &["--ascii", "--help"]);
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    assert!(out.is_ascii(), "ASCII 가 아닌 글자가 남았다:\n{out}");
    assert!(out.contains("  0  clear | help"), "{out}");
}
