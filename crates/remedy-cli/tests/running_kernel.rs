//! 지금 도는 커널 — **이 기계에서** 실제로 읽고, 그 커널의 패키지와 잇는가 (코어 1.28.0 · H1).
//!
//! 수집기의 단위 시험(`remedy-collect` 의 `kernel.rs`)은 가짜 파일 시스템 위에서 돈다. 엔진 하네스
//! (`testbed/harness/linux/verify-linux.sh` 의 K1 ~ K3)는 컨테이너 안에서 돌아, 커널은 호스트의 것인데 패키지 DB 는
//! 이미지의 것이다 — 그래서 이음을 세우려고 자리 채우기 기록을 넣는다. **이 시험은 둘이 함께 진짜인 자리**다. CI
//! 리눅스 잡의 `cargo test` 는 러너 호스트(컨테이너가 아니다)에서 돌고, 거기의 커널과 dpkg 기록은 함께 그 기계의
//! 것이다.
//!
//! 기대값은 그 자리에서 정한다 — 값은 `uname -r` · `uname -v` · `/proc/version_signature` 로, 이음은
//! `dpkg-query -W -f '${db:Status-Abbrev}' linux-image-<release>` 가 깔림(`ii` 등)인가로. 그 패키지가 없는
//! 기계(컨테이너 · WSL · 직접 지은 커널 · dpkg 가 없는 배포판)에서는 이음이 서지 않아야 한다. 룰은 엔진 하네스와
//! 같은 `testbed/harness/linux/kernel-plugin.yaml` 이다.
//!
//! # root 가 필요한가
//!
//! 읽는 파일은 모두 누구나 읽는다 — `/proc/sys/kernel/osrelease` · `version` 은 444, `/var/lib/dpkg/status` 는
//! 644 다(랩 VM 과 bookworm · ubuntu:24.04 컨테이너에서 uid 65534 로 읽어 잼 · 2026-11-28). 막는 것은 **관리자 문**
//! 이다 — `collect` 는 배포 빌드에서 root 가 아니면 5 로 멈춘다(`admin_gate.rs`). 이 시험은 개발 빌드의
//! `REMEDY_ELEVATION=yes` 로 그 문만 넘기고 **도는 사용자 그대로** 읽는다 — root 가 아닌 회차가 거부 0 으로
//! 통과하면 읽기에는 root 가 필요 없다는 실측이다. bookworm 컨테이너에서 uid 1000 으로 돌려 그렇게 통과했다
//! (2026-11-28). 러너의 `cargo test` 도 root 가 아닌 사용자로 돌 것으로 보지만 재지 않았다 — 실패 문구가 uid 를 적는다.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_remedy");

fn rule() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testbed/harness/linux/kernel-plugin.yaml")
}

fn work() -> PathBuf {
    let d = std::env::temp_dir().join("remedy-cli-running-kernel");
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("작업 폴더");
    d
}

/// 이 기계의 명령 하나 — (성공했는가, 표준 출력에서 끝 줄바꿈 하나를 뗀 것). 명령이 없으면 `None`.
fn host(prog: &str, args: &[&str]) -> Option<(bool, String)> {
    let o = Command::new(prog).args(args).output().ok()?;
    let s = String::from_utf8_lossy(&o.stdout);
    Some((
        o.status.success(),
        s.strip_suffix('\n').unwrap_or(&s).to_string(),
    ))
}

fn must(prog: &str, args: &[&str]) -> String {
    match host(prog, args) {
        Some((true, s)) => s,
        other => panic!("{prog} {args:?}: {other:?}"),
    }
}

/// 개발 빌드를 관리자 문만 넘겨 부른다 — 도는 사용자는 그대로다.
fn remedy(args: &[&str]) -> (i32, String) {
    let out = Command::new(EXE)
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        .env("REMEDY_LANG", "ko")
        .output()
        .unwrap_or_else(|e| panic!("{EXE} 실행 실패: {e}"));
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn json(p: &Path, text: &str) -> serde_json::Value {
    let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}\n{text}", p.display()));
    serde_json::from_slice(&bytes).expect("json")
}

/// 커널이 낸 파일 — 값 뒤의 줄바꿈 하나를 뗀다. 없으면 빈 문자열(그 밖의 오류는 실패).
fn proc_value(path: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(s) => s.strip_suffix('\n').unwrap_or(&s).to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => panic!("{path}: {e}"),
    }
}

/// dpkg 가 그 패키지를 깔린 것으로 아는가 — 수집기와 같은 잣대(깔림 · 트리거 대기)로 `Status-Abbrev` 의 둘째 글자를
/// 본다. dpkg 가 없거나 모르는 이름이면 아니다.
fn dpkg_installed(name: &str) -> bool {
    match host("dpkg-query", &["-W", "-f", "${db:Status-Abbrev}", name]) {
        Some((true, s)) => matches!(s.chars().nth(1), Some('i' | 't' | 'W')),
        _ => false,
    }
}

#[test]
fn the_running_kernel_here_is_read_and_linked_to_its_own_package() {
    let w = work();
    let uid = must("id", &["-u"]);
    let rule = rule().display().to_string();
    let a = w.join("artifacts.json");
    let (code, text) = remedy(&[
        "collect",
        "--plugin",
        &rule,
        "--out",
        &a.display().to_string(),
    ]);
    assert_eq!(code, 0, "collect — uid {uid}\n{text}");
    let env = json(&a, &text);
    // 거부 · 잘림이 없다 — root 가 아닌 회차에서 이것이 '읽기에 root 가 필요 없다' 의 실측이다.
    let scope = &env["scope"];
    assert_eq!(scope["denied_dirs"], 0, "uid {uid} · {scope}");
    assert_eq!(scope["truncated"], false, "uid {uid} · {scope}");

    let kernel = env["kernel"].as_array().expect("kernel 배열");
    assert_eq!(kernel.len(), 1, "{kernel:?}");
    let k = &kernel[0];
    let release = must("uname", &["-r"]);
    assert_eq!(k["release"], release.as_str(), "{k}");
    assert_eq!(k["build"], must("uname", &["-v"]).as_str(), "{k}");
    assert_eq!(
        k["release"],
        proc_value("/proc/sys/kernel/osrelease").as_str(),
        "{k}"
    );
    assert_eq!(
        k["signature"],
        proc_value("/proc/version_signature").as_str(),
        "{k}"
    );

    // 이음 — 그 자리의 dpkg 가 말하는 대로.
    let name = format!("linux-image-{release}");
    let installed = dpkg_installed(&name);
    let s = w.join("scan.json");
    let (code, text) = remedy(&[
        "evaluate",
        "--artifacts",
        &a.display().to_string(),
        "--plugin",
        &rule,
        "--out",
        &s.display().to_string(),
    ]);
    let scan = json(&s, &text);
    let linked: Vec<&str> = scan["evidence"]
        .as_array()
        .expect("evidence")
        .iter()
        .filter(|e| e["rule"] == "linked")
        .filter_map(|e| e["target"]["name"].as_str())
        .collect();
    if installed {
        assert_eq!(linked, [name.as_str()], "dpkg 가 {name} 을 안다\n{text}");
        assert_eq!(code, 2, "이어졌으면 판정이 선다\n{text}");
    } else {
        assert!(linked.is_empty(), "dpkg 가 {name} 을 모른다: {linked:?}");
        assert_eq!(code, 0, "이어지지 않으면 판정이 서지 않는다\n{text}");
    }
}
