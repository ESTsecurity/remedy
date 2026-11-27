//! `restore` 의 **종료 코드와 부작용**을 실제 바이너리로 확인한다.
//!
//! 무인 배포는 종료 코드만 본다. "가드가 막았다"(5)와 "하지 않았다"(2)와
//! "복원했다"(0)가 뒤섞이면 후속 조치가 어긋난다.
//!
//! 그리고 여기서 재는 것의 절반은 **하지 않은 일**이다 — 계획만 보였을 때
//! 파일이 생기지 않았는가, 가드가 막았을 때 보호 경로에 쓰지 않았는가.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_remedy")
}

struct Lab {
    dir: PathBuf,
}

impl Lab {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("remedy-restore-it-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }
    fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }
    fn s(&self, rel: &str) -> String {
        self.path(rel).to_string_lossy().to_string()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 컨테이너를 만든다. 격리물을 **만드는** 것은 P6 의 몫이라 제품 CLI 에 없다.
fn make_container(out: &Path, entries: Vec<(&str, &[u8], serde_json::Value)>, passphrase: &str) {
    use remedy_core::quarantine::{ContentKey, Header};
    let ck = ContentKey::generate().unwrap();
    let header = Header {
        run_id: "01JTEST0000000000000000A".into(),
        created: "2026-08-21T00:00:00Z".into(),
        core_version: "0".into(),
        cipher: "xchacha20poly1305".into(),
        wraps: vec![remedy_quarantine::wrap_with_passphrase(passphrase, &ck).unwrap()],
    };
    let mut b = remedy_quarantine::Builder::new(header, "it-fixture");
    for (origin, content, meta) in entries {
        b.add(remedy_quarantine::Entry {
            kind: remedy_sdk::EntryKind::File,
            origin: origin.to_string(),
            meta,
            content: content.to_vec(),
        });
    }
    std::fs::write(out, b.seal(&ck).unwrap()).unwrap();
}

fn run(args: &[&str]) -> (i32, String) {
    let o = Command::new(bin())
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        // 시험은 한국어 문구를 단정한다. 기본 언어는 영어다 (2026-09-06).
        .env("REMEDY_LANG", "ko")
        .output()
        .expect("실행");
    let text = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
    (o.status.code().unwrap_or(-1), text)
}

#[test]
fn plan_only_writes_nothing_and_exits_two() {
    let lab = Lab::new("planonly");
    let dest = lab.s("복원될 파일.bin");
    std::fs::write(lab.path("pass.txt"), "열쇠말").unwrap();
    make_container(
        &lab.path("c.rq"),
        vec![(dest.as_str(), b"original", serde_json::json!({}))],
        "열쇠말",
    );

    let (code, out) = run(&[
        "restore",
        "--container",
        &lab.s("c.rq"),
        "--passphrase-file",
        &lab.s("pass.txt"),
        "--state-dir",
        &lab.s("state"),
    ]);
    assert_eq!(code, 2, "계획만 보였으면 2 여야 한다\n{out}");
    assert!(out.contains("아무것도 하지 않았습니다"), "{out}");
    assert!(!Path::new(&dest).exists(), "계획만 보이는데 파일이 생겼다");
}

#[test]
fn yes_restores_the_exact_bytes_and_exits_zero() {
    let lab = Lab::new("yes");
    let dest = lab.s("payload.bin");
    let body: Vec<u8> = (0u8..=255).cycle().take(3000).collect();
    std::fs::write(lab.path("pass.txt"), "열쇠말").unwrap();
    make_container(
        &lab.path("c.rq"),
        vec![(dest.as_str(), &body, serde_json::json!({}))],
        "열쇠말",
    );

    let (code, out) = run(&[
        "restore",
        "--container",
        &lab.s("c.rq"),
        "--passphrase-file",
        &lab.s("pass.txt"),
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(std::fs::read(&dest).unwrap(), body, "바이트가 달라졌다");
}

#[test]
fn a_protected_destination_stops_the_whole_restore_with_five() {
    // **복원도 쓰기다.** 하나라도 보호 대상을 가리키면 전부 멈춘다 — 남은 것만
    // 골라 복원하려면 `--entry` 로 명시해야 한다. 조용히 일부만 하면 사용자는
    // 무엇이 빠졌는지 모른다.
    let lab = Lab::new("guard");
    // 컨테이너는 **호스트가 만든 것**이라 이 기계의 저널에 대응하는 기록이
    // 없다. 그것이 이 시험의 핵심이다 — 넘겨받은 격리물은 보호 경로에 쓸 수
    // 없어야 하고, 판별자는 컨테이너가 아니라 **우리 저널**이다
    // (`restore.rs` 의 `vouched`).
    let bait = if cfg!(windows) {
        "C:\\Windows\\System32\\remedy-it-must-not-write.dll"
    } else {
        "/etc/remedy-it-must-not-write"
    };
    let safe = lab.s("safe.bin");
    std::fs::write(lab.path("pass.txt"), "열쇠말").unwrap();
    make_container(
        &lab.path("c.rq"),
        vec![
            (safe.as_str(), b"safe", serde_json::json!({})),
            (bait, b"bait", serde_json::json!({})),
        ],
        "열쇠말",
    );

    let (code, out) = run(&[
        "restore",
        "--container",
        &lab.s("c.rq"),
        "--passphrase-file",
        &lab.s("pass.txt"),
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 5, "가드 중단은 5 여야 한다\n{out}");
    assert!(!Path::new(bait).exists(), "보호 경로에 썼다");
    assert!(
        !Path::new(&safe).exists(),
        "가드가 막았는데 나머지를 복원했다"
    );
}

#[test]
fn an_unexpanded_token_is_refused() {
    // 불변식 R. 토큰이 남아 있으면 다른 머신에서 다른 곳으로 복원된다.
    let lab = Lab::new("token");
    std::fs::write(lab.path("pass.txt"), "열쇠말").unwrap();
    make_container(
        &lab.path("c.rq"),
        vec![(
            "%LOCALAPPDATA%\\Programs\\evil\\x.exe",
            b"x",
            serde_json::json!({}),
        )],
        "열쇠말",
    );

    let (code, out) = run(&[
        "restore",
        "--container",
        &lab.s("c.rq"),
        "--passphrase-file",
        &lab.s("pass.txt"),
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 5, "{out}");
    assert!(out.contains("불변식 R"), "{out}");
}

#[test]
fn extract_mode_never_touches_the_original_path() {
    // 꺼내기는 원본 자리에 쓰지 않는다. 보호 경로 항목도 꺼낼 수는 있어야 한다 —
    // 그것이 오탐 복구의 마지막 수단이다 (설계-02 §9).
    let lab = Lab::new("extract");
    let bait = if cfg!(windows) {
        "C:\\Windows\\System32\\remedy-it-extract-only.dll"
    } else {
        "/etc/remedy-it-extract-only"
    };
    std::fs::write(lab.path("pass.txt"), "열쇠말").unwrap();
    make_container(
        &lab.path("c.rq"),
        vec![(bait, b"payload", serde_json::json!({}))],
        "열쇠말",
    );

    let (code, out) = run(&[
        "restore",
        "--container",
        &lab.s("c.rq"),
        "--passphrase-file",
        &lab.s("pass.txt"),
        "--state-dir",
        &lab.s("state"),
        "--extract-to",
        &lab.s("out"),
        "--yes",
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(!Path::new(bait).exists(), "원본 자리에 썼다");
    let got: Vec<_> = std::fs::read_dir(lab.path("out")).unwrap().collect();
    assert_eq!(got.len(), 1, "꺼낸 파일이 없다");
}

/// `--yes` 로 되돌리고 그 화면에서 '복원 [e0]' 줄 뒤만 돌려준다 — 계획 쪽의 '복원 불가' 줄과 가르기 위해서다.
fn restore_and_take_the_after_part(
    lab: &Lab,
    dest: &str,
    meta: serde_json::Value,
) -> (i32, String) {
    std::fs::write(lab.path("pass.txt"), "열쇠말").unwrap();
    make_container(&lab.path("c.rq"), vec![(dest, b"x", meta)], "열쇠말");
    let (code, out) = run(&[
        "restore",
        "--container",
        &lab.s("c.rq"),
        "--passphrase-file",
        &lab.s("pass.txt"),
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    let after = out
        .split_once("  복원 [e0]")
        .map(|(_, a)| a.to_string())
        .unwrap_or_else(|| panic!("복원 줄이 없다\n{out}"));
    (code, after)
}

#[cfg(windows)]
#[test]
fn what_the_plan_promised_but_the_restore_missed_is_said_after_restoring() {
    // 계획은 담아 둔 SDDL 을 되돌린다고 하지만 그 문자열이 SDDL 이 아니라는 것은 쓸 때에야 안다. 1.26.0 은 복원
    // 뒤의 보고서를 찍지 않아 '복원 [e0] … (content · …)' 줄만 남고 못 된 것이 화면에서 사라졌다(이슈 #172 ①).
    // 종료 코드는 그대로 0 이다 — 본문은 돌아왔다.
    let lab = Lab::new("missed");
    let dest = lab.s("payload.bin");
    let meta = serde_json::json!({ "sddl": "이건 SDDL 이 아니다" });
    let (code, after) = restore_and_take_the_after_part(&lab, &dest, meta);
    assert_eq!(code, 0, "{after}");
    assert!(
        after.contains("복원 불가  sddl: SDDL 을 해석하지 못했습니다"),
        "되돌린 뒤 못 된 것을 말하지 않는다\n{after}"
    );
}

#[cfg(unix)]
#[test]
fn what_the_plan_promised_but_the_restore_missed_is_said_after_restoring() {
    // 계획은 담아 둔 소유자를 되돌린다고 하지만 남의 uid 로 chown 하는 길은 root 에서만 열린다 — root 가 아닌
    // 회차는 쓸 때에야 막힌다. 1.26.0 은 소유자를 되돌리지 않고 복원 뒤의 보고서도 찍지 않았다(이슈 #172 ①).
    // 소유자를 되돌리지 못하면 setuid · setgid 를 뺀다 — 남의 것이던 4755 가 되돌린 사람의 4755 가 되지 않는다.
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let lab = Lab::new("missed");
    let dest = lab.s("tool");
    let root = std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0);
    let meta = serde_json::json!({ "uid": 65534, "gid": 65534, "mode": 0o104755 });
    let (code, after) = restore_and_take_the_after_part(&lab, &dest, meta);
    assert_eq!(code, 0, "{after}");
    let md = std::fs::metadata(&dest).unwrap();
    // 가운뎃점은 터미널이 UTF-8 이 아니면 `|` 로 찍힌다 — 칸 이름의 차례만 본다.
    let first = after.lines().next().unwrap_or("");
    if root {
        let (o, m) = (first.find("owner"), first.find("mode"));
        assert!(
            o.is_some() && o < m,
            "소유자를 mode 보다 먼저 되돌린다\n{after}"
        );
        assert_eq!(md.uid(), 65534, "{after}");
        assert_eq!(md.permissions().mode() & 0o7777, 0o4755, "{after}");
        assert!(!after.contains("복원 불가"), "{after}");
    } else {
        assert!(after.contains("복원 불가  owner: "), "{after}");
        assert!(
            after.contains("복원 불가  mode: 소유자를 되돌리지 못해"),
            "{after}"
        );
        assert_eq!(md.permissions().mode() & 0o7777, 0o755, "{after}");
    }
}

#[cfg(unix)]
#[test]
fn a_user_link_on_the_way_stops_the_restore_with_five_and_writes_nothing() {
    // 1.26.0 에서 잰 꼴(이슈 #172 ①) — 격리된 파일의 부모를 사용자가 root 의 자리를 가리키는 링크로 바꿔 두자
    // 제자리 복원이 그 링크를 따라 root 의 자리에 담아 둔 이름 · 바이트 · 소유자 · 4755 를 썼다. 가드가 막고(5)
    // 아무것도 쓰지 않는다. root 로 돌면 링크를 남의 uid(4242)로 바꾸고, 아니면 링크가 이미 이 시험의 것이다.
    use std::os::unix::fs::{lchown, symlink, MetadataExt};
    let lab = Lab::new("linkguard");
    let place = lab.path("root-place");
    std::fs::create_dir_all(&place).unwrap();
    let bin = lab.path("bin");
    symlink(&place, &bin).unwrap();
    if std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0) {
        lchown(&bin, Some(4242), Some(4242)).unwrap();
    }
    let tool = lab.s("bin/tool");
    std::fs::write(lab.path("pass.txt"), "열쇠말").unwrap();
    make_container(
        &lab.path("c.rq"),
        vec![(
            tool.as_str(),
            b"x",
            serde_json::json!({ "mode": 0o104755, "uid": 4242, "gid": 4242 }),
        )],
        "열쇠말",
    );
    let (code, out) = run(&[
        "restore",
        "--container",
        &lab.s("c.rq"),
        "--passphrase-file",
        &lab.s("pass.txt"),
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 5, "가드 중단은 5 여야 한다\n{out}");
    assert!(out.contains("링크를 따라 쓰지 않습니다"), "{out}");
    assert!(
        std::fs::read_dir(&place).unwrap().next().is_none(),
        "링크가 가리킨 자리에 썼다\n{out}"
    );
    assert!(std::fs::symlink_metadata(&bin)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn a_wrong_passphrase_does_not_open_it() {
    let lab = Lab::new("wrongpass");
    std::fs::write(lab.path("pass.txt"), "틀린 말").unwrap();
    make_container(
        &lab.path("c.rq"),
        vec![(lab.s("x").as_str(), b"x", serde_json::json!({}))],
        "맞는 말",
    );
    let (code, out) = run(&[
        "restore",
        "--container",
        &lab.s("c.rq"),
        "--passphrase-file",
        &lab.s("pass.txt"),
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("개봉 실패"), "{out}");
}

#[test]
fn a_local_only_container_warns_that_a_reinstall_loses_it() {
    // 설계-03 §5 — 로컬 wrap 뿐이면 머신을 재설치하는 순간 열 수 없다.
    // 그 사실을 말하지 않으면 사용자는 백업이 있다고 믿는다.
    let lab = Lab::new("localonly");
    use remedy_core::quarantine::{ContentKey, Header};
    let ck = ContentKey::generate().unwrap();
    let mk = remedy_quarantine::MachineKey::load_or_create(&lab.path("state/machine.key")).unwrap();
    let header = Header {
        run_id: "01JTEST0000000000000000B".into(),
        created: "2026-08-21T00:00:00Z".into(),
        core_version: "0".into(),
        cipher: "xchacha20poly1305".into(),
        wraps: vec![mk.wrap(&ck).unwrap()],
    };
    let mut b = remedy_quarantine::Builder::new(header, "it");
    b.add(remedy_quarantine::Entry {
        kind: remedy_sdk::EntryKind::File,
        origin: lab.s("x.bin"),
        meta: serde_json::json!({}),
        content: b"x".to_vec(),
    });
    std::fs::write(lab.path("c.rq"), b.seal(&ck).unwrap()).unwrap();

    let (code, out) = run(&[
        "restore",
        "--container",
        &lab.s("c.rq"),
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("재설치하면"), "경고가 없다\n{out}");
}
