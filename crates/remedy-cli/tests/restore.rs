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
