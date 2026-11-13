//! 통합 시험의 기준 폴더 — 크레이트의 고정 사본(`testdata/url.json` · `testdata/baseline.json`)을 일회용 키로
//! 서명하고, 띄우는 `remedy-net` 에 그 자리(`REMEDY_NET_CRITERIA`)와 개발 키(`REMEDY_NET_ANCHOR`)를 준다.
//! 시험 빌드는 개발 빌드라 그 키를 받는다(배포 빌드는 박힌 키만 쓴다 · `src/criteria.rs`).

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// 서명한 기준 폴더와 그 공개키.
pub struct Signed {
    pub dir: PathBuf,
    pub anchor: String,
}

/// 이 시험 바이너리에서 한 번 만든다.
pub fn signed() -> &'static Signed {
    static ONE: OnceLock<Signed> = OnceLock::new();
    ONE.get_or_init(|| {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().expect("키쌍");
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("remedy-net-criteria-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("기준 폴더");
        let root = env!("CARGO_MANIFEST_DIR");
        for f in ["url.json", "baseline.json"] {
            std::fs::copy(format!("{root}/testdata/{f}"), dir.join(f)).expect(f);
        }
        sign(&dir, &kp, "remedy-net-criteria");
        Signed {
            dir,
            anchor: anchor(&kp),
        }
    })
}

/// 폴더를 통째로 서명한다 — 룰을 서명하는 것과 같은 형식(`cargo xtask sign`).
pub fn sign(dir: &std::path::Path, kp: &minisign::KeyPair, id: &str) {
    let tree = remedy_trust::collect(dir).expect("트리");
    let manifest = remedy_trust::Manifest::render(&tree);
    let comment = remedy_trust::TrustedComment::render(id, "1.0.0", "2026-11-13T00:00:00Z");
    let sig = minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        manifest.as_bytes(),
        Some(&comment),
        Some("remedy plugin signature"),
    )
    .expect("서명");
    std::fs::write(dir.join(remedy_trust::MANIFEST_NAME), manifest).expect("매니페스트");
    std::fs::write(dir.join(remedy_trust::SIGNATURE_NAME), sig.to_string()).expect("서명 파일");
}

/// 공개키의 base64 한 줄 — 배포 빌드에 박는 값과 같은 꼴.
pub fn anchor(kp: &minisign::KeyPair) -> String {
    let boxed = kp.pk.to_box().expect("공개키 상자").to_string();
    boxed.lines().nth(1).expect("공개키 줄").trim().to_string()
}

/// 서명한 기준 폴더를 보는 `remedy-net`.
pub fn command() -> Command {
    let s = signed();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_remedy-net"));
    cmd.env("REMEDY_NET_CRITERIA", &s.dir)
        .env("REMEDY_NET_ANCHOR", &s.anchor);
    cmd
}
