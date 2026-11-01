//! 배포 꾸러미의 모양이 **탐색과 검증 둘 다** 만족하는가.
//!
//! 두 요구가 서로 당긴다.
//!
//! - `plugin verify` 는 디렉터리의 **모든** 파일이 매니페스트에 있기를 요구한다.
//!   그것이 "몰래 추가한 룰" 방어의 핵심이다(`TrustedComment` 설계, `TreeDiff::Extra`).
//! - 꾸러미에는 `remedy.exe` 와 `README.txt` 가 함께 있어야 한다. 받는 사람이
//!   푸는 폴더가 그것이기 때문이다.
//!
//! 둘을 한 폴더에 두면 **꾸러미가 자기 검증에 실패한다** — 2026-09-08 에 실제로
//! 밟았고(`README.txt`·`remedy.exe`: 서명되지 않은 파일이 들어 있습니다, 종료 5),
//! 플러그인을 `plugins/<이름>/` 안에 두어 검증 경계와 꾸러미 경계를 갈랐다.
//!
//! **그 배치를 여기서 잠근다.** `xtask package` 가 만드는 모양이 바뀌면 이 시험이
//! 먼저 운다 — 받는 사람이 발견하기 전에.

use std::path::{Path, PathBuf};

/// 꾸러미 모양을 흉내 낸다. 서명은 하지 않는다 — 여기서 재는 것은 **배치**이고,
/// 서명 사슬은 `remedy-trust` 의 시험과 `plugin verify` 가 잰다.
fn bundle(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join("remedy-cli-bundle").join(name);
    let _ = std::fs::remove_dir_all(&d);
    let plugin = d.join("plugins").join("evilai-locust");
    std::fs::create_dir_all(plugin.join("rules")).expect("꾸러미");
    for (p, body) in [
        (d.join("remedy.exe"), "MZ"),
        (d.join("README.txt"), "쓰는 법"),
        (
            plugin.join("plugin.yaml"),
            "schema_version: 1\nid: evilai-locust\n",
        ),
        (
            plugin.join("rules/evilai.yar"),
            "rule x { condition: false }",
        ),
        (plugin.join("MANIFEST"), "# remedy plugin manifest v1\n"),
        (plugin.join("MANIFEST.minisig"), "untrusted comment: x\n"),
    ] {
        std::fs::write(&p, body).expect("파일");
    }
    d
}

/// `discover::beside` 와 같은 규칙 — 실행 파일 옆의 `plugin.yaml` 과
/// `plugins/<이름>/plugin.yaml` 을 한 단계까지 본다.
///
/// **제품 코드를 그대로 부르지 못한다** — `discover` 는 바이너리 크레이트의
/// 모듈이라 통합 시험에서 링크되지 않는다. 그래서 규칙을 여기 다시 적되,
/// 갈라지면 아래 시험이 잡도록 **같은 두 자리만** 본다.
fn found_plugins(exe: &Path) -> Vec<PathBuf> {
    let Some(root) = exe.parent() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let flat = root.join("plugin.yaml");
    if flat.is_file() {
        out.push(flat);
    }
    if let Ok(rd) = std::fs::read_dir(root.join("plugins")) {
        let mut dirs: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for dir in dirs {
            let p = dir.join("plugin.yaml");
            if p.is_file() {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn the_bundle_layout_is_discoverable() {
    // 안내 모드(4-3)가 이 꾸러미를 열었을 때 플러그인을 찾아야 한다.
    let d = bundle("discoverable");
    let got = found_plugins(&d.join("remedy.exe"));
    assert_eq!(got.len(), 1, "{got:?}");
    assert!(
        got[0].ends_with("plugins/evilai-locust/plugin.yaml")
            || got[0].ends_with(r"plugins\evilai-locust\plugin.yaml"),
        "{got:?}"
    );
}

#[test]
fn the_exe_and_readme_are_outside_the_signed_folder() {
    // **이것이 2026-09-08 에 밟은 결함이다.** 서명 경계 안에 서명되지 않은 파일이
    // 있으면 `plugin verify` 가 그 폴더를 거부한다.
    let d = bundle("boundary");
    let signed = d.join("plugins").join("evilai-locust");

    for stray in ["remedy.exe", "README.txt"] {
        assert!(
            !signed.join(stray).exists(),
            "{stray} 가 서명 경계 안에 있다 — 꾸러미가 자기 검증에 실패한다"
        );
        assert!(d.join(stray).is_file(), "{stray} 가 꾸러미 뿌리에 없다");
    }

    // 서명 경계 안에 있어야 하는 것.
    for needed in ["plugin.yaml", "MANIFEST", "MANIFEST.minisig"] {
        assert!(signed.join(needed).is_file(), "{needed} 가 없다");
    }
    assert!(signed.join("rules").join("evilai.yar").is_file());
}

#[test]
fn a_flat_layout_would_put_the_exe_inside_the_signed_folder() {
    // 위 시험이 "무엇이든 통과" 로 서지 않게 — 실패하던 옛 배치를 만들어
    // 그것이 실제로 경계를 깨는지 보인다.
    let d = std::env::temp_dir().join("remedy-cli-bundle").join("flat");
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("rules")).expect("폴더");
    for (p, body) in [
        (d.join("remedy.exe"), "MZ"),
        (d.join("plugin.yaml"), "id: x"),
        (d.join("MANIFEST"), "# remedy plugin manifest v1\n"),
    ] {
        std::fs::write(&p, body).expect("파일");
    }
    // 서명 경계(= MANIFEST 가 있는 폴더)에 실행 파일이 함께 있다.
    let boundary = d.clone();
    assert!(
        boundary.join("remedy.exe").exists(),
        "이 배치가 바로 거부당하던 모양이다"
    );
}
