//! 실행 파일 옆의 플러그인을 찾고, **쓸 수 있는지 확인한다** (Phase 4-2).
//!
//! # 왜 필요한가
//!
//! `run`·`scan` 은 `--plugin <경로>` 를 요구한다. 그것이 옳다 — 운영자가 무엇을
//! 돌릴지 명시하는 자리다. 그러나 홈페이지에서 받아 더블클릭한 사람에게는 칠
//! 자리가 없다. 지금 배포물의 정의상(`docs/operator.md` §0: 실행 파일 · plugin.yaml ·
//! 그 옆 rules/) 그 사람은 압축을 풀고 YAML 경로를 타이핑해야 한다 —
//! 할 수 없다.
//!
//! # 어디서도 부르지 않는다 — 아직은
//!
//! **이 모듈은 4-2 에서 시험으로만 선다.** 안내 모드 본체(4-3)가 이것을 부르고,
//! 그 전까지 제품 동작은 한 글자도 바뀌지 않는다. `run --plugin` 없이 부르면
//! 지금처럼 종료 코드 4 다.
//!
//! 순서를 그렇게 잡은 이유가 있다. 탐색은 **읽기 권한의 상한을 여는 일**이라,
//! 검증 게이트가 서기 전에 로드 경로에 붙이면 실행 파일 옆에 `plugin.yaml` 을
//! 놓을 수 있는 무엇이든 관리자 권한의 삭제 도구를 얻는다.
//!
//! # 검증이 없으면 쓰지 않는다
//!
//! 찾은 것을 그냥 쓰지 않는다. `plugin verify` 와 **같은 사슬**을 지나야 한다 —
//! 앵커 → 서명된 매니페스트 → 파일 목록 대조. 그 사슬의 첫 고리인 신뢰 앵커가
//! 이 빌드에 없으면(지금이 그렇다) **거절한다.** 경고하고 진행하는 선택지도
//! 있었지만, 그러면 검증 없는 자동 탐색이 제품에 들어간다 (결정 2026-09-08).

use std::path::{Path, PathBuf};

/// 찾은 플러그인 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// `plugin.yaml` 의 경로.
    pub path: PathBuf,
    /// 그 디렉터리 — 검증과 룰 적재가 보는 자리다.
    pub dir: PathBuf,
}

/// 왜 쓸 수 없는가. **화면 문구는 부르는 쪽이 만든다** — 이 모듈은 사실만 낸다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unusable {
    /// 이 빌드에 신뢰 앵커가 박혀 있지 않다. 검증 자체가 불가능하다.
    NoAnchor,
    /// 서명 매니페스트나 서명 파일이 없다 — 서명되지 않은 꾸러미다.
    NotSigned(String),
    /// 서명이 맞지 않거나 파일 목록이 어긋난다.
    Tampered(String),
}

/// 실행 파일 옆에서 플러그인을 찾는다. **읽기만 한다.**
///
/// 두 자리를 본다 — 실행 파일과 나란히 놓인 `plugin.yaml`, 그리고
/// `plugins/<이름>/plugin.yaml`. 배포물이 그 두 모양 중 하나이기 때문이고,
/// 더 깊이 뒤지지 않는다: 깊이 뒤질수록 "옆에 놓기만 하면 된다" 는 공격면이
/// 넓어진다.
///
/// 이름 순으로 돌려준다 — 같은 꾸러미에서 늘 같은 차례가 나와야 사람이 고른
/// 번호가 뜻을 갖는다.
pub fn beside(exe: &Path) -> Vec<Found> {
    let Some(root) = exe.parent() else {
        return Vec::new();
    };
    let mut out = Vec::new();

    let flat = root.join("plugin.yaml");
    if flat.is_file() {
        out.push(Found {
            dir: root.to_path_buf(),
            path: flat,
        });
    }

    let nest = root.join("plugins");
    if let Ok(rd) = std::fs::read_dir(&nest) {
        let mut dirs: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for d in dirs {
            let p = d.join("plugin.yaml");
            if p.is_file() {
                out.push(Found { dir: d, path: p });
            }
        }
    }
    out
}

/// 이 꾸러미를 써도 되는가 — `plugin verify` 와 **같은 사슬**이다.
///
/// `anchor_b64` 는 빌드에 박힌 앵커(`EMBEDDED_ANCHOR`). `None` 이면 검증할 방법이
/// 없으므로 [`Unusable::NoAnchor`] 다.
///
/// # 폐기 목록은 여기서 보지 않는다
///
/// 그것은 상태 디렉터리를 읽는 일이고 부르는 쪽이 그 경로를 안다. 여기는
/// **꾸러미 자체가 우리 것인가** 만 답한다 — `plugin verify` 도 그 순서다.
pub fn usable(dir: &Path, anchor_b64: Option<&str>) -> Result<(), Unusable> {
    let Some(b64) = anchor_b64 else {
        return Err(Unusable::NoAnchor);
    };
    let anchor = remedy_trust::Anchor::from_base64(b64)
        .map_err(|e| Unusable::Tampered(format!("신뢰 앵커를 읽지 못했습니다: {e}")))?;

    // **없는 것과 틀린 것을 나눈다.** 미서명 꾸러미는 "서명이 없다" 로 보고돼야
    // 하고, 그것을 "검증 실패" 와 뭉뚱그리면 받는 사람이 원인을 찾는 데 시간을
    // 쓴다 (`cmd_plugin_verify` 가 같은 이유로 같게 나눈다).
    let manifest_path = dir.join(remedy_trust::MANIFEST_NAME);
    let sig_path = dir.join(remedy_trust::SIGNATURE_NAME);
    let manifest = std::fs::read(&manifest_path)
        .map_err(|_| Unusable::NotSigned(manifest_path.display().to_string()))?;
    let signature = std::fs::read_to_string(&sig_path)
        .map_err(|_| Unusable::NotSigned(sig_path.display().to_string()))?;

    let verified = remedy_trust::verify_manifest(&anchor, &manifest, &signature)
        .map_err(|e| Unusable::Tampered(e.to_string()))?;
    let actual = remedy_trust::collect(dir).map_err(|e| Unusable::Tampered(e.to_string()))?;
    verified
        .check_tree(&actual)
        .map_err(|e| Unusable::Tampered(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 실행 파일 하나와 그 옆의 자리들.
    fn lab(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join("remedy-cli-discover").join(name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("작업 디렉터리");
        d
    }

    fn touch(p: &Path) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("상위");
        }
        std::fs::write(p, "schema_version: 1\n").expect("파일");
    }

    #[test]
    fn nothing_beside_the_binary_is_not_an_error() {
        // 치료할 것을 못 찾은 것과 실패는 다르다. 빈 목록이 그 사실이다.
        let d = lab("empty");
        assert_eq!(beside(&d.join("remedy.exe")), Vec::new());
    }

    #[test]
    fn a_plugin_next_to_the_binary_is_found() {
        let d = lab("flat");
        touch(&d.join("plugin.yaml"));
        let got = beside(&d.join("remedy.exe"));
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].dir, d);
        assert_eq!(got[0].path, d.join("plugin.yaml"));
    }

    #[test]
    fn plugins_in_their_own_folders_are_found_in_name_order() {
        // **차례가 고정이라야 사람이 고른 번호가 뜻을 갖는다.**
        let d = lab("nested");
        touch(&d.join("plugins").join("zeta").join("plugin.yaml"));
        touch(&d.join("plugins").join("alpha").join("plugin.yaml"));
        touch(&d.join("plugins").join("mid").join("plugin.yaml"));
        let got = beside(&d.join("remedy.exe"));
        let names: Vec<String> = got
            .iter()
            .map(|f| f.dir.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["alpha", "mid", "zeta"], "{got:?}");
    }

    #[test]
    fn the_search_does_not_go_deeper_than_one_level() {
        // 깊이 뒤질수록 "옆에 놓기만 하면 된다" 는 자리가 넓어진다.
        let d = lab("deep");
        touch(&d.join("plugins").join("a").join("b").join("plugin.yaml"));
        assert_eq!(beside(&d.join("remedy.exe")), Vec::new());
    }

    #[test]
    fn a_directory_named_plugin_yaml_is_not_a_plugin() {
        // `is_file` 이 아니라 존재만 보면 폴더가 플러그인으로 잡힌다.
        let d = lab("dirnamed");
        std::fs::create_dir_all(d.join("plugin.yaml")).expect("폴더");
        assert_eq!(beside(&d.join("remedy.exe")), Vec::new());
    }

    #[test]
    fn without_an_anchor_nothing_is_usable() {
        // **이 빌드의 지금 상태다.** 앵커를 주는 자리가 저장소 어디에도 없다
        // (`option_env!("REMEDY_TRUST_ANCHOR")` 의 값이 비어 있다). 그때 찾은
        // 것을 그냥 쓰면 검증 없는 자동 탐색이 제품에 들어간다.
        let d = lab("noanchor");
        touch(&d.join("plugin.yaml"));
        assert_eq!(usable(&d, None), Err(Unusable::NoAnchor));
    }

    #[test]
    fn an_unsigned_bundle_says_it_is_unsigned_not_that_it_failed() {
        // 받는 사람이 원인을 찾는 데 시간을 쓰지 않게, 없는 것과 틀린 것을 나눈다.
        let d = lab("unsigned");
        touch(&d.join("plugin.yaml"));
        // 형식이 맞는 앵커라야 그다음 고리까지 간다. 실제 릴리스 키가 아니라
        // 이 시험을 위해 만든 것이다.
        let anchor = remedy_trust::Anchor::from_base64(TEST_ANCHOR_B64);
        assert!(anchor.is_ok(), "시험용 앵커가 형식에 맞지 않다: {anchor:?}");
        match usable(&d, Some(TEST_ANCHOR_B64)) {
            Err(Unusable::NotSigned(what)) => {
                assert!(what.contains(remedy_trust::MANIFEST_NAME), "{what}")
            }
            other => panic!("서명 없음으로 보고하지 않았다: {other:?}"),
        }
    }

    /// 형식만 맞는 시험용 minisign 공개키. **릴리스 키가 아니다** — 이것으로
    /// 서명된 것은 없으므로 검증은 언제나 실패한다. 여기서 재는 것은 *"앵커가
    /// 있을 때 그다음 고리까지 가는가"* 뿐이다.
    const TEST_ANCHOR_B64: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
}
