//! 결과 폴더 · 실행 번호 · 결과 파일 — `url` · `image` · `container` 가 함께 쓴다.
//!
//! 결과 폴더는 약관과 입력 검사를 지난 뒤에만 만든다 — 점검하지 않은 실행은 폴더를 남기지 않는다. 결과 파일은
//! 덮어쓰지 않고(같은 이름이 있으면 실패), 유닉스에서는 주인만 읽는다(0600).

use crate::text::ascii_safe;
use crate::{clock, Outcome};
use remedy_sdk::i18n::Lang;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// 결과 폴더의 기본값 — 스캐너와 같다.
pub(crate) const DEFAULT_OUT_DIR: &str = "results";

/// 결과 파일의 상한 — 넘으면 쓰지 않고 처리 실패로 끝낸다.
const MAX_REPORT_BYTES: usize = 16 << 20;

/// 이 기계의 경로만 — 네트워크 경로(`\\` · `//`)와 제어 문자는 받지 않는다.
pub(crate) fn local_path(value: String, lang: Lang) -> Result<String, String> {
    if value.chars().any(char::is_control) || value.starts_with("\\\\") || value.starts_with("//") {
        return Err(lang
            .t(
                "이 기계의 경로를 적으십시오(네트워크 경로는 받지 않습니다).",
                "give a local path (network paths are not accepted).",
            )
            .to_string());
    }
    Ok(value)
}

/// 결과 폴더 — 없으면 만든다. 그 자리에 파일 · 링크가 있으면 쓰지 않는다.
pub(crate) fn prepare_dir(dir: &Path, lang: Lang) -> Result<PathBuf, &'static str> {
    if let Ok(m) = std::fs::symlink_metadata(dir) {
        if m.file_type().is_symlink() || !m.is_dir() {
            return Err(lang.t(
                "결과 폴더 자리에 폴더가 아닌 것(파일 · 링크)이 있습니다.",
                "the result folder path holds something that is not a folder (a file or a link).",
            ));
        }
    }
    std::fs::create_dir_all(dir).map_err(|_| {
        lang.t(
            "결과 폴더를 만들지 못했습니다.",
            "could not create the result folder.",
        )
    })?;
    Ok(dir.to_path_buf())
}

/// `20261110T031000Z-<16자리 16진수>` — 결과 파일 이름에도 들어간다.
pub(crate) fn run_id(started: SystemTime) -> String {
    let mut bytes = [0u8; 8];
    let random = rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .is_ok();
    let suffix: String = if random {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    } else {
        format!("{:016x}", std::process::id())
    };
    format!("{}-{suffix}", clock::compact(started))
}

/// 결과 파일 `remedy-net-<명령>-<실행 번호>.json` 을 쓴다 — 같은 이름이 있으면 덮지 않는다.
pub(crate) fn save_json<T: Serialize>(
    dir: &Path,
    command: &str,
    run_id: &str,
    report: &T,
) -> std::io::Result<PathBuf> {
    let bytes = serde_json::to_vec_pretty(report)?;
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(std::io::Error::other("결과가 16 MiB 를 넘는다"));
    }
    let path = dir.join(format!("remedy-net-{command}-{run_id}.json"));
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut f = open.open(&path)?;
    f.write_all(&bytes)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(path)
}

/// 처리 실패 — 까닭을 표준 오류에 한 줄로 내고 7 로 끝낸다.
pub(crate) fn fail(lang: Lang, why: &str) -> Outcome {
    eprintln!(
        "{}",
        ascii_safe(lang.pick(format!("오류: {why}"), format!("error: {why}")))
    );
    Outcome::Failed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "remedy-net-output-{name}-{}-{}",
            std::process::id(),
            run_id(SystemTime::now())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn network_paths_and_control_characters_are_refused() {
        for bad in ["\\\\server\\share", "//server/share", "out\ndir", "a\u{7}"] {
            assert!(local_path(bad.to_string(), Lang::Ko).is_err(), "{bad:?}");
        }
        assert_eq!(
            local_path("results".to_string(), Lang::Ko).as_deref(),
            Ok("results")
        );
    }

    #[test]
    fn a_file_in_the_folder_place_is_refused_and_a_folder_is_made() {
        let base = scratch("dir");
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("taken");
        std::fs::write(&file, b"x").unwrap();
        assert!(prepare_dir(&file, Lang::Ko).is_err());
        let made = prepare_dir(&base.join("new").join("deeper"), Lang::Ko).unwrap();
        assert!(made.is_dir());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_report_is_written_once_and_never_overwritten() {
        let dir = scratch("save");
        std::fs::create_dir_all(&dir).unwrap();
        let path = save_json(&dir, "image", "RUN", &serde_json::json!({"a": 1})).unwrap();
        assert!(path.ends_with("remedy-net-image-RUN.json"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with("}\n"), "{text}");
        assert!(save_json(&dir, "image", "RUN", &serde_json::json!({"a": 2})).is_err());
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"a\": 1"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_ids_differ_and_start_with_the_time() {
        let t = SystemTime::now();
        let (a, b) = (run_id(t), run_id(t));
        assert_ne!(a, b);
        assert_eq!(a.len(), "20261110T031000Z-0123456789abcdef".len());
        assert!(a.contains('T') && a.contains("Z-"));
    }
}
