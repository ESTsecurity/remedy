//! 회차 로그 — 화면에 나간 모든 줄이 시각과 함께 남는 파일.
//!
//! # 왜 필요한가
//!
//! 저널(`journal.jsonl`)은 기계가 읽는 기록이고 **무엇을 했는가**만 적는다.
//! 배너·계획·경고·실패 문구·마무리 표 — 사람이 본 화면은 stdout/stderr 로만
//! 나가서 콘솔을 닫으면 사라졌다. 신고할 때 "무슨 메시지가 나왔나요" 에 답할
//! 파일이 없었다 (2026-09-06 관측성 검토).
//!
//! # 어디에
//!
//! `<state>/logs/<run_id>.log`. 기계를 만지는 명령(`scan`·`run`·`apply`·
//! `verify`·`resume`·`restore`)만 남기고, 조회(`--help`·`plugin lint`)는 남기지
//! 않는다. 자동으로 지우지 않는다 — `support-bundle` 이 담아 간다 (결정
//! 2026-09-07).
//!
//! # 이름이 늦게 정해지는 문제
//!
//! `apply` 는 계획 파일을 읽어야 `run_id` 를 안다. 배너는 그 전에 나간다. 그래서
//! 임시 이름으로 열고 `run_id` 를 알게 되면 [`RunLog::rename_to`] 로 바꾼다.
//! 열린 파일의 이름을 바꾸는 것은 Windows 에서도 된다 — 표준 라이브러리가
//! `FILE_SHARE_DELETE` 로 연다 (시험 `rename_keeps_writing`).
//!
//! # 크래시
//!
//! 패닉 훅은 같은 폴더에 `crash-<시각>.txt` 를 남긴다 ([`crash_path`]). 회차
//! 로그가 열려 있으면 거기에도 한 줄 적는다.

use std::io::Write;
use std::path::{Path, PathBuf};

/// 로그가 사는 폴더.
pub fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("logs")
}

/// 회차 로그 파일 이름.
pub fn path(state_dir: &Path, run_id: &str) -> PathBuf {
    dir(state_dir).join(format!("{run_id}.log"))
}

/// 크래시 기록 파일 이름. `at` 은 RFC 3339 — 파일 이름에 못 쓰는 `:` 를 뺀다.
pub fn crash_path(state_dir: &Path, at: &str) -> PathBuf {
    let safe: String = at
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    dir(state_dir).join(format!("crash-{safe}-{}.txt", std::process::id()))
}

/// 열린 회차 로그. 줄마다 `flush` 한다 — 크래시가 나도 마지막 줄까지 남게.
pub struct RunLog {
    file: std::fs::File,
    path: PathBuf,
    state_dir: PathBuf,
}

impl RunLog {
    /// `<state>/logs/<name>.log` 를 열거나 만든다. 첫 줄에 머리를 적는다.
    pub fn open(state_dir: &Path, name: &str, header: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir(state_dir))?;
        let path = path(state_dir, name);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let mut log = Self {
            file,
            path,
            state_dir: state_dir.to_path_buf(),
        };
        log.line("#", header)?;
        Ok(log)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// 한 줄. `mark` 는 stdout 이면 `|`, stderr 이면 `!`, 머리·메모면 `#`.
    pub fn line(&mut self, mark: &str, text: &str) -> std::io::Result<()> {
        writeln!(
            self.file,
            "{} {mark} {text}",
            crate::pipeline::now_rfc3339()
        )?;
        self.file.flush()
    }

    /// 여러 줄 텍스트를 줄마다 적는다. 마지막 빈 줄은 버린다.
    pub fn lines(&mut self, mark: &str, text: &str) -> std::io::Result<()> {
        let mut it = text.split('\n').peekable();
        while let Some(l) = it.next() {
            if l.is_empty() && it.peek().is_none() {
                break;
            }
            self.line(mark, l)?;
        }
        Ok(())
    }

    /// `run_id` 를 알게 됐을 때 파일 이름을 그것으로 바꾼다. 이미 그 이름이면
    /// 아무것도 하지 않는다.
    pub fn rename_to(&mut self, run_id: &str) -> std::io::Result<()> {
        let to = path(&self.state_dir, run_id);
        if to == self.path {
            return Ok(());
        }
        std::fs::rename(&self.path, &to)?;
        self.path = to;
        self.line("#", &format!("run_id {run_id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("remedy-runlog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn writes_lines_with_marks_and_time() {
        let state = tmp("lines");
        let mut log = RunLog::open(&state, "run-1", "remedy test").unwrap();
        log.line("|", "hello").unwrap();
        log.line("!", "warn").unwrap();
        log.lines("|", "a\nb\n").unwrap();
        let text = std::fs::read_to_string(path(&state, "run-1")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 5, "{text}");
        assert!(lines[0].ends_with("# remedy test"), "{}", lines[0]);
        assert!(lines[1].contains(" | hello"), "{}", lines[1]);
        assert!(lines[2].contains(" ! warn"), "{}", lines[2]);
        assert!(lines[4].contains(" | b"), "{}", lines[4]);
        // 시각은 RFC 3339 로 시작한다.
        assert_eq!(&lines[1][4..5], "-");
        assert!(lines[1].starts_with("20"), "{}", lines[1]);
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn rename_keeps_writing() {
        let state = tmp("rename");
        let mut log = RunLog::open(&state, "apply-tmp", "h").unwrap();
        log.line("|", "before").unwrap();
        log.rename_to("run-42").unwrap();
        log.line("|", "after").unwrap();
        assert!(!path(&state, "apply-tmp").exists(), "옛 이름이 남았다");
        let text = std::fs::read_to_string(path(&state, "run-42")).unwrap();
        assert!(text.contains("before") && text.contains("after"), "{text}");
        assert!(text.contains("# run_id run-42"), "{text}");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn crash_path_has_no_colons() {
        let p = crash_path(Path::new("s"), "2026-09-07T02:11:03Z");
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("crash-2026-09-07T02-11-03Z-"), "{name}");
        assert!(!name.contains(':'));
    }
}
