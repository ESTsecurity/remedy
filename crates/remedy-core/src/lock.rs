//! 전역 뮤텍스 — **두 인스턴스가 동시에 돌면 안 된다** (설계-09 P6).
//!
//! 설계-09 §1 의 개정 이력이 이것을 P6 로 올려 두었다: "동시 실행 뮤텍스 부재 —
//! 두 인스턴스가 저널·격리소를 깨뜨린다".
//!
//! 무엇이 깨지는가:
//!
//! - **격리 컨테이너.** 실행 1회당 `<run_id>.rq` 파일 하나인데, 두 실행이 같은
//!   초에 시작하면 run_id 가 겹칠 수 있고 그러면 한쪽 복원 데이터가 사라진다.
//! - **저널.** 이어 쓰기라 두 실행의 줄이 섞이고, 재기동한 코드가 "무엇까지
//!   했는가" 를 잘못 읽는다.
//! - **머신 키.** 없으면 만드는데, 둘이 동시에 만들면 나중 것이 이긴다.
//!
//! # 왜 파일 잠금인가
//!
//! 이름 있는 커널 뮤텍스는 OS 마다 다르고 unsafe 가 필요하다. 파일 잠금은
//! `std::fs::File::try_lock` 이 두 플랫폼에서 같은 모양으로 주고, **프로세스가
//! 죽으면 OS 가 푼다** — 잠금 파일을 지우는 것을 잊어서 영영 못 도는 상태가
//! 생기지 않는다.
//!
//! 처음에는 `fs4` 를 쓰려 했는데 컴파일러가 그 import 를 쓰지 않는다고 알려 줬다.
//! `try_lock` 이 이미 표준에 들어와 있어서다. 의존을 하나 덜었다.
//!
//! 잠금 파일 자체는 지우지 않는다. 지우려는 순간 다른 프로세스가 그 파일을
//! 잠그고 있을 수 있고, 지우고 다시 만들면 두 프로세스가 **서로 다른 파일을**
//! 잠근 채 둘 다 성공한다.

use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("{msg} ({0})", msg = remedy_sdk::i18n::t("다른 remedy 인스턴스가 이미 돌고 있습니다", "another remedy instance is already running"))]
    Busy(String),
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// 잡고 있는 동안 다른 인스턴스가 들어오지 못한다.
///
/// **떨어뜨리면 풀린다.** 명시적으로 풀지 않는 이유는, 풀어야 할 자리를 잊는
/// 경로가 반드시 생기기 때문이다.
#[derive(Debug)]
pub struct RunLock {
    _file: File,
    path: PathBuf,
}

impl RunLock {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 잠근다. 이미 잡혀 있으면 **기다리지 않고 거절한다.**
    ///
    /// 기다리면 무인 배포에서 두 번째 인스턴스가 조용히 멈춰 있다가 시간이
    /// 지나 돌기 시작한다. 그때는 첫 번째가 만든 상태 위에서 도는 것이고,
    /// 그것은 사용자가 승인한 것과 다른 일이다.
    pub fn acquire(state_dir: &Path) -> Result<Self, LockError> {
        std::fs::create_dir_all(state_dir).map_err(|e| LockError::Io {
            path: state_dir.display().to_string(),
            source: e,
        })?;
        let path = state_dir.join("remedy.lock");
        let file = File::options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| LockError::Io {
                path: path.display().to_string(),
                source: e,
            })?;

        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file, path }),
            Err(_) => Err(LockError::Busy(path.display().to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("remedy-lock-test-{name}"));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn a_second_instance_is_refused_while_the_first_holds_it() {
        let dir = tmp("busy");
        let first = RunLock::acquire(&dir).expect("첫 번째는 잡는다");
        match RunLock::acquire(&dir) {
            Err(LockError::Busy(_)) => {}
            other => panic!("두 번째가 들어왔다: {other:?}"),
        }
        drop(first);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dropping_the_lock_lets_the_next_one_in() {
        // 풀리지 않으면 재부팅 전까지 아무것도 못 돈다.
        let dir = tmp("release");
        {
            let _l = RunLock::acquire(&dir).expect("첫 번째");
        }
        let _second = RunLock::acquire(&dir).expect("풀린 뒤에는 들어와야 한다");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_lock_file_survives_so_two_processes_lock_the_same_thing() {
        // 잠금 파일을 지우고 다시 만들면 두 프로세스가 **서로 다른 파일**을
        // 잠근 채 둘 다 성공한다.
        let dir = tmp("persist");
        let path = {
            let l = RunLock::acquire(&dir).expect("잠금");
            l.path().to_path_buf()
        };
        assert!(path.exists(), "잠금 파일이 사라졌다");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_state_directory_is_created_not_an_error() {
        // 첫 실행에는 상태 디렉터리가 없다.
        let dir = tmp("mkdir").join("깊은").join("경로");
        let _l = RunLock::acquire(&dir).expect("만들어야 한다");
        assert!(dir.exists());
        std::fs::remove_dir_all(std::env::temp_dir().join("remedy-lock-test-mkdir")).ok();
    }
}
