//! 지은 나무(시험용) — 파일 · 디렉터리 · 링크 · 소켓을 글로 적어 [`Host`] 로 준다.

use super::Host;
use std::collections::BTreeMap;
use std::io;

/// 경로 → 내용. `/proc` 아래 자리는 상대 경로(`net/unix`)로 적는다.
#[derive(Default)]
pub(crate) struct FakeHost {
    pub(crate) files: BTreeMap<String, Vec<u8>>,
    pub(crate) dirs: BTreeMap<String, Result<Vec<String>, io::ErrorKind>>,
    pub(crate) links: BTreeMap<String, Result<String, io::ErrorKind>>,
    /// 링크를 따른 결과(없으면 없는 경로).
    pub(crate) resolved: BTreeMap<String, String>,
    pub(crate) sockets: Vec<String>,
    pub(crate) pipe_names: Option<Vec<String>>,
}

impl FakeHost {
    /// Docker 가 `/run/docker.sock` 을 받는 기계 — `/var/run` 은 `/run` 으로 가는 링크다. 프로세스는 아직 없다.
    pub(crate) fn docker_socket() -> FakeHost {
        let mut h = FakeHost::default();
        h.resolved
            .insert("/var/run/docker.sock".into(), "/run/docker.sock".into());
        h.resolved
            .insert("/run/docker.sock".into(), "/run/docker.sock".into());
        h.sockets.push("/run/docker.sock".into());
        h.files.insert(
            "net/unix".into(),
            b"Num       RefCount Protocol Flags    Type St Inode Path\n\
              0000000000000000: 00000002 00000000 00010000 0001 01 123 /run/docker.sock\n\
              0000000000000000: 00000003 00000000 00000000 0001 03 124 /run/docker.sock\n"
                .to_vec(),
        );
        h.files.insert(
            "mounts".into(),
            b"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n".to_vec(),
        );
        h.dirs.insert(String::new(), Ok(Vec::new()));
        h
    }

    /// 프로세스 하나 — 실행 파일과 인자, 쥔 디스크립터의 대상들.
    pub(crate) fn process(&mut self, pid: u32, exe: &str, args: &[&str], fds: &[&str]) {
        let pid = pid.to_string();
        if let Some(Ok(list)) = self.dirs.get_mut("") {
            list.push(pid.clone());
        }
        self.links.insert(format!("{pid}/exe"), Ok(exe.to_string()));
        let mut cmdline = Vec::new();
        for a in args {
            cmdline.extend_from_slice(a.as_bytes());
            cmdline.push(0);
        }
        self.files.insert(format!("{pid}/cmdline"), cmdline);
        let names: Vec<String> = (0..fds.len()).map(|i| (i + 3).to_string()).collect();
        for (name, target) in names.iter().zip(fds) {
            self.links
                .insert(format!("{pid}/fd/{name}"), Ok(target.to_string()));
        }
        self.dirs.insert(format!("{pid}/fd"), Ok(names));
    }
}

fn missing() -> io::Error {
    io::ErrorKind::NotFound.into()
}

impl Host for FakeHost {
    fn resolve(&self, path: &str) -> io::Result<String> {
        self.resolved.get(path).cloned().ok_or_else(missing)
    }

    fn is_socket(&self, path: &str) -> io::Result<bool> {
        Ok(self.sockets.iter().any(|s| s == path))
    }

    fn proc_read(&self, rel: &str) -> io::Result<Vec<u8>> {
        self.files.get(rel).cloned().ok_or_else(missing)
    }

    fn proc_list(&self, rel: &str) -> io::Result<Vec<String>> {
        match self.dirs.get(rel) {
            Some(Ok(names)) => Ok(names.clone()),
            Some(Err(kind)) => Err((*kind).into()),
            None => Err(missing()),
        }
    }

    fn proc_link(&self, rel: &str) -> io::Result<String> {
        match self.links.get(rel) {
            Some(Ok(target)) => Ok(target.clone()),
            Some(Err(kind)) => Err((*kind).into()),
            None => Err(missing()),
        }
    }

    fn pipes(&self) -> io::Result<Vec<String>> {
        self.pipe_names
            .clone()
            .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
    }
}
