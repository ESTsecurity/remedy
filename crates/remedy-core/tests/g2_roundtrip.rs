//! **G2 — Op 마다 `apply → restore` 왕복이 원본을 복원한다** (설계-09 P7).
//!
//! # 왜 표인가
//!
//! P7 의 완료 조건은 "Op**마다**" 다. Op 별로 시험을 흩어 두면 새 Op 이 들어올 때
//! 왕복 시험 없이 넘어가는 것을 아무도 막지 못한다. 그래서 이 파일은 **카탈로그를
//! 기준으로** 돈다 — 게이트 이하의 모든 Op 이 여기 사례를 가져야 하고, 없으면
//! [`every_op_the_gate_allows_has_a_case`] 가 깨진다.
//!
//! # 왕복은 세 번 잰다
//!
//! `수행 전 == 복원 후` 만으로는 부족하다. **아무것도 하지 않은 Op 도 그 등식을
//! 만족한다.** 그래서 `수행 후 != 수행 전` 을 함께 잰다 — 파괴가 실제로 일어났고
//! 그것이 정확히 되돌아왔음을 둘이 함께 말한다.

use remedy_apply::{Executor, Silent};
use remedy_platform::write::{
    AvExclusion, DirIndex, FileMeta, PlatformWrite, RegistryValueBackup, RestoreReport,
};
use remedy_platform::PlatformError;
use remedy_sdk::artifact::{Action, CoreInfo, Envelope, HostInfo, PlanBody, PlanEnvelope};
use remedy_sdk::catalog::{Op, Phase, Risk};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ───────────────────────────────────────────────────── 실험대

/// 파일은 진짜, 레지스트리·예약 작업·재부팅 큐는 메모리.
///
/// 진짜 OS 를 건드리지 않으면서 **실행기와 복원기가 실제로 쓰는 코드 경로**를
/// 그대로 지나게 한다. 파일 계열을 가짜로 만들면 이 시험이 재는 것이
/// 왕복이 아니라 가짜의 대칭성이 된다.
struct Bench {
    dir: PathBuf,
    reg: RefCell<BTreeMap<String, RegistryValueBackup>>,
    tasks: RefCell<BTreeMap<String, (Vec<u8>, bool)>>,
    /// 재부팅 삭제 예약. `(원본, 대상)` 짝이고 대상이 비면 삭제다.
    pending: RefCell<Vec<(String, String)>>,
    /// 돌고 있는 프로세스. `(pid, 이미지, 명령줄)`.
    procs: RefCell<Vec<(u32, String, String)>>,
    /// 정지한 서비스 정의 키.
    stopped: RefCell<Vec<String>>,
}

const AV_ROOT: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions";

impl Bench {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("remedy-g2-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("작업 디렉터리");
        Self {
            dir,
            reg: RefCell::new(BTreeMap::new()),
            tasks: RefCell::new(BTreeMap::new()),
            pending: RefCell::new(Vec::new()),
            procs: RefCell::new(Vec::new()),
            stopped: RefCell::new(Vec::new()),
        }
    }

    fn path(&self, rel: &str) -> String {
        self.dir.join(rel).to_string_lossy().to_string()
    }

    fn file(&self, rel: &str, body: &[u8]) -> String {
        let p = self.dir.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).expect("부모");
        }
        std::fs::write(&p, body).expect("파일");
        p.to_string_lossy().to_string()
    }

    fn set_reg(&self, target: &str, vtype: u32, value: &str) {
        self.reg.borrow_mut().insert(
            target.into(),
            RegistryValueBackup::from_string(vtype, value),
        );
    }

    /// `REG_DWORD 0`. 제외 목록 항목이 이 모양이다.
    fn set_dword(&self, target: &str) {
        self.reg.borrow_mut().insert(
            target.into(),
            RegistryValueBackup {
                vtype: 4,
                bytes: vec![0, 0, 0, 0],
            },
        );
    }

    fn task(&self, id: &str, xml: &str) {
        self.tasks
            .borrow_mut()
            .insert(id.into(), (xml.as_bytes().to_vec(), true));
    }

    /// 레지스트리 전체를 사람이 읽을 한 덩어리로.
    fn reg_dump(&self) -> String {
        self.reg
            .borrow()
            .iter()
            .map(|(k, v)| format!("{k}={}:{:?}", v.vtype, v.bytes))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn proc_dump(&self) -> String {
        format!("{:?}\n{:?}", self.procs.borrow(), self.stopped.borrow())
    }

    fn task_dump(&self) -> String {
        self.tasks
            .borrow()
            .iter()
            .map(|(k, (x, on))| format!("{k}|{on}|{}", String::from_utf8_lossy(x)))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn pending_dump(&self) -> String {
        format!("{:?}", self.pending.borrow())
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `full` 이 `key` 하위의 값이면 그 상대 경로. 아니면 `None`.
///
/// 실험대의 레지스트리는 평평한 지도이므로 "하위" 를 접두로 판정한다. 경계를
/// 역슬래시로 두지 않으면 `Services\Evil` 이 `Services\EvilTwin` 을 품는다.
fn under(full: &str, key: &str) -> Option<String> {
    let prefix = format!("{}\\", key.to_lowercase());
    full.to_lowercase()
        .strip_prefix(&prefix)
        .map(|_| full[key.len() + 1..].to_string())
}

/// 파일 나무 하나를 (상대경로, 내용) 으로 편다. 빈 디렉터리도 센다.
fn tree(root: &Path) -> String {
    if !root.exists() {
        return "<없음>".into();
    }
    if root.is_file() {
        return format!("f:{:?}", std::fs::read(root).unwrap_or_default());
    }
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            if p.is_dir() {
                out.push(format!("d:{rel}"));
                stack.push(p);
            } else {
                out.push(format!(
                    "f:{rel}:{:?}",
                    std::fs::read(&p).unwrap_or_default()
                ));
            }
        }
    }
    out.sort();
    out.join("\n")
}

impl PlatformWrite for Bench {
    fn backend_name(&self) -> &'static str {
        "g2-bench"
    }

    // ── 파일 계열은 진짜다 ────────────────────────────────────
    fn plan_restore(&self, dest: &str, meta: &FileMeta) -> RestoreReport {
        remedy_platform::write::FsRestore.plan_restore(dest, meta)
    }
    fn restore_file(
        &self,
        dest: &str,
        content: &[u8],
        meta: &FileMeta,
    ) -> Result<RestoreReport, PlatformError> {
        remedy_platform::write::FsRestore.restore_file(dest, content, meta)
    }
    fn quarantine_read(&self, path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
        remedy_platform::write::FsRestore.quarantine_read(path)
    }
    fn destroy_file(&self, path: &str) -> Result<(), PlatformError> {
        remedy_platform::write::FsRestore.destroy_file(path)
    }
    fn exists(&self, path: &str) -> bool {
        remedy_platform::write::FsRestore.exists(path)
    }
    fn is_dir(&self, path: &str) -> bool {
        remedy_platform::write::FsRestore.is_dir(path)
    }
    fn dir_read(&self, path: &str) -> Result<(Vec<u8>, DirIndex), PlatformError> {
        remedy_platform::write::FsRestore.dir_read(path)
    }
    fn dir_destroy(&self, path: &str) -> Result<(), PlatformError> {
        remedy_platform::write::FsRestore.dir_destroy(path)
    }
    fn dir_restore(
        &self,
        path: &str,
        content: &[u8],
        index: &DirIndex,
    ) -> Result<RestoreReport, PlatformError> {
        remedy_platform::write::FsRestore.dir_restore(path, content, index)
    }
    fn stream_read(&self, target: &str) -> Result<Vec<u8>, PlatformError> {
        remedy_platform::write::FsRestore.stream_read(target)
    }
    fn stream_delete(&self, target: &str) -> Result<(), PlatformError> {
        remedy_platform::write::FsRestore.stream_delete(target)
    }
    fn shortcut_strip_args(&self, path: &str, expect: &str) -> Result<(), PlatformError> {
        remedy_platform::write::FsRestore.shortcut_strip_args(path, expect)
    }
    // 인증서 파일도 진짜 파일이다. **신뢰 저장소를 다시 만드는 단계는 여기
    // 없다** — 그것은 OS 도구를 부르는 일이고 G2 가 재는 것이 아니다. G2 는
    // 실행기와 복원기의 대칭을 재고, 도구 호출은 실기기에서 `linux_write.rs`
    // 가 잰다.
    fn cert_read(&self, path: &str) -> Result<Vec<u8>, PlatformError> {
        std::fs::read(path).map_err(|e| PlatformError::io(path, e))
    }
    fn cert_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
    fn cert_delete(&self, path: &str) -> Result<(), PlatformError> {
        std::fs::remove_file(path).map_err(|e| PlatformError::io(path, e))
    }
    fn cert_restore(&self, path: &str, content: &[u8]) -> Result<(), PlatformError> {
        std::fs::write(path, content).map_err(|e| PlatformError::io(path, e))
    }
    fn text_line_read(&self, path: &str, line_no: u32) -> Result<String, PlatformError> {
        remedy_platform::write::FsRestore.text_line_read(path, line_no)
    }
    fn text_line_remove(&self, path: &str, line_no: u32, e: &str) -> Result<(), PlatformError> {
        remedy_platform::write::FsRestore.text_line_remove(path, line_no, e)
    }
    fn text_line_restore(&self, path: &str, line_no: u32, l: &str) -> Result<(), PlatformError> {
        remedy_platform::write::FsRestore.text_line_restore(path, line_no, l)
    }
    fn structured_remove_key(&self, path: &str, key: &str) -> Result<(), PlatformError> {
        remedy_platform::write::FsRestore.structured_remove_key(path, key)
    }
    fn structured_set_key(&self, p: &str, k: &str, v: &str) -> Result<(), PlatformError> {
        remedy_platform::write::FsRestore.structured_set_key(p, k, v)
    }

    // ── 레지스트리는 메모리 ───────────────────────────────────
    fn registry_read(&self, target: &str) -> Result<RegistryValueBackup, PlatformError> {
        self.reg
            .borrow()
            .get(target)
            .cloned()
            .ok_or(PlatformError::Unsupported("그런 값이 없다"))
    }
    fn registry_delete(&self, target: &str) -> Result<(), PlatformError> {
        self.reg
            .borrow_mut()
            .remove(target)
            .map(|_| ())
            .ok_or(PlatformError::Unsupported("그런 값이 없다"))
    }
    fn registry_write(&self, t: &str, v: &RegistryValueBackup) -> Result<(), PlatformError> {
        self.reg.borrow_mut().insert(t.into(), v.clone());
        Ok(())
    }
    fn registry_exists(&self, target: &str) -> bool {
        self.reg.borrow().contains_key(target)
    }

    /// 제외 목록은 **레지스트리에서 파생된다.** 따로 들고 있으면 파괴가 지운
    /// 레지스트리 값과 백업이 담은 목록이 어긋나도 이 시험이 모른다.
    fn av_exclusions_read(&self) -> Result<Vec<AvExclusion>, PlatformError> {
        Ok(self
            .reg
            .borrow()
            .keys()
            .filter_map(|k| k.strip_prefix(&format!("{AV_ROOT}\\")))
            .filter_map(|rest| rest.split_once('\\'))
            .map(|(leaf, value)| AvExclusion {
                kind: match leaf {
                    "Paths" => "path".into(),
                    "Processes" => "process".into(),
                    _ => "ext".into(),
                },
                value: value.to_string(),
            })
            .collect())
    }

    fn av_exclusions_write(&self, want: &[AvExclusion]) -> Result<(), PlatformError> {
        let mut reg = self.reg.borrow_mut();
        reg.retain(|k, _| !k.starts_with(&format!("{AV_ROOT}\\")));
        for x in want {
            let leaf = match x.kind.as_str() {
                "path" => "Paths",
                "process" => "Processes",
                _ => "Extensions",
            };
            reg.insert(
                format!("{AV_ROOT}\\{leaf}\\{}", x.value),
                RegistryValueBackup {
                    vtype: 4,
                    bytes: vec![0, 0, 0, 0],
                },
            );
        }
        Ok(())
    }

    // ── 재부팅 큐 ─────────────────────────────────────────────
    fn schedule_delete_on_reboot(&self, path: &str) -> Result<(), PlatformError> {
        self.pending
            .borrow_mut()
            .push((path.to_string(), String::new()));
        Ok(())
    }
    fn cancel_delete_on_reboot(&self, path: &str) -> Result<(), PlatformError> {
        self.pending
            .borrow_mut()
            .retain(|(src, _)| !src.eq_ignore_ascii_case(path));
        Ok(())
    }

    // ── 예약 작업 ─────────────────────────────────────────────
    fn persistence_read(
        &self,
        id: &str,
    ) -> Result<(Vec<u8>, remedy_platform::write::PersistenceIndex), PlatformError> {
        if let Some(why) = remedy_platform::write::task_id_problem(id) {
            return Err(PlatformError::Refused(why.into()));
        }
        self.tasks
            .borrow()
            .get(id)
            // 이 가짜 백엔드에는 곁가지가 없다 — 예약 작업은 정의 하나가 전부다.
            .map(|t| {
                (
                    t.0.clone(),
                    remedy_platform::write::PersistenceIndex::default(),
                )
            })
            .ok_or(PlatformError::Unsupported("그런 작업이 없다"))
    }
    fn persistence_exists(&self, id: &str) -> bool {
        self.tasks.borrow().contains_key(id)
    }
    fn persistence_disable(
        &self,
        id: &str,
        _at: Option<&remedy_platform::write::LineAt>,
    ) -> Result<(), PlatformError> {
        match self.tasks.borrow_mut().get_mut(id) {
            Some(t) => {
                t.1 = false;
                Ok(())
            }
            None => Err(PlatformError::Unsupported("그런 작업이 없다")),
        }
    }
    fn persistence_delete(
        &self,
        id: &str,
        _at: Option<&remedy_platform::write::LineAt>,
    ) -> Result<(), PlatformError> {
        self.tasks
            .borrow_mut()
            .remove(id)
            .map(|_| ())
            .ok_or(PlatformError::Unsupported("그런 작업이 없다"))
    }
    // ── P8 ────────────────────────────────────────────────────

    fn registry_key_read(
        &self,
        key: &str,
    ) -> Result<(Vec<u8>, remedy_platform::write::RegKeyIndex), PlatformError> {
        let mut index = remedy_platform::write::RegKeyIndex::default();
        let mut body = Vec::new();
        let mut found = false;
        for (k, v) in self.reg.borrow().iter() {
            let Some(rest) = under(k, key) else { continue };
            found = true;
            let (sub, name) = match rest.rsplit_once('\\') {
                Some((s, n)) => (s.to_string(), n.to_string()),
                None => (String::new(), rest),
            };
            if !sub.is_empty() && !index.keys.contains(&sub) {
                index.keys.push(sub.clone());
            }
            index.values.push(remedy_platform::write::RegValueEntry {
                key: sub,
                name,
                vtype: v.vtype,
                size: v.bytes.len() as u64,
            });
            body.extend_from_slice(&v.bytes);
        }
        if !found {
            return Err(PlatformError::Unsupported("그런 키가 없다"));
        }
        index.keys.sort();
        Ok((body, index))
    }

    fn registry_key_delete(&self, key: &str) -> Result<(), PlatformError> {
        let before = self.reg.borrow().len();
        self.reg.borrow_mut().retain(|k, _| under(k, key).is_none());
        if self.reg.borrow().len() == before {
            return Err(PlatformError::Unsupported("그런 키가 없다"));
        }
        Ok(())
    }

    fn registry_key_restore(
        &self,
        key: &str,
        content: &[u8],
        index: &remedy_platform::write::RegKeyIndex,
    ) -> Result<(), PlatformError> {
        let mut off = 0usize;
        for v in &index.values {
            if !remedy_platform::write::reg_rel_is_contained(&v.key) {
                return Err(PlatformError::Unsupported("목차가 루트 밖을 가리킨다"));
            }
            let end = off
                .checked_add(v.size as usize)
                .filter(|e| *e <= content.len())
                .ok_or(PlatformError::Unsupported("목차가 본문 길이와 맞지 않는다"))?;
            let full = if v.key.is_empty() {
                format!("{key}\\{}", v.name)
            } else {
                format!("{key}\\{}\\{}", v.key, v.name)
            };
            self.reg.borrow_mut().insert(
                full,
                RegistryValueBackup {
                    vtype: v.vtype,
                    bytes: content[off..end].to_vec(),
                },
            );
            off = end;
        }
        Ok(())
    }

    fn registry_key_exists(&self, key: &str) -> bool {
        self.reg.borrow().keys().any(|k| under(k, key).is_some())
    }

    fn processes_matching(
        &self,
        p: &remedy_platform::write::KillPredicate,
    ) -> Result<Vec<remedy_platform::write::Target>, PlatformError> {
        if p.is_empty() {
            return Err(PlatformError::Refused("술어가 비어 있다".into()));
        }
        Ok(self
            .procs
            .borrow()
            .iter()
            .filter(|(_, img, cmd)| {
                p.image_path
                    .as_ref()
                    .is_none_or(|w| img.eq_ignore_ascii_case(w))
                    && p.cmdline_contains.as_ref().is_none_or(|n| cmd.contains(n))
            })
            .map(|(pid, img, cmd)| remedy_platform::write::Target {
                pid: *pid,
                image_path: img.clone(),
                cmdline: cmd.clone(),
            })
            .collect())
    }

    fn process_kill(&self, pids: &[u32]) -> Result<(), PlatformError> {
        self.procs
            .borrow_mut()
            .retain(|(p, _, _)| !pids.contains(p));
        Ok(())
    }

    fn service_running(&self, target: &str) -> bool {
        self.registry_key_exists(target) && !self.stopped.borrow().iter().any(|s| s == target)
    }
    fn service_stop(&self, target: &str) -> Result<(), PlatformError> {
        self.stopped.borrow_mut().push(target.to_string());
        Ok(())
    }
    fn service_disable(&self, target: &str) -> Result<(), PlatformError> {
        self.set_reg(&format!("{target}\\Start"), 4, "4");
        Ok(())
    }
    fn service_delete(&self, target: &str) -> Result<(), PlatformError> {
        self.registry_key_delete(target)
    }
    fn service_clear_recovery(&self, target: &str) -> Result<(), PlatformError> {
        self.reg
            .borrow_mut()
            .remove(&format!("{target}\\FailureActions"))
            .map(|_| ())
            .ok_or(PlatformError::Unsupported("복구 동작이 없다"))
    }

    /// **제품과 같은 코드를 부른다.** 가짜가 관대하면 이 시험이 재는 것이
    /// 제품이 아니라 가짜의 관대함이 된다 — P10-B 전에는 코어에 서명 검증
    /// 수단이 아예 없어 여기서 오류를 냈고, 이제는 있으므로 그것을 쓴다.
    ///
    /// 실험대 디렉터리에는 서명된 실행 파일이 없으므로 빈 목록이 나오고,
    /// 재귀 삭제가 왕복까지 간다. **정상 프로그램이 섞였을 때 막히는가**는
    /// `remedy-platform` 의 `trusted_in_dir` 시험이 실기기 파일로 잰다.
    #[cfg(windows)]
    fn survey_recursive_target(
        &self,
        dir: &str,
        max_children: u32,
        max_depth: u32,
    ) -> Result<Vec<String>, PlatformError> {
        remedy_platform::windows::survey_recursive_target_under(dir, max_children, max_depth)
    }

    fn create_restore_point(&self, _label: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(
            "실험대는 복원 지점을 만들지 않는다",
        ))
    }

    fn persistence_restore(
        &self,
        id: &str,
        xml: &[u8],
        _index: &remedy_platform::write::PersistenceIndex,
    ) -> Result<(), PlatformError> {
        self.tasks
            .borrow_mut()
            .insert(id.into(), (xml.to_vec(), true));
        Ok(())
    }
}

// ─────────────────────────────────────────────────────── 사례

/// 무엇을 볼 것인가. 왕복이 정말 일어났는지는 이것으로만 알 수 있다.
enum Probe {
    /// 이 경로의 파일 또는 나무.
    Tree(String),
    Registry,
    Tasks,
    /// 파일과 재부팅 큐를 함께. 예약은 파일을 바꾸지 않는다.
    FileAndPending(String),
    /// 프로세스 목록과 정지한 서비스.
    Runtime,
}

impl Probe {
    fn read(&self, b: &Bench) -> String {
        match self {
            Probe::Tree(p) => tree(Path::new(p)),
            Probe::Registry => b.reg_dump(),
            Probe::Tasks => b.task_dump(),
            Probe::FileAndPending(p) => format!("{}\n{}", tree(Path::new(p)), b.pending_dump()),
            Probe::Runtime => format!("{}\n{}", b.proc_dump(), b.reg_dump()),
        }
    }
}

struct Case {
    /// `process.kill` 은 대상이 없다 — PID 는 계획에 들어갈 자리가 없고
    /// 술어가 그 자리를 대신한다 (설계-03 §1).
    target: Option<String>,
    locator: Option<serde_json::Value>,
    strip: Option<String>,
    probe: Probe,
    /// 왕복할 수 없는 Op 이면 그 이유. 그때는 **거절되는지**만 잰다.
    refuses: Option<&'static str>,
    /// 되돌릴 수 없는 Op 인가. 담을 것이 없으므로 컨테이너도 없다.
    irreversible: bool,
}

fn plain(target: String, probe: Probe) -> Case {
    Case {
        target: Some(target),
        locator: None,
        strip: None,
        probe,
        refuses: None,
        irreversible: false,
    }
}

/// 이 Op 의 실험을 차린다. `None` 이면 사례가 없다는 뜻이고, 그 자체가 실패다.
fn case_for(op: Op, b: &Bench) -> Option<Case> {
    const LNK_TARGET: &[u8] = &[];
    let _ = LNK_TARGET;
    Some(match op {
        // ── 파일 ──────────────────────────────────────────────
        Op::FileQuarantineOnly => plain(b.file("q.exe", b"payload"), Probe::Tree(b.path("q.exe"))),
        Op::FileDelete => plain(b.file("d.exe", b"payload"), Probe::Tree(b.path("d.exe"))),
        Op::FileDeleteOnReboot => {
            // 파일은 그대로 있고 **큐가 바뀐다.** 파일만 보면 이 Op 의 왕복은
            // 아무것도 재지 못한다.
            let p = b.file("locked.exe", b"payload");
            plain(p.clone(), Probe::FileAndPending(p))
        }
        Op::FileDeleteStream => {
            let host = b.file("host.txt", "본문".as_bytes());
            let stream = format!("{host}:evil");
            // NTFS 가 아니면 그냥 그 이름의 파일이 된다. 어느 쪽이든
            // "그 대상을 담고 지우고 되돌린다" 는 성질은 같다.
            std::fs::write(&stream, b"payload").ok()?;
            plain(stream.clone(), Probe::Tree(stream))
        }
        // **무엇을 뗄지 계획이 말한다.** 픽스처가 담은 인자와 같아야 실행기가
        // 움직인다 — 그 값이 어긋나면 아무것도 하지 않고 실패하는 것이 옳다.
        Op::ShortcutStripArgs => {
            let p = b.file("s.lnk", &lnk_with_arguments());
            Case {
                locator: Some(serde_json::json!({ "args": "-enc evil" })),
                ..plain(p.clone(), Probe::Tree(p))
            }
        }
        Op::BrowserExtRemove => {
            let root = b
                .dir
                .join("User Data/Default/Extensions/aaaaaaaabbbbbbbbccccccccdddddddd");
            std::fs::create_dir_all(root.join("1.0_0/_locales/ko")).expect("확장");
            std::fs::create_dir_all(root.join("1.0_0/_metadata")).expect("빈 것");
            std::fs::write(root.join("1.0_0/manifest.json"), b"{}").expect("manifest");
            let t = root.to_string_lossy().to_string();
            plain(t.clone(), Probe::Tree(t))
        }

        // ── 설정 파일 ─────────────────────────────────────────
        Op::TextConfigRemoveLine => Case {
            target: Some(b.file("app.ini", b"[a]\r\nkeep=1\r\nevil=x\r\n")),
            locator: Some(serde_json::json!({ "line_no": 3, "line": "evil=x" })),
            probe: Probe::Tree(b.path("app.ini")),
            strip: None,
            refuses: None,
            irreversible: false,
        },
        Op::HostsRestoreLine => Case {
            target: Some(b.file("hosts", b"127.0.0.1 localhost\n1.2.3.4 evil.example\n")),
            locator: Some(serde_json::json!({ "line_no": 2, "line": "1.2.3.4 evil.example" })),
            probe: Probe::Tree(b.path("hosts")),
            strip: None,
            refuses: None,
            irreversible: false,
        },
        Op::StructuredConfigRemoveKey => Case {
            target: Some(b.file(
                "prefs.json",
                "{\n  \"keep\": 1,\n  \"evil\": 2\n}\n".as_bytes(),
            )),
            locator: Some(serde_json::json!({ "key_path": "evil" })),
            probe: Probe::Tree(b.path("prefs.json")),
            strip: None,
            refuses: None,
            irreversible: false,
        },
        Op::StructuredConfigRestoreDefault => Case {
            target: Some(b.file("p2.json", "{\n  \"evil\": 2\n}\n".as_bytes())),
            locator: Some(serde_json::json!({ "key_path": "evil" })),
            probe: Probe::Tree(b.path("p2.json")),
            strip: None,
            // **왕복할 수 없다.** OS 기본값 카탈로그에 구조적 설정 항목이 하나도
            // 없어 이 Op 은 언제나 거절된다. 값의 출처가 카탈로그뿐이라는 규칙
            // (설계-03 §2)의 직접적인 결과이고, 항목이 생기면 여기도 바뀐다.
            // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
            refuses: Some(remedy_sdk::i18n::t("카탈로그", "catalog")),
            irreversible: false,
        },

        // ── 레지스트리 ────────────────────────────────────────
        Op::RegistryDeleteValue => {
            b.set_reg("HKCU\\Software\\Evil\\Run", 1, "C:\\a\\evil.exe");
            plain("HKCU\\Software\\Evil\\Run".into(), Probe::Registry)
        }
        Op::AutorunRemove => {
            b.set_reg(
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil",
                1,
                "C:\\a\\evil.exe",
            );
            plain(
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil".into(),
                Probe::Registry,
            )
        }
        Op::ProxyRestore => {
            b.set_reg(
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer",
                1,
                "evil:8080",
            );
            plain(
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer"
                    .into(),
                Probe::Registry,
            )
        }
        Op::FirewallRestoreRule => {
            b.set_reg(
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\\{evil}",
                1,
                "v2.31|Action=Allow|Dir=In|",
            );
            plain(
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\\{evil}".into(),
                Probe::Registry,
            )
        }
        Op::AvRestoreExclusions => {
            // 제외 항목의 값은 `REG_DWORD 0` 이다. 되돌릴 때 코어가 쓰는 것과
            // 같은 모양으로 차려 둔다 — 다르면 왕복이 아니라 표현 차이를 잰다.
            b.set_dword(&format!("{AV_ROOT}\\Paths\\C:\\evil"));
            b.set_dword(&format!("{AV_ROOT}\\Paths\\C:\\normal"));
            plain(format!("{AV_ROOT}\\Paths\\C:\\evil"), Probe::Registry)
        }
        Op::RegistryStripValue => {
            b.set_reg(
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
                1,
                "C:\\Windows\\system32\\userinit.exe,C:\\a\\evil.exe",
            );
            Case {
                target: Some(
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"
                        .into(),
                ),
                locator: None,
                strip: Some("C:\\a\\evil.exe".into()),
                probe: Probe::Registry,
                refuses: None,
                irreversible: false,
            }
        }
        Op::EnvStripPath => {
            b.set_reg(
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\Path",
                2,
                "C:\\Windows;C:\\a\\evil",
            );
            Case {
                target: Some(
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\Path"
                        .into(),
                ),
                locator: None,
                strip: Some("C:\\a\\evil".into()),
                probe: Probe::Registry,
                refuses: None,
                irreversible: false,
            }
        }
        Op::RegistryRestoreDefault => {
            // 카탈로그에 있는 대상이어야 한다. 값의 출처는 코어 안뿐이다.
            let t = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell";
            assert!(
                remedy_sdk::catalog::restore_default_for(t).is_some(),
                "이 시험이 기대는 카탈로그 항목이 사라졌다"
            );
            b.set_reg(t, 1, "explorer.exe,evil.exe");
            plain(t.into(), Probe::Registry)
        }

        // ── 예약 작업 ─────────────────────────────────────────
        Op::PersistenceDisable => {
            b.task(
                "\\Microsoft\\Windows\\Locust",
                "<Task><Enabled>true</Enabled></Task>",
            );
            plain("\\Microsoft\\Windows\\Locust".into(), Probe::Tasks)
        }
        Op::PersistenceDelete => {
            b.task(
                "\\Microsoft\\Windows\\Locust2",
                "<Task><Enabled>true</Enabled></Task>",
            );
            plain("\\Microsoft\\Windows\\Locust2".into(), Probe::Tasks)
        }

        // ── P8 ────────────────────────────────────────────────
        Op::ProcessKill => {
            b.procs
                .borrow_mut()
                .push((4242, "C:\\a\\evil.exe".into(), "evil.exe -run".into()));
            b.procs
                .borrow_mut()
                .push((4243, "C:\\a\\good.exe".into(), "good.exe".into()));
            Case {
                target: None,
                locator: Some(serde_json::json!({ "image_path": "C:\\a\\evil.exe" })),
                strip: None,
                probe: Probe::Runtime,
                refuses: None,
                // **되돌릴 수 없다.** 죽은 프로세스는 되살릴 수 없고, 그래서
                // 이 Op 은 백업할 것도 없다 (설계-03 §5).
                irreversible: true,
            }
        }
        Op::ServiceStop => {
            let t = svc(b, "EvilSvc");
            Case {
                target: Some(t),
                probe: Probe::Runtime,
                locator: None,
                strip: None,
                refuses: None,
                // 정지는 상태 변화이고 정의는 그대로다. 담아 둔 정의를
                // 되돌려도 **다시 시작되지는 않는다** — 그래서 왕복이
                // 성립하지 않는다. 설계-03 §2 도 이 Op 의 되돌림을
                // "불가(상태 기록)" 로 적는다.
                irreversible: true,
            }
        }
        Op::ServiceDisable => plain(svc(b, "EvilSvc2"), Probe::Registry),
        Op::ServiceDelete => plain(svc(b, "EvilSvc3"), Probe::Registry),
        Op::ServiceClearRecovery => plain(svc(b, "EvilSvc4"), Probe::Registry),
        Op::RegistryDeleteKey => {
            let root = "HKCU\\Software\\Evil";
            b.set_reg(&format!("{root}\\A"), 1, "1");
            b.set_reg(&format!("{root}\\Sub\\B"), 1, "2");
            plain(root.into(), Probe::Registry)
        }
        // **모양이 플랫폼마다 다르다.** Windows 인증서는 레지스트리 키 하나,
        // Linux 인증서는 파일이다. 여기서 Windows 모양만 태우면 Linux 의
        // 담기·되돌리기 가지는 **G2 가 한 번도 지나지 않는다** — 그 상태의
        // "왕복 OK" 는 잰 적 없는 것에 대한 초록이다 (설계-09 P12 후속).
        Op::CertStoreRemove if !cfg!(windows) => {
            let f = b.file("evil-ca.crt", b"-----BEGIN CERTIFICATE-----\n");
            plain(f.clone(), Probe::Tree(f))
        }
        Op::CertStoreRemove => {
            let t = "HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\DEADBEEF";
            b.set_reg(&format!("{t}\\Blob"), 3, "der");
            plain(t.into(), Probe::Registry)
        }
        Op::BootRestoreDefault => {
            let t = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell";
            assert!(
                remedy_sdk::catalog::restore_default_for(t).is_some(),
                "이 시험이 기대는 카탈로그 항목이 사라졌다"
            );
            b.set_reg(t, 1, "evil.exe");
            plain(t.into(), Probe::Registry)
        }
        Op::DirDeleteRecursive => {
            let d = b.dir.join("나무");
            std::fs::create_dir_all(d.join("하위")).expect("나무");
            std::fs::write(d.join("a.txt"), b"x").expect("파일");
            // **P10-C 에서 왕복하게 됐다.** 이전에는 `refuses: Some("서명")`
            // 이었다 — 서명을 확인할 수단이 없어 실행기가 거부했고, 그것이
            // 옳았다("확인하지 못했다" 를 "없다" 로 읽으면 가드가 없는 것과
            // 같다). 이제 수단이 있고, 이 나무에는 서명된 실행 파일이 없으므로
            // 확인이 빈 목록으로 끝나 파괴와 복원까지 간다.
            //
            // **하위까지 살아 돌아와야** 왕복이 성립한다 — 한 겹만 되돌아오면
            // 그것은 복원이 아니라 껍데기다. `Probe::Tree` 가 그것을 잰다.
            plain(
                d.to_string_lossy().to_string(),
                Probe::Tree(d.to_string_lossy().to_string()),
            )
        } // **catch-all 이 없다.** P8 이 마지막 Op 을 채우면서 29종 전부가 여기
          // 사례를 갖고, 남겨 두면 도달할 수 없는 코드가 된다.
          //
          // 없는 편이 낫다. Op 을 새로 정의하면 이 `match` 가 컴파일되지 않고,
          // 그것이 "왕복 사례를 쓰라" 는 가장 확실한 알림이다.
    })
}

/// 서비스 정의 키 하나를 차린다. 실기기와 같은 값 이름을 쓴다.
fn svc(b: &Bench, name: &str) -> String {
    let key = format!("HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}");
    b.set_reg(&format!("{key}\\Start"), 4, "2");
    b.set_reg(&format!("{key}\\ImagePath"), 2, "C:\\a\\evil.exe");
    b.set_reg(&format!("{key}\\FailureActions"), 3, "recovery");
    key
}

/// 인자가 붙은 최소 `.lnk`. 헤더 0x4C · StringData(NAME·ARGUMENTS).
fn lnk_with_arguments() -> Vec<u8> {
    // `IS_UNICODE` 가 없으면 StringData 가 ANSI 로 읽혀 아무것도 파싱되지 않는다.
    const IS_UNICODE: u32 = 1 << 7;
    const HAS_NAME: u32 = 1 << 2;
    const HAS_ARGUMENTS: u32 = 1 << 5;
    let mut b = vec![0u8; 0x4C];
    b[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
    b[20..24].copy_from_slice(&(IS_UNICODE | HAS_NAME | HAS_ARGUMENTS).to_le_bytes());
    for s in ["이름", "-enc evil"] {
        let u: Vec<u16> = s.encode_utf16().collect();
        b.extend_from_slice(&(u.len() as u16).to_le_bytes());
        for c in u {
            b.extend_from_slice(&c.to_le_bytes());
        }
    }
    b
}

// ───────────────────────────────────────────────────── 수행

fn plan_of(run: &str, a: Action) -> PlanEnvelope {
    Envelope {
        schema_version: 1,
        kind: remedy_sdk::artifact::ArtifactKind::Plan,
        run_id: run.to_string(),
        created: "2026-08-22T00:00:00Z".into(),
        host: HostInfo {
            hostname: "T".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        core: CoreInfo {
            version: "0".into(),
            build: "dev".into(),
        },
        plugins: Vec::new(),
        body: PlanBody {
            actions: vec![a],
            verdicts: vec!["g0".into()],
            observation: Default::default(),
            deferred: Vec::new(),
            verify_after_reboot: false,
            submit_hint: None,
        },
    }
}

fn action_for(op: Op, c: &Case) -> Action {
    Action {
        seq: 1,
        op,
        target: c.target.clone(),
        r#match: c.locator.clone(),
        max_targets: None,
        // 재귀 삭제 상한. 이 왕복 시험은 규모가 작아 넉넉히 준다 — 여기서
        // 재려는 것은 담고 되돌리는 것이지 상한이 아니다 (그것은 p8_guards).
        max_children: Some(500),
        max_depth: Some(8),
        max_retries: None,
        include_descendants: None,
        sha256: None,
        size: None,
        strip: c.strip.clone(),
        because: vec!["e#0".into()],
        backup: None,
        reversible: op.info().reversible,
        risk: Risk::Medium,
        user_impact: None,
    }
}

fn restore_all(b: &Bench, run: &str, state: &Path, container: &Path) {
    let bytes = remedy_core::restore::read_container(container).expect("컨테이너");
    let sealed = remedy_core::restore::peek(&bytes).expect("헤더");
    let key = remedy_core::restore::unlock(
        &sealed.header,
        &remedy_core::restore::KeySource {
            state_dir: Some(state.to_path_buf()),
            ..Default::default()
        },
    )
    .expect("풀기");
    let opened = sealed.unlock(&key).expect("열기");
    let plan = remedy_core::restore::plan(
        &opened,
        run,
        b,
        &remedy_core::restore::Guards {
            protected: &remedy_plan::Protected::new(
                remedy_sdk::catalog::Platform::Windows,
                remedy_plan::expand_env_for_protection,
            ),
            vouched: &remedy_core::restore::vouched(state, run),
        },
        &[],
        None,
    )
    .expect("복원 계획");
    for item in &plan.items {
        assert!(item.blocked.is_none(), "복원이 막혔다: {:?}", item.blocked);
    }
    for o in remedy_core::restore::apply(&plan, &opened, &key, b).expect("복원") {
        assert!(o.result.is_ok(), "{}: {:?}", o.dest, o.result);
    }
}

/// 게이트가 허용하는 Op 목록. **카탈로그가 정한다.**
///
/// # 플랫폼도 카탈로그가 정한다
///
/// 이 시험이 도는 기계에서 계획기가 낼 수 있는 Op 만 본다. Windows 축만 보면
/// Linux 에서 `dir.delete_recursive` 를 태우게 되는데, 그 Op 은 조건 3(하위에
/// 신뢰 서명 파일이 있으면 거부)을 지킬 수단이 Linux 에 없어 카탈로그가 닫아
/// 두었다 (설계-09 P12 결정 3).
///
/// **`derive::available` 과 같은 물음이어야 한다.** 게이트가 계획기보다 넓으면
/// 계획기가 내지도 않을 Op 을 재게 되고, 좁으면 계획기가 내는 Op 이 안 재진다.
fn ops_in_gate() -> Vec<Op> {
    Op::ALL
        .into_iter()
        .filter(|o| {
            let from = if cfg!(windows) {
                Some(o.info().implemented_in)
            } else if cfg!(target_os = "linux") {
                o.info().linux_from
            } else {
                None
            };
            from.is_some_and(|p| p <= remedy_sdk::IMPLEMENTED_THROUGH)
        })
        .collect()
}

/// 사례가 있는 Op 전부. **게이트 밖도 돈다.**
///
/// 게이트는 "계획기가 낼 수 있는가" 이고 이 시험은 "실행기·복원기가 제대로
/// 하는가" 다. 둘은 다른 질문이다 — P8 Op 은 구현이 끝났지만 게이트는 VM
/// 실증 뒤에야 올라가고(설계-09 P8), 그때까지 검증이 멈춰 있을 이유가 없다.
///
/// # Phase 는 무시하고 플랫폼은 무시하지 않는다
///
/// 앞 문단이 무시하는 것은 **"아직"** 이다. **"이 플랫폼에 없다"** 는 다르다 —
/// `dir.delete_recursive` 는 Linux 에서 조건 3 을 지킬 수단이 없어 카탈로그가
/// 닫아 두었고(설계-09 P12 결정 3), 그것을 여기서 태우면 **있지도 않을 기능의
/// 왕복**을 재게 된다.
fn ops_with_a_case() -> Vec<Op> {
    Op::ALL
        .into_iter()
        .filter(|op| {
            if !cfg!(windows) && op.info().linux_from.is_none() {
                return false;
            }
            let b = Bench::new(&format!("has-{}", op.info().id.replace('.', "_")));
            case_for(*op, &b).is_some()
        })
        .collect()
}

#[test]
fn every_op_the_gate_allows_has_a_case() {
    // **이 시험이 이 파일의 존재 이유다.** Op 이 늘면 왕복 사례도 늘어야 하고,
    // 그것을 사람의 기억에 맡기지 않는다.
    let missing: Vec<&str> = ops_in_gate()
        .into_iter()
        .filter(|op| {
            let b = Bench::new(&format!("probe-{}", op.info().id.replace('.', "_")));
            case_for(*op, &b).is_none()
        })
        .map(|op| op.info().id)
        .collect();
    assert!(
        missing.is_empty(),
        "게이트({:?}) 안인데 왕복 사례가 없는 Op: {missing:?}",
        remedy_sdk::IMPLEMENTED_THROUGH
    );
    // **모르는 게이트 값에서는 조용히 넘어가지 않는다.**
    //
    // 앞서 이 자리는 `if IMPLEMENTED_THROUGH == Phase::P7 { .. }` 였다. 게이트를
    // 올리는 순간 실패하지 않고 **그냥 안 돌게 된다** — 재는 것이 없는 검사로
    // 조용히 바뀐다. 게이트를 올릴 때마다 손으로 숫자를 넣게 만드는 것이 요점이다.
    //
    // **카탈로그에서 계산하면 안 된다.** `ops_in_gate()` 가 이미 카탈로그를
    // 읽으므로, 기대값도 거기서 뽑으면 자기 자신과 비교하는 항진명제가 된다.
    // 손으로 적은 숫자여야 누군가 Op 의 `implemented_in` 을 옮겼을 때 알아챈다.
    //
    // **플랫폼마다 다르다.** Linux 는 게이트가 P12 로 오르기 전까지 0 이었다 —
    // `linux_from` 이 전부 `Some(P12)` 이거나 `None` 이었기 때문이다. 그 0 이
    // "시험이 안 돈다" 로 조용히 바뀌지 않도록 여기서도 숫자로 못 박는다.
    let expected = if cfg!(windows) {
        match remedy_sdk::IMPLEMENTED_THROUGH {
            Phase::P7 => 20,  // P6 의 격리 하나 + P7 의 19종
            Phase::P8 => 28,  // + P8 의 8종 (dir.delete_recursive 는 P10 이라 빠진다)
            Phase::P10 => 29, // + dir.delete_recursive — P10 의 유일한 Op (P10-C 에서 열렸다)
            // P12 는 Linux 축만 연다. Windows 축의 Op 은 전부 P10 이하다.
            Phase::P12 => 29,
            g => panic!("게이트를 {g:?} 로 올렸으면 이 표도 갱신할 것"),
        }
    } else {
        match remedy_sdk::IMPLEMENTED_THROUGH {
            Phase::P7 | Phase::P8 | Phase::P10 => 0,
            // 2026-08-27 (P12 마감). 카탈로그가 Linux 에서 수행한다고 적은 것 전부다 —
            // 파일 계열 6 · 지속성 2 · 서비스 2 · 자동실행 1 · 바로가기 1 ·
            // 프로세스 1 · `structured_config.restore_default`(계획은 되지만
            // `NOT_PLANNABLE_YET` 이라 사례가 면제된다). 인증서 1 이 2026-08-28 에 더해졌다.
            // 2026-08-28: `cert_store.remove` 가 열려 15 가 됐다.
            // 2026-09-29: `service.stop` 이 열려 16 이 됐다 — 시스템 유닛을 systemd 에게
            // 멈추게 한다(설계-09 P12 결정 A). 서비스가 3 이 됐다.
            Phase::P12 => 16,
            g => panic!("게이트를 {g:?} 로 올렸으면 이 표도 갱신할 것"),
        }
    };
    assert_eq!(ops_in_gate().len(), expected, "{:?}", ops_in_gate());
}

#[test]
fn every_op_in_the_gate_round_trips() {
    let mut checked = Vec::new();
    for op in ops_with_a_case() {
        let slug = op.info().id.replace('.', "_");
        let b = Bench::new(&slug);
        let Some(c) = case_for(op, &b) else {
            panic!("{}: 왕복 사례가 없다", op.info().id);
        };
        let state = b.dir.join("state");
        let before = c.probe.read(&b);

        let rep = Executor::new(&b, state.clone())
            .with_progress(&Silent)
            .with_clock("2026-08-22T00:00:00Z")
            .apply(&plan_of(&slug, action_for(op, &c)));

        if let Some(why) = c.refuses {
            // 왕복할 수 없는 Op — **거절되고 아무것도 바뀌지 않아야 한다.**
            //
            // 거절이 어느 문에서 나오는지는 Op 마다 다르다. 백업보다 먼저
            // 막는 것(재귀 삭제의 서명 확인)은 `apply` 자체가 실패하고,
            // 수행 시점에 막는 것은 결과 한 줄이 실패로 남는다. **둘 다
            // "아무것도 바뀌지 않았다" 이고**, 그것이 여기서 재는 것이다.
            let rep = match rep {
                Ok(r) => r,
                Err(e) => {
                    let msg = e.to_string();
                    assert!(msg.contains(why), "{}: 사유가 다르다 {msg}", op.info().id);
                    assert_eq!(
                        c.probe.read(&b),
                        before,
                        "{}: 거절인데 바뀌었다",
                        op.info().id
                    );
                    checked.push(op.info().id);
                    continue;
                }
            };
            let errs: Vec<String> = rep
                .body
                .results
                .iter()
                .filter_map(|r| r.error.clone())
                .collect();
            assert_eq!(
                (rep.done(), rep.failed()),
                (0, 1),
                "{}: 거절되지 않았다",
                op.info().id
            );
            assert!(
                errs.iter().any(|e| e.contains(why)),
                "{}: 사유가 다르다 {errs:?}",
                op.info().id
            );
            assert_eq!(
                c.probe.read(&b),
                before,
                "{}: 거절인데 바뀌었다",
                op.info().id
            );
            checked.push(op.info().id);
            continue;
        }

        let rep = rep.unwrap_or_else(|e| panic!("{}: {e}", op.info().id));
        let errs: Vec<String> = rep
            .body
            .results
            .iter()
            .filter_map(|r| r.error.clone())
            .collect();
        assert_eq!(
            (rep.done(), rep.failed()),
            (1, 0),
            "{}: {errs:?}",
            op.info().id
        );

        if c.irreversible {
            // **되돌릴 수 없다고 선언한 Op 은 담을 것도 없어야 한다.**
            // 되돌릴 수 있다고 적어 놓고 담을 자리가 없으면 그 Op 은 복원
            // 불가능한 파괴가 된다 — 카탈로그가 그 대응을 강제하지만
            // (`backup_kinds`), 실제로 컨테이너가 만들어지지 않는 것은
            // 여기서만 확인된다.
            assert!(
                rep.container.is_none() || op.backup_kinds().is_empty(),
                "{}: 되돌릴 수 없다면서 컨테이너를 만들었다",
                op.info().id
            );
            assert_ne!(
                c.probe.read(&b),
                before,
                "{}: 수행했는데 세상이 그대로다",
                op.info().id
            );
            checked.push(op.info().id);
            continue;
        }

        // **무언가 실제로 일어났는가.** 이것이 없으면 아무것도 하지 않는 Op 도
        // 왕복 시험을 통과한다.
        let after = c.probe.read(&b);
        assert_ne!(
            after,
            before,
            "{}: 수행했는데 세상이 그대로다",
            op.info().id
        );

        restore_all(
            &b,
            &slug,
            &state,
            &rep.container
                .clone()
                .unwrap_or_else(|| panic!("{}: 컨테이너가 만들어지지 않았다", op.info().id)),
        );
        assert_eq!(
            c.probe.read(&b),
            before,
            "{}: 되돌렸는데 원본과 다르다",
            op.info().id
        );
        checked.push(op.info().id);
    }
    assert_eq!(checked.len(), ops_with_a_case().len(), "{checked:?}");
}
