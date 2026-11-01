//! 파일 계열 Op 4종 (설계-09 P7).
//!
//! **실제로 파일을 지운다.** 임시 디렉터리 안에서만 돈다.
//!
//! 재는 것의 절반은 **하지 않은 일**이다 — 스트림 하나를 지우면서 호스트
//! 파일을 건드리지 않았는가, 예약이 파괴로 보고되지 않았는가, 인자를 빼면서
//! 대상까지 지우지 않았는가.

use remedy_apply::{Executor, Silent};
use remedy_platform::write::{
    FileMeta, FsRestore, PlatformWrite, RegistryValueBackup, RestoreReport,
};
use remedy_platform::PlatformError;
use remedy_sdk::artifact::{Action, CoreInfo, Envelope, HostInfo, PlanBody, PlanEnvelope};
use remedy_sdk::catalog::{Op, Risk};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// 파일은 진짜로 다루고, 레지스트리·스트림·바로가기는 기록만 한다.
///
/// 재부팅 예약은 레지스트리 쓰기라 실기기에서 시험할 수 없다. **무엇을 큐에
/// 넣었는지**는 여기서 정확히 잴 수 있다.
struct Lab {
    dir: PathBuf,
    reg: RefCell<BTreeMap<String, RegistryValueBackup>>,
    scheduled: RefCell<Vec<String>>,
    streams: RefCell<BTreeMap<String, Vec<u8>>>,
    stripped: RefCell<Vec<String>>,
    /// 켜면 **백업은 되지만 파괴가 실패한다.** 잠긴 파일이 그 모양이다.
    destroy_fails: std::cell::Cell<bool>,
}

impl Lab {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("remedy-p7-file-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("작업 디렉터리");
        Self {
            dir,
            reg: RefCell::new(BTreeMap::new()),
            scheduled: RefCell::new(Vec::new()),
            streams: RefCell::new(BTreeMap::new()),
            stripped: RefCell::new(Vec::new()),
            destroy_fails: std::cell::Cell::new(false),
        }
    }
    fn file(&self, name: &str, body: &[u8]) -> String {
        let p = self.dir.join(name);
        std::fs::write(&p, body).expect("파일");
        p.to_string_lossy().to_string()
    }
    fn stream(&self, host: &str, name: &str, body: &[u8]) -> String {
        let t = format!("{host}:{name}");
        self.streams.borrow_mut().insert(t.clone(), body.to_vec());
        t
    }
    fn state(&self) -> PathBuf {
        self.dir.join("state")
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl PlatformWrite for Lab {
    fn backend_name(&self) -> &'static str {
        "p7-file-lab"
    }
    fn plan_restore(&self, dest: &str, meta: &FileMeta) -> RestoreReport {
        FsRestore.plan_restore(dest, meta)
    }
    fn restore_file(
        &self,
        dest: &str,
        content: &[u8],
        meta: &FileMeta,
    ) -> Result<RestoreReport, PlatformError> {
        // 스트림 대상은 가짜 저장소로 되돌린다.
        if self.streams.borrow().contains_key(dest) || dest.contains(".txt:") {
            self.streams
                .borrow_mut()
                .insert(dest.to_string(), content.to_vec());
            return Ok(RestoreReport {
                restored: vec![dest.to_string()],
                lost: Vec::new(),
            });
        }
        FsRestore.restore_file(dest, content, meta)
    }
    fn quarantine_read(&self, path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
        FsRestore.quarantine_read(path)
    }
    fn destroy_file(&self, path: &str) -> Result<(), PlatformError> {
        if self.destroy_fails.get() {
            return Err(PlatformError::Unsupported("잠겨 있다"));
        }
        FsRestore.destroy_file(path)
    }
    fn exists(&self, path: &str) -> bool {
        if let Some(v) = self.streams.borrow().get(path) {
            let _ = v;
            return true;
        }
        std::path::Path::new(path).exists()
    }

    fn registry_read(&self, target: &str) -> Result<RegistryValueBackup, PlatformError> {
        self.reg
            .borrow()
            .get(target)
            .cloned()
            .ok_or(PlatformError::Unsupported("그런 값이 없다"))
    }
    fn registry_write(
        &self,
        target: &str,
        value: &RegistryValueBackup,
    ) -> Result<(), PlatformError> {
        self.reg
            .borrow_mut()
            .insert(target.to_string(), value.clone());
        Ok(())
    }

    fn schedule_delete_on_reboot(&self, path: &str) -> Result<(), PlatformError> {
        self.scheduled.borrow_mut().push(path.to_string());
        Ok(())
    }
    fn stream_read(&self, target: &str) -> Result<Vec<u8>, PlatformError> {
        self.streams
            .borrow()
            .get(target)
            .cloned()
            .ok_or(PlatformError::Unsupported("그런 스트림이 없다"))
    }
    fn stream_delete(&self, target: &str) -> Result<(), PlatformError> {
        self.streams
            .borrow_mut()
            .remove(target)
            .map(|_| ())
            .ok_or(PlatformError::Unsupported("그런 스트림이 없다"))
    }
    fn shortcut_strip_args(&self, path: &str, expect: &str) -> Result<(), PlatformError> {
        // 실제 변환은 순수 함수가 따로 시험한다. 여기서 재는 것은
        // **호출되었는가와 파일을 지우지 않았는가**, 그리고 **계획이 본 인자가
        // 백엔드까지 닿았는가**다.
        self.stripped.borrow_mut().push(format!("{path}|{expect}"));
        Ok(())
    }
}

fn plan_of(run: &str, actions: Vec<Action>) -> PlanEnvelope {
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
            actions,
            verdicts: vec!["g0".into()],
            observation: Default::default(),
            deferred: Vec::new(),
            verify_after_reboot: false,
            submit_hint: None,
        },
    }
}

/// 술어(`match`)를 붙인 Action. `shortcut.strip_args` 는 그것 없이는 거절된다.
fn act_matching(seq: u32, op: Op, target: &str, m: serde_json::Value) -> Action {
    Action {
        r#match: Some(m),
        ..act(seq, op, target)
    }
}

fn act(seq: u32, op: Op, target: &str) -> Action {
    let info = op.info();
    Action {
        seq,
        op,
        target: Some(target.to_string()),
        r#match: None,
        max_targets: None,
        max_retries: None,
        max_children: None,
        max_depth: None,
        include_descendants: None,
        sha256: None,
        size: None,
        strip: None,
        because: vec!["e#0".into()],
        backup: None,
        reversible: info.reversible,
        risk: Risk::Low,
        user_impact: None,
    }
}

fn run(lab: &Lab, name: &str, actions: Vec<Action>) -> remedy_apply::Report {
    Executor::new(lab, lab.state())
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(name, actions))
        .expect("수행")
}

// ───────────────────────────────────────────── file.delete

#[test]
fn deleting_a_file_removes_it_and_backs_it_up_first() {
    let lab = Lab::new("delete");
    let p = lab.file("evil.exe", b"payload");
    let rep = run(&lab, "delete", vec![act(1, Op::FileDelete, &p)]);

    assert_eq!((rep.done(), rep.failed()), (1, 0), "{:?}", rep.body.results);
    assert!(!std::path::Path::new(&p).exists(), "파일이 남았다");
    assert!(rep.container.is_some(), "백업 없이 지웠다");
    assert!(
        !rep.body.reboot_required,
        "지웠는데 재부팅이 필요하다고 한다"
    );
}

#[test]
fn a_locked_file_fails_and_is_not_silently_rerouted() {
    // **실행기가 Op 을 바꾸지 않는다.** 조건 분기로 동작을 추가하면 드라이런이
    // 보여준 것과 실행한 것이 달라진다 (불변식 P, 설계-03 §1). 잠긴 파일은
    // 실패로 기록되고 부분 치료로 보고된다 (설계-03 §5 — 재부팅 뒤 재시도는 v1 에
    // 없다).
    let lab = Lab::new("locked");
    let p = lab.file("locked.sys", b"driver");
    // **백업은 되고 파괴만 실패한다.** 잠긴 파일이 정확히 그 모양이다 —
    // 읽을 수는 있지만 지울 수 없다. 백업 단계에서 멈추는 경우로 시험하면
    // `perform` 에 닿지도 않아 이 가드를 재지 못한다(역검증에서 그렇게 샜다).
    lab.destroy_fails.set(true);

    let rep = run(&lab, "locked", vec![act(1, Op::FileDelete, &p)]);

    assert_eq!(rep.failed(), 1, "잠긴 파일이 성공으로 보고됐다");
    assert!(
        lab.scheduled.borrow().is_empty(),
        "실행기가 Op 을 바꿔 재부팅 예약으로 갈아탔다 — 드라이런이 보여준 것과 다르다"
    );
    assert!(
        std::path::Path::new(&p).exists(),
        "실패인데 파일이 사라졌다"
    );
    assert!(
        !rep.body.reboot_required,
        "예약하지 않았는데 재부팅이 필요하다고 한다"
    );
}

// ───────────────────────────────────────────── file.delete_on_reboot

#[test]
fn scheduling_a_delete_says_a_reboot_is_needed() {
    // **예약은 파괴가 아니다.** 파일은 아직 그 자리에 있고 사라지는 것은 다음
    // 부팅이다 — 말하지 않으면 사용자는 치료가 끝났다고 읽는다.
    let lab = Lab::new("reboot");
    let p = lab.file("locked.sys", b"driver");
    let rep = run(&lab, "reboot", vec![act(1, Op::FileDeleteOnReboot, &p)]);

    assert_eq!((rep.done(), rep.failed()), (1, 0), "{:?}", rep.body.results);
    assert_eq!(lab.scheduled.borrow().as_slice(), std::slice::from_ref(&p));
    assert!(
        rep.body.reboot_required,
        "재부팅이 필요하다고 말하지 않았다"
    );
    // 아직 그 자리에 있어야 한다. 지웠다면 예약할 이유가 없었다.
    assert!(std::path::Path::new(&p).exists(), "예약인데 지웠다");
    // 그래도 백업은 있다 — 재부팅 뒤에는 되돌릴 수 없기 때문이다.
    assert!(rep.container.is_some(), "예약인데 백업이 없다");
}

// ───────────────────────────────────────────── file.delete_stream

#[test]
fn deleting_a_stream_leaves_the_host_file_alone() {
    let lab = Lab::new("stream");
    let host = lab.file("download.txt", "본문 그대로".as_bytes());
    let s = lab.stream(&host, "Zone.Identifier", b"[ZoneTransfer]\r\nZoneId=3\r\n");

    let rep = run(&lab, "stream", vec![act(1, Op::FileDeleteStream, &s)]);
    assert_eq!((rep.done(), rep.failed()), (1, 0), "{:?}", rep.body.results);

    assert!(!lab.streams.borrow().contains_key(&s), "스트림이 남았다");
    assert!(
        std::path::Path::new(&host).exists(),
        "스트림을 지우면서 호스트 파일까지 지웠다"
    );
    assert_eq!(
        std::fs::read(&host).expect("본문"),
        "본문 그대로".as_bytes(),
        "호스트 파일 내용이 바뀌었다"
    );
}

#[test]
fn a_stream_backup_holds_the_stream_not_the_host_file() {
    // 파일 전체를 담으면 스트림 하나를 지우고 **파일 전체를 되돌리는** 꼴이 되고,
    // 그 사이 파일에 일어난 변경이 사라진다.
    let lab = Lab::new("streambk");
    let host = lab.file(
        "download.txt",
        "아주 긴 본문 ...........................".as_bytes(),
    );
    let s = lab.stream(&host, "Zone.Identifier", b"ZoneId=3");

    let rep = run(&lab, "streambk", vec![act(1, Op::FileDeleteStream, &s)]);
    let path = rep.container.clone().expect("컨테이너");
    let bytes = std::fs::read(&path).expect("읽기");
    let sealed = remedy_quarantine::Sealed::parse(&bytes).expect("헤더");
    let mk = remedy_quarantine::MachineKey::load_or_create(&lab.state().join("machine.key"))
        .expect("키");
    let slot = sealed
        .header
        .wraps
        .iter()
        .find(|w| w.kind == remedy_quarantine::WrapKind::Local)
        .expect("로컬 wrap");
    let ck = mk.unwrap(slot).expect("풀기");
    let opened = sealed.unlock(&ck).expect("열기");
    let e = opened.manifest.entries.first().expect("엔트리");
    assert_eq!(e.kind, remedy_sdk::EntryKind::FileStream);
    assert_eq!(e.origin, s);
    let body = opened.read(&e.id, &ck).expect("본문");
    assert_eq!(
        body.content, b"ZoneId=3",
        "스트림이 아니라 다른 것을 담았다"
    );
}

// ───────────────────────────────────────────── shortcut.strip_args

#[test]
fn a_plan_that_does_not_say_which_arguments_is_refused() {
    // 술어가 없으면 실행기는 **지금 파일에 있는 것**을 뗄 수밖에 없다. 수집과
    // 실행 사이에 사용자가 정당한 인자를 붙였다면 그것이 곧 계획에 없는
    // 파괴다. `text_config.remove_line` 이 줄 번호와 내용을 요구하는 것과 같다.
    let lab = Lab::new("lnknomatch");
    let p = lab.file("악성.lnk", b"lnk-bytes");
    let rep = run(&lab, "lnknomatch", vec![act(1, Op::ShortcutStripArgs, &p)]);

    assert_eq!((rep.done(), rep.failed()), (0, 1), "{:?}", rep.body.results);
    assert!(
        lab.stripped.borrow().is_empty(),
        "거절해 놓고 백엔드를 불렀다"
    );
}

#[test]
fn stripping_shortcut_arguments_does_not_delete_the_shortcut() {
    let lab = Lab::new("lnk");
    let p = lab.file("악성.lnk", b"lnk-bytes");
    let rep = run(
        &lab,
        "lnk",
        vec![act_matching(
            1,
            Op::ShortcutStripArgs,
            &p,
            serde_json::json!({ "args": "-enc BASE64" }),
        )],
    );

    assert_eq!((rep.done(), rep.failed()), (1, 0), "{:?}", rep.body.results);
    assert_eq!(
        lab.stripped.borrow().as_slice(),
        [format!("{p}|-enc BASE64")],
        "계획이 본 인자가 백엔드까지 닿지 않았다"
    );
    assert!(
        std::path::Path::new(&p).exists(),
        "인자만 빼야 하는데 바로가기를 지웠다"
    );
}

#[test]
fn a_shortcut_edit_backs_up_the_whole_file() {
    // **부분 편집의 백업은 값 전체다** (설계-03 §2). 복원하면 인자가 붙은
    // 원본이 그대로 돌아오며, 그것이 옳은 동작이다.
    let lab = Lab::new("lnkbk");
    let p = lab.file("악성.lnk", b"lnk-with-args");
    let rep = run(
        &lab,
        "lnkbk",
        vec![act_matching(
            1,
            Op::ShortcutStripArgs,
            &p,
            serde_json::json!({ "args": "-enc BASE64" }),
        )],
    );

    let bytes = std::fs::read(rep.container.clone().expect("컨테이너")).expect("읽기");
    let sealed = remedy_quarantine::Sealed::parse(&bytes).expect("헤더");
    let mk = remedy_quarantine::MachineKey::load_or_create(&lab.state().join("machine.key"))
        .expect("키");
    let slot = sealed
        .header
        .wraps
        .iter()
        .find(|w| w.kind == remedy_quarantine::WrapKind::Local)
        .expect("로컬 wrap");
    let ck = mk.unwrap(slot).expect("풀기");
    let opened = sealed.unlock(&ck).expect("열기");
    let e = opened.manifest.entries.first().expect("엔트리");
    assert_eq!(e.kind, remedy_sdk::EntryKind::File, "파일 전체가 아니다");
    let body = opened.read(&e.id, &ck).expect("본문");
    assert_eq!(body.content, b"lnk-with-args");
}
