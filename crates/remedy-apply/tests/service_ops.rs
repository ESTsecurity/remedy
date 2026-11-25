//! 서비스 Op — **다시 시작해야 끝나는 치료**(2026-11-25 · 이슈 #172 ⑥).
//!
//! 재는 것은 둘이다.
//!
//! 1. 서비스를 지웠는데 SCM 이 삭제를 미루면(그 서비스에 열린 핸들이 있다 · 아직 돈다) 정의 키에 지울 표시가
//!    남는다. 그 치료를 '다시 시작해야 끝남' 으로 알리는가 — 종료 코드의 바탕(실패 0)은 그대로다.
//! 2. 드라이버가 정지를 받지 않으면(`PlatformError::NotStoppable`) 같은 대상의 사용 안 함이 끝났을 때만 받는가.
//!    끝나지 않았으면 그 정지를 실패로 되돌리는가 — 결정 2026-09-13(정말로 멈추지 않을 서비스를 '치료 완료' 로
//!    보고하지 않는다)이 그대로인가.
//!
//! 진짜 SCM 은 랩 하네스(`Invoke-WinwyvernVerify.ps1` 의 H 칸)가 잰다. 여기는 실행기의 판단만 가짜로 잰다.

use remedy_apply::{Event, Executor, Progress, Restart};
use remedy_platform::write::{FileMeta, FsRestore, PlatformWrite, RegKeyIndex, RestoreReport};
use remedy_platform::PlatformError;
use remedy_sdk::artifact::{Action, CoreInfo, Envelope, HostInfo, PlanBody, PlanEnvelope};
use remedy_sdk::catalog::{Op, Risk};
use std::cell::{Cell, RefCell};
use std::path::PathBuf;

const KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\NeacSafe64";

#[derive(Clone, Copy)]
enum Stop {
    Ok,
    NotStoppable,
    Refused,
    TimedOut,
}

/// 서비스 하나를 흉내 내는 백엔드. 부른 것을 차례로 적는다.
struct Scm {
    dir: PathBuf,
    stop: Cell<Stop>,
    disable_fails: Cell<bool>,
    /// 지운 뒤 지울 표시가 몇 번 물을 때까지 남는가. `u32::MAX` 면 끝까지 남는다(핸들이 열려 있다).
    pending_polls: Cell<u32>,
    /// 지울 표시를 묻는 것이 실패한다.
    query_fails: Cell<bool>,
    deleted: Cell<bool>,
    polls: Cell<u32>,
    calls: RefCell<Vec<String>>,
}

impl Scm {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("remedy-svc-ops-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("작업 디렉터리");
        Self {
            dir,
            stop: Cell::new(Stop::Ok),
            disable_fails: Cell::new(false),
            pending_polls: Cell::new(0),
            query_fails: Cell::new(false),
            deleted: Cell::new(false),
            polls: Cell::new(0),
            calls: RefCell::new(Vec::new()),
        }
    }
    fn state(&self) -> PathBuf {
        self.dir.join("state")
    }
    fn call(&self, what: &str) {
        self.calls.borrow_mut().push(what.to_string());
    }
}

impl Drop for Scm {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl PlatformWrite for Scm {
    fn backend_name(&self) -> &'static str {
        "svc-ops-scm"
    }
    fn plan_restore(&self, dest: &str, meta: &FileMeta) -> RestoreReport {
        FsRestore.plan_restore(dest, meta)
    }
    fn quarantine_read(&self, path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
        FsRestore.quarantine_read(path)
    }
    fn restore_file(
        &self,
        dest: &str,
        content: &[u8],
        meta: &FileMeta,
    ) -> Result<RestoreReport, PlatformError> {
        FsRestore.restore_file(dest, content, meta)
    }
    fn destroy_file(&self, _path: &str) -> Result<(), PlatformError> {
        unreachable!("이 시험은 파일을 지우지 않는다")
    }
    fn exists(&self, _path: &str) -> bool {
        false
    }

    // 백업 — 정의 키 하위 트리. 내용은 재지 않는다(복원 시험의 몫).
    fn registry_key_read(&self, _key: &str) -> Result<(Vec<u8>, RegKeyIndex), PlatformError> {
        Ok((b"key".to_vec(), RegKeyIndex::default()))
    }
    fn registry_key_exists(&self, _key: &str) -> bool {
        !self.deleted.get()
    }

    fn service_running(&self, _target: &str) -> bool {
        true
    }
    fn service_clear_recovery(&self, _target: &str) -> Result<(), PlatformError> {
        self.call("clear_recovery");
        Ok(())
    }
    fn service_stop(&self, _target: &str) -> Result<(), PlatformError> {
        self.call("stop");
        let why = || "sc.exe stop failed (exit code 1052)".to_string();
        match self.stop.get() {
            Stop::Ok => Ok(()),
            Stop::NotStoppable => Err(PlatformError::NotStoppable(why())),
            Stop::Refused => Err(PlatformError::Refused(why())),
            Stop::TimedOut => Err(PlatformError::TimedOut("1053".into())),
        }
    }
    fn service_disable(&self, _target: &str) -> Result<(), PlatformError> {
        self.call("disable");
        if self.disable_fails.get() {
            return Err(PlatformError::Refused("sc.exe config failed".into()));
        }
        Ok(())
    }
    fn service_delete(&self, _target: &str) -> Result<(), PlatformError> {
        self.call("delete");
        self.deleted.set(true);
        Ok(())
    }
    fn service_delete_pending(&self, _path: &str) -> Result<bool, PlatformError> {
        self.call("pending?");
        if self.query_fails.get() {
            return Err(PlatformError::Unsupported("access denied"));
        }
        if !self.deleted.get() {
            return Ok(false);
        }
        let n = self.polls.get();
        self.polls.set(n + 1);
        Ok(n < self.pending_polls.get())
    }
}

/// `--events` 가 쓰는 꼴 그대로 줄을 모은다.
#[derive(Default)]
struct Events(RefCell<Vec<String>>);

impl Progress for Events {
    fn emit(&self, event: &Event<'_>) {
        self.0
            .borrow_mut()
            .push(serde_json::to_string(event).expect("이벤트 직렬화"));
    }
}

impl Events {
    fn finished(&self) -> serde_json::Value {
        let lines = self.0.borrow();
        let last = lines.last().expect("이벤트가 없다");
        serde_json::from_str(last).expect("JSON")
    }
    fn notes(&self) -> Vec<String> {
        self.0
            .borrow()
            .iter()
            .filter_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).ok()?;
                (v["event"] == "note").then(|| v["text"].as_str().unwrap_or_default().to_string())
            })
            .collect()
    }
}

fn act(seq: u32, op: Op) -> Action {
    let info = op.info();
    Action {
        seq,
        op,
        target: Some(KEY.to_string()),
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
        risk: Risk::Medium,
        user_impact: None,
    }
}

/// 계획기가 서비스 하나에 내는 꼴 — 복구 해제 → 정지 → 사용 안 함 → 삭제(derive.rs).
fn cure() -> Vec<Action> {
    vec![
        act(1, Op::ServiceClearRecovery),
        act(2, Op::ServiceStop),
        act(3, Op::ServiceDisable),
        act(4, Op::ServiceDelete),
    ]
}

fn plan_of(run: &str, actions: Vec<Action>) -> PlanEnvelope {
    Envelope {
        schema_version: 1,
        kind: remedy_sdk::artifact::ArtifactKind::Plan,
        run_id: run.to_string(),
        created: "2026-11-25T00:00:00Z".into(),
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

fn run(scm: &Scm, ev: &Events, name: &str, actions: Vec<Action>) -> remedy_apply::Report {
    Executor::new(scm, scm.state())
        .with_progress(ev)
        .with_clock("2026-11-25T00:00:00Z")
        .apply(&plan_of(name, actions))
        .expect("수행")
}

fn journal(rep: &remedy_apply::Report) -> String {
    std::fs::read_to_string(&rep.journal).expect("저널")
}

fn outcome_of(rep: &remedy_apply::Report, seq: u32) -> remedy_sdk::artifact::ActionOutcome {
    rep.body
        .results
        .iter()
        .find(|r| r.seq == seq)
        .map(|r| r.outcome)
        .expect("그 seq 의 결과")
}

// ───────────────────────────────────────────── 지운 서비스

#[test]
fn a_service_that_is_gone_right_away_says_nothing_more() {
    // **정상 경로는 지금 그대로다** — 끝 줄의 칸 셋, 재부팅 필요 없음, 남은 것 없음.
    let scm = Scm::new("gone");
    let ev = Events::default();
    let rep = run(&scm, &ev, "gone", cure());

    assert_eq!((rep.done(), rep.failed()), (4, 0), "{:?}", rep.body.results);
    assert!(rep.at_restart.is_empty(), "{:?}", rep.at_restart);
    assert!(!rep.body.reboot_required);
    assert_eq!(
        ev.0.borrow().last().map(String::as_str),
        Some(r#"{"event":"finished","done":4,"failed":0}"#),
        "정상 회차의 끝 줄 바이트가 바뀌었다"
    );
    assert_eq!(
        scm.polls.get(),
        1,
        "지운 뒤 한 번만 물어야 한다 — 정상 경로에 기다림이 들었다"
    );
}

#[test]
fn a_postponed_delete_is_reported_as_finishing_at_restart() {
    // 랩(2026-11-25)의 꼴 — 핸들을 쥔 채 치료하면 4건 done 인데 정의 키에 지울 표시가 남는다.
    let scm = Scm::new("pending");
    scm.pending_polls.set(u32::MAX);
    let ev = Events::default();
    let rep = run(&scm, &ev, "pending", cure());

    assert_eq!(
        (rep.done(), rep.failed()),
        (4, 0),
        "결과는 끝남 그대로다(종료 1)"
    );
    assert_eq!(rep.at_restart.get(&4), Some(&Restart::DeletePending));
    assert_eq!(rep.at_restart.len(), 1, "{:?}", rep.at_restart);
    assert!(
        rep.body.reboot_required,
        "다시 시작해야 끝난다고 말하지 않았다"
    );
    let f = ev.finished();
    assert_eq!(f["reboot_required"], true, "{f}");
    assert_eq!(
        (f["done"].as_u64(), f["failed"].as_u64()),
        (Some(4), Some(0)),
        "{f}"
    );

    let j = journal(&rep);
    let note = j
        .find("seq 4: Windows 가 서비스 지우기를 미뤘습니다")
        .expect("저널에 사유가 없다");
    let end = j.find(r#""rec":"end""#).expect("end");
    assert!(note < end, "사유는 End 앞에 남아야 한다\n{j}");
}

#[test]
fn a_delete_that_settles_within_the_wait_is_not_reported() {
    let scm = Scm::new("settles");
    scm.pending_polls.set(3);
    let ev = Events::default();
    let rep = run(&scm, &ev, "settles", cure());

    assert!(rep.at_restart.is_empty(), "{:?}", rep.at_restart);
    assert!(!rep.body.reboot_required);
    assert_eq!(scm.polls.get(), 4, "풀릴 때까지 다시 물어야 한다");
}

#[test]
fn a_delete_that_cannot_be_checked_says_so() {
    // 읽지 못한 것을 '지워졌다' 로 접지 않는다.
    let scm = Scm::new("unverified");
    scm.query_fails.set(true);
    let ev = Events::default();
    let rep = run(&scm, &ev, "unverified", cure());

    assert_eq!((rep.done(), rep.failed()), (4, 0));
    assert_eq!(rep.at_restart.get(&4), Some(&Restart::DeleteUnverified));
    assert!(rep.body.reboot_required);
    assert!(
        journal(&rep).contains("seq 4: 서비스를 지운 뒤 지울 표시가 풀렸는지 확인하지 못했습니다"),
        "{}",
        journal(&rep)
    );
}

// ───────────────────────────────────────────── 정지를 받지 않는 드라이버

#[test]
fn a_driver_that_will_not_stop_is_accepted_when_it_is_disabled() {
    let scm = Scm::new("nostop");
    scm.stop.set(Stop::NotStoppable);
    // 도는 드라이버는 지워도 다시 시작할 때까지 남는다.
    scm.pending_polls.set(u32::MAX);
    let ev = Events::default();
    let rep = run(&scm, &ev, "nostop", cure());

    assert_eq!((rep.done(), rep.failed()), (4, 0), "{:?}", rep.body.results);
    assert_eq!(rep.at_restart.get(&2), Some(&Restart::StopAtRestart));
    assert_eq!(rep.at_restart.get(&4), Some(&Restart::DeletePending));
    assert!(rep.body.reboot_required);
    // 오류 머리의 언어는 단정하지 않는다 — `cargo test` 아래에서는 영어로 풀린다.
    let j = journal(&rep);
    assert!(
        j.lines().any(|l| l.contains(r#""rec":"note""#)
            && l.contains("seq 2:")
            && l.contains("1052")
            && l.contains("다시 시작해야 끝나는 것으로 받습니다")),
        "받은 사유가 저널에 없다\n{j}"
    );
}

#[test]
fn a_driver_that_will_not_stop_still_fails_without_a_disable() {
    // 사용 안 함이 없으면 다시 시작해도 다시 올라온다 — 받을 근거가 없다.
    let scm = Scm::new("nostop-alone");
    scm.stop.set(Stop::NotStoppable);
    let ev = Events::default();
    let rep = run(&scm, &ev, "nostop-alone", vec![act(1, Op::ServiceStop)]);

    assert_eq!((rep.done(), rep.failed()), (0, 1));
    assert!(rep.at_restart.is_empty());
    assert!(!rep.body.reboot_required);
}

#[test]
fn a_driver_stop_is_turned_back_into_a_failure_when_the_disable_fails() {
    // **결정 2026-09-13 이 지키는 자리** — 사용 안 함이 끝나지 않았으면 다시 시작해도 그 드라이버는 올라온다.
    let scm = Scm::new("nostop-nodisable");
    scm.stop.set(Stop::NotStoppable);
    scm.disable_fails.set(true);
    let ev = Events::default();
    let rep = run(&scm, &ev, "nostop-nodisable", cure());

    use remedy_sdk::artifact::ActionOutcome::Failed;
    assert_eq!(
        outcome_of(&rep, 2),
        Failed,
        "끝 확인이 정지를 되돌리지 않았다"
    );
    assert_eq!(outcome_of(&rep, 3), Failed);
    assert_eq!(rep.failed(), 2, "{:?}", rep.body.results);
    assert!(!rep.at_restart.contains_key(&2), "{:?}", rep.at_restart);
    let f = ev.finished();
    assert_eq!(
        f["failed"].as_u64(),
        Some(2),
        "끝 판정은 되돌린 것을 센다: {f}"
    );
    assert!(
        ev.notes().iter().any(|n| n.starts_with("seq 2:")),
        "되돌린 사실이 이벤트에 없다: {:?}",
        ev.notes()
    );

    // 저널은 나중 기록이 이긴다 — seq 2 의 결과가 둘이고, 뒤의 것이 실패다.
    let j = journal(&rep);
    let lines: Vec<&str> = j
        .lines()
        .filter(|l| l.contains(r#""outcome""#) && l.contains(r#""seq":2"#))
        .collect();
    assert_eq!(lines.len(), 2, "{j}");
    assert!(lines[1].contains("failed"), "{}", lines[1]);
}

#[test]
fn other_stop_failures_are_still_failures() {
    for (name, stop) in [("refused", Stop::Refused), ("timedout", Stop::TimedOut)] {
        let scm = Scm::new(name);
        scm.stop.set(stop);
        let ev = Events::default();
        let rep = run(&scm, &ev, name, cure());
        assert_eq!(
            outcome_of(&rep, 2),
            remedy_sdk::artifact::ActionOutcome::Failed,
            "{name}"
        );
        assert!(
            !rep.at_restart.contains_key(&2),
            "{name}: {:?}",
            rep.at_restart
        );
        assert_eq!(rep.failed(), 1, "{name}: {:?}", rep.body.results);
    }
}
