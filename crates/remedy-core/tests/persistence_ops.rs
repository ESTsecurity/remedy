//! 지속성 제거 Op 2종 — `persistence.disable` · `persistence.delete` (설계-09 P7).
//!
//! 진짜 스케줄러를 건드리지 않는다. 여기서 재는 것은 **실행기가 무엇을 어떤
//! 순서로 부르는가**다 — 정의를 담기 전에 지우지 않는가, 이미 없는 것을 실패로
//! 올리지 않는가, `disable` 과 `delete` 가 서로의 문을 두드리지 않는가.
//!
//! 실제 `schtasks` 호출은 `Live` 안에 있고, 그쪽에서 재는 것은 **부르기 전에
//! 막는 검사**다 (등록 경로 검증 · IFEO). 두 시험이 다른 것을 잰다.

use remedy_apply::{Executor, Silent};
use remedy_platform::write::{FileMeta, PlatformWrite, RestoreReport};
use remedy_platform::PlatformError;
use remedy_sdk::artifact::{Action, CoreInfo, Envelope, HostInfo, PlanBody, PlanEnvelope};
use remedy_sdk::catalog::{Op, Risk};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// 등록 경로 → (정의 XML, 활성 여부).
#[derive(Default)]
struct FakeScheduler {
    tasks: RefCell<BTreeMap<String, (Vec<u8>, bool)>>,
    /// 부른 순서. 백업이 파괴보다 먼저인지 여기서 보인다.
    calls: RefCell<Vec<String>>,
}

impl FakeScheduler {
    fn with(id: &str, xml: &str) -> Self {
        let mut m = BTreeMap::new();
        m.insert(id.to_string(), (xml.as_bytes().to_vec(), true));
        Self {
            tasks: RefCell::new(m),
            calls: RefCell::new(Vec::new()),
        }
    }
    fn log(&self, what: &str) {
        self.calls.borrow_mut().push(what.to_string());
    }
    fn enabled(&self, id: &str) -> Option<bool> {
        self.tasks.borrow().get(id).map(|t| t.1)
    }
    fn xml(&self, id: &str) -> Option<String> {
        self.tasks
            .borrow()
            .get(id)
            .map(|t| String::from_utf8_lossy(&t.0).into_owned())
    }
}

impl PlatformWrite for FakeScheduler {
    fn backend_name(&self) -> &'static str {
        "fake-scheduler"
    }
    fn plan_restore(&self, _dest: &str, _meta: &FileMeta) -> RestoreReport {
        RestoreReport::default()
    }
    fn restore_file(
        &self,
        _dest: &str,
        _content: &[u8],
        _meta: &FileMeta,
    ) -> Result<RestoreReport, PlatformError> {
        Err(PlatformError::Unsupported("파일은 다루지 않는다"))
    }
    fn quarantine_read(&self, _path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
        Err(PlatformError::Unsupported("파일은 다루지 않는다"))
    }
    fn destroy_file(&self, _path: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("파일은 다루지 않는다"))
    }
    fn exists(&self, _path: &str) -> bool {
        false
    }

    fn persistence_read(
        &self,
        id: &str,
    ) -> Result<(Vec<u8>, remedy_platform::write::PersistenceIndex), PlatformError> {
        self.log("read");
        // 진짜 백엔드와 같은 자리에서 같은 검사를 한다.
        if let Some(why) = remedy_platform::write::task_id_problem(id) {
            return Err(PlatformError::Refused(why.to_string()));
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
        self.log("disable");
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
        self.log("delete");
        self.tasks
            .borrow_mut()
            .remove(id)
            .map(|_| ())
            .ok_or(PlatformError::Unsupported("그런 작업이 없다"))
    }

    fn persistence_restore(
        &self,
        id: &str,
        xml: &[u8],
        _index: &remedy_platform::write::PersistenceIndex,
    ) -> Result<(), PlatformError> {
        self.log("restore");
        self.tasks
            .borrow_mut()
            .insert(id.to_string(), (xml.to_vec(), true));
        Ok(())
    }
}

const XML: &str =
    "<?xml version=\"1.0\"?><Task><Settings><Enabled>true</Enabled></Settings></Task>";
const ID: &str = "\\Microsoft\\Windows\\Locust";

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

fn act(op: Op, target: &str) -> Action {
    Action {
        seq: 1,
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
        reversible: op.info().reversible,
        risk: Risk::Medium,
        user_impact: None,
    }
}

fn state(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("remedy-p7-task-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn run(b: &FakeScheduler, name: &str, op: Op, target: &str) -> (usize, usize, Vec<String>) {
    let rep = Executor::new(b, state(name))
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(name, vec![act(op, target)]))
        .expect("수행");
    let errs = rep
        .body
        .results
        .iter()
        .filter_map(|r| r.error.clone())
        .collect();
    (rep.done(), rep.failed(), errs)
}

#[test]
fn disabling_leaves_the_definition_in_place() {
    // `persistence.disable` 은 재기동 차단이지 제거가 아니다 (설계-03 §2 3단계).
    // 정의가 사라지면 뒤따르는 Action 들이 무엇을 지웠는지 사람이 알 수 없다.
    let b = FakeScheduler::with(ID, XML);
    let (done, failed, errs) = run(&b, "disable", Op::PersistenceDisable, ID);
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(b.enabled(ID), Some(false));
    assert_eq!(b.xml(ID).as_deref(), Some(XML));
    assert_eq!(*b.calls.borrow(), vec!["read", "disable"], "순서가 다르다");
}

#[test]
fn deleting_takes_the_registration_away() {
    let b = FakeScheduler::with(ID, XML);
    let (done, failed, errs) = run(&b, "delete", Op::PersistenceDelete, ID);
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert!(b.enabled(ID).is_none(), "등록이 남았다");
    assert_eq!(*b.calls.borrow(), vec!["read", "delete"], "순서가 다르다");
}

#[test]
fn the_definition_is_read_before_anything_changes() {
    // 정의를 담지 못하면 **아무것도 파괴하지 않는다** (설계-03 §5).
    let b = FakeScheduler::with(ID, XML);
    let e = Executor::new(&b, state("nobackup"))
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(
            "nobackup",
            vec![act(Op::PersistenceDelete, "\\없는\\작업")],
        ))
        .expect_err("백업이 실패해야 한다");
    assert!(e.to_string().contains("seq 1"), "{e}");
    assert!(b.enabled(ID).is_some(), "다른 작업이 지워졌다");
    assert_eq!(*b.calls.borrow(), vec!["read"], "읽기 뒤에 무언가를 했다");
}

#[test]
fn a_registration_path_that_climbs_out_never_reaches_the_scheduler() {
    // 등록 경로는 `%SystemRoot%\System32\Tasks\<id>` 로 풀린다. `..` 이 있으면
    // 그것은 임의 파일 읽기다. 검사는 **읽기보다 먼저**다.
    let b = FakeScheduler::with(ID, XML);
    let e = Executor::new(&b, state("climb"))
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(
            "climb",
            vec![act(Op::PersistenceDelete, "\\..\\..\\config\\SAM")],
        ))
        .expect_err("거부해야 한다");
    assert!(e.to_string().contains("'..'"), "{e}");
    assert_eq!(*b.calls.borrow(), vec!["read"], "스케줄러를 건드렸다");
    assert!(b.enabled(ID).is_some());
}

#[test]
fn a_task_already_gone_is_not_a_failure() {
    // 크래시가 파괴와 저널 기록 사이에 왔을 수 있다. 목표 상태는 이미
    // 이루어졌고, 그것을 실패로 올리면 무인 배포가 "부분 실패" 를 본다.
    //
    // 백업은 성공해야 하므로 정의는 읽히되 파괴 시점에는 없어야 한다 —
    // 읽은 뒤 사라지게 만든다.
    let b = FakeScheduler::with(ID, XML);
    let e = Executor::new(&b, state("gone"))
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of("gone", vec![act(Op::PersistenceDelete, ID)]));
    assert!(e.is_ok());
    // 두 번째 실행 — 이제 정말 없다. 백업 단계에서 멈춘다(파괴 전).
    let e2 = Executor::new(&b, state("gone2"))
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of("gone2", vec![act(Op::PersistenceDelete, ID)]))
        .expect_err("담을 것이 없다");
    assert!(e2.to_string().contains("그런 작업이 없다"), "{e2}");
}

#[test]
fn the_definition_that_was_captured_is_the_one_that_comes_back() {
    // 백업 → 파괴 → 복원 세 벌이 같은 것을 가리키는가 (G2).
    let b = FakeScheduler::with(ID, XML);
    let dir = state("roundtrip");
    let rep = Executor::new(&b, dir.clone())
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of("roundtrip", vec![act(Op::PersistenceDelete, ID)]))
        .expect("수행");
    assert!(b.enabled(ID).is_none());

    let container = rep.container.clone().expect("컨테이너");
    let bytes = remedy_core::restore::read_container(&container).expect("컨테이너");
    let sealed = remedy_core::restore::peek(&bytes).expect("헤더");
    let key = remedy_core::restore::unlock(
        &sealed.header,
        &remedy_core::restore::KeySource {
            state_dir: Some(dir.clone()),
            ..Default::default()
        },
    )
    .expect("풀기");
    let opened = sealed.unlock(&key).expect("열기");
    let plan = remedy_core::restore::plan(
        &opened,
        "roundtrip",
        &b,
        &remedy_core::restore::Guards {
            protected: &remedy_plan::Protected::new(
                remedy_sdk::catalog::Platform::Windows,
                remedy_plan::expand_env_for_protection,
            ),
            vouched: &remedy_core::restore::vouched(&dir, "roundtrip"),
        },
        &[],
        None,
    )
    .expect("복원 계획");
    for item in &plan.items {
        assert!(item.blocked.is_none(), "막혔다: {:?}", item.blocked);
        assert_eq!(item.dest, ID, "되돌릴 자리가 등록 경로가 아니다");
    }
    for o in remedy_core::restore::apply(&plan, &opened, &key, &b).expect("복원") {
        assert!(o.result.is_ok(), "{:?}", o.result);
    }
    assert_eq!(b.xml(ID).as_deref(), Some(XML), "정의가 달라졌다");
}

#[test]
fn a_container_pointing_somewhere_odd_is_blocked_before_restore() {
    // 컨테이너가 변조되면 **복원이 임의 경로 쓰기**가 된다. 헤더 AAD 가 변조를
    // 잡지만 탐지에만 기대지 않는다 (불변식 R).
    let b = FakeScheduler::with("\\a /Delete /TN \\b", XML);
    let dir = state("odd");
    // 계획 단계에서 이미 거부되므로 apply 는 성공하지 못한다 — 백업이 막힌다.
    let e = Executor::new(&b, dir)
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(
            "odd",
            vec![act(Op::PersistenceDelete, "\\a /Delete /TN \\b")],
        ))
        .expect_err("거부해야 한다");
    // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
    assert!(
        e.to_string()
            .contains(remedy_sdk::i18n::t("스위치", "switch")),
        "{e}"
    );
}

#[test]
fn each_platform_writes_through_its_live_backend() {
    // **이 자리는 같은 결함을 두 번 냈다.**
    //
    // 처음에는 Windows 에서 `FsRestore` 를 돌려주고 있었다 — 그 사이 P7 이
    // 들여온 레지스트리·예약 작업 Op 은 실제 머신에서 전부 `Unsupported` 로
    // 실패했을 것이고, 시험은 가짜 백엔드를 쓰기 때문에 전부 통과했다.
    //
    // 두 번째는 Linux 다. P12 순서 8 이 Linux 쓰기 백엔드를 세우면서
    // `default_backend()` 를 갱신하지 않았고, **이 시험이 `"fs"` 를 기대하도록
    // 적혀 있어 그 상태를 오히려 고정했다.** 게이트가 P12 로 올라 Linux Op
    // 14종이 열린 뒤에도 실제 바이너리는 파일 계열만 수행할 수 있었다 —
    // 실기기에서 `cert_store.remove` 를 처음 돌려 보고 드러났다.
    //
    // 감사 로그에 남는 백엔드 이름이 곧 "무엇이 시스템을 고쳤는가" 다.
    // 그것을 직접 잰다 — 파일 Op 만으로는 두 백엔드가 구분되지 않는다
    // (`Live` 가 그쪽은 `FsRestore` 에 위임한다).
    let name = remedy_core::restore::default_backend().backend_name();
    if cfg!(windows) {
        assert_eq!(name, "windows-live", "Windows 인데 라이브 백엔드가 아니다");
    } else if cfg!(target_os = "linux") {
        assert_eq!(name, "linux", "Linux 인데 라이브 백엔드가 아니다");
    } else {
        // 라이브 백엔드가 없는 플랫폼(macOS). `restore` 만 되고 `apply` 는
        // 되지 않는 상태이고, 그것이 이 플랫폼의 현재 사실이다.
        assert_eq!(name, "fs");
    }
}
