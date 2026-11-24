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

    fn persistence_exists(&self, id: &str, _at: Option<&remedy_platform::write::LineAt>) -> bool {
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

// ───────────────────────────────────── cron 줄 — 실제 crontab 으로 (Linux)

/// 한 crontab 의 나쁜 줄을 증거에서 계획하고, 이 플랫폼의 백엔드로 치료한 뒤 복원을 두 번 돌린다
/// (이슈 #166 ② ③ · 1.25.3 은 일부 실패 · `#` 줄이 남은 거짓 완료 · 같은 줄 두 번이었다).
///
/// 증거는 평가기가 내는 차례로 담는다 — 대상 id(`<파일>:<번호>`)의 문자열 순으로 `<룰>#<n>` 을 매기고
/// 그 id 의 문자열 순으로 세운다. 그래서 `:12` 가 `:3` 앞에 서는 경우(e)와 아닌 경우(a · b · d)가 함께
/// 든다. 계획은 가드까지 도는 `remedy_plan::plan` 으로 짓는다 — 임시 폴더의 cron 파일은 보호 목록 밖이고
/// 지속성은 `scan_roots` 상한을 받지 않으므로 가드가 막으면 그것이 이 시험의 실패다.
///
/// 룰이 둘인 경우(twice · twice-pair)는 나쁜 줄마다 두 룰이 함께 짚는다. 1.25.3 은 같은 줄의 끄기 · 지우기를 둘씩
/// 계획해, 둘째 지우기가 그 번호에 올라온 정상 줄을 보고 거부됐다(일부 실패). 계획이 한 칸으로 합친다.
#[cfg(target_os = "linux")]
#[test]
fn cron_lines_go_and_come_back_byte_for_byte() {
    // (이름, 줄 수, 나쁜 줄 번호, 룰)
    let cases: [(&str, usize, &[usize], &[&str]); 8] = [
        // 줄 하나짜리 파일 — 치료 뒤 빈 파일
        ("one", 1, &[1], &["cron"]),
        // 네 줄 중 셋째
        ("third", 4, &[3], &["cron"]),
        // 3 · 5번, 뒤에 정상 줄
        ("a", 6, &[3, 5], &["cron"]),
        // 3 · 5번, 5번이 마지막 줄
        ("b", 5, &[3, 5], &["cron"]),
        // 3 · 4번 붙음
        ("d", 5, &[3, 4], &["cron"]),
        // 13줄 중 3 · 12번 — 문자열 순으로는 :12 가 먼저
        ("e", 13, &[3, 12], &["cron"]),
        // 2번 줄을 두 룰이 짚고 3번이 정상 줄
        ("twice", 4, &[2], &["cron", "cron2"]),
        // 3 · 5번을 두 룰이 함께 짚는다
        ("twice-pair", 6, &[3, 5], &["cron", "cron2"]),
    ];
    let live = remedy_core::restore::default_backend();
    for (name, lines, bad, rules) in cases {
        let c = CronCase::new(name, lines, bad, rules);
        assert_eq!(
            c.plan.body.actions.len(),
            2 * bad.len(),
            "{name}: 줄마다 끄기 · 지우기 하나씩이어야 한다"
        );
        let rep = c.apply(&live);
        assert_eq!(
            (rep.done(), rep.failed()),
            (2 * bad.len(), 0),
            "{name}: {:?}",
            errors(&rep)
        );
        assert_eq!(
            c.read(),
            c.cleaned,
            "{name}: 치료 뒤 — 나쁜 줄만 빠지고 `#` 줄이 남지 않아야 한다"
        );
        c.restore_twice(&live, &rep);
    }
}

/// 수집 · 계획과 실행 사이에 crontab 이 짧아져 나쁜 줄(마지막 5번)이 한 줄 위로 올라온 기계. 계획의 번호는 이제
/// 파일 끝을 넘는다(이슈 #166 ③).
///
/// - 새로 도는 회차는 담기에서 멈춘다 — 그 번호의 줄을 읽지 못해 아무것도 바꾸지 않는다(종료 5).
/// - 담기를 마친 뒤 멈춘 회차를 이어 돌면 담기를 다시 하지 않는다. 1.25.3 은 그 자리에서 번호만 보고 *"이미
///   없다"* 로 끄기 · 지우기를 건너뛰어 2건 수행 · 종료 1 이었다 — 악성 줄은 주석도 없이 남았다. 이제 그 줄이 파일에
///   있으므로 끄기 · 지우기가 그 번호에서 계획의 줄을 찾지 못해 거부되고(실패 2건), 파일은 그대로다.
#[cfg(target_os = "linux")]
#[test]
fn a_cron_line_that_moved_before_the_run_is_not_reported_as_treated() {
    let live = remedy_core::restore::default_backend();
    let shift = |c: &CronCase| {
        let rest: String = c.read().split_inclusive('\n').skip(1).collect();
        std::fs::write(&c.file, rest).expect("crontab");
    };

    let fresh = CronCase::new("moved-fresh", 5, &[5], &["cron"]);
    shift(&fresh);
    let before = fresh.read();
    let e = Executor::new(&live, fresh.state_dir())
        .with_progress(&Silent)
        .with_clock("2026-11-24T00:00:00Z")
        .apply(&fresh.plan)
        .expect_err("담기에서 멈춰야 한다");
    assert!(
        matches!(e, remedy_apply::ApplyError::StoppedBeforeDestruction(_)),
        "{e}"
    );
    assert_eq!(fresh.read(), before);

    let c = CronCase::new("moved-resume", 5, &[5], &["cron"]);
    crash(&Crashy::new(&live, Die::BeforeDisable), &c);
    assert_eq!(c.read(), c.body, "죽기 전에 아무것도 바꾸지 않아야 한다");
    shift(&c);
    let moved = c.read();
    let rep = c.apply(&live);
    assert_eq!(rep.resumed, Some(remedy_apply::Resume::Continue), "{rep:?}");
    assert_eq!((rep.done(), rep.failed()), (0, 2), "{:?}", errors(&rep));
    assert_eq!(c.read(), moved, "올라온 나쁜 줄을 건드렸다");
}

/// 줄을 지운 **직후에** 죽고(저널에는 못 적었다) 이어 돈 회차 — 그 번호에 아래의 정상 줄이 올라와 있다. 1.25.3 은
/// 번호만 보고 *"있다"* 고 해 다시 지우러 갔다가 *"내용이 계획과 다릅니다"* 로 거짓 실패했다(이슈 #166 ③). 지운
/// 줄은 어디에도 없으므로 끝난 것이고, 복원은 처음 바이트로 돌아온다.
#[cfg(target_os = "linux")]
#[test]
fn a_crash_right_after_deleting_a_cron_line_is_not_a_false_failure() {
    let live = remedy_core::restore::default_backend();
    let c = CronCase::new("deleted-crash", 4, &[2], &["cron"]);
    crash(&Crashy::new(&live, Die::AfterDelete), &c);
    assert_eq!(c.read(), c.cleaned, "지운 뒤에 죽어야 한다");
    let rep = c.apply(&live);
    assert_eq!(rep.resumed, Some(remedy_apply::Resume::Continue), "{rep:?}");
    assert_eq!(rep.carried, 1, "끄기는 이전 시도가 끝냈다");
    assert_eq!((rep.done(), rep.failed()), (2, 0), "{:?}", errors(&rep));
    assert_eq!(c.read(), c.cleaned);
    c.restore_twice(&live, &rep);
}

/// 남는 한계를 못 박는다(`remedy-platform` 의 `persistence_exists` 문서) — 같은 내용의 나쁜 줄이 둘(3 · 5번)인 crontab
/// 에서 아래 줄을 지운 직후 죽고 이어 돈 회차. 위의 꺼진 같은 줄(`#…`)이 지운 줄을 *"있다"* 로 읽게 해, 그 지우기가 5번
/// 줄이 없다며 거부된다 — 파일은 치료된 채 일부 실패다(끄기 둘은 이전 시도가 끝냈다). 이 한계를 고치면 이 시험을
/// (4, 0) 으로 바꾼다. 복원은 처음 바이트로 돌아온다.
#[cfg(target_os = "linux")]
#[test]
fn a_crash_after_deleting_one_of_two_same_cron_lines_is_still_a_false_failure() {
    let live = remedy_core::restore::default_backend();
    let c = CronCase::same("same-crash", 5, &[3, 5], &["cron"]);
    crash(&Crashy::new(&live, Die::AfterDelete), &c);
    let rep = c.apply(&live);
    assert_eq!(rep.resumed, Some(remedy_apply::Resume::Continue), "{rep:?}");
    assert_eq!(rep.carried, 2, "끄기 둘은 이전 시도가 끝냈다");
    assert_eq!((rep.done(), rep.failed()), (3, 1), "{:?}", errors(&rep));
    assert_eq!(c.read(), c.cleaned);
    c.restore_twice(&live, &rep);
}

/// 검사 뒤 나쁜 줄이 **제자리에서** 고쳐진 기계 — 인자만 바뀐 같은 악성 줄이다. 계획의 줄은 이제 파일 어디에도 없지만
/// 그 번호에는 줄이 있다. 끄기가 그 줄과 견주어 거부하고(실패) 파일은 그대로다. *"어디에도 없으면 끝났다"* 로 끄기까지
/// 건너뛰면 끄기 · 지우기가 둘 다 '수행' 이 되어 고쳐진 악성 줄이 남은 채 치료 완료(종료 1)로 끝난다 — 번호만 보던
/// 1.25.3 은 이것을 실패로 알렸다. 새로 도는 회차와, 담기를 마친 뒤 멈춘 회차를 이어 도는 것을 함께 잰다. 새로 돈
/// 회차의 복원은 담은 줄(고쳐진 줄)이 그 번호에 그대로 있어 아무것도 넣지 않는다.
#[cfg(target_os = "linux")]
#[test]
fn a_cron_line_changed_in_place_is_not_reported_as_treated() {
    let live = remedy_core::restore::default_backend();
    let rewrite = |c: &CronCase| {
        let changed = c
            .read()
            .replace("/tmp/.cache/bad-2\n", "/tmp/.cache/bad-2 -k 2\n");
        assert_ne!(changed, c.read(), "{}: 줄을 고치지 못했다", c.name);
        std::fs::write(&c.file, &changed).expect("crontab");
        changed
    };

    let fresh = CronCase::new("changed-fresh", 3, &[2], &["cron"]);
    let changed = rewrite(&fresh);
    let rep = fresh.apply(&live);
    assert!(rep.failed() > 0, "고쳐진 줄을 치료했다고 한다: {rep:?}");
    assert_eq!(fresh.read(), changed, "고쳐진 줄을 건드렸다");
    fresh.restore_twice_to(&live, &rep, &changed);

    let c = CronCase::new("changed-resume", 3, &[2], &["cron"]);
    crash(&Crashy::new(&live, Die::BeforeDisable), &c);
    assert_eq!(c.read(), c.body, "죽기 전에 아무것도 바꾸지 않아야 한다");
    let changed = rewrite(&c);
    let rep = c.apply(&live);
    assert_eq!(rep.resumed, Some(remedy_apply::Resume::Continue), "{rep:?}");
    assert!(rep.failed() > 0, "고쳐진 줄을 치료했다고 한다: {rep:?}");
    assert_eq!(c.read(), changed, "고쳐진 줄을 건드렸다");
}

/// 조합형 한글(NFD)이 든 cron 줄. 수집기는 줄을 NFC 로 담으므로 계획의 줄과 파일의 줄은 바이트가 다르다. 대조가 양쪽을
/// NFC 로 맞추므로 그 줄을 끄고 지우며, 복원은 원래 바이트로 돌아온다. 맞추지 않으면 끄기는 그 번호의 줄과 견주어
/// 거부되고(1.25.3 과 같다), *"어디에도 없으면 끝났다"* 만 보면 끄기 · 지우기가 둘 다 건너뛰어진다.
#[cfg(target_os = "linux")]
#[test]
fn a_cron_line_with_decomposed_hangul_is_treated_and_comes_back() {
    let live = remedy_core::restore::default_backend();
    // '가' 를 자모 둘(U+1100 U+1161)로 — 셸 주석이라 명령은 같다.
    let c = CronCase::with_tail("nfd", 4, &[2], &["cron"], " # \u{1100}\u{1161}");
    assert_ne!(
        remedy_sdk::normalize::nfc(&c.body),
        c.body,
        "파일의 줄이 NFD 여야 한다"
    );
    let rep = c.apply(&live);
    assert_eq!((rep.done(), rep.failed()), (2, 0), "{:?}", errors(&rep));
    assert_eq!(c.read(), c.cleaned);
    c.restore_twice(&live, &rep);
}

/// 한 crontab 과 그 나쁜 줄들의 계획. 폴더는 떨어질 때 지운다.
#[cfg(target_os = "linux")]
struct CronCase {
    name: String,
    root: std::path::PathBuf,
    file: String,
    body: String,
    cleaned: String,
    plan: PlanEnvelope,
}

#[cfg(target_os = "linux")]
impl CronCase {
    /// `lines` 줄짜리 crontab 의 `bad` 번 줄을 `rules` 의 룰마다 증거로 담고 계획한다.
    fn new(name: &str, lines: usize, bad: &[usize], rules: &[&str]) -> Self {
        Self::with_tail(name, lines, bad, rules, "")
    }

    /// 나쁜 줄 끝에 `tail` 을 붙인다. 증거의 줄은 수집기처럼 NFC 로 담는다(`remedy-collect` 의 `cron.rs` 가
    /// `normalize::nfc(line.trim())` 을 싣는다) — 파일의 줄이 NFD 면 계획의 줄과 바이트가 다르다.
    fn with_tail(name: &str, lines: usize, bad: &[usize], rules: &[&str], tail: &str) -> Self {
        Self::build(name, lines, bad, rules, &|i| {
            format!("*/5 * * * * /tmp/.cache/bad-{i}{tail}")
        })
    }

    /// 나쁜 줄이 모두 같은 내용이다 — 번호만 다르다.
    fn same(name: &str, lines: usize, bad: &[usize], rules: &[&str]) -> Self {
        Self::build(name, lines, bad, rules, &|_| {
            "*/5 * * * * /tmp/.cache/bad-same".to_string()
        })
    }

    fn build(
        name: &str,
        lines: usize,
        bad: &[usize],
        rules: &[&str],
        bad_line: &dyn Fn(usize) -> String,
    ) -> Self {
        use remedy_sdk::artifact::{ArtifactKind, Evidence, EvidenceGroup, ScanBody};
        let root = state(&format!("cron-{name}"));
        std::fs::create_dir_all(&root).expect("작업 디렉터리");
        let file = root.join("root").to_string_lossy().to_string();
        let line = |i: usize| {
            if bad.contains(&i) {
                bad_line(i)
            } else {
                format!("{i} 4 * * * /usr/bin/ok-{i}")
            }
        };
        let body: String = (1..=lines).map(|i| line(i) + "\n").collect();
        let cleaned: String = (1..=lines)
            .filter(|i| !bad.contains(i))
            .map(|i| line(i) + "\n")
            .collect();
        std::fs::write(&file, &body).expect("crontab");

        let mut targets: Vec<(String, usize)> =
            bad.iter().map(|&i| (format!("{file}:{i}"), i)).collect();
        targets.sort();
        let mut evidence: Vec<Evidence> = Vec::new();
        for rule in rules {
            for (k, (id, i)) in targets.iter().enumerate() {
                evidence.push(Evidence {
                    id: format!("{rule}#{k}"),
                    rule: rule.to_string(),
                    subject: remedy_sdk::catalog::Subject::Persistence,
                    score: None,
                    target: serde_json::json!({
                        "id": id,
                        "source": file,
                        "linux": { "cron": {
                            "line_no": i,
                            "line": remedy_sdk::normalize::nfc(line(*i).trim())
                        } }
                    }),
                    captures: Default::default(),
                    matched: Vec::new(),
                    label: None,
                });
            }
        }
        evidence.sort_by(|a, b| a.id.cmp(&b.id));
        let ids: Vec<String> = evidence.iter().map(|e| e.id.clone()).collect();
        let scan = Envelope {
            schema_version: 1,
            kind: ArtifactKind::Scan,
            run_id: format!("cron-{name}"),
            created: "2026-11-24T00:00:00Z".into(),
            host: HostInfo {
                hostname: "T".into(),
                os: "linux".into(),
                version: "12".into(),
                arch: "amd64".into(),
            },
            core: CoreInfo {
                version: "0".into(),
                build: "dev".into(),
            },
            plugins: Vec::new(),
            body: ScanBody {
                evidence,
                groups: vec![EvidenceGroup {
                    id: "g0".into(),
                    evidence: ids,
                    captures: Default::default(),
                    verdict: true,
                    excluded_reason: None,
                }],
                verdicts: vec!["g0".into()],
                verdict_rules: Vec::new(),
                issues: Vec::new(),
                observation: Default::default(),
                scan_roots: vec![root.to_string_lossy().to_string()],
                removable_roots: Vec::new(),
            },
        };
        let detect: Vec<serde_json::Value> = rules
            .iter()
            .map(|rule| {
                serde_json::json!({"id": rule, "subject": "persistence",
                    "where": [{"field": "command", "op": "contains", "value": "bad-"}]})
            })
            .collect();
        let remove: Vec<serde_json::Value> = rules
            .iter()
            .map(|rule| serde_json::json!({ "ref": rule }))
            .collect();
        let manifest: remedy_sdk::manifest::PluginManifest =
            serde_json::from_value(serde_json::json!({
                "schema_version": 1, "id": "cron-lines", "version": "0.1.0", "min_core": "1.0.0",
                "platforms": ["linux"], "name": {"en": "cron lines"},
                "scan_roots": [root.to_string_lossy()], "subjects": ["persistence"],
                "detect": detect,
                "verdict": {"require": rules[0]},
                "remediate": {"remove": remove}
            }))
            .expect("매니페스트");
        let plan = remedy_plan::plan(&scan, Some(&manifest)).expect("계획");
        Self {
            name: name.to_string(),
            root,
            file,
            body,
            cleaned,
            plan,
        }
    }

    fn state_dir(&self) -> std::path::PathBuf {
        self.root.join("state")
    }

    fn read(&self) -> String {
        std::fs::read_to_string(&self.file).expect("읽기")
    }

    fn apply(&self, b: &dyn PlatformWrite) -> remedy_apply::Report {
        Executor::new(b, self.state_dir())
            .with_progress(&Silent)
            .with_clock("2026-11-24T00:00:00Z")
            .apply(&self.plan)
            .expect("치료")
    }

    /// 그 회차의 컨테이너를 통째로 두 번 되돌린다 — 두 번 다 처음 바이트여야 한다.
    fn restore_twice(&self, live: &dyn PlatformWrite, rep: &remedy_apply::Report) {
        self.restore_twice_to(live, rep, &self.body);
    }

    /// 그 회차의 컨테이너를 통째로 두 번 되돌린다 — 두 번 다 `want` 여야 한다.
    fn restore_twice_to(&self, live: &dyn PlatformWrite, rep: &remedy_apply::Report, want: &str) {
        let name = &self.name;
        let container = rep.container.clone().expect("컨테이너");
        let bytes = remedy_core::restore::read_container(&container).expect("컨테이너");
        let sealed = remedy_core::restore::peek(&bytes).expect("헤더");
        let key = remedy_core::restore::unlock(
            &sealed.header,
            &remedy_core::restore::KeySource {
                state_dir: Some(self.state_dir()),
                ..Default::default()
            },
        )
        .expect("풀기");
        let opened = sealed.unlock(&key).expect("열기");
        let restore = remedy_core::restore::plan(
            &opened,
            &self.plan.run_id,
            live,
            &remedy_core::restore::Guards {
                protected: &remedy_plan::Protected::new(
                    remedy_sdk::catalog::Platform::Linux,
                    remedy_plan::expand_env_for_protection,
                ),
                vouched: &remedy_core::restore::vouched(&self.state_dir(), &self.plan.run_id),
            },
            &[],
            None,
        )
        .expect("복원 계획");
        // 한 번, 그리고 다시 돌린 복원.
        for round in 1..=2 {
            for o in remedy_core::restore::apply(&restore, &opened, &key, live).expect("복원") {
                assert!(
                    o.result.is_ok(),
                    "{name} · {round}: {}: {:?}",
                    o.dest,
                    o.result
                );
            }
            assert_eq!(self.read(), want, "{name}: {round}번째 복원 뒤");
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for CronCase {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[cfg(target_os = "linux")]
fn errors(rep: &remedy_apply::Report) -> Vec<String> {
    rep.body
        .results
        .iter()
        .filter_map(|r| r.error.clone())
        .collect()
}

/// 어디서 죽는가.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Die {
    /// 처음 끄기를 부르기 **전** — 담기는 끝났고 아무것도 바뀌지 않았다.
    BeforeDisable,
    /// 처음 지우기가 끝난 **뒤** — 줄은 빠졌는데 저널에는 못 적었다.
    AfterDelete,
}

/// 라이브 백엔드를 그대로 부르다가 정한 자리에서 죽는다. `remedy-apply` 의 `execute.rs` 와 같은 수다 — 실행기
/// 한가운데서 패닉을 던지면 그때까지 fsync 된 저널과 컨테이너만 남고, 그것이 전원이 나간 뒤의 상태와 같다.
#[cfg(target_os = "linux")]
struct Crashy<'a> {
    live: &'a dyn PlatformWrite,
    die: Die,
}

#[cfg(target_os = "linux")]
impl<'a> Crashy<'a> {
    fn new(live: &'a dyn PlatformWrite, die: Die) -> Self {
        Self { live, die }
    }
}

#[cfg(target_os = "linux")]
impl PlatformWrite for Crashy<'_> {
    fn backend_name(&self) -> &'static str {
        "crashy"
    }
    fn plan_restore(&self, dest: &str, meta: &FileMeta) -> RestoreReport {
        self.live.plan_restore(dest, meta)
    }
    fn restore_file(
        &self,
        dest: &str,
        content: &[u8],
        meta: &FileMeta,
    ) -> Result<RestoreReport, PlatformError> {
        self.live.restore_file(dest, content, meta)
    }
    fn quarantine_read(&self, path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
        self.live.quarantine_read(path)
    }
    fn destroy_file(&self, path: &str) -> Result<(), PlatformError> {
        self.live.destroy_file(path)
    }
    fn exists(&self, path: &str) -> bool {
        self.live.exists(path)
    }
    fn persistence_read(
        &self,
        id: &str,
    ) -> Result<(Vec<u8>, remedy_platform::write::PersistenceIndex), PlatformError> {
        self.live.persistence_read(id)
    }
    fn persistence_exists(&self, id: &str, at: Option<&remedy_platform::write::LineAt>) -> bool {
        self.live.persistence_exists(id, at)
    }
    fn persistence_disable(
        &self,
        id: &str,
        at: Option<&remedy_platform::write::LineAt>,
    ) -> Result<(), PlatformError> {
        assert!(
            self.die != Die::BeforeDisable,
            "[시험] 끄기 직전에 전원이 나갔다고 친다"
        );
        self.live.persistence_disable(id, at)
    }
    fn persistence_delete(
        &self,
        id: &str,
        at: Option<&remedy_platform::write::LineAt>,
    ) -> Result<(), PlatformError> {
        let r = self.live.persistence_delete(id, at);
        assert!(
            self.die != Die::AfterDelete,
            "[시험] 지운 직후에 전원이 나갔다고 친다"
        );
        r
    }
}

/// 실행기를 돌리다 죽인다. 남은 것은 디스크에 fsync 된 저널과 컨테이너뿐이다.
#[cfg(target_os = "linux")]
fn crash(b: &Crashy<'_>, c: &CronCase) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.apply(b)));
    assert!(r.is_err(), "{}: 죽지 않았다 — 크래시 지점이 틀렸다", c.name);
}
