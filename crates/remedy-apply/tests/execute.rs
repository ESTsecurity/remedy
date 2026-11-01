//! 실행기 — **실제로 파일을 지운다.** 임시 디렉터리 안에서만 돈다.
//!
//! 여기서 재는 것의 절반은 **하지 않은 일**이다. 백업이 실패했을 때 원본이
//! 남아 있는가, 파괴 하나가 실패했을 때 나머지가 계속 갔는가, 계획에 없는 것을
//! 하지 않았는가.

use remedy_apply::{ApplyError, Executor, KeyPolicy, ScheduledVerify, VerifyRequest};
use remedy_platform::write::{
    FileMeta, FsRestore, PlatformWrite, RemovedBy, RestoreReport, VerifySite,
};
use remedy_sdk::artifact::{
    Action, ArtifactKind, CoreInfo, Envelope, HostInfo, Observation, PlanBody, PlanEnvelope,
};
use remedy_sdk::catalog::{Op, Risk};
use std::path::PathBuf;

struct Lab {
    dir: PathBuf,
}

impl Lab {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("remedy-apply-it-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }
    fn file(&self, name: &str, body: &[u8]) -> String {
        let p = self.dir.join(name);
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().to_string()
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

fn action(seq: u32, target: &str) -> Action {
    Action {
        seq,
        op: Op::FileQuarantineOnly,
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
        because: vec!["payload#0".into()],
        backup: None,
        reversible: true,
        risk: Risk::Low,
        user_impact: None,
    }
}

fn plan(actions: Vec<Action>) -> PlanEnvelope {
    Envelope {
        schema_version: 1,
        kind: ArtifactKind::Plan,
        run_id: "run-test".into(),
        created: "2026-08-21T00:00:00Z".into(),
        host: HostInfo {
            hostname: "h".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        core: CoreInfo {
            version: "0".into(),
            build: "d".into(),
        },
        plugins: Vec::new(),
        body: PlanBody {
            actions,
            verdicts: vec!["g0".into()],
            observation: Observation::default(),
            deferred: Vec::new(),
            verify_after_reboot: false,
            submit_hint: None,
        },
    }
}

#[test]
fn a_file_is_quarantined_and_the_original_is_gone() {
    let lab = Lab::new("basic");
    let body = b"payload bytes".to_vec();
    let target = lab.file("evil.exe", &body);

    let ex = Executor::new(&FsRestore, lab.state());
    let r = ex.apply(&plan(vec![action(1, &target)])).expect("수행");

    assert_eq!(r.done(), 1, "{:?}", r.body.results);
    assert!(
        !std::path::Path::new(&target).exists(),
        "원본이 남아 있다 — 격리는 옮기는 것이다"
    );

    // 컨테이너에 바이트가 그대로 있어야 한다. 이것이 성립하지 않으면 이 도구가
    // 존재하는 이유가 무너진다.
    let path = r.container.expect("컨테이너");
    let bytes = std::fs::read(&path).unwrap();
    let sealed = remedy_quarantine::Sealed::parse(&bytes).unwrap();
    let mk =
        remedy_quarantine::MachineKey::load_or_create(&lab.state().join("machine.key")).unwrap();
    let key = mk.unwrap(&sealed.header.wraps[0]).unwrap();
    let opened = sealed.unlock(&key).unwrap();
    assert_eq!(opened.read("e0", &key).unwrap().content, body);
}

#[test]
fn the_backup_lands_on_disk_before_anything_is_destroyed() {
    // **순서가 전부다.** 백업이 메모리에만 있는 상태에서 파괴가 시작되면
    // 크래시 한 번에 원본이 사라진다.
    //
    // 백업을 일부러 실패시키고(대상 하나가 없다) 나머지 원본이 **살아 있는지**
    // 본다. 항목마다 "백업하고 지우고" 를 반복했다면 앞의 것은 이미 사라진다.
    let lab = Lab::new("order");
    let alive = lab.file("first.exe", b"still here");
    let missing = lab.dir.join("없는파일.exe").to_string_lossy().to_string();

    let ex = Executor::new(&FsRestore, lab.state());
    let err = ex
        .apply(&plan(vec![action(1, &alive), action(2, &missing)]))
        .expect_err("백업이 실패해야 한다");

    assert!(
        matches!(err, ApplyError::StoppedBeforeDestruction(_)),
        "{err:?}"
    );
    assert!(
        std::path::Path::new(&alive).exists(),
        "백업이 실패했는데 앞의 원본이 사라졌다 — 백업과 파괴가 섞여 돌았다"
    );
    assert_eq!(
        err.exit_code(),
        remedy_sdk::artifact::ExitCode::GuardStop,
        "백업 전 중단은 가드가 막은 것이다"
    );
}

#[test]
fn a_destruction_failure_does_not_roll_back_the_rest() {
    // 로더는 지워졌고 페이로드 삭제가 실패했다면, 롤백하면 **로더가 복원되어
    // 위협이 재무장된다** (설계-03 §5). 나머지를 계속 수행한다.
    struct FlakyOnSecond;
    impl PlatformWrite for FlakyOnSecond {
        fn backend_name(&self) -> &'static str {
            "flaky"
        }
        fn plan_restore(&self, d: &str, m: &FileMeta) -> RestoreReport {
            FsRestore.plan_restore(d, m)
        }
        fn restore_file(
            &self,
            d: &str,
            c: &[u8],
            m: &FileMeta,
        ) -> Result<RestoreReport, remedy_platform::PlatformError> {
            FsRestore.restore_file(d, c, m)
        }
        fn quarantine_read(
            &self,
            p: &str,
        ) -> Result<(Vec<u8>, FileMeta), remedy_platform::PlatformError> {
            FsRestore.quarantine_read(p)
        }
        fn destroy_file(&self, p: &str) -> Result<(), remedy_platform::PlatformError> {
            if p.contains("두번째") {
                return Err(remedy_platform::PlatformError::Unsupported("일부러 실패"));
            }
            FsRestore.destroy_file(p)
        }
        fn exists(&self, p: &str) -> bool {
            FsRestore.exists(p)
        }
    }

    let lab = Lab::new("noroll");
    let a = lab.file("첫번째.exe", b"one");
    let b = lab.file("두번째.exe", b"two");
    let c = lab.file("세번째.exe", b"three");

    let ex = Executor::new(&FlakyOnSecond, lab.state());
    let r = ex
        .apply(&plan(vec![action(1, &a), action(2, &b), action(3, &c)]))
        .expect("실패해도 계획은 끝까지 간다");

    assert_eq!(r.done(), 2, "{:?}", r.body.results);
    assert_eq!(r.failed(), 1);
    assert!(!std::path::Path::new(&a).exists(), "1번이 안 지워졌다");
    assert!(std::path::Path::new(&b).exists(), "실패한 2번이 지워졌다");
    assert!(
        !std::path::Path::new(&c).exists(),
        "2번이 실패했다고 3번을 멈췄다 — 나머지를 계속해야 한다"
    );

    // 그리고 **되돌리지 않았다.** 1번이 다시 살아나면 위협이 재무장된다.
    assert!(!std::path::Path::new(&a).exists());
}

#[test]
fn the_journal_records_intent_backup_and_outcome_in_that_order() {
    use remedy_journal::{Journal, Record};
    let lab = Lab::new("journal");
    let target = lab.file("evil.exe", b"x");

    let ex = Executor::new(&FsRestore, lab.state());
    let r = ex.apply(&plan(vec![action(1, &target)])).expect("수행");

    let reading = Journal::read(&r.journal).expect("저널");
    assert!(reading.finished(), "End 가 없다");
    assert!(!reading.truncated);

    let kinds: Vec<&str> = reading
        .records
        .iter()
        .map(|x| match x {
            Record::Start { .. } => "start",
            Record::Intent { .. } => "intent",
            Record::Backup { .. } => "backup",
            Record::Outcome { .. } => "outcome",
            Record::End { .. } => "end",
            Record::Resumed { .. } => "resumed",
            // Action 에 붙지 않는 사실. 이 계획에는 고위험 Op 이 없어
            // 복원 지점을 시도하지 않으므로 나오지 않는다.
            Record::Note { .. } => "note",
            // 재부팅 뒤 재검사 — 이 계획은 원하지 않으므로 나오지 않는다.
            Record::VerifyScheduled { .. } => "verify_scheduled",
            Record::VerifyNotScheduled { .. } => "verify_not_scheduled",
        })
        .collect();
    assert_eq!(
        kinds,
        vec!["start", "intent", "backup", "outcome", "end"],
        "설계-03 §5 의 순서다: intent -> backup -> outcome"
    );
    assert!(reading.undecided().is_empty(), "미결 항목이 남았다");
}

#[test]
fn nothing_is_backed_up_when_the_plan_is_empty() {
    let lab = Lab::new("empty");
    let ex = Executor::new(&FsRestore, lab.state());
    let r = ex.apply(&plan(Vec::new())).expect("빈 계획도 유효하다");
    assert!(r.container.is_none(), "빈 계획이 컨테이너를 만들었다");
    assert_eq!(r.done(), 0);
}

#[test]
fn an_op_whose_backup_kind_we_cannot_capture_stops_before_destruction() {
    // **백업할 수 없으면 파괴하지 않는다** (설계-03 §5). 담을 방법이 없는
    // 종류라면 그 사실을 파괴 전에 알아야 하고, 그때 답은 "아무것도 하지
    // 않았다" 다 — 실패 하나로 세고 넘어가면 그 Action 은 되돌릴 수 없는
    // 파괴가 될 수 있다.
    let lab = Lab::new("nocapture");
    let target = lab.file("cert.dat", b"x");
    let mut a = action(1, &target);
    a.op = Op::CertStoreRemove; // 백업 종류가 `cert_store` 하나뿐이다.

    let ex = Executor::new(&FsRestore, lab.state());
    let e = ex
        .apply(&plan(vec![a]))
        .expect_err("담을 수 없으면 멈춰야 한다");
    assert!(
        matches!(e, ApplyError::StoppedBeforeDestruction(_)),
        "{e:?}"
    );
    assert!(
        std::path::Path::new(&target).exists(),
        "멈췄다면서 파일이 사라졌다"
    );
}

#[test]
fn an_op_this_core_will_not_perform_destroys_nothing() {
    // 실행기는 **계획을 믿지 않는다.** 손으로 고친 plan.json 이 들어올 수 있다.
    //
    // 이 시험은 원래 "아직 구현되지 않은 Op" 을 썼다. P8 이 마지막 Op 을
    // 채우면서 그런 Op 이 없어졌고, `ApplyError::UnsupportedOp` 도 함께
    // 사라졌다. 남은 성질은 이것이다 — **코어가 하지 않기로 한 것을 계획이
    // 지시하면 아무것도 파괴되지 않는다.**
    //
    // `dir.delete_recursive` 가 그 자리다. 구현은 끝났지만 안에 신뢰 서명된
    // 파일이 있는지 확인할 수단이 없어 거부된다 (설계-09 P8).
    let lab = Lab::new("refused");
    let target = lab.file("x.dat", b"x");
    let mut a = action(1, &target);
    a.op = Op::DirDeleteRecursive;
    // 계획기는 언제나 상한을 각인한다. 그것이 없으면 **다른 이유로** 거부되어
    // 이 시험이 재려던 것(서명 확인 수단 없음)을 못 잰다.
    a.max_children = Some(500);
    a.max_depth = Some(8);

    let ex = Executor::new(&FsRestore, lab.state());
    let e = ex.apply(&plan(vec![a])).expect_err("거부해야 한다");
    // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
    assert!(
        e.to_string()
            .contains(remedy_sdk::i18n::t("서명", "signatures")),
        "{e}"
    );
    assert!(
        std::path::Path::new(&target).exists(),
        "거부했는데 파일이 사라졌다"
    );
}

#[test]
fn a_plan_envelope_is_required() {
    let lab = Lab::new("envelope");
    let mut p = plan(Vec::new());
    p.kind = ArtifactKind::Scan;
    let ex = Executor::new(&FsRestore, lab.state());
    assert!(matches!(ex.apply(&p), Err(ApplyError::NotAPlan(_))));
}

#[test]
fn extra_wraps_make_the_container_openable_elsewhere() {
    // 로컬 wrap 뿐이면 머신을 재설치하는 순간 열 수 없다 (설계-03 §5).
    let lab = Lab::new("wraps");
    let target = lab.file("evil.exe", b"secret");
    let (org_sk, org_pk) = remedy_quarantine::generate_org_keypair().unwrap();

    let ex = Executor::new(&FsRestore, lab.state()).with_keys(KeyPolicy {
        passphrase: Some("복구 암호".into()),
        org_public: Some(org_pk),
    });
    let r = ex.apply(&plan(vec![action(1, &target)])).expect("수행");

    let bytes = std::fs::read(r.container.unwrap()).unwrap();
    let sealed = remedy_quarantine::Sealed::parse(&bytes).unwrap();
    assert_eq!(sealed.header.wraps.len(), 3);
    assert!(!sealed.header.only_local_wrap());

    // 다른 머신이라 가정 — 조직 키로 연다.
    let org_slot = sealed
        .header
        .wraps
        .iter()
        .find(|w| w.kind == remedy_quarantine::WrapKind::Org)
        .unwrap();
    let key = remedy_quarantine::unwrap_with_org_key(&org_sk, org_slot).unwrap();
    let opened = sealed.unlock(&key).unwrap();
    assert_eq!(opened.read("e0", &key).unwrap().content, b"secret");
}

#[test]
fn a_readonly_file_is_still_removed() {
    // 악성코드가 제거를 방해하려고 읽기 전용을 거는 것은 흔한 수법이다.
    //
    // 이 성질은 우리 코드가 아니라 `std::fs::remove_file` 이 준다 — Windows 에서
    // `FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE` 를 쓴다. 그래도 시험으로
    // 고정한다. 우리가 그것에 기대고 있다는 사실이 여기 적혀 있어야, 언젠가
    // 그 동작이 바뀌면 여기서 걸린다.
    let lab = Lab::new("readonly");
    let target = lab.file("locked.exe", b"locked");
    let mut perm = std::fs::metadata(&target).unwrap().permissions();
    perm.set_readonly(true);
    std::fs::set_permissions(&target, perm).unwrap();

    let ex = Executor::new(&FsRestore, lab.state());
    let r = ex.apply(&plan(vec![action(1, &target)])).expect("수행");
    assert_eq!(r.done(), 1, "{:?}", r.body.results);
    assert!(!std::path::Path::new(&target).exists());
}

// ──────────────────────────────────────────── 크래시 뒤 이어서 수행 (P6)
//
// **크래시를 흉내 내지 않고 진짜로 낸다.** 실행기 한가운데서 패닉을 던지면
// 그때까지 fsync 된 저널만 디스크에 남는데, 그것이 전원이 나간 뒤의 상태와
// 같다. 저널을 손으로 지어내면 실행기가 실제로 남기는 것과 어긋날 수 있고,
// 그러면 시험은 통과하는데 진짜 크래시는 못 살린다.

/// N번째 파괴 **직후에** 죽는다 — 파일은 사라졌는데 저널에는 못 적힌 상태.
struct DiesAfterDestroying {
    done: std::cell::Cell<usize>,
    at: usize,
}

/// N번째 백업 **읽기에서** 죽는다 — 아직 아무것도 파괴되지 않은 상태.
struct DiesWhileBackingUp {
    read: std::cell::Cell<usize>,
    at: usize,
}

macro_rules! passthrough {
    () => {
        fn backend_name(&self) -> &'static str {
            "crashy"
        }
        fn plan_restore(&self, d: &str, m: &FileMeta) -> RestoreReport {
            FsRestore.plan_restore(d, m)
        }
        fn restore_file(
            &self,
            d: &str,
            c: &[u8],
            m: &FileMeta,
        ) -> Result<RestoreReport, remedy_platform::PlatformError> {
            FsRestore.restore_file(d, c, m)
        }
        fn exists(&self, p: &str) -> bool {
            FsRestore.exists(p)
        }
    };
}

impl PlatformWrite for DiesAfterDestroying {
    passthrough!();
    fn quarantine_read(
        &self,
        p: &str,
    ) -> Result<(Vec<u8>, FileMeta), remedy_platform::PlatformError> {
        FsRestore.quarantine_read(p)
    }
    fn destroy_file(&self, p: &str) -> Result<(), remedy_platform::PlatformError> {
        let n = self.done.get() + 1;
        self.done.set(n);
        let r = FsRestore.destroy_file(p);
        assert!(n != self.at, "[시험] 여기서 전원이 나갔다고 친다");
        r
    }
}

impl PlatformWrite for DiesWhileBackingUp {
    passthrough!();
    fn quarantine_read(
        &self,
        p: &str,
    ) -> Result<(Vec<u8>, FileMeta), remedy_platform::PlatformError> {
        let n = self.read.get() + 1;
        self.read.set(n);
        assert!(n != self.at, "[시험] 여기서 전원이 나갔다고 친다");
        FsRestore.quarantine_read(p)
    }
    fn destroy_file(&self, p: &str) -> Result<(), remedy_platform::PlatformError> {
        FsRestore.destroy_file(p)
    }
}

/// 실행기를 돌리다 죽인다. 남은 것은 디스크에 fsync 된 저널과 컨테이너뿐이다.
fn crash(backend: &dyn PlatformWrite, state: &std::path::Path, p: &PlanEnvelope) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Executor::new(backend, state).apply(p)
    }));
    assert!(r.is_err(), "죽지 않았다 — 크래시 지점이 틀렸다");
}

fn gone(p: &str) -> bool {
    !std::path::Path::new(p).exists()
}

#[test]
fn a_crash_between_destroying_and_recording_does_not_become_a_false_failure() {
    // **가장 고약한 자리다.** 파일은 이미 사라졌는데 저널은 그것을 모른다.
    // 그대로 다시 지우러 가면 "없는 파일" 오류가 나고 실패로 기록되는데,
    // 실제로는 성공한 것이다. 무인 배포는 종료 코드만 보므로 그 거짓 실패가
    // 그대로 "부분 실패" 로 올라간다.
    let lab = Lab::new("resume-mid");
    let (a, b, c) = (
        lab.file("1.exe", b"one"),
        lab.file("2.exe", b"two"),
        lab.file("3.exe", b"three"),
    );
    let p = plan(vec![action(1, &a), action(2, &b), action(3, &c)]);

    crash(
        &DiesAfterDestroying {
            done: 0.into(),
            at: 2,
        },
        &lab.state(),
        &p,
    );
    assert!(gone(&a) && gone(&b), "2번째까지는 지워진 뒤에 죽어야 한다");
    assert!(!gone(&c), "3번째는 아직이다");

    // 다시 부른다 — 재기동이다.
    let r = Executor::new(&FsRestore, lab.state())
        .with_clock("2026-08-21T01:00:00Z")
        .apply(&p)
        .expect("이어서 수행해야 한다");

    assert_eq!(r.resumed, Some(remedy_apply::Resume::Continue), "{r:?}");
    assert_eq!(r.carried, 1, "1번은 이전 시도가 끝냈다");
    assert_eq!(
        r.failed(),
        0,
        "이미 지운 것을 실패로 셌다: {:?}",
        r.body.results
    );
    assert_eq!(r.done(), 3, "결과는 run 전체를 담아야 한다");
    assert!(gone(&c), "3번이 안 지워졌다");

    // **격리소는 이전 시도가 만든 것 그대로다.** 다시 만들었다면 이미 지워진
    // 1·2번의 원본이 들어갈 수 없으므로 복원이 불가능해진다.
    let bytes = std::fs::read(r.container.as_ref().unwrap()).unwrap();
    let sealed = remedy_quarantine::Sealed::parse(&bytes).unwrap();
    let mk =
        remedy_quarantine::MachineKey::load_or_create(&lab.state().join("machine.key")).unwrap();
    let key = mk.unwrap(&sealed.header.wraps[0]).unwrap();
    let opened = sealed.unlock(&key).unwrap();
    for (i, body) in [b"one".as_slice(), b"two", b"three"].iter().enumerate() {
        let e = opened.read(&format!("e{i}"), &key).unwrap();
        assert_eq!(&e.content, body, "e{i} 의 원본이 다르다");
    }
}

#[test]
fn a_crash_during_backup_destroys_nothing_so_the_backup_runs_again() {
    // `Resume::Restart` 의 전제다 — **모든 `Backup` 이 적힌 뒤에야 첫 파괴가
    // 시작된다.** 그래서 백업이 모자란 저널은 "아직 아무것도 파괴되지 않았다"
    // 를 뜻하고, 백업 단계를 통째로 다시 돌아도 안전하다.
    let lab = Lab::new("resume-backup");
    let (a, b) = (lab.file("1.exe", b"one"), lab.file("2.exe", b"two"));
    let p = plan(vec![action(1, &a), action(2, &b)]);

    crash(
        &DiesWhileBackingUp {
            read: 0.into(),
            at: 2,
        },
        &lab.state(),
        &p,
    );
    assert!(
        !gone(&a) && !gone(&b),
        "백업 도중에 죽었는데 원본이 사라졌다 — 백업과 파괴가 섞여 돌았다"
    );

    let r = Executor::new(&FsRestore, lab.state())
        .with_clock("2026-08-21T01:00:00Z")
        .apply(&p)
        .expect("처음부터 다시 돌아야 한다");
    assert_eq!(r.resumed, Some(remedy_apply::Resume::Restart), "{r:?}");
    assert_eq!(r.carried, 0, "끝난 것이 없었다");
    assert_eq!(r.done(), 2);
    assert!(gone(&a) && gone(&b));
}

#[test]
fn the_resumed_journal_reads_to_the_end_even_when_the_crash_cut_a_line() {
    // 크래시는 쓰기 도중에 온다. 잘린 꼬리를 잘라 내지 않고 이어 쓰면 이어 쓴
    // 첫 줄이 거기 붙어 한 줄로 깨지고, **이어서 수행한 기록이 통째로
    // 읽히지 않는다.** 저널이 있는데 아무것도 모르는 상태가 된다.
    use remedy_journal::{Journal, Record};
    let lab = Lab::new("resume-torn");
    let (a, b) = (lab.file("1.exe", b"one"), lab.file("2.exe", b"two"));
    let p = plan(vec![action(1, &a), action(2, &b)]);

    crash(
        &DiesAfterDestroying {
            done: 0.into(),
            at: 2,
        },
        &lab.state(),
        &p,
    );

    // fsync 중에 전원이 나가면 이런 꼬리가 남는다.
    let jpath = remedy_journal::journal_path(&lab.state(), &p.run_id);
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&jpath)
            .unwrap();
        f.write_all(br#"{"rec":"outcome","seq":2,"out"#).unwrap();
    }
    assert!(Journal::read(&jpath).unwrap().truncated);

    let r = Executor::new(&FsRestore, lab.state())
        .apply(&p)
        .expect("이어서 수행해야 한다");
    assert_eq!(r.done(), 2, "{:?}", r.body.results);

    let after = Journal::read(&jpath).unwrap();
    assert!(!after.truncated, "잘린 흔적이 남았다");
    assert!(after.finished(), "이어 쓴 end 가 읽히지 않는다");
    assert!(
        after
            .records
            .iter()
            .any(|x| matches!(x, Record::Resumed { .. })),
        "이어받았다는 표시가 없다"
    );
    assert!(after.undecided().is_empty(), "{:?}", after.undecided());
}

#[test]
fn a_crash_before_the_intents_were_written_still_leaves_a_readable_audit_log() {
    // 크래시가 `Start` 와 첫 `Intent` 사이에 오면 저널은 **무엇을 하려던
    // 참이었는가**를 말하지 못한다. 이어받은 실행이 그것을 채우지 않으면 이 run
    // 의 감사 로그에는 계획이 통째로 빠진다 (설계-03 §7).
    use remedy_journal::{Journal, Record};
    let lab = Lab::new("resume-nointent");
    let (a, b) = (lab.file("1.exe", b"one"), lab.file("2.exe", b"two"));
    let p = plan(vec![action(1, &a), action(2, &b)]);

    // 백업 첫 줄에서 죽여 Start + Intent 만 남긴 뒤, Start 한 줄만 남기고 자른다.
    // fsync 도중에 전원이 나가면 나오는 모양이다.
    crash(
        &DiesWhileBackingUp {
            read: 0.into(),
            at: 1,
        },
        &lab.state(),
        &p,
    );
    let jpath = remedy_journal::journal_path(&lab.state(), &p.run_id);
    let text = std::fs::read_to_string(&jpath).unwrap();
    let first = text.lines().next().unwrap().to_string();
    std::fs::write(&jpath, format!("{first}\n")).unwrap();
    assert!(Journal::read(&jpath).unwrap().intended().is_empty());

    let r = Executor::new(&FsRestore, lab.state())
        .apply(&p)
        .expect("이어서 수행해야 한다");
    assert_eq!(r.done(), 2, "{:?}", r.body.results);

    let after = Journal::read(&jpath).unwrap();
    let intents: Vec<u32> = after.intended().into_iter().collect();
    assert_eq!(intents, vec![1, 2], "하려던 일이 저널에 없다");
    assert!(after
        .records
        .iter()
        .any(|x| matches!(x, Record::Resumed { .. })));
}

#[test]
fn resuming_does_not_rewrite_intents_that_are_already_there() {
    // 400건짜리 계획을 이어받을 때마다 400번을 다시 fsync 하는 것은 그저
    // 느려지는 일이다. 그리고 감사 로그가 두 배로 불어난다.
    use remedy_journal::{Journal, Record};
    let lab = Lab::new("resume-nodup");
    let (a, b) = (lab.file("1.exe", b"one"), lab.file("2.exe", b"two"));
    let p = plan(vec![action(1, &a), action(2, &b)]);

    crash(
        &DiesAfterDestroying {
            done: 0.into(),
            at: 1,
        },
        &lab.state(),
        &p,
    );
    Executor::new(&FsRestore, lab.state())
        .apply(&p)
        .expect("이어서 수행");

    let jpath = remedy_journal::journal_path(&lab.state(), &p.run_id);
    let n = Journal::read(&jpath)
        .unwrap()
        .records
        .iter()
        .filter(|x| matches!(x, Record::Intent { .. }))
        .count();
    assert_eq!(n, 2, "Intent 가 {n}줄이다 — 이미 적힌 것을 다시 적었다");
}

#[test]
fn a_finished_run_is_not_applied_twice() {
    // 두 번 수행하면 격리소를 새 키로 덮어써 **이전 원본을 영영 못 연다.**
    let lab = Lab::new("resume-done");
    let target = lab.file("evil.exe", b"x");
    let p = plan(vec![action(1, &target)]);

    let ex = Executor::new(&FsRestore, lab.state());
    ex.apply(&p).expect("첫 수행");
    let err = ex.apply(&p).expect_err("두 번째는 막아야 한다");

    assert!(matches!(err, ApplyError::AlreadyApplied(_)), "{err:?}");
    assert_eq!(err.exit_code(), remedy_sdk::artifact::ExitCode::GuardStop);
}

#[test]
fn a_different_plan_cannot_take_over_the_same_run() {
    // run_id 는 같은데 내용이 다르면, 이어서 수행한 결과는 **사용자가 승인한
    // 어느 계획과도 다른 것**이 된다.
    let lab = Lab::new("resume-other");
    let (a, b) = (lab.file("1.exe", b"one"), lab.file("2.exe", b"two"));
    let mine = plan(vec![action(1, &a), action(2, &b)]);

    crash(
        &DiesAfterDestroying {
            done: 0.into(),
            at: 2,
        },
        &lab.state(),
        &mine,
    );

    let c = lab.file("3.exe", b"three");
    let mut other = mine.clone();
    other.body.actions.push(action(3, &c));

    let err = Executor::new(&FsRestore, lab.state())
        .apply(&other)
        .expect_err("다른 계획으로 이어받으면 안 된다");
    assert!(matches!(err, ApplyError::PlanChanged(_)), "{err:?}");
    assert_eq!(err.exit_code(), remedy_sdk::artifact::ExitCode::GuardStop);
    assert!(!gone(&c), "막았는데 새 계획의 대상이 사라졌다");
}

#[test]
fn resuming_without_the_container_stops_before_destroying_anything_more() {
    // 저널은 백업이 끝났다는데 격리소가 없다. 그 상태로 이어서 파괴하면
    // **되돌릴 길이 없다.**
    let lab = Lab::new("resume-nocontainer");
    let (a, b, c) = (
        lab.file("1.exe", b"one"),
        lab.file("2.exe", b"two"),
        lab.file("3.exe", b"three"),
    );
    let p = plan(vec![action(1, &a), action(2, &b), action(3, &c)]);

    crash(
        &DiesAfterDestroying {
            done: 0.into(),
            at: 2,
        },
        &lab.state(),
        &p,
    );
    std::fs::remove_file(lab.state().join("quarantine").join("run-test.rq")).unwrap();

    let err = Executor::new(&FsRestore, lab.state())
        .apply(&p)
        .expect_err("격리소 없이 이어서 파괴하면 안 된다");
    assert!(
        matches!(err, ApplyError::ContainerMissing { .. }),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), remedy_sdk::artifact::ExitCode::GuardStop);
    assert!(!gone(&c), "막았는데 남은 대상이 사라졌다");
}

#[test]
fn actions_are_performed_in_the_order_the_plan_lists_them() {
    // **순서는 계획이 정한다** (설계-03 §2). 계획기가 단계로 정렬해 `seq` 를
    // 1부터 다시 매기지만, 실행기가 보는 것은 배열의 순서다 — `seq` 로 다시
    // 정렬하면 손으로 고친 계획이 승인 화면과 다른 순서로 돌게 된다.
    //
    // 이 성질을 **VM 하네스에서 재려 했었다.** 그런데 하네스가 계획을 손으로
    // 쓰면서 순서를 이미 정해 놓으므로, 거기서 재는 것은 결국 이것뿐이었다.
    // 실기기가 필요 없는 성질은 여기 있는 편이 낫다 — 하네스는 "환경이 정말
    // 되살리는가" 를 재는 자리다.
    use remedy_journal::{Journal, Record};
    // **이름이 겹치면 안 된다.** `Lab` 은 이름으로 임시 디렉터리를 잡고
    // 시험은 병렬로 돈다 — 처음엔 `order` 로 지었다가 위의
    // `the_backup_lands_on_disk_before_anything_is_destroyed` 와 같은
    // 디렉터리를 써서 저널이 지워졌다. 단독 실행에서는 통과했다.
    let lab = Lab::new("plan-order");
    let a = lab.file("첫.exe", b"1");
    let b = lab.file("둘.exe", b"2");
    let c = lab.file("셋.exe", b"3");

    // 배열 순서와 `seq` 순서를 **일부러 어긋나게** 둔다. 그러지 않으면 어느
    // 것을 따르는지 이 시험이 가리지 못한다.
    let plan = plan(vec![action(3, &c), action(1, &a), action(2, &b)]);
    let r = Executor::new(&FsRestore, lab.state())
        .apply(&plan)
        .expect("수행");
    assert_eq!(r.done(), 3, "{:?}", r.body.results);

    let reading = Journal::read(&r.journal).expect("저널");
    let order: Vec<u32> = reading
        .records
        .iter()
        .filter_map(|x| match x {
            Record::Outcome { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect();
    assert_eq!(
        order,
        vec![3, 1, 2],
        "배열 순서가 아니라 다른 순서로 돌았다"
    );
}

/// **어떤 바이너리가 이 기계를 고쳤는가**가 저널에 남는다.
///
/// 2026-09-02 에 서명 없는 배포 빌드도 파괴를 하게 됐다. 통제를 하나 뺐으면
/// 흔적은 남겨야 한다 — 그 전까지 이 사실은 `support-bundle` 에만 있었고,
/// 그것은 **지금** 그 자리에 있는 파일을 재므로 나중에 바이너리가 바뀌면
/// 치료 당시와 다른 값을 보고한다.
///
/// 검사는 판단하지 않는다. 값은 `remedy-core` 가 시작할 때 한 번 재서
/// 넘겨준 것이고, 이 크레이트는 받아 적을 뿐이다.
#[test]
fn the_journal_says_which_binary_did_the_work() {
    use remedy_journal::{Journal, Record};
    let lab = Lab::new("integrity-in-journal");
    let target = lab.file("payload.exe", b"x");
    let ex = Executor::new(&FsRestore, lab.state()).with_self_integrity("unsigned");
    let r = ex.apply(&plan(vec![action(1, &target)])).expect("수행");

    let reading = Journal::read(&r.journal).expect("저널");
    let got = reading.records.iter().find_map(|x| match x {
        Record::Start { self_integrity, .. } => Some(self_integrity.clone()),
        _ => None,
    });
    assert_eq!(
        got,
        Some(Some("unsigned".to_string())),
        "치료를 수행한 바이너리가 무엇인지 기록에 없다"
    );
}

/// 주지 않으면 **그 줄이 없다.** 모르는 것을 `unknown` 으로 적으면
/// "검사했는데 알 수 없었다" 와 구분되지 않는다.
#[test]
fn not_telling_is_not_the_same_as_unknown() {
    let lab = Lab::new("integrity-absent");
    let target = lab.file("payload.exe", b"x");
    let ex = Executor::new(&FsRestore, lab.state());
    let r = ex.apply(&plan(vec![action(1, &target)])).expect("수행");

    let text = std::fs::read_to_string(&r.journal).expect("저널 본문");
    assert!(!text.contains("self_integrity"), "{text}");
}

// ── 재부팅 뒤 재검사 예약 (설계-03 §8 · P12) ────────────────────────────
//
// **감사 로그에 남는가, 그리고 `End` 앞에 남는가.** 뒤에 남으면 끝난 회차가
// 이어받기 대상으로 되살아난다 — `Reading::finished` 는 마지막 줄을 본다.

/// 예약을 받아 적기만 하는 백엔드. 파일은 `FsRestore` 에 맡긴다.
#[derive(Default)]
struct Schedules {
    placed: std::sync::Mutex<Vec<String>>,
}

impl PlatformWrite for Schedules {
    fn backend_name(&self) -> &'static str {
        "schedules"
    }
    fn plan_restore(&self, d: &str, m: &FileMeta) -> RestoreReport {
        FsRestore.plan_restore(d, m)
    }
    fn restore_file(
        &self,
        d: &str,
        c: &[u8],
        m: &FileMeta,
    ) -> Result<RestoreReport, remedy_platform::PlatformError> {
        FsRestore.restore_file(d, c, m)
    }
    fn quarantine_read(
        &self,
        p: &str,
    ) -> Result<(Vec<u8>, FileMeta), remedy_platform::PlatformError> {
        FsRestore.quarantine_read(p)
    }
    fn destroy_file(&self, p: &str) -> Result<(), remedy_platform::PlatformError> {
        FsRestore.destroy_file(p)
    }
    fn exists(&self, p: &str) -> bool {
        FsRestore.exists(p)
    }
    fn schedule_verify_after_reboot(
        &self,
        run_id: &str,
        exe: &std::path::Path,
        plugin: &std::path::Path,
        state_dir: Option<&std::path::Path>,
        lang: remedy_sdk::i18n::Lang,
    ) -> Result<(), remedy_platform::PlatformError> {
        self.placed
            .lock()
            .unwrap()
            .push(remedy_platform::write::scheduled_verify_command(
                exe, run_id, plugin, state_dir, lang,
            ));
        Ok(())
    }
    fn scheduled_verify_site(&self) -> Option<VerifySite> {
        Some(VerifySite {
            location: "/etc/systemd/system/remedy-verify.service".into(),
            removed_by: RemovedBy::Itself,
        })
    }
}

fn wants_reboot_check(mut p: PlanEnvelope) -> PlanEnvelope {
    p.body.verify_after_reboot = true;
    p
}

fn verify_request() -> VerifyRequest {
    VerifyRequest {
        exe: PathBuf::from("/usr/local/bin/remedy"),
        plugin: PathBuf::from("/opt/plugins/x/plugin.yaml"),
        state_dir: None,
        lang: remedy_sdk::i18n::Lang::Ko,
    }
}

#[test]
fn the_reboot_check_is_journalled_right_before_the_end() {
    use remedy_journal::{Journal, Record};
    let lab = Lab::new("verify-journal");
    let target = lab.file("payload.exe", b"x");
    let backend = Schedules::default();
    let ex = Executor::new(&backend, lab.state()).with_verify_after_reboot(Ok(verify_request()));
    let r = ex
        .apply(&wants_reboot_check(plan(vec![action(1, &target)])))
        .expect("수행");

    // 실제로 걸었고, 보고가 건 그대로를 싣는다.
    let placed = backend.placed.lock().unwrap().clone();
    assert_eq!(placed.len(), 1, "{placed:?}");
    match &r.scheduled_verify {
        Some(ScheduledVerify::Scheduled { site, command }) => {
            assert_eq!(command, &placed[0], "보고한 명령이 건 명령과 다르다");
            assert_eq!(site.as_ref().map(|s| s.removed_by), Some(RemovedBy::Itself));
        }
        other => panic!("{other:?}"),
    }

    // **감사 로그에, `End` 바로 앞에.** 규칙 (3) 이 요구하는 기록이다.
    let reading = Journal::read(&r.journal).expect("저널");
    let n = reading.records.len();
    assert!(matches!(reading.records[n - 1], Record::End { .. }));
    match &reading.records[n - 2] {
        Record::VerifyScheduled {
            location,
            removed_by,
            command,
        } => {
            assert_eq!(
                location.as_deref(),
                Some("/etc/systemd/system/remedy-verify.service")
            );
            assert_eq!(removed_by.as_deref(), Some("itself"));
            assert_eq!(command, &placed[0]);
        }
        other => panic!("End 앞에 예약 기록이 없다: {other:?}"),
    }
    // 끝난 회차는 끝난 회차로 읽힌다 — 이어받기 목록에 되살아나지 않는다.
    assert!(reading.finished(), "끝난 회차가 끝나지 않은 것으로 읽힌다");
    assert!(
        remedy_journal::unfinished(&lab.state()).unwrap().is_empty(),
        "끝난 회차가 이어받기 목록에 있다"
    );
}

#[test]
fn a_reboot_check_that_could_not_be_placed_is_journalled_too() {
    // `FsRestore` 는 예약하지 않는다(트레이트 기본값). **걸지 못한 것도 이 회차가
    // 한 일이다** — 그리고 치료의 실패가 아니다.
    use remedy_journal::{Journal, Record};
    let lab = Lab::new("verify-refused");
    let target = lab.file("payload.exe", b"x");
    let ex = Executor::new(&FsRestore, lab.state()).with_verify_after_reboot(Ok(verify_request()));
    let r = ex
        .apply(&wants_reboot_check(plan(vec![action(1, &target)])))
        .expect("예약 실패는 치료 실패가 아니다");
    assert_eq!(r.done(), 1);

    let Some(ScheduledVerify::NotScheduled { reason }) = &r.scheduled_verify else {
        panic!("{:?}", r.scheduled_verify);
    };
    let reading = Journal::read(&r.journal).expect("저널");
    let n = reading.records.len();
    assert_eq!(
        reading.records[n - 2],
        Record::VerifyNotScheduled {
            reason: reason.clone()
        }
    );
    assert!(reading.finished());
}

#[test]
fn a_request_the_caller_could_not_make_is_journalled_and_nothing_is_placed() {
    // 부른 쪽이 요청을 못 만들었다(`apply --plan` 은 플러그인 경로를 모른다).
    // 백엔드는 부르지 않고 **그 이유를 남긴다.**
    use remedy_journal::{Journal, Record};
    let lab = Lab::new("verify-no-request");
    let target = lab.file("payload.exe", b"x");
    let backend = Schedules::default();
    let why = "이 명령은 플러그인 경로를 모른다";
    let ex = Executor::new(&backend, lab.state()).with_verify_after_reboot(Err(why.into()));
    let r = ex
        .apply(&wants_reboot_check(plan(vec![action(1, &target)])))
        .expect("수행");

    assert!(
        backend.placed.lock().unwrap().is_empty(),
        "요청이 없는데 걸었다"
    );
    assert_eq!(
        r.scheduled_verify,
        Some(ScheduledVerify::NotScheduled { reason: why.into() })
    );
    let reading = Journal::read(&r.journal).expect("저널");
    assert!(
        reading
            .records
            .contains(&Record::VerifyNotScheduled { reason: why.into() }),
        "이유가 감사 로그에 없다"
    );
}

#[test]
fn nothing_is_placed_or_written_unless_the_plan_and_the_caller_both_ask() {
    // 계획이 원하지 않으면 요청이 있어도 걸지 않는다.
    let lab = Lab::new("verify-plan-silent");
    let a = lab.file("a.exe", b"a");
    let backend = Schedules::default();
    let r = Executor::new(&backend, lab.state())
        .with_verify_after_reboot(Ok(verify_request()))
        .apply(&plan(vec![action(1, &a)]))
        .expect("수행");
    assert_eq!(r.scheduled_verify, None);
    assert!(backend.placed.lock().unwrap().is_empty());
    let text = std::fs::read_to_string(&r.journal).expect("저널 본문");
    assert!(!text.contains("\"verify_"), "{text}");

    // 계획이 원해도 부른 쪽이 요청을 넘기지 않으면 걸지도 적지도 않는다.
    let lab = Lab::new("verify-caller-silent");
    let b = lab.file("b.exe", b"b");
    let r = Executor::new(&backend, lab.state())
        .apply(&wants_reboot_check(plan(vec![action(1, &b)])))
        .expect("수행");
    assert_eq!(r.scheduled_verify, None);
    assert!(backend.placed.lock().unwrap().is_empty());
    let text = std::fs::read_to_string(&r.journal).expect("저널 본문");
    assert!(!text.contains("\"verify_"), "{text}");
}

#[test]
fn a_resumed_run_places_the_reboot_check_too() {
    // **이어받은 회차도 같은 자리에서 건다** (결정 자료 가1). `resume` 은 `apply`
    // 와 같은 실행기를 지나므로, 7단계에 닿기 전에 죽은 회차는 이어받는 쪽이
    // 예약을 건다 — 새 회차의 시험만으로는 이것이 재어지지 않았다.
    use remedy_journal::{Journal, Record};
    let lab = Lab::new("resume-verify");
    let (a, b, c) = (
        lab.file("1.exe", b"one"),
        lab.file("2.exe", b"two"),
        lab.file("3.exe", b"three"),
    );
    let p = wants_reboot_check(plan(vec![action(1, &a), action(2, &b), action(3, &c)]));

    crash(
        &DiesAfterDestroying {
            done: 0.into(),
            at: 2,
        },
        &lab.state(),
        &p,
    );
    assert!(!gone(&c), "3번은 아직이다");

    let backend = Schedules::default();
    let r = Executor::new(&backend, lab.state())
        .with_clock("2026-08-21T01:00:00Z")
        .with_verify_after_reboot(Ok(verify_request()))
        .apply(&p)
        .expect("이어서 수행해야 한다");

    assert_eq!(r.resumed, Some(remedy_apply::Resume::Continue), "{r:?}");
    assert!(gone(&c), "3번이 안 지워졌다");
    let placed = backend.placed.lock().unwrap().clone();
    assert_eq!(placed.len(), 1, "이어받은 회차가 예약하지 않았다");
    match &r.scheduled_verify {
        Some(ScheduledVerify::Scheduled { command, .. }) => assert_eq!(command, &placed[0]),
        other => panic!("{other:?}"),
    }
    let reading = Journal::read(&r.journal).expect("저널");
    let n = reading.records.len();
    assert!(matches!(reading.records[n - 1], Record::End { .. }));
    assert!(
        matches!(reading.records[n - 2], Record::VerifyScheduled { .. }),
        "End 앞에 예약 기록이 없다: {:?}",
        reading.records[n - 2]
    );
}

// ─────────────────────────────── 꼬리에서 멈춘 회차 (결정 자료 다1)
//
// 마지막 결과를 적은 뒤 `End` 전에 멈추면 파괴는 끝난 것이다. 그 사이에 있는
// 것은 7단계(재부팅 뒤 재검사 예약) 하나다 — 그래서 **예약하다 죽는** 백엔드로
// 그 자리를 진짜로 낸다. 저널을 손으로 잘라 만들지 않는다(위 크래시 시험들과
// 같은 이유).

/// 재부팅 뒤 재검사를 **예약하다가** 죽는다. 파일은 `FsRestore` 에 맡긴다.
struct DiesWhileScheduling;

impl PlatformWrite for DiesWhileScheduling {
    passthrough!();
    fn quarantine_read(
        &self,
        p: &str,
    ) -> Result<(Vec<u8>, FileMeta), remedy_platform::PlatformError> {
        FsRestore.quarantine_read(p)
    }
    fn destroy_file(&self, p: &str) -> Result<(), remedy_platform::PlatformError> {
        FsRestore.destroy_file(p)
    }
    fn schedule_verify_after_reboot(
        &self,
        _run_id: &str,
        _exe: &std::path::Path,
        _plugin: &std::path::Path,
        _state_dir: Option<&std::path::Path>,
        _lang: remedy_sdk::i18n::Lang,
    ) -> Result<(), remedy_platform::PlatformError> {
        panic!("[시험] 여기서 전원이 나갔다고 친다");
    }
}

#[test]
fn a_run_that_stopped_after_its_last_result_is_finished_without_redoing_anything() {
    use remedy_journal::{Journal, Record};
    let lab = Lab::new("resume-tail");
    let (a, b) = (lab.file("1.exe", b"one"), lab.file("2.exe", b"two"));
    let p = wants_reboot_check(plan(vec![action(1, &a), action(2, &b)]));

    let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Executor::new(&DiesWhileScheduling, lab.state())
            .with_verify_after_reboot(Ok(verify_request()))
            .apply(&p)
    }));
    assert!(died.is_err(), "죽지 않았다 — 크래시 지점이 틀렸다");
    assert!(gone(&a) && gone(&b), "둘 다 지워진 뒤에 죽어야 한다");

    // 남은 저널이 이 시험의 전제다 — 결과는 전부 있고 `End` 는 없다.
    let path = remedy_journal::journal_path(&lab.state(), &p.run_id);
    let before = Journal::read(&path).expect("저널");
    assert_eq!(before.decided().len(), 2, "{:?}", before.records);
    assert!(!before.finished(), "End 가 적혔다 — 크래시 지점이 틀렸다");

    // 다시 부른다 — 재기동이다.
    let backend = Schedules::default();
    let r = Executor::new(&backend, lab.state())
        .with_clock("2026-08-21T01:00:00Z")
        .with_verify_after_reboot(Ok(verify_request()))
        .apply(&p)
        .expect("꼬리를 마저 해야 한다 — 이미 수행된 계획으로 거부했다");

    assert_eq!(r.resumed, Some(remedy_apply::Resume::Tail), "{r:?}");
    assert_eq!(r.carried, 2, "둘 다 이전 시도가 끝냈다");
    assert_eq!((r.done(), r.failed()), (2, 0), "{:?}", r.body.results);
    // **남은 것만 했다** — 예약 하나. 격리소는 이전 시도가 만든 그대로다.
    assert_eq!(backend.placed.lock().unwrap().len(), 1);
    assert!(r.container.as_ref().is_some_and(|c| c.exists()), "{r:?}");

    let after = Journal::read(&r.journal).expect("저널");
    let n = after.records.len();
    assert!(matches!(after.records[n - 1], Record::End { .. }));
    assert!(
        matches!(after.records[n - 2], Record::VerifyScheduled { .. }),
        "End 앞에 예약 기록이 없다: {:?}",
        after.records[n - 2]
    );
    // 새로 적은 것은 이어받았다는 기록과 그 둘뿐이다 — 결과를 다시 적지 않았다.
    assert_eq!(
        n,
        before.records.len() + 3,
        "{:?}",
        &after.records[before.records.len()..]
    );
    assert!(after.finished());
    assert!(
        remedy_journal::unfinished(&lab.state()).unwrap().is_empty(),
        "끝난 회차가 이어받기 목록에 남았다"
    );
}
