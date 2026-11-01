//! 레지스트리 계열 Op 8종 (설계-09 P7).
//!
//! **계획기 게이트를 거치지 않는다.** 게이트는 19종이 전부 될 때 올라가지만,
//! 실행기는 계획을 받아 수행할 뿐이므로 지금 잴 수 있다. 여기서 재는 것은
//! `백업 → 파괴 → 복원` 세 벌이 **같은 것을 가리키는가**다 (G2).

use remedy_apply::{Executor, Silent};
use remedy_platform::write::{
    AvExclusion, FileMeta, PlatformWrite, RegistryValueBackup, RestoreReport,
};
use remedy_platform::PlatformError;
use remedy_sdk::artifact::{Action, CoreInfo, Envelope, HostInfo, PlanBody, PlanEnvelope};
use remedy_sdk::catalog::{Op, Risk};
use std::cell::RefCell;
use std::collections::BTreeMap;

// ───────────────────────────────────────────── 가짜 레지스트리

/// 대상 문자열 → (타입, 바이트). 실제 레지스트리와 같은 모양으로만 답한다.
#[derive(Default)]
struct FakeRegistry {
    values: RefCell<BTreeMap<String, RegistryValueBackup>>,
    exclusions: RefCell<Vec<AvExclusion>>,
    /// 켜면 **읽힌 값이 곧바로 사라진다.** 백업과 파괴 사이의 경쟁을 만든다.
    vanish_after_read: std::cell::Cell<bool>,
}

impl FakeRegistry {
    fn with(values: &[(&str, u32, &str)]) -> Self {
        let m: BTreeMap<String, RegistryValueBackup> = values
            .iter()
            .map(|(t, vt, v)| (t.to_string(), RegistryValueBackup::from_string(*vt, v)))
            .collect();
        Self {
            values: RefCell::new(m),
            exclusions: RefCell::new(Vec::new()),
            vanish_after_read: std::cell::Cell::new(false),
        }
    }
    /// `REG_MULTI_SZ` 값 하나를 든 가짜.
    ///
    /// **항목을 그대로 받는다** — 줄바꿈으로 이어 붙인 문자열을 받으면
    /// 시험이 실기기와 다른 모양을 재게 된다. 빈 항목도 항목이다.
    fn with_multi(target: &str, items: &[&str]) -> Self {
        let owned: Vec<String> = items.iter().map(|s| s.to_string()).collect();
        let mut m = BTreeMap::new();
        m.insert(target.to_string(), RegistryValueBackup::from_multi(&owned));
        Self {
            values: RefCell::new(m),
            exclusions: RefCell::new(Vec::new()),
            vanish_after_read: std::cell::Cell::new(false),
        }
    }
    fn text(&self, target: &str) -> Option<String> {
        self.values.borrow().get(target).and_then(|v| v.as_string())
    }
    fn multi(&self, target: &str) -> Option<Vec<String>> {
        self.values.borrow().get(target).and_then(|v| v.as_multi())
    }
    fn bytes(&self, target: &str) -> Option<Vec<u8>> {
        self.values.borrow().get(target).map(|v| v.bytes.clone())
    }
    fn has(&self, target: &str) -> bool {
        self.values.borrow().contains_key(target)
    }
}

impl PlatformWrite for FakeRegistry {
    fn backend_name(&self) -> &'static str {
        "fake-registry"
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

    fn registry_read(&self, target: &str) -> Result<RegistryValueBackup, PlatformError> {
        let v = self
            .values
            .borrow()
            .get(target)
            .cloned()
            .ok_or(PlatformError::Unsupported("그런 값이 없다"))?;
        if self.vanish_after_read.get() {
            self.values.borrow_mut().remove(target);
        }
        Ok(v)
    }
    fn registry_delete(&self, target: &str) -> Result<(), PlatformError> {
        self.values
            .borrow_mut()
            .remove(target)
            .map(|_| ())
            .ok_or(PlatformError::Unsupported("그런 값이 없다"))
    }
    fn registry_write(
        &self,
        target: &str,
        value: &RegistryValueBackup,
    ) -> Result<(), PlatformError> {
        self.values
            .borrow_mut()
            .insert(target.to_string(), value.clone());
        Ok(())
    }
    fn registry_exists(&self, target: &str) -> bool {
        self.has(target)
    }
    fn av_exclusions_read(&self) -> Result<Vec<AvExclusion>, PlatformError> {
        Ok(self.exclusions.borrow().clone())
    }
    fn av_exclusions_write(&self, want: &[AvExclusion]) -> Result<(), PlatformError> {
        *self.exclusions.borrow_mut() = want.to_vec();
        Ok(())
    }
}

// ───────────────────────────────────────────── 계획 만들기

fn work(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join("remedy-p7-registry").join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("작업 디렉터리");
    d
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

fn act(seq: u32, op: Op, target: &str, strip: Option<&str>) -> Action {
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
        strip: strip.map(str::to_string),
        because: vec!["e#0".into()],
        backup: None,
        reversible: info.reversible,
        risk: Risk::Low,
        user_impact: None,
    }
}

/// 계획을 수행하고 (성공 수, 실패 수, 실패 사유)를 돌려준다.
fn run(name: &str, fake: &FakeRegistry, actions: Vec<Action>) -> (usize, usize, Vec<String>) {
    let dir = work(name);
    let rep = Executor::new(fake, &dir)
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(name, actions))
        .expect("수행");
    let errs: Vec<String> = rep
        .body
        .results
        .iter()
        .filter_map(|a| a.error.clone())
        .collect();
    (rep.done(), rep.failed(), errs)
}

const RUN_KEY: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil";
const SHELL: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell";
const USERINIT: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit";
const PATH_VAR: &str =
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\Path";
const BOOT_EXEC: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute";

// ───────────────────────────────────────────── 값을 지우는 Op

#[test]
fn deleting_a_value_removes_exactly_that_one() {
    let fake = FakeRegistry::with(&[(RUN_KEY, 1, "C:\\evil.exe"), (SHELL, 1, "explorer.exe")]);
    let (done, failed, errs) = run(
        "delete",
        &fake,
        vec![act(1, Op::RegistryDeleteValue, RUN_KEY, None)],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert!(!fake.has(RUN_KEY), "대상이 남았다");
    assert!(fake.has(SHELL), "옆의 값까지 지웠다");
}

#[test]
fn a_target_that_cannot_be_backed_up_is_not_destroyed() {
    // **백업할 수 없는 것은 파괴하지 않는다** (설계-03 §5). 값이 없으면 백업이
    // 실패하고, 그 실패의 뜻은 "아직 아무것도 파괴되지 않았다" 다.
    let fake = FakeRegistry::default();
    let dir = work("nobackup");
    let e = Executor::new(&fake, &dir)
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(
            "nobackup",
            vec![act(1, Op::RegistryDeleteValue, RUN_KEY, None)],
        ))
        .expect_err("백업할 수 없으면 멈춰야 한다");
    assert!(
        matches!(e, remedy_apply::ApplyError::StoppedBeforeDestruction(_)),
        "{e:?}"
    );
}

#[test]
fn a_value_that_vanished_after_backup_is_not_a_false_failure() {
    // 백업과 파괴 사이에 대상이 사라질 수 있다. 그때 "없는 값" 오류를 실패로
    // 세면 **실제로는 목표 상태가 이루어졌는데** 무인 배포에 "부분 실패" 로
    // 올라가고, 사람이 감염을 찾으러 간다.
    //
    // 백업은 손에 있으므로 되돌릴 수도 있다 — 답은 성공이다.
    let fake = FakeRegistry::with(&[(RUN_KEY, 1, "C:\\evil.exe")]);
    fake.vanish_after_read.set(true);
    let (done, failed, errs) = run(
        "vanish",
        &fake,
        vec![act(1, Op::RegistryDeleteValue, RUN_KEY, None)],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert!(!fake.has(RUN_KEY));
}

#[test]
fn the_three_other_delete_ops_do_the_same_thing() {
    // 같은 일을 하는 Op 이 셋 더 있다. 하나만 시험하면 나머지가 조용히
    // 다른 길로 가도 모른다.
    //
    // **`av.restore_exclusions` 는 여기 없다.** 한동안 있었고, 그것이 결함을
    // 얼어붙게 했다 — 이 시험이 초록이라 "레지스트리 값 하나로 다뤄도 된다"
    // 는 것이 확인된 사실처럼 보였다. 실제로는 제외 항목의 값 이름이 경로라
    // 그 갈래가 아무것도 지우지 못한다. 아래 전용 시험이 그 자리를 맡는다.
    for (i, op) in [Op::AutorunRemove, Op::ProxyRestore, Op::FirewallRestoreRule]
        .into_iter()
        .enumerate()
    {
        let fake = FakeRegistry::with(&[(RUN_KEY, 1, "C:\\evil.exe")]);
        let (done, failed, errs) = run(&format!("del{i}"), &fake, vec![act(1, op, RUN_KEY, None)]);
        assert_eq!((done, failed), (1, 0), "{} :: {errs:?}", op.id());
        assert!(!fake.has(RUN_KEY), "{} 가 지우지 않았다", op.id());
    }
}

// ───────────────────────────────────────────── 보안 제품 예외 목록

/// `...\\Exclusions\\Paths\\<경로>` — **값 이름 자체가 경로다.**
const EXCL_PATH: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Users\\t\\AppData\\Local\\Programs\\Eviljs-we9i6";

fn excl(kind: &str, value: &str) -> AvExclusion {
    AvExclusion {
        kind: kind.into(),
        value: value.into(),
    }
}

#[test]
fn removing_an_exclusion_whose_name_contains_backslashes() {
    // **이것이 실기기에서 조용히 실패하던 자리다** (2026-08-31).
    //
    // 대상이 일반 레지스트리 갈래로 가면 `split_value_name` 이 마지막
    // 역슬래시에서 잘라 없는 키를 열고, 없으니 "이미 지워졌다" 로 성공을
    // 보고한다. 목록은 그대로인데 `apply` 는 완전 치료로 끝난다.
    let fake = FakeRegistry::with(&[]);
    *fake.exclusions.borrow_mut() = vec![
        excl(
            "path",
            "C:\\Users\\t\\AppData\\Local\\Programs\\Eviljs-we9i6",
        ),
        excl("path", "C:\\Program Files\\정상앱"),
        excl("process", "dbeaver.exe"),
    ];

    let (done, failed, errs) = run(
        "excl",
        &fake,
        vec![act(1, Op::AvRestoreExclusions, EXCL_PATH, None)],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");

    let left = fake.exclusions.borrow().clone();
    assert_eq!(
        left,
        vec![
            excl("path", "C:\\Program Files\\정상앱"),
            excl("process", "dbeaver.exe"),
        ],
        "악성 예외만 빠지고 나머지는 남아야 한다"
    );
}

#[test]
fn an_exclusion_that_is_already_gone_is_not_a_failure() {
    // 크래시가 파괴와 기록 사이에 왔다면 이미 없다. 거짓 실패가 "부분 실패"
    // 로 올라가면 사람이 감염을 찾으러 간다.
    let fake = FakeRegistry::with(&[]);
    *fake.exclusions.borrow_mut() = vec![excl("process", "dbeaver.exe")];

    let (done, failed, errs) = run(
        "excl-gone",
        &fake,
        vec![act(1, Op::AvRestoreExclusions, EXCL_PATH, None)],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(fake.exclusions.borrow().len(), 1, "남은 것을 건드렸다");
}

#[test]
fn a_target_that_is_not_an_exclusion_is_refused_not_guessed() {
    // 모양이 아니면 **거절한다.** 짐작해서 다른 것을 지우는 것보다 낫다.
    let fake = FakeRegistry::with(&[(RUN_KEY, 1, "C:\\evil.exe")]);
    *fake.exclusions.borrow_mut() = vec![excl("path", "C:\\evil")];

    let (done, failed, _errs) = run(
        "excl-bad",
        &fake,
        vec![act(1, Op::AvRestoreExclusions, RUN_KEY, None)],
    );
    assert_eq!((done, failed), (0, 1), "모양이 아닌 대상을 수행했다");
    assert!(fake.has(RUN_KEY), "엉뚱한 레지스트리 값을 지웠다");
}

// ───────────────────────────────────────────── 부분 편집

#[test]
fn stripping_a_value_keeps_the_rest() {
    // **통째로 지우면 시스템을 못 쓰게 되는 대상이 오히려 주류다.**
    // `Userinit` 를 지우면 로그온이 깨진다 (설계-02 §6-1).
    let fake = FakeRegistry::with(&[(
        USERINIT,
        1,
        "C:\\Windows\\system32\\userinit.exe,C:\\evil.exe",
    )]);
    let (done, failed, errs) = run(
        "strip",
        &fake,
        vec![act(
            1,
            Op::RegistryStripValue,
            USERINIT,
            Some("C:\\evil.exe"),
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(
        fake.text(USERINIT).as_deref(),
        Some("C:\\Windows\\system32\\userinit.exe,"),
        "정상 부분까지 잘렸다"
    );
}

#[test]
fn stripping_without_a_needle_is_refused_not_guessed() {
    let fake = FakeRegistry::with(&[(USERINIT, 1, "userinit.exe,")]);
    let (done, failed, errs) = run(
        "noneedle",
        &fake,
        vec![act(1, Op::RegistryStripValue, USERINIT, None)],
    );
    assert_eq!((done, failed), (0, 1));
    assert!(
        errs[0].contains(remedy_sdk::i18n::t("무엇을 지울지", "what to strip")),
        "{errs:?}"
    );
    assert_eq!(fake.text(USERINIT).as_deref(), Some("userinit.exe,"));
}

#[test]
fn stripping_a_non_string_value_is_refused() {
    // REG_DWORD 에서 문자열을 잘라 내는 것은 편집이 아니라 손상이다.
    // **`REG_MULTI_SZ` 는 이 갈래에 들지 않는다** — 목록은 아래에서 다룬다.
    let fake = FakeRegistry::default();
    fake.values.borrow_mut().insert(
        USERINIT.to_string(),
        RegistryValueBackup {
            vtype: 4,
            bytes: vec![1, 0, 0, 0],
        },
    );
    let (done, failed, errs) = run(
        "dword",
        &fake,
        vec![act(1, Op::RegistryStripValue, USERINIT, Some("x"))],
    );
    assert_eq!((done, failed), (0, 1));
    assert!(
        errs[0].contains(remedy_sdk::i18n::t(
            "문자열도 목록도 아니",
            "neither a string nor a list"
        )),
        "{errs:?}"
    );
}

#[test]
fn stripping_with_an_empty_needle_is_refused_not_treated_as_success() {
    // 빈 needle 은 문자열 값을 `trim` 만 해서 다시 쓰고 **성공으로 끝난다.**
    // 계획기의 `interpolate` 가 빈 capture 를 해소하면 실제로 그렇게 된다.
    let fake = FakeRegistry::with(&[(USERINIT, 1, " userinit.exe, ")]);
    let (done, failed, errs) = run(
        "empty-needle",
        &fake,
        vec![act(1, Op::RegistryStripValue, USERINIT, Some(""))],
    );
    assert_eq!((done, failed), (0, 1));
    assert!(
        errs[0].contains(remedy_sdk::i18n::t("빈 문자열", "empty string")),
        "{errs:?}"
    );
    assert_eq!(
        fake.text(USERINIT).as_deref(),
        Some(" userinit.exe, "),
        "거부해 놓고 값을 건드렸다"
    );
}

// ───────────────────────────────────────────── 목록 값의 부분 편집

/// 실기기의 `BootExecute` 모양. **가운데가 정상 보안 제품의 것**이고 빈 항목이
/// 섞여 있다 (2026-09-05 실측).
fn boot_items() -> Vec<&'static str> {
    vec!["autocheck autochk *", "", "bootalyac.exe", "", "wbboot.exe"]
}

#[test]
fn stripping_a_multi_sz_removes_only_the_named_item() {
    // 이 값은 **통째로 지울 수 없다** — `autocheck autochk *` 가 함께 사라지면
    // 디스크 검사가 돌지 않는다. `to: default` 도 쓸 수 없다(카탈로그에 없다).
    // 목록 타입을 다루지 못하던 동안 이 지속성을 고칠 방법이 아예 없었다.
    let fake = FakeRegistry::with_multi(BOOT_EXEC, &boot_items());
    let (done, failed, errs) = run(
        "multi",
        &fake,
        vec![act(
            1,
            Op::RegistryStripValue,
            BOOT_EXEC,
            Some("wbboot.exe"),
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(
        fake.multi(BOOT_EXEC),
        Some(vec![
            "autocheck autochk *".to_string(),
            String::new(),
            "bootalyac.exe".to_string(),
            String::new(),
        ]),
        "정상 항목이나 빈 항목까지 건드렸다"
    );
}

#[test]
fn stripping_a_multi_sz_does_not_cut_a_longer_sibling() {
    // **부분 문자열로 자르면 `alyac.exe` 가 `bootalyac.exe` 에 걸린다** — 정상
    // 보안 제품의 부팅 항목을 없애는 것이고, PATH 에서 이미 막아 둔 실수와
    // 같은 것이다.
    let fake = FakeRegistry::with_multi(BOOT_EXEC, &boot_items());
    let (done, failed, errs) = run(
        "multi-sub",
        &fake,
        vec![act(1, Op::RegistryStripValue, BOOT_EXEC, Some("alyac.exe"))],
    );
    // 맞는 항목이 없으므로 아무것도 쓰지 않고 성공이다.
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(
        fake.multi(BOOT_EXEC),
        Some(boot_items().iter().map(|s| s.to_string()).collect()),
        "부분 문자열로 잘렸다"
    );
}

#[test]
fn stripping_a_multi_sz_matches_an_item_that_carries_arguments() {
    // 이 목록의 항목은 **명령줄**이다 — `autocheck autochk *` 가 그 모양이라
    // 검체가 인자를 달고 올 수 있다. 항목 전체가 같은 것만 보면 그때 아무것도
    // 지우지 않고 성공으로 끝난다.
    let fake = FakeRegistry::with_multi(BOOT_EXEC, &["autocheck autochk *", "wbboot.exe -s"]);
    let (done, failed, errs) = run(
        "multi-args",
        &fake,
        vec![act(
            1,
            Op::RegistryStripValue,
            BOOT_EXEC,
            Some("wbboot.exe"),
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(
        fake.multi(BOOT_EXEC),
        Some(vec!["autocheck autochk *".to_string()])
    );
}

#[test]
fn stripping_a_multi_sz_keeps_the_value_type() {
    // `REG_SZ` 로 바꿔 쓰면 부팅 관리자가 그 값을 목록으로 읽지 못한다.
    let fake = FakeRegistry::with_multi(BOOT_EXEC, &boot_items());
    run(
        "multi-type",
        &fake,
        vec![act(
            1,
            Op::RegistryStripValue,
            BOOT_EXEC,
            Some("wbboot.exe"),
        )],
    );
    assert_eq!(fake.values.borrow()[BOOT_EXEC].vtype, 7, "타입이 바뀌었다");
}

#[test]
fn stripping_an_absent_multi_sz_item_writes_nothing() {
    // 크래시가 파괴와 기록 사이에 왔다면 이미 없다. 다시 지우려 들면 거짓
    // 실패가 "부분 실패" 로 올라간다 — 그러나 **다시 쓰지도 않는다.**
    let fake = FakeRegistry::with_multi(BOOT_EXEC, &boot_items());
    let before = fake.bytes(BOOT_EXEC);
    let (done, failed, errs) = run(
        "multi-gone",
        &fake,
        vec![act(1, Op::RegistryStripValue, BOOT_EXEC, Some("gone.exe"))],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(fake.bytes(BOOT_EXEC), before, "바꿀 것이 없는데 다시 썼다");
}

#[test]
fn stripping_every_item_leaves_an_empty_list_not_a_deleted_value() {
    // 계획이 승인받은 것은 `strip` 이지 `delete` 가 아니다. 값이 통째로
    // 사라지면 저널이 적은 것과 일어난 일이 달라진다.
    let fake = FakeRegistry::with_multi(BOOT_EXEC, &["wbboot.exe"]);
    let (done, failed, errs) = run(
        "multi-all",
        &fake,
        vec![act(
            1,
            Op::RegistryStripValue,
            BOOT_EXEC,
            Some("wbboot.exe"),
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert!(fake.has(BOOT_EXEC), "값 자체가 사라졌다");
    assert_eq!(fake.multi(BOOT_EXEC), Some(Vec::new()));
}

#[test]
fn stripping_a_path_entry_does_not_cut_a_longer_sibling() {
    // **`C:\a` 를 지우려다 `C:\ab` 까지 잘리면 안 된다.** PATH 는 `;` 로 이어진
    // 목록이고, 부분 문자열로 자르는 것과 항목으로 자르는 것은 다르다.
    let fake = FakeRegistry::with(&[(PATH_VAR, 2, "C:\\a;C:\\ab;C:\\c")]);
    let (done, failed, errs) = run(
        "path",
        &fake,
        vec![act(1, Op::EnvStripPath, PATH_VAR, Some("C:\\a"))],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(fake.text(PATH_VAR).as_deref(), Some("C:\\ab;C:\\c"));
}

#[test]
fn stripping_a_path_tolerates_a_needle_that_carries_the_separator() {
    // **정답 플러그인이 실제로 이렇게 적혀 있었다** — `value: "C:\ProgramData\
    // WebBoost;"`. 항목 하나를 통째로 견주는 방식에서 그 문자열은 어느 항목과도
    // 같지 않아 아무것도 지우지 않고 **성공으로 끝났다** (2026-09-05).
    //
    // `;` 는 어떤 경로에도 들어갈 수 없는 글자라 떼어 내는 것이 모호하지 않고,
    // 떼어 낸 뒤에도 항목 하나보다 넓게 맞히지 않는다.
    let fake = FakeRegistry::with(&[(PATH_VAR, 2, "C:\\WebBoost;C:\\WebBoostLib;C:\\c")]);
    let (done, failed, errs) = run(
        "path-semi",
        &fake,
        vec![act(1, Op::EnvStripPath, PATH_VAR, Some("C:\\WebBoost;"))],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(
        fake.text(PATH_VAR).as_deref(),
        Some("C:\\WebBoostLib;C:\\c"),
        "구분자를 뗀 뒤에도 항목 하나만 지워야 한다"
    );
}

#[test]
fn stripping_a_path_refuses_a_needle_that_is_only_a_separator() {
    // 구분자만 남으면 빈 항목을 골라 없애는 편집이 된다. 그것은 치료가 아니다.
    let fake = FakeRegistry::with(&[(PATH_VAR, 2, "C:\\a;;C:\\c")]);
    let (done, failed, errs) = run(
        "path-onlysemi",
        &fake,
        vec![act(1, Op::EnvStripPath, PATH_VAR, Some(";"))],
    );
    assert_eq!((done, failed), (0, 1));
    assert!(
        errs[0].contains(remedy_sdk::i18n::t("구분자뿐", "only a separator")),
        "{errs:?}"
    );
    assert_eq!(fake.text(PATH_VAR).as_deref(), Some("C:\\a;;C:\\c"));
}

#[test]
fn stripping_a_path_keeps_the_value_type() {
    // PATH 는 `REG_EXPAND_SZ` 다. `REG_SZ` 로 바꿔 쓰면 `%SystemRoot%` 가
    // 전개되지 않는 문자열로 남고, 복원한 것처럼 보이지만 동작이 다르다.
    let fake = FakeRegistry::with(&[(PATH_VAR, 2, "C:\\a;C:\\evil")]);
    run(
        "ptype",
        &fake,
        vec![act(1, Op::EnvStripPath, PATH_VAR, Some("C:\\evil"))],
    );
    assert_eq!(fake.values.borrow()[PATH_VAR].vtype, 2, "타입이 바뀌었다");
}

// ───────────────────────────────────────────── 기본값 복원

#[test]
fn restoring_a_default_uses_the_catalog_not_the_plan() {
    // **값의 출처는 카탈로그뿐이다.** 계획에 적힌 값을 쓰면 서명된 도구가 임의
    // 레지스트리 값을 쓸 수 있는 것이고, 그 자체가 공격 도구다 (설계-03 §2).
    let fake = FakeRegistry::with(&[(SHELL, 1, "C:\\evil.exe")]);
    let (done, failed, errs) = run(
        "default",
        &fake,
        // `strip` 에 엉뚱한 값을 넣어도 쓰이지 않아야 한다.
        vec![act(
            1,
            Op::RegistryRestoreDefault,
            SHELL,
            Some("C:\\attacker.exe"),
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(fake.text(SHELL).as_deref(), Some("explorer.exe"));
}

#[test]
fn restoring_a_dword_default_writes_a_number_not_text() {
    // `LoadAppInit_DLLs` 는 이 카탈로그의 **첫 수 값**이다. 검체가 1 로 켜 두고,
    // 치료는 0 으로 되돌려야 한다.
    //
    // 문자열로 되돌리면 바이트가 `30 00 00 00` 이 되고 그것을 수로 읽으면
    // **48** 이다 — 0 이 아니므로 **AppInit 적재가 켜진 채로 남는다.** 길이가
    // 우연히 4바이트라 레지스트리도 실행기도 오류를 내지 않는다.
    const LOAD_APPINIT: &str =
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs";
    let fake = FakeRegistry::default();
    fake.values
        .borrow_mut()
        .insert(LOAD_APPINIT.to_string(), RegistryValueBackup::from_dword(1));
    let (done, failed, errs) = run(
        "dword-default",
        &fake,
        vec![act(1, Op::RegistryRestoreDefault, LOAD_APPINIT, None)],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    let v = fake.values.borrow()[LOAD_APPINIT].clone();
    assert_eq!(v.vtype, 4, "타입이 REG_DWORD 가 아니다");
    assert_eq!(v.bytes, vec![0, 0, 0, 0], "0 이 아닌 값이 남았다");
}

#[test]
fn restoring_an_empty_string_default_keeps_the_value_present() {
    // `AppInit_DLLs` 는 청정 Windows 에 **빈 문자열로 존재한다.** 지우는 것과
    // 비우는 것은 다르다 — 지우면 보안 기준선 점검이 "설정되지 않음" 으로
    // 읽고, 기계가 감염 전 상태로 돌아가지 않은 것이다.
    const APPINIT: &str =
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs";
    let fake = FakeRegistry::with(&[(APPINIT, 1, "C:\\ProgramData\\SvcAssist\\sahook.dll")]);
    let (done, failed, errs) = run(
        "empty-default",
        &fake,
        vec![act(1, Op::RegistryRestoreDefault, APPINIT, None)],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert!(
        fake.has(APPINIT),
        "값 자체가 사라졌다 — 비우는 것이지 지우는 것이 아니다"
    );
    assert_eq!(fake.text(APPINIT).as_deref(), Some(""));
}

#[test]
fn restoring_a_target_outside_the_catalog_is_refused() {
    let fake = FakeRegistry::with(&[(RUN_KEY, 1, "C:\\evil.exe")]);
    let (done, failed, errs) = run(
        "nocat",
        &fake,
        vec![act(1, Op::RegistryRestoreDefault, RUN_KEY, None)],
    );
    assert_eq!((done, failed), (0, 1));
    assert!(
        errs[0].contains(remedy_sdk::i18n::t("카탈로그", "catalog")),
        "{errs:?}"
    );
    assert_eq!(
        fake.text(RUN_KEY).as_deref(),
        Some("C:\\evil.exe"),
        "거절했는데 값이 바뀌었다"
    );
}

// ───────────────────────────────────────────── 백업 (G2 의 앞 절반)

#[test]
fn what_is_deleted_is_in_the_container_first() {
    // **백업이 끝나고 디스크에 내려간 뒤에만 파괴한다** (설계-03 §5).
    // 백업에 없는 것을 지웠다면 그 Action 은 되돌릴 수 없다.
    let fake = FakeRegistry::with(&[(RUN_KEY, 1, "C:\\evil.exe")]);
    let dir = work("backup");
    let mut a = act(1, Op::RegistryDeleteValue, RUN_KEY, None);
    a.backup = None; // 백업 종류는 카탈로그가 정한다.
    let rep = Executor::new(&fake, &dir)
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of("backup", vec![a]))
        .expect("수행");
    assert_eq!(rep.failed(), 0);

    let container = rep.container.clone().expect("격리 컨테이너");
    assert!(container.exists(), "격리 컨테이너가 없다: {container:?}");

    // 컨테이너를 열어 **그 값이 그 타입으로** 들어 있는지 본다.
    // `remedy-core` 는 상위 크레이트라 여기서 쓸 수 없다 — 격리소를 직접 연다.
    let bytes = std::fs::read(&container).expect("컨테이너");
    let sealed = remedy_quarantine::Sealed::parse(&bytes).expect("헤더");
    let mk = remedy_quarantine::MachineKey::load_or_create(&dir.join("machine.key")).expect("키");
    let slot = sealed
        .header
        .wraps
        .iter()
        .find(|w| w.kind == remedy_quarantine::WrapKind::Local)
        .expect("로컬 wrap");
    let key = mk.unwrap(slot).expect("풀기");
    let opened = sealed.unlock(&key).expect("열기");
    let entry = opened
        .manifest
        .entries
        .iter()
        .find(|e| e.origin == RUN_KEY)
        .unwrap_or_else(|| panic!("백업에 대상이 없다: {:?}", opened.manifest.entries));
    let body = opened.read(&entry.id, &key).expect("본문");
    assert_eq!(entry.kind, remedy_sdk::EntryKind::RegistryValue);
    assert_eq!(
        body.meta.get("vtype").and_then(|v| v.as_u64()),
        Some(1),
        "타입이 담기지 않았다 — 되돌릴 때 무엇으로 쓸지 알 수 없다"
    );
    assert_eq!(
        RegistryValueBackup {
            vtype: 1,
            bytes: body.content.clone(),
        }
        .as_string()
        .as_deref(),
        Some("C:\\evil.exe")
    );
}
