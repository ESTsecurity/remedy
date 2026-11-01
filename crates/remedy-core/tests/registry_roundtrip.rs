//! 레지스트리 계열 **왕복** — 지운 것이 되살아나는가 (G2, 설계-09 P7).
//!
//! `remedy-apply` 는 복원을 모르고 `remedy-core` 만 둘을 다 본다. 그래서
//! **백업 → 파괴 → 복원**이 같은 것을 가리키는지는 여기서만 잴 수 있다.

use remedy_apply::{Executor, Silent};
use remedy_platform::write::{
    AvExclusion, FileMeta, PlatformWrite, RegistryValueBackup, RestoreReport,
};
use remedy_platform::PlatformError;
use remedy_sdk::artifact::{Action, CoreInfo, Envelope, HostInfo, PlanBody, PlanEnvelope};
use remedy_sdk::catalog::{Op, Risk};
use std::cell::RefCell;
use std::collections::BTreeMap;

#[derive(Default)]
struct FakeRegistry {
    values: RefCell<BTreeMap<String, RegistryValueBackup>>,
    exclusions: RefCell<Vec<AvExclusion>>,
}

impl FakeRegistry {
    fn text(&self, t: &str) -> Option<String> {
        self.values.borrow().get(t).and_then(|v| v.as_string())
    }
    fn vtype(&self, t: &str) -> Option<u32> {
        self.values.borrow().get(t).map(|v| v.vtype)
    }
}

impl PlatformWrite for FakeRegistry {
    fn backend_name(&self) -> &'static str {
        "fake-registry"
    }
    fn plan_restore(&self, _d: &str, _m: &FileMeta) -> RestoreReport {
        RestoreReport::default()
    }
    fn restore_file(
        &self,
        _d: &str,
        _c: &[u8],
        _m: &FileMeta,
    ) -> Result<RestoreReport, PlatformError> {
        Err(PlatformError::Unsupported("파일은 다루지 않는다"))
    }
    fn quarantine_read(&self, _p: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
        Err(PlatformError::Unsupported("파일은 다루지 않는다"))
    }
    fn destroy_file(&self, _p: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("파일은 다루지 않는다"))
    }
    fn exists(&self, _p: &str) -> bool {
        false
    }
    fn registry_read(&self, t: &str) -> Result<RegistryValueBackup, PlatformError> {
        self.values
            .borrow()
            .get(t)
            .cloned()
            .ok_or(PlatformError::Unsupported("그런 값이 없다"))
    }
    fn registry_delete(&self, t: &str) -> Result<(), PlatformError> {
        self.values
            .borrow_mut()
            .remove(t)
            .map(|_| ())
            .ok_or(PlatformError::Unsupported("그런 값이 없다"))
    }
    fn registry_write(&self, t: &str, v: &RegistryValueBackup) -> Result<(), PlatformError> {
        self.values.borrow_mut().insert(t.to_string(), v.clone());
        Ok(())
    }
    fn registry_exists(&self, t: &str) -> bool {
        self.values.borrow().contains_key(t)
    }
    fn av_exclusions_read(&self) -> Result<Vec<AvExclusion>, PlatformError> {
        Ok(self.exclusions.borrow().clone())
    }
    fn av_exclusions_write(&self, want: &[AvExclusion]) -> Result<(), PlatformError> {
        *self.exclusions.borrow_mut() = want.to_vec();
        Ok(())
    }
}

fn work(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join("remedy-p7-roundtrip").join(name);
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

/// 계획을 수행하고 그 컨테이너를 그대로 복원한다.
/// 백업 → 파괴 → 복원 세 벌이 같은 것을 가리키는가 (G2).
///
/// `after_destroy` 가 **파괴가 실제로 일어났는지**를 재는 자리다. 이것이
/// 없으면 왕복 대조가 공허해질 수 있다 — 지운 것이 없으면 복원 뒤의 상태는
/// 당연히 같고, 그 초록은 복원 능력이 아니라 아무 일도 없었음을 뜻한다.
/// `av.restore_exclusions` 가 정확히 그렇게 한동안 초록이었다 (2026-08-31).
fn round_trip(
    name: &str,
    fake: &FakeRegistry,
    actions: Vec<Action>,
    after_destroy: impl Fn(&FakeRegistry),
) {
    let dir = work(name);
    let rep = Executor::new(fake, &dir)
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(name, actions))
        .expect("수행");
    assert_eq!(rep.failed(), 0, "{:?}", rep.body.results);
    after_destroy(fake);

    let path = rep.container.clone().expect("격리 컨테이너");
    let bytes = remedy_core::restore::read_container(&path).expect("컨테이너 읽기");
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
        name,
        fake,
        &remedy_core::restore::Guards {
            protected: &remedy_plan::Protected::new(
                remedy_sdk::catalog::Platform::Windows,
                remedy_plan::expand_env_for_protection,
            ),
            vouched: &Default::default(),
        },
        &[],
        None,
    )
    .expect("복원 계획");
    for item in &plan.items {
        assert!(
            item.blocked.is_none(),
            "복원이 막혔다: {:?} — {:?}",
            item.dest,
            item.blocked
        );
    }
    let out = remedy_core::restore::apply(&plan, &opened, &key, fake).expect("복원");
    for o in &out {
        assert!(o.result.is_ok(), "{}: {:?}", o.dest, o.result);
    }
}

const RUN_KEY: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil";
const PATH_VAR: &str =
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\Path";

fn with(values: &[(&str, u32, &str)]) -> FakeRegistry {
    FakeRegistry {
        values: RefCell::new(
            values
                .iter()
                .map(|(t, vt, v)| (t.to_string(), RegistryValueBackup::from_string(*vt, v)))
                .collect(),
        ),
        exclusions: RefCell::new(Vec::new()),
    }
}

#[test]
fn a_deleted_value_comes_back_byte_for_byte() {
    let fake = with(&[(RUN_KEY, 2, "%APPDATA%\\evil.exe")]);
    let before = fake.values.borrow()[RUN_KEY].clone();

    round_trip(
        "delete",
        &fake,
        vec![act(1, Op::RegistryDeleteValue, RUN_KEY, None)],
        |f| assert!(!f.values.borrow().contains_key(RUN_KEY), "지우지 않았다"),
    );

    let after = fake
        .values
        .borrow()
        .get(RUN_KEY)
        .cloned()
        .expect("되살아나지 않았다");
    assert_eq!(after, before, "바이트가 다르다");
    // **타입까지 같아야 한다.** `REG_EXPAND_SZ` 가 `REG_SZ` 로 돌아오면
    // `%APPDATA%` 가 전개되지 않는 문자열로 남는다 — 복원한 것처럼 보이지만
    // 동작이 다르다.
    assert_eq!(fake.vtype(RUN_KEY), Some(2));
}

#[test]
fn a_stripped_value_comes_back_with_the_malicious_part() {
    // **복원하면 오염된 원본이 그대로 돌아오며, 그것이 옳은 동작이다.**
    // 사용자가 복원을 요청했다는 것은 우리 판정이 틀렸다고 본다는 뜻이므로,
    // 우리가 "옳다고 생각한 부분" 만 남겨서는 안 된다 (설계-03 §2).
    let fake = with(&[(PATH_VAR, 2, "C:\\ok;C:\\evil")]);
    round_trip(
        "strip",
        &fake,
        vec![act(1, Op::EnvStripPath, PATH_VAR, Some("C:\\evil"))],
        |f| assert_eq!(f.text(PATH_VAR).as_deref(), Some("C:\\ok"), "자르지 않았다"),
    );
    assert_eq!(
        fake.text(PATH_VAR).as_deref(),
        Some("C:\\ok;C:\\evil"),
        "부분 편집의 복원이 편집 전 값 전체가 아니다"
    );
}

/// 제외 항목 하나를 가리키는 대상. **값 이름 자체가 경로다.**
const EXCL_EVIL: &str =
    "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\\C:\\evil.exe";

#[test]
fn the_whole_exclusion_list_comes_back() {
    // 예외 목록의 백업은 **항목 하나가 아니라 목록 전체**다 (설계-02 §9).
    //
    // 대상이 한동안 `RUN_KEY` 였고, 그래서 이 시험은 **지우지 않고**
    // 초록이었다 — 왕복을 재는데 무엇도 사라지지 않았으니 목록이 같은 것은
    // 당연했다. 왕복을 재려면 **먼저 지워졌음을 확인해야 한다.**
    let fake = with(&[(RUN_KEY, 1, "x")]);
    *fake.exclusions.borrow_mut() = vec![
        AvExclusion {
            kind: "path".into(),
            value: "C:\\정상".into(),
        },
        AvExclusion {
            kind: "process".into(),
            value: "C:\\evil.exe".into(),
        },
    ];
    let before = fake.exclusions.borrow().clone();

    round_trip(
        "av",
        &fake,
        vec![act(1, Op::AvRestoreExclusions, EXCL_EVIL, None)],
        |f| {
            assert_eq!(
                f.exclusions.borrow().len(),
                1,
                "파괴 단계가 예외를 지우지 않았다 — 그러면 아래 왕복 대조가 공허하다"
            );
        },
    );

    assert_eq!(
        *fake.exclusions.borrow(),
        before,
        "목록이 그대로 오지 않았다"
    );
}

#[test]
fn a_backup_without_a_value_type_is_refused_not_guessed() {
    // 타입 없이 되돌리면 `REG_EXPAND_SZ` 였던 자리가 `REG_SZ` 가 되고, 그 값의
    // `%SystemRoot%` 가 전개되지 않는 문자열로 남는다 — **복원한 것처럼 보이지만
    // 동작이 다르다.** 짐작하느니 되돌리지 않는 편이 낫다.
    use remedy_quarantine::{Builder, ContentKey, Entry, Header, MachineKey};

    let dir = work("notype");
    let key = ContentKey::generate().expect("키");
    let mk = MachineKey::load_or_create(&dir.join("machine.key")).expect("머신 키");
    let header = Header {
        run_id: "notype".into(),
        created: "2026-08-22T00:00:00Z".into(),
        core_version: "0".into(),
        cipher: remedy_quarantine::key::CIPHER_ID.into(),
        wraps: vec![mk.wrap(&key).expect("wrap")],
    };
    let mut b = Builder::new(header, "t");
    b.add(Entry {
        kind: remedy_sdk::EntryKind::RegistryValue,
        origin: RUN_KEY.to_string(),
        // **타입이 없다.** 예전 컨테이너이거나 변조된 것이다.
        meta: serde_json::Value::Null,
        content: b"\x00\x00".to_vec(),
    });
    let bytes = b.seal(&key).expect("봉인");

    let sealed = remedy_core::restore::peek(&bytes).expect("헤더");
    let opened = sealed.unlock(&key).expect("열기");
    let fake = with(&[]);
    let plan = remedy_core::restore::plan(
        &opened,
        "notype",
        &fake,
        &remedy_core::restore::Guards {
            protected: &remedy_plan::Protected::new(
                remedy_sdk::catalog::Platform::Windows,
                remedy_plan::expand_env_for_protection,
            ),
            vouched: &Default::default(),
        },
        &[],
        None,
    )
    .expect("복원 계획");
    let out = remedy_core::restore::apply(&plan, &opened, &key, &fake).expect("복원");
    assert_eq!(out.len(), 1);
    let err = out[0].result.as_ref().expect_err("타입 없이 되돌렸다");
    // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
    assert!(
        err.contains(remedy_sdk::i18n::t("타입", "value type")),
        "{err}"
    );
    assert!(fake.values.borrow().is_empty(), "거절했는데 값을 썼다");
}
