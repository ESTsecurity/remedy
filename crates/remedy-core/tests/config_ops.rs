//! 설정 계열 Op 4종과 그 **왕복** (설계-09 P7, G2).
//!
//! 실제 파일로 돈다. 재는 것은 `백업 → 편집 → 복원` 이 같은 것을 가리키는가와,
//! **손대지 않기로 한 것을 손대지 않았는가**다.

use remedy_apply::{Executor, Silent};
use remedy_platform::write::PlatformWrite;
use remedy_sdk::artifact::{Action, CoreInfo, Envelope, HostInfo, PlanBody, PlanEnvelope};
use remedy_sdk::catalog::{Op, Risk};
use std::path::PathBuf;

struct Lab {
    dir: PathBuf,
}

impl Lab {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("remedy-p7-config-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("작업 디렉터리");
        Self { dir }
    }
    fn file(&self, name: &str, body: &str) -> String {
        let p = self.dir.join(name);
        std::fs::write(&p, body).expect("파일");
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

fn backend() -> impl PlatformWrite {
    remedy_core::restore::default_backend()
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

fn act(op: Op, target: &str, locator: serde_json::Value) -> Action {
    let info = op.info();
    Action {
        seq: 1,
        op,
        target: Some(target.to_string()),
        r#match: Some(locator),
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

/// 계획을 수행한다. (성공, 실패, 사유, 컨테이너 경로)
fn run(
    lab: &Lab,
    name: &str,
    actions: Vec<Action>,
) -> (usize, usize, Vec<String>, Option<PathBuf>) {
    let b = backend();
    let rep = Executor::new(&b, lab.state())
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(name, actions))
        .expect("수행");
    let errs: Vec<String> = rep
        .body
        .results
        .iter()
        .filter_map(|r| r.error.clone())
        .collect();
    (rep.done(), rep.failed(), errs, rep.container.clone())
}

/// 그 컨테이너를 그대로 복원한다.
fn restore(lab: &Lab, name: &str, container: &std::path::Path) {
    let b = backend();
    let bytes = remedy_core::restore::read_container(container).expect("컨테이너");
    let sealed = remedy_core::restore::peek(&bytes).expect("헤더");
    let key = remedy_core::restore::unlock(
        &sealed.header,
        &remedy_core::restore::KeySource {
            state_dir: Some(lab.state()),
            ..Default::default()
        },
    )
    .expect("풀기");
    let opened = sealed.unlock(&key).expect("열기");
    let plan = remedy_core::restore::plan(
        &opened,
        name,
        &b,
        &remedy_core::restore::Guards {
            protected: &remedy_plan::Protected::new(
                remedy_sdk::catalog::Platform::Windows,
                remedy_plan::expand_env_for_protection,
            ),
            vouched: &remedy_core::restore::vouched(&lab.state(), name),
        },
        &[],
        None,
    )
    .expect("복원 계획");
    for item in &plan.items {
        assert!(item.blocked.is_none(), "복원이 막혔다: {:?}", item.blocked);
    }
    for o in remedy_core::restore::apply(&plan, &opened, &key, &b).expect("복원") {
        assert!(o.result.is_ok(), "{}: {:?}", o.dest, o.result);
    }
}

// ───────────────────────────────────── text_config.remove_line

const INI: &str = "[boot]\r\nshell=explorer.exe\r\nevil=payload.exe\r\nlast=1\r\n";

#[test]
fn removing_a_line_takes_only_that_line() {
    let lab = Lab::new("line");
    let p = lab.file("settings.ini", INI);
    let (done, failed, errs, _) = run(
        &lab,
        "line",
        vec![act(
            Op::TextConfigRemoveLine,
            &p,
            serde_json::json!({ "line_no": 3, "line": "evil=payload.exe" }),
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(
        std::fs::read_to_string(&p).expect("읽기"),
        "[boot]\r\nshell=explorer.exe\r\nlast=1\r\n",
        "줄 끝이나 다른 줄이 바뀌었다"
    );
}

#[test]
fn a_line_that_moved_is_not_removed_at_all() {
    // **번호와 내용이 둘 다 맞아야 한다.** 수집과 실행 사이에 파일이 바뀌었으면
    // 아무것도 하지 않는 편이 낫다 — 설정 파일에서 엉뚱한 줄을 지우면 그 앱이
    // 못 뜬다.
    let lab = Lab::new("moved");
    let p = lab.file("settings.ini", INI);
    let (done, failed, errs, _) = run(
        &lab,
        "moved",
        vec![act(
            Op::TextConfigRemoveLine,
            &p,
            serde_json::json!({ "line_no": 2, "line": "evil=payload.exe" }),
        )],
    );
    assert_eq!((done, failed), (0, 1), "{errs:?}");
    // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
    assert!(
        errs[0].contains(remedy_sdk::i18n::t(
            "계획과 다르다",
            "differs from the plan"
        )),
        "{errs:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&p).expect("읽기"),
        INI,
        "파일이 바뀌었다"
    );
}

#[test]
fn a_removed_line_comes_back_in_place() {
    let lab = Lab::new("lineback");
    let p = lab.file("settings.ini", INI);
    let (_, failed, errs, c) = run(
        &lab,
        "lineback",
        vec![act(
            Op::TextConfigRemoveLine,
            &p,
            serde_json::json!({ "line_no": 3, "line": "evil=payload.exe" }),
        )],
    );
    assert_eq!(failed, 0, "{errs:?}");
    restore(&lab, "lineback", &c.expect("컨테이너"));
    assert_eq!(
        std::fs::read_to_string(&p).expect("읽기"),
        INI,
        "되돌렸는데 원본과 다르다"
    );
}

#[test]
fn a_hosts_line_uses_the_same_machinery() {
    // `hosts.restore_line` 과 `text_config.remove_line` 은 담을 바이트가 같다
    // (설계-02 §9). 하나만 시험하면 다른 하나가 조용히 다른 길로 가도 모른다.
    let lab = Lab::new("hosts");
    let body = "# 주석\n127.0.0.1 localhost\n1.2.3.4 evil.example\n";
    let p = lab.file("hosts", body);
    let (done, failed, errs, _) = run(
        &lab,
        "hosts",
        vec![act(
            Op::HostsRestoreLine,
            &p,
            serde_json::json!({ "line_no": 3, "line": "1.2.3.4 evil.example" }),
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(
        std::fs::read_to_string(&p).expect("읽기"),
        "# 주석\n127.0.0.1 localhost\n"
    );
}

// ─────────────────────────── structured_config.remove_key

const JSON: &str = "{\n  \"keep\": 1,\n  \"policy\": { \"evil\": \"x\", \"ok\": 2 }\n}\n";

#[test]
fn removing_a_json_key_leaves_the_rest() {
    let lab = Lab::new("json");
    let p = lab.file("prefs.json", JSON);
    let (done, failed, errs, _) = run(
        &lab,
        "json",
        vec![act(
            Op::StructuredConfigRemoveKey,
            &p,
            serde_json::json!({ "key_path": "policy.evil" }),
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&p).expect("읽기")).expect("json");
    assert!(v["policy"].get("evil").is_none());
    assert_eq!(v["policy"]["ok"], 2);
    assert_eq!(v["keep"], 1);
}

#[test]
fn a_structured_edit_is_backed_up_as_the_whole_file() {
    // **파싱해 고쳐 쓰면 들여쓰기와 키 순서가 바뀐다.** 값만 담아 두면 복원이
    // 그 편집된 형태 위에 값을 되돌리는 것이라 원본 바이트로 돌아가지 못한다
    // (설계-02 §9).
    let lab = Lab::new("jsonback");
    let p = lab.file("prefs.json", JSON);
    let (_, failed, errs, c) = run(
        &lab,
        "jsonback",
        vec![act(
            Op::StructuredConfigRemoveKey,
            &p,
            serde_json::json!({ "key_path": "policy.evil" }),
        )],
    );
    assert_eq!(failed, 0, "{errs:?}");
    // 편집이 실제로 형태를 바꿨는지 먼저 확인한다 — 안 바뀌었다면 이 시험이
    // 아무것도 재지 못한다.
    assert_ne!(
        std::fs::read_to_string(&p).expect("읽기"),
        JSON,
        "편집이 파일을 바꾸지 않았다"
    );
    restore(&lab, "jsonback", &c.expect("컨테이너"));
    assert_eq!(
        std::fs::read_to_string(&p).expect("읽기"),
        JSON,
        "바이트로 돌아오지 않았다"
    );
}

#[test]
fn restoring_a_structured_default_outside_the_catalog_is_refused() {
    // **값의 출처는 카탈로그뿐이다** (설계-03 §2). 지금 카탈로그에 구조적 설정
    // 항목이 하나도 없으므로 이 Op 은 언제나 거절된다 — 그 사실이 조용하지
    // 않아야 한다.
    let lab = Lab::new("jsondefault");
    let p = lab.file("prefs.json", JSON);
    let (done, failed, errs, _) = run(
        &lab,
        "jsondefault",
        vec![act(
            Op::StructuredConfigRestoreDefault,
            &p,
            serde_json::json!({ "key_path": "policy.evil" }),
        )],
    );
    assert_eq!((done, failed), (0, 1), "{errs:?}");
    assert!(
        errs[0].contains(remedy_sdk::i18n::t("카탈로그", "catalog")),
        "{errs:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&p).expect("읽기"),
        JSON,
        "거절했는데 파일이 바뀌었다"
    );
}
