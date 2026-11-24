//! 설정 계열 Op 4종과 그 **왕복** (설계-09 P7, G2).
//!
//! 실제 파일로 돈다. 재는 것은 `백업 → 편집 → 복원` 이 같은 것을 가리키는가와,
//! **손대지 않기로 한 것을 손대지 않았는가**다.

use remedy_apply::{Executor, Silent};
use remedy_platform::write::{FileMeta, PlatformWrite, RestoreReport};
use remedy_platform::PlatformError;
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
fn a_line_and_then_its_whole_file_come_back_as_the_original() {
    // 한 파일을 줄 룰과 파일 룰이 함께 짚으면 계획은 [줄 빼기, 그 파일의 격리]다(같은 단계 · 들어온
    // 차례). 담기는 파괴 전에 다 끝나므로 엔트리는 그 줄과 원본 파일이다. 복원은 목록 차례로 돌아야
    // 원본이 된다 — 줄을 먼저 넣고 원본으로 덮는다. 목록을 통째로 뒤집으면 원본 위에 그 줄이 한 번
    // 더 들어간다(cron 줄의 차례만 바꾸는 까닭 · `restore::apply`).
    let lab = Lab::new("line-then-file");
    let p = lab.file("settings.ini", INI);
    let mut file = act(Op::FileQuarantineOnly, &p, serde_json::json!({}));
    file.seq = 2;
    file.r#match = None;
    let (done, failed, errs, c) = run(
        &lab,
        "line-then-file",
        vec![
            act(
                Op::TextConfigRemoveLine,
                &p,
                serde_json::json!({ "line_no": 3, "line": "evil=payload.exe" }),
            ),
            file,
        ],
    );
    assert_eq!((done, failed), (2, 0), "{errs:?}");
    assert!(!std::path::Path::new(&p).exists(), "격리한 파일이 남았다");
    restore(&lab, "line-then-file", &c.expect("컨테이너"));
    assert_eq!(
        std::fs::read_to_string(&p).expect("읽기"),
        INI,
        "되돌렸는데 원본과 다르다"
    );
}

/// 한 파일에서 줄을 둘 이상 빼는 계획을 증거에서 짓고(가드까지 도는 `remedy_plan::plan`), 이 플랫폼의 백엔드로
/// 치료한 뒤 복원한다. 1.25.3 은 위 줄부터 빼 둘째 줄이 *"그 자리의 줄이 계획과 다릅니다"* 로 거부됐다(일부 실패 ·
/// 나쁜 줄이 남는다). cron 줄과 같은 번호 밀림이다(이슈 #166 ③).
///
/// 증거는 평가기가 내는 차례로 담는다 — 텍스트 설정은 수집기가 (파일, 번호) 오름차순으로 세운다. hosts 는 레코드의
/// 문자열 차례라 번호와 상관이 없으므로 가장 나쁜 차례(번호 오름차순)로 담고, 둘째 줄을 파일의 마지막 줄로 둔다.
#[test]
fn lines_in_one_file_go_and_come_back_byte_for_byte() {
    use remedy_sdk::artifact::{ArtifactKind, Evidence, EvidenceGroup, ScanBody};
    use remedy_sdk::catalog::Subject::{HostsEntry, TextConfig};
    let lab = Lab::new("lines");
    let conf_body = "[boot]\r\nevil=a.exe\r\nshell=explorer.exe\r\nevil=b.exe\r\nlast=1\r\n";
    let hosts_body = "127.0.0.1 localhost\n10.20.30.40 a.example\n10.20.30.40 b.example\n";
    let conf = lab.file("app.ini", conf_body);
    let hosts = lab.file("hosts", hosts_body);
    let ev = |id: &str, subject, target: serde_json::Value| Evidence {
        id: id.into(),
        rule: id.split('#').next().unwrap_or_default().into(),
        subject,
        score: None,
        target,
        captures: Default::default(),
        matched: Vec::new(),
        label: None,
    };
    let text = |n: u32, line: &str| serde_json::json!({ "path": conf, "line_no": n, "line": line, "key": "evil", "value": "x" });
    let entry = |n: u32, name: &str| {
        serde_json::json!({
            "ip": "10.20.30.40", "hostnames": [name], "line_no": n, "source": hosts,
            "line": format!("10.20.30.40 {name}")
        })
    };
    let evidence = vec![
        ev("conf#0", TextConfig, text(2, "evil=a.exe")),
        ev("conf#1", TextConfig, text(4, "evil=b.exe")),
        ev("hosts#0", HostsEntry, entry(2, "a.example")),
        ev("hosts#1", HostsEntry, entry(3, "b.example")),
    ];
    let ids: Vec<String> = evidence.iter().map(|e| e.id.clone()).collect();
    let root = lab.dir.to_string_lossy().to_string();
    let scan = Envelope {
        schema_version: 1,
        kind: ArtifactKind::Scan,
        run_id: "lines".into(),
        created: "2026-11-24T00:00:00Z".into(),
        host: HostInfo {
            hostname: "T".into(),
            os: if cfg!(windows) { "windows" } else { "linux" }.into(),
            version: "10".into(),
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
            scan_roots: vec![root.clone()],
            removable_roots: Vec::new(),
        },
    };
    let manifest: remedy_sdk::manifest::PluginManifest =
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": "lines", "version": "0.1.0", "min_core": "1.0.0",
            "platforms": ["windows", "linux"], "name": {"en": "lines"},
            "scan_roots": [root], "subjects": ["text_config", "hosts_entry"],
            "detect": [
                {"id": "conf", "subject": "text_config",
                 "where": [{"field": "line", "op": "contains", "value": "evil="}]},
                {"id": "hosts", "subject": "hosts_entry",
                 "where": [{"field": "ip", "op": "contains", "value": "10.20.30.40"}]}
            ],
            "verdict": {"require": "conf"},
            "remediate": {"remove": [{"ref": "conf"}], "restore": ["hosts"]}
        }))
        .expect("매니페스트");
    let plan = remedy_plan::plan(&scan, Some(&manifest)).expect("계획");

    let b = backend();
    let rep = Executor::new(&b, lab.state())
        .with_progress(&Silent)
        .with_clock("2026-11-24T00:00:00Z")
        .apply(&plan)
        .expect("수행");
    let errs: Vec<String> = rep
        .body
        .results
        .iter()
        .filter_map(|r| r.error.clone())
        .collect();
    assert_eq!((rep.done(), rep.failed()), (4, 0), "{errs:?}");
    assert_eq!(
        std::fs::read_to_string(&conf).expect("읽기"),
        "[boot]\r\nshell=explorer.exe\r\nlast=1\r\n"
    );
    assert_eq!(
        std::fs::read_to_string(&hosts).expect("읽기"),
        "127.0.0.1 localhost\n"
    );

    restore(&lab, "lines", &rep.container.clone().expect("컨테이너"));
    assert_eq!(std::fs::read_to_string(&conf).expect("읽기"), conf_body);
    assert_eq!(std::fs::read_to_string(&hosts).expect("읽기"), hosts_body);
}

/// 같은 격리물을 두 번 복원해도 원래 바이트다 — 그 번호의 줄이 이미 담아 둔 줄이면 넣지 않는다. 1.25.3 은 보지 않고
/// 넣어 두 번째 복원이 줄마다 하나씩 더 넣었다. 계획은 계획기가 짓는 차례(한 파일의 줄은 아래 줄부터)로 손으로 둔다.
#[test]
fn restoring_the_same_lines_twice_gives_back_the_original_bytes() {
    let lab = Lab::new("twice");
    let conf_body = "[boot]\r\nevil=a.exe\r\nshell=explorer.exe\r\nevil=b.exe\r\nlast=1\r\n";
    let hosts_body = "127.0.0.1 localhost\n10.20.30.40 a.example\n10.20.30.40 b.example\n";
    let conf = lab.file("app.ini", conf_body);
    let hosts = lab.file("hosts", hosts_body);
    let line = |op: Op, path: &str, n: u32, text: &str, seq: u32| {
        let mut a = act(op, path, serde_json::json!({ "line_no": n, "line": text }));
        a.seq = seq;
        a
    };
    let (done, failed, errs, c) = run(
        &lab,
        "twice",
        vec![
            line(Op::TextConfigRemoveLine, &conf, 4, "evil=b.exe", 1),
            line(Op::TextConfigRemoveLine, &conf, 2, "evil=a.exe", 2),
            line(Op::HostsRestoreLine, &hosts, 3, "10.20.30.40 b.example", 3),
            line(Op::HostsRestoreLine, &hosts, 2, "10.20.30.40 a.example", 4),
        ],
    );
    assert_eq!((done, failed), (4, 0), "{errs:?}");
    assert_eq!(
        std::fs::read_to_string(&conf).expect("읽기"),
        "[boot]\r\nshell=explorer.exe\r\nlast=1\r\n"
    );
    assert_eq!(
        std::fs::read_to_string(&hosts).expect("읽기"),
        "127.0.0.1 localhost\n"
    );
    let c = c.expect("컨테이너");
    for round in 1..=2 {
        restore(&lab, "twice", &c);
        assert_eq!(
            std::fs::read_to_string(&conf).expect("읽기"),
            conf_body,
            "{round}번째 복원 뒤"
        );
        assert_eq!(
            std::fs::read_to_string(&hosts).expect("읽기"),
            hosts_body,
            "{round}번째 복원 뒤"
        );
    }
}

/// 담기를 마치고(컨테이너는 디스크에 내려갔다) 줄을 지우기 전에 멈춘 회차를 복원해도 줄이 늘지 않는다 — 파일은
/// 그대로라 줄마다 그 번호에 담아 둔 줄이 있다. 1.25.3 은 줄마다 하나씩 더 넣었다.
///
/// 멈춤은 실행기 한가운데서 패닉을 던져 만든다(`persistence_ops.rs` 의 `Crashy` 와 같은 수) — 그때까지 fsync 된
/// 저널과 컨테이너만 남고, 그것이 전원이 나간 뒤의 상태와 같다. 컨테이너는 그 회차의 자리에서 바로 연다.
#[test]
fn restoring_a_run_that_stopped_before_removing_adds_no_line() {
    let lab = Lab::new("stopped");
    let body = "[boot]\r\nevil=a.exe\r\nshell=explorer.exe\r\nevil=b.exe\r\nlast=1\r\n";
    let conf = lab.file("app.ini", body);
    let lower = act(
        Op::TextConfigRemoveLine,
        &conf,
        serde_json::json!({ "line_no": 4, "line": "evil=b.exe" }),
    );
    let mut upper = act(
        Op::TextConfigRemoveLine,
        &conf,
        serde_json::json!({ "line_no": 2, "line": "evil=a.exe" }),
    );
    upper.seq = 2;
    let live = backend();
    let dying = DiesBeforeRemoving(&live);
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Executor::new(&dying, lab.state())
            .with_progress(&Silent)
            .with_clock("2026-08-22T00:00:00Z")
            .apply(&plan_of("stopped", vec![lower, upper]))
    }));
    assert!(stopped.is_err(), "지우기 전에 멈추지 않았다");
    assert_eq!(
        std::fs::read_to_string(&conf).expect("읽기"),
        body,
        "멈추기 전에 파일을 바꿨다"
    );

    let container = remedy_core::restore::container_path(&lab.state(), "stopped");
    restore(&lab, "stopped", &container);
    assert_eq!(
        std::fs::read_to_string(&conf).expect("읽기"),
        body,
        "줄이 늘었다"
    );
}

/// 이 플랫폼의 라이브 백엔드를 그대로 부르다가 줄을 지우기 직전에 멈춘다(패닉).
struct DiesBeforeRemoving<'a>(&'a dyn PlatformWrite);

impl PlatformWrite for DiesBeforeRemoving<'_> {
    fn backend_name(&self) -> &'static str {
        "dies-before-removing"
    }
    fn plan_restore(&self, dest: &str, meta: &FileMeta) -> RestoreReport {
        self.0.plan_restore(dest, meta)
    }
    fn restore_file(
        &self,
        dest: &str,
        content: &[u8],
        meta: &FileMeta,
    ) -> Result<RestoreReport, PlatformError> {
        self.0.restore_file(dest, content, meta)
    }
    fn quarantine_read(&self, path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
        self.0.quarantine_read(path)
    }
    fn destroy_file(&self, path: &str) -> Result<(), PlatformError> {
        self.0.destroy_file(path)
    }
    fn exists(&self, path: &str) -> bool {
        self.0.exists(path)
    }
    fn text_line_read(&self, path: &str, line_no: u32) -> Result<String, PlatformError> {
        self.0.text_line_read(path, line_no)
    }
    fn text_line_remove(
        &self,
        _path: &str,
        _line_no: u32,
        _expect: &str,
    ) -> Result<(), PlatformError> {
        panic!("[시험] 줄을 지우기 직전에 전원이 나갔다고 친다")
    }
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
