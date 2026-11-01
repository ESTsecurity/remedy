//! **격리 → 복원 → 원본 일치** (설계-09 P6 검증 1).
//!
//! P5 가 만든 컨테이너·복원 경로와 P6 이 만든 실행기가 처음으로 한 줄에 선다.
//! 지금까지 둘은 각자 시험됐을 뿐, remedy 가 **스스로 격리한 것을 스스로
//! 되돌린** 적은 없었다.
//!
//! 이 왕복이 성립하지 않으면 "지우기 전에 되돌리기" 는 문서에만 있는 말이 된다.

use remedy_apply::{Executor, KeyPolicy};
use remedy_platform::write::FsRestore;
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
        let dir = std::env::temp_dir().join(format!("remedy-roundtrip-{name}"));
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

fn plan_for(targets: &[&str]) -> PlanEnvelope {
    Envelope {
        schema_version: 1,
        kind: ArtifactKind::Plan,
        run_id: "run-roundtrip".into(),
        created: "2026-08-21T00:00:00Z".into(),
        host: HostInfo {
            hostname: "h".into(),
            os: if cfg!(windows) { "windows" } else { "linux" }.into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        core: CoreInfo {
            version: "0".into(),
            build: "d".into(),
        },
        plugins: Vec::new(),
        body: PlanBody {
            actions: targets
                .iter()
                .enumerate()
                .map(|(i, t)| Action {
                    seq: i as u32 + 1,
                    op: Op::FileQuarantineOnly,
                    target: Some(t.to_string()),
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
                })
                .collect(),
            verdicts: vec!["g0".into()],
            observation: Observation::default(),
            deferred: Vec::new(),
            verify_after_reboot: false,
            submit_hint: None,
        },
    }
}

#[test]
fn what_remedy_quarantines_remedy_can_restore() {
    let lab = Lab::new("basic");

    // 바이트열을 일부러 다양하게 둔다 — 0바이트, 이진, 비ASCII.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("updater.exe", (0u8..=255).cycle().take(8192).collect()),
        ("설정 파일.dat", "한글 · 탭\t줄바꿈\n끝".as_bytes().to_vec()),
        ("empty.bin", Vec::new()),
    ];
    let targets: Vec<String> = cases
        .iter()
        .map(|(name, body)| lab.file(name, body))
        .collect();
    let refs: Vec<&str> = targets.iter().map(String::as_str).collect();

    // ── 격리 ───────────────────────────────────────────────────
    let ex = Executor::new(&FsRestore, lab.state());
    let report = ex.apply(&plan_for(&refs)).expect("격리");
    assert_eq!(report.done(), 3, "{:?}", report.body.results);
    for t in &targets {
        assert!(
            !std::path::Path::new(t).exists(),
            "{t} 가 제자리에 남아 있다"
        );
    }

    // ── 복원 ───────────────────────────────────────────────────
    let bytes = std::fs::read(report.container.as_ref().expect("컨테이너")).expect("읽기");
    let sealed = remedy_core::restore::peek(&bytes).expect("헤더");
    let key = remedy_core::restore::unlock(
        &sealed.header,
        &remedy_core::restore::KeySource {
            state_dir: Some(lab.state()),
            ..Default::default()
        },
    )
    .expect("로컬 키로 열린다");
    let opened = sealed.unlock(&key).expect("색인");

    let plan = remedy_core::restore::plan(
        &opened,
        &sealed.header.run_id,
        &FsRestore,
        &remedy_core::restore::Guards {
            protected: &remedy_core::restore::default_protected(),
            vouched: &Default::default(),
        },
        &[],
        None,
    )
    .expect("복원 계획");
    assert_eq!(plan.allowed().count(), 3, "{:?}", plan.items);

    let out = remedy_core::restore::apply(&plan, &opened, &key, &FsRestore).expect("복원");
    assert_eq!(out.len(), 3);
    for o in &out {
        assert!(o.result.is_ok(), "{:?}", o.result);
    }

    // ── 원본 일치 ──────────────────────────────────────────────
    for ((name, body), path) in cases.iter().zip(targets.iter()) {
        let got = std::fs::read(path).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(&got, body, "{name}: 바이트가 달라졌다");
    }
}

#[test]
fn a_restore_puts_it_back_where_it_was_not_somewhere_else() {
    // 불변식 R — 컨테이너에 적힌 절대 경로 그대로다. 한 글자라도 다르면
    // 사용자는 파일이 사라진 채로 "복원했습니다" 를 듣는다.
    let lab = Lab::new("exactpath");
    let deep = lab.dir.join("a").join("b");
    std::fs::create_dir_all(&deep).unwrap();
    let target = deep.join("payload.bin").to_string_lossy().to_string();
    std::fs::write(&target, b"exact").unwrap();

    let ex = Executor::new(&FsRestore, lab.state());
    let report = ex.apply(&plan_for(&[&target])).expect("격리");

    // 원본이 있던 디렉터리까지 지워 본다 — 복원이 다시 만들어야 한다.
    std::fs::remove_dir_all(lab.dir.join("a")).unwrap();

    let bytes = std::fs::read(report.container.unwrap()).unwrap();
    let sealed = remedy_core::restore::peek(&bytes).unwrap();
    let key = remedy_core::restore::unlock(
        &sealed.header,
        &remedy_core::restore::KeySource {
            state_dir: Some(lab.state()),
            ..Default::default()
        },
    )
    .unwrap();
    let opened = sealed.unlock(&key).unwrap();
    let plan = remedy_core::restore::plan(
        &opened,
        "r",
        &FsRestore,
        &remedy_core::restore::Guards {
            protected: &remedy_core::restore::default_protected(),
            vouched: &Default::default(),
        },
        &[],
        None,
    )
    .unwrap();
    assert_eq!(plan.items[0].dest, target, "복원 대상이 원본 경로와 다르다");

    remedy_core::restore::apply(&plan, &opened, &key, &FsRestore).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"exact");
}

#[test]
fn a_container_with_an_org_wrap_survives_losing_the_machine_key() {
    // 머신을 재설치하면 로컬 키가 사라진다. 그때 내용을 되찾는 경로가
    // 조직 복구 키다 (설계-03 §5).
    let lab = Lab::new("orgkey");
    let target = lab.file("문서.hwp", "사용자 문서".as_bytes());
    let (org_sk, org_pk) = remedy_quarantine::generate_org_keypair().unwrap();

    let ex = Executor::new(&FsRestore, lab.state()).with_keys(KeyPolicy {
        passphrase: None,
        org_public: Some(org_pk),
    });
    let report = ex.apply(&plan_for(&[&target])).expect("격리");

    // 재설치 — 머신 키를 잃는다.
    std::fs::remove_file(lab.state().join("machine.key")).unwrap();

    let bytes = std::fs::read(report.container.unwrap()).unwrap();
    let sealed = remedy_core::restore::peek(&bytes).unwrap();
    let key = remedy_core::restore::unlock(
        &sealed.header,
        &remedy_core::restore::KeySource {
            org_secret: Some(org_sk),
            state_dir: Some(lab.state()),
            ..Default::default()
        },
    )
    .expect("조직 키로 열려야 한다");
    let opened = sealed.unlock(&key).unwrap();
    assert_eq!(
        opened.read("e0", &key).unwrap().content,
        "사용자 문서".as_bytes()
    );
}
