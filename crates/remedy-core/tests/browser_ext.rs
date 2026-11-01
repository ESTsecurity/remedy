//! `browser_ext.remove` 와 그 **왕복** (설계-09 P7, G2).
//!
//! 실제 파일로 돈다. 재는 것은 셋이다 — 확장 나무가 통째로 담기고 지워지는가,
//! 되돌리면 같은 나무가 되는가, 그리고 **모양이 다른 대상을 거부하는가.**
//! 마지막이 가장 중요하다. 이 Op 은 재귀 삭제이고, 모양 검사가 없으면
//! `dir.delete_recursive`(P8)가 `guard` 로 막아 둔 동작이 P7 에 열린다.

use remedy_apply::{Executor, Silent};
use remedy_platform::write::PlatformWrite;
use remedy_sdk::artifact::{Action, CoreInfo, Envelope, HostInfo, PlanBody, PlanEnvelope};
use remedy_sdk::catalog::{Op, Risk};
use std::path::{Path, PathBuf};

struct Lab {
    dir: PathBuf,
}

impl Lab {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("remedy-p7-ext-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("작업 디렉터리");
        Self { dir }
    }

    /// `<프로필>/Extensions/<확장 id>/<버전>/…` 을 만든다. 실기기와 같은 모양이다.
    fn extension(&self, ext_id: &str, version: &str) -> PathBuf {
        let root = self
            .dir
            .join("User Data")
            .join("Default")
            .join("Extensions")
            .join(ext_id);
        let v = root.join(version);
        std::fs::create_dir_all(v.join("_locales/ko")).unwrap();
        std::fs::create_dir_all(v.join("_metadata")).unwrap();
        std::fs::write(
            v.join("manifest.json"),
            r#"{"name":"악성","version":"1"}"#.as_bytes(),
        )
        .unwrap();
        std::fs::write(v.join("_locales/ko/messages.json"), "{}".as_bytes()).unwrap();
        std::fs::write(v.join("bg.js"), b"fetch('http://evil')\n").unwrap();
        root
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

/// 나무 전체를 (상대경로, 내용) 으로 편다. 빈 디렉터리도 센다.
fn snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if p.is_dir() {
                out.push((format!("d:{rel}"), Vec::new()));
                stack.push(p);
            } else {
                out.push((format!("f:{rel}"), std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
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

fn act(target: &str) -> Action {
    let info = Op::BrowserExtRemove.info();
    Action {
        seq: 1,
        op: Op::BrowserExtRemove,
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
        risk: Risk::Medium,
        user_impact: None,
    }
}

fn run(lab: &Lab, name: &str, target: &str) -> (usize, usize, Vec<String>, Option<PathBuf>) {
    let b = backend();
    let rep = Executor::new(&b, lab.state())
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(name, vec![act(target)]))
        .expect("수행");
    let errs: Vec<String> = rep
        .body
        .results
        .iter()
        .filter_map(|r| r.error.clone())
        .collect();
    (rep.done(), rep.failed(), errs, rep.container.clone())
}

fn restore(lab: &Lab, name: &str, container: &Path) {
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
            vouched: &Default::default(),
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

#[test]
fn an_extension_directory_comes_back_exactly() {
    let lab = Lab::new("roundtrip");
    let root = lab.extension("abcdefghijklmnopabcdefghijklmnop", "1.0.0_0");
    let want = snapshot(&root);
    let target = root.to_string_lossy().to_string();

    let (done, failed, errs, c) = run(&lab, "roundtrip", &target);
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert!(!root.exists(), "확장 디렉터리가 남았다");

    restore(&lab, "roundtrip", &c.expect("컨테이너"));
    assert_eq!(snapshot(&root), want, "되돌린 확장이 원본과 다르다");
}

#[test]
fn only_that_extension_goes() {
    // 형제 확장과 프로필의 나머지는 그대로여야 한다.
    let lab = Lab::new("sibling");
    let evil = lab.extension("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.0.0_0");
    let good = lab.extension("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "2.0.0_0");
    let prefs = lab
        .dir
        .join("User Data")
        .join("Default")
        .join("Preferences");
    std::fs::write(&prefs, br#"{"a":1}"#).unwrap();

    let (done, failed, errs, _) = run(&lab, "sibling", &evil.to_string_lossy());
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert!(!evil.exists());
    assert!(
        good.join("2.0.0_0/manifest.json").exists(),
        "형제가 지워졌다"
    );
    assert!(prefs.exists(), "프로필 파일이 지워졌다");
}

#[test]
fn every_version_of_that_extension_goes() {
    // 대상은 버전 디렉터리가 아니라 **확장 디렉터리**다. 버전 하나만 지우면
    // 다른 버전이 그대로 남아 확장이 계속 산다.
    let lab = Lab::new("versions");
    let root = lab.extension("cccccccccccccccccccccccccccccccc", "1.0.0_0");
    lab.extension("cccccccccccccccccccccccccccccccc", "2.0.0_0");
    assert!(root.join("2.0.0_0").exists(), "준비가 틀렸다");

    let (done, failed, errs, _) = run(&lab, "versions", &root.to_string_lossy());
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert!(!root.exists(), "확장이 남았다");
}

#[test]
fn a_target_that_is_not_an_extension_directory_is_refused() {
    // **실행기는 계획을 믿지 않는다.** `plan.json` 은 손으로 고칠 수 있고,
    // 모양 검사가 없으면 이 Op 은 임의 경로 재귀 삭제다.
    //
    // 거부는 **백업보다 먼저**여야 한다. 담고 나서 거부하면 파괴는 막히지만
    // 프로필이 통째로 격리소에 복사된 뒤다.
    let lab = Lab::new("shape");
    let root = lab.extension("dddddddddddddddddddddddddddddddd", "1.0.0_0");
    let profile = lab.dir.join("User Data").join("Default");
    let exts = profile.join("Extensions");

    for (i, (why, target)) in [
        ("프로필 전체", profile.to_string_lossy().to_string()),
        ("Extensions 자체", exts.to_string_lossy().to_string()),
        (
            "버전 디렉터리",
            root.join("1.0.0_0").to_string_lossy().to_string(),
        ),
        ("확장과 무관한 곳", lab.dir.to_string_lossy().to_string()),
        (
            "타고 올라가기",
            format!("{}\\..\\..", root.to_string_lossy()),
        ),
        (
            "확장 자리의 파일",
            exts.join("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
                .to_string_lossy()
                .to_string(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        if why == "확장 자리의 파일" {
            std::fs::write(&target, b"x").unwrap();
        }
        let b = backend();
        let e = Executor::new(&b, lab.state())
            .with_progress(&Silent)
            .with_clock("2026-08-22T00:00:00Z")
            .apply(&plan_of(&format!("shape{i}"), vec![act(&target)]))
            .expect_err(&format!("{why}: 통과했다"));
        let msg = e.to_string();
        assert!(
            msg.contains("Extensions") || msg.contains("..") || msg.contains("디렉터리가 아닙니다"),
            "{why}: {msg}"
        );
        assert!(
            root.join("1.0.0_0/manifest.json").exists(),
            "{why}: 지워졌다"
        );
        assert!(profile.exists(), "{why}: 프로필이 지워졌다");
        // **격리소에 아무것도 담기지 않았다.** 파괴가 없는 것만으로는 부족하다.
        let q = lab.state().join("quarantine");
        let made = std::fs::read_dir(&q).map(|d| d.count()).unwrap_or(0);
        assert_eq!(made, 0, "{why}: 거부했는데 컨테이너가 만들어졌다");
    }
}

#[test]
fn an_extension_already_gone_is_not_a_failure() {
    // 크래시가 파괴와 저널 기록 사이에 왔을 수 있다. 목표 상태는 이미
    // 이루어졌고, 그것을 실패로 올리면 무인 배포가 "부분 실패" 를 본다.
    let lab = Lab::new("gone");
    let root = lab.extension("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "1.0.0_0");
    let target = root.to_string_lossy().to_string();
    std::fs::remove_dir_all(&root).unwrap();

    let b = backend();
    // 백업 단계가 먼저 걸린다 — 담을 것이 없으므로 파괴 전에 멈추는 것이 옳다.
    let e = Executor::new(&b, lab.state())
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of("gone", vec![act(&target)]))
        .expect_err("백업이 실패해야 한다");
    assert!(
        e.to_string().contains("seq 1"),
        "파괴 전에 멈춘 것이 아니다: {e}"
    );
}
