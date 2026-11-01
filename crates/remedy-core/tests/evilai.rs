//! 첫 플러그인이 **물 수 있는가** (설계-09 P9).
//!
//! 청정 코퍼스에서 아무것도 나오지 않는 것은 절반이다. G1(`corpus.rs`)은 그쪽만
//! 잰다. 룰이 통째로 죽어도 청정 검사는 초록이므로, **나와야 할 때 나오는지**를
//! 여기서 잰다.
//!
//! # 여기서 재지 않는 것 — 룰의 정확도
//!
//! 그것은 실검체가 필요하고 검체는 저장소 밖에 있다. `cargo xtask yara` 가 그
//! 몫이다.
//! 여기서 재는 것은 **배선**이다 — 스냅샷의 바이트가 YARA 까지 닿고, 판정이
//! 서고, 계획이 도출되는가.
//!
//! 그래서 페이로드 바이트를 검체에서 가져오지 않고 **룰 파일에서 만든다.**
//! 저장소에 악성코드를 넣지 않으면서 룰이 실제로 발화하는지 볼 수 있다.

use remedy_artifacts::record::WinTaskFields;
use remedy_artifacts::{
    AutorunRecord, AvExclusionRecord, FileRecord, Observations, PersistenceRecord, ProcessRecord,
    Scope, WinTask,
};
use remedy_sdk::artifact::{ArtifactsEnvelope, CoreInfo, HostInfo};
use remedy_sdk::catalog::{Op, Platform, Subject};
use remedy_sdk::manifest::PluginManifest;
use std::path::{Path, PathBuf};

const PROGRAMS: &str = "C:\\Users\\test\\AppData\\Local\\Programs";
const PAYLOAD_DIR: &str = "C:\\Users\\test\\AppData\\Local\\Programs\\SystemSoftwareUpdaterV2-q5ty";
const NODE: &str = "C:\\Program Files\\nodejs\\node.exe";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("저장소 루트")
}

fn plugin_dir() -> PathBuf {
    repo_root().join("plugins/evilai-locust")
}

fn manifest() -> PluginManifest {
    let p = plugin_dir().join("plugin.yaml");
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_yaml_ng::from_str(&text).unwrap_or_else(|e| panic!("매니페스트가 파싱되지 않는다: {e}"))
}

/// 제품 CLI 의 `load_rules` 와 같은 규칙 — 이름은 `rules/<파일>.yar` 이다.
fn rules() -> Vec<(String, String)> {
    let dir = plugin_dir().join("rules");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir).expect("rules 디렉터리").flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("yar")) {
            let name = format!("rules/{}", p.file_name().unwrap().to_string_lossy());
            out.push((name, std::fs::read_to_string(&p).expect("룰 파일")));
        }
    }
    out.sort();
    assert!(!out.is_empty(), "rules 디렉터리에서 .yar 을 읽지 못했다");
    out
}

/// 룰이 발화하는 바이트를 **룰 파일에서** 만든다.
///
/// 상수를 시험에 베껴 두면 룰만 고쳤을 때 조용히 어긋난다. 룰이 진실이므로
/// 거기서 꺼낸다.
fn payload_bytes() -> Vec<u8> {
    let yar = std::fs::read_to_string(plugin_dir().join("rules/evilai.yar")).expect("룰 파일");
    // `        $a00 = "'AM9P'" ascii` 에서 큰따옴표 안을 꺼낸다.
    let mut consts = Vec::new();
    for line in yar.lines() {
        let t = line.trim();
        if !t.starts_with("$a") {
            continue;
        }
        let Some(open) = t.find('"') else { continue };
        let Some(close) = t.rfind('"') else { continue };
        if close > open + 1 {
            consts.push(t[open + 1..close].to_string());
        }
    }
    // 임계값은 20 이다. 30 개를 넣어 여유를 두되, 꺼낸 수가 모자라면 시험이
    // 공허해지므로 그 자리에서 멈춘다.
    assert!(
        consts.len() >= 25,
        "룰에서 상수를 {}개밖에 꺼내지 못했다 — 이 시험은 아무것도 재지 못한다",
        consts.len()
    );
    consts.truncate(30);
    format!(
        "'use strict';function R(){{var F=[{}];return F;}}",
        consts.join(",")
    )
    .into_bytes()
}

fn infected() -> (ArtifactsEnvelope, Scope) {
    let script = format!("{PAYLOAD_DIR}\\preload.js");
    let quoted = format!("\"{script}\"");
    let cmdline = format!("\"{NODE}\" {quoted}");

    let mut sc = Scope::diagnostic(
        vec!["C:\\Windows\\System32\\Tasks".into(), PROGRAMS.into()],
        Platform::Windows,
    );
    sc.subjects = vec![
        Subject::Persistence,
        Subject::File,
        Subject::Autorun,
        Subject::Process,
        Subject::AvExclusion,
    ];

    let mut o = Observations::default();

    o.put(
        Subject::Persistence,
        &[PersistenceRecord {
            // `id` 는 전체 등록 경로, `register_path` 는 **폴더**다 (후행 `\`).
            id: "\\Microsoft\\Windows\\Locust".into(),
            name: "Locust".into(),
            enabled: true,
            trigger: vec!["logon".into()],
            command: NODE.into(),
            args: quoted.clone(),
            principal: None,
            source: "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\Locust".into(),
            linux: None,
            win: Some(WinTask {
                task: WinTaskFields {
                    register_path: "\\Microsoft\\Windows\\".into(),
                    actions: vec!["exec".into()],
                    run_level: None,
                    working_directory: None,
                },
            }),
        }],
    );

    let bytes = payload_bytes();
    let key = "sha256:evilai-test-payload";
    o.put(
        Subject::File,
        &[FileRecord {
            path: script.clone(),
            size: bytes.len() as u64,
            mtime: "2026-08-20T00:00:00Z".into(),
            ctime: None,
            sha256: None,
            signature: None,
            version: None,
            zone: None,
            streams: Vec::new(),
            content_ref: Some(key.into()),
        }],
    );
    {
        use base64::Engine;
        o.blobs.insert(
            key.into(),
            base64::engine::general_purpose::STANDARD.encode(&bytes),
        );
    }

    o.put(
        Subject::Process,
        &[ProcessRecord {
            pid: 4242,
            ppid: 1000,
            image_path: NODE.into(),
            cmdline: cmdline.clone(),
            cmdline_decoded: cmdline.clone(),
            args: quoted.clone(),
            user: "test".into(),
            start_time: "2026-08-20T00:00:00Z".into(),
            modules: Vec::new(),
        }],
    );

    o.put(
        Subject::Autorun,
        &[AutorunRecord {
            id: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater".into(),
            scope: "user".into(),
            name: "Updater".into(),
            command: cmdline,
            source: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
        }],
    );

    o.put(
        Subject::AvExclusion,
        &[AvExclusionRecord {
            kind: "path".into(),
            // **제외 대상은 값 이름이고 `source` 는 그것이 사는 키다.**
            // 계획기가 `source\value` 로 대상을 만들어 G6 이 레지스트리 값 경로로
            // 대조하므로, 여기에 짧은 이름을 넣으면 절대 경로가 아니라며 막힌다.
            // 수집기(`registry.rs::av_exclusions`)가 넣는 것과 같은 전체 키다.
            value: PAYLOAD_DIR.into(),
            source: "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths".into(),
        }],
    );

    let env = remedy_artifacts::assemble(
        "test-run".into(),
        "2026-08-20T00:00:00Z".into(),
        HostInfo {
            hostname: "LAB".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        CoreInfo {
            version: "0".into(),
            build: "test".into(),
        },
        &sc,
        o,
    );
    (env, sc)
}

#[test]
fn the_manifest_parses_and_has_no_blocking_issues() {
    let m = manifest();
    assert_eq!(m.id, "evilai-locust");
    // 선언한 subject 를 전부 쓰는가. 쓰지 않을 것을 선언해 두면 권한 상한만
    // 넓히고 아무 능력도 얻지 못한다.
    let used: std::collections::BTreeSet<_> = m.detect.iter().map(|r| r.subject).collect();
    for s in &m.subjects {
        assert!(
            used.contains(s),
            "subject '{}' 를 선언해 두고 detect 에서 쓰지 않는다",
            s.id()
        );
    }
    // 서명 주체를 본 적이 없으므로 비어 있어야 한다 (설계-04 §2 정정).
    assert!(
        m.signed_malware.is_empty(),
        "본 적 없는 서명 주체가 열거돼 있다"
    );

    let issues = remedy_sdk::validate(&m);
    let blocking: Vec<_> = issues.iter().filter(|i| i.available_in.is_none()).collect();
    assert!(
        blocking.is_empty(),
        "매니페스트에 차단 문제가 있다: {blocking:?}"
    );
}

#[test]
fn an_infected_snapshot_produces_the_removal_it_should() {
    let m = manifest();
    let (env, _sc) = infected();
    let scan = remedy_core::pipeline::evaluate_with_rules(&env, &m, &rules()).expect("평가");

    assert!(
        !scan.body.verdicts.is_empty(),
        "감염 스냅샷에서 판정이 서지 않았다 — issues: {:?}",
        scan.body.issues
    );

    let plan = remedy_core::plan(&scan, Some(&m)).expect("계획");
    let ops: std::collections::BTreeSet<Op> = plan.body.actions.iter().map(|a| a.op).collect();
    let dump = || {
        format!(
            "actions={:?}\ndeferred={:?}",
            plan.body
                .actions
                .iter()
                .map(|a| (a.seq, a.op.id(), a.target.clone()))
                .collect::<Vec<_>>(),
            plan.body
                .deferred
                .iter()
                .map(|d| d.reason.clone())
                .collect::<Vec<_>>()
        )
    };

    // **P8 이 만든 process.kill 이 실제 플러그인에서 닿는가** (설계-09 P9 finding F).
    // 초안은 subject 만 선언하고 규칙이 없어 이 Op 이 어떤 계획에도 들어갈 수
    // 없었다.
    assert!(
        ops.contains(&Op::ProcessKill),
        "process.kill 이 계획되지 않았다.\n{}",
        dump()
    );
    assert!(
        ops.contains(&Op::PersistenceDelete),
        "persistence.delete 가 계획되지 않았다.\n{}",
        dump()
    );
    assert!(
        ops.contains(&Op::PersistenceDisable),
        "persistence.disable 이 계획되지 않았다 — 택일이 아니라 순차여야 한다.\n{}",
        dump()
    );
    assert!(
        ops.contains(&Op::AutorunRemove),
        "autorun.remove 가 계획되지 않았다.\n{}",
        dump()
    );

    // 프로세스는 대상이 비고 술어가 고정한다. PID 는 계획 시점과 실행 시점
    // 사이에 바뀐다 (설계-03 §1).
    let kill = plan
        .body
        .actions
        .iter()
        .find(|a| a.op == Op::ProcessKill)
        .expect("process.kill");
    assert!(kill.target.is_none(), "process.kill 에 고정 대상이 실렸다");
    assert!(kill.r#match.is_some(), "process.kill 에 술어가 없다");

    // 순서: 종료(2단계)가 비활성화(3단계)보다 먼저다.
    let seq_of = |op: Op| plan.body.actions.iter().find(|a| a.op == op).map(|a| a.seq);
    assert!(
        seq_of(Op::ProcessKill) < seq_of(Op::PersistenceDisable),
        "프로세스 종료가 작업 비활성화보다 나중이다.\n{}",
        dump()
    );
}

#[test]
fn the_release_record_exists_and_matches_the_manifest_version() {
    // **출시 게이트 기록이 낡으면 "통과했다" 가 그대로 거짓이 된다.**
    //
    // 설계-03 §10 은 모든 플러그인이 배포 전 G1~G9 를 통과할 것을 요구하고,
    // G9 는 v1 동안 수동이라 사람이 결과를 적는다. 손으로 적는 것은 잊히므로,
    // **버전이 오르면 기록도 함께 갱신하도록** 여기서 묶는다. 판정 내용까지는
    // 재지 않는다 — 그것은 사람이 읽고 판단할 것이고, 여기서 재려 들면
    // 문서의 문구가 사실상 API 가 된다.
    let m = manifest();
    let p = plugin_dir().join("RELEASE.md");
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "{}: {e}\n출시 게이트 기록이 없다. 배포 전 G1~G9 통과 기록을 남길 것 (설계-03 §10).",
            p.display()
        )
    });
    assert!(
        text.contains(&m.version),
        "RELEASE.md 에 매니페스트 버전 '{}' 이 없다 — 기록이 낡았다.\n\
         버전을 올렸다면 그 릴리스의 게이트 결과를 다시 적을 것.",
        m.version
    );
}

#[test]
fn 페이로드_디렉터리가_계획에_들어간다() {
    // **P10-C 에서 열렸다.** 이전에는 `dir.delete_recursive` 가 계획에 들어가지
    // 못해 빈 폴더가 남았고, 그 사실이 `deferred` 로 보고됐다(P9 §2 표 1번).
    //
    // 이제 들어간다. 그러려면 계획기 가드 셋을 모두 통과해야 한다 — 대상이
    // 증거에서 파생된 경로인가, 그 안에서 악성으로 판정된 것이 있는가, 보호
    // 목록과 교차하지 않는가 (설계-03 §4). 네 번째 조건(하위 신뢰 서명)은
    // 실행 시점에야 알 수 있어 실행기가 본다.
    let m = manifest();
    let (env, _sc) = infected();
    let scan = remedy_core::pipeline::evaluate_with_rules(&env, &m, &rules()).expect("평가");
    let plan = remedy_core::plan(&scan, Some(&m)).expect("계획");

    let ops: Vec<Op> = plan.body.actions.iter().map(|a| a.op).collect();
    assert!(
        ops.contains(&Op::DirDeleteRecursive),
        "재귀 삭제가 계획에 없다 — 가드에 걸렸을 수 있다: {:?}",
        plan.body.deferred
    );

    // 그 Action 이 겨누는 것이 페이로드 디렉터리여야 한다. 다른 곳을 겨눈
    // 재귀 삭제가 통과하면 그것이 이 Op 을 P10 까지 미룬 이유 그 자체다.
    let target = plan
        .body
        .actions
        .iter()
        .find(|a| a.op == Op::DirDeleteRecursive)
        .and_then(|a| a.target.as_deref())
        .unwrap_or_default();
    assert!(
        target.contains("Programs"),
        "재귀 삭제가 엉뚱한 곳을 겨눈다: {target:?}"
    );
}
