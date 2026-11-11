//! 평가기 의미 검증 (설계-02 §4·§5, 설계-09 P2).
//!
//! 여기서 가장 중요한 것은 **증거 그룹이 실제로 격리되는가** 다. 그룹이 새면
//! 서로 무관한 두 정상 소프트웨어의 조각이 합쳐져 감염 판정을 만든다.

use remedy_artifacts::{
    BootConfigRecord, FileRecord, Observations, PackageRecord, PersistenceRecord, Scope, WinTask,
};
use remedy_detect::{evaluate, Snapshot};
use remedy_sdk::artifact::{ArtifactsEnvelope, CoreInfo, HostInfo};
use remedy_sdk::catalog::{Platform, Subject};
use remedy_sdk::manifest::PluginManifest;

const ROOT: &str = "c:\\users\\t\\appdata\\local\\programs";

fn file(path: &str) -> FileRecord {
    FileRecord {
        path: path.into(),
        size: 10,
        mtime: "2026-08-20T00:00:00Z".into(),
        ctime: None,
        sha256: None,
        signature: None,
        version: None,
        zone: None,
        streams: Vec::new(),
        content_ref: None,
        package: String::new(),
        package_match: String::new(),
    }
}

fn task(name: &str, dir: &str) -> PersistenceRecord {
    PersistenceRecord {
        id: format!("\\Microsoft\\Windows\\{name}"),
        name: name.into(),
        enabled: true,
        trigger: vec!["logon".into()],
        command: "c:\\program files\\nodejs\\node.exe".into(),
        // 설계-02 §4 예시의 정규식 `(?i)\.js(\s|$)` 은 .js 뒤에 공백이나 문자열 끝을
        // 요구한다. 따옴표로 감싼 인자(`"...main.js" --run`)는 그 룰이 놓친다.
        // 룰의 성질이지 엔진의 문제가 아니므로, 여기서는 룰이 기대하는 형태를 쓴다.
        args: format!("{dir}\\main.js --run"),
        principal: Some("SYSTEM".into()),
        source: format!("c:\\windows\\system32\\tasks\\microsoft\\windows\\{name}"),
        linux: None,
        win: Some(WinTask {
            task: remedy_artifacts::record::WinTaskFields {
                register_path: "\\Microsoft\\Windows\\".into(),
                actions: vec!["exec".into()],
                run_level: None,
                working_directory: None,
                command_expanded: None,
                args_expanded: None,
            },
        }),
    }
}

fn scope() -> Scope {
    Scope::diagnostic(vec![ROOT.into()], Platform::Windows)
}

/// 두 subject 만 담은 관찰. `Observations` 는 subject 키 맵이라 구조체
/// 리터럴로 쓸 수 없다 — subject 가 늘어도 시험이 따라 늘지 않게 하려는 것이
/// 그 모양의 목적이다.
fn observations(files: Vec<FileRecord>, persistence: Vec<PersistenceRecord>) -> Observations {
    let mut o = Observations::default();
    o.put(Subject::File, &files);
    o.put(Subject::Persistence, &persistence);
    o
}

fn snapshot(obs: Observations) -> ArtifactsEnvelope {
    remedy_artifacts::assemble(
        "r".into(),
        "2026-08-20T00:00:00Z".into(),
        HostInfo {
            hostname: "H".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        CoreInfo {
            version: "0".into(),
            build: "d".into(),
        },
        &scope(),
        obs,
    )
}

/// EvilAI 형태의 룰. 작업이 가리킨 폴더 안에서만 페이로드를 찾는다.
const MANIFEST: &str = r#"
schema_version: 1
id: sample
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name: { ko: "예시", en: "Sample" }
scan_roots: ["c:\\users\\t\\appdata\\local\\programs"]
subjects: [persistence, file]
detect:
  - id: task
    subject: persistence
    where:
      all:
        - { field: command, op: matches, value: "(?i)\\\\node\\.exe$" }
        - { field: args,    op: matches, value: "(?i)\\.js(\\s|$)" }
    capture:
      script_path: "args | first_path"
      payload_dir: "${script_path} | dirname"
  - id: payload
    subject: file
    from: "${task.payload_dir}"
    where:
      - { field: path, op: ends_with, value: "\\evil.js" }
verdict:
  require: "task and payload"
"#;

fn manifest(yaml: &str) -> PluginManifest {
    serde_yaml_ng::from_str(yaml).expect("매니페스트 파싱")
}

// ─────────────────────────────────────────── 부팅 구성

/// 안전 모드가 **막혔다**는 것을 룰이 근거로 쓸 수 있는가.
///
/// 이 자리는 오래 비어 있었다. 카탈로그에 `boot_config` subject 와
/// `safeboot_available` 필드가 있었지만 **그것을 보는 룰도 시험도 없었고**,
/// 관측 쪽은 접근 거부를 "없다" 로 접고 있어 잠긴 기계와 지워진 기계가 같은
/// 값을 냈다. 관측이 갈라진 지금, 룰이 그 값에 닿는지를 여기서 잰다.
const BOOT_MANIFEST: &str = r#"
schema_version: 1
id: safeboot-blocked
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name: { ko: "안전 모드 차단", en: "safe mode blocked" }
scan_roots: ["c:\\users\\t\\appdata\\local\\programs"]
subjects: [boot_config]
detect:
  - id: blocked
    subject: boot_config
    where:
      - { field: safeboot_available, op: equals, value: "unreadable" }
verdict:
  require: "blocked"
"#;

fn boot(safeboot: &str) -> BootConfigRecord {
    BootConfigRecord {
        entry: "{current}".into(),
        recoveryenabled: "unknown".into(),
        safeboot_available: safeboot.into(),
    }
}

/// **범위가 subject 를 가른다.** `assemble` 은 `scope.subjects` 에 없는 subject 를
/// 스냅샷에 담지 않는다 — 선언한 것만 보는 상한이다(설계-02 §8). 진단 범위는
/// `file`·`persistence` 둘뿐이므로 부팅 구성을 재려면 그것을 선언해야 한다.
fn boot_scope() -> Scope {
    let mut s = scope();
    s.subjects.push(Subject::BootConfig);
    s
}

fn boot_snapshot(safeboot: &str) -> ArtifactsEnvelope {
    let mut o = Observations::default();
    o.put(Subject::BootConfig, &[boot(safeboot)]);
    remedy_artifacts::assemble(
        "r".into(),
        "2026-08-20T00:00:00Z".into(),
        HostInfo {
            hostname: "H".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        CoreInfo {
            version: "0".into(),
            build: "d".into(),
        },
        &boot_scope(),
        o,
    )
}

#[test]
fn a_rule_can_see_that_safe_mode_is_locked() {
    let env = boot_snapshot("unreadable");
    let body = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(BOOT_MANIFEST),
        &boot_scope(),
    )
    .unwrap();
    assert_eq!(
        body.verdicts.len(),
        1,
        "잠긴 것을 판정하지 못했다: {:?}",
        body.verdicts
    );
}

// ─────────────────────────────────────────── 버전 비교

/// 취약 버전 점검의 모양 그대로다 — **수정판 미만이면 취약**.
///
/// `browser_extension.version` 을 고른 이유는 그것이 지금 **채워지는 유일한
/// 버전 필드**라는 데 있다(`Subject::fields`). PHP 바이너리의 버전은 아직
/// 필드가 없어 이 연산자로 닿지 못한다 — 그 자리는 PE 버전 필드가 필요하다.
const VERSION_MANIFEST: &str = r#"
schema_version: 1
id: vulnerable-extension
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
kind: check
name: { ko: "취약 확장", en: "vulnerable extension" }
scan_roots: ["c:\\users\\t\\appdata\\local\\programs"]
subjects: [browser_extension]
detect:
  - id: old
    subject: browser_extension
    where:
      all:
        - { field: ext_id,  op: equals,     value: "abc" }
        - { field: version, op: version_lt, value: "8.2.29" }
verdict:
  require: "old"
"#;

fn ext(version: &str) -> remedy_artifacts::BrowserExtensionRecord {
    remedy_artifacts::BrowserExtensionRecord {
        browser: "chrome".into(),
        profile: "Default".into(),
        ext_id: "abc".into(),
        name: "X".into(),
        version: version.into(),
        path: format!("{ROOT}\\abc"),
    }
}

fn ext_scope() -> Scope {
    let mut s = scope();
    s.subjects.push(Subject::BrowserExtension);
    s
}

fn ext_snapshot(version: &str) -> ArtifactsEnvelope {
    let mut o = Observations::default();
    o.put(Subject::BrowserExtension, &[ext(version)]);
    remedy_artifacts::assemble(
        "r".into(),
        "2026-08-20T00:00:00Z".into(),
        HostInfo {
            hostname: "H".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        CoreInfo {
            version: "0".into(),
            build: "d".into(),
        },
        &ext_scope(),
        o,
    )
}

fn ext_eval(version: &str) -> remedy_sdk::artifact::ScanBody {
    ext_eval_with(version, VERSION_MANIFEST)
}

fn ext_eval_with(version: &str, yaml: &str) -> remedy_sdk::artifact::ScanBody {
    let env = ext_snapshot(version);
    evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(yaml),
        &ext_scope(),
    )
    .unwrap()
}

// ─────────────────────────────────────────── 확인 필요 (`verdict.unconfirmed` · 2026-11-09)

/// 위 룰에 **"있는데 고쳤는지 모른다"** 를 더한 모양 — 고친 판 이상이면 *확인 필요* 다.
fn review_manifest() -> String {
    VERSION_MANIFEST
        .replace("min_core: \"1.0.0\"", "min_core: \"1.3.0\"")
        .replace(
            "verdict:\n  require: \"old\"\n",
            "  - id: present\n    subject: browser_extension\n    where:\n      \
             - { field: ext_id, op: equals, value: \"abc\" }\n\
             verdict:\n  require: \"old\"\n  unconfirmed:\n    - when: \"present\"\n      \
             why: { ko: \"고친 빌드인지 가릴 근거가 없습니다\", en: \"no basis to tell a fixed build\" }\n",
        )
}

#[test]
fn an_unconfirmed_line_stands_only_where_no_verdict_does() {
    let yaml = review_manifest();
    // 고친 판 이상 — 판정은 서지 않고 *확인 필요* 가 선다.
    let body = ext_eval_with("8.2.30", &yaml);
    assert!(body.verdicts.is_empty(), "{:?}", body.verdicts);
    let notes = &body.observation.unconfirmed;
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0].groups, vec!["g0".to_string()]);
    assert_eq!(
        notes[0].why_in(remedy_sdk::i18n::Lang::En),
        "no basis to tell a fixed build"
    );
    // 식이 짚는 규칙이 산출물에 실린다 — 화면이 그 규칙의 증거만 고른다(2026-11-11).
    assert_eq!(notes[0].rules, vec!["present".to_string()]);
    assert_eq!(body.verdict_rules, vec!["old".to_string()]);
    assert!(!body.observation.is_complete_for_check());

    // **찾은 것이 모르는 것보다 앞선다** — 판정이 선 그룹은 확인 필요로 세지 않는다.
    let body = ext_eval_with("8.2.28", &yaml);
    assert_eq!(body.verdicts.len(), 1);
    assert!(
        body.observation.unconfirmed.is_empty(),
        "{:?}",
        body.observation.unconfirmed
    );
}

#[test]
fn an_unconfirmed_line_naming_a_missing_rule_is_refused() {
    // 서지 않는 줄은 *확인 필요* 를 조용히 0 으로 만든다 — 평가에서도 막는다(린트는 건너뛸 수 있다).
    let yaml = review_manifest().replace("when: \"present\"", "when: \"ghost\"");
    let env = ext_snapshot("8.2.30");
    let err = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(&yaml),
        &ext_scope(),
    )
    .expect_err("없는 규칙을 가리켰다");
    assert!(err.to_string().contains("verdict.unconfirmed"), "{err}");
}

#[test]
fn a_rule_without_unconfirmed_writes_the_same_observation() {
    // 이 칸이 없는 룰은 전과 한 글자도 같다 — 산출물에 키조차 나오지 않는다(불변식 I1).
    let body = ext_eval("8.2.30");
    assert!(body.observation.unconfirmed.is_empty());
    let json = serde_json::to_string(&body.observation).unwrap();
    assert!(!json.contains("unconfirmed"), "{json}");
}

#[test]
fn version_lt_finds_what_lt_could_not() {
    // `8.2.9` 는 수로 읽히지 않아 `lt` 가 *"견줄 수 없습니다"* 로 끝났고,
    // 두 자리로 줄여 적으면 `8.10 < 8.9` 가 되어 **순서가 뒤집혔다**.
    for vulnerable in ["8.2.28", "8.2.9", "8.1.99", "7.9.9", "8.2", "8.02.28"] {
        let body = ext_eval(vulnerable);
        assert!(body.issues.is_empty(), "{vulnerable}: {:?}", body.issues);
        assert_eq!(
            body.verdicts.len(),
            1,
            "{vulnerable} 를 취약으로 보지 못했다"
        );
    }
}

#[test]
fn the_fixed_release_and_anything_newer_is_not_vulnerable() {
    // 성분 수가 달라도 같아야 한다 — 공급사가 `8.2.29` 로 적고 설치본이
    // `8.2.29.0` 으로 보고하면 수정된 기계가 취약으로 나간다.
    for safe in ["8.2.29", "8.2.29.0", "8.2.30", "8.3.0", "9.0.0", "8.2.290"] {
        let body = ext_eval(safe);
        assert!(body.issues.is_empty(), "{safe}: {:?}", body.issues);
        assert!(body.verdicts.is_empty(), "{safe} 를 취약으로 봤다");
    }
}

#[test]
fn a_tail_is_reported_not_guessed() {
    // `8.4.0RC1` 은 `8.4.0` 보다 낮고 `8.2.29-1ubuntu1` 은 `8.2.29` 보다 높다.
    // **조용히 거짓을 내면 취약한 기계가 양호로 나간다** — 어느 쪽인지 모르면
    // 사람이 보게 해야 한다.
    for tail in ["8.2.28-1ubuntu1", "8.2.0RC1", "8.2.28-dev"] {
        let body = ext_eval(tail);
        assert!(body.verdicts.is_empty(), "{tail} 로 판정을 세웠다");
        assert_eq!(body.issues.len(), 1, "{tail}: {:?}", body.issues);
        let i = &body.issues[0];
        assert!(
            i.contains(tail) && i.contains("버전으로 읽지 못했습니다"),
            "관측된 값을 짚지 않았다: {i}"
        );
        // 룰이 적은 값은 버전이다. 그쪽을 짚으면 고칠 자리를 잘못 말한다 —
        // 작성자는 고칠 것이 없는 줄을 고치려 든다.
        assert!(!i.contains("룰이 적은"), "고칠 자리를 잘못 짚었다: {i}");

        // **주의 줄만으로는 모자랐다** (실측 2026-10-27). 화면이 *"버전으로
        // 읽지 못했습니다"* 와 *"취약한 곳을 찾지 못했습니다"* 를 한 번에
        // 말하고 **종료 0** 으로 나갔다 — 무인 배포는 그 줄이 실린 stderr 를
        // 버린다. 관측에 남아야 종료 6 이 된다.
        assert_eq!(
            body.observation.unreadable_versions,
            vec![tail.to_string()],
            "{tail} 이 관측에 남지 않았다 — 종료 0 이 나간다"
        );
        assert!(!body.observation.is_complete(), "{tail}: 완전하다고 했다");
        assert!(
            !body.observation.is_complete_for_check(),
            "{tail}: 점검도 면제가 아니다"
        );
        // 재지 못한 것은 **버전**이다. YARA 칸에 들어가면 화면이 *"YARA 규칙을
        // 평가하지 못했습니다"* 라고 잘못 지목한다.
        assert!(
            body.observation.unevaluated_rules.is_empty(),
            "{tail} 을 YARA 칸에 넣었다"
        );
    }
}

#[test]
fn a_version_written_without_quotes_is_refused_at_evaluation_too() {
    // **린트만으로는 모자랐다** — `scan` 은 린트를 돌리지 않는다. YAML 이
    // 따옴표 없는 `8.10` 을 실수로 읽어 `8.1` 로 도착하고, `is_version("8.1")` 이
    // 참이라 비교를 그냥 지났다: `8.9 < 8.10` 인 취약한 기계가 **진단 한 줄 없이
    // 종료 0** 으로 나갔다(실측 2026-10-27 · 적대 검증 high).
    let y = VERSION_MANIFEST.replace("value: \"8.2.29\"", "value: 8.10");
    let env = ext_snapshot("8.9");
    let body = evaluate(&Snapshot::from_envelope(&env), &manifest(&y), &ext_scope()).unwrap();
    assert!(body.verdicts.is_empty(), "망가진 리터럴로 판정을 세웠다");
    assert!(
        !body.observation.is_complete(),
        "따옴표 없는 리터럴을 조용히 지났다 — 종료 0 이 나간다"
    );
    assert_eq!(body.observation.unreadable_versions.len(), 1);
    assert!(
        body.observation.unreadable_versions[0].starts_with("version: "),
        "라벨이 자리를 짚지 않았다: {:?}",
        body.observation.unreadable_versions
    );
    assert_eq!(body.issues.len(), 1, "{:?}", body.issues);
    assert!(
        body.issues[0].contains("따옴표"),
        "고칠 길을 말하지 않았다: {}",
        body.issues[0]
    );

    // **음성 대조.** 따옴표를 치면 의도한 대로 취약이다.
    let ok = VERSION_MANIFEST.replace("value: \"8.2.29\"", "value: \"8.10\"");
    let body = evaluate(&Snapshot::from_envelope(&env), &manifest(&ok), &ext_scope()).unwrap();
    assert!(body.observation.is_complete(), "{:?}", body.issues);
    assert_eq!(body.verdicts.len(), 1, "8.9 < 8.10 을 놓쳤다");
    // 정수도 왕복한다.
    let int = VERSION_MANIFEST.replace("value: \"8.2.29\"", "value: 9");
    let body = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(&int),
        &ext_scope(),
    )
    .unwrap();
    assert!(body.observation.is_complete(), "{:?}", body.issues);
    assert_eq!(body.verdicts.len(), 1, "8.9 < 9 를 놓쳤다");
}

#[test]
fn version_gt_compares_in_the_other_direction() {
    // **적대 검증(medium)**: `version_gt` 의 방향을 재는 시험이 없어 Greater 를
    // Less 로 바꿔도 전부 초록이었다.
    let y = VERSION_MANIFEST.replace("op: version_lt", "op: version_gt");
    for (v, want) in [("8.2.30", 1usize), ("8.2.29", 0), ("8.2.28", 0)] {
        let env = ext_snapshot(v);
        let body = evaluate(&Snapshot::from_envelope(&env), &manifest(&y), &ext_scope()).unwrap();
        assert_eq!(body.verdicts.len(), want, "version_gt 8.2.29 에 {v}");
    }
}

#[test]
fn an_empty_version_does_not_leave_the_reason_line_dangling() {
    // 관측된 값이 **비어 있으면**(설치본이 `version` 을 비워 둔다) 사유 줄의 끝이
    // 빈 채로 나간다 — `YARA 규칙 1개를 평가하지 못했습니다: ` 를 막으려고 지은
    // `yara_label` 과 같은 규율이다. 읽는 사람이 무엇이 문제인지 알 수 없다.
    let body = ext_eval("");
    assert_eq!(
        body.observation.unreadable_versions,
        vec!["version: \"\"".to_string()],
        "빈 값을 그대로 적었다"
    );
    assert!(!body.observation.is_complete());
    // **두 언어를 다 잰다.** `reasons()` 는 주위 언어(`i18n::current()`)를 따르므로
    // 한쪽만 재면 시험 프로세스의 기본 언어에 결과가 달린다.
    for lang in [remedy_sdk::i18n::Lang::Ko, remedy_sdk::i18n::Lang::En] {
        let reason = body
            .observation
            .reasons_in(lang)
            .into_iter()
            .find(|r| r.contains("version: \"\""))
            .unwrap_or_else(|| panic!("{lang:?}: 사유 줄이 없다"));
        // 사유 줄이 끝에서 끊기지 않는다.
        assert!(
            reason.trim_end().ends_with('"'),
            "{lang:?}: 끝이 비었다: {reason}"
        );
    }
}

#[test]
fn a_version_that_reads_leaves_the_observation_complete() {
    // **음성 대조.** 늘 불완전을 내면 모든 버전 점검이 6 으로 나가 쓸 수 없다.
    for ok in ["8.2.28", "8.2.29", "8.2.30"] {
        let body = ext_eval(ok);
        assert!(
            body.observation.unreadable_versions.is_empty(),
            "{ok}: {:?}",
            body.observation.unreadable_versions
        );
        assert!(body.observation.is_complete(), "{ok}: 불완전이라 했다");
    }
}

#[test]
fn a_locked_machine_and_a_wiped_one_are_not_the_same_evidence() {
    // **이것이 관측을 가른 이유다.** 둘 다 "안전 모드를 못 쓴다" 이지만
    // 무엇을 봤는지가 다르고, 룰은 그 차이에 걸 수 있어야 한다.
    for other in ["no", "partial", "yes", "unknown"] {
        let env = boot_snapshot(other);
        let body = evaluate(
            &Snapshot::from_envelope(&env),
            &manifest(BOOT_MANIFEST),
            &scope(),
        )
        .unwrap();
        assert!(
            body.verdicts.is_empty(),
            "'{other}' 를 'unreadable' 룰이 잡았다"
        );
    }
}

// ─────────────────────────────────────────── 증거 그룹

#[test]
fn two_parents_make_two_isolated_groups() {
    // 작업 2건 -> 그룹 2개. 각 그룹은 **자기 payload_dir 안에서만** 자식을 평가한다.
    let a = format!("{ROOT}\\app-a");
    let b = format!("{ROOT}\\app-b");
    let env = snapshot(observations(
        vec![
            file(&format!("{a}\\evil.js")),
            file(&format!("{b}\\clean.js")),
        ],
        vec![task("A", &a), task("B", &b)],
    ));

    let body = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(MANIFEST),
        &scope(),
    )
    .unwrap();

    assert_eq!(body.groups.len(), 2, "부모 2건이면 그룹 2개");
    assert_eq!(
        body.verdicts.len(),
        1,
        "evil.js 가 있는 그룹만 판정을 통과해야 한다"
    );

    let passed = body.groups.iter().find(|g| g.verdict).expect("통과한 그룹");
    assert_eq!(
        passed.captures.get("task.payload_dir").unwrap(),
        &a,
        "통과한 그룹의 payload_dir 은 A 여야 한다"
    );
    // 통과한 그룹의 payload 증거는 전부 app-a 안에 있어야 한다.
    let payload_paths: Vec<&str> = passed
        .evidence
        .iter()
        .filter_map(|id| body.evidence.iter().find(|x| &x.id == id))
        .filter(|e| e.rule == "payload")
        .filter_map(|e| e.target["path"].as_str())
        .collect();
    assert_eq!(payload_paths.len(), 1, "payload 증거가 하나여야 한다");
    assert!(
        payload_paths[0].contains("app-a"),
        "그룹 경계를 넘은 증거가 있다: {payload_paths:?}"
    );
}

#[test]
fn child_is_not_evaluated_when_parent_misses() {
    // 부모가 0건이면 자식은 평가하지 않는다. 오류가 아니라 미매치다.
    let env = snapshot(observations(
        vec![file(&format!("{ROOT}\\app-a\\evil.js"))],
        vec![],
    ));
    let body = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(MANIFEST),
        &scope(),
    )
    .unwrap();
    assert!(body.verdicts.is_empty());
    assert!(
        !body.evidence.iter().any(|e| e.rule == "payload"),
        "부모 없이 자식이 평가되면 안 된다"
    );
}

#[test]
fn verdict_needs_both_rules_in_the_same_group() {
    // 작업은 A 를 가리키는데 evil.js 는 B 에 있다. 어느 그룹도 성립하지 않아야 한다.
    let a = format!("{ROOT}\\app-a");
    let b = format!("{ROOT}\\app-b");
    let env = snapshot(observations(
        vec![file(&format!("{b}\\evil.js"))],
        vec![task("A", &a)],
    ));
    let body = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(MANIFEST),
        &scope(),
    )
    .unwrap();
    assert!(
        body.verdicts.is_empty(),
        "그룹 밖의 증거로 판정이 성립하면 안 된다"
    );
}

// ─────────────────────────────────────────── 상한

#[test]
fn derived_path_outside_scan_roots_excludes_the_group() {
    // 파생 경로는 공격자가 영향을 줄 수 있는 값이다. 상한을 넘으면 경고가 아니라 제외다.
    let outside = "c:\\windows\\temp\\x";
    let env = snapshot(observations(
        vec![file(&format!("{outside}\\evil.js"))],
        vec![task("A", outside)],
    ));
    let body = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(MANIFEST),
        &scope(),
    )
    .unwrap();

    assert!(
        body.verdicts.is_empty(),
        "제외된 그룹은 판정을 통과할 수 없다"
    );
    let g = &body.groups[0];
    assert!(g.excluded_reason.is_some(), "제외 사유가 남아야 한다");
    assert!(
        g.excluded_reason.as_ref().unwrap().contains("scan_roots"),
        "사유가 상한 위반임을 밝혀야 한다: {:?}",
        g.excluded_reason
    );
}

// ─────────────────────────────────────────── 결정성 · 정규화

#[test]
fn evaluation_is_byte_identical_across_runs() {
    // 결정성이 없으면 계획 비교 회귀 검증이 성립하지 않는다 (설계-09 P2).
    let a = format!("{ROOT}\\app-a");
    let env = snapshot(observations(
        vec![file(&format!("{a}\\evil.js"))],
        vec![task("A", &a)],
    ));
    let s = Snapshot::from_envelope(&env);
    let m = manifest(MANIFEST);
    let one = serde_json::to_string(&evaluate(&s, &m, &scope()).unwrap()).unwrap();
    let two = serde_json::to_string(&evaluate(&s, &m, &scope()).unwrap()).unwrap();
    assert_eq!(one, two);
}

#[test]
fn decomposed_hangul_path_still_matches() {
    // 외부 매체를 거친 파일명이 NFD 로 들어오는 경우가 실제로 있다.
    use unicode_normalization::UnicodeNormalization;
    let dir = format!("{ROOT}\\한글폴더");
    let nfd_dir: String = dir.nfd().collect();
    let env = snapshot(observations(
        vec![file(&format!("{dir}\\evil.js"))],
        vec![task("A", &nfd_dir)],
    ));
    let body = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(MANIFEST),
        &scope(),
    )
    .unwrap();
    assert_eq!(
        body.verdicts.len(),
        1,
        "NFD 로 들어온 한글 경로가 NFC 파일과 같은 트리로 인식되어야 한다"
    );
}

// ─────────────────────────────────────────── DAG

#[test]
fn cyclic_reference_is_rejected() {
    let yaml = MANIFEST.replace(
        "  - id: task\n    subject: persistence",
        "  - id: task\n    subject: persistence\n    from: \"${payload.dir}\"",
    );
    let env = snapshot(Observations::default());
    let e = evaluate(&Snapshot::from_envelope(&env), &manifest(&yaml), &scope()).unwrap_err();
    assert!(e.0.contains("순환"), "순환 참조를 지목해야 한다: {e}");
}

#[test]
fn reference_to_missing_rule_is_rejected() {
    let yaml = MANIFEST.replace("${task.payload_dir}", "${nope.dir}");
    let env = snapshot(Observations::default());
    let e = evaluate(&Snapshot::from_envelope(&env), &manifest(&yaml), &scope()).unwrap_err();
    assert!(e.0.contains("nope"), "없는 규칙을 지목해야 한다: {e}");
}

#[test]
fn verdict_referencing_missing_rule_is_rejected() {
    // 조용히 두면 "왜 안 잡히는가" 의 원인이 보이지 않는다.
    let yaml = MANIFEST.replace(
        "require: \"task and payload\"",
        "require: \"task and ghost\"",
    );
    let env = snapshot(Observations::default());
    let e = evaluate(&Snapshot::from_envelope(&env), &manifest(&yaml), &scope()).unwrap_err();
    assert!(e.0.contains("ghost"), "{e}");
}

// ─────────────────────────────────────────── 연산자

#[test]
fn p2_operators_work() {
    let five = r#"
schema_version: 1
id: ops
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name: { en: "ops" }
scan_roots: ["c:\\users\\t\\appdata\\local\\programs"]
subjects: [file]
detect:
  - id: eq
    subject: file
    where: [{ field: path, op: equals,      value: "C:\\Users\\T\\AppData\\Local\\Programs\\app-a\\evil.js" }]
  - id: ct
    subject: file
    where: [{ field: path, op: contains,    value: "APP-A" }]
  - id: sw
    subject: file
    where: [{ field: path, op: starts_with, value: "C:\\Users" }]
  - id: ew
    subject: file
    where: [{ field: path, op: ends_with,   value: ".JS" }]
  - id: mt
    subject: file
    where: [{ field: path, op: matches,     value: "(?i)evil\\.js$" }]
verdict:
  require: "eq and ct and sw and ew and mt"
"#;
    let env = snapshot(observations(
        vec![file(&format!("{ROOT}\\app-a\\evil.js"))],
        vec![],
    ));
    let body = evaluate(&Snapshot::from_envelope(&env), &manifest(five), &scope()).unwrap();
    assert_eq!(
        body.verdicts.len(),
        1,
        "Windows 에서 다섯 연산자가 모두 대소문자를 무시하고 매치해야 한다: {:?}",
        body.issues
    );
}

#[test]
fn every_operator_the_catalog_calls_available_actually_evaluates() {
    // **카탈로그가 "쓸 수 있다" 고 말한 연산자는 실제로 돌아야 한다.** 하나를
    // 빠뜨리면 린트를 통과한 룰이 평가에서 조용히 미매치가 되고, 작성자는
    // 이유를 알 수 없다. 목록을 손으로 적지 않는 이유는 게이트가 올라갈 때마다
    // 이 시험이 거짓말을 시작하기 때문이다.
    use remedy_sdk::catalog::Operator;

    let a = format!("{ROOT}\\app-a");
    let env = snapshot(observations(
        vec![file(&format!("{a}\\evil.js"))],
        vec![task("A", &a)],
    ));
    let snap = Snapshot::from_envelope(&env);

    for op in Operator::ALL {
        if op.info().implemented_in > remedy_sdk::IMPLEMENTED_THROUGH {
            continue;
        }
        // 연산자마다 값의 모양이 다르다. 여기서 재는 것은 "맞는가" 가 아니라
        // "평가되는가" 이므로 매치 여부는 보지 않는다.
        let value = match op {
            Operator::Exists => String::new(),
            Operator::In => "[\"a\", \"b\"]".into(),
            Operator::Gt | Operator::Lt => "1".into(),
            Operator::VersionLt | Operator::VersionGt => "\"1.0\"".into(),
            // **모양이 맞는 값을 줘야 그 길을 지난다.** `"evil"` 로는
            // `is_pkg_version` 이 거절해 비교 코드가 한 번도 돌지 않고,
            // 그러면 이 시험은 배선만 보고 통과한다.
            Operator::PkgVersionLt => "\"1.0-1ubuntu2\"".into(),
            Operator::RpmVersionLt => "\"0:8.0.30-8.el9_8.1\"".into(),
            Operator::Yara => "\"rules/x.yar:r\"".into(),
            _ => "\"evil\"".into(),
        };
        let pred = if value.is_empty() {
            format!("{{ field: path, op: {} }}", op.id())
        } else {
            format!("{{ field: path, op: {}, value: {value} }}", op.id())
        };
        let yaml = MANIFEST.replace(
            "- { field: path, op: ends_with, value: \"\\\\evil.js\" }",
            &format!("- {pred}"),
        );
        let body = evaluate(&snap, &manifest(&yaml), &scope()).unwrap();
        let unimplemented: Vec<&String> = body
            .issues
            .iter()
            .filter(|i| i.contains("아직 없습니다") || i.contains("평가할 수 없습니다"))
            .collect();
        assert!(
            unimplemented.is_empty(),
            "'{}' 는 카탈로그가 {} 라고 하는데 평가되지 않았다: {unimplemented:?}",
            op.id(),
            op.info().implemented_in.as_str()
        );
    }
}

// ─────────────────────────────────────────── RPM 판 (코어 1.3.0)

/// RHEL 9 의 공지 한 줄 모양 — 공급사로 가르고, 판은 rpm 의 규칙으로 견준다.
const RPM_MANIFEST: &str = r#"
schema_version: 1
id: rpm-line
version: 0.1.0
min_core: "1.3.0"
platforms: [linux]
name: { ko: "예시", en: "Sample" }
scan_roots: ["/etc/php"]
subjects: [package]
detect:
  - id: rhel9
    subject: package
    where:
      all:
        - { field: vendor, op: equals, value: "Red Hat, Inc." }
        - { field: name, op: equals, value: php-cli }
        - { field: version, op: rpm_version_lt, value: "0:8.0.30-8.el9_8.1" }
verdict:
  require: "rhel9"
"#;

fn rpm(version: &str, vendor: &str) -> PackageRecord {
    PackageRecord {
        name: "php-cli".into(),
        version: version.into(),
        upstream_version: "8.0.30".into(),
        revision: String::new(),
        arch: "x86_64".into(),
        source: "php".into(),
        manager: "rpm".into(),
        vendor: vendor.into(),
    }
}

#[test]
fn an_rpm_line_picks_the_vendor_and_compares_as_rpm_does() {
    let mut sc = Scope::diagnostic(Vec::new(), Platform::Linux);
    sc.subjects.push(Subject::Package);
    let matched = |rec: PackageRecord| {
        let mut o = Observations::default();
        o.put(Subject::Package, &[rec]);
        let host = HostInfo {
            hostname: "H".into(),
            os: "linux".into(),
            version: "9".into(),
            arch: "amd64".into(),
        };
        let core = CoreInfo {
            version: "0".into(),
            build: "d".into(),
        };
        let env = remedy_artifacts::assemble(
            "r".into(),
            "2026-11-09T00:00:00Z".into(),
            host,
            core,
            &sc,
            o,
        );
        let body = evaluate(&Snapshot::from_envelope(&env), &manifest(RPM_MANIFEST), &sc).unwrap();
        assert!(body.issues.is_empty(), "{:?}", body.issues);
        body.verdicts.len()
    };
    const RH: &str = "Red Hat, Inc.";
    // 고친 판보다 낮다 — 개정의 `_` 뒤(`el9_8` 의 8 · `.1`)까지 rpm 의 규칙으로 본다.
    assert_eq!(matched(rpm("8.0.30-8.el9_7", RH)), 1);
    assert_eq!(matched(rpm("8.0.30-8.el9_8", RH)), 1);
    // 고친 판 · 그보다 높은 판.
    assert_eq!(matched(rpm("8.0.30-8.el9_8.1", RH)), 0);
    assert_eq!(matched(rpm("8.0.30-9.el9", RH)), 0);
    // 같은 판 문자열이라도 다른 공급사의 빌드는 그 공지의 대상이 아니다.
    assert_eq!(
        matched(rpm(
            "8.0.30-8.el9_7",
            "Rocky Enterprise Software Foundation"
        )),
        0
    );
}

#[test]
fn a_single_star_does_not_cross_separators_but_a_double_one_does() {
    // 넘게 만들면 `C:\Users\*\Desktop` 이 훨씬 깊은 곳까지 지목하게 된다.
    // 넘어야 할 때 쓰는 것이 `**` 다.
    let a = format!("{ROOT}\\app-a");
    let env = snapshot(observations(
        vec![file(&format!("{a}\\evil.js"))],
        vec![task("A", &a)],
    ));
    let snap = Snapshot::from_envelope(&env);

    let verdicts = |pattern: &str| {
        let yaml = MANIFEST.replace(
            "op: ends_with, value: \"\\\\evil.js\"",
            &format!("op: glob, value: \"{pattern}\""),
        );
        evaluate(&snap, &manifest(&yaml), &scope())
            .unwrap()
            .verdicts
            .len()
    };

    assert_eq!(verdicts("**\\\\evil.js"), 1, "`**` 는 구분자를 넘어야 한다");
    assert_eq!(
        verdicts("*\\\\evil.js"),
        0,
        "`*` 가 구분자를 넘었다 — 룰이 의도한 것보다 넓은 것을 지목하게 된다"
    );
}

#[test]
fn a_yara_rule_without_content_is_unevaluated_not_a_miss() {
    // 미매치로 흘려보내면 룰이 죽은 채 "안 맞았다" 로 판정이 나간다 (설계-03 §1).
    let yaml = MANIFEST.replace(
        "- { field: path, op: ends_with, value: \"\\\\evil.js\" }",
        "- { yara: \"rules/x.yar:r\" }",
    );
    let a = format!("{ROOT}\\app-a");
    let env = snapshot(observations(
        vec![file(&format!("{a}\\evil.js"))],
        vec![task("A", &a)],
    ));
    let body = evaluate(&Snapshot::from_envelope(&env), &manifest(&yaml), &scope()).unwrap();
    assert!(
        body.issues
            .iter()
            .any(|i| i.contains("평가하지 못했습니다")),
        "훑을 본문이 없다는 사실이 보고되지 않았다: {:?}",
        body.issues
    );
    assert!(
        body.verdicts.is_empty(),
        "평가하지 못한 조건으로 판정하면 안 된다"
    );
    // **그리고 관측에 실려야 한다** (결정 2026-10-26). `issues` 에만 남으면 판정이
    // 없을 때 종료 코드가 0 "위협 없음" 이 되고, 무인 배포는 그 주의 줄이 실린
    // stderr 를 버린다 — 재지 못한 스캔이 깨끗하다고 말한다.
    assert_eq!(
        body.observation.unevaluated_rules,
        vec!["rules/x.yar:r".to_string()],
        "평가하지 못한 규칙이 관측에 실리지 않았다"
    );
    assert!(
        !body.observation.is_complete(),
        "평가하지 못했는데 관측이 완전하다고 한다"
    );
}

#[test]
fn a_yara_rule_unevaluated_on_many_records_is_named_once() {
    // 본문 없는 파일이 여럿이어도 **규칙은 한 번만** 적는다 — 이유 줄은 레코드가
    // 아니라 룰을 말한다. 레코드마다 적으면 큰 폴더 하나가 화면을 덮는다.
    let yaml = MANIFEST.replace(
        "- { field: path, op: ends_with, value: \"\\\\evil.js\" }",
        "- { yara: \"rules/x.yar:r\" }",
    );
    let a = format!("{ROOT}\\app-a");
    let env = snapshot(observations(
        vec![
            file(&format!("{a}\\evil.js")),
            file(&format!("{a}\\other.js")),
            file(&format!("{a}\\third.js")),
        ],
        vec![task("A", &a)],
    ));
    let body = evaluate(&Snapshot::from_envelope(&env), &manifest(&yaml), &scope()).unwrap();
    assert_eq!(
        body.observation.unevaluated_rules,
        vec!["rules/x.yar:r".to_string()],
        "같은 규칙이 여러 번 실렸거나 실리지 않았다"
    );
}

#[test]
fn a_rule_that_never_touches_yara_leaves_the_observation_complete() {
    // **역검증.** 새 필드가 YARA 와 무관한 평가까지 불완전하게 만들면, 모든
    // 스캔이 6 을 내고 운영자는 6 을 정상으로 배운다 — 그러면 6 이 죽는다.
    let a = format!("{ROOT}\\app-a");
    let env = snapshot(observations(
        vec![file(&format!("{a}\\evil.js"))],
        vec![task("A", &a)],
    ));
    let body = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(MANIFEST),
        &scope(),
    )
    .unwrap();
    assert!(
        body.observation.unevaluated_rules.is_empty(),
        "YARA 를 쓰지 않았는데 미평가가 실렸다: {:?}",
        body.observation.unevaluated_rules
    );
}

#[test]
fn exclude_suppresses_a_match() {
    let yaml = MANIFEST.replace(
        "    capture:\n      script_path:",
        "    exclude:\n      - { field: source, op: contains, value: \"\\\\tasks\\\\microsoft\\\\windows\\\\a\" }\n    capture:\n      script_path:",
    );
    let a = format!("{ROOT}\\app-a");
    let env = snapshot(observations(
        vec![file(&format!("{a}\\evil.js"))],
        vec![task("A", &a)],
    ));
    let body = evaluate(&Snapshot::from_envelope(&env), &manifest(&yaml), &scope()).unwrap();
    assert!(
        body.verdicts.is_empty(),
        "제외 조건에 걸린 작업은 매치가 아니다"
    );
}

#[test]
fn a_field_the_core_never_fills_is_reported_in_the_scan_itself() {
    // **린트는 건너뛸 수 있고, 실행하는 사람은 매니페스트를 읽지 않는다.**
    // 산출물이 홀로 읽혀야 한다는 요구(설계-03 §1)를 지키려면 `scan.json` 이
    // 그 사실을 들고 있어야 한다 (설계-09 P9).
    //
    // **필드를 `signature.subject` 에서 `streams` 로 바꿨다** (2026-09-05).
    // `signature` 는 Windows 에서 채워지게 됐고, 이 스냅샷은 Windows 다 —
    // 그대로 두면 이 시험이 "채우지 않는 필드" 가 아니라 **채우는 필드**를
    // 대고 묻게 된다. `streams` 는 열거에 unsafe 가 필요해 어느 플랫폼에서도
    // 비어 있다.
    let y = r#"
schema_version: 1
id: unfilled
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: { en: 'unfilled' }
scan_roots: ['c:\users\t\appdata\local\programs']
subjects: [file]
detect:
  - id: signed
    subject: file
    where: [{ field: 'streams', op: exists }]
verdict: { require: 'signed' }
"#;
    let env = snapshot(observations(
        vec![file(&format!(r"{ROOT}\app-a\evil.js"))],
        vec![],
    ));
    let body = evaluate(&Snapshot::from_envelope(&env), &manifest(y), &scope()).unwrap();

    // 레코드가 있는데도 아무것도 안 잡힌다 — 그것이 조용하면 안 되는 이유다.
    assert!(body.evidence.is_empty());
    assert_eq!(
        body.issues.len(),
        1,
        "규칙마다 한 번이어야 한다(레코드마다가 아니라): {:?}",
        body.issues
    );
    assert!(body.issues[0].contains("signed"), "{:?}", body.issues);
    assert!(
        body.issues[0].contains("streams") && body.issues[0].contains("채우지 않습니다"),
        "{:?}",
        body.issues
    );
    // **어디서나 비는 필드에는 플랫폼을 붙이지 않는다.** 붙이면 다른 플랫폼에서는
    // 산다고 읽힌다 (2026-09-05, `file.signature` 가 그 반대 모양이었다).
    assert!(
        !body.issues[0].contains("windows 에서") && !body.issues[0].contains("linux 에서"),
        "어디서나 비는 필드인데 플랫폼을 붙였다: {:?}",
        body.issues
    );
}

/// **Windows 도 `process.modules` 를 채운다 — 그래서 *"채우지 않습니다"* 진단이 나오면 안 된다**
/// (2026-11-12 · `remedy-winmods`).
///
/// 2026-10-27 부터 이 자리는 *"빈 목록은 두 방향으로 틀리고 진단 한 줄이 둘을 다 덮는다"* 를 쟀다 —
/// Windows 수집기가 목록을 늘 비웠고, 그 축을 `NOT_POPULATED_YET` 이 들고 있었다. 이제 그 줄을
/// 뺐으므로 Windows 스냅샷에서 모듈을 쓴 룰에 그 진단이 붙으면 **채워진 목록을 쓴 룰에 거짓
/// 경고**가 된다. 빈 목록의 평가 자체는 그대로다 — 평가기가 목록을 JSON 문자열로 꺼내므로
/// (`expr::field`) `exists` 는 `"[]"` 에서도 참이고 `contains` 는 거짓이다(보호 프로세스 · 끝난
/// 프로세스의 빈 목록이 그 꼴이다).
#[test]
fn a_windows_module_list_is_no_longer_flagged_as_unpopulated() {
    let mut obs = Observations::default();
    obs.put(
        Subject::Process,
        &[proc_without_modules(4), proc_without_modules(8)],
    );
    // **`Scope::diagnostic` 은 `file`·`persistence` 둘만 담는다.** 그대로 쓰면
    // 프로세스가 스냅샷에 들어오지 않아 이 시험이 아무것도 재지 않는다 —
    // 처음에 그렇게 썼고 `exists` 가 0건으로 나왔다.
    let mut sc = scope();
    sc.subjects.push(Subject::Process);
    let env = remedy_artifacts::assemble(
        "r".into(),
        "2026-08-20T00:00:00Z".into(),
        HostInfo {
            hostname: "H".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        CoreInfo {
            version: "0".into(),
            build: "d".into(),
        },
        &sc,
        obs,
    );
    let snap = Snapshot::from_envelope(&env);
    let scope = || sc.clone();

    // ── `exists` — 빈 목록 `"[]"` 도 있는 값이다 ───────────────────────
    let seen = evaluate(&snap, &manifest(&modules_rule("exists", None)), &scope()).unwrap();
    assert_eq!(
        seen.evidence.len(),
        2,
        "빈 목록인데도 둘 다 걸려야 한다 — `[]` 는 있는 값이다: {:?}",
        seen.evidence
    );
    assert!(
        !seen
            .issues
            .iter()
            .any(|i| i.contains("modules") && i.contains("채우지 않습니다")),
        "Windows 도 채우는데 '채우지 않습니다' 가 붙었다: {:?}",
        seen.issues
    );

    // ── `contains` — 빈 목록에서는 거짓이다 ──────────────────────────
    let none = evaluate(
        &snap,
        &manifest(&modules_rule("contains", Some("ntdll"))),
        &scope(),
    )
    .unwrap();
    assert!(
        none.evidence.is_empty(),
        "빈 목록에서 contains 가 걸렸다: {:?}",
        none.evidence
    );
    assert!(
        !none.issues.iter().any(|i| i.contains("modules")),
        "Windows 도 채우는데 모듈 진단이 붙었다: {:?}",
        none.issues
    );
}

/// 모듈 목록이 빈 Windows 프로세스 — 보호 프로세스(PPL)와 끝난 프로세스가 그렇다(`remedy-winmods`).
fn proc_without_modules(pid: u32) -> remedy_artifacts::ProcessRecord {
    remedy_artifacts::ProcessRecord {
        pid,
        ppid: 1,
        image_path: format!(r"{ROOT}\svc-{pid}.exe"),
        cmdline: String::new(),
        cmdline_decoded: String::new(),
        args: String::new(),
        user: "t".into(),
        start_time: "2026-08-20T00:00:00Z".into(),
        modules: Vec::new(),
        modules_denied: false,
    }
}

fn modules_rule(op: &str, value: Option<&str>) -> String {
    let v = match value {
        Some(v) => format!(", value: {v}"),
        None => String::new(),
    };
    format!(
        r#"
schema_version: 1
id: mods
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: {{ en: 'mods' }}
scan_roots: ['{ROOT}']
subjects: [process]
detect:
  - id: mods
    subject: process
    where: [{{ field: modules, op: {op}{v} }}]
verdict: {{ require: 'mods' }}
"#
    )
}

/// **한 플랫폼에서만 비는 필드는 그 플랫폼의 스냅샷에서만 말한다.**
///
/// `file.signature` 는 Windows 에서 `remedy-wintrust` 가 채우고 Linux 에는
/// Authenticode 가 없어 비어 있다. 2026-09-05 까지 축이 없어 어디서나 죽었다고
/// 말했고, 그것은 Windows 작성자에게 거짓말이었다.
#[test]
fn a_field_empty_on_one_platform_is_reported_only_there() {
    let y = r#"
schema_version: 1
id: sig
version: 1.0.0
min_core: '1.0.0'
platforms: [windows, linux]
name: { en: 'sig' }
scan_roots: ['c:\users\t\appdata\local\programs']
subjects: [file]
detect:
  - id: signed
    subject: file
    where: [{ field: 'signature.subject', op: equals, value: 'Acme' }]
verdict: { require: 'signed' }
"#;
    let env = snapshot(observations(
        vec![file(&format!(r"{ROOT}\app-a\evil.js"))],
        vec![],
    ));
    let snap = Snapshot::from_envelope(&env);

    // Windows 스냅샷 — 채워지므로 말할 것이 없다.
    let win = evaluate(&snap, &manifest(y), &scope()).unwrap();
    assert!(
        win.issues.is_empty(),
        "Windows 에서 채워지는 필드를 죽었다고 한다: {:?}",
        win.issues
    );

    // Linux 스냅샷 — 정말 비므로 말한다. 그리고 **어느 플랫폼인지** 말한다.
    let mut lin_scope = scope();
    lin_scope.platform = Platform::Linux;
    let lin = evaluate(&snap, &manifest(y), &lin_scope).unwrap();
    assert_eq!(lin.issues.len(), 1, "{:?}", lin.issues);
    assert!(
        lin.issues[0].contains("linux 에서"),
        "어느 플랫폼인지 말하지 않는다: {:?}",
        lin.issues
    );
}

#[test]
fn a_rule_on_filled_fields_leaves_the_scan_quiet() {
    // 위 시험이 "언제나 한 줄 남긴다" 로 통과하면 안 된다.
    let env = snapshot(observations(
        vec![file(&format!(r"{ROOT}\app-a\evil.js"))],
        vec![task("t", &format!(r"{ROOT}\app-a"))],
    ));
    let body = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(MANIFEST),
        &scope(),
    )
    .unwrap();
    assert!(
        !body.issues.iter().any(|i| i.contains("채우지 않습니다")),
        "{:?}",
        body.issues
    );
}

// ── 정규식은 패턴마다 한 번 컴파일한다 (2026-09-28) ─────────────────────
//
// `matches` 는 레코드마다 불린다. 컴파일한 정규식을 다시 쓰게 되면서 아래 셋이
// 달라지면 안 된다 — 패턴이 다른 규칙끼리 섞이지 않는가 · 보간된 값마다 따로
// 서는가 · 잘못된 정규식의 보고가 전과 같은가.

const REGEXES: &str = r#"
schema_version: 1
id: regexes
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name: { en: "regexes" }
scan_roots: ["c:\\users\\t\\appdata\\local\\programs"]
subjects: [file]
detect:
  - id: js
    subject: file
    where: [{ field: path, op: matches, value: "(?i)evil\\.js$" }]
  - id: dll
    subject: file
    where: [{ field: path, op: matches, value: "(?i)bad\\.dll$" }]
verdict:
  require: "js and dll"
"#;

fn paths_of(body: &remedy_sdk::artifact::ScanBody, rule: &str) -> Vec<String> {
    body.evidence
        .iter()
        .filter(|e| e.rule == rule)
        .filter_map(|e| e.target["path"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn two_patterns_on_the_same_records_stay_apart() {
    let a = format!("{ROOT}\\app-a");
    let env = snapshot(observations(
        vec![
            file(&format!("{a}\\evil.js")),
            file(&format!("{a}\\bad.dll")),
            file(&format!("{a}\\notes.txt")),
        ],
        vec![],
    ));
    let body = evaluate(&Snapshot::from_envelope(&env), &manifest(REGEXES), &scope()).unwrap();
    assert_eq!(body.verdicts.len(), 1, "{:?}", body.issues);
    assert_eq!(paths_of(&body, "js"), vec![format!("{a}\\evil.js")]);
    assert_eq!(paths_of(&body, "dll"), vec![format!("{a}\\bad.dll")]);
}

/// 보간된 패턴 — 그룹마다 값이 다르다. 캐시가 보간 **전** 문자열로 열리면
/// 둘째 그룹이 첫째 그룹의 정규식을 받아 쓴다.
const PER_GROUP: &str = r#"
schema_version: 1
id: per-group
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name: { en: "per group" }
scan_roots: ["c:\\users\\t\\appdata\\local\\programs"]
subjects: [persistence, file]
detect:
  - id: task
    subject: persistence
    where:
      - { field: args, op: matches, value: "(?i)\\.js(\\s|$)" }
    capture:
      script_path: "args | first_path"
      payload_dir: "${script_path} | dirname"
      nm: "name"
  - id: payload
    subject: file
    from: "${task.payload_dir}"
    where:
      - { field: path, op: matches, value: "(?i)${task.nm}\\.js$" }
verdict:
  require: "task and payload"
"#;

#[test]
fn an_interpolated_pattern_stands_per_group() {
    let a = format!("{ROOT}\\app-a");
    let b = format!("{ROOT}\\app-b");
    let env = snapshot(observations(
        vec![
            file(&format!("{a}\\alpha.js")),
            file(&format!("{a}\\beta.js")),
            file(&format!("{b}\\alpha.js")),
            file(&format!("{b}\\beta.js")),
        ],
        vec![task("alpha", &a), task("beta", &b)],
    ));
    let body = evaluate(
        &Snapshot::from_envelope(&env),
        &manifest(PER_GROUP),
        &scope(),
    )
    .unwrap();
    assert_eq!(body.verdicts.len(), 2, "{:?}", body.issues);
    for (nm, dir) in [("alpha", &a), ("beta", &b)] {
        let g = body
            .groups
            .iter()
            .find(|g| g.captures.get("task.nm").map(String::as_str) == Some(nm))
            .unwrap_or_else(|| panic!("{nm} 그룹이 없다"));
        let payload: Vec<&str> = g
            .evidence
            .iter()
            .filter_map(|id| body.evidence.iter().find(|x| &x.id == id))
            .filter(|e| e.rule == "payload")
            .filter_map(|e| e.target["path"].as_str())
            .collect();
        assert_eq!(
            payload,
            vec![format!("{dir}\\{nm}.js").as_str()],
            "{nm} 그룹"
        );
    }
}

#[test]
fn a_bad_pattern_is_still_reported_once() {
    // 캐시가 컴파일 오류까지 담아도 보고는 전과 같아야 한다. 평가는 레코드마다
    // 한 줄씩 남기고 `evaluate` 가 끝에서 정렬·중복 제거하므로 **한 줄**이다 —
    // 캐시를 넣기 전에 이 시험으로 잰 값이다.
    let yaml = REGEXES.replace(r#""(?i)bad\\.dll$""#, r#""(unclosed""#);
    let a = format!("{ROOT}\\app-a");
    let env = snapshot(observations(
        vec![
            file(&format!("{a}\\evil.js")),
            file(&format!("{a}\\bad.dll")),
            file(&format!("{a}\\notes.txt")),
        ],
        vec![],
    ));
    let body = evaluate(&Snapshot::from_envelope(&env), &manifest(&yaml), &scope()).unwrap();
    let bad: Vec<&String> = body
        .issues
        .iter()
        .filter(|i| i.starts_with("정규식 '(unclosed' 가 올바르지 않습니다:"))
        .collect();
    assert_eq!(bad.len(), 1, "{:?}", body.issues);
    assert!(body.verdicts.is_empty(), "잘못된 정규식은 매치가 아니다");
}
