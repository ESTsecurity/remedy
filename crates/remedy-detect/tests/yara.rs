//! YARA 가 **파일·레지스트리 값·설정 라인**에서 도는가 (설계-09 P4 검증).
//!
//! 파일만 되면 절반이다. 악성코드가 스크립트를 레지스트리 값에 넣고 로더만
//! 파일로 두는 것은 흔한 배치이고, 그때 파일 쪽에는 볼 것이 없다.
//!
//! # 여기서 가장 중요한 것은 **미평가와 미매치의 구분**이다
//!
//! 훑을 바이트가 없는데 "안 맞았다" 로 나가면 룰이 죽은 채 판정이 선다
//! (설계-03 §1). 그 구분이 무너지면 YARA 를 붙인 의미가 없다.

use remedy_artifacts::{
    Observations, RegistryValueRecord, Scope, StructuredConfigRecord, TextConfigRecord,
};
use remedy_detect::{evaluate, Snapshot};
use remedy_sdk::artifact::{ArtifactsEnvelope, CoreInfo, HostInfo};
use remedy_sdk::catalog::{Platform, Subject};
use remedy_sdk::manifest::PluginManifest;

const ROOT: &str = "c:\\lab";
const RULE: &str = r#"
    rule marker {
        strings:
            $m = "REMEDY-YARA-MARKER" ascii
        condition:
            $m
    }
    rule shellcode {
        strings:
            $s = { DE AD BE EF }
        condition:
            $s
    }
"#;

fn rules() -> Vec<(String, String)> {
    vec![("rules/lab.yar".into(), RULE.into())]
}

fn scope(subject: Subject) -> Scope {
    let mut s = Scope::diagnostic(vec![ROOT.into()], Platform::Windows);
    s.subjects = vec![subject];
    s
}

fn snapshot(obs: Observations, sc: &Scope) -> ArtifactsEnvelope {
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
        sc,
        obs,
    )
}

fn manifest(subject: &str, field: &str) -> PluginManifest {
    let yaml = format!(
        r#"
schema_version: 1
id: yara-probe
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name: {{ ko: "y", en: "y" }}
scan_roots: ['{ROOT}']
subjects: [{subject}]
detect:
  - id: hit
    subject: {subject}
    where:
      - {{ field: {field}, op: yara, value: "rules/lab.yar:marker" }}
verdict:
  require: "hit"
"#
    );
    serde_yaml_ng::from_str(&yaml).expect("매니페스트")
}

/// `(증거 수, issues)`.
fn run(obs: Observations, sc: &Scope, m: &PluginManifest) -> (usize, Vec<String>) {
    let env = snapshot(obs, sc);
    let snap = Snapshot::from_envelope(&env).with_rules(&rules());
    let body = evaluate(&snap, m, sc).expect("평가");
    (body.evidence.len(), body.issues)
}

fn registry(data: &str) -> Observations {
    let mut o = Observations::default();
    o.put(
        Subject::RegistryValue,
        &[RegistryValueRecord {
            hive: "HKLM".into(),
            key: "SOFTWARE\\X".into(),
            name: "Payload".into(),
            r#type: "REG_SZ".into(),
            data: data.into(),
        }],
    );
    o
}

#[test]
fn a_registry_text_value_is_scanned_as_its_own_bytes() {
    // 악성코드가 스크립트를 레지스트리 값에 넣고 로더만 파일로 두는 배치에서는
    // 파일 쪽에 볼 것이 없다.
    let sc = scope(Subject::RegistryValue);
    let m = manifest("registry_value", "data");

    let (hits, issues) = run(registry("echo REMEDY-YARA-MARKER"), &sc, &m);
    assert_eq!(hits, 1, "{issues:?}");
    assert!(issues.is_empty(), "{issues:?}");

    let (hits, issues) = run(registry("아무 값"), &sc, &m);
    assert_eq!(hits, 0, "{issues:?}");
    assert!(
        issues.is_empty(),
        "안 맞은 것은 미평가가 아니다: {issues:?}"
    );
}

#[test]
fn a_binary_registry_value_is_scanned_through_its_blob() {
    // `data` 가 `sha256:…` 참조인 경우다. 참조 문자열을 훑으면 20여 바이트를
    // 대상으로 룰이 도는 셈이 되고, 결과는 "안 맞았다" 로 나가 미평가를 감춘다.
    let bytes = vec![0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
    let key = "sha256:deadbeef";
    let mut o = registry(key);
    o.blobs.insert(key.into(), {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    });

    let sc = scope(Subject::RegistryValue);
    let yaml = format!(
        r#"
schema_version: 1
id: yara-probe
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name: {{ ko: "y", en: "y" }}
scan_roots: ['{ROOT}']
subjects: [registry_value]
detect:
  - id: hit
    subject: registry_value
    where:
      - {{ field: data, op: yara, value: "rules/lab.yar:shellcode" }}
verdict:
  require: "hit"
"#
    );
    let m: PluginManifest = serde_yaml_ng::from_str(&yaml).expect("매니페스트");
    let (hits, issues) = run(o, &sc, &m);
    assert_eq!(hits, 1, "{issues:?}");
}

#[test]
fn a_reference_whose_blob_is_missing_is_unevaluated_not_a_miss() {
    // **이 구분이 무너지면 YARA 를 붙인 의미가 없다.** 참조 문자열을 그대로
    // 훑으면 "안 맞았다" 가 되어 미평가가 감춰진다.
    let sc = scope(Subject::RegistryValue);
    let m = manifest("registry_value", "data");
    let (hits, issues) = run(registry("sha256:없는것"), &sc, &m);
    assert_eq!(hits, 0);
    assert!(
        issues.iter().any(|i| i.contains("평가하지 못했습니다")),
        "미평가를 보고하지 않았다: {issues:?}"
    );
}

#[test]
fn a_config_line_is_scanned() {
    let mut o = Observations::default();
    o.put(
        Subject::TextConfig,
        &[
            TextConfigRecord {
                path: format!("{ROOT}\\a.ini"),
                line_no: 1,
                line: "shell=REMEDY-YARA-MARKER.exe".into(),
                section: "boot".into(),
                key: "shell".into(),
                value: "REMEDY-YARA-MARKER.exe".into(),
            },
            TextConfigRecord {
                path: format!("{ROOT}\\a.ini"),
                line_no: 2,
                line: "other=1".into(),
                section: "boot".into(),
                key: "other".into(),
                value: "1".into(),
            },
        ],
    );
    let sc = scope(Subject::TextConfig);
    let m = manifest("text_config", "line");
    let (hits, issues) = run(o, &sc, &m);
    assert_eq!(hits, 1, "한 줄만 맞아야 한다: {issues:?}");
}

#[test]
fn a_structured_config_value_is_scanned() {
    let mut o = Observations::default();
    o.put(
        Subject::StructuredConfig,
        &[StructuredConfigRecord {
            path: format!("{ROOT}\\m.json"),
            format: "json".into(),
            key_path: "content_scripts.0.js".into(),
            value: "REMEDY-YARA-MARKER".into(),
        }],
    );
    let sc = scope(Subject::StructuredConfig);
    let m = manifest("structured_config", "value");
    let (hits, issues) = run(o, &sc, &m);
    assert_eq!(hits, 1, "{issues:?}");
}

#[test]
fn a_missing_field_is_unevaluated_not_a_miss() {
    // 오타 난 필드 이름이 조용히 "안 맞았다" 가 되면 작성자는 이유를 알 수 없다.
    let sc = scope(Subject::RegistryValue);
    let m = manifest("registry_value", "없는필드");
    let (hits, issues) = run(registry("x"), &sc, &m);
    assert_eq!(hits, 0);
    assert!(
        issues.iter().any(|i| i.contains("없는필드")),
        "어느 필드가 없는지 말해야 한다: {issues:?}"
    );
}

// ─────────────────── 재지 못한 YARA 가 결과를 바꿀 수 있었는가 (결정 2026-10-26)
//
// 재지 못한 YARA 는 관측 불완전(종료 6)이다. 단 **그 YARA 가 무엇을 냈어도
// 레코드의 매치가 같았다면** 6 이 아니다 — 형제 술어가 이미 거짓으로 정한
// 레코드에서는 "위협 없음" 을 말할 수 있다. 그것을 가르지 않으면 술어 순서만으로
// 0 과 6 이 갈리고, 청정 기계가 늘 6 을 내 운영자가 6 을 정상으로 배운다.
//
// **판정식은 보지 않는다**(보수 쪽) — 맨 끝의 두 시험이 그 경계를 고정한다.

fn file(path: &str, content_ref: Option<&str>) -> remedy_artifacts::FileRecord {
    remedy_artifacts::FileRecord {
        path: path.into(),
        size: 10,
        mtime: "2026-08-20T00:00:00Z".into(),
        ctime: None,
        sha256: None,
        signature: None,
        version: None,
        zone: None,
        streams: Vec::new(),
        content_ref: content_ref.map(Into::into),
        package: String::new(),
        package_match: String::new(),
    }
}

/// `app.js` 는 본문이 담겼고(표지 없음) `readme.txt` 는 본문이 없다.
fn two_files() -> Observations {
    let mut o = Observations::default();
    o.put(
        Subject::File,
        &[
            file(&format!("{ROOT}\\app.js"), Some("sha256:k")),
            file(&format!("{ROOT}\\readme.txt"), None),
        ],
    );
    o.blobs.insert("sha256:k".into(), {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(b"var x = 1;")
    });
    o
}

fn file_manifest(detect: &str, require: &str) -> PluginManifest {
    let yaml = format!(
        r#"
schema_version: 1
id: yara-order
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name: {{ ko: "y", en: "y" }}
scan_roots: ['{ROOT}']
subjects: [file]
detect:
{detect}
verdict:
  require: "{require}"
"#
    );
    serde_yaml_ng::from_str(&yaml).expect("매니페스트")
}

fn body_of(obs: Observations, sc: &Scope, m: &PluginManifest) -> remedy_sdk::artifact::ScanBody {
    let env = snapshot(obs, sc);
    evaluate(&Snapshot::from_envelope(&env).with_rules(&rules()), m, sc).expect("평가")
}

const MARKER: &str = "rules/lab.yar:marker";

#[test]
fn where_order_does_not_decide_completeness() {
    let sc = scope(Subject::File);
    let path_first = file_manifest(
        "  - id: hit\n    subject: file\n    where:\n      \
         - { field: path, op: ends_with, value: \".js\" }\n      \
         - { yara: \"rules/lab.yar:marker\" }",
        "hit",
    );
    let yara_first = file_manifest(
        "  - id: hit\n    subject: file\n    where:\n      \
         - { yara: \"rules/lab.yar:marker\" }\n      \
         - { field: path, op: ends_with, value: \".js\" }",
        "hit",
    );
    let a = body_of(two_files(), &sc, &path_first);
    let b = body_of(two_files(), &sc, &yara_first);
    assert!(a.verdicts.is_empty() && b.verdicts.is_empty());
    // `readme.txt` 는 `.js` 가 아니므로 YARA 가 무엇을 냈어도 안 맞는다.
    assert!(
        a.observation.unevaluated_rules.is_empty(),
        "{:?}",
        a.observation
    );
    assert_eq!(
        a.observation.unevaluated_rules, b.observation.unevaluated_rules,
        "같은 논리곱이 술어 순서로 0 과 6 으로 갈린다"
    );

    // **양성 대조** — 경로로 좁히지 않으면 `readme.txt` 가 맞았을 수도 있다.
    // 이것이 6 이 아니면 위 두 단언은 아무것도 재지 않은 것이다.
    let unscoped = file_manifest(
        "  - id: hit\n    subject: file\n    where:\n      \
         - { yara: \"rules/lab.yar:marker\" }",
        "hit",
    );
    let c = body_of(two_files(), &sc, &unscoped);
    assert_eq!(c.observation.unevaluated_rules, vec![MARKER.to_string()]);
    assert!(!c.observation.is_complete());
}

#[test]
fn an_unevaluated_yara_beside_a_branch_that_matched_does_not_count() {
    // `any` 의 다른 갈래가 이미 맞았다 — YARA 가 무엇을 냈어도 매치다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: hit\n    subject: file\n    where:\n      any:\n        \
         - { yara: \"rules/lab.yar:marker\" }\n        \
         - { field: path, op: ends_with, value: \".txt\" }",
        "hit",
    );
    let body = body_of(two_files(), &sc, &m);
    assert_eq!(body.evidence.len(), 1, "{:?}", body.issues);
    assert!(
        body.observation.unevaluated_rules.is_empty(),
        "{:?}",
        body.observation
    );
}

#[test]
fn an_unevaluated_exclude_counts_when_it_could_have_excluded() {
    // **`not` 아래의 규칙이면 제외를 재지 못한 것이 "위협 없음" 을 만든다.**
    // 제외됐어야 할 증거가 남아 `not r` 이 거짓이 되고 판정이 사라진다. 제외가
    // 맞았다면 판정이 섰다 — 그러므로 0 이 아니라 6 이다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: base\n    subject: file\n    where:\n      \
         - { field: path, op: ends_with, value: \".js\" }\n  \
         - id: r\n    subject: file\n    where:\n      \
         - { field: path, op: ends_with, value: \".txt\" }\n    exclude:\n      \
         - { yara: \"rules/lab.yar:marker\" }",
        "base and not r",
    );
    let body = body_of(two_files(), &sc, &m);
    assert!(body.verdicts.is_empty());
    assert_eq!(body.observation.unevaluated_rules, vec![MARKER.to_string()]);
    assert!(
        body.issues
            .iter()
            .any(|i| i.contains("평가하지 못했습니다")),
        "6 의 이유가 주의 줄에 없다: {:?}",
        body.issues
    );

    // **이미 제외됐으면 무관하다** — 다른 제외 술어가 맞았다.
    let excluded = file_manifest(
        "  - id: r\n    subject: file\n    where:\n      \
         - { field: path, op: ends_with, value: \".txt\" }\n    exclude:\n      \
         - { yara: \"rules/lab.yar:marker\" }\n      \
         - { field: path, op: ends_with, value: \"readme.txt\" }",
        "r",
    );
    let body = body_of(two_files(), &sc, &excluded);
    assert!(body.evidence.is_empty(), "{:?}", body.evidence);
    assert!(
        body.observation.unevaluated_rules.is_empty(),
        "{:?}",
        body.observation
    );
}

#[test]
fn a_yara_predicate_on_a_cross_subject_field_is_unevaluated() {
    // 다른 subject 를 참조하는 필드는 아직 없다. 그 위의 YARA 도 재지 못한 것이다.
    let sc = scope(Subject::RegistryValue);
    let m = manifest("registry_value", "file(data).content_ref");
    let env = snapshot(registry("x"), &sc);
    let body = evaluate(&Snapshot::from_envelope(&env).with_rules(&rules()), &m, &sc).unwrap();
    assert_eq!(body.observation.unevaluated_rules, vec![MARKER.to_string()]);
    assert!(
        body.issues.iter().any(|i| i.contains("다른 subject")),
        "{:?}",
        body.issues
    );
}

#[test]
fn an_oversized_binary_registry_value_is_unevaluated_not_a_miss() {
    // 수집기는 256 KiB 를 넘는 이진 값의 바이트를 담지 않고 크기만 적는다. 그
    // 자리표시를 내용으로 훑으면 "안 맞았다" 가 되어 미평가가 감춰진다.
    let sc = scope(Subject::RegistryValue);
    let m = manifest("registry_value", "data");
    let placeholder = remedy_sdk::artifact::binary_placeholder(307_200, true);
    let env = snapshot(registry(&placeholder), &sc);
    let body = evaluate(&Snapshot::from_envelope(&env).with_rules(&rules()), &m, &sc).unwrap();
    assert!(body.verdicts.is_empty());
    assert_eq!(
        body.observation.unevaluated_rules,
        vec![MARKER.to_string()],
        "{:?}",
        body.issues
    );
    assert!(
        body.issues
            .iter()
            .any(|i| i.contains("평가하지 못했습니다")),
        "{:?}",
        body.issues
    );
}

#[test]
fn a_yara_predicate_without_a_rule_reference_is_named_readably() {
    // 룰 참조가 없으면 규칙 이름 대신 **필드와 값**으로 적는다 — 사유 줄의 끝이
    // `content_ref: ` 처럼 빈 채로 나가지 않게.
    let sc = scope(Subject::RegistryValue);
    let yaml = format!(
        r#"
schema_version: 1
id: yara-probe
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name: {{ ko: "y", en: "y" }}
scan_roots: ['{ROOT}']
subjects: [registry_value]
detect:
  - id: hit
    subject: registry_value
    where:
      - {{ field: data, op: yara }}
verdict:
  require: "hit"
"#
    );
    let m: PluginManifest = serde_yaml_ng::from_str(&yaml).expect("매니페스트");
    let env = snapshot(registry("x"), &sc);
    let body = evaluate(&Snapshot::from_envelope(&env).with_rules(&rules()), &m, &sc).unwrap();
    assert_eq!(
        body.observation.unevaluated_rules,
        vec!["data: null".to_string()]
    );

    // 비어 있는 참조도 이름이 빈 채로 나가지 않는다.
    let yaml_empty = yaml.replace(
        "{ field: data, op: yara }",
        "{ field: data, op: yara, value: \"\" }",
    );
    let empty: PluginManifest = serde_yaml_ng::from_str(&yaml_empty).expect("매니페스트");
    let body = evaluate(
        &Snapshot::from_envelope(&env).with_rules(&rules()),
        &empty,
        &sc,
    )
    .unwrap();
    assert_eq!(
        body.observation.unevaluated_rules,
        vec!["data: \"\"".to_string()]
    );
}

#[test]
fn a_definite_exclude_makes_an_unknown_condition_irrelevant() {
    // 확정 제외로 어차피 빠질 레코드다 — YARA 가 무엇을 냈어도 매치가 아니다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: hit\n    subject: file\n    where:\n      \
         - { yara: \"rules/lab.yar:marker\" }\n    exclude:\n      \
         - { field: path, op: ends_with, value: \"readme.txt\" }",
        "hit",
    );
    let body = body_of(two_files(), &sc, &m);
    assert!(body.evidence.is_empty(), "{:?}", body.evidence);
    assert!(
        body.observation.unevaluated_rules.is_empty(),
        "{:?}",
        body.observation
    );
    // 이유 줄도 남지 않는다 — 6 이 아닌데 "평가하지 못했습니다" 가 나오면 읽는
    // 사람이 무엇을 해야 할지 모른다.
    assert!(
        !body
            .issues
            .iter()
            .any(|i| i.contains("평가하지 못했습니다")),
        "{:?}",
        body.issues
    );
}

#[test]
fn an_unknown_condition_whose_capture_cannot_resolve_is_irrelevant() {
    // 조건을 재지 못했어도 capture 를 풀 수 없으면 증거가 될 수 없었다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: hit\n    subject: file\n    where:\n      \
         - { yara: \"rules/lab.yar:marker\" }\n    capture:\n      \
         x: \"no_such_field\"",
        "hit",
    );
    let body = body_of(two_files(), &sc, &m);
    assert!(
        body.observation.unevaluated_rules.is_empty(),
        "{:?}",
        body.observation
    );
}

#[test]
fn an_unknown_condition_and_an_unknown_exclude_are_both_named() {
    // 조건 · 제외를 둘 다 재지 못했다 — 둘 다 그 레코드의 매치를 가른다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: hit\n    subject: file\n    where:\n      \
         - { yara: \"rules/lab.yar:marker\" }\n    exclude:\n      \
         - { yara: \"rules/lab.yar:shellcode\" }",
        "hit",
    );
    let body = body_of(two_files(), &sc, &m);
    assert_eq!(
        body.observation.unevaluated_rules,
        vec![MARKER.to_string(), "rules/lab.yar:shellcode".to_string()]
    );
}

#[test]
fn a_rule_name_typo_is_named_on_records_without_content() {
    // 본문이 없는 레코드에서도 오타는 **오타로** 읽혀야 한다 — "본문 없음" 으로
    // 읽히면 작성자는 엉뚱하게 수집부터 고친다.
    let sc = scope(Subject::File);
    let only_readme = || {
        let mut o = Observations::default();
        o.put(Subject::File, &[file(&format!("{ROOT}\\readme.txt"), None)]);
        o
    };
    let typo = |tail: &str| {
        file_manifest(
            &format!(
                "  - id: hit\n    subject: file\n    where:\n      \
                 - {{ yara: \"rules/lab.yar:no_such_rule\" }}\n      \
                 - {{ field: path, op: ends_with, value: \"{tail}\" }}"
            ),
            "hit",
        )
    };
    // 결과를 가르지 않아도 줄은 남는다.
    let body = body_of(only_readme(), &sc, &typo(".exe"));
    assert!(body.observation.unevaluated_rules.is_empty());
    assert!(
        body.issues.iter().any(|i| i.contains("룰이 없습니다")),
        "{:?}",
        body.issues
    );
    // 결과를 가르면 6 이고, 이유는 본문이 아니라 룰 이름이다.
    let body = body_of(only_readme(), &sc, &typo(".txt"));
    assert_eq!(
        body.observation.unevaluated_rules,
        vec!["rules/lab.yar:no_such_rule".to_string()]
    );
    assert!(
        body.issues.iter().any(|i| i.contains("룰이 없습니다")),
        "{:?}",
        body.issues
    );
    assert!(
        !body
            .issues
            .iter()
            .any(|i| i.contains("content_ref' 가 없습니다")),
        "{:?}",
        body.issues
    );
}

#[test]
fn a_plugin_defect_in_exclude_is_reported_when_another_exclude_decided() {
    // 다른 제외가 이미 정했어도 제외의 YARA 가 드러낸 플러그인 결함은 남긴다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: r\n    subject: file\n    where:\n      \
         - { field: path, op: ends_with, value: \".js\" }\n    exclude:\n      \
         - { yara: \"rules/lab.yar:no_such_rule\" }\n      \
         - { field: path, op: ends_with, value: \"app.js\" }",
        "r",
    );
    let body = body_of(two_files(), &sc, &m);
    assert!(body.evidence.is_empty(), "{:?}", body.evidence);
    assert!(body.observation.unevaluated_rules.is_empty());
    assert!(
        body.issues.iter().any(|i| i.contains("no_such_rule")),
        "{:?}",
        body.issues
    );
}

#[test]
fn a_capture_that_cannot_resolve_makes_an_unknown_irrelevant() {
    // capture 는 YARA 와 무관하다. 풀지 못하면 제외가 무엇을 냈어도 증거가 아니다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: r\n    subject: file\n    where:\n      \
         - { field: path, op: ends_with, value: \".txt\" }\n    exclude:\n      \
         - { yara: \"rules/lab.yar:marker\" }\n    capture:\n      \
         x: \"no_such_field\"",
        "r",
    );
    let body = body_of(two_files(), &sc, &m);
    assert!(body.evidence.is_empty(), "{:?}", body.evidence);
    assert!(
        body.observation.unevaluated_rules.is_empty(),
        "{:?}",
        body.observation
    );
}

#[test]
fn only_the_branch_that_decides_names_its_rules() {
    // `readme.txt` 에서 두 YARA 를 다 재지 못한다. 첫 갈래는 `.exe` 가 거짓으로
    // 정했으므로 결과를 가르는 것은 둘째 갈래의 룰 하나다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: hit\n    subject: file\n    where:\n      any:\n        \
         - all:\n            \
         - { yara: \"rules/lab.yar:marker\" }\n            \
         - { field: path, op: ends_with, value: \".exe\" }\n        \
         - { yara: \"rules/lab.yar:shellcode\" }",
        "hit",
    );
    let body = body_of(two_files(), &sc, &m);
    assert!(body.verdicts.is_empty());
    assert_eq!(
        body.observation.unevaluated_rules,
        vec!["rules/lab.yar:shellcode".to_string()]
    );
}

#[test]
fn an_unknown_does_not_add_predicates_to_the_evidence() {
    // 증거의 `matched` 는 계획기가 지울 값을 정하는 입력이다(`proxy_targets`).
    // 첫 갈래는 YARA 에서 매치가 아니게 됐다 — 그 뒤 술어는 전처럼 싣지 않는다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: hit\n    subject: file\n    where:\n      any:\n        \
         - all:\n            \
         - { field: path, op: ends_with, value: \".txt\" }\n            \
         - { yara: \"rules/lab.yar:marker\" }\n            \
         - { field: path, op: starts_with, value: \"c:\\\\lab\" }\n        \
         - { field: path, op: ends_with, value: \"readme.txt\" }",
        "hit",
    );
    let body = body_of(two_files(), &sc, &m);
    assert_eq!(body.evidence.len(), 1, "{:?}", body.issues);
    let ops: Vec<String> = body.evidence[0]
        .matched
        .iter()
        .map(|p| {
            format!(
                "{} {}",
                p.op,
                p.value.as_ref().and_then(|v| v.as_str()).unwrap_or("")
            )
        })
        .collect();
    assert_eq!(ops, vec!["ends_with .txt", "ends_with readme.txt"]);
}

#[test]
fn a_plugin_defect_is_reported_even_when_it_did_not_decide() {
    // 룰 이름 오타는 레코드가 아니라 **플러그인의** 결함이다 — 청정 기계에서도
    // 줄이 남아야 고칠 수 있다. 본문이 없는 레코드의 사정은 결과를 가르지 않았으면
    // 줄도 남기지 않는다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: hit\n    subject: file\n    where:\n      \
         - { yara: \"rules/lab.yar:no_such_rule\" }\n      \
         - { field: path, op: ends_with, value: \".exe\" }",
        "hit",
    );
    let body = body_of(two_files(), &sc, &m);
    assert!(body.observation.unevaluated_rules.is_empty());
    assert!(
        body.issues.iter().any(|i| i.contains("no_such_rule")),
        "플러그인 결함이 보고되지 않았다: {:?}",
        body.issues
    );
    assert!(
        !body
            .issues
            .iter()
            .any(|i| i.contains("content_ref' 가 없습니다")),
        "결과를 가르지 않은 레코드의 사정이 남았다: {:?}",
        body.issues
    );
}

#[test]
fn a_binary_text_placeholder_is_unevaluated_not_a_miss() {
    // 고정 자리 subject(autorun · service …)의 이진 값은 바이트 수만 적힌다.
    let sc = scope(Subject::RegistryValue);
    let m = manifest("registry_value", "data");
    let placeholder = remedy_sdk::artifact::binary_placeholder(17, false);
    let env = snapshot(registry(&placeholder), &sc);
    let body = evaluate(&Snapshot::from_envelope(&env).with_rules(&rules()), &m, &sc).unwrap();
    assert_eq!(body.observation.unevaluated_rules, vec![MARKER.to_string()]);
}

// ───────────────────── 경계 — 판정식은 보지 않는다(보수 쪽 · 설계 §11)

#[test]
fn a_verdict_that_cannot_stand_still_counts_the_unknown() {
    // `exe` 가 확정 0 이라 `hit` 이 무엇이든 판정은 없다 — 그래도 6 이다. 판정식
    // 수준의 거름은 미평가에 기댄 판정을 가리는 일과 같은 장치라 함께 정한다.
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: exe\n    subject: file\n    where:\n      \
         - { field: path, op: ends_with, value: \".exe\" }\n  \
         - id: hit\n    subject: file\n    where:\n      \
         - { yara: \"rules/lab.yar:marker\" }",
        "exe and hit",
    );
    let body = body_of(two_files(), &sc, &m);
    assert!(body.verdicts.is_empty());
    assert_eq!(body.observation.unevaluated_rules, vec![MARKER.to_string()]);
}

#[test]
fn an_unevaluated_exclude_leaves_the_record_as_evidence() {
    // 제외를 재지 못한 레코드는 전처럼 증거로 남고 그 위에 판정(2)이 선다 —
    // 미평가 주의와 함께. 2 와 그 주의가 같이 나오면 *확인 필요* 로 읽는다(가이드 24).
    let sc = scope(Subject::File);
    let m = file_manifest(
        "  - id: r\n    subject: file\n    where:\n      \
         - { field: path, op: ends_with, value: \".txt\" }\n    exclude:\n      \
         - { yara: \"rules/lab.yar:marker\" }",
        "r",
    );
    let body = body_of(two_files(), &sc, &m);
    assert_eq!(body.verdicts.len(), 1);
    assert_eq!(body.observation.unevaluated_rules, vec![MARKER.to_string()]);
}
