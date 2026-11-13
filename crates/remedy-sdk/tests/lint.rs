//! `plugin lint` 검사 (설계-09 P3).
//!
//! 각 검사는 **막아야 할 것을 막는가**와 **막지 말아야 할 것을 통과시키는가**를
//! 함께 본다. 늘 거부하는 린터는 늘 통과하는 린터만큼 쓸모없고, 전자는 작성자가
//! 우회로를 만들게 만들어 더 나쁘다.

use remedy_sdk::lint::{blocking, lint, Severity};
use remedy_sdk::manifest::PluginManifest;

/// 통과하는 최소 매니페스트. 각 시험은 여기서 한 곳만 비튼다.
const BASE: &str = r#"
schema_version: 1
id: lint-base
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: { ko: '시험', en: 'lint base' }
scan_roots: ['C:\remedy-lab\fixtures', '%SystemRoot%\System32\Tasks']
subjects: [persistence, file]
detect:
  - id: task
    subject: persistence
    where:
      all:
        - { field: command, op: contains, value: '\remedy-lab\fixtures\' }
    capture:
      payload_dir: 'command | dirname'
  - id: payload
    subject: file
    from: '${task.payload_dir}'
    where:
      - { field: path, op: ends_with, value: '\main.js' }
verdict: { require: 'task and payload' }
"#;

fn parse(yaml: &str) -> PluginManifest {
    serde_yaml_ng::from_str(yaml).unwrap_or_else(|e| panic!("매니페스트 파싱 실패: {e}\n{yaml}"))
}

fn errors(yaml: &str) -> Vec<String> {
    lint(&parse(yaml))
        .into_iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| format!("{} :: {}", i.at, i.message))
        .collect()
}

fn warnings(yaml: &str) -> Vec<String> {
    lint(&parse(yaml))
        .into_iter()
        .filter(|i| i.severity == Severity::Warning)
        .map(|i| format!("{} :: {}", i.at, i.message))
        .collect()
}

/// `file.package` · `package_match` 는 `package` subject 를 함께 선언한 **리눅스** 룰에서만 채운다(코어 1.7.0) —
/// 그 밖에서 그 칸을 보는 술어는 늘 거짓이라 경고한다. 맞게 쓴 룰에는 말하지 않는다.
#[test]
fn package_fields_need_the_package_subject_on_linux() {
    let yaml = |platforms: &str, subjects: &str| {
        [
            "schema_version: 1",
            "id: pkg-fields",
            "version: 1.0.0",
            "min_core: '1.0.0'",
            &format!("platforms: [{platforms}]"),
            "name: { ko: '시험', en: 'pkg fields' }",
            "scan_roots: ['/usr/bin']",
            &format!("subjects: [{subjects}]"),
            "detect:",
            "  - id: changed",
            "    subject: file",
            "    where:",
            "      - { field: package_match, op: equals, value: different }",
            "verdict: { require: 'changed' }",
        ]
        .join("\n")
    };
    let about = |w: &[String]| w.iter().filter(|s| s.contains("'package_match'")).count();
    let ok = warnings(&yaml("linux", "file, package"));
    assert_eq!(about(&ok), 0, "{ok:?}");
    let w = warnings(&yaml("linux", "file"));
    assert_eq!(about(&w), 1, "{w:?}");
    assert!(w.iter().any(|s| s.contains("선언하지 않았다")), "{w:?}");
    let w = warnings(&yaml("windows, linux", "file, package"));
    assert!(
        w.iter()
            .any(|s| s.contains("Windows 에는 패키지 DB 가 없다")),
        "{w:?}"
    );
}

#[test]
fn the_base_manifest_is_clean() {
    // **이것이 먼저다.** 정상 매니페스트를 막는 린터는 아무도 안 쓴다.
    let issues = lint(&parse(BASE));
    assert_eq!(blocking(&issues), 0, "오류가 나오면 안 된다: {issues:#?}");
    assert!(issues.is_empty(), "경고도 없어야 한다: {issues:#?}");
}

#[test]
fn missing_rule_reference_is_an_error_and_lists_what_exists() {
    // 없는 규칙을 가리키면 그 조건은 영원히 해소되지 않고 **조용히 미매치**가 된다.
    let y = BASE.replace(
        "from: '${task.payload_dir}'",
        "from: '${없는룰.payload_dir}'",
    );
    let issues = lint(&parse(&y));
    let e: Vec<_> = issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .collect();
    assert_eq!(e.len(), 1, "{issues:#?}");
    assert!(e[0].message.contains("없는룰"));
    // 유효값을 알려 주지 않으면 작성자는 추측한다. 추측이 통과하면 그 추측이
    // 다음 룰에도 쓰인다.
    let valid = e[0].valid.as_deref().unwrap_or_default();
    assert!(
        valid.contains("task") && valid.contains("payload"),
        "{valid}"
    );
}

#[test]
fn missing_capture_on_an_existing_rule_is_an_error() {
    let y = BASE.replace("${task.payload_dir}", "${task.없는캡처}");
    let e = errors(&y);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].contains("없는캡처"), "{e:?}");
}

#[test]
fn verdict_referencing_a_missing_rule_is_an_error() {
    let y = BASE.replace("require: 'task and payload'", "require: 'task and 없는룰'");
    let e = errors(&y);
    assert!(e.iter().any(|x| x.contains("verdict.require")), "{e:?}");
}

// ───────────────────────────── 확인 필요 (`verdict.unconfirmed` · 2026-11-09 · 코어 1.3.0)

/// 점검 룰에 *확인 필요* 한 줄을 단 모양 — 각 시험이 한 곳만 비튼다.
fn with_unconfirmed() -> String {
    BASE.replace("min_core: '1.0.0'", "min_core: '1.3.0'")
        .replace("name: {", "kind: check\nname: {")
        .replace(
            "verdict: { require: 'task and payload' }",
            "verdict:\n  require: 'task and payload'\n  unconfirmed:\n    \
             - when: 'task'\n      why: { ko: '판을 확인하십시오', en: 'check the build' }",
        )
}

#[test]
fn an_unconfirmed_line_on_a_check_rule_is_clean() {
    let e = errors(&with_unconfirmed());
    assert!(e.is_empty(), "{e:?}");
}

#[test]
fn an_unconfirmed_line_needs_a_check_rule() {
    // 치료 룰의 6 은 *"다 보지 못했다"* 하나다.
    let y = with_unconfirmed().replace("kind: check\n", "");
    let e = errors(&y);
    assert!(
        e.iter().any(|x| x.starts_with("verdict.unconfirmed ::")),
        "{e:?}"
    );
}

#[test]
fn an_unconfirmed_line_names_existing_rules() {
    let y = with_unconfirmed().replace("when: 'task'", "when: 'task and 없는룰'");
    let e = errors(&y);
    assert!(
        e.iter()
            .any(|x| x.starts_with("verdict.unconfirmed[0].when") && x.contains("없는룰")),
        "{e:?}"
    );
}

#[test]
fn an_unconfirmed_line_speaks_both_languages() {
    // 사유 줄이 6 의 유일한 설명이다 — 한쪽이 비면 그 언어의 무인 배포가 까닭을 읽지 못한다.
    let y = with_unconfirmed().replace(", en: 'check the build'", "");
    let e = errors(&y);
    assert!(
        e.iter()
            .any(|x| x.starts_with("verdict.unconfirmed[0].why") && x.contains("'en'")),
        "{e:?}"
    );
}

#[test]
fn an_unconfirmed_line_needs_core_1_3_0() {
    // 낮은 코어는 이 칸을 모른다 — 요구 판을 적어야 로드 단계가 그 차이를 말한다.
    let y = with_unconfirmed().replace("min_core: '1.3.0'", "min_core: '1.2.1'");
    let e = errors(&y);
    assert!(
        e.iter()
            .any(|x| x.starts_with("min_core ::") && x.contains("1.3.0")),
        "{e:?}"
    );
}

// ───────────────────────────── 네트워크 점검 (`network` · 2026-11-10 · 코어 1.4.0)

/// 네트워크 점검 룰의 온전한 모양 — 이 기계를 읽는 칸이 전부 비어 있다. 각 시험이 한 곳만 비튼다.
const NETWORK: &str = r#"
schema_version: 1
id: lint-network
version: 1.0.0
min_core: '1.4.0'
platforms: [windows, linux]
name: { ko: '원격 점검', en: 'remote check' }
kind: check
network: url
scan_roots: []
subjects: []
detect: []
"#;

#[test]
fn a_network_check_rule_is_clean() {
    let issues = lint(&parse(NETWORK));
    assert_eq!(blocking(&issues), 0, "오류가 나오면 안 된다: {issues:#?}");
    assert_eq!(
        parse(NETWORK).network.map(|n| n.id()),
        Some("url"),
        "값이 동반 프로그램의 명령 이름이다"
    );
}

#[test]
fn a_network_check_must_be_a_check() {
    // 본체는 그 결과로 아무것도 바꾸지 않는다 — 치료 룰이 네트워크를 말하면 그 약속이 깨진다.
    let e = errors(&NETWORK.replace("kind: check\n", ""));
    assert!(e.iter().any(|x| x.starts_with("network ::")), "{e:?}");
}

#[test]
fn a_network_check_reads_nothing_on_this_machine() {
    // 채워 두면 서명된 룰이 '이 자리를 읽는다' 고 적어 놓고 실제로는 읽지 않는다.
    for (from, to, at) in [
        ("scan_roots: []", "scan_roots: ['/etc']", "scan_roots"),
        ("subjects: []", "subjects: [file]", "subjects"),
        (
            "detect: []",
            "detect: []\nverdict: { require: 'x' }",
            "verdict",
        ),
        (
            "detect: []",
            "detect: []\nhash_large: ['node.exe']",
            "hash_large",
        ),
        (
            "detect: []",
            "detect: []\ntext_config_dirs: ['/etc/php']",
            "text_config_dirs",
        ),
    ] {
        let e = errors(&NETWORK.replace(from, to));
        assert!(
            e.iter()
                .any(|x| x.starts_with(&format!("{at} ::")) && x.contains("이 기계를 보지 않는다")),
            "{at}: {e:?}"
        );
    }
}

#[test]
fn a_network_check_needs_core_1_4_0() {
    let e = errors(&NETWORK.replace("min_core: '1.4.0'", "min_core: '1.3.0'"));
    assert!(
        e.iter()
            .any(|x| x.starts_with("min_core ::") && x.contains("1.4.0")),
        "{e:?}"
    );
}

#[test]
fn the_network_value_is_a_closed_set() {
    // 룰이 프로그램 이름 · 인자를 고르는 문이 되지 않게 — 아는 값만, 값 없는 키도 거부.
    for bad in ["network: curl", "network:", "network: ~", "network: [url]"] {
        let y = NETWORK.replace("network: url", bad);
        assert!(
            serde_yaml_ng::from_str::<PluginManifest>(&y).is_err(),
            "{bad:?} 를 받았다"
        );
    }
}

#[test]
fn a_network_check_does_not_name_files_or_archive_members() {
    // 1.11.0 의 두 칸도 이 기계를 읽는 칸이다 — 네트워크 점검 룰에 적으면 같은 오류다.
    for (to, at) in [
        ("detect: []\nfile_names: ['*.jar']", "file_names"),
        ("detect: []\narchive_members: ['*.jar']", "archive_members"),
    ] {
        let e = errors(&NETWORK.replace("detect: []", to));
        assert!(
            e.iter()
                .any(|x| x.starts_with(&format!("{at} ::")) && x.contains("이 기계를 보지 않는다")),
            "{at}: {e:?}"
        );
    }
}

// ───────────────────────────── 데이터 룰 (`kind: data` · 2026-11-13 · 코어 1.12.0)

/// 데이터 룰의 온전한 모양 — 동반 프로그램이 읽는 기준만 담고 이 기계를 보지 않는다.
const DATA: &str = r#"
schema_version: 1
id: lint-data
version: 1.0.0
min_core: '1.12.0'
platforms: [windows, linux]
name: { ko: '기준', en: 'criteria' }
kind: data
scan_roots: []
subjects: []
detect: []
"#;

#[test]
fn a_data_rule_is_clean() {
    let issues = lint(&parse(DATA));
    assert_eq!(blocking(&issues), 0, "오류가 나오면 안 된다: {issues:#?}");
}

#[test]
fn a_data_rule_reads_nothing_and_does_nothing() {
    // 채워 두면 서명된 룰이 '이 자리를 읽는다 · 이것을 고친다' 고 적어 놓고 아무도 그것을 하지 않는다.
    for (from, to, at) in [
        ("scan_roots: []", "scan_roots: ['/etc']", "scan_roots"),
        ("subjects: []", "subjects: [file]", "subjects"),
        (
            "detect: []",
            "detect: []\nverdict: { require: 'x' }",
            "verdict",
        ),
        ("detect: []", "detect: []\nnetwork: url", "network"),
        (
            "detect: []",
            "detect: []\nfile_names: ['*.json']",
            "file_names",
        ),
        (
            "detect: []",
            "detect: []\nremediate: { remove: [] }",
            "remediate",
        ),
    ] {
        let e = errors(&DATA.replace(from, to));
        assert!(
            e.iter().any(|x| x.starts_with(&format!("{at} ::"))
                && x.contains("데이터 룰은 이 기계를 보지 않는다")),
            "{at}: {e:?}"
        );
    }
}

#[test]
fn a_data_rule_needs_core_1_12_0() {
    let e = errors(&DATA.replace("min_core: '1.12.0'", "min_core: '1.11.0'"));
    assert!(
        e.iter()
            .any(|x| x.starts_with("min_core ::") && x.contains("1.12.0")),
        "{e:?}"
    );
}

#[test]
fn an_ordinary_rule_still_needs_a_verdict() {
    // `verdict` 가 빠져도 읽히게 된 것은 네트워크 점검 룰 때문이다 — 그 밖의 룰에서는 오류로 남는다.
    let e = errors(&BASE.replace("verdict: { require: 'task and payload' }", ""));
    assert!(
        e.iter().any(|x| x.starts_with("verdict.require ::")),
        "{e:?}"
    );
}

// ───────────────────────────── 큰 파일 해시 (`hash_large` · 2026-11-09 · 코어 1.3.0)

/// 기본 모양에 `hash_large` 한 줄을 끼운다.
fn with_hash_large(names: &str, core: &str) -> String {
    BASE.replace("min_core: '1.0.0'", &format!("min_core: '{core}'"))
        .replace("subjects:", &format!("hash_large: {names}\nsubjects:"))
}

#[test]
fn a_hash_large_name_on_core_1_3_0_is_clean() {
    let e = errors(&with_hash_large("['node.exe', 'php*.dll']", "1.3.0"));
    assert!(e.is_empty(), "{e:?}");
}

#[test]
fn a_hash_large_entry_is_one_file_name() {
    // 경로를 적으면 이 키가 읽는 자리를 정하는 것처럼 읽힌다 — 그 자리는 scan_roots 다.
    for bad in ["'C:\\Program Files\\nodejs\\node.exe'", "'bin/node'", "''"] {
        let e = errors(&with_hash_large(&format!("[{bad}]"), "1.3.0"));
        assert!(
            e.iter().any(|x| x.starts_with("hash_large[0] ::")),
            "{bad}: {e:?}"
        );
    }
    // 글자 · 숫자가 없는 꼴은 상한을 넘는 파일을 전부 흘려 읽는다 — 상한을 통째로 올리는 것과 같다.
    // 확장자 하나(`*.exe`)는 좁힌 것이라 받는다.
    let e = errors(&with_hash_large("['*', '*.*', '*.exe']", "1.3.0"));
    for i in 0..2 {
        assert!(
            e.iter()
                .any(|x| x.starts_with(&format!("hash_large[{i}] ::"))
                    && x.contains("어느 이름에나")),
            "{i}: {e:?}"
        );
    }
    assert!(
        !e.iter().any(|x| x.starts_with("hash_large[2] ::")),
        "{e:?}"
    );
}

#[test]
fn a_hash_large_line_needs_core_1_3_0() {
    // 낮은 코어는 이 키를 모른다 — 요구 판을 적어야 로드 단계가 그 차이를 말한다.
    let e = errors(&with_hash_large("['node.exe']", "1.2.1"));
    assert!(
        e.iter()
            .any(|x| x.starts_with("min_core ::") && x.contains("hash_large")),
        "{e:?}"
    );
}

#[test]
fn duplicate_rule_ids_are_an_error() {
    // 같은 id 가 둘이면 `${task.x}` 가 어느 것을 가리키는지 알 수 없다.
    let y = BASE.replace("  - id: payload", "  - id: task");
    let e = errors(&y);
    assert!(e.iter().any(|x| x.contains("중복")), "{e:?}");
}

#[test]
fn a_broken_regex_is_caught_before_it_reaches_a_customer_pc() {
    let y = BASE.replace(
        "{ field: path, op: ends_with, value: '\\main.js' }",
        "{ field: path, op: matches, value: '(unclosed' }",
    );
    let issues = lint(&parse(&y));
    let e: Vec<_> = issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .collect();
    assert_eq!(e.len(), 1, "{issues:#?}");
    assert!(e[0].message.contains("컴파일할 수 없다"), "{:?}", e[0]);
    assert!(
        e[0].valid.as_deref().unwrap_or_default().contains("RE2"),
        "무엇이 안 되는지 말해야 한다: {:?}",
        e[0]
    );
}

/// `payload` 룰의 술어를 통째로 바꿔 끼운다.
fn with_payload_pred(pred: &str) -> String {
    BASE.replace("{ field: path, op: ends_with, value: '\\main.js' }", pred)
}

#[test]
fn a_version_literal_that_is_not_a_version_is_an_error() {
    // 그 항목은 어느 기계에서도 판정을 세우지 못하고 진단만 남긴다 — 문법은
    // 통과하고 룰만 0건이 되는, `sha256` 자리 표시와 같은 모양의 사고다.
    for bad in ["8.2.x", "8.2.29-1ubuntu1", "8.4.0RC1", "v8.2.29", "8.2."] {
        let y = with_payload_pred(&format!(
            "{{ field: path, op: version_lt, value: '{bad}' }}"
        ));
        let e = errors(&y);
        assert_eq!(e.len(), 1, "{bad}: {e:?}");
        assert!(e[0].contains(bad), "{bad} 를 짚지 않았다: {}", e[0]);
    }
}

#[test]
fn a_distro_version_passes_pkg_version_lt_and_fails_version_lt() {
    // **같은 값이 한쪽에서는 맞고 다른 쪽에서는 오류다.** `version_lt` 가 꼬리를
    // 거절하는 것이 그 연산자의 요점이고, `pkg_version_lt` 는 그 꼬리를 받는
    // 것이 요점이다 — 둘을 한 자리에서 보되 판정은 나뉘어야 한다.
    for v in [
        "8.1.2-1ubuntu2.28",
        "1:2.38.1-5+deb12u3",
        "3.6.8-r1",
        "8.2.29~rc1",
        "12.4+deb12u15",
    ] {
        let ok = with_payload_pred(&format!(
            "{{ field: path, op: pkg_version_lt, value: '{v}' }}"
        ));
        assert_eq!(blocking(&lint(&parse(&ok))), 0, "'{v}': {:?}", errors(&ok));

        let no = with_payload_pred(&format!("{{ field: path, op: version_lt, value: '{v}' }}"));
        assert!(
            !errors(&no).is_empty(),
            "'{v}' 를 version_lt 가 받아 버렸다"
        );
    }
}

#[test]
fn a_shape_the_two_package_managers_read_differently_is_an_error() {
    // apk 는 `_alpha` 를 그 판보다 **낮게**, dpkg 의 규칙은 **높게** 읽는다 —
    // 순서가 반대라 추측하지 않는다. 그리고 판이 아닌 것도 막는다.
    for bad in ["1.0_alpha1", "wheezy", "v8.2.29", "-1", "a:1.0"] {
        let y = with_payload_pred(&format!(
            "{{ field: path, op: pkg_version_lt, value: '{bad}' }}"
        ));
        let e = errors(&y);
        assert_eq!(e.len(), 1, "{bad}: {e:?}");
        assert!(e[0].contains(bad), "{bad} 를 짚지 않았다: {}", e[0]);
        // **`version_lt` 의 문구를 내보내면 안 된다** — 그쪽은 "패키지 개정은
        // 받지 않는다" 고 가르치는데 여기서는 그것이 거짓이다.
        assert!(
            !e[0].contains("점으로 나눈 숫자만"),
            "엉뚱한 사유를 냈다: {}",
            e[0]
        );
    }
}

#[test]
fn an_unquoted_version_is_an_error_for_the_package_operator_too() {
    // `pkg_version_lt` 는 꼬리를 받지만, 따옴표 없이 적은 `8.10` 은 꼬리가 아니라
    // **이미 `8.1` 로 도착한 값**이다 — `is_pkg_version` 이 참이라 모양 검사로는
    // 잡히지 않는다.
    for v in ["8.10", "1.20"] {
        let y = with_payload_pred(&format!(
            "{{ field: path, op: pkg_version_lt, value: {v} }}"
        ));
        let e = errors(&y);
        assert_eq!(e.len(), 1, "{v}: {e:?}");
        assert!(e[0].contains("따옴표"), "{v}: {}", e[0]);
    }
}

#[test]
fn an_rpm_version_passes_rpm_version_lt_and_fails_pkg_version_lt() {
    // RHEL 의 개정은 `_` 를 담는다 — `pkg_version_lt` 는 그것을 거절하고(dpkg 와 apk 가 반대로
    // 읽는다) `rpm_version_lt` 는 받는다(rpm 에서는 구분자일 뿐이다).
    for v in [
        "0:8.0.30-8.el9_8.1",
        "7.4.33-8.module+el8.10.0+25117+30337cca",
        "0:8.3.36-150700.3.24.1",
        "1.0~rc1",
        "1.0^git1",
    ] {
        let ok = with_payload_pred(&format!(
            "{{ field: path, op: rpm_version_lt, value: '{v}' }}"
        ));
        assert_eq!(blocking(&lint(&parse(&ok))), 0, "'{v}': {:?}", errors(&ok));
    }
    let no = with_payload_pred("{ field: path, op: pkg_version_lt, value: '0:8.0.30-8.el9_8.1' }");
    assert!(
        !errors(&no).is_empty(),
        "pkg_version_lt 가 `_` 를 받아 버렸다"
    );
}

#[test]
fn a_shape_rpm_does_not_write_is_an_error_for_rpm_version_lt() {
    for bad in [
        "php-8.0.30",
        "el9",
        "a:1.0",
        ":1.0",
        "1.0 2",
        "8.0.30-8.el9#1",
    ] {
        let y = with_payload_pred(&format!(
            "{{ field: path, op: rpm_version_lt, value: '{bad}' }}"
        ));
        let e = errors(&y);
        assert_eq!(e.len(), 1, "{bad}: {e:?}");
        assert!(
            e[0].contains(bad) && e[0].contains("RPM 판"),
            "{bad}: {}",
            e[0]
        );
    }
    // 따옴표 없는 `8.10` 은 이미 `8.1` 로 도착한 값이다 — 모양 검사로는 잡히지 않는다.
    let y = with_payload_pred("{ field: path, op: rpm_version_lt, value: 8.10 }");
    let e = errors(&y);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].contains("따옴표"), "{}", e[0]);
}

#[test]
fn a_version_operator_without_a_value_is_an_error() {
    // 값이 없으면 평가기가 관측에 적을 이름조차 비어 **사유 줄의 끝이 빈 채로**
    // 나간다 — `yara_label` 이 막으려는 바로 그 모양이다. `takes_value` 는
    // 카탈로그에 적혀 있을 뿐 강제되지 않는다(기존).
    let y = with_payload_pred("{ field: path, op: version_lt }");
    let e = errors(&y);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].contains("(없음)"), "빈 값을 그대로 보였다: {}", e[0]);
}

#[test]
fn a_version_literal_written_without_quotes_is_an_error() {
    // **적대 검증이 찾은 high 를 여기 못 박는다** (2026-10-27 · 실측 재현).
    // YAML 은 따옴표 없는 `8.10` 을 실수로 읽고, 엔진에 도착하는 값은 `8.1` 이다 —
    // **뒤의 0 은 돌아오지 않는다.** 그 값으로 견주면 `8.9 < 8.10` 이 거짓이 되어
    // 취약한 기계가 **진단 한 줄 없이 종료 0** 으로 나갔다. `is_version("8.1")` 이
    // 참이라 다른 검사로는 잡히지 않는다.
    //
    // **이 시험의 앞 판은 그 경로를 '통과해야 한다' 고 적고 있었다.**
    for v in ["8.10", "8.2", "8.0", "1.20"] {
        let y = with_payload_pred(&format!("{{ field: path, op: version_lt, value: {v} }}"));
        let e = errors(&y);
        assert_eq!(e.len(), 1, "{v}: {e:?}");
        assert!(
            e[0].contains("따옴표"),
            "따옴표를 요구하지 않았다: {}",
            e[0]
        );
    }
}

#[test]
fn an_integer_and_a_quoted_version_round_trip_so_they_pass() {
    // **음성 대조.** 정수는 왕복하므로 막을 이유가 없고, 따옴표를 친 값은
    // 애초에 손실이 없다. 둘 다 막으면 작성자가 배우는 것은 좁히는 법이 아니라
    // 린트를 피하는 철자법이 된다.
    for v in ["8", "0", "12345"] {
        let y = with_payload_pred(&format!("{{ field: path, op: version_lt, value: {v} }}"));
        assert_eq!(blocking(&lint(&parse(&y))), 0, "{v}: {:?}", errors(&y));
        assert!(warnings(&y).is_empty(), "{v}: {:?}", warnings(&y));
    }
    for v in ["8.10", "8.2.29", "8.0"] {
        let y = with_payload_pred(&format!("{{ field: path, op: version_lt, value: '{v}' }}"));
        assert_eq!(blocking(&lint(&parse(&y))), 0, "'{v}': {:?}", errors(&y));
    }
}

#[test]
fn the_version_check_reads_exclude_too() {
    // `exclude` 에서 못 읽은 버전은 **제외를 일으키지 않아 패치된 기계가
    // 취약으로** 나간다. 그 갈래를 재는 시험이 없어 세 줄을 지워도 전부
    // 초록이었다(2026-10-27 적대 검증).
    let y = BASE.replace(
        "      - { field: path, op: ends_with, value: '\\main.js' }",
        "      - { field: path, op: ends_with, value: '\\main.js' }\n    exclude:\n      \
         - { field: path, op: version_lt, value: '8.2.x' }",
    );
    let e = errors(&y);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(
        e[0].starts_with("detect[1].exclude"),
        "자리가 틀렸다: {}",
        e[0]
    );
}

#[test]
fn a_tail_bearing_version_under_lt_also_gets_the_hint() {
    // **적대 검증(medium)**: 전에는 `is_version` 이 참인 값만 봐서
    // `8.2.29-1ubuntu1` 에 한 글자도 말하지 않았다 — 배포판이 패치한 버전이
    // 바로 그 모양이라 '가장 흔한 경우' 가 조용히 지나갔다.
    for v in ["8.2.29-1ubuntu1", "8.4.0RC1", "8.2.x", "8.2.29"] {
        let y = with_payload_pred(&format!("{{ field: path, op: lt, value: '{v}' }}"));
        assert_eq!(blocking(&lint(&parse(&y))), 0, "{v} 는 오류가 아니다");
        let w = warnings(&y);
        assert_eq!(w.len(), 1, "{v}: {w:?}");
    }
    // 시각은 `lt` 의 정상 입력이다 — 쌍점으로 가른다.
    for v in ["2026-08-21T00:00:00Z", "2026-08-21T00:00:00.5Z"] {
        let y = with_payload_pred(&format!("{{ field: path, op: lt, value: '{v}' }}"));
        assert!(warnings(&y).is_empty(), "{v}: {:?}", warnings(&y));
    }
}

#[test]
fn a_well_formed_version_literal_passes_both_directions() {
    // **음성 대조.** 늘 거부하는 검사는 늘 통과하는 검사만큼 쓸모없다.
    for (op, v) in [
        ("version_lt", "8.2.29"),
        ("version_gt", "8.2"),
        ("version_lt", "8"),
        ("version_lt", "8.2.29.0"),
        // 참조는 리터럴이 아니다 — 지금 알 수 없다.
        ("version_lt", "${task.payload_dir}"),
    ] {
        let y = with_payload_pred(&format!("{{ field: path, op: {op}, value: '{v}' }}"));
        let issues = lint(&parse(&y));
        assert_eq!(blocking(&issues), 0, "{op} {v}: {issues:#?}");
        assert!(warnings(&y).is_empty(), "{op} {v}: {:?}", warnings(&y));
    }
}

#[test]
fn lt_with_a_version_literal_points_at_the_new_operator() {
    // **연산자가 생겼다는 사실을 아무도 알려 주지 않으면** 작성자는 같은
    // 실수를 같은 방식으로 한다. `lt` 는 수와 시각만 보므로 `8.2.29` 는
    // 조용히 거짓이 된다(PHP 대응 자료 §8 ④).
    for (op, want) in [("lt", "version_lt"), ("gt", "version_gt")] {
        let y = with_payload_pred(&format!("{{ field: path, op: {op}, value: '8.2.29' }}"));
        assert_eq!(blocking(&lint(&parse(&y))), 0, "{op} 은 오류가 아니다");
        let w = warnings(&y);
        assert_eq!(w.len(), 1, "{op}: {w:?}");
        let valid = lint(&parse(&y))
            .into_iter()
            .find(|i| i.severity == Severity::Warning)
            .and_then(|i| i.valid)
            .unwrap_or_default();
        assert!(
            valid.contains(want),
            "{op} 에게 {want} 를 알리지 않았다: {valid}"
        );
    }
}

#[test]
fn a_number_or_an_instant_under_lt_stays_quiet() {
    // 수로도 읽히는 값은 `lt` 의 정상 입력이다 — `8.2` 까지 경고하면 작성자가
    // 배우는 것은 좁히는 법이 아니라 **경고를 끄는 철자법**이 된다.
    for v in [
        "4096",
        "8.2",
        "0",
        "2026-08-21T00:00:00Z",
        "${baseline.when}",
    ] {
        let y = with_payload_pred(&format!("{{ field: path, op: lt, value: '{v}' }}"));
        assert!(warnings(&y).is_empty(), "{v}: {:?}", warnings(&y));
    }
    // 따옴표가 없어 YAML 이 수로 주는 경우도 같다. **`gt`·`lt` 에서는 실수가
    // 정상 입력**이므로 따옴표를 요구하지 않는다 — 거기서는 수로 견주기 때문이다.
    for v in ["4096", "8.2", "0", "8.10"] {
        let y = with_payload_pred(&format!("{{ field: path, op: lt, value: {v} }}"));
        assert_eq!(blocking(&lint(&parse(&y))), 0, "{v}: {:?}", errors(&y));
        assert!(warnings(&y).is_empty(), "{v}: {:?}", warnings(&y));
    }
}

#[test]
fn a_broken_regex_in_exclude_is_caught_too() {
    // `exclude` 에서 깨진 정규식은 평가 때도 말이 없다 — 제외가 조용히 꺼지고,
    // 치료 플러그인이면 걸러 내려던 정상 파일이 증거로 남는다.
    let y = BASE.replace(
        "      - { field: path, op: ends_with, value: '\\main.js' }",
        "      - { field: path, op: ends_with, value: '\\main.js' }\n    exclude:\n      \
         - { field: path, op: matches, value: '(?=vendor)' }",
    );
    let issues = lint(&parse(&y));
    let e: Vec<_> = issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .collect();
    assert_eq!(e.len(), 1, "{issues:#?}");
    assert!(e[0].at.contains("exclude"), "{:?}", e[0]);
    assert!(e[0].message.contains("컴파일할 수 없다"), "{:?}", e[0]);
}

#[test]
fn a_regex_with_a_capture_reference_is_reported_as_unchecked_not_silently_skipped() {
    // 검사하지 못한 것을 조용히 넘기면 "린트 통과" 가 거짓말이 된다.
    let y = BASE.replace(
        "{ field: path, op: ends_with, value: '\\main.js' }",
        "{ field: path, op: matches, value: '^${task.payload_dir}.*' }",
    );
    let w = warnings(&y);
    assert!(
        w.iter().any(|x| x.contains("미리 컴파일할 수 없다")),
        "{w:?}"
    );
    assert_eq!(errors(&y).len(), 0, "경고이지 오류가 아니다");
}

#[test]
fn valid_regex_passes() {
    let y = BASE.replace(
        "{ field: path, op: ends_with, value: '\\main.js' }",
        r"{ field: path, op: matches, value: '(?i)\\node\.exe$' }",
    );
    assert_eq!(errors(&y).len(), 0, "{:?}", errors(&y));
}

#[test]
fn remediate_referencing_reputation_is_refused() {
    // **방향 제약** (설계-03 §3 5층). 감염 호스트의 네트워크는 신뢰할 수 없다 —
    // 조회 응답을 근거로 파괴를 늘리면 공격자가 응답을 조작해 정상 파일을
    // 지우게 만들 수 있다.
    let y = format!("{BASE}\nremediate:\n  remove:\n    - {{ ref: 'reputation.malicious' }}\n");
    let e = errors(&y);
    assert!(
        e.iter().any(|x| x.contains("reputation")),
        "reputation 참조가 막혀야 한다: {e:?}"
    );
}

#[test]
fn remediate_referencing_a_missing_rule_is_an_error() {
    let y = format!("{BASE}\nremediate:\n  remove:\n    - {{ ref: 없는룰 }}\n");
    let e = errors(&y);
    assert!(e.iter().any(|x| x.contains("없는룰")), "{e:?}");
}

#[test]
fn remediate_referencing_a_real_rule_passes() {
    let y = format!("{BASE}\nremediate:\n  remove:\n    - {{ ref: payload }}\n");
    assert_eq!(errors(&y).len(), 0, "{:?}", errors(&y));
}

#[test]
fn recursive_delete_without_guard_is_an_error() {
    // capture 해석이 어긋나 대상이 엉뚱한 상위 경로로 잡혀도, 그 안에 악성 판정
    // 파일이 없으면 계획이 만들어지지 않아야 한다 (설계-03 §4).
    let y = format!(
        "{BASE}\nremediate:\n  remove:\n    - {{ path: '${{task.payload_dir}}', recursive: true }}\n"
    );
    let e = errors(&y);
    assert!(e.iter().any(|x| x.contains("guard")), "{e:?}");
}

#[test]
fn overbroad_scan_root_is_a_warning_not_an_error() {
    // 넓은 범위가 실제로 필요한 플러그인이 있다. 오류로 막으면 작성자가
    // 우회로를 만든다.
    let y = BASE.replace("'C:\\remedy-lab\\fixtures'", "'C:\\'");
    let w = warnings(&y);
    assert!(w.iter().any(|x| x.contains("scan_roots")), "{w:?}");
    assert_eq!(errors(&y).len(), 0, "경고이지 오류가 아니다");
}

#[test]
fn breadth_is_measured_by_where_the_token_points_not_by_its_letters() {
    // **관측 01 D1.** 세그먼트만 세면 좁은 쪽이 경고를 맞고 넓은 쪽이 통과한다.
    // `%LOCALAPPDATA%` 는 한 덩어리지만 실제로는 다섯 단계 깊고,
    // `C:\Users` 는 두 조각인데 전 사용자를 품는다.
    let localappdata = BASE.replace("'C:\\remedy-lab\\fixtures'", "'%LOCALAPPDATA%'");
    let w = warnings(&localappdata);
    assert!(
        !w.iter().any(|x| x.contains("전체를 훑는다")),
        "%LOCALAPPDATA% 를 과광범위로 봤다: {w:?}"
    );

    let users = BASE.replace("'C:\\remedy-lab\\fixtures'", "'C:\\Users'");
    let w = warnings(&users);
    assert!(
        w.iter().any(|x| x.contains("전체를 훑는다")),
        "C:\\Users 가 통과했다 — 전 사용자를 품는다: {w:?}"
    );

    // 관측 01 에서 실제로 뒤집혔던 짝. 이제 방향이 맞는다.
    let userprofile = BASE.replace("'C:\\remedy-lab\\fixtures'", "'%USERPROFILE%'");
    assert!(
        !warnings(&userprofile)
            .iter()
            .any(|x| x.contains("전체를 훑는다")),
        "%USERPROFILE% 는 사용자 하나다"
    );
}

#[test]
fn a_wide_root_with_structured_config_says_what_it_costs() {
    // **폭 경고가 두 가지를 뜻한다.** 보통은 "지울 수 있는 범위가 넓다" 이고,
    // `structured_config` 가 함께 선언되면 거기에 **스캔이 아예 서지 못한다**
    // 가 더해진다 — 그 수집기는 JSON 을 잎 단위로 펴므로 넓은 경로에서
    // `scope.max_files`(5만)에 걸리고, 잘린 스냅샷은 종료 코드 6 이 된다.
    //
    // 2026-09-04 실측: `C:\ProgramData` 로 감염 스냅샷을 뜨려다 그렇게 됐다.
    // Windows 자신의 원격 분석 설정 하나(utc.privacy.json 4 MB)가 삼켰다.
    // 경고는 이미 있었지만 **무엇을 잃는지 말하지 않아** 그 자리를 지나쳤다.
    let wide = BASE.replace("'C:\\remedy-lab\\fixtures'", "'C:\\ProgramData'");
    let w = warnings(&wide);
    assert!(
        w.iter().any(|x| x.contains("전체를 훑는다")),
        "C:\\ProgramData 가 통과했다: {w:?}"
    );
    assert!(
        !w.iter().any(|x| x.contains("종료 코드")),
        "structured_config 를 선언하지 않았는데 그 대가를 말했다: {w:?}"
    );

    let with_sc = wide.replace(
        "subjects: [persistence, file]",
        "subjects: [persistence, file, structured_config]",
    );
    let w = warnings(&with_sc);
    let hit = w
        .iter()
        .find(|x| x.contains("전체를 훑는다"))
        .unwrap_or_else(|| panic!("폭 경고가 사라졌다: {w:?}"));
    assert!(
        hit.contains("structured_config") && hit.contains("종료 코드"),
        "무엇을 잃는지 말하지 않았다: {hit}"
    );
}

#[test]
fn an_unknown_token_is_reported_as_unmeasured_not_passed() {
    // 폭을 재지 못한 것을 통과로 읽으면 "검사했다" 가 거짓이 된다.
    let y = BASE.replace("'C:\\remedy-lab\\fixtures'", "'%NOSUCHVAR%\\x\\y'");
    let w = warnings(&y);
    assert!(
        w.iter().any(|x| x.contains("폭을 재지 못했다")),
        "모르는 토큰이 조용히 통과했다: {w:?}"
    );
}

#[test]
fn a_wildcard_in_scan_roots_is_an_error() {
    // 관측 01 에서 과광범위 경고가 작성자를 정확히 이 함정으로 몰았다 —
    // "좁혀라" 는 말에 `\*` 를 붙였고, 린트는 초록이 됐고, 수집은 0건이 됐다.
    let y = BASE.replace("'C:\\remedy-lab\\fixtures'", "'%LOCALAPPDATA%\\*'");
    let e = errors(&y);
    assert!(
        e.iter().any(|x| x.contains("와일드카드")),
        "와일드카드가 통과했다: {e:?}"
    );
}

#[test]
fn a_verdict_resting_on_one_rule_is_a_warning() {
    // 독립적인 두 근거의 논리곱이라야 룰 하나의 오탐이 곧바로 삭제로 이어지지 않는다.
    let y = BASE.replace("require: 'task and payload'", "require: 'task'");
    let w = warnings(&y);
    assert!(w.iter().any(|x| x.contains("verdict.require")), "{w:?}");
}

#[test]
fn the_lab_plugin_in_the_repo_lints_clean() {
    // 저장소가 들고 있는 유일한 플러그인이다. 이것이 린트를 통과하지 못하면
    // 린터든 플러그인이든 둘 중 하나가 틀렸다.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testbed/harness/guest/lab-plugin.yaml");
    let text = std::fs::read_to_string(&path).expect("실험 플러그인");
    let m: PluginManifest = serde_yaml_ng::from_str(&text).expect("파싱");
    let issues = lint(&m);
    assert_eq!(blocking(&issues), 0, "오류가 있다: {issues:#?}");
}

// ───────────────────────── restore_default 대상 (설계-03 §2, P7)

const WINLOGON: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

/// `to: default` 로 되돌리려는 레지스트리 규칙을 붙인 매니페스트.
///
/// 대상을 리터럴로 고정하므로 린트가 판단할 수 있다.
fn with_restore(hive: &str, key: &str, name: &str) -> String {
    let rule = format!(
        "  - id: shell\n    subject: registry_value\n    where:\n      all:\n\
         \x20       - {{ field: hive, op: equals, value: '{hive}' }}\n\
         \x20       - {{ field: key,  op: equals, value: '{key}' }}\n\
         \x20       - {{ field: name, op: equals, value: '{name}' }}\n\
         verdict: {{ require: 'task and payload' }}"
    );
    BASE.replace(
        "subjects: [persistence, file]",
        "subjects: [persistence, file, registry_value]",
    )
    .replace("verdict: { require: 'task and payload' }", &rule)
        + "remediate:\n  restore:\n    - { ref: shell, to: default }\n"
}

#[test]
fn a_target_in_the_defaults_catalog_passes() {
    // 막지 말아야 할 것을 막으면 작성자가 우회로를 만든다.
    let y = with_restore("HKLM", WINLOGON, "Shell");
    let e = errors(&y);
    assert!(
        !e.iter().any(|x| x.contains("기본값 카탈로그")),
        "카탈로그에 있는 대상을 막았다: {e:?}"
    );
}

#[test]
fn a_target_outside_the_catalog_is_refused_with_the_list() {
    // **서명된 도구가 임의 레지스트리 값을 쓸 수 있으면 그 자체가 공격 도구다.**
    let y = with_restore("HKLM", "SOFTWARE\\Vendor\\Config", "Payload");
    let issues = lint(&parse(&y));
    let hit = issues
        .iter()
        .find(|i| i.message.contains("기본값 카탈로그"))
        .unwrap_or_else(|| panic!("카탈로그 밖 대상이 통과했다: {issues:#?}"));
    assert_eq!(hit.severity, Severity::Error);
    // 유효 목록을 줘야 그 자리에서 고친다 (설계-06 §7).
    let valid = hit.valid.as_deref().unwrap_or("");
    assert!(valid.contains("Winlogon"), "유효 목록이 없다: {valid}");
}

#[test]
fn a_restore_ref_to_a_missing_rule_is_refused() {
    // `check_remediate_refs` 는 remove·edit 만 보고 restore 를 보지 않았다.
    let y = with_restore("HKLM", WINLOGON, "Shell").replace(
        "{ ref: shell, to: default }",
        "{ ref: nosuch, to: default }",
    );
    let e = errors(&y);
    assert!(
        e.iter().any(|x| x.contains("없는 규칙")),
        "없는 규칙을 가리키는데 통과했다: {e:?}"
    );
}

#[test]
fn a_target_that_is_not_pinned_is_a_warning_not_a_pass() {
    // 대상이 증거에 따라 달라지면 여기서는 알 수 없다. 조용히 통과시키면
    // "린트 통과" 가 거짓말이 된다 — 계획 단계가 본다는 사실을 남긴다.
    let y = with_restore("HKLM", WINLOGON, "Shell").replace(
        "{ field: name, op: equals, value: 'Shell' }",
        "{ field: name, op: contains, value: 'Sh' }",
    );
    let w = warnings(&y);
    assert!(
        w.iter().any(|x| x.contains("계획 단계")),
        "고정되지 않은 대상을 조용히 통과시켰다: {w:?}"
    );
}

// ───────────────────────── 아직 채워지지 않는 필드 (설계-09 P9)

#[test]
fn a_rule_that_reads_a_field_the_core_never_fills_is_warned() {
    // **이름이 맞으므로 `check_fields` 는 통과시킨다.** 그런데 수집기가 그
    // 필드를 채우지 않으므로 술어는 언제나 거짓이고, 작성자는 룰이 도는 줄
    // 안다 (설계-09 P9).
    let y = BASE.replace(
        r"{ field: path, op: ends_with, value: '\main.js' }",
        "{ field: 'streams', op: exists }",
    );
    assert_ne!(
        y, BASE,
        "치환이 걸리지 않았다 — 이 시험은 아무것도 재지 않는다"
    );
    let w = warnings(&y);
    assert!(
        w.iter().any(|x| x.contains("streams")
            && x.contains("아직 채우지 않는")
            && x.contains("unsafe")),
        "{w:#?}"
    );
    // 오류는 아니다 — 룰이 틀린 것이 아니라 코어가 아직 못 하는 것이다.
    assert!(errors(&y).is_empty(), "{:#?}", errors(&y));
}

/// 수집기는 룰이 모듈 칸을 쓸 때만 Windows 의 모듈 목록을 연다(`Scope::process_modules`) — 그 물음에 답하는
/// 함수가 `where` 와 `exclude` 를 둘 다 보는가. 하나라도 놓치면 모듈을 겨눈 룰이 빈 목록을 받아 조용히 미탐이
/// 된다.
#[test]
fn uses_field_sees_where_and_exclude() {
    use remedy_sdk::catalog::Subject;
    let mods = ["modules", "modules_denied"];
    // 쓰지 않는다 — BASE 는 지속성 · 파일만 본다.
    assert!(!remedy_sdk::lint::uses_field(
        &parse(BASE),
        Subject::Process,
        &mods
    ));
    let with = |rule: &str| {
        BASE.replace(
            "verdict: { require: 'task and payload' }",
            &format!("{rule}\nverdict: {{ require: 'task and payload' }}"),
        )
    };
    let in_where = with(
        "  - id: mods\n    subject: process\n    where:\n      - { field: modules, op: contains, value: php8ts }",
    );
    let in_exclude = with(
        "  - id: mods\n    subject: process\n    where:\n      - { field: image_path, op: ends_with, value: httpd.exe }\n    exclude:\n      - { field: modules_denied, op: equals, value: 'true' }",
    );
    let other_field = with(
        "  - id: mods\n    subject: process\n    where:\n      - { field: image_path, op: ends_with, value: httpd.exe }",
    );
    for (name, y, want) in [
        ("where", &in_where, true),
        ("exclude", &in_exclude, true),
        ("다른 칸", &other_field, false),
    ] {
        assert_ne!(y.as_str(), BASE, "{name}: 치환이 걸리지 않았다");
        assert_eq!(
            remedy_sdk::lint::uses_field(&parse(y), Subject::Process, &mods),
            want,
            "{name}"
        );
    }
}

#[test]
fn a_rule_that_reads_process_modules_on_windows_is_not_warned() {
    // 2026-10-27 부터 이 자리는 *"Windows 에서 `modules` 를 쓰면 경고한다"* 를 쟀다 —
    // 그때 Windows 수집기는 목록을 늘 비웠고, 모든 프로세스가 싣는 `ntdll` 을 건 검사가
    // 경고 없이 종료 0 으로 끝났던 일이 그 경고를 세웠다(PHP 문서 §8-3 실측).
    // **2026-11-12 부터 Windows 도 채운다**(`remedy-winmods`) — 이제 경고하면 채워진 목록을
    // 쓴 룰에 거짓말을 하는 것이다. Linux 쪽 같은 시험이 아래에 있다.
    let y = BASE
        .replace(
            "subjects: [persistence, file]",
            "subjects: [persistence, file, process]",
        )
        .replace(
            "verdict: { require: 'task and payload' }",
            "  - id: mods\n    subject: process\n    where:\n      \
             - { field: modules, op: contains, value: ntdll }\n\
             verdict: { require: 'task and payload and mods' }",
        );
    assert_ne!(
        y, BASE,
        "치환이 걸리지 않았다 — 이 시험은 아무것도 재지 않는다"
    );
    let w = warnings(&y);
    assert!(
        !w.iter().any(|x| x.contains("modules")),
        "Windows 도 채우는 필드에 '언제나 거짓' 이라고 말했다: {w:#?}"
    );
    assert!(errors(&y).is_empty(), "{:#?}", errors(&y));
}

#[test]
fn the_same_rule_on_linux_is_not_warned_because_linux_fills_it() {
    // **축이 있는 이유다.** 2026-09-05 에 `file.signature` 를 "어디서나 빈다" 로
    // 적고 있었고, 그래서 린트가 Windows 작성자에게 *"이 술어는 언제나
    // 거짓이다"* 라고 말했다 — 거짓말이었다. 방향을 바꿔 같은 자리가 생기지
    // 않게 여기서 잰다: Linux 는 `/proc/<pid>/maps` 로 모듈을 채우므로
    // **말할 것이 없다.**
    let y = LINUX_BASE
        .replace(
            "subjects: [text_config]",
            "subjects: [text_config, process]",
        )
        .replace(
            "verdict: { require: 'hook' }",
            "  - id: mods\n    subject: process\n    where:\n      \
             - { field: modules, op: contains, value: libphp }\n\
             verdict: { require: 'hook and mods' }",
        );
    assert_ne!(
        y, LINUX_BASE,
        "치환이 걸리지 않았다 — 이 시험은 아무것도 재지 않는다"
    );
    let w = warnings(&y);
    assert!(
        !w.iter().any(|x| x.contains("modules")),
        "Linux 가 채우는 필드에 '언제나 거짓' 이라고 말했다: {w:#?}"
    );
    assert!(errors(&y).is_empty(), "{:#?}", errors(&y));
}

#[test]
fn the_same_field_inside_exclude_says_the_exclusion_will_not_happen() {
    // **`exclude` 에 있으면 방향이 반대다.** 술어가 거짓이면 제외가 일어나지
    // 않아 조용히 **더 공격적인** 쪽으로 무너진다. EvilAI 초안의 첫 오탐
    // 방어가 정확히 그 모양이었다.
    // **필드를 `signature.subject` 에서 `streams` 로 바꿨다** (2026-09-05).
    // `signature` 는 Windows 에서 채워지게 됐고 `BASE` 는 Windows 전용이라,
    // 그대로 두면 이 시험이 **채워지는 필드**를 대고 묻는다.
    let y = BASE.replace(
        "    capture:",
        "    exclude:\n      - { field: 'file(command).streams', op: exists }\n    capture:",
    );
    assert_ne!(
        y, BASE,
        "치환이 걸리지 않았다 — 이 시험은 아무것도 재지 않는다"
    );
    let w = warnings(&y);
    assert!(
        w.iter()
            .any(|x| x.contains("exclude") && x.contains("제외가 일어나지 않는다")),
        "{w:#?}"
    );
}

#[test]
fn a_rule_that_only_reads_filled_fields_gets_no_such_warning() {
    // 위 두 시험이 "언제나 경고한다" 로 통과하면 안 된다.
    let w = warnings(BASE);
    assert!(
        !w.iter().any(|x| x.contains("아직 채우지 않는")),
        "채워지는 필드만 쓰는데 경고가 났다: {w:#?}"
    );
}

#[test]
fn every_unfilled_field_names_a_field_that_actually_exists() {
    // **목록이 실재하지 않는 필드를 가리키면 이 검사는 아무것도 잡지 못한다.**
    // `fields()` 에 없는 이름을 적어 두면 술어가 그 이름을 쓸 수도 없다.
    use remedy_sdk::catalog::Subject;
    for (s, field, only_on, why) in Subject::NOT_POPULATED_YET {
        // **한 플랫폼에서만 빈다고 적었으면 그 플랫폼에 개념이 있어야 한다.**
        // 없는 플랫폼을 가리키면 그 줄은 영영 아무에게도 말하지 않는다.
        if let Some(p) = only_on {
            let i = s.info();
            let exists = match p {
                remedy_sdk::catalog::Platform::Windows => i.windows,
                _ => i.linux,
            };
            assert!(
                exists,
                "'{}' 의 '{field}' 가 {} 에서 빈다고 적혔는데 그 플랫폼에 이 subject 가 없다",
                s.id(),
                p.id()
            );
        }
        let known = s.fields();
        assert!(
            known
                .iter()
                .any(|f| *f == field || f.starts_with(&format!("{field}."))),
            "'{}' 의 '{field}' 가 subject 필드 목록에 없다: {known:?}",
            s.id()
        );
        assert!(why.len() > 40, "'{field}': 이유가 너무 짧다");
    }
}

#[test]
fn descendants_on_a_non_process_subject_is_an_error() {
    // **다른 subject 에 붙으면 계획기가 조용히 무시한다.** 작성자는 계보까지
    // 지운 줄 알고, 감시자는 살아남는다 (설계-03 §2).
    let y = format!("{BASE}remediate:\n  remove:\n    - {{ ref: payload, descendants: true }}\n");
    let e = errors(&y);
    assert!(
        e.iter()
            .any(|x| x.contains("descendants") && x.contains("프로세스에만")),
        "{e:#?}"
    );
}

#[test]
fn descendants_on_a_process_subject_passes() {
    // 위 시험이 "언제나 막는다" 로 통과하면 안 된다.
    let y = BASE
        .replace(
            "subjects: [persistence, file]",
            "subjects: [persistence, file, process]",
        )
        // 규칙은 `verdict` 앞에 들어가야 한다 — BASE 는 그 줄로 끝난다.
        .replace(
            "verdict: { require: 'task and payload' }",
            "  - id: proc\n    subject: process\n    where:\n      \
             - { field: image_path, op: contains, value: 'evil' }\n\
             verdict: { require: 'task and payload' }\n\
             remediate:\n  remove:\n    - { ref: proc, descendants: true }",
        );
    let e = errors(&y);
    assert!(
        !e.iter().any(|x| x.contains("descendants")),
        "프로세스인데 막았다: {e:#?}"
    );
}

/// BASE 에 규칙 하나를 더하고 그것을 `edit` 로 가리킨다.
fn with_edit(subject: &str, rule: &str) -> String {
    BASE.replace(
        "subjects: [persistence, file]",
        &format!("subjects: [persistence, file, {subject}]"),
    )
    .replace(
        "scan_roots: ['C:\\remedy-lab\\fixtures', '%SystemRoot%\\System32\\Tasks']",
        "scan_roots: ['C:\\remedy-lab\\fixtures', '%SystemRoot%\\System32\\Tasks', \
         'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon']",
    )
    // 규칙은 `verdict` 앞에 들어가야 한다 — BASE 는 그 줄로 끝난다.
    .replace(
        "verdict: { require: 'task and payload' }",
        &format!(
            "{rule}verdict: {{ require: 'task and payload' }}\n\
             remediate:\n  edit:\n    - {{ ref: target, op: strip, value: '${{target.tail}}' }}\n"
        ),
    )
}

#[test]
fn edit_on_a_shortcut_is_an_error_that_points_to_remove() {
    // **계획기는 `edit` 의 대상을 보지 않는다.** 바로가기에도 `registry.strip_value`
    // 를 세우고, 백업이 `.lnk` 를 레지스트리로 읽지 못해 치료가 guard 정지로
    // 끝났다 (2026-09-28 `shortcut-r1` 실기기). 인자는 `remove` 가 뗀다.
    let y = with_edit(
        "shortcut",
        "  - id: target\n    subject: shortcut\n    where:\n      \
         - { field: args, op: contains, value: '--load-extension=' }\n    \
         capture: { tail: 'args' }\n",
    );
    let e = errors(&y);
    assert!(
        e.iter().any(|x| x.starts_with("remediate.edit[0].ref")
            && x.contains("remove")
            && x.contains("shortcut.strip_args")),
        "{e:#?}"
    );
}

#[test]
fn edit_on_a_structured_config_is_an_error_that_points_to_remove() {
    // Linux 에는 부분 편집 Op 이 없어 보류로 빠지고, 보류 사유는 까닭을 말하지
    // 않는다 (2026-09-28 `npm-r1` 사전 기준의 변형). 설정 항목은 `remove` 가
    // 키 하나만 뺀다.
    let y = with_edit(
        "structured_config",
        "  - id: target\n    subject: structured_config\n    where:\n      \
         - { field: key_path, op: equals, value: 'scripts.postinstall' }\n    \
         capture: { tail: 'value' }\n",
    );
    let e = errors(&y);
    assert!(
        e.iter().any(|x| x.starts_with("remediate.edit[0].ref")
            && x.contains("remove")
            && x.contains("structured_config.remove_key")),
        "{e:#?}"
    );
}

#[test]
fn edit_on_a_registry_value_passes() {
    // 위 두 시험이 "`edit` 는 언제나 막는다" 로 통과하면 안 된다.
    let y = with_edit(
        "registry_value",
        "  - id: target\n    subject: registry_value\n    where:\n      \
         - { field: name, op: equals, value: 'Userinit' }\n    \
         capture: { tail: 'data' }\n",
    );
    let e = errors(&y);
    assert!(
        !e.iter().any(|x| x.starts_with("remediate.edit")),
        "레지스트리 값인데 막았다: {e:#?}"
    );
}

#[test]
fn edit_on_a_windows_autorun_passes() {
    // **`Userinit` 은 `autorun` 으로도 모인다**(Winlogon 의 실행 값 셋 —
    // `remedy-collect` `registry.rs`). 계획기는 그 대상을 `키\값이름` 으로
    // 세우므로 부분 편집이 그대로 맞는다 — 설계-02 §6-1 의 대표 용도다.
    let y = with_edit(
        "autorun",
        "  - id: target\n    subject: autorun\n    where:\n      \
         - { field: name, op: equals, value: 'Userinit' }\n    \
         capture: { tail: 'command' }\n",
    );
    let e = errors(&y);
    assert!(
        !e.iter().any(|x| x.starts_with("remediate.edit")),
        "자동 실행 값인데 막았다: {e:#?}"
    );
}

#[test]
fn 재부팅_후_재평가는_이제_경고가_아니다() {
    // **P10-F 에서 구현됐다.** 이전에는 "아직 이 코어에 없다" 를 경고했다 —
    // 조용히 무시하면 작성자는 재부팅 뒤 확인이 걸린 줄 알고, 랜덤 폴더명이
    // 바뀌는 재감염은 그 확인으로만 잡히기 때문이었다.
    //
    // 이제 계획이 그 요청을 나르고(`PlanBody::verify_after_reboot`), `apply` 가
    // RunOnce 에 일회성 항목을 등록한다. 경고가 남아 있으면 **회피할 수 없는
    // 경고**가 되고, 그런 경고는 무시되기 시작한다 (설계-06 §7).
    let y = format!(
        "{BASE}remediate:\n  remove:\n    - {{ ref: payload }}\n  verify:\n    after_reboot: true\n"
    );
    let w = warnings(&y);
    assert!(
        !w.iter().any(|x| x.contains("after_reboot")),
        "구현됐는데 아직 경고한다: {w:#?}"
    );
    assert!(
        errors(&y).is_empty(),
        "오류가 나오면 안 된다: {:#?}",
        errors(&y)
    );
}

#[test]
fn not_asking_for_it_says_nothing() {
    // 위 시험이 "언제나 경고한다" 로 통과하면 안 된다.
    let y = format!("{BASE}remediate:\n  remove:\n    - {{ ref: payload }}\n");
    assert!(
        !warnings(&y).iter().any(|x| x.contains("after_reboot")),
        "{:#?}",
        warnings(&y)
    );
}

// ── 재귀 삭제 범위 (설계-06 §7 다섯 번째 검사) ──────────────────────

/// BASE 에 `remediate.remove` 하나를 붙인다. `scan_roots` 도 갈아 끼운다.
fn with_recursive(scan_roots: &str, path: &str, recursive: bool) -> String {
    let base = BASE.replace(
        r"scan_roots: ['C:\remedy-lab\fixtures', '%SystemRoot%\System32\Tasks']",
        &format!("scan_roots: {scan_roots}"),
    );
    format!(
        "{base}\nremediate:\n  remove:\n    - path: '{path}'\n      recursive: {recursive}\n      guard: payload\n"
    )
}

#[test]
fn 홈_직하를_통째로_지우면_경고한다() {
    // Documents·Desktop·Downloads 가 있는 자리다. 위협 하나를 없애려다 사람의
    // 자료를 없앤다.
    for path in [
        r"%USERPROFILE%\Downloads",
        r"C:\Users\bob\Documents",
        r"%PUBLIC%\Desktop",
    ] {
        let y = with_recursive(r"['C:\remedy-lab\fixtures']", path, true);
        let w = warnings(&y);
        assert!(
            w.iter().any(|m| m.contains("홈 직하")),
            "경고하지 않았다 — {path}\n{w:#?}"
        );
    }
}

#[test]
fn 홈_아래_깊은_곳은_경고하지_않는다() {
    // `%LOCALAPPDATA%\Programs` 는 홈에서 세 칸 아래다. 여기까지 경고하면
    // 회피할 수 없는 경고가 되고, 그러면 검사가 무시되기 시작한다.
    for path in [
        r"%LOCALAPPDATA%\Programs\SomeApp",
        r"%APPDATA%\Vendor",
        r"C:\Program Files\App",
    ] {
        let y = with_recursive(r"['C:\remedy-lab\fixtures']", path, true);
        let w = warnings(&y);
        assert!(
            !w.iter().any(|m| m.contains("홈 직하")),
            "쓸데없이 경고했다 — {path}\n{w:#?}"
        );
    }
}

#[test]
fn 파생_경로는_상한으로_판정한다() {
    // `${...}` 는 매니페스트만 보고 값을 알 수 없다. 상한은 scan_roots 이므로
    // 그 아래에 홈 직하가 들어갈 수 있으면 이 재귀 삭제도 거기 닿을 수 있다.
    let risky = with_recursive(r"['%USERPROFILE%']", "${task.payload_dir}", true);
    let w = warnings(&risky);
    assert!(
        w.iter().any(|m| m.contains("홈 직하")),
        "상한이 홈인데 경고하지 않았다\n{w:#?}"
    );

    let safe = with_recursive(r"['%LOCALAPPDATA%\Programs']", "${task.payload_dir}", true);
    let w = warnings(&safe);
    assert!(
        !w.iter().any(|m| m.contains("홈 직하")),
        "상한이 깊은데 경고했다\n{w:#?}"
    );
}

#[test]
fn 재귀가_아니면_보지_않는다() {
    // 파일 하나를 지우는 것은 이 검사의 대상이 아니다.
    let y = with_recursive(
        r"['%USERPROFILE%']",
        r"%USERPROFILE%\Downloads\evil.exe",
        false,
    );
    let w = warnings(&y);
    assert!(
        !w.iter().any(|m| m.contains("홈 직하")),
        "재귀가 아닌데 경고했다\n{w:#?}"
    );
}

#[test]
fn 홈들이_모인_곳도_상한으로_본다() {
    // `C:\Users` 아래에는 모든 사용자의 홈이 있다. 파생 경로가 그 아래 두 칸이면
    // 누군가의 홈 직하다.
    for root in [r"['C:\Users']", r"['%ALLUSERPROFILES%']", r"['/home']"] {
        let y = with_recursive(root, "${task.payload_dir}", true);
        let w = warnings(&y);
        assert!(
            w.iter().any(|m| m.contains("홈 직하")),
            "경고하지 않았다 — scan_roots {root}\n{w:#?}"
        );
    }
}

// ─────────────────────────── YARA 는 본문이 있어야 돈다

/// BASE 의 `payload` 를 YARA 로 바꾼 것. `collect_extra` 는 없다.
const YARA_NO_CONTENT: &str = r#"
schema_version: 1
id: lint-yara
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: { ko: '시험', en: 'lint yara' }
scan_roots: ['C:\remedy-lab\fixtures']
subjects: [persistence, file]
detect:
  - id: task
    subject: persistence
    where:
      all:
        - { field: command, op: contains, value: '\remedy-lab\fixtures\' }
    capture:
      payload_dir: 'command | dirname'
  - id: payload
    subject: file
    from: '${task.payload_dir}'
    where:
      - { yara: 'rules/x.yar:some_rule' }
verdict: { require: 'task and payload' }
"#;

#[test]
fn yara_without_collected_content_is_an_error() {
    // 본문이 없으면 평가기는 "안 맞았다" 가 아니라 "재지 못했다" 를 낸다.
    // 실기기에서만 드러나므로 룰을 손에 든 자리에서 막는다.
    let e = errors(YARA_NO_CONTENT);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].contains("collect_extra"), "{e:?}");
}

#[test]
fn yara_with_collected_content_passes() {
    let yaml = YARA_NO_CONTENT.to_string() + "collect_extra:\n  - { ref: task, content: true }\n";
    assert!(errors(&yaml).is_empty(), "{:?}", errors(&yaml));
}

#[test]
fn a_collect_extra_that_does_not_take_content_does_not_count() {
    // `content: false` 는 본문을 담지 않는다. 항목이 있다는 것만으로
    // 통과시키면 이 검사가 아무것도 막지 못한다.
    let yaml = YARA_NO_CONTENT.to_string() + "collect_extra:\n  - { ref: task }\n";
    assert_eq!(errors(&yaml).len(), 1, "{:?}", errors(&yaml));
}

#[test]
fn a_manifest_without_yara_needs_no_collected_content() {
    // BASE 는 YARA 를 쓰지 않는다. 이 검사가 거기까지 번지면 안 된다.
    assert!(errors(BASE).is_empty(), "{:?}", errors(BASE));
}

#[test]
fn a_subject_form_collect_extra_does_not_count_as_content() {
    // `subject` 형은 "이 경로를 이 subject 로도 보라" 는 뜻이라 본문을 담지
    // 않는다. 세면 YARA 가 미평가인 매니페스트가 통과한다.
    let yaml = YARA_NO_CONTENT.to_string()
        + r"collect_extra:
  - { subject: file, path: 'C:\remedy-lab\fixtures' }
";
    assert_eq!(errors(&yaml).len(), 1, "{:?}", errors(&yaml));
}

#[test]
fn a_path_form_collect_extra_counts_as_content() {
    // `path` 형은 그 경로의 본문을 담는 것이 목적이다.
    let yaml = YARA_NO_CONTENT.to_string()
        + r"collect_extra:
  - { path: 'C:\remedy-lab\fixtures\x.js' }
";
    assert!(errors(&yaml).is_empty(), "{:?}", errors(&yaml));
}

// ─────────────────────── restore 는 되돌릴 증거가 있어야 한다

#[test]
fn a_named_restore_without_its_subject_rule_is_an_error() {
    // `restore: [av_exclusions]` 는 av_exclusion **증거**를 되돌린다. 그 subject
    // 규칙이 없으면 Action 이 조용히 안 나온다 — deferred 에도 안 잡힌다.
    let yaml = BASE.to_string() + "remediate:\n  restore:\n    - av_exclusions\n";
    let e = errors(&yaml);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].contains("av_exclusion"), "{e:?}");
}

#[test]
fn a_restore_name_that_is_not_in_the_table_is_an_error() {
    // **한 걸음 앞의 같은 결함이다.** 위 시험은 "이름은 맞는데 증거가 없다"
    // 를 잡는다. 여기는 **이름 자체가 없는** 경우다.
    //
    // `restore_op` 이 `.unwrap_or(Op::RegistryRestoreDefault)` 로 받으므로
    // 모르는 이름은 오류가 아니라 **엉뚱한 Op** 이 된다. 2026-09-03 Linux
    // 하네스가 규칙 id 를 적어(`restore: [hostline]`) 이것을 밟았고, 린트는
    // 오류 0 · 경고 0 을 냈으며 hosts 줄은 영영 되돌아오지 않았다.
    let yaml = BASE.to_string() + "remediate:\n  restore:\n    - hostline\n";
    let e = errors(&yaml);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].contains("hostline"), "{e:?}");

    // **쓸 수 있는 이름 넷을 함께 보여야 작성자가 고칠 수 있다.** 표가 소스에만
    // 있으면 "틀렸다" 만 듣고 무엇이 맞는지는 모른다.
    let valid = lint(&parse(&yaml))
        .into_iter()
        .find(|i| i.at.starts_with("remediate.restore["))
        .and_then(|i| i.valid)
        .unwrap_or_default();
    for (name, _, _) in remedy_sdk::catalog::RESTORE_NAMED {
        assert!(valid.contains(name), "'{name}' 을 보이지 않았다: {valid}");
    }
}

#[test]
fn every_name_in_the_table_is_accepted() {
    // 표가 자라면 이 시험이 함께 자란다. 막지 말아야 할 것을 막으면
    // 작성자가 우회로를 만든다.
    for (name, subject, _) in remedy_sdk::catalog::RESTORE_NAMED {
        let yaml = BASE.to_string() + &format!("remediate:\n  restore:\n    - {name}\n");
        let e = errors(&yaml);
        assert!(
            !e.iter()
                .any(|x| x.contains("이름으로 지정할 수 있는 원복이 아니다")),
            "표에 있는 '{name}'({}) 를 모르는 이름이라 했다: {e:?}",
            subject.id()
        );
    }
}

#[test]
fn a_named_restore_with_its_subject_rule_passes() {
    let yaml = BASE.to_string()
        + r"  - id: excl
    subject: av_exclusion
    where:
      - { field: value, op: contains, value: '\remedy-lab\fixtures\' }
" + "remediate:\n  restore:\n    - av_exclusions\n";
    // BASE 의 detect 목록 뒤에 규칙을 잇기 위해 subjects 도 넓힌다.
    let yaml = yaml.replace(
        "subjects: [persistence, file]",
        "subjects: [persistence, file, av_exclusion]",
    );
    let yaml = yaml.replace("verdict: { require: 'task and payload' }\n", "");
    let yaml = yaml + "verdict: { require: 'task and payload' }\n";
    assert!(errors(&yaml).is_empty(), "{:?}", errors(&yaml));
}

// ─────────────────────── from 은 path 필드가 있어야 통한다

#[test]
fn from_on_a_subject_without_a_path_field_is_an_error() {
    // from 은 레코드의 path 를 읽는다. autorun 에는 path 가 없어서 모든
    // 레코드가 걸러지고 그 규칙은 영영 매치되지 않는다.
    let yaml = BASE.to_string()
        + r"  - id: run
    subject: autorun
    from: '${task.payload_dir}'
    where:
      - { field: command, op: contains, value: 'x' }
";
    let yaml = yaml.replace(
        "subjects: [persistence, file]",
        "subjects: [persistence, file, autorun]",
    );
    let yaml = yaml.replace("verdict: { require: 'task and payload' }\n", "");
    let yaml = yaml + "verdict: { require: 'task and payload' }\n";
    let e = errors(&yaml);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].contains("path"), "{e:?}");
}

#[test]
fn from_on_file_passes() {
    // BASE 의 payload 규칙이 file 에 from 을 건다. 이 검사가 거기까지 번지면
    // 안 된다.
    assert!(errors(BASE).is_empty(), "{:?}", errors(BASE));
}

// ──────────────────────────────────────────── subject × 플랫폼 (설계-09 P12)

/// Linux 전용 최소 매니페스트. `subjects` 만 비튼다.
const LINUX_BASE: &str = r#"
schema_version: 1
id: lint-linux
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
name: { ko: '시험', en: 'lint linux' }
scan_roots: ['%HOME%/.config']
subjects: [text_config]
detect:
  - id: hook
    subject: text_config
    where:
      all:
        - { field: key, op: equals, value: 'loader' }
verdict: { require: 'hook' }
"#;

// ───────────────────────── 확장자 밖의 설정 디렉터리 (C-5 · 2026-10-27)

#[test]
fn a_declared_dropin_directory_inside_the_ceiling_is_clean() {
    // **이것이 먼저다.** 여기서 경고가 나오면 이 기능을 쓸 수 없다.
    let y = LINUX_BASE.replace(
        "subjects: [text_config]",
        "subjects: [text_config]\ntext_config_dirs: ['%HOME%/.config/pam.d']",
    );
    assert_ne!(y, LINUX_BASE, "치환이 걸리지 않았다");
    let issues = lint(&parse(&y));
    assert!(issues.is_empty(), "{issues:#?}");
}

#[test]
fn a_dropin_directory_outside_scan_roots_is_an_error() {
    // 이 선언은 **같은 상한 안에서** 확장자 밖의 파일까지 읽는 것이다. 밖을
    // 적을 수 있으면 읽기 권한의 상한이 두 곳이 되고, 서명 검토자가
    // `scan_roots` 만 읽으면 실제로 무엇을 읽는지 모른다.
    let y = LINUX_BASE.replace(
        "subjects: [text_config]",
        "subjects: [text_config]\ntext_config_dirs: ['/etc/pam.d']",
    );
    let e = errors(&y);
    assert!(
        e.iter()
            .any(|x| x.contains("/etc/pam.d") && x.contains("`scan_roots` 밖")),
        "{e:#?}"
    );
}

#[test]
fn a_dropin_directory_without_the_subject_is_an_error() {
    // 그 subject 를 모으지 않으면 아무도 읽지 않는다 — 조용한 0건이다.
    let y = LINUX_BASE
        .replace(
            "subjects: [text_config]",
            "subjects: [file]\ntext_config_dirs: ['%HOME%/.config/pam.d']",
        )
        .replace("subject: text_config", "subject: file")
        .replace(
            "{ field: key, op: equals, value: 'loader' }",
            "{ field: path, op: contains, value: 'x' }",
        );
    let e = errors(&y);
    assert!(
        e.iter()
            .any(|x| x.contains("text_config") && x.contains("`subjects`")),
        "{e:#?}"
    );
}

#[test]
fn declaring_the_ceiling_itself_as_a_dropin_dir_is_warned() {
    // `/etc` 를 적으면 그 아래 직접 자식 **전부**가 줄 단위로 들어온다 —
    // `passwd` · `shadow` · `group` 이 거기 있다. 막지는 않는다(서명된
    // 선언이다). 드롭인 디렉터리를 겨누라고 말한다.
    let y = LINUX_BASE.replace(
        "subjects: [text_config]",
        "subjects: [text_config]\ntext_config_dirs: ['%HOME%/.config']",
    );
    let w = warnings(&y);
    assert!(
        w.iter()
            .any(|x| x.contains("`scan_roots` 자체") && x.contains("자격증명")),
        "{w:#?}"
    );
    assert!(errors(&y).is_empty(), "{:#?}", errors(&y));
}

#[test]
fn an_existing_manifest_without_the_field_is_untouched() {
    // **멈출 조건 4.** 새 문법이 기존 매니페스트의 뜻을 바꾸면 출하된 룰이
    // 조용히 달라진다. 적지 않은 매니페스트는 검사 자체를 지나지 않는다.
    assert!(parse(LINUX_BASE).text_config_dirs.is_empty());
    assert!(lint(&parse(LINUX_BASE)).is_empty());
    assert!(errors(BASE).is_empty(), "{:#?}", errors(BASE));
}

#[test]
fn a_linux_plugin_that_only_uses_collectable_subjects_is_clean() {
    // **이것이 먼저다.** ex03 이 실제로 이 모양이고, 여기서 경고가 나오면
    // Linux 플러그인을 쓸 수 없다.
    let issues = lint(&parse(LINUX_BASE));
    assert!(issues.is_empty(), "{issues:#?}");
}

#[test]
fn a_linux_only_plugin_declaring_a_windows_only_subject_is_an_error() {
    // 실측으로 드러난 구멍이다. `platforms: [linux]` 에 `subjects: [firewall_rule]`
    // 를 적은 매니페스트가 **오류 0 · 경고 0** 으로 통과했다. 그 플러그인은 Linux
    // 에서 수집이 통째로 죽거나 0건을 조용히 보고한다.
    let y = LINUX_BASE.replace(
        "subjects: [text_config]",
        "subjects: [text_config, firewall_rule]",
    );
    let e = errors(&y);
    assert!(
        e.iter().any(|s| s.starts_with("subjects.firewall_rule")),
        "{e:?}"
    );
}

#[test]
fn the_message_separates_a_missing_concept_from_a_missing_collector() {
    // 작성자가 할 일이 다르다. 개념이 없으면 룰을 다시 짜야 하고, 수집기가
    // 없으면 요청하면 된다. 같은 문장을 주면 앞의 작성자가 기다린다.
    let no_concept = errors(&LINUX_BASE.replace(
        "subjects: [text_config]",
        "subjects: [text_config, registry_value]",
    ));
    let no_collector = errors(&LINUX_BASE.replace(
        "subjects: [text_config]",
        "subjects: [text_config, firewall_rule]",
    ));
    assert!(
        no_concept.iter().any(|s| s.contains("개념이 없다")),
        "{no_concept:?}"
    );
    assert!(
        no_collector
            .iter()
            .any(|s| s.contains("수집기가 Windows 전용")),
        "{no_collector:?}"
    );
}

#[test]
fn a_cross_platform_plugin_gets_a_warning_not_an_error() {
    // 오류로 막으면 `platforms` 에 linux 를 더하는 것만으로 멀쩡한 Windows 룰이
    // 거부된다. 그 플러그인은 Windows 에서 **실제로 동작한다.**
    let y = LINUX_BASE
        .replace("platforms: [linux]", "platforms: [windows, linux]")
        .replace(
            "subjects: [text_config]",
            "subjects: [text_config, firewall_rule]",
        );
    assert!(errors(&y).is_empty(), "{:?}", errors(&y));
    assert!(
        warnings(&y)
            .iter()
            .any(|s| s.starts_with("subjects.firewall_rule")),
        "{:?}",
        warnings(&y)
    );
}

#[test]
fn a_windows_only_plugin_is_never_asked_about_linux() {
    // BASE 는 `persistence` 와 `file` 뿐이라 이 검사에 걸릴 것이 없지만,
    // 레지스트리 subject 를 더해도 조용해야 한다 — platforms 에 linux 가 없다.
    //
    // **레지스트리 루트를 함께 준다.** 주지 않으면 도달 가능성 검사가 먼저
    // 걸려(`registry_value` 는 그 종류의 루트가 있어야 모인다) 이 시험이
    // 재려던 것과 다른 이유로 빨개진다.
    let y = BASE
        .replace(
            r"scan_roots: ['C:\remedy-lab\fixtures', '%SystemRoot%\System32\Tasks']",
            r"scan_roots: ['C:\remedy-lab\fixtures', 'HKLM\SOFTWARE\Acme\Thing']",
        )
        .replace(
            "subjects: [persistence, file]",
            "subjects: [persistence, file, registry_value, firewall_rule]",
        );
    let issues = lint(&parse(&y));
    assert!(
        !issues.iter().any(|i| i.at.starts_with("subjects.")),
        "{issues:#?}"
    );
}

// ──────────────────────────────────────────── edit × 플랫폼 (설계-09 P12)

/// LINUX_BASE 에 자동 실행 규칙 하나를 더하고 그것을 `edit` 로 가리킨다.
fn linux_with_edit(platforms: &str) -> String {
    LINUX_BASE
        .replace("platforms: [linux]", &format!("platforms: {platforms}"))
        .replace(
            "subjects: [text_config]",
            "subjects: [text_config, autorun]",
        )
        .replace(
            "verdict: { require: 'hook' }",
            "  - id: target\n    subject: autorun\n    where:\n      \
             - { field: command, op: contains, value: '/tmp/' }\n    \
             capture: { tail: 'command' }\n\
             verdict: { require: 'hook' }\n\
             remediate:\n  edit:\n    - { ref: target, op: strip, value: '${target.tail}' }",
        )
}

#[test]
fn a_linux_only_plugin_with_edit_is_an_error() {
    // **부분 편집 Op 은 Linux 칸이 비어 있다**(`registry.strip_value` ·
    // `env.strip_path`). 계획기는 그 edit 를 보류로 빼고, 사유는 *"이 Op 은 지금
    // 수행할 수 없다"* 뿐이다 (2026-09-28 npm-r1 사전 기준의 변형). Linux 전용이면
    // 그 edit 는 어디서도 돌지 않는다.
    let e = errors(&linux_with_edit("[linux]"));
    assert!(
        e.iter()
            .any(|s| s.starts_with("remediate.edit[0]") && s.contains("Linux")),
        "{e:?}"
    );
}

#[test]
fn a_cross_platform_plugin_with_edit_gets_a_warning_not_an_error() {
    // Windows 에서는 **실제로 동작한다** — 오류로 막으면 platforms 에 linux 를
    // 더하는 것만으로 멀쩡한 Windows 룰이 거부된다(subject × 플랫폼과 같은 판단).
    let y = linux_with_edit("[windows, linux]");
    assert!(
        !errors(&y).iter().any(|s| s.starts_with("remediate.edit")),
        "{:?}",
        errors(&y)
    );
    assert!(
        warnings(&y)
            .iter()
            .any(|s| s.starts_with("remediate.edit[0]") && s.contains("Linux")),
        "{:?}",
        warnings(&y)
    );
}

#[test]
fn a_windows_only_plugin_with_edit_is_never_asked_about_linux() {
    // 위 두 시험이 "edit 면 언제나 Linux 를 묻는다" 로 통과하면 안 된다.
    let y = with_edit(
        "autorun",
        "  - id: target\n    subject: autorun\n    where:\n      \
         - { field: name, op: equals, value: 'Userinit' }\n    \
         capture: { tail: 'command' }\n",
    );
    let issues = lint(&parse(&y));
    assert!(
        !issues
            .iter()
            .any(|i| i.at.starts_with("remediate.edit") && i.message.contains("Linux")),
        "{issues:#?}"
    );
}

// ─────────────────────────────────────────── kind: check (B-1 · 2026-10-26)

/// `BASE` 에 `remediate` 를 붙인 판. 모순을 만들려면 치료가 있어야 한다.
fn with_remediate(extra_head: &str) -> String {
    format!(
        "{extra_head}{}\nremediate:\n  remove:\n    - {{ ref: payload }}\n",
        BASE.trim_start_matches('\n')
    )
}

#[test]
fn declaring_check_while_remediating_is_an_error() {
    // **이 검사는 자동으로 재지 않으면 지워도 아무도 모른다.** 게이트 아홉과
    // 워크스페이스 시험이 전부 초록인 채로 사라질 수 있었다(적대 검증 2026-10-26).
    let e = errors(&with_remediate("kind: check\n"));
    assert_eq!(e.len(), 1, "모순 하나만 나와야 한다: {e:#?}");
    assert!(
        e[0].starts_with("remediate :: kind: check"),
        "자리와 사유가 remediate 를 가리켜야 한다: {}",
        e[0]
    );

    // **음성 대조 둘.** 늘 거부하는 검사는 늘 통과하는 검사만큼 쓸모없다.
    assert_eq!(
        errors(&with_remediate("")).len(),
        0,
        "kind 가 없으면 치료는 정상이다"
    );
    assert_eq!(
        errors(&format!("kind: check\n{}", BASE.trim_start_matches('\n'))).len(),
        0,
        "kind: check 이고 remediate 가 없으면 정상이다"
    );
}

#[test]
fn an_empty_kind_value_is_refused_not_silently_dropped() {
    // `kind:` · `kind: null` · `kind: ~` 가 **키를 지운 것과 같아지면** 플러그인이
    // 조용히 치료로 돌아간다 — 종료 0 이 6 이 되고 *취약* 이 *위협* 이 된다.
    // 값 오타(`chekc`)는 거부되는데 "값을 비웠다" 만 통과했다(실측 2026-10-26).
    for empty in ["kind:\n", "kind: null\n", "kind: ~\n"] {
        let y = format!("{empty}{}", BASE.trim_start_matches('\n'));
        let r = serde_yaml_ng::from_str::<PluginManifest>(&y);
        assert!(r.is_err(), "{empty:?} 가 통과했다 — 선언이 조용히 사라진다");
    }
    // 키가 아예 없는 것은 정상이다 — 그것이 치료 플러그인이다.
    assert!(serde_yaml_ng::from_str::<PluginManifest>(BASE)
        .expect("kind 없는 매니페스트는 통과한다")
        .kind
        .is_none());
    // 값 오타는 여전히 거부된다.
    assert!(serde_yaml_ng::from_str::<PluginManifest>(&format!(
        "kind: chekc\n{}",
        BASE.trim_start_matches('\n')
    ))
    .is_err());
}
