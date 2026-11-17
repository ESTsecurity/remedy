//! lint 의 시험 — 2026-11-17 에 그 파일에서 떼어 냈다. 내용은 그대로이고, 안에 든 모듈의 `super::` 만
//! `super::super::`(= 그 모듈)로 바꿨다.

mod schema_hint_tests {
    use super::super::schema_hints;

    fn manifest(where_: &str, exclude: &str) -> String {
        format!(
            r#"
schema_version: 1
id: t
version: 1.0.0
min_core: "1.0.0"
platforms: [linux]
kind: check
name: {{ ko: "t", en: "t" }}
scan_roots: ["/opt"]
subjects: [file]
detect:
  - id: r
    subject: file
    where:
{where_}
{exclude}
verdict: {{ require: "r" }}
"#
        )
    }

    #[test]
    fn an_unknown_operator_is_named_with_its_place_and_the_valid_ones() {
        // 1.10.0 에서 이 룰은 `untagged enum Condition at line 11 column 5` 로만 나왔다.
        let y = manifest(
            "      - { field: path, op: ends_with, value: '.jar' }\n      - { field: path, op: zip_contains, value: 'x' }",
            "",
        );
        assert!(serde_yaml_ng::from_str::<crate::manifest::PluginManifest>(&y).is_err());
        let h = schema_hints(&y);
        assert_eq!(h.len(), 1, "{h:?}");
        assert!(h[0].contains("detect[0] ('r').where[1]"), "{h:?}");
        assert!(h[0].contains("모르는 연산자 'zip_contains'"), "{h:?}");
        assert!(
            h[0].contains("ends_with"),
            "쓸 수 있는 것을 말하지 않았다: {h:?}"
        );
    }

    #[test]
    fn nested_groups_exclude_and_unknown_keys_are_reached() {
        let y = manifest(
            "      - any:\n          - { field: path, op: ends_with, valu: '.jar' }\n          - { yara: 'rules/a.yar:x', op: equals }",
            "    exclude:\n      - { field: path, op: inside }",
        );
        let h = schema_hints(&y).join("\n");
        assert!(h.contains("where[0].any[0]: 모르는 칸 'valu'"), "{h}");
        assert!(
            h.contains("where[0].any[1]: yara 술어에 모르는 칸 'op'"),
            "{h}"
        );
        assert!(h.contains("exclude[0]: 모르는 연산자 'inside'"), "{h}");
    }

    #[test]
    fn a_manifest_that_parses_has_no_hints() {
        let y = manifest("      - { field: path, op: ends_with, value: '.jar' }", "");
        assert!(serde_yaml_ng::from_str::<crate::manifest::PluginManifest>(&y).is_ok());
        assert!(schema_hints(&y).is_empty());
    }
}

mod archive_field_tests {
    use super::super::{lint, Severity};
    use crate::manifest::PluginManifest;

    fn m(head: &str, subjects: &str, rule_subject: &str) -> PluginManifest {
        let y = format!(
            r#"
schema_version: 1
id: t
version: 1.0.0
min_core: "1.0.0"
platforms: [linux]
kind: check
name: {{ ko: "t", en: "t" }}
scan_roots: ["%FIXED_DISKS%"]
subjects: [{subjects}]
{head}
detect:
  - id: r
    subject: {rule_subject}
    where:
      - {{ field: path, op: ends_with, value: "pom.properties" }}
verdict: {{ require: "r" }}
"#
        );
        serde_yaml_ng::from_str(&y).unwrap_or_else(|e| panic!("{e}\n{y}"))
    }

    fn found(m: &PluginManifest) -> Vec<(Severity, String, String)> {
        lint(m)
            .into_iter()
            .map(|i| (i.severity, i.at, i.message))
            .collect()
    }

    #[test]
    fn a_complete_archive_rule_has_no_archive_or_disk_issue() {
        let mm = m(
            "file_names: [\"*.jar\", \"*.war\"]\narchive_members: [\"pom.properties\", \"*.jar\"]",
            "file, archive_entry",
            "archive_entry",
        );
        let got = found(&mm);
        assert!(
            got.iter()
                .all(|(_, at, msg)| !at.starts_with("archive_members")
                    && !at.starts_with("file_names")
                    && at != "scan_roots[0]"
                    && !msg.contains("archive_entry")),
            "{got:#?}"
        );
    }

    #[test]
    fn archive_entry_without_file_or_members_is_an_error() {
        let no_file = m(
            "archive_members: [\"pom.properties\"]",
            "archive_entry",
            "archive_entry",
        );
        assert!(
            found(&no_file)
                .iter()
                .any(|(s, at, msg)| *s == Severity::Error
                    && at == "subjects"
                    && msg.contains("`file`")),
            "{:#?}",
            found(&no_file)
        );
        let no_members = m(
            "file_names: [\"*.jar\"]",
            "file, archive_entry",
            "archive_entry",
        );
        assert!(found(&no_members)
            .iter()
            .any(|(s, at, _)| *s == Severity::Error && at == "archive_members"));
        // 반대 방향은 경고다 — 칸이 아무 일도 하지 않을 뿐 수집이 틀리지는 않는다.
        let unused = m("archive_members: [\"pom.properties\"]", "file", "file");
        assert!(found(&unused)
            .iter()
            .any(|(s, at, _)| *s == Severity::Warning && at == "archive_members"));
    }

    #[test]
    fn a_path_in_a_name_pattern_is_an_error() {
        let mm = m(
            "file_names: [\"lib/*.jar\"]\narchive_members: ['META-INF\\MANIFEST.MF']",
            "file, archive_entry",
            "archive_entry",
        );
        let errs: Vec<String> = found(&mm)
            .into_iter()
            .filter(|(s, _, _)| *s == Severity::Error)
            .map(|(_, at, _)| at)
            .collect();
        assert!(
            errs.contains(&"file_names[0]".to_string())
                && errs.contains(&"archive_members[0]".to_string()),
            "{errs:?}"
        );
    }

    #[test]
    fn the_disk_token_warns_only_when_names_do_not_narrow_it() {
        // 디스크 토큰은 넓은 것이 뜻이라 깊이 경고를 내지 않는다 — 이름으로 좁히지 않았을 때만 말한다.
        let wide = m("", "file", "file");
        let w = found(&wide);
        assert!(
            w.iter().any(|(s, at, msg)| *s == Severity::Warning
                && at == "scan_roots[0]"
                && msg.contains("file_names")),
            "{w:#?}"
        );
        let narrow = m("file_names: [\"*.jar\"]", "file", "file");
        let n = found(&narrow);
        assert!(!n.iter().any(|(_, at, _)| at == "scan_roots[0]"), "{n:#?}");
    }
}

mod depth_tests {
    use super::super::root_depth;

    /// **구조가 같은 자리는 두 플랫폼에서 같은 깊이여야 한다.**
    ///
    /// 이것이 어긋나 있어서 파일 넷짜리 `/etc/ld.so.conf.d` 가 `C:\\Windows` 와
    /// 같은 깊이로 계산됐고, 리눅스 플러그인이 근거 없는 폭 경고를 안고
    /// 다녔다 (2026-09-01 AI 시험 ldso-r1).
    #[test]
    fn the_same_place_has_the_same_depth_on_both_platforms() {
        let pairs = [
            ("C:\\", "/"),               // 루트
            ("C:\\Users", "/home"),      // 루트 바로 아래
            ("C:\\Users\\u", "/home/u"), // 그 아래
            // 루트에서 두 칸 아래끼리. `/usr/local/lib` 은 세 칸이라 짝이 아니다.
            ("C:\\Windows\\System32", "/usr/lib"),
        ];
        for (win, posix) in pairs {
            assert_eq!(
                root_depth(win),
                root_depth(posix),
                "{win} 과 {posix} 는 같은 자리인데 깊이가 다르다"
            );
        }
    }

    /// 토큰과 리터럴이 같은 자리를 가리키면 값도 같아야 한다.
    ///
    /// `%HOME%` 은 표에 3으로 못 박혀 있다. 리터럴 `/home/u` 도 3이어야
    /// 같은 자리를 어떻게 적었는지에 따라 경고가 갈리지 않는다.
    #[test]
    fn a_token_and_the_literal_it_stands_for_agree() {
        assert_eq!(root_depth("%HOME%"), Some(3));
        assert_eq!(root_depth("/home/u"), Some(3));
        assert_eq!(root_depth("%USERPROFILE%"), root_depth("C:\\Users\\u"));
    }

    /// 경고 문턱(깊이 2 이하)의 양쪽.
    #[test]
    fn the_warning_threshold_falls_where_it_should() {
        // 넓다 — 경고를 맞아야 한다.
        for wide in ["/", "/etc", "/home", "C:\\", "C:\\Users"] {
            assert!(
                root_depth(wide).is_some_and(|d| d <= 2),
                "{wide} 이 넓은 것으로 잡히지 않는다"
            );
        }
        // 좁다 — 맞으면 안 된다. 첫 줄이 이 회차가 드러낸 자리다.
        for narrow in [
            "/etc/ld.so.conf.d",
            "/usr/local/lib",
            "/usr/share/applications",
            "C:\\Windows\\System32",
        ] {
            assert!(
                root_depth(narrow).is_some_and(|d| d > 2),
                "{narrow} 이 넓은 것으로 잡힌다"
            );
        }
    }
}

mod enumerated_tests {
    use super::super::{check_sha256_literals, lint, Severity};
    use crate::catalog::{EnumeratedField, Subject};
    use crate::manifest::PluginManifest;

    /// 매니페스트 하나. `<PRED>` 자리에 술어를 끼운다.
    fn with(subject: &str, pred: &str) -> PluginManifest {
        let y = format!(
            "schema_version: 1\n\
             id: enum-probe\n\
             version: 1.0.0\n\
             min_core: '1.0.0'\n\
             platforms: [windows]\n\
             name: {{ en: 'enum probe' }}\n\
             scan_roots: ['%LOCALAPPDATA%\\Programs']\n\
             subjects: [{subject}]\n\
             detect:\n\
             \x20 - id: r\n\
             \x20   subject: {subject}\n\
             \x20   where:\n\
             \x20     - {pred}\n\
             verdict: {{ require: 'r' }}\n"
        );
        serde_yaml_ng::from_str(&y).unwrap_or_else(|e| panic!("{e}\n{y}"))
    }

    fn issues(subject: &str, pred: &str) -> Vec<(Severity, String)> {
        lint(&with(subject, pred))
            .into_iter()
            .filter(|i| i.at.ends_with(".value"))
            .map(|i| (i.severity, i.message))
            .collect()
    }

    /// **우리가 만드는 전수**를 벗어나면 오류다. 다른 값이 나올 수 없으므로
    /// 그 술어는 어느 기계에서도 참이 되지 않는다.
    #[test]
    fn a_value_our_collector_never_writes_is_an_error() {
        let got = issues("service", "{ field: state, op: equals, value: 'running' }");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Error);
        assert!(got[0].1.contains("running"), "{}", got[0].1);
    }

    /// **OS 표기를 그대로 통과시키는 자리**는 경고에 그친다. 전수의 주인이
    /// 우리가 아니라서, 새 값이 나타났을 때 맞는 룰을 막으면 안 된다.
    #[test]
    fn a_value_the_os_owns_is_only_a_warning() {
        let got = issues(
            "firewall_rule",
            "{ field: direction, op: equals, value: 'inbound' }",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Warning);
    }

    /// `package.manager` 는 셋이다 — 코어 1.3.0 에서 `rpm` 이 들어왔다. 수집이 적는 값을 전수가
    /// 모르면 **RPM 줄이 전부 린트 오류**가 된다(2026-11-09 · 룰을 쓰다 드러났다).
    #[test]
    fn every_package_manager_the_collector_writes_is_known() {
        for m in ["dpkg", "apk", "rpm"] {
            let got = issues(
                "package",
                &format!("{{ field: manager, op: equals, value: '{m}' }}"),
            );
            assert!(got.is_empty(), "{m}: {got:?}");
        }
        let got = issues("package", "{ field: manager, op: equals, value: 'yum' }");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Error);
    }

    /// `sha256` 리터럴 — 자리 표시·대문자는 오류, 한 글자의 반복은 경고, 실제
    /// 지문과 `${…}` 는 조용하다 (`check_sha256_literals`, 2026-10-02).
    #[test]
    fn a_sha256_placeholder_is_an_error_and_a_repeated_digit_is_a_warning() {
        let got = issues(
            "file",
            "{ field: sha256, op: equals, value: 'FILL_IN_sha256_of_the_sample' }",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Error);
        assert!(got[0].1.contains("64자"), "{}", got[0].1);

        let upper = "A".repeat(64);
        let got = issues(
            "file",
            &format!("{{ field: sha256, op: equals, value: '{upper}' }}"),
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(
            got[0].0,
            Severity::Error,
            "대문자는 수집이 적는 모양이 아니다"
        );

        let zeros = "0".repeat(64);
        let got = issues(
            "file",
            &format!("{{ field: sha256, op: equals, value: '{zeros}' }}"),
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(
            got[0].0,
            Severity::Warning,
            "모양은 맞되 자리 표시로 보인다"
        );

        let real = "311778aeaef745dbff90e62bc6b368eb209f87e83132328e54ad565dc2ff9411";
        assert!(issues(
            "file",
            &format!("{{ field: sha256, op: equals, value: '{real}' }}")
        )
        .is_empty());
        // `${…}` 는 리터럴이 아니다 — 참조 검사는 따로 울리므로 이 검사만 부른다.
        let mut out = Vec::new();
        check_sha256_literals(
            &with(
                "file",
                "{ field: sha256, op: equals, value: '${seed.digest}' }",
            ),
            &mut out,
        );
        assert!(out.is_empty(), "{out:?}");
    }

    /// `in` 목록은 항목마다 본다 — 자리를 `value[k]` 로 짚는다.
    #[test]
    fn each_sha256_list_entry_is_checked_on_its_own() {
        let real = "311778aeaef745dbff90e62bc6b368eb209f87e83132328e54ad565dc2ff9411";
        let m = with(
            "file",
            &format!("{{ field: sha256, op: in, value: ['{real}', 'FILL_IN'] }}"),
        );
        let got: Vec<_> = lint(&m)
            .into_iter()
            .filter(|i| i.at.contains(".value["))
            .collect();
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].at.ends_with(".value[1]"), "{}", got[0].at);
        assert_eq!(got[0].severity, Severity::Error);
    }

    /// 대소문자는 접는다. Windows 평가가 접으므로 표기 차이로 막으면
    /// **맞는 룰이 막힌다** — 시험 회차 하나가 `allow` 로 정확히 맞혔다.
    #[test]
    fn case_alone_is_not_a_complaint() {
        assert!(issues(
            "firewall_rule",
            "{ field: action, op: equals, value: 'allow' }"
        )
        .is_empty());
    }

    /// 값이 실행 시점에 정해지는 자리와 부분 일치는 재지 않는다.
    #[test]
    fn interpolation_and_partial_matches_are_left_alone() {
        assert!(issues(
            "firewall_rule",
            "{ field: direction, op: equals, value: '${r.x}' }"
        )
        .is_empty());
        assert!(issues(
            "firewall_rule",
            "{ field: direction, op: contains, value: 'bound' }"
        )
        .is_empty());
    }

    /// **전수가 실재하는 필드에 붙어 있는가.** `fields()` 에서 이름이 사라지면
    /// 이 표는 아무것도 막지 않으면서 남는다.
    #[test]
    fn every_enumerated_field_is_a_field_of_that_subject() {
        for e in Subject::ENUMERATED_FIELDS {
            assert!(
                e.subject.fields().contains(&e.field),
                "{}.{} 는 그 subject 의 필드가 아니다",
                e.subject.id(),
                e.field
            );
            assert!(
                !e.values.is_empty(),
                "{}.{} 의 전수가 비었다",
                e.subject.id(),
                e.field
            );
            assert!(
                EnumeratedField::lookup(e.subject, e.field).is_some(),
                "{}.{} 를 lookup 이 못 찾는다",
                e.subject.id(),
                e.field
            );
        }
    }
}

mod wildcard_tests {
    use super::super::{lint, Severity};
    use crate::manifest::PluginManifest;

    const IFEO: &str =
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

    fn roots(rs: &[&str]) -> PluginManifest {
        let list = rs
            .iter()
            .map(|r| format!("  - '{r}'"))
            .collect::<Vec<_>>()
            .join("\n");
        let y = format!(
            r#"schema_version: 1
id: star-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: {{ en: 'star probe' }}
scan_roots:
{list}
subjects: [registry_value]
detect:
  - id: r
    subject: registry_value
    where:
      - {{ field: name, op: equals, value: 'Debugger' }}
verdict: {{ require: 'r' }}
"#
        );
        serde_yaml_ng::from_str(&y).unwrap_or_else(|e| panic!("{e}\n{y}"))
    }

    /// `scan_roots[..]` 자리의 진단만.
    fn at_roots(rs: &[&str]) -> Vec<(Severity, String)> {
        lint(&roots(rs))
            .into_iter()
            .filter(|i| i.at.starts_with("scan_roots["))
            .map(|i| (i.severity, i.message))
            .collect()
    }

    /// **값 수집은 재귀하지 않는다.** 하위 키 이름이 미리 정해지지 않는 자리는
    /// 끝의 별표 없이는 도달할 수 없다 — IFEO 가 그렇다.
    #[test]
    fn a_registry_root_may_end_in_a_star() {
        let got = at_roots(&[&format!("{IFEO}\\*")]);
        assert!(got.is_empty(), "{got:?}");
    }

    /// 파일 경로는 그대로 막는다. 전개되지 않아 없는 디렉터리가 되고 0건이 된다.
    #[test]
    fn a_file_root_may_not() {
        let got = at_roots(&["%LOCALAPPDATA%\\*"]);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Error);
    }

    /// 마지막 칸의 이름 꼴은 받는다 — 그 폴더 바로 아래의 맞는 파일만 고른다(코어 1.2.0).
    /// 얕은 목록이라 깊이 경고도 없다.
    #[test]
    fn a_file_root_may_end_in_a_name_pattern() {
        for r in [
            "%ALLUSERPROFILES%\\AppData\\Local\\Temp\\*.js",
            "C:\\x\\a?.js",
            "C:\\*.lnk",
        ] {
            let got = at_roots(&[r]);
            assert!(got.is_empty(), "{r}: {got:?}");
        }
    }

    /// 이름 칸이 와일드카드뿐이면 '재귀로 다 본다' 로 읽힌다 — 받지 않는다. 폴더 칸의
    /// 와일드카드는 지정 토큰이 함께 있어도 받지 않는다(전에는 토큰이 검사를 건너뛰게 했다).
    #[test]
    fn a_bare_star_or_a_folder_wildcard_is_still_an_error() {
        for r in [
            "C:\\x\\*",
            "C:\\x\\??",
            "C:\\x\\*\\a.js",
            "%ALLUSERPROFILES%\\AppData\\*\\Temp",
        ] {
            let got = at_roots(&[r]);
            assert_eq!(got.len(), 1, "{r}: {got:?}");
            assert_eq!(got[0].0, Severity::Error, "{r}");
        }
    }

    /// 전개기가 **첫 번째** 별표만 펼친다. 둘 이상 쓰면 나머지가 리터럴로 남아 조용히
    /// 0건이 되고, 이름에 섞인 별표(`Run*`)는 펼치지 않는다.
    #[test]
    fn a_second_star_or_a_star_inside_a_name_is_an_error() {
        for r in [
            format!("{IFEO}\\*\\*"),
            "HKLM\\SOFTWARE\\*\\*\\Windows".to_string(),
            "HKLM\\SOFTWARE\\Microsoft\\Run*".to_string(),
            "HKLM\\SOFTWARE\\*x\\Windows".to_string(),
        ] {
            let got = at_roots(&[&r]);
            assert_eq!(got.len(), 1, "{r}: {got:?}");
            assert_eq!(got[0].0, Severity::Error, "{r}");
        }
    }

    /// **가운데의 한 칸 별표는 받는다** (2026-11-12). 전개기가 꼬리를 하위 키마다 붙이므로
    /// 리터럴이 남지 않는다 — NSSM 이 감싸 띄우는 프로그램이 `Services\*\Parameters` 에 있다.
    #[test]
    fn a_registry_root_may_hold_one_star_in_the_middle() {
        for r in [
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*\\Parameters",
            "HKLM\\SOFTWARE\\*\\Windows",
        ] {
            let got = at_roots(&[r]);
            assert!(got.is_empty(), "{r}: {got:?}");
        }
    }

    /// 가운데 별표도 깊이를 사지 않는다 — `HKLM\*\X` 는 `HKLM\*` 만큼의 키를 읽는다.
    #[test]
    fn a_middle_star_does_not_buy_a_depth_level() {
        let got = at_roots(&["HKLM\\*\\Parameters"]);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, Severity::Warning);
    }

    /// 지정 토큰은 그대로 통한다. 이쪽은 별표가 중간에 온다.
    #[test]
    fn the_designated_user_hive_token_still_passes() {
        let got = at_roots(&["HKU\\*\\Software\\Acme\\Thing"]);
        assert!(got.is_empty(), "{got:?}");
    }

    /// **별표는 좁히는 것이 아니라 넓히는 것이다.** 세그먼트가 하나 늘었다고
    /// 깊이를 더 세면 더 넓은 쪽이 조용히 폭 경고를 피한다.
    #[test]
    fn a_trailing_star_does_not_buy_a_depth_level() {
        let bare = at_roots(&["HKLM\\SOFTWARE"]);
        let starred = at_roots(&["HKLM\\SOFTWARE\\*"]);
        assert_eq!(bare.len(), 1, "{bare:?}");
        assert_eq!(bare[0].0, Severity::Warning);
        assert_eq!(
            starred.len(),
            1,
            "별표를 붙였다고 폭 경고가 사라지면 안 된다: {starred:?}"
        );
        assert_eq!(starred[0].0, Severity::Warning);
    }
}

mod reachability_tests {
    use super::super::{lint, Severity};
    use crate::catalog::{Scoping, Subject};
    use crate::manifest::PluginManifest;

    fn probe(roots: &[&str], subjects: &str, subject: &str) -> PluginManifest {
        let list = roots
            .iter()
            .map(|r| format!("  - '{r}'"))
            .collect::<Vec<_>>()
            .join("\n");
        let y = format!(
            r#"schema_version: 1
id: reach-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: {{ en: 'reach probe' }}
scan_roots:
{list}
subjects: [{subjects}]
detect:
  - id: r
    subject: {subject}
    where:
      - {{ field: name, op: equals, value: 'x' }}
verdict: {{ require: 'r' }}
"#
        );
        serde_yaml_ng::from_str(&y).unwrap_or_else(|e| panic!("{e}\n{y}"))
    }

    fn subject_errors(roots: &[&str], subjects: &str, subject: &str) -> Vec<String> {
        lint(&probe(roots, subjects, subject))
            .into_iter()
            .filter(|i| i.severity == Severity::Error && i.at.starts_with("subjects."))
            .map(|i| i.at)
            .collect()
    }

    /// 선언만으로는 모이지 않는다. 레지스트리 루트가 없으면 **언제나 0건**이다.
    #[test]
    fn a_registry_subject_without_a_registry_root_is_an_error() {
        let got = subject_errors(
            &["%LOCALAPPDATA%\\Programs"],
            "registry_value",
            "registry_value",
        );
        assert_eq!(got, vec!["subjects.registry_value".to_string()], "{got:?}");
    }

    /// 반대쪽도 같다 — 레지스트리 루트만 있으면 파일 계열이 0건이다.
    #[test]
    fn a_path_subject_without_a_path_root_is_an_error() {
        let got = subject_errors(&["HKLM\\SOFTWARE\\Acme"], "file", "file");
        assert_eq!(got, vec!["subjects.file".to_string()], "{got:?}");
    }

    /// 둘 다 있으면 조용하다.
    #[test]
    fn both_kinds_present_is_clean() {
        let got = subject_errors(
            &["%LOCALAPPDATA%\\Programs", "HKLM\\SOFTWARE\\Acme"],
            "file, registry_value",
            "file",
        );
        assert!(got.is_empty(), "{got:?}");
    }

    /// **자리가 정해진 subject 는 묻지 않는다.** 물으면 방화벽 규칙 하나를
    /// 보려고 없는 파일 루트를 적게 만든다 — 상한이 넓어질 뿐이다.
    #[test]
    fn a_fixed_subject_is_never_asked_for_a_root() {
        let got = subject_errors(&["HKLM\\SOFTWARE\\Acme"], "firewall_rule", "firewall_rule");
        assert!(got.is_empty(), "{got:?}");
    }

    /// 열아홉이 전부 갈려 있는가. 새 subject 가 기본값으로 조용히 `Fixed` 가
    /// 되면 이 검사가 그 자리를 영영 보지 않는다.
    ///
    /// **못박은 수가 사람을 멈추게 하는 자리다.** 2026-10-27 에 `package` 를
    /// 더하며 여기서 멈췄고, 멈춰서 보고 `Fixed` 를 골랐다 — 패키지 DB 는
    /// `/var/lib/dpkg/status` · `/lib/apk/db/installed` 로 **자리가 정해져
    /// 있어** `scan_roots` 를 보지 않는다.
    ///
    /// 2026-11-12 에 `archive_entry` 를 더하며 다시 멈췄고 `Path` 를 골랐다 — 여는 아카이브는 `file` 이
    /// `scan_roots` 안에서 기록한 파일이라, 경로 루트가 없으면 그 subject 는 아무것도 열지 못한다.
    #[test]
    fn every_subject_declares_how_it_is_scoped() {
        let n = Subject::ALL.len();
        let fixed = Subject::ALL
            .into_iter()
            .filter(|s| matches!(s.info().scoping, Scoping::Fixed))
            .count();
        assert_eq!(n, 21);
        assert_eq!(Subject::ArchiveEntry.info().scoping, Scoping::Path);
        // 전부 Fixed 면 이 검사는 아무것도 막지 못한다.
        assert!(fixed < n, "scan_roots 를 받는 subject 가 하나도 없다");
    }
}

mod subject_roots_tests {
    use super::super::{lint, Severity};
    use crate::manifest::PluginManifest;

    /// `subject_roots` 를 붙인 탐침. `narrow` 는 YAML 조각이다.
    fn probe(narrow: &str) -> PluginManifest {
        let y = format!(
            r#"schema_version: 1
id: narrow-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: {{ en: 'narrow probe' }}
scan_roots:
  - 'C:\PROGRAMDATA'
subjects: [file, structured_config]
{narrow}
detect:
  - id: r
    subject: file
    where:
      - {{ field: path, op: exists }}
verdict: {{ require: r }}
"#
        );
        serde_yaml_ng::from_str(&y).expect("탐침 매니페스트")
    }

    fn errors(m: &PluginManifest) -> Vec<String> {
        lint(m)
            .into_iter()
            .filter(|i| i.severity == Severity::Error && i.at.starts_with("subject_roots"))
            .map(|i| format!("{}: {}", i.at, i.message))
            .collect()
    }

    #[test]
    fn a_narrowing_inside_the_ceiling_is_accepted() {
        let m = probe("subject_roots:\n  structured_config: ['C:\\PROGRAMDATA\\Acme']");
        assert!(errors(&m).is_empty(), "{:?}", errors(&m));
    }

    /// **넓히는 길이 없어야 한다.** 이것이 이 기능의 안전 성질 전부다 —
    /// 읽기 권한의 상한이 `scan_roots` 하나로 남는다.
    #[test]
    fn a_narrowing_outside_the_ceiling_is_an_error() {
        let m = probe("subject_roots:\n  structured_config: ['C:\\Windows\\System32']");
        let e = errors(&m);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("밖이다"), "{e:?}");
    }

    /// 접두가 같아도 **성분 경계**가 아니면 밖이다.
    /// `C:\\ProgramDataX` 는 `C:\\ProgramData` 안이 아니다.
    #[test]
    fn a_sibling_that_merely_shares_a_prefix_is_outside() {
        let m = probe("subject_roots:\n  structured_config: ['C:\\PROGRAMDATAX']");
        assert_eq!(errors(&m).len(), 1, "{:?}", errors(&m));
    }

    #[test]
    fn narrowing_a_subject_that_was_never_declared_is_an_error() {
        let m = probe("subject_roots:\n  text_config: ['C:\\PROGRAMDATA\\Acme']");
        let e = errors(&m);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("`subjects` 에 없다"), "{e:?}");
    }

    /// 빈 목록은 "아무 데도 보지 않는다" 이고 결과는 조용한 0건이다.
    #[test]
    fn an_empty_narrowing_is_an_error() {
        let m = probe("subject_roots:\n  structured_config: []");
        let e = errors(&m);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("빈 목록"), "{e:?}");
    }

    /// 자리가 정해진 subject 를 좁혀도 아무 일이 없다. 좁혔다고 믿게 두지 않는다.
    #[test]
    fn narrowing_a_fixed_place_subject_warns() {
        let y = "subject_roots:\n  persistence: ['C:\\PROGRAMDATA\\Acme']";
        let m: PluginManifest = serde_yaml_ng::from_str(&format!(
            r#"schema_version: 1
id: fixed-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: {{ en: 'fixed probe' }}
scan_roots:
  - 'C:\PROGRAMDATA'
subjects: [file, persistence]
{y}
detect:
  - id: r
    subject: file
    where:
      - {{ field: path, op: exists }}
verdict: {{ require: r }}
"#
        ))
        .expect("탐침");
        let w: Vec<String> = lint(&m)
            .into_iter()
            .filter(|i| i.severity == Severity::Warning && i.at.starts_with("subject_roots"))
            .map(|i| i.message)
            .collect();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("자리가 정해진"), "{w:?}");
    }

    /// 넓은 루트 경고가 **이미 푼 문제를 지적하지 않는다.**
    ///
    /// 무시되는 경고는 정말 필요한 자리에서도 읽히지 않는다.
    #[test]
    fn the_wide_root_warning_stops_naming_structured_config_once_it_is_narrowed() {
        let wide = probe("");
        let narrowed = probe("subject_roots:\n  structured_config: ['C:\\PROGRAMDATA\\Acme']");
        let says = |m: &PluginManifest| {
            lint(m)
                .into_iter()
                .any(|i| i.message.contains("structured_config 가 함께 선언돼 있다"))
        };
        assert!(says(&wide), "좁히지 않았는데 말하지 않는다");
        assert!(
            !says(&narrowed),
            "이미 좁혔는데 계속 지적한다 — 늑대소년이다"
        );
    }
}

/// **문서가 진단 전부를 덮는가.**
///
/// # 왜 필요한가
///
/// `32-lint-errors.md` 는 `generate.rs` 의 **손으로 적은 사례**를 린트에 태워
/// 만든다. 그래서 진단을 더하면서 사례를 넣지 않으면 **문서만 조용히
/// 침묵한다.** 2026-09-04 에 그랬다 — `check_subject_roots` 로 오류 넷을
/// 더했는데 사례가 없었고, 회차를 준비하다 우연히 발견했다. 그때 응시자에게
/// 가는 꾸러미에는 그 진단의 설명이 없는 채였다.
///
/// # 무엇을 세는가
///
/// **검사 함수**를 센다. 메시지를 세는 것이 더 촘촘하지만, 그러려면 진단마다
/// 안정된 이름을 붙여야 하고 그것은 34곳을 고치는 일이다. 검사 하나가 여러
/// 메시지를 내므로 이 게이트는 *"그 검사를 다루는 사례가 하나는 있다"* 까지만
/// 보증한다 — 그 한계를 여기 적어 둔다.
///
/// # 어떻게 세는가
///
/// 진단은 자기가 어느 검사에서 나왔는지 말하지 않는다. 그래서 **검사를 사례에
/// 직접 태운다.** 제품 코드를 하나도 바꾸지 않고 정확히 셀 수 있는 길이다.
mod doc_coverage_tests {
    use super::super::*;
    use crate::manifest::PluginManifest;

    /// `lint()` 이 부르는 검사 전부. **표가 곧 닫힌 집합이다.**
    ///
    /// `ids` 를 더 받는 넷은 클로저로 모양을 맞춘다.
    #[allow(clippy::type_complexity)]
    fn checks() -> Vec<(
        &'static str,
        Box<dyn Fn(&PluginManifest, &mut Vec<LintIssue>)>,
    )> {
        fn with_ids(
            f: fn(&PluginManifest, &BTreeSet<&str>, &mut Vec<LintIssue>),
        ) -> Box<dyn Fn(&PluginManifest, &mut Vec<LintIssue>)> {
            Box::new(move |m, out| {
                let ids: BTreeSet<&str> = m.detect.iter().map(|r| r.id.as_str()).collect();
                f(m, &ids, out)
            })
        }
        vec![
            (
                "check_duplicate_rule_ids",
                Box::new(check_duplicate_rule_ids),
            ),
            ("check_references", with_ids(check_references)),
            ("check_fields", Box::new(check_fields)),
            (
                "check_unpopulated_fields",
                Box::new(check_unpopulated_fields),
            ),
            ("check_package_fields", Box::new(check_package_fields)),
            ("check_archive_fields", Box::new(check_archive_fields)),
            ("check_enumerated_values", Box::new(check_enumerated_values)),
            ("check_sha256_literals", Box::new(check_sha256_literals)),
            ("check_version_literals", Box::new(check_version_literals)),
            (
                "check_subject_reachability",
                Box::new(check_subject_reachability),
            ),
            ("check_subject_roots", Box::new(check_subject_roots)),
            ("check_text_config_dirs", Box::new(check_text_config_dirs)),
            ("check_regexes", Box::new(check_regexes)),
            (
                "check_reputation_direction",
                Box::new(check_reputation_direction),
            ),
            ("check_remediate_refs", with_ids(check_remediate_refs)),
            (
                "check_collect_extra_refs",
                with_ids(check_collect_extra_refs),
            ),
            (
                "check_collect_extra_globs",
                Box::new(check_collect_extra_globs),
            ),
            (
                "check_yara_without_content",
                Box::new(check_yara_without_content),
            ),
            ("check_restore_named", Box::new(check_restore_named)),
            ("check_from_subject", Box::new(check_from_subject)),
            ("check_restore_defaults", with_ids(check_restore_defaults)),
            ("check_overbroad", Box::new(check_overbroad)),
            ("check_recursive_scope", Box::new(check_recursive_scope)),
            ("check_subject_platform", Box::new(check_subject_platform)),
            ("check_edit_platform", Box::new(check_edit_platform)),
            ("check_name", Box::new(check_name)),
            ("check_product_missing", Box::new(check_product_missing)),
        ]
    }

    /// 위 표가 `lint()` 과 갈라지지 않았는가.
    ///
    /// 검사를 새로 더하고 표에 넣지 않으면 그 검사는 아래 시험을 지나가지
    /// 못한다 — 그러면 이 게이트 자체가 조용히 느슨해진다. **소스를 읽어
    /// 대조한다.**
    #[test]
    fn the_check_table_matches_what_lint_calls() {
        // 시험이 `lint/tests.rs` 로 옮겨 와 소스는 한 칸 위다.
        let src = include_str!("../lint.rs");
        let body = src
            .split("pub fn lint(")
            .nth(1)
            .expect("lint() 를 찾지 못했다");
        let body = &body[..body.find("\n}\n").expect("lint() 의 끝")];

        let mut called: Vec<&str> = Vec::new();
        for line in body.lines() {
            if let Some(i) = line.find("check_") {
                let rest = &line[i..];
                let end = rest.find('(').unwrap_or(rest.len());
                called.push(&rest[..end]);
            }
        }
        called.sort();
        called.dedup();

        let mut listed: Vec<&str> = checks().iter().map(|(n, _)| *n).collect();
        listed.sort();

        assert_eq!(
            called, listed,
            "검사 표가 lint() 과 갈라졌다. 새 검사를 더했다면 `checks()` 에도 넣을 것 — \
             넣지 않으면 그 검사에 사례가 없어도 아무도 말하지 않는다"
        );
    }

    /// **검사마다 사례가 하나는 있는가.**
    ///
    /// 없으면 `32-lint-errors.md` 가 그 진단을 설명하지 않는다. 응시자에게 가는
    /// 꾸러미가 그 문서를 싣고 있으므로, 빠진 검사는 **설명 없는 오류**가 된다.
    #[test]
    fn every_check_has_a_case_in_the_generated_document() {
        let cases: Vec<PluginManifest> = crate::generate::lint_cases()
            .iter()
            .filter_map(|c| serde_yaml_ng::from_str(&c.yaml).ok())
            .collect();
        assert!(
            cases.len() >= 10,
            "파싱된 사례가 {}개뿐이다 — 사례 YAML 이 깨졌나",
            cases.len()
        );

        let mut naked = Vec::new();
        for (name, f) in checks() {
            let fires = cases.iter().any(|m| {
                let mut out = Vec::new();
                f(m, &mut out);
                !out.is_empty()
            });
            if !fires {
                naked.push(name);
            }
        }

        assert!(
            naked.is_empty(),
            "이 검사들을 다루는 사례가 `generate.rs` 에 없다: {}\n\
             그러면 `32-lint-errors.md` 가 그 진단을 설명하지 않고, 그 문서는 \
             응시자에게 가는 꾸러미에 실린다 — **설명 없는 오류**가 된다.\n\
             `lint_cases()` 에 `case(...)` 나 `append(...)` 를 하나 더할 것.",
            naked.join(" · ")
        );
    }
}

/// **한 플랫폼에서만 비는 필드를 다른 플랫폼에 대고 말하지 않는다.**
///
/// 2026-09-05 까지 `NOT_POPULATED_YET` 에 플랫폼 축이 없어서, Windows 플러그인이
/// `signature.trusted` 를 쓰면 *"이 술어는 언제나 거짓이다"* 라는 경고를 받았다.
/// 거짓이었다 — `remedy-wintrust` 가 채우고 청정 코퍼스에 6,689건이 있다.
/// 하필 `22-remediate-recipes.md` 가 **신뢰 서명이 재귀 삭제를 막는다**고
/// 가르치는 바로 그 필드였다.
mod signature_platform_tests {
    use super::super::*;
    use crate::catalog::Platform;
    use crate::manifest::PluginManifest;

    fn probe(platforms: &str, field: &str) -> PluginManifest {
        let y = format!(
            r#"schema_version: 1
id: sig-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [{platforms}]
name: {{ en: 'sig probe' }}
scan_roots: ['%LOCALAPPDATA%\\Programs']
subjects: [file]
detect:
  - id: payload
    subject: file
    where:
      - {{ field: {field}, op: exists }}
verdict: {{ require: payload }}
"#
        );
        serde_yaml_ng::from_str(&y).expect("탐침")
    }

    fn says(m: &PluginManifest, needle: &str) -> bool {
        lint(m).iter().any(|i| i.message.contains(needle))
    }

    #[test]
    fn windows_is_not_told_that_signature_is_dead() {
        let m = probe("windows", "signature.trusted");
        assert!(
            !says(&m, "채우지 않는 필드"),
            "Windows 에서 채워지는 필드를 죽었다고 말한다: {:?}",
            lint(&m).iter().map(|i| &i.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn linux_is_still_told() {
        let m = probe("linux", "signature.trusted");
        let msgs: Vec<String> = lint(&m).into_iter().map(|i| i.message).collect();
        assert!(
            msgs.iter().any(|x| x.contains("채우지 않는 필드")),
            "Linux 에서는 정말 비는데 말하지 않는다: {msgs:?}"
        );
        assert!(
            msgs.iter().any(|x| x.contains("linux 에서")),
            "어느 플랫폼인지 말하지 않는다 — '채우지 않는다' 와 'Linux 에서는 \
             채우지 않는다' 는 작성자가 할 일이 다르다: {msgs:?}"
        );
    }

    /// 겸용 플러그인은 **듣는 편이 낫다.** 한쪽에서 죽는다는 사실이 여전히
    /// 그 플러그인의 사실이다.
    #[test]
    fn a_cross_platform_plugin_is_told() {
        let m = probe("windows, linux", "signature.trusted");
        assert!(says(&m, "채우지 않는 필드"), "겸용에게 말하지 않는다");
    }

    /// 어디서나 비는 필드는 플랫폼과 무관하게 말한다.
    #[test]
    fn a_field_empty_everywhere_is_told_on_windows_too() {
        let m = probe("windows", "streams");
        assert!(
            says(&m, "채우지 않는 필드"),
            "어디서나 비는 필드를 말하지 않는다"
        );
    }

    /// 평가기도 같은 사실을 말한다 — **스냅샷이 뜬 기계**를 기준으로.
    #[test]
    fn the_evaluator_asks_about_the_snapshot_platform() {
        let m = probe("windows, linux", "signature.trusted");
        let win = unpopulated_field_uses(&m, &[Platform::Windows]);
        let lin = unpopulated_field_uses(&m, &[Platform::Linux]);
        assert!(win.is_empty(), "Windows 스냅샷에서 죽었다고 한다: {win:?}");
        assert_eq!(lin.len(), 1, "Linux 스냅샷에서 말하지 않는다: {lin:?}");
        assert_eq!(lin[0].only_on, Some(Platform::Linux));
    }

    #[test]
    fn a_name_in_one_language_only_is_an_error() {
        // name 은 고객 화면의 첫 줄이다. `ko` 만 있으면 영어 화면에 한국어
        // 이름이 나오고, 비어 있으면 위협 이름 줄이 조용히 빠진다 (2026-09-06 실측).
        let base: PluginManifest =
            serde_yaml_ng::from_str(crate::generate::LINT_BASE).expect("기준 매니페스트");
        assert!(
            lint(&base).iter().all(|i| !i.at.starts_with("name.")),
            "기준이 걸린다"
        );

        let mut ko_only = base.clone();
        ko_only.name.remove("en");
        let issues: Vec<_> = lint(&ko_only)
            .into_iter()
            .filter(|i| i.at == "name.en")
            .collect();
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].severity, Severity::Error);

        let mut empty = base.clone();
        empty.name.clear();
        let ats: Vec<String> = lint(&empty)
            .into_iter()
            .filter(|i| i.at.starts_with("name."))
            .map(|i| i.at)
            .collect();
        assert_eq!(ats, vec!["name.ko".to_string(), "name.en".to_string()]);

        let mut blank = base.clone();
        blank.name.insert("en".into(), "   ".into());
        assert!(
            lint(&blank).iter().any(|i| i.at == "name.en"),
            "빈 문자열은 없는 것과 같다"
        );
    }
}

mod glob_tests {
    use super::super::{lint, Severity};
    use crate::manifest::PluginManifest;

    fn probe(subjects: &str, glob: &str) -> PluginManifest {
        let y = format!(
            r#"schema_version: 1
id: glob-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
name: {{ ko: '글롭 탐침', en: 'glob probe' }}
scan_roots: ['/usr/lib64']
subjects: [{subjects}]
detect:
  - id: r
    subject: file
    where:
      - {{ field: path, op: ends_with, value: '/x' }}
verdict: {{ require: 'r' }}
collect_extra:
  - {{ glob: '{glob}' }}
"#
        );
        serde_yaml_ng::from_str(&y).unwrap_or_else(|e| panic!("{e}\n{y}"))
    }

    fn glob_errors(subjects: &str, glob: &str) -> usize {
        lint(&probe(subjects, glob))
            .into_iter()
            .filter(|i| i.severity == Severity::Error && i.at == "collect_extra[0].glob")
            .count()
    }

    #[test]
    fn a_glob_in_one_folder_inside_the_roots_is_quiet() {
        assert_eq!(glob_errors("file", "/usr/lib64/libkeyutils*"), 0);
    }

    /// 셋 다 오류 없이 **조용한 0건**이 되는 자리다 — 린트가 아니면 아무도 모른다.
    #[test]
    fn a_glob_that_can_pick_nothing_is_an_error() {
        assert_eq!(
            glob_errors("file", "/usr/*/libkeyutils*"),
            1,
            "폴더 쪽 와일드카드"
        );
        assert_eq!(glob_errors("file", "/etc/libkeyutils*"), 1, "scan_roots 밖");
        assert_eq!(glob_errors("file", "libkeyutils*"), 1, "폴더가 없다");
        assert_eq!(
            glob_errors("process", "/usr/lib64/libkeyutils*"),
            1,
            "file 이 없다"
        );
    }
}
