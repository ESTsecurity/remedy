//! 스캐너 `internal/phpconfig` 의 시험을 옮겼다. 원래 이름은 각 시험 위에 적었다.

use super::*;

const UPLOAD: &str = "session.upload_progress.enabled";
const HANDLER: &str = "session.serialize_handler";

fn doc(path: &str, text: &str) -> Document {
    Document {
        path: path.to_string(),
        data: text.as_bytes().to_vec(),
    }
}

fn assess_ko(text: &str) -> Finding {
    assess("id", &[doc("config", text)], &[], Lang::Ko)
}

fn evidence_text(f: &Finding) -> String {
    f.evidence
        .iter()
        .map(|e| format!("{}{}", e.source, e.detail))
        .collect()
}

/// 한 번, 온전히, 이 값으로 읽혔는가.
fn one(setting: &Setting, value: &str, scoped: bool) -> bool {
    setting.count == 1 && !setting.invalid && setting.scoped == scoped && setting.values == [value]
}

/// 두 이름에 대해 본 것을 한 줄로 — `수|값/값|풀지 못함|범위` 둘을 `;` 로 잇는다.
fn dump(seen: &Seen) -> String {
    let one = |s: &Setting| {
        let values = s.values.join("/");
        format!("{}|{values}|{}|{}", s.count, s.invalid, s.scoped)
    };
    format!("{};{}", one(&seen.upload), one(&seen.handler))
}

/// 스캐너 `TestAssessIdentityAndAlwaysReview`.
#[test]
fn the_finding_is_always_review_required() {
    let texts = [
        "",
        "session.upload_progress.enabled=Off",
        "session.upload_progress.enabled=On\nsession.serialize_handler=php_binary",
        "session.upload_progress.enabled=1\nsession.serialize_handler=php_serialize",
        "session.upload_progress.enabled=0\nsession.serialize_handler=php",
        "session.upload_progress.enabled=${SETTING}",
        "session.serialize_handler=not-a-handler",
    ];
    for text in texts {
        let f = assess("host-1", &[doc("/etc/php.ini", text)], &[], Lang::Ko);
        assert_eq!(f.status, Status::ReviewRequired, "{text:?}");
        assert_eq!(f.product, Product::Php);
        assert_eq!(f.id, format!("host-1:{CVE}"));
        assert_eq!(f.name, "PHP 세션 설정");
        assert_eq!(f.cves, vec![CVE.to_string()]);
    }
    let f = assess("image-1", &[], &[], Lang::Ko);
    assert_eq!(f.status, Status::ReviewRequired);
    assert!(f.reason.contains("설정 미확인"), "{}", f.reason);
    assert_eq!(CVE, "CVE-2026-115560");
}

/// 스캐너 `TestSupportedAssignments` 의 표.
#[test]
fn the_three_syntaxes_are_read() {
    let cases: [(&str, &str, &str, &str, bool); 11] = [
        (
            "ini",
            "[Session]\nsession.upload_progress.enabled=On\nsession.serialize_handler=php_binary",
            "On",
            "php_binary",
            false,
        ),
        (
            "quoted-ini",
            "\u{feff}session.upload_progress.enabled = \"Off\" ; comment\r\nsession.serialize_handler='php_serialize'",
            "Off",
            "php_serialize",
            false,
        ),
        (
            "fpm-value",
            "[www]\nphp_value[session.upload_progress.enabled] = yes\nphp_value[session.serialize_handler] = php_binary",
            "On",
            "php_binary",
            true,
        ),
        (
            "fpm-admin",
            "php_admin_value[session.upload_progress.enabled]=false\nphp_admin_value[session.serialize_handler]=\"php_serialize\"",
            "Off",
            "php_serialize",
            false,
        ),
        (
            "fpm-flag",
            "[www]\nphp_flag[session.upload_progress.enabled]=true\nphp_value[session.serialize_handler]=php_binary",
            "On",
            "php_binary",
            true,
        ),
        (
            "fpm-admin-flag",
            "[www]\nphp_admin_flag[session.upload_progress.enabled]=Off\nphp_admin_value[session.serialize_handler]=php_serialize",
            "Off",
            "php_serialize",
            true,
        ),
        (
            "apache-value",
            "php_value session.upload_progress.enabled On\nphp_value session.serialize_handler php_binary",
            "On",
            "php_binary",
            false,
        ),
        (
            "apache-admin-value",
            "php_admin_value session.upload_progress.enabled 0\nphp_admin_value session.serialize_handler php",
            "Off",
            "php",
            false,
        ),
        (
            "apache-flag",
            "PHP_FLAG session.upload_progress.enabled oFF\nphp_value \"session.serialize_handler\" \"php_binary\"",
            "Off",
            "php_binary",
            false,
        ),
        (
            "apache-admin-flag",
            "php_admin_flag session.upload_progress.enabled On\nphp_admin_value session.serialize_handler 'php_serialize'",
            "On",
            "php_serialize",
            false,
        ),
        (
            "windows-unrelated-path",
            "extension_dir=C:\\php\\ext\\\nsession.upload_progress.enabled=Off\ninclude_path=\"C:\\php\\\"\nsession.serialize_handler=php_binary",
            "Off",
            "php_binary",
            false,
        ),
    ];
    for (name, text, upload, handler, scoped) in cases {
        let seen = parse(text.as_bytes());
        assert!(
            one(&seen.upload, upload, scoped),
            "{name}: {:?}",
            seen.upload
        );
        assert!(
            one(&seen.handler, handler, scoped),
            "{name}: {:?}",
            seen.handler
        );
    }
}

/// 스캐너 `TestBooleanLiteralsAndHandlerNames`.
#[test]
fn boolean_words_and_handler_names_are_a_closed_list() {
    for value in ["On", "TRUE", "yes", "1", "Off", "False", "no", "none", "0"] {
        let seen = parse(format!("{UPLOAD}={value}").as_bytes());
        assert!(
            !seen.upload.invalid && seen.upload.values.len() == 1,
            "아는 값을 버렸다: {value:?}: {:?}",
            seen.upload
        );
    }
    for value in ["PHP", "PHP_BINARY", "igbinary", "", "php_serialize extra"] {
        let seen = parse(format!("{HANDLER}={value}").as_bytes());
        assert!(
            seen.handler.invalid && seen.handler.values.is_empty(),
            "모르는 처리기를 받았다: {value:?}: {:?}",
            seen.handler
        );
    }
}

/// 스캐너 `TestCommentsAndLookalikeNamesAreIgnored`.
#[test]
fn comments_and_lookalike_names_are_ignored() {
    let text = "; session.upload_progress.enabled=On
# php_flag session.upload_progress.enabled On
;php_value[session.serialize_handler]=php_binary
session.upload_progress.enabled_extra=On
session.serialize_handler_backup=php_binary
prefix.session.upload_progress.enabled=Off
session.upload_progress.cleanup=Off
some_key=\"session.upload_progress.enabled=Off\"
echo \"session.upload_progress.enabled=Off\";
php_value some_key \"session.serialize_handler=php_binary\"
";
    assert_eq!(parse(text.as_bytes()), Seen::default());
}

/// 스캐너 `TestDynamicMalformedAndUnexpectedValuesAreUnresolved`.
#[test]
fn dynamic_and_malformed_values_stay_unresolved() {
    let texts = [
        r#"session.upload_progress.enabled=${UPLOAD_ENABLED:-Off}"#,
        r#"session.upload_progress.enabled="${UPLOAD_ENABLED}""#,
        r#"session.upload_progress.enabled=2"#,
        r#"session.upload_progress.enabled=Off # not an ini comment"#,
        r#"session.upload_progress.enabled="Off;secret""#,
        r#"session.upload_progress.enabled="Off"#,
        r#"session.upload_progress.enabled="O\ff""#,
        r#"session.upload_progress.enabled="Off" "On""#,
        r#"session.upload_progress.enabled[]=Off"#,
        r#"session.upload_progress.enabled Off"#,
        r#"php_value[session.upload_progress.enabled]=${ENABLED}"#,
        r#"php_admin_value[session.upload_progress.enabled] Off"#,
        r#"php_value[session.upload_progress.enabled = Off"#,
        r#"php_flag session.upload_progress.enabled true"#,
        r#"php_admin_flag session.upload_progress.enabled 0"#,
        r#"php_flag session.upload_progress.enabled "Off" extra"#,
        r#"php_flag session.upload_progress.enabled Off # not an Apache comment"#,
        r#"php_flag session.upload_progress.enabled "Off"#,
    ];
    for text in texts {
        let upload = parse(text.as_bytes()).upload;
        assert!(
            upload.count == 1 && upload.invalid && upload.values.is_empty(),
            "풀지 못할 입력이 값이 됐다: {text:?}: {upload:?}"
        );
    }
    for text in [
        "php_flag session.serialize_handler php_binary",
        "php_admin_flag[session.serialize_handler]=php_binary",
    ] {
        let handler = parse(text.as_bytes()).handler;
        assert!(
            handler.invalid && handler.values.is_empty(),
            "처리기를 켜고 끄는 값으로 받았다: {text:?}: {handler:?}"
        );
    }
}

/// 스캐너 `TestScopedSettingsNeverConfirmDisable`.
#[test]
fn scoped_settings_never_confirm_a_disable() {
    let texts = [
        "[PATH=/srv/app]\nsession.upload_progress.enabled=Off",
        "[HOST=example.test]\nsession.upload_progress.enabled=Off",
        "[PATH = /srv/app]\nsession.upload_progress.enabled=Off",
        "[PATH=/srv/app]\n[Session]\nsession.upload_progress.enabled=Off",
        "[www]\nphp_admin_value[session.upload_progress.enabled]=Off",
        "<IfModule mod_php.c>\nphp_flag session.upload_progress.enabled Off\n</IfModule>",
        "<VirtualHost *:80>\nphp_admin_flag session.upload_progress.enabled Off\n</VirtualHost>",
        "</Directory>\nphp_flag session.upload_progress.enabled Off",
        "<IfModule mod_php.c>\n</Directory>\nphp_flag session.upload_progress.enabled Off",
    ];
    for text in texts {
        let upload = parse(text.as_bytes()).upload;
        assert!(
            upload.scoped && !upload.single("Off"),
            "범위 안의 설정을 전체 설정으로 읽었다: {text:?}: {upload:?}"
        );
        let f = assess_ko(text);
        assert!(
            !f.reason.contains("운영 반영 여부는 미확인"),
            "{text:?}: {}",
            f.reason
        );
        assert!(
            f.evidence[0].detail.contains("적용 범위 미확인"),
            "{text:?}: {}",
            f.evidence[0].detail
        );
    }
    let closed = "<IfModule mod_php.c>\n</IfModule>\nphp_flag session.upload_progress.enabled Off";
    let upload = parse(closed.as_bytes()).upload;
    assert!(
        !upload.scoped && upload.single("Off"),
        "닫힌 Apache 구역이 남았다: {upload:?}"
    );
}

/// 스캐너 `TestDuplicateAndConflictingAssignments`.
#[test]
fn duplicates_and_conflicts_are_not_resolved() {
    for second in ["Off", "On"] {
        let docs = [
            doc("php.ini", &format!("{UPLOAD}=Off\n{HANDLER}=php_binary")),
            doc("pool.conf", &format!("{UPLOAD}={second}")),
        ];
        let f = assess("id", &docs, &[], Lang::Ko);
        assert!(
            !f.reason.contains("운영 반영 여부는 미확인"),
            "{}",
            f.reason
        );
        assert!(
            f.reason.contains("실제 적용값을 확인하지 못했습니다"),
            "{}",
            f.reason
        );
        // 두 파일에 같은 값이면 중복, 다른 값이면 충돌이다(스캐너의 답과 같다).
        let want = match second {
            "Off" => "중복 설정이 있어 실제 적용값을 확인하지 못했습니다.",
            _ => "설정값이 충돌해 실제 적용값을 확인하지 못했습니다.",
        };
        assert_eq!(f.reason, want);
    }
    let f = assess_ko(&format!("{UPLOAD}=Off\n{UPLOAD}=On"));
    let detail = &f.evidence[0].detail;
    assert!(
        detail.contains("설정값 충돌") && detail.contains("중복 설정"),
        "{detail}"
    );
}

/// 스캐너 `TestLiteralObservationsRequireRuntimeOrApplicationCheck`.
#[test]
fn a_literal_setting_still_needs_the_runtime_or_the_application() {
    let f = assess_ko(&format!("{UPLOAD}=Off\n{HANDLER}=php_binary"));
    assert_eq!(
        f.reason,
        "비활성화 설정을 발견했지만 운영 반영 여부는 미확인입니다."
    );
    let f = assess_ko(&format!("{UPLOAD}=On\n{HANDLER}=php_serialize"));
    assert_eq!(
        f.reason,
        "활성화 설정이 있습니다. 실제 적용값과 앱 코드 확인이 필요합니다."
    );
    let text = evidence_text(&f);
    for required in ["session_start 전에", "ini_set", "php 로 변경"] {
        assert!(text.contains(required), "앱 쪽 조건이 빠졌다: {required:?}");
    }
}

/// 스캐너 `TestNoRawConfigurationOrIssueTextIsRetained`.
#[test]
fn no_raw_configuration_or_issue_text_is_kept() {
    const SECRET: &str = "PRIVATE_TEST_VALUE_7c19";
    let text = format!(
        "password={SECRET}\n{UPLOAD}=Off ; {SECRET}\n{HANDLER}=\"{SECRET}\"\nphp_value session.serialize_handler ${{{SECRET}}}\n"
    );
    let issues = [format!("cannot read: {SECRET}")];
    for lang in [Lang::Ko, Lang::En] {
        let f = assess("id", &[doc("/etc/php.ini\u{1b}[2J", &text)], &issues, lang);
        let json = serde_json::to_string(&f).unwrap();
        for forbidden in [SECRET, "password", "cannot read", "\u{1b}", "${"] {
            assert!(
                !json.contains(forbidden),
                "원문이 샜다 {forbidden:?}: {json}"
            );
        }
        // 직렬화의 이스케이프에 기대지 않는다 — 근거 자체에 제어 문자가 없다.
        assert!(!evidence_text(&f).contains('\u{1b}'));
        assert!(f.evidence[0].source.starts_with("/etc/php.ini"));
        assert!(f.evidence[0].detail.contains(&format!("{UPLOAD}=Off")));
    }
    let f = assess("id", &[doc("/etc/php.ini", &text)], &issues, Lang::Ko);
    assert!(!f.reason.contains("설정 수집 미확인"));
    assert!(evidence_text(&f).contains("설정 수집 미확인 1건"));
}

/// 스캐너 `TestContinuedCommentsAndMultilineValuesAreNotAssignments`.
#[test]
fn continued_lines_and_multiline_values_are_not_settings() {
    let texts = [
        "# disabled Apache example \\\nphp_flag session.upload_progress.enabled Off\n",
        "UnknownDirective first \\\nphp_flag session.upload_progress.enabled Off\n",
        "password=\"line one\nsession.upload_progress.enabled=Off\nline three\"\n",
        "php_value password \"line one\nphp_flag session.upload_progress.enabled Off\nline three\"\n",
    ];
    for text in texts {
        let upload = parse(text.as_bytes()).upload;
        assert_eq!(upload.count, 0, "{text:?}: {upload:?}");
    }
}

/// 스캐너 `TestLongUnrelatedLineDoesNotHideFollowingSetting`.
#[test]
fn a_long_unrelated_line_does_not_hide_the_next_setting() {
    let text = format!("unrelated={}\n{UPLOAD}=Off", "x".repeat(128 << 10));
    let f = assess_ko(&text);
    assert!(f.evidence[0].detail.contains(&format!("{UPLOAD}=Off")));
}

/// 스캐너 `TestFixedConsoleExplanationsStayWithinLimit` — 까닭과 할 일은 화면 한 줄(120칸)에 드는 고정
/// 문장이고, 설정 이름은 근거에만 적는다. 한글은 두 칸으로 센다.
#[test]
fn reason_and_action_are_short_fixed_sentences() {
    let texts = [
        String::new(),
        format!("{UPLOAD}=Off"),
        format!("{UPLOAD}=On"),
        format!("{HANDLER}=php_binary"),
        format!("{UPLOAD}=Off\n{UPLOAD}=On"),
        format!("{UPLOAD}=Off\n{UPLOAD}=Off"),
        format!("[PATH=/srv/app]\n{UPLOAD}=Off"),
        format!("{UPLOAD}=${{VALUE}}"),
    ];
    let mut reasons = std::collections::HashSet::new();
    for text in &texts {
        for (lang, cells) in [(Lang::Ko, 2), (Lang::En, 1)] {
            let issues = ["read error".to_string()];
            let f = assess("id", &[doc("config", text)], &issues, lang);
            for value in [&f.reason, &f.action] {
                assert!(value.chars().count() * cells <= 120, "{value:?}");
                assert!(!value.contains(['\r', '\n']), "{value:?}");
                assert!(
                    !value.contains(UPLOAD) && !value.contains(HANDLER),
                    "{value:?}"
                );
            }
            if lang == Lang::Ko {
                reasons.insert(f.reason);
            }
        }
    }
    assert_eq!(
        reasons.len(),
        7,
        "까닭 일곱 갈래가 다 나와야 한다: {reasons:?}"
    );
}

/// 스캐너 `TestOfficialConditionsAndMitigationRemainWithNoDocuments`.
#[test]
fn the_advisory_stays_even_without_documents() {
    let f = assess("id", &[], &["unavailable".to_string()], Lang::Ko);
    let text = evidence_text(&f);
    let on = format!("{UPLOAD}=On");
    let off = format!("{UPLOAD}=Off");
    let no_upload = format!("{UPLOAD} 설정 미발견");
    let no_handler = format!("{HANDLER} 설정 미발견");
    for required in [
        OFFICIAL_SOURCE,
        on.as_str(),
        "php_binary/php_serialize",
        "session_start 전에 ini_set",
        "php 로 변경",
        off.as_str(),
        "요청 해석 전에",
        "모든 PHP worker",
        "이 도구는 설정을 바꾸지 않습니다",
        no_upload.as_str(),
        no_handler.as_str(),
        "설정 수집 미확인 1건",
    ] {
        assert!(text.contains(required), "빠졌다: {required:?}\n{text}");
    }
}

#[test]
fn the_reasons_come_in_the_scanner_order() {
    let reason = |text: &str| assess_ko(text).reason;
    // 충돌이 중복보다, 중복이 끈 설정보다 먼저다.
    assert!(reason(&format!("{UPLOAD}=Off\n{UPLOAD}=On")).contains("충돌"));
    assert!(reason(&format!("{UPLOAD}=Off\n{UPLOAD}=Off")).contains("중복"));
    assert!(reason(&format!("{HANDLER}=php\n{HANDLER}=php")).contains("중복"));
    // 켠 설정은 범위 안이어도 켠 설정으로 알린다. 끈 설정은 범위 안이면 범위를 알린다.
    assert!(reason(&format!("[HOST=a]\n{UPLOAD}=On")).contains("활성화"));
    assert!(reason(&format!("[HOST=a]\n{UPLOAD}=Off")).contains("적용 범위"));
    // 처리기만 있으면 찾지 못한 것이고, 값을 풀지 못했으면 그렇게 적는다.
    assert!(reason(&format!("{HANDLER}=php_binary")).contains("찾지 못했습니다"));
    assert!(reason(&format!("{UPLOAD}=maybe")).contains("해석하지 못했습니다"));
    let action = |text: &str| assess_ko(text).action;
    let (on, off) = (format!("{UPLOAD}=On"), format!("{UPLOAD}=Off"));
    assert_eq!(action(""), action(&format!("{UPLOAD}=maybe")));
    assert!(action(&off).contains("PHP worker"));
    for text in ["", "x=1", on.as_str(), off.as_str()] {
        assert!(action(text).ends_with("하십시오."), "{:?}", action(text));
    }
}

#[test]
fn english_output_carries_no_korean() {
    let texts = [
        String::new(),
        format!("{UPLOAD}=Off"),
        format!("{UPLOAD}=On\n{UPLOAD}=Off\n{HANDLER}=${{X}}"),
        format!("[PATH=/srv]\n{UPLOAD}=Off"),
    ];
    for text in &texts {
        let issues = ["x".to_string()];
        let f = assess("id", &[doc("", text)], &issues, Lang::En);
        let all = format!("{}{}{}{}", f.name, f.reason, f.action, evidence_text(&f));
        let hangul = all.chars().find(|c| ('가'..='힣').contains(c));
        assert_eq!(hangul, None, "{all}");
        assert_eq!(f.evidence[0].source, "path unknown");
        assert!(all.contains("collection issues: 1"), "{all}");
    }
    let ko = assess("id", &[doc("", "")], &[], Lang::Ko);
    assert_eq!(ko.evidence[0].source, "경로 미확인");
    let f = assess_ko(&format!("{UPLOAD}=On\n{UPLOAD}=Off\n{HANDLER}=${{X}}"));
    assert_eq!(
        f.evidence[0].detail,
        format!(
            "{UPLOAD}=On/Off; 설정값 충돌; 중복 설정; 적용 순서 미확인; {HANDLER} 값 미확인; 해석할 수 없는 값 또는 문법"
        )
    );
}

/// 스캐너(`d3acb38`)의 `parse` 에 같은 입력을 넣어 얻은 답이다. 옮긴 시험이 닿지 않는 자리 — 낱말 사이의
/// 유니코드 공백과 낱말을 끊는 Latin-1 바이트, 유니코드 대소문자 접기, 구역의 짝, BOM 과 줄 끝, 줄 잇기와 여러
/// 줄 값, FPM · Apache 문법의 모서리 — 를 스캐너와 맞춘다.
#[test]
fn edge_cases_parse_as_the_scanner_does() {
    let rows: &[(&[u8], &str)] = &[
        (b"php_flag\xc2\xa0session.upload_progress.enabled Off", "0||false|false;0||false|false"),
        (b"php_flag session.upload_progress.enabled \xc2\xa0Off", "1|Off|false|false;0||false|false"),
        (b"php_flag session.upload_progress.enabled\xe3\x80\x80 Off", "0||false|false;0||false|false"),
        (b"php_flag session.upload_progress.enabled Off\xc2\xa0x", "1||true|false;0||false|false"),
        (b"php_flag session.upload_progress.enabled Off\xa0", "1||true|false;0||false|false"),
        (b"php_flag\x0bsession.upload_progress.enabled\x0cOff", "1|Off|false|false;0||false|false"),
        (b"php_value session.serialize_handler voil\xc3\xa0", "0||false|false;1||true|false"),
        (b"php_flag\x85session.upload_progress.enabled Off", "0||false|false;0||false|false"),
        (b"session.upload_progress.enabled\xa0=Off", "1||true|false;0||false|false"),
        (b"session.upload_progress.enabled\xc2\xa0=Off", "0||false|false;0||false|false"),
        (b"session.upload_progress.enabled\x85 = On", "1||true|false;0||false|false"),
        (b"session.upload_progress.enabled\x0b=\x0cOn", "1|On|false|false;0||false|false"),
        (b"session.upload_progress.enabled=\xc2\xa0On\xe3\x80\x80", "1|On|false|false;0||false|false"),
        (b"session.upload_progress.enabled=On\xa0", "1||true|false;0||false|false"),
        (b"[HO\xc5\xbfT=x]\nsession.upload_progress.enabled=Off", "1|Off|false|true;0||false|false"),
        (b"[P\xce\x91TH=/x]\nsession.upload_progress.enabled=Off", "1|Off|false|false;0||false|false"),
        (b"[\xc2\xa0path\xe3\x80\x80= /x]\nsession.upload_progress.enabled=Off", "1|Off|false|true;0||false|false"),
        (b"[PATHS=/x]\nsession.upload_progress.enabled=Off", "1|Off|false|false;0||false|false"),
        (b"PHP_ADM\xc4\xb0N_FLAG session.upload_progress.enabled On", "1|On|false|false;0||false|false"),
        (b"php_adm\xc4\xb1n_flag session.upload_progress.enabled On", "0||false|false;0||false|false"),
        (b"php_value session.serialize_handler php_b\xc4\xb1nary", "0||false|false;1||true|false"),
        (b"session.upload_progress.enabled=ye\xc5\xbf", "1||true|false;0||false|false"),
        (b"session.upload_progress.enabled=TRUE", "1|On|false|false;0||false|false"),
        (b"[www]\nsession.upload_progress.enabled=Off", "1|Off|false|false;0||false|false"),
        (b"[www]\nphp_value[session.upload_progress.enabled]=Off", "1|Off|false|true;0||false|false"),
        (b"[PATH=/x]\n[www]\nphp_value[session.serialize_handler]=php", "0||false|false;1|php|false|true"),
        (b"[\"x]\nsession.upload_progress.enabled=Off", "0||false|false;0||false|false"),
        (b"[x] ; \"\nsession.upload_progress.enabled=Off", "1|Off|false|false;0||false|false"),
        (b"[x\nsession.upload_progress.enabled=Off", "1|Off|false|true;0||false|false"),
        (b"[x]y\nsession.upload_progress.enabled=Off", "1|Off|false|true;0||false|false"),
        (b"<IfModule\tmod_php.c>\n</IfModule>\nphp_flag session.upload_progress.enabled Off", "1|Off|false|true;0||false|false"),
        (b"<IfModule mod_php.c>\n</ifmodule>\nphp_flag session.upload_progress.enabled Off", "1|Off|false|false;0||false|false"),
        (b"<\xff>\n</\xfe>\nphp_flag session.upload_progress.enabled Off", "1|Off|false|false;0||false|false"),
        (b"<\xe2\x82>\n</\xff>\nphp_flag session.upload_progress.enabled Off", "1|Off|false|true;0||false|false"),
        (b"<a>\n<b>\n</a>\nphp_flag session.upload_progress.enabled Off", "1|Off|false|true;0||false|false"),
        (b"<a>\n<b>\n</b>\n</a>\nphp_flag session.upload_progress.enabled Off", "1|Off|false|false;0||false|false"),
        (b"<a\nphp_flag session.upload_progress.enabled Off", "1|Off|false|true;0||false|false"),
        (b"<\xc4\xb0f x>\n</if>\nphp_flag session.upload_progress.enabled Off", "1|Off|false|false;0||false|false"),
        (b"  <Directory \"/var/www\">  \n\tphp_admin_value session.serialize_handler php_serialize\n</Directory>", "0||false|false;1|php_serialize|false|true"),
        (b"\xef\xbb\xbfsession.upload_progress.enabled=Off", "1|Off|false|false;0||false|false"),
        (b"x=1\n\xef\xbb\xbfsession.upload_progress.enabled=Off", "0||false|false;0||false|false"),
        (b"session.upload_progress.enabled=Off\rsession.serialize_handler=php", "1||true|false;0||false|false"),
        (b"session.upload_progress.enabled=Off\r\r\nsession.serialize_handler=php", "1|Off|false|false;1|php|false|false"),
        (b"session.upload_progress.enabled=Off\n\rsession.serialize_handler=php", "1|Off|false|false;1|php|false|false"),
        (b"x \\\nsession.upload_progress.enabled=Off", "0||false|false;0||false|false"),
        (b"x=1 \\\nsession.upload_progress.enabled=Off", "1|Off|false|false;0||false|false"),
        (b"x \\\\\nsession.upload_progress.enabled=Off\nsession.serialize_handler=php", "0||false|false;1|php|false|false"),
        (b"; c \\\nsession.upload_progress.enabled=Off", "0||false|false;0||false|false"),
        (b"foo \"a\\\"\nsession.upload_progress.enabled=Off\n\"\nsession.serialize_handler=php", "0||false|false;1|php|false|false"),
        (b"x=\"a\\\"\nsession.upload_progress.enabled=Off\n\"\nsession.serialize_handler=php", "1|Off|false|false;0||false|false"),
        (b"x='a\nsession.upload_progress.enabled=Off\n' ; \"\nsession.serialize_handler=php", "0||false|false;1|php|false|false"),
        (b"x=1 ; \"a\nsession.upload_progress.enabled=Off", "1|Off|false|false;0||false|false"),
        (b"session.upload_progress.enabled=On\\\nsession.serialize_handler=php", "1||true|false;1|php|false|false"),
        (b"session.upload_progress.enabled=\"On\n\"\nsession.serialize_handler=php", "1||true|false;1|php|false|false"),
        (b"php_value[session.upload_progress.enabled]]=On", "1||true|false;0||false|false"),
        (b"php_flag[session.serialize_handler]=php", "0||false|false;1||true|false"),
        (b"php_admin_value[ session.upload_progress.enabled ]=On", "0||false|false;0||false|false"),
        (b"php_value[session.upload_progress.enabled=On", "1||true|false;0||false|false"),
        (b"php_value[session.upload_progress.enabledx=On", "0||false|false;0||false|false"),
        (b"php_value [session.upload_progress.enabled]=On", "0||false|false;0||false|false"),
        (b"PHP_VALUE[session.upload_progress.enabled]=On", "0||false|false;0||false|false"),
        (b"php_admin_flag[session.upload_progress.enabled] = \"none\" ; c", "1|Off|false|false;0||false|false"),
        (b"session.upload_progress.enabled = \"On\" ; x", "1|On|false|false;0||false|false"),
        (b"session.upload_progress.enabled = 'On' # x", "1||true|false;0||false|false"),
        (b"session.upload_progress.enabled=\"On\"\"Off\"", "1||true|false;0||false|false"),
        (b"session.upload_progress.enabled=", "1||true|false;0||false|false"),
        (b"session.upload_progress.enabled", "1||true|false;0||false|false"),
        (b"session.upload_progress.enabled==On", "1||true|false;0||false|false"),
        (b"session.serialize_handler=php_serialize ; c", "0||false|false;1|php_serialize|false|false"),
        (b"session.serialize_handler='php_binary'", "0||false|false;1|php_binary|false|false"),
        (b"session.serialize_handler=Php", "0||false|false;1||true|false"),
        (b"php_flag session.upload_progress.enabled 'On'x", "1||true|false;0||false|false"),
        (b"php_flag \"session.upload_progress.enabled\" on", "1|On|false|false;0||false|false"),
        (b"PHP_FLAG session.upload_progress.enabled ON\r", "1|On|false|false;0||false|false"),
        (b"php_value session.upload_progress.enabled 1", "1|On|false|false;0||false|false"),
        (b"php_flag session.upload_progress.enabled 1", "1||true|false;0||false|false"),
        (b"php_admin_value 'session.serialize_handler' \"php\"", "0||false|false;1|php|false|false"),
        (b"php_flag session.upload_progress.enabled Off \\", "1||true|false;0||false|false"),
        (b"php_flag session.upload_progress.enabled", "1||true|false;0||false|false"),
        (b"php_flag session.upload_progress.enabled ", "1||true|false;0||false|false"),
        (b"php_flag session.upload_progress.enabled \"\"", "1||true|false;0||false|false"),
        (b"php_flag session.upload_progress.enabled On Off", "1||true|false;0||false|false"),
        (b"php_value session.upload_progress.enabled On\nphp_admin_value session.upload_progress.enabled on\nsession.upload_progress.enabled=1", "3|On|false|false;0||false|false"),
        (b"#c=1 \\\nsession.upload_progress.enabled=Off", "0||false|false;0||false|false"),
        (b"<a>=1 \\\nsession.upload_progress.enabled=Off", "0||false|false;0||false|false"),
        (b"x \\\r\nsession.upload_progress.enabled=Off", "0||false|false;0||false|false"),
        (b"[\"a\\b\"]\nsession.upload_progress.enabled=Off", "1|Off|false|true;0||false|false"),
        (b"['x\\']\nsession.upload_progress.enabled=Off", "0||false|false;0||false|false"),
        (b"['a;b']\nsession.upload_progress.enabled=Off", "1|Off|false|false;0||false|false"),
        (b"\xc2\xa0session.upload_progress.enabled=Off", "1|Off|false|false;0||false|false"),
        (b"< IfModule x >\n</IfModule>\nphp_flag session.upload_progress.enabled Off", "1|Off|false|false;0||false|false"),
        (b"<IfModule x>\n</ IfModule >\nphp_flag session.upload_progress.enabled Off", "1|Off|false|true;0||false|false"),
    ];
    for (text, want) in rows {
        let shown = String::from_utf8_lossy(text);
        assert_eq!(dump(&parse(text)), *want, "{shown:?}");
    }
}
