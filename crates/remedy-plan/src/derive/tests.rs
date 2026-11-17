//! derive 의 시험 — 2026-11-17 에 derive.rs(3,509줄 중 시험 1,975줄)에서 떼어 냈다. 내용은 그대로다.

use super::*;

/// `derive` 를 부르되 **미룬 사유가 지금 언어로 나오는지** 함께 본다.
///
/// # 왜 캡처가 아니라 여기인가 (2026-09-16)
///
/// `deferred[*].reason` 은 화면에 나간다 — *"이 계획은 치료의 전부가 아닙니다"*
/// 아래 줄이 그것이다(`remedy-report`). 그런데 **콘솔 캡처는 그 절을 한 번도
/// 밟지 않는다**: 기준선 둘에서 `재시도 대기` 는 0 이다. 캡처가 쓰는
/// 플러그인이 미룰 것 없이 다 계획되기 때문이고, 그것을 억지로 만들면
/// 캡처가 계획기 시험이 된다.
///
/// 그 상황을 만드는 것은 **이미 아래 시험들이다.** 라이브러리 시험은 언어를
/// 정하지 않아 영어로 돌므로(`i18n::current` 의 기본값), 사유에 한글이 남아
/// 있으면 그 사유는 한 언어뿐이라는 뜻이다.
///
/// `guard.rs` 의 같은 래퍼와 한 쌍이다 — 이름을 그대로 두어 아래 호출들을
/// 고치지 않는다.
fn derive(scan: &ScanEnvelope, manifest: &PluginManifest, mode: Mode, allow: &Allowed) -> Derived {
    let d = super::derive(scan, manifest, mode, allow);
    for x in &d.deferred {
        assert!(
            !x.reason.chars().any(|c| ('가'..='힣').contains(&c)),
            "미룬 사유가 영어 회차에서 한글로 나온다 ({}): {}",
            x.at,
            x.reason
        );
    }
    d
}

/// 증거 하나 — **레코드 모양 그대로.** 아래의 `ev` 는 파일 경로 전용이라
/// 레지스트리처럼 조각으로 오는 subject 를 만들 수 없다.
fn ev_raw(subject: Subject, target: serde_json::Value) -> Evidence {
    Evidence {
        id: "e#0".into(),
        rule: "r".into(),
        subject,
        score: None,
        target,
        captures: Default::default(),
        matched: Vec::new(),
        label: None,
    }
}

/// 증거만 담은 최소 `scan.json` 봉투.
fn scan_with(evidence: Vec<Evidence>) -> ScanEnvelope {
    Envelope {
        schema_version: 1,
        kind: ArtifactKind::Scan,
        run_id: "r".into(),
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
        body: ScanBody {
            evidence,
            groups: Vec::new(),
            verdicts: Vec::new(),
            verdict_rules: Vec::new(),
            issues: Vec::new(),
            observation: Default::default(),
            scan_roots: Vec::new(),
            removable_roots: Vec::new(),
        },
    }
}

#[test]
fn a_text_line_is_pinned_by_number_and_content() {
    // 번호만이면 파일이 바뀌었을 때 엉뚱한 줄을 지우고, 내용만이면 같은
    // 줄이 여럿일 때 정해지지 않는다. **둘 다 실어야 한다.**
    let e = ev_raw(
        Subject::TextConfig,
        serde_json::json!({
            "path": "C:\\app\\settings.ini",
            "line_no": 3,
            "line": "evil=payload.exe"
        }),
    );
    let l = locator(&e).expect("술어");
    assert_eq!(l["line_no"], 3);
    assert_eq!(l["line"], "evil=payload.exe");
    assert_eq!(
        target_of(&e, Platform::Windows).as_deref(),
        Some("C:\\app\\settings.ini")
    );
}

#[test]
fn a_hosts_entry_points_at_the_file_it_came_from() {
    // 파일 자리를 계획기가 상수로 들고 있으면 스냅샷을 뜬 기계와 다른
    // 자리를 고칠 수 있다 — hosts 는 OS 마다 자리가 다르다.
    let e = ev_raw(
        Subject::HostsEntry,
        serde_json::json!({
            "ip": "1.2.3.4",
            "hostnames": ["evil.example", "cdn.evil.example"],
            "line_no": 7,
            "source": "C:\\Windows\\System32\\drivers\\etc\\hosts"
        }),
    );
    assert_eq!(
        target_of(&e, Platform::Windows).as_deref(),
        Some("C:\\Windows\\System32\\drivers\\etc\\hosts")
    );
    let l = locator(&e).expect("술어");
    assert_eq!(l["line_no"], 7);
    // 수집기가 주석과 여분 공백을 떼고 담으므로 같은 모양으로 다시 잇는다.
    assert_eq!(l["line"], "1.2.3.4 evil.example cdn.evil.example");
}

#[test]
fn a_structured_key_is_pinned_by_its_path() {
    let e = ev_raw(
        Subject::StructuredConfig,
        serde_json::json!({
            "path": "C:\\app\\prefs.json",
            "format": "json",
            "key_path": "policy.evil",
            "value": "x"
        }),
    );
    assert_eq!(locator(&e).expect("술어")["key_path"], "policy.evil");
}

#[test]
fn subjects_that_need_no_locator_get_none() {
    // 파일 하나를 통째로 지우는 데에는 술어가 필요 없다. 빈 술어를 실어
    // 두면 실행기가 그것을 찾다 실패한다.
    let e = ev_raw(Subject::File, serde_json::json!({ "path": "C:\\a.exe" }));
    assert!(locator(&e).is_none());
}

#[test]
fn a_file_held_by_a_running_process_is_planned_for_reboot() {
    // **계획기가 잠금을 안다.** 실행기가 만나서 갈아타면 그것은 "조건
    // 분기로 동작을 추가" 하는 것이라 불변식 P 가 깨지고, 드라이런이
    // 보여준 것과 실행한 것이 달라진다 (설계-03 §1).
    let file = ev_raw(
        Subject::File,
        serde_json::json!({ "path": "C:\\evil\\payload.dll" }),
    );
    let proc_ev = ev_raw(
        Subject::Process,
        serde_json::json!({
            "image_path": "C:\\Windows\\explorer.exe",
            "modules": ["C:\\Windows\\system32\\a.dll", "C:\\evil\\payload.dll"]
        }),
    );
    let scan = scan_with(vec![file.clone(), proc_ev]);
    assert_eq!(
        removal_ops_for(&file, &scan).ops(),
        &[Op::FileDeleteOnReboot],
        "로드된 모듈인데 지금 지우려 한다"
    );
}

#[test]
fn a_running_process_image_is_also_locked() {
    let file = ev_raw(
        Subject::File,
        serde_json::json!({ "path": "C:\\evil\\svc.exe" }),
    );
    let proc_ev = ev_raw(
        Subject::Process,
        serde_json::json!({ "image_path": "C:\\evil\\svc.exe", "modules": [] }),
    );
    let scan = scan_with(vec![file.clone(), proc_ev]);
    assert_eq!(
        removal_ops_for(&file, &scan).ops(),
        &[Op::FileDeleteOnReboot]
    );
}

#[test]
fn an_ordinary_file_is_not_pushed_to_reboot() {
    // 막지 말아야 할 것을 막으면 모든 삭제가 재부팅으로 밀린다.
    let file = ev_raw(
        Subject::File,
        serde_json::json!({ "path": "C:\\evil\\dropped.js" }),
    );
    let proc_ev = ev_raw(
        Subject::Process,
        serde_json::json!({ "image_path": "C:\\Windows\\explorer.exe", "modules": [] }),
    );
    let scan = scan_with(vec![file.clone(), proc_ev]);
    assert_eq!(
        removal_ops_for(&file, &scan).ops(),
        removal_ops(Subject::File).ops(),
        "잠기지 않은 파일까지 재부팅으로 밀었다"
    );
}

#[test]
fn the_lock_check_ignores_case_like_windows_does() {
    // 같은 파일을 대소문자가 달라 다른 것으로 보면 잠금을 놓친다.
    let file = ev_raw(
        Subject::File,
        serde_json::json!({ "path": "C:\\Evil\\Payload.DLL" }),
    );
    let proc_ev = ev_raw(
        Subject::Process,
        serde_json::json!({ "image_path": "x", "modules": ["c:\\evil\\payload.dll"] }),
    );
    let scan = scan_with(vec![file.clone(), proc_ev]);
    assert_eq!(
        removal_ops_for(&file, &scan).ops(),
        &[Op::FileDeleteOnReboot]
    );
}

/// 리눅스 스냅숏. `scan_with` 와 같고 `host.os` 만 다르다.
fn linux_scan_with(evidence: Vec<Evidence>) -> ScanEnvelope {
    let mut s = scan_with(evidence);
    s.host.os = "linux".into();
    s
}

#[test]
fn a_running_image_on_linux_is_removed_like_any_file() {
    // **잠금은 Windows 의 것이다.** 카탈로그가 리눅스에서 `file.delete_on_reboot`
    // 를 닫은 까닭이 그것이다("없는 것이 아니라 필요 없다"). 그 Op 을 고르면
    // 데몬의 실행 파일이 미룸으로 빠진다 — 랩 VM 에서 그랬다
    // (설계-09 P12 "systemd `Restart=` 데몬 실증", 2026-09-29).
    let file = ev_raw(
        Subject::File,
        serde_json::json!({ "path": "/opt/a/daemon" }),
    );
    let proc_ev = ev_raw(
        Subject::Process,
        serde_json::json!({ "image_path": "/opt/a/daemon", "modules": [] }),
    );
    let scan = linux_scan_with(vec![file.clone(), proc_ev]);
    assert_eq!(
        removal_ops_for(&file, &scan).ops(),
        removal_ops(Subject::File).ops(),
        "리눅스에서 돌고 있는 실행 파일을 재부팅 삭제로 보냈다"
    );
}

#[test]
fn the_reboot_delete_branch_is_reachable_only_where_files_lock() {
    // 잠긴 파일 분기가 서는 플랫폼에서만 `file.delete_on_reboot` 가 계획된다.
    // 표가 이것을 모르면 그 플랫폼이 낼 수 없는 Op 을 낼 수 있다고 약속한다.
    assert!(plannable_ops_on(Platform::Windows).contains(&Op::FileDeleteOnReboot));
    assert!(!plannable_ops_on(Platform::Linux).contains(&Op::FileDeleteOnReboot));
}

#[test]
fn a_registry_value_target_is_composed_from_its_parts() {
    // `registry_value` 는 `hive`·`key`·`name` 이 따로다. 합치지 않으면
    // **대상 없는 증거**가 되고 Action 이 만들어지지 않는다.
    let e = ev_raw(
        Subject::RegistryValue,
        serde_json::json!({ "hive": "HKLM", "key": "SOFTWARE\\X", "name": "Evil" }),
    );
    assert_eq!(
        target_of(&e, Platform::Windows).as_deref(),
        Some("HKLM\\SOFTWARE\\X\\Evil")
    );

    // 키 단위 관찰에는 값 이름이 없다.
    let k = ev_raw(
        Subject::RegistryKey,
        serde_json::json!({ "hive": "HKLM", "key": "SOFTWARE\\X" }),
    );
    assert_eq!(
        target_of(&k, Platform::Windows).as_deref(),
        Some("HKLM\\SOFTWARE\\X")
    );
}

#[test]
fn an_exclusion_target_keeps_the_value_name() {
    // **제외 대상은 값 이름이다.** `source` 는 그것이 사는 키일 뿐이라,
    // 그대로 쓰면 `Paths` 라는 이름의 값을 지우려 든다 — 그런 값은 없다.
    let e = ev_raw(
        Subject::AvExclusion,
        serde_json::json!({
            "kind": "path",
            "value": "C:\\evil",
            "source": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
        }),
    );
    assert_eq!(
        target_of(&e, Platform::Windows).as_deref(),
        Some("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\evil")
    );
}

#[test]
fn a_firewall_target_keeps_the_rule_id() {
    // 규칙 하나가 값 하나이고 `id` 가 그 값 이름이다.
    let e = ev_raw(
        Subject::FirewallRule,
        serde_json::json!({
            "id": "Evil-In-TCP",
            "source": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
        }),
    );
    let t = target_of(&e, Platform::Windows).expect("대상");
    assert!(t.ends_with("\\FirewallRules\\Evil-In-TCP"), "{t}");
}

#[test]
fn proxy_targets_come_only_from_what_the_rule_matched() {
    // **룰이 짚지 않은 설정까지 지우면 증거 없는 파괴다.**
    let mut e = ev_raw(
        Subject::ProxyConfig,
        serde_json::json!({ "scope": "user", "pac_url": "http://evil/p.pac" }),
    );
    e.matched = vec![remedy_sdk::artifact::MatchedPredicate {
        field: "pac_url".into(),
        op: "starts_with".into(),
        value: None,
    }];
    let t = proxy_targets(&e);
    assert_eq!(t.len(), 1, "{t:?}");
    assert!(t[0].ends_with("\\AutoConfigURL"), "{t:?}");
    assert!(
        t[0].starts_with("HKCU\\"),
        "user 범위인데 HKLM 을 짚었다: {t:?}"
    );

    // 아무것도 짚지 않았으면 지울 것도 없다.
    e.matched = vec![remedy_sdk::artifact::MatchedPredicate {
        field: "scope".into(),
        op: "equals".into(),
        value: None,
    }];
    assert!(proxy_targets(&e).is_empty(), "짚지 않은 설정을 지우려 한다");
}

#[test]
fn a_system_scope_proxy_points_at_hklm() {
    let mut e = ev_raw(
        Subject::ProxyConfig,
        serde_json::json!({ "scope": "system" }),
    );
    e.matched = vec![remedy_sdk::artifact::MatchedPredicate {
        field: "server".into(),
        op: "contains".into(),
        value: None,
    }];
    let t = proxy_targets(&e);
    assert_eq!(t.len(), 1);
    assert!(t[0].starts_with("HKLM\\"), "{t:?}");
    assert!(t[0].ends_with("\\ProxyServer"), "{t:?}");
}

#[test]
fn regenerators_are_exactly_the_ops_that_run_at_stage_five() {
    // **재생성을 일으키는 설정을 남긴 채 산출물만 지우면 즉시 돌아온다**
    // (설계-03 §2). 카탈로그의 `regenerator` 와 여기 목록이 갈라지면 그
    // 사고가 조용히 난다 — 계획은 정상으로 보이고 다음 트리거에서 되살아난다.
    for op in Op::ALL {
        if op.info().regenerator {
            assert_eq!(stage(op), 5, "'{}' 는 유발자인데 5단계가 아니다", op.id());
        }
    }
    // 반대 방향. 5단계인데 유발자가 아닌 것은 `boot.restore_default` 하나이며,
    // 그것은 다른 이유로 거기 있다(치료 도구가 쓸 수단을 되찾는다).
    let odd: Vec<&str> = Op::ALL
        .iter()
        .filter(|o| stage(**o) == 5 && !o.info().regenerator)
        .map(|o| o.id())
        .collect();
    assert_eq!(
        odd,
        vec!["boot.restore_default"],
        "5단계인데 유발자가 아닌 Op 이 늘었다 — 이유를 적었는가"
    );
}

#[test]
fn a_regenerator_runs_before_the_artifact_it_would_recreate() {
    // 예약 작업(유발자) → 드롭 파일(산출물). 순서를 어기면 다음 트리거에서
    // 파일이 되돌아온다.
    assert!(
        stage(Op::PersistenceDelete) < stage(Op::FileQuarantineOnly),
        "예약 작업이 드롭 파일보다 늦게 지워진다"
    );
    assert!(
        stage(Op::RegistryDeleteValue) < stage(Op::BrowserExtRemove),
        "정책 레지스트리가 브라우저 확장보다 늦게 지워진다"
    );
}

#[test]
fn the_planner_gate_is_the_sdk_gate() {
    // **같은 개념을 두 곳에 적으면 갈라진다.** 실제로 갈라졌었다 —
    // 계획기 P6, SDK P4. 그동안 실행기는 `file.quarantine_only` 를
    // 수행하는데 생성물은 "현재 코어: P4" 라고 광고했다.
    //
    // 상수를 합쳤으므로 지금은 구조적으로 같다. 이 시험은 누가 다시
    // 따로 두면 깨지라고 있다.
    for op in Op::ALL {
        assert_eq!(
            available(op, Platform::Windows),
            op.info().implemented_in <= remedy_sdk::IMPLEMENTED_THROUGH,
            "'{}' 에서 계획기 게이트와 SDK 게이트가 다르다",
            op.id()
        );
    }
    assert!(
        Op::ALL.iter().any(|o| available(*o, Platform::Windows)),
        "아무것도 계획할 수 없다"
    );

    // **Linux 도 같은 규칙을 따른다.** 2026-08-27 에 게이트가 P12 로 오르며
    // 열렸다 — 그전까지는 `Some(P12)` 가 게이트 밖이라 전부 미룸이었다.
    for op in Op::ALL {
        assert_eq!(
            available(op, Platform::Linux),
            op.info()
                .linux_from
                .is_some_and(|p| p <= remedy_sdk::IMPLEMENTED_THROUGH),
            "'{}' 에서 Linux 게이트가 카탈로그와 다르다",
            op.id()
        );
    }

    // **여는 것과 여는 줄 아는 것은 다르다.** 손으로 적은 목록이어야
    // 카탈로그를 잘못 건드렸을 때 알아챈다 — 카탈로그에서 뽑으면 자기
    // 자신과 비교하는 항진명제가 된다.
    let mut open: Vec<&str> = Op::ALL
        .into_iter()
        .filter(|o| available(*o, Platform::Linux))
        .map(|o| o.id())
        .collect();
    open.sort();
    assert_eq!(
        open,
        vec![
            "autorun.remove",
            "browser_ext.remove",
            "cert_store.remove",
            "file.delete",
            "file.quarantine_only",
            "hosts.restore_line",
            "persistence.delete",
            "persistence.disable",
            "process.kill",
            "service.delete",
            "service.disable",
            // 결정 A (2026-09-29) — 시스템 유닛을 systemd 에게 멈추게 한다.
            // 백엔드 `stop_unit_in` · 시험 `a_unit_is_stopped_by_asking_systemd_…`.
            "service.stop",
            "shortcut.strip_args",
            "structured_config.remove_key",
            "structured_config.restore_default",
            "text_config.remove_line",
        ],
        "Linux 에서 수행하는 Op 이 바뀌었다. 백엔드와 시험을 함께 확인할 것"
    );

    // **macOS 는 지원 대상이 아니다.** 모르는 플랫폼에서 파괴하지 않는다.
    assert!(
        !Op::ALL.iter().any(|o| available(*o, Platform::Darwin)),
        "지원하지 않는 플랫폼에서 수행 가능한 Op 이 있다"
    );

    // **이 자리에는 "막는 것이 하나는 있어야 한다" 가 있었다.** 2026-08-25
    // (P10-C) 에 마지막 하나(`dir.delete_recursive`)가 열리며 그 전제가
    // 끝났다 — 지금 게이트는 아무것도 막지 않는다.
    //
    // 게이트를 지우지 않는 이유는 **다음 Op 때문**이다. 새로 정의하는
    // 순간 그것이 다시 막히고, 위 첫 단언이 두 게이트가 갈라지지 않는지를
    // 계속 본다. 그 성질이 이 시험의 본체이고, 지금 사실은 아래가 적는다.
}
use remedy_sdk::artifact::{ArtifactKind, CoreInfo, Envelope, EvidenceGroup, HostInfo, ScanBody};

fn ev(id: &str, rule: &str, subject: Subject, path: &str) -> Evidence {
    Evidence {
        id: id.into(),
        rule: rule.into(),
        subject,
        score: None,
        target: serde_json::json!({ "path": path }),
        captures: Default::default(),
        matched: Vec::new(),
        label: None,
    }
}

fn group(id: &str, ev: &[&str], verdict: bool) -> EvidenceGroup {
    EvidenceGroup {
        id: id.into(),
        evidence: ev.iter().map(|s| s.to_string()).collect(),
        captures: Default::default(),
        verdict,
        excluded_reason: None,
    }
}

fn scan(evidence: Vec<Evidence>, groups: Vec<EvidenceGroup>) -> ScanEnvelope {
    Envelope {
        schema_version: 1,
        kind: ArtifactKind::Scan,
        run_id: "r".into(),
        created: "t".into(),
        host: HostInfo {
            hostname: "h".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        core: CoreInfo {
            version: "0".into(),
            build: "d".into(),
        },
        plugins: Vec::new(),
        body: ScanBody {
            evidence,
            groups,
            removable_roots: Vec::new(),
            verdicts: vec!["g0".into()],
            verdict_rules: Vec::new(),
            issues: Vec::new(),
            observation: Default::default(),
            scan_roots: vec![r"C:\a".into()],
        },
    }
}

fn manifest(remediate: serde_json::Value) -> PluginManifest {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1, "id": "x", "version": "0.1.0", "min_core": "1.0.0",
        "platforms": ["windows"], "name": {"en": "x"},
        "scan_roots": ["C:\\a"], "subjects": ["file", "persistence"],
        "detect": [{"id": "payload", "subject": "file",
                    "where": [{"field": "path", "op": "contains", "value": "evil"}]}],
        "verdict": {"require": "payload"},
        "remediate": remediate
    }))
    .expect("매니페스트")
}

/// 서명 정보를 실은 파일 증거. `trusted` 와 주체를 골라 넣는다.
const HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn ev_signed(id: &str, path: &str, trusted: bool, subject: &str, thumb: &str) -> Evidence {
    let mut e = ev(id, "payload", Subject::File, path);
    e.target = serde_json::json!({
        "path": path,
        "signature": { "trusted": trusted, "subject": subject, "thumbprint": thumb }
    });
    e
}

fn signed_manifest(signed_malware: serde_json::Value) -> PluginManifest {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1, "id": "x", "version": "0.1.0", "min_core": "1.0.0",
        "platforms": ["windows"], "name": {"en": "x"},
        "scan_roots": ["C:\\a"], "subjects": ["file"],
        "detect": [{"id": "payload", "subject": "file",
                    "where": [{"field": "path", "op": "contains", "value": "evil"}]}],
        "verdict": {"require": "payload"},
        "signed_malware": signed_malware,
        "remediate": { "remove": [{ "ref": "payload" }] }
    }))
    .expect("매니페스트")
}

/// 해시가 실린 증거. 5층은 이것으로만 판단한다.
fn ev_hashed(id: &str, path: &str, sha: &str) -> Evidence {
    let mut e = ev(id, "payload", Subject::File, path);
    e.target = serde_json::json!({ "path": path, "sha256": sha });
    e
}

fn allowed(sha: &str, why: &str) -> Allowed {
    let mut m = Allowed::new();
    m.insert(sha.to_ascii_lowercase(), why.to_string());
    m
}

#[test]
fn 조직_허용_목록에_있으면_삭제에서_빠진다() {
    // 설계-03 §3 5층. **판정은 그대로 선다** — 파괴만 하지 않는다.
    let s = scan(
        vec![ev_hashed("payload#0", r"C:\a\evil.exe", HASH)],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([]));
    let d = derive(
        &s,
        &m,
        Mode::default(),
        &allowed(HASH, "in-house build tool"),
    );

    assert!(
        d.actions.is_empty(),
        "면제 대상에 파괴가 계획됐다: {:?}",
        d.actions
    );
    // **조용히 빠지지 않는다.** 사유가 보고에 남아야 조직이 감사에 답한다.
    assert_eq!(d.deferred.len(), 1, "{:?}", d.deferred);
    assert!(
        d.deferred[0]
            .reason
            .contains(remedy_sdk::i18n::t("5층", "layer 5"))
            && d.deferred[0].reason.contains("in-house build tool"),
        "사유가 5층과 근거를 말하지 않는다: {:?}",
        d.deferred[0]
    );
}

#[test]
fn 목록이_비면_아무것도_면제되지_않는다() {
    // **이 시험이 위 시험을 지킨다.** 위가 "언제나 면제한다" 로 통과하면
    // 5층은 파괴를 통째로 끄는 스위치가 된다.
    let s = scan(
        vec![ev_hashed("payload#0", r"C:\a\evil.exe", HASH)],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([]));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    assert!(
        !d.actions.is_empty(),
        "면제가 없는데 파괴가 계획되지 않았다"
    );
}

#[test]
fn 다른_해시는_면제되지_않는다() {
    // 목록에 무엇이 있든 **그 해시만** 면제된다.
    let other = HASH.replace('e', "f");
    let s = scan(
        vec![ev_hashed("payload#0", r"C:\a\evil.exe", HASH)],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([]));
    let d = derive(&s, &m, Mode::default(), &allowed(&other, "다른 것"));
    assert!(
        !d.actions.is_empty(),
        "엉뚱한 해시로 면제됐다: {:?}",
        d.deferred
    );
}

#[test]
fn 대소문자가_면제를_가르지_않는다() {
    // 도구마다 표기가 갈린다. 그것 때문에 면제가 빗나가면 정상 파일이
    // 지워지고, 운영자는 이유를 알 수 없다.
    let s = scan(
        vec![ev_hashed(
            "payload#0",
            r"C:\a\evil.exe",
            &HASH.to_ascii_uppercase(),
        )],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([]));
    let d = derive(
        &s,
        &m,
        Mode::default(),
        &allowed(HASH, "in-house build tool"),
    );
    assert!(
        d.actions.is_empty(),
        "대문자 해시가 면제를 못 받았다: {:?}",
        d.actions
    );
}

#[test]
fn 해시가_없는_대상은_이_층으로_면제되지_않는다() {
    // 목록이 해시로만 지목하기 때문이다. 경로로 지목하면 그 자리에 파일을
    // 놓는 것만으로 면제를 얻는다 (`remedy-trust::allowlist` 모듈 주석).
    let s = scan(
        vec![ev("payload#0", "payload", Subject::File, r"C:\a\evil.exe")],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([]));
    let d = derive(
        &s,
        &m,
        Mode::default(),
        &allowed(HASH, "in-house build tool"),
    );
    assert!(
        !d.actions.is_empty(),
        "해시 없는 대상이 면제됐다: {:?}",
        d.deferred
    );
}

#[test]
fn 신뢰_서명이_허용_목록보다_먼저_보고된다() {
    // 설계-03 §3 은 **평가 순서 고정**이다. 순서가 뒤집히면 서명된 대상이
    // 허용 목록 사유로 보고되고, 그 둘은 운영자가 할 일이 다르다 —
    // 하나는 `signed_malware` 에 열거하는 것이고 다른 하나는 목록에서
    // 빼는 것이다.
    let mut e = ev_signed(
        "payload#0",
        r"C:\a\evil.exe",
        true,
        "CN=Some Vendor, O=Some Vendor",
        "AABB",
    );
    e.target["sha256"] = serde_json::json!(HASH);
    let s = scan(vec![e], vec![group("g0", &["payload#0"], true)]);
    let m = signed_manifest(serde_json::json!([]));
    let d = derive(
        &s,
        &m,
        Mode::default(),
        &allowed(HASH, "in-house build tool"),
    );

    assert_eq!(d.deferred.len(), 1, "{:?}", d.deferred);
    assert!(
        d.deferred[0]
            .reason
            .contains(remedy_sdk::i18n::t("2층", "layer 2")),
        "5층이 2층보다 먼저 걸렸다: {:?}",
        d.deferred[0]
    );
}

#[test]
fn 신뢰_서명이_있으면_삭제에서_빠진다() {
    // 설계-03 §3 2층. **열거 없는 포괄적 무시가 불가능하므로**, 목록이 비어
    // 있으면 서명된 대상은 어떤 경우에도 통과하지 못한다.
    let s = scan(
        vec![ev_signed(
            "payload#0",
            r"C:\a\evil.exe",
            true,
            "CN=Some Vendor, O=Some Vendor",
            "AABB",
        )],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([]));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert!(
        d.actions.is_empty(),
        "서명된 대상에 파괴가 계획됐다: {:?}",
        d.actions
    );
    // **조용히 빠지지 않는다.** 빠졌다는 사실과 사유가 보고에 남아야 한다.
    assert_eq!(d.deferred.len(), 1, "{:?}", d.deferred);
    assert!(
        d.deferred[0]
            .reason
            .contains(remedy_sdk::i18n::t("2층", "layer 2")),
        "사유가 2층을 가리키지 않는다: {:?}",
        d.deferred[0]
    );
}

#[test]
fn 주체를_열거하면_서명된_악성코드를_지운다() {
    let s = scan(
        vec![ev_signed(
            "payload#0",
            r"C:\a\evil.exe",
            true,
            "CN=Some Vendor, O=Some Vendor",
            "AABB",
        )],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([{ "subject": "CN=Some Vendor, O=Some Vendor" }]));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert_eq!(d.actions.len(), 1, "열거했는데 빠졌다: {:?}", d.deferred);
}

#[test]
fn 지문은_대소문자를_가리지_않는다() {
    // 지문 표기가 도구마다 갈린다. 그것 때문에 예외가 빗나가면 서명된
    // 악성코드를 지우지 못한다.
    let s = scan(
        vec![ev_signed(
            "payload#0",
            r"C:\a\evil.exe",
            true,
            "CN=V",
            "AABBCCDD",
        )],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([{ "thumbprint": "aabbccdd" }]));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert_eq!(d.actions.len(), 1, "{:?}", d.deferred);
}

#[test]
fn 다른_주체를_열거한_것은_통과시키지_않는다() {
    // 목록에 무엇이든 들어 있으면 통과하는 식이면 그것이 포괄적 무시다.
    let s = scan(
        vec![ev_signed(
            "payload#0",
            r"C:\a\evil.exe",
            true,
            "CN=Real Vendor",
            "AABB",
        )],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([{ "subject": "CN=Someone Else" }]));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert!(d.actions.is_empty(), "{:?}", d.actions);
}

#[test]
fn 자기서명은_2층의_보호를_받지_못한다() {
    // `trusted: false` — 서명은 있으나 신뢰 루트에 닿지 않는다. 이것을
    // 보호하면 서명을 붙이는 것만으로 치료를 피할 수 있게 된다.
    let s = scan(
        vec![ev_signed(
            "payload#0",
            r"C:\a\evil.exe",
            false,
            "CN=Evil Self Signed",
            "AABB",
        )],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([]));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert_eq!(
        d.actions.len(),
        1,
        "자기서명이 보호를 받았다: {:?}",
        d.deferred
    );
}

#[test]
fn 확인하지_않은_것을_신뢰로_읽지_않는다() {
    // `signature` 가 아예 없다 = "확인하지 않았다"(설계-03 §3). 그것을
    // 신뢰로 읽으면 실행 파일이 아닌 대상이 전부 보호받게 된다.
    let s = scan(
        vec![ev("payload#0", "payload", Subject::File, r"C:\a\evil.js")],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = signed_manifest(serde_json::json!([]));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert_eq!(d.actions.len(), 1, "{:?}", d.deferred);
}

#[test]
fn a_file_evidence_becomes_a_quarantine_action() {
    // 파일 제거는 **가장 덜 위험한** Op 으로 간다 — 격리는 옮기는 것이라
    // 되돌리기가 Op 의 정의 자체에 들어 있다 (설계-03 §2).
    let s = scan(
        vec![ev("payload#0", "payload", Subject::File, r"C:\a\evil.exe")],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "payload" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert_eq!(d.actions.len(), 1, "{:?}", d.actions);
    let a = &d.actions[0];
    assert_eq!(a.op, Op::FileQuarantineOnly);
    assert_eq!(a.target.as_deref(), Some(r"C:\a\evil.exe"));
    assert_eq!(a.because, vec!["payload#0"]);
    assert!(a.reversible);
    assert!(d.deferred.is_empty(), "{:?}", d.deferred);
}

#[test]
fn a_reversible_action_always_carries_a_backup_slot() {
    // 되돌릴 수 있다고 해 놓고 백업 자리가 없으면 그것은 복원 불가능한 파괴다.
    let s = scan(
        vec![ev("payload#0", "payload", Subject::File, r"C:\a\evil.exe")],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "payload" }] }));
    let b = derive(&s, &m, Mode::default(), &Allowed::new()).actions[0]
        .backup
        .clone()
        .expect("백업 자리");
    assert_eq!(b.kind, "file");
}

#[test]
fn evidence_in_a_failing_group_is_not_treated() {
    // **판정 없이 지우지 않는다.** 판정이 서지 않은 그룹의 증거로 무언가를
    // 지우면 `verdict.require` 가 존재하는 이유가 사라진다.
    let s = scan(
        vec![ev("payload#0", "payload", Subject::File, r"C:\a\evil.exe")],
        vec![group("g0", &["payload#0"], false)],
    );
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "payload" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    assert!(d.actions.is_empty(), "판정 없이 계획됐다: {:?}", d.actions);
}

// ── 이동식 매체 (설계-03 §4, 설계-09 P7) ──────────────────

/// 이동식 루트 하나를 실은 스냅샷.
fn scan_on_removable(paths: &[&str], removable: &[&str]) -> ScanEnvelope {
    let ev: Vec<Evidence> = paths
        .iter()
        .enumerate()
        .map(|(i, p)| ev(&format!("payload#{i}"), "payload", Subject::File, p))
        .collect();
    let ids: Vec<String> = ev.iter().map(|e| e.id.clone()).collect();
    let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
    let mut s = scan(ev, vec![group("g0", &refs, true)]);
    s.body.removable_roots = removable.iter().map(|r| r.to_string()).collect();
    s
}

#[test]
fn an_unattended_run_does_not_plan_destruction_on_removable_media() {
    // 꽂혀 있는 것이 감염된 USB 인지 사용자의 백업 디스크인지는 **눈앞에서
    // 보는 사람만** 안다. 무인 모드에는 그 사람이 없다.
    let s = scan_on_removable(&[r"E:\evil.exe"], &[r"E:\"]);
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "payload" }] }));
    let d = derive(&s, &m, Mode::Unattended, &Allowed::new());

    assert!(d.actions.is_empty(), "{:?}", d.actions);
    assert_eq!(d.deferred.len(), 1, "{:?}", d.deferred);
    assert!(
        d.deferred[0]
            .reason
            .contains(remedy_sdk::i18n::t("이동식", "removable")),
        "{:?}",
        d.deferred[0]
    );
    // **조용히 빠지지 않는다.** 이유가 없으면 계획이 치료의 전부인 것처럼
    // 읽힌다 (설계-03 §2).
    assert!(d.deferred[0].reason.contains("E:\\"), "{:?}", d.deferred[0]);
}

#[test]
fn an_interactive_run_plans_it_but_flags_the_medium() {
    // 사람이 있으면 물어볼 수 있다. 물어볼 거리가 계획에 실려야 한다.
    let s = scan_on_removable(&[r"E:\evil.exe"], &[r"E:\"]);
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "payload" }] }));
    let d = derive(&s, &m, Mode::Interactive, &Allowed::new());

    assert_eq!(d.actions.len(), 1, "{:?}", d.actions);
    assert!(d.deferred.is_empty(), "{:?}", d.deferred);
    let u = d.actions[0]
        .user_impact
        .as_ref()
        .expect("영향이 적혀야 한다");
    assert_eq!(u.kind, remedy_sdk::artifact::UserImpactKind::RemovableMedia);
    assert!(u.note.as_deref().unwrap_or("").contains("E:\\"), "{u:?}");
}

#[test]
fn a_fixed_disk_target_is_untouched_by_the_gate() {
    // 위 두 시험이 "무엇이든 막는다/표시한다" 로 통과하면 안 된다.
    let s = scan_on_removable(&[r"C:\a\evil.exe"], &[r"E:\"]);
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "payload" }] }));
    for mode in [Mode::Interactive, Mode::Unattended] {
        let d = derive(&s, &m, mode, &Allowed::new());
        assert_eq!(d.actions.len(), 1, "{mode:?}: {:?}", d.actions);
        assert!(d.actions[0].user_impact.is_none(), "{mode:?}");
        assert!(d.deferred.is_empty(), "{mode:?}: {:?}", d.deferred);
    }
}

#[test]
fn the_gate_keeps_sequence_numbers_dense() {
    // 무인 모드에서 빠질 Action 이 번호를 받아 두면 `seq` 가 듬성듬성해지고,
    // 그것이 곧 "계획에 없는 번호" 로 읽힌다.
    let s = scan_on_removable(&[r"E:\evil.exe", r"C:\a\evil.exe"], &[r"E:\"]);
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "payload" }] }));
    let d = derive(&s, &m, Mode::Unattended, &Allowed::new());
    assert_eq!(d.actions.len(), 1, "{:?}", d.actions);
    assert_eq!(d.actions[0].seq, 1);
}

#[test]
fn a_snapshot_without_removable_roots_gates_nothing() {
    // 판단의 근거는 **스냅샷에 적힌 루트**다. 계획 시점에 지금 꽂힌 매체를
    // 다시 물으면 같은 스냅샷이 같은 계획을 내지 않는다.
    let s = scan_on_removable(&[r"E:\evil.exe"], &[]);
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "payload" }] }));
    let d = derive(&s, &m, Mode::Unattended, &Allowed::new());
    assert_eq!(d.actions.len(), 1, "{:?}", d.actions);
}

#[test]
fn every_implemented_op_is_either_plannable_or_listed_with_a_reason() {
    // **"Op 을 구현했다" 와 "플러그인이 그것을 쓸 수 있다" 는 다르다.**
    // 둘을 구분하지 않으면 Phase 완료 보고가 절반만 참이 된다.
    let plannable = plannable_ops();
    let excused: std::collections::BTreeSet<Op> =
        NOT_PLANNABLE_YET.iter().map(|(o, _)| *o).collect();

    let orphans: Vec<&str> = Op::ALL
        .into_iter()
        .filter(|o| o.info().implemented_in <= remedy_sdk::IMPLEMENTED_THROUGH)
        .filter(|o| !plannable.contains(o) && !excused.contains(o))
        .map(|o| o.info().id)
        .collect();
    assert!(
        orphans.is_empty(),
        "구현했는데 계획기가 낼 수 없는 Op: {orphans:?}\n\
         길을 내거나, `NOT_PLANNABLE_YET` 에 이유와 함께 적을 것."
    );

    // 반대 방향. 해소된 것이 목록에 남아 있으면 그 문장이 거짓말이 된다.
    let stale: Vec<&str> = NOT_PLANNABLE_YET
        .iter()
        .filter(|(o, _)| plannable.contains(o))
        .map(|(o, _)| o.info().id)
        .collect();
    assert!(
        stale.is_empty(),
        "이제 계획될 수 있는데 아직 '못 한다' 고 적혀 있다: {stale:?}"
    );

    // 이유 없는 면제는 면제가 아니다.
    for (op, why) in NOT_PLANNABLE_YET {
        assert!(why.len() > 30, "{}: 이유가 너무 짧다", op.info().id);
    }

    // ── 두 목록이 섞이지 않는가 ──────────────────────────
    //
    // `PLANNED_BUT_GUARDED` 는 **도출은 되는데 가드가 막는** 자리다.
    // 도출조차 안 되는 것이 거기 들어가면 위 `orphans` 검사가 그것을
    // 놓치고, 반대로 여기 것이 저기 들어가면 `stale` 이 거짓으로 깨진다.
    for (op, why) in PLANNED_BUT_GUARDED {
        assert!(why.len() > 30, "{}: 이유가 너무 짧다", op.info().id);
        assert!(
            plannable.contains(&op),
            "{}: 도출조차 되지 않는다면 NOT_PLANNABLE_YET 이 맞는 자리다",
            op.info().id
        );
        assert!(
            !excused.contains(&op),
            "{}: 두 목록에 함께 있다. 어느 쪽에서 막히는지 하나로 정할 것",
            op.info().id
        );
    }
}

#[test]
fn every_op_a_platform_performs_can_be_reached_there() {
    // **두 축이 어긋나면 Op 표가 도달할 수 없는 것을 약속한다.**
    //
    // `SubjectInfo::linux_from` 은 수집하는가를, `OpInfo::linux_from` 은
    // 수행하는가를 말한다. 실측에서 열 개가 어긋나 있었다 — `service.*` 넷은
    // systemd 를 읽지도 못하면서 "Linux 는 P12 부터" 라고 적혀 있었다.
    //
    // 이 시험이 그 짝을 기계가 지키게 한다. 순서 9 에서 `service` 수집기를
    // 만들면 **여기가 먼저 깨지며 Op 도 올리라고 말한다.**
    let excused: std::collections::BTreeSet<Op> =
        NOT_PLANNABLE_YET.iter().map(|(o, _)| *o).collect();

    for platform in [Platform::Windows, Platform::Linux] {
        let reachable = plannable_ops_on(platform);
        let orphans: Vec<&str> = Op::ALL
            .into_iter()
            .filter(|o| match platform {
                Platform::Windows => true,
                _ => o.info().linux_from.is_some(),
            })
            .filter(|o| !reachable.contains(o) && !excused.contains(o))
            .map(|o| o.info().id)
            .collect();
        assert!(
            orphans.is_empty(),
            "{}: 수행한다고 적혀 있는데 그 Op 을 유발할 subject 를 이 플랫폼에서 \
             수집하지 않는다: {orphans:?}\n\
             subject 수집기를 만들거나, 그 Op 의 linux_from 을 None 으로 내릴 것 \
             (설계-09 P12).",
            platform.id()
        );
    }
}

#[test]
fn a_subject_we_collect_can_actually_be_cleaned_there() {
    // 반대 방향. 수집만 하고 아무것도 못 하면 그 subject 를 쓴 룰은 판정만
    // 내고 치료가 통째로 미룸이 된다 — **"치료 전용 백신" 이 치료를 못 한다.**
    //
    // 미룸 자체는 옳은 동작이지만(설계-09 P12 결정 1), 그것이 **영구 상태**면
    // 카탈로그가 그렇게 말해야 한다. `indicator` 는 파생 지표라 제거 Op 이
    // 파일 계열과 같고, 그래서 여기 걸리지 않는다.
    for x in Subject::ALL {
        if x.info().linux_from.is_none() {
            continue;
        }
        let ops = removal_ops(x);
        // **빈 목록은 실수가 아니라 선언이다** (C-2 · `package`).
        //
        // 이 시험이 막는 증상은 *"판정만 내고 치료가 통째로 미룸"* 인데, 빈
        // 목록에서는 **미룰 것조차 없다** — `split_removal` 이 고른 것도 미룬
        // 것도 없이 돌아온다. 그 증상이 생기지 않으므로 여기 걸릴 자리가
        // 아니다. 치료가 **영원히 없는** subject 가 그 모양이고, 패키지를
        // 지우거나 올리는 것은 공급사의 일이다(설계-00 §3).
        //
        // 실수로 빈 것과 가르려고 **누가 비어 있는지를 못박는다** — 새
        // subject 를 Op 없이 더하면 여기서 멈추고, 그때 "영원히 없는가" 를
        // 사람이 한 번 답해야 한다.
        //
        // `unix_socket`(코어 1.2.0)도 그렇다 — 소켓을 닫는 것은 치료가 아니고 그
        // 소켓을 연 프로세스가 다시 연다(설계-01 D11 근거 1 · 카탈로그의 그 항목).
        //
        // `archive_entry`(코어 1.11.0)도 그렇다 — jar 를 고치는 것은 치료가 아니다. 클래스를 빼면 서명 ·
        // 무결성을 보는 앱이 멈추고, 어느 판으로 올릴지는 그 앱을 만든 쪽의 일이다(설계-02 §3 의 덧붙임).
        if ops.ops().is_empty() {
            assert!(
                matches!(
                    x,
                    Subject::Package | Subject::UnixSocket | Subject::ArchiveEntry
                ),
                "'{}' 의 제거 Op 이 비어 있다. 치료가 영원히 없는 subject 라면 \
                 이 시험에 이름을 적고 그 이유를 카탈로그에 적을 것",
                x.info().id
            );
            continue;
        }
        let any = ops.ops().iter().any(|o| o.info().linux_from.is_some());
        assert!(
            any,
            "'{}' 를 Linux 에서 수집하는데 제거 Op 이 하나도 Linux 에서 \
             수행되지 않는다: {:?}",
            x.info().id,
            ops.ops().iter().map(|o| o.info().id).collect::<Vec<_>>()
        );
    }
}

#[test]
fn an_unattended_run_does_not_remove_certificates() {
    // 신뢰 루트를 잘못 지우면 그 기계의 TLS 검사가 통째로 깨진다 —
    // 기업 내부 CA 가 그 자리에 있는 것이 정상인 환경이 흔하다 (설계-09 P8).
    //
    // **게이트를 거치지 않고 문을 직접 잰다.** `cert_store.remove` 는 P8 이고
    // 이 코어의 게이트는 P7 이라, `derive` 를 통과시키면 그 앞의
    // "아직 없는 Op" 미룸에 먼저 걸린다. 게이트가 올라가는 날 이 문이
    // 준비돼 있어야 하고, 준비됐는지는 지금 잴 수 있다.
    let target = r"HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\DEADBEEF";
    let s = scan(Vec::new(), Vec::new());
    let make = || Derived {
        actions: vec![action(
            Op::CertStoreRemove,
            Some(target.into()),
            vec!["e#0".into()],
        )],
        deferred: Vec::new(),
    };

    let mut d = make();
    gate_needs_a_human(&mut d, &s, Mode::Unattended);
    assert!(d.actions.is_empty(), "{:?}", d.actions);
    assert_eq!(d.deferred.len(), 1, "{:?}", d.deferred);
    assert!(
        d.deferred[0]
            .reason
            .contains(remedy_sdk::i18n::t("신뢰 루트", "trust root")),
        "{:?}",
        d.deferred[0]
    );

    // 대화형에서는 계획하되 무엇이 깨질 수 있는지 사람에게 보인다.
    let mut d = make();
    gate_needs_a_human(&mut d, &s, Mode::Interactive);
    assert_eq!(d.actions.len(), 1, "{:?}", d.actions);
    assert!(
        d.actions[0].user_impact.is_some(),
        "무엇이 깨질 수 있는지 적히지 않았다"
    );
    assert!(d.deferred.is_empty());
}

#[test]
fn a_service_target_is_its_definition_key() {
    // 이름만 적으면 보호 목록 대조도 G6 의 상한 판정도 걸리지 않는다 —
    // 둘 다 대상의 모양을 보고 갈린다.
    //
    // **`id` 와 `name` 을 다르게 둔다.** 둘을 같은 값으로 두면 이 시험은
    // 어느 쪽을 쓰든 통과하고, 실제로 그 상태에서 `name` 을 쓰는 버그가
    // 살아남았다 — 실기기에서 계획 여덟 건이 통째로 수행되지 않았다
    // (2026-09-05). 검체는 둘을 일부러 다르게 둔다.
    let e = ev_raw(
        Subject::Service,
        serde_json::json!({
            "id": "EvilSvc", "name": "친절한 도우미", "state": "unknown",
            "start_type": "auto", "image_path": "C:\\a\\evil.exe"
        }),
    );
    assert_eq!(
        target_of(&e, Platform::Windows).as_deref(),
        Some("HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc"),
        "표시 이름으로 조립하면 그 레지스트리 키는 존재하지 않는다"
    );
}

#[test]
fn 게이트_밖에_남은_것이_없다() {
    // **이 시험은 원래 "빠진 조각마다 이름이 남는다" 를 쟀다.**
    // `split_removal` 이 차례에서 미구현 Op 을 만나면 그것을 버리지 않고
    // `missing` 으로 넘기는지, 택일에서는 고르지 못한 것을 미룸으로 세지
    // 않는지 — 조용히 빠지면 계획이 치료의 전부인 것처럼 읽히기 때문이다
    // (설계-03 §2).
    //
    // 그것을 재려면 **게이트 밖 Op 이 하나는 있어야 한다.** 시험은 그 자리를
    // 예약 작업 → 서비스 → `dir.delete_recursive` 로 옮겨 다녔고,
    // 2026-08-25 (P10-C) 에 마지막 하나가 열리며 재현할 대상이 사라졌다.
    //
    // **`split_removal` 의 미룸 경로가 죽은 것은 아니다** — 새 Op 을
    // 정의하면 그 순간 다시 산다. 그때 이 시험을 되살릴 수 있게 무엇을
    // 재던 것인지 위에 남겨 두고, 여기서는 사실만 못 박는다.
    let outside: Vec<&str> = Op::ALL
        .iter()
        .filter(|o| !available(**o, Platform::Windows))
        .map(|o| o.id())
        .collect();
    assert!(
        outside.is_empty(),
        "게이트 밖 Op 이 생겼다: {outside:?} — 위 주석대로 이 시험을 \
         미룸 경로 시험으로 되살릴 것"
    );
}

#[test]
fn removing_a_service_plans_the_whole_sequence_in_order() {
    // **하나만 해서는 서비스가 사라지지 않는다.** 설계-03 §2 가 고정한
    // 차례는 `복구 동작 제거 → 정지 → 비활성화 → 삭제` 이고, 계획기가
    // 그것을 내지 못하면 VM 하네스가 실증한 "순서를 지키면 SCM 을 이긴다"
    // 가 **실제 계획으로는 도달할 수 없는 성질**이 된다 (설계-09 P8).
    //
    // 게이트를 P8 로 올리기 전에는 이 자리가
    // `[ServiceDisable, ServiceDelete]` 택일이었고, 계획기는 언제나
    // 비활성화 하나만 냈다.
    // **수집기가 내는 모양 그대로 쓴다.** `ev()` 는 `path` 만 넣는데
    // 서비스의 대상은 정의 키라 `name` 에서 만들어진다 — `path` 짜리
    // 증거로는 `target_of` 가 비고, 그러면 Action 이 하나도 안 나오면서
    // 시험이 "차례가 나온다" 를 재지 못한다.
    let mut svc = ev_raw(
        Subject::Service,
        serde_json::json!({
            "id": "EvilSvc", "name": "EvilSvc", "state": "running",
            "start_type": "auto", "image_path": r"C:\a\evil.exe"
        }),
    );
    svc.id = "svc#0".into();
    svc.rule = "svc".into();
    let s = scan(vec![svc], vec![group("g0", &["svc#0"], true)]);
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "svc" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert!(d.deferred.is_empty(), "{:?}", d.deferred);
    let ops: Vec<Op> = d.actions.iter().map(|a| a.op).collect();
    assert_eq!(
        ops,
        vec![
            Op::ServiceClearRecovery,
            Op::ServiceStop,
            Op::ServiceDisable,
            Op::ServiceDelete,
        ],
        "설계-03 §2 의 차례가 아니다"
    );
    // 복구 동작 제거가 종료보다 앞이라는 것이 이 차례의 핵심이다.
    assert!(stage(Op::ServiceClearRecovery) < stage(Op::ProcessKill));
    assert!(
        stage(Op::ServiceStop) < stage(Op::ProcessKill),
        "정지가 종료보다 뒤다"
    );
    // 대상은 넷 다 같은 정의 키다.
    assert!(d
        .actions
        .iter()
        .all(|a| a.target.as_deref() == Some(r"HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc")));
}

/// 리눅스 서비스 증거 하나와 그 실행 파일로 도는 프로세스. **수집기가 내는 모양
/// 그대로다** — `id` 가 유닛 파일 경로이고 계획의 대상이 된다.
fn linux_service_scan(unit: &str) -> ScanEnvelope {
    let mut svc = ev_raw(
        Subject::Service,
        serde_json::json!({
            "id": unit, "name": unit.rsplit('/').next().unwrap(), "state": "unknown",
            "start_type": "enabled", "image_path": "/opt/a/evil"
        }),
    );
    svc.id = "svc#0".into();
    svc.rule = "svc".into();
    let mut p = process_evidence();
    p.target["image_path"] = serde_json::json!("/opt/a/evil");
    let mut s = scan(vec![svc, p], vec![group("g0", &["svc#0", "proc#0"], true)]);
    s.host.os = "linux".into();
    s
}

#[test]
fn a_linux_system_unit_is_stopped_before_its_process_is_killed() {
    // **systemd 는 죽은 주 프로세스를 메모리의 정의로 되살린다** (`Restart=`).
    // 정지를 먼저 걸면 스스로 멈춘 것은 되살리지 않는다 — 랩 VM 에서 정지 요청
    // 직후의 SIGKILL 10번이 한 번도 되살아나지 않았다 (설계-09 P12 결정 A,
    // 2026-09-29). 그래서 리눅스도 Windows 와 같은 차례다: 정지 → 종료.
    let s = linux_service_scan("/etc/systemd/system/evil.service");
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "svc" }, { "ref": "proc" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    let ops: Vec<Op> = d.actions.iter().map(|a| a.op).collect();
    assert_eq!(
        ops,
        vec![
            Op::ServiceStop,
            Op::ProcessKill,
            Op::ServiceDisable,
            Op::ServiceDelete
        ],
        "정지가 종료보다 앞이 아니다"
    );
    let stop = &d.actions[0];
    assert_eq!(
        stop.target.as_deref(),
        Some("/etc/systemd/system/evil.service")
    );
    // 남는 미룸은 리눅스에 개념이 없는 하나뿐이다 — 정지가 먼저 돌면 필요도 없다.
    let deferred: Vec<Op> = d.deferred.iter().map(|x| x.op).collect();
    assert_eq!(deferred, vec![Op::ServiceClearRecovery], "{:?}", d.deferred);
}

#[test]
fn a_linux_user_unit_is_not_stopped_but_deferred() {
    // **사용자 유닛은 그 사용자의 관리자가 돌린다.** 멈추려면 그 사용자의 세션
    // 버스가 필요한데 root 로 도는 치료 도구에는 없다 (결정 5). 시스템 관리자에게
    // 같은 이름을 멈추라고 하면 **엉뚱한 유닛**이 멈추거나 "없다" 가 성공으로
    // 읽힌다 — 그래서 계획에 넣지 않고 미룬다. 끄고 지우는 것은 파일이라 된다.
    for unit in [
        "/home/u/.config/systemd/user/evil.service",
        "/etc/systemd/user/evil.service",
    ] {
        let s = linux_service_scan(unit);
        let m = manifest(serde_json::json!({ "remove": [{ "ref": "svc" }] }));
        let d = derive(&s, &m, Mode::default(), &Allowed::new());

        let ops: Vec<Op> = d.actions.iter().map(|a| a.op).collect();
        assert_eq!(ops, vec![Op::ServiceDisable, Op::ServiceDelete], "{unit}");
        let stop = d
            .deferred
            .iter()
            .find(|x| x.op == Op::ServiceStop)
            .unwrap_or_else(|| panic!("{unit}: 정지가 미룸에 없다 — {:?}", d.deferred));
        // 사유는 화면 언어를 따른다(`ko_en`). 어느 쪽이든 그 까닭을 말해야 한다.
        assert!(
            stop.reason.contains("세션 버스") || stop.reason.contains("session bus"),
            "{unit}: 왜 미뤘는지 말하지 않는다 — {stop:?}"
        );
    }
}

/// 수집기가 내는 모양 그대로의 프로세스 증거.
fn process_evidence() -> Evidence {
    let mut p = ev_raw(
        Subject::Process,
        serde_json::json!({
            "pid": 1234, "ppid": 8, "image_path": r"C:\a\evil.exe",
            "cmdline": r"C:\a\evil.exe --run", "cmdline_decoded": r"C:\a\evil.exe --run",
            "args": "--run", "user": "T\\u", "start_time": "2026-08-23T00:00:00Z",
            "modules": []
        }),
    );
    p.id = "proc#0".into();
    p.rule = "proc".into();
    p
}

#[test]
fn a_process_evidence_becomes_a_kill_with_a_predicate_and_no_target() {
    // **`process.kill` 이 어떤 계획에도 들어갈 수 없었다** (설계-09 P9
    // 준비 점검). 두 가지가 함께 빠져 있었다.
    //
    //   1 `ProcessRecord` 에는 `path`·`source`·`id` 가 없어 `target_of` 가
    //     `None` 을 주고, remove arm 이 그 자리에서 Action 을 버렸다.
    //   2 `locator` 에 프로세스 분기가 없어 술어가 실리지 않았고, 실리더라도
    //     G6 이 "무엇을 종료할지 계획이 말하지 않았습니다" 로 막았다.
    //
    // **대상이 비는 것이 정상이다** — PID 는 계획 시점과 실행 시점 사이에
    // 바뀌므로 계획에 들어갈 자리가 없고(설계-03 §1), G6 의 상한 검사도
    // `target` 이 없으면 건너뛴다. 프로세스에는 `scan_roots` 에 대응하는
    // 것이 없다.
    let s = scan(
        vec![process_evidence()],
        vec![group("g0", &["proc#0"], true)],
    );
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "proc" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert!(d.deferred.is_empty(), "{:?}", d.deferred);
    assert_eq!(d.actions.len(), 1, "{:?}", d.actions);
    let a = &d.actions[0];
    assert_eq!(a.op, Op::ProcessKill);
    assert_eq!(a.target, None, "프로세스에 대상이 실렸다");
    assert_eq!(
        a.r#match.as_ref().and_then(|m| m.get("image_path")),
        Some(&serde_json::json!(r"C:\a\evil.exe")),
        "술어가 이미지 경로를 짚지 않았다: {:?}",
        a.r#match
    );
}

#[test]
fn an_unattended_run_still_kills_the_process() {
    // **부작용을 붙이는 일이 미루는 일이 되면 안 된다.**
    //
    // 지금 `user_impact` 를 붙이는 유일한 자리(`gate_needs_a_human`)는
    // *"대화형이면 표시하고 무인이면 미룬다"* 다. 그 모양을 `ProcessKill` 에
    // 베끼면 무인 배포가 프로세스를 죽이지 않게 되고, 그러면 페이로드
    // 파일이 잠겨 치료가 통째로 실패한다. 여기는 **알리기만 하는** 자리다.
    let s = scan(
        vec![process_evidence()],
        vec![group("g0", &["proc#0"], true)],
    );
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "proc" }] }));
    for mode in [Mode::Interactive, Mode::Unattended] {
        let d = derive(&s, &m, mode, &Allowed::new());
        assert_eq!(d.actions.len(), 1, "{mode:?}: {:?}", d.actions);
        assert_eq!(d.actions[0].op, Op::ProcessKill, "{mode:?}");
        assert!(
            d.deferred.is_empty(),
            "{mode:?} 에서 프로세스 종료가 미뤄졌다: {:?}",
            d.deferred
        );
    }
}

#[test]
fn killing_a_process_says_which_program_stops() {
    // **승인 직전에 가장 듣고 싶은 말이다.** 이 줄이 없으면 사용자는 무엇이
    // 멈추는지 모른 채 승인한다 — SDK 와 리포트에 문장이 다 있는데 어느
    // 계획기도 붙이지 않고 있었다 (생산자 0건, 2026-09-08).
    let s = scan(
        vec![process_evidence()],
        vec![group("g0", &["proc#0"], true)],
    );
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "proc" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    let u = d.actions[0]
        .user_impact
        .as_ref()
        .expect("프로세스 종료에 부작용이 적히지 않았다");
    assert_eq!(u.kind, remedy_sdk::artifact::UserImpactKind::AppTerminate);
    // **경로가 아니라 이름이다.** 화면 한 줄에 전체 경로가 들어가면 읽히지 않고,
    // 무엇이 멈추는지는 이름이 답한다.
    assert_eq!(u.app.as_deref(), Some("evil.exe"), "{u:?}");
}

#[test]
fn a_file_pushed_to_reboot_says_the_cleanup_finishes_later() {
    // `RebootRequired` 가 맞는 유일한 자리다 — 정리가 재시작 뒤에 끝난다.
    // (`verify.after_reboot` 는 "한 번 더 검사한다" 라 뜻이 다르고 화면이
    // 계획의 값을 직접 읽는다.)
    // 그 파일을 **돌고 있는 프로세스가 잡고 있다** — `locked_by_a_process` 가
    // `image_path` 로 짝을 짓는다.
    let s = scan(
        vec![
            ev("file#0", "f", Subject::File, r"C:\a\evil.exe"),
            process_evidence(),
        ],
        vec![group("g0", &["file#0", "proc#0"], true)],
    );
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "f" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    let a = d
        .actions
        .iter()
        .find(|a| a.op == Op::FileDeleteOnReboot)
        .expect("잠긴 파일이 재부팅 삭제로 가지 않았다");
    let u = a.user_impact.as_ref().expect("부작용이 적히지 않았다");
    assert_eq!(u.kind, remedy_sdk::artifact::UserImpactKind::RebootRequired);
    // 영어 화면에 한글이 섞이지 않도록 `note` 는 비운다 — 하려던 말은
    // 기본 문장과 `op_effect` 가 두 언어로 한다.
    assert_eq!(u.note, None, "{u:?}");
}

#[test]
fn a_running_image_on_linux_is_quarantined_not_deferred() {
    // 위 시험의 리눅스판. 같은 모양의 증거가 리눅스 스냅숏에서는 평소의 격리로
    // 계획되고, 미룸에 `file.delete_on_reboot` 가 남지 않아야 한다 — 남으면
    // 화면이 "이 계획은 치료의 전부가 아닙니다" 를 말하고 실행 파일은 그대로 남는다.
    let mut p = process_evidence();
    p.target["image_path"] = serde_json::json!("/opt/a/evil");
    let mut s = scan(
        vec![ev("file#0", "f", Subject::File, "/opt/a/evil"), p],
        vec![group("g0", &["file#0", "proc#0"], true)],
    );
    s.host.os = "linux".into();
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "f" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert!(
        d.actions
            .iter()
            .any(|a| a.op == Op::FileQuarantineOnly && a.target.as_deref() == Some("/opt/a/evil")),
        "실행 파일이 격리로 계획되지 않았다: {:?}",
        d.actions
    );
    assert!(
        d.deferred.iter().all(|x| x.op != Op::FileDeleteOnReboot),
        "리눅스에 없는 재부팅 삭제로 미뤘다: {:?}",
        d.deferred
    );
}

#[test]
fn an_ordinary_action_invents_no_side_effect() {
    // 위 둘이 "무엇에나 붙인다" 로 통과하면 안 된다.
    let s = scan(
        vec![ev("file#0", "f", Subject::File, r"C:\a\evil.exe")],
        vec![group("g0", &["file#0"], true)],
    );
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "f" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    assert_eq!(d.actions.len(), 1, "{:?}", d.actions);
    assert_eq!(d.actions[0].op, Op::FileQuarantineOnly);
    assert!(d.actions[0].user_impact.is_none(), "{:?}", d.actions[0]);
}

#[test]
fn a_manifest_can_ask_for_the_process_lineage() {
    // **실행기와 SDK 필드만 있고 매니페스트가 요구할 길이 없었다** — P8 에서
    // 실행기 쪽만 만들었고, 그래서 `include_descendants` 는 어떤 계획에도
    // 들어갈 수 없었다 (설계-09 P9 준비 점검).
    //
    // 디렉터리의 `recursive: true` 와 같은 자리다: 둘 다 "이것이 거느린
    // 것까지" 를 뜻하고 둘 다 명시해야만 켜진다.
    // 위 시험과 **같은 증거**를 쓴다. 모양이 갈리면 한쪽만 진짜를 잰다.
    let s = scan(
        vec![process_evidence()],
        vec![group("g0", &["proc#0"], true)],
    );

    let on = derive(
        &s,
        &manifest(serde_json::json!({
            "remove": [{ "ref": "proc", "descendants": true }]
        })),
        Mode::default(),
        &Allowed::new(),
    );
    assert_eq!(on.actions.len(), 1, "{:?}", on.actions);
    assert_eq!(on.actions[0].op, Op::ProcessKill);
    assert_eq!(on.actions[0].include_descendants, Some(true));

    // **기본은 꺼짐이다.** 위 시험이 "언제나 켠다" 로 통과하면 안 된다.
    let off = derive(
        &s,
        &manifest(serde_json::json!({ "remove": [{ "ref": "proc" }] })),
        Mode::default(),
        &Allowed::new(),
    );
    assert_eq!(off.actions[0].include_descendants, None);
}

#[test]
fn removing_a_scheduled_task_plans_disable_then_delete() {
    // **서비스와 같은 이유다.** 비활성화만 하면 정의가 남고, 사용자는 작업
    // 스케줄러에서 꺼진 악성 작업을 본다 — "무엇이 남아 있으면 안 되는가"
    // 에 답하지 못한 것이다.
    //
    // 이 자리를 잰 시험이 없었다. `Persistence` 를 차례로 바꿔도 전체
    // 618 시험이 전부 초록이었고, 가이드 예제 ex01 은 `remediate` 가
    // 없어 `actions: []` 라 잡지 못한다 (설계-09 P9 준비 점검).
    let mut t = ev_raw(
        Subject::Persistence,
        serde_json::json!({
            "id": r"\Microsoft\Windows\Locust",
            "register_path": r"\Microsoft\Windows\Locust",
            "command": r"C:\Program Files\nodejs\node.exe"
        }),
    );
    t.id = "task#0".into();
    t.rule = "task".into();
    let s = scan(vec![t], vec![group("g0", &["task#0"], true)]);
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "task" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    assert!(d.deferred.is_empty(), "{:?}", d.deferred);
    let ops: Vec<Op> = d.actions.iter().map(|a| a.op).collect();
    assert_eq!(
        ops,
        vec![Op::PersistenceDisable, Op::PersistenceDelete],
        "{ops:?}"
    );
    // 비활성화(3단계)가 삭제(5단계, regenerator)보다 앞이다.
    assert!(stage(Op::PersistenceDisable) < stage(Op::PersistenceDelete));
}

#[test]
fn removing_a_file_plans_one_op_not_the_whole_list() {
    // 위 시험이 "언제나 목록을 전부 낸다" 로 통과하면 안 된다. 파일은
    // **격리하거나 지우거나** 하나이지 둘 다가 아니다.
    let s = scan(
        vec![ev("payload#0", "payload", Subject::File, r"C:\a\evil.exe")],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "payload" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    assert_eq!(d.actions.len(), 1, "{:?}", d.actions);
    assert_eq!(d.actions[0].op, Op::FileQuarantineOnly);
}

#[test]
fn edit_and_restore_are_planned_now_that_their_ops_exist() {
    // 원래 "편집·원복도 미룸으로 남는다" 였다. P7 이 그 두 arm 의 Op 을
    // 전부 들여왔으므로 이제 **계획된다.** 방향을 뒤집어 그대로 잰다 —
    // 지우면 두 arm 이 Action 을 만드는지 아무도 확인하지 않는다.
    //
    // 두 arm 의 미룸 분기는 지금 닿을 수 있는 Op 이 없다(편집은
    // `registry.strip_value` 하나뿐이고 이름 원복은 넷 다 P7 이다).
    // `remove` arm 이 같은 `available()`·`defer()` 를 쓰고 그쪽은 위
    // 시험이 잰다.
    let mut reg = ev_raw(
        Subject::RegistryValue,
        serde_json::json!({
            "hive": "HKLM",
            "key": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "name": "Shell"
        }),
    );
    reg.id = "reg#0".into();
    reg.rule = "payload".into();
    reg.captures.insert("x".into(), "evil.exe".to_string());

    let mut avx = ev_raw(
        Subject::AvExclusion,
        serde_json::json!({
            "kind": "path",
            "value": "C:\\a",
            "source": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
        }),
    );
    avx.id = "avx#0".into();
    avx.rule = "avx".into();

    // 편집할 값은 **판정 그룹의 capture** 에서 온다 — 리터럴로 임의 편집을
    // 지시할 수 없다 (설계-02 §6).
    let mut g = group("g0", &["reg#0", "avx#0"], true);
    g.captures.insert("payload.x".into(), "evil.exe".into());
    let s = scan(vec![reg, avx], vec![g]);
    let m = manifest(serde_json::json!({
        "edit": [{ "ref": "payload", "op": "strip", "value": "${payload.x}" }],
        "restore": ["av_exclusions"]
    }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    let ops: Vec<Op> = d.actions.iter().map(|a| a.op).collect();
    assert!(ops.contains(&Op::RegistryStripValue), "{ops:?}");
    assert!(ops.contains(&Op::AvRestoreExclusions), "{ops:?}");
    assert!(d.deferred.is_empty(), "{:?}", d.deferred);
}

#[test]
fn a_named_restore_carries_the_locator_its_op_needs() {
    // **`restore` 도 술어를 붙여야 한다.** `remove` 쪽만 붙이고 있었고,
    // 그래서 `restore: [hosts]` 는 계획까지 서고 G6 도 지나는데 `apply` 가
    // 백업 단계에서 통째로 멈췄다 — *"계획에 줄 번호가 없습니다"*.
    //
    // 2026-09-03 Linux 하네스가 찾았다. 시험은 계획만 보고 `apply` 를
    // 돌리지 않아 `tls-intercept` 정답 플러그인이 이 절을 쓰면서도
    // 통과했다. **양쪽 플랫폼에서 한 번도 동작한 적이 없었다.**
    let mut h = ev_raw(
        Subject::HostsEntry,
        serde_json::json!({
            "ip": "127.0.0.1",
            "hostnames": ["evil.example"],
            "line_no": 9,
            "source": "C:\\Windows\\System32\\drivers\\etc\\hosts"
        }),
    );
    h.id = "hosts#0".into();
    h.rule = "hosts".into();

    let s = scan(vec![h], vec![group("g0", &["hosts#0"], true)]);
    let m = manifest(serde_json::json!({ "restore": ["hosts"] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    let a = d
        .actions
        .iter()
        .find(|a| a.op == Op::HostsRestoreLine)
        .unwrap_or_else(|| panic!("hosts.restore_line 이 계획되지 않았다: {:?}", d.actions));
    assert_eq!(
        a.r#match.as_ref().and_then(|m| m.get("line_no")),
        Some(&serde_json::json!(9)),
        "줄 번호가 없다 — 실행기가 백업 단계에서 멈춘다: {:?}",
        a.r#match
    );
}

#[test]
fn every_restore_action_can_be_backed_up() {
    // 위 시험의 일반형. **담을 종류가 `TextLine` 하나뿐인 Op 은 줄 번호가
    // 없으면 백업이 불가능하고, 백업이 불가능하면 `apply` 가 통째로 멈춘다**
    // (`remedy-apply` 의 `capture_one`).
    //
    // 이름 원복 넷을 전부 태워 그 짝을 기계가 지키게 한다.
    for (name, subject, op) in remedy_sdk::catalog::RESTORE_NAMED {
        if op.info().implemented_in > remedy_sdk::catalog::Phase::P12 {
            continue;
        }
        let target = match subject {
            Subject::HostsEntry => serde_json::json!({
                "ip": "127.0.0.1", "hostnames": ["evil.example"],
                "line_no": 9, "source": "C:\\Windows\\System32\\drivers\\etc\\hosts"
            }),
            Subject::AvExclusion => serde_json::json!({
                "kind": "path", "value": "C:\\a",
                "source": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
            }),
            Subject::ProxyConfig => serde_json::json!({
                "scope": "user", "server": "127.0.0.1:8899", "enabled": true,
                "source": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
            }),
            Subject::FirewallRule => serde_json::json!({
                "name": "evil", "direction": "In", "action": "allow",
                "source": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
            }),
            _ => continue,
        };
        let mut e = ev_raw(subject, target);
        e.id = format!("{name}#0");
        e.rule = name.to_string();

        let s = scan(vec![e], vec![group("g0", &[&format!("{name}#0")], true)]);
        let m = manifest(serde_json::json!({ "restore": [name] }));
        let d = derive(&s, &m, Mode::default(), &Allowed::new());

        for a in d.actions.iter().filter(|a| a.op == op) {
            let kinds = op.backup_kinds();
            if kinds == [remedy_sdk::quarantine::EntryKind::TextLine] {
                assert!(
                    a.r#match.as_ref().and_then(|m| m.get("line_no")).is_some(),
                    "'{name}' 의 {} 가 줄 번호 없이 계획됐다 — 백업 단계에서 멈춘다",
                    op.info().id
                );
            }
        }
    }
}

#[test]
fn a_recursive_path_target_is_deferred_until_its_op_exists() {
    // dir.delete_recursive 는 **P10** 이다. 고위험이라서가 아니라, 이것을
    // 안전하게 만드는 서명 가드(설계-03 §4 조건 3)가 §3 2층에 속하고 그
    // 2층이 `remedy-trust` 와 함께 P10 에 오기 때문이다.
    let s = scan(
        vec![ev(
            "payload#0",
            "payload",
            Subject::File,
            r"C:\a\evil\x.exe",
        )],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = manifest(serde_json::json!({
        "remove": [{ "path": "${payload.dir}", "recursive": true, "guard": "payload" }]
    }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    assert!(d.actions.is_empty());
    assert_eq!(d.deferred[0].op, Op::DirDeleteRecursive);
    assert_eq!(d.deferred[0].arrives_in, "P10");
}

#[test]
fn a_guard_that_caught_nothing_defers_instead_of_breaking_the_whole_plan() {
    // **판정이 guard 를 필수로 두지 않으면 이 자리가 열린다.**
    //
    // `A and (B or C)` 에 `guard: B` 를 걸고 B 가 이미 없는 기계가 그것이다.
    // 그런 판정은 다른 백신이 페이로드만 잡아간 기계를 구하려고 일부러
    // 여는 것인데, 그 기계에서 근거 없는 Action 이 만들어져 G6·G7 에 걸리고
    // **계획이 통째로 거부됐다**(종료 코드 5). 느슨한 판정이 구하려던 바로
    // 그 기계가 아무것도 치료받지 못하는 기계가 됐다.
    //
    // 2026-09-04 회차가 그 모양을 냈고 응시자는 가이드를 그대로 따랐다.
    //
    // 미룸이 옳다 — guard 를 optional evidence 에 거는 것은 *"그 안에서
    // 실제로 뭔가 찾았을 때만 폴더째 지운다"* 는 뜻이고, 미룸이 그것을
    // 그대로 수행한다. 그리고 나머지 Action 은 살아서 기계가 치료된다.
    let s = scan(
        // `runkey` 만 잡혔다. guard 가 가리키는 `payload` 는 0건이다.
        vec![ev(
            "runkey#0",
            "runkey",
            Subject::RegistryValue,
            r"HKCU\Software\X",
        )],
        vec![group("g0", &["runkey#0"], true)],
    );
    let m = manifest(serde_json::json!({
        "remove": [
            { "ref": "runkey" },
            { "path": "${runkey.dir}", "recursive": true, "guard": "payload" }
        ]
    }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());

    // **근거 없는 Action 이 하나도 나가지 않는다.** 나가면 G7 이 문다.
    for a in &d.actions {
        assert!(
            !a.because.is_empty(),
            "because 가 빈 Action 이 나갔다: {:?}",
            a.op
        );
    }
    assert!(
        !d.actions.iter().any(|a| a.op == Op::DirDeleteRecursive),
        "근거 없는 재귀 삭제가 계획에 들어갔다"
    );
    assert!(
        d.deferred.iter().any(|x| x.op == Op::DirDeleteRecursive),
        "미룸에도 없다 — 조용히 사라지면 작성자가 알 수 없다: {:?}",
        d.deferred
    );
    // **나머지는 살아 있어야 한다.** 이것이 이 고침의 요점이다.
    assert!(
        !d.actions.is_empty(),
        "재귀 삭제 하나 때문에 계획이 통째로 비었다"
    );
}

#[test]
fn a_guard_with_evidence_still_plans_the_recursive_delete() {
    // 반대 방향. 미루는 쪽만 재면 "언제나 미룬다" 로 고쳐도 통과한다.
    let s = scan(
        vec![ev(
            "payload#0",
            "payload",
            Subject::File,
            r"C:\a\evil\x.exe",
        )],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = manifest(serde_json::json!({
        "remove": [{ "path": "${payload.dir}", "recursive": true, "guard": "payload" }]
    }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    let all: Vec<Op> = d
        .actions
        .iter()
        .map(|a| a.op)
        .chain(d.deferred.iter().map(|x| x.op))
        .collect();
    assert!(
        all.contains(&Op::DirDeleteRecursive),
        "근거가 있는데도 사라졌다: {all:?}"
    );
}

#[test]
fn an_unresolved_capture_defers_instead_of_guessing() {
    // 반쯤 채운 경로는 **엉뚱한 곳을 가리킨다.** 지우는 것보다 아무것도
    // 하지 않는 편이 낫다.
    let s = scan(
        vec![ev("payload#0", "payload", Subject::File, r"C:\a\evil.exe")],
        vec![group("g0", &["payload#0"], true)],
    );
    let m = manifest(serde_json::json!({
        "remove": [{ "path": "${payload.없는캡처}\\x" }]
    }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    assert!(d.actions.is_empty());
    assert!(d.deferred[0].reason.contains("capture"), "{:?}", d.deferred);
}

/// 판정식이 갈래를 둘 때 **서지 않은 갈래의 경로 삭제는 미루지 않는다** — 그 갈래에는
/// 지울 것이 없다(EvilAI 0.2.0 · 2026-11-08 랩에서 보도 꼴 치료마다 미룸 두 줄이 떴다).
/// 선 갈래의 경로는 그대로 계획된다.
#[test]
fn a_path_of_a_branch_that_did_not_stand_is_skipped_not_deferred() {
    let mut g = group("g0", &["task#0", "payload#0"], true);
    g.captures.insert(
        "task.payload_dir".into(),
        r"C:\Users\u\AppData\Local\Programs\x".into(),
    );
    let s = scan(
        vec![
            ev("task#0", "task", Subject::Persistence, r"\Locust"),
            ev(
                "payload#0",
                "payload",
                Subject::File,
                r"C:\Users\u\AppData\Local\Programs\x\a.js",
            ),
        ],
        vec![g],
    );
    let m = manifest(serde_json::json!({
        "remove": [
            { "path": "${task.payload_dir}", "recursive": true, "guard": "payload" },
            { "path": "${task-x.payload_dir}", "recursive": true, "guard": "payload-x" }
        ]
    }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    assert!(
        d.deferred.is_empty(),
        "서지 않은 갈래가 미룸으로 나갔다: {:?}",
        d.deferred
    );
    assert_eq!(d.actions.len(), 1, "{:?}", d.actions);
    assert_eq!(d.actions[0].op, Op::DirDeleteRecursive);
}

#[test]
fn actions_are_ordered_by_stage_and_renumbered() {
    // 순서는 코어가 정한다 (설계-03 §2). 유발자가 산출물보다 먼저다.
    assert!(stage(Op::ServiceClearRecovery) < stage(Op::ProcessKill));
    assert!(stage(Op::ProcessKill) < stage(Op::PersistenceDisable));
    assert!(stage(Op::PersistenceDelete) < stage(Op::FileQuarantineOnly));
    assert!(stage(Op::FileQuarantineOnly) < stage(Op::AvRestoreExclusions));

    let s = scan(
        vec![
            ev("payload#0", "payload", Subject::File, r"C:\a\one.exe"),
            ev("payload#1", "payload", Subject::File, r"C:\a\two.exe"),
        ],
        vec![group("g0", &["payload#0", "payload#1"], true)],
    );
    let m = manifest(serde_json::json!({ "remove": [{ "ref": "payload" }] }));
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    assert_eq!(d.actions.len(), 2);
    // seq 는 1부터 빈틈없이 매겨진다 — 감사 로그가 이것으로 Action 을 가리킨다.
    assert_eq!(d.actions[0].seq, 1);
    assert_eq!(d.actions[1].seq, 2);
}

#[test]
fn every_op_has_a_stage() {
    // 새 Op 이 늘면 여기서 컴파일이 막힌다(match 가 exhaustive). 그래도
    // 단계가 겹치거나 빠지지 않는지는 값으로 확인한다.
    for op in Op::ALL {
        let s = stage(op);
        assert!((1..=7).contains(&s), "{} 의 단계가 {s}", op.info().id);
    }
}

#[test]
fn a_manifest_without_remediate_plans_nothing() {
    let s = scan(
        vec![ev("payload#0", "payload", Subject::File, r"C:\a\evil.exe")],
        vec![group("g0", &["payload#0"], true)],
    );
    let mut m = manifest(serde_json::json!({}));
    m.remediate = None;
    let d = derive(&s, &m, Mode::default(), &Allowed::new());
    assert!(d.actions.is_empty());
    assert!(d.deferred.is_empty());
}
