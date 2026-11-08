//! 스냅샷 포맷 왕복 — 이 포맷이 흔들리면 그 위의 전부가 흔들린다 (설계-03 §1).

use remedy_artifacts::*;
use remedy_sdk::artifact::{ArtifactKind, ArtifactsEnvelope, CoreInfo, HostInfo, SecurityProduct};
use remedy_sdk::catalog::{Platform, Subject};

fn host() -> HostInfo {
    HostInfo {
        hostname: "TESTVM".into(),
        os: "windows".into(),
        version: "10.0.19045".into(),
        arch: "amd64".into(),
    }
}

fn core() -> CoreInfo {
    CoreInfo {
        version: "0.0.0".into(),
        build: "dev".into(),
    }
}

fn sample_file() -> FileRecord {
    FileRecord {
        path: "c:\\users\\test\\appdata\\local\\programs\\app-1\\main.js".into(),
        size: 1234,
        mtime: "2026-08-20T10:50:00Z".into(),
        ctime: None,
        sha256: Some("a".repeat(64)),
        signature: None,
        version: None,
        zone: None,
        streams: Vec::new(),
        content_ref: None,
    }
}

fn sample_task() -> PersistenceRecord {
    PersistenceRecord {
        id: "\\Microsoft\\Windows\\Locust".into(),
        name: "Locust".into(),
        enabled: true,
        trigger: vec!["logon".into()],
        command: "c:\\program files\\nodejs\\node.exe".into(),
        args: "\"C:\\...\\main.js\"".into(),
        principal: Some("SYSTEM".into()),
        source: "c:\\windows\\system32\\tasks\\microsoft\\windows\\locust".into(),
        // **실물이 아니라 필드 표본이다.** 실제 레코드는 예약 작업이거나 cron
        // 줄이지 둘 다일 수 없다. 여기서 둘을 함께 채우는 이유는 아래
        // `the_sdk_field_catalog_matches_the_real_records` 가 이 표본에서 필드
        // 전수를 뽑기 때문이다 — 한쪽만 채우면 나머지 네임스페이스는 아무도
        // 대조하지 않는다.
        linux: Some(record::LinuxPersistence {
            cron: Some(record::CronLine {
                line_no: 7,
                line: "@reboot /home/a/.cache/upd.sh".into(),
            }),
        }),
        win: Some(WinTask {
            task: record::WinTaskFields {
                register_path: "\\Microsoft\\Windows\\".into(),
                actions: vec!["exec".into()],
                run_level: Some("HighestAvailable".into()),
                working_directory: None,
                command_expanded: None,
                args_expanded: None,
            },
        }),
    }
}

fn scope() -> Scope {
    Scope::diagnostic(
        vec!["c:\\users\\test\\appdata\\local\\programs".into()],
        Platform::Windows,
    )
}

/// 수집기가 **돌았고** 선언된 subject 마다 결과를 담은 상태. 여기서는 전부 빈 목록이다.
///
/// 빈 목록조차 담지 않으면 그 subject 는 "보지 않았다"(`uncollected_subjects`)가
/// 되어 관측이 불완전해진다. 찾아봤는데 없는 것과 아예 보지 않은 것을 가르는
/// 것이 `Observations` 가 subject 키 맵인 이유다.
fn ran(sc: &Scope) -> Observations {
    let mut o = Observations::default();
    for s in &sc.subjects {
        o.put::<serde_json::Value>(*s, &[]);
    }
    o
}

#[test]
fn a_declared_subject_with_no_entry_is_unseen_not_empty() {
    // 이 구분이 무너지면 수집기가 통째로 실패한 실행이 "위협 없음" 으로 읽힌다.
    let s = scope();
    let env = assemble(
        "r".into(),
        "t".into(),
        host(),
        core(),
        &s,
        Observations::default(),
    );
    let o = env.body.observation();
    assert_eq!(o.uncollected_subjects.len(), s.subjects.len());
    assert!(
        !o.is_complete(),
        "보지 않은 subject 가 있는데 완전하다고 나왔다"
    );

    // 빈 목록을 담으면 "찾아봤는데 없었다" 다.
    let env = assemble("r".into(), "t".into(), host(), core(), &s, ran(&s));
    let o = env.body.observation();
    assert!(o.uncollected_subjects.is_empty());
    assert!(o.is_complete());
}

#[test]
fn envelope_round_trips_with_observations() {
    // 봉투와 본문이 둘 다 flatten 을 쓴다. 중첩 flatten 은 조용히 어긋날 수 있어
    // 실제 관찰을 담은 상태로 왕복시켜 확인한다.
    let mut obs = Observations {
        security_products: vec![SecurityProduct {
            vendor: "ALYac".into(),
            realtime: Some(true),
        }],
        truncated: false,
        denied_dirs: 0,
        missing_roots: Vec::new(),
        ..Default::default()
    };
    obs.put(Subject::File, &[sample_file()]);
    obs.put(Subject::Persistence, &[sample_task()]);
    let env = assemble(
        "01J000000000000000000000".into(),
        "2026-08-20T10:50:00Z".into(),
        host(),
        core(),
        &scope(),
        obs,
    );

    let json = serde_json::to_string_pretty(&env).expect("직렬화");
    // 설계-02 §8 은 subject 배열을 본문 최상위에 둔다.
    assert!(json.contains("\"file\""), "file 배열이 최상위여야 한다");
    assert!(json.contains("\"persistence\""));
    assert!(json.contains("\"collected_at\""));
    assert!(json.contains("\"security_products\""));

    let back: ArtifactsEnvelope = serde_json::from_str(&json).expect("역직렬화");
    assert_eq!(back.kind, ArtifactKind::Artifacts);
    assert_eq!(back.body.collector.bitness, collector_info().bitness);
    assert_eq!(files_of(&back), vec![sample_file()]);
    assert_eq!(persistence_of(&back), vec![sample_task()]);
    assert_eq!(back.body.security_products.len(), 1);
    assert!(!back.body.scope.truncated);
}

#[test]
fn undeclared_subject_is_not_emitted() {
    // 선언하지 않은 subject 가 스냅샷에 담기면 "선언한 것만 본다" 가 무너진다.
    let mut s = scope();
    s.subjects = vec![Subject::File];
    let mut obs = Observations::default();
    obs.put(Subject::File, &[sample_file()]);
    obs.put(Subject::Persistence, &[sample_task()]);
    let env = assemble("r".into(), "t".into(), host(), core(), &s, obs);
    assert!(env.body.observations.contains_key("file"));
    assert!(
        !env.body.observations.contains_key("persistence"),
        "선언하지 않은 subject 는 담기면 안 된다"
    );
}

#[test]
fn truncation_is_carried_into_the_snapshot() {
    // 잘린 스냅샷으로 "위협 없음" 을 결론지으면 안 된다.
    let mut obs = ran(&scope());
    obs.truncated = true;
    let env = assemble("r".into(), "t".into(), host(), core(), &scope(), obs);
    assert!(env.body.scope.truncated);
}

#[test]
fn assemble_is_deterministic() {
    // 같은 입력이면 바이트까지 같아야 한다. 시계를 안에서 읽으면 이것이 깨진다.
    let mk = || {
        assemble(
            "01J000000000000000000000".into(),
            "2026-08-20T10:50:00Z".into(),
            host(),
            core(),
            &scope(),
            {
                let mut o = Observations::default();
                o.put(Subject::File, &[sample_file()]);
                o.put(Subject::Persistence, &[sample_task()]);
                o
            },
        )
    };
    let a = serde_json::to_string(&mk()).unwrap();
    let b = serde_json::to_string(&mk()).unwrap();
    assert_eq!(a, b);
}

#[test]
fn no_subject_name_collides_with_a_reserved_body_key() {
    // observations 는 본문 최상위로 평탄화된다(설계-02 §8). subject 이름이
    // 봉투·본문의 고정 필드와 겹치면 직렬화가 **조용히** 그것을 덮어쓴다.
    // 오류도 경고도 없이 스냅샷만 망가지고, 그 위에서 "위협 없음" 이 결론난다.
    //
    // 이 테스트가 깨졌다면 새 subject 의 이름을 바꾸거나, observations 를
    // 중첩 객체로 옮기고 설계-02 §8 을 함께 고칠 것.
    use remedy_sdk::artifact::RESERVED_BODY_KEYS;
    let clashes: Vec<&str> = Subject::ALL
        .iter()
        .map(|s| s.id())
        .filter(|id| RESERVED_BODY_KEYS.contains(id))
        .collect();
    assert!(
        clashes.is_empty(),
        "subject 이름이 봉투 필드와 겹친다: {clashes:?}"
    );
}

#[test]
fn denied_directories_are_carried_into_the_snapshot() {
    // 못 본 것을 없는 것으로 읽으면 안 된다. 관리자 권한 없이 돌린 수집이
    // "예약 작업 없음" 으로 보고되면 그 위에서 "위협 없음" 이 결론난다.
    let mut obs = ran(&scope());
    obs.denied_dirs = 3;
    let env = assemble("r".into(), "t".into(), host(), core(), &scope(), obs);
    assert_eq!(env.body.scope.denied_dirs, 3);
}

/// **어느 자리였는지도 실려야 한다** (2026-09-14).
///
/// 개수만 있던 동안 `%ProgramFiles%` 의 `denied_dirs=2` 가 P2 를 미결로
/// 세웠는데, 회차가 끝난 뒤에는 그 폴더들이 전부 열려 원인에 닿지 못했다.
#[test]
fn denied_paths_ride_along_and_stay_a_sample() {
    use remedy_artifacts::{Harvest, DENIED_SAMPLE};

    // 걷기 하나가 거부를 만나면 개수와 경로가 함께 오른다.
    let mut h: Harvest<u8> = Harvest::default();
    h.deny("C:\\locked-a");
    h.absorb_denied(2, vec!["C:\\locked-b".into()]);
    assert_eq!(h.denied_dirs, 3, "개수는 전부 센다");
    assert_eq!(h.denied_paths, vec!["C:\\locked-a", "C:\\locked-b"]);

    // **표본이다.** 상한을 넘으면 경로는 멈추고 개수만 는다 — 그 차이가
    // "전수가 아니다" 라고 말한다.
    let mut big: Harvest<u8> = Harvest::default();
    for i in 0..(DENIED_SAMPLE + 10) {
        big.deny(format!("C:\\d{i}"));
    }
    assert_eq!(big.denied_dirs, DENIED_SAMPLE + 10);
    assert_eq!(big.denied_paths.len(), DENIED_SAMPLE);

    // 봉투까지 간다.
    let mut obs = ran(&scope());
    obs.absorb(&h);
    let env = assemble("r".into(), "t".into(), host(), core(), &scope(), obs);
    assert_eq!(env.body.scope.denied_dirs, 3);
    assert_eq!(env.body.scope.denied_paths.len(), 2);
    // `observation()` 이 도출할 때도 따라간다 — plan.json 만 받아 든 사람이
    // 같은 사실을 읽는다.
    assert_eq!(env.body.observation().denied_paths.len(), 2);
}
