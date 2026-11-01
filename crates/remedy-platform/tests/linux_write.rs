//! Linux 쓰기 백엔드의 **실기기 왕복** (설계-09 P12 순서 8, P7 → P8 게이트).
//!
//! # 왜 진짜 파일인가
//!
//! `g2_roundtrip.rs` 는 가짜 백엔드에 대고 **실행기와 복원기의 대칭**을 잰다.
//! 여기서 재는 것은 다르다 — **이 플랫폼의 백엔드가 실제로 하는가**이고, 그것은
//! 진짜 파일 시스템 위에서만 드러난다. 위임을 빠뜨린 메서드는 가짜 백엔드
//! 시험에서 영원히 안 보인다.
//!
//! # 무엇을 재는가
//!
//! Op 마다 셋을 함께 본다. `수행 전 == 복원 후` 만으로는 부족하다 —
//! **아무것도 하지 않은 Op 도 그 등식을 만족한다.**
//!
//! 1. 수행 후가 수행 전과 **다르다** (파괴가 실제로 일어났다)
//! 2. 복원 후가 수행 전과 **같다** (정확히 되돌아왔다)
//! 3. 카탈로그가 Linux 에서 수행한다고 적은 Op 은 **여기 사례가 있거나**
//!    `NOT_IMPLEMENTED_YET` 에 이유와 함께 적혀 있다

#![cfg(target_os = "linux")]

use remedy_platform::linux::{Live, NOT_IMPLEMENTED_YET};
use remedy_platform::write::{FileMeta, KillPredicate, LineAt, PlatformWrite};
use remedy_platform::PlatformError;
use remedy_sdk::catalog::Op;
use std::path::PathBuf;

fn lab(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("remedy-linux-write-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("실험 디렉터리");
    d
}

fn p(dir: &std::path::Path, name: &str) -> String {
    dir.join(name).to_string_lossy().to_string()
}

// ───────────────────────────────────────────── file.quarantine_only · file.delete

#[test]
fn a_file_survives_quarantine_and_comes_back() {
    // `file.quarantine_only` 와 `file.delete` 가 함께 쓰는 길이다 — 담고, 지우고,
    // 되돌린다. 담지 못하면 지우지 않는다 (설계-00 §5-2).
    let d = lab("file");
    let f = p(&d, "payload.js");
    std::fs::write(&f, b"evil()\n").expect("쓰기");
    let before = std::fs::read(&f).expect("읽기");

    let l = Live::new();
    let (content, meta) = l.quarantine_read(&f).expect("담기");
    assert_eq!(content, before, "담은 것이 원본과 다르다");

    l.destroy_file(&f).expect("지우기");
    assert!(!l.exists(&f), "지워지지 않았다");

    let report = l.restore_file(&f, &content, &meta).expect("되돌리기");
    assert_eq!(
        std::fs::read(&f).expect("읽기"),
        before,
        "원본과 다르게 돌아왔다"
    );
    assert!(
        report.restored.contains(&"content".to_string()),
        "{report:?}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn planning_a_restore_warns_before_overwriting() {
    // 설계-02 §9 는 되살릴 수 없는 것을 **실행 전에** 말하라고 한다. 그 자리에
    // 이미 파일이 있으면 복원은 덮어쓰기이고, 그 사실을 나중에 알리면 늦다.
    let d = lab("plan");
    let f = p(&d, "there.txt");
    std::fs::write(&f, b"x").expect("쓰기");

    let r = Live::new().plan_restore(&f, &FileMeta::default());
    // 기대값도 같은 언어로 짓는다 — 시험은 영어로 돈다(`i18n::current` 기본값).
    let want = remedy_sdk::i18n::t("기존 파일", "existing file");
    assert!(
        r.lost.iter().any(|x| x.item == want),
        "덮어쓴다는 사실을 말하지 않았다: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ───────────────────────────────────────── text_config.remove_line · hosts.restore_line

#[test]
fn a_config_line_goes_and_comes_back_in_place() {
    // 두 Op 이 실행기에서 같은 가지를 쓴다. **줄 번호만으로 고치지 않는다** —
    // 수집과 실행 사이에 파일이 바뀌면 그 번호가 다른 내용일 수 있다.
    let d = lab("line");
    let f = p(&d, "app.conf");
    let before = "[plugins]\nloader=/usr/lib/ok.so\nloader=/home/a/.local/evil.so\n";
    std::fs::write(&f, before).expect("쓰기");

    let l = Live::new();
    let line = l.text_line_read(&f, 3).expect("줄 읽기");
    assert!(line.contains("evil.so"), "{line}");

    // **들여쓴 줄도 제자리로 돌아와야 한다** (2026-10-27 · C-4 측정에서 드러났다).
    //
    // 담는 쪽(`nth_line`)이 양끝을 다듬고 있었다. 설정 파일에서는 모양만
    // 어긋나지만, C-5 가 소스 파일을 이 Op 의 사거리에 넣은 뒤로는 **되돌린
    // 소스가 원본과 다른 바이트**가 된다 — `.php` 실측에서 그렇게 나왔다.
    // 이 픽스처는 들여쓰기가 없어 그 자리를 한 번도 밟지 않았다.
    let g = p(&d, "indented.php");
    let src = "<?php\n$a = 1;\n    eval(base64_decode('eA=='));\nreturn $a;\n";
    std::fs::write(&g, src).expect("쓰기");
    let implant = l.text_line_read(&g, 3).expect("줄 읽기");
    assert_eq!(
        implant, "    eval(base64_decode('eA=='));",
        "들여쓰기를 잃었다 — 되돌릴 때 원본 바이트로 가지 못한다"
    );
    l.text_line_remove(&g, 3, &implant).expect("줄 제거");
    assert_eq!(
        std::fs::read_to_string(&g).expect("읽기"),
        "<?php\n$a = 1;\nreturn $a;\n",
        "심은 줄만 빠져야 한다"
    );
    l.text_line_restore(&g, 3, &implant).expect("줄 복원");
    assert_eq!(
        std::fs::read_to_string(&g).expect("읽기"),
        src,
        "되돌린 소스가 원본과 다른 바이트다"
    );

    l.text_line_remove(&f, 3, &line).expect("줄 제거");
    let after = std::fs::read_to_string(&f).expect("읽기");
    assert_ne!(after, before, "아무것도 지우지 않았다");
    assert!(!after.contains("evil.so"), "{after}");
    assert!(after.contains("ok.so"), "정상 줄까지 지웠다: {after}");

    l.text_line_restore(&f, 3, &line).expect("줄 복원");
    assert_eq!(std::fs::read_to_string(&f).expect("읽기"), before);

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_line_whose_content_changed_is_not_removed() {
    // **내용 대조가 실제로 무는가.** 이것이 없으면 위 시험은 줄 번호만으로
    // 지우는 구현에서도 통과한다.
    let d = lab("mismatch");
    let f = p(&d, "app.conf");
    std::fs::write(&f, "a\nb\nc\n").expect("쓰기");

    let e = Live::new()
        .text_line_remove(&f, 2, "전혀 다른 내용")
        .expect_err("막아야 한다");
    assert_eq!(
        std::fs::read_to_string(&f).expect("읽기"),
        "a\nb\nc\n",
        "{e}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

// ───────────────────────────────────────────── structured_config.remove_key

#[test]
fn a_json_key_goes_and_the_file_comes_back() {
    // **되돌리기는 키를 다시 쓰는 것이 아니라 파일을 되살리는 것이다.**
    // `structured_set_key` 는 없는 키를 만들지 않는다 — 서명된 도구가 임의
    // 키를 새로 쓸 수 있으면 그 자체가 공격 도구다 (설계-03 §2). 그래서 이
    // Op 의 백업은 **파일 전체**이고, G2 의 왕복 사례도 그 모양이다.
    let d = lab("json");
    let f = p(&d, "prefs.json");
    let before = br#"{"a":{"b":"evil"},"c":1}"#;
    std::fs::write(&f, before).expect("쓰기");

    let l = Live::new();
    let (backup, meta) = l.quarantine_read(&f).expect("담기");

    l.structured_remove_key(&f, "a.b").expect("키 제거");
    let after = std::fs::read_to_string(&f).expect("읽기");
    assert!(!after.contains("evil"), "{after}");
    assert!(after.contains("\"c\""), "다른 키까지 지웠다: {after}");

    // 복원은 덮어쓰기다. 그 자리에 파일이 있으므로 먼저 치운다 — 실행기도
    // 같은 순서로 한다.
    l.destroy_file(&f).expect("치우기");
    l.restore_file(&f, &backup, &meta).expect("되돌리기");
    assert_eq!(std::fs::read(&f).expect("읽기"), before.to_vec());

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn setting_a_key_that_does_not_exist_is_refused() {
    // 위 시험이 통과하는 잘못된 방법이 "없으면 만든다" 이다. 그러면 서명된
    // 도구가 임의 설정 키를 새로 쓸 수 있게 된다.
    let d = lab("json-new");
    let f = p(&d, "prefs.json");
    std::fs::write(&f, br#"{"a":1}"#).expect("쓰기");

    let e = Live::new()
        .structured_set_key(&f, "b.c", "x")
        .expect_err("막아야 한다");
    assert_eq!(
        std::fs::read_to_string(&f).expect("읽기"),
        r#"{"a":1}"#,
        "{e}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

// ───────────────────────────────────────────── browser_ext.remove

#[test]
fn an_extension_directory_goes_and_comes_back_whole() {
    // 확장 하나는 **디렉터리 하나**다. 목차와 본문이 함께 돌아와야 한다.
    let d = lab("ext");
    let ext = d.join("Extensions").join("abcdef").join("1.0");
    std::fs::create_dir_all(&ext).expect("디렉터리");
    std::fs::write(ext.join("manifest.json"), br#"{"name":"evil"}"#).expect("쓰기");
    std::fs::create_dir_all(ext.join("js")).expect("하위");
    std::fs::write(ext.join("js").join("bg.js"), b"chrome.tabs\n").expect("쓰기");
    let target = ext.to_string_lossy().to_string();

    let l = Live::new();
    assert!(l.is_dir(&target));
    let (content, index) = l.dir_read(&target).expect("담기");

    l.dir_destroy(&target).expect("지우기");
    assert!(!l.exists(&target), "지워지지 않았다");

    l.dir_restore(&target, &content, &index).expect("되돌리기");
    assert_eq!(
        std::fs::read_to_string(ext.join("js").join("bg.js")).expect("읽기"),
        "chrome.tabs\n",
        "하위까지 돌아오지 않았다"
    );

    let _ = std::fs::remove_dir_all(&d);
}

// ───────────────────────────────────────────── process.kill

#[test]
fn an_empty_predicate_is_refused_not_expanded() {
    // **빈 술어는 모든 프로세스를 뜻한다.** 그것을 돌려주면 이 문이 임의
    // 열거가 된다 (설계-04 §1).
    let e = Live::new()
        .processes_matching(&KillPredicate::default())
        .expect_err("거절해야 한다");
    // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
    assert!(
        format!("{e}").contains(remedy_sdk::i18n::t("술어", "predicate")),
        "{e}"
    );
}

#[test]
fn a_predicate_finds_this_very_process() {
    // 지금 도는 시험 자신이 확실한 대상이다. 0건이 나오면 열거가 통하지 않는
    // 것이고, 그 상태의 `process.kill` 은 조용히 아무것도 안 한다.
    let me = std::env::current_exe().expect("내 경로");
    let found = Live::new()
        .processes_matching(&KillPredicate {
            image_path: Some(me.to_string_lossy().to_string()),
            cmdline_contains: None,
        })
        .expect("열거");
    assert!(
        found.iter().any(|t| t.pid == std::process::id()),
        "자기 자신을 못 찾았다: {found:?}"
    );
}

#[test]
fn killing_nothing_is_not_an_error() {
    // 멱등해야 한다 (설계-03 §5). 재기동한 실행기가 같은 Action 을 다시 돌린다.
    Live::new().process_kill(&[]).expect("빈 목록");
}

// ───────────────────────────────────────────── cert_store.remove

/// `update-ca-certificates` 를 실제로 부를 수 있는 기계인가.
///
/// 두 조건이 함께 필요하다 — 도구가 있고, root 여야 한다. 그것을 재는 이유는
/// 아래 시험이 **환경에 따라 다른 것을 주장하기 때문**이지 건너뛰기 위해서가
/// 아니다. 어느 쪽이든 무언가를 확인한다.
fn can_refresh_ca_store() -> bool {
    let has_tool = [
        "/usr/sbin/update-ca-certificates",
        "/usr/bin/update-ca-trust",
    ]
    .iter()
    .any(|t| std::path::Path::new(t).is_file());
    has_tool
        && std::process::Command::new("/usr/bin/id")
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false)
}

#[test]
fn a_cert_file_is_read_before_it_is_touched() {
    // 담기가 먼저다. 이 하나가 안 되면 뒤의 모든 것이 **백업 없는 삭제**가 된다.
    let d = lab("cert-read");
    let f = p(&d, "evil-ca.crt");
    std::fs::write(
        &f,
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )
    .expect("쓰기");

    let l = Live::new();
    assert!(l.cert_exists(&f), "있는 것을 없다고 한다");
    assert!(
        l.cert_read(&f).expect("담기").starts_with(b"-----BEGIN"),
        "본문이 아니다"
    );
    assert!(!l.cert_exists(&p(&d, "nope.crt")), "없는 것을 있다고 한다");

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn removing_a_cert_rebuilds_the_trust_store_or_says_it_could_not() {
    // **파일을 지우는 것은 치료가 아니다.**
    //
    // 실측(WSL Ubuntu 24.04): `/usr/share/ca-certificates/**.crt` 를 지워도
    // `/etc/ssl/certs/ca-certificates.crt` 번들에 그 인증서가 그대로 남는다.
    // TLS 검사는 그 번들을 읽으므로 신뢰가 사라지지 않는다.
    //
    // 그래서 이 시험은 **성공을 재지 않는다.** 재는 것은 *"다시 만들지 못했으면
    // 실패라고 말하는가"* 다 — 조용한 성공이 이 Op 의 유일한 위험한 결과다.
    let d = lab("cert-remove");
    let f = p(&d, "evil-ca.crt");
    std::fs::write(&f, b"payload\n").expect("쓰기");

    let l = Live::new();
    let r = l.cert_delete(&f);

    if can_refresh_ca_store() {
        r.expect("도구가 있고 root 인데 실패했다");
        assert!(!l.cert_exists(&f), "성공이라면서 파일이 남아 있다");

        // 왕복. 되돌린 뒤 본문이 같아야 한다.
        l.cert_restore(&f, b"payload\n").expect("되돌리기");
        assert_eq!(
            std::fs::read(&f).expect("읽기"),
            b"payload\n",
            "본문이 다르게 돌아왔다"
        );
        let _ = std::fs::remove_file(&f);
    } else {
        let e = r.expect_err("다시 만들 수 없는데 성공을 돌려줬다");
        let msg = format!("{e}");
        assert!(
            msg.contains("신뢰") || msg.contains("update-ca"),
            "왜 실패했는지 말하지 않는다: {msg}"
        );
    }

    let _ = std::fs::remove_dir_all(&d);
}

// ───────────────────────────────────────────── 카탈로그와의 대조

#[test]
fn every_op_linux_performs_has_a_case_or_a_written_reason() {
    // **"백엔드를 구현했다" 와 "그 Op 이 실제로 도는가" 는 다르다.**
    //
    // trait 의 기본 구현이 `Unsupported` 라 위임을 빠뜨려도 컴파일이 된다.
    // 그러면 구현이 없는 것이 **조용한 상태**가 되고, P12 의 게이트를 올리는
    // 사람은 무엇이 남았는지 알 길이 없다.
    //
    // 여기 사례가 있는 Op 을 손으로 적는 이유는 위 시험들이 실제로 그것을
    // 태우기 때문이다 — 카탈로그에서 뽑으면 자기 자신과 비교하는 항진명제가 된다.
    let covered = [
        "autorun.remove",
        "shortcut.strip_args",
        "service.stop",
        "service.disable",
        "service.delete",
        "persistence.disable",
        "persistence.delete",
        "file.quarantine_only",
        "file.delete",
        "text_config.remove_line",
        "hosts.restore_line",
        "structured_config.remove_key",
        "browser_ext.remove",
        "process.kill",
        "cert_store.remove",
    ];
    let excused: Vec<&str> = NOT_IMPLEMENTED_YET.iter().map(|(o, _)| *o).collect();

    let missing: Vec<&str> = Op::ALL
        .into_iter()
        .filter(|o| o.info().linux_from.is_some())
        .map(|o| o.info().id)
        // `structured_config.restore_default` 는 계획 자체가 안 된다 —
        // 기본값 카탈로그가 비어 있다 (`NOT_PLANNABLE_YET`). 계획될 수 없는 Op
        // 의 백엔드를 재는 것은 공허하다.
        .filter(|id| *id != "structured_config.restore_default")
        .filter(|id| !covered.contains(id) && !excused.contains(id))
        .collect();
    assert!(
        missing.is_empty(),
        "카탈로그가 Linux 에서 수행한다고 적었는데 왕복 사례도 면제 사유도 \
         없는 Op: {missing:?}\n\
         구현하고 사례를 더하거나, NOT_IMPLEMENTED_YET 에 이유와 함께 적을 것."
    );

    // 반대 방향. 해소된 것이 목록에 남아 있으면 그 문장이 거짓말이 된다.
    let stale: Vec<&str> = excused
        .iter()
        .copied()
        .filter(|id| covered.contains(id))
        .collect();
    assert!(
        stale.is_empty(),
        "이제 되는데 '못 한다' 고 적혀 있다: {stale:?}"
    );

    // 이유 없는 면제는 면제가 아니다.
    for (op, why) in NOT_IMPLEMENTED_YET {
        assert!(why.len() > 30, "{op}: 이유가 너무 짧다");
    }
}

#[test]
fn nothing_is_left_unimplemented() {
    // **비어야 P12 의 게이트가 올라간다** — `IMPLEMENTED_THROUGH` 를 P12 로
    // 올리는 것은 "이 코어가 Linux 에서 그 Op 들을 한다" 는 선언이고, 목록에
    // 무언가 남아 있으면 그 선언이 절반만 참이다.
    //
    // 목록이 다시 채워지면 위
    // `every_op_linux_performs_has_a_case_or_a_written_reason` 가 이유를
    // 요구하고, **그 항목이 정말로 `Unsupported` 를 내는지 재는 것은 그때 여기에
    // 더한다** — 메서드 이름으로 부르는 것이라 일반화할 수 없다.
    assert!(
        NOT_IMPLEMENTED_YET.is_empty(),
        "아직 구현되지 않은 Op 이 남아 있다: {:?}",
        NOT_IMPLEMENTED_YET
            .iter()
            .map(|(o, _)| *o)
            .collect::<Vec<_>>()
    );
}

// ───────────────────────────────────────── persistence.disable · persistence.delete

/// cron 항목 하나가 든 crontab 파일과 그 항목의 `id`.
fn crontab(dir: &std::path::Path, body: &str) -> String {
    let f = p(dir, "cron.d-updater");
    std::fs::write(&f, body).expect("쓰기");
    f
}

#[test]
fn a_cron_line_is_commented_out_and_comes_back() {
    // **가장 흔한 Linux 지속성이다.** 끄는 것은 줄 주석이고, 되돌리기는 그
    // `#` 를 떼는 것이 아니라 담아 둔 줄을 그 자리에 다시 넣는 것이다.
    let d = lab("cron-disable");
    let body = "SHELL=/bin/sh\n@reboot /home/a/.cache/upd.sh\n17 * * * * root /usr/bin/ok\n";
    let f = crontab(&d, body);
    let id = format!("{f}:2");
    let at = LineAt {
        line_no: 2,
        line: "@reboot /home/a/.cache/upd.sh".into(),
    };

    let l = Live::new();
    assert!(l.persistence_exists(&id), "있는 줄을 없다고 한다");
    let (backup, index) = l.persistence_read(&id).expect("담기");
    assert!(index.links.is_empty(), "cron 에는 곁가지가 없다: {index:?}");

    l.persistence_disable(&id, Some(&at)).expect("끄기");
    let after = std::fs::read_to_string(&f).expect("읽기");
    assert!(after.contains("#@reboot"), "주석 처리되지 않았다: {after}");
    assert!(
        after.contains("/usr/bin/ok"),
        "정상 줄까지 건드렸다: {after}"
    );
    // **끄고 나서도 "있다" 여야 한다.** 이 함수는 *"도는가"* 가 아니라
    // *"있는가"* 를 말한다 — 실행기가 이것으로 `persistence.delete` 를 건너뛸지
    // 정하므로, 꺼진 것을 없다고 하면 차례의 뒷단계가 통째로 사라진다.
    // 악성 줄이 `#` 하나 붙은 채 남고 실행기는 "지웠다" 고 보고한다.
    assert!(
        l.persistence_exists(&id),
        "끈 것을 없다고 한다 — delete 가 건너뛰어진다"
    );

    // 멱등해야 한다 — 재기동한 실행기가 같은 Action 을 다시 돌린다.
    // **그 멱등성은 이 함수가 아니라 `persistence_disable` 자신이 지킨다.**
    l.persistence_disable(&id, Some(&at)).expect("두 번째");
    assert_eq!(std::fs::read_to_string(&f).expect("읽기"), after);

    // 그리고 끈 뒤에도 지울 수 있어야 한다. `expect_line` 이 앞의 `#` 를 떼고
    // 비교하므로 계획이 든 원본 줄로 그대로 지목된다.
    l.persistence_delete(&id, Some(&at)).expect("끈 뒤 지우기");
    let gone = std::fs::read_to_string(&f).expect("읽기");
    assert!(!gone.contains("upd.sh"), "끈 뒤 지웠는데 남았다: {gone}");
    assert!(gone.contains("/usr/bin/ok"), "정상 줄까지 지웠다: {gone}");

    // **두 번 지우는 것은 계약에 없다.** 첫 삭제로 그 줄이 사라지면 같은 번호에
    // 다음 줄(정상 작업)이 오고, 그것을 지우면 이 도구가 하지 말아야 할 일을
    // 한다. 그래서 `expect_line` 이 거절한다 — 아래
    // `a_cron_line_that_changed_is_not_touched` 가 같은 것을 다른 입력으로 잰다.
    //
    // **멱등성은 이 함수가 아니라 `persistence_exists` 가 지킨다** —
    // `remedy-apply` 가 부르기 전에 그것으로 묻고 없으면 건너뛴다.
    let e = l
        .persistence_delete(&id, Some(&at))
        .expect_err("두 번째 삭제는 거절해야 한다");
    assert!(
        format!("{e}").contains(remedy_sdk::i18n::t(
            "계획과 다르다",
            "does not match the plan"
        )),
        "{e}"
    );
    let gone = std::fs::read_to_string(&f).expect("읽기");
    assert!(!gone.contains("upd.sh"), "{gone}");
    assert!(gone.contains("/usr/bin/ok"), "정상 작업이 지워졌다: {gone}");

    l.persistence_restore(&id, &backup, &index)
        .expect("되돌리기");
    assert_eq!(std::fs::read_to_string(&f).expect("읽기"), body);

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_cron_line_that_changed_is_not_touched() {
    // **이것이 계약을 넓힌 이유다.** 번호만으로 고치면 그 사이에 파일이
    // 바뀌었을 때 정상 작업을 조용히 멈춘다.
    let d = lab("cron-mismatch");
    let body = "@reboot /usr/bin/legit\n";
    let f = crontab(&d, body);
    let id = format!("{f}:1");

    let e = Live::new()
        .persistence_disable(
            &id,
            Some(&LineAt {
                line_no: 1,
                line: "@reboot /home/a/.cache/upd.sh".into(),
            }),
        )
        .expect_err("막아야 한다");
    assert_eq!(std::fs::read_to_string(&f).expect("읽기"), body, "{e}");

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_cron_line_without_its_content_is_refused() {
    // 위 시험이 통과하는 잘못된 방법이 "내용이 없으면 번호로 한다" 이다.
    let d = lab("cron-noat");
    let body = "@reboot /usr/bin/legit\n";
    let f = crontab(&d, body);

    let e = Live::new()
        .persistence_disable(&format!("{f}:1"), None)
        .expect_err("막아야 한다");
    assert!(
        format!("{e}").contains(remedy_sdk::i18n::t("줄 내용", "line content")),
        "{e}"
    );
    assert_eq!(std::fs::read_to_string(&f).expect("읽기"), body);

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_systemd_unit_loses_its_links_and_gets_them_back() {
    // **활성화는 유닛 파일 안에 없다.** 링크를 담지 않으면 복원한 유닛이 꺼진
    // 채로 돌아오고, 사용자는 복원이 됐다고 믿는다.
    let d = lab("unit");
    let unit = p(&d, "upd.service");
    let body =
        "[Service]\nExecStart=/home/a/.local/bin/upd\n\n[Install]\nWantedBy=default.target\n";
    std::fs::write(&unit, body).expect("쓰기");
    let wants = d.join("default.target.wants");
    std::fs::create_dir_all(&wants).expect("디렉터리");
    let link = wants.join("upd.service");
    std::os::unix::fs::symlink(&unit, &link).expect("링크");

    let l = Live::new();
    assert!(l.persistence_exists(&unit));
    let (backup, index) = l.persistence_read(&unit).expect("담기");
    assert_eq!(index.links.len(), 1, "링크를 못 봤다: {index:?}");

    l.persistence_disable(&unit, None).expect("끄기");
    assert!(!link.exists(), "링크가 남았다");
    assert!(
        std::path::Path::new(&unit).exists(),
        "끄기인데 유닛까지 지웠다"
    );

    l.persistence_delete(&unit, None).expect("지우기");
    assert!(!std::path::Path::new(&unit).exists());

    l.persistence_restore(&unit, &backup, &index)
        .expect("되돌리기");
    assert_eq!(std::fs::read_to_string(&unit).expect("읽기"), body);
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "유닛만 돌아오고 링크가 안 돌아왔다 — 꺼진 채로 복원된 것이다"
    );

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn deleting_a_unit_takes_its_links_with_it() {
    // 링크를 남기면 **같은 이름의 유닛이 다시 놓였을 때 곧바로 부활한다.**
    let d = lab("unit-links");
    let unit = p(&d, "upd.service");
    std::fs::write(&unit, "[Service]\nExecStart=/x\n").expect("쓰기");
    let wants = d.join("multi-user.target.wants");
    std::fs::create_dir_all(&wants).expect("디렉터리");
    let link = wants.join("upd.service");
    std::os::unix::fs::symlink(&unit, &link).expect("링크");

    Live::new().persistence_delete(&unit, None).expect("지우기");
    assert!(
        std::fs::symlink_metadata(&link).is_err(),
        "유닛은 지웠는데 링크가 남았다"
    );

    let _ = std::fs::remove_dir_all(&d);
}

// ───────────────────────────────────────── service.disable · service.delete

#[test]
fn a_service_unit_loses_its_links_and_comes_back() {
    // **`.service` 는 `service` subject 다** — `.timer` 와 파일 다루는 법은
    // 같지만 subject 가 다르고, 그래서 Op 도 다르다 (설계-09 P12 순서 9).
    let d = lab("svc");
    let unit = p(&d, "evil.service");
    let body = "[Service]\nExecStart=/tmp/.x/evil\n\n[Install]\nWantedBy=multi-user.target\n";
    std::fs::write(&unit, body).expect("쓰기");
    let wants = d.join("multi-user.target.wants");
    std::fs::create_dir_all(&wants).expect("디렉터리");
    let link = wants.join("evil.service");
    std::os::unix::fs::symlink(&unit, &link).expect("링크");

    let l = Live::new();
    // 실행기의 `service.delete` 가지가 이 이름으로 "아직 있는가" 를 묻는다.
    assert!(l.registry_key_exists(&unit));
    let (backup, index) = l.persistence_read(&unit).expect("담기");
    assert_eq!(index.links.len(), 1, "{index:?}");

    l.service_disable(&unit).expect("끄기");
    assert!(!link.exists(), "링크가 남았다");
    assert!(
        std::path::Path::new(&unit).exists(),
        "끄기인데 유닛까지 지웠다"
    );

    l.service_delete(&unit).expect("지우기");
    assert!(!l.registry_key_exists(&unit));

    l.persistence_restore(&unit, &backup, &index)
        .expect("되돌리기");
    assert_eq!(std::fs::read_to_string(&unit).expect("읽기"), body);
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "유닛만 돌아오고 링크가 안 돌아왔다 — 꺼진 채로 복원된 것이다"
    );

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn stopping_a_service_is_asked_of_systemd() {
    // **서비스 관리자가 해야 하는 일이고, 그래서 systemd 에게 시킨다** (설계-09 P12
    // 결정 A, 2026-09-29). 파일만 지우고 프로세스를 죽이면 systemd 가 메모리의
    // 정의로 되살렸다.
    //
    // **이 시험은 진짜 systemd 를 건드리지 않는다** — 개발 기계의 서비스를 멈출 수
    // 있기 때문이다. `systemctl` 을 부르는 갈래는 `linux.rs` 안의 시험이 가짜 도구와
    // 가짜 부팅 표지로 잰다. 여기서는 이 기계가 무엇이든 참인 것만 본다.
    let l = Live::new();
    let unit = "/etc/systemd/system/x.service";
    // 복구 동작 제거는 여전히 없다 — 정지가 먼저 돌면 필요도 없다.
    assert!(matches!(
        l.service_clear_recovery(unit),
        Err(PlatformError::Unsupported(_))
    ));
    // systemd 가 PID 1 인가가 곧 "멈출 것이 있는가" 다.
    let booted = std::path::Path::new("/run/systemd/system").is_dir();
    assert_eq!(l.service_running(unit), booted);
    if booted {
        // 사용자 유닛은 도구를 부르기 전에 거부한다 — 시스템 관리자에게 같은 이름을
        // 멈추라고 하면 엉뚱한 유닛이 멈출 수 있다.
        assert!(matches!(
            l.service_stop("/home/u/.config/systemd/user/x.service"),
            Err(PlatformError::Refused(_))
        ));
    } else {
        // 컨테이너처럼 systemd 가 없으면 멈출 관리자도 없다 — 할 일이 없다.
        assert!(l.service_stop(unit).is_ok());
    }
}

// ───────────────────────────────────── autorun.remove · shortcut.strip_args

#[test]
fn an_autostart_entry_is_a_file_and_comes_back() {
    // Linux 자동실행은 **파일 하나**다 — Windows 에서 레지스트리 값 하나인 것과
    // 자리만 다르다 (설계-09 P12 순서 9).
    let d = lab("autorun");
    let f = p(&d, "evil.desktop");
    let body = "[Desktop Entry]\nType=Application\nName=Updater\nExec=/tmp/.x/upd --daemon\n";
    std::fs::write(&f, body).expect("쓰기");

    let l = Live::new();
    let (backup, meta) = l.quarantine_read(&f).expect("담기");
    l.destroy_file(&f).expect("지우기");
    assert!(!l.exists(&f));

    l.restore_file(&f, &backup, &meta).expect("되돌리기");
    assert_eq!(std::fs::read_to_string(&f).expect("읽기"), body);

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_desktop_entry_loses_its_arguments_but_keeps_the_command() {
    // 바로가기는 **명령을 숨기기 좋은 자리**다. 아이콘과 이름은 정상 프로그램의
    // 것을 쓰면서 인자만 바꾸면 사용자에게는 원래 프로그램으로 보인다.
    let d = lab("desktop-args");
    let f = p(&d, "app.desktop");
    std::fs::write(
        &f,
        "[Desktop Entry]\nName=Viewer\nExec=/usr/bin/viewer --load /tmp/.x/evil.so %U\nIcon=viewer\n\n\
         [Desktop Action New]\nExec=/usr/bin/viewer --new\n",
    )
    .expect("쓰기");

    Live::new()
        .shortcut_strip_args(&f, "--load /tmp/.x/evil.so")
        .expect("인자 제거");
    let after = std::fs::read_to_string(&f).expect("읽기");
    assert!(after.contains("Exec=/usr/bin/viewer %U"), "{after}");
    assert!(!after.contains("evil.so"), "{after}");
    // **필드 코드는 인자가 아니다.** 지우면 항목이 원래 하던 일을 못 한다.
    assert!(after.contains("%U"), "{after}");
    // 이름과 아이콘은 그대로다 — 인자만 떼는 Op 이다.
    assert!(after.contains("Name=Viewer"), "{after}");
    // 두 번째 절은 항목이 저절로 실행하는 명령이 아니다. 건드리지 않는다.
    assert!(after.contains("Exec=/usr/bin/viewer --new"), "{after}");

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_entry_without_arguments_is_left_alone() {
    // 멱등해야 한다 (설계-03 §5). 두 번째 실행이 파일을 다시 쓰면 mtime 이
    // 바뀌고, 그것만으로 다른 도구가 변경을 감지한다.
    let d = lab("desktop-noargs");
    let f = p(&d, "app.desktop");
    let body = "[Desktop Entry]\nExec=/usr/bin/viewer\n";
    std::fs::write(&f, body).expect("쓰기");
    let before = std::fs::metadata(&f)
        .expect("메타")
        .modified()
        .expect("mtime");

    Live::new().shortcut_strip_args(&f, "").expect("인자 제거");
    assert_eq!(std::fs::read_to_string(&f).expect("읽기"), body);
    assert_eq!(
        std::fs::metadata(&f)
            .expect("메타")
            .modified()
            .expect("mtime"),
        before,
        "바꿀 것이 없는데 파일을 다시 썼다"
    );

    let _ = std::fs::remove_dir_all(&d);
}
