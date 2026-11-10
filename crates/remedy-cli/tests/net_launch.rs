//! 네트워크 점검 룰 — 본체가 동반 프로그램(`remedy-net`)을 **언제 띄우고 언제 띄우지 않는가** (코어 1.4.0).
//!
//! 바이너리를 실제로 띄운다. 본체에는 통신 코드가 없고, 룰이 `network: <점검>` 을 선언했을 때 실행 파일
//! 옆의 `remedy-net` 을 띄워 맡긴다 — 서명이 맞는 것만(설계-04 §1 *동반 모듈*).
//!
//! # 동반 프로그램 자리에 본체의 사본을 둔다
//!
//! 여기서 재는 것은 **띄우기까지의 조건**과 **종료 코드가 돌아오는 길**이다. 진짜 통신 프로그램일 필요가
//! 없다 — 본체의 사본은 `url` 이라는 명령을 몰라 입력 오류(4)로 끝나고, 그 4 가 돌아오면 띄운 것이다.
//! 진짜 `remedy-net` 까지 잇는 길은 배포 잡(`ci/release.sh`)이 받는 사람이 푸는 그 폴더에서 잰다.
//!
//! # 공개키
//!
//! `cargo test` 가 지은 바이너리에는 공개키가 박혀 있지 않다. 시험이 키쌍을 만들고 개발 빌드 전용
//! `REMEDY_NET_ANCHOR` 로 준다 — 그 자리는 배포 빌드에서 컴파일되지 않는다(`net::dev_anchor`).

use minisign::KeyPair;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const EXE: &str = env!("CARGO_BIN_EXE_remedy");
const CORE: &str = env!("CARGO_PKG_VERSION");

const RULE: &str = "schema_version: 1\nid: net-check\nversion: 1.0.0\nmin_core: '1.4.0'\n\
                    platforms: [windows, linux]\nname: { ko: '원격 점검', en: 'remote check' }\n\
                    kind: check\nnetwork: url\nscan_roots: []\nsubjects: []\ndetect: []\n";

fn exe_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

/// 본체를 복사한 폴더와 그 옆의 네트워크 점검 룰.
struct Lab {
    dir: PathBuf,
    rule: PathBuf,
}

fn lab(name: &str) -> Lab {
    let dir = std::env::temp_dir()
        .join("remedy-cli-net-launch")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("plugins").join("net-check")).expect("작업 디렉터리");
    std::fs::copy(EXE, dir.join(exe_name("remedy"))).expect("바이너리 복사");
    let rule = dir.join("plugins").join("net-check").join("plugin.yaml");
    std::fs::write(&rule, RULE).expect("plugin.yaml");
    Lab { dir, rule }
}

/// 동반 프로그램 폴더 — 본체의 사본을 그 이름으로 둔다.
fn put_companion(lab: &Lab) -> PathBuf {
    let dir = lab.dir.join("remedy-net");
    std::fs::create_dir_all(&dir).expect("폴더");
    std::fs::copy(EXE, dir.join(exe_name("remedy-net"))).expect("동반 프로그램 자리");
    dir
}

/// 폴더를 통째로 서명한다 — 룰을 서명하는 것과 같은 형식이다(`cargo xtask sign`).
fn sign(dir: &Path, kp: &KeyPair, id: &str, version: &str) {
    let tree = remedy_trust::collect(dir).expect("트리");
    let manifest = remedy_trust::Manifest::render(&tree);
    let comment = remedy_trust::TrustedComment::render(id, version, "2026-11-10T00:00:00Z");
    let sig = minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        manifest.as_bytes(),
        Some(&comment),
        Some("remedy plugin signature"),
    )
    .expect("서명");
    std::fs::write(dir.join(remedy_trust::MANIFEST_NAME), manifest).expect("매니페스트");
    std::fs::write(dir.join(remedy_trust::SIGNATURE_NAME), sig.to_string()).expect("서명 파일");
}

/// 공개키의 base64 한 줄 — 배포 빌드에 박는 값과 같은 꼴이다.
fn anchor(kp: &KeyPair) -> String {
    let boxed = kp.pk.to_box().expect("공개키 상자").to_string();
    boxed.lines().nth(1).expect("공개키 줄").trim().to_string()
}

fn keypair() -> KeyPair {
    KeyPair::generate_unencrypted_keypair().expect("키쌍")
}

/// `scan --plugin <룰> --out-dir <폴더> --url …` — 권한은 **없는 것으로** 못박는다(네트워크 점검은
/// 관리자 문을 지나지 않는다).
fn scan(lab: &Lab, key: Option<&str>, extra: &[&str]) -> Output {
    let mut cmd = Command::new(lab.dir.join(exe_name("remedy")));
    cmd.args(["scan", "--plugin"])
        .arg(&lab.rule)
        .arg("--out-dir")
        .arg(lab.dir.join("out"))
        .args(extra)
        .env("REMEDY_LANG", "ko")
        .env("REMEDY_ASCII", "0")
        .env("REMEDY_ELEVATION", "no")
        .env_remove("REMEDY_NET_ANCHOR")
        .stdin(Stdio::null());
    if let Some(k) = key {
        cmd.env("REMEDY_NET_ANCHOR", k);
    }
    cmd.output().expect("실행")
}

const URL: &[&str] = &["--url", "http://127.0.0.1:9/"];

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// 띄우지 않았다 — 가드 중단(5)이고, 동반 프로그램이 내는 말(알 수 없는 명령)이 없다.
fn assert_refused(o: &Output, why: &str) {
    let t = text(o);
    assert_eq!(o.status.code(), Some(5), "{t}");
    assert!(t.contains(why), "까닭 '{why}' 가 없다:\n{t}");
    assert!(!t.contains("알 수 없는 명령"), "띄웠다:\n{t}");
}

#[test]
fn without_the_companion_the_check_cannot_run() {
    // 네트워크를 쓰지 않으려고 폴더를 지운 자리 — 본체에는 통신할 길이 없다.
    let lab = lab("absent");
    let kp = keypair();
    let o = scan(&lab, Some(&anchor(&kp)), URL);
    assert_refused(&o, "이 폴더에 remedy-net 이 없습니다");
    assert!(
        !lab.dir.join("out").exists(),
        "점검하지 않았는데 결과 폴더를 지었다"
    );
}

#[test]
fn a_build_without_a_key_starts_nothing() {
    let lab = lab("no-key");
    let kp = keypair();
    sign(&put_companion(&lab), &kp, "remedy-net", CORE);
    // 서명은 맞지만 이 빌드는 그것을 확인할 공개키가 없다 — 있는 파일을 그냥 띄우지 않는다.
    assert_refused(&scan(&lab, None, URL), "서명을 확인할 수 없어");
}

#[test]
fn an_unsigned_companion_is_not_started() {
    let lab = lab("unsigned");
    put_companion(&lab);
    let kp = keypair();
    assert_refused(&scan(&lab, Some(&anchor(&kp)), URL), "서명이 없어");
}

#[test]
fn a_companion_signed_by_another_key_is_not_started() {
    let lab = lab("other-key");
    sign(&put_companion(&lab), &keypair(), "remedy-net", CORE);
    let ours = keypair();
    assert_refused(&scan(&lab, Some(&anchor(&ours)), URL), "서명한 것과 달라");
}

#[test]
fn a_changed_companion_is_not_started() {
    let lab = lab("changed");
    let kp = keypair();
    let dir = put_companion(&lab);
    sign(&dir, &kp, "remedy-net", CORE);
    // 서명한 뒤 실행 파일을 바꿨다.
    let program = dir.join(exe_name("remedy-net"));
    let mut bytes = std::fs::read(&program).unwrap();
    bytes.extend_from_slice(b"tampered");
    std::fs::write(&program, bytes).unwrap();
    assert_refused(&scan(&lab, Some(&anchor(&kp)), URL), "서명한 것과 달라");

    // 서명한 폴더에 파일을 더해도 같다 — 몰래 넣은 것을 함께 띄우는 길이 없다.
    let lab = lab_added();
    assert_refused(&scan(&lab.0, Some(&lab.1), URL), "서명한 것과 달라");
}

fn lab_added() -> (Lab, String) {
    let lab = lab("added");
    let kp = keypair();
    let dir = put_companion(&lab);
    sign(&dir, &kp, "remedy-net", CORE);
    std::fs::write(dir.join("extra.dll"), b"x").unwrap();
    (lab, anchor(&kp))
}

#[test]
fn a_signed_rule_folder_in_its_place_is_not_started() {
    // 우리 키로 서명한 것이어도 **동반 프로그램에 한 서명**이어야 한다 — 서명된 룰 폴더를 이 자리에
    // 옮겨 놓은 것을 띄우지 않는다.
    let lab = lab("not-companion");
    let kp = keypair();
    sign(&put_companion(&lab), &kp, "evilai-locust", CORE);
    assert_refused(
        &scan(&lab, Some(&anchor(&kp)), URL),
        "동반 프로그램의 것이 아니어서",
    );
}

#[test]
fn another_version_is_not_started() {
    let lab = lab("other-version");
    let kp = keypair();
    sign(&put_companion(&lab), &kp, "remedy-net", "0.0.1");
    let o = scan(&lab, Some(&anchor(&kp)), URL);
    assert_refused(&o, "버전(0.0.1)");
}

#[test]
fn a_verified_companion_is_started_and_its_exit_code_comes_back() {
    let lab = lab("verified");
    let kp = keypair();
    sign(&put_companion(&lab), &kp, "remedy-net", CORE);
    let o = scan(&lab, Some(&anchor(&kp)), URL);
    let t = text(&o);
    // 자리에 둔 것은 본체의 사본이다 — `url` 을 몰라 4 로 끝나고, 그 4 가 본체의 종료 코드가 된다.
    assert_eq!(o.status.code(), Some(4), "{t}");
    assert!(t.contains("알 수 없는 명령"), "띄우지 않았다:\n{t}");
    // 띄우기 **전에** 알린다 — 네트워크를 쓴다는 것과 누가 쓰는지.
    let notice = t.find("이 점검은 네트워크를 씁니다").expect("알림이 없다");
    assert!(t.contains("remedy-net 을 실행해 맡깁니다"), "{t}");
    assert!(
        notice < t.find("알 수 없는 명령").unwrap(),
        "알림이 뒤에 나왔다:\n{t}"
    );
    // 관리자 문을 지나지 않았다(권한을 '없음' 으로 못박았다) — 그 문이 닫힐 때의 문장(*관리자 · root
    // 권한이 필요합니다*)이 없다. 낱말로 보지 않는다: 자리에 둔 사본이 찍는 사용법에도 *root 권한으로
    // 실행해야 합니다* 가 있다(리눅스에서 이 단언이 그 줄에 걸렸다).
    assert!(!t.contains("권한이 필요합니다"), "{t}");
    // 무엇이 서명 확인의 기준이 됐는지 남는다(개발 빌드 전용 자리).
    assert!(t.contains("REMEDY_NET_ANCHOR"), "{t}");
}

#[test]
fn what_the_operator_typed_reaches_the_companion_untouched() {
    // 본체는 주소 · 동의 · CA 파일을 풀이하지 않는다 — 그대로 넘긴다. 사본(본체)은 받은 명령을 모른다고
    // 답하므로, 넘어간 꼴은 그 사본의 인자 오류 문장으로는 볼 수 없다. 그래서 여기서는 **주소가 없으면
    // 띄우지 않는다** 만 잰다 — 넘기는 꼴은 `net` 모듈이 한 자리에서 짓는다.
    let lab = lab("no-url");
    let kp = keypair();
    sign(&put_companion(&lab), &kp, "remedy-net", CORE);
    let o = scan(&lab, Some(&anchor(&kp)), &[]);
    let t = text(&o);
    assert_eq!(o.status.code(), Some(4), "{t}");
    assert!(t.contains("--url"), "{t}");
    assert!(!t.contains("알 수 없는 명령"), "주소 없이 띄웠다:\n{t}");
}

#[test]
fn commands_that_read_this_machine_refuse_a_network_rule() {
    // 그 룰로 수집 · 평가를 돌리면 빈 결과가 '깨끗함' 으로 읽힌다 — 어떻게 돌리는지 말하고 멈춘다.
    let lab = lab("local-commands");
    let o = Command::new(lab.dir.join(exe_name("remedy")))
        .args(["collect", "--plugin"])
        .arg(&lab.rule)
        .arg("--out")
        .arg(lab.dir.join("artifacts.json"))
        .env("REMEDY_LANG", "ko")
        .env("REMEDY_ELEVATION", "yes")
        .stdin(Stdio::null())
        .output()
        .expect("실행");
    let t = text(&o);
    assert_eq!(o.status.code(), Some(4), "{t}");
    assert!(t.contains("네트워크로 점검합니다"), "{t}");
    assert!(!lab.dir.join("artifacts.json").exists());
}
