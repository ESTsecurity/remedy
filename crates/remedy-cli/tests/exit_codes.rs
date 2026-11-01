//! 종료 코드 계약 (설계-02 §8).
//!
//! **이것이 무인 배포의 기계 판독 계약이다.** 사람은 stdout 을 읽지만 배포
//! 스크립트는 종료 코드만 본다. 0 이 "이 PC 는 깨끗하다" 로 읽히므로, 코드 하나가
//! 틀리면 감염된 PC 가 검사 완료로 기록된다.
//!
//! 바이너리를 실제로 띄워서 확인한다. 내부 함수를 부르면 인자 파싱과 오류 경로가
//! 검사되지 않고, 정작 사용자가 겪는 것은 그 경로다.

// `Path` 는 Windows 전용 헬퍼(`plugin`)의 인자 타입으로만 쓴다. 함께 임포트하면
// Linux 에서 미사용이 되어 `-D warnings` 에 걸린다.
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// `cargo` 가 이 테스트에 넣어 주는 산출물 경로. 빌드 설정이 바뀌어도 따라간다.
const EXE: &str = env!("CARGO_BIN_EXE_remedy");

fn work() -> PathBuf {
    let d = std::env::temp_dir().join("remedy-cli-exit-codes");
    std::fs::create_dir_all(&d).expect("작업 디렉터리");
    d
}

fn run(args: &[&str]) -> i32 {
    let out = Command::new(EXE)
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        // 시험은 한국어 문구를 단정한다. 기본 언어는 영어다 (2026-09-06).
        .env("REMEDY_LANG", "ko")
        .output()
        .unwrap_or_else(|e| panic!("{EXE} 실행 실패: {e}"));
    out.status.code().unwrap_or(-1)
}

/// 마커 파일과 페이로드가 든 트리. 두 룰이 한 그룹으로 묶여 판정이 난다.
///
/// **`on_metal` 에서만 쓴다.** 그 모듈이 `#[cfg(windows)]` 인 이유(수집 백엔드가
/// Windows 에만 있다)가 이 헬퍼에도 그대로 걸린다. 조건을 붙이지 않으면 Linux
/// 에서 미사용 함수가 되어 `-D warnings` 에 걸리는데, **Windows 에서만 개발하면
/// 그것이 보이지 않는다** — 실제로 `ci/linux-check-local.sh` 가 잡아냈다.
#[cfg(windows)]
fn tree() -> PathBuf {
    let root = work().join("tree");
    let app = root.join("app-a");
    std::fs::create_dir_all(&app).expect("트리");
    std::fs::write(app.join("marker.txt"), b"MARKER").expect("marker");
    std::fs::write(app.join("main.js"), b"// payload").expect("payload");
    root
}

/// 트리를 조준하는 최소 플러그인. YAML 작은따옴표는 역슬래시를 그대로 둔다.
///
/// `tree` 와 같은 이유로 Windows 전용이다.
#[cfg(windows)]
fn plugin(root: &Path) -> PathBuf {
    let p = work().join("plugin.yaml");
    std::fs::write(
        &p,
        format!(
            r#"schema_version: 1
id: exit-code-test
version: 1.0.0
min_core: '1.0.0'
platforms: [windows, linux]
name: {{ en: 'exit code test' }}
scan_roots: ['{root}']
subjects: [file]
detect:
  - id: marker
    subject: file
    where:
      - {{ field: path, op: ends_with, value: 'marker.txt' }}
    capture:
      dir: 'path | dirname'
  - id: payload
    subject: file
    from: '${{marker.dir}}'
    where:
      - {{ field: path, op: ends_with, value: 'main.js' }}
verdict: {{ require: 'marker and payload' }}
"#,
            root = root.display()
        ),
    )
    .expect("플러그인");
    p
}

#[test]
fn version_and_no_args_are_zero() {
    assert_eq!(run(&["--version"]), 0);
    assert_eq!(run(&[]), 0, "인자 없이 부르면 사용법을 보이고 0 이다");
}

#[test]
fn usage_errors_are_four() {
    // 4 를 다른 코드와 섞으면 배포 스크립트가 "내가 잘못 불렀다" 와
    // "이 PC 에 문제가 있다" 를 구분하지 못한다.
    assert_eq!(run(&["존재하지-않는-명령"]), 4);
    assert_eq!(
        run(&["collect", "--out", "x.json"]),
        4,
        "--root 도 --plugin 도 없다"
    );
    assert_eq!(run(&["collect", "--root"]), 4, "값이 없는 인자");
    assert_eq!(run(&["collect", "root", "x"]), 4, "'--' 없는 인자");
    let out = work().join("nope.json");
    assert_eq!(
        run(&[
            "evaluate",
            "--artifacts",
            "없는파일.json",
            "--plugin",
            "없는플러그인.yaml",
            "--out",
            out.to_str().unwrap(),
        ]),
        4,
        "없는 입력 파일"
    );
}

#[test]
fn selftest_is_zero() {
    assert_eq!(run(&["selftest"]), 0);
}

/// Windows 에서만 수집 백엔드가 있다. 다른 플랫폼에서는 수집이 성립하지 않으므로
/// 이 아래 검사는 `NoBackend` 오류를 받는다 (설계-09 P12 에서 Linux 가 들어온다).
#[cfg(windows)]
mod on_metal {
    use super::*;

    #[test]
    fn threat_found_is_two_and_beats_incompleteness() {
        // **불완전성은 "없다" 를 뒤집을 뿐 "있다" 를 뒤집지 못한다.** 이 성질이
        // 깨지면 무인 배포가 실제 감염을 "관측 불완전" 으로 흘려보낸다.
        let root = tree();
        let p = plugin(&root);
        let dir = work().join("scan-out");
        assert_eq!(
            run(&[
                "scan",
                "--plugin",
                p.to_str().unwrap(),
                "--out-dir",
                dir.to_str().unwrap(),
            ]),
            2,
            "위협 발견 · 치료 안 함"
        );
    }

    #[test]
    fn incomplete_observation_is_six_not_zero() {
        // 진단 모드는 예약 작업도 수집한다. 관리자 권한이 없으면 그 디렉터리를
        // 못 읽는데, 지금까지는 그 실행이 0(위협 없음)을 냈다. 그 PC 는 검사받았다고
        // 기록되지만 실제로는 절반만 본 것이다.
        //
        // 관리자로 돌리면 접근이 되어 0 이 나올 수 있다. 그때는 이 검사가 성립하지
        // 않으므로 **통과시키지 않고 건너뛴 사실을 남긴다** — 조용히 통과하면
        // 이 검사는 있으나 마나다.
        let out = work().join("incomplete.json");
        let code = run(&[
            "collect",
            "--root",
            tree().to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]);
        assert!(
            code == 0 || code == 6,
            "수집은 성공해야 한다. 실제 종료 코드: {code}"
        );

        let text = std::fs::read_to_string(&out).expect("스냅샷");
        let v: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        let denied = v["scope"]["denied_dirs"].as_u64().unwrap_or(0);
        let truncated = v["scope"]["truncated"].as_bool().unwrap_or(false);

        if denied > 0 || truncated {
            assert_eq!(code, 6, "관측이 불완전한데 0 을 냈다 — 거짓 음성이다");
        } else {
            assert_eq!(code, 0, "관측이 완전한데 0 이 아니다");
            eprintln!("주의: 이 실행은 관측이 완전해 6 경로를 확인하지 못했다");
        }
    }
}
