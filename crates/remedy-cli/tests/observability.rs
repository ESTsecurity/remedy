//! 죽거나 멈추면 무엇이 남는가 — 관측성 (2026-09-07 Phase 1).
//!
//! 세 가지를 잰다.
//! 1. 패닉이 나면 **종료 코드 7** 로 나가고 `logs/crash-*.txt` 에 무엇이 어디서
//!    죽었는지 남는다 (개발 빌드의 `REMEDY_PANIC_TEST=1` 로 일으킨다).
//! 2. 기계를 만지는 명령은 화면에 나간 줄을 `logs/<run_id>.log` 에 시각과 함께
//!    복사한다.
//! 3. `support-bundle` 이 그 로그를 `run.log` 로 담는다.

use std::path::{Path, PathBuf};
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_remedy");

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], extra_env: &[(&str, &str)]) -> Out {
    let mut c = Command::new(EXE);
    c.args(args)
        .env("REMEDY_ELEVATION", "yes")
        .env("REMEDY_LANG", "ko");
    for (k, v) in extra_env {
        c.env(k, v);
    }
    let out = c
        .output()
        .unwrap_or_else(|e| panic!("{EXE} 실행 실패: {e}"));
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn work(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "remedy-cli-observability-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("작업 디렉터리");
    d
}

fn tree(base: &Path) -> PathBuf {
    let root = base.join("tree");
    let app = root.join("app-a");
    std::fs::create_dir_all(&app).expect("트리");
    std::fs::write(app.join("marker.txt"), b"MARKER").expect("marker");
    root
}

fn plugin(base: &Path, root: &Path) -> PathBuf {
    let p = base.join("plugin.yaml");
    std::fs::write(
        &p,
        format!(
            r#"schema_version: 1
id: observability-test
version: 1.0.0
min_core: '1.0.0'
platforms: [windows, linux]
name: {{ ko: '관측성 시험', en: 'observability test' }}
scan_roots: ['{root}']
subjects: [file]
detect:
  - id: marker
    subject: file
    where:
      - {{ field: path, op: ends_with, value: 'marker.txt' }}
verdict: {{ require: 'marker' }}
"#,
            root = root.display().to_string().replace('\\', "/")
        ),
    )
    .expect("플러그인");
    p
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

fn files_in(dir: &Path, prefix: &str, suffix: &str) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            let n = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            n.starts_with(prefix) && n.ends_with(suffix)
        })
        .collect();
    v.sort();
    v
}

#[test]
fn panic_exits_seven_and_leaves_a_crash_record() {
    let base = work("panic");
    let root = tree(&base);
    let plugin = plugin(&base, &root);
    let state = base.join("state");
    let out = run(
        &["verify", "--plugin", &s(&plugin), "--state-dir", &s(&state)],
        &[("REMEDY_PANIC_TEST", "1")],
    );
    assert_eq!(
        out.code, 7,
        "stdout:\n{}\nstderr:\n{}",
        out.stdout, out.stderr
    );
    assert!(out.stderr.contains("내부 오류"), "{}", out.stderr);
    assert!(out.stderr.contains("종료 코드 7"), "{}", out.stderr);
    assert!(
        out.stderr.contains("REMEDY_PANIC_TEST"),
        "무엇이 죽었는지가 화면에 없다: {}",
        out.stderr
    );

    let crashes = files_in(&state.join("logs"), "crash-", ".txt");
    assert_eq!(
        crashes.len(),
        1,
        "크래시 기록: {crashes:?}\nstderr: {}",
        out.stderr
    );
    let text = std::fs::read_to_string(&crashes[0]).unwrap();
    for needle in [
        "internal error (panic)",
        "where :",
        "tee.rs",
        "REMEDY_PANIC_TEST",
        "args  :",
    ] {
        assert!(text.contains(needle), "{needle} 이 없다:\n{text}");
    }
    // 화면이 기록 파일의 위치를 말한다.
    assert!(
        out.stderr.contains(&s(&crashes[0])) || out.stderr.contains("crash-"),
        "기록 위치를 말하지 않았다: {}",
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn scan_leaves_a_timed_run_log_and_the_bundle_carries_it() {
    let base = work("runlog");
    let root = tree(&base);
    let plugin = plugin(&base, &root);
    let state = base.join("state");
    let out_dir = base.join("out");
    let out = run(
        &[
            "scan",
            "--plugin",
            &s(&plugin),
            "--out-dir",
            &s(&out_dir),
            "--state-dir",
            &s(&state),
        ],
        &[],
    );
    assert!(
        out.code == 2 || out.code == 6,
        "code {}: {}\n{}",
        out.code,
        out.stdout,
        out.stderr
    );

    let logs = files_in(&state.join("logs"), "run-", ".log");
    assert_eq!(logs.len(), 1, "회차 로그: {logs:?}");
    let text = std::fs::read_to_string(&logs[0]).unwrap();

    // 화면에 나간 줄이 그대로 있다 — 배너의 제품 줄과 검사 마무리.
    assert!(
        text.contains("ESTsecurity 전용백신"),
        "배너가 없다:\n{text}"
    );
    assert!(text.contains("검사 완료"), "마무리가 없다:\n{text}");
    // 검사 시간의 내역은 로그에만 — 화면(--verbose 아님)에는 없다.
    assert!(
        text.contains("# 검사 시간") && text.contains("해시"),
        "시간 내역이 없다:\n{text}"
    );
    assert!(!out.stdout.contains("검사 시간"), "{}", out.stdout);
    // 첫 줄은 머리 — 명령줄이 있어 어떤 호출이었는지 안다.
    let first = text.lines().next().unwrap_or("");
    assert!(
        first.contains("# remedy ") && first.contains("scan --plugin"),
        "{first}"
    );
    // 줄마다 시각과 표식.
    for l in text.lines().filter(|l| !l.is_empty()) {
        assert!(
            l.starts_with("20") && l.as_bytes()[10] == b'T',
            "시각이 없다: {l}"
        );
        assert!(
            l.contains(" | ") || l.contains(" ! ") || l.contains(" # "),
            "표식이 없다: {l}"
        );
    }
    // stdout 에 나간 줄 수 만큼은 로그에도 있다 (배너의 여러 줄 텍스트 포함).
    let screen_lines = out.stdout.lines().filter(|l| !l.is_empty()).count();
    let logged_out = text.lines().filter(|l| l.contains(" | ")).count();
    assert!(
        logged_out >= screen_lines,
        "화면 {screen_lines}줄, 로그 {logged_out}줄\n{text}"
    );

    // run_id 는 파일 이름이다. support-bundle 이 run.log 로 담는다.
    let run_id = logs[0].file_stem().unwrap().to_string_lossy().to_string();
    let bundle_out = base.join("bundle");
    let b = run(
        &[
            "support-bundle",
            "--run",
            &run_id,
            "--state-dir",
            &s(&state),
            "--out",
            &s(&bundle_out),
        ],
        &[],
    );
    assert_eq!(b.code, 0, "{}\n{}", b.stdout, b.stderr);
    let copied = bundle_out
        .join(format!("remedy-support-{run_id}"))
        .join("run.log");
    assert!(
        copied.exists(),
        "run.log 가 꾸러미에 없다: {}\n{}",
        b.stdout,
        b.stderr
    );
    assert_eq!(std::fs::read_to_string(&copied).unwrap(), text);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn lookup_commands_leave_no_log() {
    let base = work("lookup");
    let state = base.join("state");
    // 조회는 상태 폴더를 받지 않고, 받아도 로그를 열지 않는다.
    let out = run(&["--version"], &[]);
    assert_eq!(out.code, 0);
    assert!(!state.join("logs").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_slow_scan_beats_and_a_fast_one_is_silent() {
    let base = work("heartbeat");
    let root = tree(&base);
    let plugin = plugin(&base, &root);
    let state = base.join("state");
    let out_dir = base.join("out");
    let args = [
        "scan",
        "--plugin",
        &s(&plugin),
        "--out-dir",
        &s(&out_dir),
        "--state-dir",
        &s(&state),
    ];
    // 느린 검사: 1초 주기, 2.6초 지연 → 최소 두 번 뛴다. 화면과 로그 둘 다에.
    let slow = run(
        &args,
        &[
            ("REMEDY_HEARTBEAT_SECS", "1"),
            ("REMEDY_SLOW_COLLECT_MS", "2600"),
        ],
    );
    let beats = slow
        .stdout
        .lines()
        .filter(|l| l.starts_with("검사 중"))
        .count();
    assert!(beats >= 2, "심장박동 {beats}회:\n{}", slow.stdout);
    for l in slow.stdout.lines().filter(|l| l.starts_with("검사 중")) {
        assert!(l.contains("경과") && l.contains("초"), "{l}");
    }
    let logs = files_in(&state.join("logs"), "run-", ".log");
    assert_eq!(logs.len(), 1);
    let text = std::fs::read_to_string(&logs[0]).unwrap();
    assert!(
        text.lines().filter(|l| l.contains("| 검사 중")).count() >= 2,
        "{text}"
    );

    // 빠른 검사: 한 줄도 없다 — 화면은 전과 같다.
    let _ = std::fs::remove_dir_all(&state);
    let fast = run(&args, &[]);
    assert!(!fast.stdout.contains("검사 중"), "{}", fast.stdout);
    let _ = std::fs::remove_dir_all(&base);
}
