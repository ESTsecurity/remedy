//! 재평가 결과가 **어딘가에 남는가** (설계-03 §8, P10-F).
//!
//! # 왜 이 시험이 필요한가
//!
//! `verify_after_reboot` 가 예약한 실행에는 사람이 없다. RunOnce 는 콘솔 없이
//! 돌고, OS 는 항목을 실행 직전에 지운다. 2026-08-29 실기기 측정에서 그 실행이
//! **실제로 도는 것**은 확인했는데(프로세스 생성 감사 4688), **판정이
//! 무엇이었는지는 어디에서도 알 수 없었다** — 콘솔도 종료 코드도 파일도 없었다.
//!
//! 설계-03 §5 는 무인 배포에서 종료 코드가 "후속 조치의 트리거" 라고 적는다.
//! 받는 쪽이 없으면 그 문장이 성립하지 않는다.
//!
//! **바이너리를 실제로 띄운다.** 내부 함수를 부르면 인자 파싱을 지나지 않고,
//! 예약된 명령이 지나는 것은 정확히 그 경로다.

use std::path::PathBuf;
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_remedy");

fn lab(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("remedy-verify-record-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("작업 디렉터리");
    d
}

/// 홑따옴표 YAML 스칼라에 넣을 경로. 그 안에서 `'` 는 `''` 로 적는다 — 계정 이름에
/// 아포스트로피가 있는 기계(`C:\Users\O'Brien\…`)에서 매니페스트가 깨지지 않게.
fn sq(p: &std::path::Path) -> String {
    p.to_string_lossy().replace('\'', "''")
}

/// 아무것도 맞히지 않는 플러그인. **판정이 서지 않는 것이 이 시험의 전제다** —
/// 재평가가 `clean` 으로 끝나야 기록의 내용을 예측할 수 있다. 그러려면 관측도
/// 온전해야 하므로 상한은 **시험 폴더 자신**이다 — 작업 폴더(`.`)에 기대지 않는다.
fn plugin(dir: &std::path::Path) -> PathBuf {
    plugin_at(dir, dir)
}

/// 상한을 `root` 로 둔 같은 플러그인. 없는 폴더면 "선언한 자리가 전부 없다" 로
/// 관측이 불완전하다 — 권한과 무관하게 결정적이다.
fn plugin_at(dir: &std::path::Path, root: &std::path::Path) -> PathBuf {
    let p = dir.join("plugin.yaml");
    // **홑따옴표.** 겹따옴표 YAML 은 Windows 경로의 `\` 를 이스케이프로 읽는다.
    let yaml = r#"schema_version: 1
id: verify-record-test
version: 2.3.4
min_core: '1.0.0'
platforms: [windows, linux]
name:
  ko: "재평가 기록 시험"
  en: "verify record test"
scan_roots: ['ROOT']
subjects: [file]
detect:
  - id: never
    subject: file
    where:
      - { field: path, op: equals, value: "/nonexistent/remedy-verify-record-never" }
verdict: { require: "never" }
"#
    .replace("ROOT", &sq(root));
    std::fs::write(&p, yaml).expect("플러그인");
    p
}

/// 본문 상한(1KB)에 걸려 `probe` 의 YARA 를 **재지 못하는** 플러그인. `seen` 은
/// 무해한 파일 하나를 맞힌다 — 판정식(`require`)에 넣으면 판정이 서고(재발),
/// 빼면 치료와 무관한 증거로만 남는다.
fn yara_plugin(d: &std::path::Path, require: &str) -> PathBuf {
    let root = d.join("root");
    std::fs::create_dir_all(&root).expect("루트");
    std::fs::create_dir_all(d.join("rules")).expect("rules");
    // 표지 한 줄 + 4 KiB — 1KB 상한은 넘는다. 무해한 문자열이다.
    let probe = root.join("probe.txt");
    std::fs::write(
        &probe,
        format!("REMEDY-VERIFY-YARA-MARKER\n{}\n", "x".repeat(4096)),
    )
    .expect("표지");
    std::fs::write(root.join("seen.txt"), "nothing to see\n").expect("무해한 파일");
    std::fs::write(
        d.join("rules").join("probe.yar"),
        "rule probe_marker { strings: $a = \"REMEDY-VERIFY-YARA-MARKER\" condition: $a }\n",
    )
    .expect("룰");
    let pl = d.join("plugin.yaml");
    let yaml = r#"schema_version: 1
id: verify-record-yara
version: 1.0.0
min_core: '1.0.0'
platforms: [windows, linux]
name:
  ko: "재평가 기록 시험 (YARA)"
  en: "verify record test (yara)"
scan_roots: ['ROOT']
subjects: [file]
collect_extra:
  - { path: 'PROBE', max_size: 1KB }
detect:
  - id: seen
    subject: file
    where:
      - { field: path, op: ends_with, value: "seen.txt" }
  - id: probe
    subject: file
    where:
      - { field: path, op: ends_with, value: "probe.txt" }
      - { yara: "rules/probe.yar:probe_marker" }
verdict: { require: "REQUIRE" }
"#
    .replace("ROOT", &sq(&root))
    .replace("PROBE", &sq(&probe))
    .replace("REQUIRE", require);
    std::fs::write(&pl, yaml).expect("플러그인");
    pl
}

fn run(args: &[&str]) -> (i32, String) {
    let o = Command::new(EXE)
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        // 시험은 한국어 문구를 단정한다. 기본 언어는 영어다 (2026-09-06).
        .env("REMEDY_LANG", "ko")
        .output()
        .expect("실행");
    let text = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
    (o.status.code().unwrap_or(-1), text)
}

/// `--run` 이 가리킬 계획 하나. `verify --run` 은 그것에서 치료 전 증거를 읽는다.
///
/// **본문을 `body` 로 감싸지 않는다.** 봉투가 `#[serde(flatten)]` 이라 감싸면
/// 통째로 무시되고 본문이 전부 기본값이 되는데 **파싱은 통과한다** — 조용히
/// 아무것도 재지 않는 픽스처가 된다 (2026-08-29 실측).
fn plant_plan(state: &std::path::Path, run_id: &str) {
    let dir = state.join("plan");
    std::fs::create_dir_all(&dir).expect("plan 디렉터리");
    std::fs::write(
        dir.join(format!("{run_id}.json")),
        r#"{"schema_version":1,"kind":"remedy.plan","run_id":"RUN","created":"2026-08-29T00:00:00Z",
            "host":{"hostname":"h","os":"windows","version":"10","arch":"amd64"},
            "core":{"version":"1.0.0","build":"test"},"plugins":[],
            "actions":[],"verdicts":[],"observation":{"truncated":false,"denied_dirs":0},
            "verify_after_reboot":true,"deferred":[]}"#
            .replace("RUN", run_id),
    )
    .expect("계획");
}

/// 그 회차의 기록 한 줄.
fn record(state: &std::path::Path, run_id: &str) -> (serde_json::Value, String) {
    let line = std::fs::read_to_string(state.join("verify").join(format!("{run_id}.jsonl")))
        .expect("읽기");
    let v = serde_json::from_str(line.trim()).expect("JSON 한 줄");
    (v, line)
}

#[test]
fn a_verify_with_a_run_leaves_a_record() {
    // **이것이 재부팅 뒤 예약된 실행이 지나는 길이다.**
    let d = lab("leaves");
    let state = d.join("state");
    let pl = plugin(&d);
    plant_plan(&state, "run-x");

    let (code, text) = run(&[
        "verify",
        "--run",
        "run-x",
        "--plugin",
        pl.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "치료 성공이어야 한다\n{text}");

    let rec = state.join("verify").join("run-x.jsonl");
    assert!(rec.is_file(), "기록이 없다: {}\n{text}", rec.display());

    let (v, line) = record(&state, "run-x");
    assert_eq!(v["run_id"], "run-x");
    assert_eq!(v["outcome"], "clean");
    // **종료 코드가 함께 적혀야 한다.** 이 파일을 읽는 쪽은 프로세스를 보지
    // 못했으므로 여기서 받아야 한다 (설계-03 §5).
    assert_eq!(v["exit_code"], 0);
    assert_eq!(v["plugin_id"], "verify-record-test");
    assert_eq!(v["plugin_version"], "2.3.4");
    // 관측이 온전한 회차의 줄은 전과 같다 — 이 줄을 글자로 읽는 하네스가 있다.
    assert!(v.get("observation").is_none(), "{line}");
    assert!(
        text.contains("재평가 기록 ->"),
        "어디에 적었는지 말하지 않는다\n{text}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_incomplete_re_evaluation_is_not_treatment_success() {
    // **다 보지 못한 재평가가 "치료 성공"(0)을 말하던 자리다**(결정 2026-10-26).
    // 재부팅 뒤 자동 재검사는 사람이 없어, 그 0 이 "치료가 유지됐다" 로 읽힌다.
    let d = lab("incomplete");
    let state = d.join("state");
    let pl = plugin_at(&d, &d.join("no-such-root"));
    plant_plan(&state, "run-z");

    let (code, text) = run(&[
        "verify",
        "--run",
        "run-z",
        "--plugin",
        pl.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert_eq!(code, 6, "다 보지 못했는데 6 이 아니다\n{text}");
    assert!(
        !text.contains("치료 성공. 같은 플러그인이"),
        "다 보지 못했는데 치료 성공을 말한다\n{text}"
    );
    assert!(
        text.contains("치료를 확인하지 못했습니다"),
        "결론이 없다\n{text}"
    );
    assert!(
        text.contains("전부 존재하지 않아"),
        "왜 못 봤는지가 화면에 없다\n{text}"
    );

    // 기록이 그것을 말한다 — **무엇을 못 봤는지까지.**
    let (v, line) = record(&state, "run-z");
    assert_eq!(v["outcome"], "incomplete", "{line}");
    assert_eq!(v["exit_code"], 6, "{line}");
    let missing = &v["observation"]["missing_roots"];
    assert!(
        missing.as_array().is_some_and(|a| a
            .iter()
            .any(|r| r.as_str().is_some_and(|s| s.contains("no-such-root")))),
        "기록에 못 본 자리가 없다: {line}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_english_conclusion_does_not_say_treatment_succeeded() {
    // 기본 언어는 영어이고(2026-09-06) 예약 명령은 회차의 언어를 싣는다 — 영어
    // 무인 배포의 회차 로그가 6 인데 "Treatment succeeded" 라고 적으면 안 된다.
    let d = lab("english");
    let state = d.join("state");
    let pl = plugin_at(&d, &d.join("no-such-root"));
    plant_plan(&state, "run-e");

    let (code, text) = run(&[
        "verify",
        "--run",
        "run-e",
        "--plugin",
        pl.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
        "--lang",
        "en",
    ]);
    assert_eq!(code, 6, "{text}");
    assert!(
        text.contains("The treatment could not be confirmed"),
        "영어 결론이 없다\n{text}"
    );
    assert!(
        !text.contains("Treatment succeeded"),
        "다 보지 못했는데 영어 화면이 치료 성공을 말한다\n{text}"
    );
    let (v, line) = record(&state, "run-e");
    assert_eq!(v["outcome"], "incomplete", "{line}");

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_yara_rule_it_could_not_measure_says_why_on_the_verify_screen() {
    // 재지 못한 YARA 도 다 보지 못한 것이다(결정 2026-10-26). **왜 못 쟀는지**도
    // 재검사 화면에 있어야 한다 — `scan` 은 "해소되지 않았습니다" 블록으로 말하는데
    // 재검사는 그 목록을 버렸고, 재부팅 회차에는 그 화면(회차 로그)이 전부다.
    //
    // 판정식은 `probe` 뿐이라 `seen` 의 증거는 치료와 무관한 증거로 남는다 —
    // 증거가 있어도 불완전은 불완전이다(0건일 때만의 이야기가 아니다).
    let d = lab("yara");
    let state = d.join("state");
    let pl = yara_plugin(&d, "probe");
    plant_plan(&state, "run-w");

    let (code, text) = run(&[
        "verify",
        "--run",
        "run-w",
        "--plugin",
        pl.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert_eq!(code, 6, "재지 못했는데 6 이 아니다\n{text}");
    assert!(
        text.contains("YARA 규칙 1개를 평가하지 못했습니다"),
        "무엇을 못 쟀는지가 없다\n{text}"
    );
    assert!(
        text.contains("해소되지 않았습니다") && text.contains("상한"),
        "왜 못 쟀는지(본문 상한)가 재검사 화면에 없다\n{text}"
    );
    assert!(
        text.contains("치료를 확인하지 못했습니다"),
        "결론이 없다\n{text}"
    );

    let (v, line) = record(&state, "run-w");
    assert_eq!(v["outcome"], "incomplete", "{line}");
    assert_eq!(v["exit_code"], 6, "{line}");
    assert!(
        v["observation"]["unevaluated_rules"]
            .as_array()
            .is_some_and(|a| a.iter().any(|r| r == "rules/probe.yar:probe_marker")),
        "기록에 못 잰 규칙이 없다: {line}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_recurrence_on_an_incomplete_re_evaluation_still_says_what_was_not_seen() {
    // **찾은 것이 먼저다** — 판정이 다시 서면 다 보지 못했어도 재발(2)이다. 그래도
    // 기록과 화면은 무엇을 · 왜 못 봤는지를 싣는다: 사람 없는 회차에서 "그 재발이
    // 다 본 위에서 섰는가" 를 물을 근거다. 결과가 6 일 때만 싣거나 원인 블록을 6 갈래
    // 안에서만 내면 이 시험이 진다(적대 검증).
    let d = lab("recur");
    let state = d.join("state");
    let pl = yara_plugin(&d, "seen or probe");
    plant_plan(&state, "run-r");

    let (code, text) = run(&[
        "verify",
        "--run",
        "run-r",
        "--plugin",
        pl.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert_eq!(code, 2, "판정이 섰는데 2 가 아니다\n{text}");
    assert!(text.contains("재발."), "재발 결론이 없다\n{text}");
    assert!(
        !text.contains("치료를 확인하지 못했습니다"),
        "재발인데 6 의 결론을 말한다\n{text}"
    );
    assert!(
        text.contains("YARA 규칙 1개를 평가하지 못했습니다"),
        "재발 화면에 무엇을 못 봤는지가 없다\n{text}"
    );
    assert!(
        text.contains("해소되지 않았습니다") && text.contains("상한"),
        "재발 회차에서 원인 블록이 빠졌다\n{text}"
    );

    let (v, line) = record(&state, "run-r");
    assert_eq!(v["outcome"], "recurred", "{line}");
    assert_eq!(v["exit_code"], 2, "{line}");
    assert!(
        v["verdicts"].as_array().is_some_and(|a| !a.is_empty()),
        "{line}"
    );
    assert!(
        v["observation"]["unevaluated_rules"]
            .as_array()
            .is_some_and(|a| a.iter().any(|r| r == "rules/probe.yar:probe_marker")),
        "재발 기록에 못 잰 규칙이 없다: {line}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_second_verify_appends_instead_of_replacing() {
    // 예약된 것 한 번, 사람이 한 번. 뒤엣것이 앞엣것을 지우면
    // **"재부팅 직후에는 무엇이었나"** 를 물을 수 없다.
    let d = lab("append");
    let state = d.join("state");
    let pl = plugin(&d);
    plant_plan(&state, "run-y");

    for _ in 0..2 {
        let (code, text) = run(&[
            "verify",
            "--run",
            "run-y",
            "--plugin",
            pl.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "{text}");
    }

    let line = std::fs::read_to_string(state.join("verify").join("run-y.jsonl")).expect("읽기");
    assert_eq!(
        line.lines().filter(|l| !l.trim().is_empty()).count(),
        2,
        "덮어썼다:\n{line}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn without_a_run_there_is_nothing_to_attach_the_record_to() {
    // `--run` 없이 부르면 재발 여부와 관측 완전성만 답한다(치료 전 증거가 없다).
    // 그때는 어느 치료에 대한 판정인지가 없으므로 **적을 자리도 없다.**
    //
    // 조용히 아무 데나 적으면 나중에 그 파일이 무엇에 대한 기록인지 아무도
    // 모른다.
    let d = lab("norun");
    let state = d.join("state");
    let pl = plugin(&d);

    let (code, text) = run(&[
        "verify",
        "--plugin",
        pl.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{text}");
    assert!(
        !state.join("verify").exists(),
        "붙일 run 이 없는데 기록을 만들었다\n{text}"
    );

    let _ = std::fs::remove_dir_all(&d);
}
