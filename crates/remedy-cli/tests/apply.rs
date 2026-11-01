//! `apply` 의 **안전장치**를 실제 바이너리로 확인한다.
//!
//! 여기서 재는 것은 대부분 **하지 않은 일**이다. `--yes` 없이 파괴하지 않았는가,
//! `--dry-run` 이 아무것도 바꾸지 않았는가, 두 번째 인스턴스가 막혔는가.
//!
//! 시험은 터미널이 아닌 곳에서 돈다. 그래서 `--yes` 없는 실행은 **거절**되는
//! 것이 정상이고, 그것 자체가 이 시험 하나다 — 무인 배포에서 승인할 사람이
//! 없는데 파괴가 진행되면 안 된다.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_remedy")
}

struct Lab {
    dir: PathBuf,
}

impl Lab {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("remedy-cli-apply-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }
    fn s(&self, rel: &str) -> String {
        self.dir.join(rel).to_string_lossy().to_string()
    }
    /// 대상 파일 하나를 만들고 그것을 겨눈 plan.json 을 쓴다.
    fn plan_with_one_target(&self) -> (String, String) {
        let target = self.s("evil.exe");
        std::fs::write(&target, b"payload").unwrap();
        let plan = serde_json::json!({
            "schema_version": 1,
            "kind": "remedy.plan",
            "run_id": "run-cli-test",
            "created": "2026-08-21T00:00:00Z",
            "host": { "hostname": "h", "os": "windows", "version": "10", "arch": "amd64" },
            "core": { "version": "0", "build": "d" },
            "plugins": [],
            "actions": [{
                "seq": 1, "op": "file.quarantine_only", "target": target,
                "because": ["payload#0"], "reversible": true, "risk": "low"
            }],
            "verdicts": ["g0"]
        });
        let path = self.s("plan.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        (path, target)
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(args: &[&str]) -> (i32, String) {
    let o = Command::new(bin())
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        // 시험은 한국어 문구를 단정한다. 기본 언어는 영어다 (2026-09-06).
        .env("REMEDY_LANG", "ko")
        .output()
        .expect("실행");
    let text = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
    (o.status.code().unwrap_or(-1), text)
}

#[test]
fn without_yes_and_without_a_terminal_it_refuses() {
    // **무인 배포에서 승인할 사람이 없다.** 조용히 진행하는 것보다 아무것도
    // 하지 않는 편이 낫다.
    let lab = Lab::new("noyes");
    let (plan, target) = lab.plan_with_one_target();
    let (code, out) = run(&["apply", "--plan", &plan, "--state-dir", &lab.s("state")]);

    assert_eq!(code, 2, "하지 않았으면 2 여야 한다\n{out}");
    assert!(out.contains("승인할 사람이 없습니다"), "{out}");
    assert!(Path::new(&target).exists(), "승인 없이 파일이 사라졌다");
}

#[test]
fn dry_run_changes_nothing_and_says_so() {
    let lab = Lab::new("dryrun");
    let (plan, target) = lab.plan_with_one_target();
    let (code, out) = run(&[
        "apply",
        "--plan",
        &plan,
        "--state-dir",
        &lab.s("state"),
        "--dry-run",
        "--yes",
    ]);

    assert_eq!(code, 2, "{out}");
    assert!(out.contains("아무것도 변경하지 않았습니다"), "{out}");
    assert!(Path::new(&target).exists(), "드라이런이 파일을 지웠다");
    assert!(
        !Path::new(&lab.s("state/quarantine")).exists(),
        "드라이런이 격리소를 만들었다"
    );
}

#[test]
fn dry_run_wins_over_yes() {
    // 둘 다 주면 **덜 위험한 쪽**이 이긴다. 반대면 `--dry-run` 을 붙인 실행이
    // 파괴하고, 그것은 이 플래그를 붙인 이유와 정반대다.
    let lab = Lab::new("bothflags");
    let (plan, target) = lab.plan_with_one_target();
    let (code, _) = run(&[
        "apply",
        "--plan",
        &plan,
        "--state-dir",
        &lab.s("state"),
        "--yes",
        "--dry-run",
    ]);
    assert_eq!(code, 2);
    assert!(Path::new(&target).exists());
}

#[test]
fn with_yes_it_quarantines_and_reports_how_to_undo() {
    let lab = Lab::new("yes");
    let (plan, target) = lab.plan_with_one_target();
    let (code, out) = run(&[
        "apply",
        "--plan",
        &plan,
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);

    assert_eq!(code, 1, "치료 완료는 1 이다\n{out}");
    assert!(!Path::new(&target).exists(), "원본이 남아 있다\n{out}");
    // **되돌리는 법을 반드시 알려 준다.** 모르면 격리는 삭제와 같다.
    assert!(out.contains("remedy restore --run"), "{out}");
    assert!(Path::new(&lab.s("state/quarantine")).exists());
}

#[test]
fn a_second_instance_is_blocked_by_the_mutex() {
    // 두 인스턴스가 같은 상태 디렉터리에서 돌면 저널과 격리소가 깨진다.
    let lab = Lab::new("mutex");
    let (plan, _) = lab.plan_with_one_target();
    let state = lab.s("state");

    // 첫 번째를 잡아 둔 채로 CLI 를 부른다.
    std::fs::create_dir_all(&state).unwrap();
    let held = remedy_core::RunLock::acquire(Path::new(&state)).expect("잠금");

    let (code, out) = run(&["apply", "--plan", &plan, "--state-dir", &state, "--yes"]);
    assert_eq!(code, 5, "뮤텍스 중단은 가드다(5)\n{out}");
    assert!(out.contains("이미 돌고 있습니다"), "{out}");

    drop(held);
}

#[test]
fn progress_events_are_ndjson_and_separate_from_human_output() {
    // GUI 셸과 무인 배포가 읽는 것이다. 사람 쪽 문구를 파싱하게 만들면 그 문구가
    // 사실상 API 가 된다.
    let lab = Lab::new("events");
    let (plan, _) = lab.plan_with_one_target();
    let events = lab.s("events.ndjson");
    let (code, out) = run(&[
        "apply",
        "--plan",
        &plan,
        "--state-dir",
        &lab.s("state"),
        "--yes",
        "--events",
        &events,
    ]);
    assert_eq!(code, 1, "{out}");

    let text = std::fs::read_to_string(&events).expect("이벤트 파일");
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(lines.len() >= 4, "이벤트가 너무 적다: {text}");

    let kinds: Vec<String> = lines
        .iter()
        .map(|l| {
            let v: serde_json::Value =
                serde_json::from_str(l).unwrap_or_else(|e| panic!("NDJSON 이 아니다: {l}\n{e}"));
            v["event"].as_str().unwrap_or("?").to_string()
        })
        .collect();
    assert_eq!(
        kinds.first().map(String::as_str),
        Some("started"),
        "{kinds:?}"
    );
    assert!(kinds.contains(&"backed_up".to_string()), "{kinds:?}");
    assert!(kinds.contains(&"action".to_string()), "{kinds:?}");
    assert_eq!(
        kinds.last().map(String::as_str),
        Some("finished"),
        "{kinds:?}"
    );
}

#[test]
fn a_plan_with_no_actions_does_not_take_the_lock_or_ask() {
    // 할 일이 없는데 승인 화면을 띄우면, 사람은 그 화면을 읽지 않게 된다.
    let lab = Lab::new("noaction");
    let plan = serde_json::json!({
        "schema_version": 1, "kind": "remedy.plan", "run_id": "r", "created": "t",
        "host": { "hostname": "h", "os": "windows", "version": "10", "arch": "amd64" },
        "core": { "version": "0", "build": "d" }, "plugins": [],
        "actions": [], "verdicts": []
    });
    let path = lab.s("plan.json");
    std::fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();

    let (code, out) = run(&["apply", "--plan", &path, "--state-dir", &lab.s("state")]);
    assert_eq!(code, 0, "위협이 없으면 0 이다\n{out}");
    assert!(out.contains("수행할 항목이 없습니다"), "{out}");
}

#[test]
fn a_scan_envelope_is_not_a_plan() {
    let lab = Lab::new("wrongenvelope");
    let (plan, _) = lab.plan_with_one_target();
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&plan).unwrap()).unwrap();
    v["kind"] = serde_json::json!("remedy.scan");
    std::fs::write(&plan, serde_json::to_vec(&v).unwrap()).unwrap();

    let (code, _) = run(&[
        "apply",
        "--plan",
        &plan,
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_ne!(code, 1, "scan 봉투를 계획으로 수행했다");
}

// ─────────────────────────────────────── 크래시 뒤 재기동 (P6, 설계-09 §P6)
//
// **프로세스를 진짜로 죽인다.** `kill` 은 Windows 에서 `TerminateProcess`,
// Unix 에서 `SIGKILL` 이라 소멸자도 unwinding 도 없다 — 전원이 나간 것과 같다.
// 죽이는 자리는 진행 이벤트로 잡는다: `action` 은 나왔는데 `finished` 는 아직인
// 순간이 곧 파괴 도중이다.

impl Lab {
    /// 대상 `n` 건짜리 계획. 파괴 한 건마다 저널 fsync 가 한 번이므로, 건수가
    /// 곧 죽일 수 있는 시간 창이다.
    fn plan_with_many(&self, n: u32) -> (String, Vec<String>) {
        let mut targets = Vec::new();
        let mut actions = Vec::new();
        for i in 0..n {
            let t = self.s(&format!("evil-{i:04}.exe"));
            std::fs::write(&t, format!("payload {i}").as_bytes()).unwrap();
            actions.push(serde_json::json!({
                "seq": i + 1, "op": "file.quarantine_only", "target": t,
                "because": ["payload#0"], "reversible": true, "risk": "low"
            }));
            targets.push(t);
        }
        let plan = serde_json::json!({
            "schema_version": 1, "kind": "remedy.plan", "run_id": "run-crash",
            "created": "2026-08-21T00:00:00Z",
            "host": { "hostname": "h", "os": "windows", "version": "10", "arch": "amd64" },
            "core": { "version": "0", "build": "d" }, "plugins": [],
            "actions": actions, "verdicts": ["g0"]
        });
        let path = self.s("plan.json");
        std::fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
        (path, targets)
    }
}

/// 파괴가 시작되기를 기다릴 최대 시간.
///
/// **넉넉해야 한다.** 자식은 400건을 담고(격리 컨테이너 + 저널 fsync) 나서야
/// 첫 파괴를 시작한다. 그 백업 단계는 파일 시스템에 따라 몇 초에서 몇십 초까지
/// 걸린다 — WSL 에서 저장소가 `/mnt/d`(9p) 위에 있으면 특히 그렇다.
///
/// 예산이 짧으면 **파괴가 시작되기도 전에 죽이고**, 그러면 이 시험은 아무것도
/// 재지 못한다. 실측 2026-08-29: 고정 반복 20,000회(≈4초)가 WSL 에서 두 번
/// 모자랐다.
///
/// 이벤트를 보는 즉시 빠져나오므로 **빠른 기계에서는 이 값이 비용이 아니다.**
const WAIT_FOR_DESTRUCTION: std::time::Duration = std::time::Duration::from_secs(30);

/// 관찰 간격.
///
/// **200µs 로 돌리면 폴링이 자식과 파일 시스템을 다툰다.** 기다리는 대상을
/// 느리게 만드는 관찰이다. 1ms 면 파괴 구간(건마다 fsync 한 번, 400건)에 견줘
/// 충분히 촘촘하다.
const POLL: std::time::Duration = std::time::Duration::from_millis(1);

/// 관찰이 왜 실패했는가. **두 방향은 고쳐야 할 것이 다르다.**
enum MissedWhy {
    /// 예산 안에 파괴가 시작되지 않았다 — 백업 단계가 느리다.
    NeverStarted,
    /// 관찰과 `kill()` 사이에 자식이 끝냈다 — 창이 좁다.
    AlreadyDone,
}

/// 파괴 도중에 죽인다. 돌아오는 값은 그때까지 나온 이벤트 종류다.
fn kill_mid_destruction(args: &[&str], events: &str) -> (Vec<String>, Option<MissedWhy>) {
    let mut child = Command::new(bin())
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        // 시험은 한국어 문구를 단정한다. 기본 언어는 영어다 (2026-09-06).
        .env("REMEDY_LANG", "ko")
        .spawn()
        .expect("실행");
    let mut seen: Vec<String>;
    let deadline = std::time::Instant::now() + WAIT_FOR_DESTRUCTION;
    let mut why = Some(MissedWhy::NeverStarted);
    loop {
        seen = std::fs::read_to_string(events)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .ok()
                    .and_then(|v| v["event"].as_str().map(str::to_string))
            })
            .collect();
        if seen.iter().any(|e| e == "finished") {
            why = Some(MissedWhy::AlreadyDone);
            break;
        }
        if seen.iter().any(|e| e == "action") {
            // 파괴가 시작됐다. 여기서 죽이는 것이 이 시험의 목적이고, 그래도
            // 늦을 수 있다 — 그때는 아래 판정이 `AlreadyDone` 으로 가른다.
            why = None;
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(POLL);
    }
    let _ = child.kill();
    let _ = child.wait();
    (seen, why)
}

#[test]
fn a_killed_run_is_picked_up_where_it_stopped() {
    // **관찰이 경쟁이다.** `action` 이벤트를 본 뒤 `kill()` 이 닿기까지 사이에
    // 자식이 400건을 다 끝낼 수 있다. 그때 재는 것은 제품이 아니라 관찰의
    // 실패이므로 **다시 본다** — 실험대는 이름이 같아도 매번 새로 만들어진다.
    //
    // 2026-08-27 (P12 마감) 에 드러났다. 그전까지 Linux 에서는 이 Op 들이 전부
    // 미룸이라 파괴가 일어나지 않았고, 게이트가 오르며 **처음으로 진짜 일을
    // 하게 되자** 그 창이 좁아졌다.
    for attempt in 1..=4 {
        if crash_and_resume(attempt == 4) {
            return;
        }
    }
}

/// 한 번 시도한다. 관찰에 성공하고 이어받기까지 확인했으면 `true`.
///
/// `last` 면 관찰 실패도 그대로 실패로 낸다 — 조용히 넘어가면 이 시험이 아무것도
/// 재지 않는 검사로 바뀐다.
fn crash_and_resume(last: bool) -> bool {
    use std::collections::BTreeMap;
    let lab = Lab::new("crash");
    let state = lab.s("state");
    let events = lab.s("events.ndjson");
    let (plan, targets) = lab.plan_with_many(400);
    let before: BTreeMap<&String, Vec<u8>> = targets
        .iter()
        .map(|t| (t, std::fs::read(t).unwrap()))
        .collect();

    let (seen, mut why) = kill_mid_destruction(
        &[
            "apply",
            "--plan",
            &plan,
            "--state-dir",
            &state,
            "--yes",
            "--events",
            &events,
        ],
        &events,
    );
    let killed_at = targets.iter().filter(|t| !Path::new(t).exists()).count();
    // 이벤트를 봤어도 `kill()` 이 닿기 전에 끝났을 수 있다. 대상이 그것을 말한다.
    if why.is_none() && (killed_at == 0 || killed_at == targets.len()) {
        why = Some(if killed_at == 0 {
            MissedWhy::NeverStarted
        } else {
            MissedWhy::AlreadyDone
        });
    }
    if let Some(w) = why {
        // **두 방향을 구분해 적는다.** 한동안 둘이 같은 문구를 냈고, 그래서
        // 실패를 보고도 무엇을 고쳐야 할지 알 수 없었다 (2026-08-29).
        let what = match w {
            MissedWhy::NeverStarted => format!(
                "{WAIT_FOR_DESTRUCTION:?} 안에 파괴가 시작되지 않았다 — \
                 백업 단계가 그보다 느리다. 예산을 늘릴 것"
            ),
            MissedWhy::AlreadyDone => "관찰과 kill 사이에 자식이 끝냈다 — 창이 좁다".to_string(),
        };
        assert!(
            !last,
            "네 번 시도했는데 파괴 도중에 죽이지 못했다 — 이 시험은 아무것도 \
             재지 못한다.\n  왜: {what}\n  이벤트: {seen:?} · 사라진 대상 {killed_at}/{}건",
            targets.len()
        );
        return false;
    }

    // **잠금 파일은 남아 있다.** OS 가 잠금을 풀어 주지 않으면 여기서 막힌다 —
    // 크래시 한 번에 그 기계는 재부팅 전까지 아무것도 못 고치게 된다.
    assert!(
        Path::new(&lab.s("state/remedy.lock")).exists(),
        "잠금 파일이 없다"
    );

    let resume_events = lab.s("resume.ndjson");
    let (code, out) = run(&[
        "apply",
        "--plan",
        &plan,
        "--state-dir",
        &state,
        "--yes",
        "--events",
        &resume_events,
    ]);
    assert_eq!(code, 1, "이어서 수행하면 치료 완료(1)다\n{out}");
    assert!(out.contains("이전 실행을 이어받았습니다"), "{out}");

    // **기계 쪽에도 말해야 한다.** `started{actions:400}` 뒤에 `action` 이 몇 건만
    // 오면, 읽는 쪽은 나머지가 조용히 빠졌다고 읽는다.
    let text = std::fs::read_to_string(&resume_events).expect("이벤트 파일");
    let ev: Vec<serde_json::Value> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("NDJSON"))
        .collect();
    let resumed = ev
        .iter()
        .find(|v| v["event"] == "resumed")
        .unwrap_or_else(|| panic!("resumed 이벤트가 없다: {text}"));
    let already = resumed["already"].as_u64().unwrap() as usize;
    // 사라진 파일 수와 **한 건까지 어긋날 수 있다.** 파괴와 저널 기록 사이에서
    // 죽으면 파일은 없는데 결과는 안 적힌 상태가 되기 때문이다. 그 한 건이 곧
    // 이 시험이 겨누는 자리다 — 두 건 이상 어긋나면 순서가 틀린 것이다.
    assert!(
        already == killed_at || already + 1 == killed_at,
        "결과가 남은 것은 {already}건인데 사라진 파일은 {killed_at}건이다"
    );
    assert_eq!(resumed["remaining"], (targets.len() - already) as u64);
    assert_eq!(resumed["redo_backup"], false, "격리소는 이미 있다");
    assert!(
        out.contains(&format!("{}건 수행 완료", targets.len())),
        "결과가 run 전체를 담지 않았다\n{out}"
    );
    assert!(
        targets.iter().all(|t| !Path::new(t).exists()),
        "이어받았는데 남은 대상이 있다"
    );

    // **되돌릴 수 있어야 한다.** 이어받은 실행이 격리소를 새로 만들었다면 이미
    // 지워진 앞쪽 원본은 그 안에 없고, 여기서 드러난다.
    let (code, out) = run(&[
        "restore",
        "--run",
        "run-crash",
        "--state-dir",
        &state,
        "--yes",
    ]);
    assert_eq!(code, 0, "{out}");
    for (t, body) in &before {
        assert_eq!(
            &std::fs::read(t).unwrap_or_default(),
            body,
            "{t} 이 원본과 다르다"
        );
    }

    // 그리고 같은 계획을 또 부르면 **막는다.** 두 번 수행하면 격리소를 새 키로
    // 덮어써 방금 되살린 원본을 영영 못 연다.
    let (code, out) = run(&["apply", "--plan", &plan, "--state-dir", &state, "--yes"]);
    assert_eq!(code, 5, "이미 수행된 계획은 가드가 막는다(5)\n{out}");
    assert!(out.contains("이미 수행된 계획"), "{out}");
    true
}

#[test]
fn a_travelling_plan_that_touches_removable_media_is_refused_unattended() {
    // 계획은 **다른 기계에서 만들어져 올 수 있다.** `run --yes` 는 애초에 이런
    // Action 을 만들지 않지만(계획기가 거른다), `apply --plan` 은 남의 계획을
    // 받는다. 그때 막는 자리가 여기다.
    //
    // 드라이브 문자는 재사용된다 — 스냅샷을 뜬 시점의 `E:` 와 지금의 `E:` 가
    // 같은 매체라는 보장이 없고, 그것을 확인할 수 있는 것은 눈앞의 사람뿐이다
    // (설계-03 §4).
    let lab = Lab::new("removable");
    let target = lab.s("on-usb.exe");
    std::fs::write(&target, b"payload").unwrap();
    let plan = serde_json::json!({
        "schema_version": 1,
        "kind": "remedy.plan",
        "run_id": "run-removable",
        "created": "2026-08-22T00:00:00Z",
        "host": { "hostname": "h", "os": "windows", "version": "10", "arch": "amd64" },
        "core": { "version": "0", "build": "d" },
        "plugins": [],
        "actions": [{
            "seq": 1, "op": "file.quarantine_only", "target": target,
            "because": ["payload#0"], "reversible": true, "risk": "low",
            "user_impact": { "kind": "removable_media", "note": "이동식 매체 'E:\' 위에 있다" }
        }],
        "verdicts": ["g0"]
    });
    let path = lab.s("plan.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();

    let (code, out) = run(&[
        "apply",
        "--plan",
        &path,
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 5, "가드가 막아야 한다 (종료 코드 5): {out}");
    assert!(out.contains("이동식 매체"), "{out}");
    // **아무것도 파괴되지 않았다.**
    assert!(
        Path::new(&target).exists(),
        "거부했는데 대상이 사라졌다: {out}"
    );
}

#[test]
fn an_ordinary_plan_is_still_accepted_unattended() {
    // 위 시험이 "--yes 를 언제나 막는다" 로 통과하면 안 된다.
    let lab = Lab::new("ordinary");
    let (plan, target) = lab.plan_with_one_target();
    let (code, out) = run(&[
        "apply",
        "--plan",
        &plan,
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 1, "치료됐어야 한다: {out}");
    assert!(!Path::new(&target).exists(), "격리되지 않았다: {out}");
}

// ─────────────────────────────────────────────── resume (P9)

#[test]
fn apply_leaves_the_approved_plan_where_resume_can_find_it() {
    // **`resume` 은 `--plan` 을 받지 않는다** — 크래시나 재부팅 뒤에 사람이나 배포
    // 도구가 run_id 만으로 부른다(RunOnce 가 심는 것은 `verify` 뿐이다). "저장된
    // 계획으로 재개" 가 성립하려면 그 저장이 apply 에서 일어나야 한다 (설계-00 §6).
    let lab = Lab::new("planpersist");
    let (plan, _) = lab.plan_with_one_target();
    let (code, out) = run(&[
        "apply",
        "--plan",
        &plan,
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 1, "{out}");
    let saved = lab.s("state/plan/run-cli-test.json");
    assert!(Path::new(&saved).exists(), "계획이 남지 않았다\n{out}");

    // 남긴 것이 **승인된 그 계획**이어야 한다. 다른 것을 남기면 이어받은
    // 실행이 사용자가 승인하지 않은 일을 한다.
    //
    // **바이트가 아니라 뜻으로 견준다.** 저장되는 것은 파싱된 정규형이라
    // 생략된 필드(`observation` 등)가 기본값으로 채워진다. 재야 할 성질은
    // "같은 파일인가" 가 아니라 **"이어받을 수 있는가"** 다 — 저널의
    // `plan_sha256` 이 그것을 판정하므로, 저장된 계획을 다시 넣었을 때
    // "다른 계획이다" 가 아니라 "이미 수행됐다" 가 나와야 한다.
    let a: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&plan).unwrap()).unwrap();
    let b: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&saved).unwrap()).unwrap();
    assert_eq!(a["actions"], b["actions"], "Action 이 달라졌다");
    assert_eq!(a["run_id"], b["run_id"]);
    assert_eq!(a["verdicts"], b["verdicts"]);

    let (_, again) = run(&[
        "apply",
        "--plan",
        &saved,
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert!(
        again.contains("이미 수행된"),
        "저장된 계획이 같은 것으로 인정되지 않는다\n{again}"
    );
}

#[test]
fn resume_without_a_saved_plan_says_so_instead_of_scanning() {
    // **절대 재스캔하지 않는다.** 계획이 없으면 이어받을 것이 없다고 말할
    // 뿐이고, 새로 스캔해서 다른 계획을 만들어 내면 사용자가 승인한 것과
    // 다른 일이 벌어진다 (불변식 P 의 연장).
    let lab = Lab::new("resume-empty");
    let (code, out) = run(&["resume", "--state-dir", &lab.s("state")]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("이어서 수행할 실행이 없습니다"), "{out}");
}

#[test]
fn resume_refuses_a_run_whose_plan_is_gone() {
    // 저널만 있고 계획이 없으면 **모르는 채로 진행하지 않는다.**
    let lab = Lab::new("resume-noplan");
    std::fs::create_dir_all(lab.s("state/journal")).unwrap();
    std::fs::write(lab.s("state/journal/ghost.jsonl"), b"").unwrap();
    let (code, out) = run(&["resume", "--run", "ghost", "--state-dir", &lab.s("state")]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("저장된 계획이 없어"), "{out}");
}

#[test]
fn a_finished_run_is_not_resumed() {
    // 끝난 실행을 다시 집으면 이미 한 일을 또 한다.
    let lab = Lab::new("resume-done");
    let (plan, _) = lab.plan_with_one_target();
    let (code, _) = run(&[
        "apply",
        "--plan",
        &plan,
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 1);
    let (code, out) = run(&["resume", "--state-dir", &lab.s("state"), "--yes"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("이어서 수행할 실행이 없습니다"), "{out}");
}

#[test]
fn a_run_that_stopped_right_before_its_end_is_finished_by_resume() {
    // 결과는 전부 적혔는데 `End` 가 없는 회차다 — 실행기 시험이 진짜 크래시로
    // 이 상태를 만든다(`a_run_that_stopped_after_its_last_result_is_finished_…`).
    // 여기서 재는 것은 **`resume` 이 그 회차를 끝내는가**다. 한동안 "이미 수행된
    // 계획" 으로 거부해(종료 코드 5) 영영 끝나지 않았다 (결정 자료 다1).
    let lab = Lab::new("resume-tail");
    let (plan, target) = lab.plan_with_one_target();
    let state = lab.s("state");
    let (code, _) = run(&["apply", "--plan", &plan, "--state-dir", &state, "--yes"]);
    assert_eq!(code, 1);

    // `End` 한 줄을 떼어 낸다. 이 계획은 재검사를 원하지 않으므로 그 앞 줄이
    // 마지막 결과다 — 7단계가 아무것도 적지 않는 회차의 꼬리 창이다.
    let journal = lab.s("state/journal/run-cli-test.jsonl");
    let text = std::fs::read_to_string(&journal).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    assert!(
        lines.pop().is_some_and(|l| l.contains(r#""rec":"end""#)),
        "{text}"
    );
    assert!(
        lines
            .last()
            .is_some_and(|l| l.contains(r#""rec":"outcome""#)),
        "{text}"
    );
    std::fs::write(&journal, lines.join("\n") + "\n").unwrap();

    let (code, out) = run(&["resume", "--state-dir", &state, "--yes"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("이전 실행을 이어받았습니다. 1건은 이미 끝나 있었습니다."),
        "{out}"
    );
    let after = std::fs::read_to_string(&journal).unwrap();
    assert!(
        after
            .lines()
            .last()
            .is_some_and(|l| l.contains(r#""rec":"end""#)),
        "{after}"
    );

    // 이제 끝난 회차다 — 다시 불러도 이어받을 것이 없다.
    let (code, out) = run(&["resume", "--state-dir", &state, "--yes"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("이어서 수행할 실행이 없습니다"), "{out}");
    assert!(!Path::new(&target).exists(), "대상이 되살아났다");
}

#[test]
fn apply_without_a_plugin_path_does_not_promise_the_automatic_check() {
    // **지킬 수 없는 약속을 하지 않는다** (P12 D4) — 기계만이 아니라 부른 명령도
    // 본다. `apply --plan` 은 플러그인 경로를 모르므로 재부팅 뒤 재검사를 예약할
    // 수 없는데, 승인 전 화면은 "자동으로 한 번 더 검사합니다" 를 약속하고 실행
    // 뒤 경고가 그것을 바로잡았다 (결정 자료 나1 · 2026-09-29 실측). `resume` 도
    // 같은 길(`run_apply`)을 지난다.
    let lab = Lab::new("promise-no-plugin");
    let (plan, _) = lab.plan_with_one_target();
    let text = std::fs::read_to_string(&plan).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["verify_after_reboot"] = serde_json::Value::Bool(true);
    std::fs::write(&plan, serde_json::to_vec_pretty(&v).unwrap()).unwrap();

    let (code, out) = run(&[
        "apply",
        "--plan",
        &plan,
        "--dry-run",
        "--yes",
        "--state-dir",
        &lab.s("state"),
    ]);
    assert_eq!(code, 2, "{out}");
    assert!(
        !out.contains("자동으로 한 번 더 검사합니다"),
        "걸 수 없는데 약속했다:\n{out}"
    );
    assert!(
        out.contains("직접 부를 명령을 알려 드립니다"),
        "할 일을 말하지 않았다:\n{out}"
    );
    // 이유는 기계가 먼저다 — 걸 수 없는 기계(리눅스 CI 컨테이너: systemd 가 init 이
    // 아니다)에서는 그쪽 이유가 나온다. 기계가 걸 수 있는 곳에서만 이 실행이
    // 플러그인 경로를 모른다는 이유를 단정한다.
    if remedy_core::restart::verify_after_reboot_support().is_ok() {
        assert!(
            out.contains("플러그인 경로를 모릅니다"),
            "이유를 말하지 않았다:\n{out}"
        );
    }
}

// ─────────────────────────────────────── 출력 인코딩 · 언어 (P9)

#[test]
fn file_output_is_utf8_without_a_bom_whatever_the_console_is() {
    // **한글 Windows 콘솔의 기본 코드페이지에 맞춰 쓰면 파일로 리다이렉트했을
    // 때 깨진다** (설계-00 §5-2). 그리고 BOM 을 붙이면 serde_json 을 비롯한
    // 파서가 거부한다.
    let lab = Lab::new("utf8");
    let (plan, _) = lab.plan_with_one_target();
    let (code, _) = run(&[
        "apply",
        "--plan",
        &plan,
        "--state-dir",
        &lab.s("state"),
        "--yes",
    ]);
    assert_eq!(code, 1);

    let saved = lab.s("state/plan/run-cli-test.json");
    let bytes = std::fs::read(&saved).unwrap();
    assert!(
        !bytes.starts_with(&[0xEF, 0xBB, 0xBF]),
        "BOM 이 붙었다 — 파서가 거부한다"
    );
    // 코드페이지로 썼다면 여기서 깨진다.
    let text = std::str::from_utf8(&bytes).expect("UTF-8 이 아니다");
    assert!(text.contains("run-cli-test"));
}

#[test]
fn the_plan_render_follows_the_requested_language() {
    // **계획 렌더러는 두 언어로 나온다** (설계-09 P9). CLI 자신의 문구는 아직
    // 한국어뿐이고 그것은 알려진 한계다 — 여기서 재는 것은 렌더러다.
    let lab = Lab::new("lang");
    let (plan, _) = lab.plan_with_one_target();
    let state = lab.s("state");

    let (_, ko_out) = run(&[
        "apply",
        "--plan",
        &plan,
        "--dry-run",
        "--yes",
        "--lang",
        "ko",
        "--state-dir",
        &state,
    ]);
    assert!(ko_out.contains("건을 수행합니다"), "{ko_out}");

    let (_, en_out) = run(&[
        "apply",
        "--plan",
        &plan,
        "--dry-run",
        "--yes",
        "--lang",
        "en",
        "--state-dir",
        &state,
    ]);
    assert!(en_out.contains("action(s) will run"), "{en_out}");
    assert!(
        !en_out.contains("건을 수행합니다"),
        "영어를 요청했는데 한국어 렌더가 나왔다\n{en_out}"
    );
}
