//! 실기기 치료 결과가 **지금 자료에 대해** 재어졌는가 (채점 5의 오프라인 짝).
//!
//! # 무엇을 막는 검사인가
//!
//! 채점 5(`testbed/harness/*/…exam-apply…`)는 랩 기계가 필요해서
//! `cargo xtask all` 안에서 돌 수 없다. 그래서 **아무도 안 돌리면 안 돌아간다.**
//! 지금 그것을 막는 것은 시험 출력의 다섯 번째 줄 하나뿐이다.
//!
//! 2026-09-05 에 그 구멍으로 실제로 지나갔다. `appinit-implant` 의 정답
//! 플러그인과 기대 Op 을 바꾸면서 실기기 결과가 낡았는데, **알려 주는 것이
//! 없었다** — 다시 돌린 것은 그러기로 마음먹었기 때문이지 무엇이 요구해서가
//! 아니었다.
//!
//! 그래서 위협마다 **재었다는 증거**를 저장소에 두고, 그 증거가 지금 자료와
//! 맞는지 본다.
//!
//! | 무엇이 바뀌면 | 증거가 낡는가 |
//! |---|---|
//! | 정답 플러그인 | **낡는다** — 다른 답을 잰 결과다 |
//! | `expected-ops.txt` | **낡는다** — 다른 기준으로 잰 결과다 |
//! | `must-remain.txt` | **낡는다** — 남아야 하는 자리가 달라졌다 |
//! | 치료 코드 | 낡지만 **여기서는 못 본다** (아래) |
//!
//! # 이 검사가 대신하지 못하는 것
//!
//! **코드가 바뀌어 증거가 낡는 경우는 오프라인에서 잡을 수 없다.** 바이너리는
//! 커밋되지 않으므로 견줄 것이 없고, 소스 지문으로 묶으면 무관한 커밋마다
//! 게이트가 빨개져 아무도 보지 않게 된다.
//!
//! # 증거를 손으로 쓰는 것
//!
//! 이 파일은 사람이 쓸 수 있는 JSON 이고 게이트는 그것을 읽는다. **완전히 막을
//! 수는 없다** — 하네스도 우리 코드이므로, 마음먹은 사람은 하네스를 고쳐 무엇이든
//! 적게 할 수 있다. 목표는 *"손으로 못 쓰게"* 가 아니라 *"손으로 쓴 것이 티가
//! 나게"* 다.
//!
//! 두 가지를 본다.
//!
//! **1. 재료에서 스스로 계산해 견준다.** 밟는 자리 수·남아야 하는 자리 수·내용
//! 검사 수는 `expected-ops.txt` 와 `must-remain.txt` 에서 나오는 값이다. 게이트가
//! 그것을 직접 세어 증거의 수와 맞춰 본다. 그래서 **다른 위협의 증거를 베껴 오면
//! 즉시 걸린다** — 지문만 고쳐서는 그 수들이 맞지 않는다.
//!
//! 그리고 합격한 회차는 세 수가 전부 N/N 이어야 한다. 못 잰 자리가 하나라도
//! 있으면 두 하네스가 미결로 내리기 때문이다.
//!
//! **2. 기계만 낼 수 있는 흔적을 본다.** 세 단계의 시각·상태 지문·항목 수와
//! 기계 이름이다. 서로 아귀가 맞아야 하므로, 지어내려면 그럴듯한 기계 한 대를
//! 통째로 지어내야 한다.
//!
//! `snapshots` 검사가 같은 자리에서 같은 말을 한다 — *"그것까지 잡으려면
//! 실기기에서 다시 뜨는 수밖에 없다. 이 검사는 그 자리를 대신하지 않고
//! 오프라인에서 잡을 수 있는 것만 잡는다."* 증거에 바이너리 지문과 시각을
//! 적어 두는 것은 사람이 그 판단을 할 수 있게 하기 위해서다.

use serde_json::Value;
use std::path::Path;

/// 이 위협의 재료가 말하는 수 — 밟는 자리 · 남아야 하는 자리 · 내용 검사.
///
/// **하네스가 적은 수를 믿지 않고 여기서 다시 센다.** 두 하네스가 같은 규칙으로
/// 범위를 만들므로 그 규칙을 여기 한 번 더 적으면 셋이 서로를 붙든다.
struct Counted {
    places: usize,
    content: usize,
    must_remain: usize,
}

fn is_registry(target: &str) -> bool {
    let t = target.to_ascii_uppercase();
    ["HKLM\\", "HKCU\\", "HKCR\\", "HKCC\\", "HKU\\"]
        .iter()
        .any(|h| t.starts_with(h))
}

fn count_from_materials(dir: &Path) -> Result<Counted, String> {
    use std::collections::BTreeSet;
    let ops = std::fs::read_to_string(dir.join("expected-ops.txt"))
        .map_err(|e| format!("{}/expected-ops.txt 를 읽지 못했다: {e}", dir.display()))?;

    let mut places: BTreeSet<String> = BTreeSet::new();
    let mut content: BTreeSet<String> = BTreeSet::new();
    for line in ops.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (body, matcher) = match t.split_once(" :: ") {
            Some((b, m)) => (b.trim(), m.trim()),
            None => (t, ""),
        };
        let Some((op, target)) = body.split_once(' ') else {
            continue;
        };
        let target = target.trim();
        // `process.kill` 의 대상은 술어다 — 밟는 자리가 아니다.
        if target.is_empty() || target == "-" {
            continue;
        }
        places.insert(target.to_lowercase());

        // 내용 검사가 붙는 자리: **고치는 Op** 의 **파일** 대상에 매치가 있을 때.
        let edits = remedy_sdk::catalog::Op::ALL
            .iter()
            .find(|o| o.id() == op)
            .is_some_and(|o| o.edits_in_place());
        if edits && !matcher.is_empty() && !is_registry(target) {
            content.insert(target.to_lowercase());
        }
    }
    if places.is_empty() {
        return Err(format!(
            "{}/expected-ops.txt 에 밟는 자리가 없다",
            dir.display()
        ));
    }

    let must = std::fs::read_to_string(dir.join("must-remain.txt"))
        .map_err(|e| format!("{}/must-remain.txt 를 읽지 못했다: {e}", dir.display()))?;
    let must_remain = must
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count();

    Ok(Counted {
        places: places.len(),
        content: content.len(),
        must_remain,
    })
}

/// 그 회차가 **기계에서 돌았다는 흔적**이 아귀가 맞는가.
///
/// 여기서 참이 나온다고 그 회차가 돌았다는 뜻은 아니다. 거짓이 나오면 **돌지
/// 않았다는 뜻**이고, 그것이 이 검사가 하는 일의 전부다.
fn trace_problems(v: &Value) -> Vec<String> {
    let mut bad = Vec::new();
    let t = &v["trace"];
    if t.is_null() {
        return vec!["회차의 흔적(trace)이 없다".to_string()];
    }
    if t["host"].as_str().unwrap_or("").trim().is_empty() {
        bad.push("기계 이름이 비었다".to_string());
    }
    if t["actions_done"].as_u64().unwrap_or(0) == 0 {
        bad.push("수행한 것이 0건이다 — 그 회차는 치료를 재지 않았다".to_string());
    }

    let stages = t["stages"].as_array().cloned().unwrap_or_default();
    let find = |name: &str| stages.iter().find(|s| s["stage"].as_str() == Some(name));
    let mut prev = String::new();
    let mut digests = Vec::new();
    for want in ["clean", "infected", "treated"] {
        let Some(s) = find(want) else {
            bad.push(format!("'{want}' 단계의 흔적이 없다"));
            continue;
        };
        let at = s["at"].as_str().unwrap_or("");
        // 사전순 비교로 충분하다 — 둘 다 `YYYY-MM-DDTHH:MM:SSZ` 다.
        if at.len() != 20 || !at.ends_with('Z') {
            bad.push(format!("'{want}' 의 시각이 이상하다 ({at})"));
        } else if !prev.is_empty() && at < prev.as_str() {
            bad.push(format!("'{want}' 가 앞 단계보다 이르다 ({prev} → {at})"));
        }
        if !at.is_empty() {
            prev = at.to_string();
        }
        let d = s["sha256"].as_str().unwrap_or("");
        if d.len() != 64 || !d.chars().all(|c| c.is_ascii_hexdigit()) {
            bad.push(format!("'{want}' 의 상태 지문이 이상하다"));
        }
        digests.push(d.to_string());
        if s["counts"].as_object().is_none_or(|c| c.is_empty()) {
            bad.push(format!("'{want}' 의 항목 수가 없다"));
        }
    }
    // 감염이 기계를 바꾸고 치료가 다시 바꾼다. 같으면 그 단계는 뜨지 않은 것이다.
    if digests.len() == 3 {
        if digests[0] == digests[1] {
            bad.push("감염 전후의 상태가 같다 — 픽스처가 아무것도 세우지 않았다".to_string());
        }
        if digests[1] == digests[2] {
            bad.push("치료 전후의 상태가 같다 — 치료가 아무것도 하지 않았다".to_string());
        }
    }
    // **`ran_at` 과는 견주지 않는다.** 단계 시각은 게스트가, `ran_at` 은
    // 호스트가 적는다. 랩 VM 은 스냅샷에서 되살아나므로 시계가 호스트보다
    // 몇 주 뒤에 있다(실측 2026-08-24 대 2026-09-06). 서로 다른 시계를 견주면
    // 정상 회차가 거짓 불합격이 된다.
    bad
}

/// 증거 파일의 판. 모양이 바뀌면 올린다 — 판이 다른 증거를 읽으면 없는 필드가
/// 기본값으로 읽히고, 그 기본값이 통과로 보이는 것이 가장 나쁘다.
/// `/2` — 정답의 지문을 파일 하나(`plugin_sha256`)에서 폴더의 **파일 지도**
/// (`plugin_files`)로 바꿨다. `evilai-locust` 의 판별자가 `rules/*.yar` 이라
/// `plugin.yaml` 만 잡으면 그 룰이 바뀌어도 증거가 낡지 않는다.
const SCHEMA: &str = "remedy-exam-apply/4";

/// 증거 파일 이름. 위협 폴더에 둔다 — 재료 옆에 있어야 재료를 고칠 때 눈에 띈다.
const RECORD: &str = "apply-result.json";

/// **한 번 재는 것으로 부족한 위협.** 위협 설명이 서로 다른 두 상태를 요구하면
/// 두 상태를 다 재고 다 기록해야 한다.
///
/// `evilai-locust` 이 그렇다 — *"실행 중인 프로세스도 다뤄야 한다 … 있을 때도
/// **없을 때도** 처리돼야 한다."* 한 쪽만 증거로 두면 **탐지가 프로세스에
/// 의존하게 되는 회귀를 이 게이트가 못 잡는다.** 두 쪽 다 실기기에서 재어졌던
/// 적은 있지만(2026-09-05) 고정된 적은 없었다.
///
/// (위협, 추가로 요구하는 증거 파일, 그 갈래를 뜨는 법)
const EXTRA_VARIANTS: &[(&str, &str, &str)] = &[(
    "evilai-locust",
    "apply-result-no-process.json",
    "-NoProcess",
)];

pub fn run(root: &Path) -> Result<(), String> {
    let threats = root.join("testbed/ai-exam/threats");
    let mut checked = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut lines: Vec<String> = Vec::new();

    // **정답의 자리는 `exam::REFERENCES` 가 안다.** 위협 폴더만 뒤지면
    // `evilai-locust` 가 정답 없는 위협으로 보인다 — 그것의 정답은 제품이 싣는
    // `plugins/evilai-locust` 이고, 그렇게 조용히 면제된 채 이 게이트가
    // "정답이 없어 못 재는 위협" 이라고 **거짓을 적고 있었다** (2026-09-05).
    let mut refs: Vec<(&str, &str)> = crate::exam::REFERENCES.to_vec();
    refs.sort();
    if refs.is_empty() {
        return Err("정답 표가 비었다. exam::REFERENCES 를 볼 것".into());
    }

    for (name, rel) in refs {
        let name = name.to_string();
        let dir = threats.join(&name);
        let plugin_dir = root.join(rel);
        let plugin = plugin_dir.join("plugin.yaml");
        if !plugin.exists() {
            errors.push(format!(
                "{name}: 정답 플러그인이 없다 ({})",
                plugin.display()
            ));
            continue;
        }

        // 이 검사는 정답 폴더 **전체**를 지문으로 삼는다. `plugin.yaml` 하나만
        // 잡으면 `rules/*.yar` 이 바뀌어도 증거가 낡지 않는데, evilai 의
        // 판별자가 정확히 그 YARA 룰이다.
        // 이 위협이 요구하는 증거 파일 전부. 대개 하나, 갈래가 둘인 위협은 둘.
        let mut wanted: Vec<(String, String)> = vec![(RECORD.to_string(), String::new())];
        for (t, file, flag) in EXTRA_VARIANTS {
            if *t == name {
                wanted.push((file.to_string(), format!(" {flag}")));
            }
        }
        let mut all_ok = true;
        for (file, flag) in &wanted {
            let record_path = dir.join(file);
            let Ok(text) = std::fs::read_to_string(&record_path) else {
                errors.push(format!(
                    "{name}: 실기기 치료 결과가 없다 ({file}).\n      {}{flag}",
                    how_to(root, &name)
                ));
                all_ok = false;
                continue;
            };
            let v: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    errors.push(format!("{name}: {file} 를 읽지 못했다: {e}"));
                    all_ok = false;
                    continue;
                }
            };
            if v["schema"].as_str() != Some(SCHEMA) {
                errors.push(format!(
                    "{name}: {file} 의 schema 가 '{SCHEMA}' 가 아니다 ({}). 다시 돌릴 것",
                    v["schema"].as_str().unwrap_or("없음")
                ));
                all_ok = false;
                continue;
            }

            // **파일마다 해시를 적는다.** 폴더 전체를 한 값으로 접으려면 "무엇을
            // 어떤 순서로 이어 붙이는가" 라는 규격이 생기고, 그 규격을 Rust ·
            // PowerShell · bash 세 곳에 적으면 반드시 갈라진다. 지도끼리 견주면
            // 각 언어가 아는 것은 "파일 하나의 sha256" 뿐이다.
            let files_now = plugin_files(&plugin_dir)?;
            let expected = dir.join("expected-ops.txt");
            let expected_now = sha256_of(&expected)?;
            // 남아야 하는 자리가 늘면 그 회차는 새 요구를 재지 않은 것이다.
            let must = dir.join("must-remain.txt");
            let must_now = sha256_of(&must)?;
            let mut stale = Vec::new();
            match v["plugin_files"].as_object() {
                Some(m) => {
                    let mut recorded: std::collections::BTreeMap<String, String> = m
                        .iter()
                        .map(|(k, x)| (k.clone(), x.as_str().unwrap_or_default().to_string()))
                        .collect();
                    // 기록된 쪽에서도 판정과 무관한 것을 뺀다. 하네스가 지문을
                    // 뜬 시점에는 그 파일들이 목록에 있었고, **증거를 손으로
                    // 고치는 것은 이 게이트가 막으려는 바로 그 일이다** — 대신
                    // 견주기 전에 양쪽에서 같은 것을 빼서 맞춘다.
                    for k in [
                        remedy_trust::MANIFEST_NAME,
                        remedy_trust::SIGNATURE_NAME,
                        "RELEASE.md",
                    ] {
                        recorded.remove(k);
                    }
                    if recorded != files_now {
                        stale.push("정답 플러그인");
                    }
                }
                None => stale.push("정답 플러그인(지문이 없다)"),
            }
            if v["expected_ops_sha256"].as_str() != Some(expected_now.as_str()) {
                stale.push("expected-ops.txt");
            }
            if v["must_remain_sha256"].as_str() != Some(must_now.as_str()) {
                stale.push("must-remain.txt");
            }
            if !stale.is_empty() {
                errors.push(format!(
                    "{name}({file}): 실기기 치료 결과가 낡았다 — 그 뒤에 바뀐 것: {}\n      {}{flag}",
                    stale.join(" · "),
                    how_to(root, &name)
                ));
                all_ok = false;
                continue;
            }

            let verdict = v["verdict"].as_str().unwrap_or("없음");
            if verdict != "pass" {
                errors.push(format!(
                    "{name}: 마지막 실기기 치료가 '{verdict}' 였다. 합격이 아닌 결과를 \
                 증거로 둘 수 없다"
                ));
                all_ok = false;
                continue;
            }

            // ── 증거가 이 위협의 것인가 · 재료와 아귀가 맞는가 ──────────
            //
            // 여기까지는 지문만 봤다. 지문은 **재료가 바뀌었는가**를 말하지
            // 그 결과가 **이 위협을 잰 것인가**를 말하지 않는다. 다른 위협의
            // 증거를 베껴 지문만 맞추면 위의 검사는 전부 통과한다.
            let mut wrong = Vec::new();
            if v["threat"].as_str() != Some(name.as_str()) {
                wrong.push(format!(
                    "threat 이 '{}' 다 (이 폴더는 {name})",
                    v["threat"].as_str().unwrap_or("없음")
                ));
            }
            // 위협이 도는 곳은 재료가 정한다 — `exam` 이 안내문을 고르는 것과
            // 같은 판단이고, 두 곳이 갈라지지 않게 같은 사실을 본다.
            let want_platform = if root
                .join("testbed/harness/linux/threats")
                .join(format!("{name}-collect.yaml"))
                .exists()
            {
                "linux"
            } else {
                "windows"
            };
            if v["platform"].as_str() != Some(want_platform) {
                wrong.push(format!(
                    "platform 이 '{}' 다 (이 위협은 {want_platform} 에서 돈다)",
                    v["platform"].as_str().unwrap_or("없음")
                ));
            }

            let c = count_from_materials(&dir)?;
            let n = |k: &str| v[k].as_u64().unwrap_or(u64::MAX) as usize;
            for (label, recorded, want) in [
                ("밟는 자리", n("scope_targets"), c.places),
                ("남아야 하는 자리", n("must_remain"), c.must_remain),
                ("내용 검사", n("content_checks"), c.content),
            ] {
                if recorded != want {
                    wrong.push(format!(
                        "{label}가 {}곳이라는데 재료를 세면 {want}곳이다",
                        if recorded == usize::MAX {
                            "없음".to_string()
                        } else {
                            recorded.to_string()
                        }
                    ));
                }
            }
            // **합격은 전부 잰 회차만 낸다.** 못 잰 자리가 하나라도 있으면 두
            // 하네스가 미결로 내린다. 그러니 합격인데 N < M 이면 그 증거는
            // 하네스가 낸 것이 아니다.
            for (label, seen, all) in [
                ("밟는 자리", n("measured"), c.places),
                ("남아야 하는 자리", n("must_remain_measured"), c.must_remain),
                ("내용 검사", n("content_measured"), c.content),
            ] {
                if seen != all {
                    wrong.push(format!(
                        "합격인데 {label}를 {seen}/{all} 만 쟀다 — 하네스는 그것을 미결로 낸다"
                    ));
                }
            }
            wrong.extend(trace_problems(&v));

            if !wrong.is_empty() {
                errors.push(format!(
                    "{name}({file}): 이 증거는 그 회차가 실제로 돈 것으로 보이지 않는다\n{}\n      {}{flag}",
                    wrong
                        .iter()
                        .map(|w| format!("        - {w}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    how_to(root, &name)
                ));
                all_ok = false;
                continue;
            }

            // **남아야 하는 자리도 적는다.** 이 줄이 그 회차가 무엇을 쟀는지
            // 말하는 유일한 자리다. 밟는 자리만 적으면 "건드리면 안 되는 것을
            // 지켰는가" 는 재고도 안 재는 것처럼 보인다.
            let must = v["must_remain"].as_u64().unwrap_or(0);
            let must_seen = v["must_remain_measured"].as_u64().unwrap_or(0);
            // 내용 검사는 밟는 자리의 **갈래**다 — 별개의 자리가 아니라 그중
            // 몇을 "지목한 만큼만 달라졌는가" 로 판정했는지를 말한다.
            let cont = v["content_checks"].as_u64().unwrap_or(0);
            let cont_seen = v["content_measured"].as_u64().unwrap_or(0);
            lines.push(format!(
                "    {name}{}  {} · {} · 밟는 자리 {}/{} (내용 {}/{}) · 남아야 하는 자리 {}/{} · {} · {}",
                v["variant"]
                    .as_str()
                    .map(|x| format!(" [{x}]"))
                    .unwrap_or_default(),
                v["platform"].as_str().unwrap_or("?"),
                v["mode"].as_str().unwrap_or("?"),
                v["measured"].as_u64().unwrap_or(0),
                v["scope_targets"].as_u64().unwrap_or(0),
                cont_seen,
                cont,
                must_seen,
                must,
                v["ran_at"].as_str().unwrap_or("?"),
                v["trace"]["host"].as_str().unwrap_or("?"),
            ));
        }
        if all_ok {
            checked += 1;
        }
    }

    for l in &lines {
        println!("{l}");
    }
    if !errors.is_empty() {
        return Err(format!(
            "실기기 치료 결과 {}건 문제 (채점 5):\n  {}",
            errors.len(),
            errors.join("\n  ")
        ));
    }
    println!("실기기 OK — 위협 {checked}개의 치료 결과가 지금 자료로 재어졌다");
    Ok(())
}

/// 이 위협을 어떻게 다시 재는가. **명령을 적어 준다** — 게이트가 빨개졌을 때
/// 무엇을 해야 하는지 찾아 헤매게 하지 않는다.
fn how_to(root: &Path, threat: &str) -> String {
    let linux = root
        .join("testbed/harness/linux/threats")
        .join(format!("{threat}-collect.yaml"))
        .exists();
    if linux {
        let attended = threat == "tls-intercept";
        format!(
            "다시 재려면: testbed/harness/linux/invoke-exam-apply.sh --threat {threat}{} --record",
            if attended { " --attended" } else { "" }
        )
    } else {
        format!(
            // `-Revert` 를 권한다 — 깨끗한 출발이라야 차분이 뜻을 갖는다.
            //
            // 2026-09-11 에 잠시 뺐었다. 되돌린 게스트의 자동 갱신기가 회차
            // 도중에 움직여 채점 5 가 불합격했기 때문이다. 기준 스냅샷을
            // `remedy-lab-base-v3` 로 다시 뜨며 그 갱신기를 껐고, 같은 명령이
            // `-Revert` 로 합격한다.
            "다시 재려면: testbed/harness/host/Invoke-ExamApply.ps1 -Threat {threat} -Revert -Record"
        )
    }
}

/// 정답 폴더의 **파일마다** 상대 경로와 sha256.
///
/// 경로 구분자는 `/` 로 맞춘다 — 하네스가 Windows 와 Linux 양쪽에서 이 지도를
/// 만든다. `RELEASE.md` 같은 문서도 들어간다. 뺄 규칙을 두면 그 규칙이 세 곳에
/// 생기고, 문서만 고쳤을 때 게이트가 빨개지는 값은 그 위험보다 싸다.
fn plugin_files(dir: &Path) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut out = std::collections::BTreeMap::new();
    walk(dir, dir, &mut out)?;
    // **서명은 판정 로직이 아니다.** 같은 플러그인을 다시 서명하면 매니페스트와
    // 서명 파일이 바뀌지만 그 플러그인이 내는 답은 한 글자도 다르지 않다. 그것을
    // 지문에 넣으면 서명할 때마다 실기기 증거가 "낡았다" 로 판정되고, 그러면
    // 사람이 재지 않은 채 증거를 다시 적게 된다 (2026-09-08 에 실제로 걸렸다).
    //
    // 룰과 매니페스트 본문은 그대로 지문에 남는다 — evilai 의 판별자가 정확히
    // 그 YARA 룰이므로 그것이 바뀌면 증거는 정말로 낡는다.
    out.remove(remedy_trust::MANIFEST_NAME);
    out.remove(remedy_trust::SIGNATURE_NAME);
    // **릴리스 기록도 판정 로직이 아니다.** `RELEASE.md` 는 출시 게이트 통과를
    // 사람이 적는 자리이고(`remedy-core/tests/evilai.rs` 가 매니페스트 버전과
    // 맞는지만 본다), 거기 한 줄을 더해도 그 플러그인이 내는 답은 같다.
    // 2026-09-08 에 서명 기록을 적었다가 실기기 증거가 "낡았다" 로 판정됐다.
    out.remove("RELEASE.md");
    if out.is_empty() {
        return Err(format!("{} 에 파일이 없다", dir.display()));
    }
    Ok(out)
}

fn walk(
    base: &Path,
    dir: &Path,
    out: &mut std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    for e in std::fs::read_dir(dir)
        .map_err(|x| format!("{} 읽기 실패: {x}", dir.display()))?
        .flatten()
    {
        let p = e.path();
        if p.is_dir() {
            walk(base, &p, out)?;
        } else {
            let rel = p
                .strip_prefix(base)
                .map_err(|_| "경로가 폴더 밖이다".to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, sha256_of(&p)?);
        }
    }
    Ok(())
}

fn sha256_of(p: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(p).map_err(|e| format!("{} 읽기 실패: {e}", p.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("저장소 루트")
            .to_path_buf()
    }

    /// **이 검사가 실제로 돈다는 것을 고정한다.** 증거 파일이 하나도 없어도
    /// 통과하는 상태가 되면 게이트가 장식이 된다.
    #[test]
    fn every_threat_with_an_answer_has_a_machine_result() {
        let root = repo_root();
        run(&root).expect("실기기 치료 결과 게이트");
    }

    /// 정답이 있는 위협의 수를 고정한다. 위협을 더하고 증거를 안 두면 위의
    /// 시험이 잡지만, **정답 표에서 지워서** 검사 대상이 줄어드는 것은 잡지
    /// 못한다.
    ///
    /// 아홉이다 — 시험 전용 여덟과 제품이 싣는 `evilai-locust` 하나.
    ///
    /// **이름에 수를 박지 않는다** (2026-09-21). 그전 이름은
    /// `..._covers_seven_threats` 였고, 여덟째를 더하자 이름과 단언이 함께
    /// 틀렸다. 수는 아래 상수 하나에만 둔다.
    #[test]
    fn the_reference_table_covers_every_threat() {
        // 2026-09-09: c2-beacon 이 일곱째다 — 알려진 지표 목록으로 잡는 위협.
        // 2026-09-21: xmr-miner 가 여덟째다 — 리눅스 systemd 유닛을 처음 밟는다.
        // 2026-09-21: ssh-backdoor 가 아홉째다 — 리눅스 cron 을 처음 밟되
        //             탐지 쪽만이다. 치료는 파일 격리로 한다(까닭은 그 위협의
        //             expected-ops.txt 머리에).
        // 2026-09-21: ransomware 가 열째다 — `registry.delete_value` 를 처음
        //             밟고, "지우면 안 되는 것"(암호화된 사용자 문서)을 처음
        //             묻는다.
        // 2026-09-21: selfcopy-worm 이 열한째다 — 해시 하나가 다섯 자리를
        //             집는다. G5 의 최상위 디렉터리 상한에 닿되 통과한다.
        // 2026-09-21: webshell-upload 가 열두째다 — `glob` 을 처음 쓰고,
        //             자리와 종류의 조합으로만 갈리는 첫 위협이다.
        // 2026-09-21: proxy-dns-hijack 이 열셋째다 — hosts 를 Windows 에서
        //             처음 밟는다. 그러느라 Windows 채점기에 `line=` 검사를
        //             더했다(리눅스 쪽에는 있었다).
        // 2026-09-21: shortcut-hijack 이 열넷째다 — `.lnk` 를 Windows 에서
        //             처음 밟는다. 같은 까닭으로 `args=` 검사도 더했고,
        //             이로써 두 하네스가 같은 매치를 전부 본다.
        // 2026-09-21: cred-dump 가 열다섯째다 — `registry.delete_value` 를
        //             두 번째로 밟고(ransomware 가 처음), 같은 키의 정상 값
        //             다섯 옆에서 값 하나만 겨눈다.
        // 2026-09-21: regkey-stager 가 열여섯째다 — `registry_key` subject 와
        //             `base64_decode` 를 처음 밟는다. 키는 증거이고 치료
        //             대상이 아니다(G6 가 키 삭제를 거부한다).
        // 2026-09-22: sideload-drop 이 열일곱째다 — `gt` 와 `lt` 를 처음 밟아
        //             연산자 열둘을 전부 채웠다. 시각·크기를 함께 보아야
        //             갈리고, 비교의 기준은 그 기계의 파일에서 뽑는다.
        // 2026-09-22: hook-implant 가 열여덟째다 — 분석가 YARA 룰과 위협
        //             폴더의 `rules/*.yar` 주입 경로를 시험에서 처음 밟는다.
        //             내용 말고는 셋을 가를 잣대가 없다.
        // 2026-09-22: npm-posthook 이 열아홉째다 — `structured_config` 를
        //             리눅스에서 처음 밟고, 그러느라 리눅스 채점기에
        //             `key_path=` 검사를 더했다(Windows 쪽에는 있었다).
        //             이로써 네 매치 종류를 두 하네스가 모두 본다.
        // 2026-09-22: hexcfg-loader 가 스무째다 — capture 함수 셋
        //             (`hex_decode`·`basename`·`lower`)을 한 사슬로 처음 밟는다.
        //             셋 중 하나만 빼도 판정이 서지 않는다.
        // 실기기 결과는 각 위협 폴더의 apply-result.json.
        assert_eq!(
            crate::exam::REFERENCES.len(),
            20,
            "정답 표의 크기가 바뀌었다. 늘었으면 그 위협의 실기기 결과를 두고,              줄었으면 왜 지웠는지 여기 적을 것"
        );
    }
}
