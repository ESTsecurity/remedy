//! `cargo xtask rule-records` — 룰의 출시 기록(`plugins/<id>/RELEASE.md`)에 두 표가 있고 지금 룰과 맞는가(2026-11-22).
//!
//! - **0 을 내는 갈래**(점검 룰 — `kind: check`) — 0(취약한 곳을 찾지 못했습니다 · 해당 없음)을 내는 갈래마다 근거와 그 갈래를
//!   재는 하네스 칸. 공개한 점검 룰 넷이 '취약한데 0' 갈래를 실은 채 나갔고 게이트가 아니라 독립 검토가 찾았다 — 0 의 길을 이름 ·
//!   근거 · 시험으로 적게 한다. 기계가 보는 것은 칸이 찼는지 · 칸 id 가 그 룰의 하네스(머리 10줄의 `# 룰:` — 그 하네스가 쓰는
//!   픽스처 폴더 포함)에 있는지까지다. 근거가 맞는지는 사람이 본다. 보지 않는 자리(기록의 *보지 않는 것*)는 갈래가 아니라
//!   넣지 않는다.
//! - **빈틈은 늘지 못한다** — 근거가 `근거 없음 — …` 이거나 하네스 칸이 `없음` 인 줄이 빈틈이다. 2026-11-22 에 지금 룰 17개의
//!   표를 채우며 드러난 빈틈은 그대로 보이게 두고, git 바탕(`gitbase`)보다 빈틈이 는 룰 · 바탕에 없던 새 룰의 빈틈을 막는다.
//!   바탕의 기록에 아직 이 절이 없으면(옮겨 가는 동안) 견주지 않는다.
//! - **린트 경고**(모든 룰) — `plugin lint` 가 낸 경고의 자리(`scan_roots[0]` · `verdict.require` …)마다 까닭 한 줄. 지금 경고가
//!   아닌 자리의 줄도 실패다 — 표가 지금 룰을 말하게 한다.
//!
//! 두 표는 기록의 맨 앞(버전 절보다 위)에 두는 살아 있는 절이다 — 머리 `## 0 을 내는 갈래` · `## 린트 경고` 와 표 머리
//! `| 갈래 | 근거 | 하네스 칸 |` · `| 자리 | 까닭 |` 를 그대로 쓴다.

use std::path::{Path, PathBuf};

use remedy_sdk::lint::Severity;
use remedy_sdk::manifest::{PluginKind, PluginManifest};

const ZERO: &str = "## 0 을 내는 갈래";
const ZERO_HEAD: [&str; 3] = ["갈래", "근거", "하네스 칸"];
const LINT: &str = "## 린트 경고";
const LINT_HEAD: [&str; 2] = ["자리", "까닭"];

pub fn run(root: &Path) -> Result<(), String> {
    let harnesses = harness_texts(root)?;
    let base = crate::gitbase::resolve(root, &[]).map_err(|e| format!("rule-records: {e}"))?;
    let mut bad = Vec::new();
    let (mut checks, mut zero_rows, mut gaps, mut warnings) = (0, 0, 0, 0);
    for dir in rule_dirs(root)? {
        let id = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(dir.join("plugin.yaml"))
            .map_err(|e| format!("rule-records: {id}: {e}"))?;
        let manifest: PluginManifest = serde_yaml_ng::from_str(&text)
            .map_err(|e| format!("rule-records: {id}: 매니페스트 파싱 {e}"))?;
        let record = std::fs::read_to_string(dir.join("RELEASE.md")).unwrap_or_default();
        let mine: Vec<&str> = harnesses
            .iter()
            .filter(|(_, ids, _)| ids.iter().any(|i| i == &id))
            .map(|(_, _, t)| t.as_str())
            .collect();
        let at: Vec<String> = remedy_sdk::lint::lint(&manifest)
            .into_iter()
            .filter(|i| i.severity == Severity::Warning)
            .map(|i| i.at)
            .collect();
        warnings += at.len();
        for p in check_lint(&record, &at) {
            bad.push(format!("{id}: {p}"));
        }
        if manifest.kind == Some(PluginKind::Check) {
            checks += 1;
            let z = check_zero(&record, &mine);
            zero_rows += z.rows;
            gaps += z.gaps;
            bad.extend(z.problems.into_iter().map(|p| format!("{id}: {p}")));
            let at_base = crate::gitbase::show(root, &base, &format!("plugins/{id}/RELEASE.md"))?
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            if let Some(p) = ratchet(z.gaps, base_gaps(at_base.as_deref())) {
                bad.push(format!("{id}: {p}"));
            }
        }
    }
    if !bad.is_empty() {
        let mut msg = format!(
            "rule-records: 출시 기록의 표가 지금 룰과 맞지 않는다 — {}건(바탕 {base})\n",
            bad.len()
        );
        for b in &bad {
            msg.push_str(&format!("  {b}\n"));
        }
        msg.push_str("  꼴: 기록 맨 앞의 '## 0 을 내는 갈래'(| 갈래 | 근거 | 하네스 칸 |) · '## 린트 경고'(| 자리 | 까닭 |)\n");
        return Err(msg);
    }
    println!(
        "rule-records OK — 점검 룰 {checks}개의 0 을 내는 갈래 {zero_rows}줄(빈틈 {gaps} — 바탕보다 늘지 않았다) · 린트 경고 {warnings}개에 까닭이 있다"
    );
    Ok(())
}

/// 점검 룰 하나의 0 갈래 표 — 줄 수 · 빈틈 줄 수 · 꼴의 문제(빈틈은 문제가 아니다 — 수는 래칫이 본다).
struct Zero {
    rows: usize,
    gaps: usize,
    problems: Vec<String>,
}

/// 빈틈 줄인가 — 근거를 대지 못했거나(`근거 없음 — …`) 그 갈래를 재는 하네스 칸이 없다(`없음`).
fn is_gap(why: &str, cells: &str) -> bool {
    why.starts_with("근거 없음") || cells == "없음"
}

fn check_zero(record: &str, harnesses: &[&str]) -> Zero {
    let mut bad = Vec::new();
    let Some(rows) = table(record, ZERO, &ZERO_HEAD) else {
        return Zero {
            rows: 0,
            gaps: 0,
            problems: vec![format!(
                "'{ZERO}' 절(표 머리 | 갈래 | 근거 | 하네스 칸 |)이 없다"
            )],
        };
    };
    if rows.is_empty() {
        bad.push(format!("'{ZERO}' 표에 줄이 없다"));
    }
    let mut gaps = 0;
    for r in &rows {
        let (what, why, cells) = (&r[0], &r[1], &r[2]);
        if what.is_empty() {
            bad.push("0 갈래의 '갈래' 칸이 비었다".into());
        }
        if why.is_empty() {
            bad.push(format!(
                "'{what}' — 근거 칸이 비었다(댈 수 없으면 '근거 없음 — <무엇이 없는지>')"
            ));
        }
        if is_gap(why, cells) {
            gaps += 1;
        }
        if cells == "없음" {
            continue;
        }
        let ids = backticked(cells);
        if ids.is_empty() {
            bad.push(format!(
                "'{what}' — 하네스 칸은 `칸 id` 들이거나 '없음' 이다"
            ));
        } else if harnesses.is_empty() {
            bad.push(format!(
                "'{what}' — 이 룰에는 '# 룰:' 하네스가 없다 — 하네스 칸은 '없음'"
            ));
        } else {
            for i in ids
                .iter()
                .filter(|i| !harnesses.iter().any(|t| has_token(t, i)))
            {
                bad.push(format!(
                    "'{what}' — 하네스 칸 '{i}' 이 그 룰의 하네스에 없다"
                ));
            }
        }
    }
    Zero {
        rows: rows.len(),
        gaps,
        problems: bad,
    }
}

/// 바탕 기록의 빈틈 줄 수 — 바탕에 그 룰이 없으면 0(새 룰은 빈틈 없이 든다) · 기록에 이 절이 아직 없으면 `None`(견주지 않는다).
fn base_gaps(record: Option<&str>) -> Option<usize> {
    let Some(r) = record else {
        return Some(0);
    };
    let rows = table(r, ZERO, &ZERO_HEAD)?;
    Some(rows.iter().filter(|c| is_gap(&c[1], &c[2])).count())
}

/// 빈틈이 바탕보다 늘었으면 그 문제.
fn ratchet(head: usize, base: Option<usize>) -> Option<String> {
    let b = base?;
    (head > b).then(|| {
        format!(
            "0 갈래의 빈틈(근거 없음 · 하네스 칸 없음)이 바탕의 {b}줄보다 늘어 {head}줄이다 — 새 갈래는 근거와 그 갈래를 재는 하네스 칸을 함께 적는다"
        )
    })
}

/// 린트 경고 표 — 지금 경고의 자리마다 까닭이 있고, 표의 자리가 모두 지금 경고다.
fn check_lint(record: &str, at: &[String]) -> Vec<String> {
    let rows = table(record, LINT, &LINT_HEAD);
    let mut bad = Vec::new();
    let Some(rows) = rows else {
        if !at.is_empty() {
            bad.push(format!(
                "린트 경고 {}개({})의 까닭 — '{LINT}' 절(| 자리 | 까닭 |)이 없다",
                at.len(),
                at.join(" · ")
            ));
        }
        return bad;
    };
    let listed: Vec<(String, &str)> = rows
        .iter()
        .map(|r| {
            (
                backticked(&r[0]).first().cloned().unwrap_or_default(),
                r[1].as_str(),
            )
        })
        .collect();
    for a in at {
        match listed.iter().find(|(p, _)| p == a) {
            None => bad.push(format!("린트 경고 '{a}' 의 까닭이 '{LINT}' 표에 없다")),
            Some((_, why)) if why.is_empty() || why.starts_with("까닭 없음") => {
                bad.push(format!("린트 경고 '{a}' 의 까닭 칸이 비었다"))
            }
            Some(_) => {}
        }
    }
    for (p, _) in listed.iter().filter(|(p, _)| !at.contains(p)) {
        bad.push(format!(
            "'{LINT}' 표의 '{p}' 는 지금 린트 경고가 아니다 — 그 줄을 지운다"
        ));
    }
    bad
}

/// 머리 줄 `heading` 아래 첫 표의 줄들(칸은 다듬은 글). 머리가 없으면 `None`. 표 머리의 칸 이름이 `head` 와 다르면 `None` 이다 —
/// 칸을 바꾼 표를 조용히 다른 뜻으로 읽지 않는다.
fn table(md: &str, heading: &str, head: &[&str]) -> Option<Vec<Vec<String>>> {
    let mut lines = md.lines().skip_while(|l| l.trim_end() != heading).skip(1);
    let mut rows = Vec::new();
    let mut seen_head = false;
    for l in lines.by_ref() {
        let t = l.trim();
        if !seen_head {
            if t.is_empty() {
                continue;
            }
            if t.starts_with("## ") {
                return None;
            }
            if !t.starts_with('|') {
                continue;
            }
            if cells(t) != head {
                return None;
            }
            seen_head = true;
            continue;
        }
        if !t.starts_with('|') {
            break;
        }
        let c = cells(t);
        if c.iter().all(|x| x.chars().all(|ch| ch == '-' || ch == ':')) {
            continue;
        }
        if c.len() != head.len() {
            return None;
        }
        rows.push(c);
    }
    seen_head.then_some(rows)
}

fn cells(row: &str) -> Vec<String> {
    let inner = row.trim().trim_start_matches('|').trim_end_matches('|');
    inner.split('|').map(|c| c.trim().to_string()).collect()
}

/// 칸 안의 `` `…` `` 들.
fn backticked(cell: &str) -> Vec<String> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// 글 안에 그 낱말이 앞뒤로 영숫자 없이 서는가(`b06` 은 `b06-nginxorg-1319` 에 선다 · `b061` 에는 서지 않는다).
fn has_token(text: &str, word: &str) -> bool {
    let bytes = text.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    text.match_indices(word).any(|(i, _)| {
        let before = i == 0 || !is_word(bytes[i - 1]);
        let j = i + word.len();
        let after = j >= bytes.len() || !is_word(bytes[j]);
        before && after
    })
}

fn rule_dirs(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root.join("plugins"))
        .map_err(|e| format!("rule-records: plugins/: {e}"))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("plugin.yaml").is_file())
        .collect();
    dirs.sort();
    Ok(dirs)
}

/// 룰 하네스 — `testbed/harness/{linux,host}/` 바로 아래 파일 가운데 머리 10줄에 `# 룰: <id>[, <id>…] — …` 줄이 있는 것.
/// (경로 · 그 줄이 적은 룰 id · 본문)
fn harness_texts(root: &Path) -> Result<Vec<(PathBuf, Vec<String>, String)>, String> {
    let mut out = Vec::new();
    for sub in ["testbed/harness/linux", "testbed/harness/host"] {
        let Ok(rd) = std::fs::read_dir(root.join(sub)) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let Ok(bytes) = std::fs::read(&p) else {
                continue;
            };
            let mut text = String::from_utf8_lossy(&bytes).into_owned();
            let ids = rule_ids(&text);
            if !ids.is_empty() {
                // 경우를 픽스처가 짓는 하네스(log4j — `fixtures/log4j/build-cases.py` · `official.txt`)는 그 칸 id 가 본문에 없다 —
                // 하네스가 가리키는 픽스처 폴더의 파일도 함께 찾는 글로 둔다.
                for name in fixture_dirs(&text) {
                    text.push('\n');
                    text.push_str(&read_tree(&root.join(sub).join("fixtures").join(name)));
                }
                out.push((p, ids, text));
            }
        }
    }
    Ok(out)
}

/// 하네스 본문이 가리키는 픽스처 폴더 이름들 — `fixtures/<이름>` 의 `<이름>`(영숫자 · `-` · `_` · `.`).
fn fixture_dirs(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .match_indices("fixtures/")
        .map(|(i, m)| {
            text[i + m.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .collect::<String>()
        })
        .filter(|n| !n.is_empty() && n != "." && n != "..")
        .collect();
    out.sort();
    out.dedup();
    out
}

/// 폴더 아래 파일 전부의 글(읽지 못한 파일은 건너뛴다 · 없는 폴더는 빈 글).
fn read_tree(dir: &Path) -> String {
    let mut out = String::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            out.push_str(&read_tree(&p));
        } else if let Ok(bytes) = std::fs::read(&p) {
            out.push_str(&String::from_utf8_lossy(&bytes));
            out.push('\n');
        }
    }
    out
}

/// 머리 10줄의 `# 룰: a, b — 설명` 이 적은 id 들(`ci/batch.sh` 의 하네스 찾기와 같은 줄).
fn rule_ids(text: &str) -> Vec<String> {
    for l in text.lines().take(10) {
        let l = l.trim_start_matches('\u{feff}').trim_end_matches('\r');
        if let Some(rest) = l.strip_prefix("# 룰: ") {
            let list = rest.split(" —").next().unwrap_or(rest);
            return list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HARNESS: &str = "#!/bin/bash\n# 룰: demo-check-linux — 시험\nrun_case b06-fixed debian12 0 \":\" \"고친 판\"\n";

    fn record(zero: &str, lint: &str) -> String {
        format!("# demo — 릴리스 기록\n\n{zero}\n{lint}\n## 0.1.0 — 1차\n\n본문\n")
    }

    const ZERO_OK: &str = "## 0 을 내는 갈래\n\n| 갈래 | 근거 | 하네스 칸 |\n|---|---|---|\n| 1.31.9 이상 | 공지 — 고친 판 1.31.9 | `b06` |\n";

    #[test]
    fn a_full_zero_table_passes() {
        let z = check_zero(&record(ZERO_OK, ""), &[HARNESS]);
        assert_eq!((z.rows, z.gaps, z.problems), (1, 0, Vec::<String>::new()));
    }

    #[test]
    fn a_missing_zero_table_fails() {
        let z = check_zero(&record("", ""), &[HARNESS]);
        assert!(z.problems[0].contains("절"), "{:?}", z.problems);
    }

    #[test]
    fn a_cell_id_missing_from_the_harness_fails() {
        let t = ZERO_OK.replace("`b06`", "`b07`");
        let z = check_zero(&record(&t, ""), &[HARNESS]);
        assert!(
            z.problems.iter().any(|b| b.contains("'b07'")),
            "{:?}",
            z.problems
        );
    }

    #[test]
    fn a_prefix_of_an_id_is_not_the_id() {
        // `b0` 은 `b06-fixed` 의 앞부분일 뿐이다.
        let t = ZERO_OK.replace("`b06`", "`b0`");
        let z = check_zero(&record(&t, ""), &[HARNESS]);
        assert!(
            z.problems.iter().any(|b| b.contains("'b0'")),
            "{:?}",
            z.problems
        );
    }

    #[test]
    fn gaps_are_counted_not_refused() {
        // 근거 없음 · 하네스 칸 없음은 빈틈이다 — 꼴의 문제가 아니라 래칫이 수를 본다.
        let t = ZERO_OK.replace("공지 — 고친 판 1.31.9", "근거 없음 — 공지가 없다");
        let z = check_zero(&record(&t, ""), &[HARNESS]);
        assert_eq!((z.gaps, z.problems.len()), (1, 0), "{:?}", z.problems);
        let none = ZERO_OK.replace("`b06`", "없음");
        let z = check_zero(&record(&none, ""), &[HARNESS]);
        assert_eq!((z.gaps, z.problems.len()), (1, 0), "{:?}", z.problems);
        // 하네스가 없는 룰도 '없음' 은 빈틈이다(그 갈래를 재는 칸이 없다).
        assert_eq!(check_zero(&record(&none, ""), &[]).gaps, 1);
    }

    #[test]
    fn cell_form_and_harness_presence_are_refused() {
        assert!(
            !check_zero(&record(ZERO_OK, ""), &[]).problems.is_empty(),
            "하네스 없는 룰에 칸 id 를 적었다"
        );
        let bare = ZERO_OK.replace("`b06`", "b06");
        assert!(
            !check_zero(&record(&bare, ""), &[HARNESS])
                .problems
                .is_empty(),
            "백틱 없는 칸"
        );
        let empty = ZERO_OK.replace("공지 — 고친 판 1.31.9", "");
        assert!(
            !check_zero(&record(&empty, ""), &[HARNESS])
                .problems
                .is_empty(),
            "빈 근거 칸"
        );
    }

    #[test]
    fn the_ratchet_refuses_more_gaps_than_the_base() {
        assert!(ratchet(3, Some(2)).is_some());
        assert!(ratchet(2, Some(2)).is_none());
        assert!(ratchet(1, Some(2)).is_none());
        assert!(
            ratchet(5, None).is_none(),
            "바탕에 아직 절이 없으면 견주지 않는다"
        );
        // 바탕에 없던 새 룰은 빈틈 없이 든다.
        assert_eq!(base_gaps(None), Some(0));
        assert!(ratchet(1, base_gaps(None)).is_some());
        // 바탕의 기록에 절이 없으면 None · 있으면 그 빈틈 수.
        assert_eq!(base_gaps(Some("# demo\n\n## 0.1.0\n")), None);
        let gap = ZERO_OK.replace("`b06`", "없음");
        assert_eq!(base_gaps(Some(&record(&gap, ""))), Some(1));
    }

    #[test]
    fn harness_fixture_dirs_are_read_as_part_of_the_harness() {
        let t = "FX=\"$HERE/fixtures/log4j\"\n# 꼴은 `fixtures/log4j/build-cases.py` · fixtures/ 만 쓴 줄\n";
        assert_eq!(fixture_dirs(t), vec!["log4j".to_string()]);
    }

    #[test]
    fn a_renamed_column_is_not_read_as_the_table() {
        let t = ZERO_OK.replace("| 갈래 | 근거 | 하네스 칸 |", "| 갈래 | 출처 | 하네스 칸 |");
        let z = check_zero(&record(&t, ""), &[HARNESS]);
        assert!(z.problems[0].contains("절"), "{:?}", z.problems);
    }

    #[test]
    fn lint_reasons_follow_the_current_warnings() {
        let lint = "## 린트 경고\n\n| 자리 | 까닭 |\n|---|---|\n| `scan_roots[0]` | 설치 폴더가 배포사마다 다르다 |\n";
        let at = vec!["scan_roots[0]".to_string()];
        assert!(check_lint(&record("", lint), &at).is_empty());
        let more = vec!["scan_roots[0]".to_string(), "verdict.require".to_string()];
        assert!(check_lint(&record("", lint), &more)
            .iter()
            .any(|b| b.contains("'verdict.require'")));
        assert!(check_lint(&record("", lint), &[])
            .iter()
            .any(|b| b.contains("지금 린트 경고가 아니다")));
        assert!(check_lint(&record("", ""), &at)[0].contains("절"));
        assert!(
            check_lint(&record("", ""), &[]).is_empty(),
            "경고가 없는 룰은 절이 없어도 된다"
        );
    }

    #[test]
    fn rule_line_names_every_rule_in_the_list() {
        let t = "\u{feff}#Requires -Version 5.1\r\n# 룰: a-check, b-clean — 설명\r\n";
        assert_eq!(
            rule_ids(t),
            vec!["a-check".to_string(), "b-clean".to_string()]
        );
        assert!(rule_ids("#!/bin/bash\n# 도구\n").is_empty());
    }
}
