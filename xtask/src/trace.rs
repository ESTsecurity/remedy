//! 추적성 검사 — 설계 문서의 인벤토리가 Phase 계획(설계-09 §3)에 전부 있는가.
//!
//! 문서가 열한 개로 늘어난 이상 사람 눈으로는 반드시 놓친다. 실제로 2차 개정에서
//! 이 대조로 누락 19건이 나왔다.

use crate::docs;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

struct Inventory {
    label: &'static str,
    items: Vec<String>,
    /// 설계-09에 적힌 개수 표기(`Op 28종`)를 검사할 때 쓰는 접두사.
    count_prefix: Option<&'static str>,
}

fn ops(root: &Path) -> Result<Inventory, String> {
    let doc = docs::read(root, "설계-03")?;
    let sec = docs::section(&doc, "## 2. 파괴 동작은 닫힌 집합", "\n## 3.")?;
    let mut set = BTreeSet::new();
    for row in docs::table_rows(sec) {
        for tok in docs::backticked(row) {
            if docs::is_op(&tok) {
                set.insert(tok);
            }
        }
    }
    Ok(Inventory {
        label: "Op",
        items: set.into_iter().collect(),
        count_prefix: Some("Op "),
    })
}

fn subjects(root: &Path) -> Result<Inventory, String> {
    let doc = docs::read(root, "설계-02")?;
    let sec = docs::section(&doc, "## 3. 관찰 대상 타입", "\n### v1 열거 범위")?;
    let mut set = BTreeSet::new();
    for row in docs::table_rows(sec) {
        if let Some(first) = docs::backticked(row).into_iter().next() {
            if docs::is_ident(&first) {
                set.insert(first);
            }
        }
    }
    Ok(Inventory {
        label: "subject",
        items: set.into_iter().collect(),
        count_prefix: Some("subject "),
    })
}

/// 격리 컨테이너의 엔트리 종류 (설계-02 §9).
///
/// 이 인벤토리가 없던 동안 표는 8종이었고 28개 Op 중 11개가 담길 자리가 없었다.
/// Op·subject·게이트는 대조했지만 이 축만 없어서 아무도 몰랐다.
fn entry_kinds(root: &Path) -> Result<Inventory, String> {
    let doc = docs::read(root, "설계-02")?;
    let sec = docs::section(&doc, "### 엔트리 종류별 저장 항목", "\n### ")?;
    let mut set = BTreeSet::new();
    for row in docs::table_rows(sec) {
        if let Some(first) = docs::backticked(row).into_iter().next() {
            if docs::is_ident(&first) {
                set.insert(first);
            }
        }
    }
    Ok(Inventory {
        label: "엔트리",
        items: set.into_iter().collect(),
        count_prefix: Some("엔트리 종류 "),
    })
}

fn gates(root: &Path) -> Result<Inventory, String> {
    let doc = docs::read(root, "설계-03")?;
    let sec = docs::section(&doc, "## 10. 출시 게이트", "\n### ")?;
    let mut set = BTreeSet::new();
    for row in docs::table_rows(sec) {
        let cell = row.trim_matches('|').split('|').next().unwrap_or("").trim();
        if let Some(num) = cell.strip_prefix('G') {
            if num.chars().all(|c| c.is_ascii_digit()) && !num.is_empty() {
                set.insert(format!("G{num}"));
            }
        }
    }
    Ok(Inventory {
        label: "게이트",
        items: set.into_iter().collect(),
        count_prefix: None,
    })
}

fn commands(root: &Path) -> Result<Inventory, String> {
    let doc = docs::read(root, "설계-01")?;
    let sec = docs::section(&doc, "### 하위 명령", "\n### ")?;
    let mut set = BTreeSet::new();
    for row in docs::table_rows(sec) {
        let cells: Vec<&str> = row.trim_matches('|').split('|').collect();
        if cells.len() < 2 {
            continue;
        }
        for tok in docs::backticked(cells[1]) {
            set.insert(tok);
        }
    }
    Ok(Inventory {
        label: "CLI 명령",
        items: set.into_iter().collect(),
        count_prefix: None,
    })
}

fn crates(root: &Path) -> Result<Inventory, String> {
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cargo metadata 실행 실패: {e}"))?;
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("metadata 파싱 실패: {e}"))?;
    let mut set = BTreeSet::new();
    for pkg in json["packages"].as_array().ok_or("packages 없음")? {
        let name = pkg["name"].as_str().unwrap_or_default();
        if name.starts_with("remedy-") {
            set.insert(name.to_string());
        }
    }
    Ok(Inventory {
        label: "크레이트",
        items: set.into_iter().collect(),
        count_prefix: None,
    })
}

/// 매트릭스 절에 `Op 28종` 처럼 적힌 개수가 실제와 맞는지 본다.
///
/// 검사 범위를 §3으로 좁히는 이유는 Phase 설명에도 `subject 2종` 같은 표기가
/// 있어서다. 그것들은 해당 Phase의 부분집합이지 총수가 아니다.
fn check_declared_count(matrix: &str, inv: &Inventory) -> Option<String> {
    let prefix = inv.count_prefix?;
    let mut found = Vec::new();
    let mut cursor = 0usize;
    while let Some(i) = matrix[cursor..].find(prefix) {
        let at = cursor + i + prefix.len();
        let digits: String = matrix[at..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(n) = digits.parse::<usize>() {
            found.push(n);
        }
        cursor = at.max(cursor + i + 1);
    }
    if found.is_empty() {
        return Some(format!(
            "{} 총수 표기('{prefix}N종')를 설계-09 §3에서 찾지 못했다",
            inv.label
        ));
    }
    if found.contains(&inv.items.len()) {
        None
    } else {
        Some(format!(
            "{} 개수 표기 불일치: 설계-09 §3은 {:?}종이라 적었으나 실제 {}종",
            inv.label,
            found,
            inv.items.len()
        ))
    }
}

/// 설계-09 §3 의 Phase 표를 `항목 -> Phase` 로 읽는다.
///
/// 행 모양: `| **P7** | 중 | `file.delete` · `persistence.disable` · ... |`
/// `item_cell` 은 항목이 들어 있는 열 번호다 (0-기준).
fn phase_map(section: &str, item_cell: usize) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for row in docs::table_rows(section) {
        let cells: Vec<&str> = row.trim_matches('|').split('|').collect();
        if cells.len() <= item_cell {
            continue;
        }
        let phase = cells[0].trim().trim_matches('*').trim();
        if !phase.starts_with('P') || !phase[1..].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        for tok in docs::backticked(cells[item_cell]) {
            map.insert(tok, phase.to_string());
        }
    }
    map
}

/// SDK 의 `implemented_in` 이 설계-09 §3 매트릭스와 같은가.
///
/// P1 이 "정의는 전부, 구현은 점진적으로" 를 택한 이상, 두 곳에 적힌 Phase 가
/// 갈라지면 작성자는 "P4 에서 된다" 는 말을 믿을 수 없게 된다. 그 말이 틀리면
/// 기다리는 대신 우회로를 만들기 시작한다 (설계-09 P1 검증).
fn check_implemented_in(root: &Path) -> Result<Vec<String>, String> {
    let plan = docs::read(root, "설계-09")?;
    let mut problems = Vec::new();

    let op_sec = docs::section(&plan, "### 3.2 Op", "\n### 3.3")?;
    let doc_ops = phase_map(op_sec, 2);
    if doc_ops.is_empty() {
        return Err("설계-09 §3.2 에서 Op-Phase 대응을 하나도 읽지 못했다".into());
    }
    for op in remedy_sdk::Op::ALL {
        let info = op.info();
        match doc_ops.get(info.id) {
            None => problems.push(format!("Op '{}' 가 설계-09 §3.2 표에 없다", info.id)),
            Some(doc_phase) if doc_phase != info.implemented_in.as_str() => problems.push(format!(
                "Op '{}' 의 Phase 불일치: SDK={} 설계-09 §3.2={}",
                info.id,
                info.implemented_in.as_str(),
                doc_phase
            )),
            Some(_) => {}
        }
    }

    let sub_sec = docs::section(&plan, "### 3.3 subject", "\n### 3.4")?;
    let doc_subjects = phase_map(sub_sec, 1);
    if doc_subjects.is_empty() {
        return Err("설계-09 §3.3 에서 subject-Phase 대응을 하나도 읽지 못했다".into());
    }
    for subject in remedy_sdk::Subject::ALL {
        let info = subject.info();
        match doc_subjects.get(info.id) {
            None => problems.push(format!("subject '{}' 가 설계-09 §3.3 표에 없다", info.id)),
            Some(doc_phase) if doc_phase != info.implemented_in.as_str() => problems.push(format!(
                "subject '{}' 의 Phase 불일치: SDK={} 설계-09 §3.3={}",
                info.id,
                info.implemented_in.as_str(),
                doc_phase
            )),
            Some(_) => {}
        }
    }

    // 엔트리 종류. 한 행에 여러 종류가 오므로 `phase_map` 이 아니라 직접 읽는다.
    let ek_sec = docs::section(&plan, "### 3.6 엔트리 종류", "\n---")?;
    let mut doc_kinds: BTreeMap<String, String> = BTreeMap::new();
    for row in docs::table_rows(ek_sec) {
        let cells: Vec<&str> = row.trim_matches('|').split('|').collect();
        if cells.len() < 2 {
            continue;
        }
        let phase = cells[0].trim().trim_matches('*').trim().to_string();
        if !phase.starts_with('P') {
            continue;
        }
        for tok in docs::backticked(cells[1]) {
            doc_kinds.insert(tok, phase.clone());
        }
    }
    if doc_kinds.is_empty() {
        return Err("설계-09 §3.6 에서 엔트리 종류-Phase 대응을 하나도 읽지 못했다".into());
    }
    for kind in remedy_sdk::EntryKind::ALL {
        let info = kind.info();
        match doc_kinds.get(info.id) {
            None => problems.push(format!(
                "엔트리 종류 '{}' 가 설계-09 §3.6 표에 없다",
                info.id
            )),
            Some(doc_phase) if doc_phase != info.implemented_in.as_str() => problems.push(format!(
                "엔트리 종류 '{}' 의 Phase 불일치: SDK={} 설계-09 §3.6={}",
                info.id,
                info.implemented_in.as_str(),
                doc_phase
            )),
            Some(_) => {}
        }
    }

    // 반대 방향 — 문서에는 있는데 SDK 에 없는 것.
    for id in doc_ops.keys() {
        if remedy_sdk::Op::from_id(id).is_none() {
            problems.push(format!("설계-09 §3.2 의 Op '{id}' 가 SDK 에 없다"));
        }
    }
    for id in doc_subjects.keys() {
        if remedy_sdk::Subject::from_id(id).is_none() {
            problems.push(format!("설계-09 §3.3 의 subject '{id}' 가 SDK 에 없다"));
        }
    }
    for id in doc_kinds.keys() {
        if remedy_sdk::EntryKind::from_id(id).is_none() {
            problems.push(format!("설계-09 §3.6 의 엔트리 종류 '{id}' 가 SDK 에 없다"));
        }
    }

    // **되돌릴 수 있다고 선언한 Op 은 담을 자리가 있어야 한다.** 이 대응이
    // 어긋나면 격리소가 있다는 말이 거짓이 된다. SDK 테스트도 같은 것을 보지만,
    // trace 는 문서를 읽는 쪽이라 여기서도 확인한다.
    for op in remedy_sdk::Op::ALL {
        let info = op.info();
        if info.reversible == op.backup_kinds().is_empty() {
            problems.push(format!(
                "Op '{}' — reversible={} 인데 백업 종류 {}개",
                info.id,
                info.reversible,
                op.backup_kinds().len()
            ));
        }
    }

    println!(
        "  {:8} {:3}종  {}",
        "Phase대응",
        doc_ops.len() + doc_subjects.len() + doc_kinds.len(),
        if problems.is_empty() {
            "OK"
        } else {
            "불일치"
        }
    );
    Ok(problems)
}

pub fn run(root: &Path) -> Result<(), String> {
    let plan = docs::read(root, "설계-09")?;
    let matrix = docs::section(&plan, "## 3. 추적성 매트릭스", "\n## 4.")?.to_string();
    let inventories = vec![
        ops(root)?,
        subjects(root)?,
        entry_kinds(root)?,
        gates(root)?,
        commands(root)?,
        crates(root)?,
    ];

    let mut problems = Vec::new();
    for inv in &inventories {
        if inv.items.is_empty() {
            problems.push(format!("{} 인벤토리를 하나도 추출하지 못했다", inv.label));
            continue;
        }
        let missing: Vec<&String> = inv.items.iter().filter(|i| !plan.contains(*i)).collect();
        let mark = if missing.is_empty() { "OK" } else { "누락" };
        println!("  {:8} {:3}종  {}", inv.label, inv.items.len(), mark);
        for m in &missing {
            problems.push(format!("{} '{}' 가 설계-09에 없다", inv.label, m));
        }
        if let Some(p) = check_declared_count(&matrix, inv) {
            problems.push(p);
        }
    }

    problems.extend(check_implemented_in(root)?);

    if problems.is_empty() {
        println!("trace OK — 설계 인벤토리가 Phase 계획에 전부 반영되어 있다");
        Ok(())
    } else {
        Err(format!(
            "추적성 위반 {}건:\n{}",
            problems.len(),
            problems
                .iter()
                .map(|p| format!("  {p}"))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}
