//! 금지 의존 검사 (설계-04 §1).
//!
//! 안전 불변식이 사람의 기억이 아니라 빌드에 걸려 있어야 한다. 금지 쌍 목록은
//! **설계-04 문서에서 읽는다** — 코드에 박으면 문서와 갈라진다.

use crate::docs;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

/// 설계-04 §1의 금지 의존 표를 파싱한다.
///
/// 표 행 형식: `| \`remedy-detect\` → \`remedy-platform\` | 설명 |`
pub fn forbidden_pairs(root: &Path) -> Result<Vec<(String, String)>, String> {
    let doc = docs::read(root, "설계-04")?;
    let sec = docs::section(&doc, "### 의존 방향이 안전 속성을 강제한다", "\n### ")?;
    let mut pairs = Vec::new();
    for row in docs::table_rows(sec) {
        let first_cell = row.trim_matches('|').split('|').next().unwrap_or("");
        if !first_cell.contains('→') {
            continue;
        }
        let toks: Vec<String> = docs::backticked(first_cell)
            .into_iter()
            .filter(|t| t.starts_with("remedy-"))
            .collect();
        if toks.len() == 2 {
            pairs.push((toks[0].clone(), toks[1].clone()));
        }
    }
    if pairs.is_empty() {
        return Err("설계-04 §1에서 금지 의존 쌍을 하나도 읽지 못했다".into());
    }
    Ok(pairs)
}

/// 워크스페이스 내부 의존 그래프. `cargo metadata --no-deps` 로 충분하다.
fn internal_graph(root: &Path) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cargo metadata 실행 실패: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata 실패: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("metadata 파싱 실패: {e}"))?;

    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let packages = json["packages"]
        .as_array()
        .ok_or("metadata 에 packages 가 없다")?;
    for pkg in packages {
        let name = pkg["name"].as_str().unwrap_or_default().to_string();
        let mut deps = BTreeSet::new();
        if let Some(list) = pkg["dependencies"].as_array() {
            for dep in list {
                let dn = dep["name"].as_str().unwrap_or_default();
                if dn.starts_with("remedy-") {
                    deps.insert(dn.to_string());
                }
            }
        }
        graph.insert(name, deps);
    }
    Ok(graph)
}

/// `from` 에서 도달 가능한 모든 크레이트. **전이 의존을 본다** —
/// 직접 의존만 검사하면 한 단계만 우회해도 규칙이 무력해진다.
fn reachable(graph: &BTreeMap<String, BTreeSet<String>>, from: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![from.to_string()];
    while let Some(cur) = stack.pop() {
        if let Some(deps) = graph.get(&cur) {
            for d in deps {
                if seen.insert(d.clone()) {
                    stack.push(d.clone());
                }
            }
        }
    }
    seen
}

/// 제품 바이너리의 이름. 하네스도 문서도 사용자도 이 이름을 부른다.
const PRODUCT_BIN: &str = "remedy";

/// CLI 크레이트가 `remedy` 라는 이름의 바이너리를 내는가.
///
/// `[[bin]]` 절이 없으면 크레이트 이름을 따라 `remedy-cli.exe` 가 나온다.
/// 그런데 target 디렉터리에 예전 `remedy.exe` 가 남아 있으면 아무 오류 없이
/// **낡은 바이너리가 시험된다.** P2 작업 중에 실제로 그럴 뻔했다.
fn check_product_bin(root: &Path) -> Result<(), String> {
    let manifest = root.join("crates/remedy-cli/Cargo.toml");
    let text =
        std::fs::read_to_string(&manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;

    let declared = text
        .lines()
        .map(str::trim)
        .skip_while(|l| *l != "[[bin]]")
        .find_map(|l| l.strip_prefix("name")?.trim().strip_prefix('='))
        .map(|v| v.trim().trim_matches('"').to_string());

    match declared.as_deref() {
        Some(PRODUCT_BIN) => {
            println!("arch OK — 제품 바이너리 이름 '{PRODUCT_BIN}'");
            Ok(())
        }
        Some(other) => Err(format!(
            "제품 바이너리 이름이 '{other}' 다. '{PRODUCT_BIN}' 이어야 한다"
        )),
        None => Err(format!(
            "crates/remedy-cli/Cargo.toml 에 [[bin]] name = \"{PRODUCT_BIN}\" 이 없다.\n\
             그러면 remedy-cli.exe 가 나오는데, 낡은 remedy.exe 가 남아 있으면\n\
             오류 없이 그쪽이 시험된다."
        )),
    }
}

pub fn run(root: &Path) -> Result<(), String> {
    check_product_bin(root)?;

    let pairs = forbidden_pairs(root)?;
    let graph = internal_graph(root)?;
    println!("금지 의존 {}건을 설계-04 §1에서 읽었다", pairs.len());

    let mut violations = Vec::new();
    for (from, to) in &pairs {
        if !graph.contains_key(from) {
            return Err(format!(
                "금지 규칙의 크레이트 '{from}' 가 워크스페이스에 없다"
            ));
        }
        if !graph.contains_key(to) {
            return Err(format!(
                "금지 규칙의 크레이트 '{to}' 가 워크스페이스에 없다"
            ));
        }
        if reachable(&graph, from).contains(to) {
            violations.push(format!("  {from} → {to} (전이 포함)"));
        }
    }

    if violations.is_empty() {
        println!("arch OK — 금지 의존 {}건 모두 위반 없음", pairs.len());
        Ok(())
    } else {
        Err(format!(
            "금지 의존 위반 {}건:\n{}",
            violations.len(),
            violations.join("\n")
        ))
    }
}

/// `unsafe` 를 쓸 수 있는 크레이트 (설계-04 §1).
///
/// **여기 없는 크레이트는 `#![forbid(unsafe_code)]` 를 달아야 한다.** 예외를
/// 하나 만들었으면 그것이 번지지 않게 하는 것이 예외를 만든 사람의 몫이다.
const UNSAFE_ALLOWED: &[&str] = &["remedy-wintrust"];

/// 모든 크레이트가 `forbid(unsafe_code)` 를 달고 있는지 본다.
///
/// P10-B 에서 `remedy-wintrust` 하나가 예외가 됐다(안전 래퍼가 없는
/// `WinVerifyTrust` 를 감싼다). 그 예외가 조용히 늘어나면 "이 저장소는 unsafe 를
/// 쓰지 않는다" 는 말이 사실이 아니게 되고, 그 사실을 아무도 모르게 된다.
pub fn forbid_unsafe(root: &Path) -> Result<(), String> {
    let crates_dir = root.join("crates");
    let entries = std::fs::read_dir(&crates_dir)
        .map_err(|e| format!("{} 를 읽지 못했다: {e}", crates_dir.display()))?;

    let mut missing = Vec::new();
    let mut stale = Vec::new();
    let mut checked = 0usize;

    for entry in entries {
        let dir = entry.map_err(|e| format!("{e}"))?.path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();

        // 크레이트 루트는 lib.rs 아니면 main.rs 다.
        let src = ["lib.rs", "main.rs"]
            .iter()
            .map(|f| dir.join("src").join(f))
            .find(|p| p.exists());
        let Some(src) = src else { continue };
        checked += 1;

        let text = std::fs::read_to_string(&src)
            .map_err(|e| format!("{} 를 읽지 못했다: {e}", src.display()))?;
        // **주석 속 언급이 아니라 실제 속성만 본다.** `remedy-wintrust` 의
        // 문서가 "다른 크레이트는 전부 #![forbid(unsafe_code)] 이고" 라고
        // 적고 있어서, 문자열만 찾으면 그 크레이트가 forbid 를 단 것으로
        // 읽힌다 — 처음 돌렸을 때 실제로 그렇게 나왔다.
        let forbids = text
            .lines()
            .any(|l| l.trim_start().starts_with("#![forbid(unsafe_code)]"));
        let allowed = UNSAFE_ALLOWED.contains(&name.as_str());

        if !forbids && !allowed {
            missing.push(name);
        } else if forbids && allowed {
            // 예외로 적혔는데 실제로는 forbid 다 — 예외가 필요 없어졌다.
            stale.push(name);
        }
    }

    if checked == 0 {
        return Err("크레이트를 하나도 보지 못했다".into());
    }
    if !missing.is_empty() {
        return Err(format!(
            "#![forbid(unsafe_code)] 가 없다: {}. \
             unsafe 가 정말 필요하면 xtask/src/arch.rs 의 UNSAFE_ALLOWED 에 \
             근거와 함께 넣을 것",
            missing.join(", ")
        ));
    }
    if !stale.is_empty() {
        return Err(format!(
            "UNSAFE_ALLOWED 에 있는데 forbid 를 달고 있다: {}. \
             예외가 필요 없어졌으면 목록에서 뺄 것",
            stale.join(", ")
        ));
    }

    println!(
        "unsafe OK — 크레이트 {checked}개 중 {}개만 예외이고 나머지는 forbid 다",
        UNSAFE_ALLOWED.len()
    );
    Ok(())
}
