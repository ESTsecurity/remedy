//! 금지 의존 검사 (설계-04 §1).
//!
//! 안전 불변식이 사람의 기억이 아니라 빌드에 걸려 있어야 한다. 금지 쌍 목록은
//! **설계-04 문서에서 읽는다** — 코드에 박으면 문서와 갈라진다.

use crate::docs;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::process::Command;

/// 본체 의존 트리에 들어오면 안 되는 네트워크 크레이트 — HTTP · TLS · 소켓 · DNS (설계-04 §1 의
/// *본체 → 네트워크 크레이트* 줄). 통신은 동반 모듈 `remedy-net` 의 일이다.
///
/// 허용 목록이 아니라 금지 목록이다 — 여기 없는 새 HTTP 크레이트는 지나간다. 그래서 배포본의 임포트
/// 검사(`cargo xtask static`)를 대신하지 않고 그 앞에 선다: 이것은 의존을 **들이는 커밋**에서 걸리고,
/// 그것은 지은 산출물에서 소켓 라이브러리를 본다.
const NETWORK_CRATES: &[&str] = &[
    // HTTP 클라이언트 · 서버
    "reqwest",
    "hyper",
    "hyper-util",
    "h2",
    "h3",
    "ureq",
    "attohttpc",
    "isahc",
    "curl",
    "curl-sys",
    "surf",
    "http-client",
    "actix-web",
    "actix-http",
    "axum",
    "warp",
    "tiny_http",
    "tide",
    // TLS
    "rustls",
    "rustls-webpki",
    "webpki",
    "webpki-roots",
    "native-tls",
    "openssl",
    "openssl-sys",
    "tokio-rustls",
    "tokio-native-tls",
    "hyper-rustls",
    "hyper-tls",
    "schannel",
    "security-framework",
    "boring",
    "boring-sys",
    // 소켓 · 비동기 네트워크 · DNS
    "socket2",
    "async-net",
    "async-std",
    "smol",
    "trust-dns-resolver",
    "trust-dns-proto",
    "hickory-resolver",
    "hickory-proto",
    // 그 밖의 원격 프로토콜
    "tungstenite",
    "tokio-tungstenite",
    "quinn",
    "quinn-proto",
    "lettre",
    "ssh2",
    "libssh2-sys",
    "tonic",
];

/// 기능을 켜야 소켓을 여는 크레이트 — 그 기능이 켜졌을 때만 걸린다. `tokio` 를 본체가 다른 크레이트를
/// 거쳐 끌어오고 동반 모듈이 `net` 을 켜면, 워크스페이스로 함께 지을 때 그 기능이 본체에도 들어간다.
///
/// **`mio` 의 `net` 은 넣지 않았다.** 본체 자신이 켠다 — `crossterm → signal-hook-mio` 가 터미널 신호(창
/// 크기 바뀜)를 받는 자기 파이프로 로컬 `UnixStream` 쌍을 쓴다(리눅스 갈래 · 2026-11-10 `cargo tree -e
/// features -i mio` 실측). 네트워크가 아니라 프로세스 안의 IPC 다. 네트워크 소켓을 여는 크레이트는 이름
/// (`socket2` 등)으로 본다.
const NETWORK_FEATURES: &[(&str, &str)] = &[("tokio", "net")];

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

    if !violations.is_empty() {
        return Err(format!(
            "금지 의존 위반 {}건:\n{}",
            violations.len(),
            violations.join("\n")
        ));
    }
    println!("arch OK — 금지 의존 {}건 모두 위반 없음", pairs.len());
    network_free(root)
}

/// 설계-04 §1 의 *본체 → 네트워크 크레이트* 줄을 본다 — 그 크레이트의 **전이 의존 전체**에
/// [`NETWORK_CRATES`] 와 [`NETWORK_FEATURES`] 가 없어야 한다.
///
/// 내부 쌍 검사와 다른 것은 외부 크레이트까지 본다는 점이다. 공유 크레이트(`remedy-sdk` 등)가 통신
/// 의존을 들이면 본체가 그것을 링크하게 되는데, 쌍 검사는 `remedy-*` 이름만 보므로 그것을 못 본다.
fn network_free(root: &Path) -> Result<(), String> {
    let target = network_rule_root(root)?;
    let meta = full_metadata(root)?;
    let reached = normal_closure(&meta, &target)?;
    let bad = network_violations(&reached);
    if !bad.is_empty() {
        return Err(format!(
            "{target} 의 의존 트리에 네트워크 크레이트 {}건 — 통신은 동반 모듈 remedy-net 의 일이다 (설계-04 §1):\n{}",
            bad.len(),
            bad.join("\n")
        ));
    }
    println!(
        "arch OK — {target} 의 의존 {}개에 HTTP · TLS · 소켓 크레이트 0 (이름 {}개 · 기능 {}개를 본다)",
        reached.len(),
        NETWORK_CRATES.len(),
        NETWORK_FEATURES.len()
    );
    Ok(())
}

/// 설계-04 §1 의 *`remedy-…` → 네트워크 크레이트* 줄이 가리키는 크레이트. **그 줄이 없으면 멈춘다** —
/// 금지 쌍과 같이 규칙의 자리는 문서이고, 문서에서 줄이 빠졌는데 검사만 남으면 둘이 갈라진다.
fn network_rule_root(root: &Path) -> Result<String, String> {
    let doc = docs::read(root, "설계-04")?;
    let sec = docs::section(&doc, "### 의존 방향이 안전 속성을 강제한다", "\n### ")?;
    for row in docs::table_rows(sec) {
        let first_cell = row.trim_matches('|').split('|').next().unwrap_or("");
        if !first_cell.contains('→') || !first_cell.contains("네트워크") {
            continue;
        }
        let toks: Vec<String> = docs::backticked(first_cell)
            .into_iter()
            .filter(|t| t.starts_with("remedy-"))
            .collect();
        if let [one] = toks.as_slice() {
            return Ok(one.clone());
        }
    }
    Err("설계-04 §1 에 '`remedy-…` → 네트워크 크레이트' 줄이 없다".into())
}

/// 의존을 풀어 낸 메타데이터. `--no-deps` 와 달리 외부 크레이트와 켜진 기능이 들어 있다.
fn full_metadata(root: &Path) -> Result<serde_json::Value, String> {
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cargo metadata 실행 실패: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata 실패: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("metadata 파싱 실패: {e}"))
}

/// 본체에서 닿는 크레이트 하나.
struct Reached {
    name: String,
    /// 켜진 기능 — 워크스페이스 전체로 합친 값이다(`cargo build --workspace` 가 실제로 그렇게 짓는다).
    features: BTreeSet<String>,
    /// 본체에서 이 크레이트까지의 이름 — 위반을 적을 때 누가 끌어왔는지 보인다.
    chain: Vec<String>,
}

/// `root` 에서 **일반 의존**으로 닿는 크레이트 전부(전이). dev · build 의존은 배포 바이너리에 링크되지
/// 않으므로 따라가지 않는다. 대상 OS 는 가리지 않는다 — Windows · 리눅스 갈래를 함께 본다.
fn normal_closure(meta: &serde_json::Value, root: &str) -> Result<Vec<Reached>, String> {
    let packages = meta["packages"]
        .as_array()
        .ok_or("metadata 에 packages 가 없다")?;
    let name_of: BTreeMap<&str, &str> = packages
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p["name"].as_str()?)))
        .collect();
    let root_id = packages
        .iter()
        .find(|p| p["name"] == root && p["source"].is_null())
        .and_then(|p| p["id"].as_str())
        .ok_or_else(|| format!("워크스페이스에 '{root}' 가 없다"))?;
    let nodes = meta["resolve"]["nodes"]
        .as_array()
        .ok_or("metadata 에 resolve 가 없다 — 의존을 풀지 않은 메타데이터다")?;
    let node_of: BTreeMap<&str, &serde_json::Value> = nodes
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();

    let mut parent: BTreeMap<&str, &str> = BTreeMap::new();
    let mut seen: BTreeSet<&str> = BTreeSet::from([root_id]);
    let mut queue: VecDeque<&str> = VecDeque::from([root_id]);
    let mut out = Vec::new();
    while let Some(id) = queue.pop_front() {
        let Some(node) = node_of.get(id) else {
            continue;
        };
        if id != root_id {
            let mut chain = vec![name_of.get(id).copied().unwrap_or(id).to_string()];
            let mut cur = id;
            while let Some(p) = parent.get(cur) {
                chain.push(name_of.get(p).copied().unwrap_or(p).to_string());
                cur = p;
            }
            chain.reverse();
            let features = node["features"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|f| f.as_str().map(String::from))
                .collect();
            out.push(Reached {
                name: name_of.get(id).copied().unwrap_or(id).to_string(),
                features,
                chain,
            });
        }
        for dep in node["deps"].as_array().into_iter().flatten() {
            // `dep_kinds` 가 없는 판의 cargo 면 일반 의존으로 친다 — 모르면 넓게 본다.
            let normal = dep["dep_kinds"]
                .as_array()
                .is_none_or(|kinds| kinds.iter().any(|k| k["kind"].is_null()));
            let Some(pkg) = dep["pkg"].as_str() else {
                continue;
            };
            if normal && seen.insert(pkg) {
                parent.insert(pkg, id);
                queue.push_back(pkg);
            }
        }
    }
    Ok(out)
}

/// 닿는 크레이트 가운데 금지 목록에 걸리는 것 — `본체 → … → 그 크레이트` 사슬로 적는다.
fn network_violations(reached: &[Reached]) -> Vec<String> {
    let mut bad = Vec::new();
    for r in reached {
        if NETWORK_CRATES.contains(&r.name.as_str()) {
            bad.push(format!("  {} (네트워크 크레이트)", r.chain.join(" → ")));
        }
        for (krate, feature) in NETWORK_FEATURES {
            if r.name == *krate && r.features.contains(*feature) {
                bad.push(format!("  {} (기능 '{feature}')", r.chain.join(" → ")));
            }
        }
    }
    bad.sort();
    bad.dedup();
    bad
}

/// `unsafe` 를 쓸 수 있는 크레이트 (설계-04 §1).
///
/// **여기 없는 크레이트는 `#![forbid(unsafe_code)]` 를 달아야 한다.** 예외를
/// 하나 만들었으면 그것이 번지지 않게 하는 것이 예외를 만든 사람의 몫이다.
const UNSAFE_ALLOWED: &[&str] = &["remedy-wintrust", "remedy-winmods"];

/// 모든 크레이트가 `forbid(unsafe_code)` 를 달고 있는지 본다.
///
/// P10-B 에서 `remedy-wintrust` 가 예외가 됐다(안전 래퍼가 없는
/// `WinVerifyTrust` 를 감싼다). 그다음 `remedy-winmods` 가 둘째 예외가 됐다 —
/// Windows 프로세스에 실린 모듈을 읽는 두 함수(`K32EnumProcessModulesEx` ·
/// `K32GetModuleFileNameExW`)도 안전 래퍼가 없다(목표 결정 29). 그 예외가 조용히
/// 늘어나면 "이 저장소는 unsafe 를 쓰지 않는다" 는 말이 사실이 아니게 되고, 그
/// 사실을 아무도 모르게 된다.
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn repo_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask 는 저장소 루트 아래에 있다")
            .to_path_buf()
    }

    /// 본체 → 공유 크레이트 → 외부 크레이트 → `socket2`, dev 로만 닿는 `reqwest`, 그리고 `tokio`.
    fn meta(tokio_features: &[&str]) -> serde_json::Value {
        let reg = "registry+https://github.com/rust-lang/crates.io-index";
        let normal = json!([{ "kind": null, "target": null }]);
        let dev = json!([{ "kind": "dev", "target": null }]);
        json!({
            "packages": [
                { "id": "cli", "name": "remedy-cli", "source": null },
                { "id": "sdk", "name": "remedy-sdk", "source": null },
                { "id": "foo", "name": "foo", "source": reg },
                { "id": "sock", "name": "socket2", "source": reg },
                { "id": "req", "name": "reqwest", "source": reg },
                { "id": "tok", "name": "tokio", "source": reg }
            ],
            "resolve": { "nodes": [
                { "id": "cli", "features": [], "deps": [
                    { "pkg": "sdk", "dep_kinds": normal },
                    { "pkg": "req", "dep_kinds": dev },
                    { "pkg": "tok", "dep_kinds": normal }
                ]},
                { "id": "sdk", "features": [], "deps": [{ "pkg": "foo", "dep_kinds": normal }] },
                { "id": "foo", "features": [], "deps": [{ "pkg": "sock", "dep_kinds": normal }] },
                { "id": "sock", "features": [], "deps": [] },
                { "id": "req", "features": [], "deps": [] },
                { "id": "tok", "features": tokio_features, "deps": [] }
            ]}
        })
    }

    #[test]
    fn a_network_crate_behind_a_shared_crate_is_caught_with_its_chain() {
        let reached = normal_closure(&meta(&["rt"]), "remedy-cli").unwrap();
        assert_eq!(
            network_violations(&reached),
            vec!["  remedy-cli → remedy-sdk → foo → socket2 (네트워크 크레이트)".to_string()]
        );
    }

    #[test]
    fn dev_dependencies_are_not_followed() {
        // 시험이 HTTP 클라이언트를 써도 배포 바이너리에는 링크되지 않는다.
        let reached = normal_closure(&meta(&["rt"]), "remedy-cli").unwrap();
        assert!(reached.iter().all(|r| r.name != "reqwest"));
    }

    #[test]
    fn tokio_counts_only_with_its_socket_feature() {
        let quiet = normal_closure(&meta(&["rt"]), "remedy-cli").unwrap();
        assert!(!network_violations(&quiet)
            .iter()
            .any(|v| v.contains("tokio")));
        let loud = normal_closure(&meta(&["rt", "net"]), "remedy-cli").unwrap();
        assert!(
            network_violations(&loud).contains(&"  remedy-cli → tokio (기능 'net')".to_string())
        );
    }

    #[test]
    fn an_unknown_root_is_an_error() {
        assert!(normal_closure(&meta(&[]), "remedy-net").is_err());
    }

    #[test]
    fn the_design_doc_draws_the_companion_boundary() {
        let root = repo_root();
        let pairs = forbidden_pairs(&root).unwrap();
        for (from, to) in [
            ("remedy-cli", "remedy-net"),
            ("remedy-net", "remedy-apply"),
            ("remedy-net", "remedy-platform"),
            // 동반 모듈이 링크할 판독기 — 이 줄이 빠지면 판독기가 OS 의존을 들여도 동반 모듈이 그것을 쓰기 전에는 걸리지 않는다.
            ("remedy-rpmdb", "remedy-platform"),
        ] {
            assert!(
                pairs.contains(&(from.to_string(), to.to_string())),
                "설계-04 §1 에 {from} → {to} 줄이 없다"
            );
        }
        assert_eq!(network_rule_root(&root).unwrap(), "remedy-cli");
    }
}
