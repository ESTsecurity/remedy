//! 동반 프로그램의 판정 기준 — 데이터 룰 `remedy-net-criteria` 가 읽히는가, 그리고 본체의 점검 룰과 같은
//! 값인가 (코어 1.12.0).
//!
//! 기준은 remedy-net 바이너리가 아니라 데이터 룰의 파일(`url.json` · `baseline.json`)에 있다. 같은 공지에서
//! 온 값이 본체의 점검 룰(`php2shell-check-*` · `node2shell-check-*`)에도 있으므로 한쪽만 고치면 여기서
//! 걸리게 한다. 1.11.0 까지는 remedy-net 의 크레이트 시험이 하던 대조다 — 크레이트가 룰 파일을 읽으면 룰을
//! 고칠 때 크레이트 시험이 깨진다(룰과 코어의 결합). 그래서 저장소 검사로 옮겼다.
//!
//! **개수를 박지 않는다** — 기준이 늘거나 줄어도 이 검사는 그대로다. 보는 것:
//!
//! - 두 파일이 remedy-net 이 실행 때 쓰는 코드로 읽힌다(`remedy_net::criteria::check_texts`).
//! - url 표: `same_as` 가 `php2shell-check-linux <지금 버전>` 이고, 배포판 줄마다 그 룰에 같은 수정 버전
//!   (`op: pkg_version_lt`)이, 상류 수정 버전이 그 룰의 `상류: …` 줄에 있다.
//! - 이미지 · 컨테이너 기준: PHP 상류 수정 버전이 두 PHP 룰의 `상류: …` 줄과 Windows 룰의 `version_lt` 에,
//!   Node 상류 수정 버전이 두 Node 룰에 있다. PHP 공식 빌드 해시는 출처(공식 Docker 이미지 · PHP for
//!   Windows)마다 그 OS 의 룰에 같은 버전으로, Node 해시는 기준의 버전마다 x64 하나씩 두 룰에 같은 버전으로
//!   있다(리눅스 룰의 musl 은 공식 빌드가 있는 버전만).
//!
//! ```text
//! cargo xtask net-criteria
//! ```

use remedy_sdk::catalog::Platform;
use remedy_sdk::manifest::{PluginKind, PluginManifest};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const DIR: &str = "plugins/remedy-net-criteria";

fn read(root: &Path, rel: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| format!("{rel}: {e}"))
}

fn manifest(root: &Path, plugin: &str) -> Result<(String, PluginManifest), String> {
    let rel = format!("plugins/{plugin}/plugin.yaml");
    let text = read(root, &rel)?;
    let m = serde_yaml_ng::from_str(&text).map_err(|e| format!("{rel}: {e}"))?;
    Ok((text, m))
}

/// 룰 파일이 따옴표 안에 적은 SHA-256 → (버전, 꼴) — 그 줄의 주석 `# <버전> <꼴> …`. 한 해시가 여러 목록에
/// 나오면 주석이 같아야 한다.
fn host_hashes(rule: &str, problems: &mut Vec<String>) -> BTreeMap<String, (String, String)> {
    let mut out: BTreeMap<String, (String, String)> = BTreeMap::new();
    for line in rule.lines() {
        let Some(hash) = line.split('"').nth(1) else {
            continue;
        };
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let comment = line.split('#').nth(1).unwrap_or_default();
        let mut words = comment.split_whitespace();
        let listed = (
            words.next().unwrap_or_default().to_string(),
            words.next().unwrap_or_default().to_string(),
        );
        let key = hash.to_ascii_lowercase();
        if let Some(old) = out.get(&key) {
            if *old != listed {
                problems.push(format!("{hash}: 룰의 두 줄이 다른 버전 · 꼴을 적었다"));
            }
        }
        out.insert(key, listed);
    }
    out
}

/// 객체 칸의 값을 열쇠 차례로 (`8.2` · `8.3` …).
fn upstream(v: &Value) -> Vec<String> {
    let map: BTreeMap<String, String> = v
        .as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    map.into_values().collect()
}

fn check_url(root: &Path, url: &Value, problems: &mut Vec<String>) -> Result<(), String> {
    let (rule, m) = manifest(root, "php2shell-check-linux")?;
    let want = format!("{} {}", m.id, m.version);
    if url["same_as"].as_str() != Some(want.as_str()) {
        problems.push(format!(
            "url.json 의 same_as 가 '{}' 다 — 지금 룰은 '{want}'",
            url["same_as"].as_str().unwrap_or_default()
        ));
    }
    for line in url["lines"].as_array().into_iter().flatten() {
        let fixed = line["fixed"].as_str().unwrap_or_default();
        if !rule.contains(&format!("op: pkg_version_lt, value: \"{fixed}\"")) {
            problems.push(format!("url.json 의 배포판 줄 {fixed} 가 {} 에 없다", m.id));
        }
    }
    let line = format!("상류: {}", upstream(&url["upstream"]).join(" · "));
    if !rule.contains(&line) {
        problems.push(format!(
            "url.json 의 상류 수정 버전({line})이 {} 에 없다",
            m.id
        ));
    }
    Ok(())
}

fn check_fixed(root: &Path, base: &Value, problems: &mut Vec<String>) -> Result<(), String> {
    let php = upstream(&base["products"]["php"]["upstream"]);
    let line = format!("상류: {}", php.join(" · "));
    for plugin in ["php2shell-check-linux", "php2shell-check-windows"] {
        let (rule, _) = manifest(root, plugin)?;
        if !rule.contains(&line) {
            problems.push(format!(
                "baseline.json 의 PHP 상류 수정 버전({line})이 {plugin} 에 없다"
            ));
        }
        if plugin.ends_with("windows") {
            for fixed in &php {
                if !rule.contains(&format!("op: version_lt, value: \"{fixed}\"")) {
                    problems.push(format!(
                        "PHP 수정 버전 {fixed} 의 version_lt 가 {plugin} 에 없다"
                    ));
                }
            }
        }
    }
    let node = upstream(&base["products"]["node"]["upstream"]).join(" · ");
    for plugin in ["node2shell-check-linux", "node2shell-check-windows"] {
        let (rule, _) = manifest(root, plugin)?;
        if !rule.contains(&node) {
            problems.push(format!(
                "baseline.json 의 Node 상류 수정 버전({node})이 {plugin} 에 없다"
            ));
        }
    }
    Ok(())
}

/// (해시, 버전, 출처)
fn hashes(base: &Value, product: &str) -> Vec<(String, String, String)> {
    base["products"][product]["hashes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|h| {
            let s = |k: &str| h[k].as_str().unwrap_or_default().to_string();
            (s("sha256").to_ascii_lowercase(), s("version"), s("source"))
        })
        .collect()
}

/// PHP 공식 빌드의 해시 — 출처마다 그 OS 의 룰에 같은 버전으로.
fn check_php_hashes(root: &Path, base: &Value, problems: &mut Vec<String>) -> Result<(), String> {
    let homes = [
        (
            "https://registry-1.docker.io/",
            "php2shell-check-linux",
            "linux/",
        ),
        (
            "https://downloads.php.net/",
            "php2shell-check-windows",
            "windows/",
        ),
    ];
    let mut known = BTreeMap::new();
    for (_, plugin, _) in homes {
        let (rule, _) = manifest(root, plugin)?;
        known.insert(plugin, host_hashes(&rule, problems));
    }
    for (sha, version, source) in hashes(base, "php") {
        let Some((_, plugin, platform)) = homes.iter().find(|(h, _, _)| source.starts_with(h))
        else {
            problems.push(format!("PHP 해시 {sha} 의 출처를 모른다: {source}"));
            continue;
        };
        match known[plugin].get(&sha) {
            Some((v, label)) if *v == version && label.starts_with(platform) => {}
            Some((v, label)) => problems.push(format!(
                "PHP {version} {sha}: {plugin} 은 {v} {label} 로 적었다"
            )),
            None => problems.push(format!("PHP {version} {sha} 가 {plugin} 에 없다")),
        }
    }
    Ok(())
}

/// Node.js 공식 빌드의 해시 — 기준의 버전마다 x64 하나씩, 같은 버전으로. 룰에 있는 기준의 해시는 그 꼴의
/// 것뿐이다.
fn check_node_hashes(root: &Path, base: &Value, problems: &mut Vec<String>) -> Result<(), String> {
    let ours = hashes(base, "node");
    let versions: BTreeSet<&str> = ours.iter().map(|(_, v, _)| v.as_str()).collect();
    for (plugin, every, optional) in [
        (
            "node2shell-check-linux",
            "linux-x64",
            Some("linux-x64-musl"),
        ),
        ("node2shell-check-windows", "win-x64", None),
    ] {
        let (rule, _) = manifest(root, plugin)?;
        let known = host_hashes(&rule, problems);
        let mut covered: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for (sha, version, _) in &ours {
            let Some((v, label)) = known.get(sha) else {
                continue;
            };
            if v != version {
                problems.push(format!("Node {version} {sha}: {plugin} 은 {v} 로 적었다"));
            }
            if label != every && Some(label.as_str()) != optional {
                problems.push(format!(
                    "Node {version} {sha}: {plugin} 의 꼴 {label} 은 보지 않는 꼴이다"
                ));
                continue;
            }
            if !covered
                .entry(label.as_str())
                .or_default()
                .insert(version.as_str())
            {
                problems.push(format!("Node {version}: {plugin} 의 {label} 해시가 둘이다"));
            }
        }
        let have = covered.get(every).cloned().unwrap_or_default();
        let missing: Vec<&&str> = versions.iter().filter(|v| !have.contains(**v)).collect();
        if !missing.is_empty() {
            problems.push(format!(
                "{plugin} 에 {every} 해시가 없는 기준의 버전 {}개: {}",
                missing.len(),
                missing
                    .iter()
                    .take(5)
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(" · ")
            ));
        }
    }
    Ok(())
}

pub fn run(root: &Path) -> Result<(), String> {
    let url_text = read(root, &format!("{DIR}/url.json"))?;
    let base_text = read(root, &format!("{DIR}/baseline.json"))?;
    remedy_net::criteria::check_texts(&url_text, &base_text)?;
    let (_, m) = manifest(root, "remedy-net-criteria")?;
    if m.kind != Some(PluginKind::Data)
        || m.id != remedy_net::criteria::ID
        || !m.platforms.contains(&Platform::Windows)
        || !m.platforms.contains(&Platform::Linux)
    {
        return Err(format!(
            "{DIR}/plugin.yaml 은 두 OS 의 kind: data 룰이고 id 가 {} 여야 한다",
            remedy_net::criteria::ID
        ));
    }
    let url: Value = serde_json::from_str(&url_text).map_err(|e| e.to_string())?;
    let base: Value = serde_json::from_str(&base_text).map_err(|e| e.to_string())?;
    let mut problems = Vec::new();
    check_url(root, &url, &mut problems)?;
    check_fixed(root, &base, &mut problems)?;
    check_php_hashes(root, &base, &mut problems)?;
    check_node_hashes(root, &base, &mut problems)?;
    if !problems.is_empty() {
        return Err(format!(
            "net-criteria — 기준과 본체의 점검 룰이 어긋난다 {}건:\n  {}",
            problems.len(),
            problems.join("\n  ")
        ));
    }
    let n = |p: &str| hashes(&base, p).len();
    println!(
        "net-criteria OK — {} {} 의 url 표 · 기준 {}(PHP 해시 {} · Node 해시 {})이 본체의 점검 룰 넷과 같다",
        m.id,
        m.version,
        base["version"].as_str().unwrap_or_default(),
        n("php"),
        n("node")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_listed_twice_must_say_the_same_thing() {
        let h = "a".repeat(64);
        let mut problems = Vec::new();
        let same = format!("- \"{h}\"  # 8.3.36 linux/amd64\n- \"{h}\"  # 8.3.36 linux/amd64\n");
        assert_eq!(host_hashes(&same, &mut problems).len(), 1);
        assert!(problems.is_empty());
        let other = format!("- \"{h}\"  # 8.3.36 linux/amd64\n- \"{h}\"  # 8.3.35 linux/amd64\n");
        host_hashes(&other, &mut problems);
        assert_eq!(problems.len(), 1, "{problems:?}");
    }

    #[test]
    fn the_upstream_values_come_in_branch_order() {
        let v: Value = serde_json::json!({"8.3": "8.3.36", "8.2": "8.2.35"});
        assert_eq!(upstream(&v), ["8.2.35", "8.3.36"]);
    }

    /// 저장소의 기준이 본체의 룰과 같은가 — `xtask all` 이 도는 그 검사를 시험으로도 한 번.
    #[test]
    fn the_repository_criteria_match_the_host_rules() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("저장소 뿌리");
        run(root).expect("net-criteria");
    }
}
