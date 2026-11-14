//! 동반 프로그램의 판정 기준 — 데이터 룰 `remedy-net-criteria` 가 읽히는가, 그리고 본체의 점검 룰과 같은
//! 값인가 (코어 1.12.0 · Apache 는 1.18.0).
//!
//! 기준은 remedy-net 바이너리가 아니라 데이터 룰의 파일(`url.json` · `baseline.json` · `apache.json`)에 있다. 같은
//! 공지에서 온 값이 본체의 점검 룰(`php2shell-check-*` · `node2shell-check-*` · `apache-http2-check-linux`)에도
//! 있으므로 한쪽만 고치면 여기서 걸리게 한다. 1.11.0 까지는 remedy-net 의 크레이트 시험이 하던 대조다 — 크레이트가 룰 파일을 읽으면 룰을
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
//! - Apache 기준: `same_as` 가 `apache-http2-check-linux <지금 버전>` 이고, 고친 판의 **모음**이 그 룰의 판 비교
//!   (`pkg_version_lt` · `rpm_version_lt` · `apk_version_lt`) 값의 모음과 같다(양쪽 어느 한쪽에만 있는 값이 없다).
//!   RPM 줄의 공급사가 그 룰에 있고, 영향 범위의 양 끝 · 줄의 하한 · 지원 하한이 그 룰의 `version_gt` ·
//!   `version_lt` 값(끝 자리 하나 아래 · 위)으로 있다.
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

/// 룰 글에서 그 연산자들의 값 모음 — `op: <연산자>, value: "<값>"` 꼴의 것.
fn op_values(rule: &str, ops: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for op in ops {
        let head = format!("op: {op}, value: \"");
        for (i, _) in rule.match_indices(&head) {
            let after = &rule[i + head.len()..];
            if let Some(end) = after.find('"') {
                out.insert(after[..end].to_string());
            }
        }
    }
    out
}

/// `X.Y.Z` 의 끝 자리를 하나 내리거나 올린 것 — 영향 범위의 끝을 룰의 `version_gt` · `version_lt` 값과 견준다.
fn step(v: &str, up: bool) -> Option<String> {
    let (head, last) = v.rsplit_once('.')?;
    let n: u64 = last.parse().ok()?;
    let n = if up {
        n.checked_add(1)?
    } else {
        n.checked_sub(1)?
    };
    Some(format!("{head}.{n}"))
}

/// Apache 기준이 본체의 리눅스 Apache 룰과 같은가. 고친 판의 수를 준다.
fn check_apache(root: &Path, apache: &Value, problems: &mut Vec<String>) -> Result<usize, String> {
    let (rule, m) = manifest(root, "apache-http2-check-linux")?;
    let want = format!("{} {}", m.id, m.version);
    if apache["same_as"].as_str() != Some(want.as_str()) {
        problems.push(format!(
            "apache.json 의 same_as 가 '{}' 다 — 지금 룰은 '{want}'",
            apache["same_as"].as_str().unwrap_or_default()
        ));
    }
    let lines: Vec<&Value> = apache["lines"].as_array().into_iter().flatten().collect();
    let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let mine: BTreeSet<String> = lines
        .iter()
        .map(|l| text(&l["fixed"]))
        .filter(|f| !f.is_empty())
        .collect();
    let host = op_values(
        &rule,
        &["pkg_version_lt", "rpm_version_lt", "apk_version_lt"],
    );
    if mine != host {
        problems.push(format!(
            "apache.json 의 고친 판이 {} 의 판 비교와 다르다 — 기준에만: {:?} · 룰에만: {:?}",
            m.id,
            mine.difference(&host).collect::<Vec<_>>(),
            host.difference(&mine).collect::<Vec<_>>()
        ));
    }
    for vendor in lines
        .iter()
        .map(|l| text(&l["vendor"]))
        .filter(|v| !v.is_empty())
    {
        if !rule.contains(&format!("value: \"{vendor}\"")) {
            problems.push(format!(
                "apache.json 의 공급사 '{vendor}' 가 {} 에 없다",
                m.id
            ));
        }
    }
    let (gt, lt) = (
        op_values(&rule, &["version_gt"]),
        op_values(&rule, &["version_lt"]),
    );
    let mut floors = vec![
        text(&apache["upstream"]["affected"][0]),
        text(&apache["module"]["affected"][0]),
    ];
    floors.extend(
        lines
            .iter()
            .map(|l| text(&l["from_upstream"]))
            .filter(|v| !v.is_empty()),
    );
    for low in floors {
        if !step(&low, false).is_some_and(|below| gt.contains(&below)) {
            problems.push(format!(
                "apache.json 의 하한 {low} 에 맞는 version_gt 가 {} 에 없다",
                m.id
            ));
        }
    }
    let mut ceilings: Vec<String> = [
        &apache["upstream"]["affected"][1],
        &apache["module"]["affected"][1],
    ]
    .iter()
    .filter_map(|v| step(&text(v), true))
    .collect();
    ceilings.extend(
        lines
            .iter()
            .map(|l| text(&l["supported_from"]))
            .filter(|v| !v.is_empty()),
    );
    for high in ceilings {
        if !lt.contains(&high) {
            problems.push(format!(
                "apache.json 의 상한 · 지원 하한 {high} 에 맞는 version_lt 가 {} 에 없다",
                m.id
            ));
        }
    }
    Ok(mine.len())
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
    let apache_text = read(root, &format!("{DIR}/apache.json"))?;
    remedy_net::criteria::check_texts(&url_text, &base_text, &apache_text)?;
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
    let apache: Value = serde_json::from_str(&apache_text).map_err(|e| e.to_string())?;
    let mut problems = Vec::new();
    check_url(root, &url, &mut problems)?;
    check_fixed(root, &base, &mut problems)?;
    check_php_hashes(root, &base, &mut problems)?;
    check_node_hashes(root, &base, &mut problems)?;
    let apache_fixed = check_apache(root, &apache, &mut problems)?;
    if !problems.is_empty() {
        return Err(format!(
            "net-criteria — 기준과 본체의 점검 룰이 어긋난다 {}건:\n  {}",
            problems.len(),
            problems.join("\n  ")
        ));
    }
    let n = |p: &str| hashes(&base, p).len();
    println!(
        "net-criteria OK — {} {} 의 url 표 · 기준 {}(PHP 해시 {} · Node 해시 {}) · Apache 고친 판 {}이 본체의 점검 룰 다섯과 같다",
        m.id,
        m.version,
        base["version"].as_str().unwrap_or_default(),
        n("php"),
        n("node"),
        apache_fixed
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

    #[test]
    fn op_values_and_steps() {
        let rule = "- { field: version, op: pkg_version_lt, value: \"2.4.71-1\" }\n  { op: version_gt, value: \"2.4.54\" } { op: version_gt, value: \"2.0.7\" }";
        assert_eq!(
            op_values(rule, &["pkg_version_lt"])
                .into_iter()
                .collect::<Vec<_>>(),
            ["2.4.71-1"]
        );
        assert_eq!(op_values(rule, &["version_gt"]).len(), 2);
        assert_eq!(step("2.4.55", false).as_deref(), Some("2.4.54"));
        assert_eq!(step("2.0.42", true).as_deref(), Some("2.0.43"));
        assert_eq!(step("2.4.0", false), None);
    }

    /// 이름 붙인 손질 하나 — 기준 JSON 의 값 하나를 바꾼다.
    type Edit = (&'static str, fn(&mut Value));

    /// 거꾸로 잰다 — 저장소의 Apache 기준에서 값 하나를 바꾸면 검사가 그것을 잡는다(고친 판 · 공급사 · 하한 · 상한).
    #[test]
    fn a_changed_apache_value_is_caught() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("저장소 뿌리");
        let good: Value =
            serde_json::from_str(&read(root, &format!("{DIR}/apache.json")).unwrap()).unwrap();
        let mut ok = Vec::new();
        // 서로 다른 고친 판의 수 — 줄은 21 이지만 SUSE 줄은 고친 판이 없고, Rocky 의 두 줄은 RHEL 본류와 같은 판이다.
        assert_eq!(check_apache(root, &good, &mut ok).unwrap(), 18);
        assert!(ok.is_empty(), "{ok:?}");
        let edits: [Edit; 6] = [
            ("고친 판", |v| {
                v["lines"][0]["fixed"] = "2.4.71-1~deb12u2".into()
            }),
            ("공급사", |v| v["lines"][8]["vendor"] = "Red Hat".into()),
            ("하한", |v| v["upstream"]["affected"][0] = "2.4.56".into()),
            ("mod_h2 상한", |v| {
                v["module"]["affected"][1] = "2.0.41".into()
            }),
            ("지원 하한", |v| {
                v["lines"][20]["supported_from"] = "3.20".into()
            }),
            ("같은 룰", |v| {
                v["same_as"] = "apache-http2-check-linux 0.1.0".into()
            }),
        ];
        for (name, edit) in edits {
            let mut v = good.clone();
            edit(&mut v);
            let mut problems = Vec::new();
            check_apache(root, &v, &mut problems).unwrap();
            assert!(!problems.is_empty(), "{name} 을 바꿨는데 잡지 못했다");
        }
    }
}
