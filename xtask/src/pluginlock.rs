//! 플러그인 버전 잠금 — **룰을 고치면 플러그인 버전을 올린다** (결정 2026-09-06).
//!
//! # 왜 필요한가
//!
//! 고객 화면의 첫 줄이 플러그인의 `version` 을 적는다. 룰(`rules/*.yar`)이나
//! 매니페스트만 고치고 버전을 그대로 두면 **고객이 보는 것은 같은데 도구는
//! 다른 것**이 된다. 서명과 실기기 증거는 그 차이를 잡지만 고객은 모른다.
//!
//! 린트는 매니페스트 하나만 보므로 "전과 달라졌는가" 를 알 수 없다. 그것을
//! 아는 자리는 저장소이고, 저장소 게이트가 하는 일은 늘 같다 — **기록해 두고
//! 견준다.** 실기기 증거 게이트(`examapply`)와 같은 모양이다.
//!
//! # 무엇을 기록하는가
//!
//! `plugins/versions.lock.json` 에 플러그인마다 `version` 과 **파일별 sha256
//! 지도**를 둔다. 폴더를 한 값으로 접지 않는다 — 접는 규격이 생기면 그것을
//! 적는 언어마다 갈라진다 (`examapply` 의 같은 결정).
//!
//! | 상황 | 판정 |
//! |---|---|
//! | 파일이 그대로다 | 통과 |
//! | 파일이 바뀌었고 `version` 도 올랐다 | **잠금이 낡았다** — `--write` 로 갱신하고 커밋 |
//! | 파일이 바뀌었는데 `version` 이 그대로다 | **실패** — 버전을 올릴 것 |
//! | 잠금에 없는 플러그인 | 실패 — `--write` 로 등록 |
//!
//! `--write` 는 "바뀌었는데 버전이 그대로" 인 경우에도 잠금을 갱신하지 **않는다.**
//! 그것을 허용하면 이 게이트는 규칙이 아니라 서식이 된다.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const LOCK: &str = "plugins/versions.lock.json";

/// 잠글 플러그인 폴더. 제품 플러그인과 시험의 정답 여섯이다.
fn plugin_dirs(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for base in ["plugins", "testbed/ai-exam/threats"] {
        let dir = root.join(base);
        let rd = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for e in rd {
            let e = e.map_err(|e| e.to_string())?;
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            let candidate = if base == "plugins" {
                p.clone()
            } else {
                p.join("reference-plugin")
            };
            if candidate.join("plugin.yaml").exists() {
                out.push(candidate);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Entry {
    version: String,
    /// 플러그인 폴더 기준 상대 경로(`/` 구분) → sha256.
    files: BTreeMap<String, String>,
}

fn sha256_of(p: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

/// 데이터 룰(`kind: data`)에서 잠그지 않는 파일 — 서명 둘과 사람이 읽는 기록.
const NOT_DATA: [&str; 3] = ["MANIFEST", "MANIFEST.minisig", "RELEASE.md"];

/// 플러그인 폴더의 지금 상태. `plugin.yaml` 과 `rules/**` 만 본다 — 그 둘이
/// 치료를 정한다. **데이터 룰은 맨 위의 데이터 파일도 본다**(코어 1.12.0) — 판정 기준이
/// 그 파일들에 있으므로, 기준을 고치면 버전을 올리게 한다.
fn entry_of(dir: &Path) -> Result<(String, Entry), String> {
    let manifest = std::fs::read_to_string(dir.join("plugin.yaml"))
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let m: remedy_sdk::manifest::PluginManifest =
        serde_yaml_ng::from_str(&manifest).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut files = BTreeMap::new();
    files.insert(
        "plugin.yaml".to_string(),
        sha256_of(&dir.join("plugin.yaml"))?,
    );
    let rules = dir.join("rules");
    if rules.is_dir() {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&rules)
            .map_err(|e| format!("{}: {e}", rules.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        paths.sort();
        for p in paths {
            let rel = format!(
                "rules/{}",
                p.file_name().unwrap_or_default().to_string_lossy()
            );
            files.insert(rel, sha256_of(&p)?);
        }
    }
    if m.kind == Some(remedy_sdk::manifest::PluginKind::Data) {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        paths.sort();
        for p in paths {
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name != "plugin.yaml" && !NOT_DATA.contains(&name.as_str()) {
                files.insert(name, sha256_of(&p)?);
            }
        }
    }
    Ok((
        m.id.clone(),
        Entry {
            version: m.version.clone(),
            files,
        },
    ))
}

fn read_lock(root: &Path) -> Result<BTreeMap<String, Entry>, String> {
    let p = root.join(LOCK);
    if !p.exists() {
        return Ok(BTreeMap::new());
    }
    let text = std::fs::read_to_string(&p).map_err(|e| format!("{LOCK}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{LOCK}: {e}"))
}

pub fn run(root: &Path, write: bool) -> Result<(), String> {
    let mut locked = read_lock(root)?;
    let mut errors = Vec::new();
    let mut stale = Vec::new();
    let mut now: BTreeMap<String, Entry> = BTreeMap::new();

    for dir in plugin_dirs(root)? {
        let (id, cur) = entry_of(&dir)?;
        let rel = dir.strip_prefix(root).unwrap_or(&dir).display().to_string();
        match locked.get(&id) {
            None => {
                if write {
                    locked.insert(id.clone(), cur.clone());
                } else {
                    errors.push(format!(
                        "{id} ({rel}): 잠금에 없다.\n      cargo xtask plugin-lock --write 로 등록하고 커밋할 것"
                    ));
                }
            }
            Some(prev) if prev.files == cur.files => {
                if prev.version != cur.version {
                    // 파일은 그대로인데 버전만 올랐다 — 허용하되 잠금을 맞춘다.
                    stale.push(id.clone());
                    if write {
                        locked.insert(id.clone(), cur.clone());
                    }
                }
            }
            Some(prev) if prev.version == cur.version => {
                let changed: Vec<&String> = cur
                    .files
                    .iter()
                    .filter(|(k, v)| prev.files.get(*k) != Some(v))
                    .map(|(k, _)| k)
                    .chain(prev.files.keys().filter(|k| !cur.files.contains_key(*k)))
                    .collect();
                errors.push(format!(
                    "{id} ({rel}): 룰이 바뀌었는데 version 이 {} 그대로다 — 바뀐 것: {}\n      \
                     고객 화면은 이 버전을 적는다. plugin.yaml 의 version 을 올리고 \
                     cargo xtask plugin-lock --write 로 잠금을 갱신할 것",
                    cur.version,
                    changed
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            Some(_) => {
                // 파일이 바뀌었고 버전도 올랐다 — 규칙대로다. 잠금만 낡았다.
                stale.push(id.clone());
                if write {
                    locked.insert(id.clone(), cur.clone());
                }
            }
        }
        now.insert(id, cur);
    }

    if !errors.is_empty() {
        return Err(format!(
            "플러그인 버전 잠금 {}건 문제:\n  {}",
            errors.len(),
            errors.join("\n  ")
        ));
    }
    if write {
        let text = serde_json::to_string_pretty(&locked).map_err(|e| e.to_string())?;
        std::fs::write(root.join(LOCK), text + "\n").map_err(|e| format!("{LOCK}: {e}"))?;
        println!("plugin-lock 갱신 — 플러그인 {}개", locked.len());
        return Ok(());
    }
    if !stale.is_empty() {
        return Err(format!(
            "플러그인 버전 잠금이 낡았다 ({}): 버전은 올랐는데 잠금이 옛것이다.\n  \
             cargo xtask plugin-lock --write 로 갱신하고 커밋할 것",
            stale.join(", ")
        ));
    }
    println!(
        "plugin-lock OK — 플러그인 {}개, 룰을 고친 것은 전부 버전을 올렸다",
        now.len()
    );
    Ok(())
}
