//! 플러그인 버전 잠금 — **룰을 고치면 플러그인 버전을 올린다** (결정 2026-09-06).
//!
//! # 왜 필요한가
//!
//! 고객 화면의 첫 줄이 플러그인의 `version` 을 적는다. 룰(`rules/*.yar`)이나
//! 매니페스트만 고치고 버전을 그대로 두면 **고객이 보는 것은 같은데 도구는
//! 다른 것**이 된다. 서명과 실기기 증거는 그 차이를 잡지만 고객은 모른다.
//!
//! 린트는 매니페스트 하나만 보므로 "전과 달라졌는가" 를 알 수 없다. 그것을
//! 아는 자리는 저장소이고, 저장소 게이트가 하는 일은 늘 같다 — **견준다.**
//!
//! # 무엇과 견주는가 (2026-11-21 부터)
//!
//! 전에는 `plugins/versions.lock.json` 에 플러그인마다 버전과 파일 해시를 커밋해 두고 견줬다. 룰 PR 마다 그 파일을
//! 고쳐 셋이 함께 지으면 부딪혔다(목표 remedy_하루30건_대응체계 차례 2) — 이제 견주는 상대는 **git 의 바탕**이다
//! (`crate::gitbase` — PR 은 받는 가지의 끝, 출시는 지금 Latest 의 태그). 보는 파일은 그대로 `plugin.yaml` 과
//! `rules/` 의 파일이고, 데이터 룰은 맨 위의 데이터 파일도 본다.
//!
//! | 상황 | 판정 |
//! |---|---|
//! | 바탕에 없는 플러그인 | 통과 — 새 룰 |
//! | 파일이 그대로다 | 통과 |
//! | 파일이 바뀌었고 `version` 도 올랐다 | 통과 |
//! | 파일이 바뀌었는데 `version` 이 그대로다 | **실패** — 버전을 올릴 것 |
//! | `version` 이 내려갔다 | **실패** |
//!
//! ```text
//! cargo xtask plugin-lock                 바탕을 스스로 고른다(gitbase 의 차례)
//! cargo xtask plugin-lock --base <ref>    그 커밋 · 태그와 견준다(배포 잡은 지금 Latest)
//! ```

use crate::gitbase;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// 잠글 플러그인 폴더(저장소 기준 상대 경로). 제품 플러그인과 시험의 정답 여섯이다.
fn plugin_dirs(root: &Path) -> Result<Vec<String>, String> {
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
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let rel = if base == "plugins" {
                format!("{base}/{name}")
            } else {
                format!("{base}/{name}/reference-plugin")
            };
            if root.join(&rel).join("plugin.yaml").exists() {
                out.push(rel);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    version: String,
    /// 플러그인 폴더 기준 상대 경로(`/` 구분) → sha256.
    files: BTreeMap<String, String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// 데이터 룰(`kind: data`)에서 잠그지 않는 파일 — 서명 둘과 사람이 읽는 기록.
const NOT_DATA: [&str; 3] = ["MANIFEST", "MANIFEST.minisig", "RELEASE.md"];

fn parse(text: &str, at: &str) -> Result<remedy_sdk::manifest::PluginManifest, String> {
    serde_yaml_ng::from_str(text).map_err(|e| format!("{at}: {e}"))
}

/// 플러그인 폴더의 지금 상태(작업 트리). `plugin.yaml` 과 `rules/` 의 파일만 본다 — 그 둘이 치료를 정한다.
/// **데이터 룰은 맨 위의 데이터 파일도 본다**(코어 1.12.0) — 판정 기준이 그 파일들에 있으므로, 기준을 고치면 버전을
/// 올리게 한다. 셋째 값은 그 룰의 `added`(코어 1.25.0 — [`added_too_late`] 가 본다).
fn entry_now(root: &Path, rel: &str) -> Result<(String, Entry, Option<String>), String> {
    let dir = root.join(rel);
    let yaml = std::fs::read(dir.join("plugin.yaml")).map_err(|e| format!("{rel}: {e}"))?;
    let m = parse(&String::from_utf8_lossy(&yaml), rel)?;
    let mut files = BTreeMap::new();
    files.insert("plugin.yaml".to_string(), sha256_hex(&yaml));
    let rules = dir.join("rules");
    if rules.is_dir() {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&rules)
            .map_err(|e| format!("{}: {e}", rules.display()))?
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
            let bytes = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            files.insert(format!("rules/{name}"), sha256_hex(&bytes));
        }
    }
    if m.kind == Some(remedy_sdk::manifest::PluginKind::Data) {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
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
                let bytes = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                files.insert(name, sha256_hex(&bytes));
            }
        }
    }
    Ok((
        m.id.clone(),
        Entry {
            version: m.version.clone(),
            files,
        },
        m.added.clone(),
    ))
}

/// 바탕(`rev`)의 같은 폴더 — `entry_now` 와 같은 파일을 git 에서 읽는다. 바탕에 그 폴더가 없으면 `None`(새 룰).
/// 줄바꿈은 `.gitattributes` 가 LF 로 고정해 작업 트리와 git 의 바이트가 같다.
fn entry_at(root: &Path, rev: &str, rel: &str) -> Result<Option<Entry>, String> {
    let Some(yaml) = gitbase::show(root, rev, &format!("{rel}/plugin.yaml"))? else {
        return Ok(None);
    };
    let m = parse(&String::from_utf8_lossy(&yaml), &format!("{rev}:{rel}"))?;
    let mut files = BTreeMap::new();
    files.insert("plugin.yaml".to_string(), sha256_hex(&yaml));
    let all = gitbase::ls(root, rev, rel)?;
    let prefix = format!("{rel}/");
    let data = m.kind == Some(remedy_sdk::manifest::PluginKind::Data);
    for path in &all {
        let Some(tail) = path.strip_prefix(&prefix) else {
            continue;
        };
        let key = if let Some(r) = tail.strip_prefix("rules/") {
            if r.contains('/') {
                continue;
            }
            format!("rules/{r}")
        } else if data && !tail.contains('/') && tail != "plugin.yaml" && !NOT_DATA.contains(&tail)
        {
            tail.to_string()
        } else {
            continue;
        };
        if let Some(bytes) = gitbase::show(root, rev, path)? {
            files.insert(key, sha256_hex(&bytes));
        }
    }
    Ok(Some(Entry {
        version: m.version.clone(),
        files,
    }))
}

/// `X.Y.Z` 를 수 셋으로. 꼴이 아니면 `None`(그 꼴은 SDK 의 `validate` 가 본다).
fn semver3(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.split('.').map(|p| p.parse::<u64>().ok());
    let t = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(t)
}

/// 바탕과 지금을 견준 판정 — 문제면 그 까닭.
fn judge(base: Option<&Entry>, cur: &Entry) -> Option<String> {
    let base = base?;
    if base.files == cur.files {
        return None;
    }
    if base.version == cur.version {
        let changed: Vec<&str> = cur
            .files
            .iter()
            .filter(|(k, v)| base.files.get(*k) != Some(v))
            .map(|(k, _)| k.as_str())
            .chain(
                base.files
                    .keys()
                    .filter(|k| !cur.files.contains_key(*k))
                    .map(String::as_str),
            )
            .collect();
        return Some(format!(
            "룰이 바뀌었는데 version 이 {} 그대로다 — 바뀐 것: {}\n      \
             고객 화면은 이 버전을 적는다. plugin.yaml 의 version 을 올리고 그 버전의 업데이트 내역 조각을 \
             docs/changes/ 에 더할 것",
            cur.version,
            changed.join(", ")
        ));
    }
    if let (Some(b), Some(c)) = (semver3(&base.version), semver3(&cur.version)) {
        if c < b {
            return Some(format!(
                "version 이 {} 에서 {} 로 내려갔다 — 받은 사람의 화면이 옛 버전을 새것으로 적는다",
                base.version, cur.version
            ));
        }
    }
    None
}

/// 룰의 `added` 가 오늘(KST)보다 **하루 넘게 늦은가** — 그러면 그 까닭. 미래 날짜 오타(`2062-11-19`) 하나가 꾸러미의
/// 가장 새 날이 되면 그날까지 다른 룰이 고르는 화면의 *새로 추가된 항목* 에 오르지 못하고, 꼬리표는 월 · 일만 적어
/// 화면에서는 드러나지 않는다(2026-11-19 검토). 하루는 자정을 넘겨 적은 날을 받는 여유다. 꼴이 틀린 날은 SDK 의
/// `validate` 가 거절하므로 여기서는 보지 않는다. 2026-11-21 까지는 기준이 룰 버전 파일의 날이었다 — 그 파일은 이제
/// 출시 때 정한다.
fn added_too_late(added: &str, today: i64) -> Option<String> {
    let day = remedy_sdk::utc::day_number(added)?;
    (day > today + 1).then(|| {
        format!(
            "added '{added}' 가 오늘(KST)보다 늦다 — 미래 날짜는 그날까지 다른 룰을 새로 추가된 항목에서 밀어낸다"
        )
    })
}

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "--write") {
        return Err(
            "plugin-lock --write 는 없다 — 2026-11-21 부터 잠금 파일(plugins/versions.lock.json)을 두지 않고 git 의 \
             바탕과 견준다. 룰을 고쳤으면 version 을 올리고 docs/changes/ 에 조각을 더할 것"
                .into(),
        );
    }
    let base = gitbase::resolve(root, args)?;
    let today = gitbase::today_kst();
    let mut errors = Vec::new();
    let mut n = 0;
    for rel in plugin_dirs(root)? {
        let (id, cur, added) = entry_now(root, &rel)?;
        if let Some(why) = added.as_deref().and_then(|a| added_too_late(a, today)) {
            errors.push(format!(
                "{id} ({rel}): {why}\n      plugin.yaml 의 added 를 그 위협을 더한 한국 날짜로 고칠 것"
            ));
        }
        let at_base = entry_at(root, &base, &rel)?;
        if let Some(why) = judge(at_base.as_ref(), &cur) {
            errors.push(format!("{id} ({rel}): {why}"));
        }
        n += 1;
    }
    if !errors.is_empty() {
        return Err(format!(
            "플러그인 버전 잠금 {}건 문제(바탕 {base}):\n  {}",
            errors.len(),
            errors.join("\n  ")
        ));
    }
    println!(
        "plugin-lock OK — 플러그인 {n}개, 바탕 {base} 와 견줘 룰을 고친 것은 전부 버전을 올렸다"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{added_too_late, judge, Entry};
    use std::collections::BTreeMap;

    fn entry(version: &str, files: &[(&str, &str)]) -> Entry {
        Entry {
            version: version.into(),
            files: files
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    /// 오늘과 그다음 날까지는 받고, 그보다 늦으면(연도 · 월 오타) 멈춘다.
    #[test]
    fn an_added_date_later_than_today_is_refused() {
        let today = remedy_sdk::utc::day_number("2026-11-19").expect("날");
        assert_eq!(added_too_late("2026-11-18", today), None);
        assert_eq!(added_too_late("2026-11-19", today), None);
        assert_eq!(
            added_too_late("2026-11-20", today),
            None,
            "자정을 넘긴 하루"
        );
        for typo in ["2026-11-21", "2026-12-19", "2062-11-19"] {
            assert!(added_too_late(typo, today).is_some(), "{typo}");
        }
        // 꼴이 틀린 날은 validate 의 몫이다 — 여기서는 말하지 않는다.
        assert_eq!(added_too_late("2026-11-31", today), None);
    }

    /// 표의 다섯 갈래 — 새 룰 · 그대로 · 올림 · 그대로인 버전 · 내린 버전.
    #[test]
    fn the_five_cases_of_the_table() {
        let a = entry("0.2.1", &[("plugin.yaml", "aa"), ("rules/x.yar", "11")]);
        assert_eq!(judge(None, &a), None, "바탕에 없는 새 룰");
        assert_eq!(judge(Some(&a), &a), None, "그대로");
        let bumped = entry("0.2.2", &[("plugin.yaml", "bb"), ("rules/x.yar", "11")]);
        assert_eq!(judge(Some(&a), &bumped), None, "바뀌고 올렸다");
        let same = entry("0.2.1", &[("plugin.yaml", "aa"), ("rules/x.yar", "22")]);
        let why = judge(Some(&a), &same).expect("버전을 안 올렸다");
        assert!(why.contains("rules/x.yar"), "{why}");
        let gone = entry("0.2.1", &[("plugin.yaml", "aa")]);
        assert!(
            judge(Some(&a), &gone).is_some(),
            "지운 룰 파일도 바뀐 것이다"
        );
        let lower = entry("0.1.9", &[("plugin.yaml", "cc"), ("rules/x.yar", "11")]);
        assert!(judge(Some(&a), &lower).unwrap().contains("내려갔다"));
        // 파일이 그대로면 버전만 바꿔도 통과다(바탕과 견줄 것이 없다).
        let only_version = entry("0.2.9", &[("plugin.yaml", "aa"), ("rules/x.yar", "11")]);
        assert_eq!(judge(Some(&a), &only_version), None);
    }
}
