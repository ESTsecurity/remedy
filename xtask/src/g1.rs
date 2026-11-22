//! `cargo xtask g1` — 저장소의 룰 전부를 청정 코퍼스에 대어 판정 0 · 파괴 동작 0 을 본다(G1 · 2026-11-22).
//!
//! `crates/remedy-core/tests/corpus.rs` 의 G1 은 손으로 적는 목록(위협 룰 넷 · 랩 룰 · 가이드 예제)만 돈다. 목록 밖의 룰(점검 룰
//! 전부)은 출시 때 사람이 `remedy evaluate` 로 손 루프를 돌고 그 결과를 출시 기록에 적었다 — 기계가 다시 보지 않았다. 여기서는
//! `plugins/*/plugin.yaml` 을 모두 읽어 같은 길(평가 → 계획 → `is_clean`)로 잰다. 룰을 더하면 저절로 든다 — 목록에 적는 일이 없다.
//!
//! - 데이터 룰(`kind: data`)은 판정이 없어 뺀다(`cargo xtask net-criteria` 가 본다). 원격 점검 룰(`network:`)도 뺀다 — 판정을
//!   동반 프로그램이 대상 주소 · 이미지에서 내고, 이 기계의 스냅샷으로 평가하지 않는다.
//! - 룰이 선언한 플랫폼의 스냅샷에만 댄다. 그 플랫폼의 스냅샷이 하나도 없으면 실패다 — 0개를 재고 통과라 하지 않는다.
//! - **관측 모자람(6)은 실패가 아니라 알림이다** — G1 은 청정 기계에서 판정 · 파괴 동작이 서는지를 본다(승인자의 아홉 가지 7).
//!   스냅샷에 YARA 가 볼 본문이 없어 규칙이 미평가된 것(코퍼스의 한계)과 룰이 선언한 확인 필요(공식 빌드 해시와 다른 실행
//!   파일 등)가 거기 든다 — 까닭을 갈라 알린다.
//! - 스냅샷은 작업 스레드마다 하나씩 읽어 그 플랫폼의 룰 전부에 대고 버린다(큰 스냅샷은 풀면 수십 MB 다 · 스레드는 8 까지).
//! - 엔진 경로(`crates/`) 밖이라 이 검사를 고쳐도 룰만 바뀐 출시가 막히지 않는다.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use remedy_sdk::catalog::Platform;
use remedy_sdk::manifest::{PluginKind, PluginManifest};

/// 룰 하나 — 이름 · 매니페스트 · 실은 `.yar`(제품 CLI 의 `load_rules` 와 같은 이름 `rules/<파일>`).
struct Rule {
    id: String,
    manifest: PluginManifest,
    yar: Vec<(String, String)>,
}

/// 룰 하나 × 스냅샷 하나를 잰 것.
struct Pair {
    rule: String,
    snapshot: String,
    verdicts: usize,
    actions: usize,
    /// 관측이 모자란 까닭(충분하면 `None`).
    short: Option<&'static str>,
}

/// 잰 것을 모은 것 — 룰마다 잰 스냅샷 수 · 판정 · 동작이 선 짝 · 관측이 모자란 짝.
struct Measured {
    faced: BTreeMap<String, usize>,
    bad: Vec<String>,
    short: Vec<String>,
}

pub fn run(root: &Path) -> Result<(), String> {
    let rules = load_rules(root)?;
    let entries =
        remedy_testkit::load_corpus(&root.join("corpus/clean")).map_err(|e| format!("g1: {e}"))?;
    if entries.is_empty() {
        return Err("g1: 청정 코퍼스(corpus/clean)가 비었다 — 잰 것이 없다".into());
    }
    let m = measure(&rules, &entries)?;
    let mut problems = m.bad;
    for r in &rules {
        if m.faced.get(r.id.as_str()).copied().unwrap_or(0) == 0 {
            problems.push(format!(
                "{}: 선언한 플랫폼의 청정 스냅샷이 코퍼스에 없다 — 재지 않았다",
                r.id
            ));
        }
    }
    if !problems.is_empty() {
        let mut msg = format!(
            "g1: 청정 환경에서 판정 · 파괴 동작이 섰다 — {}건\n",
            problems.len()
        );
        for p in &problems {
            msg.push_str(&format!("  {p}\n"));
        }
        return Err(msg);
    }
    let pairs: usize = m.faced.values().sum();
    println!(
        "g1 OK — 룰 {}개(데이터 · 원격 점검 룰 빼고) · 청정 스냅샷 {}개 · 잰 짝 {pairs} — 판정 0 · 파괴 동작 0",
        rules.len(),
        entries.len()
    );
    if !m.short.is_empty() {
        println!(
            "  알림 — 관측 모자람(종료 6) {}짝(실패가 아니다):",
            m.short.len()
        );
        for s in &m.short {
            println!("    {s}");
        }
    }
    Ok(())
}

/// 스냅샷마다 그 플랫폼의 룰 전부를 평가 → 계획한다 — 작업 스레드가 스냅샷을 하나씩 집는다.
fn measure(rules: &[Rule], entries: &[remedy_testkit::CorpusEntry]) -> Result<Measured, String> {
    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 8)
        .min(entries.len().max(1));
    let results: Vec<Result<Vec<Pair>, String>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                s.spawn(|| {
                    let mut out = Vec::new();
                    while let Some(e) = entries.get(next.fetch_add(1, Ordering::Relaxed)) {
                        out.extend(one_snapshot(rules, e)?);
                    }
                    Ok(out)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err("g1: 작업 스레드가 죽었다".into()))
            })
            .collect()
    });
    let mut pairs = Vec::new();
    for r in results {
        pairs.extend(r?);
    }
    pairs.sort_by(|a, b| (&a.snapshot, &a.rule).cmp(&(&b.snapshot, &b.rule)));
    let mut m = Measured {
        faced: BTreeMap::new(),
        bad: Vec::new(),
        short: Vec::new(),
    };
    for p in &pairs {
        *m.faced.entry(p.rule.clone()).or_default() += 1;
        if p.verdicts > 0 || p.actions > 0 {
            m.bad.push(format!(
                "{}/{}: 판정 그룹 {} · Action {}건",
                p.rule, p.snapshot, p.verdicts, p.actions
            ));
        }
        if let Some(why) = p.short {
            m.short.push(format!("{}/{} — {why}", p.rule, p.snapshot));
        }
    }
    Ok(m)
}

/// 스냅샷 하나를 읽어 그 플랫폼의 룰 전부에 댄다.
fn one_snapshot(rules: &[Rule], e: &remedy_testkit::CorpusEntry) -> Result<Vec<Pair>, String> {
    let artifacts =
        remedy_testkit::read_artifacts(&e.path).map_err(|err| format!("g1: {}: {err}", e.name))?;
    let platform = platform_of(&artifacts);
    let mut out = Vec::new();
    for r in rules
        .iter()
        .filter(|r| r.manifest.platforms.contains(&platform))
    {
        let scan = remedy_core::pipeline::evaluate_with_rules(&artifacts, &r.manifest, &r.yar)
            .map_err(|err| format!("g1: {}/{}: 평가 실패 {err}", r.id, e.name))?;
        let plan = remedy_core::pipeline::plan(&scan, Some(&r.manifest))
            .map_err(|err| format!("g1: {}/{}: 계획 실패 {err}", r.id, e.name))?;
        out.push(Pair {
            rule: r.id.clone(),
            snapshot: e.name.clone(),
            verdicts: plan.body.verdicts.len(),
            actions: plan.body.actions.len(),
            short: shortfall(&scan.body.observation, r.manifest.kind),
        });
    }
    Ok(out)
}

/// 관측이 그 룰에 모자란 까닭 — CLI 의 `complete_enough` 와 같은 잣대(점검 룰은 `is_complete_for_check`).
fn shortfall(
    o: &remedy_sdk::artifact::Observation,
    kind: Option<PluginKind>,
) -> Option<&'static str> {
    let enough = match kind {
        Some(PluginKind::Check) => o.is_complete_for_check(),
        _ => o.is_complete(),
    };
    if enough {
        None
    } else if !o.unevaluated_rules.is_empty() {
        Some("YARA 규칙 미평가(스냅샷에 그 파일의 본문이 없다 — 코퍼스의 한계)")
    } else if !o.unconfirmed.is_empty() {
        Some("룰이 선언한 확인 필요")
    } else if !o.unreadable_versions.is_empty() {
        Some("판을 읽지 못했다")
    } else {
        Some("관측 불완전(잘림 · 거부 등)")
    }
}

/// 스냅샷이 뜬 플랫폼 — `host.os` 가 말한다(corpus.rs 와 같은 규칙).
fn platform_of(env: &remedy_sdk::artifact::ArtifactsEnvelope) -> Platform {
    if env.host.os.eq_ignore_ascii_case("windows") {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

/// `plugins/*/plugin.yaml` 전부(이름순) — 데이터 룰 · 원격 점검 룰은 뺀다.
fn load_rules(root: &Path) -> Result<Vec<Rule>, String> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root.join("plugins"))
        .map_err(|e| format!("g1: plugins/: {e}"))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("plugin.yaml").is_file())
        .collect();
    dirs.sort();
    let mut out = Vec::new();
    for d in dirs {
        let id = d
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let text =
            std::fs::read_to_string(d.join("plugin.yaml")).map_err(|e| format!("g1: {id}: {e}"))?;
        let manifest: PluginManifest =
            serde_yaml_ng::from_str(&text).map_err(|e| format!("g1: {id}: 매니페스트 파싱 {e}"))?;
        // 데이터 룰은 판정이 없고, 원격 점검 룰(`network:`)은 판정을 동반 프로그램(remedy-net)이 대상 주소 · 이미지에서 낸다 —
        // 이 기계의 스냅샷으로 평가하는 룰이 아니다(메뉴도 '원격 점검' 묶음으로 따로 둔다 · `discover::menu_facts`).
        if manifest.kind == Some(PluginKind::Data) || manifest.network.is_some() {
            continue;
        }
        let yar = load_yar(&d.join("rules")).map_err(|e| format!("g1: {id}: {e}"))?;
        out.push(Rule { id, manifest, yar });
    }
    if out.is_empty() {
        return Err("g1: plugins/ 에 룰이 없다".into());
    }
    Ok(out)
}

/// `rules/*.yar` — 폴더가 없으면 빈 목록(YARA 없는 룰). 있는데 `.yar` 이 없으면 실패다 — 싣겠다고 해 놓고 못 실으면 YARA 조건이
/// 전부 미평가가 되어 판정 없음이 오탐 0 처럼 보인다.
fn load_yar(dir: &Path) -> Result<Vec<(String, String)>, String> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
    {
        let p = e.path();
        if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("yar")) {
            let name = format!(
                "rules/{}",
                p.file_name().unwrap_or_default().to_string_lossy()
            );
            let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            out.push((name, text));
        }
    }
    if out.is_empty() {
        return Err(format!("{} 에 .yar 이 없다", dir.display()));
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 청정 코퍼스에서 반드시 매치되는 룰을 지어 이 검사가 실제로 무는지 본다 — 물지 못하는 G1 은 늘 초록이다(corpus.rs 의
    /// `the_gate_can_actually_bite_on_every_platform_in_the_corpus` 와 같은 물음을 이 검사의 길로).
    #[test]
    fn the_check_bites_a_rule_that_matches_every_clean_linux_snapshot() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let entries = remedy_testkit::load_corpus(&root.join("corpus/clean")).unwrap();
        let linux: Vec<_> = entries
            .into_iter()
            .filter(|e| {
                platform_of(&remedy_testkit::read_artifacts(&e.path).unwrap()) == Platform::Linux
            })
            .take(2)
            .collect();
        assert!(!linux.is_empty(), "코퍼스에 리눅스 스냅샷이 없다");
        let manifest: PluginManifest = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": "g1-bite", "version": "0.0.0", "min_core": "1.0.0", "platforms": ["linux"],
            "name": { "en": "g1 bite" }, "scan_roots": ["/etc"], "subjects": ["persistence"],
            "detect": [{ "id": "any-unit", "subject": "persistence", "where": [{ "field": "id", "op": "exists" }] }],
            "verdict": { "require": "any-unit" },
            "remediate": { "remove": [{ "ref": "any-unit" }] }
        }))
        .unwrap();
        let rules = vec![Rule {
            id: "g1-bite".into(),
            manifest,
            yar: Vec::new(),
        }];
        let m = measure(&rules, &linux).unwrap();
        assert_eq!(m.faced.get("g1-bite").copied(), Some(linux.len()));
        assert_eq!(
            m.bad.len(),
            linux.len(),
            "반드시 매치되는 룰이 청정 스냅샷에서 서지 않았다 — 이 검사가 공허하다: {:?}",
            m.bad
        );
    }
}
