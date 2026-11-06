//! G1 — 청정 코퍼스 오탐 게이트 (설계-04 §3.2, 설계-09 §5).
//!
//! **오탐 방지의 실질적 사거리는 여기다.** 스냅샷이 있으면 VM 없이 CI 에서
//! 수백 개 청정 환경을 초 단위로 돌릴 수 있다 (설계-03 §1).
//!
//! 코퍼스 스냅샷은 **실기기에서** 뜬다.
//!
//! | 플랫폼 | 뜨는 법 |
//! |---|---|
//! | Windows | `testbed\harness\host\Invoke-P2Verify.ps1 -ImportCorpus` |
//! | Linux | `remedy collect` 뒤 `cargo xtask corpus --in <파일> --label <이름> --out corpus/clean` |
//!
//! # 플랫폼마다 따로 재야 한다
//!
//! 코퍼스에 Windows 스냅샷만 있으면 Linux 룰은 **오탐 게이트를 한 번도 지나지
//! 않는다.** 그리고 게이트가 초록인 것과 게이트가 그 플랫폼에서 물 수 있는
//! 것은 다르다 — 그래서 아래 시험들은 코퍼스에 있는 플랫폼 전부를 돌며 각각
//! 확인한다.

use remedy_sdk::catalog::{Platform, Subject};
use remedy_sdk::manifest::PluginManifest;
use remedy_testkit::{is_clean, load_corpus, read_artifacts};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("저장소 루트")
}

fn corpus_dir() -> PathBuf {
    repo_root().join("corpus/clean")
}

#[test]
fn clean_corpus_has_at_least_three_snapshots() {
    // 설계-09 P2 의 요건이다. 하나짜리 코퍼스는 게이트가 아니라 장식이다.
    let entries = load_corpus(&corpus_dir()).expect("코퍼스 로드");
    assert!(
        entries.len() >= 3,
        "corpus/clean 에 스냅샷이 {}개뿐이다. 최소 3개가 필요하다 (설계-09 P2).\n\
         생성: testbed\\harness\\host\\Invoke-P2Verify.ps1 -ImportCorpus",
        entries.len()
    );
}

#[test]
fn clean_snapshots_are_complete() {
    // 잘렸거나 접근이 거부된 스냅샷은 청정 기준이 될 수 없다. 그 안에 "없다" 는
    // "못 봤다" 일 수 있고, 그 위에서 도는 오탐 게이트는 아무것도 보장하지 않는다.
    let entries = load_corpus(&corpus_dir()).expect("코퍼스 로드");
    for e in &entries {
        let env = read_artifacts(&e.path).unwrap_or_else(|err| panic!("{}: {err}", e.name));
        assert!(
            !env.body.scope.truncated,
            "{}: 상한에 걸려 잘린 스냅샷이다",
            e.name
        );
        assert_eq!(
            env.body.scope.denied_dirs, 0,
            "{}: 접근 거부 디렉터리가 있다. 관리자 권한으로 다시 뜰 것",
            e.name
        );
        assert!(
            !env.body.scope.scan_roots.is_empty(),
            "{}: scan_roots 가 비어 있다",
            e.name
        );
    }
}

#[test]
fn corpus_values_stay_inside_the_declared_sets() {
    // `Subject::ENUMERATED_FIELDS` 는 린트가 **오류로 막는** 근거다. 그
    // 전수가 실기기에서 나오는 값과 어긋나면 **맞는 룰이 막힌다** — 없는
    // 필드를 잡는 검사보다 위험한 자리다. 그래서 실기기 스냅샷으로 되재
    // 둔다. 새 값이 나타나면 고객 PC 가 아니라 여기가 먼저 말한다.
    let entries = load_corpus(&corpus_dir()).expect("코퍼스 로드");
    let mut checked = 0usize;
    for e in &entries {
        let env = read_artifacts(&e.path).unwrap_or_else(|err| panic!("{}: {err}", e.name));
        let body = serde_json::to_value(&env.body).expect("본문 직렬화");
        for ef in Subject::ENUMERATED_FIELDS {
            let Some(records) = body.get(ef.subject.id()).and_then(|v| v.as_array()) else {
                continue;
            };
            for r in records {
                let Some(serde_json::Value::String(v)) = r.get(ef.field) else {
                    continue;
                };
                assert!(
                    ef.accepts(v),
                    "{}: {}.{} 에 전수 밖의 값 '{v}' 이 있다.                      `ENUMERATED_FIELDS` 를 고칠 것 — 지금 적힌 전수는 [{}]",
                    e.name,
                    ef.subject.id(),
                    ef.field,
                    ef.values.join(" · ")
                );
                checked += 1;
            }
        }
    }
    // 0 을 통과로 읽지 않는다. subject 이름이나 직렬화가 바뀌면 이 시험은
    // 아무것도 재지 않으면서 초록이 된다.
    assert!(
        checked > 500,
        "코퍼스에서 잰 값이 {checked}개뿐이다 — 필드 이름이나 직렬화가 바뀌었나"
    );
}

/// 스냅샷이 뜬 플랫폼. `host.os` 가 말한다.
fn platform_of(env: &remedy_sdk::artifact::ArtifactsEnvelope) -> Platform {
    if env.host.os.eq_ignore_ascii_case("windows") {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

/// 그 플랫폼의 **반드시 매치되는** 자체 점검 매니페스트.
///
/// 치료까지 적는다 — 판정만 내는 매니페스트로는 `is_clean` 의 Action 검사가
/// 도는지 알 수 없다. 그쪽이 공허해도 시험은 초록이다.
fn selfcheck(platform: Platform) -> PluginManifest {
    let v = match platform {
        Platform::Windows => serde_json::json!({
            "schema_version": 1, "id": "gate-selfcheck", "version": "0.0.0",
            "min_core": "1.0.0", "platforms": ["windows"],
            "name": { "en": "gate self-check" },
            "scan_roots": ["%SystemRoot%\\System32\\Tasks"],
            "subjects": ["persistence"],
            // 예약 작업 id 는 언제나 `\` 로 시작한다.
            "detect": [{ "id": "any-task", "subject": "persistence",
                         "where": [{ "field": "id", "op": "contains", "value": "\\" }] }],
            "verdict": { "require": "any-task" },
            "remediate": { "remove": [{ "ref": "any-task" }] }
        }),
        _ => serde_json::json!({
            "schema_version": 1, "id": "gate-selfcheck", "version": "0.0.0",
            "min_core": "1.0.0", "platforms": ["linux"],
            "name": { "en": "gate self-check" },
            "scan_roots": ["/etc"],
            "subjects": ["persistence"],
            // cron 항목이든 systemd 유닛이든 id 는 있다. 값의 모양은 플랫폼마다
            // 다르므로 **존재만** 묻는다.
            "detect": [{ "id": "any-unit", "subject": "persistence",
                         "where": [{ "field": "id", "op": "exists" }] }],
            "verdict": { "require": "any-unit" },
            "remediate": { "remove": [{ "ref": "any-unit" }] }
        }),
    };
    serde_json::from_value(v).expect("자체 점검 매니페스트")
}

/// 상한을 넉넉히 준다. **여기서 재는 것은 상한이 아니라 게이트다** — 청정
/// 스냅샷의 예약 작업 수백 건이 기본 상한에 걸리면 계획 자체가 서지 않아
/// Action 차원을 볼 수 없다.
fn wide_open() -> remedy_plan::Limits {
    remedy_plan::Limits {
        total_files: u32::MAX,
        same_hash_items: u32::MAX,
        total_bytes: u64::MAX,
        distinct_top_dirs: u32::MAX,
        evidence_groups: u32::MAX,
        ..Default::default()
    }
}

#[test]
fn the_gate_can_actually_bite_on_every_platform_in_the_corpus() {
    // 게이트가 초록인 것과 게이트가 **물 수 있는 것**은 다르다.
    //
    // 청정 코퍼스에서 반드시 매치되는 룰을 일부러 만들어, 이 검사가 정말로
    // 판정을 잡아내는지 확인한다. 이것이 없으면 평가기가 어떻게 망가져
    // 아무것도 매치하지 않게 되더라도 오탐 게이트는 영원히 초록이고,
    // 우리는 보호받고 있다고 믿게 된다.
    //
    // **플랫폼마다 따로 센다.** 합쳐서 세면 Windows 스냅샷 하나가 무는 것으로
    // Linux 코퍼스 전체가 검증된 것처럼 보인다.
    let entries = load_corpus(&corpus_dir()).expect("코퍼스 로드");
    let mut bit: BTreeMap<&str, usize> = BTreeMap::new();
    let mut destructive: BTreeMap<&str, usize> = BTreeMap::new();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();

    for e in &entries {
        let artifacts = read_artifacts(&e.path).unwrap_or_else(|err| panic!("{}: {err}", e.name));
        let platform = platform_of(&artifacts);
        let key = platform.id();
        *seen.entry(key).or_default() += 1;

        let always = selfcheck(platform);
        let scan = remedy_core::evaluate(&artifacts, &always).expect("평가");
        let plan = remedy_core::plan_with(
            &scan,
            Some(&always),
            &remedy_core::Allowed::new(),
            &wide_open(),
            remedy_core::Mode::Interactive,
        )
        .expect("계획");
        if !is_clean(&plan) {
            *bit.entry(key).or_default() += 1;
        }
        if !plan.body.actions.is_empty() {
            *destructive.entry(key).or_default() += 1;
        }
    }

    // **코퍼스에 이 둘이 다 있어야 한다.** 하나만 있으면 나머지 플랫폼의 룰은
    // 오탐 게이트를 한 번도 지나지 않는데, 그 상태의 초록은 "오탐이 없다" 가
    // 아니라 "재지 않았다" 다.
    for want in ["windows", "linux"] {
        assert!(
            seen.contains_key(want),
            "코퍼스에 {want} 스냅샷이 없다. 그 플랫폼의 룰은 G1 을 지나지 않는다.\n\
             본 것: {seen:?}"
        );
    }

    for (platform, n) in &seen {
        assert!(
            bit.get(platform).copied().unwrap_or(0) > 0,
            "{platform}: 스냅샷 {n}개 중 어디에서도 반드시 매치되는 룰이 판정을 \
             내지 못했다. 그 플랫폼의 오탐 게이트가 공허하다 — 평가 경로나 \
             코퍼스 내용을 확인할 것."
        );
    }

    // **P7 부터는 Action 차원도 물어야 한다** (설계-09 P7 "G1이 여기서부터
    // 의미를 갖는다"). P6 까지는 파괴 Op 이 계획될 수 없어 이 수가 언제나 0
    // 이었고, 그래서 `is_clean` 의 Action 검사가 실제로는 아무것도 재지 않았다.
    //
    // **2026-08-27 부터 Linux 도 같은 요구를 받는다.** 그전까지 이 자리는
    // `linux == 0` 이었다 — 실행기가 없어 계획기가 전부 미뤘기 때문이다.
    // 게이트가 P12 로 오르며 그 전제가 끝났고, 이 시험이 그때 깨져 알려 줬다.
    for platform in ["windows", "linux"] {
        assert!(
            destructive.get(platform).copied().unwrap_or(0) > 0,
            "{platform}: 판정은 났는데 파괴 Action 이 한 건도 도출되지 않았다. \
             G1 의 Action 차원이 그 플랫폼에서 공허하다 — 게이트({:?})나 \
             계획기를 확인할 것.",
            remedy_sdk::IMPLEMENTED_THROUGH
        );
    }
}

/// 이 저장소가 싣는 플러그인 전부 — `(이름, 매니페스트, 룰 디렉터리)`.
///
/// 새 플러그인은 **여기에 추가한다.** 빠뜨리면 그 플러그인은 G1 을 통과한 적이
/// 없는 채로 배포된다.
///
/// # 가이드 예제도 여기 있다
///
/// `docs/plugin-guide/examples/` 의 예제들은 배포되지 않지만 **복제된다.** 작성자가
/// 그것을 베껴 룰을 쓰므로, 예제가 청정 환경에서 판정을 내면 그 형태가 그대로
/// 재생산된다. `guide.rs` 는 예제를 자기 `artifacts.json` 에 대고 돌려 *"의도한
/// 것을 잡는가"* 를 재고, 여기서는 **실기기 스냅샷에 대고 "잡지 말아야 할 것을
/// 안 잡는가"** 를 잰다. 둘은 다른 물음이다.
fn plugins() -> Vec<(&'static str, PathBuf, Option<PathBuf>)> {
    let ex = |n: &str| {
        repo_root()
            .join("docs/plugin-guide/examples")
            .join(n)
            .join("plugin.yaml")
    };
    vec![
        (
            "lab-plugin",
            repo_root().join("testbed/harness/guest/lab-plugin.yaml"),
            None,
        ),
        (
            "evilai-locust",
            repo_root().join("plugins/evilai-locust/plugin.yaml"),
            Some(repo_root().join("plugins/evilai-locust/rules")),
        ),
        (
            "cwpdoor-1-check",
            repo_root().join("plugins/cwpdoor-1-check/plugin.yaml"),
            Some(repo_root().join("plugins/cwpdoor-1-check/rules")),
        ),
        (
            "cwpdoor-2-clean",
            repo_root().join("plugins/cwpdoor-2-clean/plugin.yaml"),
            Some(repo_root().join("plugins/cwpdoor-2-clean/rules")),
        ),
        ("ex01-scheduled-task", ex("ex01-scheduled-task"), None),
        ("ex02-registry-ifeo", ex("ex02-registry-ifeo"), None),
        ("ex03-text-config", ex("ex03-text-config"), None),
        // 점검 전용(`remediate` 없음). 계획이 비어도 **판정**이 청정 기계에서
        // 서면 안 된다 — 위 시험은 동작과 판정을 둘 다 본다.
        ("ex04-check-only", ex("ex04-check-only"), None),
    ]
}

/// 제품 CLI 의 `load_rules` 와 같은 규칙 — 이름은 `rules/<파일>.yar` 이다.
///
/// 절대 경로로 담으면 `rules/x.yar:name` 참조가 어긋나 룰이 통째로 미평가가
/// 된다. 그 상태의 "판정 없음" 은 오탐 0건이 아니다.
fn load_yar(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("{}: {err}", dir.display()))
        .flatten()
    {
        let p = e.path();
        if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("yar")) {
            let name = format!("rules/{}", p.file_name().unwrap().to_string_lossy());
            out.push((name, std::fs::read_to_string(&p).expect("룰 파일")));
        }
    }
    out.sort();
    out
}

#[test]
fn plugins_find_nothing_in_clean_environments() {
    // G1 의 본체.
    let entries = load_corpus(&corpus_dir()).expect("코퍼스 로드");
    assert!(
        !entries.is_empty(),
        "코퍼스가 비어 있으면 게이트가 공허하다"
    );

    for (name, manifest_path, rules_dir) in plugins() {
        let text = std::fs::read_to_string(&manifest_path)
            .unwrap_or_else(|err| panic!("{}: {err}", manifest_path.display()));
        let manifest: PluginManifest = serde_yaml_ng::from_str(&text)
            .unwrap_or_else(|err| panic!("{name}: 매니페스트 파싱 {err}"));

        let rules = rules_dir.as_deref().map(load_yar).unwrap_or_default();
        if rules_dir.is_some() {
            // 싣겠다고 해 놓고 못 실으면 yara 조건이 전부 미평가가 된다.
            assert!(!rules.is_empty(), "{name}: rules 에서 .yar 을 읽지 못했다");
        }

        for e in &entries {
            let artifacts =
                read_artifacts(&e.path).unwrap_or_else(|err| panic!("{}: {err}", e.name));
            let scan = remedy_core::pipeline::evaluate_with_rules(&artifacts, &manifest, &rules)
                .unwrap_or_else(|err| panic!("{name}/{}: 평가 실패 {err}", e.name));
            let plan = remedy_core::plan(&scan, Some(&manifest))
                .unwrap_or_else(|err| panic!("{name}/{}: {err}", e.name));

            assert!(
                is_clean(&plan),
                "{name}/{}: 청정 환경에서 판정이 나왔다 — 오탐이다.\n  \
                 판정 그룹 {:?}\n  Action {}건",
                e.name,
                scan.body.verdicts,
                plan.body.actions.len()
            );
        }
    }
}

/// 규칙 하나에 대한 스냅샷 누계 — 마주한 수 · 매치한 수 · 술어별 통과.
#[derive(Default)]
struct Faced {
    records: usize,
    matched: usize,
    per_predicate: Vec<(String, usize)>,
}

/// 규칙마다 **몇 건을 마주했는가**. 0 은 통과가 아니라 "재지 않았다" 다.
///
/// # 왜 파괴 0건만으로는 부족한가
///
/// `plugins_find_nothing_in_clean_environments` 의 초록에는 뜻이 정반대인 둘이
/// 섞인다 — 레코드 12만 건을 걸러 낸 것과, 볼 레코드가 **한 건도 없었던** 것.
/// 게이트는 둘을 같은 초록으로 보고한다.
///
/// 2026-09-04 Windows 코퍼스를 넓히다 드러났다. `C:\ProgramData` 가 코퍼스에
/// 없어서, 거기 페이로드를 두는 위협 셋의 규칙이 후보 0건 위에서 통과하고
/// 있었다. **코퍼스에 넣고 나서야** "청정 서비스 711건 중 0건" 이라는 문장을
/// 쓸 수 있었다.
///
/// # 세는 방법
///
/// 플러그인이 선언한 플랫폼의 스냅샷만 센다. Windows 플러그인이 Linux 스냅샷의
/// 레코드를 마주한 것은 그 플러그인이 시험됐다는 뜻이 아니다.
///
/// **파생 규칙은 세지 않는다.** 부모가 서지 않는 청정 환경에서 자식 규칙은
/// 평가가 시작조차 되지 않으므로(`eval_rule` 이 `from` 을 풀지 못한다), 그
/// 0 은 코퍼스의 문제가 아니라 구조의 성질이다. 그래서 G1 의 판별력은 사실상
/// **뿌리 규칙에 몰려 있고**, 이 시험이 그것을 숨기지 않는다.
#[test]
fn every_root_rule_faces_real_records_in_the_clean_corpus() {
    let entries = load_corpus(&corpus_dir()).expect("코퍼스 로드");

    // (플러그인, 규칙) -> 누계
    let mut faced: BTreeMap<(String, String), Faced> = BTreeMap::new();
    let mut derived: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (name, manifest_path, rules_dir) in plugins() {
        let text = std::fs::read_to_string(&manifest_path)
            .unwrap_or_else(|err| panic!("{}: {err}", manifest_path.display()));
        let manifest: PluginManifest = serde_yaml_ng::from_str(&text)
            .unwrap_or_else(|err| panic!("{name}: 매니페스트 파싱 {err}"));
        let rules = rules_dir.as_deref().map(load_yar).unwrap_or_default();

        for e in &entries {
            let artifacts =
                read_artifacts(&e.path).unwrap_or_else(|err| panic!("{}: {err}", e.name));
            // **그 플러그인의 플랫폼만.** 다른 플랫폼 스냅샷에서 마주친 수를
            // 더하면 Windows 플러그인이 Linux 코퍼스로 시험된 것처럼 보인다.
            if !manifest.platforms.contains(&platform_of(&artifacts)) {
                continue;
            }
            let scope = remedy_core::pipeline::scope_of(&artifacts);
            let snapshot = remedy_detect::Snapshot::from_envelope(&artifacts).with_rules(&rules);

            for p in remedy_detect::pressure(&snapshot, &manifest, &scope) {
                if p.derived {
                    derived
                        .entry(name.to_string())
                        .or_default()
                        .push(p.rule.clone());
                    continue;
                }
                let slot = faced.entry((name.to_string(), p.rule.clone())).or_default();
                slot.records += p.records;
                slot.matched += p.matched;
                if slot.per_predicate.is_empty() {
                    slot.per_predicate = p.per_predicate.clone();
                } else {
                    for (i, (_, n)) in p.per_predicate.iter().enumerate() {
                        if let Some(cell) = slot.per_predicate.get_mut(i) {
                            cell.1 += n;
                        }
                    }
                }
            }
        }
    }

    // 재는 것 자체가 사라지는 것을 막는다. 규칙 목록이나 매니페스트 파싱이
    // 바뀌어 표가 비면 아래 단언은 전부 공허하게 통과한다.
    //
    // **플러그인마다 뿌리가 하나는 있어야 한다** — 개수를 못박지 않는 이유는
    // 그 수가 늘 플러그인 수와 같기 때문이다. 지금 이 저장소의 플러그인 여섯은 각각
    // 뿌리 규칙 **하나**와 파생 규칙 하나 이상으로 되어 있다. 숫자를 적으면 규칙을
    // 하나 더할 때마다 고쳐야 하고, 고치다 보면 0 도 함께 지나간다.
    for (name, _, _) in plugins() {
        assert!(
            faced.keys().any(|(p, _)| p == name),
            "{name}: 뿌리 규칙이 하나도 잡히지 않았다. 전부 파생이면 이 플러그인은 \
             청정 코퍼스로 시험된 적이 없다 — 부모 없이는 자식이 평가되지 않는다"
        );
    }

    let mut report = String::from("\n청정 코퍼스가 뿌리 규칙에 가한 압력\n");
    let mut starved = Vec::new();
    for ((plugin, rule), f) in &faced {
        report.push_str(&format!(
            "  {plugin:<22} {rule:<16} 마주 {:>7} · 매치 {}\n",
            f.records, f.matched
        ));
        for (label, n) in &f.per_predicate {
            report.push_str(&format!("      {n:>7} ← {label}\n"));
        }
        if f.records == 0 {
            starved.push(format!("{plugin}/{rule}"));
        }
    }
    println!("{report}");

    assert!(
        starved.is_empty(),
        "{}\n이 뿌리 규칙들은 청정 코퍼스에서 레코드를 한 건도 마주하지 않았다: {}\n\
         그 초록은 '오탐이 없다' 가 아니라 '재지 않았다' 다. 해당 subject 를 담은 \
         스냅샷을 코퍼스에 넣거나, 잴 수 없다는 사실을 문서에 적을 것.",
        report,
        starved.join(" · ")
    );

    // 마주치기만 하고 아무것도 걸러 내지 않는 규칙은 없어야 한다 — 매치가
    // 났다면 그것은 오탐이고 `plugins_find_nothing_in_clean_environments` 가
    // 먼저 물어야 한다. 여기서 다시 확인하는 이유는 그 시험이 판정(verdict)
    // 차원에서 보는 반면 이쪽은 **규칙 차원**이기 때문이다. 판정식이 여러
    // 규칙을 요구하면 규칙 하나가 청정 레코드를 물어도 판정은 서지 않는다.
    for ((plugin, rule), f) in &faced {
        assert_eq!(
            f.matched, 0,
            "{plugin}/{rule}: 청정 레코드 {}건을 물었다. 판정까지 가지 \
             않았을 뿐 규칙 차원에서는 오탐이다",
            f.matched
        );
    }
}

/// 압력을 재는 것 자체가 **0 과 많음을 구별하는가**.
///
/// `every_root_rule_faces_real_records_in_the_clean_corpus` 는 "0 이 아니다" 로
/// 통과한다. 그러니 재는 쪽이 망가져 언제나 큰 수를 내놓으면 그 시험은 영원히
/// 초록이고, 우리는 모든 규칙이 압력을 받고 있다고 믿게 된다. 이 저장소가
/// `the_gate_can_actually_bite_on_every_platform_in_the_corpus` 를 두는 것과
/// 같은 이유다 — **게이트를 재는 게이트.**
///
/// 코퍼스에 있는 subject 와 없는 subject 를 같은 스냅샷에 대고 함께 묻는다.
/// 둘이 갈리지 않으면 압력 수치는 아무 뜻이 없다.
#[test]
fn the_pressure_probe_tells_zero_from_many() {
    let entries = load_corpus(&corpus_dir()).expect("코퍼스 로드");
    // Windows 스냅샷 하나면 된다 — `persistence` 는 차 있고 `hosts_entry` 는
    // Windows 수집기가 채우지 않아 비어 있다 (2026-09-04 실측: 0건).
    let win = entries
        .iter()
        .map(|e| read_artifacts(&e.path).unwrap_or_else(|err| panic!("{}: {err}", e.name)))
        .find(|a| platform_of(a) == Platform::Windows)
        .expect("Windows 스냅샷");

    let m: PluginManifest = serde_json::from_value(serde_json::json!({
        "schema_version": 1, "id": "pressure-probe", "version": "0.0.0",
        "min_core": "1.0.0", "platforms": ["windows"],
        "name": { "en": "pressure probe" },
        "scan_roots": [r"%SystemRoot%\System32\Tasks"],
        "subjects": ["persistence", "hosts_entry"],
        "detect": [
            { "id": "full", "subject": "persistence",
              "where": [{ "field": "id", "op": "exists" }] },
            { "id": "empty", "subject": "hosts_entry",
              "where": [{ "field": "line", "op": "exists" }] }
        ],
        "verdict": { "require": "full" }
    }))
    .expect("탐침 매니페스트");

    let scope = remedy_core::pipeline::scope_of(&win);
    let snapshot = remedy_detect::Snapshot::from_envelope(&win);
    let p = remedy_detect::pressure(&snapshot, &m, &scope);

    let full = p.iter().find(|x| x.rule == "full").expect("full");
    let empty = p.iter().find(|x| x.rule == "empty").expect("empty");

    assert!(
        full.records > 0,
        "차 있는 subject 에서 0 이 나왔다 — 압력 측정이 레코드를 못 찾는다"
    );
    assert_eq!(
        empty.records, 0,
        "비어 있는 subject 에서 {}건이 나왔다 — 압력 측정이 subject 를 구별하지 못한다",
        empty.records
    );
    // 있는 쪽은 술어가 실제로 통과시켜야 한다. `exists` 가 전부 거짓이면
    // 마주친 수만 크고 술어 칸은 전부 0 인 표가 나오는데, 그것은 압력이 아니라
    // 평가 경로가 끊긴 것이다.
    assert_eq!(
        full.per_predicate.first().map(|x| x.1),
        Some(full.records),
        "`id exists` 가 {}건 중 일부만 통과했다 — 술어 평가 경로를 확인할 것",
        full.records
    );
}

/// 청정 코퍼스가 **재지 못하는** subject 와 그 이유. `(subject, 플랫폼, 왜)`.
///
/// # 0 은 네 가지 뜻이고 할 일이 전부 다르다
///
/// | | 뜻 | 할 일 |
/// |---|---|---|
/// | A | 그 플랫폼에 **개념이 없다** | 없다 — 룰을 다시 짠다 |
/// | B | 개념은 있으나 **이 코어가 수집하지 않는다** | 수집기를 쓴다. 린트가 이미 말한다 |
/// | C | 수집하는데 **코퍼스 기계에 그것이 없다** | 그런 기계를 하나 뜬다 |
/// | D | 수집하고 기계에도 있는데 **코퍼스가 그 자리를 안 봤다** | `scan_roots` 를 고쳐 다시 뜬다 |
///
/// 압력 시험(`every_root_rule_faces_real_records_in_the_clean_corpus`)은 넷을
/// **같은 문장으로** 보고한다. 그것이 옳다 — 그 시험이 재는 것은 "쟀는가" 이지
/// "왜 못 쟀는가" 가 아니다. 대신 이유를 여기 적어 둔다.
///
/// A 는 적지 않는다. 개념이 없는 자리는 `SubjectInfo` 가 이미 말하고 아래
/// 시험이 먼저 걸러 낸다.
///
/// # 표가 줄기도 해야 한다
///
/// 메워진 자리가 표에 남아 있으면 **실패한다.** 그러지 않으면 이 표는 자라기만
/// 하고, 이미 해결된 구멍이 영원히 "못 잼" 으로 남는다.
const UNMEASURED: &[(&str, &str, &str)] = &[
    (
        "hosts_entry",
        "windows",
        "C — 기본 Windows 의 hosts 파일에는 항목이 없다. 실기기에서 확인했다 \
         (2026-09-04: 21줄 전부 주석). 뒤집어 말하면 **Windows 에서 hosts 항목은 \
         그 자체로 드물다.** 항목이 있는 기계를 하나 뜨면 메워진다",
    ),
    (
        "browser_extension",
        "linux",
        "C — 상한은 닿는다. `%ALLUSERPROFILES%/.config` 를 더해 실제 크로미움 \
         프로필 파일 129건을 모았는데도 확장은 0개였다 \
         (`docker-debian12-chromium`, 2026-09-04). Debian 의 chromium 은 기본 \
         확장을 싣지 않는다 — 확장이 설치된 데스크톱을 하나 뜨면 메워진다",
    ),
    (
        "av_exclusion",
        "linux",
        "B — 이 코어가 Linux 에서 수집하지 않는다 (`linux_from: None`). \
         코퍼스로 메울 수 있는 자리가 아니다",
    ),
    ("boot_config", "linux", "B — 위와 같다"),
    ("firewall_rule", "linux", "B — 위와 같다"),
    ("proxy_config", "linux", "B — 위와 같다"),
];

/// 비어 있는 subject 마다 **왜 비었는지가 적혀 있는가.**
///
/// 압력 시험은 뿌리 규칙이 마주한 수를 본다. 그런데 지금 아무 규칙도 쓰지 않는
/// subject 는 그 시험에 걸리지 않는다 — 누군가 처음 그것을 쓰는 날 비로소
/// 0 이 드러나고, 그때 **왜 0 인지를 다시 조사해야 한다.** 그 조사는 이미
/// 2026-09-04 에 한 번 했다(`Linux-빈-주체-넷.md`). 두 번 하지 않도록 결과를
/// 소스에 둔다.
#[test]
fn every_empty_subject_has_a_recorded_reason() {
    let entries = load_corpus(&corpus_dir()).expect("코퍼스 로드");
    let mut count: BTreeMap<(&str, &str), usize> = BTreeMap::new();

    for e in &entries {
        let env = read_artifacts(&e.path).unwrap_or_else(|err| panic!("{}: {err}", e.name));
        let plat = platform_of(&env).id();
        let body = serde_json::to_value(&env.body).expect("본문 직렬화");
        for s in Subject::ALL {
            let n = body
                .get(s.id())
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            *count.entry((plat, s.id())).or_default() += n;
        }
    }

    let mut unexplained = Vec::new();
    let mut stale = Vec::new();
    let mut looked = 0usize;

    for plat in ["windows", "linux"] {
        for s in Subject::ALL {
            let i = s.info();
            // 개념이 없으면(A) 코퍼스가 채울 것이 아니다.
            let exists = if plat == "windows" {
                i.windows
            } else {
                i.linux
            };
            if !exists {
                continue;
            }
            looked += 1;
            let n = count.get(&(plat, s.id())).copied().unwrap_or(0);
            let recorded = UNMEASURED
                .iter()
                .any(|(id, p, _)| *id == s.id() && *p == plat);
            match (n, recorded) {
                (0, false) => unexplained.push(format!("{plat}/{}", s.id())),
                (n, true) if n > 0 => stale.push(format!("{plat}/{} ({n}건)", s.id())),
                _ => {}
            }
        }
    }

    // 0 을 통과로 읽지 않는다. subject 이름이나 직렬화가 바뀌면 이 시험은
    // 아무것도 보지 않으면서 초록이 된다.
    assert!(
        looked >= 20,
        "본 (플랫폼, subject) 짝이 {looked}개뿐이다 — Subject::ALL 이나 직렬화를 확인할 것"
    );

    assert!(
        unexplained.is_empty(),
        "이 자리들이 청정 코퍼스에서 0건인데 이유가 적혀 있지 않다: {}\n\
         `UNMEASURED` 에 한 줄을 더할 것 — 넷 중 무엇인지 판단해서 적는다.\n\
           B 수집기가 없다 (`SubjectInfo::linux_from` 이 `None`)\n\
           C 수집은 하는데 코퍼스 기계에 그것이 없다\n\
           D 수집하고 기계에도 있는데 코퍼스가 그 자리를 안 봤다 — `scan_roots` 를 고친다\n\
         C 와 D 를 가르려면 **그 subject 가 사는 자리를 상한에 넣고 한 번 떠 본다.**",
        unexplained.join(" · ")
    );

    assert!(
        stale.is_empty(),
        "이 자리는 메워졌는데 `UNMEASURED` 에 아직 '못 잼' 으로 남아 있다: {}\n\
         표에서 지울 것 — 남겨 두면 해결된 구멍이 영원히 구멍으로 보고된다.",
        stale.join(" · ")
    );
}

/// `NOT_POPULATED_YET` 이 **실기기와 맞는가.**
///
/// # 왜 코퍼스가 이것을 되재야 하는가
///
/// 그 표는 *"이 필드는 아직 비어 있다"* 를 선언하고, 린트와 평가기가 그것을
/// 근거로 **"이 술어는 언제나 거짓이다"** 라고 말한다. 표가 낡으면 그 말이
/// 거짓말이 되는데, **수집기가 채우기 시작하는 것은 표와 아무 상관이 없다** —
/// 아무도 지우라고 말해 주지 않는다.
///
/// 실제로 그랬다. `file.signature` 를 `remedy-wintrust` 가 채우기 시작한 뒤에도
/// 표가 *"언제나 없다"* 를 들고 있었고, 2026-09-05 에 다른 일을 하다 발견했다.
/// 그 사이 Windows 플러그인은 **가이드가 가르치는 필드를 죽었다고 듣고**
/// 있었다.
///
/// # 두 방향을 다 본다
///
/// - 비었다고 적은 자리에 **값이 있으면** 표가 낡았다.
/// - 한 플랫폼에서만 빈다고 적었는데 **다른 플랫폼에도 없으면** 그 축이 거짓이다
///   (`None` 이어야 한다).
///
/// 뒤엣것이 없으면 표가 반대로 낡는다 — 어디서나 비는 필드를 한쪽만 빈다고
/// 적어 두면, 다른 쪽 작성자가 조용히 0건을 맞힌다.
#[test]
fn the_unpopulated_table_matches_the_corpus() {
    let entries = load_corpus(&corpus_dir()).expect("코퍼스 로드");

    // (플랫폼, subject, 필드) -> 값이 있는 레코드 수
    let mut seen: BTreeMap<(&str, &str, &str), usize> = BTreeMap::new();
    let mut records: BTreeMap<(&str, &str), usize> = BTreeMap::new();

    for e in &entries {
        let env = read_artifacts(&e.path).unwrap_or_else(|err| panic!("{}: {err}", e.name));
        let plat = platform_of(&env).id();
        let body = serde_json::to_value(&env.body).expect("본문 직렬화");
        for (s, field, _only_on, _why) in Subject::NOT_POPULATED_YET {
            let Some(rows) = body.get(s.id()).and_then(|v| v.as_array()) else {
                continue;
            };
            *records.entry((plat, s.id())).or_default() += rows.len();
            let n = rows
                .iter()
                .filter(|r| match r.get(field) {
                    None | Some(serde_json::Value::Null) => false,
                    // 빈 배열은 "열거하지 않았다" 다. 값이 있는 것으로 세지 않는다.
                    Some(serde_json::Value::Array(a)) => !a.is_empty(),
                    Some(_) => true,
                })
                .count();
            *seen.entry((plat, s.id(), field)).or_default() += n;
        }
    }

    // 0 을 통과로 읽지 않는다. subject 이름이나 직렬화가 바뀌면 이 시험은
    // 아무것도 보지 않으면서 초록이 된다.
    let total: usize = records.values().sum();
    assert!(
        total > 1000,
        "표가 가리키는 subject 의 레코드가 {total}건뿐이다 — 직렬화가 바뀌었나"
    );

    let mut wrong = Vec::new();
    for (s, field, only_on, _why) in Subject::NOT_POPULATED_YET {
        for plat in ["windows", "linux"] {
            let n = seen.get(&(plat, s.id(), field)).copied().unwrap_or(0);
            let declared_empty = match only_on {
                None => true,
                Some(p) => p.id() == plat,
            };
            let have = records.get(&(plat, s.id())).copied().unwrap_or(0);
            if have == 0 {
                continue; // 그 플랫폼에 그 subject 자체가 없다. 잴 것이 없다.
            }
            if declared_empty && n > 0 {
                wrong.push(format!(
                    "{plat}/{}.{field}: 비었다고 적었는데 {n}건에 값이 있다 — 표를 고칠 것",
                    s.id()
                ));
            }
            if !declared_empty && n == 0 {
                wrong.push(format!(
                    "{plat}/{}.{field}: 이 플랫폼에서는 채워진다고 적었는데 {have}건 중 \
                     0건이다 — 축을 `None` 으로 되돌릴 것",
                    s.id()
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "`NOT_POPULATED_YET` 이 실기기와 어긋난다:\n  {}\n\
         이 표가 린트와 평가기의 '이 술어는 언제나 거짓이다' 근거다. 낡으면 \
         그 말이 거짓말이 된다.",
        wrong.join("\n  ")
    );
}
