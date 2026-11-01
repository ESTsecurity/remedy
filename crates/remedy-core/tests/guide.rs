//! 가이드 예제는 **문서가 아니라 테스트다** (설계-06 §5, 설계-04 §4 `guide` 작업).
//!
//! AI 는 예제를 **패턴으로 복제한다.** 깨진 예제가 문서에 남아 있으면 그 형태가
//! 그대로 재생산된다. 사람은 "이건 좀 이상한데" 하고 넘어가지만 AI 는 넘어가지
//! 않는다. 그래서 예제를 CI 에서 실행하고, 스키마가 바뀌면 **예제가 먼저 깨진다.**
//!
//! 이 장치는 만들자마자 값을 했다. 첫 ex01 의 룰이 `args matches '(?i)\.js(\s|$)'`
//! 였는데, 실제 인자가 `"...main.js" --run` 이라 `.js` 다음 글자가 따옴표였다.
//! 산문 예제였다면 그대로 남았을 것이다 — 실제로 `docs/design/예시-EvilAI-플러그인.md` 가
//! 같은 패턴을 들고 있었다.

use remedy_sdk::catalog::{Scoping, Subject};
use remedy_sdk::manifest::PluginManifest;
use remedy_testkit::{compare_plan, is_clean, load_corpus, read_artifacts, read_plan};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("저장소 루트")
}

fn examples_dir() -> PathBuf {
    repo_root().join("docs/plugin-guide/examples")
}

/// 예제 하나. 세 파일이 함께 있어야 한다.
struct Example {
    name: String,
    plugin: PluginManifest,
    artifacts: PathBuf,
    expected: PathBuf,
}

fn examples() -> Vec<Example> {
    let dir = examples_dir();
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) => panic!("{}: {e}", dir.display()),
    };
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        // 세 파일 중 하나라도 없으면 **건너뛰지 않고 실패한다.** 조용히
        // 건너뛰면 반쪽짜리 예제가 문서에 남고, 아무도 그것을 모른다.
        let plugin_path = p.join("plugin.yaml");
        let artifacts = p.join("artifacts.json");
        let expected = p.join("expected-plan.json");
        for f in [&plugin_path, &artifacts, &expected] {
            assert!(f.exists(), "{name}: {} 가 없다", f.display());
        }
        let text = std::fs::read_to_string(&plugin_path).expect("플러그인");
        let plugin: PluginManifest = serde_yaml_ng::from_str(&text)
            .unwrap_or_else(|e| panic!("{name}: plugin.yaml 파싱 실패 {e}"));
        out.push(Example {
            name,
            plugin,
            artifacts,
            expected,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[test]
fn there_is_at_least_one_example() {
    // 예제가 없으면 아래 검사들이 전부 공허하게 통과한다.
    assert!(
        !examples().is_empty(),
        "docs/plugin-guide/examples 가 비어 있다"
    );
}

#[test]
fn every_example_lints_clean() {
    // 린트를 통과하지 못하는 예제를 문서에 두면, 그것을 복제한 룰도 통과하지 못한다.
    for ex in examples() {
        let issues = remedy_sdk::lint(&ex.plugin);
        let errors = remedy_sdk::lint::blocking(&issues);
        assert_eq!(errors, 0, "{}: 린트 오류\n{issues:#?}", ex.name);
        // 경고도 남기지 않는다. 예제가 경고를 달고 있으면 "이 정도는 괜찮다" 가
        // 학습된다.
        assert!(issues.is_empty(), "{}: 린트 경고\n{issues:#?}", ex.name);
    }
}

#[test]
fn every_example_produces_its_expected_plan() {
    for ex in examples() {
        let artifacts =
            read_artifacts(&ex.artifacts).unwrap_or_else(|e| panic!("{}: {e}", ex.name));
        let scan = remedy_core::evaluate(&artifacts, &ex.plugin)
            .unwrap_or_else(|e| panic!("{}: 평가 실패 {e}", ex.name));
        let plan = remedy_core::plan(&scan, Some(&ex.plugin))
            .unwrap_or_else(|e| panic!("{}: {e}", ex.name));

        let expected = read_plan(&ex.expected).unwrap_or_else(|e| panic!("{}: {e}", ex.name));
        let diff = compare_plan(&expected, &plan);
        assert!(
            diff.is_empty(),
            "{}: 기대 계획과 다르다\n  {}",
            ex.name,
            diff.join("\n  ")
        );
    }
}

#[test]
fn every_example_finds_something_in_its_own_snapshot() {
    // **판정이 0건인 예제는 아무것도 가르치지 않는다.** 위 비교만 있으면
    // "기대도 0건, 실제도 0건" 으로 통과해 버린다 — 검증에서 가장 위험한 형태다.
    for ex in examples() {
        let artifacts = read_artifacts(&ex.artifacts).expect("스냅샷");
        let scan = remedy_core::evaluate(&artifacts, &ex.plugin).expect("평가");
        assert!(
            !scan.body.verdicts.is_empty(),
            "{}: 자기 스냅샷에서 판정이 0건이다",
            ex.name
        );
        assert!(
            !scan.body.evidence.is_empty(),
            "{}: 증거가 0건이다",
            ex.name
        );
    }
}

#[test]
fn every_example_is_clean_against_the_clean_corpus() {
    // **G1.** 예제가 그 자체로 청정 환경 무해성을 통과하지 못하면 가이드에
    // 넣지 않는다 (설계-06 §5). AI 가 복제할 형태이므로 더욱 그렇다.
    let corpus = load_corpus(&repo_root().join("corpus/clean")).expect("코퍼스");
    assert!(
        !corpus.is_empty(),
        "청정 코퍼스가 비어 있으면 이 검사가 공허하다"
    );

    for ex in examples() {
        for entry in &corpus {
            let artifacts =
                read_artifacts(&entry.path).unwrap_or_else(|e| panic!("{}: {e}", entry.name));
            let scan = remedy_core::evaluate(&artifacts, &ex.plugin)
                .unwrap_or_else(|e| panic!("{} x {}: 평가 실패 {e}", ex.name, entry.name));
            let plan = remedy_core::plan(&scan, Some(&ex.plugin))
                .unwrap_or_else(|e| panic!("{} x {}: {e}", ex.name, entry.name));
            assert!(
                is_clean(&plan),
                "{} 가 청정 스냅샷 '{}' 에서 판정을 냈다 — 오탐이다\n  판정 {:?}",
                ex.name,
                entry.name,
                scan.body.verdicts
            );
        }
    }
}

#[test]
fn the_minimal_guide_set_exists_and_fits_its_budget() {
    // 설계-06 §10 의 4주차 최소 집합. 이것이 있어야 AI 반복 루프가 성립한다.
    let guide = repo_root().join("docs/plugin-guide");
    for f in ["00-invariants.md", "01-quickstart.md"] {
        assert!(guide.join(f).exists(), "{f} 가 없다");
    }

    // `00-invariants.md` 는 **항상 문맥에 로드된다.** 2 KB 를 넘으면 다른 것이
    // 밀려난다 (설계-06 §9).
    let size = std::fs::metadata(guide.join("00-invariants.md"))
        .expect("불변식 파일")
        .len();
    assert!(
        size <= 2048,
        "00-invariants.md 가 {size} 바이트다. 상한은 2048 — 항상 로드되는 파일이라 \
         넘으면 다른 것이 밀려난다"
    );
}

#[test]
fn guide_files_declare_their_own_version() {
    // AI 가 낡은 가이드를 읽고 낡은 스키마용 룰을 쓰는 것을 막으려면 **문서가
    // 자기 버전을 말할 수 있어야 한다** (설계-06 §9).
    let guide = repo_root().join("docs/plugin-guide");
    let mut checked = 0;
    for f in [
        guide.join("00-invariants.md"),
        guide.join("01-quickstart.md"),
        examples_dir().join("ex01-scheduled-task/README.md"),
    ] {
        let text = std::fs::read_to_string(&f).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        let head = text.lines().next().unwrap_or_default();
        assert!(
            head.contains("schema_version:") && head.contains("min_core:"),
            "{}: 첫 줄에 버전 헤더가 없다",
            f.display()
        );
        checked += 1;
    }
    assert_eq!(checked, 3);
}

/// `10-manifest.md` 의 표는 **손으로 적은 것**이다.
///
/// `31-nonexistent.md` 가 *"옮겨 적는 순간 낡기 시작한다"* 고 못박은 그
/// 부류인데, 매니페스트를 쓰는 사람이 바로 그 자리에서 봐야 해서 남겼다.
/// 대신 **낡으면 시끄럽게** 만든다 — 2026-09-01 까지 이 표가 `registry_value`
/// 를 반대 칸에 두고 있었고, 그것을 보고 쓴 답 둘과 우리 정답 플러그인이
/// 실기기에서 0건을 모으는 상태로 지나갔다.
#[test]
fn the_manifest_scoping_table_agrees_with_the_catalog() {
    use std::collections::BTreeSet;
    fn row(doc: &str, marker: &str) -> BTreeSet<String> {
        let line = doc
            .lines()
            .find(|l| l.starts_with('|') && l.contains(marker))
            .unwrap_or_else(|| panic!("10-manifest.md 에 '{marker}' 줄이 없다 — 표가 바뀌었나"));
        let cell = line.split('|').nth(2).expect("두 번째 칸");
        // `a` · `b` → 홀수 조각이 이름이다.
        cell.split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect()
    }

    let doc = std::fs::read_to_string(repo_root().join("docs/plugin-guide/10-manifest.md"))
        .expect("10-manifest.md");

    let want_scoped: BTreeSet<String> = Subject::ALL
        .into_iter()
        .filter(|s| !matches!(s.info().scoping, Scoping::Fixed))
        .map(|s| s.id().to_string())
        .collect();
    let want_fixed: BTreeSet<String> = Subject::ALL
        .into_iter()
        .filter(|s| matches!(s.info().scoping, Scoping::Fixed))
        .map(|s| s.id().to_string())
        .collect();

    assert_eq!(
        row(&doc, "가 범위를 정한다"),
        want_scoped,
        "표의 '범위를 정한다' 칸이 카탈로그와 다르다"
    );
    assert_eq!(
        row(&doc, "무관하게 수집된다"),
        want_fixed,
        "표의 '무관하게 수집된다' 칸이 카탈로그와 다르다"
    );
}
