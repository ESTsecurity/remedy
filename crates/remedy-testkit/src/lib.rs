//! 테스트 공용 — 코퍼스 로더와 계획 비교기 (설계-04 §3.2, 설계-09 P2).
//!
//! 정규화 규칙을 한 곳에 둔다. 테스트마다 복사되면 어느 순간 서로 달라지고,
//! **비교가 아무것도 잡지 못하게 된다.**
//!
//! 정규화 대상을 늘릴 때는 리뷰를 받아야 한다. 남발하면 diff 가 늘 비어 보이고,
//! 그것은 "회귀가 없다" 가 아니라 "회귀를 볼 수 없다" 이다.
#![forbid(unsafe_code)]

use remedy_sdk::artifact::{ArtifactsEnvelope, PlanEnvelope, ScanEnvelope};
use std::path::{Path, PathBuf};

pub const CRATE_NAME: &str = "remedy-testkit";

#[derive(Debug, thiserror::Error)]
pub enum TestkitError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

// ─────────────────────────────────────────────────────── 코퍼스

/// 코퍼스 항목 하나. 파일 이름이 곧 환경 이름이다.
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    pub name: String,
    pub path: PathBuf,
}

/// 디렉터리에서 스냅샷을 모은다. 순서는 파일 이름 순으로 **결정적**이다.
///
/// `.json` 과 `.json.gz` 를 모두 읽는다. 코퍼스는 계속 늘어날 것이고(설계-04
/// §3.2 는 수백 개의 청정 환경을 말한다), 실측한 스냅샷 하나가 12.9MB 였다.
/// 원문 그대로 쌓으면 저장소가 감당하지 못한다 — gzip 후 15% 다.
pub fn load_corpus(dir: &Path) -> Result<Vec<CorpusEntry>, TestkitError> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        // 코퍼스가 아직 없는 것은 오류가 아니다. 비어 있음을 돌려준다.
        Err(_) => return Ok(out),
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = match corpus_name(&p) {
            Some(n) => n,
            None => continue,
        };
        out.push(CorpusEntry { name, path: p });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// 코퍼스 항목의 이름. 스냅샷 파일이 아니면 `None`.
///
/// `a.json` -> `a`, `a.json.gz` -> `a`. 압축 여부는 이름에 남기지 않는다 —
/// 같은 스냅샷을 압축했다는 이유로 코퍼스 항목 이름이 달라지면 안 된다.
fn corpus_name(p: &Path) -> Option<String> {
    let file = p.file_name()?.to_str()?;
    let stem = file
        .strip_suffix(".json.gz")
        .or_else(|| file.strip_suffix(".json"))?;
    Some(stem.to_string())
}

pub fn read_artifacts(path: &Path) -> Result<ArtifactsEnvelope, TestkitError> {
    read_json(path)
}

pub fn read_scan(path: &Path) -> Result<ScanEnvelope, TestkitError> {
    read_json(path)
}

pub fn read_plan(path: &Path) -> Result<PlanEnvelope, TestkitError> {
    read_json(path)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, TestkitError> {
    let text = read_maybe_gz(path)?;
    serde_json::from_str(&text).map_err(|source| TestkitError::Json {
        path: path.display().to_string(),
        source,
    })
}

/// 확장자가 `.gz` 면 풀어서 읽는다.
fn read_maybe_gz(path: &Path) -> Result<String, TestkitError> {
    let io = |source| TestkitError::Io {
        path: path.display().to_string(),
        source,
    };
    if path.extension().and_then(|s| s.to_str()) != Some("gz") {
        return std::fs::read_to_string(path).map_err(io);
    }
    use std::io::Read;
    let bytes = std::fs::read(path).map_err(io)?;
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .map_err(io)?;
    Ok(text)
}

// ─────────────────────────────────────────────────────── 정규화

/// 비교 전에 지워야 하는 휘발성 필드 (설계-04 §3.2).
///
/// **이 목록을 늘리는 것은 리뷰 대상이다.** 하나 늘 때마다 비교가 볼 수 있는
/// 범위가 줄어든다.
pub const VOLATILE_KEYS: [&str; 6] = [
    "run_id",
    "created",
    "collected_at",
    "hostname",
    "mtime",
    "ctime",
];

/// 휘발성 필드를 고정값으로 바꾼다. 키를 지우지 않고 **치환**하는 이유는,
/// 필드가 통째로 사라지는 회귀도 잡아야 하기 때문이다.
pub fn normalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if VOLATILE_KEYS.contains(&k.as_str()) {
                    *v = serde_json::Value::String("<정규화됨>".into());
                } else {
                    normalize(v);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(normalize),
        _ => {}
    }
}

/// 정규화한 두 값의 차이. 같으면 빈 목록이다.
pub fn diff(expected: &serde_json::Value, actual: &serde_json::Value) -> Vec<String> {
    let (mut e, mut a) = (expected.clone(), actual.clone());
    normalize(&mut e);
    normalize(&mut a);
    let mut out = Vec::new();
    walk_diff("", &e, &a, &mut out);
    out
}

fn walk_diff(at: &str, e: &serde_json::Value, a: &serde_json::Value, out: &mut Vec<String>) {
    use serde_json::Value as V;
    match (e, a) {
        (V::Object(em), V::Object(am)) => {
            let mut keys: Vec<&String> = em.keys().chain(am.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let child = if at.is_empty() {
                    k.clone()
                } else {
                    format!("{at}.{k}")
                };
                match (em.get(k), am.get(k)) {
                    (Some(x), Some(y)) => walk_diff(&child, x, y, out),
                    (Some(_), None) => out.push(format!("{child}: 기대에는 있고 실제에는 없다")),
                    (None, Some(_)) => out.push(format!("{child}: 실제에만 있다")),
                    (None, None) => {}
                }
            }
        }
        (V::Array(ex), V::Array(ax)) => {
            if ex.len() != ax.len() {
                out.push(format!(
                    "{at}: 개수가 다르다 (기대 {} / 실제 {})",
                    ex.len(),
                    ax.len()
                ));
            }
            for (i, (x, y)) in ex.iter().zip(ax.iter()).enumerate() {
                walk_diff(&format!("{at}[{i}]"), x, y, out);
            }
        }
        _ => {
            if e != a {
                out.push(format!("{at}: 기대 {e} / 실제 {a}"));
            }
        }
    }
}

/// 계획이 기대와 같은가. 다르면 사람이 읽을 차이 목록을 돌려준다.
pub fn compare_plan(expected: &PlanEnvelope, actual: &PlanEnvelope) -> Vec<String> {
    diff(
        &serde_json::to_value(expected).expect("계획 직렬화"),
        &serde_json::to_value(actual).expect("계획 직렬화"),
    )
}

/// Action 하나를 **자리표** 한 줄로. `<op> <대상>` 또는
/// `<op> <대상> :: <k>=<v>, …`.
///
/// `testbed/ai-exam/threats/*/expected-ops.txt` 가 이 모양으로 적혀 있고,
/// 시험 채점(`xtask::exam`)과 첫 플러그인 기준선(`remedy-core` 의
/// `infected.rs`)이 **둘 다** 그것을 읽는다. 그래서 렌더링이 여기 하나뿐이어야
/// 한다 — 두 곳에 두면 갈라지는 날 한쪽 시험이 조용히 다른 것을 재게 된다.
///
/// # 왜 Op 이름만으로는 부족한가
///
/// 2026-09-04 `appinit-r3` 회차의 사전 기준에 실측으로 적었다 — `AppInit_DLLs`
/// 만 지우고 `LoadAppInit_DLLs` 를 남긴 변형이 **네 판정을 전부 통과하고
/// 경고도 0** 이었다. 종류만 세면 `registry.delete_value` 를 1건 내든 2건
/// 내든 같은 하나이기 때문이다.
///
/// **개수가 아니라 대상을 센다.** 개수만 세면 `AppInit_DLLs` 와 `Spooler` 를
/// 지운 답이 2건으로 통과한다 — 절반짜리 치료보다 나쁜 실패다.
///
/// 대상 문자열은 응시자가 아니라 코어가 증거에서 조립하므로(`derive.rs`),
/// 룰을 어떻게 적었든 **같은 레코드를 짚으면 같은 문자열**이 나온다.
/// `match` 를 함께 적는 이유는 그것이 유일한 구분인 Op 이 있기 때문이다 —
/// `structured_config.remove_key` 는 어느 항목을 빼는가가 거기에만 있고,
/// `process.kill` 은 대상 자체가 없다.
pub fn locator(a: &remedy_sdk::artifact::Action) -> String {
    let mut s = format!("{} {}", a.op.id(), a.target.as_deref().unwrap_or("-"));
    if let Some(serde_json::Value::Object(m)) = &a.r#match {
        // 직렬화가 BTreeMap 이라 이미 키 정렬이다.
        let pairs: Vec<String> = m
            .iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(x) => format!("{k}={x}"),
                other => format!("{k}={other}"),
            })
            .collect();
        if !pairs.is_empty() {
            s.push_str(" :: ");
            s.push_str(&pairs.join(", "));
        }
    }
    s
}

/// **G1 의 판정** — 청정 환경에서 파괴 Action 이 하나도 없어야 한다.
///
/// 두 차원을 함께 본다. 판정 그룹이 서면 사람에게 "감염" 이라고 말하는 것이고,
/// Action 이 서면 실제로 무언가를 부순다.
///
/// **Action 차원은 P7 부터 의미가 있다.** 그 전에는 파괴 Op 이 게이트 밖이라
/// 계획기가 전부 `deferred` 로 미뤘고, 그래서 이 검사가 언제나 참이었다 —
/// 재는 것이 없는 검사였다. `corpus.rs` 의 자체 점검이 그 차원까지 실제로
/// 무는지 확인한다.
pub fn is_clean(plan: &PlanEnvelope) -> bool {
    plan.body.actions.is_empty() && plan.body.verdicts.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn volatile_fields_are_normalized_not_dropped() {
        // 지우면 "필드가 통째로 사라진" 회귀를 못 잡는다.
        let mut v = json!({ "run_id": "r1", "keep": 1 });
        normalize(&mut v);
        assert_eq!(v["run_id"], json!("<정규화됨>"));
        assert_eq!(v["keep"], json!(1));
    }

    #[test]
    fn nested_and_array_values_are_normalized() {
        let mut v = json!({ "file": [{ "mtime": "a", "path": "p" }] });
        normalize(&mut v);
        assert_eq!(v["file"][0]["mtime"], json!("<정규화됨>"));
        assert_eq!(v["file"][0]["path"], json!("p"));
    }

    #[test]
    fn identical_after_normalization_is_no_diff() {
        let a = json!({ "run_id": "r1", "created": "t1", "x": 1 });
        let b = json!({ "run_id": "r2", "created": "t2", "x": 1 });
        assert!(diff(&a, &b).is_empty(), "휘발성 차이는 무시되어야 한다");
    }

    #[test]
    fn real_difference_is_reported_with_a_path() {
        let a = json!({ "plan": { "actions": [1, 2] } });
        let b = json!({ "plan": { "actions": [1, 3] } });
        let d = diff(&a, &b);
        assert_eq!(d.len(), 1);
        assert!(d[0].starts_with("plan.actions[1]"), "{:?}", d);
    }

    #[test]
    fn missing_and_extra_keys_are_both_reported() {
        let a = json!({ "only_expected": 1 });
        let b = json!({ "only_actual": 2 });
        let d = diff(&a, &b);
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn array_length_change_is_reported() {
        // 개수가 줄어든 것을 놓치면 "탐지가 사라진" 회귀를 못 잡는다.
        let d = diff(&json!({ "a": [1, 2, 3] }), &json!({ "a": [1, 2] }));
        assert!(d.iter().any(|x| x.contains("개수가 다르다")), "{:?}", d);
    }

    #[test]
    fn missing_corpus_directory_is_not_an_error() {
        let entries = load_corpus(Path::new("존재하지-않는-디렉터리")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn corpus_name_ignores_compression() {
        // 같은 스냅샷을 압축했다는 이유로 항목 이름이 달라지면, 기대 결과가
        // 이름으로 묶여 있는 비교가 전부 어긋난다.
        assert_eq!(corpus_name(Path::new("a/win10.json")).unwrap(), "win10");
        assert_eq!(corpus_name(Path::new("a/win10.json.gz")).unwrap(), "win10");
        assert_eq!(corpus_name(Path::new("a/notes.txt")), None);
        assert_eq!(corpus_name(Path::new("a/blob.gz")), None);
    }

    #[test]
    fn gzipped_snapshot_reads_back_identically() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("remedy-testkit-gz");
        std::fs::create_dir_all(&dir).unwrap();
        let raw = r#"{"x":1,"긴한글":"값"}"#;

        let path = dir.join("sample.json.gz");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(raw.as_bytes()).unwrap();
        std::fs::write(&path, enc.finish().unwrap()).unwrap();

        let back: serde_json::Value = read_json(&path).unwrap();
        assert_eq!(
            back,
            serde_json::from_str::<serde_json::Value>(raw).unwrap()
        );
        std::fs::remove_file(&path).ok();
    }
}
