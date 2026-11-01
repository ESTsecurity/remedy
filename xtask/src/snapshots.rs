//! 커밋된 스냅샷이 **지금 수집기가 낼 수 있는 모양인가** (설계-09 P12 후속).
//!
//! # 무엇을 막는 검사인가
//!
//! 저장소에 커밋된 스냅샷은 두 곳에서 채점의 입력이 된다 — 청정 코퍼스가
//! G1(오탐)을, AI 시험 위협의 감염 스냅샷이 채점 3·4 를 맡는다. **그런데
//! 그 자료가 옳은지는 아무도 보지 않았다.**
//!
//! 2026-09-04 에 위협 다섯을 실기기 스냅샷으로 옮기며 손으로 쓴 자료가
//! 무엇을 담을 수 있는지 드러났다:
//!
//! | 어디 | 적혀 있던 값 | 수집기가 내는 값 |
//! |---|---|---|
//! | `service-userinit` | `service.state: "running"` | `unknown` — 실행 여부는 레지스트리에 없다 |
//! | `service-userinit` | `service.start_type: "demand"` | `manual` — `Start=3` 의 이름 |
//! | `tls-intercept` | `cert_store.store: "system"` | `local` — 그 자리는 손으로 더한 CA 다 |
//!
//! 앞의 둘은 **값 전수에 없는 낱말**이다. 이 검사가 있었다면 그날이 아니라
//! 그 자료가 커밋되던 날 걸렸다.
//!
//! 세 번째는 값 전수 안에 있어서 이 검사로는 잡히지 않는다. **그것까지
//! 잡으려면 실기기에서 다시 뜨는 수밖에 없다** — 이 검사는 그 자리를 대신하지
//! 않고, 오프라인에서 잡을 수 있는 것만 잡는다.
//!
//! # 왜 게이트인가
//!
//! 수집기를 고치면 커밋된 스냅샷이 낡는다. 오늘 `service.name` 을 고쳤고
//! 그 순간 다섯 스냅샷 중 하나가 옛 모양이 됐다 — **알려 주는 것이 없었다.**
//! 값 전수와 필드 이름은 카탈로그에 있으므로, 그 둘이 갈라지는 것만은
//! 기계가 볼 수 있다.

use remedy_sdk::catalog::{EnumeratedField, Platform, Subject};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

/// 봉투에서 subject 배열이 아닌 키. 여기 없는 배열 키는 subject 여야 한다.
///
/// **모르는 키를 조용히 넘기지 않는다** — 봉투에 배열이 하나 늘었는데 그것이
/// subject 인지 아닌지 이 검사가 모르면, 그 자리는 영영 검사되지 않는다.
const NOT_SUBJECT: [&str; 2] = ["plugins", "security_products"];

struct Finding {
    file: String,
    error: bool,
    what: String,
}

pub fn run(root: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    collect_files(&root.join("corpus/clean"), &mut files);
    collect_files(&root.join("corpus/infected"), &mut files);
    for t in dirs(&root.join("testbed/ai-exam/threats")) {
        collect_files(&t.join("infected"), &mut files);
    }
    files.sort();

    if files.is_empty() {
        return Err("검사할 스냅샷이 하나도 없다. 경로가 바뀌었는지 볼 것".into());
    }

    let mut findings = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        match read_json(f) {
            Ok(v) => check_one(&rel, &v, &mut findings),
            Err(e) => findings.push(Finding {
                file: rel,
                error: true,
                what: format!("읽지 못했다: {e}"),
            }),
        }
    }

    let errors = findings.iter().filter(|f| f.error).count();
    let warns = findings.len() - errors;
    for f in &findings {
        println!(
            "  {} {}: {}",
            if f.error { "오류" } else { "경고" },
            f.file,
            f.what
        );
    }
    if errors > 0 {
        return Err(format!(
            "스냅샷 {}개 중 오류 {errors}건 · 경고 {warns}건.\n  \
             값 전수와 필드 이름은 카탈로그가 정한다 — 스냅샷이 그것과 갈라졌다면 \
             자료가 낡았거나 손으로 쓰인 것이다. 실기기에서 다시 뜰 것 \
             (testbed/harness/*/new-threat-snapshot.*)",
            files.len()
        ));
    }
    println!(
        "snapshots OK — 스냅샷 {}개가 카탈로그와 맞는다{}",
        files.len(),
        if warns > 0 {
            format!(" (경고 {warns}건)")
        } else {
            String::new()
        }
    );
    Ok(())
}

fn dirs(p: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(p)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    out
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        let n = p.file_name().unwrap_or_default().to_string_lossy();
        if n.ends_with(".json") || n.ends_with(".json.gz") {
            out.push(p);
        }
    }
}

fn read_json(p: &Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(p).map_err(|e| e.to_string())?;
    let text = if p.to_string_lossy().ends_with(".gz") {
        let mut s = String::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
        s
    } else {
        String::from_utf8(bytes).map_err(|e| e.to_string())?
    };
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn check_one(rel: &str, v: &serde_json::Value, out: &mut Vec<Finding>) {
    let mut push = |error: bool, what: String| {
        out.push(Finding {
            file: rel.to_string(),
            error,
            what,
        })
    };

    let Some(obj) = v.as_object() else {
        push(true, "최상위가 객체가 아니다".into());
        return;
    };

    // ── 봉투 ────────────────────────────────────────────────────────
    //
    // **잘린 스냅샷은 채점 데이터가 될 수 없다.** 그 상태의 "위협 없음" 은
    // "못 봤다" 이기 때문이다 — 코퍼스 스크립트가 같은 규칙을 적고 있는데
    // 커밋된 자료에 대해서는 아무도 확인하지 않았다.
    let scope = obj.get("scope").and_then(|s| s.as_object());
    if let Some(s) = scope {
        if s.get("truncated").and_then(|b| b.as_bool()) == Some(true) {
            push(true, "잘린 스냅샷이다 (scope.truncated)".into());
        }
        match s.get("denied_dirs").and_then(|n| n.as_u64()) {
            Some(0) | None => {}
            Some(n) => push(
                true,
                format!("접근 거부 {n}건이 담겨 있다 (scope.denied_dirs)"),
            ),
        }
    }

    let platform = match obj
        .get("host")
        .and_then(|h| h.get("os"))
        .and_then(|s| s.as_str())
    {
        Some(os) if os.eq_ignore_ascii_case("windows") => Platform::Windows,
        Some(_) => Platform::Linux,
        None => {
            push(true, "host.os 가 없다".into());
            return;
        }
    };

    // ── 레코드 ──────────────────────────────────────────────────────
    for (key, val) in obj {
        let Some(arr) = val.as_array() else { continue };
        if NOT_SUBJECT.contains(&key.as_str()) {
            continue;
        }
        let Some(subject) = Subject::from_id(key) else {
            push(
                true,
                format!("'{key}' 는 subject 도 봉투 배열도 아니다 — NOT_SUBJECT 에 넣거나 이름을 고칠 것"),
            );
            continue;
        };
        if arr.is_empty() {
            continue;
        }

        // **그 플랫폼에서 수집되지 않는 subject 가 담겨 있다.**
        let collectable = match platform {
            Platform::Windows => subject.info().windows,
            _ => subject.info().linux_from.is_some(),
        };
        if !collectable {
            push(
                true,
                format!(
                    "{} 스냅샷에 '{key}' 레코드 {}건이 있다 — 그 플랫폼에서 수집되지 않는 subject 다",
                    platform.id(),
                    arr.len()
                ),
            );
        }

        let known: BTreeSet<&str> = subject.fields().iter().copied().collect();
        // 값 전수가 정의된 필드는 빈 배열이 아닌 것만 잰다 — 레코드 타입이
        // 아직 없는 subject 는 검사를 건너뛴 사실이 드러나야 한다.
        let skip_fields = known.is_empty();
        let mut bad_field = BTreeSet::new();
        let mut bad_value: BTreeSet<(String, String)> = BTreeSet::new();
        let mut soft_value: BTreeSet<(String, String)> = BTreeSet::new();

        for rec in arr {
            let Some(r) = rec.as_object() else {
                push(true, format!("'{key}' 에 객체가 아닌 항목이 있다"));
                break;
            };
            let mut flat = Vec::new();
            flatten(r, "", &mut flat);
            for (field, leaf) in &flat {
                if !skip_fields && !known.contains(field.as_str()) {
                    bad_field.insert(field.clone());
                }
                let Some(e) = EnumeratedField::lookup(subject, field) else {
                    continue;
                };
                let Some(s) = leaf.as_str() else { continue };
                if s.is_empty() || e.values.contains(&s) {
                    continue;
                }
                // 대소문자는 플랫폼마다 다르다. Windows 비교는 접으므로
                // 접어서 같으면 값 자체는 아는 것이다.
                if platform == Platform::Windows
                    && e.values.iter().any(|v| v.eq_ignore_ascii_case(s))
                {
                    continue;
                }
                if e.defined {
                    bad_value.insert((field.clone(), s.to_string()));
                } else {
                    soft_value.insert((field.clone(), s.to_string()));
                }
            }
        }

        for f in &bad_field {
            push(
                true,
                format!(
                    "'{key}' 레코드에 '{f}' 필드가 있는데 카탈로그에 없다. \
                     쓸 수 있는 것: {}",
                    subject.fields().join(" · ")
                ),
            );
        }
        for (f, v) in &bad_value {
            let e = EnumeratedField::lookup(subject, f).expect("방금 찾았다");
            push(
                true,
                format!(
                    "'{key}.{f}' 에 '{v}' 가 담겨 있다 — 수집기가 내지 않는 값이다. \
                     쓸 수 있는 것: {}",
                    e.values.join(" · ")
                ),
            );
        }
        for (f, v) in &soft_value {
            push(
                false,
                format!(
                    "'{key}.{f}' 의 '{v}' 가 알려진 값 목록에 없다. \
                     그 목록이 닫혀 있지 않으므로(defined: false) 막지는 않는다"
                ),
            );
        }
    }
}

/// 중첩 객체를 `signature.trusted` 꼴로 편다.
///
/// 카탈로그의 필드 목록이 그 표기를 쓴다(`Subject::fields`). 펴지 않으면
/// `signature` 하나가 모르는 필드로 잡히고, 그 안쪽은 영영 검사되지 않는다.
fn flatten(
    obj: &serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    out: &mut Vec<(String, serde_json::Value)>,
) {
    for (k, v) in obj {
        let name = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            serde_json::Value::Object(inner) => flatten(inner, &name, out),
            other => out.push((name, other.clone())),
        }
    }
}
