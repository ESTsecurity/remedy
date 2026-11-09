//! 생성물 — `plugin.schema.json` · 카탈로그 · 가이드 레퍼런스.
//!
//! 레퍼런스는 문서가 아니라 **생성물이다** (설계-06 §4). 사람이 표를 옮겨 적는
//! 한 언젠가 어긋나고, 어긋난 레퍼런스는 없느니만 못하다.
//!
//! `cargo xtask schema` 가 이 결과를 저장소의 파일과 대조한다. SDK 를 고치고
//! 생성물을 커밋하지 않으면 CI 가 실패한다.

use crate::artifact::{
    ArtifactKind, ArtifactsEnvelope, ExitCode, PlanEnvelope, ResultEnvelope, ScanEnvelope,
};
use crate::catalog::{CaptureFn, Op, Operator, Subject, DESIGNATED_TOKENS};
use crate::manifest::PluginManifest;
use serde_json::json;

/// 생성물이 놓이는 곳 (설계-04 §1).
/// 생성물이 놓이는 자리. **`machine/` 밖에도 생성물이 있다** — 오류 표는
/// 작성자가 읽는 문서라 번호 붙은 본문 자리에 둔다(설계-06 §2).
pub const OUT_DIR: &str = "docs/plugin-guide";

pub struct Generated {
    /// `OUT_DIR` 기준 상대 경로. `machine/` 접두가 붙는 것이 기계 판독용이다.
    pub path: &'static str,
    pub content: String,
}

/// 모든 생성물. 순서는 고정이다.
pub fn all() -> Vec<Generated> {
    vec![
        Generated {
            path: "machine/plugin.schema.json",
            content: plugin_schema(),
        },
        Generated {
            path: "machine/subjects.json",
            content: subjects_json(),
        },
        Generated {
            path: "machine/ops.json",
            content: ops_json(),
        },
        Generated {
            path: "machine/catalog.json",
            content: catalog_json(),
        },
        Generated {
            path: "machine/artifact.schema.json",
            content: artifact_schema(),
        },
        Generated {
            path: "machine/REFERENCE.md",
            content: reference_md(),
        },
        Generated {
            path: "32-lint-errors.md",
            content: lint_errors_md(),
        },
        Generated {
            path: "machine/AI-CONTEXT.md",
            content: ai_context_md(),
        },
    ]
}

fn pretty(v: &serde_json::Value) -> String {
    let mut s = serde_json::to_string_pretty(&canonical(v)).expect("직렬화 실패");
    s.push('\n');
    s
}

/// 객체의 키를 이름 순으로 다시 쌓는다.
///
/// # 왜 필요한가
///
/// `serde_json` 의 객체는 기본으로 `BTreeMap`(이름 순)이지만, 의존 그래프
/// 어딘가가 `preserve_order` 기능을 켜면 `IndexMap`(삽입 순)이 된다. 기능은
/// **워크스페이스 전체에 합쳐지므로**, 관계없는 크레이트 하나가 그것을 켜는
/// 순간 생성물의 키 순서가 통째로 뒤집힌다.
///
/// 실제로 그렇게 됐다. 퍼징을 위해 `xtask` 가 `remedy-detect` 를 의존하게
/// 만들었더니 `yara-x → walrus → gimli → indexmap` 경로로 그 기능이 켜졌고,
/// 손대지 않은 `ops.json`·`catalog.json`·`subjects.json` 이 전부 어긋났다.
///
/// **생성물은 의존성의 기능 플래그에 좌우되면 안 된다.** 여기서 순서를 못
/// 박으면 두 표현이 같은 파일을 만든다.
fn canonical(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::with_capacity(keys.len());
            for k in keys {
                out.insert(k.clone(), canonical(&m[k]));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(a) => {
            // 배열의 **순서는 뜻이 있다.** 정렬하면 Op 목록의 Phase 순서 같은
            // 것이 무너진다. 안쪽만 정규화한다.
            serde_json::Value::Array(a.iter().map(canonical).collect())
        }
        other => other.clone(),
    }
}

/// `plugin.yaml` 의 JSON Schema. **타입에서 직접 생성한다.**
pub fn plugin_schema() -> String {
    let schema = schemars::schema_for!(PluginManifest);
    pretty(&serde_json::to_value(&schema).expect("스키마 직렬화 실패"))
}

/// 산출 아티팩트 봉투 4종의 JSON Schema (설계-02 §8).
///
/// # 왜 이것까지 생성하는가
///
/// `artifacts.json` 은 **스냅샷 기반 검증 전체의 지지대**다 (설계-03 §1). 그런데
/// P2 까지 이 포맷에는 드리프트 가드가 없었다 — 실측으로 `CollectScope` 에 필드를
/// 하나 추가해도 `xtask schema` 가 통과했다. 아무 diff 도 남지 않으므로 리뷰할
/// 것이 없고, 코퍼스 테스트는 **깨지는** 변경만 잡고 **추가되는** 변경은 통과시킨다.
///
/// 봉투가 조용히 바뀌면 이미 뜬 코퍼스 스냅샷과 새 스냅샷이 다른 물건이 되는데,
/// 그 사실이 어디에도 드러나지 않는다.
pub fn artifact_schema() -> String {
    // 네 종을 한 파일에 담는다. 봉투는 함께 움직이는 하나의 계약이고, 파일을
    // 넷으로 나누면 그중 하나만 갱신되는 상태가 만들어진다.
    let schemas = json!({
        "artifacts": serde_json::to_value(schemars::schema_for!(ArtifactsEnvelope))
            .expect("artifacts 스키마"),
        "scan": serde_json::to_value(schemars::schema_for!(ScanEnvelope)).expect("scan 스키마"),
        "plan": serde_json::to_value(schemars::schema_for!(PlanEnvelope)).expect("plan 스키마"),
        "result": serde_json::to_value(schemars::schema_for!(ResultEnvelope))
            .expect("result 스키마"),
    });
    pretty(&schemas)
}

/// subject 전수 — **필드 목록을 포함한다.**
///
/// # 왜 필드가 여기 있어야 하는가
///
/// `00-invariants.md` 는 "subject · 필드 · 연산자 · Op 는 닫힌 집합이다. 전수는
/// `machine/` 에 있다" 고 약속한다. 그런데 필드가 빠져 있었다 — **문서가 약속을
/// 지키지 않는 상태**였고, 관측 01 에서 5/5 가 이것을 최대 장애로 지목했다.
///
/// 없는 필드를 쓴 룰은 조용히 아무것도 매치하지 않는다. 실제로 그렇게 실패했다 —
/// `signature.trusted` 를 쓴 룰이 문법·경고를 통과하고 동작에서 아무것도 못 잡았다.
/// 그 subject 에서 **값까지 닫힌** 필드만 모은다.
fn enumerated_of(s: Subject) -> serde_json::Value {
    let m: serde_json::Map<String, serde_json::Value> = Subject::ENUMERATED_FIELDS
        .iter()
        .filter(|e| e.subject == s)
        .map(|e| {
            (
                e.field.to_string(),
                json!({
                    "values": e.values,
                    // `true` 면 수집기가 만드는 전수라 다른 값이 나올 수 없다.
                    // `false` 면 OS 표기를 그대로 통과시키는 자리라 **아는
                    // 만큼**이다 — 린트도 오류가 아니라 경고로 말한다.
                    "defined": e.defined,
                    "why": e.why,
                }),
            )
        })
        .collect();
    serde_json::Value::Object(m)
}

pub fn subjects_json() -> String {
    let items: Vec<_> = Subject::ALL
        .iter()
        .map(|s| {
            let i = s.info();
            json!({
                "id": i.id,
                "implemented_in": i.implemented_in.as_str(),
                "windows": i.windows,
                "linux": i.linux,
                // `linux` 와 짝이다. `linux: true` 인데 여기가 null 이면
                // **개념은 있으나 이 코어가 수집하지 않는다** 는 뜻이다.
                "linux_from": i.linux_from.map(|p| p.as_str()),
                // **선언만으로는 모이지 않는다.** `path`·`registry` 는 그 종류의
                // 루트가 `scan_roots` 에 하나라도 있어야 하고, 없으면 그 subject
                // 는 언제나 0건이다. `fixed` 는 자리가 정해져 있어 무관하다.
                "scoping": i.scoping.as_str(),
                "summary": i.summary,
                // 빈 배열은 "필드가 없다" 가 아니라 **"아직 정의되지 않았다"** 다
                // (`Subject::fields` 와 같은 규약). 지금은 빈 것이 없다.
                "fields": s.fields(),
                // **이름만 주면 값을 지어낸다.** 필드 이름을 전수로 주는 것과
                // 같은 이유로 값도 전수를 준다 — 이름은 맞고 값만 틀린 술어는
                // 조용히 0건을 맞히고, 그것을 알려 주는 것이 여기뿐이다
                // (`Subject::ENUMERATED_FIELDS`).
                //
                // 없는 필드는 값이 열려 있다는 뜻이다.
                "enumerated": enumerated_of(*s),
            })
        })
        .collect();
    pretty(&json!({ "count": items.len(), "subjects": items }))
}

pub fn ops_json() -> String {
    let items: Vec<_> = Op::ALL
        .iter()
        .map(|o| {
            let i = o.info();
            json!({
                "id": i.id,
                "implemented_in": i.implemented_in.as_str(),
                // **Linux 에서 이 Op 을 수행하게 되는 Phase.** `null` 은 그
                // 플랫폼에 개념이 없다는 뜻이고, 기다려도 오지 않는다.
                "linux_from": i.linux_from.map(|p| p.as_str()),
                "risk": i.risk.as_str(),
                "reversible": i.reversible,
                // 순서는 코어가 정하지만 **왜 그 순서인지**는 작성자가 알아야
                // 자기 룰이 왜 그렇게 계획되는지 읽을 수 있다 (설계-03 §2).
                "regenerator": i.regenerator,
                // **치료 뒤 대상이 남아 있어야 하는가.** 실기기 채점(채점 5)의
                // 하네스가 이것으로 "아직 있다" 를 합격과 불합격으로 가른다 —
                // 두 플랫폼의 하네스가 같은 표를 읽어야 갈라지지 않는다
                // (`Op::edits_in_place` 의 설명).
                "edits_in_place": o.edits_in_place(),
            })
        })
        .collect();
    pretty(&json!({ "count": items.len(), "ops": items }))
}

/// 나머지 닫힌 집합을 한 파일에 모은다. 작성 도구가 유효값을 열거할 때 쓴다.
pub fn catalog_json() -> String {
    let operators: Vec<_> = Operator::ALL
        .iter()
        .map(|o| {
            let i = o.info();
            json!({
                "id": i.id,
                "implemented_in": i.implemented_in.as_str(),
                "takes_value": i.takes_value,
            })
        })
        .collect();
    let capture_fns: Vec<_> = CaptureFn::ALL.iter().map(|c| c.id()).collect();
    let tokens: Vec<_> = DESIGNATED_TOKENS
        .iter()
        .map(|t| {
            json!({
                "token": t.token,
                "expands_to": t.expands_to,
                "requires_allow_removable": t.requires_allow_removable,
            })
        })
        .collect();
    let kinds: Vec<_> = ArtifactKind::ALL
        .iter()
        .map(|k| json!({ "kind": k.id(), "stage": k.stage() }))
        .collect();
    let exits: Vec<_> = ExitCode::ALL
        .iter()
        .map(|e| json!({ "code": e.code(), "meaning": e.meaning() }))
        .collect();

    pretty(&json!({
        "schema_version": crate::SCHEMA_VERSION,
        "implemented_through": crate::IMPLEMENTED_THROUGH.as_str(),
        // `restore_default` 가 쓸 수 있는 값의 전부. 여기 없는 대상은 되돌릴 수
        // 없고, 린트가 유효 목록과 함께 거절한다 (설계-03 §2).
        // **타입을 함께 낸다.** 값만 내면 `0` 이 수인지 문자열 `"0"` 인지 읽는
        // 쪽이 알 수 없고, 그 구분이 `LoadAppInit_DLLs` 에서는 켜짐과 꺼짐의
        // 차이다 (`DefaultValue` 의 설명).
        "restore_defaults": crate::catalog::RESTORE_DEFAULTS
            .iter()
            .map(|(t, v)| match v {
                crate::catalog::DefaultValue::Text(x) => {
                    json!({ "target": t, "default": x, "type": "REG_SZ" })
                }
                crate::catalog::DefaultValue::Dword(n) => {
                    json!({ "target": t, "default": n, "type": "REG_DWORD" })
                }
            })
            .collect::<Vec<_>>(),
        "operators": operators,
        "capture_functions": capture_fns,
        "designated_tokens": tokens,
        "artifact_kinds": kinds,
        "exit_codes": exits,
    }))
}

/// capture 함수의 **뜻**. `REFERENCE.md` 와 `AI-CONTEXT.md` 가 같은 문장을 낸다.
///
/// **이름 목록만으로는 쓸 수 없는 함수가 있다** (2026-09-23). `sshbd-r1` 답안이
/// `AuthorizedKeysFile /etc/ssh/.maint/keys` 에 `line | first_path` 를 걸어
/// 경로를 기대했고, 실제로는 **첫 공백 토큰** `AuthorizedKeysFile` 이 나와
/// 판정이 무너졌다. 그 문장은 `AI-CONTEXT.md` 에만 있었는데, 주입 꾸러미는 그
/// 파일을 *"같은 내용이 두 번"* 이라며 빼고 `REFERENCE.md` 를 싣는다 —
/// 꾸러미에서는 그 뜻이 어디에도 없었다.
///
/// 한 곳에 두어 둘이 갈라지지 않게 한다. `key`/`value` 조언은 수집기가 **`=`
/// 로만 쪼갠다**(`remedy-collect/src/config.rs`)는 사실에 맞춘 것이다 — 공백으로
/// 쓰는 설정에서는 둘 다 비어 그 조언이 통하지 않는다.
const CAPTURE_FN_NOTE: &str = "`first_path` 는 **첫 공백 토큰**을 뽑는다(따옴표는 \
     벗긴다) — 경로가 아니어도 그것을 낸다. `last_path` 는 **역슬래시가 든 마지막 \
     토큰**(없으면 슬래시가 든 마지막 토큰)을 뽑는다 — `--run` 같은 플래그와 `/min` \
     같은 스위치는 건너뛰고, 경로가 둘 이상이면 마지막 것이다. 줄 중간의 경로는 \
     둘 다 뽑지 못한다. \
     `key`/`value` 는 `=` 로 쓴 줄에서만 채워진다 — 공백으로 쓰는 설정\
     (`sshd_config` 등)에서는 둘 다 비므로 그 자리는 리터럴로 적는다.";

/// 사람이 읽는 레퍼런스. 표를 손으로 옮겨 적지 않기 위한 것이다.
pub fn reference_md() -> String {
    let mut s = String::new();
    // 버전 헤더 (설계-06 §9). **문서가 자기 버전을 말할 수 있어야** AI 가 낡은
    // 가이드를 읽고 낡은 스키마용 룰을 쓰는 것을 막을 수 있다.
    s.push_str(&format!(
        "<!-- schema_version: {} | min_core: 1.0.0 | generated: true -->\n\n",
        crate::SCHEMA_VERSION
    ));
    s.push_str("# 레퍼런스 (생성물 — 직접 고치지 말 것)\n\n");
    s.push_str("`remedy-sdk` 에서 생성된다. 고칠 곳은 `crates/remedy-sdk/src/catalog.rs` 다.\n");
    s.push_str("`cargo xtask schema` 가 이 파일과 SDK 의 일치를 검사한다.\n\n");
    s.push_str(&format!(
        "- 스키마 버전: {}\n- 현재 구현된 Phase: {}\n\n",
        crate::SCHEMA_VERSION,
        crate::IMPLEMENTED_THROUGH.as_str()
    ));

    s.push_str(&format!("## 관찰 대상 {}종\n\n", Subject::ALL.len()));
    // 세 상태를 한 열에 담는다. Phase · `개념만` · `—` 가 각각 "수집한다" ·
    // "개념은 있는데 수집기가 없다" · "개념이 없다" 다.
    s.push_str(
        "**Windows** · **Linux** 열은 *이 코어가 그 플랫폼에서 수집하기 시작하는 Phase* 다.\n\n\
         `—` 는 그 플랫폼에 **개념이 없다** — 기다려도 오지 않는다. `개념만` 은 개념은 \
         있으나 **이 코어가 아직 수집하지 않는다** 는 뜻이다. 그 subject 를 선언한 룰은 \
         그 플랫폼에서 **0건**이 되고, `plugin lint` 가 둘 다 잡는다.\n\n",
    );
    s.push_str("| subject | Windows | Linux | 설명 |\n|---|---|---|---|\n");
    for x in Subject::ALL {
        let i = x.info();
        let linux = match (i.linux_from, i.linux) {
            (Some(p), _) => p.as_str(),
            (None, true) => "개념만",
            (None, false) => "—",
        };
        s.push_str(&format!(
            "| `{}` | {} | {} | {} |
",
            i.id,
            if i.windows {
                i.implemented_in.as_str()
            } else {
                "—"
            },
            linux,
            i.summary
        ));
    }

    // **필드 전수는 이 문서의 본체다.** 없는 필드를 쓴 룰은 조용히 아무것도
    // 매치하지 않고, 작성자는 룰이 틀렸다고 생각한다 (관측 01).
    s.push_str("\n### subject 별 필드 (닫힌 집합)\n\n");
    s.push_str("여기 없는 이름을 쓰면 `plugin lint` 가 거절한다.\n\n");
    for x in Subject::ALL {
        let f = x.fields();
        s.push_str(&format!("- **`{}`** — ", x.id()));
        if f.is_empty() {
            s.push_str("_아직 정의되지 않았다. 린트가 필드 이름을 검사하지 못한다._\n");
        } else {
            s.push_str(
                &f.iter()
                    .map(|n| format!("`{n}`"))
                    .collect::<Vec<_>>()
                    .join(" · "),
            );
            s.push('\n');
        }
    }

    s.push_str(&format!("\n## 파괴·변경 동작 {}종\n\n", Op::ALL.len()));
    s.push_str("플러그인이 직접 적지 않는다. 계획기가 도출한다.\n\n");
    s.push_str(
        "| Op | Windows | Linux | 위험 | 되돌릴 수 있는가 | 유발자 |\n|---|---|---|---|---|---|\n",
    );
    for x in Op::ALL {
        let i = x.info();
        s.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            i.id,
            i.implemented_in.as_str(),
            // **`-` 는 "그 플랫폼에 개념이 없다"** 이지 "아직" 이 아니다.
            match i.linux_from {
                Some(p) => p.as_str(),
                None => "-",
            },
            i.risk.as_str(),
            if i.reversible { "O" } else { "-" },
            if i.regenerator { "O" } else { "-" }
        ));
    }
    s.push_str(
        "\n유발자는 **산출물보다 먼저** 실행된다. 재생성을 일으키는 설정을 남긴 채 \
산출물만 지우면 다음 트리거에서 그대로 돌아온다 (설계-03 §2).\n",
    );

    // **값의 출처를 코어 안에 가둔다.** 플러그인은 어느 대상을 되돌릴지만
    // 말한다 — 서명된 도구가 임의 레지스트리 값을 쓸 수 있으면 그 자체가
    // 공격 도구다 (설계-03 §2).
    s.push_str("\n## `restore_default` 가 되돌릴 수 있는 대상\n\n");
    s.push_str("여기 없는 대상을 `to: default` 로 지정하면 `plugin lint` 가 거절한다.\n\n");
    s.push_str("| 대상 | 기본값 |\n|---|---|\n");
    for (t, v) in crate::catalog::RESTORE_DEFAULTS {
        s.push_str(&format!("| `{}` | {} |\n", t, v.display()));
    }

    s.push_str(&format!("\n## 연산자 {}종\n\n", Operator::ALL.len()));
    s.push_str("| 연산자 | 구현 Phase | value 필요 |\n|---|---|---|\n");
    for x in Operator::ALL {
        let i = x.info();
        s.push_str(&format!(
            "| `{}` | {} | {} |\n",
            i.id,
            i.implemented_in.as_str(),
            if i.takes_value { "O" } else { "-" }
        ));
    }

    s.push_str(&format!("\n## capture 함수 {}종\n\n", CaptureFn::ALL.len()));
    for x in CaptureFn::ALL {
        s.push_str(&format!("- `{}`\n", x.id()));
    }
    s.push('\n');
    s.push_str(CAPTURE_FN_NOTE);
    s.push('\n');

    s.push_str("\n## 지정 확장 토큰\n\n");
    s.push_str("| 토큰 | 확장 대상 | allow_removable 필요 |\n|---|---|---|\n");
    for t in DESIGNATED_TOKENS {
        s.push_str(&format!(
            "| `{}` | {} | {} |\n",
            t.token,
            t.expands_to,
            if t.requires_allow_removable { "O" } else { "-" }
        ));
    }

    s.push_str("\n## 산출 아티팩트\n\n| kind | 단계 |\n|---|---|\n");
    for k in ArtifactKind::ALL {
        s.push_str(&format!("| `{}` | `{}` |\n", k.id(), k.stage()));
    }

    s.push_str("\n## 종료 코드\n\n| 코드 | 의미 |\n|---|---|\n");
    for e in ExitCode::ALL {
        s.push_str(&format!("| {} | {} |\n", e.code(), e.meaning()));
    }

    s
}

// ─────────────────────────────────────────────── 32-lint-errors.md

/// 진단 하나를 보여 주는 사례.
pub(crate) struct Case {
    /// 작성자가 하려던 것.
    title: &'static str,
    /// 무엇을 비틀어 이 진단을 냈는가. `BASE` 에서 바꾼 자리다.
    what: &'static str,
    /// 어떻게 고치는가.
    fix: &'static str,
    /// 실제 매니페스트.
    pub(crate) yaml: String,
}

/// 사례들이 비트는 최소 매니페스트. **이것 자체는 진단이 하나도 없어야 한다.**
pub(crate) const LINT_BASE: &str = r#"schema_version: 1
id: lint-base
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: { ko: '린트 기준', en: 'lint base' }
scan_roots: ['%LOCALAPPDATA%\Programs']
subjects: [persistence, file]
detect:
  - id: task
    subject: persistence
    where:
      all:
        - { field: command, op: matches, value: '(?i)\\node\.exe$' }
    capture:
      payload_dir: 'command | dirname'
  - id: payload
    subject: file
    from: '${task.payload_dir}'
    where:
      - { field: path, op: ends_with, value: '\main.js' }
verdict: { require: 'task and payload' }
"#;

fn case(title: &'static str, what: &'static str, fix: &'static str, from: &str, to: &str) -> Case {
    assert!(
        LINT_BASE.contains(from),
        "사례 '{title}': BASE 에 '{from}' 이 없다"
    );
    Case {
        title,
        what,
        fix,
        yaml: LINT_BASE.replace(from, to),
    }
}

fn append(title: &'static str, what: &'static str, fix: &'static str, extra: &str) -> Case {
    Case {
        title,
        what,
        fix,
        yaml: format!("{LINT_BASE}{extra}"),
    }
}

pub(crate) fn lint_cases() -> Vec<Case> {
    vec![
        case(
            "표시명에 두 언어를 다 적는다",
            "`name` 에 한 언어만 있다. 고객 화면의 첫 줄이 다른 언어에서 비거나 엉뚱한 언어로 나온다",
            "`name: { ko: …, en: … }` 둘 다 채운다. 룰만 고쳤어도 `version` 을 올린다",
            "name: { ko: '린트 기준', en: 'lint base' }",
            "name: { ko: '린트 기준' }",
        ),
        case(
            "드롭인 디렉터리를 확장자 없이 읽는다",
            "`text_config_dirs` 가 `scan_roots` 밖이다",
            "상한 안의 디렉터리로 적는다. 넓혀야 하면 `scan_roots` 를 고친다",
            "subjects: [persistence, file]",
            "subjects: [persistence, file, text_config]\ntext_config_dirs: ['%ProgramData%\\Acme\\conf.d']",
        ),
        case(
            "다른 규칙의 capture 를 가리킨다",
            "없는 규칙 이름을 썼다",
            "규칙 id 를 확인한다. 진단이 쓸 수 있는 이름을 전수로 알려 준다",
            "${task.payload_dir}",
            "${없는룰.payload_dir}",
        ),
        case(
            "capture 이름을 가리킨다",
            "그 규칙에 없는 capture 를 썼다",
            "부모 규칙의 `capture:` 아래 이름과 맞춘다",
            "${task.payload_dir}",
            "${task.없는캡처}",
        ),
        case(
            "판정식을 쓴다",
            "`verdict.require` 가 없는 규칙을 가리킨다",
            "규칙 id 를 확인한다. 오타 하나로 판정이 영영 서지 않는다",
            "require: 'task and payload'",
            "require: 'task and 없는룰'",
        ),
        case(
            "규칙을 하나 더 둔다",
            "id 가 겹쳤다",
            "id 를 유일하게 짓는다. 겹치면 `${task.x}` 가 어느 것을 가리키는지 알 수 없다",
            "  - id: payload",
            "  - id: task",
        ),
        case(
            "정규식으로 매치한다",
            "컴파일되지 않는 정규식이다",
            "RE2 문법이다. 역참조·전방탐색이 없다",
            "value: '(?i)\\\\node\\.exe$'",
            "value: '(unclosed'",
        ),
        // 2026-10-02. worm-r3 가 값을 몰라 자리 표시를 두었고(`FILL_IN_…`), 린트는
        // 조용했다 — 판정이 서지 않은 뒤에야 보였다. worm-r1 은 0 을 64개 적었다.
        case(
            "지문으로 잡는다",
            "`sha256` 의 값이 소문자 16진 64자가 아니다 — 값을 몰라 자리 표시를 두었다",
            "값을 모르면 적지 않는다. 아는 자리(정기 작업이 부르는 파일)에서 `sha256` 을 \
             capture 해 `${…}` 로 모은다 — `20-detect` §값을 모르는 지문. 위협 정보가 값을 \
             줬다면 그대로 붙인다(소문자 64자)",
            "- { field: path, op: ends_with, value: '\\main.js' }",
            "- { field: sha256, op: equals, value: 'FILL_IN_sha256_of_the_sample' }",
        ),
        case(
            "지문 자리를 비워 둔다",
            "`sha256` 의 값이 한 글자의 반복이다(0 을 64개) — 모양은 맞지만 실제 지문일 수 없다",
            "**경고다.** 자리 표시로 보여 알리는 것이지 막지 않는다. 고치는 법은 위와 같다",
            "- { field: path, op: ends_with, value: '\\main.js' }",
            "- { field: sha256, op: equals, value: '0000000000000000000000000000000000000000000000000000000000000000' }",
        ),
        // 2026-10-27. 버전 비교 연산자를 더하면서 함께 왔다. 꼬리 붙은 버전은
        // **사전 배포와 패키지 개정이 모양은 같고 순서가 반대**라 받지 않는다.
        case(
            "버전을 견준다",
            "`version_lt` · `version_gt` 의 값이 버전이 아니다 — 꼬리가 붙었거나 `x` 를 적었다",
            "점으로 나눈 숫자만 적는다(예: 8.2.29). 계열을 좁히려면 `starts_with \"8.2.\"` 를 \
             함께 건다. 꼬리(`RC1` · `-dev` · `-1ubuntu1`)는 순서가 서로 반대여서 받지 않는다",
            "- { field: path, op: ends_with, value: '\\main.js' }",
            "- { field: path, op: version_lt, value: '8.2.29-1ubuntu1' }",
        ),
        // 적대 검증이 찾은 high (2026-10-27). 하필 이 모양이 기능의 동기 예시다 —
        // 설명을 읽은 작성자가 `value: 8.10` 을 그대로 적는 것이 가장 자연스럽다.
        case(
            "버전을 따옴표로 감싼다",
            "버전을 따옴표 없이 적었다 — YAML 이 실수로 읽어 뒤의 0 이 사라진다",
            "따옴표로 감싼다(`value: \"8.10\"`). 없으면 엔진에 `8.1` 로 도착해 `8.9` 를 \
             양호로 보고, 원문은 복원할 길이 없다. 정수(`value: 8`)는 왕복하므로 그대로 \
             둬도 된다",
            "- { field: path, op: ends_with, value: '\\main.js' }",
            "- { field: path, op: version_lt, value: 8.10 }",
        ),
        case(
            "버전에 맞는 연산자를 고른다",
            "`gt` · `lt` 에 버전을 적었다 — 그쪽은 수와 RFC3339 시각만 견준다",
            "**경고다.** 막지 않지만 그 항목은 조용히 거짓이 된다. `version_lt` · \
             `version_gt` 를 쓴다",
            "- { field: path, op: ends_with, value: '\\main.js' }",
            "- { field: path, op: lt, value: '8.2.29' }",
        ),
        case(
            "필드를 고른다",
            "그 subject 에 없는 필드다",
            "`machine/subjects.json` 을 본다. 진단이 쓸 수 있는 필드를 전수로 준다",
            "field: command",
            "field: cmdline_of_task",
        ),
        case(
            "다른 subject 의 파일을 좁힌다",
            "`from` 을 `path` 필드가 없는 subject 에 걸었다",
            "`where` 값에 `${다른규칙.capture}` 를 넣어 묶는다",
            "  - id: payload\n    subject: file\n    from:",
            "  - id: payload\n    subject: autorun\n    from:",
        ),
        append(
            "제거 대상을 선언한다",
            "없는 규칙을 가리켰다",
            "`ref` 는 규칙 id 다. 증거 id(`payload#0`)가 아니다",
            "remediate:\n  remove:\n    - { ref: 없는룰 }\n",
        ),
        append(
            "조회 결과로 제거를 늘린다",
            "`reputation` 을 제거 근거로 삼았다",
            "**방향 제약이다.** 조회는 삭제를 늘릴 수 없다 — 감염 호스트의 응답은 신뢰할 수 없다",
            "remediate:\n  remove:\n    - { ref: 'reputation.malicious' }\n",
        ),
        append(
            "폴더를 통째로 지운다",
            "`guard` 없이 `recursive: true` 를 썼다",
            "그 폴더 안에서 악성 판정된 규칙을 `guard` 로 지목한다",
            "remediate:\n  remove:\n    - { path: '${task.payload_dir}', recursive: true }\n",
        ),
        append(
            "본문을 담는다",
            "`collect_extra` 가 없는 규칙을 가리켰다",
            "규칙 id 를 확인한다. 없으면 그 선언은 영영 해소되지 않는다",
            "collect_extra:\n  - { ref: 없는룰, content: true }\n",
        ),
        append(
            "이름이 감염마다 다른 파일의 본문을 담는다",
            "`glob` 의 폴더를 `scan_roots` 밖에 적었다",
            "`scan_roots` 안의 폴더로 적는다. 글롭은 주 수집이 걸은 `file` 레코드에서 고르므로 \
             밖의 폴더는 **조용한 0건**이다. 와일드카드는 마지막 성분에만 둔다",
            "collect_extra:\n  - { glob: 'C:\\Windows\\System32\\*.dll' }\n",
        ),
        Case {
            title: "YARA 로 본문을 판정한다",
            what: "본문을 담는 `collect_extra` 가 하나도 없다",
            fix: "`{ ref: <경로로 매치되는 규칙>, content: true }` 를 둔다. YARA 규칙 자신을 가리키면 순환이다",
            yaml: LINT_BASE.replace(
                "      - { field: path, op: ends_with, value: '\\main.js' }",
                "      - { yara: 'rules/x.yar:some_rule' }",
            ),
        },
        append(
            "지우면 시스템이 깨지는 값을 되돌린다",
            "`to: default` 를 `remove` 절에 넣었다",
            "**`restore` 절이다.** `remove` 는 `{ ref: … }` 와 `{ path: … }` 만 받는다",
            "remediate:\n  remove:\n    - { ref: task, to: default }\n",
        ),
        append(
            "subject 하나만 더 좁힌다",
            "`subject_roots` 에 `scan_roots` 밖의 경로를 적었다",
            "**좁히기만 한다.** `scan_roots` 안의 경로로 적을 것 — 넓힐 수 있으면 \
             읽기 권한의 상한이 두 곳이 되고, 서명 검토자가 한 곳만 읽으면 실제로 \
             무엇을 읽는지 모른다",
            "subject_roots:\n  file: ['C:\\Windows\\System32']\n",
        ),
        append(
            "선언하지 않은 subject 를 좁힌다",
            "`subjects` 에 없는 이름을 `subject_roots` 에 적었다",
            "`subjects` 에 넣거나 이 줄을 지운다. 선언하지 않은 subject 를 좁히는 것은 \
             아무 효과가 없고, 그래서 **작성자만 좁혔다고 믿는다**",
            "subject_roots:\n  text_config: ['%LOCALAPPDATA%\\Programs']\n",
        ),
        case(
            "코어 판을 잘못 적는다",
            "`min_core` 가 버전으로 읽히지 않는다",
            "semver 로 적는다. **Phase 이름이 아니다** — `P10` 같은 것은 개발 \
             순서이지 배포 판이 아니고, 이 문서에 있는 Op 은 전부 `1.0.0` 에 있다",
            "min_core: '1.0.0'",
            "min_core: 'P10'",
        ),
        Case {
            title: "Linux 에서도 돌게 하려고 플랫폼을 늘린다",
            what: "그 subject 를 이 코어가 Linux 에서 수집하지 않는다",
            fix: "`machine/subjects.json` 의 `linux_from` 을 본다. **비어 있으면 그 \
                  플랫폼에서 언제나 0건**이다 — Linux 전용이면 오류, 겸용이면 경고다",
            yaml: LINT_BASE
                .replace("platforms: [windows]", "platforms: [windows, linux]")
                .replace(
                    "subjects: [persistence, file]",
                    "subjects: [persistence, file, firewall_rule]",
                ),
        },
        // `edit` 가 세우는 부분 편집 Op 은 Linux 칸이 비어 있다 — 계획기는 그 edit 를
        // 보류로 빼고 사유는 "이 Op 은 지금 수행할 수 없습니다" 뿐이다 (2026-09-28
        // npm-r1 사전 기준의 변형).
        Case {
            title: "부분 편집을 Linux 에서도 쓴다",
            what: "`edit` 가 세우는 부분 편집 Op 이 Linux 에 없다",
            fix: "`machine/ops.json` 의 `linux_from` 을 본다. `registry.strip_value` · \
                  `env.strip_path` 가 비어 있으면 **그 edit 는 Linux 에서 늘 보류**된다 \
                  — Linux 전용이면 오류, 겸용이면 경고다",
            yaml: LINT_BASE
                .replace("platforms: [windows]", "platforms: [windows, linux]")
                .replace(
                    "subjects: [persistence, file]",
                    "subjects: [persistence, file, autorun]",
                )
                .replace(
                    "verdict: { require: 'task and payload' }\n",
                    "  - id: runkey\n    subject: autorun\n    where:\n      \
                     - { field: command, op: contains, value: '\\main.js' }\n    \
                     capture: { tail: 'command' }\n\
                     verdict: { require: 'task and payload' }\n\
                     remediate:\n  edit:\n    - { ref: runkey, op: strip, value: '${runkey.tail}' }\n",
                ),
        },
        // 계획기는 `edit` 의 대상을 보지 않고 `registry.strip_value` 를 세운다 —
        // 바로가기에 걸면 치료가 guard 정지로 끝났다 (2026-09-28 shortcut-r1 실기기).
        Case {
            title: "바로가기 인자를 edit 로 뗀다",
            what: "`edit` 가 레지스트리 값이 아닌 것을 가리킨다",
            fix: "바로가기 인자 · 설정 항목은 `remove` 가 subject 에 맞는 Op 으로 뗀다",
            yaml: LINT_BASE
                .replace(
                    "subjects: [persistence, file]",
                    "subjects: [persistence, file, shortcut]",
                )
                .replace(
                    "verdict: { require: 'task and payload' }\n",
                    "  - id: lnk\n    subject: shortcut\n    where:\n      \
                     - { field: args, op: contains, value: '--load-extension=' }\n    \
                     capture: { tail: 'args' }\n\
                     verdict: { require: 'task and payload' }\n\
                     remediate:\n  edit:\n    - { ref: lnk, op: strip, value: '${lnk.tail}' }\n",
                ),
        },
        case(
            "레지스트리를 보는 subject 를 선언한다",
            "`scan_roots` 에 레지스트리 루트가 없다",
            "`HKLM\\…` 형태의 루트를 하나 이상 적는다. 없으면 **`registry_value` 는 \
             언제나 0건**이고, 그 위에서 도는 룰은 아무것도 맞히지 못한 채 초록이 된다",
            "subjects: [persistence, file]",
            "subjects: [persistence, file, registry_value]",
        ),
        case(
            "파일의 대체 스트림을 본다",
            "정의는 됐는데 이 코어가 아직 채우지 않는 필드다",
            "`machine/subjects.json` 이 그 사유를 적는다. **없는 필드가 아니라 \
             언제나 비어 있는 필드**이므로 문법은 통과하고 룰만 조용히 0건이 된다",
            "- { field: path, op: ends_with, value: '\\main.js' }",
            "- { field: streams, op: exists }",
        ),
        // 위 사례의 둘째 줄로만 나오던 경고다 — 자기 절이 없어 xmr-r1 응시자가
        // 그것을 예상하지 못했다 (runs/2026-09-23-opus-4.8-xmr-r1/NOTES.md).
        case(
            "부분 문자열 하나로 가른다",
            "조건이 넓은 비교(`contains`·`exists`) 하나뿐이고 값이 3바이트 이하다 — 그 \
             규칙은 사실상 필터가 없다",
            "대상을 특정하는 조건을 하나 더 두어 `all` 로 묶거나, 값을 그 대상만 가리키는 \
             길이로 늘린다. 부모 규칙이면 맞은 레코드마다 증거 그룹이 하나씩 생기고, \
             50개를 넘으면 계획 단계의 상한에 걸린다 — 무인 실행은 치료 전에 멈추고, \
             대화형은 계획 전문을 보여 주고 승인을 받는다. **같은 뜻을 다른 연산자로 \
             돌려 적어 경고만 끄지 않는다** — 경고는 사라져도 폭은 그대로다",
            "op: matches, value: '(?i)\\\\node\\.exe$'",
            "op: contains, value: 'js'",
        ),
        case(
            "사용자 홈 아래를 재귀로 지운다",
            "파생 경로가 홈 직하가 될 수 있는 상한에서 재귀 삭제를 건다",
            "상한을 홈보다 깊게 내린다. `%USERPROFILE%` 이하가 상한이면 파생 경로가 \
             `Documents`·`Desktop` 이 될 수 있고, 그러면 **사용자 자료를 통째로 지운다**",
            "scan_roots: ['%LOCALAPPDATA%\\Programs']",
            concat!(
                "scan_roots: ['%USERPROFILE%']\nremediate:\n  remove:\n    ",
                "- { path: '${task.payload_dir}', recursive: true, guard: payload }",
            ),
        ),
        Case {
            title: "지속성 값을 OS 기본값으로 되돌린다",
            what: "그 레지스트리 값이 기본값 카탈로그에 없다",
            fix: "**값 하나로 복원이 완결되는 대상만** 담긴다. 카탈로그에 없으면 \
                  되돌릴 값을 코어가 모르므로, 되돌리기가 아니라 제거로 다뤄야 한다",
            yaml: LINT_BASE
                .replace(
                    "subjects: [persistence, file]",
                    "subjects: [persistence, file, registry_value]",
                )
                .replace(
                    "scan_roots: ['%LOCALAPPDATA%\\Programs']",
                    "scan_roots: ['%LOCALAPPDATA%\\Programs', 'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run']",
                )
                .replace(
                    "verdict:",
                    concat!(
                        "  - id: runkey\n",
                        "    subject: registry_value\n",
                        "    where:\n",
                        "      all:\n",
                        "        - { field: hive, op: equals, value: 'HKLM' }\n",
                        "        - { field: key, op: equals, value: 'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run' }\n",
                        "        - { field: name, op: equals, value: 'Updater' }\n",
                        "remediate:\n",
                        "  restore:\n",
                        "    - { ref: runkey, to: default }\n",
                        "verdict:",
                    ),
                ),
        },
        append(
            "보안 제품 예외를 되돌린다",
            "`av_exclusion` 을 탐지하는 규칙이 없다",
            "그 subject 규칙을 두고 우리 경로를 짚는다. 없으면 되돌릴 증거가 안 잡힌다",
            "remediate:\n  restore:\n    - av_exclusions\n",
        ),
        Case {
            title: "값이 닫힌 필드에 다른 낱말을 쓴다",
            what: "필드 이름은 맞는데 이 코어가 그 자리에 적지 않는 값을 썼다",
            fix: "`machine/subjects.json` 의 `enumerated` 를 본다. **값이 닫힌 필드는 \
                  거기에 전수가 있다.** 이름이 맞아 문법도 통과하던 자리라, 없으면 \
                  규칙이 조용히 0건을 맞히고 그것에 기댄 판정이 서지 않는다",
            yaml: LINT_BASE
                .replace(
                    "subjects: [persistence, file]",
                    "subjects: [persistence, file, service]",
                )
                .replace(
                    "verdict: { require: 'task and payload' }",
                    concat!(
                        "  - id: svc\n",
                        "    subject: service\n",
                        "    where:\n",
                        "      - { field: state, op: equals, value: 'running' }\n",
                        "verdict: { require: 'task and payload and svc' }"
                    ),
                ),
        },
        case(
            "넓게 훑는다",
            "`scan_roots` 가 사실상 전체를 가리킨다",
            "**경고다.** 넓은 범위가 실제로 필요하면 그 이유를 서명 단계에서 설명한다",
            "['%LOCALAPPDATA%\\Programs']",
            "['C:\\Users']",
        ),
    ]
}

/// `32-lint-errors.md` — 린트가 무엇을 왜 막는가 (설계-06 §2·§7).
///
/// # 메시지를 손으로 적지 않는다
///
/// 아래 사례를 **실제로 `lint()` 에 통과시켜** 나온 진단을 그대로 싣는다.
/// 메시지가 바뀌면 이 문서도 바뀌고, 검사가 발동하지 않으면 그 줄에 그렇게
/// 적힌다 — 조용히 빈 칸이 되지 않는다.
///
/// 손으로 적은 오류 표는 반드시 낡고, **낡은 오류 메시지를 읽은 AI 는 지금은
/// 없는 수정법을 시도한다.**
pub fn lint_errors_md() -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "<!-- schema_version: {} | min_core: 1.0.0 | generated: true -->\n\n",
        crate::SCHEMA_VERSION
    ));
    s.push_str("# 린트 진단 (생성물 — 직접 고치지 말 것)\n\n");
    s.push_str(
        "아래 메시지는 **실제로 `plugin lint` 를 돌려 받은 것**이다. \
         `crates/remedy-sdk/src/generate.rs` 의 사례를 고치면 이 문서가 바뀐다.\n\n",
    );
    s.push_str(
        "**오류는 로드를 막고, 경고는 막지 않는다.** 경고가 남은 채로 서명하려면 \
         각각의 이유를 설명해야 한다 (설계-06 §8).\n\n",
    );

    // 기준 매니페스트가 깨끗한지 먼저 확인한다. 여기서 진단이 나오면 아래
    // 사례들의 "이것 때문에 났다" 가 전부 거짓이 된다.
    let base: crate::manifest::PluginManifest =
        serde_yaml_ng::from_str(LINT_BASE).expect("LINT_BASE 파싱");
    let base_issues = crate::lint(&base);
    if !base_issues.is_empty() {
        s.push_str(&format!(
            "> **기준 매니페스트에서 진단 {}건이 났다.** 아래 사례가 무엇 때문에 \
             걸린 것인지 말할 수 없는 상태다 — `generate.rs` 의 `LINT_BASE` 를 고쳐야 한다.\n\n",
            base_issues.len()
        ));
    }

    for c in lint_cases() {
        s.push_str(&format!("## {}\n\n", c.title));
        s.push_str(&format!("**무엇이 잘못됐나.** {}\n\n", c.what));

        let parsed: Result<crate::manifest::PluginManifest, _> = serde_yaml_ng::from_str(&c.yaml);
        match parsed {
            Err(e) => {
                s.push_str(&format!(
                    "```\n{e}\n```\n\n**이것은 린트가 아니라 파싱 단계에서 걸린다.** \
                     알 수 없는 키는 무시가 아니라 거부다.\n\n"
                ));
            }
            Ok(m) => {
                let issues = crate::lint(&m);
                let fresh: Vec<_> = issues
                    .iter()
                    .filter(|i| !base_issues.iter().any(|b| b == *i))
                    .collect();
                if fresh.is_empty() {
                    s.push_str(
                        "> **이 사례가 아무 진단도 내지 않았다.** 검사가 사라졌거나 \
                         사례가 더는 그것을 발동시키지 못한다 — 둘 다 고쳐야 한다.\n\n",
                    );
                } else {
                    s.push_str("```\n");
                    for i in fresh {
                        s.push_str(&format!("{i}\n"));
                    }
                    s.push_str("```\n\n");
                }
            }
        }
        s.push_str(&format!("**고치는 법.** {}\n\n", c.fix));
    }
    s
}

// ─────────────────────────────────────────────── machine/AI-CONTEXT.md

/// `AI-CONTEXT.md` 가 싣는 최소 매니페스트. **생성기가 이것을 실제로 린트에
/// 통과시킨다** — 문서에 실린 예제는 복제되므로 틀린 것이 실리면 그 형태가
/// 그대로 재생산된다 (설계-06 §5).
const AI_CONTEXT_EXAMPLE: &str = r#"schema_version: 1
id: example-threat
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name: { ko: "예제 위협 제거", en: "Example threat removal" }
scan_roots: ["%LOCALAPPDATA%\\Programs"]   # persistence 는 이 상한과 무관하다
subjects: [persistence, file]
detect:
  - id: task                      # 부모 — 증거 그룹 하나가 생긴다
    subject: persistence
    where:
      all:
        - { field: command, op: matches, value: '(?i)\\node\.exe$' }
        - { field: args,    op: matches, value: '(?i)\.js("|\s|$)' }
    capture:
      dir: "args | first_path | dirname"   # 파이프는 몇 단이든 이어 붙일 수 있다
  - id: payload                   # 자식 — 부모가 가리킨 폴더 안만
    subject: file
    from: "${task.dir}"
    where:
      - { field: path, op: ends_with, value: ".js" }
verdict:
  require: "task and payload"     # 독립적인 두 근거
remediate:
  remove:
    - { ref: task }
    - { ref: payload }
"#;

/// `machine/AI-CONTEXT.md` — **하나만 넣을 때 넣는 파일** (설계-06 §2·§9).
///
/// 폴더 전체를 문맥에 넣을 수 없을 때 이것 하나로 룰을 쓸 수 있어야 한다.
/// 상한 8 KB 는 `cargo xtask guide` 가 잰다 — 넘으면 빌드가 멈춘다.
///
/// # 무엇을 넣고 무엇을 빼는가
///
/// **전수 카탈로그가 본체다.** 없는 필드·연산자·Op 를 쓴 룰은 조용히 아무것도
/// 매치하지 않으므로, 산문을 줄여서라도 목록은 전부 싣는다.
///
/// 레시피와 안티패턴은 **뺀다** — 그것은 판단을 가르치는 자리이고 8 KB 에
/// 들어가지 않는다. 대신 어느 파일을 봐야 하는지만 남긴다.
pub fn ai_context_md() -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "<!-- schema_version: {} | min_core: 1.0.0 | generated: true -->\n\n",
        crate::SCHEMA_VERSION
    ));
    s.push_str("# remedy 플러그인 — 압축 문맥 (생성물)\n\n");
    s.push_str(&format!(
        "스키마 {} · 구현 Phase {}. 이 파일 하나로 룰을 쓸 수 있게 만든 것이다. \
         판단이 필요한 자리(레시피·안티패턴·리뷰)는 `docs/plugin-guide/` 의 \
         번호 붙은 문서를 본다.\n\n",
        crate::SCHEMA_VERSION,
        crate::IMPLEMENTED_THROUGH.as_str()
    ));

    s.push_str("## 절대 규칙\n\n");
    s.push_str(
        "- `subject` · 필드 · 연산자 · `Op` 는 **닫힌 집합**이다. 여기 없는 이름을 쓰면 거부된다.\n\
         - 플러그인은 `Op` 을 직접 고르지 않는다. **무엇을 없앨지만 선언**하고 순서·Op 은 코어가 정한다.\n\
         - 제거 대상은 **증거에서 파생된 것**이어야 한다. 리터럴 절대 경로는 거부된다.\n\
         - `scan_roots` 는 성능이 아니라 **읽기 권한 상한**이다.\n\
         - 판정은 `verdict.require` 의 불 대수식이 정한다. **점수 임계값 문법은 없다.**\n\
         - 점검(`kind: check`)은 모르는 것을 `verdict.unconfirmed`(`when` · `why` ko·en · 코어 1.3.0)로 \
         *확인 필요*(6) 라고 말한다 — 모르는데 판정을 세우지 않으면 0 이 나간다.\n\n",
    );

    s.push_str("## 최소 매니페스트\n\n```yaml\n");
    s.push_str(AI_CONTEXT_EXAMPLE);
    s.push_str("```\n\n");

    // **예제를 실제로 린트에 통과시킨다.** 문서에 실린 예제는 복제되므로
    // 틀린 것이 실리면 그 형태가 그대로 재생산된다 (설계-06 §5).
    match serde_yaml_ng::from_str::<crate::manifest::PluginManifest>(AI_CONTEXT_EXAMPLE) {
        Err(e) => s.push_str(&format!(
            "> **위 예제가 파싱되지 않는다: {e}** — `generate.rs` 를 고쳐야 한다.\n\n"
        )),
        Ok(m) => {
            let issues = crate::lint(&m);
            if !issues.is_empty() {
                s.push_str(&format!(
                    "> **위 예제에서 진단 {}건이 났다.** 문서가 거부되는 형태를 \
                     가르치고 있다 — `generate.rs` 를 고쳐야 한다.\n\n",
                    issues.len()
                ));
            }
        }
    }

    s.push_str("## subject 와 필드 (닫힌 집합)\n\n");
    for x in Subject::ALL {
        let f = x.fields();
        s.push_str(&format!("- `{}`: ", x.id()));
        if f.is_empty() {
            s.push_str("_(필드 미정의)_\n");
        } else {
            s.push_str(&f.join(" "));
            s.push('\n');
        }
    }

    s.push_str("\n**`from` 은 `path` 필드가 있는 subject 에만 통한다** — ");
    let with_path: Vec<&str> = Subject::ALL
        .iter()
        .filter(|x| x.fields().contains(&"path"))
        .map(|x| x.id())
        .collect();
    s.push_str(&with_path.join(" "));
    s.push_str(". 그 밖에는 `where` 값에 `${다른규칙.capture}` 를 넣어 부모에 묶는다.\n\n");

    s.push_str(&format!("## Op {}종 (계획기가 고른다)\n\n", Op::ALL.len()));
    let ops: Vec<&str> = Op::ALL.iter().map(|x| x.id()).collect();
    s.push_str(&ops.join(" · "));
    s.push_str("\n\n**유발자는 산출물보다 먼저 실행된다** — ");
    let regen: Vec<&str> = Op::ALL
        .iter()
        .filter(|x| x.info().regenerator)
        .map(|x| x.id())
        .collect();
    s.push_str(&regen.join(" · "));
    s.push_str(".\n\n");

    s.push_str("## 연산자\n\n");
    let ops: Vec<&str> = Operator::ALL.iter().map(|x| x.id()).collect();
    s.push_str(&ops.join(" · "));
    s.push_str("\n\n정규식은 **RE2** 다. 역참조·전방탐색이 없다.\n\n");

    s.push_str("## capture 함수\n\n");
    let caps: Vec<&str> = CaptureFn::ALL.iter().map(|x| x.id()).collect();
    s.push_str(&caps.join(" · "));
    s.push_str("\n\n");
    s.push_str(CAPTURE_FN_NOTE);
    s.push_str("\n\n");

    s.push_str("## 지정 확장 토큰\n\n");
    s.push_str(
        "`%ALLUSERPROFILES%`(사용자 수만큼) · `HKU\\*`(하이브 수만큼) · \
         `%REMOVABLE%`(매체 수만큼 · `allow_removable: true` 필요). \
         **하나가 여럿이 된다** — 쓰지 않으면 다중 사용자 기계에서 현재 \
         사용자만 치료된다.\n\n",
    );

    s.push_str("## 없는 것 (지어내지 말 것)\n\n");
    s.push_str(
        "- 임의 명령 실행 Op (`exec` · `run_command` · `powershell`)\n\
         - 파일 **쓰기·수정** Op. 파괴와 원복만 있다\n\
         - 네트워크 요청. 조회는 `enrich` 단계이고 룰이 호출하지 않는다\n\
         - 스크립트 런타임\n\
         - 백업을 끄는 옵션 · 삭제 상한이나 보호 경로를 조정하는 키\n\
         - `verdict` 의 점수 임계값 문법\n\n",
    );

    s.push_str("## 자주 걸리는 것\n\n");
    s.push_str(
        "- YARA 를 쓰면 `collect_extra` 로 **본문을 담아야** 한다. 안 담으면 \
         *\"재지 못했다\"* 가 되고 판정이 서지 않는다. 가리킬 규칙은 **경로로 \
         매치되는** 것이어야 한다(YARA 규칙 자신을 가리키면 순환).\n\
         - `restore: [av_exclusions]` 는 `av_exclusion` **증거**를 되돌린다. \
         그 subject 탐지 규칙이 없으면 Action 이 만들어지지 않는다.\n\
         - `recursive: true` 는 `guard` 를 문법 수준에서 요구한다.\n\
         - **`to: default` 는 `restore` 절이다** — `remove` 에 넣으면 린트가 \
         아니라 파싱에서 멈춘다. 지우면 시스템이 깨지는 값(로그온 셸 등)을 \
         되돌리는 자리이고, 대상은 코어 카탈로그에 있는 것만이다.\n\
         - `platforms` 와 `win.*`/`linux.*` 필드가 어긋나면 거부된다.\n\n",
    );

    s.push_str("## 더 볼 곳\n\n");
    s.push_str(
        "`00-invariants.md`(절대 규칙) · `10-manifest.md`(키·`scan_roots`) · \
         `20-detect-recipes.md`(탐지·YARA) · `22-remediate-recipes.md`(제거) · \
         `23-collect-and-submit.md`(본문·제출) · `24-check-plugins.md`(점검 전용) · \
         `30-antipatterns.md`(거부되는 형태) · \
         `31-nonexistent.md`(없는 기능) · `32-lint-errors.md`(진단) · \
         `40-review-checklist.md`(서명 전) · `examples/`(CI 에서 도는 실물 — 제거까지 둘 · 탐지만 하나 · 점검 하나)\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 이 값의 모든 객체가 키 이름 순인가.
    fn keys_are_sorted(v: &serde_json::Value) -> Result<(), String> {
        match v {
            serde_json::Value::Object(m) => {
                let keys: Vec<&String> = m.keys().collect();
                let mut want = keys.clone();
                want.sort();
                if keys != want {
                    return Err(format!("{keys:?}"));
                }
                for val in m.values() {
                    keys_are_sorted(val)?;
                }
                Ok(())
            }
            serde_json::Value::Array(a) => {
                for x in a {
                    keys_are_sorted(x)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    #[test]
    fn generated_json_keys_are_in_a_fixed_order() {
        // **생성물은 의존성의 기능 플래그에 좌우되면 안 된다.**
        //
        // `serde_json` 의 객체는 기본으로 이름 순이지만, 의존 그래프 어딘가가
        // `preserve_order` 를 켜면 삽입 순이 된다. 기능은 워크스페이스 전체에
        // 합쳐지므로 관계없는 크레이트 하나가 그것을 켜는 순간 생성물이 통째로
        // 어긋난다 — 퍼징 때문에 `xtask` 가 `remedy-detect` 를 의존하게 만들었을
        // 때 실제로 그렇게 됐다.
        //
        // 이 시험은 그 기능이 **켜져 있을 때** 값을 한다. 꺼져 있으면 파싱이
        // 알아서 정렬하므로 공허해지지만, 지금 이 워크스페이스는 켜져 있다.
        for item in all() {
            if !item.path.ends_with(".json") {
                continue;
            }
            let v: serde_json::Value = serde_json::from_str(&item.content)
                .unwrap_or_else(|e| panic!("{}: {e}", item.path));
            if let Err(order) = keys_are_sorted(&v) {
                panic!("{} 의 키가 이름 순이 아니다: {order}", item.path);
            }
        }
    }

    #[test]
    fn every_lint_case_actually_fires() {
        // **사례가 발동하지 않으면 그 검사는 문서에서 사라진다.** 생성기가
        // 그 사실을 문서에 적으므로, 여기서 그 문구를 찾아 실패시킨다.
        let md = lint_errors_md();
        assert!(
            !md.contains("아무 진단도 내지 않았다"),
            "발동하지 않는 사례가 있다:
{md}"
        );
        assert!(
            !md.contains("기준 매니페스트에서 진단"),
            "LINT_BASE 자체가 깨끗하지 않다:
{md}"
        );
    }

    #[test]
    fn the_ai_context_example_lints_clean() {
        // 문서에 실린 예제는 복제된다. 거부되는 형태를 가르치면 안 된다.
        let md = ai_context_md();
        assert!(
            !md.contains("진단") || !md.contains("건이 났다"),
            "AI-CONTEXT 의 예제가 진단을 낸다:
{md}"
        );
        assert!(!md.contains("파싱되지 않는다"), "예제가 파싱되지 않는다");
    }

    #[test]
    fn the_ai_context_fits_its_budget() {
        // 상한 8 KB (설계-06 §9). `xtask guide` 도 재지만, 생성 시점에 넘으면
        // 커밋된 파일이 이미 넘은 상태가 된다.
        let n = ai_context_md().len();
        assert!(n <= 8 * 1024, "AI-CONTEXT.md 가 {n} 바이트다 (상한 8192)");
    }

    #[test]
    fn canonical_sorts_objects_but_leaves_arrays_alone() {
        // 배열의 **순서는 뜻이 있다.** 정렬하면 Op 목록의 Phase 순서 같은 것이
        // 무너진다.
        let v = serde_json::json!({ "b": 1, "a": [3, 1, 2] });
        let out = pretty(&v);
        assert!(
            out.find("\"a\"").unwrap() < out.find("\"b\"").unwrap(),
            "객체 키가 정렬되지 않았다:\n{out}"
        );
        assert!(out.contains("3,"), "배열이 정렬됐다:\n{out}");
    }
}
