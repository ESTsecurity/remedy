//! 신고 첨부물 (설계-04 §6).
//!
//! # 이것이 푸는 문제
//!
//! > 신고를 받기 위한 최소 요건: **첨부해야 할 파일 목록과 그 경로가 명시**되어야
//! > 한다. 고객에게 "로그를 보내 주세요" 라고 하면 무엇을 보낼지 몰라 대응이
//! > 지연된다.
//!
//! 오탐 대응 경로(§6)의 두 번째 칸이다 — 복구(`restore`) 다음, 재현·판정 앞.
//! **여기서 막히면 뒤가 전부 늦어진다.**
//!
//! # 보내지 않는다, 만들 뿐이다
//!
//! 설계-01 D9 가 치료 경로에 네트워크를 금지하고, `remedy-apply → remedy-submit`
//! 금지 의존이 그것을 빌드로 강제한다. 이 모듈은 **파일을 모아 디렉터리 하나를
//! 만들고 끝난다** — 어디로 보낼지는 사람이 정한다.
//!
//! # `remedy-submit` 과 다른 것이다
//!
//! | | `submit` | 여기 |
//! |---|---|---|
//! | 목적 | 검체를 사내 분석 시스템에 **제출** | 오탐을 우리에게 **신고** |
//! | 내용 | 악성 의심 파일 | 우리 실행 기록 |
//! | 네트워크 | 쓴다 (치료 경로 밖) | 쓰지 않는다 |
//! | 동의·마스킹 | 필요 (설계-00 §7 법무) | 아래 |
//!
//! **마스킹하지 않는다.** 오탐 판정은 "어느 경로의 무엇을 지웠는가" 를 봐야
//! 서는데, 그 경로를 가리면 판정할 수 없다. 대신 **무엇이 담겼는지 명시**해
//! 사람이 보내기 전에 판단하게 한다 — 그것이 이 설계가 고른 쪽이다.
//!
//! # 압축하지 않는다
//!
//! zip 크레이트를 들이면 배포 표면이 늘고, 디렉터리 하나를 압축하는 것은 OS 가
//! 이미 한다. 여기서는 **모으고 목록을 적는 것**까지 한다.

use std::path::{Path, PathBuf};

/// 담긴 것 하나.
#[derive(Debug, Clone)]
pub struct Included {
    /// 꾸러미 안의 이름.
    pub name: String,
    /// 어디서 왔나.
    pub source: PathBuf,
    pub bytes: u64,
    /// 이것이 무엇인가. 목록에 그대로 적힌다.
    pub what: &'static str,
}

/// **일부러 담지 않은 것과 그 이유.**
///
/// 빠진 것을 적지 않으면 받는 쪽은 "왜 없지" 를 묻고, 보내는 쪽은 "다 보냈는데"
/// 라고 답한다. 그 왕복이 §6 이 없애려는 지연 그 자체다.
#[derive(Debug, Clone)]
pub struct Excluded {
    pub name: String,
    pub why: &'static str,
}

#[derive(Debug)]
pub struct Bundle {
    pub dir: PathBuf,
    pub run_id: String,
    pub included: Vec<Included>,
    pub excluded: Vec<Excluded>,
    /// 플러그인 작성자가 남긴 **손으로 올릴 때의 판단 근거**.
    ///
    /// 제출 기능은 제품 범위 밖이다 (설계-09 "제출을 제품 밖으로"). 그래서 이
    /// 값은 자동 제출기가 아니라 **이 꾸러미를 들고 올리는 사람**이 본다.
    ///
    /// 계획에서 읽는다 — `support-bundle` 은 `--run` 만 받으므로 매니페스트를
    /// 다시 찾게 만들면 그 경로는 있는데 쓰이지 않는 경로가 된다.
    pub submit_hint: Option<remedy_sdk::manifest::SubmitHint>,
}

impl Bundle {
    pub fn is_empty(&self) -> bool {
        self.included.is_empty()
    }
}

/// 이 실행의 신고 첨부물을 만든다.
///
/// `out` 아래에 `remedy-support-<run_id>` 디렉터리를 만들고 파일을 복사한다.
/// **원본을 옮기거나 지우지 않는다** — 격리물이 자동 삭제되지 않는 것과 같은
/// 이유다(설계-03 §5). 신고를 보낸 뒤에도 이 기계에서 복구할 수 있어야 한다.
pub fn build(state_dir: &Path, run_id: &str, out: &Path) -> Result<Bundle, String> {
    if run_id.is_empty() || run_id.contains(['/', '\\', ':']) {
        // run_id 가 경로 조각이 되므로 그대로 믿지 않는다.
        return Err(format!(
            "run_id 가 이름으로 쓸 수 없는 모양이다: {run_id:?}"
        ));
    }

    let dir = out.join(format!("remedy-support-{run_id}"));
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("{} 를 만들지 못했습니다: {e}", dir.display()))?;

    let mut included = Vec::new();
    let mut missing = Vec::new();

    // 담는 것 — **무엇을 하려 했나**와 **무엇을 했나**.
    for (src, name, what) in [
        (
            remedy_apply::plan_path(state_dir, run_id),
            "plan.json",
            remedy_sdk::i18n::t("무엇을 하려 했는가: 승인된 계획 전문", "what was going to happen: the approved plan in full"),
        ),
        (
            remedy_journal::journal_path(state_dir, run_id),
            "journal.jsonl",
            remedy_sdk::i18n::t("무엇을 했는가: 감사 로그", "what was done: the audit log"),
        ),
        (
            // **재부팅 뒤 예약된 재평가의 결과가 여기 말고는 없다** — 그 실행은
            // 콘솔 없이 돌고 종료 코드가 사라진다 (설계-03 §8).
            crate::verify_log::path(state_dir, run_id),
            "verify.jsonl",
            remedy_sdk::i18n::t("치료가 유지됐는가: 재평가 기록", "whether the treatment held: the re-evaluation record"),
        ),
        (
            crate::runlog::path(state_dir, run_id),
            "run.log",
            remedy_sdk::i18n::t("사람이 본 화면: 배너·계획·경고·실패 문구·마무리 표, 줄마다 시각", "what the operator saw: banner, plan, warnings, failures, closing table, each line timed"),
        ),
    ] {
        match copy_one(&src, &dir.join(name)) {
            Ok(bytes) => included.push(Included {
                name: name.into(),
                source: src,
                bytes,
                what,
            }),
            Err(_) => missing.push(name),
        }
    }

    // 환경 — 이 실행이 **어떤 코어에서** 돌았는가. 오탐 재현의 전제다.
    let env = environment(run_id);
    let env_path = dir.join("environment.json");
    std::fs::write(&env_path, &env)
        .map_err(|e| format!("{} 를 쓰지 못했습니다: {e}", env_path.display()))?;
    included.push(Included {
        name: "environment.json".into(),
        source: env_path,
        bytes: env.len() as u64,
        what: remedy_sdk::i18n::t(
            "어떤 코어에서 돌았는가: 버전, 타깃, 자기무결성, 엔진 상태",
            "which core ran: version, target, self-integrity, engine state",
        ),
    });

    let excluded = excluded_list(state_dir, run_id);
    // **계획에서 읽는다.** 없거나 깨졌으면 `None` 이다 — 첨부물을 만드는 일이
    // 그것 하나 때문에 멈추면 안 된다. 계획 파일 자체는 위에서 이미 담겼고,
    // 못 담았으면 `missing` 이 그렇게 말한다.
    let hint = read_submit_hint(state_dir, run_id);

    let readme = render_readme(run_id, &included, &excluded, &missing, hint.as_ref());
    std::fs::write(dir.join("README.txt"), &readme)
        .map_err(|e| format!("README 를 쓰지 못했습니다: {e}"))?;

    Ok(Bundle {
        dir,
        run_id: run_id.to_string(),
        included,
        excluded,
        submit_hint: hint,
    })
}

/// 승인된 계획에서 제출 힌트를 읽는다.
fn read_submit_hint(state_dir: &Path, run_id: &str) -> Option<remedy_sdk::manifest::SubmitHint> {
    let text = std::fs::read_to_string(remedy_apply::plan_path(state_dir, run_id)).ok()?;
    let plan: remedy_sdk::artifact::PlanEnvelope = serde_json::from_str(&text).ok()?;
    plan.body.submit_hint
}

fn copy_one(src: &Path, dst: &Path) -> Result<u64, ()> {
    if !src.exists() {
        return Err(());
    }
    std::fs::copy(src, dst).map_err(|_| ())
}

/// 담지 않은 것. **경로까지 적는다** — 받는 쪽이 요청할 수 있어야 하고, 보내는
/// 쪽이 무엇을 쥐고 있는지 알아야 한다.
fn excluded_list(state_dir: &Path, run_id: &str) -> Vec<Excluded> {
    let mut v = Vec::new();
    let container = crate::restore::container_path(state_dir, run_id);
    if container.exists() {
        v.push(Excluded {
            name: container.display().to_string(),
            why: remedy_sdk::i18n::t(
                "격리 컨테이너: 검체와 사용자 파일 내용이 들어 있습니다. \
                 오탐 복구는 보내지 않고 이 기계에서 `remedy restore --run <id>` 로 합니다",
                "quarantine container: holds the sample and user file contents. \
                 Do not send it; a false-positive is undone on this machine with `remedy restore --run <id>`",
            ),
        });
    }
    let key = state_dir.join("machine.key");
    if key.exists() {
        v.push(Excluded {
            name: key.display().to_string(),
            why: remedy_sdk::i18n::t(
                "격리 컨테이너를 여는 봉인 키. 보내면 그 컨테이너를 누구나 열 수 있습니다. \
                 어떤 경우에도 첨부하지 마십시오",
                "the sealing key that opens the quarantine container. Sending it lets anyone \
                 open the container. Never attach it",
            ),
        });
    }
    v
}

/// 이 실행이 어떤 코어에서 돌았는가.
fn environment(run_id: &str) -> String {
    let t = crate::self_test();
    let integrity = crate::integrity::check_self();
    // 손으로 짓는다. serde 로 임시 구조체를 두는 것보다 **무엇이 담기는지**가
    // 여기서 바로 보인다 — 이 파일은 사람이 읽고 보낼지 판단하는 것이다.
    let linked = t
        .linked
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{\n  \"run_id\": \"{run_id}\",\n  \"core_version\": \"{}\",\n  \
         \"target\": \"{}\",\n  \"self_integrity\": \"{}\",\n  \
         \"dev_build\": {},\n  \"yara_ok\": {},\n  \"linked\": [{linked}]\n}}\n",
        env!("CARGO_PKG_VERSION"),
        t.target,
        integrity,
        crate::integrity::is_dev_build(),
        t.yara.ok(),
    )
}

fn render_readme(
    run_id: &str,
    included: &[Included],
    excluded: &[Excluded],
    missing: &[&str],
    hint: Option<&remedy_sdk::manifest::SubmitHint>,
) -> String {
    let mut s = String::new();
    s.push_str(&format!("remedy 신고 첨부물 — 실행 {run_id}\n"));
    s.push_str("=======================================\n\n");

    s.push_str("담긴 것\n");
    for i in included {
        s.push_str(&format!(
            "  {:<18} {:>9} 바이트  {}\n    <- {}\n",
            i.name,
            i.bytes,
            i.what,
            i.source.display()
        ));
    }

    if !missing.is_empty() {
        s.push_str("\n찾지 못한 것\n");
        for m in missing {
            s.push_str(&format!(
                "  {m} — 이 실행의 기록이 상태 디렉터리에 없습니다. \
                 다른 --state-dir 로 돌렸거나 아직 그 단계에 이르지 않았습니다\n"
            ));
        }
    }

    if !excluded.is_empty() {
        s.push_str("\n일부러 담지 않은 것 — 그리고 왜\n");
        for e in excluded {
            s.push_str(&format!("  {}\n    {}\n", e.name, e.why));
        }
    }

    s.push_str(
        "\n보내기 전에 열어 보십시오\n  \
         파일 경로·호스트명·사용자명이 **그대로** 들어 있습니다. 가리지 않는 이유는 \
         오탐 판정이\n  \"어느 경로의 무엇을 지웠는가\" 를 봐야 서기 때문입니다 — \
         그 경로를 가리면 판정할 수 없습니다.\n  \
         담긴 것이 보내도 되는 내용인지 사람이 보고 정합니다.\n",
    );

    // 플러그인 작성자가 남긴 판단.
    //
    // **제출 기능은 제품에 없다** (설계-09 "제출을 제품 밖으로"). 그래서 이것은
    // 자동 제출기가 아니라 **이 꾸러미를 들고 올리는 사람**에게 주는 말이다.
    if let Some(h) = hint {
        s.push_str("\n플러그인이 남긴 것 — 손으로 올릴 때 보십시오\n");
        if !h.samples.is_empty() {
            s.push_str(&format!(
                "  함께 올리면 유용한 증거: {}\n  \
                 (규칙 id 다. 그 파일은 격리 컨테이너 안에 있고 이 지원 번들에는 \
                 담기지 않습니다 — 위 '담지 않은 것' 참조)\n",
                h.samples.join(" · ")
            ));
        }
        if let Some(c) = h.confidentiality_min {
            let label = match c {
                0 => "공개",
                1 => "대외비",
                2 => "기밀",
                _ => "극비",
            };
            s.push_str(&format!(
                "  기밀 등급 하한: {c} ({label})\n  \
                 **이 등급 아래로 다루지 마십시오.** 플러그인은 이 값을 올릴 수만 \
                 있고 낮출 수 없습니다 (설계-05 §4-2).\n"
            ));
        }
    }

    s.push_str(
        "\n보내는 법\n  \
         이 디렉터리를 통째로 압축해 첨부합니다. 압축은 이 도구가 하지 않습니다 — \
         OS 가 이미 합니다.\n  \
         신고 경로는 배포처의 SECURITY.md 또는 이슈 템플릿에 있습니다.\n",
    );

    s.push_str(
        "\n먼저 할 것이 있다면\n  \
         오탐이라고 보면 **신고보다 복구가 먼저다** — `remedy restore --run ",
    );
    s.push_str(run_id);
    s.push_str(
        "`.\n  격리물은 자동으로 지워지지 않으므로 신고 뒤에도 복구할 수 있습니다 \
         (설계-03 §5).\n",
    );

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("remedy-support-test-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("실험 디렉터리");
        d
    }

    /// 실행 하나가 남긴 것처럼 상태 디렉터리를 꾸민다.
    fn seed(state: &Path, run_id: &str, with_container: bool) {
        std::fs::create_dir_all(state.join("plan")).unwrap();
        std::fs::create_dir_all(state.join("journal")).unwrap();
        std::fs::write(
            remedy_apply::plan_path(state, run_id),
            br#"{"schema_version":1}"#,
        )
        .unwrap();
        std::fs::write(
            remedy_journal::journal_path(state, run_id),
            b"{\"kind\":\"start\"}\n",
        )
        .unwrap();
        std::fs::write(state.join("machine.key"), b"0123456789abcdef").unwrap();
        if with_container {
            std::fs::create_dir_all(state.join("quarantine")).unwrap();
            std::fs::write(crate::restore::container_path(state, run_id), b"RQ").unwrap();
        }
    }

    /// 제출 힌트가 실린 계획 하나.
    ///
    /// `seed` 의 계획은 `{"schema_version":1}` 뿐이라 봉투로 읽히지 않는다 —
    /// 그것으로 충분한 시험이 따로 있고, 여기서는 **실제 봉투**가 필요하다.
    fn seed_plan_with_hint(state: &Path, run_id: &str, hint: serde_json::Value) {
        std::fs::create_dir_all(state.join("plan")).unwrap();
        // **손으로 중괄호를 escape 하지 않는다.** `format!` 로 JSON 을 짜면
        // `{{` 한 쌍이 어긋나도 파싱은 통과하고 필드만 조용히 빠진다 —
        // 실제로 그렇게 됐다.
        let json = serde_json::json!({
            "schema_version": 1,
            "kind": "remedy.plan",
            "run_id": run_id,
            "created": "2026-08-29T00:00:00Z",
            "host": { "hostname": "h", "os": "windows", "version": "10", "arch": "amd64" },
            "core": { "version": "1.0.0", "build": "t" },
            "plugins": [],
            // **`body` 로 감싸지 않는다.** 봉투가 `#[serde(flatten)]` 이라
            // 감싸면 통째로 무시되고 본문은 전부 기본값이 된다 — 파싱은
            // 통과하므로 조용하다. 실제로 그렇게 한 번 속았다.
            "actions": [],
            "verdicts": [],
            "observation": { "truncated": false, "denied_dirs": 0 },
            "submit_hint": hint,
        });
        std::fs::write(
            remedy_apply::plan_path(state, run_id),
            serde_json::to_string(&json).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn 제출_힌트가_계획을_타고_꾸러미까지_온다() {
        // **제출 기능은 제품에 없다** (설계-09 "제출을 제품 밖으로"). 그래서 이
        // 값은 자동 제출기가 아니라 이 꾸러미를 들고 올리는 사람이 본다.
        //
        // 계획이 나르는 이유: `support-bundle` 은 `--run` 만 받는다. 매니페스트를
        // 다시 찾게 만들면 그 경로는 있는데 쓰이지 않는 경로가 된다.
        let base = lab("hint");
        let state = base.join("state");
        seed(&state, "r1", false);
        seed_plan_with_hint(
            &state,
            "r1",
            serde_json::json!({ "samples": ["payload"], "confidentiality_min": 1 }),
        );

        let b = build(&state, "r1", &base.join("out")).expect("꾸러미");
        let h = b.submit_hint.as_ref().expect("힌트가 오지 않았다");
        assert_eq!(h.samples, vec!["payload".to_string()]);
        assert_eq!(h.confidentiality_min, Some(1));

        // README 가 그것을 사람에게 말해야 한다 — 구조체에만 있으면
        // 꾸러미를 받는 사람은 보지 못한다.
        let readme = std::fs::read_to_string(b.dir.join("README.txt")).unwrap();
        assert!(readme.contains("손으로 올릴 때"), "{readme}");
        assert!(readme.contains("payload"), "{readme}");
        assert!(readme.contains("대외비"), "{readme}");
    }

    #[test]
    fn 힌트가_없으면_그_절이_아예_나오지_않는다() {
        // **없는 것을 있는 척하지 않는다.** 빈 절이 있으면 받는 쪽은
        // "플러그인이 아무것도 안 남겼다" 와 "이 도구가 못 읽었다" 를 구분할 수
        // 없다.
        let base = lab("nohint");
        let state = base.join("state");
        seed(&state, "r1", false);

        let b = build(&state, "r1", &base.join("out")).expect("꾸러미");
        assert!(b.submit_hint.is_none());
        let readme = std::fs::read_to_string(b.dir.join("README.txt")).unwrap();
        assert!(!readme.contains("손으로 올릴 때"), "{readme}");
    }

    #[test]
    fn 계획과_저널과_환경을_담는다() {
        let base = lab("full");
        let state = base.join("state");
        seed(&state, "r1", true);

        let b = build(&state, "r1", &base.join("out")).expect("꾸러미");
        let names: Vec<&str> = b.included.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"plan.json"), "{names:?}");
        assert!(names.contains(&"journal.jsonl"), "{names:?}");
        assert!(names.contains(&"environment.json"), "{names:?}");

        // 실제로 파일이 있어야 한다 — 목록만 짓는 것이 아니다.
        for n in &names {
            assert!(b.dir.join(n).exists(), "{n} 이 없다");
        }
        assert!(b.dir.join("README.txt").exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn 봉인_키를_담지_않고_그_사실을_적는다() {
        // **이것이 이 모듈의 가장 위험한 자리다.** machine.key 가 새어 나가면
        // 격리 컨테이너를 누구나 열 수 있다.
        let base = lab("key");
        let state = base.join("state");
        seed(&state, "r1", true);

        let b = build(&state, "r1", &base.join("out")).expect("꾸러미");
        assert!(!b.dir.join("machine.key").exists(), "봉인 키가 담겼다");

        let readme = std::fs::read_to_string(b.dir.join("README.txt")).unwrap();
        assert!(readme.contains("machine.key"), "빠진 사실을 적지 않았다");
        // 사유는 두 언어다 — 라이브러리 시험은 영어로 돈다.
        assert!(
            readme.contains("어떤 경우에도 첨부하지 마십시오")
                || readme.contains("Never attach it"),
            "{readme}"
        );

        // 격리 컨테이너도 마찬가지다.
        assert!(!b.dir.join("r1.rq").exists());
        assert!(
            readme.contains("격리 컨테이너") || readme.contains("quarantine container"),
            "{readme}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn 없는_실행은_찾지_못했다고_적는다() {
        // 상태 디렉터리가 비어 있어도 **꾸러미는 만들어진다** — 환경 정보와
        // "무엇이 없었는지" 가 그 자체로 신고에 쓰이는 정보다.
        let base = lab("empty");
        let state = base.join("state");
        std::fs::create_dir_all(&state).unwrap();

        let b = build(&state, "없는실행", &base.join("out")).expect("꾸러미");
        let readme = std::fs::read_to_string(b.dir.join("README.txt")).unwrap();
        assert!(readme.contains("찾지 못한 것"), "{readme}");
        assert!(readme.contains("plan.json"), "{readme}");
        // 환경 정보는 언제나 담긴다.
        assert!(b.dir.join("environment.json").exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn 원본을_옮기거나_지우지_않는다() {
        // 신고를 보낸 뒤에도 이 기계에서 복구할 수 있어야 한다.
        let base = lab("keep");
        let state = base.join("state");
        seed(&state, "r1", true);

        build(&state, "r1", &base.join("out")).expect("꾸러미");
        assert!(
            remedy_apply::plan_path(&state, "r1").exists(),
            "원본이 사라졌다"
        );
        assert!(crate::restore::container_path(&state, "r1").exists());
        assert!(state.join("machine.key").exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn 경로가_될_수_없는_run_id_를_거부한다() {
        let base = lab("bad");
        for bad in ["", "../escape", "a/b", "a\\b", "C:x"] {
            assert!(
                build(&base, bad, &base).is_err(),
                "받아들이면 안 된다: {bad:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn 복구가_먼저라고_말한다() {
        // 설계-04 §6 의 순서가 복구 → 신고다. 첨부물을 만들면서 그 순서를
        // 뒤집어 말하면 사용자가 복구를 미룬다.
        let base = lab("order");
        let state = base.join("state");
        seed(&state, "r7", false);

        let b = build(&state, "r7", &base.join("out")).expect("꾸러미");
        let readme = std::fs::read_to_string(b.dir.join("README.txt")).unwrap();
        assert!(readme.contains("신고보다 복구가 먼저다"), "{readme}");
        assert!(readme.contains("restore --run r7"), "{readme}");

        let _ = std::fs::remove_dir_all(&base);
    }
}
