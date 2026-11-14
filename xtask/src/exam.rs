//! AI 합격 시험 채점 (설계-09 P11 · 설계-06 §10).
//!
//! # 무엇을 재는 시험인가
//!
//! 설계-09 P11 이 요구한 것은 *"고정 프롬프트 + 지정 위협 설명 → 룰 생성 →
//! `plugin lint` 통과 + 청정 코퍼스 0건. **누가 언제 돌려도 같은 절차**"* 다.
//!
//! **"같은 결과" 가 아니라 "같은 절차" 다.** 모델은 고정할 수 없다 — 판이 바뀌고,
//! 같은 판도 같은 답을 두 번 내지 않는다. 그래서 이것은 회귀 시험이 아니라
//! **관측 도구**다. 설계-06 §10 이 *"AI 가 무엇을 틀리는가가 관측되고, 그 관측이
//! 나머지 문서의 목차를 정한다"* 고 적은 그 관측이 여기서 나온다.
//!
//! # 채점이 사람 판단에 기대면 시험이 아니다
//!
//! 네 판정 전부 자동이다. 사람이 "이 정도면 괜찮다" 를 말하는 순간 그 시험은
//! 돌릴 때마다 다른 답을 낸다.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use remedy_sdk::manifest::PluginManifest;

/// 시험에 주입하는 가이드 파일 (고정). `testbed/ai-exam/inject.txt` 와 **같아야
/// 하고**, `xtask guide` 가 그것을 검사한다 — 문서와 코드가 갈라지면 "고정" 이
/// 말뿐이 된다.
///
/// **여기서 뺀 것도 고정의 일부다.** 첫 플러그인과 코퍼스는 정답이므로 넣지
/// 않는다. 목록을 바꾸면 그 회차는 다른 시험이고, 기록에 그렇게 적어야 한다.
pub const INJECT: &[&str] = &[
    "docs/plugin-guide/README.md",
    "docs/plugin-guide/00-invariants.md",
    "docs/plugin-guide/01-quickstart.md",
    "docs/plugin-guide/10-manifest.md",
    "docs/plugin-guide/20-detect-recipes.md",
    "docs/plugin-guide/22-remediate-recipes.md",
    "docs/plugin-guide/23-collect-and-submit.md",
    "docs/plugin-guide/30-antipatterns.md",
    "docs/plugin-guide/32-lint-errors.md",
    "docs/plugin-guide/31-nonexistent.md",
    "docs/plugin-guide/40-review-checklist.md",
    "docs/plugin-guide/machine/REFERENCE.md",
    "docs/plugin-guide/machine/catalog.json",
    "docs/plugin-guide/machine/subjects.json",
    "docs/plugin-guide/machine/ops.json",
    // **`machine/AI-CONTEXT.md` 는 넣지 않는다.** 그것은 "폴더 전체를 넣을 수
    // 없을 때 하나만 넣는 파일"(설계-06 §2)이라 전부 넣는 꾸러미에서는 같은
    // 내용이 두 번 들어갈 뿐이다.
    //
    // **2026-09-23 까지 그 말은 한 문장만큼 틀렸다.** `sshbd-r1` 답안이
    // `line | first_path` 에서 경로를 기대했다가 첫 공백 토큰을 받아 무너졌고,
    // 그 뜻(*"첫 공백 토큰"*)은 이 파일에만 있었다. 그날 AI-CONTEXT 의 주장
    // 열일곱을 꾸러미와 대조했더니 **열셋은 있고 capture 함수 절만 없었다.**
    // 그 문장을 `generate.rs` 의 상수 하나로 빼 `REFERENCE.md` 도 내게 했고,
    // 다시 대조하니 열여섯은 문장으로, 남은 하나(파이프 여러 단)는 예시로
    // 있다. **이 파일에만 있는 사실을 새로 만들면 이 판단을 다시 볼 것.**
    //
    // 예제 셋. **`artifacts.json` 은 넣지 않는다** — 스냅샷 값을 베끼면
    // 탐지가 아니라 받아쓰기가 된다.
    "docs/plugin-guide/examples/ex01-scheduled-task/plugin.yaml",
    "docs/plugin-guide/examples/ex01-scheduled-task/README.md",
    "docs/plugin-guide/examples/ex02-registry-ifeo/plugin.yaml",
    "docs/plugin-guide/examples/ex02-registry-ifeo/README.md",
    "docs/plugin-guide/examples/ex03-text-config/plugin.yaml",
    "docs/plugin-guide/examples/ex03-text-config/README.md",
];

/// **점검 위협의 꾸러미에만 더하는 파일** — 점검 룰(`kind: check`)의 규약과 실물이다. `unconfirmed` · 판 비교
/// 연산자 · `%FIXED_DISKS%` 는 이 파일들에만 있다. `testbed/ai-exam/inject-check.txt` 와 같아야 한다(`xtask guide`).
///
/// **치료 위협의 꾸러미에는 넣지 않는다**(2026-10-25 · 시험 README 의 '넣지 않는 것') — 치료 룰을 쓰게 하는 시험에서
/// 점검 전용의 "처치 절을 뺀다" 를 응시자 앞에 두면 오도가 된다. 그래서 위협 스무 개의 꾸러미는 그대로이고,
/// 점검 위협(2026-11-14 · `apache-h2`)이 생긴 날부터 그 꾸러미에만 실린다.
pub const INJECT_CHECK: &[&str] = &[
    "docs/plugin-guide/24-check-plugins.md",
    "docs/plugin-guide/examples/ex04-check-only/plugin.yaml",
    "docs/plugin-guide/examples/ex04-check-only/README.md",
];

/// 채점 결과. **숫자를 구조로 남긴다** — 출력만 하면 회귀 테스트가 그것을
/// 잡을 수 없고, 린트를 느슨하게 고쳤을 때 과거 회차가 조용히 통과한다.
pub struct Score {
    /// 매니페스트를 파싱하지 못했다. **그러면 나머지는 재지 못한다** — 0 으로
    /// 두면 "린트 오류 없음" 으로 읽히고, 파싱조차 안 되는 답이 그 항목만은
    /// 통과한 것처럼 보인다.
    ///
    /// 파싱 실패도 채점 결과의 하나다. `Err` 로 빠져나가면 그 회차를 기록에
    /// 남길 수 없고, 다음 회차가 같은 실수를 해도 대조할 것이 없다.
    pub parse_error: Option<String>,
    pub plugin_id: String,
    pub issues: Vec<remedy_sdk::lint::LintIssue>,
    pub lint_errors: usize,
    pub clean_total: usize,
    /// 청정 코퍼스가 이 답안의 **뿌리 규칙**에 들이민 레코드 수.
    ///
    /// 스냅샷 수(`clean_total`)는 사거리가 아니다. 같은 25장이라도 규칙이
    /// 12만 건을 걸러 낸 것과 한 건도 마주하지 않은 것은 뜻이 정반대인데,
    /// 스냅샷 수는 둘을 같은 문장으로 적는다.
    pub clean_records: usize,
    /// 청정 코퍼스에서 파괴가 난 스냅샷.
    pub dirty: Vec<String>,
    pub infected_total: usize,
    /// 감염 스냅샷인데 판정이 서지 않은 것.
    pub missed: Vec<String>,
    /// 감염 스냅샷인데 **guard 가 계획을 거부한** 것. 그 기계에서는 치료가 하나도
    /// 일어나지 않으므로 기대 Op 이 전부 `lacking` 에 든다. 이 칸은 그 까닭을
    /// 보인다 — 빠짐만 보면 규칙이 틀린 것과 계획이 막힌 것이 같은 줄이 된다.
    pub rejected: Vec<String>,
    pub expected_ops: usize,
    /// 감염 스냅샷에서 나온 Action **전부**의 수.
    ///
    /// `lacking`·`extra` 는 자리표의 **집합**으로 잰다. 그래서 같은 자리표가
    /// 두 번 나와도 접혀서 기대와 정확히 맞는다 — 2026-09-05 `hijack-r3` 이
    /// 그랬다. Action 14건 중 서로 다른 것이 8건인데 채점 4는 8건으로 읽고
    /// 빠짐 0으로 통과시켰다.
    ///
    /// 겹침이 위험하지는 않다. 실행기는 *"지울 것이 이미 없다"* 를 성공으로
    /// 다루므로(`remedy-apply`, 재기동 대비) 두 번째 시도는 아무 일도 하지
    /// 않는다. 그러나 **사람이 읽는 수가 틀린다** — 여덟 가지를 하는 계획이
    /// 열넷이라고 말하고, 그 뒤에 있는 설계 오해(한 감염을 그룹 둘로 팬아웃)가
    /// 보이지 않는다.
    ///
    /// 그래서 **막지 않고 보이게 한다.** 인스턴스 둘이 정말로 같은 값을
    /// 건드리는 경우를 상상할 수 있어, 오류로 만들면 늑대소년이 된다.
    pub planned_total: usize,
    /// 기대 목록에 있는데 계획에 없는 Op.
    pub lacking: Vec<String>,
    /// 계획에 있는데 기대 목록에 없는 Op. **불합격 사유가 아니다.**
    pub extra: Vec<String>,
}

impl Score {
    pub fn lint_warnings(&self) -> usize {
        self.issues.len() - self.lint_errors
    }

    /// 계획이 낸 **서로 다른** 자리표의 수.
    ///
    /// 집합을 따로 들고 다니지 않는다 — 기대와 빠짐·기대 밖에서 정확히
    /// 나온다. 기대 중 나온 것(`expected - lacking`)에 기대 밖을 더한 것이다.
    pub fn planned_distinct(&self) -> usize {
        self.expected_ops.saturating_sub(self.lacking.len()) + self.extra.len()
    }

    /// 같은 자리표가 몇 번 겹쳐 나왔는가. **불합격 사유가 아니다**
    /// (`planned_total` 문서 참조).
    pub fn duplicates(&self) -> usize {
        self.planned_total.saturating_sub(self.planned_distinct())
    }

    /// 불합격 사유. 비어 있으면 합격이다.
    pub fn failures(&self) -> Vec<String> {
        if let Some(e) = &self.parse_error {
            return vec![format!("매니페스트를 파싱하지 못했다 — {e}")];
        }
        let mut out = Vec::new();
        if self.lint_errors > 0 {
            out.push(format!("린트 오류 {}건", self.lint_errors));
        }
        if !self.dirty.is_empty() {
            out.push(format!("청정 코퍼스에서 파괴 {}건", self.dirty.len()));
        }
        if !self.missed.is_empty() {
            out.push(format!(
                "감염 스냅샷 {}건에서 판정이 서지 않는다",
                self.missed.len()
            ));
        }
        if !self.rejected.is_empty() {
            out.push(format!(
                "감염 스냅샷 {}건에서 guard 가 계획을 거부했다",
                self.rejected.len()
            ));
        }
        if !self.lacking.is_empty() {
            out.push(format!("계획에 빠진 Op {}건", self.lacking.len()));
        }
        out
    }

    pub fn passed(&self) -> bool {
        self.failures().is_empty()
    }
}

/// 한 답을 채점한다. **출력하지 않는다** — 회귀 테스트가 이것을 부른다.
pub fn score(root: &Path, dir: &Path, t: &Threat) -> Result<Score, String> {
    let manifest_path = dir.join("plugin.yaml");
    let text = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("{} 를 읽지 못했다: {e}", manifest_path.display()))?;
    let m: PluginManifest = match serde_yaml_ng::from_str(&text) {
        Ok(m) => m,
        Err(e) => {
            return Ok(Score {
                parse_error: Some(e.to_string()),
                plugin_id: "(파싱 실패)".into(),
                issues: Vec::new(),
                lint_errors: 0,
                clean_total: 0,
                clean_records: 0,
                dirty: Vec::new(),
                infected_total: 0,
                missed: Vec::new(),
                rejected: Vec::new(),
                expected_ops: 0,
                planned_total: 0,
                lacking: Vec::new(),
                extra: Vec::new(),
            })
        }
    };
    let rules = load_rules(dir)?;

    // ── 1. 린트 ──────────────────────────────────────────────
    let issues = remedy_sdk::lint(&m);
    let lint_errors = remedy_sdk::lint::blocking(&issues);

    // ── 2. 청정 코퍼스 (G1) ──────────────────────────────────
    let clean_dir = root.join("corpus").join("clean");
    let corpus = remedy_testkit::load_corpus(&clean_dir).map_err(|e| format!("{e}"))?;
    if corpus.is_empty() {
        // 비어 있으면 이 판정이 공허하게 통과한다.
        return Err(format!("{} 가 비어 있다", clean_dir.display()));
    }
    let mut dirty = Vec::new();
    // **스냅샷 수가 아니라 레코드 수가 사거리다.** "25개 중 파괴 0개" 는 그
    // 25장이 이 답안에 무엇을 들이밀었는지 말하지 않는다 — 뿌리 규칙이 12만
    // 건을 걸러 낸 것과 한 건도 마주하지 않은 것이 같은 문장이 된다
    // (2026-09-04 Windows 코퍼스 확장에서 드러났다).
    let mut clean_records = 0usize;
    for entry in &corpus {
        let artifacts = remedy_testkit::read_artifacts(&entry.path)
            .map_err(|e| format!("{}: {e}", entry.name))?;
        let scope = remedy_core::pipeline::scope_of(&artifacts);
        if m.platforms.contains(&scope.platform) {
            let snap = remedy_detect::Snapshot::from_envelope(&artifacts).with_rules(&rules);
            for p in remedy_detect::pressure(&snap, &m, &scope) {
                // 파생 규칙은 부모가 서지 않는 청정 환경에서 평가 자체가
                // 시작되지 않는다. 그 수를 더하면 사거리를 부풀린다.
                if !p.derived {
                    clean_records += p.records;
                }
            }
        }
        // **다른 플랫폼 스냅샷도 센다** — 제품의 G1(`remedy-core` tests/corpus.rs)이
        // 그렇다. 실행 시점에 `platforms` 로 거르는 곳이 없고 `%ALLUSERPROFILES%` 는
        // Linux 에서도 홈을 펼친다. 다만 **표시는 가른다** — 읽는 사람이 Windows
        // 답이 Windows 기계를 부순 줄로 읽지 않게 (2026-09-29 결정).
        let mark = if m.platforms.contains(&scope.platform) {
            String::new()
        } else {
            format!(" · {FOREIGN}({})", scope.platform.id())
        };
        let scan = remedy_core::pipeline::evaluate_with_rules(&artifacts, &m, &rules)
            .map_err(|e| format!("{}: 평가 실패 {e}", entry.name))?;
        let plan = match remedy_core::plan(&scan, Some(&m)) {
            Ok(p) => p,
            // **guard 가 거부한 계획도 채점 결과다.** 청정 기계에서 거부될 만큼
            // 부수려 한 것이므로 파괴로 센다. `?` 로 빠져나가면 채점이 멈추고 그
            // 회차를 기록할 수 없다 (2026-09-28 webshell-r1 사전 기준의 변형).
            Err(remedy_core::PipelineError::Plan(remedy_plan::PlanError::Guard(v))) => {
                dirty.push(format!("{} — guard 거부 {}{mark}", entry.name, joined(&v)));
                continue;
            }
            Err(e) => return Err(format!("{}: {e}", entry.name)),
        };
        if !remedy_testkit::is_clean(&plan) {
            dirty.push(format!(
                "{} — 파괴 Action {}건{mark}",
                entry.name,
                plan.body.actions.len()
            ));
        }
    }

    // ── 3·4. 점검 위협은 하네스가 잰다 ──────────────────────────
    // 감염 스냅샷도 기대 Op 도 없다. 여기서는 린트와 청정 코퍼스까지만 — 판정은 `t.harness` 가 실제 배포판에서
    // 잰다(`run` 이 그 명령을 적는다).
    if t.is_check() {
        return Ok(Score {
            parse_error: None,
            plugin_id: m.id.clone(),
            issues,
            lint_errors,
            clean_total: corpus.len(),
            clean_records,
            dirty,
            infected_total: 0,
            missed: Vec::new(),
            rejected: Vec::new(),
            expected_ops: 0,
            planned_total: 0,
            lacking: Vec::new(),
            extra: Vec::new(),
        });
    }

    // ── 3·4. 감염 스냅샷 ─────────────────────────────────────
    let infected = remedy_testkit::load_corpus(&t.infected_dir).map_err(|e| format!("{e}"))?;
    if infected.is_empty() {
        return Err(format!("{} 가 비어 있다", t.infected_dir.display()));
    }
    let mut missed = Vec::new();
    let mut rejected = Vec::new();
    let mut planned: BTreeSet<String> = BTreeSet::new();
    let mut planned_total = 0usize;
    for entry in &infected {
        let artifacts = remedy_testkit::read_artifacts(&entry.path)
            .map_err(|e| format!("{}: {e}", entry.name))?;
        let scan = remedy_core::pipeline::evaluate_with_rules(&artifacts, &m, &rules)
            .map_err(|e| format!("{}: 평가 실패 {e}", entry.name))?;
        if scan.body.verdicts.is_empty() {
            missed.push(entry.name.clone());
        }
        let plan = match remedy_core::plan(&scan, Some(&m)) {
            Ok(p) => p,
            // 감염 기계에서 거부되면 치료가 하나도 일어나지 않는다 — 기대 Op 이
            // 전부 빠진다. 까닭은 `rejected` 가 보인다 (2026-09-27 proxy-r1 사전
            // 기준의 변형).
            Err(remedy_core::PipelineError::Plan(remedy_plan::PlanError::Guard(v))) => {
                rejected.push(format!("{} — guard 거부 {}", entry.name, joined(&v)));
                continue;
            }
            Err(e) => return Err(format!("{}: {e}", entry.name)),
        };
        planned_total += plan.body.actions.len();
        planned.extend(plan.body.actions.iter().map(remedy_testkit::locator));
    }

    let expected = load_expected_ops(t)?;
    let lacking: Vec<String> = expected.difference(&planned).cloned().collect();
    let extra: Vec<String> = planned.difference(&expected).cloned().collect();

    Ok(Score {
        parse_error: None,
        plugin_id: m.id.clone(),
        issues,
        lint_errors,
        clean_total: corpus.len(),
        clean_records,
        dirty,
        infected_total: infected.len(),
        missed,
        rejected,
        expected_ops: expected.len(),
        planned_total,
        lacking,
        extra,
    })
}

/// 청정 코퍼스의 파괴가 **답의 `platforms` 밖** 스냅샷에서 났다는 표시.
const FOREIGN: &str = "다른 플랫폼";

/// guard 가 거부한 까닭을 한 줄로.
fn joined<T: std::fmt::Display>(v: &[T]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(" · ")
}

/// 시험 하나. **위협마다 채점 재료가 다르다** — 위협 설명 · 분석가 룰 ·
/// 감염 스냅샷 · 기대 Op.
///
/// # 왜 나누는가
///
/// 예제는 셋(예약 작업·레지스트리·설정 파일)인데 시험이 하나에 묶여 있으면
/// **나머지 둘이 가르치는 자리에 결함이 있어도 아무도 못 본다.** 그리고 감염
/// 스냅샷을 코퍼스에 몰아넣으면 첫 플러그인이 두 번째 위협을 탐지하지 못해
/// 자기 시험에서 떨어진다 — 위협이 다르니 당연한 일인데 채점은 그것을 실패로
/// 읽는다.
pub struct Threat {
    pub name: String,
    pub dir: PathBuf,
    /// 감염 스냅샷이 있는 곳. 위협 폴더에 `infected/` 가 있으면 그것,
    /// 없으면 저장소의 `corpus/infected/`.
    pub infected_dir: PathBuf,
    /// **점검 위협**이면 채점 하네스(저장소 상대 경로 · 위협 폴더의 `harness.txt` 첫 줄).
    ///
    /// 점검 룰은 아무것도 바꾸지 않으므로 감염 스냅샷 · 기대 Op 으로 잴 것이 없다. 갈라야 하는 것은 취약 ·
    /// 깨끗 · 확인 필요이고, 그것은 **실제 배포판에 깐 패키지**에서만 잴 수 있다 — 스냅샷에 판 문자열을
    /// 지어 넣으면 배포판의 판 비교(dpkg · rpm · apk)를 재지 못한다. 그래서 3 · 4 를 하네스가 맡는다.
    pub harness: Option<String>,
}

impl Threat {
    /// 점검 위협인가 — 꾸러미의 머리말 · 프롬프트와 채점이 갈린다.
    pub fn is_check(&self) -> bool {
        self.harness.is_some()
    }
}

/// 기본 위협. 인자를 주지 않으면 이것으로 돈다.
const DEFAULT_THREAT: &str = "evilai-locust";

/// 위협마다 **정답이 하나씩 있어야 한다.** 없으면 그 위협의 기대 Op 이
/// 도달 가능한지 아무도 모르고, 응시자만 떨어진다.
///
/// **`evilai-locust` 만 자리가 다르다.** 그것은 제품이 싣는 진짜 플러그인이고
/// 나머지 다섯은 시험 전용이다. 이 표가 그 사실을 담는 유일한 자리이므로
/// `examapply` 도 여기를 읽는다 — 위협 폴더만 뒤지면 evilai 가 **정답이 없는
/// 위협으로 보이고 조용히 면제된다** (2026-09-05 실측).
///
/// (위협, 정답 플러그인 경로)
pub const REFERENCES: &[(&str, &str)] = &[
    ("evilai-locust", "plugins/evilai-locust"),
    (
        "service-userinit",
        "testbed/ai-exam/threats/service-userinit/reference-plugin",
    ),
    (
        "ldso-preload",
        "testbed/ai-exam/threats/ldso-preload/reference-plugin",
    ),
    // 알려진 지표 목록(해시 · C2 도메인)으로 잡는 첫 위협 (2026-09-09).
    // `in` 연산자와 `indicator` 대상을 처음으로 밟는다 — 그 전까지 둘은
    // 엔진에만 있었고 어느 룰도 쓰지 않았다.
    (
        "c2-beacon",
        "testbed/ai-exam/threats/c2-beacon/reference-plugin",
    ),
    (
        "search-hijack",
        "testbed/ai-exam/threats/search-hijack/reference-plugin",
    ),
    (
        "tls-intercept",
        "testbed/ai-exam/threats/tls-intercept/reference-plugin",
    ),
    (
        "appinit-implant",
        "testbed/ai-exam/threats/appinit-implant/reference-plugin",
    ),
    // 리눅스 systemd 유닛을 처음 밟는 위협 (2026-09-21). 앞의 일곱은 서비스를
    // Windows 에서만 다뤘고, 리눅스 수집기(`systemd.rs`)와 쓰기 백엔드는 P12 에
    // 섰는데 그것을 밟는 위협이 없었다. 처음에는 **리눅스 Op 이 둘뿐**이었고
    // (`service.stop` · `service.clear_recovery` 는 `linux_from` 이 null), 계획기가
    // "이 계획은 치료의 전부가 아닙니다" 를 적었다. `service.stop` 은 2026-09-29 에
    // 열렸다(설계-09 P12 결정 A) — 남은 미룸은 `service.clear_recovery` 하나다.
    (
        "xmr-miner",
        "testbed/ai-exam/threats/xmr-miner/reference-plugin",
    ),
    // 리눅스 cron 을 처음 밟는 위협 (2026-09-21). 앞의 여덟은 지속성을 Windows
    // 예약 작업으로만 다뤘고, cron 수집기(`cron.rs`)는 P12 에 섰는데 그것을
    // 밟는 위협이 없었다. **넷이 서로를 되살린다** — cron 을 남기면 설정
    // 조각과 열쇠가 10분 뒤 돌아온다.
    //
    // **밟는 것은 판정 쪽이다.** cron 줄은 증거로만 쓰고 치료는 파일 격리로
    // 한다 — 까닭 둘은 그 위협의 `expected-ops.txt` 머리에 적었다.
    (
        "ssh-backdoor",
        "testbed/ai-exam/threats/ssh-backdoor/reference-plugin",
    ),
    // **`registry.delete_value` 를 처음 밟는 위협** (2026-09-21). 카탈로그의
    // Op 스물아홉 중 계획까지 되면서 아무 위협도 밟지 않은 마지막 자리였다 —
    // 나머지 다섯은 `derive.rs` 의 도달 불가 목록에 있다.
    //
    // 그보다 이 위협의 중심은 **지우면 안 되는 것**이다. 검체가 암호화한
    // 사용자 문서(`*.locked`)가 몸값 노트와 같은 폴더에 있고, 검체가 만든
    // 시각까지 같다. 자리로도 시각으로도 가를 수 없다.
    (
        "ransomware",
        "testbed/ai-exam/threats/ransomware/reference-plugin",
    ),
    // **해시 하나가 다섯 자리를 집는 위협** (2026-09-21). `c2-beacon` 도 해시로
    // 겨누지만 저쪽은 서로 다른 해시 여럿을 피드에서 받아 대조하는 쪽이고,
    // 이쪽은 하나의 해시가 이 기계에 여럿 있는 확산이다.
    //
    // 치료 대상이 최상위 디렉터리 **정확히 다섯**에 걸쳐 있다. G5 의
    // `distinct_top_dirs` 상한과 같은 수이고 `> 5` 에서 걸리므로 닿되
    // 통과한다 — 넘기는 쪽은 `guards.rs` 가 조작 입력으로 재고 있다.
    (
        "selfcopy-worm",
        "testbed/ai-exam/threats/selfcopy-worm/reference-plugin",
    ),
    // **`glob` 을 처음 쓰는 위협** (2026-09-21). 연산자 열둘 가운데 `glob` ·
    // `gt` · `lt` 셋이 한 번도 쓰이지 않았고, 이것이 `glob` 을 밟는다 —
    // 자리와 종류를 한 조건으로 묶을 수 있는 유일한 연산자다.
    //
    // 밟는 자리가 둘뿐인 까닭은 **웹셸이 파일 말고 아무것도 남기지 않기**
    // 때문이다. 자동 실행 등록도 서비스도 없다 — 웹 서버가 대신 실행한다.
    (
        "webshell-upload",
        "testbed/ai-exam/threats/webshell-upload/reference-plugin",
    ),
    // **`hosts` 를 Windows 에서 처음 밟는 위협** (2026-09-21). 리눅스 쪽
    // `tls-intercept` 가 `/etc/hosts` 를 밟고 있었지만 Windows 재료에는 그
    // 자리가 없었고, 그래서 채점기도 `line=` 매치를 볼 줄 몰랐다 — 같은 것을
    // 재는 두 하네스가 비대칭이었다. `Invoke-ExamApply.ps1` 에 그 검사를
    // 더하고 기존 Windows 위협 일곱을 다시 재어 회귀 0 을 확인했다.
    //
    // 검체가 바꾼 것 중 **하나는 그대로 두는 것이 맞다**(프록시 켜짐 플래그).
    // "검체가 바꾼 것은 전부 되돌린다" 가 틀리는 자리다.
    (
        "proxy-dns-hijack",
        "testbed/ai-exam/threats/proxy-dns-hijack/reference-plugin",
    ),
    // **`.lnk` 를 Windows 에서 처음 밟는 위협** (2026-09-21).
    // `shortcut.strip_args` 는 리눅스 쪽 `ldso-preload` 가 `.desktop` 으로만
    // 밟고 있었고, 그래서 Windows 채점기도 `args=` 매치를 볼 줄 몰랐다 —
    // `line=` 과 같은 부류의 비대칭이라 함께 닫았다.
    //
    // 지울 것이 바로가기가 아니다. 파일도 가리키는 곳도 남고 **덧붙은 인자만**
    // 떨어진다. 옆의 정상 바로가기 하나가 인자를 갖고 있어서, "인자가 있으면
    // 검체" 로 가르는 답안이 거기서 무너진다.
    (
        "shortcut-hijack",
        "testbed/ai-exam/threats/shortcut-hijack/reference-plugin",
    ),
    // **`registry.delete_value` 를 두 번째로 밟는 위협** (2026-09-21).
    // `ransomware` 가 처음 밟았고(작업 관리자 잠금), 여기서는 인증 공급자
    // 설정의 값 하나다. 검체가 새로 만든 값이라 지우면 청정 기준과 같아진다.
    //
    // 중심은 **키가 아니라 값 하나를 겨누는가**다. 같은 키에 배포판이 넣어 둔
    // 값 다섯이 함께 사는데(그중 둘이 `must-remain.txt` 에 있다), 자리째
    // 겨누는 답안은 다섯을 함께 지우고 인증 구성을 망가뜨린다. 그리고 덤프
    // 파일은 안에 사용자의 자격 증명이 있어도 치운다 — `ransomware` 의
    // `*.locked` 와 정반대로, 가르는 것은 **누가 만든 파일인가**다.
    (
        "cred-dump",
        "testbed/ai-exam/threats/cred-dump/reference-plugin",
    ),
    // **`registry_key` subject 를 처음 밟는 위협** (2026-09-21). subject 열여덟
    // 가운데 어느 위협도 쓰지 않은 둘 중 하나였다 (나머지 하나 `boot_config` 는
    // 대상을 지목할 수 없어 치료가 닿지 않는다 — `NOT_PLANNABLE_YET`).
    //
    // **증거인 것과 치울 것이 다르다.** 검체가 만든 것은 키 하나이고 그 존재가
    // 판정의 근거인데, `registry.delete_key` 는 G6 가 예외 없이 거부하므로
    // (`PLANNED_BUT_GUARDED`) 키를 겨눈 답안은 계획이 통째로 거부된다. 치료는
    // 그 안의 값 둘·파일 둘·자동 실행 하나다.
    //
    // **`base64_decode` 를 처음 쓴다.** capture 함수 여덟 중 `first_path` 와
    // `dirname` 둘만 쓰이고 있었다. 파일 경로가 값에 감춰져 있어 풀지 않으면
    // 닿지 못하고, 옆의 정상 키도 같은 방식으로 적어 **모양으로는 가를 수
    // 없다** — `expand_env` 는 아직 평가할 수 없어(수집 시점 환경이 스냅샷에
    // 없다) 이 자리에 쓰지 않았다.
    (
        "regkey-stager",
        "testbed/ai-exam/threats/regkey-stager/reference-plugin",
    ),
    // **`gt` 와 `lt` 를 처음 밟는 위협** (2026-09-22). 이로써 **그때의** 연산자
    // 열둘이 전부 어느 위협에든 쓰였다 — `ransomware` 가 Op 축을 닫은 것과 같은
    // 자리다. 2026-10-27 에 `version_lt`·`version_gt` 가 더해져 14 가 됐고, 그
    // 둘은 로스터 밖이다 — 버전을 담는 필드가 하나뿐이라 위협 픽스처로 세울
    // 자리가 없다(구조 설계 C-1b).
    //
    // **두 성질을 함께 보아야 갈린다.** 한 폴더에 파일 다섯이 있고 둘만
    // 검체인데, 자리도 이름꼴도 같아서 가르는 것은 주 실행 파일에 대한 상대
    // 비교뿐이다. 조건 하나만 쓰면 정상 파일이 걸린다는 것을 반증 실험으로
    // 확인했다(시각만 → `core.dll`, 크기만 → `ui.dll`. 둘 다
    // `must-remain.txt` 에 있다).
    //
    // **비교의 오른쪽이 상수가 아니다.** `${baseline.when}` · `${baseline.bulk}`
    // 로 그 기계에서 뽑는다 — 절대 시각과 바이트 수는 기계마다 다르다.
    (
        "sideload-drop",
        "testbed/ai-exam/threats/sideload-drop/reference-plugin",
    ),
    // **분석가 룰을 시험에서 처음 밟는 위협** (2026-09-22). `yara` 술어와
    // 위협 폴더의 `rules/*.yar` 주입 경로는 그때까지 제품 플러그인
    // (`evilai-locust`) 하나만 쓰고 있었고, 시험 전용 위협은 하나도 없었다.
    //
    // **내용으로만 갈린다.** 훅 폴더의 스크립트 셋이 같은 확장자에 **같은
    // 시각**이고 크기도 39 바이트 안이며, 로그온 항목에 걸린 것이 둘이다
    // (하나는 벤더의 정상 항목). 앞선 회차들의 잣대가 전부 통하지 않는다 —
    // 룰 술어를 빼면 계획이 Action 2 에서 4 로 늘며 정상 파일과 정상 자동
    // 실행을 함께 지운다(반증 실험).
    //
    // **본문이 담겨야 룰이 돈다.** 수집은 `collect_extra` 의 경로 형으로
    // 담고(`collect` 는 증거 참조를 풀지 않는다), 정답은 실기기에서 옳은
    // 참조 형(`{ref: hooks, content: true}`)을 쓴다. 그 `hooks` 규칙은 본문
    // 없이 매치돼야 하므로 경로로만 맞히고, 치료 대상이 아니다.
    (
        "hook-implant",
        "testbed/ai-exam/threats/hook-implant/reference-plugin",
    ),
    // **`structured_config` 를 리눅스에서 처음 밟는 위협** (2026-09-22). 그
    // subject 는 Windows 의 `appinit-implant` 하나만 쓰고 있었고, 그래서
    // **리눅스 채점기가 `key_path=` 매치를 볼 줄 몰랐다** — `line=`·`args=` 와
    // 같은 부류의 비대칭이라 이 회차에 닫았다. 이제 네 매치 종류를 두 하네스가
    // 모두 본다(리눅스 위협 여섯을 다시 재어 회귀 0 을 확인했다).
    //
    // **항목 이름으로 가르면 안 된다.** 설치 훅은 정상 패키지가 흔히 쓰는
    // 자리이고 옆 패키지도 같은 키를 갖는다 — 값 조건을 빼면 계획이 그
    // 정상 패키지의 설정까지 고친다(반증 실험).
    //
    // 파일을 치우지 않고 **키 하나만** 뺀다. 같은 파일의 벤더 항목 다섯이
    // 그대로인지는 `key_path=` 가 실기기에서 잰다.
    (
        "npm-posthook",
        "testbed/ai-exam/threats/npm-posthook/reference-plugin",
    ),
    // **capture 함수 셋을 한 사슬로 처음 밟는 위협** (2026-09-22).
    // `hex_decode` · `basename` · `lower` 는 여덟 함수 중 마지막까지 쓰이지
    // 않은 셋이었다(`expand_env` 는 구조적으로 막혀 있다 — `ExprError::later`).
    //
    // **셋이 전부 일한다.** 하나씩 빼고 같은 스냅샷에서 계획을 뜨면 **판정 0 ·
    // Action 0** 이 된다 — 값을 풀지 못하거나(hex), 목록의 이름과 견줄 수
    // 없거나(basename), 표기가 달라 닿지 못한다(lower).
    //
    // **`lower` 는 리눅스에서만 뜻이 있다.** `norm_for_compare` 가 Windows 에서만
    // 대소문자를 접으므로, 같은 설계를 Windows 에 두면 그 함수가 잉여가 된다.
    (
        "hexcfg-loader",
        "testbed/ai-exam/threats/hexcfg-loader/reference-plugin",
    ),
    // **처음 재는 점검 위협** (2026-11-14). 정답은 제품이 싣는 룰이다 — `evilai-locust` 처럼. 여기서 재는 것은
    // 린트와 청정 코퍼스까지이고, 판정(취약 · 깨끗 · 확인 필요)은 위협의 `harness.txt` 가 가리키는 하네스 55칸이
    // 실제 배포판에서 잰다. 실기기 치료 게이트(`examapply`)는 점검 위협을 건너뛴다 — 바꾸는 것이 없다.
    ("apache-h2", "plugins/apache-http2-check-linux"),
];

pub fn threat(root: &Path, name: &str) -> Result<Threat, String> {
    let dir = root.join("testbed/ai-exam/threats").join(name);
    if !dir.join("THREAT.md").exists() {
        let known = threat_names(root).join(" · ");
        return Err(format!(
            "위협 '{name}' 이 없다 (있는 것: {known})\n  {}",
            dir.display()
        ));
    }
    // 위협 전용 스냅샷이 있으면 그것만 본다. **코퍼스 전체를 돌리면 다른
    // 위협의 스냅샷에서 판정이 안 서고, 그것을 미탐으로 읽는다.**
    let own = dir.join("infected");
    let infected_dir = if own.is_dir() {
        own
    } else {
        root.join("corpus").join("infected")
    };
    // 하네스를 적었는데 그 파일이 없으면 멈춘다 — 조용히 치료 위협으로 채점하면 감염 스냅샷이 없어 엉뚱한
    // 실패가 난다.
    let harness = match std::fs::read_to_string(dir.join("harness.txt")) {
        Err(_) => None,
        Ok(text) => {
            let h = text
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with('#'))
                .ok_or_else(|| format!("{name}/harness.txt 가 비어 있다"))?
                .to_string();
            if !root.join(&h).is_file() {
                return Err(format!("{name}/harness.txt 의 하네스가 없다: {h}"));
            }
            Some(h)
        }
    };
    Ok(Threat {
        name: name.to_string(),
        dir,
        infected_dir,
        harness,
    })
}

pub fn threat_names(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root.join("testbed/ai-exam/threats")) {
        for e in rd.flatten() {
            if e.path().join("THREAT.md").exists() {
                out.push(e.file_name().to_string_lossy().to_string());
            }
        }
    }
    out.sort();
    out
}

fn threat_arg(args: &[String]) -> &str {
    args.iter()
        .position(|a| a == "--threat")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .unwrap_or(DEFAULT_THREAT)
}

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "--list-inject") {
        let mut total = 0u64;
        for p in INJECT {
            let full = root.join(p);
            let n = std::fs::metadata(&full).map(|m| m.len()).unwrap_or(0);
            total += n;
            println!("{p}");
        }
        eprintln!("\n{}개 · {} KB", INJECT.len(), total / 1024);
        return Ok(());
    }

    if args.iter().any(|a| a == "--bundle") {
        // **stdout 으로 내보내지 않는다.** 셸이 그 바이트를 세 번 손댄다 —
        // 콘솔 코드페이지로 디코드(CP949 면 한글이 깨진다) · 리다이렉트 기본
        // 인코딩으로 재인코딩(BOM · UTF-16) · 줄 단위 재작성(LF → CRLF).
        //
        // 실측: 같은 명령이 Bash 에서 93,884 바이트, PowerShell 에서 96,405
        // 바이트를 냈다. **셸을 바꾸면 응시자가 받는 입력이 달라진다** — 그러면
        // "누가 언제 돌려도 같은 절차" 가 성립하지 않는다.
        //
        // `fs::write` 는 바이트를 그대로 쓴다. 셸이 개입할 자리가 없다.
        let out = args
            .iter()
            .position(|a| a == "--out")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("testbed/ai-exam/exam-bundle.txt"));
        let _ = &out;
        let text = bundle(root, &threat(root, threat_arg(args))?)?;
        std::fs::write(&out, text.as_bytes())
            .map_err(|e| format!("{} 에 쓰지 못했다: {e}", out.display()))?;
        println!(
            "꾸러미 {} KB → {}\n  새 대화에 이 파일을 통째로 붙인다",
            text.len() / 1024,
            out.display()
        );
        return Ok(());
    }

    let dir = args
        .iter()
        .position(|a| a == "--dir")
        .and_then(|i| args.get(i + 1))
        .ok_or_else(|| USAGE.to_string())?;
    let dir = PathBuf::from(dir);

    let t = threat(root, threat_arg(args))?;
    let s = score(root, &dir, &t)?;
    println!(
        "채점 대상: {} ({})\n위협: {}",
        s.plugin_id,
        dir.display(),
        t.name
    );
    println!();

    if let Some(e) = &s.parse_error {
        // **린트 전에 걸린 것이다.** 알 수 없는 키는 무시가 아니라 거부이고,
        // 절이 틀린 항목도 여기서 멈춘다.
        println!("  파싱 실패 :: {e}");
        println!();
        return Err(format!("불합격 — {}", s.failures().join(" · ")));
    }

    if s.lint_errors > 0 {
        for i in &s.issues {
            println!("    {} :: {}", i.at, i.message);
        }
    }
    println!(
        "  1. 린트          오류 {} · 경고 {}",
        s.lint_errors,
        s.lint_warnings()
    );
    if s.lint_warnings() > 0 && s.lint_errors == 0 {
        // **경고는 불합격이 아니다.** 서명 단계에서 사람이 확인하는 자리이고
        // (설계-06 §7), 여기서 막으면 작성자가 경고를 끄는 법부터 배운다.
        for i in s
            .issues
            .iter()
            .filter(|i| remedy_sdk::lint::blocking(std::slice::from_ref(i)) == 0)
        {
            println!("       경고 {} :: {}", i.at, i.message);
        }
    }

    for d in &s.dirty {
        println!("    {d}");
    }
    // 다른 플랫폼의 파괴도 파괴다(G1 과 같다). 몇 개가 그쪽인지만 덧붙인다.
    let foreign = s.dirty.iter().filter(|d| d.contains(FOREIGN)).count();
    println!(
        "  2. 청정 코퍼스   {}개 중 파괴 {}개{} (뿌리 규칙이 마주한 레코드 {}건)",
        s.clean_total,
        s.dirty.len(),
        if foreign > 0 {
            format!(" — 그중 {FOREIGN} {foreign}개")
        } else {
            String::new()
        },
        s.clean_records
    );

    // **점검 위협은 판정을 여기서 재지 않는다** — 감염 스냅샷이 없고, 취약 · 깨끗 · 확인 필요는 실제 배포판에 깐
    // 패키지에서만 잰다. 재지 않은 것을 초록으로 적지 않도록 하네스 명령을 남긴다.
    if let Some(h) = &t.harness {
        println!(
            "  3. 판정          여기서 재지 않는다 — 점검 위협은 하네스가 실제 배포판에서 잰다"
        );
        println!("       bash {h} --bin <musl 정적 개발 빌드> \\");
        println!(
            "           --plugins <이 답을 `{}/` 로 두고 개발 키로 서명한 폴더>",
            s.plugin_id
        );
        println!();
        if s.passed() {
            println!("린트 · 청정 코퍼스 통과 — 판정은 위 하네스로 마저 잰다");
            return Ok(());
        }
        return Err(format!("불합격 — {}", s.failures().join(" · ")));
    }

    for x in &s.missed {
        println!("    {x}");
    }
    println!(
        "  3. 감염 탐지     {}개 중 판정 {}개",
        s.infected_total,
        s.infected_total - s.missed.len()
    );

    for x in &s.rejected {
        println!("    {x}");
    }
    for x in &s.lacking {
        println!("    빠짐 {x}");
    }
    // **겹침은 있을 때만 말한다.** 늘 붙이면 0 이라는 글자가 스물세 회차에
    // 걸쳐 반복되고, 그러면 정작 있을 때 눈에 띄지 않는다.
    let dup = s.duplicates();
    let dup_note = if dup > 0 {
        format!(" · 계획 {}건 중 겹침 {dup}건", s.planned_total)
    } else {
        String::new()
    };
    println!(
        "  4. 계획 완결성   기대 {}건 중 빠짐 {}건{}{dup_note}",
        s.expected_ops,
        s.lacking.len(),
        if s.extra.is_empty() {
            String::new()
        } else {
            format!(" · 기대 밖 {}건 (불합격 아님)", s.extra.len())
        }
    );
    for x in &s.extra {
        println!("       기대 밖 {x}");
    }

    // **여기가 재지 않는 것을 여기서 말한다.**
    //
    // 네 판정은 전부 계획까지만 잰다. 계획이 서고 실행에서 거부되거나 조용히
    // 아무것도 하지 않는 Action 은 어느 판정에도 걸리지 않는다 — 2026-09-05
    // 하루에 그 틈으로 결함 셋이 지나갔다(`REG_MULTI_SZ` 거부 · `strip` needle 의
    // 구분자 · 대상 겹침). 셋 다 여기서 초록이었다.
    //
    // 이 줄이 없으면 "네 판정 통과" 가 "치료가 된다" 로 읽힌다. 재지 않은 것을
    // 말하지 않는 초록이 이 저장소가 계속 잡아 온 실패다.
    println!("  5. 실기기 치료   여기서 재지 않는다 — 랩 기계가 필요하다");
    // **위협마다 도는 곳이 다르다.** Windows 는 VM 이고 Linux 는 컨테이너다.
    // 잘못된 명령을 적어 두면 아무도 돌리지 않는다.
    if root
        .join("testbed/harness/linux/threats")
        .join(format!("{}-collect.yaml", t.name))
        .exists()
    {
        println!(
            "       testbed/harness/linux/invoke-exam-apply.sh --threat {} \\",
            t.name
        );
        println!("           --plugin <이 플러그인의 저장소 상대 경로>");
    } else {
        println!(
            "       testbed/harness/host/Invoke-ExamApply.ps1 -Threat {} \\",
            t.name
        );
        println!("           -Plugin <이 플러그인> -Revert");
    }

    println!();
    if s.passed() {
        println!("합격 — 네 판정을 전부 통과했다");
        if s.lint_warnings() > 0 {
            println!(
                "  다만 경고 {}건이 남아 있다. 서명 단계에서 각각의 이유를 \
                 설명해야 한다 (설계-06 §8)",
                s.lint_warnings()
            );
        }
        Ok(())
    } else {
        Err(format!("불합격 — {}", s.failures().join(" · ")))
    }
}

const USAGE: &str = "사용법: cargo xtask exam --dir <플러그인 디렉터리>
      cargo xtask exam --list-inject
      cargo xtask exam --bundle [--out <파일>]
      두 명령 모두 --threat <이름> 을 받는다 (기본: evilai-locust)";

/// 감염 스냅샷에서 **반드시 나와야 하는 Op** (설계-09 P11).
///
/// `testbed/ai-exam/expected-ops.txt` 에 한 줄에 하나씩 둔다. 고정되는 것
/// 중 하나이므로 바꾸면 그 회차는 다른 시험이고, 기록에 그렇게 적어야 한다.
///
/// **첫 플러그인이 이 목록을 만족하는지는 `xtask guide` 가 강제한다** — 정답이
/// 자기 채점 기준을 못 넘기면 그 기준이 틀린 것이다.
fn load_expected_ops(t: &Threat) -> Result<BTreeSet<String>, String> {
    let p = t.dir.join("expected-ops.txt");
    let text =
        std::fs::read_to_string(&p).map_err(|e| format!("{} 를 읽지 못했다: {e}", p.display()))?;
    let set: BTreeSet<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    if set.is_empty() {
        return Err(format!(
            "{} 가 비어 있다 — 4 번 판정이 공허해진다",
            p.display()
        ));
    }
    // **대상이 없는 줄은 받지 않는다.** 2026-09-04 까지 이 파일은 Op 이름만
    // 적었고, 그래서 `registry.delete_value` 한 줄이 "그 종류가 하나라도
    // 있으면 통과" 를 뜻했다. 절반짜리 치료가 그 틈으로 지나갔다.
    //
    // 옛 모양을 조용히 받아 주면 위협마다 느슨한 줄이 남고, 어느 줄이 조이고
    // 어느 줄이 느슨한지 아무도 모르게 된다. 그래서 **오류로 막는다.**
    let bare: Vec<&String> = set.iter().filter(|l| !l.contains(' ')).collect();
    if !bare.is_empty() {
        return Err(format!(
            "{} 에 대상 없이 Op 이름만 적힌 줄이 있다: {}\n\
             `<op> <대상>` 또는 `<op> <대상> :: <k>=<v>` 로 적을 것 — Op 종류만 \
             세면 값 하나만 지운 답과 둘 다 지운 답이 구별되지 않는다.\n\
             정답 플러그인의 계획에서 그대로 옮기면 된다.",
            p.display(),
            bare.iter()
                .map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(" · ")
        ));
    }

    // 오타 난 Op 이름은 영영 "빠짐" 으로 나와 아무도 통과하지 못한다.
    let unknown: Vec<&str> = set
        .iter()
        .filter_map(|l| l.split(' ').next())
        .filter(|n| remedy_sdk::catalog::Op::ALL.iter().all(|o| o.id() != *n))
        .collect();
    if !unknown.is_empty() {
        return Err(format!(
            "{} 에 카탈로그에 없는 Op 이 있다: {}",
            p.display(),
            unknown.join(" · ")
        ));
    }
    Ok(set)
}

/// 응시 꾸러미를 조립한다 — 주입 파일 + 분석가 룰 + 프롬프트 한 덩어리.
///
/// # 왜 기계가 조립하는가
///
/// 절차는 사람이 17 개 조각을 순서대로 붙이라고 말한다. **조립 실수가 곧 회차
/// 오염이다** — 파일 하나를 빠뜨리면 그 회차는 다른 시험이 되는데, 사람은
/// 그것을 눈치채지 못한다. 그리고 이 시험은 모델이 바뀔 때마다 다시 돌려야
/// 가치가 있으므로, 한 번은 할 수 있어도 반복되지 않는 절차는 절차가 아니다.
///
/// # 출제자 주의는 응시자에게 가지 않는다
///
/// `PROMPT.md` 와 `THREAT.md` 의 구분선 위쪽은 **출제 메모**다. 거기에는
/// "1 회차가 이렇게 무너졌다" 같은 문장이 있고, 그것을 응시자가 보면 힌트가
/// 된다. 구분선 아래만 취한다.
/// 꾸러미 맨 앞에 붙는 맥락.
///
/// # 왜 이것이 있는가
///
/// 2026-09-04 `appinit-r3` 회차에서 Opus 5 가 꾸러미를 안전장치 분류기가 막았다.
/// 응시자를 4.8 로 내려서 돌렸고, 그 사실을 회차 기록에 남겼다.
///
/// 꾸러미는 그때까지 **규격 문서 → 위협 관측 보고** 순으로 시작했다. 읽는
/// 쪽에서 보면 첫 만 자가 침해 지표와 지속성 기법 설명이고, **무엇을 만들라는
/// 것인지가 한참 뒤에 나온다.** 분류기가 그것을 공격 자료로 읽은 것이 이상한
/// 일이 아니다.
///
/// 그래서 **없던 사실을 앞에 적는다.** 우회가 아니라 누락을 메우는 것이다 —
/// 아래 문장은 전부 이 저장소에서 확인된다:
///
/// - 산출물은 **선언형 YAML** 하나다. 플러그인은 코드를 싣지 않고, 코어가
///   닫힌 연산 29종만 해석한다 (`catalog.rs` 의 `Op::ALL`).
/// - 읽기는 `scan_roots` 상한 안으로 제한되고, 삭제는 전부 격리 컨테이너로
///   되돌릴 수 있다 (설계-03).
/// - 위협 설명은 **격리된 실험용 VM** 에서 뜬 관측 보고이고, 그 안의 페이로드는
///   크기만 맞춘 무해한 자리 채우기다 (`THREAT.md` 의 출제자 주의).
/// - 채점의 절반이 **정상 데이터를 부수지 않았는가**다.
///
/// 이 글이 꾸러미 크기에 더하는 것은 1 KB 남짓이고, `INJECT` 의 문서를 하나도
/// 바꾸지 않는다. **"누가 언제 돌려도 같은 절차" 는 유지된다** — 이 머리말도
/// 고정이고, 바꾸면 그 회차는 다른 시험이므로 기록에 적어야 한다.
const HEADER: &str = "\
# 이 요청에 대하여 — 방어 목적 보안 도구의 규칙 작성

`remedy` 는 이스트시큐리티가 만드는 **전용백신**(dedicated antivirus)이다.
감염된 기계에서 악성 항목을 찾아 **지우고 되돌리는** 방어 도구이고, 이
요청은 그 도구가 읽을 **탐지·치료 규칙 하나를 작성하는 일**이다.

무엇을 만드는지 먼저 밝힌다.

- 산출물은 **선언형 YAML 파일 하나**다. 플러그인은 코드를 싣지 않는다 —
  코어가 미리 정해 둔 연산 29종만 해석하고, 그 밖의 것은 할 수 없다.
- 읽을 수 있는 범위는 규칙이 스스로 선언한 경로 상한(`scan_roots`) 안뿐이다.
  그것은 성능 설정이 아니라 **권한 상한**이다.
- 지우는 것은 전부 격리 컨테이너에 담겨 **되돌릴 수 있다.**
- 아래 위협 설명은 **격리된 실험용 가상 기계**에 감염 상태를 세우고 관측한
  보고다. 거기 쓰인 페이로드는 크기만 맞춘 **무해한 자리 채우기**이며 실제
  악성코드가 아니다. 공격 코드도, 취약점도, 회피 기법도 이 문서에 없다.
- 채점의 절반은 **정상 데이터를 부수지 않았는가**를 본다. 정상 프로그램의
  설정과 같은 자리에 있는 악성 항목만 정확히 골라내는 것이 이 과제의 핵심이다.

---

";

/// 점검 위협의 머리말. `HEADER` 는 치료 규칙과 감염 기계의 관측 보고를 말하므로 점검 위협에는 틀린다 —
/// 점검 규칙은 아무것도 바꾸지 않고, 위협 설명은 공지와 배포판 보안 추적기를 읽은 보고다. 이것도 고정이다.
const HEADER_CHECK: &str = "\
# 이 요청에 대하여 — 방어 목적 보안 도구의 점검 규칙 작성

`remedy` 는 이스트시큐리티가 만드는 **전용백신**(dedicated antivirus)이다. 이
요청은 그 도구가 읽을 **취약점 점검 규칙 하나를 작성하는 일**이다 — 기계에 깔린
소프트웨어가 공지된 취약 판인지, 고쳐졌는지를 가린다.

무엇을 만드는지 먼저 밝힌다.

- 산출물은 **선언형 YAML 파일 하나**다. 플러그인은 코드를 싣지 않는다 —
  코어가 미리 정해 둔 관찰 대상과 연산자만 해석하고, 그 밖의 것은 할 수 없다.
- 읽을 수 있는 범위는 규칙이 스스로 선언한 경로 상한(`scan_roots`) 안뿐이다.
  그것은 성능 설정이 아니라 **권한 상한**이다.
- 점검 규칙은 **아무것도 바꾸지 않는다** — 읽고 판정만 한다.
- 아래 위협 설명은 공급사 공지와 배포판 보안 추적기를 읽고 쓴 보고다. 공격
  코드도, 악용 방법도 이 문서에 없다.
- 채점은 실제 배포판에 깐 패키지에서 **고친 기계를 취약으로 내지 않는가 ·
  모르는 것을 깨끗하다고 하지 않는가**를 본다.

---

";

pub fn bundle(root: &Path, t: &Threat) -> Result<String, String> {
    let mut s = String::new();

    // 점검 위협은 머리말과 프롬프트가 다르다 — 위협 스무 개의 회차가 `PROMPT.md` 의 글자에 묶여 있어 고치지
    // 않고 따로 둔다(`PROMPT-check.md` 의 출제 메모).
    let (header, prompt_file) = if t.is_check() {
        (HEADER_CHECK, "PROMPT-check.md")
    } else {
        (HEADER, "PROMPT.md")
    };
    s.push_str(header);

    s.push_str(
        "아래는 `remedy` 전용백신의 플러그인 규격 문서 전부다. \
         파일마다 경로를 함께 적었다.\n\n",
    );

    let extra: &[&str] = if t.is_check() { INJECT_CHECK } else { &[] };
    for rel in INJECT.iter().chain(extra) {
        let p = root.join(rel);
        let body = std::fs::read_to_string(&p)
            .map_err(|e| format!("{} 를 읽지 못했다: {e}", p.display()))?;
        s.push_str(&file_block(rel, &body));
    }

    // 분석가 제공물. **응시자가 놓을 자리 이름으로 적는다** — 출제 폴더의
    // 경로를 그대로 주면 답이 그 경로를 참조하려 든다.
    // 위협 폴더의 `rules/*.yar` 을 전부 싣는다. 없는 위협도 있다.
    if let Ok(rd) = std::fs::read_dir(t.dir.join("rules")) {
        let mut files: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "yar"))
            .collect();
        files.sort();
        for p in files {
            let body = std::fs::read_to_string(&p)
                .map_err(|e| format!("{} 를 읽지 못했다: {e}", p.display()))?;
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            s.push_str(&file_block(&format!("rules/{name}"), &body));
        }
    }

    let prompt = std::fs::read_to_string(root.join("testbed/ai-exam").join(prompt_file))
        .map_err(|e| format!("{prompt_file} 를 읽지 못했다: {e}"))?;
    let threat = std::fs::read_to_string(t.dir.join("THREAT.md"))
        .map_err(|e| format!("{}/THREAT.md 를 읽지 못했다: {e}", t.name))?;

    let prompt_body = between_rules(prompt_file, &prompt, 2)?;
    let threat_body = between_rules("THREAT.md", &threat, 1)?;

    // 룰이 없는 위협에서는 룰 관련 문단을 뺀다. **남겨 두면 응시자가 오지도
    // 않은 파일을 찾는다.**
    let prompt_body = strip_rule_block(&prompt_body, s.contains("파일: rules/"));
    if !prompt_body.contains(THREAT_SLOT) {
        return Err(format!(
            "{prompt_file} 본문에 {THREAT_SLOT} 자리가 없다 — 위협 설명을 넣을 곳이 사라졌다"
        ));
    }
    s.push_str(prompt_body.replace(THREAT_SLOT, threat_body.trim()).trim());
    s.push('\n');
    Ok(s)
}

/// `{{THREAT}}` — 위협 설명이 들어가는 자리.
/// `{{IF_RULES}}`…`{{END_RULES}}` 처리. 룰이 있으면 마커만 지우고, 없으면
/// 그 사이를 통째로 뺀다.
fn strip_rule_block(text: &str, keep: bool) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find("{{IF_RULES}}") {
        out.push_str(&rest[..i]);
        let after = &rest[i + "{{IF_RULES}}".len()..];
        let Some(j) = after.find("{{END_RULES}}") else {
            // 짝이 없으면 그대로 둔다 — 조용히 삼키면 프롬프트가 잘린다.
            out.push_str(&rest[i..]);
            return out;
        };
        if keep {
            out.push_str(&after[..j]);
        }
        rest = &after[j + "{{END_RULES}}".len()..];
    }
    out.push_str(rest);
    out
}

const THREAT_SLOT: &str = "{{THREAT}}";

fn file_block(rel: &str, body: &str) -> String {
    let bar = "─".repeat(60);
    format!("{bar}\n파일: {rel}\n{bar}\n\n{}\n\n", body.trim_end())
}

/// 구분선(`---`) 사이를 꺼낸다.
///
/// **개수를 검사한다.** 나중에 누가 문서에 구분선을 하나 더 넣으면 조용히
/// 엉뚱한 데서 잘리고, 그러면 응시자가 받는 프롬프트가 달라진다 — 그 회차는
/// 다른 시험인데 아무도 모른다.
fn between_rules(name: &str, text: &str, want: usize) -> Result<String, String> {
    let lines: Vec<&str> = text.lines().collect();
    let marks: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim() == "---")
        .map(|(i, _)| i)
        .collect();
    if marks.len() != want {
        return Err(format!(
            "{name} 의 구분선이 {}개다 — {want}개여야 한다. \
             본문 경계가 달라지면 그 회차는 다른 시험이 된다",
            marks.len()
        ));
    }
    let start = marks[0] + 1;
    let end = if want == 2 { marks[1] } else { lines.len() };
    Ok(lines[start..end].join("\n"))
}

/// `dir/rules/*.yar` 를 읽는다. 제품 CLI 와 같은 규칙이다 — 다르게 읽으면
/// 시험에서 통과한 룰이 현장에서 다른 답을 낸다.
fn load_rules(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let rules_dir = dir.join("rules");
    if !rules_dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let rd = std::fs::read_dir(&rules_dir)
        .map_err(|e| format!("{} 를 읽지 못했다: {e}", rules_dir.display()))?;
    for e in rd {
        let p = e.map_err(|e| format!("{e}"))?.path();
        if p.extension().is_some_and(|x| x == "yar") {
            let name = format!(
                "rules/{}",
                p.file_name().unwrap_or_default().to_string_lossy()
            );
            let body = std::fs::read_to_string(&p)
                .map_err(|e| format!("{} 를 읽지 못했다: {e}", p.display()))?;
            out.push((name, body));
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 지금까지 돌린 회차의 채점 결과. **새 회차를 넣으면 여기에도 넣어야
    /// 한다** — 아래 검사가 개수를 대조하므로 빠뜨리면 실패한다.
    ///
    /// # 왜 숫자까지 고정하는가
    ///
    /// 합격/불합격만 고정하면 느슨하다. **린트를 하나 느슨하게 고쳤을 때
    /// 과거 회차가 조용히 통과하는 것**이 정확히 막으려는 일이고, 그것은
    /// 진단 수가 줄어드는 것으로 먼저 나타난다.
    ///
    /// 린트를 새로 추가하면 이 표가 바뀌는 것이 정상이다. 그때 각 회차를 다시
    /// 보고 **그 변화가 옳은지 판단**해야 한다 — 표를 기계적으로 맞추는 것이
    /// 아니라.
    struct Expected {
        dir: &'static str,
        /// 어느 위협으로 채점하는가. **회차 디렉터리 이름만으로는 알 수 없다.**
        threat: &'static str,
        /// 매니페스트가 파싱되는가. `false` 면 아래 숫자는 **재지 못한 것**이고
        /// 0 인 것이 통과를 뜻하지 않는다.
        parses: bool,
        errors: usize,
        warnings: usize,
        dirty: usize,
        missed: usize,
        lacking: usize,
    }

    const EXPECTED_RUNS: &[Expected] = &[
        // 오염 없는 첫 회차. 입력이 깨진 채였고, from 을 autorun 에 걸어
        // Run 값 제거를 잃었다.
        Expected {
            dir: "2026-08-26-claude-ai-r0-broken-input",
            threat: "evilai-locust",
            parses: true,
            errors: 3,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 2,
        },
        // 오염 없는 첫 온전한 합격 (Fable 5).
        Expected {
            dir: "2026-08-26-fable-5-r1",
            threat: "evilai-locust",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // 같은 모델·같은 위협. 문서가 다섯 늘어난 뒤다. 계획에서
        // file.quarantine_only 를 뺐고 그것이 유일한 불합격 사유다.
        // **대신 우리 첫 플러그인의 결함 둘을 드러냈다.**
        Expected {
            dir: "2026-08-26-fable-5-r2",
            threat: "evilai-locust",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 1,
        },
        // **두 번째 위협의 첫 회차.** 판단은 전부 옳았는데 `to: default` 를
        // `restore` 가 아니라 `remove` 절에 넣어 파싱에서 멈췄다. 그 문법
        // 예시가 주입 문서 21개 중 **0건**이었다.
        Expected {
            dir: "2026-08-26-fable-5-r3",
            threat: "service-userinit",
            parses: false,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **세 번째 주기 검증.** r3 가 드러낸 `to: default` 빈칸을 메운 뒤
        // 받은 회차다. 정확히 `restore` 절에 썼고, 폴더의 나머지 파일까지
        // 격리해 **참조 답안보다 하나 더 했다**(cache.db).
        // **2026-09-02 재채점.** 도달 가능성 검사가 생기면서 린트 오류 1이
        // 붙었다 — `registry_value` 를 선언했는데 `scan_roots` 에 레지스트리
        // 루트가 없어 실기기에서는 언제나 0건이고, Userinit 복원이 아무것도
        // 맞히지 못한다.
        //
        // **답안의 흠이 아니다.** 이 회차가 돌던 시점의 `10-manifest.md` 표는
        // `registry_value` 를 "무관하게 수집된다" 칸에 두고 있었다(`a253eee`
        // 시점 확인). 표는 그 뒤 `307eda9` 에서 고쳤다. 같은 표 아래 쓰인
        // **우리 정답 플러그인도 같은 결함을 갖고 있었고 함께 고쳤다.**
        //
        // 미리 뜬 스냅샷으로 도는 채점은 이것을 볼 수 없었다 — 수집이 이미
        // 끝난 자료라 "그 스냅샷을 뜰 수 있는가" 를 묻지 않는다.
        Expected {
            dir: "2026-08-26-fable-5-svc-r2",
            threat: "service-userinit",
            parses: true,
            errors: 1,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // 아래 셋은 저장소를 보며 쓴 오염 회차다. r1 은 위협 설명이 틀려
        // 도달할 수 없었던 문제이고, r2 는 collect_extra 를 몰라 실기기에서
        // 미평가가 되는 상태였다.
        Expected {
            dir: "2026-08-26-opus-5-r1",
            threat: "evilai-locust",
            parses: true,
            errors: 1,
            warnings: 0,
            dirty: 0,
            missed: 1,
            lacking: 6,
        },
        Expected {
            dir: "2026-08-26-opus-5-r2",
            threat: "evilai-locust",
            parses: true,
            errors: 1,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        Expected {
            dir: "2026-08-26-opus-5-r3",
            threat: "evilai-locust",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **오염 없는 세 번째 합격**이고 Opus 계열로는 첫 무오염 회차다.
        // 문서가 하나 늘어난 뒤(31-nonexistent 의 「볼 수 없는 것」) 처음 받은
        // 답이기도 하다 — 앞선 회차들과 주입 목록이 다르다.
        //
        // 네 판정만으로는 이 회차가 왜 값이 있는지 보이지 않는다.
        // **채점기가 못 재는 자리에서 우리 쪽 결함을 드러냈다** — ex01 과 참조
        // 플러그인이 선언한 %SystemRoot%\System32\Tasks scan_root 은 필요
        // 없는데, 답안은 그것을 빼고도 실기기에서 같은 계획을 냈다.
        // 자세한 것은 그 회차의 NOTES.md.
        Expected {
            dir: "2026-09-01-opus-4.8-r1",
            threat: "evilai-locust",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **두 번째 위협의 두 번째 합격**이고 Opus 로는 처음이다.
        //
        // 재는 값은 "합격" 이 아니라 **r3 가 무너진 자리가 메워진 채 남아
        // 있는가** 다. r3 는 to: default 를 remove 절에 넣어 파싱에서 멈췄고
        // 그 문법 예시가 주입 문서에 0건이었다. 그 빈칸을 메운 뒤 fable-5 가
        // 통과했고, 이 회차가 **다른 모델로** 같은 자리를 지났다.
        //
        // 경고 1은 %ProgramData% 가 넓다는 것이다. 답안이 그 경고를 예상하고
        // 좁힐 수 없는 이유를 미리 적었다 — 경고가 불합격이 아닌 이유
        // (설계-06 §8)를 알고 쓴 것이다.
        //
        // 프롬프트가 바뀐 첫 회차이기도 하다(검체를 설명하는 문장을 뺐다).
        // **2026-09-02 재채점.** 도달 가능성 검사가 생기면서 린트 오류 1이
        // 붙었다 — `registry_value` 를 선언했는데 `scan_roots` 에 레지스트리
        // 루트가 없어 실기기에서는 언제나 0건이고, Userinit 복원이 아무것도
        // 맞히지 못한다.
        //
        // **답안의 흠이 아니다.** 이 회차가 돌던 시점의 `10-manifest.md` 표는
        // `registry_value` 를 "무관하게 수집된다" 칸에 두고 있었다(`a253eee`
        // 시점 확인). 표는 그 뒤 `307eda9` 에서 고쳤다. 같은 표 아래 쓰인
        // **우리 정답 플러그인도 같은 결함을 갖고 있었고 함께 고쳤다.**
        //
        // 미리 뜬 스냅샷으로 도는 채점은 이것을 볼 수 없었다 — 수집이 이미
        // 끝난 자료라 "그 스냅샷을 뜰 수 있는가" 를 묻지 않는다.
        Expected {
            dir: "2026-09-01-opus-5-r1",
            threat: "service-userinit",
            parses: true,
            errors: 1,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **세 번째 위협의 첫 회차.** text_config.remove_line 과
        // shortcut.strip_args 를 처음 밟은 답이다.
        //
        // 이 위협이 재려고 만든 자리를 통과했다 — dir.delete_recursive 가
        // 리눅스에 없다는 것을 Op 표에서 찾아 파일 단위 격리로 갈아탔다.
        // THREAT.md 는 그 Op 이 없다는 말을 하지 않는다.
        //
        // 받을 때는 경고가 2건이었고 **둘 다 답안의 흠이 아니라 우리 린트의
        // 성질이었다.** 같은 날 그중 하나를 고쳤다.
        //
        //   - 폭 경고(사라졌다): root_depth 가 C: 를 한 단계로 세어 리눅스
        //     경로가 한 단계 얕게 계산됐다. 파일 넷짜리 /etc/ld.so.conf.d 가
        //     C:\Windows 와 같은 깊이 2로 잡혔다. **근거 없는 경고였으므로
        //     지금 1건인 것이 옳다** — 표를 기계적으로 맞춘 것이 아니다.
        //   - 'path exists'(남았다): 이쪽은 근거가 있다. from 은 어디를 좁히지
        //     몇 개를 좁히지 않으므로 파일이 많은 폴더에서는 상한 50에 걸린다.
        //     가이드가 이제 그 형태를 가르치면서 "경고가 맞다" 고 함께 적는다.
        //
        // 세 회차 만에 처음으로 가이드 빈칸이 나온 회차다 — 부모가 디렉터리만
        // capture 했을 때 "그 폴더의 파일 전부" 를 잡는 예가 없었다.
        Expected {
            dir: "2026-09-01-opus-4.8-ldso-r1",
            threat: "ldso-preload",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **고친 것을 재는 회차.** r1 이 낸 셋을 닫은 뒤 같은 위협을 다시 냈다.
        //
        // 숫자만으로는 갈리지 않는다 — r1 이 빈칸이 있는 채로도 맞혔으므로
        // 통과는 "가이드 덕분" 인지 "원래 되는 것" 인지 말해 주지 않는다.
        // 갈린 것은 **답안의 서술**이다. r1 은 `path exists` 를 지어냈고
        // 경고에 대해 아무 말이 없었다. r2 는 22-remediate-recipes.md 의
        // 새 문단을 인용하고, 경고가 일어나기 전에 그 이유를 적었다 —
        // "from 은 어디만 좁히고 몇 개는 좁히지 않으므로". 인용한 소제목도
        // 실재한다. **빈칸을 메운 문장이 읽혔다는 뜻이다.**
        //
        // 모델이 r1 과 같아 "다른 모델도 그러한가" 는 아직 모른다.
        Expected {
            dir: "2026-09-01-opus-4.8-ldso-r2",
            threat: "ldso-preload",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **네 번째 위협의 첫 회차.** cert_store.remove 와 hosts.restore_line 을
        // 처음 밟았다(Op 진도 13 -> 16/29). 응시자 답으로는 첫 무경고 합격이다.
        //
        // 이 위협은 실패가 채점 4번에만 걸리도록 지었다 — hosts 를 restore 가
        // 아니라 remove 에 넣으면 린트·코퍼스·판정을 다 통과하고 계획에서만
        // 갈린다. 답안은 restore 를 정확히 썼고, 인증서는 지문까지, hosts 는
        // 루프백 IP 까지 조건에 넣어 우리 정답보다 좁다.
        //
        // **정답과 답안이 판정을 다르게 세웠고 둘 다 통과한다.** 정답은
        // "ca and redirect", 답안은 "proxy and cakey" 다. 둘 다 논리곱이고
        // 독립적이고 프로세스를 뺐다 — 가이드가 가르치는 것을 둘 다 지켰다.
        // 그런데 바이너리만 지워진 기계에서 앞은 CA 를 빼고 뒤는 아무것도
        // 하지 않는다. **판정에 무엇을 넣을지 고르는 기준이 없다**는 것이
        // 이 회차의 산출물이고, 그 회차의 NOTES.md 에 적었다.
        //
        // **2026-09-04 에 이 숫자가 0 → 1 로 바뀌었다. 답안 때문이 아니다.**
        //
        // 그날 이 위협을 합성 JSON 에서 실기기 스냅샷으로 옮기며 인증서를
        // **실제로 발급했다.** 지문이 `7C41A93E…` 에서 `F64CBE1E…` 로 바뀌었고,
        // 답안이 리터럴로 박은 지문이 더는 맞지 않아 `cert_store.remove` 가
        // 계획에서 빠졌다.
        //
        // **답안이 틀린 것이 아니다.** 지문을 못박는 것은 옳은 방식이고 —
        // 인증서에서 지문이 곧 신원이다 — 우리 정답 플러그인도 같은 이유로
        // 그것을 권했다. 문제는 그때 THREAT.md 가 적고 있던 지문이 **아무
        // 인증서의 것도 아니었다**는 것이다. 손으로 지어낸 40자리였다.
        //
        // 그래서 이 숫자는 답안의 품질이 아니라 **채점 데이터가 실기기로
        // 옮겨진 사실**을 기록한다. 커밋 하나로 되돌릴 수 없는 종류의 변화라
        // 여기 남긴다. 회차의 NOTES.md 에도 같은 것을 적었다.
        //
        // 인증서는 이제 저장소에 커밋돼 있으므로(`fixtures/netguard-proxy.crt`)
        // 다시 뜨더라도 지문은 그대로다 — 이 어긋남은 한 번뿐이다.
        Expected {
            dir: "2026-09-01-opus-4.8-tls-r1",
            threat: "tls-intercept",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 1,
        },
        // **다섯 번째 위협의 첫 회차이자 여덟 회차 만의 불합격이다.**
        //
        // 판정이 서지 않아(1건 중 0건) 계획이 통째로 비었다. 그런데 원인은
        // 값 **하나**였다 — direction 에 "inbound" 라 적었고 스냅샷은 "In" 다.
        // 답안 사본에서 그 한 낱말만 바꾸니 네 판정을 전부 통과했다.
        //
        // action 도 "allow" 로 틀렸는데 그쪽은 아프지 않았다. Windows 에서는
        // 비교가 대소문자를 접는다(norm_for_compare). 표기 차이는 봐주고
        // **어휘 차이는 봐주지 않는데, 어느 쪽인지 알려 주는 것이 없다.**
        //
        // 판단은 전부 옳았다. 키가 아니라 값 둘, 파일이 아니라 항목 하나,
        // 삭제가 아니라 원복 — 그리고 판정에서 산출물을 빼면서 그날 넣은
        // 40-review-checklist.md 2번을 근거로 인용했다.
        //
        // **이 회차의 산출물: 열거형 필드의 값 어휘가 어디에도 없다.**
        // subjects.json 은 필드 **이름**을 닫힌 집합으로 주면서 값은 주지
        // 않는다. 주입 꾸러미 138 KB 전체에 "In" 이 0건이고, THREAT.md 는
        // 출제 규칙상 한국어로 "들어옴 · 허용" 이라 적는다. 응시자가 알
        // 방법이 없었다.
        //
        // 그리고 **이 실패는 조용했다.** 없는 필드는 린트가 전수와 함께
        // 거부하고, 채우지 않는 필드는 평가기가 "언제나 거짓" 이라 적었는데,
        // 값이 틀려 언제나 거짓인 술어에는 그런 장치가 없었다 — 0건을 맞히고
        // 조용히 초록이 됐다.
        //
        // **그래서 같은 날 그 장치를 만들었다** (`Subject::ENUMERATED_FIELDS`).
        // 경고가 1이 아니라 **2인 것이 이 줄의 요점이다** — 늘어난 하나가
        // 바로 이 답안의 direction 을 짚는 새 진단이다. 답안은 그대로인데
        // 코어가 이제 그것을 말한다. 자세한 것은 그 회차의 NOTES.md.
        //
        // **2026-09-04: 빠짐이 4 에서 6 으로 바뀌었다. 답안은 그대로다.**
        // 그날 기대 목록을 Op 이름에서 (Op, 대상) 자리표로 조였고, 이 위협의
        // 기대가 4종 → 6건이 됐다(`registry.delete_value` 와
        // `file.quarantine_only` 이 각각 둘이다). 이 회차는 판정이 서지 않아
        // **전에도 하나도 못 냈고 지금도 하나도 못 낸다** — 분모만 움직였다.
        // 기록된 스물한 회차 중 수가 바뀐 것은 이 하나뿐이고, 나머지는 빠짐
        // **항목까지** 그대로다.
        // ── 2026-09-05: `appinit-implant` 의 기준이 바뀌었다 ────────────────
        //
        // `AppInit_DLLs` 와 `LoadAppInit_DLLs` 의 기대가
        // `registry.delete_value` 에서 `registry.restore_default` 로 바뀌었다.
        // 둘은 청정 Windows 에 이미 있는 값이고(각각 `REG_SZ` 빈 문자열,
        // `REG_DWORD` 0) 검체가 만든 것이 아니라 덮어쓴 것이다. 채점 5 가
        // 실기기에서 그것을 냈다 — `apply` 는 완전 치료(1)라고 하는데 기계가
        // 청정 기준과 달랐다.
        //
        // 그래서 **r2·r3·r4 가 빠짐 0 에서 2 로 바뀐다.** 셋 다 같은 자리에서
        // 같은 선택을 했다.
        //
        // **그 셋을 틀렸다고 읽으면 안 된다.** 그날 카탈로그에는 이 두 자리가
        // 없었고, `to: default` 를 쓰면 린트가 *"OS 기본값 카탈로그에 없다"* 로
        // 거절했다. **코어가 옳게 할 방법을 주지 않았으므로 `remove` 가 그때
        // 쓸 수 있는 전부였다.** 기준이 그 한계를 그대로 적고 있었던 것이고,
        // 오늘 코어를 고치면서 기준도 함께 옮겼다.
        //
        // r1 은 숫자가 그대로다 — 판정이 서지 않아 아무것도 계획하지 못했고,
        // 여섯 중 둘의 이름만 바뀌었다.
        Expected {
            dir: "2026-09-01-opus-4.8-appinit-r1",
            threat: "appinit-implant",
            parses: true,
            errors: 0,
            warnings: 2,
            dirty: 0,
            missed: 1,
            lacking: 6,
        },
        // **메운 빈칸이 읽히는지 재는 회차.** r1 이 값 어휘가 없어 무너진
        // 자리에 전수를 넣고 같은 위협을 다시 냈다.
        //
        // ldso-r2 와 달리 **숫자가 뜻을 갖는다.** 그때는 r1 이 이미 합격이라
        // 무엇이 달라졌는지 갈리지 않았는데, 이번 r1 은 불합격이었고 그
        // 원인이 한 자리뿐임을 실측으로 확정해 두었다. 주입 파일 중 바뀐
        // 것은 둘(subjects.json 의 enumerated · 린트 사례 하나)이고
        // PROMPT.md 와 THREAT.md 는 한 글자도 바뀌지 않았다.
        //
        // **채점 전에 읽어 낼 기준을 적어 두었다** — "합격이어도 direction 을
        // 쓰지 않았으면 아무것도 못 잰다". 답안은 그것을 썼고(값 In),
        // 주석에 전수의 **근거**까지 풀어 적었다("Dir= 토큰이 그대로 온다").
        // 값을 베낀 것이 아니라 기전을 읽었다.
        //
        // 답안이 우리 결함 둘을 짚었고 둘 다 사실이었다. 판정식 문법이
        // 문서에 없던 것은 같은 날 메웠다. ex02 가 실기기에서 0건을
        // 수집한다는 것은 결정이 필요해 남겨 두었다 — 그 회차의 NOTES.md.
        Expected {
            dir: "2026-09-01-opus-4.8-appinit-r2",
            threat: "appinit-implant",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 2,
        },
        // **이 시험을 통틀어 가장 좁은 비교다.** 같은 모델(Opus 5)·같은 위협·
        // 같은 절차이고 달라진 것은 문서뿐이다. 직전 회차 opus-5-r1 은 이
        // 위협에서 린트 오류 1(레지스트리 루트 없음)이었고 이번은 0이다.
        //
        // 답안이 Winlogon 키를 scan_roots[0] 에 넣고 10-manifest.md 를 근거로
        // 달았다 — 2026-09-01 에 그 표를 고치며 써 넣은 문장을 거의 그대로
        // 옮겼다. 같은 표의 반대 칸(service 는 무관하다)도 함께 읽었다.
        //
        // **더 큰 것은 service.state 다.** THREAT.md 가 "상태 실행 중" 이라
        // 적는데 답안은 running 을 쓰지 않았고 subjects.json 의 값 전수를
        // 근거로 댔다. appinit-r1 이 "인바운드" 를 그대로 옮겨 불합격한 것과
        // **같은 자리·같은 크기의 함정**이고, 그 회차가 낸 산출물이 막았다.
        // 자리가 다르다 — 그때는 firewall_rule.direction, 이번엔 service.state.
        // 한 필드를 고친 것이 아니라 태도가 옮겨졌다는 두 번째 관측이다.
        //
        // 어제 연 끝 별표를 **쓰지 않기로** 판단한 것도 이 회차다 — Userinit
        // 은 직속 값이라 필요 없고 별표는 넓히는 쪽이라는 이유까지 적었다.
        // **여섯 번째 위협의 첫 회차이자 응시자 답안의 두 번째 무경고 합격이다.**
        //
        // 재려던 것(경로 목록·부팅 목록을 remove 가 아니라 edit 에 넣는가)은
        // 통과했고, 두 value 를 증거에서 파생시켜 **우리 정답보다 나았다** —
        // 우리 쪽은 리터럴이었다. 확장 상한을 %ALLUSERPROFILES% 로 편 것도
        // 우리보다 낫다(다중 사용자 기계). 정답을 둘 다 고쳤다.
        //
        // **산출물은 이 답안이 우리 위협의 결함을 찾은 것이다.** THREAT.md 34행이
        // wbsvc.exe 를 "상주하며" 라 적는데 expected-ops.txt 는 "실행 중인
        // 프로세스를 관측하지 않았다" 며 process.kill 을 빼고 있었다 — 문제와
        // 채점 데이터가 갈라진 것이고(출제자 주의 2번), 감염 스냅샷에 process
        // 레코드가 없어 채점이 어느 쪽으로도 말하지 않았다.
        //
        // 보고가 상주를 말하므로 위협 쪽을 맞췄다. 그러자 계획기가
        // locked_by_a_process 로 파일을 다르게 다뤄 file.delete_on_reboot 이
        // 따라왔다 — **프로세스를 탐지한 플러그인만 받는 Op 이라 공짜가 아니다.**
        // 기대 5 -> 7건, Op 진도 22 -> 24/29.
        //
        // 아래 숫자는 위협을 고친 뒤의 것이다. 답안은 그대로이고 **기대가
        // 자랐다** — "7건을 맞혔다" 가 아니라 "이미 갖고 있던 것이 기대에
        // 들어왔다" 로 읽어야 한다.
        Expected {
            dir: "2026-09-02-opus-5-hijack-r1",
            threat: "search-hijack",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **이 시험의 첫 재현이다.** fable-5 로 돌리려 했으나 그 모델의 안전
        // 필터가 거부해 못 바꿨고, 그래서 같은 모델·사실상 같은 입력·같은
        // 위협이 됐다. 열여덟 회차가 전부 n=1 이었으므로 변동폭을 잰 적이
        // 없었다.
        //
        // **숫자는 r1 과 같고 접근은 셋이 달랐다** — 판정식(넷으로 편 "둘 이상"),
        // 경로에서 뺄 값의 출처(파일 폴더 vs 목록의 첫 항목), 브라우저 상한
        // (Default\Extensions vs User Data). 표본 하나짜리 회차를 "이 모델은
        // 이렇게 한다" 로 읽으면 안 된다는 증거다.
        //
        // 산출물은 REG_MULTI_SZ 직렬화가 문서에 없다는 것이다. 답안이 구분자를
        // 모른다는 이유로 조건에서 뺐고, 실제로 `join("\n")` 인데 어디에도
        // 적혀 있지 않았다. 시험으로 고정하고 registry_value.type 설명에 적었다.
        Expected {
            dir: "2026-09-02-opus-5-hijack-r2",
            threat: "search-hijack",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        Expected {
            dir: "2026-09-02-opus-5-svc-r3",
            threat: "service-userinit",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **첫 위협의 여덟 번째 회차.** 오류 0 · 경고 0 · 파괴 0 · 빠짐 0 ·
        // 기대 밖 0 — 이 표의 현재 값으로 무경고 합격 여섯 중 하나다.
        //
        // 회차 폴더에 `rules/evilai.yar` 이 오지 않았다. 그것은 응시자가 쓴 것이
        // 아니라 분석가 룰로 **주어진** 파일이고(답안이 두 곳에서 "받은 파일
        // 그대로" 라 적는다) 앞선 여섯 회차도 전부 바이트 동일한 사본을 갖고
        // 있다. 위협의 것을 그대로 놓고 채점했다.
        //
        // **그 사이에 산출물이 하나 나왔다.** 룰 없이 돌린 첫 채점이 빠진 Op
        // 하나가 아니라 **계획 전체 거부**(종료 코드 5)로 떨어졌다 —
        // `guard: payload` 의 증거가 없어 G6·G7 에 걸렸다.
        //
        // `22-remediate-recipes.md` 는 재귀 삭제가 "걸리면 deferred 가 된다" 고
        // 가르치고 있었다. 틀렸다 — `check_recursive` 의 조건 1·2·4·5 는 전부
        // G6 위반이고 위반 하나면 계획이 통째로 서지 않는다. 실행 시점인 것은
        // 3·6 뿐이다. 작성자는 최악을 "폴더가 안 지워진다" 로 읽는데 실제
        // 최악은 "아무것도 안 지워진다" 다.
        //
        // **답안은 가이드를 그대로 따랐다**(§3 이 "deferred 가 될 수 있고" 라
        // 적는다). 답안의 흠이 아니라 우리 문서의 흠이고, 조건별 결과를 표로
        // 넣어 고쳤다.
        //
        // 이 답안의 두 결정이 서로를 무르는 것도 그 자리에서 보였다 — 판정을
        // `task and (payload or runkey or exclusion)` 로 연 이유가 ".js 가 이미
        // 없는 기계" 인데, 바로 그 기계에서 `guard: payload` 도 증거가 없어
        // 계획이 거부된다.
        Expected {
            dir: "2026-09-04-opus-5-r1",
            threat: "evilai-locust",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **회차가 하나뿐이던 가장 얇은 위협의 두 번째.** 그리고 채점 기준을
        // **답안이 오기 전에** 커밋하고 돌린 첫 회차다
        // (커밋 25e41bf).
        //
        // 재려던 자리는 `store` 하나였다. 검체는
        // `/usr/local/share/ca-certificates` 에 있고 수집기는 그 자리를
        // `local` 이라 적는데, **우리 정답이 `system` 으로 좁혀 실기기에서
        // 판정조차 서지 않고 있었다**(2026-09-05 에 고쳤다). 게다가 `local`
        // 이라는 값은 이 회차 **하루 전**에야 값 전수에 들어왔다 — 그전에는
        // 옳은 값을 쓰면 린트 오류였다.
        //
        // 답안은 `store equals "local"` 을 쓰고 그 구분을 소스와 같은 말로
        // 적었다. 하루 된 수정이 응시자에게 닿는 것을 잰 셈이다.
        //
        // **산출물 1 — 고리가 한 바퀴 돌았다.** 답안의 판정 절이
        // *"guard 를 쓰지 않으므로 판정은 서는데 계획이 거부되는 형태
        // (22-remediate-recipes.md 의 2026-09-04 사례)는 나오지 않는다"* 고
        // 적는다. 그 문단은 **바로 앞 회차**가 낸 것이다. 이 시험이 열아홉
        // 회차 동안 관측으로 문서를 고쳐 왔지만, 그 문서가 다음 응시자의
        // 판단을 바꾸는 것을 본 것은 처음이다.
        //
        // **산출물 2 — `min_core` 빈칸이 두 회차 연속으로 나왔다.** 답은 표가
        // 아니라 사실 하나였다: 판은 아직 1.0.0 하나이고 Phase 는 개발
        // 순서이지 배포 판이 아니다. 없다는 사실을 적지 않아 둘이 같은 자리에서
        // 멈췄다. 10-manifest.md 의 min_core 행에 적었다.
        Expected {
            dir: "2026-09-04-opus-5-tls-r2",
            threat: "tls-intercept",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // 기준을 **답안 전에** 못박은 두 번째 회차
        // (커밋 66bf138).
        //
        // **경고 1건이 이 회차의 전부다.** 네 판정은 전부 통과했고 계획도 손으로
        // 읽어 여섯 건이 모두 정확했다 — 값 둘만, 규칙 하나만, 설정 항목
        // 하나만. 그런데 `%PROGRAMDATA%` 를 상한으로 잡으면서
        // `structured_config` 를 함께 선언했다. 실기기 Win10 에서 그 조합이
        // **종료 코드 6**(관측 불완전)을 낸다 — 원격 분석 JSON 하나가 5만 상한을
        // 삼킨다. 네 판정 어느 것도 이것을 보지 못한다. 평가는 **스냅샷의**
        // scan_roots 를 쓰기 때문이다. **린트 경고 하나가 자동 채점 전체가
        // 못 보는 실기기 실패를 잡았다.**
        //
        // **산출물 — 상한을 subject 별로 나눌 수 없다.** 답안이 넓게 잡은 것은
        // 게을러서가 아니다. 페이로드 폴더 이름은 증거에서 파생되므로 미리
        // 못박을 수 없고, 우리 정답이 `C:\ProgramData\SvcAssist` 를 적을 수
        // 있는 것은 **답을 이미 알기 때문**이다. `scan_roots` 는 subject 를
        // 가리지 않는 단일 목록이라 "파일은 넓게, 구조적 설정은 좁게" 를
        // 말할 방법이 없다. 이 회차가 그 자리를 처음 짚었다.
        //
        // 그리고 같은 날 고친 THREAT.md 가 닿았다 — 답안 주석이
        // *"이 키의 값 19개가 모인다"* 라고 적는다. 그 수는 이 회차 직전에
        // 실측으로 바로잡은 것이다(그전에는 "둘" 이었다).
        Expected {
            dir: "2026-09-04-opus-4.8-appinit-r3",
            threat: "appinit-implant",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 2,
        },
        // **문서가 실기기 결과를 바꾼 것을 처음 봤다.**
        //
        // r3 이 부딪힌 자리에 그 뒤 `subject_roots` 를 만들었다. 응시자는
        // `plugin lint` 를 돌릴 수 없으므로 통로가 문서 셋뿐이었는데
        // (`10-manifest.md` · 안티패턴 §12 · `32-lint-errors.md`), **셋 중 둘을
        // 읽고 썼다.** 좁힘을 적었고, 그 아래에 *"좁히는 것은 수집 비용을 줄일
        // 뿐 삭제 상한은 여전히 scan_roots 다"* 라고 적었다 — 전날 넣은
        // 안티패턴 §12 그대로다.
        //
        // 실기기에서 재면 이렇다. 같은 기계 · 같은 위협 · **같은 모델**.
        //
        //   r3 답안  종료 코드 6 · truncated · structured_config 50,000
        //   r4 답안  종료 코드 0 · 온전       · structured_config 0
        //
        // 앞선 회차들은 *"우리가 고친 것이 다음 응시자에게 닿는다"* 를 답안의
        // 문장으로 봤다. 이번엔 **실기기 결과가 갈렸다.**
        //
        // 경고 1건은 `%PROGRAMDATA%` 의 넓이다 — 그 문구에서
        // `structured_config` 절이 빠진 것이 좁혔다는 증거다.
        //
        // 설계가 우리 정답과 갈린 자리 하나: `loadflag` 를 뿌리가 아니라
        // **파생**으로 두어 같은 키임을 확인한다. 그래서 청정 코퍼스가 마주한
        // 레코드가 374 → **187** 로 반이다. 판정 안전은 그대로지만(부모 없이
        // 자식이 서지 않는다) 재는 양은 줄었다.
        Expected {
            dir: "2026-09-05-opus-4.8-appinit-r4",
            threat: "appinit-implant",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 2,
        },
        // **압력 121,472건 — 지금까지 가장 크다.** 정답이 685건이니 177배다.
        // `payload` 를 뿌리 규칙으로 두어 청정 파일 121,282건을 전부 마주하고
        // 0건을 맞힌다.
        //
        // 사전 기준이 물은 것을 전부 통과했고, 셋은 **정답보다 낫다** — 판정이
        // 부분 청소된 기계에 강하고(`셋 중 둘`), 프로세스를 리터럴이 아니라
        // `${payload.dir}` 로 좁히며, `REG_MULTI_SZ` 에서 한 줄을 뽑는 capture
        // 함수가 카탈로그에 없다는 것을 알고 파일 증거의 basename 으로 돌아간다.
        //
        // **산출물 — 계획에 중복 여섯이 있는데 채점 넷이 못 본다.**
        // `payload` 가 capture 를 가진 뿌리 규칙이고 파일 둘을 맞혀 증거 그룹이
        // 둘로 팬아웃한다. 둘 다 같은 `${payload.dir}` 을 풀어 같은 하위 Action
        // 을 각각 만든다 — Action 14건 중 서로 다른 것은 8건이다.
        //
        // 그런데 `planned` 가 `BTreeSet` 이라 중복이 접혀 기대와 정확히 맞는다.
        // **2026-09-04 에 절반짜리 치료를 잡도록 조였는데, 두 배짜리 치료는
        // 여전히 못 잡는다.**
        //
        // 모델은 Opus 5 다 — `appinit` 두 회차를 막았던 분류기가 이번엔
        // 서지 않았다. 왜인지는 모른다(위협이 다르고 머리말은 같다). 표본이
        // 위협마다 하나라 가를 수 없다는 사실을 그 회차 기록에 적었다.
        Expected {
            dir: "2026-09-05-opus-5-hijack-r3",
            threat: "search-hijack",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **미끼를 보고 술어 둘을 곱했다.**
        //
        // 감염 스냅샷이 실기기로 바뀌며 서비스가 3 → 713 이 됐고, 그러면서
        // 정답의 경로 정규식과 같은 모양인 정상 서비스가 하나 들어왔다
        // (`Acme Update Service`, 시작 유형 `manual`). 답안이 그것을 **이름으로
        // 짚고** `start_type equals auto` 의 이유로 적었다. 계획을 손으로
        // 읽었고 미끼는 없다 — Action 8건 · 겹침 0 · 보류 0.
        //
        // `state` 함정도 피했다. 위협 설명은 그 서비스가 돌고 있다고 적지만
        // 수집기는 그 필드를 언제나 `unknown` 으로 남긴다. **관측 보고의
        // 문장과 스냅샷의 필드가 다르다는 것을 알아채고 데이터 쪽을 따랐다.**
        //
        // **산출물 — 응시자가 자기 검증 절차를 적었다.** `answer.md` 가 받을
        // 경고를 예측하고, 코퍼스가 그것을 재지 못한다는 것을 알고(평가가
        // 스냅샷의 상한을 쓴다), 실기기 `scan` 으로 무엇을 확인할지 이름으로
        // 적었다 — `file` 이 잘리지 않는지, `registry_value` 가 0건이 아닌지.
        // 그대로 돌렸더니 종료 코드 0 · truncated false · file 5,553 ·
        // registry_value 35 로 **둘 다 맞았다.** 지난 네 회차 동안 그 확인은
        // 내가 채점하며 하던 일이다.
        Expected {
            dir: "2026-09-05-opus-5-srv-r4",
            threat: "service-userinit",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **룰로만 갈리는 위협의 첫 회차** (2026-09-22). 열일곱 일 만이고, 그
        // 사이 위협이 여섯에서 스무 개로 늘었다 — 이 회차는 그중 한 번도
        // 응시되지 않은 열넷에서 처음 돈다.
        //
        // 합격·무경고. 압력 242,554건은 지금까지 가장 크다. 사전 기준이
        // *"사람이 읽어야 보인다"* 고 적은 물음 셋(본문 담기 선언 · 2패스의
        // 순환 · 룰 무수정)을 전부 통과했고, **채점 5를 응시자 답안으로 처음
        // 돌려** 그 순환이 실기기에서도 서는 것을 확인했다.
        //
        // 전달 사고 하나가 있었다 — 룰이 회차 폴더 루트에 저장돼 첫 채점이
        // 불합격이었다(`load_rules` 는 `rules/` 를 읽는다). 답안의 매니페스트가
        // 선언한 자리로 옮겨 다시 쟀고, 그 밖에는 한 바이트도 고치지 않았다.
        // 자세한 것은 그 회차의 NOTES.md.
        Expected {
            dir: "2026-09-22-opus-5-hook-r1",
            threat: "hook-implant",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **감춘 값을 풀어 이어 쓰는 위협의 첫 회차** (2026-09-22). 같은 날 두
        // 번째 회차이고, 한 번도 응시되지 않은 열셋 중 하나에서 돈다.
        //
        // 합격·무경고. 압력 265건은 지금까지 가장 작다 — 뿌리 규칙이 설정 항목
        // 하나이고 나머지 둘이 부모에 묶여 있다. 실기기에서 **치료 후 상태가
        // 정답의 것과 sha256 까지 같았다.**
        //
        // 이 회차의 판별은 **자동으로 되지 않는다.** 위협 설명이 풀어 낸 결과를
        // 평문으로 보여 주므로 그것을 리터럴로 박은 답안도 다섯을 전부 통과한다
        // (사전 기준 ③, 변형 실측). 그래서 매니페스트 본문을 기계로 훑어
        // 검체의 폴더·파일 이름이 0회임을 확인했다 — 답안은 `hex_decode` ·
        // `dirname` · `basename | lower` 로 **풀었다.**
        //
        // 답안이 우리 쪽 구멍 둘을 드러냈다: 리눅스에서 `after_reboot` 이
        // 예약되지 않는데 계획 화면은 약속한다는 것, 그리고 청정 코퍼스 28장에
        // nodewatch 정상 설치가 한 장도 없다는 것. 자세한 것은 그 회차의
        // NOTES.md.
        Expected {
            dir: "2026-09-22-opus-5-hexcfg-r1",
            threat: "hexcfg-loader",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **응시자가 안전 장치를 처음 밟는 회차** (2026-09-22). 같은 날 세
        // 번째이고, **Opus 5 가 안전장치 분류기에 막혀 Opus 4.8 이 답했다** — 사전
        // 기준 ③이 그 경우를 미리 적어 두었다.
        //
        // 합격, 경고 1건. 그 경고(`%PROGRAMDATA%` 가 사실상 전체를 훑는다)는
        // **맞는 지적이고 답안이 그 이유를 미리 주석에 적었다.** 여기서 0 이
        // 나오면 린트가 상한 깊이를 놓친 것이므로 그때 봐야 한다.
        //
        // 압력 186건은 **정답(420)보다 작다** — 응시자가 정답보다 사거리가
        // 짧은 첫 회차다. 사거리와 권한 상한이 다른 축이라는 것이 이 회차에서
        // 드러났다.
        //
        // 사전 기준이 변형으로 재어 둔 정지(G6 세 줄)는 일어나지 않았다.
        // 답안은 증거인 키를 치우지 않았고 그 이유를 주석에 두 번 적었다.
        // `after_reboot` 이 Windows 에서는 예약된다는 것도 이 회차가 쟀다 —
        // `hexcfg-r1` 의 리눅스 관측과 반대쪽이다. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-22-opus-4.8-stager-r1",
            threat: "regkey-stager",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **"무엇을 지우면 안 되는가" 를 묻는 첫 회차** (2026-09-22). 같은 날
        // 네 번째이고, 앞 셋이 전부 "설정에 감춘 것을 찾아 치운다" 계열이었던
        // 것과 결이 다르다.
        //
        // **이 회차는 자동 넷이 거의 아무것도 못 가른다.** 사전 기준이 만든
        // 함정 변형 셋(폴더로 가르기 · 바탕화면 되돌리기 · 정책 키째 겨누기)이
        // 전부 자동 넷에서 합격했고 `must-remain` 에서만 갈렸다. 그래서 이
        // 회차의 진짜 점수는 채점 5 의 **남아야 하는 자리 6/6** 이다 — 암호화된
        // 사용자 문서 둘 · 정상 문서 · 벤더 프로그램 · 바탕화면 값 · 조직 정책 값.
        //
        // 합격, 경고 1건. 그 경고(`%PROGRAMDATA%` 가 사실상 전체를 훑는다)는
        // **직전 `stager-r1` 답안과 같은 자리·같은 이유**다. 두 회차 연속이라
        // 가이드가 그 트레이드오프를 다루지 않는다는 신호일 수 있다.
        //
        // 답안이 정답보다 나은 자리도 둘 있었다 — 페이로드 폴더를 리터럴이
        // 아니라 자동 실행 명령에서 파생했고(`command | first_path | dirname`),
        // 협박문 범위를 `%ALLUSERPROFILES%` 로 펴 다른 사용자 프로필까지
        // 치료한다. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-22-opus-5-ransom-r1",
            threat: "ransomware",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **아홉 회차 만의 첫 불합격** (2026-09-22).
        //
        // 1. 이 위협은 해시로 갈리는데 꾸러미가 그 값을 주지 않는다(실측:
        //    `311778ae…` 가 꾸러미에 0회). 답안은 지어내지 않고 자리 표시자를
        //    두고 *"받아서 쓰라"* 고 적었다 — 프롬프트가 요구하는 그대로다.
        //
        //    **다만 "답할 수 없었다" 는 아니다**(같은 날 뒤에 실측으로 정정).
        //    `THREAT.md` 가 크기를 주므로 `size equals 38912` 로 바꾼 변형이
        //    **합격한다.** 그리고 해시를 적지 않은 것은 출제자 주의 4 에 적힌
        //    **의도된 설계**라 뒤집지 않기로 했다. 정확한 서술은 *"의도한 길만
        //    막혀 있었다"* 이다.
        // 2. 답안이 정기 작업을 `persistence` 로 다뤘는데 **이 스냅샷에
        //    persistence 가 0건**이었다. 수집 매니페스트가 `subjects: [file]` 만
        //    선언했다(`ssh-backdoor` 는 선언해서 16건이 담긴다).
        //
        //    **이쪽은 고쳤다** — 매니페스트에 `persistence` 를 더하고 스냅샷을
        //    다시 떴다(16건). 정답은 회귀 0 이고 **이 회차의 점수도 그대로다**
        //    (자리 표시자 해시 때문에 `replica` 가 여전히 0).
        //
        //    고치고 나서 보인 것: 진단으로 판정을 세우면 계획이
        //    `persistence.delete/disable` 로 **줄 단위**로 나온다. `THREAT.md`
        //    요구 사항 2 가 *"줄만 빼면 빈 파일이 남는다"* 며 파일 제거를
        //    요구하므로 **답안의 치료 선택이 요구를 못 채운다** — 답안의 주석
        //    (*"항목 전체를 치운다"*)이 실측과 다르다.
        //
        // 진단(답안 점수가 아니다): 해시만 실제 값으로 바꿔도 여전히 판정 0 —
        // 2번이 단독으로 치명적이다. 해시 + 판정을 `replica` 만으로 하면
        // **판정 1/1 · 빠짐 1건**으로, **해시 규칙 자체는 완벽하다.**
        //
        // 사전 기준이 *"점수로는 안 갈린다"* 고 못박은 ②-2(자리를 나열하지
        // 않는가)는 **통과했다.** 실기기에서도 아무것도 부수지 않았다
        // (남아야 6/6 · 치료가 만든 변화 0). **시험이 정직을 벌한 자리이고,**
        // 픽스처를 고치면 이 회차는 다른 시험이 되므로 재응시로 기록한다.
        // 자세한 것은 NOTES.md.
        //
        // **경고 1 은 뒤에 생긴 검사다** (2026-10-02 · `check_sha256_literals`). 그때는
        // 경고 0 이었다 — 0 을 64개 적은 자리 표시가 린트를 조용히 지났다. 기록은
        // 지금 자료로 다시 채점한 값이다.
        Expected {
            dir: "2026-09-22-opus-5-worm-r1",
            threat: "selfcopy-worm",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 1,
            lacking: 6,
        },
        // **고침이 통하는지 재는 회차** (2026-09-23). 문제는 r1 과 바이트
        // 동일하고(`cmp`) 바뀐 것은 채점 자료뿐이다 — `ldso-r1 → r2` 와 같다.
        // r1 은 Opus 5, 이번은 **Opus 4.8** 이 답했다.
        //
        // **통했다.** r1 에서는 `persistence` 가 0건이라 그 길로 간 답안이
        // 판정을 못 세웠는데, `e24da93` 뒤로는 선다 — 이번 답안이 그 길로
        // 가서 **판정 1/1** 이 나왔다.
        //
        // 불합격은 치료 쪽이다. 사전 기준(`d33acf4`)이 변형으로 미리 잰
        // 넷째 줄 *"탐지·치료 모두 persistence → 빠짐 1 · 기대 밖 2"* 가
        // 그대로 나왔다.
        //
        // **실기기가 처음 보여준 것**: `persistence.delete` 는 cron 드롭인에서
        // **줄만 뺀다.** 치료 뒤 파일이 `01ba4719…`(개행 한 바이트)로 남았고,
        // THREAT.md 요구 사항 2 가 금한 상태다. 서로 다른 모델 둘(r1 Opus 5 ·
        // r2 Opus 4.8)이 *"유닛째 치운다"* 로 같은 오해를 했다 —
        // `22-remediate-recipes.md` 에 persistence 언급이 0회이고 `ops.json` 의
        // `edits_in_place: false` 가 그 오해를 부추길 수 있다. 범위 밖이라
        // 적어만 둔다.
        //
        // 답안은 해시도 크기도 아닌 **숨김 basename + `count(copy) >= 2`** 로
        // 갈랐다(`count` 는 `31-nonexistent.md` 의 문서화된 문법이고 응시자가
        // 쓴 것은 처음이다). 자리는 나열하지 않았다. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-22-opus-4.8-worm-r2",
            threat: "selfcopy-worm",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 1,
        },
        // **어제 고친 가이드 문단(`ccfaf57`)을 겨냥해 고른 회차** (2026-09-23).
        // Opus 5.5 로 시작했으나 안전장치 분류기에 막혀 **Opus 4.8** 이 답했다.
        //
        // 불합격이지만 **재려던 것은 맞혔다.** 정기 작업을 `file` 로 치우고
        // `persistence` 를 증거로만 썼다 — `worm-r1`·`worm-r2` 가 틀린 그
        // 자리다. 꾸러미에 **한 번만** 있는 낱말 "파일째"(그 문단)가 답안에
        // 세 번 나오고, 위협 설명에 없는 *"persistence 제거는 줄만 뺀다"* 가
        // 답안에 있다. 진단(sshd 규칙을 뺀 사본)으로 계획이
        // `file.quarantine_only /etc/cron.d/ssh-maint` 로 서는 것을 확인했다.
        //
        // 불합격의 원인은 다른 자리 둘이 겹친 것이다:
        //   1. `line | first_path` 가 `AuthorizedKeysFile /etc/ssh/.maint/keys`
        //      에서 **첫 공백 토큰** `AuthorizedKeysFile` 을 냈다. `dirname` 이
        //      빈 값이 되어 `from` 이 상한 밖으로 판정됐다. 꾸러미는
        //      `first_path` 를 *"첫 경로를 뽑는다"* 로만 적고, 정확한 뜻은
        //      위의 `INJECT` 가 빼는 `AI-CONTEXT.md` 에만 있다.
        //   2. `sshd-hook`·`cron-hook` 이 **각각 1건씩** 맞아 한 그룹을
        //      공유했고(그룹은 부모가 2건 이상일 때만 나뉜다), sshd 쪽의 그룹
        //      제외가 cron 쪽 증거까지 지웠다. 답안의 논리합 설계가 거기서
        //      무너졌다.
        // 둘 다 범위 밖이라 고치지 않았다. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-23-opus-4.8-sshbd-r1",
            threat: "ssh-backdoor",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 1,
            lacking: 4,
        },
        // **가이드 수정의 효과를 가장 깨끗하게 잰 회차** (2026-09-23). r1 과
        // **같은 판**(Opus 5.5 → 분류기 → Opus 4.8)이 답했고, 위협·스냅샷·
        // 채점기가 같고, 다른 것은 꾸러미의 877 바이트(`9ac5f5b` · `bbc3ce1`)
        // 뿐이다. 결과가 **불합격(판정 0 · 빠짐 4) → 합격(빠짐 0 · 기대 밖 0)**
        // 으로 바뀌었고, 치료 후 기계 상태가 정답과 sha256 까지 같다.
        //
        // 사전 기준(`13d3aad`)의 진단 행 *"r1 구조 + sshd 자리만 리터럴 →
        // 합격"* 이 그대로 나왔다. 답안이 r1 을 넘어뜨린 자리(`line |
        // first_path`)를 리터럴로 바꾸며 *"(문서 §capture 함수의 지침)"* 이라고
        // **절 이름으로 인용**했고, *"sshd_config 는 key/value 가 빈다"* 라는 그
        // 문장에만 있는 사실을 적었다.
        //
        // 그룹 문단(`bbc3ce1`)은 흔적이 없다. 답안이 `from` 을 하나도 안 써
        // (r1 은 넷) 그룹이 제외될 자리를 만들지 않았다 — **결과적으로 피했다**
        // 로 적고 "알고 피했다" 로 읽지 않는다. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-23-opus-4.8-sshbd-r2",
            threat: "ssh-backdoor",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **사전 기준 없이 돌린 회차** (2026-09-23 · Opus 4.8). 준비 단계가
        // 안전장치에 막혀 기준을 답안 전에 적지 못했다 — 그래서 이 합격을
        // 어느 가이드 문단의 효과로도 읽지 않는다. 치료 후 기계 상태가 정답과
        // sha256 까지 같다. 경고 1 은 조건 하나짜리 넓은 비교(값 2자)이고,
        // 그 경고에는 `32-lint-errors.md` 에 자기 절이 없다. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-23-opus-4.8-xmr-r1",
            threat: "xmr-miner",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **문제가 도달할 수 없었던 회차** (2026-09-27 · Opus 5.5 → 4.8).
        // `THREAT.md` 본문에 다이제스트 목록이 없었다(실측 0개 — 출제 메모 2 와
        // 어긋난다). 응시자는 값을 지어내지 않고 자리 채우기를 두고 그렇게
        // 적었다. 답안 구조 그대로 다이제스트 넷만 정답 것으로 바꾼 진단 사본은
        // 합격(기대 밖 0)이다 — 불합격은 우리 문제의 결함이다. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-27-opus-4.8-c2-r1",
            threat: "c2-beacon",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 1,
            lacking: 3,
        },
        // **문제만 바뀐 회차** (2026-09-27 · Opus 5.5 → 4.8, r1 과 같은 판).
        // r1 이후 달라진 것은 위협 설명의 다이제스트 목록(+270 바이트, `ff7b8cf`)
        // 뿐이고, 결과가 **불합격(판정 0 · 빠짐 3) → 합격(빠짐 0 · 기대 밖 0)** 으로
        // 바뀌었다. 다이제스트 넷을 순서까지 정확히 옮겼고(변종 몫 둘 포함 — 자동
        // 채점은 그 둘을 재지 못한다), 치료 후 상태가 정답과 sha256 까지 같다.
        // 경고 1 은 정답과 같은 `scan_roots` 경고다. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-27-opus-4.8-c2-r2",
            threat: "c2-beacon",
            parses: true,
            errors: 0,
            warnings: 1,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **무경고 합격** (2026-09-27 · Opus 5.5 → 4.8). 되돌리기(hosts · 프록시)와
        // 없애기(파일 · 자동 시작)를 절로 갈랐다 — 사전 기준이 미리 잰 대로, 틀리면
        // 계획이 G6 에 거부되는 자리다. 채점 5(랩 VM)도 합격이다 — hosts 는 돌려진
        // 두 줄만 빠졌고 건드리지 않는 자리는 그대로다. 지문 여덟은 0 이라 가이드
        // 문단의 효과로 적지 않는다. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-27-opus-4.8-proxy-r1",
            threat: "proxy-dns-hijack",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **가이드의 빈칸이 그대로 드러난 회차** (2026-09-28 · Opus 5.5 → 4.8).
        // 바로가기 인자를 `edit` 로 떼려 했다 — 사전 기준이 미리 잰 그 길이다
        // (빠짐 1 · 기대 밖 1 `registry.strip_value`). 응시자는 그것이 해석임을
        // 스스로 밝혔다. 채점 5 는 guard 정지(종료 5) — 백업 단계에서 그 Op 을
        // 담지 못해 아무것도 파괴하지 않았다.
        //
        // **이 회차는 채점에 약 15분 걸렸다**(실측 917초). 파일 규칙의 `matches`
        // 가 레코드마다 정규식을 컴파일했다 — `c150f47` 이 패턴마다 한 번만
        // 컴파일하게 고친 뒤로는 19초다(2026-09-29 실측). 자세한 것은 NOTES.md.
        //
        // **2026-09-29 부터 린트 오류 1 이다.** `edit` 가 레지스트리 값이 아닌
        // subject 를 가리키면 린트가 막고 `remove` 를 알려 준다(`remedy-sdk`
        // lint.rs `edit_instead`) — 이 답안이 그 검사가 생긴 까닭이다. 빠짐 ·
        // 기대 밖은 그대로다(계획기는 바뀌지 않았다).
        Expected {
            dir: "2026-09-28-opus-4.8-shortcut-r1",
            threat: "shortcut-hijack",
            parses: true,
            errors: 1,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 1,
        },
        // **가이드만 바뀐 회차 — 그러나 판도 바뀌었다** (2026-09-28 · Opus 5.5,
        // 강등 없음 · r1 은 4.8). 가이드 두 문장(`8894b21`, +146 바이트) 뒤에
        // 바로가기 인자를 `remove` 로 뗐다 — 불합격(빠짐 1)에서 무경고 합격으로.
        // 사전 지문은 0 이지만 꾸러미에서 새 문장에만 있는 "인자만" 을 두 번
        // 썼다. 판이 달라 가이드 덕으로만 돌리지 않는다. 채점 5 합격.
        // 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-28-opus-5.5-shortcut-r2",
            threat: "shortcut-hijack",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **응시자가 가이드의 빈칸을 짚은 회차** (2026-09-28 · Opus 5.5 → 4.8).
        // 상대 비교(기준 파일의 시각 · 크기를 capture 해 `gt` · `lt`)를 "확인된
        // 문법이 아니다" 라며 쓰지 않았다 — 가이드 산문에 `gt` · `lt` 예가 없고
        // 무엇을 견주는지도 없다(사전 기준 ①-1). 자동 시작이 가리키는 실행 파일만
        // 잡고 라이브러리는 남긴다고 스스로 적었다 — 빠짐 1. 채점 5 도 그 한
        // 파일로 불합격, 남아야 하는 자리 3/3 그대로. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-28-opus-4.8-sideload-r1",
            threat: "sideload-drop",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 1,
        },
        // **가이드만 바뀐 회차 — 그러나 판도 바뀌었다** (2026-09-28 · Opus 5.5,
        // 강등 없음 · r1 은 4.8). 새 절(`2d1ba53`, +817 바이트) 뒤에 기준 파일의
        // 시각 · 크기를 capture 해 `gt` · `lt` 를 한 레코드에 걸었다 — 불합격
        // (빠짐 1)에서 무경고 합격으로. 자는 `remove` 에 넣지 않았다. 사전 지문은
        // 0 이지만 필드를 그대로 capture 하는 구조(새 절에만 있다)를 썼다. 판이
        // 달라 가이드 덕으로만 돌리지 않는다. 채점 5 합격. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-28-opus-5.5-sideload-r2",
            threat: "sideload-drop",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **가이드 산문에 없는 `glob` 을 밟지 않고 무경고 합격** (2026-09-28 · Opus
        // 5.5 → 4.8). 같은 `path` 에 `starts_with`(업로드 폴더) · `ends_with`(`.aspx`)
        // 를 한 규칙에 걸었다 — 사전 기준이 미리 잰 "glob 없이 두 조건" 과 같은
        // 계획이다. 판정은 근거 하나로 두고 까닭을 적었다(가이드는 근거를 늘리라고
        // 민다). `scan_roots` 를 업로드 폴더로 좁히며 "파일 수집은 재귀한다" 를
        // 가이드 없이 추론했고, 채점 5 가 하위 폴더까지 닿는 것으로 확인했다(2/2 ·
        // 남아야 하는 자리 6/6). 사전 지문 일곱은 0. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-28-opus-4.8-webshell-r1",
            threat: "webshell-upload",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **방향을 뒤집어 무경고 합격** (2026-09-28 · Opus 5.5, 강등 없음). 정답은
        // 두 규칙에 폴더를 리터럴로 적지만, 이 답안은 스크립트를 부모로 세워
        // `path` 를 capture 하고 설치 훅은 값이 그 경로를 담을 때만 맞게 했다 —
        // `first_path` 가 인터프리터 이름을 낸다는 함정(사전 기준 ①-3)을 스스로
        // 짚었다. 훅은 `remove` 로 가리켜 `remove_key` 를 이름으로 불렀고, 채점 5 의
        // 내용 검사 1/1 · 남아야 하는 자리 3/3. 사전 지문 일곱은 0 이지만 `20-detect`
        // 의 "부모가 될 수 없는 자리" 문단을 따른 흔적이 뚜렷하다. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-28-opus-5.5-npm-r1",
            threat: "npm-posthook",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **판 통제 — r1 과 같은 4.8 이 합격했다** (2026-09-28 · 출제자가 판을 골랐다).
        // 가이드는 r2 와 같고(+ 무관한 절 하나), 바로가기를 이번에는 `remove` 로
        // 가리켰다 — r1 의 `edit` 와 갈린다. 사전 지문 "인자만"(새 문장에만 있다)이
        // 치료 문맥에 셋. 사전 기준대로 r1 → r2 의 차이를 **가이드로 설명할 수
        // 있다** 까지만 적는다(한 표본 대 한 표본). 채점 5 합격 · 내용 검사 1/1.
        // 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-28-opus-4.8-shortcut-r3",
            threat: "shortcut-hijack",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **판 통제 — 꾸러미가 r2 와 바이트까지 같고, r1 과 같은 4.8 이 합격했다**
        // (2026-09-28 · 출제자가 판을 골랐다). 기준 파일에서 시각 · 크기를 capture 해
        // 한 규칙에 `gt` · `lt` 를 걸었고 자는 `remove` 에 넣지 않았다. capture 이름
        // (`when` · `bulk`)까지 새 절 예시와 같아 예시를 가까이 따른 쪽으로 적는다
        // (사후 근거). 사전 기준대로 r1 → r2 의 차이를 **새 절로 설명할 수 있다**
        // 까지만 적는다. 채점 5 합격. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-09-28-opus-4.8-sideload-r3",
            threat: "sideload-drop",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **2차 주기 — r4 의 빈칸이 닫혔다** (2026-10-01 · Opus 4.8, 5.5 에서 강등 —
        // 출제자 기록). 두 AppInit 값을 `remove` 가 아니라 `restore … to: default` 로
        // 되돌려 `registry.restore_default` 둘이 섰다 — r4 가 지금 자료로 떨어지는
        // 바로 그 자리이고, 답안이 30-antipatterns §14 를 이름으로 불렀다. 판정은 근거
        // 셋(레지스트리 · DLL 실재 · 방화벽)의 논리곱. 채점 5 합격(이 위협의 첫 실기기
        // 측정) · 내용 검사 1/1 · 남아야 하는 자리 4/4. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-10-01-opus-4.8-appinit-r5",
            threat: "appinit-implant",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // **2차 주기 — 다른 자리에서 떨어졌다** (2026-10-01 · Opus 4.8). r2 의 빈칸(cron 을
        // `persistence` 로 지워 빈 파일이 남는다)은 닫혔다 — 드롭인을 `file` 로 잡아
        // 파일째 격리한다. 그런데 복제본은 `sha256 in` 에 **자리 표시**(`FILL_IN_…`)를
        // 두어 아무것도 맞히지 않는다 — "관측 보고가 값을 주지 않았다" 는 답안의 말은
        // 맞다(출제 설계). 같은 재료로 `command` → 그 파일의 `sha256` capture → `equals`
        // 로 모으면 네 판정을 지난다(실측, NOTES.md) — 세 회차가 그 길을 못 찾았다.
        // 판정 0 · 빠짐 6 · 채점 5 불합격(지운 것 0). 자세한 것은 NOTES.md.
        //
        // **린트 오류 1 은 뒤에 생긴 검사다** (2026-10-02 · `check_sha256_literals`).
        // 그때는 오류 0 이었다 — 자리 표시 `FILL_IN_…` 가 린트를 조용히 지났고,
        // 바로 이 회차가 그 검사를 만들었다. 기록은 지금 자료로 다시 채점한 값이다.
        Expected {
            dir: "2026-10-01-opus-4.8-worm-r3",
            threat: "selfcopy-worm",
            parses: true,
            errors: 1,
            warnings: 0,
            dirty: 0,
            missed: 1,
            lacking: 6,
        },
        // **2차 주기 재시험 — 새 절이 닿았다** (2026-10-02 · Opus 4.8, 5.5 에서 강등 —
        // r3 와 같은 판). 가이드에 "값을 모르는 지문은 아는 자리에서 capture 해
        // 모은다" 절을 더한 뒤(431c2a1) 친 회차. 답안이 그 사슬 그대로다 — cron 의
        // `command` → 그 파일의 `sha256` capture → `equals` 로 복제본 전부, 거기에
        // `count(clones) >= 2` 를 더해 자가복제의 사실을 요구했다. 자리 표시 없음.
        // cron 드롭인은 r3 처럼 파일째. 경고 2 는 `scan_roots` 의 `/opt` · `/srv` 가
        // 넓다는 것(정답은 `/opt/backup` · `/srv/data`). 채점 5 합격(수행 6 · 남아야
        // 6/6). 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-10-02-opus-4.8-worm-r4",
            threat: "selfcopy-worm",
            parses: true,
            errors: 0,
            warnings: 2,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // 첫 점검 위협(2026-11-14). 여기서는 린트 · 청정 코퍼스까지 — 판정은 하네스가 잰다(54/55 · 떨어진
        // S1 은 위협 설명이 그 화면 문구를 주지 않은 출제 쪽 빈칸이었다). 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-11-14-opus-5.5-apache-r1",
            threat: "apache-h2",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
        // 위협 설명에 S1 문구를 준 뒤의 회차 — 하네스 55/55, 첫 점검 위협 합격. 자세한 것은 NOTES.md.
        Expected {
            dir: "2026-11-14-opus-5.5-apache-r2",
            threat: "apache-h2",
            parses: true,
            errors: 0,
            warnings: 0,
            dirty: 0,
            missed: 0,
            lacking: 0,
        },
    ];

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("저장소 루트")
            .to_path_buf()
    }

    #[test]
    fn every_recorded_run_still_scores_the_same() {
        let root = repo_root();
        for e in EXPECTED_RUNS {
            let dir = root.join("testbed/ai-exam/runs").join(e.dir);
            let t = threat(&root, e.threat).unwrap_or_else(|x| panic!("{}: {x}", e.dir));
            let s = score(&root, &dir, &t).unwrap_or_else(|x| panic!("{}: {x}", e.dir));
            assert_eq!(
                s.parse_error.is_none(),
                e.parses,
                "{}: 파싱 여부가 바뀌었다 {:?}",
                e.dir,
                s.parse_error
            );
            if !e.parses {
                // 파싱이 안 되면 나머지는 재지 못한 것이다. 0 을 통과로 읽지
                // 않기 위해 여기서 멈춘다.
                continue;
            }
            assert_eq!(s.lint_errors, e.errors, "{}: 린트 오류", e.dir);
            assert_eq!(s.lint_warnings(), e.warnings, "{}: 린트 경고", e.dir);
            assert_eq!(s.dirty.len(), e.dirty, "{}: 청정 파괴 {:?}", e.dir, s.dirty);
            assert_eq!(
                s.missed.len(),
                e.missed,
                "{}: 감염 미탐 {:?}",
                e.dir,
                s.missed
            );
            assert_eq!(
                s.lacking.len(),
                e.lacking,
                "{}: 계획 빠짐 {:?}",
                e.dir,
                s.lacking
            );
        }
    }

    #[test]
    fn the_table_covers_every_run_on_disk() {
        // **회차를 넣고 표를 안 고치면 그 회차는 아무도 안 본다.**
        let dir = repo_root().join("testbed/ai-exam/runs");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        on_disk.sort();
        let mut listed: Vec<String> = EXPECTED_RUNS.iter().map(|e| e.dir.to_string()).collect();
        listed.sort();
        assert_eq!(
            on_disk, listed,
            "runs/ 와 EXPECTED_RUNS 가 갈라졌다 — 새 회차를 기록하지 않았거나 지웠다"
        );
    }

    /// 임시 폴더에 매니페스트 하나를 두고 채점한다. 끝나면 지운다.
    fn score_text(threat_name: &str, text: &str, tag: &str) -> Result<Score, String> {
        let root = repo_root();
        let dir = std::env::temp_dir().join(format!("remedy-exam-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        std::fs::write(dir.join("plugin.yaml"), text)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        let t = threat(&root, threat_name).unwrap_or_else(|e| panic!("{threat_name}: {e}"));
        let s = score(&root, &dir, &t);
        let _ = std::fs::remove_dir_all(&dir);
        s
    }

    /// 크기 조건 하나만 보는 Windows 전용 답 — 청정 기계의 작은 파일을 전부 건다
    /// (2026-09-28 webshell-r1 사전 기준의 변형).
    const SIZE_ONLY: &str = r#"schema_version: 1
id: size-only
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name: { ko: '변형', en: 'variant' }
scan_roots: ['C:\inetpub\wwwroot']
subjects: [file]
detect:
  - id: shell
    subject: file
    where:
      - { field: size, op: lt, value: 2048 }
verdict: { require: 'shell' }
remediate:
  remove:
    - { ref: shell }
"#;

    #[test]
    fn a_plan_the_guard_rejects_on_the_clean_corpus_is_scored_as_dirty() {
        // **채점이 멈추면 그 회차를 기록할 수 없다.** 크기 조건 하나는 guard 가
        // 계획을 거부할 만큼 건다(G5). 청정 코퍼스에서 부수려 한 것이므로 파괴로 센다.
        let s = score_text("webshell-upload", SIZE_ONLY, "clean-guard")
            .unwrap_or_else(|e| panic!("채점이 멈췄다: {e}"));
        assert!(
            s.dirty
                .iter()
                .any(|d| d.contains("guard 거부") && d.contains("[G5]")),
            "{:?}",
            s.dirty
        );
        assert!(!s.passed());
    }

    #[test]
    fn a_destruction_on_another_platform_is_marked_but_still_counted() {
        // **세는 기준은 G1 과 같다** — 제품의 청정 코퍼스 게이트(`remedy-core`
        // tests/corpus.rs)는 플랫폼과 무관하게 모든 스냅샷을 본다. 실행 시점에
        // `platforms` 로 거르는 곳이 없고 `%ALLUSERPROFILES%` 는 Linux 에서도 홈을
        // 펼치기 때문이다. 다만 읽는 사람이 헷갈리지 않게 **다른 플랫폼이라고
        // 적는다** (2026-09-29 결정 — 표시만 가른다).
        let s = score_text("webshell-upload", SIZE_ONLY, "foreign-mark")
            .unwrap_or_else(|e| panic!("채점이 멈췄다: {e}"));
        let linux: Vec<&String> = s
            .dirty
            .iter()
            .filter(|d| d.starts_with("docker-"))
            .collect();
        let windows: Vec<&String> = s
            .dirty
            .iter()
            .filter(|d| d.starts_with("win10x64-"))
            .collect();
        assert!(!linux.is_empty() && !windows.is_empty(), "{:?}", s.dirty);
        assert!(
            linux.iter().all(|d| d.contains("다른 플랫폼(linux)")),
            "Windows 전용 답의 Linux 스냅샷 파괴에 표시가 없다: {linux:?}"
        );
        assert!(
            windows.iter().all(|d| !d.contains("다른 플랫폼")),
            "자기 플랫폼의 파괴에 표시가 붙었다: {windows:?}"
        );
    }

    #[test]
    fn a_plan_the_guard_rejects_on_the_infected_snapshot_lacks_every_op() {
        // hosts · 프록시를 `restore` 가 아니라 `remove` 에 두면 감염 기계에서 계획이
        // 거부된다(G6 — hosts 가 읽기 상한 밖). 치료가 하나도 일어나지 않으므로
        // 기대 Op 이 전부 빠진다 (2026-09-27 proxy-r1 사전 기준의 변형).
        let root = repo_root();
        let path =
            root.join("testbed/ai-exam/threats/proxy-dns-hijack/reference-plugin/plugin.yaml");
        let src =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let old = "  restore:\n    - hosts # hosts.restore_line — 돌려진 줄 둘에 각각\n    \
                   - proxy # proxy.restore\n  remove:\n";
        assert_eq!(
            src.matches(old).count(),
            1,
            "정답의 restore 절 모양이 바뀌었다"
        );
        let text = src.replace(
            old,
            "  remove:\n    - { ref: redirect }\n    - { ref: proxy }\n",
        );
        let s = score_text("proxy-dns-hijack", &text, "infected-guard")
            .unwrap_or_else(|e| panic!("채점이 멈췄다: {e}"));
        assert!(
            s.rejected
                .iter()
                .any(|r| r.contains("guard 거부") && r.contains("[G6]")),
            "{:?}",
            s.rejected
        );
        assert_eq!(
            s.lacking.len(),
            s.expected_ops,
            "치료가 하나도 일어나지 않았으니 기대가 전부 빠진다: {:?}",
            s.lacking
        );
        assert!(s.dirty.is_empty(), "{:?}", s.dirty);
        assert!(!s.passed());
    }

    use super::REFERENCES;

    #[test]
    fn every_threat_has_a_reference_answer_that_passes() {
        let root = repo_root();
        let mut names = threat_names(&root);
        names.sort();
        let mut listed: Vec<String> = REFERENCES.iter().map(|(n, _)| n.to_string()).collect();
        listed.sort();
        assert_eq!(
            names, listed,
            "위협과 참조 답안이 갈라졌다 — 새 위협에 정답을 두지 않았다"
        );

        for (name, path) in REFERENCES {
            let t = threat(&root, name).unwrap_or_else(|e| panic!("{name}: {e}"));
            let s = score(&root, &root.join(path), &t).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                s.passed(),
                "{name}: 정답이 자기 기준을 못 넘는다 {:?}",
                s.failures()
            );
            // **정답이 계획하는 것은 전부 기대 목록에 있어야 한다.**
            //
            // `passed()` 는 `expected ⊆ planned` 만 본다(기대 밖은 불합격
            // 사유가 아니다). 그래서 기대 목록에서 한 줄을 지워도 정답은
            // 그대로 합격이고, **그 줄이 요구하던 것은 조용히 요구되지 않게
            // 된다** — 2026-09-04 에 닫은 절반짜리 치료 구멍이 정확히 그 모양으로
            // 다시 열린다.
            //
            // 정답의 계획이 곧 기대 목록의 출처이므로 둘은 같아야 한다.
            assert!(
                s.extra.is_empty(),
                "{name}: 정답이 계획하는데 expected-ops.txt 에 없는 것이 있다: {:?}\n\
                 기대 목록에서 지워지면 그 요구가 조용히 사라진다. 정답의 계획을 \
                 그대로 옮길 것.",
                s.extra
            );
            // **정답은 같은 것을 두 번 하지 않는다.**
            //
            // 겹침은 불합격 사유가 아니다 — 응시자에게는 보여만 준다. 그러나
            // 우리 정답이 겹치기 시작하면 그것은 답안의 성질이 아니라
            // **코어의 팬아웃이 바뀐 것**이고, 그때는 아무도 말해 주지 않는다.
            //
            // 2026-09-05 기준 여섯 전부 0이다. 이 줄이 깨지면 계획기를 먼저
            // 볼 것 — 증거 그룹이 하나여야 할 자리에서 둘이 되지 않았는지.
            assert_eq!(
                s.duplicates(),
                0,
                "{name}: 정답이 같은 자리표를 {}번 겹쳐 낸다 (계획 {}건 · 서로 다른 것 {}건)",
                s.duplicates(),
                s.planned_total,
                s.planned_distinct()
            );
        }
    }

    /// **정답이 목록이나 리터럴 해시로 가르는 값은 위협 설명에 실려 있어야 한다.**
    ///
    /// `in` 목록(해시 · 도메인)은 위협 정보가 주는 값이라 응시자가 만들어 낼 수
    /// 없다. 위협 설명에 없으면 **정답만 도달하는 문제**가 된다 — 출제 메모가
    /// 스스로 경고한 *"문제와 채점 데이터가 갈라지면 응시자는 도달할 수 없다"*.
    ///
    /// 2026-09-27 `c2-r1` 에서 실제로 그랬다. `c2-beacon` 본문에 다이제스트 넷이
    /// 없었고, 응시자는 값을 지어내지 않고 자리 채우기를 두었다 — 불합격은
    /// 문제의 결함이었다. 위의 검사는 이것을 잡지 못한다: 정답은 값을 **이미
    /// 알고 있다.**
    ///
    /// **`equals` 의 리터럴 해시도 같은 값이다** (2026-10-02). `selfcopy-worm` 정답
    /// 1.0.0 은 `sha256 equals 311778ae…` — `infected/` 에서 읽은 값 — 로 다섯을
    /// 집었고, 위협 설명은 설계대로 그 값을 주지 않았다. 이 검사는 `in` 만 봐서
    /// 조용했고, `worm-r1` 과 `worm-r3` 가 같은 자리에 자리 표시를 두고 떨어진
    /// 뒤에야 사람이 찾았다. 그래서 **64자 16진 리터럴은 연산자를 가리지 않고**
    /// 본다. `${…}` 로 풀리는 값(기계에서 뽑는 지문)은 리터럴이 아니라 걸리지
    /// 않는다 — 그것이 1.0.1 의 답이다.
    #[test]
    fn every_listed_value_in_a_reference_answer_is_in_its_threat() {
        fn is_sha256_literal(s: &str) -> bool {
            s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
        }
        fn collect_literals(v: &serde_yaml_ng::Value, out: &mut Vec<String>) {
            match v {
                serde_yaml_ng::Value::Sequence(xs) => {
                    xs.iter().for_each(|x| collect_literals(x, out))
                }
                serde_yaml_ng::Value::Mapping(m) => {
                    let is_in = m.get("op").and_then(|o| o.as_str()) == Some("in");
                    match m.get("value") {
                        Some(serde_yaml_ng::Value::Sequence(vals)) if is_in => {
                            out.extend(vals.iter().filter_map(|x| x.as_str().map(str::to_string)));
                        }
                        // `equals` 든 무엇이든 — 해시 모양의 리터럴은 위협 정보의 값이다.
                        Some(serde_yaml_ng::Value::String(s)) if is_sha256_literal(s) => {
                            out.push(s.clone());
                        }
                        _ => {}
                    }
                    m.values().for_each(|x| collect_literals(x, out));
                }
                _ => {}
            }
        }

        let root = repo_root();
        let mut missing = Vec::new();
        let mut checked = 0;
        for (name, path) in REFERENCES {
            let yaml = std::fs::read_to_string(root.join(path).join("plugin.yaml"))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let m: serde_yaml_ng::Value =
                serde_yaml_ng::from_str(&yaml).unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut values = Vec::new();
            for rule in m
                .get("detect")
                .and_then(|d| d.as_sequence())
                .into_iter()
                .flatten()
            {
                if let Some(w) = rule.get("where") {
                    collect_literals(w, &mut values);
                }
            }
            if values.is_empty() {
                continue;
            }
            let text = std::fs::read_to_string(
                root.join("testbed/ai-exam/threats")
                    .join(name)
                    .join("THREAT.md"),
            )
            .unwrap_or_else(|e| panic!("{name}: {e}"));
            let body =
                between_rules("THREAT.md", &text, 1).unwrap_or_else(|e| panic!("{name}: {e}"));
            checked += 1;
            for v in values {
                if !body.contains(&v) {
                    missing.push(format!("{name}: {v}"));
                }
            }
        }
        // **검사가 일하고 있는지 본다.** 목록을 쓰는 정답이 하나도 없으면 이
        // 검사는 아무것도 재지 않고 초록이 된다. 2026-09-27 기준 셋이다 —
        // `c2-beacon`(해시 넷 · 도메인 셋) · `ssh-backdoor` · `ransomware`.
        assert!(
            checked >= 3,
            "목록을 쓰는 정답이 {checked}개뿐이다 — 검사가 헛돈다"
        );
        assert!(
            missing.is_empty(),
            "정답이 목록이나 리터럴 해시로 가르는 값이 위협 설명(THREAT.md 구분선 아래)에 없다:\n  {}\n\
             응시자는 그 값을 만들어 낼 수 없다 — 문제가 도달할 수 없게 된다. 값을 본문에 \
             싣거나, 정답이 그 값을 기계에서 뽑게(capture · `${{…}}`) 할 것.",
            missing.join("\n  ")
        );
    }

    /// 기대 목록이 **대상까지** 적고 있는가 — 조인 것이 조용히 풀리지 않게.
    ///
    /// `load_expected_ops` 가 Op 이름만 적힌 줄을 오류로 막지만, 그것만으로는
    /// 부족하다. 누군가 자리표를 **하나씩만** 남기면(같은 Op 의 둘째 대상을
    /// 지우면) 파일은 여전히 자리표 모양이고 검사도 통과하는데, 절반짜리
    /// 치료는 다시 지나간다.
    ///
    /// 그래서 **구분이 실제로 일하고 있는지**를 본다. 같은 Op 이 대상만 달리
    /// 두 번 이상 나오는 위협이 하나도 없으면, 이 형식은 종류만 세던 때와
    /// 구별되지 않는다.
    ///
    /// 2026-09-04 기준으로 그런 위협이 넷이다 — `appinit-implant`(등록값 둘 ·
    /// 파일 둘) · `service-userinit`(파일 둘) · `search-hijack`(확장 둘) ·
    /// `tls-intercept`(hosts 줄 둘 · 파일 둘).
    #[test]
    fn expected_ops_still_name_their_targets() {
        let root = repo_root();
        let mut discriminating = Vec::new();

        for name in threat_names(&root) {
            let t = threat(&root, &name).unwrap_or_else(|e| panic!("{name}: {e}"));
            // 점검 위협에는 기대 Op 이 없다 — 판정은 그 위협의 하네스가 잰다.
            if t.is_check() {
                continue;
            }
            let expected = load_expected_ops(&t).unwrap_or_else(|e| panic!("{name}: {e}"));

            // 자리표는 `<op> <대상>` 이다. Op 이름만 남은 줄은 로더가 이미
            // 막지만, 여기서도 본다 — 로더를 느슨하게 고치면 이 줄이 남는다.
            for line in &expected {
                assert!(
                    line.contains(' '),
                    "{name}: '{line}' 에 대상이 없다. Op 종류만 세면 값 하나만 \
                     지운 답과 둘 다 지운 답이 구별되지 않는다"
                );
            }

            let kinds: BTreeSet<&str> = expected
                .iter()
                .filter_map(|l| l.split(' ').next())
                .collect();
            if expected.len() > kinds.len() {
                discriminating.push(name.clone());
            }
        }

        assert!(
            !discriminating.is_empty(),
            "같은 Op 을 대상만 달리 두 번 이상 기대하는 위협이 하나도 없다.\n\
             그러면 이 형식은 Op 종류만 세던 때와 구별되지 않고, 절반짜리 치료가 \
             다시 지나간다 — 2026-09-04 에 실측으로 확인한 그 구멍이다.\n\
             기대 목록을 정답 플러그인의 계획에서 다시 옮길 것."
        );
    }

    /// **겹침 세기가 공허하지 않은가.**
    ///
    /// 위의 정답 게이트는 `duplicates() == 0` 을 요구한다. 그런데 그 계산이
    /// 망가져 언제나 0 을 내놓으면 게이트는 영원히 초록이고, 우리는 정답이
    /// 깨끗하다고 믿게 된다. `the_gate_can_actually_bite…` 와 같은 이유로
    /// **0 이 아닌 값을 실제로 내는 회차 하나**를 걸어 둔다.
    ///
    /// 2026-09-05 `hijack-r3` 이 그것이다. `payload` 가 capture 를 가진 뿌리
    /// 규칙이고 파일 둘을 맞혀 증거 그룹이 둘로 팬아웃한다 — 둘 다 같은
    /// `${payload.dir}` 을 풀어 같은 하위 Action 을 각각 만든다.
    ///
    /// **그 회차는 합격이다.** 겹침은 불합격 사유가 아니고, 실행기가
    /// *"지울 것이 이미 없다"* 를 성공으로 다루므로 해롭지도 않다. 다만
    /// 여덟 가지를 하는 계획이 열넷이라고 말하는 것을 사람이 봐야 한다.
    #[test]
    fn the_duplicate_count_is_not_always_zero() {
        let root = repo_root();
        let t = threat(&root, "search-hijack").expect("위협");
        let dir = root.join("testbed/ai-exam/runs/2026-09-05-opus-5-hijack-r3");
        let s = score(&root, &dir, &t).expect("채점");

        assert_eq!(
            s.planned_total, 14,
            "계획 건수가 바뀌었다 — 팬아웃이 달라졌나"
        );
        assert_eq!(s.planned_distinct(), 8, "서로 다른 자리표가 바뀌었다");
        assert_eq!(
            s.duplicates(),
            6,
            "겹침 세기가 이 회차에서 0 이 아니어야 한다 — 정답 게이트가 공허해진다"
        );
        assert!(
            s.passed(),
            "겹침은 불합격 사유가 아니다: {:?}",
            s.failures()
        );
    }

    #[test]
    fn the_first_plugin_passes_its_own_exam() {
        // **정답이 자기 시험을 못 넘기면 시험 쪽이 틀린 것이다.**
        let root = repo_root();
        let t = threat(&root, DEFAULT_THREAT).expect("기본 위협");
        let s = score(&root, &root.join("plugins/evilai-locust"), &t).expect("첫 플러그인");
        assert!(s.passed(), "첫 플러그인이 불합격이다: {:?}", s.failures());
    }

    /// **점검 위협의 꾸러미는 점검을 말한다.** 치료 위협의 머리말과 프롬프트("탐지하고 제거하는" · "감염 상태를
    /// 세우고 관측한 보고")가 점검 위협에 실리면 응시자는 지울 것을 찾는다 — 점검 룰은 아무것도 바꾸지 않는다.
    /// 그리고 점검 위협이 하나도 없으면 이 갈래는 아무도 재지 않는다.
    #[test]
    fn a_check_threat_bundle_speaks_of_checking_not_removal() {
        let root = repo_root();
        let checks: Vec<String> = threat_names(&root)
            .into_iter()
            .filter(|n| threat(&root, n).is_ok_and(|t| t.is_check()))
            .collect();
        assert!(!checks.is_empty(), "점검 위협이 하나도 없다");
        // 점검 룰 안내는 점검 위협의 꾸러미에만 — 치료 위협에는 오도가 된다(2026-10-25 결정).
        let guide = format!("파일: {}", INJECT_CHECK[0]);
        let cure = bundle(&root, &threat(&root, DEFAULT_THREAT).unwrap()).unwrap();
        assert!(
            !cure.contains(&guide),
            "치료 위협의 꾸러미에 점검 룰 안내가 실렸다"
        );
        for name in checks {
            let t = threat(&root, &name).unwrap();
            let text = bundle(&root, &t).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                text.starts_with(HEADER_CHECK),
                "{name}: 점검 머리말이 아니다"
            );
            assert!(
                text.contains("**점검하는** 플러그인"),
                "{name}: 점검 프롬프트가 아니다"
            );
            assert!(text.contains(&guide), "{name}: 점검 룰 안내가 없다");
            for cure in ["탐지하고 제거하는", "감염 상태를", "지우는 대상이 전부"]
            {
                assert!(
                    !text.contains(cure),
                    "{name}: 치료 위협의 문구 '{cure}' 가 실렸다"
                );
            }
            // 판정은 하네스가 재므로 여기서는 린트 · 청정 코퍼스까지다 — 그 둘을 정답이 넘어야 한다.
            let reference = REFERENCES
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("{name}: 정답이 표에 없다"))
                .1;
            let s = score(&root, &root.join(reference), &t).unwrap();
            assert!(s.passed(), "{name}: 정답이 불합격이다: {:?}", s.failures());
            assert_eq!(
                (s.infected_total, s.expected_ops),
                (0, 0),
                "{name}: 감염 · 기대 Op 을 쟀다"
            );
        }
    }
}
