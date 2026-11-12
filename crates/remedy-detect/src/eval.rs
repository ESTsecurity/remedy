//! 룰 평가 — 증거 그룹 · 참조 DAG · capture · `verdict.require` (설계-02 §4·§5).
//!
//! 입력은 **아티팩트 스냅샷뿐**이다. 이 크레이트는 `remedy-platform` 에 의존할 수
//! 없으므로(설계-04 §1) 시스템에 닿을 방법 자체가 없다. 탐지는 불활성 스냅샷
//! 위에서만 돈다.
//!
//! 그 덕분에 같은 스냅샷을 두 번 평가하면 바이트까지 같은 결과가 나온다. 결정성이
//! 없으면 계획 비교 회귀 검증이 성립하지 않는다 (설계-09 P2).

use crate::expr;
use crate::verdict;
use remedy_artifacts::Scope;
use remedy_sdk::artifact::{Evidence, EvidenceGroup, MatchedPredicate, ScanBody};
use remedy_sdk::catalog::{Operator, Phase, Subject};
use remedy_sdk::manifest::{Condition, DetectRule, PluginManifest, Predicate};
use remedy_sdk::normalize;
use std::collections::{BTreeMap, BTreeSet};

/// 그룹 수 안전 상한.
///
/// 진짜 상한은 계획 단계에 있다(설계-03 §4, P3). 여기 있는 것은 평가가 메모리를
/// 먹어 치우는 것을 막는 최소한의 방어다. 여기 걸리면 룰이 지나치게 넓다는 뜻이고,
/// 그것은 치료할 일이 아니라 룰 오류다.
const MAX_GROUPS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalError(pub String);

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 평가에 쓰는 스냅샷 뷰. subject 별 레코드를 `Value` 로 들고 있다.
///
/// 타입별 분기 대신 `Value` 를 쓰는 이유는 subject 가 P4 에서 16종 늘기 때문이다.
/// 필드 조회를 한 곳에 모아 두면 늘어나는 것은 레코드 정의뿐이다.
pub struct Snapshot {
    by_subject: BTreeMap<Subject, Vec<serde_json::Value>>,
    /// 훑을 수 있는 본문. 키는 레코드의 `content_ref` 다.
    ///
    /// **비어 있는 것이 기본이다.** `collect_extra` 로 선언한 것만 담기므로,
    /// 대부분의 레코드에는 훑을 바이트가 없다. 그런 대상에 걸린 YARA 규칙은
    /// 미매치가 아니라 **미평가**이며 그 사실이 보고된다 (설계-03 §1).
    blobs: BTreeMap<String, Vec<u8>>,
    /// 플러그인이 실은 `.yar` 들. 없으면 YARA 규칙은 전부 **미평가**다.
    rules: Option<remedy_yara::RuleSet>,
}

impl Snapshot {
    /// **subject 이름으로 훑는다.** 종류를 여기 나열하면 수집기에 subject 를
    /// 더할 때마다 이 목록도 따라 늘어야 하고, 빠뜨리면 수집은 됐는데
    /// 평가되지 않는 조용한 구멍이 생긴다.
    pub fn from_envelope(env: &remedy_sdk::artifact::ArtifactsEnvelope) -> Self {
        let mut by_subject = BTreeMap::new();
        for s in Subject::ALL {
            let Some(v) = env.body.observations.get(s.id()) else {
                continue;
            };
            let mut records: Vec<serde_json::Value> = match v {
                serde_json::Value::Array(a) => a.clone(),
                // 목록이 아닌 것은 레코드 집합이 아니다. 조용히 빈 것으로
                // 다루면 그 subject 는 "없다" 로 읽힌다.
                _ => continue,
            };
            // 결정성을 위해 정렬한다. 수집기가 이미 정렬해 주지만 스냅샷은 손으로
            // 만들어질 수도 있다.
            records.sort_by_key(key_of);
            by_subject.insert(s, records);
        }
        // base64 를 여기서 한 번만 푼다. 술어마다 풀면 같은 파일을 규칙 수만큼
        // 다시 디코딩한다.
        let blobs = env
            .body
            .blobs
            .iter()
            .filter_map(|(k, v)| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(v)
                    .ok()
                    .map(|b| (k.clone(), b))
            })
            .collect();
        Self {
            by_subject,
            blobs,
            rules: None,
        }
    }

    /// 플러그인이 실은 YARA 룰을 붙인다. `(파일 이름, 원문)` 목록이다.
    ///
    /// 스냅샷과 따로 받는 이유: 룰은 **플러그인의 것**이고 스냅샷은 관찰이다.
    /// 같은 스냅샷을 다른 플러그인으로 평가할 수 있어야 한다.
    pub fn with_rules(mut self, sources: &[(String, String)]) -> Self {
        if !sources.is_empty() {
            self.rules = Some(remedy_yara::RuleSet::compile(sources));
        }
        self
    }

    /// 컴파일하지 못한 룰 파일. 평가 시작 전에 사람에게 알려야 한다.
    pub fn broken_rule_files(&self) -> Vec<(String, String)> {
        self.rules
            .as_ref()
            .map(|r| {
                r.failed
                    .iter()
                    .map(|(f, e)| (f.clone(), e.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn records(&self, s: Subject) -> &[serde_json::Value] {
        self.by_subject.get(&s).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// 레코드의 안정적인 식별자. 정렬과 증거 순서를 결정한다.
fn key_of(v: &serde_json::Value) -> String {
    for k in ["path", "id"] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()) {
            return s.to_string();
        }
    }
    v.to_string()
}

// ─────────────────────────────────────────────────────── 참조 DAG

/// 규칙이 참조하는 다른 규칙 id 들.
fn refs_of(rule: &DetectRule) -> BTreeSet<String> {
    let mut keys = Vec::new();
    if let Some(f) = &rule.from {
        expr::references(f, &mut keys);
    }
    for e in rule.capture.values() {
        expr::references(e, &mut keys);
    }
    collect_condition_refs(&rule.condition, &mut keys);
    for p in &rule.exclude {
        collect_predicate_refs(p, &mut keys);
    }

    keys.into_iter()
        // `${name}` 은 같은 규칙 안의 capture 다. `${rule.name}` 만 규칙 참조다.
        .filter_map(|k| k.split_once('.').map(|(r, _)| r.to_string()))
        .filter(|r| r != &rule.id)
        .collect()
}

fn collect_condition_refs(c: &Condition, out: &mut Vec<String>) {
    match c {
        Condition::All(a) => a.all.iter().for_each(|x| collect_condition_refs(x, out)),
        Condition::Any(a) => a.any.iter().for_each(|x| collect_condition_refs(x, out)),
        Condition::List(l) => l.iter().for_each(|x| collect_condition_refs(x, out)),
        Condition::One(p) => collect_predicate_refs(p, out),
    }
}

fn collect_predicate_refs(p: &Predicate, out: &mut Vec<String>) {
    if let Predicate::Field(f) = p {
        if let Some(serde_json::Value::String(s)) = &f.value {
            expr::references(s, out);
        }
    }
}

/// 판정식이 짚는 규칙 id — 식에 적힌 차례, 중복 없이. `a or (a and b)` 는 `[a, b]` 다.
fn rules_named(e: &verdict::Expr) -> Vec<String> {
    let mut all = Vec::new();
    verdict::referenced_rules(e, &mut all);
    let mut out: Vec<String> = Vec::with_capacity(all.len());
    for r in all {
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

/// 위상 정렬. 순환 참조는 거부한다 — **평가 순서를 플러그인 작성자가 적지 않는다.**
fn topo_order(rules: &[DetectRule]) -> Result<Vec<usize>, EvalError> {
    let index: BTreeMap<&str, usize> = rules
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), i))
        .collect();

    let mut deps: Vec<BTreeSet<usize>> = Vec::with_capacity(rules.len());
    for r in rules {
        let mut d = BTreeSet::new();
        for name in refs_of(r) {
            match index.get(name.as_str()) {
                Some(i) => {
                    d.insert(*i);
                }
                None => {
                    return Err(EvalError(format!(
                        "규칙 '{}' 가 없는 규칙 '{}' 를 참조합니다",
                        r.id, name
                    )))
                }
            }
        }
        deps.push(d);
    }

    let mut done = vec![false; rules.len()];
    let mut order = Vec::with_capacity(rules.len());
    while order.len() < rules.len() {
        // 매 회차에서 준비된 것 중 **선언 순서가 앞선 것**을 고른다. 결정적이다.
        let next = (0..rules.len()).find(|&i| !done[i] && deps[i].iter().all(|&d| done[d]));
        match next {
            Some(i) => {
                done[i] = true;
                order.push(i);
            }
            None => {
                let stuck: Vec<&str> = (0..rules.len())
                    .filter(|&i| !done[i])
                    .map(|i| rules[i].id.as_str())
                    .collect();
                return Err(EvalError(format!(
                    "규칙 참조에 순환이 있습니다: {}",
                    stuck.join(" · ")
                )));
            }
        }
    }
    Ok(order)
}

// ─────────────────────────────────────────────────────── 술어 평가

/// 비교 전 정규화.
///
/// P2 결정: `equals`·`contains`·`starts_with`·`ends_with` 는 **Windows 에서
/// 대소문자를 무시**한다. OS 자신의 의미와 같고, 그러지 않으면 `NODE.EXE` 와
/// `node.exe` 가 다른 것이 되어 조용한 미탐을 만든다.
///
/// `matches` 는 예외다 — 정규식의 대소문자는 룰이 `(?i)` 로 직접 정한다. 첫
/// 플러그인의 룰이 실제로 그렇게 적혀 있다.
fn norm_for_compare(s: &str, scope: &Scope) -> String {
    let n = normalize::nfc(s);
    if scope.platform == remedy_sdk::catalog::Platform::Windows {
        normalize::fold_case(&n)
    } else {
        n
    }
}

struct PredOutcome {
    matched: bool,
    record: Option<MatchedPredicate>,
    /// **재지 못했다** — `matched` 는 거짓이지만 *"안 맞았다"* 가 아니라 *"모른다"*
    /// 다. [`Issues::unevaluated`] 만 이것을 세운다.
    unknown: bool,
}

/// 조건의 값. **재지 못한 YARA 는 거짓이 아니라 `Unknown` 이다** (결정 2026-10-26).
///
/// 조건에는 부정이 없으므로(`all` · `any` · 목록뿐) 3값 논리가 정확하다 —
/// `Unknown` 은 *"재지 못한 술어가 무엇을 냈느냐에 따라 결과가 갈린다"* 와 같은
/// 뜻이다. 그래서 **술어 순서와 무관하다.** `[yara, path]` 와 `[path, yara]` 는
/// 같은 값을 낸다 — 거짓을 거짓으로 볼 때는 둘이 달랐다(2026-10-26 적대 검증).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tri {
    False,
    Unknown,
    True,
}

impl From<&PredOutcome> for Tri {
    fn from(o: &PredOutcome) -> Self {
        if o.unknown {
            Tri::Unknown
        } else if o.matched {
            Tri::True
        } else {
            Tri::False
        }
    }
}

/// `any` — 참이 하나라도 있으면 참이다. `exclude` 가 쓴다(조건은 [`eval_any`]).
fn any3(items: impl Iterator<Item = Tri>) -> Tri {
    let mut out = Tri::False;
    for t in items {
        match t {
            Tri::True => return Tri::True,
            Tri::Unknown => out = Tri::Unknown,
            Tri::False => {}
        }
    }
    out
}

/// 평가 한 번 동안 쓰는 정규식 — 패턴(보간 · 정규화 뒤) → 컴파일 결과.
///
/// **`matches` 는 레코드마다 불린다.** 거기서 컴파일하면 같은 정규식을 레코드
/// 수만큼 다시 만든다 — 2026-09-28 `shortcut-r1` 채점이 파일 레코드 12만여 건에서
/// 917초였고, 같은 뜻의 `contains` 로는 15초였다.
///
/// `evaluate` · `pressure` 한 번의 수명만 산다. 전역에 두지 않으므로 모듈 머리의
/// 결정성이 그대로이고, 컴파일 오류도 담아 두어 보고 문구가 전과 같다.
type Regexes = BTreeMap<String, Result<regex::Regex, String>>;

/// 평가 한 번이 남기는 문제 — **사람이 읽을 메시지**와 **재지 못한 YARA**.
///
/// # 왜 둘을 한 자리에 드는가 (결정 2026-10-26)
///
/// YARA 를 재지 못한 갈래는 메시지와 함께 그 규칙을 관측에 남겨야 한다 —
/// 메시지만 남으면 판정이 없을 때 종료 코드 0 "위협 없음" 이 나갔다(2026-10-25
/// 적대 검증 · 재현). 메시지 문자열을 다시 읽어 규칙을 뽑으면 **문구를 고치는 날
/// 조용히 끊긴다.** 그래서 갈래가 직접 [`Issues::unevaluated`] 를 부른다.
///
/// # 재지 못한 것은 그것이 무엇을 갈랐는지 보고 거른다
///
/// 조건의 갈래마다 · 레코드마다 새 `Issues` 에 모았다가 [`Issues::absorb`] 로
/// 올린다. 재지 못한 YARA 는 **그 갈래가 [`Tri::Unknown`] 으로 끝났을 때만**
/// 올라간다 — 형제 술어가 이미 거짓으로 정한 `all`, 다른 갈래가 이미 참인 `any`,
/// 확정 제외 · capture 실패로 어차피 증거가 안 되는 레코드에서는 YARA 가 무엇을
/// 냈어도 결과가 같다. **판정식은 보지 않는다** — 다른 필수 규칙이 0 이라 판정이
/// 어차피 서지 않아도 올라간다(보수 쪽 · 사고-대응-도구-구조-설계 §11).
#[derive(Default)]
struct Issues {
    messages: Vec<String>,
    unevaluated: Vec<Unevaluated>,
}

/// 재지 못한 것이 **무엇인가.**
///
/// 사유 줄의 낱말이 갈린다 — *"YARA 규칙을 평가하지 못했습니다"* 와 *"버전을
/// 견주지 못했습니다"* 는 읽는 사람이 할 일이 다르다(본문을 담게 고치는 것 ·
/// 꼬리를 가릴 방법을 찾는 것). 둘을 한 줄에 넣으면 화면이 재지 못한 것을
/// **잘못 지목한다**.
enum Unmeasured {
    YaraRule,
    Version,
}

/// 재지 못한 술어 하나.
struct Unevaluated {
    what: Unmeasured,
    /// YARA 면 `rules/<파일>.yar:<룰 이름>`([`yara_label`]), 버전이면 읽지 못한
    /// 값이다.
    rule: String,
    /// 사람이 읽을 이유.
    why: String,
    /// 레코드와 무관한 **플러그인의 결함**인가 — 룰 파일 없음 · 참조 오류 · 룰
    /// 이름 없음 · 컴파일 실패 · 아직 없는 필드. 결과를 가르지 않았어도 이유
    /// 줄은 남긴다. 버리면 그 결함이 청정 기계에서 보이지 않는다 — 전에는
    /// 술어 순서에 따라 보였다(2026-10-26 적대 검증).
    plugin: bool,
}

impl Issues {
    fn push(&mut self, message: impl Into<String>) {
        self.messages.push(message.into());
    }

    /// YARA 술어 하나를 이 **레코드에서** 재지 못했다 — 본문이 없다 · 필드가 없다.
    /// 규칙과 이유를 적고 *"모른다"* 를 돌려준다.
    fn unevaluated(&mut self, rule: impl Into<String>, why: impl Into<String>) -> PredOutcome {
        self.unknown(Unmeasured::YaraRule, rule.into(), why.into(), false)
    }

    /// 버전으로 읽지 못해 **견주지 못했다.** *"안 맞았다"* 로 돌려주면 취약한
    /// 기계가 종료 0 으로 나간다(실측 2026-10-27) — YARA 와 같은 레일을 탄다.
    ///
    /// `plugin` 은 **룰이 적은 값**을 읽지 못했을 때다. 린트가 리터럴은 미리
    /// 거절하므로 그 길은 `${…}` 로 풀린 값뿐이고, 결과를 가르지 않았어도 이유
    /// 줄은 남겨야 그 결함이 보인다.
    fn unreadable_version(
        &mut self,
        value: impl Into<String>,
        why: impl Into<String>,
        plugin: bool,
    ) -> PredOutcome {
        self.unknown(Unmeasured::Version, value.into(), why.into(), plugin)
    }

    /// YARA 술어 하나를 **플러그인 때문에** 재지 못했다. [`Issues::unevaluated`]
    /// 와 같되, 결과를 가르지 않았어도 이유 줄은 남는다([`Unevaluated::plugin`]).
    fn broken(&mut self, rule: impl Into<String>, why: impl Into<String>) -> PredOutcome {
        self.unknown(Unmeasured::YaraRule, rule.into(), why.into(), true)
    }

    /// 메시지는 버리고 재지 못한 것만 남긴다 — `exclude` 의 문제는 전부터 버렸다.
    fn unevaluated_only(self) -> Issues {
        Issues {
            messages: Vec::new(),
            unevaluated: self.unevaluated,
        }
    }

    fn unknown(
        &mut self,
        what: Unmeasured,
        rule: String,
        why: String,
        plugin: bool,
    ) -> PredOutcome {
        self.unevaluated.push(Unevaluated {
            what,
            rule,
            why,
            plugin,
        });
        PredOutcome {
            matched: false,
            record: None,
            unknown: true,
        }
    }

    /// 갈래 하나의 문제를 받아들인다. 메시지는 전부, 재지 못한 YARA 는 그것이
    /// **결과를 갈랐을 때만**(`decisive`). 가르지 않았으면 레코드의 사정(본문 ·
    /// 필드 없음)은 이유 줄까지 버린다 — 6 이 아닌데 *"평가하지 못했습니다"* 가
    /// 남으면 읽는 사람이 무엇을 해야 할지 모른다. 플러그인의 결함은 줄만 남긴다.
    fn absorb(&mut self, other: Issues, decisive: bool) {
        self.messages.extend(other.messages);
        if decisive {
            self.unevaluated.extend(other.unevaluated);
        } else {
            self.messages.extend(
                other
                    .unevaluated
                    .into_iter()
                    .filter(|u| u.plugin)
                    .map(|u| u.why),
            );
        }
    }
}

/// `yara:` 줄임말이 겨누는 필드. 레코드가 스냅샷에 담아 둔 본문의 참조다.
const DEFAULT_CONTENT_FIELD: &str = "content_ref";

/// 본문 참조의 앞머리. 이 접두가 있으면 값이 아니라 **`blobs` 의 키**다.
///
/// 우리가 정한 이름공간이라 관측된 값과 헷갈릴 여지가 없다 — 파일 경로도
/// 레지스트리 데이터도 이렇게 시작하지 않는다.
pub const BLOB_PREFIX: &str = "sha256:";

/// 재지 못한 YARA 술어를 관측에 적을 이름 — 대개 `rules/<파일>.yar:<룰 이름>`.
///
/// 룰 참조가 틀렸으면 그 원문을, 비었거나 아예 없으면 **필드와 값**(`data: ""` ·
/// `data: null`)을 적는다 — 사유 줄의 끝이 빈 채로 나가지 않게. 언어와 무관한
/// 표기라 영어 화면에도 그대로다. 이름을 짓는 자리는 여기 하나다.
fn yara_label(f: &remedy_sdk::manifest::FieldPredicate) -> String {
    match &f.value {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => {
            remedy_yara::RuleRef::parse(s)
                .map(|r| r.as_text())
                .unwrap_or_else(|_| s.clone())
        }
        Some(other) => format!("{}: {other}", f.field),
        None => format!("{}: null", f.field),
    }
}

/// YARA 술어. **미매치와 미평가를 가른다.**
///
/// 훑을 바이트가 없으면 "안 맞았다" 가 아니라 "재지 못했다" 이고, 그 사실은
/// [`Issues::unevaluated`] (레코드의 사정) · [`Issues::broken`] (플러그인의 결함)
/// 을 거쳐 *"모른다"* 로 돌아간다. 그것이 결과를 갈랐으면 관측의
/// `unevaluated_rules` 로 나가 관측 불완전(종료 6)이 된다 (설계-03 §1 · 결정
/// 2026-10-26). **거짓으로 돌아가는 것은 룰이 실제로 돌아 안 맞았을 때뿐이다.**
///
/// 판정이 서면 미평가가 남아 있어도 판정이 우선한다(종료 2) — 설계-03 §1 의
/// *"미평가 규칙이 있는 판정은 감염 확정에 쓸 수 없다"* 를 코드는 아직 지키지
/// 않는다(사고-대응-도구-구조-설계 §11).
fn eval_yara(
    f: &remedy_sdk::manifest::FieldPredicate,
    record: &serde_json::Value,
    snap: &Snapshot,
    issues: &mut Issues,
) -> PredOutcome {
    let raw = match &f.value {
        Some(serde_json::Value::String(s)) => s.clone(),
        // 룰 참조조차 없다.
        _ => {
            return issues.broken(
                yara_label(f),
                "yara 연산자의 value 는 'rules/<파일>.yar:<룰 이름>' 이어야 합니다",
            )
        }
    };
    let rule_ref = match remedy_yara::RuleRef::parse(&raw) {
        Ok(r) => r,
        Err(e) => return issues.broken(yara_label(f), e.0),
    };
    let rule = rule_ref.as_text();

    let Some(rules) = &snap.rules else {
        return issues.broken(
            &rule,
            format!(
                "'{rule}' 를 평가하지 못했습니다 — 이 플러그인에 YARA 룰 파일이 실려 있지 않습니다"
            ),
        );
    };
    // 참조가 가리키는 룰을 **바이트보다 먼저** 본다 — 파일 컴파일 실패 · 파일 없음 ·
    // 룰 이름 없음은 레코드와 무관한 플러그인의 결함이다. 나중에 보면 본문 없는
    // 레코드에서 그 오타가 "본문 없음" 으로 읽힌다(2026-10-26 적대 검증).
    if let Err(e) = rules.check(&rule_ref) {
        return issues.broken(&rule, e.0);
    }

    let Some(value) = expr::field(record, &f.field) else {
        return issues.unevaluated(
            &rule,
            format!(
                "'{rule}' 를 평가하지 못했습니다 — 이 관찰에 '{}' 가 없습니다",
                f.field
            ),
        );
    };

    // **필드가 바이트를 내놓는 방식은 둘이다** (설계-09 P4 — "바이트열 제공
    // 필드 전반").
    //
    //   1 본문 참조(`sha256:…`) — 스냅샷의 `blobs` 를 가리킨다. 파일 본문과
    //     이진 레지스트리 값이 이 형태다.
    //   2 값 자체 — 문자열 필드는 그 UTF-8 바이트가 곧 내용이다. 레지스트리의
    //     텍스트 값(`data`)과 설정 파일의 한 줄(`line`)이 여기 해당한다.
    //
    // 참조인데 그 본문이 없으면 **미평가**다. 그때 참조 문자열 자체를 훑으면
    // `sha256:…` 이라는 20여 바이트를 대상으로 룰이 도는 셈이 되고, 그 결과는
    // "안 맞았다" 로 나가 미평가를 감춘다.
    //
    // 바이트를 담지 않은 이진 값도 같다 — 수집기가 크기만 적은 자리표시
    // (`<binary N bytes>` · 상한을 넘었으면 `…, 상한 초과>`)이고, 그것을 훑으면
    // 스무 바이트 남짓의 표기를 대상으로 룰이 돈다.
    let bytes: &[u8] = if value.starts_with(BLOB_PREFIX) {
        match snap.blobs.get(&value) {
            Some(b) => b,
            None => {
                let why = format!(
                    "'{rule}' 를 평가하지 못했습니다 — 본문 참조 '{value}' 가 스냅샷에 없습니다 \
                     (collect_extra 로 content 를 선언해야 합니다)"
                );
                return issues.unevaluated(&rule, why);
            }
        }
    } else if remedy_sdk::artifact::is_binary_placeholder(&value) {
        return issues.unevaluated(
            &rule,
            format!(
                "'{rule}' 를 평가하지 못했습니다 — 이진 값의 바이트가 스냅샷에 없습니다 ({value})"
            ),
        );
    } else {
        value.as_bytes()
    };

    match rules.matches(&rule_ref, bytes) {
        Ok(matched) => PredOutcome {
            matched,
            record: matched.then(|| MatchedPredicate {
                field: f.field.clone(),
                op: f.op.id().to_string(),
                value: f.value.clone(),
            }),
            unknown: false,
        },
        // 훑지 못한 것이다. 미매치로 흘려보내면 룰이 죽은 채 판정이 나간다.
        // 참조는 위에서 확인했으므로 남는 것은 이 바이트를 훑다 실패한 경우다.
        Err(e) => issues.unevaluated(rule, e.0),
    }
}

#[allow(clippy::too_many_arguments)]
fn eval_predicate(
    p: &Predicate,
    record: &serde_json::Value,
    bindings: &BTreeMap<String, String>,
    scope: &Scope,
    snap: &Snapshot,
    regexes: &mut Regexes,
    issues: &mut Issues,
) -> PredOutcome {
    // `yara: "rules/x.yar:r"` 는 `{ field: content_ref, op: yara, value: ... }`
    // 의 줄임이다. 대상은 그 레코드가 스냅샷에 담아 둔 본문이다.
    let yara_form;
    let f = match p {
        Predicate::Yara(y) => {
            yara_form = remedy_sdk::manifest::FieldPredicate {
                field: DEFAULT_CONTENT_FIELD.to_string(),
                op: Operator::Yara,
                value: Some(serde_json::Value::String(y.yara.clone())),
            };
            &yara_form
        }
        Predicate::Field(f) => f,
    };

    let phase = f.op.info().implemented_in;
    if phase > remedy_sdk::IMPLEMENTED_THROUGH {
        issues.push(format!(
            "연산자 '{}' 는 아직 없습니다 ({} 에서 사용 가능해집니다)",
            f.op.id(),
            phase.as_str()
        ));
        return PredOutcome {
            matched: false,
            record: None,
            unknown: false,
        };
    }

    if expr::is_cross_subject(&f.field) {
        let message = format!(
            "다른 subject 를 참조하는 필드 '{}' 는 아직 없습니다 ({} 에서 사용 가능해집니다)",
            f.field,
            Phase::P4.as_str()
        );
        // 그 위의 YARA 는 **재지 못한 것이다** — `eval_yara` 에 닿기 전에 돌아가도.
        if f.op == Operator::Yara {
            return issues.broken(yara_label(f), message);
        }
        issues.push(message);
        return PredOutcome {
            matched: false,
            record: None,
            unknown: false,
        };
    }

    // `yara` 도 값을 꺼내기 전에 갈라진다. 훑을 것은 문자열이 아니라 바이트다.
    if f.op == Operator::Yara {
        return eval_yara(f, record, snap, issues);
    }

    // `exists` 는 **값을 꺼내기 전에** 답한다. 없는 필드를 미매치로 흘려보내면
    // "이 필드가 없다" 를 물을 방법이 사라진다.
    if f.op == Operator::Exists {
        let present = expr::field(record, &f.field).is_some();
        return PredOutcome {
            matched: present,
            record: present.then(|| MatchedPredicate {
                field: f.field.clone(),
                op: f.op.id().to_string(),
                value: None,
            }),
            unknown: false,
        };
    }

    let actual = match expr::field(record, &f.field) {
        Some(v) => v,
        // 없는 필드는 비교할 수 없다. `not_equals` 도 마찬가지다 — 없는 값이
        // 무언가와 "다르다" 고 말하면, 오타 난 필드 이름이 조용히 참이 된다.
        None => {
            return PredOutcome {
                matched: false,
                record: None,
                unknown: false,
            }
        }
    };

    // `in` 은 값이 배열이다. 문자열로 뭉개면 목록의 뜻이 사라진다.
    if f.op == Operator::In {
        let items = match &f.value {
            Some(serde_json::Value::Array(a)) => a,
            _ => {
                issues.push(format!(
                    "'{}' 에 쓴 in 연산자의 value 가 목록이 아닙니다",
                    f.field
                ));
                return PredOutcome {
                    matched: false,
                    record: None,
                    unknown: false,
                };
            }
        };
        let want = norm_for_compare(&actual, scope);
        let matched = items.iter().any(|it| {
            let raw = match it {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            expr::interpolate(&raw, bindings)
                .map(|v| norm_for_compare(&v, scope) == want)
                .unwrap_or(false)
        });
        return PredOutcome {
            matched,
            record: matched.then(|| MatchedPredicate {
                field: f.field.clone(),
                op: f.op.id().to_string(),
                value: f.value.clone(),
            }),
            unknown: false,
        };
    }

    // 룰이 적은 값도 같은 정규화를 거친다 — 작성자의 편집기가 무엇을 뱉었는지에
    // 판정이 좌우되면 안 된다 (설계-02 §4).
    let raw = match &f.value {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    let expected = match expr::interpolate(&raw, bindings) {
        Some(v) => v,
        // 참조가 아직 해소되지 않았다 = 미매치. 오류가 아니다.
        None => {
            return PredOutcome {
                matched: false,
                record: None,
                unknown: false,
            }
        }
    };

    let matched = match f.op {
        Operator::Matches => {
            let compiled = regexes
                .entry(normalize::literal(&expected))
                .or_insert_with_key(|p| regex::Regex::new(p).map_err(|e| e.to_string()));
            match compiled {
                Ok(re) => re.is_match(&normalize::nfc(&actual)),
                Err(e) => {
                    issues.push(format!("정규식 '{expected}' 가 올바르지 않습니다: {e}"));
                    false
                }
            }
        }
        Operator::Equals => norm_for_compare(&actual, scope) == norm_for_compare(&expected, scope),
        Operator::Contains => {
            norm_for_compare(&actual, scope).contains(&norm_for_compare(&expected, scope))
        }
        Operator::StartsWith => {
            norm_for_compare(&actual, scope).starts_with(&norm_for_compare(&expected, scope))
        }
        Operator::EndsWith => {
            norm_for_compare(&actual, scope).ends_with(&norm_for_compare(&expected, scope))
        }
        Operator::NotEquals => {
            norm_for_compare(&actual, scope) != norm_for_compare(&expected, scope)
        }
        Operator::Glob => crate::compare::glob(
            &norm_for_compare(&actual, scope),
            &norm_for_compare(&expected, scope),
        ),
        // 크기와 시각만 견준다. 견줄 수 없는 값이면 **오류로 말한다** — 조용히
        // false 를 내면 룰이 왜 안 맞는지 알 수 없다.
        Operator::Gt | Operator::Lt => match crate::compare::cmp(&actual, &expected) {
            Some(ord) => {
                if f.op == Operator::Gt {
                    ord == std::cmp::Ordering::Greater
                } else {
                    ord == std::cmp::Ordering::Less
                }
            }
            None => {
                issues.push(format!(
                    "'{}' 의 값 '{}' 와 '{}' 는 견줄 수 없습니다 — {} 는 크기(수)나 시각(RFC3339 UTC)만 비교합니다",
                    f.field,
                    actual,
                    expected,
                    f.op.id()
                ));
                false
            }
        },
        // 점으로 나눈 숫자만 견준다. 꼬리(`RC1` · `-1ubuntu1`)는 모양이 같고
        // 순서가 반대라 **추측하지 않는다** — *"안 맞았다"* 가 아니라 *"재지
        // 못했다"* 로 돌려 YARA 와 같은 레일을 탄다(관측 불완전 · 종료 6).
        // **따옴표 없이 적은 버전은 여기 오기 전에 이미 망가져 있다.**
        // YAML 이 `8.10` 을 실수로 읽어 `8.1` 로 도착하고, 그것은 `is_version` 이
        // 참이라 아래 비교를 그냥 지난다 — 취약한 기계가 진단 한 줄 없이 종료 0
        // 으로 나갔다(실측 2026-10-27 · 적대 검증). 린트가 오류로 막지만
        // **`scan` 은 린트를 돌리지 않으므로** 여기서도 막는다.
        // **`pkg_version_lt` 도 같은 사고를 당한다.** 그 연산자는 꼬리를 받지만
        // 따옴표 없이 적은 `8.10` 은 꼬리가 아니라 **이미 `8.1` 로 도착한 값**이고,
        // 그것은 `is_pkg_version` 이 참이라 비교를 그냥 지난다.
        Operator::VersionLt
        | Operator::VersionGt
        | Operator::PkgVersionLt
        | Operator::RpmVersionLt
            if f.value
                .as_ref()
                .is_some_and(remedy_sdk::catalog::unquoted_version_number) =>
        {
            let why = format!(
                "'{}' 에 걸린 {} 의 값을 버전으로 읽지 못했습니다 — 룰이 따옴표 없이 \
                 적어 YAML 이 실수로 읽었습니다. 엔진에 도착한 값은 '{expected}' 이고 \
                 뒤의 0 은 돌아오지 않습니다. `value: \"8.10\"` 처럼 따옴표로 감싸야 \
                 합니다",
                f.field,
                f.op.id()
            );
            return issues.unreadable_version(format!("{}: {expected}", f.field), why, true);
        }
        // 배포판이 적은 판 — **개정 꼬리까지** 견준다. 규칙은 dpkg 의 것이고
        // (데비안 정책 §5.6.12) 모양이 아니면 추측하지 않는다.
        //
        // **사유 문구가 위와 다르다.** 그쪽은 *"패키지 개정은 받지 않습니다"* 라고
        // 말하는데 여기서는 그것이 거짓이다 — 받는 것이 이 연산자의 요점이다.
        Operator::PkgVersionLt => match crate::compare::pkg_version_cmp(&actual, &expected) {
            Some(ord) => ord == std::cmp::Ordering::Less,
            None => {
                let rule_side = !remedy_sdk::catalog::is_pkg_version(&expected);
                let bad = if rule_side { &expected } else { &actual };
                let why = pkg_version_issue(&f.field, &actual, &expected, f.op.id());
                return issues.unreadable_version(version_label(&f.field, bad), why, rule_side);
            }
        },
        // RPM 이 적은 판 — rpm 의 규칙(`rpmvercmp`)으로 견준다. `_` 를 받는 것이 `pkg_version_lt` 와
        // 갈리는 자리이고(RHEL 의 `el9_8`), 모양이 아니면 같은 레일로 *"재지 못했다"* 가 된다.
        Operator::RpmVersionLt => match crate::compare::rpm_version_cmp(&actual, &expected) {
            Some(ord) => ord == std::cmp::Ordering::Less,
            None => {
                let rule_side = !remedy_sdk::catalog::is_rpm_version(&expected);
                let bad = if rule_side { &expected } else { &actual };
                let why = rpm_version_issue(&f.field, &actual, &expected);
                return issues.unreadable_version(version_label(&f.field, bad), why, rule_side);
            }
        },
        Operator::VersionLt | Operator::VersionGt => {
            match crate::compare::version_cmp(&actual, &expected) {
                Some(ord) => {
                    if f.op == Operator::VersionLt {
                        ord == std::cmp::Ordering::Less
                    } else {
                        ord == std::cmp::Ordering::Greater
                    }
                }
                None => {
                    let rule_side = !crate::compare::is_version(&expected);
                    let bad = if rule_side { &expected } else { &actual };
                    let why = version_issue(&f.field, &actual, &expected, f.op.id());
                    return issues.unreadable_version(version_label(&f.field, bad), why, rule_side);
                }
            }
        }
        // `exists` 와 `in` 은 위에서 이미 답했고, `yara` 는 바이트를 요구하므로
        // 필드 비교의 자리가 아니다.
        other => {
            issues.push(format!(
                "연산자 '{}' 를 여기서 평가할 수 없습니다",
                other.id()
            ));
            false
        }
    };

    PredOutcome {
        matched,
        record: matched.then(|| MatchedPredicate {
            field: f.field.clone(),
            op: f.op.id().to_string(),
            value: f.value.clone(),
        }),
        unknown: false,
    }
}

/// 견주지 못한 값을 관측에 적을 이름.
///
/// 값이 비어 있으면 **필드와 빈 값**을 적는다 — `value` 를 아예 적지 않은 룰
/// (린트가 오류로 막지만 `${…}` 로 풀린 값은 빈 문자열이 될 수 있다)에서 사유
/// 줄의 끝이 빈 채로 나가지 않게. [`yara_label`] 과 같은 규율이고, 언어와 무관한
/// 표기라 영어 화면에도 그대로다.
fn version_label(field: &str, value: &str) -> String {
    if value.trim().is_empty() {
        format!("{field}: \"\"")
    } else {
        value.to_string()
    }
}

/// 버전 비교가 막혔을 때 **어느 쪽을** 읽지 못했는지 짚는다.
///
/// 두 값을 나란히 적기만 하면 고칠 자리를 알 수 없다. 룰이 바꿀 수 있는 것은
/// 자기가 적은 값뿐이고, 관측된 값이 버전이 아니면 그것은 **필드를 잘못 고른
/// 것**이다 — 고치는 길이 서로 다르다.
/// `pkg_version_lt` 가 못 읽었을 때의 사유.
///
/// **[`version_issue`] 를 쓸 수 없다.** 그쪽은 *"패키지 개정(-1ubuntu1)은 받지
/// 않습니다"* 라고 말하는데, 이 연산자는 그것을 받는 것이 요점이다 — 그 문구를
/// 그대로 내보내면 작성자가 맞게 적은 룰을 의심한다.
fn pkg_version_issue(field: &str, actual: &str, expected: &str, op: &str) -> String {
    use remedy_sdk::catalog::is_pkg_version;
    let how = format!(
        "{op} 는 배포판이 적는 판을 비교합니다(예: 8.1.2-1ubuntu2.28 · 1:2.38.1-5+deb12u3). \
         숫자로 시작해야 하고, `_` 는 받지 않습니다 — apk 는 `_alpha` 를 그 판보다 \
         낮게 읽고 dpkg 의 규칙은 높게 읽어 **순서가 반대**입니다"
    );
    use remedy_sdk::i18n::particle;
    let (pa, pe) = (particle(actual, "을", "를"), particle(expected, "을", "를"));
    match (is_pkg_version(actual), is_pkg_version(expected)) {
        (false, true) => {
            format!("'{field}' 의 값 '{actual}' {pa} 판으로 읽지 못했습니다 — {how}")
        }
        (true, false) => format!("룰이 적은 '{expected}' {pe} 판으로 읽지 못했습니다 — {how}"),
        _ => format!(
            "'{field}' 의 값 '{actual}' 과 룰이 적은 '{expected}' {pe} \
             모두 판으로 읽지 못했습니다 — {how}"
        ),
    }
}

/// `rpm_version_lt` 가 못 읽었을 때의 사유 — 모양 규칙이 `pkg_version_lt` 와 달라(`_` 를 받는다) 문구를
/// 따로 둔다.
fn rpm_version_issue(field: &str, actual: &str, expected: &str) -> String {
    use remedy_sdk::catalog::is_rpm_version;
    use remedy_sdk::i18n::particle;
    let how = "rpm_version_lt 는 RPM 이 적는 판을 비교합니다(예: 0:8.0.30-8.el9_8.1 · \
               7.4.33-8.module+el8.10.0+25117+30337cca). 숫자로 시작해야 합니다";
    let (pa, pe) = (particle(actual, "을", "를"), particle(expected, "을", "를"));
    match (is_rpm_version(actual), is_rpm_version(expected)) {
        (false, true) => format!("'{field}' 의 값 '{actual}' {pa} 판으로 읽지 못했습니다 — {how}"),
        (true, false) => format!("룰이 적은 '{expected}' {pe} 판으로 읽지 못했습니다 — {how}"),
        _ => format!(
            "'{field}' 의 값 '{actual}' 과 룰이 적은 '{expected}' {pe} 모두 판으로 읽지 못했습니다 — {how}"
        ),
    }
}

fn version_issue(field: &str, actual: &str, expected: &str, op: &str) -> String {
    let how = format!(
        "{op} 는 점으로 나눈 숫자만 비교합니다(예: 8.2.29). \
         사전 배포 꼬리(RC1 · -dev)와 패키지 개정(-1ubuntu1)은 \
         순서가 서로 반대여서 받지 않습니다"
    );
    // 조사는 **값의 마지막 글자**가 정한다 — `'8.2.29'` 는 *구* 로 끝나 `를` 다.
    // 손으로 박으면 값에 따라 틀린다 (`i18n::particle`).
    use remedy_sdk::i18n::particle;
    let (pa, pe) = (particle(actual, "을", "를"), particle(expected, "을", "를"));
    let actual_ok = crate::compare::is_version(actual);
    match (actual_ok, crate::compare::is_version(expected)) {
        (false, true) => {
            format!("'{field}' 의 값 '{actual}' {pa} 버전으로 읽지 못했습니다 — {how}")
        }
        (true, false) => format!("룰이 적은 '{expected}' {pe} 버전으로 읽지 못했습니다 — {how}"),
        _ => format!(
            "'{field}' 의 값 '{actual}' 과 룰이 적은 '{expected}' {pe} \
             모두 버전으로 읽지 못했습니다 — {how}"
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn eval_condition(
    c: &Condition,
    record: &serde_json::Value,
    bindings: &BTreeMap<String, String>,
    scope: &Scope,
    snap: &Snapshot,
    regexes: &mut Regexes,
    issues: &mut Issues,
    matched: &mut Vec<MatchedPredicate>,
) -> Tri {
    match c {
        Condition::One(p) => {
            let o = eval_predicate(p, record, bindings, scope, snap, regexes, issues);
            let t = Tri::from(&o);
            if let Some(m) = o.record {
                matched.push(m);
            }
            t
        }
        // 목록은 암묵적 all 이다.
        Condition::All(a) => eval_all(
            &a.all, record, bindings, scope, snap, regexes, issues, matched,
        ),
        Condition::List(l) => eval_all(l, record, bindings, scope, snap, regexes, issues, matched),
        Condition::Any(a) => eval_any(
            &a.any, record, bindings, scope, snap, regexes, issues, matched,
        ),
    }
}

/// `all` — 거짓이 하나라도 있으면 거짓이다. **재지 못한 것이 앞에 있어도.**
///
/// 갈래마다 문제를 따로 모은다. 결과가 `Unknown` 이면 `Unknown` 인 갈래의 미평가만
/// 결과를 갈랐고, 거짓이면 아무것도 가르지 않았다.
///
/// **첫 `Unknown` 뒤의 갈래도 평가한다** — 뒤에 거짓이 있으면 이 `all` 은 거짓이다.
/// 그래서 전에는 단락으로 돌지 않던 술어가 돌고 그 메시지(정규식 오류 등)가 더해질
/// 수 있다. 증거 · 판정은 전과 같다.
///
/// **첫 `Unknown` 뒤의 갈래가 맞힌 술어는 증거에 싣지 않는다.** 그 `all` 은 이미
/// 참이 될 수 없고, 거짓을 거짓으로 볼 때는 거기서 멈춰 싣지 않았다 — 계획기가 그
/// 술어로 지울 값을 정한다(`remedy-plan` 의 `proxy_targets`).
#[allow(clippy::too_many_arguments)]
fn eval_all(
    items: &[Condition],
    record: &serde_json::Value,
    bindings: &BTreeMap<String, String>,
    scope: &Scope,
    snap: &Snapshot,
    regexes: &mut Regexes,
    issues: &mut Issues,
    matched: &mut Vec<MatchedPredicate>,
) -> Tri {
    let mut out = Tri::True;
    let mut seen = Issues::default();
    let mut after_unknown = Vec::new();
    for x in items {
        let mut local = Issues::default();
        let buf = if out == Tri::Unknown {
            &mut after_unknown
        } else {
            &mut *matched
        };
        let t = eval_condition(x, record, bindings, scope, snap, regexes, &mut local, buf);
        if t == Tri::False {
            seen.absorb(local, false);
            issues.absorb(seen, false);
            return Tri::False;
        }
        if t == Tri::Unknown {
            out = Tri::Unknown;
        }
        seen.absorb(local, t == Tri::Unknown);
    }
    issues.absorb(seen, out == Tri::Unknown);
    out
}

/// `any` — 참이 하나라도 있으면 참이다. 결과가 `Unknown` 이면 `Unknown` 인 갈래의
/// 미평가만 결과를 갈랐고, 참이면 아무것도 가르지 않았다.
#[allow(clippy::too_many_arguments)]
fn eval_any(
    items: &[Condition],
    record: &serde_json::Value,
    bindings: &BTreeMap<String, String>,
    scope: &Scope,
    snap: &Snapshot,
    regexes: &mut Regexes,
    issues: &mut Issues,
    matched: &mut Vec<MatchedPredicate>,
) -> Tri {
    let mut out = Tri::False;
    let mut seen = Issues::default();
    for x in items {
        let mut local = Issues::default();
        let t = eval_condition(
            x, record, bindings, scope, snap, regexes, &mut local, matched,
        );
        if t == Tri::True {
            seen.absorb(local, false);
            issues.absorb(seen, false);
            return Tri::True;
        }
        if t == Tri::Unknown {
            out = Tri::Unknown;
        }
        seen.absorb(local, t == Tri::Unknown);
    }
    issues.absorb(seen, out == Tri::Unknown);
    out
}

// ─────────────────────────────────────────────────────── 그룹 평가

#[derive(Clone)]
struct Group {
    /// 룰 id -> 이 그룹의 증거 id
    evidence: BTreeMap<String, Vec<String>>,
    /// `rule.capture` -> 값
    captures: BTreeMap<String, String>,
    excluded: Option<String>,
}

struct RuleMatch {
    evidence: Evidence,
    captures: BTreeMap<String, String>,
}

#[allow(clippy::too_many_arguments)]
fn eval_rule(
    rule: &DetectRule,
    snapshot: &Snapshot,
    group: &Group,
    scope: &Scope,
    counter: &mut BTreeMap<String, usize>,
    regexes: &mut Regexes,
    issues: &mut Issues,
) -> Result<Vec<RuleMatch>, String> {
    // `from` 은 증거에서 파생된 경로다. 상한 밖이면 **그룹을 제외한다.**
    let from_dir = match &rule.from {
        None => None,
        Some(t) => match expr::interpolate(t, &group.captures) {
            None => return Ok(Vec::new()), // 부모 capture 가 아직 없다 = 미매치
            Some(dir) => {
                if !scope.allows(&dir) {
                    return Err(format!(
                        "규칙 '{}' 의 파생 경로 '{}' 가 scan_roots 밖입니다",
                        rule.id, dir
                    ));
                }
                Some(dir)
            }
        },
    };

    let mut out = Vec::new();
    for record in snapshot.records(rule.subject) {
        if let Some(dir) = &from_dir {
            // 디스크의 자리를 쥔 칸 — 대개 `path`, `archive_entry` 는 `archive` 다(그 `path` 는 안쪽 경로).
            let field = rule.subject.from_field().unwrap_or("path");
            let path = expr::field(record, field).unwrap_or_default();
            if !normalize::is_within(&path, dir, scope.platform) {
                continue;
            }
        }

        let mut bindings = group.captures.clone();
        let mut matched = Vec::new();
        // 레코드 하나의 문제는 따로 모은다 — 재지 못한 YARA 는 **이 레코드의 매치를
        // 갈랐을 때만** 관측에 남는다(`Issues` 머리). 조건이 거짓이거나 · 확정 제외
        // 되거나 · capture 를 풀지 못하면 YARA 가 무엇을 냈어도 매치가 아니다.
        let mut cond_issues = Issues::default();
        let cond = eval_condition(
            &rule.condition,
            record,
            &bindings,
            scope,
            snapshot,
            regexes,
            &mut cond_issues,
            &mut matched,
        );
        if cond == Tri::False {
            issues.absorb(cond_issues, false);
            continue;
        }
        // 제외 조건은 하나라도 걸리면 매치가 아니다.
        //
        // 여기서 생긴 문제는 버린다 — **재지 못한 YARA 가 제외를 가를 수 있었을
        // 때만 빼고.** 그 레코드는 증거로 남지만(제외되지 않은 쪽 — 전과 같다),
        // 판정식이 이 규칙을 `not` 으로 보면 남은 증거가 판정을 지워 "위협 없음" 이
        // 거짓이 된다(2026-10-26 적대 검증). 그래서 그때는 관측에 싣는다.
        let mut ex_issues = Issues::default();
        let excluded = any3(rule.exclude.iter().map(|p| {
            Tri::from(&eval_predicate(
                &Predicate::clone(p),
                record,
                &bindings,
                scope,
                snapshot,
                regexes,
                &mut ex_issues,
            ))
        }));
        if excluded == Tri::True {
            issues.absorb(cond_issues, false);
            issues.absorb(ex_issues.unevaluated_only(), false);
            continue;
        }
        // 증거가 되는 것은 전과 같이 **조건이 확정 참인 레코드**다. 조건을 재지
        // 못한 레코드는 capture 만 시험한다 — 그 오류는 증거가 아닌 레코드의 것이라
        // 보고하지 않는다.
        let candidate = cond == Tri::True;
        let mut unreported = Issues::default();
        let capture_sink = if candidate {
            &mut *issues
        } else {
            &mut unreported
        };

        // capture 는 **의존 관계로 해소한다. 선언 순서에 기대지 않는다.**
        //
        // `payload_dir: "${script_path} | dirname"` 처럼 뒤 항목이 앞 항목을
        // 참조하는데, 매니페스트의 매핑은 순서를 보존하지 않는다. 순서에 기대면
        // 이름을 바꾸는 것만으로 룰이 조용히 매치되지 않는다 — 실제로 이 함정을
        // 한 번 밟았다.
        //
        // 규칙 사이의 평가 순서를 작성자가 적지 않는 것(설계-02 §4)과 같은 원칙이다.
        let mut own = BTreeMap::new();
        let mut pending: Vec<(&String, &String)> = rule.capture.iter().collect();
        let mut failed = false;
        while !pending.is_empty() {
            let before = pending.len();
            let mut next = Vec::new();
            for (name, expression) in pending {
                match expr::capture(expression, record, &bindings) {
                    Err(e) => {
                        capture_sink.push(format!("규칙 '{}' 의 capture '{name}': {e}", rule.id));
                        failed = true;
                        break;
                    }
                    // 참조가 아직 없다. 다음 회차에 다시 시도한다.
                    Ok(None) => next.push((name, expression)),
                    Ok(Some(v)) => {
                        bindings.insert((*name).clone(), v.clone());
                        own.insert(format!("{}.{}", rule.id, name), v);
                    }
                }
            }
            if failed {
                break;
            }
            if next.len() == before {
                // 한 회차에 아무것도 못 풀었다 — 없는 필드를 보거나 참조가
                // 순환한다. 이 레코드는 매치가 아니다.
                failed = true;
                break;
            }
            pending = next;
        }
        if failed {
            // capture 는 YARA 와 무관하다 — 무엇을 냈어도 매치가 아니었다.
            issues.absorb(cond_issues, false);
            issues.absorb(ex_issues.unevaluated_only(), false);
            continue;
        }
        issues.absorb(cond_issues, cond == Tri::Unknown);
        issues.absorb(ex_issues.unevaluated_only(), excluded == Tri::Unknown);
        if !candidate {
            continue;
        }

        let n = counter.entry(rule.id.clone()).or_insert(0);
        let id = format!("{}#{}", rule.id, *n);
        *n += 1;

        out.push(RuleMatch {
            evidence: Evidence {
                id,
                rule: rule.id.clone(),
                subject: rule.subject,
                score: rule.score,
                target: record.clone(),
                captures: own
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.split_once('.')
                                .map(|x| x.1.to_string())
                                .unwrap_or_default(),
                            v.clone(),
                        )
                    })
                    .collect(),
                matched,
            },
            captures: own,
        });
    }
    Ok(out)
}

/// 스냅샷과 매니페스트로 `scan.json` 본문을 만든다.
pub fn evaluate(
    snapshot: &Snapshot,
    manifest: &PluginManifest,
    scope: &Scope,
) -> Result<ScanBody, EvalError> {
    let order = topo_order(&manifest.detect)?;
    let require =
        verdict::parse(&manifest.verdict.require).map_err(|e| EvalError(e.to_string()))?;
    // `verdict.unconfirmed` — 판정이 서지 않은 그룹에서만 본다(아래). 같은 문법이다.
    let unconfirmed = manifest
        .verdict
        .unconfirmed
        .iter()
        .map(|u| {
            verdict::parse(&u.when).map_err(|e| EvalError(format!("verdict.unconfirmed: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 판정식이 없는 규칙을 참조하면 영원히 성립하지 않는다. 조용히 두면
    // "왜 안 잡히는가" 의 원인이 보이지 않는다.
    let wanted = rules_named(&require);
    for w in &wanted {
        if !manifest.detect.iter().any(|r| &r.id == w) {
            return Err(EvalError(format!(
                "verdict.require 가 없는 규칙 '{w}' 를 참조합니다"
            )));
        }
    }
    for expr in &unconfirmed {
        if let Some(w) = rules_named(expr)
            .iter()
            .find(|w| !manifest.detect.iter().any(|r| r.id == **w))
        {
            return Err(EvalError(format!(
                "verdict.unconfirmed 가 없는 규칙 '{w}' 를 참조합니다"
            )));
        }
    }

    // 어떤 규칙이 다른 규칙의 부모인가.
    let mut is_parent: BTreeSet<&str> = BTreeSet::new();
    for r in &manifest.detect {
        for d in refs_of(r) {
            is_parent.insert(
                manifest
                    .detect
                    .iter()
                    .find(|x| x.id == d)
                    .map(|x| x.id.as_str())
                    .unwrap_or_default(),
            );
        }
    }

    // 그룹 번호는 마지막에 팬아웃 순서대로 다시 매긴다.
    let mut groups = vec![Group {
        evidence: BTreeMap::new(),
        captures: BTreeMap::new(),
        excluded: None,
    }];
    let mut all_evidence: Vec<Evidence> = Vec::new();
    let mut counter: BTreeMap<String, usize> = BTreeMap::new();
    let mut regexes = Regexes::new();
    let mut issues = Issues::default();

    // **아직 채워지지 않는 필드를 쓴 규칙을 먼저 말한다** (설계-02 §3).
    //
    // 린트가 작성 시점에 경고하지만 린트는 건너뛸 수 있고, 실행하는 사람은
    // 매니페스트를 읽지 않는다. 산출물이 홀로 읽혀야 한다는 요구(설계-03 §1)를
    // 지키려면 `scan.json` 자체가 그 사실을 들고 있어야 한다.
    //
    // **레코드마다가 아니라 규칙마다 한 번**이다. 필드가 없는 것은 레코드의
    // 사정이 아니라 이 코어의 사정이므로, 5천 건을 돌며 같은 줄을 5천 번 적을
    // 이유가 없다.
    for u in remedy_sdk::lint::unpopulated_field_uses(manifest, &[scope.platform]) {
        let tail = if u.in_exclude {
            "exclude 라 제외가 일어나지 않습니다. 걸러 내려던 것이 그대로 남습니다"
        } else {
            "이 술어는 언제나 거짓입니다"
        };
        issues.push(format!(
            "'{}' 가 '{}' 를 보는데 이 코어는 {}그 필드를 채우지 않습니다 — {tail}. {}",
            u.rule,
            u.field,
            match u.only_on {
                Some(p) => format!("{} 에서 ", p.id()),
                None => String::new(),
            },
            u.why
        ));
    }

    for &i in &order {
        let rule = &manifest.detect[i];
        let deps = refs_of(rule);
        let mut next: Vec<Group> = Vec::new();

        for g in groups.into_iter() {
            if g.excluded.is_some() {
                next.push(g);
                continue;
            }
            // 부모가 0건이면 자식은 평가하지 않는다 (미매치, 오류 아님).
            if deps
                .iter()
                .any(|d| g.evidence.get(d).map(|v| v.is_empty()).unwrap_or(true))
            {
                next.push(g);
                continue;
            }

            match eval_rule(
                rule,
                snapshot,
                &g,
                scope,
                &mut counter,
                &mut regexes,
                &mut issues,
            ) {
                Err(reason) => {
                    let mut ex = g;
                    ex.excluded = Some(reason);
                    next.push(ex);
                }
                Ok(matches) => {
                    if is_parent.contains(rule.id.as_str()) && matches.len() > 1 {
                        // 부모 증거 인스턴스마다 독립 스코프가 생긴다.
                        for m in matches {
                            let mut g2 = g.clone();
                            g2.evidence
                                .insert(rule.id.clone(), vec![m.evidence.id.clone()]);
                            g2.captures.extend(m.captures.clone());
                            all_evidence.push(m.evidence);
                            next.push(g2);
                        }
                    } else {
                        let mut g2 = g;
                        let ids: Vec<String> =
                            matches.iter().map(|m| m.evidence.id.clone()).collect();
                        if let Some(first) = matches.first() {
                            g2.captures.extend(first.captures.clone());
                        }
                        g2.evidence.insert(rule.id.clone(), ids);
                        for m in matches {
                            all_evidence.push(m.evidence);
                        }
                        next.push(g2);
                    }
                }
            }

            if next.len() > MAX_GROUPS {
                return Err(EvalError(format!(
                    "증거 그룹이 {MAX_GROUPS}개를 넘었습니다. 룰의 범위가 지나치게 넓습니다"
                )));
            }
        }
        groups = next;
    }

    // 그룹 번호를 다시 매긴다 — 팬아웃 순서가 곧 번호다.
    let mut out_groups = Vec::with_capacity(groups.len());
    let mut passed = Vec::new();
    // `verdict.unconfirmed` 의 줄마다 그것이 선 그룹.
    let mut unconfirmed_at: Vec<Vec<String>> = vec![Vec::new(); unconfirmed.len()];
    for (n, g) in groups.into_iter().enumerate() {
        let id = format!("g{n}");
        let counts: BTreeMap<String, usize> = g
            .evidence
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect();
        let ok = g.excluded.is_none() && verdict::eval(&require, &counts);
        if ok {
            passed.push(id.clone());
        } else if g.excluded.is_none() {
            // **찾은 것이 모르는 것보다 앞선다** — 판정이 선 그룹은 확인 필요로 세지 않는다.
            // 제외된 그룹도 세지 않는다(제외는 '이것은 아니다' 를 이미 말했다).
            for (i, expr) in unconfirmed.iter().enumerate() {
                if verdict::eval(expr, &counts) {
                    unconfirmed_at[i].push(id.clone());
                }
            }
        }
        let mut ids: Vec<String> = g.evidence.values().flatten().cloned().collect();
        ids.sort();
        out_groups.push(EvidenceGroup {
            id,
            evidence: ids,
            captures: g.captures,
            verdict: ok,
            excluded_reason: g.excluded,
        });
    }

    all_evidence.sort_by(|a, b| a.id.cmp(&b.id));
    // 여기 남은 미평가는 전부 **결과를 갈랐던** 것이다(`Issues::absorb`). 규칙은
    // 레코드 천 개에서 재지 못해도 한 번만 적고, 이유는 주의 줄로 나간다.
    let Issues {
        mut messages,
        unevaluated,
    } = issues;
    let mut unevaluated_rules = BTreeSet::new();
    let mut unreadable_versions = BTreeSet::new();
    for u in unevaluated {
        match u.what {
            Unmeasured::YaraRule => unevaluated_rules.insert(u.rule),
            Unmeasured::Version => unreadable_versions.insert(u.rule),
        };
        messages.push(u.why);
    }
    messages.sort();
    messages.dedup();

    Ok(ScanBody {
        evidence: all_evidence,
        groups: out_groups,
        verdicts: passed,
        // 화면이 판정 그룹에서 이 규칙들의 증거만 적는다(`ScanBody::verdict_rules`).
        verdict_rules: wanted,
        issues: messages,
        // 평가기는 **스냅샷의** 완전성과 범위를 판단할 위치가 아니다 — 둘 다 수집
        // 범위의 사실이고, 봉투를 조립하는 쪽(remedy-core)이 실어 온다.
        //
        // **둘은 평가기만 안다** — 평가 중에 재지 못한 YARA 규칙(결정 2026-10-26)
        // 과 견주지 못한 버전(2026-10-27 · C-1). 그것만 여기 싣고, remedy-core 가
        // 스냅샷의 관측과 합친다.
        observation: remedy_sdk::artifact::Observation {
            unevaluated_rules: unevaluated_rules.into_iter().collect(),
            unreadable_versions: unreadable_versions.into_iter().collect(),
            // 선 줄만 싣는다 — 서지 않은 줄까지 실으면 빈 사유가 화면에 남는다.
            unconfirmed: manifest
                .verdict
                .unconfirmed
                .iter()
                .zip(&unconfirmed)
                .zip(unconfirmed_at)
                .filter(|(_, groups)| !groups.is_empty())
                .map(
                    |((u, expr), groups)| remedy_sdk::artifact::UnconfirmedNote {
                        why: u.why.clone(),
                        groups,
                        // 화면이 짚은 그룹에서 이 규칙들의 증거만 적는다(`UnconfirmedNote::rules`).
                        rules: rules_named(expr),
                    },
                )
                .collect(),
            ..Default::default()
        },
        scan_roots: Vec::new(),
        removable_roots: Vec::new(),
    })
}

// ─────────────────────────────────────────────────── 압력

/// 청정 코퍼스가 규칙 **하나**에 실제로 가한 압력.
///
/// # 왜 이것을 따로 재는가
///
/// G1 이 초록인 것은 *"청정 환경에서 판정이 나지 않았다"* 다. 그런데 그 초록에는
/// 뜻이 정반대인 둘이 섞여 있다.
///
/// | | 뜻 |
/// |---|---|
/// | 레코드 12만 건을 보고 전부 걸러 냈다 | 오탐이 없다 |
/// | 볼 레코드가 **한 건도 없었다** | 아무것도 재지 않았다 |
///
/// 게이트는 둘을 같은 초록으로 보고한다. 2026-09-04 Windows 코퍼스를 넓히다
/// 드러났다 — `C:\ProgramData` 가 코퍼스에 없어서, 거기 페이로드를 두는 위협
/// 셋의 규칙이 **후보 0건 위에서** 통과하고 있었다. 코퍼스에 넣고 나서야
/// "청정 서비스 711건 중 0건" 이라는 문장을 쓸 수 있었고, 그전에는 그 질문
/// 자체가 성립하지 않았다.
///
/// 리눅스 검증 하네스가 **통과 · 실패 · 못 잼** 셋으로 답하는 것과 같은 이유다.
/// "못 잼" 을 "통과" 로 세면 게이트는 늘 초록이다.
#[derive(Debug, Clone)]
pub struct RulePressure {
    pub rule: String,
    pub subject: Subject,
    /// 이 규칙의 술어가 **마주한** 레코드 수.
    ///
    /// 0 이면 이 규칙은 이 스냅샷에서 평가된 적이 없다. 그 초록은 "오탐이
    /// 없다" 가 아니라 "재지 않았다" 다.
    pub records: usize,
    /// 조건 전체를 통과한 레코드 수. 청정 스냅샷에서는 0이어야 한다.
    pub matched: usize,
    /// 술어가 **혼자서** 통과시킨 레코드 수 — `(표시, 통과)`.
    ///
    /// 어느 술어가 거절을 떠받치는지 보여 준다. `[a=711, b=0]` 이면 두 번째가
    /// 전부 거절했다는 뜻이고, 그 조합에서 **첫 번째는 이 코퍼스가 시험하지
    /// 못했다.** 파생 규칙에서는 비어 있다.
    pub per_predicate: Vec<(String, usize)>,
    /// 부모 증거에서 파생되는 규칙인가.
    ///
    /// 청정 환경에서는 부모가 서지 않으므로 이런 규칙은 **평가 자체가 시작되지
    /// 않는다** (`eval_rule` 이 `from` 을 풀지 못해 곧바로 미매치로 돌아온다).
    /// 그래서 G1 의 판별력은 사실상 뿌리 규칙에 몰려 있고, 이 표시가 그것을
    /// 숨기지 않는다.
    pub derived: bool,
}

/// 조건 안의 잎 술어를 순서대로 편다.
fn leaf_predicates<'a>(c: &'a Condition, out: &mut Vec<&'a Predicate>) {
    match c {
        Condition::One(p) => out.push(p),
        Condition::All(a) => a.all.iter().for_each(|x| leaf_predicates(x, out)),
        Condition::Any(a) => a.any.iter().for_each(|x| leaf_predicates(x, out)),
        Condition::List(v) => v.iter().for_each(|x| leaf_predicates(x, out)),
    }
}

/// 술어를 사람이 읽을 한 줄로. 값은 길면 자른다 — 표에 들어갈 것이다.
fn predicate_label(p: &Predicate) -> String {
    match p {
        Predicate::Yara(y) => format!("yara {}", y.yara),
        Predicate::Field(f) => {
            let v = match &f.value {
                None => String::new(),
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
            };
            let v: String = if v.chars().count() > 40 {
                format!("{}…", v.chars().take(39).collect::<String>())
            } else {
                v
            };
            if v.is_empty() {
                format!("{} {}", f.field, f.op.id())
            } else {
                format!("{} {} {v}", f.field, f.op.id())
            }
        }
    }
}

/// 매니페스트의 규칙마다 이 스냅샷이 가한 압력을 잰다.
///
/// **평가기를 다시 구현하지 않는다** — 같은 `eval_condition`·`eval_predicate` 를
/// 부른다. 재는 쪽이 따로 구현하면 그 둘이 갈라지는 날 압력 수치가 조용히
/// 거짓이 된다.
///
/// 파생 규칙(`from` 또는 부모 참조)은 `records` 만 채운다. 부모 없이 술어를
/// 재면 `${parent.x}` 가 풀리지 않아 언제나 거짓이고, 그 0 은 규칙의 성질이
/// 아니라 재는 방법의 성질이다.
pub fn pressure(
    snapshot: &Snapshot,
    manifest: &PluginManifest,
    scope: &Scope,
) -> Vec<RulePressure> {
    let empty: BTreeMap<String, String> = BTreeMap::new();
    let mut regexes = Regexes::new();
    let mut out = Vec::new();

    for rule in &manifest.detect {
        let derived = rule.from.is_some() || !refs_of(rule).is_empty();
        let records = snapshot.records(rule.subject);
        // 압력은 판정이 아니라 **마주한 수**를 센다 — 여기 쌓인 문제는 버린다.
        let mut issues = Issues::default();

        let mut matched = 0usize;
        let mut per_predicate = Vec::new();

        if !derived {
            for r in records {
                let mut m = Vec::new();
                if eval_condition(
                    &rule.condition,
                    r,
                    &empty,
                    scope,
                    snapshot,
                    &mut regexes,
                    &mut issues,
                    &mut m,
                ) == Tri::True
                {
                    matched += 1;
                }
            }

            let mut leaves = Vec::new();
            leaf_predicates(&rule.condition, &mut leaves);
            for p in leaves {
                let n = records
                    .iter()
                    .filter(|r| {
                        eval_predicate(p, r, &empty, scope, snapshot, &mut regexes, &mut issues)
                            .matched
                    })
                    .count();
                per_predicate.push((predicate_label(p), n));
            }
        }

        out.push(RulePressure {
            rule: rule.id.clone(),
            subject: rule.subject,
            records: records.len(),
            matched,
            per_predicate,
            derived,
        });
    }
    out
}
