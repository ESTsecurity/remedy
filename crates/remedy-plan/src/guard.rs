//! 계획기 가드 (설계-03 §3·§4, 설계-09 P3).
//!
//! **거부는 계획 단계에서 일어난다.** 실행 중에 막으면 이미 일부는 지워진 뒤다.
//!
//! # P3 에는 Op 가 없는데 왜 지금 만드는가
//!
//! Op 첫 등장은 P6(`file.quarantine_only`)이고 `apply` 도 P6 이다(설계-09 §3.2·§3.4).
//! 그래서 이 가드들은 지금 **조작한 입력**으로만 검증된다 — 설계-09 §3.5 가 G5·G6·G7
//! 의 최초 의미 Phase 를 P3 으로 두고 비고에 "조작 입력" 이라 적은 이유다.
//!
//! 순서가 반대면 안 된다. 파괴를 만들 수 있게 해 둔 뒤 가드를 붙이면, 그 사이의
//! 모든 커밋이 가드 없는 파괴 경로를 갖는다. **가드가 파괴보다 먼저** 라는 순서
//! 자체가 안전장치다 (설계-09 §2).

use crate::limits::Limits;
use crate::protect::{Protected, Protection};
use remedy_sdk::artifact::Action;
use remedy_sdk::catalog::{Op, Platform};
use remedy_sdk::normalize;
use std::collections::BTreeMap;

/// 가드가 막은 이유. **감사 로그에 그대로 남는다.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// 어느 게이트인가. 설계-03 §10 의 G 번호.
    pub gate: &'static str,
    /// 문제가 있는 Action. 계획 전체가 문제라면 `None`.
    pub seq: Option<u32>,
    pub message: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.seq {
            Some(s) => write!(f, "[{}] Action #{s}: {}", self.gate, self.message),
            None => write!(f, "[{}] {}", self.gate, self.message),
        }
    }
}

/// 계획을 검사할 때 알아야 하는 것들.
pub struct Context<'a> {
    pub limits: &'a Limits,
    pub protected: &'a Protected,
    /// 이 실행의 증거 그룹 수. 룰 과광범위 탐지용이다.
    pub group_count: usize,
    /// 읽기 권한 상한 (설계-02 §2). **여기 밖은 지울 수도 없다.**
    pub scan_roots: Vec<String>,
    /// 경로 비교 규칙. 대소문자를 접을지가 여기서 갈린다.
    pub platform: Platform,
    /// 증거에서 파생된 경로(capture)의 집합. 재귀 삭제는 여기 있는 것만 겨눌 수 있다.
    pub derived_paths: Vec<String>,
    /// 증거 id → 그 증거가 가리키는 경로.
    ///
    /// 재귀 삭제의 `guard` 조건이 이것을 요구한다 — **그 디렉터리 안에서 악성으로
    /// 판정된 것이 최소 1개** 확인되어야 한다 (설계-03 §4). `because` 가 비어
    /// 있지 않다는 것만으로는 부족하다. 근거가 **엉뚱한 곳**을 가리켜도 통과하기
    /// 때문이다.
    pub evidence_path: BTreeMap<String, String>,
}

/// 계획 전체를 검사한다. **하나라도 걸리면 계획이 거부된다.**
///
/// 위반을 모아서 돌려주는 이유: 첫 번째만 알려 주면 고치고 다시 돌리기를 반복하게
/// 되고, 그 사이 무엇이 더 걸릴지 알 수 없다.
pub fn check(actions: &[Action], cx: &Context) -> Vec<Violation> {
    let mut v = Vec::new();
    v.extend(check_groups(cx));
    for a in actions {
        v.extend(check_because(a));
        v.extend(check_ceiling(a, cx));
        v.extend(check_protected(a, cx));
        v.extend(check_protected_process(a, cx));
        v.extend(check_recursive(a, cx));
    }
    v.extend(check_totals(actions, cx));
    v
}

/// 가드 사유를 **두 언어로 짓는다.**
///
/// # 왜 조각을 잇지 않는가
///
/// 수와 낱말의 순서가 언어마다 달라, 조각만 번역하면 어느 한쪽이 반드시
/// 어그러진다. 양쪽 문장을 통째로 짓고 여기서 고른다.
///
/// # 왜 이 파일에 이것이 필요했나 (2026-09-16)
///
/// 가드 사유는 종료 코드 5 로 **고객에게 간다.** 그런데 콘솔 캡처가 밟는 것은
/// `G5` 하나뿐이라, 나머지 열여덟은 영어로 돌려도 한국어로 나오는 것을 아무도
/// 보지 못했다. 아래 시험 모듈의 `check` 래퍼가 그것을 드러냈다.
/// **`derive.rs` 도 쓴다** — 미룬 사유(`deferred[*].reason`)가 같은 문제를
/// 가졌고, 같은 이유로 캡처가 그 자리를 밟지 않는다.
/// **`Lang::pick` 의 껍데기다** — 이 크레이트 안의 호출 스물몇을 그대로 두려고
/// 이름만 남겼다.
///
/// 09-16 에 잠깐 `i18n::t_owned` 를 새로 만들었는데, `pick` 이 이미 같은 일을
/// 하고 저장소 서른여섯 곳이 그것을 쓰고 있었다. **있는 것을 못 보고 만든
/// 중복이라 지웠다.**
pub(crate) fn ko_en(ko: String, en: String) -> String {
    remedy_sdk::i18n::current().pick(ko, en)
}

/// **G7 — 증거 추적성.** 근거 없는 Action 은 존재할 수 없다.
///
/// `because` 가 비면 "왜 지웠는가" 에 답할 수 없다. 오탐 신고를 받았을 때 그
/// 답이 없으면 무엇이 잘못됐는지 밝힐 방법이 없고, 같은 사고가 반복된다.
fn check_because(a: &Action) -> Option<Violation> {
    if !a.because.is_empty() {
        return None;
    }
    let op = a.op.id();
    Some(Violation {
        gate: "G7",
        seq: Some(a.seq),
        message: ko_en(
            format!("because 가 비어 있습니다. '{op}' 를 왜 수행하는지 가리키는 증거가 최소 하나 있어야 합니다"),
            format!("`because` is empty; '{op}' needs at least one piece of evidence saying why it runs"),
        ),
    })
}

/// 계획의 대상이 무엇으로 생겼는가.
///
/// **`scan_roots` 는 파일 경로의 상한이다.** 레지스트리 값과 예약 작업의 등록
/// 경로는 파일 시스템 밖에 있으므로 그 상한에 담기지 않는다. 그것들을 경로처럼
/// 대조하면 언제나 밖으로 판정된다 — 실제로 그랬고, 게이트를 P7 로 올리는
/// 순간 청정 코퍼스에서 `persistence.disable` 200여 건이 전부 G6 위반으로 나왔다.
/// 설계-02 §4 가 이미 그렇게 적고 있다 — *"레지스트리 읽기처럼 경로 개념이
/// 없는 대상에는 적용되지 않는다"*. **코드가 문서를 따라가지 못했고, 게이트를
/// 올리기 전에는 그 차이를 잴 자리가 없었다.**
/// P6 까지는 계획될 수 있는 Op 이 `file.quarantine_only` 하나뿐이라 드러나지
/// 않았다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// 파일 시스템 경로. 상한은 `scan_roots` 다.
    Path,
    /// `<하이브>\<키>[\<값>]`.
    Registry,
    /// 예약 작업 등록 경로 (`\Microsoft\Windows\...`).
    Task,
    /// 셋 중 어느 것도 아니다. **모르는 모양은 허용하지 않는다.**
    Unknown,
}

fn shape_of(target: &str, platform: Platform) -> Shape {
    let head = target.split('\\').next().unwrap_or("").to_ascii_uppercase();
    if matches!(
        head.as_str(),
        "HKLM" | "HKCU" | "HKU" | "HKEY_LOCAL_MACHINE" | "HKEY_CURRENT_USER" | "HKEY_USERS"
    ) {
        return Shape::Registry;
    }
    let b = target.as_bytes();
    let win_abs = b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
    if win_abs || target.starts_with("\\\\") {
        return Shape::Path;
    }
    if platform != Platform::Windows && target.starts_with('/') {
        return Shape::Path;
    }
    // 역슬래시 하나로 시작하는 것은 예약 작업이다. UNC(`\\`)는 위에서 걸렀다.
    if target.starts_with('\\') {
        return Shape::Task;
    }
    Shape::Unknown
}

/// **읽기 상한 밖은 지울 수도 없다** (설계-02 §2·§4).
///
/// `scan_roots` 는 성능 최적화가 아니라 권한 상한이다. 그런데 파생 경로는
/// **공격자가 값에 영향을 줄 수 있다** — capture 가 엉뚱한 상위 경로로 잡히도록
/// 유도할 수 있고, 그것이 상한을 넘게 만들 수 있다면 그것은 상한이 아니다.
///
/// 평가기도 파생 경로를 검사해 그룹을 제외하지만, 여기서 한 번 더 본다.
/// 한 겹뿐인 경계는 그 한 겹이 뚫리면 없는 것과 같다.
///
/// # 파일 시스템 밖의 대상은 다른 상한을 받는다
///
/// 레지스트리 값과 예약 작업에는 `scan_roots` 에 해당하는 것이 없다. 그 대상들의
/// 상한은 **선언된 `subjects`** 다 — 수집기는 선언되지 않은 subject 를 열거하지
/// 않으므로, 계획에 그 대상이 들어와 있다는 것 자체가 상한 안에서 관측됐다는
/// 뜻이다. `because` 가 실재하는 증거를 가리키는지는 G6 의 다른 검사가 본다.
///
/// **그래서 이 함수는 "경로가 아니면 통과" 가 아니라 "아는 모양이면 통과" 다.**
/// 모르는 모양은 그대로 막는다 — 그러지 않으면 `scan_roots` 를 우회하는 길이
/// 모양 하나 바꾸는 것으로 열린다.
/// 이 Op 의 대상이 **`scan_roots` 와 무관하게 수집되는** subject 에서 오는가.
///
/// `10-manifest.md` 의 표가 그 목록이다 — `persistence` · `service` · `autorun` ·
/// `cert_store` 는 자리가 정해져 있어 플러그인이 위치를 선언할 이유가 없고, 선언하게 만들면
/// **위치를 틀린 플러그인이 조용히 0건을 보고한다.**
///
/// 수집이 그 상한을 안 받으면 제거도 안 받아야 한다. 한쪽만 걸면 "볼 수는 있는데
/// 지울 수는 없는" 대상이 생기고, 그것은 치료 전용 도구로서 앞뒤가 안 맞는다.
fn collected_from_a_fixed_place(op: Op) -> bool {
    matches!(
        op,
        Op::PersistenceDisable
            | Op::PersistenceDelete
            | Op::ServiceClearRecovery
            | Op::ServiceStop
            | Op::ServiceDisable
            | Op::ServiceDelete
            | Op::AutorunRemove
            // 인증서 저장소도 자리가 정해져 있다 — Windows 는 레지스트리,
            // Linux 는 `/usr/share/ca-certificates` 와
            // `/usr/local/share/ca-certificates` 다. 플러그인이 그 위치를 선언할
            // 이유가 없고, 선언하게 만들면 위치를 틀린 플러그인이 조용히 0건을
            // 보고한다 (설계-09 P12 후속).
            | Op::CertStoreRemove
            // ── 이름으로 지정하는 원복 넷 (`RESTORE_NAMED`) ──────────
            //
            // 넷 다 `Scoping::Fixed` subject 를 되돌린다. 플러그인은 그 자리를
            // 선언하지 않고 — 선언할 수도 없다 — `restore: [hosts]` 처럼
            // **이름**만 적는다.
            //
            // 2026-09-03 Linux 하네스가 이것을 밟았다. `restore: [hosts]` 가
            // G6 에 걸려 계획이 통째로 거부됐다:
            //
            //   [G6] '/etc/hosts' 이 읽기 상한 밖이다
            //
            // Windows 쪽 셋은 대상이 레지스트리 값이라 `shape_of` 에서 이미
            // 걸러져 여태 드러나지 않았다. `hosts` 만 양쪽에서 경로다.
            //
            // 아래 시험이 이 목록을 카탈로그에 묶는다 — 손으로 든 목록과
            // `Scoping` 이 갈라지면 그 자리에서 걸린다.
            | Op::HostsRestoreLine
            | Op::AvRestoreExclusions
            | Op::ProxyRestore
            | Op::FirewallRestoreRule
    )
}

fn check_ceiling(a: &Action, cx: &Context) -> Option<Violation> {
    let target = a.target.as_deref()?;

    match shape_of(target, cx.platform) {
        Shape::Registry | Shape::Task => return None,
        Shape::Unknown => {
            return Some(Violation {
                gate: "G6",
                seq: Some(a.seq),
                message: ko_en(
                    format!(
                        "'{target}' 은 절대 경로도 레지스트리 값도 예약 작업 등록 경로도 아닙니다. \
                         상한을 대조할 수 없는 대상은 지우지 않습니다"
                    ),
                    format!(
                        "'{target}' is neither an absolute path nor a registry value nor a task \
                         registration path; a target whose ceiling cannot be checked is not deleted"
                    ),
                ),
            })
        }
        Shape::Path => {}
    }

    // **고정 자리에서 오는 subject 는 `scan_roots` 가 상한이 아니다** (설계-09
    // P12 마감).
    //
    // 위 문단이 레지스트리 값과 예약 작업을 두고 말한 그 원칙이다 — 그 대상들의
    // 상한은 선언된 `subjects` 이고, 수집기가 선언되지 않은 subject 를 열거하지
    // 않으므로 계획에 들어와 있다는 것 자체가 상한 안에서 관측됐다는 뜻이다.
    //
    // Windows 에서는 그 대상이 레지스트리 값·등록 경로라 위 `match` 에서 이미
    // 빠져나갔다. **Linux 에서는 같은 것이 파일 경로**라 여기까지 온다 —
    // systemd 유닛 · cron 파일 · XDG autostart 항목. 모양이 다르다고 상한이
    // 달라지면 같은 subject 가 플랫폼마다 다른 규칙을 받는다.
    //
    // 모양 검사는 위에서 이미 끝났다. **모르는 모양은 여전히 막힌다** — 여기서
    // 비켜 가는 것은 `scan_roots` 대조 하나뿐이고, 보호 목록 대조와 `because`
    // 검사는 그대로 지난다.
    if collected_from_a_fixed_place(a.op) {
        return None;
    }

    // 상한을 모르면 아무것도 허용하지 않는다. "상한이 없다" 가 아니라
    // "알 수 없다" 이고, 알 수 없으면 막는 편이 옳다.
    let inside = cx
        .scan_roots
        .iter()
        .any(|r| normalize::is_within(target, r, cx.platform));
    if inside {
        return None;
    }
    Some(Violation {
        gate: "G6",
        seq: Some(a.seq),
        message: if cx.scan_roots.is_empty() {
            ko_en(
                format!("'{target}' — 이 평가의 읽기 상한(scan_roots)을 알 수 없습니다. 상한을 모르면 아무것도 지울 수 없습니다"),
                format!("'{target}' — this evaluation's read ceiling (scan_roots) is unknown; without it nothing can be deleted"),
            )
        } else {
            let roots = cx.scan_roots.join(" · ");
            ko_en(
                format!("'{target}' 이 읽기 상한 밖입니다. 선언된 상한: {roots}"),
                format!("'{target}' is outside the read ceiling. Declared: {roots}"),
            )
        },
    })
}

/// **G6 — 보호 경로 불가침.**
///
/// 규칙은 두 겹이다(설계-03 §3). 보호 디렉터리 **자체**에 대한 재귀 삭제는 항상
/// 거부하고, 하위의 **개별 파일**은 조건부로 허용한다. 하나로 뭉뚱그리면 첫
/// 플러그인부터 못 쓰거나 OS 파괴 경로가 열린다.
fn check_protected(a: &Action, cx: &Context) -> Option<Violation> {
    let target = a.target.as_deref()?;

    // 대상이 보호 디렉터리를 **품고 있는** 경우. 대상 자체가 목록에 없어도
    // 통째로 지우면 그 안의 보호 디렉터리가 함께 사라진다.
    if Limits::is_recursive(a.op) {
        if let Some(held) = cx.protected.contains_protected(target) {
            return Some(Violation {
                gate: "G6",
                seq: Some(a.seq),
                message: ko_en(
                    format!("'{target}' 을 통째로 지우면 보호 디렉터리 '{held}' 가 함께 사라집니다"),
                    format!("deleting '{target}' wholesale would take the protected directory '{held}' with it"),
                ),
            });
        }
    }
    let p = cx.protected.check(target)?;

    let recursive = Limits::is_recursive(a.op);
    match (&p, recursive) {
        // 보호 디렉터리 자체 · 루트 · 홈은 무엇으로도 건드릴 수 없다.
        (Protection::ProtectedDirectory(_) | Protection::Root | Protection::UserHome, _) => {
            Some(Violation {
                gate: "G6",
                seq: Some(a.seq),
                message: ko_en(
                    format!("'{target}' 은 {p} 입니다. 코어 내장 보호 목록은 플러그인이 뒤집을 수 없습니다"),
                    format!("'{target}' is {p}. A plugin cannot override the core's built-in protected list"),
                ),
            })
        }
        // 보호 디렉터리 하위를 통째로 지우는 것도 금지다.
        (Protection::InsideProtectedDirectory(_), true) => Some(Violation {
            gate: "G6",
            seq: Some(a.seq),
            message: ko_en(
                format!(
                    "'{target}' 은 {p} 입니다. 재귀 삭제는 보호 디렉터리 하위에서도 거부됩니다 \
                     — 개별 파일 삭제만 조건부로 허용됩니다"
                ),
                format!(
                    "'{target}' is {p}. Recursive deletion is refused below a protected directory \
                     too — only individual files may be deleted, and only conditionally"
                ),
            ),
        }),
        // 하위 개별 파일: 조건부 허용. 조건은 "신뢰 서명 없음 + 증거 링크 존재"
        // 다(설계-03 §3 1층).
        //
        // **두 조건 다 다른 곳이 강제한다.** 증거 링크는 G7 이, 신뢰 서명은
        // P10-B 가 세운 2층이 본다 — `derive.rs` 의 `layer2_holds` 가 서명된
        // 대상을 애초에 Action 으로 만들지 않는다. 여기서 다시 보면 같은 판정이
        // 두 곳에 생기고, 그 둘이 갈라지는 날 어느 쪽이 참인지 알 수 없게 된다.
        (Protection::InsideProtectedDirectory(_), false) => None,
    }
}

/// 재귀 삭제 추가 가드 (설계-03 §4).
///
/// 2번이 핵심이다 — capture 해석이 어긋나 대상이 엉뚱한 상위 경로로 잡혀도,
/// 그 안에 악성 판정 파일이 없으면 계획이 만들어지지 않는다.
/// **G6 — 임계 프로세스.** 종료하면 즉시 시스템이 멈추는 것은 겨눌 수 없다.
///
/// PID 는 계획에 들어갈 자리가 없다(설계-03 §1) — 대상은 술어로 고정된다. 그래서
/// 계획 시점에 볼 수 있는 것은 **술어가 지목하는 이미지 경로**이고, 그것이 임계
/// 프로세스를 가리키면 여기서 막는다.
///
/// 실행 시점의 PID 검사(`PROTECTED_PIDS`)는 술어가 실제로 무엇을 지목했는지
/// 알게 되는 P8 의 몫이다. 둘은 서로를 대체하지 않는다 — 여기서 막으면 사람이
/// 승인 화면에서 보기 전에 걸리고, 거기서 막으면 술어가 예상 밖의 것을 지목한
/// 경우가 걸린다.
fn check_protected_process(a: &Action, cx: &Context) -> Vec<Violation> {
    if a.op != Op::ProcessKill {
        return Vec::new();
    }
    let mut out = Vec::new();
    let Some(m) = &a.r#match else {
        // 술어가 없으면 무엇을 죽일지 계획이 말하지 않은 것이다.
        out.push(Violation {
            gate: "G6",
            seq: Some(a.seq),
            message: ko_en(
                "process.kill 에 대상 술어가 없습니다. 무엇을 종료할지 계획이 말하지 않으면 \
                 승인할 수도 감사할 수도 없습니다"
                    .into(),
                "process.kill has no target predicate. If the plan does not say what to terminate, \
                 it can be neither approved nor audited"
                    .into(),
            ),
        });
        return out;
    };

    if let Some(image) = m.get("image_path").and_then(|v| v.as_str()) {
        if cx.protected.is_critical_process(image, None) {
            out.push(Violation {
                gate: "G6",
                seq: Some(a.seq),
                message: ko_en(
                    format!(
                        "'{image}' 은 종료하면 즉시 시스템이 멈추는 프로세스입니다. \
                         악성코드가 같은 이름을 쓰더라도 이 경로는 겨눌 수 없습니다"
                    ),
                    format!(
                        "'{image}' halts the system the moment it is terminated. Even if malware \
                         reuses the name, this path cannot be targeted"
                    ),
                ),
            });
        }
    }
    out
}

fn check_recursive(a: &Action, cx: &Context) -> Vec<Violation> {
    if !Limits::is_recursive(a.op) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let target = a.target.as_deref().unwrap_or_default();

    // 1. 대상이 **증거에서 추출된 capture** 여야 한다. 리터럴 경로 금지.
    if !cx.derived_paths.iter().any(|d| d == target) {
        out.push(Violation {
            gate: "G6",
            seq: Some(a.seq),
            message: ko_en(
                format!(
                    "'{target}' 은 증거에서 파생된 경로가 아닙니다. 재귀 삭제 대상은 capture 에서만 올 수 있습니다 \
                     — 리터럴 경로나 설정값에서 온 경로는 거부됩니다"
                ),
                format!(
                    "'{target}' is not a path derived from evidence. A recursive-delete target may \
                     only come from a capture — literal paths and configured paths are refused"
                ),
            ),
        });
    }

    // 2. **그 디렉터리 안에서** 악성으로 판정된 것이 최소 1개 (설계-03 §4).
    //
    // `because` 가 비어 있지 않다는 것만으로는 부족하다. 근거가 엉뚱한 곳을
    // 가리켜도 통과하기 때문이다 — `C:\Users\a\문서` 를 지우면서 근거로
    // `C:\Temp\evil.exe` 를 대는 계획이 그렇게 만들어질 수 있다.
    if a.because.is_empty() {
        out.push(Violation {
            gate: "G6",
            seq: Some(a.seq),
            message: ko_en(
                "재귀 삭제는 그 안에서 악성으로 판정된 대상을 가리키는 guard 증거를 요구합니다".into(),
                "a recursive delete requires guard evidence pointing at something judged malicious \
                 inside it"
                    .into(),
            ),
        });
    } else {
        let known: Vec<&String> = a
            .because
            .iter()
            .filter_map(|id| cx.evidence_path.get(id))
            .collect();
        if known.is_empty() {
            // 근거의 경로를 하나도 모르면 **조건을 확인하지 못한 것**이다.
            // 확인하지 못한 것을 통과로 읽으면 가드가 없는 것과 같다.
            out.push(Violation {
                gate: "G6",
                seq: Some(a.seq),
                message: ko_en(
                    format!(
                        "재귀 삭제 '{target}' 의 근거 {:?} 가 어느 경로를 가리키는지 알 수 없다. \
                         그 안에서 악성으로 판정된 것이 있는지 확인할 수 없으면 지우지 않습니다",
                        a.because
                    ),
                    format!(
                        "cannot tell which path the evidence {:?} for the recursive delete of \
                         '{target}' points at; without that check nothing is deleted",
                        a.because
                    ),
                ),
            });
        } else if !known
            .iter()
            .any(|p| normalize::is_within(p, target, cx.platform))
        {
            out.push(Violation {
                gate: "G6",
                seq: Some(a.seq),
                message: {
                    let list = known
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(" · ");
                    ko_en(
                        format!(
                            "재귀 삭제 '{target}' 의 근거가 전부 그 바깥을 가리킵니다: {list}. \
                             디렉터리를 통째로 지우려면 **그 안에서** 악성으로 판정된 것이 \
                             최소 하나 있어야 합니다 (설계-03 §4)"
                        ),
                        format!(
                            "every piece of evidence for the recursive delete of '{target}' points \
                             outside it: {list}. Deleting a directory wholesale needs at least one \
                             thing judged malicious **inside** it (design-03 §4)"
                        ),
                    )
                },
            });
        }
    }

    // 5. 대상이 **`scan_roots` 상한 자체**면 거부 (설계-03 §4).
    //
    // 조건 2 는 "그 안에 악성 판정이 있는가" 만 본다. **상위 경로 안에 악성
    // 파일이 있으면 통과한다** — capture 가 한 단계 얕게 뽑히면 상한 전체가
    // 대상이 되고 조건 2 는 그것을 막지 못한다.
    //
    // 실측(P11 r2): 첫 플러그인이 `args` 에서 `…\Programs\loader.js` 를 뽑아
    // `dirname` 이 `%LOCALAPPDATA%\Programs` 가 됐고, 그 폴더 전체가 재귀 삭제
    // 대상이 됐다. **사용자가 설치한 정상 프로그램이 전부 거기 있다.**
    //
    // 상한과 같아졌다는 것은 capture 가 예상대로 풀리지 않았다는 신호다.
    // 상한 전체를 지우는 것이 어떤 룰의 의도일 수는 없다.
    if cx.scan_roots.iter().any(|r| {
        normalize::for_compare(r, cx.platform) == normalize::for_compare(target, cx.platform)
    }) {
        out.push(Violation {
            gate: "G6",
            seq: Some(a.seq),
            message: ko_en(
                format!(
                    "재귀 삭제 대상 '{target}' 이 scan_roots 상한 자체입니다 — capture 가 한 단계 얕게 \
                     풀렸을 때 생기는 모양이고, 그 아래에는 대개 사용자가 설치한 것들이 있습니다 \
                     (설계-03 §4 조건 5)"
                ),
                format!(
                    "the recursive-delete target '{target}' is the scan_roots ceiling itself — this \
                     is what a capture resolved one level too shallow looks like, and what sits \
                     below it is usually what the user installed (design-03 §4, condition 5)"
                ),
            ),
        });
    }
    out
}

/// **G5 — 폭주 차단.** 무인 모드는 프롬프트 없이 중단한다 (fail-closed).
fn check_totals(actions: &[Action], cx: &Context) -> Vec<Violation> {
    let mut out = Vec::new();
    let l = cx.limits;

    // 동일 해시 반복 항목은 **별도 상한**을 받는다. 랜섬노트처럼 판정 근거가 한
    // 번만 필요했던 대상은 위험이 개수에 비례하지 않는다 (설계-03 §4).
    // 두 상한은 독립적으로 걸린다 — 서로 다른 파일 1001개는 여전히 중단된다.
    // **무엇이 파일을 없애는가는 `Limits` 가 안다.** 여기서 Op 목록을 다시
    // 적으면 둘이 어긋나고, 실제로 어긋나 있었다 — 격리가 빠져 이 상한 셋이
    // 어떤 계획에도 걸리지 않았다 (실측 2026-09-08).
    let deletes: Vec<&Action> = actions
        .iter()
        .filter(|a| Limits::removes_a_file(a.op))
        .collect();

    let mut by_hash: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for a in &deletes {
        if let Some(h) = a.sha256.as_deref() {
            *by_hash.entry(h).or_insert(0) += 1;
        }
    }
    let repeated: usize = by_hash.values().filter(|c| **c > 1).sum();
    let distinct = deletes.len() - repeated;

    if distinct > l.total_files as usize {
        out.push(Violation {
            gate: "G5",
            seq: None,
            message: ko_en(
                format!(
                    "서로 다른 파일 {distinct}개를 지우려 합니다. 상한은 {}개입니다",
                    l.total_files
                ),
                format!(
                    "{distinct} distinct files would be deleted; the limit is {}",
                    l.total_files
                ),
            ),
        });
    }
    if repeated > l.same_hash_items as usize {
        out.push(Violation {
            gate: "G5",
            seq: None,
            message: ko_en(
                format!(
                    "동일 해시 반복 항목 {repeated}개. 상한은 {}개입니다",
                    l.same_hash_items
                ),
                format!(
                    "{repeated} items repeat the same hash; the limit is {}",
                    l.same_hash_items
                ),
            ),
        });
    }

    let bytes: u64 = deletes.iter().filter_map(|a| a.size).sum();
    if bytes > l.total_bytes {
        out.push(Violation {
            gate: "G5",
            seq: None,
            message: ko_en(
                format!(
                    "총 {bytes} 바이트를 지우려 합니다. 상한은 {} 바이트입니다",
                    l.total_bytes
                ),
                format!(
                    "{bytes} bytes would be deleted in total; the limit is {}",
                    l.total_bytes
                ),
            ),
        });
    }

    // 서로 다른 최상위 디렉터리 수 — 확산 탐지용이다. 감염이 한 폴더에 머물지
    // 않고 퍼졌다면 룰이 과광범위할 가능성이 먼저다.
    let tops: std::collections::BTreeSet<String> = actions
        .iter()
        .filter_map(|a| a.target.as_deref())
        .filter_map(top_dir)
        .collect();
    if tops.len() > l.distinct_top_dirs as usize {
        out.push(Violation {
            gate: "G5",
            seq: None,
            message: {
                let list = tops.iter().cloned().collect::<Vec<_>>().join(" · ");
                let n = tops.len();
                ko_en(
                    format!(
                        "서로 다른 최상위 디렉터리 {n}개에 걸쳐 있습니다. 상한은 {}개입니다 ({list})",
                        l.distinct_top_dirs
                    ),
                    format!(
                        "it spans {n} distinct top-level directories; the limit is {} ({list})",
                        l.distinct_top_dirs
                    ),
                )
            },
        });
    }
    out
}

/// 증거 그룹 수 상한. **룰 과광범위 탐지용**이다.
fn check_groups(cx: &Context) -> Option<Violation> {
    if cx.group_count <= cx.limits.evidence_groups as usize {
        return None;
    }
    Some(Violation {
        gate: "G5",
        seq: None,
        message: ko_en(
            format!(
                "증거 그룹이 {}개입니다. 상한은 {}개 — 이 정도면 룰이 과광범위할 가능성이 먼저입니다",
                cx.group_count, cx.limits.evidence_groups
            ),
            format!(
                "there are {} evidence groups; the limit is {} — at this point an over-broad rule \
                 is the likelier explanation",
                cx.group_count, cx.limits.evidence_groups
            ),
        ),
    })
}

/// `C:\a\b\c` -> `C:\a`, `/a/b/c` -> `/a`. 최상위 디렉터리를 뽑는다.
fn top_dir(path: &str) -> Option<String> {
    let unix = path.starts_with('/');
    let parts: Vec<&str> = path.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
    match parts.len() {
        0 => None,
        1 => Some(parts[0].to_string()),
        _ if unix => Some(format!("/{}", parts[0])),
        _ => Some(format!("{}\\{}", parts[0], parts[1])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_sdk::catalog::{Platform, Risk};

    /// `check` 를 부르되 **사유가 지금 언어로 나오는지** 함께 본다.
    ///
    /// # 왜 캡처가 아니라 여기인가 (2026-09-16)
    ///
    /// 가드 사유는 종료 코드 5 로 **고객에게 간다.** 그런데 이 파일의 열여덟
    /// 줄 중 콘솔 캡처가 밟는 것은 `G5` 하나뿐이다 — 나머지는 캡처가 일으키지
    /// 않는 상황에서만 나온다(보호 경로 · 재귀 삭제 · 임계 프로세스 …).
    /// **캡처를 넓히는 것은 답이 아니다**: 그 상황을 전부 만들려면 캡처가
    /// 가드 시험이 되고, 그러면 평소 화면이 기준선에서 밀려난다.
    ///
    /// 그 상황을 만드는 것은 **이미 아래 시험들이다.** 그래서 캡처 대신 여기서
    /// 본다. 라이브러리 시험은 언어를 정하지 않아 영어로 돌므로
    /// (`i18n::current` 의 기본값), 사유에 한글이 남아 있으면 그 사유는 한
    /// 언어뿐이라는 뜻이다.
    ///
    /// **이름을 `check` 그대로 둔 것**은 아래 스물넷을 고치지 않기 위해서다.
    /// 로컬 정의가 `use super::*` 로 들어온 이름을 가린다 — 새 시험을 쓰는
    /// 사람도 그냥 `check` 를 부르면 이 검사를 함께 받는다.
    fn check(actions: &[Action], cx: &Context) -> Vec<Violation> {
        let v = super::check(actions, cx);
        for x in &v {
            assert!(
                !x.message.chars().any(|c| ('가'..='힣').contains(&c)),
                "가드 사유가 영어 회차에서 한글로 나온다 ({}): {}",
                x.gate,
                x.message
            );
        }
        v
    }

    fn protected() -> Protected {
        Protected::new(Platform::Windows, |s| {
            s.replace("%SystemRoot%", "C:\\Windows")
                .replace("%ProgramFiles(x86)%", "C:\\Program Files (x86)")
                .replace("%ProgramFiles%", "C:\\Program Files")
        })
    }

    fn action(seq: u32, op: Op, target: &str) -> Action {
        Action {
            seq,
            op,
            target: Some(target.to_string()),
            r#match: None,
            max_targets: None,
            max_children: None,
            max_depth: None,
            max_retries: None,
            include_descendants: None,
            strip: None,
            sha256: None,
            size: None,
            because: vec!["rule#0".into()],
            backup: None,
            reversible: true,
            risk: Risk::Medium,
            user_impact: None,
        }
    }

    struct Fixture {
        limits: Limits,
        protected: Protected,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                limits: Limits::default(),
                protected: protected(),
            }
        }
        /// 이 시험들의 읽기 상한. 각 시험이 **자기 관심사 하나만** 보도록
        /// 넉넉히 연다 — 상한 자체는 따로 시험한다.
        fn cx(&self, derived: &[&str], groups: usize) -> Context<'_> {
            self.cx_roots(
                derived,
                groups,
                &[
                    r"C:\remedy-lab",
                    r"C:\Windows",
                    r"C:\a",
                    r"C:\dir0",
                    r"C:\dir1",
                    r"C:\dir2",
                ],
            )
        }

        fn cx_roots(&self, derived: &[&str], groups: usize, roots: &[&str]) -> Context<'_> {
            Context {
                limits: &self.limits,
                protected: &self.protected,
                group_count: groups,
                // 기본 근거는 **첫 파생 경로 안**을 가리킨다. 재귀 삭제의 guard
                // 조건을 보는 시험이 아니면 여기서 걸리지 않아야 한다.
                evidence_path: BTreeMap::from([(
                    "rule#0".to_string(),
                    format!("{}\\payload.exe", derived.first().unwrap_or(&r"C:\a")),
                )]),
                derived_paths: derived.iter().map(|s| s.to_string()).collect(),
                scan_roots: roots.iter().map(|s| s.to_string()).collect(),
                platform: Platform::Windows,
            }
        }
    }

    #[test]
    fn empty_plan_passes() {
        // P2 의 계획이 이 모양이다. 가드가 빈 계획을 막으면 아무것도 못 한다.
        let f = Fixture::new();
        assert!(check(&[], &f.cx(&[], 0)).is_empty());
    }

    #[test]
    fn a_target_outside_the_read_ceiling_is_refused() {
        // **읽기 상한 밖은 지울 수도 없다.** 파생 경로는 공격자가 값에 영향을
        // 줄 수 있으므로, 그것이 상한을 넘게 만들 수 있다면 그것은 상한이 아니다.
        let f = Fixture::new();
        let a = action(1, Op::FileDelete, r"C:\Users\alice\Desktop\x.js");
        let v = check(&[a], &f.cx_roots(&[], 1, &[r"C:\remedy-lab"]));
        assert!(
            v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                "읽기 상한 밖",
                "outside the read ceiling"
            ))),
            "{v:?}"
        );
    }

    #[test]
    fn an_unknown_ceiling_allows_nothing() {
        // 상한을 모르는 것은 "상한이 없다" 가 아니다. 모르면 막는다.
        let f = Fixture::new();
        let a = action(1, Op::FileDelete, r"C:\remedy-lab\x\evil.js");
        let v = check(&[a], &f.cx_roots(&[], 1, &[]));
        assert!(
            v.iter().any(|x| x
                .message
                .contains(remedy_sdk::i18n::t("알 수 없습니다", "is unknown"))),
            "{v:?}"
        );
    }

    #[test]
    fn a_target_inside_the_ceiling_passes() {
        let f = Fixture::new();
        let a = action(1, Op::FileDelete, r"C:\remedy-lab\x\evil.js");
        let v = check(&[a], &f.cx_roots(&[], 1, &[r"C:\remedy-lab"]));
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn a_sibling_prefix_does_not_satisfy_the_ceiling() {
        // `C:\remedy-lab-evil` 은 `C:\remedy-lab` 안이 아니다. 단순 접두
        // 비교였다면 통과한다.
        let f = Fixture::new();
        let a = action(1, Op::FileDelete, r"C:\remedy-lab-evil\x.js");
        let v = check(&[a], &f.cx_roots(&[], 1, &[r"C:\remedy-lab"]));
        assert!(
            v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                "읽기 상한 밖",
                "outside the read ceiling"
            ))),
            "{v:?}"
        );
    }

    #[test]
    fn g7_action_without_evidence_is_refused() {
        let f = Fixture::new();
        let mut a = action(1, Op::FileDelete, "C:\\remedy-lab\\x\\evil.js");
        a.because.clear();
        let v = check(&[a], &f.cx(&[], 1));
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].gate, "G7");
        assert!(
            v[0].message.contains("file.delete"),
            "무엇을 막았는지 말해야 한다"
        );
    }

    #[test]
    fn g6_protected_directory_itself_is_refused_for_any_op() {
        let f = Fixture::new();
        for op in [Op::FileDelete, Op::DirDeleteRecursive] {
            let v = check(&[action(1, op, "C:\\Windows\\System32")], &f.cx(&[], 1));
            assert!(
                v.iter().any(|x| x.gate == "G6"),
                "{op:?} 가 통과했다: {v:?}"
            );
        }
    }

    #[test]
    fn g6_individual_file_inside_protected_dir_is_allowed() {
        // **이것이 통과해야 첫 플러그인이 동작한다.** 악성코드는 실제로
        // System32 에 드롭되고, EvilAI 탐지 조건에도 그 경로가 들어간다.
        let f = Fixture::new();
        let v = check(
            &[action(1, Op::FileDelete, "C:\\Windows\\System32\\evil.dll")],
            &f.cx(&[], 1),
        );
        assert!(
            v.is_empty(),
            "보호 디렉터리 하위 개별 파일은 허용된다: {v:?}"
        );
    }

    #[test]
    fn g6_recursive_delete_inside_protected_dir_is_refused() {
        let f = Fixture::new();
        let target = "C:\\Windows\\System32\\evil";
        let v = check(
            &[action(1, Op::DirDeleteRecursive, target)],
            &f.cx(&[target], 1),
        );
        assert!(v.iter().any(|x| x.gate == "G6"), "{v:?}");
    }

    #[test]
    fn recursive_delete_requires_a_derived_path() {
        // capture 가 아닌 리터럴 경로로 재귀 삭제를 걸 수 없다. 이것이 없으면
        // 플러그인이 임의 디렉터리를 통째로 지울 수 있다.
        let f = Fixture::new();
        let target = "C:\\remedy-lab\\fixtures\\app-1";

        let refused = check(&[action(1, Op::DirDeleteRecursive, target)], &f.cx(&[], 1));
        assert!(
            refused
                .iter()
                .any(|x| x.message.contains(remedy_sdk::i18n::t(
                    "파생된 경로가 아니다",
                    "not a path derived from evidence"
                ))),
            "{refused:?}"
        );

        let allowed = check(
            &[action(1, Op::DirDeleteRecursive, target)],
            &f.cx(&[target], 1),
        );
        assert!(
            allowed.is_empty(),
            "capture 에서 온 경로는 통과한다: {allowed:?}"
        );
    }

    #[test]
    fn registry_key_delete_gets_the_recursive_guard() {
        let f = Fixture::new();
        let key = "HKLM\\SOFTWARE\\Evil";
        let v = check(&[action(1, Op::RegistryDeleteKey, key)], &f.cx(&[], 1));
        assert!(
            v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                "파생된 경로가 아니다",
                "not a path derived from evidence"
            ))),
            "레지스트리 키 삭제도 하위 트리 전체를 지운다: {v:?}"
        );
    }

    #[test]
    fn registry_key_delete_needs_evidence_inside_the_key() {
        // 설계-09 P8 검증 목록이 이 Op 을 이름으로 든다. `dir.delete_recursive`
        // 가 P10 으로 옮겨간 뒤에도 **같은 가드가 P8 에서 계속 돈다** — 두
        // Op 이 `Limits::is_recursive` 를 공유하기 때문이다.
        let f = Fixture::new();
        let key = r"HKLM\SOFTWARE\Evil";
        let mut a = action(1, Op::RegistryDeleteKey, key);
        a.because.clear();
        let v = check(&[a], &f.cx(&[key], 1));
        assert!(
            v.iter().any(|x| x.message.contains("guard")),
            "근거 없는 키 삭제가 통과했다: {v:?}"
        );
    }

    /// 근거가 **그 디렉터리 안**을 가리켜야 한다 (설계-03 §4).
    ///
    /// `because` 가 비어 있지 않다는 것만 보면, `C:\Users\a\문서` 를 지우면서
    /// 근거로 `C:\Temp\evil.exe` 를 대는 계획이 통과한다.
    fn recursive_with_evidence_at(dir: &str, evidence: &str) -> Vec<Violation> {
        let f = Fixture::new();
        let mut cx = f.cx(&[dir], 1);
        cx.evidence_path = BTreeMap::from([("rule#0".to_string(), evidence.to_string())]);
        check(&[action(1, Op::DirDeleteRecursive, dir)], &cx)
    }

    #[test]
    fn recursive_delete_of_a_scan_root_itself_is_refused() {
        // **조건 2 는 이것을 막지 못한다.** 상한 안에 악성 판정 파일이 있으면
        // 통과하기 때문이다 — capture 가 한 단계 얕게 풀리면 상한 전체가
        // 대상이 되고, 그 아래에는 대개 사용자가 설치한 것들이 있다.
        //
        // 실측(P11 r2): 첫 플러그인이 `…\Programs\loader.js` 에서 dirname 을
        // 뽑아 `%LOCALAPPDATA%\Programs` 전체를 겨눴다.
        let f = Fixture::new();
        let root = r"C:\a";
        let mut cx = f.cx(&[root], 1);
        cx.evidence_path = BTreeMap::from([("rule#0".to_string(), r"C:\a\evil.js".to_string())]);
        let v = check(&[action(1, Op::DirDeleteRecursive, root)], &cx);
        assert!(
            v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                "scan_roots 상한 자체",
                "the scan_roots ceiling itself"
            ))),
            "상한 자체를 지우는 계획이 통과했다: {v:?}"
        );
    }

    #[test]
    fn recursive_delete_one_level_below_a_scan_root_passes() {
        // **한 단계 아래는 정상이다.** 이 검사가 거기까지 번지면 재귀 삭제가
        // 사실상 불가능해진다.
        let v = recursive_with_evidence_at(r"C:\a\evil", r"C:\a\evil\payload.exe");
        assert!(v.is_empty(), "한 단계 아래를 거부했다: {v:?}");
    }

    #[test]
    fn recursive_delete_needs_its_evidence_inside_the_directory() {
        let v = recursive_with_evidence_at(r"C:\a\evil", r"C:\a\evil\payload.exe");
        assert!(v.is_empty(), "안에 있는 근거를 거부했다: {v:?}");
    }

    #[test]
    fn recursive_delete_with_evidence_elsewhere_is_refused() {
        let v = recursive_with_evidence_at(r"C:\a\evil", r"C:\dir1\somewhere-else.exe");
        assert!(
            v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                "바깥을 가리킵니다",
                "points outside it"
            ))),
            "엉뚱한 곳을 가리키는 근거로 디렉터리를 통째로 지웠다: {v:?}"
        );
    }

    #[test]
    fn recursive_delete_with_an_unknown_evidence_path_is_refused() {
        // 확인하지 못한 것을 통과로 읽으면 가드가 없는 것과 같다.
        let f = Fixture::new();
        let dir = r"C:\a\evil";
        let mut cx = f.cx(&[dir], 1);
        cx.evidence_path = BTreeMap::new();
        let v = check(&[action(1, Op::DirDeleteRecursive, dir)], &cx);
        assert!(
            v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                "알 수 없습니다",
                "cannot tell which path"
            ))),
            "근거의 위치를 모르는데 통과시켰다: {v:?}"
        );
    }

    #[test]
    fn a_sibling_directory_does_not_satisfy_the_recursive_guard() {
        // `C:\a\evil-backup` 안의 증거로 `C:\a\evil` 을 지울 수는 없다.
        let v = recursive_with_evidence_at(r"C:\a\evil", r"C:\a\evil-backup\payload.exe");
        assert!(
            v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                "바깥을 가리킵니다",
                "points outside it"
            ))),
            "접두만 같은 형제 디렉터리가 guard 를 만족시켰다: {v:?}"
        );
    }

    fn kill(seq: u32, image: Option<&str>) -> Action {
        let mut a = action(seq, Op::ProcessKill, "");
        a.target = None;
        a.r#match = image.map(|p| serde_json::json!({ "image_path": p }));
        a
    }

    #[test]
    fn killing_a_critical_process_is_refused() {
        // 종료하면 즉시 시스템이 멈춘다. 악성코드가 같은 이름을 쓰더라도
        // **이 경로**는 겨눌 수 없다.
        let f = Fixture::new();
        for image in [
            r"C:\Windows\System32\lsass.exe",
            r"C:\Windows\System32\csrss.exe",
            r"C:\Windows\System32\wininit.exe",
        ] {
            let v = check(&[kill(1, Some(image))], &f.cx(&[], 1));
            assert!(
                v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                    "즉시 시스템이 멈추는",
                    "halts the system"
                ))),
                "{image} 를 종료하는 계획이 통과했다: {v:?}"
            );
        }
    }

    #[test]
    fn killing_an_impostor_in_a_user_directory_is_allowed() {
        // 임계 프로세스는 **경로**로 판정한다. 사용자 폴더의 같은 이름은
        // 오히려 잡아야 할 것이다.
        let f = Fixture::new();
        let v = check(&[kill(1, Some(r"C:\a\lsass.exe"))], &f.cx(&[], 1));
        assert!(v.is_empty(), "사칭 프로세스를 막았다: {v:?}");
    }

    #[test]
    fn a_kill_without_a_predicate_is_refused() {
        // 무엇을 죽일지 계획이 말하지 않으면 승인할 수도 감사할 수도 없다.
        let f = Fixture::new();
        let v = check(&[kill(1, None)], &f.cx(&[], 1));
        assert!(
            v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                "대상 술어가 없다",
                "has no target predicate"
            ))),
            "{v:?}"
        );
    }

    /// 계획에 **실제로 나오는** Op 으로도 상한이 선다. 이 시험이 없던 동안
    /// G5 는 나올 수 없는 Op 만 세고 있었다 (2026-09-08).
    #[test]
    fn g5_격리도_파일_상한에_들어간다() {
        let mut f = Fixture::new();
        f.limits.total_files = 2;
        let acts: Vec<Action> = (0..6)
            .map(|i| action(i, Op::FileQuarantineOnly, &format!("C:\\a\\b\\f{i}")))
            .collect();
        let v = check(&acts, &f.cx(&[], 1));
        // 기대값도 같은 언어로 짓는다 — 시험은 영어로 돈다(`i18n::current` 기본값).
        assert!(
            v.iter().any(|x| x.gate == "G5"
                && x.message
                    .contains(remedy_sdk::i18n::t("6개", "6 distinct files"))),
            "{v:?}"
        );
    }

    #[test]
    fn g5_distinct_files_over_limit_is_refused() {
        let mut f = Fixture::new();
        f.limits.total_files = 2;
        let acts: Vec<Action> = (0..3)
            .map(|i| action(i, Op::FileDelete, &format!("C:\\a\\b\\f{i}")))
            .collect();
        let v = check(&acts, &f.cx(&[], 1));
        assert!(v.iter().any(|x| x.gate == "G5"), "{v:?}");
    }

    #[test]
    fn g5_same_hash_items_get_their_own_limit() {
        // 랜섬노트 수천 장이 단일 상한에 걸려 치료가 중단되면, 가장 필요한 곳에서
        // 막힌다. 판정 근거가 한 번만 필요했으므로 위험이 개수에 비례하지 않는다.
        let mut f = Fixture::new();
        f.limits.total_files = 2;
        f.limits.same_hash_items = 100;

        let acts: Vec<Action> = (0..50)
            .map(|i| {
                let mut a = action(i, Op::FileDelete, &format!("C:\\a\\b\\note{i}.txt"));
                a.sha256 = Some("same".repeat(16));
                a
            })
            .collect();
        let v = check(&acts, &f.cx(&[], 1));
        assert!(
            v.is_empty(),
            "동일 해시 50장은 별도 상한(100)에 걸리지 않는다: {v:?}"
        );

        // 그런데 서로 다른 파일 3개는 여전히 막힌다. 두 상한은 독립이다.
        let mut mixed = acts.clone();
        for i in 0..3u32 {
            mixed.push(action(1000 + i, Op::FileDelete, &format!("C:\\a\\b\\x{i}")));
        }
        let v2 = check(&mixed, &f.cx(&[], 1));
        assert!(
            v2.iter().any(|x| x
                .message
                .contains(remedy_sdk::i18n::t("서로 다른 파일", "distinct files"))),
            "{v2:?}"
        );
    }

    #[test]
    fn g5_byte_limit() {
        let mut f = Fixture::new();
        f.limits.total_bytes = 100;
        let mut a = action(1, Op::FileDelete, "C:\\a\\b\\big.bin");
        a.size = Some(101);
        let v = check(&[a], &f.cx(&[], 1));
        assert!(
            v.iter()
                .any(|x| x.message.contains(remedy_sdk::i18n::t("바이트", "bytes"))),
            "{v:?}"
        );
    }

    #[test]
    fn g5_spread_across_top_directories() {
        let mut f = Fixture::new();
        f.limits.distinct_top_dirs = 2;
        let acts: Vec<Action> = (0..3)
            .map(|i| action(i, Op::FileDelete, &format!("C:\\dir{i}\\sub\\f")))
            .collect();
        let v = check(&acts, &f.cx(&[], 1));
        assert!(
            v.iter().any(|x| x.message.contains(remedy_sdk::i18n::t(
                "최상위 디렉터리",
                "top-level directories"
            ))),
            "{v:?}"
        );
    }

    #[test]
    fn g5_evidence_group_limit_needs_no_actions() {
        // 그룹 상한은 **Op 0종인 지금도 실제로 걸린다.** P3 에서 유일하게
        // 조작 입력 없이 살아 있는 가드다.
        let mut f = Fixture::new();
        f.limits.evidence_groups = 3;
        let v = check(&[], &f.cx(&[], 4));
        assert_eq!(v.len(), 1);
        assert!(
            v[0].message
                .contains(remedy_sdk::i18n::t("과광범위", "over-broad")),
            "{:?}",
            v[0]
        );
    }

    #[test]
    fn violations_are_collected_not_short_circuited() {
        // 첫 번째만 알려 주면 고치고 다시 돌리기를 반복하게 된다.
        let f = Fixture::new();
        let mut a = action(1, Op::DirDeleteRecursive, "C:\\Windows\\System32");
        a.because.clear();
        let v = check(&[a], &f.cx(&[], 1));
        assert!(v.len() >= 2, "여러 위반을 모아서 알려야 한다: {v:?}");
    }

    #[test]
    fn top_dir_extraction() {
        assert_eq!(top_dir("C:\\a\\b\\c"), Some("C:\\a".into()));
        assert_eq!(top_dir("/a/b/c"), Some("/a".into()));
        assert_eq!(top_dir(""), None);
    }

    // ── G6 의 상한은 대상의 모양마다 다르다 ───────────────────

    #[test]
    fn the_fixed_place_list_matches_the_catalog() {
        // **손으로 든 목록과 카탈로그가 갈라지면 계획이 통째로 거부된다.**
        //
        // `collected_from_a_fixed_place` 는 손목록이고 `Scoping::Fixed` 는
        // 카탈로그다. 둘이 같은 것을 말해야 하는데 강제하는 것이 없었고, 그래서
        // `Op::HostsRestoreLine` 이 빠진 채로 남아 있었다 — Windows 에서는
        // 나머지 셋의 대상이 레지스트리라 `shape_of` 에서 걸러져 드러나지
        // 않았고, Linux 하네스가 `restore: [hosts]` 를 쓰면서 처음 드러났다.
        //
        // 이 시험은 두 방향을 다 본다. 이름 원복 넷과, Fixed subject 가 낼 수
        // 있는 제거 Op 전부.
        for (name, subject, op) in remedy_sdk::catalog::RESTORE_NAMED {
            if subject.info().scoping != remedy_sdk::catalog::Scoping::Fixed {
                continue;
            }
            assert!(
                collected_from_a_fixed_place(op),
                "'{name}' 은 {} 를 되돌리는데 그 subject 는 Scoping::Fixed 다. \
                 {} 를 collected_from_a_fixed_place 에 넣을 것 — 넣지 않으면 \
                 작성자가 선언할 수 없는 자리를 상한에 적으라고 요구하게 된다",
                subject.id(),
                op.info().id
            );
        }

        for subject in remedy_sdk::catalog::Subject::ALL {
            if subject.info().scoping != remedy_sdk::catalog::Scoping::Fixed {
                continue;
            }
            for op in crate::derive::producible_ops(subject) {
                // 파일 계열로 흘러가는 것은 예외다 — `process`·`indicator` 는
                // 자리가 고정이지만 **대상이 파일 경로**라 상한이 진짜로 필요하다.
                if matches!(
                    op,
                    Op::FileQuarantineOnly
                        | Op::FileDelete
                        | Op::FileDeleteOnReboot
                        | Op::ProcessKill
                ) {
                    continue;
                }
                // **`text_config.remove_line` 은 둘이 나눠 쓴다.**
                //
                // `hosts_entry`(Fixed)와 `text_config`(Path)가 같은 Op 을 내므로
                // Op 만 보고는 가를 수 없다. 면제하면 임의 텍스트 파일의 줄
                // 제거가 상한 검사를 통째로 빠져나간다 — 그쪽이 훨씬 나쁘다.
                //
                // 그래서 `remove` 로 hosts 줄을 지우는 계획은 상한 검사를
                // 받는다. 그것이 옳다: hosts 는 `remove` 가 아니라 `restore`
                // 자리이고(22-remediate-recipes.md), `restore` 쪽은 위 첫
                // 순회가 `hosts.restore_line` 으로 이미 덮었다.
                if op == Op::TextConfigRemoveLine {
                    continue;
                }
                assert!(
                    collected_from_a_fixed_place(op),
                    "{} 는 Scoping::Fixed 인데 그것이 내는 {} 가 목록에 없다",
                    subject.id(),
                    op.info().id
                );
            }
        }
    }

    #[test]
    fn a_registry_target_is_not_measured_against_scan_roots() {
        // 레지스트리 값은 파일 시스템 밖에 있다. 경로처럼 대조하면 언제나 밖으로
        // 판정되고, 게이트를 P7 로 올리는 순간 청정 코퍼스에서 예약 작업
        // 200여 건이 전부 이 위반으로 나왔다. P6 까지는 계획될 수 있는 Op 이
        // `file.quarantine_only` 하나뿐이라 드러나지 않았다.
        let f = Fixture::new();
        let cx = f.cx_roots(&[r"C:\a"], 1, &[r"C:\a"]);
        let a = action(1, Op::RegistryDeleteValue, r"HKCU\Software\Evil\Run");
        assert_eq!(check_ceiling(&a, &cx), None);
    }

    #[test]
    fn a_task_registration_path_is_not_measured_against_scan_roots() {
        let f = Fixture::new();
        let cx = f.cx_roots(&[r"C:\a"], 1, &[r"C:\a"]);
        let a = action(1, Op::PersistenceDisable, r"\Microsoft\Windows\Locust");
        assert_eq!(check_ceiling(&a, &cx), None);
    }

    #[test]
    fn a_shape_we_do_not_know_is_still_refused() {
        // **"경로가 아니면 통과" 가 아니라 "아는 모양이면 통과" 다.** 아니면
        // 상한을 우회하는 길이 모양 하나 바꾸는 것으로 열린다.
        let f = Fixture::new();
        let cx = f.cx_roots(&[r"C:\a"], 1, &[r"C:\a"]);
        for odd in ["evil.exe", r"..\..\evil", r"HKZZ\a\b", ""] {
            let a = action(1, Op::FileQuarantineOnly, odd);
            let v = check_ceiling(&a, &cx).unwrap_or_else(|| panic!("통과했다: '{odd}'"));
            assert_eq!(v.gate, "G6");
        }
    }

    #[test]
    fn a_path_outside_the_ceiling_is_still_refused() {
        // 위 시험들이 상한 자체를 없앤 것이 아님을 확인한다.
        let f = Fixture::new();
        let cx = f.cx_roots(&[r"C:\a"], 1, &[r"C:\a"]);
        let a = action(1, Op::FileQuarantineOnly, r"C:\밖\evil.exe");
        let v = check_ceiling(&a, &cx).expect("막아야 한다");
        assert!(
            v.message.contains(remedy_sdk::i18n::t(
                "읽기 상한 밖",
                "outside the read ceiling"
            )),
            "{v:?}"
        );
    }
}
