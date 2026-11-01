//! 폐기 목록과 역행 금지 (설계-03 §6 · 설계-01 D6).
//!
//! # 킬 스위치는 2층이다
//!
//! 감염 PC 는 인터넷이 끊겨 있는 경우가 흔하므로 온라인 목록 하나에 기댈 수
//! 없다. 그리고 네트워크를 막을 수 있는 공격자는 폐기 조회도 막을 수 있으므로,
//! **조회 실패를 통과로 처리하는 것은 공격자가 스스로 유발할 수 있는 실패**다.
//!
//! | 층 | 무엇 | 네트워크 |
//! |---|---|---|
//! | (a) 폐기 목록 | 서명된 목록. 최신·세밀한 통제 | 배포에만 필요 |
//! | (b) 코어 내장 최소 버전 + **역행 금지** | 오프라인에서 실제로 강제되는 것 | 필요 없다 |
//!
//! (b)를 만료 시각이 아니라 **버전**으로 두는 것이 핵심이다. 악성코드는 시스템
//! 시계를 흔히 조작하므로 만료 기반 규칙은 시계를 되돌려 무장 해제할 수 있지만,
//! 버전 비교는 그렇지 않다.
//!
//! # 파일 하나에 서명과 본문을 함께 담는다
//!
//! ```text
//! untrusted comment: remedy revocation list
//! RUR…                                        ← 서명
//! trusted comment: remedy-revocations serial=7 issued=2026-08-26T00:00:00Z
//! …                                           ← 주석까지 덮는 서명
//!                                             ← 빈 줄
//! {"schema_version":1,"entries":[…]}          ← 서명 대상 본문
//! ```
//!
//! minisign 관례는 서명을 별도 파일로 두는 것이지만, 이 목록은 **파일 공유나
//! 이동식 매체로 폐쇄망에 반입된다**(설계-03 §6). 두 파일이면 하나만 옮기는
//! 사고가 생기고, 본문만 옮겨진 것은 "서명이 없다" 로 보이지만 서명만 옮겨진
//! 것은 아무 말도 하지 않는다. 하나로 묶으면 그 사고가 없다.
//!
//! 쪼개기는 쉽다 — 앞 4줄이 `.minisig`, 빈 줄 뒤가 본문이다. 제3자가 외부
//! `minisign` 으로 확인하려면 그렇게 나누면 된다.
//!
//! # serial 과 발행 시각은 본문이 아니라 서명 주석에 있다
//!
//! 두 곳에 두면 갈라지고, 갈라지면 어느 쪽이 참인지 알 수 없다. 주석은 서명이
//! 덮으므로 고칠 수 없다.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::version::{Range, Version};
use crate::{Anchor, TrustError};

/// 목록 본문의 스키마 버전.
pub const SCHEMA_VERSION: u32 = 1;

/// 상태 디렉터리 안에서 반입된 목록이 앉는 자리.
pub const LIST_FILE: &str = "revocations.sig";

/// 역행 금지 상태가 앉는 자리. **이름을 한 곳에만 둔다** — 쓰는 쪽과 읽는 쪽이
/// 다른 이름을 쓰면 상태가 조용히 비어 있게 되고, 그러면 역행 금지가 없다.
pub const STATE_FILE: &str = "trust-state.json";

/// 서명 주석의 접두. 플러그인 서명(`remedy-plugin …`)과 섞이지 않게 한다 —
/// **플러그인 서명을 폐기 목록으로 들이밀 수 없어야** 한다.
const COMMENT_PREFIX: &str = "remedy-revocations ";

// ───────────────────────────────────────────────────────── 목록

/// 폐기 한 건.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// 대상 플러그인 id.
    pub plugin: String,
    /// 이 버전 **미만** 전부. `exact` 와 둘 중 하나만 있어야 한다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub below: Option<String>,
    /// 이 버전 하나만.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    /// 왜 폐기했는가. **비워 둘 수 없다** — 사유 없는 폐기는 나중에 누구도
    /// 되돌릴지 판단할 수 없다.
    pub reason: String,
}

impl Entry {
    fn range(&self) -> Result<Range, TrustError> {
        let bad = |m: String| TrustError::Revocation(m);
        match (&self.below, &self.exact) {
            (Some(b), None) => Version::parse(b).map(Range::Below).ok_or_else(|| {
                bad(format!(
                    "'{}' 의 below 가 x.y.z 가 아니다: {b:?}",
                    self.plugin
                ))
            }),
            (None, Some(e)) => Version::parse(e).map(Range::Exact).ok_or_else(|| {
                bad(format!(
                    "'{}' 의 exact 가 x.y.z 가 아니다: {e:?}",
                    self.plugin
                ))
            }),
            (Some(_), Some(_)) => Err(bad(format!(
                "'{}' 에 below 와 exact 가 둘 다 있습니다 — 어느 쪽을 겨누는지 알 수 없습니다",
                self.plugin
            ))),
            (None, None) => Err(bad(format!(
                "'{}' 에 below 도 exact 도 없습니다 — 무엇을 폐기하는지 말하지 않습니다",
                self.plugin
            ))),
        }
    }
}

/// 목록 본문 (서명 대상).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    pub schema_version: u32,
    #[serde(default)]
    pub entries: Vec<Entry>,
}

/// 서명이 확인된 폐기 목록.
///
/// **이 값이 있다는 것은 서명이 통과했다는 뜻이다.** 실패 경로에서는 만들어지지
/// 않으므로 호출자가 검증 여부를 따로 기억할 필요가 없다 — 플러그인 서명의
/// `Verified` 와 같은 규칙이다.
#[derive(Debug, Clone)]
pub struct RevocationList {
    serial: u64,
    issued_at: String,
    entries: Vec<(Entry, Range)>,
}

impl RevocationList {
    /// 단조 증가 일련번호. 역행 금지가 이 값을 본다.
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// 발행 시각 (RFC3339 UTC). **신선도 판정의 기준**이다.
    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().map(|(e, _)| e)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 이 플러그인·버전을 겨누는 항목이 있으면 그 사유.
    pub fn covering(&self, plugin: &str, version: Version) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|(e, r)| e.plugin == plugin && r.covers(version))
            .map(|(e, _)| e)
    }
}

/// 목록 본문을 만든다. 서명 도구가 쓴다.
pub fn render_body(entries: &[Entry]) -> Result<String, TrustError> {
    for e in entries {
        e.range()?; // 만들 때 걸러 낸다 — 서명한 뒤에 형식 오류를 알면 늦다
        if e.reason.trim().is_empty() {
            return Err(TrustError::Revocation(format!(
                "'{}' 에 사유가 없습니다",
                e.plugin
            )));
        }
    }
    let body = Body {
        schema_version: SCHEMA_VERSION,
        entries: entries.to_vec(),
    };
    serde_json::to_string_pretty(&body)
        .map_err(|e| TrustError::Revocation(format!("본문을 만들지 못했습니다: {e}")))
}

/// 서명 주석을 만든다.
pub fn render_comment(serial: u64, issued_at: &str) -> String {
    format!("{COMMENT_PREFIX}serial={serial} issued={issued_at}")
}

/// 서명된 목록 파일 하나를 읽는다.
///
/// 서명이 맞지 않으면 `Err` 다 — **"폐기 목록이 없다" 와 "폐기 목록을 지웠다"
/// 를 구분할 수 있어야** 하고, 서명이 그 구분을 만든다.
pub fn parse_signed(anchor: &Anchor, text: &str) -> Result<RevocationList, TrustError> {
    let (sig, body_text) = split(text)?;
    let comment = crate::verify_signed(anchor, body_text.as_bytes(), &sig)?;

    let (serial, issued_at) = parse_comment(&comment)?;

    let body: Body = serde_json::from_str(body_text)
        .map_err(|e| TrustError::Revocation(format!("본문을 읽지 못했습니다: {e}")))?;
    if body.schema_version != SCHEMA_VERSION {
        return Err(TrustError::Revocation(format!(
            "모르는 schema_version {} (이 코어는 {SCHEMA_VERSION})",
            body.schema_version
        )));
    }

    let mut entries = Vec::with_capacity(body.entries.len());
    for e in body.entries {
        let r = e.range()?;
        if e.reason.trim().is_empty() {
            return Err(TrustError::Revocation(format!(
                "'{}' 에 사유가 없습니다",
                e.plugin
            )));
        }
        entries.push((e, r));
    }

    Ok(RevocationList {
        serial,
        issued_at,
        entries,
    })
}

/// 서명 4줄과 본문을 가른다.
/// 서명 4줄과 본문을 가른다.
///
/// **허용 목록도 같은 형식이다** — 파일 하나에 서명과 본문을 담는 이유(위 모듈
/// 주석)가 그쪽에도 그대로 적용된다. 두 곳에 같은 파서를 두면 언젠가 갈라지고,
/// 갈라진 파서는 한쪽만 고쳐진다.
pub(crate) fn split(text: &str) -> Result<(String, &str), TrustError> {
    let mut idx = 0usize;
    let mut lines = 0usize;
    for line in text.split_inclusive('\n') {
        idx += line.len();
        lines += 1;
        if lines == 4 {
            break;
        }
    }
    if lines < 4 {
        return Err(TrustError::Revocation(
            "서명 4줄이 없습니다 — 서명된 목록 파일이 아닙니다".into(),
        ));
    }
    let sig = text[..idx].to_string();
    // 빈 줄 하나를 건너뛴다. 없으면 형식이 아니다.
    let rest = &text[idx..];
    let body = rest
        .strip_prefix("\r\n")
        .or_else(|| rest.strip_prefix('\n'))
        .ok_or_else(|| {
            TrustError::Revocation("서명 뒤에 빈 줄이 없습니다 — 본문이 시작되지 않습니다".into())
        })?;
    if body.trim().is_empty() {
        return Err(TrustError::Revocation("본문이 비어 있습니다".into()));
    }
    Ok((sig, body))
}

fn parse_comment(raw: &str) -> Result<(u64, String), TrustError> {
    let body = raw.strip_prefix(COMMENT_PREFIX).ok_or_else(|| {
        TrustError::Revocation(format!(
            "폐기 목록 서명이 아니다 — 주석이 {COMMENT_PREFIX:?} 로 시작하지 않는다: {raw:?}"
        ))
    })?;
    parse_serial_issued(body)
}

/// 접두를 뗀 주석에서 `serial` 과 `issued` 를 읽는다.
///
/// **접두는 부르는 쪽이 확인한다** — 그것이 폐기 목록과 허용 목록을 가르는
/// 자리이고, 여기서 함께 보면 한쪽을 다른 쪽으로 들이밀 수 있게 된다.
pub(crate) fn parse_serial_issued(raw: &str) -> Result<(u64, String), TrustError> {
    let body = raw;
    let mut serial = None;
    let mut issued = None;
    for tok in body.split_whitespace() {
        let Some((k, v)) = tok.split_once('=') else {
            return Err(TrustError::Revocation(format!(
                "키=값 이 아닌 토큰: {tok:?}"
            )));
        };
        match k {
            "serial" => {
                serial =
                    Some(v.parse::<u64>().map_err(|_| {
                        TrustError::Revocation(format!("serial 이 수가 아니다: {v:?}"))
                    })?)
            }
            "issued" => issued = Some(v.to_string()),
            other => return Err(TrustError::Revocation(format!("모르는 키: {other:?}"))),
        }
    }
    match (serial, issued) {
        (Some(s), Some(i)) => Ok((s, i)),
        _ => Err(TrustError::Revocation(format!(
            "serial 과 issued 가 둘 다 있어야 한다: {raw:?}"
        ))),
    }
}

// ───────────────────────────────────────────── 역행 금지 상태

/// 이 기계가 지금까지 본 것 중 가장 높은 값들.
///
/// # 이 파일은 변조될 수 있다
///
/// 관리자 권한 공격자는 이 상태를 지우거나 낮출 수 있다. Android Verified Boot
/// 는 이것을 변조 감지 가능 저장소에 두지만 우리에게는 그런 자리가 없다.
///
/// **그래서 2층인 것이다.** 상태를 지우면 판정은 코어에 컴파일된 하한
/// ([`MinVersions`])으로 떨어지고, 그것은 바이너리를 바꾸지 않는 한 낮출 수
/// 없다. 상태는 하한을 **올려 두는** 장치이지 하한 자체가 아니다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustState {
    /// 지금까지 본 폐기 목록 중 가장 큰 serial.
    #[serde(default)]
    pub revocation_serial: u64,
    /// 지금까지 본 **허용 목록** 중 가장 큰 serial (설계-03 §3 5층).
    ///
    /// 폐기 목록과 따로 센다 — 둘은 다른 사람이 다른 주기로 발행할 수 있고,
    /// 한 값으로 묶으면 한쪽을 올릴 때 다른 쪽이 함께 올라 **낡지 않은 목록이
    /// 낡았다고 거부된다.**
    ///
    /// `#[serde(default)]` 이라 이 필드가 없는 옛 상태 파일도 그대로 읽힌다.
    #[serde(default)]
    pub allowlist_serial: u64,
    /// 플러그인별로 지금까지 본 가장 높은 버전.
    #[serde(default)]
    pub plugins: BTreeMap<String, String>,
}

impl TrustState {
    /// 이 플러그인에 대해 관측한 최고 버전.
    pub fn seen(&self, plugin: &str) -> Option<Version> {
        self.plugins.get(plugin).and_then(|s| Version::parse(s))
    }

    /// 관측을 기록한다. **낮아지지 않는다** — 그것이 역행 금지의 본체다.
    pub fn observe_plugin(&mut self, plugin: &str, v: Version) {
        let higher = match self.seen(plugin) {
            Some(cur) if cur >= v => cur,
            _ => v,
        };
        self.plugins.insert(plugin.to_string(), higher.to_string());
    }

    pub fn observe_revocation(&mut self, serial: u64) {
        self.revocation_serial = self.revocation_serial.max(serial);
    }

    /// 허용 목록 관측. **낮아지지 않는다** — 회수된 면제가 옛 목록으로
    /// 되살아나는 것을 막는 것이 이 값의 몫이다.
    pub fn observe_allowlist(&mut self, serial: u64) {
        self.allowlist_serial = self.allowlist_serial.max(serial);
    }
}

/// 코어 바이너리에 **컴파일되는** 최소 버전 표 (설계-01 D6).
///
/// 비어 있는 것이 지금의 사실이다 — 아직 아무 플러그인도 폐기하지 않았다.
/// 값을 채우는 것은 코어 재배포이고, 설계-01 D7 이 *"코어 재배포가 곧 폐기
/// 메커니즘의 집행"* 이라고 적은 것이 이 자리다.
#[derive(Debug, Clone, Default)]
pub struct MinVersions {
    table: BTreeMap<String, Version>,
}

impl MinVersions {
    /// `[(플러그인 id, "x.y.z")]` 에서 만든다. 형식이 어긋나면 **패닉이 아니라
    /// 오류**다 — 코어에 박히는 값이므로 빌드가 아니라 기동에서 걸린다.
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Result<Self, TrustError> {
        let mut table = BTreeMap::new();
        for (id, v) in pairs {
            let parsed = Version::parse(v).ok_or_else(|| {
                TrustError::Revocation(format!("내장 최소 버전 '{id}' = {v:?} 가 x.y.z 가 아니다"))
            })?;
            table.insert((*id).to_string(), parsed);
        }
        Ok(Self { table })
    }

    pub fn get(&self, plugin: &str) -> Option<Version> {
        self.table.get(plugin).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

// ───────────────────────────────────────────────────────── 판정

/// 로드를 막는 이유.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// 버전이 `x.y.z` 가 아니다. **판정할 수 없으므로 거부한다.**
    UnreadableVersion { plugin: String, raw: String },
    /// 폐기 목록이 이 버전을 겨눈다.
    Revoked {
        plugin: String,
        version: Version,
        reason: String,
    },
    /// 코어에 박힌 하한보다 낮다.
    BelowMinimum {
        plugin: String,
        version: Version,
        minimum: Version,
    },
    /// 전에 더 높은 버전을 봤다 — 되돌리기 시도다.
    Rollback {
        plugin: String,
        version: Version,
        seen: Version,
    },
    /// 폐기 목록의 serial 이 전에 본 것보다 낮다.
    StaleRevocations { serial: u64, seen: u64 },
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::UnreadableVersion { plugin, raw } => write!(
                f,
                "'{plugin}' 의 버전 {raw:?} 를 읽지 못했다 — x.y.z 여야 폐기 여부를 판정할 수 있다"
            ),
            Denial::Revoked {
                plugin,
                version,
                reason,
            } => write!(f, "'{plugin}' {version} 은 폐기됐습니다: {reason}"),
            Denial::BelowMinimum {
                plugin,
                version,
                minimum,
            } => write!(
                f,
                "'{plugin}' {version} 은 이 코어가 요구하는 최소 버전 {minimum} 보다 낮습니다"
            ),
            Denial::Rollback {
                plugin,
                version,
                seen,
            } => write!(
                f,
                "'{plugin}' {version} 은 이 기계가 전에 본 {seen} 보다 낮습니다 — 되돌리기는 받지 않습니다"
            ),
            Denial::StaleRevocations { serial, seen } => write!(
                f,
                "폐기 목록 serial {serial} 이 전에 본 {seen} 보다 낮습니다 — 옛 목록으로 되돌릴 수 없습니다"
            ),
        }
    }
}

impl std::error::Error for Denial {}

/// 이 플러그인을 로드해도 되는가.
///
/// 세 층을 **순서대로** 본다 — 폐기 목록(a) · 코어 하한(b) · 역행 금지(b).
/// 어느 하나라도 걸리면 거부이고, 목록이 없어도 (b) 는 그대로 작동한다.
pub fn check_plugin(
    plugin: &str,
    version_raw: &str,
    list: Option<&RevocationList>,
    min: &MinVersions,
    state: &TrustState,
) -> Result<Version, Denial> {
    let Some(v) = Version::parse(version_raw) else {
        return Err(Denial::UnreadableVersion {
            plugin: plugin.to_string(),
            raw: version_raw.to_string(),
        });
    };

    if let Some(e) = list.and_then(|l| l.covering(plugin, v)) {
        return Err(Denial::Revoked {
            plugin: plugin.to_string(),
            version: v,
            reason: e.reason.clone(),
        });
    }
    if let Some(m) = min.get(plugin) {
        if v < m {
            return Err(Denial::BelowMinimum {
                plugin: plugin.to_string(),
                version: v,
                minimum: m,
            });
        }
    }
    if let Some(seen) = state.seen(plugin) {
        if v < seen {
            return Err(Denial::Rollback {
                plugin: plugin.to_string(),
                version: v,
                seen,
            });
        }
    }
    Ok(v)
}

/// 새 폐기 목록을 받아들여도 되는가. **역행 금지가 목록에도 걸린다.**
pub fn check_revocations(list: &RevocationList, state: &TrustState) -> Result<(), Denial> {
    if list.serial < state.revocation_serial {
        return Err(Denial::StaleRevocations {
            serial: list.serial,
            seen: state.revocation_serial,
        });
    }
    Ok(())
}

// ───────────────────────────────────────────────────── 신선도

/// 폐기 목록이 얼마나 새것인가.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    /// 목록이 아예 없다.
    Absent,
    /// 있고, 발행 시각이 이것이다.
    Known { issued_at: String },
}

/// 신선도에 따라 무엇을 할 것인가.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// 그대로 진행한다.
    Proceed,
    /// 진행하되 사람에게 말한다.
    WarnAndProceed(String),
    /// 멈춘다.
    Stop(String),
}

/// 신선도 정책 (설계-03 §6).
///
/// # 왜 모드로 가르는가
///
/// 판단 기준은 HTTP 캐싱의 `must-revalidate` 정의가 가장 명료하다 — **낡은
/// 데이터를 받아들이는 것이 "조용한 오작동" 을 유발할 때만 fail-closed** 로
/// 가고, 단지 확신이 낮아지는 것뿐이라면 경고로 족하다.
///
/// - 무인 배포에서 폐기된 플러그인이 도는 것은 **조용한 오작동**이다
/// - 대화형 실행에서 신선도 정보가 낡은 것은 **확신 저하**다
///
/// 그리고 인터넷 없는 감염 PC 가 이 도구를 가장 필요로 하는 상황이다. 거기서
/// 막으면 도구가 아니라 장애물이 된다.
pub fn freshness_policy(f: &Freshness, unattended: bool) -> Policy {
    match (f, unattended) {
        (Freshness::Known { .. }, _) => Policy::Proceed,
        (Freshness::Absent, false) => Policy::WarnAndProceed(
            "폐기 목록이 없습니다 — 폐기된 플러그인을 걸러 내지 못한 채로 진행합니다. \
             `revocation import` 로 목록을 반입하면 이 경고가 사라집니다"
                .into(),
        ),
        (Freshness::Absent, true) => Policy::Stop(
            "폐기 목록이 없어 무인 실행을 멈춥니다. 폐쇄망이라면 인터넷에 연결된 \
             기계에서 목록을 받아 `--revocations <파일>` 로 반입하십시오 (설계-03 §6). \
             사람이 보고 있지 않은 곳에서 폐기된 플러그인이 도는 것은 조용한 오작동입니다"
                .into(),
        ),
    }
}
