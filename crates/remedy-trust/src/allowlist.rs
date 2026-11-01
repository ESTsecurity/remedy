//! 조직 서명 허용 목록 (설계-03 §3 5층).
//!
//! # 왜 우리가 직접 갖는가
//!
//! 설계-03 §3 의 5층은 원래 **사내 분석 시스템이 부여한 화이트리스트 태그**를
//! 근거로 삼는다. 그 시스템의 `clean` 은 *"정상임이 확인됨"* 이 아니라
//! **"패턴 점수 20 미만"** 이라(설계-05 §3), 점수를 제외 근거로 쓰면 **회피에
//! 성공한 악성코드가 자동으로 면제된다.** 그래서 명시적 태그만이 쓸 수 있는
//! 신호였다.
//!
//! 그 태그를 요청하는 대신 **조직이 서명한 목록을 우리가 직접 갖기로 했다**
//! (2026-08-28 P13 결정). 부여·회수 주체와 이력이 우리 서명 체계 안에 있어
//! 감사에 답할 수 있고, 저쪽 운영 부담이 없으며, **`enrich`(P13)를 기다리지
//! 않아도 v1 에서 5층이 선다.**
//!
//! # 폐기 목록과 같은 레일이다
//!
//! 형식·서명·역행 금지가 [`revocation`](crate::revocation) 과 같다. 다른 것은
//! **방향**뿐이다.
//!
//! | | 폐기 목록 | 허용 목록 |
//! |---|---|---|
//! | 없으면 | 폐기 여부를 확인하지 못했다 (경고) | **면제가 없다** — 안전한 쪽 |
//! | 무엇을 여나 | 아무것도. 닫는다 | 파괴 대상에서 뺀다 |
//! | 역행 금지가 막는 것 | 폐기된 플러그인의 부활 | **회수된 면제의 부활** |
//!
//! 마지막 줄이 이 목록에도 역행 금지가 필요한 이유다. 어떤 해시를 면제했다가
//! **악성으로 드러나 목록에서 뺐다면**, 옛 목록을 되밀어 그 면제를 되살릴 수
//! 있으면 안 된다.
//!
//! # 해시로만 지목한다
//!
//! 경로로 지목하면 **그 자리에 파일을 놓는 것만으로 면제를 얻는다.** 서명
//! 주체로 지목하는 것은 2층이 이미 하는 일이고, 여기서 겹치면 같은 판단이 두
//! 곳에 생긴다.
//!
//! SHA-256 은 그 파일 자체를 가리키고 이름을 바꿔도 따라간다. 대신 **해시가
//! 없는 대상은 이 목록으로 면제되지 않는다** — 레지스트리 값·예약 작업이
//! 그렇고, 그것은 다른 종류의 결정이다.

use serde::{Deserialize, Serialize};

use crate::{Anchor, TrustError};

/// 목록 본문의 스키마 버전.
pub const SCHEMA_VERSION: u32 = 1;

/// 상태 디렉터리 안에서 반입된 목록이 앉는 자리.
pub const LIST_FILE: &str = "allowlist.sig";

/// 서명 주석의 접두. **폐기 목록을 허용 목록으로 들이밀 수 없어야** 한다 —
/// 그 둘은 방향이 정반대다.
const COMMENT_PREFIX: &str = "remedy-allowlist ";

/// 허용 목록이 틀렸다. **두 언어를 다 받는다.**
///
/// 이 크레이트의 다른 사유와 달리 여기 것은 **고객 화면에 나간다** —
/// `main.rs` 의 `load_allowed` 가 `scan`·`run` 에서 불러 종료 코드 5 로 낸다.
/// 인자를 하나만 받던 동안 그 사실이 보이지 않았다.
fn bad(ko: impl Into<String>, en: impl Into<String>) -> TrustError {
    TrustError::Revocation(remedy_sdk::i18n::current().pick(ko.into(), en.into()))
}

// ───────────────────────────────────────────────────────── 목록

/// 면제 한 건.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// 대상 파일의 SHA-256. 대소문자는 가리지 않는다.
    pub sha256: String,
    /// **왜 면제하는가.** 비워 둘 수 없다 — 사유 없는 면제는 나중에 누구도
    /// 되돌릴지 판단할 수 없고, 그것이 이 목록이 감사에 답하는 방식이다.
    pub reason: String,
}

impl Entry {
    /// 해시가 SHA-256 의 모양인가.
    ///
    /// **틀린 해시는 조용히 아무것도 면제하지 않는다.** 방향은 안전하지만
    /// 운영자는 면제된 줄 안다 — 그래서 만들 때 걸러 낸다.
    fn check(&self) -> Result<(), TrustError> {
        let h = self.sha256.trim();
        if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(bad(
                format!(
                    "'{}' 은 SHA-256 이 아닙니다 — 16진 64자여야 합니다",
                    self.sha256
                ),
                format!(
                    "'{}' is not a SHA-256 — it must be 64 hex characters",
                    self.sha256
                ),
            ));
        }
        if self.reason.trim().is_empty() {
            return Err(bad(
                format!("{} 에 사유가 없습니다", &h[..12]),
                format!("{} has no reason", &h[..12]),
            ));
        }
        Ok(())
    }
}

/// 목록 본문 (서명 대상).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    pub schema_version: u32,
    #[serde(default)]
    pub entries: Vec<Entry>,
}

/// 서명이 확인된 허용 목록.
///
/// **이 값이 있다는 것은 서명이 통과했다는 뜻이다.** 실패 경로에서는 만들어지지
/// 않으므로 호출자가 검증 여부를 따로 기억할 필요가 없다.
#[derive(Debug, Clone)]
pub struct Allowlist {
    serial: u64,
    issued_at: String,
    entries: Vec<Entry>,
}

impl Allowlist {
    /// 단조 증가 일련번호. 역행 금지가 이 값을 본다.
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// 발행 시각 (RFC3339 UTC).
    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 이 해시를 면제하는 항목이 있으면 그것.
    ///
    /// 대소문자를 가리지 않는다 — 도구마다 표기가 갈리고, 그것 때문에 면제가
    /// 조용히 빗나가면 운영자는 이유를 알 수 없다.
    pub fn covering(&self, sha256: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.sha256.eq_ignore_ascii_case(sha256.trim()))
    }
}

/// 목록 본문을 만든다. 서명 도구가 쓴다.
pub fn render_body(entries: &[Entry]) -> Result<String, TrustError> {
    for e in entries {
        e.check()?; // 만들 때 걸러 낸다 — 서명한 뒤에 형식 오류를 알면 늦다
    }
    let body = Body {
        schema_version: SCHEMA_VERSION,
        entries: entries.to_vec(),
    };
    serde_json::to_string_pretty(&body).map_err(|e| {
        bad(
            format!("본문을 만들지 못했습니다: {e}"),
            format!("the body could not be built: {e}"),
        )
    })
}

/// 서명 주석을 만든다.
pub fn render_comment(serial: u64, issued_at: &str) -> String {
    format!("{COMMENT_PREFIX}serial={serial} issued={issued_at}")
}

/// 서명된 목록 파일 하나를 읽는다.
///
/// 서명이 맞지 않으면 `Err` 다 — **"허용 목록이 없다" 와 "허용 목록을
/// 바꿔치기했다" 를 구분할 수 있어야** 하고, 서명이 그 구분을 만든다.
pub fn parse_signed(anchor: &Anchor, text: &str) -> Result<Allowlist, TrustError> {
    let (sig, body_text) = crate::revocation::split(text)?;
    let comment = crate::verify_signed(anchor, body_text.as_bytes(), &sig)?;

    let rest = comment.strip_prefix(COMMENT_PREFIX).ok_or_else(|| {
        bad(
            format!("허용 목록의 서명 주석이 아니다: {comment:?}"),
            format!("not an allowlist signature comment: {comment:?}"),
        )
    })?;
    let (serial, issued_at) = crate::revocation::parse_serial_issued(rest)?;

    let body: Body = serde_json::from_str(body_text).map_err(|e| {
        bad(
            format!("본문을 읽지 못했습니다: {e}"),
            format!("the body could not be read: {e}"),
        )
    })?;
    if body.schema_version != SCHEMA_VERSION {
        return Err(bad(
            format!(
                "모르는 schema_version {} (이 코어는 {SCHEMA_VERSION})",
                body.schema_version
            ),
            format!(
                "unknown schema_version {} (this core is {SCHEMA_VERSION})",
                body.schema_version
            ),
        ));
    }
    for e in &body.entries {
        e.check()?;
    }
    Ok(Allowlist {
        serial,
        issued_at,
        entries: body.entries,
    })
}

/// 역행 금지. **회수된 면제가 옛 목록으로 되살아나면 안 된다.**
pub fn check_allowlist(
    list: &Allowlist,
    state: &crate::revocation::TrustState,
) -> Result<(), StaleAllowlist> {
    if list.serial < state.allowlist_serial {
        return Err(StaleAllowlist {
            serial: list.serial,
            seen: state.allowlist_serial,
        });
    }
    Ok(())
}

/// 옛 허용 목록을 되밀었다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleAllowlist {
    pub serial: u64,
    pub seen: u64,
}

impl std::fmt::Display for StaleAllowlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (serial, seen) = (self.serial, self.seen);
        write!(
            f,
            "{}",
            remedy_sdk::i18n::current().pick(
                format!(
                    "허용 목록이 낡았습니다 (serial {serial} < 이미 본 {seen}). \
                     회수된 면제를 옛 목록으로 되살릴 수 없습니다"
                ),
                format!(
                    "the allowlist is stale (serial {serial} < already seen {seen}). \
                     A withdrawn exemption cannot be brought back with an older list"
                ),
            )
        )
    }
}

/// 계획기가 받는 모양. **서명을 모른다.**
///
/// 검증은 이 크레이트의 일이고, 계획기는 *"이 해시가 면제인가"* 만 물으면 된다.
/// 그렇게 갈라 두면 계획기 시험이 minisign 키 없이 돈다.
pub type Allowed = std::collections::BTreeMap<String, String>;

/// 검증된 목록을 계획기가 쓸 모양으로 편다.
///
/// 키는 **소문자 해시**다. 조회하는 쪽도 소문자로 맞춘다 — 표기가 갈려 면제가
/// 빗나가는 것을 한 곳에서 막는다.
pub fn flatten(list: &Allowlist) -> Allowed {
    list.entries()
        .map(|e| (e.sha256.trim().to_ascii_lowercase(), e.reason.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn has_hangul(s: &str) -> bool {
        s.chars().any(|c| ('가'..='힣').contains(&c))
    }

    /// **이 크레이트에서 고객 화면에 닿는 것은 허용 목록뿐이다.**
    /// `main.rs` 의 `load_allowed` 가 `scan`·`run` 에서 불러 종료 코드 5 로 낸다.
    /// 나머지(`revocation`·`manifest`)는 도구 명령에서만 나오므로 09-06 결정대로
    /// 한국어로 남는다.
    ///
    /// **이름을 그대로 둔 것**은 아래 시험들을 고치지 않기 위해서다.
    fn render_body(entries: &[Entry]) -> Result<String, TrustError> {
        let r = super::render_body(entries);
        if let Err(e) = &r {
            assert!(!has_hangul(&e.to_string()), "{e}");
        }
        r
    }

    fn check_allowlist(
        list: &Allowlist,
        state: &crate::revocation::TrustState,
    ) -> Result<(), StaleAllowlist> {
        let r = super::check_allowlist(list, state);
        if let Err(d) = &r {
            assert!(!has_hangul(&d.to_string()), "{d}");
        }
        r
    }

    fn entry(h: &str, why: &str) -> Entry {
        Entry {
            sha256: h.into(),
            reason: why.into(),
        }
    }

    #[test]
    fn a_reason_is_required() {
        // **사유 없는 면제는 감사에 답할 수 없다.** 서명한 뒤에 알면 늦으므로
        // 만들 때 막는다.
        let e = render_body(&[entry(H, "  ")]).expect_err("막아야 한다");
        // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
        assert!(
            format!("{e}").contains(remedy_sdk::i18n::t("사유", "reason")),
            "{e}"
        );
    }

    #[test]
    fn a_hash_that_is_not_a_hash_is_refused() {
        // 틀린 해시는 조용히 아무것도 면제하지 않는다 — 방향은 안전하지만
        // 운영자는 면제된 줄 안다.
        for bad_hash in [
            "deadbeef",
            "",
            &H[..63],
            &format!("{H}0"),
            &H.replace('e', "z"),
        ] {
            let r = render_body(&[entry(bad_hash, "랩")]);
            assert!(r.is_err(), "'{bad_hash}' 가 통과했다");
        }
        assert!(render_body(&[entry(H, "랩")]).is_ok());
    }

    #[test]
    fn case_does_not_decide_whether_an_exemption_applies() {
        // 도구마다 대소문자 표기가 갈린다. 그것 때문에 면제가 빗나가면
        // 운영자는 이유를 알 수 없다.
        let list = Allowlist {
            serial: 1,
            issued_at: "2026-08-29T00:00:00Z".into(),
            entries: vec![entry(&H.to_ascii_uppercase(), "랩")],
        };
        assert!(list.covering(H).is_some(), "소문자로 못 찾았다");
        assert!(list.covering(&H.to_ascii_uppercase()).is_some());
        assert!(
            list.covering(&H.replace('e', "f")).is_none(),
            "엉뚱한 해시가 맞았다"
        );
    }

    #[test]
    fn an_older_list_cannot_bring_back_a_withdrawn_exemption() {
        // **이 목록에도 역행 금지가 필요한 이유다.** 악성으로 드러나 뺀 면제를
        // 옛 목록을 되밀어 되살릴 수 있으면 안 된다.
        let mut state = crate::revocation::TrustState::default();
        state.observe_allowlist(7);

        let old = Allowlist {
            serial: 6,
            issued_at: "2026-01-01T00:00:00Z".into(),
            entries: Vec::new(),
        };
        let e = check_allowlist(&old, &state).expect_err("막아야 한다");
        assert_eq!(e.serial, 6);
        assert_eq!(e.seen, 7);

        let same = Allowlist {
            serial: 7,
            ..old.clone()
        };
        assert!(
            check_allowlist(&same, &state).is_ok(),
            "같은 serial 은 통과해야 한다"
        );
    }

    #[test]
    fn flatten_lowercases_so_lookups_cannot_miss() {
        let list = Allowlist {
            serial: 1,
            issued_at: "2026-08-29T00:00:00Z".into(),
            entries: vec![entry(&H.to_ascii_uppercase(), "랩 승인")],
        };
        let flat = flatten(&list);
        assert_eq!(flat.get(H).map(String::as_str), Some("랩 승인"));
    }
}
