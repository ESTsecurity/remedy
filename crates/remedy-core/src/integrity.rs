//! 코어 자기무결성 (설계-01 D7).
//!
//! > 시작 시 자기 서명을 검증하고, 실패하면 **파괴 동작을 수행하지 않는다**
//! > (스캔·보고까지만). 변조된 remedy 가 파괴 도구로 쓰이는 경로를 막는다.
//!
//! # 왜 스캔은 남기는가
//!
//! 변조된 바이너리라도 **관측과 보고는 해가 적다.** 그리고 그 실행이 남긴
//! 산출물(스냅샷·계획)이 사고를 밝히는 재료가 된다. 전부 막으면 무엇이 잘못됐는지
//! 알아낼 방법까지 함께 막힌다.
//!
//! 막는 것은 **파괴**다 — 임의의 파일을 지우고 프로세스를 죽이는 능력이 우리
//! 서명 뒤에 숨는 것이 D7 이 노리는 실패다.
//!
//! # 검사는 여기서, 강제는 진입에서
//!
//! [`check_self`] 는 `current_exe()` 를 본다. **라이브러리 함수가 그것을 스스로
//! 부르지 않는다** — 시험 바이너리를 검증하게 되고, 그 답은 제품에 대해 아무것도
//! 말하지 않는다. CLI 가 한 번 검사해 [`Stance`] 를 얻고, 파괴 명령이 그것을 본다.

use std::fmt;

/// 이 바이너리의 서명 상태.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfIntegrity {
    /// 신뢰 서명이 확인됐다.
    Verified { subject: Option<String> },
    /// 서명이 아예 없다. 개발 빌드이거나 서명 전 산출물이다.
    Unsigned,
    /// 서명이 있으나 신뢰할 수 없다 — **변조되었거나 우리 것이 아니다.**
    ///
    /// 둘을 구분하지 않는다. 서명 이후 한 바이트가 바뀐 것과 남이 자기 키로
    /// 서명한 것은 **둘 다 "우리가 만들어 서명한 그 바이너리가 아니다"** 이고,
    /// 그 사실만으로 파괴를 막기에 충분하다.
    Untrusted { subject: Option<String> },
    /// 확인하지 못했다. 이 플랫폼에 Authenticode 가 없거나 API 가 답하지 않았다.
    Unknown(String),
}

impl SelfIntegrity {
    /// 기록에 남길 **안정된 이름.**
    ///
    /// `Display` 는 사람이 읽는 문장이라 **화면 언어에 따라 달라지고**, 문구를
    /// 다듬는 순간 옛 기록과도 갈라진다. 도구가 비교할 값이 아니다. 저널은 사고를
    /// 밝히는 자리이므로 그 자리에는 흔들리지 않는 이름이 들어가야 한다
    /// (`SafeBoot::id` 와 같은 규약).
    ///
    /// **주체(누가 서명했는가)는 담지 않는다.** `Untrusted` 는 파괴에 닿지
    /// 못하므로 저널에 남는 값은 `verified`·`unsigned`·`unknown` 뿐이고, 그
    /// 셋에서 답해야 하는 질문은 *"공식 배포본이었는가"* 하나다. 누가
    /// 서명했는지는 바이너리 자신이 들고 있다.
    pub const fn id(&self) -> &'static str {
        match self {
            SelfIntegrity::Verified { .. } => "verified",
            SelfIntegrity::Unsigned => "unsigned",
            SelfIntegrity::Untrusted { .. } => "untrusted",
            SelfIntegrity::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for SelfIntegrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use remedy_sdk::i18n::t;
        match self {
            SelfIntegrity::Verified { subject } => {
                let head = t("서명 확인", "signature verified");
                match subject {
                    Some(s) => write!(f, "{head} — {s}"),
                    None => write!(f, "{head}"),
                }
            }
            SelfIntegrity::Unsigned => write!(f, "{}", t("서명 없음", "unsigned")),
            SelfIntegrity::Untrusted { subject } => {
                let head = t("신뢰할 수 없는 서명", "untrusted signature");
                match subject {
                    Some(s) => write!(f, "{head} — {s}"),
                    None => write!(f, "{head}"),
                }
            }
            SelfIntegrity::Unknown(why) => {
                write!(
                    f,
                    "{} — {why}",
                    t("확인하지 못했습니다", "could not be checked")
                )
            }
        }
    }
}

/// 이 상태에서 무엇을 해도 되는가.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stance {
    /// 전부. 파괴를 포함한다.
    Full,
    /// 스캔·보고까지만. 사유는 사람에게 그대로 보인다.
    ReadOnly { why: String },
}

impl Stance {
    pub fn allows_destruction(&self) -> bool {
        matches!(self, Stance::Full)
    }
}

/// 이 바이너리를 검사한다.
///
/// **Windows 밖에서는 `Unknown` 이다.** Linux 에는 Authenticode 가 없고, 그
/// 플랫폼의 무결성은 패키지 서명 같은 다른 수단이다 (P12). 없는 것을 있다고
/// 말하지 않는다.
pub fn check_self() -> SelfIntegrity {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return SelfIntegrity::Unknown(remedy_sdk::i18n::current().pick(
                format!("자기 경로를 얻지 못했습니다: {e}"),
                format!("could not determine this program's path: {e}"),
            ))
        }
    };
    check_path(&exe)
}

/// 경로 하나를 검사한다. 시험이 사본을 만들어 확인할 수 있게 열어 둔다.
pub fn check_path(path: &std::path::Path) -> SelfIntegrity {
    match remedy_wintrust::verify(path) {
        Ok(v) if v.trusted => SelfIntegrity::Verified { subject: v.subject },
        Ok(v) if v.kind == remedy_wintrust::SignatureKind::Unsigned => SelfIntegrity::Unsigned,
        Ok(v) => SelfIntegrity::Untrusted { subject: v.subject },
        Err(e) => SelfIntegrity::Unknown(verify_reason(&e)),
    }
}

/// `remedy-wintrust` 의 오류를 **화면 언어로** 옮긴다.
///
/// wintrust 는 의존이 하나도 없는 크레이트다 — 저장소의 유일한 `unsafe` 를 담고
/// 있어 표면을 넓히지 않는다. 그래서 그 `Display` 는 한국어 하나뿐이고, 그것을
/// 그대로 `Unknown(e.to_string())` 으로 얼리면 영어 화면에 이렇게 나온다:
///
/// ```text
/// Notice: self-integrity could not be checked (이 플랫폼에는 Authenticode 가 없다). …
/// ```
///
/// 리눅스에서 **가장 먼저 보이는 줄**이 그것이었다 (실측 2026-09-07). 언어를 아는
/// 자리는 여기이므로 여기서 고른다 — wintrust 에 의존을 더하지 않는다.
///
/// 증거에는 영향이 없다. 저널·`environment.json` 이 적는 것은 [`SelfIntegrity::id`]
/// 가 내는 안정된 토큰(`unknown`)이고, 이 문장은 화면에만 나간다.
fn verify_reason(e: &remedy_wintrust::VerifyError) -> String {
    use remedy_wintrust::VerifyError as E;
    match e {
        E::BadPath => remedy_sdk::i18n::t(
            "경로를 Windows 문자열로 옮기지 못했습니다",
            "the path could not be converted to a Windows string",
        )
        .to_string(),
        E::Unexpected(c) => remedy_sdk::i18n::current().pick(
            format!("WinVerifyTrust 가 예상 밖의 코드를 냈습니다: {c:#010x}"),
            format!("WinVerifyTrust returned an unexpected code: {c:#010x}"),
        ),
        E::Unsupported => remedy_sdk::i18n::t(
            "이 플랫폼에는 Authenticode 가 없습니다",
            "this platform has no Authenticode",
        )
        .to_string(),
    }
}

/// 개발 빌드인가.
///
/// **배포 바이너리에는 이 문이 닫혀 있다.** 설계-03 §6 이 `--allow-unsigned` 를
/// *"별도 빌드 태그가 붙은 개발 바이너리에서만 존재하며, 배포 바이너리에는
/// 플래그 자체가 없다"* 로 둔 것과 같은 규칙이다 — 여기서는 플래그가 아니라
/// 컴파일 시점의 사실이므로 실행 중에 켤 수 없다.
pub const fn is_dev_build() -> bool {
    cfg!(debug_assertions)
}

/// 검사 결과가 무엇을 허용하는가 (설계-01 D7).
///
/// | 상태 | 개발 빌드 | 배포 빌드 |
/// |---|---|---|
/// | 서명 확인 | 전부 | 전부 |
/// | **신뢰할 수 없는 서명** | **읽기만** | **읽기만** |
/// | 서명 없음 | 전부 (경고) | 전부 (경고) |
/// | 확인 불가 | 전부 (경고) | 전부 (경고) |
///
/// **신뢰할 수 없는 서명은 개발 빌드에서도 막는다.** 그것은 "아직 서명하지
/// 않았다" 가 아니라 "누군가 손댔다" 이고, 빌드 종류가 그 사실을 바꾸지 않는다.
///
/// # 서명 없음은 막지 않는다 (2026-09-02 결정)
///
/// 그 전까지는 배포 빌드에서 읽기만 허용했다. 근거는 *"배포본은 반드시
/// 서명되므로 서명 없는 배포 빌드는 우리 손을 거치지 않은 것"* 이었다.
///
/// **바꾼 이유는 그 규칙이 막는 대상이 공격자가 아니라 우리 자신이었기
/// 때문이다.** 인증서는 공식 배포의 절차이지 기능의 조건이 아닌데, 그렇게
/// 두면 시연·현장 검증·내부 시험처럼 **서명 전 바이너리로 해야 하는 일이
/// 통째로 막힌다.**
///
/// 잃는 것을 정직하게 적는다. 서명을 **떼어 낸** 바이너리가 이제 파괴를 한다.
/// 다만 그 자리에서 얻던 방어는 원래도 얇았다 — 바이너리를 바꿀 수 있는 자는
/// 검사 자체를 뺀 것으로 바꿀 수 있다. **남는 절반은 여전히 값이 있다**:
/// 서명해 두고 그 뒤에 고친 바이너리(`Untrusted`)는 계속 막는다. 그쪽은
/// 부분 다운로드·디스크 손상·실제 변조를 잡는 신호다.
///
/// 대신 **말한다.** `advisory` 가 서명 없는 배포 빌드에서도 한 줄을 낸다 —
/// 막지 않기로 했으면 남기기라도 해야 한다.
///
/// **확인 불가는 막지 않는다.** Windows 밖에서는 늘 이 값이고, 거기서 파괴를
/// 막으면 그 플랫폼에서 도구가 아예 서지 않는다. 대신 그 사실을 말한다 — 못 하는
/// 것을 못 한다고 적는 것이 이 저장소의 규칙이다.
pub fn stance(i: &SelfIntegrity) -> Stance {
    match i {
        SelfIntegrity::Verified { .. } => Stance::Full,

        SelfIntegrity::Untrusted { subject } => {
            let who = match subject {
                Some(s) => format!(" ({s})"),
                None => String::new(),
            };
            Stance::ReadOnly {
                why: remedy_sdk::i18n::current().pick(
                    format!(
                        "이 바이너리의 서명을 신뢰할 수 없다{who} — 서명 이후 내용이 바뀌었거나 \
                         우리가 만든 것이 아닙니다. 스캔과 보고는 하지만 파괴는 하지 않습니다 \
                         (설계-01 D7). 배포처에서 원본을 다시 받으십시오"
                    ),
                    format!(
                        "this binary's signature is not trusted{who} — either the contents \
                         changed after signing or we did not build it. Scanning and reporting \
                         still run, but nothing is destroyed (design-01 D7). Download the \
                         original from the distribution site again"
                    ),
                ),
            }
        }

        // 위 주석의 근거로 막지 않는다. 서명은 공식 배포의 절차이지 기능의
        // 조건이 아니다 — 대신 `advisory` 가 매 실행에서 그 사실을 말한다.
        SelfIntegrity::Unsigned => Stance::Full,

        SelfIntegrity::Unknown(_) => Stance::Full,
    }
}

/// 서명 없는 배포 빌드의 알림 (한국어, 영어).
///
/// **공식 Release 에서 받은 파일도 이 줄을 띄운다** — 코드서명이 없는 동안은 그렇다.
/// 그래서 *"공식 배포본이 아닙니다"* 라고 단정하지 않고, 서명이 없어 **스스로 확인하지
/// 못한다**는 사실과 대신 확인할 길(받은 파일의 체크섬)을 말한다(2026-11-06 결정).
/// 매 실행 첫 줄이라 기본 창 폭에서 한 줄이어야 한다 — 아래 시험이 잰다.
const UNSIGNED: (&str, &str) = (
    "코드서명이 없어 공식 배포본인지 스스로 확인하지 못합니다. 받은 파일은 체크섬으로 확인하십시오",
    "unsigned, so this binary cannot verify that it is the official release. Check the downloaded file's checksum",
);

/// 사람에게 보일 한 줄. 파괴를 막지 않는 경우에도 **말해야 하는 것**이 있다.
pub fn advisory(i: &SelfIntegrity) -> Option<String> {
    match i {
        SelfIntegrity::Verified { .. } => None,
        SelfIntegrity::Unsigned if is_dev_build() => {
            Some(
                remedy_sdk::i18n::t(
                    "개발 빌드입니다. 서명이 없고, 자기무결성 검사가 이 실행을 막지 않습니다",
                    "development build: unsigned, and the self-integrity check does not block this run",
                )
                .into(),
            )
        }
        // **배포 빌드에서도 말한다.** 막지 않기로 한 자리라 이 한 줄이 남는
        // 유일한 흔적이다. 조용하면 서명된 배포본과 구분되지 않는다.
        SelfIntegrity::Unsigned => Some(remedy_sdk::i18n::t(UNSIGNED.0, UNSIGNED.1).into()),
        SelfIntegrity::Unknown(why) => Some(remedy_sdk::i18n::current().pick(
            format!("자기무결성을 확인하지 못했습니다 ({why}). 막지는 않지만 확인된 것도 아닙니다"),
            format!("self-integrity could not be checked ({why}). Not blocking, but not verified either"),
        )),
        // 나머지는 `stance` 가 이미 사유를 들고 있다.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 신뢰할_수_없는_서명은_빌드_종류와_무관하게_막는다() {
        // "아직 서명하지 않았다" 와 "누군가 손댔다" 는 다르다. 뒤엣것은 개발
        // 빌드에서도 파괴를 허용할 이유가 없다.
        let s = stance(&SelfIntegrity::Untrusted {
            subject: Some("CN=Someone Else".into()),
        });
        assert!(!s.allows_destruction(), "{s:?}");
        let Stance::ReadOnly { why } = s else {
            unreachable!()
        };
        assert!(
            why.contains("CN=Someone Else"),
            "누가 서명했는지 말해야 한다: {why}"
        );
    }

    #[test]
    fn 서명_확인은_전부_허용한다() {
        assert!(stance(&SelfIntegrity::Verified {
            subject: Some("CN=EST security".into())
        })
        .allows_destruction());
    }

    #[test]
    fn 확인하지_못한_것은_막지_않되_말한다() {
        // Windows 밖에서는 늘 이 값이다. 여기서 막으면 그 플랫폼에서 도구가
        // 아예 서지 않는다.
        let i = SelfIntegrity::Unknown("이 플랫폼에는 Authenticode 가 없다".into());
        assert!(stance(&i).allows_destruction());
        assert!(
            advisory(&i).is_some(),
            "조용히 넘어가면 확인한 것으로 읽힌다"
        );
    }

    /// **서명은 공식 배포의 절차이지 기능의 조건이 아니다** (2026-09-02 결정).
    /// 그 전까지 배포 빌드에서 막았고, 그 규칙이 막은 것은 공격자가 아니라
    /// 시연·현장 검증·내부 시험이었다.
    #[test]
    fn 서명_없음은_막지_않되_빌드_종류와_무관하게_말한다() {
        assert!(
            stance(&SelfIntegrity::Unsigned).allows_destruction(),
            "서명이 없다는 이유로 막았다"
        );
        assert!(
            advisory(&SelfIntegrity::Unsigned).is_some(),
            "막지 않기로 했으면 말이라도 해야 한다 — 조용하면 서명된 배포본과 구분되지 않는다"
        );
    }

    /// 매 실행 첫 줄이 **기본 창(콘솔 호스트 · Windows Terminal 120칸)에서 한 줄**이다.
    /// 두 줄로 접히면 메뉴가 창을 채울 때 그 첫 줄이 창 위로 밀려 꼬리만 남는다
    /// (2026-11-06 화면 이미지 — 옛 문구는 140칸이었다). 폭은 화면 층과 같이 센다 —
    /// ASCII 가 아니면 두 칸이고, 화면이 앞에 붙이는 표시와 머리말도 센다.
    #[test]
    fn 서명_없음의_알림은_기본_창에서_한_줄이다() {
        let cols = |s: &str| {
            s.chars()
                .map(|c| if c.is_ascii() { 1 } else { 2 })
                .sum::<usize>()
        };
        for (head, note) in [("! 알림: ", UNSIGNED.0), ("! Notice: ", UNSIGNED.1)] {
            let w = cols(head) + cols(note);
            assert!(w <= 120, "{w}칸 — {head}{note}");
        }
    }

    #[test]
    fn 이_바이너리를_실제로_검사한다() {
        // 시험 바이너리에는 서명이 없다. **그것을 확인하는 것이 요점이다** —
        // 검사가 무언가를 실제로 재고 있는지, 늘 같은 값을 내는 것은 아닌지.
        let i = check_self();
        assert!(
            matches!(i, SelfIntegrity::Unsigned | SelfIntegrity::Unknown(_)),
            "서명되지 않은 시험 바이너리가 다른 값을 냈다: {i}"
        );
    }
}

#[cfg(test)]
mod reason_tests {
    use super::*;

    /// 라이브러리 시험의 기본 언어는 영어다. **영어 화면에 한글이 섞이면 안 된다.**
    #[test]
    fn 영어_화면의_사유에는_한글이_없다() {
        for e in [
            remedy_wintrust::VerifyError::Unsupported,
            remedy_wintrust::VerifyError::BadPath,
            remedy_wintrust::VerifyError::Unexpected(0x8009_2003u32 as i32),
        ] {
            let why = verify_reason(&e);
            assert!(why.is_ascii(), "영어 화면에 한글이 섞였다: {why}");
            let line = advisory(&SelfIntegrity::Unknown(why.clone())).expect("알림");
            assert!(line.is_ascii(), "영어 알림에 한글이 섞였다: {line}");
        }
    }

    /// 사유가 바뀌어도 **증거에 나가는 토큰은 그대로**다.
    #[test]
    fn 증거_토큰은_언어와_무관하다() {
        let i = SelfIntegrity::Unknown(verify_reason(&remedy_wintrust::VerifyError::Unsupported));
        assert_eq!(i.id(), "unknown");
    }

    fn 한글이_있는가(s: &str) -> bool {
        s.chars().any(|c| ('가'..='힣').contains(&c))
    }

    /// **가드가 막은 사유는 종료 코드 5 로 화면에 그대로 나간다** —
    /// `integrity_gate` 가 이 문자열을 `Failure { code: GuardStop }` 으로 옮긴다.
    /// 무인 배포가 5 를 받고 왜 막혔는지 읽지 못하면 그 코드는 반만 쓸모 있다.
    #[test]
    fn 가드가_막은_사유에는_한글이_없다() {
        for subject in [None, Some("Someone Else Co.".to_string())] {
            let Stance::ReadOnly { why } = stance(&SelfIntegrity::Untrusted { subject }) else {
                panic!("신뢰할 수 없는 서명은 읽기 전용이어야 한다");
            };
            assert!(!한글이_있는가(&why), "가드 사유에 한글이 섞였다: {why}");
        }
    }

    /// `Display` 는 `support-bundle` 의 `env.json` 에 실려 나간다 — 고객이 받아
    /// 읽고 보낼지 판단하는 파일이다. 기계가 비교하는 값은 `id()` 쪽이다.
    #[test]
    fn 꾸러미에_적는_무결성_한_줄에는_한글이_없다() {
        let who = Some("Someone Else Co.".to_string());
        for i in [
            SelfIntegrity::Verified {
                subject: who.clone(),
            },
            SelfIntegrity::Verified { subject: None },
            SelfIntegrity::Unsigned,
            SelfIntegrity::Untrusted { subject: who },
            SelfIntegrity::Untrusted { subject: None },
            SelfIntegrity::Unknown("no such file".into()),
        ] {
            let line = i.to_string();
            assert!(
                !한글이_있는가(&line),
                "꾸러미 한 줄에 한글이 섞였다: {line}"
            );
        }
    }
}
