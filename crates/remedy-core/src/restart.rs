//! 재시작을 권할 것인가 (설계-00 §6 · 설계-03 §8).
//!
//! # 왜 판정과 출력을 나누는가
//!
//! 이 판정은 **사람에게 하는 말**이고, 그 말이 틀리면 사용자는 부팅되지 않는
//! 컴퓨터를 받는다. 악성코드가 `SafeBoot` 키를 지우는 것은 오래된 수법이며,
//! 그것을 모른 채 *"안전 모드로 재시작하세요"* 라고 하는 것이 이 결함의 본체다.
//!
//! 그만큼 중요한 판정이 `println!` 안에 섞여 있으면 **시험할 수 없다.** P9 이
//! 이 경로를 실증하지 못한 이유가 그것이었다 — 함수는 있는데 도달하는 조건을
//! 만들 수 없었고, 만들었어도 출력을 잡아야 확인이 됐다.
//!
//! 그래서 판정은 여기 순수 함수로 두고, 렌더링만 CLI 에 남긴다.
//!
//! # 손상을 발견해도 고치지 않는다
//!
//! `SafeBoot` 하위에는 수백 개 항목이 있어 카탈로그 복원이 현실적이지 않고,
//! 어설픈 복원은 더 나쁜 상태를 만든다. 복원은 OS 복구 도구의 영역이다 —
//! 우리는 **알리는 것**까지 한다.

use remedy_platform::read::BootHealth;

/// **CLI 가 상태를 보고 말을 고른다.** 문자열 id 를 넘기면 그 문자열이 사실상
/// API 가 되고, 새 상태가 늘 때 렌더링이 조용히 옛 갈래로 떨어진다
/// (`remedy-cli` 는 `remedy-platform` 을 직접 의존하지 않는다 — 설계-04 §1).
pub use remedy_platform::read::SafeBoot;

/// 이 실행이 끝난 뒤 사람에게 할 말.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartAdvice {
    /// 할 말이 없다. 재시작이 도움이 되지 않는다.
    Nothing,

    /// 부팅 건전성을 읽지 못했다. **권하지 않는다** — "모른다" 를 "괜찮다" 로
    /// 접으면 그 접는 자리가 곧 사고다.
    CannotTell,

    /// 재시작해도 된다.
    Safe {
        /// 예약된 삭제가 남아 있는가. **예약은 파괴가 아니다** — 그 파일은 아직
        /// 그 자리에 있고 사라지는 것은 다음 부팅이다.
        pending_deletes: bool,
        /// 실패한 항목이 있는가. 안전 모드로 재시작해 **새로 검사**할 수 있다 —
        /// 같은 계획은 다시 적용하지 않는다(끝난 회차는 거부한다).
        failed: usize,
    },

    /// **재시작을 권할 수 없다.** 안전 모드가 온전하지 않거나, 온전한지를
    /// 확인하지 못했다.
    ///
    /// 그 둘을 여기서 접지 않는다 — `safeboot.observed_damage()` 가
    /// *"손상을 봤다"* 와 *"보지 못했다"* 를 가르고, 사람에게 할 말이 다르다
    /// (설계-00 §5-1 — 접근 거부의 원인을 구분해 보고한다).
    Unsafe {
        safeboot: SafeBoot,
        pending_deletes: bool,
    },
}

impl RestartAdvice {
    /// 사람에게 말할 것이 있는가.
    pub fn speaks(&self) -> bool {
        !matches!(self, RestartAdvice::Nothing)
    }

    /// 이것이 경고인가. 경고는 stderr 로 나간다.
    pub fn is_warning(&self) -> bool {
        matches!(
            self,
            RestartAdvice::CannotTell | RestartAdvice::Unsafe { .. }
        )
    }
}

/// 무엇을 말할지 정한다.
///
/// `health` 가 `None` 인 것은 **읽지 못했다**는 뜻이다. 이 플랫폼에 그 개념이
/// 없거나 레지스트리를 읽을 수 없었다 — 어느 쪽이든 권하지 않는다.
pub fn advise(reboot_required: bool, failed: usize, health: Option<&BootHealth>) -> RestartAdvice {
    // 재시작이 도움이 되는 경우에만 입을 연다. 아무 일도 없었는데 재부팅을
    // 권하면 그 권고는 다음번에 무시된다.
    if !reboot_required && failed == 0 {
        return RestartAdvice::Nothing;
    }
    let Some(h) = health else {
        return RestartAdvice::CannotTell;
    };
    if h.may_suggest_restart() {
        RestartAdvice::Safe {
            pending_deletes: reboot_required,
            failed,
        }
    } else {
        RestartAdvice::Unsafe {
            safeboot: h.safeboot,
            pending_deletes: reboot_required,
        }
    }
}

// ───────────────────────────────────── 재부팅 후 검증 예약 (설계-03 §8)

/// 예약이 앉는 자리와 그것을 지우는 주체. CLI 가 `remedy-platform` 을 직접
/// 의존하지 않으므로(설계-04 §1) 여기서 내보낸다 — `SafeBoot` 와 같은 길.
///
/// **거는 것은 실행기다** (`remedy_apply::Executor::with_verify_after_reboot`).
/// `End` 앞에서 걸어야 감사 로그에 남는다 — 한동안 이 모듈이 CLI 대신 걸었고,
/// 그 결과는 화면에만 있었다 (P12). 걸린 자리는 실행기의 보고가 싣는다.
pub use remedy_platform::write::{RemovedBy, VerifySite};

/// **이 기계에서** 재부팅 뒤 검증을 예약할 수 있는가. 아니면 사람이 읽을 이유.
///
/// 승인 **전에** 묻는다 (P12 D4) — 계획 화면이 약속할지 사실을 말할지를 이것이
/// 정한다. 부수 효과가 없다 — 트레이트가 그것을 약속한다.
pub fn verify_after_reboot_support() -> Result<(), String> {
    use remedy_platform::write::PlatformWrite;
    let Some(p) = remedy_platform::live() else {
        return Err(remedy_sdk::i18n::t(
            "이 플랫폼에는 쓰기 백엔드가 없습니다",
            "this platform has no write backend",
        )
        .to_string());
    };
    p.verify_after_reboot_support().map_err(|e| match e {
        // 화면이 이미 *"걸 수 없습니다"* 라고 말한다 — 변이의 머리
        // (*"이 플랫폼에서는 지원되지 않습니다"*)를 한 번 더 붙이지 않는다.
        remedy_platform::PlatformError::Unsupported(why) => why.to_string(),
        other => other.to_string(),
    })
}

/// 예약될 명령줄. **CLI 가 그것을 그대로 실행해 볼 수 있게** 여기로 낸다.
///
/// `remedy-cli` 는 `remedy-platform` 을 직접 의존하지 않는다(설계-04 §1) —
/// 조립은 core 가 맡는다. 그 규칙 때문에 `scheduled_verify.rs` 시험이 이 문을
/// 지난다.
pub fn scheduled_verify_command(
    exe: &std::path::Path,
    run_id: &str,
    plugin: &std::path::Path,
    state_dir: Option<&std::path::Path>,
    lang: remedy_sdk::i18n::Lang,
) -> String {
    remedy_platform::write::scheduled_verify_command(exe, run_id, plugin, state_dir, lang)
}

/// 남아 있는 예약을 지운다 (자기 흔적 규칙 2).
///
/// **없으면 성공이다.** Windows 는 RunOnce 항목을 실행 직전에 지우므로 정상
/// 경로에서는 지울 것이 없다.
pub fn clear_scheduled_verify() -> Result<(), String> {
    use remedy_platform::write::PlatformWrite;
    let Some(p) = remedy_platform::live() else {
        // 쓰기 백엔드가 없는 곳에는 예약도 없다.
        return Ok(());
    };
    p.cancel_scheduled_verify().map_err(|e| e.to_string())
}

/// 지금 예약이 걸려 있는가. 진단과 시험이 쓴다.
pub fn scheduled_verify() -> Option<String> {
    use remedy_platform::write::PlatformWrite;
    remedy_platform::live()?.scheduled_verify().ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_platform::read::SafeBoot;

    fn healthy() -> BootHealth {
        BootHealth {
            safeboot: SafeBoot::Available,
            recovery_enabled: None,
        }
    }

    fn damaged() -> BootHealth {
        BootHealth {
            safeboot: SafeBoot::Missing,
            recovery_enabled: None,
        }
    }

    #[test]
    fn 할_일이_없으면_입을_열지_않는다() {
        // 아무 일도 없었는데 재부팅을 권하면 그 권고는 다음번에 무시된다.
        assert_eq!(advise(false, 0, Some(&healthy())), RestartAdvice::Nothing);
        assert!(!advise(false, 0, None).speaks());
    }

    #[test]
    fn 예약된_삭제가_있으면_말한다() {
        // **예약은 파괴가 아니다.** 그 파일은 아직 그 자리에 있다.
        let a = advise(true, 0, Some(&healthy()));
        assert_eq!(
            a,
            RestartAdvice::Safe {
                pending_deletes: true,
                failed: 0
            }
        );
        assert!(a.speaks());
        assert!(!a.is_warning());
    }

    #[test]
    fn 실패가_있으면_안전_모드를_제안한다() {
        let a = advise(false, 2, Some(&healthy()));
        assert_eq!(
            a,
            RestartAdvice::Safe {
                pending_deletes: false,
                failed: 2
            }
        );
    }

    #[test]
    fn 안전_모드가_손상되면_권하지_않는다() {
        // **이것이 이 판정의 존재 이유다.** 악성코드가 SafeBoot 키를 지우는
        // 것은 오래된 수법이고, 그것을 모른 채 "안전 모드로 재시작하세요" 라고
        // 하면 사용자는 부팅되지 않는 컴퓨터를 받는다.
        let a = advise(false, 1, Some(&damaged()));
        assert!(matches!(a, RestartAdvice::Unsafe { .. }), "{a:?}");
        assert!(a.is_warning());
    }

    #[test]
    fn 잠긴_것과_지워진_것을_같은_말로_보고하지_않는다() {
        // 둘 다 재시작을 막는다. 그러나 **손상을 봤다고 주장할 수 있는 것은
        // 하나뿐이다** — 정책이 잠근 기업 기계에 "악성코드가 손댔을 수 있다"
        // 고 말하면 그것이 오탐이다 (설계-00 §5-1).
        let locked = BootHealth {
            safeboot: SafeBoot::Unreadable,
            recovery_enabled: None,
        };
        let a = advise(false, 1, Some(&locked));
        assert!(matches!(a, RestartAdvice::Unsafe { .. }), "{a:?}");
        assert!(a.is_warning());
        let RestartAdvice::Unsafe { safeboot, .. } = a else {
            unreachable!()
        };
        assert!(!safeboot.observed_damage(), "보지 못한 것을 손상이라 했다");

        let RestartAdvice::Unsafe { safeboot, .. } = advise(false, 1, Some(&damaged())) else {
            unreachable!()
        };
        assert!(safeboot.observed_damage(), "본 것을 봤다고 말하지 않는다");
    }

    #[test]
    fn 읽지_못한_것을_괜찮다로_접지_않는다() {
        let a = advise(true, 0, None);
        assert_eq!(a, RestartAdvice::CannotTell);
        assert!(a.is_warning());
    }

    #[test]
    fn 복구_환경이_꺼져_있으면_권하지_않는다() {
        // `may_suggest_restart` 가 그것을 본다. 여기서는 그 판정이 실제로
        // 전달되는지만 확인한다 — 두 층이 갈라지면 한쪽이 조용히 관대해진다.
        let h = BootHealth {
            safeboot: SafeBoot::Available,
            recovery_enabled: Some(false),
        };
        assert!(matches!(
            advise(true, 0, Some(&h)),
            RestartAdvice::Unsafe { .. }
        ));
    }
}
