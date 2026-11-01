//! OS 원시 연산. **read 와 write 를 분리한다** (설계-04 §1, 설계-09 P2).
//!
//! 분리가 모듈성 때문이 아니다. `remedy-apply` 는 술어 해소에 필요한 최소 읽기를
//! 해야 하지만 탐색은 할 수 없어야 하고, `remedy-collect` 는 읽기만 해야 한다.
//! 두 능력이 한 trait 에 있으면 그 구분이 주석으로만 남는다.
//!
//! trait 이 OS 중립인 것은 P12(Linux)의 전제다. 여기 Windows 전용 개념이 새어
//! 나가면 Linux 백엔드를 끼울 자리가 없어진다.
#![forbid(unsafe_code)]

pub mod disk;
mod local;
pub mod meta;
/// 걷기의 진행 계수기 — 검사가 어디까지 왔는가.
pub mod progress;
pub mod read;
/// 복원 정보 폴더 잠금 — **정책은 하나, 호출은 플랫폼마다 다르다.**
pub mod statedir;
/// 외부 도구를 상한 안에서 부르고 stderr 를 보존한다.
pub mod tool;
pub mod write;

#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

pub const CRATE_NAME: &str = "remedy-platform";

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("이 플랫폼에서는 지원되지 않습니다", "not supported on this platform"))]
    Unsupported(&'static str),
    /// 쓰기 경계가 **할 수 있지만 하지 않기로** 한 경우.
    ///
    /// `Unsupported` 와 다르다 — 그쪽은 "이 백엔드에 그 문이 없다" 이고, 이쪽은
    /// "문은 있는데 지금 열면 안 된다" 다. 감사 로그에서 둘이 섞이면 "구현이
    /// 없어서 못 했다" 와 "가드가 막았다" 를 구분할 수 없다.
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("거부됐습니다", "refused"))]
    Refused(String),
    /// **아무도 거부하지 않았다 — 기다리던 쪽이 먼저 손을 뗐다.**
    ///
    /// [`Refused`](Self::Refused) 와 짝이면서 반대다. 그쪽은 *누군가 안 된다고
    /// 했다* 이고 이쪽은 *아무도 답을 주지 않은 채 시간이 끝났다* 이다. 지금
    /// 일어난 일이 무엇인지도 다르지만, **그 다음에 무엇을 해야 하는지가**
    /// 결정적으로 다르다.
    ///
    /// | | 무슨 일인가 | 다음에 할 일 |
    /// |---|---|---|
    /// | `Refused` | 경계가 막았다. 그 뒤로 아무 일도 없다 | 사유를 없애야 한다 |
    /// | `TimedOut` | 요청은 갔고 아직 진행 중일 수 있다 | **다시 봐야 안다** |
    ///
    /// 처음 이 변이를 낸 자리는 `sc.exe stop` 의 1053 하나다
    /// (`windows::stop_reason`): SCM 이 서비스의 제어
    /// 핸들러를 60초까지만 기다리고 포기하는데, 그때 서비스는 **아직 멈추는
    /// 중**이고 실측에서 실제로 그 뒤 멈췄다. 그것을 `거부됐다:` 로 적으면
    /// 화면이 *"뭔가가 막았다"* 고 말하지만 막은 것은 아무것도 없다.
    ///
    /// # 우리가 끊은 것이 아니다
    ///
    /// [`crate::tool`] 은 **어떤 상한에서도 자식을 죽이지 않는다**(결정
    /// 2026-09-07). 그러니 이 변이는 "remedy 가 기다리다 지쳤다" 가 아니라
    /// 언제나 **OS 쪽 상한**이다. 그 구분이 흐려지면 "1분만 더 돌면 끝날 일을
    /// 끊지 않는다" 는 결정 자체가 화면에서 거짓말이 된다.
    ///
    /// **판정은 [`Refused`](Self::Refused) 와 같다** — 부르는 쪽에서는 둘 다
    /// 실패다. 정말로 멈추지 않는 서비스를 '치료 완료' 로 보고하는 것이 방어
    /// 도구가 낼 수 있는 가장 나쁜 거짓말이므로, 안전한 쪽으로 틀린다. 달라진
    /// 것은 **사람이 읽는 한 줄**뿐이다 (결정 2026-09-13).
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("기다리다 끝났습니다", "waited and gave up"))]
    TimedOut(String),
    /// 백업 전에 확인해 막은 경우. **파괴는 시작되지 않았다** (설계-00 §5-2).
    #[error("{msg}: {0}", msg = remedy_sdk::i18n::t("여유 공간이 부족합니다", "not enough free space"))]
    NoSpace(String),
}

impl PlatformError {
    pub fn io(path: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// 거부 사유를 **두 언어로만** 만들 수 있게 한다 (2026-09-16).
    ///
    /// # 왜 생성자인가
    ///
    /// `Refused` 는 *"할 수 있지만 하지 않기로 했다"* 이므로 **가드가 막은
    /// 것**이고, 종료 코드 5 로 고객 화면에 나간다. 그런데 이 사유들은
    /// 콘솔 캡처가 밟지 않는다 — 잠긴 서비스, 없는 cmdlet, 재귀 삭제 상한
    /// 같은 상황을 캡처가 만들지 않기 때문이다.
    ///
    /// 시험으로 재려 해도 이 크레이트는 통합 시험이 둘뿐이고 플랫폼에 묶여
    /// 있다. 그래서 `remedy-apply` 와 같은 수를 쓴다 — **만드는 자리를 좁혀**
    /// 한 언어로는 만들 수 없게 한다.
    ///
    /// `Display` 의 앞머리(`거부됐다:` / `refused:`)는 이미 두 언어다. 여기서
    /// 채우는 것은 그 뒤에 붙는 **사유**다.
    pub fn refused(ko: String, en: String) -> Self {
        Self::Refused(remedy_sdk::i18n::current().pick(ko, en))
    }
}

/// 이 기계의 이름.
///
/// # 왜 여기 있는가
///
/// `remedy-core` 가 `COMPUTERNAME` 과 `HOSTNAME` 을 차례로 보고 있었는데,
/// **Linux 의 `HOSTNAME` 은 export 되지 않는 셸 변수다.** 그래서 실기기에서 뜬
/// 스냅샷이 전부 `unknown` 이었다 — 고객 PC 에서 `collect` 만 하고 분석은 사내
/// 에서 한다는 설계-03 §1 (4) 에서, 어느 기계 것인지 말하지 못하는 스냅샷이다.
///
/// OS 마다 답이 다른 물음이므로 이 크레이트의 것이다.
pub fn hostname() -> String {
    #[cfg(windows)]
    {
        if let Ok(v) = std::env::var("COMPUTERNAME") {
            if !v.is_empty() {
                return v;
            }
        }
    }
    #[cfg(unix)]
    {
        // `gethostname(2)` 는 unsafe 가 필요하다. 커널이 같은 값을 파일로 낸다.
        for p in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
            if let Ok(v) = std::fs::read_to_string(p) {
                let v = v.trim();
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
    }
    // 환경 변수는 **마지막**이다. 사람이 덮어쓸 수 있는 값이라 기계의 이름을
    // 묻는 물음의 답으로는 약하다.
    for k in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    // **비워 두지 않는다.** 빈 문자열은 "이름이 없다" 로 읽히지만 실제로는
    // "알아내지 못했다" 다.
    "unknown".to_string()
}

/// 현재 실행 중인 백엔드를 만든다.
///
/// **빈 구현을 돌려주지 않는다.** "수집하지 못했다" 와 "없다" 가 구분되어야
/// 하기 때문이다 — 아무것도 못 보는 백엔드가 조용히 성공하면 그 실행은
/// "위협 없음" 으로 끝나고, 아무도 그것이 관측이 아니었다는 것을 모른다.
///
/// Linux 백엔드는 **읽기만 한다** (설계-09 P12). 파괴 요구는 계획 단계에서
/// `deferred` 로 나간다.
/// 사용자 로케일 이름. Windows 는 `HKCU\Control Panel\International\LocaleName`
/// (예: `ko-KR`), 그 밖의 OS 는 `None` — 거기서는 `LANG` 이 같은 말을 한다.
///
/// OS 마다 답이 다른 물음이므로 이 크레이트의 것이다 (`hostname` 과 같다).
pub fn user_locale() -> Option<String> {
    #[cfg(windows)]
    {
        windows::user_locale()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(windows)]
pub fn live() -> Option<windows::Live> {
    Some(windows::Live::new())
}

#[cfg(target_os = "linux")]
pub fn live() -> Option<linux::Live> {
    Some(linux::Live::new())
}

/// 그 밖의 플랫폼에는 백엔드가 없다. macOS 가 여기다.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn live() -> Option<std::convert::Infallible> {
    None
}

#[cfg(test)]
mod tests {
    /// 이 기계의 이름을 실제로 알아내는가.
    ///
    /// **Linux 에서 `unknown` 이 나오던 것이 이 시험의 이유다.** 값이 무엇인지는
    /// 기계마다 다르므로 고정할 수 없지만, *알아내지 못했다*는 답은 실패다 —
    /// 그러면 스냅샷이 어느 기계 것인지 말하지 못한다.
    #[test]
    fn this_machine_has_a_name() {
        let n = super::hostname();
        assert!(!n.is_empty());
        assert_ne!(n, "unknown", "기계 이름을 알아내지 못했다");
    }
}
