//! 여유 공간 — **부족하면 파괴를 시작하지 않는다** (설계-00 §5-2).
//!
//! 격리 백업은 원본만큼의 공간을 먹는다. 백업 도중 디스크가 차면 그때는 이미
//! 일부가 파괴됐을 수 있고, 백업이 없는 파괴는 되돌릴 수 없다. 그래서 **쓰기
//! 전에** 묻는다.
//!
//! # 모른다는 것을 모른다고 말한다
//!
//! 질의가 실패할 수 있다 — 네트워크 드라이브, 권한, 지원하지 않는 파일 시스템.
//! 그때 0 이나 넉넉한 값으로 뭉개면 "확인했다" 와 "확인하지 못했다" 가 같아진다.
//! 이 프로젝트가 종료 코드 6 을 따로 둔 것과 같은 이유로, 여기서도 셋을 나눈다 —
//! 충분하다 · 부족하다 · **모른다**.

use crate::PlatformError;

/// 어느 볼륨의 여유 공간.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Space {
    /// 실제로 물어서 얻은 값.
    Known(u64),
    /// 묻지 못했다. 이유를 함께 든다 — 조용히 통과시키지 않기 위해서다.
    Unknown(String),
}

impl Space {
    /// 이만큼 쓸 수 있는가. **모르면 `None`** — 참도 거짓도 아니다.
    pub fn fits(&self, need: u64) -> Option<bool> {
        match self {
            Space::Known(a) => Some(*a >= need),
            Space::Unknown(_) => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Space::Known(a) => format!("{} {}", a, remedy_sdk::i18n::t("바이트", "bytes")),
            Space::Unknown(why) => {
                format!("{} ({why})", remedy_sdk::i18n::t("알 수 없음", "unknown"))
            }
        }
    }
}

/// 이 경로가 놓일 볼륨의 여유 공간.
///
/// 아직 없는 경로도 물을 수 있어야 한다 — 복원 대상은 지워진 자리다. 그래서
/// **존재하는 가장 가까운 상위 디렉터리**에 대고 묻는다.
pub fn available(path: &str) -> Space {
    let mut p = std::path::Path::new(path);
    loop {
        if p.exists() {
            return match fs4::available_space(p) {
                Ok(n) => Space::Known(n),
                Err(e) => Space::Unknown(e.to_string()),
            };
        }
        match p.parent() {
            Some(parent) if parent != p => p = parent,
            _ => {
                return Space::Unknown(remedy_sdk::i18n::current().pick(
                    format!("'{path}' 의 상위 중 존재하는 것이 없습니다"),
                    format!("none of '{path}' parents exist"),
                ));
            }
        }
    }
}

/// 이 경로가 속한 볼륨을 가리키는 열쇠.
///
/// 서로 다른 디렉터리라도 같은 볼륨이면 여유 공간을 **나눠 쓴다.** 각각 따로
/// 재면 둘 다 통과하고 합쳐서는 안 들어가는 상황을 놓친다.
///
/// Windows 는 드라이브 문자로 정확히 가른다. Unix 는 마운트 지점을 알아내려면
/// 별도 질의가 필요하므로 전부 한 덩어리로 본다 — **보수적인 쪽으로 틀린다**
/// (실제로는 들어가는데 거절할 수 있고, 그 반대는 없다).
/// 이 경로가 사는 볼륨. **파일 경로가 아니면 `None` 이다.**
///
/// 복원 항목의 `dest` 는 파일 경로만이 아니다 — 레지스트리 값, 예약 작업, 보안
/// 제품 예외 목록(`av_exclusions`)이 그대로 온다. **그것들은 볼륨에 살지 않으므로
/// 여유 공간을 잴 대상이 아니다.**
///
/// 앞서는 알아보지 못한 것을 전부 `/` 로 접었고, 그래서 Windows 복원 계획에
/// **있지도 않은 `볼륨 /`** 이 나왔다 (실측 2026-09-07):
///
/// ```text
///   볼륨 /  필요 6935 · 여유 21220614144 바이트
///   볼륨 C:  필요 508 · 여유 21220614144 바이트
/// ```
///
/// 종류 14가지를 손으로 가르는 대신 **플랫폼의 사실**로 가른다 — Windows 에서
/// 드라이브 문자도 UNC 도 아니면 파일 자리가 아니고, 유닉스에서 절대 경로가
/// 아니면 파일 자리가 아니다.
pub fn volume_of(path: &str) -> Option<String> {
    if cfg!(windows) {
        let b = path.as_bytes();
        if b.len() >= 2 && b[1] == b':' {
            return Some(path[..2].to_ascii_uppercase());
        }
        // UNC 는 공유 단위로 본다.
        let rest = path.strip_prefix("\\\\")?;
        let mut it = rest.splitn(3, '\\');
        let server = it.next().unwrap_or("");
        let share = it.next().unwrap_or("");
        if server.is_empty() || share.is_empty() {
            return None;
        }
        return Some(format!("\\\\{server}\\{share}").to_ascii_uppercase());
    }
    path.starts_with('/').then(|| "/".to_string())
}

/// 볼륨별 필요 용량을 확인한다.
///
/// `needs` 는 (대상 경로, 필요 바이트) 목록이다. 같은 볼륨의 것은 **합쳐서** 잰다.
#[derive(Debug, Clone)]
pub struct SpaceCheck {
    pub volume: String,
    /// 그 볼륨에서 물어본 경로 하나. 사람이 어디를 말하는지 알아야 한다.
    pub probe: String,
    pub need: u64,
    pub space: Space,
}

impl SpaceCheck {
    pub fn insufficient(&self) -> bool {
        self.space.fits(self.need) == Some(false)
    }
    pub fn unknown(&self) -> bool {
        matches!(self.space, Space::Unknown(_))
    }
}

pub fn check(needs: &[(String, u64)]) -> Vec<SpaceCheck> {
    let mut by_volume: std::collections::BTreeMap<String, (String, u64)> =
        std::collections::BTreeMap::new();
    for (path, n) in needs {
        // 볼륨이 없는 자리(레지스트리·예약 작업·예외 목록)는 건너뛴다.
        let Some(k) = volume_of(path) else { continue };
        let e = by_volume.entry(k).or_insert_with(|| (path.clone(), 0));
        e.1 += n;
    }
    by_volume
        .into_iter()
        .map(|(volume, (probe, need))| SpaceCheck {
            volume,
            space: available(&probe),
            probe,
            need,
        })
        .collect()
}

/// 쓰기 전에 확인하고, **부족하면 시작하지 않는다.**
pub fn require(needs: &[(String, u64)]) -> Result<Vec<SpaceCheck>, PlatformError> {
    let checks = check(needs);
    if checks.iter().any(|c| c.insufficient()) {
        let detail: Vec<String> = checks
            .iter()
            .filter(|c| c.insufficient())
            .map(|c| {
                let (v, need, free) = (&c.volume, c.need, c.space.describe());
                remedy_sdk::i18n::current().pick(
                    format!("{v}: 필요 {need} · 여유 {free}"),
                    format!("{v}: needs {need} · free {free}"),
                )
            })
            .collect();
        return Err(PlatformError::NoSpace(detail.join(" · ")));
    }
    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **데이터는 빼고 우리 문구만 본다.** `'…'` 안은 부르는 쪽이 준 경로이고,
    /// 그것이 한국어인 것은 우리가 고칠 수 있는 일이 아니다 — §3 이 캡처에서
    /// "입력 에코는 우리 문구가 아니다" 로 가른 것과 같다.
    fn has_hangul(s: &str) -> bool {
        let mut out = String::new();
        let mut inside = false;
        for c in s.chars() {
            match c {
                '\'' => inside = !inside,
                _ if !inside => out.push(c),
                _ => {}
            }
        }
        out.chars().any(|c| ('가'..='힣').contains(&c))
    }

    /// **여유 공간 부족은 종료 코드 5 다** — `ApplyError`·`RestoreError` 가
    /// `NoSpace` 만 따로 보아 가드 중단으로 낸다. 그 사유가 영어 화면에서
    /// 한글이면 5 를 받은 쪽이 왜 막혔는지 읽지 못한다.
    ///
    /// **이름을 그대로 둔 것**은 아래 시험들을 고치지 않기 위해서다.
    fn require(needs: &[(String, u64)]) -> Result<Vec<SpaceCheck>, PlatformError> {
        let r = super::require(needs);
        if let Err(e) = &r {
            assert!(!has_hangul(&e.to_string()), "{e}");
        }
        r
    }

    fn available(path: &str) -> Space {
        let s = super::available(path);
        assert!(!has_hangul(&s.describe()), "{}", s.describe());
        s
    }

    #[test]
    fn an_existing_path_reports_a_number() {
        let here = std::env::temp_dir();
        match available(here.to_str().unwrap()) {
            Space::Known(n) => assert!(n > 0, "임시 디렉터리에 여유가 0 이다"),
            Space::Unknown(why) => panic!("임시 디렉터리를 묻지 못했다: {why}"),
        }
    }

    #[test]
    fn a_missing_path_falls_back_to_its_nearest_existing_parent() {
        // 복원 대상은 **지워진 자리**다. 없는 경로를 물을 수 없으면 쓸모가 없다.
        let deep = std::env::temp_dir().join("없는곳/더없는곳/파일.bin");
        assert!(
            matches!(available(deep.to_str().unwrap()), Space::Known(_)),
            "상위로 올라가 묻지 못했다"
        );
    }

    #[test]
    fn an_unreachable_path_says_it_does_not_know() {
        // 0 으로 뭉개면 "확인했다" 와 "확인하지 못했다" 가 같아진다.
        let s = available("\\\\없는서버\\없는공유\\x");
        assert!(matches!(s, Space::Unknown(_)), "{s:?}");
        assert_eq!(s.fits(1), None, "모르는데 판단을 내놨다");
    }

    /// 합치는 규칙은 플랫폼과 무관하지만 **볼륨을 무엇으로 보는가는 다르다** —
    /// Windows 는 드라이브 문자와 UNC 공유, 유닉스는 `/` 하나다. 입력을 가르지
    /// 않으면 리눅스에서 `volume_of("C:\a\x")` 가 `None` 이 되어 이 시험이
    /// 조용히 아무것도 재지 못한다(실제로 P5 이래 그랬다).
    #[test]
    fn same_volume_needs_are_summed() {
        // 각각 따로 재면 둘 다 통과하고 합쳐서는 안 들어가는 상황을 놓친다.
        #[cfg(windows)]
        let (needs, want_volumes, want_key) = (
            vec![
                ("C:\\a\\x".to_string(), 100),
                ("C:\\b\\y".to_string(), 200),
                ("D:\\z".to_string(), 50),
            ],
            2,
            "C:",
        );
        #[cfg(not(windows))]
        let (needs, want_volumes, want_key) = (
            vec![("/a/x".to_string(), 100), ("/b/y".to_string(), 200)],
            1,
            "/",
        );

        let checks = check(&needs);
        assert_eq!(
            checks.len(),
            want_volumes,
            "볼륨이 {want_volumes}개여야 한다: {checks:?}"
        );
        let c = checks.iter().find(|c| c.volume == want_key).unwrap();
        assert_eq!(c.need, 300, "같은 볼륨은 합쳐야 한다");
    }

    #[test]
    fn volume_keys_split_the_way_the_filesystem_does() {
        #[cfg(windows)]
        {
            assert_eq!(volume_of("C:\\Windows\\x").as_deref(), Some("C:"));
            assert_eq!(volume_of("c:/users/a").as_deref(), Some("C:"));
            assert_eq!(
                volume_of("\\\\srv\\share\\dir\\f").as_deref(),
                Some("\\\\SRV\\SHARE")
            );
            // 볼륨에 살지 않는 것들 — 복원 항목의 dest 로 실제로 오는 모양이다.
            assert_eq!(volume_of("HKCU\\SOFTWARE\\x"), None);
            assert_eq!(volume_of("\\Microsoft\\Windows\\Locust"), None);
        }
        #[cfg(not(windows))]
        {
            assert_eq!(volume_of("/var/lib/x").as_deref(), Some("/"));
            assert_eq!(volume_of("C:\\Windows\\x"), None);
        }
        // 어느 플랫폼에서도 이름 하나는 볼륨이 아니다.
        assert_eq!(volume_of("av_exclusions"), None);
    }

    #[test]
    fn 볼륨이_없는_자리는_공간_계산에_들지_않는다() {
        // 앞서는 `볼륨 /` 이라는 없는 볼륨이 화면에 섰다 (2026-09-07).
        assert!(check(&[("av_exclusions".to_string(), 500)]).is_empty());
    }

    #[test]
    fn an_impossible_need_is_refused() {
        let needs = vec![(
            std::env::temp_dir().to_string_lossy().to_string(),
            u64::MAX / 2,
        )];
        assert!(require(&needs).is_err(), "들어갈 리 없는 요구가 통과했다");
    }

    /// **Windows 전용이다.** 유닉스에는 "볼륨을 모른다" 가 없다 — `volume_of` 가
    /// 절대 경로면 `/` 를, 아니면 `None` 을 주고 `None` 은 `check` 가 아예
    /// 거른다. 리눅스에서 이 시험을 돌리면 `checks` 가 비어 첨자에서 터진다.
    #[cfg(windows)]
    #[test]
    fn an_unknown_volume_does_not_block_but_is_reported() {
        // 모른다는 이유로 막으면 지원하지 않는 파일 시스템에서 아무것도 못 한다.
        // 대신 **모른다는 사실이 호출자에게 전달**되어야 한다.
        let needs = vec![("\\\\없는서버\\없는공유\\x".to_string(), 1)];
        let checks = require(&needs).expect("모르는 것은 막지 않는다");
        assert!(checks[0].unknown());
    }
}
