//! 1층 — 코어 내장 불변 보호 목록 (설계-03 §3).
//!
//! **플러그인도 사용자도 뒤집을 수 없다.** 화이트리스트 다섯 층 중 유일하게
//! 선언으로 우회할 수 없는 층이고, 그것이 이 층의 존재 이유다.
//!
//! # 규칙은 두 겹이다
//!
//! 디렉터리 단위 금지 + 개별 파일 조건부 허용. 악성코드는 실제로 `System32` 에
//! 드롭되므로(첫 플러그인 대상 EvilAI 의 탐지 조건에도 `\System32\` 가 들어간다)
//! **디렉터리를 통째로 막으면 첫 플러그인부터 동작하지 않고, 통째로 열면 OS
//! 파괴 경로가 열린다.**
//!
//! # 경로만으로는 부족하다
//!
//! 경로 보호 목록은 **종료를 막지 못한다** — 종료는 파일을 건드리는 동작이
//! 아니기 때문이다. 악성코드가 정상 프로세스명으로 위장하거나 인젝션한 경우
//! `image_path` 로 매칭하는 룰이 임계 시스템 프로세스를 지목할 수 있고,
//! `csrss.exe` · `winlogon.exe` 를 종료하면 **즉시 블루스크린**이다.

use remedy_sdk::catalog::Platform;
use remedy_sdk::normalize;

/// Windows 보호 경로 (설계-03 §3 의 목록 그대로). 환경변수는 호출자가 전개해 넘긴다.
///
/// `%SystemRoot%` 자체는 여기 없다. 목록에 없는 것을 보태면 그 하위가 통째로 잠겨
/// 첫 플러그인부터 동작하지 않는다. 그것을 통째로 지우는 시도는 다른 방식으로
/// 막힌다 — **대상이 보호 디렉터리를 품고 있으면 거부**한다.
const WINDOWS_DIRS: [&str; 7] = [
    r"%SystemRoot%\System32",
    r"%SystemRoot%\SysWOW64",
    r"%SystemRoot%\WinSxS",
    r"%SystemRoot%\Boot",
    r"%ProgramFiles%\Windows Defender",
    r"%ProgramFiles(x86)%\Windows Defender",
    // **코어의 작업 디렉터리** (설계-01 D7). 격리 컨테이너와 저널이 여기 있다.
    r"%ProgramData%\remedy",
];

/// 코어의 작업 디렉터리를 여기 넣는 이유 (설계-01 D7).
///
/// > 자기 격리소·저널을 자기 삭제 대상으로 삼지 않는다. 코어의 작업 디렉터리는
/// > 1층 보호 목록에 준해 취급한다.
///
/// **격리 컨테이너가 되돌리기의 유일한 수단**이다. 그것을 지우면 복구가 끊기고,
/// 그때는 사고가 사고로 끝나지 않는다. 저널도 같다 — 무엇을 했는지 말할 수 있는
/// 유일한 기록이다.
///
/// `--state-dir` 로 다른 곳을 지정하면 그 경로는 이 목록에 없다. **그것은
/// 사용자가 의식적으로 고른 자리**이고, 기본 위치를 지키는 것이 이 항목의 몫이다.
///
/// Linux 보호 경로.
const LINUX_DIRS: [&str; 11] = [
    "/bin",
    "/sbin",
    "/usr",
    "/lib",
    "/lib64",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/etc",
    // 코어의 작업 디렉터리 (설계-01 D7).
    "/var/lib/remedy",
];

/// 종료하면 즉시 시스템이 멈추는 프로세스.
///
/// **판정 기준은 이름이 아니라 경로다.** 이름만 보면 `C:\Temp\lsass.exe` 같은
/// 위장이 보호를 얻는다 (설계-03 §3).
///
/// 목록 자체는 SDK 가 들고 있다 — 실행기(`remedy-apply`)도 같은 것을 봐야 하고
/// 그쪽은 이 크레이트를 의존하지 않는다. **두 곳에 적으면 갈라진다.**
use remedy_sdk::catalog::WINDOWS_CRITICAL_PROCESSES as WINDOWS_CRITICAL;

pub use remedy_sdk::catalog::PROTECTED_PIDS;

/// 보호 목록. 환경변수가 전개된 상태로 만든다.
#[derive(Debug, Clone)]
pub struct Protected {
    platform: Platform,
    /// 정규화·대소문자 접힘까지 끝난 비교용 경로.
    dirs: Vec<String>,
    /// 시스템 디렉터리 — 임계 프로세스가 여기서 돌아야 진짜다.
    system_dirs: Vec<String>,
}

/// 왜 보호되는가. 감사 로그에 그대로 남는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protection {
    /// 보호 디렉터리 그 자체. 재귀 삭제는 항상 거부된다.
    ProtectedDirectory(String),
    /// 보호 디렉터리 **하위**. 개별 파일은 조건부로 허용된다.
    InsideProtectedDirectory(String),
    /// 드라이브 루트 또는 파일 시스템 루트.
    Root,
    /// 사용자 홈 디렉터리 자체.
    UserHome,
}

impl std::fmt::Display for Protection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // **두 언어로 짓는다.** 이 값은 가드 사유 문장 한가운데로 들어가고,
        // 그 사유는 종료 코드 5 로 고객에게 간다 (2026-09-16).
        let t = |ko: &str, en: &str| -> String {
            match remedy_sdk::i18n::current() {
                remedy_sdk::i18n::Lang::Ko => ko.to_string(),
                remedy_sdk::i18n::Lang::En => en.to_string(),
            }
        };
        let s = match self {
            Protection::ProtectedDirectory(d) => t(
                &format!("보호 디렉터리 '{d}' 자체"),
                &format!("the protected directory '{d}' itself"),
            ),
            Protection::InsideProtectedDirectory(d) => t(
                &format!("보호 디렉터리 '{d}' 하위"),
                &format!("inside the protected directory '{d}'"),
            ),
            Protection::Root => t("드라이브·파일시스템 루트", "a drive or filesystem root"),
            Protection::UserHome => t("사용자 홈 디렉터리 자체", "the user home directory itself"),
        };
        write!(f, "{s}")
    }
}

impl Protected {
    /// `expand` 는 `%NAME%` 를 전개한다. 전개하지 못한 항목은 **버리지 않고 그대로
    /// 둔다** — 조용히 사라지면 그 경로가 보호받지 못한다는 사실이 보이지 않는다.
    pub fn new(platform: Platform, expand: impl Fn(&str) -> String) -> Self {
        let raw: &[&str] = match platform {
            Platform::Windows => &WINDOWS_DIRS,
            _ => &LINUX_DIRS,
        };
        let dirs: Vec<String> = raw
            .iter()
            .map(|d| normalize::for_compare(&expand(d), platform))
            .collect();
        let system_dirs = match platform {
            Platform::Windows => vec![
                normalize::for_compare(&expand("%SystemRoot%\\System32"), platform),
                normalize::for_compare(&expand("%SystemRoot%\\SysWOW64"), platform),
            ],
            _ => vec![
                normalize::for_compare("/usr/lib/systemd", platform),
                normalize::for_compare("/sbin", platform),
                normalize::for_compare("/usr/sbin", platform),
            ],
        };
        Self {
            platform,
            dirs,
            system_dirs,
        }
    }

    /// 이 경로가 보호받는가. 받지 않으면 `None`.
    pub fn check(&self, path: &str) -> Option<Protection> {
        let p = normalize::for_compare(path, self.platform);
        if p.is_empty() {
            return None;
        }
        if is_root(&p, self.platform) {
            return Some(Protection::Root);
        }
        if self.is_user_home(&p) {
            return Some(Protection::UserHome);
        }
        for d in &self.dirs {
            if p == *d {
                return Some(Protection::ProtectedDirectory(d.clone()));
            }
            if normalize::is_within(&p, d, self.platform) {
                return Some(Protection::InsideProtectedDirectory(d.clone()));
            }
        }
        None
    }

    /// 이 경로를 통째로 지우면 보호 디렉터리가 함께 사라지는가.
    ///
    /// 재귀 삭제는 대상 **자체**가 목록에 없어도 그 안의 보호 디렉터리를
    /// 파괴할 수 있다. "안에 있는가" 만 보면 이 방향을 통째로 놓친다.
    pub fn contains_protected(&self, path: &str) -> Option<String> {
        let p = normalize::for_compare(path, self.platform);
        if p.is_empty() {
            return None;
        }
        self.dirs
            .iter()
            .find(|d| *d != &p && normalize::is_within(d, &p, self.platform))
            .cloned()
    }

    /// `C:\Users\<사람>` 또는 `/home/<사람>` **자체**. 그 하위는 보호하지 않는다.
    fn is_user_home(&self, folded: &str) -> bool {
        let (prefix, depth) = match self.platform {
            // `C:\Users\alice` -> ["c:", "users", "alice"]
            Platform::Windows => ("users", 3usize),
            // `/home/alice` -> ["home", "alice"] (2)
            _ => ("home", 2usize),
        };
        let parts: Vec<&str> = folded
            .split(['\\', '/'])
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() != depth {
            return false;
        }
        match self.platform {
            Platform::Windows => parts[1] == prefix,
            _ => parts[0] == prefix,
        }
    }

    /// 이 프로세스를 종료하면 시스템이 즉시 멈추는가.
    ///
    /// **경로로 판정한다.** 이름만 보면 `C:\Temp\lsass.exe` 같은 위장이 보호를
    /// 얻고, 그러면 악성코드가 시스템 프로세스 이름을 쓰는 것만으로 치료를
    /// 회피한다 — 보호 목록이 공격자의 도구가 된다.
    pub fn is_critical_process(&self, image_path: &str, pid: Option<u32>) -> bool {
        if let Some(id) = pid {
            if PROTECTED_PIDS.contains(&id) {
                return true;
            }
        }
        let p = normalize::for_compare(image_path, self.platform);
        let name = p.rsplit(['\\', '/']).next().unwrap_or("");
        let named = match self.platform {
            Platform::Windows => WINDOWS_CRITICAL.contains(&name),
            _ => matches!(name, "init" | "systemd"),
        };
        if !named {
            return false;
        }
        // 이름이 맞아도 시스템 디렉터리에서 돌지 않으면 위장이다 — 보호하지 않는다.
        self.system_dirs
            .iter()
            .any(|d| normalize::is_within(&p, d, self.platform))
    }
}

fn is_root(folded: &str, platform: Platform) -> bool {
    match platform {
        // `c:`, `c:\`
        Platform::Windows => {
            let t = folded.trim_end_matches('\\');
            t.len() == 2 && t.ends_with(':')
        }
        _ => folded == "/",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win() -> Protected {
        Protected::new(Platform::Windows, |s| {
            s.replace("%SystemRoot%", "C:\\Windows")
                .replace("%ProgramFiles(x86)%", "C:\\Program Files (x86)")
                .replace("%ProgramFiles%", "C:\\Program Files")
                .replace("%ProgramData%", "C:\\ProgramData")
        })
    }

    #[test]
    fn 코어의_작업_디렉터리는_자기_삭제_대상이_아니다() {
        // 설계-01 D7. **격리 컨테이너가 되돌리기의 유일한 수단**이고, 그것을
        // 지우면 복구가 끊긴다 — 그때는 사고가 사고로 끝나지 않는다.
        let p = win();
        assert_eq!(
            p.check(r"C:\ProgramData\remedy"),
            Some(Protection::ProtectedDirectory(
                r"c:\programdata\remedy".into()
            )),
            "작업 디렉터리 자체가 보호되지 않는다"
        );
        // 격리 컨테이너와 저널이 그 아래에 있다.
        for inside in [
            r"C:\ProgramData\remedy\quarantine\r1.rq",
            r"C:\ProgramData\remedy\journal\r1.jsonl",
            r"C:\ProgramData\remedy\remedy.lock",
        ] {
            assert!(
                matches!(
                    p.check(inside),
                    Some(Protection::InsideProtectedDirectory(_))
                ),
                "{inside} 이 보호되지 않는다"
            );
        }
        // 옆 이름은 우리 것이 아니다 — 성분 경계로 봐야 한다.
        assert!(p.check(r"C:\ProgramData\remedy-other\x").is_none());
    }

    #[test]
    fn 리눅스에서도_작업_디렉터리를_지킨다() {
        let p = Protected::new(Platform::Linux, |s| s.to_string());
        assert!(p.check("/var/lib/remedy").is_some());
        assert!(p.check("/var/lib/remedy/quarantine/r1.rq").is_some());
    }

    #[test]
    fn protected_directory_itself_is_distinguished_from_its_contents() {
        // 이 구분이 규칙의 전부다. 디렉터리 자체는 재귀 삭제 불가, 하위 개별
        // 파일은 조건부 허용 — 하나로 뭉뚱그리면 첫 플러그인부터 못 쓰거나
        // OS 파괴 경로가 열린다.
        let p = win();
        assert_eq!(
            p.check("C:\\Windows\\System32"),
            Some(Protection::ProtectedDirectory(
                "c:\\windows\\system32".into()
            ))
        );
        assert!(matches!(
            p.check("C:\\Windows\\System32\\evil.dll"),
            Some(Protection::InsideProtectedDirectory(_))
        ));
    }

    #[test]
    fn case_and_separator_do_not_evade_protection() {
        let p = win();
        assert!(p.check("c:/windows/system32/x.dll").is_some());
        assert!(p.check("C:\\WINDOWS\\SYSTEM32").is_some());
    }

    #[test]
    fn sibling_prefix_is_not_protected() {
        // `C:\Windows\System32Extra` 는 System32 가 아니다. 성분 경계로 봐야 한다.
        let p = win();
        assert!(p.check("C:\\Windows\\System32Extra\\x.dll").is_none());
    }

    #[test]
    fn deleting_a_parent_that_holds_a_protected_dir_is_seen() {
        // **이 방향을 놓치면 `dir.delete_recursive C:\Windows` 가 통과한다.**
        // C:\Windows 는 설계-03 §3 의 목록에 없지만 그 안에 System32 가 있다.
        let p = win();
        assert!(
            p.check("C:\\Windows").is_none(),
            "목록에 없으므로 그 자체는 보호 대상이 아니다"
        );
        assert!(
            p.contains_protected("C:\\Windows").is_some(),
            "그러나 보호 디렉터리를 품고 있다"
        );
        assert!(
            p.contains_protected("C:\\").is_some(),
            "드라이브 루트도 마찬가지"
        );
        assert!(p.contains_protected("C:\\remedy-lab").is_none());
        // 자기 자신은 '품고 있다' 가 아니다 — 그것은 check() 가 볼 몫이다.
        assert!(p.contains_protected("C:\\Windows\\System32").is_none());
    }

    #[test]
    fn roots_and_user_home_itself_are_protected() {
        let p = win();
        assert_eq!(p.check("C:\\"), Some(Protection::Root));
        assert_eq!(p.check("D:"), Some(Protection::Root));
        assert_eq!(p.check("C:\\Users\\alice"), Some(Protection::UserHome));
        // 홈 **하위**는 보호하지 않는다. 악성코드가 사는 곳이 대개 여기다.
        assert!(p
            .check("C:\\Users\\alice\\AppData\\Local\\Programs\\x")
            .is_none());
    }

    #[test]
    fn ordinary_paths_are_not_protected() {
        let p = win();
        assert!(p.check("C:\\remedy-lab\\fixtures\\app\\main.js").is_none());
        assert!(p.check("").is_none());
    }

    #[test]
    fn critical_process_is_judged_by_path_not_name() {
        // **이 테스트가 보호 목록이 공격자의 도구가 되는 것을 막는다.**
        // 이름만으로 판정하면 악성코드가 lsass.exe 라는 이름을 쓰는 것만으로
        // 치료를 회피한다.
        let p = win();
        assert!(p.is_critical_process("C:\\Windows\\System32\\lsass.exe", None));
        assert!(!p.is_critical_process("C:\\Temp\\lsass.exe", None));
        assert!(!p.is_critical_process("C:\\Users\\a\\AppData\\lsass.exe", None));
        assert!(!p.is_critical_process("C:\\Windows\\System32\\notepad.exe", None));
    }

    #[test]
    fn fixed_pids_are_protected_regardless_of_path() {
        let p = win();
        assert!(p.is_critical_process("C:\\Temp\\anything.exe", Some(4)));
        assert!(p.is_critical_process("/tmp/whatever", Some(1)));
        assert!(!p.is_critical_process("C:\\Temp\\anything.exe", Some(1234)));
    }

    #[test]
    fn linux_protection() {
        let p = Protected::new(Platform::Linux, |s| s.to_string());
        assert_eq!(p.check("/"), Some(Protection::Root));
        assert!(matches!(
            p.check("/usr"),
            Some(Protection::ProtectedDirectory(_))
        ));
        assert!(matches!(
            p.check("/usr/bin/evil"),
            Some(Protection::InsideProtectedDirectory(_))
        ));
        assert_eq!(p.check("/home/alice"), Some(Protection::UserHome));
        assert!(p.check("/home/alice/.config/evil").is_none());
        assert!(p.check("/opt/app/x").is_none());
    }
}
