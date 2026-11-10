//! 컨테이너 안의 경로 — 엔진 OS 의 규칙으로 가른다. 이 프로그램이 어느 OS 에서 돌든 같다.
//!
//! 스캐너 `paths.go` 를 옮겼다. 리눅스 경로는 깨끗한 절대 경로 하나(`/` 뿐인 것 · 끝의 `/` · `\` · 제어 문자는
//! 받지 않는다)이고, Windows 경로는 드라이브로 시작하는 절대 경로뿐이다 — 장치 이름(`CON` · `COM1` …) · 대체 스트림
//! (`:`) · 와일드카드 · 끝의 점과 공백은 받지 않는다. 디렉터리 하나 · 루트 전체를 묻는 요청은 이 검사에서 걸러진다.

use super::gostr::{cut, fold_eq, lower, upper};
use crate::scan::slashpath;

/// 경로 하나의 상한(바이트).
const MAX_PATH: usize = 4096;
/// `PATH` 에서 꺼내는 디렉터리 수.
const MAX_SEARCH_DIRS: usize = 32;

/// 어느 OS 든 그 OS 의 파일 경로다.
pub(crate) fn valid_file_path(name: &str) -> bool {
    valid_linux_file_path(name) || valid_windows_file_path(name)
}

pub(crate) fn valid_linux_file_path(name: &str) -> bool {
    name.len() <= MAX_PATH
        && name.starts_with('/')
        && name != "/"
        && name == slashpath::clean(name)
        && !name.ends_with('/')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
}

/// `C:\` · `c:/` 처럼 드라이브 문자로 시작한다.
pub(crate) fn windows_drive_path(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

pub(crate) fn valid_windows_file_path(name: &str) -> bool {
    if name.len() > MAX_PATH || !windows_drive_path(name) || name.chars().any(char::is_control) {
        return false;
    }
    let relative = name[3..].replace('\\', "/");
    if relative.is_empty() || relative.contains([':', '<', '>', '"', '|', '?', '*']) {
        return false;
    }
    relative.split('/').all(windows_part)
}

/// 경로의 한 요소 — 비지 않고, `.` · `..` 가 아니고, 점 · 공백으로 끝나지 않고, 장치 이름이 아니다.
fn windows_part(part: &str) -> bool {
    if part.is_empty() || part == "." || part == ".." || part.ends_with('.') || part.ends_with(' ')
    {
        return false;
    }
    let upper = upper(part);
    let stem = cut(&upper, ".").0.trim_end_matches(' ');
    let number = if stem.starts_with("COM") || stem.starts_with("LPT") {
        &stem[3..]
    } else {
        ""
    };
    let device = matches!(stem, "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || (!number.is_empty() && "|1|2|3|4|5|6|7|8|9|¹|²|³|".contains(&format!("|{number}|")));
    !device
}

/// 마지막 요소 — `\` 도 가름표로 본다.
pub(crate) fn base(name: &str) -> String {
    slashpath::base(&name.replace('\\', "/")).to_string()
}

/// 마지막 요소를 뺀 디렉터리. Windows 경로는 `\` 로 돌려준다(`C:\php\php.exe` → `C:\php`, `C:\php.exe` → `C:\`).
pub(crate) fn dir(name: &str) -> String {
    let mut directory = slashpath::dir(&name.replace('\\', "/"));
    if windows_drive_path(name) {
        if directory.len() == 2 {
            directory.push('/');
        }
        return directory.replace('/', "\\");
    }
    directory
}

/// 디렉터리와 이름을 잇는다 — 디렉터리가 Windows 경로면 `\` 로.
pub(crate) fn join(directory: &str, name: &str) -> String {
    if windows_drive_path(directory) {
        return slashpath::join(&[&directory.replace('\\', "/"), name]).replace('/', "\\");
    }
    slashpath::join(&[directory, name])
}

/// 같은 파일인지 견주는 값 — Windows 경로는 대소문자와 가름표를 맞춘다.
pub(crate) fn key(name: &str) -> String {
    if windows_drive_path(name) {
        return lower(&name.replace('\\', "/"));
    }
    name.to_string()
}

/// 아카이브 항목의 이름이 요청한 파일의 마지막 요소와 같다 — Windows 경로면 대소문자를 가리지 않는다.
pub(crate) fn same_file_base(actual: &str, requested: &str) -> bool {
    let wanted = base(requested);
    if windows_drive_path(requested) {
        return fold_eq(actual, &wanted);
    }
    actual == wanted
}

/// 환경 변수의 `PATH`(Windows 엔진은 대소문자를 가리지 않는다)에서 받을 수 있는 디렉터리 — 적힌 차례로 32개까지,
/// 겹친 것은 한 번.
pub(crate) fn search_path(env: &[String], windows: bool) -> Vec<String> {
    for item in env {
        let (key_name, value, found) = cut(item, "=");
        let path = if windows {
            fold_eq(key_name, "PATH")
        } else {
            key_name == "PATH"
        };
        if !found || !path {
            continue;
        }
        return search_dirs(value, windows);
    }
    Vec::new()
}

fn search_dirs(value: &str, windows: bool) -> Vec<String> {
    let separator = if windows { ';' } else { ':' };
    let mut directories: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for directory in value.split(separator) {
        if directories.len() >= MAX_SEARCH_DIRS {
            break;
        }
        let valid = if windows {
            valid_windows_file_path(directory)
                || (directory.len() == 3 && windows_drive_path(directory))
        } else {
            valid_linux_file_path(directory) || directory == "/"
        };
        let k = key(directory);
        if valid && !seen.contains(&k) {
            directories.push(directory.to_string());
            seen.push(k);
        }
    }
    directories
}

/// 컨테이너 ID 의 꼴 — 소문자 16진수 12~64자.
pub(crate) fn container_id(id: &str) -> bool {
    (12..=64).contains(&id.len()) && lower_hex(id)
}

/// 이미지 ID 의 꼴 — `sha256:` 이 붙거나 붙지 않은 소문자 16진수 64자.
pub(crate) fn image_id(id: &str) -> bool {
    let digest = id.strip_prefix("sha256:").unwrap_or(id);
    digest.len() == 64 && lower_hex(digest)
}

fn lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_paths_are_clean_absolute_files() {
        for good in ["/etc/os-release", "/usr/local/bin/php", "/한글/php"] {
            assert!(valid_linux_file_path(good), "{good}");
        }
        for bad in [
            "/",
            "",
            "etc/os-release",
            "/etc/",
            "/etc/../os-release",
            "/etc//os-release",
            "/etc/./os-release",
            "/a\\b",
            "/a\nb",
            "/a\u{85}b",
        ] {
            assert!(!valid_linux_file_path(bad), "{bad:?}");
        }
        assert!(!valid_linux_file_path(&format!("/{}", "a".repeat(4096))));
        assert!(valid_linux_file_path(&format!("/{}", "a".repeat(4095))));
    }

    #[test]
    fn windows_directory_and_join_keep_backslashes() {
        assert_eq!(dir(r"C:\php\php.exe"), r"C:\php");
        assert_eq!(dir(r"C:\php.exe"), r"C:\");
        assert_eq!(dir("/usr/local/bin/php"), "/usr/local/bin");
        assert_eq!(join(r"C:\php", "php8.dll"), r"C:\php\php8.dll");
        assert_eq!(join(r"C:\", "php.ini"), r"C:\php.ini");
        assert_eq!(join("/usr/bin", "node"), "/usr/bin/node");
        assert_eq!(base(r"C:\php\PHP.EXE"), "PHP.EXE");
        assert_eq!(key(r"C:\PHP\Php.exe"), "c:/php/php.exe");
        assert_eq!(key("/usr/Bin"), "/usr/Bin");
        assert!(same_file_base("PHP.EXE", r"C:\php\php.exe"));
        assert!(!same_file_base("PHP", "/usr/bin/php"));
    }

    #[test]
    fn ids_have_the_engine_shape() {
        assert!(container_id("0123456789ab"));
        assert!(container_id(&"a".repeat(64)));
        assert!(!container_id("0123456789a"));
        assert!(!container_id(&"a".repeat(65)));
        assert!(!container_id("0123456789AB"));
        assert!(!container_id("name-of-it"));
        assert!(image_id(&format!("sha256:{}", "0".repeat(64))));
        assert!(image_id(&"f".repeat(64)));
        assert!(!image_id(&format!("sha512:{}", "0".repeat(64))));
        assert!(!image_id("sha256:abc"));
    }
}
