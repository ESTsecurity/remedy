//! `.desktop` 항목 파싱 (설계-09 P12 순서 9).
//!
//! # 한 형식이 두 subject 를 먹인다
//!
//! `.desktop` 은 XDG 데스크톱 항목이다. 그것이 **어디 있는가**가 subject 를
//! 가른다.
//!
//! | 자리 | subject | 왜 |
//! |---|---|---|
//! | `~/.config/autostart` · `/etc/xdg/autostart` | `autorun` | 로그온마다 저절로 실행된다 |
//! | 그 밖 (`applications` 등) | `shortcut` | 사람이 눌러야 실행된다 |
//!
//! Windows 도 같은 모양이다 — 시작 폴더의 `.lnk` 는 `autorun` 이고 바탕화면의
//! `.lnk` 는 `shortcut` 이다. **파일 형식이 아니라 자리가 정한다.**
//!
//! # 파싱은 방어적으로 한다
//!
//! 남이 쓴 파일이다. `[Desktop Entry]` 밖의 절(`[Desktop Action …]`)과 로케일
//! 접미(`Name[ko]=`)가 흔하므로, **첫 절의 접미 없는 키만** 읽는다 — 로케일 값을
//! 담으면 같은 항목이 기계마다 다른 이름으로 스냅샷에 들어간다.

use remedy_artifacts::{AutorunRecord, ShortcutRecord};

/// XDG 자동실행 자리. `%HOME%` 아래는 호출자가 사용자마다 붙인다.
pub(crate) const AUTOSTART_DIRS: [&str; 2] = ["/etc/xdg/autostart", "/usr/share/gnome/autostart"];

/// 로그온마다 실행되는 셸 조각.
///
/// `~/.bashrc` 같은 **줄 단위** 자동실행은 여기 없다. 그것은 셸 코드라 "명령
/// 하나" 로 환원되지 않고, 잘못 환원하면 레코드가 거짓을 말한다. 그 자리는
/// `text_config` 가 줄로 담아야 하고 아직 그 확장자 목록에 없다.
pub(crate) const PROFILE_DIRS: [&str; 1] = ["/etc/profile.d"];

/// `.desktop` 파일에서 읽어 낸 것.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DesktopEntry {
    pub name: String,
    /// `Exec=` 전체. 실행 파일과 인자가 아직 붙어 있다.
    pub exec: String,
    pub path: String,
    pub icon: String,
    /// `Hidden=true` 는 **이 항목을 없는 것으로 하라**는 뜻이다 (XDG 규격).
    /// 상위 자리의 같은 이름을 가리는 데 쓴다.
    pub hidden: bool,
}

pub fn parse(text: &str) -> DesktopEntry {
    let mut d = DesktopEntry::default();
    let mut in_entry = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            // 첫 절만 본다. `[Desktop Action Foo]` 의 `Exec=` 는 그 동작의
            // 것이지 항목이 저절로 실행하는 명령이 아니다.
            in_entry = line.eq_ignore_ascii_case("[Desktop Entry]");
            continue;
        }
        if !in_entry {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        // **로케일 접미가 붙은 키는 버린다.** `Name[ko]` 를 담으면 같은 항목이
        // 기계마다 다른 이름으로 스냅샷에 들어간다.
        let key = key.trim();
        if key.contains('[') {
            continue;
        }
        let value = value.trim();
        match key {
            "Name" => d.name = value.to_string(),
            "Exec" => d.exec = value.to_string(),
            "Path" => d.path = value.to_string(),
            "Icon" => d.icon = value.to_string(),
            "Hidden" => d.hidden = value.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    d
}

/// `Exec=` 를 실행 파일과 인자로 가른다.
///
/// **규칙은 쓰기 경계에 있다** ([`remedy_platform::write::split_exec`]). 수집기가
/// "인자" 라고 담은 것과 실행기가 떼는 것이 갈라지면, 계획이 본 것과 실행이
/// 하는 것이 조용히 달라진다 — 2026-09-06 부터 계획이 이 값을 담으므로 그 둘은
/// **같아야만 하는 값**이다.
pub fn split_exec(exec: &str) -> (String, String) {
    remedy_platform::write::split_exec(exec)
}

/// XDG 자동실행 항목 하나를 레코드로.
///
/// `id` 는 **파일 경로**다. `AutorunRecord` 에는 계획기가 대상으로 삼을 다른
/// 자리가 없고, 이름만 적으면 쓰기 경계가 파일을 찾아 헤매야 한다 (불변식 P).
pub fn to_autorun(d: &DesktopEntry, path: &str, scope: &str) -> AutorunRecord {
    use remedy_sdk::normalize;
    let file = path.rsplit('/').next().unwrap_or(path);
    AutorunRecord {
        id: path.to_string(),
        scope: scope.to_string(),
        name: normalize::nfc(if d.name.is_empty() { file } else { &d.name }),
        command: normalize::nfc(&d.exec),
        source: path
            .rsplit_once('/')
            .map(|(dir, _)| dir.to_string())
            .unwrap_or_default(),
    }
}

/// 로그온마다 도는 셸 조각 하나를 레코드로.
///
/// 스크립트 **파일 하나**가 항목이다 — 그 안의 줄이 아니다.
pub fn profile_script_to_autorun(path: &str) -> AutorunRecord {
    let file = path.rsplit('/').next().unwrap_or(path);
    AutorunRecord {
        id: path.to_string(),
        scope: "system".into(),
        name: file.to_string(),
        command: path.to_string(),
        source: path
            .rsplit_once('/')
            .map(|(dir, _)| dir.to_string())
            .unwrap_or_default(),
    }
}

/// `.desktop` 항목 하나를 바로가기 레코드로.
pub fn to_shortcut(d: &DesktopEntry, path: &str) -> ShortcutRecord {
    use remedy_sdk::normalize;
    let (target, args) = split_exec(&d.exec);
    ShortcutRecord {
        path: path.to_string(),
        target: normalize::nfc(&target),
        args: normalize::nfc(&args),
        working_dir: normalize::nfc(&d.path),
        icon: normalize::nfc(&d.icon),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: &str = "\
[Desktop Entry]
Type=Application
Name=Updater
Name[ko]=업데이터
Exec=/home/a/.local/bin/upd --daemon %U
Path=/home/a
Icon=updater

[Desktop Action Config]
Exec=/home/a/.local/bin/upd --config
";

    #[test]
    fn a_locale_suffixed_key_is_not_the_name() {
        // 로케일 값을 담으면 **같은 항목이 기계마다 다른 이름**으로 스냅샷에
        // 들어가고, 이름으로 매치하는 룰이 한국어 데스크톱에서만 빗나간다.
        let d = parse(ENTRY);
        assert_eq!(d.name, "Updater");
    }

    #[test]
    fn a_second_section_does_not_overwrite_the_exec() {
        // `[Desktop Action …]` 의 `Exec=` 는 그 동작의 것이지 항목이 저절로
        // 실행하는 명령이 아니다. 덮어쓰면 자동실행이 무엇을 돌리는지 틀리게 적는다.
        let d = parse(ENTRY);
        assert_eq!(d.exec, "/home/a/.local/bin/upd --daemon %U");
    }

    #[test]
    fn field_codes_are_not_arguments() {
        // `%U` 는 실행할 때 치환되는 자리표시자다. 인자로 담으면 인자를 지우는
        // Op 이 그것까지 지우고, 그러면 항목이 원래 하던 일을 못 한다.
        let (cmd, args) = split_exec("/home/a/.local/bin/upd --daemon %U");
        assert_eq!(cmd, "/home/a/.local/bin/upd");
        assert_eq!(args, "--daemon");
    }

    #[test]
    fn an_autorun_carries_its_path_as_the_id() {
        // 계획기가 대상으로 삼을 자리가 `id` 뿐이다 — `AutorunRecord` 에 경로를
        // 담는 다른 필드가 없다.
        let d = parse(ENTRY);
        let r = to_autorun(&d, "/home/a/.config/autostart/upd.desktop", "user");
        assert_eq!(r.id, "/home/a/.config/autostart/upd.desktop");
        assert_eq!(r.source, "/home/a/.config/autostart");
        assert_eq!(r.scope, "user");
        assert_eq!(r.command, "/home/a/.local/bin/upd --daemon %U");
    }

    #[test]
    fn a_shortcut_splits_target_from_args() {
        let d = parse(ENTRY);
        let r = to_shortcut(&d, "/usr/share/applications/upd.desktop");
        assert_eq!(r.target, "/home/a/.local/bin/upd");
        assert_eq!(r.args, "--daemon");
        assert_eq!(r.working_dir, "/home/a");
        assert_eq!(r.icon, "updater");
    }

    #[test]
    fn a_nameless_entry_falls_back_to_the_file_name() {
        // 빈 이름은 보고서에서 아무것도 말하지 않는다.
        let d = parse("[Desktop Entry]\nExec=/x\n");
        let r = to_autorun(&d, "/etc/xdg/autostart/evil.desktop", "system");
        assert_eq!(r.name, "evil.desktop");
    }

    #[test]
    fn a_hidden_entry_is_read_as_hidden() {
        // XDG 의 `Hidden=true` 는 "이 항목을 없는 것으로 하라" 다. 상위 자리의
        // 같은 이름을 가리는 데 쓰이므로 **그 사실이 레코드에 드러나야** 한다.
        assert!(parse("[Desktop Entry]\nHidden=true\nExec=/x\n").hidden);
        assert!(!parse(ENTRY).hidden);
    }
}
