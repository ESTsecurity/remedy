//! cron 항목 파싱 (설계-09 P12).
//!
//! # 자리가 정해져 있다
//!
//! Windows 예약 작업이 `System32\Tasks` 하나인 것과 같다. 플러그인이 위치를
//! 선언할 이유가 없고, 선언하게 만들면 위치를 틀린 플러그인이 조용히 0건을
//! 보고한다. 그래서 `scan_roots` 와 무관하게 아래 자리를 본다.
//!
//! | 자리 | 형식 | 실행 주체 |
//! |---|---|---|
//! | `/etc/crontab` | 사용자 칸이 **있다** | 그 칸 |
//! | `/etc/cron.d/*` | 〃 | 〃 |
//! | `/var/spool/cron/crontabs/*` · `/var/spool/cron/*` | 사용자 칸이 **없다** | 파일 이름 |
//! | `/etc/cron.{hourly,daily,weekly,monthly}/*` | 스크립트. 일정은 폴더가 정한다 | root |
//!
//! **사용자 칸의 유무가 형식을 가른다.** 잘못 세면 명령의 첫 낱말이 사용자
//! 이름으로 먹히거나 그 반대가 되고, 그러면 `command` 가 통째로 어긋나 룰이
//! 전부 빗나간다.
//!
//! # 실행 비트를 본다
//!
//! `run-parts` 는 `/etc/cron.daily` 아래에서 실행 비트가 없는 파일을 건너뛴다.
//! 그것을 모르면 **돌지도 않는 스크립트를 활성 지속성으로 보고**하게 된다.

use remedy_artifacts::record::{CronLine, LinuxPersistence};
use remedy_artifacts::PersistenceRecord;

/// 사용자 칸이 있는 시스템 crontab.
pub(crate) const SYSTEM_FILES: [&str; 1] = ["/etc/crontab"];
/// 사용자 칸이 있는 시스템 crontab 조각들이 사는 폴더.
pub(crate) const SYSTEM_DIRS: [&str; 1] = ["/etc/cron.d"];
/// 사용자 칸이 없는 개인 crontab 이 사는 폴더. 파일 이름이 곧 사용자다.
pub(crate) const SPOOL_DIRS: [&str; 2] = ["/var/spool/cron/crontabs", "/var/spool/cron"];
/// `run-parts` 가 도는 폴더.
///
/// **일정은 폴더 이름이 정한다.** 그래서 따로 들고 다니지 않는다 — `source` 에
/// 그대로 남고, 룰은 `source starts_with "/etc/cron.daily/"` 로 묻는다.
pub(crate) const RUN_PARTS: [&str; 4] = [
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];

/// 한 줄에서 읽어 낸 것.
#[derive(Debug, PartialEq, Eq)]
pub struct CronEntry {
    /// 일정 표현 그대로. `@reboot` · `*/5 * * * *`.
    pub schedule: String,
    /// 실행 주체. 사용자 칸이 없는 형식에서는 호출자가 채운다.
    pub user: Option<String>,
    pub command: String,
    pub args: String,
}

/// 일정 표현을 Windows 와 **같은 낱말**로 옮긴다.
///
/// `boot` · `calendar` 는 예약 작업 XML 이 쓰는 것과 같다. 새 낱말을 만들면
/// Windows 용으로 쓴 `trigger contains "boot"` 가 Linux 에서 안 맞는다.
pub fn trigger_kind(schedule: &str) -> &'static str {
    if schedule.eq_ignore_ascii_case("@reboot") {
        "boot"
    } else {
        "calendar"
    }
}

/// 줄 하나를 읽는다. 항목이 아니면 `None`.
///
/// `has_user` 는 **형식이 정한다** — `/etc/crontab` 계열은 참, 개인 crontab 은
/// 거짓이다.
pub fn parse_line(line: &str, has_user: bool) -> Option<CronEntry> {
    let t = line.trim();
    // 주석과 빈 줄. 주석까지 담으면 "이 명령이 cron 에 있다" 를 묻는 룰이
    // 주석에도 걸린다 (hosts 수집기와 같은 판단).
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    // `SHELL=/bin/sh` · `PATH=...` · `MAILTO=` 같은 환경 설정. 첫 낱말에 `=` 가
    // 있고 공백이 없으면 항목이 아니다.
    if let Some(first) = t.split_whitespace().next() {
        if first.contains('=') && !first.starts_with('@') {
            return None;
        }
    }

    // `@reboot` 계열은 일정이 한 칸이고, 그 밖은 다섯 칸이다.
    let fields = if t.starts_with('@') { 1 } else { 5 };
    let mut it = t.split_whitespace();
    let mut schedule = String::new();
    for i in 0..fields {
        let f = it.next()?;
        if i > 0 {
            schedule.push(' ');
        }
        schedule.push_str(f);
    }

    let user = if has_user {
        Some(it.next()?.to_string())
    } else {
        None
    };

    // 남은 전부가 명령이다. **여기서 다시 쪼개지 않는다** — `cd / && run-parts`
    // 처럼 셸 문법이 섞이므로 첫 낱말만 실행 파일로 보고 나머지를 인자로 둔다.
    let rest: Vec<&str> = it.collect();
    if rest.is_empty() {
        return None;
    }
    Some(CronEntry {
        schedule,
        user,
        command: rest[0].to_string(),
        args: rest[1..].join(" "),
    })
}

/// crontab 항목 하나를 레코드로.
///
/// # `id` 가 파일과 줄 번호인 이유
///
/// cron 항목에는 이름이 없다. Windows 예약 작업의 `id` 가 등록 경로인 것처럼,
/// 여기서 **그 항목이 등록된 자리**는 파일과 줄이다.
///
/// 줄 번호는 위쪽이 편집되면 밀린다. 그래서 이것을 지우는 Op 은 줄 번호만으로
/// 지우지 않고 **내용까지 대조한다** — `text_config.remove_line` 과 같은 규약이다.
pub fn to_record(
    e: CronEntry,
    source: &str,
    line_no: u32,
    line: &str,
    enabled: bool,
) -> PersistenceRecord {
    use remedy_sdk::normalize;
    let name = source.rsplit('/').next().unwrap_or(source).to_string();
    PersistenceRecord {
        id: format!("{source}:{line_no}"),
        name,
        enabled,
        trigger: vec![trigger_kind(&e.schedule).to_string()],
        command: normalize::nfc(&e.command),
        args: normalize::nfc(&e.args),
        principal: e.user,
        source: source.to_string(),
        win: None,
        // **원문을 함께 담는다.** 이 줄을 지우는 Op 이 번호만으로 고치지 않고
        // 내용까지 대조한다 (설계-09 P12 결정 5). `trigger` 는 `boot`/`calendar`
        // 로 정규화된 값이라 그것으로는 `*/5 * * * *` 를 되살릴 수 없다.
        linux: Some(LinuxPersistence {
            cron: Some(CronLine {
                line_no,
                line: normalize::nfc(line.trim()),
            }),
        }),
    }
}

/// `run-parts` 폴더의 스크립트 하나를 레코드로.
///
/// 일정은 폴더 이름이 정하고(그래서 `source` 가 그것을 말한다) 실행 주체는
/// root 다. **실행 비트가 없으면 `enabled: false`** — `run-parts` 가 건너뛴다.
pub fn run_parts_record(path: &str, mode: Option<u32>) -> PersistenceRecord {
    let name = path.rsplit('/').next().unwrap_or(path).to_string();
    PersistenceRecord {
        id: path.to_string(),
        name,
        // **모르면 켜진 것으로 둔다.** 스냅샷 백엔드처럼 권한 비트를 못 보는
        // 곳에서 `false` 로 두면 돌고 있는 지속성이 "꺼져 있다" 로 보고된다.
        enabled: mode.is_none_or(|m| m & 0o111 != 0),
        trigger: vec!["calendar".to_string()],
        command: path.to_string(),
        args: String::new(),
        principal: Some("root".to_string()),
        source: path.to_string(),
        win: None,
        // 스크립트 **파일 하나**이지 줄이 아니다. 지우는 것도 파일이다.
        linux: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_system_crontab_line_has_a_user_column() {
        // **사용자 칸을 잘못 세면 명령이 통째로 어긋난다.** 여기서는 `root` 가
        // 사용자이지 실행 파일이 아니다.
        let e = parse_line(
            "17 *\t* * *\troot    cd / && run-parts /etc/cron.hourly",
            true,
        )
        .expect("항목");
        assert_eq!(e.schedule, "17 * * * *");
        assert_eq!(e.user.as_deref(), Some("root"));
        assert_eq!(e.command, "cd");
        assert_eq!(e.args, "/ && run-parts /etc/cron.hourly");
    }

    #[test]
    fn a_user_crontab_line_has_no_user_column() {
        // 같은 줄을 개인 crontab 으로 읽으면 여섯 번째 낱말이 명령이다. 형식을
        // 틀리면 `/home/a/upd.sh` 가 사용자 이름으로 먹힌다.
        let e = parse_line("*/5 * * * * /home/a/upd.sh --quiet", false).expect("항목");
        assert_eq!(e.schedule, "*/5 * * * *");
        assert_eq!(e.user, None);
        assert_eq!(e.command, "/home/a/upd.sh");
        assert_eq!(e.args, "--quiet");
    }

    #[test]
    fn at_reboot_is_a_boot_trigger() {
        // **고전적인 지속성 자리다.** 일정 칸이 다섯이 아니라 하나이므로 형식을
        // 따로 다루지 않으면 명령이 네 칸 뒤로 밀린다.
        let e = parse_line("@reboot /home/a/.cache/upd.sh", false).expect("항목");
        assert_eq!(e.schedule, "@reboot");
        assert_eq!(e.command, "/home/a/.cache/upd.sh");
        assert_eq!(trigger_kind(&e.schedule), "boot");
    }

    #[test]
    fn at_daily_is_still_a_calendar_trigger() {
        let e = parse_line("@daily /usr/bin/backup", false).expect("항목");
        assert_eq!(trigger_kind(&e.schedule), "calendar");
    }

    #[test]
    fn comments_and_environment_lines_are_not_entries() {
        // 주석까지 담으면 "이 명령이 cron 에 있다" 를 묻는 룰이 주석에도 걸린다.
        assert_eq!(parse_line("# @reboot /evil.sh", false), None);
        assert_eq!(parse_line("", false), None);
        assert_eq!(parse_line("SHELL=/bin/sh", false), None);
        assert_eq!(parse_line("PATH=/usr/bin:/bin", false), None);
        assert_eq!(parse_line("MAILTO=", false), None);
    }

    #[test]
    fn a_line_without_a_command_is_not_an_entry() {
        // 일정만 있고 명령이 없는 줄. 담으면 `command` 가 빈 레코드가 되고,
        // 그것은 "명령이 없는 예약" 이라는 있지도 않은 것을 보고하는 셈이다.
        assert_eq!(parse_line("*/5 * * * *", false), None);
        assert_eq!(parse_line("@reboot", false), None);
    }

    #[test]
    fn a_run_parts_script_without_the_exec_bit_is_not_enabled() {
        // `run-parts` 가 건너뛴다. 켜진 것으로 보고하면 없는 지속성을 만든다.
        let off = run_parts_record("/etc/cron.daily/x", Some(0o644));
        assert!(!off.enabled);
        let on = run_parts_record("/etc/cron.daily/x", Some(0o755));
        assert!(on.enabled);
    }

    #[test]
    fn not_knowing_the_mode_leaves_it_enabled() {
        // **모르는 것을 꺼진 것으로 보고하지 않는다.** 권한 비트를 못 보는
        // 백엔드에서 `false` 를 내면 돌고 있는 지속성이 사라진다.
        assert!(run_parts_record("/etc/cron.daily/x", None).enabled);
    }

    #[test]
    fn the_id_says_where_the_entry_is_registered() {
        let e = parse_line("@reboot /evil.sh", false).expect("항목");
        let r = to_record(e, "/etc/cron.d/updater", 7, "@reboot /evil.sh", true);
        assert_eq!(r.id, "/etc/cron.d/updater:7");
        assert_eq!(r.name, "updater");
        assert_eq!(r.source, "/etc/cron.d/updater");
        assert_eq!(r.trigger, vec!["boot"]);
        // **원문이 함께 담긴다.** 이 줄을 지우는 Op 이 내용까지 대조한다.
        let c = r
            .linux
            .as_ref()
            .and_then(|l| l.cron.as_ref())
            .expect("cron");
        assert_eq!(c.line_no, 7);
        assert_eq!(c.line, "@reboot /evil.sh");
    }
}
