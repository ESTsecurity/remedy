//! 예약 작업 정의(Task XML) 파싱.
//!
//! COM(`ITaskService`)을 쓰지 않고 `%SystemRoot%\System32\Tasks` 아래의 정의 파일을
//! 직접 읽는다. 이유는 셋이다.
//!
//! - 룰이 `source contains "\System32\"` 를 쓰므로 **정의 파일의 실제 경로**가 있어야 한다
//! - COM 은 스냅샷 백엔드에서 재현할 수 없다. 파일이면 코퍼스에 그대로 담긴다
//! - 32비트 프로세스의 WOW64 문제를 경로 하나로 다룰 수 있다 (`Sysnative`)
//!
//! 정의 파일은 대개 UTF-16LE + BOM 이다. 그대로 XML 파서에 넣으면 아무것도
//! 읽히지 않으므로 먼저 UTF-8 로 바꾼다.

use quick_xml::events::Event;
use quick_xml::Reader;
use remedy_artifacts::record::WinTaskFields;
use remedy_artifacts::{PersistenceRecord, WinTask};
use remedy_sdk::catalog::Platform;
use remedy_sdk::normalize;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedTask {
    pub command: String,
    pub args: String,
    /// Action 의 종류. Exec 가 아닌 작업이 절반을 넘는다(실측 218건 중 119건).
    pub actions: Vec<String>,
    pub working_directory: Option<String>,
    pub principal: Option<String>,
    pub run_level: Option<String>,
    pub enabled: bool,
    pub triggers: Vec<String>,
}

/// 바이트열을 UTF-8 문자열로. UTF-16LE/BE BOM 을 처리한다.
///
/// 구조적 설정의 XML(`config.rs`)도 이것으로 읽는다 — `.config` · `.xml` 도 UTF-16 으로
/// 저장되는 일이 있고, 그대로 파서에 넣으면 깨진 문서로 보여 잎이 하나도 나오지 않는다.
pub(crate) fn to_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16(&units).ok();
    }
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16(&units).ok();
    }
    let s = std::str::from_utf8(bytes).ok()?;
    Some(s.trim_start_matches('\u{feff}').to_string())
}

/// 정의 XML 하나를 읽는다. 작업 XML 이 아니면 `None`.
pub fn parse(bytes: &[u8]) -> Option<ParsedTask> {
    let text = to_text(bytes)?;
    if !text.contains("<Task") {
        return None;
    }

    let mut r = Reader::from_str(&text);
    r.config_mut().trim_text(true);

    let mut t = ParsedTask {
        // 작업 XML 의 Settings/Enabled 는 생략 가능하고 기본이 true 다.
        enabled: true,
        ..Default::default()
    };
    let mut path: Vec<String> = Vec::new();

    loop {
        match r.read_event() {
            Err(_) => return None,
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = local_name(e.name().as_ref());
                path.push(name.clone());
                // 트리거는 종류 자체가 정보다. `<LogonTrigger>` -> "logon"
                if path.len() >= 2 && path[path.len() - 2] == "Triggers" {
                    t.triggers.push(trigger_kind(&name));
                }
                // Action 종류도 마찬가지다. `<ComHandler>` 인 작업은 Command 가
                // 없는 것이 정상인데, 그것을 빈 명령으로만 남기면 "실행하는 것이
                // 없다" 와 구분되지 않는다.
                if path.len() >= 2 && path[path.len() - 2] == "Actions" {
                    t.actions.push(snake_case(&name));
                }
            }
            Ok(Event::Empty(e)) => {
                let name = local_name(e.name().as_ref());
                match path.last().map(|s| s.as_str()) {
                    Some("Triggers") => t.triggers.push(trigger_kind(&name)),
                    Some("Actions") => t.actions.push(snake_case(&name)),
                    _ => {}
                }
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::Text(e)) => {
                // 0.41 부터 본문 디코딩과 엔티티 해제가 나뉘었다.
                // 해제에 실패하면 원문을 쓴다 — 명령줄을 통째로 잃는 것보다 낫다.
                let raw = match e.xml_content(quick_xml::XmlVersion::Implicit1_0) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let v = quick_xml::escape::unescape(&raw)
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| raw.into_owned());
                match path_tail(&path) {
                    // 첫 Exec 만 본다. 여러 Action 이 있으면 나머지는 args 에
                    // 담기지 않지만, 그 경우 룰이 첫 Action 을 보는 것이 맞다.
                    ["Actions", "Exec", "Command"] if t.command.is_empty() => t.command = v,
                    ["Actions", "Exec", "Arguments"] if t.args.is_empty() => t.args = v,
                    ["Actions", "Exec", "WorkingDirectory"] => t.working_directory = Some(v),
                    ["Principals", "Principal", "UserId"] => t.principal = Some(v),
                    ["Principals", "Principal", "GroupId"] if t.principal.is_none() => {
                        t.principal = Some(v)
                    }
                    ["Principals", "Principal", "RunLevel"] => t.run_level = Some(v),
                    // 트리거 안의 <Enabled> 와 구분해야 한다. 경로 꼬리 셋으로 본다.
                    [_, "Settings", "Enabled"] => t.enabled = v.eq_ignore_ascii_case("true"),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    t.triggers.sort();
    t.triggers.dedup();
    t.actions.sort();
    t.actions.dedup();
    Some(t)
}

fn local_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    s.rsplit(':').next().unwrap_or("").to_string()
}

fn trigger_kind(tag: &str) -> String {
    snake_case(tag.strip_suffix("Trigger").unwrap_or(tag))
}

fn snake_case(tag: &str) -> String {
    let mut out = String::new();
    for (i, c) in tag.char_indices() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// 경로의 마지막 세 조각. 얕은 매칭으로 충분하다.
fn path_tail(path: &[String]) -> [&str; 3] {
    let n = path.len();
    let g = |k: usize| -> &str {
        if n >= k {
            path[n - k].as_str()
        } else {
            ""
        }
    };
    [g(3), g(2), g(1)]
}

/// 작업 계정의 프로필 변수 다섯을 편다 — 뜻은 `WinTaskFields::args_expanded` 의 문서.
///
/// `profile` 을 모르면 원문 그대로다. 아는 다섯이 아닌 변수(`%windir%` 등)도 그대로
/// 둔다 — 엔진을 돌린 계정의 값으로 펴면 다른 계정의 작업이 엉뚱한 자리를 가리킨다.
pub fn expand_user_vars(s: &str, profile: Option<&str>) -> String {
    let Some(profile) = profile.map(|p| p.trim_end_matches(['\\', '/'])) else {
        return s.to_string();
    };
    let value = |name: &str| -> Option<String> {
        Some(match name.to_ascii_uppercase().as_str() {
            "USERPROFILE" => profile.to_string(),
            "LOCALAPPDATA" => format!("{profile}\\AppData\\Local"),
            "APPDATA" => format!("{profile}\\AppData\\Roaming"),
            "TEMP" | "TMP" => format!("{profile}\\AppData\\Local\\Temp"),
            _ => return None,
        })
    };
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            out.push_str(&rest[start..]);
            return normalize::nfc(&out);
        };
        match value(&after[..end]) {
            Some(v) => {
                out.push_str(&v);
                rest = &after[end + 1..];
            }
            // 모르는 이름이다. 여는 `%` 만 옮기고 그 뒤부터 다시 찾는다 — 닫는 `%` 가
            // 다음 변수의 여는 것일 수 있다(`%a%%LOCALAPPDATA%`).
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    normalize::nfc(&out)
}

/// 파싱 결과를 레코드로. 등록 경로는 정의 파일의 위치에서 나온다.
pub fn to_record(
    t: ParsedTask,
    source_path: &str,
    tasks_root_normalized: &str,
    platform: Platform,
) -> PersistenceRecord {
    // 저장용 정규화 — 대소문자를 보존한다. 이 값이 곧 계획이 지목할 대상이다.
    let src = normalize::for_record(source_path, platform);
    // `...\Tasks\Microsoft\Windows\Locust` -> `\Microsoft\Windows\Locust`
    //
    // 접두 판정은 접어서 하고 슬라이싱은 원본에 대고 한다. 루트와 실제 경로의
    // 대소문자가 다를 수 있는데(환경변수 전개 결과 vs 디렉터리 열거 결과),
    // 그 차이로 접두를 못 찾으면 id 가 전체 경로가 되어 룰이 전부 빗나간다.
    let root_cmp = normalize::for_compare(tasks_root_normalized, platform);
    let src_cmp = normalize::for_compare(&src, platform);
    let rel = if src_cmp.starts_with(&root_cmp) {
        src[root_cmp.len()..].to_string()
    } else {
        src.clone()
    };
    let id = if rel.starts_with('\\') {
        rel.clone()
    } else {
        format!("\\{rel}")
    };
    let name = id.rsplit('\\').next().unwrap_or("").to_string();
    // 룰이 `starts_with "\Microsoft\Windows\"` 를 쓰므로 등록 폴더는 후행
    // 구분자를 남긴다.
    let register_path = match id.rfind('\\') {
        Some(i) => id[..=i].to_string(),
        None => "\\".to_string(),
    };

    PersistenceRecord {
        id,
        name,
        enabled: t.enabled,
        trigger: t.triggers,
        command: normalize::nfc(&t.command),
        args: normalize::nfc(&t.args),
        principal: t.principal,
        source: src,
        // 예약 작업은 파일 안의 줄이 아니다.
        linux: None,
        win: Some(WinTask {
            task: WinTaskFields {
                register_path,
                actions: t.actions,
                run_level: t.run_level,
                working_directory: t.working_directory,
                // 수집기가 작업 계정의 프로필을 안 뒤에 채운다(`expand_user_vars`).
                command_expanded: None,
                args_expanded: None,
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Someone</Author></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <BootTrigger />
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Program Files\nodejs\node.exe</Command>
      <Arguments>C:\Users\t\AppData\Local\Programs\app-1\main.js --run</Arguments>
    </Exec>
  </Actions>
</Task>"#;

    fn utf16le(s: &str) -> Vec<u8> {
        let mut out = vec![0xFF, 0xFE];
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    #[test]
    fn parses_utf8_task_xml() {
        let t = parse(XML.as_bytes()).expect("파싱");
        assert_eq!(t.command, "C:\\Program Files\\nodejs\\node.exe");
        assert!(t.args.ends_with("main.js --run"));
        assert_eq!(t.principal.as_deref(), Some("S-1-5-18"));
        assert_eq!(t.run_level.as_deref(), Some("HighestAvailable"));
        assert!(t.enabled);
        assert_eq!(t.triggers, vec!["boot", "logon"]);
    }

    #[test]
    fn parses_utf16le_with_bom() {
        // 실제 작업 정의 파일이 이 형태다. 그대로 파서에 넣으면 아무것도 안 읽힌다.
        let t = parse(&utf16le(XML)).expect("UTF-16 파싱");
        assert_eq!(t.command, "C:\\Program Files\\nodejs\\node.exe");
    }

    #[test]
    fn non_task_xml_is_skipped() {
        assert!(parse(b"<html><body/></html>").is_none());
        assert!(parse(&[0xDE, 0xAD, 0xBE, 0xEF]).is_none());
    }

    #[test]
    fn disabled_task_is_reported_as_disabled() {
        let off = XML.replace(
            "<Settings><Enabled>true</Enabled></Settings>",
            "<Settings><Enabled>false</Enabled></Settings>",
        );
        assert!(!parse(off.as_bytes()).unwrap().enabled);
    }

    #[test]
    fn missing_settings_defaults_to_enabled() {
        // Settings/Enabled 는 생략 가능하고 기본이 true 다. false 로 읽으면
        // 살아 있는 지속성 항목을 꺼져 있다고 보고하게 된다.
        let none = XML.replace("<Settings><Enabled>true</Enabled></Settings>", "");
        assert!(parse(none.as_bytes()).unwrap().enabled);
    }

    #[test]
    fn record_derives_register_path_from_file_location() {
        let t = parse(XML.as_bytes()).unwrap();
        let r = to_record(
            t,
            "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\Locust",
            "C:\\Windows\\System32\\Tasks",
            Platform::Windows,
        );
        assert_eq!(r.id, "\\Microsoft\\Windows\\Locust");
        assert_eq!(r.name, "Locust");
        assert_eq!(
            r.win.unwrap().task.register_path,
            "\\Microsoft\\Windows\\",
            "룰이 starts_with 로 비교하므로 후행 구분자가 있어야 한다"
        );
        assert!(
            r.source.to_ascii_lowercase().contains("\\system32\\"),
            "룰이 source contains '\\System32\\' 를 쓴다: {}",
            r.source
        );
    }

    #[test]
    fn exec_action_kind_is_recorded() {
        assert_eq!(parse(XML.as_bytes()).unwrap().actions, vec!["exec"]);
    }

    /// Exec 가 아닌 Action 만 가진 작업. `<Actions>` 절만 바꿔 끼운다.
    fn with_actions(inner: &str) -> String {
        let head = XML.split("<Actions").next().unwrap();
        format!(
            "{head}<Actions Context=\"Author\">{inner}</Actions>
</Task>"
        )
    }

    #[test]
    fn non_exec_action_is_visible_instead_of_an_empty_command() {
        // 정상 Windows 10 의 예약 작업 218건 중 119건이 이 형태다. 빈 명령만
        // 남기면 "아무것도 실행하지 않는 작업" 처럼 보이고, 룰 작성자는 왜
        // 안 맞는지 알 수 없다.
        let xml = with_actions("<ComHandler><ClassId>{0}</ClassId></ComHandler>");
        let t = parse(xml.as_bytes()).expect("파싱");
        assert!(t.command.is_empty(), "ComHandler 에는 Command 가 없다");
        assert_eq!(t.actions, vec!["com_handler"]);

        let r = to_record(
            t,
            "C:\\Windows\\System32\\Tasks\\Solo",
            "C:\\Windows\\System32\\Tasks",
            Platform::Windows,
        );
        assert_eq!(r.win.unwrap().task.actions, vec!["com_handler"]);
    }

    #[test]
    fn self_closing_action_is_recorded_too() {
        assert_eq!(
            parse(with_actions("<ComHandler />").as_bytes())
                .unwrap()
                .actions,
            vec!["com_handler"]
        );
    }

    #[test]
    fn top_level_task_has_root_register_path() {
        let t = parse(XML.as_bytes()).unwrap();
        let r = to_record(
            t,
            "C:\\Windows\\System32\\Tasks\\Solo",
            "C:\\Windows\\System32\\Tasks",
            Platform::Windows,
        );
        assert_eq!(r.id, "\\Solo");
        assert_eq!(r.win.unwrap().task.register_path, "\\");
    }

    /// Trend Micro 가 본 EvilAI 작업(2025-09). `%^LOCALAPPDATA^%` 로 등록해 변수가
    /// 펴지지 않은 채 저장된다 — 그 작업의 계정으로 펴야 페이로드 자리가 나온다.
    #[test]
    fn user_vars_expand_against_the_task_accounts_profile() {
        let args = r#"/c start "" /min "%LOCALAPPDATA%\Programs\nodejs\node.exe" "%LocalAppData%\TEMP\0b3cor.js""#;
        assert_eq!(
            expand_user_vars(args, Some(r"C:\Users\test")),
            r#"/c start "" /min "C:\Users\test\AppData\Local\Programs\nodejs\node.exe" "C:\Users\test\AppData\Local\TEMP\0b3cor.js""#
        );
        assert_eq!(
            expand_user_vars(
                r"%USERPROFILE%\a %APPDATA%\b %TEMP%\c %TMP%\d",
                Some(r"D:\P\u\")
            ),
            r"D:\P\u\a D:\P\u\AppData\Roaming\b D:\P\u\AppData\Local\Temp\c D:\P\u\AppData\Local\Temp\d"
        );
    }

    /// 모르는 계정과 모르는 변수는 그대로 둔다 — 엔진을 돌린 계정의 값으로 펴면 다른
    /// 계정의 작업이 엉뚱한 자리를 가리킨다.
    #[test]
    fn unknown_accounts_and_other_vars_stay_literal() {
        let s = r"%LOCALAPPDATA%\x";
        assert_eq!(expand_user_vars(s, None), s);
        assert_eq!(
            expand_user_vars(r"%windir%\a %LOCALAPPDATA%\b", Some(r"C:\Users\t")),
            r"%windir%\a C:\Users\t\AppData\Local\b"
        );
        assert_eq!(
            expand_user_vars(r"%a%%LOCALAPPDATA%\b", Some(r"C:\Users\t")),
            r"%a%C:\Users\t\AppData\Local\b"
        );
        assert_eq!(
            expand_user_vars("50% done %", Some(r"C:\Users\t")),
            "50% done %"
        );
    }
}
