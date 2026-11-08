//! 필드 조회와 capture 표현식 (설계-02 §4).
//!
//! capture 함수는 **닫힌 집합**이다. 임의 코드가 아니므로 룰이 무엇을 계산하는지
//! 읽는 것만으로 알 수 있고, 평가가 결정적이다.

use remedy_sdk::catalog::{CaptureFn, Phase};
use remedy_sdk::normalize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExprError {
    pub message: String,
    /// 기다리면 되는 문제라면 그 Phase.
    pub available_in: Option<Phase>,
}

impl ExprError {
    fn now(m: impl Into<String>) -> Self {
        Self {
            message: m.into(),
            available_in: None,
        }
    }
    fn later(m: impl Into<String>, p: Phase) -> Self {
        Self {
            message: m.into(),
            available_in: Some(p),
        }
    }
}

impl std::fmt::Display for ExprError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(p) = self.available_in {
            write!(f, " ({} 에서 사용 가능해집니다)", p.as_str())?;
        }
        Ok(())
    }
}

/// 레코드에서 점 표기 경로로 값을 꺼낸다. 예: `command`, `win.task.register_path`
///
/// 값이 문자열이 아니면 문자열로 변환한다 — 룰의 비교 연산자는 전부 문자열
/// 기반이고, 타입별 분기를 두면 룰 작성자가 타입을 신경 써야 한다.
pub fn field(record: &serde_json::Value, path: &str) -> Option<String> {
    // `file(command).signature.subject` 처럼 다른 subject 로 건너뛰는 참조는
    // 레코드 하나로 답할 수 없다. P4 의 표면이다.
    if path.contains('(') {
        return None;
    }
    let mut cur = record;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(match cur {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => return None,
        other => other.to_string(),
    })
}

/// 다른 subject 를 건너뛰는 필드 참조인가. 오류 메시지를 정확히 내기 위해 쓴다.
pub fn is_cross_subject(path: &str) -> bool {
    path.contains('(')
}

/// `${...}` 참조를 실제 값으로 바꾼다.
///
/// `${rule.capture}` 는 다른 규칙의 capture, `${capture}` 는 같은 규칙 안의 capture 다.
/// 해소되지 않으면 `None` — 그 조건은 평가할 수 없으므로 미매치로 처리한다.
pub fn interpolate(template: &str, bindings: &BTreeMap<String, String>) -> Option<String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let j = after.find('}')?;
        let key = &after[..j];
        out.push_str(bindings.get(key)?);
        rest = &after[j + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// 템플릿이 참조하는 키 전부.
///
/// 정의는 SDK 에 있다. `${}` 는 매니페스트 문법이고, 평가기와 린터가 각자
/// 파싱하면 **린트를 통과한 룰이 평가에서 다르게 읽힌다.**
pub use remedy_sdk::manifest::references;

/// capture 표현식을 평가한다. `<source> | <fn> | <fn> ...`
///
/// `source` 는 `${...}` 참조이거나 레코드의 필드 경로다.
pub fn capture(
    expression: &str,
    record: &serde_json::Value,
    bindings: &BTreeMap<String, String>,
) -> Result<Option<String>, ExprError> {
    let mut parts = expression.split('|').map(str::trim);
    let source = parts.next().unwrap_or("");
    if source.is_empty() {
        return Err(ExprError::now("capture 표현식이 비어 있습니다"));
    }

    let mut value = if source.contains("${") {
        match interpolate(source, bindings) {
            Some(v) => v,
            None => return Ok(None), // 참조가 아직 없다 = 미매치
        }
    } else {
        match field(record, source) {
            Some(v) => v,
            None => return Ok(None),
        }
    };

    for f in parts {
        value = apply(f, &value)?;
    }
    Ok(Some(value))
}

fn apply(name: &str, v: &str) -> Result<String, ExprError> {
    let f = CaptureFn::ALL
        .into_iter()
        .find(|c| c.id() == name)
        .ok_or_else(|| {
            ExprError::now(format!(
                "capture 함수 '{name}' 는 없습니다. 쓸 수 있는 것: {}",
                CaptureFn::ALL
                    .iter()
                    .map(|c| c.id())
                    .collect::<Vec<_>>()
                    .join(" · ")
            ))
        })?;

    Ok(match f {
        CaptureFn::FirstPath => first_path(v),
        CaptureFn::LastPath => last_path(v),
        CaptureFn::Dirname => dirname(v),
        CaptureFn::Basename => basename(v),
        CaptureFn::Lower => normalize::fold_case(v),
        CaptureFn::TrimQuotes => trim_quotes(v).to_string(),
        CaptureFn::HexDecode => hex_decode(v)?,
        CaptureFn::Base64Decode => base64_decode(v)?,
        CaptureFn::ExpandEnv => {
            // 현재 프로세스의 환경을 읽으면 **평가가 기계에 따라 달라진다.**
            // 같은 스냅샷을 두 번 평가해 같은 결과가 나와야 한다는 P2 의 결정성
            // 요건과 정면으로 어긋난다. 수집 시점의 환경을 스냅샷에 담은 뒤에야
            // 가능하다.
            return Err(ExprError::later(
                "expand_env 는 수집 시점의 환경이 스냅샷에 있어야 평가할 수 있습니다",
                Phase::P4,
            ));
        }
    })
}

/// 명령줄에서 첫 번째 경로를 꺼낸다. 따옴표로 묶인 경로를 먼저 본다.
fn first_path(v: &str) -> String {
    let t = v.trim();
    if let Some(rest) = t.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
    }
    t.split_whitespace().next().unwrap_or("").to_string()
}

/// 명령줄에서 **마지막** 경로를 꺼낸다 — 역슬래시가 든 마지막 토큰, 없으면 슬래시가
/// 든 마지막 토큰.
///
/// 토큰은 따옴표로 묶인 덩어리 하나(따옴표는 뗀다)이거나 공백으로 갈린 낱말 하나다.
/// 구분자가 없는 토큰(`--run` · 빈 `""`)은 경로가 아니라 건너뛴다.
///
/// **역슬래시를 먼저 보는 까닭.** Windows 의 스위치(`/c` · `/min`)는 슬래시를
/// 담는다. 슬래시를 같은 무게로 세면 `cmd.exe /c start "" /min "…\node.exe"
/// "…\a.js" /x` 에서 `/x` 가 잡힌다. 역슬래시가 하나도 없을 때만 슬래시를 경로로
/// 본다 — Linux 의 명령줄이 그렇다.
///
/// `first_path` 와 짝이지만 같은 규칙이 아니다. 첫 자리는 실행 파일 자리라 첫
/// 토큰이 곧 경로지만, 마지막 자리에는 플래그가 올 수 있다. 그리고 **경로가 둘 이상
/// 나오면 마지막 것**이다 — `"…\a.js" "…\b.json"` 이면 `…\b.json` 이다. 룰이
/// 원하는 경로가 마지막이라는 것은 룰의 `where` 가 보증해야 한다.
fn last_path(v: &str) -> String {
    let tokens = cmdline_tokens(v);
    let pick = |sep: char| tokens.iter().rev().find(|t| t.contains(sep)).cloned();
    pick('\\').or_else(|| pick('/')).unwrap_or_default()
}

/// 명령줄을 토큰으로 가른다. 따옴표 덩어리는 따옴표를 뗀 한 토큰이다. 닫히지 않은
/// 따옴표는 끝까지를 한 덩어리로 본다 — 남이 만든 문자열이라 짝이 맞는다고
/// 믿지 않는다.
fn cmdline_tokens(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = v.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut tok = String::new();
        if c == '"' {
            chars.next();
            for ch in chars.by_ref() {
                if ch == '"' {
                    break;
                }
                tok.push(ch);
            }
        } else {
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() {
                    break;
                }
                tok.push(ch);
                chars.next();
            }
        }
        out.push(tok);
    }
    out
}

fn split_at_last_sep(v: &str) -> Option<(usize, char)> {
    v.char_indices().rfind(|(_, c)| *c == '\\' || *c == '/')
}

fn dirname(v: &str) -> String {
    let t = trim_quotes(v);
    match split_at_last_sep(t) {
        Some((i, _)) if i > 0 => t[..i].to_string(),
        Some((_, c)) => c.to_string(), // 루트
        None => String::new(),
    }
}

fn basename(v: &str) -> String {
    let t = trim_quotes(v);
    match split_at_last_sep(t) {
        Some((i, c)) => t[i + c.len_utf8()..].to_string(),
        None => t.to_string(),
    }
}

fn trim_quotes(v: &str) -> &str {
    let t = v.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        &t[1..t.len() - 1]
    } else {
        t
    }
}

/// 디코딩 결과 크기 상한. 넘으면 미매치가 아니라 오류다 — 조용히 잘린 값으로
/// 판정하면 무엇을 근거로 지웠는지 설명할 수 없게 된다.
const MAX_DECODED: usize = 1 << 20;

fn hex_decode(v: &str) -> Result<String, ExprError> {
    let s: String = v.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err(ExprError::now("hex_decode: 길이가 홀수입니다"));
    }
    if s.len() / 2 > MAX_DECODED {
        return Err(ExprError::now("hex_decode: 결과가 상한을 넘습니다"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for pair in b.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| ExprError::now("hex_decode: 16진수가 아닙니다"))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| ExprError::now("hex_decode: 16진수가 아닙니다"))?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn base64_decode(v: &str) -> Result<String, ExprError> {
    use base64::Engine;
    let s: String = v.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() / 4 * 3 > MAX_DECODED {
        return Err(ExprError::now("base64_decode: 결과가 상한을 넘습니다"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| ExprError::now(format!("base64_decode: {e}")))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec() -> serde_json::Value {
        json!({
            "command": "C:\\Program Files\\nodejs\\node.exe",
            "args": "\"C:\\Users\\t\\AppData\\Local\\Programs\\app-1\\main.js\" --run",
            "win": { "task": { "register_path": "\\Microsoft\\Windows\\" } },
            "enabled": true,
            "size": 1234
        })
    }

    #[test]
    fn field_navigates_dotted_paths() {
        assert_eq!(
            field(&rec(), "command").unwrap(),
            "C:\\Program Files\\nodejs\\node.exe"
        );
        assert_eq!(
            field(&rec(), "win.task.register_path").unwrap(),
            "\\Microsoft\\Windows\\"
        );
        assert_eq!(field(&rec(), "없는필드"), None);
    }

    #[test]
    fn field_stringifies_non_strings() {
        // 룰의 비교 연산자는 전부 문자열 기반이다.
        assert_eq!(field(&rec(), "enabled").unwrap(), "true");
        assert_eq!(field(&rec(), "size").unwrap(), "1234");
    }

    #[test]
    fn cross_subject_field_is_not_resolved_here() {
        assert!(is_cross_subject("file(command).signature.subject"));
        assert_eq!(field(&rec(), "file(command).signature.subject"), None);
    }

    #[test]
    fn first_path_then_dirname_is_the_evilai_pattern() {
        let b = BTreeMap::new();
        let script = capture("args | first_path", &rec(), &b).unwrap().unwrap();
        assert_eq!(
            script,
            "C:\\Users\\t\\AppData\\Local\\Programs\\app-1\\main.js"
        );

        let mut b2 = BTreeMap::new();
        b2.insert("script_path".to_string(), script);
        let dir = capture("${script_path} | dirname", &rec(), &b2)
            .unwrap()
            .unwrap();
        assert_eq!(dir, "C:\\Users\\t\\AppData\\Local\\Programs\\app-1");
    }

    /// Trend Micro 가 본 EvilAI 의 작업 동작(2025-09 보도). `first_path` 는 `/c` 를
    /// 집는다 — 이 함수가 생긴 까닭이다.
    #[test]
    fn last_path_takes_the_script_out_of_a_cmd_start_wrapper() {
        let args = r#"/c start "" /min "%LOCALAPPDATA%\Programs\nodejs\node.exe" "%LOCALAPPDATA%\TEMP\0b3c-9e1aor.js""#;
        assert_eq!(first_path(args), "/c");
        assert_eq!(last_path(args), r"%LOCALAPPDATA%\TEMP\0b3c-9e1aor.js");
    }

    #[test]
    fn last_path_skips_trailing_flags_and_windows_switches() {
        assert_eq!(last_path(r#""C:\a\main.js" --run"#), r"C:\a\main.js");
        assert_eq!(last_path(r#""C:\a\main.js" /x"#), r"C:\a\main.js");
        assert_eq!(last_path(r"C:\a\main.js --run"), r"C:\a\main.js");
    }

    #[test]
    fn last_path_takes_the_last_of_several_paths() {
        // 룰이 원하는 경로가 마지막임을 보증하는 것은 룰의 `where` 다.
        assert_eq!(last_path(r#""C:\a\x.js" "C:\b\y.json""#), r"C:\b\y.json");
    }

    #[test]
    fn last_path_falls_back_to_slashes_only_without_backslashes() {
        assert_eq!(last_path("/usr/bin/node /opt/x/a.js --run"), "/opt/x/a.js");
        assert_eq!(last_path("--run -v"), "");
        assert_eq!(last_path(""), "");
    }

    #[test]
    fn last_path_tolerates_an_unclosed_quote() {
        assert_eq!(last_path(r#"/c "C:\a\b.js"#), r"C:\a\b.js");
    }

    #[test]
    fn unresolved_reference_is_a_miss_not_an_error() {
        // 부모가 아직 매치되지 않았을 뿐이다. 오류로 만들면 정상 상황이 실패가 된다.
        let b = BTreeMap::new();
        assert_eq!(capture("${nope} | dirname", &rec(), &b).unwrap(), None);
    }

    #[test]
    fn unknown_capture_function_lists_valid_ones() {
        let b = BTreeMap::new();
        let e = capture("args | dirnmae", &rec(), &b).unwrap_err();
        assert!(e.message.contains("dirname"), "유효값을 알려줘야 한다: {e}");
    }

    #[test]
    fn expand_env_is_refused_with_a_reason() {
        // 현재 프로세스 환경을 읽으면 결정성이 깨진다.
        let b = BTreeMap::new();
        let e = capture("args | expand_env", &rec(), &b).unwrap_err();
        assert_eq!(e.available_in, Some(Phase::P4));
    }

    #[test]
    fn path_helpers() {
        assert_eq!(basename("C:\\a\\b\\c.js"), "c.js");
        assert_eq!(dirname("C:\\a\\b\\c.js"), "C:\\a\\b");
        assert_eq!(dirname("\"C:\\a\\b\\c.js\""), "C:\\a\\b");
        assert_eq!(first_path("\"C:\\a b\\c.js\" --x"), "C:\\a b\\c.js");
        assert_eq!(first_path("C:\\a\\c.js --x"), "C:\\a\\c.js");
    }

    #[test]
    fn decoders() {
        assert_eq!(hex_decode("48656c6c6f").unwrap(), "Hello");
        assert!(hex_decode("48656c6c6").is_err(), "홀수 길이");
        assert!(hex_decode("zz").is_err());
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), "Hello");
        assert!(base64_decode("!!!").is_err());
    }

    #[test]
    fn interpolate_needs_every_reference() {
        let mut b = BTreeMap::new();
        b.insert("a.x".to_string(), "1".to_string());
        assert_eq!(interpolate("p/${a.x}/q", &b).unwrap(), "p/1/q");
        assert_eq!(interpolate("p/${a.y}/q", &b), None);
    }

    #[test]
    fn references_are_collected() {
        let mut v = Vec::new();
        references("${task.dir}/x/${task.name}", &mut v);
        assert_eq!(v, vec!["task.dir", "task.name"]);
    }
}
