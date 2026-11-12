//! 레지스트리에서 오는 subject 들 (설계-09 P4).
//!
//! `autorun` · `service` · `av_exclusion` · `proxy_config` · `boot_config` 은
//! **자리가 정해져 있다.** 예약 작업이 `System32\Tasks` 하나인 것과 같다 —
//! 플러그인이 위치를 선언할 이유가 없고, 선언하게 만들면 위치를 틀린 플러그인이
//! 조용히 0건을 보고한다.
//!
//! `registry_value` · `registry_key` 는 반대다. 어느 키를 볼지는 위협마다 다르고
//! 플러그인만 안다. 그래서 **`scan_roots` 에 적힌 레지스트리 경로**만 본다 —
//! 그것이 이 subject 의 상한이다.
//!
//! # `HKU\*`
//!
//! 로그온한 사용자마다 SID 가 다르므로 리터럴로 적을 수 없다. `HKU\*\...` 는
//! 실제 SID 로 펼친다. `_Classes` 로 끝나는 것은 같은 사용자의 클래스 하이브라
//! 두 번 세지 않도록 건너뛴다.

use remedy_artifacts::{
    AutorunRecord, AvExclusionRecord, BootConfigRecord, CollectError, FirewallRuleRecord, Harvest,
    ProxyConfigRecord, RegistryKeyRecord, RegistryValueRecord, Scope, ServiceRecord,
};
use remedy_platform::read::{RegValue, RegistryRead};
use remedy_platform::write::{DEFENDER_EXCLUSIONS, DEFENDER_EXCLUSION_ROOT};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// 로그온·부팅 자동 실행이 등록되는 자리. `(scope, 키)`.
///
/// 실행 순서가 아니라 **관찰 대상 목록**이다. RunOnce 까지 보는 이유는 그것이
/// 한 번 돌고 사라지는 자리라 오히려 은폐에 쓰이기 때문이다.
const AUTORUN_KEYS: [(&str, &str); 6] = [
    (
        "system",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ),
    (
        "system",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ),
    (
        "system",
        "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    ),
    (
        "user",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ),
    (
        "user",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ),
    (
        "system",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    ),
];

/// Winlogon 에서 자동 실행에 해당하는 값 이름. 키 전체를 자동 실행으로 세면
/// 화면 보호기 설정 같은 것까지 섞인다.
const WINLOGON_RUN_VALUES: [&str; 3] = ["Userinit", "Shell", "Taskman"];

const SERVICES_KEY: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services";
// 안전 모드 키 경로는 `remedy_platform::read::SAFEBOOT_KEY` 하나다. 여기에
// 다시 적으면 판정과 상수가 따로 놀 수 있다.

// Defender 제외 목록의 자리는 `remedy_platform::write` 에 하나만 있다. 수집기와
// 쓰기 백엔드가 같은 문자열을 보지 않으면 증거의 `source` 와 Action 의 대상이
// 갈라지고, 그러면 쓰기 경계가 지우려는 것을 찾지 못한다.

/// 방화벽 규칙. **값 하나가 규칙 하나다.**
const FIREWALL_RULES_KEY: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";

const PROXY_KEYS: [(&str, &str); 2] = [
    (
        "user",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    ),
    (
        "system",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    ),
];

/// 알려진 하이브 이름인가. `scan_roots` 에서 레지스트리 경로를 가려내는 데 쓴다.
pub fn is_registry_root(root: &str) -> bool {
    // **전수는 SDK 에 있다.** 여기 따로 적으면 한쪽만 고쳐졌을 때 린트가
    // 통과시킨 루트를 이쪽이 파일 경로로 읽는다.
    remedy_sdk::catalog::is_registry_root(root)
}

fn split_hive(key: &str) -> (String, String) {
    match key.split_once('\\') {
        Some((h, rest)) => (h.to_string(), rest.to_string()),
        None => (key.to_string(), String::new()),
    }
}

/// 레지스트리 루트의 `\*` 를 **직속 하위 키**로 펼친다. 별표가 없으면 그대로 하나다.
///
/// 두 자리에 쓴다.
///
/// - `HKU\*\...` — 사용자 SID 마다 하나. 지정 토큰이다.
/// - `<키>\*` — 하위 키 이름이 **미리 정해지지 않는** 자리. IFEO 가 그렇다
///   (하이재킹당한 실행 파일 이름마다 키가 하나씩 생기고 값은 그 안에 있는데,
///   값 수집은 재귀하지 않는다).
///
/// - `<키>\*\<꼬리>` — 하위 키마다 **같은 이름의 아래 키 하나**. NSSM 이 감싸 띄우는
///   프로그램이 `Services\<이름>\Parameters` 에 있다(2026-11-12). 꼬리는 그대로 붙는다.
///
/// **첫 번째 `\*` 만 펼친다.** 그래서 린트가 한 칸 전체인 별표 하나로 제한한다 —
/// 둘을 쓰면 뒤엣것이 리터럴로 남아 조용히 0건이 된다.
///
/// 펼치지 못하면 **빈 목록**이다. 원본을 그대로 돌려주면 별표가 든 키를
/// 읽으려다 조용히 0건이 되고, 그것은 "그런 것이 없다" 로 읽힌다.
pub fn expand_user_hive<R: RegistryRead>(reg: &R, root: &str) -> Vec<String> {
    let Some(star) = root.find("\\*") else {
        return vec![root.to_string()];
    };
    let head = &root[..star];
    let tail = &root[star + 2..];
    let Ok(sids) = reg.subkeys(head) else {
        return Vec::new();
    };
    // `S-1-5-21-..._Classes` 는 같은 사용자의 클래스 하이브다. 함께 세면
    // 사용자 하나가 둘로 보인다. **그것은 HKU 에서만 참이다** — 다른 하이브의
    // 하위 키가 우연히 그 이름으로 끝난다고 거를 이유가 없다. 2026-09-02 에
    // 레지스트리 루트의 끝 `\*` 를 열면서 이 거르기가 HKU 밖으로 새는 것이
    // 드러났다.
    let user_hive = head
        .split(['\\', '/'])
        .next()
        .is_some_and(|h| h.eq_ignore_ascii_case("HKU") || h.eq_ignore_ascii_case("HKEY_USERS"));
    let mut out: Vec<String> = sids
        .into_iter()
        .filter(|s| !(user_hive && s.ends_with("_Classes")))
        .map(|s| format!("{head}\\{s}{tail}"))
        .collect();
    // **여기서 정렬한다.** 백엔드가 정렬해 주기를 기대하면 그 보장이 백엔드마다
    // 갈리고, 같은 기계를 두 번 수집한 스냅샷이 달라진다.
    out.sort();
    out
}

/// 키가 열리지 않았다. **없는 것인가, 못 읽은 것인가.**
///
/// `denied_dirs` 에 더할 수를 돌려준다 — 정말 없으면 0, 그 밖이면 1.
///
/// # 왜 갈라야 하는가
///
/// `key_exists` 는 여는 데 실패하면 `false` 다 — **없는 것과 막힌 것을 같게
/// 본다.** 그래서 `Deny` 가 걸린 키에서 수집기는 0건을 돌려주고 관측은
/// 깨끗하다고 말한다. 검사 제외 목록을 잠근 기계가 **"제외 없음"** 으로,
/// 자동 실행을 잠근 기계가 **"자동 실행 없음"** 으로 읽힌다.
///
/// 왜인지는 **부모가 안다.** 부모 열거는 자식의 ACL 과 무관하게 이름을 준다
/// (`read::seen` 의 근거). 실측(2026-09-01, Win10 VM): 방화벽 규칙 키에
/// `Deny Everyone ReadKey` 를 걸자 키는 열리지 않았고 부모는 그 이름을 그대로
/// 열거했다.
///
/// **정말 없는 것을 세지 않는 이유**: 그 자리가 없는 것이 정상인 키가 많다
/// (제외를 한 번도 넣지 않은 기계에는 `Exclusions\Paths` 가 아예 없다).
/// 그것까지 세면 멀쩡한 기계가 영원히 관측 불완전이 된다.
/// **`Seen` 을 그대로 돌려준다** (B-9 · 2026-10-27). 전에는 0/1 이었고 그래서
/// 부르는 쪽이 *"못 봤다"* 의 이유를 알 수 없었다 — `scan_roots` 쪽이 그것을
/// 쓰게 되면서 갈래를 잃지 않는 것이 중요해졌다.
pub(crate) fn unreadable_or_absent<R: RegistryRead>(
    reg: &R,
    key: &str,
) -> remedy_platform::read::Seen {
    use remedy_platform::read::Seen;
    let Some((parent, name)) = key.rsplit_once('\\') else {
        // 하이브 이름 자체다. 물을 부모가 없으므로 **모르는 것을 없다로
        // 접지 않는다.**
        return Seen::CannotTell;
    };
    // 부모가 이름을 주지 않으면 `Absent`, 이름은 있는데 열리지 않으면 `Locked`,
    // 부모조차 열거하지 못했으면 `CannotTell`. 뒤의 둘은 **봤어야 할 것을 못
    // 본 것**이다.
    //
    // **조상을 타고 올라가 가르지 않는다** (2026-10-27 에 그 길로 가 봤다).
    // `subkeys` 가 *없는 키*와 *막힌 키*를 한 `Err` 로 접었다면 여기서 부모에게
    // 다시 물어 갈라야 했지만, 백엔드가 [`std::io::ErrorKind`] 로 이미 가른다
    // (`windows.rs::subkeys`) — 없는 키는 빈 목록으로 오므로 이 자리는
    // `Absent` 를 그대로 받는다. 접기를 **답을 아는 자리에서** 푸는 쪽이
    // 호출도 하나로 끝난다.
    remedy_platform::read::seen(reg, parent, name)
}

/// 못 본 것이면 **어느 키였는지와 함께** 센다.
///
/// 위 함수가 0/1 만 돌려주던 동안, 거부가 잡혀도 화면과 산출물에는 개수만
/// 남았다. 레지스트리 쪽은 키 이름이 곧 원인이라 그것을 잃으면 다음 사람이
/// 기계를 뒤져야 하고, 그때는 이미 잠금이 풀려 있을 수 있다 (2026-09-14 에
/// `%ProgramFiles%` 에서 그 일을 겪었다).
fn deny_if_unreadable<R: RegistryRead, T>(h: &mut Harvest<T>, reg: &R, key: &str) {
    if unreadable_or_absent(reg, key) != remedy_platform::read::Seen::Absent {
        h.deny(key);
    }
}
/// 로그온한 **다른** 사용자의 자동 실행 키 — `HKU\<SID>` 아래의 그 사용자 몫.
///
/// `HKCU` 는 엔진을 돌린 계정 하나다. SYSTEM(무인 배포)이나 다른 관리자로 치료하면
/// 감염된 사용자의 Run 값이 보이지 않아 **'치료 완료' 뒤에 남았다** — 2026-11-08 랩
/// 실측(공개 v1.1.3): SYSTEM · 새 관리자 두 경우 다 종료 1 인데 그 값이 남았고, 두
/// 계정 다 `HKU\<감염 사용자 SID>` 에서 그 값을 읽을 수 있었다. 하이브는 그 사용자가
/// 로그온해 있어야 실려 있다 — 로그오프한 사용자의 `NTUSER.DAT` 를 싣지는 않는다
/// (남의 하이브를 싣는 것은 파괴 범위가 다르다).
const USER_AUTORUN_TAILS: [&str; 2] = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
];

/// 자동 실행 항목.
///
/// `own_sid` 는 엔진을 돌린 계정의 SID 다 — 그 하이브는 `HKCU` 로 이미 모았으므로
/// `HKU` 쪽에서 뺀다. 모르면(`None`) `HKU` 쪽을 모으지 않는다: 자기 하이브를 가려낼
/// 수 없으면 한 값이 `HKCU` 와 `HKU\<SID>` 로 두 번 잡혀 두 번 지우려 든다.
pub fn autoruns<R: RegistryRead>(
    reg: &R,
    own_sid: Option<&str>,
) -> Result<Harvest<AutorunRecord>, CollectError> {
    let mut h = Harvest::default();
    let mut keys: Vec<(&str, String)> = AUTORUN_KEYS
        .iter()
        .map(|(scope, key)| (*scope, key.to_string()))
        .collect();
    if let Some(own) = own_sid {
        for tail in USER_AUTORUN_TAILS {
            for key in expand_user_hive(reg, &format!("HKU\\*\\{tail}")) {
                // 진짜 사용자 계정만 — `%ALLUSERPROFILES%` 와 같은 선이다.
                let sid = key.split('\\').nth(1).unwrap_or_default();
                if sid.starts_with("S-1-5-21-") && !sid.eq_ignore_ascii_case(own) {
                    keys.push(("user", key));
                }
            }
        }
    }
    for (scope, key) in keys {
        let key = key.as_str();
        if !reg.key_exists(key) {
            // 없는 키는 정상이다(그 Windows 판에 그 자리가 없을 수 있다).
            // **다만 잠긴 키도 여기로 온다** — 부모에게 물어 갈라야 자동 실행을
            // 잠근 기계가 "자동 실행 없음" 으로 읽히지 않는다.
            deny_if_unreadable(&mut h, reg, key);
            continue;
        }
        let values = reg
            .values(key)
            .map_err(|e| CollectError::Other(e.to_string()))?;
        let winlogon = key.ends_with("\\Winlogon");
        for (name, v) in values {
            if winlogon
                && !WINLOGON_RUN_VALUES
                    .iter()
                    .any(|w| w.eq_ignore_ascii_case(&name))
            {
                continue;
            }
            h.records.push(AutorunRecord {
                id: format!("{key}\\{name}"),
                scope: scope.to_string(),
                name,
                command: v.as_text(),
                source: key.to_string(),
            });
        }
    }
    h.records.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(h)
}

/// 서비스.
pub fn services<R: RegistryRead>(reg: &R) -> Result<Harvest<ServiceRecord>, CollectError> {
    let mut h = Harvest::default();
    if !reg.key_exists(SERVICES_KEY) {
        // 이 키는 어느 Windows 에나 있다. 없다면 못 읽은 것이고, 그것을
        // "서비스 없음" 으로 보고하면 그 위에서 "위협 없음" 이 결론난다.
        //
        // **여기서는 `read::seen` 을 묻지 않는다.** 방화벽 쪽과 다른 이유는
        // 하나다 — 저기서는 "정말 없다" 가 정상일 수 있어서 갈라야 하지만,
        // 여기서는 없든 잠겼든 모르든 **셋 다 세야 한다.** 세 갈래가 한
        // 동작으로 모이면 갈라 묻는 것은 잡음이다.
        h.deny(SERVICES_KEY);
        return Ok(h);
    }
    let names = reg
        .subkeys(SERVICES_KEY)
        .map_err(|e| CollectError::Other(e.to_string()))?;
    for name in names {
        let key = format!("{SERVICES_KEY}\\{name}");
        let values = match reg.values(&key) {
            Ok(v) => v,
            Err(_) => {
                // **조용히 넘기지 않는다.** 부모는 이름을 줬는데 값을 못
                // 읽었다 — 자기 키에 `Deny` 를 건 서비스는 여기서 목록에서
                // 사라지고, 관측은 깨끗하다고 말했다. 방화벽 키에서 고친 것과
                // 같은 결함이 서비스 하나 단위로 남아 있었다.
                //
                // 다만 **사라진 것과 막힌 것을 가른다.** 열거와 읽기 사이에
                // 서비스가 지워질 수 있고(설치 제거), 그 경쟁까지 세면 하필
                // 그 순간에 훑은 실행이 관측 불완전이 된다. 여기가 `read::seen`
                // 이 실제로 세 갈래를 가르는 자리다.
                match remedy_platform::read::seen(reg, SERVICES_KEY, &name) {
                    // 그 사이에 사라졌다. 못 본 것이 아니라 없어진 것이다.
                    remedy_platform::read::Seen::Absent => {}
                    // 막혔거나(Locked), 이제는 부모조차 못 읽는다(CannotTell).
                    _ => h.deny(format!("{SERVICES_KEY}\\{name}")),
                }
                continue;
            }
        };
        let get = |want: &str| {
            values
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(want))
                .map(|(_, v)| v.clone())
        };
        // `Type` 이 없으면 서비스 키가 아니다(설정만 있는 하위 키가 섞인다).
        if get("Type").is_none() && get("ImagePath").is_none() {
            continue;
        }
        // **표시 이름을 담는다.** 여기가 `name: name.clone()` 이라 `id` 의
        // 복사본이었다 — 그 필드가 아무 정보도 나르지 않았고, 사람이 실제로
        // 보는 이름(서비스 관리자·작업 관리자가 보이는 것)은 버려졌다.
        //
        // 2026-09-04 실기기 픽스처로 옮기며 드러났다. `service-userinit` 의
        // 위협 설명이 *"표시 이름 Host Cache Service"* 라 적는데 스냅샷에는
        // 그 문자열이 한 군데도 없었다. 작성자가 보고서를 그대로 옮겨
        // 이름으로 짚으면 **조용히 0건**이 된다.
        //
        // # `@` 로 시작하는 것은 담지 않는다
        //
        // OS 서비스의 `DisplayName` 은 대개 간접 문자열이다
        // (`@%SystemRoot%\System32\dnsapi.dll,-101`). 사람이 보는 "DNS Client"
        // 로 펴려면 `RegLoadMUIString` 이 필요하고 그것은 unsafe 다. 그 원문을
        // 그대로 담으면 룰 작성자가 읽을 수 없는 값이 되므로, 그때는 키 이름을
        // 쓴다 — 서비스 관리자의 "서비스 이름" 칸이 보여 주는 바로 그 값이다.
        //
        // 공격자가 붙이는 표시 이름은 리터럴이라 이 갈림에서 남는 쪽이다.
        let display = get("DisplayName")
            .map(|v| v.as_text())
            .filter(|s| !s.is_empty() && !s.starts_with('@'))
            .unwrap_or_else(|| name.clone());
        h.records.push(ServiceRecord {
            id: name.clone(),
            name: display,
            // **실행 여부는 레지스트리에 없다.** 없는 것을 "정지" 로 적으면
            // 돌고 있는 악성 서비스가 멈춘 것으로 보고된다.
            state: "unknown".into(),
            start_type: match get("Start") {
                Some(RegValue::Dword(0)) => "boot",
                Some(RegValue::Dword(1)) => "system",
                Some(RegValue::Dword(2)) => "auto",
                Some(RegValue::Dword(3)) => "manual",
                Some(RegValue::Dword(4)) => "disabled",
                _ => "unknown",
            }
            .into(),
            image_path: get("ImagePath").map(|v| v.as_text()).unwrap_or_default(),
        });
    }
    h.records.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(h)
}

/// 보안 제품의 검사 제외 항목.
///
/// **값 이름이 제외 대상이다.** 값 내용은 표식일 뿐이라 `data` 를 보면 아무것도
/// 없다 — 그것을 모르고 값 쪽을 읽으면 제외 목록이 통째로 빈 것으로 나온다.
pub fn av_exclusions<R: RegistryRead>(reg: &R) -> Result<Harvest<AvExclusionRecord>, CollectError> {
    let mut h = Harvest::default();
    for (kind, leaf) in DEFENDER_EXCLUSIONS {
        let key = format!("{DEFENDER_EXCLUSION_ROOT}\\{leaf}");
        if !reg.key_exists(&key) {
            // **검사 제외는 잠기기 쉬운 자리다** — 변조 방지가 켜진 Defender
            // 에서도, 제외를 심어 놓고 키를 잠근 검체에서도 그렇다. 갈라 묻지
            // 않으면 그런 기계가 "제외 없음" 으로 읽히고, 그 위에서
            // `av.restore_exclusions` 는 되돌릴 것이 없다고 말한다.
            deny_if_unreadable(&mut h, reg, &key);
            continue;
        }
        let values = reg
            .values(&key)
            .map_err(|e| CollectError::Other(e.to_string()))?;
        for (name, _) in values {
            h.records.push(AvExclusionRecord {
                kind: kind.to_string(),
                value: name,
                source: key.clone(),
            });
        }
    }
    h.records
        .sort_by(|a, b| (&a.kind, &a.value).cmp(&(&b.kind, &b.value)));
    Ok(h)
}

/// 프록시 설정.
pub fn proxy_configs<R: RegistryRead>(reg: &R) -> Result<Harvest<ProxyConfigRecord>, CollectError> {
    let mut h = Harvest::default();
    for (scope, key) in PROXY_KEYS {
        if !reg.key_exists(key) {
            deny_if_unreadable(&mut h, reg, key);
            continue;
        }
        let values = reg
            .values(key)
            .map_err(|e| CollectError::Other(e.to_string()))?;
        let get = |want: &str| {
            values
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(want))
                .map(|(_, v)| v.as_text())
                .unwrap_or_default()
        };
        let rec = ProxyConfigRecord {
            scope: scope.to_string(),
            server: get("ProxyServer"),
            pac_url: get("AutoConfigURL"),
            bypass: get("ProxyOverride"),
        };
        // 셋 다 비었으면 프록시 설정이 없는 것이다. 빈 레코드를 담으면
        // "프록시가 설정되어 있다" 를 묻는 룰이 전부 걸린다.
        if rec.server.is_empty() && rec.pac_url.is_empty() && rec.bypass.is_empty() {
            continue;
        }
        h.records.push(rec);
    }
    Ok(h)
}

/// 방화벽 규칙.
///
/// **값 하나가 규칙 하나다.** 값 이름이 규칙 식별자이고, 내용은
/// `v2.33|Action=Allow|Dir=In|App=...|` 형태의 `|` 로 이어 붙인 목록이다.
/// 실기기 Windows 11 에서 값 812건을 직접 읽어 형식을 확인했다.
///
/// `netsh` 를 부르지 않는 이유는 프로세스를 띄우지 않기 위해서이기도 하지만,
/// **출력이 로캘에 따라 달라지기** 때문이다. 한국어 Windows 에서 `사용: 예` 를
/// 파싱하는 코드는 영어 Windows 에서 조용히 아무것도 못 읽는다.
pub fn firewall_rules<R: RegistryRead>(
    reg: &R,
) -> Result<Harvest<FirewallRuleRecord>, CollectError> {
    let mut h = Harvest::default();
    if !reg.key_exists(FIREWALL_RULES_KEY) {
        // **못 열었다. 그것이 "없다" 라는 뜻은 아니다.** 갈라 묻는 근거는
        // `unreadable_or_absent` 에 있다.
        //
        // 이 자리가 그 판단을 처음 요구했다. 실측(2026-09-01, Win10 VM):
        // 이 키에 `Deny Everyone ReadKey` 를 걸자 키는 열리지 않았고 부모는
        // `FirewallRules` 를 그대로 열거했다. 되돌린 뒤 값 508건이 다시
        // 읽혔다(`netsh` 도 508건). 방화벽을 무력화한 기계가 그 전까지
        // **"방화벽 규칙 없음"** 으로 읽혔다.
        //
        // **부모를 먼저 묻지 않는 이유**: 키가 읽히면 그냥 읽는다. 부모 열거만
        // 막힌 기계에서 읽을 수 있는 규칙을 포기할 이유가 없다.
        deny_if_unreadable(&mut h, reg, FIREWALL_RULES_KEY);
        return Ok(h);
    }
    let values = reg
        .values(FIREWALL_RULES_KEY)
        .map_err(|e| CollectError::Other(e.to_string()))?;
    for (name, v) in values {
        h.records
            .push(parse_firewall_rule(&name, &v.as_text(), FIREWALL_RULES_KEY));
    }
    h.records.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(h)
}

/// `v2.33|Action=Allow|Dir=In|...|` 한 줄을 레코드로.
///
/// 두 가지를 조심한다.
///
/// - **같은 키가 여러 번 나온다.** 실기기에서 `Profile` 이 규칙 812개에 845번
///   나왔다 — 한 규칙이 여러 프로파일에 걸린 것이다. 덮어쓰면 마지막 것만 남아
///   "Public 전용" 인 규칙과 "Domain·Public" 인 규칙을 구분할 수 없다.
/// - **값 안에 `|` 가 들어갈 수 있다.** 그런 조각은 `=` 가 없으므로, 버리지 않고
///   앞 키의 값에 `|` 와 함께 되붙인다. 버리면 경로가 조용히 잘리고, 잘린 경로를
///   보는 룰은 맞지 않는다.
fn parse_firewall_rule(id: &str, raw: &str, source: &str) -> FirewallRuleRecord {
    let mut fields: Vec<(String, String)> = Vec::new();
    for part in raw.split('|') {
        if part.is_empty() {
            continue;
        }
        match part.split_once('=') {
            Some((k, v)) => fields.push((k.to_ascii_lowercase(), v.to_string())),
            // 앞머리의 버전 토큰(`v2.33`)에는 되붙일 곳이 없다. 그냥 넘긴다.
            None => {
                if let Some(last) = fields.last_mut() {
                    last.1.push('|');
                    last.1.push_str(part);
                }
            }
        }
    }
    let get = |want: &str| -> String {
        let hits: Vec<&str> = fields
            .iter()
            .filter(|(k, _)| k == want)
            .map(|(_, v)| v.as_str())
            .collect();
        hits.join(",")
    };
    // 원격 주소는 IPv4·IPv6 가 따로 적힌다. 룰이 둘을 나눠 물을 이유가 없다.
    let remote_address = [get("ra4"), get("ra6")]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    FirewallRuleRecord {
        id: id.to_string(),
        name: get("name"),
        direction: get("dir"),
        action: get("action"),
        // 적히지 않았으면 켜진 것으로 본다 — Windows 는 기본값을 적지 않는다.
        enabled: !get("active").eq_ignore_ascii_case("false"),
        protocol: get("protocol"),
        local_port: get("lport"),
        remote_port: get("rport"),
        remote_address,
        application: get("app"),
        service: get("svc"),
        profile: get("profile"),
        source: source.to_string(),
    }
}

/// 부팅 구성.
///
/// **안전 모드로 들어갈 수 있는가**가 설계-03 의 선행 점검이다. 악성코드가
/// `SafeBoot` 키를 지워 안전 모드 진입을 막는 것은 오래된 수법이고, 그것을
/// 모른 채 "안전 모드에서 다시 시도하세요" 라고 안내하면 부팅 불가로 이어진다.
pub fn boot_configs<R: RegistryRead>(reg: &R) -> Result<Harvest<BootConfigRecord>, CollectError> {
    // **판정은 `remedy-platform` 에 있다.** 실행기도 재시작을 제안하기 전에
    // 같은 것을 묻는데, `remedy-apply` 는 `remedy-collect` 를 의존할 수 없다
    // (설계-04 §1). 양쪽에 적으면 갈라진다.
    let h_ = remedy_platform::read::boot_health(reg);
    let mut h = Harvest::default();
    h.records.push(BootConfigRecord {
        entry: "{current}".into(),
        // BCD 는 레지스트리 하이브지만 마운트되어 있지 않다. 읽지 못한 것을
        // "꺼져 있다" 로 적으면 안 되므로 모른다고 말한다.
        recoveryenabled: match h_.recovery_enabled {
            Some(true) => "yes".into(),
            Some(false) => "no".into(),
            None => "unknown".into(),
        },
        safeboot_available: h_.safeboot.id().into(),
    });
    Ok(h)
}

/// 레지스트리 값과 그중 이진 값의 바이트.
///
/// 키는 `sha256:<16진>` 이고 그것이 레코드의 `data` 에 들어간다.
pub type RegistryValues = (Harvest<RegistryValueRecord>, BTreeMap<String, Vec<u8>>);

/// 이진 레지스트리 값 하나를 스냅샷에 담는 상한.
///
/// 넘으면 담지 않고 크기만 적는다. 상한이 없으면 큰 이진 값 하나가 스냅샷을
/// 통째로 삼킨다 — 실측으로 `HKLM\SOFTWARE` 아래에는 메가바이트급 값이 흔하다.
const MAX_BINARY_BYTES: usize = 256 * 1024;

/// 선언된 레지스트리 루트 아래의 값 전부.
///
/// 두 번째 반환값은 **이진 값의 바이트**다. 키는 `sha256:<16진>` 이고 그것이
/// 레코드의 `data` 에 들어간다 — 그래야 `yara` 를 이진 레지스트리 값에 걸 수
/// 있다 (설계-09 P4 "YARA 가 파일·레지스트리 값·설정 라인에서 동작").
/// 16진 문자열로 풀어 적으면 룰이 훑을 것은 바이트가 아니라 그 표기가 된다.
pub fn registry_values<R: RegistryRead>(
    reg: &R,
    scope: &Scope,
) -> Result<RegistryValues, CollectError> {
    let mut h = Harvest::default();
    let mut blobs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for root in registry_roots(reg, scope) {
        if h.records.len() >= scope.max_files {
            h.truncated = true;
            break;
        }
        if !reg.key_exists(&root) {
            // **작성자가 상한에 적은 키다.** 없는 것은 정상이지만(그 제품이
            // 설치되지 않았다) 잠긴 것은 다르다 — 갈라 묻지 않으면 그 키를
            // 잠근 기계가 "값 없음" 으로 읽힌다.
            deny_if_unreadable(&mut h, reg, &root);
            continue;
        }
        let (hive, key) = split_hive(&root);
        let values = reg
            .values(&root)
            .map_err(|e| CollectError::Other(e.to_string()))?;
        for (name, v) in values {
            let data = match v.bytes() {
                Some(b) if b.len() <= MAX_BINARY_BYTES => {
                    let k = format!("sha256:{:x}", Sha256::digest(b));
                    blobs.entry(k.clone()).or_insert_with(|| b.to_vec());
                    k
                }
                // 상한을 넘은 이진 값. **크기를 적어 둔다** — 빈 문자열로 두면
                // "값이 없다" 로 읽힌다. 평가기가 이 표기를 알아보고 YARA 를
                // "재지 못했다" 로 친다 — 같은 함수로 만들어야 둘이 어긋나지 않는다.
                Some(b) => remedy_sdk::artifact::binary_placeholder(b.len(), true),
                None => v.as_text(),
            };
            h.records.push(RegistryValueRecord {
                hive: hive.clone(),
                key: key.clone(),
                name,
                r#type: v.type_name().to_string(),
                data,
            });
        }
    }
    h.records
        .sort_by(|a, b| (&a.hive, &a.key, &a.name).cmp(&(&b.hive, &b.key, &b.name)));
    Ok((h, blobs))
}

/// 선언된 레지스트리 루트 자체.
pub fn registry_keys<R: RegistryRead>(
    reg: &R,
    scope: &Scope,
) -> Result<Harvest<RegistryKeyRecord>, CollectError> {
    let mut h = Harvest::default();
    for root in registry_roots(reg, scope) {
        if !reg.key_exists(&root) {
            deny_if_unreadable(&mut h, reg, &root);
            continue;
        }
        let (hive, key) = split_hive(&root);
        h.records.push(RegistryKeyRecord {
            hive,
            key,
            subkeys: reg.subkeys(&root).unwrap_or_default(),
            values: reg
                .values(&root)
                .unwrap_or_default()
                .into_iter()
                .map(|(n, _)| n)
                .collect(),
        });
    }
    h.records
        .sort_by(|a, b| (&a.hive, &a.key).cmp(&(&b.hive, &b.key)));
    Ok(h)
}

/// `scan_roots` 중 레지스트리인 것. 한 칸 전체인 `\*` 가 직속 하위 키로 펼쳐진다
/// (끝이면 하위 키 자체, 가운데면 하위 키마다 꼬리를 붙인 키).
fn registry_roots<R: RegistryRead>(reg: &R, scope: &Scope) -> Vec<String> {
    let mut out: Vec<String> = scope
        .scan_roots
        .iter()
        .filter(|r| is_registry_root(r))
        .flat_map(|r| expand_user_hive(reg, r))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_platform::PlatformError;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeReg {
        keys: BTreeMap<String, Vec<(String, RegValue)>>,
        subs: BTreeMap<String, Vec<String>>,
        /// 열거가 거부되는 키. **비어 있는 것과 다르다** — 빈 목록은 "봤는데
        /// 없다" 이고, 거부는 "보지 못했다" 다.
        denied: std::collections::BTreeSet<String>,
        /// 값 읽기가 거부되는 키. 부모는 이름을 주는데 이것은 열리지 않는다.
        denied_values: std::collections::BTreeSet<String>,
        /// **첫 열거에만 나오고 사라지는 이름.** 열거와 읽기 사이에 서비스가
        /// 지워지는 경쟁을 흉내 낸다 — 그것을 거부로 세면 안 된다.
        vanishing: BTreeMap<String, Vec<String>>,
        enumerated: std::cell::Cell<bool>,
    }

    impl FakeReg {
        /// 이 키의 **값 읽기가 거부된다**. 이름은 부모가 주는데 열리지 않는다.
        fn deny_values(mut self, k: &str) -> Self {
            self.denied_values.insert(k.to_string());
            self
        }
        /// `k` 를 **첫 열거에만** 넣는다. 두 번째부터는 사라진다.
        fn vanishing(mut self, k: &str, names: &[&str]) -> Self {
            self.vanishing
                .insert(k.to_string(), names.iter().map(|s| s.to_string()).collect());
            self
        }
        /// 이 키의 **하위 열거가 거부된다**. 없는 것과 다르다.
        fn deny_enum(mut self, k: &str) -> Self {
            self.denied.insert(k.to_string());
            self
        }
        fn key(mut self, k: &str, vals: &[(&str, RegValue)]) -> Self {
            self.keys.insert(
                k.to_string(),
                vals.iter()
                    .map(|(n, v)| (n.to_string(), v.clone()))
                    .collect(),
            );
            self
        }
        fn sub(mut self, k: &str, names: &[&str]) -> Self {
            self.subs
                .insert(k.to_string(), names.iter().map(|s| s.to_string()).collect());
            self
        }
    }

    impl RegistryRead for FakeReg {
        fn value(&self, key: &str, name: &str) -> Result<Option<RegValue>, PlatformError> {
            Ok(self
                .keys
                .get(key)
                .and_then(|v| v.iter().find(|(n, _)| n == name))
                .map(|(_, v)| v.clone()))
        }
        fn subkeys(&self, key: &str) -> Result<Vec<String>, PlatformError> {
            if self.denied.contains(key) {
                return Err(PlatformError::Unsupported("열거 거부"));
            }
            let mut out = self.subs.get(key).cloned().unwrap_or_default();
            // 첫 열거에만 붙는다. `seen` 이 뒤이어 물으면 이미 없다.
            if !self.enumerated.replace(true) {
                if let Some(extra) = self.vanishing.get(key) {
                    out.extend(extra.iter().cloned());
                }
            }
            Ok(out)
        }
        fn values(&self, key: &str) -> Result<Vec<(String, RegValue)>, PlatformError> {
            if self.denied_values.contains(key) {
                return Err(PlatformError::Unsupported("값 읽기 거부"));
            }
            Ok(self.keys.get(key).cloned().unwrap_or_default())
        }
        fn key_exists(&self, key: &str) -> bool {
            self.keys.contains_key(key) || self.subs.contains_key(key)
        }
    }

    /// 규칙 키의 **부모**와 그 이름. 본문은 일반 분리(`rsplit_once`)를 쓰므로
    /// 이 둘은 시험이 세 갈래를 짜맞출 때만 필요하다.
    const FIREWALL_POLICY_KEY: &str =
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";
    const FIREWALL_RULES_NAME: &str = "FirewallRules";

    fn scope(roots: &[&str]) -> Scope {
        Scope::diagnostic(
            roots.iter().map(|s| s.to_string()).collect(),
            remedy_sdk::catalog::Platform::Windows,
        )
    }

    #[test]
    fn winlogon_only_yields_the_values_that_actually_run() {
        // 키 전체를 자동 실행으로 세면 화면 보호기 설정까지 섞인다.
        let reg = FakeReg::default().key(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            &[
                (
                    "Userinit",
                    RegValue::Str("c:\\windows\\system32\\userinit.exe,".into()),
                ),
                ("ScreenSaverGracePeriod", RegValue::Str("5".into())),
            ],
        );
        let h = autoruns(&reg, None).unwrap();
        assert_eq!(h.records.len(), 1, "{:?}", h.records);
        assert_eq!(h.records[0].name, "Userinit");
    }

    /// SYSTEM 이나 다른 관리자로 돌려도 **로그온한 다른 사용자의 Run 값**이 보인다
    /// (코어 1.2.0 · 2026-11-08 랩 실측이 그 값이 '치료 완료' 뒤에 남는 것을 보였다).
    /// 자기 하이브는 `HKCU` 로 이미 모았으므로 `HKU` 쪽에서 빼고, 클래스 하이브와
    /// 시스템 계정은 보지 않는다.
    #[test]
    fn other_logged_on_users_run_values_are_collected_without_doubling_our_own() {
        let me = "S-1-5-21-1-2-3-1001";
        let other = "S-1-5-21-1-2-3-1002";
        let run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        let val = |c: &str| vec![("Updater", RegValue::Str(c.into()))];
        let reg = FakeReg::default()
            .sub(
                "HKU",
                &[
                    me,
                    other,
                    &format!("{other}_Classes"),
                    "S-1-5-18",
                    ".DEFAULT",
                ],
            )
            .key(&format!("HKCU\\{run}"), &val("mine.exe"))
            .key(&format!("HKU\\{me}\\{run}"), &val("mine.exe"))
            .key(&format!("HKU\\{other}\\{run}"), &val("theirs.exe"))
            .key(&format!("HKU\\S-1-5-18\\{run}"), &val("system.exe"));

        let h = autoruns(&reg, Some(me)).unwrap();
        let ids: Vec<&str> = h.records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                format!("HKCU\\{run}\\Updater").as_str(),
                format!("HKU\\{other}\\{run}\\Updater").as_str(),
            ],
        );
        assert!(h.records.iter().all(|r| r.scope == "user"));

        // 자기 SID 를 모르면 `HKU` 쪽을 모으지 않는다 — 두 번 지우려 들지 않게.
        let h = autoruns(&reg, None).unwrap();
        assert_eq!(h.records.len(), 1, "{:?}", h.records);
    }

    #[test]
    fn a_missing_services_key_is_counted_as_unseen() {
        // 이 키는 어느 Windows 에나 있다. 없으면 못 읽은 것이고, 그것을
        // "서비스 없음" 으로 보고하면 그 위에서 "위협 없음" 이 결론난다.
        let h = services(&FakeReg::default()).unwrap();
        assert!(h.records.is_empty());
        assert_eq!(h.denied_dirs, 1, "못 본 것을 세지 않았다");
    }

    #[test]
    fn service_start_type_is_named_not_numbered() {
        let reg = FakeReg::default().sub(SERVICES_KEY, &["Evil"]).key(
            &format!("{SERVICES_KEY}\\Evil"),
            &[
                ("Start", RegValue::Dword(2)),
                ("Type", RegValue::Dword(16)),
                ("ImagePath", RegValue::Str("c:\\evil.exe".into())),
            ],
        );
        let h = services(&reg).unwrap();
        assert_eq!(h.records.len(), 1);
        assert_eq!(h.records[0].start_type, "auto");
        // 실행 여부는 레지스트리에 없다. 모르는 것을 "정지" 로 적으면 안 된다.
        assert_eq!(h.records[0].state, "unknown");
    }

    /// **없는 것과 못 읽는 것을 가른다.** 이 판단이 다섯 수집기에 공통이라
    /// 헬퍼 하나로 모았고, 갈래마다 여기서 잰다.
    #[test]
    fn an_unopenable_key_is_absent_only_when_the_parent_says_so() {
        let key = "HKLM\\SOFTWARE\\Vendor\\Thing";
        let parent = "HKLM\\SOFTWARE\\Vendor";

        use remedy_platform::read::Seen;

        // 부모가 이름을 주지 않는다 = 정말 없다.
        let absent = FakeReg::default().sub(parent, &["Other"]);
        assert_eq!(unreadable_or_absent(&absent, key), Seen::Absent);

        // 부모는 이름을 주는데 키가 열리지 않는다 = 잠겼다.
        let locked = FakeReg::default().sub(parent, &["Thing"]);
        assert_eq!(
            unreadable_or_absent(&locked, key),
            Seen::Locked,
            "잠긴 키를 없다고 접었다"
        );

        // 부모조차 열거하지 못한다 = 모른다. **모르는 것을 없다로 접지 않는다.**
        let cannot = FakeReg::default().deny_enum(parent);
        assert_eq!(unreadable_or_absent(&cannot, key), Seen::CannotTell);

        // 하이브 이름 자체다. 물을 부모가 없다.
        assert_eq!(
            unreadable_or_absent(&FakeReg::default(), "HKLM"),
            Seen::CannotTell
        );

        // **조상을 타고 올라가 가른다** (2026-10-27). 실기기에서는 `subkeys` 가
        // 열기 실패를 `Err` 로 주므로 *"부모를 열거하지 못했다"* 가 두 뜻을
        // 담는다 — 부모가 **없어서**와 부모가 **막혀서**. 그 둘을 한쪽으로
        // 접으면 한쪽이 반드시 틀린다. 깊은 자리에서 둘을 함께 잰다.
        let deep = "HKLM\\SOFTWARE\\Vendor\\Agent\\State";

        // 설치되지 않은 제품 — `Vendor` 부터 없어 조상 전부가 열리지 않는다.
        // 열리는 조상(`SOFTWARE`)이 *"그런 이름 없다"* 고 말해 준다.
        // **이것을 `CannotTell` 로 접으면 미설치 기계가 영원히 종료 6 이다.**
        let not_installed = FakeReg::default().sub("HKLM\\SOFTWARE", &["Microsoft"]);
        assert_eq!(
            unreadable_or_absent(&not_installed, deep),
            Seen::Absent,
            "미설치 제품의 깊은 키를 '모른다' 로 접었다 — B-6 가 고친 자리다"
        );

        // 같은 깊이인데 중간 조상에 `Deny` 가 걸렸다. 조상은 이름을 주지만
        // 열리지 않으므로 **아래를 말할 수 없다.**
        let locked_ancestor = FakeReg::default()
            .sub("HKLM\\SOFTWARE", &["Vendor"])
            .deny_enum("HKLM\\SOFTWARE\\Vendor\\Agent");
        assert_eq!(
            unreadable_or_absent(&locked_ancestor, deep),
            Seen::CannotTell,
            "조상이 막혔는데 '없다' 고 단정했다 — 부모 키를 잠그면 점검이 꺼진다"
        );

        // **갈래를 잃지 않는 것이 B-9 에서 중요해졌다** — `scan_roots` 쪽이
        // `Locked` 와 `CannotTell` 을 `missing_roots` 에서 빼내는 데 쓴다.
        // 0/1 로 접으면 그 자리에서 다시 갈라야 한다.
    }

    /// **검사 제외는 잠기기 쉬운 자리다.** 잠긴 목록을 "제외 없음" 으로
    /// 보고하면 그 위에서 `av.restore_exclusions` 가 되돌릴 것이 없다고 말한다.
    #[test]
    fn a_locked_exclusion_list_is_not_an_empty_one() {
        let leaf = DEFENDER_EXCLUSIONS[0].1;
        // 부모는 이름을 주는데 그 키는 열리지 않는다.
        let locked = FakeReg::default().sub(DEFENDER_EXCLUSION_ROOT, &[leaf]);
        let h = av_exclusions(&locked).unwrap();
        assert!(h.records.is_empty());
        assert_eq!(
            h.denied_dirs, 1,
            "잠긴 제외 목록을 못 본 것으로 세지 않았다"
        );

        // 제외를 한 번도 넣지 않은 기계에는 그 키가 아예 없다 — 정상이다.
        let h2 = av_exclusions(&FakeReg::default().sub(DEFENDER_EXCLUSION_ROOT, &[])).unwrap();
        assert_eq!(
            h2.denied_dirs, 0,
            "없는 것까지 세면 멀쩡한 기계가 관측 불완전이 된다"
        );
    }

    /// 상한에 적은 키가 잠겨 있으면 **작성자가 보라고 한 것을 못 본 것**이다.
    #[test]
    fn a_locked_declared_root_is_counted_as_unseen() {
        let root = "HKLM\\SOFTWARE\\Vendor\\Thing";
        let reg = FakeReg::default().sub("HKLM\\SOFTWARE\\Vendor", &["Thing"]);
        let (h, _) = registry_values(&reg, &scope(&[root])).unwrap();
        assert!(h.records.is_empty());
        assert_eq!(h.denied_dirs, 1);

        let hk = registry_keys(&reg, &scope(&[root])).unwrap();
        assert_eq!(hk.denied_dirs, 1);
    }
    #[test]
    fn av_exclusions_come_from_value_names_not_value_data() {
        // 값 내용은 표식(0)일 뿐이다. 그쪽을 읽으면 제외 목록이 통째로 빈다.
        let reg = FakeReg::default().key(
            &format!("{DEFENDER_EXCLUSION_ROOT}\\Paths"),
            &[("C:\\evil", RegValue::Dword(0))],
        );
        let h = av_exclusions(&reg).unwrap();
        assert_eq!(h.records.len(), 1);
        assert_eq!(h.records[0].kind, "path");
        assert_eq!(h.records[0].value, "C:\\evil");
    }

    #[test]
    fn a_user_hive_star_expands_to_real_sids() {
        let reg = FakeReg::default().sub("HKU", &["S-1-5-21-1", "S-1-5-21-1_Classes", "S-1-5-18"]);
        let got = expand_user_hive(&reg, "HKU\\*\\Software\\X");
        assert_eq!(
            got,
            vec![
                "HKU\\S-1-5-18\\Software\\X".to_string(),
                "HKU\\S-1-5-21-1\\Software\\X".to_string(),
            ],
            "_Classes 하이브를 함께 세면 사용자 하나가 둘로 보인다"
        );
    }

    /// **HKU 밖에서도 펼쳐진다.** 값 수집이 재귀하지 않아, 하위 키 이름이
    /// 미리 정해지지 않는 자리(IFEO)는 이것 없이는 도달할 수 없다.
    #[test]
    fn a_trailing_star_expands_to_direct_subkeys_outside_hku() {
        let reg = FakeReg::default().sub("HKLM\\SOFTWARE\\IFEO", &["taskmgr.exe", "chrome.exe"]);
        let got = expand_user_hive(&reg, "HKLM\\SOFTWARE\\IFEO\\*");
        assert_eq!(
            got,
            vec![
                "HKLM\\SOFTWARE\\IFEO\\chrome.exe".to_string(),
                "HKLM\\SOFTWARE\\IFEO\\taskmgr.exe".to_string(),
            ]
        );
    }

    /// `_Classes` 거르기는 **HKU 의 성질**이다. 다른 하이브에서 그 이름으로
    /// 끝나는 하위 키를 거르면 도달할 수 있던 대상이 조용히 사라진다.
    #[test]
    fn the_classes_filter_does_not_leak_outside_hku() {
        let reg = FakeReg::default().sub("HKLM\\SOFTWARE\\IFEO", &["app_Classes", "b.exe"]);
        let got = expand_user_hive(&reg, "HKLM\\SOFTWARE\\IFEO\\*");
        assert_eq!(
            got,
            vec![
                "HKLM\\SOFTWARE\\IFEO\\app_Classes".to_string(),
                "HKLM\\SOFTWARE\\IFEO\\b.exe".to_string(),
            ]
        );
    }

    /// **가운데의 `\*` 도 펼친다** (2026-11-12). 꼬리는 하위 키마다 그대로 붙고, 꼬리
    /// 키가 없는 하위 키는 '없음' 이지 '못 봄' 이 아니다 — 서비스 대부분에는
    /// `Parameters` 가 없다. 이름은 있는데 열리지 않는 꼬리는 여전히 못 본 것이다.
    #[test]
    fn a_middle_star_expands_with_its_tail_and_only_locked_tails_are_unseen() {
        let services = "HKLM\\SYSTEM\\CurrentControlSet\\Services";
        let reg = FakeReg::default()
            .sub(services, &["Spooler", "web-php", "locked"])
            .sub(&format!("{services}\\Spooler"), &[])
            .sub(&format!("{services}\\web-php"), &["Parameters"])
            .sub(&format!("{services}\\locked"), &["Parameters"])
            .key(
                &format!("{services}\\web-php\\Parameters"),
                &[(
                    "Application",
                    RegValue::Str("C:\\tools\\php\\php-cgi.exe".into()),
                )],
            );
        let root = format!("{services}\\*\\Parameters");
        assert_eq!(
            expand_user_hive(&reg, &root),
            vec![
                format!("{services}\\Spooler\\Parameters"),
                format!("{services}\\locked\\Parameters"),
                format!("{services}\\web-php\\Parameters"),
            ]
        );
        let (h, _) = registry_values(&reg, &scope(&[&root])).unwrap();
        assert_eq!(h.records.len(), 1, "{:?}", h.records);
        assert_eq!(
            h.records[0].key,
            "SYSTEM\\CurrentControlSet\\Services\\web-php\\Parameters"
        );
        assert_eq!(h.records[0].name, "Application");
        assert_eq!(
            h.denied_dirs, 1,
            "Parameters 가 없는 서비스를 못 본 것으로 셌거나, 잠긴 것을 놓쳤다"
        );
    }

    #[test]
    fn an_unexpandable_user_hive_yields_nothing_not_the_literal() {
        // 원본을 돌려주면 `HKU\*\...` 라는 없는 키를 읽으려다 조용히 0건이 되고,
        // 그것은 "사용자가 없다" 로 읽힌다.
        let got = expand_user_hive(&FakeReg::default(), "HKU\\*\\Software\\X");
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn registry_subjects_only_look_at_declared_roots() {
        // 어느 키를 볼지는 위협마다 다르고 플러그인만 안다. 선언 밖을 보면
        // 그것은 플러그인이 볼 수 있는 범위의 상한을 넘는 것이다.
        let reg = FakeReg::default()
            .key(
                "HKLM\\SOFTWARE\\Declared",
                &[("A", RegValue::Str("1".into()))],
            )
            .key("HKLM\\SOFTWARE\\Other", &[("B", RegValue::Str("2".into()))]);
        let sc = scope(&["HKLM\\SOFTWARE\\Declared", "c:\\some\\path"]);
        let (h, _) = registry_values(&reg, &sc).unwrap();
        assert_eq!(h.records.len(), 1, "{:?}", h.records);
        assert_eq!(h.records[0].name, "A");
        assert_eq!(h.records[0].hive, "HKLM");
        assert_eq!(h.records[0].key, "SOFTWARE\\Declared");
    }

    #[test]
    fn a_binary_value_becomes_a_blob_so_yara_can_scan_it() {
        // 16진 문자열로 풀어 적으면 룰이 훑을 것은 **바이트가 아니라 그 표기**가
        // 된다. 참조로 두고 바이트를 따로 담아야 `yara` 가 이진 레지스트리 값을
        // 볼 수 있다 (설계-09 P4).
        let reg = FakeReg::default().key(
            "HKLM\\SOFTWARE\\Declared",
            &[("Blob", RegValue::Binary(vec![1, 2, 3]))],
        );
        let (h, blobs) = registry_values(&reg, &scope(&["HKLM\\SOFTWARE\\Declared"])).unwrap();
        assert_eq!(h.records[0].r#type, "REG_BINARY");
        let key = &h.records[0].data;
        assert!(key.starts_with("sha256:"), "{key}");
        assert_eq!(blobs.get(key).map(|b| b.as_slice()), Some(&[1u8, 2, 3][..]));
    }

    #[test]
    fn an_oversized_binary_value_says_so_instead_of_going_in() {
        // 상한이 없으면 큰 이진 값 하나가 스냅샷을 통째로 삼킨다. 빈 문자열로
        // 두면 "값이 없다" 로 읽히므로 크기를 적어 둔다.
        let big = vec![0u8; MAX_BINARY_BYTES + 1];
        let reg = FakeReg::default().key(
            "HKLM\\SOFTWARE\\Declared",
            &[("Blob", RegValue::Binary(big))],
        );
        let (h, blobs) = registry_values(&reg, &scope(&["HKLM\\SOFTWARE\\Declared"])).unwrap();
        assert!(blobs.is_empty());
        assert!(
            h.records[0].data.contains("상한 초과"),
            "{:?}",
            h.records[0]
        );
        // 평가기가 이것을 알아봐야 YARA 가 이 표기를 내용으로 훑지 않는다.
        assert!(
            remedy_sdk::artifact::is_binary_placeholder(&h.records[0].data),
            "{:?}",
            h.records[0]
        );
        assert!(!remedy_sdk::artifact::is_binary_placeholder(
            "echo 상한 초과"
        ));
    }

    #[test]
    fn a_text_value_stays_text_so_rules_can_compare_it() {
        // 텍스트 값까지 참조로 바꾸면 `data contains` 를 쓰는 룰이 전부 깨진다.
        let reg = FakeReg::default().key(
            "HKLM\\SOFTWARE\\Declared",
            &[("Cmd", RegValue::Str("powershell -enc AAAA".into()))],
        );
        let (h, blobs) = registry_values(&reg, &scope(&["HKLM\\SOFTWARE\\Declared"])).unwrap();
        assert_eq!(h.records[0].data, "powershell -enc AAAA");
        assert!(blobs.is_empty());
    }

    #[test]
    fn proxy_with_nothing_set_is_not_a_record() {
        // 빈 레코드를 담으면 "프록시가 설정되어 있다" 를 묻는 룰이 전부 걸린다.
        let reg = FakeReg::default().key(PROXY_KEYS[0].1, &[("ProxyEnable", RegValue::Dword(0))]);
        assert!(proxy_configs(&reg).unwrap().records.is_empty());
    }

    /// 안전 모드 키의 자리. `sub` 로 **열거**를, `key` 로 **열림**을 세운다 —
    /// 판정이 그 둘을 따로 묻기 때문이다 (`remedy_platform::read::seen`).
    fn safeboot(modes: &[&str], openable: &[&str]) -> FakeReg {
        use remedy_platform::read::{SAFEBOOT_KEY, SAFEBOOT_NAME, SAFEBOOT_PARENT};
        let mut reg = FakeReg::default()
            .sub(SAFEBOOT_PARENT, &[SAFEBOOT_NAME])
            .sub(SAFEBOOT_KEY, modes);
        for m in openable {
            reg = reg.key(&format!("{SAFEBOOT_KEY}\\{m}"), &[]);
        }
        reg
    }

    #[test]
    fn safeboot_reports_partial_when_only_one_mode_survives() {
        // 악성코드가 `Minimal` 만 지우는 경우가 있다. "yes" 로 뭉뚱그리면
        // 안전 모드로 안내했다가 부팅 불가로 이어진다.
        let h = boot_configs(&safeboot(&["Network"], &["Network"])).unwrap();
        assert_eq!(h.records[0].safeboot_available, "partial");
        assert_eq!(h.records[0].recoveryenabled, "unknown");
    }

    #[test]
    fn safeboot_that_is_listed_but_locked_is_not_reported_as_gone() {
        // **레코드에 실려 나가는 값이다.** 룰이 이것을 보고 판정하므로
        // (`docs/plugin-guide/10-manifest.md`), 잠긴 것을 "없다" 로 적으면
        // 정책이 잠근 기계가 감염으로 읽힌다.
        let h = boot_configs(&safeboot(&["Minimal", "Network"], &["Network"])).unwrap();
        assert_eq!(h.records[0].safeboot_available, "unreadable");
    }

    #[test]
    fn a_healthy_machine_still_reads_yes() {
        // 열거 기반으로 바꾸면서 정상 경로가 바뀌지 않았음을 잡아 둔다.
        let h = boot_configs(&safeboot(&["Minimal", "Network"], &["Minimal", "Network"])).unwrap();
        assert_eq!(h.records[0].safeboot_available, "yes");
    }

    // ─────────────────────────────────────────── 방화벽 규칙

    /// 실기기 Windows 11 의 `FirewallRules` 에서 그대로 옮긴 값이다.
    /// 손으로 지어낸 문자열로 파서를 시험하면 내가 상상한 형식만 검사된다.
    const REAL_RULE: &str = "v2.33|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|Profile=Public|\
        RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|\
        Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|\
        EmbedCtxt=@FirewallAPI.dll,-32752|";

    #[test]
    fn a_real_rule_parses_into_its_parts() {
        let r = parse_firewall_rule("NETDIS-UPnPHost-Out-TCP", REAL_RULE, "HKLM\\...");
        assert_eq!(r.id, "NETDIS-UPnPHost-Out-TCP");
        assert_eq!(r.direction, "Out");
        assert_eq!(r.action, "Allow");
        assert!(r.enabled);
        assert_eq!(r.protocol, "6");
        assert_eq!(r.remote_port, "2869");
        assert_eq!(r.local_port, "", "적히지 않은 항목은 비어야 한다");
        assert_eq!(r.application, "%SystemRoot%\\system32\\svchost.exe");
        assert_eq!(r.service, "fdphost");
        assert_eq!(r.profile, "Public");
        assert_eq!(r.name, "@FirewallAPI.dll,-32765");
        // IPv4·IPv6 를 나눠 물을 이유가 없다.
        assert_eq!(r.remote_address, "LocalSubnet,LocalSubnet");
    }

    #[test]
    fn a_disabled_rule_is_not_reported_as_enabled() {
        // 꺼진 규칙을 켜진 것으로 읽으면 "차단 규칙이 걸려 있다" 가 거짓이 된다.
        let off = REAL_RULE.replace("Active=TRUE", "Active=FALSE");
        assert!(!parse_firewall_rule("x", &off, "k").enabled);
        // 적히지 않았으면 켜진 것으로 본다 — Windows 는 기본값을 적지 않는다.
        let none = REAL_RULE.replace("Active=TRUE|", "");
        assert!(parse_firewall_rule("x", &none, "k").enabled);
    }

    #[test]
    fn a_repeated_key_keeps_every_value() {
        // **실기기에서 규칙 812개에 `Profile` 이 845번 나왔다.** 덮어쓰면
        // 마지막 것만 남아 "Public 전용" 과 "Domain·Public" 을 구분할 수 없다.
        let two = "v2.33|Action=Block|Dir=In|Profile=Domain|Profile=Public|Name=x|";
        assert_eq!(parse_firewall_rule("x", two, "k").profile, "Domain,Public");
    }

    #[test]
    fn a_pipe_inside_a_value_does_not_truncate_it() {
        // 잘린 경로를 보는 룰은 맞지 않는다. 조각을 버리는 대신 되붙인다.
        let odd = "v2.33|Action=Allow|Dir=In|App=c:\\pipe|weird\\a.exe|Name=x|";
        let r = parse_firewall_rule("x", odd, "k");
        assert_eq!(r.application, "c:\\pipe|weird\\a.exe");
        assert_eq!(r.name, "x", "되붙이기가 뒤 항목까지 삼켰다");
    }

    #[test]
    fn the_collector_reads_one_record_per_value() {
        let reg = FakeReg::default().key(
            FIREWALL_RULES_KEY,
            &[
                ("규칙B", RegValue::Str(REAL_RULE.into())),
                (
                    "규칙A",
                    RegValue::Str("v2.33|Action=Block|Dir=In|Name=a|".into()),
                ),
            ],
        );
        let h = firewall_rules(&reg).expect("수집");
        assert_eq!(h.records.len(), 2);
        // 순서가 실행마다 달라지면 스냅샷이 실행마다 달라진다.
        assert_eq!(h.records[0].id, "규칙A");
        assert_eq!(h.records[0].action, "Block");
        assert_eq!(h.records[0].source, FIREWALL_RULES_KEY);
    }

    /// 자기 키를 잠근 서비스가 **목록에서 조용히 사라지지 않는다.**
    ///
    /// 부모는 이름을 준다. 그런데 값이 읽히지 않는다 — 예전에는 `continue` 로
    /// 넘겨서 그 서비스가 없는 것이 되고 관측은 깨끗했다. 자기 키에 `Deny` 를
    /// 거는 것은 악성코드에게 싼 수단이고(SafeBoot 에서 실측했다), 그러면
    /// 그 서비스는 이 도구에게 보이지 않는다.
    #[test]
    fn a_service_whose_key_we_cannot_read_is_counted_not_skipped() {
        let locked = format!("{SERVICES_KEY}\\잠긴서비스");
        let reg = FakeReg::default()
            .sub(SERVICES_KEY, &["잠긴서비스", "보이는서비스"])
            .deny_values(&locked)
            .key(
                &format!("{SERVICES_KEY}\\보이는서비스"),
                &[
                    ("Type", RegValue::Dword(16)),
                    ("ImagePath", RegValue::Str("C:\\x.exe".into())),
                ],
            );
        let h = services(&reg).expect("수집");
        assert_eq!(h.records.len(), 1, "읽힌 서비스는 그대로 나와야 한다");
        assert_eq!(h.records[0].name, "보이는서비스");
        assert_eq!(h.denied_dirs, 1, "못 읽은 서비스를 없는 것으로 보고했다");
    }

    /// 표시 이름을 담되 **읽을 수 없는 것은 담지 않는다** (설계-09 P12 후속).
    ///
    /// 여기가 `name: id.clone()` 이라 그 필드가 아무 정보도 나르지 않았다.
    /// 사람이 보는 이름은 버려졌고, 보고서를 그대로 옮긴 룰은 조용히 0건이 됐다.
    #[test]
    fn a_service_carries_the_name_a_person_sees() {
        let reg = FakeReg::default()
            .sub(SERVICES_KEY, &["악성", "OS서비스", "이름없음"])
            // 공격자가 붙이는 표시 이름은 리터럴이다 — 이쪽이 남아야 한다.
            .key(
                &format!("{SERVICES_KEY}\\악성"),
                &[
                    ("Type", RegValue::Dword(16)),
                    ("DisplayName", RegValue::Str("Host Cache Service".into())),
                    (
                        "ImagePath",
                        RegValue::Str("C:\\ProgramData\\x\\svc.exe".into()),
                    ),
                ],
            )
            // OS 서비스는 간접 문자열이다. 그대로 담으면 작성자가 읽을 수 없다.
            .key(
                &format!("{SERVICES_KEY}\\OS서비스"),
                &[
                    ("Type", RegValue::Dword(32)),
                    (
                        "DisplayName",
                        RegValue::Str("@%SystemRoot%\\System32\\dnsapi.dll,-101".into()),
                    ),
                    (
                        "ImagePath",
                        RegValue::Str("C:\\Windows\\svchost.exe".into()),
                    ),
                ],
            )
            // 표시 이름이 아예 없는 서비스도 있다.
            .key(
                &format!("{SERVICES_KEY}\\이름없음"),
                &[
                    ("Type", RegValue::Dword(16)),
                    ("ImagePath", RegValue::Str("C:\\y.exe".into())),
                ],
            );
        let h = services(&reg).expect("수집");
        let by = |id: &str| {
            h.records
                .iter()
                .find(|r| r.id == id)
                .expect(id)
                .name
                .clone()
        };
        assert_eq!(
            by("악성"),
            "Host Cache Service",
            "리터럴 표시 이름을 버렸다"
        );
        assert_eq!(by("OS서비스"), "OS서비스", "간접 문자열을 그대로 담았다");
        assert_eq!(by("이름없음"), "이름없음", "표시 이름이 없으면 키 이름이다");
        // `id` 는 언제나 키 이름이다 — 쓰기 경계가 그것으로 서비스를 찾는다.
        for r in &h.records {
            assert!(!r.id.is_empty(), "id 가 비었다: {r:?}");
        }
    }

    /// **사라진 것은 세지 않는다.**
    ///
    /// 열거와 읽기 사이에 서비스가 지워질 수 있다(설치 제거). 그 경쟁까지
    /// 거부로 세면 하필 그 순간에 훑은 실행이 관측 불완전이 되고, 상시로 뜨는
    /// 경고는 경고가 아니게 된다.
    #[test]
    fn a_service_that_vanished_between_listing_and_reading_is_not_a_denial() {
        // 첫 열거에만 나오고, `seen` 이 다시 물을 때는 이미 없다.
        // 지워진 키는 열리지 않으므로 값 읽기도 실패한다 — 그 자리를 재는 것이다.
        let gone = format!("{SERVICES_KEY}\\사라질서비스");
        let reg = FakeReg::default()
            .sub(SERVICES_KEY, &[])
            .vanishing(SERVICES_KEY, &["사라질서비스"])
            .deny_values(&gone);
        let h = services(&reg).expect("수집");
        assert!(h.records.is_empty());
        assert_eq!(h.denied_dirs, 0, "사라진 것을 못 본 것으로 셌다");
    }

    /// 상수 셋이 갈라지지 않는가.
    ///
    /// 전체 경로와 "부모 + 이름" 을 따로 들고 있다. 한쪽만 고치면 부모 열거가
    /// 엉뚱한 자리를 보고, 그러면 **잠긴 키를 없는 키로 읽는다** — 이 함수가
    /// 막으려는 바로 그 상태로 조용히 되돌아간다.
    #[test]
    fn the_parent_and_the_name_still_spell_the_full_key() {
        assert_eq!(
            FIREWALL_RULES_KEY,
            format!("{FIREWALL_POLICY_KEY}\\{FIREWALL_RULES_NAME}")
        );
    }

    /// 부모가 이름을 주는데 키가 열리지 않으면 **거부로 센다.**
    ///
    /// 이것이 이 수집기의 핵심 성질이다. 세지 않으면 방화벽 규칙을 가려 둔
    /// 기계가 "규칙 없음 · 관측 완전" 으로 보고된다.
    #[test]
    fn a_locked_firewall_key_is_counted_as_denied_not_reported_as_empty() {
        // 부모는 이름을 준다. 그러나 그 키 자체는 어디에도 없다 = 열리지 않는다.
        let reg = FakeReg::default().sub(FIREWALL_POLICY_KEY, &[FIREWALL_RULES_NAME]);
        let h = firewall_rules(&reg).expect("수집");
        assert!(h.records.is_empty());
        assert_eq!(h.denied_dirs, 1, "못 본 것을 없는 것으로 보고했다");
        // **어느 키였는지도 남는다** (2026-09-14). 개수만으로는 다음 사람이
        // 기계를 뒤져야 하고, 그때는 이미 잠금이 풀려 있을 수 있다.
        assert_eq!(
            h.denied_paths,
            vec![FIREWALL_RULES_KEY.to_string()],
            "거부된 키 이름이 없다"
        );
    }

    /// 키가 읽히면 **부모 열거가 막혀 있어도 읽는다.**
    ///
    /// 부모를 먼저 묻는 순서로 짜면 이 자리에서 읽을 수 있는 규칙을 포기하게
    /// 된다. 관측 구멍을 세려다 관측을 잃는 것이라 순서가 뒤집혀 있으면 안 된다.
    #[test]
    fn a_readable_key_is_read_even_when_the_parent_cannot_be_enumerated() {
        let reg = FakeReg::default().deny_enum(FIREWALL_POLICY_KEY).key(
            FIREWALL_RULES_KEY,
            &[("규칙A", RegValue::Str(REAL_RULE.into()))],
        );
        let h = firewall_rules(&reg).expect("수집");
        assert_eq!(h.records.len(), 1, "읽을 수 있는 규칙을 포기했다");
        assert_eq!(h.denied_dirs, 0);
    }

    /// 부모조차 열거하지 못하면 **모른다** 이고, 모르는 것은 거부 쪽에 둔다.
    #[test]
    fn a_parent_we_cannot_enumerate_is_counted_too() {
        let reg = FakeReg::default().deny_enum(FIREWALL_POLICY_KEY);
        let h = firewall_rules(&reg).expect("수집");
        assert!(h.records.is_empty());
        assert_eq!(h.denied_dirs, 1, "모르는 것을 '없다' 로 접었다");
    }

    /// 부모가 이름을 주고 키도 열리면 평소대로. **거부는 세지 않는다.**
    #[test]
    fn a_readable_firewall_key_counts_no_denial() {
        let reg = FakeReg::default()
            .sub(FIREWALL_POLICY_KEY, &[FIREWALL_RULES_NAME])
            .key(
                FIREWALL_RULES_KEY,
                &[("규칙A", RegValue::Str(REAL_RULE.into()))],
            );
        let h = firewall_rules(&reg).expect("수집");
        assert_eq!(h.records.len(), 1);
        assert_eq!(h.denied_dirs, 0, "읽었는데 거부로 셌다");
    }

    #[test]
    fn no_firewall_key_is_not_an_error() {
        // 키가 없는 환경(정책으로 지운 서버 등)에서 수집이 통째로 실패하면
        // 나머지 subject 까지 잃는다.
        let reg = FakeReg::default();
        assert!(firewall_rules(&reg).expect("수집").records.is_empty());
    }
}
