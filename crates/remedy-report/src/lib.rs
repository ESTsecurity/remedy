//! 계획 렌더러 · 결과 리포트 · 자립률 집계 (설계-09 P9).
//!
//! # 왜 렌더링이 크레이트로 나오는가
//!
//! CLI 가 문자열을 직접 만들면 **그 문구가 사실상 API 가 된다.** 기계가 읽는
//! 것은 NDJSON 이벤트와 JSON 산출물이고, 사람이 읽는 것은 여기서 만든다.
//! 둘을 한 자리에 두면 문구를 고칠 때마다 파싱하는 쪽이 깨진다 (설계-01 D5).
//!
//! # 부작용을 먼저 말한다
//!
//! 브라우저 확장을 제거하려면 브라우저를 종료해야 하고, 그러면 저장하지 않은
//! 작업이 사라진다. **삭제 목록만 보여주고 이것을 말하지 않으면 승인은 정보에
//! 근거한 것이 아니다.** 그래서 `user_impact` 가 목록보다 앞이다 (설계-01 D5).
#![forbid(unsafe_code)]

use remedy_sdk::artifact::{
    ActionOutcome, DeferredItem, PlanEnvelope, ResultBody, UserImpact, UserImpactKind,
};

/// 크레이트가 링크되었음을 확인하는 표식. P0의 의존 그래프 검증용이다.
pub const CRATE_NAME: &str = "remedy-report";

/// 회사와 제품의 표기 — **한 자리에만** 적는다.
///
/// 고객 화면에 나가는 이름·저작권은 여기서만 나온다. 제품명을 바꾸는 일이
/// 생기면(예: "알약 전용백신") 이 모듈 하나만 고치면 된다. 코드명 `remedy` 는
/// 실행 파일 이름으로만 남고 고객 화면에는 나오지 않는다.
///
/// 표기 규칙은 알약 제품정보 창의 것을 따른다 — `항목 : 값`, 날짜는
/// `2026-09-06 19:05`, 푸터는 `Copyright © … ESTsecurity Corp. All Rights Reserved.`
pub mod brand {
    use remedy_sdk::i18n::{deco, Lang};

    pub const PRODUCT_KO: &str = "ESTsecurity 전용백신";
    pub const PRODUCT_EN: &str = "ESTsecurity Dedicated Cleaner";
    pub const COMPANY: &str = "ESTsecurity";
    pub const COPYRIGHT_YEAR: &str = "2026";

    pub fn product(lang: Lang) -> &'static str {
        lang.t(PRODUCT_KO, PRODUCT_EN)
    }

    /// 알약 제품정보 창의 푸터 문장. ASCII 모드에서는 `(c)`.
    pub fn copyright() -> String {
        format!(
            "Copyright {} {} ESTsecurity Corp. All Rights Reserved.",
            deco().copyright(),
            COPYRIGHT_YEAR
        )
    }
}

/// 배너에 적을 회차 정보. CLI 가 채우고 렌더러가 문장을 만든다.
#[derive(Debug, Clone, Default)]
pub struct Banner<'a> {
    pub core_version: &'a str,
    /// 플러그인 표시명 (`name.ko` / `name.en`). 없으면 줄이 빠진다.
    pub plugin_name: Option<&'a str>,
    pub plugin_id: Option<&'a str>,
    pub plugin_version: Option<&'a str>,
    /// 시작 시각 (UTC, `YYYY-MM-DDTHH:MM:SSZ`).
    pub started_at: &'a str,
    pub hostname: &'a str,
    pub os: &'a str,
}

/// 첫 화면. 알약 제품정보 창처럼 **제품명 + 버전** 한 줄이 먼저 오고, 그 아래
/// 이번 회차가 무엇을 다루는지(플러그인 이름)와 언제·어디서 도는지가 온다.
pub fn render_banner(b: &Banner<'_>, lang: Lang) -> String {
    let d = remedy_sdk::i18n::deco();
    let mut out = String::new();
    out.push_str(d.rule());
    out.push('\n');
    out.push_str(&format!(" {} {}\n", brand::product(lang), b.core_version));
    if let Some(name) = b.plugin_name {
        match (b.plugin_id, b.plugin_version) {
            (Some(id), Some(v)) => out.push_str(&format!(" {name}  ({id} {v})\n")),
            _ => out.push_str(&format!(" {name}\n")),
        }
    }
    out.push_str(d.rule());
    out.push('\n');
    out.push_str(&format!(
        " {} : {}\n",
        pad(lang.t("시작 시각", "Started"), 10),
        pretty_time(b.started_at)
    ));
    if !b.hostname.is_empty() {
        out.push_str(&format!(
            " {} : {} ({})\n",
            pad(lang.t("실행 기계", "Machine"), 10),
            b.hostname,
            b.os
        ));
    }
    out
}

/// `2026-09-06T08:16:06Z` → `2026-09-06 08:16:06 UTC`. 알약이 쓰는 모양이고,
/// 시계가 UTC 라는 사실을 숨기지 않는다 (이 도구는 지역 시각 변환을 하지 않는다).
pub fn pretty_time(rfc3339: &str) -> String {
    match rfc3339.strip_suffix('Z') {
        Some(body) if body.len() == 19 => format!("{} UTC", body.replacen('T', " ", 1)),
        _ => rfc3339.to_string(),
    }
}

/// Op 하나를 고객이 읽는 문장으로.
///
/// **와일드카드가 없다.** Op 이 늘면 컴파일러가 이 표의 빈칸을 잡는다 —
/// `Op::edits_in_place` 와 같은 이유다. 카탈로그 ID(`file.quarantine_only`)는
/// 계획 JSON 과 `--verbose` 에만 나온다.
pub fn op_label(op: remedy_sdk::catalog::Op, lang: Lang) -> &'static str {
    use remedy_sdk::catalog::Op::*;
    match op {
        FileQuarantineOnly => lang.t("파일 격리", "Quarantine file"),
        FileDelete => lang.t("파일 삭제", "Delete file"),
        FileDeleteOnReboot => lang.t("파일 삭제 예약 (다음 부팅)", "Delete file at next boot"),
        FileDeleteStream => lang.t("숨김 데이터 스트림 삭제", "Delete alternate data stream"),
        DirDeleteRecursive => lang.t("폴더 삭제", "Delete folder"),
        ShortcutStripArgs => lang.t("바로가기 인자 제거", "Strip shortcut arguments"),
        RegistryDeleteValue => lang.t("레지스트리 값 삭제", "Delete registry value"),
        RegistryStripValue => lang.t(
            "레지스트리 값에서 항목 제거",
            "Remove entry from registry value",
        ),
        RegistryRestoreDefault => lang.t("레지스트리 값 기본값 복원", "Restore registry default"),
        RegistryDeleteKey => lang.t("레지스트리 키 삭제", "Delete registry key"),
        PersistenceDisable => lang.t("자동 실행 등록 비활성화", "Disable persistence entry"),
        PersistenceDelete => lang.t("자동 실행 등록 삭제", "Delete persistence entry"),
        AutorunRemove => lang.t("시작 프로그램 항목 제거", "Remove autorun entry"),
        // **"설정 파일" 이라 부르지 않는다** (2026-10-27). C-5 가 드롭인 디렉터리
        // 선언으로 소스 파일을 이 Op 의 사거리에 넣은 뒤로, 고객 화면이
        // `index.php` 를 두고 *"설정 파일 줄 제거"* 라고 말하고 있었다 — PHP2Shell
        // 룰의 실측 출력에서 그대로 보였다. 모양은 이웃을 따른다
        // (`레지스트리 값에서 항목 제거` · `PATH 환경 변수에서 항목 제거`).
        TextConfigRemoveLine => lang.t("파일에서 줄 제거", "Remove line from file"),
        StructuredConfigRemoveKey => lang.t("설정 항목 제거", "Remove config entry"),
        StructuredConfigRestoreDefault => lang.t("설정 항목 기본값 복원", "Restore config default"),
        EnvStripPath => lang.t("PATH 환경 변수에서 항목 제거", "Remove entry from PATH"),
        BrowserExtRemove => lang.t("브라우저 확장 제거", "Remove browser extension"),
        ProcessKill => lang.t("프로세스 종료", "Terminate process"),
        ServiceClearRecovery => lang.t("서비스 복구 설정 해제", "Clear service recovery"),
        ServiceStop => lang.t("서비스 중지", "Stop service"),
        ServiceDisable => lang.t("서비스 비활성화", "Disable service"),
        ServiceDelete => lang.t("서비스 삭제", "Delete service"),
        AvRestoreExclusions => lang.t("보안 제품 예외 목록 원복", "Restore AV exclusions"),
        HostsRestoreLine => lang.t("hosts 항목 원복", "Restore hosts entry"),
        ProxyRestore => lang.t("프록시 설정 원복", "Restore proxy setting"),
        FirewallRestoreRule => lang.t("방화벽 규칙 원복", "Restore firewall rule"),
        CertStoreRemove => lang.t("신뢰 인증서 제거", "Remove trusted certificate"),
        BootRestoreDefault => lang.t("부팅 설정 원복", "Restore boot setting"),
    }
}

/// 이 동작이 끝나면 **무엇이 달라지는가.**
///
/// `op_label` 은 하는 일의 이름이고(`시작 프로그램 항목 제거`), 이것은 그 결과다
/// (`부팅할 때 자동으로 실행되지 않게 됩니다`). 계획을 먼저 보이는 설계는 읽는
/// 사람이 **승인할 수 있어야** 뜻이 있는데, 동사만으로는 무엇이 나빠지고 무엇이
/// 좋아지는지 알 수 없다.
///
/// **`op_label` 을 바꾸지 않는 이유**는 그 문구를 하네스와 실기기 채점이 읽기
/// 때문이다. 여기는 계획 화면에만 붙는 별도 줄이다 — 진행 줄은 그대로다.
///
/// 되돌리는 것(`* 원복`)은 "없애는" 것이 아니라 "제자리로 돌리는" 것이라 그렇게
/// 적는다. 사용자가 잃는 것이 없다는 사실이 승인의 근거가 된다.
pub fn op_effect(op: remedy_sdk::catalog::Op, lang: Lang) -> &'static str {
    use remedy_sdk::catalog::Op::*;
    match op {
        // **`금고` 가 아니라 `격리소` 다** (2026-10-28). 같은 자리를 저장소 전체가
        // `격리소` 라 부르는데(31곳) 이 한 줄만 `금고` 였고, 그래서 **한 화면에서
        // 한 개념이 두 이름**으로 불렸다 — Windows 기준선 883줄에서 금고 11 ·
        // 격리소 7. 업계에서 쓰는 말도 격리(quarantine) 쪽이다.
        FileQuarantineOnly => lang.t(
            "파일을 격리소로 옮깁니다. 지우는 것이 아니라 되돌릴 수 있습니다",
            "moves the file into quarantine — not deleted, and reversible",
        ),
        FileDelete => lang.t("파일을 지웁니다", "deletes the file"),
        FileDeleteOnReboot => lang.t(
            "지금은 잠겨 있어 다음 재시작 때 지웁니다",
            "it is locked now, so it is deleted at the next restart",
        ),
        FileDeleteStream => lang.t(
            "파일에 숨어 있던 여분의 데이터를 지웁니다. 파일 자체는 남습니다",
            "removes hidden extra data; the file itself stays",
        ),
        DirDeleteRecursive => lang.t(
            "폴더와 그 안의 것을 통째로 지웁니다",
            "deletes the folder and everything in it",
        ),
        ShortcutStripArgs => lang.t(
            "바로가기에 덧붙은 인자만 뗍니다. 바로가기는 그대로 씁니다",
            "strips the added arguments; the shortcut still works",
        ),
        RegistryDeleteValue => lang.t(
            "레지스트리 값 하나를 지웁니다",
            "deletes one registry value",
        ),
        RegistryStripValue => lang.t(
            "값에 끼어든 항목만 뺍니다. 나머지 항목은 그대로입니다",
            "removes only the injected entry; the rest of the value stays",
        ),
        RegistryRestoreDefault => lang.t(
            "바뀐 설정을 Windows 기본값으로 되돌립니다",
            "puts the changed setting back to the Windows default",
        ),
        RegistryDeleteKey => lang.t(
            "레지스트리 키를 통째로 지웁니다",
            "deletes the whole registry key",
        ),
        PersistenceDisable => lang.t(
            "지우기 전에 먼저 꺼서 그 사이에 다시 실행되지 않게 합니다",
            "turns it off first so it cannot run while being removed",
        ),
        PersistenceDelete => lang.t(
            "예약 실행 등록을 없앱니다. 정해진 때에 자동으로 실행되지 않게 됩니다",
            "removes the scheduled entry so it no longer runs on its own",
        ),
        AutorunRemove => lang.t(
            "부팅할 때 자동으로 실행되지 않게 됩니다",
            "it will no longer start automatically at boot",
        ),
        // 위 이름과 같은 이유로 "설정 파일" 을 빼고 **그 파일**로 적는다. 뜻은
        // 그대로다 — 덧붙은 줄만 빠지고 파일은 남는다.
        TextConfigRemoveLine => lang.t(
            "그 파일에서 덧붙은 줄만 뺍니다. 파일은 지우지 않습니다",
            "removes only the added line from that file; the file itself is kept",
        ),
        StructuredConfigRemoveKey => lang.t(
            "설정에서 그 항목만 뺍니다. 나머지 설정은 그대로입니다",
            "removes just that entry; the rest of the settings stay",
        ),
        StructuredConfigRestoreDefault => lang.t(
            "바뀐 설정 항목을 원래 값으로 되돌립니다",
            "puts the changed entry back to its original value",
        ),
        EnvStripPath => lang.t(
            "PATH 에 끼어든 폴더를 뺍니다. 명령이 그 폴더의 것으로 바꿔치기되지 않게 됩니다",
            "removes the injected folder from PATH so commands are no longer hijacked",
        ),
        BrowserExtRemove => lang.t(
            "브라우저에서 그 확장을 지웁니다. 브라우저를 닫아야 할 수 있습니다",
            "removes that browser extension; the browser may need to be closed",
        ),
        ProcessKill => lang.t(
            "지금 돌고 있는 그 프로그램을 멈춥니다",
            "stops that program while it is running",
        ),
        ServiceClearRecovery => lang.t(
            "서비스가 죽으면 자동으로 되살아나던 설정을 풉니다",
            "clears the setting that revived the service when it died",
        ),
        ServiceStop => lang.t("돌고 있는 서비스를 멈춥니다", "stops the running service"),
        ServiceDisable => lang.t(
            "부팅할 때 그 서비스가 시작되지 않게 합니다",
            "keeps the service from starting at boot",
        ),
        ServiceDelete => lang.t("서비스 등록을 없앱니다", "removes the service registration"),
        AvRestoreExclusions => lang.t(
            "검사에서 빠져 있던 자리를 다시 검사 대상으로 되돌립니다",
            "puts the excluded places back under scanning",
        ),
        HostsRestoreLine => lang.t(
            "주소가 엉뚱한 곳으로 가던 것을 원래대로 되돌립니다",
            "puts the redirected address back",
        ),
        ProxyRestore => lang.t(
            "인터넷 연결이 거쳐 가던 자리를 원래대로 되돌립니다",
            "puts the proxy setting back",
        ),
        FirewallRestoreRule => lang.t(
            "방화벽에 뚫려 있던 구멍을 원래대로 되돌립니다",
            "puts the firewall rule back",
        ),
        CertStoreRemove => lang.t(
            "심어진 인증서를 뺍니다. 그것을 쓰던 통신은 다시 검증을 받습니다",
            "removes the planted certificate so traffic is verified again",
        ),
        BootRestoreDefault => lang.t(
            "바뀐 부팅 설정을 원래대로 되돌립니다",
            "puts the changed boot setting back",
        ),
    }
}

/// 치료가 끝난 뒤의 한 줄 결과. 종료 코드가 말하는 것을 사람의 문장으로.
///
/// # 점검은 다른 낱말을 쓴다 (B-2 · 2026-10-26)
///
/// 같은 종료 코드가 두 가지를 뜻한다. 치료 플러그인의 2 는 *"감염됐다"* 이고
/// 점검 플러그인의 2 는 *"취약하다"* 다 — 고객에게 그 둘은 전혀 다른 일이고,
/// 취약한 서버에 *"위협 발견"* 이라고 말하면 감염된 줄 알고 기계를 내린다.
/// 반대로 0 은 치료에서는 *"깨끗하다"* 이지만 점검에서는 *"그 취약점이 없다"* 다.
///
/// **치료의 문구는 한 글자도 바뀌지 않는다.** `kind` 가 `None` 이면 지금까지와
/// 같은 문자열이다 — 콘솔 기준선 4벌과 하네스가 그 꼴로 돌고 있다.
/// 점검 화면이 한 번에 늘어놓는 항목 수 (2026-10-28).
///
/// **상한이 있는 이유는 결론이 화면 밖으로 밀리지 않게 하는 것**이다 — 작을수록
/// 좋은 수가 아니다. 지금까지 실측한 흔적은 콘솔 기준선 4벌에서 **0~6건**,
/// PHP 점검 룰에서 **2~8건** 이라 **본 적 있는 화면은 전부 안 잘린다.** 넘치는
/// 것은 넓게 쓴 룰이고, 그때도 `--verbose` 가 전부 보인다.
pub const FINDINGS_SHOWN: usize = 10;

/// `target` 에서 문자열 하나를 꺼낸다. 배열이면 첫 칸을 쓴다(`hostnames`).
fn text_at(t: &serde_json::Value, key: &str) -> Option<String> {
    let v = t.get(key)?;
    let s = match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => a.first()?.as_str()?.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => return None,
    };
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn first_of(t: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| text_at(t, k))
}

/// 증거 하나를 **사람이 읽을 이름**으로.
///
/// # 계획기의 `evidence_paths` 와 **다른 함수인 이유**
///
/// 그쪽은 재귀 삭제 가드라 경로를 못 꺼낸 증거를 **일부러 버린다** — *"모르는
/// 것을 아는 척하면 가드가 통과시킨다"*. 화면은 계약이 반대다: **못 꺼내도
/// 적어야 한다.** 가드가 넓어지면 사고지만, 화면이 비면 사용자는 *"취약 1건"*
/// 만 보고 아무것도 할 수 없다 — 그것이 이 함수가 생긴 이유다.
///
/// 어느 필드가 그 subject 의 이름인지는 **카탈로그의 필드 표**가 정한다
/// (`remedy-sdk/src/catalog.rs` 의 `fields()`). 거기 없는 모양이 오면 subject
/// 의 id 로 떨어진다 — 빈 줄보다 낫다.
pub fn evidence_label(subject: remedy_sdk::catalog::Subject, target: &serde_json::Value) -> String {
    use remedy_sdk::catalog::Subject as S;
    let named = match subject {
        S::File | S::Shortcut | S::StructuredConfig => first_of(target, &["path"]),
        // 줄 단위로 보는 것은 **줄 번호까지** 적어야 찾아갈 수 있다.
        S::TextConfig => match (first_of(target, &["path"]), text_at(target, "line_no")) {
            (Some(p), Some(n)) => Some(format!("{p}:{n}")),
            (p, _) => p,
        },
        S::Package | S::Service | S::FirewallRule => first_of(target, &["name"]),
        S::Persistence | S::Autorun => first_of(target, &["name", "id", "command"]),
        S::Process => first_of(target, &["image_path", "cmdline", "pid"]),
        S::Indicator | S::AvExclusion => first_of(target, &["value"]),
        S::RegistryValue => match (first_of(target, &["hive"]), first_of(target, &["key"])) {
            (Some(h), Some(k)) => Some(match first_of(target, &["name"]) {
                Some(n) => format!("{h}\\{k}\\{n}"),
                None => format!("{h}\\{k}"),
            }),
            _ => first_of(target, &["key", "name"]),
        },
        S::RegistryKey => match (first_of(target, &["hive"]), first_of(target, &["key"])) {
            (Some(h), Some(k)) => Some(format!("{h}\\{k}")),
            _ => first_of(target, &["key"]),
        },
        S::BootConfig => first_of(target, &["entry"]),
        S::HostsEntry => first_of(target, &["hostnames", "ip", "line"]),
        S::CertStore => first_of(target, &["subject", "thumbprint", "store"]),
        S::ProxyConfig => first_of(target, &["server", "pac_url", "scope"]),
        S::BrowserExtension => first_of(target, &["name", "ext_id", "path"]),
    };
    named.unwrap_or_else(|| subject.info().id.to_string())
}

/// 점검 결과를 **항목으로** 늘어놓는 줄들 (2026-10-28).
///
/// # 왜 생겼나
///
/// 점검 화면이 `취약 N건` 이라는 **수만** 내고 끝났다. 무엇이 취약한지 —
/// 어느 파일의 어느 값인지 — 는 `scan.json` 에만 있었고 마지막 줄이 사람에게
/// 그 JSON 을 읽으라고 했다. 치료 쪽은 계획을 줄줄이 적는데 **점검만 비어**
/// 있었다.
///
/// # 무엇을 고르나
///
/// **판정이 선 그룹의 증거만** 적는다. 흔적 전부가 아니다 — 제외된 그룹의
/// 증거까지 적으면 *"이것도 취약한가"* 를 사람이 가려야 한다.
///
/// `limit` 을 넘으면 뒤는 `그 외 M건` 한 줄로 접는다. `--verbose` 는
/// `usize::MAX` 를 주어 전부 본다.
pub fn check_findings(
    evidence: &[remedy_sdk::artifact::Evidence],
    groups: &[remedy_sdk::artifact::EvidenceGroup],
    lang: Lang,
    limit: usize,
) -> Vec<String> {
    let mut ids: Vec<&str> = Vec::new();
    for g in groups.iter().filter(|g| g.verdict) {
        for id in &g.evidence {
            if !ids.contains(&id.as_str()) {
                ids.push(id);
            }
        }
    }
    // 그룹이 비어 있는 플러그인도 있다(판정이 증거 하나로 서는 모양). 그때는
    // 흔적을 그대로 쓴다 — 빈 목록보다 낫다.
    let picked: Vec<&remedy_sdk::artifact::Evidence> = if ids.is_empty() {
        evidence.iter().collect()
    } else {
        ids.iter()
            .filter_map(|id| evidence.iter().find(|e| e.id == *id))
            .collect()
    };
    if picked.is_empty() {
        return Vec::new();
    }

    // **같은 것을 두 번 적지 않는다** (2026-10-28 실측에서 더했다). 룰 둘이 같은
    // 레코드를 짚으면 증거가 둘이 되고, 리눅스 화면이 같은 패키지 넷을 **두 번**
    // 늘어놓았다. 사용자가 볼 것은 *"무엇이 취약한가"* 이지 *"룰이 몇 개
    // 맞았는가"* 가 아니다 — 뒤의 수는 윗줄의 `흔적 N건` 이 이미 말한다.
    //
    // 가르는 기준은 **찍히는 줄 그대로**다. 같은 파일이라도 적히는 값이 다르면
    // 다른 줄이므로 남는다.
    let mut bodies: Vec<String> = Vec::new();
    for e in &picked {
        let b = finding_body(e, lang);
        if !bodies.contains(&b) {
            bodies.push(b);
        }
    }

    let mut out = Vec::new();
    for (i, body) in bodies.iter().take(limit).enumerate() {
        out.push(format!("   {}. {body}", i + 1));
    }
    if bodies.len() > limit {
        let rest = bodies.len() - limit;
        out.push(format!(
            "      {}",
            lang.pick(
                format!("그 외 {rest}건 — 전체는 --verbose 로 봅니다"),
                format!("and {rest} more - use --verbose to see them all"),
            )
        ));
    }
    out
}

/// 증거 한 건이 화면에 적히는 **알맹이** — 번호를 뺀 줄.
///
/// 중복을 가르는 기준이기도 하다: 같은 알맹이는 한 번만 적는다.
fn finding_body(e: &remedy_sdk::artifact::Evidence, lang: Lang) -> String {
    let label = evidence_label(e.subject, &e.target);
    // **판정을 가른 값**을 함께 적는다 — 이름만으로는 "왜" 가 없다.
    //
    // # 왜 한 칸만 적나 (2026-10-28 실측에서 고쳤다)
    //
    // 처음에는 맞은 필드를 전부 적었더니 리눅스 화면이
    // `(source php8.1 · upstream_version 8.1.2 · version 8.1.2-1ubuntu2.28)`
    // 로 나왔다 — **엔진 필드 이름 셋**이고 사용자에게 뜻이 없다. 판이 맞은
    // 룰이면 사람이 볼 값은 **판 하나**다. 그 밖의 모양에서만 맞은 필드를
    // 원래 이름으로 적는다(이름에 이미 쓴 필드는 뺀다).
    let in_label = ["path", "name", "key", "hive", "line_no", "entry"];
    let matched_version = e
        .matched
        .iter()
        .any(|m| m.field == "version" || m.field == "upstream_version");
    let why = if matched_version {
        text_at(&e.target, "version")
            .or_else(|| text_at(&e.target, "upstream_version"))
            .map(|v| lang.pick(format!("버전 {v}"), format!("version {v}")))
    } else {
        e.matched
            .iter()
            .filter(|m| !in_label.contains(&m.field.as_str()))
            .find_map(|m| text_at(&e.target, &m.field).map(|v| format!("{} {v}", m.field)))
    };
    match why {
        Some(w) => format!("{label}  ({w})"),
        None => label,
    }
}

pub fn result_line(
    code: remedy_sdk::artifact::ExitCode,
    done: usize,
    lang: Lang,
    kind: Option<remedy_sdk::manifest::PluginKind>,
) -> String {
    use remedy_sdk::artifact::ExitCode as C;
    use remedy_sdk::manifest::PluginKind;
    if kind == Some(PluginKind::Check) {
        // 점검에 **치료가 없다.** 그래서 2 는 "치료하지 않았습니다" 가 아니고,
        // 6 은 "'위협 없음' 을 말할 수 없습니다" 가 아니다. 나머지 코드는
        // 점검에서 나오지 않거나(1·3) 뜻이 같다(4·5·7) — 그대로 떨어진다.
        match (code, lang) {
            (C::NoThreat, Lang::Ko) => return "취약한 곳을 찾지 못했습니다.".to_string(),
            (C::NoThreat, Lang::En) => return "No vulnerability was found.".to_string(),
            // **`위` 라고 쓸 수 있게 됐다** (2026-10-28). 그전에는 이 줄이
            // 화면의 마지막이라 *"근거는 산출 폴더의 scan.json 에 있습니다"* 로
            // 끝났다 — **사람에게 JSON 을 읽으라는 말**이었고, 그 사이에
            // `check_findings` 가 취약한 항목을 바로 위에 적는다.
            (C::FoundNotRemediated, Lang::Ko) => {
                return "취약합니다. 위에 적은 항목을 확인하십시오.".to_string()
            }
            (C::FoundNotRemediated, Lang::En) => {
                return "Vulnerable. Review the items listed above.".to_string()
            }
            (C::IncompleteObservation, Lang::Ko) => {
                return "다 보지 못해 '취약하지 않다' 를 말할 수 없습니다.".to_string()
            }
            (C::IncompleteObservation, Lang::En) => {
                return "Observation incomplete: cannot declare 'not vulnerable'.".to_string()
            }
            _ => {}
        }
    }
    match (code, lang) {
        (C::NoThreat, Lang::Ko) => "위협이 발견되지 않았습니다.".to_string(),
        (C::NoThreat, Lang::En) => "No threat was found.".to_string(),
        // "N건 수행 완료" 는 하네스가 읽는 문구다 — 바꾸지 않는다.
        (C::Remediated, Lang::Ko) => format!("위협 발견, 치료 완료 ({done}건 수행 완료)"),
        (C::Remediated, Lang::En) => format!("Threat found, treated ({done} action(s) done)"),
        (C::FoundNotRemediated, Lang::Ko) => "위협 발견, 치료하지 않았습니다.".to_string(),
        (C::FoundNotRemediated, Lang::En) => "Threat found, not treated.".to_string(),
        (C::PartialFailure, Lang::Ko) => format!("일부 실패 ({done}건 수행 완료)"),
        (C::PartialFailure, Lang::En) => format!("Partial failure ({done} action(s) done)"),
        (C::UsageError, Lang::Ko) => "입력 오류".to_string(),
        (C::UsageError, Lang::En) => "Usage error".to_string(),
        (C::GuardStop, Lang::Ko) => "안전 가드가 중단했습니다.".to_string(),
        (C::GuardStop, Lang::En) => "Stopped by a safety guard.".to_string(),
        (C::IncompleteObservation, Lang::Ko) => {
            "관측이 불완전해 '위협 없음' 을 말할 수 없습니다.".to_string()
        }
        (C::IncompleteObservation, Lang::En) => {
            "Observation incomplete: cannot declare 'no threat'.".to_string()
        }
        // 마무리 표에는 사실상 나오지 않는다 — 패닉 훅이 그 전에 나간다. 그래도
        // 완전 매치를 지켜 새 코드가 조용히 빠지는 일이 없게 한다.
        (C::InternalError, Lang::Ko) => "내부 오류로 멈췄습니다.".to_string(),
        (C::InternalError, Lang::En) => "Stopped by an internal error.".to_string(),
    }
}

/// 대상이 비어 있는 Action 의 자리 표시.
///
/// **계획과 진행이 같은 말을 해야 한다.** 계획은 `프로세스 종료  (실행 중인 것을
/// 찾아서)` 라고 적는데 진행 줄은 빈칸이었다 — 같은 Action 인데 화면에서 달라
/// 보였다 (실측 2026-09-07).
pub fn no_target(lang: Lang) -> &'static str {
    lang.t("(실행 중인 것을 찾아서)", "(matched at run time)")
}

/// 마무리 화면 — 결과 한 줄, 소요 시간, 되돌리는 법, 저작권.
pub struct Closing<'a> {
    pub code: remedy_sdk::artifact::ExitCode,
    pub done: usize,
    pub elapsed_secs: u64,
    pub run_id: Option<&'a str>,
    pub quarantine: Option<&'a str>,
    pub journal: Option<&'a str>,
    /// 점검 플러그인이면 결과 줄이 점검 어휘를 쓴다 ([`result_line`]).
    pub kind: Option<remedy_sdk::manifest::PluginKind>,
    /// 되돌리기 · 신고 안내에 붙일 상태 폴더(따옴표까지 씌운 인자). **기본 자리가 아닐
    /// 때만** 준다 — 메뉴는 받은 폴더의 `state` 에 쓰는데 안내가 그것을 빼면, 그 줄을 그대로
    /// 친 사람은 기본 자리를 찾다 종료 4 로 끝난다(2026-11-07 실측). 기본이면 `None` 이고
    /// 줄은 전과 한 글자도 같다(무인 배포 출력 · 불변식 I1).
    pub state_dir: Option<&'a str>,
}

pub fn render_closing(c: &Closing<'_>, lang: Lang) -> String {
    let d = remedy_sdk::i18n::deco();
    let mut out = String::new();
    out.push_str(d.rule());
    out.push('\n');
    let w = 10;
    out.push_str(&format!(
        " {} : {}\n",
        pad(lang.t("결과", "Result"), w),
        result_line(c.code, c.done, lang, c.kind)
    ));
    out.push_str(&format!(
        " {} : {}\n",
        pad(lang.t("소요 시간", "Elapsed"), w),
        elapsed(c.elapsed_secs, lang)
    ));
    if let Some(q) = c.quarantine {
        out.push_str(&format!(
            " {} : {q}\n",
            pad(lang.t("격리소", "Quarantine"), w)
        ));
    }
    if let Some(j) = c.journal {
        out.push_str(&format!(" {} : {j}\n", pad(lang.t("저널", "Journal"), w)));
    }
    if let Some(run) = c.run_id {
        // "remedy restore --run" 은 시험과 하네스가 읽는 문구다 — 상태 폴더는 그 뒤에 붙인다.
        let at = c
            .state_dir
            .map(|d| format!(" --state-dir {d}"))
            .unwrap_or_default();
        out.push_str(&format!(
            " {} : remedy restore --run {run}{at}\n",
            pad(lang.t("되돌리려면", "To undo"), w)
        ));
        out.push_str(&format!(
            " {} : remedy support-bundle --run {run}{at}\n",
            pad(lang.t("오탐 신고", "Report FP"), w)
        ));
    }
    out.push_str(d.rule());
    out.push('\n');
    out.push_str(&format!(" {}\n", brand::copyright()));
    out
}

/// 표시 폭. 한글·한자·전각은 두 칸, 나머지는 한 칸이다.
fn display_width(s: &str) -> usize {
    s.chars()
        .map(|c| {
            let u = c as u32;
            if (0x1100..=0x115F).contains(&u)
                || (0x2E80..=0xA4CF).contains(&u)
                || (0xAC00..=0xD7A3).contains(&u)
                || (0xF900..=0xFAFF).contains(&u)
                || (0xFE30..=0xFE4F).contains(&u)
                || (0xFF00..=0xFF60).contains(&u)
                || (0xFFE0..=0xFFE6).contains(&u)
            {
                2
            } else {
                1
            }
        })
        .sum()
}

/// 표시 폭 기준으로 오른쪽을 채운다. 표의 `항목 : 값` 이 두 언어에서 같은
/// 자리에 콜론을 갖게 한다.
pub fn pad(s: &str, width: usize) -> String {
    let w = display_width(s);
    if w >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - w))
    }
}

fn elapsed(secs: u64, lang: Lang) -> String {
    match lang {
        Lang::Ko if secs == 0 => "1초 미만".to_string(),
        Lang::Ko if secs >= 60 => format!("{}분 {}초", secs / 60, secs % 60),
        Lang::Ko => format!("{secs}초"),
        Lang::En if secs == 0 => "under 1s".to_string(),
        Lang::En if secs >= 60 => format!("{}m {}s", secs / 60, secs % 60),
        Lang::En => format!("{secs}s"),
    }
}

/// 사람에게 보여 줄 언어.
///
/// **파일 출력은 언어와 무관하게 UTF-8 고정이다** (설계-00 §5-2). 한글 Windows
/// 콘솔의 기본 코드페이지에 맞춰 쓰면 파일로 리다이렉트했을 때 깨진다.
/// 언어는 SDK 가 정한다(`remedy_sdk::i18n`) — 오류 `Display` 도 같은 것을
/// 읽어야 하기 때문이다. 여기서는 다시 내보내 옛 경로를 살린다.
pub use remedy_sdk::i18n::Lang;

/// `user_impact` 를 사람의 문장으로.
pub fn impact_line(i: &UserImpact, lang: Lang) -> String {
    let app = i
        .app
        .as_deref()
        .unwrap_or(lang.t("해당 프로그램", "the program"));
    let mut s = match i.kind {
        // **조건절이다 — 두 자리 다 참이어야 한다.**
        //
        // 2026-09-08 까지 *"…저장하지 않은 작업이 사라진다"* 로 단정하고 있었다.
        // 정상 프로그램(브라우저 확장을 지우려 브라우저를 닫는 자리)을 위해 쓴
        // 문장이라, 악성 스크립트를 돌리는 프로세스를 죽이는 자리에 그대로 붙이면
        // **없는 것이 사라진다고 말하게 된다.** 사용자는 무엇을 먼저 저장해야
        // 하는지 찾다가 승인을 미룬다.
        //
        // 그리고 능동("종료해야 한다")이 아니라 결과로 적는다 — 이 도구가 죽이는
        // 경우와 사람이 닫아야 하는 경우가 둘 다 여기로 온다.
        //
        // 줄표는 **장식**이라 `deco()` 가 정한다 — 리터럴 `—` 를 박아 두었더니 `--ascii`
        // 화면에서 이 줄만 유니코드가 샜다 (Windows 기준선 C3, 2026-09-30). 조사는
        // 앞말의 받침으로 고른다 — `이(가)` 병기는 회사 이름을 건 화면에 맞지 않는다.
        UserImpactKind::AppTerminate => {
            let dash = remedy_sdk::i18n::deco().dash();
            match lang {
                Lang::Ko => format!(
                    "{who} 종료됩니다{dash}저장하지 않은 작업이 있으면 사라집니다",
                    who = remedy_sdk::i18n::with_particle(app, "이", "가")
                ),
                Lang::En => format!("{app} will be terminated{dash}any unsaved work is lost"),
            }
        }
        // 정상 서명된 프로그램 옆의 악성 DLL 만 제거하는 것은 **옳은 처리이지만**
        // 그 프로그램은 더 이상 실행되지 않는다. 말하지 않으면 사용자는 무슨
        // 일이 일어났는지 모른다.
        UserImpactKind::AppBroken => match lang {
            Lang::Ko => format!(
                "{who} 더 이상 실행되지 않을 수 있습니다",
                who = remedy_sdk::i18n::with_particle(app, "이", "가")
            ),
            Lang::En => format!("{app} may no longer run"),
        },
        UserImpactKind::RebootRequired => lang
            .t(
                "재시작해야 정리가 끝납니다",
                "a restart is needed to finish",
            )
            .to_string(),
        UserImpactKind::RemovableMedia => lang
            .t(
                "이동식 매체의 대상입니다",
                "the target is on removable media",
            )
            .to_string(),
    };
    if let Some(note) = &i.note {
        s.push_str(" (");
        s.push_str(note);
        s.push(')');
    }
    s
}

/// 재부팅 뒤 재검사를 **이 기계가** 걸 수 있는가 (설계-03 §8 · P12).
///
/// 계획은 무엇을 원하는지(`verify_after_reboot`)만 싣는다. **걸 수 있는지는
/// 계획이 아니라 기계의 사실**이라 화면을 그리는 쪽이 물어서 넘긴다 — 묻지 않고
/// 약속하던 것이 P12 의 결함이었다 (`hexcfg-r1` 채점 5: 리눅스 컨테이너에서
/// 약속하고, 실행 뒤에 "예약하지 못했다" 로 바로잡았다).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterReboot<'a> {
    /// 걸 수 있다. 계획이 원하면 약속한다.
    Schedulable,
    /// 걸 수 없다 — 그 이유. 기계의 사실일 수도(쓰기 백엔드 · systemd), 부른
    /// 명령이 플러그인 경로를 몰라 요청을 만들 수 없다는 사실일 수도 있다(결정
    /// 자료 나1). 계획이 원해도 약속하지 않고 사실을 말한다.
    Unavailable(&'a str),
}

/// 계획을 사람이 읽는 글로.
///
/// **순서가 규격이다** — 부작용, 그다음 목록, 그다음 미룸. 목록을 먼저 보여
/// 주면 읽는 사람은 그것만 보고 승인한다 (설계-01 D5).
pub fn render_plan(p: &PlanEnvelope, lang: Lang, after_reboot: AfterReboot<'_>) -> String {
    let mut out = String::new();

    // ── 1. 부작용 (목록보다 **앞**) ───────────────────────────────
    let impacts: Vec<(u32, &UserImpact)> = p
        .body
        .actions
        .iter()
        .filter_map(|a| a.user_impact.as_ref().map(|i| (a.seq, i)))
        .collect();
    if !impacts.is_empty() {
        out.push_str(lang.t("이 치료의 부작용:\n", "Side effects of this treatment:\n"));
        for (seq, i) in &impacts {
            out.push_str(&format!("  ! [{seq}] {}\n", impact_line(i, lang)));
        }
        out.push('\n');
    }

    // ── 2. 무엇을 손대는가 ────────────────────────────────────────
    //
    // 수행할 것이 없으면 목록 머리도 없다. "0 건을 수행합니다:" 뒤에 빈 줄이
    // 오는 화면은 고객에게 무슨 뜻인지 말하지 않는다 — 그 말은 마무리가 한다.
    // **미룬 것(3절)은 수행할 것이 없어도 보인다** — 조용히 빠지면 이 계획이
    // 치료의 전부인 것처럼 읽힌다.
    if !p.body.actions.is_empty() {
        out.push_str(&format!(
            "{} {}\n",
            p.body.actions.len(),
            lang.t("건을 수행합니다:", "action(s) will run:")
        ));
        for a in &p.body.actions {
            // 카탈로그 ID 는 계획 JSON 에 있다. 화면은 고객이 읽는 문장이다.
            out.push_str(&format!(
                "  {:>2}. {}  {}\n",
                a.seq,
                op_label(a.op, lang),
                a.target.as_deref().unwrap_or(no_target(lang))
            ));
            // **동사 아래에 결과를 적는다.** 승인은 무엇이 달라지는지 알아야
            // 승인이다. 들여쓰기로 목록의 뼈대와 갈라 놓아, 훑는 사람은 번호
            // 줄만 읽고 판단하려는 사람은 그 아래를 읽는다.
            out.push_str(&format!("      {}\n", op_effect(a.op, lang)));
        }
    }

    // ── 3. 계획에 넣지 못한 것 ────────────────────────────────────
    //
    // **조용히 빠지면 이 계획이 치료의 전부인 것처럼 읽힌다** (설계-03 §2).
    //
    // **위협이 없으면 말하지 않는다** (2026-11-07 결정 ②). 판정이 없으면 치료할 것이 없고,
    // 그때 남는 항목은 대상이 정해지지 않은 치료 줄(*"capture 가 해소되지 않아"*)뿐이다 —
    // 깨끗한 Windows 를 검사할 때마다 그 줄과 재시작 안내(4절)가 떠서 처음 쓰는 사람이
    // 무엇이 잘못됐는지 물었다(v1.1.0 적대적 검토). 계획 JSON 에는 그대로 남는다.
    let treating = !p.body.verdicts.is_empty();
    if treating && !p.body.deferred.is_empty() {
        // **두 갈래를 섞지 않는다.** 기다리면 오는 것과 코어가 하지 않기로 한
        // 것은 운영자가 할 일이 완전히 다르다 — 앞은 코어를 올리는 일이고,
        // 뒤는 서명·허용 목록·매체를 다루는 일이다.
        //
        // 한동안 섞여 있었다. 2층(신뢰 서명)이 선 뒤로 그 항목들이
        // *"아직 이 코어에 없는 Op 을 요구한다"* 로 보고됐는데, 그 Op 은 있다.
        // 5층(허용 목록)이 오며 같은 자리가 다시 드러났다 (2026-08-29).
        //
        // **그 OS 에 없는 동작은 세지 않는다** (같은 날 결정 ③). 리눅스에는 서비스 복구
        // 설정이 없다 — 그것을 *"아직 지원하지 않는 동작"* 으로 세면 CWPdoor 제거가 덜 된
        // 치료처럼 읽힌다(룰의 RELEASE.md 도 *"빠진 치료가 아니다"* 라고 적었다).
        let (waiting, held): (Vec<_>, Vec<_>) = p
            .body
            .deferred
            .iter()
            .filter(|d| !not_on_this_os(d))
            .partition(|d| not_here_yet(d));

        if !waiting.is_empty() {
            out.push('\n');
            out.push_str(&format!(
                "  ** {}{}\n",
                lang.t(
                    "이 계획은 치료의 전부가 아닙니다 — ",
                    "this plan is not the whole treatment — "
                ),
                // **고객 화면이다.** 카탈로그 ID(`dir.delete_recursive`)와 `Op`·`코어`
                // 같은 내부 낱말, 마크다운 굵게(`**`)가 안내 모드의 첫 화면에 그대로
                // 찍히고 있었다 (Windows 기준선 A8, 2026-09-30). 항목은 `op_label` 로
                // 사람 말로 적고, 매니페스트 자리(`remediate.remove[4]`)는 작성자가
                // 찾을 수 있게 괄호 안에 남긴다. ID 는 계획 JSON 과 `--verbose` 에 있다.
                match lang {
                    Lang::Ko => format!(
                        "{}건은 아직 지원하지 않는 동작이라 계획에 넣지 못했습니다:",
                        waiting.len()
                    ),
                    Lang::En => format!(
                        "{} item(s) need an action this version does not support yet:",
                        waiting.len()
                    ),
                }
            ));
            for d in &waiting {
                out.push_str(&format!(
                    "     - {} ({}, {}){}{}\n",
                    op_label(d.op, lang),
                    d.at,
                    d.arrives_in,
                    remedy_sdk::i18n::deco().dash(),
                    d.reason
                ));
            }
        }

        if !held.is_empty() {
            out.push('\n');
            out.push_str(&format!(
                "  ** {}\n",
                match lang {
                    Lang::Ko => format!(
                        "{}건은 안전 규칙에 따라 이 프로그램이 하지 않기로 했습니다:",
                        held.len()
                    ),
                    Lang::En => format!(
                        "{} item(s) this program chose not to do under its safety rules:",
                        held.len()
                    ),
                }
            ));
            for d in &held {
                out.push_str(&format!(
                    "     - {} ({}){}{}\n",
                    op_label(d.op, lang),
                    d.at,
                    remedy_sdk::i18n::deco().dash(),
                    d.reason
                ));
            }
        }
    }

    // ── 4. 치료 뒤에 일어날 일 ────────────────────────────────────
    //
    // **승인 전에 알았어야 하는 사실이다.** 재부팅 뒤 한 번 더 검사한다는 것을
    // 치료가 끝난 뒤에야 말하면, 사용자는 다음 재시작에 뜨는 검은 창을 예상하지
    // 못한다. 값은 이미 계획에 실려 있다(`PlanBody::verify_after_reboot`).
    //
    // **`user_impact` 가 아니다.** `RebootRequired` 는 *"재시작해야 정리가
    // 끝난다"* 이고 그것이 맞는 자리는 `file.delete_on_reboot` 뿐이다. 여기는
    // 정리가 이미 끝나고 **한 번 더 확인**하는 것이라 뜻이 다르다.
    //
    // **지킬 수 없는 약속을 하지 않는다** (P12 D4). 걸 수 없으면 — 기계가 못 하든,
    // 부른 명령이 플러그인 경로를 몰라 요청을 만들 수 없든 — 이유를 말하고, 직접
    // 부를 명령은 실행 뒤 안내가 준다. 문구는 이유를 가리지 않는다: "이 기계에서는"
    // 이라고 하면 명령이 이유일 때 거짓이 된다 (결정 자료 나1).
    //
    // 위협이 없으면 치료도 재시작 뒤 검사도 없다 — 3절과 같은 까닭으로 말하지 않는다.
    if treating && p.body.verify_after_reboot {
        out.push('\n');
        match after_reboot {
            AfterReboot::Schedulable => out.push_str(lang.t(
                "  * 치료를 마친 뒤 이 PC 를 재시작하면 자동으로 한 번 더 검사합니다.\n",
                "  * After you restart this PC, one more check runs automatically.\n",
            )),
            AfterReboot::Unavailable(why) => out.push_str(&match lang {
                Lang::Ko => format!(
                    "  * 재시작 뒤 자동 재검사를 걸 수 없습니다 ({why}).\n    \
                     치료가 끝나면 직접 부를 명령을 알려 드립니다.\n"
                ),
                Lang::En => format!(
                    "  * The automatic check after a restart cannot be scheduled ({why}).\n    \
                     When the treatment ends you will be shown the command to run yourself.\n"
                ),
            }),
        }
    }
    out
}

/// 이 항목이 **그 OS 에 개념이 없는 동작**인가 — `arrives_in` 이 Phase 이름이 아니고 그 Op 이
/// 리눅스에 없다(`remedy-plan` 의 `defer` 가 그렇게 적는다). Windows 는 모든 Op 이 Phase 를
/// 가지므로 걸리지 않는다. 사용자 유닛의 서비스 정지처럼 **있는데 그 자리에서만 못 하는**
/// 것은 Op 이 리눅스에 있으므로 걸리지 않고 그대로 보인다.
fn not_on_this_os(d: &remedy_sdk::artifact::DeferredItem) -> bool {
    let phase = remedy_sdk::catalog::Phase::ALL
        .iter()
        .any(|p| p.as_str() == d.arrives_in);
    !phase && d.op.info().linux_from.is_none()
}

/// 이 항목이 **기다리면 오는 것**인가.
///
/// `arrives_in` 이 이 코어의 게이트보다 뒤라면 아직 없는 것이고, 게이트 안이면
/// **있는데 하지 않은 것**이다. 플랫폼에 개념이 없는 경우(`arrives_in` 이 Phase
/// 이름이 아닌 문장)도 기다리는 쪽이다 — 룰을 고쳐야 한다는 뜻이지만, 어느
/// 쪽이든 이 실행이 할 수 있는 일이 아니다.
fn not_here_yet(d: &remedy_sdk::artifact::DeferredItem) -> bool {
    let Some(p) = remedy_sdk::catalog::Phase::ALL
        .iter()
        .find(|p| p.as_str() == d.arrives_in)
    else {
        // Phase 이름이 아니다 — "linux 에는 개념이 없습니다" 같은 문장.
        return true;
    };
    *p > remedy_sdk::IMPLEMENTED_THROUGH
}

/// 수행 결과를 사람이 읽는 글로.
pub fn render_result(r: &ResultBody, lang: Lang) -> String {
    let mut out = String::new();
    let count = |o: ActionOutcome| r.results.iter().filter(|x| x.outcome == o).count();
    let (done, failed, skipped) = (
        count(ActionOutcome::Done),
        count(ActionOutcome::Failed),
        count(ActionOutcome::Skipped),
    );

    out.push_str(&match lang {
        Lang::Ko => format!("수행 {done} · 실패 {failed} · 건너뜀 {skipped}\n"),
        Lang::En => format!("done {done} · failed {failed} · skipped {skipped}\n"),
    });

    // **왜 안 했는지가 왜 했는지보다 중요할 때가 있다** (설계-03 §7).
    for x in r.results.iter().filter(|x| x.error.is_some()) {
        out.push_str(&format!(
            "  {} [{}] {}  {}\n",
            lang.t("실패", "failed"),
            x.seq,
            x.op.info().id,
            x.error.as_deref().unwrap_or_default()
        ));
    }
    if let Some(q) = &r.quarantine {
        out.push_str(&format!("{} {q}\n", lang.t("격리소:", "quarantine:")));
    }
    if r.reboot_required {
        // **예약은 파괴가 아니다.** 아직 그 자리에 있고 사라지는 것은 다음
        // 부팅이다. 말하지 않으면 사용자는 치료가 끝났다고 읽는다.
        out.push_str(lang.t(
            "일부 항목은 다음 부팅에 사라집니다 — 아직 그 자리에 있습니다.\n",
            "some items disappear at the next boot — they are still there.\n",
        ));
    }
    out
}

// ─────────────────────────────────────────────── 자립률 (설계-01 D10)

/// 코어를 고쳐야 했던 이유.
///
/// **분류가 곧 다음에 무엇을 만들지다.** 자립률이 떨어지는 것만 알면 할 수
/// 있는 일이 없고, 왜 떨어지는지를 알면 T3 에서 T2 로 내릴 대상이 데이터로
/// 나온다 (설계-01 D10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Shortfall {
    /// 관찰 대상이 없다 — 열거 능력의 부족.
    NoObservation,
    /// 파괴 동작이 없다 — Op 카탈로그의 공백.
    NoOp,
    /// 로직 표현의 한계. **이것이 상위 요인이 되는 날** 스크립트 런타임의
    /// 도입 조건이 성립한다 (설계-01 D10). 그 전에는 근거 없는 선택이다.
    Logic,
}

impl Shortfall {
    pub const ALL: [Shortfall; 3] = [Shortfall::NoObservation, Shortfall::NoOp, Shortfall::Logic];
    pub const fn id(self) -> &'static str {
        match self {
            Shortfall::NoObservation => "no_observation",
            Shortfall::NoOp => "no_op",
            Shortfall::Logic => "logic",
        }
    }
    pub const fn label(self, lang: Lang) -> &'static str {
        match self {
            Shortfall::NoObservation => lang.t("관찰 대상이 없습니다", "no observation"),
            Shortfall::NoOp => lang.t("삭제·변경 동작이 없습니다", "no removal or change action"),
            Shortfall::Logic => lang.t("로직 표현의 한계", "logic cannot be expressed"),
        }
    }
}

/// 미룬 항목 하나를 분류한다.
///
/// **미룸은 subject 가 아니라 Op 을 이름으로 든다.** `DeferredItem.op` 이 곧
/// "없어서 못 한 것" 이므로, 지금 이 코어가 낼 수 있는 미룸은 전부
/// [`Shortfall::NoOp`] 이다. 나머지 둘은 미룸으로 표현되지 않는다 — 관찰
/// 대상이 없으면 룰을 **쓸 수조차 없어** 계획까지 오지 못하고, 로직 한계도
/// 마찬가지다.
///
/// 그래서 이 함수는 지금 한 갈래만 낸다. **그 사실을 감추지 않는다** — 세
/// 범주를 다 세는 척하면 "관찰 대상 없음 0건" 이 "그런 일이 없다" 로 읽힌다.
/// 나머지 둘의 입력은 사람이 적는 목록이며, 그것이 P9 의 "없어서 불편한 API
/// 목록 문서화" 다.
pub fn classify(_d: &DeferredItem) -> Shortfall {
    Shortfall::NoOp
}

/// 자립률 집계 결과.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelfSufficiency {
    /// 본 계획 수.
    pub plans: usize,
    /// 그중 **코어 수정 없이 온전히 치료된** 계획 수.
    pub self_sufficient: usize,
    /// 범주별 미룸 건수. 오름차순 고정이라 출력이 흔들리지 않는다.
    pub by_shortfall: Vec<(Shortfall, usize)>,
    /// 어떤 Op 이 몇 번 막았는가. **다음에 무엇을 만들지가 여기서 나온다.**
    pub blocking_ops: Vec<(String, usize)>,
}

impl SelfSufficiency {
    /// 코어 수정 없이 완료된 비율. 표본이 없으면 `None` — **0% 로 접지
    /// 않는다.** 재지 않은 것과 0인 것은 다르다 (설계-00 §5-1).
    pub fn rate(&self) -> Option<f64> {
        (self.plans > 0).then(|| self.self_sufficient as f64 / self.plans as f64)
    }
}

/// 계획들을 훑어 자립률을 낸다.
///
/// > **플러그인 자립률** = 새 위협 대응 건수 중 **코어 수정 없이 플러그인만으로
/// > 완료된 비율** (설계-01 D10)
///
/// 여기서 "대응 건수" 는 계획 하나다. 미룸이 하나도 없으면 그 대응은 코어를
/// 고치지 않고 끝난 것이다.
///
/// **출시를 막는 게이트가 아니라 추세 지표다.** 떨어지면 배포를 멈추는 것이
/// 아니라 다음에 무엇을 코어에 넣을지를 정한다 (설계-03 §7).
pub fn self_sufficiency<'a>(plans: impl IntoIterator<Item = &'a PlanEnvelope>) -> SelfSufficiency {
    use std::collections::BTreeMap;
    let mut out = SelfSufficiency::default();
    let mut by: BTreeMap<Shortfall, usize> = BTreeMap::new();
    let mut ops: BTreeMap<String, usize> = BTreeMap::new();

    for p in plans {
        out.plans += 1;
        if p.body.deferred.is_empty() {
            out.self_sufficient += 1;
        }
        for d in &p.body.deferred {
            *by.entry(classify(d)).or_default() += 1;
            *ops.entry(d.op.info().id.to_string()).or_default() += 1;
        }
    }
    out.by_shortfall = by.into_iter().collect();
    // 많이 막은 것이 앞이다. 같으면 이름 순 — 출력이 실행마다 흔들리면
    // 추세를 읽을 수 없다.
    out.blocking_ops = {
        let mut v: Vec<(String, usize)> = ops.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    };
    out
}

/// 자립률을 사람이 읽는 글로.
pub fn render_self_sufficiency(s: &SelfSufficiency, lang: Lang) -> String {
    let mut out = String::new();
    match s.rate() {
        None => out.push_str(lang.t(
            "자립률: 잰 것이 없습니다 (계획 0건)\n",
            "self-sufficiency: nothing measured (0 plans)\n",
        )),
        Some(r) => out.push_str(&match lang {
            Lang::Ko => format!(
                "자립률: {:.0}% ({}/{} 계획이 코어 수정 없이 끝납니다)\n",
                r * 100.0,
                s.self_sufficient,
                s.plans
            ),
            Lang::En => format!(
                "self-sufficiency: {:.0}% ({}/{} plans need no core change)\n",
                r * 100.0,
                s.self_sufficient,
                s.plans
            ),
        }),
    }
    for (k, n) in &s.by_shortfall {
        out.push_str(&format!("  {} : {n}\n", k.label(lang)));
    }
    if !s.blocking_ops.is_empty() {
        out.push_str(lang.t(
            "  막고 있는 Op (많은 순):\n",
            "  blocking Ops (most first):\n",
        ));
        for (op, n) in &s.blocking_ops {
            out.push_str(&format!("    {op}  {n}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests;
