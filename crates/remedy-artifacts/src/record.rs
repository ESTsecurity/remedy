//! subject 레코드 (설계-09 §3.3). P2 가 `file`·`persistence`, P4 가 나머지다.
//!
//! 필드 이름은 설계-02 §3 의 공통 필드와 같다. OS 고유 속성은 `win.*` 네임스페이스로
//! 분리해, Linux 백엔드(P12)가 같은 레코드를 채울 수 있게 한다.
//!
//! # 필드 이름은 여기서 정하지 않는다
//!
//! 룰이 적을 수 있는 이름은 `remedy-sdk` 의 `Subject::fields()` 가 정한다. 이
//! 파일의 구조체는 **그 목록과 한 글자도 다르면 안 된다** — 다르면 린트를
//! 통과한 룰이 평가에서 아무것도 맞히지 못하고, 작성자는 이유를 알 수 없다.
//! `tests/format.rs` 의 `the_sdk_field_catalog_matches_the_real_records` 가
//! subject 마다 그것을 대조한다.
//!
//! # P4 레코드는 전부 평평하다
//!
//! `file`·`persistence` 만 중첩(`signature.*`·`win.task.*`)을 쓴다. 나머지는
//! 평평하게 두는데, 중첩은 룰 작성자가 점 경로를 정확히 외워야 하고 그 값이
//! 카탈로그와 어긋나기 쉽기 때문이다.

use serde::{Deserialize, Serialize};

/// 아직 채우지 않는 필드에 대하여
///
/// `signature` · `zone` · `streams` 는 스키마에는 있지만 P2 에서 채우지 않는다.
/// 비워 두는 것과 "없다" 는 다르므로 전부 `Option` 이고, 채워지는 Phase 를 각
/// 필드에 적어 둔다. `None` 을 "서명 없음" 으로 읽으면 서명된 악성코드 예외
/// (설계-03 §3 2층)가 조용히 무력해진다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    /// 정규화된 절대 경로. 환경변수는 수집 시점에 전개된다.
    pub path: String,
    pub size: u64,
    /// RFC3339 UTC.
    pub mtime: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctime: Option<String>,
    /// 소문자 16진. 크기 상한을 넘으면 `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// P4 에서 채운다. `None` 은 "확인하지 않았다" 이지 "서명이 없다" 가 아니다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    /// 실행 파일이 선언한 **문자열 `FileVersion`** — `StringFileInfo` 쪽이고
    /// **공백 뒤 주석(`(WinBuild…)`)만 버린** 값이다 (C-1b).
    ///
    /// 2진 `VS_FIXEDFILEINFO` 가 아닌 이유와 `0.0.0.0` 을 담지 않는 이유는
    /// `remedy-collect` 의 `peversion` 문서에 있다 — 짧게는 **공급사가 공지하는
    /// 눈금이 문자열 쪽이고**(`postgres.exe` 는 문자열 `16.10` ↔ 2진
    /// `16.0.10.0`), `0.0.0.0` 을 담으면 버전을 선언하지 않은 파일 전부가
    /// `version_lt` 에 맞는다.
    ///
    /// **`a.b.c.d` 네 자리라고 가정하면 안 된다** — 자유 형식이라 `8.2.35` 처럼
    /// 세 자리도, `8.2.27RC1` 처럼 꼬리 붙은 것도 온다(둘 다 실물 PHP 실측).
    /// 꼬리는 줄이지 않고 담아 `version_lt` 가 거부하게 한다 — 사전 배포를 정식
    /// 판이라고 말하는 대신 **종료 6**(사람이 가린다)으로 간다.
    ///
    /// `None` 은 `signature` 와 같은 뜻이다 — **"확인하지 않았다"**. 대상 형식이
    /// 아니었거나, 상한을 넘어 읽지 않았거나, 리소스가 없거나, 버전을 선언하지
    /// 않았다. "버전이 0 이다" 가 아니다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 감염 소스(Mark-of-the-Web). P4 에서 채운다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<Zone>,
    /// 대체 데이터 스트림. P4 에서 채운다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<String>,
    /// 본문을 스냅샷에 담았다면 그 참조. 없으면 YARA 규칙은 **미평가**다
    /// (설계-03 §1). 미평가 규칙이 있는 판정은 감염 확정에 쓸 수 없다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub trusted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zone {
    pub zone_id: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_url: Option<String>,
}

/// 지속성 항목. Windows 는 예약 작업, Linux 는 cron·systemd timer 다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistenceRecord {
    /// 등록 경로. 예: `\Microsoft\Windows\Locust`
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// 기동 조건의 요약. 예: `logon`, `boot`, `schedule`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trigger: Vec<String>,
    /// 실행 파일. 정규화된 경로다.
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: String,
    /// 실행 주체 계정.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// 이 항목이 어디서 왔는가. 예약 작업이면 정의 파일 경로다.
    ///
    /// EvilAI 룰이 `source contains "\System32\"` 를 쓰므로 실제 파일 경로여야 한다.
    #[serde(default)]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub win: Option<WinTask>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<LinuxPersistence>,
}

/// Linux 지속성 고유 속성.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxPersistence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cron: Option<CronLine>,
}

/// Linux 인증서 저장소 고유 속성.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxCert {
    /// 인증서 파일의 절대 경로.
    pub path: String,
}

/// cron 항목이 **파일 안의 줄**이라는 사실 (설계-09 P12 결정 5).
///
/// # 왜 원문을 담는가
///
/// 이 줄을 지우거나 주석 처리하는 Op 은 **번호만으로 고치지 않는다** — 수집과
/// 실행 사이에 파일이 바뀌면 그 번호가 다른 내용일 수 있고, 엉뚱한 줄을 건드리면
/// 정상 작업이 조용히 멈춘다.
///
/// `hosts_entry` 는 파싱된 값(`ip` 와 이름)에서 줄을 **재구성**해 같은 일을 한다.
/// cron 은 그럴 수 없다 — 레코드가 담는 `trigger` 는 `boot`/`calendar` 로
/// 정규화된 값이라 `*/5 * * * *` 를 되살릴 수 없기 때문이다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronLine {
    /// 사람이 보는 줄 번호. 1 부터다.
    pub line_no: u32,
    /// 그 줄의 원문. 앞뒤 공백은 떼어 담는다.
    pub line: String,
}

/// Windows 예약 작업 고유 속성.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinTask {
    pub task: WinTaskFields,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinTaskFields {
    /// 작업 스케줄러 트리에서 이 작업이 들어 있는 **폴더**. 후행 `\` 를 남긴다.
    /// 최상위 작업이면 `\` 다.
    ///
    /// Windows 자신의 `TaskPath` 와 같은 뜻이다(`Get-ScheduledTask` 의 그것).
    /// 작업 이름까지 포함한 전체 등록 경로는 `id` 다 — 룰이 특정 작업 하나를
    /// 지목하려면 `id` 를, 폴더로 묶으려면 이 필드를 쓴다.
    ///
    /// 예: `\Microsoft\Windows\Locust` 라는 작업이면
    ///     `id` = `\Microsoft\Windows\Locust`, `register_path` = `\Microsoft\Windows\`
    pub register_path: String,
    /// 이 작업이 가진 Action 의 종류. `exec` · `com_handler` · `send_email` 등.
    ///
    /// `command` 가 비어 있는 것이 "실행 파일이 지정되지 않았다" 인지 "애초에
    /// Exec 액션이 아니다" 인지 구분하기 위해 필요하다. 실측한 정상 Windows 10
    /// 의 예약 작업 218건 중 **119건이 Exec 가 아니다**(대부분 ComHandler).
    /// 그것을 전부 빈 명령으로 뭉뚱그리면 룰이 왜 안 맞는지 알 수 없고,
    /// "이 작업은 아무것도 실행하지 않는다" 로 잘못 읽힌다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    /// `command` 에서 **작업 계정의 프로필 변수**를 편 값 (코어 1.2.0).
    ///
    /// 예약 작업은 `%LOCALAPPDATA%` 같은 변수를 **펴지 않은 채** 저장할 수 있고,
    /// 돌 때 그 작업의 계정으로 편다. 원문만 보면 그 경로가 실제로 어느 파일인지
    /// 모른다 — Trend Micro 가 본 EvilAI 의 작업이 그 꼴이다(2025-09 보도:
    /// `"%LOCALAPPDATA%\TEMP\{UID}or.js"`). 그래서 수집할 때 **작업 계정**의 프로필로
    /// 편 값을 함께 담는다. 엔진을 돌린 계정이 아니다 — 다른 관리자나 SYSTEM 으로
    /// 검사해도 같은 값이 나와야 한다.
    ///
    /// 펴는 것은 `USERPROFILE` · `LOCALAPPDATA` · `APPDATA` · `TEMP` · `TMP` 다섯이고
    /// 자리는 Windows 의 기본 자리다(사용자가 셸 폴더를 옮겼으면 다르다). 그 밖의
    /// 변수와, 프로필을 모르는 계정(그룹 · 시스템 계정 · 찾지 못한 이름)의 변수는
    /// **그대로 둔다** — 지어내지 않는다.
    ///
    /// `None` 은 "이 수집이 펴지 않았다" 다(1.2.0 전의 스냅샷). 펼 것이 없으면 원문과
    /// 같은 값이 든다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_expanded: Option<String>,
    /// `args` 에서 같은 것을 편 값. 뜻은 `command_expanded` 와 같다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_expanded: Option<String>,
}

// ─────────────────────────────────────────────────────── P4 subject 레코드
//
// 아래 레코드의 필드는 전부 **언제나 직렬화된다.** `skip_serializing_if` 를
// 붙이면 값이 비었을 때 필드가 사라지고, 그러면 룰의 `exists` 가 "관측하지
// 않았다" 와 "값이 비었다" 를 구분하지 못한다. 값이 없을 수 있는 자리는
// 빈 문자열이 아니라 그 사실이 드러나는 형태로 둔다.

/// 로그온·부팅 때 자동으로 실행되는 항목. Windows 는 Run/RunOnce 키와 시작 폴더다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutorunRecord {
    /// 이 항목을 유일하게 가리키는 이름. 레지스트리면 `<키>\<값이름>` 이다.
    pub id: String,
    /// `user` 또는 `system`. 지우면 누구에게 영향이 가는지가 여기 있다.
    pub scope: String,
    pub name: String,
    /// 실행될 명령 전체. 인자까지 포함한다.
    pub command: String,
    /// 어디서 왔는가. 레지스트리 키 경로 또는 시작 폴더 파일 경로다.
    pub source: String,
}

/// Windows 서비스 / systemd 유닛.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub id: String,
    pub name: String,
    /// `running` · `stopped` · `unknown`. 소문자로 고정한다.
    pub state: String,
    /// `boot` · `system` · `auto` · `manual` · `disabled` · `unknown`.
    pub start_type: String,
    pub image_path: String,
}

/// 돌고 있는 프로세스.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub ppid: u32,
    pub image_path: String,
    /// 실행 파일까지 포함한 명령 전체.
    ///
    /// # 비어 있으면 "명령줄이 없다" 가 아니라 **"우리에게 없다"** 다
    ///
    /// 실측 (2026-09-01, Win10 관리자 세션): 프로세스 145개 중 **19개**가
    /// 비었다. `System Idle Process` 하나만 `image_path` 까지 비었고, 나머지
    /// 18개는 실행 파일은 알지만 명령줄만 없다 — `csrss` · `wininit` ·
    /// `services` · `smss` · 보안 제품 · `svchost` 4개.
    ///
    /// **이것은 권한 문제가 아니다.** 같은 기계에서 WMI(`Win32_Process`, SYSTEM
    /// 으로 돌며 `SeDebugPrivilege` 를 가진다)에 같은 pid 를 물었을 때
    /// 명령줄을 준 것은 **0개**였다. OS 가 아무에게도 주지 않는다. 그래서
    /// `unsafe` 로 토큰을 올려도 달라지지 않고, 관리자를 요구하게 된 뒤에도
    /// 그대로 남는다.
    ///
    /// # 그래서 `denied_dirs` 에 세지 않는다
    ///
    /// 세면 **모든 Windows 기계가 상시로 관측 불완전**이 되고 종료 코드 6이
    /// 항상 뜬다. 설계-01 이 적은 그대로 — 해결 불가능한 6이 상시로 섞이면
    /// 운영자는 6을 정상으로 학습하고, 그러면 6이 잡으라고 만든 신호가 죽는다.
    /// `denied_dirs` 의 뜻은 *"거부는 언제나 이상 징후"* 이고, 그 뜻을 지키려면
    /// 늘 있는 것을 거기 넣으면 안 된다.
    ///
    /// # 룰 작성자에게
    ///
    /// `cmdline` 조건은 **이 18개에 닿지 않는다.** 보호 프로세스를 겨누려면
    /// 명령줄이 아니라 그 프로세스가 무엇으로 등록되었는지를 본다 —
    /// `service` 의 `image_path`·`start_type`, `autorun` 의 `command`.
    /// (`docs/plugin-guide/31-nonexistent.md`)
    pub cmdline: String,
    /// base64·hex 로 감싼 명령을 푼 것. 풀 것이 없으면 `cmdline` 과 같다.
    ///
    /// **인코딩은 은폐 수단이지 실행 방식이 아니다.** 룰이 원문만 볼 수 있으면
    /// `powershell -enc <base64>` 한 줄로 모든 문자열 룰이 무력해진다.
    pub cmdline_decoded: String,
    pub args: String,
    pub user: String,
    /// RFC3339 UTC.
    pub start_time: String,
    /// 실린 모듈의 경로. **플랫폼마다 있는 것이 다르다.**
    ///
    /// | 플랫폼 | 값 | 왜 |
    /// |---|---|---|
    /// | Linux | `/proc/<pid>/maps` 의 **실행 가능한 파일 매핑** | 읽기 하나다 |
    /// | Windows | **언제나 빈 목록** | 열거에 `EnumProcessModules` 가 필요하고 그것은 unsafe 다. 이 저장소는 크레이트 전부에 `forbid(unsafe_code)` 를 건다 |
    ///
    /// # Windows 에서 빈 목록은 "모듈이 없다" 가 아니다
    ///
    /// 그 사실을 사람의 선의에 맡기지 않는다 —
    /// `Subject::NOT_POPULATED_YET` 이 이 필드를 `Some(Platform::Windows)` 로
    /// 들고 있어서 **린트가 작성 시점에, 평가기가 `scan.json` 에** 말한다.
    /// 빈 목록은 두 방향으로 틀린다: `contains` 는 늘 거짓(미탐)이고,
    /// `exists` 는 평가기가 목록을 `"[]"` 로 꺼내므로 **늘 참**(오탐)이다.
    ///
    /// Windows 에서 같은 것을 보려면 그 모듈 **파일 자체를 겨눈다** —
    /// `file` 과 `yara:` 가 같은 것을 본다.
    ///
    /// # Linux 의 빈 목록
    ///
    /// 커널 스레드는 주소 공간이 없어 정말로 비고, 그것은 **봤고 없었던**
    /// 쪽이다. 읽지 못한 쪽은 여기 오지 않고 거부로 세어 종료 코드 6 이 된다
    /// (`RawProcess::modules_denied`).
    pub modules: Vec<String>,
}

/// 다른 관찰에서 뽑아낸 지표. 파일도 레지스트리도 아니고 **파생 관찰**이다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndicatorRecord {
    /// `url` · `domain` · `ip` · `hash`.
    pub kind: String,
    pub value: String,
    /// 어느 관찰에서 나왔는가. 근거 없는 지표는 만들지 않는다.
    pub source_ref: String,
}

/// 레지스트리 값 하나.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValueRecord {
    pub hive: String,
    /// 하이브를 뺀 키 경로.
    pub key: String,
    /// 값 이름. 기본값이면 빈 문자열이다.
    pub name: String,
    /// `REG_SZ` 등 레지스트리 자신의 타입 이름.
    #[serde(rename = "type")]
    pub r#type: String,
    pub data: String,
}

/// 레지스트리 키 하나와 그 아래의 이름들.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryKeyRecord {
    pub hive: String,
    pub key: String,
    pub subkeys: Vec<String>,
    /// 값 **이름**만. 내용은 `registry_value` 가 담는다 — 두 곳에 같은 것을
    /// 담으면 언젠가 갈라진다.
    pub values: Vec<String>,
}

/// ini·conf 등 줄 단위 설정의 한 줄.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextConfigRecord {
    pub path: String,
    /// 1부터 센다. 사람이 편집기에서 보는 번호와 같아야 한다.
    pub line_no: u32,
    pub line: String,
    /// `[section]` 안이면 그 이름. 밖이면 빈 문자열이다.
    pub section: String,
    pub key: String,
    pub value: String,
}

/// JSON 같은 구조적 설정의 잎 하나.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredConfigRecord {
    pub path: String,
    /// `json` 등.
    pub format: String,
    /// 점으로 이은 경로. 배열은 `a.0.b` 처럼 색인으로 적는다.
    pub key_path: String,
    pub value: String,
}

/// 바로가기.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortcutRecord {
    pub path: String,
    pub target: String,
    pub args: String,
    pub working_dir: String,
    pub icon: String,
}

/// 부팅 구성.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootConfigRecord {
    pub entry: String,
    /// 복구 환경이 켜져 있는가. 모르면 `unknown`.
    pub recoveryenabled: String,
    /// 안전 모드로 들어갈 수 있는가. 설계-03 이 요구하는 선행 점검이다.
    pub safeboot_available: String,
}

/// hosts 파일의 한 줄.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostsEntryRecord {
    pub ip: String,
    pub hostnames: Vec<String>,
    pub line_no: u32,
    /// 이 항목을 읽은 파일. **스냅샷은 홀로 읽혀야 한다** (설계-02 §8).
    ///
    /// hosts 파일의 자리는 OS 마다 다르고(Windows 는 `System32\drivers\etc`,
    /// Linux 는 `/etc`), 계획기가 그것을 상수로 들고 있으면 스냅샷을 뜬 기계와
    /// 다른 자리를 고칠 수 있다. **이것이 없으면 `hosts.restore_line` 은 대상을
    /// 짚지 못해 계획되지 않는다.**
    pub source: String,
    /// 그 자리의 **원본 줄** (주석을 뗀 뒤, 앞뒤 공백만 정리한 것).
    ///
    /// # 왜 파생이 아니라 원본인가
    ///
    /// `hosts.restore_line` 을 수행할 때 실행기가 *"그 자리의 줄이 계획과
    /// 같은가"* 를 본다 — 수집과 치료 사이에 파일이 바뀌었으면 손대지 않기
    /// 위해서다. 그런데 계획기가 `ip` 와 `hostnames` 로 줄을 **다시 지으면**
    /// 그 비교가 공백 하나에 걸린다.
    ///
    /// 실측(2026-09-03, ubuntu:24.04 컨테이너): 실제 파일은
    /// `127.0.0.1\tlab.remedy.invalid` 인데 재구성은
    /// `127.0.0.1 lab.remedy.invalid` 였다. 탭 하나 때문에 실행기가
    /// *"그 자리의 줄이 계획과 다르다"* 며 거부했다. **거의 모든 실기기의
    /// `/etc/hosts` 가 탭을 쓴다** — 그러니 이 Op 은 사실상 늘 실패했다.
    ///
    /// `text_config` 의 `line` 과 `persistence` 의 cron `line` 이 이미 같은
    /// 이유로 원본을 담고 있었다. 여기만 빠져 있었다.
    ///
    /// `#[serde(default)]` 인 이유: 이 필드가 생기기 전에 뜬 스냅샷이 코퍼스에
    /// 있다. 빈 값이면 계획기가 재구성으로 되돌아가되, 그 스냅샷으로는 이 Op 이
    /// 예전처럼 동작한다 — 옛 자료를 읽을 수 있게 두는 값이다.
    #[serde(default)]
    pub line: String,
}

/// 브라우저 확장.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserExtensionRecord {
    pub browser: String,
    pub profile: String,
    pub ext_id: String,
    pub name: String,
    pub version: String,
    pub path: String,
}

/// 보안 제품의 검사 제외 항목.
///
/// **치료가 끝나면 원복해야 하는 대상이다** (설계-03 §2 7단계). 악성코드가
/// 자기 폴더를 제외 목록에 넣어 두고 사라지면, 그 구멍은 남는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvExclusionRecord {
    /// `path` · `process` · `ext`.
    pub kind: String,
    pub value: String,
    /// 어느 제품·어느 키에서 왔는가.
    pub source: String,
}

/// 인증서 저장소의 항목.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertStoreRecord {
    /// `ROOT` · `CA` · `TrustedPublisher` 등 저장소 이름.
    pub store: String,
    pub subject: String,
    pub issuer: String,
    /// SHA-1 지문. 대문자 16진.
    pub thumbprint: String,
    /// RFC3339 UTC. 읽지 못했으면 빈 문자열이다.
    pub not_after: String,
    /// Linux 고유 — 이 인증서가 사는 **파일**.
    ///
    /// Windows 인증서는 레지스트리 값이라 경로가 없다. Linux 는 파일이고,
    /// **계획기가 대상으로 삼을 자리가 여기뿐이다** — 다른 필드로는 쓰기 경계가
    /// 파일을 찾아 헤매야 한다 (불변식 P, 설계-09 P12 후속).
    ///
    /// 룰에서는 `linux.path` 로 적는다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<LinuxCert>,
}

/// 설치된 패키지 하나 (C-2).
///
/// # 왜 버전이 셋인가
///
/// 배포판 판 문자열 하나로는 견줄 수 없다. `version_lt` 는 점으로 나눈 숫자만
/// 받고, 꼬리는 **모양이 같고 순서가 반대**라 추측하지 않는다 — `8.4.0RC1` 은
/// `8.4.0` 보다 낮고 `8.2.29-1ubuntu1` 은 `8.2.29` 보다 높다. 그래서 수집기가
/// 갈라 담는다 (`1:2.38.1-5+deb12u3` 실측):
///
/// | 필드 | 값 | 쓰는 법 |
/// |---|---|---|
/// | [`version`](Self::version) | `1:2.38.1-5+deb12u3` | **원문이 증거다.** `equals` · `contains` |
/// | [`upstream_version`](Self::upstream_version) | `2.38.1` | `version_lt` · `version_gt` |
/// | [`revision`](Self::revision) | `5+deb12u3` | `contains` — 백포트 판을 알아볼 때 |
///
/// # 치료 Op 이 없다
///
/// 패키지를 지우거나 올리는 것은 **공급사의 일**이다(설계-00 §3). 이 subject 는
/// 점검의 근거이고, 계획기의 `removal_ops` 가 빈 목록을 돌려준다 — 미룸으로도
/// 빠지지 않는다.
///
/// # 설치된 것만 담는다
///
/// dpkg 는 지워도 설정이 남은 패키지를 `deinstall ok config-files` 로 들고
/// 있는데, 그 판 번호는 **디스크에 있는 것을 설명하지 않는다.** 담으면 지운
/// 패키지가 *"취약한 판이 깔려 있다"* 로 읽힌다. 그래서 `installed` 계열만
/// 담고, 그것이 이 subject 의 뜻이다(*"설치된 패키지"*) — 버린 것이 아니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRecord {
    /// 패키지 이름. dpkg 의 `Package`, apk 의 `P:`.
    pub name: String,
    /// **DB 에 적힌 그대로의 판.** epoch 과 개정 꼬리를 포함한다.
    pub version: String,
    /// 앞의 점숫자만 떼어 낸 것. `version_lt` 가 받는 모양이다.
    ///
    /// **읽지 못하면 빈 문자열이다.** 지어내지 않는다 — `file.version` 이
    /// `0.0.0.0` 을 담지 않는 이유와 같다. `~rc1` 같은 사전 배포 꼬리는 여기
    /// 남지 않으므로(`1.2.3~rc1` → `1.2.3`), 그것을 가려야 하는 룰은
    /// [`version`](Self::version) 을 본다.
    pub upstream_version: String,
    /// 배포판 개정. 마지막 `-` 뒤다. 없으면 빈 문자열이다.
    ///
    /// **백포트의 흔적이 여기 있다** — `5+deb12u3` · `1ubuntu2.21` · `r1`.
    /// 순서를 정할 수 없으므로(그래서 `version_lt` 가 꼬리를 받지 않는다)
    /// `contains` 로 알아보는 자리다.
    pub revision: String,
    /// 아키텍처. dpkg 의 `Architecture`, apk 의 `A:`.
    pub arch: String,
    /// 이 패키지를 만든 원본 패키지. dpkg 의 `Source`, apk 의 `o:`(origin).
    ///
    /// 없으면 빈 문자열이고, 그때는 이름이 곧 원본이다. `php8.2-cli` 의
    /// `source` 가 `php8.2` 이므로 **계열 하나를 한 줄로 겨눌 수 있다.**
    pub source: String,
    /// 어느 DB 에서 읽었는가. `dpkg` · `apk` · `rpm`(코어 1.3.0).
    pub manager: String,
    /// 공급사 — RPM 의 `VENDOR`(`Red Hat, Inc.` · `Oracle America` · `SUSE LLC …`) (2026-11-09 · 코어 1.3.0).
    ///
    /// **같은 판 문자열을 여러 공급사가 낸다** — RHEL 의 `8.0.30-8.el9_8.1` 을 다시 지은 Rocky · Alma 도 같은
    /// 판을 적는다. 공급사 공지는 그 공급사의 빌드에만 말하므로 룰이 이 칸으로 가른다. dpkg · apk 에는 이
    /// 칸이 없어 비고, **비면 산출물에 싣지 않는다** — 그 기계들의 스냅샷은 전과 바이트까지 같다.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vendor: String,
}

/// 이름 있는 UNIX 소켓 (Linux · `/proc/net/unix` · 코어 1.2.0).
///
/// Ebury 의 현재 주 탐지법이 **추상 소켓 이름**이다(ESET 공개 점검 스크립트 —
/// `@/run/systemd/log` · `@event-0YsOG9WSOE` 처럼 정상 경로를 흉내 낸 이름). 이
/// 엔진은 정적 바이너리라 사용자 영역 루트킷이 `libc` 를 가로채 그 줄을 숨겨도
/// 속지 않는다 — `/proc/net/unix` 를 시스템 호출로 직접 읽는다.
///
/// 찾기 전용이다 — 소켓을 닫는 Op 은 없고 있어서도 안 된다(설계-01 D11). 판정은
/// 그 소켓을 연 상주 임플란트의 존재를 말할 뿐이다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixSocketRecord {
    /// `/proc/net/unix` 가 보여 주는 이름 그대로. **추상 소켓은 `@` 로 시작한다**
    /// (커널이 앞의 NUL 을 `@` 로 적는다) — 같은 글자의 파일 소켓 경로와 다른 것이다.
    pub name: String,
    pub inode: u64,
    /// 연결을 받으려고 듣고 있는가(`Flags` 의 `__SO_ACCEPTCON`, `0x10000`).
    pub listening: bool,
    /// `stream` · `dgram` · `seqpacket`. 그 밖의 값은 `type-<16진>` 그대로다.
    pub kind: String,
}

/// 프록시 설정.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfigRecord {
    /// `user` 또는 `system`.
    pub scope: String,
    pub server: String,
    pub pac_url: String,
    pub bypass: String,
}

/// 방화벽 규칙.
///
/// `av_exclusion`·`proxy_config` 와 같은 부류다 — **악성코드가 건드리는 보안
/// 설정이고, 되돌려 놓아야 한다.** 자기 인바운드를 허용하거나 보안 제품의
/// 아웃바운드를 막는 규칙이 여기 남는다.
///
/// 빈 문자열은 "그 규칙에 그 항목이 없다" 다. Windows 는 지정하지 않은 항목을
/// 아예 적지 않으므로, `local_port` 가 비었다는 것은 **모든 포트**라는 뜻이다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRuleRecord {
    /// 규칙 식별자. Windows 에서는 레지스트리 값 이름이다.
    pub id: String,
    /// 표시 이름. `@FirewallAPI.dll,-32765` 같은 **간접 참조일 수 있다** —
    /// 문자열 자원을 풀려면 DLL 을 로드해야 하고, 악성코드는 대개 리터럴을
    /// 적으므로 원문 그대로가 탐지에 더 쓸모 있다.
    pub name: String,
    /// `In` 또는 `Out`.
    pub direction: String,
    /// `Allow` 또는 `Block`.
    pub action: String,
    pub enabled: bool,
    /// IANA 번호. `6`=TCP, `17`=UDP. 비면 모든 프로토콜.
    pub protocol: String,
    pub local_port: String,
    pub remote_port: String,
    /// 원격 주소 제한. `LocalSubnet` 같은 이름일 수 있다.
    pub remote_address: String,
    /// 이 규칙이 걸린 실행 파일.
    pub application: String,
    /// 이 규칙이 걸린 서비스.
    pub service: String,
    /// `Domain` · `Private` · `Public`. 여럿이면 쉼표로 잇는다.
    pub profile: String,
    /// 이 규칙을 읽은 자리. 치료가 어디를 되돌려야 하는지 여기서 안다.
    pub source: String,
}
