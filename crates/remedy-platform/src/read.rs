//! 읽기 trait. **이 파일에 파괴 동작이 들어오면 분리가 무의미해진다.**

use crate::PlatformError;

/// 파일 시스템 항목. OS 중립이다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEntry {
    /// 정규화된 절대 경로. 32비트 프로세스라도 **룰이 적는 경로**를 담는다
    /// (`Sysnative` 가 아니라 `System32`).
    pub path: String,
    pub is_dir: bool,
    /// 심볼릭 링크·정션인가.
    ///
    /// 재귀 순회는 여기서 멈춘다. 따라가면 같은 파일을 두 번 세거나 순환하고,
    /// 파괴 단계에서는 재귀 삭제가 링크된 디렉터리로 번진다 (설계-02 §4).
    pub is_reparse: bool,
    pub size: u64,
    pub mtime: String,
    pub ctime: Option<String>,
    /// Unix 권한 비트. Windows 에서는 `None`.
    ///
    /// **실행 비트가 뜻을 갖는 자리가 있다.** `run-parts` 는 `/etc/cron.daily`
    /// 아래에서 실행 비트가 없는 파일을 건너뛰므로, 그것을 모르면 돌지도 않는
    /// 스크립트를 "활성 지속성" 으로 보고하게 된다.
    pub mode: Option<u32>,
}

/// 순회 결과.
///
/// 개수만 돌려주지 않는 이유는 **"없다" 와 "못 봤다" 가 달라서**다. 접근이 거부된
/// 디렉터리를 조용히 건너뛰고 빈 목록을 돌려주면, 비관리자로 돌린 수집이
/// "예약 작업 없음" 으로 보고되고 그 스냅샷으로 "위협 없음" 이 결론난다.
#[derive(Debug, Default)]
pub struct WalkResult {
    pub entries: Vec<FsEntry>,
    /// 상한에 걸려 잘렸는가.
    pub truncated: bool,
    /// 접근이 거부되어 열지 못한 디렉터리 수. **전부 센다.**
    pub denied: usize,
    /// 그중 **앞의 몇 개** 경로 ([`DENIED_SAMPLE`] 까지).
    ///
    /// # 왜 개수만으로는 모자랐나 (2026-09-14)
    ///
    /// `%ProgramFiles%` 수집이 `denied_dirs=2` 를 내 P2 가 미결로 끝났는데,
    /// **어느 폴더인지 아무 데도 없었다.** 회차가 끝난 뒤 게스트를 뒤졌을
    /// 때는 5,713개 폴더가 전부 열렸다 — 수집이 300초 도는 **그때만** 잠기는
    /// 자리였고, 그러면 사람은 영영 원인에 닿지 못한다.
    ///
    /// # 전수가 아니다
    ///
    /// 비관리자로 돌리면 거부가 수백이 될 수 있다. 표본만 담고 `denied` 는
    /// 그대로 전부 센다 — **길이가 `denied` 보다 작으면 잘린 것**이고, 그
    /// 사실이 두 값의 차이로 드러난다.
    pub denied_paths: Vec<String>,
}

/// 거부된 경로를 몇 개까지 담는가.
///
/// 원인을 짚기에 충분하고 산출물을 부풀리지 않는 수. 넘으면 `denied` 와
/// 길이가 갈라지고, 그 차이가 "표본이다" 라고 말한다.
pub const DENIED_SAMPLE: usize = 32;

pub trait FsRead {
    /// `root` 아래를 재귀로 훑는다.
    ///
    /// 반환 순서는 **결정적**이어야 한다. 순서가 흔들리면 같은 시스템을 두 번
    /// 수집한 스냅샷이 달라지고, 그러면 diff 가 아무것도 말해 주지 않는다.
    fn walk(&self, root: &str, limit: usize) -> Result<WalkResult, PlatformError>;

    /// 파일 본문. `max` 를 넘으면 `None` — 자르지 않는다. 잘린 내용으로 해시하면
    /// 그 해시는 아무 의미가 없다.
    fn read_file(&self, path: &str, max: u64) -> Result<Option<Vec<u8>>, PlatformError>;

    /// 이 경로를 **봤는가 · 없는가 · 못 물었는가** (B-9 · 2026-10-27).
    ///
    /// # 왜 참·거짓이 아닌가
    ///
    /// `exists() -> bool` 은 *"없다"* 와 *"못 물었다"* 를 한 값에 접는다. 선언한
    /// 루트의 부모까지 막힌 트리나 도달 불가 UNC 가 **없는 루트**로 집계되고,
    /// 열린 루트가 하나라도 함께 있으면 `all_roots_missing()` 이 성립하지 않아
    /// **경고 없는 종료 0** 이 나갔다(실측). 레지스트리 쪽은 처음부터 [`seen`] 으로
    /// 갈라 물었다 — *"없다고 말하려면 없는 것을 봐야 한다."*
    ///
    /// 그래서 백엔드가 답해야 하는 것을 **세 갈래로 바꿨다.** 기억이 아니라
    /// 컴파일러가 강제한다 (설계-04 §1 의 규율).
    fn look(&self, path: &str) -> Seen;

    /// 이 경로가 존재하는가. 없으면 열거를 건너뛴다.
    ///
    /// **[`FsRead::look`] 에서 파생된다** — `Present` 만 참이다. 걷기를 건너뛸지
    /// 묻는 자리는 이 답으로 충분하다(못 물은 루트는 걸을 수 없다). *"없다"* 와
    /// *"못 물었다"* 를 **가려야 하는 자리**는 `look` 을 쓴다.
    fn exists(&self, path: &str) -> bool {
        matches!(self.look(path), Seen::Present)
    }
}

/// 레지스트리 값. Windows 전용 개념이지만 trait 자체는 백엔드가 없으면
/// 구현되지 않을 뿐이다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Str(String),
    Dword(u32),
    /// 이진 값. **바이트를 들고 있어야** YARA 를 걸 수 있다 (설계-09 P4 —
    /// "바이트열 제공 필드 전반").
    Binary(Vec<u8>),
    /// 여러 문자열(`REG_MULTI_SZ`). Defender 제외 목록처럼 목록이 값 하나에
    /// 들어가는 자리가 있다.
    Multi(Vec<String>),
    Qword(u64),
    Other,
}

impl RegValue {
    /// 룰이 `data` 로 볼 값. 종류가 무엇이든 문자열 하나로 읽힌다.
    pub fn as_text(&self) -> String {
        match self {
            RegValue::Str(s) => s.clone(),
            RegValue::Dword(d) => d.to_string(),
            RegValue::Qword(q) => q.to_string(),
            RegValue::Multi(v) => v.join("\n"),
            // 16진 문자열이 아니라 **바이트 수**를 낸다. 이진 값을 문자열로
            // 견주는 룰은 어차피 뜻이 없다. 이 표기 위의 `yara` 는 평가기가
            // "재지 못했다" 로 친다 — 바이트가 레코드에 없기 때문이다.
            RegValue::Binary(b) => remedy_sdk::artifact::binary_placeholder(b.len(), false),
            RegValue::Other => String::new(),
        }
    }

    /// 룰이 `type` 으로 볼 이름. 레지스트리 자신의 이름을 그대로 쓴다.
    pub fn type_name(&self) -> &'static str {
        match self {
            RegValue::Str(_) => "REG_SZ",
            RegValue::Dword(_) => "REG_DWORD",
            RegValue::Qword(_) => "REG_QWORD",
            RegValue::Multi(_) => "REG_MULTI_SZ",
            RegValue::Binary(_) => "REG_BINARY",
            RegValue::Other => "REG_UNKNOWN",
        }
    }

    /// YARA 가 훑을 바이트. 없으면 그 규칙은 **미평가**다.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            RegValue::Binary(b) => Some(b.as_slice()),
            _ => None,
        }
    }
}

/// 안전 모드로 들어갈 수 있는가.
///
/// **모르는 것과 없는 것을 가른다.** `Unknown` 을 `No` 로 접으면 읽지 못한
/// 기계에 "복구 매체를 준비하라" 고 말하게 되고, `Yes` 로 접으면 부팅되지
/// 않는 컴퓨터를 만든다 (설계-00 §5-1·§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeBoot {
    /// `Minimal` 과 `Network` 가 둘 다 있고 읽힌다.
    Available,
    /// 하나만 있다. 진입은 될 수 있으나 온전하지 않다.
    Partial,
    /// 둘 다 없다. **안전 모드를 제안하면 안 된다.**
    Missing,
    /// **이름은 있는데 열리지 않는다.** 접근이 막혔다.
    ///
    /// 오래 `Missing` 으로 접혀 있었다. 그런데 실기기에서 **잠그는 쪽이 훨씬
    /// 싸다** — `SafeBoot` 하위 항목은 `TrustedInstaller` 소유에 `D:PAI` 라
    /// 지우려면 소유권을 100개 넘게 가져와야 하지만, `Deny ReadKey` 는 관리자
    /// 권한으로 한 번이면 된다 (2026-08-31 실측).
    ///
    /// 없는 것으로 접으면 두 가지를 함께 잃는다. 정책이 잠근 기업 기계에
    /// *"악성코드가 손댔을 수 있다"* 고 말하게 되고, 악성코드가 잠근 기계에서는
    /// **무엇을 했는지** 말하지 못한다.
    Unreadable,
    /// **아무것도 말할 수 없다.** 상위 키조차 열거하지 못했다.
    Unknown,
}

impl SafeBoot {
    pub const fn id(self) -> &'static str {
        match self {
            SafeBoot::Available => "yes",
            SafeBoot::Partial => "partial",
            SafeBoot::Missing => "no",
            SafeBoot::Unreadable => "unreadable",
            SafeBoot::Unknown => "unknown",
        }
    }
    /// 재시작을 제안해도 되는가. **`Partial` 은 안 된다** — 온전하지 않은
    /// 안전 모드는 들어갔다가 못 나오는 자리를 만든다.
    ///
    /// `Unreadable` 과 `Unknown` 도 안 된다. **모르는 것을 괜찮은 것으로 접지
    /// 않는다** — 새 값이 늘어도 이 함수가 `Available` 하나만 참인 이유다.
    pub const fn safe_to_suggest(self) -> bool {
        matches!(self, SafeBoot::Available)
    }

    /// 손상을 **본** 것인가, **보지 못한** 것인가.
    ///
    /// 둘 다 재시작을 막지만 사람에게 할 말이 다르다 — 앞은 *"악성코드가
    /// 손댔을 수 있다"* 이고 뒤는 *"확인하지 못했다"* 다. 설계-00 §5-1 이
    /// **접근 거부의 원인을 구분해 보고하라**고 요구하는 자리이기도 하다.
    pub const fn observed_damage(self) -> bool {
        matches!(self, SafeBoot::Partial | SafeBoot::Missing)
    }
}

/// 재시작을 제안하기 전에 반드시 보는 것 (설계-00 §6).
///
/// 악성코드는 **안전 모드 진입을 막는다.** `SafeBoot` 키를 지우는 것이 흔한
/// 수법이고, 그 상태에서 "안전 모드로 재시작하세요" 라고 하면 사용자는
/// **부팅되지 않는 컴퓨터를 받는다.** 같은 문제가 일반 재부팅 제안에도 있다 —
/// `verify_after_reboot` 와 재부팅 삭제(`file.delete_on_reboot`)가 재부팅을 전제하기
/// 때문이다.
///
/// **v1 은 탐지만 한다.** `SafeBoot` 하위에는 수백 개 항목이 있어 카탈로그
/// 복원이 현실적이지 않고, 어설픈 복원은 더 나쁜 상태를 만든다. 복원은 OS
/// 복구 도구의 영역이다. 다만 **알지 못한 채 권하는 것**이 이 결함의 본체이므로
/// 탐지는 반드시 한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootHealth {
    pub safeboot: SafeBoot,
    /// 복구 환경이 켜져 있는가. **BCD 는 마운트되어 있지 않아 아직 모른다** —
    /// 읽지 못한 것을 "꺼져 있다" 로 적지 않는다.
    pub recovery_enabled: Option<bool>,
}

impl BootHealth {
    /// 재시작을 제안해도 되는가.
    ///
    /// 복구 환경을 **모르는 것은 막지 않는다.** 그것까지 막으면 BCD 를 읽지
    /// 못하는 모든 기계에서 재부팅 제안이 사라지는데, 지금은 모든 기계가
    /// 그렇다. 막는 것은 확실히 나쁜 것 하나 — 안전 모드가 없는 경우다.
    pub const fn may_suggest_restart(&self) -> bool {
        self.safeboot.safe_to_suggest() && !matches!(self.recovery_enabled, Some(false))
    }
}

/// 이 실행이 **기계를 고칠 수 있는 권한**을 가졌는가.
///
/// # 왜 묻는가
///
/// 전용백신이 하는 일은 대부분 관리자를 요구한다. 권한 없이 돌면 예약 작업
/// 디렉터리를 열지 못하고(실측: 표준 사용자로 `System32\Tasks` 접근 거부),
/// 감염된 기계에서 **증거 0건**이 나온다. 그것을 "위협 없음" 으로 읽지 않게
/// 막는 장치는 따로 있지만(`Observation`), **애초에 그 자리에 가지 않는 편이
/// 낫다** — 실패는 첫 줄에서 한 문장으로 말해야 한다.
///
/// # 관리자라고 다 되는 것은 아니다
///
/// 이 함수가 `Some(true)` 라도 못 하는 일이 남는다 — 변조 방지가 막는 Defender
/// 예외 키, `TrustedInstaller` 가 소유한 `SafeBoot` 하위, 보호 프로세스의
/// 명령줄(실측 2026-08-31: 관리자 세션에서 159개 중 19개). 그래서 이 검사는
/// **관측 완전성 보고를 대신하지 않는다.** 둘 다 필요하다.
///
/// `None` 은 **재지 못했다**는 뜻이다. 모르는 것을 "괜찮다" 로 접지 않는다 —
/// 부르는 쪽이 거절한다.
pub fn elevated() -> Option<bool> {
    platform_elevated()
}

/// Windows — **예약 작업 디렉터리를 열어 본다.**
///
/// 토큰을 직접 묻는 길(`GetTokenInformation`)은 `unsafe` 를 요구하고, 이
/// 크레이트는 `forbid` 를 지킨다(설계-04 §1). 그래서 **관리자만 열 수 있는
/// 자리를 하나 골라 읽어 본다.**
///
/// # 왜 하필 이 자리인가
///
/// `System32\Tasks` 는 이 도구가 **반드시 읽어야 하는 곳**이고, 못 읽었을 때
/// 실제로 손해가 나는 곳이다(실측 2026-08-31: 표준 사용자로 감염 기계를 훑으면
/// 이 디렉터리가 거부되고 증거가 0건이 된다). 권한 질문의 대리 지표가 아니라
/// **질문 그 자체**다.
///
/// 그리고 **읽기다.** 레지스트리에 시험 삼아 써 보는 방법도 있지만, 그것은
/// 죽으면 찌꺼기를 남기고 어떤 환경에서는 가상화되어 거짓으로 통과한다
/// (실측: 샌드박스 안에서 `HKLM\SYSTEM\CurrentControlSet\Services` 에 값이
/// 써졌다). 아무것도 바꾸지 않는 검사가 옳다.
///
/// 이 방법은 **상승하지 않은 관리자 토큰도 걸러 낸다** — 그 토큰에서 관리자
/// 그룹은 거부 전용이라 접근 검사가 그대로 떨어진다. 그것이 정확히 우리가
/// 원하는 구분이다.
#[cfg(windows)]
fn platform_elevated() -> Option<bool> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    match std::fs::read_dir(format!(r"{root}\System32\Tasks")) {
        Ok(_) => Some(true),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Some(false),
        // 거부가 아닌 오류는 **모른다** 다. Vista 이후 어느 Windows 에나 있는
        // 자리이므로, 없다면 이 기계에 대해 우리가 모르는 일이 벌어지고 있다.
        Err(_) => None,
    }
}

/// Linux — 유효 UID 가 0 인가.
///
/// `/proc/self/status` 의 `Uid:` 줄은 `실제 유효 저장 파일시스템` 넷을 준다.
/// **`libc::geteuid` 를 부르지 않는 이유**는 그것이 `unsafe` 이고, 이 크레이트가
/// 그것을 금지하기 때문이다. `/proc` 은 리눅스 수집기가 이미 전제하는 것이라
/// 새로 기대는 것이 없다.
#[cfg(unix)]
fn platform_elevated() -> Option<bool> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    euid_is_root(&text)
}

/// `/proc/self/status` 에서 **유효 UID** 를 읽는다.
///
/// 그 줄은 `Uid:` 뒤에 `실제 유효 저장 파일시스템` 넷을 탭으로 준다. 우리가
/// 물어야 하는 것은 **유효(effective) UID** 다 — 실제 UID 로 판단하면 권한을
/// 내려놓았다 다시 올릴 수 있는 실행을 "권한 없음" 이라 말하게 된다.
///
/// 순수 함수로 떼어 둔 이유는 여기가 이 검사에서 유일하게 틀릴 수 있는
/// 자리이기 때문이다. 파일을 읽는 부분은 틀릴 데가 없다.
#[cfg(unix)]
fn euid_is_root(status: &str) -> Option<bool> {
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    let euid = line.split_whitespace().nth(2)?;
    Some(euid == "0")
}

#[cfg(not(any(windows, unix)))]
fn platform_elevated() -> Option<bool> {
    None
}

/// 안전 모드 하위 키가 사는 자리.
pub const SAFEBOOT_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot";

/// 위 키가 사는 자리와 그 이름. **열거로 이름을 보기 위해 따로 든다.**
///
/// 아래 [`seen`] 참조 — 이름이 목록에 있는지와 열리는지는 다른 질문이고,
/// 그 둘을 가르려면 부모를 열거해야 한다. 셋이 갈라지지 않는 것은 시험이 본다.
pub const SAFEBOOT_PARENT: &str = r"HKLM\SYSTEM\CurrentControlSet\Control";
pub const SAFEBOOT_NAME: &str = "SafeBoot";

/// 부팅 건전성을 읽는다.
///
/// # 왜 여기 있는가
///
/// 두 곳이 이것을 묻는다 — 수집기는 **관찰로**(`boot_config` subject),
/// 실행기는 **재시작을 제안하기 전에**. `remedy-apply` 는 `remedy-collect` 를
/// 의존할 수 없으므로(설계-04 §1) 판정을 양쪽에 적으면 갈라진다. 공통 조상인
/// 여기 한 곳에 둔다.
pub fn boot_health<R: RegistryRead>(reg: &R) -> BootHealth {
    BootHealth {
        safeboot: safeboot_state(reg),
        recovery_enabled: None,
    }
}

/// 키 하나가 **없는가, 잠겼는가, 있는가.**
///
/// 이 판정이 필요한 자리는 안전 모드만이 아니다. 수집기도 같은 질문을 한다 —
/// *"이 키가 없는 것인가, 내가 못 읽는 것인가."* 두 곳이 각자 답하면 언젠가
/// 갈라지므로 여기 하나만 둔다(설계-04 §1 — 판정은 공통 조상에).
///
/// # 왜 `key_exists` 하나로는 안 되는가
///
/// `key_exists` 는 여는 데 실패하면 `false` 다 — **없는 것과 못 여는 것을 같게
/// 본다.** 그런데 부모를 열거하면 `RegEnumKeyEx` 는 **자식의 ACL 과 무관하게
/// 이름을 준다** (2026-08-31 실측: `Network` 에 `Deny ReadKey` 를 건 직후에도
/// 부모 열거는 여전히 `Minimal, Network` 를 돌려주었고 `Network` 자체는 열리지
/// 않았다). 그 둘을 겹쳐 보면 세 갈래가 선다.
pub fn seen<R: RegistryRead>(reg: &R, parent: &str, name: &str) -> Seen {
    let Ok(names) = reg.subkeys(parent) else {
        return Seen::CannotTell;
    };
    if !names.iter().any(|x| x.eq_ignore_ascii_case(name)) {
        return Seen::Absent;
    }
    if reg.key_exists(&format!("{parent}\\{name}")) {
        Seen::Present
    } else {
        Seen::Locked
    }
}

/// [`seen`] 의 세 갈래 — 그리고 "모른다".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    Present,
    /// 목록에는 있는데 열리지 않는다.
    Locked,
    Absent,
    /// 부모를 열거하지 못했다.
    CannotTell,
}

/// 안전 모드 진입 가능성.
///
/// **없다고 말하려면 없는 것을 봐야 한다.** 못 읽은 자리는 `Unreadable` 이나
/// `Unknown` 이고, 둘 다 재시작을 막지만 *손상을 봤다*고 주장하지는 않는다
/// (설계-00 §5-1 — 접근 거부의 원인을 구분해 보고한다).
fn safeboot_state<R: RegistryRead>(reg: &R) -> SafeBoot {
    match seen(reg, SAFEBOOT_PARENT, SAFEBOOT_NAME) {
        Seen::Absent => return SafeBoot::Missing,
        Seen::Locked => return SafeBoot::Unreadable,
        Seen::CannotTell => return SafeBoot::Unknown,
        Seen::Present => {}
    }
    let minimal = seen(reg, SAFEBOOT_KEY, "Minimal");
    let network = seen(reg, SAFEBOOT_KEY, "Network");
    match (minimal, network) {
        (Seen::Present, Seen::Present) => SafeBoot::Available,
        // **모른다가 없다를 이긴다.** 하나라도 읽지 못했으면 나머지가 무엇이든
        // "없다" 고 단정할 수 없다.
        (Seen::CannotTell, _) | (_, Seen::CannotTell) => SafeBoot::Unknown,
        (Seen::Locked, _) | (_, Seen::Locked) => SafeBoot::Unreadable,
        (Seen::Absent, Seen::Absent) => SafeBoot::Missing,
        _ => SafeBoot::Partial,
    }
}

pub trait RegistryRead {
    /// `HKLM\SOFTWARE\...` 형태의 경로에서 값을 읽는다.
    fn value(&self, key: &str, name: &str) -> Result<Option<RegValue>, PlatformError>;
    /// 하위 키 이름.
    fn subkeys(&self, key: &str) -> Result<Vec<String>, PlatformError>;
    /// 키가 가진 값 **전부**. 이름 순으로 준다.
    ///
    /// 이름을 미리 알아야 읽을 수 있는 `value` 만으로는 `registry_value` subject
    /// 가 성립하지 않는다 — 악성코드가 쓰는 값 이름을 미리 알 수 없기 때문이다.
    fn values(&self, key: &str) -> Result<Vec<(String, RegValue)>, PlatformError>;
    /// 키 자체가 있는가. 없는 것과 못 읽는 것을 가르는 데 쓴다.
    fn key_exists(&self, key: &str) -> bool;
}

/// 돌고 있는 프로세스 하나. OS 중립이다.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawProcess {
    pub pid: u32,
    pub ppid: u32,
    pub image_path: String,
    /// 실행 파일까지 포함한 명령 전체.
    pub cmdline: String,
    /// 실행 파일을 뺀 인자.
    pub args: String,
    pub user: String,
    /// RFC3339 UTC.
    pub start_time: String,
    /// 실린 모듈의 경로. **플랫폼마다 있는 것이 다르다** —
    /// [`ProcessRead::processes`] 가 어느 쪽이 채우는지 적는다.
    pub modules: Vec<String>,
    /// 모듈 목록을 **묻고 거부당했는가.**
    ///
    /// 빈 목록만으로는 *"모듈이 없다"* 와 *"못 읽었다"* 가 구분되지 않는다.
    /// 뒤엣것은 거부로 세어 종료 코드 6 으로 말해야 한다 — 레지스트리 쪽
    /// `unreadable_or_absent` 와 같은 규율이다.
    ///
    /// **사라진 프로세스는 여기 들어오지 않는다.** 열거와 읽기 사이에 끝난
    /// 프로세스는 정상이고, 그것을 거부로 세면 모든 회차가 관측 불완전이 된다.
    pub modules_denied: bool,
}

pub trait ProcessRead {
    /// 지금 돌고 있는 프로세스. **pid 순으로** 준다.
    ///
    /// # 모듈 목록은 Linux 만 준다
    ///
    /// | 플랫폼 | `modules` | 왜 |
    /// |---|---|---|
    /// | Linux | **채운다** — `/proc/<pid>/maps` 의 실행 가능한 파일 매핑 | 읽기 하나다. unsafe 가 필요 없다 |
    /// | Windows | 빈 목록 | 열거에 `EnumProcessModules`(또는 `CreateToolhelp32Snapshot`)가 필요하고 그것은 unsafe 다. 이 크레이트는 `forbid(unsafe_code)` 를 유지한다 |
    ///
    /// 빈 목록을 *"모듈이 없다"* 로 읽으면 안 되는 자리가 Windows 에 남는다.
    /// 그 사실은 `Subject::NOT_POPULATED_YET` 이 `Some(Platform::Windows)` 로
    /// 들고 있어서 **린트와 평가기가 작성자에게 직접 말한다.**
    fn processes(&self) -> Result<Vec<RawProcess>, PlatformError>;
}

/// 환경변수 전개. 수집 시점의 것이며, **평가기는 이것을 쓰지 않는다.**
///
/// 평가가 기계의 환경에 좌우되면 같은 스냅샷을 두 번 평가한 결과가 달라진다.
pub trait EnvRead {
    fn expand(&self, s: &str) -> String;

    /// 계정의 프로필 폴더 — 예약 작업의 `principal`(SID 또는 계정 이름)을 받는다.
    ///
    /// 작업 계정의 변수(`%LOCALAPPDATA%` 등)를 **그 계정의 자리로** 펴는 데 쓴다
    /// (`WinTaskFields::args_expanded`). 모르면 `None` 이고 **기본은 모른다** — 프로필
    /// 목록이 없는 백엔드(Linux · 시험용)가 그렇다. 지어내지 않는다.
    fn profile_of(&self, principal: &str) -> Option<String> {
        let _ = principal;
        None
    }

    /// 이 엔진을 돌리는 계정의 SID(Windows). 모르면 `None` — 기본은 모른다.
    ///
    /// 로그온한 다른 사용자의 Run 값을 `HKU\<SID>` 에서 모을 때(코어 1.2.0) **자기
    /// 하이브를 빼는 데** 쓴다 — `HKCU` 와 같은 하이브라 함께 모으면 한 값을 두 번
    /// 지우려 든다. 모르면 `HKU` 쪽을 모으지 않는다(`registry::autoruns`).
    fn own_sid(&self) -> Option<String> {
        None
    }
}

/// `scan_root` 하나를 편 결과.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootExpansion {
    pub roots: Vec<String>,
    /// 펼치는 동안 알게 된 사실. **조용히 사라지면 안 된다** — 토큰이 아무것도
    /// 되지 못한 실행은 그 범위를 0건으로 보고하고, 그것은 "없다" 로 읽힌다.
    pub notes: Vec<String>,
}

/// 지정 확장 토큰을 실제 경로들로 편다 (설계-02 §4).
///
/// **하나가 여럿이 될 수 있다.** `%ALLUSERPROFILES%` 는 사용자 수만큼,
/// `%REMOVABLE%` 는 꽂힌 매체 수만큼, `HKU\*` 는 로그온한 하이브 수만큼이다.
/// 1:1 로 다루면 이 토큰들이 전개되지 않은 채 경로로 쓰이고, 존재하지 않는
/// 경로가 되어 **조용히 0건**이 된다.
///
/// `%ALLUSERPROFILES%` 가 없으면 다중 사용자 환경에서 현재 로그온 사용자만
/// 치료되고 나머지는 감염 상태로 남는다 (설계-02 §4).
pub trait ExpandRoots {
    /// `allow_removable` 은 매니페스트의 선언이다. `%REMOVABLE%` 는 그것 없이
    /// 펼쳐지지 않는다 — 이동식 매체를 건드리는 것은 사용자가 예상하지 못하는
    /// 일이고, 선언이 그 동의를 대신한다 (설계-03 §4).
    fn expand_roots(&self, root: &str, allow_removable: bool) -> RootExpansion;
}

// ─────────────────────────────────────────────────────── 백엔드가 없는 플랫폼
//
// Windows 도 Linux 도 아닌 곳이다. macOS 가 여기 있다.
//
// `live()` 가 `None` 을 돌려주는 플랫폼에서도 **상위 코드는 컴파일되어야 한다.**
// 파이프라인은 OS 중립이고(그것이 P12 의 전제다) `remedy_platform::live()` 하나로
// 갈린다. 그런데 `Infallible` 이 이 trait 들을 구현하지 않으면 파이프라인 본문이
// 타입 검사를 통과하지 못한다 — 실제로 P2 에서 Linux 컴파일이 그렇게 깨졌고,
// CI 가 한 번도 돌지 않아 아무도 몰랐다.
//
// 모든 메서드 본문이 `match *self {}` 인 것은 눈속임이 아니다. `Infallible` 은
// **값이 존재할 수 없는 타입**이므로 이 코드에 도달하는 길이 언어 수준에서 없다.
// 빈 결과를 돌려주는 가짜 백엔드였다면 "수집하지 못했다" 와 "없다" 가 뭉뚱그려졌을
// 텐데, 여기서는 애초에 호출이 불가능하다.
#[cfg(not(any(windows, target_os = "linux")))]
mod no_backend {
    use super::*;
    use std::convert::Infallible;

    impl FsRead for Infallible {
        fn walk(&self, _root: &str, _limit: usize) -> Result<WalkResult, PlatformError> {
            match *self {}
        }
        fn read_file(&self, _path: &str, _max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
            match *self {}
        }
        fn look(&self, _path: &str) -> Seen {
            match *self {}
        }
    }

    impl RegistryRead for Infallible {
        fn value(&self, _key: &str, _name: &str) -> Result<Option<RegValue>, PlatformError> {
            match *self {}
        }
        fn subkeys(&self, _key: &str) -> Result<Vec<String>, PlatformError> {
            match *self {}
        }
        fn values(&self, _key: &str) -> Result<Vec<(String, RegValue)>, PlatformError> {
            match *self {}
        }
        fn key_exists(&self, _key: &str) -> bool {
            match *self {}
        }
    }

    impl ProcessRead for Infallible {
        fn processes(&self) -> Result<Vec<RawProcess>, PlatformError> {
            match *self {}
        }
    }

    impl EnvRead for Infallible {
        fn expand(&self, _s: &str) -> String {
            match *self {}
        }
    }

    impl ExpandRoots for Infallible {
        fn expand_roots(&self, _root: &str, _allow_removable: bool) -> RootExpansion {
            match *self {}
        }
    }
}

#[cfg(test)]
mod boot_tests {
    use super::*;
    use std::collections::BTreeMap;

    /// **여러 값이 `data` 에 어떻게 실리는가.** 룰이 `REG_MULTI_SZ` 값에
    /// 조건을 걸려면 이것을 알아야 하는데, 아는 곳이 이 한 줄뿐이라 문서가
    /// 추측하게 만든다. 여기서 고정하고 `registry_value.type` 의 설명이
    /// 그 사실을 말한다.
    ///
    /// 2026-09-02 `hijack-r2` 응시자가 *"구분자가 무엇인지 몰라 조건에 넣지
    /// 않았다 — 넣고 틀리면 오류 없이 조용히 안 맞는다"* 고 적어 드러났다.
    #[test]
    fn multi_sz_values_are_joined_with_newlines() {
        let v = RegValue::Multi(vec!["autocheck autochk *".into(), "bootalyac.exe".into()]);
        assert_eq!(v.as_text(), "autocheck autochk *\nbootalyac.exe");
        assert_eq!(v.type_name(), "REG_MULTI_SZ");
    }

    /// **빈 항목은 빈 줄이 된다.** 수집기가 그것을 버리던 동안 이 자리는 물어볼
    /// 수조차 없었다 — 실기기의 `BootExecute` 는 빈 항목을 품는데 스냅샷은
    /// 그것을 지운 모양으로 적혔다 (2026-09-05).
    ///
    /// 룰 작성자에게 이것이 뜻하는 바: `ends_with`·`starts_with` 를 이 필드에
    /// 걸면 빈 항목 하나에 부서진다. 카탈로그의 `registry_value.type` 설명이
    /// 그 사실을 말한다.
    #[test]
    fn an_empty_multi_sz_item_shows_up_as_an_empty_line() {
        let v = RegValue::Multi(vec![
            "autocheck autochk *".into(),
            String::new(),
            "bootalyac.exe".into(),
        ]);
        assert_eq!(v.as_text(), "autocheck autochk *\n\nbootalyac.exe");
        assert!(
            v.as_text().contains("bootalyac.exe"),
            "contains 는 빈 항목이 있어도 선다"
        );
    }

    /// **이진 값은 바이트 수만 적힌다** — 그 표기 위의 `yara` 를 평가기가
    /// "재지 못했다" 로 알아봐야 한다(결정 2026-10-26). 알아보지 못하면 17바이트
    /// 남짓의 표기를 훑어 *"안 맞았다"* 가 된다.
    #[test]
    fn a_binary_value_is_written_as_a_placeholder_the_evaluator_knows() {
        let v = RegValue::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(v.as_text(), "<binary 4 bytes>");
        assert!(remedy_sdk::artifact::is_binary_placeholder(&v.as_text()));
    }

    /// **열거와 열기를 따로 흉내 낸다.** 실기기에서 둘이 갈리기 때문이다 —
    /// 자식에 `Deny ReadKey` 를 걸면 부모 열거에는 이름이 남고 여는 것만
    /// 막힌다. 이 둘을 같게 흉내 내는 가짜는 그 자리를 영영 잴 수 없다.
    #[derive(Default)]
    struct Reg {
        /// 부모 경로 → 그 아래 이름 목록.
        listed: BTreeMap<String, Vec<String>>,
        /// 실제로 열리는 키.
        openable: Vec<String>,
        /// 열거가 실패하는 부모.
        blind: Vec<String>,
    }
    impl RegistryRead for Reg {
        fn value(&self, _k: &str, _n: &str) -> Result<Option<RegValue>, PlatformError> {
            Ok(None)
        }
        fn subkeys(&self, key: &str) -> Result<Vec<String>, PlatformError> {
            if self.blind.iter().any(|b| b == key) {
                return Err(PlatformError::Refused("열거할 수 없다".into()));
            }
            Ok(self.listed.get(key).cloned().unwrap_or_default())
        }
        fn values(&self, _k: &str) -> Result<Vec<(String, RegValue)>, PlatformError> {
            Ok(Vec::new())
        }
        fn key_exists(&self, key: &str) -> bool {
            self.openable.iter().any(|k| k == key)
        }
    }

    /// `Minimal`·`Network` 각각을 `있음` · `잠김` · `없음` 으로 세운다.
    fn machine(minimal: Option<bool>, network: Option<bool>) -> Reg {
        let mut r = Reg {
            listed: BTreeMap::from([(
                SAFEBOOT_PARENT.to_string(),
                vec![SAFEBOOT_NAME.to_string()],
            )]),
            openable: vec![SAFEBOOT_KEY.to_string()],
            blind: Vec::new(),
        };
        let mut names = Vec::new();
        for (name, state) in [("Minimal", minimal), ("Network", network)] {
            // None = 없다 · Some(false) = 이름은 있는데 안 열린다 · Some(true) = 있다
            let Some(open) = state else { continue };
            names.push(name.to_string());
            if open {
                r.openable.push(format!("{SAFEBOOT_KEY}\\{name}"));
            }
        }
        r.listed.insert(SAFEBOOT_KEY.to_string(), names);
        r
    }

    fn with(modes: &[&str]) -> BootHealth {
        let has = |m: &str| modes.contains(&m).then_some(true);
        boot_health(&machine(has("Minimal"), has("Network")))
    }

    #[test]
    fn both_modes_present_means_we_may_suggest_a_restart() {
        let h = with(&["Minimal", "Network"]);
        assert_eq!(h.safeboot, SafeBoot::Available);
        assert!(h.may_suggest_restart());
    }

    #[test]
    fn a_missing_safeboot_key_stops_the_suggestion() {
        // **이것이 이 검사의 본체다** (설계-00 §6). 악성코드가 `SafeBoot` 를
        // 지운 기계에 "안전 모드로 재시작하세요" 라고 하면 사용자는 부팅되지
        // 않는 컴퓨터를 받는다.
        let h = with(&[]);
        assert_eq!(h.safeboot, SafeBoot::Missing);
        assert!(!h.may_suggest_restart(), "권하면 안 되는데 권한다");
    }

    #[test]
    fn only_one_mode_is_not_good_enough() {
        // 악성코드가 `Minimal` 만 지우는 경우가 있다. "있다" 로 뭉뚱그리면
        // 온전하지 않은 안전 모드로 안내하게 된다.
        for one in ["Minimal", "Network"] {
            let h = with(&[one]);
            assert_eq!(h.safeboot, SafeBoot::Partial, "{one}");
            assert!(!h.may_suggest_restart(), "{one} 하나뿐인데 권한다");
        }
    }

    #[test]
    fn the_three_names_of_one_key_do_not_drift() {
        // 자리를 두 번 적었다 — 열거하려면 부모가 따로 필요했기 때문이다.
        // 갈라지면 `seen` 이 엉뚱한 부모를 열거하고, 그러면 언제나 `Absent` 다.
        assert_eq!(format!("{SAFEBOOT_PARENT}\\{SAFEBOOT_NAME}"), SAFEBOOT_KEY);
    }

    #[test]
    fn a_locked_key_is_not_a_missing_one() {
        // **이것이 이 변경의 본체다.** 이름은 목록에 있는데 열리지 않는다.
        // 실기기에서 잠그는 쪽이 지우는 쪽보다 훨씬 싸다 — 지우려면 자손
        // 100개 넘게 소유권을 가져와야 하고, 잠그는 것은 한 번의 호출이다.
        let h = boot_health(&machine(Some(false), Some(true)));
        assert_eq!(h.safeboot, SafeBoot::Unreadable);
        assert!(!h.may_suggest_restart(), "읽지도 못했는데 권한다");
        assert!(
            !h.safeboot.observed_damage(),
            "보지 못한 것을 손상으로 보고하면 정책이 잠근 기계에 오탐이 된다"
        );
    }

    #[test]
    fn not_reading_beats_not_finding() {
        // 하나는 잠기고 하나는 없다. **"없다" 고 단정할 수 없다** — 잠긴 쪽이
        // 무엇인지 보지 못했기 때문이다.
        let h = boot_health(&machine(Some(false), None));
        assert_eq!(h.safeboot, SafeBoot::Unreadable);
    }

    #[test]
    fn a_blind_parent_says_nothing_at_all() {
        // 상위 키조차 열거하지 못하면 안전 모드에 대해 말할 것이 없다.
        // `Missing` 으로 접으면 읽지 못한 기계에 "복구 매체를 준비하라" 고 한다.
        let mut r = machine(Some(true), Some(true));
        r.blind.push(SAFEBOOT_KEY.to_string());
        let h = boot_health(&r);
        assert_eq!(h.safeboot, SafeBoot::Unknown);
        assert!(!h.may_suggest_restart());
        assert!(!h.safeboot.observed_damage());

        // 그 위가 막혀도 마찬가지다.
        let mut r = machine(Some(true), Some(true));
        r.blind.push(SAFEBOOT_PARENT.to_string());
        assert_eq!(boot_health(&r).safeboot, SafeBoot::Unknown);
    }

    #[test]
    fn a_safeboot_key_that_is_not_there_at_all_is_missing() {
        // 상위 열거에 이름 자체가 없다 = 정말 없다. 이것만 `Missing` 이다.
        let mut r = machine(Some(true), Some(true));
        r.listed.insert(SAFEBOOT_PARENT.to_string(), Vec::new());
        let h = boot_health(&r);
        assert_eq!(h.safeboot, SafeBoot::Missing);
        assert!(h.safeboot.observed_damage(), "본 것은 봤다고 말해야 한다");
    }

    #[test]
    fn the_locked_state_has_its_own_id() {
        // 이 문자열이 `boot_config` 레코드로 나가고 룰이 그것을 본다.
        // 이름이 바뀌면 이미 배포된 룰이 조용히 매치되지 않는다.
        assert_eq!(SafeBoot::Unreadable.id(), "unreadable");
        assert_eq!(SafeBoot::Unknown.id(), "unknown");
        assert_eq!(SafeBoot::Available.id(), "yes");
        assert_eq!(SafeBoot::Partial.id(), "partial");
        assert_eq!(SafeBoot::Missing.id(), "no");
    }

    #[test]
    fn recovery_known_to_be_off_also_stops_it() {
        // 지금은 BCD 를 읽지 못해 언제나 `None` 이지만, 읽게 되는 날 이 성질이
        // 이미 있어야 한다. `None`(모른다)은 막지 않고 `Some(false)`만 막는다 —
        // 모르는 것까지 막으면 모든 기계에서 재부팅 제안이 사라진다.
        let mut h = with(&["Minimal", "Network"]);
        assert!(h.may_suggest_restart());
        h.recovery_enabled = Some(false);
        assert!(!h.may_suggest_restart());
        h.recovery_enabled = Some(true);
        assert!(h.may_suggest_restart());
    }

    #[test]
    fn the_live_reader_does_not_claim_to_know_the_recovery_state() {
        // BCD 는 마운트되어 있지 않다. 읽지 못한 것을 "꺼져 있다" 로 적으면
        // 모든 기계가 손상으로 보고된다 (설계-00 §5-1).
        assert_eq!(with(&["Minimal", "Network"]).recovery_enabled, None);
    }
}

#[cfg(all(test, unix))]
mod elevation_tests {
    use super::euid_is_root;

    #[test]
    fn the_effective_uid_is_the_second_number_not_the_first() {
        // 권한을 내려놓은 실행: 실제 0, 유효 1000. **유효를 본다.**
        let dropped = "Name:\tx\nUid:\t0\t1000\t1000\t1000\nGid:\t0\t0\t0\t0\n";
        assert_eq!(euid_is_root(dropped), Some(false));

        // setuid 로 올라온 실행: 실제 1000, 유효 0.
        let raised = "Name:\tx\nUid:\t1000\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
        assert_eq!(euid_is_root(raised), Some(true));
    }

    #[test]
    fn plain_root_and_plain_user() {
        assert_eq!(euid_is_root("Uid:\t0\t0\t0\t0\n"), Some(true));
        assert_eq!(euid_is_root("Uid:\t1000\t1000\t1000\t1000\n"), Some(false));
    }

    #[test]
    fn a_status_we_cannot_read_is_unknown_not_unprivileged() {
        // **모르는 것을 "권한 없음" 으로도, "있음" 으로도 접지 않는다.**
        // 부르는 쪽이 `None` 을 보고 거절한다.
        assert_eq!(euid_is_root(""), None);
        assert_eq!(euid_is_root("Name:\tx\nGid:\t0\t0\t0\t0\n"), None);
        assert_eq!(euid_is_root("Uid:\n"), None);
        assert_eq!(euid_is_root("Uid:\t0\n"), None);
    }

    #[test]
    fn a_line_that_merely_starts_with_uid_is_not_confused() {
        // "Uid:" 로 시작하는 줄만 본다. `Umask:` 같은 이웃에 걸리지 않는다.
        let s = "Umask:\t0022\nUid:\t0\t0\t0\t0\n";
        assert_eq!(euid_is_root(s), Some(true));
    }
}
