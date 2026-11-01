//! Windows 라이브 백엔드.
//!
//! # WOW64 를 `Sysnative` 로 다룬다
//!
//! 32비트 프로세스가 64비트 Windows 에서 `%SystemRoot%\System32` 를 열면 OS 가
//! 말없이 `SysWOW64` 로 바꿔친다. 그러면 **룰이 적은 경로와 실제로 본 경로가
//! 달라지고, 조용한 미탐이 된다** (설계-02 §4).
//!
//! `Wow64DisableWow64FsRedirection` 을 부르는 대신 `%SystemRoot%\Sysnative` 별칭을
//! 쓴다. 같은 결과를 얻으면서 unsafe 가 필요 없고, 리다이렉션을 껐다가 되돌리지
//! 못하는 실패 경로도 없다.
//!
//! 접근에만 별칭을 쓰고 **기록하는 경로는 언제나 `System32`** 다. 룰이 적는 경로가
//! 곧 스냅샷의 경로여야 한다.

use crate::read::{
    EnvRead, ExpandRoots, FsRead, ProcessRead, RawProcess, RegValue, RegistryRead, RootExpansion,
    WalkResult,
};
use crate::write::{PlatformWrite, DEFENDER_EXCLUSIONS, DEFENDER_EXCLUSION_ROOT};
use crate::PlatformError;
use remedy_sdk::catalog::Platform;
use remedy_sdk::normalize;

pub struct Live {
    /// 32비트 프로세스가 64비트 OS 에서 도는가.
    wow64: bool,
    system_root: String,
}

impl Default for Live {
    fn default() -> Self {
        Self::new()
    }
}

impl Live {
    pub fn new() -> Self {
        let wow64 = cfg!(target_pointer_width = "32")
            && std::env::var_os("PROCESSOR_ARCHITEW6432").is_some();
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        Self { wow64, system_root }
    }

    pub fn is_wow64(&self) -> bool {
        self.wow64
    }

    fn system32(&self) -> String {
        normalize::for_record(
            &format!("{}\\System32", self.system_root),
            Platform::Windows,
        )
    }

    fn sysnative(&self) -> String {
        normalize::for_record(
            &format!("{}\\Sysnative", self.system_root),
            Platform::Windows,
        )
    }

    /// 실제로 열 때 쓸 경로. 기록용 경로와 다를 수 있다.
    pub fn for_access(&self, path: &str) -> String {
        if !self.wow64 {
            return path.to_string();
        }
        let s32 = self.system32();
        if !normalize::is_within(path, &s32, Platform::Windows) {
            return path.to_string();
        }
        // 접두만 바꾼다. 뒤는 **대소문자를 그대로 둔다.**
        let rec = normalize::for_record(path, Platform::Windows);
        format!("{}{}", self.sysnative(), &rec[s32.len()..])
    }

    /// 예약 작업의 정의 파일. **읽기 전용 용도다.**
    ///
    /// 등록 경로 `\Microsoft\Windows\Locust` 는 언제나
    /// `%SystemRoot%\System32\Tasks\Microsoft\Windows\Locust` 에 있다. 이 해소는
    /// `registry_read` 가 `HKLM\...` 를 하이브 핸들로 푸는 것과 같은 종류의
    /// 플랫폼 사실이지 대상의 재해석이 아니다 (불변식 P).
    ///
    /// 정의를 **고칠 때는 쓰지 않는다** — 그것은 [`Self::schtasks`] 의 몫이다.
    fn task_file(&self, id: &str) -> Result<String, PlatformError> {
        if let Some(why) = crate::write::task_id_problem(id) {
            return Err(PlatformError::refused(
                format!("작업 등록 경로: {why}"),
                format!("task registration path: {why}"),
            ));
        }
        Ok(self.for_access(&format!("{}\\System32\\Tasks{}", self.system_root, id)))
    }

    /// `schtasks.exe` 를 부른다.
    ///
    /// # 왜 프로세스를 띄우는가
    ///
    /// 작업 스케줄러의 권위 있는 상태는 정의 XML **과**
    /// `HKLM\...\Schedule\TaskCache` 에 나뉘어 있고, 후자는 문서화되지 않은
    /// 이진 blob 과 XML 무결성 해시를 담는다. XML 만 고치면 해시가 어긋나
    /// Windows 는 그 작업을 "비활성" 이 아니라 **"손상"** 으로 취급한다 —
    /// 아무것도 하지 않은 것보다 나쁘다. COM(`ITaskService`)은 `unsafe` 를
    /// 요구해 이 크레이트의 `forbid(unsafe_code)` 와 충돌한다. 남는 것이 OS
    /// 자신의 관리 경로다 (설계-01 D12).
    ///
    /// # 어떻게 좁히는가
    ///
    /// - **절대 경로**로 부른다. 이름으로 부르면 PATH 를 쥔 쪽이 이긴다.
    /// - 셸을 거치지 않고 인자를 벡터로 넘긴다.
    /// - 출력은 **읽지 않는다.** 지역화되어 있어 파싱하면 언어별로 갈라진다.
    ///   판단은 종료 코드로만 한다.
    /// - IFEO 하이재킹을 먼저 확인한다. 이 도구의 위협 모델이 IFEO 를 T2 로
    ///   명시하는데(설계-02 §2), 정작 우리가 그것에 걸려 악성코드를 띄우면
    ///   치료 도구가 실행 수단이 된다.
    fn schtasks(&self, args: &[&str], id: &str) -> Result<(), PlatformError> {
        if let Some(why) = crate::write::task_id_problem(id) {
            return Err(PlatformError::refused(
                format!("작업 등록 경로: {why}"),
                format!("task registration path: {why}"),
            ));
        }
        self.system_tool("schtasks.exe", args).map_err(|e| match e {
            PlatformError::Refused(m) => PlatformError::refused(
                format!("{m}. 지정 계정으로 도는 작업은 암호 없이 다시 등록할 수 없습니다"),
                format!(
                    "{m}. A task that runs as a named account cannot be re-registered without \
                     its password"
                ),
            ),
            other => other,
        })
    }

    /// OS 가 딸려 보내는 관리 도구를 부른다 (설계-01 D12).
    ///
    /// 위의 `schtasks` 하나를 위해 만든 문을 P8 이 `sc.exe`·PowerShell 까지
    /// 쓰게 되면서 일반화했다. 좁히는 방법은 그대로다.
    ///
    /// **도구 이름은 코드가 정한다.** 계획이나 매니페스트에서 온 문자열이
    /// 실행 파일 이름이 되는 길을 아예 두지 않는다.
    ///
    /// **종료 코드를 그대로 돌려준다.** 코드를 보는 부름이 따로 필요한
    /// 이유: Defender 예외 변경은 실패 이유가 둘 이상이고(cmdlet 자체가 없다 /
    /// 변경이 거부됐다) 자식의 출력을 읽지 않기로 했으므로, 그것을 가르는 통로가 코드뿐이다.
    /// 도구 목록·IFEO 게이트를 지나 부르고 **끝날 때까지 기다린다**. 종료 코드와 stderr 를
    /// 함께 돌려주므로 부르는 쪽이 사유를 잃지 않는다 (`crate::tool`).
    fn run_tool(
        &self,
        exe_name: &str,
        args: &[&str],
    ) -> Result<crate::tool::Outcome, PlatformError> {
        if !SYSTEM_TOOLS.contains(&exe_name) {
            return Err(PlatformError::refused(
                format!("'{exe_name}' 은 이 코어가 부르는 도구 목록에 없습니다"),
                format!("'{exe_name}' is not in the list of tools this core invokes"),
            ));
        }
        let image = exe_name.rsplit('\\').next().unwrap_or(exe_name);
        if let Some(why) = ifeo_problem(image, &|k| self.registry_exists(k)) {
            return Err(PlatformError::Refused(why));
        }
        let warn_after = warn_for(image);
        let exe = self.for_access(&format!("{}\\System32\\{exe_name}", self.system_root));
        let mut cmd = std::process::Command::new(&exe);
        cmd.args(args);
        crate::tool::run_tool(cmd, &tool_label(exe_name, args), warn_after)
            .map_err(|e| PlatformError::io(&exe, e))
    }

    /// 종료 코드를 돌려준다 — 부르는 쪽이 코드의 뜻을 아는 도구(`sc.exe` 1062 등).
    /// 코드 없는 종료(시그널)는 사유를 담은 `Err`.
    fn system_tool_code(&self, exe_name: &str, args: &[&str]) -> Result<i32, PlatformError> {
        let out = self.run_tool(exe_name, args)?;
        if out.success() {
            return Ok(0);
        }
        match out.code {
            Some(c) => Ok(c),
            None => Err(PlatformError::Refused(
                out.reason(&tool_label(exe_name, args)),
            )),
        }
    }

    /// 성공만 바라는 도구. 실패 사유에 도구의 stderr 첫 200자가 붙는다.
    fn system_tool(&self, exe_name: &str, args: &[&str]) -> Result<(), PlatformError> {
        let out = self.run_tool(exe_name, args)?;
        if out.success() {
            return Ok(());
        }
        Err(PlatformError::Refused(
            out.reason(&tool_label(exe_name, args)),
        ))
    }

    /// 정의 키에서 서비스 이름을 꺼낸다.
    ///
    /// 대상은 `HKLM\SYSTEM\CurrentControlSet\Services\<이름>` 이다. 이름만
    /// 적힌 문자열을 받지 않는 이유: 보호 목록 대조도 G6 의 상한 판정도 대상의
    /// **모양**을 보고 갈리는데, 이름 하나짜리 문자열은 어느 쪽에도 걸리지
    /// 않는다.
    fn service_name(&self, target: &str) -> Result<String, PlatformError> {
        let want = normalize::for_compare(SERVICES_KEY, Platform::Windows);
        let got = normalize::for_compare(target, Platform::Windows);
        let Some(rest) = got.strip_prefix(&format!("{want}\\")) else {
            return Err(PlatformError::refused(
                format!("'{target}' 은 서비스 정의 키가 아닙니다"),
                format!("'{target}' is not a service definition key"),
            ));
        };
        // **한 칸 밑만.** `Services\a\Parameters` 를 서비스 이름으로 읽으면
        // 엉뚱한 것을 지운다.
        if rest.is_empty() || rest.contains('\\') {
            return Err(PlatformError::refused(
                format!("'{target}' 이 서비스 이름 한 칸을 가리키지 않습니다"),
                format!("'{target}' does not point at a single service name"),
            ));
        }
        // `sc.exe` 의 스위치 문자와 인용을 막는다.
        if rest.contains(['/', '"', ' ']) || rest.chars().any(|c| c.is_control()) {
            return Err(PlatformError::refused(
                format!("'{rest}' 은 서비스 이름으로 쓸 수 없는 문자를 담고 있습니다"),
                format!("'{rest}' contains characters that cannot be used in a service name"),
            ));
        }
        // 원본 대소문자를 돌려준다. 비교만 접어서 했다 — `for_compare` 는
        // 길이를 바꾸지 않으므로 뒤에서 같은 길이를 떼면 된다.
        Ok(target[target.len() - rest.len()..].to_string())
    }

    /// 기록용 경로. 항상 `System32` 표기이며 대소문자는 보존한다.
    fn for_record(&self, accessed: &str) -> String {
        let rec = normalize::for_record(accessed, Platform::Windows);
        let native = self.sysnative();
        // 접두 판정은 대소문자를 접어서 한다. 슬라이싱은 원본에 대고 한다 —
        // fold_case 가 길이를 바꾸지 않으므로 두 형태의 길이가 같다.
        if normalize::for_compare(&rec, Platform::Windows)
            .starts_with(&normalize::for_compare(&native, Platform::Windows))
        {
            return format!("{}{}", self.system32(), &rec[native.len()..]);
        }
        rec
    }
}

impl crate::local::PathView for Live {
    fn for_access(&self, path: &str) -> String {
        Live::for_access(self, path)
    }
    fn for_record(&self, accessed: &str) -> String {
        Live::for_record(self, accessed)
    }
}

impl FsRead for Live {
    fn walk(&self, root: &str, limit: usize) -> Result<WalkResult, PlatformError> {
        crate::local::walk(self, root, limit)
    }

    fn read_file(&self, path: &str, max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
        crate::local::read_file(self, path, max)
    }

    fn look(&self, path: &str) -> crate::read::Seen {
        crate::local::look(self, path)
    }
}

impl EnvRead for Live {
    fn expand(&self, s: &str) -> String {
        crate::local::expand_percent(s)
    }
}

impl RegistryRead for Live {
    fn value(&self, key: &str, name: &str) -> Result<Option<RegValue>, PlatformError> {
        let (root, sub) = split_hive(key)?;
        let k = match root.open_subkey(sub) {
            Ok(k) => k,
            Err(_) => return Ok(None),
        };
        // 문자열로 먼저 시도하고 안 되면 DWORD. 그 밖의 타입은 P2 에서 쓰지 않는다.
        if let Ok(s) = k.get_value::<String, _>(name) {
            return Ok(Some(RegValue::Str(s)));
        }
        match k.get_value::<u32, _>(name) {
            Ok(d) => Ok(Some(RegValue::Dword(d))),
            Err(_) => Ok(None),
        }
    }

    /// 하위 키 이름.
    ///
    /// # 열지 못한 것을 "열었는데 비었다" 로 말하지 않는다 (2026-10-27 · B-9)
    ///
    /// 이 자리가 `Err(_) => Ok(Vec::new())` 였던 동안 [`crate::read::seen`] 의
    /// *"모른다"* 는 **실기기에서 설 수 없었다** — 그 함수는 부모 열거가 실패할
    /// 때만 `CannotTell` 을 내는데, 여기가 실패를 빈 목록으로 바꿔 버렸다.
    /// 그래서 부모가 ACL 로 막힌 키는 *"봤는데 없다"* 로 집계되고, 그 키만
    /// 선언한 점검 플러그인은 **종료 0 "점검 대상이 이 기계에 없습니다"** 를
    /// 냈다(실측 2026-10-27 · `HKCU` 에 `Deny ReadKey`). 열린 루트가 하나라도
    /// 같이 선언되면 치료 플러그인도 **주의 한 줄 없이 종료 0** 이었다.
    ///
    /// `Path::exists()` 가 오류 전부를 *"없다"* 로 접던 것과 **같은 결함**이고,
    /// 공격자 쪽에서 보면 **부모 키를 잠그는 것만으로 점검을 끄는 길**이다.
    ///
    /// 호출자 아홉 가운데 여덟은 `Err` 를 지금의 빈 목록과 **같게** 다룬다
    /// (`unwrap_or_default` · `if let Ok` · `let Ok(..) else`). 남은 하나
    /// (`registry::services`)는 호출 **전에** `key_exists` 로 막아 둔다 —
    /// 그래서 이 고침은 "모른다" 를 되살리는 것 말고는 아무 자리도 바꾸지 않는다.
    ///
    /// # 없는 키는 그대로 빈 목록이다
    ///
    /// `open_subkey` 는 **없을 때도 막힐 때도** 실패하므로 둘을 [`std::io::
    /// ErrorKind`] 로 가른다 — [`crate::local::look`] 이 파일 쪽에서 쓰는 것과
    /// 같은 규율이다. 없는 키까지 `Err` 로 올리면 `read::seen` 이 *"모른다"* 를
    /// 내고, **설치되지 않은 제품의 깊은 키가 영원히 관측 불완전**이 된다
    /// (B-6 가 고친 자리). 그 길로 한 번 가 봤고, 조상을 타고 올라가 가르는
    /// 방법도 섰지만 — 오류 종류가 이미 답을 담고 있어 **호출 하나로 끝난다.**
    fn subkeys(&self, key: &str) -> Result<Vec<String>, PlatformError> {
        let (root, sub) = split_hive(key)?;
        let k = match root.open_subkey(sub) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(PlatformError::Io {
                    path: key.to_string(),
                    source: e,
                })
            }
        };
        // **부분 목록도 "없다" 로 읽힌다.** 열거가 중간에 깨지면 뒤쪽 이름이
        // 사라지고, 그것을 찾던 호출자는 *봤는데 없다* 로 결론짓는다.
        let mut names = Vec::new();
        for n in k.enum_keys() {
            names.push(n.map_err(|e| PlatformError::Io {
                path: key.to_string(),
                source: e,
            })?);
        }
        names.sort();
        Ok(names)
    }

    /// 키가 가진 값 전부.
    ///
    /// [`Self::subkeys`] 와 같은 이유로 열기 실패를 삼키지 않는다. 이쪽에는
    /// 그 `Err` 를 기다리는 자리가 **이미 쓰여 있었다** — `registry::services`
    /// 의 `Err(_)` 분기가 *"자기 키에 `Deny` 를 건 서비스는 여기서 목록에서
    /// 사라지고, 관측은 깨끗하다고 말했다"* 를 막겠다고 적어 두었는데, 빈
    /// 목록이 오는 동안 그 분기는 한 번도 발화하지 못했다.
    fn values(&self, key: &str) -> Result<Vec<(String, RegValue)>, PlatformError> {
        let (root, sub) = split_hive(key)?;
        let k = match root.open_subkey(sub) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(PlatformError::Io {
                    path: key.to_string(),
                    source: e,
                })
            }
        };
        let mut out = Vec::new();
        for v in k.enum_values() {
            let (name, v) = v.map_err(|e| PlatformError::Io {
                path: key.to_string(),
                source: e,
            })?;
            out.push((name, from_reg(&v)));
        }
        // 열거 순서는 레지스트리가 정한다. 정렬하지 않으면 같은 기계를 두 번
        // 수집한 스냅샷이 달라지고, diff 가 아무것도 말해 주지 않는다.
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    fn key_exists(&self, key: &str) -> bool {
        match split_hive(key) {
            Ok((root, sub)) => root.open_subkey(sub).is_ok(),
            Err(_) => false,
        }
    }
}

/// `winreg` 의 값 하나를 우리 표현으로 옮긴다.
///
/// **이진 값의 바이트를 버리지 않는다.** 버리면 `yara` 를 레지스트리 값에 걸
/// 수 없고, 그것은 설계-09 P4 가 요구하는 "바이트열 제공 필드 전반" 의 절반을
/// 잘라 내는 것이다.
fn from_reg(v: &winreg::RegValue) -> RegValue {
    use winreg::enums::RegType::*;
    match v.vtype {
        REG_SZ | REG_EXPAND_SZ => match String::from_utf16(&utf16_of(&v.bytes)) {
            Ok(s) => RegValue::Str(s.trim_end_matches('\0').to_string()),
            Err(_) => RegValue::Other,
        },
        // **빈 항목을 버리지 않는다.** 여기는 오래 `split('\0')` 뒤에
        // `filter(!is_empty)` 였는데, 그것은 종단이 만드는 빈 조각을 없애려던
        // 것이었지 항목을 고르는 판단이 아니었다 — 그런데 진짜 빈 항목까지
        // 함께 가져갔다. `PendingFileRenameOperations` 에서 빈 목적지는
        // "지워라" 를 뜻하므로, 그 값의 스냅샷은 출발지만 남은 절반이었다.
        //
        // 파싱은 `write::split_multi_sz` 한 곳에 있다. 두 벌이던 동안 각자
        // 다른 것을 잃었다 (그 함수의 표).
        REG_MULTI_SZ => RegValue::Multi(crate::write::split_multi_sz(&utf16_of(&v.bytes))),
        REG_DWORD | REG_DWORD_BIG_ENDIAN => {
            if v.bytes.len() >= 4 {
                let b = [v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3]];
                let n = if v.vtype == REG_DWORD_BIG_ENDIAN {
                    u32::from_be_bytes(b)
                } else {
                    u32::from_le_bytes(b)
                };
                RegValue::Dword(n)
            } else {
                RegValue::Other
            }
        }
        REG_QWORD => {
            if v.bytes.len() >= 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&v.bytes[..8]);
                RegValue::Qword(u64::from_le_bytes(b))
            } else {
                RegValue::Other
            }
        }
        REG_BINARY | REG_NONE => RegValue::Binary(v.bytes.clone()),
        _ => RegValue::Other,
    }
}

fn utf16_of(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn split_hive(key: &str) -> Result<(winreg::RegKey, &str), PlatformError> {
    use winreg::enums::*;
    // **하이브만 적은 경로도 열려야 한다.** `HKU` 하나로 하위 키를 세는 자리가
    // 있다 — `HKU\*` 를 실제 SID 로 펼치려면 먼저 `HKU` 자신을 열어야 한다.
    // 이것이 없어 실측에서 `HKU\*` 가 통째로 펼쳐지지 않았고, 그 플러그인은
    // 레지스트리 값을 0건으로 보고했다.
    let (hive, rest) = key.split_once('\\').unwrap_or((key, ""));
    let h = match hive.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        _ => {
            return Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
                "알 수 없는 레지스트리 하이브",
                "unknown registry hive",
            )))
        }
    };
    Ok((winreg::RegKey::predef(h), rest))
}

/// 사용자 로케일 이름 — `HKCU\Control Panel\International\LocaleName`, 예: `ko-KR`.
///
/// 언어 판단(`remedy_sdk::i18n`)의 Windows 갈래가 쓴다. **표시 언어가 아니라
/// 로케일이다** — `PreferredUILanguages` 는 표시 언어를 바꾼 적 없는 계정에는
/// 없고(실측 2026-09-09, 개발 PC 도 비어 있었다) `LocaleName` 은 늘 있다. POSIX
/// `LANG` 에 해당하는 값이기도 하다. `GetUserDefaultUILanguage` 는 `unsafe` 가
/// 필요하고 그것은 `remedy-wintrust` 밖에서 쓰지 않는다 — 레지스트리는 안전하게
/// 읽힌다.
pub fn user_locale() -> Option<String> {
    use winreg::enums::*;
    let key = winreg::RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Control Panel\International")
        .ok()?;
    let v: String = key.get_value("LocaleName").ok()?;
    let v = v.trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// 재부팅 때 처리할 파일 이동·삭제 큐 (`REG_MULTI_SZ`).
///
/// 항목이 **짝**으로 들어간다 — `(원본, 대상)` 이고 대상이 비면 삭제다.
const PENDING_RENAME: &str =
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations";
/// 키 하나와 그 하위를 목차·본문으로 편다.
///
/// **재귀 대신 명시적 스택을 쓰지 않는 이유**: 레지스트리 깊이는 파일 시스템과
/// 달리 얕고(수십), 재귀가 읽기 쉽다. 그래도 무한 재귀는 없다 — 레지스트리에는
/// 순환이 없다.
#[cfg(windows)]
fn dump_key(
    root_key: &str,
    rel: &str,
    index: &mut crate::write::RegKeyIndex,
    body: &mut Vec<u8>,
) -> Result<(), PlatformError> {
    let full = if rel.is_empty() {
        root_key.to_string()
    } else {
        format!("{root_key}\\{rel}")
    };
    let (root, rest) = split_hive(&full)?;
    let k = root.open_subkey(rest).map_err(|e| PlatformError::Io {
        path: full.clone(),
        source: e,
    })?;

    // 값 순서를 고정한다. 열거 순서는 보장되지 않고, 그러면 같은 키를 두 번
    // 담을 때 컨테이너 바이트가 달라져 결정성 검사가 흔들린다.
    let mut values: Vec<(String, winreg::RegValue)> = k.enum_values().flatten().collect();
    values.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, v) in values {
        index.values.push(crate::write::RegValueEntry {
            key: rel.to_string(),
            name,
            vtype: reg_type_num(v.vtype),
            size: v.bytes.len() as u64,
        });
        body.extend_from_slice(&v.bytes);
    }

    let mut subs: Vec<String> = k.enum_keys().flatten().collect();
    subs.sort();
    for s in subs {
        let child = if rel.is_empty() {
            s.clone()
        } else {
            format!("{rel}\\{s}")
        };
        index.keys.push(child.clone());
        dump_key(root_key, &child, index, body)?;
    }
    Ok(())
}

/// `winreg` 의 열거형을 타입 번호로. [`reg_type`] 의 역함수다.
#[cfg(windows)]
fn reg_type_num(t: winreg::enums::RegType) -> u32 {
    use winreg::enums::RegType::*;
    match t {
        REG_NONE => 0,
        REG_SZ => 1,
        REG_EXPAND_SZ => 2,
        REG_BINARY => 3,
        REG_DWORD => 4,
        REG_DWORD_BIG_ENDIAN => 5,
        REG_LINK => 6,
        REG_MULTI_SZ => 7,
        REG_QWORD => 11,
        // `winreg` 가 다루지 않는 타입. 이진으로 담아 두면 바이트는 살아남고,
        // 되돌릴 때 `reg_type` 이 3 을 알아본다.
        _ => 3,
    }
}

/// 이 코어가 부르는 OS 관리 도구. **여기 없는 것은 부르지 않는다.**
///
/// 목록이 코드에 박혀 있는 것이 요점이다 — 계획이나 매니페스트에서 온 문자열이
/// 실행 파일 이름이 되는 길을 아예 두지 않는다.
/// `sc.exe stop` 의 종료 코드를 **사유와 부류**로. `None` 이면 목표 상태가
/// 이루어진 것이다.
///
/// # 1053 은 거부가 아니다
///
/// `ERROR_SERVICE_REQUEST_TIMEOUT` 은 **SCM 이 서비스의 제어 핸들러를 60초까지만
/// 기다리고 포기했다**는 뜻이다(2026-09-12 실측: 정지를 70초·150초 붙들어도 둘 다
/// 60.1초에 1053 이 왔다). 그때 서비스는 **아직 멈추는 중**이고, 실제로 그 뒤에
/// 멈췄다.
///
/// 그런데 예전 문구는 `sc.exe stop 가 실패했다 (종료 코드 1053)` 이었다. 기계는
/// 치료되는데 도구는 실패라고만 말하는 것 — 결정 2026-09-07 이 막으려던 모양이
/// 우리가 죽여서가 아니라 **SCM 이 포기해서** 생긴 자리다.
///
/// # 그래도 실패로 센다 (결정 2026-09-13)
///
/// 성공으로 돌리면 **정말로 멈추지 않는 서비스**가 '치료 완료' 로 보고된다 —
/// 방어 도구가 낼 수 있는 가장 나쁜 거짓말이다. 안전한 쪽으로 틀리고, 대신
/// 사유가 무엇을 봐야 하는지 말한다.
///
/// # 왜 문자열이 아니라 오류를 돌려주는가 (2026-09-13)
///
/// 문구만 고쳤을 때 화면은 `거부됐다: sc.exe stop 을 SCM 이 … 포기했다` 였다 —
/// **접두가 본문과 반대말을 하고 있었다.** [`PlatformError::Refused`] 는 "할 수
/// 있지만 하지 않기로 했다" 는 뜻인데 1053 은 아무도 거부하지 않은 자리다.
/// 부류를 부르는 쪽에서 고르게 두면 같은 어긋남이 언제든 다시 생기므로,
/// **어느 부류인지까지 이 함수가 정한다.** 그래야 시험이 그것을 물어볼 수 있다.
fn stop_reason(code: i32) -> Option<PlatformError> {
    const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
    const ERROR_SERVICE_REQUEST_TIMEOUT: i32 = 1053;
    match code {
        0 | ERROR_SERVICE_NOT_ACTIVE => None,
        // **기다리다 끝났다** — 요청은 SCM 에 닿았고 서비스는 아직 멈추는 중일
        // 수 있다. 거부가 아니므로 `Refused` 로 적지 않는다.
        ERROR_SERVICE_REQUEST_TIMEOUT => Some(PlatformError::TimedOut(
            remedy_sdk::i18n::t(
                "sc.exe stop 을 SCM 이 60초까지만 기다리고 포기했습니다 (1053). \
             서비스는 아직 멈추는 중일 수 있습니다 — 재평가가 답합니다",
                "the SCM waited 60s for sc.exe stop and gave up (1053). \
             The service may still be stopping; re-evaluation will tell",
            )
            .into(),
        )),
        // 그 밖의 코드는 **SCM 이 요청을 물리친 것**이다. 그쪽은 거부가 맞다.
        other => Some(PlatformError::Refused(remedy_sdk::i18n::current().pick(
            format!("sc.exe stop 가 실패했습니다 (종료 코드 {other})"),
            format!("sc.exe stop failed (exit code {other})"),
        ))),
    }
}

/// 이 도구가 몇 초를 넘기면 알리는가. **죽이지는 않는다**(결정 2026-09-07).
///
/// | 도구 | 시점 | 왜 |
/// |---|---|---|
/// | `powershell.exe` | 300초 | 복원 지점(`Checkpoint-Computer`)은 정상일 때도 수십 초~분 |
/// | `sc.exe` | **30초** | OS 가 60초에 먼저 포기한다 — [`crate::tool::WARN_SC`] |
/// | 그 밖 | 60초 | |
///
/// **함수로 둔 이유는 시험 때문이다.** 호출부에 `if` 로 박아 두면 그 선택이
/// 옳은지 물어볼 자리가 없다 — `sc.exe` 가 60초였을 때 아무도 그것이 영영
/// 뜨지 않는 값이라는 것을 몰랐다.
fn warn_for(image: &str) -> std::time::Duration {
    if image.eq_ignore_ascii_case("powershell.exe") {
        crate::tool::WARN_LONG
    } else if image.eq_ignore_ascii_case("sc.exe") {
        crate::tool::WARN_SC
    } else {
        crate::tool::WARN_SHORT
    }
}

/// 사유 문장의 머리: `sc.exe stop`. 경로는 떼고 이미지 이름만.
fn tool_label(exe_name: &str, args: &[&str]) -> String {
    let image = exe_name.rsplit('\\').next().unwrap_or(exe_name);
    format!("{image} {}", args.first().copied().unwrap_or("?"))
}

const SYSTEM_TOOLS: [&str; 4] = [
    "schtasks.exe",
    "sc.exe",
    "taskkill.exe",
    r"WindowsPowerShell\v1.0\powershell.exe",
];

/// 서비스 정의가 사는 곳.
const SERVICES_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";

/// 이 실행 파일이 IFEO 로 가로채여 있는가. 있으면 그 사유.
///
/// `Debugger` 가 걸린 이미지를 실행하면 OS 는 그 디버거를 대신 띄운다. 이
/// 도구의 위협 모델은 IFEO 를 T2(선언으로 도달 가능한 지속성)로 명시하는데
/// (설계-02 §2), 정작 우리가 거기에 걸려 악성코드를 띄우면 **치료 도구가
/// 실행 수단이 된다.**
///
/// 조회를 주입받는 이유는 이 판단을 레지스트리 없이 잴 수 있게 하기 위해서다 —
/// 켤 수 없는 가드는 켜졌는지 알 수 없는 가드다.
fn ifeo_problem(exe: &str, exists: &dyn Fn(&str) -> bool) -> Option<String> {
    let key = format!(
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\\
         Image File Execution Options\\{exe}\\Debugger"
    );
    exists(&key).then(|| {
        remedy_sdk::i18n::current().pick(
            format!(
                "'{key}' 가 걸려 있습니다 — 이대로 부르면 우리가 악성코드를 띄웁니다. \
                 그 값을 먼저 제거해야 합니다"
            ),
            format!(
                "'{key}' is set — calling the tool as-is would have us launch the malware. \
                 That value must be removed first"
            ),
        )
    })
}

/// 등록 경로를 임시 파일 이름으로 쓸 수 있게 접는다. **식별이 아니라 표시용**이다 —
/// 어느 작업의 정의인지는 이미 `/TN` 이 말한다.
fn sanitize_for_file(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// PowerShell 홑따옴표 문자열 리터럴로 감싼다.
///
/// **이스케이프 규칙이 하나뿐이라 이 방식을 골랐다** — 홑따옴표를 두 번 적는
/// 것. 홑따옴표 문자열 안에서는 `$`·백틱·`"` 가 전부 글자 그대로이고, 줄바꿈이
/// 들어 있어도 문자열 안에 머문다. 큰따옴표를 쓰면 `$(...)` 가 살아나고, 그
/// 순간 제외 항목의 이름이 곧 실행될 코드가 된다.
fn ps_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// `-EncodedCommand` 가 받는 모양 — UTF-16LE 의 base64.
///
/// 명령줄에 셸 메타문자가 한 글자도 실리지 않는다. Windows 의 인용 규칙과
/// PowerShell 의 재파싱이 겹치는 자리를 통째로 없애는 것이 목적이다.
fn encode_command(script: &str) -> String {
    use base64::Engine as _;
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(utf16)
}

/// 제외 종류별 Defender cmdlet 매개변수.
///
/// `kind` 는 `crate::write::DEFENDER_EXCLUSIONS` 의 것과 같아야 한다 — 아래
/// `av_exclusions_write` 가 둘을 맞추어 돌린다.
const DEFENDER_EXCLUSION_PARAMS: [(&str, &str); 3] = [
    ("path", "ExclusionPath"),
    ("process", "ExclusionProcess"),
    ("ext", "ExclusionExtension"),
];

/// 타입 번호를 `winreg` 의 열거형으로 되돌린다.
///
/// **모르는 번호는 거절한다.** 임의 번호를 그대로 쓰면 레지스트리에 해석 불가능한
/// 값이 남고, 그것을 만든 것이 치료 도구가 된다.
fn reg_type(vtype: u32) -> Result<winreg::enums::RegType, PlatformError> {
    use winreg::enums::RegType::*;
    Ok(match vtype {
        0 => REG_NONE,
        1 => REG_SZ,
        2 => REG_EXPAND_SZ,
        3 => REG_BINARY,
        4 => REG_DWORD,
        5 => REG_DWORD_BIG_ENDIAN,
        6 => REG_LINK,
        7 => REG_MULTI_SZ,
        11 => REG_QWORD,
        _ => {
            return Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
                "모르는 레지스트리 값 타입",
                "unknown registry value type",
            )))
        }
    })
}

/// 쓰기 권한으로 키를 연다. **키를 만들지 않는다.**
///
/// 없는 키를 만들어 값을 쓰면 그것은 복원이 아니라 생성이다 — 백업에 있던 값을
/// 되돌리는 자리에서 원래 없던 키가 생겨난다.
fn open_for_write(key: &str) -> Result<winreg::RegKey, PlatformError> {
    use winreg::enums::*;
    let (root, rest) = split_hive(key)?;
    root.open_subkey_with_flags(rest, KEY_READ | KEY_SET_VALUE)
        .map_err(|e| PlatformError::Io {
            path: key.to_string(),
            source: e,
        })
}

// 이식 가능한 부분은 `FsRestore` 가 맡는다 — 본문·수정 시각·읽기 전용은
// OS 와 무관하게 같다. 여기 있는 것은 **이 OS 에서만 사실인 것**이고,
// 그것을 쓸 수 없는 자리는 조용히 넘기지 않고 보고서의 `lost` 에 적는다.
impl PlatformWrite for Live {
    fn backend_name(&self) -> &'static str {
        "windows-live"
    }

    fn registry_read(
        &self,
        target: &str,
    ) -> Result<crate::write::RegistryValueBackup, PlatformError> {
        let (key, name) = crate::write::split_value_name(target).ok_or(PlatformError::refused(
            "레지스트리 대상에 값 이름이 없습니다".into(),
            "the registry target has no value name".into(),
        ))?;
        let (root, rest) = split_hive(key)?;
        let k = root.open_subkey(rest).map_err(|e| PlatformError::Io {
            path: key.to_string(),
            source: e,
        })?;
        let v = k.get_raw_value(name).map_err(|e| PlatformError::Io {
            path: target.to_string(),
            source: e,
        })?;
        Ok(crate::write::RegistryValueBackup {
            vtype: v.vtype as u32,
            bytes: v.bytes,
        })
    }

    fn registry_delete(&self, target: &str) -> Result<(), PlatformError> {
        let (key, name) = crate::write::split_value_name(target).ok_or(PlatformError::refused(
            "레지스트리 대상에 값 이름이 없습니다".into(),
            "the registry target has no value name".into(),
        ))?;
        open_for_write(key)?
            .delete_value(name)
            .map_err(|e| PlatformError::Io {
                path: target.to_string(),
                source: e,
            })
    }

    fn registry_write(
        &self,
        target: &str,
        value: &crate::write::RegistryValueBackup,
    ) -> Result<(), PlatformError> {
        let (key, name) = crate::write::split_value_name(target).ok_or(PlatformError::refused(
            "레지스트리 대상에 값 이름이 없습니다".into(),
            "the registry target has no value name".into(),
        ))?;
        // 타입 번호를 그대로 되돌린다. 우리 열거형을 거치면 `Other` 로 떨어지는
        // 타입이 복원에서 달라진다.
        let raw = winreg::RegValue {
            vtype: reg_type(value.vtype)?,
            bytes: value.bytes.clone(),
        };
        open_for_write(key)?
            .set_raw_value(name, &raw)
            .map_err(|e| PlatformError::Io {
                path: target.to_string(),
                source: e,
            })
    }

    fn registry_exists(&self, target: &str) -> bool {
        self.registry_read(target).is_ok()
    }

    fn verify_after_reboot_support(&self) -> Result<(), PlatformError> {
        // RunOnce 는 레지스트리 값 하나다 — 붙일 자리는 모든 Windows 에 있다.
        // HKLM 에 쓸 권한은 치료가 이미 요구하므로, 그것이 없으면 예약하는
        // 순간 오류로 드러난다(트레이트 설명의 "그 너머의 실패").
        Ok(())
    }

    fn scheduled_verify_site(&self) -> Option<crate::write::VerifySite> {
        Some(crate::write::VerifySite {
            location: format!(
                "{}\\{}",
                crate::write::RUNONCE_KEY,
                crate::write::SCHEDULED_VERIFY_NAME
            ),
            // OS 가 실행 직전에 지운다 — RunOnce 를 고른 결정적 이유 (설계-03 §8).
            removed_by: crate::write::RemovedBy::Os,
        })
    }

    fn schedule_verify_after_reboot(
        &self,
        run_id: &str,
        exe: &std::path::Path,
        plugin: &std::path::Path,
        state_dir: Option<&std::path::Path>,
        lang: remedy_sdk::i18n::Lang,
    ) -> Result<(), PlatformError> {
        // 경로에 공백이 있을 수 있다. 따옴표로 감싸지 않으면 RunOnce 가 첫
        // 공백에서 잘라 읽고, 그러면 아무것도 실행되지 않는다.
        //
        // **`--plugin` 이 빠지면 이 명령은 실행되지 않는다.** `verify` 가 룰을
        // 그것으로 읽고, 없으면 사용법 오류로 끝난다 — RunOnce 는 콘솔 없이
        // 돌고 OS 가 항목을 먼저 지우므로 아무 흔적도 남지 않는다.
        let cmd = crate::write::scheduled_verify_command(exe, run_id, plugin, state_dir, lang);
        let target = format!(
            "{}\\{}",
            crate::write::RUNONCE_KEY,
            crate::write::SCHEDULED_VERIFY_NAME
        );
        // REG_SZ = 1. `from_string` 이 UTF-16LE 과 종단 NUL 을 붙인다 — 그
        // 인코딩을 여기 다시 적으면 두 곳이 갈라진다.
        let value = crate::write::RegistryValueBackup::from_string(1, &cmd);
        crate::write::PlatformWrite::registry_write(self, &target, &value)
    }

    fn cancel_scheduled_verify(&self) -> Result<(), PlatformError> {
        let target = format!(
            "{}\\{}",
            crate::write::RUNONCE_KEY,
            crate::write::SCHEDULED_VERIFY_NAME
        );
        // **없으면 성공이다.** Windows 는 RunOnce 항목을 실행 직전에 지우므로
        // 정상 경로에서는 지울 것이 없다 — 그것을 실패로 읽으면 verify 가 매번
        // 오류로 끝난다.
        if !crate::write::PlatformWrite::registry_exists(self, &target) {
            return Ok(());
        }
        crate::write::PlatformWrite::registry_delete(self, &target)
    }

    fn scheduled_verify(&self) -> Result<Option<String>, PlatformError> {
        let target = format!(
            "{}\\{}",
            crate::write::RUNONCE_KEY,
            crate::write::SCHEDULED_VERIFY_NAME
        );
        match crate::write::PlatformWrite::registry_read(self, &target) {
            // `as_string` 이 REG_SZ/REG_EXPAND_SZ 만 받는다. 다른 타입이면
            // 우리가 쓴 것이 아니므로 `None` 이 옳다.
            Ok(v) => Ok(v.as_string()),
            // 없는 것은 오류가 아니다.
            Err(_) => Ok(None),
        }
    }

    fn schedule_delete_on_reboot(&self, path: &str) -> Result<(), PlatformError> {
        // 세션 관리자가 부팅 초기에 이 목록을 읽어 실행한다. `\??\` 는 NT
        // 네임스페이스 접두이며, 없으면 항목이 조용히 무시된다.
        let src = format!("\\??\\{}", self.for_access(path));
        let now = self
            .registry_read(PENDING_RENAME)
            .ok()
            .and_then(|v| v.as_multi())
            .unwrap_or_default();
        // 이미 예약돼 있으면 두 번 넣지 않는다. 재기동한 실행기가 같은 Action 을
        // 다시 수행할 수 있다.
        if now.chunks(2).any(|p| p.first().is_some_and(|s| *s == src)) {
            return Ok(());
        }
        let mut next = now;
        next.push(src);
        // **빈 대상이 "지워라" 다.** 짝을 맞추지 않으면 그 뒤 항목이 통째로
        // 어긋나 엉뚱한 파일이 옮겨진다.
        next.push(String::new());
        self.registry_write(
            PENDING_RENAME,
            &crate::write::RegistryValueBackup::from_multi(&next),
        )
    }

    fn cancel_delete_on_reboot(&self, path: &str) -> Result<(), PlatformError> {
        let src = format!("\\??\\{}", self.for_access(path));
        let Some(now) = self
            .registry_read(PENDING_RENAME)
            .ok()
            .and_then(|v| v.as_multi())
        else {
            // 큐 자체가 없다. 없앨 것도 없다.
            return Ok(());
        };
        // **짝 단위로 지운다.** 원본 하나만 빼면 그 뒤가 통째로 어긋나 엉뚱한
        // 파일이 옮겨진다 — 이 목록은 `(원본, 대상)` 이 이어 붙은 것이다.
        let next: Vec<String> = now
            .chunks(2)
            .filter(|p| !p.first().is_some_and(|s| s.eq_ignore_ascii_case(&src)))
            .flat_map(|p| p.iter().cloned())
            .collect();
        if next.len() == now.len() {
            return Ok(());
        }
        // 남은 것이 없으면 값을 지운다. 빈 `REG_MULTI_SZ` 를 남기는 것보다
        // 원래 없던 상태로 돌리는 편이 맞다.
        if next.is_empty() {
            return self.registry_delete(PENDING_RENAME);
        }
        self.registry_write(
            PENDING_RENAME,
            &crate::write::RegistryValueBackup::from_multi(&next),
        )
    }

    fn stream_read(&self, target: &str) -> Result<Vec<u8>, PlatformError> {
        crate::write::FsRestore.stream_read(&self.for_access(target))
    }

    fn stream_delete(&self, target: &str) -> Result<(), PlatformError> {
        crate::write::FsRestore.stream_delete(&self.for_access(target))
    }

    fn shortcut_strip_args(&self, path: &str, expect: &str) -> Result<(), PlatformError> {
        crate::write::FsRestore.shortcut_strip_args(&self.for_access(path), expect)
    }

    // ── 설정 계열 ─────────────────────────────────────────────

    fn text_line_read(&self, path: &str, line_no: u32) -> Result<String, PlatformError> {
        crate::write::FsRestore.text_line_read(&self.for_access(path), line_no)
    }

    fn text_line_remove(
        &self,
        path: &str,
        line_no: u32,
        expect: &str,
    ) -> Result<(), PlatformError> {
        crate::write::FsRestore.text_line_remove(&self.for_access(path), line_no, expect)
    }

    fn text_line_restore(&self, path: &str, line_no: u32, line: &str) -> Result<(), PlatformError> {
        crate::write::FsRestore.text_line_restore(&self.for_access(path), line_no, line)
    }

    fn structured_remove_key(&self, path: &str, key_path: &str) -> Result<(), PlatformError> {
        crate::write::FsRestore.structured_remove_key(&self.for_access(path), key_path)
    }

    fn structured_set_key(
        &self,
        path: &str,
        key_path: &str,
        value: &str,
    ) -> Result<(), PlatformError> {
        crate::write::FsRestore.structured_set_key(&self.for_access(path), key_path, value)
    }

    // ── 디렉터리 ──────────────────────────────────────────────
    //
    // 훑기와 되돌리기는 이식 가능하다. 여기서는 WOW64 경로 매핑만 얹는다.

    fn is_dir(&self, path: &str) -> bool {
        crate::write::FsRestore.is_dir(&self.for_access(path))
    }

    fn dir_read(&self, path: &str) -> Result<(Vec<u8>, crate::write::DirIndex), PlatformError> {
        crate::write::FsRestore.dir_read(&self.for_access(path))
    }

    fn dir_destroy(&self, path: &str) -> Result<(), PlatformError> {
        crate::write::FsRestore.dir_destroy(&self.for_access(path))
    }

    /// 이 디렉터리 안에 **신뢰 서명된 파일**이 있는가 (설계-03 §4 조건 3).
    ///
    /// 기본 구현은 `Unsupported` 로 끝나고 실행기가 그것을 거부로 옮긴다.
    /// **P10-B 가 서명 검증 수단을 들여왔으므로 여기서 실제로 답한다.**
    fn survey_recursive_target(
        &self,
        dir: &str,
        max_children: u32,
        max_depth: u32,
    ) -> Result<Vec<String>, PlatformError> {
        survey_recursive_target_under(&self.for_access(dir), max_children, max_depth)
    }

    fn dir_restore(
        &self,
        path: &str,
        content: &[u8],
        index: &crate::write::DirIndex,
    ) -> Result<crate::write::RestoreReport, PlatformError> {
        crate::write::FsRestore.dir_restore(&self.for_access(path), content, index)
    }

    // ── 예약 작업 ─────────────────────────────────────────────

    /// **곁가지가 없다.** 예약 작업은 정의 XML 하나가 그 작업의 전부다 —
    /// systemd 처럼 활성화가 파일 밖에 있지 않다 (설계-09 P12 결정 5).
    fn persistence_read(
        &self,
        id: &str,
    ) -> Result<(Vec<u8>, crate::write::PersistenceIndex), PlatformError> {
        let path = self.task_file(id)?;
        let bytes = std::fs::read(&path).map_err(|e| PlatformError::io(&path, e))?;
        Ok((bytes, crate::write::PersistenceIndex::default()))
    }

    fn persistence_exists(&self, id: &str) -> bool {
        self.task_file(id)
            .is_ok_and(|p| std::fs::symlink_metadata(p).is_ok())
    }

    /// `at` 은 오지 않는다. 예약 작업은 줄이 아니라 등록 경로이고, 계획기도
    /// 그 자리를 채우지 않는다 (`locator`).
    fn persistence_disable(
        &self,
        id: &str,
        _at: Option<&crate::write::LineAt>,
    ) -> Result<(), PlatformError> {
        self.schtasks(&["/Change", "/TN", id, "/DISABLE"], id)
    }

    fn persistence_delete(
        &self,
        id: &str,
        _at: Option<&crate::write::LineAt>,
    ) -> Result<(), PlatformError> {
        self.schtasks(&["/Delete", "/TN", id, "/F"], id)
    }

    fn persistence_restore(
        &self,
        id: &str,
        xml: &[u8],
        _index: &crate::write::PersistenceIndex,
    ) -> Result<(), PlatformError> {
        // XML 을 임시 파일로 내려놓고 등록한다. `schtasks` 는 정의를 파일로만
        // 받는다. 원본 바이트를 **그대로** 쓴다 — 인코딩을 바꾸면 우리가 담은
        // 것과 등록되는 것이 달라진다.
        let tmp = std::env::temp_dir().join(format!("remedy-task-{}.xml", sanitize_for_file(id)));
        let tmp_s = tmp.to_string_lossy().to_string();
        std::fs::write(&tmp, xml).map_err(|e| PlatformError::io(&tmp_s, e))?;
        let r = self.schtasks(&["/Create", "/XML", &tmp_s, "/TN", id, "/F"], id);
        let _ = std::fs::remove_file(&tmp);
        r
    }

    // ── 레지스트리 키 하위 트리 (P8) ──────────────────────────

    fn registry_key_read(
        &self,
        key: &str,
    ) -> Result<(Vec<u8>, crate::write::RegKeyIndex), PlatformError> {
        let mut index = crate::write::RegKeyIndex::default();
        let mut body = Vec::new();
        dump_key(key, "", &mut index, &mut body)?;
        index.keys.sort();
        Ok((body, index))
    }

    fn registry_key_delete(&self, key: &str) -> Result<(), PlatformError> {
        use winreg::enums::*;
        let (root, rest) = split_hive(key)?;
        // `delete_subkey_all` 은 하위까지 지운다. 하위가 남아 있으면
        // `delete_subkey` 는 실패하고, 그 실패를 "이미 없다" 로 읽으면
        // 반쯤 지워진 트리가 남는다.
        root.open_subkey_with_flags("", KEY_READ)
            .and_then(|k| k.delete_subkey_all(rest))
            .map_err(|e| PlatformError::Io {
                path: key.to_string(),
                source: e,
            })
    }

    fn registry_key_restore(
        &self,
        key: &str,
        content: &[u8],
        index: &crate::write::RegKeyIndex,
    ) -> Result<(), PlatformError> {
        let (root, rest) = split_hive(key)?;
        let make = |rel: &str| -> Result<winreg::RegKey, PlatformError> {
            if !crate::write::reg_rel_is_contained(rel) {
                return Err(PlatformError::refused(
                    "목차가 루트 밖을 가리킵니다 — 되돌리지 않습니다".into(),
                    "the table of contents points outside the root — not restoring".into(),
                ));
            }
            let full = if rel.is_empty() {
                rest.to_string()
            } else {
                format!("{rest}\\{rel}")
            };
            root.create_subkey(&full)
                .map(|(k, _)| k)
                .map_err(|e| PlatformError::Io {
                    path: format!("{key}\\{rel}"),
                    source: e,
                })
        };
        // 빈 하위 키도 만든다. 값이 없는 키는 값 목록에 흔적을 남기지 않는다.
        make("")?;
        for rel in &index.keys {
            make(rel)?;
        }
        let mut off = 0usize;
        for v in &index.values {
            let end = off
                .checked_add(v.size as usize)
                .filter(|e| *e <= content.len())
                .ok_or(PlatformError::refused(
                    "목차가 본문 길이와 맞지 않습니다".into(),
                    "the table of contents does not match the body length".into(),
                ))?;
            let k = make(&v.key)?;
            let raw = winreg::RegValue {
                vtype: reg_type(v.vtype)?,
                bytes: content[off..end].to_vec(),
            };
            k.set_raw_value(&v.name, &raw)
                .map_err(|e| PlatformError::Io {
                    path: format!("{key}\\{}\\{}", v.key, v.name),
                    source: e,
                })?;
            off = end;
        }
        Ok(())
    }

    fn registry_key_exists(&self, key: &str) -> bool {
        split_hive(key)
            .and_then(|(root, rest)| {
                root.open_subkey(rest).map_err(|e| PlatformError::Io {
                    path: key.to_string(),
                    source: e,
                })
            })
            .is_ok()
    }

    // ── 프로세스 (P8) ─────────────────────────────────────────

    fn processes_matching(
        &self,
        p: &crate::write::KillPredicate,
    ) -> Result<Vec<crate::write::Target>, PlatformError> {
        // **빈 술어는 모든 프로세스를 뜻한다.** 그것을 돌려주면 이 문이
        // 임의 열거가 된다 (설계-04 §1).
        if p.is_empty() {
            return Err(PlatformError::refused(
                "술어가 비어 있습니다. 무엇을 종료할지 계획이 말하지 않았습니다".into(),
                "the predicate is empty; the plan does not say what to terminate".into(),
            ));
        }
        let mut sys = sysinfo::System::new();
        crate::local::refresh_all_processes(&mut sys);
        let mut out = Vec::new();
        for (pid, proc_) in sys.processes() {
            let image = proc_
                .exe()
                .map(|e| normalize::nfc(&self.for_record(&e.to_string_lossy())))
                .unwrap_or_default();
            let cmd: Vec<String> = proc_
                .cmd()
                .iter()
                .map(|a| a.to_string_lossy().to_string())
                .collect();
            let cmdline = normalize::nfc(&cmd.join(" "));
            if let Some(want) = &p.image_path {
                if !image.eq_ignore_ascii_case(want) {
                    continue;
                }
            }
            if let Some(needle) = &p.cmdline_contains {
                if !cmdline.to_lowercase().contains(&needle.to_lowercase()) {
                    continue;
                }
            }
            out.push(crate::write::Target {
                pid: pid.as_u32(),
                image_path: image,
                cmdline,
            });
        }
        out.sort_by_key(|t| t.pid);
        Ok(out)
    }

    /// # 재사용된 PID 를 자손으로 세지 않는다
    ///
    /// Windows 는 부모가 죽어도 자식의 부모 PID 를 고치지 않는다 (Unix 처럼
    /// init 에 재양육하지 않는다). 그 PID 가 재사용되면 **남남인 프로세스가
    /// 자손으로 보인다.** 술어가 지목한 것이 재사용된 PID 라면, 그 자리에서
    /// 무관한 프로세스 트리 하나를 통째로 종료하게 된다.
    ///
    /// 그래서 시각을 함께 본다 — **자식은 부모보다 먼저 시작할 수 없다.**
    /// 시작 시각을 읽지 못한 프로세스(핸들이 열리지 않으면 `sysinfo` 가 0 을
    /// 준다)는 관계를 확인하지 못한 것이므로 **자손으로 세지 않는다.**
    /// 확인하지 못한 것을 확인된 것처럼 다루지 않는다 (설계-00 §5-1).
    fn process_descendants(
        &self,
        roots: &[u32],
    ) -> Result<Vec<crate::write::Target>, PlatformError> {
        if roots.is_empty() {
            return Ok(Vec::new());
        }
        let mut sys = sysinfo::System::new();
        crate::local::refresh_all_processes(&mut sys);

        // (pid, ppid, start_time) 한 벌. 지도와 세부가 같은 스냅샷에서 나온다.
        let mut kin: Vec<(u32, u32, u64)> = Vec::new();
        for (pid, proc_) in sys.processes() {
            kin.push((
                pid.as_u32(),
                proc_.parent().map(|x| x.as_u32()).unwrap_or(0),
                proc_.start_time(),
            ));
        }
        let started = |pid: u32| kin.iter().find(|(p, _, _)| *p == pid).map(|(_, _, s)| *s);

        // 너비 우선. 이미 본 PID 는 다시 넣지 않는다 — 순환하는 부모 관계는
        // 정상이 아니지만, 그 비정상이 이 함수를 멈추게 해서는 안 된다.
        let mut seen: Vec<u32> = roots.to_vec();
        let mut frontier: Vec<u32> = roots.to_vec();
        let mut found: Vec<u32> = Vec::new();
        while !frontier.is_empty() {
            let mut next = Vec::new();
            for parent in &frontier {
                let Some(p_start) = started(*parent) else {
                    continue;
                };
                for (pid, ppid, c_start) in &kin {
                    if ppid != parent || seen.contains(pid) {
                        continue;
                    }
                    // 둘 중 하나라도 시각을 모르면 관계를 확인하지 못했다.
                    if p_start == 0 || *c_start == 0 || *c_start < p_start {
                        continue;
                    }
                    seen.push(*pid);
                    found.push(*pid);
                    next.push(*pid);
                }
            }
            frontier = next;
        }

        let mut out = Vec::new();
        for pid in found {
            let Some(proc_) = sys.process(sysinfo::Pid::from_u32(pid)) else {
                continue;
            };
            let image = proc_
                .exe()
                .map(|e| normalize::nfc(&self.for_record(&e.to_string_lossy())))
                .unwrap_or_default();
            let cmd: Vec<String> = proc_
                .cmd()
                .iter()
                .map(|a| a.to_string_lossy().to_string())
                .collect();
            out.push(crate::write::Target {
                pid,
                image_path: image,
                cmdline: normalize::nfc(&cmd.join(" ")),
            });
        }
        out.sort_by_key(|t| t.pid);
        Ok(out)
    }

    /// # `sysinfo` 의 `kill()` 을 쓰지 않는다
    ///
    /// 그것은 Windows 에서 `Command::new("taskkill.exe")` 를 띄운다 — **이름으로**
    /// 부르므로 PATH 를 쥔 쪽이 이긴다. 설계-01 D12 가 `schtasks` 를 위해 만든
    /// 문(절대 경로·허용 목록·IFEO 확인)을 프로세스 종료만 우회하고 있었고,
    /// 그것이 이 도구에서 가장 나쁜 자리다 — **파괴 경로에 뚫린 실행 경로**다.
    ///
    /// 그래서 같은 문으로 되돌린다. 덤으로 `taskkill` 은 `/PID` 를 여러 번 받아
    /// **집합을 한 번에** 끝낸다 — 프로세스를 하나마다 띄우던 것이 한 번이
    /// 되고, 그만큼 워치독이 끼어들 창이 좁아진다.
    fn process_kill(&self, pids: &[u32]) -> Result<(), PlatformError> {
        if pids.is_empty() {
            return Ok(());
        }
        let mut args: Vec<String> = vec!["/F".into()];
        for p in pids {
            args.push("/PID".into());
            args.push(p.to_string());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match self.system_tool("taskkill.exe", &refs) {
            Ok(()) => Ok(()),
            // **종료 코드를 실패로 읽지 않는다.** `taskkill` 은 "그 PID 가 이미
            // 없다" 에도 0 이 아닌 값을 낸다. 진짜 답은 재평가가 준다 —
            // 실행기가 곧바로 다시 훑어 남은 것을 센다.
            Err(PlatformError::Refused(_)) => Ok(()),
            // 도구를 띄우지 못한 것은 다른 이야기다. 그때는 아무것도 죽지 않았다.
            Err(e) => Err(e),
        }
    }

    // ── 서비스 (P8) ───────────────────────────────────────────

    fn service_running(&self, target: &str) -> bool {
        // SCM 에 묻지 않고 정의 키의 존재만 본다면 그것은 "돈다" 가 아니다.
        // `sc.exe query` 의 종료 코드로 판단한다 — 정지 상태면 1062 다.
        let Ok(name) = self.service_name(target) else {
            return false;
        };
        self.system_tool("sc.exe", &["query", &name]).is_ok()
    }

    /// **이미 멈춰 있는 것은 실패가 아니다.**
    ///
    /// `sc.exe stop` 은 돌고 있지 않은 서비스에 `1062`
    /// (`ERROR_SERVICE_NOT_ACTIVE`) 를 낸다. 그것을 실패로 세면 목표 상태
    /// (멈춰 있다)가 이미 이루어졌는데 `apply` 가 **부분 실패(3)** 로 끝난다 —
    /// 지울 것이 이미 없을 때 성공으로 다루는 다른 Op 들과 같은 자리다.
    ///
    /// 등록만 되고 시작되지 않은 서비스가 흔하다. 2026-09-05 채점 5 에서
    /// `service-userinit` 이 정확히 그랬다: 일곱 건이 수행되고 기계는 청정
    /// 기준으로 돌아왔는데 보고는 부분 실패였다.
    ///
    /// **다른 코드는 그대로 실패다.** 1062 만 목표 상태를 뜻한다 — 다만 1053 은
    /// 실패라고 부르되 **무엇이 일어난 것인지 다르게 말한다**([`stop_reason`]):
    /// 거부가 아니라 [`PlatformError::TimedOut`] 이다.
    fn service_stop(&self, target: &str) -> Result<(), PlatformError> {
        let name = self.service_name(target)?;
        let code = self.system_tool_code("sc.exe", &["stop", &name])?;
        match stop_reason(code) {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    fn service_disable(&self, target: &str) -> Result<(), PlatformError> {
        let name = self.service_name(target)?;
        // `start= disabled` 의 공백은 sc.exe 의 문법이다. 인자 하나로 붙여
        // 보내면 파싱되지 않는다.
        self.system_tool("sc.exe", &["config", &name, "start=", "disabled"])
    }

    fn service_delete(&self, target: &str) -> Result<(), PlatformError> {
        let name = self.service_name(target)?;
        self.system_tool("sc.exe", &["delete", &name])
    }

    fn service_clear_recovery(&self, target: &str) -> Result<(), PlatformError> {
        let name = self.service_name(target)?;
        // `actions= ""` 가 "복구 동작 없음" 이다. `reset= 0` 은 실패 횟수를
        // 즉시 초기화한다.
        self.system_tool("sc.exe", &["failure", &name, "reset=", "0", "actions=", ""])
    }

    // ── 복원 지점 (P8) ────────────────────────────────────────

    fn create_restore_point(&self, label: &str) -> Result<(), PlatformError> {
        // **인자에 계획의 문자열을 넣지 않는다.** 라벨은 코어가 만든 것만
        // 받고, 그것도 영숫자로 접어서 넘긴다 — PowerShell 인자에 임의
        // 문자열을 넣는 순간 그 문이 명령 주입 자리가 된다.
        let safe: String = label
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(48)
            .collect();
        if safe.is_empty() {
            return Err(PlatformError::refused(
                "복원 지점 이름이 비었습니다".into(),
                "the restore point label is empty".into(),
            ));
        }
        self.system_tool(
            "WindowsPowerShell\\v1.0\\powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "Checkpoint-Computer -Description {safe} -RestorePointType APPLICATION_INSTALL"
                ),
            ],
        )
    }

    fn av_exclusions_read(&self) -> Result<Vec<crate::write::AvExclusion>, PlatformError> {
        let mut out: Vec<crate::write::AvExclusion> = Vec::new();
        for (kind, leaf) in DEFENDER_EXCLUSIONS {
            let key = format!("{DEFENDER_EXCLUSION_ROOT}\\{leaf}");
            let (root, rest) = split_hive(&key)?;
            // 없는 키는 정상이다. 그 종류의 제외가 하나도 없다는 뜻이다.
            let Ok(k) = root.open_subkey(rest) else {
                continue;
            };
            for name in k.enum_values().filter_map(|v| v.ok()).map(|(n, _)| n) {
                out.push(crate::write::AvExclusion {
                    kind: kind.to_string(),
                    value: name,
                });
            }
        }
        // 순서를 고정한다. 백업이 실행마다 달라지면 같은 상태의 두 컨테이너가
        // 다른 바이트가 되고, 결정성 대조가 성립하지 않는다.
        out.sort();
        Ok(out)
    }

    /// 예외 목록을 `want` 와 같게 만든다.
    ///
    /// # 레지스트리로는 안 된다
    ///
    /// Defender 의 `Exclusions` 키는 **변조 방지(Tamper Protection)** 가 쓰기를
    /// 막는다. 관리자여도 거부다 — `reg delete` 도 `OpenSubKey(writable)` 도
    /// "액세스가 거부되었습니다" 로 끝난다 (2026-08-31 Win10 실측). 변조 방지는
    /// 2019년부터 기본 켜짐이므로 **보통의 기계에서 이 경로는 언제나 실패한다.**
    ///
    /// 지원되는 길은 Defender 서비스를 거치는 `Add-MpPreference` /
    /// `Remove-MpPreference` 뿐이고, 그쪽은 변조 방지가 켜진 채로도 동작한다
    /// (같은 실측).
    ///
    /// # 무엇을 더하고 뺄지는 여기서 정한다
    ///
    /// PowerShell 안에서 `Get-MpPreference` 로 현재 목록을 다시 읽지 않는다.
    /// 그 cmdlet 은 **정책(GPO) 예외까지 합쳐서** 돌려주는데 그것들은
    /// `HKLM\SOFTWARE\Policies\...` 에 살아 `Remove-MpPreference` 로 지울 수
    /// 없다. 지우려 들면 매번 실패한다. 읽기는 `av_exclusions_read` 하나로
    /// 통일하고 — 그것은 Defender 자신의 키만 본다 — 델타만 넘긴다.
    fn av_exclusions_write(&self, want: &[crate::write::AvExclusion]) -> Result<(), PlatformError> {
        let now = self.av_exclusions_read()?;
        let mut body = String::new();
        let mut changes = 0usize;

        for (kind, param) in DEFENDER_EXCLUSION_PARAMS {
            let has = |v: &[crate::write::AvExclusion], value: &str| {
                v.iter()
                    .any(|x| x.kind == kind && x.value.eq_ignore_ascii_case(value))
            };
            // 지울 것이 먼저다. 같은 입력이 언제나 같은 명령을 만들도록 순서를
            // 고정한다 — 실패를 재현할 수 없으면 진단할 수도 없다.
            for x in now.iter().filter(|x| x.kind == kind) {
                if !has(want, &x.value) {
                    body.push_str(&format!(
                        "  Remove-MpPreference -{param} {}\n",
                        ps_literal(&x.value)
                    ));
                    changes += 1;
                }
            }
            for x in want.iter().filter(|x| x.kind == kind) {
                if !has(&now, &x.value) {
                    body.push_str(&format!(
                        "  Add-MpPreference -{param} {}\n",
                        ps_literal(&x.value)
                    ));
                    changes += 1;
                }
            }
        }
        if changes == 0 {
            return Ok(());
        }

        // **실패 이유를 종료 코드로 받는다.** `system_tool` 은 자식의 출력을
        // 버리므로(그것이 옳다 — 악성코드가 고른 문자열이 우리 로그에 그대로
        // 흐르지 않는다) 무엇이 잘못됐는지는 코드로만 온다.
        let script = format!(
            "$ErrorActionPreference='Stop'\n\
             if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {{ exit 3 }}\n\
             try {{\n{body}}} catch {{ exit 4 }}\n\
             exit 0\n"
        );

        // **인자 줄에 값을 싣지 않는다.** 제외 항목의 값 이름은 악성코드가 고른
        // 문자열일 수 있다. 예외를 등록하려면 이미 관리자여야 하지만, 서명된
        // 치료 도구가 그 문자열을 셸에 넘기는 것은 그것대로 원시 도구가 된다.
        // Windows 명령줄 인용 규칙과 PowerShell 의 재파싱이 겹치는 자리는
        // 역사적으로 새는 곳이다. `-EncodedCommand` 는 base64(UTF-16LE) 라
        // 알파벳에 셸 메타문자가 없다 — 인용 층이 통째로 사라진다.
        //
        // 값 자체는 `ps_literal` 이 홑따옴표 리터럴로 감싼다. PowerShell 의
        // 홑따옴표 문자열은 `$` 도 백틱도 해석하지 않고 이스케이프 규칙이
        // `'` → `''` 하나뿐이다.
        let code = self.system_tool_code(
            "WindowsPowerShell\\v1.0\\powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &encode_command(&script),
            ],
        )?;
        match code {
            0 => Ok(()),
            3 => Err(PlatformError::refused(
                "Defender 의 예외 목록 cmdlet 이 없습니다 — 이 기계의 보안 제품이 Defender 가 \
                 아니거나 서비스가 꺼져 있습니다. 예외 목록은 손으로 되돌려야 합니다"
                    .into(),
                "the Defender exclusion cmdlets are missing — either this machine's security \
                 product is not Defender or the service is off. Restore the exclusions by hand"
                    .into(),
            )),
            _ => Err(PlatformError::refused(
                format!(
                    "Defender 예외 목록을 바꾸지 못했습니다 (powershell 종료 코드 {code}). \
                     변조 방지 정책이 예외 변경까지 막는 구성일 수 있습니다"
                ),
                format!(
                    "could not change the Defender exclusions (powershell exit code {code}). \
                     Tamper protection may be configured to block exclusion changes too"
                ),
            )),
        }
    }

    fn plan_restore(
        &self,
        dest: &str,
        meta: &crate::write::FileMeta,
    ) -> crate::write::RestoreReport {
        crate::write::FsRestore.plan_restore(dest, meta)
    }

    fn restore_file(
        &self,
        dest: &str,
        content: &[u8],
        meta: &crate::write::FileMeta,
    ) -> Result<crate::write::RestoreReport, PlatformError> {
        crate::write::FsRestore.restore_file(dest, content, meta)
    }

    fn quarantine_read(
        &self,
        path: &str,
    ) -> Result<(Vec<u8>, crate::write::FileMeta), PlatformError> {
        // WOW64 별칭을 적용해 연다. 32비트 프로세스가 `System32` 를 그대로 열면
        // OS 가 `SysWOW64` 로 바꿔치고, 그러면 **기록된 경로와 실제로 담은 파일이
        // 달라진다** (설계-02 §4).
        crate::write::FsRestore.quarantine_read(&self.for_access(path))
    }

    fn destroy_file(&self, path: &str) -> Result<(), PlatformError> {
        crate::write::FsRestore.destroy_file(&self.for_access(path))
    }

    fn exists(&self, path: &str) -> bool {
        // 여기도 WOW64 별칭을 거친다. 지울 때 본 자리와 있는지 물을 때 본 자리가
        // 다르면, 재기동한 실행기가 "이미 지웠다" 를 정반대로 판단한다.
        crate::write::FsRestore.exists(&self.for_access(path))
    }
}

impl ProcessRead for Live {
    fn processes(&self) -> Result<Vec<RawProcess>, PlatformError> {
        crate::local::processes(self)
    }
}

/// 프로필·하이브 수 상한.
///
/// 상한이 없으면 프로필이 수백 개인 터미널 서버에서 `%ALLUSERPROFILES%` 하나가
/// 수집 범위를 통째로 삼킨다. 넘으면 **잘렸다고 말한다** — 조용히 자르면
/// 뒤쪽 사용자가 감염 상태로 남는다.
const MAX_PROFILES: usize = 64;

/// 실제 사용자 프로필 목록의 출처.
///
/// `C:\Users\*` 를 훑지 않는 이유는 그것이 **디렉터리 목록이지 프로필 목록이
/// 아니기** 때문이다. 프로필이 다른 드라이브에 있을 수 있고, `Public` 처럼
/// 사용자가 아닌 것이 섞이며, 지워진 계정의 잔여 폴더도 남는다.
const PROFILE_LIST: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

impl ExpandRoots for Live {
    fn expand_roots(&self, root: &str, allow_removable: bool) -> RootExpansion {
        let mut out = RootExpansion::default();

        // `HKU\*` — 로그온한 사용자 하이브. `_Classes` 는 같은 사용자의 클래스
        // 하이브라 함께 세면 사용자 하나가 둘로 보인다.
        if let Some(star) = root.find("\\*") {
            let head = &root[..star];
            if head.eq_ignore_ascii_case("HKU") || head.eq_ignore_ascii_case("HKEY_USERS") {
                let tail = &root[star + 2..];
                let mut sids: Vec<String> = self
                    .subkeys(head)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|s| !s.ends_with("_Classes"))
                    .collect();
                sids.sort();
                if sids.len() > MAX_PROFILES {
                    let n = sids.len();
                    out.notes.push(remedy_sdk::i18n::current().pick(
                        format!("{root}: 하이브 {n}개 중 {MAX_PROFILES}개까지만 봅니다"),
                        format!("{root}: looking at only {MAX_PROFILES} of {n} hives"),
                    ));
                    sids.truncate(MAX_PROFILES);
                }
                if sids.is_empty() {
                    out.notes.push(remedy_sdk::i18n::current().pick(
                        format!("{root}: 사용자 하이브를 하나도 읽지 못했습니다"),
                        format!("{root}: not one user hive could be read"),
                    ));
                }
                out.roots = sids
                    .into_iter()
                    .map(|s| format!("{head}\\{s}{tail}"))
                    .collect();
                return out;
            }
        }

        // `%ALLUSERPROFILES%` — 모든 사용자 프로필 디렉터리.
        if let Some(rest) = crate::local::strip_token(root, "%ALLUSERPROFILES%") {
            let mut dirs = Vec::new();
            for sid in self.subkeys(PROFILE_LIST).unwrap_or_default() {
                // **진짜 사용자 계정만.** `S-1-5-18/19/20` 은 시스템 프로필이고
                // 그것까지 열면 `C:\Windows\system32\config\systemprofile` 이
                // 사용자 폴더로 들어와 범위가 크게 넓어진다.
                if !sid.starts_with("S-1-5-21-") {
                    continue;
                }
                if let Ok(Some(RegValue::Str(p))) =
                    self.value(&format!("{PROFILE_LIST}\\{sid}"), "ProfileImagePath")
                {
                    let p = self.expand(&p);
                    if !p.is_empty() {
                        dirs.push(p);
                    }
                }
            }
            dirs.sort();
            dirs.dedup();
            if dirs.len() > MAX_PROFILES {
                let n = dirs.len();
                out.notes.push(remedy_sdk::i18n::current().pick(
                    format!("{root}: 프로필 {n}개 중 {MAX_PROFILES}개까지만 봅니다"),
                    format!("{root}: looking at only {MAX_PROFILES} of {n} profiles"),
                ));
                dirs.truncate(MAX_PROFILES);
            }
            if dirs.is_empty() {
                out.notes.push(remedy_sdk::i18n::current().pick(
                    format!("{root}: 사용자 프로필을 하나도 읽지 못했습니다"),
                    format!("{root}: not one user profile could be read"),
                ));
            }
            out.roots = dirs
                .into_iter()
                .map(|d| normalize::for_record(&format!("{d}{rest}"), Platform::Windows))
                .collect();
            return out;
        }

        // `%REMOVABLE%` — 꽂혀 있는 이동식 매체.
        if let Some(rest) = crate::local::strip_token(root, "%REMOVABLE%") {
            if !allow_removable {
                // **선언이 동의를 대신한다.** 조용히 펼치면 사용자가 예상하지
                // 못한 매체가 범위에 들어온다 (설계-03 §4).
                out.notes.push(remedy_sdk::i18n::current().pick(
                    format!("{root}: allow_removable 을 선언하지 않아 펼치지 않았습니다"),
                    format!("{root}: not expanded because allow_removable was not declared"),
                ));
                return out;
            }
            let mut mounts: Vec<String> = sysinfo::Disks::new_with_refreshed_list()
                .iter()
                .filter(|d| d.is_removable())
                .map(|d| d.mount_point().to_string_lossy().to_string())
                .collect();
            mounts.sort();
            mounts.dedup();
            if mounts.is_empty() {
                // 꽂힌 것이 없는 것은 정상이다. 그래도 말은 해 둔다 — 룰이
                // 이동식 매체를 겨눴는데 아무것도 못 봤다는 사실이 남아야 한다.
                out.notes.push(remedy_sdk::i18n::current().pick(
                    format!("{root}: 연결된 이동식 매체가 없습니다"),
                    format!("{root}: no removable media is attached"),
                ));
            }
            out.roots = mounts
                .into_iter()
                .map(|m| {
                    normalize::for_record(
                        &format!("{}{rest}", m.trim_end_matches(['\\', '/'])),
                        Platform::Windows,
                    )
                })
                .collect();
            return out;
        }

        // 그 밖은 1:1 환경변수 전개다.
        out.roots = vec![self.expand(root)];
        out
    }
}

/// 재귀 삭제 대상 아래에서 신뢰 서명된 실행 파일을 찾는다.
///
/// # 확인하지 못한 것을 "없다" 로 읽지 않는다
///
/// 이 함수가 `Ok(빈 목록)` 을 내면 실행기는 **지워도 된다**고 읽는다. 그래서
/// 하나라도 확인하지 못했으면 `Err` 다 — 읽을 수 없는 파일, 서명을 판정하지
/// 못한 파일, 그리고 **다 보지 못한 경우**(상한 초과)가 전부 여기 들어간다.
///
/// # 여기 있는 상한은 정책이 아니다
///
/// 설계-03 §4 의 정책 상한(하위 항목 500 · 깊이 8)은 `remedy-plan` 의 것이고,
/// 쓰기 경계가 그것을 알면 계층이 뒤집힌다. 여기 있는 값은 **이 함수가 끝나기
/// 위한 한계**다 — 넘으면 답을 내지 않고 그 사실을 말한다.
#[cfg(windows)]
pub fn survey_recursive_target_under(
    root: &str,
    max_children: u32,
    max_depth: u32,
) -> Result<Vec<String>, PlatformError> {
    /// **안전망**이다. 정책 상한(`max_children`)이 이보다 크게 설정되면 이쪽이
    /// 먼저 걸린다 — 어느 쪽이든 거부이므로 방향은 같다.
    const MAX_ENTRIES: usize = 20_000;
    /// 순환 링크나 병적으로 깊은 트리에서 끝나기 위한 값. 위와 같은 성격이다.
    const MAX_DEPTH: usize = 32;

    // 정책 상한은 안전망보다 먼저 걸려야 한다. 둘 중 작은 쪽을 쓴다.
    let cap_entries = (max_children as usize).min(MAX_ENTRIES);
    let cap_depth = (max_depth as usize).min(MAX_DEPTH);
    /// 보고에 담을 개수. 하나만 있어도 거부이므로 전부 모을 이유가 없다.
    const MAX_REPORTED: usize = 5;

    let mut found: Vec<String> = Vec::new();
    let mut seen = 0usize;
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(std::path::PathBuf::from(root), 0)];

    while let Some((dir, depth)) = stack.pop() {
        if depth > cap_depth {
            return Err(PlatformError::refused(
                format!(
                    "'{root}' 아래가 {cap_depth} 단계보다 깊습니다 (설계-03 §4 재귀 삭제 상한)"
                ),
                format!(
                    "'{root}' goes deeper than {cap_depth} levels (design-03 §4 recursive \
                     delete ceiling)"
                ),
            ));
        }
        let rd =
            std::fs::read_dir(&dir).map_err(|e| PlatformError::io(dir.display().to_string(), e))?;
        for entry in rd {
            let entry = entry.map_err(|e| PlatformError::io(dir.display().to_string(), e))?;
            let path = entry.path();

            seen += 1;
            if seen > cap_entries {
                return Err(PlatformError::refused(
                    format!(
                        "'{root}' 아래 항목이 {cap_entries} 개를 넘습니다 \
                         (설계-03 §4 재귀 삭제 상한)"
                    ),
                    format!(
                        "'{root}' has more than {cap_entries} items below it (design-03 §4 \
                         recursive delete ceiling)"
                    ),
                ));
            }

            // 링크는 따라가지 않는다 — 따라가면 이 디렉터리 밖을 검사하게 되고,
            // 그 결과로 지울지 말지를 정하면 엉뚱한 곳이 판정을 좌우한다.
            // 다만 **그 사실을 답에 반영해야 한다**: 링크가 있으면 그 너머를 보지
            // 못했으므로 "없다" 고 말할 수 없다.
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|e| PlatformError::io(path.display().to_string(), e))?;
            if meta.file_type().is_symlink() {
                let p = path.display();
                return Err(PlatformError::refused(
                    format!("'{p}' 는 링크입니다 — 그 너머에 신뢰 서명된 것이 있는지 확인할 수 없습니다"),
                    format!(
                        "'{p}' is a link — we cannot tell whether anything trust-signed sits \
                         beyond it"
                    ),
                ));
            }

            if meta.is_dir() {
                stack.push((path, depth + 1));
                continue;
            }

            let Some(p) = path.to_str() else {
                let d = path.display();
                return Err(PlatformError::refused(
                    format!("'{d}' 의 이름을 읽지 못해 서명을 확인할 수 없습니다"),
                    format!(
                        "'{d}': its name could not be read, so the signature cannot be checked"
                    ),
                ));
            };
            // 서명을 실을 수 있는 형식만 본다. 나머지는 Authenticode 대상이
            // 아니므로 "확인하지 못했다" 가 아니라 "해당 없음" 이다.
            if !is_signable(p) {
                continue;
            }
            match remedy_wintrust::verify(&path) {
                Ok(v) if v.trusted => {
                    if found.len() < MAX_REPORTED {
                        found.push(match v.subject {
                            Some(s) => format!("{p} ({s})"),
                            None => p.to_string(),
                        });
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(PlatformError::refused(
                        format!("'{p}' 의 서명을 확인하지 못했습니다: {e}"),
                        format!("'{p}': its signature could not be checked: {e}"),
                    ))
                }
            }
        }
    }
    Ok(found)
}

/// Authenticode 를 실을 수 있는 확장자인가.
///
/// `remedy-collect` 의 같은 목록과 **뜻이 같아야 한다** — 한쪽이 보는 것을 다른
/// 쪽이 안 보면, 수집이 신뢰로 적은 파일을 여기서는 못 보고 지우게 된다.
#[cfg(windows)]
fn is_signable(path: &str) -> bool {
    const EXT: &[&str] = &[
        "exe", "dll", "sys", "ocx", "cpl", "scr", "drv", "efi", "msi", "msp", "ax", "node",
    ];
    let Some(dot) = path.rfind('.') else {
        return false;
    };
    let ext = &path[dot + 1..];
    if ext.is_empty() || ext.len() > 4 {
        return false;
    }
    EXT.contains(&ext.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scheduled_verify_site_is_the_runonce_value_the_report_always_named() {
        // 보고의 위치 문구가 호출자(`restart.rs`)에서 백엔드 질의로 옮겨 간다
        // (P12). **Windows 화면은 한 글자도 바뀌면 안 된다** — 그 문자열을
        // 여기 그대로 박아 둔다.
        let site = Live::new()
            .scheduled_verify_site()
            .expect("Windows 는 예약한다");
        assert_eq!(
            site.location,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\remedy-verify"
        );
        assert_eq!(site.removed_by, crate::write::RemovedBy::Os);
        assert!(Live::new().verify_after_reboot_support().is_ok());
    }

    /// 토큰을 펴되 **주석이 영어 회차에서 한글로 나오지 않는가**를 함께 잰다.
    ///
    /// `RootExpansion::notes` 는 `pipeline::scope_from_manifest` 가
    /// `Unresolved { at: "scan_roots" }` 로 바꾸고, `main.rs` 의
    /// `warn_unresolved_extra` 가 `scan`·`run` 의 stderr 로 찍는다. §17 이 그
    /// 화면을 두 언어로 고칠 때 이쪽에서 흘러드는 문구는 손대지 않았다.
    ///
    /// **메서드라 이름 가리기가 안 되므로** 감싸는 함수를 두고 시험이 이것을
    /// 부르게 한다 — 새 시험을 쓰는 사람은 `expand_roots` 를 직접 불러도 되지만,
    /// 그러면 이 검사를 받지 않는다.
    fn expand(live: &Live, root: &str, allow_removable: bool) -> crate::read::RootExpansion {
        use crate::read::ExpandRoots;
        let e = live.expand_roots(root, allow_removable);
        for n in &e.notes {
            assert!(
                !n.chars().any(|c| ('가'..='힣').contains(&c)),
                "수집 주석이 영어 회차에서 한글로 나온다: {n}"
            );
        }
        e
    }

    /// **알리는 시점이 도구마다 다른 이유가 있다.**
    ///
    /// `sc.exe` 가 60초였을 때 그 경고는 영영 뜨지 않았다 — `ControlService` 가
    /// 같은 60초에 포기하고 1053 을 내기 때문이다(2026-09-12 실측). 값을 되돌리면
    /// 이 시험이 먼저 깨진다.
    /// **1053 은 실패지만 '거부' 가 아니다.**
    ///
    /// SCM 이 60초를 기다리다 포기한 것이고 서비스는 아직 멈추는 중이다(실측:
    /// 그 뒤 멈췄다). 예전 문구는 `sc.exe stop 가 실패했다 (종료 코드 1053)`
    /// 하나뿐이라 사람이 무엇을 봐야 할지 알 수 없었다.
    ///
    /// **성공으로 돌리지는 않는다**(결정 2026-09-13) — 정말로 멈추지 않는
    /// 서비스를 '치료 완료' 로 보고하는 것이 더 나쁘다.
    #[test]
    fn a_stop_timeout_says_what_actually_happened() {
        // 목표 상태가 이루어진 둘.
        assert!(stop_reason(0).is_none());
        assert!(
            stop_reason(1062).is_none(),
            "이미 멈춰 있는 것은 실패가 아니다"
        );

        // **언어를 단정하지 않는다.** `cargo test` 아래에서는 영어로 풀린다 —
        // 한국어 낱말을 단정했다가 그것으로 한 번 깨졌다(2026-09-13).
        let err = stop_reason(1053).expect("실패로는 센다");
        let timeout = err.to_string();
        assert!(
            timeout.contains("60"),
            "SCM 의 상한을 말해야 한다: {timeout}"
        );
        assert!(timeout.contains("1053"), "코드를 대야 한다: {timeout}");
        assert!(
            timeout.contains("재평가") || timeout.contains("re-evaluation"),
            "무엇이 답하는지 말해야 한다: {timeout}"
        );
        assert!(
            !timeout.contains("실패했습니다") && !timeout.contains("failed (exit code"),
            "'실패했습니다' 하나로 뭉뚱그리던 옛 문구로 돌아갔다: {timeout}"
        );

        // 그 밖은 종료 코드를 그대로 댄다.
        let other = stop_reason(5).expect("실패다").to_string();
        assert!(other.contains('5'), "{other}");
    }

    /// 1053 은 **거부가 아니다** — 접두가 본문과 반대말을 하지 않아야 한다.
    ///
    /// 문구만 고쳤던 동안 화면은 `거부됐다: … SCM 이 … 포기했다` 였다.
    /// 아무도 거부하지 않은 자리에 "거부" 가 붙어 있었고, 그 어긋남은 부류를
    /// 부르는 쪽이 골랐기 때문에 생겼다. 이제 [`stop_reason`] 이 정하므로
    /// 여기서 물어볼 수 있다.
    #[test]
    fn a_stop_timeout_is_not_called_a_refusal() {
        assert!(
            matches!(stop_reason(1053), Some(PlatformError::TimedOut(_))),
            "1053 은 기다리다 끝난 것이다: {:?}",
            stop_reason(1053)
        );
        // 그 밖의 코드는 SCM 이 요청을 물리친 것이라 거부가 맞다.
        assert!(
            matches!(stop_reason(5), Some(PlatformError::Refused(_))),
            "{:?}",
            stop_reason(5)
        );

        // **접두가 둘을 가른다.** 언어는 단정하지 않고, 서로 다르다는 것만 본다.
        let t = stop_reason(1053).unwrap().to_string();
        let r = stop_reason(5).unwrap().to_string();
        let head = |s: &str| s.split(':').next().unwrap_or_default().to_string();
        assert_ne!(
            head(&t),
            head(&r),
            "두 부류가 같은 접두로 나간다: {t} / {r}"
        );
    }

    #[test]
    fn sc_exe_is_warned_about_before_the_os_gives_up() {
        use std::time::Duration;
        assert_eq!(warn_for("sc.exe"), Duration::from_secs(30));
        assert_eq!(warn_for("SC.EXE"), Duration::from_secs(30), "대소문자 무관");
        // OS 가 포기하는 시점보다 **이르다** 는 것이 이 값의 전부다.
        assert!(warn_for("sc.exe") < crate::tool::WARN_SHORT);

        assert_eq!(warn_for("powershell.exe"), crate::tool::WARN_LONG);
        assert_eq!(warn_for("taskkill.exe"), crate::tool::WARN_SHORT);
        assert_eq!(warn_for("schtasks.exe"), crate::tool::WARN_SHORT);
    }

    #[test]
    fn a_bare_hive_name_opens() {
        // **`HKU\*` 를 펼치려면 `HKU` 자신을 열어야 한다.** 하위 경로가 없는
        // 경로를 거부하던 동안 그 토큰이 통째로 펼쳐지지 않았고, 그 플러그인은
        // 레지스트리 값을 0건으로 보고했다. 실측에서 드러난 결함이다.
        for hive in ["HKU", "HKLM", "HKCU", "HKEY_USERS"] {
            assert!(split_hive(hive).is_ok(), "{hive} 를 열지 못했다");
        }
        assert!(split_hive("HKNOPE").is_err());
        assert!(split_hive("HKNOPE\\x").is_err());
    }

    #[test]
    fn removable_is_not_expanded_without_the_declaration() {
        // **선언이 동의를 대신한다.** 조용히 펼치면 사용자가 예상하지 못한
        // 매체가 범위에 들어온다 (설계-03 §4).
        let live = Live::new();
        let e = expand(&live, "%REMOVABLE%\\", false);
        assert!(e.roots.is_empty(), "{:?}", e.roots);
        assert!(
            e.notes.iter().any(|n| n.contains("allow_removable")),
            "왜 펼치지 않았는지 말해야 한다: {:?}",
            e.notes
        );
    }

    #[test]
    fn a_plain_path_expands_one_to_one() {
        let live = Live::new();
        let e = expand(&live, "C:\\Windows\\System32", false);
        assert_eq!(e.roots, vec!["C:\\Windows\\System32".to_string()]);
        assert!(e.notes.is_empty());
    }

    #[test]
    fn non_wow64_leaves_paths_alone() {
        let live = Live {
            wow64: false,
            system_root: "C:\\Windows".into(),
        };
        let p = "C:\\Windows\\System32\\Tasks\\x";
        assert_eq!(live.for_access(p), p);
    }

    #[test]
    fn wow64_uses_sysnative_for_access_but_records_system32() {
        // 이것이 없으면 32비트 빌드가 SysWOW64 를 보고도 System32 를 봤다고 기록한다.
        let live = Live {
            wow64: true,
            system_root: "C:\\Windows".into(),
        };
        let accessed = live.for_access("C:\\Windows\\System32\\Tasks\\x");
        assert!(
            accessed.to_ascii_lowercase().contains("sysnative"),
            "접근은 Sysnative 로: {accessed}"
        );
        assert_eq!(
            live.for_record(&accessed),
            "C:\\Windows\\System32\\Tasks\\x",
            "기록은 System32 로. **대소문자는 보존한다** — plan.json 이 지목하는 값이다"
        );
    }

    #[test]
    fn wow64_does_not_touch_other_paths() {
        let live = Live {
            wow64: true,
            system_root: "C:\\Windows".into(),
        };
        let p = "C:\\Users\\t\\AppData\\Local\\Programs\\x";
        assert_eq!(live.for_access(p), p);
    }

    #[test]
    fn missing_env_var_is_left_intact() {
        // 조용히 빈 문자열이 되면 `%FOO%\bar` 가 `\bar` 가 되어 전혀 다른 곳을 가리킨다.
        let live = Live::new();
        assert_eq!(
            live.expand("%REMEDY_NO_SUCH_VAR_12345%\\bar"),
            "%REMEDY_NO_SUCH_VAR_12345%\\bar"
        );
    }

    #[test]
    fn env_expansion_works_for_real_vars() {
        let live = Live::new();
        let out = live.expand("%SystemRoot%\\System32");
        assert!(
            out.to_ascii_lowercase().ends_with("\\system32") && !out.contains('%'),
            "전개 결과: {out}"
        );
    }

    // ── 예약 작업 가드 (P7) ───────────────────────────────────

    #[test]
    fn an_ifeo_debugger_stops_us_from_launching_schtasks() {
        // 걸려 있으면 우리가 부르는 것은 schtasks 가 아니다.
        let hooked = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\\
                      Image File Execution Options\\schtasks.exe\\Debugger";
        let why = ifeo_problem("schtasks.exe", &|k| k == hooked).expect("막아야 한다");
        assert!(why.contains("Image File Execution Options"), "{why}");
    }

    #[test]
    fn a_clean_machine_does_not_trip_the_ifeo_guard() {
        // 위 시험이 "무엇이든 막는다" 로 통과하면 안 된다.
        assert_eq!(ifeo_problem("schtasks.exe", &|_| false), None);
        // 다른 이미지에 걸린 것은 우리 일이 아니다.
        assert_eq!(
            ifeo_problem("schtasks.exe", &|k| k.contains("notepad.exe")),
            None
        );
    }

    #[test]
    fn a_registration_path_is_checked_before_the_file_is_touched() {
        // `task_file` 이 `%SystemRoot%\System32\Tasks\<id>` 를 만든다. 검사가
        // 없으면 `..` 하나로 임의 파일 읽기가 된다.
        let live = Live::new();
        for bad in [
            "\\..\\..\\config\\SAM",
            "\\a /Delete /TN \\b",
            "C:\\Windows\\System32\\Tasks\\Locust",
        ] {
            let e = live.task_file(bad).expect_err("거부해야 한다");
            assert!(
                e.to_string().contains("거부됐습니다") || e.to_string().contains("refused"),
                "{bad}: {e}"
            );
        }
    }

    /// **없는 키는 빈 목록이고, 그것이 `read::seen` 의 `Absent` 를 만든다.**
    ///
    /// 이 한 줄을 `Err` 로 올리면 설치되지 않은 제품의 `scan_roots` 가 *"모른다"*
    /// 가 되어 **멀쩡한 기계 전부가 종료 6** 이 된다(B-6 가 고친 자리). 가짜로는
    /// 잴 수 없는 갈래다 — `ErrorKind` 는 실제 레지스트리만 준다. 그래서 실물로
    /// 재고, 쓰지 않는 자리를 골라 **아무것도 만들지 않는다.**
    ///
    /// 짝이 되는 갈래(막힌 키 → `Err` → `CannotTell`)는 `Deny ReadKey` 를
    /// 걸어야 나오므로 여기서 재지 않는다. 실측은 2026-10-27 에 `HKCU` 에
    /// `Deny ReadKey` 를 건 탐침으로 했다(종료 0 → 6).
    #[test]
    fn a_registry_key_that_is_not_there_enumerates_as_empty_not_as_an_error() {
        let live = Live::new();
        let gone = "HKCU\\Software\\remedy-no-such-key-b9\\deeper\\deepest";
        assert!(!live.key_exists(gone));
        assert_eq!(
            live.subkeys(gone).expect("없는 키는 오류가 아니다"),
            Vec::<String>::new()
        );
        assert!(
            live.values(gone)
                .expect("없는 키는 오류가 아니다")
                .is_empty(),
            "값 쪽도 같아야 한다 — 한쪽만 바뀌면 수집기가 갈린다"
        );
        // 그래서 선언 루트는 **없는 루트**로 집계된다.
        assert_eq!(
            crate::read::seen(&live, "HKCU\\Software", "remedy-no-such-key-b9"),
            crate::read::Seen::Absent
        );
    }

    #[test]
    fn a_good_registration_path_lands_in_the_tasks_folder() {
        // 위 시험이 무엇이든 거부하는 것으로 통과하면 안 된다.
        let live = Live::new();
        let p = live
            .task_file("\\Microsoft\\Windows\\Locust")
            .expect("풀려야 한다");
        assert!(
            p.to_ascii_lowercase()
                .ends_with("\\system32\\tasks\\microsoft\\windows\\locust")
                || p.to_ascii_lowercase()
                    .ends_with("\\sysnative\\tasks\\microsoft\\windows\\locust"),
            "{p}"
        );
    }

    #[test]
    fn schtasks_is_not_launched_for_a_bad_registration_path() {
        // 검증이 프로세스를 띄우기 **전에** 있어야 한다.
        let live = Live::new();
        let e = live
            .schtasks(&["/Delete", "/TN", "\\..\\밖", "/F"], "\\..\\밖")
            .expect_err("거부해야 한다");
        assert!(e.to_string().contains("'..'"), "{e}");
    }

    // ── P8 도구·서비스 이름 ───────────────────────────────────

    #[test]
    fn only_known_system_tools_are_launched() {
        // **도구 이름은 코드가 정한다.** 계획이나 매니페스트에서 온 문자열이
        // 실행 파일 이름이 되는 길을 아예 두지 않는다.
        let live = Live::new();
        for bad in ["cmd.exe", "..\\..\\evil.exe", "notepad.exe", ""] {
            let e = live.system_tool(bad, &["/?"]).expect_err("거부해야 한다");
            // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
            let want = remedy_sdk::i18n::t("도구 목록에 없습니다", "not in the list of tools");
            assert!(e.to_string().contains(want), "{bad}: {e}");
        }
    }

    #[test]
    fn a_service_target_must_name_exactly_one_service() {
        // 대상은 `HKLM\SYSTEM\CurrentControlSet\Services\<이름>` 이다. 한 칸
        // 밑이 아니면 엉뚱한 것을 지운다.
        let live = Live::new();
        assert_eq!(
            live.service_name(r"HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc")
                .expect("풀려야 한다"),
            "EvilSvc"
        );
        for bad in [
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            r"HKLM\SYSTEM\CurrentControlSet\Services\Evil\Parameters",
            r"HKLM\SOFTWARE\Evil",
            "EvilSvc",
            r"HKLM\SYSTEM\CurrentControlSet\Services\a /delete b",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\a\"b",
        ] {
            assert!(live.service_name(bad).is_err(), "통과했다: {bad}");
        }
    }

    #[test]
    fn the_service_name_keeps_its_original_case() {
        // 비교만 접어서 한다. 접힌 이름을 `sc.exe` 에 넘기면 대소문자를 가리는
        // 환경에서 다른 것을 지목한다.
        let live = Live::new();
        assert_eq!(
            live.service_name(r"hklm\system\currentcontrolset\services\EvilSvc")
                .expect("풀려야 한다"),
            "EvilSvc"
        );
    }

    #[test]
    fn a_process_listing_carries_the_command_line() {
        // **이것이 비어 있으면 조용히 무너지는 것이 많다.** `process.cmdline`
        // 을 보는 룰, `cmdline_decoded` 로 인코딩을 푸는 길, `process.kill` 의
        // `cmdline_contains` 술어가 전부 여기에 걸려 있다.
        //
        // 실제로 비어 있었다. `sysinfo::refresh_processes` 의 기본 갱신 종류에
        // `cmd` 가 없고, 그것을 P8 워치독 하네스가 잡았다 — `image_path` 로는
        // 찾는데 `cmdline_contains` 로는 못 찾았다.
        //
        // 표식을 인자로 들고 도는 자식을 띄워서 되짚는다. `ping -n` 은 어느
        // Windows 에나 있고, 인자가 명령줄에 그대로 남는다.
        let marker = format!("REMEDY-CMDLINE-{}", std::process::id());
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let mut child = std::process::Command::new(format!(r"{root}\System32\cmd.exe"))
            .args([
                "/c",
                "ping",
                "-n",
                "8",
                "127.0.0.1",
                ">nul",
                "&&",
                "rem",
                &marker,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("자식을 띄우지 못했다");

        let live = Live::new();
        let mut seen = false;
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Ok(list) = live.processes() {
                if list.iter().any(|p| p.cmdline.contains(&marker)) {
                    seen = true;
                    break;
                }
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(seen, "프로세스 목록에 명령줄이 실려 오지 않았다");
    }

    #[test]
    fn the_lineage_walk_finds_a_real_child() {
        // 가짜 백엔드는 부모 지도를 손으로 준다. **여기서만 진짜 OS 가 준
        // 계보를 본다** — `sysinfo` 의 `parent()` 가 갱신 종류에 걸려 비어
        // 있었다면(`cmd` 가 그랬듯) 이 시험만이 잡는다.
        use crate::write::PlatformWrite;
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let mut child = std::process::Command::new(format!(r"{root}\System32\cmd.exe"))
            .args(["/c", "ping", "-n", "8", "127.0.0.1"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("자식을 띄우지 못했다");

        let live = Live::new();
        let me = std::process::id();
        let mut found = false;
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Ok(kin) = live.process_descendants(&[me]) {
                if kin.iter().any(|t| t.pid == child.id()) {
                    found = true;
                    break;
                }
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(found, "계보 탐색이 제 자식을 찾지 못했다");
    }

    #[test]
    fn a_process_is_never_its_own_ancestor_and_strangers_stay_out() {
        // 계보가 "전부" 를 돌려주면 `include_descendants` 는 술어를 무의미하게
        // 만든다. 시스템에는 언제나 프로세스가 여럿 도는데 자식을 하나도 띄우지
        // 않은 뿌리에서 무언가 나온다면, 그것은 걷기가 아니라 열거다.
        use crate::write::PlatformWrite;
        let live = Live::new();
        // PID 0 은 어떤 프로세스도 아니다. 그런데 부모를 모르는 프로세스의
        // `parent()` 가 0 으로 실려 오면, 순진한 구현은 여기서 세상 전부를 준다.
        let kin = live.process_descendants(&[0]).expect("걷기");
        assert!(kin.is_empty(), "PID 0 에서 {}개가 나왔다", kin.len());
    }
    // ── Defender 예외를 바꾸는 PowerShell ───────────────────────

    #[test]
    fn a_single_quote_is_the_only_escape() {
        // 홑따옴표 리터럴 안에서는 `$`·백틱·큰따옴표가 전부 글자다. 규칙이
        // 하나뿐이라 이 방식을 골랐다 — 규칙이 늘면 빠뜨린 하나가 곧 실행이다.
        assert_eq!(ps_literal("C:\\a b"), "'C:\\a b'");
        assert_eq!(ps_literal("it's"), "'it''s'");
        assert_eq!(
            ps_literal("$(calc)`n\"x\""),
            "'$(calc)`n\"x\"'",
            "확장 문법이 살아나면 제외 항목 이름이 곧 실행될 코드가 된다"
        );
    }

    #[test]
    fn the_encoded_command_has_no_shell_metacharacters() {
        // `-EncodedCommand` 를 쓰는 이유가 이것이다. 명령줄에 실리는 글자가
        // base64 알파벳뿐이면 인용 층이 통째로 사라진다.
        let e = encode_command("Remove-MpPreference -ExclusionPath 'C:\\a b' # \" $x");
        assert!(
            e.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "{e}"
        );
    }

    #[test]
    fn encoding_is_utf16_le_as_powershell_expects() {
        // ASCII 한 글자가 2바이트다. 잘못된 인코딩으로 넘기면 PowerShell 이
        // 조용히 다른 것을 실행한다.
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encode_command("ab"))
            .expect("base64");
        assert_eq!(raw, vec![b'a', 0, b'b', 0]);
    }

    #[test]
    fn korean_survives_the_round_trip() {
        // 제외 경로에 한글이 들어가는 것은 흔하다 (`C:\사용자\...`).
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encode_command("가"))
            .expect("base64");
        let u: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&u).unwrap(), "가");
    }
}
