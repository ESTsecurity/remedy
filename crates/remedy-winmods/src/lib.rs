//! remedy-winmods — Windows 프로세스에 실린 모듈 (목표 기준 7 의 마지막 항목), 그리고 권한을 올려 이 프로그램을
//! 다시 여는 호출 하나([`relaunch_elevated`]).
//!
//! # 저장소에서 `unsafe` 를 쓰는 둘째 크레이트다
//!
//! 권한을 올려 다시 여는 `ShellExecuteExW`(`runas`)도 안전 래퍼가 없는 Windows 호출이라 여기 둔다 — 그
//! 함수 하나 때문에 `unsafe` 예외 크레이트를 하나 더 세우지 않는다.
//!
//! 모듈 목록은 Toolhelp 스냅숏(`CreateToolhelp32Snapshot` · `Module32FirstW/NextW`)으로 얻고, 260 글자를
//! 넘는 경로만 `K32GetModuleFileNameExW` 로 다시 묻는다. 모두 안전 래퍼가 없다 — `sysinfo` 는 실행 파일
//! 경로까지만 주고, Linux 처럼 읽을 파일(`/proc/<pid>/maps`)도 없다. `remedy-platform` 의 `forbid` 를 푸는
//! 대신 이 호출과 그 둘레(프로세스 열기 · 보호 수준 · 끝났는지 · 닫기)를 이 크레이트 하나에 가둔다 —
//! `remedy-wintrust` 와 같은 판단이다(설계-04 §1). 다른 크레이트는 `forbid(unsafe_code)` 를 그대로 두고,
//! `xtask arch` 가 예외 목록 밖의 크레이트를 막는다.
//!
//! 모두 kernel32 의 함수다 — `psapi.dll` 의 같은 함수는 배포본의 임포트에 DLL 하나를 더한다.
//!
//! # 답은 넷이다 — 읽음 · 끝남 · 보호 · 거부
//!
//! 2026-11-12 랩 VM(Windows 10 22H2 · 관리자 · 프로세스 158개) 실측:
//!
//! | 답 | 수 | 무엇 |
//! |---|---|---|
//! | [`Modules::Read`] | 139 | SYSTEM 서비스까지 관리자 토큰으로 열린다 |
//! | [`Modules::Protected`] | 16 | 보호 프로세스(PPL) — Defender · 백신 서비스 · `csrss` · `System` 등. 여는 것부터 거부된다 |
//! | [`Modules::Gone`] | 1 | `Idle`(pid 0) — 열 수 있는 프로세스가 아니다. 묻는 사이에 끝난 것도 여기다(다른 회차에 `conhost` 하나) |
//! | [`Modules::Refused`] | 2 | 보호 프로세스가 아닌데 목록만 거부한다 — 스스로를 지키는 보안 제품(nProtect 의 둘) |
//!
//! **보호는 거부가 아니다.** 보호 프로세스는 OS 가 정한 서명의 모듈만 싣는다 — PHP 의 DLL 은
//! 실릴 수 없다. 그것을 거부로 세면 모든 Windows 가 늘 관측 불완전이 된다.
//!
//! # 디버그 권한을 켜지 않는다
//!
//! 같은 실측에서 `SeDebugPrivilege` 를 끈 토큰과 켠 토큰의 답이 같았다(읽음 140 · 나머지 19 가 같은
//! 목록). 관리자 토큰만으로 SYSTEM 서비스(서비스로 띄운 Apache 가 그 자리다)의 모듈이 읽힌다 —
//! 쓰지 않는 권한을 켜지 않는다.

/// 한 프로세스의 모듈을 물은 답.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modules {
    /// 읽었다 — 실린 모듈의 경로(실행 파일 자신을 포함한다)를 OS 가 준 차례로.
    Read(Vec<String>),
    /// 묻는 사이에 끝났거나 그런 pid 가 없다. **거부가 아니다** — 열거와 읽기 사이에 프로세스가
    /// 끝나는 것은 정상이다.
    Gone,
    /// 보호 프로세스(PPL)다. 서명된 모듈만 실을 수 있어 PHP · Node 의 모듈이 들어갈 자리가 아니다.
    Protected,
    /// 보호 프로세스가 아닌데 목록을 내주지 않았다. 못 본 것이므로 부르는 쪽이 **거부로 적는다.**
    Refused,
}

/// pid 하나의 모듈을 묻는다.
///
/// Windows 밖에서는 늘 [`Modules::Refused`] 다 — 이 크레이트를 부르는 곳은 Windows 백엔드뿐이고,
/// 다른 플랫폼에서 불렸다면 그것은 *읽지 못했다* 로 말해야 한다(빈 목록이 *"모듈이 없다"* 가 되지
/// 않게).
pub fn modules_of(pid: u32) -> Modules {
    #[cfg(windows)]
    {
        imp::modules_of(pid)
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Modules::Refused
    }
}

/// 한 프로세스의 실행 파일을 **열지 않고** 물은 답([`image_paths_of`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Image {
    /// 실행 파일 경로 — 장치 경로(`\Device\HarddiskVolume3\…`)를 드라이브 문자(`C:\…`)로 바꾼 것.
    Path(String),
    /// **실행 파일이 없는 프로세스**다 — 커널이 띄운 최소 프로세스(`System` · `Secure System` · `Registry` ·
    /// `MemCompression` · `vmmemWSL`). 파일에서 실린 것이 없어 모듈도 없다 — 못 본 것이 없으니 **거부가 아니다.**
    /// OS 의 답이 성공인데 이름이 비었거나 장치 경로가 아닌(`\` 로 시작하지 않는) 짧은 이름일 때다 — 파일에서 띄운
    /// 프로세스는 늘 장치 경로를 받는다(2026-11-19 실측: `System` · `Secure System` 은 빈 이름, 나머지 셋은 짧은 이름).
    NoFile,
    /// 모른다 — 묻는 사이에 끝났거나, 묻지 못했거나, 드라이브 문자로 바꿀 수 없는 자리(네트워크 공유 · 문자 없는
    /// 볼륨)다. 부르는 쪽은 지금처럼 *모른다* 로 둔다.
    Unknown,
}

/// pid 마다 **실행 파일** — 프로세스를 **열지 않고** OS 에 묻는다(`NtQuerySystemInformation` 의
/// `SystemProcessIdInformation`). 답은 [`Image`] 셋 중 하나다.
///
/// # 왜 필요한가 (1.25.0 · 2026-11-19 실측)
///
/// 실제 PC(Windows 11 · 관리자로 연 콘솔)에서 빠른 검사의 점검 항목마다 *"접근이 거부된 디렉터리 열기 37회"* 가
/// 서고 모두 6 이 됐다. 거부된 것은 폴더가 아니라 **실행 파일 경로를 읽지 못한 프로세스**였고(`pid N`), 그 32개
/// 표본은 보안 제품이 아니라 서비스 계정으로 도는 평범한 Windows · 서비스 프로세스였다 — `csrss` · `fontdrvhost` ·
/// `conhost` · `dwm` · `WUDFHost` · `WmiPrvSE` · `NgcIso` 등. 관리자 토큰으로도 그 프로세스의 DACL 이 여는 것을 막아
/// `sysinfo` 의 경로도, 가장 좁은 권한의 [`modules_of`] 도 거부됐다(랩 VM 은 원격 셸이라 이 일이 없었다). 이 호출은
/// 열지 않으므로 그 DACL 에 걸리지 않는다 — 디버그 권한을 켜지 않는다는 결정(위 *디버그 권한을 켜지 않는다*)도
/// 그대로다. 같은 PC 의 32개 표본은 이 길로 모두 경로를 얻었다.
///
/// 경로를 모르는 채로 그 프로세스를 *룰과 상관없다* 고 건너뛰지 않는 까닭: IIS 의 앱 풀 계정으로 도는 `php-cgi.exe`
/// 처럼 판정의 대상이 바로 그런 프로세스일 수 있다. 경로를 알면 룰이 그 경로로 판정하고, 수집기는 *경로가 보이는
/// 거부* 를 관측 불완전으로 세지 않는다(`remedy-collect` 의 `processes`).
///
/// 같은 PC 에서 이 길로도 경로가 없는 것은 실행 파일이 없는 최소 프로세스뿐이었다([`Image::NoFile`] — `System` ·
/// `Secure System` · `Registry` · `MemCompression` · WSL 의 `vmmemWSL` · 관리자가 아닌 셸에서 프로세스 전부를 쟀다).
/// 그것은 열지 못하면 모듈 거부로 돌아오므로 부르는 쪽이 모듈을 묻지 않는다.
///
/// Windows 밖에서는 모두 [`Image::Unknown`] 이다.
pub fn image_paths_of(pids: &[u32]) -> Vec<Image> {
    #[cfg(windows)]
    {
        imp::image_paths_of(pids)
    }
    #[cfg(not(windows))]
    {
        vec![Image::Unknown; pids.len()]
    }
}

/// UAC 창에서 [아니요]를 골랐다 — `ERROR_CANCELLED`.
pub const DECLINED: u32 = 1223;

/// 이 프로그램을 **관리자 권한으로 다시 연다** — 사용자 계정 컨트롤(UAC) 창이 뜬다(목표 remedy_시연전_안정화
/// D8). 탐색기에서 더블클릭한 메뉴는 권한 없이 뜨고, 검사 · 치료는 관리자 권한이 있어야 돈다.
///
/// `Ok(())` 는 새 창이 떴다는 뜻이다 — 부르는 쪽은 제 창을 닫는다. `Err` 는 Win32 오류 번호다([`DECLINED`] 는
/// 사람이 거절한 것). Windows 밖에서는 늘 `Err(0)` 이다.
pub fn relaunch_elevated(exe: &std::path::Path, dir: &std::path::Path) -> Result<(), u32> {
    #[cfg(windows)]
    {
        elevate::relaunch(exe, dir)
    }
    #[cfg(not(windows))]
    {
        let _ = (exe, dir);
        Err(0)
    }
}

#[cfg(windows)]
mod elevate {
    //! 호출부. 넘기는 문자열은 모두 이 함수의 지역 값(NUL 로 끝나는 UTF-16)이고 호출이 끝날 때까지 산다.

    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub(super) fn relaunch(exe: &std::path::Path, dir: &std::path::Path) -> Result<(), u32> {
        let verb = wide(std::ffi::OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let directory = wide(dir.as_os_str());
        // SAFETY: 모든 칸이 정수 · 포인터 · 공용체인 C 구조체라 0 바이트가 올바른 값이다.
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        // 부른 쪽은 곧바로 끝난다 — 실행이 끝까지 간 뒤에 돌아오게 한다(문서의 권고).
        info.fMask = SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpDirectory = directory.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        // SAFETY: `info` 와 그것이 가리키는 세 문자열은 이 함수의 지역 값이고 호출이 끝날 때까지 산다.
        if unsafe { ShellExecuteExW(&mut info) } != 0 {
            Ok(())
        } else {
            // SAFETY: 같은 스레드에서 바로 앞 호출의 오류를 읽는다.
            Err(unsafe { GetLastError() })
        }
    }
}

#[cfg(windows)]
mod imp {
    //! 호출부. **이 모듈만 `unsafe` 를 쓴다** — 핸들은 [`Owned`] 가 닫고, 구조체 · 버퍼는 Rust 가 소유한
    //! 지역 값이며, 넘기는 크기는 늘 그 값의 크기다.
    //!
    //! # 목록은 Toolhelp 스냅숏 한 번으로 받는다
    //!
    //! 처음에는 `K32EnumProcessModulesEx` 로 핸들을 받고 모듈마다 `K32GetModuleFileNameExW` 로 경로를
    //! 물었다. 그 함수는 부를 때마다 대상 프로세스의 로더 목록을 **처음부터 다시 걷는다** — 모듈 수의 제곱으로
    //! 늘어 랩 VM(프로세스 160여 개)에서 검사 하나에 5초쯤 들었다. 스냅숏(`CreateToolhelp32Snapshot`)은 목록을
    //! 한 번에 경로째 준다. 경로 칸이 `MAX_PATH`(260)라 칸을 다 채운 모듈만 긴 경로 API 로 다시 묻는다.

    use super::{Image, Modules};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_BAD_LENGTH, ERROR_INVALID_PARAMETER, ERROR_PARTIAL_COPY,
        HANDLE, HMODULE, INVALID_HANDLE_VALUE, MAX_PATH, STILL_ACTIVE,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };
    use windows_sys::Win32::System::ProcessStatus::K32GetModuleFileNameExW;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessInformation, OpenProcess, ProcessProtectionLevelInfo,
        PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, PROTECTION_LEVEL_NONE,
    };

    /// 스냅숏을 다시 묻는 횟수 — 막 뜨거나 끝나는 프로세스는 `ERROR_PARTIAL_COPY` · `ERROR_BAD_LENGTH` 를
    /// 내고, 문서가 다시 물으라고 한다.
    const SNAPSHOT_TRIES: usize = 3;
    /// 모듈 수의 상한. 넘으면 목록을 다 읽지 못한 것이라 [`Modules::Refused`] 로 말한다 — 앞쪽만 담으면
    /// 뒤쪽 모듈을 겨눈 룰이 조용히 미탐이 된다.
    const MAX_MODULES: usize = 65_536;
    /// 긴 경로 한 줄의 칸(UTF-16). 긴 경로(`\\?\`)의 상한이 32,767 글자다.
    const PATH_CHARS: usize = 32_768;

    /// 연 핸들(프로세스 · 스냅숏). 떨어질 때 닫는다.
    struct Owned(HANDLE);

    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: 만든 쪽이 유효한 핸들만 담고, 이 값은 여기서 한 번만 닫힌다.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    /// 프로세스를 연다. 실패하면 Win32 오류 번호.
    fn open(pid: u32, access: u32) -> Result<Owned, u32> {
        // SAFETY: 포인터를 받지 않는 호출이다. 돌려준 핸들은 `Owned` 가 소유한다.
        let h = unsafe { OpenProcess(access, 0, pid) };
        if h.is_null() {
            // SAFETY: 같은 스레드에서 바로 앞 호출의 오류를 읽는다.
            Err(unsafe { GetLastError() })
        } else {
            Ok(Owned(h))
        }
    }

    pub(super) fn modules_of(pid: u32) -> Modules {
        // **pid 0 은 Toolhelp 에서 '이 프로세스' 다** — `Idle` 의 목록으로 제 모듈을 내면 안 된다.
        if pid == 0 {
            return Modules::Gone;
        }
        match snapshot(pid) {
            Ok(paths) => Modules::Read(paths),
            // 그런 pid 가 없다 — 열거 뒤에 끝난 프로세스가 여기로 온다.
            Err(ERROR_INVALID_PARAMETER) => Modules::Gone,
            Err(_) => classify(pid),
        }
    }

    /// 목록을 내주지 않은 프로세스가 끝났는가 · 보호 프로세스인가 · 거부인가 — 가장 좁은 권한으로
    /// 묻는다(보호 프로세스도 그 권한은 내준다).
    fn classify(pid: u32) -> Modules {
        let p = match open(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
            Ok(p) => p,
            Err(ERROR_INVALID_PARAMETER) => return Modules::Gone,
            Err(_) => return Modules::Refused,
        };
        if exited(&p) {
            return Modules::Gone;
        }
        let mut info = PROCESS_PROTECTION_LEVEL_INFORMATION { ProtectionLevel: 0 };
        let size = std::mem::size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32;
        // SAFETY: `info` 는 이 함수의 지역 값이고, 넘기는 크기는 그 구조체의 크기 그대로다.
        let ok = unsafe {
            GetProcessInformation(
                p.0,
                ProcessProtectionLevelInfo,
                (&mut info as *mut PROCESS_PROTECTION_LEVEL_INFORMATION).cast(),
                size,
            )
        };
        // 묻지 못했으면 보호라고 짐작하지 않는다 — 못 본 것은 거부다.
        if ok != 0 && info.ProtectionLevel != PROTECTION_LEVEL_NONE {
            Modules::Protected
        } else {
            Modules::Refused
        }
    }

    /// 그 프로세스가 이미 끝났는가.
    fn exited(p: &Owned) -> bool {
        let mut code = 0u32;
        // SAFETY: `code` 는 이 함수의 지역 값이다.
        let ok = unsafe { GetExitCodeProcess(p.0, &mut code) };
        ok != 0 && code != STILL_ACTIVE as u32
    }

    /// 모듈 경로 전부(32비트 프로세스의 모듈도). 실패하면 Win32 오류 번호.
    fn snapshot(pid: u32) -> Result<Vec<String>, u32> {
        let mut last = ERROR_PARTIAL_COPY;
        for _ in 0..SNAPSHOT_TRIES {
            // SAFETY: 포인터를 받지 않는 호출이다. 돌려준 핸들은 `Owned` 가 소유한다.
            let h =
                unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
            if h == INVALID_HANDLE_VALUE {
                // SAFETY: 같은 스레드에서 바로 앞 호출의 오류를 읽는다.
                last = unsafe { GetLastError() };
                if last == ERROR_PARTIAL_COPY || last == ERROR_BAD_LENGTH {
                    continue;
                }
                return Err(last);
            }
            let snap = Owned(h);
            return walk(&snap, pid);
        }
        Err(last)
    }

    /// 스냅숏의 모듈을 차례로 읽는다.
    fn walk(snap: &Owned, pid: u32) -> Result<Vec<String>, u32> {
        // SAFETY: 모든 칸이 정수 · 포인터 · 정수 배열인 C 구조체라 0 바이트가 올바른 값이다.
        let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        let mut out = Vec::new();
        // SAFETY: `entry` 는 이 함수의 지역 값이고 `dwSize` 를 그 크기로 채웠다.
        let mut ok = unsafe { Module32FirstW(snap.0, &mut entry) };
        let mut long: Option<Owned> = None;
        while ok != 0 {
            if out.len() >= MAX_MODULES {
                return Err(ERROR_PARTIAL_COPY);
            }
            let n = entry
                .szExePath
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExePath.len());
            if n + 1 >= MAX_PATH as usize {
                // 칸을 다 채웠다 — 잘렸을 수 있다. 긴 경로 API 로 다시 묻고, 못 물으면 그 모듈은 넣지
                // 않는다(잘린 경로는 다른 파일을 가리킨다).
                if long.is_none() {
                    long = open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).ok();
                }
                if let Some(p) = &long {
                    if let Some(path) = long_path(p, entry.hModule) {
                        out.push(path);
                    }
                }
            } else if n > 0 {
                out.push(String::from_utf16_lossy(&entry.szExePath[..n]));
            }
            // SAFETY: 위와 같다 — 같은 지역 값을 다시 채운다.
            ok = unsafe { Module32NextW(snap.0, &mut entry) };
        }
        Ok(out)
    }

    /// 긴 경로 하나. 그 사이에 내려간 모듈이거나 칸을 다 채우면 `None`.
    fn long_path(p: &Owned, m: HMODULE) -> Option<String> {
        let mut buf = vec![0u16; PATH_CHARS];
        // SAFETY: `buf` 는 `PATH_CHARS` 칸이고 그 수를 그대로 넘긴다. 쓰인 글자 수만 읽는다.
        let n =
            unsafe { K32GetModuleFileNameExW(p.0, m, buf.as_mut_ptr(), buf.len() as u32) } as usize;
        (n > 0 && n < buf.len()).then(|| String::from_utf16_lossy(&buf[..n]))
    }

    // ── 열지 않고 묻는 실행 파일 경로 (1.25.0) ───────────────────────────────────────

    use windows_sys::Wdk::System::SystemInformation::{
        NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS,
    };
    use windows_sys::Win32::Foundation::{NTSTATUS, UNICODE_STRING};
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

    /// `SystemProcessIdInformation` — 문서에 이름이 없는 정보 갈래다(`windows-sys` 에 상수가 없다). Vista 부터 있고
    /// 작업 관리자 · Process Explorer 가 열 수 없는 프로세스의 이름을 이 길로 얻는다.
    const SYSTEM_PROCESS_ID_INFORMATION: SYSTEM_INFORMATION_CLASS = 88;
    /// 칸이 모자랐다 — 답의 `MaximumLength` 가 필요한 바이트 수다.
    const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC000_0004_u32 as i32;
    /// 처음 칸(UTF-16 글자). 거의 모든 경로가 들어간다.
    const NAME_CHARS: usize = 1024;
    /// `UNICODE_STRING` 의 길이 칸이 16비트 바이트 수라 그보다 긴 이름은 없다.
    const NAME_CHARS_MAX: usize = (u16::MAX as usize) / 2;

    /// 그 정보 갈래의 입출력 구조체(ntdll 의 `SYSTEM_PROCESS_ID_INFORMATION`).
    #[repr(C)]
    struct ProcessIdInfo {
        process_id: HANDLE,
        image_name: UNICODE_STRING,
    }

    pub(super) fn image_paths_of(pids: &[u32]) -> Vec<Image> {
        // 드라이브 문자 표는 한 번만 짓는다 — 프로세스마다 26 번 묻지 않게.
        let drives = drive_devices();
        pids.iter()
            .map(|&pid| match nt_image_name(pid) {
                Some(nt) => image_from(&nt, &drives),
                // 묻지 못했다 — 없는 pid(묻는 사이에 끝났거나 `Idle`)는 `STATUS_INVALID_CID` 다.
                None => Image::Unknown,
            })
            .collect()
    }

    /// OS 가 준 이름 하나를 [`Image`] 로. 빈 이름 · 장치 경로가 아닌 짧은 이름은 실행 파일이 없는 프로세스다.
    pub(super) fn image_from(nt: &str, drives: &[(char, String)]) -> Image {
        if !nt.starts_with('\\') {
            return Image::NoFile;
        }
        to_dos(nt, drives).map_or(Image::Unknown, Image::Path)
    }

    /// pid 하나의 이미지 이름. 답이 성공이면 `Some`(빈 이름일 수 있다), 묻지 못했으면 `None`.
    fn nt_image_name(pid: u32) -> Option<String> {
        let mut chars = NAME_CHARS;
        for _ in 0..3 {
            let mut buf = vec![0u16; chars];
            let mut info = ProcessIdInfo {
                process_id: pid as usize as HANDLE,
                image_name: UNICODE_STRING {
                    Length: 0,
                    MaximumLength: (buf.len() * 2) as u16,
                    Buffer: buf.as_mut_ptr(),
                },
            };
            // SAFETY: `info` 와 그것이 가리키는 `buf` 는 이 함수의 지역 값이고 호출이 끝날 때까지 산다. 넘기는 크기는
            // 구조체의 크기 그대로이고, OS 는 `MaximumLength` 바이트까지만 `buf` 에 쓴다.
            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_PROCESS_ID_INFORMATION,
                    (&mut info as *mut ProcessIdInfo).cast(),
                    std::mem::size_of::<ProcessIdInfo>() as u32,
                    std::ptr::null_mut(),
                )
            };
            if status == STATUS_INFO_LENGTH_MISMATCH {
                let need = info.image_name.MaximumLength as usize / 2 + 1;
                if need <= chars || need > NAME_CHARS_MAX {
                    return None;
                }
                chars = need;
                continue;
            }
            if status < 0 {
                return None;
            }
            let n = info.image_name.Length as usize / 2;
            if n > buf.len() {
                return None;
            }
            // 성공인데 빈 이름 — `System` · `Secure System` 이다([`image_from`] 이 실행 파일 없음으로 읽는다).
            return Some(String::from_utf16_lossy(&buf[..n]));
        }
        None
    }

    /// 드라이브 문자마다 그 장치 이름(`C:` → `\Device\HarddiskVolume3`). 묻지 못한 문자는 빠진다.
    fn drive_devices() -> Vec<(char, String)> {
        let mut out = Vec::new();
        for letter in b'A'..=b'Z' {
            let name = [u16::from(letter), u16::from(b':'), 0];
            let mut target = vec![0u16; NAME_CHARS];
            // SAFETY: `name` 은 NUL 로 끝나는 지역 값이고, `target` 은 `NAME_CHARS` 칸이며 그 수를 그대로 넘긴다.
            let n =
                unsafe { QueryDosDeviceW(name.as_ptr(), target.as_mut_ptr(), target.len() as u32) }
                    as usize;
            if n == 0 || n > target.len() {
                continue;
            }
            // 답은 NUL 로 나뉜 여러 줄일 수 있다 — 첫 줄이 지금 그 문자가 가리키는 장치다.
            let end = target[..n].iter().position(|&c| c == 0).unwrap_or(n);
            if end > 0 {
                out.push((char::from(letter), String::from_utf16_lossy(&target[..end])));
            }
        }
        out
    }

    /// 장치 경로를 드라이브 문자 경로로. 맞는 장치가 없으면 `None`.
    pub(super) fn to_dos(nt: &str, drives: &[(char, String)]) -> Option<String> {
        drives.iter().find_map(|(letter, dev)| {
            let head = nt.get(..dev.len())?;
            let rest = nt.get(dev.len()..)?;
            (head.eq_ignore_ascii_case(dev) && rest.starts_with('\\'))
                .then(|| format!("{letter}:{rest}"))
        })
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// 이 시험 프로세스는 제 실행 파일과 `ntdll.dll` 을 싣는다.
    #[test]
    fn this_process_lists_its_own_modules() {
        let Modules::Read(mods) = modules_of(std::process::id()) else {
            panic!("제 모듈을 읽지 못했다");
        };
        let me = std::env::current_exe().expect("실행 파일 경로");
        let me = me.to_string_lossy().to_lowercase();
        assert!(
            mods.iter().any(|m| m.to_lowercase() == me),
            "제 실행 파일이 목록에 없다: {mods:?}"
        );
        assert!(
            mods.iter()
                .any(|m| m.to_lowercase().ends_with("\\ntdll.dll")),
            "ntdll.dll 이 목록에 없다: {mods:?}"
        );
    }

    /// 없는 pid 는 거부가 아니라 *끝남* 이다 — 거부로 세면 열거 뒤에 끝난 프로세스가 회차를 관측
    /// 불완전으로 만든다. Windows 의 pid 는 4 의 배수라 4 로 나누어떨어지지 않는 큰 값은 쓰이지 않는다.
    #[test]
    fn a_missing_pid_is_gone() {
        assert_eq!(modules_of(0xFFFF_FFF1), Modules::Gone);
    }

    /// 열지 않고 물은 제 경로가 `current_exe` 와 같다 — 장치 경로를 드라이브 문자로 바꾸는 길까지 재는 셈이다.
    #[test]
    fn this_process_image_path_without_opening() {
        let got = image_paths_of(&[std::process::id()]);
        let me = std::env::current_exe().expect("실행 파일 경로");
        assert_eq!(got.len(), 1);
        let Image::Path(path) = &got[0] else {
            panic!("제 경로를 묻지 못했다: {:?}", got[0]);
        };
        assert!(
            path.eq_ignore_ascii_case(&me.to_string_lossy()),
            "{path} ≠ {}",
            me.display()
        );
    }

    /// 없는 pid · `Idle` 은 *모른다* 이고, `System` 은 *실행 파일이 없다* 다 — 거부로 셀 프로세스가 아니다.
    #[test]
    fn missing_idle_and_system() {
        assert_eq!(
            image_paths_of(&[0xFFFF_FFF1, 0, 4]),
            vec![Image::Unknown, Image::Unknown, Image::NoFile]
        );
    }

    /// OS 의 답 하나를 읽는 규칙 — 빈 이름 · 짧은 이름은 실행 파일 없음, 장치 경로는 드라이브 문자로, 바꿀 수 없는
    /// 장치 경로는 모름(2026-11-19 실측한 답의 꼴 그대로).
    #[test]
    fn os_answers_turn_into_images() {
        let drives = vec![('C', String::from(r"\Device\HarddiskVolume3"))];
        for minimal in [
            "",
            "Registry",
            "MemCompression",
            "vmmemWSL",
            "Secure System",
        ] {
            assert_eq!(
                imp::image_from(minimal, &drives),
                Image::NoFile,
                "{minimal:?}"
            );
        }
        assert_eq!(
            imp::image_from(
                r"\Device\HarddiskVolume3\Windows\System32\vmwp.exe",
                &drives
            ),
            Image::Path(String::from(r"C:\Windows\System32\vmwp.exe"))
        );
        assert_eq!(
            imp::image_from(r"\Device\Mup\server\share\php-cgi.exe", &drives),
            Image::Unknown
        );
    }

    /// 장치 경로 → 드라이브 문자. 장치 이름의 대소문자는 가리지 않고, 장치 이름 바로 뒤가 `\` 일 때만이다
    /// (`HarddiskVolume3` 가 `HarddiskVolume30` 의 앞부분으로 맞지 않게).
    #[test]
    fn device_paths_turn_into_drive_letters() {
        let drives = vec![
            ('C', String::from(r"\Device\HarddiskVolume3")),
            ('D', String::from(r"\Device\HarddiskVolume30")),
        ];
        assert_eq!(
            imp::to_dos(
                r"\Device\HarddiskVolume3\Windows\System32\csrss.exe",
                &drives
            )
            .as_deref(),
            Some(r"C:\Windows\System32\csrss.exe")
        );
        assert_eq!(
            imp::to_dos(r"\device\harddiskvolume30\web\nginx.exe", &drives).as_deref(),
            Some(r"D:\web\nginx.exe")
        );
        assert_eq!(
            imp::to_dos(r"\Device\Mup\server\share\x.exe", &drives),
            None
        );
        assert_eq!(imp::to_dos(r"\Device\HarddiskVolume3", &drives), None);
    }

    /// 진단용(기본으로 돌지 않는다) — `REMEDY_TEST_PIDS`(쉼표로 나눈 pid)마다 열지 않고 물은 경로를 적는다. 관리자로도
    /// 열 수 없는 프로세스가 경로를 얻는지 이 기계에서 볼 때 쓴다.
    #[test]
    #[ignore]
    fn print_image_paths_of_given_pids() {
        let pids: Vec<u32> = std::env::var("REMEDY_TEST_PIDS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        for (pid, image) in pids.iter().zip(image_paths_of(&pids)) {
            let shown = match image {
                Image::Path(path) => path,
                Image::NoFile => String::from("(실행 파일 없음)"),
                Image::Unknown => String::from("(모름)"),
            };
            println!("{pid}\t{shown}");
        }
    }

    /// `Idle`(pid 0) 도 끝남이다(랩 VM 실측과 같다).
    #[test]
    fn the_idle_process_is_gone() {
        assert_eq!(modules_of(0), Modules::Gone);
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    /// Windows 밖에서 불리면 빈 목록이 아니라 *읽지 못했다* 로 말한다.
    #[test]
    fn outside_windows_it_says_refused() {
        assert_eq!(modules_of(std::process::id()), Modules::Refused);
    }

    /// Windows 밖에서는 실행 파일을 묻지 않는다 — *실행 파일 없음* 이 아니라 *모른다* 로 답한다.
    #[test]
    fn outside_windows_image_is_unknown() {
        assert_eq!(
            image_paths_of(&[1, 2]),
            vec![Image::Unknown, Image::Unknown]
        );
    }

    /// Windows 밖에서는 다시 열지 않는다 — 거절(1223)이 아닌 오류로 답한다.
    #[test]
    fn outside_windows_relaunch_is_not_attempted() {
        let here = std::path::Path::new(".");
        assert_eq!(relaunch_elevated(here, here), Err(0));
    }
}
