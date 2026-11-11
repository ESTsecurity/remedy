//! remedy-winmods — Windows 프로세스에 실린 모듈 (목표 기준 7 의 마지막 항목).
//!
//! # 저장소에서 `unsafe` 를 쓰는 둘째 크레이트다
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

    use super::Modules;
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
}
