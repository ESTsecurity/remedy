//! remedy-winmods — Windows 프로세스에 실린 모듈 (목표 기준 7 의 마지막 항목).
//!
//! # 저장소에서 `unsafe` 를 쓰는 둘째 크레이트다
//!
//! 모듈 목록은 `K32EnumProcessModulesEx` 와 `K32GetModuleFileNameExW` 로만 얻는다. 둘 다 안전
//! 래퍼가 없다 — `sysinfo` 는 실행 파일 경로까지만 주고, Linux 처럼 읽을 파일(`/proc/<pid>/maps`)도
//! 없다. `remedy-platform` 의 `forbid` 를 푸는 대신 이 두 호출과 그 둘레(프로세스 열기 · 보호 수준 ·
//! 끝났는지 · 닫기)를 이 크레이트 하나에 가둔다 — `remedy-wintrust` 와 같은 판단이다(설계-04 §1).
//! 다른 크레이트는 `forbid(unsafe_code)` 를 그대로 두고, `xtask arch` 가 예외 목록 밖의 크레이트를
//! 막는다.
//!
//! kernel32 의 `K32` 판을 쓴다 — `psapi.dll` 의 같은 함수는 배포본의 임포트에 DLL 하나를 더한다.
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
    //! 호출부. **이 모듈만 `unsafe` 를 쓴다** — 핸들은 [`Process`] 가 닫고, 버퍼는 Rust 가 소유한
    //! `Vec` 이며, 넘기는 크기는 늘 그 버퍼의 크기다.

    use super::Modules;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, ERROR_PARTIAL_COPY, HANDLE, HMODULE,
        STILL_ACTIVE,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        K32EnumProcessModulesEx, K32GetModuleFileNameExW, LIST_MODULES_ALL,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessInformation, OpenProcess, ProcessProtectionLevelInfo,
        PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, PROTECTION_LEVEL_NONE,
    };

    /// 처음 마련하는 모듈 칸. 랩 VM 의 프로세스 하나가 싣는 모듈은 많아야 수백 개였다.
    const FIRST_CAPACITY: usize = 1024;
    /// 모듈 칸의 상한. 넘으면 목록을 다 읽지 못한 것이라 [`Modules::Refused`] 로 말한다 — 앞쪽만
    /// 담으면 뒤쪽 모듈을 겨눈 룰이 조용히 미탐이 된다.
    const MAX_MODULES: usize = 65_536;
    /// 경로 한 줄의 칸(UTF-16). 긴 경로(`\\?\`)의 상한이 32,767 글자다.
    const PATH_CHARS: usize = 32_768;

    /// 연 프로세스 핸들. 떨어질 때 닫는다.
    struct Process(HANDLE);

    impl Drop for Process {
        fn drop(&mut self) {
            // SAFETY: `open` 이 null 이 아닌 핸들만 담고, 이 값은 여기서 한 번만 닫힌다.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    /// 프로세스를 연다. 실패하면 Win32 오류 번호.
    fn open(pid: u32, access: u32) -> Result<Process, u32> {
        // SAFETY: 포인터를 받지 않는 호출이다. 돌려준 핸들은 `Process` 가 소유한다.
        let h = unsafe { OpenProcess(access, 0, pid) };
        if h.is_null() {
            // SAFETY: 같은 스레드에서 바로 앞 호출의 오류를 읽는다.
            Err(unsafe { GetLastError() })
        } else {
            Ok(Process(h))
        }
    }

    pub(super) fn modules_of(pid: u32) -> Modules {
        let p = match open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) {
            Ok(p) => p,
            // 그런 pid 가 없다 — `Idle`(0) 과, 열거 뒤에 끝난 프로세스가 여기로 온다.
            Err(ERROR_INVALID_PARAMETER) => return Modules::Gone,
            Err(_) => return protected_or_refused(pid),
        };
        match list(&p) {
            Ok(paths) => Modules::Read(paths),
            Err(_) if exited(&p) => Modules::Gone,
            Err(_) => protected_or_refused(pid),
        }
    }

    /// 거부된 프로세스가 보호 프로세스인가 — 보호 수준은 가장 좁은 권한으로 묻는다(보호
    /// 프로세스도 그 권한은 내준다).
    fn protected_or_refused(pid: u32) -> Modules {
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
    fn exited(p: &Process) -> bool {
        let mut code = 0u32;
        // SAFETY: `code` 는 이 함수의 지역 값이다.
        let ok = unsafe { GetExitCodeProcess(p.0, &mut code) };
        ok != 0 && code != STILL_ACTIVE as u32
    }

    /// 모듈 경로 전부. 실패하면 Win32 오류 번호.
    ///
    /// 막 뜬 프로세스는 로더가 아직 목록을 세우지 않아 `ERROR_PARTIAL_COPY` 를 낸다 — 한 번만 다시
    /// 묻는다.
    fn list(p: &Process) -> Result<Vec<String>, u32> {
        let mods = match handles(p) {
            Err(ERROR_PARTIAL_COPY) => handles(p)?,
            other => other?,
        };
        let mut buf = vec![0u16; PATH_CHARS];
        let mut out = Vec::with_capacity(mods.len());
        for m in mods {
            // SAFETY: `buf` 는 `PATH_CHARS` 칸이고 그 수를 그대로 넘긴다. 쓰인 글자 수만 읽는다.
            let n = unsafe { K32GetModuleFileNameExW(p.0, m, buf.as_mut_ptr(), buf.len() as u32) };
            let n = n as usize;
            // 0 은 그 사이에 내려간 모듈이다 — 지금 실려 있지 않으니 목록에 넣지 않는다. 칸을 다
            // 채웠으면 잘린 경로라 넣지 않는다(잘린 경로는 다른 파일을 가리킨다).
            if n == 0 || n >= buf.len() {
                continue;
            }
            out.push(String::from_utf16_lossy(&buf[..n]));
        }
        Ok(out)
    }

    /// 실린 모듈의 핸들. 칸이 모자라면 OS 가 알려 준 수만큼 늘려 다시 묻는다.
    fn handles(p: &Process) -> Result<Vec<HMODULE>, u32> {
        let unit = std::mem::size_of::<HMODULE>();
        let mut capacity = FIRST_CAPACITY;
        loop {
            let mut mods: Vec<HMODULE> = vec![std::ptr::null_mut(); capacity];
            let mut needed = 0u32;
            let bytes = (capacity * unit) as u32;
            // SAFETY: `mods` 는 `capacity` 칸이고 `bytes` 는 그 바이트 수다. `needed` 는 지역 값이다.
            let ok = unsafe {
                K32EnumProcessModulesEx(
                    p.0,
                    mods.as_mut_ptr(),
                    bytes,
                    &mut needed,
                    LIST_MODULES_ALL,
                )
            };
            if ok == 0 {
                // SAFETY: 같은 스레드에서 바로 앞 호출의 오류를 읽는다.
                return Err(unsafe { GetLastError() });
            }
            let count = needed as usize / unit;
            if count <= capacity {
                mods.truncate(count);
                return Ok(mods);
            }
            if capacity >= MAX_MODULES {
                // 상한을 넘는 목록 — 다 읽지 못했다.
                return Err(ERROR_PARTIAL_COPY);
            }
            capacity = count.min(MAX_MODULES);
        }
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
