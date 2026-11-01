//! 복원 정보 폴더를 **관리자만 읽고 쓰게** 잠근다 (목표 `remedy_cli` ⓪).
//!
//! # 무엇이 열려 있었나 (2026-10-29 실측)
//!
//! 이 폴더 하나에 **셋이 함께** 있다 — 계획(`plan/`), 저널(`journal/`), 그리고
//! 격리 컨테이너를 여는 **봉인 키**(`machine.key`). 그런데 그 권한을 세우는
//! 코드가 없어 OS 기본값으로 남아 있었다.
//!
//! | | 일반 사용자가 **키를 읽나** | 일반 사용자가 **파일을 심나** |
//! |---|---|---|
//! | Windows `C:\ProgramData\remedy` | **읽는다** (`Users:(RX)`) | **심는다** (`Users:(CI)(WD,AD)`) |
//! | Linux `/var/lib/remedy` | **읽는다** (`644`) | 못 한다 (`755 root:root`) |
//!
//! 키를 읽으면 그 키로 봉인한 **가짜 컨테이너**를 만들 수 있고, 파일을 심으면
//! 저널·계획과 짝을 맞춘 **가짜 회차**를 놓을 수 있다. `resume` 은 저장된 계획을
//! **재스캔 없이** 수행하므로, 관리자가 그것을 고르면 관리자 권한으로 돈다
//! (가드 G1~G9 · 보호 경로 · 상한 안에서).
//!
//! # 정책은 하나, 호출은 둘
//!
//! 정책: **관리자 계정만 읽고 쓴다.** 두 플랫폼에서 같은 말이다.
//!
//! | | 어떻게 |
//! |---|---|
//! | Linux | `chmod 0700` 폴더 · `0600` 키. **폴더가 0700 이면 자식은 모드와 무관하게 남이 못 본다** — 통과 권한이 없다 |
//! | Windows | `icacls /inheritance:r /grant:r` 로 상속을 끊고 **SYSTEM · Administrators** 만 남긴다 |
//!
//! # 왜 `icacls.exe` 인가
//!
//! 이 크레이트는 Windows 일을 **OS 도구를 불러** 한다 — `schtasks.exe` ·
//! `sc.exe` · `powershell.exe`. 같은 자리에 `icacls.exe` 를 둔다. Win32 DACL
//! API 를 직접 부르면 `unsafe` FFI 와 새 의존이 들고, 이 저장소는 크레이트
//! 하나만 빼고 `forbid(unsafe_code)` 다.
//!
//! **SID 로 준다.** `BUILTIN\Administrators` 는 언어판마다 이름이 다르다
//! (한국어 Windows 는 `BUILTIN\Administrators` 를 그대로 쓰지만 보장이 아니다).
//! 잘 알려진 SID 는 어디서나 같다 — `*S-1-5-18`(SYSTEM) ·
//! `*S-1-5-32-544`(Administrators).
//!
//! # 🔴 잠그면 **자기도 못 들어갈 수 있다** — 부르는 자리를 좁힌 까닭
//!
//! 2026-10-29 에 실측으로 밟았다. 처음 판은 `--state-dir` 로 받은 폴더까지
//! 잠갔고 **시험 열이 종료 5 로 떨어졌다.** 까닭이 곧 제품의 결함이다:
//! `Administrators` 만 남기면 **승격되지 않은 프로세스는 자기가 쓰던 폴더를
//! 잃는다.** 그 뒤 `remedy.lock` 조차 열지 못해 *"액세스가 거부되었습니다"* 가
//! 났다.
//!
//! 더 나쁜 것은 **되돌리기 전까지 남는다**는 점이다. 잠긴 임시 폴더 스물이
//! 남아 다음 회차 시험까지 깼다 — 소유자라서 `icacls /reset` 으로 풀 수
//! 있었지만, 고객 기계라면 그 자리는 사람이 손으로 풀어야 한다.
//!
//! 그래서 부르는 쪽([`remedy-cli`] 의 `state_dir`)이 **둘을 모두 만족할 때만**
//! 부른다 — ① 기본 폴더일 때(운영자가 `--state-dir` 로 이름을 준 것은 그의
//! 선택이다) ② **승격되었을 때**(아니면 자기가 못 읽게 될 수 있다).
//!
//! # 실패해도 명령을 세우지 않는다
//!
//! 잠금은 **더하는 안전장치**다. 못 걸었다고 치료나 복원을 거절하면, 권한이
//! 모자란 자리에서 **치료 자체가 막힌다** — 그것이 사용자에게 더 나쁘다. 그래서
//! 결과를 돌려주고 **부르는 쪽이 한 줄 알린다.** 조용히 넘기지는 않는다.

use std::path::Path;

/// 폴더를 만들고(없으면) 관리자만 읽고 쓰게 잠근다.
///
/// 이미 있는 폴더도 잠근다 — **기존 설치가 열린 채로 남으면 안 된다.**
///
/// 멱등이다. 여러 번 불러도 결과가 같다.
pub fn secure(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    lock(dir)
}

#[cfg(unix)]
fn lock(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    // **폴더가 0700 이면 키는 이미 남이 못 본다**(통과 권한이 없다). 그래도
    // 키 자체를 0600 으로 좁힌다 — 폴더 권한이 언젠가 느슨해져도 한 겹이 남는다.
    let key = dir.join("machine.key");
    if key.is_file() {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", key.display()))?;
    }
    Ok(())
}

#[cfg(windows)]
fn lock(dir: &Path) -> Result<(), String> {
    // `/inheritance:r` 가 상속받은 ACE 를 **지운다** — `Users:(RX)` 와
    // `Users:(WD,AD)` 가 그 상속이다. `/grant:r` 가 남길 둘을 다시 준다.
    // `(OI)(CI)` 로 자식에게 내려 보내 나중에 생기는 `journal/`·`machine.key`
    // 까지 덮는다.
    let out = std::process::Command::new("icacls.exe")
        .arg(dir)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)F",
            "/Q",
        ])
        .output()
        .map_err(|e| format!("icacls.exe 를 띄우지 못했다: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let msg = String::from_utf8_lossy(&out.stderr);
    let msg = if msg.trim().is_empty() {
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    } else {
        msg.trim().to_string()
    };
    Err(format!(
        "icacls.exe 가 {} 로 끝났다: {msg}",
        out.status.code().unwrap_or(-1)
    ))
}

#[cfg(test)]
mod tests {
    use super::secure;

    /// 없는 폴더도 만든다 — 부르는 쪽이 `create_dir_all` 을 따로 하지 않아도 된다.
    #[test]
    fn it_creates_the_folder() {
        let d = std::env::temp_dir().join(format!("remedy-sd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        secure(&d).expect("잠금");
        assert!(d.is_dir());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **멱등이다.** `state_dir` 를 쓰는 명령마다 불리므로 두 번째가 실패하면
    /// 두 번째 회차부터 매번 경고가 난다.
    #[test]
    fn calling_twice_is_the_same_as_once() {
        let d = std::env::temp_dir().join(format!("remedy-sd2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        secure(&d).expect("첫 번째");
        secure(&d).expect("두 번째");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 리눅스에서 **폴더가 0700 이고 키가 0600** 인지 잰다. 이것이 이 모듈의
    /// 전부다 — 통과 권한이 없으면 남은 자식을 볼 수 없다.
    #[cfg(unix)]
    #[test]
    fn unix_leaves_nothing_for_others() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("remedy-sd3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("machine.key"), b"x").unwrap();
        // 일부러 느슨하게 만든 뒤 잠근다 — 기존 설치를 흉내 낸다.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(
            d.join("machine.key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        secure(&d).expect("잠금");

        let dm = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        let km = std::fs::metadata(d.join("machine.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dm, 0o700, "폴더 모드 {dm:o}");
        assert_eq!(km, 0o600, "키 모드 {km:o}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
