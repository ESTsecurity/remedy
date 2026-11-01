//! 표준 라이브러리로 되는 읽기. **플랫폼 백엔드 둘이 함께 쓴다.**
//!
//! # 왜 공통으로 두는가
//!
//! 디렉터리 순회·본문 읽기·시각 변환·`%NAME%` 전개는 Windows 와 Linux 가 똑같다.
//! 다른 것은 **경로 하나**뿐이다 — Windows 는 WOW64 때문에 접근용 경로와 기록용
//! 경로가 갈리고, Linux 는 둘이 같다.
//!
//! 복사해 두면 갈라진다. 그리고 그 갈라짐은 **보이지 않는다** — Windows 에서
//! 개발하면 Linux 쪽 순회는 아무도 눈으로 보지 않고, 순회 순서나 상한 처리가
//! 어긋나도 스냅샷이 조금 다를 뿐 실패하지 않는다. 그런 차이는 오탐 게이트를
//! 통과한 뒤에 드러난다 (설계-09 P12).
//!
//! # 여기에 파괴 동작을 두지 않는다
//!
//! `read.rs` 와 같은 규칙이다. 이 파일은 읽기만 하고, 쓰기는 `write.rs` 의
//! 경계를 지난다.

use crate::read::{FsEntry, RawProcess, WalkResult};
use crate::PlatformError;
use remedy_sdk::normalize;

/// 경로를 두 가지로 본다. **접근할 때 여는 경로**와 **스냅샷에 적는 경로**다.
///
/// Windows 32비트 프로세스는 `System32` 를 열면 OS 가 `SysWOW64` 로 바꿔치므로
/// `Sysnative` 로 열어야 하는데, 룰이 적는 경로는 언제나 `System32` 다. 그
/// 갈라짐을 순회 코드가 알 필요는 없고 **이 두 함수만 알면 된다.**
pub(crate) trait PathView {
    /// 실제로 열 때 쓸 경로.
    fn for_access(&self, path: &str) -> String;
    /// 스냅샷에 적을 경로.
    fn for_record(&self, accessed: &str) -> String;
}

/// `root` 아래를 재귀로 훑는다.
///
/// # 결정적이어야 한다
///
/// 같은 시스템을 두 번 수집한 스냅샷이 달라지면 diff 가 아무것도 말해 주지
/// 않는다. 그래서 한 디렉터리의 항목을 정렬해 방문하고, 끝에서 전체를 다시
/// 정렬한다.
///
/// # 못 본 것을 없는 것으로 만들지 않는다
///
/// 열지 못한 디렉터리는 **세어서** [`WalkResult::denied`] 로 알린다. 조용히
/// 건너뛰면 비관리자로 돌린 수집이 "예약 작업 없음" 으로 보고되고, 그 스냅샷
/// 위에서 "위협 없음" 이 결론난다.
pub(crate) fn walk(
    view: &impl PathView,
    root: &str,
    limit: usize,
) -> Result<WalkResult, PlatformError> {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut denied = 0usize;
    let mut denied_paths: Vec<String> = Vec::new();
    // 재귀 대신 명시적 스택. 깊은 트리에서 스택이 터지지 않고, 순서를 통제할 수 있다.
    let mut stack = vec![view.for_access(root)];

    while let Some(dir) = stack.pop() {
        if truncated {
            break;
        }
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            // 한 디렉터리 때문에 전체를 잃으면 안 되므로 계속 간다. 다만
            // **세어서 알린다** — 못 본 것을 없는 것으로 보고하면 안 된다.
            Err(_) => {
                denied += 1;
                // **어느 자리였는지 앞의 몇 개는 적는다.** 개수만으로는 회차가
                // 끝난 뒤 원인에 닿을 수 없다 — 그때는 이미 잠금이 풀려 있다
                // (2026-09-14 에 그렇게 놓쳤다).
                if denied_paths.len() < crate::read::DENIED_SAMPLE {
                    denied_paths.push(normalize::nfc(&view.for_record(&dir)));
                }
                continue;
            }
        };
        crate::progress::enter_dir(&dir);
        // 결정성을 위해 한 디렉터리의 항목을 정렬한 뒤 처리한다.
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());

        let mut subdirs = Vec::new();
        for e in entries {
            // `symlink_metadata` 가 아니라 `metadata` 다 — 크기와 시각은 **가리킨
            // 대상의 것**이어야 한다. 링크 여부는 `file_type` 이 따로 말한다.
            let md = match e.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            crate::progress::tick_entry();
            let is_reparse = e.file_type().map(|t| t.is_symlink()).unwrap_or(false);
            let accessed = e.path().to_string_lossy().to_string();
            let entry = FsEntry {
                path: normalize::nfc(&view.for_record(&accessed)),
                is_dir: md.is_dir(),
                is_reparse,
                size: if md.is_dir() { 0 } else { md.len() },
                mtime: rfc3339(md.modified()).unwrap_or_else(|| "1970-01-01T00:00:00Z".into()),
                ctime: rfc3339(md.created()),
                mode: unix_mode(&md),
            };
            if entry.is_dir {
                // 재파스 지점은 따라가지 않는다. 따라가면 같은 파일을 두 번 세거나
                // 순환한다 (설계-02 §4).
                if !is_reparse {
                    subdirs.push(accessed);
                }
            } else {
                if out.len() >= limit {
                    truncated = true;
                    break;
                }
                out.push(entry);
                continue;
            }
            out.push(entry);
        }
        // 스택은 뒤에서 꺼내므로 역순으로 넣어야 사전순으로 방문한다.
        subdirs.reverse();
        stack.extend(subdirs);
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(WalkResult {
        entries: out,
        truncated,
        denied,
        denied_paths,
    })
}

/// 파일 본문. `max` 를 넘으면 `None` — **자르지 않는다.**
///
/// 잘린 내용으로 해시하면 그 해시는 아무 의미가 없고, 잘린 본문에 YARA 를 걸면
/// "안 맞았다" 가 나온다. 둘 다 "재지 못했다" 여야 한다.
/// Unix 권한 비트. Windows 에서는 `None` — 있지도 않은 값을 0 으로 채우면
/// "아무 권한도 없다" 로 읽힌다.
#[cfg(unix)]
fn unix_mode(md: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(md.permissions().mode())
}

#[cfg(not(unix))]
fn unix_mode(_md: &std::fs::Metadata) -> Option<u32> {
    None
}

pub(crate) fn read_file(
    view: &impl PathView,
    path: &str,
    max: u64,
) -> Result<Option<Vec<u8>>, PlatformError> {
    let p = view.for_access(path);
    let md = std::fs::metadata(&p).map_err(|e| PlatformError::io(path, e))?;
    if md.len() > max {
        return Ok(None);
    }
    std::fs::read(&p)
        .map(Some)
        .map_err(|e| PlatformError::io(path, e))
}

/// 이 경로를 **봤는가 · 없는가 · 못 물었는가** (B-9 · 2026-10-27).
///
/// # 왜 `Path::exists()` 로는 안 되는가
///
/// 그것은 `metadata()` 의 **오류 전부를 `false` 로 접는다.** 그래서 선언한
/// 루트의 부모까지 막힌 트리, 도달 불가 UNC 공유, 준비되지 않은 장치가 모두
/// *"없다"* 가 된다. 열린 루트가 하나라도 함께 있으면 `all_roots_missing()` 이
/// 성립하지 않아 **경고 한 줄 없이 종료 0 "위협이 발견되지 않았습니다"** 가
/// 나갔다(실측 2026-10-27 · 적대 검증이 세 회차 연속 짚었다).
///
/// 레지스트리 쪽은 **모양만 갈라 물었다** — [`crate::read::seen`] 이 부모에게
/// 이름을 묻고 세 갈래를 돌려주는데, 백엔드(`windows.rs::subkeys`)가 열기
/// 실패를 `Ok(빈 목록)` 으로 바꿔 버려 *"모른다"* 가 **실기기에서 설 수
/// 없었다.** 그래서 부모가 ACL 로 막힌 키도 *"봤는데 없다"* 였고, 같은 종료 0
/// 이 거기서도 나갔다(실측 2026-10-27 · 적대 검증). **두 쪽 다 같은 결함을
/// 갖고 있었고, 같은 날 같은 규율로 고쳤다.**
///
/// # 부모에게 묻지 않아도 되는 이유
///
/// 레지스트리는 `key_exists` 가 참·거짓뿐이라 **있는지**는 부모를 열거해
/// 갈라야 한다. 그러나 *없는 부모*와 *막힌 부모*를 가르는 일은 거기서도
/// `open_subkey` 의 **오류 종류**가 한다 — 조상을 타고 올라가는 길도 섰지만
/// 호출이 길어질 뿐 답은 같았다. 파일은 한 걸음 더 간단해서 `metadata()` 의
/// 오류 종류 하나로 셋이 전부 갈린다.
///
/// | `metadata()` | 뜻 |
/// |---|---|
/// | `Ok` | `Present` |
/// | `NotFound` | `Absent` — 이름 해석이 실패했다(설치되지 않은 제품 등) |
/// | `PermissionDenied` | `Locked` — 있는지조차 물을 수 없다 |
/// | 그 밖 | `CannotTell` — 도달 불가 UNC · 준비 안 된 장치 · 심볼릭 고리 |
///
/// # 링크를 따라간다
///
/// `symlink_metadata` 가 아니라 `metadata` 다. 실제 디렉터리를 가리키는
/// 심볼릭 링크를 루트로 적는 것은 정상이고, 그것을 `Absent` 로 읽으면 멀쩡한
/// 선언이 무효가 된다. `Path::exists()` 도 따라갔으므로 **뜻이 바뀌지 않는다.**
pub(crate) fn look(view: &impl PathView, path: &str) -> crate::read::Seen {
    use crate::read::Seen;
    use std::io::ErrorKind;
    match std::fs::metadata(view.for_access(path)) {
        Ok(_) => Seen::Present,
        Err(e) => match e.kind() {
            ErrorKind::NotFound => Seen::Absent,
            ErrorKind::PermissionDenied => Seen::Locked,
            _ => Seen::CannotTell,
        },
    }
}

/// `%NAME%` 를 전개한다. 없는 변수는 **그대로 둔다.**
///
/// 조용히 빈 문자열이 되면 `%FOO%\bar` 가 `\bar` 가 되어 전혀 다른 경로를
/// 가리킨다 — 그 경로는 존재하지 않고, 수집은 0건이 되며, 아무도 이유를 모른다.
///
/// # Linux 에서도 `%NAME%` 다
///
/// `$NAME` 이 아니다. 매니페스트 문법은 플랫폼이 갈라져서는 안 된다 — 갈라지면
/// 교차 플랫폼 플러그인이 같은 뜻을 두 번 적어야 하고, 그중 하나만 고치는 실수가
/// 생긴다. 확장 결과만 플랫폼을 따른다.
pub(crate) fn expand_percent(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            None => {
                out.push_str(&rest[i..]);
                return out;
            }
            Some(j) => {
                let name = &after[..j];
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[j + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// 토큰으로 시작하면 그 뒤를 돌려준다. 대소문자를 가리지 않는다.
pub(crate) fn strip_token<'a>(root: &'a str, token: &str) -> Option<&'a str> {
    if root.len() < token.len() {
        return None;
    }
    root[..token.len()]
        .eq_ignore_ascii_case(token)
        .then(|| &root[token.len()..])
}

/// 프로세스 목록을 **필요한 것까지** 새로 고친다.
///
/// # 왜 `refresh_processes` 를 그대로 쓰지 않는가
///
/// `sysinfo::System::refresh_processes` 의 기본 갱신 종류는
/// `nothing().with_memory().with_cpu().with_disk_usage().with_exe(..)` 다 —
/// **`cmd` 도 `user` 도 들어 있지 않다.** 그래서 `Process::cmd()` 가 언제나
/// 비어 있고, 그 위에 세운 것이 전부 조용히 무너진다.
///
/// 실측으로 드러났다 (설계-09 P8 워치독 하네스). `process.kill` 이
/// `cmdline_contains` 술어로 아무것도 찾지 못하는데 `image_path` 로는 찾았고,
/// WMI 는 그 명령줄을 그대로 보여 주고 있었다.
///
/// **수집기도 같은 함수를 쓴다.** 즉 지금까지 뜬 모든 스냅샷의
/// `process.cmdline` · `cmdline_decoded` · `args` · `user` 가 비어 있었다.
/// 설계-02 가 `cmdline_decoded` 를 둔 이유("인코딩은 은폐 수단이지 실행 방식이
/// 아니다 — 룰이 원문만 볼 수 있으면 `powershell -enc <base64>` 한 줄로 모든
/// 문자열 룰이 무력해진다")가 통째로 성립하지 않고 있었다.
///
/// 그래서 갱신 종류를 **한 곳에서** 정한다. 두 자리에 적으면 갈라진다.
pub(crate) fn refresh_all_processes(sys: &mut sysinfo::System) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        // `environ` 은 넣지 않는다. 크고, 개인정보가 들어오며, 룰이 쓰지 않는다.
        ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::Always)
            .with_cmd(UpdateKind::Always)
            .with_user(UpdateKind::Always),
    );
}

/// 프로세스 열거.
///
/// `sysinfo` 를 쓰는 이유는 `forbid(unsafe_code)` 다. `CreateToolhelp32Snapshot`
/// 이나 `NtQuerySystemInformation` 을 직접 부르려면 unsafe 가 필요하고, 그것을
/// 이 크레이트에 들이면 SDDL·복원처럼 이미 안전 래퍼로 해결한 자리들의 근거가
/// 함께 무너진다.
///
/// 임포트 테이블은 늘지 않는다 — 실측으로 `ntdll`·`kernel32`·`advapi32` 만 쓰고
/// 셋 다 이미 있다. 네트워크 심볼은 들어오지 않는다(설계-09 P6 검증 항목).
/// `default-features = false` 로 네트워크·디스크 컴포넌트를 아예 뺐다.
pub(crate) fn processes(view: &impl PathView) -> Result<Vec<RawProcess>, PlatformError> {
    let mut sys = sysinfo::System::new();
    refresh_all_processes(&mut sys);

    let mut out: Vec<RawProcess> = sys
        .processes()
        .iter()
        .map(|(pid, p)| {
            let image_path = p
                .exe()
                .map(|e| normalize::nfc(&view.for_record(&e.to_string_lossy())))
                .unwrap_or_default();
            let cmd: Vec<String> = p
                .cmd()
                .iter()
                .map(|a| a.to_string_lossy().to_string())
                .collect();
            RawProcess {
                pid: pid.as_u32(),
                ppid: p.parent().map(|x| x.as_u32()).unwrap_or(0),
                image_path,
                cmdline: normalize::nfc(&cmd.join(" ")),
                args: normalize::nfc(&cmd.iter().skip(1).cloned().collect::<Vec<_>>().join(" ")),
                user: p
                    .user_id()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| String::from("unknown")),
                start_time: format_epoch(p.start_time()),
                // **여기서는 비운다.** 모듈 목록은 플랫폼마다 얻는 길이 달라
                // 공통 코드가 채울 것이 없다 — Linux 백엔드가 `/proc` 에서
                // 이어 채우고, Windows 는 열거가 unsafe 라 빈 채로 둔다
                // (`ProcessRead::processes` 의 표).
                modules: Vec::new(),
                modules_denied: false,
            }
        })
        .collect();
    // **pid 순으로 고정한다.** 열거 순서는 OS 가 정하고, 그대로 두면 같은
    // 기계를 두 번 수집한 스냅샷이 달라진다.
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

pub(crate) fn rfc3339(t: std::io::Result<std::time::SystemTime>) -> Option<String> {
    let t = t.ok()?;
    let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(format_epoch(secs))
}

/// UTC RFC3339. 시간대 라이브러리를 끌어오지 않는다 — 스냅샷은 항상 UTC 다.
pub(crate) fn format_epoch(secs: u64) -> String {
    // 1970-01-01 부터의 일수/초로 그레고리력을 편다.
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant 의 days-from-civil 역함수.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 경로를 그대로 쓰는 관점. Linux 백엔드가 이것이다.
    struct Identity;
    impl PathView for Identity {
        fn for_access(&self, p: &str) -> String {
            p.to_string()
        }
        fn for_record(&self, p: &str) -> String {
            p.to_string()
        }
    }

    fn lab(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("remedy-local-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("실험 디렉터리");
        d
    }

    #[test]
    fn walking_the_same_tree_twice_gives_the_same_order() {
        // **순서가 흔들리면 diff 가 아무것도 말해 주지 않는다.** 파일 시스템의
        // 열거 순서는 보장되지 않으므로 우리가 정렬해야 한다.
        let d = lab("order");
        for n in ["c.txt", "a.txt", "b.txt"] {
            std::fs::write(d.join(n), b"x").expect("쓰기");
        }
        std::fs::create_dir(d.join("sub")).expect("하위");
        std::fs::write(d.join("sub").join("z.txt"), b"x").expect("쓰기");

        let one = walk(&Identity, d.to_str().unwrap(), 100).expect("순회");
        let two = walk(&Identity, d.to_str().unwrap(), 100).expect("순회");
        assert_eq!(one.entries, two.entries);
        let names: Vec<&str> = one
            .entries
            .iter()
            .filter(|e| !e.is_dir)
            .map(|e| e.path.rsplit(['\\', '/']).next().unwrap())
            .collect();
        assert_eq!(names, vec!["a.txt", "b.txt", "c.txt", "z.txt"]);

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn hitting_the_limit_says_so() {
        // 잘린 것을 "전부 봤다" 로 보고하면 그 스냅샷 위의 판정이 전부 근거를
        // 잃는다.
        let d = lab("limit");
        for i in 0..5 {
            std::fs::write(d.join(format!("{i}.txt")), b"x").expect("쓰기");
        }
        let w = walk(&Identity, d.to_str().unwrap(), 2).expect("순회");
        assert!(w.truncated, "상한에 걸렸는데 말하지 않았다");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_missing_root_is_a_denied_directory_not_an_empty_result() {
        // 없는 경로를 조용히 빈 결과로 돌려주면 `scan_roots` 오타가 "위협 없음"
        // 이 된다 (관측 01 D2).
        let w = walk(&Identity, "/no/such/place/at/all", 100).expect("순회");
        assert!(w.entries.is_empty());
        assert_eq!(w.denied, 1, "열지 못한 사실이 세어지지 않았다");
    }

    #[test]
    fn a_file_over_the_cap_comes_back_as_none_not_truncated() {
        // 잘린 본문으로 해시하면 그 해시는 아무 의미가 없다.
        let d = lab("cap");
        let f = d.join("big.bin");
        std::fs::write(&f, vec![0u8; 100]).expect("쓰기");
        assert_eq!(
            read_file(&Identity, f.to_str().unwrap(), 50).expect("읽기"),
            None
        );
        assert_eq!(
            read_file(&Identity, f.to_str().unwrap(), 100)
                .expect("읽기")
                .map(|v| v.len()),
            Some(100)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_unknown_variable_stays_put() {
        // 빈 문자열이 되면 `%FOO%/bar` 가 `/bar` 가 되어 전혀 다른 곳을 가리킨다.
        let name = "REMEDY_NO_SUCH_VAR_9F3A";
        assert_eq!(
            expand_percent(&format!("%{name}%/bar")),
            format!("%{name}%/bar")
        );
    }

    #[test]
    fn an_unpaired_percent_is_left_alone() {
        assert_eq!(expand_percent("50% off"), "50% off");
    }

    #[test]
    fn a_designated_token_is_recognised_case_insensitively() {
        // 룰이 `%AllUserProfiles%` 로 적었다고 펼쳐지지 않으면, 그 플러그인은
        // 존재하지 않는 경로를 보며 0건을 보고한다.
        assert_eq!(
            strip_token("%ALLUSERPROFILES%\\x", "%ALLUSERPROFILES%"),
            Some("\\x")
        );
        assert_eq!(
            strip_token("%AllUserProfiles%\\x", "%ALLUSERPROFILES%"),
            Some("\\x")
        );
        assert_eq!(strip_token("%APPDATA%\\x", "%ALLUSERPROFILES%"), None);
        assert_eq!(strip_token("%ALL%", "%ALLUSERPROFILES%"), None);
    }

    #[test]
    fn epoch_zero_is_the_unix_epoch() {
        assert_eq!(format_epoch(0), "1970-01-01T00:00:00Z");
        // 윤년 경계. 2024-02-29 12:34:56 UTC
        assert_eq!(format_epoch(1_709_210_096), "2024-02-29T12:34:56Z");
        assert_eq!(format_epoch(1_771_500_600), "2026-02-19T11:30:00Z");
    }
}
