//! 배포 바이너리 임포트 검사 (설계-09 P0 검증, 설계-01 D3·D9).
//!
//! # 왜 빌드 산출물을 따로 검사하는가
//!
//! `+crt-static` 은 **플래그 하나로 조용히 빠질 수 있다.** 실제로 그랬다 —
//! 플래그가 `.gitlab-ci.yml` 의 `RUSTFLAGS` 에만 있어서 로컬 빌드는 전부
//! `VCRUNTIME140.dll` 과 `api-ms-win-crt-*` 6종을 임포트했고, 그 바이너리로
//! VM 검증을 12/12 통과했다. 검증은 통과하는데 배포될 물건은 다른 것이었다.
//!
//! 설정 파일에 플래그를 박아 두는 것만으로는 부족하다. 설정이 무시되는 길이
//! 여럿 있다(`RUSTFLAGS` 환경변수가 `target.*.rustflags` 를 통째로 덮는다).
//! **산출물 자체를 보는 검사**만이 그 전부를 한 번에 막는다.
//!
//! # 무엇을 막는가
//!
//! - **CRT 동적 링크** — 전용백신은 파일 하나로 배포된다(설계-01 D3).
//!   VC++ 재배포 패키지가 없는 PC 에서 실행 자체가 안 되면 그 전제가 무너진다.
//! - **네트워크** — 치료 경로에 네트워크 코드가 링크되지 않아야 한다(설계-01 D9).
//!   크레이트 수준 금지는 P10 에서 다루지만, 임포트 테이블은 지금도 볼 수 있다.
//!
//! 허용 목록이 아니라 금지 목록인 이유: 새 Windows API 를 쓸 때마다 이 검사가
//! 깨지면 사람이 목록을 기계적으로 늘리게 되고, 그러면 검사가 형식이 된다.
//! 대신 **임포트 전체를 항상 출력한다** — 늘어난 것이 눈에 보여야 한다.

use std::collections::BTreeSet;
use std::path::Path;

/// C 런타임을 동적으로 끌어오는 임포트. 하나라도 있으면 단일 파일 배포가 아니다.
const CRT: [&str; 5] = ["api-ms-win-crt-", "vcruntime", "msvcp", "msvcr", "ucrtbase"];

/// 네트워크 스택. 치료 경로에 있어서는 안 된다 (설계-01 D9).
const NETWORK: [&str; 6] = [
    "ws2_32", "wininet", "winhttp", "iphlpapi", "dnsapi", "mswsock",
];

fn imports(path: &Path) -> Result<BTreeSet<String>, String> {
    use object::Object;

    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let file = object::File::parse(&*data).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = BTreeSet::new();
    for imp in file
        .imports()
        .map_err(|e| format!("{}: 임포트 테이블 {e}", path.display()))?
    {
        out.insert(String::from_utf8_lossy(imp.library()).into_owned());
    }
    Ok(out)
}

fn matches(lib: &str, needles: &[&str]) -> bool {
    let l = lib.to_ascii_lowercase();
    needles.iter().any(|n| l.contains(n))
}

/// 바이너리 하나를 검사한다. 사람이 읽을 결과를 찍고 위반 목록을 돌려준다.
fn check_one(path: &Path) -> Result<Vec<String>, String> {
    let libs = imports(path)?;
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    println!(
        "{} ({:.1} MB) — 임포트 {}건",
        path.display(),
        size as f64 / (1024.0 * 1024.0),
        libs.len()
    );

    let mut bad = Vec::new();
    for lib in &libs {
        let mark = if matches(lib, &CRT) {
            bad.push(format!("{lib} (CRT 동적 링크)"));
            " <-- CRT"
        } else if matches(lib, &NETWORK) {
            bad.push(format!("{lib} (네트워크)"));
            " <-- 네트워크"
        } else {
            ""
        };
        println!("    {lib}{mark}");
    }
    if libs.is_empty() {
        println!("    (없음 — 완전 정적)");
    }
    Ok(bad)
}

pub fn run(root: &Path, paths: &[String]) -> Result<(), String> {
    if paths.is_empty() {
        return Err(
            "검사할 바이너리를 지정할 것: cargo xtask static <경로>...\n\
             예: cargo xtask static target/x86_64-pc-windows-msvc/release/remedy.exe"
                .to_string(),
        );
    }

    let mut violations = Vec::new();
    for p in paths {
        // 상대 경로는 워크스페이스 루트 기준으로 읽는다. CI 와 하네스가 서로 다른
        // 작업 디렉터리에서 부르기 때문이다.
        let path = if Path::new(p).is_absolute() {
            Path::new(p).to_path_buf()
        } else {
            root.join(p)
        };
        if !path.exists() {
            return Err(format!("{} 가 없다. 먼저 빌드할 것.", path.display()));
        }
        for v in check_one(&path)? {
            violations.push(format!("  {} : {v}", path.display()));
        }
    }

    if violations.is_empty() {
        println!("static OK — CRT·네트워크 임포트 없음");
        return Ok(());
    }
    Err(format!(
        "임포트 위반 {}건:\n{}\n\n\
         CRT 가 걸렸다면 `+crt-static` 이 적용되지 않은 빌드다. 확인할 것:\n\
         - .cargo/config.toml 의 [target.'cfg(target_env = \"msvc\")'] rustflags\n\
         - RUSTFLAGS 환경변수가 설정되어 있으면 위 설정을 **통째로 덮는다**",
        violations.len(),
        violations.join("\n")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crt_names_are_recognized() {
        for lib in [
            "VCRUNTIME140.dll",
            "api-ms-win-crt-heap-l1-1-0.dll",
            "MSVCP140.dll",
            "ucrtbase.dll",
        ] {
            assert!(matches(lib, &CRT), "{lib} 는 CRT 로 잡혀야 한다");
        }
    }

    #[test]
    fn core_api_sets_are_not_crt() {
        // `api-ms-win-core-*` 는 CRT 가 아니라 OS API 세트다. 이것까지 막으면
        // 정적 빌드조차 통과하지 못한다.
        for lib in [
            "api-ms-win-core-synch-l1-2-0.dll",
            "KERNEL32.dll",
            "ntdll.dll",
            "bcryptprimitives.dll",
            "ADVAPI32.dll",
        ] {
            assert!(!matches(lib, &CRT), "{lib} 는 CRT 가 아니다");
            assert!(!matches(lib, &NETWORK), "{lib} 는 네트워크가 아니다");
        }
    }

    #[test]
    fn network_names_are_recognized() {
        for lib in ["WS2_32.dll", "WININET.dll", "winhttp.dll", "IPHLPAPI.DLL"] {
            assert!(matches(lib, &NETWORK), "{lib} 는 네트워크로 잡혀야 한다");
        }
    }

    #[test]
    fn empty_path_list_is_an_error() {
        // 검사할 것이 없으면 조용히 통과시키지 않는다. CI 에서 경로 오타가 나면
        // 검사가 통과한 것처럼 보이는 것이 가장 위험하다.
        assert!(run(Path::new("."), &[]).is_err());
    }
}
