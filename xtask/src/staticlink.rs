//! 배포 바이너리 임포트 검사 (설계-09 P0 검증, 설계-01 D3·D9).
//!
//! # 왜 빌드 산출물을 따로 검사하는가
//!
//! `+crt-static` 은 **플래그 하나로 조용히 빠질 수 있다.** 실제로 그랬다 —
//! 플래그가 옛 CI 설정의 `RUSTFLAGS` 에만 있어서 로컬 빌드는 전부
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

/// 동반 프로그램(`remedy-net`)에서 막는 네트워크 임포트 — **OS 의 HTTP 스택**이다.
///
/// 그 프로그램은 통신이 일이라 소켓(`ws2_32`)을 쓴다. 그러나 HTTP 는 스스로 짠다 — 리다이렉트 ·
/// 프록시 · 재시도 · 연결 재사용이 처음부터 없게(워크스페이스 `Cargo.toml` 의 통신 절). `wininet` ·
/// `winhttp` 가 임포트에 나타나면 의존 하나가 OS 의 HTTP 스택을 끌어온 것이고, 그 스택은 시스템
/// 프록시와 자동 설정을 따른다 — 사용자가 적지 않은 곳으로 요청이 돌아갈 길이 생긴다.
const COMPANION_NETWORK: [&str; 2] = ["wininet", "winhttp"];

/// 무엇을 검사하는가 — 본체인가 동반 프로그램인가.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    /// 본체 `remedy` — 네트워크 임포트가 하나도 없어야 한다(설계-01 D9).
    Core,
    /// 동반 프로그램 `remedy-net` — 소켓은 그 프로그램의 일이고, OS 의 HTTP 스택만 막는다.
    Companion,
}

impl Target {
    fn network(self) -> &'static [&'static str] {
        match self {
            Target::Core => &NETWORK,
            Target::Companion => &COMPANION_NETWORK,
        }
    }
}

/// 바이너리 하나를 검사한다. 사람이 읽을 결과를 찍고 위반 목록을 돌려준다.
fn check_one(path: &Path, target: Target) -> Result<Vec<String>, String> {
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
        } else if matches(lib, target.network()) {
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

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    // `--companion` 은 뒤따르는 경로 전부를 동반 프로그램으로 본다 — 한 번에 한 종류만 검사한다.
    // 섞어 주면 본체에 느슨한 규칙이 걸릴 수 있어, 깃발 하나가 호출 전체를 정한다.
    let target = if args.iter().any(|a| a == "--companion") {
        Target::Companion
    } else {
        Target::Core
    };
    let paths: Vec<&String> = args.iter().filter(|a| *a != "--companion").collect();
    if paths.is_empty() {
        return Err(
            "검사할 바이너리를 지정할 것: cargo xtask static [--companion] <경로>...\n\
             예: cargo xtask static target/x86_64-pc-windows-msvc/release/remedy.exe\n\
             동반 프로그램: cargo xtask static --companion target/x86_64-pc-windows-msvc/release/remedy-net.exe"
                .to_string(),
        );
    }
    // **이름으로 한 번 더 막는다.** 본체를 `--companion` 으로 검사하면 소켓 임포트가 통과한다 —
    // 배포 잡의 줄 하나를 잘못 붙이는 것으로 본체의 검사가 조용히 느슨해지지 않게.
    for p in &paths {
        let stem = Path::new(p.as_str())
            .file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let is_companion = stem == crate::sign::COMPANION;
        if is_companion != (target == Target::Companion) {
            return Err(format!(
                "{p}: 이름과 검사 종류가 맞지 않는다 — remedy-net 은 --companion 으로, 그 밖의 \
                 바이너리는 깃발 없이 검사한다"
            ));
        }
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
        for v in check_one(&path, target)? {
            violations.push(format!("  {} : {v}", path.display()));
        }
    }

    if violations.is_empty() {
        match target {
            Target::Core => println!("static OK — CRT·네트워크 임포트 없음"),
            Target::Companion => println!(
                "static OK — CRT 임포트 없음 · OS 의 HTTP 스택(wininet · winhttp) 없음 \
                 (동반 프로그램 — 소켓은 그 프로그램의 일이다)"
            ),
        }
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

    /// 동반 프로그램은 소켓을 쓴다 — 막는 것은 OS 의 HTTP 스택이고, CRT 는 본체와 똑같이 막는다.
    #[test]
    fn the_companion_may_use_sockets_but_not_the_os_http_stack() {
        for lib in ["WS2_32.dll", "crypt32.dll", "bcrypt.dll", "IPHLPAPI.DLL"] {
            assert!(
                !matches(lib, Target::Companion.network()),
                "{lib} 는 동반 프로그램에서 막지 않는다"
            );
        }
        for lib in ["WININET.dll", "winhttp.dll"] {
            assert!(matches(lib, Target::Companion.network()), "{lib}");
        }
        // 본체의 목록은 그대로다 — 소켓 하나도 위반이다.
        assert!(matches("WS2_32.dll", Target::Core.network()));
    }

    /// 이름과 검사 종류가 엇갈리면 멈춘다 — 본체를 느슨한 규칙으로 검사하는 줄이 조용히 통과하지 않게.
    #[test]
    fn the_flag_and_the_file_name_must_agree() {
        let root = Path::new(".");
        let e = run(root, &["--companion".into(), "remedy.exe".into()]).unwrap_err();
        assert!(e.contains("이름과 검사 종류가 맞지 않는다"), "{e}");
        let e = run(root, &["remedy-net.exe".into()]).unwrap_err();
        assert!(e.contains("이름과 검사 종류가 맞지 않는다"), "{e}");
        // 깃발만 주고 경로가 없으면 검사할 것이 없다 — 통과가 아니다.
        assert!(run(root, &["--companion".into()]).is_err());
    }

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
