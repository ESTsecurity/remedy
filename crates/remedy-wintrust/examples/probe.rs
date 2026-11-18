//! 파일 하나하나의 서명 판정을 눈으로 보는 도구.
//!
//! 시험이 자동으로 잴 수 없는 것 — 자기서명·변조·만료 — 을 사람이 만들어 놓고
//! 확인할 때 쓴다. 그 검체들은 저장소에 둘 수 없다(만들어야 하고, 만료된다).
//!
//! ```text
//! cargo run -p remedy-wintrust --example probe -- C:\Windows\System32\notepad.exe
//! ```

// 사람이 손으로 돌리는 진단 도구다 — 제품의 `std::env::args` 금지(clippy.toml)는 여기에 걸지 않는다.
#![allow(clippy::disallowed_methods)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("사용법: probe <파일>...");
        std::process::exit(2);
    }
    for a in &args {
        let p = std::path::Path::new(a);
        match remedy_wintrust::verify(p) {
            Ok(v) => println!(
                "{:<48} trusted={:<5} kind={:?} distrust={:?}\n{:>50}subject={}\n{:>50}thumb={}",
                a,
                v.trusted,
                v.kind,
                v.distrust,
                "",
                v.subject.as_deref().unwrap_or("(없음)"),
                "",
                v.thumbprint.as_deref().unwrap_or("(없음)")
            ),
            Err(e) => println!("{a:<48} 확인하지 못했다 — {e}"),
        }
    }
}
