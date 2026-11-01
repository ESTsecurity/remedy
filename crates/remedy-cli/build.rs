//! 빌드 타깃을 바이너리에 새긴다.
//!
//! 32비트 빌드가 64비트 OS에서 도는 상황(WOW64)을 사람이 눈으로 구분할 수 있어야
//! 한다 — 설계-02 §4의 리다이렉션 문제는 어느 비트로 빌드되었는지 모르면 진단할 수
//! 없다.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=REMEDY_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
