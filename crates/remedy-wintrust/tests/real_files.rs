//! 실기기 파일로 재는 시험 (설계-03 §3 2층).
//!
//! **고정 검체를 저장소에 두지 않는다.** 서명은 만료·폐기·정책으로 바뀌고,
//! 굳어 둔 바이트는 "그때 그 기계에서 참이었다" 만 말한다. 이 시험이 묻는 것은
//! *"이 기계의 OS 가 정상이라고 보는 것을 우리도 정상이라고 보는가"* 다.

#![cfg(windows)]

use std::path::{Path, PathBuf};

use remedy_wintrust::{verify, SignatureKind};

fn system32(name: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    Path::new(&root).join("System32").join(name)
}

#[test]
fn 시스템_파일이_신뢰로_판정된다() {
    for name in ["kernel32.dll", "ntdll.dll", "notepad.exe"] {
        let p = system32(name);
        if !p.exists() {
            continue;
        }
        let v = verify(&p).unwrap_or_else(|e| panic!("{name}: 확인하지 못했다 — {e}"));
        assert!(v.trusted, "{name}: 신뢰로 판정되지 않았다 — {v:?}");

        // 전체 DN 이어야 한다. CN 만 오면 `CertGetNameStringW` 의 타입을 잘못
        // 넘긴 것이고, 그러면 O= 로 거르려던 제외 규칙이 조용히 어긋난다.
        let subject = v.subject.as_deref().unwrap_or("");
        assert!(
            subject.contains("O=Microsoft Corporation"),
            "{name}: 전체 DN 이 아니거나 뜻밖이다 — {subject:?}"
        );
        assert!(
            v.thumbprint.as_deref().is_some_and(|t| t.len() == 40),
            "{name}: SHA-1 지문이 40자리 hex 가 아니다 — {:?}",
            v.thumbprint
        );
    }
}

#[test]
fn 카탈로그만으로_신뢰를_얻는_파일이_있다() {
    // **이 시험이 이 크레이트의 존재 이유다.** `notepad.exe` 는 파일 안에
    // 인증서 테이블이 없다(2026-08-25 실측: Size=0). PE 테이블만 읽는 구현은
    // 이것을 "서명 없음" 으로 읽고, 그러면 2층이 System32 를 보호하지 못한다.
    let p = system32("notepad.exe");
    if !p.exists() {
        eprintln!("notepad.exe 가 없어 건너뛴다");
        return;
    }
    let v = verify(&p).expect("확인하지 못했다");
    assert!(v.trusted, "카탈로그 보증 파일을 신뢰하지 않았다 — {v:?}");
    assert_eq!(
        v.kind,
        SignatureKind::CatalogOnly,
        "파일 안에 인증서 테이블이 없어야 한다 — {v:?}"
    );
}

#[test]
fn 서명이_없는_파일은_확인했고_신뢰하지_않는다로_끝난다() {
    // 임시 파일 하나를 만들어 본다. PE 도 아니므로 `TRUST_E_SUBJECT_FORM_UNKNOWN`
    // 또는 `TRUST_E_NOSIGNATURE` 가 온다 — 둘 다 "확인했다" 다.
    let p = std::env::temp_dir().join("remedy-wintrust-unsigned.txt");
    std::fs::write(&p, b"not a signed binary").expect("임시 파일");

    let v = verify(&p).expect("확인하지 못했다");
    assert!(!v.trusted, "서명 없는 파일을 신뢰로 판정했다 — {v:?}");
    assert_eq!(v.kind, SignatureKind::Unsigned);
    assert!(v.subject.is_none(), "없는 서명에 주체가 붙었다 — {v:?}");

    let _ = std::fs::remove_file(&p);
}

#[test]
fn 없는_파일은_판정이_아니라_오류다() {
    // 설계-03 §3: "서명을 확인하지 못한 것을 '서명 없음' 으로 읽지 않는다".
    let p = std::env::temp_dir().join("remedy-wintrust-그런파일없다.exe");
    let _ = std::fs::remove_file(&p);
    assert!(
        verify(&p).is_err(),
        "읽을 수 없는 파일에 판정을 냈다 — 그것이 '서명 없음' 으로 흘러가면 2층이 무너진다"
    );
}

#[test]
fn 파일_내장_서명도_읽는다() {
    // 있으면 재고, 없으면 건너뛴다. 개발 기계에 Node 가 있으면 이 경로가 산다.
    let candidates = [
        PathBuf::from("C:\\Program Files\\nodejs\\node.exe"),
        PathBuf::from("C:\\Program Files\\Git\\cmd\\git.exe"),
    ];
    let Some(p) = candidates.iter().find(|p| p.exists()) else {
        eprintln!("내장 서명 검체를 찾지 못해 건너뛴다");
        return;
    };
    let v = verify(p).unwrap_or_else(|e| panic!("{}: 확인하지 못했다 — {e}", p.display()));
    assert!(v.trusted, "{}: 신뢰로 판정되지 않았다 — {v:?}", p.display());
    assert_eq!(
        v.kind,
        SignatureKind::Embedded,
        "{}: 파일 내장 서명일 것으로 봤다 — {v:?}",
        p.display()
    );
    assert!(v.subject.is_some(), "주체가 비었다 — {v:?}");
}
