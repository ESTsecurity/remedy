//! 합성 PE 로 파서를 **어느 플랫폼에서도** 잰다 (C-1b · 2026-10-27).
//!
//! # 왜 필요한가
//!
//! `tests/peversion_real.rs` 는 `#![cfg(windows)]` 다 — 실물 PE 와 비교할
//! 오라클이 Windows 에만 있다. 그래서 **리눅스 CI 에서는 파서 전체가 측정되지
//! 않았다**: `version_resource`·`blob_of`·`node`·`siblings` 를 통째로
//! `None` 으로 바꿔도 전부 초록이었다(2026-10-27 적대 검증).
//!
//! 여기서는 PE 를 **손으로 짓는다**. 짓는 쪽과 읽는 쪽이 같은 상수를 쓰지 않도록
//! 자리를 전부 숫자로 적는다 — 그러지 않으면 내가 틀리게 지은 것을 틀리게 읽고
//! 통과한다. 그 자리가 맞는지는 `peversion_real.rs` 가 실물로 댄다.

// PE 를 짓는 코드는 `peversion_wiring.rs` 와 나눠 쓴다. 시험 사이에 코드를
// 공유하려면 별도 크레이트가 필요하므로 `include!` 로 붙인다.
include!("common/peversion_pe.rs");

#[test]
fn 합성_pe_에서_선언한_버전을_읽는다() {
    // **이 시험이 파서 전체를 어느 플랫폼에서도 잰다** — `object` 로 리소스를
    // 걷는 자리부터 노드 걸음까지 전부 지난다.
    for v in ["16.10", "8.2.29", "1.2.3.4", "10.0.26100.9711"] {
        let pe = pe_with(v);
        assert_eq!(
            remedy_collect::peversion::of("x.dll", &pe).as_deref(),
            Some(v),
            "{v} 를 읽지 못했다"
        );
    }
}

#[test]
fn 공백_뒤_주석을_버린다() {
    // 실물 23.9% 가 이 모양이다(실측). 버리지 않으면 비교가 거부한다.
    let pe = pe_with("10.0.26100.9549 (WinBuild.160101.0800)");
    assert_eq!(
        remedy_collect::peversion::of("x.dll", &pe).as_deref(),
        Some("10.0.26100.9549")
    );
}

#[test]
fn 숫자에_붙은_꼬리는_남긴다() {
    // 줄이면 사전 배포를 정식 판이라고 말하는 것이다. 담되 `version_lt` 가
    // 거부해 종료 6 으로 간다 (C-1).
    for v in ["8.2.29-dev", "8.4.0RC1", "8.2.29-1ubuntu1"] {
        let pe = pe_with(v);
        assert_eq!(
            remedy_collect::peversion::of("x.dll", &pe).as_deref(),
            Some(v),
            "{v} 가 줄었다"
        );
    }
}

#[test]
fn 선언하지_않은_버전은_담지_않는다() {
    // `"0.0.0.0"` 을 담으면 `version_lt "8.2.29"` 가 그 파일 전부에 맞는다 —
    // 버전을 모르는 파일이 전부 취약으로 나간다.
    for v in ["0.0.0.0", "0", "0.0", "00.00.00.00"] {
        let pe = pe_with(v);
        assert_eq!(
            remedy_collect::peversion::of("x.dll", &pe),
            None,
            "{v} 를 담았다"
        );
    }
    // 역검증 — 0 이 아닌 자리가 하나라도 있으면 담는다.
    let pe = pe_with("0.0.1.0");
    assert_eq!(
        remedy_collect::peversion::of("x.dll", &pe).as_deref(),
        Some("0.0.1.0")
    );
}

#[test]
fn 이름_층에서_vs_version_info_를_고른다() {
    // **적대 검증이 찾은 high** (2026-10-27). 리소스 디렉터리는 이름 붙은
    // 항목을 ID 보다 앞에 쌓는다 — 첫 항목을 쓰면 꾸민 PE 가 값을 바꿔치기한다.
    // 여기서는 ID 로 같은 모양을 짓는다: **ID 2 를 먼저** 쌓고 ID 1 을 뒤에 둔다.
    let decoy = version_blob("99.9.9.9");
    let real = version_blob("8.2.1.0");
    let pe = pe64(&resource_section(&[(2, &decoy), (1, &real)]));
    assert_eq!(
        remedy_collect::peversion::of("x.dll", &pe).as_deref(),
        Some("8.2.1.0"),
        "첫 항목을 집었다 — 미끼 버전이 담긴다"
    );
}

#[test]
fn 깨진_pe_는_값을_지어내지_않는다() {
    let good = pe_with("16.10");
    // 자리를 하나씩 부순다. 어느 것도 값을 내서는 안 된다.
    for cut in [0x40usize, 0x84, 0x100, RSRC_FILE as usize + 8] {
        if cut >= good.len() {
            continue;
        }
        let mut bad = good.clone();
        bad.truncate(cut);
        assert_eq!(
            remedy_collect::peversion::of("x.dll", &bad),
            None,
            "{cut} 에서 자른 PE 가 값을 냈다"
        );
    }
    // 리소스 디렉터리의 자리를 섹션 밖으로 보낸다.
    let mut bad = good.clone();
    bad[RSRC_FILE as usize + 0x14..RSRC_FILE as usize + 0x18]
        .copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
    assert_eq!(remedy_collect::peversion::of("x.dll", &bad), None);
}

#[test]
fn 대상_형식이_아니면_읽지_않는다() {
    // 서명과 같은 목록이다. `.ini` 는 PE 가 들어 있어도 읽지 않는다.
    let pe = pe_with("16.10");
    assert_eq!(remedy_collect::peversion::of("x.ini", &pe), None);
    assert_eq!(remedy_collect::peversion::of("/usr/bin/php", &pe), None);
}
