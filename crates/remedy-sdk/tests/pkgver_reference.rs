//! 패키지 판 비교 한 벌(`remedy_sdk::pkgver`)이 **그 도구 자신의 답**과 같은가.
//!
//! `tests/data/pkgver/*.tsv` 는 2026-11-17 에 만든 기준 자료다 — 좁은 알파벳에서 뽑은 판 짝 600개씩(같은 씨앗 ·
//! 짝의 반은 한 글자만 바꿔 모서리를 자주 밟게)을 진짜 도구에 물었다: `dpkg --compare-versions`(debian:12) ·
//! python3-rpm 의 `labelCompare`(oraclelinux:9 · epoch 은 첫 `:` 앞, 개정은 마지막 `-` 뒤) · `apk version -t`
//! (alpine:3.22 · apk-tools 2.14.13). 셋째 칸은 `<` `=` `>`, 도구가 판으로 받지 않은 짝은 `!` 다.
//!
//! 제품이 견주는 것은 꼴 검사(`catalog::is_pkg_version` · `is_rpm_version` · `is_apk_version`)를 지난 판뿐이라
//! 그 짝만 본다. 그 짝에서 하나라도 답이 갈리면 실패한다 — 한 벌로 합치기 전 본체의 dpkg 비교는 비숫자 구간의
//! 숫자 순서가 dpkg 와 달랐다(`1.1` 대 `1.a`).

use remedy_sdk::catalog::{is_apk_version, is_pkg_version, is_rpm_version};
use remedy_sdk::pkgver::{apk_cmp, dpkg_cmp, rpm_cmp};
use std::cmp::Ordering;

fn check(
    name: &str,
    data: &str,
    valid: fn(&str) -> bool,
    cmp: fn(&str, &str) -> Ordering,
) -> usize {
    let mut seen = 0;
    let mut bad = Vec::new();
    for line in data.lines().filter(|l| !l.is_empty()) {
        let mut cols = line.split('\t');
        let (a, b, want) = (
            cols.next().unwrap(),
            cols.next().unwrap(),
            cols.next().unwrap(),
        );
        if want == "!" || !valid(a) || !valid(b) {
            continue;
        }
        seen += 1;
        let got = match cmp(a, b) {
            Ordering::Less => "<",
            Ordering::Equal => "=",
            Ordering::Greater => ">",
        };
        if got != want {
            bad.push(format!("{a} {got} {b} (도구는 {want})"));
        }
    }
    assert!(
        bad.is_empty(),
        "{name} 와 갈린 짝 {}개:\n{}",
        bad.len(),
        bad.join("\n")
    );
    println!("{name}: 꼴을 지난 짝 {seen}개 — 모두 도구와 같은 답");
    seen
}

#[test]
fn dpkg_comparisons_match_dpkg() {
    let n = check(
        "dpkg",
        include_str!("data/pkgver/dpkg.tsv"),
        is_pkg_version,
        dpkg_cmp,
    );
    assert!(n > 100, "꼴을 지난 짝이 너무 적다: {n}");
}

#[test]
fn rpm_comparisons_match_rpm() {
    let n = check(
        "rpm",
        include_str!("data/pkgver/rpm.tsv"),
        is_rpm_version,
        rpm_cmp,
    );
    assert!(n > 100, "꼴을 지난 짝이 너무 적다: {n}");
}

#[test]
fn apk_comparisons_match_apk() {
    let n = check(
        "apk",
        include_str!("data/pkgver/apk.tsv"),
        is_apk_version,
        apk_cmp,
    );
    assert!(n > 100, "꼴을 지난 짝이 너무 적다: {n}");
}
