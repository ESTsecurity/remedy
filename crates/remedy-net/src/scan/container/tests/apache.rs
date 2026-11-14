//! Apache(코어 1.18.0) — 컨테이너의 패키지 기록 · 공식 `httpd` 꼴 · 알려진 자리의 설정. 기준은 시험 사본
//! (`testdata/apache.json`). 판정 표는 `scan::rules::apache` 가 재고, 여기서는 컨테이너에서 무엇을 읽어 넘기는지 잰다.

use super::support::*;
use crate::scan::binary::fixtures::minimal_elf64;
use crate::scan::container::files::scan_container_files;
use crate::scan::container::inspect::Inspect;
use crate::scan::container::record::finalize_container_target;
use crate::scan::model::{Finding, Product, Status, Target, TargetKind};
use crate::scan::rules::RuleSet;
use base64::Engine as _;
use remedy_sdk::i18n::Lang;
use sha1::{Digest as _, Sha1};

const DEBIAN_MAINTAINER: &str = "Debian Apache Maintainers <debian-apache@lists.debian.org>";
const MODULE: &str = "/usr/lib/apache2/modules/mod_http2.so";

fn module() -> Vec<u8> {
    minimal_elf64()
}

fn httpd(version: &str) -> Vec<u8> {
    let mut data = minimal_elf64();
    data.extend_from_slice(format!("\0Apache/{version} (Unix)\0").as_bytes());
    data
}

/// 컨테이너 하나를 Apache 만 골라 본다.
fn scan(files: Vec<(&str, Vec<u8>)>, env: &[&str]) -> (Target, Vec<String>) {
    scan_on(&files_engine(files), env)
}

fn scan_on(engine: &Engine, env: &[&str]) -> (Target, Vec<String>) {
    let (b, _, _) = budget();
    let mut c = client(&b, engine, "linux");
    let inspected = Inspect {
        env: env.iter().map(|e| e.to_string()).collect(),
        ..Inspect::default()
    };
    let mut t = Target::new(
        format!("container:{TEST_ID}"),
        TargetKind::Container,
        TEST_ID,
        &[],
    );
    scan_container_files(
        &mut c,
        &mut t,
        TEST_ID,
        &inspected,
        RuleSet::fixture(),
        &[Product::Apache],
    );
    finalize_container_target(&mut t, Lang::Ko);
    (t, engine.lines())
}

fn apache(t: &Target) -> Vec<&Finding> {
    t.findings
        .iter()
        .filter(|f| f.product == Product::Apache)
        .collect()
}

fn debian(version: &str, sum: &str) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("/etc/os-release", b"ID=debian\nVERSION_ID=\"12\"\n".to_vec()),
        (
            "/var/lib/dpkg/status",
            format!("Package: apache2-bin\nStatus: install ok installed\nVersion: {version}\nArchitecture: amd64\nMaintainer: {DEBIAN_MAINTAINER}\n\n").into_bytes(),
        ),
        (
            "/var/lib/dpkg/info/apache2-bin:amd64.md5sums",
            format!("{sum}  usr/lib/apache2/modules/mod_http2.so\n").into_bytes(),
        ),
        (MODULE, module()),
    ]
}

fn enabled(mut files: Vec<(&'static str, Vec<u8>)>) -> Vec<(&'static str, Vec<u8>)> {
    files.push((
        "/etc/apache2/mods-enabled/http2.load",
        b"LoadModule http2_module x\n".to_vec(),
    ));
    files.push((
        "/etc/apache2/mods-enabled/http2.conf",
        b"Protocols h2 h2c http/1.1\n".to_vec(),
    ));
    files
}

#[test]
fn a_debian_package_with_http2_on_is_vulnerable_and_a_fixed_one_still_needs_review() {
    let sum = md5_hex(&module());
    let (t, _) = scan(enabled(debian("2.4.62-1~deb12u2", &sum)), &[]);
    assert_eq!(
        t.products[&Product::Apache].status,
        Status::Vulnerable,
        "{t:#?}"
    );
    let f = apache(&t);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert!(
        f[0].evidence
            .iter()
            .any(|e| e.detail.contains("일치합니다")),
        "{f:#?}"
    );
    // 고친 판 — 판정은 양호지만 컨테이너는 파일을 하나씩만 읽어 *양호* 로 올리지 않는다.
    let (t, _) = scan(enabled(debian("2.4.71-1~deb12u1", &sum)), &[]);
    assert_eq!(apache(&t)[0].status, Status::Clear, "{t:#?}");
    assert_eq!(t.products[&Product::Apache].status, Status::ReviewRequired);
    assert!(t.products[&Product::Apache]
        .gaps
        .iter()
        .any(|g| g.contains("개별 파일만")));
    // 켠 흔적이 없으면 영향 판도 확인 필요.
    let (t, _) = scan(debian("2.4.62-1~deb12u2", &sum), &[]);
    assert_eq!(apache(&t)[0].status, Status::ReviewRequired, "{t:#?}");
}

/// Debian 의 `mods-enabled` 는 링크다 — 엔진의 파일 정보가 링크(대상이 있는 꼴)여도 그 이름이 있으면 켠 흔적이다
/// (2026-11-14 실제 컨테이너에서 `a2enmod http2` 뒤 6 으로 나온 것을 고쳤다).
#[test]
fn debian_mods_enabled_links_count_as_signs() {
    let files: std::collections::HashMap<String, Vec<u8>> =
        debian("2.4.62-1~deb12u2", &md5_hex(&module()))
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
    let engine = Engine::new(move |s| {
        let base = s.file.rsplit('/').next().unwrap_or_default().to_string();
        if s.file.starts_with("/etc/apache2/mods-enabled/")
            && matches!(base.as_str(), "http2.load" | "http2.conf")
        {
            let stat = encoded_stat(
                &base,
                30,
                0o777 | MODE_SYMLINK,
                &format!("../mods-available/{base}"),
            );
            return Ok(Answer::ok(Vec::new()).stat(&stat));
        }
        Ok(match files.get(&s.file) {
            Some(content) => file_answer(s, &base, content, 0o755),
            None => Answer::status(404),
        })
    });
    let (t, _) = scan_on(&engine, &[]);
    assert_eq!(
        t.products[&Product::Apache].status,
        Status::Vulnerable,
        "{t:#?}"
    );
    let f = apache(&t);
    assert!(
        f[0].evidence
            .iter()
            .any(|e| e.source.ends_with("mods-enabled/http2.load")),
        "{f:#?}"
    );
}

#[test]
fn a_module_that_does_not_match_its_record_is_not_judged() {
    let (t, _) = scan(enabled(debian("2.4.62-1~deb12u2", &md5_hex(b"other"))), &[]);
    let f = apache(&t);
    assert_eq!(f[0].status, Status::ReviewRequired, "{f:#?}");
    assert!(f[0].reason.contains("믿을 근거"), "{}", f[0].reason);
    assert!(
        f[0].evidence
            .iter()
            .any(|e| e.detail.contains("일치하지 않습니다")),
        "{f:#?}"
    );
}

#[test]
fn the_official_httpd_container_goes_by_its_markers() {
    let files = || {
        vec![
            (
                "/etc/os-release",
                b"ID=debian\nVERSION_ID=\"13\"\n".to_vec(),
            ),
            ("/var/lib/dpkg/status", Vec::new()),
            ("/usr/local/apache2/bin/httpd", httpd("2.4.65")),
            (
                "/usr/local/apache2/conf/httpd.conf",
                b"LoadModule http2_module modules/mod_http2.so\nProtocols h2 http/1.1\n".to_vec(),
            ),
        ]
    };
    let env = [
        "HTTPD_PREFIX=/usr/local/apache2",
        "HTTPD_VERSION=2.4.65",
        "HTTPD_PATCHES=",
    ];
    let (t, _) = scan(files(), &env);
    assert_eq!(
        t.products[&Product::Apache].status,
        Status::Vulnerable,
        "{t:#?}"
    );
    let f = apache(&t);
    assert_eq!(f[0].version.as_deref(), Some("2.4.65"));
    assert!(
        f[0].evidence
            .iter()
            .any(|e| e.detail.contains("공식 httpd 이미지의 꼴")),
        "{f:#?}"
    );
    let (t, _) = scan(files(), &[]);
    let f = apache(&t);
    assert_eq!(f[0].status, Status::ReviewRequired, "{f:#?}");
    assert!(
        f[0].evidence
            .iter()
            .any(|e| e.detail.contains("HTTPD_VERSION 이 없습니다")),
        "{f:#?}"
    );
}

#[test]
fn an_alpine_record_counts_when_its_checksum_matches() {
    let files = |right: bool| {
        let z = base64::engine::general_purpose::STANDARD.encode(Sha1::digest(if right {
            module()
        } else {
            b"other".to_vec()
        }));
        vec![
            ("/etc/os-release", b"ID=alpine\nVERSION_ID=3.22.2\n".to_vec()),
            (
                "/lib/apk/db/installed",
                format!("P:apache2-http2\nV:2.4.65-r1\nF:usr/lib/apache2\nR:mod_http2.so\na:0:0:755\nZ:Q1{z}\n\n").into_bytes(),
            ),
            ("/usr/lib/apache2/mod_http2.so", module()),
            (
                "/etc/apache2/conf.d/http2.conf",
                b"LoadModule http2_module modules/mod_http2.so\nProtocols h2 http/1.1\n".to_vec(),
            ),
        ]
    };
    let (t, _) = scan(files(true), &[]);
    assert_eq!(
        t.products[&Product::Apache].status,
        Status::Vulnerable,
        "{t:#?}"
    );
    let (t, _) = scan(files(false), &[]);
    assert_eq!(apache(&t)[0].status, Status::ReviewRequired, "{t:#?}");
}

#[test]
fn no_apache_reads_no_settings_and_never_says_clear() {
    let (t, lines) = scan(
        vec![
            (
                "/etc/os-release",
                b"ID=debian\nVERSION_ID=\"12\"\n".to_vec(),
            ),
            ("/var/lib/dpkg/status", Vec::new()),
        ],
        &[],
    );
    assert!(apache(&t).is_empty(), "{t:#?}");
    assert_eq!(t.products[&Product::Apache].status, Status::ReviewRequired);
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("/etc/httpd/conf/httpd.conf")),
        "{lines:#?}"
    );
}
