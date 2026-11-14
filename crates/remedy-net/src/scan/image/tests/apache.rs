//! Apache(코어 1.18.0) — 이미지의 패키지 · 공식 `httpd` 꼴 · HTTP/2 흔적. 기준은 시험 사본(`testdata/apache.json`).
//!
//! 판정 표 자체는 `scan::rules::apache` 의 시험이 잰다 — 여기서는 이미지에서 무엇을 근거로 넘기는지를 잰다.

use super::fixtures::*;
use crate::scan::model::{Product, Status, Target};
use crate::scan::rules::RuleSet;
use base64::Engine as _;
use serde_json::{json, Value};
use sha1::{Digest as _, Sha1};

const DEBIAN_MAINTAINER: &str = "Debian Apache Maintainers <debian-apache@lists.debian.org>";
const MODULE: &str = "usr/lib/apache2/modules/mod_http2.so";
const A: [Product; 1] = [Product::Apache];

fn rules() -> &'static RuleSet {
    RuleSet::fixture()
}

/// OCI 레이아웃 하나 — 이미지 설정에 환경 변수를 싣는다(공식 `httpd` 이미지의 표지).
fn image(items: &[Item], env: &[&str]) -> Scratch {
    let (dir, _) = oci(&[tar(items)], Packing::Raw, &[]);
    if env.is_empty() {
        return dir;
    }
    let index: Value =
        serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
    let manifest_path = blob_path(
        dir.path(),
        index["manifests"][0]["digest"].as_str().unwrap(),
    );
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let config_path = blob_path(dir.path(), manifest["config"]["digest"].as_str().unwrap());
    let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    config["config"] = json!({ "Env": env });
    manifest["config"] = blob(dir.path(), &bytes(&config), OCI_CONFIG);
    let mut d = blob(dir.path(), &bytes(&manifest), OCI_MANIFEST);
    d["platform"] = json!({"os": "linux", "architecture": "amd64"});
    write_index(dir.path(), &[d]);
    dir
}

fn scan(items: &[Item], env: &[&str], products: &[Product]) -> Target {
    let dir = image(items, env);
    let mut targets = run(dir.path(), products, rules());
    assert_eq!(targets.len(), 1, "{targets:#?}");
    targets.remove(0)
}

fn apache_status(t: &Target) -> Status {
    t.products[&Product::Apache].status
}

fn apache_findings(t: &Target) -> Vec<&crate::scan::model::Finding> {
    t.findings
        .iter()
        .filter(|f| f.product == Product::Apache)
        .collect()
}

/// Debian 의 apache2-bin 과 그 mod_http2.so · 파일 목록 · 검증 기록. `sums` 가 거짓이면 다른 내용의 MD5 를 적는다.
fn debian(version: &str, sums: bool) -> Vec<Item> {
    let module = elf(&[]);
    let md5 = if sums {
        md5_hex(&module)
    } else {
        md5_hex(b"other")
    };
    vec![
        reg("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n"),
        reg(
            "var/lib/dpkg/status",
            format!("Package: apache2-bin\nStatus: install ok installed\nVersion: {version}\nArchitecture: amd64\nMaintainer: {DEBIAN_MAINTAINER}\n\n"),
        ),
        reg("var/lib/dpkg/info/apache2-bin.list", format!("/usr/sbin/apache2\n/{MODULE}\n")),
        reg("var/lib/dpkg/info/apache2-bin.md5sums", format!("{md5}  {MODULE}\n")),
        reg(MODULE, module),
        reg("etc/apache2/apache2.conf", "IncludeOptional mods-enabled/*.load\nIncludeOptional mods-enabled/*.conf\n"),
        reg("etc/apache2/mods-available/http2.load", "LoadModule http2_module /usr/lib/apache2/modules/mod_http2.so\n"),
        reg("etc/apache2/mods-available/http2.conf", "Protocols h2 h2c http/1.1\n"),
    ]
}

/// `a2enmod http2` 가 만드는 두 링크.
fn enabled() -> Vec<Item> {
    vec![
        kind(
            "etc/apache2/mods-enabled/http2.load",
            b'2',
            "../mods-available/http2.load",
        ),
        kind(
            "etc/apache2/mods-enabled/http2.conf",
            b'2',
            "../mods-available/http2.conf",
        ),
    ]
}

#[test]
fn a_debian_package_is_judged_with_the_http2_signs() {
    let mut on = debian("2.4.62-1~deb12u2", true);
    on.extend(enabled());
    let t = scan(&on, &[], &A);
    assert_eq!(apache_status(&t), Status::Vulnerable, "{t:#?}");
    assert_eq!(t.status, Status::Vulnerable);
    let f = apache_findings(&t);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].package.as_deref(), Some("apache2-bin"));
    assert!(
        f[0].evidence
            .iter()
            .any(|e| e.detail.contains("일치합니다")),
        "{f:#?}"
    );
    // 모듈을 켜지 않은 기본 설정 — 영향 판이어도 확인 필요(호스트 룰의 결정 3).
    let off = scan(&debian("2.4.62-1~deb12u2", true), &[], &A);
    assert_eq!(apache_status(&off), Status::ReviewRequired, "{off:#?}");
    // 고친 판은 켰어도 양호.
    let mut fixed = debian("2.4.71-1~deb12u1", true);
    fixed.extend(enabled());
    let fixed = scan(&fixed, &[], &A);
    assert_eq!(apache_status(&fixed), Status::Clear, "{fixed:#?}");
    assert_eq!(fixed.status, Status::Clear);
    assert!(fixed.complete);
}

#[test]
fn a_module_that_does_not_match_its_record_is_not_judged() {
    let mut items = debian("2.4.71-1~deb12u1", false);
    items.extend(enabled());
    let t = scan(&items, &[], &A);
    assert_eq!(apache_status(&t), Status::ReviewRequired, "{t:#?}");
    let f = apache_findings(&t);
    assert!(f[0].reason.contains("믿을 근거"), "{}", f[0].reason);
    assert!(
        f[0].evidence
            .iter()
            .any(|e| e.detail.contains("일치하지 않습니다")),
        "{f:#?}"
    );
}

#[test]
fn php_config_capture_still_feeds_the_http2_signs() {
    // 기본 점검(all)은 PHP 도 고른다 — Apache 설정은 PHP 설정으로 담기지만 같은 바이트로 흔적을 본다.
    let mut items = debian("2.4.62-1~deb12u2", true);
    items.push(reg(
        "etc/apache2/sites-available/site.conf",
        "<VirtualHost *:443>\n  Protocols h2 http/1.1\n</VirtualHost>\n",
    ));
    items.push(reg(
        "etc/apache2/conf-enabled/h2.conf",
        "LoadModule http2_module /usr/lib/apache2/modules/mod_http2.so\n",
    ));
    let all = [Product::Php, Product::Node, Product::Apache];
    let t = scan(&items, &[], &all);
    assert_eq!(apache_status(&t), Status::Vulnerable, "{t:#?}");
    let f = apache_findings(&t);
    assert!(f[0]
        .evidence
        .iter()
        .any(|e| e.source == "/etc/apache2/sites-available/site.conf"));
    // PHP 를 고르지 않아도 같다(그때는 Apache 몫의 한도로 담는다).
    let alone = scan(&items, &[], &A);
    assert_eq!(apache_status(&alone), Status::Vulnerable, "{alone:#?}");
}

/// 공식 `httpd` 이미지의 꼴 — `/usr/local/apache2` 에 직접 빌드, 패키지 기록에 Apache 가 없다.
fn official(version: &str, conf: &str) -> Vec<Item> {
    let mut httpd = elf(&[]);
    httpd[2048..].fill(0);
    let text = format!("\0Apache/{version} (Unix)\0Apache/{version}\0");
    httpd[2048..2048 + text.len()].copy_from_slice(text.as_bytes());
    vec![
        reg("etc/os-release", "ID=debian\nVERSION_ID=\"13\"\n"),
        reg("var/lib/dpkg/status", format!("Package: libc6\nStatus: install ok installed\nVersion: 2.41-12\nMaintainer: {DEBIAN_MAINTAINER}\n\n")),
        mode(reg("usr/local/apache2/bin/httpd", httpd), 0o755),
        reg("usr/local/apache2/modules/mod_http2.so", elf(&[])),
        reg("usr/local/apache2/conf/httpd.conf", conf),
    ]
}

fn env(version: &str) -> Vec<String> {
    vec![
        "HTTPD_PREFIX=/usr/local/apache2".to_string(),
        format!("HTTPD_VERSION={version}"),
        "HTTPD_PATCHES=".to_string(),
    ]
}

const DEFAULT_CONF: &str = "#LoadModule http2_module modules/mod_http2.so\nListen 80\n";
const H2_CONF: &str = "LoadModule http2_module modules/mod_http2.so\nProtocols h2 http/1.1\n";

#[test]
fn the_official_httpd_image_goes_by_its_markers() {
    let e65 = env("2.4.65");
    let e65: Vec<&str> = e65.iter().map(String::as_str).collect();
    // 기본 설정은 HTTP/2 가 꺼져 있다(httpd.conf 의 주석 줄) — 영향 판이어도 확인 필요.
    let t = scan(&official("2.4.65", DEFAULT_CONF), &e65, &A);
    assert_eq!(apache_status(&t), Status::ReviewRequired, "{t:#?}");
    let f = apache_findings(&t);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].version.as_deref(), Some("2.4.65"));
    assert!(
        f[0].evidence
            .iter()
            .any(|e| e.detail.contains("공식 httpd 이미지의 꼴")),
        "{f:#?}"
    );
    let on = scan(&official("2.4.65", H2_CONF), &e65, &A);
    assert_eq!(apache_status(&on), Status::Vulnerable, "{on:#?}");
    let e71 = env("2.4.71");
    let e71: Vec<&str> = e71.iter().map(String::as_str).collect();
    let fixed = scan(&official("2.4.71", H2_CONF), &e71, &A);
    assert_eq!(apache_status(&fixed), Status::Clear, "{fixed:#?}");
}

#[test]
fn a_version_text_without_the_markers_is_not_judged() {
    let check = |env: &[&str], why: &str| {
        let t = scan(&official("2.4.65", H2_CONF), env, &A);
        assert_eq!(apache_status(&t), Status::ReviewRequired, "{t:#?}");
        let f = apache_findings(&t);
        assert!(
            f[0].evidence.iter().any(|e| e.detail.contains(why)),
            "{why}: {f:#?}"
        );
    };
    check(&[], "HTTPD_VERSION 이 없습니다");
    check(&["HTTPD_VERSION=2.4.71", "HTTPD_PATCHES="], "다릅니다");
    check(
        &["HTTPD_VERSION=2.4.65", "HTTPD_PATCHES=CVE-fix.patch abc"],
        "HTTPD_PATCHES",
    );
    check(
        &["HTTPD_VERSION=2.4.65", "HTTPD_PREFIX=/opt/httpd"],
        "HTTPD_PREFIX",
    );
}

#[test]
fn an_httpd_without_the_apache_version_text_is_not_apache() {
    // busybox 의 httpd 처럼 이름만 같은 실행 파일.
    let items = vec![
        reg("etc/os-release", "ID=alpine\nVERSION_ID=3.22.2\n"),
        reg(
            "lib/apk/db/installed",
            "P:busybox\nV:1.37.0-r18\nF:bin\nR:busybox\n\n",
        ),
        mode(reg("usr/sbin/httpd", elf(&[])), 0o755),
    ];
    let t = scan(&items, &[], &A);
    assert!(apache_findings(&t).is_empty(), "{t:#?}");
    assert_eq!(apache_status(&t), Status::Clear);
}

/// Alpine 의 apache2-http2 — 기록의 `Z:Q1`(SHA-1 의 base64)이 실제 파일과 맞을 때만 그 판을 쓴다(목표 결정 3).
fn alpine(version: &str, right_sum: bool) -> Vec<Item> {
    let module = elf(&[]);
    let digest = Sha1::digest(if right_sum { &module[..] } else { b"other" });
    let z = base64::engine::general_purpose::STANDARD.encode(digest);
    vec![
        reg("etc/os-release", "ID=alpine\nVERSION_ID=3.22.2\n"),
        reg(
            "lib/apk/db/installed",
            format!("P:apache2-http2\nV:{version}\nF:etc/apache2/conf.d\nR:http2.conf\nZ:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\nF:usr/lib/apache2\nR:mod_http2.so\na:0:0:755\nZ:Q1{z}\n\n"),
        ),
        reg("usr/lib/apache2/mod_http2.so", module),
        reg("etc/apache2/conf.d/http2.conf", "LoadModule http2_module modules/mod_http2.so\nProtocols h2 http/1.1\n"),
    ]
}

#[test]
fn an_alpine_record_counts_when_its_checksum_matches() {
    let t = scan(&alpine("2.4.65-r1", true), &[], &A);
    assert_eq!(apache_status(&t), Status::Vulnerable, "{t:#?}");
    let fixed = scan(&alpine("2.4.71-r0", true), &[], &A);
    assert_eq!(apache_status(&fixed), Status::Clear, "{fixed:#?}");
    let wrong = scan(&alpine("2.4.71-r0", false), &[], &A);
    assert_eq!(apache_status(&wrong), Status::ReviewRequired, "{wrong:#?}");
    let f = apache_findings(&wrong);
    assert!(
        f[0].evidence
            .iter()
            .any(|e| e.detail.contains("apk 기록의 체크섬")),
        "{f:#?}"
    );
}

#[test]
fn no_apache_is_clear_and_php_alone_does_not_look() {
    let items = vec![
        reg("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n"),
        reg("var/lib/dpkg/status", format!("Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\nMaintainer: {DEBIAN_MAINTAINER}\n\n")),
    ];
    let t = scan(&items, &[], &A);
    assert_eq!(t.status, Status::Clear, "{t:#?}");
    assert!(t.complete);
    // PHP 만 고르면 Apache 칸이 없다 — 1.17.0 의 결과와 같다.
    let mut on = debian("2.4.62-1~deb12u2", true);
    on.extend(enabled());
    let php = scan(&on, &[], &[Product::Php]);
    assert!(!php.products.contains_key(&Product::Apache));
    assert!(apache_findings(&php).is_empty());
}
