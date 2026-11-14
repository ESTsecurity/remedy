//! Apache — 배포판 패키지의 HTTP/2 모듈과 패키지 없는 `httpd`(코어 1.18.0 · 목표 `remedy_net아파치`).
//!
//! 판정은 `scan::rules` 의 Apache 기준이 한다(본체의 점검 룰 `apache-http2-check-linux` 와 같다). 여기서는 무엇을
//! 근거로 넘길지를 정한다.
//!
//! - **패키지** — 기준이 보는 패키지(`apache2-bin` · `mod_http2` · `apache2` · `apache2-http2`)는 그 패키지가 가진
//!   `mod_http2.so` 가 패키지 기록과 같을 때만 판을 믿는다. dpkg 는 공식 관리자 주소 + `.md5sums`, RPM 은 공급사 ·
//!   아키텍처 + 파일 다이제스트, apk 는 기록의 체크섬(`Z:Q1` · SHA-1)이 실제 파일과 맞을 때다(목표 결정 3). 하나라도
//!   어긋나면 판정하지 않는다(*확인 필요*) — 서명을 확인한 것은 아니다.
//! - **패키지 없는 `httpd`** — 어느 패키지도 가지지 않은 `httpd` 실행 파일 가운데 서버 판 문자열(`Apache/2.x.y`)이
//!   든 것. 공식 `httpd` 이미지의 꼴(`HTTPD_PREFIX` 의 `bin/httpd` · `HTTPD_VERSION` 이 판 문자열과 같음 ·
//!   `HTTPD_PATCHES` 가 빔)일 때만 그 판을 믿는다. 그 밖은 *확인 필요* 다 — 판 문자열만으로는 판정하지 않는다.
//! - **HTTP/2 흔적** — `scan::apacheconf` 의 자리 · 줄. PHP 설정으로 담은 파일도 같은 바이트라 그대로 읽는다.
//!   흔적은 대상 전체의 것이다(호스트 룰과 같다).

use super::packages::{file_problem, Record, APK_SOURCE, DPKG_SOURCE};
use super::rootfs::{Entry, RootFs};
use super::tarball::{TYPE_DIR, TYPE_REG, TYPE_SYMLINK};
use super::Cx;
use crate::scan::apacheconf::{
    is_apache_binary, is_config_path, official_note, server_versions, Http2, DEBIAN_CONF,
    DEBIAN_LOAD,
};
use crate::scan::binary::valid_runtime_binary;
use crate::scan::model::{Evidence, Finding, Product, Target};
use crate::scan::rules::{Component, PackageManager, UPSTREAM};
use crate::scan::slashpath;
use base64::Engine as _;
use remedy_sdk::i18n::Lang;
use std::collections::BTreeSet;

/// Apache 설정 파일 하나를 담는 상한 — 본체의 점검 룰이 담는 크기(`max_size: 1MB`)와 같다.
pub(super) const APACHE_FILE_LIMIT: i64 = 1 << 20;
/// Apache 설정을 담는 합계 — PHP 설정으로 담지 않은 것만 센다.
pub(super) const APACHE_DATA_LIMIT: i64 = 16 << 20;
/// Apache 설정 파일 수의 상한.
pub(super) const MAX_APACHE_FILES: usize = 256;
/// 한 대상의 Apache 판정 · 후보 수.
const MAX_ITEMS: usize = 1024;

/// Apache 를 판정한다. `os` 는 배포판의 `(ID, VERSION_ID)`.
pub(super) fn inspect(
    fs: &RootFs,
    t: &mut Target,
    cx: &Cx<'_>,
    packages: &[Record],
    os: (&str, &str),
) {
    let lang = cx.lang;
    let Some(criteria) = cx.rules.apache() else {
        t.add_product_gap(
            Product::Apache,
            lang.t(
                "Apache 판정 기준을 읽지 못했습니다",
                "the Apache criteria could not be read",
            ),
        );
        return;
    };
    let h2 = signs(fs, t);
    for p in packages {
        if !criteria.watches(manager(p), &p.name) {
            continue;
        }
        if t.findings.len() >= MAX_ITEMS {
            t.add_product_gap(Product::Apache, item_limit(lang));
            return;
        }
        let finding = package_finding(fs, t, cx, (p, packages), os, &h2);
        t.findings.push(finding);
    }
    let owned = owned_binaries(fs, packages);
    unowned_files(fs, t, cx, &owned, &h2);
}

/// 그 기록을 적은 패키지 관리자.
fn manager(p: &Record) -> PackageManager {
    if p.rpm {
        PackageManager::Rpm
    } else if p.source == DPKG_SOURCE {
        PackageManager::Dpkg
    } else if p.source == APK_SOURCE {
        PackageManager::Apk
    } else {
        PackageManager::Unknown
    }
}

/// HTTP/2 를 켠 흔적 — Debian 계열의 `mods-enabled` 이름과, 정한 자리의 설정 파일 본문.
fn signs(fs: &RootFs, t: &mut Target) -> Http2 {
    let mut h2 = Http2::default();
    for name in [DEBIAN_LOAD, DEBIAN_CONF] {
        // 링크라도 이름이 있으면 켠 것이다(본문은 보지 않는다).
        if fs.entries.get(name).is_some_and(|e| !e.special()) {
            h2.debian_enabled(name);
        }
    }
    for (name, e) in &fs.entries {
        // 링크(sites-enabled 의 것 등)는 세지 않는다 — 그 대상이 정한 자리에 있으면 거기서 읽힌다(호스트 룰과 같다).
        if e.kind != TYPE_REG || !is_config_path(name) {
            continue;
        }
        let path = format!("/{name}");
        if !e.truncated && e.data.len() as i64 == e.size {
            h2.read_config(&path, &e.data);
            t.add_product_scope(Product::Apache, path);
        } else {
            h2.unread.push(path);
        }
    }
    h2
}

/// 그 패키지 빌드의 `mod_http2.so` 와 그것을 가진 기록. 패키지 자신에게 없으면 **같은 빌드의 하위 패키지**(이름이
/// `<패키지>-` 로 시작하고 판 · 공급사 · 관리자가 같은 것)의 것이다 — SUSE 는 모듈을 MPM 패키지(`apache2-prefork` 등)에
/// 담는다(2026-11-14 Leap 15.6 실측).
fn module_files<'a>(p: &'a Record, packages: &'a [Record]) -> Vec<(&'a Record, &'a String)> {
    let own = |r: &'a Record| {
        r.files
            .iter()
            .filter(|f| slashpath::base(f) == "mod_http2.so")
            .map(move |f| (r, f))
    };
    let mine: Vec<_> = own(p).collect();
    if !mine.is_empty() {
        return mine;
    }
    let prefix = format!("{}-", p.name);
    packages
        .iter()
        .filter(|q| {
            q.name.starts_with(&prefix)
                && q.version == p.version
                && q.vendor == p.vendor
                && q.rpm == p.rpm
                && q.source == p.source
        })
        .flat_map(own)
        .collect()
}

/// 패키지 하나의 판정 — 판을 믿을 수 있는지(그 빌드의 `mod_http2.so` 가 기록과 같은가)를 본 뒤 기준에 넘긴다.
fn package_finding(
    fs: &RootFs,
    t: &mut Target,
    cx: &Cx<'_>,
    (p, packages): (&Record, &[Record]),
    os: (&str, &str),
    h2: &Http2,
) -> Finding {
    let lang = cx.lang;
    let manager = manager(p);
    let modules = module_files(p, packages);
    let mut c = Component::new(Product::Apache);
    c.id = format!("{}:{}", t.id, p.name);
    c.name = lang
        .t("Apache 이미지 패키지", "Apache image package")
        .to_string();
    c.path = modules
        .first()
        .map(|(_, m)| format!("/{m}"))
        .unwrap_or_default();
    c.version = p.version.clone();
    c.package = p.name.clone();
    (c.distribution, c.distribution_version) = (os.0.to_string(), os.1.to_string());
    c.source = p.source.clone();
    c.runtime = "mod_http2".to_string();
    (c.architecture, c.package_vendor, c.package_module) =
        (p.architecture.clone(), p.vendor.clone(), p.module.clone());
    c.package_manager = manager;
    let problem = verify(fs, p, manager, &modules, lang);
    c.trusted = problem.is_none();
    if let Some(Ok((_, e))) = modules.first().map(|(_, m)| fs.resolve(m)) {
        c.sha256 = e.sha256.clone();
    }
    let mut f = cx.rules.evaluate_apache(&c, h2, lang);
    let note = problem.unwrap_or_else(|| verified(p, manager, lang));
    f.evidence.push(Evidence::new(p.source.as_str(), note));
    t.add_product_scope(Product::Apache, p.source.clone());
    f
}

/// 판을 믿지 못하는 까닭 — 순서대로 하나만. 문제가 없으면 `None`.
fn verify(
    fs: &RootFs,
    p: &Record,
    manager: PackageManager,
    modules: &[(&Record, &String)],
    lang: Lang,
) -> Option<String> {
    if modules.is_empty() {
        return Some(lang.pick(
            format!(
                "패키지 {} 의 파일 목록에 HTTP/2 모듈(mod_http2.so)이 없습니다",
                p.name
            ),
            format!(
                "the file list of package {} has no HTTP/2 module (mod_http2.so)",
                p.name
            ),
        ));
    }
    let untrusted = |r: &Record| match manager {
        PackageManager::Dpkg | PackageManager::Rpm => !r.trusted,
        PackageManager::Apk => false,
        PackageManager::Unknown => true,
    };
    if let Some(r) = std::iter::once(p)
        .chain(modules.iter().map(|(r, _)| *r))
        .find(|r| untrusted(r))
    {
        return Some(lang.pick(
            format!(
                "패키지 {} 의 공식 공급사 정보를 확인하지 못했습니다",
                r.name
            ),
            format!(
                "the official vendor of package {} could not be confirmed",
                r.name
            ),
        ));
    }
    let mut checked = 0usize;
    for (owner, listed) in modules {
        let (owner, listed): (&Record, &str) = (owner, listed);
        // 링크는 본문이 없어 기록에 체크섬도 없다(SUSE 의 `/etc/alternatives/mod_http2.so`) — 그 대상은 따로 적혀 있다.
        if fs
            .entries
            .get(listed)
            .is_some_and(|e| e.kind == TYPE_SYMLINK)
        {
            continue;
        }
        checked += 1;
        let Ok((resolved, e)) = fs.resolve(listed) else {
            return Some(lang.pick(
                format!("최종 이미지에 패키지 기록의 HTTP/2 모듈 파일이 없습니다: /{listed}"),
                format!("the HTTP/2 module file in the package record is not in the final image: /{listed}"),
            ));
        };
        if e.kind != TYPE_REG || !valid_runtime_binary(&e.data, e.size.max(0) as u64) {
            return Some(lang.pick(
                format!("HTTP/2 모듈 파일의 머리 또는 파일 범위를 확인하지 못했습니다: /{resolved}"),
                format!("the HTTP/2 module file's header or file ranges could not be confirmed: /{resolved}"),
            ));
        }
        // 기록의 열쇠는 그 패키지가 적은 경로다 — 링크를 푼 경로가 아니다(merged-usr 의 `lib` → `usr/lib`). 하위
        // 패키지의 모듈이면 그 하위 패키지의 기록과 견준다.
        let problem = match manager {
            PackageManager::Apk => apk_problem(owner, listed, e, lang),
            _ => file_problem(owner, listed, e, lang),
        };
        if problem.is_some() {
            return problem;
        }
    }
    if checked == 0 {
        return Some(lang.pick(
            format!(
                "패키지 {} 의 기록에 HTTP/2 모듈의 본체(일반 파일)가 없습니다 — 링크뿐입니다",
                p.name
            ),
            format!(
                "the record of package {} has no HTTP/2 module body (regular file) - only links",
                p.name
            ),
        ));
    }
    None
}

/// apk 기록의 체크섬(`Q1` + SHA-1 의 base64)이 실제 파일과 맞는가. 문제가 없으면 `None`.
fn apk_problem(p: &Record, listed: &str, e: &Entry, lang: Lang) -> Option<String> {
    let mismatch = || {
        Some(lang.pick(
            format!("apk 기록의 체크섬과 실제 파일 내용이 일치하지 않습니다: /{listed}"),
            format!("the file content does not match the apk record's checksum: /{listed}"),
        ))
    };
    let Some(want) = p.checksums.as_ref().and_then(|sums| sums.get(listed)) else {
        return Some(lang.pick(
            format!("apk 기록에 HTTP/2 모듈 파일의 체크섬이 없습니다: /{listed}"),
            format!("the apk record has no checksum for the HTTP/2 module file: /{listed}"),
        ));
    };
    let Some(digest) = want
        .strip_prefix("Q1")
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
    else {
        return mismatch();
    };
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if e.sha1.is_empty() || digest.len() != 20 || hex != e.sha1 {
        return mismatch();
    }
    None
}

/// 판을 믿은 근거 — 서명을 확인한 것은 아니다.
fn verified(p: &Record, manager: PackageManager, lang: Lang) -> String {
    let how = match manager {
        PackageManager::Dpkg => "MD5(.md5sums)",
        PackageManager::Rpm => p.checksum_algorithm,
        _ => "SHA-1(apk Z:Q1)",
    };
    lang.pick(
        format!("HTTP/2 모듈 파일의 {how} 가 이 패키지 기록과 일치합니다. 패키지 서명이나 공급사 출처를 암호학적으로 검증한 결과는 아닙니다"),
        format!("the HTTP/2 module file's {how} matches this package record. This is not a cryptographic check of the package signature or vendor origin"),
    )
}

/// 어느 패키지든 가진 `httpd` · `mod_http2.so` — 그 이름과 링크를 푼 경로.
fn owned_binaries(fs: &RootFs, packages: &[Record]) -> BTreeSet<String> {
    let mut owned = BTreeSet::new();
    for p in packages {
        for f in p.files.iter().filter(|f| is_apache_binary(f)) {
            if let Ok((resolved, _)) = fs.resolve(f) {
                owned.insert(resolved);
            }
            owned.insert(f.clone());
        }
    }
    owned
}

/// 어느 패키지도 가지지 않은 `httpd` 가운데 서버 판 문자열이 든 실행 파일.
fn unowned_files(fs: &RootFs, t: &mut Target, cx: &Cx<'_>, owned: &BTreeSet<String>, h2: &Http2) {
    let lang = cx.lang;
    let mut seen = BTreeSet::new();
    for (name, e) in &fs.entries {
        let skip = e.kind == TYPE_DIR || fs.special(name) || fs.runtime_data_file(name);
        if slashpath::base(name) != "httpd" || skip || owned.contains(name) {
            continue;
        }
        let Ok((resolved, entry)) = fs.resolve(name) else {
            continue;
        };
        let executable =
            entry.kind == TYPE_REG && valid_runtime_binary(&entry.data, entry.size.max(0) as u64);
        if owned.contains(&resolved) || !executable || !seen.insert(resolved.clone()) {
            continue;
        }
        let versions = server_versions(&entry.data);
        if versions.is_empty() {
            continue; // Apache 가 아니다(busybox 의 httpd 등).
        }
        if t.findings.len() >= MAX_ITEMS {
            t.add_product_gap(Product::Apache, item_limit(lang));
            return;
        }
        let found = Unowned {
            name,
            resolved: &resolved,
            entry,
            versions: &versions,
        };
        let finding = unowned_finding(fs, t, cx, &found, h2);
        t.findings.push(finding);
        t.add_product_scope(Product::Apache, format!("/{name}"));
    }
}

/// 찾은 패키지 없는 `httpd` 하나 — 이름 · 링크를 푼 자리 · 항목 · 판 문자열들.
struct Unowned<'a> {
    name: &'a str,
    resolved: &'a str,
    entry: &'a Entry,
    versions: &'a [String],
}

fn unowned_finding(
    fs: &RootFs,
    t: &Target,
    cx: &Cx<'_>,
    found: &Unowned<'_>,
    h2: &Http2,
) -> Finding {
    let lang = cx.lang;
    let (name, resolved, e, versions) = (found.name, found.resolved, found.entry, found.versions);
    let version = versions.join(", ");
    let marker = fs.httpd_env.official(resolved, versions, lang);
    let mut c = Component::new(Product::Apache);
    c.id = format!("{}:{name}", t.id);
    c.name = lang
        .t("Apache 이미지 파일", "Apache image file")
        .to_string();
    c.path = format!("/{name}");
    c.version = version.clone();
    c.distribution = UPSTREAM.to_string();
    c.source = super::php::static_source(lang).to_string();
    c.runtime = "httpd".to_string();
    c.sha256 = e.sha256.clone();
    c.trusted = marker.is_ok();
    let mut f = cx.rules.evaluate_apache(&c, h2, lang);
    f.evidence.push(Evidence::new(
        format!("/{name}"),
        lang.pick(
            format!("실행 파일의 서버 판 문자열: Apache/{version}"),
            format!("server version text in the executable: Apache/{version}"),
        ),
    ));
    let source = lang.t("이미지 설정", "image configuration");
    let note = match marker {
        Ok(()) => official_note(&version, lang),
        Err(why) => why,
    };
    f.evidence.push(Evidence::new(source, note));
    f
}

fn item_limit(lang: Lang) -> &'static str {
    lang.t(
        "Apache 판정 항목 1024개 제한을 넘었습니다",
        "the limit of 1024 Apache findings was exceeded",
    )
}
