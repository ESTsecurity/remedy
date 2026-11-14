//! Apache — 컨테이너의 패키지 기록 · 패키지 없는 `httpd` · 알려진 자리의 설정(코어 1.18.0 · 목표 `remedy_net아파치`).
//!
//! 이미지 점검(`scan::image::apache`)과 같은 규칙이다 — 판을 믿는 근거(실제 `mod_http2.so` 가 패키지 기록과 같다 ·
//! 공식 `httpd` 이미지의 표지)와 HTTP/2 흔적(`scan::apacheconf`). 다른 점은 컨테이너의 파일을 **하나씩만** 읽는다는
//! 것이다 — 폴더를 훑지 않으므로 알려진 자리의 설정과 실행 파일만 읽는다. 그래서 컨테이너의 Apache 는 *양호* 로
//! 내지 않는다(PHP · Node.js 와 같다 · 못 본 자리가 늘 남는다).
//!
//! - dpkg: `info/<패키지>[:<아키텍처>].md5sums` 의 `mod_http2.so` 줄과 그 파일의 MD5.
//! - RPM: 그 패키지(없으면 같은 빌드의 하위 패키지)의 파일 다이제스트와 그 파일.
//! - apk: `installed` 의 `Z:Q1…`(SHA-1)과 그 파일.

use super::client::Client;
use super::files::Subject;
use super::record::record_partial;
use super::rpm::RpmPackage;
use crate::scan::apacheconf::{
    official_note, server_versions, Http2, HttpdEnv, DEBIAN_CONF, DEBIAN_LOAD,
};
use crate::scan::binary::valid_runtime_binary;
use crate::scan::model::{Evidence, Finding, Product, Target};
use crate::scan::rules::{Component, PackageManager, UPSTREAM};
use base64::Engine as _;
use remedy_sdk::i18n::Lang;

/// 설정 파일 하나를 읽는 상한 — 이미지 점검과 같다.
const CONFIG_LIMIT: u64 = 1 << 20;
/// dpkg 의 검증 기록 하나를 읽는 상한.
const MD5SUMS_LIMIT: u64 = 1 << 20;

/// 흔적을 찾는 설정 — 찾은 꼴마다 그 배포판의 기본 자리만 읽는다(폴더를 훑지 못한다 · 엔진 API 요청은 실행 전체
/// 128회라 아낀다). 모두 `scan::apacheconf::is_config_path` 의 자리다. 링크인 `sites-enabled` 는 그 대상인
/// `sites-available` 로 읽는다.
const DEBIAN_CONFIGS: [&str; 4] = [
    "/etc/apache2/apache2.conf",
    "/etc/apache2/ports.conf",
    "/etc/apache2/sites-available/000-default.conf",
    "/etc/apache2/sites-available/default-ssl.conf",
];
const RPM_CONFIGS: [&str; 5] = [
    "/etc/httpd/conf/httpd.conf",
    "/etc/httpd/conf.d/ssl.conf",
    "/etc/httpd/conf.modules.d/10-h2.conf",
    "/etc/httpd/conf.modules.d/00-base.conf",
    "/etc/apache2/httpd.conf",
];
const APK_CONFIGS: [&str; 3] = [
    "/etc/apache2/httpd.conf",
    "/etc/apache2/conf.d/http2.conf",
    "/etc/apache2/conf.d/ssl.conf",
];
/// 직접 빌드는 그 접두사 아래의 이 둘.
const BUILD_CONFIGS: [&str; 2] = ["conf/httpd.conf", "conf/extra/httpd-ssl.conf"];

/// 판정을 기다리는 것 — 판을 믿을 근거를 본 뒤 HTTP/2 흔적과 함께 기준에 넘긴다.
struct Pending {
    component: Component,
    notes: Vec<Evidence>,
}

/// Apache 를 판정해 대상에 싣는다.
pub(crate) fn scan_apache_container(c: &mut Client<'_>, t: &mut Target, s: &Subject<'_>) {
    let lang = c.lang;
    let Some(criteria) = s.rules.apache() else {
        t.add_product_gap(
            Product::Apache,
            lang.t(
                "Apache 판정 기준을 읽지 못했습니다.",
                "The Apache criteria could not be read.",
            ),
        );
        return;
    };
    let manager = match (s.distro, s.rpm.is_some()) {
        (_, true) => PackageManager::Rpm,
        ("debian" | "ubuntu", _) => PackageManager::Dpkg,
        ("alpine", _) => PackageManager::Apk,
        _ => PackageManager::Unknown,
    };
    let mut pending = Vec::new();
    for p in s.packages.iter().filter(|p| p.product == Product::Apache) {
        let mut component = p.clone();
        component.package_manager = manager;
        if !criteria.watches(manager, &component.package) {
            continue; // 같은 빌드의 하위 패키지(SUSE 의 MPM) — 모듈 대조에만 쓴다.
        }
        // 모듈 대조를 지나야 그 판을 믿는다 — RPM · apk 기록은 믿지 않는 채로 오고, dpkg 는 공식 관리자 주소일 때만
        // 대조까지 간다(`verify`).
        let (trusted, note) = match verify(c, s, &component) {
            Ok(note) => (true, note),
            Err(why) => (false, why),
        };
        component.trusted = trusted;
        pending.push(Pending {
            notes: vec![Evidence::new(component.source.as_str(), note)],
            component,
        });
    }
    let prefix = unowned_build(c, t, s, &mut pending);
    // 흔적은 *영향* 판에서만 판정을 가른다 — 흔적이 다 있다고 쳐도 *취약* 이 나오지 않으면 설정을 읽지 않는다.
    let all_on = Http2 {
        module: vec![String::new()],
        protocols: vec![String::new()],
        ..Http2::default()
    };
    let matters = pending.iter().any(|p| {
        s.rules.evaluate_apache(&p.component, &all_on, lang).status
            == crate::scan::model::Status::Vulnerable
    });
    if !pending.is_empty() {
        let h2 = if matters {
            signs(c, t, s, manager, prefix.as_deref())
        } else {
            Http2::default()
        };
        for Pending { component, notes } in pending {
            let mut f: Finding = s.rules.evaluate_apache(&component, &h2, lang);
            f.evidence.extend(notes);
            t.findings.push(f);
            record_partial(c, t);
        }
    }
    let (ko, en) = (
        "개별 파일만 조회하므로 다른 Apache 설치 경로와 Include 로 읽는 설정까지 모두 확인하지는 못합니다.",
        "Only individual files are read, so other Apache installations and settings read through Include are not all covered.",
    );
    t.add_product_gap(Product::Apache, lang.t(ko, en));
}

/// 판을 믿을 근거 — 실제 `mod_http2.so` 가 패키지 기록과 같다. 맞으면 그 근거, 아니면 까닭.
fn verify(c: &mut Client<'_>, s: &Subject<'_>, p: &Component) -> Result<String, String> {
    let lang = c.lang;
    match p.package_manager {
        PackageManager::Dpkg if p.trusted => verify_dpkg(c, s, p),
        PackageManager::Rpm => verify_rpm(c, s, p),
        PackageManager::Apk => verify_apk(c, s, p),
        _ => Err(lang.pick(
            format!(
                "패키지 {} 의 공식 공급사 정보를 확인하지 못했습니다",
                p.package
            ),
            format!(
                "the official vendor of package {} could not be confirmed",
                p.package
            ),
        )),
    }
}

fn no_module(p: &Component, lang: Lang) -> String {
    lang.pick(
        format!(
            "패키지 {} 의 기록에 HTTP/2 모듈(mod_http2.so)이 없습니다",
            p.package
        ),
        format!(
            "the record of package {} has no HTTP/2 module (mod_http2.so)",
            p.package
        ),
    )
}

fn mismatch(name: &str, lang: Lang) -> String {
    lang.pick(
        format!("패키지 기록과 실제 HTTP/2 모듈 파일의 내용이 일치하지 않습니다: {name}"),
        format!("the actual HTTP/2 module file does not match the package record: {name}"),
    )
}

fn matched(how: &str, lang: Lang) -> String {
    lang.pick(
        format!("컨테이너의 HTTP/2 모듈 파일의 {how} 가 이 패키지 기록과 일치합니다. 패키지 서명이나 공급사 출처를 암호학적으로 검증한 결과는 아닙니다"),
        format!("the container's HTTP/2 module file's {how} matches this package record. This is not a cryptographic check of the package signature or vendor origin"),
    )
}

/// 모듈 파일 하나를 읽는다 — 실행 파일 머리까지 본다.
fn read_module(
    c: &mut Client<'_>,
    s: &Subject<'_>,
    name: &str,
) -> Result<super::client::BinaryFile, String> {
    let lang = c.lang;
    let file = c.read_binary(s.id, name).map_err(|e| {
        let why = e.message(lang);
        lang.pick(
            format!("HTTP/2 모듈 파일을 읽지 못했습니다 {name}: {why}"),
            format!("Could not read the HTTP/2 module file {name}: {why}"),
        )
    })?;
    if !valid_runtime_binary(&file.prefix, file.size) {
        return Err(lang.pick(
            format!("HTTP/2 모듈 파일의 머리 또는 파일 범위를 확인하지 못했습니다: {name}"),
            format!(
                "the HTTP/2 module file's header or file ranges could not be confirmed: {name}"
            ),
        ));
    }
    Ok(file)
}

/// dpkg — `info/<패키지>[:<아키텍처>].md5sums` 의 `mod_http2.so` 줄.
fn verify_dpkg(c: &mut Client<'_>, s: &Subject<'_>, p: &Component) -> Result<String, String> {
    let lang = c.lang;
    let base = format!("/var/lib/dpkg/info/{}", p.package);
    // 아키텍처가 붙은 이름은 `Multi-Arch: same` 패키지의 것이다 — apache2-bin 은 붙지 않은 이름이라 먼저 묻는다.
    let mut names = vec![format!("{base}.md5sums")];
    if !p.architecture.is_empty() {
        names.push(format!("{base}:{}.md5sums", p.architecture));
    }
    let mut sums = None;
    for name in &names {
        match c.read_metadata(s.id, name, MD5SUMS_LIMIT) {
            Ok(data) => {
                sums = Some(data);
                break;
            }
            Err(e) if e.is_missing() => continue,
            Err(e) => {
                let why = e.message(lang);
                return Err(lang.pick(
                    format!("패키지 파일 검증 기록(.md5sums)을 읽지 못했습니다 {name}: {why}"),
                    format!("Could not read the package checksum list (.md5sums) {name}: {why}"),
                ));
            }
        }
    }
    let Some(sums) = sums else {
        return Err(lang.pick(
            format!(
                "패키지 {} 의 파일 검증 기록(.md5sums)이 없습니다",
                p.package
            ),
            format!("package {} has no checksum list (.md5sums)", p.package),
        ));
    };
    let lines: Vec<(String, String)> = String::from_utf8_lossy(&sums)
        .lines()
        .filter_map(|line| {
            let (hash, path) = line.split_once("  ")?;
            let path = path.trim();
            (path.rsplit('/').next() == Some("mod_http2.so")).then(|| {
                (
                    hash.trim().to_ascii_lowercase(),
                    format!("/{}", path.trim_start_matches('/')),
                )
            })
        })
        .collect();
    if lines.is_empty() {
        return Err(no_module(p, lang));
    }
    for (hash, name) in &lines {
        let file = read_module(c, s, name)?;
        if file.md5.is_empty() || !file.md5.eq_ignore_ascii_case(hash) {
            return Err(mismatch(name, lang));
        }
    }
    Ok(matched("MD5(.md5sums)", lang))
}

/// RPM — 그 패키지(없으면 같은 빌드의 하위 패키지)의 `mod_http2.so` 다이제스트.
fn verify_rpm(c: &mut Client<'_>, s: &Subject<'_>, p: &Component) -> Result<String, String> {
    let lang = c.lang;
    let Some(records) = s.rpm else {
        return Err(no_module(p, lang));
    };
    let Some(own) = records.get(&p.id) else {
        return Err(no_module(p, lang));
    };
    if own.vendor.is_empty() || own.architecture.is_empty() {
        return Err(lang.pick(
            format!(
                "패키지 {} 의 공식 공급사 정보를 확인하지 못했습니다",
                p.package
            ),
            format!(
                "the official vendor of package {} could not be confirmed",
                p.package
            ),
        ));
    }
    let digests = |r: &RpmPackage| -> Vec<(String, String, String)> {
        r.checksums
            .iter()
            .filter(|(path, sum)| {
                path.rsplit('/').next() == Some("mod_http2.so") && !sum.is_empty()
            })
            .map(|(path, sum)| {
                (
                    format!("/{path}"),
                    sum.clone(),
                    r.checksum_algorithm.clone(),
                )
            })
            .collect()
    };
    let mut modules = digests(own);
    if modules.is_empty() {
        let prefix = format!("{}-", own.name);
        for r in records.values().filter(|r| {
            r.name.starts_with(&prefix)
                && r.version == own.version
                && r.vendor == own.vendor
                && r.architecture == own.architecture
        }) {
            modules.extend(digests(r));
        }
    }
    if modules.is_empty() || own.checksum_error.is_some() {
        return Err(no_module(p, lang));
    }
    modules.sort();
    for (name, sum, algorithm) in &modules {
        let file = read_module(c, s, name)?;
        let actual = if algorithm == "sha256" {
            &file.sha256
        } else {
            &file.md5
        };
        if actual.is_empty() || !actual.eq_ignore_ascii_case(sum) {
            return Err(mismatch(name, lang));
        }
    }
    Ok(matched(&modules[0].2, lang))
}

/// apk — `installed` 의 그 패키지 문단에서 `mod_http2.so` 의 `Z:Q1…`(SHA-1 의 base64).
fn verify_apk(c: &mut Client<'_>, s: &Subject<'_>, p: &Component) -> Result<String, String> {
    let lang = c.lang;
    let text = String::from_utf8_lossy(s.package_data).replace("\r\n", "\n");
    let mut modules = Vec::new();
    for paragraph in text.split("\n\n") {
        let field = |k: &str| {
            paragraph
                .lines()
                .find_map(|l| l.strip_prefix(k))
                .unwrap_or_default()
        };
        if field("P:") != p.package || field("V:") != p.version {
            continue;
        }
        let (mut dir, mut last) = (String::new(), None::<String>);
        for line in paragraph.lines() {
            if let Some(d) = line.strip_prefix("F:") {
                (dir, last) = (d.to_string(), None);
            } else if let Some(f) = line.strip_prefix("R:") {
                last = Some(format!(
                    "/{}",
                    [dir.as_str(), f].join("/").trim_start_matches('/')
                ));
            } else if let Some(z) = line.strip_prefix("Z:") {
                if let Some(name) = last.take().filter(|n| n.ends_with("/mod_http2.so")) {
                    modules.push((name, z.to_string()));
                }
            }
        }
    }
    if modules.is_empty() {
        return Err(no_module(p, lang));
    }
    for (name, z) in &modules {
        let digest = z
            .strip_prefix("Q1")
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .filter(|d| d.len() == 20)
            .ok_or_else(|| mismatch(name, lang))?;
        let want: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let file = read_module(c, s, name)?;
        if file.sha1 != want {
            return Err(mismatch(name, lang));
        }
    }
    Ok(matched("SHA-1(apk Z:Q1)", lang))
}

/// 패키지 없는 `httpd` — `HTTPD_PREFIX` 의 `bin/httpd`(없으면 공식 이미지의 자리 `/usr/local/apache2`) 한 자리만
/// 묻는다. 찾았으면 그 접두사(설정을 읽을 자리)를 준다. 다른 자리의 직접 빌드는 컨테이너에서 찾지 못한다 — 대신
/// 컨테이너는 늘 *못 본 자리* 가 남아 *양호* 로 내지 않는다.
fn unowned_build(
    c: &mut Client<'_>,
    t: &mut Target,
    s: &Subject<'_>,
    pending: &mut Vec<Pending>,
) -> Option<String> {
    let lang = c.lang;
    let env = HttpdEnv::from_env(&s.inspected.env);
    let path = env.binary_path();
    let name = format!("/{path}");
    let file = match c.read_binary(s.id, &name) {
        Ok(file) => file,
        Err(e) if e.is_missing() => return None,
        Err(e) => {
            // 설정이 가리킨 자리만 *보지 못한 것* 으로 남긴다 — 그 밖은 흔히 없는 자리다.
            if env.version.is_some() {
                let why = e.message(lang);
                t.add_product_gap(
                    Product::Apache,
                    lang.pick(
                        format!("Apache 실행 파일을 읽지 못했습니다 {name}: {why}"),
                        format!("Could not read the Apache executable {name}: {why}"),
                    ),
                );
            }
            return None;
        }
    };
    let versions = server_versions(&file.prefix);
    if versions.is_empty() || !valid_runtime_binary(&file.prefix, file.size) {
        return None; // Apache 가 아니다.
    }
    let marker = env.official(&path, &versions, lang);
    let version = versions.join(", ");
    let mut component = Component::new(Product::Apache);
    component.id = format!("container-file:{name}");
    component.name = lang.t("Apache 실행 파일", "Apache executable").to_string();
    component.path = name.clone();
    component.version = version.clone();
    component.distribution = UPSTREAM.to_string();
    component.source = format!("container:{}{name}", s.id);
    component.runtime = "httpd".to_string();
    component.sha256 = file.sha256.clone();
    component.trusted = marker.is_ok();
    let note = match marker {
        Ok(()) => official_note(&version, lang),
        Err(why) => why,
    };
    let source = lang.t("컨테이너 설정", "container configuration");
    pending.push(Pending {
        notes: vec![
            Evidence::new(
                name.as_str(),
                lang.pick(
                    format!("실행 파일의 서버 판 문자열: Apache/{version}"),
                    format!("server version text in the executable: Apache/{version}"),
                ),
            ),
            Evidence::new(source, note),
        ],
        component,
    });
    t.add_product_scope(Product::Apache, name.as_str());
    Some(path.trim_end_matches("/bin/httpd").to_string())
}

/// HTTP/2 를 켠 흔적 — 찾은 꼴의 기본 자리만. Debian 계열은 `mods-enabled` 이름(HEAD 하나)도 본다. `prefix` 는 찾은
/// 직접 빌드의 접두사(뿌리 기준 · 앞의 `/` 없이)다.
fn signs(
    c: &mut Client<'_>,
    t: &mut Target,
    s: &Subject<'_>,
    manager: PackageManager,
    prefix: Option<&str>,
) -> Http2 {
    let mut h2 = Http2::default();
    let mut names: Vec<String> = Vec::new();
    match manager {
        PackageManager::Dpkg => {
            for name in [DEBIAN_LOAD, DEBIAN_CONF] {
                if c.stat(s.id, &format!("/{name}")).is_ok() {
                    h2.debian_enabled(name);
                }
            }
            names.extend(DEBIAN_CONFIGS.iter().map(|n| n.to_string()));
        }
        PackageManager::Rpm => names.extend(RPM_CONFIGS.iter().map(|n| n.to_string())),
        PackageManager::Apk => names.extend(APK_CONFIGS.iter().map(|n| n.to_string())),
        PackageManager::Unknown => {}
    }
    if let Some(prefix) = prefix {
        for tail in BUILD_CONFIGS {
            let name = format!("/{}", crate::scan::slashpath::join(&[prefix, tail]));
            if !names.contains(&name)
                && crate::scan::apacheconf::is_config_path(name.trim_start_matches('/'))
            {
                names.push(name);
            }
        }
    }
    for name in names {
        match c.read_metadata(s.id, &name, CONFIG_LIMIT) {
            Ok(data) if data.len() as u64 <= CONFIG_LIMIT => {
                h2.read_config(&name, &data);
                t.add_product_scope(Product::Apache, name.as_str());
            }
            Err(e) if e.is_missing() => {}
            _ => h2.unread.push(name),
        }
    }
    h2
}
