//! PHP — 패키지가 소유한 실행 파일과 소유자 없는 실행 파일. 스캐너의 `inspectPHPRootFS` 를 옮겼다.
//!
//! 패키지가 소유한 파일은 그 패키지의 버전으로 판정한다 — 단, 실행 파일의 머리가 온전하고, 패키지 출처를 믿을 수
//! 있고, 파일이 패키지 기록(체크섬)과 같고, 파일 안의 PHP 버전 글자가 패키지 버전과 맞을 때만. 하나라도 어긋나면
//! 판정하지 않고 *보지 못한 것* 으로 남긴다. 소유자 없는 파일은 공식 빌드의 해시로만 판정하고, 그 밖에는 *확인
//! 필요* 다 — 파일 안의 버전 글자는 누가 지었는지를 말하지 않는다.

use super::packages::{file_problem, Record};
use super::rootfs::RootFs;
use super::tarball::TYPE_DIR;
use super::Cx;
use crate::scan::binary::valid_runtime_binary;
use crate::scan::linuxmeta::lower;
use crate::scan::model::{Evidence, Product, Target};
use crate::scan::rules::{Component, PackageManager, UPSTREAM};
use crate::scan::slashpath;
use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use remedy_sdk::i18n::Lang;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// 한 대상의 PHP 판정 · 후보 파일 수.
const MAX_ITEMS: usize = 4096;

fn php_file_name() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)^(?:php(?:[0-9]+(?:\.[0-9]+)?)?(?:-(?:fpm|cgi|cli))?",
            r"|php-(?:fpm|cgi)(?:[0-9]+(?:\.[0-9]+)?)?",
            r"|libphp(?:[0-9]+(?:\.[0-9]+)?)?\.(?:so|dll)",
            r"|php[0-9]+(?:ts|apache[0-9]+_[0-9]+)?\.dll)(?:\.exe)?$",
        ))
        .expect("고정된 정규식")
    })
}

fn php_package_name() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)^(?:php(?:[0-9]+(?:\.[0-9]+)?)?(?:-(?:cli|cgi|fpm|embed|apache2|apache))?",
            r"|libapache2-mod-php(?:[0-9]+(?:\.[0-9]+)?)?",
            r"|libphp(?:[0-9]+(?:\.[0-9]+)?)?)$",
        ))
        .expect("고정된 정규식")
    })
}

fn php_version_text() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| {
        BytesRegex::new(
            r"(?i)(?:PHP[/ ]|PHP_VERSION[= :\x00]+)([0-9]+\.[0-9]+\.[0-9]+(?:[-+._a-zA-Z0-9]*))",
        )
        .expect("고정된 정규식")
    })
}

fn core_version() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[0-9]+\.[0-9]+\.[0-9]+").expect("고정된 정규식"))
}

/// PHP 실행 파일 · 모듈의 이름인가(마지막 요소, 대소문자 무시).
pub(super) fn is_php_runtime(name: &str) -> bool {
    php_file_name().is_match(slashpath::base(name))
}

/// PHP 패키지의 이름인가.
pub(super) fn is_php_package(name: &str) -> bool {
    php_package_name().is_match(name)
}

/// 실행 꼴 — 이름으로 가른다.
fn runtime_name(name: &str) -> &'static str {
    let base = lower(slashpath::base(name).as_bytes());
    if base.contains("fpm") {
        "fpm"
    } else if base.contains("cgi") {
        "cgi"
    } else if base.starts_with("libphp") {
        "apache-module"
    } else {
        "cli"
    }
}

/// 파일 안의 PHP 버전 글자(첫 번째).
fn version_in(data: &[u8]) -> Option<String> {
    let caps = php_version_text().captures(data)?;
    Some(String::from_utf8_lossy(&caps[1]).into_owned())
}

/// 패키지 버전의 `X.Y.Z` 와 파일 안의 버전 글자(앞의 32개)가 모두 맞는가.
fn package_matches_binary(version: &str, data: &[u8]) -> bool {
    let Some(core) = core_version().find(version) else {
        return false;
    };
    php_version_text().captures_iter(data).take(32).all(|caps| {
        core_version()
            .find(&String::from_utf8_lossy(&caps[1]))
            .map(|m| m.as_str())
            == Some(core.as_str())
    })
}

/// PHP 를 판정한다. `os` 는 배포판의 `(ID, VERSION_ID)`.
pub(super) fn inspect(
    fs: &RootFs,
    t: &mut Target,
    cx: &Cx<'_>,
    packages: &[Record],
    os: (&str, &str),
) {
    let mut owned: BTreeMap<String, String> = BTreeMap::new();
    let mut php_packages = 0usize;
    for p in packages.iter().filter(|p| is_php_package(&p.name)) {
        php_packages += 1;
        if !owned_files(fs, t, cx, p, os, &mut owned) {
            return;
        }
    }
    let count = unowned_files(fs, t, cx, &owned);
    if php_packages > 0 && count == 0 {
        t.add_product_gap(
            Product::Php,
            cx.lang.t(
                "PHP 패키지 기록은 있으나 최종 이미지의 PHP 실행 파일을 확인하지 못했습니다",
                "there are PHP package records, but no PHP executable was found in the final image",
            ),
        );
    }
}

/// 패키지 하나가 소유한 실행 파일. 판정 항목이 한도에 닿으면 거짓(그만둔다).
fn owned_files(
    fs: &RootFs,
    t: &mut Target,
    cx: &Cx<'_>,
    p: &Record,
    os: (&str, &str),
    owned: &mut BTreeMap<String, String>,
) -> bool {
    let lang = cx.lang;
    for filename in p.files.iter().filter(|f| is_php_runtime(f)) {
        let Ok((resolved, e)) = fs.resolve(filename) else {
            continue;
        };
        if e.kind != super::tarball::TYPE_REG || fs.runtime_data_file(&resolved) {
            continue;
        }
        let identity = format!("{}:{}={}", p.name, p.architecture, p.version);
        if let Some(owner) = owned.get(&resolved) {
            if *owner != identity {
                t.add_product_gap(
                    Product::Php,
                    lang.pick(
                        format!("둘 이상의 PHP 패키지가 같은 파일을 소유한다고 기록돼 있습니다: /{resolved}"),
                        format!("more than one PHP package records owning the same file: /{resolved}"),
                    ),
                );
            }
            continue;
        }
        if let Some(problem) = owned_problem(p, &resolved, e, lang) {
            t.add_product_gap(Product::Php, problem);
            continue;
        }
        if t.findings.len() >= MAX_ITEMS {
            t.add_product_gap(Product::Php, item_limit(lang));
            return false;
        }
        owned.insert(resolved.clone(), identity);
        let finding = package_finding(t, cx, p, (filename, &resolved), &e.sha256, os);
        t.findings.push(finding);
        t.add_product_scope(Product::Php, format!("/{filename}"));
    }
    true
}

/// 패키지가 소유한 파일을 판정하지 못하는 까닭 — 순서대로 하나만.
fn owned_problem(
    p: &Record,
    resolved: &str,
    e: &super::rootfs::Entry,
    lang: Lang,
) -> Option<String> {
    if !valid_runtime_binary(&e.data, e.size.max(0) as u64) {
        return Some(lang.pick(
            format!("PHP 실행 파일의 머리 또는 파일 범위를 확인하지 못했습니다: /{resolved}"),
            format!(
                "the PHP executable's header or file ranges could not be confirmed: /{resolved}"
            ),
        ));
    }
    if !p.trusted {
        return Some(lang.pick(
            format!("PHP 패키지의 공식 공급사 정보를 확인하지 못했습니다: /{resolved}"),
            format!("the PHP package's official vendor could not be confirmed: /{resolved}"),
        ));
    }
    if let Some(problem) = file_problem(p, resolved, e, lang) {
        return Some(problem);
    }
    if !package_matches_binary(&p.version, &e.data) {
        return Some(lang.pick(
            format!("PHP 패키지 버전과 실행 파일의 버전 정보가 서로 다릅니다: /{resolved}"),
            format!(
                "the PHP package version and the executable's version text differ: /{resolved}"
            ),
        ));
    }
    None
}

/// 패키지가 소유한 파일의 판정. `paths` 는 (패키지 기록의 경로, 링크를 푼 경로).
fn package_finding(
    t: &Target,
    cx: &Cx<'_>,
    p: &Record,
    paths: (&str, &str),
    sha256: &str,
    os: (&str, &str),
) -> crate::scan::model::Finding {
    let lang = cx.lang;
    let (filename, resolved) = paths;
    let mut c = Component::new(Product::Php);
    c.id = format!("{}:{resolved}", t.id);
    c.name = lang.t("PHP 이미지 패키지", "PHP image package").to_string();
    c.path = format!("/{filename}");
    c.version = p.version.clone();
    c.package = p.name.clone();
    (c.distribution, c.distribution_version) = (os.0.to_string(), os.1.to_string());
    c.source = p.source.clone();
    c.runtime = runtime_name(filename).to_string();
    c.trusted = p.trusted;
    c.sha256 = sha256.to_string();
    (c.architecture, c.package_vendor, c.package_module) =
        (p.architecture.clone(), p.vendor.clone(), p.module.clone());
    c.package_manager = manager(p);
    let mut f = cx.rules.evaluate(&c, lang);
    f.evidence.push(Evidence::new(
        p.source.as_str(),
        lang.pick(
            format!("최종 이미지의 패키지 파일 목록에서 /{resolved} 경로를 확인했습니다"),
            format!("the path /{resolved} was found in the final image's package file list"),
        ),
    ));
    if p.rpm {
        f.evidence.push(Evidence::new(
            p.source.as_str(),
            rpm_match_note(p.checksum_algorithm, lang),
        ));
    }
    f
}

/// 패키지 관리자 — RPM 이거나 dpkg `status` 에서 읽은 것.
pub(super) fn manager(p: &Record) -> PackageManager {
    if p.rpm {
        PackageManager::Rpm
    } else if p.source == super::packages::DPKG_SOURCE {
        PackageManager::Dpkg
    } else {
        PackageManager::Unknown
    }
}

/// RPM 기록과 파일이 맞았다는 근거 — 서명을 확인한 것은 아니다.
pub(super) fn rpm_match_note(algorithm: &str, lang: Lang) -> String {
    lang.pick(
        format!("실제 파일의 {algorithm} 이 로컬 RPM DB 기록과 일치합니다. 패키지 서명이나 공급사 출처를 암호학적으로 검증한 결과는 아닙니다"),
        format!("the file's {algorithm} matches the local RPM database record. This is not a cryptographic check of the package signature or vendor origin"),
    )
}

fn item_limit(lang: Lang) -> &'static str {
    lang.t(
        "PHP 판정 항목 4096개 제한을 넘었습니다",
        "the limit of 4096 PHP findings was exceeded",
    )
}

/// 패키지가 소유하지 않은 PHP 실행 파일 이름들 — 센 후보 수를 준다.
fn unowned_files(
    fs: &RootFs,
    t: &mut Target,
    cx: &Cx<'_>,
    owned: &BTreeMap<String, String>,
) -> usize {
    let lang = cx.lang;
    let mut count = 0usize;
    for (name, e) in &fs.entries {
        let skip = e.kind == TYPE_DIR || fs.special(name) || fs.runtime_data_file(name);
        if !is_php_runtime(name) || skip {
            continue;
        }
        count += 1;
        if count > MAX_ITEMS {
            t.add_product_gap(
                Product::Php,
                lang.t(
                    "PHP 후보 파일 4096개 제한을 넘었습니다",
                    "the limit of 4096 PHP candidate files was exceeded",
                ),
            );
            break;
        }
        let resolved = fs.resolve(name);
        if resolved.as_ref().is_ok_and(|(r, _)| owned.contains_key(r)) {
            continue;
        }
        if t.findings.len() >= MAX_ITEMS {
            t.add_product_gap(Product::Php, item_limit(lang));
            break;
        }
        let finding = unowned_finding(t, cx, name, resolved.map_err(|(_, why)| why));
        t.findings.push(finding);
        t.add_product_scope(Product::Php, format!("/{name}"));
    }
    count
}

fn unowned_finding(
    t: &Target,
    cx: &Cx<'_>,
    name: &str,
    resolved: Result<(String, &super::rootfs::Entry), super::rootfs::Unresolved>,
) -> crate::scan::model::Finding {
    let lang = cx.lang;
    let (version, sha256) = match &resolved {
        Ok((_, e)) if e.kind == super::tarball::TYPE_REG => {
            (version_in(&e.data).unwrap_or_default(), e.sha256.clone())
        }
        _ => (String::new(), String::new()),
    };
    let mut c = Component::new(Product::Php);
    c.id = format!("{}:{name}", t.id);
    c.name = lang.t("PHP 이미지 파일", "PHP image file").to_string();
    c.path = format!("/{name}");
    c.version = version.clone();
    c.distribution = UPSTREAM.to_string();
    c.source = static_source(lang).to_string();
    c.runtime = runtime_name(name).to_string();
    c.sha256 = sha256;
    let mut f = cx.rules.evaluate(&c, lang);
    if let Err(why) = resolved {
        f.evidence
            .push(Evidence::new(format!("/{name}"), why.message(lang)));
    }
    if !version.is_empty() {
        f.evidence.push(Evidence::new(
            format!("/{name}"),
            lang.t(
                "바이너리의 버전 문자열은 보조 근거이며, 공식 빌드를 식별하는 근거로 쓰지 않습니다",
                "the version text in the binary is supporting evidence only and does not identify an official build",
            ),
        ));
    }
    f
}

/// 소유자 없는 파일의 근거 출처.
pub(super) fn static_source(lang: Lang) -> &'static str {
    lang.t(
        "이미지 파일의 정적 정보",
        "static information from the image file",
    )
}
