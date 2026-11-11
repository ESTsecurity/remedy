//! PHP 세션 설정(CVE-2026-115560) — 컨테이너의 설정 파일을 하나씩 읽어 [`crate::scan::phpconfig`] 에 넘긴다.
//!
//! 스캐너 `phpconfig.go`(컨테이너 쪽)를 옮겼다. 설정 파일도 파일 하나 읽기의 같은 관문을 지나고(4 MiB 까지),
//! 컨테이너마다 8개까지다. PHP 를 찾은 대상에서만, 실행 파일 · Node.js 를 다 읽은 뒤에 읽는다 — 설정 조회가 다른
//! 수집의 요청 몫을 먹지 않게.
//!
//! 판정은 늘 *확인 필요* 다. conf.d · FPM 풀 · Apache include · `.user.ini` 의 전체 목록과, 실행 중인 프로세스가
//! 실제로 읽은 설정은 파일 조회만으로 알 수 없다 — 그 한계를 늘 적는다.

use super::client::Client;
use super::files::Subject;
use super::gostr::{cut, fold_eq, lower};
use super::inspect::Inspect;
use super::paths;
use super::php::{container_commands, php_runtime_path};
use super::record::record_partial;
use crate::scan::model::{Product, Target};
use crate::scan::phpconfig::{self, Document};
use crate::scan::rules::Component;
use crate::scan::slashpath;
use regex::Regex;
use remedy_sdk::i18n::Lang;
use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;

/// 설정 파일 하나.
const CONFIG_FILE_LIMIT: u64 = 4 << 20;
/// 컨테이너 하나에서 읽는 설정 파일 수.
const MAX_CONFIG_FILES: usize = 8;

fn env_version() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:^|[^0-9])([5-9])\.([0-9]{1,2})(?:\.|$|[^0-9])").expect("고정된 정규식")
    })
}

fn package_version() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^php([5-9])(?:\.?([0-9]{1,2}))(?:-|$)").expect("고정된 정규식"))
}

/// 설정 파일을 읽고 세션 설정 판정을 싣는다.
pub(crate) fn scan_php_configuration(c: &mut Client<'_>, t: &mut Target, s: &Subject<'_>) {
    let lang = c.lang;
    let (id, inspected, packages, distro) = (s.id, s.inspected, s.packages, s.distro);
    let mut issues = vec![
        lang.t(
            "개별 설정 파일만 조회하므로 conf.d, FPM 풀, Apache include 및 .user.ini 의 전체 목록을 확인하지 못했습니다.",
            "Only individual configuration files are read, so the full lists of conf.d, FPM pools, Apache includes and .user.ini were not confirmed.",
        )
        .to_string(),
        lang.t(
            "실행 중 프로세스가 실제로 읽은 설정과 요청별 설정은 파일 조회만으로 확인할 수 없습니다.",
            "The settings a running process actually read, and per-request settings, cannot be confirmed by reading files.",
        )
        .to_string(),
    ];
    let scope = t
        .products
        .get(&Product::Php)
        .map(|p| p.scope.clone())
        .unwrap_or_default();
    let (mut names, omitted) = php_config_paths(inspected, packages, distro, &scope);
    if omitted {
        issues.push(lang.t(
            "환경 변수에 상대 경로이거나 파일인지 확인할 수 없는 PHPRC 경로가 있어 일부 설정 경로를 확인하지 못했습니다.",
            "An environment variable holds a relative PHPRC path, or one that may not be a file, so some configuration paths were not confirmed.",
        ).to_string());
    }
    if names.len() > MAX_CONFIG_FILES {
        names.truncate(MAX_CONFIG_FILES);
        issues.push(
            lang.t(
                "설정 파일 조회는 컨테이너당 8개로 제한했습니다.",
                "Configuration reads are limited to 8 files per container.",
            )
            .to_string(),
        );
    }
    let docs = read_configs(c, t, id, &names, &mut issues);
    set_php_config_finding(t, &docs, &issues, lang);
    for issue in issues {
        t.add_product_gap(Product::Php, issue);
    }
    record_partial(c, t);
}

fn read_configs(
    c: &mut Client<'_>,
    t: &mut Target,
    id: &str,
    names: &[String],
    issues: &mut Vec<String>,
) -> Vec<Document> {
    let lang = c.lang;
    let mut docs = Vec::new();
    for name in names {
        if let Err(halt) = c.budget.check() {
            let why = halt.message(lang);
            issues.push(lang.pick(
                format!("설정 파일 수집을 멈췄습니다: {why}"),
                format!("Configuration collection stopped: {why}"),
            ));
            break;
        }
        let mut data = Vec::new();
        let read = c.read_regular(id, name, CONFIG_FILE_LIMIT, &mut |r, size| {
            data = vec![0u8; usize::try_from(size).unwrap_or(usize::MAX)];
            r.read_exact(&mut data)
                .map_err(super::archive::content_failure)
        });
        if let Err(e) = read {
            let why = e.message(lang);
            issues.push(lang.pick(
                format!("설정 파일을 확인하지 못했습니다 {name}: {why}"),
                format!("Could not check the configuration file {name}: {why}"),
            ));
            continue;
        }
        docs.push(Document {
            path: name.clone(),
            data,
        });
        t.add_product_scope(Product::Php, name.as_str());
    }
    docs
}

/// PHP 를 고르고 찾은 대상에 세션 설정 판정이 아직 없으면 싣는다.
pub(crate) fn set_php_config_finding(
    t: &mut Target,
    docs: &[Document],
    issues: &[String],
    lang: Lang,
) {
    if !t.products.contains_key(&Product::Php) || !container_php_found(t) {
        return;
    }
    let id = format!("{}:{}", t.id, phpconfig::CVE);
    if t.findings.iter().any(|f| f.id == id) {
        return;
    }
    let finding = phpconfig::assess(&t.id, docs, issues, lang);
    t.findings.push(finding);
}

/// PHP 의 발견이 하나라도 있다.
pub(crate) fn container_php_found(t: &Target) -> bool {
    t.findings.iter().any(|f| f.product == Product::Php)
}

/// 읽어 볼 설정 파일과, 환경 변수 때문에 일부 경로를 확인하지 못했는지.
pub(crate) fn php_config_paths(
    inspected: &Inspect,
    packages: &[Component],
    distro: &str,
    runtime_paths: &[String],
) -> (Vec<String>, bool) {
    if distro == "windows" {
        return windows_php_config_paths(inspected, runtime_paths);
    }
    let mut out = ConfigPaths::default();
    // 같은 키가 여럿이면 뒤의 것(스캐너는 맵에 차례로 담았다).
    let env = |key: &str| {
        inspected
            .env
            .iter()
            .filter_map(|item| item.split_once('='))
            .rfind(|(k, _)| *k == key)
            .map_or("", |(_, v)| v)
    };
    let mut omitted = false;
    let phprc = env("PHPRC");
    if !phprc.is_empty() {
        if !paths::valid_file_path(phprc) {
            omitted = true;
        } else if lower(phprc).ends_with(".ini") {
            out.add(phprc);
        } else {
            // PHPRC 는 파일도 디렉터리도 될 수 있다 — 파일인지 알 수 없으면 그 아래 php.ini 만 묻는다.
            out.add(&slashpath::join(&[phprc, "php.ini"]));
            omitted = true;
        }
    }
    let ini_dir = env("PHP_INI_DIR");
    if !ini_dir.is_empty() {
        if paths::valid_file_path(ini_dir) {
            out.add(&slashpath::join(&[ini_dir, "php.ini"]));
        } else {
            omitted = true;
        }
    }
    if ini_dir == "/usr/local/etc/php" {
        out.add("/usr/local/etc/php-fpm.d/www.conf");
        out.add("/usr/local/etc/php-fpm.conf");
    }
    let versions = config_versions(env("PHP_VERSION"), packages);
    distro_paths(&mut out, distro, &versions);
    for name in [
        "/usr/local/etc/php/php.ini",
        "/usr/local/etc/php-fpm.d/www.conf",
        "/usr/local/etc/php-fpm.conf",
        "/etc/php.ini",
    ] {
        out.add(name);
    }
    (out.list, omitted)
}

/// `X.Y` 들 — 환경 변수의 PHP 버전과 PHP 패키지 이름(`php8.2-cli` · `php83`)에서.
fn config_versions(php_version: &str, packages: &[Component]) -> BTreeSet<String> {
    let mut versions = BTreeSet::new();
    if let Some(m) = env_version().captures(php_version) {
        versions.insert(format!("{}.{}", &m[1], &m[2]));
    }
    for p in packages.iter().filter(|p| p.product == Product::Php) {
        if let Some(m) = package_version().captures(&p.package) {
            versions.insert(format!("{}.{}", &m[1], &m[2]));
        }
    }
    versions
}

fn distro_paths(out: &mut ConfigPaths, distro: &str, versions: &BTreeSet<String>) {
    match distro {
        "debian" | "ubuntu" => {
            for v in versions {
                for name in [
                    "fpm/php.ini",
                    "cli/php.ini",
                    "apache2/php.ini",
                    "fpm/pool.d/www.conf",
                    "fpm/php-fpm.conf",
                ] {
                    out.add(&format!("/etc/php/{v}/{name}"));
                }
            }
            out.add("/etc/apache2/apache2.conf");
        }
        "alpine" => {
            for v in versions {
                let base = format!("/etc/php{}", v.replace('.', ""));
                for name in ["php.ini", "php-fpm.d/www.conf", "php-fpm.conf"] {
                    out.add(&format!("{base}/{name}"));
                }
            }
            out.add("/etc/apache2/httpd.conf");
        }
        _ => {
            for name in [
                "/etc/php.ini",
                "/etc/php-fpm.d/www.conf",
                "/etc/php-fpm.conf",
                "/etc/httpd/conf/httpd.conf",
            ] {
                out.add(name);
            }
        }
    }
}

/// 차례를 지키며 겹치지 않게 모은 경로.
#[derive(Default)]
struct ConfigPaths {
    list: Vec<String>,
    seen: HashSet<String>,
}

impl ConfigPaths {
    fn add(&mut self, name: &str) {
        if paths::valid_file_path(name) && name.len() <= 4096 && self.seen.insert(name.to_string())
        {
            self.list.push(name.to_string());
        }
    }

    fn add_windows(&mut self, name: &str) {
        if paths::valid_windows_file_path(name) && self.seen.insert(paths::key(name)) {
            self.list.push(name.to_string());
        }
    }
}

/// Windows — `PHPRC` · `PHP_INI_DIR`(대소문자 무시), 실행 파일 옆의 php.ini, 기본 자리.
fn windows_php_config_paths(inspected: &Inspect, runtime_paths: &[String]) -> (Vec<String>, bool) {
    let mut out = ConfigPaths::default();
    let mut omitted = false;
    for item in &inspected.env {
        let (key, value, _) = cut(item, "=");
        let phprc = fold_eq(key, "PHPRC");
        if !phprc && !fold_eq(key, "PHP_INI_DIR") {
            continue;
        }
        let drive_root = value.len() == 3 && paths::windows_drive_path(value);
        if !paths::valid_windows_file_path(value) && !drive_root {
            omitted = true;
            continue;
        }
        if phprc && lower(value).ends_with(".ini") {
            out.add_windows(value);
        } else {
            out.add_windows(&paths::join(value, "php.ini"));
            omitted = omitted || phprc;
        }
    }
    let commands = container_commands(inspected);
    for name in commands.iter().chain(runtime_paths) {
        if paths::valid_windows_file_path(name) && php_runtime_path(name, true) {
            out.add_windows(&paths::join(&paths::dir(name), "php.ini"));
        }
    }
    out.add_windows(r"C:\php\php.ini");
    (out.list, omitted)
}
