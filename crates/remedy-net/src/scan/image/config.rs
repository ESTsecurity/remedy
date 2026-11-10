//! PHP 세션 설정(CVE-2026-115560) — 이미지에 담긴 PHP 설정 파일을 모아 [`crate::scan::phpconfig::assess`] 에
//! 넘긴다. 스캐너의 `internal/images/phpconfig.go` 를 옮겼다.
//!
//! PHP 를 고른 점검에서만 담고, PHP(파일 또는 패키지)가 있을 때만 판정 항목을 낸다. 설정 파일은 파일당 4 MiB ·
//! 합계 16 MiB · 64개까지만 담는다 — 실행 파일을 담는 한도와 따로 센다. 판정은 늘 *확인 필요* 다(운영 컨테이너의
//! 마운트 · 환경 변수 · 시작 옵션은 이미지에 없다).

use super::packages::Record;
use super::php::is_php_package;
use super::rootfs::RootFs;
use super::source::archive_path;
use super::tarball::TYPE_REG;
use super::Cx;
use crate::scan::model::{Product, Target};
use crate::scan::phpconfig::{assess, Document, CVE};
use crate::scan::slashpath;
use regex::Regex;
use remedy_sdk::i18n::Lang;
use std::sync::OnceLock;

pub(super) const CONFIG_FILE_LIMIT: i64 = 4 << 20;
pub(super) const CONFIG_DATA_LIMIT: i64 = 16 << 20;
pub(super) const MAX_CONFIG_FILES: usize = 64;

fn config_directory() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:^|/)(?:php(?:[0-9]+(?:\.[0-9]+)?)?(?:-fpm)?(?:\.d)?|pool\.d)(?:/|$)")
            .expect("고정된 정규식")
    })
}

/// 이름으로 본 PHP 설정 파일 — `php.ini` · `.user.ini` · `.htaccess` · FPM 설정, PHP 설정 폴더의 `.ini` · `.conf`,
/// Apache 설정 폴더의 `.conf`.
pub(super) fn is_php_config(name: &str) -> bool {
    let name = crate::scan::linuxmeta::lower(name.as_bytes());
    let base = slashpath::base(&name);
    if matches!(base, "php.ini" | ".user.ini" | ".htaccess" | "php-fpm.conf")
        || (base.starts_with("php-fpm") && base.ends_with(".conf"))
    {
        return true;
    }
    if (base.ends_with(".ini") || base.ends_with(".conf")) && config_directory().is_match(&name) {
        return true;
    }
    base.ends_with(".conf")
        && ["etc/apache2/", "etc/httpd/", "usr/local/apache2/conf/"]
            .iter()
            .any(|dir| name.starts_with(dir))
}

/// 이 이름을 PHP 설정으로 담는가 — PHP 를 고른 점검이고, 이름이 설정 파일의 꼴이거나 이미지 설정이 가리킨 파일.
pub(super) fn selected_config(fs: &RootFs, name: &str, products: &[Product]) -> bool {
    products.contains(&Product::Php) && (is_php_config(name) || fs.config_paths.contains(name))
}

/// 이미지 설정의 `PHPRC` · `PHP_INI_DIR` 이 가리키는 설정 파일 — 절대 경로만, 가상 뿌리 안의 이름으로 둔다.
pub(super) fn configure_paths(fs: &mut RootFs, env: &[String]) {
    fs.config_paths.clear();
    for item in env {
        let Some((key, value)) = item.split_once('=') else {
            continue;
        };
        if (key != "PHPRC" && key != "PHP_INI_DIR") || !value.starts_with('/') {
            continue;
        }
        let Ok(name) = archive_path(&value[1..], Lang::En) else {
            continue;
        };
        if name == "." {
            continue;
        }
        let ini = crate::scan::linuxmeta::lower(name.as_bytes()).ends_with(".ini");
        if key == "PHPRC" && ini {
            fs.config_paths.insert(name);
        } else {
            fs.config_paths.insert(slashpath::join(&[&name, "php.ini"]));
        }
    }
}

/// 설정을 모아 판정 항목을 낸다(스캐너의 `inspectPHPConfiguration`).
pub(super) fn inspect(fs: &RootFs, t: &mut Target, cx: &Cx<'_>, packages: &[Record]) {
    if !t.products.contains_key(&Product::Php) {
        return;
    }
    let found = php_found(t) || packages.iter().any(|p| is_php_package(&p.name));
    if !found {
        return;
    }
    let lang = cx.lang;
    let mut issues = vec![
        lang.t(
            "이미지에 저장된 설정이며, 운영 컨테이너의 마운트 · 환경 변수 · 시작 옵션과 실제 적용 상태는 확인하지 못했습니다.",
            "These are the settings stored in the image; the running container's mounts, environment variables, start options and the values in effect were not confirmed.",
        )
        .to_string(),
        lang.t(
            "이미지 밖의 .user.ini 와 include, 시작할 때 만들어지는 설정은 모두 확인하지 못했습니다.",
            "No .user.ini or include outside the image, and no setting generated at start, was confirmed.",
        )
        .to_string(),
    ];
    let docs = documents(fs, t, &mut issues, lang);
    if fs.config_limited {
        issues.push(
            lang.t(
                "설정 파일 수집 한도(파일당 4 MiB, 합계 16 MiB, 64개)에 닿아 일부 내용을 수집하지 못했습니다.",
                "The settings collection limit (4 MiB per file, 16 MiB in total, 64 files) was reached, so some content was not collected.",
            )
            .to_string(),
        );
    }
    append_finding(t, &docs, &issues, true, lang);
    for issue in issues {
        t.add_product_gap(Product::Php, issue);
    }
}

/// 다 담은 설정 파일들 — 64개까지.
fn documents(fs: &RootFs, t: &mut Target, issues: &mut Vec<String>, lang: Lang) -> Vec<Document> {
    let limit = lang.t(
        "설정 파일 판독은 이미지당 64개로 제한했습니다.",
        "Reading settings files is limited to 64 per image.",
    );
    let mut docs = Vec::new();
    let mut checked = 0usize;
    for name in fs.entries.keys() {
        if !selected_config(fs, name, &[Product::Php]) {
            continue;
        }
        checked += 1;
        if checked > MAX_CONFIG_FILES {
            issues.push(limit.to_string());
            break;
        }
        let whole = fs
            .resolve(name)
            .ok()
            .filter(|(_, e)| e.kind == TYPE_REG && !e.truncated && e.data.len() as i64 == e.size);
        let Some((_, e)) = whole else {
            issues.push(lang.pick(
                format!("설정 파일 전체를 확인하지 못했습니다: /{name}"),
                format!("a settings file could not be read whole: /{name}"),
            ));
            continue;
        };
        docs.push(Document {
            path: format!("/{name}"),
            data: e.data.clone(),
        });
        t.add_product_scope(Product::Php, format!("/{name}"));
        if docs.len() >= MAX_CONFIG_FILES {
            issues.push(limit.to_string());
            break;
        }
    }
    docs
}

/// 세션 설정 항목 하나 — PHP 를 고르지 않았거나, PHP 가 없거나(`package_found` 도 아니거나), 이미 있으면 더하지
/// 않는다(스캐너의 `appendPHPConfigFinding`).
pub(super) fn append_finding(
    t: &mut Target,
    docs: &[Document],
    issues: &[String],
    package_found: bool,
    lang: Lang,
) {
    if !t.products.contains_key(&Product::Php) || (!php_found(t) && !package_found) {
        return;
    }
    let id = format!("{}:{CVE}", t.id);
    if t.findings.iter().any(|f| f.id == id) {
        return;
    }
    let finding = assess(&t.id, docs, issues, lang);
    t.findings.push(finding);
}

/// 대상에 PHP 판정이 있는가.
fn php_found(t: &Target) -> bool {
    t.findings.iter().any(|f| f.product == Product::Php)
}
