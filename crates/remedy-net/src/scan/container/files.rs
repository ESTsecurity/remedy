//! 컨테이너 하나의 파일 — 배포판 · 패키지 기록 · PHP · Node.js · 세션 설정의 차례(스캐너 `scanContainerFiles`).
//!
//! 리눅스 엔진은 배포판 기록(os-release 와 옛 꼴 일곱)을 64 KiB 까지 읽어 배포판을 정하고, 그 배포판의 패키지
//! DB(dpkg · apk · RPM)를 읽는다. Windows 엔진은 패키지 DB 를 보지 않는다. Hyper-V 격리의 Windows 컨테이너는 파일
//! 조회 API 를 쓸 수 없어 요청하지 않는다. 마운트가 있으면 그 경계 안은 읽지 않고, 디렉터리 링크를 거친 마운트는 알
//! 수 없다고 적는다.

use super::client::Client;
use super::failure::Policy;
use super::gostr::fold_eq;
use super::inspect::Inspect;
use super::node::scan_node_container;
use super::packages::{parse_apk, parse_dpkg};
use super::php::scan_php_container;
use super::phpconf::{container_php_found, scan_php_configuration};
use super::rpm::{read_rpm_packages, RpmRecords};
use crate::scan::linuxmeta::{parse_release, RELEASE_FILES};
use crate::scan::model::{Product, Target};
use crate::scan::rules::{Component, RuleSet};

/// 배포판 기록 하나의 상한.
const RELEASE_LIMIT: u64 = 64 << 10;
const RPM_DISTROS: [&str; 12] = [
    "rhel",
    "redhat",
    "centos",
    "ol",
    "rocky",
    "almalinux",
    "fedora",
    "sles",
    "sled",
    "opensuse",
    "opensuse-leap",
    "opensuse-tumbleweed",
];

/// 컨테이너 하나를 판정할 때 함께 쓰는 것.
pub(crate) struct Subject<'x> {
    pub(crate) id: &'x str,
    pub(crate) inspected: &'x Inspect,
    pub(crate) rules: &'x RuleSet,
    /// 고른 제품의 패키지 기록(PHP · Node.js · Brotli).
    pub(crate) packages: &'x [Component],
    /// apk `installed` 의 바이트 — Node.js 의 파일 소유를 다시 읽는다.
    pub(crate) package_data: &'x [u8],
    /// 배포판 식별자 · `windows` · 빈 글.
    pub(crate) distro: &'x str,
    pub(crate) rpm: Option<&'x RpmRecords>,
}

/// 고른 제품의 파일을 읽어 판정을 싣는다. 대상은 아직 올리지 않는다.
pub(crate) fn scan_container_files(
    c: &mut Client<'_>,
    t: &mut Target,
    id: &str,
    inspected: &Inspect,
    rules: &RuleSet,
    products: &[Product],
) {
    let products = if products.is_empty() {
        &[Product::Php][..]
    } else {
        products
    };
    t.init_products(products);
    c.mounts.insert(id.to_string(), inspected.mounts.clone());
    if inspected.mounts.iter().any(|m| m.kind != "npipe") {
        let (ko, en) = (
            "디렉터리 링크를 거친 마운트 연결과 점검 중 경로 변경은 확인하지 못했습니다.",
            "Mounts reached through directory links, and path changes during the check, were not confirmed.",
        );
        for p in products {
            t.add_product_gap(*p, c.lang.t(ko, en));
        }
    }
    if c.windows() {
        windows_files(c, t, id, inspected, rules, products);
    } else {
        linux_files(c, t, id, inspected, rules, products);
    }
}

fn selected(t: &Target, product: Product) -> bool {
    t.products.contains_key(&product)
}

fn windows_files(
    c: &mut Client<'_>,
    t: &mut Target,
    id: &str,
    inspected: &Inspect,
    rules: &RuleSet,
    products: &[Product],
) {
    t.metadata.insert("distribution".into(), "windows".into());
    t.metadata.insert("engine_os".into(), "windows".into());
    t.metadata
        .insert("container_isolation".into(), inspected.isolation.clone());
    if fold_eq(&inspected.isolation, "hyperv") {
        let (ko, en) = (
            "실행 중인 Hyper-V 격리 Windows 컨테이너는 Docker 의 개별 파일 조회 API 가 지원되지 않습니다.",
            "Docker's file API is not supported for a running Windows container with Hyper-V isolation.",
        );
        for p in products {
            t.add_product_gap(*p, c.lang.t(ko, en));
        }
        return;
    }
    let s = Subject {
        id,
        inspected,
        rules,
        packages: &[],
        package_data: &[],
        distro: "windows",
        rpm: None,
    };
    if selected(t, Product::Php) {
        scan_php_container(c, t, &s);
    }
    if archive_failure_gap(c, t, id, products) {
        return;
    }
    if selected(t, Product::Node) {
        scan_node_container(c, t, &s);
    }
    if archive_failure_gap(c, t, id, products) {
        return;
    }
    if selected(t, Product::Php) && container_php_found(t) {
        scan_php_configuration(c, t, &s);
    }
}

/// 앞서 Windows 파일 조회가 5xx 를 냈으면 그 까닭을 제품마다 적고 그만둔다.
fn archive_failure_gap(c: &Client<'_>, t: &mut Target, id: &str, products: &[Product]) -> bool {
    let Some(status) = c.archive_failure(id) else {
        return false;
    };
    let why = super::failure::Failure::Policy(Policy::WindowsArchive(status)).message(c.lang);
    for p in products {
        t.add_product_gap(*p, why.clone());
    }
    true
}

fn linux_files(
    c: &mut Client<'_>,
    t: &mut Target,
    id: &str,
    inspected: &Inspect,
    rules: &RuleSet,
    products: &[Product],
) {
    let (distro, release) = detect_release(c, t, id, products);
    if distro.is_empty() {
        let (ko, en) = (
            "지원되는 배포판 식별 기록을 읽거나 해석하지 못했습니다.",
            "No supported distribution record could be read or parsed.",
        );
        t.add_gap(c.lang.t(ko, en));
    }
    t.metadata.insert("distribution".into(), distro.clone());
    t.metadata
        .insert("distribution_version".into(), release.clone());
    let (packages, package_data, rpm) = read_packages(c, t, id, &distro, &release, products);
    let s = Subject {
        id,
        inspected,
        rules,
        packages: &packages,
        package_data: &package_data,
        distro: &distro,
        rpm: rpm.as_ref(),
    };
    if selected(t, Product::Php) {
        scan_php_container(c, t, &s);
    }
    if selected(t, Product::Node) {
        scan_node_container(c, t, &s);
    }
    if selected(t, Product::Php) && container_php_found(t) {
        scan_php_configuration(c, t, &s);
    }
}

/// 배포판 — 앞선 기록이 우선이고, 읽지 못했거나 꼴이 어긋난 기록은 건너뛴다.
fn detect_release(
    c: &mut Client<'_>,
    t: &mut Target,
    id: &str,
    products: &[Product],
) -> (String, String) {
    for name in RELEASE_FILES {
        let Ok(data) = c.read_metadata(id, name, RELEASE_LIMIT) else {
            continue;
        };
        let Some(found) = parse_release(name, &data) else {
            continue;
        };
        t.add_scope(name);
        for p in products {
            t.add_product_scope(*p, name);
        }
        return found;
    }
    (String::new(), String::new())
}

/// 배포판의 패키지 기록 — 고른 제품의 패키지, (apk 면) DB 의 바이트, (RPM 이면) 패키지의 기록.
fn read_packages(
    c: &mut Client<'_>,
    t: &mut Target,
    id: &str,
    distro: &str,
    release: &str,
    products: &[Product],
) -> (Vec<Component>, Vec<u8>, Option<RpmRecords>) {
    let lang = c.lang;
    let name = match distro {
        "debian" | "ubuntu" => "/var/lib/dpkg/status",
        "alpine" => "/lib/apk/db/installed",
        d if RPM_DISTROS.contains(&d) => {
            let (packages, records) = read_rpm_packages(c, t, id, distro, release, products);
            return (packages, Vec::new(), Some(records));
        }
        _ => {
            let (ko, en) = (
                "배포판 정보가 없거나, 명령을 실행하지 않고는 이 배포판의 패키지 DB 를 해석할 수 없습니다.",
                "There is no distribution information, or this distribution's package database cannot be read without running a command.",
            );
            t.add_gap(lang.t(ko, en));
            return (Vec::new(), Vec::new(), None);
        }
    };
    let data = match c.read_file(id, name) {
        Ok(data) => data,
        Err(e) => {
            let why = e.message(lang);
            t.add_gap(lang.pick(
                format!("설치 패키지 정보를 읽지 못했습니다: {why}"),
                format!("The installed package information could not be read: {why}"),
            ));
            return (Vec::new(), Vec::new(), None);
        }
    };
    let source = format!("container:{id}{name}");
    let packages = if distro == "alpine" {
        parse_apk(&data, release, &source, products, lang)
    } else {
        parse_dpkg(&data, distro, release, &source, products, lang)
    };
    t.add_scope(name);
    for p in products {
        t.add_product_scope(*p, name);
    }
    (packages, data, None)
}
