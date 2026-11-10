//! RPM — 컨테이너의 패키지 DB 를 읽고, 실행 파일이 그 DB 의 기록과 같은지 본다.
//!
//! 스캐너 `scan.go` 의 `readRPMPackages` 와 `rpm_files.go` 를 옮겼다. DB 는 `remedy_rpmdb::read_untrusted` 로 읽는다
//! — 믿지 못할 입력의 상한(DB 64 MiB · 기록 16 MiB · 기록과 항목 100,000 · 복사 64 MiB · 파생 정보 16 MiB)이 그
//! 안에 있다. 자리는 `/usr/lib/sysimage/rpm` 다음 `/var/lib/rpm`, 이름은 `rpmdb.sqlite` · `Packages` ·
//! `Packages.db` 차례이고, 없는 것(404)만 다음으로 넘어간다 — 다른 실패는 옛 DB 를 고르지 않고 멈춘다. SQLite DB 는
//! 쓰기 로그(`-wal` · `-journal`)가 0 바이트여야 한다.
//!
//! **실행 파일과 기록을 견준다.** 패키지가 그 경로를 제 것으로 적고 있고, 그 파일의 다이제스트(MD5 · SHA-256)가 실제
//! 바이트와 같을 때만 그 패키지의 버전 · 공급사를 믿는다. 로컬 DB 의 일관성일 뿐 패키지 서명을 확인한 것은 아니다.

use super::client::{BinaryFile, Client};
use super::packages::package_product;
use super::paths;
use super::php::{php_module, php_runtime_path};
use crate::scan::binary::{is_brotli_decoder, is_node_runtime};
use crate::scan::model::{Product, Target};
use crate::scan::rules::{Component, PackageManager};
use crate::scan::slashpath;
use remedy_rpmdb::{DigestAlgorithm, RpmDbError};
use remedy_sdk::i18n::Lang;
use std::collections::{BTreeMap, HashMap};

const ROOTS: [&str; 2] = ["/usr/lib/sysimage/rpm", "/var/lib/rpm"];
const NAMES: [&str; 3] = ["rpmdb.sqlite", "Packages", "Packages.db"];
/// `read_untrusted` 가 읽지 않는 알고리즘을 말하는 글 — 그 갈래만 따로 말한다.
const UNSUPPORTED_ALGORITHM: RpmDbError =
    RpmDbError::Format("읽지 않는 파일 다이제스트 알고리즘이다");

/// 패키지 하나(스캐너 `images.RPMPackage`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RpmPackage {
    pub(crate) name: String,
    /// `[epoch:]version-release` — epoch 는 0 보다 클 때만.
    pub(crate) version: String,
    pub(crate) architecture: String,
    pub(crate) vendor: String,
    pub(crate) module: String,
    /// 정리한 상대 경로(`usr/bin/php`).
    pub(crate) files: Vec<String>,
    /// `md5` · `sha256`. 읽지 못했으면 빈 글.
    pub(crate) checksum_algorithm: String,
    pub(crate) checksum_error: Option<RpmProblem>,
    /// 상대 경로 → 소문자 16진 다이제스트.
    pub(crate) checksums: HashMap<String, String>,
}

/// 기록과 파일을 견주지 못한 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RpmProblem {
    Malformed,
    Unsupported,
    Conflicting,
    DuplicatePackage,
    OwnerConflict,
    NotExecutable,
    NoDigest,
    Mismatch,
}

impl RpmProblem {
    pub(crate) fn message(self, lang: Lang) -> &'static str {
        use RpmProblem::*;
        match self {
            Malformed => lang.t(
                "RPM 파일 체크섬 기록의 형식이 잘못됐습니다",
                "the RPM file checksum record is malformed",
            ),
            Unsupported => lang.t(
                "지원하지 않는 RPM 파일 체크섬 알고리즘입니다",
                "the RPM file checksum algorithm is not supported",
            ),
            Conflicting => lang.t(
                "같은 RPM 파일의 체크섬 기록이 서로 다릅니다",
                "the RPM checksum records of the same file differ",
            ),
            DuplicatePackage => lang.t(
                "같은 RPM 패키지 이름과 아키텍처의 설치 기록이 겹칩니다",
                "the install records of one RPM package name and architecture are duplicated",
            ),
            OwnerConflict => lang.t(
                "같은 실제 파일의 RPM 소유 기록이 서로 다릅니다",
                "the RPM ownership records of the same file differ",
            ),
            NotExecutable => lang.t(
                "RPM 이 소유한 파일의 실행 파일 머리를 확인하지 못했습니다",
                "the executable header of the RPM-owned file could not be confirmed",
            ),
            NoDigest => lang.t(
                "RPM 체크섬 기록에 그 실행 파일의 경로가 없습니다",
                "the RPM checksum record has no entry for this executable",
            ),
            Mismatch => lang.t(
                "RPM 파일 체크섬 기록과 실제 파일 내용이 다릅니다",
                "the RPM file checksum record does not match the file's content",
            ),
        }
    }
}

/// 실제 파일 하나에 붙은 RPM 기록.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RpmFileCheck {
    pub(crate) algorithm: String,
    pub(crate) digest: String,
    pub(crate) problem: Option<RpmProblem>,
}

/// 패키지 ID(`container-package:이름:아키텍처`) → 그 기록.
pub(crate) type RpmRecords = HashMap<String, RpmPackage>;

fn gap(t: &mut Target, ko: String, en: String, lang: Lang) {
    t.add_gap(lang.pick(ko, en));
}

/// 패키지 DB 를 찾아 읽는다 — 고른 제품의 패키지와, 그 패키지들의 기록.
pub(crate) fn read_rpm_packages(
    c: &mut Client<'_>,
    t: &mut Target,
    id: &str,
    distro: &str,
    release: &str,
    products: &[Product],
) -> (Vec<Component>, RpmRecords) {
    let lang = c.lang;
    for root in ROOTS {
        for base in NAMES {
            let name = format!("{root}/{base}");
            let data = match c.read_file(id, &name) {
                Ok(data) => data,
                Err(e) => {
                    if c.budget.check().is_err() {
                        return Default::default();
                    }
                    if e.is_missing() {
                        continue;
                    }
                    let why = e.message(lang);
                    let (ko, en) = (
                        format!("RPM 패키지 DB 를 읽지 못했습니다: {name}: {why}"),
                        format!("The RPM package database could not be read: {name}: {why}"),
                    );
                    gap(t, ko, en, lang);
                    return Default::default();
                }
            };
            if base == "rpmdb.sqlite" && !write_log_clean(c, t, id, &name) {
                return Default::default();
            }
            let place = Place {
                id,
                name: &name,
                distro,
                release,
            };
            return parse_database(c, t, &place, &data, products);
        }
    }
    gap(
        t,
        "RPM 패키지 DB 를 읽지 못했습니다.".into(),
        "The RPM package database could not be read.".into(),
        lang,
    );
    Default::default()
}

/// SQLite 의 쓰기 로그 — 비어 있지 않거나 읽지 못하면 DB 의 상태가 일관되다고 할 수 없다. 0 바이트 상한이라 비어
/// 있지 않은 로그는 HEAD 에서 걸린다.
fn write_log_clean(c: &mut Client<'_>, t: &mut Target, id: &str, name: &str) -> bool {
    for suffix in ["-wal", "-journal"] {
        if let Err(e) = c.read_metadata(id, &format!("{name}{suffix}"), 0) {
            if !e.is_missing() {
                let (ko, en) = (
                    format!("RPM DB 의 쓰기 로그가 남아 있거나 로그 상태를 읽지 못해 일관된 패키지 상태를 확인할 수 없습니다: {name}"),
                    format!("The RPM database has a pending write log, or its log could not be read, so a consistent package state cannot be confirmed: {name}"),
                );
                gap(t, ko, en, c.lang);
                return false;
            }
        }
    }
    true
}

/// 읽은 DB 의 자리.
struct Place<'p> {
    id: &'p str,
    name: &'p str,
    distro: &'p str,
    release: &'p str,
}

fn parse_failed(t: &mut Target, detail: Option<(&str, &str)>, lang: Lang) {
    let (ko, en) = match detail {
        Some((ko, en)) => (
            format!("RPM 패키지 DB 를 해석하지 못했습니다: {ko}"),
            format!("The RPM package database could not be parsed: {en}"),
        ),
        None => (
            "RPM 패키지 DB 를 해석하지 못했습니다.".to_string(),
            "The RPM package database could not be parsed.".to_string(),
        ),
    };
    gap(t, ko, en, lang);
}

fn parse_database(
    c: &mut Client<'_>,
    t: &mut Target,
    place: &Place<'_>,
    data: &[u8],
    products: &[Product],
) -> (Vec<Component>, RpmRecords) {
    let lang = c.lang;
    let Ok(read) = remedy_rpmdb::read_untrusted(data) else {
        parse_failed(t, None, lang);
        return Default::default();
    };
    if read.limit.is_some() {
        // 앞의 패키지는 남기고 다 읽지 못했다고 적는다.
        let detail = (
            "상한에 닿아 일부 패키지만 읽었습니다",
            "a limit was reached, so only part of the packages were read",
        );
        parse_failed(t, Some(detail), lang);
    }
    let Some(packages) = read
        .packages
        .into_iter()
        .map(convert)
        .collect::<Option<Vec<_>>>()
    else {
        let detail = (
            "안전하지 않은 파일 경로가 있습니다",
            "it holds an unsafe file path",
        );
        parse_failed(t, Some(detail), lang);
        return Default::default();
    };
    let found = select(c, t, place, packages, products);
    t.add_scope(place.name);
    for p in products {
        t.add_product_scope(*p, place.name);
    }
    found
}

/// 고른 제품의 패키지만 — 패키지마다 항목 하나를 센다.
fn select(
    c: &mut Client<'_>,
    t: &mut Target,
    place: &Place<'_>,
    packages: Vec<RpmPackage>,
    products: &[Product],
) -> (Vec<Component>, RpmRecords) {
    let (mut result, mut records) = (Vec::new(), RpmRecords::new());
    for mut p in packages {
        if c.budget.count_entry().is_err() {
            let (ko, en) = (
                "RPM 패키지 탐색 한도를 넘었습니다.".to_string(),
                "The RPM package search limit was exceeded.".to_string(),
            );
            gap(t, ko, en, c.lang);
            return (result, records);
        }
        let Some(product) = package_product(&p.name, products) else {
            continue;
        };
        let component = rpm_component(product, &p, place, c.lang);
        if records.contains_key(&component.id) {
            p.checksum_error = Some(RpmProblem::DuplicatePackage);
        }
        records.insert(component.id.clone(), p);
        result.push(component);
    }
    (result, records)
}

fn rpm_component(product: Product, p: &RpmPackage, place: &Place<'_>, lang: Lang) -> Component {
    let mut c = Component::new(product);
    c.id = format!("container-package:{}:{}", p.name, p.architecture);
    c.name = lang.t("RPM 패키지", "RPM package").to_string();
    c.path = place.name.to_string();
    c.version = p.version.clone();
    c.package = p.name.clone();
    c.architecture = p.architecture.clone();
    c.package_vendor = p.vendor.clone();
    c.package_module = p.module.clone();
    c.distribution = place.distro.to_string();
    c.distribution_version = place.release.to_string();
    c.source = format!("container:{}{}", place.id, place.name);
    c.runtime = "container".to_string();
    c.package_manager = PackageManager::Rpm;
    c
}

/// `read_untrusted` 의 패키지를 스캐너의 꼴로 — 경로를 정리하고 다이제스트를 경로에 붙인다. 안전하지 않은 경로가
/// 하나라도 있으면 `None`(DB 전체를 믿지 않는다).
pub(crate) fn convert(p: remedy_rpmdb::Package) -> Option<RpmPackage> {
    let h = &p.header;
    let mut version = format!("{}-{}", h.version, h.release);
    if let Some(epoch) = h.epoch.filter(|e| *e > 0) {
        version = format!("{epoch}:{version}");
    }
    // 다이제스트와 같은 차례의 경로 — 뿌리(`/`)는 빈 글로 자리만 지킨다.
    let mut indexed = Vec::with_capacity(p.files.len());
    for recorded in &p.files {
        indexed.push(if recorded == "/" {
            String::new()
        } else {
            package_path(recorded)?
        });
    }
    let files = indexed.iter().filter(|f| !f.is_empty()).cloned().collect();
    let mut out = RpmPackage {
        name: h.name.clone(),
        version,
        architecture: h.arch.clone(),
        vendor: h.vendor.clone(),
        module: p.modularity_label.clone().unwrap_or_default(),
        files,
        ..RpmPackage::default()
    };
    match &p.digests {
        Err(e) => {
            out.checksum_error = Some(if *e == UNSUPPORTED_ALGORITHM {
                RpmProblem::Unsupported
            } else {
                RpmProblem::Malformed
            });
        }
        Ok(d) => attach_digests(&mut out, &indexed, d.algorithm, &d.digests),
    }
    Some(out)
}

fn attach_digests(
    out: &mut RpmPackage,
    indexed: &[String],
    algorithm: DigestAlgorithm,
    digests: &[String],
) {
    out.checksum_algorithm = match algorithm {
        DigestAlgorithm::Md5 => "md5",
        DigestAlgorithm::Sha256 => "sha256",
    }
    .to_string();
    for (file, digest) in indexed.iter().zip(digests) {
        if file.is_empty() || digest.is_empty() {
            continue;
        }
        let digest = digest.to_ascii_lowercase();
        match out.checksums.get(file) {
            Some(previous) if *previous != digest => {
                out.checksum_error = Some(RpmProblem::Conflicting);
                out.checksums.clear();
                return;
            }
            _ => {
                out.checksums.insert(file.clone(), digest);
            }
        }
    }
}

/// 기록된 경로를 상대 경로로 정리한다(스캐너 `packagePath`). 역슬래시 · NUL · 겹친 앞 `/` · 드라이브 · `..` 요소 ·
/// 마지막 요소 `.`(rpm 이 나눠 적는 꼴에서 파일 이름이 `.`) · 4096 바이트를 넘는 경로는 받지 않는다.
fn package_path(recorded: &str) -> Option<String> {
    let rel = recorded.strip_prefix('/').unwrap_or(recorded);
    let drive =
        rel.len() >= 2 && rel.as_bytes()[1] == b':' && rel.as_bytes()[0].is_ascii_alphabetic();
    let unsafe_shape = rel.is_empty()
        || rel.contains(['\\', '\0'])
        || rel.starts_with('/')
        || drive
        || rel.split('/').any(|part| part == "..")
        || rel.rsplit('/').next() == Some(".");
    if unsafe_shape {
        return None;
    }
    let clean = slashpath::clean(rel);
    (clean.len() <= 4096).then_some(clean)
}

/// 실제 파일 경로 → 그것을 소유한 패키지와 기록. 실행 파일 · 라이브러리의 꼴인 경로만 본다(파일마다 항목 하나).
pub(crate) fn rpm_file_owners(
    c: &Client<'_>,
    packages: &[Component],
    records: Option<&RpmRecords>,
) -> (BTreeMap<String, Component>, HashMap<String, RpmFileCheck>) {
    let (mut owners, mut checks) = (BTreeMap::new(), HashMap::new());
    let Some(records) = records else {
        return (owners, checks);
    };
    for component in packages {
        let Some(p) = records.get(&component.id) else {
            continue;
        };
        let mut component = component.clone();
        component.package_manager = PackageManager::Rpm;
        for filename in &p.files {
            if c.budget.check().is_err() {
                return (owners, checks);
            }
            let name = format!("/{}", filename.strip_prefix('/').unwrap_or(filename));
            if !c.valid_path(&name) || !owned_kind(component.product, &name) {
                continue;
            }
            if c.budget.count_entry().is_err() {
                return (owners, checks);
            }
            let mut check = RpmFileCheck {
                algorithm: p.checksum_algorithm.clone(),
                digest: p
                    .checksums
                    .get(filename.trim_start_matches('/'))
                    .cloned()
                    .unwrap_or_default(),
                problem: p.checksum_error,
            };
            let differs = owners.get(&name).is_some_and(|prev: &Component| {
                prev.id != component.id || prev.version != component.version
            });
            if differs {
                check.problem = Some(RpmProblem::OwnerConflict);
            }
            if let Some(problem) = checks
                .get(&name)
                .and_then(|prev: &RpmFileCheck| prev.problem)
            {
                check.problem = Some(problem);
            }
            owners.insert(name.clone(), component.clone());
            checks.insert(name, check);
        }
    }
    (owners, checks)
}

/// 그 제품에서 실제 파일과 견줄 꼴의 경로인가 — PHP 는 실행 파일 · Apache 모듈, 그 밖은 Node.js · Brotli 디코더.
fn owned_kind(product: Product, name: &str) -> bool {
    if product == Product::Php {
        return php_runtime_path(name, false) || php_module(&paths::base(name));
    }
    is_node_runtime(name) || is_brotli_decoder(name)
}

/// 실제 파일이 RPM 기록과 같을 때만 그 패키지를 믿는다 — 같지 않으면 까닭을 준다.
pub(crate) fn verify_rpm_container_file(
    owner: &Component,
    file: &BinaryFile,
    check: &RpmFileCheck,
    lang: Lang,
) -> (Component, Option<RpmProblem>) {
    let mut owner = owner.clone();
    owner.trusted = false;
    let problem = if let Some(p) = check.problem {
        Some(p)
    } else if !file.info.valid {
        Some(RpmProblem::NotExecutable)
    } else if check.digest.is_empty() {
        Some(RpmProblem::NoDigest)
    } else {
        match check.algorithm.as_str() {
            "sha256" => digest_problem(&check.digest, &file.sha256),
            "md5" => digest_problem(&check.digest, &file.md5),
            _ => Some(RpmProblem::Unsupported),
        }
    };
    if problem.is_some() {
        return (owner, problem);
    }
    owner.trusted = true;
    let algorithm = &check.algorithm;
    owner.source.push_str(&lang.pick(
        format!("; 실제 파일의 {algorithm} 이 로컬 RPM DB 기록과 같음(패키지 서명 확인 아님)"),
        format!("; the file's {algorithm} matches the local RPM database record (not a package signature check)"),
    ));
    (owner, None)
}

fn digest_problem(recorded: &str, actual: &str) -> Option<RpmProblem> {
    (actual.is_empty() || !recorded.eq_ignore_ascii_case(actual)).then_some(RpmProblem::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_paths_are_cleaned_like_the_scanner() {
        assert_eq!(package_path("/usr/bin/php").as_deref(), Some("usr/bin/php"));
        assert_eq!(
            package_path("/usr//bin/./php").as_deref(),
            Some("usr/bin/php")
        );
        for bad in [
            "//usr/bin/php",
            "/usr/../bin/php",
            "/a\\b",
            "/C:/php",
            "/usr/bin/.",
            "/",
        ] {
            assert_eq!(package_path(bad), None, "{bad}");
        }
        assert_eq!(package_path(&format!("/{}", "a".repeat(4097))), None);
    }
}
