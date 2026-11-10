//! Node.js — 실행 파일 · `libnode` 와 그것이 실제로 연결한 Brotli 디코더. 스캐너의 `node.go` 를 옮겼다.
//!
//! Node.js 의 판정은 Brotli 를 어떻게 쓰느냐에 달렸다. ELF 의 DT_NEEDED 를 끝까지 읽어 Brotli 디코더를 연결하면
//! *공유* 로 보고, 표준 라이브러리 폴더에서 같은 ABI 의 그 SONAME 파일을 하나로 찾을 때만 그 파일과 소유 패키지로
//! 판정한다(이미지의 로더를 실행하지 않는다). 같은 SONAME 이 둘 이상이거나, 동적 정보가 받은 앞부분 밖에 있거나,
//! 설정의 환경 변수가 로더를 바꾸면 연결을 확인하지 못한 것이다. 연결이 없고 공식 배포본의 해시와 맞으면 Brotli
//! 를 담아 지은 빌드로 본다.

use super::packages::{file_problem, Record};
use super::php::{manager, static_source};
use super::rootfs::{Entry, RootFs};
use super::tarball::{TYPE_DIR, TYPE_REG};
use super::Cx;
use crate::scan::binary::{binary_magic, inspect_node_binary, is_brotli_decoder, is_node_runtime};
use crate::scan::linuxmeta::ElfIdentity;
use crate::scan::model::{Evidence, Finding, Product, Target};
use crate::scan::rules::{Component, DependencyMode, PackageManager, UPSTREAM};
use crate::scan::slashpath;
use regex::Regex;
use remedy_sdk::i18n::Lang;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// 한 대상의 Node.js 후보 파일 수.
const MAX_CANDIDATES: usize = 4096;
/// `libnode` 를 거쳐 따라가는 깊이.
const MAX_DEPTH: usize = 8;

fn node_package_name() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:nodejs(?:-libs)?|node|libnode[0-9]*|nodejs[0-9]+(?:-libs)?)$")
            .expect("고정된 정규식")
    })
}

fn brotli_package_name() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:libbrotli[0-9]*|libbrotli-dec(?:oder)?[0-9]*|brotli(?:-libs)?)$")
            .expect("고정된 정규식")
    })
}

/// Node.js 또는 Brotli 패키지의 이름인가.
pub(super) fn is_node_family(name: &str) -> bool {
    node_package_name().is_match(name) || brotli_package_name().is_match(name)
}

/// 파일을 소유한 패키지 — 판정에 쓰는 칸만.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Owner {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) source: String,
    pub(super) architecture: String,
    pub(super) vendor: String,
    pub(super) module: String,
    pub(super) trusted: bool,
    pub(super) manager: PackageManager,
}

impl Owner {
    pub(super) fn of(p: &Record) -> Owner {
        Owner {
            name: p.name.clone(),
            version: p.version.clone(),
            source: p.source.clone(),
            architecture: p.architecture.clone(),
            vendor: p.vendor.clone(),
            module: p.module.clone(),
            trusted: p.trusted,
            manager: manager(p),
        }
    }

    /// 패키지 칸을 채운다 — 이름 · 버전 · 배포판 · 출처 · 믿음 · RPM 범위.
    fn fill(&self, c: &mut Component, os: (&str, &str)) {
        c.package = self.name.clone();
        c.version = self.version.clone();
        (c.distribution, c.distribution_version) = (os.0.to_string(), os.1.to_string());
        c.source = self.source.clone();
        c.trusted = self.trusted;
        (c.architecture, c.package_vendor, c.package_module) = (
            self.architecture.clone(),
            self.vendor.clone(),
            self.module.clone(),
        );
        c.package_manager = self.manager;
    }
}

/// 파일 → 소유자, 그리고 소유자가 둘 이상인 파일.
#[derive(Debug, Default)]
pub(super) struct Owners {
    pub(super) by_file: BTreeMap<String, Owner>,
    pub(super) conflicts: BTreeSet<String>,
}

impl Owners {
    fn of(&self, file: &str) -> Option<&Owner> {
        self.by_file
            .get(file)
            .filter(|_| !self.conflicts.contains(file))
    }
}

/// Node.js 를 판정한다. `os` 는 배포판의 `(ID, VERSION_ID)`.
pub(super) fn inspect(
    fs: &RootFs,
    t: &mut Target,
    cx: &Cx<'_>,
    packages: &[Record],
    os: (&str, &str),
) {
    let (owners, packaged) = owners(fs, t, cx.lang, packages);
    let links = Links {
        fs,
        owners: &owners,
        os,
        lang: cx.lang,
    };
    let count = candidates(fs, t, cx, &links);
    if packaged > 0 && count == 0 {
        t.add_product_gap(
            Product::Node,
            cx.lang.t(
                "Node.js 패키지 기록은 있으나 최종 이미지의 실행 파일이나 libnode 를 확인하지 못했습니다",
                "there are Node.js package records, but no executable or libnode was found in the final image",
            ),
        );
    }
}

/// 패키지가 소유한 Node.js · Brotli 파일. 기록과 다른 파일의 소유자는 믿지 않는다. Node.js 패키지 수를 함께 준다.
fn owners(fs: &RootFs, t: &mut Target, lang: Lang, packages: &[Record]) -> (Owners, usize) {
    let mut owners = Owners::default();
    let mut packaged = 0;
    for p in packages.iter().filter(|p| is_node_family(&p.name)) {
        packaged += usize::from(node_package_name().is_match(&p.name));
        for name in p
            .files
            .iter()
            .filter(|f| is_node_runtime(f) || is_brotli_decoder(f))
        {
            let Ok((resolved, entry)) = fs.resolve(name) else {
                continue;
            };
            if entry.kind != TYPE_REG {
                continue;
            }
            let mut owner = Owner::of(p);
            if let Some(problem) = file_problem(p, &resolved, entry, lang) {
                owner.trusted = false;
                t.add_product_gap(Product::Node, problem);
            }
            let previous = owners.by_file.get(&resolved);
            let differs = previous.is_some_and(|q| {
                q.name != p.name || q.version != p.version || q.architecture != p.architecture
            });
            if differs {
                owners.conflicts.insert(resolved.clone());
                t.add_product_gap(
                    Product::Node,
                    lang.pick(
                        format!("둘 이상의 패키지가 같은 Node.js 또는 Brotli 파일을 소유한다고 기록돼 있습니다: /{resolved}"),
                        format!("more than one package records owning the same Node.js or Brotli file: /{resolved}"),
                    ),
                );
            }
            owners.by_file.insert(resolved, owner);
        }
    }
    (owners, packaged)
}

/// Node.js 실행 파일 · `libnode` 이름의 항목들 — 센 후보 수를 준다.
fn candidates(fs: &RootFs, t: &mut Target, cx: &Cx<'_>, links: &Links<'_>) -> usize {
    let mut count = 0usize;
    let mut seen = BTreeSet::new();
    for (name, e) in &fs.entries {
        if !is_node_runtime(name) || e.kind == TYPE_DIR || fs.runtime_data_file(name) {
            continue;
        }
        count += 1;
        if count > MAX_CANDIDATES {
            t.add_product_gap(
                Product::Node,
                cx.lang.t(
                    "Node.js 후보 파일 4096개 제한을 넘었습니다",
                    "the limit of 4096 Node.js candidate files was exceeded",
                ),
            );
            break;
        }
        let resolved = fs.resolve(name).map_err(|(_, why)| why);
        if let Ok((r, _)) = &resolved {
            if !seen.insert(r.clone()) {
                continue;
            }
        }
        let (finding, complete) = candidate(t, cx, links, name, resolved);
        if !complete {
            t.add_product_gap(
                Product::Node,
                cx.lang.pick(
                    format!("Node.js 와 Brotli 의 연결 관계를 확인하지 못했습니다: /{name}"),
                    format!("how Node.js links Brotli could not be confirmed: /{name}"),
                ),
            );
        }
        t.findings.push(finding);
        t.add_product_scope(Product::Node, format!("/{name}"));
    }
    count
}

/// 후보 하나의 판정과, 의존을 끝까지 확인했는지.
fn candidate(
    t: &Target,
    cx: &Cx<'_>,
    links: &Links<'_>,
    name: &str,
    resolved: Result<(String, &Entry), super::rootfs::Unresolved>,
) -> (Finding, bool) {
    let lang = cx.lang;
    let mut c = Component::new(Product::Node);
    c.id = format!("node:{}:{name}", t.id);
    c.name = lang
        .t("Node.js 이미지 파일", "Node.js image file")
        .to_string();
    c.path = format!("/{name}");
    c.distribution = UPSTREAM.to_string();
    c.source = static_source(lang).to_string();
    c.runtime = "node".to_string();
    if let Ok((r, entry)) = &resolved {
        if entry.kind == TYPE_REG && !entry.sha256.is_empty() && binary_magic(&entry.data) {
            examine(&mut c, cx, links, r, entry);
        }
    }
    let mut f = cx.rules.evaluate(&c, lang);
    if c.trusted && !c.package_vendor.is_empty() {
        f.evidence.push(Evidence::new(
            c.source.as_str(),
            lang.t(
                "실제 파일의 체크섬이 로컬 RPM DB 기록과 일치합니다. 패키지 서명이나 공급사 출처를 암호학적으로 검증한 결과는 아닙니다",
                "the file's checksum matches the local RPM database record. This is not a cryptographic check of the package signature or vendor origin",
            ),
        ));
    }
    if let Err(why) = resolved {
        f.evidence
            .push(Evidence::new(format!("/{name}"), why.message(lang)));
    }
    if !c.version.is_empty() {
        f.evidence.push(Evidence::new(
            format!("/{name}"),
            lang.t(
                "바이너리의 버전 문자열과 이미지 태그는 보조 정보이며 공식 빌드의 근거로 쓰지 않습니다",
                "the version text in the binary and the image tag are supporting information only, not evidence of an official build",
            ),
        ));
    }
    (f, c.dependencies_complete)
}

/// 실행 파일의 버전 · 해시 · 소유 패키지 · 의존.
fn examine(c: &mut Component, cx: &Cx<'_>, links: &Links<'_>, resolved: &str, entry: &Entry) {
    let info = inspect_node_binary(&entry.data, entry.size.max(0) as u64);
    c.version = info.version.unwrap_or_default();
    c.sha256 = entry.sha256.clone();
    if let Some(owner) = links.owners.of(resolved) {
        owner.fill(c, links.os);
        c.name = cx
            .lang
            .t("Node.js 이미지 패키지", "Node.js image package")
            .to_string();
    }
    let (mode, deps, complete) = links.deps(resolved, &mut BTreeSet::new(), 0);
    (c.dependency_mode, c.dependencies, c.dependencies_complete) = (mode, deps, complete);
    let bundled = cx.rules.node_hash_version(&c.sha256).is_some();
    if !links.fs.loader_override && c.dependency_mode != DependencyMode::Shared && bundled {
        c.dependency_mode = DependencyMode::Bundled;
        c.dependencies_complete = true;
    }
}

/// 연결을 따라가는 데 쓰는 것.
pub(super) struct Links<'a> {
    pub(super) fs: &'a RootFs,
    pub(super) owners: &'a Owners,
    pub(super) os: (&'a str, &'a str),
    pub(super) lang: Lang,
}

impl Links<'_> {
    /// `name` 이 Brotli 를 어떻게 쓰는가 — 방식 · 연결된 Brotli · 끝까지 확인했는지(스캐너의 `nodeDependencies`).
    pub(super) fn deps(
        &self,
        name: &str,
        active: &mut BTreeSet<String>,
        depth: usize,
    ) -> (DependencyMode, Vec<Component>, bool) {
        let unknown = (DependencyMode::Unknown, Vec::new(), false);
        if self.fs.loader_override {
            return unknown;
        }
        let Some(entry) = self.fs.entries.get(name) else {
            return unknown;
        };
        if active.contains(name)
            || depth > MAX_DEPTH
            || entry.kind != TYPE_REG
            || entry.sha256.is_empty()
        {
            return unknown;
        }
        active.insert(name.to_string());
        let result = self.walk(name, entry, active, depth);
        active.remove(name);
        result
    }

    fn walk(
        &self,
        name: &str,
        entry: &Entry,
        active: &mut BTreeSet<String>,
        depth: usize,
    ) -> (DependencyMode, Vec<Component>, bool) {
        let info = inspect_node_binary(&entry.data, entry.size.max(0) as u64);
        if !info.dependencies_complete {
            return (DependencyMode::Unknown, Vec::new(), false);
        }
        let (mut mode, mut complete, mut deps) = (DependencyMode::Bundled, true, Vec::new());
        for needed in &info.needed {
            let brotli = is_brotli_decoder(needed);
            if !brotli && !is_node_runtime(needed) {
                continue;
            }
            if brotli {
                mode = DependencyMode::Shared;
            }
            let Some((resolved, linked)) = self.linked_library(needed, &info.elf) else {
                complete = false;
                continue;
            };
            if !brotli {
                let (child_mode, child_deps, child_complete) =
                    self.deps(&resolved, active, depth + 1);
                complete &= child_complete;
                if child_mode == DependencyMode::Shared {
                    mode = DependencyMode::Shared;
                }
                deps.extend(child_deps);
                continue;
            }
            deps.push(self.brotli(name, &resolved, linked));
        }
        if !complete && mode == DependencyMode::Bundled {
            mode = DependencyMode::Unknown;
        }
        (mode, deps, complete)
    }

    /// 연결된 Brotli 디코더 하나.
    fn brotli(&self, name: &str, resolved: &str, linked: &Entry) -> Component {
        let lang = self.lang;
        let mut c = Component::new(Product::Brotli);
        c.id = format!("{name}:{resolved}");
        c.name = lang
            .t("연결된 Brotli 디코더", "linked Brotli decoder")
            .to_string();
        c.path = format!("/{resolved}");
        c.sha256 = linked.sha256.clone();
        c.distribution = UPSTREAM.to_string();
        c.source = lang.pick(
            format!("/{name} 의 ELF DT_NEEDED"),
            format!("ELF DT_NEEDED of /{name}"),
        );
        c.runtime = "shared-library".to_string();
        if let Some(owner) = self.owners.of(resolved) {
            owner.fill(&mut c, self.os);
        }
        c.source = lang.pick(
            format!("/{name} 의 ELF DT_NEEDED → /{resolved}; {}", c.source),
            format!("ELF DT_NEEDED of /{name} → /{resolved}; {}", c.source),
        );
        if c.trusted && !c.package_vendor.is_empty() {
            c.source.push_str(lang.t(
                "; 파일 체크섬과 로컬 RPM DB 기록 일치(패키지 서명 검증 아님)",
                "; file checksum matches the local RPM database record (not a package signature check)",
            ));
        }
        c
    }

    /// DT_NEEDED 의 SONAME 을 표준 라이브러리 폴더의 파일 하나로(스캐너의 `linkedLibrary`). 같은 ABI 의 다른 파일이
    /// 둘 이상이거나, 하나라도 읽히지 않으면 `None`.
    fn linked_library(&self, soname: &str, identity: &ElfIdentity) -> Option<(String, &Entry)> {
        if !identity.valid() {
            return None;
        }
        let mut found: Option<(String, &Entry)> = None;
        for candidate in self.fs.entries.keys() {
            if slashpath::base(candidate) != soname || !standard_library_path(candidate) {
                continue;
            }
            let (name, entry) = self.fs.resolve(candidate).ok()?;
            if entry.kind != TYPE_REG || entry.sha256.is_empty() {
                return None;
            }
            let info = inspect_node_binary(&entry.data, entry.size.max(0) as u64);
            if !info.elf.valid() {
                return None;
            }
            if !identity.compatible(&info.elf) {
                continue;
            }
            if !info.dependencies_complete || found.as_ref().is_some_and(|(prev, _)| *prev != name)
            {
                return None;
            }
            found = Some((name, entry));
        }
        found
    }
}

/// 표준 라이브러리 폴더이거나 그 바로 아래 폴더의 파일인가.
fn standard_library_path(name: &str) -> bool {
    let dir = slashpath::dir(name);
    [
        "lib",
        "lib64",
        "lib32",
        "libx32",
        "usr/lib",
        "usr/lib64",
        "usr/lib32",
        "usr/libx32",
        "usr/local/lib",
    ]
    .iter()
    .any(|root| {
        dir == *root
            || dir
                .strip_prefix(&format!("{root}/"))
                .is_some_and(|rest| !rest.contains('/'))
    })
}
