//! Node.js — 실행 파일과, 그것이 실제로 연결한 Brotli 디코더.
//!
//! 스캐너 `node.go` 를 옮겼다. 실행 파일 후보는 패키지가 소유한 Node.js 파일(dpkg 의 `.list` · apk 의 `R:` · RPM),
//! 주 프로세스의 실행 파일, 컨테이너의 명령에 적힌 경로(이름뿐이면 `PATH` 에서 찾는다)다. **환경 변수(`NODE_VERSION`)만
//! 으로는 Node.js 가 있다고 하지 않는다** — 보조 정보로만 싣는다.
//!
//! 연결된 Brotli 는 실행 파일의 동적 의존(DT_NEEDED)을 따라 패키지가 소유한 파일 가운데 같은 ABI 의 것을 하나로
//! 정할 수 있을 때만 잇는다(`libnode` 를 거쳐 8단계까지). 둘 이상이거나 읽지 못하면 연결을 *확인하지 못함* 으로
//! 둔다. 로더를 바꾸는 환경 변수(`LD_LIBRARY_PATH` · `LD_PRELOAD` · `LD_AUDIT`)가 있으면 연결을 끝까지 보았다고 하지
//! 않는다. 공식 배포본의 해시와 맞는 실행 파일은 Brotli 를 담아 지은 빌드다.

use super::client::{BinaryFile, Client};
use super::files::Subject;
use super::gostr::{cut, lower};
use super::inspect::Inspect;
use super::paths;
use super::php::{container_commands, env_key, evaluate};
use super::process::runtime_paths;
use super::record::record_partial;
use super::rpm::{rpm_file_owners, verify_rpm_container_file, RpmFileCheck};
use crate::scan::binary::{is_brotli_decoder, is_node_runtime};
use crate::scan::container::failure::Failure;
use crate::scan::linuxmeta;
use crate::scan::model::{Evidence, Product, Target};
use crate::scan::rules::{Component, DependencyMode, RuleSet, UPSTREAM};
use crate::scan::slashpath;
use remedy_sdk::i18n::Lang;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Node.js 후보 파일의 상한.
const MAX_CANDIDATES: usize = 4096;
/// `.list` 하나.
const LIST_LIMIT: u64 = 4 << 20;
/// 동적 의존을 따라가는 깊이.
const MAX_DEPTH: usize = 8;

/// 경로 → 그 파일을 소유한 패키지.
pub(crate) type Owners = BTreeMap<String, Component>;
/// 읽은 실행 파일(앞부분은 버린 것) — 같은 파일을 두 번 읽지 않는다.
type Cache = HashMap<String, BinaryFile>;

/// 실행 파일을 읽는 쪽 — 시험은 바이트를 지어 넣는다.
pub(crate) type ReadBinary<'r> = &'r mut dyn FnMut(&str) -> Result<BinaryFile, Failure>;

fn read_cached(
    c: &mut Client<'_>,
    cache: &mut Cache,
    id: &str,
    name: &str,
) -> Result<BinaryFile, Failure> {
    if let Some(hit) = cache.get(name) {
        return Ok(hit.clone());
    }
    let mut file = c.read_binary(id, name)?;
    file.prefix = Vec::new();
    cache.insert(name.to_string(), file.clone());
    Ok(file)
}

/// 고른 제품의 Node.js 를 판정해 대상에 싣는다.
pub(crate) fn scan_node_container(c: &mut Client<'_>, t: &mut Target, s: &Subject<'_>) {
    let lang = c.lang;
    let (id, inspected, rules) = (s.id, s.inspected, s.rules);
    let mut owners = node_file_owners(c, t, id, s.packages, s.package_data, s.distro);
    let (rpm_owners, checks) = rpm_file_owners(c, s.packages, s.rpm);
    for (name, owner) in rpm_owners {
        if matches!(owner.product, Product::Node | Product::Brotli) {
            owners.insert(name, owner);
        }
    }
    let mut candidates: BTreeSet<String> = owners
        .iter()
        .filter(|(name, o)| o.product == Product::Node && is_node_runtime(name))
        .map(|(name, _)| name.clone())
        .collect();
    let (live, runtime_gap) = runtime_paths(c, id, inspected.pid, &[Product::Node]);
    candidates.extend(live);
    if let Some(g) = runtime_gap {
        t.add_product_gap(Product::Node, g);
    }
    let mut cache = Cache::new();
    resolve_commands(c, &mut cache, id, inspected, &mut candidates);
    for value in &inspected.env {
        let (key, hint, _) = cut(value, "=");
        if env_key(c, key, "NODE_VERSION") {
            t.metadata
                .insert("node_version_hint".into(), hint.to_string());
        }
    }
    let ctx = NodeContext {
        id,
        inspected,
        rules,
        owners: &owners,
        checks: &checks,
    };
    judge_candidates(c, t, &mut cache, &ctx, &candidates);
    if candidates.is_empty() {
        let (ko, en) = (
            "Node.js 실행 파일의 정확한 경로를 확인하지 못했습니다.",
            "The exact path of a Node.js executable was not confirmed.",
        );
        t.add_product_gap(Product::Node, lang.t(ko, en));
    }
    let (ko, en) = (
        "개별 파일만 조회하므로 다른 Node.js 설치 경로와 실행 중인 모든 프로세스까지 확인하지는 못합니다.",
        "Only individual files are read, so other Node.js installations and every running process are not all covered.",
    );
    t.add_product_gap(Product::Node, lang.t(ko, en));
}

/// 명령에 적힌 Node.js — 경로면 그대로, 이름뿐이면 `PATH` 의 디렉터리에서 처음 읽히는 것.
fn resolve_commands(
    c: &mut Client<'_>,
    cache: &mut Cache,
    id: &str,
    inspected: &Inspect,
    candidates: &mut BTreeSet<String>,
) {
    let windows = c.windows();
    for command in container_commands(inspected) {
        if !is_node_runtime(&paths::base(&command)) {
            continue;
        }
        if c.valid_path(&command) {
            candidates.insert(command);
            continue;
        }
        if command != paths::base(&command) {
            continue;
        }
        let mut command = command;
        if windows && !lower(&command).ends_with(".exe") {
            command.push_str(".exe");
        }
        for directory in paths::search_path(&inspected.env, windows) {
            let name = paths::join(&directory, &command);
            if !c.valid_path(&name) {
                continue;
            }
            if read_cached(c, cache, id, &name).is_ok() {
                candidates.insert(name);
                break;
            }
            if c.budget.check().is_err() {
                break;
            }
        }
    }
}

/// 판정에 함께 쓰는 것.
struct NodeContext<'x> {
    id: &'x str,
    inspected: &'x Inspect,
    rules: &'x RuleSet,
    owners: &'x Owners,
    checks: &'x HashMap<String, RpmFileCheck>,
}

fn judge_candidates(
    c: &mut Client<'_>,
    t: &mut Target,
    cache: &mut Cache,
    ctx: &NodeContext<'_>,
    candidates: &BTreeSet<String>,
) {
    let lang = c.lang;
    for (i, name) in candidates.iter().enumerate() {
        if i >= MAX_CANDIDATES {
            let (ko, en) = (
                "Node.js 후보 파일 4096개 제한을 넘었습니다.",
                "The limit of 4096 Node.js candidate files was exceeded.",
            );
            t.add_product_gap(Product::Node, lang.t(ko, en));
            break;
        }
        if let Err(halt) = c.budget.check() {
            let why = halt.message(lang);
            let gap = lang.pick(
                format!("Node.js 파일 수집을 멈췄습니다: {why}"),
                format!("Node.js file collection stopped: {why}"),
            );
            t.add_product_gap(Product::Node, gap);
            break;
        }
        let data = match read_cached(c, cache, ctx.id, name) {
            Ok(data) => data,
            Err(e) => {
                let why = e.message(lang);
                let gap = lang.pick(
                    format!("Node.js 파일을 읽지 못했습니다 {name}: {why}"),
                    format!("Could not read the Node.js file {name}: {why}"),
                );
                t.add_product_gap(Product::Node, gap);
                continue;
            }
        };
        judge_one(c, t, cache, ctx, name, &data);
        record_partial(c, t);
    }
}

/// 실행 파일 하나의 발견.
fn judge_one(
    c: &mut Client<'_>,
    t: &mut Target,
    cache: &mut Cache,
    ctx: &NodeContext<'_>,
    name: &str,
    data: &BinaryFile,
) {
    let lang = c.lang;
    let mut component = file_component(t, ctx, name, data, lang);
    let (mode, deps, complete) = {
        let id = ctx.id;
        let mut read = |n: &str| read_cached(c, cache, id, n);
        let mut active = HashSet::new();
        let walk = Walk {
            owners: ctx.owners,
            checks: Some(ctx.checks),
            lang,
        };
        node_container_dependencies(name, data, &walk, &mut read, &mut active, 0)
    };
    component.dependency_mode = mode;
    component.dependencies = deps;
    component.dependencies_complete = complete;
    let loader = ctx.inspected.env.iter().any(|v| {
        v.starts_with("LD_LIBRARY_PATH=")
            || v.starts_with("LD_PRELOAD=")
            || v.starts_with("LD_AUDIT=")
    });
    if loader {
        component.dependencies_complete = false;
        if component.dependency_mode != DependencyMode::Shared {
            component.dependency_mode = DependencyMode::Unknown;
        }
    } else if component.dependency_mode != DependencyMode::Shared
        && ctx.rules.node_hash_version(&component.sha256).is_some()
    {
        component.dependency_mode = DependencyMode::Bundled;
        component.dependencies_complete = true;
    }
    let mut finding = evaluate(ctx.rules, &component, lang);
    if data.info.version.is_some() {
        finding.evidence.push(Evidence::new(
            name,
            lang.t(
                "바이너리 버전 문자열은 보조 정보이며 공식 빌드의 근거로 쓰지 않습니다",
                "the version string in the binary is a hint only and is not used as evidence of an official build",
            ),
        ));
    }
    if let Some(hint) = t
        .metadata
        .get("node_version_hint")
        .filter(|h| !h.is_empty())
    {
        let detail = lang.pick(
            format!("이미지 환경 변수의 보조 정보: {hint}"),
            format!("hint from the image environment variable: {hint}"),
        );
        finding
            .evidence
            .push(Evidence::new("Config.Env:NODE_VERSION", detail));
    }
    t.findings.push(finding);
    t.add_product_scope(Product::Node, name);
    if !component.dependencies_complete {
        t.add_product_gap(
            Product::Node,
            lang.pick(
                format!("Node.js 와 Brotli 의 연결 관계를 확인하지 못했습니다: {name}"),
                format!("The link between Node.js and Brotli was not confirmed: {name}"),
            ),
        );
    }
}

/// 실행 파일의 기본 꼴 — 패키지가 소유했으면 그 기록을 덮는다(RPM 이면 실제 파일과 견준 결과).
fn file_component(
    t: &mut Target,
    ctx: &NodeContext<'_>,
    name: &str,
    data: &BinaryFile,
    lang: Lang,
) -> Component {
    let mut component = Component::new(Product::Node);
    component.id = format!("node-container-file:{name}");
    component.name = lang
        .t("Node.js 실행 파일", "Node.js executable")
        .to_string();
    component.path = name.to_string();
    component.version = data.info.version.clone().unwrap_or_default();
    component.source = format!("container:{}{name}", ctx.id);
    component.runtime = "node".to_string();
    component.sha256 = data.sha256.clone();
    component.distribution = UPSTREAM.to_string();
    let Some(owner) = ctx.owners.get(name) else {
        return component;
    };
    let mut owner = owner.clone();
    if let Some(check) = ctx.checks.get(name) {
        let (verified, problem) = verify_rpm_container_file(&owner, data, check, lang);
        owner = verified;
        component.source = owner.source.clone();
        if let Some(p) = problem {
            t.add_product_gap(Product::Node, format!("{}: {name}", p.message(lang)));
        }
    }
    component.package = owner.package;
    component.version = owner.version;
    component.distribution = owner.distribution;
    component.distribution_version = owner.distribution_version;
    component.trusted = owner.trusted;
    component.architecture = owner.architecture;
    component.package_vendor = owner.package_vendor;
    component.package_module = owner.package_module;
    component.package_manager = owner.package_manager;
    component
}

/// 패키지 기록이 소유한 Node.js · Brotli 파일 — dpkg 는 `info/<패키지>[:<아키텍처>].list`, apk 는 `F:` · `R:` 줄.
pub(crate) fn node_file_owners(
    c: &mut Client<'_>,
    t: &mut Target,
    id: &str,
    packages: &[Component],
    package_data: &[u8],
    distro: &str,
) -> Owners {
    let mut owners = Owners::new();
    match distro {
        "debian" | "ubuntu" => dpkg_owners(c, t, id, packages, &mut owners),
        "alpine" => apk_owners(c, t, packages, package_data, &mut owners),
        _ => {}
    }
    owners
}

/// 소유 기록 하나를 싣는다. 둘 이상의 패키지가 같은 파일을 적었으면 믿지 않는다.
fn add_owner(
    c: &Client<'_>,
    t: &mut Target,
    owners: &mut Owners,
    name: &str,
    component: &Component,
) {
    if !c.valid_path(name) || (!is_node_runtime(name) && !is_brotli_decoder(name)) {
        return;
    }
    let mut component = component.clone();
    if let Some(old) = owners.get(name) {
        if !old.trusted {
            component.trusted = false;
        }
        let differs = old.package != component.package
            || old.version != component.version
            || old.architecture != component.architecture;
        if differs {
            component.trusted = false;
            let gap = c.lang.pick(
                format!("둘 이상의 패키지가 같은 Node.js · Brotli 파일을 소유한다고 적혀 있습니다: {name}"),
                format!("More than one package records owning the same Node.js · Brotli file: {name}"),
            );
            t.add_product_gap(Product::Node, gap);
        }
    }
    owners.insert(name.to_string(), component);
}

fn dpkg_owners(
    c: &mut Client<'_>,
    t: &mut Target,
    id: &str,
    packages: &[Component],
    owners: &mut Owners,
) {
    let lang = c.lang;
    for component in packages
        .iter()
        .filter(|p| matches!(p.product, Product::Node | Product::Brotli))
    {
        let base = format!("/var/lib/dpkg/info/{}", component.package);
        let mut name = format!("{base}.list");
        if !component.architecture.is_empty() {
            if !linuxmeta::valid_package_architecture(&component.architecture) {
                let gap = lang.pick(
                    format!("dpkg 아키텍처 기록이 잘못됐습니다: {}", component.package),
                    format!(
                        "The dpkg architecture record is invalid: {}",
                        component.package
                    ),
                );
                t.add_product_gap(Product::Node, gap);
                continue;
            }
            name = format!("{base}:{}.list", component.architecture);
        }
        let mut data = c.read_metadata(id, &name, LIST_LIMIT);
        if data.as_ref().is_err_and(Failure::is_missing) && !component.architecture.is_empty() {
            name = format!("{base}.list");
            data = c.read_metadata(id, &name, LIST_LIMIT);
        }
        let data = match data {
            Ok(data) => data,
            Err(e) => {
                let why = e.message(lang);
                let gap = lang.pick(
                    format!("Node.js · Brotli 패키지의 파일 목록을 확인하지 못했습니다: {name}: {why}"),
                    format!("Could not check the file list of the Node.js · Brotli package: {name}: {why}"),
                );
                t.add_product_gap(Product::Node, gap);
                continue;
            }
        };
        t.add_product_scope(Product::Node, name.as_str());
        for line in String::from_utf8_lossy(&data).split('\n') {
            add_owner(c, t, owners, line.trim(), component);
        }
    }
}

fn apk_owners(
    c: &Client<'_>,
    t: &mut Target,
    packages: &[Component],
    package_data: &[u8],
    owners: &mut Owners,
) {
    let by_package: HashMap<&str, &Component> =
        packages.iter().map(|p| (p.package.as_str(), p)).collect();
    let text = String::from_utf8_lossy(package_data).replace("\r\n", "\n");
    for paragraph in text.split("\n\n") {
        let package = paragraph
            .split('\n')
            .find_map(|line| line.strip_prefix("P:"))
            .unwrap_or_default();
        let Some(component) = by_package.get(package) else {
            continue;
        };
        let mut dir = "";
        for line in paragraph.split('\n') {
            if let Some(d) = line.strip_prefix("F:") {
                dir = d;
            }
            let Some(file) = line.strip_prefix("R:") else {
                continue;
            };
            if file != slashpath::base(file)
                || file == "."
                || file == ".."
                || file.contains(['\\', '\0'])
            {
                let (ko, en) = (
                    "apk 파일 목록의 경로가 잘못됐습니다.",
                    "A path in the apk file list is invalid.",
                );
                t.add_product_gap(Product::Node, c.lang.t(ko, en));
                continue;
            }
            let joined = slashpath::join(&[dir, file]);
            let name = format!("/{}", joined.strip_prefix('/').unwrap_or(&joined));
            add_owner(c, t, owners, &name, component);
        }
    }
}

/// 의존을 따라갈 때 함께 쓰는 것.
pub(crate) struct Walk<'w> {
    pub(crate) owners: &'w Owners,
    pub(crate) checks: Option<&'w HashMap<String, RpmFileCheck>>,
    pub(crate) lang: Lang,
}

/// 실행 파일이 실제로 연결한 Brotli — 연결 꼴(담아 지음 · 공유 · 모름), 이어진 Brotli 들, 끝까지 보았는가.
pub(crate) fn node_container_dependencies(
    name: &str,
    data: &BinaryFile,
    walk: &Walk<'_>,
    read: ReadBinary<'_>,
    active: &mut HashSet<String>,
    depth: usize,
) -> (DependencyMode, Vec<Component>, bool) {
    let info = &data.info;
    if active.contains(name) || depth > MAX_DEPTH || !info.dependencies_complete {
        return (DependencyMode::Unknown, Vec::new(), false);
    }
    active.insert(name.to_string());
    let mut mode = DependencyMode::Bundled;
    let mut complete = true;
    let mut deps = Vec::new();
    for needed in &info.needed {
        let brotli = is_brotli_decoder(needed);
        if !is_node_runtime(needed) && !brotli {
            continue;
        }
        if brotli {
            mode = DependencyMode::Shared;
        }
        let Some((candidate, linked)) = unique_candidate(data, needed, walk.owners, read) else {
            complete = false;
            continue;
        };
        let mut owner = walk
            .owners
            .get(&candidate)
            .cloned()
            .unwrap_or_else(|| Component::new(Product::Brotli));
        if let Some(check) = walk.checks.and_then(|m| m.get(&candidate)) {
            let (verified, problem) = verify_rpm_container_file(&owner, &linked, check, walk.lang);
            owner = verified;
            complete &= problem.is_none();
        }
        if is_node_runtime(needed) {
            let (child_mode, child_deps, child_complete) =
                node_container_dependencies(&candidate, &linked, walk, read, active, depth + 1);
            complete &= child_complete;
            if child_mode == DependencyMode::Shared {
                mode = DependencyMode::Shared;
            }
            deps.extend(child_deps);
            continue;
        }
        mode = DependencyMode::Shared;
        deps.push(brotli_dependency(
            name, &candidate, &linked, owner, walk.lang,
        ));
    }
    active.remove(name);
    if !complete && mode == DependencyMode::Bundled {
        mode = DependencyMode::Unknown;
    }
    (mode, deps, complete)
}

/// 그 이름의 소유 파일 가운데 같은 ABI 인 것 하나. 읽지 못하거나 의존을 다 읽지 못한 것 · 같은 ABI 둘은 정하지 못함.
fn unique_candidate(
    data: &BinaryFile,
    needed: &str,
    owners: &Owners,
    read: ReadBinary<'_>,
) -> Option<(String, BinaryFile)> {
    let mut found: Option<(String, BinaryFile)> = None;
    for filename in owners.keys().filter(|f| slashpath::base(f) == needed) {
        let child = match read(filename) {
            Ok(child) if child.info.elf.valid() => child,
            _ => return None,
        };
        if !data.info.elf.compatible(&child.info.elf) {
            continue;
        }
        if !child.info.dependencies_complete || found.as_ref().is_some_and(|(f, _)| f != filename) {
            return None;
        }
        found = Some((filename.clone(), child));
    }
    found
}

fn brotli_dependency(
    name: &str,
    candidate: &str,
    linked: &BinaryFile,
    owner: Component,
    lang: Lang,
) -> Component {
    let mut dependency = owner;
    dependency.product = Product::Brotli;
    dependency.name = lang
        .t("연결된 Brotli 디코더", "linked Brotli decoder")
        .to_string();
    dependency.path = candidate.to_string();
    dependency.sha256 = linked.sha256.clone();
    dependency.runtime = "shared-library".to_string();
    let source = dependency.source.clone();
    dependency.source = lang.pick(
        format!("{name} 의 ELF DT_NEEDED → {candidate}; {source}"),
        format!("ELF DT_NEEDED of {name} → {candidate}; {source}"),
    );
    dependency
}
