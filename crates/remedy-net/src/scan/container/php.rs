//! PHP — 패키지 기록 · 이미지의 환경 변수 · 실행 파일을 판정한다.
//!
//! 스캐너 `scan.go` 의 `scanPHPContainer` · `phpContainerPaths` 와 `php_windows_core.go` 를 옮겼다.
//!
//! - **패키지 기록만으로 양호를 내지 않는다.** 수정 버전의 패키지 기록이어도 실제 파일과 이어 보지 못했으면 *확인
//!   필요* 로 내린다. 미수정 기록은 취약으로 남는다.
//! - **실행 파일**은 정확한 경로로만 읽는다 — 컨테이너의 명령에 적힌 경로, 공식 PHP 이미지의 알려진 자리(그 이미지의
//!   단서가 있을 때), `PATH` 와 알려진 디렉터리에 이름을 이은 자리, RPM 이 소유한 자리, 주 프로세스의 실행 파일. 후보는
//!   64개까지다.
//! - **Windows** 는 실행 파일과 같은 폴더의 코어 DLL(`php8.dll` …)까지 본다 — 코어를 확인하지 못하면 실행 파일의 양호도
//!   *확인 필요* 로 내린다.
//! - 개별 파일만 읽으므로 다른 설치 자리 · Apache 모듈 · FPM 작업자를 다 보았다고 하지 않는다 — 그 한계를 늘 적는다.

use super::client::Client;
use super::files::Subject;
use super::gostr::{cut, fold_eq, lower};
use super::inspect::Inspect;
use super::paths;
use super::process::runtime_paths;
use super::record::record_partial;
use super::rpm::{rpm_file_owners, verify_rpm_container_file};
use crate::scan::model::{Evidence, Product, Status, Target};
use crate::scan::rules::{Component, RuleSet};
use regex::Regex;
use remedy_sdk::i18n::Lang;
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

/// PHP 후보 경로의 상한.
const MAX_CANDIDATES: usize = 64;
/// Windows 의 PHP 코어 DLL — 실행 파일과 같은 폴더에서 찾는다.
const WINDOWS_CORES: [&str; 6] = [
    "php8.dll",
    "php8ts.dll",
    "php7.dll",
    "php7ts.dll",
    "php5.dll",
    "php5ts.dll",
];

fn php_executable() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:php(?:[0-9]+(?:\.[0-9]+)?)?(?:-cgi|-fpm)?|php-fpm[0-9]+(?:\.[0-9]+)?)$")
            .expect("고정된 정규식")
    })
}

fn php_container_module() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:libphp[0-9.]*(?:\.so(?:\.[0-9]+)*)|mod_php[0-9.]*\.so)$")
            .expect("고정된 정규식")
    })
}

fn binary_version() -> &'static regex::bytes::Regex {
    static RE: OnceLock<regex::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::bytes::Regex::new(r"(?-u)PHP[/ ]([0-9]+\.[0-9]+\.[0-9]+)").expect("고정된 정규식")
    })
}

/// 이름이 PHP 실행 파일의 꼴이다(`php` · `php8.3` · `php-fpm` · `php-cgi` …).
pub(crate) fn php_executable_name(name: &str) -> bool {
    php_executable().is_match(name)
}

/// 이름이 PHP 의 Apache 모듈 · 공유 라이브러리의 꼴이다.
pub(crate) fn php_module(name: &str) -> bool {
    php_container_module().is_match(name)
}

/// 경로의 마지막 요소가 PHP 실행 파일의 꼴이다 — Windows 는 대소문자를 가리지 않고 `.exe` 를 뗀다.
pub(crate) fn php_runtime_path(name: &str, windows: bool) -> bool {
    let mut base = paths::base(name);
    if windows {
        base = lower(&base);
        if let Some(stem) = base.strip_suffix(".exe") {
            base = stem.to_string();
        }
    }
    php_executable_name(&base)
}

/// 컨테이너가 실행하는 명령의 낱말들 — 경로 · 진입점 · 명령 · 인자 차례. 인자의 수는 JSON 상한이 막는다.
pub(crate) fn container_commands(inspected: &Inspect) -> Vec<String> {
    let mut commands = vec![inspected.path.clone()];
    commands.extend(inspected.entrypoint.iter().cloned());
    commands.extend(inspected.cmd.iter().cloned());
    commands.extend(inspected.args.iter().cloned());
    commands
}

/// 그 환경 변수의 키인가 — Windows 엔진이면 대소문자를 가리지 않는다.
pub(crate) fn env_key(c: &Client<'_>, key: &str, wanted: &str) -> bool {
    key == wanted || (c.windows() && fold_eq(key, wanted))
}

/// 읽을 PHP 후보 하나 — `explicit` 은 명령 · RPM · 프로세스가 가리킨 자리라 못 읽으면 그 사실을 적는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) name: String,
    pub(crate) explicit: bool,
}

struct Candidates<'c> {
    client: &'c Client<'c>,
    list: Vec<Candidate>,
    seen: HashSet<String>,
}

impl Candidates<'_> {
    fn add(&mut self, name: &str, explicit: bool) {
        if self.client.valid_path(name)
            && self.list.len() < MAX_CANDIDATES
            && self.seen.insert(paths::key(name))
        {
            self.list.push(Candidate {
                name: name.to_string(),
                explicit,
            });
        }
    }
}

/// 명령 · 환경에서 고른 PHP 후보(64개까지).
pub(crate) fn php_container_paths(c: &Client<'_>, inspected: &Inspect) -> Vec<Candidate> {
    let mut found = Candidates {
        client: c,
        list: Vec::new(),
        seen: HashSet::new(),
    };
    let windows = c.windows();
    let commands = container_commands(inspected);
    let mut hint = inspected
        .env
        .iter()
        .any(|v| env_key(c, cut(v, "=").0, "PHP_VERSION"));
    for name in &commands {
        if paths::base(name) == "docker-php-entrypoint" {
            hint = true;
        }
        if php_runtime_path(name, windows) && c.valid_path(name) {
            found.add(name, true);
        }
    }
    if hint {
        let known: &[&str] = if windows {
            &[r"C:\php\php.exe", r"C:\php\php-cgi.exe"]
        } else {
            &[
                "/usr/local/bin/php",
                "/usr/local/sbin/php-fpm",
                "/usr/local/bin/php-cgi",
                "/usr/local/lib/libphp.so",
                "/usr/lib/apache2/modules/libphp.so",
            ]
        };
        for name in known {
            found.add(name, false);
        }
    }
    for name in &commands {
        if !php_runtime_path(name, windows) || *name != paths::base(name) {
            continue;
        }
        let mut name = name.clone();
        if windows && !lower(&name).ends_with(".exe") {
            name.push_str(".exe");
        }
        for directory in paths::search_path(&inspected.env, windows) {
            found.add(&paths::join(&directory, &name), false);
        }
        // `PATH` 가 없는 inspect 에도 들어맞는 알려진 자리.
        let dirs: &[&str] = if windows {
            &[r"C:\php"]
        } else {
            &["/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin"]
        };
        for directory in dirs {
            found.add(&paths::join(directory, &name), false);
        }
    }
    found.list
}

/// 판정 — 규칙에 맡긴다.
pub(crate) fn evaluate(rules: &RuleSet, c: &Component, lang: Lang) -> crate::scan::model::Finding {
    rules.evaluate(c, lang)
}

/// PHP 를 판정해 대상에 싣는다.
pub(crate) fn scan_php_container(c: &mut Client<'_>, t: &mut Target, s: &Subject<'_>) {
    let lang = c.lang;
    let (id, inspected, rules) = (s.id, s.inspected, s.rules);
    package_findings(c, t, rules, s.packages);
    env_findings(c, t, inspected, rules);
    let mut paths = php_container_paths(c, inspected);
    let (owners, checks) = rpm_file_owners(c, s.packages, s.rpm);
    for (name, _) in owners.iter().filter(|(_, o)| o.product == Product::Php) {
        if paths.len() >= MAX_CANDIDATES {
            let (ko, en) = (
                "PHP 후보 경로 64개 제한을 넘었습니다.",
                "The limit of 64 PHP candidate paths was exceeded.",
            );
            t.add_product_gap(Product::Php, lang.t(ko, en));
            break;
        }
        paths.push(Candidate {
            name: name.clone(),
            explicit: true,
        });
    }
    let (live, runtime_gap) = runtime_paths(c, id, inspected.pid, &[Product::Php]);
    paths.extend(live.into_iter().map(|name| Candidate {
        name,
        explicit: true,
    }));
    if let Some(g) = runtime_gap {
        t.add_product_gap(Product::Php, g);
    }
    let ctx = FileContext {
        id,
        rules,
        owners: &owners,
        checks: &checks,
    };
    let executables = read_candidates(c, t, &ctx, &paths);
    if c.windows() {
        scan_windows_php_core(c, t, id, rules, &executables);
    }
    let (ko, en) = (
        "개별 파일만 조회하므로 다른 PHP 설치 경로와 Apache 모듈까지 모두 확인하지는 못합니다.",
        "Only individual files are read, so other PHP installations and Apache modules are not all covered.",
    );
    t.add_product_gap(Product::Php, lang.t(ko, en));
}

/// 패키지 기록의 판정 — 양호는 *확인 필요* 로 내린다(실제 파일과 이어 보지 않았다).
fn package_findings(c: &Client<'_>, t: &mut Target, rules: &RuleSet, packages: &[Component]) {
    let lang = c.lang;
    for component in packages.iter().filter(|p| p.product == Product::Php) {
        let mut finding = evaluate(rules, component, lang);
        if finding.status == Status::Clear {
            finding.status = Status::ReviewRequired;
            finding.reason = lang
                .t(
                    "수정 버전의 PHP 패키지 기록은 있지만 실제 파일과의 연결을 확인하지 못했습니다.",
                    "There is a record of a fixed PHP package, but its link to the actual files was not confirmed.",
                )
                .to_string();
            finding.action = lang
                .t(
                    "컨테이너 담당자가 실제 PHP 실행 파일과 패키지의 파일 검증 기록을 대조하십시오.",
                    "Have the container owner compare the actual PHP executable with the package's file verification record.",
                )
                .to_string();
            finding.evidence.push(Evidence::new(
                component.source.as_str(),
                lang.t(
                    "설치 패키지 기록과 컨테이너의 실제 PHP 파일을 대조한 근거가 없습니다.",
                    "There is no evidence comparing the installed package record with the container's actual PHP files.",
                ),
            ));
        }
        t.findings.push(finding);
        record_partial(c, t);
    }
}

/// 이미지의 `PHP_VERSION` — 믿지 않는 단서로만 판정에 넣는다.
fn env_findings(c: &Client<'_>, t: &mut Target, inspected: &Inspect, rules: &RuleSet) {
    let lang = c.lang;
    for value in &inspected.env {
        let (key, hint, _) = cut(value, "=");
        if !env_key(c, key, "PHP_VERSION") {
            continue;
        }
        let mut component = Component::new(Product::Php);
        component.id = "container-env".to_string();
        component.name = lang
            .t("PHP 이미지 환경 변수", "PHP image environment variable")
            .to_string();
        component.path = "Config.Env:PHP_VERSION".to_string();
        component.version = hint.to_string();
        component.source = "container inspect".to_string();
        component.runtime = "container".to_string();
        t.findings.push(evaluate(rules, &component, lang));
        record_partial(c, t);
    }
}

/// 실행 파일을 읽는 데 함께 쓰는 것.
struct FileContext<'x> {
    id: &'x str,
    rules: &'x RuleSet,
    owners: &'x BTreeMap<String, Component>,
    checks: &'x std::collections::HashMap<String, super::rpm::RpmFileCheck>,
}

/// 후보를 차례로 읽어 판정한다. Windows 면 폴더마다 실행 파일 발견의 자리를 모아 돌려준다.
fn read_candidates(
    c: &mut Client<'_>,
    t: &mut Target,
    ctx: &FileContext<'_>,
    paths: &[Candidate],
) -> BTreeMap<String, Vec<usize>> {
    let lang = c.lang;
    let mut seen = HashSet::new();
    let mut executables: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut found = false;
    for candidate in paths {
        if !seen.insert(paths::key(&candidate.name)) {
            continue;
        }
        if let Err(halt) = c.budget.check() {
            let why = halt.message(lang);
            let gap = lang.pick(
                format!("PHP 파일 수집을 멈췄습니다: {why}"),
                format!("PHP file collection stopped: {why}"),
            );
            t.add_product_gap(Product::Php, gap);
            break;
        }
        let name = &candidate.name;
        let data = match c.read_binary(ctx.id, name) {
            Ok(data) => data,
            Err(e) => {
                if candidate.explicit {
                    let why = e.message(lang);
                    let gap = lang.pick(
                        format!("PHP 파일을 읽지 못했습니다 {name}: {why}"),
                        format!("Could not read the PHP file {name}: {why}"),
                    );
                    t.add_product_gap(Product::Php, gap);
                }
                continue;
            }
        };
        found = true;
        let component = file_component(c, t, ctx, name, &data);
        t.findings.push(evaluate(ctx.rules, &component, lang));
        if c.windows() {
            executables
                .entry(paths::dir(name))
                .or_default()
                .push(t.findings.len() - 1);
        }
        t.add_product_scope(Product::Php, name.as_str());
        record_partial(c, t);
    }
    if !found {
        let (ko, en) = (
            "실행 중 PHP 파일의 정확한 경로를 확인하지 못했습니다.",
            "The exact path of a running PHP file was not confirmed.",
        );
        t.add_product_gap(Product::Php, lang.t(ko, en));
    }
    executables
}

/// 읽은 실행 파일 하나 — 이름 · 실행 꼴 · 버전 글자, RPM 이 소유했으면 그 기록과 견준 결과.
fn file_component(
    c: &Client<'_>,
    t: &mut Target,
    ctx: &FileContext<'_>,
    name: &str,
    data: &super::client::BinaryFile,
) -> Component {
    let lang = c.lang;
    let version = binary_version()
        .captures(&data.prefix)
        .and_then(|m| m.get(1))
        .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
        .unwrap_or_default();
    let (label, runtime) = if php_module(&paths::base(name)) {
        (lang.t("PHP Apache 모듈", "PHP Apache module"), "mod_php")
    } else if name == "/usr/local/lib/libphp.so" {
        (
            lang.t("PHP 공유 라이브러리", "PHP shared library"),
            "libphp",
        )
    } else {
        (lang.t("PHP 실행 파일", "PHP executable"), "container")
    };
    let mut component = Component::new(Product::Php);
    component.id = format!("container-file:{name}");
    component.name = label.to_string();
    component.path = name.to_string();
    component.version = version;
    component.source = format!("container:{}{name}", ctx.id);
    component.runtime = runtime.to_string();
    component.sha256 = data.sha256.clone();
    if let Some(owner) = ctx.owners.get(name) {
        let check = ctx.checks.get(name).cloned().unwrap_or_default();
        let (verified, problem) = verify_rpm_container_file(owner, data, &check, lang);
        component.package = verified.package;
        component.version = verified.version;
        component.distribution = verified.distribution;
        component.distribution_version = verified.distribution_version;
        component.source = verified.source;
        component.trusted = verified.trusted;
        component.architecture = verified.architecture;
        component.package_vendor = verified.package_vendor;
        component.package_module = verified.package_module;
        component.package_manager = verified.package_manager;
        if let Some(p) = problem {
            t.add_product_gap(Product::Php, format!("{}: {name}", p.message(lang)));
        }
    }
    component
}

/// Windows — 실행 파일이 있던 폴더마다 코어 DLL 을 읽는다. 판정이 나온 코어가 없으면 그 폴더의 실행 파일의 양호를
/// *확인 필요* 로 내린다.
pub(crate) fn scan_windows_php_core(
    c: &mut Client<'_>,
    t: &mut Target,
    id: &str,
    rules: &RuleSet,
    executables: &BTreeMap<String, Vec<usize>>,
) {
    let lang = c.lang;
    for (directory, indexes) in executables {
        let mut known = false;
        for filename in WINDOWS_CORES {
            let name = paths::join(directory, filename);
            let Ok(data) = c.read_binary(id, &name) else {
                continue;
            };
            let mut component = Component::new(Product::Php);
            component.id = format!("container-file:{name}");
            component.name = lang.t("PHP 코어 DLL", "PHP core DLL").to_string();
            component.path = name.clone();
            component.source = format!("container:{id}{name}");
            component.runtime = "container".to_string();
            component.sha256 = data.sha256;
            let finding = evaluate(rules, &component, lang);
            known |= finding.status != Status::ReviewRequired;
            t.findings.push(finding);
            t.add_product_scope(Product::Php, name);
        }
        if !known {
            core_unknown(t, directory, indexes, lang);
        }
        record_partial(c, t);
    }
    if !executables.is_empty() {
        let (ko, en) = (
            "Windows DLL 검색 경로와 실제로 로드된 PHP 코어 DLL 은 개별 파일 조회만으로 확인할 수 없습니다.",
            "The Windows DLL search path and the PHP core DLL actually loaded cannot be confirmed by reading individual files.",
        );
        t.add_product_gap(Product::Php, lang.t(ko, en));
    }
}

fn core_unknown(t: &mut Target, directory: &str, indexes: &[usize], lang: Lang) {
    t.add_product_gap(
        Product::Php,
        lang.pick(
            format!("PHP 실행 파일과 같은 폴더의 코어 DLL 보안 패치를 확인하지 못했습니다: {directory}"),
            format!("The security patch of the core DLL next to the PHP executable was not confirmed: {directory}"),
        ),
    );
    for i in indexes {
        if let Some(f) = t.findings.get_mut(*i) {
            if f.status == Status::Clear {
                f.status = Status::ReviewRequired;
                f.reason = lang
                    .t(
                        "공식 PHP 실행 파일은 확인했지만 함께 쓰는 코어 DLL 의 보안 패치를 확인하지 못했습니다.",
                        "The official PHP executable was confirmed, but the security patch of the core DLL it uses was not.",
                    )
                    .to_string();
            }
        }
    }
}
