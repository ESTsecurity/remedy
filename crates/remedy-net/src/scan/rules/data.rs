//! 기준 데이터의 꼴과 검사 — `data/baseline.json` 을 읽는 타입, 그리고 줄마다 판정 규칙의 전제를 지키는가.
//!
//! 모르는 칸은 받지 않는다(`deny_unknown_fields`). 기준 파일에 새 칸이 생겼는데 코드가 그것을 모르면 조용히
//! 버리는 대신 읽기에서 멈춘다 — 파일을 컴파일해 넣으므로 그 멈춤은 실행 중이 아니라 시험에서 드러난다.
//!
//! 검사는 판정 규칙이 기대는 것만 본다: 견줄 수 있는 꼴의 수정 버전, 그 제품의 CVE, 공급사 줄의 범위
//! (RPM 은 아키텍처 · 공급사 · 버전 범위가 다 있어야 한다), 한 해시에 한 버전. 스캐너가 서명한 파일을 바깥에서
//! 받을 때 보던 것(엔진 버전 · 기준 번호의 되돌림 · 옛 형식)은 옮기지 않았다 — 여기서는 바깥 파일을 받지 않는다.

use super::version::{is_core, rpm_has_release, valid_debian};
use super::DependencyMode;
use crate::scan::model::Product;
use regex::Regex;
use remedy_sdk::catalog::is_rpm_version;
use serde::de::IgnoredAny;
use serde::Deserialize;
use std::collections::BTreeMap;

/// 이 코드가 읽는 기준 형식. 스캐너의 옛 형식(1 — PHP 만 있던 때)은 받지 않는다.
const SCHEMA_VERSION: u32 = 2;
/// 제품마다 이 기준이 다루는 CVE. 다른 제품의 CVE 가 섞인 줄은 받지 않는다.
const PHP_CVES: [&str; 2] = ["CVE-2026-109618", "CVE-2026-109619"];
const BROTLI_CVES: [&str; 1] = ["CVE-2026-111497"];
/// php.net 수정 버전이 없는 PHP 계열 — 영향 범위로 검토한 것만.
const LEGACY_PHP: [&str; 10] = [
    "5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1",
];
/// 수정 버전 기준을 둘 수 있는 Node.js 계열 — 지원이 끝난 계열은 수정 버전으로 판정하지 않는다.
const NODE_LINES: [&str; 3] = ["22", "24", "26"];
/// RPM 버전 범위(정규식)의 상한(바이트).
const MAX_PATTERN_BYTES: usize = 512;
/// RPM 범위 낱말(아키텍처 · 모듈 이름 · 스트림)의 상한(바이트).
const MAX_TOKEN_BYTES: usize = 128;

/// 파일 전체. 스캐너의 서명 형식에서 온 칸 셋(`expires_at` · `min_engine` · `guidance`)은 자리만 받고 값을
/// 읽지 않는다 — 기준에 만료를 두지 않고, 엔진 버전 관문과 안내문은 쓰지 않는다.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    schema_version: u32,
    revision: u32,
    version: String,
    issued_at: String,
    #[serde(default, rename = "expires_at")]
    _expires_at: IgnoredAny,
    #[serde(default, rename = "min_engine")]
    _min_engine: IgnoredAny,
    products: BTreeMap<String, ProductData>,
    #[serde(default, rename = "guidance")]
    _guidance: IgnoredAny,
}

/// 제품 하나의 기준.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProductData {
    pub(super) cves: Vec<String>,
    /// 계열(`8.3` · `24`) → 상류 수정 버전.
    #[serde(default)]
    pub(super) upstream: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) advisories: Vec<Advisory>,
    /// 공식 빌드의 실행 파일 · 코어 라이브러리.
    #[serde(default)]
    pub(super) hashes: Vec<HashRecord>,
    /// 상류 공지.
    pub(super) source: String,
    #[serde(default, rename = "guidance")]
    _guidance: IgnoredAny,
    #[serde(default)]
    pub(super) build_assessments: Vec<BuildAssessment>,
    #[serde(default)]
    pub(super) legacy_php: Option<LegacyPhp>,
}

impl ProductData {
    /// 공식 빌드의 해시와 맞는 줄. 해시를 모르면(빈 값) 없다.
    pub(super) fn official(&self, sha256: &str) -> Option<&HashRecord> {
        if sha256.is_empty() {
            return None;
        }
        self.hashes
            .iter()
            .find(|h| h.sha256.eq_ignore_ascii_case(sha256))
    }
}

/// 수정 버전과 견주는 방식.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Comparator {
    /// dpkg 의 순서.
    Debian,
    /// 순수한 `X.Y.Z`.
    Upstream,
    /// rpm 의 순서 — 아키텍처 · 공급사 · 모듈 · 버전 범위가 맞을 때만.
    Rpm,
    /// 견주지 않는다 — 공급사가 미수정으로 확인한 바로 그 버전인가만 본다.
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AdvisoryStatus {
    Fixed,
    Vulnerable,
}

/// 공급사 공지 한 줄 — 배포판 · 배포판 버전 · 패키지가 맞는 것에만 말한다.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Advisory {
    pub(super) distribution: String,
    pub(super) release: String,
    pub(super) package: String,
    #[serde(default)]
    pub(super) fixed: String,
    pub(super) comparator: Comparator,
    pub(super) source: String,
    #[serde(default)]
    pub(super) status: Option<AdvisoryStatus>,
    /// [`Comparator::Exact`] 의 미수정 버전.
    #[serde(default)]
    pub(super) version: String,
    #[serde(default)]
    pub(super) architectures: Vec<String>,
    /// RPM 의 `Vendor` 꼬리표 그대로.
    #[serde(default)]
    pub(super) vendor: String,
    /// `이름:스트림`. 비면 모듈이 아닌 패키지에만 말한다.
    #[serde(default)]
    pub(super) module: String,
    #[serde(default)]
    pub(super) version_pattern: Option<VersionPattern>,
    /// 이 줄이 덮는 CVE. 비면 그 제품의 CVE 전부다.
    #[serde(default)]
    pub(super) cves: Vec<String>,
}

/// RPM 줄의 버전 범위 — 그 공급사가 그 배포판에 내는 빌드의 꼴. 읽을 때 한 번 컴파일하고, 앞뒤를 `^` · `$`
/// 로 못박은 것만 받는다(못박지 않으면 다른 저장소의 꼬리가 붙은 버전이 범위에 든다).
#[derive(Debug, Deserialize)]
#[serde(try_from = "String")]
pub(super) struct VersionPattern(Regex);

impl TryFrom<String> for VersionPattern {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if text.len() > MAX_PATTERN_BYTES || !text.starts_with('^') || !text.ends_with('$') {
            return Err(format!(
                "version_pattern 은 `^` 로 시작해 `$` 로 끝나고 {MAX_PATTERN_BYTES}바이트를 넘지 않아야 한다"
            ));
        }
        Regex::new(&text)
            .map(VersionPattern)
            .map_err(|e| format!("version_pattern 을 읽지 못했다: {e}"))
    }
}

impl VersionPattern {
    pub(super) fn is_match(&self, version: &str) -> bool {
        self.0.is_match(version)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HashRecord {
    pub(super) sha256: String,
    pub(super) version: String,
    pub(super) source: String,
    /// Node.js 의 공식 빌드는 Brotli 를 담아 짓는다(`bundled`). 다른 제품에는 없는 칸이다.
    #[serde(default)]
    pub(super) dependency_mode: Option<DependencyMode>,
}

/// 수정 버전 기준이 없는 공식 빌드 하나를, 그 빌드에 든 Brotli 의 원본 코드를 대조해 취약으로 본 근거.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BuildAssessment {
    pub(super) version: String,
    pub(super) status: AdvisoryStatus,
    pub(super) dependency_version: String,
    pub(super) source: String,
    #[serde(default)]
    pub(super) evidence: Vec<BuildSource>,
}

/// 대조한 원본 하나 — 어디의(`source`) 어떤 바이트를(`sha256`) 보았고 무엇이 있었나(`detail`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BuildSource {
    pub(super) source: String,
    pub(super) sha256: String,
    pub(super) detail: String,
}

/// php.net 수정 버전이 없는 계열 — 공식 빌드면 두 CVE 중 하나 이상의 영향 범위다. 배포판이 고쳐 낸 빌드에는
/// 말하지 않는다.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyPhp {
    pub(super) branches: Vec<String>,
    pub(super) source: String,
}

/// 읽고 검사한 기준.
pub(super) struct Checked {
    pub(super) version: String,
    pub(super) issued_at: String,
    pub(super) products: BTreeMap<Product, ProductData>,
}

pub(super) fn parse(text: &str) -> Result<Checked, String> {
    let data: Data =
        serde_json::from_str(text).map_err(|e| format!("기준 데이터를 읽지 못했다: {e}"))?;
    if data.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "지원하지 않는 기준 형식이다: {}",
            data.schema_version
        ));
    }
    if data.revision == 0 || data.version.is_empty() || !rfc3339_utc(&data.issued_at) {
        return Err("기준의 번호 · 버전 · 발행 시각이 없거나 꼴이 잘못됐다".to_string());
    }
    if data.products.is_empty() {
        return Err("제품별 기준이 하나도 없다".to_string());
    }
    let mut products = BTreeMap::new();
    for (name, p) in data.products {
        let product = [Product::Php, Product::Node, Product::Brotli]
            .into_iter()
            .find(|p| p.id() == name)
            .ok_or_else(|| format!("지원하지 않는 제품의 기준이다: {name}"))?;
        check_product(product, &p).map_err(|e| format!("{name}: {e}"))?;
        products.insert(product, p);
    }
    Ok(Checked {
        version: data.version,
        issued_at: data.issued_at,
        products,
    })
}

fn check_product(product: Product, p: &ProductData) -> Result<(), String> {
    if p.cves.is_empty() || !https(&p.source) {
        return Err("취약점 목록이나 출처가 없다".to_string());
    }
    if let Some(cve) = p.cves.iter().find(|cve| !known_cve(product, cve)) {
        return Err(format!("이 제품에서 다루지 않는 취약점이다: {cve}"));
    }
    check_legacy(product, p)?;
    check_upstream(product, &p.upstream)?;
    for (i, a) in p.advisories.iter().enumerate() {
        check_advisory(product, a, &p.cves).map_err(|e| format!("advisories[{i}]: {e}"))?;
    }
    check_builds(product, &p.build_assessments)?;
    check_hashes(product, &p.hashes)
}

fn known_cve(product: Product, cve: &str) -> bool {
    match product {
        Product::Php => PHP_CVES.contains(&cve),
        Product::Node | Product::Brotli => BROTLI_CVES.contains(&cve),
    }
}

fn check_legacy(product: Product, p: &ProductData) -> Result<(), String> {
    let Some(legacy) = &p.legacy_php else {
        return Ok(());
    };
    if product != Product::Php || legacy.branches.is_empty() || !https(&legacy.source) {
        return Err("PHP 구버전 영향 기준의 제품이나 출처가 잘못됐다".to_string());
    }
    for (i, branch) in legacy.branches.iter().enumerate() {
        if !LEGACY_PHP.contains(&branch.as_str()) {
            return Err(format!("확인되지 않은 PHP 구버전 계열이다: {branch}"));
        }
        if legacy.branches[..i].contains(branch) || p.upstream.contains_key(branch) {
            return Err(format!(
                "PHP 구버전 계열이 겹치거나 수정 버전 기준과 부딪친다: {branch}"
            ));
        }
    }
    Ok(())
}

fn check_upstream(product: Product, upstream: &BTreeMap<String, String>) -> Result<(), String> {
    // 계열 이름의 꼴 — Node.js 는 `24`, 그 밖은 `8.3`.
    let dots = usize::from(product != Product::Node);
    for (branch, fixed) in upstream {
        let in_branch = fixed
            .strip_prefix(branch.as_str())
            .is_some_and(|rest| rest.starts_with('.'));
        if !is_core(fixed) || !in_branch || branch.matches('.').count() != dots {
            return Err(format!("수정 버전의 꼴이 잘못됐다: {branch} → {fixed}"));
        }
        if product == Product::Node && !NODE_LINES.contains(&branch.as_str()) {
            return Err(format!(
                "지원이 끝났거나 확인되지 않은 Node.js 계열이다: {branch}"
            ));
        }
    }
    Ok(())
}

fn check_advisory(product: Product, a: &Advisory, cves: &[String]) -> Result<(), String> {
    if a.distribution.is_empty() || a.release.is_empty() || a.package.is_empty() {
        return Err("배포판 · 배포판 버전 · 패키지 가운데 빈 칸이 있다".to_string());
    }
    if !https(&a.source) {
        return Err("출처가 https 주소가 아니다".to_string());
    }
    check_scope(a, cves)?;
    if a.comparator == Comparator::Exact {
        // 공급사가 미수정으로 확인한 버전 한 줄 — 수정 버전이 없고, PHP 에는 쓰지 않는다.
        let sound = a.status == Some(AdvisoryStatus::Vulnerable)
            && valid_debian(&a.version)
            && a.fixed.is_empty()
            && product != Product::Php;
        return sound
            .then_some(())
            .ok_or_else(|| "미수정 버전 줄의 꼴이 잘못됐다".to_string());
    }
    if a.status == Some(AdvisoryStatus::Vulnerable) || !a.version.is_empty() || a.fixed.is_empty() {
        return Err("수정 버전 줄의 꼴이 잘못됐다".to_string());
    }
    let comparable = match a.comparator {
        Comparator::Upstream => is_core(&a.fixed),
        Comparator::Debian => valid_debian(&a.fixed),
        Comparator::Rpm | Comparator::Exact => true,
    };
    comparable
        .then_some(())
        .ok_or_else(|| format!("수정 버전을 견줄 수 없는 꼴이다: {}", a.fixed))
}

/// 줄의 범위 — 덮는 CVE 와, RPM 줄이면 아키텍처 · 공급사 · 모듈 · 버전 범위.
///
/// RPM 은 같은 버전 문자열을 여러 공급사가 낸다(Rocky · Alma 는 RHEL 의 것을 그대로 적는다). 그래서 RPM 줄은
/// 범위를 **다 적어야** 하고 덮는 CVE 도 스스로 밝혀야 한다 — 다른 방식의 줄에는 그 칸들이 있으면 안 된다.
fn check_scope(a: &Advisory, cves: &[String]) -> Result<(), String> {
    for (i, cve) in a.cves.iter().enumerate() {
        if !cves.contains(cve) || a.cves[..i].contains(cve) {
            return Err(format!("줄이 덮는 취약점이 잘못됐다: {cve}"));
        }
    }
    if a.comparator != Comparator::Rpm {
        let plain = a.architectures.is_empty()
            && a.vendor.is_empty()
            && a.module.is_empty()
            && a.version_pattern.is_none();
        return plain
            .then_some(())
            .ok_or_else(|| "RPM 줄에만 쓰는 범위 칸이 다른 방식의 줄에 있다".to_string());
    }
    if a.architectures.is_empty() || a.vendor.is_empty() || a.vendor.trim() != a.vendor {
        return Err("RPM 줄에 아키텍처나 공급사가 없다".to_string());
    }
    if a.cves.is_empty() {
        return Err("RPM 줄은 덮는 취약점을 적어야 한다".to_string());
    }
    for (i, arch) in a.architectures.iter().enumerate() {
        if !rpm_scope_token(arch) || a.architectures[..i].contains(arch) {
            return Err(format!("RPM 줄의 아키텍처가 잘못됐다: {arch}"));
        }
    }
    if !a.module.is_empty() {
        let named = a
            .module
            .split_once(':')
            .is_some_and(|(name, stream)| rpm_scope_token(name) && rpm_scope_token(stream));
        if !named {
            return Err(format!(
                "RPM 줄의 모듈은 `이름:스트림` 이어야 한다: {}",
                a.module
            ));
        }
    }
    if !is_rpm_version(&a.fixed) || !rpm_has_release(&a.fixed) {
        return Err(format!(
            "RPM 수정 버전에 개정이 없거나 꼴이 잘못됐다: {}",
            a.fixed
        ));
    }
    match &a.version_pattern {
        Some(pattern) if pattern.is_match(&a.fixed) => Ok(()),
        _ => Err("RPM 수정 버전이 그 줄의 버전 범위에 들지 않는다".to_string()),
    }
}

/// RPM 범위에 쓰는 낱말 — 글자 · 숫자와 `.` `_` `+` `-` 만.
pub(super) fn rpm_scope_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TOKEN_BYTES
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

fn check_builds(product: Product, builds: &[BuildAssessment]) -> Result<(), String> {
    for b in builds {
        let sound = product == Product::Node
            && is_core(&b.version)
            && b.status == AdvisoryStatus::Vulnerable
            && is_core(&b.dependency_version)
            && https(&b.source)
            && b.evidence.len() >= 2
            && b.evidence
                .iter()
                .all(|e| sha256_hex(&e.sha256) && https(&e.source) && !e.detail.is_empty());
        if !sound {
            return Err(format!(
                "공식 빌드를 취약으로 본 근거가 모자라거나 꼴이 잘못됐다: {}",
                b.version
            ));
        }
    }
    Ok(())
}

fn check_hashes(product: Product, hashes: &[HashRecord]) -> Result<(), String> {
    let mode = (product == Product::Node).then_some(DependencyMode::Bundled);
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for h in hashes {
        let sound = sha256_hex(&h.sha256)
            && is_core(&h.version)
            && https(&h.source)
            && h.dependency_mode == mode;
        if !sound {
            return Err(format!("파일 해시 줄의 꼴이 잘못됐다: {}", h.sha256));
        }
        let old = seen.insert(h.sha256.to_ascii_lowercase(), &h.version);
        if old.is_some_and(|version| version != h.version) {
            return Err(format!(
                "같은 파일 해시에 서로 다른 버전이 적혀 있다: {}",
                h.sha256
            ));
        }
    }
    Ok(())
}

fn sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `https://호스트/…` 인가 — 호스트가 있고 사용자 정보(`이름@`)가 없다.
fn https(source: &str) -> bool {
    let Some(rest) = source.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !host.is_empty() && !host.contains('@')
}

/// `YYYY-MM-DDTHH:MM:SSZ` 인가 — 자리마다 본다.
fn rfc3339_utc(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

/// 내장 기준을 본체의 점검 룰 파일과 대조한다.
///
/// 호스트는 본체의 점검 룰(`plugins/{php2shell,node2shell}-check-{linux,windows}`)이, 이미지와 컨테이너는 이
/// 크레이트가 본다. 같은 공지에서 온 값이 두 자리에 있으므로, 한쪽만 고치면 여기서 걸리게 한다.
///
/// 방향은 **내장 기준 → 룰 파일** 이다. 기준의 수정 버전과, 기준의 해시 가운데 그 룰이 보는 꼴의 것이 룰
/// 파일에 빠짐없이 있는가를 본다. 거꾸로는 보지 않는다 — 룰 파일은 기준에 없는 해시를 더 안다(다시 지은 공식
/// PHP 이미지 · PHP for Windows 의 다른 계열과 재빌드 · 그 안의 `brotlidec.dll`).
#[cfg(test)]
mod host_rules {
    use super::HashRecord;
    use crate::scan::model::Product::{Node, Php};
    use crate::scan::rules::tests::builtin;
    use std::collections::{BTreeMap, BTreeSet};

    fn host_rule(plugin: &str) -> String {
        let root = env!("CARGO_MANIFEST_DIR");
        std::fs::read_to_string(format!("{root}/../../plugins/{plugin}/plugin.yaml"))
            .unwrap_or_else(|e| panic!("plugins/{plugin}/plugin.yaml 을 읽지 못했다: {e}"))
    }

    /// 룰 파일의 해시 한 줄이 주석으로 붙인 것 — `# <버전> <꼴> …`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Listed<'a> {
        version: &'a str,
        /// `linux/amd64` · `linux-x64` · `win-x64` …
        label: &'a str,
    }

    /// 룰 파일이 따옴표 안에 적은 SHA-256 → 그 줄의 주석. 한 해시가 여러 목록에 나와도 주석은 같다.
    fn host_hashes(rule: &str) -> BTreeMap<&str, Listed<'_>> {
        let mut hashes = BTreeMap::new();
        for line in rule.lines() {
            let Some(hash) = line.split('"').nth(1) else {
                continue;
            };
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let comment = line.split('#').nth(1).unwrap_or_default();
            let mut words = comment.split_whitespace();
            let (version, label) = (words.next(), words.next());
            let listed = Listed {
                version: version.unwrap_or_default(),
                label: label.unwrap_or_default(),
            };
            let old = hashes.insert(hash, listed);
            assert!(
                old.is_none_or(|old| old == listed),
                "{hash}: {old:?} · {listed:?}"
            );
        }
        hashes
    }

    /// 기준의 그 해시가 룰 파일에 **같은 버전으로** 적혀 있으면 그 꼴.
    fn label_of<'a>(known: &BTreeMap<&str, Listed<'a>>, h: &HashRecord) -> Option<&'a str> {
        let listed = known.get(h.sha256.as_str())?;
        assert_eq!(listed.version, h.version, "{}", h.sha256);
        Some(listed.label)
    }

    /// 수정 버전 — 기준의 값이 네 룰 파일에 그대로 있다.
    #[test]
    fn the_fixed_versions_are_in_the_host_rules() {
        let php: Vec<&str> = builtin(Php).upstream.values().map(String::as_str).collect();
        assert_eq!(php.len(), 4);
        let line = format!("상류: {}", php.join(" · "));
        assert!(host_rule("php2shell-check-linux").contains(&line), "{line}");
        let windows = host_rule("php2shell-check-windows");
        assert!(windows.contains(&line), "{line}");
        for fixed in php {
            let row = format!("op: version_lt, value: \"{fixed}\"");
            assert!(windows.contains(&row), "{row}");
        }

        let node = builtin(Node).upstream.values();
        let node: Vec<&str> = node.map(String::as_str).collect();
        assert_eq!(node.len(), 3);
        let line = node.join(" · ");
        for plugin in ["node2shell-check-linux", "node2shell-check-windows"] {
            assert!(host_rule(plugin).contains(&line), "{plugin}: {line}");
        }
    }

    /// PHP 공식 빌드의 해시 — 기준의 37개가 전부 같은 버전으로 룰 파일에 있다. 기준의 해시는 출처로 갈린다:
    /// 공식 Docker 이미지의 실행 파일 · 코어 라이브러리(리눅스 룰)와 PHP for Windows 의 코어 DLL(Windows 룰).
    #[test]
    fn every_php_hash_is_in_the_host_rule_of_its_platform() {
        let ours = &builtin(Php).hashes;
        let mut seen = 0;
        for (plugin, host, platform, count) in [
            (
                "php2shell-check-linux",
                "registry-1.docker.io",
                "linux/",
                33,
            ),
            (
                "php2shell-check-windows",
                "downloads.php.net",
                "windows/",
                4,
            ),
        ] {
            let rule = host_rule(plugin);
            let known = host_hashes(&rule);
            let prefix = format!("https://{host}/");
            let from_host: Vec<&HashRecord> = ours
                .iter()
                .filter(|h| h.source.starts_with(&prefix))
                .collect();
            assert_eq!(from_host.len(), count, "{host}");
            for h in from_host {
                let listed = label_of(&known, h).is_some_and(|l| l.starts_with(platform));
                assert!(listed, "{plugin}: PHP {} {}", h.version, h.sha256);
                seen += 1;
            }
        }
        assert_eq!(seen, ours.len());
    }

    /// Node.js 공식 빌드의 해시 — 기준의 555개는 여러 운영체제 · 아키텍처의 것이고, 본체 룰은 x64 만 본다.
    /// 그 꼴의 해시는 기준의 89 버전마다 하나씩, 같은 버전으로 룰 파일에 있다(musl 은 공식 빌드가 있는 여덟
    /// 버전).
    #[test]
    fn the_x64_node_hashes_are_in_the_host_rules() {
        let ours = &builtin(Node).hashes;
        let versions: BTreeSet<&str> = ours.iter().map(|h| h.version.as_str()).collect();
        assert_eq!(versions.len(), 89);
        for (plugin, labels) in [
            (
                "node2shell-check-linux",
                &[("linux-x64", 89), ("linux-x64-musl", 8)][..],
            ),
            ("node2shell-check-windows", &[("win-x64", 89)][..]),
        ] {
            let rule = host_rule(plugin);
            let known = host_hashes(&rule);
            let mut listed = 0;
            for (label, count) in labels {
                let of_label: Vec<&HashRecord> = ours
                    .iter()
                    .filter(|h| label_of(&known, h) == Some(*label))
                    .collect();
                assert_eq!(of_label.len(), *count, "{plugin} {label}");
                // 버전마다 하나다 — 해시 수와 버전 수가 같다.
                let covered: BTreeSet<&str> = of_label.iter().map(|h| h.version.as_str()).collect();
                assert_eq!(covered.len(), *count, "{plugin} {label}");
                assert_eq!(covered == versions, *count == 89, "{plugin} {label}");
                listed += count;
            }
            // 그 룰 파일에 있는 기준의 해시는 위 꼴의 것이 전부다.
            let in_rule = ours.iter().filter(|h| label_of(&known, h).is_some());
            assert_eq!(in_rule.count(), listed, "{plugin}");
        }
    }
}
