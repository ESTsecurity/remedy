//! 기준 데이터의 꼴과 검사 — 데이터 룰의 `baseline.json` 을 읽는 타입, 그리고 줄마다 판정 규칙의 전제를
//! 지키는가.
//!
//! 모르는 칸은 받지 않는다(`deny_unknown_fields`). 기준 파일에 새 칸이 생겼는데 이 프로그램이 그것을 모르면
//! 조용히 버리는 대신 읽기에서 멈춘다 — 점검하지 않고 같은 릴리스의 파일을 쓰라고 말한다(종료 4).
//!
//! 검사는 판정 규칙이 기대는 것만 본다: 견줄 수 있는 꼴의 수정 버전, CVE 번호의 꼴과 줄이 덮는 CVE 가 그
//! 제품이 밝힌 목록 안인가, 공급사 줄의 범위(RPM 은 아키텍처 · 공급사 · 버전 범위가 다 있어야 한다), 한 해시에
//! 한 버전. **어느 CVE · 계열을 다루는가는 데이터가 밝힌다** — 코드에 목록을 두지 않는다(새 CVE · 계열이
//! 데이터만으로 들어온다 · 코어 1.12.0). 스캐너가 서명한 파일을 받을 때 보던 것(엔진 버전 · 기준 번호의 되돌림 ·
//! 옛 형식)은 옮기지 않았다 — 서명은 본체의 사슬이 본다(`crate::criteria`).

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
    for (i, cve) in p.cves.iter().enumerate() {
        if !cve_id(cve) || p.cves[..i].contains(cve) {
            return Err(format!("CVE 번호의 꼴이 잘못됐거나 겹친다: {cve}"));
        }
    }
    check_legacy(product, p)?;
    check_upstream(product, &p.upstream)?;
    for (i, a) in p.advisories.iter().enumerate() {
        check_advisory(product, a, &p.cves).map_err(|e| format!("advisories[{i}]: {e}"))?;
    }
    check_builds(product, &p.build_assessments)?;
    check_hashes(product, &p.hashes)
}

/// `CVE-YYYY-N…`(번호 넷 이상). 어느 CVE 를 다루는가는 그 제품의 `cves` 가 밝힌다.
fn cve_id(s: &str) -> bool {
    let Some((year, n)) = s.strip_prefix("CVE-").and_then(|r| r.split_once('-')) else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && n.len() >= 4
        && n.bytes().all(|b| b.is_ascii_digit())
}

/// PHP 계열 이름(`7.4`) — 숫자 두 조각.
fn php_branch_name(s: &str) -> bool {
    s.split_once('.').is_some_and(|(a, b)| {
        let digits = |s: &str| (1..=6).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit());
        digits(a) && digits(b)
    })
}

fn check_legacy(product: Product, p: &ProductData) -> Result<(), String> {
    let Some(legacy) = &p.legacy_php else {
        return Ok(());
    };
    if product != Product::Php || legacy.branches.is_empty() || !https(&legacy.source) {
        return Err("PHP 구버전 영향 기준의 제품이나 출처가 잘못됐다".to_string());
    }
    for (i, branch) in legacy.branches.iter().enumerate() {
        if !php_branch_name(branch) {
            return Err(format!("PHP 구버전 계열의 꼴이 잘못됐다: {branch}"));
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
