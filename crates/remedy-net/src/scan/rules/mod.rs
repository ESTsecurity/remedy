//! 판정 규칙과 기준 데이터 — PHP · Node.js · Brotli.
//!
//! 사내 runtime-scanner(`d3acb38`)의 `internal/rules` 를 옮겼다. 기준 데이터는 그 저장소의
//! `data/baseline.json`(기준 `2026-10-30.12`) 형식이고 공개 공지와 공식 배포본에서 온 값뿐이다. **이
//! 바이너리에는 없다** — 데이터 룰 `remedy-net-criteria` 의 `baseline.json` 을 서명을 확인한 뒤 읽는다
//! ([`RuleSet::load`] · `crate::criteria` · 코어 1.12.0). 기준을 바꾸면 그 파일과 데이터 룰의 버전만 고친다.
//!
//! 수집한 것 하나([`Component`])를 받아 발견 하나([`Finding`])를 낸다. 규칙은 넷이다.
//!
//! - **근거가 있어야 판정한다.** 출처를 믿을 수 있는 것(`trusted`)과 공식 빌드의 해시가 맞는 것만 견준다.
//!   버전 문자열만으로는 *양호* 도 *취약* 도 내지 않는다.
//! - **해시가 이긴다.** 공식 빌드의 SHA-256 과 맞으면 패키지 · 배포판 · 버전 칸에 무엇이 적혀 있든 그 빌드의
//!   버전으로 판정한다.
//! - **공급사의 줄 안에서만 견준다.** 배포판 패키지는 그 공급사 공지의 수정 버전과만 견주고, 그 줄의 것이
//!   아닌 버전(PPA · 직접 빌드 · 다른 저장소)은 수정을 물려받지 않는다.
//! - **대상 CVE 를 전부 덮어야 양호다.** 하나라도 덮지 못하면 *확인 필요* 로 남는다.
//!
//! # 서명은 본체의 것 하나, 만료는 두지 않는다
//!
//! 스캐너는 기준을 자기 키로 서명한 파일로 받았다. 여기서는 그 파일이 룰 폴더와 같은 사슬로 서명된 데이터
//! 룰에 있다(본체와 같은 배포 키 · `remedy-trust`) — 스캐너의 서명 · 엔진 버전 관문은 옮기지 않았다.
//! **기준은 만료되지 않는다.** 그 대신 결과가 기준의 버전 · 발행 시각 · SHA-256 을 싣는다([`RuleSet::version`] ·
//! [`RuleSet::issued_at`] · [`RuleSet::sha256`]).
//!
//! # 본체의 점검 룰과 겹치는 값
//!
//! 수정 버전과 공식 빌드 해시는 본체의 점검 룰(`plugins/{php2shell,node2shell}-check-*`)에도 있다. 두 자리가
//! 같은지는 저장소 검사(`cargo xtask net-criteria`)가 본다 — 룰 파일을 읽는 것은 크레이트 시험이 아니다(룰을
//! 고쳐도 이 크레이트의 시험이 깨지지 않게). 크레이트 시험은 고정 사본(`testdata/baseline.json`)으로 판정
//! 규칙을 잰다.

mod advisory;
mod data;
mod node;
mod php;
mod version;

#[cfg(test)]
mod tests;

use crate::scan::model::{Evidence, Finding, Product, Status};
use data::ProductData;
use remedy_sdk::i18n::Lang;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// 배포판 칸([`Component::distribution`])에 적는 값 — 배포판의 패키지가 아니라 만든 곳의 배포본이다.
pub const UPSTREAM: &str = "upstream";

/// Node.js 가 Brotli 를 어떻게 쓰는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyMode {
    /// 모른다 — 보지 못했거나 가리지 못했다.
    #[default]
    Unknown,
    /// 실행 파일 안에 담아 지었다.
    Bundled,
    /// 시스템의 공유 라이브러리를 연결한다. 이것을 확인했으면 실행 파일의 해시보다 먼저다.
    Shared,
}

/// 그 패키지를 적은 패키지 관리자.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PackageManager {
    #[default]
    Unknown,
    Dpkg,
    /// RPM 패키지는 RPM 줄(공급사 · 아키텍처 · 버전 범위가 맞는 것)로만 견준다.
    Rpm,
}

/// 수집한 것 하나 — 실행 파일 · 라이브러리 · 패키지. 모르는 칸은 비워 둔다.
///
/// 사람이 읽는 칸(`name` · `source`)은 부르는 쪽이 실행 언어로 적는다 — 발견에 그대로 실린다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub id: String,
    pub name: String,
    pub path: String,
    /// 패키지면 패키지 관리자가 적은 버전 그대로, 파일이면 파일에서 읽은 버전.
    pub version: String,
    pub package: String,
    /// 배포판 식별자(os-release 의 `ID`) 또는 [`UPSTREAM`].
    pub distribution: String,
    /// 배포판 버전(os-release 의 `VERSION_ID`).
    pub distribution_version: String,
    /// 이 값들을 어디서 읽었나 — 근거의 출처 칸이 된다.
    pub source: String,
    pub runtime: String,
    /// 파일의 SHA-256(16진수). 공식 빌드의 것과 맞으면 다른 칸보다 이것이 먼저다.
    pub sha256: String,
    pub product: Product,
    pub dependency_mode: DependencyMode,
    /// RPM 의 아키텍처(`x86_64` · `aarch64` …).
    pub architecture: String,
    /// RPM 의 `Vendor` 꼬리표 그대로.
    pub package_vendor: String,
    /// RPM 모듈 꼬리표 — `이름:스트림:버전:컨텍스트[:아키텍처]`.
    pub package_module: String,
    pub package_manager: PackageManager,
    /// Node.js 가 실제로 연결한 라이브러리들. Brotli 인 것만 본다.
    pub dependencies: Vec<Component>,
    /// 의존 목록을 끝까지 보았다.
    pub dependencies_complete: bool,
    /// 버전과 출처를 믿을 수 있다 — 패키지 DB 가 이 파일을 제 것으로 적고 있고 그 기록과 파일이 맞는다.
    /// 패키지 서명을 확인했다는 뜻은 아니다.
    pub trusted: bool,
}

impl Component {
    /// 제품만 정한 빈 것. 나머지는 아는 칸만 채운다.
    pub fn new(product: Product) -> Self {
        Component {
            id: String::new(),
            name: String::new(),
            path: String::new(),
            version: String::new(),
            package: String::new(),
            distribution: String::new(),
            distribution_version: String::new(),
            source: String::new(),
            runtime: String::new(),
            sha256: String::new(),
            product,
            dependency_mode: DependencyMode::Unknown,
            architecture: String::new(),
            package_vendor: String::new(),
            package_module: String::new(),
            package_manager: PackageManager::Unknown,
            dependencies: Vec::new(),
            dependencies_complete: false,
            trusted: false,
        }
    }
}

/// 기준 데이터를 읽지 못한 까닭 — 서명된 기준이면 같은 릴리스의 이 프로그램이 다 읽는다. 화면에는
/// [`crate::criteria::Refusal::Unreadable`] 에 실려 괄호 안의 까닭으로 나간다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError(String);

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RuleError {}

/// 읽고 검사한 기준 한 벌.
pub struct RuleSet {
    version: String,
    issued_at: String,
    sha256: String,
    products: BTreeMap<Product, ProductData>,
}

impl RuleSet {
    /// 서명을 확인한 데이터 룰의 `baseline.json` — 실행마다 한 번 읽는다(코어 1.12.0 · `crate::criteria`).
    /// 점검은 따로 도는 일감에서도 쓰므로 그 실행이 끝날 때까지 둔다.
    pub fn load() -> Result<&'static RuleSet, crate::criteria::Refusal> {
        let verified = crate::criteria::open()?;
        let text = verified.read(crate::criteria::BASELINE_FILE)?;
        let set = RuleSet::from_json(&text).map_err(|e| {
            crate::criteria::Refusal::Unreadable(
                crate::criteria::BASELINE_FILE.to_string(),
                e.to_string(),
            )
        })?;
        Ok(crate::criteria::leak(set))
    }

    /// 도움말의 기준 줄(해라체) — 받은 기준 폴더에서 읽고, 확인하지 못하면 그렇다고 적는다(도움말은
    /// 기준 없이도 선다). `image` · `container` 가 함께 쓴다.
    pub fn help_line(lang: Lang) -> String {
        match RuleSet::load() {
            Ok(rules) => {
                let (version, issued) = (rules.version(), rules.issued_at());
                let issued = issued.get(..10).unwrap_or(issued);
                lang.pick(
                    format!("기준: {version} ({issued} 발행 · 만료 없음)."),
                    format!("Criteria: {version} (issued {issued} · no expiry)."),
                )
            }
            Err(_) => lang.pick(
                format!(
                    "기준: 데이터 룰 {} 의 baseline.json — 이 자리에서 확인하지 못했다.",
                    crate::criteria::ID
                ),
                format!(
                    "Criteria: baseline.json of the data rule {} — could not be verified here.",
                    crate::criteria::ID
                ),
            ),
        }
    }

    /// 시험이 쓰는 기준 — `testdata/baseline.json`(1.11.0 까지 바이너리에 들던 파일의 고정 사본).
    #[cfg(test)]
    pub fn fixture() -> &'static RuleSet {
        static FIXTURE: std::sync::OnceLock<RuleSet> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            RuleSet::from_json(crate::criteria::testkit::BASELINE).expect("testdata/baseline.json")
        })
    }

    /// 기준 파일의 글에서 읽는다 — 데이터 룰과 시험이 쓴다. 모르는 칸 · 견줄 수 없는 꼴의 줄이 있으면 실패한다.
    pub fn from_json(text: &str) -> Result<RuleSet, RuleError> {
        let checked = data::parse(text).map_err(RuleError)?;
        let sha256 = Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(RuleSet {
            version: checked.version,
            issued_at: checked.issued_at,
            sha256,
            products: checked.products,
        })
    }

    /// 기준의 버전 — `2026-10-30.12`(발행일 · 기준 번호).
    pub fn version(&self) -> &str {
        &self.version
    }

    /// 기준을 발행한 시각(RFC 3339 UTC).
    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }

    /// 읽은 기준 파일의 SHA-256 — 스캐너가 같은 기준에 적는 값과 같다.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// 이 기준에 그 제품이 있는가.
    pub fn supports(&self, product: Product) -> bool {
        self.products.contains_key(&product)
    }

    /// 그 제품에서 보는 CVE. 기준에 없는 제품이면 비어 있다.
    pub fn cves(&self, product: Product) -> &[String] {
        self.product(product)
            .map(|p| p.cves.as_slice())
            .unwrap_or_default()
    }

    /// 수집한 것 하나를 판정한다. 사람이 읽는 칸은 `lang` 으로 적는다.
    pub fn evaluate(&self, c: &Component, lang: Lang) -> Finding {
        match c.product {
            Product::Php => self.evaluate_php(c, lang),
            Product::Node => self.evaluate_node(c, lang),
            Product::Brotli => self.evaluate_vendor_component(c, lang),
        }
    }

    /// 그 해시가 Brotli 를 담아 지은 공식 Node.js 빌드의 것이면 그 버전. 공유 연결 · 로더 덮어쓰기는 수집하는
    /// 쪽이 따로 본다 — 여기서는 파일이 무엇인지만 답한다.
    pub fn node_hash_version(&self, sha256: &str) -> Option<&str> {
        if sha256.is_empty() {
            return None;
        }
        self.product(Product::Node)?
            .hashes
            .iter()
            .find(|h| {
                h.dependency_mode == Some(DependencyMode::Bundled)
                    && h.sha256.eq_ignore_ascii_case(sha256)
            })
            .map(|h| h.version.as_str())
    }

    fn product(&self, product: Product) -> Option<&ProductData> {
        self.products.get(&product)
    }

    /// 판정의 출발점 — *확인 필요*. 근거를 찾은 규칙만 이것을 *양호* · *취약* 으로 바꾼다.
    fn new_finding(&self, c: &Component, lang: Lang) -> Finding {
        let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
        Finding {
            product: c.product,
            id: c.id.clone(),
            name: c.name.clone(),
            path: some(&c.path),
            version: some(&c.version),
            package: some(&c.package),
            vendor: some(&c.distribution),
            runtime: some(&c.runtime),
            cves: self.cves(c.product).to_vec(),
            status: Status::ReviewRequired,
            reason: lang
                .t(
                    "이 파일에 적용할 공급사 보안 패치 기준을 확인하지 못했습니다.",
                    "No vendor security patch criteria that apply to this file could be confirmed.",
                )
                .to_string(),
            action: lang
                .t(
                    "공급사나 빌드 담당자에게 해당 파일의 빌드 정보와 보안 패치 포함 여부를 확인하십시오.",
                    "Ask the vendor or whoever built this file for its build details and whether it includes the security patch.",
                )
                .to_string(),
            evidence: vec![Evidence::new(c.source.as_str(), installed(c, lang))],
        }
    }
}

/// 근거의 첫 줄 — 무엇으로 깔려 있다고 읽었나. 모르는 칸은 `-` 로 적는다.
fn installed(c: &Component, lang: Lang) -> String {
    let origin = format!("{} {}", c.distribution, c.distribution_version);
    let (origin, package, version) = (
        or_dash(origin.trim()),
        or_dash(&c.package),
        or_dash(&c.version),
    );
    lang.pick(
        format!("설치 정보: {origin} / {package} / {version}"),
        format!("Install info: {origin} / {package} / {version}"),
    )
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

/// *확인 필요* 로 두고 까닭만 바꾼다.
fn review(mut f: Finding, reason: &str) -> Finding {
    f.reason = reason.to_string();
    f
}

/// 판정과 까닭 · 할 일을 적는다.
fn settle(
    mut f: Finding,
    status: Status,
    reason: impl Into<String>,
    action: impl Into<String>,
) -> Finding {
    f.status = status;
    f.reason = reason.into();
    f.action = action.into();
    f
}
