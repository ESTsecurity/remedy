//! 스캐너 `internal/rules` 의 시험을 옮겼다. 각 시험의 이름 위에 원래 이름을 적는다.
//!
//! 버전 비교의 시험(`TestDebianOrdering` · `TestRPMOrdering` …)은 [`super::version`] 에, 내장 기준을 본체의 점검
//! 룰 파일과 대조하는 시험은 [`super::data`] 의 `host_rules` 에 있다. 여기는 기준 한 벌을 놓고 판정을 보는
//! 시험이다.
//!
//! 스캐너가 시험마다 서명해 만들던 기준은 여기서 JSON 글로 지어 [`RuleSet::from_json`] 으로 읽는다. 서명 ·
//! 되돌림 · 엔진 버전 · 발행 시각을 보던 시험은 옮기지 않았다 — 그 장치가 여기에는 없다. 스캐너의 다른 자료
//! 파일(`php-catalog.json` · `linux-vendor-advisories.json` …)과 대조하던 시험은 내장 기준의 줄로 바꿔 보거나
//! 옮기지 않았다 — 그 파일들을 들여오지 않는다.

use super::data::{HashRecord, ProductData};
use super::node::detail_en;
use super::{Component, DependencyMode, PackageManager, RuleSet, UPSTREAM};
use crate::scan::model::{Finding, Product, Status};
use remedy_sdk::i18n::Lang;
use serde_json::{json, Value};
use std::collections::BTreeSet;

use DependencyMode::{Bundled, Shared};
use PackageManager::{Dpkg, Rpm};
use Product::{Brotli, Node, Php};
use Status::{Clear, ReviewRequired as Review, Vulnerable};

const PHP_CVES: [&str; 2] = ["CVE-2026-109618", "CVE-2026-109619"];
const BROTLI_CVE: &str = "CVE-2026-111497";

// ── 기준을 짓고 읽는 도우미 ─────────────────────────────────────────────

fn rules(v: &Value) -> RuleSet {
    RuleSet::from_json(&v.to_string()).expect("시험 기준을 읽지 못했다")
}

fn refused(v: &Value) -> bool {
    RuleSet::from_json(&v.to_string()).is_err()
}

fn verdict(r: &RuleSet, c: &Component) -> Status {
    r.evaluate(c, Lang::Ko).status
}

/// 내장 기준의 한 제품 — [`super::data`] 의 대조 시험도 쓴다.
pub(super) fn builtin(product: Product) -> &'static ProductData {
    RuleSet::builtin()
        .product(product)
        .expect("내장 기준에 그 제품이 없다")
}

/// PHP 만 있는 기준 — 공급사 줄은 받은 것만.
fn php_rules(advisories: Vec<Value>) -> Value {
    json!({
        "schema_version": 2,
        "revision": 12,
        "version": "php-test",
        "issued_at": "2026-10-01T00:00:00Z",
        "products": {
            "php": {
                "cves": PHP_CVES,
                "source": "https://example.invalid/php",
                "advisories": advisories,
            }
        }
    })
}

/// 공급사 줄 하나 — dpkg 순서나 상류 `X.Y.Z` 로 견주는 것.
fn fixed_row(distribution: &str, release: &str, package: &str, how: &str, fixed: &str) -> Value {
    json!({
        "distribution": distribution,
        "release": release,
        "package": package,
        "comparator": how,
        "fixed": fixed,
        "source": "https://example.invalid/advisory",
    })
}

/// 공급사가 미수정으로 확인한 버전 한 줄(Debian 13).
fn unfixed_row(package: &str, version: &str) -> Value {
    json!({
        "distribution": "debian",
        "release": "13",
        "package": package,
        "comparator": "exact",
        "status": "vulnerable",
        "version": version,
        "source": "https://security-tracker.debian.org/tracker/CVE-2026-111497",
    })
}

fn node_hash_row(digit: &str, version: &str) -> Value {
    json!({
        "sha256": digit.repeat(64),
        "version": version,
        "source": "https://nodejs.org/fixture",
        "dependency_mode": "bundled",
    })
}

/// 스캐너 `nodeRulesFixture` — 해시 `1…` 은 고친 24.22.1, `2…` 는 고치기 전 24.22.0, `3…` 은 지원이 끝난
/// 18.20.8 이다. Brotli 의 `fixture` 배포판 줄은 수정 버전과 견주는 길을 보려고 지은 것이다.
fn node_rules() -> Value {
    json!({
        "schema_version": 2,
        "revision": 4,
        "version": "node-test",
        "issued_at": "2026-10-21T00:00:00Z",
        "products": {
            "node": {
                "cves": [BROTLI_CVE],
                "source": "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
                "upstream": {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"},
                "hashes": [
                    node_hash_row("1", "24.22.1"),
                    node_hash_row("2", "24.22.0"),
                    node_hash_row("3", "18.20.8"),
                ],
                "advisories": [unfixed_row("nodejs", "20.19.2+dfsg-1+deb13u3")],
            },
            "brotli": {
                "cves": [BROTLI_CVE],
                "source": "https://security-tracker.debian.org/tracker/CVE-2026-111497",
                "advisories": [
                    unfixed_row("libbrotli1", "1.1.0-2"),
                    fixed_row("fixture", "1", "libbrotli1", "debian", "1.1.0-2+fixture1"),
                ],
            },
        }
    })
}

/// 스캐너 `rpmTestAdvisory` — RHEL 8.10 의 `php:7.4` 모듈 줄.
fn rpm_row() -> Value {
    json!({
        "distribution": "rhel",
        "release": "8.10",
        "package": "php-cli",
        "comparator": "rpm",
        "fixed": RPM_FIXED,
        "source": "https://example.invalid/vendor/php-security",
        "architectures": ["i686", "x86_64"],
        "vendor": "Red Hat, Inc.",
        "module": "php:7.4",
        "version_pattern": r"^(?:0:)?7\.4\.[0-9]+-[0-9]+\.module\+el8\.10\.0\+[0-9]+\+[0-9a-f]+$",
        "cves": PHP_CVES,
    })
}

const RPM_FIXED: &str = "0:7.4.33-8.module+el8.10.0+2345+abcd1234";
const RPM_OLDER: &str = "7.4.33-7.module+el8.10.0+2344+abcd1234";
const RPM_MODULE: &str = "php:7.4:8100020261021081045:abcd1234";

/// 스캐너 `rpmTestComponent` — 위 줄의 수정 버전 그대로인 패키지.
fn rpm_component() -> Component {
    with(package(Php, "rhel", "8.10", "php-cli", RPM_FIXED), |c| {
        c.architecture = "i686".into();
        c.package_vendor = "Red Hat, Inc.".into();
        c.package_module = RPM_MODULE.into();
        c.package_manager = Rpm;
    })
}

// ── 수집한 것을 짓는 도우미 ─────────────────────────────────────────────

/// 몇 칸을 바꾼 것.
fn with(mut c: Component, edit: impl FnOnce(&mut Component)) -> Component {
    edit(&mut c);
    c
}

/// 출처를 믿을 수 있는 상류 빌드.
fn official(product: Product, version: &str) -> Component {
    with(Component::new(product), |c| {
        c.distribution = UPSTREAM.into();
        c.version = version.into();
        c.trusted = true;
    })
}

/// 출처를 믿을 수 있는 배포판 패키지.
fn package(product: Product, distribution: &str, release: &str, name: &str, v: &str) -> Component {
    with(Component::new(product), |c| {
        c.distribution = distribution.into();
        c.distribution_version = release.into();
        c.package = name.into();
        c.version = v.into();
        c.trusted = true;
    })
}

/// 해시만 아는 파일.
fn hashed(product: Product, sha256: &str) -> Component {
    with(Component::new(product), |c| c.sha256 = sha256.into())
}

/// `node_rules` 의 해시 — 한 글자를 64번.
fn node_build(digit: &str) -> Component {
    hashed(Node, &digit.repeat(64))
}

/// Brotli 를 담아 지었고 의존 목록을 다 본, 출처를 믿을 수 있는 상류 Node.js.
fn bundled(version: &str) -> Component {
    with(official(Node, version), |c| {
        c.dependency_mode = Bundled;
        c.dependencies_complete = true;
    })
}

/// 공유 Brotli 를 연결한 Node.js.
fn shared(base: Component, dependencies: Vec<Component>, complete: bool) -> Component {
    with(base, |c| {
        c.dependency_mode = Shared;
        c.dependencies = dependencies;
        c.dependencies_complete = complete;
    })
}

// ── 내장 기준 ───────────────────────────────────────────────────────────

/// `TestDistributedBaselineMatchesBuiltin` — 서명 봉투 대신 파일의 SHA-256 과 줄 수를 못박는다.
#[test]
fn the_embedded_baseline_is_the_scanners_file() {
    let r = RuleSet::builtin();
    assert_eq!(r.version(), "2026-10-30.12");
    assert_eq!(r.issued_at(), "2026-10-30T01:46:17Z");
    // 스캐너 저장소(d3acb38)의 `data/baseline.json` 과 같은 바이트다 — 줄 끝만 바뀌어도 여기서 걸린다.
    let digest = "2fd679f46718d75841747396e71386bf38f31442a61d2344c64dd27dc2eb9b67";
    assert_eq!(r.sha256(), digest);
    assert!(r.supports(Php) && r.supports(Node) && r.supports(Brotli));

    let php = builtin(Php);
    assert_eq!(php.upstream.len(), 4);
    assert_eq!(php.legacy_php.as_ref().map(|l| l.branches.len()), Some(10));
    assert_eq!(php.advisories.len(), 63);
    assert_eq!(php.hashes.len(), 37);

    let node = builtin(Node);
    assert_eq!(node.upstream.len(), 3);
    assert_eq!(node.build_assessments.len(), 2);
    assert_eq!(node.advisories.len(), 14);
    assert_eq!(node.hashes.len(), 555);

    assert_eq!(builtin(Brotli).advisories.len(), 18);
}

/// `TestProductCVEIsolationAndOfficialBaseline`
#[test]
fn each_product_keeps_its_own_cves_and_priority_releases_are_judged() {
    let r = RuleSet::builtin();
    assert_eq!(r.cves(Php), PHP_CVES);
    assert_eq!(r.cves(Node), [BROTLI_CVE]);
    assert_eq!(r.cves(Brotli), [BROTLI_CVE]);
    for (version, want) in [
        ("22.23.4", Clear),
        ("24.22.1", Clear),
        ("26.12.1", Clear),
        ("22.23.3", Vulnerable),
        ("24.22.0", Vulnerable),
        ("26.12.0", Vulnerable),
        ("18.20.8", Vulnerable),
        ("20.20.2", Vulnerable),
    ] {
        let hashes = builtin(Node).hashes.iter();
        let builds: Vec<&HashRecord> = hashes.filter(|h| h.version == version).collect();
        assert!(!builds.is_empty(), "{version} 의 공식 빌드가 기준에 없다");
        for h in builds {
            let f = r.evaluate(&hashed(Node, &h.sha256), Lang::Ko);
            assert_eq!(f.status, want, "{version} {}", h.sha256);
            assert_eq!(f.cves, [BROTLI_CVE]);
        }
    }
}

/// 발견은 수집한 것이 말한 것을 그대로 싣는다 — 빈 칸은 없는 것으로.
#[test]
fn a_finding_carries_what_the_component_said() {
    let fixed = "8.1.2-1ubuntu2.28";
    let c = with(package(Php, "ubuntu", "22.04", "php8.1-fpm", fixed), |c| {
        c.id = "t:1".into();
        c.name = "시험 패키지".into();
        c.source = "dpkg status".into();
        c.runtime = "fpm".into();
    });
    let f = RuleSet::builtin().evaluate(&c, Lang::Ko);
    assert_eq!((f.id.as_str(), f.name.as_str()), ("t:1", "시험 패키지"));
    assert_eq!(f.product, Php);
    assert_eq!(f.path, None);
    assert_eq!(f.version.as_deref(), Some(fixed));
    assert_eq!(f.package.as_deref(), Some("php8.1-fpm"));
    assert_eq!(f.vendor.as_deref(), Some("ubuntu"));
    assert_eq!(f.runtime.as_deref(), Some("fpm"));
    assert_eq!(f.cves, PHP_CVES);
    let installed = &f.evidence[0];
    assert_eq!(installed.source, "dpkg status");
    assert_eq!(
        installed.detail,
        "설치 정보: ubuntu 22.04 / php8.1-fpm / 8.1.2-1ubuntu2.28"
    );
    let advisory = &f.evidence[1];
    assert_eq!(
        advisory.source,
        "https://ubuntu.com/security/notices/USN-8948-1"
    );
    assert!(advisory.detail.contains(fixed), "{}", advisory.detail);
    assert!(
        advisory.detail.ends_with(&PHP_CVES.join(", ")),
        "{}",
        advisory.detail
    );
    // 모르는 칸은 `-` 로 적는다.
    let bare = RuleSet::builtin().evaluate(&official(Php, "8.3.36"), Lang::En);
    assert_eq!(
        bare.evidence[0].detail,
        "Install info: upstream / - / 8.3.36"
    );
}

// ── PHP ─────────────────────────────────────────────────────────────────

/// `TestUbuntuBackportAndUnknown`
#[test]
fn ubuntu_backports_follow_the_vendor_line() {
    let r = RuleSet::builtin();
    let fpm = |version: &str| package(Php, "ubuntu", "22.04", "php8.1-fpm", version);
    assert_eq!(verdict(r, &fpm("8.1.2-1ubuntu2.27")), Vulnerable);
    assert_eq!(verdict(r, &fpm("8.1.2-1ubuntu2.28")), Clear);
    let untrusted = with(fpm("8.1.2-1ubuntu2.28"), |c| c.trusted = false);
    assert_eq!(verdict(r, &untrusted), Review);
    assert_eq!(verdict(r, &fpm("custom")), Review);
    // 패키지 이름이 없으면 맞는 공지가 없다.
    let nameless = package(Php, "debian", "12", "", "8.2.35");
    assert_eq!(verdict(r, &nameless), Review);
}

/// `TestDebianBackportAdvisories`
#[test]
fn debian_backports_follow_the_vendor_line() {
    let r = RuleSet::builtin();
    for (name, release, version, trusted, want) in [
        ("php8.2-fpm", "12", "8.2.28-1~deb12u1", true, Vulnerable),
        ("php8.2-cli", "12", "8.2.35-1~deb12u1", true, Clear),
        (
            "libapache2-mod-php8.2",
            "12",
            "8.2.35-1~deb12u1",
            true,
            Clear,
        ),
        ("php8.4-fpm", "13", "8.4.27-1~deb13u1", true, Clear),
        ("php8.4-cli", "13", "8.4.20-1~deb13u1", true, Vulnerable),
        ("php8.2-cli", "12", "8.2.35-1~deb12u1", false, Review),
    ] {
        let c = with(package(Php, "debian", release, name, version), |c| {
            c.trusted = trusted
        });
        assert_eq!(verdict(r, &c), want, "{name} {version} trusted={trusted}");
    }
}

/// `TestPHPVerdictsRemainStableAfterLegacyExpiry` — 시각을 바꿔 가며 보던 아홉 판정. 여기에는 시계가 없다.
#[test]
fn php_verdicts_at_the_boundaries() {
    let r = RuleSet::builtin();
    let ubuntu = |version: &str| package(Php, "ubuntu", "22.04", "php8.1-fpm", version);
    let debian = |release: &str, v: &str| package(Php, "debian", release, "php8.2-cli", v);
    for (c, want) in [
        (official(Php, "8.3.35"), Vulnerable),
        (official(Php, "8.3.36"), Clear),
        (official(Php, "custom"), Review),
        (ubuntu("8.1.2-1ubuntu2.27"), Vulnerable),
        (ubuntu("8.1.2-1ubuntu2.28"), Clear),
        (ubuntu("8.1.2-1ubuntu2.28+ppa1"), Review),
        (debian("12", "8.2.28-1~deb12u1"), Vulnerable),
        (debian("12", "8.2.35-1~deb12u1"), Clear),
        (debian("13", "8.2.35-1~deb12u1"), Review),
    ] {
        let at = format!(
            "{} {} {}",
            c.distribution, c.distribution_version, c.version
        );
        assert_eq!(verdict(r, &c), want, "{at}");
    }
}

/// `TestSignedSchemaCompatibilityWithoutExpiryLimit` · `TestUnpublishedOrUnverifiedRulesCannotClear` 가운데
/// 판정이 남는 쪽 — **기준은 만료되지 않는다.** `expires_at` 이 한참 지난 기준으로도 같은 판정이 나온다.
#[test]
fn criteria_do_not_expire() {
    let mut v = php_rules(vec![]);
    v["products"]["php"]["upstream"] = json!({"8.3": "8.3.36"});
    v["expires_at"] = json!("2000-01-01T00:00:00Z");
    let r = rules(&v);
    for (version, want) in [
        ("8.3.35", Vulnerable),
        ("8.3.36", Clear),
        ("custom", Review),
    ] {
        assert_eq!(verdict(&r, &official(Php, version)), want, "{version}");
    }
}

/// `TestUbuntuThirdPartySuffixIsNotVendorFix`
#[test]
fn a_third_party_suffix_does_not_inherit_the_ubuntu_fix() {
    let r = RuleSet::builtin();
    for version in [
        "8.1.2-1ubuntu2.28+ppa1",
        "1:8.1.2-1ubuntu2.28",
        "8.3.36-custom",
        "8.1.2-1ubuntu2.999evil",
    ] {
        let c = package(Php, "ubuntu", "22.04", "php8.1-fpm", version);
        assert_eq!(verdict(r, &c), Review, "{version}");
    }
}

/// `TestReviewDebianThirdPartyBuildCannotInheritOfficialFix`
#[test]
fn a_third_party_debian_build_does_not_inherit_the_fix() {
    let row = fixed_row("debian", "12", "php8.2-cli", "debian", "8.2.35-1~deb12u1");
    let r = rules(&php_rules(vec![row]));
    let dpkg = |version: &str| {
        with(package(Php, "debian", "12", "php8.2-cli", version), |c| {
            c.package_manager = Dpkg
        })
    };
    for version in [
        "8.2.35-1~deb12u1+ppa1",
        "1:8.2.28-1~deb12u1",
        "8.2.999-custom",
    ] {
        assert_eq!(verdict(&r, &dpkg(version)), Review, "{version}");
    }
    // 대조 — 같은 기준에서 Debian 의 줄에 든 버전은 판정된다.
    assert_eq!(verdict(&r, &dpkg("8.2.35-1~deb12u1")), Clear);
    assert_eq!(verdict(&r, &dpkg("8.2.28-1~deb12u1")), Vulnerable);
}

/// `TestOfficialPHPHashesCoverServerVariantsAndWindowsCore` — 스캐너의 목록 파일과 대조하던 부분은 옮기지
/// 않았다. 기준의 8.3.35 · 8.3.36 해시가, 적힌 버전을 이기는가만 본다.
#[test]
fn an_official_hash_overrides_an_untrusted_version() {
    let r = RuleSet::builtin();
    let mut seen = 0;
    for h in &builtin(Php).hashes {
        let want = match h.version.as_str() {
            "8.3.35" => Vulnerable,
            "8.3.36" => Clear,
            _ => continue,
        };
        let c = with(hashed(Php, &h.sha256), |c| c.version = "99.99.99".into());
        let f = r.evaluate(&c, Lang::Ko);
        assert_eq!(f.status, want, "{}", h.sha256);
        assert_eq!(f.version.as_deref(), Some(h.version.as_str()));
        seen += 1;
    }
    assert_eq!(seen, 32);
    // 해시가 맞지 않으면 버전만으로는 판정하지 않는다.
    for version in ["8.3.35", "8.3.36"] {
        let c = with(hashed(Php, &"f".repeat(64)), |c| c.version = version.into());
        assert_eq!(verdict(r, &c), Review, "{version}");
    }
    // 해시의 대소문자는 가리지 않는다.
    let h = &builtin(Php).hashes[0];
    let upper = r.evaluate(&hashed(Php, &h.sha256.to_ascii_uppercase()), Lang::Ko);
    assert_eq!(upper.version.as_deref(), Some(h.version.as_str()));
    assert_ne!(upper.status, Review);
}

/// `TestLegacyPHPOfficialCatalogHashes` — 목록 파일 대신 내장 기준의 해시 줄로 본다(5.6.40 둘 · 7.4.33 셋).
#[test]
fn a_legacy_official_hash_overrides_what_the_fields_say() {
    let r = RuleSet::builtin();
    let hashes = builtin(Php).hashes.iter();
    let legacy: Vec<&HashRecord> = hashes
        .filter(|h| h.version == "5.6.40" || h.version == "7.4.33")
        .collect();
    assert_eq!(legacy.len(), 5);
    for h in legacy {
        let c = with(hashed(Php, &h.sha256), |c| {
            c.version = "99.99.99".into();
            c.package = "unverified-package".into();
            c.distribution = "unverified-vendor".into();
        });
        let f = r.evaluate(&c, Lang::Ko);
        assert_eq!(f.status, Vulnerable, "{}", h.sha256);
        assert_eq!(f.version.as_deref(), Some(h.version.as_str()));
    }
}

/// `TestLegacyPHPUpstreamAndUnknownBuilds`
#[test]
fn end_of_life_branches_are_vulnerable_only_as_official_builds() {
    let r = RuleSet::builtin();
    for version in [
        "5.4.0", "5.4.45", "5.5.38", "5.6.40", "7.0.33", "7.1.33", "7.2.34", "7.3.33", "7.4.33",
        "8.0.30", "8.1.34",
    ] {
        let f = r.evaluate(&official(Php, version), Lang::Ko);
        assert_eq!(f.status, Vulnerable, "{version}");
        assert!(f.reason.contains("하나 이상"), "{}", f.reason);
        // 같은 버전이어도 출처를 증명하지 못한 빌드는 판정하지 않는다 — 영향 범위라는 것만 알린다.
        let nameless = with(Component::new(Php), |c| c.version = version.into());
        let f = r.evaluate(&nameless, Lang::Ko);
        assert_eq!(f.status, Review, "{version}");
        assert!(f.reason.contains("구버전"), "{}", f.reason);
        for unproven in [
            with(official(Php, version), |c| c.distribution = "vendor".into()),
            with(official(Php, version), |c| c.trusted = false),
            with(official(Php, version), |c| c.package = "php-cli".into()),
        ] {
            assert_eq!(verdict(r, &unproven), Review, "{version} {unproven:?}");
        }
    }
    for version in [
        "5.3.29",
        "5.7.0",
        "6.0.0",
        "7.5.0",
        "5.6.40-custom",
        "7.4.33RC1",
        "07.4.33",
        "7.4",
        "7.4.33.1",
    ] {
        assert_eq!(verdict(r, &official(Php, version)), Review, "{version}");
    }
}

/// `TestLegacyPHPUbuntuESM`
#[test]
fn ubuntu_esm_lines_are_compared() {
    let r = RuleSet::builtin();
    // 배포판 버전 · 패키지 이름의 앞머리 · 그 줄의 버전 · 수정된 ESM 번호(그 앞 번호는 고치기 전이다).
    for (release, base, line, esm) in [
        ("14.04", "php5", "5.5.9+dfsg-1ubuntu4.29", 18),
        ("16.04", "php7.0", "7.0.33-0ubuntu0.16.04.16", 22),
        ("18.04", "php7.2", "7.2.24-0ubuntu0.18.04.17", 14),
        ("20.04", "php7.4", "7.4.3-4ubuntu2.29", 5),
    ] {
        let before = format!("{line}+esm{}", esm - 1);
        let fixed = format!("{line}+esm{esm}");
        for name in [
            format!("{base}-cli"),
            format!("{base}-cgi"),
            format!("{base}-fpm"),
            format!("libapache2-mod-{base}"),
        ] {
            for (version, want) in [
                (before.clone(), Vulnerable),
                (fixed.clone(), Clear),
                (format!("{fixed}+ppa1"), Review),
                (format!("{fixed}-custom"), Review),
                (format!("1:{fixed}"), Review),
            ] {
                let c = package(Php, "ubuntu", release, &name, &version);
                assert_eq!(verdict(r, &c), want, "{name} {version}");
            }
        }
        let cli = package(Php, "ubuntu", release, &format!("{base}-cli"), &fixed);
        let untrusted = with(cli, |c| c.trusted = false);
        assert_eq!(verdict(r, &untrusted), Review, "{release}");
    }
}

// ── Node.js · Brotli ────────────────────────────────────────────────────

/// `TestNodeOfficialBuildAndUntrustedVersions`
#[test]
fn node_official_builds_and_untrusted_versions() {
    let r = rules(&node_rules());
    let old_brotli = with(Component::new(Brotli), |c| c.version = "1.1.0".into());
    let with_old_brotli = with(node_build("1"), |c| {
        c.dependency_mode = Bundled;
        c.dependencies = vec![old_brotli];
    });
    let by_string = with(Component::new(Node), |c| {
        c.version = "24.22.1".into();
        c.trusted = true;
    });
    let untrusted = with(bundled("24.22.1"), |c| c.trusted = false);
    let deb = |version: &str| package(Node, "debian", "13", "nodejs", version);
    let (unfixed, other) = (deb("20.19.2+dfsg-1+deb13u3"), deb("20.19.2+dfsg-1+deb13u4"));
    for (name, c, want) in [
        ("fixed hash", node_build("1"), Clear),
        ("fixed build, old Brotli string", with_old_brotli, Clear),
        ("unfixed hash", node_build("2"), Vulnerable),
        ("end-of-life hash", node_build("3"), Review),
        ("untrusted upstream string", untrusted, Review),
        ("prerelease", bundled("24.22.1-rc.1"), Review),
        ("unknown line", bundled("28.0.0"), Review),
        ("unknown dependency mode", by_string, Review),
        ("vendor confirmed exact", unfixed, Vulnerable),
        ("vendor different version", other, Review),
        // 스캐너의 표에 없던 두 줄 — 출처를 믿을 수 있는 상류 빌드는 수정 버전과 견준다.
        ("trusted bundled fixed", bundled("24.22.1"), Clear),
        ("trusted bundled unfixed", bundled("24.22.0"), Vulnerable),
    ] {
        let f = r.evaluate(&c, Lang::Ko);
        assert_eq!(f.status, want, "{name}");
        assert_eq!(f.product, Node, "{name}");
        assert_eq!(f.cves, [BROTLI_CVE], "{name}");
    }
}

/// `TestNodeSharedBrotliUsesActualVendorEvidence`
#[test]
fn shared_brotli_is_judged_by_the_library_actually_linked() {
    let r = rules(&node_rules());
    let library = |distribution: &str, release: &str, version: &str| {
        with(
            package(Brotli, distribution, release, "libbrotli1", version),
            |c| c.path = "/usr/lib/libbrotlidec.so.1".into(),
        )
    };
    let vulnerable = || library("debian", "13", "1.1.0-2");
    let patched = || library("fixture", "1", "1.1.0-2+fixture1");
    let untrusted = with(vulnerable(), |c| c.trusted = false);
    let ubuntu = library("ubuntu", "26.04", "1.2.0-1");
    for (name, digit, dependencies, complete, want) in [
        (
            "fixed Node, vulnerable library",
            "1",
            vec![vulnerable()],
            true,
            Vulnerable,
        ),
        (
            "old Node, patched library",
            "2",
            vec![patched()],
            true,
            Clear,
        ),
        ("library not located", "1", vec![], false, Review),
        ("incomplete list", "1", vec![patched()], false, Review),
        (
            "vulnerable before a collection gap",
            "1",
            vec![vulnerable()],
            false,
            Vulnerable,
        ),
        (
            "plain 1.1.0 string",
            "1",
            vec![official(Brotli, "1.1.0")],
            true,
            Review,
        ),
        (
            "plain 1.2.0 string",
            "1",
            vec![official(Brotli, "1.2.0")],
            true,
            Review,
        ),
        ("untrusted package", "1", vec![untrusted], true, Review),
        ("Ubuntu not evaluated", "1", vec![ubuntu], true, Review),
    ] {
        let c = shared(node_build(digit), dependencies, complete);
        assert_eq!(verdict(&r, &c), want, "{name}");
    }
}

/// `TestNodeVerdictsRemainStableAfterLegacyExpiry`
#[test]
fn node_verdicts_at_the_boundaries() {
    let r = rules(&node_rules());
    let patched = package(Brotli, "fixture", "1", "libbrotli1", "1.1.0-2+fixture1");
    for (c, want) in [
        (node_build("1"), Clear),
        (node_build("2"), Vulnerable),
        (node_build("3"), Review),
        (shared(node_build("2"), vec![patched], true), Clear),
    ] {
        let at = format!("{:?} {}", c.dependency_mode, c.sha256);
        assert_eq!(verdict(&r, &c), want, "{at}");
    }
}

/// `TestAuthenticatedNodeHashLookupRetainsIdentityAfterExpiry`
#[test]
fn a_node_hash_names_its_version() {
    let r = rules(&node_rules());
    assert_eq!(r.node_hash_version(&"1".repeat(64)), Some("24.22.1"));
    let unknown = "f".repeat(64);
    for hash in ["", "not-a-hash", unknown.as_str()] {
        assert_eq!(r.node_hash_version(hash), None, "{hash:?}");
    }
    // Node.js 가 없는 기준에서는 어떤 해시도 이름이 없다.
    let php_only = rules(&php_rules(vec![]));
    assert_eq!(php_only.node_hash_version(&"1".repeat(64)), None);
    // 내장 기준 — 대소문자를 가리지 않는다.
    let h = &builtin(Node).hashes[0];
    let upper = h.sha256.to_ascii_uppercase();
    let named = RuleSet::builtin().node_hash_version(&upper);
    assert_eq!(named, Some(h.version.as_str()));
}

/// `TestKnownEOLBuildRequiresOfficialHashAndCodeEvidence`
#[test]
fn an_end_of_life_node_needs_the_official_hash_and_code_evidence() {
    let r = RuleSet::builtin();
    // 버전 문자열만으로는 — 출처를 믿을 수 있어도 — 지원이 끝난 계열을 취약이라 하지 않는다.
    assert_eq!(verdict(r, &bundled("18.20.8")), Review);
    let mut seen = 0;
    for h in &builtin(Node).hashes {
        if h.version != "18.20.8" && h.version != "20.20.2" {
            continue;
        }
        let f = r.evaluate(&hashed(Node, &h.sha256), Lang::Ko);
        assert_eq!(f.status, Vulnerable, "{}", h.sha256);
        assert!(f.reason.contains("미수정 코드"), "{}", f.reason);
        assert!(f.evidence.len() >= 5, "{:?}", f.evidence);
        seen += 1;
    }
    assert_eq!(seen, 11);
}

/// `TestReviewUpstreamOSIDCannotAuthenticateNodePackage`
#[test]
fn an_os_id_named_upstream_does_not_vouch_for_a_node_package() {
    let r = rules(&node_rules());
    for version in ["24.22.0", "24.22.1"] {
        let mut c = with(bundled(version), |c| {
            c.package = "nodejs".into();
            c.package_manager = Rpm;
        });
        assert_eq!(verdict(&r, &c), Review, "{version}");
        // 패키지 칸이 무엇이든 공식 빌드의 해시가 맞으면 그 빌드로 판정한다.
        c.sha256 = "2".repeat(64);
        assert_eq!(verdict(&r, &c), Vulnerable, "{version}");
        c.sha256 = "1".repeat(64);
        assert_eq!(verdict(&r, &c), Clear, "{version}");
    }
}

/// `TestLegacySchemaVerifiedBeforePHPConversion` 가운데 한 줄 — PHP 만 있는 기준은 다른 제품을 판정하지 않는다.
/// 옛 형식(1)과 그 서명은 옮기지 않았다.
#[test]
fn a_product_missing_from_the_criteria_needs_review() {
    let r = rules(&php_rules(vec![]));
    assert!(r.supports(Php) && !r.supports(Node) && !r.supports(Brotli));
    let f = r.evaluate(&official(Node, "24.22.1"), Lang::Ko);
    assert_eq!(f.status, Review);
    assert!(f.cves.is_empty());
    let library = package(Brotli, "debian", "13", "libbrotli1", "1.1.0-2");
    assert_eq!(verdict(&r, &library), Review);
}

// ── RPM 줄 ──────────────────────────────────────────────────────────────

/// `TestSignedRPMAdvisoryBoundaries`
#[test]
fn rpm_rows_match_only_their_vendor_line() {
    let r = rules(&php_rules(vec![rpm_row()]));
    let bare = RPM_FIXED.trim_start_matches("0:");
    let edit = |f: fn(&mut Component)| with(rpm_component(), f);
    let version = |v: &str| with(rpm_component(), |c| c.version = v.into());
    let module = |m: &str| with(rpm_component(), |c| c.package_module = m.into());
    for (name, c, want) in [
        ("equal", rpm_component(), Clear),
        ("before", version(&format!("0:{RPM_OLDER}")), Vulnerable),
        (
            "after",
            version("0:7.4.33-9.module+el8.10.0+2346+abcd1234"),
            Clear,
        ),
        ("implicit zero epoch", version(bare), Clear),
        (
            "missing architecture",
            edit(|c| c.architecture.clear()),
            Review,
        ),
        (
            "different architecture",
            edit(|c| c.architecture = "aarch64".into()),
            Review,
        ),
        ("missing vendor", edit(|c| c.package_vendor.clear()), Review),
        (
            "third party vendor",
            edit(|c| c.package_vendor = "Remi's RPM repository".into()),
            Review,
        ),
        (
            "third party suffix",
            version(&format!("{RPM_FIXED}.remi")),
            Review,
        ),
        ("missing module", module(""), Review),
        (
            "different stream",
            module("php:8.2:8100020261021081045:abcd1234"),
            Review,
        ),
        ("invalid module", module("php:7.4::abcd1234"), Review),
        (
            "matching module architecture",
            module(&format!("{RPM_MODULE}:i686")),
            Clear,
        ),
        (
            "different module architecture",
            module(&format!("{RPM_MODULE}:x86_64")),
            Review,
        ),
        (
            "SCL package",
            edit(|c| c.package = "rh-php74-php-cli".into()),
            Review,
        ),
        (
            "different distro",
            edit(|c| c.distribution = "ol".into()),
            Review,
        ),
        (
            "different release",
            edit(|c| c.distribution_version = "8.8".into()),
            Review,
        ),
        (
            "different package line",
            version("0:8.2.35-9.module+el8.10.0+2346+abcd1234"),
            Review,
        ),
        ("invalid epoch", version(&format!("bad:{bare}")), Review),
        ("unexpected epoch", version(&format!("99:{bare}")), Review),
        ("untrusted file", edit(|c| c.trusted = false), Review),
    ] {
        assert_eq!(verdict(&r, &c), want, "{name}");
    }
    // 스캐너가 시각을 바꿔 가며 보던 세 판정 — epoch 을 적지 않은 옛 버전, 그리고 아키텍처를 모를 때.
    let older = version(RPM_OLDER);
    assert_eq!(verdict(&r, &older), Vulnerable);
    let unscoped = with(older, |c| c.architecture.clear());
    assert_eq!(verdict(&r, &unscoped), Review);
}

/// 옮겨 온 rpm 비교가 스캐너와 갈리는 자리(`version` 의 시험)는 판정에 닿지 않는다 — 스캐너에는 없던 시험이다.
#[test]
fn rpm_versions_too_long_or_without_a_release_are_not_compared() {
    // 길이 — 줄의 범위는 지나지만(`[0-9a-f]+`) 256바이트를 넘는다.
    let r = rules(&php_rules(vec![rpm_row()]));
    let tail = "a".repeat(300);
    let long = with(rpm_component(), |c| {
        c.version = format!("0:7.4.33-9.module+el8.10.0+2346+{tail}")
    });
    assert_eq!(verdict(&r, &long), Review);
    let short = with(rpm_component(), |c| {
        c.version = "0:7.4.33-9.module+el8.10.0+2346+aaaa".into()
    });
    assert_eq!(verdict(&r, &short), Clear);

    // 개정 — 범위가 개정 없는 버전을 받는 줄이어도, 개정이 없으면 견주지 않는다.
    let mut row = rpm_row();
    row["module"] = json!("");
    row["fixed"] = json!("0:7.4.33-8.el8");
    row["version_pattern"] = json!(r"^(?:0:)?7\.4\.[0-9]+(?:-[0-9]+\.el8)?$");
    let r = rules(&php_rules(vec![row]));
    let plain = |version: &str| {
        with(rpm_component(), |c| {
            c.version = version.into();
            c.package_module.clear();
        })
    };
    assert_eq!(verdict(&r, &plain("7.4.33-8.el8")), Clear);
    assert_eq!(verdict(&r, &plain("7.4.33-7.el8")), Vulnerable);
    for version in ["7.4.33", "7.4.40", "7.4.1"] {
        assert_eq!(verdict(&r, &plain(version)), Review, "{version}");
    }
}

/// `TestRPMRequiresEveryPHPCVEForClear`
#[test]
fn an_rpm_row_must_cover_every_cve_to_clear() {
    let only = |cve: &str| {
        let mut row = rpm_row();
        row["cves"] = json!([cve]);
        row
    };
    let (first, second) = (only(PHP_CVES[0]), only(PHP_CVES[1]));
    let older = with(rpm_component(), |c| c.version = RPM_OLDER.into());

    let one = rules(&php_rules(vec![first.clone()]));
    let f = one.evaluate(&rpm_component(), Lang::Ko);
    assert_eq!(f.status, Review);
    assert!(f.reason.contains("모두의"), "{}", f.reason);
    assert_eq!(verdict(&one, &older), Vulnerable);

    let both = rules(&php_rules(vec![first, second]));
    assert_eq!(verdict(&both, &rpm_component()), Clear);
}

/// `TestSignedRPMRejectsMissingAndInvalidScope` — 엔진 버전을 보던 마지막 줄은 옮기지 않았다.
#[test]
fn an_rpm_row_without_a_full_scope_is_refused() {
    assert!(!refused(&php_rules(vec![rpm_row()])));
    // 칸 하나를 바꾸거나(`Some`) 뺀다(`None`).
    for (name, key, value) in [
        ("missing architecture", "architectures", None),
        (
            "duplicate architecture",
            "architectures",
            Some(json!(["i686", "i686"])),
        ),
        (
            "invalid architecture",
            "architectures",
            Some(json!(["i686\n"])),
        ),
        ("missing vendor", "vendor", None),
        ("missing CVEs", "cves", None),
        ("unknown CVE", "cves", Some(json!([BROTLI_CVE]))),
        (
            "duplicate CVE",
            "cves",
            Some(json!([PHP_CVES[0], PHP_CVES[0]])),
        ),
        ("invalid fixed epoch", "fixed", Some(json!("x:7.4.33-8"))),
        ("missing release", "fixed", Some(json!("7.4.33"))),
        ("missing line", "version_pattern", None),
        ("unanchored line", "version_pattern", Some(json!("7.4.33"))),
        ("invalid line", "version_pattern", Some(json!("^[$"))),
        (
            "fixed outside line",
            "version_pattern",
            Some(json!(r"^8\..*$")),
        ),
        ("unscoped module", "module", Some(json!("php"))),
        (
            "module with build",
            "module",
            Some(json!("php:7.4:123:abc")),
        ),
    ] {
        let mut row = rpm_row();
        let fields = row.as_object_mut().expect("줄은 객체다");
        match value {
            Some(value) => fields.insert(key.to_string(), value),
            None => fields.remove(key),
        };
        assert!(refused(&php_rules(vec![row])), "{name}");
    }
}

/// `TestRPMNodeStillRequiresBrotliCollection`
#[test]
fn a_patched_node_rpm_still_needs_the_brotli_linkage() {
    const FIXED: &str = "1:22.23.2-2.0.1.module+el8.10.0+2345+abcd1234";
    let mut row = rpm_row();
    row["distribution"] = json!("ol");
    row["package"] = json!("nodejs");
    row["module"] = json!("nodejs:22");
    row["vendor"] = json!("Oracle America");
    row["fixed"] = json!(FIXED);
    row["version_pattern"] = json!(concat!(
        r"^1:22\.[0-9]+\.[0-9]+-[0-9]+(?:\.[0-9]+)*",
        r"\.module\+el8\.10\.0\+[0-9]+\+[0-9a-f]+$"
    ));
    row["cves"] = json!([BROTLI_CVE]);
    let mut v = node_rules();
    v["products"] = json!({
        "node": {
            "cves": [BROTLI_CVE],
            "source": "https://example.invalid/node",
            "advisories": [row],
        }
    });
    let r = rules(&v);
    let mut c = with(package(Node, "ol", "8.10", "nodejs", FIXED), |c| {
        c.architecture = "x86_64".into();
        c.package_vendor = "Oracle America".into();
        c.package_module = "nodejs:22:8100020261021081045:abcd1234".into();
    });
    // 고친 패키지여도 Brotli 를 어떻게 쓰는지 모르면 양호가 아니다.
    assert_eq!(verdict(&r, &c), Review);
    c.dependency_mode = Bundled;
    c.dependencies_complete = true;
    assert_eq!(verdict(&r, &c), Clear);
    c.dependencies_complete = false;
    assert_eq!(verdict(&r, &c), Review);
    // 의존 목록을 다 보지 못했어도, 공급사 기준으로 고치기 전인 패키지는 취약이다.
    c.version = "1:22.23.2-2.module+el8.10.0+2344+abcd1234".into();
    assert_eq!(verdict(&r, &c), Vulnerable);
}

/// `TestRPMCannotInheritDebianOrUpstreamPackageAdvisories`
#[test]
fn an_rpm_package_does_not_inherit_dpkg_or_upstream_rows() {
    for (distribution, release, name, how, fixed) in [
        (
            "ubuntu",
            "24.04",
            "php8.3-cli",
            "debian",
            "8.3.6-0ubuntu0.24.04.13",
        ),
        ("debian", "12", "php8.2-cli", "debian", "8.2.29-1~deb12u9"),
        ("custom", "1", "php-cli", "upstream", "8.3.36"),
    ] {
        let row = fixed_row(distribution, release, name, how, fixed);
        let r = rules(&php_rules(vec![row]));
        let mut c = with(package(Php, distribution, release, name, fixed), |c| {
            c.package_vendor = "Third-party RPM".into();
            c.architecture = "i686".into();
            c.package_manager = Rpm;
        });
        assert_eq!(verdict(&r, &c), Review, "{distribution} rpm");
        c.package_manager = Dpkg;
        assert_eq!(verdict(&r, &c), Clear, "{distribution} dpkg");
    }
}

/// `TestRPMManagerDoesNotSuppressOfficialFileHash`
#[test]
fn an_official_hash_wins_over_the_rpm_manager() {
    let mut v = php_rules(vec![]);
    v["products"]["php"]["upstream"] = json!({"8.3": "8.3.36"});
    v["products"]["php"]["hashes"] = json!([{
        "sha256": "c".repeat(64),
        "version": "8.3.36",
        "source": "https://www.php.net/",
    }]);
    let c = with(hashed(Php, &"c".repeat(64)), |c| {
        c.package = "php-cli".into();
        c.package_manager = Rpm;
        c.distribution = "ubuntu".into();
        c.version = "custom".into();
    });
    let f = rules(&v).evaluate(&c, Lang::Ko);
    assert_eq!(f.status, Clear);
    assert_eq!(f.version.as_deref(), Some("8.3.36"));
}

// ── 읽기에서 거절하는 기준 ──────────────────────────────────────────────

/// `TestSignedBundleTamperingRollbackAndSchema` 가운데 형식 번호 — 서명과 되돌림은 여기에 없다.
#[test]
fn an_unknown_schema_or_field_is_refused() {
    assert!(!refused(&php_rules(vec![])));
    let mut future = php_rules(vec![]);
    future["schema_version"] = json!(3);
    assert!(refused(&future));
    let mut surprise = php_rules(vec![]);
    surprise["products"]["php"]["surprise"] = json!(true);
    assert!(refused(&surprise));
    let mut unknown_product = php_rules(vec![]);
    unknown_product["products"]["python"] = unknown_product["products"]["php"].clone();
    assert!(refused(&unknown_product));
    assert!(RuleSet::from_json("").is_err());
    let trailing = format!("{} {{}}", php_rules(vec![]));
    assert!(RuleSet::from_json(&trailing).is_err());
}

/// `TestInvalidSignedFixedVersionsRejected`
#[test]
fn malformed_fixed_versions_are_refused() {
    let row = |how: &str, fixed: &str| php_rules(vec![fixed_row("vendor", "1", "php", how, fixed)]);
    // 대조 — 같은 줄에 견줄 수 있는 수정 버전을 적으면 읽힌다.
    assert!(!refused(&row("upstream", "8.3.36")));
    assert!(!refused(&row("debian", "8.3.36-1")));
    for (how, fixed) in [
        ("upstream", "oops"),
        ("upstream", "8.3.999999999999999999999999"),
        ("debian", "invalid"),
        ("debian", "8.3.36\n"),
        ("debian", "8.3.36-"),
        ("debian", "8.3.36-1:2"),
    ] {
        assert!(refused(&row(how, fixed)), "{how} {fixed:?}");
    }
    // 입력 쪽의 넘치는 숫자도 판정하지 않는다.
    let oversized = official(Php, "8.3.999999999999999999999999");
    assert_eq!(verdict(RuleSet::builtin(), &oversized), Review);
}

/// `TestLegacyPHPRuleValidation` — 엔진 버전을 보던 한 줄은 옮기지 않았다.
#[test]
fn a_bad_legacy_branch_rule_is_refused() {
    let legacy = |branch: &str, source: &str| {
        let mut v = php_rules(vec![]);
        v["products"]["php"]["upstream"] = json!({"8.2": "8.2.35"});
        v["products"]["php"]["legacy_php"] = json!({"branches": [branch], "source": source});
        v
    };
    assert!(!refused(&legacy("7.4", "https://example.com/")));
    for (branch, source) in [
        ("5.3", "https://example.com/"),
        ("8.2", "https://example.com/"),
        ("7.4", "http://example.com/"),
    ] {
        assert!(refused(&legacy(branch, source)), "{branch} {source}");
    }
}

/// `TestSchema2SignedGuards` — 기준 번호와 엔진 버전을 보던 세 줄은 옮기지 않았다.
#[test]
fn malformed_product_rows_are_refused() {
    fn assessment(evidence: Value) -> Value {
        json!([{
            "version": "18.20.8",
            "status": "vulnerable",
            "dependency_version": "1.1.0",
            "source": "https://www.cve.org/CVERecord?id=CVE-2026-111497",
            "evidence": evidence,
        }])
    }
    assert!(!refused(&node_rules()));
    let broken = |edit: fn(&mut Value)| {
        let mut v = node_rules();
        edit(&mut v);
        refused(&v)
    };
    // 옛 형식의 칸이 섞였다.
    assert!(broken(|v| v["upstream"] = json!({"8.3": "8.3.36"})));
    // 다른 제품의 CVE.
    assert!(broken(
        |v| v["products"]["node"]["cves"] = json!([PHP_CVES[0]])
    ));
    // 공급사가 아직 평가하지 않았다는 것은 수정됐다는 근거가 아니다.
    assert!(broken(|v| {
        v["products"]["node"]["advisories"][0]["status"] = json!("Needs evaluation")
    }));
    // 한 해시에 두 버전.
    assert!(broken(|v| {
        v["products"]["node"]["hashes"] =
            json!([node_hash_row("1", "24.22.1"), node_hash_row("1", "24.22.0")])
    }));
    // 원본 근거가 없는 영향 판정.
    assert!(broken(|v| {
        v["products"]["node"]["build_assessments"] = assessment(json!([]))
    }));
    // 대조 — 원본 근거가 둘 있으면 읽힌다.
    assert!(!broken(|v| {
        let source = json!({
            "source": "https://example.invalid/decode.c",
            "sha256": "a".repeat(64),
            "detail": "시험 근거",
        });
        v["products"]["node"]["build_assessments"] = assessment(json!([source.clone(), source]))
    }));
}

// ── 글 ──────────────────────────────────────────────────────────────────

fn hangul(c: char) -> bool {
    matches!(c, '\u{1100}'..='\u{11FF}' | '\u{3130}'..='\u{318F}' | '\u{AC00}'..='\u{D7A3}')
}

/// 판정 문장 스무 가지를 다 지나는 발견들.
fn every_kind_of_finding(lang: Lang) -> Vec<Finding> {
    let r = RuleSet::builtin();
    let node_hash = |version: &str| {
        let h = builtin(Node).hashes.iter().find(|h| h.version == version);
        hashed(Node, &h.expect("그 버전의 공식 빌드").sha256)
    };
    let rhel = |product: Product, release: &str, name: &str, version: &str| {
        with(package(product, "rhel", release, name, version), |c| {
            c.architecture = "x86_64".into();
            c.package_vendor = "Red Hat, Inc.".into();
            c.package_manager = Rpm;
        })
    };
    let linked = |dependencies: Vec<Component>| shared(Component::new(Node), dependencies, true);
    let ubuntu = |version: &str| package(Php, "ubuntu", "22.04", "php8.1-fpm", version);
    let components = [
        // PHP
        with(Component::new(Php), |c| c.version = "8.3.36".into()),
        with(Component::new(Php), |c| c.version = "7.4.33".into()),
        with(official(Php, "8.3.36"), |c| c.package = "php-cli".into()),
        official(Php, "8.3.35"),
        official(Php, "8.3.36"),
        official(Php, "8.9.9"),
        official(Php, "7.4.33"),
        hashed(Php, &builtin(Php).hashes[0].sha256),
        // 공급사 공지
        ubuntu("8.1.2-1ubuntu2.27"),
        ubuntu("8.1.2-1ubuntu2.28"),
        rhel(Php, "7.9", "php", "5.4.16-48.el7_9.1"),
        // Node.js
        node_hash("18.20.8"),
        node_hash("24.22.0"),
        node_hash("24.22.1"),
        bundled("18.20.8"),
        with(official(Node, "24.22.1"), |c| c.package = "nodejs".into()),
        package(Node, "debian", "13", "nodejs", "99.0.0-1"),
        linked(vec![package(
            Brotli,
            "debian",
            "13",
            "libbrotli1",
            "1.1.0-2",
        )]),
        linked(vec![]),
        linked(vec![rhel(Brotli, "8.10", "brotli", "1.0.6-5.el8_10")]),
    ];
    let mut findings: Vec<Finding> = components.iter().map(|c| r.evaluate(c, lang)).collect();
    // 기준에 그 제품이 없을 때의 문장.
    findings.push(rules(&php_rules(vec![])).evaluate(&official(Node, "24.22.1"), lang));
    findings
}

/// 사람이 읽는 칸은 두 언어로 다 있다 — 영어 실행에 한글이 섞이지 않고, 한국어 문장은 합쇼체다.
#[test]
fn every_sentence_exists_in_both_languages() {
    let ko = every_kind_of_finding(Lang::Ko);
    let en = every_kind_of_finding(Lang::En);
    let reasons: BTreeSet<&str> = ko.iter().map(|f| f.reason.as_str()).collect();
    assert_eq!(reasons.len(), 20, "판정 문장 스무 가지: {reasons:#?}");
    let statuses: BTreeSet<Status> = ko.iter().map(|f| f.status).collect();
    assert_eq!(statuses.len(), 3);
    for (k, e) in ko.iter().zip(&en) {
        assert_eq!(k.status, e.status);
        assert_eq!(k.evidence.len(), e.evidence.len());
        let details = e.evidence.iter().map(|x| &x.detail);
        for text in [&e.reason, &e.action].into_iter().chain(details) {
            assert!(!text.is_empty() && !text.chars().any(hangul), "{text}");
        }
        for text in [&k.reason, &k.action] {
            let polite = text.ends_with("니다.") || text.ends_with("십시오.");
            assert!(polite, "{text}");
            for word in [
                "주세요",
                "꾸러미",
                "금고",
                "열쇠",
                "파괴",
                "흔적",
                "회차",
                "저널",
            ] {
                assert!(!text.contains(word), "{word}: {text}");
            }
        }
        for x in &k.evidence {
            assert!(x.detail.chars().any(hangul), "{}", x.detail);
        }
    }
}

/// 기준 데이터의 근거 설명은 한국어뿐이다 — 영어 문장이 코드에 다 있는가.
#[test]
fn every_build_evidence_detail_has_an_english_form() {
    let builds = builtin(Node).build_assessments.iter();
    let details: BTreeSet<&str> = builds
        .flat_map(|b| &b.evidence)
        .map(|e| e.detail.as_str())
        .collect();
    assert_eq!(details.len(), 4);
    for detail in details {
        assert_ne!(detail_en(detail), detail_en(""), "{detail}");
    }
}
