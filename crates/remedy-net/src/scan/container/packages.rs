//! 컨테이너의 패키지 기록 — dpkg `status` · apk `installed` 를 읽고, 패키지 이름으로 제품을 가른다.
//!
//! 스캐너 `scan.go` 의 `parseDPKG` · `parseAPK` 와 `node.go` 의 `packageProduct` 를 옮겼다. 이미지 점검의 패키지
//! 판독과 규칙이 다르다 — 이것이 컨테이너의 것이다.
//!
//! **믿을 수 있는 기록**은 dpkg 의 것 가운데 레코드의 꼴이 온전하고(겹친 칸 · 깨진 줄 · 틀린 아키텍처가 없고)
//! 관리자가 그 배포판의 공식 주소인 것뿐이다(Debian: `@lists.alioth.debian.org>` · `@tracker.debian.org>`,
//! Ubuntu: `@lists.ubuntu.com>`). apk 의 설치 기록은 저장소 · 서명 출처를 말하지 않아 늘 믿지 않는다.

use super::gostr::lower;
use crate::scan::linuxmeta;
use crate::scan::model::Product;
use crate::scan::rules::Component;
use regex::Regex;
use remedy_sdk::i18n::Lang;
use std::collections::HashMap;
use std::sync::OnceLock;

fn php_package() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"^(?:php(?:-(?:cli|cgi|fpm|embed|apache2|apache))?",
            r"|php[0-9]+(?:\.[0-9]+)?(?:-[a-z0-9+.-]+)?",
            r"|libapache2-mod-php[0-9]+(?:\.[0-9]+)?)$",
        ))
        .expect("고정된 정규식")
    })
}

fn node_package() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:nodejs(?:-libs)?|node|libnode[0-9]*|nodejs[0-9]+(?:-libs)?)$")
            .expect("고정된 정규식")
    })
}

fn brotli_package() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:libbrotli[0-9]*|libbrotli-dec(?:oder)?[0-9]*|brotli(?:-libs)?)$")
            .expect("고정된 정규식")
    })
}

/// 패키지 이름이 고른 제품의 것이면 그 제품 — Node.js 를 고르면 Brotli 패키지도 본다.
pub(crate) fn package_product(name: &str, products: &[Product]) -> Option<Product> {
    for product in products {
        if *product == Product::Php && php_package().is_match(name) {
            return Some(Product::Php);
        }
        if *product == Product::Node {
            if node_package().is_match(name) {
                return Some(Product::Node);
            }
            if brotli_package().is_match(name) {
                return Some(Product::Brotli);
            }
        }
    }
    None
}

/// 발견의 이름 — 실행 언어로.
pub(crate) fn package_label(product: Product, lang: Lang) -> &'static str {
    match product {
        Product::Php => lang.t("PHP 패키지", "PHP package"),
        _ => lang.t("Node.js · Brotli 패키지", "Node.js · Brotli package"),
    }
}

/// 빈 줄로 가른 문단들 — CRLF 는 LF 로.
fn paragraphs(data: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(data)
        .replace("\r\n", "\n")
        .split("\n\n")
        .map(str::to_string)
        .collect()
}

/// dpkg 의 `status`. 설치된(`install ok installed`) 고른 제품의 패키지만.
pub(crate) fn parse_dpkg(
    data: &[u8],
    distro: &str,
    release: &str,
    source: &str,
    products: &[Product],
    lang: Lang,
) -> Vec<Component> {
    let mut out = Vec::new();
    for paragraph in paragraphs(data) {
        let (mut fields, mut valid) = dpkg_fields(&paragraph);
        let arch = fields.get("architecture").cloned().unwrap_or_default();
        if !arch.is_empty() && !linuxmeta::valid_package_architecture(&arch) {
            fields.insert("architecture".into(), String::new());
            valid = false;
        }
        let get = |k: &str| fields.get(k).map_or("", String::as_str);
        let name = get("package");
        let Some(product) = package_product(name, products) else {
            continue;
        };
        if get("status") != "install ok installed" || get("version").is_empty() {
            continue;
        }
        let maintainer = lower(get("maintainer"));
        let official = (distro == "debian"
            && (maintainer.ends_with("@lists.alioth.debian.org>")
                || maintainer.ends_with("@tracker.debian.org>")))
            || (distro == "ubuntu" && maintainer.ends_with("@lists.ubuntu.com>"));
        let architecture = get("architecture");
        let mut c = Component::new(product);
        c.id = format!("container-package:{name}");
        if !architecture.is_empty() {
            c.id = format!("{}:{architecture}", c.id);
        }
        c.name = package_label(product, lang).to_string();
        c.path = source.to_string();
        c.version = get("version").to_string();
        c.architecture = architecture.to_string();
        c.package = name.to_string();
        c.distribution = distro.to_string();
        c.distribution_version = release.to_string();
        c.source = source.to_string();
        c.runtime = "container".to_string();
        c.trusted = valid && official;
        out.push(c);
    }
    out
}

/// 문단 하나의 칸(이름은 소문자)과 레코드가 온전한가. 이어지는 줄(빈칸 · 탭으로 시작)은 건너뛴다.
fn dpkg_fields(paragraph: &str) -> (HashMap<String, String>, bool) {
    let mut fields = HashMap::new();
    let mut valid = true;
    for line in paragraph.split('\n') {
        if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            valid = false;
            continue;
        };
        if key.is_empty() || key != key.trim() {
            valid = false;
            continue;
        }
        let key = lower(key);
        if fields.contains_key(&key) {
            valid = false;
        }
        fields.insert(key, value.trim().to_string());
    }
    (fields, valid)
}

/// apk 의 `installed`. 출처를 말하지 않는 기록이라 믿지 않는다.
pub(crate) fn parse_apk(
    data: &[u8],
    release: &str,
    source: &str,
    products: &[Product],
    lang: Lang,
) -> Vec<Component> {
    let mut out = Vec::new();
    for paragraph in paragraphs(data) {
        let mut fields: HashMap<&str, &str> = HashMap::new();
        for line in paragraph.split('\n') {
            if let Some((key, value)) = line.split_once(':') {
                fields.insert(key, value);
            }
        }
        let name = fields.get("P").copied().unwrap_or_default();
        let version = fields.get("V").copied().unwrap_or_default();
        let Some(product) = package_product(name, products) else {
            continue;
        };
        if version.is_empty() {
            continue;
        }
        let mut c = Component::new(product);
        c.id = format!("container-package:{name}");
        c.name = package_label(product, lang).to_string();
        c.path = source.to_string();
        c.version = version.to_string();
        c.package = name.to_string();
        c.distribution = "alpine".to_string();
        c.distribution_version = release.to_string();
        c.source = source.to_string();
        c.runtime = "container".to_string();
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_names_follow_the_scanner_patterns() {
        let all = [Product::Php, Product::Node];
        for php in [
            "php",
            "php-cli",
            "php-fpm",
            "php8.3-cli",
            "php83",
            "libapache2-mod-php8.2",
        ] {
            assert_eq!(package_product(php, &all), Some(Product::Php), "{php}");
        }
        for node in ["nodejs", "NodeJS-libs", "libnode115", "nodejs20"] {
            assert_eq!(package_product(node, &all), Some(Product::Node), "{node}");
        }
        for brotli in ["libbrotli1", "libbrotli-dec1", "brotli-libs", "brotli"] {
            assert_eq!(
                package_product(brotli, &all),
                Some(Product::Brotli),
                "{brotli}"
            );
        }
        assert_eq!(package_product("nodejs", &[Product::Php]), None);
        assert_eq!(package_product("php-common", &all), None);
        assert_eq!(package_product("libbrotli1", &[Product::Php]), None);
    }

    #[test]
    fn a_broken_or_duplicated_record_is_not_trusted() {
        let base = "Package: php8.2-cli\nStatus: install ok installed\nVersion: 8.2.29-1~deb12u1\nMaintainer: Debian PHP Maintainers <team+pkg-php@tracker.debian.org>\n";
        let ok = parse_dpkg(
            base.as_bytes(),
            "debian",
            "12",
            "s",
            &[Product::Php],
            Lang::Ko,
        );
        assert!(ok[0].trusted);
        assert_eq!(ok[0].id, "container-package:php8.2-cli");
        for extra in [
            "Version: 8.2.0\n",
            "broken line\n",
            " Key: x\n",
            "Architecture: AMD64\n",
        ] {
            let data = format!("{base}{extra}");
            let got = parse_dpkg(
                data.as_bytes(),
                "debian",
                "12",
                "s",
                &[Product::Php],
                Lang::Ko,
            );
            assert_eq!(got.len(), 1, "{extra:?}");
            assert_eq!(got[0].trusted, extra.starts_with(' '), "{extra:?}");
        }
        let foreign = parse_dpkg(
            base.as_bytes(),
            "ubuntu",
            "24.04",
            "s",
            &[Product::Php],
            Lang::Ko,
        );
        assert!(!foreign[0].trusted);
        let crlf = base.replace('\n', "\r\n");
        assert!(
            parse_dpkg(
                crlf.as_bytes(),
                "debian",
                "12",
                "s",
                &[Product::Php],
                Lang::Ko
            )[0]
            .trusted
        );
    }
}
