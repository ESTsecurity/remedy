//! 공급사 공지와 견준다 — 배포판 패키지와, Node.js 가 연결한 공유 Brotli.
//!
//! 줄 하나는 **배포판 · 배포판 버전 · 패키지**가 맞는 것에만 말한다. 맞은 줄에서
//!
//! - 수정 버전보다 낮으면(또는 공급사가 미수정으로 확인한 바로 그 버전이면) 그 자리에서 **취약**이다.
//! - 그렇지 않으면 그 줄이 덮는 CVE 를 덮은 것으로 센다. 제품의 CVE 를 **전부** 덮어야 *양호* 다 — 한 CVE 만
//!   고친 공지(RHEL 7 의 PHP)만으로는 양호가 되지 않는다.
//!
//! 맞는 줄이 없으면 *확인 필요* 다. 버전이 높아 보여도 그 공급사가 고쳤는지 알 근거가 없다.

use super::data::{rpm_scope_token, Advisory, Comparator, ProductData};
use super::version::{
    compare_core, compare_debian, debian_vendor_line, is_core, numeric, rpm_has_release,
    rpm_version_cmp, ubuntu_line, valid_debian, MAX_VERSION_BYTES,
};
use super::{review, settle, Component, PackageManager, RuleSet, UPSTREAM};
use crate::scan::model::{Evidence, Finding, Status};
use remedy_sdk::i18n::Lang;
use std::cmp::Ordering;

impl RuleSet {
    /// 공급사 공지로만 판정한다. 출처를 믿을 수 없는 것과 상류 배포본은 공지의 대상이 아니다.
    pub(super) fn evaluate_vendor_component(&self, c: &Component, lang: Lang) -> Finding {
        let f = self.new_finding(c, lang);
        match self.product(c.product) {
            Some(p) if c.trusted && c.distribution != UPSTREAM => {
                evaluate_advisories(p, c, f, lang)
            }
            _ => f,
        }
    }
}

fn evaluate_advisories(p: &ProductData, c: &Component, mut f: Finding, lang: Lang) -> Finding {
    let distribution = c.distribution.to_ascii_lowercase();
    let mut covered: Vec<&str> = Vec::new();
    for a in &p.advisories {
        let Some(order) = compare_advisory(c, &distribution, a) else {
            continue;
        };
        // 덮는 CVE 를 적지 않은 줄은 그 제품의 CVE 전부를 덮는다(RPM 줄은 반드시 적는다).
        let cves = if a.cves.is_empty() { &p.cves } else { &a.cves };
        let list = cves.join(", ");
        f.evidence.push(Evidence::new(
            a.source.as_str(),
            advisory_detail(a, &list, lang),
        ));
        if order.is_lt() {
            return settle(
                f,
                Status::Vulnerable,
                lang.pick(
                    format!("공급사 기준으로 {list} 보안 패치가 적용되지 않은 패키지입니다."),
                    format!("By the vendor's criteria this package does not have the security patch for {list}."),
                ),
                lang.t(
                    "공급사의 수정 패키지를 확인하고 보안 패치를 적용한 뒤 다시 점검하십시오.",
                    "Find the vendor's fixed package, apply the security patch, then check again.",
                ),
            );
        }
        covered.extend(cves.iter().map(String::as_str));
    }
    if p.cves.iter().any(|cve| !covered.contains(&cve.as_str())) {
        if covered.is_empty() {
            return f;
        }
        return review(
            f,
            lang.t(
                "점검 대상 취약점 모두의 보안 패치 적용을 확인하지 못했습니다.",
                "The security patch could not be confirmed for every vulnerability being checked.",
            ),
        );
    }
    settle(
        f,
        Status::Clear,
        lang.t(
            "공급사 기준으로 점검 대상 취약점의 보안 패치가 포함된 패키지입니다.",
            "By the vendor's criteria this package includes the security patch for the vulnerabilities being checked.",
        ),
        lang.t(
            "실행 중인 서비스에도 수정 패키지가 적용됐는지 확인하십시오.",
            "Confirm the fixed package is in effect in the running service too.",
        ),
    )
}

fn advisory_detail(a: &Advisory, cves: &str, lang: Lang) -> String {
    match (a.comparator, lang) {
        (Comparator::Exact, Lang::Ko) => {
            format!("공급사 확인 미수정 패키지 버전: {} / {cves}", a.version)
        }
        (Comparator::Exact, Lang::En) => format!(
            "Package version the vendor confirmed unfixed: {} / {cves}",
            a.version
        ),
        (_, Lang::Ko) => format!("공급사 보안 패치 버전: {} / {cves}", a.fixed),
        (_, Lang::En) => format!("Vendor security patch version: {} / {cves}", a.fixed),
    }
}

/// 그 줄이 이 패키지에 말하는가, 말한다면 수정 버전과의 순서. 말하지 않으면 `None`.
///
/// `distribution` 은 소문자로 바꾼 배포판 식별자다 — 줄 쪽은 바꾸지 않는다.
fn compare_advisory(c: &Component, distribution: &str, a: &Advisory) -> Option<Ordering> {
    // RPM 패키지는 RPM 줄만 본다 — dpkg 줄이나 상류 버전 줄의 수정을 물려받지 않는다.
    if c.package_manager == PackageManager::Rpm && a.comparator != Comparator::Rpm {
        return None;
    }
    if a.distribution != distribution
        || a.release != c.distribution_version
        || a.package != c.package
    {
        return None;
    }
    match a.comparator {
        // 미수정으로 확인된 바로 그 버전이면 수정 버전보다 낮은 것으로 친다. 다른 버전에는 말하지 않는다.
        Comparator::Exact => (c.version == a.version).then_some(Ordering::Less),
        Comparator::Debian => {
            if !valid_debian(&c.version) {
                return None;
            }
            let in_line = match a.distribution.as_str() {
                "ubuntu" => ubuntu_line(&c.version, &a.fixed),
                "debian" => debian_vendor_line(&c.version, &a.fixed),
                _ => true,
            };
            in_line.then(|| compare_debian(&c.version, &a.fixed))
        }
        Comparator::Upstream => is_core(&c.version).then(|| compare_core(&c.version, &a.fixed)),
        Comparator::Rpm => compare_rpm_row(c, a),
    }
}

/// RPM 줄 — 아키텍처 · 공급사 · 모듈 스트림이 맞고, 버전이 그 줄의 범위(`version_pattern`)에 들 때만 견준다.
///
/// 범위를 지난 버전에 두 가지를 더 본다. **길이** — 범위의 `[0-9]+` 는 길이를 막지 못한다. 그리고 **개정이
/// 있는가** — rpm 이 적는 버전에는 늘 개정이 있고, 개정이 한쪽에만 없을 때의 순서는 구현마다 다르다
/// (`version` 의 시험이 그 자리를 적어 둔다). 갈리는 자리에서 *양호* 를 내지 않으려고 견주지 않는다.
fn compare_rpm_row(c: &Component, a: &Advisory) -> Option<Ordering> {
    let scoped = a.architectures.contains(&c.architecture)
        && c.package_vendor == a.vendor
        && rpm_module_matches(&c.package_module, &a.module, &c.architecture);
    if !scoped {
        return None;
    }
    let in_line = a
        .version_pattern
        .as_ref()
        .is_some_and(|pattern| pattern.is_match(&c.version));
    if !in_line || c.version.len() > MAX_VERSION_BYTES || !rpm_has_release(&c.version) {
        return None;
    }
    rpm_version_cmp(&c.version, &a.fixed)
}

/// 패키지의 모듈 꼬리표(`이름:스트림:버전:컨텍스트[:아키텍처]`)가 그 줄의 스트림(`이름:스트림`)의 것인가.
/// 줄에 스트림이 없으면 모듈이 아닌 패키지에만 말한다 — 같은 버전 꼴을 다른 스트림 · SCL 이 내도 섞이지 않는다.
fn rpm_module_matches(label: &str, stream: &str, architecture: &str) -> bool {
    if stream.is_empty() {
        return label.is_empty();
    }
    let parts: Vec<&str> = label.split(':').collect();
    let (name, line, version, context, arch) = match parts.as_slice() {
        [n, l, v, c] => (*n, *l, *v, *c, None),
        [n, l, v, c, a] => (*n, *l, *v, *c, Some(*a)),
        _ => return false,
    };
    stream.split_once(':') == Some((name, line))
        && numeric(version)
        && rpm_scope_token(context)
        && arch.is_none_or(|a| a == architecture)
}

#[cfg(test)]
mod tests {
    use super::rpm_module_matches;

    #[test]
    fn a_module_label_must_be_of_the_rows_stream() {
        const LABEL: &str = "php:7.4:8100020261021081045:abcd1234";
        assert!(rpm_module_matches(LABEL, "php:7.4", "x86_64"));
        assert!(rpm_module_matches(
            &format!("{LABEL}:x86_64"),
            "php:7.4",
            "x86_64"
        ));
        assert!(!rpm_module_matches(
            &format!("{LABEL}:aarch64"),
            "php:7.4",
            "x86_64"
        ));
        assert!(!rpm_module_matches(LABEL, "php:8.2", "x86_64"));
        assert!(!rpm_module_matches(
            "php:7.4::abcd1234",
            "php:7.4",
            "x86_64"
        ));
        assert!(!rpm_module_matches("php:7.4", "php:7.4", "x86_64"));
        // 스트림이 없는 줄은 모듈이 아닌 패키지에만 말한다.
        assert!(rpm_module_matches("", "", "x86_64"));
        assert!(!rpm_module_matches(LABEL, "", "x86_64"));
        assert!(!rpm_module_matches("", "php:7.4", "x86_64"));
    }
}
