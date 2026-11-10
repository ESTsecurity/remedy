//! PHP — PHP2Shell(CVE-2026-109618 · CVE-2026-109619).
//!
//! 판정이 나오는 길은 셋이다.
//!
//! 1. **공식 빌드의 해시** — 맞으면 그 빌드의 버전으로 본다. 패키지 · 배포판 · 버전 칸은 보지 않는다.
//! 2. **출처를 믿을 수 있는 상류 빌드** — 순수한 `X.Y.Z` 만 그 계열의 수정 버전과 견준다. php.net 수정 버전이
//!    없는 계열(5.4~8.1)은 영향 버전이다.
//! 3. **출처를 믿을 수 있는 배포판 패키지** — 공급사 공지와 견준다([`super::advisory`]).
//!
//! 어느 길에도 들지 못하면 *확인 필요* 다.

use super::data::{LegacyPhp, ProductData};
use super::version::{compare_core, core};
use super::{review, settle, Component, RuleSet, UPSTREAM};
use crate::scan::model::{Evidence, Finding, Product, Status};
use remedy_sdk::i18n::Lang;

impl RuleSet {
    pub(super) fn evaluate_php(&self, c: &Component, lang: Lang) -> Finding {
        // 기준에 PHP 가 없으면 빈 기준으로 본다 — 해시도 수정 버전도 없어 양호 · 취약이 나올 수 없다.
        let none = ProductData::default();
        let p = self.product(Product::Php).unwrap_or(&none);
        let mut f = self.new_finding(c, lang);
        let version = match p.official(&c.sha256) {
            Some(h) => {
                f.version = Some(h.version.clone());
                f.evidence.push(Evidence::new(
                    h.source.as_str(),
                    lang.t(
                        "기준에 실린 공식 빌드의 SHA-256 과 일치",
                        "matches the SHA-256 of an official build in the criteria",
                    ),
                ));
                h.version.as_str()
            }
            None if !c.trusted => return unproven(p, c, f, lang),
            None if c.distribution != UPSTREAM => return self.evaluate_vendor_component(c, lang),
            // 배포판 식별자가 `upstream` 이라고 공식 실행 파일이 되지는 않는다. 패키지는 그 공급사의 공지로
            // 보아야 하는데, 그런 이름의 공급사 공지는 없다.
            None if !c.package.is_empty() => {
                return review(
                    f,
                    lang.t(
                        "패키지의 공급사 정보만으로 PHP 공식 배포본임을 확인할 수 없습니다.",
                        "Package vendor information alone cannot confirm this is an official PHP build.",
                    ),
                )
            }
            None => c.version.as_str(),
        };
        upstream(p, version, f, lang)
    }
}

/// 출처를 믿을 수 없는 것 — 판정하지 않는다. 버전이 영향 범위의 구버전이면 그 사실만 알린다.
fn unproven(p: &ProductData, c: &Component, f: Finding, lang: Lang) -> Finding {
    if legacy(p, &c.version).is_none() {
        return f;
    }
    settle(
        f,
        Status::ReviewRequired,
        lang.t(
            "PHP2Shell 영향 범위의 구버전입니다. 파일의 출처와 별도 보안 패치 적용 여부를 확인하지 못했습니다.",
            "This is an old version in the PHP2Shell-affected range. Where the file came from, and whether a separate security patch was applied, could not be confirmed.",
        ),
        lang.t(
            "공급사에 두 CVE 의 패치 적용 여부를 확인하십시오. 패치가 없으면 지원 중인 PHP 버전으로 전환하십시오.",
            "Ask the vendor whether both CVEs are patched. If there is no patch, move to a supported PHP version.",
        ),
    )
}

/// 버전이 php.net 수정 버전이 없는 계열의 순수한 `X.Y.Z` 면 그 계열들의 기준.
fn legacy<'a>(p: &'a ProductData, version: &str) -> Option<&'a LegacyPhp> {
    let [major, minor, _] = core(version)?;
    let branch = format!("{major}.{minor}");
    p.legacy_php
        .as_ref()
        .filter(|legacy| legacy.branches.contains(&branch))
}

/// 상류 빌드 — 순수한 `X.Y.Z` 만 견준다. 꼬리가 붙은 버전(사전 공개 · 직접 빌드)과 모르는 계열은 판정하지
/// 않는다.
fn upstream(p: &ProductData, version: &str, mut f: Finding, lang: Lang) -> Finding {
    let Some([major, minor, _]) = core(version) else {
        return f;
    };
    let Some(fixed) = p.upstream.get(&format!("{major}.{minor}")) else {
        return unfixed_branch(p, version, f, lang);
    };
    f.evidence.push(Evidence::new(
        p.source.as_str(),
        lang.pick(
            format!("공급사 보안 패치 버전: {fixed}"),
            format!("Vendor security patch version: {fixed}"),
        ),
    ));
    if compare_core(version, fixed).is_lt() {
        return settle(
            f,
            Status::Vulnerable,
            lang.t(
                "공급사 기준으로 보안 패치가 적용되지 않은 PHP 입니다.",
                "By the vendor's criteria this PHP does not have the security patch.",
            ),
            lang.pick(
                format!("{fixed} 이상의 보안 패치 버전을 확인하십시오. 백업과 호환성 확인 후 담당자가 패치를 적용하고 다시 점검하십시오."),
                format!("Find the security-patched release {fixed} or later. After a backup and a compatibility check, have the owner apply the patch and check again."),
            ),
        );
    }
    settle(
        f,
        Status::Clear,
        lang.t(
            "공급사 기준으로 두 취약점의 보안 패치가 포함된 버전입니다.",
            "By the vendor's criteria this version includes the security patch for both vulnerabilities.",
        ),
        lang.t(
            "실행 중인 PHP 에도 패치가 적용됐는지 확인하고, 로그인 · 세션 · 파일 업로드 등 서비스가 정상 동작하는지 확인하십시오.",
            "Confirm the running PHP has the patch too, and that the service (sign-in, sessions, file upload and so on) works normally.",
        ),
    )
}

/// 수정 버전 기준이 없는 계열 — php.net 이 고치지 않은 계열이면 공식 빌드는 영향 버전이고, 모르는 계열이면
/// 판정하지 않는다.
fn unfixed_branch(p: &ProductData, version: &str, mut f: Finding, lang: Lang) -> Finding {
    let Some(rule) = legacy(p, version) else {
        return review(
            f,
            lang.t(
                "현재 진단 기준에는 이 배포판 · 패키지 · PHP 계열의 보안 패치 정보가 없습니다.",
                "The current criteria have no security patch information for this distribution, package or PHP branch.",
            ),
        );
    };
    f.evidence.push(Evidence::new(
        rule.source.as_str(),
        lang.t(
            "공식 구버전의 PHP2Shell 영향 범위. 배포판 백포트와 자체 빌드에는 이 기준을 그대로 적용하지 않습니다.",
            "PHP2Shell-affected range of official old versions. Not applied as is to distribution backports or own builds.",
        ),
    ));
    settle(
        f,
        Status::Vulnerable,
        lang.t(
            "PHP2Shell 보안 패치가 없는 공식 구버전입니다. 두 CVE 중 하나 이상에 영향을 받습니다.",
            "This is an official old version with no PHP2Shell security patch. It is affected by at least one of the two CVEs.",
        ),
        lang.t(
            "지원 중인 PHP 의 보안 패치 버전으로 전환하십시오. 공급사 패치를 사용하는 경우 해당 파일에 패치가 포함됐는지 확인하십시오.",
            "Move to a security-patched release of a supported PHP. If you rely on a vendor patch, confirm that this file includes it.",
        ),
    )
}
