//! Node.js — 그 안의 Brotli 디코더(CVE-2026-111497).
//!
//! Node.js 는 Brotli 를 **안에 담아 짓거나**(공식 배포본) **시스템의 것을 연결한다**(배포판 패키지). 취약한
//! 것은 Brotli 이므로 어느 쪽인가에 따라 볼 것이 다르다.
//!
//! - **공유 연결을 확인했으면** 실제로 연결된 Brotli 를 그 공급사의 공지로 본다. 실행 파일의 해시가 공식
//!   빌드와 맞아도 그쪽이 먼저다 — 실제로 쓰는 라이브러리는 공식 빌드에 든 것과 다를 수 있다.
//! - **공식 배포본의 해시가 맞으면** 그 버전의 수정 여부로 본다. 수정 버전 기준이 없는 계열(18 · 20)은 그
//!   빌드에 든 Brotli 의 원본 코드를 대조한 근거가 기준에 있을 때만 취약이다 — 지원이 끝났다는 것만으로는
//!   취약이라 하지 않는다.
//! - **그 밖에는** 공급사 공지로 보되, Brotli 를 담아 지은 빌드이고 의존 목록을 끝까지 보았을 때만 양호를
//!   낸다. 공급사가 미수정으로 확인한 패키지는 그 확인이 없어도 취약이다.

use super::data::{BuildAssessment, ProductData};
use super::version::{compare_core, is_core};
use super::{review, settle, Component, DependencyMode, RuleSet, UPSTREAM};
use crate::scan::model::{Evidence, Finding, Product, Status};
use remedy_sdk::i18n::Lang;

/// 기준 데이터의 근거 설명(`build_assessments[].evidence[].detail`)은 한국어로만 적혀 있다. 영어 실행에서는 같은
/// 뜻의 이 문장을 낸다 — 기준에 새 설명이 들어오면 시험(`every_build_evidence_detail_has_an_english_form`)이
/// 실패한다.
const DETAIL_EN: [(&str, &str); 4] = [
    (
        "CVE CNA에서 Brotli 1.1.0 이상 1.1.1 미만을 영향 범위로 명시",
        "the CVE CNA states Brotli 1.1.0 up to but not including 1.1.1 as the affected range",
    ),
    (
        "공식 Node.js 18.20.8 소스의 포함 Brotli 버전은 1.1.0",
        "the Brotli bundled in the official Node.js 18.20.8 source is version 1.1.0",
    ),
    (
        "공식 Node.js 20.20.2 소스의 포함 Brotli 버전은 1.1.0",
        "the Brotli bundled in the official Node.js 20.20.2 source is version 1.1.0",
    ),
    (
        "공식 디코더에 블록 전환 오류 상태 검사가 없고 반환값을 무시하는 기존 호출이 남아 있음",
        "the official decoder has no block-switch error state check and still has the old calls that ignore the return value",
    ),
];

/// 공식 배포본의 해시와 맞지 않는 Node.js 를 본 결과.
enum Unlisted {
    /// 판정이 끝났다.
    Settled(Finding),
    /// 출처를 믿을 수 있는 상류 빌드다 — 그 계열의 수정 버전과 견준다.
    Upstream(Finding),
}

impl RuleSet {
    pub(super) fn evaluate_node(&self, c: &Component, lang: Lang) -> Finding {
        let mut f = self.new_finding(c, lang);
        let Some(p) = self.product(Product::Node) else {
            return review(
                f,
                lang.t(
                    "이 진단 기준에는 Node.js 보안 패치 정보가 없습니다.",
                    "These criteria have no Node.js security patch information.",
                ),
            );
        };
        if c.dependency_mode == DependencyMode::Shared {
            return self.evaluate_shared_node(c, f, lang);
        }
        let official = p.official(&c.sha256);
        let version = match official {
            Some(h) => {
                f.version = Some(h.version.clone());
                f.evidence.push(Evidence::new(
                    h.source.as_str(),
                    lang.t(
                        "공식 배포본의 서명 검증을 마친 실행 파일 SHA-256 과 일치; Brotli 포함 빌드",
                        "matches the SHA-256 of an executable from a signature-checked official release; a build that bundles Brotli",
                    ),
                ));
                h.version.as_str()
            }
            None => match self.unlisted_node(c, f, lang) {
                Unlisted::Upstream(open) => {
                    f = open;
                    c.version.as_str()
                }
                Unlisted::Settled(settled) => return settled,
            },
        };
        if !is_core(version) {
            return f;
        }
        if let Some(build) = official.and_then(|_| assessed(p, version)) {
            return bundled_brotli_unfixed(f, build, lang);
        }
        fixed_release(p, version, f, lang)
    }

    /// 공식 배포본의 해시와 맞지 않는 Node.js — 공급사 공지로 보고, 상류 빌드면 수정 버전과 견줄 것으로 넘긴다.
    fn unlisted_node(&self, c: &Component, f: Finding, lang: Lang) -> Unlisted {
        let upstream = c.distribution == UPSTREAM;
        // 배포판 식별자가 `upstream` 이라고 공식 실행 파일이 되지는 않는다.
        if upstream && !c.package.is_empty() {
            return Unlisted::Settled(review(
                f,
                lang.t(
                    "패키지의 공급사 정보만으로 Node.js 공식 배포본임을 확인할 수 없습니다.",
                    "Package vendor information alone cannot confirm this is an official Node.js build.",
                ),
            ));
        }
        let vendor = self.evaluate_vendor_component(c, lang);
        // 공급사가 미수정으로 확인한 패키지는 다른 것을 보지 못했어도 취약이다.
        if vendor.status == Status::Vulnerable {
            return Unlisted::Settled(vendor);
        }
        if c.dependency_mode != DependencyMode::Bundled || !c.dependencies_complete {
            return Unlisted::Settled(review(
                f,
                lang.t(
                    "Node.js 가 실제 사용하는 Brotli 와 포함 빌드 여부를 확인하지 못했습니다.",
                    "Which Brotli this Node.js actually uses, and whether it is a bundled build, could not be confirmed.",
                ),
            ));
        }
        if !upstream {
            return Unlisted::Settled(vendor);
        }
        if c.trusted {
            Unlisted::Upstream(f)
        } else {
            Unlisted::Settled(f)
        }
    }

    /// 공유 연결 — 실제로 연결된 Brotli 하나하나를 그 공급사의 공지로 본다. 하나라도 취약이면 취약이고, 전부
    /// 양호이며 목록을 끝까지 보았을 때만 양호다.
    fn evaluate_shared_node(&self, c: &Component, mut f: Finding, lang: Lang) -> Finding {
        let mut linked = 0usize;
        let mut all_clear = c.dependencies_complete;
        for dep in c
            .dependencies
            .iter()
            .filter(|d| d.product == Product::Brotli)
        {
            linked += 1;
            let result = self.evaluate_vendor_component(dep, lang);
            f.evidence.push(Evidence::new(
                dep.source.as_str(),
                lang.pick(
                    format!(
                        "실제 연결된 Brotli: {} / {} / {}",
                        dep.path, dep.package, dep.version
                    ),
                    format!(
                        "Brotli actually linked: {} / {} / {}",
                        dep.path, dep.package, dep.version
                    ),
                ),
            ));
            f.evidence.extend(result.evidence);
            if result.status == Status::Vulnerable {
                return settle(
                    f,
                    Status::Vulnerable,
                    lang.t(
                        "Node.js 가 실제 사용하는 공유 Brotli 에 공급사가 확인한 미수정 취약점이 있습니다.",
                        "The shared Brotli this Node.js actually uses has an unfixed vulnerability confirmed by the vendor.",
                    ),
                    lang.t(
                        "해당 배포판의 Brotli 보안 패치와 적용 방법을 확인한 뒤 라이브러리를 업데이트하고 서비스를 다시 점검하십시오.",
                        "Check that distribution's Brotli security patch and how to apply it, update the library, then check the service again.",
                    ),
                );
            }
            all_clear &= result.status == Status::Clear;
        }
        if linked == 0 || !all_clear {
            return review(
                f,
                lang.t(
                    "Node.js 가 실제 사용하는 공유 Brotli 의 파일 · 패키지 정보나 공급사 보안 패치 기준을 모두 확인하지 못했습니다.",
                    "Not all of the file and package information, or the vendor patch criteria, of the shared Brotli this Node.js actually uses could be confirmed.",
                ),
            );
        }
        settle(
            f,
            Status::Clear,
            lang.t(
                "Node.js 가 실제 사용하는 공유 Brotli 의 공급사 보안 패치 적용을 확인했습니다.",
                "The vendor security patch was confirmed on the shared Brotli this Node.js actually uses.",
            ),
            lang.t(
                "실행 중인 서비스가 확인한 라이브러리를 사용하는지 확인하고 Brotli 처리 기능을 점검하십시오.",
                "Confirm the running service uses the library that was checked, and test its Brotli handling.",
            ),
        )
    }
}

/// 그 버전의 공식 빌드를 코드 대조로 취약이라 본 근거.
fn assessed<'a>(p: &'a ProductData, version: &str) -> Option<&'a BuildAssessment> {
    p.build_assessments.iter().find(|b| b.version == version)
}

fn bundled_brotli_unfixed(mut f: Finding, build: &BuildAssessment, lang: Lang) -> Finding {
    let brotli = &build.dependency_version;
    f.evidence.push(Evidence::new(
        build.source.as_str(),
        lang.pick(
            format!("공식 배포본의 포함 Brotli {brotli}: CVE 영향 범위와 원본 디코더 코드 대조"),
            format!("Brotli {brotli} bundled in the official release: the CVE's affected range compared with the original decoder code"),
        ),
    ));
    for e in &build.evidence {
        let detail = match lang {
            Lang::Ko => format!("{} / 원본 SHA-256: {}", e.detail, e.sha256),
            Lang::En => format!("{} / source SHA-256: {}", detail_en(&e.detail), e.sha256),
        };
        f.evidence.push(Evidence::new(e.source.as_str(), detail));
    }
    settle(
        f,
        Status::Vulnerable,
        lang.t(
            "공식 Node.js 배포본에 포함된 Brotli 에서 CVE-2026-111497 의 미수정 코드를 확인했습니다.",
            "The Brotli bundled in this official Node.js release was confirmed to contain the unfixed code of CVE-2026-111497.",
        ),
        lang.t(
            "서비스 호환성을 확인한 뒤 보안 패치가 제공되는 Node.js 계열의 수정 버전으로 전환하고 다시 점검하십시오.",
            "After checking service compatibility, move to a fixed release of a Node.js line that still receives security patches, then check again.",
        ),
    )
}

/// 기준에 적힌 근거 설명의 영어 문장. 표에 없으면 설명 없이 그 사실만 적는다.
pub(super) fn detail_en(detail: &str) -> &'static str {
    DETAIL_EN
        .iter()
        .find(|(ko, _)| *ko == detail)
        .map_or("evidence recorded in the criteria", |(_, en)| *en)
}

/// Brotli 를 담아 지은 빌드 — 그 계열의 수정 버전과 견준다.
fn fixed_release(p: &ProductData, version: &str, mut f: Finding, lang: Lang) -> Finding {
    let line = version.split('.').next().unwrap_or_default();
    let Some(fixed) = p.upstream.get(line) else {
        return review(
            f,
            lang.t(
                "이 Node.js 계열에는 확인된 수정 버전 기준이 없습니다. 지원 종료 여부만으로 취약 판정하지 않습니다.",
                "There are no confirmed fixed-version criteria for this Node.js line. End of support alone is not judged vulnerable.",
            ),
        );
    };
    f.evidence.push(Evidence::new(
        p.source.as_str(),
        lang.pick(
            format!("Brotli 를 포함한 공식 Node.js 수정 버전: {fixed}"),
            format!("Fixed official Node.js release that bundles Brotli: {fixed}"),
        ),
    ));
    if compare_core(version, fixed).is_lt() {
        return settle(
            f,
            Status::Vulnerable,
            lang.t(
                "CVE-2026-111497 수정이 적용되지 않은 Node.js 입니다.",
                "This Node.js does not have the CVE-2026-111497 fix.",
            ),
            lang.pick(
                format!("서비스 호환성을 확인한 뒤 Node.js {fixed} 이상으로 업데이트하고 다시 점검하십시오."),
                format!("After checking service compatibility, update to Node.js {fixed} or later and check again."),
            ),
        );
    }
    settle(
        f,
        Status::Clear,
        lang.t(
            "Brotli 를 포함한 Node.js 빌드에 CVE-2026-111497 수정이 적용된 버전입니다.",
            "This Node.js build bundles Brotli and is a version with the CVE-2026-111497 fix.",
        ),
        lang.t(
            "실행 중인 서비스도 해당 Node.js 를 사용하는지 확인하고 Brotli 처리 기능을 점검하십시오.",
            "Confirm the running service uses this Node.js too, and test its Brotli handling.",
        ),
    )
}
