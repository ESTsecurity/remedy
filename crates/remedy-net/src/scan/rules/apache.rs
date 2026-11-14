//! Apache HTTP Server — HTTP/2 모듈(mod_http2) 원격 코드 실행(CVE-2026-119618 · 코어 1.18.0).
//!
//! 기준은 데이터 룰의 **`apache.json`** 이다. `baseline.json` 은 사내 스캐너의 형식 그대로(바이트 그대로) 두고
//! Apache 는 따로 둔다 — 영향 하한(상류 2.4.55)과 *영향 없음*(RHEL 8 의 mod_http2 1.15)을 그 형식이 담지 못한다.
//! 같은 공지의 값이 본체의 점검 룰 `apache-http2-check-linux` 에도 있고, 두 자리가 같은지는
//! `cargo xtask net-criteria` 가 본다.
//!
//! **판정은 그 룰과 같다**(목표 `remedy_net아파치` 결정 2).
//!
//! - **배포판 패키지** — 그 공급사의 줄(`lines`)에 들면 그 줄의 고친 판과 견준다. 낮으면 *영향*, 아니면 *고침*.
//!   고침이 없다고 적힌 줄(`no_fix`)과 지원이 끝난 브랜치(`supported_from` 아래)의 영향 판은 *확인 필요* 다.
//! - **줄에 들지 않는 패키지** — 상류 번호가 영향 범위(httpd `upstream.affected` · mod_h2 `module.affected`)면
//!   *확인 필요*(고친 판을 기준이 모른다), 아니면 *영향 없음*.
//! - **패키지 없는 빌드**(공식 `httpd` 이미지의 `/usr/local/apache2`) — 상류 판으로 견준다. 근거가 되는지(판 문자열이
//!   이미지의 `HTTPD_VERSION` 과 같고 `HTTPD_PATCHES` 가 비었는가 · 목표 결정 3)는 부르는 쪽이 `trusted` 로 준다.
//! - *영향* 은 **HTTP/2 를 켠 흔적**(모듈 적재 + `Protocols` 의 `h2` · `h2c`)이 다 있을 때만 *취약* 이고, 그 밖은
//!   *확인 필요* 다 — 흔적은 부르는 쪽이 모은다([`Http2`]).
//!
//! 패키지가 믿을 만한가(기록과 파일이 맞는가)는 부르는 쪽이 본다 — 믿지 못하면 `trusted` 가 거짓이고 판정하지 않는다.

use super::data::VersionPattern;
use super::version::{
    apk_version_cmp, compare_core, compare_debian, core, is_core, rpm_has_release, rpm_version_cmp,
    valid_debian, MAX_VERSION_BYTES,
};
use super::{settle, Component, PackageManager, RuleSet, UPSTREAM};
use crate::scan::apacheconf::Http2;
use crate::scan::model::{Evidence, Finding, Status};
use remedy_sdk::catalog::{is_apk_version, is_rpm_version};
use remedy_sdk::i18n::Lang;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

/// 이 코드가 읽는 `apache.json` 의 형식.
const SCHEMA_VERSION: u32 = 1;
/// 줄 수의 상한.
const MAX_LINES: usize = 512;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    schema_version: u32,
    /// 공지를 확인한 날(`YYYY-MM-DD`).
    checked: String,
    cves: Vec<String>,
    /// 같은 값을 든 본체의 점검 룰과 그 버전.
    same_as: String,
    /// 상류 공지.
    source: String,
    upstream: Upstream,
    /// mod_h2 의 번호(2.0.x)로 적은 영향 범위 — RHEL 계열의 mod_http2 가 이 번호를 쓴다.
    module: Range,
    lines: Vec<Line>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    /// 상류 httpd 의 영향 범위(양 끝 포함).
    affected: [String; 2],
    /// 상류가 고친 판.
    fixed: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    affected: [String; 2],
}

/// 패키지를 적은 관리자.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Manager {
    Dpkg,
    Rpm,
    Apk,
}

impl Manager {
    fn of(m: PackageManager) -> Option<Manager> {
        match m {
            PackageManager::Dpkg => Some(Manager::Dpkg),
            PackageManager::Rpm => Some(Manager::Rpm),
            PackageManager::Apk => Some(Manager::Apk),
            PackageManager::Unknown => None,
        }
    }
}

/// 공급사 줄 하나 — 관리자 · 패키지(· RPM 은 공급사)가 맞고 아래 조건을 다 지나는 판에만 말한다.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    manager: Manager,
    package: String,
    /// RPM 의 `Vendor` 꼬리표 그대로 — RPM 줄에만 있고 반드시 있다.
    #[serde(default)]
    vendor: String,
    /// 판 전체가 맞아야 하는 꼴(`^…$`).
    #[serde(default)]
    version_pattern: Option<VersionPattern>,
    /// 판 전체가 맞으면 이 줄이 아닌 꼴(`^…$`).
    #[serde(default)]
    except_pattern: Option<VersionPattern>,
    /// 상류 번호가 바로 이것일 때만(`X.Y.Z`).
    #[serde(default)]
    upstream: String,
    /// 상류 번호가 이것 이상일 때만(`X.Y.Z`).
    #[serde(default)]
    from_upstream: String,
    /// 고친 판 — 그 관리자의 꼴. `no_fix` 면 없다.
    #[serde(default)]
    fixed: String,
    /// 영향 판인데 공급사의 고친 판이 아직 없다.
    #[serde(default)]
    no_fix: bool,
    /// apk 줄 — 이 배포판 버전(os-release `VERSION_ID`)보다 낮은 브랜치는 지원이 끝나 고친 판이 없다.
    #[serde(default)]
    supported_from: String,
    source: String,
}

/// 읽고 검사한 Apache 기준.
pub struct ApacheCriteria {
    data: Data,
    sha256: String,
}

impl ApacheCriteria {
    /// `apache.json` 의 글에서 읽는다. 모르는 칸 · 견줄 수 없는 꼴의 줄이 있으면 실패한다.
    pub fn from_json(text: &str) -> Result<ApacheCriteria, String> {
        let data: Data =
            serde_json::from_str(text).map_err(|e| format!("기준 데이터를 읽지 못했다: {e}"))?;
        check(&data)?;
        let sha256 = Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(ApacheCriteria { data, sha256 })
    }

    /// 공지를 확인한 날.
    pub fn checked(&self) -> &str {
        &self.data.checked
    }

    /// 읽은 기준 파일의 SHA-256.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(super) fn cves(&self) -> &[String] {
        &self.data.cves
    }

    /// 판정하는 패키지인가 — 줄에 그 관리자 · 이름이 있는 패키지만 본다.
    pub fn watches(&self, manager: PackageManager, package: &str) -> bool {
        let Some(m) = Manager::of(manager) else {
            return false;
        };
        self.data
            .lines
            .iter()
            .any(|l| l.manager == m && l.package == package)
    }

    /// 상류 httpd 의 고친 판.
    pub fn upstream_fixed(&self) -> &str {
        &self.data.upstream.fixed
    }

    fn in_affected_range(&self, upstream: &str) -> bool {
        [&self.data.upstream.affected, &self.data.module.affected]
            .iter()
            .any(|[low, high]| {
                compare_core(upstream, low).is_ge() && compare_core(upstream, high).is_le()
            })
    }

    fn judge_package(&self, c: &Component) -> Judgement<'_> {
        let Some(manager) = Manager::of(c.package_manager) else {
            return Judgement::Unknown;
        };
        if c.version.len() > MAX_VERSION_BYTES {
            return Judgement::Unknown;
        }
        let up = upstream_of(manager, &c.version);
        let line = self
            .data
            .lines
            .iter()
            .find(|l| l.applies(manager, c, up.as_deref()));
        let Some(line) = line else {
            return match up {
                Some(u) if !self.in_affected_range(&u) => Judgement::NotAffected,
                _ => Judgement::Unknown,
            };
        };
        if line.no_fix {
            return Judgement::NoFix(line);
        }
        match compare(manager, &c.version, &line.fixed) {
            None => Judgement::Unknown,
            Some(o) if o.is_ge() => Judgement::Fixed(line),
            Some(_) if line.unsupported(&c.distribution_version) => Judgement::NoFix(line),
            Some(_) => Judgement::Affected(line),
        }
    }

    fn judge_upstream(&self, version: &str) -> Judgement<'_> {
        if !is_core(version) {
            return Judgement::Unknown;
        }
        if compare_core(version, &self.data.upstream.affected[0]).is_lt() {
            return Judgement::NotAffected;
        }
        if compare_core(version, &self.data.upstream.affected[1]).is_le() {
            return Judgement::UpstreamAffected;
        }
        Judgement::UpstreamFixed
    }
}

impl Line {
    fn applies(&self, manager: Manager, c: &Component, up: Option<&str>) -> bool {
        self.manager == manager
            && self.package == c.package
            && (self.vendor.is_empty() || self.vendor == c.package_vendor)
            && self
                .version_pattern
                .as_ref()
                .is_none_or(|p| p.is_match(&c.version))
            && !self
                .except_pattern
                .as_ref()
                .is_some_and(|p| p.is_match(&c.version))
            && (self.upstream.is_empty() || up == Some(self.upstream.as_str()))
            && (self.from_upstream.is_empty()
                || up.is_some_and(|u| compare_core(u, &self.from_upstream).is_ge()))
    }

    /// 그 배포판 버전이 지원이 끝난 브랜치인가 — 줄에 하한이 있고 버전이 그보다 낮을 때만. 버전을 모르면 아니다
    /// (호스트 룰도 `alpine-release` 가 없으면 지원 중으로 본다).
    fn unsupported(&self, release: &str) -> bool {
        if self.supported_from.is_empty() {
            return false;
        }
        release_below(release, &self.supported_from)
    }
}

/// `3.20.3` 이 `3.21` 보다 낮은가 — 숫자 조각만 앞에서부터 견준다. 꼴이 아니면 거짓.
fn release_below(release: &str, floor: &str) -> bool {
    let parts = |s: &str| -> Option<Vec<String>> {
        s.split('.')
            .map(|p| {
                let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
                (!digits.is_empty()).then_some(digits)
            })
            .collect()
    };
    let (Some(a), Some(b)) = (parts(release), parts(floor)) else {
        return false;
    };
    for (x, y) in a.iter().zip(&b) {
        match super::version::compare_digits(x, y) {
            Ordering::Equal => continue,
            o => return o.is_lt(),
        }
    }
    a.len() < b.len()
}

/// 판에서 상류 번호(`X.Y.Z`)만 — epoch · 개정 · 꼬리를 뗀다. 꼴이 아니면 `None`.
fn upstream_of(manager: Manager, version: &str) -> Option<String> {
    let v = version.trim();
    let v = v.split_once(':').map_or(v, |(_, rest)| rest);
    let body = match manager {
        Manager::Dpkg | Manager::Rpm => v.rsplit_once('-').map_or(v, |(head, _)| head),
        Manager::Apk => v.rsplit_once("-r").map_or(v, |(head, _)| head),
    };
    let mut out = Vec::new();
    for piece in body.split('.').take(3) {
        let digits: String = piece.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let whole = digits.len() == piece.len();
        out.push(digits);
        if !whole {
            break;
        }
    }
    let joined = out.join(".");
    is_core(&joined).then_some(joined)
}

/// 그 관리자의 순서로 견준다. 견줄 수 없는 꼴이면 `None`.
fn compare(manager: Manager, version: &str, fixed: &str) -> Option<Ordering> {
    match manager {
        Manager::Dpkg => valid_debian(version).then(|| compare_debian(version, fixed)),
        Manager::Rpm => {
            // 개정이 한쪽에만 없을 때의 순서는 구현마다 다르다 — 갈리는 자리에서 *고침* 을 내지 않는다(PHP 의 RPM 줄과 같다).
            if !rpm_has_release(version) {
                return None;
            }
            rpm_version_cmp(version, fixed)
        }
        Manager::Apk => apk_version_cmp(version, fixed),
    }
}

/// 기준이 그 판에 하는 말.
enum Judgement<'a> {
    Affected(&'a Line),
    Fixed(&'a Line),
    NoFix(&'a Line),
    UpstreamAffected,
    UpstreamFixed,
    NotAffected,
    Unknown,
}

impl RuleSet {
    /// Apache 의 판 하나를 판정한다. `h2` 는 그 대상에서 모은 HTTP/2 흔적이다.
    pub fn evaluate_apache(&self, c: &Component, h2: &Http2, lang: Lang) -> Finding {
        let mut f = self.new_finding(c, lang);
        let Some(a) = self.apache.as_ref() else {
            return f;
        };
        if !c.trusted {
            return settle(
                f,
                Status::ReviewRequired,
                lang.t(
                    "이 Apache 의 판을 믿을 근거(패키지 기록과 파일의 일치 · 공식 이미지의 표지)를 확인하지 못했습니다.",
                    "No ground to trust this Apache's version (the package record matching the file, or the official image's markers) could be confirmed.",
                ),
                lang.t(
                    "빌드한 곳에 이 Apache 의 판과 CVE-2026-119618 보안 패치 포함 여부를 확인하십시오.",
                    "Ask whoever built this Apache for its version and whether it includes the CVE-2026-119618 security patch.",
                ),
            );
        }
        let judgement = if c.distribution == UPSTREAM {
            a.judge_upstream(&c.version)
        } else {
            a.judge_package(c)
        };
        let fixed = match &judgement {
            Judgement::Affected(l) | Judgement::Fixed(l) => {
                f.evidence.push(Evidence::new(
                    l.source.as_str(),
                    lang.pick(
                        format!(
                            "공급사 보안 패치 버전: {} / {}",
                            l.fixed,
                            a.cves().join(", ")
                        ),
                        format!(
                            "Vendor security patch version: {} / {}",
                            l.fixed,
                            a.cves().join(", ")
                        ),
                    ),
                ));
                l.fixed.clone()
            }
            Judgement::NoFix(l) => {
                f.evidence
                    .push(Evidence::new(l.source.as_str(), no_fix_detail(l, lang)));
                String::new()
            }
            _ => {
                f.evidence
                    .push(Evidence::new(a.data.source.as_str(), range_detail(a, lang)));
                a.upstream_fixed().to_string()
            }
        };
        match judgement {
            Judgement::Affected(_) | Judgement::UpstreamAffected => affected(f, h2, &fixed, lang),
            Judgement::Fixed(_) | Judgement::UpstreamFixed => settle(
                f,
                Status::Clear,
                lang.t(
                    "공급사 기준으로 CVE-2026-119618 보안 패치가 포함된 판입니다.",
                    "By the vendor's criteria this version includes the CVE-2026-119618 security patch.",
                ),
                lang.t(
                    "실행 중인 서비스에도 고친 판이 적용됐는지 확인하십시오.",
                    "Confirm the fixed version is in effect in the running service too.",
                ),
            ),
            Judgement::NotAffected => settle(
                f,
                Status::Clear,
                lang.t(
                    "CVE-2026-119618 의 영향 범위 밖의 판입니다.",
                    "This version is outside the range affected by CVE-2026-119618.",
                ),
                lang.t(
                    "다른 취약점의 보안 패치 여부는 공급사 공지로 따로 확인하십시오.",
                    "Check the vendor's advisories separately for other vulnerabilities.",
                ),
            ),
            Judgement::NoFix(_) => settle(
                f,
                Status::ReviewRequired,
                lang.t(
                    "CVE-2026-119618 의 영향 판인데 이 배포판 · 브랜치의 고친 판이 아직 없습니다.",
                    "This version is affected by CVE-2026-119618 and this distribution or branch has no fixed build yet.",
                ),
                lang.t(
                    "공급사 공지를 확인하고, 고칠 때까지 Protocols 에서 h2 · h2c 를 빼십시오.",
                    "Check the vendor's advisory, and take h2 and h2c out of Protocols until it is fixed.",
                ),
            ),
            Judgement::Unknown => settle(
                f,
                Status::ReviewRequired,
                lang.t(
                    "CVE-2026-119618 의 영향 범위일 수 있는 판인데, 이 배포판 · 빌드의 고친 판을 기준이 모릅니다.",
                    "This version may be in the range affected by CVE-2026-119618, but the criteria do not know this distribution's or build's fixed version.",
                ),
                lang.t(
                    "그 배포판 · 빌드의 공지를 확인하고, 고칠 때까지 Protocols 에서 h2 · h2c 를 빼십시오.",
                    "Check that distribution's or build's advisory, and take h2 and h2c out of Protocols until it is fixed.",
                ),
            ),
        }
    }
}

/// 영향 판 — HTTP/2 를 켠 흔적이 다 있으면 *취약*, 아니면 *확인 필요*.
fn affected(mut f: Finding, h2: &Http2, fixed: &str, lang: Lang) -> Finding {
    for path in &h2.module {
        f.evidence.push(Evidence::new(
            path.as_str(),
            lang.t(
                "HTTP/2 모듈(mod_http2)을 싣는 자리",
                "this loads the HTTP/2 module (mod_http2)",
            ),
        ));
    }
    for path in &h2.protocols {
        f.evidence.push(Evidence::new(
            path.as_str(),
            lang.t(
                "HTTP/2(h2 · h2c)를 켜는 Protocols 줄",
                "a Protocols line turns HTTP/2 (h2, h2c) on",
            ),
        ));
    }
    if h2.enabled() {
        return settle_vulnerable(f, fixed, lang);
    }
    for path in &h2.unread {
        f.evidence.push(Evidence::new(
            path.as_str(),
            lang.t(
                "HTTP/2 를 켜는 줄이 있을 수 있는 설정 파일인데 본문 전체를 읽지 못했습니다(수집 한도)",
                "a settings file that may hold HTTP/2 signs could not be read whole (collection limit)",
            ),
        ));
    }
    settle_review_signs(f, fixed, lang)
}

fn settle_vulnerable(f: Finding, fixed: &str, lang: Lang) -> Finding {
    settle(
        f,
        Status::Vulnerable,
        lang.t(
            "CVE-2026-119618 보안 패치가 적용되지 않은 Apache 이고, HTTP/2(h2 · h2c)를 켠 설정이 있습니다.",
            "This Apache does not have the CVE-2026-119618 security patch, and its settings turn HTTP/2 (h2, h2c) on.",
        ),
        lang.pick(
            format!("{fixed} 이상으로 올린 뒤 다시 점검하십시오. 그때까지 Protocols 에서 h2 · h2c 를 빼십시오."),
            format!("Upgrade to {fixed} or later, then check again. Until then take h2 and h2c out of Protocols."),
        ),
    )
}

/// 영향 판인데 HTTP/2 를 켠 흔적을 다 찾지 못했다.
fn settle_review_signs(f: Finding, fixed: &str, lang: Lang) -> Finding {
    settle(
        f,
        Status::ReviewRequired,
        lang.t(
            "CVE-2026-119618 의 영향 판인데, HTTP/2 를 켠 설정(모듈 적재와 Protocols 의 h2 · h2c)을 다 찾지 못했습니다 — 이미지 밖의 설정(마운트 · 시작 옵션)이나 Include 로 읽는 다른 설정에서 켰을 수 있습니다.",
            "This version is affected by CVE-2026-119618, but not every sign of HTTP/2 being on (the module loaded and h2 or h2c in Protocols) was found - it may be turned on by settings outside the image (mounts, start options) or another file it includes.",
        ),
        lang.pick(
            format!("{fixed} 이상으로 올리십시오. 그때까지 Protocols 에 h2 · h2c 를 두지 마십시오."),
            format!("Upgrade to {fixed} or later. Until then keep h2 and h2c out of Protocols."),
        ),
    )
}

fn no_fix_detail(l: &Line, lang: Lang) -> String {
    if l.no_fix {
        lang.t(
            "공급사 공지: 영향 · 고침 대기",
            "Vendor advisory: affected, fix pending",
        )
        .to_string()
    } else {
        lang.pick(
            format!("지원이 끝난 브랜치(배포판 {} 아래)라 고친 판이 없습니다 — 지원 중인 브랜치의 고친 판: {}", l.supported_from, l.fixed),
            format!("A branch past its support (below release {}) has no fixed build - the supported branches' fixed version: {}", l.supported_from, l.fixed),
        )
    }
}

fn range_detail(a: &ApacheCriteria, lang: Lang) -> String {
    let [low, high] = &a.data.upstream.affected;
    let [mlow, mhigh] = &a.data.module.affected;
    let fixed = a.upstream_fixed();
    lang.pick(
        format!("상류 영향 범위: httpd {low} ~ {high}(고친 판 {fixed}) · mod_h2 {mlow} ~ {mhigh}"),
        format!("Upstream affected range: httpd {low} - {high} (fixed in {fixed}), mod_h2 {mlow} - {mhigh}"),
    )
}

// ── 검사 ─────────────────────────────────────────────────────────────────

fn check(d: &Data) -> Result<(), String> {
    if d.schema_version != SCHEMA_VERSION {
        return Err(format!("지원하지 않는 기준 형식이다: {}", d.schema_version));
    }
    if !date(&d.checked) || d.same_as.trim().is_empty() || !super::data::https(&d.source) {
        return Err("확인한 날 · 같은 룰 · 출처가 없거나 꼴이 잘못됐다".to_string());
    }
    if d.cves.is_empty() {
        return Err("취약점 목록이 없다".to_string());
    }
    for (i, cve) in d.cves.iter().enumerate() {
        if !super::data::cve_id(cve) || d.cves[..i].contains(cve) {
            return Err(format!("CVE 번호의 꼴이 잘못됐거나 겹친다: {cve}"));
        }
    }
    let [low, high] = &d.upstream.affected;
    let fixed = &d.upstream.fixed;
    let [mlow, mhigh] = &d.module.affected;
    let cores = [low, high, fixed, mlow, mhigh].iter().all(|v| is_core(v));
    if !cores
        || compare_core(low, high).is_gt()
        || compare_core(high, fixed).is_ge()
        || compare_core(mlow, mhigh).is_gt()
    {
        return Err(
            "영향 범위나 상류의 고친 판이 X.Y.Z 가 아니거나 순서가 맞지 않는다".to_string(),
        );
    }
    if d.lines.is_empty() || d.lines.len() > MAX_LINES {
        return Err(format!("공급사 줄이 없거나 {MAX_LINES}개를 넘는다"));
    }
    for (i, l) in d.lines.iter().enumerate() {
        check_line(l).map_err(|e| format!("줄 {}: {e}", i + 1))?;
    }
    Ok(())
}

fn check_line(l: &Line) -> Result<(), String> {
    let token = |s: &str| {
        !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
    };
    if !token(&l.package) || !super::data::https(&l.source) {
        return Err("패키지 이름이나 출처가 없거나 꼴이 잘못됐다".to_string());
    }
    match (l.manager, l.vendor.is_empty()) {
        (Manager::Rpm, true) => return Err("RPM 줄에는 공급사가 있어야 한다".to_string()),
        (Manager::Dpkg | Manager::Apk, false) => {
            return Err("공급사는 RPM 줄에만 적는다".to_string())
        }
        _ => {}
    }
    if l.manager == Manager::Rpm && !token(&l.vendor) {
        return Err("공급사의 꼴이 잘못됐다".to_string());
    }
    if !l.supported_from.is_empty()
        && (l.manager != Manager::Apk || !release_like(&l.supported_from))
    {
        return Err("supported_from 은 apk 줄에만 · 배포판 버전 꼴로 적는다".to_string());
    }
    for (name, v) in [
        ("upstream", &l.upstream),
        ("from_upstream", &l.from_upstream),
    ] {
        if !v.is_empty() && !is_core(v) {
            return Err(format!("{name} 이 X.Y.Z 가 아니다: {v}"));
        }
    }
    if l.no_fix {
        if !l.fixed.is_empty() || !l.supported_from.is_empty() {
            return Err("고침이 없는 줄에는 고친 판 · 지원 하한을 적지 않는다".to_string());
        }
        return Ok(());
    }
    if !fixed_shape(l.manager, &l.fixed) {
        return Err(format!(
            "고친 판의 꼴이 그 관리자의 것이 아니다: {}",
            l.fixed
        ));
    }
    if l.version_pattern
        .as_ref()
        .is_some_and(|p| !p.is_match(&l.fixed))
        || l.except_pattern
            .as_ref()
            .is_some_and(|p| p.is_match(&l.fixed))
    {
        return Err(format!("고친 판이 그 줄의 꼴에 들지 않는다: {}", l.fixed));
    }
    let up = upstream_of(l.manager, &l.fixed);
    if !l.upstream.is_empty() && up.as_deref() != Some(l.upstream.as_str()) {
        return Err(format!(
            "고친 판의 상류 번호가 upstream 과 다르다: {}",
            l.fixed
        ));
    }
    if !l.from_upstream.is_empty()
        && !up
            .as_deref()
            .is_some_and(|u| compare_core(u, &l.from_upstream).is_ge())
    {
        return Err(format!("고친 판이 from_upstream 아래다: {}", l.fixed));
    }
    Ok(())
}

fn fixed_shape(manager: Manager, fixed: &str) -> bool {
    if fixed.is_empty() || fixed.len() > MAX_VERSION_BYTES {
        return false;
    }
    match manager {
        Manager::Dpkg => valid_debian(fixed),
        Manager::Rpm => is_rpm_version(fixed) && rpm_has_release(fixed),
        Manager::Apk => is_apk_version(fixed),
    }
}

/// `3.21` 꼴 — 숫자 조각을 `.` 로 이은 것.
fn release_like(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `YYYY-MM-DD`.
fn date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
        && core(&s.replace('-', ".")).is_some()
}

#[cfg(test)]
mod tests {
    //! 판정 표 — 본체의 점검 룰 하네스(`testbed/harness/linux/apache-verify.sh`)가 재는 경우를 같은 판정으로 옮겼다.
    //! 기준은 `testdata/apache.json`(데이터 룰의 그 파일과 같은 사본).
    use super::*;
    use crate::scan::model::Product;
    use Status::{Clear, ReviewRequired as Review, Vulnerable};

    fn rules() -> &'static RuleSet {
        RuleSet::fixture()
    }

    fn package(manager: PackageManager, name: &str, version: &str) -> Component {
        let mut c = Component::new(Product::Apache);
        c.id = format!("t:{name}");
        c.name = "시험".to_string();
        c.package = name.to_string();
        c.version = version.to_string();
        c.distribution = "linux".to_string();
        c.package_manager = manager;
        c.trusted = true;
        c
    }

    fn rpm(vendor: &str, version: &str) -> Component {
        let mut c = package(PackageManager::Rpm, "mod_http2", version);
        c.package_vendor = vendor.to_string();
        c
    }

    fn apk(version: &str, release: &str) -> Component {
        let mut c = package(PackageManager::Apk, "apache2-http2", version);
        c.distribution = "alpine".to_string();
        c.distribution_version = release.to_string();
        c
    }

    fn upstream(version: &str) -> Component {
        let mut c = Component::new(Product::Apache);
        c.id = "t:httpd".to_string();
        c.version = version.to_string();
        c.distribution = UPSTREAM.to_string();
        c.trusted = true;
        c
    }

    fn on() -> Http2 {
        Http2 {
            module: vec!["/etc/apache2/mods-enabled/http2.load".to_string()],
            protocols: vec!["/etc/apache2/mods-enabled/http2.conf".to_string()],
            ..Http2::default()
        }
    }

    /// 켠 흔적이 있으면 그 판정, 없으면 그 판정 — 영향 판만 둘이 갈린다.
    fn both(c: &Component) -> (Status, Status) {
        let lang = Lang::Ko;
        (
            rules().evaluate_apache(c, &on(), lang).status,
            rules().evaluate_apache(c, &Http2::default(), lang).status,
        )
    }

    const DPKG: PackageManager = PackageManager::Dpkg;

    #[test]
    fn the_criteria_file_reads_and_names_its_packages() {
        let a = rules().apache().expect("기준");
        assert_eq!(a.checked(), "2026-11-13");
        assert_eq!(rules().cves(Product::Apache), ["CVE-2026-119618"]);
        assert!(rules().supports(Product::Apache));
        assert!(a.watches(DPKG, "apache2-bin"));
        assert!(a.watches(PackageManager::Rpm, "mod_http2"));
        assert!(a.watches(PackageManager::Rpm, "apache2"));
        assert!(a.watches(PackageManager::Apk, "apache2-http2"));
        // RHEL 의 httpd 에는 HTTP/2 코드가 없다(mod_http2 가 따로) · 관리자를 모르면 보지 않는다.
        assert!(!a.watches(PackageManager::Rpm, "httpd"));
        assert!(!a.watches(PackageManager::Unknown, "apache2-bin"));
        assert!(!a.watches(DPKG, "mod_http2"));
    }

    #[test]
    fn debian_and_ubuntu_lines() {
        for (version, want) in [
            // Debian 12 · 13 — 보안 갱신 꼬리(`~deb12u`)의 줄
            ("2.4.62-1~deb12u2", (Vulnerable, Review)),
            ("2.4.71-1~deb12u1", (Clear, Clear)),
            ("2.4.69-1~deb13u1", (Vulnerable, Review)),
            ("2.4.71-1~deb13u1", (Clear, Clear)),
            // testing · sid — 꼬리 없는 개정. 상류 2.4.54 이하는 영향이 없다.
            ("2.4.70-1", (Vulnerable, Review)),
            ("2.4.70-1+b2", (Vulnerable, Review)),
            ("2.4.71-1", (Clear, Clear)),
            ("2.4.54-1", (Clear, Clear)),
            // Ubuntu — 상류 번호마다 줄. 22.04 · 20.04 는 상류 2.4.55 아래인데 영향이다(새 mod_http2 백포트).
            ("2.4.58-1ubuntu8.18", (Vulnerable, Review)),
            ("2.4.58-1ubuntu8.19", (Clear, Clear)),
            ("2.4.68-1ubuntu6.1", (Vulnerable, Review)),
            ("2.4.52-1ubuntu4.26", (Vulnerable, Review)),
            ("2.4.52-1ubuntu4.27", (Clear, Clear)),
            ("2.4.41-4ubuntu3.23+esm10", (Vulnerable, Review)),
            ("2.4.41-4ubuntu3.23+esm11", (Clear, Clear)),
            // 줄 밖 — 영향 범위면 고친 판을 모르는 빌드(지원이 끝난 Debian 11 · PPA), 아니면 영향 없음.
            ("2.4.62-1~deb11u2", (Review, Review)),
            ("2.4.65-1+ubuntu24.04.1+deb.sury.org+1", (Review, Review)),
            ("2.4.38-3+deb10u10", (Clear, Clear)),
            ("2.4.29-1ubuntu4.27", (Clear, Clear)),
        ] {
            assert_eq!(
                both(&package(DPKG, "apache2-bin", version)),
                want,
                "{version}"
            );
        }
    }

    #[test]
    fn rpm_lines_go_by_vendor_and_stream() {
        let rh = "Red Hat, Inc.";
        let rocky = "Rocky Enterprise Software Foundation";
        let amazon = "Amazon Linux";
        for (vendor, version, want) in [
            // RHEL 은 마이너 스트림마다 고친 판이 다르다 — EUS 에서 고친 기계를 취약으로 내지 않는다.
            (rh, "2.0.26-6.el9_8.2", (Vulnerable, Review)),
            (rh, "2.0.26-6.el9_8.3", (Clear, Clear)),
            (rh, "2.0.26-4.el9_6.3", (Clear, Clear)),
            (rh, "2.0.26-2.el9_4.3", (Vulnerable, Review)),
            (rh, "2.0.26-7.el9_9.1", (Clear, Clear)),
            (rh, "2.0.26-5.el9", (Vulnerable, Review)),
            (rh, "2.0.29-2.el10_0.3", (Clear, Clear)),
            (rh, "2.0.29-5.el10_3", (Vulnerable, Review)),
            // RHEL 8 은 mod_http2 1.15 라 영향이 없다(VEX).
            (
                rh,
                "1.15.7-10.module+el8.10.0+21100+abcdef01",
                (Clear, Clear),
            ),
            // Rocky 는 본류의 고친 판 하나와 견준다 — 하네스 이미지(rocky9)가 이 판이다.
            (rocky, "2.0.26-6.el9_8.2", (Vulnerable, Review)),
            (rocky, "2.0.26-7.el9_9.1", (Clear, Clear)),
            (rocky, "2.0.29-5.el10_3.1", (Clear, Clear)),
            // Amazon Linux 는 httpd 의 번호(epoch 1)를 쓴다.
            (amazon, "1:2.4.62-1.amzn2023.0.1", (Vulnerable, Review)),
            (amazon, "1:2.4.71-1.amzn2023.0.1", (Clear, Clear)),
            (amazon, "1:2.4.71-1.amzn2.0.1", (Clear, Clear)),
            // 공지를 읽지 않은 공급사(AlmaLinux) — 영향 범위면 고친 판을 모른다.
            ("AlmaLinux", "2.0.26-6.el9_8.2", (Review, Review)),
            // 개정이 없는 판은 견주지 않는다.
            (rh, "2.0.26", (Review, Review)),
        ] {
            assert_eq!(both(&rpm(vendor, version)), want, "{vendor} {version}");
        }
    }

    #[test]
    fn suse_waits_for_a_fix_from_sp4() {
        let suse = "SUSE LLC <https://www.suse.com/>";
        let mut sp4 = package(PackageManager::Rpm, "apache2", "2.4.51-150400.6.43.1");
        sp4.package_vendor = suse.to_string();
        assert_eq!(both(&sp4), (Review, Review));
        let f = rules().evaluate_apache(&sp4, &on(), Lang::Ko);
        assert!(
            f.evidence.iter().any(|e| e.detail.contains("고침 대기")),
            "{f:#?}"
        );
        // SP3 이전의 코드 줄기는 영향이 없다.
        let mut sp3 = package(PackageManager::Rpm, "apache2", "2.4.51-150300.4.1");
        sp3.package_vendor = suse.to_string();
        assert_eq!(both(&sp3), (Clear, Clear));
    }

    #[test]
    fn alpine_lines_and_branches_past_support() {
        for (version, release, want) in [
            ("2.4.65-r1", "3.22.2", (Vulnerable, Review)),
            ("2.4.71-r0", "3.22.2", (Clear, Clear)),
            ("2.4.71-r0", "3.21.0", (Clear, Clear)),
            // 지원이 끝난 브랜치의 영향 판 — 그 브랜치에는 고친 판이 없다.
            ("2.4.62-r0", "3.20.3", (Review, Review)),
            ("2.4.71-r0", "3.20.3", (Clear, Clear)),
            // 배포판 버전을 모르면 지원 중으로 본다(호스트 룰과 같다).
            ("2.4.65-r1", "", (Vulnerable, Review)),
            // 상류 2.4.54 이하는 영향이 없다.
            ("2.4.54-r0", "3.22.2", (Clear, Clear)),
        ] {
            assert_eq!(both(&apk(version, release)), want, "{version} on {release}");
        }
    }

    #[test]
    fn a_self_built_apache_goes_by_the_upstream_version() {
        for (version, want) in [
            ("2.4.65", (Vulnerable, Review)),
            ("2.4.55", (Vulnerable, Review)),
            ("2.4.70", (Vulnerable, Review)),
            ("2.4.71", (Clear, Clear)),
            ("2.4.72", (Clear, Clear)),
            ("2.4.54", (Clear, Clear)),
            ("2.4.65-dev", (Review, Review)),
            ("", (Review, Review)),
        ] {
            assert_eq!(both(&upstream(version)), want, "{version}");
        }
        let f = rules().evaluate_apache(&upstream("2.4.65"), &on(), Lang::Ko);
        assert!(f.action.contains("2.4.71 이상"), "{}", f.action);
        assert_eq!(f.cves, ["CVE-2026-119618"]);
    }

    #[test]
    fn nothing_is_judged_without_ground_to_trust_it() {
        let mut c = upstream("2.4.65");
        c.trusted = false;
        let f = rules().evaluate_apache(&c, &on(), Lang::Ko);
        assert_eq!(f.status, Review);
        assert!(f.reason.contains("믿을 근거"), "{}", f.reason);
        let mut p = package(DPKG, "apache2-bin", "2.4.71-1~deb12u1");
        p.trusted = false;
        assert_eq!(both(&p), (Review, Review));
        // Apache 기준을 읽지 않은 기준(baseline 만)은 판정하지 않는다.
        let bare = RuleSet::from_json(crate::criteria::testkit::BASELINE).expect("기준");
        assert!(!bare.supports(Product::Apache));
        assert_eq!(
            bare.evaluate_apache(&upstream("2.4.71"), &on(), Lang::Ko)
                .status,
            Review
        );
    }

    #[test]
    fn an_affected_finding_names_the_signs_it_found() {
        let f = rules().evaluate_apache(
            &package(DPKG, "apache2-bin", "2.4.62-1~deb12u2"),
            &on(),
            Lang::En,
        );
        assert_eq!(f.status, Vulnerable);
        assert!(f.evidence.iter().any(|e| e.source.ends_with("http2.load")));
        assert!(f.evidence.iter().any(|e| e.source.ends_with("http2.conf")));
        assert!(f
            .evidence
            .iter()
            .any(|e| e.detail.contains("2.4.71-1~deb12u1")));
        let half = Http2 {
            module: vec!["/etc/httpd/conf.modules.d/10-h2.conf".to_string()],
            unread: vec!["/etc/httpd/conf/httpd.conf".to_string()],
            ..Http2::default()
        };
        let f = rules().evaluate_apache(
            &rpm("Rocky Enterprise Software Foundation", "2.0.26-6.el9_8.2"),
            &half,
            Lang::Ko,
        );
        assert_eq!(f.status, Review);
        assert!(f.reason.contains("다 찾지 못했습니다"), "{}", f.reason);
        // 본문 전체를 읽지 못한 설정 파일을 근거에 적는다 — 흔적이 거기 있었을 수 있다.
        assert!(f
            .evidence
            .iter()
            .any(|e| e.source == "/etc/httpd/conf/httpd.conf"
                && e.detail.contains("읽지 못했습니다")));
    }

    #[test]
    fn upstream_numbers() {
        for (manager, version, want) in [
            (Manager::Dpkg, "1:2.4.62-1~deb12u2", Some("2.4.62")),
            (Manager::Dpkg, "2.4.41-4ubuntu3.23+esm11", Some("2.4.41")),
            (Manager::Dpkg, "2.4.71", Some("2.4.71")),
            (Manager::Rpm, "1:2.4.71-1.amzn2023.0.1", Some("2.4.71")),
            (Manager::Rpm, "2.0.26-6.el9_8.2", Some("2.0.26")),
            (
                Manager::Rpm,
                "1.15.7-10.module+el8.10.0+21100+abcdef01",
                Some("1.15.7"),
            ),
            (Manager::Apk, "2.4.71-r0", Some("2.4.71")),
            (Manager::Apk, "2.4.71_p1-r0", Some("2.4.71")),
            (Manager::Dpkg, "2.4-1", None),
            (Manager::Dpkg, "abc", None),
            (Manager::Rpm, "", None),
        ] {
            assert_eq!(upstream_of(manager, version).as_deref(), want, "{version}");
        }
        assert!(release_below("3.20.3", "3.21"));
        assert!(release_below("3.2", "3.21"));
        assert!(!release_below("3.21.0", "3.21"));
        assert!(!release_below("3.22", "3.21"));
        assert!(!release_below("edge", "3.21"));
        assert!(!release_below("", "3.21"));
    }

    /// 기준 파일 하나를 고치는 손질.
    type Edit = Box<dyn Fn(&mut serde_json::Value)>;

    /// 기준 파일의 꼴 — 모르는 칸 · 줄과 맞지 않는 고친 판 · 그 관리자의 꼴이 아닌 판은 읽지 않는다.
    #[test]
    fn a_malformed_criteria_file_is_refused() {
        let good: serde_json::Value =
            serde_json::from_str(crate::criteria::testkit::APACHE).expect("사본");
        assert!(ApacheCriteria::from_json(&good.to_string()).is_ok());
        let bad = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut v = good.clone();
            edit(&mut v);
            ApacheCriteria::from_json(&v.to_string())
                .err()
                .unwrap_or_default()
        };
        let cases: Vec<(&str, Edit)> = vec![
            ("모르는 칸", Box::new(|v| v["extra"] = 1.into())),
            (
                "줄의 모르는 칸",
                Box::new(|v| v["lines"][0]["stream"] = "x".into()),
            ),
            ("형식 2", Box::new(|v| v["schema_version"] = 2.into())),
            ("날짜", Box::new(|v| v["checked"] = "2026-11".into())),
            (
                "CVE",
                Box::new(|v| v["cves"] = serde_json::json!(["CVE-26-1"])),
            ),
            (
                "범위 순서",
                Box::new(|v| v["upstream"]["affected"] = serde_json::json!(["2.4.70", "2.4.55"])),
            ),
            (
                "고친 판이 범위 안",
                Box::new(|v| v["upstream"]["fixed"] = "2.4.60".into()),
            ),
            (
                "RPM 줄에 공급사 없음",
                Box::new(|v| v["lines"][8]["vendor"] = "".into()),
            ),
            (
                "dpkg 줄에 공급사",
                Box::new(|v| v["lines"][0]["vendor"] = "Debian".into()),
            ),
            (
                "꼴에 들지 않는 고친 판",
                Box::new(|v| v["lines"][0]["fixed"] = "2.4.71-1~deb13u1".into()),
            ),
            (
                "못박지 않은 꼴",
                Box::new(|v| v["lines"][0]["version_pattern"] = "~deb12u[0-9]+$".into()),
            ),
            (
                "관리자의 꼴이 아닌 판",
                Box::new(|v| v["lines"][20]["fixed"] = "2.4.71".into()),
            ),
            (
                "upstream 과 다른 고친 판",
                Box::new(|v| v["lines"][3]["upstream"] = "2.4.66".into()),
            ),
            (
                "고침 없음인데 고친 판",
                Box::new(|v| v["lines"][19]["fixed"] = "2.4.51-150400.1.1".into()),
            ),
            (
                "dpkg 줄의 지원 하한",
                Box::new(|v| v["lines"][0]["supported_from"] = "12".into()),
            ),
            (
                "출처",
                Box::new(|v| v["lines"][0]["source"] = "http://example.com/".into()),
            ),
            ("줄 없음", Box::new(|v| v["lines"] = serde_json::json!([]))),
        ];
        for (name, edit) in cases {
            assert!(!bad(edit.as_ref()).is_empty(), "{name} 을 받았다");
        }
    }
}
