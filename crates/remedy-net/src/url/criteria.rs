//! PHP2Shell(CVE-2026-109618 · CVE-2026-109619) 의 수정 버전 — 응답 헤더가 알리는 버전을 견줄 기준.
//!
//! **표는 이 바이너리에 없다.** 데이터 룰 `remedy-net-criteria` 의 `url.json` 이 상류 수정 버전 · 지원이 끝난
//! 계열 · 배포판 공지 줄을 담고, 이 프로그램은 서명을 확인한 그 파일을 읽는다(`crate::criteria` · 코어
//! 1.12.0). 그 표는 본체의 점검 룰 `php2shell-check-linux` 의 배포판 줄 · 상류 수정 버전과 같은 값이고,
//! 두 자리가 같은지는 저장소 검사(`cargo xtask net-criteria`)가 본다 — 룰이나 기준이 바뀌어도 이 코드는
//! 바뀌지 않는다. 여기 남는 것은 그 표로 견주는 법(버전 · dpkg 비교)이다.
//!
//! 헤더는 남이 적은 글자다. 그래서 이 표는 **취약 쪽으로만** 판정을 바꾼다 — 수정 버전 이상이어도
//! 백포트 · 직접 빌드를 헤더로 가릴 수 없어 *확인 필요* 로 둔다(양호를 내지 않는다).

use serde::Deserialize;
use std::collections::BTreeMap;

/// 이 코드가 읽는 url 표의 형식.
const SCHEMA_VERSION: u32 = 1;

/// 서명을 확인한 `url.json` 에서 읽은 표.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UrlCriteria {
    schema_version: u32,
    /// 기준을 다시 확인한 날 — 결과 파일과 화면에 싣는다(결정 10: 만료를 두지 않는 대신 날짜를 적는다).
    pub(crate) checked: String,
    pub(crate) cves: Vec<String>,
    /// 같은 값을 쓰는 본체의 점검 룰(`<id> <버전>`).
    pub(crate) same_as: String,
    pub(crate) sources: Vec<String>,
    /// 상류 계열(`8.3`) → 수정 버전(`8.3.36`).
    upstream: BTreeMap<String, String>,
    /// php.net 수정 버전이 없는 계열 — 순수한 `X.Y.Z` 면 영향 버전이다.
    legacy: Vec<String>,
    /// 배포판 공지 줄.
    lines: Vec<Line>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Distro {
    Debian,
    Ubuntu,
}

/// 배포판 공지 한 줄 — 패키지 이름의 앞머리(`php8.2-` · `php5-`)와 그 배포판의 수정 버전.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    distro: Distro,
    release: String,
    package: String,
    fixed: String,
}

impl UrlCriteria {
    /// `url.json` 의 글에서 읽고, 견줄 수 있는 꼴인지 본다. 모르는 칸 · 꼴이 틀린 줄이 있으면 실패한다.
    pub(crate) fn from_json(text: &str) -> Result<UrlCriteria, String> {
        let c: UrlCriteria =
            serde_json::from_str(text).map_err(|e| format!("url 표를 읽지 못했다: {e}"))?;
        if c.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "지원하지 않는 url 표 형식이다: {}",
                c.schema_version
            ));
        }
        c.check()?;
        Ok(c)
    }

    fn check(&self) -> Result<(), String> {
        if !date(&self.checked) {
            return Err(format!("확인 날짜의 꼴이 잘못됐다: {}", self.checked));
        }
        if self.cves.is_empty() || !self.cves.iter().all(|c| cve(c)) {
            return Err("취약점 목록이 비었거나 CVE 번호의 꼴이 잘못됐다".to_string());
        }
        if self.same_as.trim().is_empty() {
            return Err("같은 값을 쓰는 룰(same_as)이 비었다".to_string());
        }
        if self.sources.is_empty() || !self.sources.iter().all(|s| s.starts_with("https://")) {
            return Err("출처가 없거나 https 주소가 아니다".to_string());
        }
        if self.upstream.is_empty() {
            return Err("상류 수정 버전이 하나도 없다".to_string());
        }
        for (branch, fixed) in &self.upstream {
            let in_branch = fixed
                .strip_prefix(branch.as_str())
                .is_some_and(|rest| rest.starts_with('.'));
            if php_branch_name(branch).is_none() || core(fixed).is_none() || !in_branch {
                return Err(format!(
                    "상류 수정 버전의 꼴이 잘못됐다: {branch} → {fixed}"
                ));
            }
        }
        for (i, branch) in self.legacy.iter().enumerate() {
            if php_branch_name(branch).is_none()
                || self.legacy[..i].contains(branch)
                || self.upstream.contains_key(branch)
            {
                return Err(format!(
                    "지원이 끝난 계열의 꼴이 잘못됐거나 겹친다: {branch}"
                ));
            }
        }
        for l in &self.lines {
            let package = l
                .package
                .strip_prefix("php")
                .and_then(|p| p.strip_suffix('-'));
            let branch_ok = package.is_some_and(|p| p == "5" || php_branch_name(p).is_some());
            if !branch_ok || l.release.is_empty() || !valid_debian(&l.fixed) {
                return Err(format!(
                    "배포판 공지 줄의 꼴이 잘못됐다: {} {} {}",
                    l.release, l.package, l.fixed
                ));
            }
        }
        Ok(())
    }

    /// 헤더가 알리는 버전이 수정 버전보다 낮은가. `Some(true)` 면 영향 버전, `Some(false)` 면 수정 버전
    /// 이상(그래도 헤더로는 양호를 낼 수 없다), `None` 이면 이 표로 가릴 수 없는 버전(직접 빌드 꼬리 ·
    /// 사전 공개 · 모르는 계열 · 배포판 줄과 맞지 않는 꼬리).
    pub(crate) fn below_fix(&self, version: &str) -> Option<bool> {
        if version.is_empty() {
            return None;
        }
        if let Some([major, minor, _]) = core(version) {
            let branch = format!("{major}.{minor}");
            return match self.upstream.get(&branch) {
                Some(fixed) => Some(compare_core(version, fixed).is_lt()),
                None => self.legacy.contains(&branch).then_some(true),
            };
        }
        if !valid_debian(version) {
            return None;
        }
        let branch = php_branch(version)?;
        let package = if branch.starts_with("5.") {
            "php5-".to_string()
        } else {
            format!("php{branch}-")
        };
        let release = debian_release(version);
        let mut fixed: Option<&str> = None;
        for line in self.lines.iter().filter(|l| l.package == package) {
            // 배너는 배포판을 밝히지 않는다. Debian 은 `~debN` 표식이, Ubuntu 는 알려진 패키지 줄이 맞아야 견준다.
            let matches = match line.distro {
                Distro::Debian => release == Some(line.release.as_str()),
                Distro::Ubuntu => ubuntu_line(version, &line.fixed),
            };
            if !matches {
                continue;
            }
            if fixed.is_some_and(|f| f != line.fixed) {
                return None;
            }
            fixed = Some(line.fixed.as_str());
        }
        fixed.map(|f| compare_debian(version, f).is_lt())
    }
}

/// `YYYY-MM-DD`.
fn date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

/// `CVE-YYYY-N…`(번호 넷 이상).
fn cve(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, n)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && n.len() >= 4
        && n.bytes().all(|b| b.is_ascii_digit())
}

/// 계열 이름(`8.3`) — 숫자 두 조각.
fn php_branch_name(s: &str) -> Option<()> {
    let (a, b) = s.split_once('.')?;
    let digits = |s: &str| (1..=6).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit());
    (digits(a) && digits(b)).then_some(())
}

/// `X.Y.Z`(각 1~6자리 숫자)면 세 조각.
fn core(v: &str) -> Option<[&str; 3]> {
    let mut it = v.split('.');
    let parts = [it.next()?, it.next()?, it.next()?];
    if it.next().is_some() {
        return None;
    }
    parts
        .iter()
        .all(|p| (1..=6).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
        .then_some(parts)
}

fn compare_core(a: &str, b: &str) -> std::cmp::Ordering {
    for (x, y) in a.split('.').zip(b.split('.')) {
        let c = compare_digits(x, y);
        if c.is_ne() {
            return c;
        }
    }
    std::cmp::Ordering::Equal
}

/// 앞의 0 을 떼고 길이 → 사전순으로 견준다(긴 숫자도 넘치지 않는다).
fn compare_digits(a: &str, b: &str) -> std::cmp::Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// `8.2.` 꼴의 앞머리 → `8.2`.
fn php_branch(v: &str) -> Option<String> {
    let mut it = v.splitn(3, '.');
    let (a, b) = (it.next()?, it.next()?);
    it.next()?;
    let digits = |s: &str| (1..=6).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit());
    (digits(a) && digits(b)).then(|| format!("{a}.{b}"))
}

/// 끝의 `~debNuK` → `N`.
fn debian_release(v: &str) -> Option<&str> {
    let at = v.rfind("~deb")?;
    let (n, k) = v[at + 4..].split_once('u')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    ((1..=6).contains(&n.len()) && digits(n) && digits(k)).then_some(n)
}

/// 데비안 판 문자열의 꼴(`[epoch:]upstream[-revision]`)인가.
fn valid_debian(s: &str) -> bool {
    if s.is_empty() || s.len() > 256 {
        return false;
    }
    let mut core = s;
    if let Some(i) = core.find(':') {
        if i == 0 || !core[..i].bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        core = &core[i + 1..];
    }
    if !core.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        return false;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".+~:-".contains(&b))
    {
        return false;
    }
    if let Some(i) = core.rfind('-') {
        let revision = &core[i + 1..];
        if i == 0
            || revision.is_empty()
            || !revision
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+~".contains(&b))
        {
            return false;
        }
    }
    true
}

/// 헤더의 판이 그 Ubuntu 패키지 줄의 것인가 — 모르는 꼬리(PPA · 직접 빌드)는 Ubuntu 수정을 물려받지 않는다.
/// ESM 은 상류 판을 두고 `+esmN` 을 붙이므로, ESM 공지에서만 그 꼬리를 받는다.
fn ubuntu_line(version: &str, fixed: &str) -> bool {
    if let Some(i) = fixed.find("+esm") {
        if !numeric(&fixed[i + 4..]) {
            return false;
        }
        let base = match version.find("+esm") {
            Some(j) if numeric(&version[j + 4..]) => &version[..j],
            Some(_) => return false,
            None => version,
        };
        return ubuntu_line(base, &fixed[..i]);
    }
    let Some(i) = fixed.rfind('.') else {
        return version == fixed;
    };
    let prefix = &fixed[..=i];
    if version == &prefix[..prefix.len() - 1] {
        return true;
    }
    match version.strip_prefix(prefix) {
        Some(suffix) => numeric(suffix),
        None => false,
    }
}

fn numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// dpkg 의 판 비교 — epoch → 상류 → 개정. `~` 는 무엇보다 앞선다.
fn compare_debian(a: &str, b: &str) -> std::cmp::Ordering {
    let (ae, au, ar) = split_debian(a);
    let (be, bu, br) = split_debian(b);
    compare_digits(ae, be)
        .then_with(|| debian_part(au, bu))
        .then_with(|| debian_part(ar, br))
}

fn split_debian(s: &str) -> (&str, &str, &str) {
    let (epoch, rest) = match s.find(':') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => ("0", s),
    };
    match rest.rfind('-') {
        Some(i) => (epoch, &rest[..i], &rest[i + 1..]),
        None => (epoch, rest, "0"),
    }
}

fn order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

fn debian_part(a: &str, b: &str) -> std::cmp::Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() || !b.is_empty() {
        while a.first().is_some_and(|c| !c.is_ascii_digit())
            || b.first().is_some_and(|c| !c.is_ascii_digit())
        {
            let c = order(a.first().copied()).cmp(&order(b.first().copied()));
            if c.is_ne() {
                return c;
            }
            a = a.get(1..).unwrap_or_default();
            b = b.get(1..).unwrap_or_default();
        }
        let i = a.iter().take_while(|c| c.is_ascii_digit()).count();
        let j = b.iter().take_while(|c| c.is_ascii_digit()).count();
        let (x, y) = (
            std::str::from_utf8(&a[..i]).unwrap_or_default(),
            std::str::from_utf8(&b[..j]).unwrap_or_default(),
        );
        let c = compare_digits(x, y);
        if c.is_ne() {
            return c;
        }
        a = &a[i..];
        b = &b[j..];
    }
    std::cmp::Ordering::Equal
}

/// 시험이 쓰는 표 — `testdata/url.json`(1.11.0 까지 바이너리에 들던 값의 고정 사본).
#[cfg(test)]
pub(crate) fn fixture() -> &'static UrlCriteria {
    static FIXTURE: std::sync::OnceLock<UrlCriteria> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        UrlCriteria::from_json(crate::criteria::testkit::URL).expect("testdata/url.json")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 스캐너 `TestVersionBelowFixNeverAssertsPatched` 의 표 그대로.
    #[test]
    fn header_versions_are_compared_only_where_the_table_can_say() {
        let c = fixture();
        for (v, want) in [
            ("8.3.2", Some(true)),
            ("8.3.36", Some(false)),
            ("8.3.40", Some(false)),
            ("8.1.2-1ubuntu2", Some(true)),
            ("8.1.2-1ubuntu2.28", Some(false)),
            ("8.5.9-0ubuntu2.0", Some(true)),
            ("8.5.4-0ubuntu1.5", Some(false)),
            ("8.2.32-1~deb12u1", Some(true)),
            ("8.2.35-1~deb12u1", Some(false)),
            ("8.4.24-1~deb13u1", Some(true)),
            ("8.4.27-1~deb13u1", Some(false)),
            ("8.4.24-1~deb12u1", None),
            ("8.2.32-1~deb13u1", None),
            ("8.3.6-custom", None),
            ("8.3.36RC1", None),
            ("7.4.3", Some(true)),
            ("8.9.9", None),
            ("", None),
        ] {
            assert_eq!(c.below_fix(v), want, "{v:?}");
        }
    }

    #[test]
    fn esm_suffixes_count_only_on_esm_lines() {
        let c = fixture();
        assert_eq!(c.below_fix("7.4.3-4ubuntu2.29+esm4"), Some(true));
        assert_eq!(c.below_fix("7.4.3-4ubuntu2.29+esm5"), Some(false));
        assert_eq!(c.below_fix("5.5.9+dfsg-1ubuntu4.29+esm17"), Some(true));
        assert_eq!(c.below_fix("5.5.9+dfsg-1ubuntu4.29+esm18"), Some(false));
        assert_eq!(c.below_fix("5.6.40-custom"), None);
        assert_eq!(c.below_fix("7.4.33RC1"), None);
        assert_eq!(c.below_fix("5.3.29"), None);
    }

    #[test]
    fn dpkg_ordering_follows_the_policy() {
        use std::cmp::Ordering::*;
        assert_eq!(compare_debian("1.0~rc1-1", "1.0-1"), Less);
        assert_eq!(compare_debian("1:0.1-1", "9.9-1"), Greater);
        assert_eq!(
            compare_debian("8.3.6-0ubuntu0.24.04.9", "8.3.6-0ubuntu0.24.04.13"),
            Less
        );
        assert_eq!(compare_debian("1.0-1", "1.0-1"), Equal);
        assert_eq!(compare_debian("1.0a-1", "1.0-1"), Greater);
    }

    /// 표의 값이 바뀌면 판정이 바뀐다 — 코드는 그대로다(목표 D4 의 실증 한 칸).
    #[test]
    fn a_new_fixed_version_in_the_data_moves_the_verdict_without_new_code() {
        let raised = crate::criteria::testkit::URL.replace("\"8.3.36\"", "\"8.3.40\"");
        let c = UrlCriteria::from_json(&raised).expect("올린 표");
        assert_eq!(fixture().below_fix("8.3.38"), Some(false));
        assert_eq!(c.below_fix("8.3.38"), Some(true));
    }

    #[test]
    fn a_table_with_unknown_fields_or_broken_rows_is_refused() {
        let base = crate::criteria::testkit::URL;
        for (from, to) in [
            ("\"schema_version\": 1", "\"schema_version\": 2"),
            ("\"checked\": \"2026-11-09\"", "\"checked\": \"11/09/2026\""),
            ("\"CVE-2026-109618\", ", "\"CVE-26\", "),
            (
                "\"https://www.php.net/archive/2026.php\"",
                "\"http://www.php.net/\"",
            ),
            ("\"8.3\": \"8.3.36\"", "\"8.3\": \"8.4.36\""),
            ("\"7.4\", ", "\"8.3\", "),
            ("\"package\": \"php8.2-\"", "\"package\": \"python3-\""),
            ("\"fixed\": \"8.2.35-1~deb12u1\"", "\"fixed\": \"\""),
            (
                "\"same_as\": \"php2shell-check-linux 0.6.0\"",
                "\"same_as\": \"\", \"extra\": 1",
            ),
        ] {
            let broken = base.replace(from, to);
            assert_ne!(broken, base, "{from}");
            assert!(UrlCriteria::from_json(&broken).is_err(), "{from} → {to}");
        }
        assert!(UrlCriteria::from_json(base).is_ok());
    }
}
