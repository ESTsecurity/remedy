//! PHP2Shell(CVE-2026-109618 · CVE-2026-109619) 의 수정 버전 — 응답 헤더가 알리는 버전을 견줄 기준.
//!
//! **본체의 점검 룰과 같은 표다.** `plugins/php2shell-check-linux/plugin.yaml` 의 배포판 줄 · 상류 수정
//! 버전과 같은 값이고, 시험(`the_table_matches_the_linux_check_rule`)이 그 파일과 대조한다 — 한쪽만
//! 고치면 시험이 실패한다. 첫 판은 기준을 바이너리에 담는다(안내 문서 §2).
//!
//! 헤더는 남이 적은 글자다. 그래서 이 표는 **취약 쪽으로만** 판정을 바꾼다 — 수정 버전 이상이어도
//! 백포트 · 직접 빌드를 헤더로 가릴 수 없어 *확인 필요* 로 둔다(양호를 내지 않는다).

/// 기준을 다시 확인한 날 — 결과 파일과 화면에 싣는다(결정 10: 만료를 두지 않는 대신 날짜를 적는다).
pub(crate) const CHECKED: &str = "2026-11-09";
pub(crate) const CVES: [&str; 2] = ["CVE-2026-109618", "CVE-2026-109619"];
/// 같은 값을 쓰는 본체의 점검 룰.
pub(crate) const SAME_AS: &str = "php2shell-check-linux 0.4.0";
pub(crate) const SOURCES: [&str; 4] = [
    "https://www.php.net/archive/2026.php",
    "https://ubuntu.com/security/notices/USN-8948-1",
    "https://ubuntu.com/security/notices/USN-8948-2",
    "https://security-tracker.debian.org/tracker/CVE-2026-109618",
];

/// 상류 계열 → 수정 버전.
const UPSTREAM: [(&str, &str); 4] = [
    ("8.2", "8.2.35"),
    ("8.3", "8.3.36"),
    ("8.4", "8.4.27"),
    ("8.5", "8.5.12"),
];

/// php.net 수정 버전이 없는 계열 — 순수한 `X.Y.Z` 면 영향 버전이다.
const LEGACY: [&str; 10] = [
    "5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Distro {
    Debian,
    Ubuntu,
}

/// 배포판 공지 한 줄 — 패키지 이름의 앞머리(`php8.2-` · `php5-`)와 그 배포판의 수정 버전.
struct Line {
    distro: Distro,
    release: &'static str,
    package: &'static str,
    fixed: &'static str,
}

const LINES: [Line; 10] = [
    Line {
        distro: Distro::Ubuntu,
        release: "22.04",
        package: "php8.1-",
        fixed: "8.1.2-1ubuntu2.28",
    },
    Line {
        distro: Distro::Ubuntu,
        release: "24.04",
        package: "php8.3-",
        fixed: "8.3.6-0ubuntu0.24.04.13",
    },
    Line {
        distro: Distro::Ubuntu,
        release: "26.04",
        package: "php8.5-",
        fixed: "8.5.4-0ubuntu1.5",
    },
    Line {
        distro: Distro::Ubuntu,
        release: "26.10",
        package: "php8.5-",
        fixed: "8.5.9-0ubuntu2.1",
    },
    Line {
        distro: Distro::Debian,
        release: "12",
        package: "php8.2-",
        fixed: "8.2.35-1~deb12u1",
    },
    Line {
        distro: Distro::Debian,
        release: "13",
        package: "php8.4-",
        fixed: "8.4.27-1~deb13u1",
    },
    Line {
        distro: Distro::Ubuntu,
        release: "14.04",
        package: "php5-",
        fixed: "5.5.9+dfsg-1ubuntu4.29+esm18",
    },
    Line {
        distro: Distro::Ubuntu,
        release: "16.04",
        package: "php7.0-",
        fixed: "7.0.33-0ubuntu0.16.04.16+esm22",
    },
    Line {
        distro: Distro::Ubuntu,
        release: "18.04",
        package: "php7.2-",
        fixed: "7.2.24-0ubuntu0.18.04.17+esm14",
    },
    Line {
        distro: Distro::Ubuntu,
        release: "20.04",
        package: "php7.4-",
        fixed: "7.4.3-4ubuntu2.29+esm5",
    },
];

/// 헤더가 알리는 버전이 수정 버전보다 낮은가. `Some(true)` 면 영향 버전, `Some(false)` 면 수정 버전
/// 이상(그래도 헤더로는 양호를 낼 수 없다), `None` 이면 이 표로 가릴 수 없는 버전(직접 빌드 꼬리 ·
/// 사전 공개 · 모르는 계열 · 배포판 줄과 맞지 않는 꼬리).
pub(crate) fn below_fix(version: &str) -> Option<bool> {
    if version.is_empty() {
        return None;
    }
    if let Some([major, minor, _]) = core(version) {
        let branch = format!("{major}.{minor}");
        return match UPSTREAM.iter().find(|(b, _)| *b == branch) {
            Some((_, fixed)) => Some(compare_core(version, fixed).is_lt()),
            None => LEGACY.contains(&branch.as_str()).then_some(true),
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
    for line in LINES.iter().filter(|l| l.package == package) {
        // 배너는 배포판을 밝히지 않는다. Debian 은 `~debN` 표식이, Ubuntu 는 알려진 패키지 줄이 맞아야 견준다.
        let matches = match line.distro {
            Distro::Debian => release == Some(line.release),
            Distro::Ubuntu => ubuntu_line(version, line.fixed),
        };
        if !matches {
            continue;
        }
        if fixed.is_some_and(|f| f != line.fixed) {
            return None;
        }
        fixed = Some(line.fixed);
    }
    fixed.map(|f| compare_debian(version, f).is_lt())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 스캐너 `TestVersionBelowFixNeverAssertsPatched` 의 표 그대로.
    #[test]
    fn header_versions_are_compared_only_where_the_table_can_say() {
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
            assert_eq!(below_fix(v), want, "{v:?}");
        }
    }

    #[test]
    fn esm_suffixes_count_only_on_esm_lines() {
        assert_eq!(below_fix("7.4.3-4ubuntu2.29+esm4"), Some(true));
        assert_eq!(below_fix("7.4.3-4ubuntu2.29+esm5"), Some(false));
        assert_eq!(below_fix("5.5.9+dfsg-1ubuntu4.29+esm17"), Some(true));
        assert_eq!(below_fix("5.5.9+dfsg-1ubuntu4.29+esm18"), Some(false));
        assert_eq!(below_fix("5.6.40-custom"), None);
        assert_eq!(below_fix("7.4.33RC1"), None);
        assert_eq!(below_fix("5.3.29"), None);
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

    /// 본체의 점검 룰과 같은 표인가 — 한쪽만 고치면 여기서 걸린다.
    #[test]
    fn the_table_matches_the_linux_check_rule() {
        let rule = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../plugins/php2shell-check-linux/plugin.yaml"
        ))
        .expect("plugins/php2shell-check-linux/plugin.yaml 을 읽지 못했다");
        assert!(rule.contains("version: 0.4.0"), "{SAME_AS} 가 아니다");
        for line in &LINES {
            let row = format!("op: pkg_version_lt, value: \"{}\"", line.fixed);
            assert!(rule.contains(&row), "룰에 {} 줄이 없다", line.fixed);
        }
        let upstream = UPSTREAM.map(|(_, f)| f).join(" · ");
        assert!(rule.contains(&format!("상류: {upstream}")), "{upstream}");
    }
}
