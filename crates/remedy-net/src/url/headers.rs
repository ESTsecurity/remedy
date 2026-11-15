//! 응답 헤더에서 읽는 것 — PHP 버전 표기와, 버전 없이 PHP 를 쓴다고 짐작할 단서, `Server` 의 Apache 와
//! `Upgrade` 의 HTTP/2 알림(코어 1.19.0).
//!
//! 본문은 읽지 않는다. 단서는 **제품을 특정하는 것만** 센다 — 흔한 캐시 헤더 · 이름 없는 세션 쿠키 ·
//! `_csrf` 같은 것은 PHP 가 아닌 앱도 낸다(스캐너가 실제 컨테이너로 가린 목록).

use regex::Regex;
use remedy_sdk::i18n::Lang;
use std::sync::OnceLock;

/// 받은 헤더 — 이름은 받은 그대로, 값은 UTF-8 로 풀 수 없는 바이트를 U+FFFD 로.
pub(crate) type Headers = [(String, String)];

/// 이름이 같은 헤더의 값 전부(받은 차례).
pub(crate) fn values<'a>(h: &'a Headers, name: &str) -> impl Iterator<Item = &'a str> + 'a {
    let name = name.to_string();
    h.iter()
        .filter(move |(n, _)| n.eq_ignore_ascii_case(&name))
        .map(|(_, v)| v.as_str())
}

fn first<'a>(h: &'a Headers, name: &str) -> Option<&'a str> {
    values(h, name).next()
}

/// `PHP/8.3.6` · `PHP 7.4.33-1+deb11u5` 꼴의 버전. 앞이 낱말 글자면(`XPHP/1.2.3`) 세지 않는다.
pub(crate) fn php_version(value: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?i)(?-u:\b)PHP[/ ]([0-9]+(?:\.[0-9]+){1,3}[-+~._a-zA-Z0-9]*)")
            .expect("고정된 정규식")
    });
    re.captures(value)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// `Server` 가 알리는 Apache HTTP Server(코어 1.19.0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApacheBanner {
    /// `ServerTokens` 에 따라 `2` · `2.4` · `2.4.65` — `Prod` 면 없다.
    pub(crate) version: Option<String>,
    /// 판 뒤 괄호 안의 OS 표시 — 상류 빌드는 `Unix` · `Win32` · `Win64`, 배포판은 제 이름(`Debian` …).
    pub(crate) os: Option<String>,
}

/// `Server` 값이 Apache 의 것이면 그 판과 OS 표시. 값의 맨 앞이 `Apache/<판>` 이거나 값 전체가 `Apache`
/// (`ServerTokens Prod`)일 때만 받는다 — `Apache-Coyote/1.1`(Tomcat) 같은 다른 제품은 아니다.
pub(crate) fn apache_banner(value: &str) -> Option<ApacheBanner> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let value = value.trim();
    if value.eq_ignore_ascii_case("apache") {
        return Some(ApacheBanner {
            version: None,
            os: None,
        });
    }
    let re = RE.get_or_init(|| {
        Regex::new(r"(?i)^Apache/([0-9][0-9A-Za-z.+~_-]*)(?:\s+\(([^()]*)\))?(?:\s|$)")
            .expect("고정된 정규식")
    });
    let c = re.captures(value)?;
    Some(ApacheBanner {
        version: c.get(1).map(|m| m.as_str().to_string()),
        os: c.get(2).map(|m| m.as_str().trim().to_string()),
    })
}

/// 상류(아파치 재단 소스) 빌드의 OS 표시 — 배포판은 제 이름을 적는다(목표 `remedy_net엔진보완` 결정 1).
pub(crate) fn upstream_os(os: &str) -> bool {
    ["Unix", "Win32", "Win64"]
        .iter()
        .any(|o| o.eq_ignore_ascii_case(os))
}

/// HTTP/2 를 알리는 `Upgrade` 값 — 낱말 가운데 `h2` · `h2c` 가 있는 첫 값. HTTP/2 를 켠 Apache 는 HTTP/1.1
/// 응답에 이것을 싣는다(2026-11-15 실측 — 공식 `httpd:2.4.65` 의 평문 `h2c` · TLS `h2` · 끄면 없다).
pub(crate) fn http2_upgrade(h: &Headers) -> Option<&str> {
    values(h, "Upgrade").find(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("h2") || t.trim().eq_ignore_ascii_case("h2c"))
    })
}

/// PHP 의 세션 기본 `Expires` — `expose_php` 를 꺼도 남는다.
const PHP_SESSION_EXPIRES: &str = "Thu, 19 Nov 1981 08:52:00 GMT";

/// 버전 없이 PHP(또는 PHP 프레임워크)를 쓴다고 짐작할 단서. 버전 · 패치 상태는 알려 주지 않는다.
pub(crate) fn php_hints(h: &Headers, lang: Lang) -> Vec<String> {
    let mut hints: Vec<&'static str> = Vec::new();
    let mut add = |label: &'static str| {
        if !hints.contains(&label) {
            hints.push(label);
        }
    };
    let cookies: [(&str, &str, &str); 16] = [
        (
            "phpsessid=",
            "PHPSESSID 세션 쿠키",
            "PHPSESSID session cookie",
        ),
        (
            "laravel_session=",
            "Laravel(laravel_session)",
            "Laravel (laravel_session)",
        ),
        (
            "laravel-session=",
            "Laravel(laravel-session)",
            "Laravel (laravel-session)",
        ),
        (
            "ci_session=",
            "CodeIgniter(ci_session)",
            "CodeIgniter (ci_session)",
        ),
        ("_nss=", "Nette(_nss)", "Nette (_nss)"),
        (
            "moodlesession",
            "Moodle(MoodleSession)",
            "Moodle (MoodleSession)",
        ),
        ("phpbb3_", "phpBB(phpbb3_)", "phpBB (phpbb3_)"),
        (
            "phpmyadmin=",
            "phpMyAdmin(phpMyAdmin)",
            "phpMyAdmin (phpMyAdmin)",
        ),
        (
            "nc_samesitecookie",
            "Nextcloud(nc_sameSiteCookie)",
            "Nextcloud (nc_sameSiteCookie)",
        ),
        (
            "oc_sessionpassphrase=",
            "Nextcloud(oc_sessionPassphrase)",
            "Nextcloud (oc_sessionPassphrase)",
        ),
        (
            "prestashop-",
            "PrestaShop(PrestaShop-)",
            "PrestaShop (PrestaShop-)",
        ),
        (
            "craft_csrf_token=",
            "Craft CMS(CRAFT_CSRF_TOKEN)",
            "Craft CMS (CRAFT_CSRF_TOKEN)",
        ),
        (
            "craftsessionid=",
            "Craft CMS(CraftSessionId)",
            "Craft CMS (CraftSessionId)",
        ),
        (
            "wordpress_logged_in_",
            "WordPress 로그인 쿠키",
            "WordPress login cookie",
        ),
        (
            "wordpress_sec_",
            "WordPress 쿠키(wordpress_sec_)",
            "WordPress cookie (wordpress_sec_)",
        ),
        (
            "wp-settings-",
            "WordPress 쿠키(wp-settings)",
            "WordPress cookie (wp-settings)",
        ),
    ];
    for c in values(h, "Set-Cookie") {
        let lower = c.trim().to_ascii_lowercase();
        for (prefix, ko, en) in cookies {
            if lower.starts_with(prefix) {
                add(lang.t(ko, en));
            }
        }
    }
    if first(h, "Expires").is_some_and(|v| v.trim().eq_ignore_ascii_case(PHP_SESSION_EXPIRES)) {
        add(lang.t(
            "Expires 가 PHP 세션 기본값(1981-11-19)",
            "Expires is the PHP session default (1981-11-19)",
        ));
    }
    if values(h, "Link").any(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("wp-json") || l.contains("api.w.org")
    }) {
        add(lang.t("WordPress REST Link 헤더", "WordPress REST Link header"));
    }
    if first(h, "X-Redirect-By").is_some_and(|v| v.trim().eq_ignore_ascii_case("WordPress")) {
        add("X-Redirect-By: WordPress");
    }
    if let Some(g) = first(h, "X-Generator").map(str::to_ascii_lowercase) {
        for (needle, label) in [
            ("drupal", "X-Generator: Drupal"),
            ("typo3", "X-Generator: TYPO3"),
            ("joomla", "X-Generator: Joomla"),
            ("mediawiki", "X-Generator: MediaWiki"),
        ] {
            if g.contains(needle) {
                add(label);
            }
        }
    }
    if first(h, "X-Drupal-Cache").is_some_and(|v| !v.is_empty())
        || first(h, "X-Drupal-Dynamic-Cache").is_some_and(|v| !v.is_empty())
    {
        add(lang.t(
            "X-Drupal-Cache 헤더(Drupal)",
            "X-Drupal-Cache header (Drupal)",
        ));
    }
    if first(h, "X-Debug-Token").is_some_and(|v| !v.is_empty())
        || first(h, "X-Debug-Token-Link").is_some_and(|v| !v.is_empty())
    {
        add(lang.t(
            "X-Debug-Token 헤더(Symfony 프로파일러)",
            "X-Debug-Token header (Symfony profiler)",
        ));
    }
    if first(h, "X-Powered-By").is_some_and(|v| v.to_ascii_lowercase().contains("nette")) {
        add("X-Powered-By: Nette Framework");
    }
    hints.into_iter().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn versions_are_read_from_php_banners_only() {
        assert_eq!(php_version("PHP/8.3.6").as_deref(), Some("8.3.6"));
        assert_eq!(
            php_version("php/8.3.36-custom").as_deref(),
            Some("8.3.36-custom")
        );
        assert_eq!(
            php_version("Apache/2.4.58 (Ubuntu) PHP/8.3.6-0ubuntu0.24.04.13").as_deref(),
            Some("8.3.6-0ubuntu0.24.04.13")
        );
        assert_eq!(php_version("PHP 7.4.33").as_deref(), Some("7.4.33"));
        assert_eq!(php_version("XPHP/8.3.6"), None);
        assert_eq!(php_version("PHP/8"), None);
        assert_eq!(php_version("Express"), None);
    }

    /// 시나리오 하나 — 이름 · 받은 헤더 · 단서 이름에 들어 있어야 할 낱말.
    type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, &'a [&'a str]);

    /// 스캐너 `TestPHPFingerprintsIdentifyPresenceOnly` 의 표 그대로(실제 컨테이너에서 본 값 포함).
    #[test]
    fn fingerprints_name_presence_only() {
        let cases: Vec<Case> = vec![
            (
                "phpsessid",
                vec![("Set-Cookie", "PHPSESSID=abc; path=/")],
                &["PHPSESSID"],
            ),
            (
                "expires1981",
                vec![("Expires", "Thu, 19 Nov 1981 08:52:00 GMT")],
                &["1981"],
            ),
            (
                "laravel_hyphen_real",
                vec![("Set-Cookie", "laravel-session=eyJ; path=/; httponly")],
                &["Laravel"],
            ),
            (
                "laravel_underscore",
                vec![("Set-Cookie", "laravel_session=xyz; path=/")],
                &["Laravel"],
            ),
            (
                "nextcloud_real",
                vec![
                    ("Set-Cookie", "nc_sameSiteCookielax=true; path=/; httponly"),
                    ("Set-Cookie", "oc_sessionPassphrase=abc; path=/; HttpOnly"),
                ],
                &["Nextcloud"],
            ),
            (
                "generic_csrf_not_php",
                vec![
                    ("X-Powered-By", "Express"),
                    ("Set-Cookie", "_csrf=token; path=/; HttpOnly; SameSite=Lax"),
                    ("Set-Cookie", "_csrf-frontend=token; path=/; HttpOnly"),
                ],
                &[],
            ),
            (
                "nette_real",
                vec![
                    ("Set-Cookie", "_nss=1; path=/; HttpOnly; SameSite=Strict"),
                    ("X-Powered-By", "Nette Framework 3"),
                ],
                &["Nette"],
            ),
            (
                "symfony_debug_real",
                vec![("X-Debug-Token", "efed81")],
                &["Symfony"],
            ),
            (
                "cakephp_has_no_header_signal",
                vec![("X-Powered-By", "PHP/8.3.36")],
                &[],
            ),
            (
                "phpmyadmin_real",
                vec![(
                    "Set-Cookie",
                    "phpMyAdmin=abc; path=/; HttpOnly; SameSite=Strict",
                )],
                &["phpMyAdmin"],
            ),
            (
                "wordpress_cookie",
                vec![("Set-Cookie", "wordpress_logged_in_9a=foo")],
                &["WordPress"],
            ),
            (
                "wordpress_link",
                vec![("Link", "<https://s/wp-json/>; rel=\"https://api.w.org/\"")],
                &["WordPress"],
            ),
            (
                "wp_redirect_real",
                vec![("X-Redirect-By", "WordPress")],
                &["WordPress"],
            ),
            (
                "drupal_generator",
                vec![("X-Generator", "Drupal 10 (https://www.drupal.org)")],
                &["Drupal"],
            ),
            (
                "joomla_hex_cookie_not_matched",
                vec![(
                    "Set-Cookie",
                    "d0e3357a3fe2b26787079bb62d2fdc4c=abc; path=/; HttpOnly",
                )],
                &[],
            ),
            (
                "generic_nocache_only",
                vec![
                    ("Cache-Control", "no-store, no-cache, must-revalidate"),
                    ("Pragma", "no-cache"),
                    ("Expires", "Thu, 01 Jan 1970 00:00:00 GMT"),
                    ("Set-Cookie", "session=abc"),
                ],
                &[],
            ),
        ];
        for (name, pairs, wants) in cases {
            let got = php_hints(&h(&pairs), Lang::Ko);
            if wants.is_empty() {
                assert!(got.is_empty(), "{name}: 단서가 없어야 하는데 {got:?}");
                continue;
            }
            let joined = got.join(" ");
            for w in wants {
                assert!(joined.contains(w), "{name}: {w:?} 가 {got:?} 에 없다");
            }
        }
    }

    /// `Server` 의 Apache — 실제 값(2026-11-15 실측 · 배포판 이름)과 다른 제품 · 꼴(코어 1.19.0).
    #[test]
    fn apache_banners_give_the_version_and_the_os_mark() {
        let some = |v: Option<&str>, os: Option<&str>| {
            Some(ApacheBanner {
                version: v.map(str::to_string),
                os: os.map(str::to_string),
            })
        };
        let rows = [
            ("Apache/2.4.65 (Unix)", some(Some("2.4.65"), Some("Unix"))),
            (
                "Apache/2.4.65 (Unix) OpenSSL/3.5.4",
                some(Some("2.4.65"), Some("Unix")),
            ),
            (
                "Apache/2.4.69 (Debian)",
                some(Some("2.4.69"), Some("Debian")),
            ),
            (
                "Apache/2.4.62 (Red Hat Enterprise Linux) OpenSSL/3.2.2",
                some(Some("2.4.62"), Some("Red Hat Enterprise Linux")),
            ),
            (
                "apache/2.4.58 (Ubuntu)",
                some(Some("2.4.58"), Some("Ubuntu")),
            ),
            ("Apache/2.4.65 (Win64)", some(Some("2.4.65"), Some("Win64"))),
            ("Apache/2.4.65", some(Some("2.4.65"), None)),
            ("Apache/2.4", some(Some("2.4"), None)),
            ("Apache", some(None, None)),
            (" Apache ", some(None, None)),
            ("Apache-Coyote/1.1", None),
            ("Apache Tomcat/9.0", None),
            ("nginx/1.27.0", None),
            ("MyApache/2.4.65 (Unix)", None),
            ("Apache/ (Unix)", None),
            ("", None),
        ];
        for (value, want) in rows {
            assert_eq!(apache_banner(value), want, "{value:?}");
        }
        assert!(upstream_os("Unix") && upstream_os("win64") && upstream_os("Win32"));
        assert!(!upstream_os("Debian") && !upstream_os("Linux/SUSE") && !upstream_os(""));
    }

    #[test]
    fn http2_is_read_from_the_upgrade_header_only() {
        for (pairs, want) in [
            (vec![("Upgrade", "h2c")], Some("h2c")),
            (vec![("Upgrade", "h2")], Some("h2")),
            (vec![("upgrade", "h2,h2c")], Some("h2,h2c")),
            (
                vec![("Upgrade", "websocket"), ("Upgrade", "H2C")],
                Some("H2C"),
            ),
            (vec![("Upgrade", "websocket")], None),
            (vec![("Upgrade", "h2x")], None),
            (vec![("Connection", "Upgrade, close")], None),
            (vec![("Alt-Svc", "h2=\":443\"")], None),
        ] {
            assert_eq!(http2_upgrade(&h(&pairs)), want, "{pairs:?}");
        }
    }
}
