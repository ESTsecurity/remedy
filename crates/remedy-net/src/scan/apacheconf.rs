//! Apache 설정에서 HTTP/2 를 켠 흔적 — 이미지 · 컨테이너가 함께 쓴다(코어 1.18.0).
//!
//! 본체의 점검 룰 `apache-http2-check-linux` 와 **같은 자리 · 같은 줄**을 본다(목표 결정 2 — 판정은 호스트 룰과
//! 같게). 자리는 그 룰의 `h2_module` · `h2_protocols` 의 경로 정규식이고, 줄은 그 룰의 YARA 두 규칙
//! (`apache_h2_loadmodule` · `apache_h2_protocols`)이다. 한쪽을 고치면 다른 쪽도 고친다.
//!
//! - **모듈 적재**: Debian 계열은 켠 모듈이 `mods-enabled` 의 이름이다(`http2.load` — 링크라 본문을 보지 않고
//!   이름으로 본다). 그 밖은 설정 파일의 살아 있는 `LoadModule http2_module` 줄이다.
//! - **Protocols**: Debian 계열에서 모듈을 켜면 함께 오는 `mods-enabled/http2.conf` 가 `Protocols h2 h2c http/1.1`
//!   을 켠다(그 룰의 2026-11-13 실측). 그 밖은 살아 있는 `Protocols` 줄의 `h2` · `h2c` 낱말이다.
//! - `mods-available` 은 켜지 않은 모듈의 줄까지 늘 있으므로 보지 않는다. `<IfModule>` · `<VirtualHost>` 안의
//!   줄인지는 가리지 않는다 — 대상 전체의 흔적으로 쓴다(그 룰과 같다).

use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use remedy_sdk::i18n::Lang;
use std::sync::OnceLock;

/// 판 문자열을 찾는 수 — 실행 파일에 같은 판이 여러 번 박힌다.
const MAX_VERSION_TEXTS: usize = 32;

/// Debian 계열에서 HTTP/2 모듈을 켰다는 이름(뿌리 기준 · 앞의 `/` 없이).
pub(crate) const DEBIAN_LOAD: &str = "etc/apache2/mods-enabled/http2.load";
/// Debian 계열에서 모듈을 켜면 함께 오는 Protocols 설정의 이름.
pub(crate) const DEBIAN_CONF: &str = "etc/apache2/mods-enabled/http2.conf";

/// 흔적을 찾는 설정 파일의 자리(뿌리 기준 · 앞의 `/` 없이) — 그 룰의 경로 정규식에서 앞의 `/` 만 뗐다.
fn config_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"^(etc/apache2/((conf\.d|conf-available|conf-enabled|sites-available|sites-enabled|vhosts\.d)/)?",
            r"|etc/httpd/(conf|conf\.d|conf\.modules\.d)/",
            r"|(usr/local/(apache2?|httpd)|opt/(apache2?|httpd))/conf/(extra/)?",
            r"|opt/lampp/etc/(extra/)?)[^/]+\.conf$",
        ))
        .expect("고정된 정규식")
    })
}

fn load_line() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| {
        BytesRegex::new(r"(?mi)^[ \t]*LoadModule[ \t]+http2_module[ \t]").expect("고정된 정규식")
    })
}

fn protocols_line() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| {
        BytesRegex::new(r"(?mi)^[ \t]*Protocols[ \t]([^\r\n#]*[ \t])?h2c?([ \t\r\n]|$)")
            .expect("고정된 정규식")
    })
}

/// 흔적을 찾는 설정 파일의 자리인가(뿌리 기준 · 앞의 `/` 없이).
pub(crate) fn is_config_path(name: &str) -> bool {
    config_path().is_match(name)
}

/// Apache 의 실행 파일(`httpd`) · HTTP/2 모듈(`mod_http2.so`)의 이름인가(마지막 요소) — 해시를 내고 앞부분을
/// 담는다. Debian 의 `apache2` 실행 파일은 담지 않는다(그 판은 패키지 기록으로 본다).
pub(crate) fn is_apache_binary(name: &str) -> bool {
    matches!(crate::scan::slashpath::base(name), "httpd" | "mod_http2.so")
}

/// 살아 있는 `LoadModule http2_module` 줄이 있는가 — 주석(`#`)으로 시작하는 줄은 아니다.
pub(crate) fn loads_module(data: &[u8]) -> bool {
    load_line().is_match(data)
}

/// 살아 있는 `Protocols` 줄에 `h2` · `h2c` 낱말이 있는가. `ProtocolsHonorOrder` 는 다른 지시어다.
pub(crate) fn offers_h2(data: &[u8]) -> bool {
    protocols_line().is_match(data)
}

fn server_version_text() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(r"Apache/(2\.[0-9]+\.[0-9]+)[^0-9.]").expect("고정된 정규식"))
}

/// 실행 파일 안의 서버 판 문자열들(`Apache/2.x.y` · 겹치지 않게 · 앞의 32개). 비면 Apache 가 아니다(busybox 의
/// `httpd` 처럼 이름만 같은 것).
pub(crate) fn server_versions(data: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for caps in server_version_text()
        .captures_iter(data)
        .take(MAX_VERSION_TEXTS)
    {
        let v = String::from_utf8_lossy(&caps[1]).into_owned();
        if !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

/// 공식 `httpd` 이미지의 표지 — 이미지(또는 컨테이너) 설정의 환경 변수. 값이 없으면 `None` 이다.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HttpdEnv {
    pub(crate) version: Option<String>,
    pub(crate) patches: Option<String>,
    pub(crate) prefix: Option<String>,
}

impl HttpdEnv {
    /// `HTTPD_VERSION` · `HTTPD_PATCHES` · `HTTPD_PREFIX`.
    pub(crate) fn from_env(env: &[String]) -> HttpdEnv {
        let get = |key: &str| {
            env.iter()
                .filter_map(|item| item.split_once('='))
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        };
        HttpdEnv {
            version: get("HTTPD_VERSION"),
            patches: get("HTTPD_PATCHES"),
            prefix: get("HTTPD_PREFIX"),
        }
    }

    /// 실행 파일이 놓일 자리(뿌리 기준 · 앞의 `/` 없이) — `HTTPD_PREFIX` 의 `bin/httpd`, 없으면 공식 이미지의 자리.
    pub(crate) fn binary_path(&self) -> String {
        let prefix = self.prefix.as_deref().unwrap_or("/usr/local/apache2");
        crate::scan::slashpath::join(&[prefix.trim_start_matches('/'), "bin/httpd"])
    }

    /// 판 문자열을 그 판으로 믿을 수 있는가(목표 `remedy_net아파치` 결정 3) — 공식 이미지의 꼴이면 `Ok`, 아니면 그
    /// 까닭. `path` 는 실행 파일의 자리(뿌리 기준 · 앞의 `/` 없이 · 링크를 푼 것)다.
    pub(crate) fn official(
        &self,
        path: &str,
        versions: &[String],
        lang: Lang,
    ) -> Result<(), String> {
        let [version] = versions else {
            return Err(lang
                .t(
                    "실행 파일에 서로 다른 서버 판 문자열이 있습니다",
                    "the executable carries more than one server version text",
                )
                .to_string());
        };
        let Some(declared) = self.version.as_deref() else {
            return Err(lang
                .t(
                    "설정에 HTTPD_VERSION 이 없습니다 — 판 문자열만으로는 판정하지 않습니다",
                    "the configuration has no HTTPD_VERSION - the version text alone is not used to judge",
                )
                .to_string());
        };
        if declared != version {
            return Err(lang.pick(
                format!("설정의 HTTPD_VERSION({declared})이 실행 파일의 판({version})과 다릅니다"),
                format!("the configuration's HTTPD_VERSION ({declared}) differs from the executable's version ({version})"),
            ));
        }
        if self
            .patches
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty())
        {
            return Err(lang
                .t(
                    "설정의 HTTPD_PATCHES 가 비어 있지 않습니다 — 상류 판에 따로 붙인 패치가 있어 판만으로 판정하지 않습니다",
                    "the configuration's HTTPD_PATCHES is not empty - patches were applied on top of the upstream version, so the version alone is not used to judge",
                )
                .to_string());
        }
        if path != self.binary_path() {
            let prefix = self.prefix.as_deref().unwrap_or("/usr/local/apache2");
            return Err(lang.pick(
                format!("실행 파일이 설정의 HTTPD_PREFIX({prefix}) 의 bin/httpd 가 아닙니다"),
                format!("the executable is not bin/httpd under the configuration's HTTPD_PREFIX ({prefix})"),
            ));
        }
        Ok(())
    }
}

/// 판 문자열을 믿은 근거 한 줄.
pub(crate) fn official_note(version: &str, lang: Lang) -> String {
    lang.pick(
        format!("공식 httpd 이미지의 꼴 — HTTPD_VERSION={version} · HTTPD_PATCHES 가 비어 있음 · 실행 파일이 HTTPD_PREFIX 의 bin/httpd"),
        format!("the official httpd image's markers - HTTPD_VERSION={version}, HTTPD_PATCHES empty, the executable is HTTPD_PREFIX's bin/httpd"),
    )
}

/// 대상 하나에서 모은 HTTP/2 흔적 — 자리는 `/` 로 시작하는 경로다.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Http2 {
    /// 모듈을 싣는 자리.
    pub module: Vec<String>,
    /// HTTP/2(h2 · h2c)를 켜는 Protocols 줄이 있는 자리.
    pub protocols: Vec<String>,
    /// 흔적을 찾을 자리인데 본문 전체를 읽지 못한 설정 파일(수집 한도 · 읽기 실패) — 흔적이 거기 있었을 수 있다.
    pub unread: Vec<String>,
}

impl Http2 {
    /// 모듈 적재와 Protocols 의 h2 · h2c 가 다 있는가 — 둘 다 있어야 악용에 닿는다(Red Hat RHSB-2026-017).
    pub fn enabled(&self) -> bool {
        !self.module.is_empty() && !self.protocols.is_empty()
    }

    /// 설정 파일 하나의 본문을 본다.
    pub(crate) fn read_config(&mut self, path: &str, data: &[u8]) {
        if loads_module(data) {
            push(&mut self.module, path);
        }
        if offers_h2(data) {
            push(&mut self.protocols, path);
        }
    }

    /// Debian 계열의 `mods-enabled` 이름 하나 — 있으면 그 흔적이다(본문은 보지 않는다).
    pub(crate) fn debian_enabled(&mut self, name: &str) {
        let path = format!("/{name}");
        if name == DEBIAN_LOAD {
            push(&mut self.module, &path);
        } else if name == DEBIAN_CONF {
            push(&mut self.protocols, &path);
        }
    }
}

fn push(list: &mut Vec<String>, path: &str) {
    if !list.iter().any(|p| p == path) {
        list.push(path.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_places_are_the_host_rules_places() {
        for yes in [
            "etc/apache2/apache2.conf",
            "etc/apache2/conf-enabled/security.conf",
            "etc/apache2/sites-available/default-ssl.conf",
            "etc/apache2/vhosts.d/a.conf",
            "etc/httpd/conf/httpd.conf",
            "etc/httpd/conf.d/ssl.conf",
            "etc/httpd/conf.modules.d/10-h2.conf",
            "usr/local/apache2/conf/httpd.conf",
            "usr/local/apache2/conf/extra/httpd-ssl.conf",
            "usr/local/httpd/conf/httpd.conf",
            "opt/apache/conf/httpd.conf",
            "opt/lampp/etc/extra/httpd-ssl.conf",
        ] {
            assert!(is_config_path(yes), "{yes}");
        }
        for no in [
            "etc/apache2/mods-available/http2.conf",
            "etc/apache2/mods-enabled/http2.conf",
            "etc/apache2/conf-enabled/sub/a.conf",
            "etc/httpd/conf.d/ssl.conf.bak",
            "usr/local/apache2/conf/original/httpd.conf",
            "srv/etc/apache2/apache2.conf",
            "etc/apache2/apache2.conf/x.conf",
        ] {
            assert!(!is_config_path(no), "{no}");
        }
    }

    #[test]
    fn only_live_lines_count() {
        assert!(loads_module(
            b"LoadModule http2_module modules/mod_http2.so\n"
        ));
        assert!(loads_module(
            b"x\n  \tloadmodule HTTP2_MODULE /usr/lib/apache2/mod_http2.so"
        ));
        assert!(loads_module(
            b"<IfModule x>\r\n  LoadModule http2_module m.so\r\n</IfModule>"
        ));
        assert!(!loads_module(
            b"#LoadModule http2_module modules/mod_http2.so\n"
        ));
        assert!(!loads_module(b"  # LoadModule http2_module m.so"));
        assert!(!loads_module(
            b"LoadModule proxy_http2_module modules/mod_proxy_http2.so\n"
        ));
        assert!(!loads_module(b"LoadModule http2_modulex m.so"));
        for yes in [
            &b"Protocols h2 http/1.1"[..],
            b"Protocols http/1.1 h2",
            b"protocols h2c\n",
            b"  Protocols h2 h2c http/1.1\r\n",
            b"a\nProtocols\th2",
        ] {
            assert!(offers_h2(yes), "{}", String::from_utf8_lossy(yes));
        }
        for no in [
            &b"Protocols http/1.1"[..],
            b"#Protocols h2 http/1.1",
            b"ProtocolsHonorOrder On",
            b"Protocols http/1.1 # h2",
            b"Protocols h2x",
            b"Protocols http/1.1 xh2",
        ] {
            assert!(!offers_h2(no), "{}", String::from_utf8_lossy(no));
        }
    }

    #[test]
    fn both_signs_are_needed() {
        let mut h = Http2::default();
        assert!(!h.enabled());
        h.read_config(
            "/etc/httpd/conf.modules.d/10-h2.conf",
            b"LoadModule http2_module modules/mod_http2.so\n",
        );
        assert!(!h.enabled());
        h.read_config("/etc/httpd/conf/httpd.conf", b"Protocols h2 http/1.1\n");
        h.read_config("/etc/httpd/conf/httpd.conf", b"Protocols h2 http/1.1\n");
        assert!(h.enabled());
        assert_eq!(h.protocols, vec!["/etc/httpd/conf/httpd.conf".to_string()]);
        let mut d = Http2::default();
        d.debian_enabled(DEBIAN_LOAD);
        d.debian_enabled("etc/apache2/mods-enabled/ssl.load");
        assert!(!d.enabled());
        d.debian_enabled(DEBIAN_CONF);
        assert!(d.enabled());
    }
}
