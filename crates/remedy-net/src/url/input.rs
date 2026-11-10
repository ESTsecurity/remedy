//! 점검할 URL — 사용자가 적은 것만 연다. 펼치지 않고(CIDR · 목록 파일) 형식이 이상하면 요청 전에 거절한다.
//!
//! 거절 문장에 URL 을 되풀이하지 않는다 — 계정 정보 · 토큰이 들어 있을 수 있다. 화면 · 결과 파일에는
//! 쿼리를 가린 꼴([`Input::display`])만 나간다. 요청에는 적은 쿼리가 그대로 간다.

use remedy_sdk::i18n::Lang;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 검사를 마친 URL 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Input {
    pub(crate) https: bool,
    /// 소문자. IPv6 는 괄호 없이.
    pub(crate) host: String,
    /// 호스트가 IP 로 적혔으면 그 주소 — 이름 풀이를 하지 않는다.
    pub(crate) ip: Option<IpAddr>,
    pub(crate) port: u16,
    /// 요청 줄의 대상 — 경로와 (있으면) `?` 뒤. 백분율 인코딩을 마친 꼴이다.
    pub(crate) target: String,
    pub(crate) has_query: bool,
}

/// 거절 사유. 문장은 URL 을 담지 않는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputError {
    Blank,
    Escape,
    Syntax,
    Credentials,
    Scheme,
    Port,
    NonAscii,
}

impl InputError {
    pub(crate) fn message(self, lang: Lang) -> &'static str {
        match self {
            InputError::Blank => lang.t(
                "빈 URL, 앞뒤 공백이나 제어 문자가 있는 URL 은 쓸 수 없습니다.",
                "an empty URL, or one with surrounding spaces or control characters, is not accepted.",
            ),
            InputError::Escape => lang.t(
                "URL 의 백분율 인코딩이 잘못됐거나 인코딩된 제어 문자가 있습니다.",
                "the URL has a malformed percent-encoding or an encoded control character.",
            ),
            InputError::Syntax => lang.t("URL 형식이 잘못됐습니다.", "the URL is malformed."),
            InputError::Credentials => lang.t(
                "계정 정보나 # 이 들어간 URL 은 쓸 수 없습니다.",
                "a URL with credentials or a # fragment is not accepted.",
            ),
            InputError::Scheme => lang.t(
                "호스트가 있는 http 또는 https URL 만 쓸 수 있습니다.",
                "only http or https URLs with a host are accepted.",
            ),
            InputError::Port => lang.t(
                "URL 포트는 1~65535 의 숫자여야 합니다.",
                "the URL port must be a number from 1 to 65535.",
            ),
            InputError::NonAscii => lang.t(
                "호스트에 ASCII 가 아닌 글자가 있습니다 — 국제화 도메인은 xn-- 꼴(punycode)로 적으십시오.",
                "the host has non-ASCII characters — write internationalized domains in xn-- (punycode) form.",
            ),
        }
    }
}

impl Input {
    pub(crate) fn parse(raw: &str) -> Result<Input, InputError> {
        if raw.is_empty() || raw.trim() != raw || raw.chars().any(char::is_control) {
            return Err(InputError::Blank);
        }
        let decoded = percent_decode(raw).ok_or(InputError::Escape)?;
        if String::from_utf8_lossy(&decoded)
            .chars()
            .any(char::is_control)
        {
            return Err(InputError::Escape);
        }
        if raw.contains('#') {
            return Err(InputError::Credentials);
        }
        let (scheme, rest) = raw.split_once(':').ok_or(InputError::Scheme)?;
        if !valid_scheme(scheme) {
            return Err(InputError::Syntax);
        }
        let https = match scheme.to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            _ => return Err(InputError::Scheme),
        };
        let rest = rest.strip_prefix("//").ok_or(InputError::Scheme)?;
        let cut = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(cut);
        if authority.contains('@') {
            return Err(InputError::Credentials);
        }
        let (host, ip, port) = split_authority(authority, https)?;
        let (path, query) = match tail.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (tail, None),
        };
        let mut target = if path.is_empty() {
            "/".to_string()
        } else {
            escape(path)
        };
        if let Some(q) = query {
            target.push('?');
            target.push_str(&escape(q));
        }
        Ok(Input {
            https,
            host,
            ip,
            port,
            target,
            has_query: query.is_some(),
        })
    }

    pub(crate) fn scheme(&self) -> &'static str {
        if self.https {
            "https"
        } else {
            "http"
        }
    }

    fn default_port(&self) -> u16 {
        if self.https {
            443
        } else {
            80
        }
    }

    /// `Host` 헤더와 정규화한 URL 의 주소 칸 — 기본 포트는 적지 않는다.
    pub(crate) fn authority(&self) -> String {
        let host = match self.ip {
            Some(IpAddr::V6(v6)) => format!("[{v6}]"),
            _ => self.host.clone(),
        };
        if self.port == self.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// 중복을 가리는 열쇠 — 대소문자 · 기본 포트 · 빈 경로를 맞춘 URL. 쿼리를 담는다.
    pub(crate) fn key(&self) -> String {
        format!("{}://{}{}", self.scheme(), self.authority(), self.target)
    }

    /// 화면 · 결과 파일에 내는 꼴 — 쿼리는 가린다.
    pub(crate) fn display(&self, lang: Lang) -> String {
        let path = self.target.split('?').next().unwrap_or("/");
        let mut s = format!("{}://{}{path}", self.scheme(), self.authority());
        if self.has_query {
            s.push_str(lang.t("?[가림]", "?[hidden]"));
        }
        s
    }

    /// 요청을 멈춘 서버를 알아보는 이름 — 끝의 `.` 를 떼고, IP 는 한 꼴로.
    pub(crate) fn server_host(&self) -> String {
        server_host(&self.host)
    }
}

/// [`Input::server_host`] 와 같은 꼴 — 연결한 상대 주소에도 쓴다.
pub(crate) fn server_host(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    match host.parse::<IpAddr>() {
        Ok(ip) => canonical(ip).to_string(),
        Err(_) => host.to_string(),
    }
}

/// IPv4 를 담은 IPv6(`::ffff:a.b.c.d`)는 IPv4 로 — 같은 서버가 두 이름을 갖지 않게.
pub(crate) fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn valid_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn split_authority(
    authority: &str,
    https: bool,
) -> Result<(String, Option<IpAddr>, u16), InputError> {
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (v6, after) = inner.split_once(']').ok_or(InputError::Syntax)?;
        let ip: Ipv6Addr = v6.parse().map_err(|_| InputError::Syntax)?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or(InputError::Syntax)?),
        };
        (ip.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, _)) if h.contains(':') => return Err(InputError::Syntax),
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err(InputError::Scheme);
    }
    if !host.is_ascii() {
        return Err(InputError::NonAscii);
    }
    let host = host.to_ascii_lowercase();
    let port = match port {
        None | Some("") => {
            if https {
                443
            } else {
                80
            }
        }
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => {
            let n: u32 = if p.len() > 5 {
                0
            } else {
                p.parse().unwrap_or(0)
            };
            if n == 0 || n > 65_535 {
                return Err(InputError::Port);
            }
            n as u16
        }
        Some(_) => return Err(InputError::Syntax),
    };
    let ip = if authority.starts_with('[') {
        host.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
    } else if let Ok(v4) = host.parse::<Ipv4Addr>() {
        Some(IpAddr::V4(v4))
    } else if host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        None
    } else {
        return Err(InputError::Syntax);
    };
    Ok((host, ip, port))
}

/// `%XX` 를 푼다. 잘못된 꼴이면 `None`.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            let text = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(text, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// 요청 줄에 그대로 둘 수 없는 바이트(공백 · ASCII 밖 · 따옴표 등)를 `%XX` 로. 이미 인코딩된 `%XX` 는 둔다.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
                    | b'?'
                    | b'%'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 스캐너 `TestInputValidation` — 요청 전에 거절한다.
    #[test]
    fn malformed_or_unsafe_urls_are_refused_before_any_request() {
        for s in [
            "http://u:p@example.com",
            "http://example.com/#",
            "http://example.com/%0a",
            "http://example.com/\x1b",
            "file:///etc/passwd",
            "http:///a",
            " http://example.com/",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://example.com:99999999999/",
            "http://example.com:8o/",
            "http://example.com/%zz",
            "http://example.com/%C2%85",
            "http:example.com",
            "example.com",
            "http://@example.com/",
            "http://[::1%25eth0]/",
            "http://exa mple.com/",
            "http://한국.kr/",
        ] {
            assert!(Input::parse(s).is_err(), "{s:?} 를 받았다");
        }
    }

    #[test]
    fn case_default_port_and_empty_path_collapse_to_one_key() {
        let a = Input::parse("http://EXAMPLE.com").unwrap();
        let b = Input::parse("http://example.com:80/").unwrap();
        let c = Input::parse("HTTP://example.com:/").unwrap();
        assert_eq!(a.key(), "http://example.com/");
        assert_eq!(a.key(), b.key());
        assert_eq!(a.key(), c.key());
        let s = Input::parse("https://example.com:8443").unwrap();
        assert_eq!(s.key(), "https://example.com:8443/");
        assert_eq!(s.authority(), "example.com:8443");
    }

    #[test]
    fn the_query_is_sent_but_never_displayed() {
        let i = Input::parse("https://example.com/path?token=do-not-store").unwrap();
        assert_eq!(i.target, "/path?token=do-not-store");
        assert_eq!(i.display(Lang::Ko), "https://example.com/path?[가림]");
        assert_eq!(i.display(Lang::En), "https://example.com/path?[hidden]");
        let bare = Input::parse("https://example.com/?").unwrap();
        assert!(bare.has_query);
        assert_eq!(bare.display(Lang::Ko), "https://example.com/?[가림]");
    }

    #[test]
    fn literals_skip_name_resolution_and_hosts_share_one_form() {
        let v6 = Input::parse("http://[::1]:8080/a").unwrap();
        assert_eq!(v6.ip, Some("::1".parse().unwrap()));
        assert_eq!(v6.authority(), "[::1]:8080");
        let v4 = Input::parse("https://127.0.0.1/").unwrap();
        assert_eq!(v4.ip, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(
            Input::parse("http://Example.COM./d").unwrap().server_host(),
            "example.com"
        );
        assert_eq!(server_host("::ffff:192.0.2.1"), "192.0.2.1");
    }

    #[test]
    fn unsafe_request_bytes_are_percent_encoded() {
        let i = Input::parse("http://example.com/a b/\u{d55c}?q=\"x\"").unwrap();
        assert_eq!(i.target, "/a%20b/%ED%95%9C?q=%22x%22");
        let kept = Input::parse("http://example.com/%7Euser/a%2Fb").unwrap();
        assert_eq!(kept.target, "/%7Euser/a%2Fb");
    }

    #[test]
    fn refusals_never_repeat_the_url() {
        for bad in [
            "http://user:SECRET@example.com/",
            "ftp://SECRET.example/",
            "http://SECRET.example:0/",
            "http://SECRET.example/%0a",
            "http://SECRET.example/#frag",
            "http://SECRET\u{d55c}.example/",
        ] {
            let e = Input::parse(bad).unwrap_err();
            for lang in [Lang::Ko, Lang::En] {
                assert!(!e.message(lang).contains("SECRET"), "{bad}: {e:?}");
            }
        }
    }
}
