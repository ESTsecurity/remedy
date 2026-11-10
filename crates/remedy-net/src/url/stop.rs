//! 요청을 멈춘 서버 — 429 · 5xx · 시간 초과 · 연결 끊김을 받은 서버에는 더 요청하지 않는다.
//!
//! 같은 서버는 **스킴 · 포트가 달라도** 같고, 이름이 달라도 **연결한 IP 가 같으면** 같다. 이름과 IP 를
//! 잇는 것은 사용자가 적은 URL 과 실제로 맺은 TCP 연결뿐이다 — 그것을 알려고 이름 풀이를 더 하지 않는다.

use std::collections::HashMap;

#[derive(Default)]
pub(crate) struct Stopped {
    hosts: HashMap<String, String>,
    ips: HashMap<String, String>,
    observed: HashMap<String, Vec<String>>,
}

impl Stopped {
    /// 이 호스트(이름 또는 IP)를 멈췄으면 그 까닭.
    pub(crate) fn reason(&self, host: &str) -> Option<String> {
        if let Some(r) = self.hosts.get(host) {
            return Some(r.clone());
        }
        if let Some(r) = self.ips.get(host) {
            // URL 이 이미 본 IP 를 그대로 적었다.
            return Some(r.clone());
        }
        self.observed
            .get(host)?
            .iter()
            .find_map(|ip| self.ips.get(ip).cloned())
    }

    pub(crate) fn stop(&mut self, host: &str, reason: &str) {
        self.hosts.insert(host.to_string(), reason.to_string());
        if let Some(ips) = self.observed.get(host) {
            for ip in ips {
                self.ips.insert(ip.clone(), reason.to_string());
            }
        }
    }

    /// 이 호스트로 맺은 연결의 상대 IP 를 적는다. 그 IP 가 이미 멈춘 서버면 이 호스트도 멈추고 까닭을 준다 —
    /// 부르는 쪽은 TLS · HTTP 바이트를 보내기 전에 연결을 닫는다.
    pub(crate) fn observe(&mut self, host: &str, ip: &str) -> Option<String> {
        let seen = self.observed.entry(host.to_string()).or_default();
        if !seen.iter().any(|s| s == ip) {
            seen.push(ip.to_string());
        }
        let reason = self.reason(host)?;
        self.stop(host, &reason);
        Some(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stop_follows_the_ip_to_other_names() {
        let mut s = Stopped::default();
        assert_eq!(s.observe("known.example", "127.0.0.1"), None);
        assert_eq!(s.observe("stopped.example", "127.0.0.1"), None);
        s.stop("stopped.example", "HTTP 503");
        // 같은 IP 로 이어진 다른 이름도, IP 를 그대로 적은 URL 도 멈춘다.
        assert_eq!(s.reason("known.example").as_deref(), Some("HTTP 503"));
        assert_eq!(s.reason("127.0.0.1").as_deref(), Some("HTTP 503"));
        // 처음 보는 이름이 그 IP 로 연결되면 그 순간 멈춘다.
        assert_eq!(s.reason("fresh.example"), None);
        assert_eq!(
            s.observe("fresh.example", "127.0.0.1").as_deref(),
            Some("HTTP 503")
        );
        assert_eq!(s.reason("fresh.example").as_deref(), Some("HTTP 503"));
        assert_eq!(s.reason("other.example"), None);
    }
}
