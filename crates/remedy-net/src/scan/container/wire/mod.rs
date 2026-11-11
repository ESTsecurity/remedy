//! 엔진과 주고받는 길 — 요청마다 새 연결을 맺고, HTTP/1.1 을 손으로 쓰고 읽고, 닫는다.
//!
//! 범용 HTTP 클라이언트를 쓰지 않는다. 처음부터 없는 것: 인증 · 쿠키 · 리다이렉트 따라가기 · 프록시 · 연결 재사용 ·
//! 압축 풀기 · 재시도. 요청은 `Connection: close` · `Accept-Encoding: identity` 를 달고, 응답 머리는 32 KiB 까지
//! 받는다. 본문은 `Content-Length` · `chunked` · 연결 닫힘으로 끝을 안다. 요청마다 시한이 있고(10초, 파일 아카이브의
//! GET 은 30초) 응답 본문을 다 받을 때까지 그 시한 안이다.
//!
//! [`Transport`] 는 요청 하나를 주고 응답 하나를 받는 자리다(스캐너의 `http.RoundTripper` 자리). 시험은 엔진 없이
//! 응답을 지어 넣는다.

pub(crate) mod http;
pub(crate) mod link;

use super::failure::{Failure, Wire};
use crate::scan::budget::Budget;
use std::io::Read;
use std::time::{Duration, Instant};

/// 기다림을 이만큼씩 끊어 취소 · 시한을 본다.
pub(crate) const SLICE: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Head,
    Get,
}

impl Method {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Method::Head => "HEAD",
            Method::Get => "GET",
        }
    }
}

/// 요청 하나.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Call<'a> {
    pub(crate) method: Method,
    /// 판을 붙인 경로(`/v1.44/containers/<id>/archive`). 판을 맞추기 전의 `/version` 만 판이 없다.
    pub(crate) path: &'a str,
    /// 부호를 입힌 쿼리(`path=%2Fetc%2Fos-release`). 없으면 빈 글.
    pub(crate) query: &'a str,
    /// 응답 본문까지 다 받아야 하는 시각.
    pub(crate) deadline: Instant,
}

/// 응답 하나 — 본문은 아직 읽지 않았다.
pub(crate) struct Reply<'a> {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    /// `Content-Length`. 모르면(`chunked` · 연결 닫힘으로 끝) `None`.
    pub(crate) content_length: Option<u64>,
    pub(crate) body: Box<dyn Read + 'a>,
}

impl Reply<'_> {
    /// 이름이 같은(대소문자 무시) 첫 헤더의 값. 없으면 빈 글.
    pub(crate) fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map_or("", |(_, v)| v.as_str())
    }
}

/// 요청 하나를 보내고 응답 머리까지 받는다. 본문을 읽는 동안에도 시한과 예산의 취소를 본다.
pub(crate) trait Transport {
    fn round_trip<'a>(&'a self, call: &Call<'_>, budget: &'a Budget) -> Result<Reply<'a>, Failure>;
}

/// 시한과 멈춤 — 연결의 읽기 · 쓰기가 기다릴 때마다 본다.
#[derive(Clone, Copy)]
pub(crate) struct Watch<'a> {
    pub(crate) deadline: Instant,
    pub(crate) budget: &'a Budget,
}

impl Watch<'_> {
    /// 남은 시간. 취소됐거나 실행 시한이 지났으면 그 까닭, 요청의 시한이 지났으면 시한 넘김이다.
    pub(crate) fn left(&self) -> Result<Duration, Failure> {
        if let Some(h) = self.budget.halted() {
            return Err(Failure::Halt(h));
        }
        let now = Instant::now();
        if now >= self.deadline {
            return Err(Wire::Timeout.into());
        }
        Ok(self.deadline - now)
    }
}
