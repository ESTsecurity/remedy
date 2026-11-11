//! HTTP/1.1 요청 한 번 — 요청 줄과 헤더 넷을 쓰고, 응답 머리를 읽고, 본문의 틀(`Content-Length` · `chunked` ·
//! 닫힘)을 푼다.
//!
//! 틀은 스캐너가 쓰던 Go `net/http` 의 판단을 따른다. `Transfer-Encoding` 은 `chunked` 하나만 받고(그때
//! `Content-Length` 는 버린다), 서로 다른 `Content-Length` 둘은 거절한다. HEAD 의 응답과 1xx · 204 · 304 에는
//! 본문이 없다. 1xx 안내 응답은 다섯 번까지 건너뛴다. `chunked` 의 줄은 CRLF 로 끝나야 하고 4 KiB 를 넘지 않으며,
//! 데이터보다 덧붙은 글자가 지나치게 많으면(16 KiB 넘게) 그만둔다.

use super::link::Link;
use super::{Call, Method, Reply, Watch};
use crate::scan::container::failure::{Failure, Wire};
use std::io::{self, Read};

/// 응답 머리의 상한.
const MAX_HEAD: usize = 32 << 10;
/// 32 KiB 안에 들 수 있는 헤더 줄의 최대 수(`a:` + CRLF = 4바이트).
const MAX_HEADERS: usize = MAX_HEAD / 4 + 1;
const MAX_INFORMATIONAL: usize = 5;
/// `chunked` 의 줄 하나 · 덧붙은 글자 · 꼬리 헤더의 상한.
const MAX_CHUNK_LINE: usize = 4096;
const MAX_CHUNK_EXCESS: i64 = 16 << 10;
const MAX_TRAILER: usize = 4096;
/// 본문을 연결에서 한 번에 받는 양.
const FILL: usize = 32 << 10;
const USER_AGENT: &str = concat!("remedy-net/", env!("CARGO_PKG_VERSION"));

/// 요청의 바이트 — 인증 · 쿠키 없이 넷만.
pub(crate) fn request_bytes(call: &Call<'_>) -> Vec<u8> {
    let target = if call.query.is_empty() {
        call.path.to_string()
    } else {
        format!("{}?{}", call.path, call.query)
    };
    format!(
        "{} {target} HTTP/1.1\r\nHost: local-engine\r\nUser-Agent: {USER_AGENT}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        call.method.as_str()
    )
    .into_bytes()
}

/// 연결 하나로 요청 하나를 주고받는다.
pub(crate) fn exchange<'a>(
    mut link: Box<dyn Link + 'a>,
    call: &Call<'_>,
    watch: Watch<'a>,
) -> Result<Reply<'a>, Failure> {
    link.send(&request_bytes(call), &watch)?;
    let mut buf = Vec::with_capacity(4096);
    let head = read_head(&mut *link, &watch, &mut buf)?;
    buf.drain(..head.len);
    let (framing, content_length) = framing(call.method, &head)?;
    let body = Body {
        link,
        watch,
        buf,
        pos: 0,
        framing,
    };
    Ok(Reply {
        status: head.status,
        headers: head.headers,
        content_length,
        body: Box::new(body),
    })
}

/// 응답 머리.
struct Head {
    status: u16,
    /// HTTP/1.x 의 x.
    minor: u8,
    headers: Vec<(String, String)>,
    /// 머리의 바이트 수(빈 줄까지).
    len: usize,
}

impl Head {
    fn values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// 다 받은 응답 머리를 돌려준다 — 1xx 안내는 건너뛰고 그 바이트를 버린다.
fn read_head(link: &mut dyn Link, watch: &Watch<'_>, buf: &mut Vec<u8>) -> Result<Head, Failure> {
    let mut informational = 0;
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(head) = parse_head(buf)? {
            if head.len > MAX_HEAD {
                return Err(Wire::HeaderTooLarge.into());
            }
            if (100..200).contains(&head.status) && head.status != 101 {
                informational += 1;
                if informational > MAX_INFORMATIONAL {
                    return Err(Wire::Malformed.into());
                }
                buf.drain(..head.len);
                continue;
            }
            return Ok(head);
        }
        if buf.len() > MAX_HEAD {
            return Err(Wire::HeaderTooLarge.into());
        }
        let room = (MAX_HEAD + 1 - buf.len()).min(chunk.len());
        let n = link.recv(&mut chunk[..room], watch)?;
        if n == 0 {
            return Err(Wire::Closed.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn parse_head(buf: &[u8]) -> Result<Option<Head>, Failure> {
    if buf.is_empty() {
        return Ok(None);
    }
    let mut headers = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf) {
        Ok(httparse::Status::Partial) => Ok(None),
        Ok(httparse::Status::Complete(len)) => {
            let status = resp.code.ok_or(Failure::Wire(Wire::Malformed))?;
            let minor = resp.version.ok_or(Failure::Wire(Wire::Malformed))?;
            let headers = resp
                .headers
                .iter()
                .map(|h| {
                    let value = String::from_utf8_lossy(h.value);
                    (h.name.to_string(), value.trim().to_string())
                })
                .collect();
            Ok(Some(Head {
                status,
                minor,
                headers,
                len,
            }))
        }
        Err(_) => Err(Wire::Malformed.into()),
    }
}

/// 본문의 끝을 아는 법.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    Empty,
    Length(u64),
    Chunked(Chunk),
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chunk {
    /// 다음 조각의 크기 줄을 읽을 차례. 덧붙은 글자의 몫을 함께 든다.
    Size {
        excess: i64,
    },
    Data {
        left: u64,
        excess: i64,
    },
    /// 조각 뒤의 CRLF.
    End {
        excess: i64,
    },
    Done,
}

/// 응답의 본문 틀과 `Content-Length`(Go 의 `resp.ContentLength` 자리).
fn framing(method: Method, head: &Head) -> Result<(Framing, Option<u64>), Failure> {
    let encodings = head.values("Transfer-Encoding");
    let chunked = head.minor >= 1 && !encodings.is_empty();
    if chunked && (encodings.len() != 1 || !encodings[0].eq_ignore_ascii_case("chunked")) {
        return Err(Wire::Framing.into());
    }
    // `chunked` 면 `Content-Length` 는 없는 것으로 친다.
    let lengths = if chunked {
        Vec::new()
    } else {
        head.values("Content-Length")
    };
    let length = match lengths.split_first() {
        None => None,
        Some((first, rest)) if rest.iter().all(|v| v == first) => Some(*first),
        Some(_) => return Err(Wire::Framing.into()),
    };
    if method == Method::Head {
        return Ok((Framing::Empty, length.map(content_length).transpose()?));
    }
    if (100..200).contains(&head.status) || head.status == 204 || head.status == 304 {
        return Ok((Framing::Empty, Some(0)));
    }
    if chunked {
        return Ok((Framing::Chunked(Chunk::Size { excess: 0 }), None));
    }
    match length {
        Some(v) => {
            let n = content_length(v)?;
            Ok((Framing::Length(n), Some(n)))
        }
        None => Ok((Framing::Close, None)),
    }
}

/// 십진수 하나 — 비었거나 숫자가 아니거나 63비트를 넘으면 거절.
fn content_length(v: &str) -> Result<u64, Failure> {
    let bad = || Failure::Wire(Wire::Framing);
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n: u64 = v.parse().map_err(|_| bad())?;
    if n > i64::MAX as u64 {
        return Err(bad());
    }
    Ok(n)
}

/// 응답 본문 — 틀을 풀어 내용만 준다. 시한 · 취소 · 틀의 문제는 [`Failure`] 를 실은 읽기 오류다.
struct Body<'a> {
    link: Box<dyn Link + 'a>,
    watch: Watch<'a>,
    buf: Vec<u8>,
    pos: usize,
    framing: Framing,
}

impl Read for Body<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let got = match self.framing {
            Framing::Empty => Ok(0),
            Framing::Close => self.raw(out),
            Framing::Length(left) => self.length(out, left),
            Framing::Chunked(state) => self.chunked(out, state),
        };
        got.map_err(Failure::into_io)
    }
}

impl Body<'_> {
    /// 받아 둔 것이 없으면 연결에서 더 받는다. 0 은 연결이 닫힌 것이다.
    fn fill(&mut self) -> Result<usize, Failure> {
        if self.pos < self.buf.len() {
            return Ok(self.buf.len() - self.pos);
        }
        self.buf.clear();
        self.pos = 0;
        self.buf.resize(FILL, 0);
        let n = self.link.recv(&mut self.buf, &self.watch);
        self.buf.truncate(*n.as_ref().unwrap_or(&0));
        n
    }

    fn raw(&mut self, out: &mut [u8]) -> Result<usize, Failure> {
        let have = self.fill()?;
        let n = have.min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    fn length(&mut self, out: &mut [u8], left: u64) -> Result<usize, Failure> {
        if left == 0 {
            return Ok(0);
        }
        let want = out.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let n = self.raw(&mut out[..want])?;
        if n == 0 {
            return Err(Wire::Closed.into());
        }
        self.framing = Framing::Length(left - n as u64);
        Ok(n)
    }

    fn chunked(&mut self, out: &mut [u8], mut state: Chunk) -> Result<usize, Failure> {
        loop {
            match state {
                Chunk::Done => return Ok(0),
                Chunk::Size { excess } => state = self.chunk_size(excess)?,
                Chunk::Data { left, excess } => {
                    let want = out.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                    let n = self.raw(&mut out[..want])?;
                    if n == 0 {
                        return Err(Wire::Closed.into());
                    }
                    let left = left - n as u64;
                    self.framing = Framing::Chunked(if left == 0 {
                        Chunk::End { excess }
                    } else {
                        Chunk::Data { left, excess }
                    });
                    return Ok(n);
                }
                Chunk::End { excess } => {
                    let mut crlf = [0u8; 2];
                    self.exact(&mut crlf)?;
                    if &crlf != b"\r\n" {
                        return Err(Wire::Framing.into());
                    }
                    state = Chunk::Size { excess };
                }
            }
            self.framing = Framing::Chunked(state);
        }
    }

    /// 크기 줄 하나 — 16진수(16자리까지), `;` 뒤의 확장은 버린다. 0 이면 꼬리 헤더를 지나 끝이다.
    fn chunk_size(&mut self, excess: i64) -> Result<Chunk, Failure> {
        let line = self.line()?;
        let mut excess = excess + line.len() as i64 + 2;
        let trimmed = trim_ascii_end(&line);
        let digits = trimmed.split(|b| *b == b';').next().unwrap_or_default();
        let size = hex(digits)?;
        excess = (excess - 16 - 2 * size.min(i64::MAX as u64 / 4) as i64).max(0);
        if excess > MAX_CHUNK_EXCESS {
            return Err(Wire::Framing.into());
        }
        if size == 0 {
            self.trailer()?;
            return Ok(Chunk::Done);
        }
        Ok(Chunk::Data { left: size, excess })
    }

    /// 꼬리 헤더 — 빈 줄까지 읽고 버린다.
    fn trailer(&mut self) -> Result<(), Failure> {
        let mut total = 0usize;
        loop {
            let line = self.line()?;
            if line.is_empty() {
                return Ok(());
            }
            total += line.len() + 2;
            if total > MAX_TRAILER {
                return Err(Wire::Framing.into());
            }
        }
    }

    /// CRLF 로 끝나는 줄 하나(CRLF 는 뗀다). 줄 안의 CR · 맨 LF · 4 KiB 넘는 줄은 거절.
    fn line(&mut self) -> Result<Vec<u8>, Failure> {
        let mut line = Vec::new();
        loop {
            if self.fill()? == 0 {
                return Err(Wire::Closed.into());
            }
            let rest = &self.buf[self.pos..];
            match rest.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    line.extend_from_slice(&rest[..=i]);
                    self.pos += i + 1;
                    break;
                }
                None => {
                    line.extend_from_slice(rest);
                    self.pos = self.buf.len();
                }
            }
            if line.len() > MAX_CHUNK_LINE + 2 {
                return Err(Wire::Framing.into());
            }
        }
        let cr = line.iter().position(|b| *b == b'\r');
        if line.len() < 2 || cr != Some(line.len() - 2) || line.len() - 2 >= MAX_CHUNK_LINE {
            return Err(Wire::Framing.into());
        }
        line.truncate(line.len() - 2);
        Ok(line)
    }

    fn exact(&mut self, out: &mut [u8]) -> Result<(), Failure> {
        let mut n = 0;
        while n < out.len() {
            let m = self.raw(&mut out[n..])?;
            if m == 0 {
                return Err(Wire::Closed.into());
            }
            n += m;
        }
        Ok(())
    }
}

fn trim_ascii_end(b: &[u8]) -> &[u8] {
    let end = b
        .iter()
        .rposition(|c| !matches!(c, b' ' | b'\t' | b'\n' | b'\r'))
        .map_or(0, |i| i + 1);
    &b[..end]
}

/// `chunked` 의 크기 — 빈 글 · 16진수가 아닌 글자 · 17자리부터는 거절.
fn hex(v: &[u8]) -> Result<u64, Failure> {
    if v.is_empty() || v.len() > 16 {
        return Err(Wire::Framing.into());
    }
    let mut n: u64 = 0;
    for b in v {
        let d = char::from(*b)
            .to_digit(16)
            .ok_or(Failure::Wire(Wire::Framing))?;
        n = n << 4 | u64::from(d);
    }
    Ok(n)
}

#[cfg(test)]
mod tests;
