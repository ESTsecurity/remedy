//! tar 판독 — Go 의 `archive/tar` 가 `Reader.Next` 로 내는 그대로.
//!
//! 사내 runtime-scanner 는 이미지 아카이브와 레이어를 Go 의 표준 판독기로 읽는다. 같은 바이트를 같게 읽으려고 그
//! 판독기의 규칙을 옮겼다(tar 크레이트의 판독기를 쓰지 않는 까닭은 워크스페이스 `Cargo.toml` 의 그 줄).
//!
//! - 머리 블록은 체크섬이 맞아야 한다 — 부호 없는 합 또는 부호 있는 합(옛 Sun tar). 머리의 수 칸 하나라도 읽히지
//!   않으면 머리 오류다. 수 칸은 8진수(앞뒤의 공백 · NUL 은 걷는다) 또는 base-256 이다.
//! - 끝은 넷이다 — 0 블록 둘, 0 블록 하나 뒤의 파일 끝, 블록 경계의 파일 끝, 마지막 항목의 채움이 덜 끝난 파일 끝.
//!   0 블록 뒤에 0 이 아닌 블록이 오면 머리 오류다. 끝 뒤에 남은 바이트는 부르는 쪽이 본다.
//! - 링크 · 장치 · 디렉터리 · FIFO 는 크기 칸과 상관없이 자료가 없다.
//! - PAX(`x`)와 GNU 긴 이름 · 링크(`L` · `K`)는 다음 항목에 붙는다. 셋 다 1 MiB 까지만 읽는다. PAX 의 `size` ·
//!   `uid` · `gid` · 시각은 꼴이 맞아야 한다. 전역 PAX(`g`)는 항목으로 내보낸다 — 부르는 쪽이 거절한다.
//! - 이름이 `/` 로 끝나는 옛 일반 파일(`\0`)은 디렉터리다.
//!
//! 희소 파일(GNU `S` · PAX `GNU.sparse.*`)은 풀지 않고 그 머리대로 내보낸다 — 부르는 쪽이 거절한다.

use super::fault::Fault;
use std::collections::BTreeMap;
use std::io::{self, Read};

const BLOCK: usize = 512;
/// PAX 머리 · GNU 긴 이름의 상한 — Go 와 libarchive 의 값.
const MAX_SPECIAL: u64 = 1 << 20;

pub(super) const TYPE_REG: u8 = b'0';
pub(super) const TYPE_LINK: u8 = b'1';
pub(super) const TYPE_SYMLINK: u8 = b'2';
pub(super) const TYPE_CHAR: u8 = b'3';
pub(super) const TYPE_BLOCK: u8 = b'4';
pub(super) const TYPE_DIR: u8 = b'5';
pub(super) const TYPE_FIFO: u8 = b'6';
pub(super) const TYPE_GNU_SPARSE: u8 = b'S';

/// 항목 하나의 머리 — Go 의 `tar.Header` 가운데 이 점검이 보는 칸.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Header {
    pub(super) typeflag: u8,
    pub(super) name: Vec<u8>,
    pub(super) linkname: Vec<u8>,
    pub(super) size: i64,
    pub(super) mode: i64,
    /// 이 항목에 붙은 PAX 기록(키마다 마지막 값).
    pub(super) pax: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// 머리 블록의 꼴.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    V7,
    UstarPax,
    Star,
    Gnu,
}

pub(super) struct TarReader<R> {
    r: R,
    /// 지금 항목에서 남은 자료.
    left: u64,
    /// 그 뒤의 채움.
    pad: u64,
}

impl<R: Read> TarReader<R> {
    pub(super) fn new(r: R) -> Self {
        TarReader { r, left: 0, pad: 0 }
    }

    pub(super) fn into_inner(self) -> R {
        self.r
    }

    /// 다음 항목. `None` 은 아카이브의 끝이다(Go 의 `io.EOF`).
    pub(super) fn next(&mut self) -> io::Result<Option<Header>> {
        let mut pax: Option<BTreeMap<Vec<u8>, Vec<u8>>> = None;
        let (mut long_name, mut long_link) = (Vec::new(), Vec::new());
        loop {
            if !self.skip_rest()? {
                return Ok(None);
            }
            let Some(block) = self.block()? else {
                return Ok(None);
            };
            let mut h = parse_block(&block)?;
            self.set_data(h.typeflag, h.size)?;
            match h.typeflag {
                b'x' | b'g' => {
                    let records = parse_pax(&self.special()?)?;
                    if h.typeflag == b'g' {
                        return Ok(Some(global(h, records)));
                    }
                    pax = Some(records);
                }
                b'L' => long_name = c_str(&self.special()?).to_vec(),
                b'K' => long_link = c_str(&self.special()?).to_vec(),
                _ => {
                    merge_pax(&mut h, pax.take().unwrap_or_default())?;
                    if !long_name.is_empty() {
                        h.name = long_name;
                    }
                    if !long_link.is_empty() {
                        h.linkname = long_link;
                    }
                    if h.typeflag == 0 {
                        h.typeflag = if h.name.ends_with(b"/") {
                            TYPE_DIR
                        } else {
                            TYPE_REG
                        };
                    }
                    self.set_data(h.typeflag, h.size)?;
                    return Ok(Some(h));
                }
            }
        }
    }

    /// 앞 항목의 남은 자료와 채움을 넘긴다. 자료가 모자라면 오류, 채움이 모자라면 끝(거짓)이다 — Go 의 `discard` 와
    /// `tryReadFull`.
    fn skip_rest(&mut self) -> io::Result<bool> {
        let left = self.left;
        if left > 0 {
            let skipped = io::copy(&mut (&mut self.r).take(left), &mut io::sink())?;
            self.left = 0;
            if skipped < left {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        let pad = std::mem::take(&mut self.pad) as usize;
        let mut buf = [0u8; BLOCK];
        Ok(read_full(&mut self.r, &mut buf[..pad])? == pad)
    }

    /// 머리 블록 하나 — Go 의 `readHeader` 의 끝 규칙.
    fn block(&mut self) -> io::Result<Option<[u8; BLOCK]>> {
        let mut b = [0u8; BLOCK];
        if !self.whole_block(&mut b)? {
            return Ok(None);
        }
        if b.iter().any(|&c| c != 0) {
            return Ok(Some(b));
        }
        if !self.whole_block(&mut b)? || b.iter().all(|&c| c == 0) {
            return Ok(None);
        }
        Err(Fault::TarHeader.into())
    }

    /// 블록 하나를 채운다. 하나도 읽지 못한 끝은 거짓, 덜 채운 끝은 오류다(Go 의 `io.ReadFull`).
    fn whole_block(&mut self, b: &mut [u8; BLOCK]) -> io::Result<bool> {
        match read_full(&mut self.r, b)? {
            0 => Ok(false),
            BLOCK => Ok(true),
            _ => Err(io::ErrorKind::UnexpectedEof.into()),
        }
    }

    /// 자료의 길이와 채움 — 머리만 있는 형식은 0 이다. 음수 크기는 머리 오류다(Go 의 `handleRegularFile`).
    fn set_data(&mut self, typeflag: u8, size: i64) -> io::Result<()> {
        let n = if header_only(typeflag) { 0 } else { size };
        let n = u64::try_from(n).map_err(|_| io::Error::from(Fault::TarHeader))?;
        self.left = n;
        self.pad = n.wrapping_neg() & (BLOCK as u64 - 1);
        Ok(())
    }

    /// PAX 머리 · GNU 긴 이름의 자료 — 1 MiB 를 넘으면 오류다.
    fn special(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(self.left.min(MAX_SPECIAL + 1) as usize);
        self.take(MAX_SPECIAL + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_SPECIAL {
            return Err(Fault::TarFieldTooLong.into());
        }
        Ok(buf)
    }
}

/// 지금 항목의 자료 — 다 읽기 전에 끝나면 오류다(Go 의 `regFileReader`).
impl<R: Read> Read for TarReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.r.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// 버퍼를 채운다 — 읽은 바이트 수(끝에 닿으면 모자랄 수 있다).
pub(super) fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn header_only(typeflag: u8) -> bool {
    matches!(typeflag, b'1'..=b'6')
}

/// NUL 앞까지(Go 의 `parseString`).
fn c_str(b: &[u8]) -> &[u8] {
    b.iter().position(|&c| c == 0).map_or(b, |i| &b[..i])
}

/// 전역 PAX 머리 — 이름은 `path` 기록이 있으면 그것이다(Go 의 `mergePAX` 를 오류 없이 적용한 것과 같다).
fn global(mut h: Header, records: BTreeMap<Vec<u8>, Vec<u8>>) -> Header {
    if let Some(path) = records.get(b"path".as_slice()).filter(|p| !p.is_empty()) {
        h.name = path.clone();
    }
    h.size = 0;
    h.pax = records;
    h
}

/// 머리 블록 — Go 의 `readHeader`(끝 규칙 뒤).
fn parse_block(b: &[u8; BLOCK]) -> io::Result<Header> {
    let format = format_of(b).ok_or(Fault::TarHeader)?;
    let mut ok = true;
    let mut num = |field: &[u8]| -> i64 {
        let v = numeric(field);
        ok &= v.is_some();
        v.unwrap_or(0)
    };
    let size = num(&b[124..136]);
    let mode = num(&b[100..108]);
    for field in [&b[108..116], &b[116..124], &b[136..148]] {
        num(field);
    }
    let mut name = c_str(&b[0..100]).to_vec();
    if format != Format::V7 {
        num(&b[329..337]);
        num(&b[337..345]);
        let prefix = match format {
            Format::UstarPax => c_str(&b[345..500]).to_vec(),
            Format::Star => {
                num(&b[476..488]);
                num(&b[488..500]);
                c_str(&b[345..476]).to_vec()
            }
            _ => gnu_prefix(b),
        };
        if !prefix.is_empty() {
            name = [prefix.as_slice(), b"/", name.as_slice()].concat();
        }
    }
    if !ok {
        return Err(Fault::TarHeader.into());
    }
    Ok(Header {
        typeflag: b[156],
        name,
        linkname: c_str(&b[157..257]).to_vec(),
        size,
        mode,
        pax: BTreeMap::new(),
    })
}

/// GNU 머리에는 앞머리 칸이 없다. 다만 Go 1.8 전의 기록기가 그 자리에 앞머리를 적은 파일이 있어, 접근 · 변경 시각
/// 칸이 수로 읽히지 않고 그 자리가 ASCII 글이면 앞머리로 읽는다(Go 와 같다).
fn gnu_prefix(b: &[u8; BLOCK]) -> Vec<u8> {
    let broken = [&b[345..357], &b[357..369]]
        .iter()
        .any(|field| field[0] != 0 && numeric(field).is_none());
    let prefix = c_str(&b[345..500]);
    if broken && prefix.iter().all(|&c| c < 0x80) {
        prefix.to_vec()
    } else {
        Vec::new()
    }
}

/// 체크섬과 마법 글자로 꼴을 가린다. 체크섬이 틀리면 `None`.
fn format_of(b: &[u8; BLOCK]) -> Option<Format> {
    let stored = octal(&b[148..156])?;
    let (mut unsigned, mut signed) = (0i64, 0i64);
    for (i, &c) in b.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        unsigned += i64::from(c);
        signed += i64::from(c as i8);
    }
    if stored != unsigned && stored != signed {
        return None;
    }
    let (magic, version, trailer) = (&b[257..263], &b[263..265], &b[508..512]);
    Some(match (magic, version) {
        (b"ustar\0", _) if trailer == b"tar\0" => Format::Star,
        (b"ustar\0", _) => Format::UstarPax,
        (b"ustar ", b" \0") => Format::Gnu,
        _ => Format::V7,
    })
}

/// base-256 또는 8진수(Go 의 `parseNumeric`). 읽히지 않거나 넘치면 `None`.
fn numeric(b: &[u8]) -> Option<i64> {
    if b.first().is_some_and(|&c| c & 0x80 != 0) {
        let inv = if b[0] & 0x40 != 0 { 0xff } else { 0x00 };
        let mut x: u64 = 0;
        for (i, &c) in b.iter().enumerate() {
            let mut c = c ^ inv;
            if i == 0 {
                c &= 0x7f;
            }
            if x >> 56 > 0 {
                return None;
            }
            x = x << 8 | u64::from(c);
        }
        if x >> 63 > 0 {
            return None;
        }
        let x = x as i64;
        return Some(if inv == 0xff { !x } else { x });
    }
    octal(b)
}

/// 8진수 칸 — 앞뒤의 공백 · NUL 을 걷고, 그 안의 첫 NUL 앞까지를 읽는다. 비면 0 이다. 2^63 이상은 Go 처럼 음수로
/// 접힌다(크기 칸이면 그 뒤에 머리 오류가 된다).
fn octal(b: &[u8]) -> Option<i64> {
    let pad = |c: &u8| *c == b' ' || *c == 0;
    let start = b.iter().position(|c| !pad(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !pad(c)).map_or(start, |i| i + 1);
    let digits = c_str(&b[start..end]);
    if digits.is_empty() {
        return Some(0);
    }
    let text = std::str::from_utf8(digits).ok()?;
    u64::from_str_radix(text, 8)
        .ok()
        .filter(|_| !text.starts_with('+'))
        .map(|x| x as i64)
}

/// PAX 기록들(Go 의 `parsePAX` · `parsePAXRecord`). 키마다 마지막 값이 남는다.
fn parse_pax(buf: &[u8]) -> io::Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let bad = || io::Error::from(Fault::TarHeader);
    let mut out = BTreeMap::new();
    let mut s = buf;
    while !s.is_empty() {
        let space = s.iter().position(|&c| c == b' ').ok_or_else(bad)?;
        let n = go_int(&s[..space])
            .filter(|n| *n >= 5 && *n <= s.len() as i64)
            .ok_or_else(bad)?;
        let n = usize::try_from(n - (space as i64 + 1))
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(bad)?;
        let rest = &s[space + 1..];
        let (record, newline) = (&rest[..n - 1], rest[n - 1]);
        let eq = record.iter().position(|&c| c == b'=');
        let (Some(eq), b'\n') = (eq, newline) else {
            return Err(bad());
        };
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        if !valid_record(key, value) {
            return Err(bad());
        }
        out.insert(key.to_vec(), value.to_vec());
        s = &rest[n..];
    }
    Ok(out)
}

/// 키는 비지 않고 `=` 이 없어야 한다. 경로 · 이름 칸의 값과 그 밖의 키에는 NUL 이 없어야 한다.
fn valid_record(key: &[u8], value: &[u8]) -> bool {
    if key.is_empty() || key.contains(&b'=') {
        return false;
    }
    match key {
        b"path" | b"linkpath" | b"uname" | b"gname" => !value.contains(&0),
        _ => !key.contains(&0),
    }
}

/// PAX 기록을 머리에 옮긴다(Go 의 `mergePAX`). 빈 값은 원래 칸을 둔다.
fn merge_pax(h: &mut Header, records: BTreeMap<Vec<u8>, Vec<u8>>) -> io::Result<()> {
    for (key, value) in &records {
        if value.is_empty() {
            continue;
        }
        let ok = match key.as_slice() {
            b"path" => {
                h.name = value.clone();
                true
            }
            b"linkpath" => {
                h.linkname = value.clone();
                true
            }
            b"size" => go_int(value).map(|n| h.size = n).is_some(),
            b"uid" | b"gid" => go_int(value).is_some(),
            b"atime" | b"mtime" | b"ctime" => pax_time(value),
            _ => true,
        };
        if !ok {
            return Err(Fault::TarHeader.into());
        }
    }
    h.pax = records;
    Ok(())
}

/// Go 의 `strconv.ParseInt(s, 10, 64)` — 부호 하나와 숫자.
fn go_int(s: &[u8]) -> Option<i64> {
    let digits = s
        .strip_prefix(b"+")
        .or_else(|| s.strip_prefix(b"-"))
        .unwrap_or(s);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(s.strip_prefix(b"+").unwrap_or(s))
        .ok()?
        .parse()
        .ok()
}

/// PAX 시각(`초[.소수]`)의 꼴.
fn pax_time(s: &[u8]) -> bool {
    let (secs, frac) = match s.iter().position(|&c| c == b'.') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, &[][..]),
    };
    go_int(secs).is_some() && frac.iter().all(u8::is_ascii_digit)
}
