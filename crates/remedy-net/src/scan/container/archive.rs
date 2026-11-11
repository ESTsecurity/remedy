//! 파일 하나짜리 아카이브 — 엔진의 파일 조회 API(`GET /containers/{id}/archive?path=`)가 주는 tar.
//!
//! 스캐너는 Go 의 `archive/tar` 로 읽고 그 위에 규칙을 얹었다(`client.go` 의 `consumeRegular`). 여기서는 그 규칙이
//! 기대는 만큼의 tar 판독을 손으로 옮겼다 — 512바이트 머리(V7 · USTAR · PAX · GNU · STAR 꼴 가르기와 체크섬), PAX
//! `x` 기록, GNU 긴 이름, 끝 표시(0 블록 둘).
//!
//! 받는 것은 **일반 파일 하나**뿐이다.
//!
//! - 항목의 이름이 요청한 파일의 마지막 요소와 같고(Windows 경로면 대소문자 무시), 링크가 아니고, 크기가 파일 정보
//!   헤더의 크기와 같다.
//! - PAX 기록은 시각 셋(`mtime` · `atime` · `ctime`)만 — 경로 · 크기 · 종류를 바꿀 수 있는 기록은 받지 않는다.
//! - GNU 꼴의 머리는 받지 않는다.
//! - 파일 뒤에는 끝 표시 말고 다른 항목이 없고, 끝 표시 뒤에는 0 만 올 수 있다.
//!
//! Go 판독기의 너그러운 자리도 그대로 둔다 — 끝 표시가 없거나 하나뿐이어도, 마지막 채움이 잘려도 끝으로 본다. 그
//! 경우에도 받은 파일 내용은 크기까지 다 읽은 것이다.

use super::failure::{Failure, FileFailure};
use super::gostr;
use super::paths;
use std::collections::BTreeMap;
use std::io::{self, Read};

const BLOCK: usize = 512;
/// PAX 기록 · GNU 긴 이름 하나의 상한.
const MAX_SPECIAL: u64 = 1 << 20;
/// 끝 표시 뒤를 읽는 조각.
const TAIL_CHUNK: usize = 32 << 10;

/// Go 의 꼴 표시(비트 묶음) — `mayOnlyBe` 로 좁혀 간다. 0 은 모름이다.
const FORMAT_V7: u8 = 1;
const USTAR: u8 = 2;
const PAX: u8 = 4;
const GNU: u8 = 8;
const STAR: u8 = 16;

/// PAX 기록 — 같은 키는 뒤의 것이 이긴다.
type Records = BTreeMap<Vec<u8>, Vec<u8>>;

/// 항목 하나의 머리.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) typeflag: u8,
    pub(crate) name: Vec<u8>,
    pub(crate) linkname: Vec<u8>,
    pub(crate) size: i64,
    pub(crate) pax: Option<Records>,
    pub(crate) format: u8,
}

/// 판독이 멈춘 까닭.
#[derive(Debug)]
pub(crate) enum TarError {
    Io(io::Error),
    /// 머리 · 기록의 꼴이 틀렸다(Go 의 `ErrHeader`).
    Header,
    /// 블록이나 항목 내용 중간에서 끝났다.
    UnexpectedEof,
    /// 특수 항목이 1 MiB 를 넘었다.
    TooLong,
}

impl TarError {
    /// 읽기 고리의 까닭(한도 · 취소 · 연결)은 그대로, 꼴의 문제는 `shape` 로.
    fn into_failure(self, shape: FileFailure) -> Failure {
        match self {
            TarError::Io(e) => carried_or(e, shape),
            _ => Failure::File(shape),
        }
    }
}

fn carried_or(e: io::Error, shape: FileFailure) -> Failure {
    match Failure::from_io(&e) {
        Failure::File(FileFailure::Read) if e.kind() == io::ErrorKind::UnexpectedEof => {
            Failure::File(shape)
        }
        Failure::File(FileFailure::Read) => Failure::File(FileFailure::Read),
        other => other,
    }
}

impl From<io::Error> for TarError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof && e.get_ref().is_none() {
            return TarError::UnexpectedEof;
        }
        TarError::Io(e)
    }
}

/// tar 판독기 — Go `tar.Reader` 의 `Next` · 항목 읽기와 같은 차례로 바이트를 쓴다.
pub(crate) struct TarReader<R> {
    r: R,
    /// 지금 항목에서 남은 내용.
    remaining: u64,
    /// 지금 항목 뒤의 채움.
    pad: u64,
}

impl<R: Read> TarReader<R> {
    pub(crate) fn new(r: R) -> Self {
        TarReader {
            r,
            remaining: 0,
            pad: 0,
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.r
    }

    /// 다음 항목. `None` 은 끝이다 — 끝 표시를 만났거나, 블록 경계 · 채움에서 입력이 끝났다.
    pub(crate) fn next(&mut self) -> Result<Option<Header>, TarError> {
        let mut format = USTAR | PAX | GNU;
        let mut pax: Option<Records> = None;
        let (mut long_name, mut long_link) = (Vec::new(), Vec::new());
        loop {
            if !self.skip_current()? {
                return Ok(None);
            }
            let Some(mut hdr) = self.read_header()? else {
                return Ok(None);
            };
            self.start_entry(&hdr)?;
            format &= hdr.format;
            match hdr.typeflag {
                b'x' | b'g' => {
                    format &= PAX;
                    let records = parse_pax(&self.read_special()?)?;
                    if hdr.typeflag == b'g' {
                        merge_pax(&mut hdr, &records)?;
                        hdr.pax = Some(records);
                        hdr.format = format;
                        return Ok(Some(hdr));
                    }
                    pax = Some(records);
                }
                b'L' | b'K' => {
                    format &= GNU;
                    let text = c_string(&self.read_special()?).to_vec();
                    if hdr.typeflag == b'L' {
                        long_name = text;
                    } else {
                        long_link = text;
                    }
                }
                _ => {
                    return self
                        .finish(hdr, pax, long_name, long_link, format)
                        .map(Some)
                }
            }
        }
    }

    /// 보통 항목 — 앞선 PAX 기록 · 긴 이름을 덮고 꼴을 정한다.
    fn finish(
        &mut self,
        mut hdr: Header,
        pax: Option<Records>,
        long_name: Vec<u8>,
        long_link: Vec<u8>,
        mut format: u8,
    ) -> Result<Header, TarError> {
        if let Some(records) = &pax {
            merge_pax(&mut hdr, records)?;
        }
        if !long_name.is_empty() {
            hdr.name = long_name;
        }
        if !long_link.is_empty() {
            hdr.linkname = long_link;
        }
        if hdr.typeflag == 0 {
            hdr.typeflag = if hdr.name.ends_with(b"/") { b'5' } else { b'0' };
        }
        self.start_entry(&hdr)?;
        if format & USTAR != 0 && format & PAX != 0 {
            format &= USTAR;
        }
        hdr.format = format;
        hdr.pax = pax;
        Ok(hdr)
    }

    /// 지금 항목의 남은 내용과 채움을 건너뛴다. 채움 중간에서 입력이 끝나면 거짓(끝)이다.
    fn skip_current(&mut self) -> Result<bool, TarError> {
        let mut sink = [0u8; BLOCK];
        while self.remaining > 0 {
            let want = (self.remaining as usize).min(sink.len());
            let n = self.r.read(&mut sink[..want])?;
            if n == 0 {
                return Err(TarError::UnexpectedEof);
            }
            self.remaining -= n as u64;
        }
        let pad = self.pad as usize;
        self.pad = 0;
        Ok(fill(&mut self.r, &mut sink[..pad])? == pad)
    }

    /// 머리 블록 하나. 0 블록 둘(또는 0 블록 하나 뒤의 끝)은 끝 표시다.
    fn read_header(&mut self) -> Result<Option<Header>, TarError> {
        let mut block = [0u8; BLOCK];
        if !self.read_block(&mut block)? {
            return Ok(None);
        }
        if block.iter().all(|b| *b == 0) {
            if !self.read_block(&mut block)? || block.iter().all(|b| *b == 0) {
                return Ok(None);
            }
            return Err(TarError::Header);
        }
        let format = block_format(&block);
        if format == 0 {
            return Err(TarError::Header);
        }
        parse_header(&block, format).map(Some)
    }

    /// 블록 하나를 다 채운다. 한 바이트도 없이 끝나면 거짓, 중간에서 끝나면 오류.
    fn read_block(&mut self, block: &mut [u8; BLOCK]) -> Result<bool, TarError> {
        match fill(&mut self.r, block)? {
            0 => Ok(false),
            BLOCK => Ok(true),
            _ => Err(TarError::UnexpectedEof),
        }
    }

    /// 항목의 내용 길이와 채움을 잡는다 — 내용이 없는 종류(링크 · 장치 · 디렉터리 · FIFO)는 0 이다.
    fn start_entry(&mut self, hdr: &Header) -> Result<(), TarError> {
        let size = if matches!(hdr.typeflag, b'1'..=b'6') {
            0
        } else {
            hdr.size
        };
        let size = u64::try_from(size).map_err(|_| TarError::Header)?;
        self.remaining = size;
        self.pad = (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64;
        Ok(())
    }

    /// 특수 항목(PAX 기록 · 긴 이름)의 내용 — 1 MiB 까지.
    fn read_special(&mut self) -> Result<Vec<u8>, TarError> {
        let mut out = Vec::new();
        (&mut self.entry())
            .take(MAX_SPECIAL + 1)
            .read_to_end(&mut out)?;
        if out.len() as u64 > MAX_SPECIAL {
            return Err(TarError::TooLong);
        }
        Ok(out)
    }

    /// 지금 항목의 내용을 읽는 쪽.
    pub(crate) fn entry(&mut self) -> Entry<'_, R> {
        Entry { tar: self }
    }
}

/// 항목 내용 — 크기까지만 주고, 그 전에 입력이 끝나면 `UnexpectedEof` 다.
pub(crate) struct Entry<'a, R> {
    tar: &'a mut TarReader<R>,
}

impl<R: Read> Read for Entry<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.tar.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.tar.remaining).unwrap_or(usize::MAX));
        let n = self.tar.r.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.tar.remaining -= n as u64;
        Ok(n)
    }
}

/// `buf` 를 채울 때까지 읽고 채운 길이를 준다 — 끝을 만나면 그때까지다(Go 의 `io.ReadFull` 바탕).
fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(m) => n += m,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// 체크섬과 마법 글자로 꼴을 가른다. 체크섬이 맞지 않으면 0(모름).
fn block_format(block: &[u8; BLOCK]) -> u8 {
    let mut p = Numbers::default();
    let stated = p.octal(&block[148..156]);
    let (unsigned, signed) = checksums(block);
    if p.bad || (stated != unsigned && stated != signed) {
        return 0;
    }
    let (magic, version, trailer) = (&block[257..263], &block[263..265], &block[508..512]);
    if magic == b"ustar\0" && trailer == b"tar\0" {
        STAR
    } else if magic == b"ustar\0" {
        USTAR | PAX
    } else if magic == b"ustar " && version == b" \0" {
        GNU
    } else {
        FORMAT_V7
    }
}

/// 체크섬 자리를 빈칸으로 친 합 — 부호 없는 것과 있는 것.
fn checksums(block: &[u8; BLOCK]) -> (i64, i64) {
    let (mut unsigned, mut signed) = (0i64, 0i64);
    for (i, &c) in block.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        unsigned += i64::from(c);
        signed += i64::from(c as i8);
    }
    (unsigned, signed)
}

/// 머리의 칸을 읽는다. 숫자 칸이 하나라도 틀리면 오류다.
fn parse_header(block: &[u8; BLOCK], format: u8) -> Result<Header, TarError> {
    let mut p = Numbers::default();
    let mut name = c_string(&block[..100]).to_vec();
    let size = p.numeric(&block[124..136]);
    for field in [100..108, 108..116, 116..124, 136..148] {
        p.numeric(&block[field]);
    }
    let mut kind = 0u8;
    if format > FORMAT_V7 {
        p.numeric(&block[329..337]);
        p.numeric(&block[337..345]);
        let (prefix, k) = format_fields(block, format, &mut p);
        kind = k;
        if !prefix.is_empty() {
            let mut full = prefix;
            full.push(b'/');
            full.extend_from_slice(&name);
            name = full;
        }
    }
    if p.bad {
        return Err(TarError::Header);
    }
    Ok(Header {
        typeflag: block[156],
        name,
        linkname: c_string(&block[157..257]).to_vec(),
        size,
        pax: None,
        format: kind,
    })
}

/// 꼴마다 다른 칸 — 이름 앞부분과 이 머리가 말하는 꼴.
fn format_fields(block: &[u8; BLOCK], format: u8, p: &mut Numbers) -> (Vec<u8>, u8) {
    if format & (USTAR | PAX) != 0 {
        let prefix = c_string(&block[345..500]).to_vec();
        // ASCII 가 아닌 바이트가 있거나 숫자 칸이 NUL 로 끝나지 않으면 USTAR 라고 단정하지 않는다.
        let ascii = block.iter().all(|b| *b < 0x80);
        let ends = [
            124..136,
            100..108,
            108..116,
            116..124,
            136..148,
            329..337,
            337..345,
        ];
        let terminated = ends.into_iter().all(|r| block[r.end - 1] == 0);
        return (prefix, if ascii && terminated { format } else { 0 });
    }
    if format & STAR != 0 {
        p.numeric(&block[476..488]);
        p.numeric(&block[488..500]);
        return (c_string(&block[345..476]).to_vec(), 0);
    }
    // GNU — 접근 · 바뀜 시각을 읽지 못하면 옛 Go 가 잘못 쓴 머리로 보고 GNU 라고 하지 않는다.
    let mut times = Numbers::default();
    if block[345] != 0 {
        times.numeric(&block[345..357]);
    }
    if block[357] != 0 {
        times.numeric(&block[357..369]);
    }
    if !times.bad {
        return (Vec::new(), format);
    }
    let prefix = c_string(&block[345..500]);
    let prefix = if prefix.is_ascii() {
        prefix.to_vec()
    } else {
        Vec::new()
    };
    (prefix, 0)
}

/// NUL 앞까지.
fn c_string(b: &[u8]) -> &[u8] {
    match b.iter().position(|c| *c == 0) {
        Some(i) => &b[..i],
        None => b,
    }
}

/// 숫자 칸 읽기 — 틀린 칸이 하나라도 있으면 `bad`.
#[derive(Default)]
struct Numbers {
    bad: bool,
}

impl Numbers {
    /// 8진수 또는 256진수(첫 비트가 켜진 칸).
    fn numeric(&mut self, b: &[u8]) -> i64 {
        match b.first() {
            Some(first) if first & 0x80 != 0 => self.base256(b),
            _ => self.octal(b),
        }
    }

    fn base256(&mut self, b: &[u8]) -> i64 {
        let inv: u8 = if b[0] & 0x40 != 0 { 0xff } else { 0 };
        let mut x: u64 = 0;
        for (i, &c) in b.iter().enumerate() {
            let mut c = c ^ inv;
            if i == 0 {
                c &= 0x7f;
            }
            if x >> 56 > 0 {
                self.bad = true;
                return 0;
            }
            x = x << 8 | u64::from(c);
        }
        if x >> 63 > 0 {
            self.bad = true;
            return 0;
        }
        let x = x as i64;
        if inv == 0xff {
            !x
        } else {
            x
        }
    }

    /// 앞뒤의 빈칸 · NUL 을 걷은 8진수. 비면 0 이다. 부호는 받지 않는다.
    fn octal(&mut self, b: &[u8]) -> i64 {
        let start = b.iter().position(|c| *c != b' ' && *c != 0);
        let Some(start) = start else {
            return 0;
        };
        let end = b
            .iter()
            .rposition(|c| *c != b' ' && *c != 0)
            .unwrap_or(start);
        let digits = c_string(&b[start..=end]);
        let mut x: u64 = 0;
        for d in digits {
            let v = match d {
                b'0'..=b'7' => u64::from(d - b'0'),
                _ => {
                    self.bad = true;
                    return 0;
                }
            };
            let Some(next) = x.checked_mul(8).and_then(|x| x.checked_add(v)) else {
                self.bad = true;
                return 0;
            };
            x = next;
        }
        x as i64
    }
}

/// PAX 기록들(`"%d %s=%s\n"` 의 이음).
fn parse_pax(mut s: &[u8]) -> Result<Records, TarError> {
    let mut records = Records::new();
    while !s.is_empty() {
        let (k, v, rest) = pax_record(s).ok_or(TarError::Header)?;
        records.insert(k.to_vec(), v.to_vec());
        s = rest;
    }
    Ok(records)
}

fn pax_record(s: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let space = s.iter().position(|b| *b == b' ')?;
    let (count, rest) = (&s[..space], &s[space + 1..]);
    let n = go_int(count)?;
    if n < 5 || n > s.len() as i64 {
        return None;
    }
    let n = n - (count.len() as i64 + 1);
    if n <= 0 {
        return None;
    }
    let n = n as usize;
    if rest[n - 1] != b'\n' {
        return None;
    }
    let record = &rest[..n - 1];
    let eq = record.iter().position(|b| *b == b'=')?;
    let (k, v) = (&record[..eq], &record[eq + 1..]);
    let text_key = matches!(k, b"path" | b"linkpath" | b"uname" | b"gname");
    let nul_free = if text_key {
        !v.contains(&0)
    } else {
        !k.contains(&0)
    };
    (!k.is_empty() && nul_free).then_some((k, v, &rest[n..]))
}

/// 기록을 머리에 덮는다 — 빈 값은 원래 칸을 둔다. 숫자 · 시각을 읽지 못하면 오류다.
fn merge_pax(hdr: &mut Header, records: &Records) -> Result<(), TarError> {
    for (k, v) in records {
        if v.is_empty() {
            continue;
        }
        let ok = match k.as_slice() {
            b"path" => {
                hdr.name = v.clone();
                true
            }
            b"linkpath" => {
                hdr.linkname = v.clone();
                true
            }
            b"uid" | b"gid" => go_int(v).is_some(),
            b"atime" | b"mtime" | b"ctime" => pax_time(v),
            b"size" => match go_int(v) {
                Some(size) => {
                    hdr.size = size;
                    true
                }
                None => false,
            },
            _ => true,
        };
        if !ok {
            return Err(TarError::Header);
        }
    }
    Ok(())
}

/// `초[.소수]` — 초는 64비트 정수여야 한다.
fn pax_time(v: &[u8]) -> bool {
    let (secs, frac) = match v.iter().position(|b| *b == b'.') {
        Some(i) => (&v[..i], &v[i + 1..]),
        None => (v, &[][..]),
    };
    go_int(secs).is_some() && frac.iter().all(u8::is_ascii_digit)
}

/// Go 의 `strconv.ParseInt(s, 10, 64)` — 부호 하나와 십진 숫자.
fn go_int(s: &[u8]) -> Option<i64> {
    let (negative, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut x: i128 = 0;
    for d in digits {
        x = x * 10 + i128::from(d - b'0');
        if x > i128::from(i64::MAX) + 1 {
            return None;
        }
    }
    let x = if negative { -x } else { x };
    i64::try_from(x).ok()
}

/// 기록이 시각 셋뿐이고 값이 `-?숫자[.숫자]` 꼴(64바이트까지)이다.
fn safe_pax(records: &Option<Records>) -> bool {
    let Some(records) = records else {
        return true;
    };
    records.iter().all(|(k, v)| {
        matches!(k.as_slice(), b"mtime" | b"atime" | b"ctime") && v.len() <= 64 && pax_time_shape(v)
    })
}

fn pax_time_shape(v: &[u8]) -> bool {
    let v = v.strip_prefix(b"-").unwrap_or(v);
    let (whole, frac) = match v.iter().position(|b| *b == b'.') {
        Some(i) => (&v[..i], Some(&v[i + 1..])),
        None => (v, None),
    };
    let digits = |d: &[u8]| !d.is_empty() && d.iter().all(u8::is_ascii_digit);
    digits(whole) && frac.is_none_or(digits)
}

/// 항목의 이름이 요청한 파일의 것이다 — 리눅스 경로는 바이트 그대로, Windows 경로는 대소문자를 접어 견준다.
fn same_base(name: &[u8], requested: &str) -> bool {
    let wanted = paths::base(requested);
    if paths::windows_drive_path(requested) {
        return gostr::fold_eq(&gostr::chars(name), &wanted);
    }
    name == wanted.as_bytes()
}

/// 받을 수 있는 항목인가 — 모듈 머리의 규칙.
fn acceptable(h: &Header, requested: &str, size: u64) -> bool {
    matches!(h.typeflag, b'0' | 0)
        && h.linkname.is_empty()
        && same_base(&h.name, requested)
        && u64::try_from(h.size) == Ok(size)
        && safe_pax(&h.pax)
        && h.format != GNU
}

/// 아카이브에서 일반 파일 하나를 꺼내 `consume` 에 준다. `consume` 은 크기만큼 읽어야 한다.
pub(crate) fn consume_regular<R: Read>(
    reader: R,
    requested: &str,
    size: u64,
    consume: &mut dyn FnMut(&mut dyn Read, u64) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let mut tar = TarReader::new(reader);
    let header = match tar.next() {
        Ok(Some(h)) => h,
        Ok(None) => return Err(Failure::File(FileFailure::ArchiveFormat)),
        Err(e) => return Err(e.into_failure(FileFailure::ArchiveFormat)),
    };
    if !acceptable(&header, requested, size) {
        return Err(Failure::File(FileFailure::ArchiveMember));
    }
    let mut content = Counted {
        inner: tar.entry(),
        n: 0,
    };
    consume(&mut content, size)?;
    if content.n != size {
        return Err(Failure::File(FileFailure::ArchiveSize));
    }
    match tar.next() {
        Ok(None) => {}
        Ok(Some(_)) => return Err(Failure::File(FileFailure::ArchiveTrailing)),
        Err(e) => return Err(e.into_failure(FileFailure::ArchiveTrailing)),
    }
    zero_tail(tar.into_inner())
}

/// 끝 표시 뒤의 남은 바이트 — 0 만 올 수 있다.
fn zero_tail<R: Read>(mut r: R) -> Result<(), Failure> {
    let mut buf = vec![0u8; TAIL_CHUNK];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) if buf[..n].iter().all(|b| *b == 0) => {}
            Ok(_) => return Err(Failure::File(FileFailure::ArchiveAfterEnd)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(carried_or(e, FileFailure::ArchiveAfterEnd)),
        }
    }
}

/// 읽은 바이트를 센다.
struct Counted<R> {
    inner: R,
    n: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.n += n as u64;
        Ok(n)
    }
}

/// 읽은 내용의 오류를 까닭으로 — 잘린 내용은 아카이브의 꼴이 틀린 것이다.
pub(crate) fn content_failure(e: io::Error) -> Failure {
    carried_or(e, FileFailure::ArchiveFormat)
}

/// 바이트로 받은 아카이브에서 꺼낸다(스캐너 `extractRegular` — 시험이 쓴다).
#[cfg(test)]
pub(crate) fn extract_regular(data: &[u8], requested: &str, size: i64) -> Result<Vec<u8>, Failure> {
    let max_archive = (256u64 << 20) + (1 << 20);
    let size = u64::try_from(size).map_err(|_| Failure::File(FileFailure::BadRequest))?;
    if !paths::valid_file_path(requested) || size > 256 << 20 || data.len() as u64 > max_archive {
        return Err(Failure::File(FileFailure::BadRequest));
    }
    let mut out = Vec::new();
    consume_regular(data, requested, size, &mut |r, _| {
        r.read_to_end(&mut out).map(|_| ()).map_err(content_failure)
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests;
