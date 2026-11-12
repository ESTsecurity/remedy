//! zip 계열 아카이브(jar · war · ear · zip) 안을 읽는다 — `archive_entry` 의 수집기 (코어 1.11.0).
//!
//! # 왜 코어가 읽는가
//!
//! log4j 점검을 룰만으로 짜 보니(2026-11-12 · 101경우) YARA 는 **원본 바이트**만 보므로 —
//!
//! - 압축된 항목의 속이 보이지 않았다. shade 된 jar 의 `pom.properties`, 압축된 war 안의 jar 가 그렇다.
//!   이름이 다른 안쪽 jar 하나는 **놓쳤다**(깨끗함으로 나왔다).
//! - 본문을 스냅샷에 담아야 해서 상한(파일 8 MiB · 검사 64 MiB)에 걸렸다. 12 MiB Spring Boot jar 와 jar
//!   80개짜리 서버가 확인 필요로 끝났다.
//!
//! 이 수집기는 목록(중앙 디렉터리)과 **이름이 맞는 항목만** 읽고 풀어, 항목마다 좌표 · 크기 · 해시 · 작은 글자
//! 내용을 레코드로 낸다. 본문은 스냅샷에 담지 않는다. 무엇이 취약한지는 여기서 정하지 않는다 — 룰이 정한다.
//!
//! # 직접 쓴 해석기
//!
//! zip 크레이트가 yara-x 를 따라 이미 들어와 있지만 그 **쓰는 면을 넓히지 않는다** — 그 크레이트에 최근
//! 권고 셋이 있었다(설계-01 · 2026-11-02). 여기 필요한 것은 목록 읽기와 저장(0) · deflate(8) 두 방식뿐이고,
//! 풀기는 이미 쓰는 flate2 가 한다. 믿을 수 없는 입력이라 **모든 길이와 자리를 견주고**(`get` ·
//! `checked_*`) 깨진 것은 그 자리 레코드의 `error` 로 남긴다 — 검사를 멈추지 않는다.
//!
//! # `error` 의 값
//!
//! 언어와 무관한 짧은 낱말이다(스냅샷이 로케일마다 달라지지 않게) — `broken`(목록 · 머리가 깨졌다) ·
//! `encrypted` · `unsupported_method` · `too_large` · `too_many_entries` · `too_deep` · `changed`(걷기 뒤에
//! 바뀌었다) · `unreadable`(읽기 오류) · `budget`(검사 전체의 상한). 뒤에 `: ` 로 사람이 볼 까닭이 붙을 수
//! 있다. 룰은 `error exists` 나 `starts_with` 로 본다.

use remedy_artifacts::{ArchiveEntryRecord, Harvest};
use remedy_platform::read::FsRead;
use remedy_sdk::normalize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

/// 끝의 목록 표지(EOCD)를 찾을 꼬리 — 표지 22 바이트 + 주석 최대 65,535.
const TAIL: u64 = 22 + 0xFFFF;

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_END: u32 = 0x0605_4b50;
const SIG_END64: u32 = 0x0606_4b50;
const SIG_LOCATOR64: u32 = 0x0706_4b50;

/// 상한 — 검사를 몇 시간으로 늘리거나 메모리를 터뜨리는 아카이브(zip 폭탄)를 막는다.
///
/// 구조체인 이유는 **시험이 줄인 값으로 같은 길을 재기** 위해서다. 제품은 [`Limits::DEFAULT`] 하나다.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// 목록(중앙 디렉터리) 하나의 바이트.
    pub directory: u64,
    /// 아카이브 하나의 항목 수.
    pub entries: u64,
    /// 겹 — 1 이 디스크 파일 바로 안이다. ear → war → jar → jar 까지.
    pub depth: u32,
    /// 항목 하나를 풀어 드는 바이트 — 해시 · 안쪽 아카이브가 이 안에서만 된다.
    pub member: u64,
    /// `text` 로 싣는 바이트.
    pub text: usize,
    /// 검사 하나의 레코드 수. 넘으면 잘린다.
    pub records: usize,
    /// 검사 하나에서 읽고 푸는 바이트. 넘으면 잘린다.
    pub total: u64,
}

impl Limits {
    pub const DEFAULT: Limits = Limits {
        // 항목 30만 개에 이름이 평균 200 바이트여도 60 MB 다.
        directory: 64 * 1024 * 1024,
        entries: 300_000,
        depth: 4,
        // `file` 의 해시 상한(32 MiB)의 두 배 — 안쪽 war 가 그보다 크다.
        member: 64 * 1024 * 1024,
        text: 64 * 1024,
        // `file` 의 개수 상한과 같다.
        records: 500_000,
        // 풀기는 초당 수백 MB 다 — 이 상한이 검사 시간을 수십 초로 묶는다.
        total: 4 * 1024 * 1024 * 1024,
    };
}

/// 검사 하나가 쓴 몫.
#[derive(Debug, Default)]
pub(crate) struct Budget {
    bytes: u64,
}

impl Budget {
    fn take(&mut self, n: u64, limits: &Limits) -> bool {
        match self.bytes.checked_add(n) {
            Some(t) if t <= limits.total => {
                self.bytes = t;
                true
            }
            _ => false,
        }
    }
}

/// 바이트를 짚어 읽는 자리 — 디스크 파일이거나, 메모리에 든 본문 · 안쪽 아카이브.
trait Source {
    fn len(&self) -> u64;
    /// `offset` 에서 **정확히** `len` 바이트. 모자라면 오류다.
    fn read(&self, offset: u64, len: u64) -> Result<Cow<'_, [u8]>, String>;
}

struct Mem<'a>(&'a [u8]);

impl Source for Mem<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read(&self, offset: u64, len: u64) -> Result<Cow<'_, [u8]>, String> {
        let start = usize::try_from(offset).map_err(|_| "broken: offset".to_string())?;
        let n = usize::try_from(len).map_err(|_| "broken: length".to_string())?;
        start
            .checked_add(n)
            .and_then(|end| self.0.get(start..end))
            .map(Cow::Borrowed)
            .ok_or_else(|| format!("broken: {len} bytes at {offset} past the end"))
    }
}

/// 디스크 파일. 걷기가 본 길이와 지금 길이가 다르면 **바뀐 것**이다 — 섞어 읽지 않는다.
struct Disk<'a, P> {
    fs: &'a P,
    path: &'a str,
    len: u64,
}

impl<P: FsRead> Source for Disk<'_, P> {
    fn len(&self) -> u64 {
        self.len
    }
    fn read(&self, offset: u64, len: u64) -> Result<Cow<'_, [u8]>, String> {
        let n = usize::try_from(len).map_err(|_| "broken: length".to_string())?;
        let (total, bytes) = self
            .fs
            .read_range(self.path, offset, n)
            .map_err(|e| format!("unreadable: {e}"))?;
        if total != self.len {
            return Err(format!(
                "changed: {} bytes when walked, {total} now",
                self.len
            ));
        }
        if bytes.len() != n {
            return Err(format!("broken: {len} bytes at {offset} past the end"));
        }
        Ok(Cow::Owned(bytes))
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    let s = b.get(at..at.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

fn broken(what: &str) -> String {
    format!("broken: {what}")
}

/// 목록의 항목 하나.
#[derive(Debug, Clone)]
struct Member {
    /// 구분자를 `/` 로 고친 이름.
    name: String,
    flags: u16,
    method: u16,
    compressed: u64,
    size: u64,
    /// 항목 머리의 자리 — 앞에 붙은 바이트(실행 스크립트)만큼 이미 옮겼다.
    local: u64,
}

/// 목록을 읽은 결과. `None` 은 **zip 이 아니다** — 끝의 표지가 없고 zip 머리로 시작하지도 않는다.
fn directory(src: &dyn Source, limits: &Limits) -> Result<Option<Vec<Member>>, String> {
    let len = src.len();
    if len < 22 {
        return not_a_zip_or_cut_short(src);
    }
    let tail_len = TAIL.min(len);
    let tail_at = len - tail_len;
    let tail = src.read(tail_at, tail_len)?;
    // 뒤에서부터 — 주석 안에 표지 모양이 있어도 진짜 표지는 주석 앞이다. 주석 길이가 꼬리에 들어맞는 첫 것.
    let Some(end) = (0..=tail.len() - 22).rev().find(|&i| {
        u32_at(&tail, i) == Some(SIG_END)
            && u16_at(&tail, i + 20).is_some_and(|c| i + 22 + c as usize <= tail.len())
    }) else {
        return not_a_zip_or_cut_short(src);
    };
    let disk = u16_at(&tail, end + 4).ok_or_else(|| broken("end record"))?;
    let cd_disk = u16_at(&tail, end + 6).ok_or_else(|| broken("end record"))?;
    let mut count = u64::from(u16_at(&tail, end + 10).ok_or_else(|| broken("end record"))?);
    let mut cd_size = u64::from(u32_at(&tail, end + 12).ok_or_else(|| broken("end record"))?);
    let mut cd_at = u64::from(u32_at(&tail, end + 16).ok_or_else(|| broken("end record"))?);
    let end_abs = tail_at + end as u64;
    // 목록이 끝나는 자리 — 보통은 끝 표지, zip64 면 그 앞의 zip64 표지다.
    let mut cd_end = end_abs;
    if count == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_at == 0xFFFF_FFFF {
        let (n, size, at, z_abs) = zip64_end(src, end_abs)?;
        count = n;
        cd_size = size;
        cd_at = at;
        cd_end = z_abs;
    } else if disk != 0 || cd_disk != 0 {
        return Err(broken("split archive"));
    }
    if cd_size > limits.directory {
        return Err(format!(
            "too_large: directory {cd_size} bytes > {}",
            limits.directory
        ));
    }
    if count > limits.entries {
        return Err(format!("too_many_entries: {count} > {}", limits.entries));
    }
    // **앞에 붙은 바이트**(Spring Boot 의 실행 스크립트 · 자가 압축 해제)만큼 모든 자리가 밀려 있다.
    let cd_start = cd_end
        .checked_sub(cd_size)
        .ok_or_else(|| broken("directory larger than the file"))?;
    let shift = cd_start
        .checked_sub(cd_at)
        .ok_or_else(|| broken("directory offset past its place"))?;
    let cd = src.read(cd_start, cd_size)?;
    parse_directory(&cd, count, shift)
        .map(Some)
        .ok_or_else(|| broken("directory"))
}

/// 끝의 표지가 없을 때 — **zip 머리(`PK 03 04`)로 시작하면 잘리거나 깨진 아카이브**다.
///
/// 이름만 jar 인 글자 파일(옛 시험 r02 · r12 — 기대값 '깨끗함')은 아카이브가 아니라 아무것도 담지 않는다. 그러나
/// 머리가 zip 인데 끝이 없는 파일(옛 시험 r03 은 3분의 1 로 잘렸고 r13 은 끝 표지가 깨졌다)을 같이 넘기면 **못 본
/// 것이 깨끗함이 된다** — 그 안에 취약한 판이 있어도 그렇다. 그래서 `broken` 으로 남겨 룰이 확인 필요로 낸다.
fn not_a_zip_or_cut_short(src: &dyn Source) -> Result<Option<Vec<Member>>, String> {
    if src.len() >= 4 && src.read(0, 4)?.as_ref() == b"PK\x03\x04" {
        return Err(broken("no end record — cut short or damaged"));
    }
    Ok(None)
}

/// zip64 끝 표지 — 항목 수 · 목록 크기 · 자리 · 그 표지의 자리.
fn zip64_end(src: &dyn Source, end_abs: u64) -> Result<(u64, u64, u64, u64), String> {
    let loc_at = end_abs
        .checked_sub(20)
        .ok_or_else(|| broken("zip64 locator"))?;
    let loc = src.read(loc_at, 20)?;
    if u32_at(&loc, 0) != Some(SIG_LOCATOR64) {
        return Err(broken("zip64 locator"));
    }
    let recorded = u64_at(&loc, 8).ok_or_else(|| broken("zip64 locator"))?;
    // 적힌 자리를 먼저 본다. 앞에 붙은 바이트가 있으면 어긋나므로 **로케이터 바로 앞**(흔한 배치)을 본다.
    let candidates = [Some(recorded), loc_at.checked_sub(56)];
    for at in candidates.into_iter().flatten() {
        let Ok(r) = src.read(at, 56) else { continue };
        if u32_at(&r, 0) != Some(SIG_END64) {
            continue;
        }
        let n = u64_at(&r, 32).ok_or_else(|| broken("zip64 end"))?;
        let size = u64_at(&r, 40).ok_or_else(|| broken("zip64 end"))?;
        let cd = u64_at(&r, 48).ok_or_else(|| broken("zip64 end"))?;
        return Ok((n, size, cd, at));
    }
    Err(broken("zip64 end"))
}

fn parse_directory(cd: &[u8], count: u64, shift: u64) -> Option<Vec<Member>> {
    let mut out = Vec::with_capacity(count.min(65_536) as usize);
    let mut p = 0usize;
    for _ in 0..count {
        if u32_at(cd, p)? != SIG_CENTRAL {
            return None;
        }
        let flags = u16_at(cd, p + 8)?;
        let method = u16_at(cd, p + 10)?;
        let mut compressed = u64::from(u32_at(cd, p + 20)?);
        let mut size = u64::from(u32_at(cd, p + 24)?);
        let name_len = usize::from(u16_at(cd, p + 28)?);
        let extra_len = usize::from(u16_at(cd, p + 30)?);
        let comment_len = usize::from(u16_at(cd, p + 32)?);
        let mut local = u64::from(u32_at(cd, p + 42)?);
        let name_at = p.checked_add(46)?;
        let extra_at = name_at.checked_add(name_len)?;
        let next = extra_at.checked_add(extra_len)?.checked_add(comment_len)?;
        let name = cd.get(name_at..extra_at)?;
        let extra = cd.get(extra_at..extra_at + extra_len)?;
        if size == 0xFFFF_FFFF || compressed == 0xFFFF_FFFF || local == 0xFFFF_FFFF {
            zip64_extra(extra, &mut size, &mut compressed, &mut local)?;
        }
        p = next;
        // 이름은 UTF-8 로 읽는다(jar 는 그렇게 쓴다). 구분자를 `\` 로 적는 도구가 있다.
        let name = String::from_utf8_lossy(name).replace('\\', "/");
        if name.ends_with('/') {
            continue; // 폴더
        }
        out.push(Member {
            name,
            flags,
            method,
            compressed,
            size,
            local: local.checked_add(shift)?,
        });
    }
    Some(out)
}

/// zip64 여분 칸(0x0001) — 32비트 칸이 가득 찬 것만 **그 순서대로** 들어 있다(APPNOTE 4.5.3).
fn zip64_extra(extra: &[u8], size: &mut u64, compressed: &mut u64, local: &mut u64) -> Option<()> {
    let mut p = 0usize;
    while p + 4 <= extra.len() {
        let id = u16_at(extra, p)?;
        let len = usize::from(u16_at(extra, p + 2)?);
        let body = extra.get(p + 4..p + 4 + len)?;
        if id == 0x0001 {
            let mut q = 0usize;
            for v in [size, compressed, local] {
                if *v == 0xFFFF_FFFF {
                    *v = u64_at(body, q)?;
                    q += 8;
                }
            }
            return Some(());
        }
        p += 4 + len;
    }
    None
}

/// 항목 하나를 푼다.
fn member_bytes(
    src: &dyn Source,
    m: &Member,
    limits: &Limits,
    budget: &mut Budget,
) -> Result<Vec<u8>, String> {
    if m.flags & 1 != 0 {
        return Err("encrypted".into());
    }
    if m.size > limits.member {
        return Err(format!("too_large: {} bytes > {}", m.size, limits.member));
    }
    let head = src.read(m.local, 30)?;
    if u32_at(&head, 0) != Some(SIG_LOCAL) {
        return Err(broken("member header"));
    }
    let name_len = u64::from(u16_at(&head, 26).ok_or_else(|| broken("member header"))?);
    let extra_len = u64::from(u16_at(&head, 28).ok_or_else(|| broken("member header"))?);
    // 자리는 믿을 수 없는 값이다 — 끝을 넘는 덧셈이 시험 빌드에서 멈추지 않게 견준다.
    let data_at = m
        .local
        .checked_add(30 + name_len + extra_len)
        .ok_or_else(|| broken("member offset"))?;
    match m.method {
        0 => {
            if m.compressed != m.size {
                return Err(broken("stored sizes differ"));
            }
            if !budget.take(m.size, limits) {
                return Err("budget".into());
            }
            Ok(src.read(data_at, m.size)?.into_owned())
        }
        8 => {
            // 압축이 크기를 늘린 항목도 있다(이미 압축된 jar) — 그래도 풀린 크기의 두 배를 넘지는 않는다.
            if m.compressed > limits.member.saturating_mul(2) {
                return Err(format!(
                    "too_large: {} compressed bytes > {}",
                    m.compressed,
                    limits.member.saturating_mul(2)
                ));
            }
            if !budget.take(m.compressed.saturating_add(m.size), limits) {
                return Err("budget".into());
            }
            let data = src.read(data_at, m.compressed)?;
            inflate(&data, m.size)
        }
        other => Err(format!("unsupported_method: {other}")),
    }
}

/// deflate 를 푼다 — **목록의 크기를 넘어 풀지 않는다**(폭탄). 크기가 다르면 깨진 것이다.
fn inflate(data: &[u8], expect: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut out = Vec::with_capacity(expect.min(16 * 1024 * 1024) as usize);
    flate2::read::DeflateDecoder::new(data)
        .take(expect.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| broken(&format!("deflate: {e}")))?;
    if out.len() as u64 != expect {
        return Err(broken(&format!(
            "inflated {} bytes, the directory says {expect}",
            out.len()
        )));
    }
    Ok(out)
}

/// zip 의 첫 표지로 시작하는가 — 안쪽 항목을 아카이브로 열지 정한다.
fn looks_like_zip(b: &[u8]) -> bool {
    b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06")
}

fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// 디스크의 파일 하나를 연다. zip 이 아니면 아무것도 담지 않는다.
///
/// `body` 는 `file` 이 해시하려고 이미 든 본문이다(32 MiB 이하) — 있으면 다시 읽지 않는다. 없으면 목록과
/// 필요한 항목만 짚어 읽는다(`read_range`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn inspect_file<P: FsRead>(
    fs: &P,
    path: &str,
    size: u64,
    body: Option<&[u8]>,
    patterns: &[String],
    limits: &Limits,
    budget: &mut Budget,
    h: &mut Harvest<ArchiveEntryRecord>,
) {
    let disk = Disk {
        fs,
        path,
        len: size,
    };
    let mem;
    let src: &dyn Source = match body {
        Some(b) => {
            mem = Mem(b);
            &mem
        }
        None => &disk,
    };
    match directory(src, limits) {
        Ok(None) => {}
        Ok(Some(members)) => walk(src, &members, path, "", 1, patterns, limits, budget, h),
        // 아카이브 자체를 못 읽었다 — 그 사실이 레코드로 남아야 룰이 *"끝까지 못 봤다"* 고 말한다.
        Err(why) => h.records.push(ArchiveEntryRecord {
            archive: path.to_string(),
            path: String::new(),
            name: String::new(),
            depth: 0,
            size,
            sha256: None,
            text: None,
            error: Some(why),
        }),
    }
}

/// 아카이브 하나의 항목들 — `depth` 는 이 항목들의 겹이다.
#[allow(clippy::too_many_arguments)]
fn walk(
    src: &dyn Source,
    members: &[Member],
    archive: &str,
    prefix: &str,
    depth: u32,
    patterns: &[String],
    limits: &Limits,
    budget: &mut Budget,
    h: &mut Harvest<ArchiveEntryRecord>,
) {
    for m in members {
        let name = leaf(&m.name);
        // 대소문자를 가리지 않는다 — `Log4j-Core-2.14.1.Jar` 로 넣은 앱이 있다(옛 시험 g6).
        if !normalize::name_in(patterns, name) {
            continue;
        }
        if h.records.len() >= limits.records {
            h.truncated = true;
            return;
        }
        let path = format!("{prefix}{}", m.name);
        let mut rec = ArchiveEntryRecord {
            archive: archive.to_string(),
            path: path.clone(),
            name: name.to_string(),
            depth,
            size: m.size,
            sha256: None,
            text: None,
            error: None,
        };
        let mut nested: Option<(Vec<u8>, Vec<Member>)> = None;
        match member_bytes(src, m, limits, budget) {
            Ok(bytes) => {
                rec.sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
                if bytes.len() <= limits.text && !bytes.contains(&0) {
                    if let Ok(t) = std::str::from_utf8(&bytes) {
                        rec.text = Some(t.to_string());
                    }
                }
                if looks_like_zip(&bytes) {
                    if depth >= limits.depth {
                        rec.error = Some(format!("too_deep: more than {} levels", limits.depth));
                    } else {
                        // 목록을 먼저 다 읽는다 — 본문을 안쪽 걷기로 넘기기 전에 빌림이 끝나야 한다.
                        let parsed = directory(&Mem(&bytes), limits);
                        match parsed {
                            Ok(Some(inner)) => nested = Some((bytes, inner)),
                            Ok(None) => {}
                            Err(why) => rec.error = Some(why),
                        }
                    }
                }
            }
            Err(why) => {
                // 검사 전체의 몫이 다했다 — 그 뒤는 보지 않은 것이라 잘림이다.
                if why == "budget" {
                    h.truncated = true;
                }
                rec.error = Some(why);
            }
        }
        h.records.push(rec);
        if let Some((bytes, inner)) = nested {
            let inner_prefix = format!("{path}!/");
            walk(
                &Mem(&bytes),
                &inner,
                archive,
                &inner_prefix,
                depth + 1,
                patterns,
                limits,
                budget,
                h,
            );
        }
        if h.truncated {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 시험용 zip — `(이름, 내용, 방식, 플래그)`. CRC 는 0 이다(이 해석기는 CRC 를 보지 않는다).
    fn zip_with(prefix: &[u8], entries: &[(&str, &[u8], u16, u16)]) -> Vec<u8> {
        let mut out = prefix.to_vec();
        let mut cd = Vec::new();
        for (name, data, method, flags) in entries {
            let payload = match *method {
                8 => deflate(data),
                _ => data.to_vec(),
            };
            let local = (out.len() - prefix.len()) as u32;
            out.extend(SIG_LOCAL.to_le_bytes());
            out.extend(20u16.to_le_bytes());
            out.extend(flags.to_le_bytes());
            out.extend(method.to_le_bytes());
            out.extend([0u8; 8]); // 시각 · CRC
            out.extend((payload.len() as u32).to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(name.as_bytes());
            out.extend(&payload);
            cd.extend(SIG_CENTRAL.to_le_bytes());
            cd.extend(20u16.to_le_bytes());
            cd.extend(20u16.to_le_bytes());
            cd.extend(flags.to_le_bytes());
            cd.extend(method.to_le_bytes());
            cd.extend([0u8; 8]);
            cd.extend((payload.len() as u32).to_le_bytes());
            cd.extend((data.len() as u32).to_le_bytes());
            cd.extend((name.len() as u16).to_le_bytes());
            cd.extend([0u8; 12]); // 여분 · 주석 · 디스크 · 속성
            cd.extend(local.to_le_bytes());
            cd.extend(name.as_bytes());
        }
        // 실행 스크립트가 붙은 jar 처럼, 적힌 자리는 앞에 붙은 바이트를 모른다.
        let cd_at = (out.len() - prefix.len()) as u32;
        out.extend(&cd);
        out.extend(SIG_END.to_le_bytes());
        out.extend([0u8; 4]);
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend((cd.len() as u32).to_le_bytes());
        out.extend(cd_at.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out
    }

    fn zip(entries: &[(&str, &[u8], u16)]) -> Vec<u8> {
        let e: Vec<_> = entries.iter().map(|(n, d, m)| (*n, *d, *m, 0u16)).collect();
        zip_with(b"", &e)
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// 메모리의 아카이브를 디스크 파일인 것처럼 연다 — `body` 를 준 길.
    fn records(bytes: &[u8], patterns: &[&str], limits: Limits) -> Harvest<ArchiveEntryRecord> {
        let mut h = Harvest::default();
        let pats: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        let fs = NoFs;
        inspect_file(
            &fs,
            "/srv/app.war",
            bytes.len() as u64,
            Some(bytes),
            &pats,
            &limits,
            &mut Budget::default(),
            &mut h,
        );
        h
    }

    /// 본문을 준 길은 디스크를 읽지 않는다 — 읽으면 시험이 실패한다.
    struct NoFs;
    impl FsRead for NoFs {
        fn walk(
            &self,
            _: &str,
            _: usize,
        ) -> Result<remedy_platform::read::WalkResult, remedy_platform::PlatformError> {
            unreachable!("걷지 않는다")
        }
        fn read_file(
            &self,
            _: &str,
            _: u64,
        ) -> Result<Option<Vec<u8>>, remedy_platform::PlatformError> {
            panic!("본문을 줬는데 디스크를 읽었다")
        }
        fn look(&self, _: &str) -> remedy_platform::read::Seen {
            remedy_platform::read::Seen::Absent
        }
    }

    const POM: &[u8] = b"artifactId=log4j-core\ngroupId=org.apache.logging.log4j\nversion=2.14.1\n";
    const POM_PATH: &str = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties";

    #[test]
    fn only_members_with_a_matching_leaf_name_become_records_with_hash_and_text() {
        let jar = zip(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", 8),
            (POM_PATH, POM, 8),
            (
                "org/apache/logging/log4j/core/lookup/JndiLookup.class",
                b"\xca\xfe\xba\xbe\0\0",
                0,
            ),
            ("a/B.class", b"\xca\xfe", 0),
        ]);
        let h = records(
            &jar,
            &["pom.properties", "jndilookup.class"],
            Limits::DEFAULT,
        );
        assert!(!h.truncated);
        let names: Vec<_> = h.records.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["pom.properties", "JndiLookup.class"], "{h:?}");
        let pom = &h.records[0];
        assert_eq!(pom.archive, "/srv/app.war");
        assert_eq!(pom.path, POM_PATH);
        assert_eq!(pom.depth, 1);
        assert_eq!(pom.size, POM.len() as u64);
        assert_eq!(pom.text.as_deref(), Some(std::str::from_utf8(POM).unwrap()));
        assert_eq!(
            pom.sha256.as_deref(),
            Some(format!("{:x}", Sha256::digest(POM)).as_str())
        );
        // NUL 이 든 항목은 글자가 아니다 — 해시만 있다.
        assert!(h.records[1].text.is_none() && h.records[1].sha256.is_some());
    }

    #[test]
    fn nested_archives_are_opened_through_deflate_and_their_paths_are_joined() {
        // 실측의 놓침(r15): 압축된 war 안에 이름이 다른 log4j-core — 원본 바이트로는 아무것도 안 보였다.
        let core = zip(&[(POM_PATH, POM, 8)]);
        let war = zip(&[
            ("WEB-INF/web.xml", b"<web-app/>", 8),
            ("WEB-INF/lib/logging-lib.jar", &core, 8),
        ]);
        let ear = zip(&[("web/app.war", &war, 8)]);
        let h = records(&ear, &["*.war", "*.jar", "pom.properties"], Limits::DEFAULT);
        let got: Vec<_> = h
            .records
            .iter()
            .map(|r| (r.depth, r.path.as_str()))
            .collect();
        let pom = format!("web/app.war!/WEB-INF/lib/logging-lib.jar!/{POM_PATH}");
        assert_eq!(
            got,
            [
                (1, "web/app.war"),
                (2, "web/app.war!/WEB-INF/lib/logging-lib.jar"),
                (3, pom.as_str()),
            ],
            "{h:?}"
        );
        assert!(h.records[2]
            .text
            .as_deref()
            .unwrap()
            .contains("version=2.14.1"));
        // 안쪽 jar 의 해시는 그 jar 의 바이트 — 이름을 바꿔도 공식 빌드를 알아본다.
        assert_eq!(
            h.records[1].sha256.as_deref(),
            Some(format!("{:x}", Sha256::digest(&core)).as_str())
        );
    }

    #[test]
    fn a_launch_script_in_front_shifts_every_offset() {
        // Spring Boot 의 '완전 실행 가능' jar 는 셸 스크립트로 시작한다. 적힌 자리는 그것을 모른다.
        let e = [(POM_PATH, POM, 8u16, 0u16)];
        let jar = zip_with(b"#!/bin/bash\necho launch\nexit 0\n", &e);
        let h = records(&jar, &["pom.properties"], Limits::DEFAULT);
        assert_eq!(h.records.len(), 1, "{h:?}");
        assert!(h.records[0].error.is_none(), "{h:?}");
        assert!(h.records[0].text.is_some());
    }

    #[test]
    fn a_file_that_is_not_a_zip_gives_nothing() {
        // 옛 시험 r02 · r12 — 이름만 jar 인 글자 파일은 아카이브가 아니다(깨끗함이 기대값).
        for b in [&b""[..], b"x", b"this is not a zip but is named app.jar"] {
            let h = records(b, &["*"], Limits::DEFAULT);
            assert!(h.records.is_empty() && !h.truncated, "{b:?}: {h:?}");
        }
    }

    #[test]
    fn a_zip_cut_short_or_with_a_damaged_end_says_so_instead_of_nothing() {
        // 옛 시험 r03(3분의 1 로 자름) · r13(끝 40 바이트를 뒤집음)의 꼴. zip 머리로 시작하니 아카이브이고,
        // 끝까지 못 읽었다는 사실이 레코드로 남아야 한다 — 남지 않으면 그 안의 취약한 판이 깨끗함이 된다.
        let jar = zip(&[(POM_PATH, POM, 8), ("a/b/c.class", &[b'X'; 5000], 0)]);
        let cut = &jar[..jar.len() / 3];
        let mut damaged = jar.clone();
        let n = damaged.len();
        for b in &mut damaged[n - 60..n - 20] {
            *b ^= 0xFF;
        }
        for (what, bytes) in [("cut", cut), ("damaged", &damaged[..])] {
            let h = records(bytes, &["*"], Limits::DEFAULT);
            assert_eq!(h.records.len(), 1, "{what}: {h:?}");
            let r = &h.records[0];
            assert_eq!((r.path.as_str(), r.depth), ("", 0), "{what}");
            assert!(
                r.error.as_deref().unwrap().starts_with("broken"),
                "{what}: {r:?}"
            );
        }
    }

    #[test]
    fn a_broken_directory_is_one_error_record_for_the_archive() {
        let mut jar = zip(&[(POM_PATH, POM, 8)]);
        // 항목 수를 늘려 목록이 중간에 끊긴 것처럼 만든다.
        let end = jar.len() - 22;
        jar[end + 8..end + 12].copy_from_slice(&[5, 0, 5, 0]);
        let h = records(&jar, &["*"], Limits::DEFAULT);
        assert_eq!(h.records.len(), 1, "{h:?}");
        let r = &h.records[0];
        assert_eq!((r.path.as_str(), r.depth), ("", 0));
        assert!(r.error.as_deref().unwrap().starts_with("broken"), "{r:?}");
    }

    #[test]
    fn encrypted_unsupported_and_oversized_members_say_why_and_keep_their_place() {
        let jar = zip_with(
            b"",
            &[
                ("a/secret.properties", b"k=v", 0, 1),
                ("a/bz.properties", b"k=v", 12, 0),
                ("a/big.properties", &[b'x'; 2048], 0, 0),
            ],
        );
        let limits = Limits {
            member: 1024,
            ..Limits::DEFAULT
        };
        let h = records(&jar, &["*.properties"], limits);
        let errs: Vec<_> = h
            .records
            .iter()
            .map(|r| r.error.clone().unwrap_or_default())
            .collect();
        assert!(errs[0].starts_with("encrypted"), "{errs:?}");
        assert!(errs[1].starts_with("unsupported_method"), "{errs:?}");
        assert!(errs[2].starts_with("too_large"), "{errs:?}");
        assert!(h.records.iter().all(|r| r.sha256.is_none()));
    }

    #[test]
    fn nesting_stops_at_the_depth_limit_and_says_so() {
        let inner = zip(&[(POM_PATH, POM, 8)]);
        let mid = zip(&[("lib/a.jar", &inner, 0)]);
        let outer = zip(&[("lib/b.jar", &mid, 0)]);
        let limits = Limits {
            depth: 2,
            ..Limits::DEFAULT
        };
        let h = records(&outer, &["*.jar", "pom.properties"], limits);
        let got: Vec<_> = h
            .records
            .iter()
            .map(|r| (r.depth, r.error.is_some()))
            .collect();
        // 1겹 b.jar 은 열리고, 2겹 a.jar 은 상한이라 열지 않는다 — pom 은 보지 못했다고 말한다.
        assert_eq!(got, [(1, false), (2, true)], "{h:?}");
        assert!(h.records[1]
            .error
            .as_deref()
            .unwrap()
            .starts_with("too_deep"));
    }

    #[test]
    fn backslash_names_are_written_with_slashes() {
        let jar = zip(&[("WEB-INF\\lib\\log4j-core-2.14.1.jar", b"x", 0)]);
        let h = records(&jar, &["*.JAR"], Limits::DEFAULT);
        assert_eq!(h.records[0].path, "WEB-INF/lib/log4j-core-2.14.1.jar");
        assert_eq!(h.records[0].name, "log4j-core-2.14.1.jar");
    }

    #[test]
    fn the_record_and_byte_budgets_truncate() {
        let jar = zip(&[("a.txt", b"1", 0), ("b.txt", b"2", 0), ("c.txt", b"3", 0)]);
        let h = records(
            &jar,
            &["*.txt"],
            Limits {
                records: 2,
                ..Limits::DEFAULT
            },
        );
        assert_eq!(h.records.len(), 2);
        assert!(h.truncated, "레코드 상한에 닿았는데 잘림이 없다");

        let h = records(
            &jar,
            &["*.txt"],
            Limits {
                total: 2,
                ..Limits::DEFAULT
            },
        );
        assert!(h.truncated, "바이트 몫이 다했는데 잘림이 없다");
        assert_eq!(h.records.last().unwrap().error.as_deref(), Some("budget"));
    }

    #[test]
    fn zip64_end_records_are_followed() {
        // 항목 수 칸을 0xFFFF 로 두고 zip64 끝 표지 · 로케이터를 넣는다.
        let mut jar = zip(&[(POM_PATH, POM, 8)]);
        let end = jar.len() - 22;
        let cd_size = u64::from(u32_at(&jar, end + 12).unwrap());
        let cd_at = u64::from(u32_at(&jar, end + 16).unwrap());
        jar.truncate(end);
        let z_at = jar.len() as u64;
        jar.extend(SIG_END64.to_le_bytes());
        jar.extend(44u64.to_le_bytes());
        jar.extend([45, 0, 45, 0]);
        jar.extend([0u8; 8]);
        jar.extend(1u64.to_le_bytes());
        jar.extend(1u64.to_le_bytes());
        jar.extend(cd_size.to_le_bytes());
        jar.extend(cd_at.to_le_bytes());
        jar.extend(SIG_LOCATOR64.to_le_bytes());
        jar.extend(0u32.to_le_bytes());
        jar.extend(z_at.to_le_bytes());
        jar.extend(1u32.to_le_bytes());
        jar.extend(SIG_END.to_le_bytes());
        jar.extend([0u8; 4]);
        jar.extend([0xFF, 0xFF, 0xFF, 0xFF]);
        jar.extend(0xFFFF_FFFFu32.to_le_bytes());
        jar.extend(0xFFFF_FFFFu32.to_le_bytes());
        jar.extend(0u16.to_le_bytes());
        let h = records(&jar, &["pom.properties"], Limits::DEFAULT);
        assert_eq!(h.records.len(), 1, "{h:?}");
        assert!(h.records[0].error.is_none(), "{h:?}");
    }

    #[test]
    fn a_file_read_from_disk_reads_only_its_ranges_and_notices_a_change() {
        use std::cell::RefCell;
        struct Ranged(Vec<u8>, RefCell<Vec<(u64, usize)>>, u64);
        impl FsRead for Ranged {
            fn walk(
                &self,
                _: &str,
                _: usize,
            ) -> Result<remedy_platform::read::WalkResult, remedy_platform::PlatformError>
            {
                unreachable!()
            }
            fn read_file(
                &self,
                _: &str,
                _: u64,
            ) -> Result<Option<Vec<u8>>, remedy_platform::PlatformError> {
                panic!("통째로 읽었다")
            }
            fn read_range(
                &self,
                _: &str,
                offset: u64,
                len: usize,
            ) -> Result<(u64, Vec<u8>), remedy_platform::PlatformError> {
                self.1.borrow_mut().push((offset, len));
                let s = (offset as usize).min(self.0.len());
                let e = (s + len).min(self.0.len());
                Ok((self.2, self.0[s..e].to_vec()))
            }
            fn look(&self, _: &str) -> remedy_platform::read::Seen {
                remedy_platform::read::Seen::Present
            }
        }
        let filler = vec![7u8; 300_000];
        let jar = zip(&[("big.bin", &filler, 0), (POM_PATH, POM, 8)]);
        let fs = Ranged(jar.clone(), RefCell::new(Vec::new()), jar.len() as u64);
        let mut h = Harvest::default();
        let pats = vec!["pom.properties".to_string()];
        inspect_file(
            &fs,
            "/srv/a.jar",
            jar.len() as u64,
            None,
            &pats,
            &Limits::DEFAULT,
            &mut Budget::default(),
            &mut h,
        );
        assert_eq!(h.records.len(), 1, "{h:?}");
        assert!(h.records[0].text.is_some());
        let read: usize = fs.1.borrow().iter().map(|(_, n)| n).sum();
        assert!(read < filler.len(), "맞지 않는 큰 항목까지 읽었다: {read}");

        // 걷기 뒤에 길이가 바뀌었다 — 섞어 읽지 않고 그렇다고 말한다.
        let fs = Ranged(jar.clone(), RefCell::new(Vec::new()), jar.len() as u64 + 1);
        let mut h = Harvest::default();
        inspect_file(
            &fs,
            "/srv/a.jar",
            jar.len() as u64,
            None,
            &pats,
            &Limits::DEFAULT,
            &mut Budget::default(),
            &mut h,
        );
        assert_eq!(h.records.len(), 1, "{h:?}");
        assert!(
            h.records[0]
                .error
                .as_deref()
                .unwrap()
                .starts_with("changed"),
            "{h:?}"
        );
    }
}
