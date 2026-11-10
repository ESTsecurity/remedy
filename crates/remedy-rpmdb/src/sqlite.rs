//! RPM 의 SQLite DB(`rpmdb.sqlite` — RHEL 9 · Fedora 계열) — 표 `Packages` 의 `blob` 열만 꺼낸다.
//!
//! # SQLite 를 링크하지 않는다
//!
//! C 라이브러리를 들이면 정적 배포 빌드가 C 툴체인에 기댄다. 쓰는 것은 공개된 파일 형식
//! (sqlite.org/fileformat2.html)의 작은 부분이다 — 첫 쪽의 스키마 표에서 `Packages` 의 뿌리 쪽을 찾고,
//! 그 **표 B-트리**를 걸어 기록마다 둘째 열(헤더 블롭)을 꺼낸다. 쓰지 않는다. WAL 은 읽지 않는다 —
//! 비어 있지 않으면 부르는 쪽이 *잘렸다* 로 말한다.
//!
//! rpm 의 표: `CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)` —
//! `hnum` 은 rowid 라 기록에는 NULL 로 담기고, 블롭이 둘째 열이다(실측 · Rocky 9).

use super::{Copies, Limits, Read, RpmDbError, COPIED};
use std::collections::HashSet;

const MAGIC: &[u8; 16] = b"SQLite format 3\0";
const LEAF_TABLE: u8 = 0x0D;
const INTERIOR_TABLE: u8 = 0x05;
/// 기록 하나의 상한 — rpm 헤더 블롭은 크게 잡아도 수 MiB 다.
const MAX_RECORD: u64 = 64 * 1024 * 1024;
/// 기록 수 상한.
const MAX_RECORDS: usize = 200_000;
/// 이 기계의 DB 를 읽을 때([`blobs`])의 상한 — 복사한 양은 보지 않는다.
const TRUSTED: Limits = Limits {
    record: MAX_RECORD,
    records: MAX_RECORDS,
    copied: u64::MAX,
};

struct Db<'a> {
    bytes: &'a [u8],
    page_size: usize,
    usable: usize,
    pages: u32,
    limits: Limits,
    /// 스키마 표와 `Packages` 의 페이로드를 함께 센다.
    copies: Copies,
}

impl<'a> Db<'a> {
    fn new(bytes: &'a [u8], limits: Limits) -> Result<Self, RpmDbError> {
        if bytes.len() < 100 || &bytes[..16] != MAGIC {
            return Err(RpmDbError::Format("SQLite 머리가 아니다"));
        }
        let raw = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
        let page_size = if raw == 1 { 65536 } else { raw };
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(RpmDbError::Format("SQLite 쪽 크기가 틀렸다"));
        }
        let usable = page_size - bytes[20] as usize;
        if usable < 480 {
            return Err(RpmDbError::Format(
                "SQLite 의 쓸 수 있는 쪽 크기가 너무 작다",
            ));
        }
        let pages = u32::try_from(bytes.len() / page_size).unwrap_or(u32::MAX);
        Ok(Self {
            bytes,
            page_size,
            usable,
            pages,
            limits,
            copies: Copies::new(limits.copied),
        })
    }

    fn page(&self, pgno: u32) -> Result<&'a [u8], RpmDbError> {
        if pgno == 0 || pgno > self.pages {
            return Err(RpmDbError::Format("SQLite 쪽 번호가 파일 밖이다"));
        }
        let start = (pgno as usize - 1) * self.page_size;
        Ok(&self.bytes[start..start + self.page_size])
    }

    /// 표 B-트리의 기록(페이로드 전체)을 rowid 차례로 모은다. 복사한 양이 상한에 닿으면 그 앞까지다.
    fn table(&self, root: u32) -> Result<Read, RpmDbError> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut stack = vec![root];
        while let Some(pgno) = stack.pop() {
            if !seen.insert(pgno) {
                return Err(RpmDbError::Format("SQLite B-트리에 고리가 있다"));
            }
            let page = self.page(pgno)?;
            let h = if pgno == 1 { 100 } else { 0 };
            let flag = *page.get(h).ok_or(RpmDbError::Format("쪽 머리가 없다"))?;
            let cells = be16(page, h + 3)? as usize;
            match flag {
                LEAF_TABLE => {
                    for i in 0..cells {
                        let at = be16(page, h + 8 + 2 * i)? as usize;
                        match self.leaf_payload(page, at) {
                            Ok(p) => out.push(p),
                            Err(e) if e == COPIED => return Ok((out, Some(e))),
                            Err(e) => return Err(e),
                        }
                        if out.len() > self.limits.records {
                            return Err(RpmDbError::Limit("SQLite 기록이 상한을 넘었다"));
                        }
                    }
                }
                INTERIOR_TABLE => {
                    // 오른쪽 끝을 먼저 넣어 왼쪽부터 꺼낸다 — rowid 차례가 그대로 남는다.
                    stack.push(be32(page, h + 8)?);
                    for i in (0..cells).rev() {
                        let at = be16(page, h + 12 + 2 * i)? as usize;
                        stack.push(be32(page, at)?);
                    }
                }
                _ => return Err(RpmDbError::Format("표 B-트리가 아닌 쪽이다")),
            }
        }
        Ok((out, None))
    }

    /// 잎 쪽의 셀 하나 — 페이로드 길이 · rowid · 페이로드(넘치면 넘침 쪽 사슬).
    fn leaf_payload(&self, page: &[u8], at: usize) -> Result<Vec<u8>, RpmDbError> {
        let (total, n1) = varint(page, at).ok_or(RpmDbError::Format("셀 길이를 읽지 못했다"))?;
        let (_rowid, n2) =
            varint(page, at + n1).ok_or(RpmDbError::Format("rowid 를 읽지 못했다"))?;
        if total > self.limits.record {
            return Err(RpmDbError::Limit("SQLite 기록 하나가 상한을 넘었다"));
        }
        let start = at + n1 + n2;
        let local = self.local_size(total as usize);
        let first = page
            .get(start..start + local)
            .ok_or(RpmDbError::Format("셀이 쪽 밖으로 나간다"))?;
        // 셀 여럿이 같은 넘침 사슬을 가리킬 수 있다 — 그때마다 복사하므로 복사하기 전에 센다.
        self.copies.take(total)?;
        let total = total as usize;
        let mut out = first.to_vec();
        if local < total {
            let mut next = be32(page, start + local)?;
            let mut hops = 0u32;
            while out.len() < total {
                hops += 1;
                if next == 0 || hops > self.pages {
                    return Err(RpmDbError::Format("넘침 쪽 사슬이 끊겼다"));
                }
                let ov = self.page(next)?;
                let take = (total - out.len()).min(self.usable - 4);
                out.extend_from_slice(
                    ov.get(4..4 + take)
                        .ok_or(RpmDbError::Format("넘침 쪽이 짧다"))?,
                );
                next = be32(ov, 0)?;
            }
        }
        Ok(out)
    }

    /// 표 잎 셀이 쪽 안에 두는 몫 (파일 형식 §B-트리 페이로드).
    fn local_size(&self, p: usize) -> usize {
        let u = self.usable;
        let x = u - 35;
        if p <= x {
            return p;
        }
        let m = ((u - 12) * 32 / 255) - 23;
        let k = m + ((p - m) % (u - 4));
        if k <= x {
            k
        } else {
            m
        }
    }
}

/// 기록의 한 열.
enum Value<'a> {
    Null,
    Int(i64),
    Bytes(&'a [u8]),
    Other,
}

/// 기록(머리 + 몸)의 `idx` 번째 열.
fn column(rec: &[u8], idx: usize) -> Option<Value<'_>> {
    let (hlen, n) = varint(rec, 0)?;
    let hlen = usize::try_from(hlen).ok()?;
    let mut at = n;
    let mut body = hlen;
    let mut col = 0usize;
    while at < hlen {
        let (st, k) = varint(rec, at)?;
        at += k;
        let size = match st {
            0 | 8 | 9 => 0,
            1 => 1,
            2 => 2,
            3 => 3,
            4 => 4,
            5 => 6,
            6 | 7 => 8,
            10 | 11 => return None,
            n => ((n - 12) / 2) as usize,
        };
        if col == idx {
            let bytes = rec.get(body..body.checked_add(size)?)?;
            return Some(match st {
                0 => Value::Null,
                8 => Value::Int(0),
                9 => Value::Int(1),
                1..=6 => {
                    let mut v: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
                    for b in bytes {
                        v = (v << 8) | *b as i64;
                    }
                    Value::Int(v)
                }
                n if n >= 12 => Value::Bytes(bytes),
                _ => Value::Other,
            });
        }
        body += size;
        col += 1;
    }
    None
}

/// SQLite 의 가변 길이 정수 — 1~9 바이트, 큰 쪽이 먼저.
fn varint(b: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for i in 0..9 {
        let byte = *b.get(at + i)?;
        if i == 8 {
            return Some(((v << 8) | byte as u64, 9));
        }
        v = (v << 7) | (byte & 0x7F) as u64;
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

fn be16(b: &[u8], at: usize) -> Result<u16, RpmDbError> {
    b.get(at..at + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or(RpmDbError::Format("쪽이 짧다"))
}

fn be32(b: &[u8], at: usize) -> Result<u32, RpmDbError> {
    b.get(at..at + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(RpmDbError::Format("쪽이 짧다"))
}

/// `Packages` 표의 헤더 블롭 전부 — 이 기계의 DB.
pub fn blobs(bytes: &[u8]) -> Result<Vec<Vec<u8>>, RpmDbError> {
    let (out, stop) = read(bytes, TRUSTED)?;
    stop.map_or(Ok(out), Err)
}

/// `Packages` 표의 헤더 블롭을 `limits` 안에서. 복사한 양이 상한에 닿으면 그 앞의 블롭과 [`COPIED`] 다 — 스키마
/// 표에서 닿으면 블롭이 없다. 블롭은 페이로드에서 한 번 더 복사하지만 센 것은 페이로드다(그것이 더 크다).
pub(crate) fn read(bytes: &[u8], limits: Limits) -> Result<Read, RpmDbError> {
    let db = Db::new(bytes, limits)?;
    // 스키마 표(첫 쪽): type · name · tbl_name · rootpage · sql.
    let (schema, stop) = db.table(1)?;
    if stop.is_some() {
        return Ok((Vec::new(), stop));
    }
    let mut root = None;
    for rec in schema {
        let is_table = matches!(column(&rec, 0), Some(Value::Bytes(b"table")));
        let named = matches!(column(&rec, 1), Some(Value::Bytes(b"Packages")));
        if is_table && named {
            if let Some(Value::Int(r)) = column(&rec, 3) {
                root = u32::try_from(r).ok();
            }
        }
    }
    let root = root.ok_or(RpmDbError::Format("Packages 표가 없다"))?;
    let (records, stop) = db.table(root)?;
    let mut out = Vec::new();
    for rec in records {
        match column(&rec, 1) {
            Some(Value::Bytes(b)) => out.push(b.to_vec()),
            Some(Value::Null) | Some(Value::Int(_)) | Some(Value::Other) | None => {
                return Err(RpmDbError::Format("Packages 의 둘째 열이 블롭이 아니다"))
            }
        }
    }
    Ok((out, stop))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::header::{self, tests::php_header};

    /// SQLite 가 직접 쓴 작은 DB — rpm 의 `CREATE TABLE` 문 그대로, 쪽 1 KiB, 합성 헤더 다섯(`php-cli` ·
    /// `gpg-pubkey` · 판이 다른 `kernel-core` 둘 · 한 쪽을 넘는 `php-fpm`). 다섯이 잎 하나에 들어가지 않아
    /// 표의 뿌리가 **내부 쪽**이고, 마지막 기록은 **넘침 쪽 사슬**에 있다.
    const TINY: &[u8] = include_bytes!("testdata/tiny-rpmdb.sqlite");

    #[test]
    fn every_blob_comes_out_in_rowid_order() {
        let got = blobs(TINY).expect("읽힌다");
        assert_eq!(
            got.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![202, 85, 196, 194, 3698]
        );
        assert_eq!(got[0], php_header(), "시험 빌더와 같은 바이트여야 한다");
        let names: Vec<String> = got
            .iter()
            .map(|b| header::parse(b).expect("헤더").name)
            .collect();
        assert_eq!(
            names,
            [
                "php-cli",
                "gpg-pubkey",
                "kernel-core",
                "kernel-core",
                "php-fpm"
            ]
        );
        // 넘침 사슬을 끝까지 따라가야 공급사 문자열이 온전하다.
        let last = header::parse(&got[4]).unwrap();
        assert!(last
            .vendor
            .starts_with("Rocky Enterprise Software Foundation"));
        assert_eq!(last.vendor.len(), 36 + 3500);
        assert_eq!(last.epoch, None);
    }

    #[test]
    fn the_fixture_walks_both_kinds_of_table_page() {
        // 시험이 내부 쪽 길을 정말 지나는지 — 자료를 다시 만들다 잎 하나로 줄면 이 시험이 먼저 깨진다.
        let db = Db::new(TINY, TRUSTED).unwrap();
        let root = db
            .table(1)
            .unwrap()
            .0
            .iter()
            .find_map(|r| match (column(r, 1), column(r, 3)) {
                (Some(Value::Bytes(b"Packages")), Some(Value::Int(n))) => Some(n as u32),
                _ => None,
            })
            .expect("Packages 표");
        assert_eq!(db.page(root).unwrap()[0], INTERIOR_TABLE);
    }

    #[test]
    fn a_database_without_the_packages_table_is_an_error() {
        let mut b = TINY.to_vec();
        for i in 0..1024 - 8 {
            if &b[i..i + 8] == b"Packages" {
                b[i] = b'Q';
            }
        }
        assert_eq!(blobs(&b), Err(RpmDbError::Format("Packages 표가 없다")));
        assert_eq!(
            blobs(b"not a database"),
            Err(RpmDbError::Format("SQLite 머리가 아니다"))
        );
    }

    #[test]
    fn cut_or_flipped_bytes_never_panic_or_shorten_a_blob() {
        // 디스크에서 온 바이트다. 어느 길이로 잘려도 **오류이거나 온전한 값**이다 — 짧아진 블롭을 조용히
        // 내면 그 패키지의 꼬리표가 엉뚱한 값이 된다. 바이트를 바꾼 것은 패닉만 없으면 된다.
        let full = blobs(TINY).unwrap();
        for cut in 0..TINY.len() {
            if let Ok(got) = blobs(&TINY[..cut]) {
                assert_eq!(got, full, "{cut} 바이트로 자른 파일이 다른 값을 냈다");
            }
        }
        let mut b = TINY.to_vec();
        for i in 0..b.len() {
            let keep = b[i];
            for v in [0x00, 0xFF, keep ^ 0x80] {
                b[i] = v;
                let _ = blobs(&b);
            }
            b[i] = keep;
        }
    }

    // ───────────────────────────── 상한 — 같은 판독기, 다른 값

    /// 시험용 DB 의 쪽 크기.
    const P: usize = 4096;

    /// 시험용 기록 — 제 블롭을 갖거나(`Own`), 앞의 `i` 번째 기록과 같은 페이로드를 담고 **넘침 사슬을 함께
    /// 쓴다**(`Same`). 함께 쓰는 사슬은 SQLite 가 쓰지 않는 모양이다 — 손으로 만든 파일만 그렇다.
    pub(crate) enum Rec {
        Own(Vec<u8>),
        Same(usize),
    }

    /// SQLite 의 가변 길이 정수 — 7비트씩, 큰 쪽이 먼저(이 시험의 값은 56비트 안이다).
    fn put_varint(out: &mut Vec<u8>, v: u64) {
        let mut groups = vec![(v & 0x7F) as u8];
        let mut rest = v >> 7;
        while rest > 0 {
            groups.push((rest & 0x7F) as u8 | 0x80);
            rest >>= 7;
        }
        out.extend(groups.iter().rev());
    }

    /// rpm 의 `Packages` 기록 — (NULL, 블롭). 머리는 길이 · NULL · 블롭의 직렬 형이다.
    pub(crate) fn record(blob: &[u8]) -> Vec<u8> {
        let mut serial = Vec::new();
        put_varint(&mut serial, blob.len() as u64 * 2 + 12);
        let mut r = vec![(2 + serial.len()) as u8, 0];
        r.extend(serial);
        r.extend_from_slice(blob);
        r
    }

    /// 스키마 표의 기록 하나 — `Packages` 의 뿌리는 쪽 2 다.
    fn schema_record() -> Vec<u8> {
        let texts: [&[u8]; 3] = [b"table", b"Packages", b"Packages"];
        let sql: &[u8] =
            b"CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)";
        let mut serials = Vec::new();
        for t in texts {
            put_varint(&mut serials, t.len() as u64 * 2 + 13);
        }
        serials.push(1);
        put_varint(&mut serials, sql.len() as u64 * 2 + 13);
        let mut r = vec![(1 + serials.len()) as u8];
        r.extend(serials);
        for t in texts {
            r.extend_from_slice(t);
        }
        r.push(2);
        r.extend_from_slice(sql);
        r
    }

    /// 판독기와 같은 식 — 표 잎 셀이 쪽 안에 두는 몫.
    fn local(p: usize) -> usize {
        let x = P - 35;
        if p <= x {
            return p;
        }
        let m = ((P - 12) * 32 / 255) - 23;
        let k = m + ((p - m) % (P - 4));
        if k <= x {
            k
        } else {
            m
        }
    }

    /// 넘친 몫을 파일 끝에 쪽 사슬로 잇는다 — 쪽마다 다음 쪽 번호와 자료. 넘치지 않으면 `None`.
    fn overflow(f: &mut Vec<u8>, rest: &[u8]) -> Option<u32> {
        if rest.is_empty() {
            return None;
        }
        let first = (f.len() / P + 1) as u32;
        let chunks: Vec<&[u8]> = rest.chunks(P - 4).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let pgno = first + i as u32;
            let next = if i + 1 < chunks.len() { pgno + 1 } else { 0 };
            let mut page = vec![0u8; P];
            page[..4].copy_from_slice(&next.to_be_bytes());
            page[4..4 + chunk.len()].copy_from_slice(chunk);
            f.extend_from_slice(&page);
        }
        Some(first)
    }

    /// 셀 하나 — 페이로드 길이 · rowid · 쪽 안의 몫 · (넘치면) 사슬의 첫 쪽.
    fn cell(payload: &[u8], rowid: u64, first: Option<u32>) -> Vec<u8> {
        let mut c = Vec::new();
        put_varint(&mut c, payload.len() as u64);
        put_varint(&mut c, rowid);
        c.extend_from_slice(&payload[..local(payload.len())]);
        if let Some(pg) = first {
            c.extend_from_slice(&pg.to_be_bytes());
        }
        c
    }

    /// 표 잎 쪽 — `base` 는 쪽의 자리, `h` 는 쪽 머리의 자리(첫 쪽은 파일 머리 100바이트 뒤).
    fn leaf(f: &mut [u8], base: usize, h: usize, cells: &[Vec<u8>]) {
        let page = &mut f[base..base + P];
        page[h] = LEAF_TABLE;
        page[h + 3..h + 5].copy_from_slice(&(cells.len() as u16).to_be_bytes());
        let mut top = P;
        for (i, c) in cells.iter().enumerate() {
            top = top
                .checked_sub(c.len())
                .expect("시험 기록이 잎 쪽 하나를 넘었다");
            page[top..top + c.len()].copy_from_slice(c);
            page[h + 8 + 2 * i..h + 10 + 2 * i].copy_from_slice(&(top as u16).to_be_bytes());
        }
        assert!(
            h + 8 + 2 * cells.len() <= top,
            "시험 기록이 잎 쪽 하나를 넘었다"
        );
    }

    /// 표 내부 쪽 — 왼쪽부터 자식 쪽 번호와 rowid, 오른쪽 끝 자식은 쪽 머리에.
    fn interior(f: &mut [u8], base: usize, children: &[u32]) {
        let page = &mut f[base..base + P];
        page[0] = INTERIOR_TABLE;
        let (last, rest) = children.split_last().expect("자식이 하나는 있다");
        page[3..5].copy_from_slice(&(rest.len() as u16).to_be_bytes());
        page[8..12].copy_from_slice(&last.to_be_bytes());
        let mut top = P;
        for (i, child) in rest.iter().enumerate() {
            let mut c = child.to_be_bytes().to_vec();
            put_varint(&mut c, i as u64 + 1);
            top -= c.len();
            page[top..top + c.len()].copy_from_slice(&c);
            page[12 + 2 * i..14 + 2 * i].copy_from_slice(&(top as u16).to_be_bytes());
        }
        assert!(
            12 + 2 * rest.len() <= top,
            "시험 기록이 내부 쪽 하나를 넘었다"
        );
    }

    /// 시험용 rpm SQLite DB — 쪽 4 KiB, 스키마 표(쪽 1)와 `Packages` 의 내부 뿌리 쪽(쪽 2). 기록마다 잎 쪽 하나를 두므로
    /// 기록의 크기와 상관없이 들어가고, 넘친 몫은 넘침 쪽 사슬에 있다.
    pub(crate) fn sqlite_db(recs: &[Rec]) -> Vec<u8> {
        let mut f = vec![0u8; 2 * P];
        f[..16].copy_from_slice(MAGIC);
        f[16..18].copy_from_slice(&(P as u16).to_be_bytes());
        leaf(&mut f, 0, 100, &[cell(&schema_record(), 1, None)]);
        let mut built: Vec<Option<(Vec<u8>, Option<u32>)>> = Vec::new();
        let mut leaves = Vec::new();
        for (i, r) in recs.iter().enumerate() {
            let rowid = i as u64 + 1;
            let c = match r {
                Rec::Own(blob) => {
                    let payload = record(blob);
                    let first = overflow(&mut f, &payload[local(payload.len())..]);
                    let c = cell(&payload, rowid, first);
                    built.push(Some((payload, first)));
                    c
                }
                Rec::Same(k) => {
                    let (payload, first) = built[*k].as_ref().expect("앞의 Own 기록");
                    let c = cell(payload, rowid, *first);
                    built.push(None);
                    c
                }
            };
            let base = f.len();
            f.resize(base + P, 0);
            leaf(&mut f, base, 0, &[c]);
            leaves.push((base / P + 1) as u32);
        }
        if leaves.is_empty() {
            leaf(&mut f, P, 0, &[]);
        } else {
            interior(&mut f, P, &leaves);
        }
        f
    }

    fn limits(records: usize, copied: u64) -> Limits {
        Limits {
            record: MAX_RECORD,
            records,
            copied,
        }
    }

    #[test]
    fn the_test_builder_writes_what_the_reader_reads() {
        // 시험 DB 가 판독기의 길(스키마 · 잎 · 넘침 사슬)을 지나는지 — 아래 상한 시험의 전제다.
        let big = vec![7u8; 3 * P];
        let db = sqlite_db(&[Rec::Own(php_header()), Rec::Own(big.clone())]);
        assert_eq!(blobs(&db).unwrap(), vec![php_header(), big.clone()]);
        // 사슬을 함께 쓰는 기록도 판독기는 따로 복사한다 — 그것이 상한이 있어야 하는 까닭이다.
        let shared = sqlite_db(&[Rec::Own(big.clone()), Rec::Same(0), Rec::Same(0)]);
        assert_eq!(blobs(&shared).unwrap(), vec![big.clone(), big.clone(), big]);
        assert_eq!(
            shared.len(),
            8 * P,
            "쪽 1 · 2, 사슬 하나(쪽 셋), 잎 쪽 셋뿐이다"
        );
        // 기록이 없는 DB 도 판독기의 길을 지난다.
        assert_eq!(blobs(&sqlite_db(&[])).unwrap(), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn copies_stop_at_the_limit_and_keep_the_records_before() {
        let big = vec![7u8; 3 * P];
        let db = sqlite_db(&[Rec::Own(php_header()), Rec::Own(big.clone())]);
        let schema = schema_record().len() as u64;
        let (a, b) = (
            record(&php_header()).len() as u64,
            record(&big).len() as u64,
        );
        // 꼭 닿으면 읽는다 · 한 바이트 모자라면 그 앞까지와 까닭.
        assert_eq!(
            read(&db, limits(10, schema + a + b)).unwrap(),
            (vec![php_header(), big], None)
        );
        assert_eq!(
            read(&db, limits(10, schema + a + b - 1)).unwrap(),
            (vec![php_header()], Some(COPIED))
        );
        assert_eq!(
            read(&db, limits(10, schema + a - 1)).unwrap(),
            (Vec::new(), Some(COPIED))
        );
        // 스키마 표에서 닿으면 `Packages` 를 찾지 못한다 — 블롭이 없다.
        assert_eq!(
            read(&db, limits(10, schema - 1)).unwrap(),
            (Vec::new(), Some(COPIED))
        );
    }

    #[test]
    fn more_records_than_the_limit_is_an_error_not_a_shorter_list() {
        let db = sqlite_db(&[Rec::Own(php_header()), Rec::Own(php_header())]);
        assert_eq!(read(&db, limits(2, u64::MAX)).unwrap().0.len(), 2);
        assert_eq!(
            read(&db, limits(1, u64::MAX)),
            Err(RpmDbError::Limit("SQLite 기록이 상한을 넘었다"))
        );
    }
}
