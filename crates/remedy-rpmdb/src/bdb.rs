//! RPM 의 Berkeley DB 해시 DB(`Packages` — RHEL 7 · 8 · CentOS 계열) — 값(헤더 블롭)만 꺼낸다.
//!
//! # 쓰는 것
//!
//! Berkeley DB 해시 형식의 읽는 쪽 일부 — 첫 쪽(메타)에서 바이트 순서 · 쪽 크기 · 마지막 쪽을 읽고, 해시
//! 쪽마다 키/값 쌍을 걸어 값을 꺼낸다. 헤더 블롭은 대개 쪽보다 커서 **넘침 쪽 사슬**(`H_OFFPAGE`)에 있다.
//! 쓰지 않고, 잠금 · 로그 · 다른 DB 형식(B-트리 · 큐)은 읽지 않는다.
//!
//! 쪽 머리(26바이트): LSN 8 · 쪽 번호 4 · 앞 쪽 4 · 다음 쪽 4 · 항목 수 2 · `hf_offset` 2 · 높이 1 · 종류 1.
//! 해시 쪽의 항목 i 의 길이는 `(i == 0 ? 쪽 크기 : inp[i-1]) - inp[i]` 다. 넘침 쪽은 `hf_offset` 이 그 쪽의
//! 자료 길이다.

use super::{Copies, Limits, Read, RpmDbError, COPIED};
use std::collections::HashSet;

const HASH_MAGIC: u32 = 0x0006_1561;
const P_HASH_UNSORTED: u8 = 2;
const P_OVERFLOW: u8 = 7;
const P_HASHMETA: u8 = 8;
const P_HASH: u8 = 13;
const DBMETA_CHKSUM: u8 = 0x01;
const H_KEYDATA: u8 = 1;
const H_OFFPAGE: u8 = 3;
const PAGE_HEADER: usize = 26;
/// 값 하나의 상한 — rpm 헤더 블롭은 크게 잡아도 수 MiB 다.
const MAX_VALUE: u32 = 64 * 1024 * 1024;
const MAX_VALUES: usize = 200_000;
/// 이 기계의 DB 를 읽을 때([`blobs`])의 상한 — 복사한 양은 보지 않는다.
const TRUSTED: Limits = Limits {
    record: MAX_VALUE as u64,
    records: MAX_VALUES,
    copied: u64::MAX,
};

struct Db<'a> {
    bytes: &'a [u8],
    little: bool,
    page_size: usize,
    pages: u32,
    limits: Limits,
    /// 쪽 안의 값과 넘침 사슬의 값을 함께 센다.
    copies: Copies,
}

impl<'a> Db<'a> {
    fn u16_at(&self, b: &[u8], at: usize) -> Result<u16, RpmDbError> {
        let s = b.get(at..at + 2).ok_or(RpmDbError::Format("쪽이 짧다"))?;
        Ok(if self.little {
            u16::from_le_bytes([s[0], s[1]])
        } else {
            u16::from_be_bytes([s[0], s[1]])
        })
    }

    fn u32_at(&self, b: &[u8], at: usize) -> Result<u32, RpmDbError> {
        let s = b.get(at..at + 4).ok_or(RpmDbError::Format("쪽이 짧다"))?;
        let a = [s[0], s[1], s[2], s[3]];
        Ok(if self.little {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }

    fn page(&self, pgno: u32) -> Result<&'a [u8], RpmDbError> {
        if pgno >= self.pages {
            return Err(RpmDbError::Format("BDB 쪽 번호가 파일 밖이다"));
        }
        let start = pgno as usize * self.page_size;
        Ok(&self.bytes[start..start + self.page_size])
    }

    /// 넘침 쪽 사슬을 따라 `len` 바이트를 모은다.
    fn overflow(&self, mut pgno: u32, len: u32) -> Result<Vec<u8>, RpmDbError> {
        if u64::from(len) > self.limits.record {
            return Err(RpmDbError::Limit("BDB 값 하나가 상한을 넘었다"));
        }
        // 항목 여럿이 같은 사슬을 가리킬 수 있다 — 그때마다 복사하므로 복사하기 전에 센다.
        self.copies.take(u64::from(len))?;
        // 길이는 파일이 주장하는 값이다 — 미리 잡는 자리는 파일 크기를 넘지 않는다.
        let mut out = Vec::with_capacity((len as usize).min(self.bytes.len()));
        let mut seen = HashSet::new();
        while out.len() < len as usize {
            if pgno == 0 || !seen.insert(pgno) {
                return Err(RpmDbError::Format("BDB 넘침 사슬이 끊겼거나 고리다"));
            }
            let page = self.page(pgno)?;
            if page[25] != P_OVERFLOW {
                return Err(RpmDbError::Format("넘침 사슬에 다른 쪽이 섞였다"));
            }
            let used = self.u16_at(page, 22)? as usize;
            let chunk = page
                .get(PAGE_HEADER..PAGE_HEADER + used)
                .ok_or(RpmDbError::Format("넘침 쪽의 길이가 쪽 밖이다"))?;
            out.extend_from_slice(chunk);
            pgno = self.u32_at(page, 16)?;
        }
        out.truncate(len as usize);
        Ok(out)
    }
}

/// 해시 DB 의 값 전부 — 이 기계의 DB.
pub fn blobs(bytes: &[u8]) -> Result<Vec<Vec<u8>>, RpmDbError> {
    let (out, stop) = read(bytes, TRUSTED)?;
    stop.map_or(Ok(out), Err)
}

/// 해시 DB 의 값을 `limits` 안에서. 복사한 양이 상한에 닿으면 그 앞의 값과 [`COPIED`] 다.
pub(crate) fn read(bytes: &[u8], limits: Limits) -> Result<Read, RpmDbError> {
    if bytes.len() < 512 {
        return Err(RpmDbError::Format("BDB 메타 쪽이 없다"));
    }
    let magic_le = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let magic_be = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let little = match (magic_le == HASH_MAGIC, magic_be == HASH_MAGIC) {
        (true, _) => true,
        (_, true) => false,
        _ => return Err(RpmDbError::Format("BDB 해시 DB 가 아니다")),
    };
    if bytes[25] != P_HASHMETA {
        return Err(RpmDbError::Format("BDB 메타 쪽이 해시 메타가 아니다"));
    }
    // 암호화(자리 24) · 검사합(자리 26 의 첫 비트)이 켜지면 쪽 머리가 길어진다 — rpm 이 켜지 않는 설정이라
    // 이 판독기는 그 모양을 모른다. 엉뚱한 자리를 읽느니 거부한다.
    if bytes[24] != 0 || bytes[26] & DBMETA_CHKSUM != 0 {
        return Err(RpmDbError::Format(
            "암호화 · 검사합이 켜진 BDB 는 읽지 않는다",
        ));
    }
    let mut db = Db {
        bytes,
        little,
        page_size: 0,
        pages: 0,
        limits,
        copies: Copies::new(limits.copied),
    };
    let page_size = db.u32_at(bytes, 20)? as usize;
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(RpmDbError::Format("BDB 쪽 크기가 틀렸다"));
    }
    // 메타가 말하는 쪽 수보다 짧으면 잘린 파일이다. 이 판독기는 쪽을 차례로 훑으므로 그대로 두면 잘린 뒤쪽의
    // 패키지가 **조용히 빠진다**(실측: CentOS 7 · Oracle Linux 8 의 DB 는 파일 길이가 정확히 그 쪽 수다).
    let pages = db
        .u32_at(bytes, 32)?
        .checked_add(1)
        .ok_or(RpmDbError::Format("BDB 마지막 쪽 번호가 틀렸다"))?;
    if bytes.len() / page_size < pages as usize {
        return Err(RpmDbError::Format(
            "BDB 파일이 메타 쪽이 말하는 길이보다 짧다",
        ));
    }
    db.page_size = page_size;
    db.pages = pages;

    let mut out = Vec::new();
    for pgno in 1..db.pages {
        let page = db.page(pgno)?;
        if page[25] != P_HASH && page[25] != P_HASH_UNSORTED {
            continue;
        }
        let entries = db.u16_at(page, 20)? as usize;
        let inp = |i: usize| db.u16_at(page, PAGE_HEADER + 2 * i).map(|v| v as usize);
        // 키와 값이 번갈아 선다 — 값은 홀수 자리다.
        for d in (1..entries).step_by(2) {
            let at = inp(d)?;
            let end = inp(d - 1)?;
            if at >= end || end > page_size {
                return Err(RpmDbError::Format("BDB 항목의 자리가 틀렸다"));
            }
            match page[at] {
                H_OFFPAGE => {
                    let first = db.u32_at(page, at + 4)?;
                    let len = db.u32_at(page, at + 8)?;
                    match db.overflow(first, len) {
                        Ok(v) => out.push(v),
                        Err(e) if e == COPIED => return Ok((out, Some(e))),
                        Err(e) => return Err(e),
                    }
                }
                H_KEYDATA => {
                    let value = &page[at + 1..end];
                    if db.copies.take(value.len() as u64).is_err() {
                        return Ok((out, Some(COPIED)));
                    }
                    out.push(value.to_vec());
                }
                // 중복(H_DUPLICATE · H_OFFDUP)은 rpm 의 Packages 에 없다 — 있으면 모르는 모양이다.
                _ => return Err(RpmDbError::Format("BDB 항목 종류를 모른다")),
            }
            if out.len() > db.limits.records {
                return Err(RpmDbError::Limit("BDB 값이 상한을 넘었다"));
            }
        }
    }
    Ok((out, None))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::header::tests::{build, php_header, s};

    const PS: usize = 512;

    fn put16(b: &mut [u8], at: usize, v: u16, le: bool) {
        b[at..at + 2].copy_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
    }

    fn put32(b: &mut [u8], at: usize, v: u32, le: bool) {
        b[at..at + 4].copy_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
    }

    /// 해시 쪽에 놓는 값 — 쪽 안(`H_KEYDATA`) 또는 넘침 쪽 사슬(`H_OFFPAGE`). `Same(i)` 는 앞의 `i` 번째 값
    /// (`Offpage`)의 사슬을 **함께 쓴다** — rpm 이 쓰지 않는 모양이고, 손으로 만든 파일만 그렇다.
    pub(crate) enum Val {
        Inline(Vec<u8>),
        Offpage(Vec<u8>),
        Same(usize),
    }

    /// 메타 쪽 · 해시 쪽 하나 · 넘침 쪽들. 키는 rpm 처럼 4바이트 정수(헤더 번호)다.
    pub(crate) fn bdb(le: bool, values: &[Val]) -> Vec<u8> {
        let chunk = PS - PAGE_HEADER;
        let overflow: usize = values
            .iter()
            .map(|v| match v {
                Val::Offpage(d) => d.len().div_ceil(chunk),
                Val::Inline(_) | Val::Same(_) => 0,
            })
            .sum();
        let pages = 2 + overflow;
        let mut f = vec![0u8; PS * pages];
        put32(&mut f, 12, HASH_MAGIC, le);
        put32(&mut f, 16, 9, le);
        put32(&mut f, 20, PS as u32, le);
        f[25] = P_HASHMETA;
        put32(&mut f, 32, (pages - 1) as u32, le);

        let mut items: Vec<Vec<u8>> = Vec::new();
        let mut next_ov = 2usize;
        // 값마다 사슬의 첫 쪽과 길이 — `Same` 이 가리킨다.
        let mut chains: Vec<Option<(u32, u32)>> = Vec::new();
        let offpage = |first: u32, len: u32| {
            let mut item = vec![0u8; 12];
            item[0] = H_OFFPAGE;
            put32(&mut item, 4, first, le);
            put32(&mut item, 8, len, le);
            item
        };
        for (k, v) in values.iter().enumerate() {
            let mut key = vec![H_KEYDATA];
            key.extend_from_slice(&(k as u32).to_le_bytes());
            items.push(key);
            match v {
                Val::Inline(d) => {
                    items.push([&[H_KEYDATA][..], &d[..]].concat());
                    chains.push(None);
                }
                Val::Same(i) => {
                    let (first, len) = chains[*i].expect("앞의 Offpage 값");
                    items.push(offpage(first, len));
                    chains.push(None);
                }
                Val::Offpage(d) => {
                    items.push(offpage(next_ov as u32, d.len() as u32));
                    chains.push(Some((next_ov as u32, d.len() as u32)));
                    let parts: Vec<&[u8]> = d.chunks(chunk).collect();
                    for (i, part) in parts.iter().enumerate() {
                        let pg = next_ov + i;
                        let page = &mut f[pg * PS..(pg + 1) * PS];
                        put32(page, 8, pg as u32, le);
                        let next = if i + 1 < parts.len() {
                            pg as u32 + 1
                        } else {
                            0
                        };
                        put32(page, 16, next, le);
                        put16(page, 20, 1, le);
                        put16(page, 22, part.len() as u16, le);
                        page[25] = P_OVERFLOW;
                        page[PAGE_HEADER..PAGE_HEADER + part.len()].copy_from_slice(part);
                    }
                    next_ov += parts.len();
                }
            }
        }
        let page = &mut f[PS..2 * PS];
        put32(page, 8, 1, le);
        put16(page, 20, items.len() as u16, le);
        page[25] = P_HASH;
        let mut top = PS;
        for (i, item) in items.iter().enumerate() {
            top -= item.len();
            page[top..top + item.len()].copy_from_slice(item);
            put16(page, PAGE_HEADER + 2 * i, top as u16, le);
        }
        assert!(
            PAGE_HEADER + 2 * items.len() <= top,
            "시험 자료가 해시 쪽 하나를 넘었다"
        );
        f
    }

    /// 넘침 쪽 둘에 걸치는 헤더.
    fn big() -> Vec<u8> {
        build(&[
            (1000, 6, s("php-fpm")),
            (1001, 6, s("8.2.35")),
            (1002, 6, s("1.module+el8.10.0+25110+f67151d2")),
            (1011, 6, s(&"V".repeat(700))),
        ])
    }

    /// rpm 의 `Packages` 모양 — 키 0 의 값은 패키지가 아니라 다음 헤더 번호(4바이트)다.
    pub(crate) fn sample(le: bool) -> Vec<u8> {
        bdb(
            le,
            &[
                Val::Inline(vec![5, 0, 0, 0]),
                Val::Inline(php_header()),
                Val::Offpage(big()),
            ],
        )
    }

    #[test]
    fn values_come_from_hash_pages_and_overflow_chains_in_both_byte_orders() {
        assert!(
            big().len() > PS - PAGE_HEADER,
            "넘침 쪽 하나에 들어간다 — 사슬을 시험하지 못한다"
        );
        for le in [true, false] {
            let f = sample(le);
            assert_eq!(
                blobs(&f).unwrap(),
                vec![vec![5, 0, 0, 0], php_header(), big()],
                "le={le}"
            );
            // 헤더가 아닌 값은 버리지 않고 센다.
            let (hs, skipped) = crate::headers(&f).unwrap();
            assert_eq!((hs.len(), skipped), (2, 1));
            assert_eq!(
                (hs[0].name.as_str(), hs[1].name.as_str()),
                ("php-cli", "php-fpm")
            );
        }
    }

    #[test]
    fn a_looping_overflow_chain_is_an_error() {
        let mut f = bdb(true, &[Val::Offpage(big())]);
        // 첫 넘침 쪽(2)의 다음 쪽을 자기 자신으로.
        put32(&mut f[2 * PS..3 * PS], 16, 2, true);
        assert_eq!(
            blobs(&f),
            Err(RpmDbError::Format("BDB 넘침 사슬이 끊겼거나 고리다"))
        );
    }

    #[test]
    fn encrypted_or_checksummed_files_are_refused() {
        let mut f = sample(true);
        f[24] = 1;
        assert!(blobs(&f).is_err(), "암호화");
        f[24] = 0;
        f[26] = DBMETA_CHKSUM;
        assert!(blobs(&f).is_err(), "검사합");
        f[26] = 0;
        assert!(blobs(&f).is_ok());
    }

    #[test]
    fn cut_or_flipped_bytes_never_panic_or_drop_a_value() {
        // 쪽을 차례로 훑으므로 잘린 파일이 **값이 빠진 성공**이 되기 쉽다 — 메타의 쪽 수가 그것을 막는다.
        let f = sample(true);
        let full = blobs(&f).unwrap();
        for cut in 0..f.len() {
            if let Ok(got) = blobs(&f[..cut]) {
                assert_eq!(got, full, "{cut} 바이트로 자른 파일이 다른 값을 냈다");
            }
        }
        let mut b = f.clone();
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

    fn limits(records: usize, copied: u64) -> Limits {
        Limits {
            record: u64::from(MAX_VALUE),
            records,
            copied,
        }
    }

    #[test]
    fn values_sharing_one_chain_are_each_copied() {
        // 항목 셋이 사슬 하나를 가리킨다 — 판독기는 셋을 따로 복사한다. 상한이 있어야 하는 까닭이다.
        let f = bdb(true, &[Val::Offpage(big()), Val::Same(0), Val::Same(0)]);
        assert_eq!(f.len(), (2 + big().len().div_ceil(PS - PAGE_HEADER)) * PS);
        assert_eq!(blobs(&f).unwrap(), vec![big(), big(), big()]);
    }

    #[test]
    fn copies_stop_at_the_limit_and_keep_the_values_before() {
        // 쪽 안의 값도 복사한 양에 든다.
        let f = sample(true);
        let (a, b, c) = (4u64, php_header().len() as u64, big().len() as u64);
        assert_eq!(
            read(&f, limits(10, a + b + c)).unwrap(),
            (vec![vec![5, 0, 0, 0], php_header(), big()], None)
        );
        assert_eq!(
            read(&f, limits(10, a + b + c - 1)).unwrap(),
            (vec![vec![5, 0, 0, 0], php_header()], Some(COPIED))
        );
        assert_eq!(
            read(&f, limits(10, a + b - 1)).unwrap(),
            (vec![vec![5, 0, 0, 0]], Some(COPIED))
        );
    }

    #[test]
    fn more_values_than_the_limit_is_an_error_not_a_shorter_list() {
        let f = sample(true);
        assert_eq!(read(&f, limits(3, u64::MAX)).unwrap().0.len(), 3);
        assert_eq!(
            read(&f, limits(2, u64::MAX)),
            Err(RpmDbError::Limit("BDB 값이 상한을 넘었다"))
        );
    }
}
