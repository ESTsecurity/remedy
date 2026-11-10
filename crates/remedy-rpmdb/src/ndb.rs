//! RPM 의 NDB(`Packages.db` — SUSE 계열) — 슬롯이 가리키는 블롭(헤더)만 꺼낸다.
//!
//! # 모양 (rpm 의 ndb 뒷단 · 리틀 엔디언)
//!
//! - 파일 머리(32바이트): 마법 `RpmP` · 판 · 세대 · 슬롯 쪽 수 · 다음 패키지 번호.
//! - 슬롯 쪽(4096바이트 × 슬롯 쪽 수, 첫 쪽의 앞 32바이트는 머리): 슬롯 16바이트 = 마법 `Slot` · 패키지 번호 ·
//!   블록 자리 · 블록 수. **블록 자리가 0 이면 빈 슬롯이다** — 패키지 번호 · 블록 수가 0 이거나 블록이 슬롯
//!   쪽 안을 가리키면 rpm 도 DB 를 거부한다(rpm 의 `rpmpkgReadSlots` 와 같은 판정).
//! - 블롭(블록 = 16바이트): 머리 16바이트 = 마법 `BlbS` · 패키지 번호 · 세대 · 길이, 그 뒤가 헤더 블롭이고
//!   꼬리 12바이트(검사합 · 길이 · 마법 `BlbE`)가 따른다.
//!
//! 쓰지 않고, 블롭 꼬리의 검사합은 보지 않는다 — 머리의 마법 · 패키지 번호 · 길이가 슬롯과 맞는지만 본다.

use super::RpmDbError;

const DB_MAGIC: &[u8; 4] = b"RpmP";
const SLOT_MAGIC: &[u8; 4] = b"Slot";
const BLOB_MAGIC: &[u8; 4] = b"BlbS";
const PAGE: usize = 4096;
const SLOT: usize = 16;
const BLOCK: usize = 16;
const BLOB_HEAD: usize = 16;
const BLOB_TAIL: usize = 12;
/// 첫 슬롯 쪽의 앞 32바이트는 파일 머리다.
const FIRST_SLOT: usize = 32 / SLOT;
const MAX_BLOB: u32 = 64 * 1024 * 1024;
const MAX_SLOT_PAGES: u32 = 4096;

fn le32(b: &[u8], at: usize) -> Result<u32, RpmDbError> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(RpmDbError::Format("NDB 가 짧다"))
}

/// 쓰인 슬롯이 가리키는 헤더 블롭 전부.
pub fn blobs(bytes: &[u8]) -> Result<Vec<Vec<u8>>, RpmDbError> {
    if bytes.len() < PAGE || &bytes[..4] != DB_MAGIC {
        return Err(RpmDbError::Format("NDB 머리가 아니다"));
    }
    let slot_pages = le32(bytes, 12)?;
    if slot_pages == 0 || slot_pages > MAX_SLOT_PAGES {
        return Err(RpmDbError::Format("NDB 슬롯 쪽 수가 틀렸다"));
    }
    let slots_end = (slot_pages as usize)
        .checked_mul(PAGE)
        .filter(|e| *e <= bytes.len())
        .ok_or(RpmDbError::Format("NDB 슬롯 쪽이 파일 밖이다"))?;
    // 블롭은 슬롯 쪽 뒤에만 있다.
    let min_block = slots_end / BLOCK;
    let mut out = Vec::new();
    for s in (FIRST_SLOT * SLOT..slots_end).step_by(SLOT) {
        if &bytes[s..s + 4] != SLOT_MAGIC {
            return Err(RpmDbError::Format("NDB 슬롯 마법이 틀렸다"));
        }
        let blkoff = le32(bytes, s + 8)? as usize;
        if blkoff == 0 {
            continue;
        }
        let pkgidx = le32(bytes, s + 4)?;
        let blkcnt = le32(bytes, s + 12)? as usize;
        if pkgidx == 0 || blkcnt == 0 || blkoff < min_block {
            return Err(RpmDbError::Format("NDB 슬롯이 틀렸다"));
        }
        let at = blkoff
            .checked_mul(BLOCK)
            .ok_or(RpmDbError::Format("NDB 블록 자리가 넘친다"))?;
        let head = bytes
            .get(at..at + BLOB_HEAD)
            .ok_or(RpmDbError::Format("NDB 블롭이 파일 밖이다"))?;
        if &head[..4] != BLOB_MAGIC || le32(head, 4)? != pkgidx {
            return Err(RpmDbError::Format("NDB 블롭 머리가 슬롯과 맞지 않는다"));
        }
        let len = le32(head, 12)?;
        if len > MAX_BLOB || (len as usize) + BLOB_HEAD + BLOB_TAIL > blkcnt.saturating_mul(BLOCK) {
            return Err(RpmDbError::Format("NDB 블롭 길이가 슬롯의 블록을 넘는다"));
        }
        let blob = bytes
            .get(at + BLOB_HEAD..at + BLOB_HEAD + len as usize)
            .ok_or(RpmDbError::Format("NDB 블롭이 파일 밖이다"))?;
        out.push(blob.to_vec());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::tests::{build, php_header, s};

    /// 슬롯 쪽 하나 뒤에 블롭을 잇는다 — 슬롯 차례대로, `None` 은 빈 슬롯. 빈 슬롯도 마법은 적혀 있다(rpm 이
    /// 슬롯 쪽을 그렇게 채운다).
    fn ndb(slots: &[Option<(u32, Vec<u8>)>]) -> Vec<u8> {
        let mut f = vec![0u8; PAGE];
        f[..4].copy_from_slice(DB_MAGIC);
        f[12..16].copy_from_slice(&1u32.to_le_bytes());
        for s in (FIRST_SLOT * SLOT..PAGE).step_by(SLOT) {
            f[s..s + 4].copy_from_slice(SLOT_MAGIC);
        }
        for (i, slot) in slots.iter().enumerate() {
            let Some((pkgidx, data)) = slot else {
                continue;
            };
            let blkoff = f.len() / BLOCK;
            let mut blob = BLOB_MAGIC.to_vec();
            blob.extend_from_slice(&pkgidx.to_le_bytes());
            blob.extend_from_slice(&0u32.to_le_bytes());
            blob.extend_from_slice(&(data.len() as u32).to_le_bytes());
            blob.extend_from_slice(data);
            while !(blob.len() + BLOB_TAIL).is_multiple_of(BLOCK) {
                blob.push(0);
            }
            blob.extend_from_slice(&0u32.to_le_bytes());
            blob.extend_from_slice(&(data.len() as u32).to_le_bytes());
            blob.extend_from_slice(b"BlbE");
            let at = (FIRST_SLOT + i) * SLOT;
            f[at + 4..at + 8].copy_from_slice(&pkgidx.to_le_bytes());
            f[at + 8..at + 12].copy_from_slice(&(blkoff as u32).to_le_bytes());
            f[at + 12..at + 16].copy_from_slice(&((blob.len() / BLOCK) as u32).to_le_bytes());
            f.extend_from_slice(&blob);
        }
        f
    }

    fn other() -> Vec<u8> {
        build(&[
            (1000, 6, s("php8-cli")),
            (1001, 6, s("8.3.36")),
            (1002, 6, s("150700.3.24.1")),
            (1011, 6, s("SUSE LLC <https://www.suse.com/>")),
        ])
    }

    /// 첫 슬롯 · 빈 슬롯 · 셋째 슬롯.
    fn sample() -> Vec<u8> {
        ndb(&[Some((1, php_header())), None, Some((7, other()))])
    }

    /// 슬롯 `i` 의 칸 하나(4 = 패키지 번호 · 8 = 블록 자리 · 12 = 블록 수)를 바꾼다.
    fn set(f: &mut [u8], i: usize, field: usize, v: u32) {
        let at = (FIRST_SLOT + i) * SLOT + field;
        f[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn occupied_slots_point_at_the_headers_and_empty_ones_are_skipped() {
        assert_eq!(blobs(&sample()).unwrap(), vec![php_header(), other()]);
    }

    #[test]
    fn slots_rpm_itself_rejects_are_errors() {
        // 블록 자리가 0 이 아닌데 패키지 번호 · 블록 수가 0 이거나, 블롭이 슬롯 쪽 안을 가리킨다.
        for (field, v) in [(4, 0), (12, 0), (8, 1)] {
            let mut f = sample();
            set(&mut f, 0, field, v);
            assert_eq!(
                blobs(&f),
                Err(RpmDbError::Format("NDB 슬롯이 틀렸다")),
                "칸 {field}"
            );
        }
        // 블록 자리가 0 이면 rpm 처럼 빈 슬롯이다 — 패키지 번호가 남아 있어도.
        let mut f = sample();
        set(&mut f, 0, 8, 0);
        assert_eq!(blobs(&f).unwrap(), vec![other()]);
    }

    #[test]
    fn a_blob_that_does_not_match_its_slot_is_an_error() {
        let mut f = sample();
        set(&mut f, 0, 4, 2);
        assert_eq!(
            blobs(&f),
            Err(RpmDbError::Format("NDB 블롭 머리가 슬롯과 맞지 않는다"))
        );
        // 블롭 길이가 슬롯의 블록(머리 · 꼬리 포함)을 넘는다.
        let mut f = sample();
        let at = PAGE + 12;
        let len = u32::from_le_bytes(f[at..at + 4].try_into().unwrap());
        f[at..at + 4].copy_from_slice(&(len + 16).to_le_bytes());
        assert_eq!(
            blobs(&f),
            Err(RpmDbError::Format("NDB 블롭 길이가 슬롯의 블록을 넘는다"))
        );
    }

    #[test]
    fn cut_or_flipped_bytes_never_panic_or_drop_a_blob() {
        // 슬롯이 블롭을 가리키므로 잘린 파일은 오류이거나(가리킨 블롭이 없다) 온전한 값이다.
        let f = sample();
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
}
