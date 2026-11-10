//! RPM 패키지 DB 를 파일로 읽는다 — SQLite(RHEL 9 · Fedora) · Berkeley DB(RHEL 7 · 8 · CentOS) ·
//! NDB(SUSE) (2026-11-09).
//!
//! # rpm 을 부르지 않는다
//!
//! dpkg · apk 와 같은 까닭이다(`remedy-collect` 의 `package.rs`) — 수집 중 자식 프로세스 0. 세 형식 모두 **읽는 쪽 일부만**
//! 구현했고(형식마다 모듈 머리에 무엇을 읽는지 적었다), 쓰지 않는다. 디스크에서 온 바이트라 모든 자리를
//! 범위로 확인하고, 모르는 모양은 오류로 돌려 부르는 쪽이 *잘렸다* 로 말하게 한다 — 조용히 0건이 되면
//! 그 기계는 *"패키지가 없다"* 가 된다.
//!
//! # 실물 대조 (2026-11-09)
//!
//! 컨테이너에서 꺼낸 DB 넷을 같은 컨테이너의 `rpm -qa` 와 견줬다 — 이름 · `epoch:판-개정` · 아키텍처 · 공급사가
//! 모두 같았다(`gpg-pubkey` 제외): Rocky 9(SQLite) 157 · CentOS 7(BDB) 148 · Oracle Linux 8(BDB) 200 ·
//! openSUSE Leap 15.6(NDB) 140. DB 하나를 읽는 데 6~11 ms 였다(디버그 빌드).
//!
//! # 따로 선 크레이트다 (2026-11-10)
//!
//! `remedy-collect` 의 모듈이었다. 그 크레이트는 `remedy-platform` 에 기대므로 동반 모듈 `remedy-net` 이 쓸 수
//! 없었다(설계-04 §1) — 이미지 안의 DB 도 같은 판독기로 읽도록 **의존 없는 크레이트**로 뺐다. 파일을 열고 읽는 양을
//! 정하고 DB 자리를 고르는 것은 부르는 쪽의 일이다.
//!
//! # 입구가 둘이다 (2026-11-10)
//!
//! [`headers`] · [`blobs`] 는 **이 기계의 DB** 를 읽는다 — 본체의 수집기가 쓰고, root 만 쓸 수 있는 파일이라 상한이
//! 넉넉하다(기록 하나 64 MiB · 복사한 양은 보지 않는다). 이미지 · 컨테이너에서 꺼낸 DB 처럼 **믿지 못할 입력**은
//! [`read_untrusted`] 가 읽는다 — 같은 판독기를 사내 runtime-scanner 와 같은 상한으로 돌리고, 이미지 점검이 쓰는
//! 꼬리표를 패키지마다 한 번에 꺼낸다(`untrusted` 모듈 머리에 상한과 그 자리가 있다). 판독기는 하나이고 상한만
//! 다르다(`Limits`).
#![forbid(unsafe_code)]

mod bdb;
pub mod header;
mod ndb;
mod sqlite;
mod untrusted;

pub use header::{DigestAlgorithm, FileDigests, RpmHeader};
pub use untrusted::{read_untrusted, Package, Untrusted};

use std::cell::Cell;

/// 읽지 못한 까닭 — 사람이 아니라 부르는 쪽이 읽는다(관측의 *잘렸다* 로 바뀐다).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpmDbError {
    Format(&'static str),
    Limit(&'static str),
}

/// 파일 머리로 형식을 가른다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Sqlite,
    Bdb,
    Ndb,
}

pub fn detect(bytes: &[u8]) -> Option<Format> {
    if bytes.starts_with(b"SQLite format 3\0") {
        return Some(Format::Sqlite);
    }
    if bytes.starts_with(b"RpmP") {
        return Some(Format::Ndb);
    }
    let m = bytes.get(12..16)?;
    let le = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
    let be = u32::from_be_bytes([m[0], m[1], m[2], m[3]]);
    (le == 0x0006_1561 || be == 0x0006_1561).then_some(Format::Bdb)
}

/// 판독기 하나가 DB 하나에 지키는 상한. 세 형식이 같은 셋을 보고, 믿는 입력과 믿지 못할 입력은 값만 다르다.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// 기록 하나 — SQLite 는 페이로드, BDB 는 값, NDB 는 블롭의 길이. 넘으면 DB 가 틀렸다(오류).
    pub(crate) record: u64,
    /// 기록 수. 넘으면 DB 가 틀렸다(오류).
    pub(crate) records: usize,
    /// DB 하나에서 복사하는 양의 합 — 닿기 전에 멈추고 그 앞의 기록을 돌려준다([`COPIED`]).
    pub(crate) copied: u64,
}

/// 복사한 양이 [`Limits::copied`] 에 닿았다 — 그 앞의 기록은 온전하다. 슬롯 · 넘침 사슬 · 셀 여럿이 같은 자리를
/// 가리키면 파일보다 큰 값이 나오는데, 그것을 막는 자리가 여기다.
pub(crate) const COPIED: RpmDbError =
    RpmDbError::Limit("RPM DB 에서 복사한 블롭이 상한(64 MiB)을 넘었다");

/// DB 하나를 읽는 동안 복사한 양.
pub(crate) struct Copies {
    cap: u64,
    used: Cell<u64>,
}

impl Copies {
    pub(crate) fn new(cap: u64) -> Self {
        Self {
            cap,
            used: Cell::new(0),
        }
    }

    /// `n` 바이트를 복사해도 되면 세고, 안 되면 아무것도 세지 않고 [`COPIED`] 다. 복사하기 **전에** 부른다.
    pub(crate) fn take(&self, n: u64) -> Result<(), RpmDbError> {
        let used = self.used.get();
        if n > self.cap - used {
            return Err(COPIED);
        }
        self.used.set(used + n);
        Ok(())
    }
}

/// 판독기가 낸 블롭과, 복사한 양의 상한에 닿아 멈췄으면 그 까닭([`COPIED`]).
pub(crate) type Read = (Vec<Vec<u8>>, Option<RpmDbError>);

/// DB 하나의 헤더 블롭 전부 — 형식을 가려 꺼내기만 하고 헤더로 읽지는 않는다.
///
/// **이 기계의 DB 용이다**(입구가 둘이다 — 크레이트 머리). 믿지 못할 입력은 [`read_untrusted`] 가 같은 블롭을
/// 상한 안에서 읽는다. **패키지가 아닌 값도 섞여 나온다** — [`header::parse`] 가 `None` 을 내는 블롭은 패키지가
/// 아니다(아래 [`headers`] 가 세는 그것이다).
pub fn blobs(bytes: &[u8]) -> Result<Vec<Vec<u8>>, RpmDbError> {
    match detect(bytes) {
        Some(Format::Sqlite) => sqlite::blobs(bytes),
        Some(Format::Bdb) => bdb::blobs(bytes),
        Some(Format::Ndb) => ndb::blobs(bytes),
        None => Err(RpmDbError::Format("RPM DB 형식을 모른다")),
    }
}

/// [`blobs`] 와 같은 판독기를 `limits` 로 돌린다 — [`read_untrusted`] 의 길.
pub(crate) fn read_blobs(bytes: &[u8], limits: Limits) -> Result<Read, RpmDbError> {
    match detect(bytes) {
        Some(Format::Sqlite) => sqlite::read(bytes, limits),
        Some(Format::Bdb) => bdb::read(bytes, limits),
        Some(Format::Ndb) => ndb::read(bytes, limits),
        None => Err(RpmDbError::Format("RPM DB 형식을 모른다")),
    }
}

/// DB 하나의 패키지 헤더 전부. 헤더로 읽히지 않는 블롭은 센다 — rpm 은 BDB 에 패키지가 아닌
/// 값(다음 헤더 번호 등)을 함께 둔다. [`blobs`] 처럼 이 기계의 DB 용이다.
pub fn headers(bytes: &[u8]) -> Result<(Vec<RpmHeader>, usize), RpmDbError> {
    let blobs = blobs(bytes)?;
    let mut out = Vec::with_capacity(blobs.len());
    let mut skipped = 0usize;
    for b in &blobs {
        match header::parse(b) {
            Some(h) => out.push(h),
            None => skipped += 1,
        }
    }
    Ok((out, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_file_is_an_error_not_an_empty_database() {
        assert_eq!(detect(b""), None);
        assert_eq!(
            headers(b"not a database at all"),
            Err(RpmDbError::Format("RPM DB 형식을 모른다"))
        );
        assert_eq!(
            blobs(b"not a database at all"),
            Err(RpmDbError::Format("RPM DB 형식을 모른다"))
        );
    }

    #[test]
    fn copies_reach_the_cap_exactly_and_a_refusal_counts_nothing() {
        let c = Copies::new(10);
        assert_eq!(c.take(4), Ok(()));
        assert_eq!(c.take(7), Err(COPIED));
        assert_eq!(c.take(6), Ok(()));
        assert_eq!(c.take(1), Err(COPIED));
        assert_eq!(c.take(0), Ok(()));
        // 이 기계의 DB 를 읽는 쪽은 상한이 없는 것과 같다.
        assert_eq!(Copies::new(u64::MAX).take(u64::MAX), Ok(()));
    }
}
