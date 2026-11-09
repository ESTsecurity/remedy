//! RPM 패키지 DB 를 파일로 읽는다 — SQLite(RHEL 9 · Fedora) · Berkeley DB(RHEL 7 · 8 · CentOS) ·
//! NDB(SUSE) (2026-11-09).
//!
//! # rpm 을 부르지 않는다
//!
//! dpkg · apk 와 같은 까닭이다(`package.rs`) — 수집 중 자식 프로세스 0. 세 형식 모두 **읽는 쪽 일부만**
//! 구현했고(형식마다 모듈 머리에 무엇을 읽는지 적었다), 쓰지 않는다. 디스크에서 온 바이트라 모든 자리를
//! 범위로 확인하고, 모르는 모양은 오류로 돌려 부르는 쪽이 *잘렸다* 로 말하게 한다 — 조용히 0건이 되면
//! 그 기계는 *"패키지가 없다"* 가 된다.
//!
//! # 실물 대조 (2026-11-09)
//!
//! 컨테이너에서 꺼낸 DB 넷을 같은 컨테이너의 `rpm -qa` 와 견줬다 — 이름 · `epoch:판-개정` · 아키텍처 · 공급사가
//! 모두 같았다(`gpg-pubkey` 제외): Rocky 9(SQLite) 157 · CentOS 7(BDB) 148 · Oracle Linux 8(BDB) 200 ·
//! openSUSE Leap 15.6(NDB) 140. DB 하나를 읽는 데 6~11 ms 였다(디버그 빌드).

mod bdb;
pub mod header;
mod ndb;
mod sqlite;

pub use header::RpmHeader;

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

/// DB 하나의 패키지 헤더 전부. 헤더로 읽히지 않는 블롭은 센다 — rpm 은 BDB 에 패키지가 아닌
/// 값(다음 헤더 번호 등)을 함께 둔다.
pub fn headers(bytes: &[u8]) -> Result<(Vec<RpmHeader>, usize), RpmDbError> {
    let blobs = match detect(bytes) {
        Some(Format::Sqlite) => sqlite::blobs(bytes)?,
        Some(Format::Bdb) => bdb::blobs(bytes)?,
        Some(Format::Ndb) => ndb::blobs(bytes)?,
        None => return Err(RpmDbError::Format("RPM DB 형식을 모른다")),
    };
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
    }
}
