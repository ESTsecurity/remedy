//! 압축 풀기 — 앞 네 바이트로 gzip · zstd · 압축 없음을 가르고, 매니페스트가 선언한 형식과 다르면 멈춘다(스캐너의
//! `expandedReader`).
//!
//! gzip 은 여러 멤버를 이어 푼다(Go 의 `gzip.Reader` 처럼 멤버 뒤에 데이터가 더 있으면 다음 멤버의 머리여야 한다).
//! 머리 규칙에 두 군데 차이가 있다 — flate2 는 예약 플래그 비트가 켜진 머리를 거절하고(Go 는 받는다), 파일 이름 ·
//! 주석 칸을 64 KiB 까지 받는다(Go 는 511 바이트). 둘 다 정상 기록기가 쓰지 않는 꼴이다.
//!
//! 푼 바이트는 *압축을 푼 양* 으로 센다. 압축 없는 레이어도 그렇다 — 스캐너가 읽은 양과 푼 양을 같은 자리에서 센다.

use super::fault::{find_halt, Fault};
use super::tarball::read_full;
use super::zstd::Zstd;
use crate::scan::budget::{Budget, ReadKind};
use flate2::bufread::MultiGzDecoder;
use std::io::{self, BufReader, Read};

/// 압축 판독기의 버퍼 — Go 의 `bufio.NewReaderSize(raw, 32<<10)`.
const BUFFER: usize = 32 << 10;

/// 푼 바이트를 읽는 리더. `media` 는 매니페스트가 선언한 형식(docker save 는 빈 글).
pub(super) fn expanded<'b, R: Read + 'b>(
    mut raw: R,
    budget: &'b Budget,
    media: &str,
) -> io::Result<Box<dyn Read + 'b>> {
    let mut head = [0u8; 4];
    let n = read_full(&mut raw, &mut head)?;
    let gzip = n >= 2 && head[..2] == [0x1f, 0x8b];
    let zstd = n == 4 && head == [0x28, 0xb5, 0x2f, 0xfd];
    if (media.ends_with("+gzip") || media.ends_with(".gzip")) && !gzip {
        return Err(Fault::GzipDeclared.into());
    }
    if media.ends_with("+zstd") && !zstd {
        return Err(Fault::ZstdDeclared.into());
    }
    let src = BufReader::with_capacity(BUFFER, io::Cursor::new(head).take(n as u64).chain(raw));
    let out: Box<dyn Read + 'b> = if gzip {
        Box::new(budget.wrap_reader(Gzip(MultiGzDecoder::new(src)), ReadKind::ImageExpanded))
    } else if zstd {
        Box::new(budget.wrap_reader(Zstd::new(src), ReadKind::ImageExpanded))
    } else {
        Box::new(budget.wrap_reader(src, ReadKind::ImageExpanded))
    };
    Ok(out)
}

/// gzip 판독기의 오류를 한 가지 문장으로 — 한도 · 취소는 그대로 올린다.
struct Gzip<R>(R);

impl<R: Read> Read for Gzip<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(|e| match find_halt(&e) {
            Some(_) => e,
            None => Fault::Gzip.into(),
        })
    }
}

/// tar 의 끝 뒤 — 0 바이트만 와야 한다(스캐너의 `zeroPaddingWriter`). 압축 스트림을 끝까지 읽어 gzip 체크섬 ·
/// zstd 프레임 끝도 이때 확인된다.
pub(super) fn drain_zeros(r: &mut dyn Read) -> io::Result<()> {
    let mut buf = vec![0u8; BUFFER];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf[..n].iter().any(|&b| b != 0) {
            return Err(Fault::TrailingData.into());
        }
    }
}
