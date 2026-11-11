//! zstd 레이어 — 프레임마다 머리를 먼저 읽어 사내 runtime-scanner 의 판독기(klauspost/compress, 창 · 메모리 상한
//! 64 MiB, 동시성 1)와 같은 규칙으로 거르고, 블록은 ruzstd 가 푼다.
//!
//! - 프레임 경계에서 데이터가 끝나면 끝이다. 1~3 바이트만 남으면 오류이고, 네 바이트 이상이면 건너뛰는 프레임이거나
//!   zstd 프레임이어야 한다.
//! - 머리의 예약 비트가 켜져 있으면 오류. 창 크기가 64 MiB 를 넘으면 오류(단일 구간 프레임은 내용 크기로 보되 1 KiB
//!   아래는 1 KiB). 사전 번호가 0 이 아니면 오류 — 사전을 주지 않는다.
//! - 머리에 내용 크기가 있으면 푼 크기가 그것과 같아야 하고, 체크섬이 있으면 맞아야 한다. ruzstd 의 스트리밍 판독기는
//!   체크섬을 대조하지 않으므로(상류 이슈 #127) 여기서 대조한다.
//!
//! ruzstd 에도 창 상한 64 MiB 를 둔다 — 위의 검사와 같은 값이라 걸리지 않지만 상한을 한 자리에만 두지 않는다. 링
//! 버퍼는 창과 블록 하나(128 KiB)를 담으므로 정상 프레임의 메모리는 64.25 MiB 안이다. 규격을 어긴 블록(한 블록이
//! 256 KiB 넘게 푸는 것)은 ruzstd 가 오류로 거르기 전에 버퍼를 한 번 두 배로 키울 수 있다 — 창이 63 MiB 를 넘는
//! 프레임에서만이고, 그때 잠깐 192 MiB 남짓이다(스캐너의 판독기는 정상 프레임에도 창의 두 배를 잡는다).

use super::fault::{find_halt, Fault};
use super::tarball::read_full;
use ruzstd::decoding::errors::FrameDecoderError;
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use std::io::{self, Read};

const MAX_WINDOW: u64 = 64 << 20;
const MIN_WINDOW: u64 = 1 << 10;
const MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

pub(super) struct Zstd<R> {
    src: R,
    dec: FrameDecoder,
    frame: Option<Frame>,
}

/// 지금 푸는 프레임.
struct Frame {
    content: Option<u64>,
    checksum: bool,
    out: u64,
}

impl<R: Read> Zstd<R> {
    pub(super) fn new(src: R) -> Self {
        let mut dec = FrameDecoder::new();
        dec.set_max_window_size(MAX_WINDOW);
        Zstd {
            src,
            dec,
            frame: None,
        }
    }

    /// 다음 zstd 프레임의 머리까지 읽는다. 데이터가 끝났으면 거짓.
    fn next_frame(&mut self) -> io::Result<bool> {
        loop {
            let mut magic = [0u8; 4];
            match read_full(&mut self.src, &mut magic)? {
                0 => return Ok(false),
                4 => {}
                _ => return Err(io::ErrorKind::UnexpectedEof.into()),
            }
            if magic[1..] == [0x2a, 0x4d, 0x18] && magic[0] & 0xf0 == 0x50 {
                self.skip_frame()?;
                continue;
            }
            if magic != MAGIC {
                return Err(Fault::ZstdHeader.into());
            }
            self.start()?;
            return Ok(true);
        }
    }

    fn skip_frame(&mut self) -> io::Result<()> {
        let mut len = [0u8; 4];
        if read_full(&mut self.src, &mut len)? != 4 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let n = u64::from(u32::from_le_bytes(len));
        let skipped = io::copy(&mut (&mut self.src).take(n), &mut io::sink())?;
        if skipped != n {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }

    /// 마법 글자 뒤의 머리를 읽어 거르고, 같은 머리를 ruzstd 에 넘긴다.
    fn start(&mut self) -> io::Result<()> {
        let mut header = MAGIC.to_vec();
        let fhd = self.field(&mut header, 1)? as u8;
        if fhd & 0x08 != 0 {
            return Err(Fault::ZstdHeader.into());
        }
        let single = fhd & 0x20 != 0;
        let window = if single {
            0
        } else {
            let wd = self.field(&mut header, 1)?;
            let base = 1u64 << (10 + (wd >> 3));
            base + base / 8 * (wd & 7)
        };
        let dictionary = self.field(&mut header, [0, 1, 2, 4][usize::from(fhd & 3)])?;
        let content = match fhd >> 6 {
            0 if !single => None,
            0 => Some(self.field(&mut header, 1)?),
            1 => Some(self.field(&mut header, 2)? + 256),
            v => Some(self.field(&mut header, 1 << v)?),
        };
        if window > MAX_WINDOW {
            return Err(Fault::ZstdWindow.into());
        }
        if single && content.unwrap_or(0).max(MIN_WINDOW) > MAX_WINDOW {
            return Err(Fault::ZstdSegment.into());
        }
        if dictionary != 0 {
            return Err(Fault::ZstdDictionary.into());
        }
        self.dec
            .reset(header.as_slice())
            .map_err(|e| decode_error(&e))?;
        self.frame = Some(Frame {
            content,
            checksum: fhd & 0x04 != 0,
            out: 0,
        });
        Ok(())
    }

    /// 머리의 작은 정수 칸 하나(리틀 엔디언) — 읽은 바이트는 `header` 에도 붙인다.
    fn field(&mut self, header: &mut Vec<u8>, len: usize) -> io::Result<u64> {
        let mut b = [0u8; 8];
        if read_full(&mut self.src, &mut b[..len])? != len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        header.extend_from_slice(&b[..len]);
        Ok(u64::from_le_bytes(b))
    }

    /// 지금 프레임에서 꺼낼 수 있는 만큼 — 0 이면 그 프레임이 끝났다.
    fn fill(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.dec.can_collect() == 0 && !self.dec.is_finished() {
            self.dec
                .decode_blocks(&mut self.src, BlockDecodingStrategy::UptoBlocks(1))
                .map_err(|e| decode_error(&e))?;
        }
        let n = self.dec.read(buf)?;
        if let Some(frame) = self.frame.as_mut() {
            frame.out += n as u64;
            if frame.content.is_some_and(|c| frame.out > c) {
                return Err(Fault::ZstdFrameSize.into());
            }
        }
        Ok(n)
    }

    /// 끝난 프레임의 내용 크기와 체크섬.
    fn finish_frame(&mut self) -> io::Result<()> {
        let Some(frame) = self.frame.take() else {
            return Ok(());
        };
        if frame.content.is_some_and(|c| c != frame.out) {
            return Err(Fault::ZstdFrameSize.into());
        }
        if frame.checksum {
            let stored = self.dec.get_checksum_from_data();
            if stored.is_none() || stored != self.dec.get_calculated_checksum() {
                return Err(Fault::ZstdChecksum.into());
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for Zstd<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.frame.is_none() && !self.next_frame()? {
                return Ok(0);
            }
            let n = self.fill(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.finish_frame()?;
        }
    }
}

/// ruzstd 의 오류 — 그 안에 한도 · 취소가 실려 있으면 그것을, 아니면 손상으로.
fn decode_error(e: &FrameDecoderError) -> io::Error {
    match find_halt(e) {
        Some(halt) => Fault::Halted(halt).into(),
        None => Fault::Zstd.into(),
    }
}
