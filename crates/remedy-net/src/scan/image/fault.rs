//! 이미지를 읽다 멈춘 까닭 — 읽기 오류(`io::Error`)에 실어 올린 뒤 *보지 못한 것* 의 문장으로 바꾼다.
//!
//! 스캐너는 라이브러리의 영어 오류 글(`gzip: invalid checksum` · `window size exceeded` …)을 그대로 *보지 못한 것*
//! 에 넣었다. 여기서는 종류마다 정해 둔 두 언어 문장을 쓴다 — 고객 화면에 라이브러리의 글이 섞이지 않게.

use crate::scan::budget::Halt;
use remedy_sdk::i18n::Lang;
use std::fmt;
use std::io;

/// 읽기 오류의 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    /// 한도 · 취소 · 시한 — 압축 판독기 안에서 올라와 원래 꼴을 잃은 것을 되살린 것.
    Halted(Halt),
    TarHeader,
    TarFieldTooLong,
    TrailingData,
    GzipDeclared,
    ZstdDeclared,
    Gzip,
    ZstdWindow,
    ZstdSegment,
    ZstdHeader,
    ZstdDictionary,
    ZstdFrameSize,
    ZstdChecksum,
    Zstd,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message(Lang::Ko))
    }
}

impl std::error::Error for Fault {}

impl From<Fault> for io::Error {
    fn from(f: Fault) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, f)
    }
}

impl Fault {
    pub(super) fn message(self, lang: Lang) -> String {
        let (ko, en) = match self {
            Fault::Halted(halt) => return halt.message(lang),
            Fault::TarHeader => ("tar 머리가 올바르지 않습니다", "invalid tar header"),
            Fault::TarFieldTooLong => (
                "tar 의 긴 이름 또는 PAX 머리가 1 MiB 를 넘습니다",
                "a tar long name or PAX header is larger than 1 MiB",
            ),
            Fault::TrailingData => (
                "tar 종료 표시 뒤에 추가 데이터가 있습니다",
                "there is extra data after the tar end marker",
            ),
            Fault::GzipDeclared => (
                "gzip 레이어로 선언했지만 실제 데이터는 gzip 이 아닙니다",
                "the layer is declared as gzip but its data is not gzip",
            ),
            Fault::ZstdDeclared => (
                "zstd 레이어로 선언했지만 실제 데이터는 zstd 가 아닙니다",
                "the layer is declared as zstd but its data is not zstd",
            ),
            Fault::Gzip => (
                "gzip 압축 데이터를 풀지 못했습니다(손상 · 체크섬 불일치 · 중간에 끝남)",
                "could not expand the gzip data (damaged, checksum mismatch or cut short)",
            ),
            Fault::ZstdWindow => (
                "zstd 프레임의 압축 창(window) 크기가 64 MiB 한도를 넘습니다",
                "the zstd frame's window size exceeds the 64 MiB limit",
            ),
            Fault::ZstdSegment => (
                "zstd 단일 구간 프레임의 크기가 64 MiB 한도를 넘습니다",
                "the zstd single-segment frame exceeds the 64 MiB limit",
            ),
            Fault::ZstdHeader => (
                "zstd 프레임 머리가 올바르지 않습니다",
                "invalid zstd frame header",
            ),
            Fault::ZstdDictionary => (
                "사전이 필요한 zstd 프레임은 풀지 않습니다",
                "zstd frames that need a dictionary are not expanded",
            ),
            Fault::ZstdFrameSize => (
                "zstd 프레임을 푼 크기가 머리에 적힌 크기와 다릅니다",
                "the expanded size of a zstd frame differs from its header",
            ),
            Fault::ZstdChecksum => (
                "zstd 프레임의 체크섬이 맞지 않습니다",
                "a zstd frame checksum does not match",
            ),
            Fault::Zstd => (
                "zstd 압축 데이터를 풀지 못했습니다(손상 또는 중간에 끝남)",
                "could not expand the zstd data (damaged or cut short)",
            ),
        };
        lang.t(ko, en).to_string()
    }
}

/// 원인 사슬을 따라 내려가 한도 · 취소를 찾는다 — 압축 판독기가 읽기 오류를 제 오류로 감싸 올려도 찾는다.
/// `io::Error` 의 `source` 는 실어 둔 오류를 건너뛰므로 그 자리는 실린 것으로 직접 내려간다.
pub(super) fn find_halt(err: &(dyn std::error::Error + 'static)) -> Option<Halt> {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(Fault::Halted(halt)) = e.downcast_ref::<Fault>() {
            return Some(*halt);
        }
        cur = match e.downcast_ref::<io::Error>() {
            Some(io) => match Halt::from_io(io) {
                Some(halt) => return Some(halt),
                None => io
                    .get_ref()
                    .map(|inner| inner as &(dyn std::error::Error + 'static)),
            },
            None => e.source(),
        };
    }
    None
}

/// 읽기 오류를 문장으로.
pub(super) fn describe(err: &io::Error, lang: Lang) -> String {
    if let Some(halt) = find_halt(err) {
        return halt.message(lang);
    }
    if let Some(fault) = err.get_ref().and_then(|e| e.downcast_ref::<Fault>()) {
        return fault.message(lang);
    }
    let words = if err.kind() == io::ErrorKind::UnexpectedEof {
        (
            "이미지 데이터가 중간에 끝났습니다",
            "the image data ended early",
        )
    } else {
        (
            "이미지 데이터를 읽지 못했습니다",
            "could not read the image data",
        )
    };
    lang.t(words.0, words.1).to_string()
}
