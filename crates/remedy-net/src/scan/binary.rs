//! 실행 파일의 머리만 읽는다 — ELF 의 적재 구간과 동적 의존(DT_NEEDED), PE 의 섹션 범위, Node.js 가 실어 둔 버전 글자.
//!
//! 사내 runtime-scanner 의 `internal/images/binary.go` · `packages.go` 의 `validRuntimeBinary` ·
//! `internal/containers/pe.go` 를 옮겼다. 이미지 점검과 컨테이너 점검이 함께 쓴다.
//!
//! **실행 파일을 싣거나 실행하지 않는다.** 앞부분(보통 8 MiB)과 파일 전체 크기만 받아, 머리가 가리키는 범위가
//! 파일 안에 드는지를 본다. 동적 문자열표가 받은 앞부분 밖에 있으면 의존을 *끝까지 확인하지 못함* 으로 낸다.
//! 버전 글자는 누가 지었는지를 말하지 않으므로 판정의 근거가 아니라 보조 단서다.

use super::linuxmeta::ElfIdentity;
use super::slashpath;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// 바이트에서 읽은 것만 담는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticBinary {
    /// 실행 파일 안의 버전 글자(`node.js/vX.Y.Z` · `\0vX.Y.Z\0`)가 한 가지로만 나올 때 그 값 — 앞의 `v` 는 뗀다.
    pub version: Option<String>,
    /// 동적 의존(DT_NEEDED)의 이름 — 적힌 차례.
    pub needed: Vec<String>,
    /// 동적 의존을 끝까지 읽었다. 거짓이면 `needed` 를 믿지 않는다.
    pub dependencies_complete: bool,
    pub elf: ElfIdentity,
    /// ELF 의 적재 구간 또는 PE 의 섹션이 파일 크기 안에 든다.
    pub valid: bool,
}

fn node_version_pattern() -> &'static regex::bytes::Regex {
    static RE: OnceLock<regex::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::bytes::Regex::new(
            r"(?-u)(?:\x00|node\.js/)(v?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\x00",
        )
        .expect("고정된 정규식")
    })
}

fn node_name_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:node(?:js)?(?:[0-9]+)?(?:\.exe)?|libnode\.(?:so(?:\.[0-9]+)*|dll|dylib))$",
        )
        .expect("고정된 정규식")
    })
}

fn brotli_name_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:libbrotlidec(?:oder)?\.(?:so(?:\.[0-9]+)*|dll|dylib)|brotlidec(?:oder)?\.dll)$",
        )
        .expect("고정된 정규식")
    })
}

/// 파일 이름이 Node.js 실행 파일 · `libnode` 의 꼴이다(대소문자 무시 · 마지막 요소만 본다).
pub fn is_node_runtime(path: &str) -> bool {
    node_name_pattern().is_match(slashpath::base(path))
}

/// 파일 이름이 Brotli 디코더 라이브러리의 꼴이다(대소문자 무시 · 마지막 요소만 본다).
pub fn is_brotli_decoder(path: &str) -> bool {
    brotli_name_pattern().is_match(slashpath::base(path))
}

/// 앞부분이 ELF 또는 MZ(PE) 의 머리로 시작한다.
pub fn binary_magic(data: &[u8]) -> bool {
    data.starts_with(b"\x7fELF") || data.starts_with(b"MZ")
}

/// Node.js 실행 파일을 읽는다. `prefix` 는 파일의 앞부분, `size` 는 파일 전체 크기.
pub fn inspect_node_binary(prefix: &[u8], size: u64) -> StaticBinary {
    let mut versions = BTreeSet::new();
    for caps in node_version_pattern().captures_iter(prefix).take(32) {
        let text = String::from_utf8_lossy(&caps[1]).into_owned();
        versions.insert(text.trim_start_matches('v').to_string());
    }
    let version = if versions.len() == 1 {
        versions.into_iter().next()
    } else {
        None
    };
    let (needed, complete) = match elf_dependencies(prefix, size) {
        Some(n) => (n, true),
        None => (Vec::new(), false),
    };
    StaticBinary {
        version,
        needed,
        dependencies_complete: complete,
        elf: ElfIdentity::parse(prefix),
        valid: valid_runtime_binary(prefix, size),
    }
}

/// 실행 파일의 머리가 온전하다 — ELF 면 적재 구간이, PE 면 섹션이 파일 크기 안에 든다. 실행 파일 이름을 가진
/// 문서 · 스크립트를 실행 파일로 세지 않으려고 쓴다.
pub fn valid_runtime_binary(data: &[u8], size: u64) -> bool {
    if data.starts_with(b"\x7fELF") {
        return elf_layout(data, size).is_some();
    }
    loose_pe(data, size).is_some()
}

/// PE 머리를 엄격하게 본다 — 컨테이너에서 받은 Windows 실행 파일에 쓴다. 실행 이미지 표시 · 알려진 기계 ·
/// 선택 머리 크기 · 섹션 수(96 까지) · 섹션이 파일 안에 드는지.
pub fn valid_pe(prefix: &[u8], size: u64) -> bool {
    strict_pe(prefix, size).is_some()
}

#[derive(Debug, Clone, Copy)]
struct Segment {
    offset: u64,
    address: u64,
    size: u64,
}

#[derive(Debug)]
struct ElfLayout {
    little: bool,
    wide: bool,
    loads: Vec<Segment>,
    dynamic: Option<Segment>,
}

/// 머리에서 읽는 정수. 범위를 넘으면 `None` — 위에서 범위를 확인했더라도 여기서 한 번 더 막는다.
struct Bytes<'a> {
    data: &'a [u8],
    little: bool,
}

impl Bytes<'_> {
    fn take<const N: usize>(&self, at: u64) -> Option<[u8; N]> {
        let start = usize::try_from(at).ok()?;
        let end = start.checked_add(N)?;
        self.data.get(start..end)?.try_into().ok()
    }
    fn u16(&self, at: u64) -> Option<u64> {
        let b = self.take::<2>(at)?;
        Some(u64::from(if self.little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }))
    }
    fn u32(&self, at: u64) -> Option<u64> {
        let b = self.take::<4>(at)?;
        Some(u64::from(if self.little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }))
    }
    fn u64(&self, at: u64) -> Option<u64> {
        let b = self.take::<8>(at)?;
        Some(if self.little {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }
}

/// ELF 의 프로그램 머리 — 실행 파일(EXEC) · 공유 객체(DYN)만, 적재 구간이 하나 이상, 동적 구간은 많아야 하나,
/// 모든 구간이 파일 전체 크기 안에 든다. 동적 문자열이나 섹션 표는 받은 앞부분 밖에 있어도 된다.
fn elf_layout(data: &[u8], size: u64) -> Option<ElfLayout> {
    let len = data.len() as u64;
    if data.len() < 52 || !data.starts_with(b"\x7fELF") || data[6] != 1 || size < len {
        return None;
    }
    let little = match data[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    let wide = match data[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let b = Bytes { data, little };
    let kind = b.u16(16)?;
    if kind != 2 && kind != 3 {
        return None;
    }
    if b.u32(20)? != 1 {
        return None;
    }
    let (phoff, entry_size, count, min_entry) = if wide {
        if data.len() < 64 {
            return None;
        }
        (b.u64(32)?, b.u16(54)?, b.u16(56)?, 56)
    } else {
        (b.u32(28)?, b.u16(42)?, b.u16(44)?, 32)
    };
    if count == 0
        || count > 4096
        || entry_size < min_entry
        || phoff > len
        || count > (len - phoff) / entry_size
    {
        return None;
    }
    let mut layout = ElfLayout {
        little,
        wide,
        loads: Vec::new(),
        dynamic: None,
    };
    for i in 0..count {
        let off = phoff + i * entry_size;
        let kind = b.u32(off)?;
        let s = if wide {
            Segment {
                offset: b.u64(off + 8)?,
                address: b.u64(off + 16)?,
                size: b.u64(off + 32)?,
            }
        } else {
            Segment {
                offset: b.u32(off + 4)?,
                address: b.u32(off + 8)?,
                size: b.u32(off + 16)?,
            }
        };
        if s.offset > size || s.size > size - s.offset {
            return None;
        }
        match kind {
            1 => layout.loads.push(s),
            2 => {
                if layout.dynamic.is_some() {
                    return None;
                }
                layout.dynamic = Some(s);
            }
            _ => {}
        }
    }
    if layout.loads.is_empty() {
        return None;
    }
    Some(layout)
}

/// 동적 의존의 이름. `None` 은 *끝까지 확인하지 못함* — 동적 구간이나 문자열표가 받은 앞부분 밖에 있다, 표가
/// 끝나지 않는다(DT_NULL 없음), 검색 경로를 바꾼다(RPATH · RUNPATH), 이름이 이상하다. 동적 구간이 없거나
/// 의존이 없으면 빈 목록(끝까지 확인함)이다.
fn elf_dependencies(data: &[u8], size: u64) -> Option<Vec<String>> {
    let layout = elf_layout(data, size)?;
    let Some(dynamic) = layout.dynamic else {
        return Some(Vec::new());
    };
    let len = data.len() as u64;
    if dynamic.offset > len || dynamic.size > len - dynamic.offset {
        return None;
    }
    let b = Bytes {
        data,
        little: layout.little,
    };
    let stride: u64 = if layout.wide { 16 } else { 8 };
    if dynamic.size % stride != 0 || dynamic.size / stride > 65536 {
        return None;
    }
    let mut offsets: Vec<u64> = Vec::new();
    let (mut str_address, mut str_size) = (0u64, 0u64);
    let mut ended = false;
    let mut custom_search = false;
    let mut pos = dynamic.offset;
    while pos < dynamic.offset + dynamic.size {
        let (tag, value) = if layout.wide {
            (b.u64(pos)?, b.u64(pos + 8)?)
        } else {
            (b.u32(pos)?, b.u32(pos + 4)?)
        };
        match tag {
            0 => ended = true,
            1 => {
                if offsets.len() >= 128 {
                    return None;
                }
                offsets.push(value);
            }
            5 => str_address = value,
            10 => str_size = value,
            15 | 29 => custom_search = true,
            _ => {}
        }
        if ended {
            break;
        }
        pos += stride;
    }
    if !ended {
        return None;
    }
    if offsets.is_empty() {
        return Some(Vec::new());
    }
    if custom_search || str_size == 0 {
        return None;
    }
    let str_offset = layout.loads.iter().find_map(|load| {
        let inside = str_address >= load.address
            && str_address - load.address <= load.size
            && str_size <= load.size - (str_address - load.address);
        inside.then(|| load.offset + (str_address - load.address))
    })?;
    if str_offset > len || str_size > len - str_offset {
        return None;
    }
    let table =
        data.get(usize::try_from(str_offset).ok()?..usize::try_from(str_offset + str_size).ok()?)?;
    let mut needed = Vec::with_capacity(offsets.len());
    for off in offsets {
        if off >= str_size {
            return None;
        }
        let text = table.get(usize::try_from(off).ok()?..)?;
        let end = text.iter().position(|&c| c == 0)?;
        if end == 0 || end > 255 {
            return None;
        }
        let name = std::str::from_utf8(&text[..end]).ok()?;
        if name == "." || name == ".." || name != slashpath::base(name) || name.contains('\\') {
            return None;
        }
        needed.push(name.to_string());
    }
    Some(needed)
}

/// 느슨한 PE 확인 — 이미지 안의 PHP · Node 실행 파일에 쓴다. 섹션 수 4096 까지 · 선택 머리의 마법 수가
/// PE32 · PE32+ · 섹션이 파일 안에 든다.
fn loose_pe(data: &[u8], size: u64) -> Option<()> {
    let len = data.len() as u64;
    if data.len() < 64 || !data.starts_with(b"MZ") || size < len {
        return None;
    }
    let b = Bytes { data, little: true };
    let off = b.u32(60)?;
    if off > len || len - off < 24 || b.take::<4>(off)? != *b"PE\0\0" {
        return None;
    }
    let sections = b.u16(off + 6)?;
    let optional = b.u16(off + 20)?;
    let start = off + 24 + optional;
    if sections == 0
        || sections > 4096
        || optional < 2
        || start > len
        || sections > (len - start) / 40
    {
        return None;
    }
    let magic = b.u16(off + 24)?;
    if magic != 0x10b && magic != 0x20b {
        return None;
    }
    section_ranges(&b, start, sections, size)
}

/// 엄격한 PE 확인 — [`valid_pe`].
fn strict_pe(prefix: &[u8], size: u64) -> Option<()> {
    let len = prefix.len() as u64;
    if prefix.len() < 64 || size < len || !prefix.starts_with(b"MZ") {
        return None;
    }
    let b = Bytes {
        data: prefix,
        little: true,
    };
    let offset = b.u32(60)?;
    if offset < 64 || offset + 24 > len || b.take::<4>(offset)? != *b"PE\0\0" {
        return None;
    }
    let machine = b.u16(offset + 4)?;
    let count = b.u16(offset + 6)?;
    let optional = b.u16(offset + 20)?;
    let characteristics = b.u16(offset + 22)?;
    if count == 0
        || count > 96
        || characteristics & 2 == 0
        || optional < 224
        || offset + 24 + optional + count * 40 > len
    {
        return None;
    }
    let magic = b.u16(offset + 24)?;
    let machine_ok = match magic {
        0x10b => machine == 0x14c || machine == 0x1c4,
        0x20b => optional >= 240 && (machine == 0x8664 || machine == 0xaa64),
        _ => false,
    };
    if !machine_ok {
        return None;
    }
    section_ranges(&b, offset + 24 + optional, count, size)
}

/// 섹션 표의 원시 자료 범위(`SizeOfRawData` · `PointerToRawData`)가 파일 크기 안에 드는지.
fn section_ranges(b: &Bytes<'_>, start: u64, count: u64, size: u64) -> Option<()> {
    for i in 0..count {
        let section = start + i * 40;
        let length = b.u32(section + 16)?;
        let pos = b.u32(section + 20)?;
        if pos > size || length > size - pos {
            return None;
        }
    }
    Some(())
}

/// 시험 자료 — 이미지 · 컨테이너 시험이 함께 쓴다. 원본 시험의 픽스처와 같은 바이트를 짓는다.
#[cfg(test)]
pub(crate) mod fixtures {
    fn put16(d: &mut [u8], at: usize, v: u16) {
        d[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(d: &mut [u8], at: usize, v: u32) {
        d[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(d: &mut [u8], at: usize, v: u64) {
        d[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// 4096 바이트 ELF64 x86-64 — 적재 구간 하나 · 동적 구간 하나 · 주어진 DT_NEEDED · 2048 자리에 `\0v22.99.0\0`.
    pub(crate) fn elf(needed: &[&str]) -> Vec<u8> {
        let mut d = vec![0u8; 4096];
        d[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        put16(&mut d, 16, 2);
        put16(&mut d, 18, 62);
        put32(&mut d, 20, 1);
        put64(&mut d, 32, 64);
        put16(&mut d, 54, 56);
        put16(&mut d, 56, 2);
        put32(&mut d, 64, 1);
        put64(&mut d, 64 + 32, 4096);
        put32(&mut d, 120, 2);
        put64(&mut d, 120 + 8, 256);
        put64(&mut d, 120 + 32, ((needed.len() + 3) * 16) as u64);
        put64(&mut d, 256, 5);
        put64(&mut d, 264, 1024);
        let mut strings = 1usize;
        for (i, name) in needed.iter().enumerate() {
            put64(&mut d, 288 + i * 16, 1);
            put64(&mut d, 296 + i * 16, strings as u64);
            d[1024 + strings..1024 + strings + name.len()].copy_from_slice(name.as_bytes());
            strings += name.len() + 1;
        }
        put64(&mut d, 272, 10);
        put64(&mut d, 280, strings as u64);
        d[2048..2048 + 10].copy_from_slice(b"\x00v22.99.0\x00");
        d
    }

    /// 128 바이트 ELF64 x86-64 — 적재 구간 하나 · 동적 구간 없음.
    pub(crate) fn minimal_elf64() -> Vec<u8> {
        let mut d = vec![0u8; 128];
        d[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        put16(&mut d, 16, 2);
        put16(&mut d, 18, 62);
        put32(&mut d, 20, 1);
        put64(&mut d, 32, 64);
        put16(&mut d, 54, 56);
        put16(&mut d, 56, 1);
        put32(&mut d, 64, 1);
        put64(&mut d, 96, 128);
        d
    }

    /// 128 바이트 ELF32 i386 — 적재 구간 하나 · 동적 구간 없음.
    pub(crate) fn minimal_elf32() -> Vec<u8> {
        let mut d = vec![0u8; 128];
        d[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
        put16(&mut d, 16, 2);
        put16(&mut d, 18, 3);
        put32(&mut d, 20, 1);
        put32(&mut d, 28, 52);
        put16(&mut d, 40, 52);
        put16(&mut d, 42, 32);
        put16(&mut d, 44, 1);
        put32(&mut d, 52, 1);
        put32(&mut d, 68, 128);
        d
    }

    /// 1024 바이트 PE32 — 섹션 하나(512 자리부터 512 바이트) · 그 자리에 `PHP/<버전>\0`. 느슨한 확인만 지난다.
    pub(crate) fn php_core_pe(version: &str) -> Vec<u8> {
        let mut d = vec![0u8; 1024];
        d[..2].copy_from_slice(b"MZ");
        put32(&mut d, 60, 64);
        d[64..68].copy_from_slice(b"PE\0\0");
        put16(&mut d, 70, 1);
        put16(&mut d, 84, 224);
        put16(&mut d, 88, 0x10b);
        put32(&mut d, 312 + 16, 512);
        put32(&mut d, 312 + 20, 512);
        let text = format!("PHP/{version}\0");
        d[512..512 + text.len()].copy_from_slice(text.as_bytes());
        d
    }

    /// 4096 바이트 PE32+ x86-64 실행 이미지 — 섹션 하나 · 1024 자리에 `marker`. 엄격한 확인도 지난다.
    pub(crate) fn container_pe(marker: &str) -> Vec<u8> {
        let mut d = vec![0u8; 4096];
        d[..2].copy_from_slice(b"MZ");
        put32(&mut d, 60, 128);
        d[128..132].copy_from_slice(b"PE\0\0");
        put16(&mut d, 132, 0x8664);
        put16(&mut d, 134, 1);
        put16(&mut d, 148, 240);
        put16(&mut d, 150, 2);
        put16(&mut d, 152, 0x20b);
        d[392..398].copy_from_slice(b".rdata");
        put32(&mut d, 404, 0x1000);
        put32(&mut d, 408, 4096 - 512);
        put32(&mut d, 412, 512);
        d[1024..1024 + marker.len()].copy_from_slice(marker.as_bytes());
        d
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    /// 원본 `TestStaticELFDependenciesRequireCompleteDynamicData`.
    #[test]
    fn static_elf_dependencies_require_complete_dynamic_data() {
        let data = elf(&["libnode.so.115", "libc.so.6"]);
        let info = inspect_node_binary(&data, data.len() as u64);
        assert!(info.dependencies_complete, "{info:?}");
        assert_eq!(info.needed, vec!["libnode.so.115", "libc.so.6"]);
        assert_eq!(info.version.as_deref(), Some("22.99.0"));
        assert!(info.valid);
        assert!(info.elf.valid());

        // 문자열표가 받은 앞부분 밖으로 잘렸다.
        assert!(!inspect_node_binary(&data[..1025], data.len() as u64).dependencies_complete);
        // 버전 글자뿐인 가짜 ELF.
        assert!(!inspect_node_binary(b"\x7fELF\x00v22.99.0\x00", 16).dependencies_complete);
        // 동적 구간의 자리가 넘친다.
        let mut invalid = data.clone();
        invalid[120 + 8..120 + 16].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
        assert!(!inspect_node_binary(&invalid, invalid.len() as u64).dependencies_complete);
    }

    #[test]
    fn no_dynamic_segment_means_complete_without_dependencies() {
        for data in [minimal_elf64(), minimal_elf32()] {
            let info = inspect_node_binary(&data, data.len() as u64);
            assert!(info.dependencies_complete);
            assert!(info.needed.is_empty());
            assert!(info.valid);
            assert_eq!(info.version, None);
        }
    }

    #[test]
    fn two_different_version_strings_give_no_version() {
        let mut data = elf(&[]);
        data[3000..3010].copy_from_slice(b"\x00v22.98.0\x00");
        assert_eq!(inspect_node_binary(&data, data.len() as u64).version, None);
        // 같은 버전이 두 번이면 하나다 — `node.js/` 꼴도 같은 것으로 센다.
        let mut same = elf(&[]);
        same[3000..3016].copy_from_slice(b"node.js/v22.99.0");
        same[3016] = 0;
        assert_eq!(
            inspect_node_binary(&same, same.len() as u64)
                .version
                .as_deref(),
            Some("22.99.0")
        );
    }

    #[test]
    fn search_path_overrides_and_odd_names_are_not_complete() {
        // DT_RUNPATH(29) 를 DT_NEEDED 뒤에 넣는다 — 의존이 있으면 끝까지 확인하지 못한 것으로 본다.
        let mut runpath = elf(&["libnode.so.115"]);
        runpath[288 + 16..288 + 24].copy_from_slice(&29u64.to_le_bytes());
        runpath[296 + 16..296 + 24].copy_from_slice(&0u64.to_le_bytes());
        let info = inspect_node_binary(&runpath, runpath.len() as u64);
        assert!(!info.dependencies_complete);

        let slash = elf(&["../libnode.so"]);
        assert!(!inspect_node_binary(&slash, slash.len() as u64).dependencies_complete);
        let backslash = elf(&["a\\b.so"]);
        assert!(!inspect_node_binary(&backslash, backslash.len() as u64).dependencies_complete);
        let dots = elf(&[".."]);
        assert!(!inspect_node_binary(&dots, dots.len() as u64).dependencies_complete);
    }

    #[test]
    fn a_segment_beyond_the_file_size_is_invalid() {
        let data = elf(&["libc.so.6"]);
        // 앞부분은 4096 바이트지만 파일 전체가 그보다 작다고 하면 머리부터 맞지 않는다.
        assert!(!valid_runtime_binary(&data, 100));
        assert!(valid_runtime_binary(&data, data.len() as u64));
        assert!(valid_runtime_binary(&data, 1 << 30));
    }

    #[test]
    fn runtime_names_are_matched_on_the_last_element_ignoring_case() {
        for yes in [
            "usr/bin/node",
            "/usr/local/bin/nodejs",
            "node22",
            "C:/Program Files/nodejs/NODE.EXE",
            "usr/lib/libnode.so.115",
            "libnode.so",
            "libnode.dll",
            "libnode.dylib",
            // 스캐너와 같이 끝의 `/` 를 떼고 본다 — 디렉터리인지는 부르는 쪽이 항목의 종류로 가린다.
            "usr/bin/node/",
        ] {
            assert!(is_node_runtime(yes), "{yes}");
        }
        for no in ["node-gyp", "nodejs-doc", "node.js", "libnode.so.x"] {
            assert!(!is_node_runtime(no), "{no}");
        }
        for yes in [
            "usr/lib/x86_64-linux-gnu/libbrotlidec.so.1",
            "libbrotlidec.so.1.1.0",
            "libbrotlidecoder.so",
            "brotlidec.dll",
            "BROTLIDECODER.DLL",
        ] {
            assert!(is_brotli_decoder(yes), "{yes}");
        }
        for no in [
            "libbrotlienc.so.1",
            "libbrotlicommon.so.1",
            "brotli",
            "libbrotlidec.a",
        ] {
            assert!(!is_brotli_decoder(no), "{no}");
        }
    }

    /// 원본 `TestWindowsBinaryRequiresValidatedPEAndFullHash` 의 머리 확인 부분.
    #[test]
    fn strict_pe_accepts_only_a_real_executable_image() {
        let pe = container_pe("node");
        assert!(valid_pe(&pe, pe.len() as u64));
        let mut fake = vec![0u8; 4096];
        fake[..2].copy_from_slice(b"MZ");
        assert!(!valid_pe(&fake, fake.len() as u64));
        let elf = minimal_elf64();
        assert!(!valid_pe(&elf, elf.len() as u64));
        assert!(!valid_pe(b"#!/bin/sh\necho node\n", 21));
        // 실행 이미지 표시를 지우면 엄격한 확인을 지나지 못한다.
        let mut not_image = pe.clone();
        not_image[150..152].copy_from_slice(&0u16.to_le_bytes());
        assert!(!valid_pe(&not_image, not_image.len() as u64));
        // 파일이 섹션보다 짧다.
        assert!(!valid_pe(&pe, 1024));
    }

    #[test]
    fn loose_pe_accepts_the_php_core_fixture() {
        let pe = php_core_pe("8.3.35");
        assert!(valid_runtime_binary(&pe, pe.len() as u64));
        // 엄격한 확인은 기계 · 선택 머리 크기가 모자라 지나지 못한다.
        assert!(!valid_pe(&pe, pe.len() as u64));
        let mut bad_magic = pe.clone();
        bad_magic[88..90].copy_from_slice(&0x107u16.to_le_bytes());
        assert!(!valid_runtime_binary(&bad_magic, bad_magic.len() as u64));
        assert!(!valid_runtime_binary(&pe[..63], 1024));
    }

    #[test]
    fn magic_is_only_the_first_bytes() {
        assert!(binary_magic(b"\x7fELF\x02"));
        assert!(binary_magic(b"MZ\x90\x00"));
        assert!(!binary_magic(b"#!/bin/sh"));
        assert!(!binary_magic(b""));
    }
}
