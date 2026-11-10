//! RPM 헤더 블롭 — 패키지 DB 가 패키지마다 담는 꼬리표 묶음.
//!
//! # 모양
//!
//! DB 에 든 블롭은 *"헤더 영역"* 이다(파일의 헤더와 달리 앞의 8바이트 마법이 없다).
//!
//! ```text
//! u32 il (항목 수, 빅 엔디언) · u32 dl (자료 길이)
//! il × { u32 tag · u32 type · i32 offset · u32 count }
//! dl 바이트의 자료 — offset 은 이 자료 안의 자리
//! ```
//!
//! [`parse`] 가 쓰는 꼬리표는 일곱뿐이다 — 이름 · epoch · 판 · 개정 · 아키텍처 · 공급사 · 원본 패키지. 문자열은
//! 자료 안에서 NUL 로 끝난다.
//!
//! # 믿지 않는다
//!
//! 블롭은 디스크에서 온 바이트다. 모든 자리를 범위로 확인하고, 모르는 모양은 **그 패키지를 버린다**
//! (`None`) — 엉뚱한 값으로 채운 기록이 판 비교에 들어가는 것보다 낫다.
//!
//! # 일곱 밖의 꼬리표 (2026-11-10)
//!
//! 동반 모듈의 이미지 점검은 같은 블롭에서 모듈 꼬리표 · 파일 경로 · 파일 다이제스트를 더 읽는다(`files` 모듈).
//! 그것은 믿지 못할 입력의 입구 [`crate::read_untrusted`] 로만 꺼낸다 — [`parse`] 와 [`RpmHeader`] 는 그대로이고,
//! 수집기는 그것을 부르지 않는다.

mod files;

pub(crate) use files::{package, Derived, DERIVED};
pub use files::{DigestAlgorithm, FileDigests};

/// 한 패키지의 꼬리표.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmHeader {
    pub name: String,
    pub epoch: Option<u32>,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub vendor: String,
    /// `php-8.0.30-8.el9_8.1.src.rpm` 처럼 원본 패키지 파일 이름 그대로.
    pub sourcerpm: String,
}

const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_EPOCH: u32 = 1003;
const TAG_VENDOR: u32 = 1011;
const TAG_ARCH: u32 = 1022;
const TAG_SOURCERPM: u32 = 1044;

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_I18NSTRING: u32 = 9;

/// rpm 자신의 상한과 같은 크기 — 항목 수 · 자료 길이. 넘으면 헤더가 아니다.
const MAX_ENTRIES: u32 = 0xFFFF;
const MAX_DATA: u32 = 256 * 1024 * 1024;

fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// 헤더 영역 하나를 읽는다. 이름 · 판 · 개정이 없으면 패키지가 아니다.
pub fn parse(blob: &[u8]) -> Option<RpmHeader> {
    let il = be_u32(blob, 0)?;
    let dl = be_u32(blob, 4)?;
    if il == 0 || il > MAX_ENTRIES || dl > MAX_DATA {
        return None;
    }
    let index_start = 8usize;
    let data_start = index_start.checked_add((il as usize).checked_mul(16)?)?;
    let data_end = data_start.checked_add(dl as usize)?;
    let data = blob.get(data_start..data_end)?;

    let mut h = RpmHeader {
        name: String::new(),
        epoch: None,
        version: String::new(),
        release: String::new(),
        arch: String::new(),
        vendor: String::new(),
        sourcerpm: String::new(),
    };
    for i in 0..il as usize {
        let e = index_start + i * 16;
        let (tag, ty, off) = (be_u32(blob, e)?, be_u32(blob, e + 4)?, be_u32(blob, e + 8)?);
        let field = match tag {
            TAG_NAME => &mut h.name,
            TAG_VERSION => &mut h.version,
            TAG_RELEASE => &mut h.release,
            TAG_VENDOR => &mut h.vendor,
            TAG_ARCH => &mut h.arch,
            TAG_SOURCERPM => &mut h.sourcerpm,
            TAG_EPOCH => {
                if ty == TYPE_INT32 {
                    h.epoch = be_u32(data, off as usize);
                }
                continue;
            }
            _ => continue,
        };
        if ty == TYPE_STRING || ty == TYPE_I18NSTRING {
            *field = c_string(data, off as usize)?;
        }
    }
    if h.name.is_empty() || h.version.is_empty() || h.release.is_empty() {
        return None;
    }
    Some(h)
}

/// 자료 안의 `at` 에서 NUL 까지. NUL 이 없으면 헤더가 깨진 것이다.
fn c_string(data: &[u8], at: usize) -> Option<String> {
    let rest = data.get(at..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    // 일곱 밖의 꼬리표를 짓는 시험 도구 — 믿지 못할 입력의 시험(`untrusted`)도 쓴다.
    pub(crate) use super::files::tests::{digests, files_in, label, pkg, MD5_HEX, SHA256_HEX};

    /// 시험용 헤더 영역을 짓는다 — 꼬리표마다 (tag, type, 값).
    pub(crate) fn build(entries: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        for (tag, ty, value) in entries {
            if *ty == TYPE_INT32 {
                while data.len() % 4 != 0 {
                    data.push(0);
                }
            }
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&ty.to_be_bytes());
            index.extend_from_slice(&(data.len() as u32).to_be_bytes());
            index.extend_from_slice(&1u32.to_be_bytes());
            data.extend_from_slice(value);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&data);
        out
    }

    pub(crate) fn s(v: &str) -> Vec<u8> {
        let mut b = v.as_bytes().to_vec();
        b.push(0);
        b
    }

    pub(crate) fn php_header() -> Vec<u8> {
        build(&[
            (TAG_NAME, TYPE_STRING, s("php-cli")),
            (TAG_VERSION, TYPE_STRING, s("8.0.30")),
            (TAG_RELEASE, TYPE_STRING, s("8.el9_8.1")),
            (TAG_EPOCH, TYPE_INT32, 0u32.to_be_bytes().to_vec()),
            (TAG_VENDOR, TYPE_STRING, s("Red Hat, Inc.")),
            (TAG_ARCH, TYPE_STRING, s("x86_64")),
            (
                TAG_SOURCERPM,
                TYPE_STRING,
                s("php-8.0.30-8.el9_8.1.src.rpm"),
            ),
        ])
    }

    #[test]
    fn a_header_yields_the_seven_tags() {
        let h = parse(&php_header()).expect("헤더");
        assert_eq!(h.name, "php-cli");
        assert_eq!(
            (h.version.as_str(), h.release.as_str()),
            ("8.0.30", "8.el9_8.1")
        );
        assert_eq!(h.epoch, Some(0));
        assert_eq!(h.vendor, "Red Hat, Inc.");
        assert_eq!(h.arch, "x86_64");
        assert_eq!(h.sourcerpm, "php-8.0.30-8.el9_8.1.src.rpm");
    }

    #[test]
    fn broken_bytes_are_not_a_package() {
        let good = php_header();
        // 잘린 블롭 · 항목 수가 거짓 · 빈 블롭 — 어느 것도 패닉 없이 None.
        assert!(parse(&good[..good.len() - 5]).is_none());
        let mut lying = good.clone();
        lying[0..4].copy_from_slice(&0x0010_0000u32.to_be_bytes());
        assert!(parse(&lying).is_none());
        assert!(parse(&[]).is_none());
        // 이름이 없으면 패키지가 아니다.
        let nameless = build(&[
            (TAG_VERSION, TYPE_STRING, s("1")),
            (TAG_RELEASE, TYPE_STRING, s("1")),
        ]);
        assert!(parse(&nameless).is_none());
    }
}
