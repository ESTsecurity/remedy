//! 배포판 식별과 ELF 식별.
//!
//! 사내 runtime-scanner 의 `internal/linuxmeta` 를 옮겼다.
//!
//! **배포판은 파일에 적힌 기록을 데이터로만 읽는다.** 셸 문법을 풀지 않고(`$(...)` 는 그저 글자다), 런타임이
//! 내는 배너로 배포판을 짐작하지 않는다. 아는 자리의 아는 꼴만 받는다 — 꼴이 어긋난 기록은 없는 것으로 치고,
//! 부르는 쪽이 [`RELEASE_FILES`] 의 다음 파일로 넘어간다.
//!
//! **ELF 식별은 맞지 않는 라이브러리를 잇지 않으려고 본다.** 기계 · 워드 크기 · 바이트 순서 · 호출 규약이
//! 다른 파일은 이름이 같아도 그 실행 파일이 쓰는 것이 아니다. 패키지의 아키텍처 이름과는 별개다.
//!
//! 기록은 글자가 아니라 바이트로 다룬다. 스캐너(Go)의 문자열은 UTF-8 이 아닌 바이트를 그대로 들고 다니므로,
//! 같은 입력에 같은 답을 내려면 여기서도 글자로 바꾸지 않는다.

use regex::bytes::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;

/// 배포판을 알리는 파일 — 앞선 것이 우선이다. os-release 가 아닌 옛 꼴은 쓸 수 있는 os-release 기록이 없을
/// 때만 본다.
pub const RELEASE_FILES: [&str; 8] = [
    "/etc/os-release",
    "/usr/lib/os-release",
    "/etc/oracle-release",
    "/etc/centos-release",
    "/etc/redhat-release",
    "/etc/debian_version",
    "/etc/lsb-release",
    "/etc/SuSE-release",
];

/// 기록 하나의 상한 — 넘으면 읽지 않는다.
const MAX_RELEASE_BYTES: usize = 64 << 10;

/// 배포판의 `(id, 버전)`. 아는 자리(`file_name`)의 아는 꼴만 받는다 — 64 KiB 를 넘거나 NUL 이 든 기록, 꼴이
/// 어긋난 기록은 `None` 이다.
///
/// - `os-release`: `ID` 와 `VERSION_ID`. 키가 겹치거나 `=` 없는 줄이 하나라도 있으면 파일 전체를 버린다 —
///   어느 줄이 참인지 고르지 않는다. 따옴표 값은 온전한 리터럴 하나여야 한다.
/// - `redhat-release` · `centos-release` · `oracle-release`: `<이름> release <버전> (<별명>)` 한 줄.
///   `centos-release` · `oracle-release` 는 제 배포판의 기록만 받는다.
/// - `debian_version`: 숫자 버전 한 줄(`bookworm/sid` 는 받지 않는다).
/// - `lsb-release`: `DISTRIB_ID` 가 Ubuntu · Debian 일 때만.
/// - `SuSE-release`: 첫 줄의 버전과 `VERSION` 이 같아야 하고, `PATCHLEVEL` 은 첫 줄의 `SP` 와 어긋나면 안 된다.
pub fn parse_release(file_name: &str, data: &[u8]) -> Option<(String, String)> {
    if data.len() > MAX_RELEASE_BYTES || data.contains(&0) {
        return None;
    }
    let text = trim(data);
    match clean(file_name)?.as_str() {
        "/etc/os-release" | "/usr/lib/os-release" => os_release(text),
        "/etc/redhat-release" => legacy_release(text, None),
        "/etc/centos-release" => legacy_release(text, Some("centos")),
        "/etc/oracle-release" => legacy_release(text, Some("ol")),
        "/etc/debian_version" => is_number(text).then(|| ("debian".to_string(), ascii(text))),
        "/etc/lsb-release" => lsb_release(text),
        "/etc/SuSE-release" => suse_release(text),
        _ => None,
    }
}

/// 패키지 DB 가 적는 아키텍처 이름의 꼴 — 소문자 · 숫자로 시작하고 `_` · `-` 까지, 64자 안.
pub fn valid_package_architecture(value: &str) -> bool {
    let b = value.as_bytes();
    let word = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    b.len() <= 64 && b.first().is_some_and(word) && b.iter().all(|c| word(c) || b"_-".contains(c))
}

/// 겹친 `/` · `.` · `..` 를 걷어 낸 절대 경로(Go 의 `path.Clean`). 아는 자리는 모두 절대 경로라, 상대 경로는
/// 어느 것과도 맞지 않는다.
fn clean(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.strip_prefix('/')?.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

fn os_release(text: &[u8]) -> Option<(String, String)> {
    let fields = fields(text)?;
    let id = fields.get(b"ID".as_slice())?;
    let version = fields.get(b"VERSION_ID".as_slice())?;
    (is_id(id) && is_number(version)).then(|| (ascii(id), ascii(version)))
}

fn lsb_release(text: &[u8]) -> Option<(String, String)> {
    let fields = fields(text)?;
    let id = lower(fields.get(b"DISTRIB_ID".as_slice())?);
    let release = fields.get(b"DISTRIB_RELEASE".as_slice())?;
    ((id == "ubuntu" || id == "debian") && is_number(release)).then(|| (id, ascii(release)))
}

/// 옛 Red Hat 계열의 한 줄. `only` 는 그 파일이 받는 배포판 하나 — `redhat-release` 는 CentOS · Oracle 도
/// 같은 이름으로 두므로 가리지 않는다.
fn legacy_release(text: &[u8], only: Option<&str>) -> Option<(String, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(concat!(
            r"^(Red Hat Enterprise Linux(?: Server| Client| Workstation| AS| ES| WS)?",
            r"|Red Hat Linux|CentOS(?: Linux| Stream)?|Oracle Linux(?: Server)?)",
            r" release ([0-9]+(?:\.[0-9]+)*)(?: \([A-Za-z0-9 ._-]+\))?$",
        ))
        .expect("고정된 정규식")
    });
    let m = re.captures(text)?;
    let name = m.get(1)?.as_bytes();
    let id = if name.starts_with(b"CentOS") {
        "centos"
    } else if name.starts_with(b"Oracle Linux") {
        "ol"
    } else if name == b"Red Hat Linux" {
        "redhat"
    } else {
        "rhel"
    };
    if only.is_some_and(|only| only != id) {
        return None;
    }
    Some((id.to_string(), ascii(m.get(2)?.as_bytes())))
}

/// 첫 줄은 이름 · 버전 · (있으면) 서비스 팩, 그 아래는 `키 = 값` 이다. 줄 끝의 CR 은 양 끝 공백과 함께 걷힌다.
fn suse_release(text: &[u8]) -> Option<(String, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(concat!(
            r"^(SUSE Linux Enterprise (?:Server|Desktop)|SUSE LINUX|openSUSE)",
            r" ([0-9]+(?:\.[0-9]+)*)(?: SP([0-9]+))?(?: \([A-Za-z0-9_ .-]+\))?$",
        ))
        .expect("고정된 정규식")
    });
    let (first, rest) = match text.iter().position(|b| *b == b'\n') {
        Some(i) => (&text[..i], &text[i + 1..]),
        None => (text, &[][..]),
    };
    let m = re.captures(trim(first))?;
    let fields = fields(rest)?;
    let stated = fields.get(b"VERSION".as_slice())?;
    if !is_number(stated) || stated.as_ref() != m.get(2)?.as_bytes() {
        return None;
    }
    let mut version = ascii(stated);
    let patch = fields.get(b"PATCHLEVEL".as_slice());
    if let Some(patch) = patch.filter(|p| !p.is_empty() && p.as_ref() != b"0") {
        let pack = m.get(3).map(|g| g.as_bytes());
        if !patch.iter().all(u8::is_ascii_digit) || pack.is_some_and(|sp| sp != patch.as_ref()) {
            return None;
        }
        version.push('.');
        version.push_str(&ascii(patch));
    }
    let name = m.get(1)?.as_bytes();
    let id = if name == b"openSUSE" || name == b"SUSE LINUX" {
        "opensuse"
    } else if name.ends_with(b"Desktop") {
        "sled"
    } else {
        "sles"
    };
    Some((id.to_string(), version))
}

/// `키=값` 줄들. 빈 줄과 `#` 줄은 건너뛴다. `=` 없는 줄 · 빈 키 · 겹친 키 · 온전하지 않은 따옴표 값이 하나라도
/// 있으면 `None` 이다. 따옴표 없는 값은 적힌 그대로다 — 셸처럼 풀지 않는다.
fn fields(text: &[u8]) -> Option<HashMap<&[u8], Cow<'_, [u8]>>> {
    let mut fields = HashMap::new();
    for line in text.split(|b| *b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let eq = line.iter().position(|b| *b == b'=')?;
        let (key, value) = (trim(&line[..eq]), trim(&line[eq + 1..]));
        if key.is_empty() || fields.contains_key(key) {
            return None;
        }
        let value = match value.first() {
            Some(b'"') => Cow::Owned(unquote(value)?),
            Some(b'\'') => Cow::Borrowed(single_quoted(value)?),
            _ => Cow::Borrowed(value),
        };
        fields.insert(key, value);
    }
    Some(fields)
}

/// 작은따옴표 값 — 양 끝이 따옴표이고 안에 따옴표가 없어야 한다. 이스케이프는 없다.
fn single_quoted(value: &[u8]) -> Option<&[u8]> {
    let inner = value.strip_prefix(b"'")?.strip_suffix(b"'")?;
    (!inner.contains(&b'\'')).then_some(inner)
}

/// 큰따옴표 값 — Go 의 `strconv.Unquote` 와 같은 규칙. 값 전체가 리터럴 하나여야 한다: 닫는 따옴표 뒤에 글자가
/// 남거나, 닫히지 않거나, 모르는 이스케이프가 있으면 `None` 이다.
///
/// 이스케이프가 아닌 글자는 그 자리에서 UTF-8 로 풀고, 풀리지 않는 바이트는 U+FFFD 로 바꾼다. 그대로 두면
/// 이스케이프가 만든 바이트(`\304`)와 날것 바이트(0xB0)가 이어져 스캐너는 보지 못하는 글자(`İ`)가 된다.
fn unquote(value: &[u8]) -> Option<Vec<u8>> {
    let mut rest = value.strip_prefix(b"\"")?;
    let mut out = Vec::with_capacity(rest.len());
    loop {
        let (&c, tail) = rest.split_first()?;
        match c {
            b'"' => return tail.is_empty().then_some(out),
            b'\\' => rest = escape(tail, &mut out)?,
            _ if c.is_ascii() => {
                out.push(c);
                rest = tail;
            }
            _ => {
                let (ch, n) = first_char(rest)?;
                out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                rest = &rest[n..];
            }
        }
    }
}

/// 역슬래시 다음의 이스케이프 하나를 풀어 `out` 에 붙이고 나머지를 준다. `\x` · 8진수는 바이트 하나(UTF-8 이
/// 아닐 수 있다), `\u` · `\U` 는 글자 하나다. `\'` 는 큰따옴표 안에서 문법 오류다.
fn escape<'a>(s: &'a [u8], out: &mut Vec<u8>) -> Option<&'a [u8]> {
    let (&c, tail) = s.split_first()?;
    let (byte, rest) = match c {
        b'a' => (0x07, tail),
        b'b' => (0x08, tail),
        b'f' => (0x0c, tail),
        b'n' => (b'\n', tail),
        b'r' => (b'\r', tail),
        b't' => (b'\t', tail),
        b'v' => (0x0b, tail),
        b'\\' | b'"' => (c, tail),
        b'x' => {
            let (v, rest) = digits(tail, 2, 16)?;
            (u8::try_from(v).ok()?, rest)
        }
        b'u' | b'U' => {
            let (v, rest) = digits(tail, if c == b'u' { 4 } else { 8 }, 16)?;
            let ch = char::from_u32(v)?;
            out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
            return Some(rest);
        }
        b'0'..=b'7' => {
            let (v, rest) = digits(s, 3, 8)?;
            (u8::try_from(v).ok()?, rest)
        }
        _ => return None,
    };
    out.push(byte);
    Some(rest)
}

/// 정확히 `n` 자리의 수와 나머지 — 자리가 모자라거나 그 진법의 숫자가 아니면 `None`.
fn digits(s: &[u8], n: usize, radix: u32) -> Option<(u32, &[u8])> {
    if s.len() < n {
        return None;
    }
    let (head, rest) = s.split_at(n);
    let mut value: u32 = 0;
    for b in head {
        value = value
            .checked_mul(radix)?
            .checked_add(char::from(*b).to_digit(radix)?)?;
    }
    Some((value, rest))
}

/// `11` · `7.9.2009` — 점으로 나눈 십진수.
fn is_number(s: &[u8]) -> bool {
    s.split(|c| *c == b'.')
        .all(|part| !part.is_empty() && part.iter().all(u8::is_ascii_digit))
}

/// os-release 의 `ID` 꼴 — 소문자 · 숫자로 시작하고 `.` · `_` · `-` 까지.
fn is_id(s: &[u8]) -> bool {
    let word = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    s.first().is_some_and(word) && s.iter().all(|c| word(c) || b"._-".contains(c))
}

/// 꼴을 확인한(ASCII 뿐인) 바이트를 글자로.
fn ascii(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}

// ── Go 문자열 함수와 같은 규칙 ──────────────────────────────────────────────────────────────────────────
//
// 스캐너는 Go 의 `strings` · `unicode` 로 글자를 가른다. 공백과 대소문자의 범위가 ASCII 보다 넓고, UTF-8 로
// 풀리지 않는 바이트를 다루는 법이 정해져 있다. 같은 입력에 같은 답을 내려고 그 규칙을 그대로 둔다. 세션 설정
// 판독([`super::phpconfig`])도 이것을 쓴다.

/// 맨 앞의 글자와 그 바이트 수. UTF-8 로 풀리지 않으면 U+FFFD 와 1 이다(그 바이트 하나만 넘어간다). 비어
/// 있으면 `None`.
pub(crate) fn first_char(s: &[u8]) -> Option<(char, usize)> {
    if s.is_empty() {
        return None;
    }
    let head = &s[..s.len().min(4)];
    let valid = match std::str::from_utf8(head) {
        Ok(v) => v,
        Err(e) => std::str::from_utf8(&head[..e.valid_up_to()]).unwrap_or_default(),
    };
    match valid.chars().next() {
        Some(c) => Some((c, c.len_utf8())),
        None => Some((char::REPLACEMENT_CHARACTER, 1)),
    }
}

/// 양 끝의 유니코드 공백을 걷는다(`strings.TrimSpace`). UTF-8 로 풀리지 않는 바이트는 공백이 아니라 그 자리에서
/// 멈춘다.
pub(crate) fn trim(s: &[u8]) -> &[u8] {
    let s = trim_start(s);
    match s.utf8_chunks().last() {
        Some(tail) if tail.invalid().is_empty() => {
            let spaces = tail.valid().len() - tail.valid().trim_end().len();
            &s[..s.len() - spaces]
        }
        _ => s,
    }
}

/// 앞쪽의 유니코드 공백만 걷는다.
pub(crate) fn trim_start(s: &[u8]) -> &[u8] {
    let mut rest = s;
    while let Some((c, n)) = first_char(rest) {
        if !c.is_whitespace() {
            break;
        }
        rest = &rest[n..];
    }
    rest
}

/// 글자마다 소문자 하나로 바꾼다(`strings.ToLower`). Rust 의 문자열 소문자 변환은 U+0130(İ)을 두 글자로 풀지만
/// Go 는 `i` 한 글자로 바꾼다 — 글자 단위 변환의 첫 글자가 그 값이다. UTF-8 이 아닌 바이트는 하나마다 U+FFFD 다.
pub(crate) fn lower(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some((c, n)) = first_char(rest) {
        out.push(c.to_lowercase().next().unwrap_or(c));
        rest = &rest[n..];
    }
    out
}

// ── ELF ────────────────────────────────────────────────────────────────────────────────────────────────

const EM_386: u16 = 3;
const EM_MIPS: u16 = 8;
const EM_PPC64: u16 = 21;
const EM_S390: u16 = 22;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const EM_RISCV: u16 = 243;

/// ARM `e_flags` 의 EABI 버전 자리.
const ARM_EABI_MASK: u32 = 0xff00_0000;
const ARM_EABI_VER5: u32 = 0x0500_0000;
/// ARM 의 부동소수점 호출 규약 — 소프트(0x200) · 하드(0x400).
const ARM_FLOAT_SOFT: u32 = 0x200;
const ARM_FLOAT_BOTH: u32 = 0x600;

/// 실행 파일과 라이브러리가 같은 ABI 인지 가리는 데 쓰는 ELF 머리의 네 값. 전부 0 이면 ELF 로 읽지 못한 것이다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ElfIdentity {
    /// `EI_CLASS` — 1 은 32비트, 2 는 64비트.
    pub class: u8,
    /// `EI_DATA` — 1 은 리틀 엔디언, 2 는 빅 엔디언.
    pub endianness: u8,
    /// `e_machine`.
    pub machine: u16,
    /// `e_flags` — 호출 규약 · 부동소수점 방식처럼 기계마다 뜻이 다른 ABI 표시.
    pub flags: u32,
}

impl ElfIdentity {
    /// 파일 앞머리에서 읽는다. 32비트 머리는 52바이트, 64비트 머리는 64바이트가 있어야 한다 — 모자라거나 ELF 가
    /// 아니면 전부 0 인 값([`ElfIdentity::valid`] 가 거짓)을 준다.
    pub fn parse(data: &[u8]) -> ElfIdentity {
        Self::read(data).unwrap_or_default()
    }

    fn read(data: &[u8]) -> Option<ElfIdentity> {
        if data.len() < 52 || !data.starts_with(b"\x7fELF") || data[6] != 1 {
            return None;
        }
        let class = data[4];
        let flags_at = match class {
            1 => 36,
            2 if data.len() >= 64 => 48,
            _ => return None,
        };
        let endianness = data[5];
        let machine: [u8; 2] = data[18..20].try_into().ok()?;
        let flags: [u8; 4] = data[flags_at..flags_at + 4].try_into().ok()?;
        let (machine, flags) = match endianness {
            1 => (u16::from_le_bytes(machine), u32::from_le_bytes(flags)),
            2 => (u16::from_be_bytes(machine), u32::from_be_bytes(flags)),
            _ => return None,
        };
        Some(ElfIdentity {
            class,
            endianness,
            machine,
            flags,
        })
    }

    pub fn valid(&self) -> bool {
        self.class != 0 && self.machine != 0
    }

    /// 같은 프로세스에 함께 실릴 수 있는가. 워드 크기 · 바이트 순서 · 기계가 같아야 하고, 그다음은 기계마다
    /// `e_flags` 에서 ABI 를 가르는 비트만 견준다. 모르는 기계는 `e_flags` 전체가 같아야 한다 — 모르는 비트를
    /// 무시해도 된다고 짐작하지 않는다.
    pub fn compatible(&self, other: &ElfIdentity) -> bool {
        if !self.valid()
            || !other.valid()
            || self.class != other.class
            || self.endianness != other.endianness
            || self.machine != other.machine
        {
            return false;
        }
        let (mut a, mut b) = (self.flags, other.flags);
        let mask = match self.machine {
            // 이 기계들은 e_flags 로 ABI 를 가르지 않는다.
            EM_386 | EM_X86_64 | EM_AARCH64 | EM_S390 => return true,
            // EABI 버전과 부동소수점 호출 규약. 두 규약 비트가 함께 켜진 파일은 어느 쪽인지 알 수 없다.
            EM_ARM => {
                if a & ARM_FLOAT_BOTH == ARM_FLOAT_BOTH || b & ARM_FLOAT_BOTH == ARM_FLOAT_BOTH {
                    return false;
                }
                // EABI5 부터는 두 비트가 다 꺼져 있어도 소프트 플로트다 — 켜진 것과 같게 본다.
                if a & ARM_EABI_MASK >= ARM_EABI_VER5 {
                    a &= !ARM_FLOAT_SOFT;
                }
                if b & ARM_EABI_MASK >= ARM_EABI_VER5 {
                    b &= !ARM_FLOAT_SOFT;
                }
                ARM_EABI_MASK | ARM_FLOAT_BOTH
            }
            // 함수 서술자를 쓰는 ELFv1 과 ELFv2 는 다른 ABI 다.
            EM_PPC64 => 0x3,
            // ABI · N32 · 32비트 모드 · 부동소수점 표현.
            EM_MIPS => 0xf720,
            // 부동소수점 ABI · RVE · RV64ILP32 · 비표준 ABI 비트. 압축 명령(RVC)은 가르지 않는다.
            EM_RISCV => 0xff00_002e,
            _ => u32::MAX,
        };
        a & mask == b & mask
    }
}

#[cfg(test)]
mod tests;
