//! 일곱 밖의 꼬리표 — 모듈 꼬리표 · 파일 경로 · 파일 다이제스트 (2026-11-10).
//!
//! # 이미지 점검이 더 읽는 것
//!
//! 동반 모듈은 이미지 안의 실행 파일이 어느 패키지의 것이고 깔린 그대로인지를 본다. 그 재료가 같은 블롭에 있다 —
//! 모듈 꼬리표([`modularity_label`]) · 파일 경로([`file_paths`]) · 파일 다이제스트와 그 알고리즘([`file_digests`]).
//! 셋 다 **블롭을 받아 그때 읽는다**: [`super::parse`] 와 [`super::RpmHeader`] 는 그대로이고, 수집기는 이것들을
//! 부르지 않는다. 파일 목록은 패키지 하나에 수천 줄이라, 필요한 패키지에서만 읽도록 따로 두었다.
//!
//! 이쪽은 `None` 대신 [`RpmDbError`] 로 까닭을 돌려준다 — *"파일 목록은 읽었는데 다이제스트가 어긋났다"* 처럼
//! 부르는 쪽이 갈라 말해야 하는 경우가 있다. 개수는 블롭이 주장하는 값이므로 **읽기 전에 상한과 남은 자료로
//! 확인하고**, 경로를 이어 붙인 합계에도 상한을 둔다(`MAX_FILES` · `MAX_PATH_BYTES`).
//!
//! # 실물 대조 (2026-11-10)
//!
//! 컨테이너에서 꺼낸 DB 다섯을 같은 컨테이너의 `rpm -qa --qf` 와 견줬다 — 패키지마다 경로(차례까지) · 다이제스트 ·
//! 알고리즘 · 모듈 꼬리표가 모두 같았고 오류는 0 이었다: Rocky 9(SQLite) 141 패키지 · 28,128 파일, Oracle Linux
//! 8(BDB) 196 · 31,974, CentOS 7(BDB) 148 · 26,042, openSUSE Leap 15.6(NDB) 141 · 6,242, 모듈 패키지 `python36` 을
//! 더한 AlmaLinux 8(BDB) 160 · 30,315. 파일이 가장 많은 패키지는 `filesystem` 의 17,262개(경로 합 415,061바이트)였다.
//! **다섯 모두 SHA-256 이었다** — MD5 와 옛 꼴(`OLDFILENAMES`)은 실물로 보지 못했고 합성 헤더로만 시험했다. 모듈
//! 꼬리표는 그 `python36` 하나다(CentOS 7 · openSUSE 의 rpm 은 그 꼬리표를 몰라 견주지 못했다).

use super::{be_u32, c_string, MAX_DATA, MAX_ENTRIES, TYPE_INT32, TYPE_STRING};
use crate::RpmDbError;

// 이미지 점검이 더 읽는 꼬리표 — 파일 이름의 옛 꼴 · 파일 다이제스트 · 파일마다의 디렉터리 번호 · 파일 이름 ·
// 디렉터리 목록 · 다이제스트 알고리즘 · 모듈 꼬리표.
const TAG_OLDFILENAMES: u32 = 1027;
const TAG_FILEDIGESTS: u32 = 1035;
const TAG_DIRINDEXES: u32 = 1116;
const TAG_BASENAMES: u32 = 1117;
const TAG_DIRNAMES: u32 = 1118;
const TAG_FILEDIGESTALGO: u32 = 5011;
const TAG_MODULARITYLABEL: u32 = 5096;

const TYPE_STRING_ARRAY: u32 = 8;

/// `FILEDIGESTALGO` 의 값 — OpenPGP 의 해시 번호다.
const ALGO_MD5: u32 = 1;
const ALGO_SHA256: u32 = 8;

/// 배열 꼬리표 하나의 항목 수 상한 — 한 패키지의 파일 수다. 동반 모듈이 옮겨 오는 사내 runtime-scanner 가 같은
/// 자리에 둔 값이다. 넘으면 읽기 전에 그만둔다.
const MAX_FILES: usize = 100_000;
/// 한 패키지의 경로를 모두 더한 길이의 상한 (원문 바이트). 경로는 디렉터리 이름과 파일 이름을 이어 만든다 — 긴
/// 디렉터리 이름 하나를 파일마다 가리키면 블롭보다 훨씬 큰 값이 나오므로, 이어 붙이기 전에 센다.
const MAX_PATH_BYTES: usize = 16 * 1024 * 1024;

/// 파일 다이제스트의 알고리즘.
///
/// rpm 은 더 많은 값을 안다(SHA-1 · SHA-384 · SHA-512 …). 읽는 것은 이 둘뿐이다 — 다른 값은 다이제스트의 꼴을
/// 확인할 수 없어 오류로 돌린다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Md5,
    Sha256,
}

impl DigestAlgorithm {
    /// 16진으로 적은 다이제스트의 글자 수.
    fn hex_len(self) -> usize {
        match self {
            DigestAlgorithm::Md5 => 32,
            DigestAlgorithm::Sha256 => 64,
        }
    }
}

/// 한 패키지의 파일 다이제스트.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigests {
    pub algorithm: DigestAlgorithm,
    /// [`file_paths`] 와 **같은 차례 · 같은 길이**다. 소문자 16진이고, 다이제스트가 없는 파일(디렉터리 · 심볼릭 링크
    /// 등)은 빈 문자열이다.
    pub digests: Vec<String>,
}

/// 모듈 꼬리표 — `이름:스트림:판:문맥` 꼴로, 그 패키지가 속한 모듈 스트림을 말한다. 모듈에 속하지 않은 패키지에는
/// 꼬리표가 없다(`None`). 꼬리표가 있는데 읽히지 않으면 없다고 하지 않고 오류로 돌린다.
pub fn modularity_label(blob: &[u8]) -> Result<Option<String>, RpmDbError> {
    let r = Region::of(blob)?;
    let Some(e) = r.entry(TAG_MODULARITYLABEL)? else {
        return Ok(None);
    };
    if e.ty != TYPE_STRING {
        return Err(RpmDbError::Format("모듈 꼬리표가 문자열이 아니다"));
    }
    c_string(r.data, e.off).map(Some).ok_or(RpmDbError::Format(
        "모듈 꼬리표가 자료 안에서 끝나지 않는다",
    ))
}

/// 이 패키지가 소유한 파일의 경로 — 헤더에 적힌 차례 그대로, 파일이 없으면 빈 목록이다.
///
/// 지금 헤더는 디렉터리 목록 · 파일 이름 · 파일마다의 디렉터리 번호로 나눠 적고(`DIRNAMES` · `BASENAMES` ·
/// `DIRINDEXES`), 옛 헤더는 온전한 경로를 적는다(`OLDFILENAMES`). 어느 쪽이든 돌려주는 값은 **`/` 로 시작하는
/// 경로**이고, 뿌리(`/`)를 소유한 패키지에서는 `/` 가 그대로 나온다.
///
/// # 정리하지 않는다
///
/// 경로는 적힌 그대로다 — `.` · `..` · 겹친 `/` 를 풀지 않고, UTF-8 이 아닌 바이트만 대체 문자로 바꾼다. 찾는
/// 키로 쓰거나 파일에 닿기 전에 **부르는 쪽이 자기 규칙으로 정리한다**. 여기서 보는 것은 나눠 적은 꼴이 rpm 이
/// 쓰는 모양인지뿐이다(`check_split`).
pub fn file_paths(blob: &[u8]) -> Result<Vec<String>, RpmDbError> {
    let r = Region::of(blob)?;
    match FileNames::of(&r)? {
        FileNames::None => Ok(Vec::new()),
        FileNames::Whole(e) => whole_paths(&r.strings(e)?),
        FileNames::Split { base, dirs, index } => {
            split_paths(&r.strings(base)?, &r.strings(dirs)?, &r.int32s(index)?)
        }
    }
}

/// 파일마다의 다이제스트와 그 알고리즘. 알고리즘 꼬리표가 없으면 MD5 다 — 그 꼬리표가 생기기 전의 헤더가 그렇다.
///
/// 다이제스트 수가 파일 수와 다르거나, 16진이 아니거나, 그 알고리즘의 길이가 아니면 오류다. 그때도 [`file_paths`]
/// 는 읽힌다 — *누구의 파일인가* 와 *깔린 그대로인가* 는 따로 답한다.
pub fn file_digests(blob: &[u8]) -> Result<FileDigests, RpmDbError> {
    let r = Region::of(blob)?;
    let algorithm = digest_algorithm(&r)?;
    let files = FileNames::of(&r)?.count();
    let raw = match r.entry(TAG_FILEDIGESTS)? {
        Some(e) => r.strings(e)?,
        None => Vec::new(),
    };
    if raw.len() != files {
        return Err(RpmDbError::Format("파일 수와 다이제스트 수가 다르다"));
    }
    let digests = raw
        .into_iter()
        .map(|d| hex_digest(d, algorithm))
        .collect::<Result<_, _>>()?;
    Ok(FileDigests { algorithm, digests })
}

/// 헤더 영역의 두 조각 — 색인(항목마다 16바이트)과 자료.
struct Region<'a> {
    index: &'a [u8],
    data: &'a [u8],
}

/// 색인 항목 하나에서 꼬리표를 뺀 나머지 — 형 · 자료 안의 자리 · 개수.
#[derive(Clone, Copy)]
struct Entry {
    ty: u32,
    off: usize,
    count: usize,
}

impl<'a> Region<'a> {
    /// [`super::parse`] 와 같은 틀 검사다 — 항목 수 · 자료 길이가 상한 안이고, 블롭이 그만큼 있어야 한다.
    fn of(blob: &'a [u8]) -> Result<Self, RpmDbError> {
        let bad = RpmDbError::Format("RPM 헤더 영역이 아니다");
        let (Some(il), Some(dl)) = (be_u32(blob, 0), be_u32(blob, 4)) else {
            return Err(bad);
        };
        if il == 0 || il > MAX_ENTRIES || dl > MAX_DATA {
            return Err(bad);
        }
        let data_start = 8 + il as usize * 16;
        let index = blob.get(8..data_start);
        let data = blob
            .get(data_start..)
            .and_then(|rest| rest.get(..dl as usize));
        match (index, data) {
            (Some(index), Some(data)) => Ok(Self { index, data }),
            _ => Err(bad),
        }
    }

    /// 꼬리표 하나의 항목. 같은 꼬리표가 두 번 나오면 어느 쪽을 믿을지 알 수 없다 — rpm 은 그런 헤더를 쓰지 않는다.
    fn entry(&self, tag: u32) -> Result<Option<Entry>, RpmDbError> {
        let mut found = None;
        for e in self.index.chunks_exact(16) {
            let word = |at: usize| u32::from_be_bytes([e[at], e[at + 1], e[at + 2], e[at + 3]]);
            if word(0) != tag {
                continue;
            }
            if found.is_some() {
                return Err(RpmDbError::Format("같은 꼬리표가 두 번 나온다"));
            }
            found = Some(Entry {
                ty: word(4),
                off: word(8) as usize,
                count: word(12) as usize,
            });
        }
        Ok(found)
    }

    /// 문자열 배열 — NUL 로 끝나는 문자열 `count` 개가 `off` 부터 잇달아 선다. 자료를 빌려 보기만 한다.
    fn strings(&self, e: Entry) -> Result<Vec<&'a [u8]>, RpmDbError> {
        if e.ty != TYPE_STRING_ARRAY {
            return Err(RpmDbError::Format(
                "문자열 배열이어야 할 꼬리표의 형이 다르다",
            ));
        }
        if e.count > MAX_FILES {
            return Err(RpmDbError::Limit("꼬리표 하나의 항목 수가 상한을 넘었다"));
        }
        let mut rest = self
            .data
            .get(e.off..)
            .ok_or(RpmDbError::Format("꼬리표의 자리가 자료 밖이다"))?;
        // 문자열 하나는 적어도 1바이트(NUL)를 쓴다 — 남은 자료보다 많은 개수는 거짓이고, 미리 잡는 자리도 그 안이다.
        if e.count > rest.len() {
            return Err(RpmDbError::Format("문자열 배열이 자료 밖으로 나간다"));
        }
        let mut out = Vec::with_capacity(e.count);
        for _ in 0..e.count {
            let end = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or(RpmDbError::Format("문자열 배열이 자료 밖으로 나간다"))?;
            out.push(&rest[..end]);
            rest = &rest[end + 1..];
        }
        Ok(out)
    }

    /// 32비트 정수 배열 (빅 엔디언).
    fn int32s(&self, e: Entry) -> Result<Vec<u32>, RpmDbError> {
        if e.ty != TYPE_INT32 {
            return Err(RpmDbError::Format(
                "정수 배열이어야 할 꼬리표의 형이 다르다",
            ));
        }
        if e.count > MAX_FILES {
            return Err(RpmDbError::Limit("꼬리표 하나의 항목 수가 상한을 넘었다"));
        }
        let bytes = e
            .off
            .checked_add(e.count * 4)
            .and_then(|end| self.data.get(e.off..end))
            .ok_or(RpmDbError::Format("정수 배열이 자료 밖으로 나간다"))?;
        Ok(bytes
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect())
    }
}

/// 파일 이름이 적힌 꼴 — 없거나, 온전한 경로이거나(옛 헤더), 셋으로 나눠 적었거나.
enum FileNames {
    None,
    Whole(Entry),
    Split {
        base: Entry,
        dirs: Entry,
        index: Entry,
    },
}

impl FileNames {
    /// 두 꼴이 함께 있거나 나눠 적은 셋 가운데 일부만 있으면 어느 것을 믿을지 알 수 없다 — 오류다.
    fn of(r: &Region<'_>) -> Result<Self, RpmDbError> {
        let whole = r.entry(TAG_OLDFILENAMES)?;
        let split = (
            r.entry(TAG_BASENAMES)?,
            r.entry(TAG_DIRNAMES)?,
            r.entry(TAG_DIRINDEXES)?,
        );
        match (whole, split) {
            (None, (None, None, None)) => Ok(FileNames::None),
            (Some(e), (None, None, None)) => Ok(FileNames::Whole(e)),
            (None, (Some(base), Some(dirs), Some(index))) => {
                Ok(FileNames::Split { base, dirs, index })
            }
            _ => Err(RpmDbError::Format("파일 이름 꼬리표의 짝이 맞지 않는다")),
        }
    }

    /// 파일 수 — 색인이 말하는 값이다.
    fn count(&self) -> usize {
        match self {
            FileNames::None => 0,
            FileNames::Whole(e) => e.count,
            FileNames::Split { base, .. } => base.count,
        }
    }
}

/// 옛 헤더의 경로들.
fn whole_paths(names: &[&[u8]]) -> Result<Vec<String>, RpmDbError> {
    let mut left = MAX_PATH_BYTES;
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        if !name.starts_with(b"/") {
            return Err(RpmDbError::Format("파일 경로가 `/` 로 시작하지 않는다"));
        }
        out.push(join(name, b"", &mut left)?);
    }
    Ok(out)
}

/// 나눠 적은 꼴에서 경로를 짓는다 — 파일 `i` 의 경로는 `dirs[index[i]]` 뒤에 `bases[i]` 를 그대로 이은 것이다.
fn split_paths(bases: &[&[u8]], dirs: &[&[u8]], index: &[u32]) -> Result<Vec<String>, RpmDbError> {
    if bases.len() != index.len() {
        return Err(RpmDbError::Format(
            "파일 이름 수와 디렉터리 번호 수가 다르다",
        ));
    }
    let mut left = MAX_PATH_BYTES;
    let mut out = Vec::with_capacity(bases.len());
    for (base, i) in bases.iter().zip(index) {
        let dir = dirs
            .get(*i as usize)
            .ok_or(RpmDbError::Format("디렉터리 번호가 디렉터리 목록 밖이다"))?;
        check_split(dir, base)?;
        out.push(join(dir, base, &mut left)?);
    }
    Ok(out)
}

/// rpm 이 쓰는 모양인가 — 디렉터리 이름은 `/` 로 시작하고 끝나며, 파일 이름에는 `/` 가 없고, 이름이 빈 것은
/// 뿌리(`/`)뿐이다. 이 모양이 아니면 둘을 이은 값이 무엇을 가리키는지 알 수 없다(`/usr/bin` 에 `php` 를 이으면
/// `/usr/binphp` 다).
fn check_split(dir: &[u8], base: &[u8]) -> Result<(), RpmDbError> {
    if !dir.starts_with(b"/") || !dir.ends_with(b"/") {
        return Err(RpmDbError::Format(
            "디렉터리 이름이 `/` 로 시작하고 끝나지 않는다",
        ));
    }
    if base.contains(&b'/') {
        return Err(RpmDbError::Format("파일 이름에 `/` 가 들어 있다"));
    }
    if base.is_empty() && dir != b"/" {
        return Err(RpmDbError::Format("이름이 빈 파일이 뿌리가 아니다"));
    }
    Ok(())
}

/// 두 조각을 이어 경로 하나를 만든다. 한 패키지의 합계가 상한을 넘으면 **만들기 전에** 그만둔다.
fn join(dir: &[u8], base: &[u8], left: &mut usize) -> Result<String, RpmDbError> {
    let len = dir.len() + base.len();
    *left = left.checked_sub(len).ok_or(RpmDbError::Limit(
        "한 패키지의 경로를 더한 길이가 상한을 넘었다",
    ))?;
    let mut bytes = Vec::with_capacity(len);
    bytes.extend_from_slice(dir);
    bytes.extend_from_slice(base);
    Ok(String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// 알고리즘 꼬리표. 없으면 MD5 이고, 있으면 값 하나짜리 정수여야 한다.
fn digest_algorithm(r: &Region<'_>) -> Result<DigestAlgorithm, RpmDbError> {
    let Some(e) = r.entry(TAG_FILEDIGESTALGO)? else {
        return Ok(DigestAlgorithm::Md5);
    };
    match r.int32s(e)?.as_slice() {
        [ALGO_MD5] => Ok(DigestAlgorithm::Md5),
        [ALGO_SHA256] => Ok(DigestAlgorithm::Sha256),
        [_] => Err(RpmDbError::Format("읽지 않는 파일 다이제스트 알고리즘이다")),
        _ => Err(RpmDbError::Format(
            "파일 다이제스트 알고리즘 값이 하나가 아니다",
        )),
    }
}

/// 다이제스트 하나 — 비었거나(다이제스트가 없는 파일), 그 알고리즘 길이의 16진이다. 소문자로 맞춘다.
fn hex_digest(d: &[u8], algorithm: DigestAlgorithm) -> Result<String, RpmDbError> {
    if d.is_empty() {
        return Ok(String::new());
    }
    if d.len() != algorithm.hex_len() || !d.iter().all(u8::is_ascii_hexdigit) {
        return Err(RpmDbError::Format(
            "파일 다이제스트가 그 알고리즘의 16진 꼴이 아니다",
        ));
    }
    Ok(d.iter().map(|b| b.to_ascii_lowercase() as char).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::tests::{php_header, s};
    use crate::header::{parse, TAG_NAME, TAG_RELEASE, TAG_VERSION};

    /// 꼬리표 하나 — (tag, type, 개수, 값).
    type Tag = (u32, u32, u32, Vec<u8>);

    /// 개수를 따로 적는 헤더 영역. 배열 꼬리표와, 개수가 거짓인 헤더를 지을 때 쓴다(`build` 는 개수가 늘 1 이다).
    fn build_counted(entries: &[Tag]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        for (tag, ty, count, value) in entries {
            if *ty == TYPE_INT32 {
                while !data.len().is_multiple_of(4) {
                    data.push(0);
                }
            }
            for word in [*tag, *ty, data.len() as u32, *count] {
                index.extend_from_slice(&word.to_be_bytes());
            }
            data.extend_from_slice(value);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&data);
        out
    }

    /// 문자열 배열 꼬리표.
    fn arr(tag: u32, values: &[&str]) -> Tag {
        let data = values.iter().flat_map(|v| s(v)).collect();
        (tag, TYPE_STRING_ARRAY, values.len() as u32, data)
    }

    /// 정수 배열 꼬리표.
    fn nums(tag: u32, values: &[u32]) -> Tag {
        let data = values.iter().flat_map(|v| v.to_be_bytes()).collect();
        (tag, TYPE_INT32, values.len() as u32, data)
    }

    /// 이름 · 판 · 개정이 있는 패키지에 꼬리표를 더한다.
    fn pkg(extra: &[Tag]) -> Vec<u8> {
        let mut entries = vec![
            (TAG_NAME, TYPE_STRING, 1, s("php-cli")),
            (TAG_VERSION, TYPE_STRING, 1, s("8.0.30")),
            (TAG_RELEASE, TYPE_STRING, 1, s("8.el9_8.1")),
        ];
        entries.extend_from_slice(extra);
        build_counted(&entries)
    }

    /// 나눠 적은 꼴의 파일 넷 — 디렉터리 둘에 걸친 파일 셋과 디렉터리 하나(`/etc/php.d`).
    fn split_files() -> Vec<Tag> {
        vec![
            arr(TAG_BASENAMES, &["php", "phar", "php.ini", "php.d"]),
            arr(TAG_DIRNAMES, &["/usr/bin/", "/etc/"]),
            nums(TAG_DIRINDEXES, &[0, 0, 1, 1]),
        ]
    }

    /// 나눠 적은 꼴 하나로 경로를 읽는다.
    fn split(bases: &[&str], dirs: &[&str], index: &[u32]) -> Result<Vec<String>, RpmDbError> {
        file_paths(&pkg(&[
            arr(TAG_BASENAMES, bases),
            arr(TAG_DIRNAMES, dirs),
            nums(TAG_DIRINDEXES, index),
        ]))
    }

    /// 파일 넷에 다이제스트 꼬리표들을 더해 읽는다.
    fn digests_with(extra: &[Tag]) -> Result<FileDigests, RpmDbError> {
        let mut entries = split_files();
        entries.extend_from_slice(extra);
        file_digests(&pkg(&entries))
    }

    /// 빈 입력의 다이제스트 — 길이와 글자만 맞으면 되는 시험 값이다.
    const MD5_HEX: &str = "d41d8cd98f00b204e9800998ecf8427e";
    const SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const BAD_COUNT: RpmDbError = RpmDbError::Limit("꼬리표 하나의 항목 수가 상한을 넘었다");
    const BAD_DIGEST: RpmDbError =
        RpmDbError::Format("파일 다이제스트가 그 알고리즘의 16진 꼴이 아니다");
    const BAD_PAIRING: RpmDbError = RpmDbError::Format("파일 이름 꼬리표의 짝이 맞지 않는다");

    #[test]
    fn paths_are_rebuilt_from_directories_names_and_indexes() {
        let blob = pkg(&split_files());
        assert_eq!(
            file_paths(&blob).unwrap(),
            [
                "/usr/bin/php",
                "/usr/bin/phar",
                "/etc/php.ini",
                "/etc/php.d"
            ]
        );
        // 파일 꼬리표가 더해져도 일곱 꼬리표를 읽는 쪽은 그대로다.
        assert_eq!(parse(&blob).expect("헤더").name, "php-cli");
        // 뿌리를 소유한 패키지 — 이름이 빈 파일은 디렉터리 `/` 에서만 선다.
        assert_eq!(split(&["", "usr"], &["/"], &[0, 0]).unwrap(), ["/", "/usr"]);
        // 적힌 그대로다 — 역슬래시도 `..` 도 풀거나 막지 않는다(정리는 부르는 쪽의 일이다).
        assert_eq!(
            split(
                &["a\\x2db.slice", "php"],
                &["/usr/lib/", "/usr/../bin/"],
                &[0, 1]
            )
            .unwrap(),
            ["/usr/lib/a\\x2db.slice", "/usr/../bin/php"]
        );
    }

    #[test]
    fn old_headers_list_whole_paths() {
        let old = arr(TAG_OLDFILENAMES, &["/usr/bin/php", "/etc/php.ini", "/"]);
        let blob = pkg(std::slice::from_ref(&old));
        assert_eq!(
            file_paths(&blob).unwrap(),
            ["/usr/bin/php", "/etc/php.ini", "/"]
        );
        // 다이제스트는 옛 꼴에서도 파일과 같은 차례로 선다.
        let digests = arr(TAG_FILEDIGESTS, &[MD5_HEX, MD5_HEX, ""]);
        let got = file_digests(&pkg(&[old, digests])).unwrap();
        assert_eq!(got.algorithm, DigestAlgorithm::Md5);
        assert_eq!(got.digests, [MD5_HEX, MD5_HEX, ""]);
        // 설치된 패키지의 경로는 `/` 로 시작한다.
        for bad in ["usr/bin/php", ""] {
            assert_eq!(
                file_paths(&pkg(&[arr(TAG_OLDFILENAMES, &[bad])])),
                Err(RpmDbError::Format("파일 경로가 `/` 로 시작하지 않는다")),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_package_without_file_tags_owns_no_files() {
        // `gpg-pubkey` 처럼 파일이 없는 패키지 — 오류가 아니라 빈 목록이다.
        let blob = php_header();
        assert_eq!(file_paths(&blob), Ok(Vec::new()));
        assert_eq!(
            file_digests(&blob),
            Ok(FileDigests {
                algorithm: DigestAlgorithm::Md5,
                digests: Vec::new(),
            })
        );
        assert_eq!(modularity_label(&blob), Ok(None));
    }

    #[test]
    fn blobs_from_a_database_are_what_these_readers_take() {
        // 판독기 시험(`sqlite`)의 그 DB — `crate::blobs` 가 낸 블롭 다섯이 `crate::headers` 가 읽은 그것이고, 여기
        // 함수들이 그대로 받는다. 합성 헤더라 파일 꼬리표 · 모듈 꼬리표는 없다.
        let db = include_bytes!("../testdata/tiny-rpmdb.sqlite");
        let got = crate::blobs(db).expect("읽힌다");
        let (parsed, skipped) = crate::headers(db).unwrap();
        assert_eq!((got.len(), parsed.len(), skipped), (5, 5, 0));
        for (blob, h) in got.iter().zip(&parsed) {
            assert_eq!(parse(blob).as_ref(), Some(h));
            assert_eq!(file_paths(blob), Ok(Vec::new()));
            assert_eq!(file_digests(blob).map(|d| d.digests), Ok(Vec::new()));
            assert_eq!(modularity_label(blob), Ok(None));
        }
    }

    #[test]
    fn digests_come_in_file_order_for_md5_and_sha256() {
        for (algo, want, hex) in [
            (ALGO_MD5, DigestAlgorithm::Md5, MD5_HEX),
            (ALGO_SHA256, DigestAlgorithm::Sha256, SHA256_HEX),
        ] {
            // 대문자로 적혀 있어도 소문자로 맞춘다. 마지막 파일은 디렉터리라 다이제스트가 없다.
            let upper = hex.to_ascii_uppercase();
            let got = digests_with(&[
                arr(TAG_FILEDIGESTS, &[hex, &upper, hex, ""]),
                nums(TAG_FILEDIGESTALGO, &[algo]),
            ])
            .unwrap();
            assert_eq!(got.algorithm, want);
            assert_eq!(got.digests, [hex, hex, hex, ""]);
        }
        // 알고리즘이 SHA-256 인데 MD5 길이면 — 길이가 알고리즘을 정하지 않는다.
        assert_eq!(
            digests_with(&[
                arr(TAG_FILEDIGESTS, &[MD5_HEX, "", "", ""]),
                nums(TAG_FILEDIGESTALGO, &[ALGO_SHA256]),
            ]),
            Err(BAD_DIGEST)
        );
    }

    #[test]
    fn a_missing_algorithm_tag_means_md5() {
        let got = digests_with(&[arr(TAG_FILEDIGESTS, &[MD5_HEX, "", MD5_HEX, ""])]).unwrap();
        assert_eq!(got.algorithm, DigestAlgorithm::Md5);
        assert_eq!(got.digests, [MD5_HEX, "", MD5_HEX, ""]);
        // 꼬리표가 없는데 SHA-256 길이면 SHA-256 으로 짐작하지 않는다.
        assert_eq!(
            digests_with(&[arr(TAG_FILEDIGESTS, &[SHA256_HEX, "", "", ""])]),
            Err(BAD_DIGEST)
        );
    }

    #[test]
    fn arrays_that_disagree_in_length_are_errors() {
        let (bases, dirs) = (["php", "phar", "php.ini", "php.d"], ["/usr/bin/", "/etc/"]);
        // 파일 이름 넷에 디렉터리 번호 셋 · 다섯.
        for index in [&[0, 0, 1][..], &[0, 0, 1, 1, 1]] {
            assert_eq!(
                split(&bases, &dirs, index),
                Err(RpmDbError::Format(
                    "파일 이름 수와 디렉터리 번호 수가 다르다"
                ))
            );
        }
        // 디렉터리 번호가 목록(둘) 밖을 가리킨다.
        for index in [[0, 0, 1, 2], [0, 0, 1, u32::MAX]] {
            assert_eq!(
                split(&bases, &dirs, &index),
                Err(RpmDbError::Format("디렉터리 번호가 디렉터리 목록 밖이다"))
            );
        }
        // 파일 넷에 다이제스트 셋 · 다섯 — 다이제스트만 오류이고 경로는 읽힌다.
        for digests in [&[MD5_HEX; 3][..], &[MD5_HEX; 5]] {
            assert_eq!(
                digests_with(&[arr(TAG_FILEDIGESTS, digests)]),
                Err(RpmDbError::Format("파일 수와 다이제스트 수가 다르다"))
            );
        }
        // 파일은 넷인데 다이제스트 꼬리표가 없다 · 파일이 없는데 다이제스트가 있다.
        assert!(digests_with(&[]).is_err());
        assert!(file_digests(&pkg(&[arr(TAG_FILEDIGESTS, &[MD5_HEX])])).is_err());
        assert_eq!(file_paths(&pkg(&split_files())).unwrap().len(), 4);
    }

    #[test]
    fn absurd_counts_are_refused_before_anything_is_reserved() {
        let php = || s("php");
        let dirs = || arr(TAG_DIRNAMES, &["/usr/bin/"]);
        let index = || nums(TAG_DIRINDEXES, &[0]);
        // 개수는 블롭이 주장하는 값이다 — 40억 개라고 적혀 있어도 그만큼 잡지 않는다.
        for count in [u32::MAX, MAX_FILES as u32 + 1] {
            let names = (TAG_BASENAMES, TYPE_STRING_ARRAY, count, php());
            assert_eq!(
                file_paths(&pkg(&[names, dirs(), index()])),
                Err(BAD_COUNT),
                "{count}"
            );
            let lying = (
                TAG_DIRINDEXES,
                TYPE_INT32,
                count,
                0u32.to_be_bytes().to_vec(),
            );
            assert_eq!(
                file_paths(&pkg(&[arr(TAG_BASENAMES, &["php"]), dirs(), lying])),
                Err(BAD_COUNT),
                "{count}"
            );
            let digests = (TAG_FILEDIGESTS, TYPE_STRING_ARRAY, count, s(MD5_HEX));
            assert_eq!(digests_with(&[digests]), Err(BAD_COUNT), "{count}");
            let algo = (
                TAG_FILEDIGESTALGO,
                TYPE_INT32,
                count,
                8u32.to_be_bytes().to_vec(),
            );
            assert_eq!(digests_with(&[algo]), Err(BAD_COUNT), "{count}");
        }
        // 상한 안이어도 남은 자료보다 많으면 거짓이다 — 문자열 하나는 적어도 1바이트, 정수 하나는 4바이트를 쓴다.
        let names = (TAG_BASENAMES, TYPE_STRING_ARRAY, 50_000, php());
        assert_eq!(
            file_paths(&pkg(&[names, dirs(), index()])),
            Err(RpmDbError::Format("문자열 배열이 자료 밖으로 나간다"))
        );
        let lying = (
            TAG_DIRINDEXES,
            TYPE_INT32,
            50_000,
            0u32.to_be_bytes().to_vec(),
        );
        assert_eq!(
            file_paths(&pkg(&[arr(TAG_BASENAMES, &["php"]), dirs(), lying])),
            Err(RpmDbError::Format("정수 배열이 자료 밖으로 나간다"))
        );
        // 마지막 문자열이 NUL 없이 자료 끝에 닿는다 · 개수가 실제보다 하나 많다.
        for (count, value) in [(1, b"php".to_vec()), (2, php())] {
            let names = (TAG_BASENAMES, TYPE_STRING_ARRAY, count, value);
            assert_eq!(
                file_paths(&pkg(&[dirs(), index(), names])),
                Err(RpmDbError::Format("문자열 배열이 자료 밖으로 나간다"))
            );
        }
    }

    #[test]
    fn the_file_count_limit_sits_exactly_at_the_documented_number() {
        let read = |n: usize| {
            let names = vec!["f"; n];
            split(&names, &["/"], &vec![0; n])
        };
        assert_eq!(read(MAX_FILES).unwrap().len(), MAX_FILES);
        assert_eq!(read(MAX_FILES + 1), Err(BAD_COUNT));
    }

    #[test]
    fn paths_that_add_up_past_the_budget_are_a_limit() {
        // 긴 디렉터리 이름 하나를 파일마다 가리킨다 — 경로 하나가 1 KiB 라 16,384개가 꼭 상한이다. 블롭은 150 KiB
        // 안팎인데 이은 경로는 16 MiB 다.
        let dir = format!("/{}/", "d".repeat(1018));
        let read = |n: usize| {
            let blob = pkg(&[
                arr(TAG_BASENAMES, &vec!["f000"; n]),
                arr(TAG_DIRNAMES, &[&dir]),
                nums(TAG_DIRINDEXES, &vec![0; n]),
            ]);
            assert!(blob.len() < 160 * 1024, "블롭 {} 바이트", blob.len());
            file_paths(&blob)
        };
        let fits = MAX_PATH_BYTES / 1024;
        let got = read(fits).unwrap();
        assert_eq!(got.len(), fits);
        assert_eq!(got.iter().map(String::len).sum::<usize>(), MAX_PATH_BYTES);
        assert_eq!(
            read(fits + 1),
            Err(RpmDbError::Limit(
                "한 패키지의 경로를 더한 길이가 상한을 넘었다"
            ))
        );
        // 옛 꼴에도 같은 상한이 선다.
        let long = format!("/{}", "p".repeat(MAX_PATH_BYTES));
        assert!(matches!(
            file_paths(&pkg(&[arr(TAG_OLDFILENAMES, &[&long])])),
            Err(RpmDbError::Limit(_))
        ));
    }

    #[test]
    fn shapes_rpm_does_not_write_are_errors() {
        // `/usr/bin` 에 `php` 를 그대로 이으면 `/usr/binphp` 다 — 잇기 전에 막는다.
        for dir in ["/usr/bin", "usr/bin/", ""] {
            assert_eq!(
                split(&["php"], &[dir], &[0]),
                Err(RpmDbError::Format(
                    "디렉터리 이름이 `/` 로 시작하고 끝나지 않는다"
                )),
                "{dir:?}"
            );
        }
        assert_eq!(
            split(&["bin/php"], &["/usr/"], &[0]),
            Err(RpmDbError::Format("파일 이름에 `/` 가 들어 있다"))
        );
        assert_eq!(
            split(&[""], &["/usr/bin/"], &[0]),
            Err(RpmDbError::Format("이름이 빈 파일이 뿌리가 아니다"))
        );
        // 나눠 적은 셋 가운데 일부만 있다 · 두 꼴이 함께 있다.
        let [bases, dirs, index] = <[Tag; 3]>::try_from(split_files()).unwrap();
        let old = arr(TAG_OLDFILENAMES, &["/usr/bin/php"]);
        for tags in [
            vec![bases.clone()],
            vec![dirs.clone()],
            vec![bases.clone(), index.clone()],
            vec![dirs.clone(), index.clone()],
            vec![old.clone(), bases.clone(), dirs.clone(), index.clone()],
            vec![old, dirs.clone()],
        ] {
            assert_eq!(file_paths(&pkg(&tags)), Err(BAD_PAIRING));
            // 파일 수를 알 수 없으면 다이제스트의 짝도 알 수 없다.
            assert_eq!(file_digests(&pkg(&tags)), Err(BAD_PAIRING));
        }
        // 같은 꼬리표가 두 번 나온다.
        let twice = [bases.clone(), dirs.clone(), index.clone(), bases.clone()];
        assert_eq!(
            file_paths(&pkg(&twice)),
            Err(RpmDbError::Format("같은 꼬리표가 두 번 나온다"))
        );
        // 형이 다르다.
        let as_string = (TAG_BASENAMES, TYPE_STRING, 1, s("php"));
        assert_eq!(
            file_paths(&pkg(&[as_string, dirs.clone(), index.clone()])),
            Err(RpmDbError::Format(
                "문자열 배열이어야 할 꼬리표의 형이 다르다"
            ))
        );
        let as_strings = arr(TAG_DIRINDEXES, &["0", "0", "1", "1"]);
        assert_eq!(
            file_paths(&pkg(&[bases.clone(), dirs.clone(), as_strings])),
            Err(RpmDbError::Format(
                "정수 배열이어야 할 꼬리표의 형이 다르다"
            ))
        );
        // 꼬리표의 자리가 자료 밖이다 — 넷째 항목(파일 이름)의 자리 칸을 바꾼다.
        let mut blob = pkg(&[bases, dirs, index]);
        let at = 8 + 3 * 16 + 8;
        blob[at..at + 4].copy_from_slice(&0x7FFF_FFFFu32.to_be_bytes());
        assert_eq!(
            file_paths(&blob),
            Err(RpmDbError::Format("꼬리표의 자리가 자료 밖이다"))
        );
    }

    #[test]
    fn digests_the_reader_cannot_check_are_errors() {
        let four = |hex: &'static str| arr(TAG_FILEDIGESTS, &[hex, hex, hex, ""]);
        // rpm 이 아는 다른 알고리즘(2 = SHA-1)은 읽지 않는다 — 길이를 확인할 수 없다.
        let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        for algo in [0, 2, 10] {
            assert_eq!(
                digests_with(&[four(sha1), nums(TAG_FILEDIGESTALGO, &[algo])]),
                Err(RpmDbError::Format("읽지 않는 파일 다이제스트 알고리즘이다")),
                "{algo}"
            );
        }
        assert_eq!(
            digests_with(&[four(SHA256_HEX), nums(TAG_FILEDIGESTALGO, &[8, 8])]),
            Err(RpmDbError::Format(
                "파일 다이제스트 알고리즘 값이 하나가 아니다"
            ))
        );
        let as_string = (TAG_FILEDIGESTALGO, TYPE_STRING, 1, s("8"));
        assert_eq!(
            digests_with(&[four(SHA256_HEX), as_string]),
            Err(RpmDbError::Format(
                "정수 배열이어야 할 꼬리표의 형이 다르다"
            ))
        );
        // 길이가 모자라다 · 넘친다 · 16진이 아니다.
        for bad in [
            &MD5_HEX[1..],
            "d41d8cd98f00b204e9800998ecf8427e0",
            "z41d8cd98f00b204e9800998ecf8427e",
        ] {
            assert_eq!(
                digests_with(&[arr(TAG_FILEDIGESTS, &[MD5_HEX, bad, "", ""])]),
                Err(BAD_DIGEST),
                "{bad}"
            );
        }
        // 그때도 경로는 읽힌다.
        let mut entries = split_files();
        entries.push(four(sha1));
        entries.push(nums(TAG_FILEDIGESTALGO, &[2]));
        assert_eq!(file_paths(&pkg(&entries)).unwrap().len(), 4);
    }

    #[test]
    fn the_module_label_is_read_when_the_header_carries_one() {
        let label = "php:8.2:20240101:abcdef01";
        let blob = pkg(&[(TAG_MODULARITYLABEL, TYPE_STRING, 1, s(label))]);
        assert_eq!(modularity_label(&blob), Ok(Some(label.to_string())));
        assert_eq!(modularity_label(&pkg(&[])), Ok(None));
        // 있는데 읽히지 않으면 없다고 하지 않는다 — 형이 다르다 · NUL 없이 자료 끝에 닿는다.
        assert_eq!(
            modularity_label(&pkg(&[arr(TAG_MODULARITYLABEL, &[label])])),
            Err(RpmDbError::Format("모듈 꼬리표가 문자열이 아니다"))
        );
        let open = (
            TAG_MODULARITYLABEL,
            TYPE_STRING,
            1,
            label.as_bytes().to_vec(),
        );
        assert_eq!(
            modularity_label(&pkg(&[open])),
            Err(RpmDbError::Format(
                "모듈 꼬리표가 자료 안에서 끝나지 않는다"
            ))
        );
    }

    #[test]
    fn bytes_that_are_not_utf8_do_not_stop_the_list() {
        let names = (TAG_BASENAMES, TYPE_STRING_ARRAY, 1, b"caf\xE9\0".to_vec());
        let dirs = arr(TAG_DIRNAMES, &["/usr/bin/"]);
        assert_eq!(
            file_paths(&pkg(&[names, dirs, nums(TAG_DIRINDEXES, &[0])])).unwrap(),
            ["/usr/bin/caf\u{FFFD}"]
        );
    }

    #[test]
    fn cut_or_flipped_blobs_never_panic_or_yield_a_shorter_list() {
        let mut entries = split_files();
        entries.push(arr(
            TAG_FILEDIGESTS,
            &[SHA256_HEX, SHA256_HEX, SHA256_HEX, ""],
        ));
        entries.push(nums(TAG_FILEDIGESTALGO, &[ALGO_SHA256]));
        entries.push((TAG_MODULARITYLABEL, TYPE_STRING, 1, s("php:8.2")));
        let blob = pkg(&entries);
        assert_eq!(file_paths(&blob).unwrap().len(), 4);
        assert_eq!(file_digests(&blob).unwrap().digests.len(), 4);
        assert_eq!(modularity_label(&blob), Ok(Some("php:8.2".to_string())));
        // 잘린 블롭은 틀이 맞지 않는다 — 짧아진 목록을 조용히 내지 않고 셋 다 오류다.
        for cut in 0..blob.len() {
            let b = &blob[..cut];
            assert!(file_paths(b).is_err(), "{cut}");
            assert!(file_digests(b).is_err(), "{cut}");
            assert!(modularity_label(b).is_err(), "{cut}");
        }
        // 바이트를 바꾼 것은 패닉만 없으면 된다.
        let mut b = blob.clone();
        for i in 0..b.len() {
            let keep = b[i];
            for v in [0x00, 0xFF, keep ^ 0x80] {
                b[i] = v;
                let _ = (file_paths(&b), file_digests(&b), modularity_label(&b));
            }
            b[i] = keep;
        }
    }
}
