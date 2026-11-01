//! 실행 파일에 박힌 버전을 스냅샷에 담는다 (C-1b · 설계-02 §3).
//!
//! # 왜 본문을 담는 길로는 모자랐나
//!
//! 지금까지 버전은 **YARA 로만** 볼 수 있었다 — `pe.version_info["ProductVersion"]`
//! 에 계열마다 범위 정규식을 손으로 썼다. 그 길은 본문을 스냅샷에 담아야 하고
//! `collect_extra` 의 `ref` 형은 **8 MiB 고정**이라 큰 바이너리가 늘 관측
//! 불완전(6)으로 끝난다. 버전이 필드로 오면 `version_lt` 가 바로 받는다.
//!
//! # 왜 `unsafe` 를 쓰지 않는가
//!
//! [`remedy_wintrust`] 가 `unsafe` 를 쓰는 근거는 *"순수 Rust 로는 정상 시스템
//! 파일이 **서명 없음**이 된다"* 였다 — **안전한 코드가 틀린 답을 내기 때문**이다
//! (카탈로그 서명 · X.509 체인). 버전은 사정이 반대다. 버전 리소스는 `.rsrc`
//! 안의 자기완결 구조라 OS 지식이 필요 없고, `object` 가 PE 를 읽는 길을 이미
//! 준다(yara-x 가 끌어오는 크레이트라 새 의존이 늘지 않는다).
//!
//! # 어느 값을 담는가 — **문자열 `FileVersion`** 이다
//!
//! 버전 리소스에는 둘이 있다. `VS_FIXEDFILEINFO` 의 `dwFileVersionMS`·`LS`(u16
//! 넷)와 `StringFileInfo` 의 `FileVersion`(자유 형식). **처음 판은 2진 값을
//! 담았고 그것이 틀렸다** — 적대 검증이 실측으로 잡았다(2026-10-27).
//!
//! | 파일 | 파일이 선언한 문자열 | 2진 고정값 | 공급사 공지 |
//! |---|---|---|---|
//! | `postgres.exe` | `16.10` | `16.0.10.0` | **16.10** |
//! | `JHI.dll` | `1.46.2024.0221` | `1.46.2024.221` | — (앞의 0) |
//!
//! 공급사는 **문자열 눈금**으로 공지한다. 2진 값을 담으면 권고대로 적은
//! `version_lt "16.10"` 이 `16.0.10.0` 에 맞는다 — 성분 2 가 `0` vs `10` 이라
//! `component_cmp` 가 길이로 Less 를 내고, **완전 패치된 16.10 기계가 취약으로**
//! 나간다. PostgreSQL 16.x 는 전부 `16.0.<부>.0` 이라 빠져나갈 길이 없다.
//!
//! 실물 PE **3,410개 중 20.4%** 에서 두 눈금이 다르다(`FileVersion` 키가 한 번만
//! 나와 바이트로 가릴 수 있는 것만 셌다). 대부분은 앞의 0 처럼 비교에 영향이
//! 없는 외형 차이지만, PostgreSQL 처럼 **눈금이 갈리면 판정이 뒤집힌다.**
//!
//! # 공백 뒤 주석만 버린다
//!
//! 같은 표본의 문자열 모양은 **순수 점숫자 74.6% · 점숫자 + 공백 뒤 주석
//! 23.9% · 그 밖 1.5%** 다. `(WinBuild.160101.0800)` 처럼 **공백으로 떨어진**
//! 주석만 버리면 98.5% 가 비교 가능해진다.
//!
//! **숫자에 붙은 꼬리는 버리지 않는다.** `8.2.29-dev` 를 `8.2.29` 로 줄이면
//! 사전 배포를 정식 판이라고 말하는 것이고, C-1 이 꼬리를 거부하는 이유가 바로
//! 그것이다(사전 배포와 패키지 개정이 모양은 같고 순서가 반대다). 그런 값은
//! 담되 `version_lt` 가 거부해 **종료 6**(사람이 본다)으로 간다.
//!
//! # 담지 않는 것
//!
//! # OS 가 아니라 **파일**을 읽는다
//!
//! `GetFileVersionInfo`(와 `.NET` 의 `FileVersionInfo`)는 서비싱이 걸린 자리에서
//! **파일이 선언한 것과 다른 값**을 낸다 — 실측으로 갈렸다(2026-10-27):
//!
//! | 경로 | 파일 바이트 | `.NET` |
//! |---|---|---|
//! | `System32\notepad.exe` | `10.0.26100.9278` | `10.0.26100.8457` |
//! | 그 파일을 복사한 것 | `10.0.26100.9278` | `10.0.26100.9278` |
//!
//! 같은 바이트인데 **경로에 따라 OS 의 답이 달라진다.** 우리는 파일을 읽는다 —
//! 그래야 ① 같은 스냅샷을 다른 기계에서 평가한 결과가 같고(설계-03 §1 — 탐지는
//! 불활성 스냅샷 위에서만 돈다) ② 같은 자리를 보는 기존 길(YARA 의
//! `pe.version_info`)과 어긋나지 않는다. `tests/peversion_real.rs` 의 오라클이
//! `.NET` 이 아니라 바이트 탐색인 것도 그 때문이다.
//!
//! - **값이 없는 파일.** `None` 은 [`crate::signature`] 와 같은 뜻이다 —
//!   **"확인하지 않았다"**. 대상 형식이 아니었거나, 상한을 넘어 읽지 않았거나,
//!   리소스가 없거나, 버전을 선언하지 않았다. "버전이 0 이다" 가 아니다.
//! - **전부 0 인 값**(`0.0.0.0`). 리소스는 있는데 버전을 선언하지 않은 파일이
//!   흔하고, 담으면 `version_lt "8.2.29"` 가 **그 파일 전부에 맞는다**.

/// `RT_VERSION`. 리소스 종류 번호다 (Windows `menurc` 문서).
const RT_VERSION: u16 = 16;

/// `VS_VERSION_INFO`. 버전 리소스의 **이름**(ID)이다.
///
/// # 왜 첫 항목을 쓰지 않는가 (2026-10-27 적대 검증 · high)
///
/// 처음 판은 이름 층에서 `entries.first()` 를 썼다. 그런데 리소스 디렉터리는
/// **이름 붙은 항목을 ID 항목보다 앞에** 쌓는다 — 실물 3,103건 전부가 그랬고
/// 뒤집힌 예가 한 건도 없다(실측). 그래서 이름 붙은 version 리소스가 하나라도
/// 있는 PE 에서는 첫 항목이 **ID 1 이 아니고**, Windows 가 보는 값과 갈린다.
///
/// 손으로 꾸민 PE 로 **취약한 기계를 양호로** 내보낼 수 있는 길이다. 종류 층이
/// 이미 번호를 지정하고 있었으므로(`RT_VERSION`) 같은 규율을 한 층 더 적는다.
const VS_VERSION_INFO: u16 = 1;

/// 버전 정보 노드 하나. 머리 모양이 층마다 같아서 한 함수로 걷는다.
///
/// ```text
/// WORD wLength       이 노드 전체(자식 포함)
/// WORD wValueLength  wType==1 이면 **낱말 수**, 0 이면 바이트 수
/// WORD wType         1 = 글자, 0 = 이진
/// WCHAR szKey[]      NUL 로 끝난다
/// (4바이트 경계) Value
/// (4바이트 경계) Children
/// ```
struct Node<'a> {
    key: String,
    value: &'a [u8],
    children: &'a [u8],
}

/// 4바이트 경계로 올린다. 버전 리소스의 모든 자리가 이 규칙을 쓴다.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(*b.get(at..at + 2)?.first_chunk::<2>()?))
}

/// NUL 로 끝나는 UTF-16LE 열. 끝나지 않으면 `None` — 추측하지 않는다.
fn utf16_key(b: &[u8], at: usize) -> Option<(String, usize)> {
    let mut units = Vec::new();
    let mut i = at;
    loop {
        let u = u16_at(b, i)?;
        i += 2;
        if u == 0 {
            break;
        }
        units.push(u);
        // 이름이 길어질 수 있는 구조가 아니다. 상한이 없으면 깨진 블롭에서
        // 블롭 끝까지 읽는다.
        if units.len() > 256 {
            return None;
        }
    }
    Some((String::from_utf16(&units).ok()?, i))
}

fn node(blob: &[u8]) -> Option<Node<'_>> {
    let length = u16_at(blob, 0)? as usize;
    let value_len_raw = u16_at(blob, 2)? as usize;
    let kind = u16_at(blob, 4)?;
    let (key, after_key) = utf16_key(blob, 6)?;
    // **낱말 수와 바이트 수를 가른다.** 글자 값의 `wValueLength` 는 낱말 수다 —
    // 바이트로 읽으면 절반만 읽고 뒤를 자식으로 오인한다.
    let value_len = if kind == 1 {
        value_len_raw.checked_mul(2)?
    } else {
        value_len_raw
    };
    let value_at = align4(after_key);
    let value_end = value_at.checked_add(value_len)?;
    let value = blob.get(value_at..value_end)?;
    // 노드의 끝은 `wLength` 가 정한다. 블롭보다 크다고 적혀 있으면 블롭을 믿는다.
    let end = length.min(blob.len());
    let children_at = align4(value_end);
    let children = if children_at < end {
        blob.get(children_at..end)?
    } else {
        &[]
    };
    Some(Node {
        key,
        value,
        children,
    })
}

/// 형제 노드를 차례로 돈다. 길이가 0 이면 멈춘다 — 그러지 않으면 깨진 블롭에서
/// 제자리를 돈다.
fn siblings(mut blob: &[u8]) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    while blob.len() >= 6 {
        let Some(length) = u16_at(blob, 0) else { break };
        let length = align4(length as usize);
        if length == 0 || length > blob.len() {
            // 마지막 노드는 패딩 없이 끝날 수 있다. 한 번은 통째로 시도한다.
            if let Some(n) = node(blob) {
                out.push(n);
            }
            break;
        }
        if let Some(n) = node(&blob[..length]) {
            out.push(n);
        }
        blob = &blob[length..];
        // 노드가 1,000개를 넘는 버전 리소스는 없다. 상한이 없으면 깨진 블롭이
        // 메모리를 먹는다.
        if out.len() > 1000 {
            break;
        }
    }
    out
}

/// 이 경로의 버전을 읽을 것인가.
///
/// **[`crate::signature::should_check`] 와 같은 목록을 쓴다.** 버전 리소스를
/// 실을 수 있는 형식이 곧 Authenticode 를 실을 수 있는 형식이고, 두 목록이
/// 갈리면 한쪽만 채워진 레코드가 생긴다.
pub fn should_read(path: &str) -> bool {
    crate::signature::should_check(path)
}

/// 이미 읽어 둔 바이트에서 버전을 읽는다. **파일을 다시 열지 않는다.**
///
/// 수집기는 해시를 위해 본문을 이미 읽는다. 그 바이트를 그대로 받으므로 추가
/// 입출력이 없고, 상한(`max_hash_bytes`)을 넘어 읽지 못한 파일은 애초에 여기
/// 오지 않는다 — 그 경우는 `None` 이고 `sha256` 이 `None` 인 것과 같은 자리다.
pub fn of(path: &str, bytes: &[u8]) -> Option<String> {
    if !should_read(path) {
        return None;
    }
    let raw = file_version_string(bytes)?;
    let v = trim_comment(&raw);
    if v.is_empty() {
        return None;
    }
    // 선언하지 않은 버전. 담으면 `version_lt` 가 그 파일 전부에 맞는다.
    if v.split('.').all(|c| c.chars().all(|d| d == '0')) {
        return None;
    }
    Some(v.to_string())
}

/// **공백으로 떨어진 주석만** 버린다. 숫자에 붙은 꼬리는 남긴다 — 모듈 설명 참조.
fn trim_comment(s: &str) -> &str {
    let s = s.trim();
    match s.find(char::is_whitespace) {
        Some(i) => s[..i].trim_end(),
        None => s,
    }
}

/// `StringFileInfo` 의 `FileVersion`.
fn file_version_string(bytes: &[u8]) -> Option<String> {
    let blob = version_resource(bytes)?;
    let root = node(&blob)?;
    if root.key != "VS_VERSION_INFO" {
        return None;
    }
    for child in siblings(root.children) {
        if child.key != "StringFileInfo" {
            continue;
        }
        // 언어·코드페이지 표가 여럿일 수 있다. **값을 가진 첫 표**를 쓴다 —
        // `.NET` 의 `FileVersionInfo` 도 번역 목록의 첫 것을 쓰고, 그 일치는
        // `tests/peversion_real.rs` 가 실물로 댄다.
        for table in siblings(child.children) {
            for s in siblings(table.children) {
                if s.key != "FileVersion" {
                    continue;
                }
                let units: Vec<u16> = s
                    .value
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&u| u != 0)
                    .collect();
                let text = String::from_utf16(&units).ok()?;
                if !text.trim().is_empty() {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// `.rsrc` 에서 `RT_VERSION` / `VS_VERSION_INFO` 블롭을 꺼낸다.
///
/// 32비트·64비트 PE 를 둘 다 받는다. 어느 단계에서든 어긋나면 `None` — 추측하지
/// 않는다. 깨진 입력에 값을 지어내면 그것이 곧 오탐이다.
fn version_resource(bytes: &[u8]) -> Option<Vec<u8>> {
    use object::read::pe::{PeFile32, PeFile64};

    // 64비트를 먼저 본다. 실패하면 32비트다 — 매직을 손으로 읽는 대신
    // 파서에게 묻는다.
    if let Ok(f) = PeFile64::parse(bytes) {
        return blob_of(&f, bytes);
    }
    let f = PeFile32::parse(bytes).ok()?;
    blob_of(&f, bytes)
}

fn blob_of<'a, H>(f: &object::read::pe::PeFile<'a, H>, bytes: &'a [u8]) -> Option<Vec<u8>>
where
    H: object::read::pe::ImageNtHeaders,
{
    let sections = f.section_table();
    let dir = f
        .data_directories()
        .resource_directory(bytes, &sections)
        .ok()??;

    // 리소스 트리는 **종류 → 이름 → 언어** 석 층이다. 앞의 두 층은 번호를
    // 지정한다(`RT_VERSION` · `VS_VERSION_INFO`) — 첫 항목을 쓰면 꾸민 PE 가
    // 값을 바꿔치기할 수 있다(위 `VS_VERSION_INFO` 설명).
    let root = dir.root().ok()?;
    let by_type = root
        .entries
        .iter()
        .find(|e| !e.has_name() && e.name_or_id().id() == Some(RT_VERSION))?;
    let names = by_type.data(dir).ok()?.table()?;
    let by_name = names
        .entries
        .iter()
        .find(|e| !e.has_name() && e.name_or_id().id() == Some(VS_VERSION_INFO))?;
    // **언어 층은 첫 항목이다.** 한 파일이 언어마다 다른 버전을 선언하는 일은
    // 없고, 있다면 그것을 가릴 근거가 우리에게 없다.
    let langs = by_name.data(dir).ok()?.table()?;
    let entry = langs.entries.first()?.data(dir).ok()?.data()?;

    let rva = entry.offset_to_data.get(object::LittleEndian);
    let size = entry.size.get(object::LittleEndian) as usize;
    let blob = sections.pe_data_at(bytes, rva)?;
    Some(blob.get(..size.min(blob.len()))?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 실행_파일만_읽는다() {
        // 서명과 같은 목록이다 — 갈리면 한쪽만 채워진 레코드가 생긴다.
        assert!(should_read("C:\\x\\php.exe"));
        assert!(should_read("C:\\x\\php8ts.dll"));
        assert!(!should_read("C:\\x\\php.ini"));
        assert!(!should_read("/usr/bin/php"));
    }

    #[test]
    fn pe_가_아닌_것은_값을_지어내지_않는다() {
        for b in [
            &b""[..],
            &b"MZ"[..],
            &b"not a pe at all"[..],
            // ELF 머리.
            &[0x7f, b'E', b'L', b'F', 2, 1, 1, 0][..],
            &[0u8; 4096][..],
        ] {
            assert_eq!(of("C:\\x\\a.exe", b), None, "{b:?} 에서 값이 나왔다");
        }
    }

    #[test]
    fn 공백_뒤_주석만_버린다() {
        // 실물 23.9% 가 이 모양이다 — 버리지 않으면 비교가 거부한다.
        assert_eq!(
            trim_comment("10.0.26100.9549 (WinBuild.160101.0800)"),
            "10.0.26100.9549"
        );
        assert_eq!(trim_comment("  16.10  "), "16.10");
        assert_eq!(trim_comment("8.2.29"), "8.2.29");
        // **숫자에 붙은 꼬리는 남긴다.** 줄이면 사전 배포를 정식 판이라고
        // 말하는 것이고, 그래서 `version_lt` 가 거부해 종료 6 으로 간다.
        assert_eq!(trim_comment("8.2.29-dev"), "8.2.29-dev");
        assert_eq!(trim_comment("8.4.0RC1"), "8.4.0RC1");
        assert_eq!(trim_comment("1.90.3.60"), "1.90.3.60");
    }

    /// 노드 하나를 짓는다 — `wType` 은 글자(1)로, 값은 UTF-16 로 넣는다.
    fn text_node(key: &str, value: &str, children: &[u8]) -> Vec<u8> {
        let mut k: Vec<u8> = key.encode_utf16().flat_map(u16::to_le_bytes).collect();
        k.extend_from_slice(&[0, 0]);
        let mut v: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        if !value.is_empty() {
            v.extend_from_slice(&[0, 0]);
        }
        let mut out = vec![0u8; 6];
        out.extend_from_slice(&k);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(&v);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(children);
        let len = out.len() as u16;
        out[0..2].copy_from_slice(&len.to_le_bytes());
        // 낱말 수다 — 바이트 수를 적으면 뒤를 자식으로 오인한다.
        out[2..4].copy_from_slice(&((v.len() / 2) as u16).to_le_bytes());
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        out
    }

    fn version_blob(file_version: &str) -> Vec<u8> {
        let s = text_node("FileVersion", file_version, &[]);
        let table = text_node("040904b0", "", &s);
        let sfi = text_node("StringFileInfo", "", &table);
        text_node("VS_VERSION_INFO", "", &sfi)
    }

    #[test]
    fn 블롭에서_문자열을_꺼낸다() {
        let blob = version_blob("16.10");
        let root = node(&blob).expect("뿌리");
        assert_eq!(root.key, "VS_VERSION_INFO");
        let sfi = siblings(root.children);
        assert_eq!(
            sfi.len(),
            1,
            "{:?}",
            sfi.iter().map(|n| &n.key).collect::<Vec<_>>()
        );
        assert_eq!(sfi[0].key, "StringFileInfo");
    }

    #[test]
    fn 깨진_블롭에서_제자리를_돌지_않는다() {
        // 길이가 0 인 노드 · 블롭보다 큰 길이 · 잘린 머리.
        for b in [
            vec![0u8; 64],
            vec![0xFF, 0xFF, 0, 0, 1, 0, 0, 0],
            vec![6, 0, 0, 0, 1, 0],
            vec![4, 0],
        ] {
            let start = std::time::Instant::now();
            let _ = siblings(&b);
            let _ = node(&b);
            assert!(
                start.elapsed().as_millis() < 100,
                "{b:?} 에서 돌아오지 않는다"
            );
        }
    }

    #[test]
    fn 선언하지_않은_버전은_담지_않는다() {
        // `"0.0.0.0"` 을 담으면 `version_lt "8.2.29"` 가 그 파일 전부에 맞는다.
        // `of` 는 PE 를 요구하므로 그 갈래만 따로 잰다.
        for v in ["0.0.0.0", "0", "0.0", "00.00.00.00"] {
            assert!(
                v.split('.').all(|c| c.chars().all(|d| d == '0')),
                "{v} 를 전부 0 으로 읽지 못했다"
            );
        }
        assert!(!"0.0.1.0".split('.').all(|c| c.chars().all(|d| d == '0')));
    }
}
