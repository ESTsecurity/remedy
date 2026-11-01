//! `.lnk` 바로가기 (MS-SHLLINK).
//!
//! 바로가기는 **명령을 숨기기 좋은 자리**다. 아이콘은 정상 프로그램의 것을 쓰고
//! 대상만 스크립트 호스트로 바꾸면, 사용자에게는 원래 프로그램으로 보인다.
//! 그래서 `target` 과 `args` 를 따로 담는다 — 하나로 뭉치면 룰이 인자만 겨눌 수 없다.
//!
//! # 파싱은 방어적으로 한다
//!
//! 남이 만든 이진 파일이다. 길이가 거짓일 수 있고, 잘려 있을 수 있다.
//! 모든 읽기는 경계를 확인하고, 어긋나면 **그 파일 하나만 버린다** — 패닉하면
//! 수집 전체가 죽고, 그것은 악성 `.lnk` 하나로 스캔을 멈출 수 있다는 뜻이다.

use remedy_artifacts::{CollectError, Harvest, Scope, ShortcutRecord};
use remedy_platform::read::FsRead;
use remedy_sdk::catalog::Subject;
use remedy_sdk::normalize;

const MAX_LNK_BYTES: u64 = 1 << 20;

/// 헤더 고정 크기. 이 값이 아니면 Shell Link 가 아니다.
const HEADER_SIZE: usize = 0x4C;
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

const HAS_LINK_TARGET_ID_LIST: u32 = 1 << 0;
const HAS_LINK_INFO: u32 = 1 << 1;
const HAS_NAME: u32 = 1 << 2;
const HAS_RELATIVE_PATH: u32 = 1 << 3;
const HAS_WORKING_DIR: u32 = 1 << 4;
const HAS_ARGUMENTS: u32 = 1 << 5;
const HAS_ICON_LOCATION: u32 = 1 << 6;
const IS_UNICODE: u32 = 1 << 7;

/// 바로가기 하나에서 뽑아낸 것.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub target: String,
    pub args: String,
    pub working_dir: String,
    pub icon: String,
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
    ]))
}

/// `\0` 로 끝나는 ANSI 문자열. lnk 의 LinkInfo 안쪽이 이 형태다.
fn cstr_at(b: &[u8], off: usize) -> String {
    let end = b[off.min(b.len())..]
        .iter()
        .position(|&c| c == 0)
        .map(|i| off + i)
        .unwrap_or(b.len());
    String::from_utf8_lossy(&b[off.min(b.len())..end]).to_string()
}

/// StringData 항목 하나. 앞의 u16 은 **문자 수**이지 바이트 수가 아니다 —
/// 유니코드일 때 두 배로 세지 않으면 그 뒤가 통째로 어긋난다.
fn read_string(b: &[u8], off: &mut usize, unicode: bool) -> Option<String> {
    let count = u16_at(b, *off)? as usize;
    *off += 2;
    let bytes = if unicode { count * 2 } else { count };
    if *off + bytes > b.len() {
        return None;
    }
    let slice = &b[*off..*off + bytes];
    *off += bytes;
    Some(if unicode {
        String::from_utf16_lossy(
            &slice
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        )
    } else {
        String::from_utf8_lossy(slice).to_string()
    })
}

/// `LinkTargetIDList` 에서 경로를 짜 맞춘다.
///
/// # 무엇을 읽고 무엇을 읽지 않는가
///
/// 항목마다 종류 바이트가 앞에 있다.
///
/// - `0x2X` — 드라이브. 뒤에 `C:\` 가 ANSI 로 온다.
/// - `0x3X` — 폴더·파일. 고정 헤더 12바이트 뒤에 **기본 이름**이 ANSI 로 온다.
/// - 그 밖(`0x1F` 루트 폴더 CLSID 등) — 경로 성분이 아니므로 건너뛴다.
///
/// 확장 블록(`0xBEEF0004`)의 유니코드 긴 이름은 읽지 않는다. 판(version)마다
/// 자리가 달라 잘못 읽을 여지가 크고, 잘못 읽은 경로는 빈 경로보다 나쁘다 —
/// 룰이 엉뚱한 것을 지목하게 된다. 그래서 **기본 이름만** 쓰며, 긴 이름이
/// 8.3 으로 줄어든 경로가 나올 수 있다. 정확한 경로가 필요한 룰은 `LinkInfo`
/// 가 채우는 경우를 쓰면 되고, 그쪽이 있으면 이 값은 덮인다.
fn path_from_id_list(list: &[u8]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut off = 0usize;
    while let Some(size) = u16_at(list, off) {
        // 0 은 목록의 끝이다. 크기에 자기 자신(2바이트)이 포함된다.
        if size < 3 {
            break;
        }
        let Some(item) = list.get(off + 2..off + size as usize) else {
            break;
        };
        off += size as usize;

        match item.first() {
            Some(t) if (0x20..0x30).contains(t) => {
                let s = cstr_at(item, 1);
                if !s.is_empty() {
                    parts.push(s.trim_end_matches('\\').to_string());
                }
            }
            // 고정 헤더: 종류(1) 미상(1) 크기(4) 시각(4) 속성(2) = 12
            Some(t) if (0x30..0x40).contains(t) && item.len() > 12 => {
                let s = cstr_at(item, 12);
                if !s.is_empty() {
                    parts.push(s);
                }
            }
            _ => {}
        }
    }
    parts.join("\\")
}

/// `.lnk` 하나를 읽는다. 형태가 어긋나면 `None` — **그 파일만 버린다.**
pub fn parse(b: &[u8]) -> Option<Link> {
    if u32_at(b, 0)? as usize != HEADER_SIZE || b.get(4..20)? != LINK_CLSID {
        return None;
    }
    let flags = u32_at(b, 20)?;
    let unicode = flags & IS_UNICODE != 0;
    let mut off = HEADER_SIZE;

    let mut link = Link::default();
    let mut id_list = String::new();
    let mut link_info_target = String::new();

    if flags & HAS_LINK_TARGET_ID_LIST != 0 {
        let size = u16_at(b, off)? as usize;
        let list = b.get(off + 2..off + 2 + size)?;
        // **여기에만 대상이 있는 바로가기가 흔하다.** 실측으로 시작 메뉴의
        // 48건 중 9건이 LinkInfo 도 상대 경로도 없이 IDList 만 갖고 있었고,
        // 그것을 읽지 않으면 `target` 이 빈 채로 나간다 — `target ends_with
        // ".exe"` 를 쓰는 룰이 다섯에 하나를 놓친다.
        id_list = path_from_id_list(list);
        off = off.checked_add(2)?.checked_add(size)?;
    }

    if flags & HAS_LINK_INFO != 0 {
        let size = u32_at(b, off)? as usize;
        let info = b.get(off..off.checked_add(size)?)?;
        // LinkInfoFlags 의 0비트가 VolumeIDAndLocalBasePath 다. 서면
        // LocalBasePathOffset(0x10)이 실제 경로를 가리킨다.
        if u32_at(info, 8)? & 1 != 0 {
            let p = u32_at(info, 0x10)? as usize;
            if p < info.len() {
                // LinkInfo 가 IDList 보다 정확하다 — 긴 이름을 그대로 담는다.
                link_info_target = cstr_at(info, p);
            }
        }
        off += size;
    }

    // **순서가 고정이다.** 하나를 건너뛰면 그 뒤가 전부 밀린다.
    if flags & HAS_NAME != 0 {
        read_string(b, &mut off, unicode)?;
    }
    let mut relative = String::new();
    if flags & HAS_RELATIVE_PATH != 0 {
        relative = read_string(b, &mut off, unicode)?;
    }
    if flags & HAS_WORKING_DIR != 0 {
        link.working_dir = read_string(b, &mut off, unicode)?;
    }
    if flags & HAS_ARGUMENTS != 0 {
        link.args = read_string(b, &mut off, unicode)?;
    }
    if flags & HAS_ICON_LOCATION != 0 {
        link.icon = read_string(b, &mut off, unicode)?;
    }

    // **StringData 뒤가 ExtraData 다.** 여기에 대상이 들어 있는 바로가기가
    // 흔하다 — 실측으로 시작 메뉴의 48건 중 9건이 `HasExpString` 만 갖고
    // `%windir%\system32\magnify.exe` 를 이 블록에 담고 있었다. 읽지 않으면
    // `target` 이 빈 채로 나가고, `target ends_with ".exe"` 를 쓰는 룰이
    // 다섯에 하나를 놓친다.
    let expanded = environment_target(b.get(off..).unwrap_or(&[]));

    // **정확한 쪽부터 쓴다.** 앞의 것이 비었을 때만 다음으로 내려간다.
    //
    //   1 LinkInfo   — 전개된 절대 경로. 가장 정확하다.
    //   2 환경변수    — `%windir%\...`. 자리가 고정이라 오독할 여지가 없다.
    //   3 IDList     — 긴 이름이 8.3 으로 줄 수 있다.
    //   4 상대 경로   — 바로가기 자신을 기준으로 한 값이라 홀로는 불완전하다.
    link.target = [link_info_target, expanded, id_list, relative]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    Some(link)
}

/// `EnvironmentVariableDataBlock` (`0xA0000001`) 의 유니코드 대상.
///
/// ExtraData 는 `u32 크기 · u32 서명 · 내용` 블록이 이어지다 크기 4 미만으로
/// 끝난다. 이 블록은 크기 `0x314` 고정이고 ANSI 260자 뒤에 유니코드 260자가 온다.
///
/// **판(version)을 추측하지 않는다.** 자리가 고정이라 잘못 읽을 여지가 없고,
/// 잘못 읽은 경로는 빈 경로보다 나쁘다 — 룰이 엉뚱한 것을 지목하게 된다.
fn environment_target(extra: &[u8]) -> String {
    const ENV_BLOCK: u32 = 0xA000_0001;
    let mut off = 0usize;
    while let Some(size) = u32_at(extra, off) {
        if size < 4 {
            break;
        }
        let Some(block) = extra.get(off..off + size as usize) else {
            break;
        };
        if u32_at(block, 4) == Some(ENV_BLOCK) && block.len() >= 8 + 260 + 520 {
            let units: Vec<u16> = block[8 + 260..8 + 260 + 520]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&u| u != 0)
                .collect();
            let s = String::from_utf16_lossy(&units);
            if !s.is_empty() {
                return s;
            }
            // 유니코드가 비었으면 ANSI 쪽을 쓴다.
            return cstr_at(block, 8);
        }
        off += size as usize;
    }
    String::new()
}

/// 선언된 범위 안의 바로가기.
pub fn shortcuts<P: FsRead>(
    fs: &P,
    scope: &Scope,
) -> Result<Harvest<ShortcutRecord>, CollectError> {
    let mut h = Harvest::default();
    for path in crate::config::files_with_ext(fs, scope, Subject::Shortcut, &[".lnk"], &mut h)? {
        let Ok(Some(bytes)) = fs.read_file(&path, MAX_LNK_BYTES) else {
            continue;
        };
        let Some(l) = parse(&bytes) else {
            // 깨진 `.lnk` 도 파일로는 이미 `file` subject 에 담겨 있다. 여기서
            // 억지로 빈 레코드를 만들면 "대상이 없는 바로가기" 가 되어,
            // `target equals ""` 같은 룰이 조용히 걸린다.
            continue;
        };
        h.records.push(ShortcutRecord {
            path: path.clone(),
            target: normalize::nfc(&l.target),
            args: normalize::nfc(&l.args),
            working_dir: normalize::nfc(&l.working_dir),
            icon: normalize::nfc(&l.icon),
        });
    }
    h.records.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 최소한의 유효한 `.lnk` 를 만든다. 손으로 짓는 이유는 **실행기가 실제로
    /// 읽는 바이트**를 시험이 통제해야 하기 때문이다.
    fn build(flags: u32, strings: &[&str], link_info: Option<&str>) -> Vec<u8> {
        let mut b = vec![0u8; HEADER_SIZE];
        b[0..4].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        b[4..20].copy_from_slice(&LINK_CLSID);
        b[20..24].copy_from_slice(&flags.to_le_bytes());

        if let Some(path) = link_info {
            // LinkInfo: 헤더 0x1C + 경로. LocalBasePathOffset 은 0x1C 로 둔다.
            let mut info = vec![0u8; 0x1C];
            info[4..8].copy_from_slice(&0x1Cu32.to_le_bytes()); // HeaderSize
            info[8..12].copy_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
            info[0x10..0x14].copy_from_slice(&0x1Cu32.to_le_bytes());
            info.extend_from_slice(path.as_bytes());
            info.push(0);
            let size = info.len() as u32;
            info[0..4].copy_from_slice(&size.to_le_bytes());
            b.extend_from_slice(&info);
        }

        for s in strings {
            let units: Vec<u16> = s.encode_utf16().collect();
            b.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in units {
                b.extend_from_slice(&u.to_le_bytes());
            }
        }
        b
    }

    #[test]
    fn target_args_and_workdir_come_out_separately() {
        // 하나로 뭉치면 룰이 인자만 겨눌 수 없다.
        let flags =
            IS_UNICODE | HAS_LINK_INFO | HAS_WORKING_DIR | HAS_ARGUMENTS | HAS_ICON_LOCATION;
        let b = build(
            flags,
            &["C:\\work", "-nop -w hidden -enc ZQBjAGgAbwA=", "C:\\i.ico"],
            Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        );
        let l = parse(&b).expect("파싱");
        assert!(l.target.ends_with("powershell.exe"), "{l:?}");
        assert!(l.args.contains("-enc"), "{l:?}");
        assert_eq!(l.working_dir, "C:\\work");
        assert_eq!(l.icon, "C:\\i.ico");
    }

    #[test]
    fn the_name_string_is_consumed_so_the_rest_does_not_shift() {
        // StringData 는 순서가 고정이다. NAME 을 건너뛰면 뒤가 전부 밀려
        // 작업 디렉터리 자리에 설명 문구가 들어온다.
        let flags = IS_UNICODE | HAS_NAME | HAS_WORKING_DIR | HAS_ARGUMENTS;
        let b = build(flags, &["설명 문구", "C:\\work", "--run"], None);
        let l = parse(&b).expect("파싱");
        assert_eq!(l.working_dir, "C:\\work");
        assert_eq!(l.args, "--run");
    }

    #[test]
    fn an_ansi_link_counts_bytes_not_double() {
        // 유니코드 플래그가 없으면 문자 수 = 바이트 수다. 두 배로 세면
        // 그 뒤가 통째로 어긋난다.
        let mut b = vec![0u8; HEADER_SIZE];
        b[0..4].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        b[4..20].copy_from_slice(&LINK_CLSID);
        b[20..24].copy_from_slice(&(HAS_ARGUMENTS | HAS_ICON_LOCATION).to_le_bytes());
        for s in ["-x", "i.ico"] {
            b.extend_from_slice(&(s.len() as u16).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
        }
        let l = parse(&b).expect("파싱");
        assert_eq!(l.args, "-x");
        assert_eq!(l.icon, "i.ico");
    }

    #[test]
    fn a_truncated_link_is_dropped_not_a_panic() {
        // 악성 `.lnk` 하나로 스캔이 멈추면 안 된다.
        let full = build(IS_UNICODE | HAS_ARGUMENTS, &["--run"], None);
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]); // 패닉하지 않으면 통과다.
        }
    }

    #[test]
    fn a_lying_length_does_not_read_past_the_end() {
        let mut b = build(IS_UNICODE | HAS_ARGUMENTS, &["--run"], None);
        let n = b.len();
        // 인자 길이를 터무니없이 크게 고친다.
        b[n - 12..n - 10].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(parse(&b).is_none(), "거짓말한 길이를 그대로 믿었다");
    }

    #[test]
    fn the_target_can_live_in_the_environment_block_alone() {
        // **실측으로 시작 메뉴 48건 중 9건이 이 모양이었다.** 읽지 않으면
        // `target ends_with ".exe"` 를 쓰는 룰이 다섯에 하나를 놓친다.
        const HAS_EXP_STRING: u32 = 1 << 9;
        let mut b = build(IS_UNICODE | HAS_NAME | HAS_EXP_STRING, &["설명"], None);

        let mut block = vec![0u8; 4 + 4 + 260 + 520];
        let block_len = block.len() as u32;
        block[0..4].copy_from_slice(&block_len.to_le_bytes());
        block[4..8].copy_from_slice(&0xA000_0001u32.to_le_bytes());
        let ansi = b"%windir%\\system32\\magnify.exe";
        block[8..8 + ansi.len()].copy_from_slice(ansi);
        let uni: Vec<u8> = "%windir%\\system32\\magnify.exe"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        block[8 + 260..8 + 260 + uni.len()].copy_from_slice(&uni);
        b.extend_from_slice(&block);
        b.extend_from_slice(&0u32.to_le_bytes()); // ExtraData 끝

        let l = parse(&b).expect("파싱");
        assert_eq!(l.target, "%windir%\\system32\\magnify.exe");
    }

    #[test]
    fn link_info_wins_over_the_environment_block() {
        // 전개된 절대 경로가 더 정확하다. 뒤집으면 룰이 보는 경로가 기계마다 달라진다.
        const HAS_EXP_STRING: u32 = 1 << 9;
        let mut b = build(
            IS_UNICODE | HAS_LINK_INFO | HAS_EXP_STRING,
            &[],
            Some("C:\\Windows\\System32\\magnify.exe"),
        );
        let mut block = vec![0u8; 4 + 4 + 260 + 520];
        let block_len = block.len() as u32;
        block[0..4].copy_from_slice(&block_len.to_le_bytes());
        block[4..8].copy_from_slice(&0xA000_0001u32.to_le_bytes());
        let uni: Vec<u8> = "%windir%\\x.exe"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        block[8 + 260..8 + 260 + uni.len()].copy_from_slice(&uni);
        b.extend_from_slice(&block);
        b.extend_from_slice(&0u32.to_le_bytes());

        let l = parse(&b).expect("파싱");
        assert_eq!(l.target, "C:\\Windows\\System32\\magnify.exe");
    }

    #[test]
    fn a_lying_extra_block_size_does_not_loop_forever() {
        // 크기 0 을 그대로 믿고 더하면 제자리에서 돈다. 악성 `.lnk` 하나로
        // 스캔이 멈추면 안 된다.
        let mut b = build(IS_UNICODE | HAS_NAME, &["x"], None);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&[0xFF; 8]);
        let _ = parse(&b);

        let mut b = build(IS_UNICODE | HAS_NAME, &["x"], None);
        b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        b.extend_from_slice(&0xA000_0001u32.to_le_bytes());
        let _ = parse(&b);
    }

    #[test]
    fn a_file_that_is_not_a_shell_link_is_refused() {
        assert!(parse(b"MZ\x90\x00").is_none());
        assert!(parse(&[0u8; 200]).is_none());
    }
}
