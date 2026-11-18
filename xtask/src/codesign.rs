//! 코드서명(Authenticode)한 실행 파일이 **지은 그 실행 파일에 서명만 더한 것인가**를 바이트로 잰다.
//!
//! # 왜 재는가
//!
//! Windows 실행 파일의 코드서명은 배포 잡 밖 — 서명 도구가 있는 기계 — 에서 한다(`.github/workflows/release.yml`
//! 첫머리 · `docs/개발-안내.md` "출시 검증"). 잡은 지은 실행 파일을 초안에 넘기고, 서명된 것을 받아 꾸러미에 넣는다.
//! 그 사이에 다른 파일(낡은 빌드 · 다른 커밋의 빌드)이 끼어도 `Get-AuthenticodeSignature` 는 `Valid` 를 낸다 — 서명은
//! 그 파일이 **누구의 것인지** 말할 뿐 **무엇을 지었는지** 말하지 않는다. 그래서 받은 서명본을 그 잡이 지은 파일과
//! 바이트로 견준다.
//!
//! # 무엇을 같다고 보는가
//!
//! 서명 도구(signtool)는 서명이 없는 PE 의 세 곳만 바꾼다(2026-11-18 실측 — 1.23.0 의 `remedy.exe` 를 서명해 견줌):
//!
//! - 선택 헤더의 `CheckSum`(4바이트) — 서명한 뒤 다시 계산한다
//! - 데이터 디렉터리의 보안 칸(`IMAGE_DIRECTORY_ENTRY_SECURITY` · 8바이트) — 붙인 인증서 표의 자리와 크기
//! - 파일 끝에 붙인 인증서 표(`WIN_CERTIFICATE` — 개정 0x0200 · 종류 PKCS#7 SignedData)
//!
//! 그래서 서명본의 앞부분(서명 전 길이만큼)이 그 열두 바이트를 빼고 서명 전 파일과 같고, 보안 칸이 정확히 그 끝을
//! 가리키며, 그 뒤가 인증서 표뿐이면 **서명만 더한 것**이다. 서명 전 파일의 길이가 8의 배수가 아니면 서명 도구가 0 을
//! 덧대 앞부분이 달라진다 — 그때는 같다고 보지 않고 멈춘다(링커가 낸 파일은 512 단위라 그럴 일이 없다).
//!
//! 서명이 **유효한지**(체인 · 타임스탬프 · 서명 주체)는 여기서 보지 않는다 — OS 가 본다(배포 잡의 서명 확인 단계 ·
//! 본체의 자기무결성). 체인 검증을 직접 짜지 않는 까닭은 `remedy-wintrust` 첫머리에 있다.

use std::ops::Range;
use std::path::Path;

/// 데이터 디렉터리에서 보안 칸(인증서 표)의 번호.
const SECURITY_DIR: usize = 4;
/// `WIN_CERTIFICATE` 의 개정 2.0.
const WIN_CERT_REVISION_2_0: u16 = 0x0200;
/// `WIN_CERT_TYPE_PKCS_SIGNED_DATA` — Authenticode 서명.
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// 서명이 바꾸는 두 칸의 자리와 인증서 표가 가리키는 곳.
#[derive(Debug, PartialEq, Eq)]
struct Layout {
    /// 선택 헤더의 `CheckSum` — 4바이트.
    checksum: usize,
    /// 보안 칸 — 8바이트(파일 오프셋 · 크기).
    security: usize,
    cert_offset: usize,
    cert_size: usize,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn layout(b: &[u8]) -> Result<Layout, String> {
    let cut = || "헤더가 잘렸다".to_string();
    if b.get(..2) != Some(b"MZ".as_slice()) {
        return Err("MZ 머리가 없다 — PE 실행 파일이 아니다".into());
    }
    let pe = u32_at(b, 0x3c).ok_or_else(cut)? as usize;
    if b.get(pe..pe.saturating_add(4)) != Some(b"PE\0\0".as_slice()) {
        return Err("PE 서명이 없다 — PE 실행 파일이 아니다".into());
    }
    // 선택 헤더는 PE 서명(4) · COFF 헤더(20) 다음이다. 데이터 디렉터리의 시작은 꼴(PE32 · PE32+)마다 다르다.
    let opt = pe + 4 + 20;
    let dirs = match u16_at(b, opt).ok_or_else(cut)? {
        0x20b => opt + 112,
        0x10b => opt + 96,
        m => return Err(format!("모르는 선택 헤더 꼴 {m:#06x}")),
    };
    let count = u32_at(b, dirs - 4).ok_or_else(cut)? as usize;
    if count <= SECURITY_DIR {
        return Err(format!("데이터 디렉터리가 {count}칸이라 보안 칸이 없다"));
    }
    let security = dirs + SECURITY_DIR * 8;
    let cert_offset = u32_at(b, security).ok_or_else(cut)? as usize;
    let cert_size = u32_at(b, security + 4).ok_or_else(cut)? as usize;
    Ok(Layout {
        checksum: opt + 64,
        security,
        cert_offset,
        cert_size,
    })
}

/// 서명본 `signed` 가 서명 전 `unsigned` 에 서명만 더한 것이면 붙은 인증서 표의 크기를 돌려준다.
fn compare(unsigned: &[u8], signed: &[u8]) -> Result<usize, String> {
    let u = layout(unsigned).map_err(|e| format!("서명 전 파일: {e}"))?;
    let s = layout(signed).map_err(|e| format!("서명본: {e}"))?;
    if u.cert_offset != 0 || u.cert_size != 0 {
        return Err(
            "서명 전 파일에 이미 인증서 표가 있다 — 잡이 지은 서명 전 파일이 아니다".into(),
        );
    }
    let end = unsigned.len();
    if !end.is_multiple_of(8) {
        return Err(format!(
            "서명 전 파일의 길이 {end} 가 8의 배수가 아니다 — 서명 도구가 0 을 덧대 앞부분이 달라지므로 이 비교로 \
             잴 수 없다"
        ));
    }
    if (u.checksum, u.security) != (s.checksum, s.security) {
        return Err("두 파일의 헤더 자리가 다르다 — 같은 실행 파일이 아니다".into());
    }
    if s.cert_offset != end {
        return Err(format!(
            "서명본의 인증서 표가 {} 에서 시작한다 — 서명 전 파일의 끝({end})이어야 한다",
            s.cert_offset
        ));
    }
    if signed.len() <= end || s.cert_size != signed.len() - end {
        return Err(format!(
            "서명본의 인증서 표 크기 {} 가 덧붙은 길이 {} 와 다르다 — 인증서 표 뒤에 다른 것이 있다",
            s.cert_size,
            signed.len().saturating_sub(end)
        ));
    }
    let length = u32_at(signed, end).ok_or("인증서 표의 머리가 잘렸다")? as usize;
    let revision = u16_at(signed, end + 4).ok_or("인증서 표의 머리가 잘렸다")?;
    let kind = u16_at(signed, end + 6).ok_or("인증서 표의 머리가 잘렸다")?;
    if length < 8 || length > s.cert_size {
        return Err(format!(
            "인증서 표의 길이 {length} 가 보안 칸의 크기 {} 와 맞지 않는다",
            s.cert_size
        ));
    }
    if revision != WIN_CERT_REVISION_2_0 || kind != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
        return Err(format!(
            "인증서 표가 Authenticode 서명이 아니다(개정 {revision:#06x} · 종류 {kind:#06x})"
        ));
    }
    // 서명이 바꾸는 두 칸을 뺀 나머지 — 체크섬이 보안 칸보다 앞이다(두 꼴 모두).
    let same: [Range<usize>; 3] = [
        0..u.checksum,
        u.checksum + 4..u.security,
        u.security + 8..end,
    ];
    for r in same {
        if unsigned[r.clone()] != signed[r.clone()] {
            let at = r.start
                + unsigned[r.clone()]
                    .iter()
                    .zip(&signed[r])
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
            return Err(format!(
                "{at} 바이트째가 다르다 — 서명 말고도 바뀐 것이 있다(같은 빌드가 아니다)"
            ));
        }
    }
    Ok(s.cert_size)
}

pub fn run(args: &[String]) -> Result<(), String> {
    let [unsigned, signed] = args else {
        return Err(
            "쓰는 법: cargo xtask codesign <서명 전 실행 파일> <서명본>\n\
             예: cargo xtask codesign handover/unsigned-remedy.exe handover/signed-remedy.exe"
                .to_string(),
        );
    };
    let read = |p: &str| std::fs::read(Path::new(p)).map_err(|e| format!("{p}: {e}"));
    let size = compare(&read(unsigned)?, &read(signed)?).map_err(|e| format!("{signed}: {e}"))?;
    println!(
        "codesign OK — {signed} 는 {unsigned} 에 Authenticode 서명({size} 바이트)만 더한 것이다"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PE: usize = 0x80;
    const OPT: usize = PE + 24;

    /// 서명이 없는 PE32+ 의 꼴만 갖춘 파일 — 길이 1024(8의 배수) · 데이터 디렉터리 16칸.
    fn unsigned() -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&(PE as u32).to_le_bytes());
        b[PE..PE + 4].copy_from_slice(b"PE\0\0");
        b[OPT..OPT + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[OPT + 108..OPT + 112].copy_from_slice(&16u32.to_le_bytes());
        for (i, x) in b.iter_mut().enumerate().skip(OPT + 240) {
            *x = (i % 251) as u8;
        }
        b
    }

    /// signtool 이 하는 대로 — 체크섬을 바꾸고, 보안 칸에 자리와 크기를 적고, 인증서 표를 끝에 붙인다.
    fn sign(u: &[u8], revision: u16, kind: u16) -> Vec<u8> {
        let mut s = u.to_vec();
        let end = s.len() as u32;
        let table = 32u32;
        s[OPT + 64..OPT + 68].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let sec = OPT + 112 + SECURITY_DIR * 8;
        s[sec..sec + 4].copy_from_slice(&end.to_le_bytes());
        s[sec + 4..sec + 8].copy_from_slice(&table.to_le_bytes());
        s.extend_from_slice(&table.to_le_bytes());
        s.extend_from_slice(&revision.to_le_bytes());
        s.extend_from_slice(&kind.to_le_bytes());
        s.extend_from_slice(&[0xAB; 24]);
        s
    }

    fn signed(u: &[u8]) -> Vec<u8> {
        sign(u, WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA)
    }

    #[test]
    fn 서명만_더한_것은_같다고_본다() {
        let u = unsigned();
        assert_eq!(compare(&u, &signed(&u)), Ok(32));
    }

    #[test]
    fn 본문의_한_바이트가_다르면_멈춘다() {
        let u = unsigned();
        let mut s = signed(&u);
        s[700] ^= 1;
        let e = compare(&u, &s).unwrap_err();
        assert!(e.contains("700 바이트째"), "{e}");
    }

    #[test]
    fn 헤더의_다른_칸이_다르면_멈춘다() {
        // 체크섬 바로 뒤 칸 — 가리는 열두 바이트 밖이다.
        let u = unsigned();
        let mut s = signed(&u);
        s[OPT + 68] ^= 1;
        assert!(compare(&u, &s).is_err());
    }

    #[test]
    fn 다른_빌드를_서명한_것은_멈춘다() {
        let u = unsigned();
        let mut other = unsigned();
        other[900] ^= 0xFF;
        assert!(compare(&u, &signed(&other)).is_err());
    }

    #[test]
    fn 서명_전_파일이_이미_서명돼_있으면_멈춘다() {
        let u = unsigned();
        let s = signed(&u);
        let e = compare(&s, &signed(&s)).unwrap_err();
        assert!(e.contains("이미 인증서 표"), "{e}");
    }

    #[test]
    fn 길이가_8의_배수가_아니면_멈춘다() {
        let mut u = unsigned();
        u.truncate(1021);
        let e = compare(&u, &signed(&u)).unwrap_err();
        assert!(e.contains("8의 배수"), "{e}");
    }

    #[test]
    fn 인증서_표_뒤에_무엇이_더_있으면_멈춘다() {
        let u = unsigned();
        let mut s = signed(&u);
        s.extend_from_slice(&[0; 8]);
        assert!(compare(&u, &s).is_err());
    }

    #[test]
    fn 인증서_표가_끝에서_시작하지_않으면_멈춘다() {
        let u = unsigned();
        let mut s = signed(&u);
        let sec = OPT + 112 + SECURITY_DIR * 8;
        s[sec..sec + 4].copy_from_slice(&1016u32.to_le_bytes());
        let e = compare(&u, &s).unwrap_err();
        assert!(e.contains("1016 에서 시작"), "{e}");
    }

    #[test]
    fn authenticode_가_아닌_인증서_표는_멈춘다() {
        let u = unsigned();
        let e = compare(&u, &sign(&u, WIN_CERT_REVISION_2_0, 0x0001)).unwrap_err();
        assert!(e.contains("Authenticode 서명이 아니다"), "{e}");
    }

    #[test]
    fn pe_가_아니면_멈춘다() {
        let e = compare(b"not a pe at all", b"not a pe").unwrap_err();
        assert!(e.contains("PE 실행 파일이 아니다"), "{e}");
        let mut u = unsigned();
        u[PE] = b'X';
        assert!(compare(&u, &signed(&unsigned())).is_err());
    }
}
