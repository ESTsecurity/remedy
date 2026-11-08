//! 이름 있는 UNIX 소켓 (Linux · `/proc/net/unix` · 코어 1.2.0).
//!
//! # 왜 여기서 보는가
//!
//! Ebury 의 현재 주 탐지법이 **추상 소켓 이름**이다 — ESET 의 공개 점검 스크립트
//! (`eset/malware-research` 의 `ebury/detect_ebury.sh`)가 이름 24개를 판(1.5 ~ 1.8.3)과
//! 함께 적는다(목록은 25줄 — 한 이름이 두 판에 겹친다). 그 이름은 `/run/systemd/log` · `/proc/udevd` 처럼 **정상 경로를
//! 흉내 내지만 파일이 아니라 추상 소켓**이다(앞에 NUL). 커널은 그 NUL 을 `@` 로
//! 적어 보여 주므로, 같은 글자의 파일 소켓과 `@` 하나로 갈린다.
//!
//! # 루트킷에 속지 않는 까닭
//!
//! ESET 스크립트는 이 표에서 소켓을 찾지 못하면 *"사용자 영역 루트킷이 켜져
//! 있는가"* 를 묻고 `LD_PRELOAD` 를 비워 다시 돈다 — Ebury 의 루트킷이 `libc` 를
//! 가로채 동적 링크된 도구의 눈에서 그 줄을 지운다. 배포 엔진은 **정적
//! 바이너리**라 그 가로채기를 지나지 않는다(설계-09 · `remedy_신규위협` 기준 11 —
//! `LD_PRELOAD` 를 건 채 정적 엔진이 감염을 2 로 냈다).
//!
//! # 담는 것과 안 담는 것
//!
//! **이름 있는 소켓만** 담는다. 이름 없는 소켓(짝을 이룬 소켓 · 이름 없이 연결된
//! 쪽)은 바쁜 서버에 수천 개이고, 룰이 겨눌 이름이 없다.
//!
//! 이 표는 **이 엔진의 네트워크 이름 공간**의 것이다 — 컨테이너 안에서 돌면 그
//! 컨테이너의 소켓만 보인다.

use remedy_artifacts::{CollectError, Harvest, Scope, UnixSocketRecord};
use remedy_platform::read::FsRead;
use remedy_sdk::catalog::Platform;
use remedy_sdk::normalize;

/// 커널이 정한 자리 하나다.
const PROC_NET_UNIX: &str = "/proc/net/unix";

/// 읽는 상한. 한 줄이 100 바이트 안팎이라 16 MiB 는 소켓 15만 개를 담는다.
/// `/proc` 파일은 크기를 0 으로 보고하므로 이 상한은 읽기 함수의 크기 검사를
/// 지나 버린다 — 그래서 아래에서 길이를 다시 본다.
const MAX_BYTES: u64 = 16 * 1024 * 1024;

/// `Flags` 열의 `__SO_ACCEPTCON` — 연결을 받으려고 듣고 있다.
const SO_ACCEPTCON: u32 = 0x0001_0000;

/// 이름 있는 UNIX 소켓.
///
/// **Linux 뿐이다.** 카탈로그가 `windows: false` 로 적어 두어 Windows 범위에서는
/// 이 subject 가 빠진다. 그래도 플랫폼을 보는 이유는 스냅샷이 다른 기계의 것일
/// 수 있어서다(`package` 와 같다).
pub fn unix_sockets<P: FsRead>(
    fs: &P,
    scope: &Scope,
) -> Result<Harvest<UnixSocketRecord>, CollectError> {
    let mut h = Harvest::default();
    if scope.platform != Platform::Linux {
        return Ok(h);
    }
    match fs.read_file(PROC_NET_UNIX, MAX_BYTES) {
        Ok(Some(bytes)) if bytes.len() as u64 <= MAX_BYTES => {
            h.records = parse(&String::from_utf8_lossy(&bytes));
        }
        // 상한을 넘었다. 한 건도 담지 못했으므로 **잘렸다고 말한다** — 조용히
        // 넘기면 그 기계는 "소켓이 없다" 가 된다.
        Ok(_) => h.truncated = true,
        // `/proc` 이 없거나 열리지 않았다. 없는 것이 아니라 못 본 것이다.
        Err(_) => h.deny(PROC_NET_UNIX),
    }
    h.records
        .sort_by(|a, b| (a.name.as_str(), a.inode).cmp(&(b.name.as_str(), b.inode)));
    h.records.dedup();
    Ok(h)
}

/// `/proc/net/unix` 본문을 레코드로. 첫 줄은 머리다.
///
/// ```text
/// Num       RefCount Protocol Flags    Type St Inode Path
/// ffff8880: 00000002 00000000 00010000 0001 01 23456 /run/systemd/journal/stdout
/// ffff8881: 00000002 00000000 00010000 0001 01 34567 @/run/systemd/log
/// ffff8882: 00000003 00000000 00000000 0001 03 34568
/// ```
///
/// 앞의 일곱 열 뒤가 이름이다. 이름 안의 공백은 그대로 둔다 — 추상 이름은 아무
/// 바이트나 될 수 있다. 모양이 어긋난 줄은 **그 줄만** 버린다.
pub fn parse(text: &str) -> Vec<UnixSocketRecord> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let (cols, name) = split_columns(line, 7)?;
            let name = name.trim_end();
            if name.is_empty() {
                return None;
            }
            let flags = u32::from_str_radix(cols[3], 16).ok()?;
            let inode = cols[6].parse::<u64>().ok()?;
            Some(UnixSocketRecord {
                name: normalize::nfc(name),
                inode,
                listening: flags & SO_ACCEPTCON != 0,
                kind: kind_of(cols[4]),
            })
        })
        .collect()
}

fn kind_of(ty: &str) -> String {
    match u32::from_str_radix(ty, 16) {
        Ok(1) => "stream".into(),
        Ok(2) => "dgram".into(),
        Ok(5) => "seqpacket".into(),
        _ => format!("type-{ty}"),
    }
}

/// 앞의 `n` 열과 그 뒤 나머지(앞 공백을 뗀 것). 열이 모자라면 `None`.
fn split_columns(line: &str, n: usize) -> Option<(Vec<&str>, &str)> {
    let mut cols = Vec::with_capacity(n);
    let mut rest = line;
    for _ in 0..n {
        let t = rest.trim_start();
        let end = t.find(char::is_whitespace).unwrap_or(t.len());
        if end == 0 {
            return None;
        }
        cols.push(&t[..end]);
        rest = &t[end..];
    }
    Some((cols, rest.trim_start()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Num       RefCount Protocol Flags    Type St Inode Path
ffff9b3e4a1b4000: 00000002 00000000 00010000 0001 01 23456 /run/systemd/journal/stdout
ffff9b3e4a1b4400: 00000003 00000000 00000000 0001 03 23457
ffff9b3e4a1b4800: 00000002 00000000 00010000 0001 01 34567 @/run/systemd/log
ffff9b3e4a1b4c00: 00000002 00000000 00000000 0002 01 34568 @event-0YsOG9WSOE
ffff9b3e4a1b5000: 00000002 00000000 00010000 0005 01 34569 @name with space
not a socket line
";

    /// 추상 이름은 `@` 로 시작하고 같은 글자의 파일 경로와 갈린다. 이름 없는 소켓과
    /// 모양이 어긋난 줄은 담지 않는다.
    #[test]
    fn named_sockets_are_kept_with_abstract_names_marked() {
        let r = parse(SAMPLE);
        let names: Vec<&str> = r.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "/run/systemd/journal/stdout",
                "@/run/systemd/log",
                "@event-0YsOG9WSOE",
                "@name with space",
            ]
        );
        assert_eq!(r[1].inode, 34567);
        assert!(r[1].listening);
        assert!(!r[2].listening, "Flags 0 은 듣지 않는다");
        assert_eq!(
            r.iter().map(|x| x.kind.as_str()).collect::<Vec<_>>(),
            vec!["stream", "stream", "dgram", "seqpacket"]
        );
    }

    #[test]
    fn an_unknown_type_is_kept_as_written() {
        let r = parse("h\nffff: 00000002 00000000 00000000 0009 01 7 @x\n");
        assert_eq!(r[0].kind, "type-0009");
    }
}
