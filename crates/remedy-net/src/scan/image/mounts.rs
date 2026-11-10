//! Linux 의 마운트 — 입력 경로가 로컬 파일 시스템 위에 있는가. 사내 runtime-scanner 의
//! `internal/storage/mounts.go` 와 `preflightPath` 를 옮겼다.
//!
//! 마운트 정보를 먼저 보고 경로는 그 뒤에 만진다 — 원격 · 자동 마운트의 경로는 `lstat` 만으로도 네트워크를 탈 수
//! 있다. 모르는 파일 시스템은 받지 않는다(FUSE · autofs 는 일부러 목록에 없다). 같은 길이로 가장 잘 맞는 마운트가
//! 여럿이고 그 가운데 하나라도 로컬이 아니면 받지 않는다.

use remedy_sdk::i18n::Lang;
use std::io::Read;

const SNAPSHOT_LIMIT: u64 = 4 << 20;

type Res<T> = Result<T, String>;

pub(super) struct Mount {
    name: String,
    local: bool,
}

/// 이 프로세스의 마운트 목록.
pub(super) fn read(lang: Lang) -> Res<Vec<Mount>> {
    let failed = || {
        lang.t(
            "로컬 마운트 목록을 확인하지 못했습니다",
            "could not read the local mount list",
        )
        .to_string()
    };
    let mut data = Vec::new();
    std::fs::File::open("/proc/self/mountinfo")
        .and_then(|f| f.take(SNAPSHOT_LIMIT + 1).read_to_end(&mut data))
        .map_err(|_| failed())?;
    parse(&data).ok_or_else(failed)
}

/// `mountinfo` 의 줄들 — 꼴이 하나라도 어긋나면 `None`.
fn parse(data: &[u8]) -> Option<Vec<Mount>> {
    if data.is_empty() || data.len() as u64 > SNAPSHOT_LIMIT || data.last() != Some(&b'\n') {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();
    for line in text.trim_end_matches('\n').split('\n') {
        let (left, right) = line.split_once(" - ")?;
        let before: Vec<&str> = left.split_whitespace().collect();
        let after: Vec<&str> = right.split_whitespace().collect();
        if before.len() < 6 || after.len() != 3 {
            return None;
        }
        let name = decode_name(before[4])?;
        if !name.starts_with('/') || crate::scan::slashpath::clean(&name) != name {
            return None;
        }
        out.push(Mount {
            name,
            local: local_kind(after[0]),
        });
    }
    Some(out)
}

/// 경로가 놓인 마운트가 로컬인가.
pub(super) fn check(name: &str, mounts: &[Mount], lang: Lang) -> Res<()> {
    let mut best: Option<usize> = None;
    let mut local = false;
    for m in mounts {
        let covers = m.name == "/" || name == m.name || name.starts_with(&format!("{}/", m.name));
        if !covers {
            continue;
        }
        match best {
            Some(len) if m.name.len() < len => {}
            Some(len) if m.name.len() == len => local &= m.local,
            _ => {
                best = Some(m.name.len());
                local = m.local;
            }
        }
    }
    match best {
        None => Err(lang
            .t(
                "입력 경로의 마운트를 확인하지 못했습니다",
                "could not find the mount of the input path",
            )
            .to_string()),
        Some(_) if !local => Err(lang
            .t(
                "네트워크 · 자동 마운트나 로컬인지 확인되지 않은 파일 시스템의 경로는 받지 않습니다",
                "paths on network, automount or unconfirmed file systems are not accepted",
            )
            .to_string()),
        Some(_) => Ok(()),
    }
}

/// 로컬 파일 시스템 — Go 와 같은 목록. 모르는 종류는 받지 않는다.
fn local_kind(kind: &str) -> bool {
    matches!(
        kind,
        "ext2"
            | "ext3"
            | "ext4"
            | "xfs"
            | "btrfs"
            | "bcachefs"
            | "f2fs"
            | "jfs"
            | "reiserfs"
            | "reiser4"
            | "nilfs2"
            | "ufs"
            | "vfat"
            | "msdos"
            | "exfat"
            | "ntfs"
            | "ntfs3"
            | "hfs"
            | "hfsplus"
            | "iso9660"
            | "udf"
            | "squashfs"
            | "erofs"
            | "ramfs"
            | "tmpfs"
            | "hugetlbfs"
            | "proc"
            | "sysfs"
            | "devtmpfs"
            | "devpts"
            | "overlay"
            | "rootfs"
            | "zfs"
    )
}

/// `\040` · `\011` · `\012` · `\134` 만 푼다 — 그 밖의 이스케이프는 꼴이 틀린 것이다.
fn decode_name(name: &str) -> Option<String> {
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let code = b.get(i + 1..i + 4)?;
        out.push(match code {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return None,
        });
        i += 4;
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_longest_mount_decides_and_a_remote_twin_wins() {
        let info = b"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
                     2 1 0:5 / /mnt/share rw - nfs4 server:/x rw\n\
                     3 1 0:6 / /mnt/my\\040disk rw - xfs /dev/sdb rw\n";
        let mounts = parse(info).unwrap();
        assert!(check("/home/a", &mounts, Lang::Ko).is_ok());
        assert!(check("/mnt/share/a", &mounts, Lang::Ko).is_err());
        assert!(check("/mnt/my disk/a", &mounts, Lang::Ko).is_ok());
        let twin = b"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 0 0:5 / / rw - cifs //s/x rw\n";
        assert!(check("/x", &parse(twin).unwrap(), Lang::Ko).is_err());
        assert!(parse(b"1 0 8:1 / / rw - ext4\n").is_none());
        assert!(parse(b"1 0 8:1 / /\\999 rw - ext4 a b\n").is_none());
    }
}
