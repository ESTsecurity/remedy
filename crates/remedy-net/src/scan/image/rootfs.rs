//! 최종 파일 구성 — 레이어를 차례로 덮어 만든 가상 뿌리. 스캐너의 `rootfs.go` 와 `packages.go` 의 `resolve` 를
//! 옮겼다.
//!
//! 이 기계에는 아무것도 풀지 않는다. 항목마다 종류 · 링크 대상 · 크기 · 권한과, 판정에 쓰는 파일만 앞부분을 담는다
//! (배포판 기록 · 패키지 DB · 실행 파일 · PHP 설정). 링크는 가상 뿌리 안에서만 따라간다 — 절대 경로 링크도 이
//! 기계가 아니라 이미지의 뿌리를 가리킨다.
//!
//! 장치(문자 · 블록)와 FIFO 는 내용 없는 항목으로 둔다(2026-11-11). 다른 항목처럼 아래 레이어의 같은 경로를 덮고
//! 화이트아웃으로 지워지지만, 실행 파일 · 설정 · 패키지 DB 의 후보가 되지 않는다 — 이미지에 내용이 없고 일반
//! 파일이 아니다.

use super::config::selected_config;
use super::php::is_php_runtime;
use super::tarball::{
    TYPE_BLOCK, TYPE_CHAR, TYPE_DIR, TYPE_FIFO, TYPE_LINK, TYPE_REG, TYPE_SYMLINK,
};
use crate::scan::binary::{binary_magic, is_brotli_decoder, is_node_runtime};
use crate::scan::linuxmeta::RELEASE_FILES;
use crate::scan::model::Product;
use crate::scan::slashpath;
use remedy_sdk::i18n::Lang;
use std::collections::{BTreeMap, BTreeSet};

/// 판정에 쓰려고 담는 데이터의 합계(PHP 설정은 따로 센다).
pub(super) const SELECTED_DATA_LIMIT: i64 = 128 << 20;
/// 가상 링크를 따라가는 깊이.
const RESOLVE_DEPTH: usize = 64;

/// 항목 하나.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Entry {
    /// tar 의 종류 글자(`0` · `1` · `2` · `5`, 내용 없는 `3` · `4` · `6`).
    pub(super) kind: u8,
    /// 링크면 가상 뿌리 안의 대상.
    pub(super) link: String,
    /// 담은 앞부분.
    pub(super) data: Vec<u8>,
    pub(super) size: i64,
    pub(super) mode: i64,
    /// 담을 자리였는데 다 담지 못했다.
    pub(super) truncated: bool,
    /// 고른 제품의 실행 파일이면 파일 전체의 SHA-256 과 MD5(16진수).
    pub(super) sha256: String,
    pub(super) md5: String,
}

/// 가상 뿌리.
#[derive(Debug, Default)]
pub(super) struct RootFs {
    /// Windows 이미지 — 이름의 대소문자를 가리지 않는다.
    pub(super) case_insensitive: bool,
    /// 설정의 환경 변수가 동적 로더를 바꾼다(`LD_LIBRARY_PATH` · `LD_PRELOAD` · `LD_AUDIT`).
    pub(super) loader_override: bool,
    /// 이름 차례(바이트 순서)로 선다 — 스캐너가 이름을 정렬해 도는 것과 같다.
    pub(super) entries: BTreeMap<String, Entry>,
    /// 담은 데이터의 합계(PHP 설정 제외).
    pub(super) captured: i64,
    /// 이미지 설정이 알려 준 PHP 설정 파일(`PHPRC` · `PHP_INI_DIR`).
    pub(super) config_paths: BTreeSet<String>,
    pub(super) config_bytes: i64,
    pub(super) config_files: usize,
    pub(super) config_limited: bool,
}

impl Entry {
    /// 내용 없는 장치 · FIFO 인가.
    pub(super) fn special(&self) -> bool {
        matches!(self.kind, TYPE_CHAR | TYPE_BLOCK | TYPE_FIFO)
    }
}

/// 가상 경로를 풀지 못한 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unresolved {
    HardLink,
    NotDirectory,
    Missing,
    Loop,
}

impl Unresolved {
    pub(super) fn message(self, lang: Lang) -> &'static str {
        match self {
            Unresolved::HardLink => lang.t(
                "하드 링크로 연결된 파일은 대상 파일과의 연결 관계를 더 확인해야 합니다",
                "a hard-linked file needs its link to the target confirmed",
            ),
            Unresolved::NotDirectory => lang.t(
                "가상 경로의 상위 항목이 폴더가 아닙니다",
                "a parent in the virtual path is not a folder",
            ),
            Unresolved::Missing => lang.t(
                "최종 이미지에 링크 대상 파일이 없습니다",
                "the link target is not in the final image",
            ),
            Unresolved::Loop => lang.t(
                "가상 링크 깊이 제한을 넘었거나 순환합니다",
                "the virtual link chain is too deep or loops",
            ),
        }
    }
}

impl RootFs {
    /// 찾는 키 — Windows 이미지는 소문자.
    pub(super) fn key(&self, name: &str) -> String {
        if self.case_insensitive {
            super::names::lower(name)
        } else {
            name.to_string()
        }
    }

    /// 가상 링크를 따라간 실제 경로와 항목. 하드 링크는 따라가지 않는다(대상과의 관계를 따로 확인해야 한다).
    pub(super) fn resolve(&self, name: &str) -> Result<(String, &Entry), (String, Unresolved)> {
        let mut name = self.key(name);
        for _ in 0..RESOLVE_DEPTH {
            match self.step(&name) {
                Step::Follow(next) => name = next,
                Step::Stay => {
                    return match self.entries.get(&name) {
                        Some(e) => Ok((name, e)),
                        None => Err((name, Unresolved::Missing)),
                    }
                }
                Step::Fail(why) => return Err((String::new(), why)),
            }
        }
        Err((String::new(), Unresolved::Loop))
    }

    /// 그 이름이, 또는 링크를 푼 대상이 내용 없는 장치 · FIFO 인가 — 실행 파일 · 설정 · 패키지 DB 의 후보에서 뺀다.
    pub(super) fn special(&self, name: &str) -> bool {
        self.entries
            .get(&self.key(name))
            .is_some_and(Entry::special)
            || self.resolve(name).is_ok_and(|(_, e)| e.special())
    }

    /// 앞머리부터 차례로 — 처음 만나는 심볼릭 링크를 풀어 다음 이름을 준다.
    fn step(&self, name: &str) -> Step {
        let parts: Vec<&str> = name.split('/').collect();
        for i in 0..parts.len() {
            let Some(e) = self.entries.get(&parts[..=i].join("/")) else {
                continue;
            };
            if e.kind == TYPE_LINK {
                return Step::Fail(Unresolved::HardLink);
            }
            if e.kind == TYPE_SYMLINK {
                return Step::Follow(if i + 1 < parts.len() {
                    slashpath::join(&[&e.link, &parts[i + 1..].join("/")])
                } else {
                    e.link.clone()
                });
            }
            if i + 1 < parts.len() && e.kind != TYPE_DIR {
                return Step::Fail(Unresolved::NotDirectory);
            }
        }
        Step::Stay
    }

    /// 실행 파일 이름을 가졌지만 문서 · 설정 자리의 평문인가 — 실행 파일 후보에서 뺀다. 링크를 푼 대상이 폴더이거나,
    /// 실행 권한 없는 · 다 담은 · `#!` 로 시작하지 않는 · NUL 없는 · UTF-8 인 · ELF · MZ 머리가 아닌 일반 파일이어야
    /// 한다.
    pub(super) fn runtime_data_file(&self, name: &str) -> bool {
        const KNOWN: [&str; 6] = [
            "usr/share/lintian/overrides/",
            "usr/share/doc/",
            "usr/share/man/",
            "etc/cron.d/",
            "var/lib/dpkg/alternatives/",
            "var/lib/apache2/module/enabled_by_admin/",
        ];
        if !KNOWN.iter().any(|prefix| name.starts_with(prefix)) {
            return false;
        }
        let Ok((_, e)) = self.resolve(name) else {
            return false;
        };
        if e.kind == TYPE_DIR {
            return true;
        }
        e.kind == TYPE_REG
            && e.mode & 0o111 == 0
            && !e.truncated
            && e.data.len() as i64 == e.size
            && !e.data.starts_with(b"#!")
            && !e.data.contains(&0)
            && std::str::from_utf8(&e.data).is_ok()
            && !binary_magic(&e.data)
    }
}

enum Step {
    Follow(String),
    Stay,
    Fail(Unresolved),
}

/// 고른 제품의 실행 파일 이름인가 — 해시를 내고 앞 8 MiB 를 담는다.
pub(super) fn is_selected_binary(name: &str, products: &[Product]) -> bool {
    products.iter().any(|p| match p {
        Product::Php => is_php_runtime(name),
        Product::Node => is_node_runtime(name) || is_brotli_decoder(name),
        Product::Brotli => false,
    })
}

/// 담을 앞부분의 크기(스캐너의 `captureLimit`). 0 이면 담지 않는다.
pub(super) fn capture_limit(name: &str, products: &[Product]) -> i64 {
    if RELEASE_FILES
        .iter()
        .any(|f| f.trim_start_matches('/') == name)
    {
        return 64 << 10;
    }
    match name {
        "etc/os-release" | "usr/lib/os-release" => return 64 << 10,
        "var/lib/dpkg/status" | "lib/apk/db/installed" => return 32 << 20,
        "var/lib/rpm/rpmdb.sqlite"
        | "usr/lib/sysimage/rpm/rpmdb.sqlite"
        | "var/lib/rpm/Packages"
        | "var/lib/rpm/Packages.db"
        | "usr/lib/sysimage/rpm/Packages"
        | "usr/lib/sysimage/rpm/Packages.db" => return 64 << 20,
        _ => {}
    }
    let dpkg_info = name.starts_with("var/lib/dpkg/info/")
        && (name.ends_with(".list") || name.ends_with(".md5sums"));
    if dpkg_info {
        return 1 << 20;
    }
    if is_selected_binary(name, products) {
        return 8 << 20;
    }
    0
}

impl RootFs {
    /// 이 이름이 담을 PHP 설정 파일인가.
    pub(super) fn selected_config(&self, name: &str, products: &[Product]) -> bool {
        selected_config(self, name, products)
    }
}
