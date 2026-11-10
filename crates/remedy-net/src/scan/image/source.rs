//! 이미지 입력 — OCI 폴더는 그 자리에서 읽고, 파일 하나(OCI 아카이브 · docker save, 압축 포함)는 작업 폴더 아래 새
//! `images-<32자리 16진수>` 폴더에 항목마다 불투명한 이름(`blob-000000` …)으로 풀었다가 점검을 마치면 지운다.
//! 사내 runtime-scanner 의 `internal/images/source.go` 를 옮겼다.
//!
//! 아카이브 항목의 이름은 이 기계의 경로로 쓰지 않는다 — 찾는 키일 뿐이다. 아카이브에는 일반 파일과 폴더만 있어야
//! 하고(링크 · 장치 · 전역 PAX 머리 · 희소 파일은 거절), 이름이 겹치거나 tar 끝 뒤에 0 이 아닌 바이트가 있으면
//! 이미지 전체를 읽지 않는다. 풀어 둔 항목을 다시 읽는 것도 *이미지 파일에서 읽는 양* 으로 센다 — 물리적으로 또
//! 읽는 것이다.

use super::expand::{drain_zeros, expanded};
use super::fault::describe;
use super::input::{self, same_dir, same_file, Held};
use super::names;
use super::tarball::{Header, TarReader, TYPE_DIR, TYPE_GNU_SPARSE, TYPE_REG};
use crate::scan::budget::{Budget, Metered, ReadKind, IMAGE_LIMIT};
use crate::scan::slashpath;
use remedy_sdk::i18n::Lang;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

type Res<T> = Result<T, String>;

/// 이미지 경로의 길이 상한(바이트).
const MAX_PATH: usize = 4096;

pub(super) struct Source<'b> {
    budget: &'b Budget,
    lang: Lang,
    /// 항목을 읽는 폴더 — OCI 폴더 또는 풀어 둔 폴더. 지우기 전에 놓아야 하므로 `Option` 이다.
    held: Option<Held>,
    /// 아카이브면 항목 이름 → 풀어 둔 파일 이름.
    members: Option<BTreeMap<String, String>>,
    /// 점검을 마치면 지울 폴더.
    cache: Option<PathBuf>,
}

impl Drop for Source<'_> {
    fn drop(&mut self) {
        self.held = None;
        if let Some(dir) = self.cache.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl<'b> Source<'b> {
    /// 입력 하나를 연다(스캐너의 `newSource`). 폴더면 그대로, 파일이면 작업 폴더 아래에 푼다.
    pub(super) fn open(input: &str, work_dir: &Path, budget: &'b Budget, lang: Lang) -> Res<Self> {
        let abs = input::validated(Path::new(input), lang)?;
        let meta = std::fs::symlink_metadata(&abs).map_err(|_| missing(&abs, lang))?;
        let mut source = Source {
            budget,
            lang,
            held: None,
            members: None,
            cache: None,
        };
        if meta.is_dir() {
            let held = Held::open(&abs, lang)?;
            if !same_dir(&meta, held.meta()) {
                return Err(lang
                    .t(
                        "OCI 입력 폴더를 여는 동안 경로가 바뀌었습니다",
                        "the OCI input folder changed while it was being opened",
                    )
                    .to_string());
            }
            source.held = Some(held);
            return Ok(source);
        }
        if !meta.is_file() {
            return Err(lang
                .t(
                    "이미지 입력은 일반 파일이거나 OCI 폴더여야 합니다",
                    "an image input must be a regular file or an OCI folder",
                )
                .to_string());
        }
        if meta.len() > IMAGE_LIMIT {
            return Err(lang
                .t(
                    "이미지 입력 파일이 8 GiB 제한을 넘었습니다",
                    "the image input file exceeds the 8 GiB limit",
                )
                .to_string());
        }
        let (file, opened) = input::open_file(&abs, lang)?;
        if !same_file(&meta, &opened) || opened.len() > IMAGE_LIMIT {
            return Err(lang
                .t(
                    "이미지 입력 파일을 여는 동안 파일 또는 크기가 바뀌었습니다",
                    "the image input file or its size changed while it was being opened",
                )
                .to_string());
        }
        source.make_cache(work_dir)?;
        source.unpack(file)?;
        Ok(source)
    }

    /// 작업 폴더 아래 새 폴더를 만들어 쥔다. 이 뒤로는 실패해도 `Drop` 이 그 폴더를 지운다.
    fn make_cache(&mut self, work_dir: &Path) -> Res<()> {
        let lang = self.lang;
        if work_dir.as_os_str().is_empty() {
            return Err(lang
                .t(
                    "이미지를 풀 작업 폴더가 지정되지 않았습니다",
                    "no work folder was given for unpacking the image",
                )
                .to_string());
        }
        let work_error = |why: String| {
            lang.pick(
                format!("이미지 작업 폴더: {why}"),
                format!("image work folder: {why}"),
            )
        };
        let work = input::validated(work_dir, lang).map_err(work_error)?;
        Held::open(&work, lang).map_err(work_error)?;
        let dir = work.join(format!("images-{}", nonce(lang)?));
        create_private_dir(&dir).map_err(|_| work_error(missing(&dir, lang)))?;
        self.cache = Some(dir.clone());
        let meta = std::fs::symlink_metadata(&dir).map_err(|_| missing(&dir, lang))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(lang
                .t(
                    "이미지 캐시 폴더가 링크 또는 특수 파일로 바뀌었습니다",
                    "the image cache folder was replaced by a link or special file",
                )
                .to_string());
        }
        let held = Held::open(&dir, lang)?;
        if !same_dir(&meta, held.meta()) {
            return Err(lang
                .t(
                    "이미지 캐시 폴더의 실제 경로가 바뀌었습니다",
                    "the real path of the image cache folder changed",
                )
                .to_string());
        }
        self.held = Some(held);
        Ok(())
    }

    /// 아카이브를 항목마다 풀어 둔다.
    fn unpack(&mut self, file: File) -> Res<()> {
        let (budget, lang) = (self.budget, self.lang);
        let dir = match &self.held {
            Some(held) => held.path().to_path_buf(),
            None => return Err(missing(Path::new("images-"), lang)),
        };
        let raw = budget.wrap_reader(file, ReadKind::ImageInput);
        let expanded = expanded(raw, budget, "").map_err(|e| describe(&e, lang))?;
        let mut tar = TarReader::new(expanded);
        let mut members = BTreeMap::new();
        loop {
            let h = match tar.next() {
                Ok(Some(h)) => h,
                Ok(None) => break,
                Err(e) => {
                    let why = describe(&e, lang);
                    return Err(lang.pick(
                        format!("이미지 아카이브 읽기: {why}"),
                        format!("reading the image archive: {why}"),
                    ));
                }
            };
            budget.count_entry().map_err(|h| h.message(lang))?;
            member(&mut tar, &h, &dir, &mut members, lang)?;
        }
        drain_zeros(&mut tar.into_inner()).map_err(|e| describe(&e, lang))?;
        self.members = Some(members);
        Ok(())
    }

    /// 그 항목이 있는가 — 아카이브는 항목 표, 폴더는 일반 파일인지.
    pub(super) fn has(&self, name: &str) -> bool {
        match &self.members {
            Some(members) => members.contains_key(name),
            None => self.held.as_ref().is_some_and(|held| {
                std::fs::symlink_metadata(held.path().join(name)).is_ok_and(|m| m.is_file())
            }),
        }
    }

    /// 항목 하나를 연다(스캐너의 `open`). 경로의 마디마다 링크 · 특수 파일이 아닌지 연기 전에 본다 — 연 뒤에
    /// 보면 FIFO 에서 멈출 수 있다. 폴더 입력은 여는 항목도 파일 항목으로 센다.
    pub(super) fn open_member(&self, name: &str) -> Res<Metered<'b, File>> {
        let lang = self.lang;
        let clean = archive_path(name, lang)
            .ok()
            .filter(|c| c != ".")
            .ok_or_else(|| {
                lang.pick(
                    format!("이미지 항목 경로가 잘못됐습니다: {name:?}"),
                    format!("invalid image entry path: {name:?}"),
                )
            })?;
        let stored = match &self.members {
            Some(members) => members.get(&clean).cloned().ok_or_else(|| {
                lang.pick(
                    format!("이미지 항목이 없습니다: {name}"),
                    format!("the image entry is missing: {name}"),
                )
            })?,
            None => {
                self.budget.count_entry().map_err(|h| h.message(lang))?;
                clean
            }
        };
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| missing(Path::new(name), lang))?;
        held.still(lang)?;
        let (path, before) = walk_member(held.path(), &stored, lang)?;
        let (file, opened) = input::open_file(&path, lang)?;
        if !opened.is_file() || opened.len() > IMAGE_LIMIT || !same_file(&before, &opened) {
            return Err(lang
                .t(
                    "이미지 항목을 여는 동안 파일이 바뀌었거나 크기 제한을 넘었습니다",
                    "an image entry changed while being opened or exceeds the size limit",
                )
                .to_string());
        }
        Ok(self.budget.wrap_reader(file, ReadKind::ImageInput))
    }

    /// 항목 하나를 끝까지 읽는다 — `max` 를 넘으면 오류다(스캐너의 `read`).
    pub(super) fn read(&self, name: &str, max: u64) -> Res<Vec<u8>> {
        let lang = self.lang;
        let mut data = Vec::new();
        self.open_member(name)?
            .take(max + 1)
            .read_to_end(&mut data)
            .map_err(|e| describe(&e, lang))?;
        if data.len() as u64 > max {
            return Err(lang.pick(
                format!("이미지 메타데이터 크기 제한을 넘었습니다: {name}"),
                format!("image metadata exceeds the size limit: {name}"),
            ));
        }
        Ok(data)
    }
}

/// 아카이브 항목 하나를 풀어 둔다 — 폴더는 건너뛰고 일반 파일만 받는다.
fn member(
    tar: &mut TarReader<impl Read>,
    h: &Header,
    dir: &Path,
    members: &mut BTreeMap<String, String>,
    lang: Lang,
) -> Res<()> {
    let name = archive_path(&names::from_bytes(&h.name), lang)?;
    if h.size < 0 || h.size as u64 > IMAGE_LIMIT {
        return Err(lang
            .t(
                "아카이브 항목 크기가 제한을 넘었습니다",
                "an archive entry exceeds the size limit",
            )
            .to_string());
    }
    reject_sparse(h, lang)?;
    if h.typeflag == TYPE_DIR {
        return Ok(());
    }
    if h.typeflag != TYPE_REG {
        return Err(lang.pick(
            format!("이미지 아카이브의 링크 또는 특수 파일은 받지 않습니다: {name}"),
            format!("links and special files in the image archive are not accepted: {name}"),
        ));
    }
    if name == "." {
        return Err(lang
            .t(
                "아카이브 파일 이름이 비어 있습니다",
                "an archive file name is empty",
            )
            .to_string());
    }
    if members.contains_key(&name) {
        return Err(lang.pick(
            format!("이미지 아카이브 항목이 겹칩니다: {name}"),
            format!("duplicate image archive entry: {name}"),
        ));
    }
    let stored = format!("blob-{:06}", members.len());
    let written = write_member(&dir.join(&stored), tar).map_err(|e| describe(&e, lang))?;
    if written != h.size as u64 {
        return Err(lang
            .t(
                "아카이브 항목의 실제 크기가 머리와 다릅니다",
                "an archive entry's actual size differs from its header",
            )
            .to_string());
    }
    members.insert(name, stored);
    Ok(())
}

/// 폴더 아래 항목의 마디마다 — 링크가 아니고, 중간은 폴더, 끝은 일반 파일이며 8 GiB 안이다.
fn walk_member(root: &Path, stored: &str, lang: Lang) -> Res<(PathBuf, std::fs::Metadata)> {
    let refused = || {
        lang.t(
            "이미지 항목의 링크 또는 특수 파일은 받지 않습니다",
            "links and special files among image entries are not accepted",
        )
        .to_string()
    };
    let parts: Vec<&str> = stored.split('/').collect();
    let mut path = root.to_path_buf();
    let mut last = None;
    for (i, part) in parts.iter().enumerate() {
        path.push(part);
        let meta = std::fs::symlink_metadata(&path).map_err(|_| missing(&path, lang))?;
        let end = i + 1 == parts.len();
        if meta.file_type().is_symlink() || (!end && !meta.is_dir()) || (end && !meta.is_file()) {
            return Err(refused());
        }
        last = Some(meta);
    }
    let meta = last.ok_or_else(refused)?;
    if meta.len() > IMAGE_LIMIT {
        return Err(lang
            .t(
                "이미지 항목 크기가 제한을 넘었습니다",
                "an image entry exceeds the size limit",
            )
            .to_string());
    }
    Ok((path, meta))
}

/// 아카이브 · 레이어 항목의 이름(스캐너의 `archivePath`) — 비거나 역슬래시 · NUL · 절대 경로 · 드라이브 문자 ·
/// `..` 이 있으면 거절하고, 정리한 이름을 준다.
pub(super) fn archive_path(name: &str, lang: Lang) -> Res<String> {
    if name.is_empty() || name.contains(['\\', '\0']) || name.starts_with('/') || drive_path(name) {
        return Err(lang.pick(
            format!("안전하지 않은 아카이브 경로입니다: {name:?}"),
            format!("unsafe archive path: {name:?}"),
        ));
    }
    if name.split('/').any(|part| part == "..") {
        return Err(lang.pick(
            format!("상위 경로를 참조하는 아카이브 항목입니다: {name:?}"),
            format!("an archive entry refers to a parent path: {name:?}"),
        ));
    }
    let clean = slashpath::clean(name);
    if names::raw_len(&clean) > MAX_PATH {
        return Err(lang
            .t(
                "아카이브 경로 길이 제한을 넘었습니다",
                "an archive path exceeds the length limit",
            )
            .to_string());
    }
    Ok(clean)
}

/// `C:` 로 시작하는가.
pub(super) fn drive_path(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()
}

/// 희소 파일은 실제 데이터 크기를 한도 안에서 확인할 수 없어 받지 않는다(스캐너의 `rejectSparse`).
pub(super) fn reject_sparse(h: &Header, lang: Lang) -> Res<()> {
    if h.typeflag == TYPE_GNU_SPARSE {
        return Err(lang
            .t(
                "희소 파일 레이어는 지원하지 않습니다",
                "sparse-file layers are not supported",
            )
            .to_string());
    }
    let sparse = h.pax.iter().any(|(k, v)| {
        k.starts_with(b"GNU.sparse.")
            || k == b"SCHILY.realsize"
            || (k == b"SCHILY.filetype" && v == b"sparse")
    });
    if sparse {
        return Err(lang
            .t(
                "희소 파일은 실제 데이터 크기가 제한 안인지 확인할 수 없어 처리하지 않습니다",
                "sparse files are not processed: their real data size cannot be checked against the limit",
            )
            .to_string());
    }
    Ok(())
}

fn missing(path: &Path, lang: Lang) -> String {
    let text = path.to_string_lossy();
    lang.pick(
        format!("이미지 항목을 찾지 못했습니다: {text}"),
        format!("could not find the image entry: {text}"),
    )
}

/// 새 파일에만 쓴다(같은 이름이 있으면 실패). 유닉스에서는 주인만 읽는다.
fn write_member(path: &Path, from: &mut impl Read) -> io::Result<u64> {
    let mut open = OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut out = open.open(path)?;
    io::copy(from, &mut out)
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
}

/// 16바이트 난수의 16진수 32자리.
fn nonce(lang: Lang) -> Res<String> {
    let mut bytes = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| {
            lang.t(
                "작업 폴더 이름에 쓸 난수를 만들지 못했습니다",
                "could not make a random name for the work folder",
            )
            .to_string()
        })?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
