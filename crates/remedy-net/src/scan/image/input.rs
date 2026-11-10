//! 입력 경로의 규칙 — 사내 runtime-scanner 의 `internal/storage` 가운데 입력 쪽(`validatedInputPath` ·
//! `validateNode` · `OpenInputFile` · `OpenInputRoot`)을 옮겼다.
//!
//! 이미지 파일 · OCI 폴더 · 작업 폴더는 이 기계의 실제 경로여야 한다. 네트워크 경로 · 링크 · junction · 특수 파일을
//! 받지 않고, 경로의 조상을 하나하나 본다. 받기 전에는 아무것도 읽거나 만들지 않는다.
//!
//! Go 가 운영체제 함수로 보는 것을 여기서는 표준 라이브러리로 본다(이 크레이트는 unsafe 를 쓰지 않는다).
//!
//! - 링크 · junction: 링크 정보(`symlink_metadata`)가 링크라고 하는 것. Windows 에서는 이름 대리 재분석 지점
//!   (symlink · junction)이고, Go 가 보는 바로 그 표시다.
//! - 실제 경로: `canonicalize` 가 낸 경로가 적은 경로와 같아야 한다(대소문자는 Windows 에서만 가리지 않는다).
//!   Windows 는 드라이브 뿌리의 실제 경로를 앞에 두고 견주므로 SUBST 드라이브도 받는다(Go 와 같다).
//! - 로컬 여부: Windows 는 드라이브 뿌리의 실제 경로가 UNC(`\\?\UNC\`)가 아니어야 하고(Go 는 드라이브 종류를
//!   묻는다), Linux 는 `/proc/self/mountinfo` 에서 그 경로의 마운트가 로컬 파일 시스템이어야 한다(Go 와 같은 목록).
//!
//! Go 가 더 보는 것 — mountinfo 가 proc 위에 있는지, 연 핸들의 파일 시스템 종류(`fstatfs`), 열 때의
//! `O_NONBLOCK` · `O_NOFOLLOW` — 은 표준 라이브러리로 볼 수 없어 빠졌다. 그 대신 열기 전에 일반 파일인지 보고(FIFO 를
//! 열다 멈추지 않는다), 연 뒤에 같은 파일인지 다시 본다(유닉스: 장치 · inode, Windows: 만든 시각 · 고친 시각 ·
//! 크기 · 속성).

use remedy_sdk::i18n::Lang;
use std::fs::{File, Metadata, OpenOptions};
use std::path::{Path, PathBuf};

/// 경로 깊이의 상한 — Go 와 같다.
const MAX_DEPTH: usize = 128;

type Res<T> = Result<T, String>;

/// `\\` · `\??\` 로 시작하는 경로(Go 의 `networkName`). `/` 도 `\` 로 본다.
pub(super) fn network_name(path: &str) -> bool {
    let p = path.replace('/', "\\");
    p.starts_with("\\\\") || p.starts_with("\\??\\")
}

/// 받을 수 있는 입력 경로면 그 절대 경로(Go 의 `validatedInputPath`). 마지막은 일반 파일이거나 폴더다.
pub(super) fn validated(path: &Path, lang: Lang) -> Res<PathBuf> {
    let text = path.to_str().unwrap_or_default();
    if text.trim().is_empty() || network_name(text) {
        return Err(lang
            .t(
                "실제 로컬 입력 경로를 지정하십시오",
                "give a real local input path",
            )
            .to_string());
    }
    let abs = absolute(path).map_err(|_| unreadable(path, lang))?;
    let abs_text = abs.to_string_lossy().into_owned();
    if network_name(&abs_text) {
        return Err(lang
            .t(
                "네트워크 입력 경로는 받지 않습니다",
                "network input paths are not accepted",
            )
            .to_string());
    }
    let (base, rest) = split_root(&abs_text).ok_or_else(|| unreadable(path, lang))?;
    let parts: Vec<&str> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(SEP).collect()
    };
    if parts.len() > MAX_DEPTH {
        return Err(lang
            .t(
                "입력 경로 깊이가 제한을 넘었습니다",
                "the input path is too deep",
            )
            .to_string());
    }
    let place = Place::of(&base, lang)?;
    place.check(Path::new(&base), true, lang)?;
    let mut current = PathBuf::from(&base);
    for (i, part) in parts.iter().enumerate() {
        current.push(part);
        place.check(&current, i + 1 < parts.len(), lang)?;
    }
    Ok(abs)
}

#[cfg(windows)]
const SEP: char = '\\';
#[cfg(not(windows))]
const SEP: char = '/';

/// Go 의 `filepath.Abs` — Windows 는 `GetFullPathNameW`, 유닉스는 작업 폴더에 붙여 글자로 정리한다.
fn absolute(path: &Path) -> std::io::Result<PathBuf> {
    let abs = std::path::absolute(path)?;
    if cfg!(windows) {
        return Ok(abs);
    }
    let text = abs.to_str().ok_or(std::io::ErrorKind::InvalidInput)?;
    Ok(PathBuf::from(crate::scan::slashpath::clean(text)))
}

/// 뿌리(`C:\` · `/`)와 그 뒤. Windows 는 드라이브 문자 경로만 — 그 밖의 꼴은 앞에서 네트워크 경로로 걸렸다.
fn split_root(abs: &str) -> Option<(String, &str)> {
    if cfg!(windows) {
        let b = abs.as_bytes();
        let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
        return drive.then(|| (abs[..3].to_string(), abs[3..].trim_end_matches('\\')));
    }
    abs.strip_prefix('/').map(|rest| ("/".to_string(), rest))
}

/// 입력의 자리 — 로컬 여부를 볼 근거(Windows 는 드라이브 뿌리의 실제 경로, Linux 는 마운트 목록).
struct Place {
    #[cfg(windows)]
    root: String,
    #[cfg(target_os = "linux")]
    mounts: Vec<super::mounts::Mount>,
}

impl Place {
    #[cfg(windows)]
    fn of(base: &str, lang: Lang) -> Res<Place> {
        let real = std::fs::canonicalize(base).map_err(|_| unreadable(Path::new(base), lang))?;
        let real = real.to_string_lossy().into_owned();
        if real.starts_with("\\\\?\\UNC\\") || !real.starts_with("\\\\?\\") {
            return Err(lang
                .t(
                    "네트워크 드라이브나 확인되지 않은 드라이브의 경로는 받지 않습니다",
                    "paths on network or unknown drives are not accepted",
                )
                .to_string());
        }
        Ok(Place {
            root: real["\\\\?\\".len()..].trim_end_matches('\\').to_string(),
        })
    }

    #[cfg(target_os = "linux")]
    fn of(_base: &str, lang: Lang) -> Res<Place> {
        Ok(Place {
            mounts: super::mounts::read(lang)?,
        })
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    fn of(_base: &str, _lang: Lang) -> Res<Place> {
        Ok(Place {})
    }

    /// 경로의 마디 하나(Go 의 `validateNode`).
    fn check(&self, path: &Path, directory: bool, lang: Lang) -> Res<()> {
        let text = path.to_string_lossy();
        if network_name(&text) {
            return Err(lang
                .t(
                    "네트워크 경로는 받지 않습니다",
                    "network paths are not accepted",
                )
                .to_string());
        }
        self.local(path, lang)?;
        let meta = std::fs::symlink_metadata(path).map_err(|_| unreadable(path, lang))?;
        if meta.file_type().is_symlink() || !(meta.is_dir() || meta.is_file()) {
            return Err(lang.pick(
                format!("링크나 특수 파일 대신 실제 로컬 경로를 지정하십시오: {text}"),
                format!("give a real local path instead of a link or special file: {text}"),
            ));
        }
        if directory && !meta.is_dir() {
            return Err(lang.pick(
                format!(
                    "폴더가 필요한 위치에 일반 파일이 있습니다. 폴더 경로를 지정하십시오: {text}"
                ),
                format!("a file sits where a folder is needed; give a folder path: {text}"),
            ));
        }
        self.real(path, lang)
    }

    #[cfg(target_os = "linux")]
    fn local(&self, path: &Path, lang: Lang) -> Res<()> {
        super::mounts::check(&path.to_string_lossy(), &self.mounts, lang)
    }

    #[cfg(not(target_os = "linux"))]
    fn local(&self, _path: &Path, _lang: Lang) -> Res<()> {
        Ok(())
    }

    /// 링크를 풀어도 같은 경로인가(Go 의 `EvalSymlinks` 와 `samePath`).
    fn real(&self, path: &Path, lang: Lang) -> Res<()> {
        let actual = std::fs::canonicalize(path).map_err(|_| unreadable(path, lang))?;
        if self.same(&actual, path) {
            return Ok(());
        }
        let text = path.to_string_lossy();
        Err(lang.pick(
            format!("경로에 링크 또는 junction 이 들어 있습니다: {text}"),
            format!("the path goes through a link or junction: {text}"),
        ))
    }

    #[cfg(windows)]
    fn same(&self, actual: &Path, path: &Path) -> bool {
        let actual = actual.to_string_lossy();
        let Some(actual) = actual.strip_prefix("\\\\?\\") else {
            return false;
        };
        let path = path.to_string_lossy();
        let expected = format!("{}{}", self.root, &path[2..]);
        actual.trim_end_matches('\\').to_lowercase()
            == expected.trim_end_matches('\\').to_lowercase()
    }

    #[cfg(not(windows))]
    fn same(&self, actual: &Path, path: &Path) -> bool {
        actual == path
    }
}

fn unreadable(path: &Path, lang: Lang) -> String {
    let text = path.to_string_lossy();
    lang.pick(
        format!("경로를 확인하지 못했습니다: {text}"),
        format!("could not check the path: {text}"),
    )
}

/// 같은 파일인가 — 유닉스는 장치 · inode, Windows 는 만든 시각 · 고친 시각 · 크기 · 속성(안정판 Rust 에는 파일
/// 번호가 없다).
pub(super) fn same_file(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        a.creation_time() == b.creation_time()
            && a.last_write_time() == b.last_write_time()
            && a.file_size() == b.file_size()
            && a.file_attributes() == b.file_attributes()
    }
}

/// 같은 폴더인가 — 유닉스는 장치 · inode, Windows 는 만든 시각 · 속성. 폴더의 고친 시각 · 크기는 안의 항목이
/// 바뀌면 따라 바뀌므로 보지 않는다(캐시 폴더에는 이 점검이 쓴다). Windows 에서는 쥔 폴더를 옮기거나 지울 수 없다 —
/// [`Held`] 가 지우기 공유 없이 연다.
pub(super) fn same_dir(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        same_file(a, b)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        a.creation_time() == b.creation_time() && a.file_attributes() == b.file_attributes()
    }
}

/// 받을 수 있는 일반 파일을 연다(Go 의 `OpenInputFile`). 열기 전에 일반 파일인지 보고, 연 뒤에 같은 파일인지 본다.
pub(super) fn open_file(path: &Path, lang: Lang) -> Res<(File, Metadata)> {
    let abs = validated(path, lang)?;
    let before = std::fs::symlink_metadata(&abs).map_err(|_| unreadable(&abs, lang))?;
    if !before.is_file() {
        return Err(lang
            .t(
                "입력은 일반 파일이어야 합니다",
                "the input must be a regular file",
            )
            .to_string());
    }
    let changed = || {
        lang.t(
            "입력 파일을 여는 동안 실제 경로 또는 파일이 바뀌었습니다",
            "the input file or its real path changed while it was being opened",
        )
        .to_string()
    };
    let file = no_follow(OpenOptions::new().read(true))
        .open(&abs)
        .map_err(|_| unreadable(&abs, lang))?;
    let after = file.metadata().map_err(|_| changed())?;
    if !after.is_file() || !same_file(&before, &after) {
        return Err(changed());
    }
    validated(&abs, lang).map_err(|_| changed())?;
    Ok((file, after))
}

/// Windows 에서는 재분석 지점을 따라가지 않고 그 자리를 연다 — 열기 직전에 링크로 바뀌어도 그 링크가 열려 같은
/// 파일 검사에서 걸린다.
fn no_follow(open: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        open.custom_flags(0x0020_0000);
    }
    open
}

/// 쥐고 있는 폴더(Go 의 `os.Root` 자리). Windows 에서는 지우기 공유 없이 열어, 점검하는 동안 그 폴더를 옮기거나
/// 지울 수 없게 한다 — Go 의 핸들과 같다. 유닉스에서는 장치 · inode 로 바꿔치기를 알아챈다.
pub(super) struct Held {
    path: PathBuf,
    meta: Metadata,
    _handle: File,
}

impl Held {
    /// 이미 있는 실제 폴더를 쥔다(Go 의 `OpenInputRoot`).
    pub(super) fn open(path: &Path, lang: Lang) -> Res<Held> {
        let abs = validated(path, lang)?;
        let not_dir = || {
            lang.t(
                "입력 경로는 이미 있는 실제 폴더여야 합니다",
                "the input path must be an existing real folder",
            )
            .to_string()
        };
        let before = std::fs::symlink_metadata(&abs).map_err(|_| not_dir())?;
        if !before.is_dir() || before.file_type().is_symlink() {
            return Err(not_dir());
        }
        let handle = dir_options()
            .open(&abs)
            .map_err(|_| unreadable(&abs, lang))?;
        let meta = handle.metadata().map_err(|_| unreadable(&abs, lang))?;
        let held = Held {
            path: abs,
            meta,
            _handle: handle,
        };
        held.still(lang)?;
        Ok(held)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn meta(&self) -> &Metadata {
        &self.meta
    }

    /// 그 경로가 아직 쥔 폴더를 가리키는가.
    pub(super) fn still(&self, lang: Lang) -> Res<()> {
        let now = std::fs::symlink_metadata(&self.path).ok();
        match now {
            Some(m) if m.is_dir() && !m.file_type().is_symlink() && same_dir(&m, &self.meta) => {
                Ok(())
            }
            _ => Err(lang
                .t(
                    "점검하는 동안 이미지 폴더의 실제 경로가 바뀌었습니다",
                    "the real path of the image folder changed during the check",
                )
                .to_string()),
        }
    }
}

fn dir_options() -> OpenOptions {
    let mut open = OpenOptions::new();
    open.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // 폴더 핸들(FILE_FLAG_BACKUP_SEMANTICS) · 재분석 지점을 따라가지 않음 · 읽기와 쓰기만 공유(옮기기 · 지우기
        // 막음).
        open.custom_flags(0x0200_0000 | 0x0020_0000);
        open.share_mode(0x1 | 0x2);
    }
    open
}
