//! 레이어 하나를 가상 뿌리에 덮는다 — 스캐너의 `applyLayer` · `virtualLink`.
//!
//! 레이어의 압축 바이트 수 · 압축 다이제스트 · 푼 다이제스트(diffID)를 끝까지 읽은 뒤에 대조하고, 셋 다 맞을 때만
//! 덮는다. 하나라도 어긋나면 그 이미지는 아래 레이어까지 버린다 — 덮이지 않은 아래 레이어의 옛 PHP 를 최종 구성으로
//! 보고하지 않는다. 화이트아웃은 아래 레이어만 지운다(같은 레이어 안의 차례와 상관없다).

use super::config::{CONFIG_DATA_LIMIT, CONFIG_FILE_LIMIT, MAX_CONFIG_FILES};
use super::expand::{drain_zeros, expanded};
use super::fault::describe;
use super::meta::{digest_path, hex};
use super::names;
use super::rootfs::{capture_limit, is_selected_binary, Entry, RootFs, SELECTED_DATA_LIMIT};
use super::source::{archive_path, drive_path, reject_sparse, Source};
use super::tarball::{
    Header, TarReader, TYPE_BLOCK, TYPE_CHAR, TYPE_DIR, TYPE_FIFO, TYPE_LINK, TYPE_REG,
    TYPE_SYMLINK,
};
use super::Cx;
use crate::scan::budget::IMAGE_LIMIT;
use crate::scan::slashpath;
use md5::{Digest as _, Md5};
use remedy_sdk::i18n::Lang;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};

type Res<T> = Result<T, String>;

/// 매니페스트가 말하는 레이어.
#[derive(Debug, Clone, Default)]
pub(super) struct LayerSpec {
    /// 이미지 안의 블롭 이름.
    pub(super) name: String,
    /// 압축 다이제스트 — docker save 는 비어 있다.
    pub(super) digest: String,
    pub(super) media_type: String,
    pub(super) diff_id: String,
    /// 압축 바이트 수 — docker save 는 -1(보지 않는다).
    pub(super) size: i64,
}

/// 한 레이어가 바꾸는 것 — 다 읽고 대조한 뒤에야 뿌리에 덮는다.
#[derive(Default)]
pub(super) struct Changes {
    pub(super) added: BTreeMap<String, Entry>,
    pub(super) deleted: BTreeSet<String>,
    pub(super) opaque: BTreeSet<String>,
    captured: i64,
    config_bytes: i64,
    config_files: usize,
    config_limited: bool,
}

/// 읽은 바이트를 세고 SHA-256 을 낸다.
struct Hashing<R> {
    inner: R,
    sha: Sha256,
    n: u64,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.sha.update(&buf[..n]);
        self.n += n as u64;
        Ok(n)
    }
}

impl<R> Hashing<R> {
    fn new(inner: R) -> Self {
        Hashing {
            inner,
            sha: Sha256::new(),
            n: 0,
        }
    }

    fn digest(&self) -> String {
        format!("sha256:{}", hex(&self.sha.clone().finalize()))
    }
}

/// 레이어 하나를 읽어 대조하고 덮는다.
pub(super) fn apply(src: &Source<'_>, fs: &mut RootFs, layer: &LayerSpec, cx: &Cx<'_>) -> Res<()> {
    let lang = cx.lang;
    digest_path(&layer.diff_id, lang).map_err(|why| {
        lang.pick(
            format!("해제한 레이어의 sha256 정보: {why}"),
            format!("sha256 of the expanded layer: {why}"),
        )
    })?;
    let mut raw = Hashing::new(src.open_member(&layer.name)?);
    let mut changes = Changes {
        captured: fs.captured,
        config_bytes: fs.config_bytes,
        config_files: fs.config_files,
        config_limited: fs.config_limited,
        ..Changes::default()
    };
    let diff = {
        let reader =
            expanded(&mut raw, cx.budget, &layer.media_type).map_err(|e| describe(&e, lang))?;
        let mut hashed = Hashing::new(reader);
        let mut tar = TarReader::new(&mut hashed);
        read_entries(&mut tar, fs, cx, &mut changes)?;
        drain_zeros(&mut tar.into_inner()).map_err(|e| describe(&e, lang))?;
        hashed.digest()
    };
    // 압축 판독기가 앞서 읽어 둔 것이 있어도 압축 스트림을 끝까지 읽는다.
    io::copy(&mut raw, &mut io::sink()).map_err(|e| describe(&e, lang))?;
    check_digests(layer, &raw, &diff, lang)?;
    merge(fs, changes, cx)
}

fn check_digests<R>(layer: &LayerSpec, raw: &Hashing<R>, diff: &str, lang: Lang) -> Res<()> {
    let words = if layer.size >= 0 && raw.n != layer.size as u64 {
        (
            "레이어의 실제 크기와 매니페스트의 크기가 다릅니다",
            "the layer's actual size differs from the manifest",
        )
    } else if !layer.digest.is_empty() && raw.digest() != layer.digest {
        (
            "압축 레이어의 sha256 해시가 일치하지 않습니다",
            "the compressed layer's sha256 digest does not match",
        )
    } else if diff != layer.diff_id {
        (
            "해제한 레이어의 sha256 해시가 일치하지 않습니다",
            "the expanded layer's sha256 digest does not match",
        )
    } else {
        return Ok(());
    };
    Err(lang.t(words.0, words.1).to_string())
}

/// 레이어의 항목을 끝까지 읽는다.
fn read_entries<R: Read>(
    tar: &mut TarReader<R>,
    fs: &RootFs,
    cx: &Cx<'_>,
    ch: &mut Changes,
) -> Res<()> {
    let lang = cx.lang;
    loop {
        let h = match tar.next() {
            Ok(Some(h)) => h,
            Ok(None) => return Ok(()),
            Err(e) => return Err(describe(&e, lang)),
        };
        cx.budget.count_entry().map_err(|h| h.message(lang))?;
        entry(tar, &h, fs, cx, ch)?;
    }
}

/// 항목 하나 — 화이트아웃은 표시만 하고, 나머지는 바꿀 것으로 담는다.
fn entry<R: Read>(
    tar: &mut TarReader<R>,
    h: &Header,
    fs: &RootFs,
    cx: &Cx<'_>,
    ch: &mut Changes,
) -> Res<()> {
    let lang = cx.lang;
    let Some(name) = entry_name(h, fs, lang)? else {
        return Ok(());
    };
    if let Some(removed) = slashpath::base(&name).strip_prefix(".wh.") {
        return whiteout(h, &name, removed, ch, lang);
    }
    let e = content(tar, h, &name, fs, cx, ch)?;
    ch.added.insert(name, e);
    Ok(())
}

/// 항목의 이름 — 크기 · 희소 파일을 거르고, 뿌리 폴더 자체(`.`)면 `None`.
fn entry_name(h: &Header, fs: &RootFs, lang: Lang) -> Res<Option<String>> {
    let name = fs.key(&archive_path(&names::from_bytes(&h.name), lang)?);
    if h.size < 0 || h.size as u64 > IMAGE_LIMIT {
        return Err(lang
            .t(
                "레이어 파일 크기가 제한을 넘었습니다",
                "a layer file exceeds the size limit",
            )
            .to_string());
    }
    reject_sparse(h, lang)?;
    if name != "." {
        return Ok(Some(name));
    }
    if h.typeflag == TYPE_DIR {
        return Ok(None);
    }
    Err(lang
        .t(
            "레이어의 뿌리가 폴더가 아닙니다",
            "the layer root is not a folder",
        )
        .to_string())
}

/// 종류마다 담을 것 — 일반 파일은 앞부분과 해시, 링크는 대상, 폴더 · 장치 · FIFO 는 자료 없이.
fn content<R: Read>(
    tar: &mut TarReader<R>,
    h: &Header,
    name: &str,
    fs: &RootFs,
    cx: &Cx<'_>,
    ch: &mut Changes,
) -> Res<Entry> {
    let lang = cx.lang;
    let mut e = Entry {
        kind: h.typeflag,
        size: h.size,
        mode: h.mode,
        ..Entry::default()
    };
    match h.typeflag {
        TYPE_REG => return capture(tar, h, name, fs, cx, ch),
        TYPE_DIR => no_data(h, "디렉터리", "directory", lang)?,
        // 장치 · FIFO 는 내용 없는 항목으로 둔다 — 덮고 지워지는 것은 다른 항목과 같고, 후보가 되지 않는다
        // (`rootfs` 머리말).
        TYPE_CHAR | TYPE_BLOCK | TYPE_FIFO => no_data(h, "장치 · FIFO", "device or FIFO", lang)?,
        TYPE_SYMLINK | TYPE_LINK => {
            let hard = h.typeflag == TYPE_LINK;
            let what = if hard {
                ("하드 링크", "hard link")
            } else {
                ("심볼릭 링크", "symbolic link")
            };
            no_data(h, what.0, what.1, lang)?;
            let target = names::from_bytes(&h.linkname);
            e.link = fs.key(&virtual_link(name, &target, hard, lang)?);
        }
        _ => {
            return Err(lang.pick(
                format!("지원하지 않는 종류의 레이어 항목입니다: {name}"),
                format!("a layer entry of an unsupported type: {name}"),
            ))
        }
    }
    Ok(e)
}

fn no_data(h: &Header, ko: &str, en: &str, lang: Lang) -> Res<()> {
    if h.size == 0 {
        return Ok(());
    }
    Err(lang.pick(
        format!("{ko} 항목에 데이터가 들어 있습니다"),
        format!("a {en} entry carries data"),
    ))
}

/// 화이트아웃 — `.wh..wh..opq` 는 그 폴더의 아래 레이어 전부, `.wh.<이름>` 은 그 이름을 지운다.
fn whiteout(h: &Header, name: &str, removed: &str, ch: &mut Changes, lang: Lang) -> Res<()> {
    if h.typeflag != TYPE_REG {
        return Err(lang
            .t(
                "whiteout 항목은 일반 파일이어야 합니다",
                "a whiteout entry must be a regular file",
            )
            .to_string());
    }
    if h.size != 0 {
        return Err(lang
            .t(
                "whiteout 항목에 데이터가 들어 있습니다",
                "a whiteout entry carries data",
            )
            .to_string());
    }
    let parent = slashpath::dir(name);
    if removed == ".wh..opq" {
        ch.opaque.insert(parent);
        return Ok(());
    }
    if matches!(removed, "" | "." | "..") {
        return Err(lang
            .t("whiteout 이름이 잘못됐습니다", "invalid whiteout name")
            .to_string());
    }
    ch.deleted.insert(slashpath::join(&[&parent, removed]));
    Ok(())
}

/// 일반 파일 — 담을 자리면 앞부분을 담고, 고른 제품의 실행 파일이면 파일 전체의 SHA-256 · MD5 를 낸다(스캐너와
/// 같은 한도 계산). PHP 설정은 따로 센다 — 파일당 4 MiB, 합계 16 MiB, 64개.
fn capture<R: Read>(
    tar: &mut TarReader<R>,
    h: &Header,
    name: &str,
    fs: &RootFs,
    cx: &Cx<'_>,
    ch: &mut Changes,
) -> Res<Entry> {
    let mut e = Entry {
        kind: TYPE_REG,
        size: h.size,
        mode: h.mode,
        ..Entry::default()
    };
    let selected = is_selected_binary(name, cx.products);
    let mut limit = capture_limit(name, cx.products);
    let config = fs.selected_config(name, cx.products);
    if config {
        limit = CONFIG_FILE_LIMIT.min(CONFIG_DATA_LIMIT - ch.config_bytes);
        if ch.config_files >= MAX_CONFIG_FILES {
            limit = 0;
        }
        ch.config_files += 1;
        ch.config_limited |= h.size > limit;
        e.truncated = h.size > limit;
    }
    let mut hash = selected.then(|| (Sha256::new(), Md5::new()));
    if limit > 0 {
        if !config {
            limit = limit.min(SELECTED_DATA_LIMIT - ch.captured);
        }
        e.truncated = h.size > limit;
        if limit > 0 {
            e.data = vec![0; h.size.min(limit) as usize];
            tar.read_exact(&mut e.data)
                .map_err(|err| describe(&err, cx.lang))?;
            feed(&mut hash, &e.data);
            let n = e.data.len() as i64;
            if config {
                ch.config_bytes += n;
            } else {
                ch.captured += n;
            }
        }
    }
    if let Some((sha, md5)) = hash.as_mut() {
        rest_into(tar, sha, md5).map_err(|err| describe(&err, cx.lang))?;
        e.sha256 = hex(&sha.clone().finalize());
        e.md5 = hex(&md5.clone().finalize());
    }
    Ok(e)
}

fn feed(hash: &mut Option<(Sha256, Md5)>, data: &[u8]) {
    if let Some((sha, md5)) = hash.as_mut() {
        sha.update(data);
        md5.update(data);
    }
}

/// 항목의 남은 데이터를 해시에 넣는다.
fn rest_into(r: &mut impl Read, sha: &mut Sha256, md5: &mut Md5) -> io::Result<()> {
    let mut buf = vec![0u8; 32 << 10];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        sha.update(&buf[..n]);
        md5.update(&buf[..n]);
    }
}

/// 링크 대상을 가상 뿌리 안의 경로로(스캐너의 `virtualLink`). 하드 링크는 아카이브 경로이고, 심볼릭 링크는 그
/// 항목의 폴더에서 푼다 — 절대 경로 링크는 이미지의 뿌리에서 시작하고, 뿌리 위로 나가면 거절한다.
pub(super) fn virtual_link(name: &str, target: &str, hard: bool, lang: Lang) -> Res<String> {
    if target.is_empty()
        || names::raw_len(target) > 4096
        || target.contains(['\\', '\0'])
        || drive_path(target)
    {
        return Err(lang
            .t("안전하지 않은 레이어 링크입니다", "unsafe layer link")
            .to_string());
    }
    if hard {
        return archive_path(target, lang);
    }
    let parent = slashpath::dir(name);
    let mut parts: Vec<&str> = if !target.starts_with('/') && parent != "." {
        parent.split('/').collect()
    } else {
        Vec::new()
    };
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(lang
                        .t(
                            "컨테이너 뿌리를 벗어나는 링크입니다",
                            "the link leaves the container root",
                        )
                        .to_string());
                }
            }
            _ => parts.push(part),
        }
    }
    Ok(if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    })
}

/// 바꿀 것을 뿌리에 덮는다(스캐너의 `merge`). 화이트아웃 · 불투명 폴더 · 폴더가 아닌 것으로 바뀐 조상은 아래
/// 레이어의 항목만 지운다. 덮은 뒤 — 새 항목의 조상이 폴더가 아니거나, 링크가 순환하거나, 하드 링크의 대상이
/// 없으면 오류다. 끊긴 심볼릭 링크는 이미지에 흔해 받는다.
fn merge(fs: &mut RootFs, ch: Changes, cx: &Cx<'_>) -> Res<()> {
    let lang = cx.lang;
    let mut gone = Vec::new();
    for (n, name) in fs.entries.keys().enumerate() {
        if (n + 1) % 256 == 0 {
            cx.budget.check().map_err(|h| h.message(lang))?;
        }
        if hidden(name, &ch) {
            gone.push(name.clone());
        }
    }
    for name in gone {
        fs.entries.remove(&name);
    }
    let names: Vec<String> = ch.added.keys().cloned().collect();
    fs.entries.extend(ch.added);
    for name in &names {
        check_parents(fs, name, lang)?;
    }
    super::links::check(fs, lang)?;
    fs.captured = ch.captured;
    fs.config_bytes = ch.config_bytes;
    fs.config_files = ch.config_files;
    fs.config_limited = ch.config_limited;
    Ok(())
}

/// 아래 레이어의 이 항목을 이번 레이어가 지우는가.
fn hidden(name: &str, ch: &Changes) -> bool {
    let mut cur = name.to_string();
    loop {
        if ch.deleted.contains(&cur) {
            return true;
        }
        if cur != name {
            if ch.opaque.contains(&cur) {
                return true;
            }
            if ch.added.get(&cur).is_some_and(|e| e.kind != TYPE_DIR) {
                return true;
            }
        }
        if cur == "." {
            return false;
        }
        cur = slashpath::dir(&cur);
    }
}

fn check_parents(fs: &RootFs, name: &str, lang: Lang) -> Res<()> {
    let mut parent = slashpath::dir(name);
    while parent != "." {
        if fs.entries.get(&parent).is_some_and(|e| e.kind != TYPE_DIR) {
            return Err(lang.pick(
                format!("레이어 경로의 상위 항목이 폴더가 아닙니다: {name}"),
                format!("a parent in a layer path is not a folder: {name}"),
            ));
        }
        parent = slashpath::dir(&parent);
    }
    Ok(())
}
