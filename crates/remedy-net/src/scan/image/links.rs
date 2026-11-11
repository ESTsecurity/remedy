//! 링크 순환 검사 — 레이어를 덮을 때마다 가상 뿌리 안에서만 따라간다(이 기계의 파일 시스템을 따라가지 않는다).
//! 심볼릭 · 하드 링크가 섞인 순환, 256 단을 넘는 사슬, 대상이 없는 하드 링크는 오류다. 끊긴 심볼릭 링크는 받는다.

use super::rootfs::RootFs;
use super::tarball::{TYPE_LINK, TYPE_SYMLINK};
use remedy_sdk::i18n::Lang;
use std::collections::HashMap;

const MAX_DEPTH: usize = 256;

type Res<T> = Result<T, String>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Open,
    Done,
}

pub(super) fn check(fs: &RootFs, lang: Lang) -> Res<()> {
    let mut marks: HashMap<&str, Mark> = HashMap::new();
    for name in fs.entries.keys() {
        visit(fs, name, 0, &mut marks, lang)?;
    }
    Ok(())
}

fn visit<'a>(
    fs: &'a RootFs,
    name: &'a str,
    depth: usize,
    marks: &mut HashMap<&'a str, Mark>,
    lang: Lang,
) -> Res<()> {
    if depth > MAX_DEPTH {
        return Err(lang
            .t(
                "레이어 링크 깊이 제한을 넘었습니다",
                "a layer link chain is too deep",
            )
            .to_string());
    }
    match marks.get(name) {
        Some(Mark::Open) => {
            return Err(lang.pick(
                format!("레이어 링크가 순환합니다: {name}"),
                format!("layer links form a loop: {name}"),
            ))
        }
        Some(Mark::Done) => return Ok(()),
        None => {}
    }
    let Some(e) = fs.entries.get(name) else {
        return Ok(());
    };
    if e.kind != TYPE_LINK && e.kind != TYPE_SYMLINK {
        return Ok(());
    }
    marks.insert(name, Mark::Open);
    if e.kind == TYPE_LINK && !fs.entries.contains_key(&e.link) {
        return Err(lang.pick(
            format!("대상이 없는 하드 링크입니다: {name}"),
            format!("a hard link has no target: {name}"),
        ));
    }
    visit(fs, &e.link, depth + 1, marks, lang)?;
    marks.insert(name, Mark::Done);
    Ok(())
}
