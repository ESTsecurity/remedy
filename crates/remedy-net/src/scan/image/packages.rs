//! 최종 구성의 배포판과 패키지 기록 — dpkg · apk · RPM DB. 스캐너의 `packages.go` 를 옮겼다.
//!
//! 패키지는 출처를 믿을 근거가 있을 때만 판정의 근거가 된다(`trusted`). dpkg 는 공식 배포판의 관리자 주소
//! (`Maintainer`)로 끝나는 것, RPM 은 공급사와 아키텍처가 적힌 것이고, apk 는 믿지 않는다. 믿을 수 있어도 실행
//! 파일이 패키지 기록과 같은지(dpkg 의 `.md5sums` · RPM 의 파일 다이제스트)를 따로 본다 — 서명을 확인한 것은 아니다.

use super::names;
use super::node::is_node_family;
use super::php::is_php_package;
use super::rootfs::{Entry, RootFs};
use super::source::archive_path;
use super::tarball::TYPE_REG;
use super::Cx;
use crate::scan::linuxmeta::{
    lower, parse_release, trim, valid_package_architecture, RELEASE_FILES,
};
use crate::scan::model::{Product, Target};
use crate::scan::slashpath;
use remedy_sdk::i18n::Lang;
use std::collections::{BTreeMap, BTreeSet};

type Res<T> = Result<T, String>;

const DPKG_STATUS: &str = "var/lib/dpkg/status";
const APK_INSTALLED: &str = "lib/apk/db/installed";
pub(super) const DPKG_SOURCE: &str = "/var/lib/dpkg/status";
const DPKG_INFO: &str = "var/lib/dpkg/info/";
/// 패키지 기록의 단락 수 상한.
const MAX_PARAGRAPHS: usize = 100_000;
/// 줄 하나의 상한(줄바꿈 포함) — Go 의 `bufio.Scanner` 버퍼.
const MAX_LINE: usize = 1 << 20;

/// 패키지 하나.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) name: String,
    pub(super) version: String,
    /// 읽은 DB(`/var/lib/dpkg/status` …).
    pub(super) source: String,
    pub(super) architecture: String,
    pub(super) vendor: String,
    pub(super) module: String,
    /// 소유한 파일(이미지 뿌리 기준, 정리한 경로).
    pub(super) files: Vec<String>,
    pub(super) trusted: bool,
    pub(super) rpm: bool,
    /// 파일 → 다이제스트. `None` 은 기록 자체가 없는 것이다.
    pub(super) checksums: Option<BTreeMap<String, String>>,
    pub(super) checksum_error: Option<String>,
    /// `md5` · `sha256`(RPM).
    pub(super) checksum_algorithm: &'static str,
}

/// 배포판 · 패키지를 읽고 고른 제품을 판정한다(스캐너의 `inspectRootFS`).
///
/// 스캐너는 서명과 발행 시각을 검증한 기준이 없으면 *보지 못한 것* 을 더했다. 여기서는 기준이 바이너리에 들어 있고
/// 만료가 없어 그 자리가 생기지 않는다(`scan::rules` 머리말).
pub(super) fn inspect(fs: &RootFs, t: &mut Target, cx: &Cx<'_>) {
    let (distro, release) = release(fs, t);
    t.metadata.insert("distribution".into(), distro.clone());
    t.metadata
        .insert("distribution_version".into(), release.clone());
    let packages = databases(fs, t, cx);
    let os = (distro.as_str(), release.as_str());
    if t.products.contains_key(&Product::Php) {
        super::php::inspect(fs, t, cx, &packages, os);
    }
    if t.products.contains_key(&Product::Node) {
        super::node::inspect(fs, t, cx, &packages, os);
    }
    super::config::inspect(fs, t, cx, &packages);
}

/// 배포판 기록 — 앞선 파일이 우선이고, 다 담아 읽은 일반 파일이어야 한다.
fn release(fs: &RootFs, t: &mut Target) -> (String, String) {
    for file in RELEASE_FILES {
        let name = file.trim_start_matches('/');
        let Ok((_, e)) = fs.resolve(name) else {
            continue;
        };
        if e.kind != TYPE_REG || e.truncated {
            continue;
        }
        if let Some(found) = parse_release(file, &e.data) {
            let products: Vec<Product> = t.products.keys().copied().collect();
            for p in products {
                t.add_product_scope(p, format!("/{name}"));
            }
            return found;
        }
    }
    (String::new(), String::new())
}

/// 패키지 DB 들 — dpkg · apk 와, RPM 은 처음 찾은 자리 하나.
fn databases(fs: &RootFs, t: &mut Target, cx: &Cx<'_>) -> Vec<Record> {
    let lang = cx.lang;
    let mut dbs = vec![DPKG_STATUS.to_string(), APK_INSTALLED.to_string()];
    if let Some(rpm) = rpm_database(fs) {
        dbs.push(rpm);
    }
    let info = DpkgInfo::index(fs);
    let mut found = false;
    let mut out = Vec::new();
    for db in dbs {
        // 내용 없는 장치 · FIFO 는 패키지 DB 후보가 아니다 — 없는 것과 같다.
        let Some(e) = fs.entries.get(&db).filter(|e| !e.special()) else {
            continue;
        };
        found = true;
        if e.kind != TYPE_REG || e.truncated {
            t.add_gap(lang.pick(
                format!("패키지 DB 전체를 읽을 수 없습니다: /{db}"),
                format!("the whole package database could not be read: /{db}"),
            ));
            continue;
        }
        let Some(mut parsed) = parse_database(fs, &db, e, t, cx) else {
            continue;
        };
        let products: Vec<Product> = t.products.keys().copied().collect();
        for p in products {
            t.add_product_scope(p, format!("/{db}"));
        }
        for record in &mut parsed {
            record.source = format!("/{db}");
            if db == DPKG_STATUS && wanted(t, &record.name) {
                attach_dpkg_files(&info, record, t, lang);
            }
        }
        out.extend(parsed);
    }
    if !found {
        t.add_gap(lang.t(
            "최종 이미지에서 지원되는 패키지 DB 를 찾지 못했습니다",
            "no supported package database was found in the final image",
        ));
    }
    out
}

fn rpm_database(fs: &RootFs) -> Option<String> {
    for root in ["usr/lib/sysimage/rpm", "var/lib/rpm"] {
        for base in ["rpmdb.sqlite", "Packages", "Packages.db"] {
            let name = format!("{root}/{base}");
            if fs.entries.get(&name).is_some_and(|e| !e.special()) {
                return Some(name);
            }
        }
    }
    None
}

/// DB 하나를 읽는다. 읽지 못하면 *보지 못한 것* 을 남기고 `None` — 다만 RPM 이 한도에 닿아 앞의 패키지만 읽은
/// 때는 그것을 쓴다.
fn parse_database(
    fs: &RootFs,
    db: &str,
    e: &Entry,
    t: &mut Target,
    cx: &Cx<'_>,
) -> Option<Vec<Record>> {
    let lang = cx.lang;
    let fail = |why: String| {
        lang.pick(
            format!("패키지 DB /{db}: {why}"),
            format!("package database /{db}: {why}"),
        )
    };
    let result = match db {
        DPKG_STATUS => parse_dpkg(&e.data, lang).map(|r| (r, None)),
        APK_INSTALLED => parse_apk(&e.data, lang).map(|r| (r, None)),
        _ => {
            if rpm_log_left(fs, db) {
                t.add_gap(lang.pick(
                    format!("RPM DB 의 쓰기 로그가 남아 있어 일관된 패키지 상태를 확인할 수 없습니다: /{db}"),
                    format!("an RPM database write log remains, so a consistent package state cannot be confirmed: /{db}"),
                ));
                return None;
            }
            super::rpm::parse(&e.data, cx)
        }
    };
    match result {
        Ok((records, None)) => Some(records),
        Ok((records, Some(limit))) => {
            t.add_gap(fail(limit));
            Some(records)
        }
        Err(why) => {
            t.add_gap(fail(why));
            None
        }
    }
}

/// `-wal` · `-journal` 이 비어 있지 않으면 DB 에 아직 반영되지 않은 바뀜이 있다.
fn rpm_log_left(fs: &RootFs, db: &str) -> bool {
    ["-wal", "-journal"].iter().any(|suffix| {
        fs.entries
            .get(&format!("{db}{suffix}"))
            .is_some_and(|e| e.size > 0)
    })
}

/// 파일 목록을 읽을 dpkg 패키지인가 — 고른 제품의 패키지만.
fn wanted(t: &Target, name: &str) -> bool {
    let php = t.products.contains_key(&Product::Php) && is_php_package(name);
    let node = t.products.contains_key(&Product::Node) && is_node_family(name);
    php || node
}

fn attach_dpkg_files(info: &DpkgInfo<'_>, record: &mut Record, t: &mut Target, lang: Lang) {
    match info.files(&record.name, &record.architecture, lang) {
        Ok(files) => record.files = files,
        Err(why) => t.add_gap(why),
    }
    match info.checksums(&record.name, &record.architecture, lang) {
        Ok(sums) => record.checksums = sums,
        Err(why) => record.checksum_error = Some(why),
    }
}

/// dpkg `status` — 설치된(`install ok installed`) 패키지만(스캐너의 `parseDPKG`).
pub(super) fn parse_dpkg(data: &[u8], lang: Lang) -> Res<Vec<Record>> {
    let bad = |ko: &'static str, en: &'static str| lang.t(ko, en).to_string();
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for lines in paragraphs(data, lang)? {
        let fields = dpkg_fields(&lines, lang)?;
        let field = |key: &str| fields.get(key.as_bytes()).copied().unwrap_or_default();
        if field("Package").is_empty() {
            return Err(bad(
                "dpkg 패키지 이름이 없습니다",
                "a dpkg package name is missing",
            ));
        }
        if field("Status") != b"install ok installed" {
            continue;
        }
        if field("Version").is_empty() {
            return Err(bad(
                "설치된 dpkg 패키지의 버전이 없습니다",
                "an installed dpkg package has no version",
            ));
        }
        let arch = names::from_bytes(field("Architecture"));
        if !arch.is_empty() && !valid_package_architecture(&arch) {
            return Err(bad(
                "dpkg 패키지 아키텍처 형식이 잘못됐습니다",
                "invalid dpkg package architecture",
            ));
        }
        let name = names::from_bytes(field("Package"));
        if !seen.insert(format!("{name}:{arch}")) {
            return Err(bad(
                "설치 상태의 dpkg 패키지가 겹칩니다",
                "an installed dpkg package appears twice",
            ));
        }
        out.push(Record {
            name,
            version: names::from_bytes(field("Version")),
            architecture: arch,
            trusted: official_maintainer(field("Maintainer")),
            ..Record::default()
        });
    }
    Ok(out)
}

/// 단락 하나의 필드 — 이어지는 줄(공백 · 탭으로 시작)은 건너뛴다. 값은 양 끝 공백을 걷는다.
fn dpkg_fields<'a>(lines: &[&'a [u8]], lang: Lang) -> Res<BTreeMap<&'a [u8], &'a [u8]>> {
    let mut fields = BTreeMap::new();
    for line in lines {
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            continue;
        }
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            return Err(lang
                .t("dpkg 필드 형식이 잘못됐습니다", "invalid dpkg field format")
                .to_string());
        };
        if fields
            .insert(&line[..colon], trim(&line[colon + 1..]))
            .is_some()
        {
            return Err(lang
                .t("dpkg 필드가 겹칩니다", "a dpkg field appears twice")
                .to_string());
        }
    }
    Ok(fields)
}

/// 공식 배포판의 관리자 주소로 끝나는가(대소문자 무시).
fn official_maintainer(maintainer: &[u8]) -> bool {
    let m = lower(maintainer);
    [
        "@lists.alioth.debian.org>",
        "@tracker.debian.org>",
        "@lists.debian.org>",
        "@lists.ubuntu.com>",
    ]
    .iter()
    .any(|suffix| m.ends_with(suffix))
}

/// 빈 줄로 나눈 단락들 — Go 의 `bufio.Scanner`(줄 끝의 CR 을 걷고, 줄이 1 MiB 를 넘으면 오류)와 같다.
fn paragraphs(data: &[u8], lang: Lang) -> Res<Vec<Vec<&[u8]>>> {
    let mut out = Vec::new();
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (line, next, ended) = match rest.iter().position(|&c| c == b'\n') {
            Some(i) => (&rest[..i], &rest[i + 1..], true),
            None => (rest, &[][..], false),
        };
        let token = line.len() + usize::from(ended);
        if token > MAX_LINE || (!ended && line.len() >= MAX_LINE) {
            return Err(lang
                .t(
                    "패키지 기록의 줄이 1 MiB 제한을 넘었습니다",
                    "a package record line exceeds the 1 MiB limit",
                )
                .to_string());
        }
        rest = next;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            if !lines.is_empty() {
                out.push(std::mem::take(&mut lines));
            }
            continue;
        }
        lines.push(line);
        if out.len() > MAX_PARAGRAPHS {
            return Err(lang
                .t(
                    "패키지 항목 개수 제한을 넘었습니다",
                    "the package entry count exceeds the limit",
                )
                .to_string());
        }
    }
    if !lines.is_empty() {
        out.push(lines);
    }
    Ok(out)
}

/// apk `installed` — 패키지마다 이름(`P`) · 버전(`V`) · 폴더(`F`) · 파일(`R`). apk 패키지는 믿지 않는다.
pub(super) fn parse_apk(data: &[u8], lang: Lang) -> Res<Vec<Record>> {
    let bad = |ko: &'static str, en: &'static str| lang.t(ko, en).to_string();
    let mut out = Vec::new();
    for lines in paragraphs(data, lang)? {
        let mut p = Record::default();
        let mut dir = String::new();
        let mut seen = [false; 2];
        for line in lines {
            if line.len() < 2 || line[1] != b':' {
                return Err(bad(
                    "apk 필드 형식이 잘못됐습니다",
                    "invalid apk field format",
                ));
            }
            let value = names::from_bytes(&line[2..]);
            match line[0] {
                b'P' | b'V' => {
                    let i = usize::from(line[0] == b'V');
                    if std::mem::replace(&mut seen[i], true) {
                        return Err(bad(
                            "apk 이름 또는 버전 필드가 겹칩니다",
                            "an apk name or version field appears twice",
                        ));
                    }
                    *if i == 0 { &mut p.name } else { &mut p.version } = value;
                }
                b'F' => dir = package_path(&value, lang)?,
                b'R' => p.files.push(apk_file(&dir, &value, lang)?),
                _ => {}
            }
        }
        if p.name.is_empty() || p.version.is_empty() {
            return Err(bad(
                "apk 패키지 이름 또는 버전이 없습니다",
                "an apk package name or version is missing",
            ));
        }
        out.push(p);
    }
    Ok(out)
}

fn apk_file(dir: &str, value: &str, lang: Lang) -> Res<String> {
    if matches!(value, "" | "." | "..") || value.contains(['/', '\\']) {
        return Err(lang
            .t("apk 파일 이름이 잘못됐습니다", "invalid apk file name")
            .to_string());
    }
    package_path(&slashpath::join(&[dir, value]), lang)
}

/// 패키지 기록의 경로 — 앞의 `/` 하나를 떼고 아카이브 경로 규칙으로 정리한다.
pub(super) fn package_path(name: &str, lang: Lang) -> Res<String> {
    archive_path(name.strip_prefix('/').unwrap_or(name), lang)
}

/// `var/lib/dpkg/info` 의 파일 목록 · 검증 기록(이름 → 항목들).
pub(super) struct DpkgInfo<'a> {
    lists: BTreeMap<String, Vec<&'a Entry>>,
    sums: BTreeMap<String, Vec<&'a Entry>>,
}

impl<'a> DpkgInfo<'a> {
    pub(super) fn index(fs: &'a RootFs) -> Self {
        let mut info = DpkgInfo {
            lists: BTreeMap::new(),
            sums: BTreeMap::new(),
        };
        let from = std::ops::Bound::Included(DPKG_INFO);
        for (name, e) in fs
            .entries
            .range::<str, _>((from, std::ops::Bound::Unbounded))
        {
            if !name.starts_with(DPKG_INFO) {
                break;
            }
            if e.special() {
                continue;
            }
            let base = slashpath::base(name);
            let (index, stem) = if let Some(stem) = base.strip_suffix(".list") {
                (&mut info.lists, stem)
            } else if let Some(stem) = base.strip_suffix(".md5sums") {
                (&mut info.sums, stem)
            } else {
                continue;
            };
            index.entry(stem.to_string()).or_default().push(e);
        }
        info
    }

    /// 아키텍처가 붙은 이름(`pkg:amd64`)이 있으면 그것, 없으면 이름만.
    fn of<'b>(
        index: &'b BTreeMap<String, Vec<&'a Entry>>,
        pkg: &str,
        arch: &str,
    ) -> &'b [&'a Entry] {
        if !arch.is_empty() {
            if let Some(entries) = index
                .get(&format!("{pkg}:{arch}"))
                .filter(|v| !v.is_empty())
            {
                return entries;
            }
        }
        index.get(pkg).map_or(&[], Vec::as_slice)
    }

    /// 패키지가 소유한 파일(스캐너의 `dpkgFiles`).
    pub(super) fn files(&self, pkg: &str, arch: &str, lang: Lang) -> Res<Vec<String>> {
        let entries = Self::of(&self.lists, pkg, arch);
        if entries.is_empty() {
            return Err(lang.pick(
                format!("패키지 {pkg} 의 파일 목록(.list)이 없습니다"),
                format!("package {pkg} has no file list (.list)"),
            ));
        }
        let mut files = Vec::new();
        for e in entries {
            if e.kind != TYPE_REG || e.truncated {
                return Err(lang.pick(
                    format!("패키지 {pkg} 의 파일 목록을 온전히 읽지 못했습니다"),
                    format!("the file list of package {pkg} could not be read whole"),
                ));
            }
            for line in e.data.split(|&c| c == b'\n') {
                let line = trim(line);
                if line.is_empty() {
                    continue;
                }
                let clean = package_path(&names::from_bytes(line), lang)?;
                if clean != "." {
                    files.push(clean);
                }
            }
        }
        Ok(files)
    }

    /// 파일 검증 기록(스캐너의 `dpkgChecksums`) — 기록이 없으면 `None`.
    pub(super) fn checksums(
        &self,
        pkg: &str,
        arch: &str,
        lang: Lang,
    ) -> Res<Option<BTreeMap<String, String>>> {
        let entries = Self::of(&self.sums, pkg, arch);
        if entries.is_empty() {
            return Ok(None);
        }
        let mut sums = BTreeMap::new();
        for e in entries {
            if e.kind != TYPE_REG || e.truncated {
                return Err(lang.pick(
                    format!("패키지 {pkg} 의 파일 검증 기록(.md5sums)을 온전히 읽지 못했습니다"),
                    format!(
                        "the checksum list (.md5sums) of package {pkg} could not be read whole"
                    ),
                ));
            }
            for line in e.data.split(|&c| c == b'\n') {
                if !trim(line).is_empty() {
                    md5sum_line(line, pkg, &mut sums, lang)?;
                }
            }
        }
        Ok(Some(sums))
    }
}

/// `<md5 32자>  <경로>` 한 줄.
fn md5sum_line(line: &[u8], pkg: &str, sums: &mut BTreeMap<String, String>, lang: Lang) -> Res<()> {
    let wrong = |ko: &str, en: &str| {
        lang.pick(
            format!("패키지 {pkg} 의 파일 검증 기록(.md5sums) {ko}"),
            format!("the checksum list (.md5sums) of package {pkg} {en}"),
        )
    };
    if line.len() < 35 || &line[32..34] != b"  " {
        return Err(wrong("형식이 잘못됐습니다", "is malformed"));
    }
    let hash = line[..32].to_ascii_lowercase();
    if !hash.iter().all(u8::is_ascii_hexdigit) {
        return Err(wrong("해시가 잘못됐습니다", "has an invalid digest"));
    }
    let hash = String::from_utf8_lossy(&hash).into_owned();
    let name = archive_path(&names::from_bytes(&line[34..]), lang)
        .ok()
        .filter(|n| n != ".")
        .ok_or_else(|| wrong("경로가 잘못됐습니다", "has an invalid path"))?;
    if sums.get(&name).is_some_and(|old| *old != hash) {
        return Err(lang.pick(
            format!("패키지 {pkg} 의 파일 검증 기록(.md5sums)이 서로 다릅니다: /{name}"),
            format!("the checksum lists (.md5sums) of package {pkg} disagree: /{name}"),
        ));
    }
    sums.insert(name, hash);
    Ok(())
}

/// 실행 파일이 패키지 기록과 같은가(스캐너의 `packageFileProblem`). 문제가 없으면 `None`.
pub(super) fn file_problem(p: &Record, name: &str, e: &Entry, lang: Lang) -> Option<String> {
    if p.rpm {
        return rpm_file_problem(p, name, e, lang);
    }
    if p.source != DPKG_SOURCE {
        return None;
    }
    if let Some(why) = &p.checksum_error {
        return Some(why.clone());
    }
    let Some(sums) = &p.checksums else {
        return Some(lang.pick(
            format!("패키지 {} 의 파일 검증 기록(.md5sums)이 없습니다", p.name),
            format!("package {} has no checksum list (.md5sums)", p.name),
        ));
    };
    match sums.get(name).filter(|s| !s.is_empty()) {
        None => Some(lang.pick(
            format!("패키지 파일 검증 기록(.md5sums)에 실행 파일 경로가 없습니다: /{name}"),
            format!("the checksum list (.md5sums) has no entry for the executable: /{name}"),
        )),
        Some(sum) if e.md5.is_empty() || *sum != e.md5 => Some(lang.pick(
            format!(
                "패키지 파일 검증 기록(.md5sums)과 실제 파일 내용이 일치하지 않습니다: /{name}"
            ),
            format!("the file content does not match the checksum list (.md5sums): /{name}"),
        )),
        Some(_) => None,
    }
}

fn rpm_file_problem(p: &Record, name: &str, e: &Entry, lang: Lang) -> Option<String> {
    let actual = if p.checksum_algorithm == "sha256" {
        &e.sha256
    } else {
        &e.md5
    };
    if let Some(why) = &p.checksum_error {
        return Some(why.clone());
    }
    let Some(sums) = &p.checksums else {
        return Some(lang.pick(
            format!("RPM 패키지 파일 체크섬 기록이 없습니다: {}", p.name),
            format!("the RPM package has no file checksums: {}", p.name),
        ));
    };
    match sums.get(name).filter(|s| !s.is_empty()) {
        None => Some(lang.pick(
            format!("RPM 체크섬 기록에 실행 파일 경로가 없습니다: /{name}"),
            format!("the RPM checksums have no entry for the executable: /{name}"),
        )),
        Some(sum) if actual.is_empty() || !sum.eq_ignore_ascii_case(actual) => Some(lang.pick(
            format!("RPM 파일 체크섬 기록과 실제 파일 내용이 일치하지 않습니다: /{name}"),
            format!("the file content does not match the RPM checksum: /{name}"),
        )),
        Some(_) => None,
    }
}
