//! 이미지 안의 RPM DB — 믿지 못할 입력을 읽는 입구(`remedy_rpmdb::read_untrusted`)로 읽고 스캐너의 패키지 기록
//! 꼴로 옮긴다(스캐너의 `rpm.go` 가운데 헤더를 패키지로 옮기는 부분).
//!
//! - 버전은 `[epoch:]판-개정` 이다(epoch 0 은 적지 않는다). 공급사와 아키텍처가 다 있으면 믿을 수 있다.
//! - 경로는 스캐너의 패키지 경로 규칙으로 정리한다. 뿌리(`/`)는 파일이 아니다. 정리하지 못하는 경로가 하나라도
//!   있으면 DB 전체를 읽지 못한 것이다(스캐너와 같다). 이름이 `.` 인 파일도 그렇다 — 스캐너는 나눠 적은 꼴의 그
//!   이름을 거절한다.
//! - 다이제스트 문제는 그 패키지의 체크섬 오류로만 남는다. 같은 경로에 서로 다른 다이제스트가 있어도 그렇다.
//! - 한도(복사한 블롭의 합 · 헤더에서 꺼낸 정보)에 닿으면 그 앞의 패키지는 쓰고 *보지 못한 것* 을 남긴다.
//!
//! 헤더로 읽히지 않는 블롭(이름 · 판 · 개정이 없거나 틀이 깨진 것)이 있으면 DB 전체를 읽지 못한 것이다. BDB 만 하나를
//! 받는다 — rpm 이 다음 헤더 번호를 기록 하나로 함께 둔다(스캐너의 `bdbRecords` 는 그 번호의 키 0 을 건너뛰었다.
//! 판독기는 어느 블롭이 그것인지 말하지 않아 수로 본다).

use super::packages::{package_path, Record};
use super::Cx;
use remedy_rpmdb::{detect, read_untrusted, DigestAlgorithm, Format, Package, RpmDbError};
use remedy_sdk::i18n::Lang;
use std::collections::BTreeMap;

type Res<T> = Result<T, String>;

/// DB 하나 — 패키지와, 한도에 닿아 앞부분만 읽었으면 그 까닭.
pub(super) fn parse(data: &[u8], cx: &Cx<'_>) -> Res<(Vec<Record>, Option<String>)> {
    let lang = cx.lang;
    cx.budget.check().map_err(|h| h.message(lang))?;
    let read = read_untrusted(data).map_err(|e| why(&e, lang))?;
    let allowed = usize::from(detect(data) == Some(Format::Bdb));
    if read.skipped > allowed {
        return Err(lang
            .t(
                "RPM DB 에 패키지 헤더로 읽히지 않는 기록이 있습니다",
                "the RPM database has a record that does not read as a package header",
            )
            .to_string());
    }
    let mut out = Vec::with_capacity(read.packages.len());
    for p in &read.packages {
        out.push(record(p, lang)?);
    }
    Ok((out, read.limit.map(|e| why(&e, lang))))
}

fn record(p: &Package, lang: Lang) -> Res<Record> {
    let h = &p.header;
    let mut version = format!("{}-{}", h.version, h.release);
    if let Some(epoch) = h.epoch.filter(|e| *e > 0) {
        version = format!("{epoch}:{version}");
    }
    let mut paths = Vec::with_capacity(p.files.len());
    let mut files = Vec::with_capacity(p.files.len());
    for raw in &p.files {
        if raw == "/" {
            paths.push(String::new());
            continue;
        }
        if raw.ends_with("/.") {
            return Err(lang
                .t(
                    "RPM 파일 경로가 잘못됐습니다",
                    "an RPM file path is invalid",
                )
                .to_string());
        }
        let clean = package_path(raw, lang)?;
        files.push(clean.clone());
        paths.push(clean);
    }
    let mut r = Record {
        name: h.name.clone(),
        version,
        architecture: h.arch.clone(),
        vendor: h.vendor.clone(),
        module: p.modularity_label.clone().unwrap_or_default(),
        files,
        trusted: !h.vendor.is_empty() && !h.arch.is_empty(),
        rpm: true,
        ..Record::default()
    };
    match &p.digests {
        Ok(d) => attach(&mut r, &paths, &d.digests, d.algorithm, lang),
        Err(e) => r.checksum_error = Some(digest_error(e, lang)),
    }
    Ok(r)
}

/// 경로 → 다이제스트(스캐너의 `FileChecksums`). 빈 다이제스트와 뿌리는 건너뛴다.
fn attach(r: &mut Record, paths: &[String], digests: &[String], algo: DigestAlgorithm, lang: Lang) {
    r.checksum_algorithm = match algo {
        DigestAlgorithm::Md5 => "md5",
        DigestAlgorithm::Sha256 => "sha256",
    };
    let mut sums = BTreeMap::new();
    for (path, digest) in paths.iter().zip(digests) {
        if path.is_empty() || digest.is_empty() {
            continue;
        }
        if sums.get(path).is_some_and(|old| old != digest) {
            r.checksum_error = Some(
                lang.t(
                    "같은 RPM 파일의 체크섬 기록이 서로 다릅니다",
                    "the RPM checksum records of one file disagree",
                )
                .to_string(),
            );
            return;
        }
        sums.insert(path.clone(), digest.clone());
    }
    r.checksums = Some(sums);
}

/// 다이제스트를 읽지 못한 까닭 — 판독기의 낱말을 스캐너의 문장으로.
fn digest_error(e: &RpmDbError, lang: Lang) -> String {
    let text = match e {
        RpmDbError::Format(t) | RpmDbError::Limit(t) => *t,
    };
    let (ko, en) = if text.contains("알고리즘이다") {
        (
            "지원하지 않는 RPM 파일 체크섬 알고리즘입니다",
            "unsupported RPM file checksum algorithm",
        )
    } else if text.contains("하나가 아니다") || text.contains("형이 다르다") {
        (
            "RPM 파일 체크섬 알고리즘 기록이 잘못됐습니다",
            "invalid RPM file checksum algorithm record",
        )
    } else if text.contains("수가 다르다") {
        (
            "RPM 파일 경로와 체크섬 기록의 개수가 다릅니다",
            "the RPM file paths and checksum records differ in count",
        )
    } else if text.contains("16진") {
        (
            "RPM 파일 체크섬의 길이 또는 형식이 잘못됐습니다",
            "an RPM file checksum has a wrong length or format",
        )
    } else {
        (
            "RPM 파일 체크섬 기록을 확인하지 못했습니다",
            "the RPM file checksum records could not be confirmed",
        )
    };
    lang.t(ko, en).to_string()
}

/// DB 를 읽지 못한 · 다 읽지 못한 까닭.
fn why(e: &RpmDbError, lang: Lang) -> String {
    let (ko, en) = match e {
        RpmDbError::Format(_) => (
            "RPM DB 형식이 올바르지 않습니다",
            "the RPM database is malformed",
        ),
        RpmDbError::Limit(t) if t.contains("파일이 상한") => (
            "RPM DB 크기 제한(64 MiB)을 넘었습니다",
            "the RPM database exceeds the 64 MiB size limit",
        ),
        RpmDbError::Limit(t) if t.contains("복사한") => (
            "RPM DB 에서 복사한 기록의 합계가 제한(64 MiB)에 닿았습니다",
            "the records copied from the RPM database reached the 64 MiB limit",
        ),
        RpmDbError::Limit(t) if t.contains("꺼낸 정보") => (
            "RPM 헤더에서 꺼낸 정보가 제한(16 MiB · 100,000 항목)에 닿았습니다",
            "the data taken from RPM headers reached the limit (16 MiB · 100,000 items)",
        ),
        RpmDbError::Limit(t) if t.contains("하나가") => (
            "RPM DB 기록 하나가 16 MiB 제한을 넘었습니다",
            "an RPM database record exceeds the 16 MiB limit",
        ),
        RpmDbError::Limit(_) => (
            "RPM DB 가 판독 제한(기록 · 항목 수)을 넘었습니다",
            "the RPM database exceeds a reading limit (records or items)",
        ),
    };
    lang.t(ko, en).to_string()
}
