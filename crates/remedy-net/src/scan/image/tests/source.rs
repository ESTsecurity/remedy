//! 스캐너 `source_test.go` · `source_unix_test.go` · `source_windows_test.go` — 입력 경로 · 항목 · 링크 · 캐시 ·
//! 중간 결과.
//!
//! 링크를 만들 수 없는 기계(Windows 의 심볼릭 링크 권한 · junction)에서는 그 시험을 건너뛰고 까닭을 적는다.

use super::fixtures::*;
use crate::scan::budget::{Budget, Cancel};
use crate::scan::image::source::Source;
use crate::scan::image::{docker, oci, scan, Cx, Request};
use crate::scan::model::{Product, Status, TargetKind};
use remedy_sdk::i18n::Lang;
use serde_json::json;
use std::path::Path;
use Packing::Raw;
use Status::{Clear, ReviewRequired as Review, Vulnerable};

fn text(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn open<'b>(input: &str, work: &Path, b: &'b Budget) -> Result<Source<'b>, String> {
    Source::open(input, work, b, Lang::Ko)
}

fn empty(dir: &Path) -> bool {
    std::fs::read_dir(dir).unwrap().next().is_none()
}

/// `TestSourceRejectsInvalidPathsBeforeReadingOrCreating`
#[test]
fn source_rejects_invalid_paths_before_reading_or_creating() {
    let dir = scratch();
    write(dir.path(), "image.tar", &tar(&[]));
    let input = text(&dir.join("image.tar"));
    let work = scratch();
    let missing = text(&dir.join("missing"));
    let work_text = text(work.path());
    let cases = [
        ("missing-input", missing.as_str(), work_text.as_str()),
        (
            "network-input",
            r"\\invalid.invalid\share\image.tar",
            work_text.as_str(),
        ),
        (
            "device-input",
            r"\\.\pipe\php-image-test",
            work_text.as_str(),
        ),
        ("empty-input", "", work_text.as_str()),
        ("missing-work", input.as_str(), missing.as_str()),
        ("file-work", input.as_str(), input.as_str()),
        (
            "network-work",
            input.as_str(),
            r"\\invalid.invalid\share\work",
        ),
        ("empty-work", input.as_str(), ""),
    ];
    for (name, input, work_dir) in cases {
        let b = budget();
        assert!(
            open(input, Path::new(work_dir), &b).is_err(),
            "{name}: 안전하지 않은 경로를 받았다"
        );
        let u = b.usage();
        assert_eq!(
            (u.image_input_bytes, u.image_expanded_bytes),
            (0, 0),
            "{name}: 확인 전에 읽었다"
        );
        assert!(
            std::fs::symlink_metadata(&missing).is_err(),
            "{name}: 없는 경로를 만들었다"
        );
        assert!(empty(work.path()), "{name}: 실패한 입력의 캐시가 남았다");
    }
}

/// `TestSourceMemberRejectsNonFilesAndEscapingPaths`
#[test]
fn source_member_rejects_non_files_and_escaping_paths() {
    let dir = scratch();
    write(dir.path(), "normal", b"verified");
    std::fs::create_dir(dir.join("directory")).unwrap();
    let b = budget();
    let s = open(&text(dir.path()), Path::new(""), &b).unwrap();
    for name in [
        "directory",
        "normal/child",
        "../escape",
        "/absolute",
        "C:/escape",
        r"normal\child",
        ".",
    ] {
        let before = b.usage().image_input_bytes;
        assert!(s.open_member(name).is_err(), "{name}: 받았다");
        assert_eq!(
            b.usage().image_input_bytes,
            before,
            "{name}: 거절한 항목을 읽었다"
        );
    }
    assert_eq!(s.read("normal", 1024).unwrap(), b"verified");
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path, _dir: bool) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink(target: &Path, link: &Path, dir: bool) -> std::io::Result<()> {
    if dir {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

/// 이 입력 · 작업 폴더를 거절하고 아무것도 읽지 않는다.
fn refused(name: &str, input: &Path, work: &Path) {
    let b = budget();
    assert!(
        open(&text(input), work, &b).is_err(),
        "{name}: 링크를 거쳐 받았다"
    );
    assert_eq!(b.usage().image_input_bytes, 0, "{name}");
}

/// `TestSourceRejectsSymbolicLinks`
#[test]
fn source_rejects_symbolic_links() {
    let base = scratch();
    let target = base.join("actual");
    write(&target, "image.tar", &tar(&[]));
    let link = base.join("link");
    if let Err(e) = symlink(&target, &link, true) {
        println!("건너뜀: 시험용 폴더 심볼릭 링크를 만들 수 없다: {e}");
        return;
    }
    let work = scratch();
    refused("input-root", &link, work.path());
    refused("input-ancestor", &link.join("image.tar"), work.path());
    refused("work-root", &target.join("image.tar"), &link);
    let file_link = base.join("file-link");
    symlink(&target.join("image.tar"), &file_link, false).unwrap();
    refused("file-link", &file_link, work.path());
    let b = budget();
    let s = open(&text(base.path()), Path::new(""), &b).unwrap();
    for name in ["file-link", "link/image.tar"] {
        assert!(
            s.open_member(name).is_err(),
            "OCI 항목의 링크를 받았다: {name}"
        );
    }
    assert!(empty(work.path()));
}

/// `TestSourceRejectsDirectoryReplacement` — Windows 는 쥔 폴더를 옮기지 못하게 하므로 건너뛴다(스캐너와 같다).
#[test]
fn source_rejects_directory_replacement() {
    let base = scratch();
    let input = base.join("layout");
    write(&input, "member", b"original");
    let b = budget();
    let s = open(&text(&input), Path::new(""), &b).unwrap();
    if let Err(e) = std::fs::rename(&input, base.join("retained")) {
        println!("건너뜀: 운영체제가 열린 폴더의 교체를 거부했다: {e}");
        return;
    }
    write(&input, "member", b"replacement");
    assert!(
        s.open_member("member").is_err(),
        "쥔 OCI 뿌리와 다른 파일을 열었다"
    );
    assert_eq!(b.usage().image_input_bytes, 0, "바뀐 경로에서 읽었다");
}

/// `TestArchiveCacheRereadsCountTowardInputBudget`
#[test]
fn archive_cache_rereads_count_toward_input_budget() {
    let dir = scratch();
    let data = b"synthetic metadata";
    let archive = tar(&[reg("metadata", data)]);
    write(dir.path(), "image.tar", &archive);
    let (b, work) = (budget(), scratch());
    let s = open(&text(&dir.join("image.tar")), work.path(), &b).unwrap();
    for i in 1..=2 {
        assert_eq!(s.read("metadata", 1024).unwrap(), data);
        let want = (archive.len() + i * data.len()) as u64;
        assert_eq!(
            b.usage().image_input_bytes,
            want,
            "다시 읽은 양을 세지 않았다"
        );
    }
    drop(s);
    assert!(empty(work.path()), "캐시 폴더가 남았다");
}

/// docker save 꼴 폴더 — 설정 · 레이어 · manifest.json.
fn docker_dir(layer: &[u8]) -> Scratch {
    let dir = scratch();
    let cfg = bytes(
        &json!({"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": [sha(layer)]}}),
    );
    let name = format!("{}.json", &sha(&cfg)[7..]);
    write(dir.path(), &name, &cfg);
    write(dir.path(), "layer.tar", layer);
    let manifest =
        json!([{"Config": name, "Layers": ["layer.tar"], "RepoTags": ["synthetic:vulnerable"]}]);
    write(dir.path(), "manifest.json", &bytes(&manifest));
    dir
}

/// `TestImageSnapshotRetainsCompletedVulnerabilityAfterCancellation`
#[test]
fn image_snapshot_retains_completed_vulnerability_after_cancellation() {
    for format in ["oci", "docker"] {
        let layer = tar(&php_entries(BEFORE));
        let input = if format == "oci" {
            oci(&[layer], Raw, &[]).0
        } else {
            docker_dir(&layer)
        };
        let cancel = Cancel::default();
        let b = Budget::new(TargetKind::Image, cancel.clone(), Lang::Ko);
        let rules = php_rules();
        let cx = Cx {
            budget: &b,
            rules: &rules,
            lang: Lang::Ko,
            products: &[Product::Php],
        };
        let name = text(input.path());
        let src = open(&name, Path::new(""), &b).unwrap();
        let targets = if format == "oci" {
            oci::scan(&src, &name, &cx)
        } else {
            docker::scan(&src, &name, &cx)
        };
        drop(src);
        single(&targets, Vulnerable);
        // 형식 판독기를 바로 불러, 바깥 점검이 끝나기 전에 그 근거가 남는지 본다.
        let partial = b.partial_targets("다음 이미지 점검이 중단됐습니다");
        single(&partial, Vulnerable);
        assert_eq!(runtime(&partial[0]).len(), 1, "{format}");
        assert_eq!(
            partial[0].metadata.get("platform").map(String::as_str),
            Some("linux/amd64")
        );
        cancel.set();
        let second = vec![text(&input.join("next-image"))];
        let req = Request {
            inputs: &second,
            work_dir: Path::new(""),
            products: &[Product::Php],
            rules: &rules,
            lang: Lang::Ko,
        };
        single(&scan(&req, &b, &mut |_| {}), Review);
        let partial = b.partial_targets("점검이 중단됐습니다");
        let statuses: Vec<Status> = partial.iter().map(|t| t.status).collect();
        assert_eq!(
            statuses,
            [Vulnerable, Review],
            "{format}: 앞선 취약 결과가 사라졌다"
        );
    }
}

/// `TestImageSnapshotDoesNotRetainDiscardedLowerFindings`
#[test]
fn image_snapshot_does_not_retain_discarded_lower_findings() {
    for upper in ["overwritten", "deleted", "corrupt"] {
        let lower = tar(&php_entries(BEFORE));
        let entries = if upper == "deleted" {
            vec![
                reg("usr/bin/.wh.php8.3", ""),
                reg("var/lib/dpkg/status", ""),
            ]
        } else {
            php_entries(FIXED)
        };
        let (dir, layers) = oci(&[lower, tar(&entries)], Raw, &[]);
        if upper == "corrupt" {
            std::fs::write(
                blob_path(dir.path(), layers[1]["digest"].as_str().unwrap()),
                b"corrupt",
            )
            .unwrap();
        }
        let b = budget();
        let targets = run_with(dir.path(), &[Product::Php], &php_rules(), &b);
        single(&targets, if upper == "deleted" { Clear } else { Review });
        let partial = b.partial_targets("다른 이미지 점검이 중단됐습니다");
        single(&partial, Review);
        if upper != "overwritten" {
            assert!(
                runtime(&partial[0]).is_empty(),
                "{upper}: 아래 레이어의 PHP 가 남았다"
            );
        }
        assert!(
            partial[0].findings.iter().all(|f| f.status != Vulnerable),
            "{upper}: 최종 이미지에 없는 취약 근거를 남겼다"
        );
    }
}

/// `TestSourceRejectsFIFOBeforeOpening` — FIFO 를 열다 멈추지 않는다. `mkfifo` 명령으로 짓는다.
#[cfg(unix)]
#[test]
fn source_rejects_fifo_before_opening() {
    use std::sync::mpsc;
    use std::time::Duration;
    let dir = scratch();
    let fifo = dir.join("fifo");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    if !made.is_ok_and(|s| s.success()) {
        println!("건너뜀: mkfifo 로 시험용 FIFO 를 만들 수 없다");
        return;
    }
    let b = budget();
    let s = open(&text(dir.path()), Path::new(""), &b).unwrap();
    for name in ["input", "member"] {
        let (tx, rx) = mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let refused = if name == "input" {
                    open(&text(&fifo), dir.path(), &b).is_err()
                } else {
                    s.open_member("fifo").is_err()
                };
                let _ = tx.send(refused);
            });
            let got = rx.recv_timeout(Duration::from_secs(1));
            if got.is_err() {
                // 멈춘 열기를 풀어 주고 실패한다 — 읽기 · 쓰기로 열면 FIFO 가 기다리지 않는다.
                let _ = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&fifo);
            }
            assert_eq!(got, Ok(true), "{name}: FIFO 를 열기 전에 거절하지 않았다");
        });
        assert_eq!(b.usage().image_input_bytes, 0, "{name}: 특수 파일을 읽었다");
    }
}

/// `cmd /C mklink /J` 로 junction 을 만든다 — 권한 없이 된다.
#[cfg(windows)]
fn junction(link: &Path, target: &Path) -> bool {
    std::process::Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `TestSourceRejectsWindowsJunctions`
#[cfg(windows)]
#[test]
fn source_rejects_windows_junctions() {
    let base = scratch();
    let target = base.join("actual");
    write(&target, "image.tar", &tar(&[]));
    let link = base.join("junction");
    if !junction(&link, &target) {
        println!("건너뜀: 시험용 junction 을 만들 수 없다");
        return;
    }
    let work = scratch();
    refused("input-root", &link, work.path());
    refused("input-ancestor", &link.join("image.tar"), work.path());
    refused("work-root", &target.join("image.tar"), &link);
    refused(
        "work-ancestor",
        &target.join("image.tar"),
        &link.join("must-not-exist"),
    );
    let b = budget();
    let s = open(&text(base.path()), Path::new(""), &b).unwrap();
    assert!(
        s.open_member("junction/image.tar").is_err(),
        "OCI 항목의 junction 을 받았다"
    );
    assert_eq!(b.usage().image_input_bytes, 0);
    drop(s);
    let names: Vec<String> = std::fs::read_dir(&target)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["image.tar"], "junction 대상에 캐시를 만들었다");
}
