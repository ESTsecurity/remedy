//! 설치된 패키지 (C-2 · 설계-09 P12 후속).
//!
//! # 매니저를 부르지 않는다
//!
//! `dpkg-query` 나 `apk info` 를 부르면 **수집 중 자식 프로세스 0** 이 깨진다.
//! 그 성질은 고객에게 나간 말이고(사고-대응 문서 §7 *"지금 그대로 되는 것"*),
//! 수집·판정·계획 코드에 실행이 한 곳도 없다는 사실이 그것을 받친다. 그래서
//! **DB 를 파일로 직접 읽는다** — dpkg 와 apk 는 둘 다 텍스트다(실측).
//!
//! | 매니저 | 자리 | 모양 | 실측 (컨테이너) |
//! |---|---|---|---|
//! | dpkg | `/var/lib/dpkg/status` | RFC822 — 빈 줄로 끊고 이어지는 줄은 공백으로 시작 | debian:12 에 88개 · 77 KB |
//! | apk | `/lib/apk/db/installed` | `글자:값` 줄, 빈 줄로 끊음 | alpine:3.21 에 15개 · 15 KB |
//!
//! **`rpm` 은 여기 없다.** 그쪽 DB 는 sqlite(또는 BDB)라 파서가 따로 필요하고,
//! 그것은 별 회차다 — `manager` 의 닫힌 값에 `rpm` 을 미리 적지 않은 이유도
//! 같다(적어 두면 RHEL 계열에서 `manager equals 'rpm'` 이 조용히 0건이 된다).

use remedy_artifacts::{CollectError, Harvest, PackageRecord, Scope};
use remedy_platform::read::FsRead;
use remedy_sdk::catalog::{is_version, Platform};
use remedy_sdk::normalize;

/// dpkg 의 DB. 한 파일이다.
const DPKG_STATUS: &str = "/var/lib/dpkg/status";
/// apk 의 DB. 한 파일이다.
const APK_INSTALLED: &str = "/lib/apk/db/installed";

/// DB 하나를 읽는 상한.
///
/// 설정 파일의 4 MiB 와 따로 둔다 — 이쪽은 **패키지 수에 비례**하고, 실측
/// (debian:12 88개 = 77 KB)에서 패키지당 약 900바이트다. 32 MiB 는 패키지
/// 3만 개를 담는 크기이고, 가장 큰 배포판 설치본도 그 아래다.
const MAX_DB_BYTES: u64 = 32 * 1024 * 1024;

/// 설치된 패키지.
///
/// **Linux 뿐이다.** 카탈로그가 `windows: false` 로 적어 두었고
/// `scope_from_manifest` 가 Windows 범위에서 이 subject 를 빼며 그 사실을
/// `notes` 로 남긴다 — 여기까지 오는 길이 없다. 그래도 플랫폼을 보는 이유는
/// 그 관문이 새면 **엉뚱한 경로를 열어 0건을 내는 쪽이 아니라** 아무 것도 하지
/// 않는 쪽이 되게 하려는 것이다.
pub fn packages<P: FsRead>(fs: &P, scope: &Scope) -> Result<Harvest<PackageRecord>, CollectError> {
    let mut h = Harvest::default();
    if scope.platform != Platform::Linux {
        return Ok(h);
    }
    for (path, manager, parse) in [
        (
            DPKG_STATUS,
            "dpkg",
            parse_dpkg as fn(&str, &str) -> Vec<PackageRecord>,
        ),
        (APK_INSTALLED, "apk", parse_apk),
    ] {
        // **없는 것과 못 읽은 것을 가른다.** apk 가 없는 데비안 기계에
        // `/lib/apk/db/installed` 가 없는 것은 정상이다.
        if !fs.exists(path) {
            continue;
        }
        match fs.read_file(path, MAX_DB_BYTES) {
            Ok(Some(bytes)) => h.records.extend(parse(&to_text(&bytes), manager)),
            // 상한을 넘었다. 한 건도 담지 못했으므로 **잘렸다고 말한다** —
            // 조용히 넘기면 그 기계는 "패키지가 없다" 가 된다.
            Ok(None) => h.truncated = true,
            // root 로 도는데 열리지 않았다. 없는 것이 아니다.
            Err(_) => h.deny(path),
        }
    }
    // **정렬한다.** 두 DB 를 이어 담으므로 순서가 매니저에 따라 갈리고,
    // 같은 기계를 두 번 수집한 스냅샷이 달라진다.
    h.records
        .sort_by(|a, b| (&a.manager, &a.name, &a.arch).cmp(&(&b.manager, &b.name, &b.arch)));
    h.records
        .dedup_by(|a, b| (&a.manager, &a.name, &a.arch) == (&b.manager, &b.name, &b.arch));
    Ok(h)
}

/// UTF-8 이 아니면 드러나야 하므로 lossy 로 읽는다. 패키지 설명에 비 ASCII
/// 가 흔하고, 거기서 멈추면 그 기계의 패키지가 통째로 사라진다.
fn to_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// dpkg 의 `status`. RFC822 레코드를 빈 줄로 끊는다.
///
/// 이어지는 줄(공백으로 시작)은 **건너뛴다.** 여기서 쓰는 필드는 전부 한 줄
/// 짜리이고, `Description` 처럼 여러 줄인 것은 담지 않는다.
fn parse_dpkg(text: &str, manager: &str) -> Vec<PackageRecord> {
    let mut out = Vec::new();
    for rec in text.split("\n\n") {
        let mut name = "";
        let mut version = "";
        let mut arch = "";
        let mut source = "";
        let mut status = "";
        for line in rec.lines() {
            if line.starts_with([' ', '\t']) {
                continue;
            }
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let v = v.trim();
            match k {
                "Package" => name = v,
                "Version" => version = v,
                "Architecture" => arch = v,
                // `Source: php8.2 (8.2.29-1)` 처럼 판이 괄호로 붙는다.
                "Source" => source = v.split_whitespace().next().unwrap_or(v),
                "Status" => status = v,
                _ => {}
            }
        }
        if name.is_empty() || !dpkg_is_installed(status) {
            continue;
        }
        out.push(record(name, version, arch, source, manager));
    }
    out
}

/// 이 레코드가 **디스크에 있는** 패키지인가.
///
/// `Status` 는 `<원함> <오류> <상태>` 셋이고 마지막 칸이 그것을 말한다(실측:
/// 컨테이너 둘 다 `install ok installed` 하나뿐이었다).
///
/// `config-files`(purge 대기)를 받으면 **지운 패키지가 "취약한 판이 깔려 있다"
/// 로 읽힌다** — 그 판 번호는 디스크에 있는 것을 설명하지 않는다. 반대로
/// `triggers-*` 는 설치가 끝난 뒤 트리거만 남은 상태라, 빼면 apt 가 도는 중인
/// 기계에서 **조용한 미탐**이 된다.
fn dpkg_is_installed(status: &str) -> bool {
    let Some(state) = status.split_whitespace().next_back() else {
        return false;
    };
    state == "installed" || state.starts_with("triggers-")
}

/// apk 의 `installed`. `글자:값` 줄을 빈 줄로 끊는다.
///
/// 레코드의 **대부분이 파일 목록**이다(`F:`·`R:`·`Z:`·`M:`·`a:`) — 실측에서
/// 패키지 하나가 100줄을 넘었다. 쓰는 것은 머리의 몇 줄뿐이므로 나머지는
/// 이름으로 걸러 버린다.
fn parse_apk(text: &str, manager: &str) -> Vec<PackageRecord> {
    let mut out = Vec::new();
    for rec in text.split("\n\n") {
        let mut name = "";
        let mut version = "";
        let mut arch = "";
        let mut origin = "";
        for line in rec.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            match k {
                "P" => name = v.trim(),
                "V" => version = v.trim(),
                "A" => arch = v.trim(),
                "o" => origin = v.trim(),
                _ => {}
            }
        }
        if name.is_empty() {
            continue;
        }
        // **apk 의 DB 에는 설치된 것만 있다.** dpkg 의 `config-files` 에 해당하는
        // 상태가 없으므로 가릴 것도 없다.
        out.push(record(name, version, arch, origin, manager));
    }
    out
}

/// 레코드 하나. 판 문자열을 셋으로 가른다.
fn record(name: &str, version: &str, arch: &str, source: &str, manager: &str) -> PackageRecord {
    let (upstream, revision) = split_version(version);
    PackageRecord {
        name: normalize::nfc(name),
        version: version.to_string(),
        upstream_version: upstream,
        revision,
        arch: arch.to_string(),
        // 같으면 적지 않는다 — `source` 의 뜻은 *"이름과 다른 원본"* 이고,
        // apk 는 그 자리에 제 이름을 그대로 적는다(`o:alpine-baselayout`).
        source: if source == name {
            String::new()
        } else {
            normalize::nfc(source)
        },
        manager: manager.to_string(),
    }
}

/// `1:2.38.1-5+deb12u3` → `("2.38.1", "5+deb12u3")`.
///
/// # 순서가 정해져 있다
///
/// 1. **epoch** — 앞의 `숫자:` 를 뗀다. 거의 없고, 있으면 그것이 가장 센
///    성분이지만 취약 판정에 쓰이는 자리가 아니다(원문은 `version` 에 남는다).
/// 2. **개정** — **마지막** `-` 뒤다(Debian 정책). `-` 가 없으면 개정이 없다.
/// 3. **상류 판** — 남은 것의 **앞쪽 점숫자만**. `12.4+deb12u15` → `12.4`,
///    `3.118ubuntu5` → `3.118`, `8.2.29~rc1` → `8.2.29`.
///
/// 3번이 `is_version` 을 통과하지 못하면 **빈 문자열이다.** 지어내지 않는다 —
/// 통과하는 모양만 담아야 `version_lt` 가 *"재지 못했다"* 로 빠지지 않는다.
///
/// `is_version` 은 **remedy-sdk 의 것을 쓴다.** 수집기가 제 판단을 따로 들면
/// 담은 값이 평가기가 받는 모양과 갈라진다.
fn split_version(version: &str) -> (String, String) {
    let v = version.trim();
    // 1. epoch
    let without_epoch = match v.split_once(':') {
        Some((e, rest)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => rest,
        _ => v,
    };
    // 2. 개정
    let (upstream_part, revision) = match without_epoch.rsplit_once('-') {
        Some((u, r)) => (u, r),
        None => (without_epoch, ""),
    };
    // 3. 앞쪽 점숫자
    let head: String = upstream_part
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let head = head.trim_end_matches('.');
    let upstream = if is_version(head) {
        head.to_string()
    } else {
        String::new()
    };
    (upstream, revision.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_platform::read::{FsEntry, Seen, WalkResult};
    use remedy_platform::PlatformError;
    use std::collections::BTreeMap;

    /// 실측한 `/var/lib/dpkg/status` 의 모양이다 (debian:12 · 2026-10-27).
    /// 이어지는 줄과 여러 줄 필드가 **실제로 섞여 있다.**
    const DPKG: &str = "\
Package: adduser
Status: install ok installed
Architecture: all
Version: 3.134
Conffiles:
 /etc/adduser.conf cc3493ecd2d09837ffdcc3e25fdfff18
Description: add and remove users and groups
 This package includes the 'adduser' command.
 .
 Package: not-a-package-this-is-prose

Package: libmount1
Status: install ok installed
Architecture: amd64
Source: util-linux
Version: 1:2.38.1-5+deb12u3

Package: php8.2-cli
Status: install ok installed
Architecture: amd64
Source: php8.2 (8.2.29-1)
Version: 8.2.7-1ubuntu2.4

Package: purged-thing
Status: deinstall ok config-files
Architecture: amd64
Version: 9.9.9

Package: mid-apt
Status: install ok triggers-pending
Architecture: amd64
Version: 1.2.3-4
";

    /// 실측한 `/lib/apk/db/installed` 의 모양이다 (alpine:3.21 · 2026-10-27).
    /// 파일 목록이 레코드의 대부분이다.
    const APK: &str = "\
C:Q17OteNVXn9/iSXcJI1Vf8x0TVc9Y=
P:alpine-baselayout
V:3.6.8-r1
A:x86_64
o:alpine-baselayout
F:etc
R:motd
Z:Q1SLkS9hBidUbPwwrw+XR0Whv3ww8=
F:etc/crontabs
a:0:0:600

P:php82
V:8.2.29-r0
A:x86_64
o:php82
F:usr/bin
R:php82
";

    #[test]
    fn a_dpkg_record_yields_name_version_and_arch() {
        let got = parse_dpkg(DPKG, "dpkg");
        let names: Vec<&str> = got.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["adduser", "libmount1", "php8.2-cli", "mid-apt"],
            "{got:#?}"
        );
        assert_eq!(got[0].version, "3.134");
        assert_eq!(got[0].arch, "all");
    }

    #[test]
    fn a_purged_package_is_not_an_installed_package() {
        // 그 판 번호는 디스크에 있는 것을 설명하지 않는다. 담으면 **지운
        // 패키지가 "취약한 판이 깔려 있다" 로 읽힌다.**
        assert!(
            !parse_dpkg(DPKG, "dpkg")
                .iter()
                .any(|r| r.name == "purged-thing"),
            "purge 대기 패키지를 설치된 것으로 담았다"
        );
    }

    #[test]
    fn a_package_waiting_on_triggers_is_still_installed() {
        // 빼면 apt 가 도는 중인 기계에서 **조용한 미탐**이 된다.
        assert!(parse_dpkg(DPKG, "dpkg").iter().any(|r| r.name == "mid-apt"));
        assert!(dpkg_is_installed("install ok triggers-awaited"));
        assert!(!dpkg_is_installed("deinstall ok config-files"));
        assert!(!dpkg_is_installed(""));
    }

    #[test]
    fn a_continuation_line_is_not_read_as_a_field() {
        // `Description` 의 이어지는 줄에 `Package: ...` 가 적혀 있어도 레코드가
        // 되어서는 안 된다 — 공백으로 시작하는 줄은 앞 필드의 몫이다.
        assert!(
            !parse_dpkg(DPKG, "dpkg")
                .iter()
                .any(|r| r.name.contains("prose")),
            "산문 줄을 패키지로 읽었다"
        );
    }

    #[test]
    fn a_source_package_lets_one_rule_aim_at_a_family() {
        // `php8.2-cli` 의 원본이 `php8.2` 다. 판이 괄호로 붙어 온다.
        let got = parse_dpkg(DPKG, "dpkg");
        let php = got.iter().find(|r| r.name == "php8.2-cli").unwrap();
        assert_eq!(php.source, "php8.2");
    }

    #[test]
    fn an_apk_record_skips_the_file_list() {
        let got = parse_apk(APK, "apk");
        let names: Vec<&str> = got.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["alpine-baselayout", "php82"], "{got:#?}");
        assert_eq!(got[1].version, "8.2.29-r0");
        assert_eq!(got[1].upstream_version, "8.2.29");
        assert_eq!(got[1].revision, "r0");
        // apk 는 `o:` 에 제 이름을 적는다. "이름과 다른 원본" 만 담는다.
        assert!(got[1].source.is_empty(), "{:?}", got[1]);
    }

    #[test]
    fn a_distro_version_splits_into_three() {
        // 실측한 모양 전부다 (debian:12 · ubuntu:22.04 · alpine:3.21).
        for (v, up, rev) in [
            ("1:2.38.1-5+deb12u3", "2.38.1", "5+deb12u3"),
            ("8.2.7-1ubuntu2.4", "8.2.7", "1ubuntu2.4"),
            ("12.4+deb12u15", "12.4", ""),
            ("3.118ubuntu5", "3.118", ""),
            ("12ubuntu4.7", "12", ""),
            ("5.2.15-2+b13", "5.2.15", "2+b13"),
            ("3.6.8-r1", "3.6.8", "r1"),
            ("3.134", "3.134", ""),
            ("8.2.29~rc1", "8.2.29", ""),
        ] {
            assert_eq!(
                split_version(v),
                (up.to_string(), rev.to_string()),
                "'{v}' 를 잘못 갈랐다"
            );
        }
    }

    #[test]
    fn an_unreadable_upstream_version_is_left_empty() {
        // 지어내면 `version_lt` 가 **엉뚱한 답**을 낸다. 비우면 그 연산자가
        // "재지 못했다" 로 가고 그것은 종료 6 이다.
        for v in ["", "wheezy", "v8.2.29", "-1", "git20240101"] {
            let (up, _) = split_version(v);
            assert!(up.is_empty(), "'{v}' 에서 상류 판을 지어냈다: '{up}'");
        }
    }

    // ───────────────────────────────────────────── 수집 경로

    #[derive(Default)]
    struct FakeFs {
        files: BTreeMap<String, Vec<u8>>,
        refuse: bool,
        too_big: bool,
    }

    impl FsRead for FakeFs {
        fn walk(&self, _root: &str, _l: usize) -> Result<WalkResult, PlatformError> {
            Ok(WalkResult {
                entries: Vec::<FsEntry>::new(),
                truncated: false,
                denied: 0,
                denied_paths: Vec::new(),
            })
        }
        fn read_file(&self, path: &str, _max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
            if self.refuse {
                return Err(PlatformError::Refused(path.to_string()));
            }
            if self.too_big {
                return Ok(None);
            }
            Ok(self.files.get(path).cloned())
        }
        fn look(&self, path: &str) -> Seen {
            if self.files.contains_key(path) {
                Seen::Present
            } else {
                Seen::Absent
            }
        }
    }

    fn linux_scope() -> Scope {
        let mut sc = Scope::diagnostic(Vec::new(), Platform::Linux);
        sc.subjects.push(remedy_sdk::catalog::Subject::Package);
        sc
    }

    fn fs_with(entries: &[(&str, &str)]) -> FakeFs {
        FakeFs {
            files: entries
                .iter()
                .map(|(p, c)| (p.to_string(), c.as_bytes().to_vec()))
                .collect(),
            ..FakeFs::default()
        }
    }

    #[test]
    fn both_databases_are_read_and_the_order_is_fixed() {
        // 두 DB 를 이어 담으므로 정렬하지 않으면 같은 기계를 두 번 수집한
        // 스냅샷이 달라진다.
        let fs = fs_with(&[(DPKG_STATUS, DPKG), (APK_INSTALLED, APK)]);
        let h = packages(&fs, &linux_scope()).unwrap();
        let got: Vec<(&str, &str)> = h
            .records
            .iter()
            .map(|r| (r.manager.as_str(), r.name.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("apk", "alpine-baselayout"),
                ("apk", "php82"),
                ("dpkg", "adduser"),
                ("dpkg", "libmount1"),
                ("dpkg", "mid-apt"),
                ("dpkg", "php8.2-cli"),
            ]
        );
        assert_eq!(h.denied_dirs, 0);
        assert!(!h.truncated);
    }

    #[test]
    fn a_missing_database_is_not_a_refusal() {
        // apk 가 없는 데비안 기계에 그 파일이 없는 것은 **정상이다.**
        let fs = fs_with(&[(DPKG_STATUS, DPKG)]);
        let h = packages(&fs, &linux_scope()).unwrap();
        assert!(h.records.iter().all(|r| r.manager == "dpkg"));
        assert_eq!(h.denied_dirs, 0, "없는 DB 를 거부로 셌다");
    }

    #[test]
    fn a_database_that_cannot_be_opened_is_reported_as_denied() {
        let mut fs = fs_with(&[(DPKG_STATUS, DPKG)]);
        fs.refuse = true;
        let h = packages(&fs, &linux_scope()).unwrap();
        assert!(h.records.is_empty());
        assert_eq!(h.denied_dirs, 1, "못 본 것을 없는 것으로 보고했다");
        assert_eq!(h.denied_paths, vec![DPKG_STATUS.to_string()]);
    }

    #[test]
    fn a_database_over_the_limit_is_reported_as_truncated() {
        // 조용히 넘기면 그 기계는 "패키지가 없다" 가 된다.
        let mut fs = fs_with(&[(DPKG_STATUS, DPKG)]);
        fs.too_big = true;
        let h = packages(&fs, &linux_scope()).unwrap();
        assert!(h.records.is_empty());
        assert!(h.truncated);
        assert_eq!(h.denied_dirs, 0, "상한 초과를 거부로 셌다");
    }

    #[test]
    fn windows_reads_nothing() {
        // 카탈로그가 `windows: false` 라 여기까지 오는 길이 없다. 그 관문이
        // 새더라도 **엉뚱한 경로를 열지 않는다.**
        let fs = fs_with(&[(DPKG_STATUS, DPKG)]);
        let sc = Scope::diagnostic(Vec::new(), Platform::Windows);
        let h = packages(&fs, &sc).unwrap();
        assert!(h.records.is_empty());
        assert_eq!(h.denied_dirs, 0);
    }
}
