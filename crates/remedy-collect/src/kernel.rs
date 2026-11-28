//! 지금 도는 커널 (Linux · `/proc/sys/kernel/osrelease` · `version` · `/proc/version_signature` · 코어 1.28.0).
//!
//! # 왜 여기서 보는가
//!
//! 깔린 커널 패키지는 **다음 부팅**을 말한다. 커널 결함을 판정할 것은 **지금 도는** 커널이다 — 고친 커널을
//! 깔고 다시 시작하지 않은 기계는 패키지만 보면 고친 것으로 읽히고, 두 판이 함께 깔린 기계는 어느 쪽으로
//! 도는지 가를 수 없다. 커널이 내는 파일 셋이 `uname -r` · `uname -v` 와 같은 값을 준다.
//!
//! | 칸 | 자리 | 값 |
//! |---|---|---|
//! | `release` | `/proc/sys/kernel/osrelease` | `uname -r` 과 같다 |
//! | `build` | `/proc/sys/kernel/version` | `uname -v` 와 같다 — Debian 은 `Debian <패키지 판> (날짜)` 를 담는다 |
//! | `release_noarch` | `release` 에서 뽑는다 | 끝의 `.<아키텍처>` 와 그 뒤 `+<변형>` 을 뗀 값 — rpm 판과 잇는 칸 |
//! | `signature` | `/proc/version_signature` | Ubuntu 커널만 낸다 — 없으면 빈 문자열 |
//!
//! 파일은 값 뒤에 줄바꿈 하나를 더 담는다(커널이 `%s\n` 으로 쓴다 — 랩 VM 실측 15 바이트 = 14 + 1). 그
//! **하나만** 뗀다. 나머지는 원문 그대로다.
//!
//! # 못 읽으면
//!
//! `osrelease` · `version` 은 리눅스에 늘 있는 자리라 못 읽는 것은 비정상이다 — **거부**로 센다(점검은 6).
//! 이 칸을 쓰는 룰마다 그것이 안전판이 된다. `version_signature` 는 없는 것이 정상이라 [`FsRead::look`] 으로
//! *없음* 과 *못 봄* 을 가른다 — 없으면 빈 문자열, 그 밖은 거부다.
//!
//! **칸 하나라도 못 읽으면 레코드를 담지 않는다.** 빈 칸은 *"없다"* 로 읽힌다 — `signature` 의 빈 문자열은
//! *"Ubuntu 커널이 아니다"* 이고, 빈 `release` 는 어느 패키지와도 이어지지 않는다. 담지 않고 거부 · 잘림으로
//! 남기면 관측이 불완전해져 *"없다"* 를 말하지 않는다.
//!
//! # 하지 않는 것
//!
//! 마운트 · 모듈 적재 · 쓰기. `mount -t nfsd` 하나로도 모듈이 실린다 — 점검이 기계를 바꾸면 안 된다. 읽는 것은
//! [`FsRead`] 하나뿐이다.
//!
//! 이 값은 **이 엔진이 도는 커널**의 것이다 — 컨테이너 안에서 돌면 호스트 커널이 보인다.

use remedy_artifacts::{CollectError, Harvest, KernelRecord, Scope};
use remedy_platform::read::{FsRead, Seen};
use remedy_sdk::catalog::Platform;
use remedy_sdk::normalize;

/// `uname -r` 과 같은 값.
const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
/// `uname -v` 와 같은 값.
const VERSION: &str = "/proc/sys/kernel/version";
/// Ubuntu 커널만 낸다.
const SIGNATURE: &str = "/proc/version_signature";

/// 파일마다 읽는 상한. 커널의 값은 수십 ~ 수백 바이트다(랩 VM 15 · 53 · 197).
///
/// `/proc` 파일은 크기를 0 으로 알려 이 상한이 읽기 함수의 크기 검사를 지나 버린다 — 그래서 받은 바이트 수를
/// 다시 잰다(`unix_socket` 과 같다).
const MAX_BYTES: u64 = 64 * 1024;

/// `release` 끝에서 떼는 아키텍처 — **닫힌 목록**이다. 목록 밖의 꼬리는 떼지 않는다: 잘못 떼어 다른 패키지와
/// 이어지는 것보다, 이어지지 않아 룰이 6 으로 받는 편이 낫다.
const ARCHES: [&str; 7] = [
    "x86_64", "aarch64", "ppc64le", "s390x", "i686", "armv7hl", "riscv64",
];

/// 지금 도는 커널 — 리눅스에서 늘 한 건(읽지 못하면 0건 + 거부 · 잘림).
///
/// **Linux 뿐이다.** 카탈로그가 `windows: false` 로 적어 두어 Windows 범위에서는 이 subject 가 빠진다. 그래도
/// 플랫폼을 보는 이유는 스냅샷이 다른 기계의 것일 수 있어서다(`package` 와 같다).
pub fn kernel<P: FsRead>(fs: &P, scope: &Scope) -> Result<Harvest<KernelRecord>, CollectError> {
    let mut h = Harvest::default();
    if scope.platform != Platform::Linux {
        return Ok(h);
    }
    let release = read_value(fs, OSRELEASE, &mut h);
    let build = read_value(fs, VERSION, &mut h);
    let signature = match fs.look(SIGNATURE) {
        Seen::Absent => Some(String::new()),
        Seen::Present => read_value(fs, SIGNATURE, &mut h),
        // 있는지조차 묻지 못했다 — 없는 것이 아니라 못 본 것이다.
        Seen::Locked | Seen::CannotTell => {
            h.deny(SIGNATURE);
            None
        }
    };
    if let (Some(release), Some(build), Some(signature)) = (release, build, signature) {
        h.records.push(KernelRecord {
            release_noarch: release_noarch(&release),
            release,
            build,
            signature,
        });
    }
    Ok(h)
}

/// 값 하나. 상한을 넘으면 잘림, 읽지 못하면 거부로 세고 `None`.
fn read_value<P: FsRead, T>(fs: &P, path: &str, h: &mut Harvest<T>) -> Option<String> {
    match fs.read_file(path, MAX_BYTES) {
        Ok(Some(bytes)) if bytes.len() as u64 <= MAX_BYTES => {
            let text = String::from_utf8_lossy(&bytes);
            Some(normalize::nfc(text.strip_suffix('\n').unwrap_or(&text)))
        }
        // 상한을 넘었다. 조용히 넘기면 그 기계는 *"커널을 모른다"* 가 아니라 *"없다"* 가 된다.
        Ok(_) => {
            h.truncated = true;
            None
        }
        Err(_) => {
            h.deny(path);
            None
        }
    }
}

/// `release` 끝의 `.<아키텍처>` 와 그 뒤 `+<변형>` 을 뗀다 — rpm 판(`판-개정`)과 잇는 값이다.
///
/// `5.14.0-503.23.1.el9_5.x86_64+rt` → `5.14.0-503.23.1.el9_5`. 아키텍처는 [`ARCHES`] 의 닫힌 목록이고 대소문자를
/// 가린다. 변형은 비지 않은 영숫자 · `_` · `-` 다. 그 꼴이 아니면(꼬리가 없거나 · 목록 밖이거나 · 앞이 비었거나
/// · 끝에 공백이 있으면) **그대로 돌려준다** — Debian 의 `6.12.118+deb13-amd64` 처럼 `+` 가 판 안에 있는 꼴도 그대로다.
pub fn release_noarch(release: &str) -> String {
    let base = match release.rsplit_once('+') {
        Some((b, v)) if is_variant(v) => b,
        _ => release,
    };
    // `+` 뒤가 변형 꼴이어도 그 앞에 아키텍처 꼬리가 없으면 `+` 는 판의 일부다(Debian `+deb13`) — 그대로 둔다.
    ARCHES
        .iter()
        .find_map(|arch| {
            base.strip_suffix(arch)?
                .strip_suffix('.')
                .filter(|head| !head.is_empty())
        })
        .unwrap_or(release)
        .to_string()
}

/// `+` 뒤의 변형 이름 꼴인가 — `rt` · `64k` · `16k` · `debug`.
fn is_variant(v: &str) -> bool {
    !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_platform::read::{Seen, WalkResult};
    use remedy_platform::PlatformError;
    use std::collections::BTreeMap;

    /// 자리 하나가 백엔드에 어떻게 보이는가.
    #[derive(Clone)]
    enum At {
        /// 읽힌다 — `/proc` 처럼 크기를 0 으로 알려 읽기 함수의 상한 검사를 지난 바이트도 그대로 온다.
        Bytes(Vec<u8>),
        /// 백엔드가 상한을 넘었다고 답한다(`Ok(None)`).
        TooBig,
        /// 없다 — 읽으면 `NotFound`, 물으면 `Absent`.
        Missing,
        /// 있는데 열리지 않는다 — 읽으면 `PermissionDenied`, 물으면 `Locked`.
        Locked,
        /// 있는지조차 묻지 못한다.
        CannotTell,
        /// 물으면 있다고 하는데 읽으면 실패한다(읽는 사이에 사라짐 등).
        PresentButFails,
    }

    struct Fake(BTreeMap<&'static str, At>);

    impl Fake {
        fn new(entries: &[(&'static str, At)]) -> Self {
            Fake(entries.iter().cloned().collect())
        }
        fn at(&self, path: &str) -> At {
            self.0.get(path).cloned().unwrap_or(At::Missing)
        }
    }

    fn io(path: &str, kind: std::io::ErrorKind) -> PlatformError {
        PlatformError::Io {
            path: path.to_string(),
            source: std::io::Error::from(kind),
        }
    }

    impl FsRead for Fake {
        fn walk(&self, _root: &str, _limit: usize) -> Result<WalkResult, PlatformError> {
            Ok(WalkResult::default())
        }
        fn read_file(&self, path: &str, _max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
            use std::io::ErrorKind;
            match self.at(path) {
                At::Bytes(b) => Ok(Some(b)),
                At::TooBig => Ok(None),
                At::Missing => Err(io(path, ErrorKind::NotFound)),
                At::Locked => Err(io(path, ErrorKind::PermissionDenied)),
                At::CannotTell | At::PresentButFails => Err(io(path, ErrorKind::Other)),
            }
        }
        fn look(&self, path: &str) -> Seen {
            match self.at(path) {
                At::Bytes(_) | At::TooBig | At::PresentButFails => Seen::Present,
                At::Missing => Seen::Absent,
                At::Locked => Seen::Locked,
                At::CannotTell => Seen::CannotTell,
            }
        }
    }

    const DEBIAN_RELEASE: &str = "6.1.0-53-amd64\n";
    const DEBIAN_BUILD: &str = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.187-1 (2026-09-07)\n";

    fn text(s: &str) -> At {
        At::Bytes(s.as_bytes().to_vec())
    }

    fn linux() -> Scope {
        Scope::diagnostic(Vec::new(), Platform::Linux)
    }

    /// 랩 VM(Debian 12)에서 읽은 꼴 그대로 — 파일은 값 뒤에 줄바꿈 하나를 더 담고, `version_signature` 는 없다.
    fn debian() -> Fake {
        Fake::new(&[
            (OSRELEASE, text(DEBIAN_RELEASE)),
            (VERSION, text(DEBIAN_BUILD)),
        ])
    }

    #[test]
    fn the_running_kernel_is_one_record_without_the_trailing_newline() {
        let h = kernel(&debian(), &linux()).unwrap();
        assert_eq!(
            h.records,
            vec![KernelRecord {
                release: "6.1.0-53-amd64".into(),
                build: "#1 SMP PREEMPT_DYNAMIC Debian 6.1.187-1 (2026-09-07)".into(),
                release_noarch: "6.1.0-53-amd64".into(),
                signature: String::new(),
            }]
        );
        assert!(!h.truncated);
        assert_eq!(h.denied_dirs, 0, "없는 version_signature 를 거부로 셌다");
    }

    #[test]
    fn the_ubuntu_signature_is_kept() {
        let mut fs = debian();
        fs.0.insert(SIGNATURE, text("Ubuntu 6.8.0-49.49-generic 6.8.12\n"));
        let h = kernel(&fs, &linux()).unwrap();
        assert_eq!(h.records.len(), 1);
        assert_eq!(h.records[0].signature, "Ubuntu 6.8.0-49.49-generic 6.8.12");
        assert_eq!(h.denied_dirs, 0);
    }

    /// 끝의 줄바꿈 **하나만** 뗀다 — 커널이 `%s\n` 으로 쓰는 그 하나다. 그 밖의 공백 · 줄바꿈은 원문대로 남아,
    /// 그런 값은 패키지 이름 · 판과 이어지지 않는다(이어지지 않으면 룰이 6 으로 받는다).
    #[test]
    fn only_the_kernels_own_newline_is_dropped() {
        for (raw, want) in [
            ("6.1.0-53-amd64", "6.1.0-53-amd64"),
            ("6.1.0-53-amd64\n", "6.1.0-53-amd64"),
            ("6.1.0-53-amd64\n\n", "6.1.0-53-amd64\n"),
            ("6.1.0-53-amd64 \n", "6.1.0-53-amd64 "),
        ] {
            let fs = Fake::new(&[(OSRELEASE, text(raw)), (VERSION, text(DEBIAN_BUILD))]);
            let h = kernel(&fs, &linux()).unwrap();
            assert_eq!(h.records[0].release, want, "{raw:?}");
        }
    }

    /// osrelease · version 은 리눅스에 늘 있는 자리다 — 없거나 열리지 않으면 **못 본 것**이고(거부 · 점검은 6),
    /// 레코드를 담지 않는다. 빈 칸으로 담으면 *"없다"* 로 읽힌다.
    #[test]
    fn an_unreadable_osrelease_or_version_is_a_denial() {
        for path in [OSRELEASE, VERSION] {
            for at in [At::Missing, At::Locked, At::CannotTell] {
                let mut fs = debian();
                fs.0.insert(path, at);
                let h = kernel(&fs, &linux()).unwrap();
                assert!(
                    h.records.is_empty(),
                    "{path}: 못 읽은 칸으로 레코드를 담았다"
                );
                assert_eq!(h.denied_dirs, 1, "{path}");
                assert_eq!(h.denied_paths, vec![path.to_string()]);
                assert!(!h.truncated, "{path}: 거부를 잘림으로 셌다");
            }
        }
    }

    /// `/proc` 은 크기를 0 으로 알려 백엔드의 상한 검사를 지난다 — 받은 바이트 수를 다시 잰다. 상한을 넘으면
    /// 잘림이고 레코드는 없다. 백엔드가 `Ok(None)` 으로 답해도 같다.
    #[test]
    fn over_the_limit_is_truncation() {
        let big = vec![b'6'; MAX_BYTES as usize + 1];
        let exact = vec![b'6'; MAX_BYTES as usize];
        for path in [OSRELEASE, VERSION] {
            for at in [At::Bytes(big.clone()), At::TooBig] {
                let mut fs = debian();
                fs.0.insert(path, at);
                let h = kernel(&fs, &linux()).unwrap();
                assert!(h.records.is_empty(), "{path}");
                assert!(h.truncated, "{path}: 상한을 넘은 값을 조용히 담았다");
                assert_eq!(h.denied_dirs, 0, "{path}: 잘림을 거부로 셌다");
            }
            // 상한과 같은 길이는 담는다.
            let mut fs = debian();
            fs.0.insert(path, At::Bytes(exact.clone()));
            let h = kernel(&fs, &linux()).unwrap();
            assert_eq!(h.records.len(), 1, "{path}");
            assert!(!h.truncated);
        }
    }

    /// `version_signature` 는 없는 것이 정상이다(Ubuntu 커널만 낸다) — `look()` 으로 *없음* 과 *못 봄* 을 가른다.
    /// 없으면 빈 문자열, 그 밖에 읽지 못한 것은 거부다. 거부면 레코드를 담지 않는다 — 빈 문자열은
    /// *"Ubuntu 커널이 아니다"* 로 읽힌다.
    #[test]
    fn the_signature_is_empty_only_when_it_is_absent() {
        for at in [At::Locked, At::CannotTell, At::PresentButFails] {
            let mut fs = debian();
            fs.0.insert(SIGNATURE, at);
            let h = kernel(&fs, &linux()).unwrap();
            assert!(h.records.is_empty());
            assert_eq!(h.denied_dirs, 1);
            assert_eq!(h.denied_paths, vec![SIGNATURE.to_string()]);
        }
        let mut fs = debian();
        fs.0.insert(SIGNATURE, At::TooBig);
        let h = kernel(&fs, &linux()).unwrap();
        assert!(h.records.is_empty());
        assert!(h.truncated);
        assert_eq!(h.denied_dirs, 0);
    }

    /// **Linux 뿐이다.** 스냅샷이 다른 기계의 것일 수 있어 플랫폼을 본다 — 다른 플랫폼에서는 읽지도 않는다.
    #[test]
    fn other_platforms_get_nothing() {
        for p in [Platform::Windows, Platform::Darwin] {
            let h = kernel(&debian(), &Scope::diagnostic(Vec::new(), p)).unwrap();
            assert!(h.records.is_empty());
            assert_eq!(h.denied_dirs, 0);
            assert!(!h.truncated);
        }
    }

    /// `release_noarch` — 닫힌 아키텍처 목록의 `.<아키텍처>` 꼬리와 그 뒤 `+<변형>` 을 뗀다. 그 밖의 꼴은 그대로다.
    #[test]
    fn release_noarch_drops_only_a_known_arch_tail() {
        for (release, want) in [
            // Fedora · RHEL — rpm 의 `판-개정` 뒤에 `.<아키텍처>` 가 붙는다.
            ("7.3.4-300.fc45.x86_64", "7.3.4-300.fc45"),
            ("5.14.0-503.23.1.el9_5.x86_64", "5.14.0-503.23.1.el9_5"),
            // 변형 꼬리 — 실시간 · 큰 페이지 · 디버그.
            ("5.14.0-503.23.1.el9_5.x86_64+rt", "5.14.0-503.23.1.el9_5"),
            ("5.14.0-503.23.1.el9_5.aarch64+64k", "5.14.0-503.23.1.el9_5"),
            ("6.11.4-301.fc41.aarch64+16k", "6.11.4-301.fc41"),
            (
                "5.14.0-503.23.1.el9_5.x86_64+debug",
                "5.14.0-503.23.1.el9_5",
            ),
            // RHEL 8 의 실시간 커널은 판 안에 `rt` 를 담는다 — 꼬리만 뗀다.
            (
                "4.18.0-553.84.1.rt7.425.el8_10.x86_64",
                "4.18.0-553.84.1.rt7.425.el8_10",
            ),
            // 목록의 나머지 아키텍처.
            ("5.14.0-503.23.1.el9_5.ppc64le", "5.14.0-503.23.1.el9_5"),
            ("5.14.0-503.23.1.el9_5.s390x", "5.14.0-503.23.1.el9_5"),
            ("6.11.4-301.fc41.i686", "6.11.4-301.fc41"),
            ("6.11.4-301.fc41.armv7hl", "6.11.4-301.fc41"),
            ("6.11.4-301.fc41.riscv64", "6.11.4-301.fc41"),
            // 꼬리가 없으면 그대로 — Debian · Ubuntu · SUSE · Alpine · WSL.
            ("6.12.118+deb13-amd64", "6.12.118+deb13-amd64"),
            ("6.1.0-53-amd64", "6.1.0-53-amd64"),
            ("6.8.0-49-generic", "6.8.0-49-generic"),
            ("6.4.0-150600.23.25-default", "6.4.0-150600.23.25-default"),
            ("6.12.13-0-lts", "6.12.13-0-lts"),
            (
                "5.15.167.4-microsoft-standard-WSL2",
                "5.15.167.4-microsoft-standard-WSL2",
            ),
            // 목록 밖 · 대소문자가 다른 아키텍처 · 빈 변형 · 점이 든 변형 · 앞이 빈 값 · 끝 공백은 손대지 않는다
            // — 이어지지 않으면 룰이 6 으로 받는다(틀리게 이어 붙이는 것보다 낫다).
            ("4.18.0-553.el8.ia64", "4.18.0-553.el8.ia64"),
            ("5.14.0-503.el9.X86_64", "5.14.0-503.el9.X86_64"),
            ("5.14.0-503.el9.x86_64+", "5.14.0-503.el9.x86_64+"),
            ("5.14.0-503.el9.x86_64+rt.1", "5.14.0-503.el9.x86_64+rt.1"),
            (".x86_64", ".x86_64"),
            ("5.14.0-503.el9.x86_64 ", "5.14.0-503.el9.x86_64 "),
            ("", ""),
        ] {
            assert_eq!(release_noarch(release), want, "{release:?}");
        }
    }
}
