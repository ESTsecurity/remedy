//! Linux 라이브 백엔드 (설계-09 P12).
//!
//! # 수집이 먼저였다
//!
//! P12 의 순서가 **수집 먼저**다 — 파괴 없이 G1(청정 환경 무해성)을 잴 수 있고,
//! 실행기를 여는 것은 P7 → P8 게이트를 다시 지나는 일이라 코퍼스가 먼저 있어야
//! 한다. 그 코퍼스는 순서 7 에서 섰다.
//!
//! # 쓰기는 파일 계열부터 (순서 8)
//!
//! 되돌릴 수 있는 Op 부터 열었다. 파일 계열은
//! [`FsRestore`](crate::write::FsRestore) 가 이미 이식 가능하게 갖고 있어 위임으로
//! 끝나고, 지속성(cron·systemd)은 계약을 대칭으로 넓혀 열었다 (설계-09 결정 5) —
//! 활성화가 파일 밖에 있고(systemd 링크) 항목이 줄일 수 있다(cron)는 두 사실이
//! [`PersistenceIndex`] 와 [`LineAt`] 로 계약에 들어왔다.
//!
//! **빈 백엔드를 돌려주지 않는 이유와 같다** — "지웠다" 와 "지울 수 없다" 가
//! 구분되어야 한다.
//!
//! # 경로가 하나다
//!
//! Windows 는 WOW64 때문에 접근용 경로와 기록용 경로가 갈리지만 Linux 는 둘이
//! 같다. 그래서 [`PathView`](crate::local::PathView) 가 항등이고, 순회·본문
//! 읽기·시각 변환·`%NAME%` 전개는 `local` 의 것을 그대로 쓴다.

use crate::local;
use crate::read::{
    EnvRead, ExpandRoots, FsRead, ProcessRead, RawProcess, RegValue, RegistryRead, RootExpansion,
    WalkResult,
};
use crate::write::{
    DirIndex, FileMeta, FsRestore, KillPredicate, LineAt, PersistenceIndex, PlatformWrite,
    RemovedBy, RestoreReport, Target, VerifySite,
};
use crate::PlatformError;
use remedy_sdk::catalog::Platform;
use remedy_sdk::normalize;

/// 이 코어가 부르는 OS 관리 도구. **여기 없는 것은 부르지 않는다.**
///
/// Windows 쪽 `SYSTEM_TOOLS` 와 같은 규율이다 — 목록이 코드에 박혀 있어서
/// 계획이나 매니페스트에서 온 문자열이 실행 파일 이름이 되는 길이 없다.
///
/// 절대 경로로 적는다. `PATH` 를 타면 **치료 도구가 공격자가 심어 둔 같은 이름의
/// 실행 파일을 부를 수 있다** — Windows 쪽에서 `%SystemRoot%\System32` 를 붙이는
/// 것과 같은 이유다.
const SYSTEM_TOOLS: [&str; 2] = [
    // Debian·Ubuntu 계열. `/etc/ssl/certs/ca-certificates.crt` 번들을 다시 만든다.
    "/usr/sbin/update-ca-certificates",
    // RHEL·SUSE 계열의 같은 도구.
    "/usr/bin/update-ca-trust",
];

/// systemd 에게 유닛을 멈추게 하는 도구 (`service.stop`). [`SYSTEM_TOOLS`] 와 같은
/// 규율이다 — 절대 경로이고, 계획의 문자열이 실행 파일 이름이 되는 길이 없다.
/// usrmerge 전 배포판은 `/bin` 에 둔다.
///
/// **`SYSTEM_TOOLS` 에 넣지 않는다.** 그 목록은 신뢰 저장소를 다시 만드는 도구를
/// 앞에서부터 찾는 자리라(`ca_tool`), 섞이면 그 도구가 없는 기계에서 `systemctl`
/// 을 신뢰 저장소 도구로 고른다.
const SYSTEMCTL: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];

/// 사용자 홈이 모여 있는 자리 — **하나뿐이다.**
///
/// `/etc/passwd` 를 파싱하지 않는 이유는 **거기 있는 것이 사람이 아닐 수
/// 있어서**다. `nobody`·`systemd-*`·`_apt` 같은 시스템 계정도 홈 경로를 갖는데,
/// 그것까지 열면 범위가 `/`·`/nonexistent`·`/var/lib/*` 로 번진다. Windows 에서
/// `S-1-5-21-` 로 진짜 사용자만 고르는 것과 같은 판단이다.
///
/// `/root` 는 여기 없다. **그것은 홈이지 홈의 부모가 아니다** — 자세한 것은
/// `%ALLUSERPROFILES%` 확장 자리에 적었다.
const HOME_PARENT: &str = "/home";

/// 이동식 매체가 마운트되는 자리.
///
/// 배포판마다 다르므로 셋을 다 본다. `/mnt` 는 관례상 수동 마운트 자리이고
/// 고정 디스크가 붙어 있을 수 있어 **`allow_removable` 없이는 열지 않는다** —
/// 그것이 이 토큰의 전제다.
const REMOVABLE_PARENTS: [&str; 3] = ["/media", "/run/media", "/mnt"];

/// `%FIXED_DISKS%` 가 펴지는 자리 — 로컬 디스크 마운트와, 그것이 아니라 뺀 마운트(`자리 (형식)`) (코어 1.11.0).
///
/// `sysinfo` 가 이미 가상 파일 시스템(`proc` · `sysfs` · `cgroup` …) · `tmpfs` · NFS · CIFS 와 `/proc` · `/sys` ·
/// `/run` 아래를 뺀다(그 크레이트의 목록). 여기서 더 빼는 것은 **이 기계의 디스크가 아닌 것**이다 — `9p`(WSL 의
/// `/mnt/c` · VM 공유 폴더) · `drvfs` · `virtiofs` · `autofs` · `fuse.*`(sshfs 같은 원격 — `fuseblk` 는 로컬
/// NTFS 라 둔다). Windows 의 고정 드라이브가 네트워크 드라이브를 넣지 않는 것과 같은 뜻이다. 이동식 매체는
/// `%REMOVABLE%` 의 몫이다.
///
/// `/` 는 늘 든다 — 루트 파일 시스템의 형식을 `sysinfo` 가 고르지 못하면 기계의 대부분을 잃는다.
fn local_disk_mounts() -> (Vec<String>, Vec<String>) {
    let mut mounts = vec!["/".to_string()];
    let mut skipped = Vec::new();
    for d in sysinfo::Disks::new_with_refreshed_list().iter() {
        if d.is_removable() {
            continue;
        }
        let fs = d.file_system().to_string_lossy().to_string();
        let at = d.mount_point().to_string_lossy().to_string();
        if matches!(fs.as_str(), "9p" | "drvfs" | "virtiofs" | "autofs") || fs.starts_with("fuse.")
        {
            skipped.push(format!("{at} ({fs})"));
            continue;
        }
        mounts.push(at);
    }
    mounts.sort();
    mounts.dedup();
    skipped.sort();
    skipped.dedup();
    (mounts, skipped)
}

/// 프로필 수 상한. Windows 쪽과 같은 이유다 — 상한이 없으면 계정이 수백 개인
/// 기계에서 `%ALLUSERPROFILES%` 하나가 수집 범위를 통째로 삼킨다.
const MAX_PROFILES: usize = 64;

pub struct Live;

impl Default for Live {
    fn default() -> Self {
        Self::new()
    }
}

impl Live {
    pub fn new() -> Self {
        Self
    }

    /// 이 기계에서 신뢰 저장소를 다시 만드는 도구.
    ///
    /// 없으면 실패다. 조용히 성공을 돌려주면 **"인증서를 제거했다" 는 보고가
    /// 거짓이 된다** — 파일은 사라졌는데 번들에 남아 TLS 검사는 여전히 그
    /// 인증서를 믿는다. 배포판마다 도구가 다르므로 [`SYSTEM_TOOLS`] 의 순서대로
    /// 찾는다.
    fn ca_tool(&self) -> Result<&'static str, PlatformError> {
        SYSTEM_TOOLS
            .iter()
            .copied()
            .find(|t| std::path::Path::new(t).is_file())
            .ok_or_else(|| {
                // `Unsupported` 가 아니라 `Refused` 다. 문은 있다 — 지금 열면
                // 파일만 사라지고 신뢰가 남으므로 **열지 않기로** 한 것이다.
                {
                    let tools = SYSTEM_TOOLS.join(" · ");
                    PlatformError::refused(
                        format!(
                            "신뢰 저장소를 다시 만들 도구가 없습니다 ({tools}). 인증서 파일만 \
                             지우면 ca-certificates.crt 번들에 남아 신뢰가 사라지지 않습니다"
                        ),
                        format!(
                            "no tool to rebuild the trust store ({tools}). Deleting only the \
                             certificate file leaves it in the ca-certificates.crt bundle, so \
                             the trust does not go away"
                        ),
                    )
                }
            })
    }

    /// 신뢰 저장소를 다시 만든다.
    ///
    /// **인증서 파일을 지우거나 되돌린 것만으로는 신뢰가 바뀌지 않는다.** TLS
    /// 검사는 `/etc/ssl/certs/ca-certificates.crt` 번들을 읽고, 그 번들은 이
    /// 도구가 만든다. 실측(WSL Ubuntu 24.04): 원본 `.crt` 를 지워도 번들에 그
    /// 인증서가 그대로 남아 있었다.
    fn refresh_ca_store(&self) -> Result<(), PlatformError> {
        let exe = self.ca_tool()?;
        let out = crate::tool::run_tool(
            std::process::Command::new(exe),
            exe,
            crate::tool::WARN_SHORT,
        )
        .map_err(|e| PlatformError::io(exe, e))?;
        if out.success() {
            return Ok(());
        }
        Err(PlatformError::Refused(out.reason(exe)))
    }
}

/// 항등이다. 접근할 때 여는 경로와 스냅샷에 적는 경로가 같다.
impl local::PathView for Live {
    fn for_access(&self, path: &str) -> String {
        path.to_string()
    }
    fn for_record(&self, accessed: &str) -> String {
        normalize::for_record(accessed, Platform::Linux)
    }
}

impl FsRead for Live {
    fn walk(&self, root: &str, limit: usize) -> Result<WalkResult, PlatformError> {
        local::walk(self, root, limit)
    }

    fn walk_files(
        &self,
        root: &str,
        limit: usize,
        names: &[String],
        one_device: bool,
    ) -> Result<WalkResult, PlatformError> {
        local::walk_files(self, root, limit, names, one_device)
    }

    fn read_file(&self, path: &str, max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
        local::read_file(self, path, max)
    }

    fn read_stream(
        &self,
        path: &str,
        max: u64,
        sink: &mut dyn FnMut(&[u8]),
    ) -> Result<bool, PlatformError> {
        local::read_stream(self, path, max, sink)
    }

    fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<(u64, Vec<u8>), PlatformError> {
        local::read_range(self, path, offset, len)
    }

    fn look(&self, path: &str) -> crate::read::Seen {
        local::look(self, path)
    }
}

impl EnvRead for Live {
    fn expand(&self, s: &str) -> String {
        local::expand_percent(s)
    }
}

impl ProcessRead for Live {
    fn processes(&self) -> Result<Vec<RawProcess>, PlatformError> {
        let mut out = local::processes(self)?;
        for p in &mut out {
            let (modules, denied) = modules_of(p.pid);
            p.modules = modules;
            p.modules_denied = denied;
        }
        Ok(out)
    }
}

/// 실린 모듈 — `/proc/<pid>/maps` 의 **실행 가능한 파일 매핑**.
///
/// # 왜 Linux 만 채우는가
///
/// Windows 에서 같은 것을 얻으려면 `EnumProcessModules` 나
/// `CreateToolhelp32Snapshot` 이 필요하고 **둘 다 unsafe** 다. 여기는 파일 하나를
/// 읽으면 끝난다 — `forbid(unsafe_code)` 를 유지한 채로 된다. 그래서 이 필드는
/// 플랫폼 축을 갖고, `Subject::NOT_POPULATED_YET` 이 그 축을
/// `Some(Platform::Windows)` 로 들고 있다.
///
/// # 되돌려 주는 둘
///
/// `(목록, 거부되었는가)` 다. **빈 목록 하나로는 세 가지가 뭉뚱그려진다** —
/// 모듈이 없는 커널 스레드, 끝난 프로세스, 읽지 못한 프로세스. 마지막 것만
/// 거부로 세고 종료 코드 6 으로 말한다.
///
/// 끝난 프로세스(`NotFound`)를 거부로 세지 않는 이유는 레지스트리 쪽
/// [`unreadable_or_absent`](crate::read) 와 같다 — 늘 있는 것을 거부에 넣으면
/// 멀쩡한 기계가 영원히 관측 불완전이 되고, 그러면 6 이 신호이기를 그만둔다.
/// 열거와 읽기 사이에 프로세스가 끝나는 것은 **정상이다.**
///
/// # 거부는 상시가 아니다 — 컨테이너에서는 실제로 난다 (실측 2026-10-27)
///
/// Docker 는 `CAP_SYS_PTRACE` 를 기본으로 떼므로 **root 라도 다른 uid 의**
/// 프로세스 maps 를 읽지 못한다. `php:8.2-apache` 로 쟀다 —
///
/// | 띄운 방식 | `www-data` 아파치 작업자 5개 | 회차 |
/// |---|---|---|
/// | 기본 | maps **거부** (`image_path` 도 빈다 — 같은 제약이다) | **종료 6** · `denied_paths` 에 그 다섯 |
/// | `--cap-add SYS_PTRACE` | 전부 읽힌다 | 종료 0 |
///
/// 호스트에서 root 로 돌면 그 능력이 있어 거부가 나지 않는다(WSL 실측: 프로세스
/// 31개 · 거부 0 · 컨테이너 debian12 도 0). **그래서 세는 것이 맞다** — 늘 나는
/// 것이 아니고, 조용히 비우면 모듈을 겨눈 룰이 그 자리에서 미탐이 된다.
///
/// 덧붙여 **mod_php 는 그 제약 아래에서도 보인다** — 아파치 **마스터**는 root 라
/// 읽히고 그쪽도 모듈을 싣는다(실측: `libphp.so` · 프로세스당 모듈 72개).
fn modules_of(pid: u32) -> (Vec<String>, bool) {
    match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
        Ok(text) => (parse_maps(&text), false),
        // 열거와 읽기 사이에 끝났다. 커널 스레드처럼 모듈이 없는 것과 같은
        // 빈 목록이 되지만, 둘 다 **봤고 없었던** 쪽이다.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Vec::new(), false),
        // root 로 돌므로 여기 오는 길은 사실상 LSM 정책뿐이다. **그래도
        // 소리를 내는 쪽으로 둔다** — 조용히 비우면 모듈을 겨눈 룰이 미탐이 된다.
        Err(_) => (Vec::new(), true),
    }
}

/// `/proc/<pid>/maps` 한 장에서 모듈 경로를 뽑는다.
///
/// # 실행 가능한 매핑만 모듈이다
///
/// 공유 라이브러리 하나는 보통 **네 줄**로 실린다 — 헤더(`r--p`) · 코드(`r-xp`) ·
/// 읽기 전용 데이터(`r--p`) · 데이터(`rw-p`). `x` 가 붙은 줄만 세면 라이브러리
/// 하나가 한 줄이 되고, 그것이 Windows 의 모듈 목록과 같은 뜻이다. 매핑을 전부
/// 담으면 같은 경로가 네 번 들어와 룰 작성자가 그 수를 세는 일이 생긴다.
///
/// 글꼴이나 데이터 파일처럼 **실행 권한 없이 mmap 된 것은 모듈이 아니다.**
///
/// # 상한을 두지 않는다
///
/// 경로로 중복을 접고 나면 남는 수는 *그 프로세스가 실제로 올린 공유 객체 수*
/// 이고, 그것은 파일 순회처럼 무한정 늘어나는 양이 아니다 — 실측(2026-10-27):
///
/// | 기계 | 프로세스 | 프로세스당 모듈 |
/// |---|---|---|
/// | WSL Ubuntu (root) | 31개 | 최대 5 · 합계 43 |
/// | `php:8.2-apache` | 8개 | **최대 72** (아파치) |
///
/// 상한을 두면 **잘렸다고 말할 채널**이 함께 필요해지는데, 한 번도 걸리지 않는
/// 채널은 그 자리에서 죽은 코드다. 실기기에서 큰 목록을 보게 되면 그때 재서
/// 넣는다.
fn parse_maps(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .lines()
        .filter_map(module_path_of)
        .map(|p| normalize::for_record(p, Platform::Linux))
        .collect();
    // **정렬한다.** `/proc/<pid>/maps` 는 주소 순이고 주소는 ASLR 이 매번
    // 바꾼다 — 그대로 두면 같은 기계를 두 번 수집한 스냅샷이 달라진다.
    out.sort();
    out.dedup();
    out
}

/// 줄 하나에서 모듈 경로. 모듈이 아니면 `None`.
///
/// 형식은 `주소범위 권한 오프셋 장치 inode  경로` 다. **경로에 공백이 있을 수
/// 있으므로** 앞의 다섯 칸만 건너뛰고 나머지를 통째로 쓴다 — 마지막 칸을
/// 공백으로 끊으면 `/opt/My App/lib.so` 가 `App/lib.so` 가 된다.
///
/// 지워진 파일은 커널이 ` (deleted)` 를 붙여 준다. **그대로 둔다** — 벗겨 내면
/// 있지도 않은 경로를 있는 것처럼 적게 되고, 하필 그 표시가 강한 신호다
/// (실행 중에 제 파일을 지우는 것).
fn module_path_of(line: &str) -> Option<&str> {
    let mut rest = line.trim_start();
    let mut perms = "";
    for i in 0..5 {
        let end = rest.find(' ')?;
        if i == 1 {
            perms = &rest[..end];
        }
        rest = rest[end..].trim_start();
    }
    if !perms.contains('x') {
        return None;
    }
    // `[heap]` · `[stack]` · `[vdso]` 와 익명 매핑은 파일이 아니다.
    rest.starts_with('/').then_some(rest)
}

/// **레지스트리는 Linux 에 없다.**
///
/// 빈 결과가 아니라 [`PlatformError::Unsupported`] 다. 빈 결과를 돌려주면
/// "`Run` 키에 아무것도 없다" 로 읽히고, 그 스냅샷 위에서 "위협 없음" 이
/// 결론난다 — 같은 이유로 [`live()`](crate::live) 도 빈 백엔드를 돌려주지 않는다.
///
/// 여기까지 오는 길은 사실상 없다. `scope_from_manifest` 가 레지스트리 subject
/// 를 Linux 범위에서 빼고, `plugin lint` 가 작성 시점에 같은 것을 잡는다.
/// **그래도 소리를 내는 쪽으로 둔다** — 그 두 관문이 새면 여기서 드러나야 한다.
impl RegistryRead for Live {
    fn value(&self, _key: &str, _name: &str) -> Result<Option<RegValue>, PlatformError> {
        Err(PlatformError::Unsupported(
            "Linux 에는 레지스트리가 없습니다",
        ))
    }

    fn subkeys(&self, _key: &str) -> Result<Vec<String>, PlatformError> {
        Err(PlatformError::Unsupported(
            "Linux 에는 레지스트리가 없습니다",
        ))
    }

    fn values(&self, _key: &str) -> Result<Vec<(String, RegValue)>, PlatformError> {
        Err(PlatformError::Unsupported(
            "Linux 에는 레지스트리가 없습니다",
        ))
    }

    fn key_exists(&self, _key: &str) -> bool {
        false
    }
}

impl ExpandRoots for Live {
    fn expand_roots(&self, root: &str, allow_removable: bool) -> RootExpansion {
        let mut out = RootExpansion::default();

        // `HKU\*` 는 Linux 에 대응물이 없다. **조용히 1:1 로 흘리지 않는다** —
        // 그러면 `HKU\*\...` 가 그대로 경로가 되어 존재하지 않는 곳을 가리키고,
        // 수집은 0건이 되며 아무도 이유를 모른다.
        if let Some(star) = root.find("\\*") {
            let head = &root[..star];
            if head.eq_ignore_ascii_case("HKU") || head.eq_ignore_ascii_case("HKEY_USERS") {
                out.notes.push(remedy_sdk::i18n::current().pick(
                    format!("{root}: Linux 에는 레지스트리 하이브가 없습니다"),
                    format!("{root}: Linux has no registry hives"),
                ));
                return out;
            }
        }

        // `%ALLUSERPROFILES%` — 모든 사용자의 홈.
        if let Some(rest) = local::strip_token(root, "%ALLUSERPROFILES%") {
            let mut dirs = Vec::new();
            // **`/home` 아래만 센다.** `/root` 는 홈이지 홈의 부모가 아니다 —
            // 그것까지 순회하면 `.config` · `.ssh` · `.cache` 가 전부 사용자
            // 프로필로 세어진다.
            //
            // 2026-09-03 Linux 하네스가 이것을 밟았다. `%ALLUSERPROFILES%` 를
            // 브라우저 확장 자리에 쓰자 상한에
            // `/root/.config/.config/google-chrome/...` 이 함께 실렸다.
            //
            // 없는 경로라 수집은 0건이지만 **해로운 것은 그쪽이 아니다**:
            //
            //   1. 선언한 읽기 상한이 가짜 항목으로 부푼다. G6 이 그 목록으로
            //      판정하므로 사람이 읽는 상한과 기계가 쓰는 상한이 갈라진다.
            //   2. `MAX_PROFILES`(64) 예산을 잡아먹는다. root 홈에 점파일이
            //      64개면 **`/home` 의 진짜 사용자들이 잘려 나가고**, 그 기계는
            //      조용히 일부 사용자만 치료된다. 이 토큰이 존재하는 이유가
            //      바로 그 반대인데.
            if let Ok(rd) = std::fs::read_dir(HOME_PARENT) {
                for e in rd.flatten() {
                    if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        dirs.push(e.path().to_string_lossy().to_string());
                    }
                }
            }
            // `/root` 는 그 자체가 홈이다.
            //
            // 비관리자로 돌면 열리지 않는다. 없는 것과 다르므로 말해 둔다 —
            // 그 사용자의 홈은 훑지 못한 것이다.
            match std::fs::read_dir("/root") {
                Ok(_) => dirs.push("/root".to_string()),
                Err(_) if std::path::Path::new("/root").exists() => {
                    out.notes.push(remedy_sdk::i18n::current().pick(
                        format!("{root}: /root 를 열지 못했습니다 (권한)"),
                        format!("{root}: /root could not be opened (permission)"),
                    ));
                }
                Err(_) => {}
            }
            dirs.sort();
            dirs.dedup();
            if dirs.len() > MAX_PROFILES {
                let n = dirs.len();
                out.notes.push(remedy_sdk::i18n::current().pick(
                    format!("{root}: 홈 {n}개 중 {MAX_PROFILES}개까지만 봅니다"),
                    format!("{root}: looking at only {MAX_PROFILES} of {n} homes"),
                ));
                dirs.truncate(MAX_PROFILES);
            }
            if dirs.is_empty() {
                out.notes.push(remedy_sdk::i18n::current().pick(
                    format!("{root}: 사용자 홈을 하나도 읽지 못했습니다"),
                    format!("{root}: not one user home could be read"),
                ));
            }
            out.roots = dirs
                .into_iter()
                .map(|d| normalize::for_record(&format!("{d}{rest}"), Platform::Linux))
                .collect();
            return out;
        }

        // `%FIXED_DISKS%` — 로컬 디스크 마운트 전부(코어 1.11.0). 각 마운트는 **다른 마운트로 넘어가지 않고**
        // 걷는다(`Scope::disk_roots` · `walk_files`) — 그래서 `/` 아래의 `/proc` · `/sys` 를 걷지 않고, 따로
        // 마운트된 `/home` 은 자기 뿌리로 한 번만 걷는다.
        if let Some(rest) = local::strip_token(root, "%FIXED_DISKS%") {
            let (mounts, skipped) = local_disk_mounts();
            if !skipped.is_empty() {
                out.notes.push(remedy_sdk::i18n::current().pick(
                    format!(
                        "{root}: 로컬 디스크가 아닌 마운트는 보지 않습니다 — {}",
                        skipped.join(" · ")
                    ),
                    format!(
                        "{root}: mounts that are not local disks are not looked at — {}",
                        skipped.join(" · ")
                    ),
                ));
            }
            out.roots = mounts
                .into_iter()
                .map(|m| {
                    let joined = if rest.is_empty() {
                        m
                    } else {
                        format!("{}{rest}", m.trim_end_matches('/'))
                    };
                    normalize::for_record(&joined, Platform::Linux)
                })
                .collect();
            return out;
        }

        // `%REMOVABLE%` — 마운트된 이동식 매체.
        if let Some(rest) = local::strip_token(root, "%REMOVABLE%") {
            if !allow_removable {
                // **선언이 동의를 대신한다** (설계-03 §4).
                out.notes.push(remedy_sdk::i18n::current().pick(
                    format!("{root}: allow_removable 을 선언하지 않아 펼치지 않았습니다"),
                    format!("{root}: not expanded because allow_removable was not declared"),
                ));
                return out;
            }
            let mut mounts: Vec<String> = sysinfo::Disks::new_with_refreshed_list()
                .iter()
                .filter(|d| d.is_removable())
                .map(|d| d.mount_point().to_string_lossy().to_string())
                .collect();
            // `sysinfo` 가 이동식으로 보지 못하는 마운트가 있다(USB 를 udisks 가
            // 붙인 경우 등). 관례 자리 아래의 마운트도 함께 본다 — **못 본 매체는
            // 감염된 채 남고, 그 매체가 다음 기계로 간다.**
            for parent in REMOVABLE_PARENTS {
                if let Ok(rd) = std::fs::read_dir(parent) {
                    for e in rd.flatten() {
                        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            mounts.push(e.path().to_string_lossy().to_string());
                        }
                    }
                }
            }
            mounts.sort();
            mounts.dedup();
            if mounts.is_empty() {
                // 꽂힌 것이 없는 것은 정상이다. 그래도 말은 해 둔다.
                out.notes.push(remedy_sdk::i18n::current().pick(
                    format!("{root}: 연결된 이동식 매체가 없습니다"),
                    format!("{root}: no removable media is attached"),
                ));
            }
            out.roots = mounts
                .into_iter()
                .map(|m| {
                    normalize::for_record(
                        &format!("{}{rest}", m.trim_end_matches('/')),
                        Platform::Linux,
                    )
                })
                .collect();
            return out;
        }

        // 그 밖은 1:1 환경변수 전개다.
        out.roots = vec![normalize::for_record(&self.expand(root), Platform::Linux)];
        out
    }
}

/// **파일 계열은 이식 백엔드가 그대로 한다** (설계-09 P12 순서 8).
///
/// # 왜 위임인가
///
/// [`FsRestore`] 는 P5 부터 *"어느 OS 에서나 같게 동작하는 부분"* 으로 만들어져
/// 있었고 — 본문·수정 시각·읽기 전용 비트, 줄 편집, 구조적 설정, 디렉터리 —
/// 비-Windows 복원 경로가 이미 그것을 쓰고 있었다. 여기서 다시 적으면 **두 벌이
/// 갈라지고, 그 갈라짐은 Linux 쪽에서 아무도 보지 않는다.**
///
/// OS 고유인 것(mode·xattr)은 `meta.rs` 의 `#[cfg(unix)]` 가지가 이미 맡는다.
///
/// # 아직 하지 않는 것
///
/// [`NOT_IMPLEMENTED_YET`] 에 이유와 함께 적혀 있고, 그 목록이 비어야 P12 의
/// 게이트가 올라간다. 적지 않고 `Unsupported` 만 남기면 "구현이 없다" 가
/// **조용한 상태**가 된다.
impl PlatformWrite for Live {
    fn backend_name(&self) -> &'static str {
        "linux"
    }

    // ── 재부팅 후 검증 예약 (설계-03 §8 · P12) ──────────────────────
    //
    // 설계-03 §8 이 정한 리눅스 분기 — *"Linux: systemd oneshot 또는 `@reboot`"* —
    // 의 앞쪽이다. 유닛의 모양과 그 까닭은 아래 `verify_unit_body` 곁에 모았다.

    fn verify_after_reboot_support(&self) -> Result<(), PlatformError> {
        verify_support_in(
            std::path::Path::new(SYSTEMD_RUN_DIR),
            std::path::Path::new(SYSTEMD_UNIT_DIR),
            std::path::Path::new(MOUNTINFO),
        )
    }

    fn scheduled_verify_site(&self) -> Option<VerifySite> {
        Some(VerifySite {
            location: verify_unit_path(std::path::Path::new(SYSTEMD_UNIT_DIR))
                .to_string_lossy()
                .to_string(),
            removed_by: RemovedBy::Itself,
        })
    }

    fn schedule_verify_after_reboot(
        &self,
        run_id: &str,
        exe: &std::path::Path,
        plugin: &std::path::Path,
        state_dir: Option<&std::path::Path>,
        lang: remedy_sdk::i18n::Lang,
    ) -> Result<(), PlatformError> {
        // 물어서 안 되는 기계에는 심지 않는다 — 부팅 때 읽을 systemd 가 없으면
        // 심은 유닛은 흔적일 뿐이다.
        self.verify_after_reboot_support()?;
        schedule_verify_in(
            std::path::Path::new(SYSTEMD_UNIT_DIR),
            run_id,
            exe,
            plugin,
            state_dir,
            lang,
        )
    }

    fn cancel_scheduled_verify(&self) -> Result<(), PlatformError> {
        // **systemd 가 없는 기계에서도 성공이다** — 지울 것이 없고, 그것이 바라는
        // 상태다. 트레이트 기본값이 그 이유로 `Ok` 를 돌려주던 것을 그대로 잇는다.
        remove_verify_unit(std::path::Path::new(SYSTEMD_UNIT_DIR))
    }

    fn scheduled_verify(&self) -> Result<Option<String>, PlatformError> {
        read_verify_unit(std::path::Path::new(SYSTEMD_UNIT_DIR))
    }

    fn plan_restore(&self, dest: &str, meta: &FileMeta) -> RestoreReport {
        FsRestore.plan_restore(dest, meta)
    }

    fn restore_file(
        &self,
        dest: &str,
        content: &[u8],
        meta: &FileMeta,
    ) -> Result<RestoreReport, PlatformError> {
        FsRestore.restore_file(dest, content, meta)
    }

    fn quarantine_read(&self, path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
        FsRestore.quarantine_read(path)
    }

    fn destroy_file(&self, path: &str) -> Result<(), PlatformError> {
        FsRestore.destroy_file(path)
    }

    fn exists(&self, path: &str) -> bool {
        FsRestore.exists(path)
    }

    // ── 줄 단위 설정 (`text_config.remove_line` · `hosts.restore_line`) ──

    fn text_line_read(&self, path: &str, line_no: u32) -> Result<String, PlatformError> {
        FsRestore.text_line_read(path, line_no)
    }

    fn text_line_remove(&self, path: &str, line_no: u32, line: &str) -> Result<(), PlatformError> {
        FsRestore.text_line_remove(path, line_no, line)
    }

    fn text_line_restore(&self, path: &str, line_no: u32, line: &str) -> Result<(), PlatformError> {
        FsRestore.text_line_restore(path, line_no, line)
    }

    // ── 구조적 설정 (`structured_config.remove_key`) ────────────────

    fn structured_remove_key(&self, path: &str, key_path: &str) -> Result<(), PlatformError> {
        FsRestore.structured_remove_key(path, key_path)
    }

    fn structured_set_key(
        &self,
        path: &str,
        key_path: &str,
        value: &str,
    ) -> Result<(), PlatformError> {
        FsRestore.structured_set_key(path, key_path, value)
    }

    // ── 디렉터리 (`browser_ext.remove`) ─────────────────────────────

    fn is_dir(&self, path: &str) -> bool {
        FsRestore.is_dir(path)
    }

    fn dir_read(&self, path: &str) -> Result<(Vec<u8>, DirIndex), PlatformError> {
        FsRestore.dir_read(path)
    }

    fn dir_destroy(&self, path: &str) -> Result<(), PlatformError> {
        FsRestore.dir_destroy(path)
    }

    fn dir_restore(
        &self,
        path: &str,
        content: &[u8],
        index: &DirIndex,
    ) -> Result<RestoreReport, PlatformError> {
        FsRestore.dir_restore(path, content, index)
    }

    // ── 지속성 (cron · systemd) ─────────────────────────────────────

    /// 이 항목이 아직 **있는가**. 재기동한 실행기가 *"내가 이미 지웠나"* 를
    /// 묻는 자리다.
    ///
    /// # 도는가가 아니라 있는가다
    ///
    /// 원래 여기가 *"줄이 남아 있고 주석이 아니면"* 이었다. 그 뜻으로는
    /// **`persistence.delete` 가 통째로 건너뛰어진다** — `disable` 이 먼저
    /// 돌며 줄에 `#` 를 붙이고, 그러면 이 함수가 "없다" 를 말하고, 실행기가
    /// `if !persistence_exists { return Ok(()) }` 로 삭제를 건너뛴다.
    ///
    /// 결과는 실행기가 *"수행 [5] persistence.delete"* 를 보고하는데 악성
    /// cron 줄이 `#` 하나 붙은 채 디스크에 남는 것이다. 되살리는 데 한 글자면
    /// 된다. 2026-09-03 Linux 하네스가 실기기에서 이것을 봤다.
    ///
    /// 차례를 `disable → delete` 로 둔 이유가 바로 그 반대였다 — *"비활성화만
    /// 하면 정의가 그대로 남고, 사용자는 꺼진 악성 항목을 본다"*(설계-03 §2).
    ///
    /// **`disable` 의 멱등성은 이 함수가 지키던 것이 아니다.**
    /// [`persistence_disable`](Self::persistence_disable) 이 자기 안에서 이미
    /// 주석 여부를 보고 그대로 돌아간다. 그래서 뜻을 존재로 바꿔도 그쪽은
    /// 그대로다.
    ///
    /// Windows 쪽(`task_file` 이 있는가)도 처음부터 **존재**였다. Linux 만
    /// 달랐다.
    fn persistence_exists(&self, id: &str) -> bool {
        match cron_at(id) {
            Some((file, line_no)) => nth_line(&file, line_no).is_ok(),
            None => std::path::Path::new(id).exists(),
        }
    }

    /// 정의와 **곁가지**를 읽어 낸다.
    ///
    /// systemd 의 활성화는 유닛 파일 안에 없고 `<target>.wants/` 아래의 링크다.
    /// 그것을 함께 담지 않으면 복원한 유닛이 **꺼진 채로** 돌아온다.
    fn persistence_read(&self, id: &str) -> Result<(Vec<u8>, PersistenceIndex), PlatformError> {
        match cron_at(id) {
            Some((file, line_no)) => {
                let line = nth_line(&file, line_no)?;
                Ok((line.into_bytes(), PersistenceIndex::default()))
            }
            None => {
                let bytes = std::fs::read(id).map_err(|e| PlatformError::io(id, e))?;
                Ok((
                    bytes,
                    PersistenceIndex {
                        links: wants_links(id),
                    },
                ))
            }
        }
    }

    /// 끈다. 정의는 남는다.
    ///
    /// | | 무엇을 하는가 |
    /// |---|---|
    /// | cron | 줄 앞에 `#` 를 붙인다 |
    /// | systemd | `<target>.wants/` 아래의 링크를 지운다 — `systemctl disable` 이 하는 일 그대로다 |
    ///
    /// **`systemctl` 을 부르지 않는다.** `--user` 유닛은 그 사용자의 세션 버스를
    /// 요구하는데 root 로 도는 치료 도구에는 그것이 없고, 사용자 유닛이 가장 흔한
    /// 지속성 자리다. 컨테이너처럼 systemd 가 pid 1 이 아닌 곳에서도 된다.
    fn persistence_disable(&self, id: &str, at: Option<&LineAt>) -> Result<(), PlatformError> {
        match cron_at(id) {
            Some((file, line_no)) => {
                let at = require_line(at, id)?;
                let cur = expect_line(&file, line_no, at)?;
                // 이미 꺼져 있으면 그대로 둔다. 멱등해야 한다 (설계-03 §5).
                if cur.trim_start().starts_with('#') {
                    return Ok(());
                }
                replace_line(&file, line_no, &format!("#{cur}"))
            }
            None => {
                for l in wants_links(id) {
                    std::fs::remove_file(&l).map_err(|e| PlatformError::io(&l, e))?;
                }
                Ok(())
            }
        }
    }

    /// 지운다. cron 은 줄을, systemd 는 유닛 파일과 링크를 함께 지운다.
    ///
    /// **링크를 남기면 같은 이름의 유닛이 다시 놓였을 때 곧바로 부활한다.**
    fn persistence_delete(&self, id: &str, at: Option<&LineAt>) -> Result<(), PlatformError> {
        match cron_at(id) {
            Some((file, line_no)) => {
                let at = require_line(at, id)?;
                expect_line(&file, line_no, at)?;
                remove_line(&file, line_no)
            }
            None => {
                for l in wants_links(id) {
                    std::fs::remove_file(&l).map_err(|e| PlatformError::io(&l, e))?;
                }
                std::fs::remove_file(id).map_err(|e| PlatformError::io(id, e))
            }
        }
    }

    /// 담아 둔 정의로 되돌린다. **곁가지까지 되돌린다.**
    fn persistence_restore(
        &self,
        id: &str,
        content: &[u8],
        index: &PersistenceIndex,
    ) -> Result<(), PlatformError> {
        match cron_at(id) {
            Some((file, line_no)) => {
                let line = String::from_utf8_lossy(content).to_string();
                insert_line(&file, line_no, line.trim_end_matches(['\r', '\n']))
            }
            None => {
                std::fs::write(id, content).map_err(|e| PlatformError::io(id, e))?;
                for l in &index.links {
                    if let Some(dir) = std::path::Path::new(l).parent() {
                        std::fs::create_dir_all(dir)
                            .map_err(|e| PlatformError::io(dir.to_string_lossy(), e))?;
                    }
                    // 이미 있으면 그대로 둔다 — 복원은 멱등해야 한다.
                    if std::path::Path::new(l).exists() {
                        continue;
                    }
                    std::os::unix::fs::symlink(id, l).map_err(|e| PlatformError::io(l, e))?;
                }
                Ok(())
            }
        }
    }

    /// `.desktop` 의 `Exec=` 에서 **인자만** 뗀다 (설계-09 P12 순서 9).
    ///
    /// [`FsRestore`] 의 것은 `.lnk` 이진 파서라 여기서 쓸 수 없다. 형식이 다를
    /// 뿐 하는 일은 같다 — 바로가기는 **명령을 숨기기 좋은 자리**이고, 아이콘과
    /// 이름은 정상 프로그램의 것을 쓰면서 인자만 바꾸면 사용자에게는 원래
    /// 프로그램으로 보인다.
    ///
    /// **필드 코드(`%U`·`%f`)는 남긴다.** 그것은 인자가 아니라 실행할 때 치환되는
    /// 자리표시자이고, 지우면 항목이 원래 하던 일을 못 한다.
    fn shortcut_strip_args(&self, path: &str, expect: &str) -> Result<(), PlatformError> {
        let text = std::fs::read_to_string(path).map_err(|e| PlatformError::io(path, e))?;

        // **계획이 본 인자와 맞춰 본다.** 수집과 실행 사이에 사용자가 정당한
        // 인자를 붙였다면 지금 있는 것을 그냥 떼는 것은 계획에 없는 파괴다.
        // 인자가 이미 없으면 목표 상태가 이루어진 것이다 — 재기동에서 흔하다.
        match crate::write::desktop_exec_args(&text) {
            None => return Ok(()),
            Some(now) if now.trim().is_empty() => return Ok(()),
            Some(now) if crate::write::same_args(&now, expect) => {}
            Some(_) => {
                return Err(PlatformError::refused(
                    "그 바로가기의 인자가 계획과 다릅니다 — 아무것도 지우지 않았습니다".into(),
                    "the shortcut's arguments differ from the plan — nothing was removed".into(),
                ))
            }
        }

        let mut out = String::with_capacity(text.len());
        let mut in_entry = false;
        let mut changed = false;
        for raw in text.lines() {
            let line = raw.trim_start();
            if line.starts_with('[') && line.ends_with(']') {
                in_entry = line.eq_ignore_ascii_case("[Desktop Entry]");
            } else if in_entry {
                if let Some(v) = line.strip_prefix("Exec=") {
                    // **가르는 규칙은 한 곳에 있다** (`write::split_exec`).
                    // 수집기가 "인자" 라고 담은 것과 여기서 떼는 것이 갈라지면
                    // 위의 맞춰 보기가 영영 어긋난다.
                    let cmd = crate::write::split_exec(v).0;
                    let keep: Vec<&str> = v
                        .split_whitespace()
                        .skip(1)
                        .filter(|a| a.len() == 2 && a.starts_with('%'))
                        .collect();
                    let next = if keep.is_empty() {
                        format!("Exec={cmd}")
                    } else {
                        format!("Exec={cmd} {}", keep.join(" "))
                    };
                    if next != format!("Exec={v}") {
                        changed = true;
                    }
                    out.push_str(&next);
                    out.push('\n');
                    continue;
                }
            }
            out.push_str(raw);
            out.push('\n');
        }
        if !changed {
            // 인자가 없다. 목표 상태는 이미 이루어졌다 — 재기동에서 흔하다.
            return Ok(());
        }
        std::fs::write(path, out).map_err(|e| PlatformError::io(path, e))
    }

    // ── 서비스 (systemd `.service`) ─────────────────────────────────
    //
    // 지속성의 유닛 경로와 **같은 일**이다. `.service` 와 `.timer` 를 가르는 것은
    // subject 이지 파일 다루는 법이 아니다 (설계-09 P12 순서 9).
    //
    // **정지만 systemd 에게 시킨다** (결정 A, 2026-09-29). 끄고 지우는 것은 파일이고,
    // 돌고 있는 것을 멈추는 일은 서비스 관리자의 몫이다 — 파일만 지우고 프로세스를
    // 죽이면 systemd 가 메모리의 정의로 되살렸다(`Restart=` 실증).
    //
    // `service.clear_recovery` 는 여기 없다 — 카탈로그가 `linux_from: None` 으로
    // 닫아 두었고, 정지가 먼저 돌면 필요도 없다.

    /// systemd 가 PID 1 이면 **돈다고 본다.**
    ///
    /// `systemctl is-active` 로 묻지 않는다. 그것은 `activating (auto-restart)` — 죽은
    /// 뒤 되살아나기를 기다리는 유닛 — 를 "돌지 않는다" 로 답하는데, 그런 유닛이야말로
    /// 멈춰야 예약된 재기동이 취소된다. 정지는 멱등하다 — 멈춘 유닛을 멈춰도 종료
    /// 코드는 0 이다 (2026-09-29 랩 VM 실측).
    ///
    /// 대상이 옳은지는 여기서 보지 않는다. 틀린 대상은 [`service_stop`] 이 **거부로
    /// 말한다** — 여기서 `false` 를 내면 실행기가 "이미 멈췄다" 로 읽고 성공을 적는다.
    ///
    /// [`service_stop`]: PlatformWrite::service_stop
    fn service_running(&self, _target: &str) -> bool {
        std::path::Path::new(SYSTEMD_RUN_DIR).is_dir()
    }

    fn service_stop(&self, target: &str) -> Result<(), PlatformError> {
        stop_unit_in(std::path::Path::new(SYSTEMD_RUN_DIR), &SYSTEMCTL, target)
    }

    fn service_disable(&self, target: &str) -> Result<(), PlatformError> {
        for l in wants_links(target) {
            std::fs::remove_file(&l).map_err(|e| PlatformError::io(&l, e))?;
        }
        Ok(())
    }

    fn service_delete(&self, target: &str) -> Result<(), PlatformError> {
        for l in wants_links(target) {
            std::fs::remove_file(&l).map_err(|e| PlatformError::io(&l, e))?;
        }
        std::fs::remove_file(target).map_err(|e| PlatformError::io(target, e))
    }

    // ── 신뢰 저장소의 인증서 (P12) ────────────────────────────

    fn cert_read(&self, path: &str) -> Result<Vec<u8>, PlatformError> {
        std::fs::read(path).map_err(|e| PlatformError::io(path, e))
    }

    fn cert_exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    fn cert_delete(&self, path: &str) -> Result<(), PlatformError> {
        // **다시 만들 수 없으면 지우지도 않는다.** 순서가 반대면 배포판이 달라
        // 도구가 없는 기계에서 파일만 사라지고 신뢰는 그대로 남는다 — 그것이
        // 가장 나쁜 상태다. 치료가 안 됐는데 증거가 없어졌다.
        self.ca_tool()?;
        std::fs::remove_file(path).map_err(|e| PlatformError::io(path, e))?;
        // 여기까지는 치료가 아니다. 번들에 아직 남아 있다.
        self.refresh_ca_store()
    }

    fn cert_restore(&self, path: &str, content: &[u8]) -> Result<(), PlatformError> {
        if let Some(dir) = std::path::Path::new(path).parent() {
            // 폴더째 사라졌을 수 있다 — `/usr/local/share/ca-certificates` 는
            // 인증서를 하나도 더하지 않은 기계에 아예 없다.
            std::fs::create_dir_all(dir)
                .map_err(|e| PlatformError::io(dir.to_string_lossy().as_ref(), e))?;
        }
        std::fs::write(path, content).map_err(|e| PlatformError::io(path, e))?;
        self.refresh_ca_store()
    }

    /// 유닛 정의가 아직 있는가. 재기동한 실행기가 묻는 자리다.
    ///
    /// **`registry_key_exists` 라는 이름으로 오는 것이 이 물음이다** — 실행기의
    /// `service.delete` 가지가 그것을 쓴다. Windows 에서 서비스 정의가
    /// 레지스트리 키라 그렇게 이름 붙었고, Linux 에서는 유닛 파일이다.
    fn registry_key_exists(&self, key: &str) -> bool {
        std::path::Path::new(key).exists()
    }

    // ── 프로세스 (`process.kill`) ───────────────────────────────────

    /// 술어가 지목한 프로세스.
    ///
    /// **빈 술어는 모든 프로세스를 뜻한다.** 그것을 돌려주면 이 문이 임의
    /// 열거가 된다 (설계-04 §1) — Windows 쪽과 같은 판단이다.
    fn processes_matching(&self, p: &KillPredicate) -> Result<Vec<Target>, PlatformError> {
        if p.is_empty() {
            return Err(PlatformError::refused(
                "술어가 비어 있습니다. 무엇을 종료할지 계획이 말하지 않았습니다".into(),
                "the predicate is empty; the plan does not say what to terminate".into(),
            ));
        }
        let mut out: Vec<Target> = local::processes(self)?
            .into_iter()
            .filter(|r| {
                // 경로는 **완전 일치**다. Linux 파일 시스템은 대소문자를 가리므로
                // 접어서 비교하면 서로 다른 파일이 같은 것으로 읽힌다.
                if let Some(want) = &p.image_path {
                    if &r.image_path != want {
                        return false;
                    }
                }
                if let Some(needle) = &p.cmdline_contains {
                    if !r.cmdline.to_lowercase().contains(&needle.to_lowercase()) {
                        return false;
                    }
                }
                true
            })
            .map(|r| Target {
                pid: r.pid,
                image_path: r.image_path,
                cmdline: r.cmdline,
            })
            .collect();
        out.sort_by_key(|t| t.pid);
        Ok(out)
    }

    /// 프로세스를 종료한다.
    ///
    /// # 왜 `sysinfo` 이고 `kill(2)` 가 아닌가
    ///
    /// `libc::kill` 은 unsafe 다. 이 크레이트는 `forbid(unsafe_code)` 를 유지하고,
    /// 그 근거는 SDDL·복원처럼 이미 안전 래퍼로 해결한 자리들과 같다.
    ///
    /// # 이미 없는 것을 실패로 읽지 않는다
    ///
    /// 종료 요청과 실제 종료 사이에 프로세스가 스스로 끝날 수 있다. 그것은
    /// 우리가 원한 상태이므로 실패가 아니다 — **진짜 답은 재평가가 준다.**
    /// 실행기가 곧바로 다시 훑어 남은 것을 센다 (Windows 의 `taskkill` 종료
    /// 코드를 무시하는 것과 같은 이유).
    fn process_kill(&self, pids: &[u32]) -> Result<(), PlatformError> {
        if pids.is_empty() {
            return Ok(());
        }
        let mut sys = sysinfo::System::new();
        local::refresh_all_processes(&mut sys);
        for pid in pids {
            if let Some(p) = sys.process(sysinfo::Pid::from_u32(*pid)) {
                // SIGKILL 이다. `kill()` 이 기본으로 그것을 보낸다.
                //
                // SIGTERM 을 먼저 보내지 않는 이유는 대상이 **악성코드**이기
                // 때문이다 — 정리할 기회를 주면 그 사이에 자기를 다시 심는다.
                p.kill();
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────── 지속성 항목의 두 모양

/// `id` 가 **cron 줄**을 가리키면 `(파일, 줄 번호)`.
///
/// # 왜 `id` 의 모양으로 가르는가
///
/// 수집기가 그렇게 짓는다 — cron 항목에는 이름이 없어 *"그 항목이 등록된 자리"*
/// 가 파일과 줄이고, systemd 유닛은 그 자리가 유닛 파일이다 (`cron.rs` ·
/// `systemd.rs`). 계획기는 `id` 를 그대로 대상으로 쓴다.
///
/// 마지막 `:` 뒤가 숫자일 때만 줄로 읽는다. 파일 이름에 `:` 가 들어갈 수 있고,
/// 그때 잘못 가르면 **엉뚱한 파일의 줄을 고친다.**
fn cron_at(id: &str) -> Option<(String, u32)> {
    let (file, n) = id.rsplit_once(':')?;
    let line_no: u32 = n.parse().ok()?;
    (line_no > 0 && !file.is_empty()).then(|| (file.to_string(), line_no))
}

/// 줄 자리가 필요한데 계획이 주지 않았다.
///
/// **조용히 번호만으로 고치지 않는다.** 그것이 이 계약을 넓힌 이유다
/// (설계-09 P12 결정 5).
fn require_line<'a>(at: Option<&'a LineAt>, id: &str) -> Result<&'a LineAt, PlatformError> {
    at.ok_or_else(|| {
        PlatformError::refused(
            format!(
                "{id}: 계획에 줄 내용이 없습니다. 번호만으로 고치면 그 사이에 파일이 \
                 바뀌었을 때 정상 작업을 멈춥니다"
            ),
            format!(
                "{id}: the plan has no line content. Fixing by number alone stops a healthy \
                 job when the file changed in between"
            ),
        )
    })
}

fn read_lines(file: &str) -> Result<Vec<String>, PlatformError> {
    let bytes = std::fs::read(file).map_err(|e| PlatformError::io(file, e))?;
    // 비 UTF-8 바이트가 있어도 **읽지 못해 아무것도 못 하는 것보다 낫다.** 그런
    // 줄은 내용 대조에서 어긋나 그 Action 이 실패하고, 그것이 안전한 실패다.
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .map(|l| l.to_string())
        .collect())
}

fn nth_line(file: &str, line_no: u32) -> Result<String, PlatformError> {
    let lines = read_lines(file)?;
    lines.get(line_no as usize - 1).cloned().ok_or_else(|| {
        PlatformError::refused(
            format!("{file}: {line_no}번 줄이 없습니다"),
            format!("{file}: there is no line {line_no}"),
        )
    })
}

/// 그 줄이 **계획이 본 그 줄인가.** 아니면 아무것도 하지 않는다.
///
/// 주석이 이미 붙어 있는 경우도 같은 줄로 본다 — `persistence_disable` 이 한 번
/// 돌고 재기동한 실행기가 다시 돌 수 있고, 그때 대조가 어긋나면 멱등하지 않다.
fn expect_line(file: &str, line_no: u32, at: &LineAt) -> Result<String, PlatformError> {
    let cur = nth_line(file, line_no)?;
    let bare = cur.trim_start().strip_prefix('#').unwrap_or(&cur).trim();
    if bare != at.line.trim() {
        return Err(PlatformError::refused(
            format!("{file}:{line_no} 의 내용이 계획과 다릅니다. 그 사이에 파일이 바뀌었습니다"),
            format!("{file}:{line_no} does not match the plan; the file changed in between"),
        ));
    }
    Ok(cur)
}

fn write_lines(file: &str, lines: &[String]) -> Result<(), PlatformError> {
    let mut out = lines.join("\n");
    // 끝의 줄바꿈을 지키지 않으면 cron 이 마지막 줄을 무시한다.
    out.push('\n');
    std::fs::write(file, out).map_err(|e| PlatformError::io(file, e))
}

fn replace_line(file: &str, line_no: u32, with: &str) -> Result<(), PlatformError> {
    let mut lines = read_lines(file)?;
    let i = line_no as usize - 1;
    if i >= lines.len() {
        return Err(PlatformError::refused(
            format!("{file}: {line_no}번 줄이 없습니다"),
            format!("{file}: there is no line {line_no}"),
        ));
    }
    lines[i] = with.to_string();
    write_lines(file, &lines)
}

fn remove_line(file: &str, line_no: u32) -> Result<(), PlatformError> {
    let mut lines = read_lines(file)?;
    let i = line_no as usize - 1;
    if i >= lines.len() {
        return Err(PlatformError::refused(
            format!("{file}: {line_no}번 줄이 없습니다"),
            format!("{file}: there is no line {line_no}"),
        ));
    }
    lines.remove(i);
    write_lines(file, &lines)
}

fn insert_line(file: &str, line_no: u32, line: &str) -> Result<(), PlatformError> {
    let mut lines = read_lines(file).unwrap_or_default();
    let i = (line_no as usize - 1).min(lines.len());
    lines.insert(i, line.to_string());
    write_lines(file, &lines)
}

/// 이 유닛을 가리키는 **활성화 링크** 전부.
///
/// # 어디를 보는가
///
/// 유닛이 사는 폴더 아래의 `*.wants/` 와 `*.requires/` 다. 그 폴더 하나만 보는
/// 것은 **탐색이 아니다** — 계획이 지목한 대상의 자기 자리이고, 임의 경로가
/// 여기 들어올 길이 없다 (불변식 P).
///
/// 링크가 유닛과 **다른 폴더**에 있는 배치(`/etc/.../x.wants/y.service` 가
/// `/usr/lib` 의 유닛을 가리키는 경우)는 여기서 안 잡힌다. 그래서 아래 `systemd`
/// 검색 자리 전부를 훑는다 — 목록이 고정돼 있으므로 여전히 탐색이 아니다.
fn wants_links(unit: &str) -> Vec<String> {
    let Some(name) = unit.rsplit('/').next() else {
        return Vec::new();
    };
    let mut roots: Vec<String> = SYSTEM_UNIT_DIRS.iter().map(|d| d.to_string()).collect();
    // 유닛이 사는 폴더도 본다. 사용자 유닛(`%HOME%/.config/systemd/user`)이
    // 위 목록에 없기 때문이다.
    if let Some(dir) = unit.rsplit_once('/').map(|(d, _)| d.to_string()) {
        roots.push(dir);
    }
    roots.sort();
    roots.dedup();

    let mut out = Vec::new();
    for root in roots {
        let Ok(rd) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Some(dname) = p.file_name().and_then(|x| x.to_str()) else {
                continue;
            };
            if !(dname.ends_with(".wants") || dname.ends_with(".requires")) {
                continue;
            }
            let link = p.join(name);
            // `symlink_metadata` 다 — 가리키는 대상이 이미 없어도 링크 자체는
            // 있다. 그것을 못 보면 지우지 못한 링크가 남는다.
            if std::fs::symlink_metadata(&link).is_ok() {
                out.push(link.to_string_lossy().to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// systemd 시스템 유닛이 사는 자리. 링크도 이 아래에 있다.
const SYSTEM_UNIT_DIRS: [&str; 4] = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

// ── 서비스 정지 — systemd 에게 시킨다 (결정 A · 2026-09-29) ─────────────
//
// 부팅 표지(`run_dir`)와 도구 목록을 받는 순수 함수로 뗀다 — `verify_support_in`
// 과 같은 까닭이다. 시험이 **진짜 systemd 를 건드리지 않고** 모든 갈래를 잰다.

/// `service.stop` 을 한다.
///
/// - systemd 가 PID 1 이 아니면(컨테이너) **멈출 관리자가 없다** — 할 일이 없다.
///   그때 멈추는 일은 `process.kill` 이 한다.
/// - 대상은 시스템 유닛이어야 한다([`system_unit_name`]) — 거부는 도구를 부르기 전이다.
/// - `--no-block` 이다. 정지 **요청이 받아들여지면** 끝난다 — Windows 의 `sc.exe stop`
///   과 같은 뜻이고, 뒤따르는 `process.kill` 이 마무리한다. 요청이 걸린 유닛은 그
///   사이에 주 프로세스가 죽어도 되살아나지 않는다 — 랩 VM 에서 정지 요청 직후의
///   SIGKILL 10번이 한 번도 되살아나지 않았다. 기다리면 `ExecStop` 이 매달린
///   유닛에서 `TimeoutStopSec` 만큼 멈춘다.
fn stop_unit_in(
    run_dir: &std::path::Path,
    tools: &[&str],
    target: &str,
) -> Result<(), PlatformError> {
    if !run_dir.is_dir() {
        return Ok(());
    }
    let unit = system_unit_name(target)?;
    let exe = tools
        .iter()
        .copied()
        .find(|t| std::path::Path::new(t).is_file())
        .ok_or_else(|| {
            let tools = tools.join(" · ");
            PlatformError::refused(
                format!("systemd 가 PID 1 인데 systemctl 이 없습니다 ({tools})"),
                format!("systemd is PID 1 but there is no systemctl ({tools})"),
            )
        })?;
    stop_unit_with(exe, &unit)
}

/// 시스템 유닛 파일의 경로에서 유닛 이름을 꺼낸다. **시스템 유닛 자리 바로 아래의
/// `.service` 가 아니면 거부한다.**
///
/// 계획기가 사용자 유닛을 미루므로 여기 오는 것은 대개 옳다 — 이것은 두 번째 겹이다.
/// 사용자 유닛을 시스템 관리자에게 멈추라고 하면 **같은 이름의 시스템 유닛**이 멈출
/// 수 있다. 이름의 글자도 systemd 유닛 이름의 것만 받는다 — 인자로 넘어가는 문자열이다.
fn system_unit_name(target: &str) -> Result<String, PlatformError> {
    let p = std::path::Path::new(target);
    let dir = p.parent().and_then(|d| d.to_str()).unwrap_or_default();
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let unit_chars = |b: u8| b.is_ascii_alphanumeric() || b"-_.:@\\".contains(&b);
    let stem = name.strip_suffix(".service").unwrap_or_default();
    if SYSTEM_UNIT_DIRS.contains(&dir) && !stem.is_empty() && name.bytes().all(unit_chars) {
        return Ok(name.to_string());
    }
    Err(PlatformError::refused(
        format!(
            "'{target}' 는 systemd 시스템 유닛이 아닙니다 — 시스템 유닛 자리 바로 아래의 \
             .service 만 systemd 에게 멈추게 합니다"
        ),
        format!(
            "'{target}' is not a systemd system unit — only a .service directly under a \
             system unit directory is handed to systemd to stop"
        ),
    ))
}

/// `systemctl stop --no-block -- <유닛>` 을 부르고 종료 코드를 뜻으로 옮긴다.
///
/// | 코드 | 뜻 (systemd 252 실측) | |
/// |---|---|---|
/// | 0 | 요청이 받아들여졌다 · 이미 멈춰 있었다 | 성공 |
/// | 5 | 그런 유닛이 로드되지 않았다 | 성공 — **멈출 것이 없다** (다시 도는 실행기가 이미 지운 유닛을 만난다) |
/// | 4 | 거부 (`RefuseManualStop=`) | 실패 |
/// | 1 | 그 밖 (템플릿 파일 이름 등) | 실패 |
///
/// `--` 뒤에 둔다 — 이름이 `-` 로 시작해도 옵션으로 읽히지 않는다.
fn stop_unit_with(systemctl: &str, unit: &str) -> Result<(), PlatformError> {
    let mut cmd = std::process::Command::new(systemctl);
    cmd.args(["stop", "--no-block", "--", unit]);
    let out = crate::tool::run_tool(cmd, "systemctl stop", crate::tool::WARN_SHORT)
        .map_err(|e| PlatformError::io(systemctl, e))?;
    match out.code {
        Some(0) | Some(5) => Ok(()),
        _ => Err(PlatformError::Refused(out.reason("systemctl stop"))),
    }
}

// ── 재부팅 후 검증 예약 — 유닛 파일 (설계-03 §8 · P12) ─────────────────
//
// **systemd oneshot 을 파일로만 심는다.** `systemctl` 을 부르지 않는 것은 이
// 백엔드의 원칙이다(`persistence_delete`) — 예외는 돌고 있는 것을 멈추는
// `service.stop` 하나다(결정 A). 부팅 때 systemd 가 `.wants/` 를 새로
// 읽으므로 `daemon-reload` 도 필요 없다.
//
// **유닛이 실행 직전에 자기를 지운다** (자기 흔적 규칙 2). Windows 가 RunOnce 를
// 고른 결정적 이유가 *"OS 가 실행 직전에 지운다"* 였다 — systemd 는 유닛을
// 스스로 지우지 않으므로 `ExecStartPre=-` 가 그 자리를 대신한다. `verify` 가
// 시작조차 못 해도(바이너리가 옮겨졌다 등) 흔적이 남지 않는다. `verify` 가 맨
// 먼저 하는 삭제(`cmd_verify` → `clear_scheduled_verify`)는 두 번째 안전장치로
// 그대로 둔다.
//
// **범용 예약이 아니다** — 이름도 명령도 고정이다(트레이트 머리의 경고 그대로).
// 여기서 지우는 것도 우리 이름 둘뿐이다.
//
// 근거는 내부 기록에 있다.

/// systemd 가 PID 1 인가를 알려 주는 자리. `sd_booted(3)` 이 보는 그것이다.
const SYSTEMD_RUN_DIR: &str = "/run/systemd/system";

/// 관리자가 두는 유닛의 자리. 배포판 유닛(`/usr/lib/systemd/system`)보다 앞선다.
const SYSTEMD_UNIT_DIR: &str = "/etc/systemd/system";

/// 부팅 때 이 유닛을 끌어올리는 대상. **로그온이 아니라 부팅이다** — RunOnce 는
/// 로그온 때 돌아, 로그온하지 않는 서버에서는 검증이 일어나지 않는다(설계-03 §8).
const VERIFY_WANTED_BY: &str = "multi-user.target";

/// 유닛이 자기를 지울 때 부르는 도구. 이 백엔드는 도구를 **절대 경로로만** 부른다
/// (`os_tools_are_named_by_absolute_path`) — 유닛도 같은 규율을 따른다.
const RM: &str = "/bin/rm";

fn verify_unit_name() -> String {
    format!("{}.service", crate::write::SCHEDULED_VERIFY_NAME)
}

fn verify_unit_path(unit_dir: &std::path::Path) -> std::path::PathBuf {
    unit_dir.join(verify_unit_name())
}

fn verify_link_path(unit_dir: &std::path::Path) -> std::path::PathBuf {
    unit_dir
        .join(format!("{VERIFY_WANTED_BY}.wants"))
        .join(verify_unit_name())
}

/// 유닛을 바꿔 끼우기 전에 쓰는 자리. 유닛 접미사가 아니라 systemd 가 읽지 않는다.
fn verify_tmp_path(unit_dir: &std::path::Path) -> std::path::PathBuf {
    unit_dir.join(format!("{}.remedy-tmp", verify_unit_name()))
}

/// 마운트 표. 유닛 자리가 **읽기 전용 파일 시스템**에 있는지를 여기서 읽는다.
const MOUNTINFO: &str = "/proc/self/mountinfo";

/// 이 기계에서 예약할 수 있는가 (P12 D3). **묻기만 한다** — 아무것도 쓰지 않는다.
///
/// # 쓸 수 있는가를 써 보지 않고 잰다
///
/// 이 질의는 승인 **전에** 불린다. 써 보고 지우면 승인 전에 기계를 만진 것이고,
/// 지우다 실패하면 그것이 곧 흔적이다. 그래서 **마운트 표**를 본다 — 유닛 자리가
/// 읽기 전용으로 마운트됐으면 root 라도 못 쓴다. NixOS 가 그 자리다
/// (`/etc/systemd/system` 이 읽기 전용 `/nix/store` 를 가리킨다). 링크를 따라간
/// 실제 자리로 재는 이유가 그것이다.
///
/// **권한은 재지 않는다.** 기계를 만지는 명령은 관리자 문(`admin_gate`)을 먼저
/// 지나고, 계획만 보여 주는 `plan` 은 root 가 아니어도 root 가 할 일을 말해야 한다.
fn verify_support_in(
    run_dir: &std::path::Path,
    unit_dir: &std::path::Path,
    mountinfo: &std::path::Path,
) -> Result<(), PlatformError> {
    if !run_dir.is_dir() {
        // 컨테이너·WSL·OpenRC 가 여기서 멈춘다. 유닛을 심어도 부팅 때 읽을
        // systemd 가 없다 — 그러면 심은 것은 흔적일 뿐이다.
        //
        // 이유는 **원인만** 적는다 — 화면이 이미 *"걸 수 없습니다"* 라고 말한다.
        return Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "systemd 가 이 기계의 init 이 아닙니다",
            "systemd is not this machine's init",
        )));
    }
    if !unit_dir.is_dir() {
        return Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "/etc/systemd/system 이 없습니다",
            "/etc/systemd/system does not exist",
        )));
    }
    let real = std::fs::canonicalize(unit_dir)
        .map_err(|e| PlatformError::io(unit_dir.to_string_lossy(), e))?;
    let table =
        std::fs::read(mountinfo).map_err(|e| PlatformError::io(mountinfo.to_string_lossy(), e))?;
    match mount_is_readonly(&real, &table) {
        Some(false) => Ok(()),
        Some(true) => Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "/etc/systemd/system 이 읽기 전용 파일 시스템에 있습니다",
            "/etc/systemd/system is on a read-only file system",
        ))),
        // 모르는 것을 "쓸 수 있다" 로 접지 않는다.
        None => Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "/etc/systemd/system 의 마운트를 찾지 못했습니다 — 쓸 수 있는지 모릅니다",
            "could not find the mount of /etc/systemd/system — cannot tell whether it is writable",
        ))),
    }
}

/// `path` 가 앉은 마운트가 읽기 전용인가. 표에서 그 마운트를 못 찾으면 `None`.
///
/// `proc(5)` 의 한 줄 — 다섯째가 마운트 자리, 여섯째가 마운트 옵션, `-` 뒤 셋째가
/// 슈퍼블록 옵션이다. **어느 쪽이든 `ro` 면 못 쓴다.** 가장 깊은 마운트가 이기고,
/// 같은 자리면 뒤엣것이 이긴다 — 나중 마운트가 앞의 것을 가린다.
///
/// 표를 바이트로 읽는다. 마운트 자리가 UTF-8 이 아닌 기계가 하나만 있어도
/// 문자열로 읽기는 통째로 실패한다.
fn mount_is_readonly(path: &std::path::Path, table: &[u8]) -> Option<bool> {
    let opt_ro = |opts: &[u8]| opts.split(|&c| c == b',').any(|o| o == b"ro");
    let mut best: Option<(usize, bool)> = None;
    for line in table.split(|&c| c == b'\n') {
        let f: Vec<&[u8]> = line.split(|&c| c == b' ').collect();
        let (Some(mp), Some(opts)) = (f.get(4), f.get(5)) else {
            continue;
        };
        // 선택 필드(`shared:1` …)는 개수가 정해져 있지 않고 `-` 가 그 끝이다.
        let Some(dash) = f.iter().skip(6).position(|x| *x == b"-").map(|i| i + 6) else {
            continue;
        };
        let mp = unescape_mount_field(mp);
        if !path.starts_with(&mp) {
            continue;
        }
        let depth = mp.components().count();
        let ro = opt_ro(opts) || f.get(dash + 3).is_some_and(|sb| opt_ro(sb));
        if best.is_none_or(|(d, _)| depth >= d) {
            best = Some((depth, ro));
        }
    }
    best.map(|(_, ro)| ro)
}

/// 마운트 표는 공백·탭·줄바꿈·역슬래시를 `\040` 같은 8진 셋으로 적는다 (`proc(5)`).
fn unescape_mount_field(b: &[u8]) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStringExt;
    let octal = |c: u8| (b'0'..=b'7').contains(&c).then(|| c - b'0');
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let esc = if b[i] == b'\\' {
            b.get(i + 1..i + 4)
                .and_then(|d| Some((octal(d[0])?, octal(d[1])?, octal(d[2])?)))
        } else {
            None
        };
        match esc {
            // `\777` 같은 것은 표에 나오지 않는다 — 나와도 멈추지 않게 감싼다.
            Some((x, y, z)) => {
                out.push(x.wrapping_mul(64).wrapping_add(y * 8 + z));
                i += 4;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    std::path::PathBuf::from(std::ffi::OsString::from_vec(out))
}

/// 경로가 유닛 파일에 **그대로** 적힐 수 있는가.
///
/// 공유 명령(`write::scheduled_verify_command`)이 경로를 `"…"` 로 감싼다. 경로 안의
/// `"`·`\` 는 systemd 의 인용 규칙과 부딪치고, 줄바꿈은 유닛 파일의 줄을 바꾼다.
/// **흔하지 않은 경로를 억지로 펴다 틀리느니 이유를 말하고 예약하지 않는다** —
/// 틀리게 펴면 재부팅 뒤 사용법 오류로 조용히 끝나는, P10 의 그 실패가 된다.
///
/// UTF-8 이 아닌 경로도 거절한다 — 유닛에 적는 순간 대체 문자로 뭉개져 **다른
/// 경로**가 된다.
fn plain_for_unit(p: &std::path::Path) -> Result<(), PlatformError> {
    let bad = match p.to_str() {
        Some(s) => s.chars().any(|c| c == '"' || c == '\\' || c.is_control()),
        None => true,
    };
    if bad {
        return Err(refuse_for_unit(p));
    }
    Ok(())
}

/// 실행 파일 자리. [`plain_for_unit`] 에 더해 `$` 를 거절한다.
///
/// systemd 는 **실행 파일 자리에서 변수를 펴지 않는다** (`systemd.service(5)` —
/// *"the first argument (i.e. the program to execute) may not be a variable"*).
/// 그러면 `$$` 로 적은 것이 `$` 로 돌아온다는 보장이 없고, 그대로 적은 `$` 가
/// 그대로 남는다는 보장도 문서에 없다. **추측으로 적느니 거절한다** — 틀리면
/// 재부팅 뒤 실행 파일을 못 찾고 조용히 끝난다.
fn plain_exe_for_unit(exe: &std::path::Path) -> Result<(), PlatformError> {
    plain_for_unit(exe)?;
    if exe.to_string_lossy().contains('$') {
        return Err(refuse_for_unit(exe));
    }
    Ok(())
}

fn refuse_for_unit(p: &std::path::Path) -> PlatformError {
    PlatformError::Refused(format!(
        "{} {}",
        remedy_sdk::i18n::t(
            "재부팅 뒤 검증 유닛에 안전하게 적을 수 없는 경로입니다:",
            "this path cannot be written safely into the verification unit:",
        ),
        p.display()
    ))
}

/// systemd 가 펴는 글자를 막는다. `%` 는 지정자(`%n`·`%i`…), `$` 는 환경 변수다 —
/// 그대로 적으면 경로가 바뀐다 (`systemd.unit(5)` · `systemd.service(5)`).
fn systemd_escape(s: &str) -> String {
    s.replace('%', "%%").replace('$', "$$")
}

/// [`systemd_escape`] 를 되돌린다. 되읽은 명령이 **예약한 명령과 같은가**를 재려고 둔다.
fn systemd_unescape(s: &str) -> String {
    s.replace("%%", "%").replace("$$", "$")
}

/// 유닛 파일의 내용. **한 곳에서만 만든다** — 되읽는 [`read_verify_unit`] 과 시험이
/// 같은 모양을 본다.
fn verify_unit_body(unit_dir: &std::path::Path, cmd: &str) -> String {
    let link = systemd_escape(&verify_link_path(unit_dir).to_string_lossy());
    let unit = systemd_escape(&verify_unit_path(unit_dir).to_string_lossy());
    let cmd = systemd_escape(cmd);
    format!(
        "# remedy: one-shot verification after reboot (design-03 section 8).\n\
         # It removes itself right before it runs. Do not edit.\n\
         [Unit]\n\
         Description=remedy verify after reboot\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStartPre=-{RM} -f \"{link}\" \"{unit}\"\n\
         ExecStart={cmd}\n\
         \n\
         [Install]\n\
         WantedBy={VERIFY_WANTED_BY}\n"
    )
}

/// 예약한다. 먼저 **유닛 파일**, 다음 **활성화 링크** — 링크가 먼저 생기면 부팅 때
/// 반쯤 쓰인 파일을 가리킬 수 있다.
fn schedule_verify_in(
    unit_dir: &std::path::Path,
    run_id: &str,
    exe: &std::path::Path,
    plugin: &std::path::Path,
    state_dir: Option<&std::path::Path>,
    lang: remedy_sdk::i18n::Lang,
) -> Result<(), PlatformError> {
    // 적기 전에 전부 본다 — 하나라도 거절되면 아무것도 쓰지 않는다.
    plain_for_unit(unit_dir)?;
    plain_exe_for_unit(exe)?;
    plain_for_unit(plugin)?;
    if let Some(d) = state_dir {
        plain_for_unit(d)?;
    }
    let cmd = crate::write::scheduled_verify_command(exe, run_id, plugin, state_dir, lang);
    let unit = verify_unit_path(unit_dir);
    let link = verify_link_path(unit_dir);
    let tmp = verify_tmp_path(unit_dir);

    // 반쯤 쓰인 유닛을 systemd 가 읽지 않게 옆에 쓰고 바꿔 끼운다. **바꿔 끼우기
    // 전에 디스크로 내린다** — 안 내리면 전원이 나간 기계가 빈 유닛을 가리키는
    // 링크로 부팅하고, 빈 유닛은 자기를 지우는 줄조차 돌지 않아 영영 남는다.
    let written = (|| {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(verify_unit_body(unit_dir, &cmd).as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &unit)
    })();
    if let Err(e) = written {
        // 바꿔 끼우지 못했으면 옆에 쓴 것도 치운다 — 규칙 (2).
        let _ = std::fs::remove_file(&tmp);
        return Err(PlatformError::io(unit.to_string_lossy(), e));
    }

    let linked = (|| {
        if let Some(wants) = link.parent() {
            std::fs::create_dir_all(wants)
                .map_err(|e| PlatformError::io(wants.to_string_lossy(), e))?;
        }
        // 옛 예약의 링크가 남아 있으면 바꿔 단다 — 예약은 늘 하나다.
        remove_if_present(&link)?;
        std::os::unix::fs::symlink(&unit, &link)
            .map_err(|e| PlatformError::io(link.to_string_lossy(), e))
    })();
    if linked.is_err() {
        // 링크 없는 유닛은 부팅 때 돌지 않고 **흔적으로만** 남는다 — 규칙 (2).
        let _ = std::fs::remove_file(&unit);
    }
    linked
}

/// 예약을 지운다 (자기 흔적 규칙 2). **링크 먼저** — 파일을 먼저 지우면 끊긴 링크가
/// 남는다. **우리 이름만 지운다** — 이 폴더의 다른 것은 건드리지 않는다.
fn remove_verify_unit(unit_dir: &std::path::Path) -> Result<(), PlatformError> {
    remove_if_present(&verify_link_path(unit_dir))?;
    remove_if_present(&verify_unit_path(unit_dir))?;
    // 바꿔 끼우다 멈춘 회차가 남긴 것도 우리 흔적이다.
    remove_if_present(&verify_tmp_path(unit_dir))
}

/// 있으면 지운다. **끊긴 링크도 본다** — `Path::exists` 는 링크를 따라가서, 가리키는
/// 파일이 이미 없으면 거짓이라 말한다. 그러면 끊긴 링크가 영영 남는다
/// (`wants_links` 가 `symlink_metadata` 를 쓰는 것과 같은 이유).
fn remove_if_present(p: &std::path::Path) -> Result<(), PlatformError> {
    match std::fs::symlink_metadata(p) {
        Ok(_) => std::fs::remove_file(p).map_err(|e| PlatformError::io(p.to_string_lossy(), e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(PlatformError::io(p.to_string_lossy(), e)),
    }
}

/// 걸려 있는 예약의 명령. **예약한 명령과 글자까지 같아야 한다** — 시험이 그것을 잰다.
fn read_verify_unit(unit_dir: &std::path::Path) -> Result<Option<String>, PlatformError> {
    let unit = verify_unit_path(unit_dir);
    match std::fs::read_to_string(&unit) {
        Ok(s) => Ok(s
            .lines()
            .find_map(|l| l.strip_prefix("ExecStart="))
            .map(systemd_unescape)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(PlatformError::io(unit.to_string_lossy(), e)),
    }
}

/// **아직 구현되지 않은 Op 과 그 이유** (설계-09 P12 순서 8).
///
/// # 왜 목록으로 못박는가
///
/// trait 의 기본 구현이 `Unsupported` 라 구현을 빠뜨려도 컴파일이 된다. 그러면
/// "이 백엔드는 그것을 안 한다" 가 **조용한 상태**가 되고, P12 의 게이트를
/// 올리는 사람은 무엇이 남았는지 알 길이 없다.
///
/// [`NOT_PLANNABLE_YET`](../../remedy_plan/derive/constant.NOT_PLANNABLE_YET.html)
/// 과 같은 규율이다. **비어야 게이트가 올라간다** — 시험이 그것을 강제한다.
///
/// **2026-08-27 로 비었다.** 마지막까지 남아 있던 `persistence.disable`·`delete`
/// 는 설계-09 P12 결정 5(계약을 대칭으로 넓힌다)로 열렸다.
pub const NOT_IMPLEMENTED_YET: [(&str, &str); 0] = [];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::PathView;

    /// 토큰을 펴되 **주석이 영어 회차에서 한글로 나오지 않는가**를 함께 잰다.
    ///
    /// `RootExpansion::notes` 는 `pipeline::scope_from_manifest` 가
    /// `Unresolved { at: "scan_roots" }` 로 바꾸고, `main.rs` 의
    /// `warn_unresolved_extra` 가 `scan`·`run` 의 stderr 로 찍는다. §17 이 그
    /// 화면을 두 언어로 고칠 때 이쪽에서 흘러드는 문구는 손대지 않았다.
    fn expand(root: &str, allow_removable: bool) -> crate::read::RootExpansion {
        use crate::read::ExpandRoots;
        let e = Live::new().expand_roots(root, allow_removable);
        for n in &e.notes {
            assert!(
                !n.chars().any(|c| ('가'..='힣').contains(&c)),
                "수집 주석이 영어 회차에서 한글로 나온다: {n}"
            );
        }
        e
    }

    /// 실제 `/proc/<pid>/maps` 의 모양이다. 같은 라이브러리가 **네 줄**로
    /// 실리고, 주소 순이라 정렬이 없으면 ASLR 이 순서를 매번 바꾼다.
    const MAPS: &str = "\
5584a0e2b000-5584a0e2d000 r--p 00000000 08:40 40823 /usr/bin/gawk
5584a0e2d000-5584a0ebe000 r-xp 00002000 08:40 40823 /usr/bin/gawk
5584a0ebe000-5584a0ec6000 r--p 00093000 08:40 40823 /usr/bin/gawk
5584a0ec6000-5584a0ec8000 rw-p 0009a000 08:40 40823 /usr/bin/gawk
5584a1f3c000-5584a1f5d000 rw-p 00000000 00:00 0                          [heap]
7f2c8b600000-7f2c8b628000 r--p 00000000 08:40 40199 /usr/lib/x86_64-linux-gnu/libc.so.6
7f2c8b628000-7f2c8b7b0000 r-xp 00028000 08:40 40199 /usr/lib/x86_64-linux-gnu/libc.so.6
7f2c8b7b0000-7f2c8b7ff000 r--p 001b0000 08:40 40199 /usr/lib/x86_64-linux-gnu/libc.so.6
7f2c8c000000-7f2c8c0f0000 r--p 00000000 08:40 51100 /usr/share/fonts/truetype/DejaVuSans.ttf
7ffd1a3e1000-7ffd1a402000 rw-p 00000000 00:00 0                          [stack]
7ffd1a4c9000-7ffd1a4cd000 r-xp 00000000 00:00 0                          [vdso]
";

    #[test]
    fn a_library_loaded_four_times_is_one_module() {
        // 매핑을 전부 담으면 같은 경로가 네 번 들어오고, 룰 작성자가 그 수를
        // 세는 일이 생긴다. 실행 가능한 줄만 세면 라이브러리 하나가 한 줄이다.
        assert_eq!(
            parse_maps(MAPS),
            vec![
                "/usr/bin/gawk".to_string(),
                "/usr/lib/x86_64-linux-gnu/libc.so.6".to_string(),
            ],
            "실행 매핑만 · 중복 없이 · 정렬되어야 한다"
        );
    }

    #[test]
    fn a_mapped_data_file_is_not_a_module() {
        // 글꼴은 `r--p` 로 올라온다. 모듈로 세면 "이 프로세스가 올린 코드" 가
        // 아닌 것이 목록에 섞이고, 그 목록을 겨눈 룰이 엉뚱한 것을 잡는다.
        assert!(
            !parse_maps(MAPS).iter().any(|m| m.ends_with(".ttf")),
            "{:?}",
            parse_maps(MAPS)
        );
    }

    #[test]
    fn pseudo_mappings_are_not_modules() {
        // `[vdso]` 는 **실행 가능**하다 — 권한만 보고 거르면 들어온다.
        for p in ["[heap]", "[stack]", "[vdso]"] {
            assert!(
                !parse_maps(MAPS).iter().any(|m| m == p),
                "{p} 가 모듈로 들어왔다"
            );
        }
    }

    #[test]
    fn a_module_path_with_a_space_survives_whole() {
        // 마지막 칸을 공백으로 끊으면 `/opt/My App/x.so` 가 `App/x.so` 가 되고,
        // 그 경로는 어느 파일도 가리키지 않는다.
        let line = "7f00-7f01 r-xp 00000000 08:40 1 /opt/My App/x.so";
        assert_eq!(module_path_of(line), Some("/opt/My App/x.so"));
    }

    #[test]
    fn a_deleted_module_keeps_the_kernel_marker() {
        // 실행 중에 제 파일을 지우는 것은 강한 신호다. 표시를 벗겨 내면
        // 있지도 않은 경로를 있는 것처럼 적게 된다.
        let line = "7f00-7f01 r-xp 00000000 08:40 1 /tmp/x.so (deleted)";
        assert_eq!(module_path_of(line), Some("/tmp/x.so (deleted)"));
    }

    #[test]
    fn an_empty_maps_file_is_not_a_refusal() {
        // 커널 스레드는 주소 공간이 없어 maps 가 빈 파일이다. **봤고 없었다** —
        // 거부가 아니다.
        assert!(parse_maps("").is_empty());
    }

    #[test]
    fn a_process_that_ended_is_not_counted_as_refused() {
        // pid 0 은 `/proc` 에 없다. 열거와 읽기 사이에 끝난 프로세스가 같은
        // 자리로 온다 — 그것을 거부로 세면 모든 회차가 관측 불완전이 되고,
        // 그러면 종료 코드 6 이 신호이기를 그만둔다.
        let (modules, denied) = modules_of(0);
        assert!(modules.is_empty());
        assert!(!denied, "사라진 프로세스를 거부로 셌다");
    }

    #[test]
    fn this_process_lists_its_own_modules() {
        // 파서가 아니라 **이 기계의 `/proc` 을** 잰다. 형식이 달라지면 여기서
        // 드러난다 — 시험 바이너리 자신이 목록에 있어야 한다.
        let (modules, denied) = modules_of(std::process::id());
        assert!(!denied, "제 프로세스의 maps 를 못 읽었다");
        assert!(
            modules.iter().any(|m| m.contains("remedy")),
            "제 실행 파일이 모듈 목록에 없다: {modules:?}"
        );
    }

    #[test]
    fn os_tools_are_named_by_absolute_path() {
        // **`PATH` 를 타면 치료 도구가 공격자의 실행 파일을 부른다.** 이름만
        // 적어도 대개 동작하므로 리뷰에서 눈에 띄지 않는다 — 기계가 본다.
        //
        // Windows 쪽 `only_known_system_tools_are_launched` 와 같은 자리다.
        for t in SYSTEM_TOOLS.iter().chain(SYSTEMCTL.iter()) {
            assert!(
                t.starts_with('/'),
                "'{t}' 이 절대 경로가 아니다 — PATH 를 타면 무엇이 실행될지 알 수 없다"
            );
        }
    }

    // ── service.stop — 진짜 systemd 를 건드리지 않고 잰다 (결정 A) ──────────
    //
    // 부팅 표지는 `FakeSystemd` 의 것이고 도구는 가짜 `systemctl` 이다. 종료 코드는
    // 랩 VM(systemd 252)에서 잰 값 그대로다 — `stop_unit_with` 의 표.

    /// 받은 인자를 한 줄씩 적고 `code` 로 끝나는 가짜 `systemctl`.
    fn fake_systemctl(fs: &FakeSystemd, code: i32, stderr: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let exe = fs.root.join("systemctl");
        let args = fs.root.join("args");
        std::fs::write(
            &exe,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho '{stderr}' >&2\nexit {code}\n",
                args.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        exe.to_string_lossy().to_string()
    }

    fn args_seen(fs: &FakeSystemd) -> Option<String> {
        std::fs::read_to_string(fs.root.join("args")).ok()
    }

    const UNIT: &str = "/etc/systemd/system/evil.service";

    #[test]
    fn a_unit_is_stopped_by_asking_systemd_without_waiting() {
        let fs = FakeSystemd::new("stop-ok");
        let exe = fake_systemctl(&fs, 0, "");
        stop_unit_in(&fs.run(), &[&exe], UNIT).expect("정지");
        assert_eq!(
            args_seen(&fs).as_deref(),
            Some("stop\n--no-block\n--\nevil.service\n"),
            "기다리지 않는 정지가 아니거나, 이름이 옵션 자리에 있다"
        );
    }

    #[test]
    fn a_unit_that_is_not_loaded_has_nothing_to_stop() {
        // 다시 도는 실행기가 이미 지운 유닛을 만난다 — 목표 상태는 이루어졌다.
        let fs = FakeSystemd::new("stop-notloaded");
        let exe = fake_systemctl(&fs, 5, "Unit evil.service not loaded.");
        assert!(stop_unit_in(&fs.run(), &[&exe], UNIT).is_ok());
    }

    #[test]
    fn a_refused_stop_is_a_failure_that_says_why() {
        // `RefuseManualStop=` — systemd 252 는 4 로 거부했다. 조용히 넘기면 실행기가
        // 멈춘 줄 알고, 뒤따르는 종료 뒤에 systemd 가 되살린다.
        let fs = FakeSystemd::new("stop-refused");
        let exe = fake_systemctl(
            &fs,
            4,
            "Operation refused, unit evil.service may be requested by dependency only",
        );
        let e = stop_unit_in(&fs.run(), &[&exe], UNIT).unwrap_err();
        assert!(matches!(e, PlatformError::Refused(_)), "{e:?}");
        assert!(
            format!("{e}").contains("Operation refused"),
            "왜 실패했는지 말하지 않는다: {e}"
        );
    }

    #[test]
    fn without_systemd_there_is_nothing_to_stop() {
        // 컨테이너처럼 systemd 가 PID 1 이 아니면 멈출 관리자가 없다. 도구를 부르지
        // 않는다 — 부르면 "booted with systemd 가 아니다" 로 실패하고, 리눅스 채점
        // 컨테이너의 치료가 부분 실패가 된다.
        let fs = FakeSystemd::new("stop-nosystemd");
        let exe = fake_systemctl(&fs, 1, "System has not been booted with systemd");
        let not_booted = fs.root.join("no-run-dir");
        assert!(stop_unit_in(&not_booted, &[&exe], UNIT).is_ok());
        assert_eq!(
            args_seen(&fs),
            None,
            "systemd 가 없는데 systemctl 을 불렀다"
        );
    }

    #[test]
    fn only_a_system_unit_is_handed_to_systemd() {
        // **두 번째 겹이다.** 계획기가 사용자 유닛을 미루지만, 손으로 고친 계획이
        // 사용자 유닛을 여기로 보내면 같은 이름의 시스템 유닛이 멈출 수 있다.
        let fs = FakeSystemd::new("stop-reject");
        let exe = fake_systemctl(&fs, 0, "");
        for target in [
            "/home/u/.config/systemd/user/evil.service",
            "/etc/systemd/user/evil.service",
            "/etc/systemd/system/sub/evil.service",
            "/etc/systemd/system/evil.timer",
            "/etc/systemd/system/.service",
            "/etc/systemd/system/evil unit.service",
            "/tmp/evil.service",
            "evil.service",
        ] {
            let e = stop_unit_in(&fs.run(), &[&exe], target).unwrap_err();
            assert!(matches!(e, PlatformError::Refused(_)), "{target}: {e:?}");
        }
        assert_eq!(
            args_seen(&fs),
            None,
            "거부해야 할 대상으로 systemctl 을 불렀다"
        );
        // 시스템 유닛 자리 넷은 모두 받는다.
        for dir in SYSTEM_UNIT_DIRS {
            assert_eq!(
                system_unit_name(&format!("{dir}/evil.service"))
                    .ok()
                    .as_deref(),
                Some("evil.service"),
                "{dir}"
            );
        }
    }

    #[test]
    fn no_systemctl_on_a_systemd_machine_is_a_failure() {
        // 조용히 성공하면 "멈췄다" 가 거짓이 된다 — `ca_tool` 과 같은 판단이다.
        let fs = FakeSystemd::new("stop-notool");
        let e = stop_unit_in(&fs.run(), &["/nonexistent/systemctl"], UNIT).unwrap_err();
        assert!(matches!(e, PlatformError::Refused(_)), "{e:?}");
    }

    #[test]
    fn the_registry_is_absent_not_empty() {
        // **빈 결과를 돌려주면 "Run 키에 아무것도 없다" 로 읽힌다.** 그 스냅샷
        // 위에서 "위협 없음" 이 결론나고, 아무도 레지스트리를 못 봤다는 것을
        // 모른다.
        let l = Live::new();
        assert!(l.value("HKLM\\X", "Y").is_err());
        assert!(l.subkeys("HKLM\\X").is_err());
        assert!(l.values("HKLM\\X").is_err());
        assert!(!l.key_exists("HKLM\\X"));
    }

    #[test]
    fn a_user_hive_token_does_not_leak_through_as_a_path() {
        // `HKU\*\...` 를 1:1 로 흘리면 그것이 그대로 경로가 되어 존재하지 않는
        // 곳을 가리킨다 — 수집은 0건이 되고 아무도 이유를 모른다.
        let e = expand("HKU\\*\\Software\\X", false);
        assert!(e.roots.is_empty(), "{e:?}");
        assert!(
            // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
            e.notes
                .iter()
                .any(|n| n.contains(remedy_sdk::i18n::t("레지스트리", "registry"))),
            "이유를 말하지 않았다: {e:?}"
        );
    }

    #[test]
    fn removable_is_not_expanded_without_the_declaration() {
        // **선언이 동의를 대신한다.** 연결된 매체가 다른 사람의 것일 수 있다.
        let e = expand("%REMOVABLE%/x", false);
        assert!(e.roots.is_empty(), "{e:?}");
        assert!(
            e.notes.iter().any(|n| n.contains("allow_removable")),
            "{e:?}"
        );
    }

    #[test]
    fn root_is_a_home_not_a_parent_of_homes() {
        // **`/root` 아래는 사용자 홈이 아니다.** `.config` · `.ssh` · `.cache`
        // 를 프로필로 세면 두 가지가 깨진다 — 선언한 읽기 상한이 가짜 항목으로
        // 부풀고(G6 이 그 목록으로 판정한다), MAX_PROFILES 예산을 잡아먹어
        // `/home` 의 진짜 사용자가 잘려 나간다.
        //
        // 2026-09-03 Linux 하네스가 상한에
        // `/root/.config/.config/google-chrome/...` 이 실린 것을 보고 찾았다.
        let e = expand("%ALLUSERPROFILES%/.config/x", false);
        for r in &e.roots {
            assert!(
                !r.starts_with("/root/") || r.starts_with("/root/.config/x"),
                "/root 아래를 홈으로 셌다: {r}  (전체: {:?})",
                e.roots
            );
        }
        // 이 시험이 도는 기계에 `/root` 가 있다면 그것 자체는 홈으로 들어와야
        // 한다. 없으면 아무 말도 하지 않는다 — 컨테이너·CI 마다 다르다.
        if std::path::Path::new("/root").is_dir() && std::fs::read_dir("/root").is_ok() {
            assert!(
                e.roots.iter().any(|r| r == "/root/.config/x"),
                "/root 자신이 홈으로 들어오지 않았다: {:?}",
                e.roots
            );
        }
    }

    #[test]
    fn an_ordinary_root_expands_one_to_one() {
        let e = expand("/etc/systemd", false);
        assert_eq!(e.roots, vec!["/etc/systemd".to_string()]);
        assert!(e.notes.is_empty(), "{e:?}");
    }

    #[test]
    fn the_two_path_views_are_the_same_here() {
        // Windows 는 WOW64 때문에 둘이 갈리지만 Linux 는 갈릴 이유가 없다.
        // 갈라지면 "지울 때 본 자리" 와 "있는지 물을 때 본 자리" 가 달라진다.
        let l = Live::new();
        assert_eq!(l.for_access("/etc/hosts"), "/etc/hosts");
        assert_eq!(l.for_record("/etc/hosts"), "/etc/hosts");
    }

    #[test]
    fn a_cron_id_is_told_apart_from_a_unit_path() {
        // **이 갈림길을 틀리면 엉뚱한 파일의 줄을 고친다.** 파일 이름에 `:` 가
        // 들어갈 수 있으므로 마지막 `:` 뒤가 숫자일 때만 줄로 읽는다.
        assert_eq!(
            cron_at("/etc/cron.d/updater:7"),
            Some(("/etc/cron.d/updater".to_string(), 7))
        );
        assert_eq!(cron_at("/etc/systemd/system/upd.service"), None);
        // 0번 줄은 없다. 사람이 세는 번호는 1 부터다.
        assert_eq!(cron_at("/etc/crontab:0"), None);
        // 숫자가 아니면 유닛 경로다.
        assert_eq!(cron_at("/etc/systemd/system/a:b.service"), None);
    }

    #[test]
    fn nothing_is_left_unimplemented() {
        // **비어야 P12 의 게이트가 올라간다.** trait 의 기본 구현이
        // `Unsupported` 라 위임을 빠뜨려도 컴파일이 되므로, 남은 것이 무엇인지는
        // 이 목록만이 말한다 (설계-09 P12 순서 8).
        assert!(NOT_IMPLEMENTED_YET.is_empty(), "{NOT_IMPLEMENTED_YET:?}");
    }

    #[test]
    fn planning_a_restore_names_what_this_platform_cannot_bring_back() {
        // 설계-02 §9 는 되살릴 수 없는 항목을 **실행 전에** 목록으로 고지하라고
        // 한다. 파일 계열은 이제 되므로 보고가 비어 있으면 안 되고, **Windows
        // 보안 디스크립터는 여기서 되살릴 수 없다**는 사실이 적혀야 한다.
        let meta = FileMeta {
            sddl: Some("O:BAG:BAD:P".into()),
            ..FileMeta::default()
        };
        let r = Live::new().plan_restore("/home/a/x.so", &meta);
        assert!(
            r.restored.contains(&"content".to_string()),
            "본문조차 못 살린다고 한다: {r:?}"
        );
        assert!(
            r.lost.iter().any(|x| x.item == "sddl"),
            "이 플랫폼에 없는 것을 살릴 수 있다고 했다: {r:?}"
        );
    }

    // ── 재부팅 후 검증 예약 (설계-03 §8 · P12) ──────────────────────
    //
    // **실제 systemd 는 여기서 안 돈다** — 이 시험은 유닛의 **모양**과 자기 삭제
    // 명령, 되읽기, 거절, 이웃 보호를 잰다. "재부팅하면 실제로 돈다" 는 P7 의
    // 리눅스 랩 VM 이 잰다.

    /// 시험마다 따로 쓰는 가짜 systemd 자리. 끝나면 지운다.
    struct FakeSystemd {
        root: std::path::PathBuf,
    }

    /// 루트 하나가 읽기·쓰기로 마운트된 표. `proc(5)` 의 모양 그대로다.
    const RW_ROOT: &str = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n";

    impl FakeSystemd {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("remedy-p12-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("run/systemd/system")).unwrap();
            std::fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
            std::fs::write(root.join("mountinfo"), RW_ROOT).unwrap();
            Self { root }
        }
        fn run(&self) -> std::path::PathBuf {
            self.root.join("run/systemd/system")
        }
        fn units(&self) -> std::path::PathBuf {
            self.root.join("etc/systemd/system")
        }
        fn mountinfo(&self) -> std::path::PathBuf {
            self.root.join("mountinfo")
        }
        fn support(&self) -> Result<(), PlatformError> {
            verify_support_in(&self.run(), &self.units(), &self.mountinfo())
        }
        fn schedule(&self, run_id: &str, plugin: &str) -> Result<(), PlatformError> {
            self.schedule_os(run_id, std::path::Path::new(plugin))
        }
        fn schedule_os(&self, run_id: &str, plugin: &std::path::Path) -> Result<(), PlatformError> {
            schedule_verify_in(
                &self.units(),
                run_id,
                std::path::Path::new("/usr/local/bin/remedy"),
                plugin,
                None,
                remedy_sdk::i18n::Lang::Ko,
            )
        }
        fn shared_command(&self, run_id: &str, plugin: &str) -> String {
            crate::write::scheduled_verify_command(
                std::path::Path::new("/usr/local/bin/remedy"),
                run_id,
                std::path::Path::new(plugin),
                None,
                remedy_sdk::i18n::Lang::Ko,
            )
        }
    }

    impl Drop for FakeSystemd {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn verification_is_offered_only_where_systemd_is_init() {
        // **컨테이너·WSL·OpenRC 에서 약속하지 않는다** (P12 D3). 거기서 유닛을
        // 심으면 부팅 때 읽을 systemd 가 없고, 심은 것은 흔적일 뿐이다.
        let fs = FakeSystemd::new("support");
        assert!(fs.support().is_ok(), "{:?}", fs.support());

        std::fs::remove_dir_all(fs.run()).unwrap();
        assert!(
            matches!(fs.support(), Err(PlatformError::Unsupported(_))),
            "systemd 가 init 이 아닌데 예약할 수 있다고 했다"
        );

        std::fs::create_dir_all(fs.run()).unwrap();
        std::fs::remove_dir_all(fs.units()).unwrap();
        assert!(
            matches!(fs.support(), Err(PlatformError::Unsupported(_))),
            "유닛 자리가 없는데 예약할 수 있다고 했다"
        );
    }

    #[test]
    fn a_read_only_unit_site_is_told_before_approval() {
        // **써 보지 않고 잰다** — 이 질의는 승인 전에 불린다. 유닛 자리가 앉은
        // 마운트가 읽기 전용이면 root 라도 못 쓰므로 약속하지 않는다.
        let fs = FakeSystemd::new("readonly");
        let real = std::fs::canonicalize(fs.units()).unwrap();
        std::fs::write(
            fs.mountinfo(),
            format!(
                "{RW_ROOT}40 22 0:40 / {} ro,relatime shared:9 - squashfs /dev/loop0 ro\n",
                real.display()
            ),
        )
        .unwrap();
        assert!(
            matches!(fs.support(), Err(PlatformError::Unsupported(_))),
            "읽기 전용 자리에 예약할 수 있다고 했다"
        );
        // 물은 것만으로 아무것도 남지 않는다.
        assert_eq!(std::fs::read_dir(fs.units()).unwrap().count(), 0);

        // 표를 읽지 못하면 "쓸 수 있다" 로 접지 않는다.
        std::fs::remove_file(fs.mountinfo()).unwrap();
        assert!(fs.support().is_err(), "모르는 것을 괜찮다고 했다");
    }

    #[test]
    fn the_mount_that_holds_a_path_is_the_deepest_one() {
        let p = std::path::Path::new("/etc/systemd/system");
        let rw_etc = "30 22 8:2 / /etc rw,relatime - ext4 /dev/sda2 rw\n";
        let ro_root = "22 1 8:1 / / ro,relatime - ext4 /dev/sda1 ro\n";

        assert_eq!(mount_is_readonly(p, RW_ROOT.as_bytes()), Some(false));
        assert_eq!(mount_is_readonly(p, ro_root.as_bytes()), Some(true));
        // 더 깊은 마운트가 이긴다 — 루트는 읽기 전용이어도 /etc 는 쓸 수 있다.
        assert_eq!(
            mount_is_readonly(p, format!("{ro_root}{rw_etc}").as_bytes()),
            Some(false)
        );
        // 같은 자리면 뒤엣것이 이긴다 — 나중 마운트가 앞의 것을 가린다.
        assert_eq!(
            mount_is_readonly(p, format!("{RW_ROOT}{ro_root}").as_bytes()),
            Some(true)
        );
        // 슈퍼블록만 읽기 전용이어도 못 쓴다.
        let ro_super = "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 ro,errors=remount-ro\n";
        assert_eq!(mount_is_readonly(p, ro_super.as_bytes()), Some(true));
        // `errors=remount-ro` 는 `ro` 가 아니다 — 옵션은 쉼표로 끊어 통째로 본다.
        let rw_super = "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw,errors=remount-ro\n";
        assert_eq!(mount_is_readonly(p, rw_super.as_bytes()), Some(false));
        // 조각으로 잰다 — `/et` 는 `/etc` 의 앞이 아니다.
        let ro_et = "31 22 8:3 / /et ro - ext4 /dev/sda3 ro\n";
        assert_eq!(
            mount_is_readonly(p, format!("{RW_ROOT}{ro_et}").as_bytes()),
            Some(false)
        );
        // 선택 필드가 여럿이어도 `-` 를 찾는다.
        let many = "22 1 8:1 / / rw shared:1 master:2 propagate_from:3 - ext4 /dev/sda1 ro\n";
        assert_eq!(mount_is_readonly(p, many.as_bytes()), Some(true));
        // 표가 비면 모른다.
        assert_eq!(mount_is_readonly(p, b""), None);
    }

    #[test]
    fn a_mount_point_with_a_space_is_read_back() {
        // 표는 공백을 `\040` 으로 적는다. 펴지 않으면 그 아래 경로가 전부 루트로
        // 떨어져 읽기 전용 마운트를 놓친다.
        assert_eq!(
            unescape_mount_field(br"/mnt/my\040disk"),
            std::path::PathBuf::from("/mnt/my disk")
        );
        assert_eq!(
            unescape_mount_field(br"/a\134b"),
            std::path::PathBuf::from("/a\\b")
        );
        // 8진 셋이 아니면 그대로 둔다.
        assert_eq!(
            unescape_mount_field(br"/a\9b\04"),
            std::path::PathBuf::from("/a\\9b\\04")
        );
        let table = format!("{RW_ROOT}40 22 0:40 / /mnt/my\\040disk ro - vfat /dev/sdb1 ro\n");
        assert_eq!(
            mount_is_readonly(std::path::Path::new("/mnt/my disk/x"), table.as_bytes()),
            Some(true)
        );
    }

    #[test]
    fn a_scheduled_verification_is_one_unit_and_one_link() {
        let fs = FakeSystemd::new("shape");
        fs.schedule("run-1-a", "/opt/plugins/x/plugin.yaml")
            .unwrap();

        let unit = verify_unit_path(&fs.units());
        let link = verify_link_path(&fs.units());
        assert!(unit.is_file(), "유닛 파일이 없다");
        let meta = std::fs::symlink_metadata(&link).expect("활성화 링크가 없다");
        assert!(meta.file_type().is_symlink(), "링크가 아니라 파일이다");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            unit,
            "링크가 유닛을 가리키지 않는다"
        );
        assert!(
            !verify_tmp_path(&fs.units()).exists(),
            "바꿔 끼우고 난 임시 파일이 남았다"
        );

        // 부팅 때 끌어올리는 자리는 로그온이 아니라 부팅이다.
        let body = std::fs::read_to_string(&unit).unwrap();
        assert!(body.contains("\nType=oneshot\n"), "{body}");
        assert!(
            body.contains("\n[Install]\nWantedBy=multi-user.target\n"),
            "{body}"
        );
    }

    #[test]
    fn the_unit_removes_itself_right_before_it_runs() {
        // **자기 흔적 규칙 2** — Windows 가 RunOnce 를 고른 그 이유를 유닛이
        // 스스로 진다. `verify` 가 시작조차 못 해도 흔적이 남지 않아야 한다.
        let fs = FakeSystemd::new("selfremove");
        fs.schedule("run-1-a", "/opt/plugins/x/plugin.yaml")
            .unwrap();
        let body = std::fs::read_to_string(verify_unit_path(&fs.units())).unwrap();

        let want = format!(
            "ExecStartPre=-/bin/rm -f \"{}\" \"{}\"",
            verify_link_path(&fs.units()).display(),
            verify_unit_path(&fs.units()).display()
        );
        let pre = body
            .find(&want)
            .unwrap_or_else(|| panic!("자기 삭제 줄이 없다:\n{body}"));
        let start = body.find("\nExecStart=").expect("ExecStart 가 없다");
        assert!(pre < start, "자기 삭제가 실행보다 뒤에 있다:\n{body}");
    }

    #[test]
    fn the_unit_carries_the_shared_command_verbatim() {
        // **값을 쓰는지가 아니라 그 값이 무엇인지를 잰다** — P10 이 `--plugin` 을
        // 빠뜨린 채 닫힌 자리(`write::scheduled_verify_command` 의 설명). 그 명령이
        // 실제로 실행되는지는 `remedy-cli/tests/scheduled_verify.rs` 가 재므로,
        // 여기서는 **유닛이 그것을 한 글자도 바꾸지 않고 담는가**를 본다.
        //
        // `%` 와 `$` 를 일부러 넣는다 — systemd 가 펴는 글자라, 이스케이프를
        // 빠뜨리면 되읽은 명령이 달라진다.
        let fs = FakeSystemd::new("verbatim");
        let plugin = "/opt/p%20x/$HOME/plugin.yaml";
        fs.schedule("run-1-a", plugin).unwrap();

        let body = std::fs::read_to_string(verify_unit_path(&fs.units())).unwrap();
        assert!(
            body.contains("/opt/p%%20x/$$HOME/plugin.yaml"),
            "systemd 가 펼 글자를 막지 않았다:\n{body}"
        );
        assert_eq!(
            read_verify_unit(&fs.units()).unwrap().as_deref(),
            Some(fs.shared_command("run-1-a", plugin).as_str()),
            "유닛에서 되읽은 명령이 예약한 명령과 다르다"
        );
    }

    #[test]
    fn a_path_that_cannot_be_written_safely_is_refused_and_nothing_is_left() {
        // 따옴표·역슬래시·줄바꿈은 유닛 파일의 인용과 줄을 깬다. **억지로 펴다
        // 틀리느니 거절한다** — 그리고 거절했으면 아무것도 남기지 않는다.
        for bad in [
            "/opt/a\"b/plugin.yaml",
            "/opt/a\\b/plugin.yaml",
            "/opt/a\nb/plugin.yaml",
        ] {
            let fs = FakeSystemd::new("refuse");
            assert!(
                matches!(fs.schedule("run-1-a", bad), Err(PlatformError::Refused(_))),
                "{bad:?} 를 거절하지 않았다"
            );
            assert!(
                !verify_unit_path(&fs.units()).exists(),
                "{bad:?}: 유닛이 남았다"
            );
            assert!(
                std::fs::symlink_metadata(verify_link_path(&fs.units())).is_err(),
                "{bad:?}: 링크가 남았다"
            );
            assert!(
                !verify_tmp_path(&fs.units()).exists(),
                "{bad:?}: 임시 파일이 남았다"
            );
        }
    }

    #[test]
    fn a_unit_that_could_not_be_linked_is_not_left_behind() {
        // 링크 자리(`.wants`)가 폴더가 아니라 파일인 기계 — 링크를 못 단다. 그러면
        // 바꿔 끼운 유닛은 부팅 때 돌지 않고 흔적으로만 남으므로 치워야 한다.
        let fs = FakeSystemd::new("nolink");
        let wants = fs.units().join("multi-user.target.wants");
        std::fs::write(&wants, "not a directory").unwrap();

        assert!(fs
            .schedule("run-1-a", "/opt/plugins/x/plugin.yaml")
            .is_err());
        assert!(
            !verify_unit_path(&fs.units()).exists(),
            "링크 없는 유닛이 남았다"
        );
        assert!(!verify_tmp_path(&fs.units()).exists(), "임시 파일이 남았다");
        assert!(wants.is_file(), "남의 것을 건드렸다");
    }

    #[test]
    fn an_exe_path_systemd_would_not_expand_is_refused() {
        // 실행 파일 자리는 변수를 펴지 않는다 — `$$` 로 적어도 `$` 로 돌아온다는
        // 보장이 없다. 인자 자리의 `$` 는 `$$` 로 적어 받는다(위 `verbatim`).
        let fs = FakeSystemd::new("exe-dollar");
        let r = schedule_verify_in(
            &fs.units(),
            "run-1-a",
            std::path::Path::new("/opt/re$dy/remedy"),
            std::path::Path::new("/opt/plugins/x/plugin.yaml"),
            None,
            remedy_sdk::i18n::Lang::Ko,
        );
        assert!(matches!(r, Err(PlatformError::Refused(_))), "{r:?}");
        assert_eq!(
            std::fs::read_dir(fs.units()).unwrap().count(),
            0,
            "거절했는데 남겼다"
        );
    }

    #[test]
    fn a_path_that_is_not_utf8_is_refused() {
        // 유닛에 적는 순간 대체 문자로 뭉개져 다른 경로가 된다.
        use std::os::unix::ffi::OsStrExt;
        let fs = FakeSystemd::new("not-utf8");
        let bad = std::ffi::OsStr::from_bytes(b"/opt/\xff/plugin.yaml");
        assert!(matches!(
            fs.schedule_os("run-1-a", std::path::Path::new(bad)),
            Err(PlatformError::Refused(_))
        ));
        assert_eq!(
            std::fs::read_dir(fs.units()).unwrap().count(),
            0,
            "거절했는데 남겼다"
        );
    }

    #[test]
    fn cancelling_removes_ours_and_nothing_else() {
        // **우리 이름 둘만 지운다** — 같은 폴더의 다른 유닛과 링크는 사용자의 것이다.
        let fs = FakeSystemd::new("cancel");
        let wants = fs.units().join("multi-user.target.wants");
        std::fs::create_dir_all(&wants).unwrap();
        let other = fs.units().join("vendor-agent.service");
        std::fs::write(&other, "[Service]\nExecStart=/usr/bin/true\n").unwrap();
        std::os::unix::fs::symlink(&other, wants.join("vendor-agent.service")).unwrap();

        fs.schedule("run-1-a", "/opt/plugins/x/plugin.yaml")
            .unwrap();
        remove_verify_unit(&fs.units()).unwrap();

        assert!(
            !verify_unit_path(&fs.units()).exists(),
            "우리 유닛이 남았다"
        );
        assert!(
            std::fs::symlink_metadata(verify_link_path(&fs.units())).is_err(),
            "우리 링크가 남았다"
        );
        assert!(other.is_file(), "이웃 유닛을 지웠다");
        assert!(
            std::fs::symlink_metadata(wants.join("vendor-agent.service")).is_ok(),
            "이웃 링크를 지웠다"
        );
        assert_eq!(read_verify_unit(&fs.units()).unwrap(), None);

        // 두 번 지워도 성공이다 — 지울 것이 없는 것이 바라는 상태다.
        remove_verify_unit(&fs.units()).unwrap();
    }

    #[test]
    fn a_dangling_link_is_still_removed() {
        // 유닛 파일만 먼저 사라진 기계. `Path::exists` 는 끊긴 링크를 없다고
        // 말하므로 그것에 기대면 링크가 영영 남는다.
        let fs = FakeSystemd::new("dangling");
        fs.schedule("run-1-a", "/opt/plugins/x/plugin.yaml")
            .unwrap();
        std::fs::remove_file(verify_unit_path(&fs.units())).unwrap();
        assert!(
            !verify_link_path(&fs.units()).exists(),
            "시험 전제: 링크가 끊겼어야 한다"
        );

        remove_verify_unit(&fs.units()).unwrap();
        assert!(
            std::fs::symlink_metadata(verify_link_path(&fs.units())).is_err(),
            "끊긴 링크가 남았다"
        );
    }

    #[test]
    fn scheduling_again_keeps_a_single_reservation() {
        // 예약은 늘 하나다 — 새 회차가 옛 것을 바꿔 단다.
        let fs = FakeSystemd::new("again");
        fs.schedule("run-1-a", "/opt/plugins/x/plugin.yaml")
            .unwrap();
        fs.schedule("run-2-b", "/opt/plugins/x/plugin.yaml")
            .unwrap();

        assert_eq!(
            read_verify_unit(&fs.units()).unwrap().as_deref(),
            Some(
                fs.shared_command("run-2-b", "/opt/plugins/x/plugin.yaml")
                    .as_str()
            )
        );
        let links: Vec<_> = std::fs::read_dir(fs.units().join("multi-user.target.wants"))
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(links.len(), 1, "링크가 쌓였다: {links:?}");
    }

    #[test]
    fn cancelling_where_nothing_was_ever_placed_succeeds() {
        // systemd 가 없는 기계(컨테이너 등)의 `verify` 가 매번 하는 호출이다.
        // 여기서 오류를 내면 모든 회차가 헛경고를 찍는다 (실측 2026-09-07).
        let fs = FakeSystemd::new("nothing");
        std::fs::remove_dir_all(fs.units()).unwrap();
        remove_verify_unit(&fs.units()).unwrap();
        assert_eq!(read_verify_unit(&fs.units()).unwrap(), None);
    }

    #[test]
    fn the_live_backend_names_its_own_site() {
        // 보고가 쓰는 자리 (자기 흔적 규칙 3). **레지스트리 경로가 아니어야 한다** —
        // 호출자가 RunOnce 경로를 박아 두던 자리가 그것을 냈을 것이다.
        let site = Live::new()
            .scheduled_verify_site()
            .expect("리눅스는 예약한다");
        assert_eq!(site.location, "/etc/systemd/system/remedy-verify.service");
        assert_eq!(site.removed_by, RemovedBy::Itself);
    }
}
