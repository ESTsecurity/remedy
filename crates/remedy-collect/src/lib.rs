//! 라이브 시스템 수집기 (설계-09 P2).
//!
//! **판단하지 않는다.** 무엇이 악성인지에 대한 결정은 여기 들어오지 않는다.
//! 수집 범위는 플러그인의 선언에서 오지만, 그 선언은 "어디를 볼 수 있는가" 일
//! 뿐이다 (설계-02 §8).
//!
//! # 진단 모드
//!
//! `collect` 단독 실행 경로에는 **파괴 코드가 링크되지 않고 플러그인도 필요 없다**
//! (설계-00 §5). 이 크레이트가 `remedy-apply` 를 의존하지 않는 것이 그 보장이고,
//! `Scope::diagnostic` 이 플러그인 없이 범위를 만드는 길이다.
#![forbid(unsafe_code)]

pub mod certstore;
pub mod config;
pub mod cron;
pub mod derived;
pub mod desktop;
pub mod extra;
mod owner;
pub mod package;
pub mod peversion;
pub mod registry;
pub mod shortcut;
pub mod signature;
pub mod systemd;
pub mod task;
pub mod unix_socket;

use remedy_artifacts::{
    CollectError, FileCollector, FileRecord, Harvest, Observations, PersistenceCollector,
    PersistenceRecord, Scope, SecurityProductCollector,
};
use remedy_platform::read::{EnvRead, FsRead, ProcessRead, RegValue, RegistryRead, Seen};
use remedy_sdk::artifact::SecurityProduct;
use remedy_sdk::catalog::Subject;
use remedy_sdk::normalize;
use sha2::{Digest, Sha256};

pub const CRATE_NAME: &str = "remedy-collect";

/// Windows Defender 의 보안 센터 AV 공급자 GUID.
///
/// 표시 이름으로 맞추면 로케일에 따라 갈라진다 — 한국어 환경에서는
/// "Microsoft Defender 바이러스 백신" 으로 나오고, 그러면 Defender 를 두 번
/// 보고하게 된다. 실제로 그렇게 나왔다. GUID 는 로케일과 무관하다.
const DEFENDER_PROVIDER_GUID: &str = "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}";

const SECURITY_CENTER_AV: &str = "HKLM\\SOFTWARE\\Microsoft\\Security Center\\Provider\\Av";
const DEFENDER_KEY: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender";

/// 라이브 백엔드 위의 수집기.
pub struct Collector<P> {
    platform: P,
}

impl<P> Collector<P> {
    pub fn new(platform: P) -> Self {
        Self { platform }
    }

    /// 백엔드. `collect_extra` 처럼 수집기 밖에서 같은 백엔드를 써야 하는
    /// 자리가 있다 — 두 번 만들면 WOW64 판정 같은 상태가 갈릴 수 있다.
    pub fn platform(&self) -> &P {
        &self.platform
    }
}

impl<P: FsRead> FileCollector for Collector<P> {
    fn collect_files(&self, scope: &Scope) -> Result<Harvest<FileRecord>, CollectError> {
        let mut h = Harvest::default();
        // **없는 루트를 먼저 걸러 낸다.** 존재하지 않는 루트는 정상이고(설치되지
        // 않은 프로그램 등) 접근 거부와 달라 denied 로 세지 않는데, 화면의
        // `루트 k/n` 에서도 세면 안 된다 — 세면 n 에 영영 닿지 못한다.
        //
        // **여기서 두 갈래 `exists()` 를 쓰는 것이 미탐이 아닌 이유**: 못 물은
        // 자리도 걷지 못하므로 거르는 것은 맞고, *그 사실* 은 `collect_all` 이
        // 이미 `unreadable_roots` 에 적었다(`scan_roots` 와 `subject_roots` 둘
        // 다). 여기서 다시 세면 한 자리가 두 번 보고된다.
        let roots: Vec<&String> = scope
            .roots_for(Subject::File)
            .iter()
            .filter(|r| root_exists(&self.platform, r))
            .collect();
        let root_total = roots.len();
        for (i, root) in roots.into_iter().enumerate() {
            let remaining = scope.max_files.saturating_sub(h.records.len());
            if remaining == 0 {
                h.truncated = true;
                break;
            }
            remedy_platform::progress::begin_root(i + 1, root_total);
            let walk_started = std::time::Instant::now();
            let w = self
                .platform
                .walk(root, remaining)
                .map_err(|e| CollectError::Other(e.to_string()))?;
            remedy_platform::progress::add_walk(walk_started.elapsed());
            // 걷기가 끝났으니 이 루트의 분모가 정해졌다.
            remedy_platform::progress::root_walked();
            h.truncated |= w.truncated;
            h.absorb_denied(w.denied, w.denied_paths);

            for e in w.entries {
                if e.is_dir {
                    continue;
                }
                // 재파스 지점은 해시하지 않는다 — 링크를 따라간 내용을 링크의
                // 해시로 기록하면 그 값이 무엇을 가리키는지 알 수 없게 된다.
                // 걷기는 끝났고 여기부터가 시간을 쓴다 — 항목마다 읽기·해시·서명.
                remedy_platform::progress::note_item(&e.path);
                // 해시 상한을 넘었지만 룰이 이름을 적은 파일 — 본문을 들지 않고 흘려 읽어
                // 해시만 구한다(`hash_large` · 코어 1.3.0). 판은 본문이 없으므로 빈다.
                let large = !e.is_reparse
                    && e.size > scope.max_hash_bytes
                    && e.size <= scope.max_large_hash_bytes
                    && hash_large_matches(&scope.hash_large, &e.path, scope.platform);
                // **본문을 한 번만 읽는다.** 해시와 버전이 같은 바이트를 쓰므로
                // 버전을 더하는 데 입출력이 늘지 않는다 (C-1b).
                let body = if e.is_reparse {
                    None
                } else if e.size > scope.max_hash_bytes {
                    if !large {
                        remedy_platform::progress::skip_big();
                    }
                    None
                } else {
                    // 읽기와 해시를 따로 잰다 — 검사 시간이 디스크에 가는지 CPU 에
                    // 가는지가 다음 결정을 정한다.
                    let t = std::time::Instant::now();
                    let bytes = self
                        .platform
                        .read_file(&e.path, scope.max_hash_bytes)
                        .ok()
                        .flatten();
                    remedy_platform::progress::add_read(
                        t.elapsed(),
                        bytes.as_ref().map(|b| b.len() as u64).unwrap_or(0),
                    );
                    bytes
                };
                let sha256 = match body.as_ref() {
                    Some(b) => {
                        let t = std::time::Instant::now();
                        let mut hasher = Sha256::new();
                        hasher.update(b);
                        let out = format!("{:x}", hasher.finalize());
                        remedy_platform::progress::add_hash(t.elapsed());
                        Some(out)
                    }
                    None if large => {
                        stream_sha256(&self.platform, &e.path, scope.max_large_hash_bytes)
                    }
                    None => None,
                };
                // 실행 파일에 박힌 버전. 상한을 넘어 읽지 못한 파일과 재파스
                // 지점은 `body` 가 이미 `None` 이므로 여기서 다시 거르지 않는다 —
                // `sha256` 이 `None` 인 것과 **같은 자리에서 같은 이유로** 빈다.
                let version = body.as_ref().and_then(|b| peversion::of(&e.path, b));
                // 2층의 재료 (설계-03 §3). 실행 파일만 확인한다 — 이유는
                // `signature` 모듈 문서에.
                let signature = if !e.is_reparse && signature::should_check(&e.path) {
                    let t = std::time::Instant::now();
                    let s = signature::of(&e.path, e.is_reparse);
                    remedy_platform::progress::add_sign(t.elapsed());
                    s
                } else {
                    None
                };
                h.records.push(FileRecord {
                    path: e.path,
                    size: e.size,
                    mtime: e.mtime,
                    ctime: e.ctime,
                    sha256,
                    signature,
                    version,
                    zone: None,
                    streams: Vec::new(),
                    content_ref: None,
                    package: String::new(),
                    package_match: String::new(),
                });
            }
        }
        // 파일 단계를 떠난다. 뒤 단계에 루트 진행이 남아 있으면 그 단계가
        // 파일 단계인 것처럼 읽힌다.
        remedy_platform::progress::end_roots();
        h.records.sort_by(|a, b| a.path.cmp(&b.path));
        h.records.dedup_by(|a, b| a.path == b.path);
        Ok(h)
    }
}

impl<P: FsRead + EnvRead> PersistenceCollector for Collector<P> {
    /// 지속성은 **스냅샷이 떠진 플랫폼**을 따라 갈린다.
    ///
    /// 실행 중인 OS 가 아니다. 그러면 같은 스냅샷을 두 기계에서 평가한 결과가
    /// 달라진다 (`snapshot_platform` 과 같은 이유).
    fn collect_persistence(
        &self,
        scope: &Scope,
    ) -> Result<Harvest<PersistenceRecord>, CollectError> {
        match scope.platform {
            remedy_sdk::catalog::Platform::Linux => self.collect_cron_and_units(scope),
            _ => self.collect_scheduled_tasks(scope),
        }
    }
}

impl<P: FsRead + EnvRead> Collector<P> {
    fn collect_scheduled_tasks(
        &self,
        scope: &Scope,
    ) -> Result<Harvest<PersistenceRecord>, CollectError> {
        // 예약 작업 정의는 파일이다. COM 을 쓰지 않고 그 파일을 읽는다.
        //
        // 룰이 `source contains "\System32\"` 를 쓰므로 **정의 파일의 실제 경로**가
        // 레코드에 남아야 한다 (설계-04 §2).
        let mut h = Harvest::default();
        let root = self.platform.expand("%SystemRoot%\\System32\\Tasks");
        if !self.platform.exists(&root) {
            // 디렉터리 자체가 안 보인다. 없어서인지 못 봐서인지 구분할 수 없으므로
            // 못 본 것으로 센다 — 조용히 0건으로 보고하면 거짓 음성이 된다.
            h.deny(&root);
            return Ok(h);
        }
        let w = self
            .platform
            .walk(&root, scope.max_files)
            .map_err(|e| CollectError::Other(e.to_string()))?;
        h.truncated = w.truncated;
        h.absorb_denied(w.denied, w.denied_paths);

        let root_norm = normalize::for_record(&root, scope.platform);
        // 작업 계정마다 한 번만 묻는다 — 작업 200여 개가 몇 계정을 나눠 쓴다.
        let mut profiles: std::collections::BTreeMap<String, Option<String>> = Default::default();
        for e in w.entries {
            if e.is_dir || e.is_reparse {
                continue;
            }
            let bytes = match self.platform.read_file(&e.path, 1 << 20) {
                Ok(Some(b)) => b,
                _ => continue,
            };
            let parsed = match task::parse(&bytes) {
                Some(p) => p,
                None => continue,
            };
            let mut r = task::to_record(parsed, &e.path, &root_norm, scope.platform);
            // **작업 계정**의 프로필로 편다 — 엔진을 돌린 계정이 아니다
            // (`WinTaskFields::args_expanded`).
            let profile = r.principal.as_deref().and_then(|p| {
                profiles
                    .entry(p.to_string())
                    .or_insert_with(|| self.platform.profile_of(p))
                    .clone()
            });
            if let Some(win) = r.win.as_mut() {
                win.task.command_expanded =
                    Some(task::expand_user_vars(&r.command, profile.as_deref()));
                win.task.args_expanded = Some(task::expand_user_vars(&r.args, profile.as_deref()));
            }
            h.records.push(r);
        }
        h.records.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(h)
    }

    // ────────────────────────────────────────────────────────── Linux

    /// cron 항목과 systemd 유닛 (설계-09 P12).
    ///
    /// # 못 본 자리를 세어 말한다
    ///
    /// 없는 것과 못 본 것을 구분한다. `/var/spool/cron/crontabs` 는 비관리자로
    /// 돌면 열리지 않는데, 조용히 0건으로 보고하면 **모든 사용자의 개인 crontab
    /// 이 깨끗한 것으로** 읽힌다.
    ///
    /// 자리가 아예 없는 것은 세지 않는다 — 이 배포판에 `/var/spool/cron` 이
    /// 없는 것은 정상이고, 그것까지 세면 어느 기계에서나 "못 본 것이 있다" 가
    /// 되어 그 신호가 죽는다.
    fn collect_cron_and_units(
        &self,
        scope: &Scope,
    ) -> Result<Harvest<PersistenceRecord>, CollectError> {
        let mut h = Harvest::default();
        for f in cron::SYSTEM_FILES {
            self.cron_file(f, true, None, &mut h);
        }
        for d in cron::SYSTEM_DIRS {
            for e in self.list_files(d, scope, &mut h) {
                self.cron_file(&e.path, true, None, &mut h);
            }
        }
        for d in cron::SPOOL_DIRS {
            for e in self.list_files(d, scope, &mut h) {
                // 파일 이름이 곧 사용자다. 이 형식에는 사용자 칸이 없다.
                let owner = e.path.rsplit('/').next().unwrap_or("").to_string();
                self.cron_file(&e.path, false, Some(&owner), &mut h);
            }
        }
        for d in cron::RUN_PARTS {
            for e in self.list_files(d, scope, &mut h) {
                // `run-parts` 는 `.` 이 든 이름을 건너뛴다 — `.dpkg-old` 같은
                // 잔해를 돌리지 않으려는 것이다. 그것을 모르면 **돌지도 않는
                // 파일이 지속성으로** 보고된다.
                let name = e.path.rsplit('/').next().unwrap_or("");
                if name.contains('.') {
                    continue;
                }
                h.records.push(cron::run_parts_record(&e.path, e.mode));
            }
        }

        // **`.timer` 만 본다.** `.service` 는 `service` subject 다 — 카탈로그의
        // 요약이 처음부터 그렇게 적고 있었다 (설계-09 P12 순서 9).
        for d in systemd::SYSTEM_DIRS {
            for (path, u, enabled) in self.units_in(d, scope, ".timer", &mut h) {
                h.records
                    .push(systemd::to_record(u, &path, false, None, enabled));
            }
        }
        for d in systemd::USER_DIRS {
            for (path, u, enabled) in self.units_in(d, scope, ".timer", &mut h) {
                h.records
                    .push(systemd::to_record(u, &path, true, None, enabled));
            }
        }
        // 사용자마다 자기 유닛을 둔다. **여기를 빠뜨리면 사용자 권한만으로
        // 심어진 지속성이 통째로 안 보인다** — 그리고 그것이 가장 흔한 자리다.
        for (owner, home) in self.homes_for(&mut h) {
            let dir = format!("{home}/.config/systemd/user");
            for (path, u, enabled) in self.units_in(&dir, scope, ".timer", &mut h) {
                h.records
                    .push(systemd::to_record(u, &path, true, Some(&owner), enabled));
            }
        }

        // 같은 이름의 유닛이 여러 자리에 있을 수 있으므로 `source` 까지 보고
        // 정렬한다. 순서가 흔들리면 같은 기계의 스냅샷이 실행마다 달라진다.
        h.records
            .sort_by(|a, b| (&a.id, &a.source).cmp(&(&b.id, &b.source)));
        drop_usr_merge_duplicates(&mut h.records);
        Ok(h)
    }

    /// 폴더 하나의 **파일만** 돌려준다. 없으면 조용히 비고, 못 열면 센다.
    fn list_files<T>(
        &self,
        dir: &str,
        scope: &Scope,
        h: &mut Harvest<T>,
    ) -> Vec<remedy_platform::read::FsEntry> {
        if !self.platform.exists(dir) {
            return Vec::new();
        }
        match self.platform.walk(dir, scope.max_files.max(1)) {
            Ok(w) => {
                h.truncated |= w.truncated;
                h.absorb_denied(w.denied, w.denied_paths);
                w.entries
                    .into_iter()
                    .filter(|e| !e.is_dir && !e.is_reparse)
                    .collect()
            }
            Err(_) => {
                h.deny(dir);
                Vec::new()
            }
        }
    }

    /// XDG 자동실행과 로그온 셸 조각 (설계-09 P12 순서 9).
    ///
    /// # 자리가 subject 를 가른다
    ///
    /// 같은 `.desktop` 형식이 `autostart` 아래 있으면 자동실행이고 그 밖에 있으면
    /// 바로가기다 — Windows 에서 시작 폴더의 `.lnk` 와 바탕화면의 `.lnk` 가
    /// 갈리는 것과 같다.
    ///
    /// # `~/.bashrc` 는 여기 없다
    ///
    /// 줄 단위 셸 자동실행은 **명령 하나로 환원되지 않는다.** 잘못 환원하면
    /// 레코드가 거짓을 말하므로, 그 자리는 줄로 담는 subject 가 맡아야 한다.
    pub fn collect_linux_autoruns(
        &self,
        scope: &Scope,
    ) -> Result<Harvest<remedy_artifacts::AutorunRecord>, CollectError> {
        let mut h = Harvest::default();

        let mut dirs: Vec<(String, &str)> = desktop::AUTOSTART_DIRS
            .iter()
            .map(|d| (d.to_string(), "system"))
            .collect();
        for (_, home) in self.homes_for(&mut h) {
            dirs.push((format!("{home}/.config/autostart"), "user"));
        }
        for (dir, scope_name) in dirs {
            for e in self.list_files(&dir, scope, &mut h) {
                if !e.path.ends_with(".desktop") {
                    continue;
                }
                let Ok(Some(bytes)) = self.platform.read_file(&e.path, 1 << 20) else {
                    continue;
                };
                let Ok(text) = String::from_utf8(bytes) else {
                    continue;
                };
                let d = desktop::parse(&text);
                // `Hidden=true` 는 **이 항목을 없는 것으로 하라**는 뜻이다.
                // 담으면 돌지도 않는 항목이 자동실행으로 보고된다.
                if d.hidden {
                    continue;
                }
                h.records.push(desktop::to_autorun(&d, &e.path, scope_name));
            }
        }

        for dir in desktop::PROFILE_DIRS {
            for e in self.list_files(dir, scope, &mut h) {
                h.records.push(desktop::profile_script_to_autorun(&e.path));
            }
        }

        h.records.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(h)
    }

    /// `.desktop` 바로가기 (설계-09 P12 순서 9).
    ///
    /// **`scan_roots` 안에서만 본다.** 자동실행과 달리 자리가 정해져 있지 않고,
    /// 데스크톱 환경마다 응용 목록이 사는 곳이 다르다 — 상한이 없으면 사용자
    /// 문서까지 훑게 된다 (`text_config` 와 같은 판단).
    ///
    /// 자동실행 자리의 항목은 **여기서 뺀다.** 같은 파일이 두 subject 로 들어가면
    /// 같은 것을 두 번 지우려는 계획이 선다.
    pub fn collect_linux_shortcuts(
        &self,
        scope: &Scope,
    ) -> Result<Harvest<remedy_artifacts::ShortcutRecord>, CollectError> {
        let mut h = Harvest::default();
        for path in crate::config::files_with_ext(
            &self.platform,
            scope,
            Subject::Shortcut,
            &[".desktop"],
            &mut h,
        )? {
            if is_autostart_path(&path) {
                continue;
            }
            let Ok(Some(bytes)) = self.platform.read_file(&path, 1 << 20) else {
                continue;
            };
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            h.records
                .push(desktop::to_shortcut(&desktop::parse(&text), &path));
        }
        h.records.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(h)
    }

    /// crontab 파일 하나를 줄 단위로 읽는다.
    fn cron_file(
        &self,
        path: &str,
        has_user: bool,
        owner: Option<&str>,
        h: &mut Harvest<PersistenceRecord>,
    ) {
        let bytes = match self.platform.read_file(path, 1 << 20) {
            Ok(Some(b)) => b,
            // 상한을 넘은 crontab 은 없다고 봐도 되지만, 못 읽은 것과 없는 것은
            // 다르다 — 있는데 못 읽었으면 센다.
            Ok(None) => return,
            Err(_) => {
                if self.platform.exists(path) {
                    h.deny(path);
                }
                return;
            }
        };
        let Ok(text) = String::from_utf8(bytes) else {
            return;
        };
        for (i, line) in text.lines().enumerate() {
            let Some(mut e) = cron::parse_line(line, has_user) else {
                continue;
            };
            if e.user.is_none() {
                e.user = owner.map(|s| s.to_string());
            }
            // 줄 번호는 1 부터다. 편집기가 그렇게 세고, 사람이 그 번호로 연다.
            h.records
                .push(cron::to_record(e, path, i as u32 + 1, line, true));
        }
    }

    /// 폴더 하나에서 접미가 맞는 유닛을 읽는다. `(경로, 파싱 결과, 활성 여부)`.
    ///
    /// **`.service` 와 `.timer` 를 가르는 것이 subject 를 가른다** — 카탈로그의
    /// 요약이 `persistence` 를 "systemd timer", `service` 를 "systemd service"
    /// 라고 적는다 (설계-09 P12 순서 9).
    fn units_in<T>(
        &self,
        dir: &str,
        scope: &Scope,
        suffix: &str,
        h: &mut Harvest<T>,
    ) -> Vec<(String, systemd::ParsedUnit, bool)> {
        // 활성화 링크는 유닛 파일 **밖에** 있다. 폴더를 한 번 훑어 모아 둔다.
        let wants = self.wants_in(dir, scope);
        let mut out = Vec::new();
        for e in self.list_files(dir, scope, h) {
            let name = e.path.rsplit('/').next().unwrap_or("");
            if !name.ends_with(suffix) {
                continue;
            }
            // `.wants/` 아래의 항목은 링크이지 유닛 정의가 아니다. 담으면 같은
            // 유닛이 두 번 세어진다.
            if e.path.contains(".wants/") || e.path.contains(".requires/") {
                continue;
            }
            let Ok(Some(bytes)) = self.platform.read_file(&e.path, 1 << 20) else {
                continue;
            };
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            out.push((e.path.clone(), systemd::parse(&text), wants.contains(name)));
        }
        out
    }

    /// systemd `.service` 유닛 (설계-09 P12 순서 9).
    ///
    /// 자리는 `persistence` 와 같다 — 같은 폴더에 `.service` 와 `.timer` 가 함께
    /// 산다. 가르는 것은 **접미**이고, 그것이 subject 를 가른다.
    pub fn collect_linux_services(
        &self,
        scope: &Scope,
    ) -> Result<Harvest<remedy_artifacts::ServiceRecord>, CollectError> {
        let mut h = Harvest::default();
        let mut dirs: Vec<String> = systemd::SYSTEM_DIRS
            .iter()
            .chain(systemd::USER_DIRS.iter())
            .map(|d| d.to_string())
            .collect();
        for (_, home) in self.homes_for(&mut h) {
            dirs.push(format!("{home}/.config/systemd/user"));
        }
        for d in dirs {
            for (path, u, enabled) in self.units_in(&d, scope, ".service", &mut h) {
                h.records
                    .push(systemd::to_service_record(u, &path, enabled));
            }
        }
        h.records
            .sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        drop_usr_merge_service_duplicates(&mut h.records);
        Ok(h)
    }

    /// `<target>.wants/` 아래에 링크된 유닛 이름들.
    ///
    /// **`[Install] WantedBy=` 는 "활성화될 수 있다" 이지 "활성화되어 있다" 가
    /// 아니다.** 실제 활성화는 이 링크다.
    fn wants_in(&self, dir: &str, scope: &Scope) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        if !self.platform.exists(dir) {
            return out;
        }
        if let Ok(w) = self.platform.walk(dir, scope.max_files.max(1)) {
            for e in w.entries {
                if !(e.path.contains(".wants/") || e.path.contains(".requires/")) {
                    continue;
                }
                if let Some(n) = e.path.rsplit('/').next() {
                    out.insert(n.to_string());
                }
            }
        }
        out
    }

    /// 사용자 홈. `(사용자, 홈 경로)`.
    ///
    /// `/etc/passwd` 를 파싱하지 않는 이유는 `remedy-platform` 의
    /// `%ALLUSERPROFILES%` 와 같다 — 거기엔 사람이 아닌 계정이 섞여 있고, 그것을
    /// 열면 범위가 `/nonexistent` · `/var/lib/*` 로 번진다.
    fn homes_for<T>(&self, h: &mut Harvest<T>) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if self.platform.exists("/home") {
            match self.platform.walk("/home", 1) {
                Ok(w) => {
                    h.absorb_denied(w.denied, w.denied_paths);
                    for e in w.entries {
                        if e.is_dir && !e.is_reparse {
                            if let Some(n) = e.path.rsplit('/').next() {
                                out.push((n.to_string(), e.path.clone()));
                            }
                        }
                    }
                }
                Err(_) => h.deny("/home"),
            }
        }
        if self.platform.exists("/root") {
            out.push(("root".to_string(), "/root".to_string()));
        }
        out.sort();
        out.dedup();
        out
    }
}

/// `/lib` 과 `/usr/lib` 이 **같은 곳**일 때 생기는 중복을 없앤다.
///
/// # 왜 필요한가
///
/// 요즘 배포판은 `/lib` 이 `/usr/lib` 로 가는 심볼릭 링크다(usr-merge). 그러면
/// 유닛 폴더를 두 번 훑게 되고, 실측에서 **186개가 그대로 두 번** 담겼다.
/// 스냅샷이 두 배가 되고 보고서가 같은 유닛을 두 줄로 낸다.
///
/// # 가로채기는 지우지 않는다
///
/// `/etc/systemd/system/foo.service` 가 `/usr/lib/...` 의 같은 이름을 덮는 것은
/// **증거다**(공격자가 벤더 유닛을 가로챘다는 사실 자체). 그래서 여기서는
/// `/lib` 접두를 `/usr/lib` 로 맞춘 뒤 **나머지가 전부 같을 때만** 버린다 —
/// 내용이 다르면 usr-merge 가 아니라 진짜 두 파일이므로 둘 다 남는다.
fn drop_usr_merge_duplicates(records: &mut Vec<PersistenceRecord>) {
    let mut seen = std::collections::BTreeSet::new();
    records.retain(|r| {
        let key = (
            usr_merge_canon(&r.source),
            r.id.clone(),
            r.command.clone(),
            r.args.clone(),
            r.enabled,
            r.trigger.clone(),
            r.principal.clone(),
        );
        seen.insert(key)
    });
}

/// 서비스 쪽의 같은 일. [`drop_usr_merge_duplicates`] 와 같은 이유다.
fn drop_usr_merge_service_duplicates(records: &mut Vec<remedy_artifacts::ServiceRecord>) {
    let mut seen = std::collections::BTreeSet::new();
    records.retain(|r| {
        let key = (
            usr_merge_canon(&r.id),
            r.name.clone(),
            r.image_path.clone(),
            r.start_type.clone(),
        );
        seen.insert(key)
    });
}

/// 이 `.desktop` 이 **자동실행 자리**에 있는가.
///
/// 같은 파일이 `autorun` 과 `shortcut` 두 subject 로 들어가면 같은 것을 두 번
/// 지우려는 계획이 선다.
fn is_autostart_path(path: &str) -> bool {
    path.contains("/autostart/")
}

/// `/lib/...` 를 `/usr/lib/...` 로 맞춘다. usr-merge 된 배포판에서 둘이 같은 곳이다.
fn usr_merge_canon(source: &str) -> String {
    match source.strip_prefix("/lib/") {
        Some(rest) => format!("/usr/lib/{rest}"),
        None => source.to_string(),
    }
}

impl<P: RegistryRead> SecurityProductCollector for Collector<P> {
    fn collect_security_products(&self) -> Result<Vec<SecurityProduct>, CollectError> {
        // Defender 의 실시간 감시 상태. 변조 보호가 켜져 있으면 못 읽을 수 있고,
        // 그때는 '모름' 이다.
        let defender_installed = self
            .platform
            .subkeys(DEFENDER_KEY)
            .map(|k| !k.is_empty())
            .unwrap_or(false);
        let defender_realtime = if defender_installed {
            match self.platform.value(
                &format!("{DEFENDER_KEY}\\Real-Time Protection"),
                "DisableRealtimeMonitoring",
            ) {
                Ok(Some(RegValue::Dword(d))) => Some(d == 0),
                Ok(None) => Some(true),
                _ => None,
            }
        } else {
            None
        };

        let mut out = Vec::new();
        let mut defender_reported = false;

        // 보안 센터에 등록된 공급자가 사실상의 설치 목록이다.
        if let Ok(providers) = self.platform.subkeys(SECURITY_CENTER_AV) {
            for guid in providers {
                let key = format!("{SECURITY_CENTER_AV}\\{guid}");
                let name = match self.platform.value(&key, "DISPLAYNAME") {
                    Ok(Some(RegValue::Str(s))) if !s.is_empty() => s,
                    _ => continue,
                };
                let is_defender = guid.eq_ignore_ascii_case(DEFENDER_PROVIDER_GUID);
                defender_reported |= is_defender;
                out.push(SecurityProduct {
                    vendor: name,
                    realtime: if is_defender { defender_realtime } else { None },
                });
            }
        }

        // 보안 센터에 Defender 가 없는데 설치되어 있다면 따로 담는다.
        if defender_installed && !defender_reported {
            out.push(SecurityProduct {
                vendor: "Windows Defender".into(),
                realtime: defender_realtime,
            });
        }

        out.sort_by(|a, b| a.vendor.cmp(&b.vendor));
        out.dedup_by(|a, b| a.vendor == b.vendor);
        Ok(out)
    }
}

/// 선언된 subject 만 수집한다. **선언한 것만 볼 수 있다.**
///
/// # 지금은 17종 전부에 자리가 있다
///
/// 한동안 `network_conn` 하나가 빠져 있었다. 연결 목록을 읽으려면 `iphlpapi` 가
/// 필요한데 배포 바이너리 검사가 그 임포트를 막고 있었기 때문이다. 그것은
/// **카탈로그에서 빠졌다** — 임포트 때문이 아니라 연결 표본이 판정 입력이 될 수
/// 없어서다 (설계-01 D11).
///
/// 그래서 지금은 선언된 subject 가 전부 담긴다. `tests/missing_roots.rs` 의
/// `every_declared_subject_gets_collected` 가 그것을 지킨다 — subject 를 새로
/// 넣고 여기 `harvest!` 줄을 빠뜨리면 그 시험이 깨진다.
///
/// 담기지 않은 subject 를 `uncollected_subjects` 로 보고하는 길은 그대로 있다
/// (`remedy_artifacts::assemble`). **지금 그 길로 나갈 subject 가 없을 뿐이고**,
/// 다음에 수집기 없는 subject 를 정의할 때 필요한 안전망이다. 그 성질 자체는
/// `remedy-artifacts` 의 `tests/format.rs` 가 직접 시험한다.
/// 이 루트가 실제로 있는가. **레지스트리 루트는 레지스트리에 묻는다.**
///
/// # 왜 나누는가
///
/// `FsRead::exists` 는 파일 시스템의 물음이다. `HKLM\SOFTWARE\…` 를 그것에
/// 넘기면 언제나 거짓이고, 그러면 **읽어 낸 키가 "없는 루트" 로 집계된다.**
///
/// 2026-09-04 실기기에서 드러났다. `appinit-implant` 정답을 청정 Win10 에
/// 돌렸더니 종료 코드 6(관측 불완전)이었다 — 선언한 루트 셋 중 둘은 검체의
/// 폴더라 정말로 없고, 셋째인 레지스트리 키는 **값 19개를 읽어냈는데도**
/// 없는 것으로 세어 `all_roots_missing()` 이 성립했다.
///
/// 그 자리가 가장 나쁘다. 검체의 폴더로 좁게 잡는 것이 옳은 설계인데, 그렇게
/// 적은 플러그인이 **청정 기계마다** 관측 불완전을 낸다 — 건강한 기계 전부에서
/// 우는 경보다.
///
/// `RegistryRead::key_exists` 는 처음부터 *"없는 것과 못 읽는 것을 가르는 데
/// 쓴다"* 고 적혀 있었고 레지스트리 수집기 전체가 그것을 쓴다. 여기만 쓰지
/// 않고 있었다.
/// # 세 갈래로 답한다 (B-9 · 2026-10-27)
///
/// 참·거짓이던 동안 *"없다"* 와 *"못 물었다"* 가 `missing_roots` 한 칸에
/// 들어갔다. 열린 루트가 하나라도 함께 있으면 `all_roots_missing()` 이
/// 성립하지 않아 **경고 한 줄 없이 종료 0** 이 나갔다 — 기계에 들여다보지도
/// 못한 폴더가 있는데 도구가 *"위협이 발견되지 않았습니다"* 라고 말했다(실측).
///
/// 레지스트리 쪽은 [`remedy_platform::read::seen`] 이 처음부터 갈라 물었고,
/// 예약 작업 디렉터리도 *"없어서인지 못 봐서인지 구분할 수 없으므로 못 본
/// 것으로 센다"* 고 적혀 있었다. **`scan_roots` 만 그 규율 밖이었다.**
fn root_look<P: FsRead + RegistryRead>(p: &P, root: &str) -> Seen {
    if remedy_sdk::catalog::is_registry_root(root) {
        // 끝의 `\*` 는 "직속 하위 키로 펼쳐라" 는 표시다. 있는지 묻는 대상은
        // 별표를 뗀 그 키다 — 별표째 물으면 어떤 키도 존재하지 않는다.
        let key = root
            .strip_suffix("\\*")
            .or_else(|| root.strip_suffix("/*"))
            .unwrap_or(root);
        if p.key_exists(key) {
            return Seen::Present;
        }
        // **부모에게 물어 갈라야** 잠긴 키가 "없는 루트" 로 집계되지 않는다.
        // `registry.rs` 의 수집기들이 쓰는 것과 같은 길이다.
        registry::unreadable_or_absent(p, key)
    } else {
        // 글롭 뿌리(`…\Temp\*.js`)는 **그 폴더**를 묻는다 — 꼴째 물으면 어떤 파일도
        // 그 이름으로 있지 않아 늘 '없는 뿌리' 가 된다. 위 레지스트리 갈래와 같은 일이다.
        p.look(root_dir(root))
    }
}

/// 있는지 물을 자리 — 글롭 뿌리면 그 폴더, 아니면 뿌리 그대로.
fn root_dir(root: &str) -> &str {
    remedy_sdk::normalize::glob_root(root)
        .map(|(dir, _)| dir)
        .unwrap_or(root)
}

/// 뿌리가 있는가. 수집기들이 걷기 전에 거르는 데 쓴다 — 글롭 뿌리는 그 폴더를 본다
/// (위 `root_look` 과 같은 이유).
pub(crate) fn root_exists<P: FsRead>(p: &P, root: &str) -> bool {
    p.exists(root_dir(root))
}

/// 이 경로의 **파일 이름**이 `hash_large` 의 꼴 하나에 맞는가 — 글롭 뿌리와 같은 규칙이다
/// (`*` · `?` · 대소문자는 플랫폼대로).
fn hash_large_matches(
    patterns: &[String],
    path: &str,
    platform: remedy_sdk::catalog::Platform,
) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    let name = normalize::for_compare(name, platform);
    patterns
        .iter()
        .any(|p| normalize::name_matches(&name, &normalize::for_compare(p.trim(), platform)))
}

/// 큰 파일을 흘려 읽어 SHA-256 을 구한다 — 본문을 들지 않는다.
///
/// 못 읽었거나 읽는 사이에 상한을 넘으면 `None` 이다. 해시가 비는 것은 상한을 넘은 파일과
/// **같은 자리 · 같은 뜻**이다 — 룰은 그것을 *"재지 못했다"* 로 읽는다.
fn stream_sha256<P: FsRead>(fs: &P, path: &str, max: u64) -> Option<String> {
    let t = std::time::Instant::now();
    let mut hasher = Sha256::new();
    let mut read = 0u64;
    let whole = fs
        .read_stream(path, max, &mut |chunk| {
            hasher.update(chunk);
            read += chunk.len() as u64;
        })
        .ok()?;
    remedy_platform::progress::add_read(t.elapsed(), read);
    whole.then(|| format!("{:x}", hasher.finalize()))
}

pub fn collect_all<P: FsRead + RegistryRead + EnvRead + ProcessRead>(
    collector: &Collector<P>,
    scope: &Scope,
) -> Result<Observations, CollectError>
where
    Collector<P>: FileCollector + PersistenceCollector + SecurityProductCollector,
{
    // **루트가 존재하는지는 subject 와 무관한 물음이다.** 그래서 어느 수집기
    // 안이 아니라 여기서 한 번만 묻는다 — `collect_files` 안에서 세면 `file` 을
    // 선언하지 않은 플러그인에서는 아무도 묻지 않게 된다.
    //
    // 없는 루트를 조용히 건너뛰던 것이 관측 01 의 D2 였다. `scan_roots` 가
    // 통째로 어긋난 실행이 "파일 0건 · 완전한 관측 · 종료 코드 0" 으로 나왔다.
    // **"없다" 와 "못 물었다" 를 가른다** (B-9 · 2026-10-27). 한 칸에 담던
    // 동안, 열린 루트가 하나라도 함께 있으면 `all_roots_missing()` 이 성립하지
    // 않아 못 본 자리가 **아무 흔적 없이** 사라졌다.
    let mut missing_roots = Vec::new();
    let mut unreadable_roots = Vec::new();
    for r in &scope.scan_roots {
        match root_look(&collector.platform, r) {
            Seen::Present => {}
            Seen::Absent => missing_roots.push(r.clone()),
            // 있는데 열리지 않거나(Locked) 물어도 답이 없다(CannotTell).
            // 둘 다 **없다고 말할 수 없는** 자리다.
            Seen::Locked | Seen::CannotTell => unreadable_roots.push(r.clone()),
        }
    }
    // **좁힌 자리도 선언한 자리다** (2026-10-27 · 적대 검증이 짚었다).
    //
    // `subject_roots` 는 `scan_roots` 보다 **깊은** 경로일 수 있고, 그러면 위
    // 루프가 그것을 보지 못한다. 수집기들은 `roots_for(S)` 를 두 갈래
    // `exists()` 로 걸러 내므로(`collect_files` 의 첫 줄 등) **못 물은 자리가
    // 흔적 없이 사라진다** — `scan_roots` 쪽에서 막은 바로 그 구멍이 한 층
    // 아래 남아 있었다. 수집기마다 고치는 대신 **묻는 자리를 하나로** 둔다.
    //
    // **없는 것은 세지 않는다.** 미설치가 정상이고, `missing_roots` 에 더하면
    // `all_roots_missing()` 의 분모(`declared_roots` — `scan_roots` 의 수)와
    // 어긋나 청정 기계의 판정이 뒤집힌다. 못 물은 것만 센다.
    for (s, roots) in &scope.subject_roots {
        if !scope.subjects.contains(s) {
            continue;
        }
        for r in roots {
            if scope.scan_roots.contains(r) {
                continue;
            }
            if matches!(
                root_look(&collector.platform, r),
                Seen::Locked | Seen::CannotTell
            ) {
                unreadable_roots.push(r.clone());
            }
        }
    }
    // 여러 subject 가 같은 자리를 좁혀 가리킬 수 있다. 사유 줄에 두 번 적지 않는다.
    unreadable_roots.sort();
    unreadable_roots.dedup();

    let mut obs = Observations {
        missing_roots,
        unreadable_roots,
        ..Default::default()
    };

    if scope.subjects.contains(&Subject::File) {
        remedy_platform::progress::set_stage("file");
        let mut h = collector.collect_files(scope)?;
        // **패키지를 보는 룰이면** 모은 파일이 패키지가 깐 그대로인지 적는다(코어 1.7.0 · `owner`). 패키지 DB 는
        // `package` subject 의 고정 자리라, 그것을 선언하지 않은 룰에서는 읽지 않는다.
        if scope.platform == remedy_sdk::catalog::Platform::Linux
            && scope.subjects.contains(&Subject::Package)
        {
            owner::annotate(&collector.platform, scope, &mut h);
        }
        obs.absorb(&h);
        obs.put(Subject::File, &h.records);
    }
    if scope.subjects.contains(&Subject::Persistence) {
        remedy_platform::progress::set_stage("persistence");
        let h = collector.collect_persistence(scope)?;
        obs.absorb(&h);
        obs.put(Subject::Persistence, &h.records);
    }

    // P4 subject. 각각 자기 자리를 알고 있으므로 여기서는 **선언 여부만** 본다.
    //
    // `harvest!` 로 묶는 이유는 세 줄(잘림·거부·담기)이 매번 같고, 그중 하나를
    // 빠뜨리면 못 본 것이 없는 것으로 보고되기 때문이다.
    macro_rules! harvest {
        ($subject:expr, $call:expr) => {
            if scope.subjects.contains(&$subject) {
                let h = $call;
                obs.absorb(&h);
                obs.put($subject, &h.records);
            }
        };
    }

    let p = &collector.platform;
    // 자동실행과 바로가기도 플랫폼마다 사는 곳이 다르다. 같은 `.desktop`
    // 형식이 **자리에 따라** 두 subject 로 갈린다 (설계-09 P12 순서 9).
    remedy_platform::progress::set_stage("autorun");
    harvest!(
        Subject::Autorun,
        match scope.platform {
            remedy_sdk::catalog::Platform::Linux => collector.collect_linux_autoruns(scope),
            _ => registry::autoruns(p, p.own_sid().as_deref()),
        }?
    );
    // 서비스도 플랫폼마다 사는 곳이 다르다. `persistence` 와 같은 이유로
    // **스냅샷이 떠진 플랫폼**을 따른다.
    remedy_platform::progress::set_stage("service");
    harvest!(
        Subject::Service,
        match scope.platform {
            remedy_sdk::catalog::Platform::Linux => collector.collect_linux_services(scope),
            _ => registry::services(p),
        }?
    );
    remedy_platform::progress::set_stage("av_exclusion");
    harvest!(Subject::AvExclusion, registry::av_exclusions(p)?);
    remedy_platform::progress::set_stage("proxy_config");
    harvest!(Subject::ProxyConfig, registry::proxy_configs(p)?);
    remedy_platform::progress::set_stage("firewall_rule");
    harvest!(Subject::FirewallRule, registry::firewall_rules(p)?);
    remedy_platform::progress::set_stage("boot_config");
    harvest!(Subject::BootConfig, registry::boot_configs(p)?);
    // 레지스트리 값은 **이진 값의 바이트도 함께** 낸다. 그것이 스냅샷의
    // `blobs` 로 가야 `yara` 를 이진 값에 걸 수 있다.
    if scope.subjects.contains(&Subject::RegistryValue) {
        remedy_platform::progress::set_stage("registry_value");
        let (h, blobs) = registry::registry_values(p, scope)?;
        obs.absorb(&h);
        obs.put(Subject::RegistryValue, &h.records);
        for (k, v) in blobs {
            use base64::Engine;
            obs.blobs
                .entry(k)
                .or_insert_with(|| base64::engine::general_purpose::STANDARD.encode(&v));
        }
    }
    remedy_platform::progress::set_stage("registry_key");
    harvest!(Subject::RegistryKey, registry::registry_keys(p, scope)?);
    remedy_platform::progress::set_stage("hosts_entry");
    harvest!(Subject::HostsEntry, config::hosts_entries(p, scope)?);
    remedy_platform::progress::set_stage("text_config");
    harvest!(Subject::TextConfig, config::text_configs(p, scope)?);
    remedy_platform::progress::set_stage("structured_config");
    harvest!(
        Subject::StructuredConfig,
        config::structured_configs(p, scope)?
    );
    remedy_platform::progress::set_stage("shortcut");
    harvest!(
        Subject::Shortcut,
        match scope.platform {
            remedy_sdk::catalog::Platform::Linux => collector.collect_linux_shortcuts(scope),
            _ => shortcut::shortcuts(p, scope),
        }?
    );
    remedy_platform::progress::set_stage("browser_extension");
    harvest!(
        Subject::BrowserExtension,
        derived::browser_extensions(p, scope)?
    );
    // 인증서도 플랫폼마다 사는 곳이 다르다 — Windows 는 레지스트리 값,
    // Linux 는 파일이다 (설계-09 P12 후속).
    remedy_platform::progress::set_stage("cert_store");
    harvest!(
        Subject::CertStore,
        match scope.platform {
            remedy_sdk::catalog::Platform::Linux => certstore::cert_stores_linux(p, scope),
            _ => certstore::cert_stores(p),
        }?
    );
    remedy_platform::progress::set_stage("process");
    harvest!(
        Subject::Process,
        derived::processes(p, scope.process_modules)?
    );
    // 패키지 DB 도 자리가 정해져 있다 — **파일로 직접 읽는다.** 매니저를
    // 부르면 수집 중 자식 프로세스 0 이 깨진다 (C-2).
    remedy_platform::progress::set_stage("package");
    harvest!(Subject::Package, package::packages(p, scope)?);
    // UNIX 소켓도 자리가 정해져 있다 — `/proc/net/unix` 를 파일로 읽는다(코어 1.2.0).
    remedy_platform::progress::set_stage("unix_socket");
    harvest!(Subject::UnixSocket, unix_socket::unix_sockets(p, scope)?);

    // `indicator` 는 **마지막이다.** 앞의 관찰에서 뽑아내므로 그것들이 먼저
    // 담겨 있어야 한다.
    if scope.subjects.contains(&Subject::Indicator) {
        remedy_platform::progress::set_stage("indicator");
        let h = derived::indicators(&indicator_sources(&obs));
        obs.put(Subject::Indicator, &h.records);
    }

    // 보안 제품은 subject 가 아니다. 판단이 아니라 진단 정보이므로 항상 담는다.
    obs.security_products = collector.collect_security_products()?;
    Ok(obs)
}

/// 지표를 뽑아낼 자리. `(source_ref, 훑을 문자열)`.
///
/// **이미 담긴 관찰에서만 뽑는다.** 시스템을 다시 보지 않으므로 같은 스냅샷에서
/// 언제나 같은 지표가 나온다.
fn indicator_sources(obs: &Observations) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (subject, fields) in [
        (Subject::Persistence, &["command", "args"][..]),
        (Subject::Autorun, &["command"][..]),
        (Subject::Process, &["cmdline_decoded"][..]),
        (Subject::TextConfig, &["line"][..]),
        (Subject::StructuredConfig, &["value"][..]),
        (Subject::HostsEntry, &["ip"][..]),
    ] {
        let Some(serde_json::Value::Array(rows)) = obs.records.get(&subject) else {
            continue;
        };
        for (i, row) in rows.iter().enumerate() {
            for f in fields {
                if let Some(text) = row.get(*f).and_then(|v| v.as_str()) {
                    if !text.is_empty() {
                        out.push((format!("{}[{i}].{f}", subject.id()), text.to_string()));
                    }
                }
            }
        }
    }
    out
}
