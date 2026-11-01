//! Linux 지속성 수집 (설계-09 P12).
//!
//! # 왜 가짜 파일 시스템인가
//!
//! 이 시험이 묻는 것은 파서가 아니라 **수집기가 어디를 보고 무엇을 채우는가**다.
//! 파서는 `cron`·`systemd` 모듈의 단위 시험이 따로 잰다.
//!
//! 실기기에 대고 재면 배포판마다 답이 달라져 CI 에서 못 쓰고, 무엇보다 **없는
//! 자리를 못 본 것으로 세는지**를 재려면 그 자리가 없어야 한다.

use remedy_artifacts::{PersistenceCollector, Scope};
use remedy_collect::Collector;
use remedy_platform::read::{EnvRead, FsEntry, FsRead, Seen, WalkResult};
use remedy_platform::PlatformError;
use remedy_sdk::catalog::{Platform, Subject};
use std::collections::BTreeMap;

/// 경로 → 내용. 디렉터리는 값이 없는 항목으로 둔다.
struct Fs {
    files: BTreeMap<String, String>,
    dirs: Vec<String>,
    /// 실행 비트가 있는 파일.
    exec: Vec<String>,
    /// 열려고 하면 거부되는 디렉터리.
    denied: Vec<String>,
}

impl Fs {
    fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            dirs: Vec::new(),
            exec: Vec::new(),
            denied: Vec::new(),
        }
    }
    fn file(mut self, path: &str, body: &str) -> Self {
        self.files.insert(path.to_string(), body.to_string());
        let mut p = path;
        while let Some((d, _)) = p.rsplit_once('/') {
            if d.is_empty() {
                break;
            }
            self.dirs.push(d.to_string());
            p = d;
        }
        self
    }
    fn executable(mut self, path: &str) -> Self {
        self.exec.push(path.to_string());
        self
    }
    fn denied_dir(mut self, path: &str) -> Self {
        self.denied.push(path.to_string());
        self.dirs.push(path.to_string());
        self
    }
}

impl FsRead for Fs {
    fn walk(&self, root: &str, _limit: usize) -> Result<WalkResult, PlatformError> {
        if self.denied.iter().any(|d| d == root) {
            return Ok(WalkResult {
                entries: Vec::new(),
                truncated: false,
                denied: 1,
                denied_paths: Vec::new(),
            });
        }
        let prefix = format!("{root}/");
        let mut entries: Vec<FsEntry> = self
            .files
            .keys()
            .filter(|p| p.starts_with(&prefix))
            .map(|p| FsEntry {
                path: p.clone(),
                is_dir: false,
                is_reparse: false,
                size: 1,
                mtime: "2026-08-27T00:00:00Z".into(),
                ctime: None,
                mode: Some(if self.exec.contains(p) { 0o755 } else { 0o644 }),
            })
            .collect();
        entries.extend(
            self.dirs
                .iter()
                .filter(|p| p.starts_with(&prefix) && !p[prefix.len()..].contains('/'))
                .map(|p| FsEntry {
                    path: p.clone(),
                    is_dir: true,
                    is_reparse: false,
                    size: 0,
                    mtime: "2026-08-27T00:00:00Z".into(),
                    ctime: None,
                    mode: Some(0o755),
                }),
        );
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries.dedup();
        Ok(WalkResult {
            entries,
            truncated: false,
            denied: 0,
            denied_paths: Vec::new(),
        })
    }

    fn read_file(&self, path: &str, _max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
        match self.files.get(path) {
            Some(b) => Ok(Some(b.as_bytes().to_vec())),
            None => Err(PlatformError::Unsupported("없다")),
        }
    }

    fn look(&self, path: &str) -> Seen {
        if self.files.contains_key(path) || self.dirs.iter().any(|d| d == path) {
            Seen::Present
        } else {
            Seen::Absent
        }
    }
}

impl EnvRead for Fs {
    fn expand(&self, s: &str) -> String {
        s.to_string()
    }
}

fn linux_scope() -> Scope {
    let mut s = Scope::diagnostic(vec!["/".into()], Platform::Linux);
    s.subjects = vec![Subject::Persistence];
    s.max_files = 10_000;
    s
}

fn collect(fs: Fs) -> remedy_artifacts::Harvest<remedy_artifacts::PersistenceRecord> {
    Collector::new(fs)
        .collect_persistence(&linux_scope())
        .expect("수집")
}

/// `service` subject 로 모은다. **`.service` 는 여기다** — 카탈로그의 요약이
/// `persistence` 를 "systemd timer", `service` 를 "systemd service" 라고 적는다
/// (설계-09 P12 순서 9).
fn services(fs: Fs) -> Vec<remedy_artifacts::ServiceRecord> {
    let mut s = linux_scope();
    s.subjects = vec![Subject::Service];
    Collector::new(fs)
        .collect_linux_services(&s)
        .expect("수집")
        .records
}

#[test]
fn a_reboot_crontab_entry_is_found_with_its_owner() {
    // **가장 흔한 Linux 지속성이다.** 개인 crontab 에는 사용자 칸이 없고, 그
    // 사실을 모르면 `/home/a/.cache/upd.sh` 가 사용자 이름으로 먹힌다.
    let h = collect(Fs::new().file(
        "/var/spool/cron/crontabs/analyst",
        "# m h dom mon dow command\n@reboot /home/analyst/.cache/upd.sh --quiet\n",
    ));
    let r = h
        .records
        .iter()
        .find(|r| r.command.contains("upd.sh"))
        .unwrap_or_else(|| panic!("못 찾았다: {:?}", h.records));
    assert_eq!(r.trigger, vec!["boot"]);
    assert_eq!(
        r.principal.as_deref(),
        Some("analyst"),
        "파일 이름이 사용자다"
    );
    assert_eq!(r.args, "--quiet");
    assert_eq!(r.id, "/var/spool/cron/crontabs/analyst:2");
}

const UNIT: &str = "\
[Unit]
Description=updater

[Service]
ExecStart=/home/analyst/.local/bin/upd

[Install]
WantedBy=default.target
";

#[test]
fn a_run_parts_script_without_the_exec_bit_is_not_enabled() {
    // `run-parts` 가 건너뛴다. 켜진 것으로 보고하면 없는 지속성을 만든다.
    let h = collect(
        Fs::new()
            .file("/etc/cron.daily/live", "#!/bin/sh\n")
            .executable("/etc/cron.daily/live")
            .file("/etc/cron.daily/dead", "#!/bin/sh\n"),
    );
    let live = h.records.iter().find(|r| r.name == "live").expect("live");
    let dead = h.records.iter().find(|r| r.name == "dead").expect("dead");
    assert!(live.enabled);
    assert!(!dead.enabled);
}

#[test]
fn a_dotted_name_in_a_run_parts_directory_is_skipped() {
    // `run-parts` 는 `.` 이 든 이름을 돌리지 않는다. `.dpkg-old` 잔해를
    // 지속성으로 보고하면 그것을 지우려는 계획이 선다.
    let h = collect(
        Fs::new()
            .file("/etc/cron.daily/logrotate.dpkg-old", "#!/bin/sh\n")
            .executable("/etc/cron.daily/logrotate.dpkg-old"),
    );
    assert!(h.records.is_empty(), "{:?}", h.records);
}

#[test]
fn a_directory_we_could_not_open_is_counted() {
    // **없는 것과 못 본 것은 다르다.** `/var/spool/cron/crontabs` 는 비관리자로
    // 돌면 안 열리는데, 조용히 0건이면 모든 사용자의 crontab 이 깨끗한 것으로
    // 읽힌다 (관측 01 D2 와 같은 사고).
    let h = collect(Fs::new().denied_dir("/var/spool/cron/crontabs"));
    assert!(h.records.is_empty());
    assert_eq!(h.denied_dirs, 1, "못 본 사실이 세어지지 않았다");
}

#[test]
fn a_place_that_simply_does_not_exist_is_not_counted_as_denied() {
    // 이 배포판에 `/var/spool/cron` 이 없는 것은 정상이다. 그것까지 세면 어느
    // 기계에서나 "못 본 것이 있다" 가 되어 그 신호가 죽는다.
    let h = collect(Fs::new().file("/etc/systemd/system/upd.service", UNIT));
    assert_eq!(h.denied_dirs, 0, "{h:?}");
}

#[test]
fn windows_snapshots_still_take_the_task_path() {
    // 갈림길은 **스냅샷이 떠진 플랫폼**이 정한다. 실행 중인 OS 로 가르면 같은
    // 스냅샷을 두 기계에서 평가한 결과가 달라진다.
    let mut s = Scope::diagnostic(vec!["c:\\x".into()], Platform::Windows);
    s.subjects = vec![Subject::Persistence];
    let h = Collector::new(Fs::new())
        .collect_persistence(&s)
        .expect("수집");
    // Windows 경로는 `%SystemRoot%\System32\Tasks` 를 찾고, 이 가짜 파일
    // 시스템에는 없으므로 **못 본 것으로 센다.**
    assert!(h.records.is_empty());
    assert_eq!(h.denied_dirs, 1);
}

// ─────────────────────────────────── systemd — 접미가 subject 를 가른다

const TIMER: &str = "\
[Unit]
Description=updater timer

[Timer]
OnCalendar=daily

[Install]
WantedBy=timers.target
";

#[test]
fn a_service_unit_is_not_persistence() {
    // **이것이 이번 교정이다.** 카탈로그의 요약이 처음부터 `persistence` 를
    // "예약 작업 · cron · systemd **timer**" 라고 적고 있었는데, 수집기가
    // `.service` 까지 거기 담고 있었다. 그러면 `service.*` Op 넷이 도달할 수
    // 없고, 룰 작성자는 `systemctl` 이 부르는 이름과 다른 subject 를 써야 한다.
    let fs = || {
        Fs::new()
            .file("/etc/systemd/system/upd.service", UNIT)
            .file("/etc/systemd/system/upd.timer", TIMER)
    };
    let persistence = collect(fs());
    let ids: Vec<&str> = persistence.records.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["/etc/systemd/system/upd.timer"],
        "타이머만 지속성이어야 한다"
    );

    let svc = services(fs());
    let names: Vec<&str> = svc.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["upd.service"], "{svc:?}");
}

#[test]
fn a_service_unit_carries_its_path_and_exec() {
    // `ServiceRecord` 에는 `source` 가 없다. 계획기가 대상을 정할 자리가 `id`
    // 뿐이고, **이름만으로는 실행기가 유닛 파일을 찾아 헤매야 한다.**
    let svc = services(Fs::new().file("/etc/systemd/system/upd.service", UNIT));
    let r = svc.first().expect("유닛");
    assert_eq!(r.id, "/etc/systemd/system/upd.service");
    assert_eq!(r.name, "upd.service");
    assert_eq!(r.image_path, "/home/analyst/.local/bin/upd");
    // 돌고 있는지는 파일에 없다. Windows 수집기와 같은 답을 낸다.
    assert_eq!(r.state, "unknown");
}

#[test]
fn a_wants_link_decides_the_start_type() {
    // **`[Install] WantedBy=` 는 "켤 수 있다" 이지 "켜져 있다" 가 아니다.**
    let off = services(Fs::new().file("/etc/systemd/system/upd.service", UNIT));
    assert_eq!(off[0].start_type, "disabled");

    let on = services(
        Fs::new()
            .file("/etc/systemd/system/upd.service", UNIT)
            .file("/etc/systemd/system/default.target.wants/upd.service", ""),
    );
    assert_eq!(on.len(), 1, "링크를 유닛으로 두 번 세었다: {on:?}");
    assert_eq!(on[0].start_type, "enabled");
}

#[test]
fn a_unit_without_an_install_section_is_static() {
    // 켤 수 있는 것이 아니라 다른 유닛이 끌어올릴 때만 도는 유닛이다.
    // `disabled` 로 적으면 "꺼 두었다" 로 읽혀 사실과 다르다.
    let svc = services(Fs::new().file(
        "/usr/lib/systemd/system/dep.service",
        "[Service]\nExecStart=/usr/bin/dep\n",
    ));
    assert_eq!(svc[0].start_type, "static");
}

#[test]
fn the_same_service_under_lib_and_usr_lib_is_one_registration() {
    // usr-merge 된 배포판에서 `/lib` 은 `/usr/lib` 로 가는 링크다.
    let svc = services(
        Fs::new()
            .file("/lib/systemd/system/upd.service", UNIT)
            .file("/usr/lib/systemd/system/upd.service", UNIT),
    );
    assert_eq!(svc.len(), 1, "{svc:?}");
}

#[test]
fn a_service_shadowed_in_etc_stays_visible() {
    // 위 시험이 통과하는 잘못된 방법이 "같은 이름이면 하나만" 이다. 그러면
    // **공격자가 벤더 유닛을 가로챈 사실이 사라진다.**
    let evil = UNIT.replace("/home/analyst/.local/bin/upd", "/tmp/.x/upd");
    let svc = services(
        Fs::new()
            .file("/usr/lib/systemd/system/upd.service", UNIT)
            .file("/etc/systemd/system/upd.service", &evil),
    );
    let paths: Vec<&str> = svc.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "/etc/systemd/system/upd.service",
            "/usr/lib/systemd/system/upd.service"
        ],
        "가로채기가 사라졌다"
    );
}
