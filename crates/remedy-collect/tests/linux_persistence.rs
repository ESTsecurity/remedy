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
    /// 있는지조차 물을 수 없는 자리(`look` 이 `Locked`).
    locked: Vec<String>,
}

impl Fs {
    fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            dirs: Vec::new(),
            exec: Vec::new(),
            denied: Vec::new(),
            locked: Vec::new(),
        }
    }
    fn locked(mut self, path: &str) -> Self {
        self.locked.push(path.to_string());
        self
    }
    /// `dir` 바로 아래의 항목 — `(경로, 폴더인가)` 를 이름 차례로.
    fn children(&self, dir: &str) -> Vec<(String, bool)> {
        let prefix = format!("{dir}/");
        let direct = |p: &&String| p.starts_with(&prefix) && !p[prefix.len()..].contains('/');
        let mut out: Vec<(String, bool)> = self
            .files
            .keys()
            .filter(direct)
            .map(|p| (p.clone(), false))
            .collect();
        out.extend(self.dirs.iter().filter(direct).map(|p| (p.clone(), true)));
        out.sort();
        out.dedup();
        out
    }
    fn entry(&self, path: &str, is_dir: bool) -> FsEntry {
        FsEntry {
            path: path.to_string(),
            is_dir,
            is_reparse: false,
            size: if is_dir { 0 } else { 1 },
            mtime: "2026-08-27T00:00:00Z".into(),
            ctime: None,
            mode: Some(if is_dir || self.exec.iter().any(|e| e == path) {
                0o755
            } else {
                0o644
            }),
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
    /// `local::walk` 의 차례와 상한 규칙을 따른다 — 폴더마다 이름 차례로 읽어 깊이 먼저 내려가고, 폴더는
    /// 세지 않고 담으며, 파일에서 담은 수가 `limit` 에 닿아 있으면 잘림을 세우고 걷기를 끝낸다. 이 규칙을
    /// 따르지 않던 동안에는 상한 1 로 `/home` 을 걷던 홈 찾기의 결함이 이 시험에서 드러나지 않았다(#172).
    fn walk(&self, root: &str, limit: usize) -> Result<WalkResult, PlatformError> {
        let mut out = Vec::new();
        let mut truncated = false;
        let mut denied = 0;
        let mut stack = vec![root.to_string()];
        while let Some(dir) = stack.pop() {
            if truncated {
                break;
            }
            if self.denied.contains(&dir) {
                denied += 1;
                continue;
            }
            let mut subdirs = Vec::new();
            for (path, is_dir) in self.children(&dir) {
                if !is_dir && out.len() >= limit {
                    truncated = true;
                    break;
                }
                out.push(self.entry(&path, is_dir));
                if is_dir {
                    subdirs.push(path);
                }
            }
            subdirs.reverse();
            stack.extend(subdirs);
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(WalkResult {
            entries: out,
            truncated,
            denied,
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
        if self.locked.iter().any(|d| d == path) {
            Seen::Locked
        } else if self.files.contains_key(path) || self.dirs.iter().any(|d| d == path) {
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

/// **SysV · OpenRC · Upstart 의 시작 스크립트도 서비스다** (2026-11-12 · 목표 결정 28). 실행하지 않고 푼
/// 실행 파일 하나가 레코드 하나이고, 덮어쓰는 설정은 스크립트가 그 자리를 적었을 때(OpenRC 는 늘)만 읽는다.
/// 바로 아래가 아닌 파일 · `.conf` 가 아닌 Upstart 파일은 스크립트가 아니다.
#[test]
fn legacy_init_scripts_give_one_service_record_per_program() {
    let svc = services(
        Fs::new()
            .file(
                "/etc/init.d/php83-fpm",
                "#!/bin/sh\nphp_fpm_BIN=/opt/php83/sbin/php-fpm\n$php_fpm_BIN --daemonize\n",
            )
            .file(
                "/etc/init.d/web",
                "#!/bin/sh\nDAEMON=/usr/bin/node\n[ -r /etc/default/web ] && . /etc/default/web\n",
            )
            .file("/etc/default/web", "DAEMON=/srv/node/bin/node\n")
            .file("/etc/init.d/quiet", "#!/bin/sh\nDAEMON=/usr/sbin/x\n")
            .file("/etc/default/quiet", "DAEMON=/srv/ignored\n")
            .file("/etc/init.d/rc", "#!/sbin/openrc-run\ncommand=/usr/bin/y\n")
            .file("/etc/conf.d/rc", "command=/opt/node/bin/node\n")
            .file(
                "/etc/init/worker.conf",
                "start on runlevel [2345]\nexec /opt/php/bin/php /srv/w.php >> /var/log/w 2>&1\n",
            )
            .file("/etc/init/README", "exec /opt/x/bin/node\n")
            .file("/etc/init.d/sub/inner", "DAEMON=/opt/x/bin/php\n"),
    );
    let got: Vec<(&str, &str, &str)> = svc
        .iter()
        .map(|r| (r.id.as_str(), r.name.as_str(), r.image_path.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                "/etc/init.d/php83-fpm",
                "php83-fpm",
                "/opt/php83/sbin/php-fpm"
            ),
            ("/etc/init.d/quiet", "quiet", "/usr/sbin/x"),
            ("/etc/init.d/rc", "rc", "/usr/bin/y"),
            ("/etc/init.d/rc", "rc", "/opt/node/bin/node"),
            ("/etc/init.d/web", "web", "/usr/bin/node"),
            ("/etc/init.d/web", "web", "/srv/node/bin/node"),
            ("/etc/init/worker.conf", "worker.conf", "/opt/php/bin/php"),
        ]
    );
    assert!(svc
        .iter()
        .all(|r| r.state == "unknown" && r.start_type == "unknown"));
}

// ─────────────────────────────────── 홈 — `/home` 바로 아래의 폴더만 (#172)

const DESKTOP: &str = "[Desktop Entry]\nType=Application\nName=lab\nExec=/usr/bin/true\n";

/// 홈을 쓰는 수집 셋(persistence · service · autorun)을 같은 가짜로 돈다 — 셋이 같은 홈 찾기를 부른다.
fn three(
    fs: impl Fn() -> Fs,
    max_files: usize,
) -> (
    remedy_artifacts::Harvest<remedy_artifacts::PersistenceRecord>,
    remedy_artifacts::Harvest<remedy_artifacts::ServiceRecord>,
    remedy_artifacts::Harvest<remedy_artifacts::AutorunRecord>,
) {
    let mut s = linux_scope();
    s.max_files = max_files;
    (
        Collector::new(fs()).collect_persistence(&s).expect("수집"),
        Collector::new(fs())
            .collect_linux_services(&s)
            .expect("수집"),
        Collector::new(fs())
            .collect_linux_autoruns(&s)
            .expect("수집"),
    )
}

/// **`/home` 의 파일 뒤에 있는 홈도 읽는다.** 쿼터를 켠 서버는 `/home` 바로 아래에 `aquota.group` ·
/// `aquota.user` 를 두고, 이름 차례가 `alice` < `aquota.*` < `bob` 이다. 홈 목록을 `/home` 걷기(상한 1)로 뽑던
/// 동안에는 첫 파일에서 걷기가 끝나 `bob` 의 유닛 · 자동실행이 말없이 빠졌다 — 잘림도 서지 않았다.
///
/// 파일 이름은 `b` 로 둔다 — 같은 자리(`alice` < `b` < `bob`)이고, `/home/` 뒤의 이름을 실사용자로 읽는 누출
/// 검사가 시험의 가짜 이름으로 안다.
#[test]
fn homes_after_a_quota_file_in_home_are_still_read() {
    let fs = || {
        Fs::new()
            .file("/home/alice/.config/systemd/user/a.timer", TIMER)
            .file("/home/b", "")
            .file("/home/bob/.config/systemd/user/b.timer", TIMER)
            .file("/home/bob/.config/systemd/user/b.service", UNIT)
            .file("/home/bob/.config/autostart/b.desktop", DESKTOP)
    };
    let (p, v, a) = three(fs, 10_000);
    let timers: Vec<(&str, Option<&str>)> = p
        .records
        .iter()
        .map(|r| (r.id.as_str(), r.principal.as_deref()))
        .collect();
    assert_eq!(
        timers,
        vec![
            ("/home/alice/.config/systemd/user/a.timer", Some("alice")),
            ("/home/bob/.config/systemd/user/b.timer", Some("bob")),
        ]
    );
    assert!(
        v.records
            .iter()
            .any(|r| r.id == "/home/bob/.config/systemd/user/b.service"),
        "{:?}",
        v.records
    );
    assert!(
        a.records
            .iter()
            .any(|r| r.id == "/home/bob/.config/autostart/b.desktop"),
        "{:?}",
        a.records
    );
    for got in [
        (p.truncated, p.denied_dirs),
        (v.truncated, v.denied_dirs),
        (a.truncated, a.denied_dirs),
    ] {
        assert_eq!(got, (false, 0));
    }
}

/// **홈 안의 폴더는 홈이 아니다.** 첫 홈의 이름 차례 맨 앞이 폴더(`~/.aaa` · 흔히 `~/.aws`)이면 그 폴더가
/// `.aaa` 라는 사용자의 홈으로 담겨, 그 아래의 유닛이 그 이름을 주체로 수집됐다.
#[test]
fn a_dot_folder_inside_the_first_home_is_not_a_home() {
    let fs = || {
        Fs::new()
            .file("/home/alice/.aaa/.config/systemd/user/decoy.timer", TIMER)
            .file("/home/alice/.bash_logout", "")
            .file("/home/alice/.config/systemd/user/a.timer", TIMER)
    };
    let (p, _, _) = three(fs, 10_000);
    let ids: Vec<&str> = p.records.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["/home/alice/.config/systemd/user/a.timer"]);
}

/// 열지 못한 `/home` 은 거부로 센다 — 못 본 홈을 없는 홈으로 보지 않는다(지금도 그렇다 · 회귀 지킴).
#[test]
fn a_home_root_we_could_not_open_is_counted_as_denied() {
    let (p, v, a) = three(|| Fs::new().denied_dir("/home"), 10_000);
    assert_eq!([p.denied_dirs, v.denied_dirs, a.denied_dirs], [1, 1, 1]);
}

/// **있는지조차 물을 수 없는 `/home` 도 거부다.** `exists` 로 물으면 잠김이 '없음' 과 같은 거짓이 되어, 홈의
/// 유닛 · 자동실행을 하나도 보지 못한 수집이 아무 말 없이 끝났다.
#[test]
fn a_locked_home_root_is_counted_as_denied() {
    let (p, v, a) = three(|| Fs::new().locked("/home"), 10_000);
    let home = vec!["/home".to_string()];
    assert_eq!((p.denied_dirs, &p.denied_paths), (1, &home));
    assert_eq!((v.denied_dirs, &v.denied_paths), (1, &home));
    assert_eq!((a.denied_dirs, &a.denied_paths), (1, &home));
}

/// **홈 안의 자리를 물을 수조차 없으면 거부로 센다.** 홈 찾기는 `/home` 목록만 읽고 홈 안을 열지 않으므로(코어
/// 1.27.0), root 가 0700 홈을 지나지 못하는 마운트(NFS root_squash 등)에서는 홈 안의 유닛 · 자동실행 폴더가 잠김으로
/// 답한다. 그것을 '없음' 으로 읽으면 그 홈을 하나도 보지 못한 수집이 아무 말 없이 0건으로 끝난다 — 1.26.0 은 홈
/// 걷기가 그 홈을 거부로 셌다. 다른 홈은 그대로 읽는다.
#[test]
fn a_locked_folder_inside_a_home_is_counted_as_denied() {
    let fs = || {
        Fs::new()
            .file("/home/alice/.config/systemd/user/a.timer", TIMER)
            .file("/home/bob/.profile", "")
            .locked("/home/bob/.config/systemd/user")
            .locked("/home/bob/.config/autostart")
    };
    let (p, v, a) = three(fs, 10_000);
    let units = vec!["/home/bob/.config/systemd/user".to_string()];
    let autostart = vec!["/home/bob/.config/autostart".to_string()];
    assert_eq!((p.denied_dirs, &p.denied_paths), (1, &units));
    assert_eq!((v.denied_dirs, &v.denied_paths), (1, &units));
    assert_eq!((a.denied_dirs, &a.denied_paths), (1, &autostart));
    let ids: Vec<&str> = p.records.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["/home/alice/.config/systemd/user/a.timer"]);
}

/// **앞 성분이 파일이라 있을 수 없는 자리는 거부가 아니다.** 홈의 `~/.config/systemd` 가 폴더가 아니라 파일이면
/// `~/.config/systemd/user` 는 없는 자리다 — 실제 파일 시스템에서는 ENOTDIR 이고, `look` 은 그것을 '없음' 으로
/// 답한다(`remedy-platform` 의 `local::look` 시험이 잰다). 잘못 만든 점파일 하나를 거부로 세면 그 기계의 유닛 ·
/// 자동실행 룰이 모두 불완전(6)이 된다. 다른 홈은 그대로 읽는다.
#[test]
fn a_file_in_place_of_a_folder_inside_a_home_is_not_counted_as_denied() {
    let fs = || {
        Fs::new()
            .file("/home/alice/.config/systemd/user/a.timer", TIMER)
            .file("/home/bob/.config/systemd", "")
    };
    let (p, v, a) = three(fs, 10_000);
    assert_eq!([p.denied_dirs, v.denied_dirs, a.denied_dirs], [0, 0, 0]);
    let ids: Vec<&str> = p.records.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["/home/alice/.config/systemd/user/a.timer"]);
}

/// **홈이 `max_files` 보다 많으면 잘림이다.** 이름 차례로 앞의 홈만 읽고, 다 읽지 못했다고 말한다.
#[test]
fn more_homes_than_max_files_is_truncated() {
    let fs = || {
        Fs::new()
            .file("/home/alice/.config/systemd/user/a.timer", TIMER)
            .file("/home/bob/.config/systemd/user/b.timer", TIMER)
            .file("/home/test/.config/systemd/user/c.timer", TIMER)
    };
    let (p, v, a) = three(fs, 2);
    let ids: Vec<&str> = p.records.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "/home/alice/.config/systemd/user/a.timer",
            "/home/bob/.config/systemd/user/b.timer",
        ]
    );
    assert_eq!([p.truncated, v.truncated, a.truncated], [true, true, true]);
}
