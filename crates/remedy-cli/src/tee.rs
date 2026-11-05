//! 화면에 나가는 모든 줄을 회차 로그에도 복사한다. 패닉 훅도 여기 있다.
//!
//! # 왜 여기인가
//!
//! CLI 의 출력은 `println!`/`eprintln!` 254곳이었다. 그 전부를 한 자리로 모으는
//! 대신, 같은 이름의 매크로 `outln!`·`errln!`·`out!` 로 바꿔 **찍는 자리는
//! 그대로 두고 복사만 덧붙인다.** 로그가 열려 있지 않으면(조회 명령) 화면에만
//! 나간다 — 화면은 전과 한 글자도 다르지 않다.
//!
//! # 패닉
//!
//! 배포 빌드는 `panic = "abort"` 다. 훅이 없으면 화면에 아무것도 없이 사라지고
//! 종료 코드는 0–7 계약 밖의 값이 된다. 훅은 (1) 상태 폴더 `logs/crash-<시각>.txt`
//! 에 무엇이 어디서 죽었는지 적고, (2) 회차 로그가 열려 있으면 거기에도 적고,
//! (3) 화면에 두 언어로 알린 뒤, (4) **종료 코드 7** 로 나간다 (결정 2026-09-07).
//! `process::exit` 는 소멸자를 돌리지 않지만 저널은 줄마다 `sync_data` 했고
//! 잠금 파일은 OS 가 푼다.

use remedy_core::runlog::RunLog;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static RUNLOG: Mutex<Option<RunLog>> = Mutex::new(None);
/// 마지막으로 정해진 상태 폴더. 크래시 기록이 갈 곳이다.
static STATE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// stdout 한 줄. 로그가 열려 있으면 `|` 로 복사한다.
macro_rules! outln {
    () => {
        $crate::tee::emit(false, String::new())
    };
    ($($arg:tt)*) => {
        $crate::tee::emit(false, format!($($arg)*))
    };
}

/// stderr 한 줄. 로그에는 `!` 로 복사한다.
macro_rules! errln {
    () => {
        $crate::tee::emit(true, String::new())
    };
    ($($arg:tt)*) => {
        $crate::tee::emit(true, format!($($arg)*))
    };
}

/// 줄바꿈 없는 stdout — 렌더러가 만든 여러 줄 텍스트와 프롬프트가 쓴다.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::tee::emit_raw(format!($($arg)*))
    };
}

fn with_log<R>(f: impl FnOnce(&mut RunLog) -> R) -> Option<R> {
    let mut guard = RUNLOG.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_mut().map(f)
}

/// 한 줄을 찍고 로그에 복사한다. **색은 화면으로 나가는 쪽에만** 얹는다
/// ([`crate::term::paint`]) — 로그와 파이프에는 지금 글자 그대로 간다.
pub fn emit(stderr: bool, text: String) {
    let shown = crate::term::paint(&text, stderr);
    let screen = shown.as_deref().unwrap_or(&text);
    if stderr {
        eprintln!("{screen}");
    } else {
        println!("{screen}");
    }
    let mark = if stderr { "!" } else { "|" };
    let _ = with_log(|l| l.lines(mark, &format!("{text}\n")));
}

pub fn emit_raw(text: String) {
    match crate::term::paint_block(&text) {
        Some(p) => print!("{p}"),
        None => print!("{text}"),
    }
    let _ = with_log(|l| l.lines("|", &text));
}

/// 기계를 만지는 명령이 시작할 때 부른다. 실패해도 명령은 계속한다 — 로그를
/// 못 여는 것이 치료를 막을 이유는 아니다. 그 사실은 화면에 한 줄 남긴다.
pub fn open(state_dir: &Path, name: &str) {
    let _ = STATE_DIR.set(state_dir.to_path_buf());
    #[cfg(debug_assertions)]
    if std::env::var("REMEDY_PANIC_TEST").is_ok_and(|v| v == "1") {
        panic!("REMEDY_PANIC_TEST: 개발 빌드 전용 패닉 시험");
    }
    let header = format!(
        "remedy {} pid {} · {}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        std::env::args().skip(1).collect::<Vec<_>>().join(" ")
    );
    match RunLog::open(state_dir, name, &header) {
        Ok(l) => {
            let mut guard = RUNLOG.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(l);
        }
        Err(e) => eprintln!(
            "{}: {} ({e})",
            remedy_sdk::i18n::t("알림", "Notice"),
            remedy_sdk::i18n::t(
                "회차 로그를 열지 못해 화면에만 남깁니다",
                "could not open the run log; output goes to the screen only"
            )
        ),
    }
}

/// 작업 하나가 끝났다 — 로그를 닫는다. 메뉴로 돌아오는 세션에서 부른다: 닫지 않으면
/// 다음 메뉴 화면이 앞 작업의 회차 로그에 섞여 들어간다. 다음 작업은 [`open`] 이 새로 연다.
pub fn close() {
    let mut guard = RUNLOG.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// `run_id` 를 알게 됐을 때. 이름을 바꾸지 못하면 임시 이름으로 계속 쓴다.
pub fn rename(run_id: &str) {
    let _ = with_log(|l| l.rename_to(run_id));
}

/// 지금 로그 파일 경로. 화면의 마무리 표가 적는다.
pub fn path() -> Option<PathBuf> {
    with_log(|l| l.path().to_path_buf())
}

/// 크래시 기록이 갈 폴더 — 정해진 상태 폴더, 없으면 기본 상태 폴더.
fn crash_dir() -> PathBuf {
    STATE_DIR
        .get()
        .cloned()
        .unwrap_or_else(remedy_core::restore::default_state_dir)
}

/// 패닉 훅. `main` 이 언어를 정한 직후 한 번 단다.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let at = remedy_core::pipeline::now_rfc3339();
        let what = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "(no message)".into());
        let where_ = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "?".into());
        let args: Vec<String> = std::env::args().collect();
        let body = format!(
            "remedy {} · internal error (panic)\nat    : {at}\nwhere : {where_}\nwhat  : {what}\nargs  : {}\nos    : {}\nrun log: {}\n",
            env!("CARGO_PKG_VERSION"),
            args.join(" "),
            std::env::consts::OS,
            path().map(|p| p.display().to_string()).unwrap_or_else(|| "-".into()),
        );
        // 멈춘 끝에 죽었다면 어디까지 걸었는지가 단서다.
        let prog = remedy_core::platform::progress::snapshot();
        let body = format!(
            "{body}stage : {}\nwalk  : {} dirs · {} entries · {} processed · last {}\n",
            if prog.stage.is_empty() {
                "-"
            } else {
                prog.stage
            },
            prog.dirs,
            prog.entries,
            prog.processed,
            if prog.current.is_empty() {
                "-"
            } else {
                prog.current.as_str()
            }
        );
        // 1) 크래시 파일 — 상태 폴더, 안 되면 임시 폴더.
        let mut written: Option<PathBuf> = None;
        for dir in [crash_dir(), std::env::temp_dir().join("remedy")] {
            let p = remedy_core::runlog::crash_path(&dir, &at);
            if std::fs::create_dir_all(remedy_core::runlog::dir(&dir)).is_ok()
                && std::fs::write(&p, &body).is_ok()
            {
                written = Some(p);
                break;
            }
        }
        // 2) 회차 로그 — 잠금이 걸려 있으면(패닉이 emit 안에서 났으면) 건너뛴다.
        if let Ok(mut guard) = RUNLOG.try_lock() {
            if let Some(l) = guard.as_mut() {
                let _ = l.line("#", &format!("PANIC {where_}: {what}"));
            }
        }
        // 3) 화면.
        let lang = remedy_sdk::i18n::current();
        eprintln!();
        eprintln!(
            "{}: {}",
            lang.t("실패", "Error"),
            lang.t(
                "내부 오류 — 도구 자체가 멈췄습니다. 기계는 이 시점까지의 저널 상태 그대로입니다",
                "internal error: the tool itself crashed. The machine is as the journal recorded up to this point"
            )
        );
        eprintln!("  {where_}: {what}");
        match &written {
            Some(p) => eprintln!("  {}: {}", lang.t("기록", "Record"), p.display()),
            None => eprintln!(
                "  {}",
                lang.t(
                    "기록을 남길 폴더가 없었습니다",
                    "no writable folder for the record"
                )
            ),
        }
        let code = remedy_sdk::artifact::ExitCode::InternalError;
        eprintln!(
            "  ({} {}: {})",
            lang.t("종료 코드", "exit code"),
            code.code(),
            code.meaning_in(lang)
        );
        std::process::exit(i32::from(code.code()));
    }));
}

/// 심장박동이 무엇을 감싸는가.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Beat {
    /// 수집·평가·계획. 끝나면 `# 검사 시간 …` 내역을 남긴다.
    Scan,
    /// 치료. 오래 도는 외부 도구가 있으면 그 이름과 시간을 보인다.
    Apply,
}

/// `f` 가 5초를 넘기면 그 뒤로 5초마다(1분 뒤에는 30초마다) 한 줄을 찍는다.
///
/// - 검사: `검사 중 · <단계> · 폴더 N개 · 항목 M개 · 처리 K/T개 · 루트 k/n · 경과 S초 · <파일>`
///   진행 칸은 [`scan_progress`] 가 만든다 — 분모를 아는 자리에서만 비율이 붙는다.
/// - 치료: `치료 중 · 도구 sc.exe stop 65초 · 경과 S초` — 외부 도구를 죽이지 않기로
///   했으므로(결정 2026-09-07) 오래 도는 도구는 이 줄이 말한다.
///
/// 빠른 회차는 한 줄도 찍지 않으므로 화면이 전과 같다. 줄이 계속 나오는데 숫자와
/// 단계가 바뀌지 않으면 그 자리에서 멈춘 것이고, 줄 자체가 멎으면 프로세스가 멈춘
/// 것이다 — 오래 걸림과 멈춤을 구별할 수 있다 (Phase 2·3, 2026-09-07).
///
/// `REMEDY_HEARTBEAT_SECS` 로 주기를 바꿀 수 있다(시험은 1초). 개발 빌드의
/// `REMEDY_SLOW_COLLECT_MS` 는 `f` 앞에 잠을 넣어 심장박동을 일으킨다.
pub fn with_heartbeat<T>(verbose: bool, beat: Beat, f: impl FnOnce() -> T) -> T {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let period = std::env::var("REMEDY_HEARTBEAT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(5);
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let started = Instant::now();
    let ticker = std::thread::spawn(move || {
        let mut next = Duration::from_secs(period);
        while !flag.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50));
            if started.elapsed() < next {
                continue;
            }
            let secs = started.elapsed().as_secs();
            let p = remedy_core::platform::progress::snapshot();
            let lang = remedy_sdk::i18n::current();
            let dot = remedy_sdk::i18n::deco().dot();
            let line = match beat {
                Beat::Scan => {
                    let stage = stage_label(p.stage, lang);
                    let progress = scan_progress(&p, lang);
                    let mut line = match lang {
                        remedy_sdk::i18n::Lang::Ko => format!(
                            "검사 중{dot}{stage}{dot}폴더 {}개{dot}항목 {}개{dot}{progress}{dot}경과 {secs}초",
                            p.dirs, p.entries
                        ),
                        remedy_sdk::i18n::Lang::En => format!(
                            "Scanning{dot}{stage}{dot}{} folders{dot}{} entries{dot}{progress}{dot}{secs}s elapsed",
                            p.dirs, p.entries
                        ),
                    };
                    // 폴더·파일 이름은 파일 단계에만 뜻이 있다. 다른 단계에서 보이면
                    // '그 폴더에서 멈췄다' 로 읽힌다 — 실기기에서 그렇게 보였다.
                    if p.stage == "file" && !p.current.is_empty() {
                        line.push_str(dot);
                        line.push_str(&remedy_core::platform::progress::shorten(&p.current, 60));
                    }
                    line
                }
                Beat::Apply => {
                    let tool = if p.tool.is_empty() {
                        String::new()
                    } else {
                        // **넘겼으면 넘겼다고 말한다.** 숫자만 보이면 60 이 선이라는
                        // 것을 화면 밖에서 아는 사람만 읽을 수 있다. 그리고 **끊지
                        // 않는다는 것**을 같은 줄에서 말해야 한다 — 그러지 않으면
                        // 사람이 먼저 끊는다(결정 2026-09-07 이 막으려던 바로 그 일).
                        let over = if p.tool_over {
                            lang.pick(
                                format!(" (상한 {}초 넘음 — 끊지 않습니다)", p.tool_warn_secs),
                                format!(" (past the {}s mark — not killing)", p.tool_warn_secs),
                            )
                        } else {
                            String::new()
                        };
                        format!(
                            "{dot}{} {} {}{over}",
                            lang.t("도구", "tool"),
                            p.tool,
                            lang.pick(format!("{}초", p.tool_secs), format!("{}s", p.tool_secs))
                        )
                    };
                    match lang {
                        remedy_sdk::i18n::Lang::Ko => format!("치료 중{tool}{dot}경과 {secs}초"),
                        remedy_sdk::i18n::Lang::En => format!("Treating{tool}{dot}{secs}s elapsed"),
                    }
                }
            };
            emit(false, line);
            // 1분이 지나면 뜸하게 — 긴 회차의 로그가 심장박동으로만 차지 않게.
            let step = if secs >= 60 { period * 6 } else { period };
            next = started.elapsed() + Duration::from_secs(step);
        }
    });
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var("REMEDY_SLOW_COLLECT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        std::thread::sleep(Duration::from_millis(ms));
    }
    let out = f();
    stop.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    if beat == Beat::Scan {
        // 검사 시간이 어디로 갔는가 — 회차 로그에는 늘, 화면에는 --verbose 일 때.
        let line = timing_line(started.elapsed(), remedy_core::platform::progress::timing());
        if verbose {
            emit(false, line);
        } else {
            let _ = with_log(|l| l.line("#", &line));
        }
    }
    out
}

/// 심장박동의 진행 칸. **분모를 아는 자리에서만 비율을 낸다.**
///
/// 사용자의 물음은 하나다 — *"얼마나 남았나."* 답하려면 분모가 있어야 하는데,
/// 그 분모는 **루트 안에서만** 확정된다: 수집은 루트마다 걷고 나서 그 루트의
/// 항목을 처리하므로, 전역 항목 수를 분모로 쓰면 다음 루트를 걸을 때 분모가
/// 커져 **비율이 뒤로 간다** (`progress.rs` 의 루트 계수 주석).
///
/// 그래서 셋으로 갈린다.
///
/// | 언제 | 무엇을 보이나 |
/// |---|---|
/// | 루트 안이고 걷기가 끝났다 | `처리 3790/7947개 · 루트 1/3` — 답할 수 있다 |
/// | 루트 안인데 아직 걷는 중이다 | `처리 0개 · 루트 1/3` — 분모를 모른다고 말하지 않는 편이 낫다 |
/// | 파일 단계가 아니다 | `처리 172개` — 예전 그대로 |
///
/// **모를 때 지어내지 않는다.** 걷는 중에 잠정 분모를 보이면 그 수가 곧 커지고,
/// 사용자는 진행이 뒤로 갔다고 읽는다.
fn scan_progress(
    p: &remedy_core::platform::progress::Snapshot,
    lang: remedy_sdk::i18n::Lang,
) -> String {
    let dot = remedy_sdk::i18n::deco().dot();
    if p.root_idx == 0 {
        return lang.pick(
            format!("처리 {}개", p.processed),
            format!("{} processed", p.processed),
        );
    }
    let of_root = lang.pick(
        format!("루트 {}/{}", p.root_idx, p.root_total),
        format!("root {}/{}", p.root_idx, p.root_total),
    );
    let done = if p.root_files > 0 {
        lang.pick(
            format!("처리 {}/{}개", p.root_processed, p.root_files),
            format!("{}/{} processed", p.root_processed, p.root_files),
        )
    } else {
        lang.pick(
            format!("처리 {}개", p.root_processed),
            format!("{} processed", p.root_processed),
        )
    };
    format!("{done}{dot}{of_root}")
}

/// 진행 단계 id 를 사람의 말로. 모르는 id 는 그대로 보인다 — 숨기는 것보다 낫다.
fn stage_label(id: &'static str, lang: remedy_sdk::i18n::Lang) -> &'static str {
    let (ko, en) = match id {
        "" => ("시작", "starting"),
        "file" => ("파일 검사", "files"),
        "persistence" => ("자동실행·서비스·작업", "persistence"),
        "registry_value" | "registry_key" => ("레지스트리", "registry"),
        "autorun" => ("자동실행", "autoruns"),
        "service" => ("서비스", "services"),
        "av_exclusion" => ("백신 예외", "AV exclusions"),
        "proxy_config" => ("프록시 설정", "proxy settings"),
        "firewall_rule" => ("방화벽 규칙", "firewall rules"),
        "boot_config" => ("부팅 설정", "boot settings"),
        "hosts_entry" => ("hosts", "hosts"),
        "text_config" | "structured_config" => ("설정 파일", "config files"),
        "shortcut" => ("바로가기", "shortcuts"),
        "browser_extension" => ("브라우저 확장", "browser extensions"),
        "cert_store" => ("인증서 저장소", "certificate stores"),
        "process" => ("프로세스", "processes"),
        "indicator" => ("지표", "indicators"),
        "extra" => ("내용 수집", "reading contents"),
        "evaluate" => ("평가", "evaluating"),
        "plan" => ("계획", "planning"),
        other => (other, other),
    };
    lang.t(ko, en)
}

/// `1.2 GB` 처럼.
fn human_bytes(n: u64) -> String {
    const K: f64 = 1024.0;
    let f = n as f64;
    if f >= K * K * K {
        format!("{:.1} GB", f / (K * K * K))
    } else if f >= K * K {
        format!("{:.1} MB", f / (K * K))
    } else if f >= K {
        format!("{:.0} KB", f / K)
    } else {
        format!("{n} B")
    }
}

fn secs(d: std::time::Duration) -> String {
    format!("{:.1}", d.as_secs_f64())
}

/// 검사 시간의 내역 한 줄. `그 밖` 은 파일 단계의 네 일에 들지 않은 시간 —
/// 레지스트리·프로세스·내용 수집·평가·계획이다.
fn timing_line(total: std::time::Duration, t: remedy_core::platform::progress::Timing) -> String {
    let lang = remedy_sdk::i18n::current();
    let dot = remedy_sdk::i18n::deco().dot();
    let accounted = t.walk + t.read + t.hash + t.sign;
    let rest = total.saturating_sub(accounted);
    match lang {
        remedy_sdk::i18n::Lang::Ko => format!(
            "검사 시간 {}초{dot}걷기 {}초{dot}읽기 {}초 ({}{dot}{}개){dot}해시 {}초{dot}서명 {}초 ({}개){dot}큰 파일 건너뜀 {}개{dot}그 밖 {}초",
            secs(total), secs(t.walk), secs(t.read), human_bytes(t.read_bytes), t.hashed_files,
            secs(t.hash), secs(t.sign), t.sign_checked, t.skipped_big, secs(rest)
        ),
        remedy_sdk::i18n::Lang::En => format!(
            "scan time {}s{dot}walk {}s{dot}read {}s ({}{dot}{} files){dot}hash {}s{dot}signatures {}s ({} files){dot}{} too big to hash{dot}other {}s",
            secs(total), secs(t.walk), secs(t.read), human_bytes(t.read_bytes), t.hashed_files,
            secs(t.hash), secs(t.sign), t.sign_checked, t.skipped_big, secs(rest)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::scan_progress;
    use remedy_core::platform::progress::Snapshot;
    use remedy_sdk::i18n::Lang;

    /// 파일 단계의 루트 안. `files` 가 0 이면 아직 걷는 중이다.
    fn in_root(idx: usize, total: usize, files: usize, done: usize) -> Snapshot {
        Snapshot {
            root_idx: idx,
            root_total: total,
            root_files: files,
            root_processed: done,
            processed: done,
            ..Default::default()
        }
    }

    #[test]
    fn a_known_denominator_becomes_a_ratio() {
        let s = in_root(1, 3, 7947, 3790);
        assert_eq!(scan_progress(&s, Lang::Ko), "처리 3790/7947개 · 루트 1/3");
        assert_eq!(
            scan_progress(&s, Lang::En),
            "3790/7947 processed · root 1/3"
        );
    }

    #[test]
    fn while_walking_no_ratio_is_invented() {
        // 분모를 모를 때 잠정값을 보이면 그 수가 곧 커지고, 사용자는 진행이
        // 뒤로 갔다고 읽는다.
        let s = in_root(1, 3, 0, 0);
        assert_eq!(scan_progress(&s, Lang::Ko), "처리 0개 · 루트 1/3");
        assert_eq!(scan_progress(&s, Lang::En), "0 processed · root 1/3");
    }

    #[test]
    fn outside_the_file_stage_the_line_is_what_it_was() {
        // 자동실행·레지스트리 단계에는 루트가 없다. 예전 모양 그대로다.
        let s = Snapshot {
            processed: 172,
            ..Default::default()
        };
        assert_eq!(scan_progress(&s, Lang::Ko), "처리 172개");
        assert_eq!(scan_progress(&s, Lang::En), "172 processed");
    }

    /// 한글 음절이 있는가. **`is_ascii()` 로는 못 잰다** — 칸 사이의 `·` 는
    /// 언어가 아니라 장식이라 영어 화면에도 나온다(장식은 터미널이 정한다).
    fn has_hangul(s: &str) -> bool {
        s.chars().any(|c| ('\u{AC00}'..='\u{D7A3}').contains(&c))
    }

    #[test]
    fn neither_language_leaks_into_the_other() {
        for s in [
            in_root(2, 2, 10, 5),
            in_root(1, 1, 0, 0),
            Snapshot::default(),
        ] {
            let en = scan_progress(&s, Lang::En);
            assert!(!has_hangul(&en), "영어 화면에 한글이 섞였다: {en}");
            let ko = scan_progress(&s, Lang::Ko);
            assert!(has_hangul(&ko), "한국어 화면에 한글이 없다: {ko}");
        }
    }
}
