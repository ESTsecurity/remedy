//! 검사가 **어디까지 왔는가** — 걷기의 진행 계수기.
//!
//! # 왜 필요한가
//!
//! 수집 단계는 시작부터 끝까지 침묵이었다. Windows 실기기의 회차 로그에 배너와
//! `검사 완료` 사이 45초가 비어 있었고, 그동안 멈춘 것과 일하는 것을 구별할 방법이
//! 없었다 (2026-09-07 Phase 1 관측). 수집기의 트레이트에 콜백을 꿰는 대신 **걷는
//! 자리가 세고, 보고 싶은 쪽이 읽는다** — 전역 원자 계수기 하나로 충분하다.
//!
//! # 무엇을 세는가
//!
//! - 연 폴더 수 · 본 항목 수 (`local::walk` 가 센다)
//! - **지금 열고 있는 폴더** — 멈췄다면 어디서 멈췄는지가 이것이다
//!
//! 세는 쪽은 잠금 없이 원자 증가만 한다(폴더 이름은 폴더마다 한 번 뮤텍스). 읽는
//! 쪽은 CLI 의 심장박동 스레드와 패닉 훅이다.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

static DIRS: AtomicUsize = AtomicUsize::new(0);
static ENTRIES: AtomicUsize = AtomicUsize::new(0);
/// 걷기 뒤에 하나씩 처리(읽기·해시·서명 확인)한 항목 수. 걷기는 몇 초지만
/// 이 처리는 항목 수에 비례해 분이 걸릴 수 있다 — 실기기 9,106개에 60초.
static PROCESSED: AtomicUsize = AtomicUsize::new(0);
static CURRENT: Mutex<String> = Mutex::new(String::new());
/// 지금 단계의 id — `file`·`persistence`·`process`·`extra`·`evaluate`·`plan` 같은
/// 카탈로그 이름. 화면 문구는 CLI 가 고른다.
static STAGE: Mutex<&'static str> = Mutex::new("");
/// 지금 돌고 있는 외부 도구와 시작 시각, 그리고 **알리는 시점**.
/// 치료 중 심장박동이 `sc.exe stop · 65초` 로 보인다 — 죽이지 않고 알리기로
/// 했으므로 (결정 2026-09-07).
///
/// **상한을 함께 든다.** 그러지 않으면 심장박동은 도구가 몇 초 돌았는지만
/// 말할 수 있고, 그 숫자가 **정상인지 넘긴 것인지는 말하지 못한다** — 60 이
/// 선이라는 것을 화면 밖에서 아는 사람만 읽을 수 있는 줄이 된다.
static TOOL: Mutex<Option<(String, std::time::Instant, Duration)>> = Mutex::new(None);

// ── 루트 단위 진행 (2026-09-08) ──────────────────────────────
//
// **"얼마나 남았나" 에 답하려면 분모가 필요하고, 그 분모는 루트 안에서만
// 확정된다.** `collect_files` 는 루트마다 걷고 나서 그 루트의 항목을 처리한다
// — 루트 하나를 다 처리한 뒤 다음 루트를 걸으면 전체 항목 수가 다시 늘어난다.
// 전역 `ENTRIES` 를 분모로 쓰면 비율이 뒤로 가는 화면이 나온다.
//
// 그래서 루트에 들어갈 때 그때까지의 값을 기준선으로 잡고, 그 루트의 걷기가
// 끝난 시점에 **그 루트의 파일 수**를 분모로 못박는다.
/// 지금 몇 번째 루트인가(1부터). 0 이면 루트 단위 진행이 아니다.
static ROOT_IDX: AtomicUsize = AtomicUsize::new(0);
/// 걸을 루트가 모두 몇 개인가. **존재하는 것만 센다** — 없는 루트를 세면
/// `루트 2/3` 에서 3 에 영영 닿지 못한다.
static ROOT_TOTAL: AtomicUsize = AtomicUsize::new(0);
static ROOT_BASE_ENTRIES: AtomicUsize = AtomicUsize::new(0);
static ROOT_BASE_DIRS: AtomicUsize = AtomicUsize::new(0);
static ROOT_BASE_PROCESSED: AtomicUsize = AtomicUsize::new(0);
/// 이 루트의 분모. **걷기가 끝나야 정해진다** — 0 이면 아직 걷는 중이다.
static ROOT_FILES: AtomicUsize = AtomicUsize::new(0);

// 검사 시간이 어디로 가는가 — 파일 단계의 네 일을 나노초로 누적한다.
// 실기기에서 검사 85초 중 60초가 걷기 뒤 항목 처리였는데, 읽기·해시·서명 중
// 무엇인지는 이것이 있어야 말할 수 있다 (2026-09-07).
static WALK_NS: AtomicU64 = AtomicU64::new(0);
static READ_NS: AtomicU64 = AtomicU64::new(0);
static HASH_NS: AtomicU64 = AtomicU64::new(0);
static SIGN_NS: AtomicU64 = AtomicU64::new(0);
static READ_BYTES: AtomicU64 = AtomicU64::new(0);
static HASHED_FILES: AtomicUsize = AtomicUsize::new(0);
static SIGN_CHECKED: AtomicUsize = AtomicUsize::new(0);
static SKIPPED_BIG: AtomicUsize = AtomicUsize::new(0);

/// 폴더 하나를 열었다.
pub fn enter_dir(path: &str) {
    DIRS.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut c) = CURRENT.lock() {
        c.clear();
        c.push_str(path);
    }
}

/// 단계가 바뀌었다. 걷기가 끝난 뒤에도 무엇을 하고 있는지 말할 수 있게 —
/// 실기기에서 걷기 5초 뒤 60초가 침묵으로 남았다 (2026-09-07).
pub fn set_stage(id: &'static str) {
    if let Ok(mut st) = STAGE.lock() {
        *st = id;
    }
}

/// 외부 도구가 돌기 시작했다. `warn_after` 는 **알리는 시점**이다
/// (`crate::tool::WARN_SHORT` · `WARN_LONG`) — 넘겨도 끊지 않고 말만 한다.
pub fn tool_started(label: &str, warn_after: Duration) {
    if let Ok(mut t) = TOOL.lock() {
        *t = Some((label.to_string(), std::time::Instant::now(), warn_after));
    }
}

/// 외부 도구가 끝났다.
pub fn tool_finished() {
    if let Ok(mut t) = TOOL.lock() {
        *t = None;
    }
}

/// 항목 하나를 봤다.
pub fn tick_entry() {
    ENTRIES.fetch_add(1, Ordering::Relaxed);
}

/// 항목 하나를 처리하기 시작했다 — 지금 자리가 이 경로다.
pub fn note_item(path: &str) {
    PROCESSED.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut c) = CURRENT.lock() {
        c.clear();
        c.push_str(path);
    }
}

fn add_ns(cell: &AtomicU64, d: Duration) {
    cell.fetch_add(d.as_nanos().min(u64::MAX as u128) as u64, Ordering::Relaxed);
}

/// 걷기에 쓴 시간.
pub fn add_walk(d: Duration) {
    add_ns(&WALK_NS, d);
}

/// 루트 하나에 들어간다. `idx` 는 1부터, `total` 은 **존재하는** 루트 수.
pub fn begin_root(idx: usize, total: usize) {
    ROOT_IDX.store(idx, Ordering::Relaxed);
    ROOT_TOTAL.store(total, Ordering::Relaxed);
    ROOT_BASE_ENTRIES.store(ENTRIES.load(Ordering::Relaxed), Ordering::Relaxed);
    ROOT_BASE_DIRS.store(DIRS.load(Ordering::Relaxed), Ordering::Relaxed);
    ROOT_BASE_PROCESSED.store(PROCESSED.load(Ordering::Relaxed), Ordering::Relaxed);
    // 걷기 전에는 분모를 모른다. 0 이 그 사실을 말한다.
    ROOT_FILES.store(0, Ordering::Relaxed);
}

/// 이 루트의 걷기가 끝났다 — 분모가 정해진다.
///
/// 걷기가 본 항목에서 폴더를 뺀 것이 처리 대상이다(`collect_files` 가
/// `is_dir` 을 건너뛴다).
pub fn root_walked() {
    let e = ENTRIES.load(Ordering::Relaxed) - ROOT_BASE_ENTRIES.load(Ordering::Relaxed);
    let d = DIRS.load(Ordering::Relaxed) - ROOT_BASE_DIRS.load(Ordering::Relaxed);
    ROOT_FILES.store(e.saturating_sub(d), Ordering::Relaxed);
}

/// 루트를 다 돌았다 — 파일 단계를 떠난다. 다른 단계에 루트 진행을 보이면
/// 그 단계가 파일 단계인 것처럼 읽힌다.
pub fn end_roots() {
    ROOT_IDX.store(0, Ordering::Relaxed);
    ROOT_FILES.store(0, Ordering::Relaxed);
}

/// 파일 하나를 읽는 데 쓴 시간과 읽은 바이트.
pub fn add_read(d: Duration, bytes: u64) {
    add_ns(&READ_NS, d);
    READ_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// 파일 하나를 해시하는 데 쓴 시간.
pub fn add_hash(d: Duration) {
    add_ns(&HASH_NS, d);
    HASHED_FILES.fetch_add(1, Ordering::Relaxed);
}

/// 서명 확인 하나에 쓴 시간.
pub fn add_sign(d: Duration) {
    add_ns(&SIGN_NS, d);
    SIGN_CHECKED.fetch_add(1, Ordering::Relaxed);
}

/// 상한보다 커서 해시를 건너뛴 파일 하나.
pub fn skip_big() {
    SKIPPED_BIG.fetch_add(1, Ordering::Relaxed);
}

/// 파일 단계의 시간 내역.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timing {
    pub walk: Duration,
    pub read: Duration,
    pub hash: Duration,
    pub sign: Duration,
    pub read_bytes: u64,
    pub hashed_files: usize,
    pub sign_checked: usize,
    pub skipped_big: usize,
}

pub fn timing() -> Timing {
    Timing {
        walk: Duration::from_nanos(WALK_NS.load(Ordering::Relaxed)),
        read: Duration::from_nanos(READ_NS.load(Ordering::Relaxed)),
        hash: Duration::from_nanos(HASH_NS.load(Ordering::Relaxed)),
        sign: Duration::from_nanos(SIGN_NS.load(Ordering::Relaxed)),
        read_bytes: READ_BYTES.load(Ordering::Relaxed),
        hashed_files: HASHED_FILES.load(Ordering::Relaxed),
        sign_checked: SIGN_CHECKED.load(Ordering::Relaxed),
        skipped_big: SKIPPED_BIG.load(Ordering::Relaxed),
    }
}

/// 지금까지의 진행.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub dirs: usize,
    pub entries: usize,
    /// 걷기 뒤 하나씩 처리한 항목 수.
    pub processed: usize,
    /// 마지막으로 연 폴더. 아직 아무 곳도 열지 않았으면 빈 문자열.
    pub current: String,
    /// 지금 단계의 id. 아직 아무 단계도 아니면 빈 문자열.
    pub stage: &'static str,
    /// 지금 돌고 있는 외부 도구. 없으면 빈 문자열.
    pub tool: String,
    /// 그 도구가 돈 시간(초).
    pub tool_secs: u64,
    /// **알리는 시점을 넘겼는가.** [`crate::tool::Outcome::slow`] 의 살아 있는
    /// 짝이다 — 저쪽은 끝난 뒤의 사실이고 이쪽은 도는 중의 사실이다.
    pub tool_over: bool,
    /// 그 도구의 알리는 시점(초). 도구가 없으면 0.
    pub tool_warn_secs: u64,
    /// 몇 번째 루트인가(1부터). **0 이면 루트 진행을 보이지 않는다.**
    pub root_idx: usize,
    /// 걸을 루트가 모두 몇 개인가.
    pub root_total: usize,
    /// 이 루트에서 처리할 파일 수. **0 이면 아직 걷는 중이라 분모를 모른다.**
    pub root_files: usize,
    /// 이 루트에서 지금까지 처리한 수.
    pub root_processed: usize,
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        dirs: DIRS.load(Ordering::Relaxed),
        entries: ENTRIES.load(Ordering::Relaxed),
        processed: PROCESSED.load(Ordering::Relaxed),
        current: CURRENT.lock().map(|c| c.clone()).unwrap_or_default(),
        stage: STAGE.lock().map(|st| *st).unwrap_or(""),
        tool: TOOL
            .lock()
            .ok()
            .and_then(|t| t.as_ref().map(|(l, _, _)| l.clone()))
            .unwrap_or_default(),
        tool_secs: TOOL
            .lock()
            .ok()
            .and_then(|t| t.as_ref().map(|(_, at, _)| at.elapsed().as_secs()))
            .unwrap_or(0),
        tool_over: TOOL
            .lock()
            .ok()
            .and_then(|t| t.as_ref().map(|(_, at, w)| at.elapsed() > *w))
            .unwrap_or(false),
        tool_warn_secs: TOOL
            .lock()
            .ok()
            .and_then(|t| t.as_ref().map(|(_, _, w)| w.as_secs()))
            .unwrap_or(0),
        root_idx: ROOT_IDX.load(Ordering::Relaxed),
        root_total: ROOT_TOTAL.load(Ordering::Relaxed),
        root_files: ROOT_FILES.load(Ordering::Relaxed),
        root_processed: PROCESSED
            .load(Ordering::Relaxed)
            .saturating_sub(ROOT_BASE_PROCESSED.load(Ordering::Relaxed)),
    }
}

/// 시험이 쓴다 — 한 프로세스에서 여러 번 걷을 때 앞의 것을 지운다.
pub fn reset() {
    DIRS.store(0, Ordering::Relaxed);
    ENTRIES.store(0, Ordering::Relaxed);
    PROCESSED.store(0, Ordering::Relaxed);
    for c in [&WALK_NS, &READ_NS, &HASH_NS, &SIGN_NS, &READ_BYTES] {
        c.store(0, Ordering::Relaxed);
    }
    for c in [
        &HASHED_FILES,
        &SIGN_CHECKED,
        &SKIPPED_BIG,
        &ROOT_IDX,
        &ROOT_TOTAL,
        &ROOT_BASE_ENTRIES,
        &ROOT_BASE_DIRS,
        &ROOT_BASE_PROCESSED,
        &ROOT_FILES,
    ] {
        c.store(0, Ordering::Relaxed);
    }
    if let Ok(mut c) = CURRENT.lock() {
        c.clear();
    }
    if let Ok(mut st) = STAGE.lock() {
        *st = "";
    }
    if let Ok(mut t) = TOOL.lock() {
        *t = None;
    }
}

/// 긴 경로를 화면 폭에 맞게 앞을 잘라 보인다: `…\Local\Programs\x`.
pub fn shorten(path: &str, max_chars: usize) -> String {
    let n = path.chars().count();
    if n <= max_chars {
        return path.to_string();
    }
    let tail: String = path
        .chars()
        .skip(n.saturating_sub(max_chars.saturating_sub(1)))
        .collect();
    format!("…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // 전역 계수기를 만지는 시험은 `tests/progress_global.rs` 에 있다 —
    // 같은 프로세스에서 `local::walk` 을 쓰는 시험과 섞이면 관측이 오염된다.
    #[test]
    fn shorten_keeps_the_tail() {
        assert_eq!(shorten("short", 10), "short");
        let s = shorten("C:\\Users\\x\\AppData\\Local\\Programs\\evil", 16);
        assert_eq!(s.chars().count(), 16, "{s}");
        assert!(s.starts_with('…') && s.ends_with("Programs\\evil"), "{s}");
    }
}
