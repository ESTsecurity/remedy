//! 요청 상한 — 스캐너의 정책(`2026-10-26.1`)을 그대로 옮겼고 실행 중에 바꾸는 옵션이 없다.
//!
//! 직렬 · 요청 사이 2초 · 실행 전체 100회 · URL 50개 · URL 하나에 2회(HEAD, 필요하면 GET 한 번) ·
//! URL 하나에 10초(간격을 기다리는 시간 · 이름 풀이를 포함한다) · 실행 전체 10분 · 응답 헤더 32 KiB.

use super::report::Target;
use remedy_sdk::i18n::Lang;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) const MAX_URLS: usize = 50;
pub(crate) const MAX_REQUESTS: u32 = 100;
pub(crate) const INTERVAL: Duration = Duration::from_secs(2);
pub(crate) const URL_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const RUN_TIMEOUT: Duration = Duration::from_secs(600);
pub(crate) const MAX_HEADER_BYTES: usize = 32 << 10;
/// 막힌 읽기 · 기다림을 이만큼씩 끊어 취소를 본다.
pub(crate) const SLICE: Duration = Duration::from_millis(100);

/// Ctrl+C · 실행 시한 — 켜지면 다음 요청을 보내지 않고, 막힌 읽기도 [`SLICE`] 안에 돌아온다.
#[derive(Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// 요청을 보내지 못한 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Halt {
    /// 실행 전체 100회.
    Limit,
    /// 이 URL 의 10초가 간격을 기다리는 동안 끝났다.
    UrlDeadline,
    /// 실행 전체 10분.
    RunDeadline,
    Cancelled,
}

impl Halt {
    pub(crate) fn message(self, lang: Lang) -> &'static str {
        match self {
            Halt::Limit => lang.t("HTTP 요청 100회", "100 HTTP requests"),
            Halt::UrlDeadline => lang.t(
                "URL 하나에 10초 제한을 넘었습니다",
                "the 10-second limit for one URL passed",
            ),
            Halt::RunDeadline => lang.t(
                "실행 전체 10분 제한을 넘었습니다",
                "the 10-minute limit for the run passed",
            ),
            Halt::Cancelled => lang.t("취소했습니다", "cancelled"),
        }
    }

    /// 이 서버로 더 요청하지 않을 까닭인가 — 시간이 다 된 것만. 상한 · 취소는 서버 탓이 아니다.
    pub(crate) fn stops_server(self) -> bool {
        matches!(self, Halt::UrlDeadline | Halt::RunDeadline)
    }
}

/// 요청 하나를 맡기 전에 묻는 자리 — 간격을 기다리고 수를 센다. 시험은 기다림을 바꿔 끼운다.
pub(crate) trait Gate: Sync {
    fn before_request(&self, url_deadline: Instant, cancel: &Cancel) -> Result<(), Halt>;
    /// 끝나지 않은 대상의 지금 모양을 남긴다 — 중단되면 이것으로 보고한다.
    fn record(&self, target: &Target);
}

/// 실제 상한.
pub(crate) struct Budget {
    interval: Duration,
    max_requests: u32,
    run_deadline: Instant,
    lang: Lang,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    requests: u32,
    next: Option<Instant>,
    stops: Vec<String>,
    partial: Vec<Target>,
}

impl Budget {
    pub(crate) fn new(started: Instant, lang: Lang) -> Budget {
        Budget::with(INTERVAL, MAX_REQUESTS, started + RUN_TIMEOUT, lang)
    }

    pub(crate) fn with(
        interval: Duration,
        max_requests: u32,
        run_deadline: Instant,
        lang: Lang,
    ) -> Budget {
        Budget {
            interval,
            max_requests,
            run_deadline,
            lang,
            state: Mutex::new(State::default()),
        }
    }

    pub(crate) fn run_deadline(&self) -> Instant {
        self.run_deadline
    }

    /// 맡은 요청 수 — 보내지 못하고 끝난 요청(TLS 거절 · 연결 실패)도 센다(스캐너와 같다).
    pub(crate) fn requests(&self) -> u32 {
        self.lock().requests
    }

    pub(crate) fn stops(&self) -> Vec<String> {
        self.lock().stops.clone()
    }

    pub(crate) fn partial(&self) -> Vec<Target> {
        self.lock().partial.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Gate for Budget {
    fn before_request(&self, url_deadline: Instant, cancel: &Cancel) -> Result<(), Halt> {
        let next = {
            let mut s = self.lock();
            if cancel.is_set() {
                return Err(Halt::Cancelled);
            }
            if Instant::now() >= self.run_deadline {
                return Err(Halt::RunDeadline);
            }
            if s.requests >= self.max_requests {
                let why = self.lang.pick(
                    format!("HTTP 요청 {}회", self.max_requests),
                    format!("{} HTTP requests", self.max_requests),
                );
                if !s.stops.contains(&why) {
                    s.stops.push(why);
                }
                return Err(Halt::Limit);
            }
            s.next
        };
        // 기다리는 동안 자물쇠를 쥐지 않는다 — 중단된 실행이 부분 결과를 읽을 수 있어야 한다.
        if let Some(next) = next {
            wait_until(next, url_deadline, self.run_deadline, cancel)?;
        }
        let mut s = self.lock();
        s.next = Some(Instant::now() + self.interval);
        s.requests += 1;
        Ok(())
    }

    fn record(&self, target: &Target) {
        let mut s = self.lock();
        match s.partial.iter_mut().find(|t| t.id == target.id) {
            Some(slot) => *slot = target.clone(),
            None => s.partial.push(target.clone()),
        }
    }
}

/// `until` 까지 기다린다. 그 전에 URL 시한 · 실행 시한 · 취소가 오면 그 까닭으로 멈춘다.
pub(crate) fn wait_until(
    until: Instant,
    url_deadline: Instant,
    run_deadline: Instant,
    cancel: &Cancel,
) -> Result<(), Halt> {
    loop {
        if cancel.is_set() {
            return Err(Halt::Cancelled);
        }
        let now = Instant::now();
        if now >= until {
            return Ok(());
        }
        if now >= url_deadline {
            return Err(Halt::UrlDeadline);
        }
        if now >= run_deadline {
            return Err(Halt::RunDeadline);
        }
        let end = until.min(url_deadline).min(run_deadline);
        std::thread::sleep((end - now).min(SLICE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_spaced_and_capped() {
        let b = Budget::with(
            Duration::from_millis(200),
            3,
            Instant::now() + Duration::from_secs(60),
            Lang::Ko,
        );
        let far = Instant::now() + Duration::from_secs(60);
        let c = Cancel::default();
        let start = Instant::now();
        for _ in 0..3 {
            b.before_request(far, &c).unwrap();
        }
        assert!(
            start.elapsed() >= Duration::from_millis(400),
            "간격을 지키지 않았다"
        );
        assert_eq!(b.before_request(far, &c), Err(Halt::Limit));
        assert_eq!(b.requests(), 3);
        assert_eq!(b.stops(), vec!["HTTP 요청 3회".to_string()]);
    }

    #[test]
    fn waiting_counts_against_the_url_deadline() {
        let b = Budget::with(
            Duration::from_secs(5),
            10,
            Instant::now() + Duration::from_secs(60),
            Lang::Ko,
        );
        let c = Cancel::default();
        b.before_request(Instant::now() + Duration::from_secs(60), &c)
            .unwrap();
        let start = Instant::now();
        let short = Instant::now() + Duration::from_millis(150);
        assert_eq!(b.before_request(short, &c), Err(Halt::UrlDeadline));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(b.requests(), 1, "보내지 않은 요청을 셌다");
        c.set();
        assert_eq!(
            b.before_request(Instant::now() + Duration::from_secs(60), &c),
            Err(Halt::Cancelled)
        );
    }
}
