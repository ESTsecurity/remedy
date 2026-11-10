//! 한도 — 실행 시한과 읽는 양 · 요청 수의 상한.
//!
//! 사내 runtime-scanner 의 `internal/control` 을 옮겼다(정책 `2026-10-26.1`). 이미지 파일 점검과 컨테이너
//! 점검이 한 실행 동안 함께 쓰는 예산이고, 실행 중에 바꾸는 옵션이 없다.
//!
//! - 실행 전체 10분.
//! - 이미지: 파일에서 읽는 양 8 GiB · 압축을 푼 양 8 GiB · 레이어 256개.
//! - 컨테이너: 엔진 API 요청 128회 · 받는 양 256 MiB · 초당 10 MiB(한 번에 32 KiB 까지).
//! - 둘 다: 파일 항목 100,000개.
//!
//! **이미지 파일을 읽을 때는 속도를 늦추지 않는다.** 사용자가 준 파일이라 늦춰서 지킬 서비스가 없다 — 양의
//! 상한은 그대로다. 살아 있는 컨테이너 엔진에서 받을 때만 늦춘다.
//!
//! **멈추는 길은 둘이다.** Ctrl+C 가 켜는 깃발([`Cancel`])과 실행 시한. 어느 쪽이든 다음 읽기 · 요청을 시작하지
//! 않고, 속도를 맞추느라 기다리던 읽기도 0.1초 안에 돌아온다. 그때까지 본 것은 [`Budget::partial_targets`]
//! 로 보고한다.
//!
//! URL 점검의 상한(HTTP 요청 수와 간격)은 [`crate::url`] 이 따로 가진다.

use super::model::{Target, TargetKind};
use remedy_sdk::i18n::Lang;
use schemars::JsonSchema;
use serde::Serialize;
use std::fmt;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// 실행 전체의 시한.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(600);
/// 컨테이너 엔진 API 요청 수.
pub const MAX_CONTAINER_REQUESTS: u32 = 128;
/// 컨테이너 엔진에서 받는 바이트 — JSON 응답과 파일 아카이브를 합쳐 센다.
pub const CONTAINER_LIMIT: u64 = 256 << 20;
/// 이미지 파일에서 읽는 바이트의 상한이자 압축을 푼 바이트의 상한 — 둘을 따로 센다.
pub const IMAGE_LIMIT: u64 = 8 << 30;
/// [`Budget::read`] 로 한 번에 받을 수 있는 가장 큰 크기.
pub const FILE_LIMIT: u64 = 256 << 20;
/// 늦춰 읽는 속도 — 초당 바이트.
pub const READ_RATE: u64 = 10 << 20;
/// 늦춰 읽을 때 한 번에 읽는 가장 큰 크기.
pub const READ_CHUNK: usize = 32 << 10;
/// 파일 항목(아카이브의 항목 · 목록의 줄) 수.
pub const MAX_ENTRIES: u32 = 100_000;
/// 이미지 레이어 수.
pub const MAX_LAYERS: u32 = 256;

/// 기다림을 이만큼씩 끊어 취소와 시한을 본다.
const SLICE: Duration = Duration::from_millis(100);
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Ctrl+C · 실행 시한 — 켜지면 다음 읽기 · 요청을 시작하지 않는다. 사본은 같은 깃발을 가리킨다.
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

/// 시각과 기다림. 시험은 이것을 바꿔 끼워 실제로 기다리지 않는다.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep(&self, d: Duration);
}

/// 실제 시계.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// 무엇을 읽는가 — 종류마다 따로 세고 상한도 따로다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadKind {
    /// 컨테이너 엔진이 준 바이트.
    Container,
    /// 이미지 파일에서 읽은 바이트 — 압축을 풀기 전.
    ImageInput,
    /// 압축을 푼 뒤의 바이트.
    ImageExpanded,
}

impl ReadKind {
    fn limit(self) -> u64 {
        match self {
            ReadKind::Container => CONTAINER_LIMIT,
            ReadKind::ImageInput | ReadKind::ImageExpanded => IMAGE_LIMIT,
        }
    }

    fn is_image(self) -> bool {
        self != ReadKind::Container
    }

    fn label(self, lang: Lang) -> &'static str {
        match self {
            ReadKind::Container => lang.t("컨테이너에서 읽는 양", "data read from containers"),
            ReadKind::ImageInput => lang.t("이미지 파일에서 읽는 양", "data read from image files"),
            ReadKind::ImageExpanded => lang.t("압축을 푼 이미지의 양", "expanded image data"),
        }
    }
}

/// 걸린 상한.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// 컨테이너 점검이 아닌 실행이 컨테이너 엔진에 요청하려 했다.
    EngineNotAllowed,
    /// 컨테이너 엔진 API 요청 수.
    Requests,
    /// 파일 항목 수.
    Entries,
    /// 이미지 레이어 수.
    Layers,
    /// 이 종류로 읽은 양.
    Bytes(ReadKind),
    /// 읽기 전에 안 크기가 이 종류의 남은 양보다 크다.
    Oversize(ReadKind),
    /// 부르는 쪽이 정한 파일 하나의 크기([`Budget::read`]). 실행 전체의 상한이 아니라 `usage.stops` 에는
    /// 적히지 않는다.
    FileSize,
}

impl Limit {
    /// 상한의 이름 — `usage.stops` 에 이 글이 들어간다.
    pub fn message(self, lang: Lang) -> String {
        match self {
            Limit::EngineNotAllowed => lang
                .t(
                    "이 점검 방식에서는 컨테이너 API 를 허용하지 않습니다",
                    "this kind of check does not allow the container API",
                )
                .to_string(),
            Limit::Requests => lang.pick(
                format!("컨테이너 API 요청 {MAX_CONTAINER_REQUESTS}회"),
                format!("{MAX_CONTAINER_REQUESTS} container API requests"),
            ),
            Limit::Entries => lang.pick(
                format!("파일 항목 {MAX_ENTRIES}개"),
                format!("{MAX_ENTRIES} file entries"),
            ),
            Limit::Layers => lang.pick(
                format!("이미지 레이어 {MAX_LAYERS}개"),
                format!("{MAX_LAYERS} image layers"),
            ),
            Limit::Bytes(kind) => {
                let (label, size) = (kind.label(lang), size_text(kind.limit()));
                lang.pick(format!("{label} {size}"), format!("{size} of {label}"))
            }
            Limit::Oversize(kind) => {
                let (label, size) = (kind.label(lang), size_text(kind.limit()));
                lang.pick(
                    format!("파일과 아카이브 부가 정보가 남은 양보다 큽니다({label} {size})"),
                    format!(
                        "the file and its archive overhead exceed what is left of the {size} of {label}"
                    ),
                )
            }
            Limit::FileSize => lang
                .t("파일별 크기 제한", "the per-file size limit")
                .to_string(),
        }
    }
}

/// `8 GiB` · `256 MiB`.
fn size_text(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    if bytes.is_multiple_of(GIB) {
        format!("{} GiB", bytes / GIB)
    } else {
        format!("{} MiB", bytes >> 20)
    }
}

/// 계속하지 못하는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    /// 깃발이 켜졌다 — 사람이 멈췄다(Ctrl+C).
    Cancelled,
    /// 실행 전체 10분.
    RunDeadline,
    /// 상한 하나에 걸렸다. 다른 상한 안의 일은 계속할 수 있다.
    Limit(Limit),
}

impl Halt {
    pub fn message(self, lang: Lang) -> String {
        match self {
            Halt::Cancelled => lang.t("취소했습니다", "cancelled").to_string(),
            Halt::RunDeadline => {
                let minutes = RUN_TIMEOUT.as_secs() / 60;
                lang.pick(
                    format!("실행 전체 {minutes}분 제한을 넘었습니다"),
                    format!("the {minutes}-minute limit for the run passed"),
                )
            }
            Halt::Limit(limit) => {
                let which = limit.message(lang);
                lang.pick(
                    format!("점검 제한에 도달했습니다: {which}"),
                    format!("check limit reached: {which}"),
                )
            }
        }
    }

    /// 읽기 오류에 실려 온 까닭을 꺼낸다. [`Metered`] 와 [`Budget::read`] 는 한도 · 중단을 `io::Error` 로
    /// 올리므로, 그 위의 코드(아카이브 해석 따위)는 이것으로 입출력 오류와 가른다.
    pub fn from_io(error: &io::Error) -> Option<Halt> {
        let carried = error.get_ref()?.downcast_ref::<Carried>()?;
        Some(carried.halt)
    }
}

/// `io::Error` 에 싣는 꼴 — 읽기 오류로 올라가도 까닭과 실행 언어를 잃지 않는다.
#[derive(Debug)]
struct Carried {
    halt: Halt,
    lang: Lang,
}

impl fmt::Display for Carried {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.halt.message(self.lang))
    }
}

impl std::error::Error for Carried {}

/// 이 실행이 쓴 양 — 결과 파일의 `usage`.
#[derive(Debug, Clone, Default, Serialize, JsonSchema)]
pub struct Usage {
    /// 맡은 컨테이너 엔진 API 요청 수.
    pub container_requests: u32,
    /// 컨테이너 엔진에서 받은 바이트.
    pub container_bytes: u64,
    /// 이미지 파일에서 읽은 바이트(압축을 풀기 전).
    pub image_input_bytes: u64,
    /// 압축을 푼 뒤의 바이트.
    pub image_expanded_bytes: u64,
    /// 센 파일 항목.
    pub entries: u32,
    /// 센 이미지 레이어.
    pub layers: u32,
    /// 걸린 상한과, 중단했으면 그 까닭.
    pub stops: Vec<String>,
}

impl Usage {
    fn bytes(&mut self, kind: ReadKind) -> &mut u64 {
        match kind {
            ReadKind::Container => &mut self.container_bytes,
            ReadKind::ImageInput => &mut self.image_input_bytes,
            ReadKind::ImageExpanded => &mut self.image_expanded_bytes,
        }
    }
}

/// 한 실행의 예산. 점검 스레드와 화면 스레드가 함께 쥔다.
pub struct Budget {
    kind: TargetKind,
    lang: Lang,
    clock: Arc<dyn Clock>,
    cancel: Cancel,
    deadline: Instant,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    usage: Usage,
    /// 처음 본 중단의 까닭.
    halted: Option<Halt>,
    /// 늦춰 읽는 다음 읽기가 시작해도 되는 시각.
    next_read: Option<Instant>,
    partial: Vec<Target>,
}

impl Budget {
    /// 지금부터 10분. `kind` 는 어느 점검인가 — 컨테이너 엔진에 요청할 수 있는지와 읽기를 늦출지를 정한다.
    pub fn new(kind: TargetKind, cancel: Cancel, lang: Lang) -> Budget {
        Budget::with_clock(kind, cancel, lang, Arc::new(SystemClock))
    }

    /// 시계를 바꿔 끼운 예산.
    pub fn with_clock(
        kind: TargetKind,
        cancel: Cancel,
        lang: Lang,
        clock: Arc<dyn Clock>,
    ) -> Budget {
        Budget {
            kind,
            lang,
            deadline: clock.now() + RUN_TIMEOUT,
            clock,
            cancel,
            state: Mutex::new(State::default()),
        }
    }

    /// 계속해도 되는가 — 취소됐거나 시한이 지났으면 그 까닭을 준다.
    pub fn check(&self) -> Result<(), Halt> {
        self.running(&mut self.lock())
    }

    /// 멈췄으면 그 까닭. **처음 본 까닭이 남는다** — 취소한 뒤 시한이 지나도 취소이고, 시한이 지난 뒤 깃발이
    /// 켜져도 시한이다. 시한을 처음 본 순간 깃발도 켠다: 깃발만 보는 자리(막힌 소켓 읽기)도 함께 멈춘다.
    pub fn halted(&self) -> Option<Halt> {
        self.running(&mut self.lock()).err()
    }

    /// 컨테이너 엔진 API 요청 하나를 맡기 전에 묻는다. 거절한 요청은 세지 않는다.
    pub fn before_request(&self) -> Result<(), Halt> {
        let mut s = self.lock();
        self.running(&mut s)?;
        if self.kind != TargetKind::Container {
            return Err(self.stop(&mut s, Limit::EngineNotAllowed));
        }
        if s.usage.container_requests >= MAX_CONTAINER_REQUESTS {
            return Err(self.stop(&mut s, Limit::Requests));
        }
        s.usage.container_requests += 1;
        Ok(())
    }

    /// 파일 항목 하나를 센다.
    pub fn count_entry(&self) -> Result<(), Halt> {
        let mut s = self.lock();
        self.running(&mut s)?;
        if s.usage.entries >= MAX_ENTRIES {
            return Err(self.stop(&mut s, Limit::Entries));
        }
        s.usage.entries += 1;
        Ok(())
    }

    /// 이미지 레이어 하나를 센다.
    pub fn count_layer(&self) -> Result<(), Halt> {
        let mut s = self.lock();
        self.running(&mut s)?;
        if s.usage.layers >= MAX_LAYERS {
            return Err(self.stop(&mut s, Limit::Layers));
        }
        s.usage.layers += 1;
        Ok(())
    }

    /// 읽기 전에 아는 크기가 남은 양에 드는가. **세지는 않는다** — 실제로 읽은 바이트는 [`Budget::wrap_reader`]
    /// 가 아카이브의 머리 · 채움까지 센다.
    pub fn check_read_size(&self, kind: ReadKind, size: u64) -> Result<(), Halt> {
        let mut s = self.lock();
        self.running(&mut s)?;
        if size > kind.limit().saturating_sub(*s.usage.bytes(kind)) {
            return Err(self.stop(&mut s, Limit::Oversize(kind)));
        }
        Ok(())
    }

    /// 읽는 만큼 세는 리더로 감싼다. 상한에 닿으면 그 바이트까지만 주고 다음 읽기가 오류다. 겹쳐 감싸도 된다 —
    /// 파일을 `ImageInput` 으로, 그것을 푼 쪽을 `ImageExpanded` 로 감싸면 둘 다 센다.
    pub fn wrap_reader<R: Read>(&self, inner: R, kind: ReadKind) -> Metered<'_, R> {
        Metered {
            budget: self,
            inner,
            kind,
        }
    }

    /// 끝까지 읽어 준다. `limit` 를 넘는 입력과 [`FILE_LIMIT`] 를 넘는 `limit` 는 [`Limit::FileSize`] 다. 읽은
    /// 바이트는 `kind` 로 센다(넘는지 보려고 한 바이트를 더 읽는다).
    pub fn read<R: Read>(&self, inner: R, limit: u64, kind: ReadKind) -> io::Result<Vec<u8>> {
        if limit > FILE_LIMIT {
            return Err(self.carry(Halt::Limit(Limit::FileSize)));
        }
        let mut data = Vec::new();
        self.wrap_reader(inner, kind)
            .take(limit + 1)
            .read_to_end(&mut data)?;
        if data.len() as u64 > limit {
            return Err(self.carry(Halt::Limit(Limit::FileSize)));
        }
        Ok(data)
    }

    /// 지금까지 쓴 양. 멈춘 실행이면 `stops` 끝에 그 까닭이 붙는다.
    pub fn usage(&self) -> Usage {
        let mut s = self.lock();
        let halted = self.running(&mut s).err();
        let mut usage = s.usage.clone();
        if let Some(halt) = halted {
            let why = halt.message(self.lang);
            usage.stops.push(
                self.lang
                    .pick(format!("점검 중단: {why}"), format!("check stopped: {why}")),
            );
        }
        usage
    }

    /// 끝나지 않은 대상의 지금 모양을 남긴다 — 중단되면 이것으로 보고한다. 같은 대상(`id` · `kind`)은 새
    /// 모양으로 바뀐다. 사본을 두므로 부르는 쪽이 대상을 더 고쳐도 남긴 것은 그대로다.
    pub fn record_target(&self, target: &Target) {
        let mut s = self.lock();
        let slot = s
            .partial
            .iter_mut()
            .find(|t| t.id == target.id && t.kind == target.kind);
        match slot {
            Some(slot) => *slot = target.clone(),
            None => s.partial.push(target.clone()),
        }
    }

    /// 남겨 둔 대상들 — `reason` 을 *보지 못한 것* 으로 달고 판정을 다시 낸다. 확인된 취약은 남고, 양호였던
    /// 것은 *확인 필요* 가 된다. 다 본 대상에 적혀 있던 까닭 · 할 일은 새 판정과 맞지 않아 다시 적는다.
    pub fn partial_targets(&self, reason: &str) -> Vec<Target> {
        let mut targets = self.lock().partial.clone();
        for t in &mut targets {
            t.add_gap(reason);
            t.reason.clear();
            t.action.clear();
            t.finalize(self.lang);
        }
        targets
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn running(&self, s: &mut State) -> Result<(), Halt> {
        if s.halted.is_none() {
            if self.cancel.is_set() {
                s.halted = Some(Halt::Cancelled);
            } else if self.clock.now() >= self.deadline {
                s.halted = Some(Halt::RunDeadline);
                self.cancel.set();
            }
        }
        s.halted.map_or(Ok(()), Err)
    }

    /// 걸린 상한을 `stops` 에 적는다. 같은 상한은 한 번만 적힌다.
    fn stop(&self, s: &mut State, limit: Limit) -> Halt {
        let why = limit.message(self.lang);
        if !s.usage.stops.contains(&why) {
            s.usage.stops.push(why);
        }
        Halt::Limit(limit)
    }

    fn carry(&self, halt: Halt) -> io::Error {
        io::Error::other(Carried {
            halt,
            lang: self.lang,
        })
    }

    /// 읽기 한 번의 몫을 미리 잡는다 — 여럿이 함께 읽어도 상한을 넘겨 읽지 않는다. 잡은 크기와, 늦춰 읽는
    /// 경우 읽기를 시작해도 되는 시각을 준다. 속도는 잡은 크기로 맞춘다(덜 읽혀도 시각을 당기지 않는다).
    fn reserve(&self, kind: ReadKind, len: usize) -> Result<(usize, Option<Instant>), Halt> {
        let mut s = self.lock();
        self.running(&mut s)?;
        let left = kind.limit().saturating_sub(*s.usage.bytes(kind));
        if left == 0 {
            return Err(self.stop(&mut s, Limit::Bytes(kind)));
        }
        let paced = !(self.kind == TargetKind::Image && kind.is_image());
        let mut want = len.min(usize::try_from(left).unwrap_or(usize::MAX));
        if paced {
            want = want.min(READ_CHUNK);
        }
        *s.usage.bytes(kind) += want as u64;
        if !paced {
            return Ok((want, None));
        }
        let now = self.clock.now();
        let start = s.next_read.map_or(now, |next| next.max(now));
        let cost = Duration::from_nanos(want as u64 * NANOS_PER_SEC / READ_RATE);
        s.next_read = Some(start + cost);
        Ok((want, Some(start)))
    }

    /// 잡아 둔 몫 가운데 읽지 못한 만큼을 돌려놓는다.
    fn refund(&self, kind: ReadKind, unread: usize) {
        if unread > 0 {
            let mut s = self.lock();
            let used = s.usage.bytes(kind);
            *used = used.saturating_sub(unread as u64);
        }
    }

    /// `until` 까지 기다린다. 자물쇠를 쥐지 않고, [`SLICE`] 씩 끊어 취소와 시한을 본다.
    fn wait_until(&self, until: Instant) -> Result<(), Halt> {
        loop {
            self.check()?;
            let now = self.clock.now();
            if now >= until {
                return Ok(());
            }
            let end = until.min(self.deadline);
            self.clock
                .sleep(end.saturating_duration_since(now).min(SLICE));
        }
    }
}

/// [`Budget::wrap_reader`] 가 주는 리더.
pub struct Metered<'a, R> {
    budget: &'a Budget,
    inner: R,
    kind: ReadKind,
}

impl<R: Read> Read for Metered<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let budget = self.budget;
        let (want, start) = budget
            .reserve(self.kind, buf.len())
            .map_err(|halt| budget.carry(halt))?;
        if let Some(start) = start {
            if let Err(halt) = budget.wait_until(start) {
                budget.refund(self.kind, want);
                return Err(budget.carry(halt));
            }
        }
        // 자물쇠를 쥐지 않고 읽는다 — 안쪽이 같은 예산으로 감싼 리더일 수 있다.
        let got = self.inner.read(&mut buf[..want]);
        let read = got.as_ref().map_or(0, |n| (*n).min(want));
        budget.refund(self.kind, want - read);
        got.map(|_| read)
    }
}

/// 손으로 돌리는 시계(시험용) — 기다림은 시각만 옮기고 실제로 자지 않는다.
#[cfg(test)]
pub(crate) struct ManualClock {
    base: Instant,
    elapsed: Mutex<Duration>,
    /// 이만큼 지나면 이 깃발을 켠다 — 기다리는 중에 누른 Ctrl+C.
    cancel_at: Mutex<Option<(Duration, Cancel)>>,
}

#[cfg(test)]
impl ManualClock {
    pub(crate) fn new() -> Arc<ManualClock> {
        Arc::new(ManualClock {
            base: Instant::now(),
            elapsed: Mutex::new(Duration::ZERO),
            cancel_at: Mutex::new(None),
        })
    }

    /// 시작한 뒤 흐른(흘렀다고 친) 시간.
    pub(crate) fn elapsed(&self) -> Duration {
        *self.elapsed.lock().unwrap()
    }

    pub(crate) fn advance(&self, d: Duration) {
        let now = {
            let mut elapsed = self.elapsed.lock().unwrap();
            *elapsed += d;
            *elapsed
        };
        if let Some((at, cancel)) = self.cancel_at.lock().unwrap().as_ref() {
            if now >= *at {
                cancel.set();
            }
        }
    }

    pub(crate) fn cancel_after(&self, at: Duration, cancel: Cancel) {
        *self.cancel_at.lock().unwrap() = Some((at, cancel));
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.base + self.elapsed()
    }
    fn sleep(&self, d: Duration) {
        self.advance(d);
    }
}

#[cfg(test)]
mod tests;
