//! 스캐너 `internal/control` 의 시험을 옮겼다. 원래 이름은 각 시험 위에 적었다.
//!
//! 시계를 바꿔 끼워([`super::ManualClock`]) 실제로는 기다리지 않는다 — 속도 맞춤도 시한도 시각을 옮겨 본다.
//! `ReadSized` 의 시험(`sized_test.go`)은 그 함수가 호스트 점검에만 쓰여 옮기지 않았다.

use super::*;
use crate::scan::model::{Evidence, Finding, Product, Status};
use std::sync::mpsc;

const KIB: usize = 1 << 10;
const HOUR: Duration = Duration::from_secs(3600);

fn budget_in(kind: TargetKind, lang: Lang) -> (Budget, Arc<ManualClock>, Cancel) {
    let clock = ManualClock::new();
    let cancel = Cancel::default();
    let budget = Budget::with_clock(kind, cancel.clone(), lang, clock.clone());
    (budget, clock, cancel)
}

fn budget(kind: TargetKind) -> (Budget, Arc<ManualClock>, Cancel) {
    budget_in(kind, Lang::Ko)
}

fn halt_of<T>(result: io::Result<T>) -> Option<Halt> {
    result.err().as_ref().and_then(Halt::from_io)
}

fn finding(product: Product, status: Status, detail: &str) -> Finding {
    Finding {
        product,
        id: format!("{}:시험", product.id()),
        name: "시험".to_string(),
        path: None,
        version: None,
        package: None,
        vendor: None,
        runtime: None,
        cves: Vec::new(),
        status,
        reason: String::new(),
        action: String::new(),
        evidence: vec![Evidence::new("시험", detail)],
    }
}

#[test]
fn the_limits_are_the_scanner_values() {
    assert_eq!(RUN_TIMEOUT, Duration::from_secs(10 * 60));
    assert_eq!(IMAGE_LIMIT, 8 * 1024 * 1024 * 1024);
    assert_eq!(CONTAINER_LIMIT, 256 * 1024 * 1024);
    assert_eq!(FILE_LIMIT, 256 * 1024 * 1024);
    assert_eq!(READ_RATE, 10 * 1024 * 1024);
    assert_eq!(READ_CHUNK, 32 * KIB);
    assert_eq!(MAX_ENTRIES, 100_000);
    assert_eq!(MAX_LAYERS, 256);
    assert_eq!(MAX_CONTAINER_REQUESTS, 128);
    assert_eq!(ReadKind::Container.limit(), CONTAINER_LIMIT);
    assert_eq!(ReadKind::ImageInput.limit(), IMAGE_LIMIT);
    assert_eq!(ReadKind::ImageExpanded.limit(), IMAGE_LIMIT);
}

/// 스캐너 `TestPartialTargetsRetainVulnerableAndCopyEvidence`.
#[test]
fn partial_targets_keep_a_confirmed_vulnerability_and_their_own_copy() {
    let (b, _, _) = budget(TargetKind::Image);
    let mut target = Target::new("one", TargetKind::Image, "시험 이미지", &[]);
    target
        .findings
        .push(finding(Product::Php, Status::Vulnerable, "confirmed"));
    target.metadata.insert("version".into(), "old".into());
    b.record_target(&target);
    // 남긴 뒤에 고친 것은 남긴 것에 닿지 않는다.
    target.findings[0].status = Status::Clear;
    target.findings[0].evidence[0].detail = "changed".to_string();
    target.metadata.insert("version".into(), "new".into());
    let got = b.partial_targets("canceled");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].status, Status::Vulnerable);
    assert!(!got[0].complete);
    assert_eq!(got[0].gaps, vec!["canceled".to_string()]);
    assert_eq!(got[0].findings[0].evidence[0].detail, "confirmed");
    assert_eq!(got[0].metadata["version"], "old");
    // 같은 대상을 다시 남기면 새 모양으로 바뀌고, 종류가 다르면 다른 대상이다.
    b.record_target(&target);
    let other = Target::new("one", TargetKind::Container, "시험 컨테이너", &[]);
    b.record_target(&other);
    let got = b.partial_targets("canceled");
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].metadata["version"], "new");
    assert_eq!(got[0].status, Status::ReviewRequired);
    assert_eq!(got[1].kind, TargetKind::Container);
}

/// 스캐너 `TestPartialTargetProductsAreDeepCopiedAndIncomplete`.
#[test]
fn partial_products_are_copied_and_marked_incomplete() {
    let (b, _, _) = budget(TargetKind::Container);
    let products = [Product::Php, Product::Node];
    let mut target = Target::new("one", TargetKind::Container, "시험", &products);
    target
        .findings
        .push(finding(Product::Node, Status::Vulnerable, "근거"));
    target.add_product_scope(Product::Node, "/usr/bin/node");
    // 다 본 것으로 끝낸 대상이다 — 그때의 까닭 · 할 일은 중단된 보고에 맞지 않는다.
    target.reason = "끝까지 보았습니다.".to_string();
    target.finalize(Lang::Ko);
    assert!(target.products[&Product::Php].complete);
    b.record_target(&target);
    target.products.get_mut(&Product::Node).unwrap().scope[0] = "changed".to_string();
    let partial = b.partial_targets("중단");
    assert_eq!(partial.len(), 1);
    let node = &partial[0].products[&Product::Node];
    assert_eq!(node.scope, vec!["/usr/bin/node".to_string()]);
    assert_eq!(node.status, Status::Vulnerable);
    assert!(!node.complete);
    let php = &partial[0].products[&Product::Php];
    assert!(!php.complete);
    assert_eq!(php.status, Status::ReviewRequired);
    assert_eq!(php.gaps, vec!["중단".to_string()]);
    assert!(!partial[0].complete);
    assert_ne!(partial[0].reason, "끝까지 보았습니다.");
    assert!(!partial[0].reason.is_empty() && !partial[0].action.is_empty());
    // 받은 것을 고쳐도 예산이 쥔 것은 그대로다.
    let mut mine = partial;
    mine[0].products.get_mut(&Product::Node).unwrap().scope[0] = "returned".to_string();
    let again = b.partial_targets("중단");
    assert_eq!(again[0].products[&Product::Node].scope[0], "/usr/bin/node");
}

/// 스캐너 `TestNestedReadersDoNotDeadlockAndCountBoth`.
#[test]
fn nested_readers_do_not_deadlock_and_both_count() {
    let (b, _, _) = budget(TargetKind::Image);
    let b = Arc::new(b);
    let (tx, rx) = mpsc::channel();
    let worker = Arc::clone(&b);
    std::thread::spawn(move || {
        let file = worker.wrap_reader(&b"abc"[..], ReadKind::ImageInput);
        let mut expanded = worker.wrap_reader(file, ReadKind::ImageExpanded);
        let mut data = Vec::new();
        let result = expanded.read_to_end(&mut data).map(|_| data);
        let _ = tx.send(result);
    });
    let data = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("겹친 리더가 서로를 막았다")
        .unwrap();
    assert_eq!(data, b"abc");
    let usage = b.usage();
    assert_eq!(usage.image_input_bytes, 3);
    assert_eq!(usage.image_expanded_bytes, 3);
}

/// 스캐너 `TestReadQuotaNeverOverreads`.
#[test]
fn a_read_never_goes_past_the_quota() {
    let (b, _, _) = budget(TargetKind::Container);
    b.lock().usage.container_bytes = CONTAINER_LIMIT - 3;
    let mut data = Vec::new();
    let result = b
        .wrap_reader(&b"abcdef"[..], ReadKind::Container)
        .read_to_end(&mut data);
    let limit = Limit::Bytes(ReadKind::Container);
    assert_eq!(halt_of(result), Some(Halt::Limit(limit)));
    assert_eq!(data, b"abc");
    let usage = b.usage();
    assert_eq!(usage.container_bytes, CONTAINER_LIMIT);
    assert_eq!(
        usage.stops,
        vec!["컨테이너에서 읽는 양 256 MiB".to_string()]
    );
}

/// 스캐너 `TestRequestLimitsAndMode` — HTTP 요청의 상한은 `url::policy` 가 가진다.
#[test]
fn requests_are_capped_and_only_a_container_check_may_send_them() {
    let (image, _, _) = budget(TargetKind::Image);
    let refused = Halt::Limit(Limit::EngineNotAllowed);
    assert_eq!(image.before_request(), Err(refused));
    assert_eq!(image.usage().container_requests, 0);
    assert_eq!(
        image.usage().stops,
        vec!["이 점검 방식에서는 컨테이너 API 를 허용하지 않습니다".to_string()]
    );

    let (b, _, _) = budget(TargetKind::Container);
    for _ in 0..MAX_CONTAINER_REQUESTS {
        b.before_request().unwrap();
    }
    assert_eq!(b.before_request(), Err(Halt::Limit(Limit::Requests)));
    assert_eq!(b.before_request(), Err(Halt::Limit(Limit::Requests)));
    let usage = b.usage();
    assert_eq!(usage.container_requests, MAX_CONTAINER_REQUESTS);
    assert_eq!(usage.stops, vec!["컨테이너 API 요청 128회".to_string()]);
}

/// 스캐너 `TestReadFileLimit`.
#[test]
fn read_stops_at_the_per_file_limit() {
    let (b, _, _) = budget(TargetKind::Container);
    let kind = ReadKind::Container;
    let over = Some(Halt::Limit(Limit::FileSize));
    assert_eq!(halt_of(b.read(&b"12345"[..], 4, kind)), over);
    // 넘는지 보려고 읽은 한 바이트까지 센다. 파일 하나의 제한은 실행의 상한이 아니다.
    assert_eq!(b.usage().container_bytes, 5);
    assert!(b.usage().stops.is_empty());
    assert_eq!(b.read(&b"1234"[..], 4, kind).unwrap(), b"1234");
    assert_eq!(b.read(&b""[..], 0, kind).unwrap(), b"");
    assert_eq!(b.usage().container_bytes, 9);
    assert_eq!(halt_of(b.read(&b"1"[..], FILE_LIMIT + 1, kind)), over);
    assert_eq!(b.usage().container_bytes, 9, "받지 않을 크기인데 읽었다");
}

/// 스캐너 `TestActualReadPacingAndCount` — 시계를 바꿔 끼워 실제로는 기다리지 않는다.
#[test]
fn container_reads_are_paced_and_counted() {
    let (b, clock, _) = budget(TargetKind::Container);
    let data = vec![1u8; 1 << 20];
    let mut reader = b.wrap_reader(data.as_slice(), ReadKind::Container);
    let mut buf = vec![0u8; 64 * KIB];
    let mut total = 0usize;
    loop {
        let n = reader.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        assert!(n <= READ_CHUNK, "한 번에 32 KiB 를 넘겨 읽었다: {n}");
        total += n;
    }
    assert_eq!(total, data.len());
    assert_eq!(b.usage().container_bytes, total as u64);
    // 첫 조각은 바로 읽고 그 뒤는 초당 10 MiB 에 맞춘다.
    let per_chunk = Duration::from_nanos(READ_CHUNK as u64 * NANOS_PER_SEC / READ_RATE);
    let least = per_chunk * (total / READ_CHUNK - 1) as u32;
    let waited = clock.elapsed();
    assert!(waited >= least, "너무 빨리 읽었다: {waited:?}");
    assert!(waited <= least + per_chunk * 2, "너무 늦췄다: {waited:?}");
}

/// 스캐너 `TestImageReadsSkipThrottleButKeepLimits`.
#[test]
fn image_reads_skip_the_pacing_but_keep_the_limits() {
    let (b, clock, _) = budget(TargetKind::Image);
    b.lock().next_read = Some(clock.now() + HOUR);
    let data = vec![1u8; 2 << 20];
    let mut buf = vec![0u8; data.len()];
    let mut reader = b.wrap_reader(data.as_slice(), ReadKind::ImageExpanded);
    // 늦추지 않으니 32 KiB 로 끊지도 않는다.
    assert_eq!(reader.read(&mut buf).unwrap(), data.len());
    assert_eq!(reader.read(&mut buf).unwrap(), 0);
    assert_eq!(b.usage().image_expanded_bytes, data.len() as u64);
    assert_eq!(clock.elapsed(), Duration::ZERO, "이미지 읽기를 늦췄다");

    b.lock().usage.image_input_bytes = IMAGE_LIMIT - 3;
    let mut got = Vec::new();
    let result = b
        .wrap_reader(&b"abcdef"[..], ReadKind::ImageInput)
        .read_to_end(&mut got);
    let limit = Limit::Bytes(ReadKind::ImageInput);
    assert_eq!(halt_of(result), Some(Halt::Limit(limit)));
    assert_eq!(got, b"abc");
    assert_eq!(b.usage().image_input_bytes, IMAGE_LIMIT);
}

/// 스캐너 `TestImageThrottleExceptionDoesNotApplyToHostMode` — 늦추지 않는 것은 이미지 점검뿐이다. 다른
/// 점검에서는 이미지 종류의 읽기도 차례를 기다리고, 기다리다 멈추면 잡아 둔 몫을 돌려놓는다.
#[test]
fn the_pacing_exception_is_for_image_checks_only() {
    let (b, clock, _) = budget(TargetKind::Container);
    b.lock().next_read = Some(clock.now() + HOUR);
    let mut buf = [0u8; 4];
    let result = b
        .wrap_reader(&b"data"[..], ReadKind::ImageInput)
        .read(&mut buf);
    assert_eq!(halt_of(result), Some(Halt::RunDeadline));
    assert_eq!(b.usage().image_input_bytes, 0, "읽지 않은 바이트를 셌다");
    assert!(clock.elapsed() >= RUN_TIMEOUT);
    assert!(clock.elapsed() < RUN_TIMEOUT + SLICE);
}

#[test]
fn a_paced_wait_notices_cancellation_within_a_slice() {
    let (b, clock, cancel) = budget(TargetKind::Container);
    b.lock().next_read = Some(clock.now() + HOUR);
    let pressed = Duration::from_millis(250);
    clock.cancel_after(pressed, cancel);
    let mut buf = [0u8; 4];
    let result = b
        .wrap_reader(&b"data"[..], ReadKind::Container)
        .read(&mut buf);
    assert_eq!(halt_of(result), Some(Halt::Cancelled));
    assert!(clock.elapsed() >= pressed && clock.elapsed() < pressed + SLICE);
    assert_eq!(b.usage().container_bytes, 0);
    assert_eq!(b.halted(), Some(Halt::Cancelled));
}

/// 스캐너 `TestImageReadsHonorCancellation` 과, 거절한 요청을 세지 않는다는 것
/// (`TestCanceledWaitDoesNotConsumeRequest` 의 컨테이너 쪽).
#[test]
fn nothing_starts_after_cancellation() {
    let (b, _, cancel) = budget(TargetKind::Image);
    cancel.set();
    for kind in [ReadKind::ImageInput, ReadKind::ImageExpanded] {
        let mut buf = [0u8; 4];
        let result = b.wrap_reader(&b"data"[..], kind).read(&mut buf);
        assert_eq!(halt_of(result), Some(Halt::Cancelled), "{kind:?}");
    }
    assert_eq!(b.check(), Err(Halt::Cancelled));
    assert_eq!(b.count_entry(), Err(Halt::Cancelled));
    assert_eq!(b.count_layer(), Err(Halt::Cancelled));
    let sized = b.check_read_size(ReadKind::ImageInput, 1);
    assert_eq!(sized, Err(Halt::Cancelled));
    let usage = b.usage();
    assert_eq!(usage.image_input_bytes + usage.image_expanded_bytes, 0);
    assert_eq!((usage.entries, usage.layers), (0, 0));

    let (b, _, cancel) = budget(TargetKind::Container);
    cancel.set();
    assert_eq!(b.before_request(), Err(Halt::Cancelled));
    assert_eq!(b.usage().container_requests, 0, "보내지 않은 요청을 셌다");
    assert_eq!(
        halt_of(b.read(&b"x"[..], 1, ReadKind::Container)),
        Some(Halt::Cancelled)
    );
}

/// 스캐너 `TestKnownWireSizeCheckedWithoutChargingUnreadBytes`.
#[test]
fn a_known_size_is_checked_without_charging_it() {
    let (b, _, _) = budget(TargetKind::Container);
    let kind = ReadKind::Container;
    b.lock().usage.container_bytes = CONTAINER_LIMIT - 4096;
    assert_eq!(b.check_read_size(kind, 4096), Ok(()));
    let over = Halt::Limit(Limit::Oversize(kind));
    assert_eq!(b.check_read_size(kind, 4097), Err(over));
    assert_eq!(b.check_read_size(kind, u64::MAX), Err(over));
    let usage = b.usage();
    assert_eq!(usage.container_bytes, CONTAINER_LIMIT - 4096);
    assert_eq!(
        usage.stops,
        vec![
            "파일과 아카이브 부가 정보가 남은 양보다 큽니다(컨테이너에서 읽는 양 256 MiB)"
                .to_string()
        ]
    );
}

#[test]
fn entries_and_layers_are_capped_and_each_stop_is_listed_once() {
    let (b, _, _) = budget(TargetKind::Image);
    b.lock().usage.entries = MAX_ENTRIES - 1;
    assert_eq!(b.count_entry(), Ok(()));
    for _ in 0..3 {
        assert_eq!(b.count_entry(), Err(Halt::Limit(Limit::Entries)));
    }
    for _ in 0..MAX_LAYERS {
        b.count_layer().unwrap();
    }
    assert_eq!(b.count_layer(), Err(Halt::Limit(Limit::Layers)));
    let usage = b.usage();
    assert_eq!((usage.entries, usage.layers), (MAX_ENTRIES, MAX_LAYERS));
    assert_eq!(
        usage.stops,
        vec![
            "파일 항목 100000개".to_string(),
            "이미지 레이어 256개".to_string()
        ]
    );
    // 한 상한에 걸려도 다른 상한 안의 일은 계속된다.
    assert_eq!(b.check(), Ok(()));
    assert_eq!(b.halted(), None);

    let (en, _, _) = budget_in(TargetKind::Image, Lang::En);
    en.lock().usage.entries = MAX_ENTRIES;
    assert_eq!(en.count_entry(), Err(Halt::Limit(Limit::Entries)));
    assert_eq!(en.usage().stops, vec!["100000 file entries".to_string()]);
}

#[test]
fn the_first_cause_of_a_halt_is_kept() {
    // 취소한 뒤 시한이 지나도 취소다.
    let (b, clock, cancel) = budget(TargetKind::Image);
    clock.advance(RUN_TIMEOUT - Duration::from_millis(1));
    assert_eq!(b.check(), Ok(()));
    assert!(b.usage().stops.is_empty());
    cancel.set();
    assert_eq!(b.check(), Err(Halt::Cancelled));
    clock.advance(HOUR);
    assert_eq!(b.halted(), Some(Halt::Cancelled));
    assert_eq!(b.usage().stops, vec!["점검 중단: 취소했습니다".to_string()]);

    // 시한이 먼저면 시한이고, 그 순간 깃발도 켜진다.
    let (b, clock, cancel) = budget_in(TargetKind::Container, Lang::En);
    clock.advance(RUN_TIMEOUT);
    assert!(!cancel.is_set());
    assert_eq!(b.halted(), Some(Halt::RunDeadline));
    assert!(cancel.is_set(), "시한이 깃발을 켜지 않았다");
    assert_eq!(b.before_request(), Err(Halt::RunDeadline));
    assert_eq!(
        b.usage().stops,
        vec!["check stopped: the 10-minute limit for the run passed".to_string()]
    );
}

#[test]
fn a_halt_survives_the_trip_through_an_io_error() {
    for (lang, text) in [(Lang::Ko, "취소했습니다"), (Lang::En, "cancelled")] {
        let (b, _, cancel) = budget_in(TargetKind::Image, lang);
        cancel.set();
        let mut buf = [0u8; 1];
        let error = b
            .wrap_reader(&b"x"[..], ReadKind::ImageInput)
            .read(&mut buf)
            .unwrap_err();
        assert_eq!(Halt::from_io(&error), Some(Halt::Cancelled));
        assert_eq!(error.to_string(), text);
    }
    let plain = io::Error::new(io::ErrorKind::UnexpectedEof, "끊겼다");
    assert_eq!(Halt::from_io(&plain), None);
    assert_eq!(
        Halt::from_io(&io::Error::from(io::ErrorKind::TimedOut)),
        None
    );

    // 안쪽 리더의 오류는 그대로 올라가고, 읽지 못한 몫은 세지 않는다.
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }
    }
    let (b, _, _) = budget(TargetKind::Image);
    let mut buf = [0u8; 8];
    let error = b
        .wrap_reader(Broken, ReadKind::ImageInput)
        .read(&mut buf)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(Halt::from_io(&error), None);
    assert_eq!(b.usage().image_input_bytes, 0);
}

#[test]
fn every_message_exists_in_both_languages() {
    let kinds = [
        ReadKind::Container,
        ReadKind::ImageInput,
        ReadKind::ImageExpanded,
    ];
    let mut halts = vec![
        Halt::Cancelled,
        Halt::RunDeadline,
        Halt::Limit(Limit::EngineNotAllowed),
        Halt::Limit(Limit::Requests),
        Halt::Limit(Limit::Entries),
        Halt::Limit(Limit::Layers),
        Halt::Limit(Limit::FileSize),
    ];
    for kind in kinds {
        halts.push(Halt::Limit(Limit::Bytes(kind)));
        halts.push(Halt::Limit(Limit::Oversize(kind)));
    }
    let hangul = |s: &str| s.chars().any(|c| ('가'..='힣').contains(&c));
    let mut seen = std::collections::HashSet::new();
    for halt in halts {
        let (ko, en) = (halt.message(Lang::Ko), halt.message(Lang::En));
        assert!(hangul(&ko), "{halt:?}: {ko}");
        assert!(!hangul(&en) && !en.is_empty(), "{halt:?}: {en}");
        assert!(
            seen.insert(ko.clone()),
            "같은 문장이 두 까닭에 쓰였다: {ko}"
        );
    }
    assert_eq!(
        Halt::Limit(Limit::Bytes(ReadKind::ImageExpanded)).message(Lang::Ko),
        "점검 제한에 도달했습니다: 압축을 푼 이미지의 양 8 GiB"
    );
    assert_eq!(
        Halt::Limit(Limit::Bytes(ReadKind::Container)).message(Lang::En),
        "check limit reached: 256 MiB of data read from containers"
    );
}

#[test]
fn the_budget_is_shared_across_threads() {
    fn shared<T: Send + Sync>() {}
    shared::<Budget>();
    shared::<Cancel>();
    let (b, _, _) = budget(TargetKind::Image);
    let b = Arc::new(b);
    let mut workers = Vec::new();
    for _ in 0..4 {
        let b = Arc::clone(&b);
        workers.push(std::thread::spawn(move || {
            let data = vec![7u8; 64 * KIB];
            let mut reader = b.wrap_reader(data.as_slice(), ReadKind::ImageExpanded);
            let mut sink = Vec::new();
            reader.read_to_end(&mut sink).unwrap();
            for _ in 0..100 {
                b.count_entry().unwrap();
            }
            sink.len()
        }));
    }
    let read: usize = workers.into_iter().map(|w| w.join().unwrap()).sum();
    assert_eq!(read, 4 * 64 * KIB);
    let usage = b.usage();
    assert_eq!(usage.image_expanded_bytes, read as u64);
    assert_eq!(usage.entries, 400);
}

#[test]
fn usage_serialises_with_the_report_field_names() {
    let (b, _, _) = budget(TargetKind::Container);
    b.before_request().unwrap();
    b.count_entry().unwrap();
    b.read(&b"{}"[..], 16, ReadKind::Container).unwrap();
    let json = serde_json::to_string(&b.usage()).unwrap();
    assert_eq!(
        json,
        r#"{"container_requests":1,"container_bytes":2,"image_input_bytes":0,"image_expanded_bytes":0,"entries":1,"layers":0,"stops":[]}"#
    );
    let schema = serde_json::to_string(&schemars::schema_for!(Usage)).unwrap();
    for field in ["container_requests", "image_expanded_bytes", "stops"] {
        assert!(schema.contains(field), "{field}");
    }
}

#[test]
fn the_real_clock_moves_forward() {
    let clock = SystemClock;
    let before = clock.now();
    clock.sleep(Duration::ZERO);
    assert!(clock.now() >= before);
    let cancel = Cancel::default();
    let b = Budget::new(TargetKind::Image, cancel.clone(), Lang::Ko);
    assert_eq!(b.check(), Ok(()));
    cancel.set();
    assert_eq!(b.check(), Err(Halt::Cancelled));
}
