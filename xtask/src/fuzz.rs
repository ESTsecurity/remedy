//! 파서 퍼징 (설계-09 P4 검증 — "파서 퍼징 7종 야간 실행").
//!
//! # 무엇을 재는가
//!
//! **패닉하지 않는가**, 그리고 **되돌아오는가**. 두 가지뿐이다.
//!
//! 여기 있는 파서는 전부 **남이 만든 바이트**를 읽는다 — 악성코드가 놓아 둔
//! `.lnk`, 조작된 예약 작업 XML, 변조된 격리 컨테이너, AI 가 지어낸 룰 식.
//! 그중 하나에서 패닉하면 수집이 통째로 죽고, **악성 파일 하나로 스캔을 멈출
//! 수 있다**는 뜻이 된다. 무한 루프도 같다.
//!
//! # 왜 `cargo-fuzz` 가 아닌가
//!
//! `cargo-fuzz` 는 nightly 와 libFuzzer 를 요구한다. 이 저장소는 stable 로
//! 빌드되고(설계-01 D1) 배포 바이너리도 stable 산출물이다. 도구 하나 때문에
//! 툴체인을 둘로 쪼개면 "CI 에서 도는 것과 배포되는 것이 다르다" 가 다시
//! 생긴다 — P0 에서 정적 CRT 로 이미 겪은 일이다.
//!
//! 대신 **결정적 시드**를 쓴다. 실패하면 시드와 입력이 함께 나오고, 같은 시드로
//! 다시 돌리면 같은 입력이 나온다. 재현되지 않는 퍼징 보고는 쓸모가 없다.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::{Duration, Instant};

/// xorshift64*. 난수 품질보다 **재현성**이 중요하다.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// 퍼징 대상 하나.
struct Target {
    name: &'static str,
    /// 씨앗 입력. 유효한 것에서 출발해야 파서의 깊은 곳까지 닿는다 —
    /// 완전한 난수는 대개 첫 줄에서 거부된다.
    corpus: Vec<Vec<u8>>,
    run: fn(&[u8]),
}

/// 입력 하나를 흔든다. 상한을 두는 이유는 **입력 크기가 시간을 지배**해서다.
fn mutate(rng: &mut Rng, base: &[u8], out: &mut Vec<u8>) {
    const MAX: usize = 64 * 1024;
    out.clear();
    out.extend_from_slice(base);
    if out.len() > MAX {
        out.truncate(MAX);
    }

    let rounds = 1 + rng.below(8);
    for _ in 0..rounds {
        match rng.below(6) {
            // 비트 뒤집기 — 길이 필드 한 자리를 거짓말로 만든다.
            0 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] ^= 1 << rng.below(8);
            }
            // 자르기 — 크래시로 반쯤 쓰인 파일이 이 모양이다.
            1 if !out.is_empty() => {
                let n = rng.below(out.len());
                out.truncate(n);
            }
            // 랜덤 바이트 덧붙이기.
            2 => {
                let n = rng.below(64);
                for _ in 0..n {
                    if out.len() >= MAX {
                        break;
                    }
                    out.push(rng.next() as u8);
                }
            }
            // 한 바이트 갈아 끼우기.
            3 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] = rng.next() as u8;
            }
            // 0 으로 채우기 — 길이 0, 오프셋 0 같은 경계를 만든다.
            4 if !out.is_empty() => {
                let i = rng.below(out.len());
                let n = rng.below(8).min(out.len() - i);
                for b in &mut out[i..i + n] {
                    *b = 0;
                }
            }
            // 0xFF 로 채우기 — 최대 길이를 만든다.
            _ if !out.is_empty() => {
                let i = rng.below(out.len());
                let n = rng.below(8).min(out.len() - i);
                for b in &mut out[i..i + n] {
                    *b = 0xFF;
                }
            }
            _ => {}
        }
    }
}

fn text(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn targets() -> Vec<Target> {
    vec![
        Target {
            name: "shortcut(.lnk)",
            corpus: vec![lnk_seed(), vec![0u8; 0x4C], Vec::new()],
            run: |b| {
                let _ = remedy_collect::shortcut::parse(b);
            },
        },
        Target {
            name: "scheduled-task(XML)",
            corpus: vec![
                text(
                    r#"<?xml version="1.0"?><Task><Actions><Exec><Command>c:\x.exe</Command>
                       <Arguments>-a</Arguments></Exec></Actions>
                       <Settings><Enabled>true</Enabled></Settings></Task>"#,
                ),
                text("<Task>"),
                Vec::new(),
            ],
            run: |b| {
                let _ = remedy_collect::task::parse(b);
            },
        },
        Target {
            name: "certificate(DER)",
            corpus: vec![der_seed(), vec![0x30, 0x82, 0xFF, 0xFF], Vec::new()],
            run: |b| {
                let _ = remedy_collect::certstore::der_of_blob(b);
            },
        },
        Target {
            name: "quarantine(container)",
            corpus: vec![text("RMDYQ"), vec![0u8; 64], Vec::new()],
            run: |b| {
                let _ = remedy_quarantine::Sealed::parse(b);
            },
        },
        Target {
            name: "verdict(expression)",
            corpus: vec![
                text("a and (b or not c)"),
                text("count(a) >= 3 and b"),
                text("((((("),
                Vec::new(),
            ],
            run: |b| {
                if let Ok(s) = std::str::from_utf8(b) {
                    let _ = remedy_detect::verdict::parse(s);
                }
            },
        },
        Target {
            name: "yara(rule-ref)",
            corpus: vec![text("rules/a.yar:name"), text(":"), Vec::new()],
            run: |b| {
                if let Ok(s) = std::str::from_utf8(b) {
                    let _ = remedy_detect::RuleRef::parse(s);
                }
            },
        },
        Target {
            name: "capture(expression)",
            corpus: vec![
                text("command | dirname | lower"),
                text("${a.b} | base64_decode | hex_decode"),
                text("|||"),
                Vec::new(),
            ],
            run: |b| {
                if let Ok(s) = std::str::from_utf8(b) {
                    let record = serde_json::json!({ "command": "c:\\x\\y.exe", "path": "c:\\x" });
                    let bindings = std::collections::BTreeMap::new();
                    let _ = remedy_detect::expr::capture(s, &record, &bindings);
                }
            },
        },
    ]
}

/// 최소한의 유효한 `.lnk`. 헤더를 통과해야 파서 안쪽까지 닿는다.
fn lnk_seed() -> Vec<u8> {
    let mut b = vec![0u8; 0x4C];
    b[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
    b[4..20].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    // IsUnicode | HasArguments | HasIconLocation
    b[20..24].copy_from_slice(&((1u32 << 7) | (1 << 5) | (1 << 6)).to_le_bytes());
    for s in ["-nop -w hidden", "C:\\i.ico"] {
        let units: Vec<u16> = s.encode_utf16().collect();
        b.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            b.extend_from_slice(&u.to_le_bytes());
        }
    }
    b
}

/// `Blob` 속성 하나에 DER 비슷한 것을 담은 씨앗.
fn der_seed() -> Vec<u8> {
    let der = vec![0x30, 0x06, 0x30, 0x04, 0x02, 0x01, 0x01, 0x00];
    let mut out = Vec::new();
    out.extend_from_slice(&32u32.to_le_bytes()); // CERT_CERT_PROP_ID
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(der.len() as u32).to_le_bytes());
    out.extend_from_slice(&der);
    out
}

pub fn run(_root: &Path, seed: u64, millis: u64) -> Result<(), String> {
    let targets = targets();
    println!(
        "퍼징 대상 {}종 · 시드 {seed} · 대상마다 {millis}ms",
        targets.len()
    );

    // 퍼징 중에는 패닉 메시지가 쏟아진다. **잡되 조용히** 한다 — 실패하면
    // 아래에서 시드와 입력을 함께 낸다.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut failures = Vec::new();
    let mut buf = Vec::new();

    for t in &targets {
        let mut rng = Rng(seed ^ (t.name.len() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        // 시드가 0 이면 xorshift 가 영영 0 이다.
        if rng.0 == 0 {
            rng.0 = 0x1234_5678_9ABC_DEF0;
        }
        let start = Instant::now();
        let budget = Duration::from_millis(millis);
        let mut iters: u64 = 0;
        let mut slowest = Duration::ZERO;

        while start.elapsed() < budget {
            let base = &t.corpus[rng.below(t.corpus.len())];
            mutate(&mut rng, base, &mut buf);
            let input = buf.clone();

            let one = Instant::now();
            let outcome = catch_unwind(AssertUnwindSafe(|| (t.run)(&input)));
            let took = one.elapsed();
            slowest = slowest.max(took);
            iters += 1;

            if outcome.is_err() {
                failures.push(format!(
                    "{} 패닉 — 시드 {seed}, 반복 {iters}, 입력 {}바이트: {}",
                    t.name,
                    input.len(),
                    hex(&input)
                ));
                break;
            }
            // **되돌아오지 않는 것도 실패다.** 무한 루프는 패닉하지 않는다.
            if took > Duration::from_secs(1) {
                failures.push(format!(
                    "{} 가 입력 하나에 {took:?} 를 썼다 — 시드 {seed}, 입력 {}바이트: {}",
                    t.name,
                    input.len(),
                    hex(&input)
                ));
                break;
            }
        }
        println!(
            "  {:<22} {iters:>8} 회 · 최장 {:>8.3}ms",
            t.name,
            slowest.as_secs_f64() * 1000.0
        );
    }

    std::panic::set_hook(previous);

    if failures.is_empty() {
        println!("fuzz OK — 패닉 없음, 입력 하나가 1초를 넘지 않음");
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

/// 실패 보고에 붙일 입력. 너무 길면 앞부분만 — 재현은 시드로 한다.
fn hex(b: &[u8]) -> String {
    let head: String = b.iter().take(64).map(|x| format!("{x:02x}")).collect();
    if b.len() > 64 {
        format!("{head}… ({}바이트)", b.len())
    } else {
        head
    }
}
