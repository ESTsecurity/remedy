//! 워치독 쌍 — **서로를 되살리는 두 프로세스** (설계-09 P8, 설계-07 시나리오 C).
//!
//! # 왜 컴파일된 픽스처인가
//!
//! 재려는 것은 "순차 종료로는 지고 정지 후 종료가 이긴다" 이고, 그 차이는
//! **첫 종료와 마지막 종료 사이의 창**이다. 그 창이 밀리초라면 상대도 밀리초
//! 안에 되살릴 수 있어야 시험이 무언가를 잰다. PowerShell 로 만든 감시자는
//! 기동에만 수백 밀리초가 걸려 **어떤 구현에게도 지고**, 그러면 "이겼다" 가
//! 아무것도 뜻하지 않는다.
//!
//! # 역할마다 하나뿐이다
//!
//! 처음 판에서는 이 규칙이 없었고, **실측에서 58개까지 불어났다.** 각자
//! 독립적으로 "상대가 없네" 라고 판단해 상대를 띄웠기 때문이다. 상대를 띄울
//! 자격이 하나뿐이어야 그 폭주가 구조적으로 불가능하다.
//!
//! 자격은 **공유 없이 연 파일 핸들**이다 (`share_mode(0)`). 같은 역할의 두 번째
//! 프로세스는 그 파일을 열지 못하고 그대로 나간다. 프로세스가 죽으면 OS 가
//! 핸들을 닫으므로 잠금이 새지 않는다 — 파일의 존재로 판정하면 강제 종료된
//! 뒤 그 역할이 영영 막힌다.
//!
//! # 폭주하지 않는다
//!
//! 스스로를 되살리는 쌍이므로 세 겹으로 묶는다. 셋 중 둘이 실패해도 나머지
//! 하나가 끝낸다.
//!
//! 1. **마감 시각** — 절대 시각을 넘기면 무조건 나간다
//! 2. **세대 상한** — 상한을 넘은 세대는 상대를 되살리지 않는다
//! 3. **표식** — 명령줄의 GUID 로만 정리한다. 다른 것을 건드리지 않는다

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Args {
    marker: String,
    role: String,
    peer: String,
    gen: u32,
    max_gen: u32,
    deadline: u64,
    dir: PathBuf,
}

fn parse() -> Option<Args> {
    let a: Vec<String> = std::env::args().collect();
    let get = |k: &str| -> Option<String> {
        a.iter()
            .position(|x| x == k)
            .and_then(|i| a.get(i + 1))
            .cloned()
    };
    Some(Args {
        marker: get("--marker")?,
        role: get("--role")?,
        peer: get("--peer")?,
        gen: get("--gen")?.parse().ok()?,
        max_gen: get("--max-gen")?.parse().ok()?,
        deadline: get("--deadline")?.parse().ok()?,
        dir: PathBuf::from(get("--dir")?),
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 밀리초 에포크. **되살리기까지 걸린 시간을 재려면 초로는 부족하다.**
///
/// 하네스가 이 값으로 "이 픽스처가 공정한 상대인가" 를 판정한다 — 되살리기가
/// 제품의 종료 창보다 느리면 어떤 구현도 이기고, 그때 "이겼다" 는 아무것도
/// 뜻하지 않는다.
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn role_lock(dir: &Path, marker: &str, role: &str) -> PathBuf {
    dir.join(format!("{marker}-{role}.lock"))
}

/// 그 역할의 자리를 **잡는다.** 이미 누가 앉아 있으면 `None`.
///
/// 공유 없이 열기 때문에 같은 파일을 두 프로세스가 함께 열 수 없다. 돌려주는
/// 핸들을 살아 있는 동안 들고 있어야 자리가 유지된다.
#[cfg(windows)]
fn take_seat(path: &Path) -> Option<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .share_mode(0)
        .open(path)
        .ok()
}

#[cfg(not(windows))]
fn take_seat(_path: &Path) -> Option<File> {
    // 이 픽스처는 Windows 전용이다. P8 의 VM 실증이 Windows 에서 돈다.
    None
}

fn spawn_peer(a: &Args) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    std::process::Command::new(exe)
        .args([
            "--marker",
            &a.marker,
            "--role",
            &a.peer,
            "--peer",
            &a.role,
            "--gen",
            &(a.gen + 1).to_string(),
            "--max-gen",
            &a.max_gen.to_string(),
            "--deadline",
            &a.deadline.to_string(),
            "--dir",
            &a.dir.to_string_lossy(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(())
}

fn main() {
    let Some(a) = parse() else {
        eprintln!(
            "사용법: lab-watchdog --marker <표식> --role <A|B> --peer <B|A> \
             --gen <세대> --max-gen <상한> --deadline <에포크초> --dir <작업 디렉터리>"
        );
        std::process::exit(2);
    };
    let _ = std::fs::create_dir_all(&a.dir);

    // 자리를 못 잡으면 같은 역할이 이미 돌고 있다. 조용히 나간다.
    let Some(_seat) = take_seat(&role_lock(&a.dir, &a.marker, &a.role)) else {
        std::process::exit(0);
    };

    // 몇 세대까지 갔는지 남긴다. 하네스가 "정말 되살아났는가" 를 이것으로 본다.
    // **줄 단위로 한 번에 쓴다** — 두 역할이 같은 파일에 붙이므로, 나눠 쓰면
    // 줄이 섞여 읽을 수 없게 된다(실측에서 그랬다).
    let line = format!(
        "{} role={} gen={} pid={}\n",
        now_ms(),
        a.role,
        a.gen,
        std::process::id()
    );
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(a.dir.join(format!("{}-generations.log", a.marker)))
    {
        let _ = f.write_all(line.as_bytes());
    }

    // **감시 주기는 짧다.** 공정한 상대여야 한다 — 느리면 어떤 구현에게도 져서
    // 시험이 아무것도 재지 못한다.
    let peer_seat = role_lock(&a.dir, &a.marker, &a.peer);
    let stop = a.dir.join(format!("{}.stop", a.marker));
    while now() < a.deadline {
        // **정지 파일이 확실한 끄기다.** 종료로 정리하려 들면 되살리기와
        // 경쟁하게 되고, 실측에서 정리 쪽이 졌다 — 8회를 죽여도 남았다.
        // 파일 하나면 다투지 않고 멈춘다.
        if stop.exists() {
            break;
        }
        if a.gen < a.max_gen && peer_is_gone(&peer_seat) {
            let _ = spawn_peer(&a);
            // **상대가 자리에 앉을 때까지 다시 띄우지 않는다.**
            //
            // 이 기다림이 없으면 프로세스가 뜨는 동안 계속 "없다" 로 읽혀 같은
            // 상대를 수십 번 띄운다 — 실측에서 41개까지 불어났다. 상한이 있어도
            // 그 사이에 불어나므로, 상한이 아니라 **띄우는 쪽의 절제**가 답이다.
            let t0 = std::time::Instant::now();
            while t0.elapsed() < Duration::from_millis(500)
                && !stop.exists()
                && peer_is_gone(&peer_seat)
            {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// 상대가 죽었는가.
///
/// # 왜 자리를 잡아 보지 않는가
///
/// 자리를 잡아 보는 것은 **잡는 것**이다. 그 순간 새로 뜬 상대가 자기 자리에
/// 앉지 못해 그대로 나가고, 그러면 관측이 관측 대상을 바꾼다 — 실측에서
/// 프로세스가 41개까지 불어난 원인이 이것이었다.
///
/// 대신 **지워 본다.** Windows 는 열려 있는 파일을 지우지 못하게 하고(공유
/// 없이 열었다), 그 거절이 곧 "살아 있다" 다. 지우기는 잠금을 잡지 않으므로
/// 상대의 자리 잡기와 다투지 않는다.
fn peer_is_gone(seat: &Path) -> bool {
    match std::fs::remove_file(seat) {
        // 지워졌다 = 아무도 들고 있지 않았다.
        Ok(()) => true,
        // 애초에 없다 = 아직 뜨지 않았거나 이미 갔다.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        // 지울 수 없다 = 누가 열어 두고 있다.
        Err(_) => false,
    }
}
