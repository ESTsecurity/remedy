//! xtask — 저장소 규칙을 강제하는 검사기.
//!
//! P0에서 코드보다 먼저 존재한다. 안전 불변식이 사람의 기억이 아니라 빌드에 걸려
//! 있어야 하기 때문이다 (설계-09 P0).
#![forbid(unsafe_code)]

mod arch;
mod console;
mod corpus;
mod docs;
mod exam;
mod examapply;
mod fixture;
mod fuzz;
mod guide;
mod leaks;
mod metrics;
mod netcriteria;
mod package;
mod pluginlock;
mod schema;
mod screens;
mod sign;
mod snapshots;
mod staticlink;
mod threats;
mod trace;
mod yara;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn workspace_root() -> PathBuf {
    // <root>/xtask/Cargo.toml -> <root>
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask 의 상위 디렉터리가 워크스페이스 루트다")
        .to_path_buf()
}

fn main() -> ExitCode {
    let root = workspace_root();
    let task = std::env::args().nth(1);

    let write = std::env::args().any(|a| a == "--write");

    let result = match task.as_deref() {
        Some("arch") => arch::run(&root).and_then(|()| arch::forbid_unsafe(&root)),
        Some("trace") => trace::run(&root),
        Some("schema") => schema::run(&root, write),
        // `static` 은 `all` 에 넣지 않는다. 빌드 산출물이 있어야 하는데, 없을 때
        // 조용히 넘어가게 만들면 "검사했다" 와 "검사할 것이 없었다" 가 같아진다.
        Some("static") => {
            let paths: Vec<String> = std::env::args()
                .skip(2)
                .filter(|a| a != "--write")
                .collect();
            staticlink::run(&root, &paths)
        }
        // 자립률. **출시를 막는 게이트가 아니라 추세 지표**라 `all` 에
        // 넣지 않는다 — 값이 낮다고 빌드를 멈추면 지표가 아니라 게이트다
        // (설계-03 §7).
        Some("metrics") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            metrics::run(&root, &args)
        }
        Some("guide") => guide::run(&root),
        Some("snapshots") => snapshots::run(&root),
        // AI 합격 시험 (설계-09 P11). **`all` 에 넣지 않는다** — 채점 대상이
        // 사람이 방금 생성한 룰이고, 없을 때 조용히 넘어가면 "시험했다" 와
        // "시험할 것이 없었다" 가 같아진다.
        Some("exam") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            exam::run(&root, &args)
        }
        // 채점 5(실기기 치료)의 **오프라인 짝**. 실기기에서 돌리는 것은 여기서
        // 못 하지만, 재었다는 증거가 지금 자료와 맞는지는 여기서 본다.
        Some("exam-apply") => examapply::run(&root),
        // **룰을 고치면 플러그인 버전을 올린다** (2026-09-06). 린트는 한 파일만
        // 보므로 "전과 달라졌는가" 는 저장소 게이트가 본다.
        Some("plugin-lock") => pluginlock::run(&root, write),
        // 동반 프로그램의 판정 기준(데이터 룰)이 읽히고 본체의 점검 룰과 같은 값인가 (코어 1.12.0).
        Some("net-criteria") => netcriteria::run(&root),
        // 공개 전 누출 검사. **`all` 에 넣지 않는다** — 옛 사본은 로컬 전용 파일을
        // 추적하고 있어 실패가 맞는 상태다. 공개 저장소에서는 CI 의 따로 선 잡이다.
        Some("leaks") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            leaks::run(&root, &args)
        }
        Some("all") => arch::run(&root)
            .and_then(|()| arch::forbid_unsafe(&root))
            .and_then(|()| trace::run(&root))
            .and_then(|()| schema::run(&root, false))
            .and_then(|()| guide::run(&root))
            // 문서가 인용한 화면이 기준선에 실제로 있는가. 커밋된 파일 둘을
            // 읽을 뿐이라 아무 데서나 돈다 — **캡처**만 실기기가 필요하다.
            .and_then(|()| console::doc(&root, &[]))
            // **다른 것을 잡는다.** `console-doc` 과 `console-diff` 는 *"전과
            // 달라졌는가"* 를 보고, 이것은 *"처음부터 틀린 말이 들어왔는가"* 를
            // 본다 — 2026-10-28 에 사람이 읽고 짚은 `--help-all` 의 한 줄이
            // 그 빈 자리였다. 커밋된 소스만 읽으므로 아무 데서나 돈다.
            .and_then(|()| screens::run(&root))
            .and_then(|()| snapshots::run(&root))
            .and_then(|()| examapply::run(&root))
            .and_then(|()| pluginlock::run(&root, false))
            // README 의 *다루는 위협* 표가 룰 매니페스트와 같은가 — 손으로 쓴 표는 룰이 늘면 어긋난다.
            .and_then(|()| threats::run(&root, &[]))
            // 동반 프로그램의 기준과 본체의 점검 룰이 같은 공지의 같은 값인가 — 한쪽만 고치면 여기서 걸린다.
            .and_then(|()| netcriteria::run(&root)),
        // VM 검증용 격리 컨테이너. 격리물을 **만드는** 것은 P6 의 몫이라
        // 제품 CLI 에 넣지 않고 개발 도구 쪽에 둔다.
        Some("fixture") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            fixture::run(&args)
        }
        // 파서 퍼징. **시드가 인자인 이유는 재현 때문이다** — 실패 보고에
        // 시드가 없으면 다시 만들어 낼 수 없고, 그런 보고는 쓸모가 없다.
        Some("fuzz") => {
            let arg = |name: &str, default: u64| -> u64 {
                std::env::args()
                    .skip_while(|a| a != name)
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(default)
            };
            fuzz::run(&root, arg("--seed", 0x5EED), arg("--millis", 2_000))
        }
        // 룰 실측 (G9). **`all` 에 넣지 않는다** — 검체는 저장소 밖에 있고,
        // 없을 때 조용히 넘어가게 만들면 "재 봤다" 와 "잴 것이 없었다" 가
        // 같아진다. 사람이 검체 경로를 대고 릴리스 전에 돌리는 게이트다.
        Some("yara") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            yara::run(&args)
        }
        // 청정 코퍼스 스냅샷 만들기. **`all` 에 넣지 않는다** — 실기기에서
        // 뜬 파일이 있어야 하고, 없을 때 조용히 넘어가면 "코퍼스를 늘렸다" 와
        // "늘릴 것이 없었다" 가 같아진다.
        Some("corpus") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            corpus::run(&args)
        }
        // 플러그인 서명. **`all` 에 넣지 않는다** — 개인키가 있어야 하고,
        // 없을 때 조용히 넘어가면 "서명했다" 와 "서명할 수 없었다" 가 같아진다.
        // 배포 꾸러미. **`all` 에 넣지 않는다** — 서명된 플러그인과 빌드된
        // 바이너리가 있어야 하고, 없을 때 조용히 넘어가면 "꾸러미를 만들었다" 와
        // "만들 것이 없었다" 가 같아진다.
        Some("package") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            package::run(&root, &args)
        }
        Some("threats") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            threats::run(&root, &args)
        }
        Some("sign") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            sign::run(&args)
        }
        // 콘솔 화면의 정규화 diff. 화면을 바꾸는 회차의 안전망이라 `all` 에 넣지
        // 않는다 — 캡처는 실기기·컨테이너에서 받는 것이고 빌드 게이트가 아니다.
        Some("console-diff") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            console::diff(&root, &args)
        }
        Some("console-normalize") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            console::normalize_cmd(&args)
        }
        // `all` 에도 들어 있다. 여기 따로 두는 것은 다른 문서를 대 볼 수 있게.
        Some("screens") => screens::run(&root),
        Some("console-doc") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            console::doc(&root, &args)
        }
        Some(other) => Err(format!("알 수 없는 작업: {other}")),
        None => Err("사용법: cargo xtask <arch|trace|schema|guide|snapshots|exam-apply|plugin-lock|net-criteria|all> [--write]\n\
                     cargo xtask metrics [--state-dir <디렉터리>] [--lang ko|en]\n\
                     cargo xtask static <바이너리 경로>...\n\
                     cargo xtask exam --dir <플러그인 디렉터리>
                     cargo xtask corpus --in <collect 결과> --label <이름>                      --out corpus/clean

                     cargo xtask fuzz [--seed <수>] [--millis <대상마다 ms>]\n\
                     cargo xtask fixture --out <파일> --dest-prefix <VM 경로> \
                     [--passphrase-out <파일>] [--org-secret-out <파일>]\n\
                     cargo xtask yara --rules <룰 디렉터리> --scan <디렉터리>... \
                     --expect <match|clean> [--rule <이름>] [--ext js] [--max-bytes <수>]
                     cargo xtask console-diff <이번 캡처>...\n\
                     cargo xtask console-normalize <캡처>...\n\
                     cargo xtask console-doc [<문서>]\n\
                     cargo xtask screens\n\
                     cargo xtask leaks [--preview] [--list]\n\
                     cargo xtask package --plugin <플러그인 디렉터리> [--plugin <또 하나> …] \
                     --bin <실행 파일> --out <꾸러미 폴더> --public-key <공개키>

                     cargo xtask sign keygen --public-key <파일> --secret-key <파일>
                     cargo xtask sign plugin --dir <플러그인> --secret-key <파일>                      --signed-at <RFC3339>
                     cargo xtask sign revocations --entries <JSON> --serial <수>                      --issued <RFC3339> --secret-key <파일> --out <파일>"
            .to_string()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("실패: {msg}");
            ExitCode::FAILURE
        }
    }
}
