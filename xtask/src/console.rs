//! 콘솔 화면의 정규화와 diff — 화면을 바꾸는 회차의 안전망 (사용자 친화성 Phase 0).
//!
//! # 무엇을 막는 검사인가
//!
//! 화면을 고치는 회차는 **"의도한 줄 외에 달라진 줄이 0"** 이어야 한다. 그것을
//! 재려면
//! 고치기 전과 후의 캡처를 견줘야 하는데, 실행마다 다른 것 — 실행 번호·시각·경과·
//! 바이트 수·pid·호스트명·열쇠 지문 — 이 잡음을 만들어 diff 가 늘 붉다. 여기서는
//! **그 잡음만** 자리표시자로 바꾸고 나머지는 바이트 그대로 둔다.
//!
//! **숫자를 전부 지우지 않는다.** `흔적 6건`·`7 건을 수행합니다`·`[1/7]`·`[exit=2]` 는
//! 화면의 뜻이고, 그것이 바뀌면 diff 에 나와야 한다. 지우는 것은 단위가 붙은 수
//! (초·바이트·MB)와 이름이 정해진 자리(실행 번호·시각·pid·열쇠·호스트)뿐이다.
//!
//! **심장박동 줄은 통째로 뺀다.** 같은 기계에서도 검사가 4초일 때와 84초일 때가
//! 있다 — 설치된 백신의 온액세스 검사가 읽기 시간을 45배 늘린다
//! (`콘솔은-이렇게-보인다.md` §19). 줄이 나오는지 자체가 시간에 달렸으므로 정규화로는
//! 고정할 수 없다. 심장박동의 **형태**는 원본 캡처에서 눈으로 본다.
//!
//! 정규식 크레이트를 쓰지 않는다 — xtask 의 의존성은 오프라인 빌드가 가진 것뿐이다.

use std::path::{Path, PathBuf};
use std::process::Command;

/// 캡처 이름에서 어느 기준선과 견줄지 고른다.
///
/// # 왜 기준선을 인자로 받지 않는가
///
/// 화면을 바꾼 회차는 **두 캡처를 다 견줘야 한다**(Windows·Linux). 기준선을
/// 인자로 받으면 같은 명령을 두 번 쳐야 하고, 한 번 치고 넘어가면 다른 쪽이
/// 조용히 안 재어진다 — 점검표가 그것을 막으려고 "둘 다" 라고 적어 두고 있었다.
/// 기준선의 이름은 고정이므로 캡처 이름만 보면 정해진다.
///
/// **기준선을 캡처 자리에 주면 크게 실패한다.** 예전 형식(`<기준선> <이번>`)을
/// 그대로 치면 기준선을 자기 자신과 견줘 `diff 0` 이 나오는데, 그것은 아무것도
/// 재지 않고 초록을 내는 가장 나쁜 결과다.
fn baseline_for(base_dir: &Path, cap: &Path) -> Result<PathBuf, String> {
    let known: Vec<PathBuf> = BASELINES
        .iter()
        .chain(BASELINES_EN.iter())
        .map(|n| base_dir.join(n))
        .collect();
    let same = |x: &Path, y: &Path| match (x.canonicalize(), y.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if known.iter().any(|k| same(k, cap)) {
        return Err(format!(
            "{} 은 기준선이다 — 인자로는 **이번 캡처만** 준다.\n  \
             예전 형식 `console-diff <기준선> <이번>` 은 없어졌다. \
             기준선은 캡처 이름에서 고른다",
            cap.display()
        ));
    }
    let name = cap
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let plat = if name.contains("win") {
        "win"
    } else if name.contains("linux") {
        "linux"
    } else {
        return Err(format!(
            "{} 이 어느 쪽 캡처인지 이름이 말하지 않는다 — \
             `…-win.txt` 나 `…-linux.txt` 로 둘 것",
            cap.display()
        ));
    };
    // **언어는 토막으로 본다.** `contains("en")` 은 너무 헐거워 시각이나 경로에
    // 우연히 들어간 두 글자를 영어로 읽는다. `-` 로 쪼갠 토막이 정확히 `en` 일
    // 때만 영어 기준선을 고른다 — `console-20260916-155601-win` 은 걸리지 않고
    // `console-en-win` 은 걸린다.
    let en = cap
        .file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .split('-')
        .any(|t| t == "en");
    Ok(base_dir.join(if en {
        format!("console-{plat}-en.txt")
    } else {
        format!("console-{plat}.txt")
    }))
}

/// `cargo xtask console-diff <이번 캡처>...` — 캡처마다 짝이 되는 기준선을 골라
/// 둘을 정규화해 옆에 `.norm.txt` 로 쓰고 `git diff --no-index` 로 견준다.
///
/// **하나가 달라도 나머지를 마저 견준다.** 첫 차이에서 멈추면 두 번 돌려야
/// 하고, 그 사이에 사람이 한쪽만 보고 넘어간다.
pub fn diff(root: &Path, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "사용법: cargo xtask console-diff <이번 캡처>... (기준선은 이름에서 고른다)".into(),
        );
    }
    let base_dir = root.join("testbed/harness/baseline/console");
    let mut differed: Vec<String> = Vec::new();
    for a in args {
        let cap = PathBuf::from(a);
        let base = baseline_for(&base_dir, &cap)?;
        let nb = normalize_file(&base)?;
        let nc = normalize_file(&cap)?;
        println!("── {} ↔ {}", base.display(), cap.display());
        let status = Command::new("git")
            .args(["diff", "--no-index", "--exit-code", "--"])
            .arg(&nb)
            .arg(&nc)
            .status()
            .map_err(|e| format!("git 을 띄우지 못했다: {e}"))?;
        match status.code() {
            Some(0) => println!("   콘솔 diff 0 — 정규화 뒤 같다"),
            Some(1) => differed.push(cap.display().to_string()),
            other => return Err(format!("git diff 가 예상 밖으로 끝났다: {other:?}")),
        }
    }
    if differed.is_empty() {
        println!("콘솔 diff 0 — 캡처 {}개가 전부 기준선과 같다", args.len());
        Ok(())
    } else {
        Err(format!(
            "화면이 다르다 ({}) — 위 diff 가 전부다. 의도한 줄만인지 볼 것",
            differed.join(" · ")
        ))
    }
}

/// `cargo xtask console-normalize <캡처>...` — 정규화한 것만 옆에 쓴다.
///
/// # 왜 출력 경로를 받지 않는가
///
/// 예전에는 둘째 인자가 **출력 파일**이었다. 그러면 `<캡처> <캡처>` 와
/// `<캡처> <출력>` 이 같은 모양이 되어, 캡처 둘을 주려던 사람이 첫 캡처를
/// 둘째 캡처 위에 덮어쓴다. `console-diff` 가 같은 자리에서 겪은 일이고
/// (0b6061c), 여기서는 그 형태를 쓰는 곳이 저장소에 하나도 없었다.
///
/// 출력은 늘 `<입력>.norm.txt` 다 — `console-diff` 가 쓰는 것과 같은 규칙이라
/// 두 명령의 산출물이 한자리에 모인다.
pub fn normalize_cmd(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "사용법: cargo xtask console-normalize <캡처>... (정규화본은 <입력>.norm.txt)".into(),
        );
    }
    // **없는 파일은 크게 실패한다.** 예전 형식(`<캡처> <출력>`)을 그대로 치면
    // 둘째 인자가 아직 없는 파일일 때가 많다 — 거기서 조용히 넘어가면 무엇이
    // 왜 안 나왔는지 알 수 없다.
    for a in args {
        if !Path::new(a).is_file() {
            return Err(format!(
                "{a} 가 파일이 아니다 — 인자는 **캡처만** 준다.\n  \
                 예전 형식 `console-normalize <캡처> <출력>` 은 없어졌다. \
                 정규화본은 늘 `<입력>.norm.txt` 로 나간다"
            ));
        }
    }
    for a in args {
        let out = normalize_file(Path::new(a))?;
        println!("정규화 → {}", out.display());
    }
    Ok(())
}

/// 대조하는 기준선. **이름이 고정이라 인자로 받지 않는다.**
const BASELINES: [&str; 2] = ["console-win.txt", "console-linux.txt"];

/// 같은 화면을 **영어로** 받은 기준선 (2026-09-16).
///
/// # 왜 따로 두는가
///
/// 09-07 에 *"영어 화면의 한글 줄 0"* 을 컨테이너 실측으로 선언했는데 7일 뒤
/// 종료 코드 6 의 사유가 한국어로 나왔다. 그 회차에 **나오지 않은 화면**이라
/// 캡처가 보지 못했을 뿐이다. 한국어 기준선만으로는 그것을 잡을 수 없다 —
/// 한국어가 한국어로 나오는 것은 언제나 옳기 때문이다.
///
/// 문서(`콘솔은-이렇게-보인다.md`)는 한국어 화면을 인용하므로 **문서 대조에는
/// 쓰지 않는다.** `.norm.txt` 가 원본과 맞는지만 함께 본다.
const BASELINES_EN: [&str; 2] = ["console-win-en.txt", "console-linux-en.txt"];

/// `cargo xtask console-doc [<문서>]` — **문서가 인용한 화면이 실제 기준선에
/// 있는지** 대조한다.
///
/// # 왜 이것이 필요한가
///
/// `docs/design/콘솔은-이렇게-보인다.md` 는 첫 줄에서 *"지어낸 화면이 하나도
/// 없다"* 고 말한다. **아무도 재지 않는 주장은 곧 거짓이 된다** — 실제로 그
/// 문서는 화면을 바꾼 회차 다섯을 지나는 동안 조용히 낡아, `restore --list`·
/// 부작용 줄·설명 줄·안내 모드·창 유지가 하나도 없는 채로 "이렇게 보인다" 고
/// 말하고 있었다 (2026-09-09 에 발견).
///
/// 그래서 문서의 코드 블록에서 **화면으로 보이는 것**을 뽑아, 줄마다 기준선
/// 캡처(`testbed/harness/baseline/console/`)에 그대로 있는지 본다.
///
/// # 어느 블록을 대조하나 — **문서가 스스로 밝힌다**
///
/// | 펜스 | 뜻 | 대조 |
/// |---|---|---|
/// | ` ``` ` (맨 펜스) | 기준선 캡처에서 옮긴 화면 | **한다** |
/// | ` ```text ` | 기준선이 **그 꼴로는** 담지 않은 화면 | 안 한다. 개수를 보고한다 |
/// | 그 밖(`yaml`·`bash` …) | 화면이 아니다 | 안 한다 |
///
/// **그 여덟이 무엇인지는 문서가 적는다** — 머리말의 표가 블록마다 어느 하네스가
/// 내는지 가리킨다(2026-10-26). 처음 이 칸에 적어 둔 예시(*"권한 안내·승인
/// 프롬프트·창 유지"*)는 낡았다 — 권한 안내 화면들은 그 뒤 맨 펜스로 옮겨져
/// **대조되고 있고**, 지금 여덟은 관측 불완전·손댄 서명·G6 사유 둘·낮춘 도구
/// 상한이다. 캡처 시나리오가 그 꼴을 만들지 않아서다.
///
/// 처음에는 블록 안에 `[exit=`·`────` 같은 **표식**이 있는지로 갈랐다. 그것이
/// 너무 좁아 기준선에 있는 블록 일곱까지 함께 빠졌고, 그중 하나가 낡아도
/// 아무도 몰랐다 (2026-09-09). **어림짐작으로 고르지 않는다** — 어디서 받은
/// 화면인지는 쓴 사람만 알고, 그러면 쓴 사람이 적어야 한다.
///
/// # 빼는 줄
///
/// | 무엇 | 왜 |
/// |---|---|
/// | `←` 가 든 줄 | 설명을 위해 덧댄 주석이다 (§1 의 뼈대 그림) |
/// | `…` 가 든 줄 | 길어서 줄인 자리다 |
/// | `$ ` 로 시작하는 줄 | 셸 프롬프트지 출력이 아니다 |
///
/// # 펜스 균형을 먼저 본다
///
/// 2026-09-09 에 닫는 펜스가 하나 겹쳐 있었는데, 그때 이 검사의 초안은 그 뒤
/// 블록을 통째로 못 보고 **"없는 줄 0개"** 를 냈다 — 맞아서가 아니라 동기를
/// 잃어서였다. **계측기가 자기 상태를 먼저 확인하지 않으면 그 결과는 증거가
/// 아니다.** 그래서 홀수면 대조하지 않고 멈춘다.
///
/// # `all` 에 들어 있다 (2026-09-11)
///
/// 처음에는 밖에 두었다 — *"기준선은 실기기·컨테이너에서 받는 것이라 빌드
/// 게이트가 될 수 없다"*. 그 말은 **캡처**에 대해 참이고 이 명령에 대해서는
/// 참이 아니었다. 여기서 하는 일은 커밋된 파일 둘 — 문서와 기준선 — 을 읽어
/// 대조하는 것뿐이라 아무 러너에서나 돈다(`snapshots` 와 같은 부류다).
///
/// 밖에 두는 동안 그 문서는 화면을 바꾼 회차 다섯을 지나며 조용히 낡았다.
/// **사람이 기억해야 도는 게이트는 언젠가 안 돈다.** 캡처와 `console-diff` 는
/// 여전히 밖이다 — 그쪽은 실기기가 있어야 한다.
///
/// # 정규화본이 낡았는지도 본다 (2026-09-11)
///
/// `<기준선>.norm.txt` 는 `console-diff` 가 원본에서 **다시 만들어 덮어쓰는**
/// 파일이다. 기준선을 올리며 `.txt` 만 커밋해도 게이트 아홉이 전부 통과하고
/// `console-diff` 마저 `diff 0` 이라 말한다 — 낡은 판을 놓고 실제로 재어 봤다.
/// **아무도 못 잡았다.** 값은 빠뜨린 사람이 아니라 다음에 그 명령을 부르는
/// 사람이 치른다: 자기가 하지 않은 변경이 자기 트리에 나타난다.
///
/// 그래서 여기서 함께 본다. 이것도 커밋된 파일을 읽어 견주는 일이라 캡처도
/// 실기기도 필요 없다. 점검표에 적어 두는 것으로는 부족하다 — 점검표 역시
/// 사람이 기억해야 도는 것이다.
pub fn doc(root: &Path, args: &[String]) -> Result<(), String> {
    let doc = match args.first() {
        Some(p) => PathBuf::from(p),
        None => root.join("docs/design").join("콘솔은-이렇게-보인다.md"),
    };
    let base_dir = root.join("testbed/harness/baseline/console");

    // **정규화한 줄로 견준다** — `console-diff` 와 같은 규칙이다. 실행 번호·시각·
    // 호스트명·바이트 수는 재캡처마다 바뀌지만 화면의 뜻이 아니다. 처음에는 원문
    // 그대로 견줬고, 기준선을 처음 새로 받은 날(2026-09-09) 46줄이 갈라졌다 —
    // 전부 그 잡음이었다. 뜻이 있는 수(`흔적 6건`·`[1/7]`·`[exit=2]`)는 정규화가
    // 남기므로 그것이 바뀌면 여전히 걸린다.
    let mut base: Vec<String> = Vec::new();
    // (골격, 어디서 왔나, 원문)
    let mut base_skel: Vec<(String, String, String)> = Vec::new();
    let mut stale: Vec<String> = Vec::new();
    for name in BASELINES.iter().chain(BASELINES_EN.iter()).copied() {
        let p = base_dir.join(name);
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        // **정규화본이 원본과 맞는가.** `console-diff` 가 견줄 때마다 이 파일을
        // 원본에서 다시 만들어 덮어쓰므로, 낡은 채로 커밋되면 다음 사람의 트리에
        // 말없이 나타난다. 여기 말고는 그것을 보는 자리가 없다.
        let np = base_dir.join(format!("{}.norm.txt", name.trim_end_matches(".txt")));
        let want = normalize(&text);
        match std::fs::read_to_string(&np) {
            Ok(got) if got == want => {}
            Ok(got) => stale.push(format!(
                "{} 가 원본과 다르다 (첫 차이 {}줄째)",
                np.display(),
                first_diff_line(&want, &got)
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => stale.push(format!(
                "{} 가 없다 — 기준선만 올리고 두고 왔다",
                np.display()
            )),
            Err(e) => stale.push(format!("{} 를 읽지 못했다: {e}", np.display())),
        }
        // **문서 대조는 한국어 기준선만.** 문서가 인용하는 화면이 한국어이고,
        // 영어 기준선을 여기 섞으면 문서의 한국어 줄이 영어 쪽에서 우연히
        // 맞을 일은 없지만 "어느 기준선에 있는가" 가 흐려진다.
        if BASELINES.contains(&name) {
            base.extend(text.lines().filter_map(|l| norm_line(l.trim_end())));
            // 골격은 원문에서 뽑는다 — 정규화가 바꾸는 것(실행 번호·시각·바이트
            // 수)은 한글이 아니라 어차피 떨어진다. 자리도 함께 들고 다닌다:
            // 갈라진 줄을 신고할 때 **골격만 보여 주면 그것으로 grep 이 되지
            // 않아** 받은 사람이 자리를 다시 찾아야 한다.
            for (i, l) in text.lines().enumerate() {
                // **심장박동 줄은 골격 말뭉치에서도 뺀다** (2026-10-28).
                //
                // `base` 는 바로 위에서 `norm_line` 이 걸러 주는데 여기는 걸러
                // 주지 않아, 어느 단계(`수집`·`평가`·`파일 검사`)가 찍히느냐에
                // 따라 말뭉치가 캡처마다 달라졌다. 그 요동이 `UNMEASURED_MAX`
                // 를 밀어 올렸다 — 까닭은 그 상수 머리에.
                if norm_line(l.trim_end()).is_none() {
                    continue;
                }
                let s = hangul_skeleton(l.trim_end());
                if s.chars().count() >= SKELETON_NEAR {
                    base_skel.push((s, format!("{name}:{}", i + 1), l.trim().to_string()));
                }
            }
        }
    }
    if base.is_empty() {
        return Err(format!("기준선이 비었다: {}", base_dir.display()));
    }

    // **기준선이 담지 않은 화면의 옳은 꼴은 제품 소스에 있다** (2026-10-26).
    //
    // 캡처 시나리오는 거부된 디렉터리·수집 잘림·손댄 서명을 만들지 않으므로 그
    // 화면들은 기준선에 없다. 그러나 그 문장은 제품의 한국어 문자열 리터럴로
    // 커밋되어 있고, 골격이 `{n}`·`{path}` 같은 서식 치환자를 경로·개수와 똑같이
    // 떨어내므로 **그대로 견줄 상대가 된다.**
    //
    // 기준선만 말뭉치로 썼을 때 화면 마감 전 판에서 잡히는 것이 일곱이었다 —
    // 그때 실제로 낡은 대조 밖 줄은 열여섯이었다. 리터럴을 더해 **열셋**이 된다
    // (오탐은 그대로 0). 적대 검증이 이 격차를 재어 보여 주었다.
    for lit in korean_literals(root)? {
        let s = hangul_skeleton(&lit.text);
        if s.chars().count() >= SKELETON_NEAR {
            base_skel.push((s, lit.origin, lit.text));
        }
    }

    let text = std::fs::read_to_string(&doc).map_err(|e| format!("{}: {e}", doc.display()))?;
    let lines: Vec<&str> = text.lines().collect();

    // ── ① 펜스 균형 ────────────────────────────────────────
    let fences: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with("```"))
        .map(|(i, _)| i)
        .collect();
    if !fences.len().is_multiple_of(2) {
        return Err(format!(
            "코드펜스가 {}개로 홀수다 — 대조하지 않는다. {} 줄 부근을 볼 것",
            fences.len(),
            fences.last().map(|i| i + 1).unwrap_or(0)
        ));
    }

    // ── ② 문서가 밝힌 대로 고른다 ──────────────────────────
    let mut missing: Vec<(usize, String)> = Vec::new();
    let mut elsewhere: Vec<usize> = Vec::new();
    // (문서 줄번호, 문서 줄, 기준선 자리, 기준선 원문, 기준선 골격)
    let mut drifted: Vec<(usize, String, String, String, String)> = Vec::new();
    let (mut checked, mut screens) = (0usize, 0usize);
    let (mut near, mut short, mut beat) = (0usize, 0usize, 0usize);
    // **수가 아니라 줄 번호를 센다** (2026-10-28).
    //
    // 2026-10-27 에 이 수가 5 에서 6 으로 늘었는데, 게이트가 수만 말해 **어느
    // 줄인지 댈 수 없었다.** 통제 실험으로 원인(기준선 재캡처)까지는 좁혔지만
    // 줄을 지목하지 못한 채 상한을 올렸다. 재현 스크립트로 세 번 맞춰 보려 했고
    // 세 번 다 게이트의 블록 선택 규칙과 어긋났다 — 재는 자리는 하나여야 한다.
    let mut no_twin: Vec<usize> = Vec::new();

    // **대조하지 않는 줄도 그냥 두지 않는다** (2026-10-26).
    //
    // 이 검사는 두 자리를 비워 두었다 — ` ```text ` 블록 전부와, 대조하는 블록
    // 안에서 `←`·`…`·`$ ` 때문에 빠지는 줄이다. 2026-09-30 화면 마감 뒤 **그 두
    // 자리가 다 낡았고** 게이트는 초록이었다. 사람이 읽어서야 드러났다.
    //
    // 그 줄도 기준선이 **거의 같은 줄**을 들고 있으면 잴 수 있다. 한글 낱말만
    // 남긴 골격으로 가장 가까운 기준선 줄을 찾아, 공통 접두가 `SKELETON_NEAR`
    // 이상인데 **어느 쪽도 다른 쪽의 접두가 아니면** 문구가 갈라진 것이다.
    //
    // 값이 다른 것은 걸지 않는다 — 경로가 Windows·Linux 로 다르고 사유 개수가
    // 2·1 로 다른 줄이 실제로 있는데, 그 둘은 문구가 같다. 골격이 값을 떨어낸다.
    let mut check_uncompared = |no: usize, line: &str| {
        // **심장박동 줄은 이 셈에서 뺀다** (2026-10-28). 어느 단계가 찍히는지가
        // 캡처 시각에 달려 짝이 있다 없다 한다 — 문구가 낡아서가 아니다.
        // 세어서 보이기만 하고 상한은 걸지 않는다.
        if norm_line(quoted_part(line).trim()).is_none() {
            beat += 1;
            return;
        }
        // `←` 뒤는 설명이다 — 화면 부분만 본다.
        let sk = hangul_skeleton(quoted_part(line));
        if sk.is_empty() {
            return; // 한글이 없다 — 경로·숫자뿐인 줄은 셈에서 뺀다.
        }
        if sk.chars().count() < SKELETON_NEAR {
            // 한글이 짧아 애초에 견줄 수 없다. 이 수는 문구가 바뀌어도 늘지
            // 않으므로 상한을 걸지 않는다 — 세어서 보이기만 한다.
            short += 1;
            return;
        }
        let Some((bsk, origin, raw)) = base_skel
            .iter()
            .max_by_key(|(b, _, _)| skeleton_lcp(&sk, b))
            .filter(|(b, _, _)| skeleton_lcp(&sk, b) >= SKELETON_NEAR)
        else {
            // 견줄 상대가 없다 — 기준선도 제품 소스도 이 문장을 담지 않았다.
            // **이 수에 상한을 건다**: 재던 줄의 문구가 크게 바뀌면 상대를 잃고
            // 여기로 떨어진다. 그것이 이 검사가 조용해지는 길이다.
            no_twin.push(no);
            return;
        };
        near += 1;
        if !skeleton_agrees(line, bsk) {
            drifted.push((
                no,
                line.trim().to_string(),
                origin.clone(),
                raw.clone(),
                bsk.clone(),
            ));
        }
    };

    for pair in fences.chunks_exact(2) {
        let (open, close) = (pair[0], pair[1]);
        let info = lines[open][3..].trim();
        match info {
            // 맨 펜스 = 기준선에서 옮긴 화면.
            "" => {}
            // 기준선 밖에서 받은 화면. 대조하지 않되 **개수를 낸다** —
            // 조용히 넘기면 이 검사의 통과가 무엇을 뜻하는지 알 수 없다.
            "text" => {
                elsewhere.push(open + 1);
                for (off, raw) in lines[open + 1..close].iter().enumerate() {
                    check_uncompared(open + off + 2, raw.trim_end());
                }
                continue;
            }
            // 룰·명령. 화면이 아니다.
            _ => continue,
        }
        let body = &lines[open + 1..close];
        screens += 1;
        for (off, raw) in body.iter().enumerate() {
            let l = raw.trim_end();
            if l.is_empty() || l.contains('←') || l.contains('…') {
                check_uncompared(open + off + 2, l);
                continue;
            }
            if l.trim_start().starts_with("$ ") {
                check_uncompared(open + off + 2, l);
                continue;
            }
            // 문서가 인용한 심장박동 줄은 형태를 보이려는 것이다 — 숫자는 견줄
            // 수 없으니 `console-diff` 처럼 뺀다.
            let Some(n) = norm_line(l) else {
                continue;
            };
            checked += 1;
            if !base.contains(&n) {
                missing.push((open + off + 2, l.to_string()));
            }
        }
    }

    // **못 잰 수가 늘면 실패다.** 까닭은 `UNMEASURED_MAX` 머리에 있다.
    let too_many = no_twin.len() > UNMEASURED_MAX;
    let twinless: String = no_twin
        .iter()
        .map(|l| l.to_string())
        .collect::<Vec<_>>()
        .join(" · ");

    if missing.is_empty() && stale.is_empty() && drifted.is_empty() && !too_many {
        println!(
            "console-doc OK — 화면 블록 {screens}개의 {checked}줄이 전부 기준선에 있다 ({})",
            doc.display()
        );
        // **네 벌이다.** 위 루프가 `BASELINES` 와 `BASELINES_EN` 을 이어 돌므로
        // 실제로 검사한 수는 넷인데 이 줄만 둘이라고 말했다 — 하네스 README 의
        // 재캡처 점검표가 그 수를 통과 기준으로 적어 두어, 읽는 사람이 Windows
        // 정규화본은 재지 않는 줄로 읽었다(적대 검증 2026-10-26).
        println!(
            "  정규화본 {}개도 원본과 같다",
            BASELINES.len() + BASELINES_EN.len()
        );
        println!(
            "  대조 밖 한글 {}줄 가운데 {near}줄을 기준선·제품 문구와 견줬다 — 문구가 같다. \
             {}줄은 견줄 상대가 없고(상한 {UNMEASURED_MAX} · 줄 {twinless}) \
             {short}줄은 한글이 짧고 {beat}줄은 심장박동이다",
            near + no_twin.len() + short + beat,
            no_twin.len()
        );
        if !elsewhere.is_empty() {
            let where_: Vec<String> = elsewhere.iter().map(|l| l.to_string()).collect();
            println!(
                "  기준선 밖 화면 {}개는 줄끼리 대조하지 않았다 (```text · 줄 {})",
                elsewhere.len(),
                where_.join(" · ")
            );
        }
        return Ok(());
    }

    // **둘 다 보고한다.** 하나에서 멈추면 두 번 돌려야 하고, 그 사이에 사람이
    // 한쪽만 보고 넘어간다 (`diff` 가 캡처 여럿을 마저 견주는 것과 같은 이유).
    let mut msg = String::new();
    if !stale.is_empty() {
        msg.push_str(&format!(
            "기준선 정규화본이 원본과 맞지 않는다 {}건:",
            stale.len()
        ));
        for s in &stale {
            msg.push_str(&format!("\n  {s}"));
        }
        // **목록에서 짓는다.** 손으로 적어 두면 기준선이 늘어난 날
        // (2026-09-16 영어 둘) 이 안내만 낡아 사람을 반만 고치게 만든다.
        let cmd: String = BASELINES
            .iter()
            .chain(BASELINES_EN.iter())
            .map(|n| format!(" testbed/harness/baseline/console/{n}"))
            .collect();
        msg.push_str(&format!(
            "\n\n`.norm.txt` 는 `console-diff` 가 원본에서 다시 만든다. 기준선을 올릴 때\n\
             `.txt` 와 함께 커밋할 것 — 두고 오면 다음에 `console-diff` 를 부르는\n\
             사람의 트리에 말없이 나타난다. 다시 만드는 명령(셸 무관 한 줄):\n  \
             cargo xtask console-normalize{cmd}"
        ));
    }
    if !missing.is_empty() {
        if !msg.is_empty() {
            msg.push_str("\n\n");
        }
        msg.push_str(&format!(
            "문서가 기준선에 없는 화면을 인용한다 {}건 (화면 블록 {screens}개 · 대조 {checked}줄):",
            missing.len()
        ));
        for (ln, l) in missing.iter().take(20) {
            let short: String = l.chars().take(100).collect();
            msg.push_str(&format!("\n  {}:{ln}  {short}", doc.display()));
        }
        if missing.len() > 20 {
            msg.push_str(&format!("\n  … 그 밖 {}건", missing.len() - 20));
        }
        msg.push_str(
            "\n\n기준선을 먼저 다시 받고(cargo xtask console-diff 로 의도한 줄만인지 본 뒤)\n\
             문서를 그에 맞춘다. 순서가 반대면 문서가 코드보다 앞서 거짓말을 한다.",
        );
    }
    if !drifted.is_empty() {
        if !msg.is_empty() {
            msg.push_str("\n\n");
        }
        msg.push_str(&format!(
            "대조 밖 줄의 문구가 갈라졌다 {}건 \
             (` ```text ` 블록과 `←`·`…`·`$ ` 로 빠지는 줄 · 재어진 {}줄 가운데):",
            drifted.len(),
            near
        ));
        for (ln, l, origin, raw, b) in drifted.iter().take(20) {
            let short: String = l.chars().take(96).collect();
            let got: String = raw.chars().take(96).collect();
            let want: String = b.chars().take(96).collect();
            msg.push_str(&format!("\n  {}:{ln}\n    문서   {short}", doc.display()));
            msg.push_str(&format!("\n    지금   {origin}  {got}"));
            msg.push_str(&format!("\n    골격   {want}"));
        }
        if drifted.len() > 20 {
            msg.push_str(&format!("\n  … 그 밖 {}건", drifted.len() - 20));
        }
        msg.push_str(
            "\n\n값이 다른 것은 걸지 않는다 — 경로·개수·실행 번호는 떨어낸 뒤 견준다.\n\
             여기 걸린 것은 **낱말**이 다르다. `지금` 줄이 지금 화면이므로 문서를 그에\n\
             맞춘다(기준선 쪽이 낡았다고 보면 캡처부터 다시 받을 것).",
        );
    }
    if too_many {
        if !msg.is_empty() {
            msg.push_str("\n\n");
        }
        msg.push_str(&format!(
            "대조 밖 줄 가운데 **견줄 상대가 없는 것이 {}줄**이다 \
             (상한 {UNMEASURED_MAX} · 재어진 것 {near}줄).\n  \
             그 줄: {twinless}\n\n\
             이 검사의 가장 나쁜 실패는 조용해지는 것이다 — 어긋남이 골격 앞 \
             {SKELETON_NEAR}글자 안에 떨어지면\n그 줄은 견줄 상대를 잃고 검사에서 빠진다. \
             그래서 빠진 수가 늘면 실패로 적는다.\n\n\
             늘어난 줄이 **문구가 바뀐 것**이면 문서를 지금 화면에 맞춘다. 문서나 기준선이\n\
             늘어 이 수가 커지는 것이 옳다면 `UNMEASURED_MAX` 를 같은 회차에 올릴 것.",
            no_twin.len()
        ));
    }
    Err(msg)
}

/// 견줄 두 본문이 몇 줄째에서 갈라지는가 (1부터). 같으면 0.
///
/// 낡았다는 말만으로는 사람이 다음에 무엇을 할지 못 정한다 — 한 줄이 다른지
/// 통째로 다른지에 따라 볼 자리가 다르다.
fn first_diff_line(want: &str, got: &str) -> usize {
    let (mut w, mut g) = (want.lines(), got.lines());
    let mut n = 0usize;
    loop {
        n += 1;
        match (w.next(), g.next()) {
            (None, None) => return 0,
            (a, b) if a != b => return n,
            _ => {}
        }
    }
}

/// `foo.txt` 옆에 `foo.norm.txt` 를 쓴다. 이미 `.norm.txt` 면 그 이름을 다시 쓴다.
fn normalize_file(p: &Path) -> Result<PathBuf, String> {
    let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let stem = name
        .strip_suffix(".norm.txt")
        .or_else(|| name.strip_suffix(".txt"))
        .unwrap_or(&name);
    let out = p.with_file_name(format!("{stem}.norm.txt"));
    std::fs::write(&out, normalize(&text)).map_err(|e| format!("{}: {e}", out.display()))?;
    Ok(out)
}

/// 캡처 본문을 정규화한다. 줄 끝은 `\n` 으로 편다.
pub fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if let Some(l) = norm_line(line) {
            out.push_str(&l);
            out.push('\n');
        }
    }
    out
}

/// 줄 하나의 정규화. 심장박동 줄이면 `None` — 그 줄은 나오는지 자체가 시간에
/// 달려 있어 견줄 수 없다. `normalize` 와 `doc` 이 같은 규칙을 쓰도록 여기 하나다.
/// 줄에서 **한글 낱말만** 순서대로 남긴다 — `주의: '위협 없음' 을 말할 수 없습니다:`
/// 는 `주의 위협 없음 을 말할 수 없습니다` 가 된다.
///
/// 문서가 인용한 화면과 기준선이 **뜻은 같은데 값만 다른** 경우가 흔하다 — 경로가
/// Windows 와 Linux 로 다르고, 사유 개수가 2 와 1 로 다르고, 실행 번호가 다르다.
/// 그 값을 전부 떨어내면 남는 것이 **문구**다. 문구가 갈라지면 그것은 낡은 인용이다.
fn hangul_skeleton(line: &str) -> String {
    let mut out = String::new();
    let mut in_word = false;
    for c in line.chars() {
        if ('\u{AC00}'..='\u{D7A3}').contains(&c) {
            if !in_word && !out.is_empty() {
                out.push(' ');
            }
            out.push(c);
            in_word = true;
        } else {
            in_word = false;
        }
    }
    out
}

/// 제품 소스의 한국어 문자열 리터럴 하나.
struct Literal {
    text: String,
    origin: String,
}

/// `crates/*/src/**/*.rs` 의 **한국어 문자열 리터럴**을 모은다.
///
/// 주석 줄은 뺀다 — 주석은 화면이 아니라 화면을 **인용한 것**이고, 그것이 낡는 일이
/// 실제로 있었다(2026-10-26). 낡은 인용을 말뭉치에 넣으면 문서의 낡은 인용이 그것과
/// 맞아 통과한다.
///
/// 이어 붙인 리터럴(`"앞 \` 줄바꿈 `뒤"`)은 조각마다 들어간다. 조각이 짧으면
/// `SKELETON_NEAR` 가 걸러 내므로 해롭지 않다.
fn korean_literals(root: &Path) -> Result<Vec<Literal>, String> {
    let mut out = Vec::new();
    let crates = root.join("crates");
    let mut dirs = vec![crates];
    while let Some(d) = dirs.pop() {
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                dirs.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text =
                    std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                for (i, line) in text.lines().enumerate() {
                    if line.trim_start().starts_with("//") {
                        continue;
                    }
                    for piece in string_pieces(line) {
                        if piece.chars().any(is_hangul) {
                            out.push(Literal {
                                text: piece,
                                origin: format!("{rel}:{}", i + 1),
                            });
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

/// 한 줄에서 겹따옴표 사이 토막을 뽑는다. 닫히지 않은 쪽(이어 붙인 리터럴의 앞
/// 조각)도 거둔다 — 그 조각에 화면 문장이 들어 있는 경우가 흔하다.
pub(crate) fn string_pieces(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    let mut prev_esc = false;
    for c in line.chars() {
        match (&mut cur, c) {
            (Some(s), '"') if !prev_esc => {
                out.push(std::mem::take(s));
                cur = None;
            }
            (Some(s), _) => s.push(c),
            (None, '"') => cur = Some(String::new()),
            (None, _) => {}
        }
        prev_esc = c == '\\' && !prev_esc;
    }
    if let Some(s) = cur {
        out.push(s);
    }
    out
}

pub(crate) fn is_hangul(c: char) -> bool {
    ('\u{AC00}'..='\u{D7A3}').contains(&c)
}

/// 문서가 인용한 **화면 부분만** 남긴다 — `←` 뒤는 설명이다.
///
/// 위 *"빼는 줄"* 표가 이미 `←` 를 주석으로 선언했다. 골격에 그 낱말을 넣으면
/// `…` 로 줄인 자리 뒤에 설명이 붙어 **멀쩡한 인용이 갈라진 것으로 걸린다**
/// (실측 — 적대 검증 2026-10-26).
fn quoted_part(line: &str) -> &str {
    line.split('←').next().unwrap_or(line)
}

/// 문서 줄이 기준선 골격과 **문구가 같은가.**
///
/// `…` 는 줄인 자리다. 그 앞뒤 토막이 기준선 골격에 **순서대로** 들어 있으면 같은
/// 줄을 줄여 쓴 것이다 — 앞만 남긴 경우든 가운데를 줄인 경우든 통과한다. 처음에는
/// *"어느 한쪽이 다른 쪽의 접두"* 로 보았는데, 가운데를 줄이면 접두가 아니어서
/// **옳은 인용을 거부했다**(실측). 값만 다른 줄은 골격이 아예 같으므로 여기 든다.
fn skeleton_agrees(doc_line: &str, base: &str) -> bool {
    let mut pos = 0usize;
    for seg in quoted_part(doc_line).split('…').map(hangul_skeleton) {
        if seg.is_empty() {
            continue;
        }
        match base[pos..].find(&seg) {
            Some(i) => pos += i + seg.len(),
            None => return false,
        }
    }
    true
}

/// 기준선에 **거의 같은 줄**이 있다고 볼 최소 공통 접두 길이(한글 골격의 글자 수).
///
/// 데이터로 골랐다(2026-10-26) — **11 이 하한이다.** 10 으로 내리면 지금 트리에서
/// 오탐이 하나 난다: 문서의 도구 상한 알림 줄이 기준선의 심장박동 줄과 공통 접두
/// 10 으로 걸린다. 화면 마감 전 판(`b0be4bd~1`)에서는 열셋이 걸리고 지금 트리에서는
/// 0 이다. 짧게 잡을수록 앞으로 더 많이 덮지만 우연히 겹친 다른 화면을 걸 위험이
/// 커진다 — 그 경계가 10 이다.
const SKELETON_NEAR: usize = 12;

/// 재지 못한 줄의 상한.
///
/// **이 규칙의 가장 나쁜 실패는 조용해지는 것이다.** 어긋남이 골격 앞 12글자 안에
/// 떨어지면 공통 접두가 문턱 밑으로 내려가 그 줄이 검사에서 **빠지고 게이트는
/// 초록**이다. 화면 마감이 건드리는 자리가 하필 머리말(`주의:`·`실패:`)이라 드문
/// 꼴이 아니다 — 적대 검증이 여덟 블록의 재는 줄을 전부 낡게 바꿨는데도 통과하는
/// 것을 실측으로 보였다(2026-10-26).
///
/// 그래서 **견줄 상대가 없는 줄의 수에 상한을 둔다.** 늘면 실패다 — 줄이 검사 밖으로
/// 나간 것을 침묵이 아니라 빨간 줄로 알게 된다.
///
/// 처음 값은 실측이었다(2026-10-26): 대조 밖 한글 72줄 가운데 **35줄을 견주고 5줄만
/// 상대가 없다**(나머지 32줄은 한글이 짧아 애초에 못 센다 — 그 수는 문구가 바뀌어도
/// 늘지 않으므로 상한을 걸지 않는다). 문서나 기준선이 늘어 이 수가 커지는 것이 옳을
/// 때는 **같은 회차에 이 값을 올린다.**
///
/// # 5 → 6 → 4 (2026-10-28) — **이 수가 시각에 따라 달라지고 있었다**
///
/// 2026-10-27 에 화면 문구 셋을 바꾸고 기준선 4벌을 다시 떴더니 이 수가 5 에서 6
/// 으로 늘었다. 통제 실험으로 *재캡처가 원인*까지는 좁혔지만 **그 한 줄을 이름으로
/// 지목하지 못한 채** 상한을 올렸다. 재현 스크립트를 세 벌 써 봤고 세 번 다 이
/// 함수의 블록 선택 규칙과 어긋나 같은 수가 나오지 않았다.
///
/// 2026-10-28 에 게이트가 **스스로 줄 번호를 말하게** 고치고 나서야 짚였다 —
/// 옛 기준선에서는 `279 · 548 · 787 · 1019 · 1418 · 1490`, 새 기준선에서는
/// `1418` 이 빠진 다섯이었다. 1418 은 콘솔 문서의
/// `검사 중 · 평가 · 폴더 1개 · …` 이고, **심장박동 줄**이다.
///
/// 짝이 생기고 사라진 까닭:
///
/// | | 잡힌 심장박동 단계 | 1418 의 짝 |
/// |---|---|---|
/// | 옛 기준선 | `자동실행·서비스·작업` · `파일 검사` | **없다** |
/// | 새 기준선 | 위 둘 + **`평가`** | **있다** |
///
/// 심장박동 줄에 어느 단계가 찍히는지는 **그 순간 검사가 어디까지 갔는지**에
/// 달렸다. `base` 는 `norm_line` 이 심장박동을 걸러 그 요동을 받지 않는데
/// **`base_skel` 은 걸러 주지 않아** 말뭉치가 캡처마다 달라졌다. 상한이 요동치면
/// 그것은 상한이 아니다 — 올리는 쪽으로만 밀려 결국 조용해진다.
///
/// 그래서 양쪽에서 심장박동을 뺀다: 말뭉치(`base_skel`)에서도, 문서 쪽 셈에서도
/// (`beat` 로 따로 세어 보인다 — 조용히 넘기지 않는다). 남는 넷
/// (`279 · 548 · 1019 · 1490`)은 캡처 시각과 무관하다.
const UNMEASURED_MAX: usize = 4;

/// 두 골격의 공통 접두 길이(글자 수).
fn skeleton_lcp(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count()
}

fn norm_line(line: &str) -> Option<String> {
    let l = norm_tokens(line);
    let l = norm_units(&l);
    let l = norm_host(&l);
    if is_heartbeat(&l) {
        None
    } else {
        Some(l)
    }
}

// ── 이름이 정해진 자리 ──────────────────────────────────────

/// 실행 번호·시각·크래시 파일·pid·열쇠 지문(`local` · `org`).
fn norm_tokens(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        let rest = &line[i..];
        if let Some(n) = run_id_len(rest) {
            out.push_str("run-X");
            i += n;
            continue;
        }
        if let Some(r) = rest.strip_prefix("crash-") {
            if let Some(t) = ts_len(r) {
                if let Some(d) = r[t..].strip_prefix('-') {
                    let n = count_while(d, |b| b.is_ascii_digit());
                    if n > 0 {
                        out.push_str("crash-<T>-N");
                        i += 6 + t + 1 + n;
                        continue;
                    }
                }
            }
        }
        if let Some(n) = ts_len(rest) {
            out.push_str("<T>");
            i += n;
            continue;
        }
        // 메뉴가 짓는 결과 폴더의 스탬프 — 같은 초에 둘째면 꼬리 `-2` 가 붙는다(`fresh_dir`).
        // 꼬리도 지운다 — 앞 작업과 같은 초였는지는 캡처마다 다르다.
        if let Some(n) = stamp_len(rest) {
            out.push_str("<T>");
            i += n;
            continue;
        }
        if let Some(r) = rest.strip_prefix("pid ") {
            let n = count_while(r, |b| b.is_ascii_digit());
            if n > 0 {
                out.push_str("pid N");
                i += 4 + n;
                continue;
            }
        }
        if let Some((tag, n)) = key_fingerprint(rest) {
            out.push_str(tag);
            out.push_str("<hex>)");
            i += n;
            continue;
        }
        let c = rest.chars().next().expect("줄 안이다");
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// 열쇠 지문 `local(<hex 1+>)` · `org(<hex 1+>)` — 태그와 닫는 괄호까지의 길이.
/// 둘 다 실행마다 다르다: 로컬 키는 회차마다, 조직 키는 캡처의 M·R 절이 그때
/// 만드는 키쌍이다. 이미 `<hex>` 인 것은 16진이 아니라 걸리지 않는다.
fn key_fingerprint(s: &str) -> Option<(&'static str, usize)> {
    ["local(", "org("].into_iter().find_map(|tag| {
        let r = s.strip_prefix(tag)?;
        let n = count_while(r, |b| b.is_ascii_hexdigit());
        (n > 0 && r[n..].starts_with(')')).then_some((tag, tag.len() + n + 1))
    })
}

/// `run-<숫자 6+>-<hex 2+>-<hex 4+>` 의 길이. `run-does-not-exist` 는 아니다.
fn run_id_len(s: &str) -> Option<usize> {
    let rest = s.strip_prefix("run-")?;
    let d = count_while(rest, |b| b.is_ascii_digit());
    if d < 6 {
        return None;
    }
    let rest = rest[d..].strip_prefix('-')?;
    let h1 = count_while(rest, |b| b.is_ascii_hexdigit());
    if h1 < 2 {
        return None;
    }
    let rest = rest[h1..].strip_prefix('-')?;
    let h2 = count_while(rest, |b| b.is_ascii_hexdigit());
    if h2 < 4 {
        return None;
    }
    Some(4 + d + 1 + h1 + 1 + h2)
}

/// `YYYY-MM-DD[T ]HH[:-]MM[:-]SS[Z]` 의 길이. 크래시 파일 이름의 `15-46-37Z` 도 든다.
/// `YYYYMMDDTHHMMSSZ` 와 꼬리 `-N` — 메뉴의 결과 폴더 이름(`remedy-cli` 의 `menu_out`).
fn stamp_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.len() < 16 {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| r.into_iter().all(|i| b[i].is_ascii_digit());
    if !(digits(0..8) && b[8] == b'T' && digits(9..15) && b[15] == b'Z') {
        return None;
    }
    let mut n = 16;
    if b.get(n) == Some(&b'-') {
        let k = count_while(&s[n + 1..], |c| c.is_ascii_digit());
        if k > 0 {
            n += 1 + k;
        }
    }
    Some(n)
}

fn ts_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let d = |i: usize| b[i].is_ascii_digit();
    let ok = d(0)
        && d(1)
        && d(2)
        && d(3)
        && b[4] == b'-'
        && d(5)
        && d(6)
        && b[7] == b'-'
        && d(8)
        && d(9)
        && (b[10] == b'T' || b[10] == b' ')
        && d(11)
        && d(12)
        && (b[13] == b':' || b[13] == b'-')
        && d(14)
        && d(15)
        && b[16] == b[13]
        && d(17)
        && d(18);
    if !ok {
        return None;
    }
    Some(if b.get(19) == Some(&b'Z') { 20 } else { 19 })
}

fn count_while(s: &str, f: impl Fn(u8) -> bool) -> usize {
    s.bytes().take_while(|b| f(*b)).count()
}

// ── 단위가 붙은 수 ──────────────────────────────────────────

/// 단위가 붙은 수만 `N` 으로. 검사 시간 줄은 수가 전부 시간·크기라 통째로.
fn norm_units(line: &str) -> String {
    let timing =
        line.contains("검사 시간") || line.contains("scan time") || line.contains("Scan time");
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        let rest = &line[i..];
        let n = number_len(rest);
        if n > 0 {
            let after = &rest[n..];
            let unit = after.starts_with('초')
                || after.starts_with('분')
                || after.starts_with(" 바이트")
                || after.starts_with(" bytes")
                || after.starts_with(" MB")
                || seconds_suffix(after)
                || minutes_suffix(after)
                || out.ends_with("필요 ")
                || out.ends_with("여유 ")
                || out.ends_with("need ")
                || out.ends_with("free ");
            if timing || unit {
                out.push('N');
            } else {
                out.push_str(&rest[..n]);
            }
            i += n;
            continue;
        }
        let c = rest.chars().next().expect("줄 안이다");
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// `45s elapsed`·`7s`·`under 1s` 의 `s` — 뒤에 글자·숫자가 이어지면 단위가 아니다.
fn seconds_suffix(after: &str) -> bool {
    let Some(r) = after.strip_prefix('s') else {
        return false;
    };
    !r.chars().next().is_some_and(char::is_alphanumeric)
}

/// `1m 24s` 의 `m` — 뒤에 공백이나 줄 끝이 와야 분이다 (`MB` 는 대문자라 안 든다).
fn minutes_suffix(after: &str) -> bool {
    let Some(r) = after.strip_prefix('m') else {
        return false;
    };
    r.is_empty() || r.starts_with(' ')
}

/// `1234` · `4.2` 의 길이. `1.0.0` 은 `1.0` 까지만 — 뒤에 단위가 없으니 그대로 남는다.
fn number_len(s: &str) -> usize {
    let d = count_while(s, |b| b.is_ascii_digit());
    if d == 0 {
        return 0;
    }
    if let Some(r) = s[d..].strip_prefix('.') {
        let f = count_while(r, |b| b.is_ascii_digit());
        if f > 0 {
            return d + 1 + f;
        }
    }
    d
}

// ── 호스트명·심장박동 ──────────────────────────────────────

/// ` 실행 기계  : 86bf120696aa (linux)` — 컨테이너 id 는 실행마다 다르다.
fn norm_host(line: &str) -> String {
    let t = line.trim_end();
    if !(t.ends_with("(windows)") || t.ends_with("(linux)")) {
        return line.to_string();
    }
    let (Some(p), Some(q)) = (line.find(": "), line.rfind(" (")) else {
        return line.to_string();
    };
    if q < p + 2 {
        return line.to_string();
    }
    format!("{}<host>{}", &line[..p + 2], &line[q..])
}

/// 화면의 심장박동과 회차 로그에 `!` 로 남은 심장박동 둘 다.
fn is_heartbeat(line: &str) -> bool {
    let body = ["<T> | ", "<T> ! ", "<T> # "]
        .iter()
        .find_map(|m| line.strip_prefix(m))
        .unwrap_or(line);
    ["검사 중", "Scanning", "치료 중", "Treating"]
        .iter()
        .any(|p| body.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::{first_diff_line, normalize};

    /// 정규화본이 낡았다고만 말하면 사람이 어디를 볼지 못 정한다.
    /// **끝이 다른 경우**가 틀리기 쉽다 — 한쪽이 먼저 끝나면 그 자리가 첫 차이다.
    #[test]
    fn first_diff_line_points_at_the_line() {
        assert_eq!(first_diff_line("가\n나\n", "가\n나\n"), 0);
        assert_eq!(first_diff_line("가\n나\n", "가\n다\n"), 2);
        // 뒤에 줄이 더 붙었다 — 앞이 다 같아도 그 자리에서 갈라진다.
        assert_eq!(first_diff_line("가\n", "가\n나\n"), 2);
        assert_eq!(first_diff_line("가\n나\n", "가\n"), 2);
        assert_eq!(first_diff_line("", ""), 0);
    }

    /// 한 줄을 넣고 한 줄을 받는다.
    fn one(s: &str) -> String {
        normalize(s).trim_end_matches('\n').to_string()
    }

    #[test]
    fn run_ids_and_times_become_placeholders() {
        assert_eq!(
            one(" 되돌리려면 : remedy restore --run run-1788796125-16ac-1dc0c55c"),
            " 되돌리려면 : remedy restore --run run-X"
        );
        assert_eq!(
            one("격리소     : C:\\remedy-lab\\state\\quarantine\\run-1788795997-0265-54c4fc.rq"),
            "격리소     : C:\\remedy-lab\\state\\quarantine\\run-X.rq"
        );
        assert_eq!(
            one(" 시작 시각  : 2026-09-07 15:48:45 UTC"),
            " 시작 시각  : <T> UTC"
        );
        assert_eq!(
            one("2026-09-07T15:48:45Z # run_id run-1788796125-16ac-1dc0c55c"),
            "<T> # run_id run-X"
        );
        // 진짜 실행 번호가 아닌 것은 건드리지 않는다.
        assert_eq!(
            one("verify --run run-does-not-exist"),
            "verify --run run-does-not-exist"
        );
    }

    /// 메뉴의 결과 폴더 스탬프 — 같은 초의 둘째 꼬리(`-2`)까지 지운다. 앞 작업과 같은 초였는지는
    /// 캡처마다 다르다(모두 검사만은 룰마다 폴더를 따로 짓는다).
    #[test]
    fn menu_out_stamps_become_placeholders() {
        assert_eq!(
            one("결과 폴더 : /tmp/c/pkg/out/20261106T123637Z-2  (artifacts.json · scan.json)"),
            "결과 폴더 : /tmp/c/pkg/out/<T>  (artifacts.json · scan.json)"
        );
        assert_eq!(
            one("결과 폴더 : C:\\lab\\out\\20261106T123637Z  (artifacts.json)"),
            "결과 폴더 : C:\\lab\\out\\<T>  (artifacts.json)"
        );
        // 꼴이 덜 찬 것은 그대로다.
        assert_eq!(one("20261106T1236Z"), "20261106T1236Z");
    }

    #[test]
    fn counts_that_carry_meaning_survive() {
        for s in [
            "검사 완료 : 흔적 6건 · 위협 1건",
            "7 건을 수행합니다:",
            "  수행 [1/7] 프로세스 종료  (실행 중인 것을 찾아서)",
            "[exit=2]",
            " ESTsecurity 전용백신 1.0.0",
            " EvilAI(Locust) 제거  (evilai-locust 0.1.0)",
            "  [G5] 서로 다른 파일 6개를 지우려 한다. 상한은 2개다",
            "  실패 [1/2] 파일 격리  /opt/rokit/a.evil  /opt/rokit/a.evil: Read-only file system (os error 30)",
            "빌드 타깃: x86_64-pc-windows-msvc",
            "  [e4] C:\\Users\\test\\AppData\\Local\\Programs\\MicrosoftResourcesAgentV12",
            "Copyright © 2026 ESTsecurity Corp. All Rights Reserved.",
            "   4. 파일 격리  /usr/local/lib/.crypt-9d41/libnsl_compat.so.2",
        ] {
            assert_eq!(one(s), s, "뜻이 있는 수가 지워졌다");
        }
    }

    #[test]
    fn units_become_n() {
        assert_eq!(
            one("복원할 항목 6건 · 7443 바이트"),
            "복원할 항목 6건 · N 바이트"
        );
        assert_eq!(one(" 소요 시간  : 7초"), " 소요 시간  : N초");
        assert_eq!(one(" 소요 시간  : 1초 미만"), " 소요 시간  : N초 미만");
        assert_eq!(
            one("########## C1. scan — 한국어   [123초]"),
            "########## C1. scan — 한국어   [N초]"
        );
        assert_eq!(
            one("  볼륨 C:  필요 508 · 여유 21294944256 바이트"),
            "  볼륨 C:  필요 N · 여유 N 바이트"
        );
        assert_eq!(
            one("배포·정리 완료 · 19320832 bytes"),
            "배포·정리 완료 · N bytes"
        );
        assert_eq!(
            one("  plan.json               1932 바이트  무엇을 하려 했는가"),
            "  plan.json               N 바이트  무엇을 하려 했는가"
        );
        assert_eq!(one(" Elapsed    : 7s"), " Elapsed    : Ns");
        assert_eq!(one(" Elapsed    : under 1s"), " Elapsed    : under Ns");
        assert_eq!(one(" 소요 시간  : 1분 24초"), " 소요 시간  : N분 N초");
        assert_eq!(one(" Elapsed    : 1m 24s"), " Elapsed    : Nm Ns");
        // `s` 뒤에 글자가 이어지면 단위가 아니다.
        assert_eq!(one("2 samples"), "2 samples");
    }

    #[test]
    fn the_timing_line_loses_every_number() {
        assert_eq!(
            one("2026-09-07T15:48:49Z # 검사 시간 4.2초 · 걷기 0.2초 · 읽기 1.8초 (670.3 MB · 7947개) · 해시 0.4초 · 서명 1.3초"),
            "<T> # 검사 시간 N초 · 걷기 N초 · 읽기 N초 (N MB · N개) · 해시 N초 · 서명 N초"
        );
    }

    #[test]
    fn heartbeats_are_dropped_wherever_they_are() {
        let text = "\
검사 중 · 파일 검사 · 폴더 1156개 · 항목 9106개 · 처리 172개 · 경과 5초 · …odules\\@github\\copilot\\…
검사 중 · 파일 검사 · 폴더 1156개 · 항목 9106개 · 처리 3790개 · 경과 60초 · …\\AppData\\Local\\Programs\\…
검사 완료 : 흔적 6건 · 위협 1건
Scanning · files · 1156 folders · 9106 entries · 2411 processed · 45s elapsed · …
2026-09-07T15:48:49Z ! 검사 중 · 평가 · 폴더 1156개 · 항목 9106개 · 처리 7947개 · 경과 84초
2026-09-07T15:48:49Z | 검사 완료 : 흔적 6건 · 위협 1건
치료 중 · 도구 sc.exe stop 65초 · 경과 70초
";
        assert_eq!(
            normalize(text),
            "검사 완료 : 흔적 6건 · 위협 1건\n<T> | 검사 완료 : 흔적 6건 · 위협 1건\n"
        );
    }

    #[test]
    fn host_key_pid_and_crash_file() {
        assert_eq!(
            one(" 실행 기계  : 86bf120696aa (linux)"),
            " 실행 기계  : <host> (linux)"
        );
        assert_eq!(
            // 지어낸 이름이다. **`DESKTOP-` 꼴을 쓰지 않는다** — 누출 검사의
            // 일반 꼴에 걸려 시험 자료가 매번 후보로 올라온다.
            one("2026-09-07T15:48:45Z |  실행 기계  : lab-pc (windows)"),
            "<T> |  실행 기계  : <host> (windows)"
        );
        assert_eq!(
            one("열쇠       : local(dfcd2cdf)"),
            "열쇠       : local(<hex>)"
        );
        // 조직 복구 키의 지문도 — 캡처의 M(Windows)·R(리눅스) 절이 회차마다 새
        // 키쌍을 만들므로 실행마다 다르다. 지우지 않으면 화면을 바꾸지 않은
        // 회차의 diff 에도 이 줄이 늘 남아 사람이 매번 귀속해야 했다 (2026-09-30).
        assert_eq!(
            one("열쇠       : local(8eb63c7c) · org(fd9c50c4)"),
            "열쇠       : local(<hex>) · org(<hex>)"
        );
        assert_eq!(
            one("Keys       : local(0b99717c) · org(6d21655d)"),
            "Keys       : local(<hex>) · org(<hex>)"
        );
        // 이미 자리표시자인 것은 그대로 — 두 번 정규화해도 같다.
        assert_eq!(
            one("열쇠       : local(<hex>) · org(<hex>)"),
            "열쇠       : local(<hex>) · org(<hex>)"
        );
        assert_eq!(
            one("2026-09-07T15:48:45Z # remedy 1.0.0 pid 5804 · run --plugin C:\\x\\plugin.yaml"),
            "<T> # remedy 1.0.0 pid N · run --plugin C:\\x\\plugin.yaml"
        );
        assert_eq!(
            one("  기록: /tmp/cap/sP/logs/crash-2026-09-07T15-46-37Z-634.txt"),
            "  기록: /tmp/cap/sP/logs/crash-<T>-N.txt"
        );
    }

    #[test]
    fn normalizing_twice_changes_nothing() {
        let text = "\
 시작 시각  : 2026-09-07 15:48:45 UTC
검사 중 · 파일 검사 · 폴더 1개 · 항목 2개 · 처리 3개 · 경과 5초
 결과       : 위협 발견, 치료 완료 (7건 수행 완료)
 소요 시간  : 7초
 되돌리려면 : remedy restore --run run-1788796125-16ac-1dc0c55c
";
        let once = normalize(text);
        assert_eq!(normalize(&once), once);
    }

    #[test]
    fn crlf_is_flattened() {
        assert_eq!(normalize("a\r\nb\r\n"), "a\nb\n");
    }
}
