//! `cargo xtask yara` — 룰을 **제품 엔진으로** 실측한다 (설계-03 §10 G9).
//!
//! 룰을 다른 YARA 로 시험해서 통과시키면 거짓 통과다. 제품이 쓰는
//! `remedy-yara` 로 컴파일하고 훑어야, 여기서 통과한 룰이 현장에서도 같은
//! 답을 낸다.
//!
//! # 이 도구가 지키는 구분
//!
//! **안 맞았다 / 못 훑었다 / 안 봤다** 를 절대 섞지 않는다. 읽지 못한 파일을
//! 조용히 "깨끗함" 으로 세면 오탐 0건이 측정이 아니라 착시가 된다 (설계-03
//! §1). 셋을 따로 세고 따로 낸다.
//!
//! # 왜 xtask 인가
//!
//! 검체는 저장소 밖에 있고 앞으로도 들어오지 않는다. 그래서 이 검사는 CI 가
//! 아니라 사람이 검체 경로를 대고 돌리는 릴리스 전 수동 게이트다 (G9).

use std::path::{Path, PathBuf};

use remedy_yara::{RuleRef, RuleSet};

/// 한 파일을 훑은 결과. `Unread` 를 `NoMatch` 로 접지 않는 것이 요점이다.
enum Outcome {
    Match,
    NoMatch,
    /// 훑지 못했다 — 미매치가 아니다.
    Unread(String),
}

struct Args {
    rules: PathBuf,
    scan: Vec<PathBuf>,
    rule: String,
    expect_match: bool,
    ext: Option<String>,
    max_bytes: u64,
    list: usize,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let get = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let rules = get("--rules").ok_or("--rules <룰 디렉터리> 가 필요하다")?;
    let scan: Vec<PathBuf> = args
        .iter()
        .enumerate()
        .filter(|(i, a)| *a == "--scan" && args.get(i + 1).is_some())
        .map(|(i, _)| PathBuf::from(&args[i + 1]))
        .collect();
    if scan.is_empty() {
        return Err("--scan <디렉터리> 가 최소 하나 필요하다".into());
    }
    let expect = get("--expect").ok_or("--expect <match|clean> 가 필요하다")?;
    let expect_match = match expect.as_str() {
        "match" => true,
        "clean" => false,
        other => return Err(format!("--expect 는 match 나 clean 이어야 한다: {other}")),
    };
    Ok(Args {
        rules: PathBuf::from(rules),
        scan,
        rule: get("--rule").unwrap_or_else(|| "evilai_locust_js".to_string()),
        expect_match,
        ext: get("--ext").map(|e| e.trim_start_matches('.').to_ascii_lowercase()),
        max_bytes: get("--max-bytes")
            .and_then(|v| v.parse().ok())
            .unwrap_or(16 * 1024 * 1024),
        list: get("--list").and_then(|v| v.parse().ok()).unwrap_or(20),
    })
}

/// 플러그인 디렉터리 기준 상대 이름(`rules/x.yar`)으로 읽는다.
///
/// 제품 CLI 의 `load_rules` 와 같은 규칙이다. 여기서 절대 경로로 담으면
/// `rules/x.yar:name` 참조가 어긋나서, 도구에서만 통과하고 제품에서는
/// 못 찾는 룰이 생긴다.
fn load_rules(dir: &Path) -> Result<Vec<(String, String)>, String> {
    if !dir.is_dir() {
        return Err(format!("{} 가 디렉터리가 아니다", dir.display()));
    }
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("yar"))
        })
        .collect();
    paths.sort();
    if paths.is_empty() {
        return Err(format!("{} 안에 .yar 이 없다", dir.display()));
    }
    let mut out = Vec::new();
    for p in paths {
        let name = format!(
            "rules/{}",
            p.file_name().unwrap_or_default().to_string_lossy()
        );
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        out.push((name, text));
    }
    Ok(out)
}

fn walk(root: &Path, ext: Option<&str>, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, ext, out);
        } else if ext.is_none_or(|x| {
            p.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case(x))
        }) {
            out.push(p);
        }
    }
}

pub fn run(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;

    let sources = load_rules(&a.rules)?;
    let set = RuleSet::compile(&sources);
    for (file, why) in &set.failed {
        eprintln!("  컴파일 실패 {file}: {why}");
    }
    if !set.failed.is_empty() {
        return Err(format!(
            "룰 파일 {}개를 컴파일하지 못했다",
            set.failed.len()
        ));
    }
    println!("룰 파일 {}개: {}", sources.len(), set.files().join(" · "));

    // 참조를 **먼저** 확인한다. 이름이 틀렸으면 전부 미매치로 나오고, 그것을
    // "오탐 0건" 으로 읽으면 아무것도 검사하지 않은 채 통과한다.
    let rref = RuleRef::parse(&format!(
        "{}:{}",
        sources
            .first()
            .map(|(n, _)| n.as_str())
            .unwrap_or("rules/?.yar"),
        a.rule
    ))
    .map_err(|e| e.to_string())?;
    set.matches(&rref, b"")
        .map_err(|e| format!("룰 참조를 확인하지 못했다: {e}"))?;
    println!("룰 참조 확인: {}", rref.as_text());

    let mut files = Vec::new();
    for root in &a.scan {
        if !root.exists() {
            return Err(format!("{} 가 없다", root.display()));
        }
        walk(root, a.ext.as_deref(), &mut files);
    }
    files.sort();
    println!(
        "대상 {}개{}",
        files.len(),
        a.ext
            .as_ref()
            .map(|e| format!(" (.{e} 만)"))
            .unwrap_or_default()
    );
    if files.is_empty() {
        // 0개를 훑고 "오탐 0건" 이라 말하면 거짓말이다.
        return Err("훑을 파일이 0개다 — 경로나 --ext 를 확인할 것".into());
    }

    let mut matched = Vec::new();
    let mut unread = Vec::new();
    let mut nomatch = 0usize;
    for p in &files {
        let outcome = match std::fs::metadata(p) {
            Err(e) => Outcome::Unread(e.to_string()),
            Ok(md) if md.len() > a.max_bytes => {
                Outcome::Unread(format!("{} 바이트 — 상한 초과", md.len()))
            }
            Ok(_) => match std::fs::read(p) {
                Err(e) => Outcome::Unread(e.to_string()),
                Ok(bytes) => match set.matches(&rref, &bytes) {
                    Err(e) => Outcome::Unread(e.to_string()),
                    Ok(true) => Outcome::Match,
                    Ok(false) => Outcome::NoMatch,
                },
            },
        };
        match outcome {
            Outcome::Match => matched.push(p.clone()),
            Outcome::NoMatch => nomatch += 1,
            Outcome::Unread(why) => unread.push((p.clone(), why)),
        }
    }

    println!();
    println!("  맞음      {}", matched.len());
    println!("  안 맞음   {nomatch}");
    println!("  못 훑음   {}", unread.len());

    let show = |label: &str, items: &[PathBuf]| {
        if items.is_empty() {
            return;
        }
        println!("\n{label} ({}건):", items.len());
        for p in items.iter().take(a.list) {
            println!("    {}", p.display());
        }
        if items.len() > a.list {
            println!("    ... 외 {}건", items.len() - a.list);
        }
    };

    if !unread.is_empty() {
        println!("\n못 훑은 것 ({}건) — 미매치가 아니다:", unread.len());
        for (p, why) in unread.iter().take(a.list) {
            println!("    {} — {why}", p.display());
        }
        if unread.len() > a.list {
            println!("    ... 외 {}건", unread.len() - a.list);
        }
    }

    if a.expect_match {
        let missed: Vec<PathBuf> = files
            .iter()
            .filter(|p| !matched.contains(p) && !unread.iter().any(|(u, _)| u == *p))
            .cloned()
            .collect();
        show("놓친 검체", &missed);
        if !missed.is_empty() || !unread.is_empty() {
            return Err(format!(
                "탐지 {}/{} — 놓침 {}건 · 못 훑음 {}건",
                matched.len(),
                files.len(),
                missed.len(),
                unread.len()
            ));
        }
        println!("\n탐지 {}/{} — 전부 맞았다", matched.len(), files.len());
    } else {
        show("오탐", &matched);
        if !matched.is_empty() {
            return Err(format!(
                "오탐 {}건 / {}개 — 이 룰은 내보낼 수 없다",
                matched.len(),
                files.len()
            ));
        }
        // 못 훑은 것이 있으면 "오탐 0건" 이라 단정하지 않는다.
        if !unread.is_empty() {
            return Err(format!(
                "오탐 0건이지만 {}건을 훑지 못했다 — 그만큼은 못 본 것이다",
                unread.len()
            ));
        }
        println!("\n오탐 0건 / {}개 — 전부 훑었다", files.len());
    }
    Ok(())
}
