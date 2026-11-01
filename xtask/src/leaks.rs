//! 공개 전 누출 검사 — GitHub 공개 저장소에 **넣기로 한 것만** 들어갔는가, 그 안에
//! 내부 값이 없는가.
//!
//! # 장치 둘
//!
//! 1. **넣는 목록**(`xtask/public-paths.txt`). 빼는 목록은 새로 생긴 파일을
//!    놓친다 — 작업 중에 생긴 임시 문서·스크립트가 빼는 목록에 없으면 그대로
//!    공개된다. 넣는 목록에서는 새 자리가 들어가려면 사람이 그 줄을 더해야 한다.
//! 2. **꼴 검사.** 일반 꼴은 여기에, 정확한 값은 로컬 전용 목록
//!    (`.cargo/leaks.yml`, 커밋하지 않는다)에 둔다. 정확한 랩 주소·호스트명을 이
//!    파일에 적으면 **지키려는 값을 검사기가 공개한다.** 같은 까닭으로 아래 시험도
//!    값을 조각으로 이어 만들고, 이 파일이 자기 규칙에 걸리지 않는지를 시험한다.
//!
//! # 찾은 값을 출력하지 않는다
//!
//! 공개 저장소의 CI 로그는 공개물이다. 찾은 값을 찍으면 로그가 누출이 된다.
//! 규칙 이름과 자리(경로:줄)만 낸다 — 값은 그 자리를 열어 본다. [`Finding`] 에
//! 값을 담는 칸이 없는 것이 그 장치다.
//!
//! # 못 훑은 것을 통과로 접지 않는다
//!
//! `.gz` 는 풀어서 본다. 코퍼스 스냅샷이 전부 그것이고, 텍스트로 읽으면 0 이
//! 나온다 — 2026-10-31 에 그 0 을 "깨끗하다" 로 읽었다가 틀렸다. 풀어 볼 수 없는
//! 형식은 **못 훑음**으로 실패한다. 안 본 것을 "안 맞았다" 로 흘리면 검사가
//! 거짓말을 한다(룰 실측 G9 과 같은 원칙).
//!
//! # 두 쓰임
//!
//! | | `cargo xtask leaks` | `cargo xtask leaks --preview` |
//! |---|---|---|
//! | 어디서 | 공개 저장소 (CI · 올리기 전 확인) | 옛 사본 |
//! | 넣는 목록 밖의 추적 파일 | **실패** | 갈래별 건수 — 공개 트리에서 빠질 것 |
//! | 커밋 메시지 | 전부 본다 | 보지 않는다 — 옛 역사는 공개되지 않는다 |
//!
//! `all` 에 넣지 않는다. 옛 사본은 로컬 전용 파일을 추적하고 있어 이 검사가
//! 실패하는 것이 맞는 상태다. 공개 저장소에서는 CI 의 따로 선 잡으로 돈다.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::process::Command;

use regex::Regex;

/// 넣는 목록.
const ALLOW: &str = "xtask/public-paths.txt";

/// 로컬 전용 정확 값 목록. **이 파일 하나만 읽는다** — 같은 폴더의 다른 `.yml`
/// 에는 자격 증명이 있다.
const LOCAL: &str = ".cargo/leaks.yml";

/// 풀어 볼 수 없는 형식. 여기 걸리면 못 훑음이다 — 통과가 아니다.
const SEALED: &[&str] = &[
    ".zip", ".7z", ".rar", ".tar", ".xz", ".bz2", ".zst", ".jar", ".cab", ".msi",
];

/// 규칙 하나. **이름만** 출력에 나간다.
struct Rule {
    name: &'static str,
    re: Regex,
    /// 정규식이 이름을 뽑아 내는 규칙이면 걸러 낼 자리 표시(소문자). 정규식에
    /// 앞보기가 없어 이름을 뽑아 코드에서 가른다.
    placeholders: Option<Vec<&'static str>>,
}

/// Windows 가 스스로 만드는 프로필 — 사람이 아니다.
const WINDOWS_PROFILES: [&str; 4] = ["public", "default", "all", "defaultapppool"];

/// 시험 자료가 쓰는 흔한 계정 이름 — 랩 계정 `test` 와 시험의 자리 표시들
/// (2026-10-31 결정). 사람을 가리키지 않아 걸지 않는다. **흔하지 않은 이름은
/// 그대로 걸린다** — 시험 자료에 섞인 실제 이름은 사람이 보고 고친다.
const TEST_NAMES: [&str; 13] = [
    "test", "analyst", "alice", "bob", "a", "b", "u", "x",
    // 제품 시험의 자리 표시와 흔한 성 — `crates/**` 의 시험 자료에서 쓴다
    // (2026-10-31 에 전수를 보고 더했다. 그 밖의 이름은 그대로 걸린다).
    "t", "o", "kim", "hong", "...",
];

/// 일반 꼴 — 이 저장소에 두어도 되는 것만.
fn rules() -> Vec<Rule> {
    let plain = |name: &'static str, pat: &str| Rule {
        name,
        re: Regex::new(pat).expect("규칙 정규식"),
        placeholders: None,
    };
    vec![
        plain(
            "회사 도메인의 호스트",
            r"(?i)\b(?:[a-z0-9-]+\.)+estsecurity\.[a-z]{2,}\b",
        ),
        plain(
            "회사 메일 주소",
            r"(?i)\b[a-z0-9._%+-]+@estsecurity\.[a-z]{2,}\b",
        ),
        plain("사설 주소 192.168", r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
        plain(
            "Windows 기본 호스트명",
            r"\b(?:DESKTOP|LAPTOP)-[A-Z0-9]{7}\b|\bWIN-[A-Z0-9]{11}\b",
        ),
        // 드라이브·마운트 뒤에 올 때만 — 조직 주소(`github.com` 뒤)는 공개 자리다.
        plain(
            "개발 PC 의 작업 폴더",
            r#"(?i)(?:\b[a-z]:[\\/]+|/mnt/[a-z]/|(?:^|[\s"'`(=])/[a-z]/)estsecurity\b"#,
        ),
        plain("WSL 에서 본 Windows 드라이브", r"/mnt/[a-z]/"),
        // 폴더 이름만이 아니라 **그 안의 문서**를 가리킬 때 — 무시 목록과 안내문은
        // 폴더 이름을 적어야 한다. 이름을 조각으로 잇는 까닭은 위 문서 주석.
        plain(
            "로컬 전용 문서 참조",
            concat!("claude", r#"docs[\\/]+[^\s\\/"'`)\]]+"#),
        ),
        Rule {
            name: "실사용자 Windows 프로필",
            // 백틱도 이름에서 뺀다 — 마크다운·주석의 `` `C:\Users\alice\x` `` 에서
            // 닫는 백틱이 이름에 붙어 자리 표시 이름이 걸리고 있었다.
            re: Regex::new(r#"(?i)\b[a-z]:[\\/]+users[\\/]+([^\\/<>%$\s"':*?|{}`]+)"#)
                .expect("규칙 정규식"),
            placeholders: Some(
                WINDOWS_PROFILES
                    .iter()
                    .chain(&TEST_NAMES)
                    .copied()
                    .collect(),
            ),
        },
        Rule {
            name: "실사용자 /home",
            re: Regex::new(r"/home/([a-z_][a-z0-9_.-]*)").expect("규칙 정규식"),
            placeholders: Some(TEST_NAMES.to_vec()),
        },
    ]
}

/// 메시지 속의 긴 인용 — 사람의 말을 옮겨 적은 자리일 수 있다. **경고**만 한다.
/// 오류 문구를 인용한 정상 메시지도 같은 꼴이다.
fn long_quote() -> Regex {
    Regex::new(r#"["“][^"”\n]{20,}["”]"#).expect("인용 정규식")
}

/// 찾은 것 하나. **값을 담는 칸이 없다** — 출력으로 새지 않게 하는 장치다.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    rule: String,
    /// 갈래를 셀 때 쓰는 원래 경로(커밋이면 `커밋 <해시>`).
    file: String,
    /// `경로:줄`.
    place: String,
    count: usize,
}

fn count(rule: &Rule, line: &str) -> usize {
    match &rule.placeholders {
        None => rule.re.find_iter(line).count(),
        Some(skip) => rule
            .re
            .captures_iter(line)
            .filter(|c| {
                c.get(1).is_some_and(|m| {
                    let name = m.as_str().to_ascii_lowercase();
                    !skip.contains(&name.as_str())
                })
            })
            .count(),
    }
}

/// 견주기 좋게 고친다 — ASCII 대소문자와 경로 구분자(역슬래시·슬래시, 겹친 것
/// 포함)를 가리지 않는다. JSON 이 역슬래시를 두 번 적어도 같은 값으로 잡힌다.
fn norm(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut sep = false;
    for ch in s.chars() {
        if ch == '\\' || ch == '/' {
            if !sep {
                out.push('/');
            }
            sep = true;
        } else {
            out.push(ch.to_ascii_lowercase());
            sep = false;
        }
    }
    out
}

/// 글 하나를 줄마다 훑는다.
fn scan_text(
    rules: &[Rule],
    local: &[String],
    file: &str,
    label: &str,
    text: &str,
    out: &mut Vec<Finding>,
) {
    for (i, raw) in text.split('\n').enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let mut push = |rule: String, count: usize| {
            out.push(Finding {
                rule,
                file: file.to_string(),
                place: format!("{label}:{}", i + 1),
                count,
            })
        };
        for r in rules {
            let n = count(r, line);
            if n > 0 {
                push(r.name.to_string(), n);
            }
        }
        if !local.is_empty() {
            let line = norm(line);
            for (k, v) in local.iter().enumerate() {
                let n = line.matches(v.as_str()).count();
                if n > 0 {
                    push(format!("로컬 값 {}번", k + 1), n);
                }
            }
        }
    }
}

/// 파일 하나를 훑을 글로 바꾼다. 못 여는 형식이면 `Err(사유)` — 못 훑음이다.
fn texts(path: &str, bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let lower = path.to_ascii_lowercase();
    if SEALED.iter().any(|s| lower.ends_with(s)) {
        return Err("풀어 볼 수 없는 형식".to_string());
    }
    let (label, data) = if lower.ends_with(".gz") {
        let mut data = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut data)
            .map_err(|e| format!("압축을 풀지 못했다: {e}"))?;
        (format!("{path} (풀어서)"), data)
    } else {
        (path.to_string(), bytes.to_vec())
    };
    let mut out = vec![(label.clone(), String::from_utf8_lossy(&data).into_owned())];
    // NUL 이 있으면 UTF-16 으로도 읽는다 — 실행 파일의 리소스 문자열이 그 꼴이다.
    if data.contains(&0) {
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push((
            format!("{label} (UTF-16)"),
            String::from_utf16_lossy(&units),
        ));
    }
    Ok(out)
}

/// 넣는 목록. `/` 로 끝나는 줄은 그 아래 전부, 아니면 파일 하나.
#[derive(Debug, Default)]
struct Allow {
    dirs: Vec<String>,
    files: BTreeSet<String>,
}

impl Allow {
    fn parse(text: &str) -> Allow {
        let mut a = Allow::default();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.ends_with('/') {
                a.dirs.push(line.to_string());
            } else {
                a.files.insert(line.to_string());
            }
        }
        a
    }

    fn allows(&self, path: &str) -> bool {
        self.files.contains(path) || self.dirs.iter().any(|d| path.starts_with(d.as_str()))
    }

    /// 아무 추적 파일에도 닿지 않는 줄 — 없어진 자리를 가리키고 있다.
    fn unused(&self, tracked: &[String]) -> Vec<String> {
        let mut out: Vec<String> = self
            .files
            .iter()
            .filter(|f| !tracked.iter().any(|t| t == *f))
            .cloned()
            .collect();
        out.extend(
            self.dirs
                .iter()
                .filter(|d| !tracked.iter().any(|t| t.starts_with(d.as_str())))
                .cloned(),
        );
        out
    }
}

#[derive(serde::Deserialize)]
struct LocalList {
    #[serde(default)]
    values: Vec<String>,
}

/// 로컬 정확 값. 파일이 없으면 빈 목록이다 — CI 에는 없고 일반 꼴만 본다.
fn load_local(root: &Path) -> Result<Vec<String>, String> {
    let path = root.join(LOCAL);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{LOCAL}: {e}"))?;
    let list: LocalList = serde_yaml_ng::from_str(&text).map_err(|e| format!("{LOCAL}: {e}"))?;
    list.values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let n = norm(v.trim());
            if n.chars().count() < 3 {
                Err(format!(
                    "{LOCAL}: {}번 값이 너무 짧다 — 세 글자 아래면 엉뚱한 곳에 걸린다",
                    i + 1
                ))
            } else {
                Ok(n)
            }
        })
        .collect()
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|e| format!("git 을 띄우지 못했다: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {} 이 실패했다: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// 추적 파일. `-z` 라 한글 이름이 따옴표 꼴로 바뀌지 않는다.
fn tracked(root: &Path) -> Result<Vec<String>, String> {
    let raw = git(root, &["ls-files", "-z"])?;
    Ok(raw
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

/// 모든 커밋의 (짧은 해시, 메시지). 기록 사이는 바이트 1, 해시와 본문 사이는 NUL.
fn messages(root: &Path) -> Result<Vec<(String, String)>, String> {
    let raw = git(root, &["log", "--all", "--format=%h%x00%B%x01"])?;
    let mut out = Vec::new();
    for rec in raw.split(|b| *b == 1) {
        let start = rec.iter().position(|b| *b != b'\n').unwrap_or(rec.len());
        let rec = &rec[start..];
        let Some(nul) = rec.iter().position(|b| *b == 0) else {
            continue;
        };
        out.push((
            String::from_utf8_lossy(&rec[..nul]).into_owned(),
            String::from_utf8_lossy(&rec[nul + 1..]).into_owned(),
        ));
    }
    Ok(out)
}

/// 맨 위 자리 — 뿌리의 파일은 `(뿌리)`.
fn top(path: &str) -> String {
    match path.split_once('/') {
        Some((head, _)) => head.to_string(),
        None => "(뿌리)".to_string(),
    }
}

/// 갈래 — 시험 자료는 세 단, 나머지는 두 단까지. 파일 자신은 갈래가 아니다.
fn group(path: &str) -> String {
    if path.starts_with("커밋 ") {
        return "커밋 메시지".to_string();
    }
    let parts: Vec<&str> = path.split('/').collect();
    let depth = if matches!(parts[0], "testbed" | "corpus") {
        3
    } else {
        2
    };
    let n = depth.min(parts.len() - 1);
    if n == 0 {
        "(뿌리)".to_string()
    } else {
        parts[..n].join("/")
    }
}

/// 갈래마다 몇 개인지 — 많은 순으로 여섯까지.
fn tally<'a>(paths: impl Iterator<Item = &'a str>, key: fn(&str) -> String) -> String {
    let mut n: BTreeMap<String, usize> = BTreeMap::new();
    for p in paths {
        *n.entry(key(p)).or_default() += 1;
    }
    let mut v: Vec<(String, usize)> = n.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let more = v.len().saturating_sub(6);
    let mut s: Vec<String> = v
        .into_iter()
        .take(6)
        .map(|(k, c)| format!("{k} {c}"))
        .collect();
    if more > 0 {
        s.push(format!("외 {more} 갈래"));
    }
    s.join(" · ")
}

/// 한 번 훑은 결과.
#[derive(Default)]
struct Scan {
    findings: Vec<Finding>,
    sealed: Vec<String>,
    commits: usize,
    quoted: Vec<String>,
    /// 예외 목록이 넘긴 건수 — **조용히 넘기지 않는다.**
    excepted: usize,
}

/// 예외 목록. **값이 아니라 규칙 이름과 경로**라서 저장소에 둔다 — 공개 저장소의
/// CI 도 같은 예외로 돌아야 한다. 로컬 목록(`.cargo/leaks.yml`)에 두면 공개 CI 가
/// 그 파일 없이 돌아 빨개진다.
const EXCEPT: &str = "xtask/leaks-except.txt";

/// 예외 한 줄 — 어느 규칙을 어느 경로에서 넘기는가.
struct Except {
    rule: String,
    prefix: String,
}

/// `규칙 이름 | 경로 접두사 | 사유` 꼴을 읽는다. `#` 뒤는 주석이다.
fn load_except(root: &Path) -> Result<Vec<Except>, String> {
    let path = root.join(EXCEPT);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for (no, raw) in text.lines().enumerate() {
        let body = raw.split('#').next().unwrap_or("").trim();
        if body.is_empty() {
            continue;
        }
        let mut parts = body.split('|').map(str::trim);
        let (Some(rule), Some(prefix)) = (parts.next(), parts.next()) else {
            return Err(format!("{EXCEPT}:{} — `규칙 | 경로` 꼴이 아니다", no + 1));
        };
        if rule.is_empty() || prefix.is_empty() {
            return Err(format!("{EXCEPT}:{} — 규칙이나 경로가 비었다", no + 1));
        }
        out.push(Except {
            rule: rule.to_string(),
            prefix: prefix.to_string(),
        });
    }
    Ok(out)
}

/// 이 찾음이 예외에 드는가. 경로는 접두사로, 규칙은 이름이 꼭 같아야 한다.
fn is_excepted(f: &Finding, except: &[Except]) -> bool {
    except
        .iter()
        .any(|e| f.rule == e.rule && f.file.starts_with(&e.prefix))
}

/// 예외를 걸러 낸다. 넘긴 건수는 세어 보고에 싣는다.
fn apply_except(scan: &mut Scan, except: &[Except]) {
    if except.is_empty() {
        return;
    }
    let mut kept = Vec::with_capacity(scan.findings.len());
    for f in scan.findings.drain(..) {
        if is_excepted(&f, except) {
            scan.excepted += f.count;
        } else {
            kept.push(f);
        }
    }
    scan.findings = kept;
}

fn scan_files(root: &Path, inside: &[&String], rules: &[Rule], local: &[String]) -> Scan {
    let mut scan = Scan::default();
    for p in inside {
        let bytes = match std::fs::read(root.join(p.as_str())) {
            Ok(b) => b,
            Err(e) => {
                scan.sealed.push(format!("{p} — 읽지 못했다: {e}"));
                continue;
            }
        };
        match texts(p, &bytes) {
            Ok(ts) => {
                for (label, t) in ts {
                    scan_text(rules, local, p, &label, &t, &mut scan.findings);
                }
            }
            Err(why) => scan.sealed.push(format!("{p} — {why}")),
        }
    }
    scan
}

fn scan_messages(
    root: &Path,
    rules: &[Rule],
    local: &[String],
    scan: &mut Scan,
) -> Result<(), String> {
    let quote = long_quote();
    for (hash, body) in messages(root)? {
        scan.commits += 1;
        let label = format!("커밋 {hash}");
        scan_text(rules, local, &label, &label, &body, &mut scan.findings);
        if body.lines().any(|l| quote.is_match(l)) {
            scan.quoted.push(hash);
        }
    }
    Ok(())
}

/// 규칙마다 한 줄 — 건수 · 자리 수 · 갈래별 자리 수. 차례는 `order` 를 따른다.
fn summary_lines(findings: &[Finding], order: &[String]) -> Vec<String> {
    let mut by_rule: BTreeMap<&str, (usize, BTreeSet<&str>)> = BTreeMap::new();
    for f in findings {
        let e = by_rule.entry(f.rule.as_str()).or_default();
        e.0 += f.count;
        e.1.insert(f.file.as_str());
    }
    order
        .iter()
        .filter_map(|name| {
            let (hits, files) = by_rule.get(name.as_str())?;
            let groups = tally(files.iter().copied(), group);
            Some(format!(
                "  {name} — {hits} 건 · {} 곳 · {groups}",
                files.len()
            ))
        })
        .collect()
}

fn parse_args(args: &[String]) -> Result<(bool, bool), String> {
    let mut preview = false;
    let mut list = false;
    for a in args {
        match a.as_str() {
            "--preview" => preview = true,
            "--list" => list = true,
            other => {
                return Err(format!(
                    "알 수 없는 인자: {other}\n사용법: cargo xtask leaks [--preview] [--list]"
                ))
            }
        }
    }
    Ok((preview, list))
}

fn report_outside(outside: &[&String], preview: bool) {
    if outside.is_empty() {
        return;
    }
    if preview {
        let groups = tally(outside.iter().map(|p| p.as_str()), top);
        println!(
            "  넣는 목록 밖 추적 파일 {} — 공개 트리에서 빠진다: {groups}",
            outside.len()
        );
    } else {
        println!("  넣는 목록 밖 추적 파일 {}:", outside.len());
        for p in outside {
            println!("    {p}");
        }
    }
}

fn report_tail(scan: &Scan, preview: bool) {
    for s in &scan.sealed {
        println!("  못 훑음: {s}");
    }
    if preview {
        println!("  커밋 메시지는 보지 않았다 — 옛 역사는 공개되지 않는다");
        return;
    }
    println!("  커밋 메시지 {} 개를 봤다", scan.commits);
    if !scan.quoted.is_empty() {
        println!(
            "  경고 — 긴 인용이 있는 커밋 {}: {} (사람의 말을 옮겨 적었는지 볼 것)",
            scan.quoted.len(),
            scan.quoted.join(" · ")
        );
    }
}

fn verdict(scan: &Scan, outside: usize, preview: bool, public: usize) -> Result<(), String> {
    let hits: usize = scan.findings.iter().map(|f| f.count).sum();
    let places: BTreeSet<&str> = scan.findings.iter().map(|f| f.file.as_str()).collect();
    let stray = if preview { 0 } else { outside };
    if hits > 0 || !scan.sealed.is_empty() || stray > 0 {
        return Err(format!(
            "누출 후보 {hits} 건 ({} 곳) · 못 훑음 {} · 넣는 목록 밖 {stray} — 공개하기 전에 고칠 것",
            places.len(),
            scan.sealed.len()
        ));
    }
    let mode = if preview { " --preview" } else { "" };
    if scan.excepted > 0 {
        // **0 이라고만 말하지 않는다.** 예외로 넘긴 것이 있으면 그 수를 함께
        // 적는다 — 넘긴 것을 숨기면 '누출 0' 이 거짓이 된다.
        println!(
            "leaks{mode} OK — 공개 트리 {public} 파일에 누출 후보 0 (예외로 넘긴 {} 건은 {EXCEPT} 에 적혀 있다)",
            scan.excepted
        );
    } else {
        println!("leaks{mode} OK — 공개 트리 {public} 파일에 누출 후보 0");
    }
    Ok(())
}

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let (preview, list) = parse_args(args)?;
    let text = std::fs::read_to_string(root.join(ALLOW)).map_err(|e| format!("{ALLOW}: {e}"))?;
    let allow = Allow::parse(&text);
    let local = load_local(root)?;
    let rules = rules();
    let files = tracked(root)?;
    let (inside, outside): (Vec<&String>, Vec<&String>) =
        files.iter().partition(|p| allow.allows(p));

    let except = load_except(root)?;
    let mut scan = scan_files(root, &inside, &rules, &local);
    if !preview {
        scan_messages(root, &rules, &local, &mut scan)?;
    }
    apply_except(&mut scan, &except);

    let mode = if preview { " --preview" } else { "" };
    println!(
        "누출 검사{mode} — 공개 트리 {} 파일 · 일반 꼴 {} 가지 · 로컬 값 {} 개",
        inside.len(),
        rules.len(),
        local.len()
    );
    if local.is_empty() {
        println!("  로컬 목록({LOCAL})이 없다 — 일반 꼴만 본다");
    }
    report_outside(&outside, preview);
    for line in allow.unused(&files) {
        println!("  넣는 목록의 쓰이지 않는 줄: {line}");
    }
    let mut order: Vec<String> = rules.iter().map(|r| r.name.to_string()).collect();
    order.extend((1..=local.len()).map(|k| format!("로컬 값 {k}번")));
    for line in summary_lines(&scan.findings, &order) {
        println!("{line}");
    }
    if list || !preview {
        for f in &scan.findings {
            let times = if f.count > 1 {
                format!(" ×{}", f.count)
            } else {
                String::new()
            };
            println!("    {} — {}{times}", f.rule, f.place);
        }
    }
    report_tail(&scan, preview);
    verdict(&scan, outside.len(), preview, inside.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 시험 값은 조각을 이어 만든다 — 이 파일이 자기 규칙에 걸리지 않게(마지막 시험).
    fn ip() -> String {
        ["192", "168", "7", "20"].join(".")
    }

    const BS: char = '\\';

    fn names(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        scan_text(&rules(), &[], "f", "f", line, &mut out);
        out.into_iter().map(|f| f.rule).collect()
    }

    #[test]
    fn a_private_address_is_found_but_its_value_is_not_in_the_finding() {
        let mut out = Vec::new();
        let line = format!("$vm = '{}'", ip());
        scan_text(&rules(), &[], "a.ps1", "a.ps1", &line, &mut out);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].place, "a.ps1:1");
        // 출력에 나가는 칸 어디에도 값이 없다.
        let shown = format!("{} {} {}", out[0].rule, out[0].file, out[0].place);
        assert!(!shown.contains(&ip()), "{shown}");
    }

    #[test]
    fn the_org_address_on_github_is_not_a_workspace_folder() {
        assert!(names("https://github.com/ESTsecurity/remedy").is_empty());
        let org = ["EST", "security"].concat();
        let windows = format!("D:{BS}{org}{BS}gitlab");
        assert_eq!(names(&windows), vec!["개발 PC 의 작업 폴더"]);
        // WSL 에서 본 같은 자리는 두 규칙에 걸린다.
        let wsl = format!("/mnt/{}/{org}/x", "d");
        assert_eq!(
            names(&wsl),
            vec!["개발 PC 의 작업 폴더", "WSL 에서 본 Windows 드라이브"]
        );
    }

    #[test]
    fn placeholder_profiles_pass_and_a_real_name_does_not() {
        for p in [
            "Public",
            "Default",
            "All Users",
            "%USERNAME%",
            "<user>",
            "$env:USERNAME",
        ] {
            let line = format!("C:{BS}Users{BS}{p}{BS}x");
            assert!(names(&line).is_empty(), "{line}");
        }
        // 시험 자료의 흔한 이름은 대소문자와 상관없이 지나간다.
        for p in TEST_NAMES.iter().chain(&["Test", "Analyst"]) {
            let line = format!("C:{BS}Users{BS}{p}{BS}AppData");
            assert!(names(&line).is_empty(), "{line}");
        }
        // 목록에 없는 이름은 걸린다 — 흔한 가상 이름이라도 목록에 없으면 사람이 본다.
        let line = format!("C:{BS}Users{BS}{}{BS}AppData", "hgildong");
        assert_eq!(names(&line), vec!["실사용자 Windows 프로필"]);
    }

    #[test]
    fn a_linux_home_with_a_name_is_found() {
        let line = format!("/{}/{}/.bashrc", "home", "hgildong");
        assert_eq!(names(&line), vec!["실사용자 /home"]);
        let line = format!("/{}/{}/.bashrc", "home", "analyst");
        assert!(names(&line).is_empty(), "{line}");
    }

    #[test]
    fn local_values_ignore_case_and_separators() {
        let local = vec![norm(&["E:", "/", "Sam", "ples"].concat())];
        // JSON 이 역슬래시를 두 번 적은 꼴로도 잡힌다.
        let line = format!("\"e:{BS}{BS}samples{BS}{BS}x\"");
        let mut out = Vec::new();
        scan_text(&rules(), &local, "f", "f", &line, &mut out);
        let got: Vec<&str> = out.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(got, vec!["로컬 값 1번"]);
    }

    #[test]
    fn a_compressed_file_is_read_after_unpacking() {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(format!("a\nb {}\n", ip()).as_bytes())
            .expect("압축");
        let packed = e.finish().expect("압축 끝");
        // 텍스트로 읽으면 아무것도 안 걸린다 — 그래서 풀어서 본다.
        let mut raw = Vec::new();
        let as_text = String::from_utf8_lossy(&packed);
        scan_text(&rules(), &[], "x.json.gz", "x.json.gz", &as_text, &mut raw);
        assert!(raw.is_empty(), "{raw:?}");
        let mut out = Vec::new();
        for (label, t) in texts("x.json.gz", &packed).expect("풀린다") {
            scan_text(&rules(), &[], "x.json.gz", &label, &t, &mut out);
        }
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].place, "x.json.gz (풀어서):2");
    }

    #[test]
    fn a_format_we_cannot_open_is_unscanned_not_clean() {
        assert!(texts("runs/a.zip", b"PK").is_err());
        assert!(texts("runs/A.ZIP", b"PK").is_err());
        assert!(texts("x.json.gz", b"not gzip").is_err());
    }

    #[test]
    fn the_allow_list_takes_folders_and_single_files() {
        let a = Allow::parse("crates/\n# 주석\nCargo.toml   # 뿌리\n\n");
        assert!(a.allows("crates/remedy-cli/src/main.rs"));
        assert!(a.allows("Cargo.toml"));
        assert!(!a.allows("Cargo.toml.bak"));
        assert!(!a.allows("cratesx/a.rs"));
        assert!(
            !a.allows("notes.md"),
            "뿌리에 새로 생긴 파일은 들어가지 못한다"
        );
        let tracked = vec!["crates/a.rs".to_string()];
        assert_eq!(a.unused(&tracked), vec!["Cargo.toml".to_string()]);
    }

    #[test]
    fn the_real_allow_list_keeps_local_files_out() {
        let a = Allow::parse(include_str!("../public-paths.txt"));
        let local_doc = ["claude", "docs/", "a.md"].concat();
        assert!(!a.allows(&local_doc));
        assert!(!a.allows(".gitlab-ci.yml"));
        assert!(!a.allows(".cargo/host.yml"));
        assert!(!a.allows(LOCAL));
        assert!(a.allows("crates/remedy-cli/src/main.rs"));
        assert!(a.allows(ALLOW), "넣는 목록 자신도 공개된다");
        // 빠지면 안 되는 쪽도 잠근다 — 하네스가 값을 못 찾으면 이 견본을 가리키는데,
        // 목록 밖으로 빠진 파일은 어떤 검사도 실패로 세지 않는다(2026-11-01 에 그렇게
        // 셋이 조용히 빠졌다).
        for name in ["host", "windows_lab", "linux_lab"] {
            let sample = format!(".cargo/{name}.example.yml");
            assert!(a.allows(&sample), "{sample} 가 공개 트리에 들어가야 한다");
        }
    }

    #[test]
    fn a_local_doc_reference_is_found_but_the_folder_name_alone_is_not() {
        let dir = ["claude", "docs"].concat();
        assert!(names(&format!("/{dir}/")).is_empty(), "무시 목록의 줄");
        assert!(names(&format!("작업 문서는 {dir}/ 에 둔다")).is_empty());
        assert_eq!(
            names(&format!("// {dir}/설계-01.md §3")),
            vec!["로컬 전용 문서 참조"]
        );
    }

    fn finding(rule: &str, file: &str) -> Finding {
        Finding {
            rule: rule.to_string(),
            file: file.to_string(),
            place: format!("{file}:1"),
            count: 1,
        }
    }

    #[test]
    fn an_exception_passes_only_the_named_rule_in_the_named_place() {
        let except = vec![Except {
            rule: "사설 주소 192.168".to_string(),
            prefix: "testbed/ai-exam/threats/".to_string(),
        }];
        let mut scan = Scan {
            findings: vec![
                // 예외에 드는 것
                finding(
                    "사설 주소 192.168",
                    "testbed/ai-exam/threats/x/infected/x.json",
                ),
                // 같은 자리인데 **다른 규칙** — 넘기지 않는다
                finding(
                    "실사용자 Windows 프로필",
                    "testbed/ai-exam/threats/x/THREAT.md",
                ),
                // 같은 규칙인데 **다른 자리** — 넘기지 않는다
                finding("사설 주소 192.168", "crates/remedy-cli/src/main.rs"),
            ],
            ..Scan::default()
        };
        apply_except(&mut scan, &except);
        assert_eq!(scan.excepted, 1);
        let left: Vec<&str> = scan.findings.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(left, vec!["실사용자 Windows 프로필", "사설 주소 192.168"]);
    }

    #[test]
    fn the_real_exception_list_parses_and_names_live_rules() {
        // **예외가 규칙 이름을 잘못 적으면 조용히 아무것도 넘기지 않는다** —
        // 그러면 게이트는 빨간데 목록은 맞아 보인다. 이름이 실제 규칙에 있는지 본다.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("저장소 뿌리");
        let except = load_except(root).expect("예외 목록을 읽어야 한다");
        assert!(!except.is_empty(), "{EXCEPT} 가 비어 있다");
        let live: Vec<&str> = rules().iter().map(|r| r.name).collect();
        for e in &except {
            assert!(
                live.contains(&e.rule.as_str()),
                "없는 규칙 이름: {}",
                e.rule
            );
            assert!(root.join(&e.prefix).exists(), "없는 경로: {}", e.prefix);
        }
    }

    #[test]
    fn a_long_quote_has_the_warning_shape() {
        let q = long_quote();
        assert!(q.is_match("그때 들은 말 \"이것은 꼭 이렇게 해야 한다고 여러 번 말했다\""));
        assert!(!q.is_match("오류 \"짧다\""));
    }

    #[test]
    fn this_file_does_not_trip_its_own_rules() {
        let mut out = Vec::new();
        let me = include_str!("leaks.rs");
        scan_text(&rules(), &[], "leaks.rs", "leaks.rs", me, &mut out);
        assert!(out.is_empty(), "{out:?}");
    }
}
