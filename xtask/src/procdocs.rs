//! 절차 문서가 도구와 맞는가 — 경로 · 링크 · 명령 인자 · 지금 값(2026-11-22 · 목표 remedy_하루30건 기준 5 (가)).
//!
//! # 무엇을 막는 검사인가
//!
//! 처음 보는 사람은 절차 문서(아래 [`DOCS`])를 보고 친다. 도구를 바꾼 커밋이 그 문서를 함께 고치지 않으면 문서가 없는
//! 스크립트 · 없는 인자 · 지난 값을 가리킨다. 2026-11-21 조사에서 도구를 바꾼 커밋 61 가운데 26 이 절차 문서를 함께
//! 고치지 않았고, 그 문서를 여는 검사는 0 이었다.
//!
//! # 보는 것
//!
//! 1. **경로** — 인라인 코드와 울타리 코드의 낱말 가운데 저장소 뿌리 이름(`ci/` · `docs/` · …)으로 시작하는 것, 그리고
//!    확장자가 붙은 맨 이름(`RELEASE.md` 꼴)이 추적하는 파일 · 폴더인가. `<…>` · `{…}` 자리 표시는 그 앞의 폴더까지,
//!    `*` 는 글로브로 본다. 커밋하지 않는 자리([`LOCAL`] — `.cargo/host.yml` 등 · 결과 폴더)는 뺀다.
//! 2. **링크** — 저장소 안 `[글](자리#닻)` 의 파일과 닻(제목에서 지은 주소 · `<a id>`).
//! 3. **명령** — `bash ci/batch.sh <명령>` · `cargo xtask <작업>` · `<스크립트.sh> --<인자>` · `<스크립트.ps1> -<인자>`.
//! 4. **지금 값** — [`values`] 의 표. 절차 문서에 새 지금 값을 적으면 그 표에 한 줄을 더한다. 값의 자리가 문서에서
//!    사라져도 실패다 — 검사가 조용히 빈 일이 되지 않게.
//!
//! # 보지 않는 것
//!
//! 표지 `<!-- 기록: … -->` 가 선 절 — 그 표지 앞의 마지막 제목이 연 절이 끝날 때까지(같은 급이나 윗급 제목 전까지) 경로 ·
//! 명령 · 값을 보지 않는다. 날짜를 단 그날의 사진이다. 링크는 기록 절에서도 본다.

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// 보는 문서 — 절차 문서 여섯과 README.
const DOCS: &[&str] = &[
    "AGENTS.md",
    "README.md",
    "docs/긴급-대응.md",
    "docs/개발-안내.md",
    "docs/이슈-처리.md",
    "docs/remedy-전체-그림.md",
    "testbed/harness/README.md",
];

/// 경로로 읽는 첫 이름 — 저장소 뿌리의 폴더.
const ROOTS: &[&str] = &[
    ".cargo/", ".github/", "ci/", "corpus/", "crates/", "docs/", "plugins/", "testbed/", "xtask/",
];

/// 커밋하지 않는 자리 — 문서가 가리켜도 저장소에 없는 것이 맞다(`AGENTS.md` *운영 정보는 저장소에 두지 않는다*). 자격 증명의
/// 자리는 공개 트리에 이름을 적지 않는다 — 절차 문서도 그 이름을 쓰지 않는다.
const LOCAL: &[&str] = &[
    ".cargo/host.yml",
    ".cargo/windows_lab.yml",
    ".cargo/linux_lab.yml",
    ".cargo/leaks.yml",
    "testbed/harness/results/",
];

/// [`LOCAL`] 의 맨 이름.
const LOCAL_NAMES: &[&str] = &["host.yml", "windows_lab.yml", "linux_lab.yml", "leaks.yml"];

/// 맨 이름으로도 보는 확장자 — 저장소 어딘가에 그 이름의 파일이 있어야 한다.
const NAME_EXT: &[&str] = &[".md", ".sh", ".ps1", ".py", ".rs", ".toml", ".yml", ".yaml"];

/// PowerShell 이 모든 스크립트에 주는 인자 — 스크립트의 `param` 에 없다.
const COMMON_PARAMS: &[&str] = &[
    "verbose",
    "debug",
    "erroraction",
    "warningaction",
    "informationaction",
    "errorvariable",
    "warningvariable",
    "informationvariable",
    "outvariable",
    "outbuffer",
    "pipelinevariable",
    "whatif",
    "confirm",
];

/// 명령이 끝나는 낱말 — 그 뒤의 인자는 다음 명령의 것이다.
const STOPS: &[&str] = &["|", "||", "&&", ";", ">", ">>", "2>", "2>&1", "*>"];

/// 저장소의 파일을 읽는 길 — 실행은 디스크, 시험은 메모리.
pub type Reader = Box<dyn Fn(&str) -> Option<String>>;

/// 저장소 — 추적하는 파일과 그 폴더 · 맨 이름, 그리고 파일을 읽는 길.
pub struct Repo {
    files: HashSet<String>,
    dirs: HashSet<String>,
    names: HashMap<String, Vec<String>>,
    read: Reader,
}

impl Repo {
    pub fn new(files: Vec<String>, read: Reader) -> Self {
        let mut dirs = HashSet::new();
        let mut names: HashMap<String, Vec<String>> = HashMap::new();
        for f in &files {
            let mut i = 0;
            while let Some(j) = f[i..].find('/') {
                i += j + 1;
                dirs.insert(f[..i].to_string());
            }
            let base = f.rsplit('/').next().unwrap_or(f).to_string();
            names.entry(base).or_default().push(f.clone());
        }
        Repo {
            files: files.into_iter().collect(),
            dirs,
            names,
            read,
        }
    }

    fn has(&self, p: &str) -> bool {
        if p.ends_with('/') {
            self.dirs.contains(p)
        } else {
            self.files.contains(p) || self.dirs.contains(&format!("{p}/"))
        }
    }

    fn glob(&self, pat: &str) -> bool {
        let pat = pat.trim_end_matches('/');
        self.files.iter().any(|f| glob_match(pat, f))
            || self
                .dirs
                .iter()
                .any(|d| glob_match(pat, d.trim_end_matches('/')))
    }

    fn text(&self, p: &str) -> Option<String> {
        (self.read)(p)
    }

    /// 맨 이름이 가리키는 파일 하나 — 같은 이름이 둘 넘으면 고르지 않는다.
    fn by_name(&self, name: &str) -> Option<&str> {
        match self.names.get(name).map(Vec::as_slice) {
            Some([one]) => Some(one.as_str()),
            _ => None,
        }
    }
}

pub fn run(root: &Path) -> Result<(), String> {
    let files = crate::gitbase::tracked(root, &[])?;
    if files.is_empty() {
        return Err("추적하는 파일이 하나도 없다 — `git ls-files` 가 빈 목록을 냈다".into());
    }
    let base = root.to_path_buf();
    let repo = Repo::new(
        files,
        Box::new(move |p| std::fs::read_to_string(base.join(p)).ok()),
    );
    let facts = Facts {
        snapshots: crate::snapshots::files(root).len(),
        ai_context_kb: crate::guide::LIMITS
            .iter()
            .find(|(n, _)| *n == "machine/AI-CONTEXT.md")
            .map(|(_, b)| b / 1024),
    };
    let mut seen = Seen::default();
    let mut hits = check(&repo, &facts, &mut seen);
    if hits.is_empty() {
        println!(
            "procdocs OK — 문서 {}개 · 경로 {}자리 · 링크 {}개 · 명령 {}개 · 지금 값 {}줄이 저장소와 맞는다",
            DOCS.len(),
            seen.paths,
            seen.links,
            seen.commands,
            seen.values
        );
        return Ok(());
    }
    hits.sort();
    Err(format!(
        "절차 문서가 저장소와 어긋난 자리 {}곳 — 도구를 바꿨으면 그 문서도 고친다(지금 값이면 \
         xtask/src/procdocs.rs 의 값 표 · 날짜를 단 옛 기록이면 그 절에 `<!-- 기록: … -->`)\n  {}",
        hits.len(),
        hits.join("\n  ")
    ))
}

/// 저장소 밖에서 오는 값(시험은 손으로 준다).
pub struct Facts {
    pub snapshots: usize,
    pub ai_context_kb: Option<usize>,
}

#[derive(Default)]
pub struct Seen {
    paths: usize,
    links: usize,
    commands: usize,
    values: usize,
}

pub fn check(repo: &Repo, facts: &Facts, seen: &mut Seen) -> Vec<String> {
    let mut hits = Vec::new();
    let batch = batch_words(repo);
    let tasks = xtask_tasks(repo);
    for doc in DOCS {
        let Some(text) = repo.text(doc) else {
            hits.push(format!(
                "{doc}: 읽지 못했다 — 이 검사가 보는 문서다(xtask/src/procdocs.rs 의 DOCS)"
            ));
            continue;
        };
        for l in lines(&text) {
            if !l.fence {
                for target in links(l.text) {
                    seen.links += 1;
                    if let Err(why) = link_ok(repo, doc, target) {
                        hits.push(format!("{doc}:{}: 링크 `{target}` — {why}", l.n));
                    }
                }
            }
            if l.record {
                continue;
            }
            for span in spans(&l) {
                let words: Vec<String> = span.split_whitespace().map(clean).collect();
                for w in &words {
                    match as_path(w) {
                        Some(Ref::Path(p)) => {
                            seen.paths += 1;
                            if !path_ok(repo, &p) {
                                hits.push(format!("{doc}:{}: `{p}` — 저장소에 없다", l.n));
                            }
                        }
                        Some(Ref::Name(n)) => {
                            seen.paths += 1;
                            if !repo.names.contains_key(&n) {
                                hits.push(format!(
                                    "{doc}:{}: `{n}` — 그 이름의 파일이 저장소에 없다",
                                    l.n
                                ));
                            }
                        }
                        None => {}
                    }
                }
                commands(
                    repo,
                    &batch,
                    &tasks,
                    &words,
                    &mut |why| {
                        hits.push(format!("{doc}:{}: {why}", l.n));
                    },
                    seen,
                );
            }
        }
    }
    values(repo, facts, &mut hits, seen);
    hits
}

// ── 줄 · 조각 ───────────────────────────────────────────────────────────────────────────────────

pub struct Line<'a> {
    pub n: usize,
    pub text: &'a str,
    /// 울타리 코드 안의 줄(이어 쓴 줄은 하나로 붙인 꼴은 [`spans`] 가 만든다).
    pub fence: bool,
    /// `<!-- 기록: … -->` 가 선 절 안.
    pub record: bool,
    pub joined: Option<String>,
}

fn heading_level(line: &str) -> Option<usize> {
    let hashes = line.chars().take_while(|&c| c == '#').count();
    if (1..=6).contains(&hashes) && line[hashes..].starts_with(' ') {
        Some(hashes)
    } else {
        None
    }
}

pub fn lines(text: &str) -> Vec<Line<'_>> {
    let mut out: Vec<Line<'_>> = Vec::new();
    let mut fence = false;
    let mut level = 0usize; // 지금 절의 제목 급(제목 앞이면 0)
    let mut record_level: Option<usize> = None;
    let mut carry: Option<(usize, String)> = None; // 울타리 안에서 이어 쓰는 줄
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let t = raw.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fence = !fence;
            carry = None;
            continue;
        }
        if !fence {
            if let Some(h) = heading_level(raw) {
                level = h;
                if record_level.is_some_and(|r| h <= r) {
                    record_level = None;
                }
            }
            // 표지는 그 줄에 홀로 선 것만 — 문장 안의 견본(`<!-- 기록: … -->` 를 적는다)은 표지가 아니다.
            if t.starts_with("<!-- 기록:") {
                record_level = Some(level.max(1));
            }
        }
        let record = record_level.is_some();
        if fence {
            // 이어 쓴 줄(bash 의 `\` · PowerShell 의 백틱)은 다음 줄과 붙여 한 명령으로 읽는다.
            let body = raw.trim_end();
            let cont = body.ends_with('\\') || body.ends_with('`');
            let piece = body.trim_end_matches(['\\', '`']).to_string();
            let joined = match carry.take() {
                Some((_, mut acc)) => {
                    acc.push(' ');
                    acc.push_str(piece.trim());
                    acc
                }
                None => piece,
            };
            if cont {
                carry = Some((n, joined));
                out.push(Line {
                    n,
                    text: raw,
                    fence,
                    record,
                    joined: None,
                });
            } else {
                out.push(Line {
                    n,
                    text: raw,
                    fence,
                    record,
                    joined: Some(joined),
                });
            }
        } else {
            out.push(Line {
                n,
                text: raw,
                fence,
                record,
                joined: None,
            });
        }
    }
    out
}

/// 낱말을 볼 조각 — 울타리 밖은 인라인 코드, 안은 이어 붙인 한 명령.
pub fn spans(l: &Line<'_>) -> Vec<String> {
    if l.fence {
        l.joined.clone().into_iter().collect()
    } else {
        crate::docs::backticked(l.text)
    }
}

/// 낱말의 겉 — 따옴표 · 괄호 · 끝의 문장 부호를 떼고, 역슬래시를 빗금으로.
pub fn clean(w: &str) -> String {
    let t =
        w.trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | ',' | ';'));
    let t = t.trim_end_matches(['.', ':', ',', ')']);
    t.replace('\\', "/")
}

pub enum Ref {
    Path(String),
    Name(String),
}

/// 낱말이 저장소 경로인가 — 뿌리 이름으로 시작하는 경로, 또는 확장자가 붙은 맨 이름.
pub fn as_path(w: &str) -> Option<Ref> {
    let mut t = w.trim_start_matches("./").to_string();
    // 줄 번호(`ci/batch.sh:441-442`)와 닻(`docs/x.md#y`)을 뗀다.
    if let Some(i) = t.find(':') {
        let after = &t[i + 1..];
        if after.is_empty() || after.starts_with(|c: char| c.is_ascii_digit()) {
            t.truncate(i);
        }
    }
    if let Some(i) = t.find('#') {
        t.truncate(i);
    }
    if t.is_empty() {
        return None;
    }
    if ROOTS.iter().any(|r| t.starts_with(r)) {
        return Some(Ref::Path(t));
    }
    // 맨 이름 — 확장자만의 낱말(`.ps1` 은 BOM …)은 이름이 아니다. 점으로 시작하는 이름(`.gitlab-ci.yml`)은 본다.
    let plain = t
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '.')
        && !t.contains([
            '/', '<', '>', '$', '%', '*', '{', '=', '…', '(', ')', '[', ']',
        ]);
    let stem = NAME_EXT
        .iter()
        .find(|e| t.ends_with(*e))
        .map(|e| t[..t.len() - e.len()].trim_start_matches('.'));
    if plain && stem.is_some_and(|s| !s.is_empty()) && !LOCAL_NAMES.contains(&t.as_str()) {
        return Some(Ref::Name(t));
    }
    None
}

pub fn path_ok(repo: &Repo, p: &str) -> bool {
    if LOCAL
        .iter()
        .any(|l| p == l.trim_end_matches('/') || (l.ends_with('/') && p.starts_with(l)))
    {
        return true;
    }
    // 지운 파일을 '전에는 이 파일로 했다' 고 적는 문장(fragments 가 다시 들어오는 것을 막는다) · 빌드 산출물(`…/target/…`).
    if crate::fragments::REMOVED.iter().any(|r| glob_match(r, p)) || p.contains("/target/") {
        return true;
    }
    // 자리 표시(`<룰>` · `{linux,host}` · `…` · 변수)는 그 앞의 폴더까지 본다.
    let p = match p.find(['<', '{', '…', '$', '%', '|']) {
        Some(i) => match p[..i].rfind('/') {
            Some(j) => &p[..=j],
            None => return true,
        },
        None => p,
    };
    if p.contains('*') {
        repo.glob(p)
    } else {
        repo.has(p)
    }
}

/// git pathspec 의 꼴 — `*` 는 빗금까지 넘는다(문서의 `'crates/*.rs'` 는 `git grep` 의 pathspec 이다).
pub fn glob_match(pat: &str, s: &str) -> bool {
    fn go(p: &[char], s: &[char]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some('*') => {
                let rest = &p[1..];
                (0..=s.len()).any(|i| go(rest, &s[i..]))
            }
            Some(&c) => s.first() == Some(&c) && go(&p[1..], &s[1..]),
        }
    }
    let p: Vec<char> = pat.chars().collect();
    let s: Vec<char> = s.chars().collect();
    go(&p, &s)
}

// ── 링크 ────────────────────────────────────────────────────────────────────────────────────────

/// 한 줄의 `[글](자리)` 의 자리 — 인라인 코드 안의 것은 견본이라 뺀다.
pub fn links(line: &str) -> Vec<&str> {
    let mut code = vec![false; line.len()];
    let mut inside = false;
    for (i, c) in line.char_indices() {
        if c == '`' {
            inside = !inside;
        }
        code[i..i + c.len_utf8()].fill(inside || c == '`');
    }
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = line[from..].find("](") {
        let at = from + i;
        let start = at + 2;
        let Some(j) = line[start..].find(')') else {
            break;
        };
        let target = line[start..start + j]
            .split_whitespace()
            .next()
            .unwrap_or("");
        if !code[at] && !target.is_empty() {
            out.push(target);
        }
        from = start + j + 1;
    }
    out
}

fn percent_decode(s: &str) -> String {
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn normalize(base_dir: &str, rel: &str) -> String {
    let mut parts: Vec<&str> = if rel.starts_with('/') {
        Vec::new()
    } else {
        base_dir.split('/').filter(|s| !s.is_empty()).collect()
    };
    for seg in rel.trim_start_matches('/').split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    if rel.ends_with('/') && !joined.is_empty() {
        format!("{joined}/")
    } else {
        joined
    }
}

/// GitHub 이 제목에서 짓는 주소 — 글자 · 숫자 · `-` · `_` 를 남기고, 빈칸은 `-`, 나머지는 뺀다.
pub fn slug(heading: &str) -> String {
    let mut s = String::new();
    for c in heading.trim().chars() {
        if c.is_alphanumeric() || c == '-' || c == '_' {
            s.extend(c.to_lowercase());
        } else if c == ' ' {
            s.push('-');
        }
    }
    s
}

pub fn anchors(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut count: HashMap<String, usize> = HashMap::new();
    for l in lines(text) {
        if l.fence {
            continue;
        }
        if let Some(h) = heading_level(l.text) {
            let base = slug(&l.text[h..]);
            let n = count.entry(base.clone()).or_insert(0);
            let id = if *n == 0 {
                base.clone()
            } else {
                format!("{base}-{n}")
            };
            *n += 1;
            out.insert(id);
        }
        for key in ["<a id=\"", "<a name=\""] {
            let mut rest = l.text;
            while let Some(i) = rest.find(key) {
                let after = &rest[i + key.len()..];
                if let Some(j) = after.find('"') {
                    out.insert(after[..j].to_lowercase());
                    rest = &after[j..];
                } else {
                    break;
                }
            }
        }
    }
    out
}

fn link_ok(repo: &Repo, doc: &str, target: &str) -> Result<(), String> {
    if target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("mailto:")
        || target.starts_with('<')
    {
        return Ok(());
    }
    let (path, anchor) = match target.split_once('#') {
        Some((p, a)) => (p, Some(a)),
        None => (target, None),
    };
    let dir = doc.rfind('/').map_or("", |i| &doc[..i]);
    let file = if path.is_empty() {
        doc.to_string()
    } else {
        normalize(dir, &percent_decode(path))
    };
    if !repo.has(&file) {
        return Err(format!("`{file}` 이 저장소에 없다"));
    }
    if let Some(a) = anchor {
        if a.is_empty() || !file.ends_with(".md") {
            return Ok(());
        }
        let want = percent_decode(a).to_lowercase();
        let Some(text) = repo.text(&file) else {
            return Err(format!("`{file}` 을 읽지 못했다"));
        };
        if !anchors(&text).contains(&want) {
            return Err(format!(
                "`{file}` 에 닻 `#{want}` 이 없다(제목을 바꿨으면 링크도)"
            ));
        }
    }
    Ok(())
}

// ── 명령 ────────────────────────────────────────────────────────────────────────────────────────

/// `ci/batch.sh` 의 명령 갈래(맨 끝 `case "${1:-}" in` 의 꼬리표)와 인자(`--rc` · `--local`).
pub fn batch_words(repo: &Repo) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(text) = repo.text("ci/batch.sh") else {
        return out;
    };
    let lines: Vec<&str> = text.lines().collect();
    if let Some(start) = lines
        .iter()
        .rposition(|l| l.trim_start().starts_with("case \"${1:-}\" in"))
    {
        for l in &lines[start + 1..] {
            let t = l.trim();
            if t.starts_with("esac") {
                break;
            }
            if let Some(i) = t.find(')') {
                for label in t[..i].split('|') {
                    let label = label.trim().trim_matches('"');
                    if !label.is_empty() && label != "*" {
                        out.insert(label.to_string());
                    }
                }
            }
        }
    }
    for l in &lines {
        if let Some(i) = l.find("\" = --") {
            let flag: String = l[i + 4..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if flag.len() > 2 {
                out.insert(flag);
            }
        }
    }
    out
}

/// `cargo xtask <작업>` 의 작업 — `xtask/src/main.rs` 의 `Some("…")` 갈래.
pub fn xtask_tasks(repo: &Repo) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(text) = repo.text("xtask/src/main.rs") else {
        return out;
    };
    let mut rest = text.as_str();
    while let Some(i) = rest.find("Some(\"") {
        let after = &rest[i + 6..];
        if let Some(j) = after.find('"') {
            out.insert(after[..j].to_string());
            rest = &after[j..];
        } else {
            break;
        }
    }
    out
}

fn placeholder(w: &str) -> bool {
    w.is_empty()
        || w.starts_with(['<', '[', '$', '%', '…', '-']) && !w.starts_with("--")
        || STOPS.contains(&w)
}

/// 스크립트 낱말이 가리키는 파일 — 경로면 그 파일, 맨 이름이면 하나뿐일 때.
fn script_of(repo: &Repo, w: &str) -> Option<String> {
    match as_path(w)? {
        Ref::Path(p) => repo.files.contains(&p).then_some(p),
        Ref::Name(n) => repo.by_name(&n).map(str::to_string),
    }
}

pub fn commands(
    repo: &Repo,
    batch: &HashSet<String>,
    tasks: &HashSet<String>,
    words: &[String],
    hit: &mut dyn FnMut(String),
    seen: &mut Seen,
) {
    // 셸 주석(`# …`) 뒤는 명령이 아니다.
    let end = words
        .iter()
        .position(|w| w.starts_with('#'))
        .unwrap_or(words.len());
    let words = &words[..end];
    // 명령의 낱말 — 영문 소문자 · 숫자 · `-` 만(문장 안의 `ci/batch.sh` 뒤에 오는 우리말 · 문장 부호는 인자가 아니다).
    let command_like = |a: &str| {
        !a.is_empty()
            && a.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    };
    for (i, w) in words.iter().enumerate() {
        if w.ends_with("ci/batch.sh") {
            if let Some(arg) = words.get(i + 1) {
                if !placeholder(arg) && command_like(arg) {
                    seen.commands += 1;
                    if !batch.contains(arg.as_str()) {
                        hit(format!(
                            "`bash ci/batch.sh {arg}` — 그 명령 · 인자가 ci/batch.sh 에 없다"
                        ));
                    }
                }
            }
            continue;
        }
        if w == "xtask" && i > 0 && words[i - 1] == "cargo" {
            if let Some(task) = words.get(i + 1) {
                if !placeholder(task) && !task.starts_with("--") && command_like(task) {
                    seen.commands += 1;
                    if !tasks.contains(task.as_str()) {
                        hit(format!(
                            "`cargo xtask {task}` — 그 작업이 xtask/src/main.rs 에 없다"
                        ));
                    }
                }
            }
            continue;
        }
        let sh = w.ends_with(".sh");
        let ps1 = w.ends_with(".ps1");
        if !(sh || ps1) {
            continue;
        }
        let Some(script) = script_of(repo, w) else {
            continue;
        };
        let Some(body) = repo.text(&script) else {
            continue;
        };
        let lower = body.to_lowercase();
        for a in &words[i + 1..] {
            if STOPS.contains(&a.as_str()) || a.ends_with(".sh") || a.ends_with(".ps1") {
                break;
            }
            if sh && a.starts_with("--") {
                let flag = a.split('=').next().unwrap_or(a);
                if flag.len() > 2
                    && flag[2..]
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-')
                {
                    seen.commands += 1;
                    if !body.contains(flag) {
                        hit(format!("`{script} {flag}` — 그 인자가 스크립트에 없다"));
                    }
                }
            } else if ps1 && a.starts_with('-') && !a.starts_with("--") {
                let name = &a[1..];
                if name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                    && name.chars().all(|c| c.is_ascii_alphanumeric())
                    && !COMMON_PARAMS.contains(&name.to_lowercase().as_str())
                {
                    seen.commands += 1;
                    if !lower.contains(&format!("${}", name.to_lowercase())) {
                        hit(format!(
                            "`{script} {a}` — 그 인자가 스크립트의 param 에 없다"
                        ));
                    }
                }
            }
        }
    }
}

// ── 지금 값 ─────────────────────────────────────────────────────────────────────────────────────

/// 우리말 수사(`열네` · `스물한`) 또는 숫자로 시작하는 수와 그 길이(바이트).
pub fn number_at(s: &str) -> Option<(usize, usize)> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if !digits.is_empty() {
        return digits.parse().ok().map(|v| (v, digits.len()));
    }
    let tens = [("서른", 30), ("스물", 20), ("스무", 20), ("열", 10)];
    let units = [
        ("하나", 1),
        ("한", 1),
        ("둘", 2),
        ("두", 2),
        ("셋", 3),
        ("세", 3),
        ("넷", 4),
        ("네", 4),
        ("다섯", 5),
        ("여섯", 6),
        ("일곱", 7),
        ("여덟", 8),
        ("아홉", 9),
    ];
    let mut v = 0;
    let mut used = 0;
    if let Some((t, n)) = tens.iter().find(|(t, _)| s.starts_with(t)) {
        v += n;
        used += t.len();
    }
    if let Some((u, n)) = units.iter().find(|(u, _)| s[used..].starts_with(u)) {
        v += n;
        used += u.len();
    }
    (used > 0).then_some((v, used))
}

/// 문서의 줄들(기록 절은 빼고)에서 `앞말` 다음의 수를 모두.
fn numbers_after(text: &str, before: &str, after: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for l in lines(text) {
        if l.record {
            continue;
        }
        let mut rest = l.text;
        while let Some(i) = rest.find(before) {
            let tail = rest[i + before.len()..].trim_start_matches(['*', ' ']);
            if let Some((v, used)) = number_at(tail) {
                if tail[used..]
                    .trim_start_matches(['*', ' '])
                    .starts_with(after)
                {
                    out.push((l.n, v));
                }
            }
            rest = &rest[i + before.len()..];
        }
    }
    out
}

/// 값 표의 한 줄 — 문서에서 찾은 값들이 저장소의 값과 같은가. 문서에서 하나도 못 찾으면 그것도 어긋남이다.
fn want(
    hits: &mut Vec<String>,
    seen: &mut Seen,
    doc: &str,
    what: &str,
    found: Vec<(usize, usize)>,
    truth: Option<usize>,
) {
    seen.values += 1;
    let Some(truth) = truth else {
        hits.push(format!("{doc}: {what} — 견줄 값을 저장소에서 읽지 못했다"));
        return;
    };
    if found.is_empty() {
        hits.push(format!(
            "{doc}: {what} — 문서에서 그 값의 자리를 찾지 못했다(문서를 고쳤으면 값 표도)"
        ));
    }
    for (n, v) in found {
        if v != truth {
            hits.push(format!("{doc}:{n}: {what} {v} — 지금은 {truth}"));
        }
    }
}

/// 엔진 0줄을 가리는 명령 — 그 뒤의 경로가 버전 검사가 보는 자리를 모두 담아야 한다.
const ENGINE_DIFF: &str = "git diff --stat origin/main...HEAD --";

fn values(repo: &Repo, facts: &Facts, hits: &mut Vec<String>, seen: &mut Seen) {
    let text = |p: &str| repo.text(p).unwrap_or_default();

    // 1 스냅샷 수 ↔ `snapshots` 가 보는 스냅샷.
    let doc = "docs/remedy-전체-그림.md";
    let found = numbers_after(&text(doc), "스냅샷", "개");
    want(hits, seen, doc, "스냅샷 수", found, Some(facts.snapshots));
    // 2 `xtask all` 의 검사 수 ↔ main.rs 의 `all` 사슬.
    let doc = "docs/개발-안내.md";
    let found = numbers_after(&text(doc), "저장소 검사", "가지");
    want(
        hits,
        seen,
        doc,
        "xtask all 의 검사 수",
        found,
        all_checks(&text("xtask/src/main.rs")),
    );
    // 3 AI-CONTEXT 의 상한 ↔ guide.rs.
    let doc = "docs/remedy-전체-그림.md";
    let found = lines(&text(doc))
        .into_iter()
        .filter(|l| !l.record && l.text.contains("AI-CONTEXT") && l.text.contains(" KB"))
        .filter_map(|l| kb_before(l.text).map(|v| (l.n, v)))
        .collect();
    want(
        hits,
        seen,
        doc,
        "AI-CONTEXT 의 상한(KB)",
        found,
        facts.ai_context_kb,
    );
    // 4 엔진 0줄을 가리는 경로 ↔ ci/version-check.sh 의 ENGINE_PATHS.
    let doc = "docs/긴급-대응.md";
    seen.values += 1;
    let engine = engine_paths(&text("ci/version-check.sh"));
    let mut spots = 0;
    for l in lines(&text(doc)) {
        for span in spans(&l) {
            if let Some(i) = span.find(ENGINE_DIFF) {
                spots += 1;
                let listed: HashSet<String> = span[i + ENGINE_DIFF.len()..]
                    .split_whitespace()
                    .map(|w| clean(w).trim_end_matches('/').to_string())
                    .collect();
                let missing: Vec<&String> =
                    engine.iter().filter(|p| !listed.contains(*p)).collect();
                if !missing.is_empty() {
                    hits.push(format!(
                        "{doc}:{}: 엔진 0줄을 가리는 경로에 {} 이 빠졌다 — 버전 검사(ci/version-check.sh 의 ENGINE_PATHS)가 보는 자리다",
                        l.n,
                        missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" · ")
                    ));
                }
            }
        }
    }
    if engine.is_empty() {
        hits.push("ci/version-check.sh: ENGINE_PATHS 를 읽지 못했다".into());
    } else if spots == 0 {
        hits.push(format!("{doc}: 엔진 0줄을 가리는 명령(`git diff --stat origin/main...HEAD -- …`)을 찾지 못했다"));
    }
    // 5 rc 묶음의 손으로 적은 단계 수 ↔ 두 스크립트.
    let doc = "testbed/harness/README.md";
    let readme = text(doc);
    let linux = count_lines(&text("testbed/harness/linux/rc-bundle.sh"), |l| {
        l.strip_prefix("step ")
            .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()))
    });
    let windows = count_lines(&text("testbed/harness/host/Invoke-RcBundle.ps1"), |l| {
        l.starts_with("Step '")
    });
    let found = stage_counts(&readme, "`linux/rc-bundle.sh`");
    want(hits, seen, doc, "리눅스 rc 묶음의 단계 수", found, linux);
    let found = stage_counts(&readme, "`host/Invoke-RcBundle.ps1`");
    want(hits, seen, doc, "Windows rc 묶음의 단계 수", found, windows);
    // 6 하네스 README 가 이름을 적지 않은 하네스 스크립트 0. 머리에 `# 하네스 표:` 줄을 단 하네스는 하루 한 번의 생성물
    // (`cargo xtask views --write`)이 README 의 표에 적는다 — 룰 PR 은 README 를 고치지 않는다(경로 제한 · `ci/rule-scope.sh`).
    // 그 줄이 있으면 이름이 적힌 것으로 센다(2026-11-22 — 전에는 새 룰 하네스를 더한 룰 PR 이 여기서 막혔다).
    seen.values += 1;
    for f in repo.files.iter().filter(|f| harness_script(f)) {
        let rel = &f["testbed/harness/".len()..];
        if !harness_named(&readme, rel, &text(f)) {
            hits.push(format!(
                "{doc}: `{rel}` — 하네스 README 가 이름을 적지 않은 하네스 스크립트다(표에 한 줄)"
            ));
        }
    }
}

fn kb_before(line: &str) -> Option<usize> {
    let i = line.find(" KB")?;
    let head = &line[..i];
    let digits: String = head
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.chars().rev().collect::<String>().parse().ok()
}

/// `Some("all") =>` 사슬의 검사 수 — 첫 호출 하나와 `.and_then(` 마다 하나.
pub fn all_checks(main_rs: &str) -> Option<usize> {
    let start = main_rs.find("Some(\"all\") =>")?;
    let rest = &main_rs[start..];
    let end = rest[1..]
        .find("\n        Some(\"")
        .map_or(rest.len(), |i| i + 1);
    Some(1 + rest[..end].matches(".and_then(").count())
}

/// `ENGINE_PATHS=(crates Cargo.toml …)` 의 경로.
pub fn engine_paths(sh: &str) -> Vec<String> {
    sh.lines()
        .find_map(|l| l.trim().strip_prefix("ENGINE_PATHS=("))
        .map(|r| {
            r.trim_end_matches(')')
                .split_whitespace()
                .map(|w| w.trim_end_matches('/').to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn count_lines(text: &str, pick: impl Fn(&str) -> bool) -> Option<usize> {
    let n = text.lines().filter(|l| pick(l)).count();
    (n > 0).then_some(n)
}

/// 하네스 README 에서 그 스크립트의 줄에 적힌 `N단계`.
fn stage_counts(readme: &str, row: &str) -> Vec<(usize, usize)> {
    lines(readme)
        .into_iter()
        .filter(|l| !l.record && l.text.starts_with("| ") && l.text.contains(row))
        .filter_map(|l| {
            let i = l.text.find("단계")?;
            let head = &l.text[..i];
            let digits: String = head
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect();
            let v = digits.chars().rev().collect::<String>().parse().ok()?;
            Some((l.n, v))
        })
        .collect()
}

/// 하네스 README 가 이름을 적어야 하는 스크립트 — testbed/harness 아래의 .sh · .ps1 · .py(결과 폴더 밖).
fn harness_script(f: &str) -> bool {
    f.starts_with("testbed/harness/")
        && !f.starts_with("testbed/harness/results/")
        && (f.ends_with(".sh") || f.ends_with(".ps1") || f.ends_with(".py"))
}

/// 하네스 README 가 그 스크립트를 적었는가 — 길 · 맨 이름 · 든 폴더, 또는 스크립트 머리 10줄의 `# 하네스 표:` 줄(하루 한 번의
/// 생성물이 README 표에 적는다).
fn harness_named(readme: &str, rel: &str, script: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    script
        .lines()
        .take(10)
        .any(|l| l.trim_start_matches('\u{feff}').starts_with("# 하네스 표:"))
        || readme.contains(rel)
        || readme.contains(base)
        || folder_named(readme, rel)
}

/// 그 스크립트가 든 폴더(`linux/rc/` 꼴 — 둘째 단부터)를 README 가 인라인 코드로 적었는가. 첫 단(`linux/`)은 모든 하네스의
/// 자리라 이름을 적은 것으로 세지 않는다.
fn folder_named(readme: &str, rel: &str) -> bool {
    let mut i = 0;
    let mut depth = 0;
    while let Some(j) = rel[i..].find('/') {
        i += j + 1;
        depth += 1;
        if depth >= 2 && readme.contains(&format!("`{}`", &rel[..i])) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(files: &[(&str, &str)]) -> Repo {
        let map: HashMap<String, String> = files
            .iter()
            .map(|(p, t)| (p.to_string(), t.to_string()))
            .collect();
        let list = files.iter().map(|(p, _)| p.to_string()).collect();
        Repo::new(list, Box::new(move |p| map.get(p).cloned()))
    }

    const BATCH: &str = "case \"${1:-}\" in\n    status) cmd_status ;;\n    --rc) cmd_batch 1 ;;\n    \"\") cmd_batch 0 ;;\nesac\n    if [ \"$a\" = --local ]; then MODE=local; fi\n";
    const MAIN: &str = "        Some(\"leaks\") => leaks::run(&root),\n        Some(\"all\") => a::run(&root)\n            .and_then(|()| b::run(&root)),\n        Some(\"views\") => v(),\n";

    fn hits(files: &[(&str, &str)], doc: &str) -> Vec<String> {
        let mut all: Vec<(&str, &str)> = files.to_vec();
        all.push(("docs/긴급-대응.md", doc));
        let r = repo(&all);
        let mut seen = Seen::default();
        let mut out = Vec::new();
        let batch = batch_words(&r);
        let tasks = xtask_tasks(&r);
        for l in lines(doc) {
            if !l.fence {
                for t in links(l.text) {
                    if let Err(e) = link_ok(&r, "docs/긴급-대응.md", t) {
                        out.push(format!("{}: link {e}", l.n));
                    }
                }
            }
            if l.record {
                continue;
            }
            for span in spans(&l) {
                let words: Vec<String> = span.split_whitespace().map(clean).collect();
                for w in &words {
                    match as_path(w) {
                        Some(Ref::Path(p)) if !path_ok(&r, &p) => {
                            out.push(format!("{}: path {p}", l.n))
                        }
                        Some(Ref::Name(n)) if !r.names.contains_key(&n) => {
                            out.push(format!("{}: name {n}", l.n))
                        }
                        _ => {}
                    }
                }
                commands(
                    &r,
                    &batch,
                    &tasks,
                    &words,
                    &mut |w| out.push(format!("{}: cmd {w}", l.n)),
                    &mut seen,
                );
            }
        }
        out
    }

    #[test]
    fn a_harness_with_a_table_line_counts_as_named() {
        // 머리의 `# 하네스 표:` 줄은 하루 한 번의 생성물이 README 표에 옮긴다 — 룰 PR 이 README 를 고치지 않아도 지난다.
        let readme = "| `linux/nginx-verify.sh` | 무엇 |\n";
        assert!(harness_named(
            readme,
            "linux/nginx-verify.sh",
            "#!/bin/bash\n"
        ));
        assert!(!harness_named(
            readme,
            "linux/new-verify.sh",
            "#!/bin/bash\n# 룰: x — 시험\n"
        ));
        assert!(harness_named(
            readme,
            "linux/new-verify.sh",
            "#!/bin/bash\n# 하네스 표: WSL | 역할\n"
        ));
        assert!(harness_named(
            readme,
            "host/New.ps1",
            "\u{feff}#Requires -Version 5.1\r\n# 하네스 표: 랩 | 역할\r\n"
        ));
    }

    #[test]
    fn a_renamed_tool_is_caught() {
        // 도구 이름을 바꾸고 문서를 그대로 두면 그 자리를 짚는다 — 기준 5 (가)의 음성 시험.
        let files = [("ci/new-name.sh", "echo")];
        let found = hits(&files, "돌린다 — `bash ci/old-name.sh` 로.\n");
        assert_eq!(found, vec!["1: path ci/old-name.sh"]);
        assert!(hits(&files, "`bash ci/new-name.sh`\n").is_empty());
    }

    #[test]
    fn placeholders_globs_local_files_and_line_numbers() {
        let files = [
            ("testbed/harness/linux/nginx-verify.sh", ""),
            ("plugins/a/plugin.yaml", ""),
            (".cargo/host.example.yml", ""),
            ("ci/batch.sh", BATCH),
        ];
        let doc = "`testbed/harness/linux/<룰>-verify.sh` · `testbed/harness/{linux,host}/<룰>-verify.*` · \
                   `plugins/*/plugin.yaml` · `.cargo/*.example.yml` · `.cargo/host.yml` · \
                   `testbed/harness/results/rc-inputs/` · `ci/batch.sh:441-442` · `plugins/a/plugin.yaml#x`\n";
        assert!(hits(&files, doc).is_empty(), "{:?}", hits(&files, doc));
        assert_eq!(
            hits(&files, "`plugins/*/missing.yaml`\n"),
            vec!["1: path plugins/*/missing.yaml"]
        );
        assert_eq!(
            hits(&files, "`docs/없는/<x>.md`\n"),
            vec!["1: path docs/없는/<x>.md"]
        );
    }

    #[test]
    fn bare_names_must_exist_somewhere() {
        let files = [("plugins/a/RELEASE.md", "")];
        // 커밋하지 않는 이름 · 확장자만의 낱말은 보지 않는다.
        assert!(hits(&files, "`RELEASE.md` · `host.yml` · `.ps1` 은 BOM\n").is_empty());
        assert_eq!(
            hits(&files, "`시연-대본.md` · `.gitlab-ci.yml`\n"),
            vec!["1: name 시연-대본.md", "1: name .gitlab-ci.yml"]
        );
    }

    #[test]
    fn links_need_the_file_and_the_heading() {
        let target = "# 제목\n\n## 처음 하는 사람 — 한 장\n\n## 처음 하는 사람 — 한 장\n<a id=\"java4shell\"></a>\n";
        let files = [("docs/개발-안내.md", target)];
        let ok = "[a](개발-안내.md#처음-하는-사람--한-장) [b](개발-안내.md#처음-하는-사람--한-장-1) [c](개발-안내.md#java4shell) [d](https://x/y) [e](#제목)\n";
        // 끝의 닻은 이 문서(시험 문서)의 제목이라 없다 — 그 하나만 걸린다.
        let found = hits(&files, ok);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("#제목"), "{found:?}");
        let bad = "[a](없는.md) [b](개발-안내.md#다른-제목) `[c](없는.md)`\n";
        let found = hits(&files, bad);
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn record_sections_skip_paths_but_not_links() {
        let doc = "## 지금\n\n`ci/있다.sh`\n\n## 옛 기록\n<!-- 기록: 2026-09-05 의 사진 -->\n`.gitlab-ci.yml` · `ci/없다.sh` [x](없는.md)\n\n### 그 안의 절\n`ci/없다2.sh`\n\n## 다음\n`ci/없다3.sh`\n";
        let files = [("ci/있다.sh", "")];
        let mut found = hits(&files, doc);
        found.sort();
        assert_eq!(
            found,
            vec![
                "13: path ci/없다3.sh",
                "7: link `docs/없는.md` 이 저장소에 없다"
            ],
            "{found:?}"
        );
        // 문장 안에 표지의 꼴을 적은 줄은 표지가 아니다 — 그 뒤도 본다.
        let doc =
            "## 규칙\n옛 절은 `<!-- 기록: YYYY-MM-DD 의 사진 -->` 표지로 뺀다.\n`ci/없다.sh`\n";
        assert_eq!(hits(&files, doc), vec!["3: path ci/없다.sh"]);
    }

    #[test]
    fn batch_and_xtask_commands() {
        let files = [("ci/batch.sh", BATCH), ("xtask/src/main.rs", MAIN)];
        let doc = "```bash\nbash ci/batch.sh status\nbash ci/batch.sh --rc\nbash ci/batch.sh --local\nbash ci/batch.sh            # 묶어 낸다 — 시험판은 --rc\nbash ci/batch.sh approve <태그>\ncargo xtask leaks\ncargo xtask views --write\ncargo xtask nosuch\n```\n\n```text\n출시(`bash\n       ci/batch.sh` — 필수 점검)\n```\n";
        let found = hits(&files, doc);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found.iter().any(|h| h.contains("ci/batch.sh approve")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|h| h.contains("cargo xtask nosuch")),
            "{found:?}"
        );
    }

    #[test]
    fn script_arguments_must_be_in_the_script() {
        let sh = "case \"$1\" in --bin) B=$2 ;; --out) O=$2 ;; esac\n";
        let ps1 = "param([string] $Package, [switch] $Runner)\n";
        let files = [
            ("testbed/harness/linux/x-verify.sh", sh),
            ("testbed/harness/host/Invoke-X.ps1", ps1),
        ];
        let doc = "```bash\nbash testbed/harness/linux/x-verify.sh --bin a \\\n    --out b --gone c\n```\n\n`Invoke-X.ps1 -Runner -Package p -Verbose -Missing`\n";
        let found = hits(&files, doc);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().any(|h| h.contains("--gone")), "{found:?}");
        assert!(found.iter().any(|h| h.contains("-Missing")), "{found:?}");
    }

    #[test]
    fn native_numbers() {
        for (s, v) in [
            ("열네 가지", 14),
            ("열다섯", 15),
            ("스물한", 21),
            ("13개", 13),
            ("일곱", 7),
            ("열", 10),
        ] {
            assert_eq!(number_at(s).map(|x| x.0), Some(v), "{s}");
        }
        assert_eq!(number_at("검사"), None);
    }

    #[test]
    fn current_values_are_compared() {
        assert_eq!(all_checks(MAIN), Some(2));
        assert_eq!(
            engine_paths("ENGINE_PATHS=(crates Cargo.toml .cargo/config.toml)\n"),
            vec!["crates", "Cargo.toml", ".cargo/config.toml"]
        );
        assert_eq!(
            numbers_after(
                "| `snapshots` | 스냅샷 **48개**가 맞는가 |\n",
                "스냅샷",
                "개"
            ),
            vec![(1, 48)]
        );
        assert_eq!(
            numbers_after("저장소 검사 열네 가지\n", "저장소 검사", "가지"),
            vec![(1, 14)]
        );
        assert_eq!(kb_before("AI-CONTEXT.md<br/>8 KB · 생성물"), Some(8));
        // 기록 절의 값은 견주지 않는다.
        let dated =
            "## 그날\n<!-- 기록: 2026-10-26 의 사진 -->\n스냅샷 48개\n## 지금\n스냅샷 49개\n";
        assert_eq!(numbers_after(dated, "스냅샷", "개"), vec![(5, 49)]);
    }

    #[test]
    fn slugs_follow_github() {
        assert_eq!(slug(" 처음 하는 사람 — 한 장"), "처음-하는-사람--한-장");
        assert_eq!(slug(" 2 · 3차"), "2--3차");
        assert_eq!(slug(" `bash ci/batch.sh` 의 길"), "bash-cibatchsh-의-길");
    }

    #[test]
    fn glob_follows_git_pathspec() {
        assert!(glob_match("plugins/*/plugin.yaml", "plugins/a/plugin.yaml"));
        assert!(glob_match("crates/*.rs", "crates/remedy-cli/src/main.rs"));
        assert!(!glob_match("plugins/*/plugin.yaml", "plugins/a/plugin.yml"));
    }

    #[test]
    fn removed_files_and_build_outputs_are_not_missing() {
        let files = [("plugins/a/plugin.yaml", "")];
        let doc = "전에는 `plugins/RULES-VERSION` · `plugins/versions.lock.json` 으로 했다 · `testbed/fixtures/x/target/release/x.exe`\n";
        assert!(hits(&files, doc).is_empty(), "{:?}", hits(&files, doc));
    }
}
