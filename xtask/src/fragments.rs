//! 업데이트 내역 조각 — `docs/changes/<이름>.md` (2026-11-21 · 목표 remedy_하루30건_대응체계 차례 2).
//!
//! 룰 PR 은 업데이트 내역 파일(`docs/업데이트-내역.md`)을 고치지 않고 **조각 하나를 더한다**. 셋이 같은 main 에서 함께
//! 지으면 그 파일 맨 위 칸에서 늘 부딪혔기 때문이다. 출시 때 배포 잡이 *지금 Latest 의 트리에 없고 이 태그의 트리에
//! 있는 조각* 을 모아 릴리스 본문 2절을 짓고(`cargo xtask changes`), 업데이트 내역 파일은 하루 한 번
//! `cargo xtask views --write` 가 공개한 출시마다 같은 함수로 지어 갈아 끼운다. 어느 출시에 실리는지를 git 이
//! 정하므로 출시 뒤 조각을 지우지 않아도 되고, 버린 묶음의 조각은 다음 묶음에 저절로 실린다.
//!
//! 조각의 꼴:
//!
//! ```text
//! ---
//! section: rules            # rules · 프로그램 · 그 밖
//! rules: [php-2026-11-check-linux, php-2026-11-check-windows]
//! ---
//! * **바뀐 것** (Linux)\
//!   설명 …
//! ```
//!
//! - `rules` 는 `section: rules` 일 때만 — 이 조각이 말하는 룰(매니페스트의 `id`). 데이터 룰은 그 기준을 쓰는 위협
//!   룰과 함께 적는다. 한 조각의 위협 룰은 한 위협(README 위협 표의 한 줄)이다.
//! - 본문은 업데이트 내역 머리 주석의 꼴이다(합쇼체 · `* **바뀐 것** (OS)\` 와 두 칸 들인 설명 · 알아 둘 점은
//!   `<details>`). `#` 로 여는 제목 줄은 쓰지 않는다 — 모으는 쪽이 짓는다: 위협 소제목은 그 줄 이름에서 끝의
//!   ' (…)' 한 덩이를 뺀 것이고, 차례는 위협 표의 차례 → 프로그램 → 그 밖이다. 같은 위협의 조각 여럿은 파일
//!   이름순으로 한 소제목에 모인다.
//! - 파일 이름은 겹치지 않게 — 룰 하나면 `<룰 id>-<새 버전>.md`, 그 밖은 `<주제>-<날>.md`.
//!
//! `cargo xtask fragments [--base <ref>]` 가 보는 것(`all` 에 들어 있다):
//! - 조각마다 꼴 — 머리 칸 · 있는 룰인가 · 한 조각의 룰은 한 위협 · 본문의 제목 줄 · 상대 링크 · `<details>` 짝 ·
//!   코드 블록 짝 · `{{`
//! - 바탕(`crate::gitbase`)보다 `version` 이 바뀐 룰(새 룰 포함)마다 **바탕 뒤에 더한 조각**이 그 룰을 적었는가
//! - 지운 파일이 되살아나지 않았는가 — 룰 버전 파일 · 잠금 · 룰 폴더의 개발 키 서명(`MANIFEST` · `MANIFEST.minisig`)

use crate::gitbase;
use crate::threats;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) const DIR: &str = "docs/changes";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Section {
    Rules,
    Program,
    Other,
}

#[derive(Debug, Clone)]
pub(crate) struct Fragment {
    pub path: String,
    pub section: Section,
    pub rules: Vec<String>,
    pub body: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    section: String,
    #[serde(default)]
    rules: Vec<String>,
}

/// 조각 파일인가 — `docs/changes/` 바로 아래의 `.md`(그 폴더의 안내 `README.md` 는 빼고).
pub(crate) fn is_fragment(path: &str) -> bool {
    let Some(name) = path.strip_prefix(&format!("{DIR}/")) else {
        return false;
    };
    !name.contains('/') && name.ends_with(".md") && name != "README.md"
}

/// 조각 하나를 읽는다 — 머리(`---` 사이의 YAML)와 본문.
pub(crate) fn parse(path: &str, text: &str) -> Result<Fragment, String> {
    let text = text.trim_start_matches('\u{feff}').replace("\r\n", "\n");
    let rest = text.strip_prefix("---\n").ok_or_else(|| {
        format!("{path}: 첫 줄이 '---' 가 아니다 — 머리(section · rules)를 먼저 쓴다")
    })?;
    let end = rest
        .find("\n---\n")
        .or_else(|| rest.ends_with("\n---").then(|| rest.len() - 4))
        .ok_or_else(|| format!("{path}: 머리를 닫는 '---' 가 없다"))?;
    let head: Head =
        serde_yaml_ng::from_str(&rest[..end]).map_err(|e| format!("{path}: 머리 — {e}"))?;
    let body = rest[(end + 4).min(rest.len())..].trim().to_string();
    let section = match head.section.as_str() {
        "rules" => Section::Rules,
        "프로그램" => Section::Program,
        "그 밖" => Section::Other,
        other => {
            return Err(format!(
                "{path}: section '{other}' — rules · 프로그램 · 그 밖 가운데 하나다"
            ))
        }
    };
    if section == Section::Rules && head.rules.is_empty() {
        return Err(format!("{path}: section 이 rules 인데 rules 가 비었다"));
    }
    // 한 줄 꼴만 — 공개 걸음(ci/publish-check.sh 의 보인 시간)이 셸로 그 줄을 읽는다. 블록 꼴(`rules:` 아래 `- id`)은 이
    // 파서가 받아도 거기서는 빈 값이 되어 60분 상한을 조용히 건너뛰었다(2026-11-21 반박 검토).
    if section == Section::Rules
        && !rest[..end].lines().any(|l| {
            let t = l.trim_end();
            t.starts_with("rules:") && t.contains('[') && t.ends_with(']')
        })
    {
        return Err(format!(
            "{path}: rules 는 한 줄로 적는다 — 'rules: [id, id]'(공개 걸음이 그 줄을 읽는다)"
        ));
    }
    if section != Section::Rules && !head.rules.is_empty() {
        return Err(format!("{path}: rules 는 section 이 rules 일 때만 쓴다"));
    }
    body_problems(&body).map_or(Ok(()), |why| Err(format!("{path}: {why}")))?;
    Ok(Fragment {
        path: path.to_string(),
        section,
        rules: head.rules,
        body,
    })
}

/// 본문의 꼴 — 릴리스 본문에 그대로 실리므로 `ci/release-notes.sh` 의 멈춤 장치와 같은 것을 PR 에서 먼저 본다.
fn body_problems(body: &str) -> Option<String> {
    if body.is_empty() {
        return Some("본문이 비었다".into());
    }
    if let Some(l) = body.lines().find(|l| l.trim_start().starts_with('#')) {
        return Some(format!(
            "본문에 제목 줄이 있다('{l}') — 위협 소제목 · 칸 머리는 모으는 쪽이 짓는다"
        ));
    }
    if body.contains("{{") {
        return Some("본문에 '{{' 가 있다 — 틀의 자리 표시로 읽힌다".into());
    }
    let fences = body
        .lines()
        .filter(|l| l.trim_start().starts_with("```"))
        .count();
    if fences % 2 != 0 {
        return Some(format!("닫히지 않은 코드 블록이 있다(``` 줄 {fences}개)"));
    }
    let open = body.matches("<details>").count();
    let close = body.matches("</details>").count();
    if open != close {
        return Some(format!(
            "<details> {open}개 · </details> {close}개 — 짝이 맞지 않는다"
        ));
    }
    let mut rel = BTreeSet::new();
    for (i, _) in body.match_indices("](") {
        let after = &body[i + 2..];
        if !(after.starts_with("https://")
            || after.starts_with("http://")
            || after.starts_with('#'))
        {
            rel.insert(after.split(')').next().unwrap_or("").to_string());
        }
    }
    if !rel.is_empty() {
        return Some(format!(
            "상대 링크는 릴리스 본문에서 열리지 않는다: {} — https:// 절대 주소로 적는다",
            rel.into_iter().collect::<Vec<_>>().join(" ")
        ));
    }
    None
}

/// 위협 소제목 — 줄 이름에서 끝의 ' (…)' 한 덩이를 뺀 것(업데이트 내역 머리 주석의 ①).
pub(crate) fn heading(row_name: &str) -> String {
    let t = row_name.trim_end();
    if t.ends_with(')') {
        if let Some(i) = t.rfind(" (") {
            return t[..i].to_string();
        }
    }
    t.to_string()
}

/// 룰 id → (위협 표 줄의 차례, 줄 이름). 데이터 룰은 표에 서지 않아 없다.
fn rows_by_id(
    plugins: &[(std::path::PathBuf, remedy_sdk::manifest::PluginManifest)],
) -> BTreeMap<String, (usize, String)> {
    let mut out = BTreeMap::new();
    for (i, (name, ids)) in threats::order(plugins).into_iter().enumerate() {
        for id in ids {
            out.insert(id, (i, name.clone()));
        }
    }
    out
}

/// 조각이 말하는 위협 — (차례, 줄 이름). 데이터 룰만 적었거나 없는 룰이거나 위협이 둘이면 그 까닭.
fn threat_of(
    f: &Fragment,
    rows: &BTreeMap<String, (usize, String)>,
    data: &BTreeSet<String>,
) -> Result<(usize, String), String> {
    let mut found: Option<(usize, String)> = None;
    for id in &f.rules {
        if data.contains(id) {
            continue;
        }
        let Some(r) = rows.get(id) else {
            return Err(format!("{}: 룰 '{id}' 가 plugins/ 에 없다", f.path));
        };
        match &found {
            None => found = Some(r.clone()),
            Some(prev) if prev.1 != r.1 => {
                return Err(format!(
                    "{}: 한 조각이 위협 둘('{}' · '{}')을 말한다 — 위협마다 조각을 나눈다",
                    f.path, prev.1, r.1
                ))
            }
            Some(_) => {}
        }
    }
    found.ok_or_else(|| {
        format!(
            "{}: 데이터 룰만 적었다 — 그 기준을 쓰는 위협 룰을 함께 적는다",
            f.path
        )
    })
}

/// 같은 소제목 안에서 조각 본문을 잇는다 — 목록끼리는 줄 하나로(한 목록), `<details>` 뒤나 목록이 아닌 것은 빈 줄로.
fn join_bodies(bodies: &[&str]) -> String {
    let mut out = String::new();
    for b in bodies {
        if !out.is_empty() {
            out.push_str(if out.contains("</details>") || !b.starts_with("* ") {
                "\n\n"
            } else {
                "\n"
            });
        }
        out.push_str(b);
    }
    out
}

/// 조각을 모아 업데이트 내역 한 칸의 본문(`### …` 묶음들)을 짓는다. 위협의 이름 · 차례는 그 조각을 실은 트리의 매니페스트로.
pub(crate) fn render(
    frags: &[Fragment],
    plugins: &[(std::path::PathBuf, remedy_sdk::manifest::PluginManifest)],
) -> Result<String, String> {
    let rows = rows_by_id(plugins);
    let data: BTreeSet<String> = plugins
        .iter()
        .filter(|(_, m)| !threats::listed(m))
        .map(|(_, m)| m.id.clone())
        .collect();
    let mut sorted: Vec<&Fragment> = frags.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut by_threat: BTreeMap<(usize, String), Vec<&str>> = BTreeMap::new();
    let mut program = Vec::new();
    let mut other = Vec::new();
    for f in sorted {
        match f.section {
            Section::Rules => {
                let k = threat_of(f, &rows, &data)?;
                by_threat.entry(k).or_default().push(&f.body);
            }
            Section::Program => program.push(f.body.as_str()),
            Section::Other => other.push(f.body.as_str()),
        }
    }
    let mut parts = Vec::new();
    for ((_, name), bodies) in &by_threat {
        parts.push(format!("### {}\n\n{}", heading(name), join_bodies(bodies)));
    }
    if !program.is_empty() {
        parts.push(format!("### 프로그램\n\n{}", join_bodies(&program)));
    }
    if !other.is_empty() {
        parts.push(format!("### 그 밖\n\n{}", join_bodies(&other)));
    }
    Ok(parts.join("\n\n"))
}

/// `head` 의 트리에 있고 `since` 의 트리에 없는 조각.
pub(crate) fn added_between(root: &Path, since: &str, head: &str) -> Result<Vec<Fragment>, String> {
    let before: BTreeSet<String> = gitbase::ls(root, since, DIR)?.into_iter().collect();
    let mut out = Vec::new();
    for path in gitbase::ls(root, head, DIR)? {
        if !is_fragment(&path) || before.contains(&path) {
            continue;
        }
        let Some(bytes) = gitbase::show(root, head, &path)? else {
            continue;
        };
        out.push(parse(&path, &String::from_utf8_lossy(&bytes))?);
    }
    Ok(out)
}

/// `cargo xtask changes --since <ref> [--head <ref>]` — 그 사이에 더한 조각으로 지은 칸의 본문을 낸다(릴리스 본문 2절).
pub fn changes(root: &Path, args: &[String]) -> Result<(), String> {
    let get = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let since = get("--since").ok_or("cargo xtask changes --since <ref> [--head <ref>]")?;
    let head = get("--head").unwrap_or_else(|| "HEAD".into());
    for r in [&since, &head] {
        if !gitbase::exists(root, r) {
            return Err(format!(
                "'{r}' 가 이 저장소에 없다 — git fetch --tags origin 뒤 다시"
            ));
        }
    }
    let frags = added_between(root, &since, &head)?;
    if frags.is_empty() {
        return Err(format!(
            "{since} 뒤에 더한 업데이트 내역 조각이 없다 — 이 출시에서 바뀐 것을 docs/changes/ 에 먼저 적는다"
        ));
    }
    let plugins = threats::plugins_at(root, &head)?;
    print!("{}", render(&frags, &plugins)?);
    Ok(())
}

/// `cargo xtask fragments [--base <ref>]` — 첫머리의 셋.
/// 2026-11-21 에 지운 파일 — 룰 버전 파일 · 잠금 · 룰 폴더의 개발 키 서명. 다시 들어오면 막고(아래 3), 절차 문서가 '전에는
/// 이 파일로 했다' 고 적는 것은 절차 문서 검사(`procdocs`)가 어긋남으로 세지 않는다.
pub(crate) const REMOVED: &[&str] = &[
    "plugins/RULES-VERSION",
    "plugins/versions.lock.json",
    "plugins/*/MANIFEST",
    "plugins/*/MANIFEST.minisig",
];

pub fn check(root: &Path, args: &[String]) -> Result<(), String> {
    let base = gitbase::resolve(root, args)?;
    let mut errors = Vec::new();

    // 1 조각마다 꼴 — 작업 트리의 조각 전부.
    let dir = root.join(DIR);
    let mut frags = Vec::new();
    if dir.is_dir() {
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        for name in names {
            let path = format!("{DIR}/{name}");
            if !is_fragment(&path) {
                continue;
            }
            let text =
                std::fs::read_to_string(root.join(&path)).map_err(|e| format!("{path}: {e}"))?;
            match parse(&path, &text) {
                Ok(f) => frags.push(f),
                Err(e) => errors.push(e),
            }
        }
    }
    let plugins = threats::plugins(root)?;
    let rows = rows_by_id(&plugins);
    let data: BTreeSet<String> = plugins
        .iter()
        .filter(|(_, m)| !threats::listed(m))
        .map(|(_, m)| m.id.clone())
        .collect();
    for f in frags.iter().filter(|f| f.section == Section::Rules) {
        for id in &f.rules {
            if !rows.contains_key(id) && !data.contains(id) {
                errors.push(format!("{}: 룰 '{id}' 가 plugins/ 에 없다", f.path));
            }
        }
        if let Err(e) = threat_of(f, &rows, &data) {
            if !errors.contains(&e) {
                errors.push(e);
            }
        }
    }

    // 2 바탕보다 version 이 바뀐 룰마다 바탕 뒤에 더한 조각이 그 룰을 적었는가.
    let before: BTreeSet<String> = gitbase::ls(root, &base, DIR)?.into_iter().collect();
    let covered: BTreeSet<&str> = frags
        .iter()
        .filter(|f| !before.contains(&f.path))
        .flat_map(|f| f.rules.iter().map(String::as_str))
        .collect();
    let mut bumped = 0;
    for (dir, m) in &plugins {
        let folder = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let at_base = gitbase::show(root, &base, &format!("plugins/{folder}/plugin.yaml"))?;
        let old = match at_base {
            None => None,
            Some(b) => Some(
                serde_yaml_ng::from_str::<remedy_sdk::manifest::PluginManifest>(
                    &String::from_utf8_lossy(&b),
                )
                .map_err(|e| format!("{base}:plugins/{folder}/plugin.yaml: {e}"))?
                .version,
            ),
        };
        if old.as_deref() == Some(m.version.as_str()) {
            continue;
        }
        bumped += 1;
        if !covered.contains(m.id.as_str()) {
            let what = match &old {
                None => "새 룰".to_string(),
                Some(o) => format!("{o} → {}", m.version),
            };
            errors.push(format!(
                "{} ({what}): 이 버전에서 바뀐 것을 적은 조각이 바탕 뒤에 없다 — {DIR}/{}-{}.md 를 더할 것(꼴은 \
                 xtask/src/fragments.rs 첫머리)",
                m.id, m.id, m.version
            ));
        }
    }

    // 3 지운 파일이 되살아나지 않았는가.
    let back = gitbase::tracked(root, REMOVED)?;
    if !back.is_empty() {
        errors.push(format!(
            "지운 파일이 다시 들어왔다: {} — 룰 버전은 출시 때 정하고(ci/batch.sh), 잠금은 git 바탕과 견주며(plugin-lock), \
             룰 서명은 배포 잡이 배포 키로 한다. 저장소에 커밋하지 않는다",
            back.join(" ")
        ));
    }

    if !errors.is_empty() {
        return Err(format!(
            "업데이트 내역 조각 {}건 문제(바탕 {base}):\n  {}",
            errors.len(),
            errors.join("\n  ")
        ));
    }
    println!(
        "fragments OK — 조각 {}개 · 바탕 {base} 뒤 버전이 바뀐 룰 {bumped}개가 모두 조각에 있다",
        frags.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frag(path: &str, head: &str, body: &str) -> Result<Fragment, String> {
        parse(path, &format!("---\n{head}\n---\n{body}\n"))
    }

    #[test]
    fn a_fragment_has_a_head_and_a_body() {
        let f = frag(
            "docs/changes/a-0.1.1.md",
            "section: rules\nrules: [a-check-linux]",
            "* **바뀐 것** (Linux)\\\n  설명입니다.",
        )
        .expect("조각");
        assert_eq!(f.section, Section::Rules);
        assert_eq!(f.rules, vec!["a-check-linux"]);
        assert!(f.body.starts_with("* **바뀐 것**"));
        let p = frag(
            "docs/changes/p.md",
            "section: 프로그램",
            "* **엔진**\\\n  설명.",
        )
        .expect("프로그램");
        assert_eq!(p.section, Section::Program);
        assert_eq!(
            frag("docs/changes/o.md", "section: 그 밖", "* x")
                .expect("그 밖")
                .section,
            Section::Other
        );
    }

    #[test]
    fn a_bad_fragment_is_refused() {
        let bad = [
            ("section: rules", "* x", "rules 가 비었다"),
            ("section: 그 밖\nrules: [a]", "* x", "rules 는"),
            ("section: 기타", "* x", "section '기타'"),
            ("section: rules\nrules: [a]\nwhat: 1", "* x", "머리"),
            ("section: rules\nrules: [a]", "### 소제목\n* x", "제목 줄"),
            (
                "section: rules\nrules: [a]",
                "* [링크](docs/x.md)",
                "상대 링크",
            ),
            ("section: rules\nrules: [a]", "* x\n<details>\n열기", "짝이"),
            ("section: rules\nrules: [a]", "* x\n```\n코드", "코드 블록"),
            ("section: rules\nrules: [a]", "* {{CHANGES}}", "'{{'"),
            ("section: rules\nrules: [a]", "", "본문이 비었다"),
            // 블록 꼴은 YAML 로는 맞지만 공개 걸음의 셸이 읽지 못한다 — 한 줄로만 받는다.
            ("section: rules\nrules:\n  - a", "* x", "한 줄로"),
        ];
        for (head, body, want) in bad {
            let e = frag("docs/changes/x.md", head, body).expect_err(head);
            assert!(e.contains(want), "{head} / {body} → {e}");
        }
        assert!(
            parse("docs/changes/x.md", "section: rules\n").is_err(),
            "머리 없음"
        );
        assert!(frag(
            "docs/changes/x.md",
            "section: rules\nrules: [a]",
            "* [주소](https://x.example/a) · [위](#b)"
        )
        .is_ok());
    }

    #[test]
    fn the_heading_drops_one_trailing_parenthesis() {
        assert_eq!(
            heading("Apache HTTP/2 점검 (CVE-2026-119618)"),
            "Apache HTTP/2 점검"
        );
        assert_eq!(heading("Log4j 점검 (CVE-2021-44228 등)"), "Log4j 점검");
        assert_eq!(heading("CWPdoor 제거"), "CWPdoor 제거");
        assert_eq!(
            heading("PHP2Shell · Apache HTTP/2 원격 점검 (웹서버 응답 헤더)"),
            "PHP2Shell · Apache HTTP/2 원격 점검"
        );
    }

    fn plugin(
        folder: &str,
        name: &str,
        platforms: &str,
        kind: &str,
    ) -> (std::path::PathBuf, remedy_sdk::manifest::PluginManifest) {
        let yaml = format!(
            "schema_version: 1\nid: {folder}\nversion: 0.2.0\nmin_core: \"1.12.0\"\n{kind}\
             platforms: [{platforms}]\nname: {{ ko: \"{name}\", en: \"x\" }}\n\
             references: [\"https://www.php.net/archive/2026.php\"]\n\
             scan_roots: [\"/opt\"]\nsubjects: [file]\ndetect:\n  - id: r\n    subject: file\n\
             \x20   where:\n      - {{ field: path, op: equals, value: \"/opt/x\" }}\n\
             verdict:\n  require: \"r\"\n"
        );
        let m = serde_yaml_ng::from_str(&yaml).expect("시험 매니페스트");
        (std::path::PathBuf::from("plugins").join(folder), m)
    }

    /// 위협 표 차례로 소제목을 세우고, 같은 위협의 OS 조각은 한 소제목에 · 프로그램 · 그 밖은 끝에.
    #[test]
    fn fragments_render_as_one_section_in_table_order() {
        let plugins = vec![
            plugin("a-check-linux", "가 점검 (CVE-1)", "linux", ""),
            plugin("a-check-windows", "가 점검 (CVE-1)", "windows", ""),
            plugin("b-check-linux", "나 점검", "linux", ""),
        ];
        let frags = vec![
            frag(
                "docs/changes/z-other.md",
                "section: 그 밖",
                "* **배포**\\\n  설명.",
            )
            .unwrap(),
            frag(
                "docs/changes/b-0.2.0.md",
                "section: rules\nrules: [b-check-linux]",
                "* **나**\\\n  설명.",
            )
            .unwrap(),
            frag(
                "docs/changes/a2.md",
                "section: rules\nrules: [a-check-windows]",
                "* **가 W** (Windows)\\\n  설명.",
            )
            .unwrap(),
            frag(
                "docs/changes/a1.md",
                "section: rules\nrules: [a-check-linux]",
                "* **가 L** (Linux)\\\n  설명.",
            )
            .unwrap(),
            frag(
                "docs/changes/p.md",
                "section: 프로그램",
                "* **엔진**\\\n  설명.",
            )
            .unwrap(),
        ];
        let out = render(&frags, &plugins).expect("모음");
        let want = "### 가 점검\n\n* **가 L** (Linux)\\\n  설명.\n* **가 W** (Windows)\\\n  설명.\n\n\
                    ### 나 점검\n\n* **나**\\\n  설명.\n\n### 프로그램\n\n* **엔진**\\\n  설명.\n\n### 그 밖\n\n* **배포**\\\n  설명.";
        assert_eq!(out, want, "\n{out}");
        // 병합 차례(넘긴 차례)가 달라도 같은 바이트다.
        let mut rev = frags.clone();
        rev.reverse();
        assert_eq!(render(&rev, &plugins).unwrap(), out);
    }

    #[test]
    fn a_fragment_names_one_threat_and_not_only_data() {
        let plugins = vec![
            plugin("a-check-linux", "가 점검", "linux", ""),
            plugin("b-check-linux", "나 점검", "linux", ""),
            plugin("c-data", "기준", "linux, windows", "kind: data\n"),
        ];
        let two = frag(
            "docs/changes/x.md",
            "section: rules\nrules: [a-check-linux, b-check-linux]",
            "* x",
        )
        .unwrap();
        assert!(render(&[two], &plugins).unwrap_err().contains("위협 둘"));
        let only = frag(
            "docs/changes/y.md",
            "section: rules\nrules: [c-data]",
            "* x",
        )
        .unwrap();
        assert!(render(&[only], &plugins)
            .unwrap_err()
            .contains("데이터 룰만"));
        let with = frag(
            "docs/changes/z.md",
            "section: rules\nrules: [a-check-linux, c-data]",
            "* x",
        )
        .unwrap();
        assert!(render(&[with], &plugins)
            .unwrap()
            .starts_with("### 가 점검"));
        let none = frag(
            "docs/changes/n.md",
            "section: rules\nrules: [no-such]",
            "* x",
        )
        .unwrap();
        assert!(render(&[none], &plugins).unwrap_err().contains("없다"));
    }

    #[test]
    fn details_and_non_lists_get_a_blank_line() {
        assert_eq!(join_bodies(&["* a", "* b"]), "* a\n* b");
        assert_eq!(
            join_bodies(&[
                "* a\n\n<details>\n<summary>x</summary>\n\ny\n\n</details>",
                "* b"
            ]),
            "* a\n\n<details>\n<summary>x</summary>\n\ny\n\n</details>\n\n* b"
        );
        assert_eq!(join_bodies(&["* a", "설명 문단"]), "* a\n\n설명 문단");
    }
}
