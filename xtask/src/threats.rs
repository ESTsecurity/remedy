//! 위협 표 — README 의 *"다루는 위협"* 표(릴리스 본문의 위협 표 · 묶음도 이것으로 짓는다)를 **룰 매니페스트에서 만든다**.
//!
//! # 왜 생성하는가
//!
//! 꾸러미가 OS 별 통합이 되면 받기 전에 무엇이 들었는지 알 자리가 README 와 릴리스 본문뿐이다.
//! 손으로 쓴 표는 룰이 늘 때 반드시 어긋난다 — 그래서 `plugins/*/plugin.yaml` 에서 만든다. 릴리스 본문은 배포 잡이
//! **태그 나무의 매니페스트에서** 지은 표(`--print`)를 `ci/release-notes.sh` 가 본문의 꼴로 바꿔 넣는다.
//!
//! 2026-11-21 부터 룰 PR 은 README 의 표를 고치지 않는다(목표 remedy_하루30건_대응체계 차례 2 — 셋이 함께 지으면 이웃
//! 줄이 부딪히고, 같은 위협을 OS 로 나눠 지으면 git 이 충돌 없이 두 줄로 합쳐 표가 틀렸다). README 의 표는 하루 한 번
//! `cargo xtask views --write` 가 갈아 끼우는 생성물이라 `cargo xtask all` 은 **지을 수 있는가**만 본다.
//!
//! ```text
//! cargo xtask threats                표를 지을 수 있는가(README 와는 견주지 않는다 · `all` 이 부른다)
//! cargo xtask threats --check        README 의 표가 지금 룰과 같은가 (아니면 실패)
//! cargo xtask threats --write        README 의 표를 다시 쓴다
//! cargo xtask threats --print        표를 그대로 낸다(배포 잡의 릴리스 본문)
//! cargo xtask threats --dirs linux   그 OS 의 룰 폴더 (배포 잡이 서명 · 꾸러미에 쓴다)
//! ```

use remedy_sdk::catalog::Platform;
use remedy_sdk::manifest::PluginManifest;
use std::path::{Path, PathBuf};

const README: &str = "README.md";
const BEGIN: &str =
    "<!-- threats:begin — `cargo xtask threats --write` 가 룰에서 만든다. 손으로 고치지 않는다 -->";
const END: &str = "<!-- threats:end -->";

/// 그 커밋 · 태그(`rev`)의 제품 룰 — git 에서 `plugins/<이름>/plugin.yaml` 을 읽어 이름순으로. 지난 출시의 업데이트
/// 내역 칸을 다시 지을 때 그 출시의 이름 · 차례로 짓는다(`crate::fragments`).
pub(crate) fn plugins_at(root: &Path, rev: &str) -> Result<Vec<(PathBuf, PluginManifest)>, String> {
    let mut out = Vec::new();
    for path in crate::gitbase::ls(root, rev, "plugins")? {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 3 || parts[2] != "plugin.yaml" {
            continue;
        }
        let Some(bytes) = crate::gitbase::show(root, rev, &path)? else {
            continue;
        };
        let m: PluginManifest = serde_yaml_ng::from_str(&String::from_utf8_lossy(&bytes))
            .map_err(|e| format!("{rev}:{path}: {e}"))?;
        out.push((PathBuf::from("plugins").join(parts[1]), m));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// 제품 룰 — `plugins/<이름>/plugin.yaml` 을 이름순으로.
pub(crate) fn plugins(root: &Path) -> Result<Vec<(PathBuf, PluginManifest)>, String> {
    let dir = root.join("plugins");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let p = e.map_err(|e| e.to_string())?.path();
        let yaml = p.join("plugin.yaml");
        if !yaml.exists() {
            continue;
        }
        let text =
            std::fs::read_to_string(&yaml).map_err(|e| format!("{}: {e}", yaml.display()))?;
        let m: PluginManifest =
            serde_yaml_ng::from_str(&text).map_err(|e| format!("{}: {e}", yaml.display()))?;
        out.push((p, m));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn os_label(p: Platform) -> &'static str {
    match p {
        Platform::Windows => "Windows",
        Platform::Linux => "Linux",
        Platform::Darwin => "macOS",
    }
}

/// 링크 글자는 주소의 호스트만 — 표가 넘치지 않게.
fn host_of(url: &str) -> &str {
    let rest = url.split("://").nth(1).unwrap_or(url);
    rest.split('/').next().unwrap_or(rest)
}

/// 표의 한 줄 — **같은 점검은 OS 가 달라도 한 줄이다** (2026-11-11 결정 · 목표 remedy_PHP스캐너통합 결정 26).
///
/// 같은 점검의 Windows 룰과 리눅스 룰이 줄을 따로 쓰면 같은 이름이 두 번 읽히고, 어느 OS 에 있는지는 줄을
/// 견줘야 안다. 이름 · 하는 일 · 참고가 같으면 한 줄로 모으고, OS 마다 칸을 두어 그 OS 의 폴더 · 버전을 적는다.
struct Row {
    name: String,
    does: &'static str,
    refs: String,
    windows: Vec<String>,
    linux: Vec<String>,
    /// 이 줄에 선 룰의 id(처음 나온 차례) — 업데이트 내역 조각을 위협 소제목으로 묶을 때 쓴다.
    ids: Vec<String>,
}

/// 표에 서는 룰인가 — 데이터 룰(`kind: data` · 코어 1.12.0)은 위협을 다루지 않고 동반 프로그램이 읽는
/// 기준을 담을 뿐이라 표에 서지 않는다. 꾸러미에는 들어간다(`--dirs`).
pub(crate) fn listed(m: &PluginManifest) -> bool {
    m.kind != Some(remedy_sdk::manifest::PluginKind::Data)
}

/// 표의 줄 이름과 그 줄의 룰 id 를 표의 차례로 — 업데이트 내역의 `### <위협>` 차례가 이것이다(`crate::fragments`).
pub(crate) fn order(plugins: &[(PathBuf, PluginManifest)]) -> Vec<(String, Vec<String>)> {
    rows(plugins).into_iter().map(|r| (r.name, r.ids)).collect()
}

/// 표의 줄 — Windows 에 있는 줄이 먼저, 그 안은 폴더 이름순(처음 나온 차례).
fn rows(plugins: &[(PathBuf, PluginManifest)]) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();
    for (dir, m) in plugins.iter().filter(|(_, m)| listed(m)) {
        let name = m
            .name
            .get("ko")
            .or_else(|| m.name.get("en"))
            .cloned()
            .unwrap_or_else(|| m.id.clone());
        let does = if m.remediate.is_some() {
            "찾아서 치료합니다 (복원할 수 있습니다)"
        } else if m.network.is_some() {
            // 이 기계가 아니라 바깥의 서버를 본다 — 받기 전에 알아야 하는 것은 네트워크를 쓴다는 것이다.
            "적어 주신 주소의 서버를 바깥에서 봅니다 (네트워크 사용)"
        } else {
            "찾기만 합니다"
        };
        let refs = m
            .references
            .first()
            .map(|u| format!("[{}]({u})", host_of(u)))
            .unwrap_or_else(|| "—".into());
        let folder = dir.file_name().unwrap_or_default().to_string_lossy();
        let cell = format!("`{folder}` {}", m.version);
        let i = match rows
            .iter()
            .position(|r| r.name == name && r.does == does && r.refs == refs)
        {
            Some(i) => i,
            None => {
                rows.push(Row {
                    name,
                    does,
                    refs,
                    windows: Vec::new(),
                    linux: Vec::new(),
                    ids: Vec::new(),
                });
                rows.len() - 1
            }
        };
        rows[i].ids.push(m.id.clone());
        if m.platforms.contains(&Platform::Windows) {
            rows[i].windows.push(cell.clone());
        }
        if m.platforms.contains(&Platform::Linux) {
            rows[i].linux.push(cell);
        }
    }
    // 안정 정렬 — Windows 에 있는 줄이 먼저, 같은 쪽 안에서는 처음 나온 차례(폴더 이름순) 그대로.
    rows.sort_by_key(|r| r.windows.is_empty());
    rows
}

/// README 의 위협 표.
///
/// 릴리스 본문은 `ci/release-notes.sh` 가 이 표를 읽어 '하는 일' 칸을 '방식' 칸(머리 · 값)으로 바꿔 넣는다 — 칸은
/// 자리로 읽고(셋째 · 넷째가 Windows · Linux 가 아니면 멈춘다), 값은 그 스크립트의 `job_ko` 가 아는 `does` 문구여야
/// 한다. 칸의 차례나 `does` 문구를 바꾸면 그 스크립트도 같은 PR 에서 고친다 — PR 의 CI 가 `ci/release-notes-test.sh`
/// 로 지금 표를 그 스크립트에 넣어 본다(배포 잡은 태그에서만 돈다).
pub(crate) fn table(plugins: &[(PathBuf, PluginManifest)]) -> String {
    let rows = rows(plugins);
    let cell = |v: &[String]| {
        if v.is_empty() {
            "—".to_string()
        } else {
            v.join(" · ")
        }
    };
    let mut out = format!(
        "| 룰 | 하는 일 | {} | {} | 참고 |\n|---|---|---|---|---|\n",
        os_label(Platform::Windows),
        os_label(Platform::Linux)
    );
    for r in rows {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            r.name,
            r.does,
            cell(&r.windows),
            cell(&r.linux),
            r.refs
        ));
    }
    out
}

/// README 의 표 구간(표지 둘 사이)을 돌려준다.
fn section(readme: &str) -> Result<(usize, usize), String> {
    let b = readme
        .find(BEGIN)
        .ok_or_else(|| format!("README 에 표지가 없다: {BEGIN}"))?;
    let e = readme[b..]
        .find(END)
        .map(|i| b + i)
        .ok_or_else(|| format!("README 에 끝 표지가 없다: {END}"))?;
    Ok((b + BEGIN.len(), e))
}

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let plugins = plugins(root)?;
    if let Some(i) = args.iter().position(|a| a == "--dirs") {
        let os = args.get(i + 1).ok_or("--dirs <windows|linux>")?;
        let want = match os.as_str() {
            "windows" => Platform::Windows,
            "linux" => Platform::Linux,
            other => return Err(format!("모르는 OS: {other} (windows · linux)")),
        };
        for (dir, m) in &plugins {
            if m.platforms.contains(&want) {
                let rel = dir.strip_prefix(root).unwrap_or(dir);
                println!("{}", rel.to_string_lossy().replace('\\', "/"));
            }
        }
        return Ok(());
    }

    if args.iter().any(|a| a == "--print") {
        print!("{}", table(&plugins));
        return Ok(());
    }

    let path = root.join(README);
    let readme = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (s, e) = section(&readme)?;
    let want = format!("\n{}", table(&plugins));
    let n = plugins.iter().filter(|(_, m)| listed(m)).count();
    let same = readme[s..e] == want;
    if args.iter().any(|a| a == "--write") {
        if same {
            println!("threats OK — README 의 위협 표가 룰 {n}개와 같다");
            return Ok(());
        }
        let next = format!("{}{want}{}", &readme[..s], &readme[e..]);
        std::fs::write(&path, next).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("threats 갱신 — README 의 위협 표를 룰 {n}개로 다시 썼다");
        return Ok(());
    }
    if args.iter().any(|a| a == "--check") {
        if same {
            println!("threats OK — README 의 위협 표가 룰 {n}개와 같다");
            return Ok(());
        }
        return Err(
            "README 의 위협 표가 룰과 다르다 — `cargo xtask threats --write`(하루 한 번 `cargo xtask views --write` 가 \
             함께 한다)"
                .into(),
        );
    }
    // 기본(`all`) — 표를 지을 수 있는가. README 의 표는 하루 한 번 갈아 끼우는 생성물이라 견주지 않는다.
    println!(
        "threats OK — 룰 {n}개로 표를 지었다{}",
        if same {
            ""
        } else {
            " (README 의 표는 낡았다 — 하루 한 번 `cargo xtask views --write` 가 갈아 끼운다)"
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_text_is_the_host() {
        assert_eq!(host_of("https://blog.example.com/a/b"), "blog.example.com");
        assert_eq!(host_of("example.com/x"), "example.com");
    }

    /// 시험용 룰 하나 — 폴더 · 이름 · OS 만 다르게.
    fn rule(folder: &str, name: &str, platforms: &str) -> (PathBuf, PluginManifest) {
        let yaml = format!(
            "schema_version: 1\nid: {folder}\nversion: 0.2.0\nmin_core: \"1.0.0\"\n\
             platforms: [{platforms}]\nname: {{ ko: \"{name}\", en: \"x\" }}\n\
             references: [\"https://www.php.net/archive/2026.php\"]\n\
             scan_roots: [\"/opt\"]\nsubjects: [file]\ndetect:\n  - id: r\n    subject: file\n\
             \x20   where:\n      - {{ field: path, op: equals, value: \"/opt/x\" }}\n\
             verdict:\n  require: \"r\"\n"
        );
        let m: PluginManifest = serde_yaml_ng::from_str(&yaml).expect("시험 매니페스트");
        (PathBuf::from(folder), m)
    }

    /// 같은 점검의 OS 짝은 **한 줄**이고, 그 OS 의 칸에 폴더가 선다 (2026-11-11 결정 26).
    #[test]
    fn one_check_on_two_systems_is_one_row() {
        let t = table(&[
            rule("a-check-linux", "가 점검", "linux"),
            rule("a-check-windows", "가 점검", "windows"),
            rule("b-only-linux", "나 점검", "linux"),
            rule("c-both", "다 점검", "windows, linux"),
            rule("d-only-windows", "라 점검", "windows"),
        ]);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "| 룰 | 하는 일 | Windows | Linux | 참고 |", "{t}");
        // 머리 두 줄 + 점검 넷 — 다섯 룰이 넷이 된다.
        assert_eq!(lines.len(), 2 + 4, "{t}");
        assert!(
            lines[2].starts_with(
                "| 가 점검 | 찾기만 합니다 | `a-check-windows` 0.2.0 | `a-check-linux` 0.2.0 |"
            ),
            "{t}"
        );
        // 매니페스트 하나가 두 OS 를 선언하면 두 칸에 같은 폴더다.
        assert!(
            lines[3].contains("| `c-both` 0.2.0 | `c-both` 0.2.0 |"),
            "{t}"
        );
        assert!(lines[4].contains("| `d-only-windows` 0.2.0 | — |"), "{t}");
        // Windows 에 없는 줄은 뒤로 — 그 안은 처음 나온 차례.
        assert!(
            lines[5].contains("| 나 점검 | 찾기만 합니다 | — | `b-only-linux` 0.2.0 |"),
            "{t}"
        );
    }

    /// 데이터 룰은 위협이 아니다 — 표에 서지 않는다(꾸러미에는 `--dirs` 로 들어간다 · 코어 1.12.0).
    #[test]
    fn a_data_rule_is_not_a_row() {
        let yaml = "schema_version: 1\nid: e-data\nversion: 1.0.0\nmin_core: \"1.12.0\"\n\
                    platforms: [windows, linux]\nkind: data\nname: { ko: \"기준\", en: \"x\" }\n\
                    scan_roots: []\nsubjects: []\ndetect: []\n";
        let data: PluginManifest = serde_yaml_ng::from_str(yaml).expect("데이터 룰");
        assert!(!listed(&data));
        let with = table(&[
            rule("a-check-linux", "가 점검", "linux"),
            (PathBuf::from("e-data"), data),
        ]);
        let without = table(&[rule("a-check-linux", "가 점검", "linux")]);
        assert_eq!(with, without);
    }

    /// 업데이트 내역의 위협 차례 — 표의 줄 차례 그대로이고, 줄마다 그 줄에 선 룰의 id 다.
    #[test]
    fn the_order_names_each_row_with_its_rules() {
        let o = order(&[
            rule("a-check-linux", "가 점검", "linux"),
            rule("a-check-windows", "가 점검", "windows"),
            rule("b-only-linux", "나 점검", "linux"),
        ]);
        assert_eq!(o.len(), 2);
        assert_eq!(o[0].0, "가 점검");
        assert_eq!(o[0].1, vec!["a-check-linux", "a-check-windows"]);
        assert_eq!(o[1].0, "나 점검");
    }

    #[test]
    fn the_section_is_between_the_two_marks() {
        let r = format!("앞\n{BEGIN}\n표\n{END}\n뒤\n");
        let (s, e) = section(&r).expect("구간");
        assert_eq!(&r[s..e], "\n표\n");
        assert!(section("표지 없음").is_err());
    }
}
