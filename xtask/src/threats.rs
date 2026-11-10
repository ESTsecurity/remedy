//! 위협 표 — README 와 릴리스 본문의 *"다루는 위협"* 을 **룰 매니페스트에서 만든다**.
//!
//! # 왜 생성하는가
//!
//! 꾸러미가 OS 별 통합이 되면 받기 전에 무엇이 들었는지 알 자리가 README 와 릴리스 본문뿐이다.
//! 손으로 쓴 표는 룰이 늘 때 반드시 어긋난다 — 그래서 `plugins/*/plugin.yaml` 에서 만들고,
//! `cargo xtask all` 이 README 의 표가 그것과 같은지 본다(`schema` 와 같은 모양). 릴리스 본문은
//! 배포 잡이 README 의 같은 구간을 옮긴다.
//!
//! ```text
//! cargo xtask threats                README 의 표가 지금 룰과 같은가 (아니면 실패)
//! cargo xtask threats --write        README 의 표를 다시 쓴다
//! cargo xtask threats --dirs linux   그 OS 의 룰 폴더 (배포 잡이 서명 · 꾸러미에 쓴다)
//! ```

use remedy_sdk::catalog::Platform;
use remedy_sdk::manifest::PluginManifest;
use std::path::{Path, PathBuf};

const README: &str = "README.md";
const BEGIN: &str =
    "<!-- threats:begin — `cargo xtask threats --write` 가 룰에서 만든다. 손으로 고치지 않는다 -->";
const END: &str = "<!-- threats:end -->";

/// 제품 룰 — `plugins/<이름>/plugin.yaml` 을 이름순으로.
fn plugins(root: &Path) -> Result<Vec<(PathBuf, PluginManifest)>, String> {
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

/// README 와 릴리스 본문에 같은 꼴로 들어가는 표. OS 차례(Windows → Linux), 그 안은 폴더 이름순.
fn table(plugins: &[(PathBuf, PluginManifest)]) -> String {
    let mut rows: Vec<(usize, String)> = Vec::new();
    for (dir, m) in plugins {
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
            "적어 준 주소의 서버를 바깥에서 봅니다 (네트워크 사용)"
        } else {
            "찾기만 합니다"
        };
        let os: Vec<&str> = m.platforms.iter().map(|p| os_label(*p)).collect();
        let order = if m.platforms.contains(&Platform::Windows) {
            0
        } else {
            1
        };
        let refs = m
            .references
            .first()
            .map(|u| format!("[{}]({u})", host_of(u)))
            .unwrap_or_else(|| "—".into());
        let folder = dir.file_name().unwrap_or_default().to_string_lossy();
        rows.push((
            order,
            format!(
                "| {name} | {does} | {} | `{folder}` {} | {refs} |",
                os.join(" · "),
                m.version
            ),
        ));
    }
    rows.sort_by_key(|(o, _)| *o);
    let mut out =
        String::from("| 룰 | 하는 일 | OS | 폴더 · 버전 | 참고 |\n|---|---|---|---|---|\n");
    for (_, r) in rows {
        out.push_str(&r);
        out.push('\n');
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

    let path = root.join(README);
    let readme = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (s, e) = section(&readme)?;
    let want = format!("\n{}", table(&plugins));
    if readme[s..e] == want {
        println!(
            "threats OK — README 의 위협 표가 룰 {}개와 같다",
            plugins.len()
        );
        return Ok(());
    }
    if args.iter().any(|a| a == "--write") {
        let next = format!("{}{want}{}", &readme[..s], &readme[e..]);
        std::fs::write(&path, next).map_err(|e| format!("{}: {e}", path.display()))?;
        println!(
            "threats 갱신 — README 의 위협 표를 룰 {}개로 다시 썼다",
            plugins.len()
        );
        return Ok(());
    }
    Err(
        "README 의 위협 표가 룰과 다르다 — `cargo xtask threats --write` 로 다시 쓰고 커밋할 것"
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_text_is_the_host() {
        assert_eq!(host_of("https://blog.example.com/a/b"), "blog.example.com");
        assert_eq!(host_of("example.com/x"), "example.com");
    }

    #[test]
    fn the_section_is_between_the_two_marks() {
        let r = format!("앞\n{BEGIN}\n표\n{END}\n뒤\n");
        let (s, e) = section(&r).expect("구간");
        assert_eq!(&r[s..e], "\n표\n");
        assert!(section("표지 없음").is_err());
    }
}
