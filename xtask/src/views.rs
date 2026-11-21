//! 하루 한 번 갈아 끼우는 생성물 (2026-11-21 · 목표 remedy_하루30건_대응체계 차례 2 · 칸 ② '출시마다 넣지 않는다').
//!
//! 출시는 태그 나무와 git 만 읽는다 — 그래서 사람이 읽는 아래 넷은 출시마다 main 에 넣지 않고, 하루 한 번 이 명령이
//! 지어 생성물 PR 하나로 갈아 끼운다(`bash ci/batch.sh views` — 룰 폴더를 건드리지 않아 CI 는 가벼운 길이다).
//!
//! | 자리 | 무엇에서 짓나 |
//! |---|---|
//! | README *다루는 위협* 표 | 룰 매니페스트(`cargo xtask threats --write` 와 같은 함수) |
//! | README *위협별 안내* 표 | `docs/위협별-안내.md` 의 절마다 고정 주소 아래 `<!-- 안내 표: <위협> \| <OS> \| <링크 글> -->` 줄 |
//! | `docs/업데이트-내역.md` 의 생성 구간 | 공개한 출시마다 그 출시가 새로 실은 조각(`crate::fragments` — 릴리스 본문 2절과 같은 함수) |
//! | 하네스 README 의 *머리 줄 하네스* 표 | `testbed/harness/{linux,host}/` 하네스 머리의 `# 하네스 표: <실행 위치> \| <역할>` 줄 |
//!
//! ```text
//! cargo xtask views --check  [--releases <파일>]   생성물이 지금 자료와 같은가(아니면 실패)
//! cargo xtask views --write  [--releases <파일>]   다시 쓴다 — 공개한 조각은 업데이트 내역에 옮겼으니 지운다
//! ```
//!
//! `--releases` 는 공개된 정식 Release 를 **새것부터** 한 줄에 하나 — `<태그>\t<이름>\t<공개 시각 RFC3339>`
//! (`ci/batch.sh views` 가 gh 로 짓는다). 없으면 업데이트 내역 구간은 건너뛰고 그렇게 적는다.

use crate::{fragments, gitbase, threats};
use std::path::Path;

const README: &str = "README.md";
const GUIDE: &str = "docs/위협별-안내.md";
const HISTORY: &str = "docs/업데이트-내역.md";
const HARNESS: &str = "testbed/harness/README.md";

const GUIDE_BEGIN: &str = "<!-- guide:begin — `cargo xtask views --write` 가 docs/위협별-안내.md 의 '안내 표' 줄에서 만든다. 손으로 고치지 않는다 -->";
const GUIDE_END: &str = "<!-- guide:end -->";
const CHANGES_BEGIN: &str = "<!-- changes:begin — `cargo xtask views --write` 가 공개한 출시마다 docs/changes/ 의 조각으로 짓는다. 손으로 고치지 않는다 -->";
const CHANGES_END: &str = "<!-- changes:end -->";
const HARNESS_BEGIN: &str = "<!-- harness:begin — `cargo xtask views --write` 가 하네스 머리의 '# 하네스 표:' 줄에서 만든다. 손으로 고치지 않는다 -->";
const HARNESS_END: &str = "<!-- harness:end -->";

/// 표지 둘 사이(앞 표지의 끝 · 뒤 표지의 시작).
fn between(text: &str, begin: &str, end: &str, file: &str) -> Result<(usize, usize), String> {
    let b = text
        .find(begin)
        .ok_or_else(|| format!("{file} 에 표지가 없다: {begin}"))?;
    let e = text[b..]
        .find(end)
        .map(|i| b + i)
        .ok_or_else(|| format!("{file} 에 끝 표지가 없다: {end}"))?;
    Ok((b + begin.len(), e))
}

/// README *위협별 안내* 표 — 안내 문서의 '안내 표' 줄(절의 고정 주소 바로 아래)에서.
fn guide_table(guide: &str) -> Result<String, String> {
    let mut anchor: Option<String> = None;
    let mut rows = Vec::new();
    for line in guide.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("<a id=\"") {
            anchor = rest.split('"').next().map(str::to_string);
            continue;
        }
        let Some(inner) = t
            .strip_prefix("<!-- 안내 표:")
            .and_then(|r| r.strip_suffix("-->"))
        else {
            continue;
        };
        let cells: Vec<&str> = inner.split('|').map(str::trim).collect();
        if cells.len() != 3 || cells.iter().any(|c| c.is_empty()) {
            return Err(format!(
                "{GUIDE} 의 안내 표 줄 '{t}' — '<!-- 안내 표: <위협> | <OS> | <링크 글> -->' 꼴이다"
            ));
        }
        let id = anchor.take().ok_or_else(|| {
            format!("{GUIDE} 의 안내 표 줄 '{t}' 위에 고정 주소(<a id=…>)가 없다")
        })?;
        rows.push(format!(
            "| {} | {} | [{}]({GUIDE}#{id}) |",
            cells[0], cells[1], cells[2]
        ));
    }
    if rows.is_empty() {
        return Err(format!("{GUIDE} 에 안내 표 줄이 없다"));
    }
    Ok(format!(
        "\n| 위협 | OS | 안내 |\n|---|---|---|\n{}\n",
        rows.join("\n")
    ))
}

/// 하네스 README 의 *머리 줄 하네스* 표.
fn harness_table(root: &Path) -> Result<String, String> {
    let mut rows = Vec::new();
    for (sub, ext) in [("linux", "sh"), ("host", "ps1")] {
        let dir = root.join("testbed/harness").join(sub);
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(&format!(".{ext}")))
            .collect();
        names.sort();
        for name in names {
            let text = std::fs::read_to_string(dir.join(&name)).unwrap_or_default();
            for line in text.lines().take(60) {
                let Some(rest) = line
                    .trim_start_matches('\u{feff}')
                    .strip_prefix("# 하네스 표:")
                else {
                    continue;
                };
                let cells: Vec<&str> = rest.split('|').map(str::trim).collect();
                if cells.len() != 2 || cells.iter().any(|c| c.is_empty()) {
                    return Err(format!(
                        "testbed/harness/{sub}/{name} 의 '# 하네스 표:' 줄 — '# 하네스 표: <실행 위치> | <역할>' 꼴이다"
                    ));
                }
                rows.push(format!("| `{sub}/{name}` | {} | {} |", cells[0], cells[1]));
                break;
            }
        }
    }
    if rows.is_empty() {
        return Ok("\n아직 없다 — 머리에 `# 하네스 표: <실행 위치> | <역할>` 줄을 단 하네스가 여기 선다.\n".into());
    }
    Ok(format!(
        "\n| 파일 | 실행 위치 | 역할 |\n|---|---|---|\n{}\n",
        rows.join("\n")
    ))
}

/// 공개된 출시 한 줄.
struct Release {
    tag: String,
    engine: String,
    rules: String,
    date: String,
}

/// RFC3339(UTC · `Z`)의 한국 날짜 `YYYY-MM-DD`.
fn kst_date(rfc: &str) -> Option<String> {
    let day = remedy_sdk::utc::day_number(rfc.get(..10)?)?;
    let hh: i64 = rfc.get(11..13)?.parse().ok()?;
    let mm: i64 = rfc.get(14..16)?.parse().ok()?;
    let ss: i64 = rfc.get(17..19)?.parse().ok()?;
    let secs = day * 86_400 + hh * 3600 + mm * 60 + ss + 9 * 3600;
    let (y, m, d, ..) = remedy_sdk::utc::civil(u64::try_from(secs).ok()?);
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

fn releases(text: &str) -> Result<Vec<Release>, String> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let cells: Vec<&str> = line.split('\t').collect();
        if cells.len() != 3 {
            return Err(format!(
                "--releases 의 줄 '{line}' — '<태그>\\t<이름>\\t<공개 시각>' 이다"
            ));
        }
        // 이름은 '프로그램 <엔진> · 룰 <룰>' 이다(release.yml 의 draft 잡). 룰 버전을 따로 매기기 전의 공개본(1.19.1 등)은
        // '프로그램 <엔진>' 뿐이라 비워 둔다 — 그 출시는 조각을 쓰지 않아 칸을 짓지 않는다(짓게 되면 아래가 멈춘다).
        let name = cells[1].trim();
        let (engine, rules) = name
            .strip_prefix("프로그램 ")
            .and_then(|rest| rest.split_once(" · 룰 "))
            .map(|(e, r)| (e.trim().to_string(), r.trim().to_string()))
            .unwrap_or_default();
        out.push(Release {
            tag: cells[0].trim().to_string(),
            engine,
            rules,
            date: kst_date(cells[2].trim())
                .ok_or_else(|| format!("공개 시각 '{}' 을 읽지 못했다", cells[2]))?,
        });
    }
    Ok(out)
}

/// 업데이트 내역의 생성 구간 — 조각을 쓴 출시마다(새것부터) 그 출시가 새로 실은 조각으로.
fn history_section(root: &Path, rels: &[Release]) -> Result<String, String> {
    let mut parts = Vec::new();
    for pair in rels.windows(2) {
        let (new, old) = (&pair[0], &pair[1]);
        for r in [&new.tag, &old.tag] {
            if !gitbase::exists(root, r) {
                return Err(format!(
                    "태그 {r} 가 이 저장소에 없다 — git fetch --tags origin 뒤 다시"
                ));
            }
        }
        if gitbase::ls(root, &new.tag, fragments::DIR)?.is_empty() {
            continue; // 조각을 쓰기 전의 출시 — 손으로 쓴 칸(얼린 아래쪽)에 있다.
        }
        let frags = fragments::added_between(root, &old.tag, &new.tag)?;
        if frags.is_empty() {
            continue;
        }
        if new.engine.is_empty() || new.rules.is_empty() {
            return Err(format!(
                "{} 의 Release 이름이 '프로그램 <엔진> · 룰 <룰>' 꼴이 아니다 — 업데이트 내역 칸의 머리를 짓지 못한다",
                new.tag
            ));
        }
        let plugins = threats::plugins_at(root, &new.tag)?;
        let head = if new.tag.starts_with("rules-") {
            format!(
                "## 룰 {} · 프로그램 {} — {}",
                new.rules, new.engine, new.date
            )
        } else {
            format!("## {} · 룰 {} — {}", new.engine, new.rules, new.date)
        };
        parts.push(format!(
            "{head}\n\n{}\n",
            fragments::render(&frags, &plugins)?
        ));
    }
    Ok(if parts.is_empty() {
        "\n".into()
    } else {
        format!("\n{}", parts.join("\n"))
    })
}

/// 고칠 파일 하나 — 지금 내용과 지은 내용.
struct View {
    file: &'static str,
    now: String,
    want: String,
}

fn replace(text: &str, begin: &str, end: &str, file: &str, inner: &str) -> Result<String, String> {
    let (s, e) = between(text, begin, end, file)?;
    Ok(format!("{}{inner}{}", &text[..s], &text[e..]))
}

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let write = args.iter().any(|a| a == "--write");
    let check = args.iter().any(|a| a == "--check");
    if write == check {
        return Err("cargo xtask views --check | --write [--releases <파일>]".into());
    }
    let rels = match args.iter().position(|a| a == "--releases") {
        Some(i) => {
            let p = args.get(i + 1).ok_or("--releases <파일>")?;
            Some(releases(
                &std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?,
            )?)
        }
        None => None,
    };

    let read = |f: &str| std::fs::read_to_string(root.join(f)).map_err(|e| format!("{f}: {e}"));
    let plugins = threats::plugins(root)?;

    // README — 두 표를 한 번에.
    let readme = read(README)?;
    let guide = guide_table(&read(GUIDE)?)?;
    let mut want_readme = replace(
        &readme,
        "<!-- threats:begin — `cargo xtask threats --write` 가 룰에서 만든다. 손으로 고치지 않는다 -->",
        "<!-- threats:end -->",
        README,
        &format!("\n{}", threats::table(&plugins)),
    )?;
    want_readme = replace(&want_readme, GUIDE_BEGIN, GUIDE_END, README, &guide)?;
    let mut views = vec![View {
        file: README,
        now: readme,
        want: want_readme,
    }];

    let harness = read(HARNESS)?;
    views.push(View {
        file: HARNESS,
        want: replace(
            &harness,
            HARNESS_BEGIN,
            HARNESS_END,
            HARNESS,
            &harness_table(root)?,
        )?,
        now: harness,
    });

    match &rels {
        Some(rels) => {
            let history = read(HISTORY)?;
            views.push(View {
                file: HISTORY,
                want: replace(
                    &history,
                    CHANGES_BEGIN,
                    CHANGES_END,
                    HISTORY,
                    &history_section(root, rels)?,
                )?,
                now: history,
            });
        }
        None => println!(
            "views: --releases 가 없어 업데이트 내역 구간은 건너뛰었다(ci/batch.sh views 가 준다)"
        ),
    }

    let stale: Vec<&View> = views.iter().filter(|v| v.now != v.want).collect();
    if check {
        if stale.is_empty() {
            println!("views OK — 생성물 {}곳이 지금 자료와 같다", views.len());
            return Ok(());
        }
        return Err(format!(
            "생성물이 낡았다: {} — bash ci/batch.sh views 가 갈아 끼운다",
            stale.iter().map(|v| v.file).collect::<Vec<_>>().join(" · ")
        ));
    }
    for v in &stale {
        std::fs::write(root.join(v.file), &v.want).map_err(|e| format!("{}: {e}", v.file))?;
        println!("views 갱신 — {}", v.file);
    }

    // 공개한 조각은 업데이트 내역에 옮겼다 — 지금 Latest 의 트리에 있는 조각을 지운다. 다음 출시는 'Latest 의 트리에
    // 없고 그 태그에 있는 조각' 을 고르므로 지운 것은 다시 실리지 않는다(지난 출시의 칸은 그 태그의 트리에서 다시 짓는다).
    if let Some(latest) = rels.as_ref().and_then(|r| r.first()) {
        let mut gone = 0;
        for path in gitbase::ls(root, &latest.tag, fragments::DIR)? {
            if path.ends_with(".md") && !path.ends_with("/README.md") && root.join(&path).is_file()
            {
                std::fs::remove_file(root.join(&path)).map_err(|e| format!("{path}: {e}"))?;
                gone += 1;
            }
        }
        if gone > 0 {
            println!(
                "views: {} 에 실린 조각 {gone}개를 지웠다(업데이트 내역에 옮겼다)",
                latest.tag
            );
        }
    }
    if stale.is_empty() {
        println!("views OK — 생성물 {}곳이 이미 같다", views.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guide_table_comes_from_the_marker_lines() {
        let g = "# 안내\n\n<a id=\"cwpdoor\"></a>\n<!-- 안내 표: CWPdoor (Control Web Panel) | Linux | 치료 뒤 할 일 -->\n\n## CWPdoor\n\n\
                 <a id=\"log4j\"></a>\n<!-- 안내 표: Log4j | Windows · Linux | 점검 결과 읽기 -->\n";
        let t = guide_table(g).expect("표");
        assert_eq!(
            t,
            "\n| 위협 | OS | 안내 |\n|---|---|---|\n\
             | CWPdoor (Control Web Panel) | Linux | [치료 뒤 할 일](docs/위협별-안내.md#cwpdoor) |\n\
             | Log4j | Windows · Linux | [점검 결과 읽기](docs/위협별-안내.md#log4j) |\n"
        );
        assert!(guide_table("<!-- 안내 표: x | y | z -->")
            .unwrap_err()
            .contains("고정 주소"));
        assert!(guide_table("<a id=\"a\"></a>\n<!-- 안내 표: x | y -->")
            .unwrap_err()
            .contains("꼴"));
    }

    #[test]
    fn a_release_line_reads_name_and_kst_date() {
        let r = releases(
            "rules-2026.11.21\t프로그램 1.25.3 · 룰 2026.11.21\t2026-11-21T05:58:18Z\n\
                          v1.25.3\t프로그램 1.25.3 · 룰 2026.11.20.4\t2026-11-20T18:04:01Z\n",
        )
        .expect("줄");
        assert_eq!(r[0].engine, "1.25.3");
        assert_eq!(r[0].rules, "2026.11.21");
        assert_eq!(r[0].date, "2026-11-21");
        // 18:04 UTC 는 한국의 다음 날 03:04 다.
        assert_eq!(r[1].date, "2026-11-21");
        // 룰 버전을 따로 매기기 전의 이름은 비워 둔다(그 출시는 칸을 짓지 않는다).
        let old = releases("v1.19.1\t프로그램 1.19.1\t2026-11-13T00:00:00Z").expect("옛 이름");
        assert!(old[0].engine.is_empty() && old[0].rules.is_empty());
        assert!(releases("x\t룰 2026.11.21").is_err(), "칸이 셋이 아니다");
    }
}
