//! `cargo xtask products` — 같은 제품의 점검 룰이 그 제품을 찾는 조건을 원본 하나(`products/<제품>.yaml`)에서 받는다
//! (2026-11-23 · 하루 30건 차례 7 · 결정 K).
//!
//! 같은 제품의 룰은 제품을 찾는 조건(깔린 자리 · 패키지 밖 · 도는 프로세스 · 서비스 · 설정이 싣는 모듈 · 다시 시작하지
//! 않음 · 바뀐 파일)을 룰마다 다시 적었고, 그 고침을 손으로 옮기다 어긋났다. 이제 룰의 `plugin.yaml` 안에서
//!
//! ```text
//!   # >>> 제품 php-linux detect
//!   …원본의 칸 그대로…
//!   # <<< 제품 php-linux detect
//! ```
//!
//! 울타리 사이는 원본 `products/php-linux.yaml` 의 `# === detect` 칸이다. 원본의 칸은 들여쓰기 없이 적고, 채울 때 울타리
//! 줄의 들여쓰기만큼 민다. 울타리 사이를 손으로 고치면 여기서 걸린다 — 원본을 고치고 `cargo xtask products --write` 로
//! 채운다. 채운 룰은 내용이 바뀌므로 `plugin-lock` 이 그 룰마다 버전 올림을, `fragments` 가 조각을 요구한다 — 같은 제품의
//! 룰이 함께 나간다.
//!
//! 받는 사람의 룰은 그대로다 — 원본은 꾸러미에 들지 않고, 채운 `plugin.yaml` 이 그 룰 폴더째 서명된다.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const OPEN: &str = "# >>> 제품 ";
const CLOSE: &str = "# <<< 제품 ";
const BLOCK: &str = "# === ";

/// (제품, 칸) → 칸의 줄(들여쓰기 없이 · 끝의 빈 줄은 뗀다).
type Sources = BTreeMap<(String, String), Vec<String>>;

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let write = match args {
        [] => false,
        [a] if a == "--write" => true,
        _ => return Err("사용법: cargo xtask products [--write]".into()),
    };
    let (sources, files) = load_sources(root)?;
    let (mut fences, mut rules) = (0, 0);
    let mut stale = Vec::new();
    for dir in rule_dirs(root)? {
        let id = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let path = dir.join("plugin.yaml");
        let text = std::fs::read_to_string(&path).map_err(|e| format!("products: {id}: {e}"))?;
        let (filled, n) = fill(&text, &sources).map_err(|e| format!("products: {id}: {e}"))?;
        if n == 0 {
            continue;
        }
        fences += n;
        rules += 1;
        if filled == text {
            continue;
        }
        if write {
            std::fs::write(&path, &filled).map_err(|e| format!("products: {id}: {e}"))?;
            println!("products: {id} 를 원본으로 채웠다");
        } else {
            stale.push(id);
        }
    }
    if !stale.is_empty() {
        return Err(format!(
            "products: 울타리 사이가 원본과 다르다 — {}\n  \
             원본(products/)을 고치고 cargo xtask products --write 로 채운다(울타리 사이는 손으로 고치지 않는다)",
            stale.join(" · ")
        ));
    }
    println!("products: 원본 {files} · 울타리 {fences}(룰 {rules}) · 어긋남 0");
    Ok(())
}

fn rule_dirs(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root.join("plugins"))
        .map_err(|e| format!("products: plugins/: {e}"))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("plugin.yaml").is_file())
        .collect();
    dirs.sort();
    Ok(dirs)
}

/// `products/*.yaml` 의 칸 전부 · 원본 파일 수. 폴더가 없으면 빈 것이다(울타리가 있으면 그 룰에서 걸린다).
fn load_sources(root: &Path) -> Result<(Sources, usize), String> {
    let mut out = Sources::new();
    let Ok(rd) = std::fs::read_dir(root.join("products")) else {
        return Ok((out, 0));
    };
    let mut paths: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    paths.sort();
    for p in &paths {
        let product = p
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let text =
            std::fs::read_to_string(p).map_err(|e| format!("products: {}: {e}", p.display()))?;
        for (block, lines) in
            blocks(&text).map_err(|e| format!("products: {}: {e}", p.display()))?
        {
            out.insert((product.clone(), block), lines);
        }
    }
    Ok((out, paths.len()))
}

/// 원본 파일의 칸 — `# === <칸>` 줄부터 다음 칸 줄이나 파일 끝까지. 첫 칸 앞의 줄(머리 주석)은 칸이 아니다.
fn blocks(text: &str) -> Result<Vec<(String, Vec<String>)>, String> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines() {
        if let Some(name) = line.strip_prefix(BLOCK) {
            let name = name.trim();
            if name.is_empty() || name.contains(char::is_whitespace) {
                return Err(format!("칸 이름은 낱말 하나다: '{line}'"));
            }
            if out.iter().any(|(n, _)| n == name) {
                return Err(format!("같은 이름의 칸이 둘이다: {name}"));
            }
            out.push((name.to_string(), Vec::new()));
        } else if let Some((_, lines)) = out.last_mut() {
            lines.push(line.to_string());
        }
    }
    for (name, lines) in &mut out {
        while lines.last().is_some_and(|l| l.trim().is_empty()) {
            lines.pop();
        }
        if lines.is_empty() {
            return Err(format!("빈 칸: {name}"));
        }
    }
    Ok(out)
}

/// 룰의 `plugin.yaml` 에서 울타리 사이를 원본의 칸으로 바꾼 글과 울타리 수. 울타리 밖은 한 글자도 바꾸지 않는다.
fn fill(text: &str, sources: &Sources) -> Result<(String, usize), String> {
    if text.contains('\r') {
        return Err("줄 끝이 CRLF 다 — 울타리를 둔 룰은 LF 로 쓴다".into());
    }
    let mut out: Vec<String> = Vec::new();
    let mut lines = text.split('\n');
    let mut n = 0;
    while let Some(line) = lines.next() {
        out.push(line.to_string());
        let body = line.trim_start();
        if body.starts_with(CLOSE) {
            return Err(format!("여는 줄 없는 닫는 울타리: '{}'", body.trim_end()));
        }
        let Some(name) = body.strip_prefix(OPEN) else {
            continue;
        };
        let name = name.trim_end();
        let (product, block) = name
            .split_once(' ')
            .filter(|(p, b)| !p.is_empty() && !b.is_empty() && !b.contains(' '))
            .ok_or_else(|| format!("울타리 이름은 '<제품> <칸>' 이다: '{}'", body.trim_end()))?;
        let src = sources
            .get(&(product.to_string(), block.to_string()))
            .ok_or_else(|| format!("원본에 없는 칸이다: products/{product}.yaml 의 '{block}'"))?;
        let indent = &line[..line.len() - body.len()];
        for l in src {
            out.push(if l.is_empty() {
                String::new()
            } else {
                format!("{indent}{l}")
            });
        }
        let close = format!("{CLOSE}{product} {block}");
        loop {
            let Some(l) = lines.next() else {
                return Err(format!("닫는 울타리가 없다: '{close}'"));
            };
            let b = l.trim();
            if b.starts_with(OPEN.trim_end()) {
                return Err(format!("울타리 안에 울타리: '{b}'"));
            }
            if b == close {
                out.push(l.to_string());
                break;
            }
            if b.starts_with(CLOSE.trim_end()) {
                return Err(format!("이름이 다른 닫는 울타리: '{b}'(기대: '{close}')"));
            }
        }
        n += 1;
    }
    Ok((out.join("\n"), n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(product: &str, text: &str) -> Sources {
        blocks(text)
            .unwrap()
            .into_iter()
            .map(|(b, l)| ((product.to_string(), b), l))
            .collect()
    }

    const ORIGIN: &str = "# 머리 주석 — 칸이 아니다\n# === detect\n- id: running_php\n  subject: process\n\n# === roots\n- \"/usr/bin\"\n\n";

    #[test]
    fn a_fence_takes_the_block_indented_to_the_fence_and_nothing_else_changes() {
        let s = src("php-linux", ORIGIN);
        let rule = "id: a\ndetect:\n  - id: mine\n  # >>> 제품 php-linux detect\n  - id: old\n  # <<< 제품 php-linux detect\nverdict: {}\n";
        let (out, n) = fill(rule, &s).unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            out,
            "id: a\ndetect:\n  - id: mine\n  # >>> 제품 php-linux detect\n  - id: running_php\n    subject: process\n  # <<< 제품 php-linux detect\nverdict: {}\n"
        );
        // 다시 채우면 같다 — 채운 글이 곧 검사의 기대다.
        assert_eq!(fill(&out, &s).unwrap().0, out);
    }

    #[test]
    fn a_hand_edit_between_fences_is_undone_and_so_reported() {
        let s = src("php-linux", ORIGIN);
        let good = fill(
            "x:\n  # >>> 제품 php-linux roots\n  # <<< 제품 php-linux roots\n",
            &s,
        )
        .unwrap()
        .0;
        let edited = good.replace("/usr/bin", "/usr/local/bin");
        assert_ne!(
            fill(&edited, &s).unwrap().0,
            edited,
            "손으로 고친 울타리 사이는 원본과 달라야 한다"
        );
    }

    #[test]
    fn broken_fences_stop_the_check() {
        let s = src("php-linux", ORIGIN);
        let cases = [
            (
                "x:\n  # >>> 제품 php-linux detect\n  - id: a\n",
                "닫는 울타리가 없다",
            ),
            ("x:\n  # <<< 제품 php-linux detect\n", "여는 줄 없는"),
            (
                "x:\n  # >>> 제품 php-linux nope\n  # <<< 제품 php-linux nope\n",
                "원본에 없는 칸",
            ),
            (
                "x:\n  # >>> 제품 node-linux detect\n  # <<< 제품 node-linux detect\n",
                "원본에 없는 칸",
            ),
            ("x:\n  # >>> 제품 php-linux\n", "'<제품> <칸>'"),
            (
                "x:\n  # >>> 제품 php-linux detect\n  # >>> 제품 php-linux roots\n",
                "울타리 안에 울타리",
            ),
            (
                "x:\n  # >>> 제품 php-linux detect\n  # <<< 제품 php-linux roots\n",
                "이름이 다른 닫는 울타리",
            ),
            ("x:\r\n  # >>> 제품 php-linux detect\r\n", "CRLF"),
        ];
        for (rule, want) in cases {
            let e = fill(rule, &s).unwrap_err();
            assert!(e.contains(want), "{rule:?} → {e}");
        }
    }

    #[test]
    fn a_rule_without_fences_is_left_alone() {
        let s = src("php-linux", ORIGIN);
        let rule = "id: a\n# 제품 php-linux 를 말하는 주석\n";
        assert_eq!(fill(rule, &s).unwrap(), (rule.to_string(), 0));
    }

    #[test]
    fn origin_blocks_drop_the_head_and_trailing_blank_lines_and_refuse_bad_names() {
        let b = blocks(ORIGIN).unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].0, "detect");
        assert_eq!(b[0].1, ["- id: running_php", "  subject: process"]);
        assert_eq!(b[1].1, ["- \"/usr/bin\""]);
        for (text, want) in [
            ("# === a\nx\n# === a\ny\n", "같은 이름"),
            ("# === a b\nx\n", "낱말 하나"),
            ("# === a\n\n", "빈 칸"),
        ] {
            assert!(blocks(text).unwrap_err().contains(want), "{text:?}");
        }
    }
}
