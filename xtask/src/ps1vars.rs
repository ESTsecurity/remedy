//! PowerShell 스크립트에서 **변수 이름 바로 뒤에 한글이 붙은 자리** — `"$n개"`.
//!
//! # 무엇을 막는 검사인가
//!
//! PowerShell 은 큰따옴표 문자열 안의 변수 이름에 한글을 이어 읽는다. `"$n개"` 는 `$n` 의 값 뒤에 `개` 를
//! 붙이지 않고 **정의되지 않은 변수 `n개` 를 빈 문자열로 편다** — `$script:m건` · `$env:OS가` 처럼 범위가
//! 붙어도 같다(Windows PowerShell 5.1 에서 잼). 하네스는 `Set-StrictMode` 를 켜지 않아 오류도 나지 않는다.
//! 2026-11-16 Windows 메뉴 하네스에서 판정 문구의 `$nRules개` 가 그렇게 빈 값이 됐다 — 한 칸은 실패했고(43칸
//! 중 42), 정규식에 쓴 다른 칸은 `(룰 ` 까지의 접두어만 남아 **개수가 틀려도 통과하는 칸**이 됐다.
//!
//! 바르게 쓰는 꼴은 `"${n}개"` · `"$($n)개"` · `"$n 개"` 다. 역따옴표로 막은 `` `$n개 `` 는 변수가 아니다.
//!
//! # 보지 않는 것
//!
//! 줄 전체가 주석(`#`)인 줄 — 설명 글에 `$root가` 라고 적어도 펴지지 않는다. 작은따옴표 문자열 · 줄 끝
//! 주석 · `<# #>` 블록은 가리지 않는다 — 거기서 걸리면 `${n}` 으로 쓰거나 띄어 쓴다(어느 쪽이든 뜻은 같다).
//! 한글로 시작하는 `$변수` 는 붙은 것이 아니라 그런 이름이라 보지 않는다.

use std::path::Path;
use std::process::Command;

pub fn run(root: &Path) -> Result<(), String> {
    let files = tracked_ps1(root)?;
    if files.is_empty() {
        return Err("검사할 .ps1 이 하나도 없다 — `git ls-files` 가 빈 목록을 냈다".into());
    }
    let mut hits = Vec::new();
    for rel in &files {
        let raw =
            std::fs::read(root.join(rel)).map_err(|e| format!("{rel} 을 읽지 못했다: {e}"))?;
        for (i, line) in String::from_utf8_lossy(&raw).lines().enumerate() {
            for var in glued(line) {
                hits.push(format!("{rel}:{}: {var}", i + 1));
            }
        }
    }
    if hits.is_empty() {
        println!(
            "ps1-vars OK — .ps1 {}개에 변수 이름 뒤에 바로 붙은 한글이 없다",
            files.len()
        );
        return Ok(());
    }
    Err(format!(
        "PowerShell 이 변수 이름에 한글을 이어 읽는 자리 {}곳 — `\"$n개\"` 는 빈 변수 `n개` 로 펴진다. \
         `${{n}}개` 로 쓴다\n  {}",
        hits.len(),
        hits.join("\n  ")
    ))
}

/// 추적하는 `.ps1`. `-z` 라 한글 이름이 따옴표 꼴로 바뀌지 않는다.
fn tracked_ps1(root: &Path) -> Result<Vec<String>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--", "*.ps1"])
        .output()
        .map_err(|e| format!("git 을 띄우지 못했다: {e}"))?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        return Err(format!("git ls-files 가 실패했다: {}", why.trim()));
    }
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

/// 한 줄에서 변수 이름 뒤에 한글이 붙은 자리를 그 꼴 그대로(`$n개` · `$script:m건`).
fn glued(line: &str) -> Vec<String> {
    let line = line.strip_prefix('\u{feff}').unwrap_or(line);
    if line.trim_start().starts_with('#') {
        return Vec::new();
    }
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    for (i, c) in chars.iter().enumerate() {
        if *c != '$' || (i > 0 && chars[i - 1] == '`') {
            continue;
        }
        let end = name_end(&chars, i + 1);
        if end > i + 1 && chars.get(end).is_some_and(|c| is_hangul(*c)) {
            out.push(chars[i..=end].iter().collect());
        }
    }
    out
}

/// `$` 다음 `at` 부터 변수 이름이 끝나는 자리 — 앞에 범위(`script:` · `env:`)가 붙을 수 있다.
/// 이름이 없으면(`${` · `$(` · `$변수`) `at` 그대로다.
fn name_end(chars: &[char], at: usize) -> usize {
    let word = |from: usize| {
        chars[from..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
            .count()
    };
    let scope = chars[at..]
        .iter()
        .take_while(|c| c.is_ascii_alphabetic())
        .count();
    let start = if scope > 0 && chars.get(at + scope) == Some(&':') {
        at + scope + 1
    } else {
        at
    };
    match word(start) {
        0 => at,
        n => start + n,
    }
}

fn is_hangul(c: char) -> bool {
    ('\u{AC00}'..='\u{D7A3}').contains(&c)
}

#[cfg(test)]
mod tests {
    use super::glued;

    #[test]
    fn a_variable_glued_to_hangul_is_caught() {
        assert_eq!(glued(r#"Write-Host "결과 $n개""#), ["$n개"]);
        assert_eq!(
            glued(r#"$x = "$script:m건 · $env:OS가 · $_가 · $nRules개""#),
            ["$script:m건", "$env:OS가", "$_가", "$nRules개"]
        );
    }

    #[test]
    fn the_right_spellings_pass() {
        for line in [
            r#""결과 ${n}개""#,
            r#""결과 $($n)개""#,
            r#""결과 $n 개""#,
            r#""결과 $n.Count개 · $a:""#,
            r#""결과 `$n개""#,
            r#""$변수 는 한글로 시작하는 이름이다""#,
            "    # 설명 글의 $root가 는 펴지지 않는다",
            "\u{feff}# 머리말 $n개",
        ] {
            assert!(glued(line).is_empty(), "{line}");
        }
    }
}
