//! 실기기 PE 로 파서를 댄다 (C-1b · 2026-10-27).
//!
//! # 왜 합성 입력만으로는 모자라나
//!
//! 버전 리소스의 자리(머리 6 + NUL 로 끝나는 키 → 4바이트 경계 → 값 → 다시
//! 경계 → 자식)는 **문서를 읽고 적은 규칙**이다. 합성 PE 는 짓는 쪽과 읽는 쪽이
//! 같은 사람의 이해에서 나오므로, 그 이해가 틀렸으면 둘이 함께 틀린다.
//! `tests/peversion_synth.rs` 가 파서의 **갈래**를 어느 플랫폼에서도 재고,
//! 이 시험이 그 **자리**가 실물과 맞는지 잰다.
//!
//! # 오라클이 `.NET` 이 아닌 이유 — 실측으로 갈렸다
//!
//! 처음에는 `[System.Diagnostics.FileVersionInfo]` 를 오라클로 썼다. 그런데
//! `System32\notepad.exe` 에서 갈렸다:
//!
//! | | 값 |
//! |---|---|
//! | **파일이 선언한 것**(바이트) | `10.0.26100.9278` |
//! | `.NET` 이 보고한 것 | `10.0.26100.8457` |
//! | 그 파일을 **복사한 뒤** `.NET` | `10.0.26100.9278` |
//!
//! 같은 바이트인데 **경로에 따라 OS 의 답이 달라진다**(서비싱·사이드바이사이드).
//! 우리는 파일을 읽으므로 오라클도 파일을 읽어야 한다 — PowerShell 의 바이트
//! 탐색이다(다른 언어, 다른 방법, 같은 질문).
//!
//! `"FileVersion"` 이 **한 번만** 나오는 파일만 쓴다. 여러 번 나오면 바이트
//! 탐색이 어느 것인지 가릴 수 없다(`setup_wm.exe` 가 그렇다 — 첫 자리가
//! `MP10_EnsureFileVer` 라는 다른 문자열이다).
//!
//! Windows 밖에서는 건너뛴다 — PE 가 없다.

#![cfg(windows)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// 한 파일에 대한 두 갈래의 독립 관측.
struct Oracle {
    /// 파일 바이트가 선언한 값. `None` = 가릴 수 없다.
    declared: Option<String>,
    /// OS 가 보기에 버전 리소스가 **아예 없다**. 그 자리에서 우리도 `None` 이어야
    /// 한다 — 없는 값을 지어내면 그것이 곧 오탐이다.
    no_resource: bool,
}

/// 파일이 선언한 `FileVersion`, **공백 앞까지**. 경로 → 값.
///
/// *"공백 뒤 주석을 버린다"* 와 *"전부 0 이면 담지 않는다"* 를 여기서 **따로**
/// 구현한다 — 우리 Rust 구현을 우리 Rust 구현으로 대면 아무것도 재지 않는다.
///
/// **줄 번호가 아니라 경로로 짝짓는다.** PowerShell 이 한 파일에서 줄을
/// 빠뜨리면 그 뒤 전부가 한 칸씩 밀려 **엉뚱한 파일의 값과 대게 된다**
/// (2026-10-27 적대 검증).
fn declared(paths: &[String]) -> BTreeMap<String, Oracle> {
    let list = paths.join("\n");
    // 바이트를 UTF-16 로 한 번 펴고 `IndexOf` 로 찾는다. PowerShell 루프로
    // 바이트를 세면 파일 하나에 수백 ms 가 들어 시험이 분 단위가 된다.
    //
    // **두 갈래를 함께 낸다.** 바이트 값(`v`)과 *"OS 가 보기에 버전 리소스가
    // 아예 없다"*(`none`). 전자는 가릴 수 있을 때만 쓰고, 후자는 그 자리에서
    // 우리도 `None` 이어야 한다는 반대 방향 단정이 된다.
    let script = r#"
$ErrorActionPreference='SilentlyContinue'
$input | ForEach-Object {
  $p = $_
  if ($p -eq '') { return }
  $none = '0'
  $v = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p)
  if ($null -ne $v -and [string]::IsNullOrWhiteSpace($v.FileVersion) `
      -and $v.FileMajorPart -eq 0 -and $v.FileMinorPart -eq 0 `
      -and $v.FileBuildPart -eq 0 -and $v.FilePrivatePart -eq 0) { $none = '1' }
  try { $b = [System.IO.File]::ReadAllBytes($p) } catch { "$p`t!`t$none"; return }
  $t = [System.Text.Encoding]::Unicode.GetString($b)
  $i = $t.IndexOf('FileVersion')
  if ($i -lt 0) { "$p`t!`t$none"; return }
  if ($t.IndexOf('FileVersion', $i + 1) -ge 0) { "$p`t!`t$none"; return }
  $tail = $t.Substring($i + 'FileVersion'.Length)
  $s = ($tail -split "`0" | Where-Object { $_ -ne '' } | Select-Object -First 1)
  if ([string]::IsNullOrWhiteSpace($s)) { "$p`t!`t$none"; return }
  $head = ($s.Trim() -split '\s+')[0]
  # **점숫자가 아니면 리소스 키가 아니다.** `aidd.dll` 처럼 디버그 문자열 안에
  # UTF-16 'FileVersion' 이 들어 있는 파일이 있다(실측) — 그 뒤를 버전으로
  # 읽으면 오라클이 거짓말을 한다.
  if ($head -notmatch '^\d+(\.\d+)*$') { "$p`t!`t$none"; return }
  $zeros = $true
  foreach ($q in $head.Split('.')) { if ($q -ne '' -and ($q -replace '0','') -ne '') { $zeros = $false } }
  if ($zeros) { "$p`t!`t$none" } else { "$p`t$head`t$none" }
}
"#;
    let mut child = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("powershell");
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(list.as_bytes())
            .expect("write");
    }
    let out = child.wait_with_output().expect("wait");
    let mut map = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.trim_end().split('\t');
        let (Some(p), Some(v), Some(none)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        map.insert(
            p.to_string(),
            Oracle {
                declared: if v == "!" || v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                },
                no_resource: none == "1",
            },
        );
    }
    map
}

/// 뿌리마다 **몫을 따로** 모은다.
///
/// 한 상한으로 깊이 우선으로 모으면 먼저 닿은 뿌리가 표본을 다 먹는다 — 처음
/// 판이 그래서 `System32` 에 한 번도 닿지 않았다(2026-10-27 적대 검증). 공급사
/// 마다 문자열 모양이 달라 한쪽만 보면 23.9% 의 주석 꼬리를 못 밟는다.
fn sample(per_root: usize) -> Vec<String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let mut roots = vec![Path::new(&root).join("System32")];
    for d in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Ok(p) = std::env::var(d) {
            roots.push(Path::new(&p).to_path_buf());
        }
    }

    let mut out = Vec::new();
    for r in roots {
        let mut taken = 0usize;
        let mut stack = vec![r];
        while let Some(dir) = stack.pop() {
            if taken >= per_root {
                break;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                if taken >= per_root {
                    break;
                }
                let p = e.path();
                let Ok(md) = e.metadata() else { continue };
                if md.is_dir() {
                    stack.push(p);
                    continue;
                }
                let s = p.to_string_lossy().to_string();
                if !remedy_collect::peversion::should_read(&s) {
                    continue;
                }
                // 오라클이 파일을 통째로 읽는다. 상한이 없으면 시험이 길어진다.
                if md.len() > 8 * 1024 * 1024 {
                    continue;
                }
                out.push(s);
                taken += 1;
            }
        }
    }
    out
}

#[test]
fn 실물_pe_가_선언한_버전을_그대로_읽는다() {
    let paths = sample(250);
    assert!(paths.len() > 200, "PE 를 {}개만 찾았다", paths.len());
    // 뿌리마다 몫을 따로 모았는지 — `System32` 가 표본에 있어야 한다.
    assert!(
        paths.iter().any(|p| p.to_lowercase().contains("system32")),
        "표본에 System32 가 없다 — 한 뿌리가 몫을 다 먹었다"
    );

    let want = declared(&paths);
    let mut agreed = 0usize;
    let mut skipped = 0usize;
    let mut empty_agreed = 0usize;
    let mut mismatch = Vec::new();
    for p in &paths {
        let Ok(bytes) = std::fs::read(p) else {
            continue;
        };
        let got = remedy_collect::peversion::of(p, &bytes);
        let Some(o) = want.get(p) else { continue };
        if let Some(w) = &o.declared {
            match &got {
                Some(a) if a == w => agreed += 1,
                // **`None` 도 불일치다.** 파일이 선언한 버전을 우리가 놓치면 그
                // 파일에 걸린 버전 점검이 조용히 거짓이 된다.
                _ => mismatch.push(format!("{p}: 우리 {got:?} ≠ 파일 {w:?}")),
            }
            continue;
        }
        // 바이트로는 가릴 수 없다. **그래도 반대 방향은 잴 수 있다** — OS 가
        // 리소스 자체가 없다고 하면 우리도 값을 내서는 안 된다.
        if o.no_resource {
            match &got {
                None => empty_agreed += 1,
                Some(v) => mismatch.push(format!("{p}: 리소스가 없는데 {v:?} 를 냈다")),
            }
        } else {
            skipped += 1;
        }
    }

    assert!(
        mismatch.is_empty(),
        "파일이 선언한 것과 다른 값을 낸 것이 {}건이다 (대상 {} · 가릴 수 없음 {skipped}):\n  {}",
        mismatch.len(),
        paths.len(),
        mismatch
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    // **공허하지 않은가.** 오라클이 전부 비면 위 단정은 언제나 참이다.
    assert!(
        agreed >= 100,
        "맞힌 것이 {agreed}개뿐이다 (대상 {} · 가릴 수 없음 {skipped}) — 오라클이 \
         아무것도 보지 않거나 파서가 자리를 못 찾고 있다",
        paths.len()
    );
    // 담긴 값에 공백이 남으면 주석을 버리지 않은 것이다.
    for p in &paths {
        let Ok(bytes) = std::fs::read(p) else {
            continue;
        };
        if let Some(v) = remedy_collect::peversion::of(p, &bytes) {
            assert!(
                !v.contains(char::is_whitespace),
                "{p}: 담긴 값에 공백이 남았다 — {v:?}"
            );
        }
    }
    eprintln!(
        "실물 PE 대조: {agreed} 일치 · 리소스 없음 {empty_agreed} 일치 · \
         가릴 수 없음 {skipped} / 대상 {}",
        paths.len()
    );
}
