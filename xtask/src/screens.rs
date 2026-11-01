//! `cargo xtask screens` — **고객이 읽는 화면에 쓰지 않기로 한 말이 돌아왔는가.**
//!
//! # 왜 이것이 따로 있는가
//!
//! 2026-10-28 에 사람이 `--help-all` 의 한 줄을 읽고 짚었다 — `--state-dir`
//! 설명이 *"되돌리기가 사는 곳이다"* 였다. 폴더를 의인화하고(비유), 동작을
//! 주어로 세우고(명사화), `저널` 이라는 엔진 낱말을 썼다.
//!
//! **그 줄을 게이트 아홉 개 중 하나도 읽지 않았다.** 기준선은 `--help-all` 을
//! 줄 **수**로만 적었고(그 뒤 담았다), `console-doc` 은 문서가 인용한 줄만
//! 대조하며, 시연 게이트는 종료 코드 **개수**를 센다. 전체로는 출하 `src/` 의
//! 한글 문자열 1,588개 가운데 기준선이 담은 것이 231개(15%)다 — 나머지는
//! **어느 게이트도 낱말을 보지 않는다.**
//!
//! `console-diff` 는 *"전과 달라졌는가"* 를 잡는다. 이 검사는 다른 것을 잡는다 —
//! **처음부터 틀린 말이 들어오는 것.** 둘이 겹치지 않으므로 둘 다 있다
//! (목표 `remedy_20261028` 결정 11 = (c)).
//!
//! # 범위 — 고객 화면 + `--help-all`
//!
//! 결정 8 = (b) 다. `crates/*/src/**/*.rs` 를 보되 아래를 뺀다:
//!
//! | 빼는 것 | 왜 |
//! |---|---|
//! | `#[cfg(test)]` 모듈 | 시험의 실패 문구는 사람이 읽는 화면이 아니다 |
//! | `tests.rs` | 같은 이유 (`remedy-report` 가 이 이름을 쓴다) |
//! | `lint.rs` · `generate.rs` | **플러그인 작성자 도구**다. 결정 8 이 (c)가 아니라 (b)여서 범위 밖이고, 말투도 해라체로 갈라져 있다 |
//! | 주석 줄 | 화면이 아니다. 비유가 적혀 있어도 둔다 |
//!
//! `crates/*/tests/` 는 애초에 보지 않는다 — `src/` 만 걷는다.

use crate::console::{is_hangul, string_pieces};
use std::path::Path;

/// 쓰지 않기로 한 말. **하나라도 나오면 실패다.**
///
/// 전부 2026-10-28 에 실제로 화면에 있었고 그 회차에 고친 것들이다. 목록은
/// *"앞으로 쓰지 말자"* 가 아니라 **"고친 것이 돌아오지 않게"** 다 — 그래서 지금
/// 0 인 것만 들어온다. 아직 쓰는 말은 [`KNOWN`] 이 센다.
const FORBIDDEN: &[(&str, &str)] = &[
    ("사는 곳", "폴더를 의인화한다 — \"무엇이 있는 폴더\" 로 쓴다"),
    (
        "파괴",
        "전용백신이 고객에게 쓰는 말이 아니다 — `삭제` · `삭제·변경`",
    ),
    (
        "syscall",
        "개발자 낱말이다 — \"이 운영체제에서는 이 값을 바꿀 수 없습니다\"",
    ),
    ("열쇠", "영문이 이미 `Keys` 다 — `키`"),
    ("되살리지", "`복원 불가` · `복원할 수 없는`"),
    ("기계를 만지는", "비유다 — `시스템을 변경하는`"),
    ("늘어놓", "구어다 — `보여 준다`"),
    ("손에 들고", "비유다 — `배포 전에 직접`"),
    ("금고", "격리 보관 자리는 `격리소` 하나로 부른다"),
    (
        "꾸러미",
        "지원 번들은 `지원 번들`, 플러그인 쪽은 `플러그인 번들` 이다 (범위 안에서 0 임을 2026-10-28 에 쟀다)",
    ),
    ("Destruction", "같은 까닭으로 영문도 쓰지 않는다"),
    ("destroyed", "같은 까닭으로 영문도 쓰지 않는다"),
    ("destructive", "같은 까닭으로 영문도 쓰지 않는다"),
    ("no syscall", "같은 까닭으로 영문도 쓰지 않는다"),
    ("This place", "장소를 `folder` 로 부른다"),
];

/// **아직 쓰는 말.** 세어서 보이고, **늘면 실패다.**
///
/// # 왜 지우지 않고 세는가
///
/// 이 자리를 비워 두면 *"금지 목록에 없으니 괜찮다"* 가 된다. 2026-10-26 에
/// `console-doc` 이 같은 실수를 했다 — 대조하지 않는 줄을 조용히 넘겼고, 그
/// 자리가 다 낡은 뒤에 사람이 읽어서야 드러났다. 그래서 **남은 것도 수로 적고
/// 그 수를 묶는다.**
///
/// 수가 줄면 실패가 아니다(보고만 한다 — 기대값을 내리라고 적는다). 늘면
/// 실패다. 바꾸기로 하면 그 회차에 이 표에서 빼고 [`FORBIDDEN`] 으로 옮긴다.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "회차",
        8,
        "결정 9 가 (b) 로 유보했다 — 하네스 셋이 이 낱말을 정규식으로 읽는다(값이 아니라 판정이 흔들린다)",
    ),
    (
        "흔적",
        1,
        "같은 까닭 — `trunc-verify` 가 `흔적 [0-9]*건` 을 읽는다",
    ),
    (
        "5층",
        1,
        "`derive.rs` 의 미룸 사유가 설계 절을 인용하는 **관례**다(`2층` 도 같은 모양). `Invoke-P10Verify.ps1` 이 판정에 쓴다 — 설계 절 인용을 고객 사유에 둘 것인가는 따로 정할 일",
    ),
    ("2층", 2, "위와 같은 관례"),
    (
        "wrap",
        14,
        "격리 컨테이너의 겹. 프로토콜 이름(`remedy.wrap.v1`)과 같은 말이라 영문도 `wrap` 이다",
    ),
    (
        "저널",
        6,
        "고객 화면의 엔진 낱말(`저널을 쓸 수 없습니다`). 2026-10-28 의 23곳 밖이었다",
    ),
    (
        "격리물",
        5,
        "고객 화면 넷이 함께 쓴다 — 한 곳만 바꾸면 한 개념이 두 이름이 된다",
    ),
];

/// 범위 밖 파일 — 플러그인 작성자 도구. 머리말의 표에 까닭이 있다.
const AUTHOR_TOOLS: &[&str] = &["lint.rs", "generate.rs"];

struct Hit {
    origin: String,
    word: &'static str,
    text: String,
}

pub fn run(root: &Path) -> Result<(), String> {
    let mut strings = 0usize;
    let mut bad: Vec<Hit> = Vec::new();
    let mut seen: Vec<usize> = vec![0; KNOWN.len()];

    for (rel, text) in sources(root)? {
        for (no, line) in screen_lines(&text) {
            for piece in string_pieces(line) {
                // **화면이 될 수 있는 것만 센다.** 한글이 있거나, 빈칸이 있는
                // 영문(= 사람이 읽는 문장)이다. 빈칸 없는 영문은 필드 이름·경로·
                // 서식 치환자라 화면이 아니다.
                let prose = piece.contains(' ');
                if !piece.chars().any(is_hangul) && !prose {
                    continue;
                }
                strings += 1;
                let origin = format!("{rel}:{no}");
                for (word, why) in FORBIDDEN {
                    // **영문 패턴은 산문에만 건다.** `destructive` 를 그냥 걸면
                    // `"destructive_ops"` 같은 **JSON 키**에 걸려 멀쩡한 스키마가
                    // 게이트를 깬다 — 식별자에는 빈칸이 없다는 것이 가르는 선이다.
                    if !word.chars().any(is_hangul) && !prose {
                        continue;
                    }
                    if piece.contains(word) {
                        bad.push(Hit {
                            origin: origin.clone(),
                            word,
                            text: format!("{piece}  ← {why}"),
                        });
                    }
                }
                for (i, (word, _, _)) in KNOWN.iter().enumerate() {
                    if piece.contains(word) {
                        seen[i] += 1;
                    }
                }
            }
        }
    }

    let grown: Vec<String> = KNOWN
        .iter()
        .zip(&seen)
        .filter(|((_, cap, _), got)| *got > cap)
        .map(|((w, cap, why), got)| format!("  {w}  {cap} → {got}\n      {why}"))
        .collect();
    let shrunk: Vec<String> = KNOWN
        .iter()
        .zip(&seen)
        .filter(|((_, cap, _), got)| *got < cap)
        .map(|((w, cap, _), got)| format!("{w} {cap}→{got}"))
        .collect();

    if bad.is_empty() && grown.is_empty() {
        println!(
            "screens OK — 화면 문자열 {strings}개에 쓰지 않기로 한 말 0개 (금지 {}가지)",
            FORBIDDEN.len()
        );
        let still: Vec<String> = KNOWN
            .iter()
            .zip(&seen)
            .map(|((w, _, _), got)| format!("{w} {got}"))
            .collect();
        println!("  아직 쓰는 말 {}가지: {}", KNOWN.len(), still.join(" · "));
        if !shrunk.is_empty() {
            println!(
                "  줄었다 — `KNOWN` 의 기대값을 같은 회차에 내릴 것: {}",
                shrunk.join(" · ")
            );
        }
        return Ok(());
    }

    let mut msg = String::new();
    if !bad.is_empty() {
        msg.push_str(&format!(
            "고객 화면에 쓰지 않기로 한 말이 {}곳 있다:",
            bad.len()
        ));
        for h in bad.iter().take(30) {
            msg.push_str(&format!("\n  {} [{}]\n      {}", h.origin, h.word, h.text));
        }
        if bad.len() > 30 {
            msg.push_str(&format!("\n  … 그 밖 {}곳", bad.len() - 30));
        }
        msg.push_str(
            "\n\n이 목록은 2026-10-28 에 화면에서 실제로 고친 말들이다. 다시 쓰려면\n\
             `FORBIDDEN` 에서 빼는 것이 아니라 **왜 그 말이어야 하는지**를 적고\n\
             목표 파일의 결정을 다시 열 것.",
        );
    }
    if !grown.is_empty() {
        if !msg.is_empty() {
            msg.push('\n');
            msg.push('\n');
        }
        msg.push_str("아직 쓰는 말이 늘었다:\n");
        msg.push_str(&grown.join("\n"));
        // **실패할 때도 전부 보인다.** 늘어난 것만 보이면 기대값을 고치려는
        // 사람이 나머지를 다시 재야 한다 — 그 한 번이 틀리면 또 빨개진다.
        let all: Vec<String> = KNOWN
            .iter()
            .zip(&seen)
            .map(|((w, cap, _), got)| format!("{w} {cap}→{got}"))
            .collect();
        msg.push_str(&format!("\n\n  지금 수 전부: {}", all.join(" · ")));
        msg.push_str(
            "\n\n늘어난 것이 옳다면(새 화면이 그 낱말을 쓸 수밖에 없다면) `KNOWN` 의\n\
             기대값을 같은 회차에 올릴 것. 그냥 쓴 것이면 그 낱말을 피할 것.",
        );
    }
    Err(msg)
}

/// 범위 안의 `src/**/*.rs` 를 (저장소 상대 경로, 본문)으로 모은다.
fn sources(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut dirs = vec![root.join("crates")];
    while let Some(d) = dirs.pop() {
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                let name = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                // `tests` 와 `target` 은 들어가지 않는다. `src` 아래만 본다.
                if name == "target" || name == "tests" || name == "benches" {
                    continue;
                }
                dirs.push(p);
                continue;
            }
            if p.extension().is_none_or(|x| x != "rs") {
                continue;
            }
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name == "tests.rs" || AUTHOR_TOOLS.contains(&name.as_str()) {
                continue;
            }
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            // `src/` 아래가 아니면 보지 않는다 — 빌드 스크립트·예제는 화면이 아니다.
            if !rel.contains("/src/") {
                continue;
            }
            let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            out.push((rel, text));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// 화면이 될 수 있는 줄만 (1부터 센 줄 번호, 줄)로 돌려준다.
///
/// 주석 줄과 `#[cfg(test)]` 모듈을 뺀다. 시험 모듈은 **중괄호를 세어** 끝을
/// 찾는다 — `#[cfg(test)]` 다음의 `mod ... {` 부터 짝이 맞는 `}` 까지다.
fn screen_lines(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut in_test = false;
    let mut depth = 0usize;
    let mut armed = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if in_test {
            depth += line.matches('{').count();
            depth = depth.saturating_sub(line.matches('}').count());
            if depth == 0 {
                in_test = false;
            }
            continue;
        }
        if t.starts_with("#[cfg(test)]") {
            armed = true;
            continue;
        }
        if armed {
            // 바로 다음의 `mod ... {` 이 시험 모듈이다. 한 줄에 `{` 가 없으면
            // 다음 줄까지 기다린다.
            if line.contains('{') {
                armed = false;
                in_test = true;
                depth = line.matches('{').count() - line.matches('}').count();
                if depth == 0 {
                    in_test = false;
                }
            }
            continue;
        }
        if t.starts_with("//") {
            continue;
        }
        out.push((i + 1, line));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{screen_lines, FORBIDDEN, KNOWN};

    fn kept(src: &str) -> Vec<&str> {
        screen_lines(src).into_iter().map(|(_, l)| l).collect()
    }

    /// **범위가 이 검사의 전부다.** 시험 모듈 안의 실패 문구에는 `파괴` 가
    /// 있고(그래야 하는 글이다), 그것이 걸리면 게이트는 영원히 빨갛다.
    #[test]
    fn a_test_module_is_not_a_screen() {
        let src = "let a = \"화면\";\n\
                   #[cfg(test)]\n\
                   mod tests {\n\
                   fn t() { assert!(x, \"파괴가 계획됐다\"); }\n\
                   }\n\
                   let b = \"다시 화면\";\n";
        let k = kept(src);
        assert!(k.iter().any(|l| l.contains("화면")), "{k:?}");
        assert!(k.iter().any(|l| l.contains("다시 화면")), "{k:?}");
        assert!(!k.iter().any(|l| l.contains("파괴")), "{k:?}");
    }

    /// `#[cfg(test)]` 와 `mod ... {` 가 **다른 줄**인 모양. 한 줄만 보고
    /// 끝내면 그다음 줄부터 전부 화면으로 읽힌다.
    #[test]
    fn the_brace_may_sit_on_the_next_line() {
        let src = "#[cfg(test)]\n\
                   mod tests\n\
                   {\n\
                   let x = \"파괴\";\n\
                   }\n\
                   let y = \"화면\";\n";
        let k = kept(src);
        assert!(!k.iter().any(|l| l.contains("파괴")), "{k:?}");
        assert!(k.iter().any(|l| l.contains("화면")), "{k:?}");
    }

    /// 중첩된 중괄호를 세지 못하면 시험 모듈이 **일찍 끝난 것으로** 보인다.
    #[test]
    fn nesting_does_not_end_the_module_early() {
        let src = "#[cfg(test)]\n\
                   mod tests {\n\
                   fn a() { if x { y(); } }\n\
                   let z = \"파괴\";\n\
                   }\n\
                   let w = \"화면\";\n";
        let k = kept(src);
        assert!(!k.iter().any(|l| l.contains("파괴")), "{k:?}");
        assert!(k.iter().any(|l| l.contains("화면")), "{k:?}");
    }

    #[test]
    fn comment_lines_are_not_screens() {
        let k = kept("// 여기는 파괴라고 적어도 된다\nlet a = \"화면\";\n");
        assert_eq!(k.len(), 1, "{k:?}");
    }

    /// 두 목록이 겹치면 한쪽이 거짓말을 한다 — 금지인데 "아직 쓴다" 고 세거나,
    /// 세면서 실패시킨다.
    #[test]
    fn the_two_lists_do_not_overlap() {
        for (f, _) in FORBIDDEN {
            for (k, _, _) in KNOWN {
                assert!(
                    !f.contains(k) && !k.contains(f),
                    "금지 {f:?} 와 아직 쓰는 말 {k:?} 가 겹친다"
                );
            }
        }
    }
}
