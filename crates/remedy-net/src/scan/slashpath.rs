//! 슬래시 경로 — 이미지 · 컨테이너 안의 경로는 이 프로그램이 Windows 에서 돌아도 `/` 로 가른다.
//!
//! 사내 runtime-scanner 는 Go 의 `path` 패키지(`Base` · `Clean` · `Dir` · `Join`)로 이 경로를 다룬다. 같은 입력에
//! 같은 판정을 내려면 경계의 모양(빈 글 · `/` 뿐인 글 · 끝의 `/` · `..`)까지 같아야 해서 그 규칙을 그대로 옮겼다.
//! 파일 시스템을 보지 않는 글자 계산이다 — 링크를 따르지 않는다.

/// 마지막 요소. 끝의 `/` 를 떼고 본다 — 빈 글이면 `.`, `/` 뿐이면 `/`.
pub fn base(path: &str) -> &str {
    if path.is_empty() {
        return ".";
    }
    let trimmed = path.trim_end_matches('/');
    let last = match trimmed.rfind('/') {
        Some(i) => &trimmed[i + 1..],
        None => trimmed,
    };
    if last.is_empty() {
        "/"
    } else {
        last
    }
}

/// 글자만으로 줄인 경로 — 겹친 `/` 를 하나로, `.` 를 빼고, 앞 요소와 짝지은 `..` 를 지운다. 뿌리(`/`)에서 시작한
/// 경로의 앞쪽 `..` 는 사라진다(`/..` → `/`). 남는 것이 없으면 `.`.
pub fn clean(path: &str) -> String {
    let src = path.as_bytes();
    if src.is_empty() {
        return ".".to_string();
    }
    let rooted = src[0] == b'/';
    let n = src.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    // `dotdot` 는 지워서는 안 되는 앞부분의 끝 — 뿌리의 `/` 나, 뿌리가 없는 경로의 앞쪽 `..` 들.
    let (mut r, mut dotdot) = (0usize, 0usize);
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }
    while r < n {
        if src[r] == b'/' || (src[r] == b'.' && (r + 1 == n || src[r + 1] == b'/')) {
            // 겹친 `/` 와 `.` 요소는 건너뛴다.
            r += 1;
        } else if src[r] == b'.'
            && src.get(r + 1) == Some(&b'.')
            && (r + 2 == n || src[r + 2] == b'/')
        {
            r += 2;
            if out.len() > dotdot {
                out.pop();
                while out.len() > dotdot && out.last() != Some(&b'/') {
                    out.pop();
                }
                // 남은 `/` 는 다음 요소 앞에서 다시 붙는다 — 여기서는 뗀다.
                if out.len() > dotdot && out.last() == Some(&b'/') {
                    out.pop();
                }
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && src[r] != b'/' {
                out.push(src[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        return ".".to_string();
    }
    // 요소 단위로만 붙이고 떼므로 UTF-8 이 깨지지 않는다.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// 마지막 요소를 뺀 나머지를 [`clean`] 한 것. `/` 가 없으면 `.`.
pub fn dir(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => clean(&path[..=i]),
        None => ".".to_string(),
    }
}

/// 빈 요소를 빼고 `/` 로 이은 뒤 [`clean`] 한다. 요소가 모두 비면 빈 글.
pub fn join(parts: &[&str]) -> String {
    let kept: Vec<&str> = parts.iter().copied().filter(|p| !p.is_empty()).collect();
    if kept.is_empty() {
        return String::new();
    }
    clean(&kept.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_matches_the_go_table() {
        let cases = [
            ("", "."),
            ("abc", "abc"),
            ("abc/def", "abc/def"),
            ("a/b/c", "a/b/c"),
            (".", "."),
            ("..", ".."),
            ("../..", "../.."),
            ("../../abc", "../../abc"),
            ("/abc", "/abc"),
            ("/", "/"),
            ("abc/", "abc"),
            ("abc/def/", "abc/def"),
            ("a/b/c/", "a/b/c"),
            ("./", "."),
            ("../", ".."),
            ("../../", "../.."),
            ("/abc/", "/abc"),
            ("abc//def//ghi", "abc/def/ghi"),
            ("//abc", "/abc"),
            ("///abc", "/abc"),
            ("//abc//", "/abc"),
            ("abc//", "abc"),
            ("abc/./def", "abc/def"),
            ("/./abc/def", "/abc/def"),
            ("abc/.", "abc"),
            ("abc/def/ghi/../jkl", "abc/def/jkl"),
            ("abc/def/../ghi/../jkl", "abc/jkl"),
            ("abc/def/..", "abc"),
            ("abc/def/../..", "."),
            ("/abc/def/../..", "/"),
            ("abc/def/../../..", ".."),
            ("/abc/def/../../..", "/"),
            ("abc/def/../../../ghi/jkl/../../../mno", "../../mno"),
            ("abc/./../def", "def"),
            ("abc//./../def", "def"),
            ("abc/../../././../def", "../../def"),
            ("/../etc/passwd", "/etc/passwd"),
            ("usr/./lib/../bin/php", "usr/bin/php"),
            ("가/나/../다", "가/다"),
        ];
        for (input, want) in cases {
            assert_eq!(clean(input), want, "clean({input:?})");
        }
    }

    #[test]
    fn base_matches_go() {
        let cases = [
            ("", "."),
            (".", "."),
            ("/.", "."),
            ("/", "/"),
            ("////", "/"),
            ("x/", "x"),
            ("abc", "abc"),
            ("abc/def", "def"),
            ("a/b/.x", ".x"),
            ("a/b/c.", "c."),
            ("a/b/c.x", "c.x"),
            ("usr/bin/php8.3", "php8.3"),
            ("C:\\php\\php.exe", "C:\\php\\php.exe"),
        ];
        for (input, want) in cases {
            assert_eq!(base(input), want, "base({input:?})");
        }
    }

    #[test]
    fn dir_matches_go() {
        let cases = [
            ("", "."),
            (".", "."),
            ("/.", "/"),
            ("/", "/"),
            ("////", "/"),
            ("/foo", "/"),
            ("x/", "x"),
            ("abc", "."),
            ("abc/def", "abc"),
            ("a/b/.x", "a/b"),
            ("a/b/c.", "a/b"),
            ("a/b/c.x", "a/b"),
        ];
        for (input, want) in cases {
            assert_eq!(dir(input), want, "dir({input:?})");
        }
    }

    #[test]
    fn join_matches_go() {
        assert_eq!(join(&[]), "");
        assert_eq!(join(&["", ""]), "");
        assert_eq!(join(&["a", "b", "c"]), "a/b/c");
        assert_eq!(join(&["a", "", "c"]), "a/c");
        assert_eq!(join(&["", "b", "c"]), "b/c");
        assert_eq!(join(&["/", "a"]), "/a");
        assert_eq!(join(&["/", ""]), "/");
        assert_eq!(join(&["a/", "b"]), "a/b");
        assert_eq!(join(&["a/", ""]), "a");
        assert_eq!(join(&["usr/lib", "../bin/php"]), "usr/bin/php");
    }
}
