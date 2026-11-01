//! 설정 파일에서 오는 subject 들 (설계-09 P4).
//!
//! `hosts_entry` 는 자리가 정해져 있고, `text_config` 와 `structured_config` 는
//! **선언된 `scan_roots` 안에서만** 본다. 설정 파일은 어디에나 있어서 상한이
//! 없으면 사용자 문서까지 통째로 스냅샷에 들어간다.
//!
//! # 왜 줄 단위인가
//!
//! 설계-03 §2 의 치료 순서에는 **부분 편집**이 있다. `Userinit` 처럼 통째로
//! 지우면 시스템을 못 쓰게 되는 값이 오히려 주류이고, 그것을 다루려면 룰이
//! "이 줄" 을 지목할 수 있어야 한다. 파일 하나를 값 하나로 담으면 그 자리가 없다.

use remedy_artifacts::{
    CollectError, Harvest, HostsEntryRecord, Scope, StructuredConfigRecord, TextConfigRecord,
};
use remedy_platform::read::{EnvRead, FsRead};
use remedy_sdk::catalog::Subject;
use remedy_sdk::normalize;

/// 줄 단위로 읽을 확장자. 넓히면 스냅샷이 커지고 개인정보 위험이 올라간다.
///
/// # `.htaccess` 는 확장자가 아니라 **이름 전체**다 (2026-10-27 · C-5)
///
/// [`files_with_ext`] 가 `ends_with` 로 거르므로 이름이 그대로 들어온다.
/// 그것이 필요한 이유는 **디렉터리별 PHP 설정이 거기 있기** 때문이다 —
/// `php_value` · `php_admin_value` 로 `php.ini` 를 덮어쓰고, 그 자리는 웹
/// 디렉터리라 공격자가 쓸 수 있다(공개 권고의 노출 조건 중 하나).
///
/// `.user.ini`(PHP 자신의 디렉터리별 INI)는 **이미 `.ini` 로 걸린다.**
///
/// `.htpasswd` 는 **넣지 않는다.** 그 파일은 비밀번호 해시이고, 줄 단위로 담으면
/// 스냅샷이 자격증명을 들고 다닌다.
const TEXT_EXT: [&str; 7] = [
    ".ini",
    ".conf",
    ".cfg",
    ".inf",
    ".properties",
    ".env",
    ".htaccess",
];
const STRUCTURED_EXT: [&str; 1] = [".json"];

/// 파일 하나에서 담을 줄 수 상한.
///
/// 상한이 없으면 로그 한 개가 스냅샷을 통째로 먹는다. 넘으면 **잘렸다고
/// 말한다** — 조용히 자르면 그 아래 줄을 겨눈 룰이 왜 안 맞는지 알 수 없다.
const MAX_LINES_PER_FILE: usize = 2_000;

/// 설정 파일 하나의 크기 상한. 넘으면 아예 읽지 않는다.
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// 설정 파일 하나를 읽는다. **읽지 못한 이유를 잃지 않는다.**
///
/// 오래 이 자리가 `let Ok(Some(b)) = fs.read_file(..) else { continue }` 였다.
/// 그러면 서로 다른 셋이 한 줄로 접힌다 —
///
/// | 실제로 일어난 일 | 그때 보고한 것 | 지금 |
/// |---|---|---|
/// | 4 MiB 를 넘어 한 바이트도 읽지 않았다 | **없음** | 잘림(`truncated`) |
/// | 열지 못했다(권한·I/O) | **없음** | 거부(`denied_dirs`) |
/// | 읽었다 | 내용 | 내용 |
///
/// 앞의 둘은 **종료 코드 6 의 근거**인데 어느 쪽도 서지 않아, 상한을 넘은
/// `php.ini` 가 있는 기계가 *"그 설정에 아무것도 없다"* 로 끝났다. 하필 `file`
/// subject 가 그 파일의 존재와 크기를 담고 있어서 **스냅샷만 봐서는 모순이
/// 보이지 않는다** — 파일은 있는데 그 파일에서 온 줄이 0건이다.
///
/// `Ok(None)` 을 거부가 아니라 잘림으로 세는 이유: 거부의 사유 줄은
/// *"관리자 권한으로 다시 돌리십시오"* 인데 상한 초과에는 틀린 안내다.
fn read_config<P: FsRead, T>(fs: &P, path: &str, h: &mut Harvest<T>) -> Option<Vec<u8>> {
    match fs.read_file(path, MAX_CONFIG_BYTES) {
        Ok(Some(b)) => Some(b),
        Ok(None) => {
            h.truncated = true;
            None
        }
        Err(_) => {
            h.deny(path);
            None
        }
    }
}

/// 텍스트로 읽는다. UTF-8 이 아니면 그 사실이 드러나야 하므로 lossy 로 읽되,
/// **BOM 은 떼어 낸다** — 첫 줄의 키 이름 앞에 보이지 않는 문자가 붙으면
/// `key equals "Shell"` 이 조용히 안 맞는다.
fn to_text(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.strip_prefix('\u{feff}').unwrap_or(&s).to_string()
}

/// hosts 파일.
///
/// **자리가 플랫폼마다 다르다.** Windows 경로 하나만 보던 동안 Linux 수집은
/// 펼쳐지지 않은 토큰을 경로로 삼아 0건에 `denied_dirs += 1` 을 냈다 —
/// 카탈로그는 이 subject 를 Linux 에서 수집한다고 적어 두고 있었다.
pub fn hosts_entries<P: FsRead + EnvRead>(
    fs: &P,
    scope: &Scope,
) -> Result<Harvest<HostsEntryRecord>, CollectError> {
    let mut h = Harvest::default();
    let path = match scope.platform {
        remedy_sdk::catalog::Platform::Windows => {
            fs.expand("%SystemRoot%\\System32\\drivers\\etc\\hosts")
        }
        _ => "/etc/hosts".to_string(),
    };
    if !fs.exists(&path) {
        // 이 파일은 어느 기계에나 있다. 없으면 못 읽은 것이다.
        h.deny(&path);
        return Ok(h);
    }
    let Some(bytes) = read_config(fs, &path, &mut h) else {
        return Ok(h);
    };
    for (i, raw) in to_text(&bytes).lines().enumerate() {
        // 주석은 담지 않는다. 담으면 "이 도메인이 hosts 에 있다" 를 묻는 룰이
        // 주석 처리된 줄에도 걸린다.
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        let names: Vec<String> = parts.map(normalize::nfc).collect();
        if names.is_empty() {
            continue;
        }
        h.records.push(HostsEntryRecord {
            ip: ip.to_string(),
            hostnames: names,
            line_no: (i + 1) as u32,
            source: path.clone(),
            // **원본 줄을 그대로 담는다.** 재구성하면 탭·연속 공백이 사라져
            // 실행기의 "계획과 같은 줄인가" 비교가 걸린다 (record.rs 참조).
            line: line.to_string(),
        });
    }
    Ok(h)
}

/// ini·conf 계열의 줄.
pub fn text_configs<P: FsRead>(
    fs: &P,
    scope: &Scope,
) -> Result<Harvest<TextConfigRecord>, CollectError> {
    let mut h = Harvest::default();
    for path in text_config_files(fs, scope, &mut h)? {
        let Some(bytes) = read_config(fs, &path, &mut h) else {
            continue;
        };
        let mut section = String::new();
        for (i, raw) in to_text(&bytes).lines().enumerate() {
            if i >= MAX_LINES_PER_FILE {
                h.truncated = true;
                break;
            }
            let line = raw.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                section = name.trim().to_string();
                continue;
            }
            // `키=값` 이 아닌 줄도 담는다. 값 없는 지시어만 있는 설정이 흔하고,
            // 그것을 버리면 `line contains` 를 쓰는 룰이 못 본다.
            let (key, value) = match line.split_once('=') {
                Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
                None => (String::new(), String::new()),
            };
            h.records.push(TextConfigRecord {
                path: path.clone(),
                line_no: (i + 1) as u32,
                line: normalize::nfc(line),
                section: section.clone(),
                key,
                value,
            });
        }
    }
    h.records
        .sort_by(|a, b| (&a.path, a.line_no).cmp(&(&b.path, b.line_no)));
    Ok(h)
}

/// JSON 설정의 잎.
pub fn structured_configs<P: FsRead>(
    fs: &P,
    scope: &Scope,
) -> Result<Harvest<StructuredConfigRecord>, CollectError> {
    let mut h = Harvest::default();
    for path in files_with_ext(
        fs,
        scope,
        Subject::StructuredConfig,
        &STRUCTURED_EXT,
        &mut h,
    )? {
        let Some(bytes) = read_config(fs, &path, &mut h) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&to_text(&bytes)) else {
            // 파싱 실패는 잡음이 아니다 — 깨진 JSON 을 심어 두는 것도 수법이다.
            // 다만 잎이 없으므로 담을 것도 없다. `file` subject 가 그 파일의
            // 존재와 해시를 이미 담고 있다.
            continue;
        };
        let mut leaves = Vec::new();
        flatten(&v, "", &mut leaves);
        for (key_path, value) in leaves {
            if h.records.len() >= scope.max_files {
                h.truncated = true;
                break;
            }
            h.records.push(StructuredConfigRecord {
                path: path.clone(),
                format: "json".into(),
                key_path,
                value,
            });
        }
    }
    h.records
        .sort_by(|a, b| (&a.path, &a.key_path).cmp(&(&b.path, &b.key_path)));
    Ok(h)
}

/// 잎마다 `a.b.0.c` 형태의 경로를 만든다.
fn flatten(v: &serde_json::Value, prefix: &str, out: &mut Vec<(String, String)>) {
    let join = |p: &str, k: &str| {
        if p.is_empty() {
            k.to_string()
        } else {
            format!("{p}.{k}")
        }
    };
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                flatten(val, &join(prefix, k), out);
            }
        }
        serde_json::Value::Array(a) => {
            for (i, val) in a.iter().enumerate() {
                flatten(val, &join(prefix, &i.to_string()), out);
            }
        }
        serde_json::Value::String(s) => out.push((prefix.to_string(), normalize::nfc(s))),
        serde_json::Value::Null => out.push((prefix.to_string(), String::new())),
        other => out.push((prefix.to_string(), other.to_string())),
    }
}

/// `text_config` 가 읽을 파일 — **접미사로 걸린 것 + 옵트인 디렉터리의 전부.**
///
/// 둘로 갈린 이유는 **축이 다르기** 때문이다.
///
/// | 축 | 누가 정하는가 | 왜 |
/// |---|---|---|
/// | 접미사 (`.conf` · `.htaccess` …) | **코어** ([`TEXT_EXT`]) | 배포판과 무관하다. 매니페스트가 정하면 같은 목록을 플러그인마다 적는다 |
/// | 디렉터리 (`/etc/pam.d`) | **매니페스트** (`text_config_dirs`) | 자리가 배포판마다 다르다. 코어가 박으면 그 목록이 영원히 낡는다 |
///
/// 드롭인 디렉터리의 파일은 **확장자가 없다** — 실측(2026-10-27, 청정 코퍼스):
/// `/etc/pam.d/` 171건이 전부 그렇고 `text_config` 로 잡힌 것이 **0건**이었다.
/// 그래서 접미사 축으로는 영영 닿지 않는다. 그리고 그 디렉터리에 **파일 하나를
/// 떨어뜨리는 것**이 그 자리를 쓰는 수법이므로, 이름을 미리 적는 방식으로는
/// 막을 수 없다 (`20-detect-recipes.md` §알려진 지표 목록과 같은 이유).
///
/// # 직접 자식만 본다
///
/// 드롭인 디렉터리는 평평하다 (`pam.d` · `cron.d` · `sudoers.d` · `conf.d`).
/// 재귀로 열면 `/etc` 한 줄로 트리 전체가 설정이 되고, 그것은 결정 5 가 버린
/// *"전부 매니페스트"* 와 같아진다 — 스냅샷이 터지고 `/etc/ssl/private` 같은
/// 자리가 줄 단위로 따라 들어온다.
///
/// # 상한은 여전히 `scan_roots` 하나다
///
/// 여기 적는 디렉터리는 `scan_roots` **안**이어야 하고 린트가 오류로 막는다.
/// `subject_roots` 와 방향만 반대다(그쪽은 좁히고 이쪽은 같은 상한 안에서 읽는
/// 것을 넓힌다) — **상한 밖으로 나가는 길은 없다.**
fn text_config_files<P: FsRead, T>(
    fs: &P,
    scope: &Scope,
    h: &mut Harvest<T>,
) -> Result<Vec<String>, CollectError> {
    let mut out = files_with_ext(fs, scope, Subject::TextConfig, &TEXT_EXT, h)?;
    for dir in &scope.text_config_dirs {
        if !fs.exists(dir) {
            // 없는 디렉터리다. PAM 이 없는 기계에 `/etc/pam.d` 가 없는 것은
            // 정상이고, 선언한 **상한**(`scan_roots`)이 없는 경우는 봉투의
            // `missing_roots`·`unreadable_roots` 가 이미 말한다.
            continue;
        }
        let w = fs
            .walk(dir, scope.max_files)
            .map_err(|e| CollectError::Other(e.to_string()))?;
        h.truncated |= w.truncated;
        h.absorb_denied(w.denied, w.denied_paths);
        for e in w.entries {
            if e.is_dir || e.is_reparse || !is_direct_child(&e.path, dir, scope.platform) {
                continue;
            }
            out.push(e.path);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// `path` 가 `dir` 의 **바로 아래**인가.
///
/// # 손으로 비교하지 않는다
///
/// `starts_with` 만으로는 세 가지가 함께 샌다 — `/etc/pam.dx` 가 자식이 되고
/// (구분자를 요구하지 않아서), `/etc/pam.d/sub/x` 가 자식이 되고(깊이를 보지
/// 않아서), Windows 에서 `C:\App\Conf.d` 와 `c:\app\conf.d` 가 달라진다
/// (대소문자). 앞의 둘은 여기서 보고, **뒤엣것은 `normalize` 가 안다** —
/// 경로 비교는 플랫폼의 성질이고 그 규칙이 이 파일에 복사되면 갈라진다.
fn is_direct_child(path: &str, dir: &str, platform: remedy_sdk::catalog::Platform) -> bool {
    let sep = if platform == remedy_sdk::catalog::Platform::Windows {
        '\\'
    } else {
        '/'
    };
    let p = normalize::for_compare(path, platform);
    let d = normalize::for_compare(dir, platform);
    let Some(rest) = p.strip_prefix(&d).and_then(|r| r.strip_prefix(sep)) else {
        return false;
    };
    !rest.is_empty() && !rest.contains(sep)
}

/// `scan_roots` 안에서 확장자가 맞는 파일.
///
/// **여기가 상한이다.** 설정 파일은 어디에나 있어서 범위를 넓히면 사용자
/// 문서까지 스냅샷에 들어간다.
///
/// **subject 를 받는 이유**: 매니페스트가 그 subject 만 더 좁게 적었을 수
/// 있다(`subject_roots`). `scope.scan_roots` 를 직접 돌면 그 좁힘이 조용히
/// 무시되고, 작성자가 피하려던 상한 초과가 그대로 일어난다.
pub(crate) fn files_with_ext<P: FsRead, T>(
    fs: &P,
    scope: &Scope,
    subject: Subject,
    exts: &[&str],
    h: &mut Harvest<T>,
) -> Result<Vec<String>, CollectError> {
    let mut out = Vec::new();
    for root in scope.roots_for(subject) {
        if crate::registry::is_registry_root(root) || !fs.exists(root) {
            continue;
        }
        let w = fs
            .walk(root, scope.max_files)
            .map_err(|e| CollectError::Other(e.to_string()))?;
        h.truncated |= w.truncated;
        h.absorb_denied(w.denied, w.denied_paths);
        for e in w.entries {
            if e.is_dir || e.is_reparse {
                continue;
            }
            let lower = e.path.to_ascii_lowercase();
            if exts.iter().any(|x| lower.ends_with(x)) {
                out.push(e.path);
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_platform::read::{FsEntry, WalkResult};
    use remedy_platform::PlatformError;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeFs {
        files: BTreeMap<String, Vec<u8>>,
    }

    impl FakeFs {
        fn with(files: &[(&str, &str)]) -> Self {
            Self {
                files: files
                    .iter()
                    .map(|(p, c)| (p.to_string(), c.as_bytes().to_vec()))
                    .collect(),
            }
        }
        /// **대소문자를 무시한다.** Windows 가 그렇기 때문이다. 엄격하게 두면
        /// `%SystemRoot%` 가 전개한 `System32` 와 시험이 적은 `system32` 가
        /// 달라져, 코드가 아니라 가짜 백엔드 때문에 시험이 깨진다.
        fn find(&self, path: &str) -> Option<&Vec<u8>> {
            self.files
                .iter()
                .find(|(p, _)| p.eq_ignore_ascii_case(path))
                .map(|(_, v)| v)
        }
    }

    impl FsRead for FakeFs {
        fn walk(&self, root: &str, _limit: usize) -> Result<WalkResult, PlatformError> {
            Ok(WalkResult {
                entries: self
                    .files
                    .keys()
                    .filter(|p| p.starts_with(root))
                    .map(|p| FsEntry {
                        path: p.clone(),
                        is_dir: false,
                        is_reparse: false,
                        size: 0,
                        mtime: "2026-08-21T00:00:00Z".into(),
                        ctime: None,
                        mode: None,
                    })
                    .collect(),
                truncated: false,
                denied: 0,
                denied_paths: Vec::new(),
            })
        }
        fn read_file(&self, path: &str, _max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
            Ok(self.find(path).cloned())
        }
        fn look(&self, path: &str) -> remedy_platform::read::Seen {
            let lower = path.to_ascii_lowercase();
            if self
                .files
                .keys()
                .any(|p| p.to_ascii_lowercase().starts_with(&lower))
            {
                remedy_platform::read::Seen::Present
            } else {
                remedy_platform::read::Seen::Absent
            }
        }
    }

    impl EnvRead for FakeFs {
        fn expand(&self, s: &str) -> String {
            s.replace("%SystemRoot%", "c:\\windows")
        }
    }

    fn scope(roots: &[&str]) -> Scope {
        Scope::diagnostic(
            roots.iter().map(|s| s.to_string()).collect(),
            remedy_sdk::catalog::Platform::Windows,
        )
    }

    /// **좁힘이 실제로 수집을 제한하는가.**
    ///
    /// 린트가 `subject_roots` 를 검사해도 수집기가 `scan_roots` 를 직접 돌면
    /// 아무 효과가 없다 — 작성자는 좁혔다고 믿고, 실기기에서는 그대로 상한에
    /// 걸린다. 그것이 이 기능을 만든 이유(2026-09-04 실측 종료 코드 6)이므로
    /// 동작으로 못박는다.
    ///
    /// 같은 스냅샷에서 `text_config` 는 둘 다 보고 `structured_config` 는
    /// 좁혀진 하나만 봐야 한다.
    #[test]
    fn a_narrowed_subject_only_walks_its_own_roots() {
        let fs = FakeFs::with(&[
            ("c:\\wide\\noise.json", "{\"a\":1}"),
            ("c:\\wide\\noise.conf", "k=v"),
            ("c:\\wide\\narrow\\wanted.json", "{\"b\":2}"),
            ("c:\\wide\\narrow\\wanted.conf", "k=v"),
        ]);
        let mut sc = scope(&["c:\\wide"]);
        sc.subject_roots.insert(
            remedy_sdk::catalog::Subject::StructuredConfig,
            vec!["c:\\wide\\narrow".to_string()],
        );

        let structured = structured_configs(&fs, &sc).unwrap();
        let paths: Vec<&str> = structured.records.iter().map(|r| r.path.as_str()).collect();
        assert!(
            paths.iter().all(|p| p.contains("narrow")),
            "좁힌 밖의 JSON 을 담았다: {paths:?}"
        );
        assert!(!paths.is_empty(), "좁힌 안의 JSON 을 놓쳤다");

        // 좁히지 않은 subject 는 상한 전체를 그대로 본다.
        let text = text_configs(&fs, &sc).unwrap();
        assert!(
            text.records.iter().any(|r| !r.path.contains("narrow")),
            "좁히지 않은 subject 까지 좁아졌다"
        );
    }

    const HOSTS: &str = "c:\\windows\\system32\\drivers\\etc\\hosts";

    #[test]
    fn a_commented_hosts_line_is_not_an_entry() {
        // 담으면 "이 도메인이 hosts 에 있다" 를 묻는 룰이 주석에도 걸린다.
        let fs = FakeFs::with(&[(
            HOSTS,
            "# 127.0.0.1 blocked.example\n10.0.0.1 evil.example ev2\n\n",
        )]);
        let h = hosts_entries(&fs, &scope(&[])).unwrap();
        assert_eq!(h.records.len(), 1, "{:?}", h.records);
        assert_eq!(h.records[0].ip, "10.0.0.1");
        assert_eq!(h.records[0].hostnames, vec!["evil.example", "ev2"]);
        assert_eq!(h.records[0].line_no, 2, "사람이 보는 줄 번호와 같아야 한다");
    }

    #[test]
    fn a_trailing_comment_is_stripped_but_the_entry_stays() {
        let fs = FakeFs::with(&[(HOSTS, "10.0.0.1 evil.example # 설명\n")]);
        let h = hosts_entries(&fs, &scope(&[])).unwrap();
        assert_eq!(h.records[0].hostnames, vec!["evil.example"]);
    }

    #[test]
    fn linux_looks_at_etc_hosts() {
        // **카탈로그가 이 subject 를 Linux 에서 수집한다고 말한다.** Windows
        // 경로만 보던 동안 그 말이 거짓이었고, 0건에 denied_dirs 까지 올랐다.
        let fs = FakeFs::with(&[(
            "/etc/hosts",
            "10.0.0.1 evil.example
",
        )]);
        let linux = Scope::diagnostic(Vec::new(), remedy_sdk::catalog::Platform::Linux);
        let h = hosts_entries(&fs, &linux).unwrap();
        assert_eq!(h.records.len(), 1, "{:?}", h.records);
        assert_eq!(h.records[0].source, "/etc/hosts");
        assert_eq!(h.denied_dirs, 0);
    }

    #[test]
    fn a_missing_hosts_file_is_counted_as_unseen() {
        let h = hosts_entries(&FakeFs::default(), &scope(&[])).unwrap();
        assert!(h.records.is_empty());
        assert_eq!(h.denied_dirs, 1, "못 본 것을 없는 것으로 보고했다");
        // 어느 자리였는지도 남는다 (2026-09-14).
        assert_eq!(h.denied_paths.len(), 1);
        assert!(
            h.denied_paths[0].contains("hosts"),
            "못 본 자리를 말하지 않는다: {:?}",
            h.denied_paths
        );
    }

    #[test]
    fn ini_sections_travel_with_each_line() {
        let fs = FakeFs::with(&[(
            "c:\\app\\settings.ini",
            "; 주석\n[boot]\nshell=evil.exe\n[other]\nx=1\n",
        )]);
        let h = text_configs(&fs, &scope(&["c:\\app"])).unwrap();
        assert_eq!(h.records.len(), 2, "{:?}", h.records);
        assert_eq!(h.records[0].section, "boot");
        assert_eq!(h.records[0].key, "shell");
        assert_eq!(h.records[0].value, "evil.exe");
        assert_eq!(h.records[1].section, "other");
    }

    #[test]
    fn a_bom_does_not_end_up_inside_the_first_key() {
        // 보이지 않는 문자가 앞에 붙으면 `key equals "shell"` 이 조용히 안 맞는다.
        let fs = FakeFs::with(&[("c:\\app\\a.ini", "\u{feff}shell=evil.exe\n")]);
        let h = text_configs(&fs, &scope(&["c:\\app"])).unwrap();
        assert_eq!(h.records[0].key, "shell");
    }

    #[test]
    fn a_directive_without_a_value_is_still_a_line() {
        // 버리면 `line contains` 를 쓰는 룰이 못 본다.
        let fs = FakeFs::with(&[("c:\\app\\a.conf", "LoadModule evil\n")]);
        let h = text_configs(&fs, &scope(&["c:\\app"])).unwrap();
        assert_eq!(h.records.len(), 1);
        assert_eq!(h.records[0].line, "LoadModule evil");
        assert!(h.records[0].key.is_empty());
    }

    #[test]
    fn json_leaves_get_dotted_paths_including_array_indexes() {
        let fs = FakeFs::with(&[(
            "c:\\app\\manifest.json",
            r#"{"name":"x","perms":["all_urls","tabs"],"n":{"deep":true}}"#,
        )]);
        let h = structured_configs(&fs, &scope(&["c:\\app"])).unwrap();
        let paths: Vec<&str> = h.records.iter().map(|r| r.key_path.as_str()).collect();
        assert_eq!(paths, vec!["n.deep", "name", "perms.0", "perms.1"]);
        let by = |p: &str| {
            h.records
                .iter()
                .find(|r| r.key_path == p)
                .map(|r| r.value.clone())
                .unwrap()
        };
        assert_eq!(by("perms.0"), "all_urls");
        assert_eq!(by("n.deep"), "true");
    }

    #[test]
    fn config_subjects_do_not_leave_the_declared_roots() {
        // 설정 파일은 어디에나 있다. 상한이 없으면 사용자 문서까지 들어간다.
        let fs = FakeFs::with(&[("c:\\app\\a.ini", "k=1\n"), ("c:\\문서\\비밀.ini", "k=2\n")]);
        let h = text_configs(&fs, &scope(&["c:\\app"])).unwrap();
        assert_eq!(h.records.len(), 1);
        assert!(h.records[0].path.starts_with("c:\\app"));
    }

    // ──────────────────────────────────── 확장자 벽 (C-5 · 2026-10-27)

    #[test]
    fn an_htaccess_is_read_line_by_line() {
        // **디렉터리별 PHP 설정이 거기 있다.** `php_value` 로 `php.ini` 를
        // 덮어쓰고, 그 자리는 웹 디렉터리라 공격자가 쓸 수 있다.
        let fs = FakeFs::with(&[(
            "c:\\www\\.htaccess",
            "php_value session.upload_progress.enabled 1\n<Files x>\nDeny from all\n</Files>\n",
        )]);
        let h = text_configs(&fs, &scope(&["c:\\www"])).unwrap();
        assert_eq!(h.records.len(), 4, "{:?}", h.records);
        assert_eq!(
            h.records[0].line,
            "php_value session.upload_progress.enabled 1"
        );
        // **`key`·`value` 는 빈다** — `.htaccess` 는 `키=값` 이 아니다. 룰은
        // `line contains` 로 겨눈다 (`31-nonexistent.md`).
        assert!(h.records[0].key.is_empty(), "{:?}", h.records[0]);
        assert!(h.records[0].value.is_empty());
    }

    #[test]
    fn an_htpasswd_is_not_collected() {
        // 그 파일은 비밀번호 해시다. 줄 단위로 담으면 스냅샷이 자격증명을
        // 들고 다닌다.
        let fs = FakeFs::with(&[("c:\\www\\.htpasswd", "admin:$apr1$abc$def\n")]);
        let h = text_configs(&fs, &scope(&["c:\\www"])).unwrap();
        assert!(h.records.is_empty(), "{:?}", h.records);
    }

    #[test]
    fn a_dropin_directory_is_read_only_when_declared() {
        // `/etc/pam.d/*` 는 확장자가 없다(실측: 코퍼스 171건 전부). 선언이
        // 없으면 영영 닿지 않고, 그 디렉터리에 파일을 떨어뜨리는 것이 바로
        // 그 자리를 쓰는 수법이다.
        let files = [
            ("/etc/pam.d/common-auth", "auth required pam_unix.so\n"),
            ("/etc/pam.d/evil", "auth optional pam_evil.so\n"),
            ("/etc/shadow", "root:$6$x:1::::::\n"),
        ];
        let fs = FakeFs::with(&files);
        let mut sc = Scope::diagnostic(
            vec!["/etc".to_string()],
            remedy_sdk::catalog::Platform::Linux,
        );

        // 선언이 없으면 0건이다 — 확장자가 없기 때문이다.
        assert!(text_configs(&fs, &sc).unwrap().records.is_empty());

        sc.text_config_dirs = vec!["/etc/pam.d".to_string()];
        let h = text_configs(&fs, &sc).unwrap();
        let paths: Vec<&str> = h.records.iter().map(|r| r.path.as_str()).collect();
        assert!(
            paths.iter().any(|p| p.ends_with("/evil")),
            "떨어뜨린 파일을 못 봤다: {paths:?}"
        );
        // **선언한 디렉터리 밖은 그대로 닫혀 있다.** `/etc` 를 상한으로 적었어도
        // `/etc/shadow` 는 줄 단위로 들어오지 않는다.
        assert!(
            !paths.iter().any(|p| p.contains("shadow")),
            "선언 밖의 파일을 읽었다: {paths:?}"
        );
    }

    #[test]
    fn a_declared_directory_does_not_reach_its_subdirectories() {
        // 재귀로 열면 `/etc` 한 줄로 트리 전체가 설정이 된다.
        let fs = FakeFs::with(&[
            ("/etc/pam.d/login", "auth required pam_unix.so\n"),
            ("/etc/pam.d/deep/nested", "auth required pam_deep.so\n"),
        ]);
        let mut sc = Scope::diagnostic(
            vec!["/etc".to_string()],
            remedy_sdk::catalog::Platform::Linux,
        );
        sc.text_config_dirs = vec!["/etc/pam.d".to_string()];
        let paths: Vec<String> = text_configs(&fs, &sc)
            .unwrap()
            .records
            .into_iter()
            .map(|r| r.path)
            .collect();
        assert!(paths.iter().any(|p| p.ends_with("/login")));
        assert!(
            !paths.iter().any(|p| p.contains("deep")),
            "하위 디렉터리까지 내려갔다: {paths:?}"
        );
    }

    #[test]
    fn a_sibling_directory_with_the_same_prefix_is_not_included() {
        use remedy_sdk::catalog::Platform::{Linux, Windows};
        assert!(is_direct_child("/etc/pam.d/login", "/etc/pam.d", Linux));
        assert!(is_direct_child("/etc/pam.d/login", "/etc/pam.d/", Linux));
        // 구분자를 요구하지 않으면 이 줄이 자식이 된다.
        assert!(!is_direct_child("/etc/pam.dx", "/etc/pam.d", Linux));
        assert!(!is_direct_child("/etc/pam.d2/login", "/etc/pam.d", Linux));
        // 깊이를 보지 않으면 이 줄이 들어온다.
        assert!(!is_direct_child(
            "/etc/pam.d/sub/login",
            "/etc/pam.d",
            Linux
        ));
        assert!(!is_direct_child("/etc/pam.d", "/etc/pam.d", Linux));
        // **Windows 는 대소문자를 접고 구분자를 바꾼다** — `normalize` 가 안다.
        assert!(is_direct_child(
            "c:\\App\\Conf.d\\x",
            "c:\\app\\conf.d",
            Windows
        ));
        assert!(is_direct_child(
            "c:/app/conf.d/x",
            "c:\\app\\conf.d",
            Windows
        ));
        // 리눅스에서는 접지 않는다. `/etc/PAM.d` 는 다른 디렉터리다.
        assert!(!is_direct_child("/etc/PAM.d/login", "/etc/pam.d", Linux));
    }

    // ────────────────────────── 조용한 건너뜀 (C-5 와 같은 함수 · 2026-10-27)

    #[test]
    fn a_config_over_the_limit_is_reported_as_truncated() {
        // 파일은 있는데 한 줄도 담지 못했다. 그것을 조용히 넘기면 상한을 넘은
        // php.ini 가 있는 기계가 "그 설정에 아무것도 없다" 로 끝난다.
        struct TooBig;
        impl FsRead for TooBig {
            fn walk(&self, _root: &str, _l: usize) -> Result<WalkResult, PlatformError> {
                Ok(WalkResult {
                    entries: vec![FsEntry {
                        path: "/etc/php/php.ini".into(),
                        is_dir: false,
                        is_reparse: false,
                        size: 9 << 20,
                        mtime: "2026-08-21T00:00:00Z".into(),
                        ctime: None,
                        mode: None,
                    }],
                    truncated: false,
                    denied: 0,
                    denied_paths: Vec::new(),
                })
            }
            // 상한을 넘으면 백엔드가 `Ok(None)` 을 준다 (`FsRead::read_file`).
            fn read_file(&self, _p: &str, _max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
                Ok(None)
            }
            fn look(&self, _p: &str) -> remedy_platform::read::Seen {
                remedy_platform::read::Seen::Present
            }
        }
        let h = text_configs(
            &TooBig,
            &Scope::diagnostic(
                vec!["/etc".to_string()],
                remedy_sdk::catalog::Platform::Linux,
            ),
        )
        .unwrap();
        assert!(h.records.is_empty());
        assert!(h.truncated, "상한을 넘은 설정을 조용히 건너뛰었다");
        // 거부가 아니다 — 그쪽 사유 줄은 "관리자 권한으로 다시 돌리십시오" 다.
        assert_eq!(h.denied_dirs, 0);
    }

    #[test]
    fn a_config_that_cannot_be_opened_is_reported_as_denied() {
        struct Refused;
        impl FsRead for Refused {
            fn walk(&self, _root: &str, _l: usize) -> Result<WalkResult, PlatformError> {
                Ok(WalkResult {
                    entries: vec![FsEntry {
                        path: "/etc/secret.conf".into(),
                        is_dir: false,
                        is_reparse: false,
                        size: 10,
                        mtime: "2026-08-21T00:00:00Z".into(),
                        ctime: None,
                        mode: None,
                    }],
                    truncated: false,
                    denied: 0,
                    denied_paths: Vec::new(),
                })
            }
            fn read_file(&self, p: &str, _max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
                Err(PlatformError::Refused(p.to_string()))
            }
            fn look(&self, _p: &str) -> remedy_platform::read::Seen {
                remedy_platform::read::Seen::Present
            }
        }
        let h = text_configs(
            &Refused,
            &Scope::diagnostic(
                vec!["/etc".to_string()],
                remedy_sdk::catalog::Platform::Linux,
            ),
        )
        .unwrap();
        assert!(h.records.is_empty());
        assert_eq!(h.denied_dirs, 1, "못 본 것을 없는 것으로 보고했다");
        assert_eq!(h.denied_paths, vec!["/etc/secret.conf".to_string()]);
        assert!(!h.truncated, "거부를 잘림으로 셌다");
    }

    #[test]
    fn a_registry_root_is_not_walked_as_a_directory() {
        // `scan_roots` 에는 레지스트리 경로가 섞인다. 그것을 디렉터리로 훑으면
        // 아무것도 못 찾고 denied 만 는다.
        let fs = FakeFs::with(&[("c:\\app\\a.ini", "k=1\n")]);
        let h = text_configs(&fs, &scope(&["HKLM\\SOFTWARE\\X", "c:\\app"])).unwrap();
        assert_eq!(h.records.len(), 1);
        assert_eq!(h.denied_dirs, 0);
    }
}
