//! PHP 세션 설정(CVE-2026-115560) — 설정 파일에서 두 값을 읽는다.
//!
//! 사내 runtime-scanner 의 `internal/phpconfig` 를 옮겼다. 설정 글을 **실행하지 않고 읽기만** 한다. 알아보는
//! 이름은 `session.upload_progress.enabled` 와 `session.serialize_handler` 둘뿐이고, 문법은 셋이다 — php.ini,
//! FPM 풀의 `php_value[...]` · `php_flag[...]`, Apache 의 `php_value` · `php_flag`(셋 다 `admin` 꼴 포함).
//!
//! **판정은 늘 *확인 필요* 다.** 디스크의 설정도, 설정이 없다는 것도 실행 중인 서비스의 값과 앱이 `ini_set` ·
//! `session_start` 를 부르는 차례를 증명하지 못한다. 달라지는 것은 까닭뿐이다.
//!
//! **근거에는 알아본 값만 싣는다.** 값은 정해진 낱말(`On` · `Off` · 처리기 이름 셋) 가운데 하나로만 남는다.
//! 환경 변수 치환 · 따옴표 안의 글 · 읽기 오류의 문장 같은 원문은 어디에도 옮기지 않는다 — 설정 파일에는
//! 비밀번호 같은 값이 함께 적혀 있다.
//!
//! 글은 바이트로 다룬다([`super::linuxmeta`] 의 머리말과 같은 까닭).

use super::linuxmeta::{first_char, lower, trim, trim_start};
use super::model::{Evidence, Finding, Product, Status};
use crate::text::plain;
use remedy_sdk::i18n::Lang;

/// 이 점검이 보는 CVE.
pub const CVE: &str = "CVE-2026-115560";

/// 발생 조건과 완화 방법을 밝힌 php.net 공지.
const OFFICIAL_SOURCE: &str = "https://www.php.net/archive/2026.php#2026-10-23-1";
/// 근거에 싣는 경로의 상한(리눅스의 경로 상한과 같다) — 넘는 경로는 잘라 싣는다.
const MAX_PATH_CHARS: usize = 4096;
/// `session.serialize_handler` 로 알아보는 이름 — 대소문자까지 이대로여야 한다.
const HANDLERS: [&str; 3] = ["php", "php_binary", "php_serialize"];
/// FPM 풀 설정이 PHP 값을 정하는 지시어.
const FPM_COMMANDS: [&str; 4] = ["php_value", "php_admin_value", "php_flag", "php_admin_flag"];
const BOM: &[u8] = b"\xef\xbb\xbf";

/// 부르는 쪽이 읽기 한도 안에서 모은 설정 글 하나. [`assess`] 는 경로와 알아본 값만 남긴다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub path: String,
    pub data: Vec<u8>,
}

/// 세션 설정의 발견 하나. `issues` 는 설정을 모으다 생긴 문제(읽기 오류 따위)로, **몇 건인지만** 싣는다.
///
/// 까닭은 이 차례로 고른다: 값이 서로 다르다 → 같은 설정이 여러 번 있다 → 끈 설정 하나뿐이다 → 켠 설정이
/// 있다 → 적용 범위가 갈린다 → 값을 풀지 못했다 → 설정을 찾지 못했다. 까닭과 할 일은 짧은 고정 문장이고,
/// 본 것은 `evidence` 에 적는다.
pub fn assess(id: &str, docs: &[Document], issues: &[String], lang: Lang) -> Finding {
    let mut all = Seen::default();
    let mut evidence = Vec::with_capacity(docs.len() + 3);
    for doc in docs {
        let seen = parse(&doc.data);
        // 경로는 이미지 · 컨테이너가 준 글자다 — 터미널 제어열이 근거에 남지 않게 걸러 싣는다.
        let mut path = plain(&doc.path, MAX_PATH_CHARS);
        if path.is_empty() {
            path = lang.t("경로 미확인", "path unknown").to_string();
        }
        evidence.push(Evidence::new(path, seen.describe(lang)));
        all.merge(&seen);
    }
    let (reason, action) = words(&all, lang);
    let mut summary = all.describe(lang);
    if !issues.is_empty() {
        let n = issues.len();
        summary.push_str(&lang.pick(
            format!("; 설정 수집 미확인 {n}건"),
            format!("; collection issues: {n}"),
        ));
    }
    evidence.push(Evidence::new(
        lang.t("설정 확인 요약", "settings summary"),
        summary,
    ));
    evidence.push(Evidence::new(OFFICIAL_SOURCE, condition(lang)));
    evidence.push(Evidence::new(OFFICIAL_SOURCE, mitigation(lang)));
    Finding {
        product: Product::Php,
        id: format!("{id}:{CVE}"),
        name: lang.t("PHP 세션 설정", "PHP session settings").to_string(),
        path: None,
        version: None,
        package: None,
        vendor: None,
        runtime: None,
        cves: vec![CVE.to_string()],
        status: Status::ReviewRequired,
        reason: reason.to_string(),
        action: action.to_string(),
        evidence,
    }
}

/// 까닭과 할 일 — 화면의 한 줄에 드는 고정 문장이다. 설정 이름과 값은 여기 적지 않는다.
fn words(all: &Seen, lang: Lang) -> (&'static str, &'static str) {
    let (upload, handler) = (&all.upload, &all.handler);
    let check_files = lang.t(
        "설정 파일과 운영 적용값을 담당자가 확인하십시오.",
        "Have the service owner check the configuration files and the values in effect.",
    );
    let check_order = lang.t(
        "설정 우선순위와 운영 적용값을 담당자가 확인하십시오.",
        "Have the service owner check which setting wins and the values in effect.",
    );
    if upload.values.len() > 1 || handler.values.len() > 1 {
        let why = lang.t(
            "설정값이 충돌해 실제 적용값을 확인하지 못했습니다.",
            "The settings conflict, so the value in effect could not be confirmed.",
        );
        (why, check_order)
    } else if upload.count > 1 || handler.count > 1 {
        let why = lang.t(
            "중복 설정이 있어 실제 적용값을 확인하지 못했습니다.",
            "A setting appears more than once, so the value in effect could not be confirmed.",
        );
        (why, check_order)
    } else if upload.single("Off") {
        (
            lang.t(
                "비활성화 설정을 발견했지만 운영 반영 여부는 미확인입니다.",
                "A setting turns it off, but whether production uses it is unconfirmed.",
            ),
            lang.t(
                "담당자가 모든 PHP worker 의 적용값을 확인하십시오.",
                "Have the service owner check the value in effect on every PHP worker.",
            ),
        )
    } else if upload.values.contains(&"On") {
        (
            lang.t(
                "활성화 설정이 있습니다. 실제 적용값과 앱 코드 확인이 필요합니다.",
                "A setting turns it on. The value in effect and the application code need checking.",
            ),
            lang.t(
                "운영 적용값과 앱의 세션 처리 순서를 담당자가 확인하십시오.",
                "Have the service owner check the values in effect and the order of the app's session calls.",
            ),
        )
    } else if upload.scoped || handler.scoped {
        (
            lang.t(
                "설정의 적용 범위를 확인하지 못했습니다.",
                "The scope the setting applies to could not be confirmed.",
            ),
            lang.t(
                "설정 범위와 운영 적용값을 담당자가 확인하십시오.",
                "Have the service owner check the setting's scope and the values in effect.",
            ),
        )
    } else if upload.invalid || handler.invalid {
        let why = lang.t(
            "세션 설정값을 해석하지 못했습니다.",
            "The session setting value could not be read.",
        );
        (why, check_files)
    } else {
        let why = lang.t(
            "세션 설정 미확인: 대상 설정을 찾지 못했습니다.",
            "Session settings unconfirmed: the settings were not found.",
        );
        (why, check_files)
    }
}

fn condition(lang: Lang) -> &'static str {
    lang.t(
        "발생 조건: session.upload_progress.enabled=On 이며 서버 session.serialize_handler 가 php_binary/php_serialize 이고 앱이 session_start 전에 ini_set 으로 session.serialize_handler 를 php 로 변경하는 경우입니다.",
        "Condition: session.upload_progress.enabled=On, the server's session.serialize_handler is php_binary/php_serialize, and the application changes session.serialize_handler to php with ini_set before session_start.",
    )
}

fn mitigation(lang: Lang) -> &'static str {
    lang.t(
        "완화 안내: session.upload_progress.enabled=Off 는 요청 해석 전에 적용돼야 합니다. 담당자가 모든 PHP worker 에 반영됐는지 확인해야 하며 이 도구는 설정을 바꾸지 않습니다.",
        "Mitigation: session.upload_progress.enabled=Off must be in effect before the request is parsed. The service owner must confirm it reached every PHP worker; this tool does not change settings.",
    )
}

/// 알아보는 두 이름.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Upload,
    Handler,
}

impl Key {
    const ALL: [Key; 2] = [Key::Upload, Key::Handler];

    fn name(self) -> &'static str {
        match self {
            Key::Upload => "session.upload_progress.enabled",
            Key::Handler => "session.serialize_handler",
        }
    }

    /// 이름이 글자 하나까지 맞을 때만.
    fn from_name(name: &[u8]) -> Option<Key> {
        Key::ALL.into_iter().find(|k| k.name().as_bytes() == name)
    }

    /// `line` 이 이 이름으로 시작하고 바로 뒤가 이름의 끝이면 그 뒤 — `…enabled_extra` 같은 닮은 이름을 거른다.
    fn after(self, line: &[u8]) -> Option<&[u8]> {
        line.strip_prefix(self.name().as_bytes())
            .filter(|rest| boundary(rest))
    }
}

/// 한 이름에 대해 본 것. 값은 [`allowed`] 가 돌려준 고정 낱말뿐이다.
#[derive(Debug, Default, PartialEq, Eq)]
struct Setting {
    /// 이 이름을 정한 줄의 수.
    count: usize,
    /// 알아본 값(겹친 것은 한 번).
    values: Vec<&'static str>,
    /// 풀지 못한 값 · 문법이 있었다.
    invalid: bool,
    /// 조건 · 범위 안에서 정한 줄이 있었다.
    scoped: bool,
}

impl Setting {
    fn add(&mut self, value: Option<&'static str>, scoped: bool) {
        self.count += 1;
        self.scoped |= scoped;
        match value {
            Some(v) if !self.values.contains(&v) => self.values.push(v),
            Some(_) => {}
            None => self.invalid = true,
        }
    }

    /// 범위 없이 한 번, 이 값으로만 정했는가.
    fn single(&self, value: &str) -> bool {
        self.count == 1 && !self.invalid && !self.scoped && self.values == [value]
    }

    fn merge(&mut self, other: &Setting) {
        self.count += other.count;
        self.invalid |= other.invalid;
        self.scoped |= other.scoped;
        for v in &other.values {
            if !self.values.contains(v) {
                self.values.push(v);
            }
        }
    }

    fn describe(&self, key: Key, lang: Lang) -> String {
        let name = key.name();
        if self.count == 0 {
            return lang.pick(format!("{name} 설정 미발견"), format!("{name} not set"));
        }
        let mut parts = vec![if self.values.is_empty() {
            lang.pick(format!("{name} 값 미확인"), format!("{name} value unknown"))
        } else {
            format!("{name}={}", self.values.join("/"))
        }];
        let notes = [
            (
                self.invalid,
                lang.t(
                    "해석할 수 없는 값 또는 문법",
                    "a value or syntax that could not be read",
                ),
            ),
            (
                self.values.len() > 1,
                lang.t("설정값 충돌", "conflicting values"),
            ),
            (
                self.count > 1,
                lang.t(
                    "중복 설정; 적용 순서 미확인",
                    "set more than once; order of application unknown",
                ),
            ),
            (
                self.scoped,
                lang.t(
                    "조건부 또는 범위별 설정; 적용 범위 미확인",
                    "conditional or scoped setting; scope of application unknown",
                ),
            ),
        ];
        parts.extend(
            notes
                .into_iter()
                .filter(|(on, _)| *on)
                .map(|(_, note)| note.to_string()),
        );
        parts.join("; ")
    }
}

/// 설정 글 하나(또는 전부)에서 두 이름에 대해 본 것.
#[derive(Debug, Default, PartialEq, Eq)]
struct Seen {
    upload: Setting,
    handler: Setting,
}

impl Seen {
    fn of(&mut self, key: Key) -> &mut Setting {
        match key {
            Key::Upload => &mut self.upload,
            Key::Handler => &mut self.handler,
        }
    }

    fn merge(&mut self, other: &Seen) {
        self.upload.merge(&other.upload);
        self.handler.merge(&other.handler);
    }

    fn describe(&self, lang: Lang) -> String {
        format!(
            "{}; {}",
            self.upload.describe(Key::Upload, lang),
            self.handler.describe(Key::Handler, lang)
        )
    }
}

/// 줄 하나가 정한 것. `value` 가 없으면 이름은 맞지만 값을 풀지 못한 줄이다.
struct Assignment {
    key: Key,
    value: Option<&'static str>,
    scoped: bool,
}

fn parse(data: &[u8]) -> Seen {
    let mut parser = Parser::default();
    for (i, line) in data.split(|b| *b == b'\n').enumerate() {
        let line = match i {
            0 => line.strip_prefix(BOM).unwrap_or(line),
            _ => line,
        };
        parser.line(line.strip_suffix(b"\r").unwrap_or(line));
    }
    parser.seen
}

/// 줄을 차례로 읽으며 드는 상태. 줄 길이에 상한을 두지 않는다 — 긴 줄이 그다음 설정을 가리면 안 되고, 읽는 양은
/// 부르는 쪽이 이미 막았다.
#[derive(Default)]
struct Parser {
    /// `[이름]` 줄을 지났다 — FPM 풀 파일에서는 그 풀에만 걸리는 설정이다.
    section: bool,
    /// `[PATH=...]` · `[HOST=...]` 를 지났거나 구역 머리줄을 읽지 못했다.
    ini_scoped: bool,
    /// 열린 Apache 구역(`<IfModule ...>` · `<VirtualHost ...>` 따위)의 이름.
    apache_open: Vec<String>,
    /// Apache 구역의 짝이 맞지 않았다 — 그 뒤로는 어느 구역 안인지 알 수 없다.
    apache_broken: bool,
    /// 앞줄이 역슬래시로 끝나 이 줄이 그 줄의 일부다(Apache 의 줄 잇기).
    continued: bool,
    /// 앞줄에서 열리고 닫히지 않은 따옴표.
    quote: Option<u8>,
    /// 그 따옴표 안에서 역슬래시가 따옴표를 감싸는가 — Apache 줄은 그렇고 ini 줄은 아니다.
    quote_escapes: bool,
    seen: Seen,
}

impl Parser {
    fn line(&mut self, physical: &[u8]) {
        let continues = physical.ends_with(b"\\") && !looks_ini(physical);
        // 열린 따옴표 값의 안쪽 줄과 이어진 줄은 따로 선 설정이 아니다. 이어진 주석도 여기서 걸린다.
        if self.continued || self.quote.is_some() {
            if self.quote.is_some() {
                self.quote = ending_quote(physical, self.quote, self.quote_escapes);
            }
            self.continued = continues;
            return;
        }
        self.continued = continues;
        let text = trim(physical);
        let Some(&first) = text.first() else { return };
        if first == b';' || first == b'#' {
            return;
        }
        self.quote_escapes = !looks_ini(text);
        self.quote = ending_quote(text, None, self.quote_escapes);
        match first {
            b'[' => self.ini_section(text),
            b'<' => self.apache_section(text),
            _ => {
                if let Some(a) = self.assignment(text) {
                    self.seen.of(a.key).add(a.value, a.scoped);
                }
            }
        }
    }

    /// `[이름]` 줄. `[PATH=...]` · `[HOST=...]` 는 그 경로 · 호스트에만 걸리는 설정의 시작이고, 뒤에 보통
    /// 구역이 와도 그 범위가 끝났다고 보지 않는다. 읽지 못한 머리줄도 범위를 모르는 것으로 친다.
    fn ini_section(&mut self, text: &[u8]) {
        let name = ini_value(text)
            .and_then(|header| header.strip_suffix(b"]"))
            .and_then(|header| header.strip_prefix(b"["));
        let Some(name) = name else {
            self.ini_scoped = true;
            return;
        };
        self.section = true;
        let name = trim(name);
        let kind = trim(&name[..name.iter().position(|b| *b == b'=').unwrap_or(name.len())]);
        if fold_eq(kind, "PATH") || fold_eq(kind, "HOST") {
            self.ini_scoped = true;
        }
    }

    /// `<이름 ...>` 은 구역을 열고 `</이름>` 은 마지막으로 연 것을 닫는다. `>` 로 끝나지 않거나 짝이 맞지 않으면
    /// 그 뒤의 Apache 설정은 모두 범위를 모르는 것이 된다.
    fn apache_section(&mut self, text: &[u8]) {
        let Some(inner) = text.strip_suffix(b">") else {
            self.apache_broken = true;
            return;
        };
        let name = trim(inner.strip_prefix(b"<").unwrap_or(inner));
        let (closing, name) = match name.strip_prefix(b"/") {
            Some(rest) => (true, rest),
            None => (false, name),
        };
        let name = lower(&name[..name.iter().position(|b| *b == b' ').unwrap_or(name.len())]);
        if !closing {
            self.apache_open.push(name);
        } else if self.apache_open.last() == Some(&name) {
            self.apache_open.pop();
        } else {
            self.apache_broken = true;
        }
    }

    /// 이 줄이 두 이름 가운데 하나를 정하는가. 이름이 정확히 맞는 줄만 알아본다.
    fn assignment(&self, line: &[u8]) -> Option<Assignment> {
        if let Some((key, after)) = Key::ALL.into_iter().find_map(|k| Some((k, k.after(line)?))) {
            // php.ini 의 `이름 = 값`.
            return Some(Assignment {
                key,
                value: assigned(key, after),
                scoped: self.ini_scoped,
            });
        }
        let fpm = FPM_COMMANDS.into_iter().find_map(|command| {
            let inside = line.strip_prefix(command.as_bytes())?.strip_prefix(b"[")?;
            Some((command, inside))
        });
        match fpm {
            Some((command, inside)) => self.fpm_assignment(command, inside),
            None => self.apache_assignment(line),
        }
    }

    /// FPM 풀의 `php_value[이름] = 값`. `inside` 는 여는 괄호 다음이다.
    fn fpm_assignment(&self, command: &str, inside: &[u8]) -> Option<Assignment> {
        let scoped = self.section || self.ini_scoped;
        let Some(end) = inside.iter().position(|b| *b == b']') else {
            // 괄호가 닫히지 않았다 — 이름이 맞으면 풀지 못한 설정으로 센다.
            let key = Key::ALL.into_iter().find(|k| k.after(inside).is_some())?;
            return Some(Assignment {
                key,
                value: None,
                scoped,
            });
        };
        let key = Key::from_name(&inside[..end])?;
        // 처리기 이름은 켜고 끄는 값이 아니다.
        let value = if key == Key::Handler && command.ends_with("flag") {
            None
        } else {
            assigned(key, &inside[end + 1..])
        };
        Some(Assignment { key, value, scoped })
    }

    /// Apache 의 `php_value 이름 값` · `php_flag 이름 On|Off`. 값은 낱말이 정확히 셋일 때만 읽는다.
    fn apache_assignment(&self, line: &[u8]) -> Option<Assignment> {
        let (args, whole) = apache_words(line);
        let [command, name, ..] = args.as_slice() else {
            return None;
        };
        let command = lower(command);
        let flag = matches!(command.as_str(), "php_flag" | "php_admin_flag");
        if !flag && !matches!(command.as_str(), "php_value" | "php_admin_value") {
            return None;
        }
        let key = Key::from_name(name)?;
        let value = match args.as_slice() {
            [_, _, value] if whole => allowed(key, value, flag),
            _ => None,
        };
        Some(Assignment {
            key,
            value,
            scoped: !self.apache_open.is_empty() || self.apache_broken,
        })
    }
}

/// 이름 다음의 `= 값` 에서 알아본 값. `=` 가 없거나 값이 아는 낱말이 아니면 `None`.
fn assigned(key: Key, after: &[u8]) -> Option<&'static str> {
    let raw = ini_value(trim(after).strip_prefix(b"=")?)?;
    allowed(key, raw, false)
}

/// 이름이 여기서 끝나는가 — 끝 · `=` · `[` · 공백.
fn boundary(rest: &[u8]) -> bool {
    rest.first()
        .is_none_or(|b| matches!(b, b'=' | b'[') || is_space_byte(*b))
}

/// 바이트 하나를 Latin-1 글자로 보고 공백인지 가린다 — ASCII 공백과 0x85(NEL) · 0xA0(NBSP). 스캐너가 낱말의
/// 끝을 이렇게 본다. 여러 바이트 글자의 뒤쪽 바이트가 이 값이면 낱말이 거기서 끊기고, 끊긴 줄은 값을 풀지
/// 못한 것으로 남는다.
fn is_space_byte(b: u8) -> bool {
    matches!(b, b'\t'..=b'\r' | b' ' | 0x85 | 0xa0)
}

/// 값으로 알아보는 낱말. 그 밖의 글자는 무엇이든 — 환경 변수 치환도 따옴표 안의 비밀도 — 돌려주지 않는다.
///
/// 처리기 이름은 정확히 셋 가운데 하나여야 하고 `php_flag` 로는 정할 수 없다. 켜고 끄는 값은 대소문자를 가리지
/// 않으며, `php_flag` 는 `on` · `off` 만, 그 밖의 문법은 php.ini 의 참 · 거짓 낱말을 다 받는다.
fn allowed(key: Key, raw: &[u8], flag: bool) -> Option<&'static str> {
    if key == Key::Handler {
        return HANDLERS.into_iter().find(|h| !flag && h.as_bytes() == raw);
    }
    match lower(raw).as_str() {
        "on" => Some("On"),
        "off" => Some("Off"),
        "true" | "yes" | "1" if !flag => Some("On"),
        "false" | "no" | "none" | "0" if !flag => Some("Off"),
        _ => None,
    }
}

/// 줄이 끝났을 때 열려 있는 따옴표. 따옴표 밖의 `;` 뒤는 주석이라 보지 않는다. `escapes` 면 따옴표 안의 `\"` ·
/// `\\` 는 따옴표를 닫지 않는다.
fn ending_quote(line: &[u8], mut quote: Option<u8>, escapes: bool) -> Option<u8> {
    let mut i = 0;
    while i < line.len() {
        let c = line[i];
        match quote {
            Some(q) => {
                let escaped = escapes
                    && c == b'\\'
                    && line.get(i + 1).is_some_and(|n| *n == q || *n == b'\\');
                if escaped {
                    i += 1;
                } else if c == q {
                    quote = None;
                }
            }
            None if c == b';' => break,
            None if c == b'"' || c == b'\'' => quote = Some(c),
            None => {}
        }
        i += 1;
    }
    quote
}

/// ini 의 `이름 = 값` 꼴인가 — `=` 앞이 빈칸 · 주석 · 꺾쇠 없는 한 낱말이다. Windows 경로처럼 역슬래시로 끝나는
/// ini 값을 Apache 의 줄 잇기로 읽지 않으려고 본다.
fn looks_ini(line: &[u8]) -> bool {
    let line = trim(line);
    let Some(eq) = line.iter().position(|b| *b == b'=') else {
        return false;
    };
    let key = trim(&line[..eq]);
    !key.is_empty() && !key.iter().any(|b| b" \t;#<>".contains(b))
}

/// ini 값 하나 — 따옴표의 짝이 맞아야 하고, 따옴표 밖의 `;` 뒤는 주석이다. 따옴표 안에 역슬래시가 있거나
/// 따옴표가 닫히지 않으면 `None` 이다(식과 이스케이프는 알아본 값이 될 수 없다). 값 전체를 감싼 따옴표는 벗긴다.
fn ini_value(raw: &[u8]) -> Option<&[u8]> {
    let mut quote = None;
    let mut end = raw.len();
    for (i, c) in raw.iter().enumerate() {
        match quote {
            Some(_) if *c == b'\\' => return None,
            Some(q) if *c == q => quote = None,
            Some(_) => {}
            None if *c == b'"' || *c == b'\'' => quote = Some(*c),
            None if *c == b';' => {
                end = i;
                break;
            }
            None => {}
        }
    }
    if quote.is_some() {
        return None;
    }
    match trim(&raw[..end]) {
        [open @ (b'"' | b'\''), inner @ .., close] if open == close => Some(inner),
        value => Some(value),
    }
}

/// Apache 지시어의 낱말들과, 줄을 끝까지 온전히 읽었는지. 낱말은 공백으로 가르고 따옴표로 묶는다. 넷째 낱말 ·
/// 닫히지 않은 따옴표 · 역슬래시 · 낱말 안의 따옴표를 만나면 거기서 그만두고 거짓을 준다 — 짐작해서 잇지 않는다.
/// Apache 의 주석은 줄 전체뿐이라 줄 끝의 `#` 은 낱말이다.
fn apache_words(line: &[u8]) -> (Vec<&[u8]>, bool) {
    let mut args = Vec::new();
    let mut rest = line;
    loop {
        rest = trim_start(rest);
        let Some(&first) = rest.first() else {
            return (args, true);
        };
        let mut end = 0;
        if first == b'"' || first == b'\'' {
            end = 1;
            while end < rest.len() && rest[end] != first {
                if rest[end] == b'\\' {
                    return (args, false);
                }
                end += 1;
            }
            if end == rest.len() {
                return (args, false);
            }
            args.push(&rest[1..end]);
            end += 1;
            if rest.get(end).is_some_and(|b| !is_space_byte(*b)) {
                return (args, false);
            }
        } else {
            while end < rest.len() && !is_space_byte(rest[end]) {
                if matches!(rest[end], b'\\' | b'"' | b'\'') {
                    return (args, false);
                }
                end += 1;
            }
            args.push(&rest[..end]);
        }
        rest = &rest[end..];
        if args.len() > 3 {
            return (args, false);
        }
    }
}

/// 대소문자를 접어 ASCII 낱말과 같은가(`strings.EqualFold`). 유니코드의 접기라 ASCII 밖의 두 글자도 ASCII 글자와
/// 같다 — `ſ`(U+017F)는 `s`, `K`(U+212A)는 `k`.
fn fold_eq(s: &[u8], word: &str) -> bool {
    let mut rest = s;
    for w in word.chars() {
        let Some((c, n)) = first_char(rest) else {
            return false;
        };
        let folded = matches!(
            (c, w.to_ascii_lowercase()),
            ('\u{17f}', 's') | ('\u{212a}', 'k')
        );
        if !c.eq_ignore_ascii_case(&w) && !folded {
            return false;
        }
        rest = &rest[n..];
    }
    rest.is_empty()
}

#[cfg(test)]
mod tests;
