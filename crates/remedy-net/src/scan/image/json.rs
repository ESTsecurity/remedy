//! 이미지 메타데이터(JSON)를 Go 의 `encoding/json` 과 같은 규칙으로 읽는다.
//!
//! 사내 runtime-scanner 는 OCI 인덱스 · 매니페스트 · 설정과 docker save 의 `manifest.json` 을 Go 의 표준 판독기로
//! 읽는다(`decodeJSON`). 같은 파일에 같은 답을 내려고 그 판독기가 겉으로 드러내는 규칙을 옮겼다 — 이미지를 실행하는
//! 쪽(containerd · Docker)도 같은 판독기라, 점검이 실행될 이미지와 다른 이미지를 보지 않게 하는 뜻도 있다.
//!
//! - 키는 대소문자를 가리지 않고 맞춘다(`mediaType` · `MEDIATYPE`). ASCII 밖에서는 `ſ` 가 `s`, `K`(켈빈 기호)가
//!   `k` 와 같다 — Go 의 `bytes.EqualFold` 다.
//! - 같은 칸이 두 번 나오면 뒤의 것이 이긴다. 객체는 앞의 값 위에 덧쓰고(앞에만 있던 칸은 남는다), 배열은 앞의
//!   원소 자리에 덧쓴 뒤 길이를 새 배열에 맞춘다.
//! - `null` 은 문자열 · 수 · 구조에는 아무것도 하지 않고, 배열 · 맵 · 포인터는 비운다.
//! - 모르는 칸은 문법만 보고 건너뛴다. 중첩은 10,000 단까지다.
//! - 정수 칸에는 정수 꼴(소수점 · 지수 없음)의 수만 들어간다. 문자열 안의 깨진 UTF-8 과 짝 없는 서로게이트는
//!   U+FFFD 가 된다.
//! - 값 하나 뒤에는 공백만 올 수 있다.
//!
//! 한 가지는 따르지 않는다 — 세 번 이상 겹친 배열 칸이 앞에서 줄어든 자리의 옛 원소를 다시 쓰는 것. Go 는 그 자리를
//! 메모리 할당 크기에 따라 재사용하므로 같은 답을 낼 수 없다. 그 자리는 새 원소로 시작한다.

use std::collections::{BTreeMap, BTreeSet};

/// Go 의 스캐너가 받는 중첩의 깊이.
const MAX_DEPTH: usize = 10_000;

/// 읽지 못한 까닭 — 부르는 쪽은 *손상* 으로만 말하므로 종류만 남긴다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JsonError {
    /// 문법이 틀렸다(빈 입력 · 깊이 초과 포함).
    Syntax,
    /// 칸의 형과 값의 형이 다르다.
    Type,
    /// 값 하나 뒤에 다른 것이 있다.
    Trailing,
}

pub(super) type JResult<T> = Result<T, JsonError>;

/// 바이트 위를 앞으로만 걷는 판독기.
pub(super) struct Json<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

/// Go 의 "있는 값에 덧써 읽기". 구조체 · 슬라이스 · 맵마다 그 판독기의 규칙대로 구현한다.
pub(super) trait Decode {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()>;
}

/// 스캐너의 `decodeJSON` — 값 하나를 읽고, 그 뒤에는 공백만 와야 한다. Go 의 `Decoder.Decode` 처럼 그 값의 문법을
/// 먼저 끝까지 본다 — 같은 값 안에서는 문법 오류가 형 오류보다 앞선다.
pub(super) fn decode<T: Decode + Default>(data: &[u8]) -> JResult<T> {
    let mut probe = Json {
        b: data,
        i: 0,
        depth: 0,
    };
    if probe.peek().is_none() {
        return Err(JsonError::Syntax);
    }
    probe.skip()?;
    let mut j = Json {
        b: data,
        i: 0,
        depth: 0,
    };
    let mut value = T::default();
    value.decode(&mut j)?;
    match j.peek() {
        None => Ok(value),
        Some(_) => Err(JsonError::Trailing),
    }
}

/// JSON 키가 그 칸의 이름인가 — Go 의 `foldName` 비교. 칸 이름은 ASCII 다.
pub(super) fn key_is(key: &str, name: &str) -> bool {
    let mut chars = key.chars();
    for n in name.bytes() {
        let same = match chars.next() {
            Some('\u{17f}') => n.eq_ignore_ascii_case(&b's'),
            Some('\u{212a}') => n.eq_ignore_ascii_case(&b'k'),
            Some(c) if c.is_ascii() => n.eq_ignore_ascii_case(&(c as u8)),
            _ => false,
        };
        if !same {
            return false;
        }
    }
    chars.next().is_none()
}

/// 구조체 하나 — `null` 이면 그대로 두고, 객체면 칸마다 `field` 를 부른다. `field` 가 모르는 칸이면 거짓을 주고
/// 값은 건너뛴다.
pub(super) fn record(
    j: &mut Json<'_>,
    mut field: impl FnMut(&mut Json<'_>, &str) -> JResult<bool>,
) -> JResult<()> {
    if j.null()? {
        return Ok(());
    }
    j.object(|j, key| if field(j, key)? { Ok(()) } else { j.skip() })
}

impl<'a> Json<'a> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.b.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        let hit = self.peek() == Some(c);
        if hit {
            self.i += 1;
        }
        hit
    }

    fn literal(&mut self, word: &[u8]) -> JResult<()> {
        if !self.b[self.i..].starts_with(word) {
            return Err(JsonError::Syntax);
        }
        self.i += word.len();
        Ok(())
    }

    fn open(&mut self) -> JResult<()> {
        self.i += 1;
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(JsonError::Syntax);
        }
        Ok(())
    }

    /// 다음 값이 `null` 이면 읽고 참.
    pub(super) fn null(&mut self) -> JResult<bool> {
        if self.peek() != Some(b'n') {
            return Ok(false);
        }
        self.literal(b"null")?;
        Ok(true)
    }

    /// 문자열 값. 다른 형이면 형 오류다.
    pub(super) fn text(&mut self) -> JResult<String> {
        match self.peek() {
            Some(b'"') => self.string(),
            Some(_) => self.wrong_type(),
            None => Err(JsonError::Syntax),
        }
    }

    /// 64비트 정수 칸 — Go 의 `strconv.ParseInt(값, 10, 64)` 가 받는 수만.
    pub(super) fn int(&mut self) -> JResult<i64> {
        match self.peek() {
            Some(b'-' | b'0'..=b'9') => {
                let literal = self.number()?;
                std::str::from_utf8(literal)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                    .ok_or(JsonError::Type)
            }
            Some(_) => self.wrong_type(),
            None => Err(JsonError::Syntax),
        }
    }

    /// 형이 틀린 값 — 문법은 맞는지 끝까지 보고 형 오류를 준다.
    fn wrong_type<T>(&mut self) -> JResult<T> {
        self.skip()?;
        Err(JsonError::Type)
    }

    /// 객체의 칸마다 `each(키)` — `each` 가 값을 읽는다.
    pub(super) fn object(
        &mut self,
        mut each: impl FnMut(&mut Self, &str) -> JResult<()>,
    ) -> JResult<()> {
        if self.peek() != Some(b'{') {
            return self.wrong_type();
        }
        self.open()?;
        if !self.eat(b'}') {
            loop {
                if self.peek() != Some(b'"') {
                    return Err(JsonError::Syntax);
                }
                let key = self.string()?;
                if !self.eat(b':') {
                    return Err(JsonError::Syntax);
                }
                each(self, &key)?;
                if self.eat(b'}') {
                    break;
                }
                if !self.eat(b',') {
                    return Err(JsonError::Syntax);
                }
            }
        }
        self.depth -= 1;
        Ok(())
    }

    /// 배열의 원소마다 `each(차례)`.
    pub(super) fn array(
        &mut self,
        mut each: impl FnMut(&mut Self, usize) -> JResult<()>,
    ) -> JResult<()> {
        if self.peek() != Some(b'[') {
            return self.wrong_type();
        }
        self.open()?;
        if !self.eat(b']') {
            let mut n = 0;
            loop {
                each(self, n)?;
                n += 1;
                if self.eat(b']') {
                    break;
                }
                if !self.eat(b',') {
                    return Err(JsonError::Syntax);
                }
            }
        }
        self.depth -= 1;
        Ok(())
    }

    /// 값 하나를 읽지 않고 건너뛴다 — 문법은 다 본다. 중첩을 되부름 없이 걷는다(깊은 입력이 스택을 다 쓰지 않게).
    pub(super) fn skip(&mut self) -> JResult<()> {
        self.raw().map(|_| ())
    }

    /// 값 하나의 원문 — Go 의 `json.RawMessage`.
    pub(super) fn raw(&mut self) -> JResult<&'a [u8]> {
        self.ws();
        let start = self.i;
        let base = self.depth;
        let mut objects: Vec<bool> = Vec::new();
        loop {
            self.scalar_or_open(&mut objects)?;
            // 값 하나를 마쳤다 — 닫는 괄호와 쉼표를 처리한다.
            loop {
                let Some(&object) = objects.last() else {
                    debug_assert_eq!(self.depth, base);
                    return Ok(&self.b[start..self.i]);
                };
                if self.eat(b',') {
                    if object {
                        self.key()?;
                    }
                    break;
                }
                if self.eat(if object { b'}' } else { b']' }) {
                    objects.pop();
                    self.depth -= 1;
                    continue;
                }
                return Err(JsonError::Syntax);
            }
        }
    }

    /// 값의 첫머리 — 스칼라면 끝까지 읽고, 빈 객체 · 배열이면 닫고, 아니면 쌓아 둔다.
    fn scalar_or_open(&mut self, objects: &mut Vec<bool>) -> JResult<()> {
        loop {
            match self.peek().ok_or(JsonError::Syntax)? {
                c @ (b'{' | b'[') => {
                    self.open()?;
                    let object = c == b'{';
                    if self.eat(if object { b'}' } else { b']' }) {
                        self.depth -= 1;
                        return Ok(());
                    }
                    if object {
                        self.key()?;
                    }
                    objects.push(object);
                }
                b'"' => return self.string().map(|_| ()),
                b't' => return self.literal(b"true"),
                b'f' => return self.literal(b"false"),
                b'n' => return self.literal(b"null"),
                b'-' | b'0'..=b'9' => return self.number().map(|_| ()),
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    /// 객체의 키와 `:`.
    fn key(&mut self) -> JResult<()> {
        if self.peek() != Some(b'"') {
            return Err(JsonError::Syntax);
        }
        self.string()?;
        if !self.eat(b':') {
            return Err(JsonError::Syntax);
        }
        Ok(())
    }

    /// 수 하나 — `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`.
    fn number(&mut self) -> JResult<&'a [u8]> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match self.b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(JsonError::Syntax),
        }
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            self.need_digits()?;
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            self.need_digits()?;
        }
        Ok(&self.b[start..self.i])
    }

    fn digits(&mut self) {
        while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
            self.i += 1;
        }
    }

    fn need_digits(&mut self) -> JResult<()> {
        if !matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
            return Err(JsonError::Syntax);
        }
        self.digits();
        Ok(())
    }

    /// 따옴표로 시작하는 문자열 — Go 의 `unquote`. 제어 문자는 문법 오류다.
    fn string(&mut self) -> JResult<String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let start = self.i;
            while matches!(self.b.get(self.i), Some(&c) if c != b'"' && c != b'\\' && c >= 0x20) {
                self.i += 1;
            }
            push_bytes(&mut out, &self.b[start..self.i]);
            match self.b.get(self.i) {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    self.escape(&mut out)?;
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    /// 역슬래시 다음 하나.
    fn escape(&mut self, out: &mut String) -> JResult<()> {
        let c = *self.b.get(self.i).ok_or(JsonError::Syntax)?;
        self.i += 1;
        let plain = match c {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode(out),
            _ => return Err(JsonError::Syntax),
        };
        out.push(plain);
        Ok(())
    }

    /// `\uXXXX` — 짝이 맞는 서로게이트는 한 글자, 짝 없는 서로게이트는 U+FFFD(다음 이스케이프는 따로 읽는다).
    fn unicode(&mut self, out: &mut String) -> JResult<()> {
        let unit = self.hex4(self.i).ok_or(JsonError::Syntax)?;
        self.i += 4;
        if (0xD800..0xE000).contains(&unit) {
            let low = (self.b.get(self.i..self.i + 2) == Some(b"\\u"))
                .then(|| self.hex4(self.i + 2))
                .flatten();
            if let Some(low) = low.filter(|l| (0xDC00..0xE000).contains(l) && unit < 0xDC00) {
                let c = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                self.i += 6;
                return Ok(());
            }
            out.push('\u{FFFD}');
            return Ok(());
        }
        out.push(char::from_u32(unit).unwrap_or('\u{FFFD}'));
        Ok(())
    }

    fn hex4(&self, at: usize) -> Option<u32> {
        let digits = self.b.get(at..at + 4)?;
        digits
            .iter()
            .try_fold(0u32, |v, d| Some(v * 16 + char::from(*d).to_digit(16)?))
    }
}

/// 날바이트를 붙인다 — UTF-8 로 풀리지 않는 바이트는 하나마다 U+FFFD.
fn push_bytes(out: &mut String, bytes: &[u8]) {
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for _ in chunk.invalid() {
            out.push('\u{FFFD}');
        }
    }
}

impl Decode for String {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        if !j.null()? {
            *self = j.text()?;
        }
        Ok(())
    }
}

impl Decode for i64 {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        if !j.null()? {
            *self = j.int()?;
        }
        Ok(())
    }
}

/// 슬라이스 — `null` 은 비우고, 배열은 앞의 원소 자리에 덧쓴 뒤 길이를 맞춘다.
impl<T: Decode + Default> Decode for Vec<T> {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        if j.null()? {
            self.clear();
            return Ok(());
        }
        let mut len = 0;
        j.array(|j, i| {
            if i >= self.len() {
                self.push(T::default());
            }
            len = i + 1;
            self[i].decode(j)
        })?;
        self.truncate(len);
        Ok(())
    }
}

/// 포인터 — `null` 은 비우고, 객체면 있던 값에 덧쓴다.
impl<T: Decode + Default> Decode for Option<Box<T>> {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        if j.null()? {
            *self = None;
            return Ok(());
        }
        self.get_or_insert_with(Box::default).decode(j)
    }
}

/// `map[string]string` — `null` 은 비우고, 객체는 있던 맵에 더한다. 원소의 `null` 은 빈 문자열로 들어간다.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct StrMap(pub(super) Option<BTreeMap<String, String>>);

impl StrMap {
    pub(super) fn get(&self, key: &str) -> &str {
        self.0
            .as_ref()
            .and_then(|m| m.get(key))
            .map_or("", String::as_str)
    }
}

impl Decode for StrMap {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        if j.null()? {
            self.0 = None;
            return Ok(());
        }
        let map = self.0.get_or_insert_with(BTreeMap::new);
        j.object(|j, key| {
            let mut value = String::new();
            value.decode(j)?;
            map.insert(key.to_string(), value);
            Ok(())
        })
    }
}

/// `map[string]json.RawMessage` 의 키 — 값은 문법만 본다. `null` 은 맵을 비운다(`nil`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct KeySet(pub(super) Option<BTreeSet<String>>);

impl Decode for KeySet {
    fn decode(&mut self, j: &mut Json<'_>) -> JResult<()> {
        if j.null()? {
            self.0 = None;
            return Ok(());
        }
        let keys = self.0.get_or_insert_with(BTreeSet::new);
        j.object(|j, key| {
            keys.insert(key.to_string());
            j.skip()
        })
    }
}

/// 구조체의 칸 표 — `record` 안에서 쓴다. 맞는 칸이 있으면 그 칸에 읽고 참을 준다.
macro_rules! fields {
    ($j:ident, $key:ident, $($name:literal => $field:expr),+ $(,)?) => {{
        $(
            if $crate::scan::image::json::key_is($key, $name) {
                $crate::scan::image::json::Decode::decode(&mut $field, $j)?;
                return Ok(true);
            }
        )+
        Ok(false)
    }};
}
pub(super) use fields;
