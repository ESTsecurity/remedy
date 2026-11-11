//! 시험 자료 — 지은 엔진(스캐너 시험의 `testRoundTrip` 자리), tar 쓰기, 파일 정보 헤더, 기준.
//!
//! 스캐너는 Go 의 `archive/tar` · `encoding/json` · `base64` 로 응답을 지었다. 여기서는 그 바이트를 손으로 짓는다 —
//! USTAR 머리(체크섬 · 8진수 칸) · PAX `x` 머리(`"%d %s=%s\n"`) · GNU 마법 글자 · 끝 표시 두 블록.

use crate::scan::budget::{Budget, Cancel, ManualClock};
use crate::scan::container::client::Client;
use crate::scan::container::failure::Failure;
use crate::scan::container::paths;
use crate::scan::container::wire::{Call, Method, Reply, Transport};
use crate::scan::model::TargetKind;
use crate::scan::rules::RuleSet;
use remedy_sdk::i18n::Lang;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(crate) const TEST_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// 쿼리 — `(키, 값)` 쌍들(스캐너 시험의 `url.Values`).
pub(crate) type Query<'a> = Vec<(&'a str, &'a str)>;
/// 요청 하나 — 방법 · 경로 · 쿼리.
pub(crate) type Api<'a> = (&'a str, String, Query<'a>);
/// Go `os.ModeDir` · `os.ModeSymlink`.
pub(crate) const MODE_DIR: u32 = 1 << 31;
pub(crate) const MODE_SYMLINK: u32 = 1 << 27;
pub(crate) const MIB: u64 = 1 << 20;

// ── 예산 ────────────────────────────────────────────────────────────────────────────────────────

/// 컨테이너 예산 — 시계를 바꿔 끼워 초당 10 MiB 맞춤이 실제로 기다리지 않는다.
pub(crate) fn budget() -> (Budget, Arc<ManualClock>, Cancel) {
    let clock = ManualClock::new();
    let cancel = Cancel::default();
    let b = Budget::with_clock(
        TargetKind::Container,
        cancel.clone(),
        Lang::Ko,
        clock.clone(),
    );
    (b, clock, cancel)
}

/// 판을 맞춘 클라이언트(스캐너 시험의 `&client{apiVersion: "1.44", engineOS: …}`).
pub(crate) fn client<'a>(b: &'a Budget, t: &'a dyn Transport, engine_os: &str) -> Client<'a> {
    let mut c = Client::new(b, t, Lang::Ko);
    c.api_version = "1.44".to_string();
    c.engine_os = engine_os.to_string();
    c
}

// ── 지은 엔진 ──────────────────────────────────────────────────────────────────────────────────

/// 엔진이 받은 요청 하나.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) method: Method,
    pub(crate) path: String,
    /// 쿼리의 `path` 값(부호를 푼 것).
    pub(crate) file: String,
    pub(crate) raw_query: String,
    pub(crate) deadline: Instant,
}

impl Seen {
    /// `HEAD /etc/os-release` 꼴 — 스캐너 시험의 `calls`.
    pub(crate) fn line(&self) -> String {
        format!("{} {}", self.method.as_str(), self.file)
    }
}

/// 지은 응답.
pub(crate) struct Answer {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) content_length: Option<u64>,
    pub(crate) body: Box<dyn Read + Send>,
}

impl Answer {
    pub(crate) fn ok(body: impl Into<Vec<u8>>) -> Answer {
        Answer {
            status: 200,
            headers: Vec::new(),
            content_length: None,
            body: Box::new(io::Cursor::new(body.into())),
        }
    }

    pub(crate) fn status(status: u16) -> Answer {
        Answer {
            status,
            ..Answer::ok(Vec::new())
        }
    }

    pub(crate) fn reader(body: impl Read + Send + 'static) -> Answer {
        Answer {
            body: Box::new(body),
            ..Answer::ok(Vec::new())
        }
    }

    pub(crate) fn header(mut self, name: &str, value: &str) -> Answer {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub(crate) fn stat(self, value: &str) -> Answer {
        self.header("X-Docker-Container-Path-Stat", value)
    }
}

type Handler = Box<dyn Fn(&Seen) -> Result<Answer, Failure> + Send + Sync>;

/// 요청마다 함수를 부르는 엔진.
pub(crate) struct Engine {
    handler: Handler,
    calls: Mutex<Vec<Seen>>,
}

impl Engine {
    pub(crate) fn new(
        handler: impl Fn(&Seen) -> Result<Answer, Failure> + Send + Sync + 'static,
    ) -> Engine {
        Engine {
            handler: Box::new(handler),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// 닿으면 시험이 실패하는 엔진.
    pub(crate) fn unreachable() -> Engine {
        Engine::new(|s| panic!("엔진에 닿았다: {} {}", s.method.as_str(), s.path))
    }

    pub(crate) fn calls(&self) -> Vec<Seen> {
        self.calls.lock().unwrap().clone()
    }

    pub(crate) fn lines(&self) -> Vec<String> {
        self.calls().iter().map(Seen::line).collect()
    }

    pub(crate) fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Transport for Engine {
    fn round_trip<'a>(
        &'a self,
        call: &Call<'_>,
        _budget: &'a Budget,
    ) -> Result<Reply<'a>, Failure> {
        let seen = Seen {
            method: call.method,
            path: call.path.to_string(),
            file: query_path(call.query),
            raw_query: call.query.to_string(),
            deadline: call.deadline,
        };
        self.calls.lock().unwrap().push(seen.clone());
        let answer = (self.handler)(&seen)?;
        Ok(Reply {
            status: answer.status,
            headers: answer.headers,
            content_length: answer.content_length,
            body: answer.body,
        })
    }
}

/// 쿼리의 `path` 값 — 퍼센트 부호와 `+` 를 푼다.
fn query_path(query: &str) -> String {
    let Some(value) = query.split('&').find_map(|kv| kv.strip_prefix("path=")) else {
        return String::new();
    };
    let b = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 3 <= b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap()
}

/// 파일을 주는 엔진(스캐너 `containerFilesFixture`) — 파일 조회만 받고, 없는 파일은 404 다. 이름은 엔진 OS 의
/// 견줄 값(Windows 는 소문자 · `/`)으로 찾는다. 항목 이름은 마지막 요소, 모드는 0755.
pub(crate) fn files_engine(files: Vec<(&str, Vec<u8>)>) -> Engine {
    let files: HashMap<String, Vec<u8>> =
        files.into_iter().map(|(k, v)| (paths::key(k), v)).collect();
    Engine::new(move |s| {
        let archive_route = format!("/v1.44/containers/{TEST_ID}/archive");
        assert_eq!(
            s.path,
            archive_route,
            "파일 조회 밖의 요청: {} {}",
            s.method.as_str(),
            s.path
        );
        let Some(content) = files.get(&paths::key(&s.file)) else {
            return Ok(Answer::status(404));
        };
        Ok(file_answer(s, &paths::base(&s.file), content, 0o755))
    })
}

/// 파일 하나의 응답 — HEAD 는 정보 헤더만, GET 은 USTAR 아카이브까지.
pub(crate) fn file_answer(s: &Seen, name: &str, content: &[u8], mode: u32) -> Answer {
    let stat = encoded_stat(name, content.len() as i64, mode, "");
    let body = if s.method == Method::Get {
        make_archive(&[Entry::file(name, content.to_vec()).mode(mode)])
    } else {
        Vec::new()
    };
    Answer::ok(body).stat(&stat)
}

// ── 파일 정보 헤더 ────────────────────────────────────────────────────────────────────────────

pub(crate) fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(v >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Go 의 `json.Marshal(pathStat)` 을 base64 로 — 칸 넷.
pub(crate) fn encoded_stat(name: &str, size: i64, mode: u32, link: &str) -> String {
    let v = json!({"name": name, "size": size, "mode": mode, "linkTarget": link});
    base64(v.to_string().as_bytes())
}

// ── tar ───────────────────────────────────────────────────────────────────────────────────────

/// 머리 블록의 꼴.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Ustar,
    Gnu,
}

/// 항목 하나 — Go `tar.Header` 의 쓰는 칸.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) mode: u32,
    pub(crate) size: u64,
    pub(crate) typeflag: u8,
    pub(crate) linkname: String,
    pub(crate) format: Format,
    /// 비어 있지 않으면 `x` 머리를 앞에 둔다(Go 의 `FormatPAX` 와 `PAXRecords` · 소수 시각).
    pub(crate) pax: Vec<(String, String)>,
    pub(crate) data: Vec<u8>,
}

impl Entry {
    /// 일반 파일 — 내용 그대로.
    pub(crate) fn file(name: &str, data: Vec<u8>) -> Entry {
        Entry {
            name: name.to_string(),
            mode: 0o644,
            size: data.len() as u64,
            typeflag: b'0',
            linkname: String::new(),
            format: Format::Ustar,
            pax: Vec::new(),
            data,
        }
    }

    /// 일반 파일 — `x` 를 크기만큼(스캐너 `makeArchive`).
    pub(crate) fn xs(name: &str, size: u64) -> Entry {
        Entry::file(name, vec![b'x'; size as usize])
    }

    /// 내용이 없는 항목 — 디렉터리 · 링크.
    pub(crate) fn special(name: &str, typeflag: u8, linkname: &str) -> Entry {
        Entry {
            typeflag,
            linkname: linkname.to_string(),
            ..Entry::file(name, Vec::new())
        }
    }

    pub(crate) fn mode(mut self, mode: u32) -> Entry {
        self.mode = mode;
        self
    }

    pub(crate) fn gnu(mut self) -> Entry {
        self.format = Format::Gnu;
        self
    }

    pub(crate) fn pax(mut self, key: &str, value: &str) -> Entry {
        self.pax.push((key.to_string(), value.to_string()));
        self
    }
}

fn octal(field: &mut [u8], value: u64) {
    let last = field.len() - 1;
    let digits = format!("{value:0last$o}");
    field[..last].copy_from_slice(digits.as_bytes());
    field[last] = 0;
}

fn text(field: &mut [u8], value: &str) {
    field[..value.len()].copy_from_slice(value.as_bytes());
}

/// 머리 블록 하나 — 체크섬까지.
pub(crate) fn header_block(
    name: &str,
    mode: u32,
    size: u64,
    typeflag: u8,
    linkname: &str,
    format: Format,
) -> [u8; 512] {
    let mut b = [0u8; 512];
    text(&mut b[..100], name);
    octal(&mut b[100..108], u64::from(mode));
    octal(&mut b[108..116], 0);
    octal(&mut b[116..124], 0);
    octal(&mut b[124..136], size);
    octal(&mut b[136..148], 1);
    b[156] = typeflag;
    text(&mut b[157..257], linkname);
    match format {
        Format::Ustar => {
            b[257..263].copy_from_slice(b"ustar\0");
            b[263..265].copy_from_slice(b"00");
        }
        Format::Gnu => {
            b[257..263].copy_from_slice(b"ustar ");
            b[263..265].copy_from_slice(b" \0");
        }
    }
    octal(&mut b[329..337], 0);
    octal(&mut b[337..345], 0);
    set_checksum(&mut b);
    b
}

/// 체크섬 칸 — 그 자리를 빈칸으로 친 합을 `%06o\0 ` 로.
pub(crate) fn set_checksum(b: &mut [u8; 512]) {
    b[148..156].copy_from_slice(b"        ");
    let sum: u32 = b.iter().map(|c| u32::from(*c)).sum();
    let digits = format!("{sum:06o}");
    b[148..154].copy_from_slice(digits.as_bytes());
    b[154] = 0;
    b[155] = b' ';
}

/// PAX 기록 하나(`"%d %s=%s\n"` — 길이는 자기 자신을 센다).
pub(crate) fn pax_record(key: &str, value: &str) -> String {
    let mut size = key.len() + value.len() + 3;
    size += size.to_string().len();
    let record = format!("{size} {key}={value}\n");
    if record.len() == size {
        return record;
    }
    format!("{} {key}={value}\n", record.len())
}

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
}

/// 항목들과 끝 표시(0 블록 둘).
pub(crate) fn make_archive(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        if !e.pax.is_empty() {
            let records: String = e.pax.iter().map(|(k, v)| pax_record(k, v)).collect();
            let name = format!("PaxHeaders.0/{}", e.name);
            out.extend_from_slice(&header_block(
                &name,
                0,
                records.len() as u64,
                b'x',
                "",
                Format::Ustar,
            ));
            out.extend_from_slice(records.as_bytes());
            pad(&mut out);
        }
        out.extend_from_slice(&header_block(
            &e.name,
            e.mode,
            e.size,
            e.typeflag,
            &e.linkname,
            e.format,
        ));
        if matches!(e.typeflag, b'0' | 0) {
            out.extend_from_slice(&e.data);
            pad(&mut out);
        }
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// 큰 일반 파일 하나의 아카이브를 메모리에 두지 않고 흘린다 — 내용은 `byte` 의 반복.
pub(crate) struct Streamed {
    head: Vec<u8>,
    size: u64,
    byte: u8,
    pos: u64,
}

impl Streamed {
    pub(crate) fn new(name: &str, size: u64, byte: u8) -> Streamed {
        Streamed {
            head: header_block(name, 0o755, size, b'0', "", Format::Ustar).to_vec(),
            size,
            byte,
            pos: 0,
        }
    }

    pub(crate) fn total(&self) -> u64 {
        512 + self.size.div_ceil(512) * 512 + 1024
    }
}

impl Read for Streamed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let total = self.total();
        if self.pos >= total || buf.is_empty() {
            return Ok(0);
        }
        // 머리 · 내용 · 채움과 끝 표시 — 지금 자리가 든 구간 하나만 채운다.
        let (end, fill) = if self.pos < 512 {
            (512, None)
        } else if self.pos < 512 + self.size {
            (512 + self.size, Some(self.byte))
        } else {
            (total, Some(0))
        };
        let n = buf.len().min((end - self.pos) as usize);
        match fill {
            None => buf[..n].copy_from_slice(&self.head[self.pos as usize..self.pos as usize + n]),
            Some(b) => buf[..n].fill(b),
        }
        self.pos += n as u64;
        Ok(n)
    }
}

/// 풀릴 때까지 막히는 읽기 — 풀리면 끝(EOF)이다. 응답을 보내지 않는 엔진의 자리.
pub(crate) struct Hold(pub(crate) Arc<AtomicBool>);

impl Read for Hold {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        while !self.0.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(0)
    }
}

/// 읽기는 `R` 에서, 쓰기는 버린다 — 파이프 스레드([`crate::scan::container::wire::link::PumpLink`])에 넘길 연결.
pub(crate) struct Duplex<R>(pub(crate) R);

impl<R: Read> Read for Duplex<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<R> io::Write for Duplex<R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 파이프 스레드 위의 실제 HTTP/1.1 — 요청마다 `serve` 가 엔진이 보낼 바이트를 정한다.
pub(crate) struct Wired<F> {
    serve: F,
    calls: Mutex<Vec<Method>>,
}

impl<F> Wired<F>
where
    F: Fn(&Call<'_>) -> Box<dyn Read + Send> + Sync,
{
    pub(crate) fn new(serve: F) -> Wired<F> {
        Wired {
            serve,
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn methods(&self) -> Vec<Method> {
        self.calls.lock().unwrap().clone()
    }
}

impl<F> Transport for Wired<F>
where
    F: Fn(&Call<'_>) -> Box<dyn Read + Send> + Sync,
{
    fn round_trip<'a>(&'a self, call: &Call<'_>, budget: &'a Budget) -> Result<Reply<'a>, Failure> {
        self.calls.lock().unwrap().push(call.method);
        let stream = Duplex((self.serve)(call));
        let watch = crate::scan::container::wire::Watch {
            deadline: call.deadline,
            budget,
        };
        let link = crate::scan::container::wire::link::PumpLink::start(stream);
        crate::scan::container::wire::http::exchange(Box::new(link), call, watch)
    }
}

/// 응답 머리 — 상태와 헤더들, 빈 줄까지.
pub(crate) fn head(status: &str, headers: &[(&str, String)]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// 실패하는 읽기(스캐너 `failedRead`).
pub(crate) struct Failing;

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("fixture stream failure"))
    }
}

/// 읽힌 바이트를 센다(스캐너 `qualificationCountReader`).
pub(crate) struct Counting<R> {
    pub(crate) inner: R,
    pub(crate) n: Arc<Mutex<u64>>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        *self.n.lock().unwrap() += n as u64;
        Ok(n)
    }
}

// ── 기준 ──────────────────────────────────────────────────────────────────────────────────────

pub(crate) const PHP_CVES: [&str; 2] = ["CVE-2026-109618", "CVE-2026-109619"];
pub(crate) const NODE_CVE: &str = "CVE-2026-111497";

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(crate) fn md5_hex(data: &[u8]) -> String {
    let mut h = crate::scan::container::codec::Md5::new();
    h.update(data);
    crate::scan::container::codec::hex(&h.finalize())
}

/// 해시 줄(스캐너 `containerHash`) — Node.js 는 Brotli 를 담아 지은 공식 빌드다.
pub(crate) fn hash_row(data: &[u8], version: &str, node: bool) -> Value {
    if node {
        json!({"sha256": sha256_hex(data), "version": version, "source": "https://nodejs.org/download/", "dependency_mode": "bundled"})
    } else {
        json!({"sha256": sha256_hex(data), "version": version, "source": "https://www.php.net/downloads.php"})
    }
}

fn rule_set(products: Value) -> RuleSet {
    let v = json!({
        "schema_version": 2,
        "revision": 4,
        "version": "container-fixture",
        "issued_at": "2026-10-01T00:00:00Z",
        "products": products,
    });
    RuleSet::from_json(&v.to_string()).expect("시험 기준을 읽지 못했다")
}

/// 스캐너 `containerHashFixture` — PHP 8.3 은 8.3.36, Node.js 22 는 22.99.0 이 수정 버전이다.
pub(crate) fn hash_rules(php: Vec<Value>, node: Vec<Value>) -> RuleSet {
    rule_set(json!({
        "php": {"cves": PHP_CVES, "source": "https://www.php.net/", "upstream": {"8.3": "8.3.36"}, "hashes": php},
        "node": {"cves": [NODE_CVE], "source": "https://nodejs.org/", "upstream": {"22": "22.99.0"}, "hashes": node},
    }))
}

/// 판정할 근거가 없는 기준 — 스캐너 시험의 `rs == nil` 자리(모든 판정이 *확인 필요* 다).
pub(crate) fn blank_rules() -> RuleSet {
    hash_rules(Vec::new(), Vec::new())
}

/// 스캐너 `containerRPMRules` — Fedora 40 의 `php-cli` · RHEL 8.10 의 `brotli` RPM 줄. `debian` 이 있으면 PHP 의 dpkg
/// 줄 하나를 더한다(Ubuntu 24.04 또는 Debian 12).
pub(crate) fn rpm_rules(debian: Option<&str>) -> RuleSet {
    let mut php_rows = vec![json!({
        "distribution": "fedora", "release": "40", "package": "php-cli", "fixed": "8.3.6-2.fc40", "comparator": "rpm",
        "architectures": ["i686"], "vendor": "Fedora Project", "version_pattern": r"^8\.3\.[0-9]+-[0-9]+\.fc40$",
        "cves": PHP_CVES, "source": "https://example.com/php-fixture",
    })];
    match debian {
        Some("debian") => {
            php_rows = vec![
                json!({"distribution": "debian", "release": "12", "package": "php8.2-cli", "fixed": "8.2.29-1~deb12u9", "comparator": "debian", "source": "https://ubuntu.com/security/"}),
            ]
        }
        Some(_) => {
            php_rows = vec![
                json!({"distribution": "ubuntu", "release": "24.04", "package": "php8.3-cli", "fixed": "8.3.6-0ubuntu0.24.04.13", "comparator": "debian", "source": "https://ubuntu.com/security/"}),
            ]
        }
        None => {}
    }
    rule_set(json!({
        "php": {"cves": PHP_CVES, "source": "https://www.php.net/", "advisories": php_rows},
        "node": {"cves": [NODE_CVE], "source": "https://nodejs.org/", "upstream": {"22": "22.99.0"}},
        "brotli": {"cves": [NODE_CVE], "source": "https://access.redhat.com/", "advisories": [{
            "distribution": "rhel", "release": "8.10", "package": "brotli", "fixed": "1.0.6-3.el8_10", "comparator": "rpm",
            "architectures": ["i686"], "vendor": "Red Hat, Inc.", "version_pattern": r"^1\.0\.6-[0-9]+\.el8_10$",
            "cves": [NODE_CVE], "source": "https://example.com/brotli-fixture",
        }]},
    }))
}

/// 세션 설정이 아닌 발견(스캐너 `runtimeFindings`).
pub(crate) fn runtime_findings(
    t: &crate::scan::model::Target,
) -> Vec<&crate::scan::model::Finding> {
    let suffix = format!(":{}", crate::scan::phpconfig::CVE);
    t.findings
        .iter()
        .filter(|f| !f.id.ends_with(&suffix))
        .collect()
}
