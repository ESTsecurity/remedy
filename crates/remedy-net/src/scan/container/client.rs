//! 엔진 API 클라이언트 — 허용 목록, 판 맞추기, 요청, JSON, 파일 하나 읽기.
//!
//! 스캐너 `client.go` 를 옮겼다. **엔진에 닿는 길은 [`Client::request`] 하나**이고, 그 첫 줄이 허용 목록이다:
//!
//! - `GET /version` · `GET /containers/json` — 쿼리 없이.
//! - `GET /containers/{id}/json` · `GET /images/{id}/json` — 꼴을 확인한 ID, 쿼리 없이.
//! - `HEAD` · `GET /containers/{id}/archive?path=` — `path` 하나, 엔진 OS 의 파일 경로, 마운트 경계 안.
//!
//! 판을 맞추기 전에는 `/version` 밖을 묻지 않는다. 판은 엔진의 범위와 이쪽의 범위(1.40 ~ Docker 1.44 · Podman
//! 1.40)가 겹치는 가장 높은 것이다. 요청마다 예산에서 한 번을 맡고(128회까지), 받는 바이트는 모두 예산이 센다.
//!
//! 파일은 하나씩 읽는다 — HEAD 의 파일 정보 헤더(`X-Docker-Container-Path-Stat`)로 일반 파일 하나임을 먼저 확인하고,
//! 크기가 남은 예산에 드는지 본 뒤에야 GET 을 보낸다. GET 의 파일 정보가 HEAD 와 다르면 본문을 읽지 않는다.

use super::archive::{self, content_failure};
use super::codec::{self, Md5};
use super::endpoint::{EngineKind, Host};
use super::failure::{Failure, FileFailure, Policy, Version};
use super::inspect::{self, EngineVersion, Mount};
use super::paths;
use super::wire::{Call, Method, Reply, Transport};
use crate::scan::binary::{self, StaticBinary};
use crate::scan::budget::{Budget, Clock, ReadKind, SystemClock};
use remedy_sdk::i18n::Lang;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;

/// JSON 응답 하나.
pub(crate) const MAX_JSON: u64 = 8 << 20;
/// 파일 하나.
pub(crate) const MAX_FILE: u64 = 256 << 20;
/// 실행 파일에서 남기는 앞부분 — 머리와 동적 의존을 본다.
pub(crate) const BINARY_PREFIX: u64 = 8 << 20;
/// 패키지 DB 같은 통째로 읽는 파일 하나.
pub(crate) const MAX_WHOLE_FILE: u64 = 64 << 20;
/// 파일 하나의 아카이브가 내용 밖에 더 가질 수 있는 양(머리 · PAX 시각 · 채움 · 끝 표시).
const ARCHIVE_OVERHEAD: u64 = 1 << 20;
const MAX_STAT_HEADER: usize = 16 << 10;
const STAT_HEADER: &str = "X-Docker-Container-Path-Stat";
/// 이쪽이 맞출 수 있는 API 판(1.N 의 N).
const API_MIN: u32 = 40;
const DOCKER_MAX: u32 = 44;
const PODMAN_MAX: u32 = 40;
/// Go `os.FileMode` 의 종류 비트 — 하나라도 켜져 있으면 일반 파일이 아니다.
const MODE_TYPE: u32 = 1 << 31 | 1 << 27 | 1 << 26 | 1 << 25 | 1 << 24 | 1 << 21 | 1 << 19;

/// 요청 하나의 시한.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timeouts {
    pub(crate) request: Duration,
    /// 파일 아카이브의 GET.
    pub(crate) archive: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            request: Duration::from_secs(10),
            archive: Duration::from_secs(30),
        }
    }
}

/// 파일 정보 헤더의 네 칸.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathStat {
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) mode: u32,
    pub(crate) link_target: String,
}

/// 읽은 실행 파일 — 전체의 해시 둘과 앞부분, 그 머리를 읽은 것.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BinaryFile {
    pub(crate) prefix: Vec<u8>,
    pub(crate) sha256: String,
    /// 로컬 RPM 기록과 견주는 값 — 출처를 증명하지 않는다.
    pub(crate) md5: String,
    pub(crate) size: u64,
    pub(crate) info: StaticBinary,
}

/// 받은 내용을 소비하는 쪽 — 크기만큼 읽어야 한다.
pub(crate) type Consume<'c> = &'c mut dyn FnMut(&mut dyn Read, u64) -> Result<(), Failure>;

pub(crate) struct Client<'a> {
    pub(crate) budget: &'a Budget,
    transport: &'a dyn Transport,
    clock: Arc<dyn Clock>,
    pub(crate) lang: Lang,
    /// 엔진 주소에서 확인한 종류. 모르면 판을 맞추지 못한다.
    pub(crate) kind: Option<EngineKind>,
    pub(crate) api_version: String,
    pub(crate) engine_os: String,
    /// 컨테이너마다의 마운트 — 그 경계 안은 읽지 않는다.
    pub(crate) mounts: HashMap<String, Vec<Mount>>,
    /// Windows 엔진의 파일 조회가 5xx 를 낸 컨테이너.
    archive_failures: HashMap<String, u16>,
    pub(crate) timeouts: Timeouts,
    /// 주 프로세스를 찾을 `/proc`. 없으면 찾지 않는다.
    pub(crate) host: Option<&'a dyn Host>,
}

impl<'a> Client<'a> {
    pub(crate) fn new(budget: &'a Budget, transport: &'a dyn Transport, lang: Lang) -> Client<'a> {
        Client {
            budget,
            transport,
            clock: Arc::new(SystemClock),
            lang,
            kind: None,
            api_version: String::new(),
            engine_os: String::new(),
            mounts: HashMap::new(),
            archive_failures: HashMap::new(),
            timeouts: Timeouts::default(),
            host: None,
        }
    }

    /// 시한을 재는 시계를 바꿔 끼운다(시험).
    #[cfg(test)]
    pub(crate) fn with_clock(mut self, clock: Arc<dyn Clock>) -> Client<'a> {
        self.clock = clock;
        self
    }

    pub(crate) fn windows(&self) -> bool {
        self.engine_os == "windows"
    }

    /// 엔진 OS 의 파일 경로인가.
    pub(crate) fn valid_path(&self, name: &str) -> bool {
        if self.windows() {
            paths::valid_windows_file_path(name)
        } else {
            paths::valid_linux_file_path(name)
        }
    }

    /// 그 경로가 컨테이너의 마운트 경계 안(또는 알 수 없는 경계)인가 — 그렇다면 읽지 않는다.
    pub(crate) fn mounted_path(&self, id: &str, name: &str) -> bool {
        let Some(mounts) = self.mounts.get(id) else {
            return false;
        };
        mounts
            .iter()
            .filter(|m| m.kind != "npipe")
            .any(|m| self.crosses(&m.destination, name))
    }

    fn crosses(&self, mount: &str, name: &str) -> bool {
        let mut destination = mount.strip_suffix('/').unwrap_or(mount);
        if self.windows() {
            destination = destination.strip_suffix('\\').unwrap_or(destination);
        }
        let root = mount == "/"
            || (self.windows() && mount.len() == 3 && paths::windows_drive_path(mount));
        if !root && !self.valid_path(destination) {
            // 알아보지 못한 경계는 넘지 않는다.
            return true;
        }
        let key = paths::key(name);
        let boundary = paths::key(mount);
        let boundary = boundary.trim_end_matches('/');
        (root && boundary.is_empty()) || key == boundary || key.starts_with(&format!("{boundary}/"))
    }

    /// 엔진에 보내는 단 하나의 길.
    pub(crate) fn request(
        &mut self,
        method: &str,
        route: &str,
        query: &[(&str, &str)],
    ) -> Result<Reply<'a>, Failure> {
        let m = allowed_api(method, route, query).ok_or(Failure::Policy(Policy::NotAllowed))?;
        let archive = route.ends_with("/archive");
        let id = route.split('/').nth(2).unwrap_or_default().to_string();
        if archive {
            self.archive_gate(&id, query_value(query, "path"))?;
        }
        if route != "/version" && self.api_version.is_empty() {
            return Err(Policy::NotNegotiated.into());
        }
        self.budget.before_request()?;
        let timeout = if m == Method::Get && archive {
            self.timeouts.archive
        } else {
            self.timeouts.request
        };
        let path = if self.api_version.is_empty() {
            route.to_string()
        } else {
            format!("/v{}{route}", self.api_version)
        };
        let query = encode_query(query);
        let call = Call {
            method: m,
            path: &path,
            query: &query,
            deadline: self.clock.now() + timeout,
        };
        let reply = self.transport.round_trip(&call, self.budget)?;
        self.accept(reply, m, route, &id)
    }

    /// 파일 조회의 관문 — 엔진 OS 의 경로, 마운트 경계 밖, 앞서 5xx 를 낸 컨테이너가 아님.
    fn archive_gate(&self, id: &str, path: &str) -> Result<(), Failure> {
        if !self.valid_path(path) || self.mounted_path(id, path) {
            return Err(Policy::OutsideScope.into());
        }
        if let Some(status) = self.archive_failures.get(id) {
            return Err(Policy::WindowsArchive(*status).into());
        }
        Ok(())
    }

    /// 상태가 2xx 이고 압축되지 않은 응답만.
    fn accept(
        &mut self,
        reply: Reply<'a>,
        m: Method,
        route: &str,
        id: &str,
    ) -> Result<Reply<'a>, Failure> {
        let status = reply.status;
        if !(200..=299).contains(&status) {
            drop(reply);
            if self.windows() && route.ends_with("/archive") && status >= 500 {
                self.archive_failures.insert(id.to_string(), status);
                return Err(Policy::WindowsArchive(status).into());
            }
            return Err(Policy::Status {
                status,
                method: m.as_str(),
                route: route.to_string(),
            }
            .into());
        }
        let encoding = reply.header("Content-Encoding");
        if !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity") {
            return Err(Policy::Compressed.into());
        }
        Ok(reply)
    }

    /// 앞서 5xx 를 낸 Windows 컨테이너.
    pub(crate) fn archive_failure(&self, id: &str) -> Option<u16> {
        self.archive_failures.get(id).copied()
    }

    /// JSON 응답 하나 — 8 MiB 까지.
    pub(crate) fn json(&mut self, route: &str) -> Result<Value, Failure> {
        let reply = self.request("GET", route, &[])?;
        let data = self
            .budget
            .read(reply.body, MAX_JSON, ReadKind::Container)
            .map_err(|e| Failure::from_io(&e))?;
        serde_json::from_slice(&data).map_err(|_| Policy::Json.into())
    }

    /// 판을 맞춘다 — 엔진 OS 도 여기서 안다.
    pub(crate) fn negotiate(&mut self) -> Result<(), Failure> {
        let engine = inspect::version(&self.json("/version")?)?;
        self.api_version = select_api_version(&engine, self.kind)?;
        self.engine_os = engine.os;
        Ok(())
    }

    /// 일반 파일 하나를 읽어 `consume` 에 준다. `file_limit` 은 이 용도의 크기 상한이다.
    pub(crate) fn read_regular(
        &mut self,
        id: &str,
        name: &str,
        file_limit: u64,
        consume: Consume<'_>,
    ) -> Result<(), Failure> {
        if !paths::container_id(id) || !self.valid_path(name) {
            return Err(FileFailure::BadRequest.into());
        }
        let route = format!("/containers/{id}/archive");
        let query = [("path", name)];
        let head = self.request("HEAD", &route, &query)?;
        let stat = decode_stat(head.header(STAT_HEADER), name);
        drop(head);
        let stat = stat?;
        if stat.size > file_limit {
            return Err(FileFailure::PurposeLimit.into());
        }
        // 일반 파일 하나와 PAX 시각 · 채움 · 끝 표시가 들 자리가 남아 있어야 GET 을 시작한다.
        let wire_limit = stat.size + ARCHIVE_OVERHEAD;
        self.budget
            .check_read_size(ReadKind::Container, wire_limit)?;
        let reply = self.request("GET", &route, &query)?;
        if decode_stat(reply.header(STAT_HEADER), name)? != stat {
            return Err(FileFailure::StatChanged.into());
        }
        if reply.content_length.is_some_and(|n| n > wire_limit) {
            return Err(FileFailure::ArchiveTooLarge.into());
        }
        let stream = ArchiveLimit {
            inner: self.budget.wrap_reader(reply.body, ReadKind::Container),
            remaining: wire_limit,
        };
        archive::consume_regular(stream, name, stat.size, consume)
    }

    /// 통째로 읽는 파일(64 MiB 까지) — 패키지 DB.
    pub(crate) fn read_file(&mut self, id: &str, name: &str) -> Result<Vec<u8>, Failure> {
        let mut out = Vec::new();
        self.read_regular(id, name, MAX_WHOLE_FILE, &mut |r, size| {
            out = vec![0u8; usize::try_from(size).unwrap_or(usize::MAX)];
            r.read_exact(&mut out).map_err(content_failure)
        })?;
        Ok(out)
    }

    /// 작은 기록 파일 — `limit` 바이트까지.
    pub(crate) fn read_metadata(
        &mut self,
        id: &str,
        name: &str,
        limit: u64,
    ) -> Result<Vec<u8>, Failure> {
        let mut out = Vec::new();
        self.read_regular(id, name, limit, &mut |r, _| {
            r.take(limit + 1)
                .read_to_end(&mut out)
                .map(|_| ())
                .map_err(content_failure)
        })?;
        Ok(out)
    }

    /// 실행 파일 하나 — 전체를 해시하고 앞부분(8 MiB)만 남긴다. Windows 엔진이면 PE 머리를 확인한다. 끝까지
    /// 확인하지 못한 파일의 해시는 남기지 않는다.
    pub(crate) fn read_binary(&mut self, id: &str, name: &str) -> Result<BinaryFile, Failure> {
        let mut result = None;
        self.read_regular(id, name, MAX_FILE, &mut |r, size| {
            result = Some(hash_stream(r, size)?);
            Ok(())
        })?;
        let file = result.ok_or(Failure::File(FileFailure::Read))?;
        if self.windows() && !binary::valid_pe(&file.prefix, file.size) {
            return Err(FileFailure::NotPe.into());
        }
        Ok(file)
    }
}

fn hash_stream(r: &mut dyn Read, size: u64) -> Result<BinaryFile, Failure> {
    let (mut sha, mut md5) = (Sha256::new(), Md5::new());
    let mut prefix = Vec::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(content_failure(e)),
        };
        sha.update(&buf[..n]);
        md5.update(&buf[..n]);
        let room = (BINARY_PREFIX as usize).saturating_sub(prefix.len()).min(n);
        prefix.extend_from_slice(&buf[..room]);
    }
    let info = binary::inspect_node_binary(&prefix, size);
    Ok(BinaryFile {
        sha256: codec::hex(&sha.finalize()),
        md5: codec::hex(&md5.finalize()),
        prefix,
        size,
        info,
    })
}

/// 파일 하나의 아카이브 상한 — 넘어 읽으려 하면 오류다.
struct ArchiveLimit<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for ArchiveLimit<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(Failure::File(FileFailure::ArchiveLimit).into_io());
        }
        let want = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// 허용 목록 — 맞으면 보낼 방법.
pub(crate) fn allowed_api(method: &str, route: &str, query: &[(&str, &str)]) -> Option<Method> {
    let m = match method {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        _ => return None,
    };
    if (route == "/version" || route == "/containers/json") && m == Method::Get && query.is_empty()
    {
        return Some(m);
    }
    let parts: Vec<&str> = route.strip_prefix('/')?.split('/').collect();
    let [kind, id, what] = parts.as_slice() else {
        return None;
    };
    let ok = match (*kind, *what) {
        ("images", "json") => m == Method::Get && paths::image_id(id) && query.is_empty(),
        ("containers", "json") => m == Method::Get && paths::container_id(id) && query.is_empty(),
        ("containers", "archive") => {
            paths::container_id(id)
                && query.len() == 1
                && query[0].0 == "path"
                && paths::valid_file_path(query[0].1)
        }
        _ => false,
    };
    ok.then_some(m)
}

fn query_value<'q>(query: &[(&str, &'q str)], key: &str) -> &'q str {
    query.iter().find(|(k, _)| *k == key).map_or("", |(_, v)| v)
}

/// 쿼리 — 키 차례로, 값마다 부호를 입힌다(`url.Values.Encode`).
fn encode_query(query: &[(&str, &str)]) -> String {
    let mut pairs = query.to_vec();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", codec::query_escape(k), codec::query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// 엔진의 범위와 이쪽의 범위가 겹치는 가장 높은 판.
pub(crate) fn select_api_version(
    engine: &EngineVersion,
    kind: Option<EngineKind>,
) -> Result<String, Failure> {
    let windows = engine.os == "windows";
    if engine.version.is_empty()
        || (engine.os != "linux" && !windows)
        || (windows && kind != Some(EngineKind::Docker))
    {
        return Err(Failure::Version(Version::Unsupported));
    }
    let (Some(max), Some(min)) = (
        api_minor(&engine.api_version),
        api_minor(&engine.min_api_version),
    ) else {
        return Err(Failure::Version(Version::Range));
    };
    let supported = match kind {
        Some(EngineKind::Podman) => PODMAN_MAX,
        Some(EngineKind::Docker) => DOCKER_MAX,
        None => return Err(Failure::Version(Version::Kind)),
    };
    if min > max || max < API_MIN || min > supported {
        return Err(Failure::Version(Version::Incompatible {
            min: engine.min_api_version.clone(),
            max: engine.api_version.clone(),
            supported,
        }));
    }
    Ok(format!("1.{}", max.min(supported)))
}

/// `1.N` 의 N — 1~999, 앞자리 0 없이.
fn api_minor(v: &str) -> Option<u32> {
    let rest = v.strip_prefix("1.")?;
    let ok = (1..=3).contains(&rest.len())
        && rest.bytes().all(|b| b.is_ascii_digit())
        && !rest.starts_with('0');
    ok.then(|| rest.parse().ok()).flatten()
}

/// 파일 정보 헤더 — base64(표준, 안 되면 URL 알파벳) 의 JSON. 요청한 파일의 이름이고, 링크가 아닌 일반 파일이고,
/// 크기가 0 ~ 256 MiB 여야 한다.
pub(crate) fn decode_stat(header: &str, requested: &str) -> Result<PathStat, Failure> {
    if header.len() > MAX_STAT_HEADER {
        return Err(FileFailure::StatTooLarge.into());
    }
    let data = codec::base64_decode(header.as_bytes(), false)
        .or_else(|| codec::base64_decode(header.as_bytes(), true))
        .ok_or(Failure::File(FileFailure::StatBase64))?;
    let raw: serde_json::Map<String, Value> =
        serde_json::from_slice(&data).map_err(|_| FileFailure::StatMissing)?;
    if ["mode", "size", "name"]
        .iter()
        .any(|k| !raw.contains_key(*k))
    {
        return Err(FileFailure::StatMissing.into());
    }
    let (stat, size) = stat_fields(&raw).ok_or(Failure::File(FileFailure::StatJson))?;
    let regular = stat.mode & MODE_TYPE == 0;
    if !paths::valid_file_path(requested)
        || !paths::same_file_base(&stat.name, requested)
        || !stat.link_target.is_empty()
        || !regular
    {
        return Err(FileFailure::NotRegular.into());
    }
    match u64::try_from(size) {
        Ok(size) if size <= MAX_FILE => Ok(PathStat { size, ..stat }),
        _ => Err(FileFailure::FileTooLarge.into()),
    }
}

/// 네 칸을 Go 의 구조체처럼 읽는다 — 형이 틀리거나 대소문자만 다른 칸이 겹치면 `None`. 크기는 부호 있는 값으로
/// 따로 준다(음수는 크기 상한에서 걸린다).
fn stat_fields(raw: &serde_json::Map<String, Value>) -> Option<(PathStat, i64)> {
    let one = |name: &str| -> Option<Option<&Value>> {
        let mut hits = raw.iter().filter(|(k, _)| super::gostr::fold_eq(k, name));
        let first = hits.next();
        hits.next()
            .is_none()
            .then(|| first.map(|(_, v)| v).filter(|v| !v.is_null()))
    };
    let text = |v: Option<&Value>| match v {
        None => Some(String::new()),
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => None,
    };
    let size = match one("size")? {
        None => 0,
        Some(Value::Number(n)) if !n.is_f64() => n.as_i64()?,
        Some(_) => return None,
    };
    let mode = match one("mode")? {
        None => 0,
        Some(Value::Number(n)) if !n.is_f64() => u32::try_from(n.as_u64()?).ok()?,
        Some(_) => return None,
    };
    let stat = PathStat {
        name: text(one("name")?)?,
        size: 0,
        mode,
        link_target: text(one("linkTarget")?)?,
    };
    Some((stat, size))
}

#[cfg(test)]
mod tests;
