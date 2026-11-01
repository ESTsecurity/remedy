//! 격리 컨테이너의 바이트 배치 (설계-02 §9).
//!
//! ```text
//!   "RMDYQ" | fmt_ver u16 | header_len u32 | header(JSON, 평문)
//!           | manifest_len u32 | manifest(봉인)
//!           | entry[0](봉인) | entry[1](봉인) | ...
//! ```
//!
//! # 왜 manifest 가 엔트리보다 앞인가
//!
//! `restore --entry <id>` 는 컨테이너 전체를 읽지 않고 하나만 꺼내야 한다. 그러려면
//! 오프셋 색인이 필요하고, 색인은 원본 경로를 담으므로 **암호 영역**이어야 한다.
//! 색인을 끝에 두면 길이를 알기 위해 꼬리부터 되짚어야 하는데(ZIP 의 EOCD 방식),
//! 그 방식은 잘린 파일에서 애매해진다. 엔트리를 먼저 봉인해 두고 색인을 만든 뒤
//! 앞에 쓰면 그런 애매함이 없다.
//!
//! # 무엇이 평문인가
//!
//! 헤더만이다. 그리고 헤더는 **세 물음에만 답한다** — 이 파일이 무엇인가,
//! 내가 열 수 있는가, 어느 실행에서 나왔는가. 플러그인 ID·위협 이름·원본 경로·
//! 엔트리 개수는 전부 암호 영역이다 (설계-03 §5).
//!
//! 헤더 전체는 모든 봉인의 AAD 로 함께 인증된다. 묶지 않으면 wrap 슬롯을 지우거나
//! `fmt_ver` 를 바꿔치기하는 변조가 인증을 통과한다.

use crate::key::{ContentKey, WrapSlot, CIPHER_ID};
use crate::QuarantineError;
use remedy_sdk::EntryKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 5] = b"RMDYQ";
pub const FMT_VER: u16 = 1;

/// 평문 헤더. 이 이상은 담지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub run_id: String,
    pub created: String,
    pub core_version: String,
    pub cipher: String,
    /// 콘텐츠 키를 감싼 슬롯들. **최소 하나는 반드시 있다.**
    pub wraps: Vec<WrapSlot>,
}

impl Header {
    /// 로컬 키 wrap 만 있는가. 그렇다면 **이 머신을 재설치하면 열 수 없다.**
    ///
    /// 설계-03 §5 는 이것을 격리 시점에 경고하라고 요구한다. 격리한 뒤에 알려
    /// 주면 이미 늦다 — 그 시점에는 파일이 이미 컨테이너 안에 있다.
    pub fn only_local_wrap(&self) -> bool {
        !self.wraps.is_empty()
            && self
                .wraps
                .iter()
                .all(|w| w.kind == crate::key::WrapKind::Local)
    }
}

/// 컨테이너에 담긴 항목 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    /// **전개된 절대 경로만 들어간다** (불변식 R, 설계-03 §5).
    ///
    /// `%LOCALAPPDATA%` 같은 토큰을 넣으면 다른 머신·다른 사용자에서 다른 곳으로
    /// 복원된다. 복원은 되돌리는 일이므로 그 어긋남은 조용히 일어난다.
    pub origin: String,
    /// 종류별 메타데이터 (타임스탬프·권한·레지스트리 값 타입 등).
    pub meta: serde_json::Value,
    pub content: Vec<u8>,
}

/// 암호 영역의 색인. 원본 경로가 여기 있다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub plugin_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub id: String,
    pub kind: EntryKind,
    pub origin: String,
    pub meta: serde_json::Value,
    pub sha256: String,
    pub size: u64,
    /// 엔트리 영역 시작으로부터의 오프셋.
    pub offset: u64,
    /// 봉인된 길이.
    pub len: u64,
}

/// AAD 를 만든다. 헤더에 **용도와 순번**을 덧붙여, 엔트리를 서로 바꿔치기하거나
/// manifest 자리에 끼워 넣는 변조를 막는다.
fn aad(header_bytes: &[u8], domain: &str, index: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(header_bytes.len() + domain.len() + 16);
    v.extend_from_slice(header_bytes);
    v.push(0);
    v.extend_from_slice(domain.as_bytes());
    v.extend_from_slice(&index.to_le_bytes());
    v
}

fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

// ─────────────────────────────────────────────────────────── 쓰기

/// 컨테이너를 만든다.
pub struct Builder {
    header: Header,
    plugin_id: String,
    threat: Option<String>,
    entries: Vec<Entry>,
}

impl Builder {
    pub fn new(header: Header, plugin_id: impl Into<String>) -> Self {
        Self {
            header,
            plugin_id: plugin_id.into(),
            threat: None,
            entries: Vec::new(),
        }
    }

    pub fn threat(mut self, t: impl Into<String>) -> Self {
        self.threat = Some(t.into());
        self
    }

    pub fn add(&mut self, entry: Entry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// 이 컨테이너가 차지할 대략의 크기. **백업 전에 여유 공간을 확인**하기
    /// 위한 것이다 (설계-00 §5-2: 부족하면 파괴를 시작하지 않는다).
    pub fn estimated_size(&self) -> u64 {
        let content: u64 = self.entries.iter().map(|e| e.content.len() as u64).sum();
        let meta: u64 = self
            .entries
            .iter()
            .map(|e| e.origin.len() as u64 + 512)
            .sum();
        // 봉인 오버헤드(논스 24 + 태그 16)와 헤더·색인 여유.
        content + meta + (self.entries.len() as u64 + 1) * 64 + 4096
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// 봉인해서 바이트로 낸다.
    pub fn seal(&self, key: &ContentKey) -> Result<Vec<u8>, QuarantineError> {
        if self.header.wraps.is_empty() {
            // 최소 하나의 wrap 이 없으면 **아무도 열 수 없는 컨테이너**가 된다.
            // 그것을 만들어 두고 원본을 지우면 복원 불가능한 파괴다.
            return Err(QuarantineError::NoWrap);
        }
        if self.header.cipher != CIPHER_ID {
            return Err(QuarantineError::unsupported(
                "이 코어가 모르는 cipher 로 만들려 합니다",
                "asked to build with a cipher this core does not know",
            ));
        }

        let header_bytes =
            serde_json::to_vec(&self.header).map_err(|e| QuarantineError::Encode(e.to_string()))?;

        // 엔트리를 먼저 봉인해야 색인의 오프셋이 정해진다.
        let mut sealed_entries: Vec<Vec<u8>> = Vec::with_capacity(self.entries.len());
        let mut index = Vec::with_capacity(self.entries.len());
        let mut offset: u64 = 0;
        for (i, e) in self.entries.iter().enumerate() {
            let payload = encode_entry(e)?;
            let sealed = key.seal(&payload, &aad(&header_bytes, "entry", i as u64))?;
            index.push(ManifestEntry {
                id: format!("e{i}"),
                kind: e.kind,
                origin: e.origin.clone(),
                meta: e.meta.clone(),
                sha256: sha256_hex(&e.content),
                size: e.content.len() as u64,
                offset,
                len: sealed.len() as u64,
            });
            offset += sealed.len() as u64;
            sealed_entries.push(sealed);
        }

        let manifest = Manifest {
            plugin_id: self.plugin_id.clone(),
            threat: self.threat.clone(),
            entries: index,
        };
        let manifest_bytes =
            serde_json::to_vec(&manifest).map_err(|e| QuarantineError::Encode(e.to_string()))?;
        let sealed_manifest = key.seal(&manifest_bytes, &aad(&header_bytes, "manifest", 0))?;

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FMT_VER.to_le_bytes());
        out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&(sealed_manifest.len() as u32).to_le_bytes());
        out.extend_from_slice(&sealed_manifest);
        for s in sealed_entries {
            out.extend_from_slice(&s);
        }
        Ok(out)
    }
}

fn encode_entry(e: &Entry) -> Result<Vec<u8>, QuarantineError> {
    // 본문을 base64 로 JSON 에 넣으면 33% 가 늘고 큰 파일에서 메모리가 두 배로 든다.
    // 메타데이터만 JSON 이고 본문은 그대로 붙인다.
    #[derive(Serialize)]
    struct Meta<'a> {
        kind: EntryKind,
        origin: &'a str,
        meta: &'a serde_json::Value,
    }
    let meta = serde_json::to_vec(&Meta {
        kind: e.kind,
        origin: &e.origin,
        meta: &e.meta,
    })
    .map_err(|err| QuarantineError::Encode(err.to_string()))?;

    let mut v = Vec::with_capacity(4 + meta.len() + e.content.len());
    v.extend_from_slice(&(meta.len() as u32).to_le_bytes());
    v.extend_from_slice(&meta);
    v.extend_from_slice(&e.content);
    Ok(v)
}

fn decode_entry(b: &[u8]) -> Result<Entry, QuarantineError> {
    #[derive(Deserialize)]
    struct Meta {
        kind: EntryKind,
        origin: String,
        meta: serde_json::Value,
    }
    if b.len() < 4 {
        return Err(QuarantineError::corrupt(
            "엔트리가 너무 짧습니다",
            "the entry is too short",
        ));
    }
    let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
    if b.len() < 4 + n {
        return Err(QuarantineError::corrupt(
            "엔트리 메타 길이가 범위를 넘습니다",
            "the entry meta length is out of range",
        ));
    }
    let m: Meta =
        serde_json::from_slice(&b[4..4 + n]).map_err(|e| QuarantineError::Encode(e.to_string()))?;
    Ok(Entry {
        kind: m.kind,
        origin: m.origin,
        meta: m.meta,
        content: b[4 + n..].to_vec(),
    })
}

// ─────────────────────────────────────────────────────────── 읽기

/// 아직 열지 않은 컨테이너. **평문 헤더만 읽은 상태다.**
pub struct Sealed<'a> {
    pub header: Header,
    header_bytes: Vec<u8>,
    sealed_manifest: &'a [u8],
    entry_region: &'a [u8],
}

impl<'a> Sealed<'a> {
    /// 키 없이 평문 헤더만 읽는다. 복원 도구가 "내가 이것을 열 수 있는가" 를
    /// 판단하는 자리다.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QuarantineError> {
        let mut p = 0usize;
        let need = |p: usize, n: usize| -> Result<(), QuarantineError> {
            if bytes.len() < p + n {
                Err(QuarantineError::corrupt(
                    "컨테이너가 중간에서 끊겼습니다",
                    "the container is truncated",
                ))
            } else {
                Ok(())
            }
        };

        need(p, MAGIC.len() + 2 + 4)?;
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(QuarantineError::corrupt(
                "remedy 격리 컨테이너가 아닙니다 (magic 불일치)",
                "not a remedy quarantine container (magic mismatch)",
            ));
        }
        p += MAGIC.len();
        let ver = u16::from_le_bytes([bytes[p], bytes[p + 1]]);
        p += 2;
        if ver != FMT_VER {
            return Err(QuarantineError::UnknownVersion(ver));
        }

        let hlen =
            u32::from_le_bytes([bytes[p], bytes[p + 1], bytes[p + 2], bytes[p + 3]]) as usize;
        p += 4;
        need(p, hlen)?;
        let header_bytes = bytes[p..p + hlen].to_vec();
        let header: Header = serde_json::from_slice(&header_bytes)
            .map_err(|e| QuarantineError::Encode(e.to_string()))?;
        p += hlen;

        need(p, 4)?;
        let mlen =
            u32::from_le_bytes([bytes[p], bytes[p + 1], bytes[p + 2], bytes[p + 3]]) as usize;
        p += 4;
        need(p, mlen)?;
        let sealed_manifest = &bytes[p..p + mlen];
        p += mlen;

        Ok(Sealed {
            header,
            header_bytes,
            sealed_manifest,
            entry_region: &bytes[p..],
        })
    }

    /// 콘텐츠 키로 색인을 연다.
    pub fn unlock(&self, key: &ContentKey) -> Result<Opened<'a>, QuarantineError> {
        let plain = key.open(
            self.sealed_manifest,
            &aad(&self.header_bytes, "manifest", 0),
        )?;
        let manifest: Manifest =
            serde_json::from_slice(&plain).map_err(|e| QuarantineError::Encode(e.to_string()))?;
        Ok(Opened {
            header_bytes: self.header_bytes.clone(),
            manifest,
            entry_region: self.entry_region,
        })
    }
}

/// 색인이 열린 컨테이너.
pub struct Opened<'a> {
    header_bytes: Vec<u8>,
    pub manifest: Manifest,
    entry_region: &'a [u8],
}

impl Opened<'_> {
    /// 엔트리 하나를 꺼낸다. **전체를 읽지 않는다.**
    pub fn read(&self, id: &str, key: &ContentKey) -> Result<Entry, QuarantineError> {
        let (i, me) = self
            .manifest
            .entries
            .iter()
            .enumerate()
            .find(|(_, e)| e.id == id)
            .ok_or_else(|| QuarantineError::NoSuchEntry(id.to_string()))?;

        let start = me.offset as usize;
        let end = start
            .checked_add(me.len as usize)
            .ok_or(QuarantineError::corrupt(
                "엔트리 오프셋이 넘쳤습니다",
                "the entry offset overflowed",
            ))?;
        if end > self.entry_region.len() {
            return Err(QuarantineError::corrupt(
                "엔트리가 파일 밖을 가리킵니다",
                "the entry points outside the file",
            ));
        }

        let plain = key.open(
            &self.entry_region[start..end],
            &aad(&self.header_bytes, "entry", i as u64),
        )?;
        let entry = decode_entry(&plain)?;

        // 색인이 말한 해시와 본문이 다르면, 둘 중 하나는 거짓이다. 복원은
        // 되돌리는 일이므로 여기서 멈춘다 — 잘못된 바이트를 원본 자리에 쓰는
        // 것이 아무것도 하지 않는 것보다 나쁘다.
        let actual = sha256_hex(&entry.content);
        if actual != me.sha256 {
            return Err(QuarantineError::corrupt(
                "엔트리 해시가 색인과 다릅니다",
                "the entry hash differs from the index",
            ));
        }
        Ok(entry)
    }

    pub fn ids(&self) -> Vec<String> {
        self.manifest.entries.iter().map(|e| e.id.clone()).collect()
    }
}
