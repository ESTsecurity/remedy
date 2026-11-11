//! 시험 자료 — 스캐너 시험의 픽스처(`fixtureTar` · `fixtureOCI` · 기준 픽스처 …)를 코드로 짓는다.

use crate::scan::budget::{Budget, Cancel};
use crate::scan::image::rootfs::{Entry, RootFs};
use crate::scan::image::{scan, Request};
use crate::scan::model::{Finding, Product, Status, Target, TargetKind};
use crate::scan::rules::RuleSet;
use remedy_sdk::i18n::Lang;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) const UBUNTU_MAINTAINER: &str =
    "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>";
/// 기준이 고친 버전으로 아는 php8.3-cli 와 그 바로 앞 버전.
pub(super) const FIXED: &str = "8.3.6-0ubuntu0.24.04.13";
pub(super) const BEFORE: &str = "8.3.6-0ubuntu0.24.04.12";
pub(super) const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub(super) const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub(super) const RAW_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";

/// tar 항목 하나 — 스캐너의 `fixtureEntry`.
#[derive(Debug, Clone)]
pub(super) struct Item {
    pub(super) name: Vec<u8>,
    pub(super) body: Vec<u8>,
    pub(super) link: Vec<u8>,
    pub(super) kind: u8,
    /// 머리에만 적는 크기(자료 없이) — 크기 검사 픽스처.
    pub(super) size: Option<u64>,
    pub(super) mode: u32,
}

pub(super) fn reg(name: &str, body: impl AsRef<[u8]>) -> Item {
    Item {
        name: name.as_bytes().to_vec(),
        body: body.as_ref().to_vec(),
        link: Vec::new(),
        kind: b'0',
        size: None,
        mode: 0o644,
    }
}

pub(super) fn kind(name: &str, kind: u8, link: &str) -> Item {
    Item {
        kind,
        link: link.as_bytes().to_vec(),
        ..reg(name, "")
    }
}

pub(super) fn mode(mut item: Item, mode: u32) -> Item {
    item.mode = mode;
    item
}

/// tar 를 바이트로 — 스캐너의 `fixtureTar`. 크기만 적은 항목이 끝이면 끝 블록을 쓰지 않는다(Go 의 기록기가
/// 그 자리에서 멈춘다).
pub(super) fn tar(items: &[Item]) -> Vec<u8> {
    let mut out = Vec::new();
    for it in items {
        out.extend_from_slice(&header(it));
        out.extend_from_slice(&it.body);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    if items.last().is_none_or(|i| i.size.is_none()) {
        out.extend_from_slice(&[0u8; 1024]);
    }
    out
}

fn header(it: &Item) -> [u8; 512] {
    let mut h = tar::Header::new_ustar();
    h.set_mode(it.mode);
    let size = if it.kind == b'0' {
        it.size.unwrap_or(it.body.len() as u64)
    } else {
        0
    };
    h.set_size(size);
    h.set_mtime(0);
    h.set_uid(0);
    h.set_gid(0);
    let b = h.as_mut_bytes();
    b[..it.name.len()].copy_from_slice(&it.name);
    // 종류 글자는 바이트로 바로 — tar 크레이트의 `set_entry_type` 은 `\0` 을 `0` 으로 바꾼다.
    b[156] = it.kind;
    b[157..157 + it.link.len()].copy_from_slice(&it.link);
    h.set_cksum();
    *h.as_bytes()
}

pub(super) fn sha(data: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(data)))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn md5_hex(data: &[u8]) -> String {
    use md5::Digest as _;
    hex(&md5::Md5::digest(data))
}

pub(super) fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut w = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    w.write_all(data).unwrap();
    w.finish().unwrap()
}

pub(super) fn zstd(data: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
}

/// 시험이 쓰고 지우는 폴더 — 임시 폴더 아래 이름이 겹치지 않는 자리.
pub(super) struct Scratch(pub(super) PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Scratch {
    pub(super) fn path(&self) -> &Path {
        &self.0
    }

    pub(super) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

pub(super) fn scratch() -> Scratch {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "remedy-net-image-{}-{nanos}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // canonicalize: 8.3 짧은 이름 · 링크가 든 임시 폴더 경로를 실제 경로로 — 입력 규칙이 그런 경로를 거절한다.
    let real = std::fs::canonicalize(&dir).unwrap();
    let text = real.to_string_lossy().into_owned();
    Scratch(PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text)))
}

pub(super) fn write(base: &Path, name: &str, data: &[u8]) {
    let full = base.join(name);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(full, data).unwrap();
}

/// 블롭 하나를 쓰고 서술자를 준다 — 스캐너의 `fixtureBlob`.
pub(super) fn blob(base: &Path, data: &[u8], media: &str) -> Value {
    let digest = sha(data);
    write(base, &format!("blobs/sha256/{}", &digest[7..]), data);
    json!({"mediaType": media, "digest": digest, "size": data.len()})
}

pub(super) fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Packing {
    Raw,
    Gzip,
    Zstd,
}

/// OCI 레이아웃 폴더 — 스캐너의 `fixtureOCI`. 레이어 서술자들도 준다.
pub(super) fn oci(layers: &[Vec<u8>], packing: Packing, arches: &[&str]) -> (Scratch, Vec<Value>) {
    let dir = scratch();
    write(
        dir.path(),
        "oci-layout",
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    );
    let mut descs = Vec::new();
    let mut diffs = Vec::new();
    for raw in layers {
        diffs.push(sha(raw));
        let (data, media) = match packing {
            Packing::Raw => (raw.clone(), RAW_LAYER.to_string()),
            Packing::Gzip => (gzip(raw), format!("{RAW_LAYER}+gzip")),
            Packing::Zstd => (zstd(raw), format!("{RAW_LAYER}+zstd")),
        };
        descs.push(blob(dir.path(), &data, &media));
    }
    let arches = if arches.is_empty() {
        &["amd64"][..]
    } else {
        arches
    };
    let mut manifests = Vec::new();
    for arch in arches {
        let cfg = json!({"os": "linux", "architecture": arch, "rootfs": {"type": "layers", "diff_ids": diffs}});
        let config = blob(dir.path(), &bytes(&cfg), OCI_CONFIG);
        let manifest = json!({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": config, "layers": descs});
        let mut d = blob(dir.path(), &bytes(&manifest), OCI_MANIFEST);
        d["platform"] = json!({"os": "linux", "architecture": arch});
        manifests.push(d);
    }
    write_index(dir.path(), &manifests);
    (dir, descs)
}

pub(super) fn write_index(dir: &Path, manifests: &[Value]) {
    let index = json!({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests});
    write(dir, "index.json", &bytes(&index));
}

/// 블롭 경로.
pub(super) fn blob_path(dir: &Path, digest: &str) -> PathBuf {
    dir.join("blobs").join("sha256").join(&digest[7..])
}

// ── 기준 ────────────────────────────────────────────────────────────────

fn php_product(extra: Value) -> Value {
    let mut p = json!({
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "source": "https://www.php.net/",
        "upstream": {"8.3": "8.3.36"},
        "advisories": [{
            "distribution": "ubuntu", "release": "24.04", "package": "php8.3-cli",
            "fixed": "8.3.6-0ubuntu0.24.04.13", "comparator": "debian",
            "source": "https://ubuntu.com/security/notices/USN-8948-1",
        }],
    });
    if let Value::Object(extra) = extra {
        p.as_object_mut().unwrap().extend(extra);
    }
    p
}

fn rules_of(products: Value) -> RuleSet {
    let text = json!({
        "schema_version": 2, "revision": 1, "version": "images-test",
        "issued_at": "2026-10-01T00:00:00Z", "products": products,
    });
    RuleSet::from_json(&text.to_string()).expect("시험 기준")
}

fn node_hash(data: &[u8], version: &str) -> Value {
    json!({"sha256": &sha(data)[7..], "version": version, "source": "https://nodejs.org/download/", "dependency_mode": "bundled"})
}

/// 스캐너 `fixtureRules` — PHP 만, Ubuntu 24.04 의 php8.3-cli 공지 하나.
pub(super) fn php_rules() -> RuleSet {
    rules_of(json!({"php": php_product(Value::Null)}))
}

/// 스캐너 `fixtureNodeRules` — `official` 이 있으면 그 해시가 22.99.0 공식 빌드다.
pub(super) fn node_rules(official: Option<&[u8]>) -> RuleSet {
    let mut node = json!({"cves": ["CVE-2026-111497"], "source": "https://nodejs.org/", "upstream": {"22": "22.99.0"}});
    if let Some(data) = official {
        node["hashes"] = json!([node_hash(data, "22.99.0")]);
    }
    rules_of(json!({
        "php": php_product(Value::Null),
        "node": node,
        "brotli": {
            "cves": ["CVE-2026-111497"], "source": "https://ubuntu.com/security/",
            "advisories": [{
                "distribution": "ubuntu", "release": "24.04", "package": "libbrotli1",
                "fixed": "1.2.0-1ubuntu0.24.04.1", "comparator": "debian",
                "source": "https://ubuntu.com/security/",
            }],
        },
    }))
}

/// 스캐너 `qualificationRules` — `vulnerable` 은 22.98.0, `fixed` 는 22.99.0 공식 빌드다.
pub(super) fn qualification_rules(vulnerable: &[u8], fixed: &[u8]) -> RuleSet {
    rules_of(json!({
        "php": php_product(Value::Null),
        "node": {
            "cves": ["CVE-2026-111497"], "source": "https://nodejs.org/", "upstream": {"22": "22.99.0"},
            "hashes": [node_hash(vulnerable, "22.98.0"), node_hash(fixed, "22.99.0")],
        },
    }))
}

/// 스캐너 `fixturePHPHashRules` · `rpmLimitHashRules` — `old` 는 8.3.35, `fixed` 는 8.3.36 공식 빌드다.
pub(super) fn php_hash_rules(old: &[u8], fixed: &[u8]) -> RuleSet {
    let hash = |data: &[u8], version: &str| json!({"sha256": &sha(data)[7..], "version": version, "source": "https://windows.php.net/"});
    rules_of(json!({"php": {
        "cves": ["CVE-2026-109618", "CVE-2026-109619"], "source": "https://www.php.net/",
        "upstream": {"8.3": "8.3.36"}, "hashes": [hash(old, "8.3.35"), hash(fixed, "8.3.36")],
    }}))
}

// ── 점검 ────────────────────────────────────────────────────────────────

pub(super) fn budget() -> Budget {
    Budget::new(TargetKind::Image, Cancel::default(), Lang::Ko)
}

/// 입력 하나를 점검한다 — 작업 폴더는 새 임시 폴더.
pub(super) fn run(input: &Path, products: &[Product], rules: &RuleSet) -> Vec<Target> {
    run_with(input, products, rules, &budget())
}

pub(super) fn run_with(
    input: &Path,
    products: &[Product],
    rules: &RuleSet,
    b: &Budget,
) -> Vec<Target> {
    let work = scratch();
    let targets = run_in(input, work.path(), products, rules, b);
    assert_eq!(
        std::fs::read_dir(work.path()).unwrap().count(),
        0,
        "작업 폴더에 남은 것이 있다"
    );
    targets
}

pub(super) fn run_in(
    input: &Path,
    work: &Path,
    products: &[Product],
    rules: &RuleSet,
    b: &Budget,
) -> Vec<Target> {
    let inputs = vec![input.to_string_lossy().into_owned()];
    let req = Request {
        inputs: &inputs,
        work_dir: work,
        products,
        rules,
        lang: Lang::Ko,
    };
    scan(&req, b, &mut |_| {})
}

/// 스캐너 `scanFixture` — PHP 만, `fixtureRules`.
pub(super) fn php_scan(input: &Path) -> Vec<Target> {
    run(input, &[Product::Php], &php_rules())
}

pub(super) const PN: [Product; 2] = [Product::Php, Product::Node];

/// 세션 설정 항목을 뺀 판정(스캐너의 `runtimeFindings`).
pub(super) fn runtime(t: &Target) -> Vec<&Finding> {
    t.findings
        .iter()
        .filter(|f| !f.id.ends_with(":CVE-2026-115560"))
        .collect()
}

/// 대상이 하나이고 그 판정이다(스캐너의 `assertSingleStatus`).
pub(super) fn single(targets: &[Target], status: Status) {
    assert_eq!(targets.len(), 1, "{targets:#?}");
    assert_eq!(targets[0].status, status, "{:#?}", targets[0]);
}

/// 대상과 제품의 *보지 못한 것* 을 한 글로.
pub(super) fn gaps(t: &Target, product: Product) -> String {
    t.products
        .get(&product)
        .map(|c| c.gaps.join("\n"))
        .unwrap_or_default()
}

// ── 실행 파일 · 패키지 ──────────────────────────────────────────────────

pub(super) fn elf(needed: &[&str]) -> Vec<u8> {
    crate::scan::binary::fixtures::elf(needed)
}

/// 스캐너 `fixtureELF32` — 4096 바이트 ELF32 i386, 동적 구간과 DT_NEEDED.
pub(super) fn elf32(needed: &[&str]) -> Vec<u8> {
    let mut d = vec![0u8; 4096];
    d[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    let p16 = |d: &mut Vec<u8>, at: usize, v: u16| d[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let p32 = |d: &mut Vec<u8>, at: usize, v: u32| d[at..at + 4].copy_from_slice(&v.to_le_bytes());
    p16(&mut d, 16, 2);
    p16(&mut d, 18, 3);
    p32(&mut d, 20, 1);
    p32(&mut d, 28, 52);
    p16(&mut d, 40, 52);
    p16(&mut d, 42, 32);
    p16(&mut d, 44, 2);
    p32(&mut d, 52, 1);
    p32(&mut d, 68, 4096);
    p32(&mut d, 84, 2);
    p32(&mut d, 88, 256);
    p32(&mut d, 100, ((needed.len() + 3) * 8) as u32);
    p32(&mut d, 256, 5);
    p32(&mut d, 260, 1024);
    let mut index = 1usize;
    for (i, name) in needed.iter().enumerate() {
        p32(&mut d, 272 + i * 8, 1);
        p32(&mut d, 276 + i * 8, index as u32);
        d[1024 + index..1024 + index + name.len()].copy_from_slice(name.as_bytes());
        index += name.len() + 1;
    }
    p32(&mut d, 264, 10);
    p32(&mut d, 268, index as u32);
    d
}

/// 스캐너 `qualificationPHP` — Ubuntu 24.04 의 php8.3-cli 와 그 실행 파일.
pub(super) fn qualification_php(
    version: &str,
    package_version: &str,
    maintainer: &str,
) -> Vec<Item> {
    let mut data = elf(&[]);
    data[2048..].fill(0);
    let text = format!("\0PHP {version}\0");
    data[2048..2048 + text.len()].copy_from_slice(text.as_bytes());
    let status = format!(
        "Package: php8.3-cli\nStatus: install ok installed\nVersion: {package_version}\nMaintainer: {maintainer}\n\n"
    );
    vec![
        reg("etc/os-release", "ID=ubuntu\nVERSION_ID=24.04\n"),
        reg("var/lib/dpkg/status", status),
        reg("var/lib/dpkg/info/php8.3-cli.list", "/usr/bin/php8.3\n"),
        reg(
            "var/lib/dpkg/info/php8.3-cli.md5sums",
            format!("{}  usr/bin/php8.3\n", md5_hex(&data)),
        ),
        reg("usr/bin/php8.3", data),
    ]
}

/// 스캐너 `qualificationChecksum`.
pub(super) fn checksum(pkg: &str, name: &str, data: &[u8]) -> Item {
    reg(
        &format!("var/lib/dpkg/info/{pkg}.md5sums"),
        format!("{}  {name}\n", md5_hex(data)),
    )
}

/// 스캐너 `phpEntries` — `qualificationPHP` 에 libc6 목록 하나를 끼운 것.
pub(super) fn php_entries(package_version: &str) -> Vec<Item> {
    let mut items = qualification_php("8.3.6", package_version, UBUNTU_MAINTAINER);
    items.insert(
        4,
        reg(
            "var/lib/dpkg/info/libc6:amd64.list",
            "/usr/lib/x86_64-linux-gnu/libc.so.6\n",
        ),
    );
    items
}

/// 스캐너 `qualificationSharedEntries` — dpkg 의 nodejs 와 libbrotli1, 그 실행 파일 · 디코더 · 검증 기록.
pub(super) fn shared_entries(needed: &[&str], brotli_version: &str) -> Vec<Item> {
    let (node, decoder) = (elf(needed), elf(&[]));
    let maintainer = format!("\nMaintainer: {UBUNTU_MAINTAINER}\n\n");
    let status = format!(
        "Package: nodejs\nStatus: install ok installed\nVersion: 22.99.0-1{maintainer}Package: libbrotli1\nStatus: install ok installed\nVersion: {brotli_version}{maintainer}"
    );
    vec![
        reg("etc/os-release", "ID=ubuntu\nVERSION_ID=24.04\n"),
        reg("var/lib/dpkg/status", status),
        reg("var/lib/dpkg/info/nodejs.list", "/usr/bin/node\n"),
        reg(
            "var/lib/dpkg/info/libbrotli1.list",
            "/usr/lib/libbrotlidec.so.1\n",
        ),
        reg("usr/bin/node", &node),
        reg("usr/lib/libbrotlidec.so.1", &decoder),
        checksum("nodejs", "usr/bin/node", &node),
        checksum("libbrotli1", "usr/lib/libbrotlidec.so.1", &decoder),
    ]
}

/// 한 바이트를 바꾼 사본.
pub(super) fn with(mut data: Vec<u8>, at: usize, value: u8) -> Vec<u8> {
    data[at] = value;
    data
}

/// 가상 뿌리에 일반 파일을 바로 넣는다 — 해시를 함께(스캐너 시험의 `fileEntry` 리터럴).
pub(super) fn put(fs: &mut RootFs, name: &str, data: Vec<u8>) {
    let entry = Entry {
        kind: b'0',
        size: data.len() as i64,
        sha256: hex(&Sha256::digest(&data)),
        md5: md5_hex(&data),
        data,
        ..Entry::default()
    };
    fs.entries.insert(name.to_string(), entry);
}
