/// `.rsrc` 의 가상 주소. 섹션 정렬(0x1000)과 같다.
pub const RSRC_RVA: u32 = 0x1000;
/// `.rsrc` 의 파일 안 자리. 파일 정렬(0x200)의 배수여야 한다.
pub const RSRC_FILE: u32 = 0x400;

pub fn u16le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
pub fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// 버전 정보 노드 하나. `wType` 은 글자(1)다.
pub fn vnode(key: &str, value: &str, children: &[u8]) -> Vec<u8> {
    let mut k: Vec<u8> = key.encode_utf16().flat_map(u16::to_le_bytes).collect();
    k.extend_from_slice(&[0, 0]);
    let mut v: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    if !value.is_empty() {
        v.extend_from_slice(&[0, 0]);
    }
    let mut out = vec![0u8; 6];
    out.extend_from_slice(&k);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend_from_slice(&v);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend_from_slice(children);
    let total = out.len() as u16;
    out[0..2].copy_from_slice(&u16le(total));
    // **낱말 수**다. 바이트 수를 적으면 뒤를 자식으로 오인한다.
    out[2..4].copy_from_slice(&u16le((v.len() / 2) as u16));
    out[4..6].copy_from_slice(&u16le(1));
    out
}

/// `VS_VERSION_INFO` 블롭. `FileVersion` 하나만 담는다.
pub fn version_blob(file_version: &str) -> Vec<u8> {
    let s = vnode("FileVersion", file_version, &[]);
    let table = vnode("040904b0", "", &s);
    let sfi = vnode("StringFileInfo", "", &table);
    vnode("VS_VERSION_INFO", "", &sfi)
}

/// 리소스 디렉터리 하나 — 머리 16바이트.
pub fn res_dir(named: u16, ids: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&u32le(0)); // characteristics
    v.extend_from_slice(&u32le(0)); // timestamp
    v.extend_from_slice(&u16le(0)); // major
    v.extend_from_slice(&u16le(0)); // minor
    v.extend_from_slice(&u16le(named));
    v.extend_from_slice(&u16le(ids));
    v
}

/// 항목 하나 — 이름/ID 와 자료/디렉터리 자리.
pub fn res_entry(name_or_id: u32, offset: u32, is_dir: bool) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&u32le(name_or_id));
    v.extend_from_slice(&u32le(if is_dir { offset | 0x8000_0000 } else { offset }));
    v
}

/// 리소스 트리. `extra` 는 **이름 층에 더 끼울 항목**이다 — 미끼를 짓는 데 쓴다.
///
/// 자리를 숫자로 적는다(0x10 · 0x18 …). 그 수가 제품 코드와 어긋나면 시험이
/// 진다 — 그것이 이 시험의 목적이다.
pub fn resource_section(blobs: &[(u32, &[u8])]) -> Vec<u8> {
    // 이름 층 항목 수만큼 디렉터리가 늘어난다.
    let n = blobs.len() as u16;
    let name_dir_at = 0x18u32;
    let lang_dirs_at = name_dir_at + 16 + 8 * u32::from(n);
    // 언어 디렉터리(16) + 항목(8) 이 이름마다 하나.
    let data_entries_at = lang_dirs_at + 24 * u32::from(n);
    let payload_at = data_entries_at + 16 * u32::from(n);

    let mut out = Vec::new();
    // 종류 층 — RT_VERSION(16) 하나.
    out.extend_from_slice(&res_dir(0, 1));
    out.extend_from_slice(&res_entry(16, name_dir_at, true));
    debug_assert_eq!(out.len() as u32, name_dir_at);

    // 이름 층 — 주어진 ID 들.
    out.extend_from_slice(&res_dir(0, n));
    for (i, (id, _)) in blobs.iter().enumerate() {
        out.extend_from_slice(&res_entry(*id, lang_dirs_at + 24 * i as u32, true));
    }
    debug_assert_eq!(out.len() as u32, lang_dirs_at);

    // 언어 층 — 이름마다 0x0409 하나.
    for i in 0..blobs.len() as u32 {
        out.extend_from_slice(&res_dir(0, 1));
        out.extend_from_slice(&res_entry(0x0409, data_entries_at + 16 * i, false));
    }
    debug_assert_eq!(out.len() as u32, data_entries_at);

    // 자료 항목 — 블롭의 RVA 와 크기.
    let mut at = payload_at;
    for (_, b) in blobs {
        out.extend_from_slice(&u32le(RSRC_RVA + at));
        out.extend_from_slice(&u32le(b.len() as u32));
        out.extend_from_slice(&u32le(0)); // code_page
        out.extend_from_slice(&u32le(0)); // reserved
        at += b.len() as u32;
        while !at.is_multiple_of(4) {
            at += 1;
        }
    }
    debug_assert_eq!(out.len() as u32, payload_at);

    // 블롭들.
    for (_, b) in blobs {
        out.extend_from_slice(b);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
    out
}

/// 최소 PE32+ 하나. `.rsrc` 한 섹션만 있다.
pub fn pe64(rsrc: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; RSRC_FILE as usize];
    f[0] = b'M';
    f[1] = b'Z';
    let pe_at = 0x80usize;
    f[0x3C..0x40].copy_from_slice(&u32le(pe_at as u32));

    let mut h = Vec::new();
    h.extend_from_slice(b"PE\0\0");
    // COFF 머리 20바이트.
    h.extend_from_slice(&u16le(0x8664)); // machine = x86-64
    h.extend_from_slice(&u16le(1)); // 섹션 하나
    h.extend_from_slice(&u32le(0)); // timestamp
    h.extend_from_slice(&u32le(0)); // ptr to symbols
    h.extend_from_slice(&u32le(0)); // num symbols
    h.extend_from_slice(&u16le(240)); // optional header 크기
    h.extend_from_slice(&u16le(0x2022)); // characteristics: DLL | large address
                                         // 선택 머리 — PE32+.
    h.extend_from_slice(&u16le(0x20B));
    h.extend_from_slice(&[14, 0]); // linker major/minor
    h.extend_from_slice(&u32le(0)); // size of code
    h.extend_from_slice(&u32le(rsrc.len() as u32)); // size of initialized data
    h.extend_from_slice(&u32le(0)); // size of uninitialized data
    h.extend_from_slice(&u32le(0)); // entry point
    h.extend_from_slice(&u32le(0x1000)); // base of code
    h.extend_from_slice(&u32le(0x1000_0000)); // image base (하위)
    h.extend_from_slice(&u32le(0)); // image base (상위)
    h.extend_from_slice(&u32le(0x1000)); // section alignment
    h.extend_from_slice(&u32le(0x200)); // file alignment
    for v in [6u16, 0, 0, 0, 6, 0] {
        h.extend_from_slice(&u16le(v)); // os/image/subsystem 버전
    }
    h.extend_from_slice(&u32le(0)); // win32 version
    h.extend_from_slice(&u32le(RSRC_RVA + 0x1000)); // size of image
    h.extend_from_slice(&u32le(RSRC_FILE)); // size of headers
    h.extend_from_slice(&u32le(0)); // checksum
    h.extend_from_slice(&u16le(2)); // subsystem = GUI
    h.extend_from_slice(&u16le(0)); // dll characteristics
    for _ in 0..4 {
        h.extend_from_slice(&u32le(0x10_0000)); // stack/heap (하위)
        h.extend_from_slice(&u32le(0)); // (상위)
    }
    h.extend_from_slice(&u32le(0)); // loader flags
    h.extend_from_slice(&u32le(16)); // 데이터 디렉터리 수
    for i in 0..16 {
        if i == 2 {
            h.extend_from_slice(&u32le(RSRC_RVA));
            h.extend_from_slice(&u32le(rsrc.len() as u32));
        } else {
            h.extend_from_slice(&u32le(0));
            h.extend_from_slice(&u32le(0));
        }
    }
    // 섹션 표 40바이트.
    let mut name = [0u8; 8];
    name[..6].copy_from_slice(b".rsrc\0");
    h.extend_from_slice(&name);
    h.extend_from_slice(&u32le(rsrc.len() as u32)); // virtual size
    h.extend_from_slice(&u32le(RSRC_RVA)); // virtual address
    let raw = (rsrc.len() as u32).div_ceil(0x200) * 0x200;
    h.extend_from_slice(&u32le(raw)); // size of raw data
    h.extend_from_slice(&u32le(RSRC_FILE)); // pointer to raw data
    h.extend_from_slice(&u32le(0)); // relocations
    h.extend_from_slice(&u32le(0)); // line numbers
    h.extend_from_slice(&u16le(0));
    h.extend_from_slice(&u16le(0));
    h.extend_from_slice(&u32le(0x4000_0040)); // 읽기 전용 자료

    assert!(
        pe_at + h.len() <= RSRC_FILE as usize,
        "머리가 섹션을 덮는다"
    );
    f[pe_at..pe_at + h.len()].copy_from_slice(&h);
    f.extend_from_slice(rsrc);
    while !f.len().is_multiple_of(0x200) {
        f.push(0);
    }
    f
}

/// `VS_VERSION_INFO`(ID 1) 하나를 가진 PE.
pub fn pe_with(file_version: &str) -> Vec<u8> {
    let blob = version_blob(file_version);
    pe64(&resource_section(&[(1, &blob)]))
}
