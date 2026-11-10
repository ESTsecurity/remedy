//! 작은 부호 셋 — 파일 정보 헤더의 base64, 쿼리 값의 퍼센트 부호, RPM 기록과 견줄 MD5.
//!
//! 셋 다 스캐너가 Go 표준 라이브러리로 하던 일이다(`encoding/base64` 의 패딩 있는 두 알파벳 · `url.QueryEscape` ·
//! `crypto/md5`). 새 의존을 들이지 않으려고 그 규칙대로 손으로 옮겼다. MD5 는 **출처를 증명하지 않는다** — 로컬 RPM
//! DB 의 기록과 파일이 같은지만 본다.

/// 패딩 있는 base64 를 푼다(`base64.StdEncoding` · `URLEncoding`). CR · LF 는 어디에 있든 건너뛰고, 패딩 뒤에
/// 글자가 남거나 4글자 묶음이 끝나지 않으면 `None` 이다. 남는 비트는 보지 않는다(Go 의 기본 · 느슨한 해석).
pub(crate) fn base64_decode(s: &[u8], url: bool) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut quantum = [0u8; 4];
    let mut j = 0usize;
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c == b'\n' || c == b'\r' {
            continue;
        }
        if c == b'=' {
            return padded_end(s, i, &quantum, j, out);
        }
        quantum[j] = sextet(c, url)?;
        j += 1;
        if j == 4 {
            emit(&mut out, &quantum, 4);
            j = 0;
        }
    }
    (j == 0).then_some(out)
}

/// 첫 `=` 를 만난 뒤 — `xx==` · `xxx=` 만 받고 그 뒤에는 CR · LF 만 올 수 있다.
fn padded_end(
    s: &[u8],
    mut i: usize,
    quantum: &[u8; 4],
    j: usize,
    mut out: Vec<u8>,
) -> Option<Vec<u8>> {
    let skip = |mut at: usize| {
        while at < s.len() && (s[at] == b'\n' || s[at] == b'\r') {
            at += 1;
        }
        at
    };
    match j {
        2 => {
            i = skip(i);
            if s.get(i) != Some(&b'=') {
                return None;
            }
            i += 1;
        }
        3 => {}
        _ => return None,
    }
    if skip(i) < s.len() {
        return None;
    }
    emit(&mut out, quantum, j);
    Some(out)
}

/// 6비트 묶음 `n` 개(2~4)를 바이트 `n - 1` 개로.
fn emit(out: &mut Vec<u8>, q: &[u8; 4], n: usize) {
    let v = u32::from(q[0]) << 18 | u32::from(q[1]) << 12 | u32::from(q[2]) << 6 | u32::from(q[3]);
    let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
    out.extend_from_slice(&bytes[..n - 1]);
}

fn sextet(c: u8, url: bool) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' if !url => Some(62),
        b'/' if !url => Some(63),
        b'-' if url => Some(62),
        b'_' if url => Some(63),
        _ => None,
    }
}

/// 쿼리 값 하나(`url.QueryEscape`) — 영숫자와 `-` `_` `.` `~` 는 그대로, 빈칸은 `+`, 나머지는 `%XX`.
pub(crate) fn query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b))
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// MD5(RFC 1321) — 조각으로 받아 끝에 16바이트를 낸다.
pub(crate) struct Md5 {
    state: [u32; 4],
    block: [u8; 64],
    filled: usize,
    length: u64,
}

const SHIFT: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

const TABLE: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

impl Md5 {
    pub(crate) fn new() -> Md5 {
        Md5 {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            block: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.filled > 0 {
            let take = (64 - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < 64 {
                return;
            }
            let block = self.block;
            self.compress(&block);
            self.filled = 0;
        }
        let mut chunks = data.chunks_exact(64);
        for chunk in &mut chunks {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            self.compress(&block);
        }
        let rest = chunks.remainder();
        self.block[..rest.len()].copy_from_slice(rest);
        self.filled = rest.len();
    }

    pub(crate) fn finalize(mut self) -> [u8; 16] {
        let bits = self.length.wrapping_mul(8);
        let mut tail = vec![0x80u8];
        let used = (self.filled + 1) % 64;
        let pad = if used <= 56 { 56 - used } else { 120 - used };
        tail.resize(1 + pad, 0);
        tail.extend_from_slice(&bits.to_le_bytes());
        let length = self.length;
        self.update(&tail);
        self.length = length;
        let mut out = [0u8; 16];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        let [mut a, mut b, mut c, mut d] = self.state;
        for (i, k) in TABLE.iter().enumerate() {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let sum = f.wrapping_add(a).wrapping_add(*k).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(sum.rotate_left(SHIFT[(i / 16) * 4 + i % 4]));
        }
        for (s, v) in self.state.iter_mut().zip([a, b, c, d]) {
            *s = s.wrapping_add(v);
        }
    }
}

/// 소문자 16진수.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md5_hex(data: &[u8]) -> String {
        let mut h = Md5::new();
        h.update(data);
        hex(&h.finalize())
    }

    #[test]
    fn md5_matches_the_rfc_1321_suite() {
        for (input, want) in [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ] {
            assert_eq!(md5_hex(input.as_bytes()), want, "{input:?}");
        }
        // 조각으로 넣어도 같다 — 블록 경계(55 · 56 · 63 · 64 · 65 바이트)를 지나는 자리.
        for len in [55usize, 56, 63, 64, 65, 1000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut h = Md5::new();
            for piece in data.chunks(7) {
                h.update(piece);
            }
            assert_eq!(hex(&h.finalize()), md5_hex(&data), "{len}");
        }
    }

    #[test]
    fn base64_follows_the_padded_go_encodings() {
        assert_eq!(base64_decode(b"e30=", false).as_deref(), Some(&b"{}"[..]));
        assert_eq!(base64_decode(b"", false).as_deref(), Some(&b""[..]));
        assert_eq!(base64_decode(b"YQ==", false).as_deref(), Some(&b"a"[..]));
        assert_eq!(
            base64_decode(b"Y\r\nQ=\n=", false).as_deref(),
            Some(&b"a"[..])
        );
        assert_eq!(base64_decode(b"-_-_", true), base64_decode(b"+/+/", false));
        for bad in [
            &b"e30"[..],
            b"YQ=",
            b"Y===",
            b"YQ==x",
            b"not base64",
            b"-_-_",
            b"=AAA",
        ] {
            assert_eq!(
                base64_decode(bad, false),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(base64_decode(b"+/+/", true), None);
    }

    #[test]
    fn query_values_are_escaped_like_go() {
        assert_eq!(query_escape("/etc/os-release"), "%2Fetc%2Fos-release");
        assert_eq!(query_escape(r"C:\php\php.exe"), "C%3A%5Cphp%5Cphp.exe");
        assert_eq!(query_escape("a b~_.-"), "a+b~_.-");
        assert_eq!(query_escape("한"), "%ED%95%9C");
    }
}
