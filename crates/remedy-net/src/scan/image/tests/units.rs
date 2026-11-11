//! Go 의 판독기를 따라 옮긴 부분의 단위 시험 — JSON · tar · zstd · 압축 선언. 스캐너에는 없던 시험이다. 바이트를
//! 바꾼 입력에서 판독기가 멈추지 않고(패닉 없이) 오류를 내는지도 본다 — 배포판은 패닉이면 프로세스가 끝난다.

use super::fixtures::*;
use crate::scan::image::expand::{drain_zeros, expanded};
use crate::scan::image::fault::{describe, Fault};
use crate::scan::image::json::{decode, JsonError};
use crate::scan::image::meta::Descriptor;
use crate::scan::image::tarball::{Header, TarReader, TYPE_DIR, TYPE_REG};
use crate::scan::image::zstd::Zstd;
use remedy_sdk::i18n::Lang;
use std::io::{self, Cursor, Read};

fn descriptor(text: &[u8]) -> Result<Descriptor, JsonError> {
    decode::<Descriptor>(text)
}

#[test]
fn json_folds_keys_and_later_duplicates_win() {
    let text = r#"{"MEDIATYPE":"a","mediatype":"b","ſize":3,"platform":{"os":"linux"},
        "platform":{"architecture":"arm64"},"digest":"x","digest":null,"annotations":{"k":"v"}}"#;
    let d = descriptor(text.as_bytes()).unwrap();
    assert_eq!(d.media_type, "b");
    assert_eq!(d.size, 3, "ſ 는 s 와 같은 키다");
    assert_eq!(
        (d.platform.os.as_str(), d.platform.architecture.as_str()),
        ("linux", "arm64")
    );
    assert_eq!(d.digest, "x", "null 은 문자열을 바꾸지 않는다");
    assert_eq!(d.annotations.get("k"), "v");
    let d = descriptor(br#"{"annotations":{"k":"v"},"annotations":null}"#).unwrap();
    assert_eq!(d.annotations.0, None, "null 은 맵을 비운다");
}

#[test]
fn json_checks_syntax_before_types_then_trailing_data() {
    for bad in [
        &br#"{"size":1.0}"#[..],
        br#"{"size":1e3}"#,
        br#"{"size":"1"}"#,
        br#"{"size":9223372036854775808}"#,
    ] {
        assert_eq!(
            descriptor(bad),
            Err(JsonError::Type),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    assert_eq!(
        descriptor(br#"{"size":-9223372036854775808}"#)
            .unwrap()
            .size,
        i64::MIN
    );
    // 같은 값 안의 문법 오류가 앞선다(Go 의 `Decoder.Decode` 는 값을 다 읽고 나서 칸에 넣는다).
    assert_eq!(descriptor(br#"{"size":"1","x":}"#), Err(JsonError::Syntax));
    assert_eq!(descriptor(br#"{"size":"1"} x"#), Err(JsonError::Type));
    assert_eq!(descriptor(b"{} {}"), Err(JsonError::Trailing));
    assert_eq!(descriptor(b"{} x"), Err(JsonError::Trailing));
    assert!(descriptor(b" {} \r\n\t").is_ok());
    for bad in [
        &b""[..],
        b"   ",
        b"{",
        br#"{"size":}"#,
        br#"{"a" 1}"#,
        br#"{"a":01}"#,
        b"{\"a\":\"\x01\"}",
    ] {
        assert_eq!(
            descriptor(bad),
            Err(JsonError::Syntax),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}

#[test]
fn json_repairs_broken_text_like_go() {
    let d = descriptor(
        b"{\"digest\":\"a\xff\xfeb\",\"data\":\"\\ud800x\",\"mediaType\":\"\\ud83d\\ude00\"}",
    )
    .unwrap();
    assert_eq!(d.digest, "a\u{fffd}\u{fffd}b", "깨진 바이트마다 U+FFFD");
    assert_eq!(d.data, "\u{fffd}x", "짝 없는 서로게이트는 U+FFFD");
    assert_eq!(d.media_type, "\u{1f600}");
}

#[test]
fn json_nesting_stops_at_ten_thousand() {
    let nested = |n: usize| format!(r#"{{"x":{}{}}}"#, "[".repeat(n), "]".repeat(n));
    assert!(descriptor(nested(9_999).as_bytes()).is_ok());
    assert_eq!(
        descriptor(nested(10_000).as_bytes()),
        Err(JsonError::Syntax)
    );
}

/// tar 를 끝까지 읽어 항목 머리와 자료를 모은다.
fn read_all(data: &[u8]) -> io::Result<Vec<(Header, Vec<u8>)>> {
    let mut tar = TarReader::new(Cursor::new(data));
    let mut out = Vec::new();
    while let Some(h) = tar.next()? {
        let mut body = Vec::new();
        tar.read_to_end(&mut body)?;
        out.push((h, body));
    }
    Ok(out)
}

/// 머리 블록 하나와 자료 — 종류 · 크기를 마음대로(PAX 머리 같은 특수 항목). 종류 글자는 바이트로 바로 적는다 —
/// tar 크레이트는 `\0` 을 `0` 으로 바꿔 적는다.
fn raw_entry(kind: u8, name: &str, body: &[u8]) -> Vec<u8> {
    let mut h = tar::Header::new_ustar();
    h.set_mode(0o644);
    h.set_size(body.len() as u64);
    let b = h.as_mut_bytes();
    b[..name.len()].copy_from_slice(name.as_bytes());
    b[156] = kind;
    h.set_cksum();
    let mut out = h.as_bytes().to_vec();
    out.extend_from_slice(body);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out
}

#[test]
fn tar_ends_like_go_archive_tar() {
    let one = tar(&[reg("a", "hello")]);
    let body = &one[..1024];
    // 끝 블록 둘 · 하나 뒤의 끝 · 블록 경계의 끝 · 채움이 덜 끝난 끝은 모두 정상 끝이다.
    for cut in [one.len(), 1024 + 512, 1024, 512 + 5 + 3] {
        let got = read_all(&one[..cut]).unwrap();
        assert_eq!(got.len(), 1, "{cut}");
        assert_eq!(got[0].1, b"hello");
    }
    // 자료가 모자라거나 머리 블록이 잘리면 오류.
    for cut in [512 + 3, 512 + 512 + 100] {
        assert!(read_all(&one[..cut]).is_err(), "{cut}");
    }
    // 0 블록 뒤에 0 이 아닌 블록.
    let mut bad = body.to_vec();
    bad.extend_from_slice(&[0u8; 512]);
    bad.extend_from_slice(&one[..512]);
    let err = read_all(&bad).unwrap_err();
    assert_eq!(describe(&err, Lang::Ko), Fault::TarHeader.message(Lang::Ko));
}

#[test]
fn tar_checks_headers_and_reads_pax_and_old_directories() {
    let mut damaged = tar(&[reg("a", "x")]);
    damaged[100] ^= 1;
    assert!(read_all(&damaged).is_err(), "체크섬이 틀린 머리를 받았다");
    // PAX 머리가 다음 항목의 이름과 크기를 바꾼다.
    let record = b"17 path=long/one\n10 size=2\n";
    let mut data = raw_entry(b'x', "PaxHeaders/a", record);
    data.extend(raw_entry(b'0', "short", b"ab"));
    data.extend_from_slice(&[0u8; 1024]);
    let got = read_all(&data).unwrap();
    assert_eq!(
        (got[0].0.name.as_slice(), got[0].0.size),
        (&b"long/one"[..], 2)
    );
    // 꼴이 틀린 PAX 크기 · 길이가 틀린 PAX 기록은 머리 오류.
    for record in [&b"11 size=-1\n"[..], b"12 size=2\n"] {
        let mut data = raw_entry(b'x', "PaxHeaders/a", record);
        data.extend(raw_entry(b'0', "short", b"ab"));
        data.extend_from_slice(&[0u8; 1024]);
        assert!(
            read_all(&data).is_err(),
            "{}",
            String::from_utf8_lossy(record)
        );
    }
    // 이름이 `/` 로 끝나는 옛 일반 파일은 폴더, 전역 PAX 는 항목으로 나온다.
    let mut data = raw_entry(0, "dir/", b"");
    data.extend(raw_entry(b'g', "global", b"12 path=xyz\n"));
    data.extend_from_slice(&[0u8; 1024]);
    let got = read_all(&data).unwrap();
    assert_eq!((got[0].0.typeflag, got[1].0.typeflag), (TYPE_DIR, b'g'));
    assert_ne!(got[1].0.typeflag, TYPE_REG);
}

#[test]
fn tar_reader_never_panics_on_mutated_input() {
    let mut data = raw_entry(b'x', "PaxHeaders/a", b"17 path=long/one\n");
    data.extend(tar(&[
        reg("a", "hello"),
        kind("l", b'2', "a"),
        reg("b", vec![7u8; 700]),
    ]));
    for i in 0..data.len() {
        for v in [0x00, 0xff, data[i] ^ 0x80, b'7'] {
            let mut b = data.clone();
            b[i] = v;
            let _ = read_all(&b);
        }
    }
    for cut in 0..data.len() {
        let _ = read_all(&data[..cut]);
    }
}

fn unzstd(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    Zstd::new(Cursor::new(data)).read_to_end(&mut out)?;
    Ok(out)
}

fn fault_of(result: io::Result<Vec<u8>>) -> String {
    describe(&result.unwrap_err(), Lang::Ko)
}

#[test]
fn zstd_frames_follow_the_go_decoder_rules() {
    let text: Vec<u8> = (0..20_000u32)
        .flat_map(|i| (i % 251).to_le_bytes())
        .collect();
    let frame = zstd(&text);
    assert_eq!(unzstd(&frame).unwrap(), text);
    // 프레임 둘 · 앞의 건너뛰는 프레임.
    assert_eq!(
        unzstd(&[frame.clone(), frame.clone()].concat()).unwrap(),
        [text.clone(), text.clone()].concat()
    );
    let skippable = [&[0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3][..], &frame].concat();
    assert_eq!(unzstd(&skippable).unwrap(), text);
    // 프레임 뒤의 1~3 바이트 · 체크섬이 틀린 프레임 · 잘린 프레임.
    for tail in 1..=3 {
        let mut data = frame.clone();
        data.extend(std::iter::repeat_n(0x28, tail));
        assert!(unzstd(&data).is_err(), "{tail} 바이트");
    }
    let mut damaged = frame.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert_eq!(
        fault_of(unzstd(&damaged)),
        Fault::ZstdChecksum.message(Lang::Ko)
    );
    assert!(unzstd(&frame[..frame.len() - 5]).is_err());
    // 머리 규칙 — 창 · 단일 구간 · 사전 · 예약 비트.
    let cases = [
        (vec![0x00, 0x88, 1, 0, 0], Fault::ZstdWindow),
        (vec![0xa0, 0x01, 0x00, 0x10, 0x04], Fault::ZstdSegment),
        (vec![0x01, 0x00, 0x07], Fault::ZstdDictionary),
        (vec![0x08, 0x00], Fault::ZstdHeader),
    ];
    for (header, fault) in cases {
        let data = [&[0x28, 0xb5, 0x2f, 0xfd][..], &header].concat();
        assert_eq!(
            fault_of(unzstd(&data)),
            fault.message(Lang::Ko),
            "{header:02x?}"
        );
    }
    assert!(Fault::ZstdWindow.message(Lang::En).contains("window"));
}

#[test]
fn zstd_reader_never_panics_on_mutated_input() {
    let text: Vec<u8> = (0..3_000u32).map(|i| (i * 7 % 13) as u8 + b'a').collect();
    let frame = zstd(&text);
    for i in 0..frame.len() {
        for v in [0x00, 0xff, frame[i] ^ 0x80, frame[i] ^ 0x01] {
            let mut b = frame.clone();
            b[i] = v;
            if let Ok(out) = unzstd(&b) {
                assert!(out.len() <= 64 << 20);
            }
        }
    }
    for cut in 0..frame.len() {
        let _ = unzstd(&frame[..cut]);
    }
}

fn expand(data: &[u8], media: &str) -> io::Result<Vec<u8>> {
    let b = budget();
    let mut out = Vec::new();
    expanded(Cursor::new(data), &b, media)?.read_to_end(&mut out)?;
    Ok(out)
}

#[test]
fn expanded_follows_the_declared_format() {
    let raw = b"plain layer bytes".to_vec();
    let gz = gzip(&raw);
    let layer = "application/vnd.oci.image.layer.v1.tar";
    assert_eq!(
        expand(&gz, layer).unwrap(),
        raw,
        "선언이 없어도 머리로 gzip 을 푼다"
    );
    assert_eq!(expand(&raw, layer).unwrap(), raw);
    assert_eq!(expand(&zstd(&raw), &format!("{layer}+zstd")).unwrap(), raw);
    let wrong = [
        (raw.clone(), format!("{layer}+gzip"), Fault::GzipDeclared),
        (gz.clone(), format!("{layer}+zstd"), Fault::ZstdDeclared),
        (
            raw.clone(),
            "application/vnd.docker.image.rootfs.diff.tar.gzip".to_string(),
            Fault::GzipDeclared,
        ),
    ];
    for (data, media, fault) in wrong {
        assert_eq!(
            fault_of(expand(&data, &media)),
            fault.message(Lang::Ko),
            "{media}"
        );
    }
    // gzip 멤버 둘은 이어 풀고, 멤버 뒤의 쓰레기 · 틀린 체크섬은 오류.
    assert_eq!(
        expand(&[gz.clone(), gz.clone()].concat(), layer).unwrap(),
        [raw.clone(), raw.clone()].concat()
    );
    let mut tail = gz.clone();
    tail.extend_from_slice(b"junk");
    assert_eq!(
        fault_of(expand(&tail, layer)),
        Fault::Gzip.message(Lang::Ko)
    );
    let mut crc = gz.clone();
    let at = crc.len() - 8;
    crc[at] ^= 1;
    assert_eq!(fault_of(expand(&crc, layer)), Fault::Gzip.message(Lang::Ko));
    // 푼 양은 *압축을 푼 양* 으로 센다.
    let b = budget();
    let mut out = Vec::new();
    expanded(Cursor::new(&gz), &b, layer)
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(b.usage().image_expanded_bytes, raw.len() as u64);
}

#[test]
fn drain_zeros_rejects_data_after_the_archive() {
    assert!(drain_zeros(&mut Cursor::new(vec![0u8; 100_000])).is_ok());
    let mut data = vec![0u8; 70_000];
    data[65_000] = 1;
    let err = drain_zeros(&mut Cursor::new(data)).unwrap_err();
    assert_eq!(
        describe(&err, Lang::Ko),
        Fault::TrailingData.message(Lang::Ko)
    );
}
