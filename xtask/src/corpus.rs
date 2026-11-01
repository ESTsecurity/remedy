//! 청정 코퍼스 스냅샷 만들기 — 스크러빙과 압축 (설계-04 §3.2, 설계-09 P12).
//!
//! # 왜 도구가 필요한가
//!
//! `corpus/clean/` 에 쌓이는 스냅샷이 **오탐 방지의 실질적 사거리**다. VM 으로는
//! 몇 개밖에 못 돌리지만 스냅샷은 CI 에서 매 커밋 돌아간다.
//!
//! 그리고 이 도구가 존재하는 이유는 **스크러빙 하나**다. 손으로 뜨면 언젠가
//! 빠뜨리고, 그러면 기계 이름과 실행 시각이 저장소에 그대로 실린다. 여기서는
//! 빠뜨릴 수 없다.
//!
//! | 지우는 것 | 왜 |
//! |---|---|
//! | `host.hostname` | 어느 기계인지 |
//! | `run_id` · `created` · `collected_at` | 언제 누가 돌렸는지 |
//! | **'최근 문서' 자리의 레코드** | 사람이 **무엇을 열었는지** |
//!
//! # '최근 문서' 를 빼는 까닭 (2026-10-31)
//!
//! Windows 는 사용자가 연 문서의 바로가기를 `…\Microsoft\Windows\Recent\` 에
//! 쌓는다. **그 파일 이름이 문서의 제목이다** — 사람이 쓰던 기계를 뜨면 신분
//! 서류·금융·계약 문서의 제목이 이름 그대로 들어온다. 실제로 커밋된 스냅샷
//! 하나에서 그 자리의 레코드 110건이 발견됐고, 거기에 개인 서류의 제목이
//! 있었다 (설계-00 §7 — 개인정보는 수집 범위 밖이다).
//!
//! **이름으로는 막을 수 없다.** 어떤 문서를 열었는지는 미리 알 수 없으므로
//! 걸러야 하는 것은 낱말이 아니라 **자리**다. 그래서 여기서 빼낸다 —
//! `New-CorpusSnapshot.ps1` 도 같은 자리를 뺀다.
//!
//! **경로의 사용자 이름은 지우지 않는다.** `/home/analyst/...` 의 `analyst` 는
//! 데이터의 일부이고, 지우면 경로 모양에 걸린 룰을 이 코퍼스로 검증할 수 없게
//! 된다. 그래서 **랩 기계에서만 뜬다** — 고객 기계 스냅샷은 여기 들어갈 것이
//! 아니다 (설계-00 §7).
//!
//! # Windows 쪽과의 관계
//!
//! `testbed/harness/host/New-CorpusSnapshot.ps1` 이 같은 스크러빙을 자기 안에
//! 갖고 있다. **그쪽은 VM 세션을 열어 수집까지 하고**, 이 도구는 이미 떠 온
//! 파일 하나를 다룬다. 규칙이 두 곳에 있는 것은 알려진 중복이고, 여기가
//! 시험이 붙는 쪽이다.

use std::path::Path;

/// 지운 자리에 남기는 표시. PS1 쪽과 **같은 값**이어야 코퍼스가 한 종류로 읽힌다.
const MASK: &str = "<코퍼스>";

/// 통째로 지우는 최상위 키.
const VOLATILE: [&str; 3] = ["run_id", "created", "collected_at"];

/// 레코드를 통째로 빼내는 자리. 구분자를 역슬래시로 펴고 소문자로 맞춘 뒤 본다.
const RECENT_DIR: &str = r"\microsoft\windows\recent\";

/// 스크러빙 결과.
#[derive(Debug)]
pub struct Scrubbed {
    pub json: String,
    /// 확인용으로 함께 센 레코드 수(빼낸 뒤의 값).
    pub counts: Vec<(String, usize)>,
    /// '최근 문서' 자리라서 빼낸 레코드 수.
    pub dropped: usize,
    /// 본문에서 기계 이름을 바꿔 적은 자리 수(`host.hostname` 칸 밖).
    pub renamed: usize,
}

/// 이 경로가 '최근 문서' 자리 아래인가.
fn under_recent(path: &str) -> bool {
    let flat: String = path
        .chars()
        .map(|c| {
            if c == '/' {
                '\\'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    flat.contains(RECENT_DIR)
}

/// 최상위 배열에서 '최근 문서' 자리의 레코드를 빼낸다. 빼낸 수를 돌려준다.
///
/// **`path` 하나만 본다.** 실측에서 그 자리는 110건 전부 `path` 에 있었고
/// (`file` 65 · `shortcut` 38 · `text_config` 7), 레코드 전체를 문자열로 훑으면
/// 13,528건짜리 스냅샷에서 느려지며 PS1 쪽과 규칙을 맞추기도 어렵다.
fn drop_recent(doc: &mut serde_json::Value) -> usize {
    let mut dropped = 0;
    if let Some(obj) = doc.as_object_mut() {
        for v in obj.values_mut() {
            if let Some(arr) = v.as_array_mut() {
                let before = arr.len();
                arr.retain(|rec| {
                    !rec.get("path")
                        .and_then(|p| p.as_str())
                        .is_some_and(under_recent)
                });
                dropped += before - arr.len();
            }
        }
    }
    dropped
}

/// 스크러빙이 걸렸는지 확인할 때 함께 세는 관측. **레코드가 바뀌면 실패다.**
///
/// 문자열 검사만으로는 부족하다 — 직렬화 왕복에서 깊이 제한에 걸려 잘려도
/// 마스크는 제자리에 있기 때문이다.
const COUNTED: [&str; 9] = [
    "file",
    "persistence",
    "security_products",
    "autorun",
    "process",
    "av_exclusion",
    "text_config",
    "structured_config",
    // C-2 (2026-10-27). 실측에서 가장 건수가 많은 축 가운데 하나다
    // (리눅스 선언 스냅샷에 413~865개) — 왕복에서 잘리면 여기서 드러난다.
    "package",
];

pub fn run(args: &[String]) -> Result<(), String> {
    let mut input = None;
    let mut out = None;
    let mut label = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => {
                input = args.get(i + 1).cloned();
                i += 2;
            }
            "--out" => {
                out = args.get(i + 1).cloned();
                i += 2;
            }
            "--label" => {
                label = args.get(i + 1).cloned();
                i += 2;
            }
            other => return Err(format!("모르는 인자: {other}")),
        }
    }
    let input = input.ok_or("--in <collect 결과 JSON> 이 필요하다")?;
    let label = label.ok_or(
        "--label <이름> 이 필요하다. 환경을 알아볼 수 있게 짓는다 — \
         '무엇이 설치된 기계인가' 가 드러나야 나중에 사거리를 셀 수 있다",
    )?;
    let out = out.ok_or("--out <디렉터리> 가 필요하다")?;

    let text = std::fs::read_to_string(&input).map_err(|e| format!("{input}: {e}"))?;
    let out_doc = scrub(&text)?;
    let clean = out_doc.json;
    let report = out_doc.counts;

    let dir = Path::new(&out);
    std::fs::create_dir_all(dir).map_err(|e| format!("{out}: {e}"))?;
    let dest = dir.join(format!("{label}.json.gz"));
    let bytes = gzip(clean.as_bytes())?;
    std::fs::write(&dest, &bytes).map_err(|e| format!("{}: {e}", dest.display()))?;

    println!(
        "  {}  {}KB (원본 {}KB)",
        dest.file_name().unwrap_or_default().to_string_lossy(),
        bytes.len() / 1024,
        clean.len() / 1024
    );
    if out_doc.dropped > 0 {
        println!("    '최근 문서' 자리 {}건을 빼냈다", out_doc.dropped);
    }
    if out_doc.renamed > 0 {
        println!("    기계 이름 {}자리를 본문에서 바꿨다", out_doc.renamed);
    }
    for (k, n) in report {
        println!("    {k} {n}건");
    }
    println!("\n다음: cargo test -p remedy-core --test corpus   (G1)");
    Ok(())
}

/// 스냅샷 하나를 스크러빙한다. `(정리된 JSON, 관측 수)`.
///
/// # 지웠는지 다시 파싱해서 본다
///
/// 필드 이름이 바뀌면 대입이 **조용히 아무것도 하지 않고**, 그때 새는 것이
/// 정확히 지우려던 것이다.
pub fn scrub(text: &str) -> Result<Scrubbed, String> {
    let mut doc: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("스냅샷을 읽지 못했다: {e}"))?;

    // **세기 전에 빼낸다** — 아래 왕복 확인은 "레코드가 그대로인가" 를 보는 것이고,
    // 여기서 뺀 것은 의도된 변화다.
    let dropped = drop_recent(&mut doc);

    let before = counts(&doc);

    let host = doc
        .get_mut("host")
        .and_then(|h| h.as_object_mut())
        .ok_or("host 가 없다. collect 결과가 아니다")?;
    if !host.contains_key("hostname") {
        return Err("host.hostname 이 없다 — 필드 이름이 바뀌었으면 이 도구도 고쳐야 한다".into());
    }
    // 본문에서도 지우려면 **지우기 전에** 이름을 들고 있어야 한다.
    let host_name = host
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    host.insert("hostname".into(), MASK.into());

    let obj = doc.as_object_mut().ok_or("최상위가 객체가 아니다")?;
    for k in VOLATILE {
        if !obj.contains_key(k) {
            return Err(format!(
                "{k} 가 없다 — 필드 이름이 바뀌었으면 이 도구도 고쳐야 한다"
            ));
        }
        obj.insert(k.into(), MASK.into());
    }

    let mut clean = serde_json::to_string(&doc).map_err(|e| e.to_string())?;

    // **이름은 `host.hostname` 에만 있지 않다.** WSL 은 `hosts` 파일의
    // `127.0.1.1` 줄에 Windows 쪽 기계 이름을 적어 두고, 그 줄은 `hosts_entry`
    // 레코드가 되어 그대로 따라 들어온다 (실측 2026-10-31 — 커밋된 WSL 스냅샷
    // 둘에 이 PC 이름이 남아 있었다). `New-CorpusSnapshot.ps1` 은 본문에 이름이
    // 남으면 **멈추는데** 이쪽에는 그 검사가 없어 조용히 지나갔다.
    //
    // 여기서는 멈추는 대신 **바꿔 적는다** — WSL 스냅샷은 늘 그 줄을 갖고 있어
    // 멈추면 손으로 고치게 되고, 그것이 이 도구가 없애려던 바로 그 일이다.
    // 이름이 너무 짧으면 바꾸지 않고 멈춘다. 흔한 낱말을 본문에서 지우면
    // 데이터가 망가진다.
    let mut renamed = 0usize;
    if host_name != MASK {
        if host_name.chars().count() < 4 {
            return Err(format!(
                "기계 이름이 너무 짧아({} 글자) 본문에서 바꿀 수 없다 — 손으로 확인할 것",
                host_name.chars().count()
            ));
        }
        renamed = clean.matches(host_name.as_str()).count();
        if renamed > 0 {
            clean = clean.replace(host_name.as_str(), MASK);
        }
    }

    // 왕복해서 확인한다. 문자열 검사만으로는 잘림을 못 잡는다.
    let check: serde_json::Value =
        serde_json::from_str(&clean).map_err(|e| format!("왕복 파싱: {e}"))?;
    if check["host"]["hostname"] != MASK {
        return Err("스크러빙이 걸리지 않았다".into());
    }
    if !host_name.is_empty() && host_name != MASK && clean.contains(host_name.as_str()) {
        return Err("기계 이름이 본문에 남아 있다".into());
    }
    for k in VOLATILE {
        if check[k] != MASK {
            return Err(format!("스크러빙이 걸리지 않았다: {k}"));
        }
    }
    let after = counts(&check);
    if before != after {
        return Err(format!(
            "왕복에서 레코드가 바뀌었다: {before:?} -> {after:?}"
        ));
    }

    Ok(Scrubbed {
        json: clean,
        counts: after,
        dropped,
        renamed,
    })
}

fn counts(doc: &serde_json::Value) -> Vec<(String, usize)> {
    COUNTED
        .iter()
        .filter_map(|k| {
            doc.get(*k)
                .and_then(|v| v.as_array())
                .map(|a| (k.to_string(), a.len()))
        })
        .collect()
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(bytes).map_err(|x| x.to_string())?;
    e.finish().map_err(|x| x.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        serde_json::json!({
            "schema_version": 1,
            "kind": "artifacts",
            "run_id": "01JABCDEF",
            "created": "2026-08-27T01:02:03Z",
            "collected_at": "2026-08-27T01:02:04Z",
            "host": { "hostname": "DESKTOP-REAL", "os": "linux",
                      "version": "", "arch": "x86_64" },
            "scope": { "scan_roots": ["/home/analyst/.config"] },
            "file": [{ "path": "/home/analyst/.config/a.conf" }],
            "persistence": [{ "id": "x.service" }]
        })
        .to_string()
    }

    #[test]
    fn the_machine_and_the_moment_are_gone() {
        // **이 도구의 존재 이유다.** 하나라도 남으면 어느 기계에서 언제 떴는지가
        // 저장소에 실린다.
        let clean = scrub(&sample()).expect("스크러빙").json;
        assert!(!clean.contains("DESKTOP-REAL"), "{clean}");
        assert!(!clean.contains("01JABCDEF"), "{clean}");
        assert!(!clean.contains("2026-08-27T01:02"), "{clean}");
    }

    #[test]
    fn the_user_name_in_paths_stays() {
        // 경로의 사용자 이름은 **데이터다.** 지우면 경로 모양에 걸린 룰을 이
        // 코퍼스로 검증할 수 없게 된다. 그래서 랩 기계에서만 뜬다.
        let clean = scrub(&sample()).expect("스크러빙").json;
        assert!(clean.contains("/home/analyst/.config"), "{clean}");
    }

    #[test]
    fn the_records_survive_the_round_trip() {
        let counts = scrub(&sample()).expect("스크러빙").counts;
        assert_eq!(
            counts,
            vec![("file".to_string(), 1), ("persistence".to_string(), 1)]
        );
    }

    /// '최근 문서' 자리의 레코드가 든 스냅샷. 구분자를 양쪽 꼴로 섞어 둔다.
    fn with_recent() -> String {
        let bs = '\\';
        let recent =
            format!("C:{bs}Users{bs}test{bs}AppData{bs}Roaming{bs}Microsoft{bs}Windows{bs}Recent");
        serde_json::json!({
            "schema_version": 1,
            "kind": "artifacts",
            "run_id": "01JABCDEF",
            "created": "2026-08-27T01:02:03Z",
            "collected_at": "2026-08-27T01:02:04Z",
            "host": { "hostname": "DESKTOP-REAL", "os": "windows",
                      "version": "", "arch": "x86_64" },
            "scope": { "scan_roots": [recent.clone()] },
            "file": [
                { "path": format!("{recent}{bs}어느-문서.pdf.lnk") },
                { "path": "C:/Users/test/AppData/Roaming/Microsoft/Windows/Recent/another.lnk" },
                { "path": format!("C:{bs}Windows{bs}System32{bs}drivers{bs}etc{bs}hosts") }
            ],
            "shortcut": [{ "path": format!("{recent}{bs}x.lnk"), "target": "C:/x.exe" }]
        })
        .to_string()
    }

    #[test]
    fn the_machine_name_goes_from_the_body_too() {
        // **WSL 은 `hosts` 의 `127.0.1.1` 줄에 Windows 쪽 기계 이름을 적는다.**
        // 그 줄이 레코드가 되어 따라 들어오므로 `host.hostname` 만 지우면 남는다 —
        // 커밋된 스냅샷 둘에서 실제로 그렇게 남아 있었다 (2026-10-31).
        let mut v: serde_json::Value = serde_json::from_str(&sample()).unwrap();
        v["hosts_entry"] = serde_json::json!([
            { "line": "127.0.1.1\tDESKTOP-REAL. DESKTOP-REAL", "hostnames": ["DESKTOP-REAL"] }
        ]);
        let s = scrub(&v.to_string()).expect("스크러빙");
        assert!(!s.json.contains("DESKTOP-REAL"), "{}", s.json);
        assert_eq!(s.renamed, 3, "세 자리를 바꿨다고 말해야 한다");
        // 레코드는 남는다 — 지우는 것이 아니라 바꿔 적는 것이다.
        assert!(s.json.contains("127.0.1.1"), "{}", s.json);
    }

    #[test]
    fn a_name_too_short_to_replace_stops_the_run() {
        // 흔한 낱말을 본문에서 지우면 데이터가 망가진다. 그러면 멈춘다.
        let mut v: serde_json::Value = serde_json::from_str(&sample()).unwrap();
        v["host"]["hostname"] = serde_json::json!("wsl");
        let e = scrub(&v.to_string()).expect_err("멈춰야 한다");
        assert!(e.contains("짧아"), "{e}");
    }

    #[test]
    fn the_recent_documents_place_is_dropped() {
        // **이름으로는 막을 수 없는 부류다.** 사람이 무엇을 열었는지는 미리 알
        // 수 없으므로 자리로 뺀다 — 실제로 개인 서류의 제목이 들어와 있었다.
        let s = scrub(&with_recent()).expect("스크러빙");
        assert_eq!(s.dropped, 3, "역슬래시·슬래시 양쪽 꼴이 다 빠져야 한다");
        // 문서의 제목이 사라져야 한다. **훑은 범위(`scope`)는 건드리지 않는다** —
        // 그것은 레코드가 아니라 "어디를 봤는가" 이고, 지우면 범위를 속이는 것이 된다.
        for title in ["어느-문서", "another.lnk", "x.lnk"] {
            assert!(!s.json.contains(title), "{title}: {}", s.json);
        }
        // 그 자리가 아닌 레코드는 남는다.
        assert!(s.json.contains("drivers"), "{}", s.json);
        // 함께 센 수는 **빼낸 뒤**의 값이다.
        assert_eq!(s.counts, vec![("file".to_string(), 1)]);
    }

    #[test]
    fn a_path_that_merely_mentions_recent_stays() {
        // 자리의 이름이 아니라 **자리**를 본다. 한 마디만 같은 경로는 남는다.
        let bs = '\\';
        assert!(!under_recent(&format!(
            "C:{bs}Program Files{bs}Recent{bs}app.exe"
        )));
        assert!(!under_recent("/home/analyst/recent-notes.txt"));
        assert!(under_recent(&format!(
            "D:{bs}x{bs}MICROSOFT{bs}WINDOWS{bs}RECENT{bs}y.lnk"
        )));
    }

    #[test]
    fn a_renamed_field_stops_the_run() {
        // **필드 이름이 바뀌면 대입이 조용히 아무것도 하지 않는다.** 그때 새는
        // 것이 정확히 지우려던 것이므로, 모르고 지나가는 대신 멈춘다.
        let mut v: serde_json::Value = serde_json::from_str(&sample()).unwrap();
        let o = v.as_object_mut().unwrap();
        let id = o.remove("run_id").unwrap();
        o.insert("runId".into(), id);
        let e = scrub(&v.to_string()).expect_err("멈춰야 한다");
        assert!(e.contains("run_id"), "{e}");
    }

    #[test]
    fn something_that_is_not_a_snapshot_is_refused() {
        let e = scrub("{\"a\":1}").expect_err("멈춰야 한다");
        assert!(e.contains("host"), "{e}");
    }

    #[test]
    fn the_written_file_reads_back_as_the_same_snapshot() {
        // gzip 이 깨지면 코퍼스가 통째로 못 읽히고, 그 상태의 G1 은 **비어
        // 있는 코퍼스**가 되어 언제나 통과한다.
        let clean = scrub(&sample()).expect("스크러빙").json;
        let packed = gzip(clean.as_bytes()).expect("압축");
        use std::io::Read;
        let mut back = String::new();
        flate2::read::GzDecoder::new(&packed[..])
            .read_to_string(&mut back)
            .expect("해제");
        assert_eq!(back, clean);
    }
}
