//! `collect_extra` 의 `ref` 형 — 두 번째 패스 (설계-02 §6-1).
//!
//! **여기가 이 기능의 존재 이유를 재는 자리다.** 매니페스트를 쓸 때는 페이로드
//! 경로를 모른다. 앞선 룰이 그것을 찾아내고, `ref` 형이 그 본문을 스냅샷에
//! 담고, 그제서야 YARA 가 훑을 바이트가 생긴다.
//!
//! 바이너리를 실제로 띄운다. 내부 함수를 부르면 `수집 → 평가 → 해소 → 재평가`
//! 순서 자체가 검사되지 않는데, 이 기능은 **그 순서가 전부**다.

use std::path::{Path, PathBuf};
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_remedy");

fn work(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join("remedy-cli-extra-ref").join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("작업 디렉터리");
    d
}

struct Run {
    code: i32,
    text: String,
}

fn run(args: &[&str]) -> Run {
    let out = Command::new(EXE)
        .args(args)
        .env("REMEDY_ELEVATION", "yes")
        // 시험은 한국어 문구를 단정한다. 기본 언어는 영어다 (2026-09-06).
        .env("REMEDY_LANG", "ko")
        .output()
        .unwrap_or_else(|e| panic!("{EXE} 실행 실패: {e}"));
    Run {
        code: out.status.code().unwrap_or(-1),
        text: String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr),
    }
}

/// 마커 하나와, **매니페스트가 이름을 모르는** 페이로드 하나.
fn tree(base: &Path) -> PathBuf {
    let app = base.join("tree").join("app-x");
    std::fs::create_dir_all(&app).expect("트리");
    std::fs::write(app.join("marker.txt"), b"MARKER").expect("marker");
    // 이름도 내용도 매니페스트에 적히지 않는다. 룰이 찾아낸다.
    std::fs::write(
        app.join("stage2.js"),
        b"var q=1; REMEDY_LAB_EVIL_STRING; go()",
    )
    .expect("payload");
    base.join("tree")
}

/// 플러그인 + 그 옆의 `rules/`.
///
/// `extra` 로 `collect_extra` 블록을 갈아 끼워 같은 룰을 다른 선언으로 돌린다.
fn plugin(base: &Path, root: &Path, extra: &str) -> PathBuf {
    let dir = base.join("plug");
    std::fs::create_dir_all(dir.join("rules")).expect("플러그인 디렉터리");
    std::fs::write(
        dir.join("rules").join("lab.yar"),
        "rule Evil { strings: $a = \"REMEDY_LAB_EVIL_STRING\" condition: $a }",
    )
    .expect("yar");

    let p = dir.join("plugin.yaml");
    let root = root.display().to_string();
    std::fs::write(
        &p,
        format!(
            r#"schema_version: 1
id: extra-ref-test
version: 1.0.0
min_core: '1.0.0'
platforms: [windows, linux]
name: {{ en: 'collect_extra ref' }}
scan_roots: ['{root}']
subjects: [file]
detect:
  - id: dropper
    subject: file
    where:
      - {{ field: path, op: ends_with, value: 'marker.txt' }}
    capture:
      dir: 'path | dirname'
  - id: payload
    subject: file
    from: '${{dropper.dir}}'
    where:
      - {{ field: path, op: ends_with, value: '.js' }}
  - id: evil
    subject: file
    from: '${{dropper.dir}}'
    where:
      - {{ field: content_ref, op: yara, value: 'rules/lab.yar:Evil' }}
verdict:
  require: 'evil'
{extra}
"#
        ),
    )
    .expect("plugin.yaml");
    p
}

/// 수집 백엔드는 **Windows 에만 있다.** 다른 플랫폼에서 `collect`·`scan` 은
/// `NoBackend` 로 끝나므로, 두 번째 패스를 재는 검사는 여기 묶는다
/// (설계-09 P12 에서 Linux 가 들어온다).
#[cfg(windows)]
mod on_metal {
    use super::*;

    /// 판정 수. **빈 배열은 직렬화에서 빠진다** — 없는 것과 0건이 같은 뜻이다.
    fn verdicts(scan: &serde_json::Value) -> usize {
        scan["verdicts"].as_array().map(|v| v.len()).unwrap_or(0)
    }

    fn scan(base: &Path, plugin: &Path) -> (Run, serde_json::Value, serde_json::Value) {
        let out = base.join("out");
        std::fs::create_dir_all(&out).expect("out");
        let r = run(&[
            "scan",
            "--plugin",
            &plugin.display().to_string(),
            "--out-dir",
            &out.display().to_string(),
        ]);
        let read = |n: &str| -> serde_json::Value {
            let p = out.join(n);
            serde_json::from_slice(
                &std::fs::read(&p)
                    .unwrap_or_else(|e| panic!("{} 를 읽지 못했다: {e}\n{}", p.display(), r.text)),
            )
            .expect("json")
        };
        let a = read("artifacts.json");
        let s = read("scan.json");
        (r, a, s)
    }

    #[test]
    fn a_ref_makes_yara_see_bytes_it_could_not_see_before() {
        // **이것이 전부다.** `ref` 없이는 훑을 바이트가 없어 판정이 서지 않고,
        // `ref` 가 있으면 선다. 같은 룰, 같은 파일, `collect_extra` 만 다르다.
        let base = work("sees");
        let root = tree(&base);

        // (1) ref 없이 — 담긴 본문이 없으므로 YARA 는 미평가고 판정이 없다.
        let p = plugin(&base, &root, "");
        let (r, art, sc) = scan(&base, &p);
        assert!(
            art["blobs"]
                .as_object()
                .map(|b| b.is_empty())
                .unwrap_or(true),
            "본문을 담으라고 하지 않았는데 담겼다"
        );
        assert_eq!(
            verdicts(&sc),
            0,
            "훑을 바이트가 없는데 판정이 섰다\n{}",
            r.text
        );
        // **"안 맞았다" 가 아니라 "못 봤다" 로 나가야 한다** — 미평가를 감추면
        // 훑지 않은 룰이 무해 판정처럼 읽힌다.
        assert!(
            r.text.contains("평가하지 못했습니다"),
            "미평가를 알리지 않는다\n{}",
            r.text
        );
        // **그리고 종료 코드가 그것을 말해야 한다** (결정 2026-10-26). 2026-10-25
        // 까지 여기서 0 "위협 없음" 이 나갔다 — 무인 배포는 위의 주의 줄이 실린
        // stderr 를 버리므로, 재지 못한 스캔이 깨끗하다고 말한 셈이다.
        assert_eq!(
            r.code, 6,
            "본문이 없어 YARA 를 재지 못했는데 '위협 없음을 말할 수 없다' 가 아니다\n{}",
            r.text
        );
        assert!(
            r.text.contains("YARA 규칙 1개를 평가하지 못했습니다"),
            "종료 코드 6 의 사유가 화면에 없다\n{}",
            r.text
        );
        let obs = &sc["observation"]["unevaluated_rules"];
        assert!(
            obs.as_array().is_some_and(|a| !a.is_empty()),
            "scan.json 의 관측에 미평가 규칙이 실리지 않았다: {obs}"
        );

        // (2) ref 로 — 룰이 찾아낸 파일의 본문이 담기고, 같은 룰이 이제 맞는다.
        let base = work("sees2");
        let root = tree(&base);
        let p = plugin(
            &base,
            &root,
            "collect_extra:\n  - { ref: payload, content: true }",
        );
        let (r, art, sc) = scan(&base, &p);

        let blobs = art["blobs"].as_object().expect("blobs");
        assert_eq!(blobs.len(), 1, "본문이 담기지 않았다\n{}", r.text);

        // 담긴 본문이 **그 파일의 레코드에 이어져** 있어야 룰이 훑을 수 있다.
        let files = art["file"].as_array().expect("file 관찰");
        let linked: Vec<&serde_json::Value> = files
            .iter()
            .filter(|f| f["content_ref"].is_string())
            .collect();
        assert_eq!(linked.len(), 1, "본문이 레코드에 이어지지 않았다");
        assert!(blobs.contains_key(linked[0]["content_ref"].as_str().unwrap()));

        assert_eq!(
            verdicts(&sc),
            1,
            "본문이 담겼는데도 판정이 서지 않았다\n{}",
            r.text
        );
        assert_eq!(r.code, 2, "찾았으면 2 다 (P4 에는 치료가 없다)\n{}", r.text);
    }

    #[test]
    fn the_saved_snapshot_reproduces_the_saved_verdict() {
        // **결정성.** 저장된 `artifacts.json` 을 다시 평가하면 저장된 `scan.json`
        // 과 같아야 한다. 두 번째 패스가 스냅샷을 바꾸므로, 바뀌기 전 것을 저장하면
        // 여기가 깨진다 — 사내에서 스냅샷만 받아 재평가하는 경로(설계-03 §1 (4))가
        // 그때부터 다른 답을 낸다.
        let base = work("determinism");
        let root = tree(&base);
        let p = plugin(
            &base,
            &root,
            "collect_extra:\n  - { ref: payload, content: true }",
        );
        let (r0, _, first) = scan(&base, &p);
        // **비교할 것이 있어야 비교가 된다.** 양쪽이 다 비면 이 시험은 아무것도
        // 재지 않는다 — 실제로 필드 경로를 잘못 짚어 그렇게 통과한 적이 있다.
        assert_eq!(
            verdicts(&first),
            1,
            "판정이 없으면 대조가 무의미하다\n{}",
            r0.text
        );

        let again = base.join("again");
        std::fs::create_dir_all(&again).expect("again");
        let r = run(&[
            "evaluate",
            "--artifacts",
            &base
                .join("out")
                .join("artifacts.json")
                .display()
                .to_string(),
            "--plugin",
            &p.display().to_string(),
            "--out",
            &again.join("scan.json").display().to_string(),
        ]);
        let second: serde_json::Value =
            serde_json::from_slice(&std::fs::read(again.join("scan.json")).unwrap_or_else(|e| {
                panic!("재평가 산출물이 없다: {e} (exit {})\n{}", r.code, r.text)
            }))
            .expect("json");

        assert_eq!(
            first["verdicts"], second["verdicts"],
            "같은 스냅샷이 다른 판정을 냈다 (exit {})\n{}",
            r.code, r.text
        );
        assert_eq!(
            first["evidence"].as_array().map(|v| v.len()),
            second["evidence"].as_array().map(|v| v.len()),
            "증거 수가 다르다"
        );
    }

    #[test]
    fn collect_alone_says_the_ref_needs_scan() {
        // `collect` 단독에는 증거가 없다. 조용히 넘어가면 그 본문에 걸린 YARA
        // 규칙이 영영 미평가인데 아무도 모른다.
        let base = work("collect-only");
        let root = tree(&base);
        let p = plugin(
            &base,
            &root,
            "collect_extra:\n  - { ref: payload, content: true }",
        );
        let out = base.join("out");
        std::fs::create_dir_all(&out).expect("out");

        let r = run(&[
            "collect",
            "--plugin",
            &p.display().to_string(),
            "--out",
            &out.join("artifacts.json").display().to_string(),
        ]);
        assert!(
            r.text.contains("증거"),
            "왜 못 풀었는지 말하지 않는다\n{}",
            r.text
        );
        assert!(
            r.text.contains("scan"),
            "무엇을 하면 되는지 말하지 않는다\n{}",
            r.text
        );
    }
}

// ───────────────────────────── 어느 플랫폼에서나 도는 것

#[test]
fn a_ref_to_a_missing_rule_is_caught_by_lint() {
    // 실행해 봐야 아는 것보다, 룰을 고칠 수 있는 자리에서 아는 편이 낫다.
    let base = work("lint");
    let root = tree(&base);
    let p = plugin(
        &base,
        &root,
        "collect_extra:\n  - { ref: 없는룰, content: true }",
    );
    let r = run(&["plugin", "lint", &p.display().to_string()]);
    assert_ne!(r.code, 0, "없는 룰을 가리키는데 통과했다\n{}", r.text);
    assert!(r.text.contains("없는 규칙"), "{}", r.text);
    // 유효 목록을 함께 줘야 그 자리에서 고친다 (설계-06 §7).
    assert!(
        r.text.contains("payload"),
        "쓸 수 있는 것을 안 알려준다\n{}",
        r.text
    );
}
