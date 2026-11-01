//! 감염 코퍼스 — **탐지 회귀** (설계-09 P9 항목 2).
//!
//! G1(`corpus.rs`)은 "여기서 아무것도 나오면 안 된다" 를 잰다. 그 대칭이
//! 여기다: **"여기서는 반드시 나와야 한다."** 룰이 통째로 죽어도 G1 은 영원히
//! 초록이므로, 그 자리를 막는 것은 이 파일뿐이다.
//!
//! # `evilai.rs` 와 무엇이 다른가
//!
//! `evilai.rs` 는 레코드를 **손으로 지어** 배선을 잰다 — 룰이 발화하고 판정이
//! 서고 계획이 나오는가. 그것으로 못 재는 것이 하나 있다: **실제 수집기가 뜬
//! 레코드의 모양.** 지어낸 레코드는 우리가 룰에 맞게 지은 것이라, 수집기가
//! `win.task.register_path` 를 다르게 채우거나 `args` 의 따옴표가 한 겹 다르면
//! 그 어긋남을 볼 수 없다. 룰은 맞는데 실기기에서만 안 맞는 상태가 된다.
//!
//! 여기 실린 스냅샷은 격리 VM 에서 `remedy collect` 가 실제로 뜬 것이고
//! (파일 8천여 · 지속성 2백여 건), 그 위에서 같은 물음을 다시 묻는다.
//!
//! # 페이로드 바이트는 실검체가 아니다
//!
//! 파일 본문만은 **룰에서 합성한 바이트**다. 저장소에 악성 바이트를 들이지
//! 않으면서 YARA 경로를 살리기 위해서이고, `evilai.rs` 가 같은 이유로 같은
//! 선택을 했다.
//! 실검체 바이트로 룰이 발화하는지는 `cargo xtask yara` 가 따로 잰다
//! (16/16).
//!
//! 바뀌는 것은 **파일 하나의 바이트뿐**이다. 경로·지속성·`principal`·AV 예외는
//! 전부 실제 수집기가 뜬 그대로이고, 이 파일이 재려는 것이 정확히 그쪽이다.
//!
//! 스냅샷 생성:
//!   `testbed\harness\host\New-InfectedSnapshot.ps1 -Label evilai-locust -Force -SamplePath <검체>`

use remedy_sdk::artifact::ArtifactsEnvelope;
use remedy_sdk::catalog::Op;
use remedy_sdk::manifest::PluginManifest;
use remedy_testkit::{load_corpus, read_artifacts};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("저장소 루트")
}

fn corpus_dir() -> PathBuf {
    repo_root().join("corpus/infected")
}

fn plugin_dir() -> PathBuf {
    repo_root().join("plugins/evilai-locust")
}

fn manifest() -> PluginManifest {
    let p = plugin_dir().join("plugin.yaml");
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_yaml_ng::from_str(&text).unwrap_or_else(|e| panic!("매니페스트가 파싱되지 않는다: {e}"))
}

/// 제품 CLI 의 `load_rules` 와 같은 규칙 — 이름은 `rules/<파일>.yar` 이다.
///
/// 절대 경로로 담으면 `rules/x.yar:name` 참조가 어긋나 룰이 통째로 미평가가
/// 된다. 그 상태의 "판정 없음" 은 탐지 실패가 아니라 **측정 실패**다.
fn rules() -> Vec<(String, String)> {
    let dir = plugin_dir().join("rules");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir).expect("rules 디렉터리").flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("yar")) {
            let name = format!("rules/{}", p.file_name().unwrap().to_string_lossy());
            out.push((name, std::fs::read_to_string(&p).expect("룰 파일")));
        }
    }
    out.sort();
    assert!(!out.is_empty(), "rules 디렉터리에서 .yar 을 읽지 못했다");
    out
}

/// 룰이 발화하는 바이트를 **룰 파일에서** 만든다.
///
/// `evilai.rs` 의 같은 이름 함수와 같은 로직이고, `New-InfectedSnapshot.ps1` 이
/// 스냅샷에 실을 때 쓰는 것과도 같다. 셋이 갈라지면 아래
/// `the_payload_blob_is_what_the_rules_expect` 가 바이트 비교에서 걸린다 —
/// 중복이 조용히 어긋나지 않도록 잡아 두는 자리가 거기다.
fn payload_bytes() -> Vec<u8> {
    let yar = std::fs::read_to_string(plugin_dir().join("rules/evilai.yar")).expect("룰 파일");
    // `        $a00 = "'AM9P'" ascii` 에서 큰따옴표 안을 꺼낸다.
    let mut consts = Vec::new();
    for line in yar.lines() {
        let t = line.trim();
        if !t.starts_with("$a") {
            continue;
        }
        let Some(open) = t.find('"') else { continue };
        let Some(close) = t.rfind('"') else { continue };
        if close > open + 1 {
            consts.push(t[open + 1..close].to_string());
        }
    }
    assert!(
        consts.len() >= 25,
        "룰에서 상수를 {}개밖에 꺼내지 못했다 — 이 시험은 아무것도 재지 못한다",
        consts.len()
    );
    consts.truncate(30);
    format!(
        "'use strict';function R(){{var F=[{}];return F;}}",
        consts.join(",")
    )
    .into_bytes()
}

/// 감염 스냅샷 전부.
///
/// **비어 있으면 그 자리에서 멈춘다.** 코퍼스가 없는데 초록인 시험은
/// "탐지된다" 가 아니라 "잴 것이 없었다" 이고, 둘은 화면에서 구분되지 않는다.
fn snapshots() -> Vec<(String, ArtifactsEnvelope)> {
    let entries = load_corpus(&corpus_dir()).expect("코퍼스 로드");
    assert!(
        !entries.is_empty(),
        "corpus/infected 가 비어 있다 — 탐지 회귀가 공허하다.\n\
         생성: testbed\\harness\\host\\New-InfectedSnapshot.ps1 -Label evilai-locust -SamplePath <검체>"
    );
    entries
        .into_iter()
        .map(|e| {
            let env = read_artifacts(&e.path).unwrap_or_else(|err| panic!("{}: {err}", e.name));
            (e.name, env)
        })
        .collect()
}

fn evaluate(
    env: &ArtifactsEnvelope,
    rules: &[(String, String)],
) -> remedy_sdk::artifact::ScanEnvelope {
    remedy_core::pipeline::evaluate_with_rules(env, &manifest(), rules).expect("평가")
}

// ────────────────────────────────────────────────── 스냅샷 자체

#[test]
fn the_infected_corpus_is_present_and_complete() {
    // 잘렸거나 접근이 거부된 스냅샷 위에서는 "탐지됐다" 도 "안 됐다" 도 말할 수
    // 없다. 그 안의 "없다" 는 "못 봤다" 일 수 있다.
    for (name, env) in snapshots() {
        assert!(
            !env.body.scope.truncated,
            "{name}: 상한에 걸려 잘린 스냅샷이다"
        );
        assert_eq!(
            env.body.scope.denied_dirs, 0,
            "{name}: 접근 거부 디렉터리가 있다. 관리자 권한으로 다시 뜰 것"
        );
        assert!(
            !env.body.scope.scan_roots.is_empty(),
            "{name}: scan_roots 가 비어 있다"
        );
    }
}

#[test]
fn the_payload_blob_is_what_the_rules_expect() {
    // **스냅샷은 낡는다.** 룰의 상수가 새 검체로 다시 도출되면 스냅샷에 구워
    // 넣은 바이트는 더 이상 발화하지 않고, 그때 나오는 "판정 없음" 은 룰이
    // 깨진 것과 구분되지 않는다. 그 어긋남을 여기서 먼저 잡는다.
    use base64::Engine;
    let want = payload_bytes();
    for (name, env) in snapshots() {
        assert!(
            !env.body.blobs.is_empty(),
            "{name}: 스냅샷에 본문(blobs)이 없다 — YARA 가 훑을 바이트가 없으면 \
             룰은 미매치가 아니라 미평가다"
        );
        let matched = env.body.blobs.iter().any(|(key, b64)| {
            let got = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap_or_else(|e| panic!("{name}/{key}: base64 를 풀지 못했다 {e}"));
            got == want
        });
        assert!(
            matched,
            "{name}: 스냅샷의 본문이 지금 룰에서 만드는 바이트와 다르다.\n\
             룰이 바뀌었으면 스냅샷도 다시 떠야 한다:\n  \
             testbed\\harness\\host\\New-InfectedSnapshot.ps1 -Label evilai-locust -Force -SamplePath <검체>"
        );
    }
}

// ────────────────────────────────────────────────── 탐지 본체

#[test]
fn the_plugin_finds_the_infection() {
    // 이 파일의 본체. 실제 수집기가 뜬 레코드 위에서 판정이 서는가.
    let rules = rules();
    for (name, env) in snapshots() {
        let scan = evaluate(&env, &rules);
        assert!(
            !scan.body.verdicts.is_empty(),
            "{name}: 감염 스냅샷에서 판정이 서지 않았다.\n  issues: {:?}\n  증거: {}건",
            scan.body.issues,
            scan.body.evidence.len()
        );
    }
}

#[test]
fn the_verdict_becomes_a_removal_plan() {
    // 판정만 서고 치료가 도출되지 않으면 사용자에게는 아무 일도 일어나지 않는다.
    let m = manifest();
    let rules = rules();
    for (name, env) in snapshots() {
        let scan = evaluate(&env, &rules);
        let plan = remedy_core::plan(&scan, Some(&m)).expect("계획");
        let ops: BTreeSet<Op> = plan.body.actions.iter().map(|a| a.op).collect();
        let dump = || {
            format!(
                "actions={:?}",
                plan.body
                    .actions
                    .iter()
                    .map(|a| (a.seq, a.op.id(), a.target.clone()))
                    .collect::<Vec<_>>()
            )
        };
        for want in [
            Op::PersistenceDisable,
            Op::PersistenceDelete,
            Op::AutorunRemove,
            Op::FileQuarantineOnly,
            Op::AvRestoreExclusions,
        ] {
            assert!(
                ops.contains(&want),
                "{name}: {} 이 계획되지 않았다.\n{}",
                want.id(),
                dump()
            );
        }
        // 순서: 비활성화(3단계)가 삭제보다 먼저다. 지우고 나면 되돌릴 자리가 없다.
        let seq_of = |op: Op| plan.body.actions.iter().find(|a| a.op == op).map(|a| a.seq);
        assert!(
            seq_of(Op::PersistenceDisable) < seq_of(Op::PersistenceDelete),
            "{name}: 작업 삭제가 비활성화보다 먼저다.\n{}",
            dump()
        );

        // **대상이 값 이름까지 가리키는가.** `Op` 이 계획에 있는 것과 그것이
        // 실제로 실행될 수 있는 것은 다르다 — `autorun.remove` 의 대상이
        // `...\Run` 에서 끊기면 백업이 그 자리를 읽지 못해 `apply` 가 파괴
        // 전에 가드 중단으로 끝난다. 감염 VM 에서 치료를 처음 돌렸을 때
        // 드러난 자리이고, 그때까지 이 시험은 Op 이 있다는 것만 보고 초록이었다.
        let autorun = plan
            .body
            .actions
            .iter()
            .find(|a| a.op == Op::AutorunRemove)
            .expect("autorun.remove");
        let target = autorun.target.clone().unwrap_or_default();
        assert!(
            target.len() > r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".len(),
            "{name}: autorun.remove 의 대상이 키에서 끊겼다 — 값 이름이 없다: {target:?}\n{}",
            dump()
        );

        // **P10-C 에서 열렸다.** 이전에는 계획에 들어가지 못해 빈 폴더가 남았고
        // 그 사실이 `deferred` 로 보고됐다. 이제 페이로드 디렉터리까지 정리된다.
        //
        // 계획에 들어가려면 가드 셋을 통과해야 한다 — 증거에서 파생된 경로인가,
        // 그 안에서 악성으로 판정된 것이 있는가, 보호 목록과 교차하지 않는가
        // (설계-03 §4). 네 번째(하위 신뢰 서명)는 실행 시점이다.
        assert!(
            ops.contains(&Op::DirDeleteRecursive),
            "{name}: 재귀 삭제가 계획에 없다 — 가드에 걸렸을 수 있다
{}",
            dump()
        );
    }
}

// ────────────────────────────────────────────── 역검증 — 공허하지 않은가

#[test]
fn without_the_rules_there_is_no_verdict() {
    // **이 시험이 정말 룰을 재고 있는가.** 룰을 빼도 판정이 선다면 위 검사는
    // 룰이 아니라 다른 무언가를 재고 있는 것이고, 룰이 죽는 회귀를 못 잡는다.
    let rules = rules();
    for (name, env) in snapshots() {
        let with = evaluate(&env, &rules);
        assert!(!with.body.verdicts.is_empty(), "{name}: 전제가 무너졌다");

        let without = evaluate(&env, &[]);
        assert!(
            without.body.verdicts.is_empty(),
            "{name}: 룰 없이도 판정이 섰다 — 이 시험은 YARA 룰을 재고 있지 않다"
        );
        // 그리고 그 사실이 **보고되어야** 한다. 조용히 사라지면 "안 맞았다" 로 읽힌다.
        assert!(
            without
                .body
                .issues
                .iter()
                .any(|i| i.contains("평가하지 못했습니다")),
            "{name}: 룰이 없는데 미평가가 보고되지 않았다 — issues: {:?}",
            without.body.issues
        );
        // **룰 파일이 실리지 않은 것도 재지 못한 것이다** (결정 2026-10-26) — 판정이
        // 없으므로 이 관측이 완전하면 종료 코드 0 "위협 없음" 이 나간다.
        assert!(
            !without.body.observation.is_complete(),
            "{name}: 룰이 없어 재지 못했는데 관측이 완전하다고 한다 — {:?}",
            without.body.observation
        );
        // 룰이 있으면 그대로 완전해야 한다 — 역검증.
        assert!(
            with.body.observation.unevaluated_rules.is_empty(),
            "{name}: 룰이 다 실렸는데 미평가가 남았다 — {:?}",
            with.body.observation.unevaluated_rules
        );
    }
}

#[test]
fn stripping_the_payload_bytes_is_reported_as_unevaluated() {
    // 본문 없는 스냅샷에서 YARA 는 **미매치가 아니라 미평가**여야 한다
    // (설계-03 §1). 미평가가 조용히 "안 맞았다" 로 나가면, 절반만 훑은 스캔이
    // "위협 없음" 을 결론짓는다. 실제로 `collect` 산출물이 이 상태다.
    let rules = rules();
    for (name, env) in snapshots() {
        let mut stripped = env.clone();
        let n = strip_content_ref(&mut stripped);
        assert_eq!(n, 1, "{name}: content_ref 를 가진 파일 레코드가 {n}건이다");

        let scan = evaluate(&stripped, &rules);
        assert!(
            scan.body.verdicts.is_empty(),
            "{name}: 본문이 없는데 판정이 섰다 — YARA 가 훑지 않은 것을 훑었다고 말한다"
        );
        assert!(
            scan.body
                .issues
                .iter()
                .any(|i| i.contains("content_ref") || i.contains("본문 참조")),
            "{name}: 본문이 없다는 사실이 보고되지 않았다 — issues: {:?}",
            scan.body.issues
        );

        // **그 사실이 관측 불완전으로 이어져야 한다** (결정 2026-10-26). 위 주석이
        // 말한 바로 그 실패 — 판정 없음 + 완전한 관측 = 종료 코드 0 — 를 막는 자리다.
        // 파이프라인이 스냅샷의 관측으로 덮어쓰면서 평가기의 기록을 지우면 여기서 진다.
        assert!(
            !scan.body.observation.unevaluated_rules.is_empty(),
            "{name}: 본문 없는 YARA 가 관측에 실리지 않았다 — {:?}",
            scan.body.observation
        );
        assert!(
            !scan.body.observation.is_complete(),
            "{name}: 재지 못했는데 관측이 완전하다고 한다"
        );

        // 계획이 같은 관측을 물려받는다 — `run` · `apply` 의 종료 코드는 계획의
        // 관측을 본다.
        let plan = remedy_core::pipeline::plan(&scan, Some(&manifest())).expect("계획");
        assert_eq!(
            plan.body.observation, scan.body.observation,
            "{name}: 계획이 관측을 물려받지 않았다"
        );
    }
}

// ────────────────────────────────────────────────────────── 스냅샷 조작

/// 페이로드 파일 레코드에서 `content_ref` 를 떼어낸다. 뗀 건수를 돌려준다.
fn strip_content_ref(env: &mut ArtifactsEnvelope) -> usize {
    let mut n = 0;
    if let Some(files) = env
        .body
        .observations
        .get_mut("file")
        .and_then(|v| v.as_array_mut())
    {
        for r in files.iter_mut() {
            if let Some(o) = r.as_object_mut() {
                if o.remove("content_ref").is_some() {
                    n += 1;
                }
            }
        }
    }
    n
}

/// **정답이 자기 채점 기준을 넘는가** (설계-09 P11 · AI 합격 시험 4 번 판정).
///
/// `testbed/ai-exam/expected-ops.txt` 는 감염 스냅샷에서 반드시 나와야 하는 Op
/// 목록이고, `cargo xtask exam` 의 4 번 판정이 그것으로 응시자를 잰다.
///
/// **첫 플러그인이 그 기준을 못 넘기면 기준 쪽이 틀린 것이다.** 응시자만
/// 채점하고 기준은 아무도 안 재면, 도달할 수 없는 목록이 조용히 자리 잡는다 —
/// 1 회차가 그렇게 무너졌다.
#[test]
fn the_first_plugin_meets_the_exam_baseline() {
    use std::collections::BTreeSet;

    // **evilai-locust 위협의 기준이다.** 시험은 위협마다 나뉘어 있고
    // (`testbed/ai-exam/threats/`), 이 파일이 보는 감염 코퍼스는 그 위협의
    // 것이다. 모든 위협의 정답을 한꺼번에 재는 것은 `xtask::exam` 테스트다.
    let list = repo_root().join("testbed/ai-exam/threats/evilai-locust/expected-ops.txt");
    let text = std::fs::read_to_string(&list).expect("expected-ops.txt");
    let expected: BTreeSet<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    assert!(!expected.is_empty(), "{} 가 비어 있다", list.display());

    // **Op 이름이 아니라 `(Op, 대상)` 자리표로 잰다** (2026-09-04). 종류만
    // 세면 같은 Op 을 하나만 낸 계획과 둘 다 낸 계획이 구별되지 않는다.
    // 렌더링은 `remedy_testkit::locator` 하나뿐이다 — 채점기와 이 시험이
    // 같은 함수를 쓴다.
    let m = manifest();
    let rules = rules();
    let mut got: BTreeSet<String> = BTreeSet::new();
    for (name, env) in snapshots() {
        let scan = evaluate(&env, &rules);
        let plan = remedy_core::plan(&scan, Some(&m)).expect("계획");
        assert!(
            !plan.body.actions.is_empty(),
            "{name}: 계획이 비었다 — 4 번 판정의 기준을 세울 수 없다"
        );
        got.extend(plan.body.actions.iter().map(remedy_testkit::locator));
    }

    let lacking: Vec<&String> = expected.difference(&got).collect();
    assert!(
        lacking.is_empty(),
        "첫 플러그인이 채점 기준을 못 넘는다 — 빠진 Op {lacking:?}\n  \
         기준이 틀렸거나 첫 플러그인이 퇴화했다. 둘 다 고쳐야 하는 것이지 \
         목록에서 지울 일이 아니다"
    );
}
