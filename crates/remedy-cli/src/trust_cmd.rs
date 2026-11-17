//! 룰 검사 · 룰 서명 확인 · 조직 허용 목록 · 폐기 목록 · 신고 묶음(2026-11-17 에 main.rs 에서 옮겼다).

use super::*;

pub(super) fn cmd_plugin_lint(raw: &[String]) -> Result<Code, Failure> {
    if raw.is_empty() {
        return Err("검사할 plugin.yaml 을 하나 이상 지정하십시오".into());
    }

    let mut total_errors = 0usize;
    let mut total_warnings = 0usize;
    let mut unreadable = 0usize;

    for path in raw {
        outln!(
            "
{path}"
        );
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                outln!("  오류 읽을 수 없습니다: {e}");
                unreadable += 1;
                continue;
            }
        };
        // 형태가 깨졌으면 의미 검사까지 갈 수 없다. serde 의 메시지가 줄·열을
        // 알려 주므로 그대로 보인다.
        let m: PluginManifest = match serde_yaml_ng::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                outln!("  오류 스키마: {e}");
                // serde 는 꼴로 갈리는 조건식에서 무엇이 틀렸는지 말하지 않는다 — 원문으로 짚는다.
                for h in remedy_sdk::lint::schema_hints(&text) {
                    outln!("      → {h}");
                }
                outln!(
                    "      쓸 수 있는 것:
{}",
                    indent(&remedy_sdk::lint::valid_values())
                );
                total_errors += 1;
                continue;
            }
        };

        let issues = remedy_sdk::lint(&m);
        let errors = remedy_sdk::lint::blocking(&issues);
        let warnings = issues.len() - errors;
        total_errors += errors;
        total_warnings += warnings;

        if issues.is_empty() {
            outln!("  통과 — 오류 0 · 경고 0");
            continue;
        }
        for i in &issues {
            outln!("  {i}");
        }
        outln!("  오류 {errors} · 경고 {warnings}");
    }

    outln!(
        "
합계: 오류 {total_errors} · 경고 {total_warnings}{}",
        if unreadable > 0 {
            format!(" · 읽지 못한 파일 {unreadable}")
        } else {
            String::new()
        }
    );

    // **경고는 실패가 아니다.** 경고로 CI 를 막으면 사람이 경고를 끄는 법부터 배운다.
    if total_errors > 0 || unreadable > 0 {
        Ok(Code::UsageError)
    } else {
        Ok(Code::NoThreat)
    }
}

/// 배포 빌드에 박아 넣는 신뢰 앵커 — minisign 공개키 base64 한 줄.
///
/// **저장소에 파일로 두지 않고 빌드 때 주입한다.** 키가 파일이면 그 파일을 제
/// 키로 바꿔치기하는 것이 서명 우회의 첫 수가 된다. 바이너리에 박히면 바이너리를
/// 다시 만들지 않고는 바꿀 수 없다.
///
/// ```text
/// REMEDY_TRUST_ANCHOR=<base64> cargo build --release
/// ```
pub(super) const EMBEDDED_ANCHOR: Option<&str> = option_env!("REMEDY_TRUST_ANCHOR");

/// 코어 바이너리에 **컴파일되는** 최소 플러그인 버전 (설계-01 D6 · 설계-03 §6).
///
/// 오프라인에서 실제로 강제되는 층이 이것이다. 네트워크가 없어도, **시계가
/// 조작돼도** 유효하다 — 만료 시각이 아니라 버전 비교이기 때문이다.
///
/// **비어 있는 것이 지금의 사실이다.** 아직 아무 플러그인도 폐기하지 않았다.
/// 값을 채우는 것은 코어 재배포이고, 설계-01 D7 이 *"코어 재배포가 곧 폐기
/// 메커니즘의 집행"* 이라고 적은 자리가 여기다.
pub(super) const MIN_PLUGIN_VERSIONS: &[(&str, &str)] = &[
    // ("evilai-locust", "1.2.0"),
];

/// 플러그인 디렉터리의 서명을 확인한다 (설계-03 §10 G8).
///
/// **서명은 아직 명령줄의 로드 경로를 막지 않는다.** 이 명령은 "서명이 맞는가" 를
/// 사람이 물어볼 수 있게 하는 자리이고, 서명되지 않은 플러그인의 실행을 거부하는
/// 것은 릴리스 키가 서고 저장소의 플러그인들이 서명된 뒤의 일이다. 그 순서를
/// 뒤집으면 아무 플러그인도 못 돌린 채 키 발급을 기다리게 된다. 폐기 목록 · 내장
/// 최소 버전은 다르다 — [`revocation_gate`] 가 검사 · 치료 · 유지 확인 · 계획 앞에서
/// 같은 판정으로 막는다.
pub(super) fn cmd_plugin_verify(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw)?;

    let dir = arg("--dir").ok_or_else(|| {
        Failure::from(ui().lang.t(
            "--dir <플러그인 디렉터리> 옵션이 필요합니다",
            "--dir <plugin directory> is required",
        ))
    })?;
    let dir = std::path::Path::new(&dir);

    let anchor = match arg("--public-key") {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Failure::from(format!("{path} 를 읽지 못했습니다: {e}")))?;
            remedy_trust::Anchor::from_public_key_file(&text)
                .map_err(|e| Failure::from(e.to_string()))?
        }
        None => match EMBEDDED_ANCHOR {
            Some(b64) => {
                remedy_trust::Anchor::from_base64(b64).map_err(|e| Failure::from(e.to_string()))?
            }
            None => {
                return Err(Failure {
                    code: Code::UsageError,
                    message: "이 빌드에는 신뢰 앵커가 박혀 있지 않습니다. \
                              --public-key 로 공개키를 지정하거나, \
                              REMEDY_TRUST_ANCHOR 를 주고 다시 빌드하십시오"
                        .to_string(),
                })
            }
        },
    };

    let manifest_path = dir.join(remedy_trust::MANIFEST_NAME);
    let sig_path = dir.join(remedy_trust::SIGNATURE_NAME);

    // **없는 것과 틀린 것을 나눈다.** 미서명 플러그인은 "서명 파일이 없다" 로
    // 보고되어야 하고, 그것을 "검증 실패" 와 뭉뚱그리면 사람이 원인을 찾는 데
    // 시간을 쓴다.
    let manifest = std::fs::read(&manifest_path).map_err(|e| Failure {
        code: Code::GuardStop,
        message: format!(
            "{} 를 읽지 못했습니다 — 서명되지 않은 플러그인일 수 있습니다 ({e})",
            manifest_path.display()
        ),
    })?;
    let signature = std::fs::read_to_string(&sig_path).map_err(|e| Failure {
        code: Code::GuardStop,
        message: format!(
            "{} 를 읽지 못했습니다 — 서명되지 않은 플러그인일 수 있습니다 ({e})",
            sig_path.display()
        ),
    })?;

    let verified =
        remedy_trust::verify_manifest(&anchor, &manifest, &signature).map_err(|e| Failure {
            code: Code::GuardStop,
            message: e.to_string(),
        })?;

    let actual = remedy_trust::collect(dir).map_err(|e| Failure {
        code: Code::GuardStop,
        message: e.to_string(),
    })?;

    verified.check_tree(&actual).map_err(|e| Failure {
        code: Code::GuardStop,
        message: e.to_string(),
    })?;

    let c = verified.comment();
    outln!("{}", dir.display());
    outln!("  서명  {} {} ({})", c.id, c.version, c.signed_at);
    outln!("  파일  {} 개 — 매니페스트와 전부 일치", actual.len());

    // ── 폐기와 역행 금지 (설계-03 §6) ────────────────────────────
    //
    // **서명이 맞는 것과 지금 써도 되는 것은 다르다.** 폐기된 판도 서명은
    // 유효하다 — 그래서 서명 검증만으로는 킬 스위치가 서지 않는다.
    let state_dir = arg("--state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);
    let list = load_revocations(&anchor, &state_dir)?;
    let state = read_state(&state_dir)?;
    let min = remedy_trust::revocation::MinVersions::from_pairs(MIN_PLUGIN_VERSIONS)
        .map_err(|e| Failure::from(e.to_string()))?;

    remedy_trust::revocation::check_plugin(&c.id, &c.version, list.as_ref(), &min, &state)
        .map_err(|d| Failure {
            code: Code::GuardStop,
            message: d.to_string(),
        })?;

    match &list {
        Some(l) => outln!("  폐기  serial {} — 이 판을 겨누는 항목 없음", l.serial()),
        None => {
            // 목록이 없다는 사실을 **말한다.** 조용히 넘어가면 "폐기를
            // 확인했다" 로 읽힌다 (설계-03 §6 신선도 정책).
            outln!("  폐기  목록 없음 — 폐기 여부를 확인하지 못했습니다");
        }
    }
    Ok(Code::NoThreat)
}

/// 상태 디렉터리에 반입된 폐기 목록을 읽는다. 없으면 `None`.
///
/// **없는 것과 틀린 것을 나눈다.** 목록이 없는 것은 아직 반입하지 않은 것이고,
/// 서명이 맞지 않는 것은 누군가 손댄 것이다 — 뒤엣것은 오류로 나간다.
pub(super) fn load_revocations(
    anchor: &remedy_trust::Anchor,
    dir: &std::path::Path,
) -> Result<Option<remedy_trust::RevocationList>, Failure> {
    let p = dir.join(remedy_trust::revocation::LIST_FILE);
    let text = match std::fs::read_to_string(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Failure::from(format!(
                "{} 를 읽지 못했습니다: {e}",
                p.display()
            )))
        }
        Ok(t) => t,
    };
    remedy_trust::revocation::parse_signed(anchor, &text)
        .map(Some)
        .map_err(|e| Failure {
            code: Code::GuardStop,
            message: format!("{}: {e}", p.display()),
        })
}

/// 서명된 허용 목록 하나를 확인한다. **상태를 바꾸지 않는다.**
pub(super) fn cmd_allowlist_verify(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw)?;
    let path = arg("--file").ok_or_else(|| Failure::from("--file <목록> 옵션이 필요합니다"))?;
    let anchor = anchor_from(&arg)?;
    let list = read_allowlist(&anchor, &path)?;

    outln!("{path}");
    outln!("  serial  {}", list.serial());
    outln!("  발행    {}", list.issued_at());
    if list.is_empty() {
        // **빈 목록도 유효한 목록이다.** "면제한 것이 없다" 를 서명해 말하는
        // 것과, 목록이 없는 것은 다르다.
        outln!("  항목    없음 — 면제한 것이 없다고 서명해 말하는 목록입니다");
    } else {
        outln!("  항목    {} 건", list.entries().count());
        for e in list.entries() {
            outln!("    {}… — {}", &e.sha256[..16], e.reason);
        }
    }
    Ok(Code::NoThreat)
}

/// 허용 목록을 상태 디렉터리로 들인다.
///
/// **들어오는 문은 이것 하나다** (설계-01 D9 — 치료 경로에 네트워크가 없다).
/// 목록을 어떻게 받든 파일로 받아 여기서 확인한다.
pub(super) fn cmd_allowlist_import(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw)?;
    let path = arg("--file").ok_or_else(|| Failure::from("--file <목록> 옵션이 필요합니다"))?;
    let anchor = anchor_from(&arg)?;
    let dir = arg("--state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);

    let list = read_allowlist(&anchor, &path)?;

    let mut state = read_state(&dir)?;
    // **회수된 면제가 옛 목록으로 되살아나면 안 된다.**
    remedy_trust::allowlist::check_allowlist(&list, &state).map_err(|d| Failure {
        code: Code::GuardStop,
        message: d.to_string(),
    })?;

    std::fs::create_dir_all(&dir)
        .map_err(|e| Failure::from(format!("{} 를 만들지 못했습니다: {e}", dir.display())))?;

    let dest = dir.join(remedy_trust::allowlist::LIST_FILE);
    std::fs::copy(&path, &dest)
        .map_err(|e| Failure::from(format!("{} 로 옮기지 못했습니다: {e}", dest.display())))?;

    state.observe_allowlist(list.serial());
    write_state(&dir, &state)?;

    outln!("반입했습니다: {}", dest.display());
    outln!("  serial  {} (발행 {})", list.serial(), list.issued_at());
    outln!("  항목    {} 건", list.entries().count());
    // **이 줄의 낱말은 아무도 읽지 않는다** (2026-10-28 전수 조사). 전에는
    // 주석이 *"5층 은 P10 검증 스크립트가 읽는 낱말"* 이라고 적었는데 잘못
    // 가리킨 것이었다 — `Invoke-P10Verify.ps1` 이 `5층` 을 읽는 자리는 **계획의
    // 미룸 사유**(`remedy-plan/src/derive.rs`)이고 이 안내가 아니다. 그래서
    // 화면에서 내부 층 번호를 빼도 그 판정은 흔들리지 않는다.
    outln!("\n  주의: 여기 있는 해시는 판정이 서도 삭제하지 않습니다 (조직 허용 목록).");
    outln!("     판정과 사유는 그대로 보고됩니다 — 조용히 사라지지 않습니다.");
    Ok(Code::NoThreat)
}

pub(super) fn read_allowlist(
    anchor: &remedy_trust::Anchor,
    path: &str,
) -> Result<remedy_trust::allowlist::Allowlist, Failure> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Failure::from(format!("{path} 를 읽지 못했습니다: {e}")))?;
    remedy_trust::allowlist::parse_signed(anchor, &text).map_err(|e| Failure {
        code: Code::GuardStop,
        message: e.to_string(),
    })
}

/// 상태 디렉터리에 반입된 조직 허용 목록을 계획기가 쓸 모양으로 읽는다
/// (설계-03 §3 5층).
///
/// # 없으면 빈 지도다 — 그리고 그것이 안전한 방향이다
///
/// 면제가 없으면 평소대로 치료할 뿐이다. 반대(목록을 못 읽었는데 면제된 것으로
/// 치는 것)라야 위험하다. 그래서 **폐기 목록과 실패 방향이 반대다** — 그쪽은
/// 없으면 경고하지만, 이쪽은 없는 것이 기본 상태다.
///
/// # 서명이 틀리면 멈춘다
///
/// 없는 것과 **바꿔치기된 것**은 다르다. 뒤엣것을 조용히 빈 지도로 만들면
/// 공격자가 파일 하나를 망가뜨려 조직의 면제를 통째로 없앨 수 있고, 그러면
/// 정상 파일이 지워진다.
///
/// # 역행 금지
///
/// 옛 목록을 되밀어 **회수된 면제를 되살릴 수 없다.** 반입 때 한 번 보고
/// (`cmd_allowlist_import`), 여기서 읽을 때 한 번 더 본다 — 파일을 직접 바꿔
/// 넣는 길이 있기 때문이다.
pub(super) fn load_allowed(
    arg: impl Fn(&str) -> Option<String>,
    dir: &std::path::Path,
) -> Result<remedy_core::Allowed, Failure> {
    let p = dir.join(remedy_trust::allowlist::LIST_FILE);
    let text = match std::fs::read_to_string(&p) {
        // **목록이 없으면 앵커도 필요 없다.** 앵커를 먼저 얻으면 신뢰 앵커가
        // 박히지 않은 개발 빌드에서 `scan` 이 통째로 멈춘다 — 허용 목록을 쓰지
        // 않는 실행까지. 실측으로 걸렸다 (2026-08-29).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(remedy_core::Allowed::new())
        }
        Err(e) => {
            return Err(Failure::from(format!(
                "{} 를 읽지 못했습니다: {e}",
                p.display()
            )))
        }
        Ok(t) => t,
    };
    let anchor = anchor_from(&arg)?;
    let list = remedy_trust::allowlist::parse_signed(&anchor, &text).map_err(|e| Failure {
        code: Code::GuardStop,
        message: format!("{}: {e}", p.display()),
    })?;
    let state = read_state(dir)?;
    remedy_trust::allowlist::check_allowlist(&list, &state).map_err(|d| Failure {
        code: Code::GuardStop,
        message: format!("{}: {d}", p.display()),
    })?;
    Ok(remedy_trust::allowlist::flatten(&list))
}

/// 이 룰로 검사 · 치료 · 유지 확인 · 계획을 해도 되는가 — `plugin verify` 와 같은 판정(설계-03 §6 · 반입한
/// 폐기 목록과 코어 내장 최소 버전)을 **룰을 읽기 전에** 한다. 막으면 종료 코드 5 다. 신원은 그 룰의
/// `plugin.yaml` 의 id · version 이다 — 명령줄은 룰의 서명을 보지 않는 모델이고(`state_dir` 의 주석), 메뉴로
/// 온 룰은 고르는 화면에서 이미 서명과 파일 대조를 지났다(`discover::usable`).
///
/// # 목록이 없으면 아무것도 읽지 않는다
///
/// 앵커도 상태 파일도 읽지 않고 버전도 해석하지 않는다 — [`load_allowed`] 와 같은 규칙이다. 지금은 발행한
/// 목록이 없고 내장 표도 비어 있어, 오늘의 실행은 모두 이 갈래로 지나간다.
///
/// # 겨눈 룰만 판정한다
///
/// 목록이 있어도 그 목록이 이 룰의 id 를 겨누지 않으면 판정하지 않는다 — 판정하면 `x.y.z` 가 아닌 버전을 쓰는
/// 다른 룰까지 5 로 멈춘다. 목록 자체(서명 · 옛 목록 되밀기)는 그래도 확인한다: 바꿔치기된 목록을 조용히
/// 넘기지 않는다([`load_allowed`] 가 읽을 때 한 번 더 보는 것과 같다). 그래서 목록이 서명 확인을 통과하지
/// 못하면 그 상태 폴더를 쓰는 실행은 룰과 상관없이 멈춘다 — 의도한 fail-closed 다.
///
/// # 메뉴는 두 자리를 본다
///
/// 메뉴는 실행 파일 옆 `state` 를 상태 폴더로 넘긴다. 문서가 안내하는 반입(`revocation import`)은 기본 자리에
/// 들어가므로, 그 자리일 때는 [`menu_state_dirs`] 의 두 자리를 다 읽고 어느 목록이든 겨누면 막는다. 이 함수를
/// 부르는 검사 · 치료 · 유지 확인은 관리자 문을 지난 뒤라 기계 공용 자리도 읽힌다. 관리자 문이 없는 `plan` 은
/// [`revocation_gate_at`] 으로 그 명령의 상태 폴더 하나만 본다. 명령줄은 어느 쪽이든 그 명령의 상태 폴더 한
/// 자리다.
pub(super) fn revocation_gate(a: &Args, m: &PluginManifest) -> Result<(), Failure> {
    revocation_gate_at(a, m, &trust_dirs(&state_dir(a)))
}

/// [`revocation_gate`] 의 판정을 준 자리들에서 한다.
pub(super) fn revocation_gate_at(
    a: &Args,
    m: &PluginManifest,
    dirs: &[std::path::PathBuf],
) -> Result<(), Failure> {
    let min = remedy_trust::revocation::MinVersions::from_pairs(MIN_PLUGIN_VERSIONS)
        .map_err(|e| Failure::from(e.to_string()))?;
    let arg = |k: &str| a.get(k.trim_start_matches("--")).map(str::to_string);
    let deny = |d: remedy_trust::revocation::Denial| Failure {
        code: Code::GuardStop,
        message: d.to_string(),
    };
    for dir in dirs {
        let p = dir.join(remedy_trust::revocation::LIST_FILE);
        match std::fs::metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(Failure::from(format!(
                    "{} 를 읽지 못했습니다: {e}",
                    p.display()
                )))
            }
            Ok(_) => {}
        }
        let Some(list) = load_revocations(&anchor_from(arg)?, dir)? else {
            continue;
        };
        let state = read_state(dir)?;
        remedy_trust::revocation::check_revocations(&list, &state).map_err(|d| Failure {
            code: Code::GuardStop,
            message: format!("{}: {d}", p.display()),
        })?;
        if list.entries().any(|e| e.plugin == m.id) {
            remedy_trust::revocation::check_plugin(&m.id, &m.version, Some(&list), &min, &state)
                .map_err(deny)?;
        }
    }
    if min.get(&m.id).is_some() {
        let none = remedy_trust::TrustState::default();
        remedy_trust::revocation::check_plugin(&m.id, &m.version, None, &min, &none)
            .map_err(deny)?;
    }
    Ok(())
}

/// 폐기 목록을 읽을 자리 — 메뉴의 상태 폴더(실행 파일 옆 `state`)면 메뉴가 회차를 찾는 두 자리, 아니면 그
/// 폴더 하나.
pub(super) fn trust_dirs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    if dir == beside_exe("state") {
        menu_state_dirs()
    } else {
        vec![dir.to_path_buf()]
    }
}

/// 인자에서 앵커를 얻는다. `plugin verify` 와 `revocation` 이 같은 규칙을 쓴다.
pub(super) fn anchor_from(
    arg: impl Fn(&str) -> Option<String>,
) -> Result<remedy_trust::Anchor, Failure> {
    match arg("--public-key") {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Failure::from(format!("{path} 를 읽지 못했습니다: {e}")))?;
            remedy_trust::Anchor::from_public_key_file(&text)
                .map_err(|e| Failure::from(e.to_string()))
        }
        None => match EMBEDDED_ANCHOR {
            Some(b64) => {
                remedy_trust::Anchor::from_base64(b64).map_err(|e| Failure::from(e.to_string()))
            }
            None => Err(Failure {
                code: Code::UsageError,
                message: "이 빌드에는 신뢰 앵커가 박혀 있지 않습니다. \
                          --public-key 로 공개키를 지정하거나, \
                          REMEDY_TRUST_ANCHOR 를 주고 다시 빌드하십시오"
                    .to_string(),
            }),
        },
    }
}

/// 이름(`--dir` 꼴)으로 값을 꺼내는 함수 — [`parse_args`] 의 규칙을 그대로 따른다. 전에는 자리만 찾고 나머지를
/// 버려, `revocation import --file l --dryrun` 처럼 모르는 옵션 · 맨 낱말이 섞여도 그대로 실행했다(2-5).
pub(super) fn simple_arg(raw: &[String]) -> Result<impl Fn(&str) -> Option<String>, Failure> {
    let a = parse_args(raw)?;
    Ok(move |name: &str| a.get(name.trim_start_matches("--")).map(str::to_string))
}

/// 폐기 목록을 읽어 보인다. **상태를 건드리지 않는다** — 반입 전에 무엇이 담겨
/// 있는지 사람이 확인하는 자리다.
pub(super) fn cmd_revocation_verify(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw)?;
    let path = arg("--file").ok_or_else(|| Failure::from("--file <목록> 옵션이 필요합니다"))?;
    let anchor = anchor_from(&arg)?;

    let list = read_list(&anchor, &path)?;

    outln!("{path}");
    outln!("  serial  {}", list.serial());
    outln!("  발행    {}", list.issued_at());
    if list.is_empty() {
        // **빈 목록도 유효한 목록이다.** "아직 아무것도 폐기하지 않았다" 를
        // 서명해 말하는 것과, 목록이 없는 것은 다르다.
        outln!("  항목    없음 — 폐기된 것이 없다고 서명해 말하는 목록입니다");
    } else {
        outln!("  항목    {} 건", list.entries().count());
        for e in list.entries() {
            let range = match (&e.below, &e.exact) {
                (Some(b), _) => format!("{b} 미만"),
                (_, Some(x)) => x.clone(),
                _ => "(형식 오류)".into(),
            };
            outln!("    {} {} — {}", e.plugin, range, e.reason);
        }
    }
    Ok(Code::NoThreat)
}

/// 목록을 상태 디렉터리로 반입한다.
///
/// **반입 경로가 신뢰를 낮추지 않는다** (설계-03 §6). 파일 공유나 이동식 매체로
/// 온 목록도 서명 검증과 역행 금지를 똑같이 거친다.
pub(super) fn cmd_revocation_import(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw)?;
    let path = arg("--file").ok_or_else(|| Failure::from("--file <목록> 옵션이 필요합니다"))?;
    let anchor = anchor_from(&arg)?;
    let dir = arg("--state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);

    let list = read_list(&anchor, &path)?;

    let mut state = read_state(&dir)?;
    // 역행 금지는 목록에도 걸린다 — 옛 목록으로 되돌리면 폐기가 풀린다.
    remedy_trust::revocation::check_revocations(&list, &state).map_err(|d| Failure {
        code: Code::GuardStop,
        message: d.to_string(),
    })?;

    std::fs::create_dir_all(&dir)
        .map_err(|e| Failure::from(format!("{} 를 만들지 못했습니다: {e}", dir.display())))?;

    let dest = dir.join(remedy_trust::revocation::LIST_FILE);
    std::fs::copy(&path, &dest)
        .map_err(|e| Failure::from(format!("{} 로 옮기지 못했습니다: {e}", dest.display())))?;

    state.observe_revocation(list.serial());
    write_state(&dir, &state)?;

    outln!("반입했습니다: {}", dest.display());
    outln!("  serial  {} (발행 {})", list.serial(), list.issued_at());
    outln!("  항목    {} 건", list.entries().count());
    Ok(Code::NoThreat)
}

pub(super) fn read_list(
    anchor: &remedy_trust::Anchor,
    path: &str,
) -> Result<remedy_trust::RevocationList, Failure> {
    // **없는 것과 틀린 것을 나눈다.** 목록이 없는 것은 사용법 문제일 수 있지만,
    // 서명이 맞지 않는 것은 가드가 막은 것이다.
    let text = std::fs::read_to_string(path)
        .map_err(|e| Failure::from(format!("{path} 를 읽지 못했습니다: {e}")))?;
    remedy_trust::revocation::parse_signed(anchor, &text).map_err(|e| Failure {
        code: Code::GuardStop,
        message: e.to_string(),
    })
}

pub(super) fn read_state(dir: &std::path::Path) -> Result<remedy_trust::TrustState, Failure> {
    let p = dir.join(remedy_trust::revocation::STATE_FILE);
    match std::fs::read_to_string(&p) {
        // 없으면 처음 보는 기계다. 빈 상태는 "아무것도 관측하지 않았다" 이고,
        // 그 위에서도 코어 내장 하한은 그대로 작동한다.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(e) => Err(Failure::from(format!(
            "{} 를 읽지 못했습니다: {e}",
            p.display()
        ))),
        Ok(text) => serde_json::from_str(&text).map_err(|e| Failure {
            // 상태를 읽지 못하면 역행 금지를 판정할 수 없다. 빈 상태로 넘어가면
            // 그것이 곧 되돌리기 통로가 된다.
            code: Code::GuardStop,
            message: format!(
                "{} 를 읽지 못했습니다: {e} — 역행 금지를 판정할 수 없으므로 멈춥니다. \
                 상태가 손상됐다면 파일을 지우고 목록을 다시 반입하십시오",
                p.display()
            ),
        }),
    }
}

/// 신고 첨부물을 만든다 (설계-04 §6).
///
/// **오탐 대응 경로의 두 번째 칸**이다 — 복구(`restore`) 다음, 재현·판정 앞.
/// 여기서 "무엇을 보낼지" 가 막히면 뒤가 전부 늦어진다.
pub(super) fn cmd_support_bundle(raw: &[String]) -> Result<Code, Failure> {
    let arg = simple_arg(raw)?;
    let run_id = arg("--run").ok_or_else(|| {
        Failure::from(
            "--run <run_id> 옵션이 필요합니다. 실행 id 는 apply 출력과 저널 이름에 있습니다",
        )
    })?;
    let state_dir = arg("--state-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(remedy_core::restore::default_state_dir);
    let out = arg("--out")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let b = remedy_core::support::build(&state_dir, &run_id, &out).map_err(Failure::from)?;
    let lang = ui().lang;
    let d = remedy_sdk::i18n::deco();
    outln!(
        "{} : {}",
        // **`꾸러미` 가 아니라 `지원 번들` 이다** (2026-10-28). 신고에 붙이는
        // 진단 모음을 업계가 그렇게 부른다.
        //
        // **다른 뜻의 `꾸러미` 는 건드리지 않았다** — `guided.rs` 의 것은 실행
        // 파일 옆의 **플러그인 꾸러미**이고(영문도 `bundles`), `lint.rs` 의 것은
        // **채점 꾸러미**다. 한 낱말이 셋을 가리키고 있었고, 싸잡아 바꾸면 두
        // 자리가 틀린 말이 된다.
        lang.t("지원 번들 폴더", "Support bundle folder"),
        b.dir.display()
    );
    outln!("\n{}", lang.t("담긴 것", "Included"));
    for i in &b.included {
        outln!(
            "  {:<18} {:>9} {}  {}",
            i.name,
            i.bytes,
            lang.t("바이트", "bytes"),
            i.what
        );
    }
    if !b.excluded.is_empty() {
        outln!(
            "\n{}",
            lang.t("일부러 담지 않은 것", "Deliberately left out")
        );
        for e in &b.excluded {
            outln!("  {}\n    {}", e.name, e.why);
        }
    }
    if let Some(h) = &b.submit_hint {
        outln!(
            "\n{}",
            lang.t(
                "플러그인이 남긴 것 (손으로 올릴 때 보십시오)",
                "Left by the plugin (for manual upload)"
            )
        );
        if !h.samples.is_empty() {
            outln!(
                "  {}: {}",
                lang.t("함께 올리면 유용한 증거", "Evidence worth attaching"),
                h.samples.join(d.dot())
            );
        }
        if let Some(c) = h.confidentiality_min {
            outln!(
                "  {}: {c}. {}",
                lang.t("기밀 등급 하한", "Minimum confidentiality"),
                lang.t(
                    "이 등급 아래로 다루지 마십시오",
                    "do not handle below this level"
                )
            );
        }
    }
    outln!(
        "\n{}",
        lang.t(
            "무엇이 담겼고 무엇이 빠졌는지는 README.txt 에 그대로 있습니다.",
            "README.txt lists exactly what is included and what is not."
        )
    );
    outln!(
        "{}",
        lang.t(
            "보내기 전에 열어 보십시오. 경로, 호스트명, 사용자명이 가려지지 않습니다.",
            "Open it before sending. Paths, host name and user name are not redacted."
        )
    );
    Ok(Code::NoThreat)
}

pub(super) fn write_state(
    dir: &std::path::Path,
    state: &remedy_trust::TrustState,
) -> Result<(), Failure> {
    let p = dir.join(remedy_trust::revocation::STATE_FILE);
    let text = serde_json::to_string_pretty(state)
        .map_err(|e| Failure::from(format!("상태를 만들지 못했습니다: {e}")))?;
    std::fs::write(&p, text)
        .map_err(|e| Failure::from(format!("{} 를 쓰지 못했습니다: {e}", p.display())))
}
