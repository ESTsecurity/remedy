//! 네트워크 점검 — **본체는 통신하지 않는다.** 그 일은 동반 프로그램 `remedy-net` 이 한다.
//!
//! 룰이 `network: <점검>` 을 선언했으면([`remedy_sdk::manifest::PluginManifest::network`]) 본체는 그 룰을
//! 스스로 돌리지 않고 **실행 파일 옆의 `remedy-net` 을 띄워 맡긴다.** 사용자는 `remedy` 하나만 실행한다 —
//! 어느 프로그램이 네트워크를 쓰는지는 띄우기 전에 화면이 말한다(결정 2026-11-10).
//!
//! # 띄우는 조건 (설계-04 §1 *동반 모듈*)
//!
//! 1. **닫힌 값** — 룰이 고르는 것은 점검의 종류 하나다. 띄울 프로그램의 이름 · 자리 · 인자의 꼴은 룰이
//!    아니라 이 파일에 적혀 있다.
//! 2. **서명이 맞는 것만** — 룰과 같은 사슬(`remedy_trust`)로 폴더를 통째로 확인하고, 서명 주석의 이름과
//!    버전이 이 본체와 같아야 한다. 확인하지 못하면 띄우지 않는다.
//! 3. **알리고 띄운다** — 네트워크를 쓴다는 것과 누가 쓰는지를 먼저 적는다. 약관 동의는 그 프로그램이 받는다.
//! 4. **종료 코드만 받는다** — 판정은 그 프로그램의 화면과 결과 파일에 있고, 본체는 그것으로 아무것도
//!    바꾸지 않는다. 두 프로그램의 종료 코드 표는 같다(`docs/operator.md` §3).
//! 5. **없으면 못 한다** — `remedy-net` 폴더를 지운 자리에서 이 점검은 서지 않고, 본체에는 통신할 길이 없다
//!    (배포본의 임포트 검사 `cargo xtask static` 이 그것을 본다).

use crate::{ui, Code, Failure};
use remedy_sdk::i18n::Lang;
use remedy_sdk::manifest::NetworkCheck;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// 실행 파일 옆의 폴더 이름이자 서명 주석의 이름.
pub(crate) const NAME: &str = "remedy-net";

/// 그 폴더 안의 실행 파일.
fn program() -> &'static str {
    if cfg!(windows) {
        "remedy-net.exe"
    } else {
        "remedy-net"
    }
}

/// 동반 프로그램을 띄우지 못하는 까닭.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// 폴더가 없다 — 받은 파일을 덜 풀었거나, 네트워크를 쓰지 않으려고 지웠다.
    Absent,
    /// 이 빌드에는 서명을 확인할 공개키가 없다(배포본이 아니다).
    NoAnchor,
    NotSigned,
    Tampered(String),
    /// 서명은 맞지만 동반 프로그램에 한 서명이 아니다(서명 주석의 이름이 다르다).
    NotCompanion(String),
    /// 다른 버전의 동반 프로그램이다 — 종료 코드 표 · 인자의 꼴이 같은 릴리스끼리만 맞는다.
    OtherVersion(String),
    /// 서명된 폴더에 실행 파일이 없다.
    NoProgram,
}

impl Refusal {
    fn message(&self, lang: Lang) -> String {
        let core = env!("CARGO_PKG_VERSION");
        match self {
            Refusal::Absent => lang
                .t(
                    "이 점검은 네트워크를 쓰는 동반 프로그램(remedy-net)이 맡는데, 이 폴더에 remedy-net 이 없습니다.\n  \
                     받은 파일을 통째로 다시 풀어 실행하십시오. 네트워크를 쓰지 않으려고 지운 것이라면 이 점검은 할 수 없습니다.",
                    "This check is done by the companion program (remedy-net), which uses the network, but remedy-net is not in this folder.\n  \
                     Extract the whole download again and run it. If it was removed to keep the network unused, this check cannot run.",
                )
                .to_string(),
            Refusal::NoAnchor => lang
                .t(
                    "이 프로그램은 동반 프로그램(remedy-net)의 서명을 확인할 수 없어 실행하지 않았습니다 (배포본이 아닙니다).",
                    "This build cannot verify the companion program (remedy-net), so it was not started (not an official release).",
                )
                .to_string(),
            Refusal::NotSigned => lang
                .t(
                    "remedy-net 에 서명이 없어 실행하지 않았습니다 — 배포처에서 받은 것이 맞는지 확인하십시오.",
                    "remedy-net is not signed, so it was not started — check that it came from the vendor.",
                )
                .to_string(),
            Refusal::Tampered(_) | Refusal::NoProgram => lang
                .t(
                    "remedy-net 의 내용이 서명한 것과 달라 실행하지 않았습니다 — 배포처에서 다시 받으십시오.",
                    "remedy-net differs from what was signed, so it was not started — download it again from the vendor.",
                )
                .to_string(),
            Refusal::NotCompanion(_) => lang
                .t(
                    "remedy-net 폴더의 서명이 동반 프로그램의 것이 아니어서 실행하지 않았습니다 — 배포처에서 다시 받으십시오.",
                    "The signature in the remedy-net folder is not the companion program's, so it was not started — download it again from the vendor.",
                )
                .to_string(),
            Refusal::OtherVersion(v) => lang.pick(
                format!(
                    "remedy-net 의 버전({v})이 이 프로그램({core})과 달라 실행하지 않았습니다 — 같은 릴리스의 파일을 함께 쓰십시오."
                ),
                format!(
                    "remedy-net is version {v} but this program is {core}, so it was not started — use files from the same release together."
                ),
            ),
        }
    }
}

/// 서명과 정체를 확인한 동반 프로그램의 경로. `beside` 는 본체 실행 파일이 있는 폴더다.
///
/// 확인하는 것은 넷이다 — 폴더의 서명이 이 빌드의 공개키로 맞는가 · 폴더의 파일이 서명한 그대로인가(더해진
/// 것도 빠진 것도 없다) · 서명 주석의 이름이 `remedy-net` 인가(서명된 룰 폴더를 이 자리에 옮겨 놓은 것이
/// 아니다) · 버전이 이 본체와 같은가.
pub(crate) fn locate(beside: &Path, anchor_b64: Option<&str>) -> Result<PathBuf, Refusal> {
    let dir = beside.join(NAME);
    if !dir.is_dir() {
        return Err(Refusal::Absent);
    }
    let Some(b64) = anchor_b64 else {
        return Err(Refusal::NoAnchor);
    };
    let anchor =
        remedy_trust::Anchor::from_base64(b64).map_err(|e| Refusal::Tampered(e.to_string()))?;
    let manifest =
        std::fs::read(dir.join(remedy_trust::MANIFEST_NAME)).map_err(|_| Refusal::NotSigned)?;
    let signature = std::fs::read_to_string(dir.join(remedy_trust::SIGNATURE_NAME))
        .map_err(|_| Refusal::NotSigned)?;
    let verified = remedy_trust::verify_manifest(&anchor, &manifest, &signature)
        .map_err(|e| Refusal::Tampered(e.to_string()))?;
    let actual = remedy_trust::collect(&dir).map_err(|e| Refusal::Tampered(e.to_string()))?;
    verified
        .check_tree(&actual)
        .map_err(|e| Refusal::Tampered(e.to_string()))?;
    let signed = verified.comment();
    if signed.id != NAME {
        return Err(Refusal::NotCompanion(signed.id.clone()));
    }
    if signed.version != env!("CARGO_PKG_VERSION") {
        return Err(Refusal::OtherVersion(signed.version.clone()));
    }
    if !actual.contains_key(program()) {
        return Err(Refusal::NoProgram);
    }
    Ok(dir.join(program()))
}

/// 동반 프로그램이 이 폴더에 있는가 — 메뉴가 줄을 켤지 정할 때 본다. 서명은 띄울 때 확인한다.
pub(crate) fn present() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(NAME).is_dir()))
        .unwrap_or(false)
}

/// 무엇을 점검할지 누가 정하는가.
pub(crate) enum Targets<'a> {
    /// 사람이 앞에 있다(메뉴) — 동반 프로그램이 주소를 묻는다.
    Ask,
    /// 명령줄이 준 것을 그대로 넘긴다. 주소의 꼴은 동반 프로그램이 본다 — 본체는 풀이하지 않는다.
    Given {
        urls: &'a [String],
        consent: Option<&'a str>,
        cacert: Option<&'a str>,
    },
}

/// 네트워크 점검 하나를 동반 프로그램에 맡긴다. `out_dir` 은 그 프로그램이 결과 파일을 쓸 폴더다.
pub(crate) fn check(
    kind: NetworkCheck,
    out_dir: &Path,
    targets: Targets<'_>,
    embedded_anchor: Option<&str>,
) -> Result<Code, Failure> {
    let lang = ui().lang;
    let beside = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
        .ok_or_else(|| Failure {
            code: Code::InternalError,
            message: lang
                .t(
                    "이 프로그램이 있는 폴더를 알아내지 못했습니다.",
                    "could not determine the folder this program is in.",
                )
                .to_string(),
        })?;
    let anchor = embedded_anchor.map(str::to_string).or_else(dev_anchor);
    let program = locate(&beside, anchor.as_deref()).map_err(|why| Failure {
        // 명령은 옳고 환경이 모자란다 — 가드 중단이다(점검한 적이 없으니 0 도 6 도 아니다).
        code: Code::GuardStop,
        message: why.message(lang),
    })?;

    // **메뉴에서는 결과를 그 폴더 안의 `remedy-net/` 에 둔다.** 본체가 쓰는 결과 폴더(`out/<시각>/`)와
    // 통신하는 프로그램이 쓰는 자리를 나눈다 — 아래에서 사용자에게 넘기는 것이 이 한 칸뿐이게 하려는
    // 것이다. 메뉴는 `out/` 과 그 한 겹 아래에서 수집 · 판정 · 계획 파일을 골라 root 로 다시 읽으므로
    // (`guided::candidate_files`), 그 겹을 넘기면 root 가 읽을 파일을 다른 사용자가 놓을 수 있게 된다.
    // 명령줄은 준 폴더를 그대로 쓴다 — 그 자리는 부른 사람이 골랐다.
    let asked = matches!(targets, Targets::Ask);
    let out_dir = &if asked {
        out_dir.join(NAME)
    } else {
        out_dir.to_path_buf()
    };
    std::fs::create_dir_all(out_dir)
        .map_err(|e| Failure::from(format!("{}: {e}", out_dir.display())))?;
    // 사람이 앞에 있을 때만 권한을 내린다 — 그때의 결과 폴더는 본체가 지은 자리라 넘겨줄 수 있다.
    let invoker = if asked { invoker() } else { None };
    let lower = invoker.filter(|who| hand_over(out_dir, &program, *who));

    announce(lang, lower, invoker.is_some());

    let build = |as_user: Option<(u32, u32)>| {
        let mut cmd = Command::new(&program);
        cmd.arg("--lang").arg(lang.id());
        if remedy_sdk::i18n::deco().ascii {
            cmd.arg("--ascii");
        }
        cmd.arg(kind.id());
        match &targets {
            Targets::Ask => {
                cmd.arg("--ask");
            }
            Targets::Given {
                urls,
                consent,
                cacert,
            } => {
                for u in *urls {
                    cmd.arg("--url").arg(u);
                }
                if let Some(c) = consent {
                    cmd.arg("--consent").arg(c);
                }
                if let Some(f) = cacert {
                    cmd.arg("--cacert").arg(f);
                }
            }
        }
        cmd.arg("--out-dir").arg(out_dir);
        as_user_of(&mut cmd, as_user);
        cmd
    };

    crate::term::companion(true);
    let status = match build(lower).status() {
        // 미리 본 권한 칸은 통과했는데 실행이 거부됐다(ACL · LSM 처럼 `reachable` 이 못 보는 것이 막는다) —
        // 넘긴 폴더를 되돌리고, 내리지 못한 채로 띄운다고 말한다.
        Err(e) if lower.is_some() && e.kind() == std::io::ErrorKind::PermissionDenied => {
            take_back(out_dir);
            outln!("{}", not_lowered(lang));
            build(None).status()
        }
        other => other,
    };
    crate::term::companion(false);
    let status = status.map_err(|e| Failure {
        code: Code::InternalError,
        message: lang.pick(
            format!("remedy-net 을 실행하지 못했습니다: {e}"),
            format!("could not start remedy-net: {e}"),
        ),
    })?;
    code_of(status, lang)
}

/// 띄우기 전에 알린다 — 네트워크를 쓴다는 것 · 누가 쓰는지 · (리눅스) 어느 권한으로 도는지.
///
/// `lower` 는 내려 띄울 사용자, `had_invoker` 는 sudo 를 건 사용자가 있었는가다. 있었는데 내리지 못하면
/// 그렇다고 말한다 — 말하지 않으면 root 로 도는 것을 받는 사람이 알 길이 없다.
fn announce(lang: Lang, lower: Option<(u32, u32)>, had_invoker: bool) {
    outln!();
    outln!(
        "{}",
        lang.t(
            "이 점검은 네트워크를 씁니다 — 적어 주시는 주소로 요청을 보냅니다.",
            "This check uses the network — it sends requests to the addresses you give.",
        )
    );
    outln!(
        "{}",
        lang.t(
            "이 프로그램(remedy)은 통신하지 않습니다. 서명을 확인한 동반 프로그램 remedy-net 을 실행해 맡깁니다.",
            "This program (remedy) does not communicate. It starts the companion program remedy-net, whose signature it has verified.",
        )
    );
    match lower {
        Some((uid, _)) => outln!(
            "{}",
            lang.pick(
                format!("remedy-net 은 root 가 아니라 sudo 를 건 사용자(uid {uid})의 권한으로 실행합니다."),
                format!("remedy-net runs as the user who invoked sudo (uid {uid}), not as root."),
            )
        ),
        None if had_invoker => outln!("{}", not_lowered(lang)),
        None => {}
    }
    outln!();
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
}

/// sudo 를 건 사용자가 있는데 그 권한으로 내리지 못했을 때의 한 줄.
fn not_lowered(lang: Lang) -> &'static str {
    lang.t(
        "sudo 를 건 사용자가 이 폴더에 닿지 못해 권한을 내리지 못했습니다 — remedy-net 을 root 로 실행합니다.",
        "The user who invoked sudo cannot reach this folder, so privileges were not lowered — remedy-net runs as root.",
    )
}

/// 동반 프로그램의 종료 코드를 본체의 것으로 — 표가 같으므로 그대로 옮긴다(결정 6).
fn code_of(status: ExitStatus, lang: Lang) -> Result<Code, Failure> {
    match status.code() {
        Some(0) => Ok(Code::NoThreat),
        Some(2) => Ok(Code::FoundNotRemediated),
        Some(4) => Ok(Code::UsageError),
        Some(6) => Ok(Code::IncompleteObservation),
        Some(7) => Ok(Code::InternalError),
        other => Err(Failure {
            code: Code::InternalError,
            message: match other {
                Some(n) => lang.pick(
                    format!("remedy-net 이 약속에 없는 종료 코드({n})로 끝났습니다 — 점검 결과를 믿을 수 없습니다."),
                    format!("remedy-net ended with an exit code outside the contract ({n}) — the check result cannot be trusted."),
                ),
                None => lang
                    .t(
                        "remedy-net 이 신호로 끝났습니다 — 점검을 마치지 못했습니다.",
                        "remedy-net was ended by a signal — the check did not finish.",
                    )
                    .to_string(),
            },
        }),
    }
}

/// sudo 로 올라온 root 면 **sudo 를 건 사용자** — 네트워크에서 온 바이트를 읽는 프로그램을 root 로 돌리지 않는다.
/// 바로 root 로 들어온 세션(`SUDO_UID` 없음)과 Windows 에는 내려갈 사용자가 없다.
#[cfg(unix)]
fn invoker() -> Option<(u32, u32)> {
    if remedy_core::elevated() != Some(true) {
        return None;
    }
    let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid: u32 = std::env::var("SUDO_GID").ok()?.parse().ok()?;
    (uid != 0).then_some((uid, gid))
}

#[cfg(not(unix))]
fn invoker() -> Option<(u32, u32)> {
    None
}

/// 결과 폴더를 그 사용자에게 넘긴다 — 본체(root)가 지은 폴더에 그 사용자가 결과 파일을 쓸 수 있게.
///
/// 넘긴 뒤 **그 사용자가 정말 거기 닿는지**(결과 폴더에 쓰기 · 실행 파일의 실행)를 미리 본다. 닿지 못하면
/// 되돌리고 권한을 내리지 않는다 — 점검을 마치고 결과를 못 쓰는 것이 더 나쁘다. root 의 umask 가 077 이면
/// 본체가 지은 `out/` 이 0700 이라 이 길로 온다(꾸러미를 root 의 홈에 푼 때도 같다).
#[cfg(unix)]
fn hand_over(out_dir: &Path, program: &Path, who: (u32, u32)) -> bool {
    if std::os::unix::fs::chown(out_dir, Some(who.0), Some(who.1)).is_err() {
        return false;
    }
    let ok = reachable(out_dir, who, 0o3) && reachable(program, who, 0o1);
    if !ok {
        take_back(out_dir);
    }
    ok
}

#[cfg(not(unix))]
fn hand_over(_out_dir: &Path, _program: &Path, _who: (u32, u32)) -> bool {
    false
}

/// 넘겼던 결과 폴더를 root 에게 되돌린다 — 내리지 못하고 root 로 띄울 때, root 가 쓰는 자리를 다른
/// 사용자의 것으로 남기지 않는다.
#[cfg(unix)]
fn take_back(out_dir: &Path) {
    let _ = std::os::unix::fs::chown(out_dir, Some(0), Some(0));
}

#[cfg(not(unix))]
fn take_back(_out_dir: &Path) {}

/// 그 사용자가 `path` 에 닿을 수 있는가 — 조상 폴더마다 통과(x)를, 마지막 칸에 `need` 를 본다.
///
/// 내려 띄울 때 표준 라이브러리가 덧붙은 그룹을 비우므로(`setgroups(0)`) 커널이 보는 것은 소유자 · 그룹 ·
/// 그 밖의 세 칸 가운데 하나다 — 여기서도 같은 차례로 한 칸을 골라 본다(소유자면 소유자 칸만 본다).
/// ACL · LSM 이 더 막는 자리는 보지 못한다 — 그때는 실행이 거부되고 `check` 가 그것을 받는다.
#[cfg(unix)]
fn reachable(path: &Path, who: (u32, u32), need: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(full) = path.canonicalize() else {
        return false;
    };
    let allowed = |p: &Path, bits: u32| {
        std::fs::metadata(p)
            .is_ok_and(|m| class_bits(m.mode(), (m.uid(), m.gid()), who) & bits == bits)
    };
    full.ancestors().skip(1).all(|dir| allowed(dir, 0o1)) && allowed(&full, need)
}

/// 그 사용자에게 적용되는 권한 칸(rwx 세 비트) — 소유자면 소유자 칸**만**, 아니고 그룹이 같으면 그룹 칸만,
/// 둘 다 아니면 그 밖의 칸이다. 먼저 맞는 칸 하나로 끝난다는 것이 커널의 규칙이다.
#[cfg(unix)]
fn class_bits(mode: u32, owner: (u32, u32), who: (u32, u32)) -> u32 {
    let shift = if owner.0 == who.0 {
        6
    } else if owner.1 == who.1 {
        3
    } else {
        0
    };
    (mode >> shift) & 0o7
}

#[cfg(unix)]
fn as_user_of(cmd: &mut Command, who: Option<(u32, u32)>) {
    use std::os::unix::process::CommandExt;
    if let Some((uid, gid)) = who {
        // uid 를 주면 표준 라이브러리가 덧붙은 그룹도 비운다(root 일 때).
        cmd.uid(uid).gid(gid);
    }
}

#[cfg(not(unix))]
fn as_user_of(_cmd: &mut Command, _who: Option<(u32, u32)>) {}

/// 시험용 공개키 — **배포되는 바이너리에는 없다**(`debug_assertions` 가 꺼진 빌드에서 컴파일되지 않는다 —
/// `elevation_override` 와 같은 장치다).
///
/// 통합 시험은 `cargo test` 가 지은 바이너리를 쓰고 거기에는 공개키가 박혀 있지 않다. 그 빌드로 *서명이
/// 맞으면 띄우고 다르면 띄우지 않는다* 를 재려면 시험이 만든 키를 줄 자리가 있어야 한다.
#[cfg(debug_assertions)]
fn dev_anchor() -> Option<String> {
    let v = std::env::var("REMEDY_NET_ANCHOR")
        .ok()
        .filter(|v| !v.is_empty())?;
    // 조용히 지나가지 않는다 — 무엇이 서명 확인의 기준이 됐는지 남는다.
    errln!(
        "{}",
        ui().lang.t(
            "알림: REMEDY_NET_ANCHOR 가 동반 프로그램의 서명 확인에 쓸 공개키를 대신했습니다 (개발 빌드 전용)",
            "Notice: REMEDY_NET_ANCHOR supplied the key used to verify the companion program (development builds only)"
        )
    );
    Some(v)
}

#[cfg(not(debug_assertions))]
fn dev_anchor() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join("remedy-cli-net").join(name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("작업 디렉터리");
        d
    }

    #[test]
    fn nothing_is_started_without_the_folder_or_a_key() {
        let d = lab("absent");
        assert_eq!(locate(&d, Some("x")), Err(Refusal::Absent));
        std::fs::create_dir_all(d.join(NAME)).unwrap();
        // 공개키가 없는 빌드는 확인할 방법이 없다 — 있는 파일을 그냥 띄우지 않는다.
        assert_eq!(locate(&d, None), Err(Refusal::NoAnchor));
    }

    #[test]
    fn an_unsigned_folder_is_refused() {
        let d = lab("unsigned");
        std::fs::create_dir_all(d.join(NAME)).unwrap();
        std::fs::write(d.join(NAME).join(program()), b"not a program").unwrap();
        // 형식이 맞는 공개키(시험용)여도 서명 파일이 없으면 거기서 멈춘다.
        let key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
        assert_eq!(locate(&d, Some(key)), Err(Refusal::NotSigned));
    }

    #[test]
    fn every_refusal_speaks_both_languages_and_names_the_program() {
        for r in [
            Refusal::Absent,
            Refusal::NoAnchor,
            Refusal::NotSigned,
            Refusal::Tampered("x".into()),
            Refusal::NotCompanion("x".into()),
            Refusal::OtherVersion("9.9.9".into()),
            Refusal::NoProgram,
        ] {
            for lang in [Lang::Ko, Lang::En] {
                assert!(r.message(lang).contains("remedy-net"), "{r:?} {lang:?}");
            }
        }
    }

    /// 소유자면 소유자 칸만 본다 — 그 밖의 칸이 더 넓어도 그쪽으로 넘어가지 않는다.
    #[cfg(unix)]
    #[test]
    fn the_permission_class_is_the_first_that_matches() {
        assert_eq!(class_bits(0o057, (10, 20), (10, 20)), 0);
        assert_eq!(class_bits(0o705, (10, 20), (11, 20)), 0);
        assert_eq!(class_bits(0o701, (10, 20), (11, 21)), 1);
        assert_eq!(class_bits(0o4755, (10, 20), (10, 99)), 7);
    }

    /// 내려 띄우기 전에 본다 — 조상 폴더를 지나지 못하거나 결과 폴더에 쓰지 못하면 내리지 않는다.
    /// root 의 umask 가 077 이면 본체가 지은 `out/` 이 0700 이라 sudo 를 건 사용자가 그 아래에 닿지 못한다.
    #[cfg(unix)]
    #[test]
    fn a_folder_the_user_cannot_pass_is_seen_before_launching() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = lab("reach");
        let out = d.join("out");
        let leaf = out.join(NAME);
        std::fs::create_dir_all(&leaf).unwrap();
        let me = std::fs::metadata(&leaf)
            .map(|m| (m.uid(), m.gid()))
            .unwrap();
        let chmod = |p: &Path, mode: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        assert!(reachable(&leaf, me, 0o3));
        chmod(&out, 0o600);
        assert!(!reachable(&leaf, me, 0o3), "지나지 못하는 조상");
        chmod(&out, 0o755);
        chmod(&leaf, 0o500);
        assert!(!reachable(&leaf, me, 0o3), "쓰지 못하는 결과 폴더");
        assert!(reachable(&leaf, me, 0o1));
        chmod(&leaf, 0o755);
    }
}
