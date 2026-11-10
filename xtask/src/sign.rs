//! 플러그인 서명 (설계-09 P10 · 설계-03 §10 G8).
//!
//! # 왜 제품 CLI 가 아니라 여기인가
//!
//! 서명에 쓰는 `minisign` 크레이트는 `rpassword`(→ `windows-sys`) · `scrypt` ·
//! `salsa20` · `pbkdf2` 를 끌어온다 — **개인키를 풀고 사람에게 암구호를 묻는
//! 도구의 의존성**이다. 치료 도구가 그것을 링크할 이유가 없다.
//!
//! 이것은 설계-01 D7 과 같은 판단이다. 치료 도구가 자기 갱신 채널을 갖지 않는
//! 것처럼, 서명 능력도 갖지 않는다. 고객 기계에서 도는 바이너리가 서명할 수
//! 있으면 그 능력이 곧 공격 표면이다.
//!
//! 검증은 반대다. 그것은 제품이 해야 하고, `remedy-trust` 가
//! `minisign-verify`(의존성 0개)로 한다.

use std::io::Write;
use std::path::{Path, PathBuf};

/// 개인키 암구호를 담는 환경변수. 없으면 대화형으로 묻는다.
///
/// **환경변수로 받는 것은 무인 릴리스를 위한 양보다.** 프로세스 목록이나
/// 로그에 새어 나갈 수 있으므로, 사람이 손으로 서명할 때는 쓰지 말 것.
const PASSWORD_ENV: &str = "REMEDY_SIGN_PASSWORD";

pub fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..]),
        Some("plugin") => sign_plugin(&args[1..]),
        Some("companion") => sign_companion(&args[1..]),
        Some("revocations") => sign_revocations(&args[1..]),
        Some("allowlist") => sign_allowlist(&args[1..]),
        Some(other) => Err(format!("알 수 없는 하위 명령: {other}")),
        None => Err(USAGE.to_string()),
    }
}

const USAGE: &str = "사용법:\n  \
    cargo xtask sign keygen --public-key <파일> --secret-key <파일>\n  \
    cargo xtask sign plugin --dir <플러그인 디렉터리> --secret-key <파일> \
    --signed-at <RFC3339>\n  \
    cargo xtask sign companion --dir <remedy-net 폴더> --secret-key <파일> \
    --signed-at <RFC3339>\n  \
    cargo xtask sign revocations --entries <JSON 파일> --serial <수> \
    --issued <RFC3339> --secret-key <파일> --out <파일>\n  \
    cargo xtask sign allowlist --entries <JSON 파일> --serial <수> \
    --issued <RFC3339> --secret-key <파일> --out <파일>";

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn need(args: &[String], name: &str) -> Result<String, String> {
    opt(args, name).ok_or_else(|| format!("{name} 가 없다\n{USAGE}"))
}

fn password() -> Option<String> {
    std::env::var(PASSWORD_ENV).ok()
}

fn keygen(args: &[String]) -> Result<(), String> {
    let pk_path = PathBuf::from(need(args, "--public-key")?);
    let sk_path = PathBuf::from(need(args, "--secret-key")?);

    // **덮어쓰지 않는다.** 개인키를 덮어쓰면 그 키로 서명한 모든 플러그인의
    // 검증 경로가 한 번에 끊기고, 되돌릴 방법이 없다.
    for p in [&pk_path, &sk_path] {
        if p.exists() {
            return Err(format!(
                "{} 가 이미 있다 — 키를 덮어쓰지 않는다. 교체하려면 먼저 옮겨 두고 \
                 그 키로 서명한 플러그인을 다시 서명할 계획을 세울 것",
                p.display()
            ));
        }
    }

    let pk_file = std::fs::File::create(&pk_path)
        .map_err(|e| format!("{} 를 만들지 못했다: {e}", pk_path.display()))?;
    let sk_file = std::fs::File::create(&sk_path)
        .map_err(|e| format!("{} 를 만들지 못했다: {e}", sk_path.display()))?;

    minisign::KeyPair::generate_and_write_encrypted_keypair(
        pk_file,
        sk_file,
        Some("remedy plugin signing key"),
        password(),
    )
    .map_err(|e| format!("키쌍 생성 실패: {e}"))?;

    println!("공개키: {}", pk_path.display());
    println!("개인키: {}", sk_path.display());
    println!();
    println!("개인키는 저장소에 넣지 말 것. 공개키는 배포 바이너리에 내장된다.");
    Ok(())
}

fn sign_plugin(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(need(args, "--dir")?);
    let sk_path = PathBuf::from(need(args, "--secret-key")?);
    let signed_at = need(args, "--signed-at")?;

    check_rfc3339(&signed_at)?;

    let (id, version) = read_plugin_identity(&dir)?;
    sign_tree(&dir, &id, &version, &sk_path, &signed_at)
}

/// 동반 프로그램(`remedy-net`)의 폴더를 서명한다 — 본체가 그 프로그램을 띄우기 전에 확인하는 서명이다
/// (설계-04 §1 *동반 모듈*).
///
/// 룰과 **같은 형식**이다(매니페스트 + minisign · 같은 키). 다른 것은 서명 주석의 이름과 버전이 어디서
/// 오는가다 — 룰은 `plugin.yaml` 에서 읽고, 동반 프로그램은 이름이 `remedy-net` 으로 고정이고 버전이
/// 코어 버전이다. 본체는 그 둘이 자기와 같은지 본다: 서명된 룰 폴더를 그 자리에 옮겨 놓거나 다른 릴리스의
/// 동반 프로그램을 섞어 놓은 것을 띄우지 않는다.
fn sign_companion(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(need(args, "--dir")?);
    let sk_path = PathBuf::from(need(args, "--secret-key")?);
    let signed_at = need(args, "--signed-at")?;

    check_rfc3339(&signed_at)?;

    // 실행 파일이 그 이름으로 들어 있어야 한다 — 빈 폴더나 엉뚱한 폴더에 서명하지 않는다.
    let has_program = [COMPANION, &format!("{COMPANION}.exe")]
        .iter()
        .any(|n| dir.join(n).is_file());
    if !has_program {
        return Err(format!(
            "{} 에 {COMPANION}(.exe) 가 없다 — 지은 동반 프로그램을 그 폴더에 먼저 둘 것",
            dir.display()
        ));
    }
    sign_tree(
        &dir,
        COMPANION,
        env!("CARGO_PKG_VERSION"),
        &sk_path,
        &signed_at,
    )
}

/// 동반 프로그램의 이름 — 폴더 이름이자 서명 주석의 이름이다(본체의 `net::NAME` 과 같은 값).
pub const COMPANION: &str = "remedy-net";

/// 폴더를 통째로 서명한다 — 매니페스트(파일마다 해시)를 만들고 그것에 서명한다.
fn sign_tree(
    dir: &Path,
    id: &str,
    version: &str,
    sk_path: &Path,
    signed_at: &str,
) -> Result<(), String> {
    let files = remedy_trust::collect(dir).map_err(|e| format!("{e}"))?;
    if files.is_empty() {
        return Err(format!("{} 에 서명할 파일이 없다", dir.display()));
    }
    let manifest = remedy_trust::Manifest::render(&files);

    let sk = minisign::SecretKey::from_file(sk_path, password())
        .map_err(|e| format!("{} 를 열지 못했다: {e}", sk_path.display()))?;

    let comment = remedy_trust::TrustedComment::render(id, version, signed_at);
    let sig = minisign::sign(
        None,
        &sk,
        manifest.as_bytes(),
        Some(&comment),
        Some("remedy plugin signature"),
    )
    .map_err(|e| format!("서명 실패: {e}"))?;

    write_file(&dir.join(remedy_trust::MANIFEST_NAME), manifest.as_bytes())?;
    write_file(
        &dir.join(remedy_trust::SIGNATURE_NAME),
        sig.to_string().as_bytes(),
    )?;

    println!("서명했다: {} ({} 개 파일)", dir.display(), files.len());
    println!("  {comment}");
    Ok(())
}

/// 폐기 목록을 서명한다 (설계-03 §6).
///
/// 입력은 항목 배열만 담은 JSON 이다 — `serial` 과 발행 시각은 **서명 주석**에
/// 들어가므로 본문에 적지 않는다. 두 곳에 두면 갈라지고, 갈라지면 어느 쪽이
/// 참인지 알 수 없다.
///
/// ```json
/// [ { "plugin": "evilai-locust", "below": "1.2.0", "reason": "오탐 사고" } ]
/// ```
fn sign_revocations(args: &[String]) -> Result<(), String> {
    let entries_path = PathBuf::from(need(args, "--entries")?);
    let sk_path = PathBuf::from(need(args, "--secret-key")?);
    let out_path = PathBuf::from(need(args, "--out")?);
    let issued = need(args, "--issued")?;
    let serial: u64 = need(args, "--serial")?
        .parse()
        .map_err(|_| "--serial 은 0 이상의 정수여야 한다".to_string())?;

    check_rfc3339(&issued)?;

    let text = std::fs::read_to_string(&entries_path)
        .map_err(|e| format!("{} 를 읽지 못했다: {e}", entries_path.display()))?;
    let entries: Vec<remedy_trust::revocation::Entry> = serde_json::from_str(&text)
        .map_err(|e| format!("{} 를 파싱하지 못했다: {e}", entries_path.display()))?;

    // **만들 때 걸러 낸다.** 서명한 뒤에 형식 오류를 알면 그 목록은 이미
    // 배포됐을 수 있다.
    let body = remedy_trust::revocation::render_body(&entries).map_err(|e| e.to_string())?;
    let comment = remedy_trust::revocation::render_comment(serial, &issued);

    let sk = minisign::SecretKey::from_file(&sk_path, password())
        .map_err(|e| format!("{} 를 열지 못했다: {e}", sk_path.display()))?;
    let sig = minisign::sign(
        None,
        &sk,
        body.as_bytes(),
        Some(&comment),
        Some("remedy revocation list"),
    )
    .map_err(|e| format!("서명 실패: {e}"))?;

    // 서명 4줄 + 빈 줄 + 본문. 한 파일인 이유는 `remedy-trust` 의
    // `revocation` 모듈 문서에 있다 — 폐쇄망 반입에서 파일 하나만 옮기는
    // 사고를 없앤다.
    let mut out = sig.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&body);

    write_file(&out_path, out.as_bytes())?;
    println!("서명했다: {} ({} 건)", out_path.display(), entries.len());
    println!("  {comment}");
    Ok(())
}

/// 조직 허용 목록에 서명한다 (설계-03 §3 5층).
///
/// 폐기 목록과 **같은 레일**이고 방향만 반대다. 서명 주석의 접두가 다르므로
/// 한쪽을 다른 쪽으로 들이밀 수 없다 — 그 둘은 정반대를 뜻하기 때문이다.
///
/// `--entries` 는 `[{"sha256": "...", "reason": "..."}]` 다. **사유는 비울 수
/// 없고 해시는 16진 64자여야 한다** — 둘 다 만들 때 걸러진다.
fn sign_allowlist(args: &[String]) -> Result<(), String> {
    let entries_path = PathBuf::from(need(args, "--entries")?);
    let sk_path = PathBuf::from(need(args, "--secret-key")?);
    let out_path = PathBuf::from(need(args, "--out")?);
    let issued = need(args, "--issued")?;
    let serial: u64 = need(args, "--serial")?
        .parse()
        .map_err(|_| "--serial 은 0 이상의 정수여야 한다".to_string())?;

    check_rfc3339(&issued)?;

    let text = std::fs::read_to_string(&entries_path)
        .map_err(|e| format!("{} 를 읽지 못했다: {e}", entries_path.display()))?;
    let entries: Vec<remedy_trust::allowlist::Entry> = serde_json::from_str(&text)
        .map_err(|e| format!("{} 를 파싱하지 못했다: {e}", entries_path.display()))?;

    // **만들 때 걸러 낸다.** 틀린 해시는 조용히 아무것도 면제하지 않는데,
    // 운영자는 면제된 줄 안다.
    let body = remedy_trust::allowlist::render_body(&entries).map_err(|e| e.to_string())?;
    let comment = remedy_trust::allowlist::render_comment(serial, &issued);

    let sk = minisign::SecretKey::from_file(&sk_path, password())
        .map_err(|e| format!("{} 를 열지 못했다: {e}", sk_path.display()))?;
    let sig = minisign::sign(
        None,
        &sk,
        body.as_bytes(),
        Some(&comment),
        Some("remedy allowlist"),
    )
    .map_err(|e| format!("서명 실패: {e}"))?;

    let mut out = sig.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&body);

    write_file(&out_path, out.as_bytes())?;
    println!("서명했다: {} ({} 건)", out_path.display(), entries.len());
    println!("  {comment}");
    println!("\n  ** 여기 있는 해시는 판정이 서도 파괴되지 않는다. 사유가 감사 기록이다.");
    Ok(())
}

/// 텍스트 파일을 **LF 로** 쓴다.
///
/// 서명은 바이트열을 덮는다. Windows 에서 만든 매니페스트가 CRLF 면 Linux 에서
/// 같은 트리를 서명해도 다른 바이트가 되고, 두 서명이 서로를 거부한다.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = std::fs::File::create(path)
        .map_err(|e| format!("{} 를 쓰지 못했다: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("{} 를 쓰지 못했다: {e}", path.display()))?;
    Ok(())
}

/// `plugin.yaml` 에서 id 와 version 을 읽는다.
///
/// **인자로 받지 않는 이유**: 두 번 적으면 갈라진다. 매니페스트가 말하는
/// 버전과 서명이 말하는 버전이 다르면 역행 금지 판정이 무엇을 근거로 하는지
/// 알 수 없게 된다.
fn read_plugin_identity(dir: &Path) -> Result<(String, String), String> {
    let path = dir.join("plugin.yaml");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("{} 를 읽지 못했다: {e}", path.display()))?;
    let m: remedy_sdk::manifest::PluginManifest = serde_yaml_ng::from_str(&text)
        .map_err(|e| format!("{} 를 파싱하지 못했다: {e}", path.display()))?;
    Ok((m.id, m.version))
}

/// 서명 시각의 형식을 본다. 이 값으로 역행 금지를 판정할 것이므로 자유
/// 문자열이어서는 안 된다.
///
/// **완전한 RFC3339 파서가 아니다** — `YYYY-MM-DDTHH:MM:SSZ` 만 받는다. 넓게
/// 받아 주면 서명마다 다른 표기가 섞이고, 그러면 두 서명 중 어느 쪽이 나중인지
/// 비교하는 코드가 표기별 분기를 갖게 된다.
fn check_rfc3339(s: &str) -> Result<(), String> {
    let bad = || {
        Err(format!(
            "--signed-at 은 YYYY-MM-DDTHH:MM:SSZ 여야 한다 (UTC): {s:?}"
        ))
    };
    let b = s.as_bytes();
    if b.len() != 20 {
        return bad();
    }
    let digits = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    if !digits.iter().all(|&i| b[i].is_ascii_digit()) {
        return bad();
    }
    if b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return bad();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 서명_시각_형식을_강제한다() {
        check_rfc3339("2026-08-25T09:00:00Z").expect("올바른 값을 거부했다");
        for bad in [
            "2026-08-25",
            "2026-08-25T09:00:00+09:00",
            "2026-08-25 09:00:00Z",
            "26-08-25T09:00:00Z",
            "2026-08-25T09:00:00z",
            "",
        ] {
            assert!(check_rfc3339(bad).is_err(), "받아들이면 안 된다: {bad:?}");
        }
    }
}
