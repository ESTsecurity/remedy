//! OS 고유 메타데이터 — **잡아 두지 않으면 영영 사라진다** (설계-02 §9).
//!
//! 격리는 원본을 컨테이너에 넣고 지운다. 그 순간 파일의 소유자·DACL·확장 속성은
//! 컨테이너에 담긴 것 말고는 남지 않는다. **복원은 나중에 나아질 수 있지만
//! 포착은 소급되지 않는다** — 이미 만들어진 컨테이너에 없는 정보는 없는 것이다.
//! 그래서 포착 쪽이 먼저다.
//!
//! # 되돌리지 못하는 것을 조용히 넘기지 않는다
//!
//! SACL 포착에는 `SeSecurityPrivilege` 가, 소유자 변경에는 `SeRestorePrivilege`
//! 가 필요하다(설계-02 §9). 이 코드는 그 특권을 켜지 않는다 — 켜려면 unsafe 로
//! 토큰을 만져야 하고, 이 크레이트는 `forbid(unsafe_code)` 를 유지한다.
//!
//! 그래서 SACL 은 포착하지 않고, 소유자 복원은 **실패하면 나머지를 살린 뒤 그
//! 사실을 보고서에 적는다.** 못 한 것을 못 했다고 말하는 편이, 다 된 것처럼
//! 보이고 권한만 틀린 파일을 남기는 것보다 낫다.
//!
//! # 상속이 대개 옳다
//!
//! 새로 만든 파일은 부모의 ACL 을 상속한다. 악성코드 대부분은 사용자 쓰기 가능한
//! 곳에 있고 명시적 ACE 가 없으므로, **SDDL 을 되돌리지 않아도 결과가 같다.**
//! 이 모듈이 값을 하는 자리는 명시적 ACE 나 비표준 소유자가 있던 파일이다 —
//! 제거를 방해하려고 ACL 을 건 악성코드, 그리고 오탐으로 격리된 사용자 문서.

use crate::write::{FileMeta, RestoreReport};

/// 지금 있는 파일의 OS 고유 메타데이터를 `meta` 에 채운다.
pub fn capture_into(path: &str, meta: &mut FileMeta) {
    capture_platform(path, meta);
}

/// 담아 둔 OS 고유 메타데이터를 되돌린다.
pub fn restore_from(path: &str, meta: &FileMeta, report: &mut RestoreReport) {
    restore_platform(path, meta, report);
}

// ────────────────────────────────────────────────────────── Windows

#[cfg(windows)]
fn capture_platform(path: &str, meta: &mut FileMeta) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::GetNamedSecurityInfo;

    // SACL 은 빼고 묻는다. SeSecurityPrivilege 없이 요청하면 전체가 실패해
    // **소유자와 DACL 까지 함께 잃는다.**
    let want = SecurityInformation::Owner | SecurityInformation::Group | SecurityInformation::Dacl;
    if let Ok(sd) = GetNamedSecurityInfo(path, SeObjectType::SE_FILE_OBJECT, want) {
        if let Ok(s) = sd.as_sddl() {
            meta.sddl = Some(s.to_string_lossy().to_string());
        }
    }
}

#[cfg(windows)]
fn restore_platform(path: &str, meta: &FileMeta, report: &mut RestoreReport) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{
        ConvertStringSecurityDescriptorToSecurityDescriptor, SetNamedSecurityInfo,
    };

    let Some(sddl) = &meta.sddl else {
        return;
    };
    let sd = match ConvertStringSecurityDescriptorToSecurityDescriptor(sddl.as_str()) {
        Ok(sd) => sd,
        Err(e) => {
            report.lose(
                "sddl",
                remedy_sdk::i18n::current().pick(
                    format!("SDDL 을 해석하지 못했습니다: {e}"),
                    format!("the SDDL could not be parsed: {e}"),
                ),
            );
            return;
        }
    };

    // **상속 차단은 따로 요청해야 붙는다.** `D:P` 를 담아 두고 `Dacl` 만 주면
    // ACE 는 적용되는데 상속은 그대로 켜진 채로 남아, 부모에서 내려온 ACE 가
    // 다시 섞인다. VM 검증에서 `D:P(...)` 를 넣었더니 `D:AI(...)` 가 나와서
    // 드러났다 — 되돌아온 것처럼 보이고 실제 권한은 달랐다.
    let dacl_flag = if dacl_is_protected(sddl) {
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl
    } else {
        SecurityInformation::Dacl | SecurityInformation::UnprotectedDacl
    };

    // 소유자·그룹은 **담겨 있을 때만** 요청한다. 없는데 요청하면 무엇이 일어나는지
    // 플랫폼마다 다르고, 여기서 애매해질 이유가 없다.
    let mut full = dacl_flag;
    if sd.owner().is_some() {
        full |= SecurityInformation::Owner;
    }
    if sd.group().is_some() {
        full |= SecurityInformation::Group;
    }

    // 소유자까지 한 번에 시도하고, 막히면 소유자만 빼고 다시 시도한다.
    // 소유자 변경에는 SeRestorePrivilege 가 필요한데 그것을 켜려면 unsafe 가
    // 필요하다. 여기서 통째로 포기하면 **DACL 까지 함께 잃는다** — 되돌릴 수 있는
    // 것은 되돌리고, 못 한 것만 적는다.
    match SetNamedSecurityInfo(
        path,
        SeObjectType::SE_FILE_OBJECT,
        full,
        sd.owner(),
        sd.group(),
        sd.dacl(),
        None,
    ) {
        Ok(()) => {
            report.restored.push("sddl".into());
            report.lose(
                "sacl",
                remedy_sdk::i18n::t(
                    "감사 ACL 은 포착하지 않았습니다 (SeSecurityPrivilege 필요 — 설계-02 §9)",
                    "the audit ACL was not captured (SeSecurityPrivilege required — \
                     design-02 §9)",
                ),
            );
        }
        Err(owner_err) => {
            match SetNamedSecurityInfo(
                path,
                SeObjectType::SE_FILE_OBJECT,
                dacl_flag,
                None,
                None,
                sd.dacl(),
                None,
            ) {
                Ok(()) => {
                    report.restored.push("dacl".into());
                    report.lose(
                        "owner",
                        remedy_sdk::i18n::current().pick(
                            format!(
                                "소유자를 되돌리지 못했습니다 (SeRestorePrivilege 필요): {owner_err}"
                            ),
                            format!(
                                "the owner could not be restored (SeRestorePrivilege \
                                 required): {owner_err}"
                            ),
                        ),
                    );
                    report.lose(
                        "sacl",
                        remedy_sdk::i18n::t(
                            "감사 ACL 은 포착하지 않았습니다 (SeSecurityPrivilege 필요)",
                            "the audit ACL was not captured (SeSecurityPrivilege required)",
                        ),
                    );
                }
                Err(e) => report.lose(
                    "sddl",
                    remedy_sdk::i18n::current().pick(
                        format!("보안 디스크립터를 되돌리지 못했습니다: {e}"),
                        format!("the security descriptor could not be restored: {e}"),
                    ),
                ),
            }
        }
    }
}

/// SDDL 의 DACL 이 **상속을 끊었는가** (`D:P...`).
///
/// 담아 둔 문자열에서 읽는다. SDDL 은 `O:` `G:` `D:` `S:` 순서이고 `:` 는 구역
/// 표시 문자 바로 뒤에만 오므로, 처음 나오는 `D:` 가 DACL 구역이다 — 별칭은 두
/// 글자이고 그 뒤에는 다음 구역 문자가 오지 `:` 가 오지 않는다.
#[cfg(windows)]
fn dacl_is_protected(sddl: &str) -> bool {
    match sddl.find("D:") {
        Some(i) => sddl[i + 2..]
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .any(|c| c == 'P'),
        None => false,
    }
}

// ────────────────────────────────────────────────────────── Unix

#[cfg(unix)]
fn capture_platform(path: &str, meta: &mut FileMeta) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::metadata(path) {
        meta.mode = Some(md.permissions().mode());
    }
    // 확장 속성. SELinux 컨텍스트(`security.selinux`)도 여기로 실려 온다.
    // 값은 임의 바이트라 base64 로 담는다.
    let mut out = std::collections::BTreeMap::new();
    if let Ok(names) = xattr::list(path) {
        for name in names {
            let key = name.to_string_lossy().to_string();
            if let Ok(Some(v)) = xattr::get(path, &name) {
                out.insert(key, base64_encode(&v));
            }
        }
    }
    if !out.is_empty() {
        meta.xattrs = out;
    }
}

#[cfg(unix)]
fn restore_platform(path: &str, meta: &FileMeta, report: &mut RestoreReport) {
    use std::os::unix::fs::PermissionsExt;

    if let Some(mode) = meta.mode {
        let perm = std::fs::Permissions::from_mode(mode);
        match std::fs::set_permissions(path, perm) {
            Ok(()) => report.restored.push("mode".into()),
            Err(e) => report.lose("mode", e.to_string()),
        }
    }

    for (name, b64) in &meta.xattrs {
        let Some(value) = base64_decode(b64) else {
            report.lose(
                format!("xattr:{name}"),
                remedy_sdk::i18n::t("base64 가 아닙니다", "not base64"),
            );
            continue;
        };
        match xattr::set(path, name, &value) {
            Ok(()) => report.restored.push(format!("xattr:{name}")),
            // SELinux 정책이 거부하면 root 라도 실패한다 (설계-02 §9).
            Err(e) => report.lose(format!("xattr:{name}"), e.to_string()),
        }
    }
}

#[cfg(unix)]
fn base64_encode(v: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in v.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(unix)]
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let b: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for c in b.chunks(4) {
        let pad = c.iter().filter(|&&x| x == b'=').count();
        let mut n = 0u32;
        for (i, &ch) in c.iter().enumerate() {
            let v = if ch == b'=' { 0 } else { val(ch)? };
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

// ─────────────────────────────────────────── 그 외 플랫폼

#[cfg(not(any(windows, unix)))]
fn capture_platform(_path: &str, _meta: &mut FileMeta) {}

#[cfg(not(any(windows, unix)))]
fn restore_platform(_path: &str, _meta: &FileMeta, report: &mut RestoreReport) {
    report.lose(
        "os-metadata",
        remedy_sdk::i18n::t(
            "이 플랫폼의 메타데이터 백엔드가 없습니다",
            "this platform has no metadata backend",
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **못 되돌린 사유는 복원 화면에 그대로 나간다** — `RestoreReport::lose` 가
    /// `lost` 에 넣고 `main.rs` 가 항목마다 `되살리지 못함 <항목>  <사유>` 로
    /// 찍는다. §3 이 `write.rs` 의 `lose()` 호출을 두 언어로 고칠 때 이 파일은
    /// 목록에 없었다.
    ///
    /// **이름을 그대로 둔 것**은 아래 시험들을 고치지 않기 위해서다.
    /// **OS 가 준 문구는 우리가 고칠 수 없다** (§4). 한국어 Windows 는
    /// `매개 변수가 틀립니다. (os error 87)` 처럼 답하고, 그것이 `{e}` 로 실려
    /// 온다. `(os error N)` 이 붙어 있으면 마지막 `: ` 뒤가 그 꼬리다.
    fn 우리_문구만(s: &str) -> &str {
        if s.contains("(os error ") {
            if let Some(i) = s.rfind(": ") {
                return &s[..i];
            }
        }
        s
    }

    fn restore_from(path: &str, meta: &FileMeta, report: &mut RestoreReport) {
        super::restore_from(path, meta, report);
        for l in &report.lost {
            let ours = 우리_문구만(&l.reason);
            assert!(
                !ours.chars().any(|c| ('가'..='힣').contains(&c)),
                "되살리지 못한 사유가 영어 회차에서 한글로 나온다 ({}): {}",
                l.item,
                l.reason
            );
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("remedy-meta-test-{name}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn capture_then_restore_round_trips_the_os_metadata() {
        // 포착이 소급되지 않는다는 것이 이 모듈의 존재 이유다. 담기지 않으면
        // 그 정보는 컨테이너에도 없고, 복원이 아무리 좋아져도 되살릴 것이 없다.
        let dir = tmp("roundtrip");
        let p = dir.join("x.bin");
        std::fs::write(&p, b"x").unwrap();
        let s = p.to_str().unwrap();

        let mut meta = FileMeta::default();
        capture_into(s, &mut meta);

        #[cfg(windows)]
        assert!(meta.sddl.is_some(), "SDDL 을 포착하지 못했다");
        #[cfg(unix)]
        assert!(meta.mode.is_some(), "mode 를 포착하지 못했다");

        // 지웠다가 되돌린다 — 격리·복원이 실제로 하는 일이다.
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"x").unwrap();

        let mut report = RestoreReport::default();
        restore_from(s, &meta, &mut report);

        #[cfg(windows)]
        {
            let ok = report.restored.iter().any(|r| r == "sddl" || r == "dacl");
            assert!(ok, "보안 디스크립터를 아무것도 되돌리지 못했다: {report:?}");
            // 못 한 것은 언제나 적힌다.
            assert!(report.lost.iter().any(|l| l.item == "sacl"), "{report:?}");
        }
        #[cfg(unix)]
        assert!(report.restored.iter().any(|r| r == "mode"), "{report:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_bad_sddl_is_reported_not_ignored() {
        let dir = tmp("badsddl");
        let p = dir.join("x");
        std::fs::write(&p, b"x").unwrap();
        let meta = FileMeta {
            sddl: Some("이건 SDDL 이 아니다".into()),
            ..Default::default()
        };
        let mut report = RestoreReport::default();
        restore_from(p.to_str().unwrap(), &meta, &mut report);
        #[cfg(windows)]
        assert!(
            report.lost.iter().any(|l| l.item == "sddl"),
            "깨진 SDDL 이 조용히 넘어갔다: {report:?}"
        );
        let _ = &report;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn protected_dacls_are_recognized_in_the_sddl() {
        // 상속 차단을 못 읽으면 `Dacl` 만 주게 되고, ACE 는 붙는데 상속은 켜진
        // 채로 남아 부모의 ACE 가 다시 섞인다. VM 검증에서 실제로 그랬다.
        assert!(dacl_is_protected("D:P(A;;FA;;;BA)"));
        assert!(dacl_is_protected("D:PAI(A;;FA;;;BA)"));
        assert!(dacl_is_protected("O:BAG:SYD:P(A;;FA;;;SY)"));
        assert!(!dacl_is_protected("D:AI(A;;FA;;;BA)"));
        assert!(!dacl_is_protected("D:(A;;FA;;;BA)"));
        // 별칭이 D 로 끝나도 구역 표시로 오해하지 않는다.
        assert!(dacl_is_protected("O:DAG:DAD:P(A;;FA;;;SY)"));
        assert!(!dacl_is_protected("O:DAG:DAD:(A;;FA;;;SY)"));
        assert!(!dacl_is_protected("S:(AU;;FA;;;WD)"));
    }

    #[cfg(unix)]
    #[test]
    fn base64_round_trips_arbitrary_bytes() {
        // 확장 속성 값은 임의 바이트다. 문자열로 담으면 깨진다.
        for v in [
            vec![],
            vec![0u8],
            vec![0u8, 255],
            vec![1, 2, 3],
            (0u8..=255).collect::<Vec<u8>>(),
        ] {
            let e = base64_encode(&v);
            assert_eq!(base64_decode(&e).as_deref(), Some(v.as_slice()), "{e}");
        }
        assert_eq!(base64_decode("!!!!"), None);
    }
}
