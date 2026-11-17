//! 쓰기 경계 — **P2 에서는 비어 있다. 그것이 게이트다.**
//!
//! 설계-09 P2 의 게이트는 "여기까지 읽기만 한다" 이다. 파괴 동작의 시그니처를
//! 지금 정해 두면 그것을 부르는 코드가 생기고, 게이트는 문서에만 남는다.
//!
//! **복원 쓰기가 P5 로 먼저 들어오고**, Op 별 파괴 쓰기가 P6(격리) →
//! P7(되돌릴 수 있는 것) → P8(되돌릴 수 없는 것) 순서로 뒤따른다. 그 순서 자체가
//! 안전 장치다 — 격리와 복원이 첫 파괴보다 먼저다 (설계-09 §2).
//!
//! 격리 컨테이너와 저널은 **이 경계를 지나지 않는다.** 그것은 remedy 가 자기 상태
//! 디렉터리에 쓰는 것이라 시스템 변경이 아니고, 여기 섞으면 "시스템에 손대는 곳은
//! 여기 하나" 라는 성질이 흐려진다 (설계-03 §5).
//!
//! # 이 모듈이 지켜야 할 성질
//!
//! - 대상은 **완전히 구체화된 형태**로만 받는다. 경로를 재해석하거나 새 대상을
//!   탐색하지 않는다 (불변식 P, 설계-03 §1).
//! - `read` 의 trait 을 여기서 재수출하지 않는다. 한 곳에서 읽고 쓸 수 있게 되면
//!   `remedy-apply` 가 탐색을 시작할 수 있다.

use crate::PlatformError;
use serde::{Deserialize, Serialize};

/// 복원할 때 되살려야 할 메타데이터.
///
/// 컨테이너에 담긴 것을 그대로 옮겨 온 값이며, **여기서 새로 계산하지 않는다.**
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    /// 수정 시각. **에포크 초와 나노초로 담는다.**
    ///
    /// 사람이 읽는 문자열로 담으면 되돌릴 때 다시 파싱해야 하고, 그 왕복에서
    /// 정밀도가 깎인다. 설계-02 §9 는 mtime 을 "나노초 정밀도 값" 으로 저장하라고
    /// 적었다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_unix: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_nanos: Option<u32>,
    /// 생성 시각. **Windows 에서만 되돌릴 수 있다.**
    ///
    /// Unix 에는 btime 설정 syscall 이 없다. Windows 에는 `SetFileTime` 이 있고
    /// std 가 `FileTimesExt::set_created` 로 그것을 안전하게 연다.
    ///
    /// 이 필드가 뒤늦게 생긴 이유: 담지 않으면 되돌릴 수도 없는데, 담는 자리와
    /// 되돌리는 자리 양쪽이 *"설정 syscall 이 없다"* 는 Unix 의 사실을
    /// **Windows 에서도 되풀이하고 있었다** (2026-08-28 v1 점검, G2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btime_unix: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btime_nanos: Option<u32>,
    /// 읽기 전용 여부 (Windows) / 쓰기 비트 (Unix).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
    /// Windows 보안 디스크립터. 자기상대 SDDL 문자열.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sddl: Option<String>,
    /// Linux 권한 비트.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// 확장 속성. 값은 임의 바이트라 base64 로 담는다.
    ///
    /// `security.selinux` 가 여기로 실려 온다. 정책이 거부하면 root 라도 되돌리지
    /// 못하므로(설계-02 §9) 그때는 보고서에 적힌다.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub xattrs: std::collections::BTreeMap<String, String>,
}

/// 복원이 실제로 무엇을 되살렸고 무엇을 못 살렸는가.
///
/// **"복원했습니다" 라고 뭉뚱그리지 않는다** (설계-02 §9). `ctime`·`btime` 처럼
/// 설정 syscall 이 아예 없는 항목이 있고, SDDL 은 권한이 있어야 쓴다. 무엇이
/// 빠졌는지 말하지 않으면 사용자는 복원이 완전했다고 믿는다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    pub restored: Vec<String>,
    /// 되살리지 못한 항목과 그 이유.
    pub lost: Vec<LostItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LostItem {
    pub item: String,
    pub reason: String,
}

impl RestoreReport {
    pub fn lose(&mut self, item: impl Into<String>, reason: impl Into<String>) {
        self.lost.push(LostItem {
            item: item.into(),
            reason: reason.into(),
        });
    }
}

/// 레지스트리 값 하나의 **원본 그대로** (설계-09 P7).
///
/// 타입 번호와 바이트를 날것으로 든다. 우리 `RegValue` 열거형으로 옮기면
/// 거기에 없는 타입이 `Other` 로 떨어지고 복원이 원본과 달라진다 —
/// **백업은 해석이 아니라 보존이다.**
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValueBackup {
    /// Windows 레지스트리 타입 번호 (`REG_SZ`=1, `REG_EXPAND_SZ`=2,
    /// `REG_BINARY`=3, `REG_DWORD`=4, `REG_MULTI_SZ`=7 …).
    pub vtype: u32,
    /// 값의 바이트. 문자열이면 UTF-16LE 이고 종단 NUL 을 포함한다.
    pub bytes: Vec<u8>,
}

/// `REG_MULTI_SZ` 의 바이트를 항목 목록으로 되짚는다.
///
/// **이 파싱이 저장소에 한 벌뿐이어야 한다.** 두 벌이던 동안 둘이 갈라져 있었고,
/// 각자 다른 것을 잃었다 (2026-09-05):
///
/// | | 수집기 (`windows.rs::from_reg`) | 백업 (`as_multi`) |
/// |---|---|---|
/// | 빈 항목 | **버렸다** (`filter(!is_empty)`) | 지켰다 |
/// | 종단 없는 손상된 값 | 지켰다 | **통째로 잃었다** |
///
/// 수집기 쪽은 `split('\0')` 이 만들어 내는 종단 조각을 걸러 내려던 것이었는데
/// 진짜 빈 항목까지 함께 가져갔다. 그 결과 실기기의 `BootExecute` 는 5항목인데
/// 스냅샷에 3항목으로 적혔고, `PendingFileRenameOperations` 는 **출발지만 남고
/// 목적지가 사라졌다** — 거기서 빈 목적지는 "지워라" 를 뜻한다.
///
/// # 구조
///
/// 몸통은 `항목\0` 이 이어진 것이고 그 뒤에 목록의 끝을 뜻하는 `\0` 이 하나 더
/// 붙는다. 끝 표시를 떼고, 남은 것을 `\0` 로 가르면 마지막 조각은 마지막 항목의
/// 종단이 만든 빈 것이라 버린다.
///
/// **종단이 없으면 떼지도 버리지도 않는다.** 레지스트리는 임의 바이트를 담을 수
/// 있고, 검체가 종단 없는 값을 써 두면 그것을 못 보는 쪽이 진다 — 잃는 것이
/// 빈 항목 하나가 아니라 **항목 전체**다.
pub fn split_multi_sz(u16s: &[u16]) -> Vec<String> {
    let body = match u16s.split_last() {
        Some((0, rest)) => rest,
        _ => u16s,
    };
    if body.is_empty() {
        return Vec::new();
    }
    let terminated = body.last() == Some(&0);
    let mut out: Vec<String> = body
        .split(|c| *c == 0)
        .map(String::from_utf16_lossy)
        .collect();
    if terminated {
        out.pop();
    }
    out
}

impl RegistryValueBackup {
    /// 문자열 값이면 그 문자열. 아니면 `None`.
    ///
    /// **부분 편집이 이것을 쓴다.** `REG_SZ`·`REG_EXPAND_SZ` 가 아닌 값에서
    /// 문자열을 잘라 내려 하면 그것은 편집이 아니라 손상이다.
    pub fn as_string(&self) -> Option<String> {
        if self.vtype != 1 && self.vtype != 2 {
            return None;
        }
        let u16s: Vec<u16> = self
            .bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|c| *c != 0)
            .collect();
        String::from_utf16(&u16s).ok()
    }

    /// `REG_MULTI_SZ` 의 문자열 목록. 아니면 `None`.
    ///
    /// 재부팅 삭제 큐가 이 타입이다. **읽어서 덧붙여야** 하며, 통째로 덮어쓰면
    /// 다른 설치 관리자가 예약해 둔 항목이 사라진다.
    pub fn as_multi(&self) -> Option<Vec<String>> {
        if self.vtype != 7 {
            return None;
        }
        let u16s: Vec<u16> = self
            .bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(split_multi_sz(&u16s))
    }

    /// 문자열 목록에서 `REG_MULTI_SZ` 를 만든다.
    pub fn from_multi(items: &[String]) -> Self {
        let mut bytes = Vec::new();
        for s in items {
            for u in s.encode_utf16() {
                bytes.extend_from_slice(&u.to_le_bytes());
            }
            bytes.extend_from_slice(&[0, 0]);
        }
        // 목록의 끝은 빈 문자열 하나 더다.
        bytes.extend_from_slice(&[0, 0]);
        Self { vtype: 7, bytes }
    }

    /// `REG_DWORD` 값을 만든다.
    ///
    /// **문자열로 우회할 수 없다.** `from_string(4, "0")` 은 UTF-16 바이트
    /// `30 00 00 00` 을 내고, 그 넷을 수로 읽으면 0 이 아니라 **48** 이다.
    /// 길이가 우연히 4바이트라 레지스트리가 받아들이므로 오류도 나지 않는다.
    pub fn from_dword(n: u32) -> Self {
        Self {
            vtype: 4,
            bytes: n.to_le_bytes().to_vec(),
        }
    }

    /// 문자열에서 같은 타입의 값을 만든다. 종단 NUL 을 붙인다.
    pub fn from_string(vtype: u32, s: &str) -> Self {
        let mut bytes = Vec::with_capacity(s.len() * 2 + 2);
        for u in s.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        Self { vtype, bytes }
    }
}

/// 쓰기 백엔드.
///
/// P5 에서는 복원 하나뿐이었다. P6 이 파일 파괴를, **P7 이 레지스트리 값**을
/// 더한다.
///
/// # 레지스트리 메서드에 기본 구현을 두는 이유
///
/// 파일만 다루는 백엔드(`FsRestore`, 시험용 가짜)가 레지스트리를 쓸 일이 없다.
/// 기본값은 **`Unsupported` 를 돌려준다** — 조용히 성공하면 백업 없이 파괴한
/// 것과 구분되지 않는다.
/// 재부팅 후 검증 예약의 **고정된 이름** (설계-03 §8 자기 흔적 규칙 1).
///
/// > 도구가 스스로 만든 지속성 항목은 고정된 식별 가능한 이름을 쓰고, 검증
/// > 직후 스스로 제거하며, 감사 로그에 자기 항목으로 기록된다.
///
/// **run_id 를 이름에 넣지 않는다.** 이름이 매번 달라지면 "우리 것" 을 알아볼
/// 수 없고, 지우다 실패한 옛 항목이 쌓여도 아무도 모른다. run_id 는 값 데이터의
/// 명령줄 인자로 들어간다.
pub const SCHEDULED_VERIFY_NAME: &str = "remedy-verify";

/// 예약이 **어디에** 앉고 **누가** 지우는가 — 보고에 그대로 쓴다 (자기 흔적 규칙 3).
///
/// **위치를 호출자가 박아 두면 플랫폼마다 틀린다.** 한동안 `remedy-core` 의
/// `restart.rs` 가 RunOnce 경로를 박아 두었고, 리눅스에서 예약이 되기 시작하면
/// 성공 메시지가 레지스트리 경로를 출력할 뻔했다 (P12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySite {
    /// 사람이 읽는 자리. Windows 는 RunOnce 값, 리눅스는 유닛 파일 경로.
    pub location: String,
    /// 실행 직전에 그 항목을 지우는 주체 (자기 흔적 규칙 2).
    pub removed_by: RemovedBy,
}

/// 예약 항목을 **실행 직전에** 지우는 주체.
///
/// 규칙 (2) 를 누가 지키는지가 플랫폼마다 다르다 — 그 사실을 사용자에게 그대로
/// 말하려고 둔다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovedBy {
    /// OS 가 지운다 — Windows RunOnce.
    Os,
    /// 항목이 스스로 지운다 — 리눅스 유닛의 `ExecStartPre`.
    Itself,
}

/// 재부팅 뒤 돌 명령줄. **여기 한 곳에서만 만든다.**
///
/// # 왜 함수인가
///
/// 이 문자열은 OS 가 나중에 실행한다. 즉 **우리가 만들어 내보내는 문자열인데
/// 아무도 파싱해 보지 않는 부류**다. 실제로 그래서 `--plugin` 이 빠진 채
/// P10 이 닫혔고, 재부팅 뒤 검증이 사용법 오류로 조용히 끝났다 (2026-08-28
/// v1 점검).
///
/// 순수 함수로 빼 두면 **CLI 가 그 문자열을 그대로 실행해 볼 수 있다** —
/// `remedy-cli/tests/scheduled_verify.rs` 가 그것을 한다.
///
/// 경로에 공백이 있을 수 있어 따옴표로 감싼다. 감싸지 않으면 RunOnce 가 첫
/// 공백에서 잘라 읽는다.
///
/// # 언어를 싣는 이유
///
/// **재부팅 회차는 환경을 물려받지 못한다.** 언어는 `--lang > REMEDY_LANG >
/// 로케일 > en` 으로 정해지는데, RunOnce 는 그 환경변수 없이 돈다. 그래서
/// 국내 배포가 `REMEDY_LANG=ko` 로 치료한 기계가 재부팅 뒤에는 영어로 돌았고,
/// **한 회차의 로그가 앞은 한국어 뒤는 영어**가 됐다 (실측 2026-09-07 P10-F).
///
/// 지금 회차가 정한 언어를 명령에 박아 넣는다 — 한 회차는 한 언어로 읽혀야
/// 한다. `--lang` 은 전역 플래그라 하위 명령보다 뒤에 와도 받아들여진다.
pub fn scheduled_verify_command(
    exe: &std::path::Path,
    run_id: &str,
    plugin: &std::path::Path,
    state_dir: Option<&std::path::Path>,
    lang: remedy_sdk::i18n::Lang,
) -> String {
    let mut cmd = format!(
        "\"{}\" verify --run {run_id} --plugin \"{}\" --lang {}",
        exe.display(),
        plugin.display(),
        lang.id()
    );
    if let Some(d) = state_dir {
        // 기본 자리가 아니면 승인된 계획을 그 아래에서 찾아야 한다.
        cmd.push_str(&format!(" --state-dir \"{}\"", d.display()));
    }
    cmd
}

/// 그 예약이 앉는 자리 (Windows).
///
/// **HKLM 이다.** 치료는 관리자 권한으로 돌고, 재검증도 같은 권한이 필요하다 —
/// `System32\Tasks` 를 다시 읽어야 하기 때문이다. HKCU 에 두면 그 사용자
/// 세션에서만 돌고 권한이 모자란다.
pub const RUNONCE_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";

pub trait PlatformWrite {
    /// 이 백엔드가 무엇인지 사람이 읽을 이름. 감사 로그에 남는다.
    fn backend_name(&self) -> &'static str;

    /// 무엇을 되살릴 수 있고 무엇을 못 살리는지 **미리** 계산한다.
    ///
    /// 설계-02 §9 는 "되살릴 수 없는 항목이 있으면 복원 **실행 전에** 목록으로
    /// 고지한다" 고 요구한다. 실행한 뒤에 알려 주면 이미 늦다.
    fn plan_restore(&self, dest: &str, meta: &FileMeta) -> RestoreReport;

    /// 파일을 원래 자리에 되돌린다.
    ///
    /// `dest` 는 **컨테이너에 적힌 절대 경로 그대로**여야 한다. 이 함수는 경로를
    /// 재해석하지 않고 환경 변수를 전개하지 않는다 (불변식 R, 설계-03 §5).
    fn restore_file(
        &self,
        dest: &str,
        content: &[u8],
        meta: &FileMeta,
    ) -> Result<RestoreReport, PlatformError>;

    /// 격리할 파일을 **읽어 낸다. 아직 지우지 않는다.**
    ///
    /// 경로 하나만 받고 디렉터리를 훑지 않는다 — 이 모듈이 `read` 의 trait 을
    /// 재수출하지 않는 이유가 `remedy-apply` 의 **탐색**을 막는 것이고, 완전히
    /// 지정된 경로 하나를 여는 것은 탐색이 아니다 (불변식 P).
    fn quarantine_read(&self, path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError>;

    /// 원본을 지운다.
    ///
    /// **백업이 끝나고 디스크에 내려간 뒤에만 부른다.** 설계-03 §5 의 실패 정책이
    /// "백업 중 실패 → 즉시 중단. 아직 아무것도 파괴되지 않았다" 인 것은 이 순서를
    /// 전제로 한다.
    fn destroy_file(&self, path: &str) -> Result<(), PlatformError>;

    /// 그 자리에 아직 있는가.
    ///
    /// **재기동한 실행기가 "내가 이미 지웠나" 를 묻는 자리다.** 크래시가 파괴와
    /// 저널 기록 사이에 오면 그 Action 은 수행됐는지 알 수 없고, 실제로 가서
    /// 보는 것 말고는 답할 방법이 없다.
    ///
    /// 계획에 적힌 경로 하나를 그대로 묻는 것이므로 **탐색이 아니다** (불변식 P).
    /// 경로를 재해석하지도, 환경 변수를 전개하지도 않는다.
    fn exists(&self, path: &str) -> bool;

    // ── 레지스트리 값 (P7) ────────────────────────────────────────
    //
    // 대상 표기는 `<하이브>\<키>\<값 이름>` 이다. 계획기가 증거에서 합치는 것과
    // 같은 모양이며, **마지막 조각이 값 이름**이다. 비어 있으면 (기본) 값이다 —
    // `...\shell\open\command\` 처럼 역슬래시로 끝나는 대상이 그것이다.

    /// 레지스트리 값 하나를 **읽어 낸다. 아직 바꾸지 않는다.**
    fn registry_read(&self, _target: &str) -> Result<RegistryValueBackup, PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 레지스트리를 읽지 않습니다",
            "this backend does not read the registry",
        )))
    }

    /// 값을 지운다. **백업이 디스크에 내려간 뒤에만 부른다.**
    fn registry_delete(&self, _target: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 레지스트리를 쓰지 않습니다",
            "this backend does not write the registry",
        )))
    }

    /// 값을 쓴다.
    ///
    /// 부분 편집(`strip`)과 기본값 복원이 **같은 문을 쓴다.** 값의 출처가
    /// 다를 뿐 하는 일은 같고, 문을 둘로 나누면 한쪽만 검사받는다.
    fn registry_write(
        &self,
        _target: &str,
        _value: &RegistryValueBackup,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 레지스트리를 쓰지 않습니다",
            "this backend does not write the registry",
        )))
    }

    /// 그 값이 아직 있는가. 재기동한 실행기가 묻는 자리다.
    fn registry_exists(&self, _target: &str) -> bool {
        false
    }

    // ── 재부팅 후 검증 예약 (설계-03 §8) ──────────────────────────
    //
    // **범용 "아무 항목이나 예약" 이 아니다.** 그런 문을 열면 이 바이너리가
    // 임의의 자동실행을 심을 수 있게 되고, 그것은 우리가 지우려는 바로 그
    // 능력이다. 여기 있는 것은 `remedy verify --run <id>` 하나뿐이고 이름도
    // 고정이다.
    //
    // 설계-03 §8 의 **자기 흔적 규칙** 셋을 아래 메서드들이 나눠 진다.
    //
    // 1. 고정된 식별 가능한 이름 — [`SCHEDULED_VERIFY_NAME`]
    // 2. 검증 직후 스스로 제거 — [`cancel_scheduled_verify`] · 실행 직전의 삭제는
    //    [`VerifySite::removed_by`] 가 누가 하는지 밝힌다
    // 3. 감사 로그에 자기 항목으로 기록 — [`scheduled_verify_site`] 가 자리를
    //    밝히고 호출자(CLI)가 저널에 남긴다

    /// **이 기계에서** 재부팅 뒤 검증을 예약할 수 있는가. 아니면 그 이유.
    ///
    /// 승인 **전에** 묻는다. 계획 화면이 *"재시작하면 한 번 더 검사합니다"* 를
    /// 약속할지 사실대로 말할지를 이것이 정한다 — 예약을 시도해 보고서야 알면
    /// 이미 승인이 끝난 뒤다. 리눅스가 예약하지 못하면서 약속하던 것이 그 자리다
    /// (P12, `hexcfg-r1` 채점 5 에서 실측).
    ///
    /// **부수 효과가 없어야 한다.** 쓰기를 시험 삼아 해 보지 않는다 — 묻는 것만으로
    /// 흔적이 생기면 규칙 (2) 를 어긴다. 쓸 수 있는가는 **써 보지 않고 알 수 있는
    /// 만큼만** 잰다(리눅스는 마운트 표). 그 너머의 실패는 예약하는 순간 오류로
    /// 드러난다.
    fn verify_after_reboot_support(&self) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 재부팅 후 검증을 예약하지 않습니다",
            "this backend does not schedule verification after reboot",
        )))
    }

    /// 예약이 앉는 자리와 그것을 지우는 주체. 예약하지 않는 백엔드는 `None`.
    fn scheduled_verify_site(&self) -> Option<VerifySite> {
        None
    }

    /// 재부팅 뒤 한 번 `remedy verify` 를 돌리도록 예약한다.
    ///
    /// `exe` 는 지금 도는 바이너리의 경로다. **플랫폼이 `current_exe()` 를
    /// 스스로 부르지 않는다** — 시험이 다른 경로를 넣어 확인할 수 있어야 하고,
    /// 무엇을 예약하는지가 호출자에게 보여야 한다.
    ///
    /// # `plugin` 이 인자인 이유
    ///
    /// 이 자리는 한동안 `verify --run <id>` 만 심었다. **그 명령은 실행되지
    /// 않는다** — `verify` 는 `--plugin` 을 필수로 받고, 없으면 사용법 오류로
    /// 즉시 끝난다. RunOnce 는 콘솔 없이 돌고 OS 가 항목을 먼저 지우므로
    /// **아무 흔적도 남지 않았다** (2026-08-28 v1 점검에서 실측).
    ///
    /// 단위 시험이 이것을 놓친 이유는 **값을 쓰는지**만 쟀기 때문이다. 그 값이
    /// **실행 가능한 명령인지**는 아무도 묻지 않았다.
    ///
    /// `state_dir` 은 기본값이 아닐 때만 준다 — `verify --run` 이 그 아래에서
    /// 승인된 계획을 찾는다.
    fn schedule_verify_after_reboot(
        &self,
        _run_id: &str,
        _exe: &std::path::Path,
        _plugin: &std::path::Path,
        _state_dir: Option<&std::path::Path>,
        _lang: remedy_sdk::i18n::Lang,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 재부팅 후 검증을 예약하지 않습니다",
            "this backend does not schedule verification after reboot",
        )))
    }

    /// 그 예약을 지운다. **이미 없으면 성공이다** — Windows 는 RunOnce 항목을
    /// 실행 *직전에* 지우므로, 정상 경로에서는 이 호출이 지울 것을 찾지 못한다.
    /// 그것이 실패가 아니라 정상이다.
    ///
    /// **예약을 아예 하지 않는 백엔드도 성공이다.** 지울 것이 없다는 뜻이고, 그것이
    /// 이 함수가 바라는 상태 그 자체다. 앞서 `Unsupported` 를 내던 탓에 리눅스의
    /// **모든** `verify` 회차가 *"주의: 재평가 예약을 지우지 못했다"* 를 찍었다 —
    /// 애초에 예약하지 않는 기계에 대고 매번 하는 헛경고였다 (실측 2026-09-07).
    ///
    /// 예약하는 쪽([`Self::schedule_verify_after_reboot`])과 묻는 쪽
    /// ([`Self::scheduled_verify`])은 그대로 `Unsupported` 다. 그 둘은 *"할 수 없다"*·
    /// *"모른다"* 가 답이지만, 지우기는 **이미 그렇게 되어 있다** 가 답이다.
    fn cancel_scheduled_verify(&self) -> Result<(), PlatformError> {
        Ok(())
    }

    /// 지금 예약이 걸려 있는가. 걸려 있으면 그 명령줄.
    fn scheduled_verify(&self) -> Result<Option<String>, PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 재부팅 후 검증을 예약하지 않습니다",
            "this backend does not schedule verification after reboot",
        )))
    }

    /// 보안 제품 예외 목록 **전체**를 읽어 낸다 (설계-02 §9).
    ///
    /// # 왜 한 항목이 아니라 전체인가
    ///
    /// 백업이 부분 diff 면 복원이 "지금 목록에 이것을 더한다" 가 된다. 그런데
    /// 복원을 요청했다는 것은 **우리 판정이 틀렸다고 본다는 뜻**이고, 그렇다면
    /// 우리가 손댄 뒤의 목록을 기준으로 삼을 이유가 없다. 변경 전 목록 전체를
    /// 그대로 되돌린다.
    fn av_exclusions_read(&self) -> Result<Vec<AvExclusion>, PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 예외 목록을 읽지 않습니다",
            "this backend does not read the exclusion list",
        )))
    }

    /// 예외 목록 전체를 되돌린다. **지금 있는 것을 지우고 백업본으로 바꾼다.**
    fn av_exclusions_write(&self, _want: &[AvExclusion]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 예외 목록을 쓰지 않습니다",
            "this backend does not write the exclusion list",
        )))
    }

    // ── 파일 계열 (P7) ────────────────────────────────────────────

    /// 재부팅 때 지우도록 예약한다.
    ///
    /// 지금 잠겨 있는 파일을 다루는 유일한 방법이다. **덮어쓰지 않고 덧붙인다** —
    /// 이 큐에는 다른 설치 관리자가 예약해 둔 항목이 함께 있고, 통째로 쓰면
    /// 그것들이 사라진다.
    ///
    /// 예약은 파괴가 아니다. 그래서 이 Op 의 결과는 "지웠다" 가 아니라
    /// **"재부팅이 필요하다"** 로 보고된다.
    fn schedule_delete_on_reboot(&self, _path: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 재부팅 삭제를 예약하지 않습니다",
            "this backend does not schedule delete-on-reboot",
        )))
    }

    /// 그 경로에 걸린 재부팅 삭제 예약을 **취소한다.**
    ///
    /// # 복원이 이것을 부르는 이유
    ///
    /// 예약은 파괴가 아니라 **미뤄 둔 파괴**다. 파일을 되돌려 놓고 예약을 그대로
    /// 두면 다음 재부팅이 그것을 다시 지운다 — 사람은 복원에 성공했다고 보고
    /// 받고, 다음 날 파일이 없다. 왕복이 원본을 복원한다는 P7 의 완료 조건이
    /// 그 시점에 거짓이 된다.
    ///
    /// **되돌리는 그 경로만** 건드린다. 큐에는 다른 설치 관리자가 넣어 둔 항목이
    /// 함께 있고, 통째로 비우면 그것들이 사라진다.
    ///
    /// 예약이 없으면 성공이다. "없앨 것이 없었다" 와 "없앴다" 는 결과가 같다.
    fn cancel_delete_on_reboot(&self, _path: &str) -> Result<(), PlatformError> {
        Ok(())
    }

    /// 대체 데이터 스트림 하나를 읽어 낸다. **호스트 파일은 건드리지 않는다.**
    ///
    /// 대상 표기는 `<경로>:<스트림 이름>` 이다.
    fn stream_read(&self, _target: &str) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 대체 스트림을 읽지 않습니다",
            "this backend does not read alternate streams",
        )))
    }

    /// 대체 데이터 스트림 하나를 지운다. 호스트 파일은 남는다.
    fn stream_delete(&self, _target: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 대체 스트림을 지우지 않습니다",
            "this backend does not delete alternate streams",
        )))
    }

    /// 바로가기의 **인자만** 지운다. 대상·작업 폴더·아이콘은 그대로다.
    ///
    /// 변환은 순수 함수([`strip_shortcut_arguments`])이고 파일 읽기·쓰기만
    /// 여기서 한다. "임의 바이트를 임의 경로에 쓴다" 는 원시 동작을 경계 밖으로
    /// 내보내지 않기 위해서다 — 그것이 있으면 이 trait 이 막는 것이 없어진다.
    ///
    /// # `expect` — 계획이 본 인자
    ///
    /// **수집과 실행 사이에 파일이 바뀔 수 있다.** 그 사이에 사용자가 정당한
    /// 인자를 붙였다면, 지금 있는 것을 그냥 떼는 것은 계획에 없는 파괴다.
    /// `text_config.remove_line` 이 줄 번호와 내용을 둘 다 맞춰 보는 것과 같은
    /// 이유다 — 어긋나면 아무것도 하지 않고 실패한다.
    ///
    /// 인자가 이미 없으면 목표 상태가 이루어진 것이므로 성공이다(재기동).
    fn shortcut_strip_args(&self, _path: &str, _expect: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 바로가기를 고치지 않습니다",
            "this backend does not edit shortcuts",
        )))
    }

    // ── 설정 계열 (P7) ────────────────────────────────────────────

    /// 지울 줄을 **읽어 낸다. 아직 지우지 않는다.**
    ///
    /// 줄 번호는 사람이 보는 것과 같은 1부터다 (수집기와 같은 규약).
    fn text_line_read(&self, _path: &str, _line_no: u32) -> Result<String, PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 줄을 읽지 않습니다",
            "this backend does not read lines",
        )))
    }

    /// 줄 하나를 지운다. **줄 번호와 내용이 둘 다 맞아야 한다.**
    ///
    /// 번호만 보면 수집과 실행 사이에 파일이 바뀌었을 때 **엉뚱한 줄**을 지운다.
    /// 내용만 보면 같은 줄이 여럿일 때 어느 것인지 정해지지 않는다. 둘 다
    /// 요구하면 파일이 달라졌을 때 **아무것도 하지 않고 실패**한다 — 설정
    /// 파일에서 그것이 옳은 실패다.
    fn text_line_remove(
        &self,
        _path: &str,
        _line_no: u32,
        _expect: &str,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 줄을 지우지 않습니다",
            "this backend does not remove lines",
        )))
    }

    /// 지웠던 줄을 되돌린다.
    fn text_line_restore(
        &self,
        _path: &str,
        _line_no: u32,
        _line: &str,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 줄을 되돌리지 않습니다",
            "this backend does not restore lines",
        )))
    }

    /// 구조적 설정에서 키 하나를 지운다.
    fn structured_remove_key(&self, _path: &str, _key_path: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 설정을 고치지 않습니다",
            "this backend does not edit config files",
        )))
    }

    /// 구조적 설정의 키에 값을 쓴다. **값의 출처는 카탈로그뿐이다** (설계-03 §2).
    fn structured_set_key(
        &self,
        _path: &str,
        _key_path: &str,
        _value: &str,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 설정을 고치지 않습니다",
            "this backend does not edit config files",
        )))
    }

    // ── 디렉터리 (P7) ─────────────────────────────────────────────

    /// 이 자리가 디렉터리인가. **백업 종류를 대상의 모양이 고른다** —
    /// `browser_ext.remove` 는 디렉터리(Chromium)일 수도 파일(`.xpi`)일 수도
    /// 있고, 그것을 Op 이름으로 추측하면 카탈로그와 갈라진다.
    fn is_dir(&self, _path: &str) -> bool {
        false
    }

    /// 디렉터리 하나를 통째로 **읽어 낸다. 아직 지우지 않는다.**
    ///
    /// 돌려주는 것은 `(본문을 이어 붙인 바이트, 목차)` 다. 컨테이너 엔트리는
    /// 하나가 하나이므로(Action 하나 = 엔트리 하나) 여러 파일을 한 엔트리에
    /// 담아야 하고, 목차가 없으면 되돌릴 때 어디서 끊을지 알 수 없다.
    /// 형식은 [`DirIndex`] 를 보라.
    fn dir_read(&self, _path: &str) -> Result<(Vec<u8>, DirIndex), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 디렉터리를 읽지 않습니다",
            "this backend does not read directories",
        )))
    }

    /// 디렉터리와 그 하위를 지운다. **백업이 디스크에 내려간 뒤에만 부른다.**
    fn dir_destroy(&self, _path: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 디렉터리를 지우지 않습니다",
            "this backend does not delete directories",
        )))
    }

    /// 담아 둔 디렉터리를 그 자리에 되돌린다.
    fn dir_restore(
        &self,
        _path: &str,
        _content: &[u8],
        _index: &DirIndex,
    ) -> Result<RestoreReport, PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 디렉터리를 되돌리지 않습니다",
            "this backend does not restore directories",
        )))
    }

    // ── 예약 작업 (P7) ────────────────────────────────────────────
    //
    // 대상 표기는 **등록 경로**다 (`\Microsoft\Windows\Locust`). 정의 파일
    // 경로가 아닌 이유는 두 가지다 — 정의 파일은 `%SystemRoot%\System32\Tasks`
    // 아래에 있어 보호 목록에 걸리고, 작업의 정체성은 파일이 아니라 등록
    // 경로이기 때문이다 (레지스트리 값에서 대상이 `<하이브>\<키>\<값>` 인 것과
    // 같다).

    /// 정의를 **읽어 낸다. 아직 바꾸지 않는다.**
    ///
    /// 두 번째 값은 본문 밖에 있는 것이다 — systemd 의 활성화 링크가 거기 실린다
    /// ([`PersistenceIndex`]). Windows 는 정의 XML 하나가 전부라 비어 있다.
    fn persistence_read(&self, _id: &str) -> Result<(Vec<u8>, PersistenceIndex), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 지속성 항목을 읽지 않습니다",
            "this backend does not read persistence entries",
        )))
    }

    /// 그 작업이 아직 등록돼 있는가. 재기동한 실행기가 묻는 자리다.
    fn persistence_exists(&self, _id: &str) -> bool {
        false
    }

    /// 비활성으로 바꾼다. 정의는 남는다.
    ///
    /// `at` 은 항목이 **파일 안의 줄**일 때만 온다 (cron). 그때는 번호만으로
    /// 고치지 않고 내용까지 대조한다 — 수집과 실행 사이에 파일이 바뀌면 그
    /// 번호가 다른 내용일 수 있고, 엉뚱한 줄을 주석 처리하면 **정상 작업이
    /// 조용히 멈춘다.**
    fn persistence_disable(&self, _id: &str, _at: Option<&LineAt>) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 지속성 항목을 고치지 않습니다",
            "this backend does not edit persistence entries",
        )))
    }

    /// 등록을 지운다. `at` 은 [`Self::persistence_disable`] 과 같다.
    fn persistence_delete(&self, _id: &str, _at: Option<&LineAt>) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 지속성 항목을 지우지 않습니다",
            "this backend does not delete persistence entries",
        )))
    }

    /// 담아 둔 정의로 다시 등록한다.
    ///
    /// **곁가지까지 되돌린다.** 유닛 파일만 쓰고 링크를 빠뜨리면 그 유닛은
    /// 꺼진 채로 돌아오고, 사용자는 복원이 됐다고 믿는다.
    fn persistence_restore(
        &self,
        _id: &str,
        _content: &[u8],
        _index: &PersistenceIndex,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 지속성 항목을 되돌리지 않습니다",
            "this backend does not restore persistence entries",
        )))
    }

    // ── 신뢰 저장소의 인증서 파일 (P12) ───────────────────────
    //
    // Windows 인증서는 레지스트리 키 하나라 아래 `registry_key_*` 를 쓴다.
    // **Linux 인증서는 파일이고, 파일을 지워도 신뢰가 사라지지 않는다.**
    //
    // 실측(WSL Ubuntu 24.04): `/usr/share/ca-certificates/**.crt` 를 지워도
    // `/etc/ssl/certs/ca-certificates.crt` 번들에 그 인증서가 그대로 남는다.
    // TLS 검사는 그 번들을 읽는다 — 즉 **파일 삭제만으로는 치료가 되지 않는다.**
    // 그래서 이 가족이 따로 있다. `destroy_file` 로 대신할 수 없다.
    //
    // 어느 문을 쓸지는 `service_*`·`persistence_*` 와 같은 규칙으로 고른다:
    // **대상의 모양**이 고른다 (설계-09 P12 결정 6과 같은 원리).

    /// 인증서 파일을 **읽어 낸다. 아직 지우지 않는다.**
    ///
    /// 목차가 없다 — 인증서 파일은 바이트가 전부다. 소유자·모드는 배포판이
    /// 정하는 값(`root:root 0644`)이고, 되살릴 때 `update-ca-certificates`
    /// 가 다시 만드는 것은 번들이지 이 파일의 메타데이터가 아니다.
    fn cert_read(&self, _path: &str) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 인증서 파일을 읽지 않습니다",
            "this backend does not read certificate files",
        )))
    }

    /// 인증서가 그 자리에 있는가.
    fn cert_exists(&self, _path: &str) -> bool {
        false
    }

    /// 인증서 파일을 지우고 **신뢰 저장소를 다시 만든다.**
    ///
    /// 둘이 한 연산인 이유는 위 주석에 있다 — 파일만 지우면 번들에 남는다.
    fn cert_delete(&self, _path: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 인증서 파일을 지우지 않습니다",
            "this backend does not delete certificate files",
        )))
    }

    /// 인증서 파일을 되돌리고 **신뢰 저장소를 다시 만든다.**
    ///
    /// 지울 때와 대칭이다. 파일만 되돌리면 번들에 없는 채로 남아 **복원했다는
    /// 보고가 사실이 아니게 된다.**
    fn cert_restore(&self, _path: &str, _content: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 인증서 파일을 되돌리지 않습니다",
            "this backend does not restore certificate files",
        )))
    }

    // ── 레지스트리 키 하위 트리 (P8) ──────────────────────────
    //
    // 값 하나가 아니라 **키와 그 아래 전부**다. `registry.delete_key` 만이
    // 아니라 `cert_store.remove`·`service.*` 도 이 문을 쓴다 — 인증서는
    // `SystemCertificates\<저장소>\Certificates\<지문>` 키 하나이고, 서비스
    // 정의는 `Services\<이름>` 키 하나다. 셋이 같은 기계를 쓰면 백업·복원의
    // 정확성을 한 곳에서만 지키면 된다.

    /// 키와 그 하위 전부를 **읽어 낸다. 아직 지우지 않는다.**
    ///
    /// 돌려주는 것은 `(값들을 이어 붙인 바이트, 목차)` 다 — [`DirIndex`] 와
    /// 같은 이유로 같은 모양이다.
    fn registry_key_read(&self, _key: &str) -> Result<(Vec<u8>, RegKeyIndex), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 레지스트리 키를 읽지 않습니다",
            "this backend does not read registry keys",
        )))
    }

    /// 키와 그 하위를 지운다. **백업이 디스크에 내려간 뒤에만 부른다.**
    fn registry_key_delete(&self, _key: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 레지스트리 키를 지우지 않습니다",
            "this backend does not delete registry keys",
        )))
    }

    /// 담아 둔 키를 그 자리에 되돌린다.
    fn registry_key_restore(
        &self,
        _key: &str,
        _content: &[u8],
        _index: &RegKeyIndex,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 레지스트리 키를 되돌리지 않습니다",
            "this backend does not restore registry keys",
        )))
    }

    /// 그 키가 아직 있는가. 재기동한 실행기가 묻는 자리다.
    fn registry_key_exists(&self, _key: &str) -> bool {
        false
    }

    // ── 프로세스 (P8) ─────────────────────────────────────────

    /// 술어가 지목하는 프로세스를 찾는다.
    ///
    /// # 왜 이것만이 실행기의 열거인가
    ///
    /// 설계-04 §1 은 `apply` 가 임의 열거 능력을 갖지 못하게 한다. 그런데
    /// **PID 는 계획에 들어갈 자리가 없다** — 계획 시점과 실행 시점 사이에
    /// 바뀌기 때문이다(설계-03 §1). 그래서 대상은 술어로 고정되고, 그 술어를
    /// 해소하는 이 한 문만 열어 둔다. 인자로 술어를 받고 맞는 것만 돌려주므로
    /// "아무거나 열거한다" 가 되지 않는다.
    fn processes_matching(&self, _p: &KillPredicate) -> Result<Vec<Target>, PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 프로세스를 찾지 않습니다",
            "this backend does not look for processes",
        )))
    }

    /// 지목된 프로세스들의 **자손**을 같은 스냅샷에서 찾는다.
    ///
    /// `include_descendants: true` 일 때만 불린다 (설계-03 §2).
    ///
    /// # 왜 실행기가 아니라 백엔드가 걷는가
    ///
    /// 부모 지도와 대상의 세부는 **같은 스냅샷에서** 나와야 한다. 실행기가
    /// 부모 목록을 따로 묻고 세부를 또 묻으면 그 사이에 목록이 바뀌고, 지도와
    /// 세부가 서로 다른 세상을 가리킨다.
    ///
    /// # 못 하면 빈 목록이 아니라 오류다
    ///
    /// 걷지 못하는 백엔드가 `Ok(vec![])` 을 돌려주면 계획이 켠
    /// `include_descendants` 가 **조용히 무시된다** — "자손이 없다" 와 "자손을
    /// 못 봤다" 가 같은 값이 된다 (설계-00 §5-1).
    fn process_descendants(&self, _roots: &[u32]) -> Result<Vec<Target>, PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 프로세스 계보를 걷지 않습니다",
            "this backend does not walk process lineage",
        )))
    }

    /// 지목된 프로세스를 **한 번에** 종료한다. 되돌릴 수 없다.
    ///
    /// # 왜 하나씩이 아닌가
    ///
    /// 설계-03 §2 가 고정한 실행 규칙은 `해소 → 전부 정지 → 전부 종료 → 재평가`
    /// 다. 하나씩 죽이면 워치독 쌍에서 진다 — A 를 죽이는 사이 B 가 A 를
    /// 되살린다. **집합을 한 번에 넘기는 것만으로도 창이 좁아진다.** 하나마다
    /// 문을 여는 것과 한 번 여는 것의 차이가 그 창이다.
    ///
    /// 정지(suspend)는 이 코어가 하지 못한다 — 설계-01 D13 이 그 강등을
    /// 결정했고, 실행기가 그 사실을 **저널에 적는다.** 없는 능력을 코드가
    /// 조용히 건너뛰면 감사에서 규칙이 다 돈 것처럼 읽힌다.
    fn process_kill(&self, _pids: &[u32]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 프로세스를 종료하지 않습니다",
            "this backend does not terminate processes",
        )))
    }

    // ── 서비스 (P8) ───────────────────────────────────────────
    //
    // 대상 표기는 **정의 키**다 (`HKLM\SYSTEM\CurrentControlSet\Services\<이름>`).
    // 서비스 이름만 적지 않는 이유는 예약 작업과 같다 — 보호 목록 대조와 G6 의
    // 상한 판정이 모양을 보고 갈리고, 이름 하나짜리 문자열은 그 어느 쪽에도
    // 걸리지 않는다.

    /// 지금 돌고 있는가. `service.stop` 의 멱등성이 여기 걸린다.
    fn service_running(&self, _target: &str) -> bool {
        false
    }

    /// 정지시킨다. **정의는 남는다.**
    fn service_stop(&self, _target: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 서비스를 정지시키지 않습니다",
            "this backend does not stop services",
        )))
    }

    /// 시작 유형을 `disabled` 로 바꾼다.
    fn service_disable(&self, _target: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 서비스를 고치지 않습니다",
            "this backend does not edit services",
        )))
    }

    /// 등록을 지운다.
    fn service_delete(&self, _target: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 서비스를 지우지 않습니다",
            "this backend does not delete services",
        )))
    }

    /// 실패 시 복구 동작을 지운다.
    ///
    /// **이것을 남긴 채 프로세스를 죽이면 SCM 이 되살린다** — 그래서 이 Op 은
    /// 실행 순서 1단계다 (설계-03 §2).
    fn service_clear_recovery(&self, _target: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 복구 동작을 지우지 않습니다",
            "this backend does not clear recovery actions",
        )))
    }

    // ── 시스템 복원 지점 (P8) ─────────────────────────────────

    /// 이 디렉터리 안에 **신뢰 서명된 파일**이 있는가.
    ///
    /// # 왜 확인할 수 없으면 거부인가
    ///
    /// 재귀 삭제가 노리는 실패는 "악성코드가 정상 프로그램 폴더에 떨어졌고,
    /// 그 폴더를 통째로 지워 정상 프로그램을 부수는 것" 이다. 서명은 그것을
    /// 가르는 신호다.
    ///
    /// **이 기본 구현에는 서명을 검증할 수단이 없다.** Windows 백엔드는
    /// `remedy-wintrust` 로 이 함수를 덮어쓰지만(`windows.rs`), 그것이 없는
    /// 백엔드는 판정을 세울 수 없다. `FileRecord.signature` 가 같은 구분을
    /// 쓴다 — 수집기가 채우되 **`None` 을 "서명 없음" 으로 읽으면 서명된
    /// 악성코드 예외가 조용히 무력해진다**고 적어 두었다. 같은 논리가 여기에도
    /// 적용된다 — "확인하지 못했다" 를 "없다" 로 읽으면 이 가드는 존재하지
    /// 않는 것이다.
    ///
    /// 그래서 기본값은 성공이 아니라 **오류**다. 실행기가 그것을 거부로 옮긴다.
    ///
    /// # 한 번 훑으며 둘을 본다
    ///
    /// 신뢰 서명(조건 3)과 **규모 상한**(설계-03 §4 — 하위 항목 수·깊이)을
    /// 함께 판정한다. 두 번 훑으면 그 사이에 트리가 바뀔 수 있고 I/O 도 두
    /// 배다.
    ///
    /// 상한을 넘으면 `Err` 다. 세다가 멈췄으므로 정확한 수는 모르고 알 필요도
    /// 없다 — **지울 수 없다는 것만 알면 된다.**
    fn survey_recursive_target(
        &self,
        _dir: &str,
        _max_children: u32,
        _max_depth: u32,
    ) -> Result<Vec<String>, PlatformError> {
        // **리눅스는 이 메서드를 구현하지 않는다.** 그래서 이 문구가 실제로
        // `refusal_before_backup` 의 사유에 실려 종료 코드 5 로 나간다.
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 코어에는 서명을 검증할 수단이 없습니다",
            "this core has no way to verify signatures",
        )))
    }

    /// 복원 지점을 만들어 **본다.**
    ///
    /// **대체재가 아니라 추가 안전망이다** (설계-00 §5-2). 실패해도 치료는
    /// 진행된다 — 격리 컨테이너가 본래의 되돌리기 수단이고, 복원 지점은 그
    /// 위에 얹는 것이다. 실패를 치명적으로 다루면 복원 지점을 못 만드는
    /// 환경(서비스 꺼짐·보호 비활성)에서 치료 자체가 막힌다.
    fn create_restore_point(&self, _label: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(remedy_sdk::i18n::t(
            "이 백엔드는 복원 지점을 만들지 않습니다",
            "this backend does not create restore points",
        )))
    }
}

/// 담아 둔 레지스트리 키의 목차.
///
/// [`DirIndex`] 와 같은 이유로 같은 모양이다 — Action 하나에 엔트리 하나이므로
/// 하위 전체가 엔트리 **하나**에 들어가고, 어디서 끊는지를 목차가 말한다.
/// 본문은 `values` 순서대로 이어 붙인 값 바이트다.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegKeyIndex {
    /// 루트 기준 상대 키 경로. 빈 문자열이 루트 자신이다.
    ///
    /// **빈 하위 키도 적는다.** 값이 하나도 없는 키는 값 목록에 흔적을 남기지
    /// 않고, 그러면 복원된 트리가 원래 모습이 아니다.
    pub keys: Vec<String>,
    pub values: Vec<RegValueEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegValueEntry {
    /// 루트 기준 상대 키 경로. 빈 문자열이면 루트 자신의 값이다.
    pub key: String,
    /// 값 이름. 빈 문자열이 (기본) 값이다.
    pub name: String,
    pub vtype: u32,
    pub size: u64,
}

/// 상대 키 경로가 **루트 안에 머무는가** (불변식 R).
///
/// 목차는 컨테이너에서 온다. 변조되면 `..\..\..` 하나로 임의 키 쓰기가 되고,
/// 그것은 복원이 아니라 설치다. 헤더 AAD 가 변조를 잡지만 탐지에만 기대지 않는다.
pub fn reg_rel_is_contained(rel: &str) -> bool {
    if rel.is_empty() {
        return true; // 루트 자신.
    }
    if rel.starts_with('\\') || rel.ends_with('\\') || rel.contains('/') {
        return false;
    }
    rel.split('\\')
        .all(|p| !p.is_empty() && p != "." && p != "..")
}

/// 무엇을 종료할 것인가. **PID 가 아니라 술어다** (설계-03 §1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KillPredicate {
    /// 이미지 경로 완전 일치 (대소문자 무시).
    pub image_path: Option<String>,
    /// 명령줄 부분 일치.
    pub cmdline_contains: Option<String>,
}

impl KillPredicate {
    /// 술어가 비어 있는가. **비면 모든 프로세스가 맞는다.**
    pub fn is_empty(&self) -> bool {
        self.image_path.is_none() && self.cmdline_contains.is_none()
    }
}

/// 술어가 실제로 지목한 프로세스 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub pid: u32,
    pub image_path: String,
    pub cmdline: String,
}

/// 지속성 항목의 **되돌릴 때 필요한 곁가지** (설계-09 P12 결정 5).
///
/// # 왜 본문만으로는 안 되는가
///
/// Windows 예약 작업은 정의 XML 하나가 그 작업의 전부라 곁가지가 없다. systemd 는
/// 다르다 — **활성화는 유닛 파일 안에 없고 `<target>.wants/` 아래의 링크다.**
/// 유닛 파일만 되살리면 그 유닛은 **꺼진 채로** 돌아온다.
///
/// [`DirIndex`] 가 디렉터리 백업의 목차인 것과 같은 자리이고, 같은 길로 흐른다 —
/// `persistence_read` 가 내고 격리 엔트리의 `meta` 에 실려 `persistence_restore`
/// 로 돌아온다.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistenceIndex {
    /// 이 항목을 가리키던 활성화 링크. 절대 경로다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
}

/// 지속성 항목이 **파일 안의 줄**일 때 그 자리 (cron).
///
/// # 번호와 내용을 함께 든다
///
/// 번호만이면 수집과 실행 사이에 파일이 바뀌었을 때 엉뚱한 줄을 고치고, 내용만
/// 이면 같은 줄이 여럿일 때 정해지지 않는다 — `text_config.remove_line` 과 같은
/// 규약이다 (설계-03 §2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineAt {
    pub line_no: u32,
    pub line: String,
}

/// 담아 둔 디렉터리의 목차.
///
/// # 왜 별도 형식이 필요한가
///
/// 컨테이너는 **Action 하나에 엔트리 하나**다. 디렉터리를 파일마다 엔트리로
/// 쪼개면 저널의 `seq → entry_id` 대응이 1:N 이 되고, 복원 화면의 `--entry`
/// 선택과 "이 Action 의 백업" 이라는 개념이 함께 무너진다. 그래서 하위 전체를
/// 엔트리 **하나**에 담고, 어디서 끊는지를 이 목차가 말한다.
///
/// 본문은 `files` 순서대로 이어 붙인 바이트다. base64 로 감싸지 않는 이유는
/// 33% 가 그대로 격리소 용량이 되기 때문이고, 목차만 JSON 이면 충분하다.
///
/// `dirs` 가 따로 있는 이유: **빈 디렉터리는 파일 목록에 흔적을 남기지 않는다.**
/// 확장의 `_metadata` 처럼 비어 있는 자리가 복원에서 사라지면 그 확장은 원래
/// 모습이 아니다.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirIndex {
    /// 루트 기준 상대 경로. 구분자는 언제나 `/` — 백업한 OS 와 되돌리는 OS 가
    /// 다를 수 있고, 그때 `\` 는 파일 이름의 일부가 된다.
    pub dirs: Vec<String>,
    pub files: Vec<DirEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirEntry {
    pub rel: String,
    pub size: u64,
    #[serde(default)]
    pub meta: FileMeta,
}

/// 이 대상이 예약 작업의 등록 경로인가.
///
/// 파일 경로(`C:\...`)·UNC(`\\서버\공유`)·레지스트리(`HKLM\...`)와 겹치지 않게
/// **역슬래시 하나로 시작**하는 것만 작업으로 본다.
pub fn is_task_target(target: &str) -> bool {
    target.starts_with('\\') && !target.starts_with("\\\\")
}

/// 작업 이름이 안전한가. 문제가 있으면 그 이유.
///
/// # 두 가지를 막는다
///
/// **경로 탈출** — 등록 경로는 `%SystemRoot%\System32\Tasks\<id>` 로 풀린다.
/// `..` 이 섞이면 그것은 임의 파일 읽기이고, 되돌릴 때는 임의 파일 쓰기다.
///
/// **스위치 주입** — `schtasks.exe` 의 스위치 문자는 `/` 다. 이름에 `/` 가 있으면
/// `/TN "\a /Delete /TN \b"` 같은 값이 인자 하나로 넘어가도 CRT 파싱을 거친 뒤
/// 스위치로 읽힐 여지가 남는다. 이름에 `/` 가 정당하게 들어갈 일은 없으므로
/// 통째로 막는 편이 확실하다.
pub fn task_id_problem(id: &str) -> Option<&'static str> {
    use remedy_sdk::i18n::t;
    if !is_task_target(id) {
        return Some(t(
            "등록 경로는 역슬래시 하나로 시작해야 합니다",
            "a registration path must start with a single backslash",
        ));
    }
    if id.len() < 2 || id.len() > 260 {
        return Some(t(
            "등록 경로의 길이가 범위를 벗어납니다",
            "the registration path length is out of range",
        ));
    }
    if id.contains('/') {
        return Some(t(
            "등록 경로에 '/' 가 있습니다 — 스위치로 읽힐 수 있습니다",
            "the registration path contains '/' and could be read as a switch",
        ));
    }
    if id.contains('"') || id.contains('\0') || id.contains('%') {
        return Some(t(
            "등록 경로에 따옴표·NUL·환경변수 토큰이 있습니다",
            "the registration path contains a quote, NUL, or environment token",
        ));
    }
    if id.chars().any(|c| c.is_control()) {
        return Some(t(
            "등록 경로에 제어문자가 있습니다",
            "the registration path contains a control character",
        ));
    }
    let segs: Vec<&str> = id.trim_start_matches('\\').split('\\').collect();
    if segs.iter().any(|s| s.is_empty() || *s == "." || *s == "..") {
        return Some(t(
            "등록 경로에 빈 조각이나 '..' 가 있습니다",
            "the registration path has an empty segment or '..'",
        ));
    }
    // 후행 공백·점은 Windows 가 파일 이름에서 말없이 떼어 낸다. 그러면 우리가
    // 지목한 것과 실제로 열리는 것이 달라진다.
    if segs
        .iter()
        .any(|s| s.ends_with(' ') || s.ends_with('.') || s.starts_with(' '))
    {
        return Some(t(
            "등록 경로 조각의 앞뒤에 공백이나 점이 있습니다",
            "a registration path segment has a leading or trailing space or dot",
        ));
    }
    None
}

/// 상대 경로가 **루트 안에 머무는가.**
///
/// 목차는 컨테이너에서 온다. 컨테이너가 변조되면 `../../..` 하나로 임의 경로
/// 쓰기가 되고, 그것은 복원이 아니라 설치다 (불변식 R). 헤더 AAD 가 변조를
/// 잡지만 **탐지에만 기대지 않는다.**
pub fn rel_is_contained(rel: &str) -> bool {
    if rel.is_empty() || rel.starts_with('/') || rel.contains('\\') || rel.contains(':') {
        return false;
    }
    rel.split('/')
        .all(|p| !p.is_empty() && p != "." && p != "..")
}

/// 줄을 **종단 문자까지 그대로** 갈라 놓는다.
///
/// `lines()` 는 `\r\n` 과 `\n` 을 똑같이 버려서, 지우고 다시 이으면 파일 전체의
/// 줄 끝이 바뀐다. 설정 파일에서 그것은 우리가 손대지 않은 줄까지 바꾼 것이다.
fn split_keeping_endings(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut start = 0usize;
    for (i, c) in b.iter().enumerate() {
        if *c == b'\n' {
            out.push(&text[start..=i]);
            start = i + 1;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// 그 번호의 줄 내용. 줄 끝과 양끝 공백은 뺀다 — 수집기가 담는 것이 그것이다.
pub fn nth_line(text: &str, line_no: u32) -> Option<String> {
    let idx = (line_no as usize).checked_sub(1)?;
    split_keeping_endings(text)
        .get(idx)
        // **줄 끝만 뗀다. 들여쓰기는 남긴다** (2026-10-27 · C-4 측정).
        //
        // 이 값은 격리 컨테이너에 담겨 복원에 그대로 쓰인다
        // (`remedy-apply` 의 `EntryKind::TextLine` 가지 — 그 주석이 *"줄을
        // 그대로 들고 있다"* 고 적은 자리다). 양끝을 다듬으면 **되돌린 줄이
        // 원본과 다른 바이트**가 된다. 설정 파일에서는 모양만 어긋나지만,
        // C-5 가 소스 파일을 이 Op 의 사거리에 넣은 뒤로는 되돌린 `.php` 가
        // 원본과 달라진다 — 실측에서 그렇게 나왔다.
        //
        // 줄 끝을 떼는 것은 남긴다: [`insert_text_line`] 이 **파일이 쓰는 줄
        // 끝을 붙이므로** 여기서 들고 있으면 두 번 들어간다.
        //
        // **대조는 이 값이 아니라 계획의 값으로 한다.** `remove_text_line` 은
        // 양쪽을 다듬어 견주므로(수집기가 담는 것이 다듬은 줄이다) 이 변화가
        // 룰이 보는 `text_config.line` 이나 그 대조를 건드리지 않는다.
        .map(|l| l.trim_end_matches(['\r', '\n']).to_string())
}

/// 텍스트에서 줄 하나를 뺀 결과. 번호나 내용이 어긋나면 `None`.
///
/// 비교는 **양끝 공백과 줄 끝을 뺀 내용**으로 한다. 수집기가 담는 것이 그것이고,
/// 편집기가 줄 끝 공백을 건드리는 일은 흔하다.
pub fn remove_text_line(text: &str, line_no: u32, expect: &str) -> Option<String> {
    let lines = split_keeping_endings(text);
    let idx = (line_no as usize).checked_sub(1)?;
    let got = lines.get(idx)?;
    if got.trim_end_matches(['\r', '\n']).trim() != expect.trim() {
        return None;
    }
    let mut out = String::with_capacity(text.len() - got.len());
    for (i, l) in lines.iter().enumerate() {
        if i != idx {
            out.push_str(l);
        }
    }
    Some(out)
}

/// 뺐던 줄을 그 자리에 되돌린다.
///
/// 파일이 그만큼 길지 않으면 **끝에 붙인다.** 복원 시점의 파일이 백업 시점과
/// 다를 수 있고, 그때 없는 자리에 억지로 넣는 것보다 끝에 두는 편이 낫다 —
/// 줄이 사라지는 것보다는 자리가 다른 편이 낫기 때문이다.
pub fn insert_text_line(text: &str, line_no: u32, line: &str) -> String {
    let lines = split_keeping_endings(text);
    // 파일이 쓰는 줄 끝을 따른다. 하나도 없으면 `\n`.
    let ending = if lines.iter().any(|l| l.ends_with("\r\n")) {
        "\r\n"
    } else {
        "\n"
    };
    let idx = (line_no as usize).saturating_sub(1).min(lines.len());
    let mut out = String::with_capacity(text.len() + line.len() + 2);
    for l in lines.iter().take(idx) {
        out.push_str(l);
    }
    // 앞 줄이 줄 끝 없이 끝났다면(파일 마지막 줄) 먼저 끊어 준다.
    if !out.is_empty() && !out.ends_with('\n') {
        out.push_str(ending);
    }
    out.push_str(line.trim_end_matches(['\r', '\n']));
    out.push_str(ending);
    for l in lines.iter().skip(idx) {
        out.push_str(l);
    }
    out
}

/// 점으로 이은 키 경로를 따라간다. 배열은 숫자 조각이다 (수집기의 `flatten` 과
/// 같은 규약).
fn json_walk<'a>(
    v: &'a mut serde_json::Value,
    parts: &[&str],
) -> Option<&'a mut serde_json::Value> {
    let mut cur = v;
    for p in parts {
        cur = match cur {
            serde_json::Value::Object(m) => m.get_mut(*p)?,
            serde_json::Value::Array(a) => a.get_mut(p.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// JSON 에서 키 하나를 지운 텍스트. 없으면 `None`.
///
/// **파싱해서 다시 쓴다.** 들여쓰기와 키 순서가 바뀌므로 백업은 값이 아니라
/// **파일 원본 전체**다 (설계-02 §9). 그래야 복원이 바이트로 정확하다.
pub fn json_remove_key(text: &str, key_path: &str) -> Option<String> {
    let mut v: serde_json::Value = serde_json::from_str(text).ok()?;
    let parts: Vec<&str> = key_path.split('.').collect();
    let (last, parents) = parts.split_last()?;
    let holder = json_walk(&mut v, parents)?;
    match holder {
        serde_json::Value::Object(m) => m.remove(*last).map(|_| ())?,
        // 배열에서 원소를 빼면 **뒤 원소의 색인이 전부 밀린다.** 같은 파일의
        // 다른 Action 이 그 색인을 가리키고 있으면 엉뚱한 것을 지운다.
        serde_json::Value::Array(_) => return None,
        _ => return None,
    }
    serde_json::to_string_pretty(&v).ok()
}

/// JSON 의 키에 문자열 값을 쓴다. 그 자리가 없으면 `None` — **만들지 않는다.**
pub fn json_set_key(text: &str, key_path: &str, value: &str) -> Option<String> {
    let mut v: serde_json::Value = serde_json::from_str(text).ok()?;
    let parts: Vec<&str> = key_path.split('.').collect();
    let slot = json_walk(&mut v, &parts)?;
    *slot = serde_json::Value::String(value.to_string());
    serde_json::to_string_pretty(&v).ok()
}

/// `.lnk` 에서 인자를 뺀 바이트. 인자가 없으면 `None` (할 일이 없다).
///
/// # 왜 순수 함수인가
///
/// 이 변환이 틀리면 바로가기가 통째로 깨진다. 파일을 만들지 않고 잴 수 있어야
/// 실패 사례를 시험으로 남길 수 있다.
///
/// # 구조
///
/// 헤더(0x4C) 뒤에 IDList·LinkInfo 가 선택적으로 오고, 그 뒤 **StringData 가
/// 고정 순서**로 온다 (NAME · RELATIVE_PATH · WORKING_DIR · ARGUMENTS ·
/// ICON_LOCATION). 하나를 건너뛰면 그 뒤가 전부 밀리므로 순서대로 걸어가
/// 인자 항목의 시작과 끝을 찾고, 그 구간을 들어낸 뒤 플래그 비트를 끈다.
/// `.desktop` 의 `Exec=` 를 실행 파일과 인자로 가른다.
///
/// # 필드 코드를 인자로 세지 않는다
///
/// XDG 는 `%f`·`%U`·`%i` 같은 자리표시자를 정의한다 — 실행할 때 파일 이름 등으로
/// 치환되는 것이지 **실제 인자가 아니다.** 담아 두면 룰이 `args contains "%"` 로
/// 잡히고, 인자를 지우는 Op 이 그것까지 지운다.
///
/// # 왜 쓰기 경계에 있는가
///
/// 한동안 이 규칙이 **수집기와 쓰기 백엔드 두 곳에** 따로 적혀 있었다. 수집기가
/// "인자" 라고 담은 것과 실행기가 "인자" 라고 떼는 것이 갈라지면, 계획이 본
/// 것과 실행이 하는 것이 조용히 달라진다 — 그리고 2026-09-06 에 계획이 그
/// 값을 담기 시작하면서 그 둘이 **같아야만 하는 값**이 됐다.
pub fn split_exec(exec: &str) -> (String, String) {
    let mut it = exec.split_whitespace();
    let cmd = it.next().unwrap_or("").to_string();
    let args: Vec<&str> = it
        .filter(|a| !(a.len() == 2 && a.starts_with('%')))
        .collect();
    (cmd, args.join(" "))
}

/// `.desktop` 본문에서 `[Desktop Entry]` 의 `Exec=` 인자만 뽑는다.
///
/// `[Desktop Action Foo]` 의 `Exec=` 는 그 동작의 것이지 항목의 것이 아니다 —
/// 수집기와 같은 판단이다.
pub fn desktop_exec_args(text: &str) -> Option<String> {
    let mut in_entry = false;
    for raw in text.lines() {
        let line = raw.trim_start();
        if line.starts_with('[') && line.ends_with(']') {
            in_entry = line.eq_ignore_ascii_case("[Desktop Entry]");
        } else if in_entry {
            if let Some(v) = line.strip_prefix("Exec=") {
                return Some(split_exec(v).1);
            }
        }
    }
    None
}

/// 계획이 본 인자와 지금 파일의 인자가 **같은가**.
///
/// 수집기는 유니코드 정규화(NFC)를 거쳐 담고 파일은 날것이다. 그 차이로
/// 거절하면 정상 치료가 막히므로 양쪽을 같은 모양으로 맞춰 견준다. 앞뒤 공백도
/// 뗀다 — `Exec=` 를 다시 지을 때 생기는 차이지 인자의 차이가 아니다.
pub fn same_args(a: &str, b: &str) -> bool {
    remedy_sdk::normalize::nfc(a.trim()) == remedy_sdk::normalize::nfc(b.trim())
}

/// `.lnk` 의 인자 구간 `[시작, 끝)` 과 유니코드 여부.
///
/// 읽는 쪽과 지우는 쪽이 **같은 계산**을 봐야 한다. 따로 적으면 한쪽만 고쳤을
/// 때 "본 것과 지운 것이 다른" 상태가 조용히 생긴다.
fn lnk_args_span(b: &[u8]) -> Option<(usize, usize, bool)> {
    const HEADER_SIZE: usize = 0x4C;
    const HAS_LINK_TARGET_ID_LIST: u32 = 1;
    const HAS_LINK_INFO: u32 = 1 << 1;
    const HAS_NAME: u32 = 1 << 2;
    const HAS_RELATIVE_PATH: u32 = 1 << 3;
    const HAS_WORKING_DIR: u32 = 1 << 4;
    const HAS_ARGUMENTS: u32 = 1 << 5;
    const IS_UNICODE: u32 = 1 << 7;

    let u16_at = |o: usize| -> Option<usize> {
        Some(u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?]) as usize)
    };
    let u32_at = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes([
            *b.get(o)?,
            *b.get(o + 1)?,
            *b.get(o + 2)?,
            *b.get(o + 3)?,
        ]))
    };

    if u32_at(0)? as usize != HEADER_SIZE {
        return None;
    }
    let flags = u32_at(20)?;
    if flags & HAS_ARGUMENTS == 0 {
        return None;
    }
    let unicode = flags & IS_UNICODE != 0;
    let mut off = HEADER_SIZE;

    if flags & HAS_LINK_TARGET_ID_LIST != 0 {
        off = off.checked_add(2)?.checked_add(u16_at(off)?)?;
    }
    if flags & HAS_LINK_INFO != 0 {
        off = off.checked_add(u32_at(off)? as usize)?;
    }
    // 문자 수 * (유니코드면 2) + 길이 필드 2바이트.
    let skip = |o: usize| -> Option<usize> {
        let n = u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?]) as usize;
        o.checked_add(2)?
            .checked_add(if unicode { n * 2 } else { n })
    };
    for f in [HAS_NAME, HAS_RELATIVE_PATH, HAS_WORKING_DIR] {
        if flags & f != 0 {
            off = skip(off)?;
        }
    }
    let start = off;
    let end = skip(off)?;
    if end > b.len() {
        return None;
    }
    Some((start, end, unicode))
}

/// `.lnk` 이 담고 있는 인자 문자열. 인자 항목이 없으면 `None`.
pub fn shortcut_arguments(b: &[u8]) -> Option<String> {
    let (start, end, unicode) = lnk_args_span(b)?;
    let body = b.get(start + 2..end)?;
    if unicode {
        let u: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&u))
    } else {
        Some(String::from_utf8_lossy(body).into_owned())
    }
}

pub fn strip_shortcut_arguments(b: &[u8]) -> Option<Vec<u8>> {
    const HAS_ARGUMENTS: u32 = 1 << 5;
    let (start, end, _) = lnk_args_span(b)?;

    let mut out = Vec::with_capacity(b.len() - (end - start));
    out.extend_from_slice(&b[..start]);
    out.extend_from_slice(&b[end..]);
    // **플래그를 끄지 않으면 그 뒤 항목이 인자로 읽힌다.** 아이콘 경로가
    // 명령행 인자가 되는 셈이라, 구간만 들어내는 것으로는 부족하다.
    let flags = u32::from_le_bytes([b[20], b[21], b[22], b[23]]);
    let cleared = (flags & !HAS_ARGUMENTS).to_le_bytes();
    out[20..24].copy_from_slice(&cleared);
    Some(out)
}

/// 보안 제품 예외 항목 하나.
///
/// **인코딩은 상위가 정한다.** 이 크레이트는 데이터를 내놓을 뿐이며, 컨테이너에
/// 무슨 형식으로 담을지는 `remedy-apply` 의 몫이다 — `FileMeta` 와 같은 층 나눔이다.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AvExclusion {
    /// `path` · `process` · `ext`.
    pub kind: String,
    /// 제외 대상. Windows 에서는 레지스트리 **값 이름**이다.
    pub value: String,
}

/// 보안 제품 예외 목록이 사는 자리. 백업의 `origin` 이 이것이다.
///
/// 파일 경로도 레지스트리 값도 아니라 복원의 "완전히 지정된 대상" 검사에 걸린다.
/// 목록 전체가 대상이므로 그것이 맞다 — 되돌릴 자리는 코어가 안다.
pub const AV_EXCLUSIONS_ORIGIN: &str = "av_exclusions";

/// Defender 제외 목록이 사는 키. 값 **이름**이 제외 대상이고 값은 표식(0)이다.
///
/// **수집기와 쓰기 백엔드가 같은 상수를 본다.** 한동안 두 곳에 따로 적혀 있었다 —
/// 같은 사실을 두 곳에 적으면 반드시 갈라진다.
pub const DEFENDER_EXCLUSION_ROOT: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions";

/// `(kind, 하위 키)`. `kind` 는 `AvExclusion::kind` 와 증거 레코드가 쓰는 값이다.
pub const DEFENDER_EXCLUSIONS: [(&str, &str); 3] = [
    ("path", "Paths"),
    ("process", "Processes"),
    ("ext", "Extensions"),
];

/// 예외 항목 하나를 가리키는 Action 대상을 `(kind, 값)` 으로 가른다.
///
/// # 왜 `split_value_name` 을 쓸 수 없는가
///
/// **제외 항목의 값 이름 자체가 경로다.** `...\Exclusions\Paths\C:\Users\x\y`
/// 를 마지막 역슬래시에서 자르면 키가 `...\Paths\C:\Users\x` 가 되고, 그런
/// 키는 없다. 없는 키를 열려다 실패하면 실행기는 그것을 *"크래시 뒤 이미 지워진
/// 것"* 으로 보아 **조용히 성공으로 넘긴다** — 악성 코드가 등록한 예외가 그대로
/// 남는데 `apply` 는 완전 치료(1)로 끝났다 (2026-08-31 실기기 실측).
///
/// 그래서 경계는 마지막 역슬래시가 아니라 **아는 접두사 셋**이다.
///
/// 대상 문자열은 계획기가 `<source 키>\<값 이름>` 으로 만든다
/// (`remedy-plan` 의 `target_of`). 대소문자는 무시한다 — 레지스트리 경로가
/// 그렇고, 접두사를 못 알아보면 Action 이 거부된다.
pub fn split_av_exclusion(target: &str) -> Option<(&'static str, &str)> {
    for (kind, leaf) in DEFENDER_EXCLUSIONS {
        let prefix = format!("{DEFENDER_EXCLUSION_ROOT}\\{leaf}\\");
        // **바이트 색인으로 자르지 않는다.** 접두사가 ASCII 여도 대상은 아무
        // 문자열이나 올 수 있고, 그 바이트 위치가 문자 경계가 아니면 슬라이스가
        // 패닉한다. `get` 은 경계가 아니면 `None` 을 준다.
        let Some(head) = target.get(..prefix.len()) else {
            continue;
        };
        if !head.eq_ignore_ascii_case(&prefix) {
            continue;
        }
        let value = &target[prefix.len()..];
        // 값이 비면 항목이 아니라 **키 그 자체다.**
        if value.is_empty() {
            continue;
        }
        return Some((kind, value));
    }
    None
}

/// `<하이브>\<키>\<값 이름>` 을 키와 값 이름으로 가른다.
///
/// **마지막 역슬래시가 경계다.** 역슬래시로 끝나면 값 이름이 빈 문자열이고,
/// 그것은 오류가 아니라 **(기본) 값**이다 — `exefile\shell\open\command` 의
/// 기본값처럼 하이재킹의 주요 표적이 거기 있다.
pub fn split_value_name(target: &str) -> Option<(&str, &str)> {
    let at = target.rfind('\\')?;
    Some((&target[..at], &target[at + 1..]))
}

/// 설정 파일을 텍스트로 읽는다.
///
/// UTF-8 이 아니면 손실 변환한다. 설정 파일은 대개 UTF-8 이고, 아니어도 **읽지
/// 못해 아무것도 못 하는 것보다 낫다** — 다만 비 UTF-8 바이트가 있는 줄은 내용
/// 대조에서 어긋나 그 Action 이 실패하고, 그것이 안전한 실패다.
fn read_text(path: &str) -> Result<String, PlatformError> {
    let bytes = std::fs::read(path).map_err(|e| PlatformError::io(path, e))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// 이식 가능한 파일 복원. 플랫폼 백엔드가 이것을 쓴다.
///
/// 여기 있는 것은 **어느 OS 에서나 같게 동작하는 부분**뿐이다 — 본문, 수정 시각,
/// 읽기 전용 비트. SDDL·mode·xattr 처럼 OS 고유인 것은 각 백엔드가 덧붙이며,
/// 아직 없는 것은 조용히 넘기지 않고 `lost` 에 적는다.
pub struct FsRestore;

/// 이 플랫폼에서 쓸 수 없는 메타데이터를 보고서에 적는다.
///
/// **가진 정보를 못 쓴다는 사실을 말하지 않으면 사용자는 복원이 완전했다고 믿는다.**
/// Windows 스냅샷을 리눅스에서 되돌리는 경로는 지원 범위 밖이지만(설계-02 §9),
/// 그렇더라도 무엇이 빠졌는지는 말해야 한다.
fn note_cross_platform(meta: &FileMeta, report: &mut RestoreReport) {
    if meta.sddl.is_some() && !cfg!(windows) {
        report.lose(
            "sddl",
            remedy_sdk::i18n::t(
                "이 플랫폼에는 Windows 보안 디스크립터가 없습니다",
                "this platform has no Windows security descriptors",
            ),
        );
    }
    if meta.mode.is_some() && !cfg!(unix) {
        report.lose(
            "mode",
            remedy_sdk::i18n::t(
                "이 플랫폼에는 POSIX 권한 비트가 없습니다",
                "this platform has no POSIX permission bits",
            ),
        );
    }
    if !meta.xattrs.is_empty() && !cfg!(unix) {
        report.lose(
            "xattr",
            remedy_sdk::i18n::t(
                "이 플랫폼에는 확장 속성이 없습니다",
                "this platform has no extended attributes",
            ),
        );
    }
}

impl PlatformWrite for FsRestore {
    fn backend_name(&self) -> &'static str {
        "fs"
    }

    fn plan_restore(&self, dest: &str, meta: &FileMeta) -> RestoreReport {
        let mut r = RestoreReport::default();
        r.restored.push("content".into());
        if meta.mtime_unix.is_some() {
            r.restored.push("mtime".into());
        }
        if meta.readonly.is_some() {
            r.restored.push("readonly".into());
        }
        if meta.sddl.is_some() && cfg!(windows) {
            r.restored.push("sddl".into());
        }
        if meta.mode.is_some() && cfg!(unix) {
            r.restored.push("mode".into());
        }
        note_cross_platform(meta, &mut r);
        // `ctime`(inode 변경 시각)은 어디에서도 설정할 수 없다. 커널이 우리가
        // 하는 쓰기 자체로 갱신한다.
        r.lose(
            "ctime",
            remedy_sdk::i18n::t(
                "운영체제가 관리하는 값이라 복원할 수 없습니다",
                "the operating system owns this value; it cannot be restored",
            ),
        );
        // **btime 은 플랫폼이 갈린다.** Unix 에는 설정 syscall 이 없고 Windows
        // 에는 `SetFileTime` 이 있다. 한동안 양쪽에 Unix 의 사실을 적어 두어
        // 되돌릴 수 있는 것을 못 한다고 보고했다 (2026-08-28 v1 점검, G2).
        match (cfg!(windows), meta.btime_unix) {
            (true, Some(_)) => r.restored.push("btime".into()),
            (true, None) => r.lose(
                "btime",
                remedy_sdk::i18n::t(
                    "격리할 때 생성 시각을 담지 않았습니다",
                    "the creation time was not captured at quarantine",
                ),
            ),
            (false, _) => r.lose(
                "btime",
                remedy_sdk::i18n::t(
                    "이 운영체제에서는 이 값을 바꿀 수 없습니다",
                    "this operating system cannot set this value",
                ),
            ),
        }
        // 여유 공간. **부족하면 파괴를 시작하지 않는다** (설계-00 §5-2).
        let space = crate::disk::available(dest);
        match space.fits(0) {
            Some(_) => {}
            None => r.lose(
                remedy_sdk::i18n::t("여유 공간 확인", "free space check"),
                space.describe(),
            ),
        }
        if std::path::Path::new(dest).exists() {
            r.lose(
                remedy_sdk::i18n::t("기존 파일", "existing file"),
                remedy_sdk::i18n::t(
                    "그 경로에 이미 파일이 있습니다. 복원하면 덮어씁니다",
                    "a file is already there; restoring would overwrite it",
                ),
            );
        }
        r
    }

    fn restore_file(
        &self,
        dest: &str,
        content: &[u8],
        meta: &FileMeta,
    ) -> Result<RestoreReport, PlatformError> {
        let path = std::path::Path::new(dest);
        let mut report = RestoreReport::default();

        // 원본이 있던 디렉터리째 지워졌을 수 있다. 그것도 복원의 일부다.
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| PlatformError::io(dest, e))?;
            }
        }

        // 읽기 전용이던 파일이 그 자리에 남아 있으면 쓰기가 막힌다. **권한을 푸는
        // 대신 지운다** — `set_readonly(false)` 는 Unix 에서 0o666 이 되어 원래보다
        // 넓은 권한을 준다. 어차피 내용을 통째로 덮어쓰므로 지우고 새로 만드는
        // 편이 의미도 맞다.
        if let Ok(md) = std::fs::metadata(path) {
            if md.permissions().readonly() {
                std::fs::remove_file(path).map_err(|e| PlatformError::io(dest, e))?;
            }
        }

        std::fs::write(path, content).map_err(|e| PlatformError::io(dest, e))?;
        report.restored.push("content".into());

        if let Some(secs) = meta.mtime_unix {
            let nanos = meta.mtime_nanos.unwrap_or(0);
            match system_time(secs, nanos) {
                Some(t) => {
                    let f = std::fs::File::options()
                        .write(true)
                        .open(path)
                        .map_err(|e| PlatformError::io(dest, e))?;
                    match f.set_modified(t) {
                        Ok(()) => report.restored.push("mtime".into()),
                        Err(e) => report.lose("mtime", e.to_string()),
                    }
                }
                None => report.lose(
                    "mtime",
                    remedy_sdk::i18n::t(
                        "표현할 수 없는 시각입니다",
                        "the timestamp cannot be represented",
                    ),
                ),
            }
        }

        // **생성 시각은 Windows 에서만 되돌린다.**
        //
        // 격리로 지운 파일을 되살리면 그 자리에 *새* 파일이 생기고, 생성 시각은
        // 되살린 순간이 된다. 그것을 고치지 않으면 감염 전후 지문 대조(G2)가
        // 어긋나고, 파일이 언제 만들어졌는지를 근거로 삼는 분석도 어긋난다.
        //
        // NTFS 의 파일 터널링(같은 이름·같은 디렉터리로 15초 안에 다시 만들면
        // 생성 시각을 물려준다)이 짧은 왕복을 가려 준 적이 있다 — **그 초록은
        // 복원 능력이 아니라 타이밍이었다** (2026-08-28 v1 점검).
        #[cfg(windows)]
        if let Some(secs) = meta.btime_unix {
            use std::os::windows::fs::FileTimesExt;
            let nanos = meta.btime_nanos.unwrap_or(0);
            match system_time(secs, nanos) {
                Some(t) => {
                    let f = std::fs::File::options()
                        .write(true)
                        .open(path)
                        .map_err(|e| PlatformError::io(dest, e))?;
                    let times = std::fs::FileTimes::new().set_created(t);
                    match f.set_times(times) {
                        Ok(()) => report.restored.push("btime".into()),
                        Err(e) => report.lose("btime", e.to_string()),
                    }
                }
                None => report.lose(
                    "btime",
                    remedy_sdk::i18n::t(
                        "표현할 수 없는 시각입니다",
                        "the timestamp cannot be represented",
                    ),
                ),
            }
        }
        #[cfg(not(windows))]
        report.lose(
            "btime",
            remedy_sdk::i18n::t(
                "이 운영체제에서는 이 값을 바꿀 수 없습니다",
                "this operating system cannot set this value",
            ),
        );

        // 읽기 전용은 **마지막에** 건다. 먼저 걸면 그 뒤의 쓰기가 막힌다.
        //
        // 푸는 쪽은 부르지 않는다. 방금 만든 파일은 이미 쓰기 가능하고,
        // `set_readonly(false)` 를 부르면 Unix 에서 0o666 이 되어 원래보다 넓어진다.
        if let Some(ro) = meta.readonly {
            if ro {
                let md = std::fs::metadata(path).map_err(|e| PlatformError::io(dest, e))?;
                let mut p = md.permissions();
                p.set_readonly(true);
                match std::fs::set_permissions(path, p) {
                    Ok(()) => report.restored.push("readonly".into()),
                    Err(e) => report.lose("readonly", e.to_string()),
                }
            } else {
                report.restored.push("readonly".into());
            }
        }

        // OS 고유 메타데이터는 **읽기 전용 다음에** 되돌린다. Unix 에서 `mode` 와
        // `readonly` 는 같은 비트를 건드리는데, 둘 다 있으면 더 구체적인 `mode` 가
        // 이겨야 한다. Windows 에서는 읽기 전용이 속성이고 DACL 쓰기는
        // WRITE_DAC 권한이라 서로 막지 않는다.
        crate::meta::restore_from(dest, meta, &mut report);
        note_cross_platform(meta, &mut report);
        report.lose(
            "ctime",
            remedy_sdk::i18n::t(
                "운영체제가 관리하는 값이라 복원할 수 없습니다",
                "the operating system owns this value; it cannot be restored",
            ),
        );
        report.lose(
            "btime",
            remedy_sdk::i18n::t(
                "읽기만 가능한 값이라 복원할 수 없습니다",
                "this value is read-only and cannot be restored",
            ),
        );
        Ok(report)
    }

    fn quarantine_read(&self, path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
        // 메타데이터를 **먼저** 뜬다. 본문을 읽는 동안 무언가가 파일을 건드리면
        // 뜬 메타데이터와 담은 바이트가 어긋나는데, 그 순서라야 어긋남이
        // "메타는 이전 것" 쪽으로 기울고 복원이 더 보수적이 된다.
        let meta = capture_meta(path)?;
        let content = std::fs::read(path).map_err(|e| PlatformError::io(path, e))?;
        Ok((content, meta))
    }

    fn exists(&self, path: &str) -> bool {
        // `metadata` 가 아니라 `symlink_metadata` 다. 심볼릭 링크가 끊긴 곳을
        // 가리키면 `metadata` 는 "없다" 고 하는데, 지워야 할 링크 자체는 있다.
        std::fs::symlink_metadata(path).is_ok()
    }

    fn destroy_file(&self, path: &str) -> Result<(), PlatformError> {
        // 읽기 전용 속성을 미리 풀지 않는다. Rust 의 `remove_file` 은 Windows 에서
        // `FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE` 를 써서 그 속성을 무시하고
        // 지운다 — 풀어 주는 코드를 덧대면 **죽은 코드**이고, Unix 에서는
        // `set_readonly(false)` 가 0o666 이 되어 오히려 권한을 넓힌다.
        //
        // 처음에는 방어적으로 풀어 뒀는데, 역검증에서 그 코드를 빼도 시험이
        // 그대로 통과해 죽은 코드임이 드러났다.
        std::fs::remove_file(path).map_err(|e| PlatformError::io(path, e))
    }

    // ── 파일 기반 Op (P7) ─────────────────────────────────────
    //
    // **여기 있는 이유**: 텍스트 줄·JSON·바로가기·대체 스트림은 OS 고유가
    // 아니라 파일 조작이다. `Live` 는 WOW64 경로 매핑만 얹어 이것을 부른다.

    fn text_line_read(&self, path: &str, line_no: u32) -> Result<String, PlatformError> {
        let text = read_text(path)?;
        nth_line(&text, line_no).ok_or(PlatformError::refused(
            "그 줄이 없습니다".into(),
            "there is no such line".into(),
        ))
    }

    fn text_line_remove(
        &self,
        path: &str,
        line_no: u32,
        expect: &str,
    ) -> Result<(), PlatformError> {
        let text = read_text(path)?;
        let after = remove_text_line(&text, line_no, expect).ok_or(PlatformError::refused(
            "그 자리의 줄이 계획과 다릅니다 — 아무것도 지우지 않았습니다".into(),
            "the line at that position differs from the plan — nothing was removed".into(),
        ))?;
        std::fs::write(path, after).map_err(|e| PlatformError::io(path, e))
    }

    fn text_line_restore(&self, path: &str, line_no: u32, line: &str) -> Result<(), PlatformError> {
        let text = read_text(path).unwrap_or_default();
        let after = insert_text_line(&text, line_no, line);
        std::fs::write(path, after).map_err(|e| PlatformError::io(path, e))
    }

    fn structured_remove_key(&self, path: &str, key_path: &str) -> Result<(), PlatformError> {
        let text = read_text(path)?;
        let after = json_remove_key(&text, key_path).ok_or(PlatformError::refused(
            "그 키가 없거나 JSON 이 아닙니다 — 아무것도 고치지 않았습니다".into(),
            "the key is missing or the file is not JSON — nothing was changed".into(),
        ))?;
        std::fs::write(path, after).map_err(|e| PlatformError::io(path, e))
    }

    fn structured_set_key(
        &self,
        path: &str,
        key_path: &str,
        value: &str,
    ) -> Result<(), PlatformError> {
        let text = read_text(path)?;
        let after = json_set_key(&text, key_path, value).ok_or(PlatformError::refused(
            "그 키가 없거나 JSON 이 아닙니다 — 만들지 않습니다".into(),
            "the key is missing or the file is not JSON — it is not created".into(),
        ))?;
        std::fs::write(path, after).map_err(|e| PlatformError::io(path, e))
    }

    fn stream_read(&self, target: &str) -> Result<Vec<u8>, PlatformError> {
        std::fs::read(target).map_err(|e| PlatformError::io(target, e))
    }

    fn stream_delete(&self, target: &str) -> Result<(), PlatformError> {
        // 스트림만 지운다. 호스트 파일은 남는다.
        std::fs::remove_file(target).map_err(|e| PlatformError::io(target, e))
    }

    fn shortcut_strip_args(&self, path: &str, expect: &str) -> Result<(), PlatformError> {
        let before = std::fs::read(path).map_err(|e| PlatformError::io(path, e))?;
        // 인자 항목이 아예 없으면 목표 상태는 이미 이루어졌다.
        let Some(now) = shortcut_arguments(&before) else {
            return Ok(());
        };
        if !same_args(&now, expect) {
            return Err(PlatformError::refused(
                "그 바로가기의 인자가 계획과 다릅니다 — 아무것도 지우지 않았습니다".into(),
                "the shortcut's arguments differ from the plan — nothing was removed".into(),
            ));
        }
        let Some(after) = strip_shortcut_arguments(&before) else {
            return Ok(());
        };
        std::fs::write(path, &after).map_err(|e| PlatformError::io(path, e))
    }

    // ── 디렉터리 ──────────────────────────────────────────────

    fn is_dir(&self, path: &str) -> bool {
        std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
    }

    fn dir_read(&self, path: &str) -> Result<(Vec<u8>, DirIndex), PlatformError> {
        let root = std::path::Path::new(path);
        let mut index = DirIndex::default();
        let mut body = Vec::new();
        walk_dir(root, root, &mut index, &mut body)?;
        // 순서를 고정한다. 파일 시스템의 열거 순서는 보장되지 않고, 그러면 같은
        // 디렉터리를 두 번 담을 때 컨테이너 바이트가 달라져 결정성 검사가
        // 흔들린다.
        index.dirs.sort();
        Ok((body, index))
    }

    fn dir_destroy(&self, path: &str) -> Result<(), PlatformError> {
        // **재해석점을 따라가지 않는다.** 루트 자체가 접합점이면 `remove_dir_all`
        // 이 그 너머를 지운다 — 확장 디렉터리 자리에 `C:\Windows` 를 가리키는
        // 접합점을 심어 두는 것으로 이 Op 이 OS 파괴 도구가 된다.
        let md = std::fs::symlink_metadata(path).map_err(|e| PlatformError::io(path, e))?;
        if md.file_type().is_symlink() {
            return Err(PlatformError::refused(
                "대상이 재귀 삭제할 디렉터리가 아니라 재해석점입니다".into(),
                "the target is a reparse point, not a directory to delete recursively".into(),
            ));
        }
        std::fs::remove_dir_all(path).map_err(|e| PlatformError::io(path, e))
    }

    fn dir_restore(
        &self,
        path: &str,
        content: &[u8],
        index: &DirIndex,
    ) -> Result<RestoreReport, PlatformError> {
        let root = std::path::Path::new(path);
        let mut report = RestoreReport::default();
        std::fs::create_dir_all(root).map_err(|e| PlatformError::io(path, e))?;
        for d in &index.dirs {
            if !rel_is_contained(d) {
                return Err(PlatformError::refused(
                    "목차가 루트 밖을 가리킵니다 — 되돌리지 않습니다".into(),
                    "the table of contents points outside the root — not restoring".into(),
                ));
            }
            std::fs::create_dir_all(root.join(d)).map_err(|e| PlatformError::io(path, e))?;
        }
        let mut off = 0usize;
        for f in &index.files {
            if !rel_is_contained(&f.rel) {
                return Err(PlatformError::refused(
                    "목차가 루트 밖을 가리킵니다 — 되돌리지 않습니다".into(),
                    "the table of contents points outside the root — not restoring".into(),
                ));
            }
            let end = off
                .checked_add(f.size as usize)
                .filter(|e| *e <= content.len())
                .ok_or(PlatformError::refused(
                    "목차가 본문 길이와 맞지 않습니다".into(),
                    "the table of contents does not match the body length".into(),
                ))?;
            let dest = root.join(&f.rel);
            let r = self.restore_file(&dest.to_string_lossy(), &content[off..end], &f.meta)?;
            report.lost.extend(r.lost);
            off = end;
        }
        report.restored.push("content".into());
        Ok(report)
    }
}

/// 하위를 훑어 목차와 본문을 만든다.
///
/// **재해석점을 만나면 통째로 거부한다.** 따라가면 담는 것이 확장 디렉터리가
/// 아니게 되고(임의 경로 읽기), 따라가지 않고 건너뛰면 백업이 불완전한 채로
/// 파괴가 진행된다. 둘 다 나쁘므로 세 번째 답을 고른다 — 아무것도 하지 않는다.
///
/// **힙의 스택으로 걷는다.** 재귀였을 때는 아주 깊은 트리가 호출 스택을 넘겨
/// `abort` 로 죽었다 — 그러면 훅이 있어도 남는 것은 "스택 넘침" 한 줄이다
/// (2026-09-06 관측성 검토 §1). 방문 순서는 재귀와 같다: 폴더의 항목을 이름순으로,
/// 하위 폴더는 만나는 자리에서 바로 내려간다. 깊이는 [`MAX_DIR_DEPTH`] 까지.
fn walk_dir(
    root: &std::path::Path,
    dir: &std::path::Path,
    index: &mut DirIndex,
    body: &mut Vec<u8>,
) -> Result<(), PlatformError> {
    let show = |p: &std::path::Path| p.to_string_lossy().to_string();
    let list =
        |d: &std::path::Path| -> Result<std::vec::IntoIter<std::path::PathBuf>, PlatformError> {
            let mut kids: Vec<std::path::PathBuf> = std::fs::read_dir(d)
                .map_err(|e| PlatformError::io(show(d), e))?
                .map(|e| e.map(|e| e.path()))
                .collect::<Result<_, _>>()
                .map_err(|e| PlatformError::io(show(d), e))?;
            kids.sort();
            Ok(kids.into_iter())
        };
    // 프레임 하나가 폴더 하나 — 재귀의 호출 프레임을 힙에 둔 것이다.
    let mut frames: Vec<std::vec::IntoIter<std::path::PathBuf>> = vec![list(dir)?];
    while let Some(top) = frames.last_mut() {
        let Some(p) = top.next() else {
            frames.pop();
            continue;
        };
        let md = std::fs::symlink_metadata(&p).map_err(|e| PlatformError::io(show(&p), e))?;
        if md.file_type().is_symlink() {
            return Err(PlatformError::refused(
                "하위에 재해석점이 있습니다 — 담을 수도 지울 수도 없습니다".into(),
                "a reparse point sits below — it can be neither captured nor deleted".into(),
            ));
        }
        let rel = p
            .strip_prefix(root)
            .map_err(|_| {
                PlatformError::refused(
                    "훑는 중에 루트 밖으로 나갔습니다".into(),
                    "the walk left the root".into(),
                )
            })?
            .to_string_lossy()
            .replace('\\', "/");
        if md.is_dir() {
            if frames.len() >= MAX_DIR_DEPTH {
                return Err(PlatformError::refused(
                    "폴더가 너무 깊습니다 — 256단을 넘는 트리는 담지 않습니다".into(),
                    "the folder is too deep — a tree over 256 levels is not captured".into(),
                ));
            }
            index.dirs.push(rel);
            frames.push(list(&p)?);
        } else {
            let meta = capture_meta(&p.to_string_lossy())?;
            let bytes = std::fs::read(&p).map_err(|e| PlatformError::io(show(&p), e))?;
            index.files.push(DirEntry {
                rel,
                size: bytes.len() as u64,
                meta,
            });
            body.extend_from_slice(&bytes);
        }
    }
    Ok(())
}

/// 담을 폴더의 깊이 상한. Windows 의 경로 길이 제한 안에서 나올 수 있는 깊이보다
/// 훨씬 크다 — 이것에 걸리는 트리는 정상 소프트웨어가 만든 것이 아니다.
const MAX_DIR_DEPTH: usize = 256;

fn system_time(secs: i64, nanos: u32) -> Option<std::time::SystemTime> {
    let base = std::time::UNIX_EPOCH;
    if secs >= 0 {
        base.checked_add(std::time::Duration::new(secs as u64, nanos))
    } else {
        base.checked_sub(std::time::Duration::new(secs.unsigned_abs(), 0))?
            .checked_add(std::time::Duration::new(0, nanos))
    }
}

/// 지금 있는 파일의 메타데이터를 읽어 담는다. **격리할 때 쓴다.**
pub fn capture_meta(path: &str) -> Result<FileMeta, PlatformError> {
    let md = std::fs::metadata(path).map_err(|e| PlatformError::io(path, e))?;
    let (secs, nanos) = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| (d.as_secs() as i64, d.subsec_nanos()))
        .unzip();
    // 생성 시각. **못 되돌리는 플랫폼에서도 담는다** — 컨테이너를 다른 곳에서
    // 열어 볼 수 있고, 포착은 소급되지 않는다.
    let (bsecs, bnanos) = md
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| (d.as_secs() as i64, d.subsec_nanos()))
        .unzip();
    let mut meta = FileMeta {
        mtime_unix: secs,
        mtime_nanos: nanos,
        btime_unix: bsecs,
        btime_nanos: bnanos,
        readonly: Some(md.permissions().readonly()),
        ..Default::default()
    };
    // **포착은 소급되지 않는다.** 격리하면서 담아 두지 않은 것은, 이미 만들어진
    // 컨테이너에 영영 없다 (설계-02 §9).
    crate::meta::capture_into(path, &mut meta);
    Ok(meta)
}

#[cfg(test)]
mod tests;
