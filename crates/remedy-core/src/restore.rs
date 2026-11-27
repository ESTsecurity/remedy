//! 복원 — **되돌리기는 사람의 결정이다** (설계-03 §5).
//!
//! 치료 도중 실패해도 자동으로 되돌리지 않는다. 로더는 지워졌고 페이로드 삭제가
//! 실패한 상태에서 롤백하면 **로더가 복원되어 위협이 재무장된다.** 되돌리기는
//! `remedy restore` 로만, 사람이 판단해서 일어난다.
//!
//! # 불변식 R
//!
//! `restore` 는 컨테이너에 기록된 항목만, 기록된 **절대 경로 그대로** 되돌린다.
//! 경로를 재해석하지 않고, 새 대상을 탐색하지 않으며, 환경 변수 토큰을 전개하지
//! 않는다. 토큰이 들어 있으면 그 엔트리는 **거부한다** — 다른 머신·다른 사용자에서
//! 다른 곳으로 복원되는 사고가 조용히 일어나기 때문이다.
//!
//! # 복원도 쓰기다
//!
//! 컨테이너가 변조되면 임의 경로 쓰기가 된다. 헤더를 AAD 로 묶어 변조는 탐지되지만
//! **탐지에만 기대지 않는다.** 복원 대상 경로도 보호 목록 검사를 받고, 걸리면
//! 거부된다(종료 코드 5). "복원은 되돌리는 것이니 안전하다" 는 직관이 틀리는
//! 지점이다. 적힌 경로가 아니라 **실제로 가는 길**도 본다 — 사용자의 링크를 따라
//! root 로 쓰지 않는다(`link_guard` · 이슈 #172 ①).
//!
//! # 여는 것과 되돌리는 것은 다르다
//!
//! 제자리 복원은 **원래 머신에서만** 보장된다 — SDDL 안의 SID 가 다른 머신에서
//! 해석되지 않으면 잘못된 권한이 붙는다. 다른 머신에서 필요한 것은 **내용을
//! 되찾는 것**이고, 그 경로가 `--extract-to` 다 (설계-02 §9).

use remedy_platform::write::{FileMeta, LastLink, LinkHit, LostItem, PlatformWrite, RestoreReport};
use remedy_quarantine::{ContentKey, Opened, QuarantineError, Sealed};
use remedy_sdk::EntryKind;
use std::collections::BTreeMap;
use std::path::Path;

/// 복원 한 건에 대한 계산 결과. **수행 전에** 만들어 사람에게 보인다.
#[derive(Debug, Clone)]
pub struct Item {
    pub id: String,
    pub kind: EntryKind,
    /// 컨테이너에 적힌 경로 그대로. 재해석하지 않는다.
    pub dest: String,
    pub size: u64,
    pub sha256: String,
    /// 무엇을 되살리고 무엇을 못 살리는가.
    pub report: RestoreReport,
    /// 막힌 이유. `Some` 이면 이 항목은 복원되지 않는다.
    pub blocked: Option<String>,
    /// **다시 시작한 뒤에는 막히지 않는다** — Windows 가 이 서비스를 지우는 중이라 막았다(2026-11-25). 화면이
    /// 끝 줄을 고른다('다시 시작한 뒤 다시 복원').
    pub restart_first: bool,
    /// **링크 가드가 막았다**(이슈 #172) — 보호 대상이 아니라 가는 길의 링크 때문이다. 화면이 끝 줄을 고른다.
    pub by_link: bool,
}

impl Item {
    pub fn allowed(&self) -> bool {
        self.blocked.is_none()
    }
}

/// 복원 계획 전체.
#[derive(Debug, Clone)]
pub struct Plan {
    pub run_id: String,
    pub plugin_id: String,
    pub threat: Option<String>,
    pub items: Vec<Item>,
    /// 꺼내기 모드라면 그 대상 디렉터리.
    pub extract_to: Option<String>,
    /// 볼륨별 여유 공간. **쓰기 전에 확인한다** (설계-00 §5-2).
    pub space: Vec<remedy_platform::disk::SpaceCheck>,
}

impl Plan {
    pub fn allowed(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| i.allowed())
    }

    pub fn blocked(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| !i.allowed())
    }

    pub fn total_bytes(&self) -> u64 {
        self.allowed().map(|i| i.size).sum()
    }

    /// 공간이 모자란 볼륨.
    pub fn out_of_space(&self) -> Vec<&remedy_platform::disk::SpaceCheck> {
        self.space.iter().filter(|s| s.insufficient()).collect()
    }

    /// 여유를 **확인하지 못한** 볼륨. 부족한 것과 다른 사실이므로 따로 센다.
    pub fn space_unknown(&self) -> Vec<&remedy_platform::disk::SpaceCheck> {
        self.space.iter().filter(|s| s.unknown()).collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("{0}")]
    Quarantine(#[from] QuarantineError),
    #[error("{0}")]
    Platform(#[from] remedy_platform::PlatformError),
    #[error("{msg}", msg = remedy_sdk::i18n::t("복원할 항목이 하나도 없습니다", "nothing to restore"))]
    Nothing,
    #[error("{msg}", msg = remedy_sdk::i18n::t("보호 목록에 걸린 항목이 있어 복원하지 않습니다", "an item is on the protected list; not restoring"))]
    Blocked,
    #[error("{msg} ({0})", msg = remedy_sdk::i18n::t("이 컨테이너에는 그 wrap 이 없습니다", "this container has no such wrap"))]
    NoSuchWrap(&'static str),
    /// 쓰기 직전에 다시 본 길에 따라 쓰면 안 되는 링크가 있다(이슈 #172 ①). 아무것도 쓰지 않았다.
    #[error("[{id}] {dest}: {why} — {msg}", msg = remedy_sdk::i18n::t("아무것도 쓰지 않았습니다", "nothing was written"))]
    LinkOnTheWay {
        id: String,
        dest: String,
        why: String,
    },
}

impl RestoreError {
    /// 무인 배포는 종료 코드만 본다. **가드가 막은 것**과 **부르는 쪽이 틀린 것**은
    /// 완전히 다른 후속 조치를 요구한다 (설계-02 §8).
    pub fn exit_code(&self) -> remedy_sdk::artifact::ExitCode {
        use remedy_sdk::artifact::ExitCode;
        match self {
            // 여유 공간 부족은 **쓰기 전에 막은 것**이다. 파괴는 시작되지 않았다.
            RestoreError::Platform(remedy_platform::PlatformError::NoSpace(_)) => {
                ExitCode::GuardStop
            }
            RestoreError::Blocked | RestoreError::LinkOnTheWay { .. } => ExitCode::GuardStop,
            _ => ExitCode::UsageError,
        }
    }
}

/// 경로가 **전개된 절대 경로**인가 (불변식 R).
///
/// 토큰이 남아 있으면 다른 머신에서 다른 곳으로 복원된다. 그 사고는 조용히
/// 일어나므로 여기서 막는다.
fn unexpanded_token(path: &str) -> Option<&'static str> {
    use remedy_sdk::i18n::t;
    if path.matches('%').count() >= 2 {
        return Some(t(
            "%NAME% 형태의 환경 변수 토큰이 남아 있습니다",
            "an environment token of the form %NAME% is still there",
        ));
    }
    if path.contains("${") || path.starts_with('~') {
        return Some(t(
            "전개되지 않은 참조가 남아 있습니다",
            "an unexpanded reference is still there",
        ));
    }
    None
}

/// 레지스트리 값 대상인가 — **하이브부터 값 이름까지 완전히 지정됐는가.**
///
/// 파일의 "절대 경로" 에 해당하는 것이 레지스트리에서는 이것이다. 하이브가
/// 없으면 어느 하이브인지 실행 시점에 정해지고, 그것은 "기록된 자리에만
/// 쓴다"(불변식 R)를 깨뜨린다.
///
/// **아직 레지스트리 보호 목록은 없다.** 여기서 막는 것은 하이브 없는 대상뿐이고,
/// 변조된 컨테이너는 헤더 AAD 가 잡는다. 값이 아니라 **키 전체**를 되돌리는
/// `registry.delete_key`(P8)가 들어올 때 보호 목록이 필요해진다.
fn is_registry_target(target: &str) -> bool {
    let head = target.split('\\').next().unwrap_or("").to_ascii_uppercase();
    let known = matches!(
        head.as_str(),
        "HKLM" | "HKCU" | "HKU" | "HKEY_LOCAL_MACHINE" | "HKEY_CURRENT_USER" | "HKEY_USERS"
    );
    // `<하이브>\<키>\<값 이름>` — 조각이 셋 이상이어야 값을 가리킨다.
    known && target.matches('\\').count() >= 2
}

fn is_absolute(path: &str) -> bool {
    let b = path.as_bytes();
    // Windows: `C:\...` 또는 UNC `\\server\share`.
    if b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') {
        return true;
    }
    if path.starts_with("\\\\") {
        return true;
    }
    path.starts_with('/')
}

/// 복원 계획을 만든다. **아무것도 쓰지 않는다.**
/// 복원이 **어디에 쓸 수 있는가**를 정하는 둘.
///
/// 하나로 묶는 이유는 인자 수가 아니라 뜻이다 — 보호 목록만으로는 답이 나오지
/// 않고([`vouched`] 의 주석), 보증만으로도 나오지 않는다. 둘이 함께여야 한 판정이
/// 된다 (설계-03 §5).
pub struct Guards<'a> {
    pub protected: &'a remedy_plan::Protected,
    /// 이 기계의 저널이 보증하는 `엔트리 id → 대상` ([`vouched`]).
    ///
    /// 빈 지도면 보호 디렉터리 하위를 전부 막는다 — **넘겨받은 컨테이너가
    /// 그렇다.**
    pub vouched: &'a BTreeMap<String, String>,
}

/// 이 기계의 저널이 보증하는 `엔트리 id → 우리가 담았던 대상`.
///
/// # 왜 저널인가
///
/// 보호 디렉터리 하위의 개별 파일은 **계획기가 지울 수 있게 허용한다**(설계-03
/// §3 1층). 그런데 복원이 그것을 막으면 "지울 수는 있는데 되돌릴 수는 없는"
/// 대상이 생긴다 — Linux 에서는 `/etc` 와 `/usr` 가 보호 목록이라 systemd 유닛 ·
/// cron · 신뢰 인증서가 **전부** 그 상태였다.
///
/// 그렇다고 컨테이너가 지시하는 대로 열어 주면 **넘겨받은 컨테이너 하나로
/// System32 에 임의 파일을 심을 수 있다.** 컨테이너는 패스프레이즈나 조직 키로도
/// 열리므로 그 공격에 기계 장악이 필요하지 않다 — 분석가에게 "고객 격리물인데
/// 복원해 달라" 고 건네는 것으로 족하다.
///
/// **저널이 둘을 가른다.** 이 기계의 저널이 *"그 run 에서 그 엔트리로 그 대상을
/// 담았다"* 고 말하면 그것은 우리가 한 일이고, 되돌리는 것은 그 정확한 역이다.
/// 넘겨받은 컨테이너에는 대응하는 저널이 없다 — 그때는 `--extract-to` 로 꺼낸다
/// (설계-02 §9 "여는 것과 되돌리는 것은 다르다" 가 이미 그렇게 정해 두었다).
///
/// # 왜 대상까지 대조하는가
///
/// 엔트리 id 만 보면 `e0` 같은 이름을 재사용한 컨테이너가 통과한다. 저널의
/// `Intent.target` 과 컨테이너의 `origin` 이 **같아야** 한다 — 그래야 "우리가
/// 지운 그 경로" 라는 뜻이 된다.
///
/// 저널이 없거나 읽히지 않으면 빈 지도다. **없는 것을 보증으로 읽지 않는다.**
pub fn vouched(state_dir: &Path, run_id: &str) -> BTreeMap<String, String> {
    let path = remedy_journal::journal_path(state_dir, run_id);
    let Ok(reading) = remedy_journal::Journal::read(&path) else {
        return BTreeMap::new();
    };
    let mut target_of_seq: BTreeMap<u32, String> = BTreeMap::new();
    let mut out = BTreeMap::new();
    for r in &reading.records {
        match r {
            remedy_journal::Record::Intent { seq, target, .. } => {
                target_of_seq.insert(*seq, target.clone());
            }
            remedy_journal::Record::Backup { seq, entry_id } => {
                if let Some(t) = target_of_seq.get(seq) {
                    out.insert(entry_id.clone(), t.clone());
                }
            }
            _ => {}
        }
    }
    out
}

/// 이 자리에 **되돌려도 되는가**. 안 되면 그 사유.
///
/// # 계획기와 같은 두 겹이어야 한다
///
/// 이 검사는 한동안 한 겹이었다 — `protected.check()` 가 무엇이든 돌려주면
/// 막았다. 계획기는 두 겹이다(`guard.rs` 의 `check_protected`): 보호 디렉터리
/// **자체**·루트·홈은 무엇으로도 못 건드리고, **하위의 개별 파일은 조건부로
/// 허용**한다.
///
/// 그 갈라짐이 **"지울 수는 있는데 되돌릴 수는 없는" 대상**을 만들었다. Linux
/// 에서 특히 심했다 — 보호 목록에 `/etc` 와 `/usr` 가 있고 systemd 유닛 · cron ·
/// XDG autostart · 신뢰 인증서가 전부 그 아래 산다. 즉 **실제 치료 대상 거의
/// 전부가 복원 불가**였다. 실기기 시연이 `/tmp` 에서 돌아 드러나지 않았다
/// (설계-09 P12 후속).
///
/// # 무엇을 여는가
///
/// 보호 디렉터리 **하위의 개별 파일 하나**를 우리가 담았던 그 자리에 되돌리는
/// 것뿐이다. 디렉터리 통째 복원은 열지 않는다 — 계획기가 그 자리에서 재귀
/// 삭제를 거부하므로 그런 엔트리는 애초에 만들어지지 않고, 그래도 만들어졌다면
/// 그것이야말로 막아야 할 것이다.
///
/// 경로는 컨테이너의 매니페스트에서 온다. 헤더 AAD 가 변조를 잡지만
/// **탐지에만 기대지 않는다** — 그래서 이 함수가 남는다.
fn protected_for_restore(
    origin: &str,
    kind: EntryKind,
    entry_id: &str,
    guards: &Guards<'_>,
) -> Option<String> {
    use remedy_plan::protect::Protection;
    // `{p}` 는 `Protection` 의 `Display` 이고 그쪽은 이미 두 언어다 — 여기서
    // 감싸는 **틀만** 고른다.
    let lang = remedy_sdk::i18n::current();
    let p = guards.protected.check(origin)?;
    let Protection::InsideProtectedDirectory(_) = p else {
        // 보호 디렉터리 자체 · 루트 · 홈은 무엇으로도 되돌리지 않는다.
        return Some(lang.pick(
            format!("보호 대상입니다 — {p}"),
            format!("protected target — {p}"),
        ));
    };
    if kind == EntryKind::Directory {
        // 나무를 되돌리면 그 아래 무엇이 생기는지 매니페스트가 정한다. 계획기가
        // 그 자리에서 재귀 삭제를 거부하므로 그런 엔트리는 애초에 만들어지지
        // 않고, 그래도 있다면 그것이야말로 막아야 할 것이다.
        return Some(lang.pick(
            format!("보호 대상입니다 — {p}. 하위 디렉터리를 통째로 되돌리지는 않습니다"),
            format!("protected target — {p}. A subdirectory is not restored as a whole"),
        ));
    }
    if guards.vouched.get(entry_id).map(String::as_str) == Some(origin) {
        return None;
    }
    Some(lang.pick(
        format!(
            "보호 대상입니다 — {p}. 이 기계의 저널에 우리가 그 자리에서 담았다는 기록이 \
             없습니다 — 넘겨받은 격리물이라면 --extract-to 로 꺼내십시오"
        ),
        format!(
            "protected target — {p}. This machine's journal has no record that we backed \
             it up from that place — if this quarantine came from elsewhere, take it out \
             with --extract-to"
        ),
    ))
}

pub fn plan(
    opened: &Opened<'_>,
    run_id: &str,
    backend: &dyn PlatformWrite,
    guards: &Guards<'_>,
    only: &[String],
    extract_to: Option<&str>,
) -> Result<Plan, RestoreError> {
    let lang = remedy_sdk::i18n::current();
    let mut items = Vec::new();

    for me in &opened.manifest.entries {
        if !only.is_empty() && !only.contains(&me.id) {
            continue;
        }

        let meta: FileMeta = serde_json::from_value(me.meta.clone()).unwrap_or_default();
        // 꺼내기는 setuid · setgid · 파일 권능 · 소유자를 빼고 쓴다 — 계획도 그 메타데이터로 센다([`apply`] 와 같다).
        let meta = if extract_to.is_some() {
            meta.for_extract()
        } else {
            meta
        };

        // 꺼내기 모드에서는 원본 경로에 쓰지 않으므로 보호 검사가 성립하지 않는다.
        // 대신 컨테이너가 지시하는 경로를 **쓰지 않는다는 사실 자체**가 방어다.
        let (dest, mut blocked) = match extract_to {
            Some(dir) => (extract_path(dir, &me.origin), None),
            None => {
                let mut blocked = None;
                if let Some(why) = unexpanded_token(&me.origin) {
                    blocked = Some(lang.pick(
                        format!("불변식 R: {why} — '{}'", me.origin),
                        format!("invariant R: {why} — '{}'", me.origin),
                    ));
                } else if me.kind == EntryKind::AvExclusion {
                    // 목록 전체가 대상이라 경로가 없다. 되돌릴 자리는 코어가
                    // 알고, 컨테이너가 지시하지 않는다 — 그래서 오히려 안전하다.
                } else if me.kind == EntryKind::Task {
                    // 작업의 자리는 등록 경로다. 그 모양이 완전한가는
                    // 플랫폼이 안다 — 여기서 다시 적으면 갈라진다.
                    if let Some(why) = remedy_platform::write::task_id_problem(&me.origin) {
                        blocked = Some(lang.pick(
                            format!("작업 등록 경로: {why} — '{}'", me.origin),
                            format!("task registration path: {why} — '{}'", me.origin),
                        ));
                    }
                } else if !is_absolute(&me.origin) && !is_registry_target(&me.origin) {
                    blocked = Some(lang.pick(
                        format!(
                            "완전히 지정된 대상이 아닙니다 (절대 경로도 레지스트리 값도 아닙니다) — '{}'",
                            me.origin
                        ),
                        format!(
                            "not a fully specified target (neither an absolute path nor a \
                             registry value) — '{}'",
                            me.origin
                        ),
                    ));
                } else if let Some(why) = protected_for_restore(&me.origin, me.kind, &me.id, guards)
                {
                    blocked = Some(why);
                }
                (me.origin.clone(), blocked)
            }
        };

        // **사용자의 링크를 따라 root 로 쓰지 않는다**(이슈 #172 ①). 복원은 root 로 돈다 — 사용자가 자기 폴더를
        // root 의 자리를 가리키는 링크로 바꿔 두자 1.26.0 은 그 너머에 담아 둔 이름 · 바이트 · 소유자 · mode 를 썼다
        // (`/home/alice/bin` → `/etc/…` 에 alice 소유 4755). 보호 목록은 적힌 경로만 보므로 이것을 보지 못한다.
        // 꺼내기는 원래 자리에 쓰지 않으므로 묻지 않는다 — 꺼낼 자리의 마지막 성분이 링크 · 하드 링크면 쓰기가 따라가지
        // 않고 그 항목을 실패로 낸다(리눅스 `FsRestore::restore_file`). 꺼낼 폴더 자체를 남이 미리 만들 수 있는 자리로
        // 고르면 그 가운데 성분은 남는 한계다. 쓰기 직전에 한 번 더 본다([`apply`]).
        let mut by_link = false;
        if blocked.is_none() && extract_to.is_none() {
            blocked = link_guard(backend, me.kind, &me.origin, &me.meta);
            by_link = blocked.is_some();
        }

        // **Windows 가 지우는 중인 서비스에는 되돌려 쓰지 않는다**(2026-11-25 · 이슈 #172 ⑥).
        //
        // 삭제가 미뤄진 서비스의 정의 키는 남아 있고, 복원은 그 키를 열어 담은 값만 쓴다 — 지울 표시가 그대로
        // 남는다. 그 서비스에 열린 핸들이 닫히거나 다시 시작하면 SCM 이 되돌려 쓴 키를 하위 키째 지운다(2026-11-25
        // 랩: 복원 0 · '3건 복원 완료' 뒤 핸들이 닫히자 키가 사라졌다). 아래의 재부팅 삭제 예약 취소와 같은 원칙이다 —
        // 되돌려 놓은 것이 다시 시작할 때 지워지면 복원이 아니다. 다시 시작하면 삭제가 끝나 키가 없고, 그 뒤의
        // 복원은 지금처럼 된다. 확인하지 못해도 막는다 — 쓰고 나서 사라지는 것보다 멈추는 편이 낫다.
        let mut restart_first = false;
        if blocked.is_none()
            && extract_to.is_none()
            && matches!(
                me.kind,
                EntryKind::Service | EntryKind::RegistryKey | EntryKind::RegistryValue
            )
        {
            match backend.service_delete_pending(&me.origin) {
                Ok(false) => {}
                Ok(true) => {
                    restart_first = true;
                    // 한 줄 리터럴이다 — 콘솔 문서(§15)의 화면 줄을 `console-doc` 이 이 리터럴과 견준다(줄잇기
                    // `\` 를 넣으면 골격이 그 자리에서 끊긴다).
                    blocked = Some(lang.pick(
                        "Windows 가 이 서비스를 지우는 중입니다 — PC 를 다시 시작하면 끝납니다. 그 전에 되돌리면 Windows 가 되돌린 등록까지 지웁니다".to_string(),
                        "Windows is removing this service — it finishes when the PC restarts; restoring before that lets Windows remove the restored registration too".to_string(),
                    ));
                }
                Err(e) => {
                    blocked = Some(lang.pick(
                        format!("이 서비스가 지워지는 중인지 확인하지 못했습니다 — 쓰지 않습니다: {e}"),
                        format!(
                            "could not check whether this service is being removed — not writing: {e}"
                        ),
                    ));
                }
            }
        }

        // 레지스트리 값과 예외 목록은 **타입과 바이트가 전부**라 잃을 것이 없다.
        // 파일용 `plan_restore` 를 그대로 부르면 없는 파일을 재는 셈이 되고,
        // 그 결과가 "되살리지 못한다" 로 사람에게 나간다.
        let report = if blocked.is_some()
            || matches!(
                me.kind,
                EntryKind::RegistryValue
                    | EntryKind::AvExclusion
                    | EntryKind::TextLine
                    | EntryKind::Task
                    | EntryKind::RegistryKey
                    | EntryKind::CertStore
                    | EntryKind::Service
                    | EntryKind::BootConfig
            ) {
            RestoreReport::default()
        } else if extract_to.is_some() {
            extract_report(backend.plan_restore(&dest, &meta))
        } else {
            backend.plan_restore(&dest, &meta)
        };

        items.push(Item {
            id: me.id.clone(),
            kind: me.kind,
            dest,
            size: me.size,
            sha256: me.sha256.clone(),
            report,
            blocked,
            restart_first,
            by_link,
        });
    }

    if items.is_empty() {
        return Err(RestoreError::Nothing);
    }

    // 볼륨별로 합쳐서 잰다. 항목마다 따로 재면 각각은 들어가는데 합쳐서는
    // 안 들어가는 경우를 놓친다.
    let needs: Vec<(String, u64)> = items
        .iter()
        .filter(|i| i.allowed())
        .map(|i| (i.dest.clone(), i.size))
        .collect();
    let space = remedy_platform::disk::check(&needs);

    Ok(Plan {
        run_id: run_id.to_string(),
        plugin_id: opened.manifest.plugin_id.clone(),
        threat: opened.manifest.threat.clone(),
        items,
        extract_to: extract_to.map(str::to_string),
        space,
    })
}

/// 꺼내기의 보고서(계획 · 복원 뒤) — **POSIX 소유자 줄을 뺀다**(이슈 #172). 꺼내기는 소유자를 쓰지 않는다
/// ([`FileMeta::for_extract`] 가 uid · gid 를 비운다 — 꺼낸 사본은 꺼낸 계정의 것이다). 그 칸이 비었다고 백엔드가 적는
/// '격리할 때 소유자를 담지 않았습니다' 는 꺼낸 사본에 대해 사실이 아니다. Windows 의 소유자 줄(담아 둔 SDDL 의
/// 소유자를 쓰다 막힌 것)은 사실이므로 그대로 둔다.
fn extract_report(mut r: RestoreReport) -> RestoreReport {
    if cfg!(unix) {
        r.lost.retain(|l| l.item != "owner");
    }
    r
}

/// 꺼내기 모드의 대상 경로. **드라이브 문자와 구분자를 평평하게 만든다** —
/// 원본 경로를 그대로 이어 붙이면 `..` 이나 절대 경로가 대상 디렉터리를 벗어난다.
fn extract_path(dir: &str, origin: &str) -> String {
    let mut flat = String::with_capacity(origin.len());
    for c in origin.chars() {
        match c {
            ':' | '\\' | '/' => flat.push('_'),
            _ => flat.push(c),
        }
    }
    let sep = if dir.contains('\\') { '\\' } else { '/' };
    format!("{}{}{}", dir.trim_end_matches(['\\', '/']), sep, flat)
}

/// 제자리 복원이 이 항목에서 **쓰는 파일 시스템 자리**와, 그 자리 자체가 링크일 때 어떻게 보는가 — 링크 가드가
/// 묻는다(이슈 #172 ①).
///
/// cron · 텍스트 줄은 그 파일 안의 줄만 고친다 — 치료도 그 자리의 링크(`/etc/resolv.conf` 같은 root 의 것)를 따라
/// 고쳤다. 유닛은 유닛 파일을 통째로 쓰되 그 자리의 root 링크(`systemctl link` 로 단 유닛)를 따라간다 — 쓰기도 믿는
/// root 링크만 따라가 그 끝을 한 번 연다(리눅스 `persistence_restore`). 활성화 링크는 그 폴더 안에 **링크를 단다**(이미
/// 있으면 그대로 둔다 — 링크를 따라 쓰지 않는다). 디렉터리는 루트와 목차의 폴더 · 파일이다. 구조적 설정은 키만이 아니라 그 파일을
/// 통째로 담아 파일처럼 쓴다. 레지스트리 · 작업 · 예외 목록 · 부팅 구성은 파일 시스템에 쓰지 않는다.
///
/// 종류를 `_` 로 닫지 않는다 — 새 종류가 생기면 여기서 컴파일이 멈춰 그 종류가 쓰는 자리를 묻게 한다.
fn write_places(kind: EntryKind, dest: &str, meta: &serde_json::Value) -> Vec<(String, LastLink)> {
    use LastLink::{Followed, Refused};
    let one = |place: &str, last| vec![(place.to_string(), last)];
    match kind {
        EntryKind::File | EntryKind::FileStream | EntryKind::StructuredConfig => one(dest, Refused),
        EntryKind::CertStore if !is_registry_target(dest) => one(dest, Refused),
        EntryKind::TextLine => one(dest, Followed),
        EntryKind::Cron => match dest.rsplit_once(':') {
            Some((file, n)) if !file.is_empty() && n.parse::<u32>().is_ok_and(|n| n > 0) => {
                one(file, Followed)
            }
            // 줄 자리가 아니면 백엔드가 유닛처럼 통째로 쓴다(`persistence_restore`).
            _ => one(dest, Refused),
        },
        EntryKind::Unit => {
            let index: remedy_platform::write::PersistenceIndex =
                serde_json::from_value(meta.clone()).unwrap_or_default();
            let mut out = one(dest, Followed);
            for l in &index.links {
                let dir = match l.rsplit_once('/') {
                    Some((d, _)) if !d.is_empty() => d,
                    _ => "/",
                };
                if !out.iter().any(|(p, _)| p == dir) {
                    out.push((dir.to_string(), Followed));
                }
            }
            out
        }
        EntryKind::Directory => {
            let index: remedy_platform::write::DirIndex =
                serde_json::from_value(meta.clone()).unwrap_or_default();
            let root = dest.trim_end_matches('/');
            let inner = index.dirs.iter().chain(index.files.iter().map(|f| &f.rel));
            std::iter::once(dest.to_string())
                .chain(inner.map(|rel| format!("{root}/{rel}")))
                .map(|p| (p, Refused))
                .collect()
        }
        EntryKind::CertStore
        | EntryKind::RegistryValue
        | EntryKind::RegistryKey
        | EntryKind::Task
        | EntryKind::Service
        | EntryKind::AvExclusion
        | EntryKind::BootConfig => Vec::new(),
    }
}

/// 링크 가드(이슈 #172 ①) — 이 항목이 쓰는 자리로 가는 길에 따라 쓰면 안 되는 링크가 있으면 막은 사유. 묻지 못한
/// 것도 막는다 — '링크가 없다' 로 접지 않는다.
fn link_guard(
    backend: &dyn PlatformWrite,
    kind: EntryKind,
    dest: &str,
    meta: &serde_json::Value,
) -> Option<String> {
    for (place, last) in write_places(kind, dest, meta) {
        match backend.link_on_the_way(&place, last) {
            Ok(None) => {}
            Ok(Some(hit)) => return Some(link_why(&hit)),
            Err(e) => return Some(link_unknown(&e)),
        }
    }
    None
}

/// 길을 묻지 못한 사유 한 줄. 아래 [`link_why`] 와 같이 한 줄 리터럴이다.
fn link_unknown(e: &remedy_platform::PlatformError) -> String {
    remedy_sdk::i18n::current().pick(
        format!("되돌릴 자리로 가는 길의 링크를 확인하지 못했습니다 — 쓰지 않습니다: {e}"),
        format!("could not check the links on the way to the restore place — not writing: {e}"),
    )
}

/// 걸린 링크의 사유 한 줄. 한 줄 리터럴이다 — 콘솔 문서가 화면 줄을 리터럴과 견주는데, 줄잇기 `\` 를 넣으면 골격이
/// 그 자리에서 끊긴다.
fn link_why(hit: &LinkHit) -> String {
    let lang = remedy_sdk::i18n::current();
    match hit {
        LinkHit::Itself { link, to } => lang.pick(
            format!("되돌릴 자리가 링크입니다 — '{link}' → '{to}'. 링크를 따라 쓰지 않습니다 — 내용이 필요하면 --extract-to 로 꺼내십시오"),
            format!("the restore place is a link — '{link}' → '{to}'; not writing through it — to get the content, take it out with --extract-to"),
        ),
        LinkHit::NotRoot { link, uid, to } => lang.pick(
            format!("되돌릴 자리로 가는 길에 root 가 아닌 사용자(uid {uid})의 링크가 있습니다 — '{link}' → '{to}'. 링크를 따라 쓰지 않습니다 — 내용이 필요하면 --extract-to 로 꺼내십시오"),
            format!("a link owned by a user other than root (uid {uid}) is on the way to the restore place — '{link}' → '{to}'; not writing through it — to get the content, take it out with --extract-to"),
        ),
        LinkHit::LooseFolder { link, to } => lang.pick(
            format!("되돌릴 자리로 가는 길에 root 의 링크가 있지만 그 링크가 놓인 폴더를 root 가 아닌 사용자도 바꿀 수 있습니다 — '{link}' → '{to}'. 링크를 따라 쓰지 않습니다 — 내용이 필요하면 --extract-to 로 꺼내십시오"),
            format!("a link owned by root is on the way to the restore place, but users other than root can change the folder it is in — '{link}' → '{to}'; not writing through it — to get the content, take it out with --extract-to"),
        ),
        LinkHit::ClimbsPastMissing { missing } => lang.pick(
            format!("되돌릴 자리의 경로가 없는 폴더 '{missing}' 아래에서 '..' 로 되짚어 올라갑니다 — 확인하지 못하는 길이라 쓰지 않습니다"),
            format!("the restore path climbs back with '..' below the missing folder '{missing}' — that way cannot be checked; not writing"),
        ),
        LinkHit::TooMany { link } => lang.pick(
            format!("되돌릴 자리로 가는 길의 링크가 너무 많이 이어집니다 — '{link}'. 쓰지 않습니다"),
            format!("too many links on the way to the restore place — '{link}'; not writing"),
        ),
    }
}

/// 계획이 되돌린다고 한 것 가운데 **되돌리지 못한 것** — 복원 뒤 화면이 항목마다 찍는다(이슈 #172 ①).
///
/// 1.26.0 은 복원 뒤의 보고서에서 되돌린 것만 찍어, 쓸 때에야 드러난 실패(남의 uid 로의 chown · 해석되지 않는
/// SDDL · 나타낼 수 없는 시각)가 화면에서 사라졌다. 계획이 이미 '복원 불가' 로 적은 것(ctime · Unix 의 btime ·
/// 옛 격리물의 소유자)은 다시 적지 않는다 — 그 줄은 복원 전에 찍혔다. 계획이 되돌린다고 하지 않은 칸(Windows 의
/// sacl)도 적지 않는다.
pub fn missed<'r>(planned: &RestoreReport, got: &'r RestoreReport) -> Vec<&'r LostItem> {
    got.lost
        .iter()
        .filter(|l| planned.restored.contains(&l.item))
        .collect()
}

/// 한 항목의 수행 결과.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub id: String,
    pub dest: String,
    pub result: Result<RestoreReport, String>,
}

/// 계획을 수행한다. **계획에 있는 것만 한다.**
pub fn apply(
    plan: &Plan,
    opened: &Opened<'_>,
    key: &ContentKey,
    backend: &dyn PlatformWrite,
) -> Result<Vec<Outcome>, RestoreError> {
    // **쓰기 전에 다시 잰다.** 계획과 수행 사이에 시간이 흐르고, 그 사이 다른
    // 무언가가 디스크를 채울 수 있다. 도중에 차면 마지막 파일이 잘린 채 남고,
    // 그것은 복원된 것처럼 보인다 (설계-00 §5-2).
    let needs: Vec<(String, u64)> = plan.allowed().map(|i| (i.dest.clone(), i.size)).collect();
    remedy_platform::disk::require(&needs)?;

    // **링크도 쓰기 직전에 다시 본다**(이슈 #172 ①). 계획을 보이고 사람이 확인하는 사이에 폴더가 링크로 바뀔 수
    // 있다. 걸리면 아무것도 쓰지 않고 멈춘다 — 계획에서 막은 것과 같은 5 다.
    //
    // 이 물음과 각 쓰기 사이에 **마지막 성분**을 링크 · 하드 링크로 바꾸면 리눅스의 파일 쓰기(`restore_file`)가 그
    // 자리를 링크를 따르지 않고 한 번 열어 그 파일 하나로 끝까지 다루므로 따라가지 않고 그 항목이 실패한다. 남는
    // 한계는 **가운데 성분**의 바꿔치기다 — 쓰기가 부모 폴더를 이름으로 풀고, 성분마다 `openat(O_NOFOLLOW)` 로 걷는
    // 길은 std 에 없다. 유닛 파일 쓰기도 믿는 root 링크만 따라가 그 끝을 한 번 연다. 인증서 · 줄 자리의 쓰기는 마지막
    // 성분도 이름으로 연다.
    if plan.extract_to.is_none() {
        let none = serde_json::Value::Null;
        for item in plan.allowed() {
            let meta = opened
                .manifest
                .entries
                .iter()
                .find(|m| m.id == item.id)
                .map_or(&none, |m| &m.meta);
            if let Some(why) = link_guard(backend, item.kind, &item.dest, meta) {
                return Err(RestoreError::LinkOnTheWay {
                    id: item.id.clone(),
                    dest: item.dest.clone(),
                    why,
                });
            }
        }
    }

    let mut out = Vec::new();
    for item in restore_order(plan, opened) {
        let entry = match opened.read(&item.id, key) {
            Ok(e) => e,
            Err(e) => {
                out.push(Outcome {
                    id: item.id.clone(),
                    dest: item.dest.clone(),
                    result: Err(e.to_string()),
                });
                continue;
            }
        };

        // **메타데이터도 색인과 같아야 한다**(이슈 #172). 계획 · 링크 가드는 색인의 meta 로 쓸 자리를 정하고, 쓰기는
        // 본문의 meta 로 유닛의 활성화 링크 · 폴더 목차를 만든다 — 다르면 가드가 묻지 않은 자리에 쓴다. 봉인할 때 둘에
        // 같은 값을 넣으므로 정직한 컨테이너는 어긋나지 않는다. 아래 경로 검사와 같은 꼴로 그 항목을 실패로 둔다.
        let indexed = opened.manifest.entries.iter().find(|m| m.id == item.id);
        if indexed.is_none_or(|m| m.meta != entry.meta) {
            out.push(Outcome {
                id: item.id.clone(),
                dest: item.dest.clone(),
                result: Err(remedy_sdk::i18n::current().pick(
                    "색인과 본문의 메타데이터가 다릅니다 — 쓰지 않았습니다".to_string(),
                    "the index and the body disagree on the metadata — nothing was written"
                        .to_string(),
                )),
            });
            continue;
        }

        // 컨테이너를 두 번 읽지 않는다. 계획을 만들 때 본 경로와 지금 쓰는 경로가
        // 같아야 한다 — 다르면 계획에 없던 곳에 쓰는 것이다.
        let dest = if plan.extract_to.is_some() {
            item.dest.clone()
        } else {
            if entry.origin != item.dest {
                out.push(Outcome {
                    id: item.id.clone(),
                    dest: item.dest.clone(),
                    result: Err(remedy_sdk::i18n::current().pick(
                        format!(
                            "색인과 본문의 경로가 다릅니다: 색인 '{}' 본문 '{}'",
                            item.dest, entry.origin
                        ),
                        format!(
                            "the index and the body disagree on the path: index '{}' body '{}'",
                            item.dest, entry.origin
                        ),
                    )),
                });
                continue;
            }
            item.dest.clone()
        };

        // **제자리 복원일 때만 종류가 갈린다.** 꺼내기 모드는 무엇이든 파일로
        // 내놓는 것이 뜻이므로 — 레지스트리 값도 바이트 그대로 파일이 된다.
        let result = if item.kind == EntryKind::RegistryValue && plan.extract_to.is_none() {
            restore_registry_value(backend, &dest, &entry)
        } else if item.kind == EntryKind::AvExclusion && plan.extract_to.is_none() {
            restore_av_exclusions(backend, &entry)
        } else if item.kind == EntryKind::TextLine && plan.extract_to.is_none() {
            restore_text_line(backend, &dest, &entry)
        } else if item.kind == EntryKind::CertStore
            && plan.extract_to.is_none()
            && !is_registry_target(&dest)
        {
            // Linux 인증서는 파일이다. **파일만 되돌리면 번들에 없는 채로 남고,
            // 그 상태의 "복원했다" 는 사실이 아니다** — 백엔드가 신뢰 저장소를
            // 다시 만드는 일까지 한다 (설계-09 P12 후속).
            backend
                .cert_restore(&dest, &entry.content)
                .map(|_| RestoreReport::default())
                .map_err(|e| e.to_string())
        } else if matches!(
            item.kind,
            EntryKind::RegistryKey | EntryKind::CertStore | EntryKind::Service
        ) && plan.extract_to.is_none()
        {
            // 셋 다 레지스트리 키 하나다. 담을 때 같은 문을 썼으니 되돌릴 때도
            // 같은 문이다 — 라벨만 다르다.
            let index: remedy_platform::write::RegKeyIndex =
                serde_json::from_value(entry.meta.clone()).unwrap_or_default();
            backend
                .registry_key_restore(&dest, &entry.content, &index)
                .map(|_| RestoreReport::default())
                .map_err(|e| e.to_string())
        } else if item.kind == EntryKind::BootConfig && plan.extract_to.is_none() {
            // 값 하나다. 레지스트리 값 복원과 같은 길을 쓴다.
            restore_registry_value(backend, &dest, &entry)
        } else if matches!(
            item.kind,
            EntryKind::Task | EntryKind::Unit | EntryKind::Cron
        ) && plan.extract_to.is_none()
        {
            // 작업은 파일로 되돌릴 수 없다. 정의를 자리에 써 넣어도 스케줄러의
            // 캐시가 모르면 등록되지 않고, 무결성 해시가 어긋나 "손상" 이 된다
            // (설계-01 D12). OS 의 등록 경로로만 되돌린다.
            // **곁가지까지 되돌린다.** 활성화 링크가 `meta` 에 실려 있다
            // (설계-09 P12 결정 5).
            let index: remedy_platform::write::PersistenceIndex =
                serde_json::from_value(entry.meta.clone()).unwrap_or_default();
            backend
                .persistence_restore(&dest, &entry.content, &index)
                .map(|_| RestoreReport::default())
                .map_err(|e| e.to_string())
        } else if item.kind == EntryKind::Directory && plan.extract_to.is_none() {
            let index: remedy_platform::write::DirIndex =
                serde_json::from_value(entry.meta.clone()).unwrap_or_default();
            backend
                .dir_restore(&dest, &entry.content, &index)
                .map_err(|e| e.to_string())
        } else if item.kind == EntryKind::FileStream && plan.extract_to.is_none() {
            // **호스트 파일을 되돌리지 않는다.** 스트림 하나를 지웠으므로
            // 되돌릴 것도 그 스트림 하나다 — 파일 전체를 쓰면 그 사이 파일에
            // 일어난 변경이 사라진다.
            //
            // `restore_file` 을 그대로 쓴다. 대상이 `<경로>:<스트림>` 이면
            // Windows 가 그 스트림에 쓴다.
            backend
                .restore_file(&dest, &entry.content, &FileMeta::default())
                .map_err(|e| e.to_string())
        } else {
            let meta: FileMeta = serde_json::from_value(entry.meta.clone()).unwrap_or_default();
            // **꺼낸 사본에 setuid · setgid · 파일 권능을 살리지 않고, 담아 둔 소유자로 바꾸지 않는다**(이슈 #172) —
            // 꺼낸 사본은 꺼낸 계정의 것이다([`FileMeta::for_extract`]).
            let extract = plan.extract_to.is_some();
            let meta = if extract { meta.for_extract() } else { meta };
            backend
                .restore_file(&dest, &entry.content, &meta)
                .map(|r| if extract { extract_report(r) } else { r })
                .map_err(|e| e.to_string())
        };

        // **되돌려 놓은 것이 재부팅 때 지워지면 복원이 아니다.**
        //
        // `file.delete_on_reboot` 는 파일을 남기고 큐에 넣는다. 복원이 파일을
        // 되돌려도 그 예약이 그대로면 다음 부팅이 다시 지운다 — 사람은 복원에
        // 성공했다고 보고받고 다음 날 파일이 없다. 이 취소는 **되돌린 경로
        // 하나만** 건드리고, 예약이 없으면 아무 일도 하지 않는다.
        //
        // 실패해도 복원 자체를 실패로 만들지 않는다. 파일은 제자리에 있고,
        // 남은 것은 예약뿐이다. 다만 조용히 넘기지도 않는다.
        let mut result = result;
        if result.is_ok() && plan.extract_to.is_none() {
            if let Err(e) = backend.cancel_delete_on_reboot(&dest) {
                result = Err(remedy_sdk::i18n::current().pick(
                    format!(
                        "되돌렸으나 재부팅 삭제 예약을 취소하지 못했습니다 — 재부팅하면 다시 \
                         사라집니다: {e}"
                    ),
                    format!(
                        "restored, but the delete-on-reboot request could not be canceled — \
                         it will disappear again after a reboot: {e}"
                    ),
                ));
            }
        }

        out.push(Outcome {
            id: item.id.clone(),
            dest,
            result,
        });
    }
    // 결과는 목록 차례로 낸다 — 화면이 그 차례로 적는다([`restore_order`] 가 바꾼 것은 수행 차례뿐이다).
    out.sort_by_key(|o| plan.items.iter().position(|i| i.id == o.id));
    Ok(out)
}

/// 되돌릴 차례 — 목록 차례 그대로이되, 줄 엔트리(cron · 텍스트 줄)의 칸만 종류마다 (파일, 줄 번호)
/// 오름차순으로 다시 앉힌다.
///
/// 한 파일의 줄은 아래 줄부터 지웠다(`remedy-plan` 의 계획 차례). 담아 둔 번호는 그 위의 줄이
/// 돌아와 있어야 제자리를 가리키므로 위 줄부터 넣는다. cron 은 끄기와 지우기가 한 줄을 하나씩 담아 같은 줄의
/// 엔트리가 둘인데, 둘째는 백엔드가 이미 돌아온 줄로 보고 건너뛴다(`persistence_restore`).
///
/// 다른 엔트리는 칸을 옮기지 않는다. 같은 파일을 줄 엔트리와 통째 엔트리가 함께 담은 복원(줄 빼기 뒤
/// 그 파일의 격리)은 줄을 먼저 넣고 통째로 덮어야 원래 바이트가 된다 — 목록을 통째로 뒤집으면 원본 위에
/// 그 줄이 한 번 더 들어간다. 꺼내기는 제자리에 넣지 않으므로 목록 차례 그대로다.
///
/// 남는 한계 — 종류마다 따로 세우고 파일은 자리 문자열 그대로 견준다. 한 파일의 줄을 cron 엔트리와 텍스트 줄
/// 엔트리가 함께 담았거나(`/etc/cron.d` 의 한 파일을 `persistence` 와 `text_config` 가 함께 고친 치료), 같은
/// 파일을 대소문자만 다른 경로로 담았으면(Windows) 그 파일의 줄이 번호 차례로 들어가지 않는다 — 자리가 어긋나거나,
/// 지우기가 거부돼 남은 줄을 한 번 더 넣을 수 있다.
fn restore_order<'p>(plan: &'p Plan, opened: &Opened<'_>) -> Vec<&'p Item> {
    let mut items: Vec<&Item> = plan.allowed().collect();
    if plan.extract_to.is_some() {
        return items;
    }
    for kind in [EntryKind::Cron, EntryKind::TextLine] {
        let slots: Vec<usize> = (0..items.len())
            .filter(|&i| items[i].kind == kind)
            .collect();
        let mut lines: Vec<(Option<(&str, u64)>, &Item)> = slots
            .iter()
            .map(|&i| (line_place(items[i], opened), items[i]))
            .collect();
        lines.sort_by(|a, b| a.0.cmp(&b.0));
        for (&i, (_, item)) in slots.iter().zip(lines) {
            items[i] = item;
        }
    }
    items
}

/// 줄 엔트리의 자리 `(파일, 줄 번호)` — cron 은 자리 `<파일>:<줄 번호>` 에서, 텍스트 줄은 담을 때 적은
/// `line_no`([`restore_text_line`] 이 읽는 그것)에서 읽는다. 그 꼴이 아니면 `None` 이고, 그런 엔트리끼리는 목록
/// 차례다.
fn line_place<'p>(item: &'p Item, opened: &Opened<'_>) -> Option<(&'p str, u64)> {
    match item.kind {
        EntryKind::Cron => {
            let (file, n) = item.dest.rsplit_once(':')?;
            Some((file, n.parse().ok()?))
        }
        EntryKind::TextLine => {
            let me = opened.manifest.entries.iter().find(|m| m.id == item.id)?;
            Some((item.dest.as_str(), me.meta.get("line_no")?.as_u64()?))
        }
        _ => None,
    }
}

/// 레지스트리 값 하나를 되돌린다.
///
/// **타입 번호가 없으면 되돌리지 않는다.** 바이트만 가지고 타입을 짐작해 쓰면
/// `REG_EXPAND_SZ` 였던 자리가 `REG_SZ` 가 되고, 그 값의 `%SystemRoot%` 가
/// 전개되지 않는 문자열로 남는다 — 복원한 것처럼 보이지만 동작이 다르다.
fn restore_registry_value(
    backend: &dyn PlatformWrite,
    dest: &str,
    entry: &remedy_quarantine::Entry,
) -> Result<remedy_platform::write::RestoreReport, String> {
    let Some(vtype) = entry.meta.get("vtype").and_then(|v| v.as_u64()) else {
        return Err(remedy_sdk::i18n::t(
            "백업에 레지스트리 값 타입이 없습니다 — 되돌릴 수 없습니다",
            "the backup has no registry value type — it cannot be restored",
        )
        .to_string());
    };
    backend
        .registry_write(
            dest,
            &remedy_platform::write::RegistryValueBackup {
                vtype: vtype as u32,
                bytes: entry.content.clone(),
            },
        )
        .map(|()| remedy_platform::write::RestoreReport {
            restored: vec![dest.to_string()],
            lost: Vec::new(),
        })
        .map_err(|e| e.to_string())
}

/// 지웠던 줄을 되돌린다 (설계-02 §9).
///
/// **줄 번호가 없으면 되돌리지 않는다.** 파일 끝에 붙이면 셸 프로필처럼 순서가
/// 뜻을 갖는 파일에서 다른 동작이 된다.
fn restore_text_line(
    backend: &dyn PlatformWrite,
    dest: &str,
    entry: &remedy_quarantine::Entry,
) -> Result<remedy_platform::write::RestoreReport, String> {
    let Some(line_no) = entry.meta.get("line_no").and_then(|v| v.as_u64()) else {
        return Err(remedy_sdk::i18n::t(
            "백업에 줄 번호가 없습니다 — 어디에 되돌릴지 알 수 없습니다",
            "the backup has no line number — there is no way to know where to put it back",
        )
        .to_string());
    };
    let line = String::from_utf8_lossy(&entry.content).into_owned();
    backend
        .text_line_restore(dest, line_no as u32, &line)
        .map(|()| remedy_platform::write::RestoreReport {
            restored: vec![format!("{dest}:{line_no}")],
            lost: Vec::new(),
        })
        .map_err(|e| e.to_string())
}

/// 보안 제품 예외 목록 전체를 되돌린다 (설계-02 §9).
fn restore_av_exclusions(
    backend: &dyn PlatformWrite,
    entry: &remedy_quarantine::Entry,
) -> Result<remedy_platform::write::RestoreReport, String> {
    let want: Vec<remedy_platform::write::AvExclusion> = serde_json::from_slice(&entry.content)
        .map_err(|e| {
            remedy_sdk::i18n::current().pick(
                format!("예외 목록을 읽을 수 없습니다: {e}"),
                format!("the exclusion list could not be read: {e}"),
            )
        })?;
    let n = want.len();
    backend
        .av_exclusions_write(&want)
        .map(|()| remedy_platform::write::RestoreReport {
            // **조각을 이어 붙이지 않는다.** 문장 구조가 언어마다 달라
            // 이으면 한쪽이 반드시 어색해진다.
            restored: vec![match remedy_sdk::i18n::current() {
                remedy_sdk::i18n::Lang::Ko => format!("보안 제품 예외 목록 {n}건"),
                remedy_sdk::i18n::Lang::En => {
                    format!("{n} AV exclusion entr{}", if n == 1 { "y" } else { "ies" })
                }
            }],
            lost: Vec::new(),
        })
        .map_err(|e| e.to_string())
}

/// 컨테이너를 파일에서 읽는다.
pub fn read_container(path: &std::path::Path) -> Result<Vec<u8>, RestoreError> {
    std::fs::read(path).map_err(|e| RestoreError::Quarantine(QuarantineError::Io(e)))
}

/// 평문 헤더만 본다. 키가 없어도 된다.
pub fn peek(bytes: &[u8]) -> Result<Sealed<'_>, RestoreError> {
    Ok(Sealed::parse(bytes)?)
}

/// 무엇으로 열 것인가.
///
/// 명시적으로 준 열쇠가 먼저다 — 사용자가 골랐는데 다른 것으로 열면, 어느 키가
/// 실제로 동작하는지 확인하려던 의도가 조용히 무시된다.
#[derive(Default)]
pub struct KeySource {
    pub passphrase: Option<String>,
    pub org_secret: Option<[u8; 32]>,
    /// 머신 키가 사는 곳. 없으면 만든다.
    pub state_dir: Option<std::path::PathBuf>,
}

/// 헤더의 wrap 슬롯 중 열 수 있는 것으로 콘텐츠 키를 얻는다.
pub fn unlock(
    header: &remedy_quarantine::Header,
    src: &KeySource,
) -> Result<ContentKey, RestoreError> {
    use remedy_quarantine::WrapKind;

    if let Some(pass) = &src.passphrase {
        let slot = header
            .wraps
            .iter()
            .find(|w| w.kind == WrapKind::Pass)
            .ok_or(RestoreError::NoSuchWrap(remedy_sdk::i18n::t(
                "패스프레이즈",
                "passphrase",
            )))?;
        return Ok(remedy_quarantine::unwrap_with_passphrase(pass, slot)?);
    }
    if let Some(sk) = &src.org_secret {
        let slot = header
            .wraps
            .iter()
            .find(|w| w.kind == WrapKind::Org)
            .ok_or(RestoreError::NoSuchWrap(remedy_sdk::i18n::t(
                "조직 복구",
                "organization recovery",
            )))?;
        return Ok(remedy_quarantine::unwrap_with_org_key(sk, slot)?);
    }

    let slot = header
        .wraps
        .iter()
        .find(|w| w.kind == WrapKind::Local)
        .ok_or(RestoreError::NoSuchWrap(remedy_sdk::i18n::t(
            "로컬", "local",
        )))?;
    let dir = src.state_dir.clone().unwrap_or_else(default_state_dir);
    let mk = remedy_quarantine::MachineKey::load_or_create(&dir.join("machine.key"))?;
    mk.unwrap(slot).map_err(RestoreError::from)
}

/// remedy 가 자기 상태를 두는 곳. 격리소와 머신 키가 여기 산다.
///
/// **시스템 경로가 아니다** — 여기 쓰는 것은 쓰기 경계를 지나지 않는다 (설계-03 §5).
pub fn default_state_dir() -> std::path::PathBuf {
    if cfg!(windows) {
        let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".into());
        std::path::PathBuf::from(base).join("remedy")
    } else {
        std::path::PathBuf::from("/var/lib/remedy")
    }
}

/// 이 실행의 격리 컨테이너 경로.
pub fn container_path(state_dir: &std::path::Path, run_id: &str) -> std::path::PathBuf {
    state_dir.join("quarantine").join(format!("{run_id}.rq"))
}

/// 보호 목록. **복원도 이 검사를 받는다.**
pub fn default_protected() -> remedy_plan::Protected {
    remedy_plan::Protected::new(
        remedy_plan::host_platform(),
        remedy_plan::expand_env_for_protection,
    )
}

/// 쓰기 백엔드. **시스템 경로에 쓰는 유일한 통로다.**
///
/// `apply` 와 `restore` 가 둘 다 이것을 쓴다.
///
/// # Windows 에서 `FsRestore` 를 돌려주면 안 된다
///
/// 한동안 그렇게 돼 있었고, 그 사이 P7 이 들여온 레지스트리·예약 작업 Op 은
/// **실제 머신에서 전부 `Unsupported` 로 실패했을 것**이다. 시험은 통과했다 —
/// 시험이 가짜 백엔드를 쓰기 때문이다. 즉 시험이 재던 것과 배포되는 것이
/// 달랐다. 그 갈라짐을 여기서 닫는다.
#[cfg(windows)]
pub fn default_backend() -> impl PlatformWrite {
    remedy_platform::windows::Live::new()
}

/// # Linux 에서도 같은 함정이 있었다
///
/// 이 자리는 P12 순서 8 까지 `FsRestore` 를 돌려줬고, **순서 8 이 Linux 쓰기
/// 백엔드를 세울 때 여기를 갱신하지 않았다.** 그 사이 게이트가 P12 로 올라
/// Linux Op 14종이 열렸는데, 실제 바이너리는 그중 파일 계열만 수행할 수 있었다 —
/// `persistence.*`·`service.*`·`process.kill`·`cert_store.remove` 는 실기기에서
/// `Unsupported` 로 실패했을 것이다. 시험은 통과했다. 시험이 가짜 백엔드를 쓰기
/// 때문이다.
///
/// **바로 위 Windows 문단과 같은 결함이 같은 함수에서 두 번 났다.** 그래서
/// 아래 [`the_default_backend_is_the_live_one`] 이 기계로 잡는다.
#[cfg(target_os = "linux")]
pub fn default_backend() -> impl PlatformWrite {
    remedy_platform::linux::Live::new()
}

/// 라이브 백엔드가 없는 플랫폼(macOS)에서는 파일 복원만 한다.
///
/// 격리함에서 파일을 되돌리는 것은 OS 고유 개념을 요구하지 않으므로 실행기 없이도
/// 선다. **`restore` 만 되고 `apply` 는 되지 않는 상태**이고, 그것이 이 플랫폼의
/// 현재 사실이다.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn default_backend() -> impl PlatformWrite {
    remedy_platform::write::FsRestore
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_platform::write::FsRestore;
    use remedy_quarantine::{Builder, Entry, Header, MachineKey};

    /// **배포되는 백엔드가 시험이 재는 백엔드와 같은 능력을 갖는가.**
    ///
    /// 이 함수는 같은 결함을 두 번 냈다 — Windows 에서 한 번(P7), Linux 에서 한
    /// 번(P12 순서 8). 둘 다 "라이브 백엔드를 만들었는데 여기를 안 고쳤다" 이고,
    /// 둘 다 **가짜 백엔드를 쓰는 시험이 전부 통과했다.**
    ///
    /// 이름으로 재는 이유: 능력을 하나씩 재면 새 Op 이 들어올 때 그 목록이
    /// 낡는다. `live()` 가 돌려주는 것과 **같은 것**이어야 한다는 한 문장이
    /// 그것을 대신한다.
    #[test]
    fn the_default_backend_is_the_live_one() {
        let Some(live) = remedy_platform::live() else {
            // 라이브 백엔드가 없는 플랫폼. `FsRestore` 가 맞다.
            assert_eq!(default_backend().backend_name(), FsRestore.backend_name());
            return;
        };
        assert_eq!(
            default_backend().backend_name(),
            live.backend_name(),
            "배포되는 백엔드가 이 플랫폼의 라이브 백엔드가 아니다 —              시험이 재는 것과 실제로 도는 것이 갈라진다"
        );
    }

    /// 계획을 세우되 **막은 사유가 영어 회차에서 한글로 나오지 않는가**를 함께
    /// 잰다. `blocked` 는 `errln!` 로 화면에 그대로 나가고 종료 코드 5 를 만든다.
    ///
    /// **이름을 `plan` 그대로 둔 것**은 아래 시험들을 고치지 않기 위해서다 —
    /// `use super::*` 로 들어온 이름을 로컬 정의가 가린다. `guard.rs` 의 `check`
    /// 래퍼와 같은 수다. 새 시험을 쓰는 사람도 그냥 `plan` 을 부르면 이 검사를
    /// 함께 받는다.
    fn plan(
        opened: &Opened<'_>,
        run_id: &str,
        backend: &dyn PlatformWrite,
        guards: &Guards<'_>,
        only: &[String],
        extract_to: Option<&str>,
    ) -> Result<Plan, RestoreError> {
        let p = super::plan(opened, run_id, backend, guards, only, extract_to)?;
        for i in &p.items {
            let Some(why) = &i.blocked else { continue };
            assert!(
                !why.chars().any(|c| ('가'..='힣').contains(&c)),
                "복원을 막은 사유가 영어 회차에서 한글로 나온다 ({}): {why}",
                i.dest
            );
        }
        Ok(p)
    }

    /// 되돌리되 **실패 사유가 영어 회차에서 한글로 나오지 않는가**를 함께 잰다.
    /// 이 문자열은 `restore` 화면에 한 항목씩 그대로 찍힌다. `plan` 래퍼와 같은
    /// 이유로 이름을 가린다.
    fn apply(
        plan: &Plan,
        opened: &Opened<'_>,
        key: &ContentKey,
        backend: &dyn PlatformWrite,
    ) -> Result<Vec<Outcome>, RestoreError> {
        let out = super::apply(plan, opened, key, backend)?;
        for o in &out {
            let Err(why) = &o.result else { continue };
            assert!(
                !why.chars().any(|c| ('가'..='힣').contains(&c)),
                "복원 실패 사유가 영어 회차에서 한글로 나온다 ({}): {why}",
                o.dest
            );
        }
        Ok(out)
    }

    /// **호스트 환경에 기대지 않는다.** 리눅스에서는 `%SystemRoot%` 가 전개되지
    /// 않아 보호 목록이 토큰 그대로 남고, 그러면 이 시험이 조용히 아무것도 재지
    /// 않게 된다 — 실제로 리눅스 검사에서 그렇게 드러났다.
    fn protected() -> remedy_plan::Protected {
        crate::pipeline::protected_for(&remedy_sdk::artifact::HostInfo {
            hostname: "W".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        })
    }

    fn build(entries: Vec<Entry>) -> (Vec<u8>, ContentKey) {
        let mk = MachineKey::from_bytes([1u8; 32]);
        let ck = ContentKey::generate().unwrap();
        let header = Header {
            run_id: "r1".into(),
            created: "2026-08-21T00:00:00Z".into(),
            core_version: "0".into(),
            cipher: "xchacha20poly1305".into(),
            wraps: vec![mk.wrap(&ck).unwrap()],
        };
        let mut b = Builder::new(header, "p");
        for e in entries {
            b.add(e);
        }
        (b.seal(&ck).unwrap(), ck)
    }

    /// **저널이 아무것도 보증하지 않는 상태.** 넘겨받은 컨테이너가 이렇다.
    fn nothing_vouched() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    fn entry(origin: &str) -> Entry {
        Entry {
            kind: EntryKind::File,
            origin: origin.into(),
            meta: serde_json::json!({}),
            content: b"payload".to_vec(),
        }
    }

    #[test]
    fn a_protected_directory_itself_is_blocked() {
        // **복원도 쓰기다.** 변조된 컨테이너가 보호 디렉터리 **자체**를
        // 지시하면 거부한다 — 계획기가 그 자리에서 거부하는 것과 같다.
        let (bytes, ck) = build(vec![entry("C:\\Windows\\System32")]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &[],
            None,
        )
        .unwrap();
        assert_eq!(p.blocked().count(), 1);
        assert!(p
            .blocked()
            .next()
            .unwrap()
            .blocked
            .as_ref()
            .unwrap()
            .contains(remedy_sdk::i18n::t("보호", "protected")));
        assert_eq!(p.allowed().count(), 0);
    }

    #[test]
    fn a_file_under_a_protected_directory_needs_the_journal() {
        // **계획기가 지울 수 있게 한 것은 되돌릴 수 있어야 한다.** 이 자리가
        // 무조건 막던 동안 System32 의 악성 DLL 을 지운 뒤 되돌릴 수 없었고,
        // Linux 는 `/etc`·`/usr` 가 보호 목록이라 systemd 유닛·cron·인증서가
        // **전부** 그 상태였다.
        //
        // **그렇다고 컨테이너가 시키는 대로 열면 안 된다.** 넘겨받은 격리물
        // 하나로 System32 에 임의 파일을 심을 수 있게 된다 — 컨테이너는
        // 패스프레이즈로도 열리므로 그 공격에 기계 장악이 필요하지 않다.
        //
        // 저널이 둘을 가른다. 여기서 두 방향을 다 잰다.
        let dest = "C:\\Windows\\System32\\evil.dll";
        let (bytes, ck) = build(vec![entry(dest)]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();

        // 보증이 없다 — 넘겨받은 컨테이너가 이렇다.
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &[],
            None,
        )
        .unwrap();
        assert_eq!(p.blocked().count(), 1);
        assert!(
            p.blocked()
                .next()
                .unwrap()
                .blocked
                .as_ref()
                .unwrap()
                .contains(remedy_sdk::i18n::t("저널", "journal")),
            "왜 막혔는지 저널을 말하지 않는다"
        );

        // 저널이 "우리가 그 자리에서 e0 을 담았다" 고 말한다.
        let mut vouch = BTreeMap::new();
        vouch.insert("e0".to_string(), dest.to_string());
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &vouch,
            },
            &[],
            None,
        )
        .unwrap();
        assert_eq!(p.blocked().count(), 0, "{:?}", p.blocked().next());
        assert_eq!(p.allowed().count(), 1);

        // **대상이 다르면 보증이 아니다.** 엔트리 id 만 맞춘 컨테이너가
        // 통과하면 이 검사는 이름 대조에 지나지 않는다.
        let mut wrong = BTreeMap::new();
        wrong.insert(
            "e0".to_string(),
            "C:\\Windows\\System32\\other.dll".to_string(),
        );
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &wrong,
            },
            &[],
            None,
        )
        .unwrap();
        assert_eq!(p.blocked().count(), 1, "다른 대상의 보증이 통했다");
    }

    #[test]
    fn the_journal_vouches_for_what_we_actually_backed_up() {
        // `vouched` 가 저널에서 무엇을 읽는지 잰다. 손으로 만든 지도로만 위
        // 시험을 돌리면 **실제 저널과 이어졌는지는 아무도 재지 않는다.**
        let dir = std::env::temp_dir().join("remedy-vouch-journal");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("journal")).unwrap();
        let path = remedy_journal::journal_path(&dir, "r7");
        let lines = [
            r#"{"rec":"intent","seq":1,"op":"file.delete","target":"C:\\x\\a.dll"}"#,
            r#"{"rec":"backup","seq":1,"entry_id":"e0"}"#,
            // 담지 못한 Action. **보증이 붙으면 안 된다** — 우리가 그 자리에서
            // 무엇을 꺼낸 적이 없다.
            r#"{"rec":"intent","seq":2,"op":"file.delete","target":"C:\\x\\b.dll"}"#,
        ];
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let v = vouched(&dir, "r7");
        assert_eq!(v.get("e0").map(String::as_str), Some(r"C:\x\a.dll"));
        assert_eq!(v.len(), 1, "담지 않은 것까지 보증했다: {v:?}");

        // 없는 run 은 빈 지도다. **없는 것을 보증으로 읽지 않는다.**
        assert!(vouched(&dir, "없는run").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_under_a_protected_one_is_still_blocked() {
        // 개별 파일과 나무는 다르다. 나무를 되돌리면 그 아래 무엇이 생기는지
        // 매니페스트가 정한다 — 계획기가 그 자리에서 재귀 삭제를 거부하는 것과
        // 짝이다.
        let (bytes, ck) = build(vec![Entry {
            kind: EntryKind::Directory,
            origin: "C:\\Windows\\System32\\evil".into(),
            meta: serde_json::json!({}),
            content: b"x".to_vec(),
        }]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &[],
            None,
        )
        .unwrap();
        assert_eq!(p.blocked().count(), 1);
    }

    #[test]
    fn an_unexpanded_token_is_refused() {
        // 불변식 R. 토큰이 남아 있으면 다른 머신에서 다른 곳으로 복원된다.
        let (bytes, ck) = build(vec![entry("%LOCALAPPDATA%\\Programs\\x\\a.exe")]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &[],
            None,
        )
        .unwrap();
        let b = p.blocked().next().unwrap();
        assert!(
            b.blocked
                .as_ref()
                .unwrap()
                .contains(remedy_sdk::i18n::t("불변식 R", "invariant R")),
            "{b:?}"
        );
    }

    #[test]
    fn a_relative_path_is_refused() {
        let (bytes, ck) = build(vec![entry("..\\..\\evil.exe")]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &[],
            None,
        )
        .unwrap();
        assert!(p
            .blocked()
            .next()
            .unwrap()
            .blocked
            .as_ref()
            .unwrap()
            .contains(remedy_sdk::i18n::t("절대 경로", "absolute path")));
    }

    #[test]
    fn extract_mode_flattens_the_path() {
        // 원본 경로를 그대로 이어 붙이면 `..` 이나 절대 경로가 대상 밖으로 나간다.
        // 드라이브 문자의 `:` 와 뒤따르는 `\` 가 각각 바뀌므로 `_` 가 둘이다.
        // 읽기 좋게 줄이지 않는 이유는, 줄이면 서로 다른 원본이 같은 이름으로
        // 겹칠 수 있어서다.
        assert_eq!(
            extract_path("D:\\out", "C:\\Users\\a\\x.exe"),
            "D:\\out\\C__Users_a_x.exe"
        );
        assert_eq!(
            extract_path("/tmp/out", "../../etc/passwd"),
            "/tmp/out/.._.._etc_passwd"
        );
    }

    #[test]
    fn extract_mode_ignores_the_protected_list() {
        // 꺼내기는 원본 자리에 쓰지 않는다. 시스템 경로 항목도 **꺼낼 수는 있어야**
        // 한다 — 그것이 오탐 복구의 마지막 수단이다.
        let (bytes, ck) = build(vec![entry("C:\\Windows\\System32\\kernel32.dll")]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &[],
            Some("D:\\out"),
        )
        .unwrap();
        assert_eq!(p.blocked().count(), 0);
        assert!(p.items[0].dest.starts_with("D:\\out"));
    }

    #[test]
    fn only_selected_entries_are_planned() {
        let (bytes, ck) = build(vec![entry("C:\\a\\x"), entry("C:\\b\\y")]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &["e1".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.items[0].id, "e1");
    }

    #[test]
    fn planning_writes_nothing() {
        let dir = std::env::temp_dir().join("remedy-restore-plan-test");
        let _ = std::fs::remove_dir_all(&dir);
        let dest = dir.join("x.bin");
        let (bytes, ck) = build(vec![entry(dest.to_str().unwrap())]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &[],
            None,
        )
        .unwrap();
        assert_eq!(p.allowed().count(), 1);
        assert!(!dest.exists(), "계산 단계가 파일을 만들었다");
        assert!(!dir.exists(), "계산 단계가 디렉터리를 만들었다");
    }

    #[test]
    fn a_full_round_trip_restores_the_bytes() {
        let dir = std::env::temp_dir().join("remedy-restore-rt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("되돌린 파일.bin");

        let (bytes, ck) = build(vec![Entry {
            kind: EntryKind::File,
            origin: dest.to_str().unwrap().to_string(),
            meta: serde_json::json!({ "readonly": false }),
            content: b"\x00\x01\x02original".to_vec(),
        }]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &[],
            None,
        )
        .unwrap();
        let out = apply(&p, &opened, &ck, &FsRestore).unwrap();

        assert_eq!(out.len(), 1);
        assert!(out[0].result.is_ok(), "{:?}", out[0].result);
        assert_eq!(std::fs::read(&dest).unwrap(), b"\x00\x01\x02original");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 복원 뒤 화면이 찍는 것은 계획이 되돌린다고 했는데 못 된 것뿐이다(이슈 #172 ①) — 계획이 이미 '복원 불가' 로
    /// 적은 것과 계획에 없던 칸은 다시 적지 않는다.
    #[test]
    fn after_restoring_only_what_the_plan_promised_and_missed_is_named() {
        let mut planned = RestoreReport {
            restored: ["content", "mtime", "owner", "mode"]
                .map(String::from)
                .to_vec(),
            lost: vec![],
        };
        planned.lose("ctime", "x");
        planned.lose("btime", "x");
        let mut got = RestoreReport {
            restored: ["content", "mtime"].map(String::from).to_vec(),
            lost: vec![],
        };
        got.lose("ctime", "x");
        got.lose("btime", "x");
        got.lose("owner", "Operation not permitted (os error 1)");
        got.lose("mode", "bits left off");
        got.lose("sacl", "not captured");
        let items: Vec<&str> = missed(&planned, &got)
            .iter()
            .map(|l| l.item.as_str())
            .collect();
        assert_eq!(items, ["owner", "mode"]);
        assert_eq!(
            missed(&planned, &got)[0].reason,
            "Operation not permitted (os error 1)"
        );

        // 다 되돌렸으면 아무것도 적지 않는다.
        assert!(missed(&planned, &planned).is_empty());
    }

    /// 꺼내기는 setuid · setgid 와 파일 권능(`security.capability`)을 빼고 소유자를 비운다 — 꺼낸 사본은 꺼낸 계정의
    /// 것이다. 나머지 칸(다른 확장 속성 포함)은 그대로다.
    ///
    /// 앞서는 소유자를 두라고 주장했다. 담아 둔 것은 숫자 uid 라 다른 기계에서 꺼내면 같은 번호의 다른 계정이 사본의
    /// 소유자가 되고, 같은 기계에서도 감염된 계정이 분석용 사본을 고칠 수 있다. 권능은 setuid 와 같은 부류다 — 남은
    /// 채로 꺼내면 누구든 그 사본을 실행해 권능을 얻는다.
    #[test]
    fn extracting_drops_the_setid_bits_the_file_capability_and_the_owner() {
        let m = FileMeta {
            mtime_unix: Some(7),
            mode: Some(0o106755),
            uid: Some(4242),
            gid: Some(4243),
            xattrs: [
                (
                    "security.capability".to_string(),
                    "AQAAAgAAAAA=".to_string(),
                ),
                ("user.note".to_string(), "eA==".to_string()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let x = m.for_extract();
        assert_eq!(x.mode, Some(0o100755));
        assert_eq!((x.uid, x.gid), (None, None));
        assert_eq!(x.xattrs.keys().collect::<Vec<_>>(), ["user.note"]);
        let mut rest = m.clone();
        rest.xattrs.remove("security.capability");
        assert_eq!(
            FileMeta {
                mode: m.mode,
                uid: m.uid,
                gid: m.gid,
                ..x.clone()
            },
            rest
        );
        assert_eq!(FileMeta::default().for_extract(), FileMeta::default());
    }

    /// 꺼낸 사본은 꺼낸 계정의 소유다 — 담아 둔 uid · gid 로 바꾸지 않고, 계획 · 복원 뒤 보고에 '소유자를 담지
    /// 않았다' 같은 소유자 줄도 서지 않는다(꺼내기는 소유자를 쓰지 않는다). root 로 돌면 담아 둔 4242 가 아니라 0:0
    /// 이어야 한다.
    #[cfg(unix)]
    #[test]
    fn an_extracted_copy_belongs_to_whoever_extracted_it() {
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata("/proc/self").unwrap();
        let dir = std::env::temp_dir().join("remedy-restore-extract-owner");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out").to_string_lossy().to_string();
        let file = |origin: &str, meta| Entry {
            kind: EntryKind::File,
            origin: origin.into(),
            meta,
            content: b"x".to_vec(),
        };
        let (bytes, ck) = build(vec![
            file(
                "/home/alice/secret.pdf",
                serde_json::json!({ "mode": 0o100600, "uid": 4242, "gid": 4243 }),
            ),
            // 1.26.0 까지의 격리물 — 소유자 칸이 없다.
            file(
                "/home/alice/old.pdf",
                serde_json::json!({ "mode": 0o100644 }),
            ),
        ]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let guards = Guards {
            protected: &protected(),
            vouched: &nothing_vouched(),
        };
        let p = plan(&opened, "r1", &FsRestore, &guards, &[], Some(&out)).unwrap();
        let owner_said = |r: &RestoreReport| {
            r.restored.iter().any(|x| x == "owner") || r.lost.iter().any(|l| l.item == "owner")
        };
        for i in &p.items {
            assert!(!owner_said(&i.report), "{}: {:?}", i.dest, i.report);
        }
        for o in apply(&p, &opened, &ck, &FsRestore).unwrap() {
            let r = o.result.as_ref().unwrap();
            assert!(!owner_said(r), "{}: {r:?}", o.dest);
            let md = std::fs::metadata(&o.dest).unwrap();
            assert_eq!((md.uid(), md.gid()), (me.uid(), me.gid()), "{}", o.dest);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 백엔드가 받은 메타데이터를 적는다(계획 · 쓰기). 되돌리기는 늘 성공한다.
    #[derive(Default)]
    struct Metas(std::cell::RefCell<Vec<(&'static str, FileMeta)>>);

    impl PlatformWrite for Metas {
        fn backend_name(&self) -> &'static str {
            "metas"
        }
        fn plan_restore(&self, _dest: &str, meta: &FileMeta) -> RestoreReport {
            self.0.borrow_mut().push(("plan", meta.clone()));
            RestoreReport::default()
        }
        fn restore_file(
            &self,
            _dest: &str,
            _content: &[u8],
            meta: &FileMeta,
        ) -> Result<RestoreReport, remedy_platform::PlatformError> {
            self.0.borrow_mut().push(("write", meta.clone()));
            Ok(RestoreReport::default())
        }
        fn quarantine_read(
            &self,
            _path: &str,
        ) -> Result<(Vec<u8>, FileMeta), remedy_platform::PlatformError> {
            Err(remedy_platform::PlatformError::Unsupported("읽지 않는다"))
        }
        fn destroy_file(&self, _path: &str) -> Result<(), remedy_platform::PlatformError> {
            Err(remedy_platform::PlatformError::Unsupported("지우지 않는다"))
        }
        fn exists(&self, _path: &str) -> bool {
            false
        }
    }

    /// 꺼내기만 setuid · setgid 와 소유자를 뺀 메타데이터를 계획과 쓰기에 넘긴다 — 제자리 복원은 담은 그대로다.
    #[test]
    fn only_extracting_hands_the_backend_a_meta_without_the_setid_bits() {
        let dir = std::env::temp_dir().join("remedy-restore-extract-meta");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let origin = dir.join("tool").to_string_lossy().to_string();
        let out = dir.join("out").to_string_lossy().to_string();
        let (bytes, ck) = build(vec![Entry {
            kind: EntryKind::File,
            origin: origin.clone(),
            meta: serde_json::json!({ "mode": 0o104755, "uid": 4242, "gid": 4242 }),
            content: b"x".to_vec(),
        }]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let guards = Guards {
            protected: &protected(),
            vouched: &nothing_vouched(),
        };
        let kept = (Some(4242), Some(4242));
        for (extract, mode, owner) in [
            (Some(out.as_str()), 0o100755, (None, None)),
            (None, 0o104755, kept),
        ] {
            let b = Metas::default();
            let p = plan(&opened, "r1", &b, &guards, &[], extract).unwrap();
            apply(&p, &opened, &ck, &b).unwrap();
            let seen = b.0.borrow();
            assert_eq!(
                seen.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
                ["plan", "write"]
            );
            for (k, m) in seen.iter() {
                assert_eq!(m.mode, Some(mode), "{extract:?} {k}");
                assert_eq!((m.uid, m.gid), owner, "{extract:?} {k}");
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 백엔드가 받은 자리를 차례대로 적는다. 되돌리기는 늘 성공한다.
    #[derive(Default)]
    struct Order(std::cell::RefCell<Vec<String>>);

    impl PlatformWrite for Order {
        fn backend_name(&self) -> &'static str {
            "order"
        }
        fn plan_restore(&self, _dest: &str, _meta: &FileMeta) -> RestoreReport {
            RestoreReport::default()
        }
        fn restore_file(
            &self,
            dest: &str,
            _content: &[u8],
            _meta: &FileMeta,
        ) -> Result<RestoreReport, remedy_platform::PlatformError> {
            self.0.borrow_mut().push(dest.to_string());
            Ok(RestoreReport::default())
        }
        fn quarantine_read(
            &self,
            _path: &str,
        ) -> Result<(Vec<u8>, FileMeta), remedy_platform::PlatformError> {
            Err(remedy_platform::PlatformError::Unsupported("읽지 않는다"))
        }
        fn destroy_file(&self, _path: &str) -> Result<(), remedy_platform::PlatformError> {
            Err(remedy_platform::PlatformError::Unsupported("지우지 않는다"))
        }
        fn exists(&self, _path: &str) -> bool {
            false
        }
        fn persistence_restore(
            &self,
            id: &str,
            _content: &[u8],
            _index: &remedy_platform::write::PersistenceIndex,
        ) -> Result<(), remedy_platform::PlatformError> {
            self.0.borrow_mut().push(id.to_string());
            Ok(())
        }
        fn text_line_restore(
            &self,
            path: &str,
            line_no: u32,
            _line: &str,
        ) -> Result<(), remedy_platform::PlatformError> {
            self.0.borrow_mut().push(format!("{path}#{line_no}"));
            Ok(())
        }
    }

    /// 지울 표시를 묻는 백엔드(2026-11-25). 물은 자리를 적고, 정해 둔 답을 낸다.
    struct Removing {
        /// `Some(b)` 면 `Ok(b)`, `None` 이면 읽지 못했다(`Err`).
        answer: Option<bool>,
        asked: std::cell::RefCell<Vec<String>>,
    }

    impl Removing {
        fn new(answer: Option<bool>) -> Self {
            Self {
                answer,
                asked: Default::default(),
            }
        }
    }

    impl PlatformWrite for Removing {
        fn backend_name(&self) -> &'static str {
            "removing"
        }
        fn plan_restore(&self, _dest: &str, _meta: &FileMeta) -> RestoreReport {
            RestoreReport::default()
        }
        fn restore_file(
            &self,
            _dest: &str,
            _content: &[u8],
            _meta: &FileMeta,
        ) -> Result<RestoreReport, remedy_platform::PlatformError> {
            unreachable!("계획만 잰다")
        }
        fn quarantine_read(
            &self,
            _path: &str,
        ) -> Result<(Vec<u8>, FileMeta), remedy_platform::PlatformError> {
            unreachable!("계획만 잰다")
        }
        fn destroy_file(&self, _path: &str) -> Result<(), remedy_platform::PlatformError> {
            unreachable!("계획만 잰다")
        }
        fn exists(&self, _path: &str) -> bool {
            false
        }
        fn service_delete_pending(
            &self,
            path: &str,
        ) -> Result<bool, remedy_platform::PlatformError> {
            self.asked.borrow_mut().push(path.to_string());
            self.answer
                .ok_or(remedy_platform::PlatformError::Unsupported("access denied"))
        }
    }

    const SVC: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\NeacSafe64";

    fn removing_entries() -> Vec<Entry> {
        let reg = |kind: EntryKind, origin: &str| Entry {
            kind,
            origin: origin.into(),
            meta: serde_json::json!({}),
            content: b"k".to_vec(),
        };
        vec![
            reg(EntryKind::Service, SVC),
            reg(EntryKind::RegistryValue, &format!(r"{SVC}\Start")),
            entry("/srv/x.bin"),
        ]
    }

    fn removing_plan(backend: &Removing, extract_to: Option<&str>) -> Plan {
        let (bytes, ck) = build(removing_entries());
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let guards = Guards {
            protected: &protected(),
            vouched: &nothing_vouched(),
        };
        plan(&opened, "r1", backend, &guards, &[], extract_to).unwrap()
    }

    /// **Windows 가 지우는 중인 서비스에는 되돌려 쓰지 않는다**(2026-11-25 · 이슈 #172 ⑥) — 랩에서 그 상태로
    /// 복원하자 0 · '3건 복원 완료' 였고, 핸들이 닫히자 SCM 이 되돌려 쓴 키를 하위 키째 지웠다. 서비스 정의 키와 그
    /// 아래 값 모두 막고, 다시 시작한 뒤에는 풀린다고 표시한다. 파일 항목에는 묻지 않는다.
    #[test]
    fn a_service_being_removed_is_held_back_until_a_restart() {
        let b = Removing::new(Some(true));
        let p = removing_plan(&b, None);

        let blocked: Vec<&Item> = p.blocked().collect();
        assert_eq!(blocked.len(), 2, "{:?}", p.items);
        assert!(
            blocked.iter().all(|i| i.restart_first && !i.by_link),
            "{blocked:?}"
        );
        assert!(p.allowed().all(|i| i.dest == "/srv/x.bin"), "{:?}", p.items);
        assert_eq!(
            *b.asked.borrow(),
            [SVC.to_string(), format!(r"{SVC}\Start")]
        );
    }

    /// 읽지 못한 것을 '지우는 중이 아니다' 로 접지 않는다 — 막되, 다시 시작하면 풀린다고는 말하지 않는다.
    #[test]
    fn a_service_whose_mark_cannot_be_read_is_held_back_too() {
        let b = Removing::new(None);
        let p = removing_plan(&b, None);
        let blocked: Vec<&Item> = p.blocked().collect();
        assert_eq!(blocked.len(), 2, "{:?}", p.items);
        assert!(blocked.iter().all(|i| !i.restart_first), "{blocked:?}");
    }

    #[test]
    fn a_service_that_is_not_being_removed_restores_as_before() {
        let b = Removing::new(Some(false));
        let p = removing_plan(&b, None);
        assert_eq!(p.blocked().count(), 0, "{:?}", p.items);
        assert_eq!(b.asked.borrow().len(), 2);
    }

    /// 꺼내기는 원래 자리에 쓰지 않으므로 묻지 않는다.
    #[test]
    fn extracting_does_not_ask_about_the_mark() {
        let b = Removing::new(Some(true));
        let p = removing_plan(&b, Some("/srv/out"));
        assert_eq!(p.blocked().count(), 0, "{:?}", p.items);
        assert!(b.asked.borrow().is_empty(), "{:?}", b.asked.borrow());
    }

    /// 한 파일의 cron 줄은 아래 줄부터 지웠으므로 위 줄부터 넣는다 — 담아 둔 번호는 위 줄이 돌아와
    /// 있어야 제자리를 가리킨다(이슈 #166 ③). 끄기 · 지우기가 한 줄을 하나씩 담아 같은 줄이 둘이다.
    /// cron 이 아닌 엔트리는 제 칸에서 돌고, 결과는 목록 차례로 나온다.
    #[test]
    fn cron_lines_are_restored_top_down_and_reported_in_list_order() {
        let cron = |origin: &str| Entry {
            kind: EntryKind::Cron,
            origin: origin.into(),
            meta: serde_json::json!({}),
            content: b"* * * * * /tmp/bad".to_vec(),
        };
        let (bytes, ck) = build(vec![
            cron("/srv/cron/root:5"),
            entry("/srv/x.bin"),
            cron("/srv/cron/root:3"),
            cron("/srv/cron/root:5"),
            cron("/srv/cron/root:3"),
        ]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let backend = Order::default();
        let p = plan(
            &opened,
            "r1",
            &backend,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &[],
            None,
        )
        .unwrap();
        let out = apply(&p, &opened, &ck, &backend).unwrap();

        assert_eq!(
            *backend.0.borrow(),
            [
                "/srv/cron/root:3",
                "/srv/x.bin",
                "/srv/cron/root:3",
                "/srv/cron/root:5",
                "/srv/cron/root:5",
            ]
        );
        let ids: Vec<&str> = out.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["e0", "e1", "e2", "e3", "e4"]);
        assert!(out.iter().all(|o| o.result.is_ok()), "{out:?}");
    }

    /// cron 줄 번호는 수로 견준다 — 자리 `<파일>:<번호>` 를 문자열로 견주면 `…:12` 가 `…:3` 앞에 서고, 아래 줄이
    /// 먼저 들어가 담아 둔 번호가 제자리를 가리키지 않는다. 목록에는 `:12` 를 앞에 둔다 — 치료가 아래 줄부터 담으므로
    /// 실제 격리물도 그 차례다. 위 시험의 `:3` · `:5` 는 두 견줌이 같은 차례를 내 이 변이를 잡지 못한다.
    #[test]
    fn cron_line_numbers_are_ordered_as_numbers_not_as_text() {
        let cron = |origin: &str| Entry {
            kind: EntryKind::Cron,
            origin: origin.into(),
            meta: serde_json::json!({}),
            content: b"* * * * * /tmp/bad".to_vec(),
        };
        let (bytes, ck) = build(vec![cron("/srv/cron/root:12"), cron("/srv/cron/root:3")]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let backend = Order::default();
        let guards = Guards {
            protected: &protected(),
            vouched: &nothing_vouched(),
        };
        let p = plan(&opened, "r1", &backend, &guards, &[], None).unwrap();
        let out = apply(&p, &opened, &ck, &backend).unwrap();

        assert_eq!(
            *backend.0.borrow(),
            ["/srv/cron/root:3", "/srv/cron/root:12"]
        );
        let ids: Vec<&str> = out.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["e0", "e1"]);
    }

    /// 텍스트 줄(`text_config.remove_line` · `hosts.restore_line` 이 담은 줄)도 같다 — 한 파일의 줄은 아래 줄부터
    /// 지웠으므로 담을 때 적은 번호(`meta.line_no`)의 오름차순으로 넣는다. 파일마다 따로 세우고, 다른 엔트리는
    /// 제 칸에서 돌며, 결과는 목록 차례로 나온다. 꺼내기는 제자리에 넣지 않으므로 목록 차례 그대로다.
    #[test]
    fn text_lines_are_restored_top_down_per_file() {
        let line = |origin: &str, n: u32| Entry {
            kind: EntryKind::TextLine,
            origin: origin.into(),
            meta: serde_json::json!({ "line_no": n }),
            content: format!("evil{n}=1").into_bytes(),
        };
        let (bytes, ck) = build(vec![
            line("/srv/app/a.conf", 12),
            line("/srv/app/b.conf", 2),
            entry("/srv/x.bin"),
            line("/srv/app/a.conf", 3),
            line("/srv/app/b.conf", 1),
        ]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let guards = Guards {
            protected: &protected(),
            vouched: &nothing_vouched(),
        };
        let backend = Order::default();
        let p = plan(&opened, "r1", &backend, &guards, &[], None).unwrap();
        let out = apply(&p, &opened, &ck, &backend).unwrap();

        assert_eq!(
            *backend.0.borrow(),
            [
                "/srv/app/a.conf#3",
                "/srv/app/a.conf#12",
                "/srv/x.bin",
                "/srv/app/b.conf#1",
                "/srv/app/b.conf#2",
            ]
        );
        let ids: Vec<&str> = out.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["e0", "e1", "e2", "e3", "e4"]);
        assert!(out.iter().all(|o| o.result.is_ok()), "{out:?}");

        // 꺼내기 — 백엔드는 받은 자리만 적고 쓰지 않는다.
        let backend = Order::default();
        let p = plan(&opened, "r1", &backend, &guards, &[], Some("/srv/out")).unwrap();
        let out = apply(&p, &opened, &ck, &backend).unwrap();
        let ids: Vec<&str> = out.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["e0", "e1", "e2", "e3", "e4"]);
        let wrote = backend.0.borrow();
        let tails: Vec<&str> = wrote
            .iter()
            .map(|w| w.rsplit('_').next().unwrap_or_default())
            .collect();
        assert_eq!(
            tails,
            ["a.conf", "b.conf", "x.bin", "a.conf", "b.conf"],
            "꺼내기가 차례를 바꿨다: {wrote:?}"
        );
    }

    /// 링크 가드를 묻는 백엔드(이슈 #172 ①). 물은 자리와 쓴 자리를 적는다.
    #[derive(Default)]
    struct Links {
        /// 자리 → 답. 없는 자리는 링크가 없고, `None` 은 묻지 못했다(`Err`).
        hits: std::cell::RefCell<BTreeMap<String, Option<remedy_platform::write::LinkHit>>>,
        asked: std::cell::RefCell<Vec<(String, remedy_platform::write::LastLink)>>,
        wrote: std::cell::RefCell<Vec<String>>,
    }

    impl Links {
        fn hit(&self, place: &str, hit: Option<remedy_platform::write::LinkHit>) {
            self.hits.borrow_mut().insert(place.to_string(), hit);
        }
    }

    impl PlatformWrite for Links {
        fn backend_name(&self) -> &'static str {
            "links"
        }
        fn plan_restore(&self, _dest: &str, _meta: &FileMeta) -> RestoreReport {
            RestoreReport {
                restored: vec!["content".into()],
                lost: vec![],
            }
        }
        fn restore_file(
            &self,
            dest: &str,
            _content: &[u8],
            _meta: &FileMeta,
        ) -> Result<RestoreReport, remedy_platform::PlatformError> {
            self.wrote.borrow_mut().push(dest.to_string());
            Ok(RestoreReport::default())
        }
        fn persistence_restore(
            &self,
            id: &str,
            _content: &[u8],
            _index: &remedy_platform::write::PersistenceIndex,
        ) -> Result<(), remedy_platform::PlatformError> {
            self.wrote.borrow_mut().push(id.to_string());
            Ok(())
        }
        fn quarantine_read(
            &self,
            _path: &str,
        ) -> Result<(Vec<u8>, FileMeta), remedy_platform::PlatformError> {
            Err(remedy_platform::PlatformError::Unsupported("읽지 않는다"))
        }
        fn destroy_file(&self, _path: &str) -> Result<(), remedy_platform::PlatformError> {
            Err(remedy_platform::PlatformError::Unsupported("지우지 않는다"))
        }
        fn exists(&self, _path: &str) -> bool {
            false
        }
        fn link_on_the_way(
            &self,
            place: &str,
            last: remedy_platform::write::LastLink,
        ) -> Result<Option<remedy_platform::write::LinkHit>, remedy_platform::PlatformError>
        {
            self.asked.borrow_mut().push((place.to_string(), last));
            match self.hits.borrow().get(place) {
                None => Ok(None),
                Some(Some(h)) => Ok(Some(h.clone())),
                Some(None) => Err(remedy_platform::PlatformError::Unsupported("access denied")),
            }
        }
    }

    fn alice_link() -> remedy_platform::write::LinkHit {
        remedy_platform::write::LinkHit::NotRoot {
            link: "/srv/home/alice/bin".into(),
            uid: 4242,
            to: "/etc/remedy-lab-d7".into(),
        }
    }

    fn open_and_plan(
        entries: Vec<Entry>,
        backend: &dyn PlatformWrite,
        extract_to: Option<&str>,
    ) -> (Vec<u8>, ContentKey, Plan) {
        let (bytes, ck) = build(entries);
        let p = {
            let sealed = peek(&bytes).unwrap();
            let opened = sealed.unlock(&ck).unwrap();
            let guards = Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            };
            plan(&opened, "r1", backend, &guards, &[], extract_to).unwrap()
        };
        (bytes, ck, p)
    }

    /// **사용자의 링크를 따라 root 로 쓰지 않는다**(이슈 #172 ①) — 1.26.0 은 alice 가 `~/bin` 을 root 의 폴더를
    /// 가리키는 링크로 바꿔 두자 그 너머에 alice 소유 4755 파일을 썼다. 제자리 복원만 묻고, 걸린 항목은 계획에서
    /// 막는다(종료 5). 꺼내기는 원래 자리에 쓰지 않으므로 묻지 않는다.
    #[test]
    fn a_link_on_the_way_holds_the_item_back_in_place_only() {
        use remedy_platform::write::LastLink;
        let tool = "/srv/home/alice/bin/tool";
        let b = Links::default();
        b.hit(tool, Some(alice_link()));
        let (_, _, p) = open_and_plan(vec![entry(tool), entry("/srv/ok.bin")], &b, None);

        let blocked: Vec<&Item> = p.blocked().collect();
        assert_eq!(blocked.len(), 1, "{:?}", p.items);
        let why = blocked[0].blocked.as_deref().unwrap();
        assert_eq!(blocked[0].dest, tool);
        assert!(
            why.contains("'/srv/home/alice/bin' → '/etc/remedy-lab-d7'") && why.contains("4242"),
            "{why}"
        );
        assert!(
            blocked[0].by_link && !blocked[0].restart_first,
            "{blocked:?}"
        );
        assert!(blocked[0].report.restored.is_empty(), "{:?}", blocked[0]);
        assert!(
            p.allowed().all(|i| i.dest == "/srv/ok.bin"),
            "{:?}",
            p.items
        );
        assert_eq!(
            *b.asked.borrow(),
            [
                (tool.to_string(), LastLink::Refused),
                ("/srv/ok.bin".to_string(), LastLink::Refused)
            ]
        );

        let b = Links::default();
        b.hit(tool, Some(alice_link()));
        let (_, _, p) = open_and_plan(vec![entry(tool)], &b, Some("/srv/out"));
        assert_eq!(p.blocked().count(), 0, "{:?}", p.items);
        assert!(b.asked.borrow().is_empty(), "{:?}", b.asked.borrow());
    }

    /// 묻지 못한 길은 '링크가 없다' 로 접지 않는다 — 막는다.
    #[test]
    fn a_way_that_cannot_be_checked_holds_the_item_back() {
        let b = Links::default();
        b.hit("/srv/x.bin", None);
        let (_, _, p) = open_and_plan(vec![entry("/srv/x.bin")], &b, None);
        let why = p.blocked().next().and_then(|i| i.blocked.clone());
        assert!(
            why.as_deref()
                .is_some_and(|w| w.contains("could not check") && w.contains("access denied")),
            "{why:?}"
        );
    }

    /// 묻는 자리는 복원이 **쓰는 자리**다 — cron 은 그 파일, 유닛은 유닛 파일과 활성화 링크를 다는 폴더, 디렉터리는
    /// 루트와 그 안의 폴더 · 파일. 줄만 고치는 자리 · 링크를 다는 폴더 · 유닛 파일(`systemctl link` 로 단 root 의
    /// 링크일 수 있다)은 자리 자체의 root 링크를 따라가고, 그 밖에 통째로 다시 쓰는 자리는 자리 자체가 링크면 걸린다.
    /// 레지스트리 값은 파일 시스템에 쓰지 않는다.
    #[test]
    fn the_places_asked_are_the_places_the_restore_writes() {
        use remedy_platform::write::LastLink::{Followed, Refused};
        let with = |kind: EntryKind, origin: &str, meta: serde_json::Value| Entry {
            kind,
            origin: origin.into(),
            meta,
            content: b"x".to_vec(),
        };
        let unit = "/srv/home/bob/.config/systemd/user/u.service";
        let wants = "/srv/home/bob/.config/systemd/user/default.target.wants";
        let b = Links::default();
        let (_, _, p) = open_and_plan(
            vec![
                with(EntryKind::Cron, "/srv/cron/alice:3", serde_json::json!({})),
                with(
                    EntryKind::TextLine,
                    "/srv/app/a.conf",
                    serde_json::json!({ "line_no": 2 }),
                ),
                with(
                    EntryKind::StructuredConfig,
                    "/srv/app/s.json",
                    serde_json::json!({ "file": {}, "key_path": "a" }),
                ),
                with(
                    EntryKind::Unit,
                    unit,
                    serde_json::json!({ "links": [format!("{wants}/u.service")] }),
                ),
                with(
                    EntryKind::Directory,
                    "/srv/ext",
                    serde_json::json!({
                        "dirs": ["_metadata"],
                        "files": [{ "rel": "a/m.json", "size": 1 }]
                    }),
                ),
                with(
                    EntryKind::RegistryValue,
                    r"HKLM\SOFTWARE\x\v",
                    serde_json::json!({ "vtype": 1 }),
                ),
                entry("/srv/x.bin"),
            ],
            &b,
            None,
        );
        assert_eq!(p.blocked().count(), 0, "{:?}", p.items);
        let want = [
            ("/srv/cron/alice", Followed),
            ("/srv/app/a.conf", Followed),
            ("/srv/app/s.json", Refused),
            (unit, Followed),
            (wants, Followed),
            ("/srv/ext", Refused),
            ("/srv/ext/_metadata", Refused),
            ("/srv/ext/a/m.json", Refused),
            ("/srv/x.bin", Refused),
        ]
        .map(|(s, l)| (s.to_string(), l));
        assert_eq!(*b.asked.borrow(), want);
    }

    /// 구조적 설정(JSON · XML · YAML 의 키를 뺀 항목)도 그 파일을 통째로 다시 쓴다 — 키를 뺀 파일은 남으므로 사용자가
    /// 그 이름이나 부모 폴더를 자기 링크로 바꿔 두기만 하면 된다. 가드가 이 종류를 묻지 않던 동안에는 쓰기가 그 링크를
    /// 따라 root 의 파일을 담아 둔 JSON 으로 덮을 수 있었다.
    #[test]
    fn a_link_on_the_way_to_a_structured_config_holds_it_back() {
        let s = "/srv/home/alice/.config/app/settings.json";
        let b = Links::default();
        b.hit(s, Some(alice_link()));
        let (_, _, p) = open_and_plan(
            vec![Entry {
                kind: EntryKind::StructuredConfig,
                origin: s.into(),
                meta: serde_json::json!({ "file": {}, "key_path": "a" }),
                content: b"{}".to_vec(),
            }],
            &b,
            None,
        );
        assert_eq!(p.blocked().count(), 1, "{:?}", p.items);
    }

    /// **쓰기 직전에 다시 본다** — 계획을 보이고 사람이 확인하는 사이에 폴더가 링크로 바뀌면 아무것도 쓰지 않고
    /// 멈춘다(5). 앞 차례의 항목도 쓰지 않는다.
    #[test]
    fn a_link_put_on_the_way_after_the_plan_stops_the_restore_before_any_write() {
        let tool = "/srv/home/alice/bin/tool";
        let b = Links::default();
        let (bytes, ck, p) = open_and_plan(vec![entry("/srv/a.bin"), entry(tool)], &b, None);
        assert_eq!(p.allowed().count(), 2, "{:?}", p.items);

        b.hit(tool, Some(alice_link()));
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let err = apply(&p, &opened, &ck, &b).expect_err("링크가 생겼는데 썼다");
        assert!(
            matches!(&err, RestoreError::LinkOnTheWay { id, dest, .. } if id == "e1" && dest == tool),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), remedy_sdk::artifact::ExitCode::GuardStop);
        let msg = err.to_string();
        assert!(
            msg.contains("nothing was written") && !msg.chars().any(|c| ('가'..='힣').contains(&c)),
            "{msg}"
        );
        assert!(b.wrote.borrow().is_empty(), "{:?}", b.wrote.borrow());
    }

    /// **색인과 본문의 메타데이터가 다르면 그 항목을 쓰지 않는다**(이슈 #172) — 계획과 쓰기 직전의 링크 가드는 색인의
    /// meta 로 쓸 자리를 정하고, 쓰기는 본문의 meta 로 유닛의 활성화 링크 · 폴더 목차를 만든다. 둘이 다르면 가드가
    /// 묻지 않은 자리(사용자가 링크로 바꾼 `x.wants`)에 쓴다. 봉인할 때 둘에 같은 값을 넣으므로 정직한 컨테이너는
    /// 어긋나지 않는다 — 경로가 다를 때와 같은 꼴로 그 항목을 실패로 둔다.
    #[test]
    fn an_item_whose_index_and_body_disagree_on_the_meta_is_not_written() {
        let unit = "/srv/home/bob/.config/systemd/user/u.service";
        let (bytes, ck) = build(vec![Entry {
            kind: EntryKind::Unit,
            origin: unit.into(),
            meta: serde_json::json!({
                "links": ["/srv/home/bob/.config/systemd/user/x.wants/u.service"]
            }),
            content: b"[Unit]\n".to_vec(),
        }]);
        let sealed = peek(&bytes).unwrap();
        let mut opened = sealed.unlock(&ck).unwrap();
        opened.manifest.entries[0].meta = serde_json::json!({ "links": [] });
        let b = Links::default();
        let guards = Guards {
            protected: &protected(),
            vouched: &nothing_vouched(),
        };
        let p = plan(&opened, "r1", &b, &guards, &[], None).unwrap();
        assert_eq!(p.allowed().count(), 1, "{:?}", p.items);

        let out = apply(&p, &opened, &ck, &b).unwrap();
        assert!(
            out[0]
                .result
                .as_ref()
                .is_err_and(|e| e.contains("disagree on the metadata")),
            "{out:?}"
        );
        assert!(b.wrote.borrow().is_empty(), "{:?}", b.wrote.borrow());
    }

    /// 배포되는 백엔드로 실제 링크를 잰다 — 1.26.0 의 꼴(사용자 소유 링크로 바뀐 부모). root 로 돌면 링크를 남의
    /// uid(4242)로 바꾼다. 계획이 막고, 계획 뒤에 바뀐 것은 수행이 막는다. 링크가 가리킨 자리에는 아무것도 없다.
    #[cfg(unix)]
    #[test]
    fn the_live_backend_does_not_restore_through_a_user_link() {
        use std::os::unix::fs::{lchown, symlink, MetadataExt};
        let dir = std::env::temp_dir().join("remedy-restore-link-guard");
        let _ = std::fs::remove_dir_all(&dir);
        let place = dir.join("root-place");
        let bin = dir.join("bin");
        std::fs::create_dir_all(&place).unwrap();
        let root = std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0);
        let put_link = || {
            symlink(&place, &bin).unwrap();
            if root {
                lchown(&bin, Some(4242), Some(4242)).unwrap();
            }
        };
        let tool = bin.join("tool").to_string_lossy().to_string();
        let entries = || {
            vec![Entry {
                kind: EntryKind::File,
                origin: tool.clone(),
                meta: serde_json::json!({ "mode": 0o104755, "uid": 4242, "gid": 4242 }),
                content: b"x".to_vec(),
            }]
        };
        let backend = default_backend();

        put_link();
        let (_, _, p) = open_and_plan(entries(), &backend, None);
        let why = p.blocked().next().and_then(|i| i.blocked.clone());
        assert!(
            why.as_deref()
                .is_some_and(|w| w.contains(&*bin.to_string_lossy())),
            "{why:?}"
        );

        std::fs::remove_file(&bin).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let (bytes, ck, p) = open_and_plan(entries(), &backend, None);
        assert_eq!(p.blocked().count(), 0, "{:?}", p.items);
        std::fs::remove_dir_all(&bin).unwrap();
        put_link();
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let err = apply(&p, &opened, &ck, &backend).expect_err("계획 뒤에 단 링크를 따라 썼다");
        assert!(matches!(err, RestoreError::LinkOnTheWay { .. }), "{err:?}");

        assert!(
            std::fs::read_dir(&place).unwrap().next().is_none(),
            "링크가 가리킨 자리에 썼다"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 되돌릴 자리 **자체**가 링크면 누구의 것이든 막는다. 따라 쓰면 본문과 `chmod` 는 대상에, `lchown` 은 링크에
    /// 가서 둘이 갈린다 — root 로 돌면 root 의 파일에 담아 둔 본문 · 4755 가 앉아 root 소유 setuid 가 된다. 계획이
    /// 막은 뒤 수행을 불러도 쓰지 않는다.
    #[cfg(unix)]
    #[test]
    fn the_live_backend_does_not_restore_onto_a_link_at_the_place() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = std::env::temp_dir().join("remedy-restore-link-itself");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let existing = dir.join("root-file");
        std::fs::write(&existing, b"root's own").unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
        let tool = dir.join("tool");
        symlink(&existing, &tool).unwrap();
        let (bytes, ck, p) = open_and_plan(
            vec![Entry {
                kind: EntryKind::File,
                origin: tool.to_string_lossy().to_string(),
                meta: serde_json::json!({ "mode": 0o104755, "uid": 4242, "gid": 4242 }),
                content: b"quarantined".to_vec(),
            }],
            &default_backend(),
            None,
        );
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let _ = apply(&p, &opened, &ck, &default_backend());

        let md = std::fs::metadata(&existing).unwrap();
        assert_eq!(
            (
                std::fs::read(&existing).unwrap(),
                md.permissions().mode() & 0o7777
            ),
            (b"root's own".to_vec(), 0o644),
            "링크를 따라 그 대상에 썼다"
        );
        let why = p.blocked().next().and_then(|i| i.blocked.clone());
        assert!(
            why.as_deref()
                .is_some_and(|w| w.starts_with("the restore place is a link")),
            "{why:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn blocked_items_are_never_written() {
        // 계획에서 막힌 것은 수행에서도 건드리지 않는다.
        let (bytes, ck) = build(vec![entry("C:\\Windows\\System32")]);
        let sealed = peek(&bytes).unwrap();
        let opened = sealed.unlock(&ck).unwrap();
        let p = plan(
            &opened,
            "r1",
            &FsRestore,
            &Guards {
                protected: &protected(),
                vouched: &nothing_vouched(),
            },
            &[],
            None,
        )
        .unwrap();
        let out = apply(&p, &opened, &ck, &FsRestore).unwrap();
        assert!(out.is_empty(), "막힌 항목이 수행됐다");
    }
}
