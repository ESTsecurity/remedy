//! `remediate` 에서 Action 을 도출한다 (설계-03 §2).
//!
//! # 플러그인은 "무엇" 만 말한다
//!
//! 플러그인이 선언하는 것은 **무엇이 남아 있으면 안 되는가**뿐이다. 어느 Op 으로
//! 그것을 이룰지, 어떤 순서로 돌지, 무엇을 백업할지는 전부 여기서 정한다
//! (설계-02 §6). 그래야 파괴 동작의 종류가 코어의 닫힌 집합 안에 머문다.
//!
//! # 위험이 낮은 Op 를 고른다
//!
//! 같은 목적을 이루는 Op 이 여럿이면 덜 위험한 쪽이다. 파일 제거는
//! `file.quarantine_only` 다 — 격리소로 **옮기는** 것이라 되돌리기가 Op 의 정의
//! 자체에 들어 있다. `file.delete`(P7)는 백업을 하더라도 되돌리기가 별도 경로다.
//!
//! # 못 하는 것을 조용히 빼지 않는다
//!
//! 아직 구현되지 않은 Op 이 필요한 항목은 계획에서 빠지되 **이유와 함께 남는다.**
//! 관측이 불완전할 수 있듯 계획도 불완전할 수 있고, 둘 다 말하지 않으면 완전한
//! 것으로 읽힌다. 이것을 빠뜨리면 "치료했다" 가 절반만 참인 채로 보고된다.

use crate::{Allowed, Mode};
use remedy_sdk::artifact::{
    Action, BackupRef, DeferredItem, Evidence, ScanEnvelope, UserImpact, UserImpactKind,
};
use remedy_sdk::catalog::{Op, Platform, Subject};
use remedy_sdk::manifest::{PluginManifest, RemoveTarget, RestoreTarget};

/// 도출 결과.
pub struct Derived {
    pub actions: Vec<Action>,
    pub deferred: Vec<DeferredItem>,
}

/// 이 코어가 실제로 수행할 수 있는 Op 인가.
///
/// `implemented_in` 은 SDK 가 들고 있고 `xtask trace` 가 설계-09 와 대조한다.
/// 여기서 다시 적지 않는 이유가 그것이다 — 두 곳에 적으면 갈라진다.
///
/// **게이트 값도 같은 이유로 SDK 것을 쓴다.** 여기에 `CURRENT_PHASE` 를 따로
/// 두고 있었고 실제로 갈라졌다 — 계획기는 P6, SDK 는 P4 였다. 그래서 실행기가
/// `file.quarantine_only` 를 수행하는 동안 가이드는 "현재 코어: P4" 라고 적혀
/// 있었다. 다음 Phase 로 올릴 때 고칠 곳은 `remedy_sdk::IMPLEMENTED_THROUGH`
/// 한 줄이다.
fn available(op: Op, platform: Platform) -> bool {
    // **플랫폼마다 다른 Phase 다.** `None` 은 그 플랫폼에 개념이 없다는 뜻이고
    // (레지스트리·대체 데이터 스트림처럼) 영원히 오지 않는다 (설계-09 P12).
    //
    // 이것이 없으면 Linux 스냅샷에서 Windows 전용 Op 이 계획에 들어가고
    // **실행에서 실패한다** — 계획은 초록인데 부분 실패로 끝난다.
    let from = match platform {
        Platform::Windows => Some(op.info().implemented_in),
        Platform::Linux => op.info().linux_from,
        // macOS 는 지원 대상이 아니다. 스냅샷이 그것을 말하면 아무것도 하지
        // 않는 것이 옳다 — 모르는 플랫폼에서 파괴하지 않는다.
        Platform::Darwin => None,
    };
    from.is_some_and(|p| p <= remedy_sdk::IMPLEMENTED_THROUGH)
}

/// subject 를 제거할 때 쓰는 Op.
///
/// **가장 덜 위험한 것부터** 적는다. 앞의 것이 아직 없으면 다음을 본다.
/// 한 subject 를 제거하는 방법. **택일인가 차례인가.**
///
/// 대부분은 택일이다 — 파일은 격리하거나 지우거나 둘 중 하나이지 둘 다가
/// 아니다. **서비스만 차례다.** 설계-03 §2 가 그 자리에서
/// `복구 동작 제거 → 정지 → 비활성화 → 삭제` 를 고정했고, 그중 하나만
/// 해서는 서비스가 사라지지 않는다.
///
/// # 왜 형으로 나누는가
///
/// 한 목록에 섞어 두고 "첫 번째로 쓸 수 있는 것" 을 고르면 두 뜻이 한 자료에
/// 눌러앉는다. 실제로 그랬다 — 서비스 목록이
/// `[ServiceDisable, ServiceDelete]` 였고, 계획기는 **언제나 비활성화 하나만**
/// 냈다. 복구 동작 제거도 정지도 갈 길이 없었고, VM 하네스가 실증한
/// "순서를 지키면 SCM 을 이긴다" 가 실제 계획으로는 **도달할 수 없는 성질**
/// 이었다 (설계-09 P8, 게이트를 P8 로 올리면서 드러났다).
#[derive(Clone, Copy)]
enum Removal {
    /// 쓸 수 있는 첫 번째 하나를 고른다.
    Choice(&'static [Op]),
    /// 쓸 수 있는 것을 **전부** 낸다. 순서는 `stage()` 가 정한다.
    Sequence(&'static [Op]),
}

impl Removal {
    fn ops(self) -> &'static [Op] {
        match self {
            Removal::Choice(o) | Removal::Sequence(o) => o,
        }
    }
}

/// 이 subject 로 **실제로 계획에 들어갈 수 있는** Op.
///
/// # 왜 `removal_ops(x).ops()` 를 그대로 쓰면 안 되는가
///
/// **택일은 하나만 낸다.** `split_removal` 이 첫 번째로 가용한 것을 고르고,
/// 하나도 가용하지 않으면 첫 번째 이름으로 미룬다 — 어느 쪽이든 뒤엣것은
/// 어떤 계획에도 들어가지 않는다. 그것을 "계획 가능" 으로 세면
/// [`plannable_ops`] 가 존재하는 이유가 무너진다: 아무도 부를 수 없는 Op 이
/// 목록에 있다는 이유로 조용해진다.
///
/// 2026-09-02 에 그것이 실제로 둘 있었다 — `file.delete` 는 격리가 언제나
/// 먼저라 뽑히지 않고, `boot.restore_default` 는 대상을 지목할 수 없다.
pub(crate) fn producible_ops(subject: Subject) -> Vec<Op> {
    // **부팅 구성은 대상을 지목할 수 없다.** `BootConfigRecord` 에 `path` 도
    // `source` 도 `id` 도 `hive`/`key` 도 없어 `target_of` 가 `None` 을
    // 돌려주고 그 Action 이 버려진다 (아래 `removal_ops` 의 같은 주석).
    if matches!(subject, Subject::BootConfig) {
        return Vec::new();
    }
    match removal_ops(subject) {
        Removal::Sequence(o) => o.to_vec(),
        Removal::Choice(o) => {
            let mut out: Vec<Op> = [Platform::Windows, Platform::Linux]
                .into_iter()
                .filter_map(|p| o.iter().copied().find(|x| available(*x, p)))
                .collect();
            // 어느 플랫폼에서도 가용하지 않으면 **첫 번째 이름으로** 미뤄진다.
            out.extend(o.first().copied());
            out.sort();
            out.dedup();
            out
        }
    }
}

fn removal_ops(subject: Subject) -> Removal {
    match subject {
        // 격리는 옮기는 것이라 되돌리기가 Op 의 정의에 들어 있다. 삭제는 그 다음이다.
        Subject::File | Subject::Indicator => {
            Removal::Choice(&[Op::FileQuarantineOnly, Op::FileDelete])
        }
        // 서비스와 같은 이유로 **차례**다. 비활성화만 하면 예약 작업 정의가
        // 그대로 남고, 사용자는 작업 스케줄러에서 꺼진 악성 작업을 본다 —
        // "무엇이 남아 있으면 안 되는가" 에 답하지 못한 것이다.
        //
        // 설계-03 §2 의 3단계가 "비활성화 (삭제 아님)" 인 것은 **그 단계에서**
        // 지우지 않는다는 뜻이지 지우지 않는다는 뜻이 아니다. `persistence.delete` 는
        // `regenerator` 라 5단계(유발자 제거)에 놓인다. 설계-07 시나리오 A 도
        // seq 2(disable)와 seq 5(delete)를 **둘 다** 기대한다.
        Subject::Persistence => Removal::Sequence(&[Op::PersistenceDisable, Op::PersistenceDelete]),
        Subject::Autorun => Removal::Choice(&[Op::AutorunRemove]),
        // **설계-03 §2 의 차례 그대로다.** 1단계(자동 소생 차단)가 복구 동작
        // 제거와 정지를, 3단계(재기동 차단)가 비활성화를, 5단계(유발자 제거)가
        // 삭제를 맡는다 — `service.delete` 는 `regenerator` 라 5단계다.
        Subject::Service => Removal::Sequence(&[
            Op::ServiceClearRecovery,
            Op::ServiceStop,
            Op::ServiceDisable,
            Op::ServiceDelete,
        ]),
        Subject::Process => Removal::Choice(&[Op::ProcessKill]),
        Subject::RegistryValue => Removal::Choice(&[Op::RegistryDeleteValue]),
        Subject::RegistryKey => Removal::Choice(&[Op::RegistryDeleteKey]),
        Subject::TextConfig | Subject::HostsEntry => Removal::Choice(&[Op::TextConfigRemoveLine]),
        Subject::StructuredConfig => Removal::Choice(&[Op::StructuredConfigRemoveKey]),
        Subject::Shortcut => Removal::Choice(&[Op::ShortcutStripArgs]),
        Subject::BrowserExtension => Removal::Choice(&[Op::BrowserExtRemove]),
        Subject::CertStore => Removal::Choice(&[Op::CertStoreRemove]),
        // **이 줄은 지금 도달하지 않는다.** `BootConfigRecord` 에는 `path` 도
        // `source` 도 `id` 도 `hive`/`key` 도 없어 `target_of` 가 `None` 을
        // 돌려주고, 아래 `(_, None) => continue` 가 그 Action 을 버린다.
        // 즉 부팅 구성 subject 로는 **어떤 치료도 계획되지 않는다** (2026-08-31).
        //
        // 카탈로그에 Op 이 있다는 것이 그 길이 열려 있다는 뜻은 아니다 —
        // 대상을 어떻게 짚을지가 함께 정해져야 한다.
        Subject::BootConfig => Removal::Choice(&[Op::BootRestoreDefault]),
        Subject::AvExclusion => Removal::Choice(&[Op::AvRestoreExclusions]),
        Subject::ProxyConfig => Removal::Choice(&[Op::ProxyRestore]),
        Subject::FirewallRule => Removal::Choice(&[Op::FirewallRestoreRule]),
        // **패키지에는 치료가 없다. 빈 것이 맞다** (C-2 · 2026-10-27).
        //
        // 설치된 패키지를 지우거나 올리는 것은 **공급사의 일**이고 설계-00 §3 이
        // 그것을 영구히 밖에 둔다 — 전용백신이 `php8.2` 를 업그레이드하면
        // 의존 트리를 끌고 와 사이트를 멈출 수 있고, 그것은 되돌릴 수 있는
        // 파괴가 아니다. 이 subject 는 **점검의 근거**다.
        //
        // 빈 `Choice` 는 `split_removal` 에서 고른 것도 미룬 것도 없음이 된다.
        // **미룸으로도 빠지지 않는 것이 요점이다** — 보류는 *"그 Op 이 나중에
        // 온다"* 는 약속이고, 여기서는 오지 않는다. `BootConfig` 와 다르다:
        // 그쪽은 Op 이 있고 대상을 짚지 못해 도달하지 않는 자리다.
        Subject::Package => Removal::Choice(&[]),
        // **소켓을 닫는 것은 치료가 아니다** — 그 소켓을 연 프로세스가 다시 연다
        // (설계-01 D11 근거 1). 찾기 전용이고, 위 `Package` 와 같은 빈 것이다.
        Subject::UnixSocket => Removal::Choice(&[]),
        // **아카이브 안을 고치는 것은 치료가 아니다** (코어 1.11.0). jar 에서 클래스를 빼면 서명 · 무결성을 보는
        // 앱이 멈추고, 어느 판으로 올릴지는 그 앱을 만든 쪽의 일이다. 찾기 전용 — 위 `Package` 와 같은 빈 것이다.
        Subject::ArchiveEntry => Removal::Choice(&[]),
        // **커널을 올리거나 다시 시작하는 것은 치료가 아니다** (코어 1.28.0). 지금 도는 커널은 판정의 근거이고,
        // 고친 커널을 깔고 다시 시작하는 것은 운영자의 일이다 — 서비스를 멈출 수 있고 되돌릴 수 있는 파괴가 아니다.
        // 찾기 전용 — 위 `Package` 와 같은 빈 것이다.
        Subject::Kernel => Removal::Choice(&[]),
    }
}

/// 이 제거 방법에서 **낼 것과 미룰 것**을 가른다.
///
/// # 왜 따로 떼는가
///
/// 게이트가 P8 이 되면서 모든 subject 가 쓸 수 있는 제거 Op 을 최소 하나씩
/// 갖게 됐다. 그래서 "쓸 수 없어서 미룬다" 는 갈래가 **어떤 subject 로도
/// 재현되지 않는다** — `derive` 를 통해서만 잴 수 있으면 그 갈래는 시험 없이
/// 남는다. 여기로 떼어 두면 임의의 `Removal` 로 직접 잴 수 있다.
///
/// 미룸이 택일과 차례에서 다르다는 것이 요점이다. **택일은 하나면 충분하므로**
/// 고르지 못한 나머지는 미룸이 아니다. **차례는 조각이 다 있어야 하므로**
/// 빠진 것마다 이름을 남긴다 — 조용히 빠지면 이 계획이 치료의 전부인 것처럼
/// 읽힌다 (설계-03 §2).
fn split_removal(removal: Removal, platform: Platform) -> (Vec<Op>, Vec<Op>) {
    let ops = removal.ops();
    match removal {
        Removal::Choice(_) => match ops.iter().copied().find(|o| available(*o, platform)) {
            Some(op) => (vec![op], Vec::new()),
            // 하나도 없으면 **첫 번째 이름으로** 미룬다. 그것이 이 subject 를
            // 제거하는 기본 수단이고, 사람이 읽을 이름은 그것이다.
            None => (Vec::new(), ops.first().copied().into_iter().collect()),
        },
        Removal::Sequence(_) => ops.iter().copied().partition(|o| available(*o, platform)),
    }
}

/// 이 증거를 제거할 Op 후보. **스냅샷이 잠금을 안다.**
///
/// # 왜 계획기가 정하는가
///
/// 잠긴 파일을 실행기가 만나 `file.delete_on_reboot` 로 갈아타면, 그것은
/// "조건 분기로 동작을 추가" 하는 것이라 불변식 P 가 깨진다 (설계-03 §1).
/// 그러면 **드라이런이 보여준 것과 실행한 것이 달라지고**, G3 는 계획에 없는
/// 레지스트리 쓰기를 위반으로 잡는다.
///
/// 대신 스냅샷에서 판단한다. 대상이 **실행 중인 프로세스의 이미지이거나 로드된
/// 모듈**이면 지금은 지울 수 없다 — 그 사실은 스냅샷만으로 결정적이고, 같은
/// 스냅샷은 언제나 같은 계획을 낸다. **잠그는 플랫폼의 이야기다**
/// ([`running_images_are_locked`]).
///
/// 프로세스를 먼저 죽이면 잠금이 풀리지만 `process.kill` 은 P8 이다. 그것이
/// 들어오면 **같은 계획 안에 그 프로세스를 죽이는 Action 이 있는가**를 함께
/// 봐야 한다.
fn removal_ops_for(e: &Evidence, scan: &ScanEnvelope) -> Removal {
    if e.subject == Subject::File
        && running_images_are_locked(crate::snapshot_platform(&scan.host))
        && locked_by_a_process(e, scan)
    {
        return Removal::Choice(&[Op::FileDeleteOnReboot]);
    }
    removal_ops(e.subject)
}

/// 돌고 있는 것이 **제 파일을 잠그는** 플랫폼인가.
///
/// Windows 는 실행 중인 이미지와 로드된 모듈을 지우지 못해 재부팅으로 미룬다.
/// **리눅스는 잠그지 않는다** — 지우는 것이 막히지 않으므로 평소의 제거로 끝난다.
/// 카탈로그가 리눅스에서 `file.delete_on_reboot` 를 닫은 까닭이 그것이다
/// ("없는 것이 아니라 필요 없다").
///
/// 이것을 보지 않으면 리눅스에서 **데몬의 실행 파일이 미룸으로 빠진다** — 필요
/// 없다고 닫아 둔 Op 을 골랐기 때문이다. 랩 VM 에서 그랬다 (설계-09 P12
/// "systemd `Restart=` 데몬 실증", 2026-09-29).
///
/// [`removal_ops_for`] 와 [`plannable_ops_on`] 이 함께 읽는다. 둘이 따로 정하면
/// 계획 가능 표가 계획기가 내지 않는 Op 을 약속한다.
fn running_images_are_locked(platform: Platform) -> bool {
    platform == Platform::Windows
}

/// 이 파일이 실행 중인 무언가에 잡혀 있는가.
fn locked_by_a_process(e: &Evidence, scan: &ScanEnvelope) -> bool {
    let Some(path) = e.target.get("path").and_then(|v| v.as_str()) else {
        return false;
    };
    scan.body.evidence.iter().any(|other| {
        if other.subject != Subject::Process {
            return false;
        }
        let same = |v: Option<&serde_json::Value>| {
            v.and_then(|x| x.as_str())
                .is_some_and(|s| s.eq_ignore_ascii_case(path))
        };
        same(other.target.get("image_path"))
            || other
                .target
                .get("modules")
                .and_then(|m| m.as_array())
                .is_some_and(|ms| ms.iter().any(|m| same(Some(m))))
    })
}

/// 증거가 가리키는 대상.
///
/// # 레지스트리는 조각으로 온다
///
/// `registry_value` 레코드는 `hive` · `key` · `name` 이 따로다 — 룰이 셋을
/// 나눠 물을 수 있어야 하기 때문이다. 그래서 `path` 도 `source` 도 `id` 도 없고,
/// **여기서 합치지 않으면 대상이 없는 증거가 되어 Action 이 만들어지지 않는다.**
/// `registry.delete_value` 가 영영 계획되지 않는 자리였다.
///
/// 합치는 모양은 수집기가 `autorun.id` 에 쓰는 것과 같다(`<하이브>\<키>\<값>`).
/// 두 자리가 다른 모양을 쓰면 같은 레지스트리 값이 Op 에 따라 다른 문자열로
/// 계획에 들어가고, 보호 경로 대조와 G3 가 그것을 다른 대상으로 본다.
fn target_of(e: &Evidence, platform: Platform) -> Option<String> {
    let s = |k: &str| e.target.get(k).and_then(|v| v.as_str());
    // **`source` 가 값이 아니라 키인 subject 들.** 그대로 쓰면 키 하나를 값
    // 이름으로 오해해 엉뚱한 것을 지운다.
    match e.subject {
        // 제외 대상은 **값 이름**이다 (`Exclusions\Paths\<경로>`).
        Subject::AvExclusion => return Some(format!("{}\\{}", s("source")?, s("value")?)),
        // 자동 실행 하나도 **레지스트리 값 하나**다. `source` 는 그 값이 사는
        // 키(`...\Run`)이므로 그대로 쓰면 키를 값 이름으로 오해한다. 아래
        // 폴백 사슬이 `source` 를 집어 실제로 그렇게 됐고, **백업이 그 자리를
        // 읽지 못해 `apply` 가 파괴 전에 가드 중단(exit 5)으로 끝났다** —
        // 감염 VM 에서 치료를 처음 돌렸을 때 드러났다 (설계-09 P9 항목 3).
        //
        // 지우는 것이 값 하나인지 키 전체인지는 **모양으로 갈리므로**, 여기서
        // 한 칸을 빠뜨리면 G6 의 보호 목록 대조도 다른 대상을 보게 된다.
        Subject::Autorun => {
            // Linux 자동실행은 **파일 하나**다. 수집기가 `id` 에 그 경로를 담는다.
            if platform != Platform::Windows {
                return s("id").map(str::to_string);
            }
            return Some(format!("{}\\{}", s("source")?, s("name")?));
        }
        // 규칙 하나가 값 하나이고 `id` 가 그 값 이름이다.
        Subject::FirewallRule => return Some(format!("{}\\{}", s("source")?, s("id")?)),
        // **작업의 자리는 등록 경로다.** `source`(정의 파일)를 쓰면 두 가지가
        // 함께 깨진다 — 정의 파일은 `%SystemRoot%\System32` 아래라 보호 목록에
        // 걸려 Action 이 언제나 거부되고, 정의를 파일로 고치면 스케줄러의
        // 무결성 해시가 어긋나 "비활성" 이 아니라 "손상" 이 된다 (설계-01 D12).
        Subject::Persistence => return s("id").map(str::to_string),
        // **서비스의 자리는 정의 키다.** 이름만 적으면 보호 목록 대조도 G6 의
        // 상한 판정도 걸리지 않는다 — 둘 다 대상의 모양을 보고 갈린다.
        Subject::Service => {
            // Linux 에서는 **유닛 파일 경로**가 그 자리다. 수집기가 `id` 에 그것을
            // 담는다 — `ServiceRecord` 에 `source` 가 없고, 이름만 적으면 쓰기
            // 경계가 유닛 파일을 찾아 헤매야 한다 (불변식 P, 설계-09 P12 순서 9).
            if platform != Platform::Windows {
                return s("id").map(str::to_string);
            }
            // **`id` 다. `name` 이 아니다.** Windows 서비스의 정의 키 이름은
            // `id` 이고 `name` 은 사람에게 보이는 표시 이름이다 — 검체는 둘을
            // 일부러 다르게 둔다(`SvcHostCache` / "Host Cache Service").
            //
            // 표시 이름으로 조립하면 그 경로는 **존재하지 않는다.** 백업이
            // 그것을 열지 못해 실행기가 `백업 단계에서 중단했다` 로 멈추고,
            // 계획 여덟 건이 통째로 수행되지 않는다 — 이 위협은 실기기에서
            // 치료가 아예 되지 않고 있었다 (2026-09-05 채점 5 첫 회차, 종료 5).
            //
            // 시험이 못 잡은 이유가 둘이다. `expected-ops.txt` 가 이 계획에서
            // 뽑혀 같은 문자열을 기대했고, 아래 시험의 픽스처가 `id` 와 `name`
            // 을 **같은 값**으로 둬서 둘을 구별할 수 없었다.
            return Some(format!(
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{}",
                s("id").or_else(|| s("name"))?
            ));
        }
        // 인증서 하나는 레지스트리 키 하나다. 수집기가 읽은 자리를 그대로
        // 되짚는다 — 두 자리가 다른 모양을 쓰면 같은 인증서가 다른 문자열로
        // 계획에 들어간다.
        Subject::CertStore => {
            // Linux 인증서는 **파일**이다. 수집기가 `linux.cert.path` 에 그것을
            // 담는다 — 다른 필드로는 쓰기 경계가 파일을 찾아 헤매야 한다.
            if platform != Platform::Windows {
                return e
                    .target
                    .get("linux")?
                    .get("path")?
                    .as_str()
                    .map(str::to_string);
            }
            return Some(format!(
                "HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\{}\\Certificates\\{}",
                s("store")?,
                s("thumbprint")?
            ));
        }
        // 확장 하나의 자리는 `.../Extensions/<확장 id>` 다. 수집기가 담는
        // `path` 는 그 **밑의 버전 디렉터리**라 그대로 쓰면 다른 버전이 남고
        // 빈 껍데기가 생긴다. 한 칸 올리는 것은 스냅샷만으로 결정적이므로
        // 계획기의 일이다 — 실행기가 하면 경로 재해석이다 (불변식 P).
        Subject::BrowserExtension => {
            let p = s("path")?;
            let (parent, _ver) = p.trim_end_matches(['\\', '/']).rsplit_once(['\\', '/'])?;
            return Some(parent.to_string());
        }
        _ => {}
    }
    if let (Some(hive), Some(key)) = (s("hive"), s("key")) {
        let mut t = format!("{hive}\\{key}");
        // `registry_key` 에는 `name` 이 없다. 그때는 키 자체가 대상이다.
        if let Some(name) = s("name") {
            t.push('\\');
            t.push_str(name);
        }
        return Some(t);
    }
    // `source` 가 여기서 걸린다. hosts 항목의 대상은 **그 파일**이고 (어느
    // 줄인지는 `locator` 가 술어로 싣는다), 그 자리를 계획기가 상수로 들고
    // 있으면 스냅샷을 뜬 기계와 다른 자리를 고칠 수 있다 — hosts 는 OS 마다
    // 자리가 다르다. `Subject::HostsEntry` 분기를 따로 두었었는데 이 사슬과
    // 결과가 같아 **아무것도 정하지 않았다.** 역검증에서 지워도 시험이 전부
    // 통과해 드러났다.
    s("path")
        .or_else(|| s("source"))
        .or_else(|| s("id"))
        .map(str::to_string)
}

/// 계획기가 **실제로 낼 수 있는** Op.
///
/// `derive` 의 각 arm 이 어디서 Op 을 고르는지를 그대로 모은다. 손으로 다시
/// 적는 것이 아니라 같은 표를 읽으므로, 새 subject 가 들어오면 여기도 함께
/// 늘어난다.
///
/// 이 함수가 존재하는 이유는 [`NOT_PLANNABLE_YET`] 하나다 — 구현했는데 아무도
/// 부를 수 없는 Op 을 **조용히 두지 않기 위해서**다.
pub fn plannable_ops() -> std::collections::BTreeSet<Op> {
    let mut s: std::collections::BTreeSet<Op> =
        Subject::ALL.into_iter().flat_map(producible_ops).collect();
    // 잠긴 파일 분기 (`removal_ops_for`).
    s.insert(Op::FileDeleteOnReboot);
    // edit arm.
    s.insert(Op::RegistryStripValue);
    s.insert(Op::EnvStripPath);
    // restore arm — 이름으로 지정하는 넷과 `to: default`.
    for (name, _, _) in remedy_sdk::catalog::RESTORE_NAMED {
        s.insert(restore_op(name));
    }
    s.insert(Op::RegistryRestoreDefault);
    // path arm — `RemoveTarget::Path` 의 `recursive: true`. **subject 를 거치지
    // 않는 유일한 제거 경로**라 위 열거에 잡히지 않는다. 매니페스트가 경로를
    // 직접 지목하고, 계획기가 그것을 이 Op 으로 옮긴다.
    s.insert(Op::DirDeleteRecursive);
    s
}

/// 그 **플랫폼에서** 계획될 수 있는 Op.
///
/// [`plannable_ops`] 의 플랫폼판이다. 어느 subject 를 그 플랫폼에서 수집하는가가
/// 갈림길이고, 수집하지 못하는 subject 는 그 Op 을 유발할 증거를 만들지 못한다.
///
/// # 왜 필요한가
///
/// 카탈로그에 **두 축**이 있다 — `SubjectInfo::linux_from`(수집하는가)과
/// `OpInfo::linux_from`(수행하는가). 둘이 어긋나면 Op 표가 **도달할 수 없는
/// 것을 약속한다.** 실측에서 열 개가 그랬다 — `service.*` 넷은 systemd 를 읽지도
/// 못하면서 "Linux 는 P12 부터" 라고 적혀 있었다 (설계-09 P12).
pub fn plannable_ops_on(platform: Platform) -> std::collections::BTreeSet<Op> {
    let collectable = |x: Subject| match platform {
        Platform::Windows => x.info().windows,
        Platform::Linux => x.info().linux_from.is_some(),
        // 모르는 플랫폼에서는 아무것도 수집하지 않는다.
        Platform::Darwin => false,
    };
    let mut s: std::collections::BTreeSet<Op> = Subject::ALL
        .into_iter()
        .filter(|x| collectable(*x))
        .flat_map(producible_ops)
        .collect();
    if collectable(Subject::File) && running_images_are_locked(platform) {
        // 잠긴 파일 분기 (`removal_ops_for`) — 잠그는 플랫폼에서만 선다.
        s.insert(Op::FileDeleteOnReboot);
    }
    if collectable(Subject::RegistryValue) {
        // edit arm 과 `to: default` — 셋 다 레지스트리 값을 고친다.
        s.insert(Op::RegistryStripValue);
        s.insert(Op::EnvStripPath);
        s.insert(Op::RegistryRestoreDefault);
    }
    for (name, subject, _) in remedy_sdk::catalog::RESTORE_NAMED {
        if collectable(subject) {
            s.insert(restore_op(name));
        }
    }
    // path arm 은 **subject 를 거치지 않는다.** 매니페스트가 경로를 직접
    // 지목하므로 어느 플랫폼에서나 계획될 수 있다.
    s.insert(Op::DirDeleteRecursive);
    s
}

/// **구현됐지만 아직 계획될 수 없는 Op 과 그 이유.**
///
/// # 왜 목록으로 못박는가
///
/// "Op 을 구현했다" 와 "플러그인이 그것을 쓸 수 있다" 는 다르다. 둘을 구분하지
/// 않으면 Phase 완료 보고가 절반만 참이 된다 — 실행기와 복원기는 완성됐는데
/// 그 Op 을 향하는 길이 없는 상태다.
///
/// **비어 있는 것이 목표다.** 새로 비는 자리가 생기면 시험이 그것을 여기 적게
/// 만들고, 적힌 것이 해소되면 시험이 그때 깨져 이 줄을 지우게 한다.
/// **도출은 되는데 가드를 지날 수 없는 Op.**
///
/// [`NOT_PLANNABLE_YET`] 과 다른 자리다. 저쪽은 *"계획기가 그 Op 을 만들지
/// 못한다"* 이고, 이쪽은 **만들어지지만 G6 가 예외 없이 거부한다** 이다.
/// `plannable_ops()` 는 subject→Op 표만 보므로 이쪽을 알지 못한다 — 그래서
/// 목록을 따로 둔다. 섞으면 저쪽의 "해소됐는데 남아 있다" 검사가 거짓으로
/// 깨진다.
///
/// **여기 적힌 것은 시험이 고정한다.** 아래 `registry.delete_key` 는
/// `remedy-plan` 의 통합 시험이 실제로 `plan()` 을 돌려 G6 거부를 확인한다.
/// 가드에 길이 생기면 그 시험이 먼저 깨지고, 그때 이 줄을 지우게 된다.
pub const PLANNED_BUT_GUARDED: [(Op, &str); 1] = [(
    Op::RegistryDeleteKey,
    "G6 가 이 Op 을 재귀 삭제로 다루어(`Limits::is_recursive` 를      `dir.delete_recursive` 와 공유합니다) 대상이 **capture 값**이기를 요구하는데,      레지스트리 키의 자리는 `hive` 와 `key` 를 이어 붙여 만드는 것이라 어떤      capture 도 그 문자열을 내지 못합니다(`derived_paths` 는 capture 값만 모읍니다).      우회하려고 그 키를 `scan_roots` 에 적으면 이번엔 조건 5(대상이 상한 자체면      거부)에 걸리고, 적지 않으면 그 키가 애초에 수집되지 않습니다 — **모으려면      상한에 적어야 하고, 적으면 지울 수 없습니다.**      조건 5 를 레지스트리에만 푸는 것은 위험합니다: `HKLM\\SOFTWARE` 는 보호      목록에 없어서, 그것을 상한으로 선언한 플러그인이 그 아래 전부를 지울 수      있게 됩니다. 고치려면 '상한보다 깊을 것' 같은 조건을 새로 세워야 하고      그것은 안전 가드 설계입니다 (2026-09-01, appinit-implant 위협을 짓다 실측).",
)];

pub const NOT_PLANNABLE_YET: [(Op, &str); 4] = [
    (
        Op::FileDeleteStream,
        "수집기가 대체 스트림을 열거하지 않습니다. 열거에는 `FindFirstStreamW` 가 \
         필요하고 그것은 unsafe 다 — 이 저장소는 크레이트 전부에 \
         `forbid(unsafe_code)` 를 겁니다. 이름을 아는 스트림만 훑는 방식은 \
         임의 이름을 쓰는 악성 스트림을 체계적으로 놓치므로 열거의 대체재가 \
         되지 못합니다. 실행기와 복원기는 완성돼 있고 왕복도 통과합니다",
    ),
    (
        Op::StructuredConfigRestoreDefault,
        "OS 기본값 카탈로그에 구조적 설정 항목이 하나도 없습니다. 값의 출처는 \
         카탈로그뿐이므로(설계-03 §2) 항목이 생기기 전에는 되돌릴 값이 없습니다. \
         브라우저 `Preferences` 처럼 OS 가 정하지 않는 파일에는 애초에 \
         '기본값' 이 없습니다",
    ),
    (
        Op::FileDelete,
        "**격리가 언제나 먼저 뽑힙니다.** 파일 제거는          `Choice(&[FileQuarantineOnly, FileDelete])` 이고 `split_removal` 이 첫 번째로          가용한 것을 고르는데, 격리는 Windows·Linux 양쪽에서 가용합니다. 그래서 이 Op          을 향하는 길이 매니페스트 쪽에 없습니다. 길을 내려면 '지울 것인가 격리할          것인가' 를 매니페스트가 말할 수 있어야 하고, 그것은 **되돌릴 수 있는 쪽이          기본**이라는 결정(설계-03 §2)을 다시 여는 일입니다. 실행기는 완성돼 있습니다",
    ),
    (
        Op::BootRestoreDefault,
        "**대상을 지목할 수 없습니다.** `BootConfigRecord` 에 `path` 도 `source` 도 `id`          도 `hive`/`key` 도 없어 `target_of` 가 `None` 을 돌려주고 그 Action 이          버려집니다. 길을 내려면 레코드가 되돌릴 자리를 이름으로 담아야 합니다.          2026-08-31 에 소스 주석으로만 적어 두었던 것을 2026-09-02 에          `plannable_ops` 를 고치며 이 목록으로 옮겼습니다 — 주석은 시험이 강제하지          않아 그 사이 이 Op 이 '일곱 번째 위협 재료' 로 잘못 세어졌습니다",
    ),
];

/// 실행 순서. 낮을수록 먼저다 (설계-03 §2).
///
/// ```text
///   1 자동 소생 차단 · 2 잠금 해제 · 3 재기동 차단 · 4 백업
///   5 유발자 제거 · 6 산출물 제거·편집 · 7 복원 · 8 사후 확인
/// ```
/// 백업(4)은 Action 이 아니라 **모든 파괴 Action 에 붙는 속성**이므로 단계가
/// 아니라 `backup` 필드로 나타난다.
fn stage(op: Op) -> u8 {
    // **유발자는 카탈로그가 안다.** 여기에 목록을 다시 적으면 Op 을 추가할 때
    // 한쪽만 고치게 되고, 그러면 재생성을 일으키는 설정을 남긴 채 산출물만
    // 지우는 계획이 나온다 (설계-03 §2).
    if op.info().regenerator {
        return 5;
    }
    match op {
        // **1단계는 "복구 동작 제거, 서비스 정지" 둘 다다** (설계-03 §2).
        //
        // 정지가 3단계(재기동 차단)에 있었다. 그러면 프로세스 종료(2단계)가
        // 정지보다 먼저 돌고, 그것은 **정상 정지가 아니라 크래시**다 — SCM 은
        // 예기치 않은 종료에만 복구 동작으로 반응한다. 복구 제거가 성공했다면
        // 결과는 같지만, 실패했다면(권한·잠금) 순서가 그대로 지는 자리가 된다.
        // 정상 정지를 먼저 하면 복구 동작을 아예 건드리지 않는다.
        //
        // 두 Op 이 같은 단계인 것은 문제가 아니다. 같은 단계 안에서는 `Vec` 의
        // 안정 정렬이 계획기가 낸 순서를 지키고, 그 순서는 `removal_ops` 가
        // 설계-03 §2 그대로 적어 둔 것이다.
        Op::ServiceClearRecovery | Op::ServiceStop => 1,
        Op::ProcessKill => 2,
        Op::PersistenceDisable | Op::ServiceDisable => 3,
        // 유발자는 아니지만 5단계다. 안전 모드를 막아 둔 것을 되돌리는 일은
        // **치료 도구가 다음에 쓸 수단을 되찾는 것**이라 산출물보다 먼저다
        // (설계-00 §6). 재생성과는 다른 이유이므로 위 분기와 나누어 둔다.
        Op::BootRestoreDefault => 5,
        // **위 분기가 이미 걸렀다.** 그래도 남겨 두는 이유는 `match` 의
        // exhaustive 검사다 — 이것이 없으면 Op 을 새로 추가할 때 여기서 막히지
        // 않고 조용히 잘못된 단계에 놓인다.
        //
        // 값을 5 로 두면 안 된다. 그러면 위 분기를 없애도 결과가 같아서
        // **카탈로그가 실제로는 아무것도 정하지 않는다** — 역검증에서 그렇게
        // 샜다. 6(산출물)으로 떨어뜨리면 카탈로그와 어긋나는 순간 순서가
        // 뒤집히고 `a_regenerator_runs_before_the_artifact_it_would_recreate`
        // 가 그것을 잡는다.
        Op::PersistenceDelete
        | Op::AutorunRemove
        | Op::ServiceDelete
        | Op::RegistryDeleteValue
        | Op::RegistryDeleteKey
        | Op::RegistryStripValue
        | Op::EnvStripPath => 6,
        // 산출물.
        Op::FileQuarantineOnly
        | Op::FileDelete
        | Op::FileDeleteOnReboot
        | Op::FileDeleteStream
        | Op::DirDeleteRecursive
        | Op::BrowserExtRemove
        | Op::CertStoreRemove
        | Op::ShortcutStripArgs
        | Op::TextConfigRemoveLine
        | Op::StructuredConfigRemoveKey => 6,
        // 복원계.
        Op::AvRestoreExclusions
        | Op::HostsRestoreLine
        | Op::ProxyRestore
        | Op::FirewallRestoreRule
        | Op::RegistryRestoreDefault
        | Op::StructuredConfigRestoreDefault => 7,
    }
}

/// 이 대상이 이동식 매체 위인가.
///
/// 판단의 근거는 **스냅샷에 적힌 루트**다. 계획 시점에 지금 꽂힌 매체를 다시
/// 물으면 스냅샷을 뜬 기계와 다른 답이 나오고, 그러면 같은 스냅샷이 같은 계획을
/// 내지 않는다.
fn on_removable(target: &str, scan: &ScanEnvelope) -> Option<String> {
    let platform = crate::snapshot_platform(&scan.host);
    scan.body
        .removable_roots
        .iter()
        .find(|r| remedy_sdk::normalize::is_within(target, r, platform))
        .cloned()
}

/// 사람이 없으면 할 수 없는 일을 무인 모드 계획에서 뺀다
/// (설계-03 §4, 설계-09 P7·P8).
///
/// # 왜 읽기 허가로는 부족한가
///
/// `allow_removable` 은 매니페스트가 "읽어도 좋다" 고 선언한 것이다. 그 위의
/// 파일을 **지우는** 것은 다른 결정이다 — 꽂혀 있는 것이 감염된 USB 인지
/// 사용자의 백업 디스크인지는 눈앞에서 보는 사람만 안다. 드라이브 문자는
/// 재사용되므로 스냅샷 시점의 `E:` 와 수행 시점의 `E:` 가 같은 매체라는 보장도
/// 없다.
///
/// 무인 모드에는 그 사람이 없다. 그래서 **계획하지 않는다** — 조용히 빼지 않고
/// 승인 전에 알아야 할 부작용. **알리기만 하고 아무것도 미루지 않는다.**
///
/// # 왜 여기가 `gate_needs_a_human` 과 다른가
///
/// 그쪽은 *"사람이 없으면 하지 않는다"* 는 **게이트**다 — 인증서 제거처럼 잘못
/// 지우면 기계가 깨지는 일에만 건다. 이쪽은 *"할 텐데 이런 일이 생긴다"* 는
/// **알림**이라 모드를 보지 않는다. 무인 배포에서도 계획은 그대로 서고, 화면을
/// 읽는 사람이 있을 때만 그 줄이 눈에 띈다.
///
/// # 두 종류만 붙는다
///
/// | Op | 종류 | 왜 |
/// |---|---|---|
/// | `process.kill` | `AppTerminate` | 돌고 있는 것을 멈춘다 — 승인 직전에 가장 듣고 싶은 말 |
/// | `file.delete_on_reboot` | `RebootRequired` | **정리가 재시작 뒤에 끝난다.** 이 종류가 맞는 유일한 자리다 |
///
/// `verify.after_reboot` 는 여기 없다. 그것은 *"정리가 끝난다"* 가 아니라
/// *"한 번 더 검사한다"* 여서 뜻이 다르고, 계획이 이미 나르므로
/// (`PlanBody::verify_after_reboot`) 화면이 그 값을 직접 읽는다.
fn informational_impact(op: Op, e: &Evidence) -> Option<UserImpact> {
    match op {
        Op::ProcessKill => Some(UserImpact {
            kind: UserImpactKind::AppTerminate,
            // **이름이 있으면 이름으로 말한다.** `해당 프로그램` 은 사용자가
            // 무엇이 멈추는지 모르게 한다. `image_path` 는 프로세스 레코드가
            // 늘 담는다 — 실측에서 `System Idle Process` 하나만 비었다.
            app: e
                .target
                .get("image_path")
                .and_then(|v| v.as_str())
                .map(file_name_of)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            note: None,
        }),
        // **`note` 를 붙이지 않는다.** 지금 `note` 를 쓰는 자리들이 한국어만
        // 담고 있어(설계 부채) 영어 화면에 한글이 섞인다. 여기서 하려던 말은
        // 기본 문장과 `op_effect` 가 두 언어로 이미 하고 있다 —
        // *"재시작해야 정리가 끝납니다"* + *"지금은 잠겨 있어 다음 재시작 때 지웁니다"*.
        Op::FileDeleteOnReboot => Some(UserImpact {
            kind: UserImpactKind::RebootRequired,
            app: None,
            note: None,
        }),
        _ => None,
    }
}

/// 경로의 마지막 성분. 두 구분자를 다 본다 — 계획은 두 플랫폼에서 만들어진다.
fn file_name_of(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// 이유와 함께 `deferred` 로 남긴다.
///
/// # 인증서 제거도 같은 자리다 (P8)
///
/// `cert_store.remove` 는 신뢰 루트를 건드린다. 가짜 루트를 심어 두는 것은 실제
/// 위협이지만(그래서 저장소를 관찰한다), **잘못 지우면 그 기계의 TLS 검사가
/// 통째로 깨진다** — 기업 내부 CA 가 그 자리에 있는 것이 정상인 환경이 흔하다.
/// 눈앞에서 인증서 주체를 읽고 판단할 사람이 없으면 하지 않는다 (설계-09 P8).
fn gate_needs_a_human(out: &mut Derived, scan: &ScanEnvelope, mode: Mode) {
    let mut kept = Vec::with_capacity(out.actions.len());
    for mut a in std::mem::take(&mut out.actions) {
        if a.op == Op::CertStoreRemove {
            match mode {
                Mode::Unattended => {
                    out.deferred.push(DeferredItem {
                        at: format!("target: {}", a.target.as_deref().unwrap_or("")),
                        op: a.op,
                        arrives_in: a.op.info().implemented_in.as_str().to_string(),
                        reason: crate::guard::ko_en(
                            "신뢰 루트를 건드립니다. 무인 모드에는 인증서를 \
                             확인할 사람이 없어 계획하지 않습니다"
                                .into(),
                            "it touches a trust root. Unattended mode has nobody to check the \
                             certificate, so it is not planned"
                                .into(),
                        ),
                    });
                    continue;
                }
                Mode::Interactive => {
                    a.user_impact = Some(UserImpact {
                        kind: UserImpactKind::AppBroken,
                        app: None,
                        note: Some(
                            "신뢰 저장소에서 인증서를 지웁니다. 기업 내부 CA 라면 \
                             그 기계의 TLS 검사가 깨집니다"
                                .into(),
                        ),
                    });
                    kept.push(a);
                    continue;
                }
            }
        }
        let Some(root) = a.target.as_deref().and_then(|t| on_removable(t, scan)) else {
            kept.push(a);
            continue;
        };
        match mode {
            Mode::Unattended => out.deferred.push(DeferredItem {
                at: format!("target: {}", a.target.as_deref().unwrap_or("")),
                op: a.op,
                arrives_in: a.op.info().implemented_in.as_str().to_string(),
                reason: crate::guard::ko_en(
                    format!(
                        "이동식 매체('{root}') 위의 대상입니다. \
                         무인 모드에는 매체를 확인할 사람이 없어 계획하지 않습니다"
                    ),
                    format!(
                        "the target sits on removable media ('{root}'). Unattended mode has \
                         nobody to check the medium, so it is not planned"
                    ),
                ),
            }),
            Mode::Interactive => {
                a.user_impact = Some(UserImpact {
                    kind: UserImpactKind::RemovableMedia,
                    app: None,
                    note: Some(format!(
                        "이동식 매체 '{root}' 위에 있습니다. \
                         꽂혀 있는 매체가 맞는지 확인하십시오"
                    )),
                });
                kept.push(a);
            }
        }
    }
    out.actions = kept;
}

/// 설계-03 §3 **2층 — 신뢰 서명 검증.**
///
/// 유효한 신뢰 벤더 서명이 있는 실행 파일은 기본적으로 삭제 대상에서 뺀다.
/// 뺄 이유가 있으면 그 사유를 돌려준다.
///
/// # 왜 "거부" 가 아니라 "제외" 인가
///
/// 계획 전체를 거부하면 서명된 파일 하나 때문에 나머지 치료가 통째로 멈춘다.
/// 설계-03 은 *"삭제 대상에서 제외한다"* 로 적었고, 빠진 것은 `deferred` 로
/// **보고된다** — 조용히 사라지지 않는다.
///
/// # 열거 없는 포괄적 무시는 불가
///
/// `signed_malware` 가 비어 있으면 어떤 서명 대상도 통과하지 못한다. 목록 자체가
/// 플래그이므로 "true + 빈 목록" 을 표현할 수 없다(`manifest.rs`). 여기서는 그
/// 목록에 **실제로 맞는 항목**이 있는지만 본다.
fn layer2_holds(e: &Evidence, manifest: &PluginManifest) -> Option<String> {
    let sig = e.target.get("signature")?;
    // `trusted` 가 없거나 false 면 2층이 잡을 것이 없다. **`signature` 자체가
    // 없는 것과 같이 다룬다** — 그것은 "확인하지 않았다" 이고(설계-03 §3),
    // 확인하지 않은 것을 신뢰로 읽지 않는다.
    if sig.get("trusted").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    let subject = sig.get("subject").and_then(|v| v.as_str());
    let thumbprint = sig.get("thumbprint").and_then(|v| v.as_str());

    let listed = manifest.signed_malware.iter().any(|s| {
        // 둘 중 하나라도 적혀 있으면 그것으로 맞춘다. 둘 다 없는 항목은 스키마
        // 검증이 이미 막는다.
        let by_subject = match (s.subject.as_deref(), subject) {
            (Some(want), Some(got)) => want == got,
            _ => false,
        };
        let by_thumb = match (s.thumbprint.as_deref(), thumbprint) {
            // 지문은 대소문자 표기가 도구마다 갈린다. 그것 때문에 예외가
            // 조용히 빗나가면 서명된 악성코드를 지우지 못한다.
            (Some(want), Some(got)) => want.eq_ignore_ascii_case(got),
            _ => false,
        };
        by_subject || by_thumb
    });
    if listed {
        return None;
    }

    let who = subject.unwrap_or(remedy_sdk::i18n::t("(주체 불명)", "(subject unknown)"));
    Some(crate::guard::ko_en(
        format!(
            "설계-03 §3 2층 — 신뢰 서명이 있어 삭제하지 않습니다 (주체 {who}). \
             지워야 한다면 매니페스트의 signed_malware 에 그 주체나 지문을 열거하십시오"
        ),
        format!(
            "design-03 §3 layer 2 — it carries a trusted signature, so it is not deleted \
             (subject {who}). To delete it anyway, list that subject or thumbprint under \
             signed_malware in the manifest"
        ),
    ))
}

/// 설계-03 §3 **5층 — 조직 서명 허용 목록.**
///
/// 조직이 서명한 목록에 이 대상의 해시가 있으면 삭제 대상에서 뺀다.
///
/// # 왜 계획기인가
///
/// 2층과 같은 자리다. 화이트리스트는 **판정을 지우는 것이 아니라 파괴를
/// 막는 것**이므로(설계-03 §3), 증거는 그대로 서고 Action 만 만들어지지 않는다.
/// 빠졌다는 사실은 `deferred` 로 나간다 — **조용히 사라지지 않는다.**
///
/// # 해시가 없는 대상은 여기서 면제되지 않는다
///
/// 목록이 해시로만 지목하기 때문이다(`remedy-trust::allowlist` 모듈 주석).
/// 경로로 지목하면 그 자리에 파일을 놓는 것만으로 면제를 얻고, 서명 주체로
/// 지목하는 것은 2층이 이미 한다.
///
/// # 목록이 없으면 아무것도 면제되지 않는다
///
/// 빈 지도가 그 상태다. **안전한 방향이다** — 면제가 없으면 평소대로 치료할
/// 뿐이고, 반대(목록을 못 읽었는데 면제된 것으로 치는 것)라야 위험하다.
fn layer5_holds(e: &Evidence, allow: &Allowed) -> Option<String> {
    let sha = e.target.get("sha256")?.as_str()?;
    let reason = allow.get(&sha.trim().to_ascii_lowercase())?;
    let head = &sha[..sha.len().min(12)];
    Some(crate::guard::ko_en(
        format!(
            "설계-03 §3 5층 — 조직 허용 목록에 있어 삭제하지 않습니다: {reason} (sha256 {head}…)"
        ),
        format!(
            "design-03 §3 layer 5 — it is on the organization allow-list, so it is not \
             deleted: {reason} (sha256 {head}…)"
        ),
    ))
}

fn defer(at: String, op: Op, platform: Platform, reason: &str) -> DeferredItem {
    let from = match platform {
        Platform::Windows => Some(op.info().implemented_in),
        Platform::Linux => op.info().linux_from,
        Platform::Darwin => None,
    };
    DeferredItem {
        at,
        op,
        // **"아직" 과 "영원히" 를 가른다.** 기다리면 되는 것과 룰을 고쳐야
        // 하는 것이 같은 표시를 달면 작성자가 무엇을 할지 모른다 —
        // 레지스트리 Op 은 Linux 에서 아무리 기다려도 오지 않는다.
        arrives_in: match from {
            Some(p) => p.as_str().to_string(),
            None => {
                let os = platform.id();
                crate::guard::ko_en(
                    format!("{os} 에는 개념이 없습니다"),
                    format!("{os} has no such concept"),
                )
            }
        },
        reason: reason.to_string(),
    }
}

/// 이 서비스의 정지가 **그 사용자의 세션 버스**를 요구하는가 — 리눅스 사용자 유닛.
///
/// systemd 는 사용자 유닛을 그 사용자의 관리자가 돌린다. 멈추려면 그 관리자에게
/// 말해야 하는데 root 로 도는 치료 도구에는 그 사용자의 세션 버스가 없다 (설계-09
/// P12 결정 5). **시스템 관리자에게 같은 이름을 멈추라고 하면** 엉뚱한 시스템
/// 유닛이 멈추거나, "그런 유닛은 없다" 가 성공으로 읽힌다.
///
/// 자리로 가른다. 수집기가 사용자 유닛을 읽는 곳 — `/usr/lib · /etc · /run` 의
/// `systemd/user` 와 각 홈의 `.config/systemd/user` — 이 전부 `/systemd/user/` 를
/// 품는다. 백엔드는 따로 **시스템 유닛 자리 바로 아래가 아니면** 거부한다 (두 겹).
fn stop_needs_a_session_bus(e: &Evidence, platform: Platform) -> bool {
    platform == Platform::Linux
        && e.subject == Subject::Service
        && e.target
            .get("id")
            .and_then(|v| v.as_str())
            .is_some_and(|id| id.contains("/systemd/user/"))
}

/// 사용자 유닛의 정지를 미룬다는 기록. `defer` 와 달리 도착 Phase 가 없다 —
/// Op 은 리눅스에 있고, **이 자리에서만** 할 수 없다.
fn user_unit_stop_deferred(at: String) -> DeferredItem {
    DeferredItem {
        at,
        op: Op::ServiceStop,
        arrives_in: crate::guard::ko_en(
            "사용자 유닛에는 없습니다".to_string(),
            "not for user units".to_string(),
        ),
        reason: crate::guard::ko_en(
            "사용자 유닛을 멈추려면 그 사용자의 세션 버스가 필요한데 root 로 도는 이 \
             도구에는 없습니다 — 끄고 지우기만 합니다"
                .to_string(),
            "stopping a user unit needs that user's session bus, which this tool running \
             as root does not have — it is only disabled and deleted"
                .to_string(),
        ),
    }
}

/// 판정이 선 그룹에 속한 증거만 치료 대상이다.
///
/// 판정이 서지 않은 그룹의 증거로 무언가를 지우면, 그것은 **판정 없이 지우는
/// 것**이다. `verdict.require` 가 존재하는 이유가 사라진다.
fn treatable_evidence(scan: &ScanEnvelope) -> Vec<&Evidence> {
    let passing: std::collections::BTreeSet<&str> = scan
        .body
        .groups
        .iter()
        .filter(|g| g.verdict)
        .flat_map(|g| g.evidence.iter().map(String::as_str))
        .collect();
    scan.body
        .evidence
        .iter()
        .filter(|e| passing.contains(e.id.as_str()))
        .collect()
}

/// `remediate` 를 Action 으로 편다.
pub fn derive(
    scan: &ScanEnvelope,
    manifest: &PluginManifest,
    mode: Mode,
    allow: &Allowed,
) -> Derived {
    // 스냅샷이 어느 플랫폼에서 떴는지. **Op 가용성이 여기에 달렸다** —
    // 같은 매니페스트가 Windows 에서는 계획을 내고 Linux 에서는 미룰 수 있다.
    let platform = crate::snapshot_platform(&scan.host);
    let mut out = Derived {
        actions: Vec::new(),
        deferred: Vec::new(),
    };
    let Some(rem) = &manifest.remediate else {
        return out;
    };
    let evidence = treatable_evidence(scan);

    // ── remove ────────────────────────────────────────────────
    for (i, t) in rem.remove.iter().enumerate() {
        let at = format!("remediate.remove[{i}]");
        match t {
            RemoveTarget::Ref(r) => {
                let hits: Vec<&&Evidence> =
                    evidence.iter().filter(|e| e.rule == r.rule_ref).collect();
                for e in hits {
                    let (mut chosen, missing) = split_removal(removal_ops_for(e, scan), platform);
                    for op in missing {
                        out.deferred.push(defer(
                            at.clone(),
                            op,
                            platform,
                            &{
                                let s = e.subject.id();
                                crate::guard::ko_en(
                                    format!("subject '{s}' 를 제거하는 데 필요한데 이 코어에 없습니다"),
                                    format!("it is needed to remove subject '{s}' but this core does not have it"),
                                )
                            },
                        ));
                    }
                    // **사용자 유닛은 멈추지 않고 미룬다** ([`stop_needs_a_session_bus`]).
                    // 끄고 지우는 것은 파일이라 그대로 계획된다.
                    if stop_needs_a_session_bus(e, platform) {
                        if let Some(i) = chosen.iter().position(|o| *o == Op::ServiceStop) {
                            chosen.remove(i);
                            out.deferred.push(user_unit_stop_deferred(at.clone()));
                        }
                    }

                    // **2층은 여기서 걸린다** (설계-03 §3). 대상이 신뢰 서명을
                    // 가졌고 매니페스트가 그 주체를 열거하지 않았다면 Action 을
                    // 만들지 않는다. 빠졌다는 사실은 `deferred` 로 나간다.
                    //
                    // 경로로 직접 지목하는 `RemoveTarget::Path` 에는 걸지 않는다
                    // — 그 경로는 증거가 아니라 매니페스트가 적은 것이고, 서명
                    // 정보가 실려 오지 않는다. 재귀 삭제의 "하위에 신뢰 서명이
                    // 있으면 거부"(설계-03 §4 조건 3)는 별개이며 P10-C 다.
                    if let Some(why) = layer2_holds(e, manifest) {
                        for op in chosen {
                            out.deferred.push(defer(at.clone(), op, platform, &why));
                        }
                        continue;
                    }

                    // **5층은 2층 뒤에 온다** (설계-03 §3 — 평가 순서 고정).
                    // 순서가 뒤집히면 서명된 대상이 허용 목록 사유로 보고되고,
                    // 그 둘은 운영자가 할 일이 다르다.
                    if let Some(why) = layer5_holds(e, allow) {
                        for op in chosen {
                            out.deferred.push(defer(at.clone(), op, platform, &why));
                        }
                        continue;
                    }

                    let resolved = target_of(e, platform);
                    for op in chosen {
                        // **프로세스만 대상이 비는 것이 정상이다** (설계-03 §1).
                        // PID 는 계획에 들어갈 자리가 없고 술어가 대신하며,
                        // G6 의 상한 검사도 `target` 이 없으면 건너뛴다 —
                        // 프로세스에는 `scan_roots` 에 대응하는 것이 없다.
                        //
                        // 다른 Op 은 대상이 없으면 무엇을 손댈지 계획이 말하지
                        // 않은 것이므로 만들지 않는다.
                        let target = match (op, &resolved) {
                            (Op::ProcessKill, _) => None,
                            (_, Some(t)) => Some(t.clone()),
                            (_, None) => continue,
                        };
                        let mut act = action(op, target, vec![e.id.clone()]);
                        act.r#match = locator(e);
                        // **부작용은 알리기만 한다 — 미루지 않는다.**
                        //
                        // 아래 `gate_needs_a_human` 은 대화형이면 표시하고 무인이면
                        // 미루는데, 그 모양을 여기 베끼면 무인 배포가 프로세스를
                        // 죽이지 않게 되고 페이로드 파일이 잠겨 치료가 통째로
                        // 실패한다. 그래서 모드를 보지 않는다
                        // (`an_unattended_run_still_kills_the_process` 가 잠근다).
                        act.user_impact = informational_impact(op, e);
                        // **매니페스트가 명시적으로 켜야 한다** (설계-03 §2).
                        // 계보 확장은 술어가 지목하지 못한 것까지 집합에 넣는
                        // 일이라 계획기가 스스로 켜지 않는다. 린트가 프로세스
                        // 아닌 subject 에 붙은 것을 미리 막는다.
                        if r.descendants && op == Op::ProcessKill {
                            act.include_descendants = Some(true);
                        }
                        out.actions.push(act);
                    }
                }
            }
            RemoveTarget::Path(p) => {
                // 재귀 삭제는 고위험이라 P8 이다. 지금은 미룬다.
                let op = if p.recursive {
                    Op::DirDeleteRecursive
                } else {
                    Op::FileQuarantineOnly
                };
                if !available(op, platform) {
                    out.deferred.push(defer(
                        at.clone(),
                        op,
                        platform,
                        &crate::guard::ko_en(
                            "이 Op 은 지금 수행할 수 없습니다".into(),
                            "this Op cannot be performed right now".into(),
                        ),
                    ));
                    continue;
                }
                // 경로는 capture 보간을 거쳐야 한다. 보간이 안 되면 대상이
                // 정해지지 않은 것이므로 만들지 않는다.
                let Some(resolved) = interpolate(&p.path, scan) else {
                    // **서지 않은 갈래의 경로는 미룸이 아니다** (코어 1.2.0). 판정식이 `or` 로
                    // 갈래를 두면(EvilAI 0.2.0 — `(task and payload) or (task-x and payload-x)
                    // or …`) 선 갈래 밖의 경로 삭제는 capture 가 없는 것이 맞다 — 그 갈래에는
                    // 지울 것이 없다. 그것을 미룸으로 내면 화면이 치료마다 *"capture 가 해소되지
                    // 않아"* 를 적어 덜 된 치료처럼 읽힌다(2026-11-08 랩 실측 · 보도 꼴 치료에서
                    // 두 줄). 그래서 **그 경로가 가리키는 규칙이 판정 그룹에 증거를 하나도 내지
                    // 않았을 때만** 조용히 건너뛴다. 증거는 냈는데 capture 가 없으면 지금처럼
                    // 미룬다 — 그것은 갈래가 선 채 대상을 못 정한 것이다.
                    let rules = template_rules(&p.path);
                    if !rules.is_empty()
                        && !rules.iter().all(|r| evidence.iter().any(|e| e.rule == *r))
                    {
                        continue;
                    }
                    out.deferred.push(defer(
                        at.clone(),
                        op,
                        platform,
                        &crate::guard::ko_en(
                            "capture 가 해소되지 않아 대상이 정해지지 않았습니다".into(),
                            "the capture did not resolve, so no target is fixed".into(),
                        ),
                    ));
                    continue;
                };
                let because = p
                    .guard
                    .as_deref()
                    .map(|g| {
                        evidence
                            .iter()
                            .filter(|e| e.rule == g)
                            .map(|e| e.id.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                // **guard 가 아무것도 잡지 않았으면 만들지 않는다.**
                //
                // 위 두 분기와 같은 자리다 — Op 이 없거나 대상이 정해지지
                // 않으면 미룬다. 여기도 같다: 그 폴더 안에서 악성으로 판정된
                // 것이 없으므로 통째로 지울 근거가 없다.
                //
                // # 만들면 계획이 통째로 무너진다
                //
                // 근거 없는 Action 은 `because` 가 빈 채로 나가고, G7("근거 없는
                // Action 은 존재할 수 없다")과 G6(재귀 삭제의 guard 요구)이 둘 다
                // 문다. **안전 가드 위반은 그 Action 하나가 아니라 계획 전체를
                // 무른다** — 종료 코드 5 다. 인증서도 레지스트리 값도 하나
                // 치료되지 않는다.
                //
                // # 이것이 언제 일어나는가 — 작성자의 흠이 아니다
                //
                // 판정이 guard 를 필수로 두지 않았을 때다. `A and (B or C)` 에
                // `guard: B` 가 그 모양이고, **B 가 이미 없는 기계**에서 일어난다.
                // 그런 판정은 다른 백신이 페이로드만 잡아간 기계를 구하려고
                // 일부러 여는 것이다(40-review-checklist.md 2번). 그래서
                // **느슨한 판정이 구하려던 바로 그 기계가 계획이 무너지는 기계**가
                // 됐다. 2026-09-04 회차가 그 모양을 냈고, 응시자는 가이드를
                // 그대로 따랐다.
                //
                // guard 를 optional evidence 에 거는 것은 옳은 설계다 —
                // *"그 안에서 실제로 뭔가 찾았을 때만 폴더째 지운다."* 미룸이
                // 그 뜻을 그대로 수행하고, 무엇을 왜 미뤘는지 보고에 남는다.
                //
                // 가드의 나머지 세 검사(리터럴 경로 · 근거의 경로를 모름 ·
                // 근거가 바깥을 가리킴)는 그대로 거부다. 그것들은 기계와
                // 무관한 매니페스트 결함이라 시끄러워야 한다.
                if p.guard.is_some() && because.is_empty() {
                    out.deferred.push(defer(
                        at.clone(),
                        op,
                        platform,
                        "guard 가 가리킨 규칙이 이 그룹에서 아무것도 잡지 않았습니다 — \
                         그 안에서 악성으로 판정된 것이 없으므로 통째로 지울 근거가 없습니다",
                    ));
                    continue;
                }
                out.actions.push(action(op, Some(resolved), because));
            }
        }
    }

    // ── edit ──────────────────────────────────────────────────
    //
    // 값의 악성 부분만 제거한다. **통째로 지우면 시스템을 못 쓰게 되는 대상이
    // 오히려 주류다** — `Userinit` 를 지우면 로그온이 깨진다 (설계-02 §6-1).
    for (i, e) in rem.edit.iter().enumerate() {
        let at = format!("remediate.edit[{i}] (ref: {})", e.rule_ref);
        for ev in evidence.iter().filter(|x| x.rule == e.rule_ref) {
            // PATH 는 `;` 로 이어진 목록이라 자르는 방법이 다르다. 대상이
            // 무엇인지가 Op 을 정한다.
            let op = if is_path_variable(ev) {
                Op::EnvStripPath
            } else {
                Op::RegistryStripValue
            };
            if !available(op, platform) {
                out.deferred.push(defer(
                    at.clone(),
                    op,
                    platform,
                    &crate::guard::ko_en(
                        "이 Op 은 지금 수행할 수 없습니다".into(),
                        "this Op cannot be performed right now".into(),
                    ),
                ));
                break;
            }
            let Some(target) = target_of(ev, platform) else {
                continue;
            };
            // **무엇을 지울지는 증거에서 나온다.** 리터럴로 임의 편집을
            // 지시할 수 없다 (설계-02 §6).
            let Some(needle) = interpolate(&e.value, scan) else {
                out.deferred.push(defer(
                    at.clone(),
                    op,
                    platform,
                    &crate::guard::ko_en(
                        "capture 가 해소되지 않아 무엇을 지울지 정해지지 않았습니다".into(),
                        "the capture did not resolve, so what to strip is not fixed".into(),
                    ),
                ));
                continue;
            };
            let mut a = action(op, Some(target), vec![ev.id.clone()]);
            a.strip = Some(needle);
            out.actions.push(a);
        }
    }

    // ── restore ───────────────────────────────────────────────
    for (i, r) in rem.restore.iter().enumerate() {
        let (op, name, rule) = match r {
            RestoreTarget::Named(n) => (restore_op(n), n.clone(), None),
            RestoreTarget::ToDefault(d) => (
                Op::RegistryRestoreDefault,
                "to_default".into(),
                Some(d.rule_ref.as_str()),
            ),
        };
        let at = format!("remediate.restore[{i}] ({name})");
        if !available(op, platform) {
            out.deferred.push(defer(
                at,
                op,
                platform,
                &crate::guard::ko_en(
                    "이 Op 은 지금 수행할 수 없습니다".into(),
                    "this Op cannot be performed right now".into(),
                ),
            ));
            continue;
        }
        // 이름으로 지정한 원복(`av_exclusions` 등)은 그 subject 의 증거를 쓴다.
        let hits: Vec<&&Evidence> = match rule {
            Some(id) => evidence.iter().filter(|x| x.rule == id).collect(),
            None => evidence
                .iter()
                .filter(|x| restore_op_for(x.subject) == Some(op))
                .collect(),
        };
        for ev in hits {
            // 프록시는 대상이 여럿일 수 있다 — 룰이 짚은 설정마다 하나씩이다.
            let targets: Vec<String> = if op == Op::ProxyRestore {
                let t = proxy_targets(ev);
                if t.is_empty() {
                    out.deferred.push(defer(
                        at.clone(),
                        op,
                        platform,
                        &crate::guard::ko_en(
                            "룰이 프록시 설정 필드를 짚지 않아 무엇을 되돌릴지 알 수 없습니다".into(),
                            "the rule does not point at a proxy setting field, so there is nothing \
                             to restore"
                                .into(),
                        ),
                    ));
                }
                t
            } else {
                target_of(ev, platform).into_iter().collect()
            };
            for target in targets {
                // **카탈로그에 없는 대상은 되돌리지 않는다.** 값의 출처가 코어
                // 안이어야 한다 (설계-03 §2). 린트가 미리 잡지만 대상이 증거에
                // 따라 달라지는 규칙은 여기서만 알 수 있다.
                if op == Op::RegistryRestoreDefault
                    && remedy_sdk::catalog::restore_default_for(&target).is_none()
                {
                    out.deferred.push(defer(
                        at.clone(),
                        op,
                        platform,
                        &crate::guard::ko_en(
                            "OS 기본값 카탈로그에 없는 대상이라 되돌릴 값이 없습니다".into(),
                            "the target is not in the OS-default catalog, so there is no value to \
                             restore back to"
                                .into(),
                        ),
                    ));
                    continue;
                }
                // **술어를 붙인다.** `remove` 쪽(위 `act.r#match = locator(e)`)
                // 과 같은 것이고, 빠뜨리면 대상 안의 **어디**를 되돌릴지
                // 계획이 말하지 않는다.
                //
                // 2026-09-03 Linux 하네스가 이것을 밟았다. `restore: [hosts]`
                // 는 계획까지 멀쩡히 서고 G6 도 지나는데, `apply` 가 백업
                // 단계에서 통째로 멈췄다:
                //
                //   실패: 백업 단계에서 중단했다 — 아무것도 파괴하지 않았다:
                //         seq 13: 이 플랫폼에서는 지원되지 않는다: 계획에 줄 번호가 없다
                //
                // `hosts.restore_line` 의 `backup_kinds` 는 `[TextLine]` 하나라
                // 실행기가 `line_no` 를 요구하는데, 이 자리가 술어를 붙이지
                // 않아 언제나 없었다. **양쪽 플랫폼에서 한 번도 동작한 적이
                // 없다** — `tls-intercept` 정답 플러그인이 이 절을 쓰고 시험도
                // 통과했지만, 시험은 계획만 보고 `apply` 를 돌리지 않는다.
                //
                // 멈춤 자체는 안전했다(파괴 전에 멈췄다). 그래도 결과는
                // *"hosts 를 되돌리는 룰은 그 기계에서 아무것도 치료하지
                // 못한다"* 였다.
                let mut act = action(op, Some(target), vec![ev.id.clone()]);
                act.r#match = locator(ev);
                out.actions.push(act);
            }
        }
    }

    // **정렬보다 먼저 거른다.** 무인 모드에서 빠질 Action 이 자리를 차지한 채
    // 번호를 받으면 `seq` 가 듬성듬성해지고, 그것이 곧 "계획에 없는 번호" 로
    // 읽힌다.
    gate_needs_a_human(&mut out, scan, mode);

    // 순서는 코어가 정한다. 같은 단계 안에서는 들어온 순서를 지켜 **같은 입력이
    // 같은 계획을 내게** 한다. 예외는 하나 — 한 파일의 줄(cron · 텍스트 설정 ·
    // hosts)은 한 번씩, 아래 줄부터 고친다([`lines_once_bottom_up`]).
    out.actions.sort_by_key(|a| (stage(a.op), a.seq));
    lines_once_bottom_up(&mut out.actions);
    for (i, a) in out.actions.iter_mut().enumerate() {
        a.seq = i as u32 + 1;
    }
    out
}

/// 파일 **안의 줄 하나**를 고치는 Action 이면 `(파일, 줄 번호)` — 술어의 `line_no` 가 그 번호다([`locator`]).
///
/// | Op | 대상 |
/// |---|---|
/// | `persistence.disable` · `persistence.delete` | `<파일>:<번호>` — cron 줄. Windows 예약 작업과 systemd 유닛은 술어가 없어 `None` 이다 |
/// | `text_config.remove_line` · `hosts.restore_line` | 그 파일 |
fn line_place(a: &Action) -> Option<(&str, u64)> {
    let n = a.r#match.as_ref()?.get("line_no")?.as_u64()?;
    let target = a.target.as_deref()?;
    let file = match a.op {
        Op::PersistenceDisable | Op::PersistenceDelete => target.strip_suffix(&format!(":{n}"))?,
        Op::TextConfigRemoveLine | Op::HostsRestoreLine => target,
        _ => return None,
    };
    Some((file, n))
}

/// **한 파일의 줄은 한 번씩, 아래 줄부터 고친다** — 같은 줄을 짚은 칸을 하나로 합치고, 같은 Op · 같은 파일의
/// 칸끼리 줄 번호가 큰 것부터 다시 앉힌다.
///
/// 지우기는 줄을 빼므로 그 아래 줄의 번호가 하나씩 당겨진다. 계획은 수집 때의 번호와 내용을 박아 두고
/// ([`locator`]) 실행기가 그 둘을 대조하므로, 위 줄을 먼저 지우면 아래 줄이 *"내용이 계획과
/// 다릅니다"* 로 거부되거나(일부 실패) 그 번호가 파일 끝을 넘어 *"이미 없다"* 로 건너뛰어 `#` 붙은
/// 줄이 남은 채 완료로 보고됐다(이슈 #166 ③ · 1.25.3). 아래 줄부터 지우면 남은 줄의 번호가 밀리지
/// 않는다. 끄기는 제자리 고침이라 차례와 상관없지만 같은 꼴로 둔다. `text_config.remove_line` ·
/// `hosts.restore_line` 도 같은 번호 밀림을 겪었다 — 수집기가 텍스트 설정을 (파일, 번호) 오름차순으로 세워 한
/// 파일의 둘째 줄이 늘 거부됐고, hosts 는 레코드의 문자열 차례라 그 차례가 번호를 따를 때만 그랬다.
///
/// **같은 줄은 한 번만 고친다.** 두 룰이 같은 줄을 짚으면(판정 `a or b` 에 `remove` 둘) 같은 줄의 Action 이 둘
/// 계획됐고, 첫째가 줄을 빼면 둘째가 그 번호에 올라온 다음 줄을 보고 거부되어 일부 실패(3)로 끝났다. 같은
/// Op · 대상 · 술어의 칸은 앞의 칸 하나로 합치고 근거(`because`)를 잇는다. 다시 앉히기보다 먼저 한다 — 같은
/// 번호 둘은 내림차순에서도 붙어 남는다.
///
/// 들어온 차례는 줄 번호의 수 차례가 아니다. 수집기가 cron 레코드를 `id`(`<파일>:<번호>`)의 문자열 순으로
/// 정렬하고, 평가기가 그 차례로 증거 번호(`<룰>#<n>`)를 매긴 뒤 그 문자열 순으로 한 번 더
/// 정렬한다 — `…:12` 가 `…:3` 앞에 오고, 한 룰의 증거가 열 개를 넘으면 `#10` 이 `#2` 앞에 온다.
/// 룰이 여럿이면 `remove` 의 ref 차례로도 섞인다. 그래서 번호를 수로 견주고, 정렬을 마친 목록에서 그
/// 묶음의 칸만 다시 앉힌다 — 다른 Action 의 칸과, 한 파일에 줄이 하나뿐인 계획은 그대로다.
///
/// **단계가 다른 Op 끼리는 다시 앉히지 않는다.** 한 hosts 파일을 `remove`(`text_config.remove_line` · 6단계)와
/// `restore: [hosts]`(`hosts.restore_line` · 7단계)가 함께 고치면 뒤 단계의 줄 번호는 앞 단계가 뺀 만큼 밀린다 —
/// 단계를 섞으면 설계-03 §2 의 차례가 무너지므로 그대로 두고, 실행기의 대조가 그 줄을 거부한다(일부 실패).
/// `/etc/cron.d` 의 한 파일을 `text_config_dirs` 로 읽어 환경 줄은 `text_config.remove_line`(6단계), 작업 줄은
/// `persistence.delete`(5단계)로 지울 때도 같다 — 작업 줄이 위에 있으면 환경 줄이 거부된다. 줄을 고치는 Op 은 넷이
/// 모두 단계가 달라, 한 단계 안에서 다른 Op 이 한 파일을 함께 고치는 꼴은 없다. 묶음의 열쇠는 대상 문자열 그대로라
/// 같은 파일을 대소문자만 다른 경로로 짚은 칸(Windows — 대소문자만 다른 `scan_roots` · `text_config_dirs` 의 겹침)도
/// 다른 파일로 묶여 함께 다시 앉히지 않는다.
fn lines_once_bottom_up(actions: &mut Vec<Action>) {
    let mut kept: Vec<Action> = Vec::with_capacity(actions.len());
    for a in actions.drain(..) {
        let twin = line_place(&a).and_then(|_| {
            kept.iter()
                .position(|k| k.op == a.op && k.target == a.target && k.r#match == a.r#match)
        });
        match twin {
            Some(i) => {
                for id in a.because {
                    if !kept[i].because.contains(&id) {
                        kept[i].because.push(id);
                    }
                }
            }
            None => kept.push(a),
        }
    }
    *actions = kept;

    let mut groups: std::collections::BTreeMap<(Op, String), Vec<usize>> = Default::default();
    for (i, a) in actions.iter().enumerate() {
        if let Some((file, _)) = line_place(a) {
            groups.entry((a.op, file.to_string())).or_default().push(i);
        }
    }
    for slots in groups.values().filter(|s| s.len() > 1) {
        let mut lines: Vec<Action> = slots.iter().map(|&i| actions[i].clone()).collect();
        lines.sort_by_key(|a| std::cmp::Reverse(line_place(a).map(|(_, n)| n)));
        for (&i, a) in slots.iter().zip(lines) {
            actions[i] = a;
        }
    }
}

fn restore_op(name: &str) -> Op {
    // 표는 카탈로그에 하나만 둔다 — 여기 목록을 따로 들면 린트와 갈라진다.
    remedy_sdk::catalog::restore_named_op(name).unwrap_or(Op::RegistryRestoreDefault)
}

/// 파일 **안에서** 무엇을 가리키는가.
///
/// # 왜 술어인가
///
/// 파일 경로만으로는 어느 줄·어느 키인지 정해지지 않는다. 값으로 박아 두는 대신
/// 술어로 고정하면 실행 시점에 해소되면서도 **무엇을 지목할지는 계획이 전부
/// 결정한다** (설계-03 §1 의 `process.kill` 과 같은 자리).
///
/// 줄은 **번호와 내용을 함께** 싣는다. 번호만이면 수집과 실행 사이에 파일이
/// 바뀌었을 때 엉뚱한 줄을 지우고, 내용만이면 같은 줄이 여럿일 때 정해지지 않는다.
fn locator(e: &Evidence) -> Option<serde_json::Value> {
    let s = |k: &str| e.target.get(k).and_then(|v| v.as_str());
    let n = |k: &str| e.target.get(k).and_then(|v| v.as_u64());
    match e.subject {
        Subject::TextConfig => Some(serde_json::json!({
            "line_no": n("line_no")?,
            "line": s("line")?,
        })),
        // hosts 는 줄 내용을 통째로 담지 않는다(ip 와 이름만 담는다). 지울 때
        // 대조할 내용은 그 둘을 다시 이은 것이다 — 수집기가 주석과 여분 공백을
        // 떼고 담으므로 같은 모양이 된다.
        // **원본 줄이 있으면 그것을 쓴다.** 실행기가 그 자리의 줄과 비교하는데,
        // `ip` 와 `hostnames` 로 다시 지으면 탭과 연속 공백이 단일 공백이 되어
        // 비교가 걸린다 — 그리고 실기기의 `/etc/hosts` 는 거의 탭을 쓴다.
        // 2026-09-03 Linux 하네스가 이것을 밟았다.
        //
        // 재구성은 **이 필드가 생기기 전에 뜬 스냅샷**을 위해 남긴다. 그런
        // 자료에서는 예전처럼 동작한다 — 나빠지지는 않는다.
        Subject::HostsEntry => {
            let raw = s("line").filter(|l| !l.is_empty());
            let line = match raw {
                Some(l) => l.to_string(),
                None => {
                    let names = e.target.get("hostnames")?.as_array()?;
                    let joined: Vec<&str> = names.iter().filter_map(|v| v.as_str()).collect();
                    format!("{} {}", s("ip")?, joined.join(" "))
                }
            };
            Some(serde_json::json!({ "line_no": n("line_no")?, "line": line }))
        }
        Subject::StructuredConfig => Some(serde_json::json!({ "key_path": s("key_path")? })),
        // cron 항목은 **파일 안의 줄**이다. 그 자리를 계획이 말하지 않으면
        // 실행기가 번호만으로 고치게 되고, 수집과 실행 사이에 파일이 바뀌면
        // **정상 작업이 조용히 멈춘다** (설계-09 P12 결정 5).
        //
        // systemd 유닛과 Windows 예약 작업은 줄이 아니라 등록 자리 자체이므로
        // 여기가 `None` 이고, 백엔드도 그때는 자리를 요구하지 않는다.
        Subject::Persistence => {
            let cron = e.target.get("linux")?.get("cron")?;
            Some(serde_json::json!({
                "line_no": cron.get("line_no")?.as_u64()?,
                "line": cron.get("line")?.as_str()?,
            }))
        }
        // **프로세스의 대상은 술어다** (설계-03 §1). PID 는 계획 시점과 실행
        // 시점 사이에 바뀌므로 계획에 들어갈 자리가 없다.
        //
        // 이 분기가 없어서 `process.kill` 이 **어떤 계획에도 들어갈 수 없었다.**
        // `locator` 가 `None` 을 주면 술어 없는 Action 이 되고, G6 이
        // "무엇을 종료할지 계획이 말하지 않았습니다" 로 막는다 (설계-09 P9 준비 점검).
        //
        // `image_path` 하나다. 명령줄은 실행마다 달라질 수 있고, 이미지 경로가
        // 같은 것을 여럿 죽이는 것은 `max_targets` 가 상한을 건다.
        Subject::Process => Some(serde_json::json!({ "image_path": s("image_path")? })),
        // **어떤 인자를 떼는가가 여기에만 있다.** `structured_config` 의
        // `key_path` 와 같은 자리다 — 계획만 보고는 그 바로가기가 무엇을 잃을지
        // 알 수 없었고, 실행기는 지금 파일에 있는 것을 그냥 뗐다. 그 사이에
        // 사용자가 정당한 인자를 붙였다면 계획에 없는 파괴가 된다.
        //
        // 수집기의 `args` 는 **필드 코드를 이미 뺀 값**이라(`write::split_exec`)
        // 그대로 "떼어야 할 것" 이다. 실행기가 이 값과 맞춰 보고 나서 뗀다.
        Subject::Shortcut => Some(serde_json::json!({ "args": s("args")? })),
        _ => None,
    }
}

/// 이 subject 의 증거를 원복하는 Op.
///
/// 이름으로 지정한 원복(`restore: [av_exclusions]`)은 **어느 증거를 되돌릴지**
/// 를 적지 않는다. subject 가 그것을 정한다 — `av_exclusion` 증거를
/// `proxy.restore` 로 되돌리면 엉뚱한 것을 지운다.
fn restore_op_for(subject: Subject) -> Option<Op> {
    remedy_sdk::catalog::restore_op_for_subject(subject)
}

/// 프록시 원복이 지울 레지스트리 값들.
///
/// # 왜 증거의 필드에서 나오는가
///
/// `proxy_config` 레코드에는 레지스트리 자리가 없다 — `scope`·`server`·
/// `pac_url`·`bypass` 뿐이다. 그래서 **무엇이 맞았는지**(`matched`)가 무엇을
/// 지울지를 정한다. 룰이 짚지 않은 설정까지 지우면 그것은 증거 없는 파괴다.
///
/// `ProxyEnable` 은 건드리지 않는다. 켜짐 플래그를 0 으로 쓰는 것은 카탈로그
/// 밖의 임의 값 쓰기이고(설계-03 §2), 서버·PAC 가 사라지면 가로채기는 이미
/// 멈춘다.
fn proxy_targets(e: &Evidence) -> Vec<String> {
    let scope = e
        .target
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("user");
    let key = if scope.eq_ignore_ascii_case("system") {
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    } else {
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    };
    let mut out: Vec<String> = e
        .matched
        .iter()
        .filter_map(|m| match m.field.as_str() {
            "server" => Some("ProxyServer"),
            "pac_url" => Some("AutoConfigURL"),
            "bypass" => Some("ProxyOverride"),
            _ => None,
        })
        .map(|name| format!("{key}\\{name}"))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// PATH 계열 환경 변수인가.
///
/// `;` 로 이어진 목록이라 부분 문자열로 자르면 안 된다 — `C:\a` 를 지우려다
/// `C:\ab` 까지 잘린다. 그래서 자르는 Op 자체가 다르다.
fn is_path_variable(e: &Evidence) -> bool {
    e.target
        .get("name")
        .and_then(|v| v.as_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("Path") || n.eq_ignore_ascii_case("PATHEXT"))
}

/// Action 하나. **되돌림·위험·백업은 Op 카탈로그가 정한다** — 플러그인도
/// 계획기도 여기에 손대지 않는다 (설계-03 §2).
fn action(op: Op, target: Option<String>, because: Vec<String>) -> Action {
    let info = op.info();
    Action {
        seq: 0, // 정렬 후 다시 매긴다.
        op,
        // **프로세스만 비어 있다** — 대상이 술어이기 때문이다 (설계-03 §1).
        target,
        r#match: None,
        max_targets: None,
        max_children: None,
        max_depth: None,
        max_retries: None,
        // **계획기가 스스로 켜지 않는다.** 계보 확장은 술어가 지목하지 못한
        // 것까지 집합에 넣는 일이라, 매니페스트가 명시적으로 요구할 때만
        // 켜진다 (설계-03 §2).
        include_descendants: None,
        sha256: None,
        size: None,
        // 부분 편집만 채운다. `action_stripping` 을 쓴다.
        strip: None,
        because,
        // 되돌릴 수 있는 Op 은 반드시 백업을 남긴다. 어느 엔트리가 될지는
        // 실행 시점에 정해지므로 종류만 못 박는다.
        backup: op.backup_kinds().first().map(|k| BackupRef {
            entry: String::new(),
            kind: k.id().to_string(),
        }),
        reversible: info.reversible,
        risk: info.risk,
        user_impact: None,
    }
}

/// `${rule.capture}` 를 그룹의 capture 로 채운다.
///
/// 하나라도 못 채우면 `None` 이다. 반쯤 채운 경로는 **엉뚱한 곳을 가리킨다** —
/// 그것을 지우는 것보다 아무것도 하지 않는 편이 낫다.
/// 경로 템플릿이 가리키는 규칙 id — `${rule.capture}` 의 `rule`. 같은 규칙 안의
/// `${capture}`(점 없음)는 규칙을 말하지 않으므로 담지 않는다.
fn template_rules(template: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(i) = rest.find("${") {
        let after = &rest[i + 2..];
        let Some(j) = after.find('}') else {
            break;
        };
        if let Some((rule, _)) = after[..j].split_once('.') {
            out.push(rule);
        }
        rest = &after[j + 1..];
    }
    out
}

fn interpolate(template: &str, scan: &ScanEnvelope) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let j = after.find('}')?;
        let key = &after[..j];
        let value = scan
            .body
            .groups
            .iter()
            .filter(|g| g.verdict)
            .find_map(|g| g.captures.get(key))?;
        out.push_str(value);
        rest = &after[j + 1..];
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(test)]
mod tests;
