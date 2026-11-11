//! 닫힌 집합 카탈로그 — subject 20종 · Op 29종 · 연산자 15종 · capture 함수 9종.
//!
//! 각 항목의 메타데이터는 **exhaustive match** 로 붙인다. 변이를 추가하면
//! 메타데이터를 채우기 전까지 컴파일이 되지 않는다. 표를 따로 두면 언젠가
//! 열거형과 어긋나고, 그 순간 "스키마 단일 소스"가 이름뿐이 된다.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────── Phase

/// 개발 Phase. 설계-09 §3 의 매트릭스와 같은 이름을 쓴다.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Phase {
    P0,
    P1,
    P2,
    P3,
    P4,
    P5,
    P6,
    P7,
    P8,
    P9,
    P10,
    P11,
    P12,
    P13,
    P14,
    P15,
}

impl Phase {
    /// 낮은 것부터. 다른 카탈로그 열거와 같은 규약이다.
    ///
    /// **이름에서 Phase 를 되찾는 자리가 있다** — `DeferredItem.arrives_in` 은
    /// 문자열이고(Phase 이름일 수도, "linux 에는 개념이 없다" 일 수도 있다),
    /// 보고서가 그것을 게이트와 견주어 *"기다리면 오는 것"* 과 *"코어가 하지
    /// 않기로 한 것"* 을 가른다.
    pub const ALL: [Phase; 16] = [
        Phase::P0,
        Phase::P1,
        Phase::P2,
        Phase::P3,
        Phase::P4,
        Phase::P5,
        Phase::P6,
        Phase::P7,
        Phase::P8,
        Phase::P9,
        Phase::P10,
        Phase::P11,
        Phase::P12,
        Phase::P13,
        Phase::P14,
        Phase::P15,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Phase::P0 => "P0",
            Phase::P1 => "P1",
            Phase::P2 => "P2",
            Phase::P3 => "P3",
            Phase::P4 => "P4",
            Phase::P5 => "P5",
            Phase::P6 => "P6",
            Phase::P7 => "P7",
            Phase::P8 => "P8",
            Phase::P9 => "P9",
            Phase::P10 => "P10",
            Phase::P11 => "P11",
            Phase::P12 => "P12",
            Phase::P13 => "P13",
            Phase::P14 => "P14",
            Phase::P15 => "P15",
        }
    }
}

/// 파괴 동작의 위험 등급 (설계-09 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    pub const fn as_str(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

/// 이 subject 를 모으려면 `scan_roots` 에 무엇이 있어야 하는가 (설계-02 §3).
///
/// # 왜 필요한가
///
/// 선언은 했는데 그 종류의 루트가 없으면 **그 subject 는 언제나 0건**이고,
/// 그 위에서 도는 룰은 아무것도 맞히지 못한 채 초록이 된다. 이 사실은
/// 2026-09-01 까지 `10-manifest.md` 의 **손으로 적은 표**에만 있었고, 그래서
/// 아무도 검사하지 못했다 — 우리 예제 `ex02` 가 그 상태로 배포되고 있었다
/// (부모가 `registry_value` 인데 레지스트리 루트가 없었다).
///
/// **미리 뜬 스냅샷으로 도는 시험은 이것을 잡지 못한다.** 수집이 이미 끝난
/// 자료라 "그 스냅샷을 뜰 수 있는가" 를 묻지 않기 때문이다. 그래서 작성
/// 시점에 린트가 본다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scoping {
    /// 자리가 정해져 있다. `scan_roots` 와 무관하게 모인다.
    Fixed,
    /// 경로 루트가 하나라도 있어야 한다.
    Path,
    /// 레지스트리 루트가 하나라도 있어야 한다.
    Registry,
}

impl Scoping {
    pub const fn as_str(self) -> &'static str {
        match self {
            Scoping::Fixed => "fixed",
            Scoping::Path => "path",
            Scoping::Registry => "registry",
        }
    }
}
// ─────────────────────────────────────────────────────────── Subject

/// 관찰 대상 타입 20종 (설계-02 §3).
///
/// 순서는 설계-02 §3 표와 같다. 사람이 두 목록을 대조할 일이 남아 있는 한
/// 순서가 같은 편이 낫다.
///
/// 카탈로그에서 **뺀** 것은 [`RETIRED_SUBJECTS`] 에 이유와 함께 남는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Subject {
    Persistence,
    Autorun,
    Service,
    Process,
    File,
    Indicator,
    RegistryValue,
    RegistryKey,
    TextConfig,
    StructuredConfig,
    Shortcut,
    BootConfig,
    HostsEntry,
    BrowserExtension,
    AvExclusion,
    CertStore,
    ProxyConfig,
    FirewallRule,
    Package,
    UnixSocket,
}

/// subject 하나에 대해 코어가 아는 모든 것.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
pub struct SubjectInfo {
    /// 룰에 적는 이름.
    pub id: &'static str,
    /// 이 subject 의 수집기가 실제로 만들어지는 Phase (설계-09 §3.3).
    pub implemented_in: Phase,
    pub windows: bool,
    /// 그 플랫폼에 **이 개념이 존재하는가**. 설계-02 §3 표의 실체 열이다.
    pub linux: bool,
    /// Linux 에서 이 subject 를 **수집하게 되는** Phase.
    ///
    /// [`Self::linux`] 와 짝이다. 하나는 개념을, 하나는 수집기를 말한다.
    ///
    /// | `linux` | `linux_from` | 뜻 |
    /// |---|---|---|
    /// | `false` | `None` | **개념이 없다** — 기다려도 오지 않는다 |
    /// | `true` | `None` | 개념은 있으나 **이 코어가 수집하지 않는다**. 날짜가 없다 |
    /// | `true` | `Some(p)` | `p` 부터 수집한다 |
    ///
    /// 가운데 줄이 이 필드를 더한 이유다. `linux: true` 하나만 두면 systemd 를
    /// 읽지도 못하면서 `service` 를 선언한 Linux 플러그인이 린트를 통과한다 —
    /// 실측했다 (설계-09 P12).
    pub linux_from: Option<Phase>,
    /// 이 subject 를 모으려면 `scan_roots` 에 무엇이 있어야 하는가.
    ///
    /// **수집기에서 재서 적었다** — `10-manifest.md` 의 표를 옮긴 것이 아니다.
    /// `Path` 는 `collect_files`·`files_with_ext` 를 지나는 것들이고,
    /// `Registry` 는 `registry_roots` 를 지나는 둘이다.
    pub scoping: Scoping,
    pub summary: &'static str,
}

/// 레지스트리 하이브 이름 전수. **`scan_roots` 의 한 줄이 파일 경로인지
/// 레지스트리 키인지 가르는 유일한 기준이다.**
///
/// 여기 한 번만 적는다. 수집기가 따로 갖고 있으면 한쪽만 고쳐졌을 때
/// **린트가 통과시킨 루트를 수집기가 파일 경로로 열려다 0건**이 된다.
pub const REGISTRY_HIVES: [&str; 6] = [
    "HKLM",
    "HKCU",
    "HKU",
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
    "HKEY_USERS",
];

/// `scan_roots` 의 이 줄이 레지스트리 키인가.
pub fn is_registry_root(root: &str) -> bool {
    let head = root.split(['\\', '/']).next().unwrap_or("");
    REGISTRY_HIVES.iter().any(|h| head.eq_ignore_ascii_case(h))
}

/// `file.package_match` 의 값 — 같다 · 다르다 · 기록이 없다(목록에는 있는데 다이제스트가 없거나 알고리즘을 모른다) ·
/// 이 파일을 끝까지 읽지 못했다(크기 상한 · 읽기 오류). 수집기(`remedy-collect` 의 `owner`)가 이 차례로 쓴다.
pub const PACKAGE_MATCH: [&str; 4] = ["same", "different", "unrecorded", "unreadable"];

/// 값이 닫힌 필드 하나 (`Subject::ENUMERATED_FIELDS`).
#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
pub struct EnumeratedField {
    pub subject: Subject,
    /// [`Subject::fields`] 에 있는 이름 그대로.
    pub field: &'static str,
    /// **관측되는 표기 그대로**의 전수.
    pub values: &'static [&'static str],
    /// 이 전수를 **우리 코드가 만드는가.**
    ///
    /// `true` 면 수집기의 `match` 가 전수라 다른 값이 나올 수 없다 — 어긋난
    /// 술어는 어느 기계에서도 참이 되지 않으므로 린트가 **오류**로 막는다.
    ///
    /// `false` 면 OS 표기를 그대로 통과시키는 자리다. 우리가 전수의 주인이
    /// 아니므로 **경고**에 그친다. 새 값이 나타나면 그때 여기에 더한다.
    pub defined: bool,
    pub why: &'static str,
}

impl EnumeratedField {
    /// 이 필드에 `v` 를 적어도 되는가. **대소문자를 접어서 본다** — Windows
    /// 평가가 접기 때문이고, 표기 차이로 맞는 룰을 막지 않기 위해서다.
    pub fn accepts(&self, v: &str) -> bool {
        self.values.iter().any(|x| x.eq_ignore_ascii_case(v))
    }

    /// `subject` 의 `field` 가 값이 닫힌 자리인가.
    pub fn lookup(subject: Subject, field: &str) -> Option<&'static EnumeratedField> {
        Subject::ENUMERATED_FIELDS
            .iter()
            .find(|e| e.subject == subject && e.field == field)
    }
}

/// 카탈로그에서 **뺀** subject 와 뺀 이유 (설계-01 D11).
///
/// # 왜 목록으로 남기는가
///
/// 그냥 지우면 그 id 를 쓴 룰은 "모르는 subject" 를 받는다. 작성자는 오타를
/// 의심하고, 철자를 고쳐 보고, 결국 **같은 제안을 다시 들고 온다.** 정의를 뺀
/// 결정은 한 번 내리고 끝나는 것이 아니라 새 작성자마다 다시 물어지는 것이라,
/// **뺐다는 사실과 이유를 그 자리에서 돌려주는 편**이 값싸다.
///
/// [`Subject`] 의 역직렬화가 여기를 본다. 그래서 `plugin.yaml` 뿐 아니라
/// **예전에 만들어진 `artifacts.json` 을 읽을 때도** 같은 설명이 나온다.
pub const RETIRED_SUBJECTS: [(&str, &str); 1] = [(
    "network_conn",
    "연결 목록은 판정 입력이 아니다 — 표본이라 두 번 재면 답이 달라지고, \
     지울 Op 도 없다(설계-03 §2 의 28종 어디에도 없다). \
     프로세스를 노린 것이라면 `process` 로 적고, 분석가에게 보여줄 정보라면 \
     치료 경로 밖의 `enrich` 를 쓰라 (설계-01 D11)",
)];

impl Subject {
    pub const ALL: [Subject; 20] = [
        Subject::Persistence,
        Subject::Autorun,
        Subject::Service,
        Subject::Process,
        Subject::File,
        Subject::Indicator,
        Subject::RegistryValue,
        Subject::RegistryKey,
        Subject::TextConfig,
        Subject::StructuredConfig,
        Subject::Shortcut,
        Subject::BootConfig,
        Subject::HostsEntry,
        Subject::BrowserExtension,
        Subject::AvExclusion,
        Subject::CertStore,
        Subject::ProxyConfig,
        Subject::FirewallRule,
        Subject::Package,
        Subject::UnixSocket,
    ];

    /// 메타데이터. `match` 가 exhaustive 하므로 변이를 추가하면 여기서 막힌다.
    /// **정의는 됐는데 수집기가 아직 채우지 않는 필드**와 그 이유.
    ///
    /// # 왜 목록으로 못박는가
    ///
    /// `fields()` 가 "쓸 수 있는 필드" 를 말하는데, 그중 일부는 **언제나 비어
    /// 있다.** 그런 필드를 쓴 술어는 조용히 거짓이 되고, 작성자는 룰이 도는
    /// 줄 안다. **`exclude` 에 있으면 더 나쁘다** — 제외가 일어나지 않으므로
    /// 조용히 **더 공격적인** 쪽으로 무너진다. EvilAI 초안의 첫 오탐 방어가
    /// 정확히 그 모양이었다 (설계-09 P9).
    ///
    /// [`NOT_PLANNABLE_YET`](../../remedy_plan/derive/constant.NOT_PLANNABLE_YET.html)
    /// 과 같은 규율이다. **비어 있는 것이 목표다** — 수집기가 채우기 시작하면
    /// 시험이 이 줄을 지우게 만든다.
    /// # 셋째 칸은 **어느 플랫폼에서** 비는가다
    ///
    /// `None` 은 어디서나 빈다. `Some(p)` 는 **그 플랫폼에서만** 빈다.
    ///
    /// 이 칸이 2026-09-05 에 생겼다. 그전에는 축이 없어서 `file.signature` 를
    /// "어디서나 빈다" 로 적고 있었는데, Windows 는 `remedy-wintrust` 로 채운다
    /// (청정 코퍼스 실측 6,689건). 그래서 린트가 Windows 플러그인에게
    /// **"이 술어는 언제나 거짓이다"** 라고 말했다 — 거짓말이었고, 하필
    /// `22-remediate-recipes.md` 가 신뢰 서명으로 재귀 삭제를 막는다고
    /// 가르치는 바로 그 필드다.
    /// # `file.version` 이 여기 **들어갈 수 없는** 이유 (2026-10-27 · C-1b)
    ///
    /// **이 표의 축은 플랫폼인데 그 필드의 축은 파일 형식이다.**
    ///
    /// ELF 에는 버전 리소스가 없다. 그래서 *"리눅스에서는 늘 빈다"* 로 읽고
    /// `Some(Platform::Linux)` 를 적으려 했는데, **그것이 거짓이다** — 수집기는
    /// 확장자만 보고 PE 를 읽으므로 **리눅스 파일계에 있는 PE 도 값을 얻는다.**
    /// 커밋된 리눅스 코퍼스가 그 자리를 이미 담고 있다: WSL 이 Windows 드라이버
    /// 저장소를 붙여 `/usr/lib/wsl/drivers/**.sys` 가 **1,519건**이다(실측).
    ///
    /// 그러면 어느 축도 참이 아니다 —
    ///
    /// | 적는 값 | 어디서 지는가 |
    /// |---|---|
    /// | `Some(Linux)` | 리눅스 코퍼스에 값이 1,519건 → *"비었다고 적었는데"* |
    /// | `None` | Windows 코퍼스에 값이 있다 → *"비었다고 적었는데"* |
    /// | 적지 않는다 | **참이다** |
    ///
    /// `the_unpopulated_table_matches_the_corpus` 가 둘 다 잡는다(앞의 것은
    /// 실측으로 밟았다). **그래서 적지 않는다.** 대가는 리눅스 플러그인이
    /// *"이 술어는 언제나 거짓이다"* 경고를 받지 못하는 것이고, 그 사실은
    /// `24-check-plugins.md` §버전 이 문장으로 말한다.
    ///
    /// 경고를 되살리려면 이 표에 **파일 형식 축**이 필요하다 — 플랫폼 축이
    /// 2026-09-05 에 생긴 것과 같은 모양의 확장이고, 관측이 더 쌓인 뒤에 판단한다.
    /// # `process.modules` 는 들어갈 수 있었고, 빠져 있었다 (2026-10-27)
    ///
    /// **문서는 말하고 있었고 린트만 침묵했다.** `31-nonexistent.md` 가
    /// *"항상 비어 있다"* 로 이미 적었는데 이 표에 없어서, 그 필드를 쓴 룰이
    /// **경고 없이 통과했다.** 모든 프로세스가 싣는 `ntdll` 을 조건으로 건 검사가
    /// *"위협이 발견되지 않았습니다"*(종료 0)로 끝났다 — 현장에서는 **"이 PC 는
    /// 깨끗하다"** 로 읽힌다(PHP 문서 §8-3 실측). 하필 PHP 권고가 악용을 확인한
    /// SAPI 가 **mod_php** 고, 그것을 보는 가장 자연스러운 룰이 그 모양이다.
    ///
    /// **빈 목록은 두 방향으로 틀린다.** 평가기가 목록 필드를 JSON 문자열로
    /// 꺼내므로(`expr::field`) 빈 배열은 `"[]"` 다 —
    ///
    /// | 쓴 술어 | 빈 목록에서 | 무너지는 방향 |
    /// |---|---|---|
    /// | `modules contains '...'` | 늘 거짓 | **미탐** — 실제로 밟았다 |
    /// | `modules exists` | **늘 참** (`"[]"` 가 있다) | **오탐** — 모든 프로세스가 걸린다 |
    ///
    /// 한 줄이 둘을 다 덮는다 — 린트가 작성 시점에, 평가기가
    /// [`lint::unpopulated_field_uses`](crate::lint::unpopulated_field_uses) 를
    /// 지나 `scan.json` 에. **진단은 술어를 막지 않는다**(`exists` 쪽 증거가 그대로
    /// 선다) — `remedy-detect` 의
    /// `an_empty_module_list_is_wrong_in_both_directions_and_says_so` 가 둘 다 잰다.
    ///
    /// **축은 이 필드에 맞는다** — `file.version` 과 다르다. 그래서 2026-10-27 에
    /// `None` 에서 **`Some(Platform::Windows)`** 로 옮겼다: Linux 수집기가
    /// `/proc/<pid>/maps` 의 실행 가능한 파일 매핑을 채우기 시작했고(C-3 · 목표
    /// `remedy_20261027`), 재수집한 청정 코퍼스가 그 자리를 담는다 —
    ///
    /// | 플랫폼 | 프로세스 | `modules` 채움 |
    /// |---|---|---|
    /// | windows | 359건 | **0건** — 열거가 unsafe 다 |
    /// | linux | 76건 | **33건** (`wsl-ubuntu24-headless` 31 · `docker-debian12` 2) |
    ///
    /// 리눅스 쪽 43건이 아직 0 인 것은 **코드가 아니라 스냅샷의 나이**다 — 그
    /// 다섯 장은 수집기가 고쳐지기 전에 떴다. 코퍼스 시험은 플랫폼마다 **한
    /// 건이라도 있는가**를 묻는다.
    ///
    /// 수집기만 고치고 이 축을 그대로 두면 `the_unpopulated_table_matches_the_corpus`
    /// 가 *"비었다고 적었는데 33건에 값이 있다"* 로 막는다 — 실제로 그 순서로
    /// 밟았고, 그것이 이 표가 낡지 않는 이유다.
    ///
    /// **2026-11-12 에 이 표에서 뺐다.** Windows 도 채운다 — `remedy-winmods` 가
    /// 모듈 열거(Toolhelp 스냅숏)를 그 크레이트 하나에 가두고 연다(목표 결정 29). 랩 VM
    /// 실측: 프로세스 158개 중 139개의 목록을 읽었고, 나머지는 보호 프로세스(PPL) 16 ·
    /// `Idle` · 스스로 목록을 거부하는 보안 제품 둘이다. 그 둘은 레코드의
    /// `modules_denied` 로 남는다(룰이 본다).
    pub const NOT_POPULATED_YET: [(Subject, &'static str, Option<Platform>, &'static str); 3] = [
        (
            Subject::File,
            "signature",
            // Windows 는 `remedy-wintrust` 가 채운다. Linux 에는 Authenticode 가
            // 없어 `verify` 가 `Unsupported` 를 내고, 수집기는 그것을 `None` 으로
            // 남긴다 — "확인하지 않았다" 와 같은 값이다.
            Some(Platform::Linux),
            "Linux 에는 Authenticode 가 없다. `remedy-wintrust` 가 그 플랫폼에서 \
             `Unsupported` 를 내고, 수집기는 그것을 `None` 으로 남긴다 — \
             **Windows 에서는 채워진다**",
        ),
        (
            Subject::File,
            "streams",
            None,
            "대체 데이터 스트림 열거에는 `FindFirstStreamW` 가 필요하고 그것은 \
             unsafe 다 — 이 저장소는 크레이트 전부에 `forbid(unsafe_code)` 를 \
             건다. 이름을 아는 스트림만 훑는 방식은 임의 이름을 쓰는 악성 \
             스트림을 체계적으로 놓치므로 열거의 대체재가 되지 못한다",
        ),
        (
            Subject::File,
            "zone",
            None,
            "Mark of the Web 은 `Zone.Identifier` 대체 스트림에 있다. 이름을 \
             알고 있으므로 열거 없이 읽을 수 있으나 수집기가 아직 읽지 않는다. \
             `referrer_url`·`host_url` 은 개인정보라 수집 범위와 제출 범위를 \
             따로 잡아야 하고(설계-02 §3), 그 결정이 아직이다",
        ),
    ];

    /// 값까지 **닫혀 있는** 필드와 그 값 전수.
    ///
    /// # 왜 필드 이름만으로는 모자라는가
    ///
    /// [`fields()`](Subject::fields) 가 이름을 전수로 주는 이유를 그대로
    /// 값에 옮긴 것이다. **AI 는 모르면 그럴듯하게 지어낸다** (설계-06 §1).
    /// 이름을 지어내면 린트가 잡지만, **이름은 맞고 값만 지어낸 술어**는
    /// 아무도 잡지 않았다 — 0건을 맞히고, 그것에 기댄 판정이 서지 않고,
    /// 계획이 비고, `exit 2` 가 난다. 현장에서는 **"이 PC 는 깨끗하다"** 로
    /// 읽힌다.
    ///
    /// 시험 회차 `2026-09-01-opus-4.8-appinit-r1` 이 정확히 그렇게 무너졌다.
    /// `direction` 에 `"inbound"` 라 적었고 관측값은 `"In"` 이다. 그 한
    /// 낱말이 유일한 불합격 사유였고, 주입 문서 138 KB 어디에도 값이 무엇인지
    /// 적혀 있지 않았다.
    ///
    /// # `defined` — 우리가 정한 것과 OS 가 준 것
    ///
    /// 둘을 섞으면 안 된다. **우리 코드가 만드는 값**은 `match` 가
    /// 전수라 다른 값이 나올 수 없으므로 어긋나면 **오류**다. **OS 표기를
    /// 그대로 통과시키는 값**은 우리가 전수의 주인이 아니므로 **경고**다.
    ///
    /// # 대소문자
    ///
    /// 여기 적는 것은 **관측되는 표기 그대로**다. Windows 평가는
    /// `norm_for_compare` 가 대소문자를 접으므로 `"allow"` 로 적어도 맞지만,
    /// Linux 는 접지 않는다. 린트는 접어서 비교한다 — 표기 차이로 오류를
    /// 내면 맞는 룰을 막기 때문이다.
    pub const ENUMERATED_FIELDS: &'static [EnumeratedField] = &[
        EnumeratedField {
            subject: Subject::Service,
            field: "state",
            values: &["unknown"],
            defined: true,
            why: "**실행 여부는 어느 쪽에도 없다.** Windows 수집기는 레지스트리를, Linux \
                수집기는 유닛 파일을 읽는다 — 둘 다 살아 있는 서비스 관리자에게 묻지 \
                않는다. 없는 것을 '정지' 로 적으면 돌고 있는 악성 서비스가 멈춘 것으로 \
                보고되므로 양쪽 다 `unknown` 만 적는다. `running`·`stopped` 로 비교하는 \
                술어는 어느 기계에서도 참이 되지 않는다",
        },
        EnumeratedField {
            subject: Subject::Service,
            field: "start_type",
            values: &[
                "boot", "system", "auto", "manual", "disabled", "unknown", "enabled", "static",
            ],
            defined: true,
            why: "앞의 여섯은 Windows 의 `Start` REG_DWORD 를 옮긴 것이고, \
                `enabled`·`static` 은 systemd 쪽이다(`[Install]` 이 없는 유닛을 systemd 가 \
                `static` 이라 부른다). 두 플랫폼의 낱말이 겹치지 않으므로 한쪽 이름을 다른 \
                쪽에 쓰면 언제나 거짓이다",
        },
        EnumeratedField {
            subject: Subject::RegistryValue,
            field: "type",
            values: &[
                "REG_SZ",
                "REG_DWORD",
                "REG_QWORD",
                "REG_MULTI_SZ",
                "REG_BINARY",
                "REG_UNKNOWN",
            ],
            defined: true,
            why: "`RegValue::type_name()` 의 전수다. 레지스트리 자신은 더 많은 형을 갖지만 \
                수집기가 이 여섯으로 접는다 — 예컨대 `REG_EXPAND_SZ` 는 `REG_SZ` 로 온다. \
                **`REG_MULTI_SZ` 의 여러 값은 `data` 에 줄바꿈으로 이어 붙는다** — \
                구분자를 다르게 짐작한 조건은 오류 없이 조용히 안 맞는다. \
                그 목록에는 **빈 항목이 섞여 있을 수 있고 빈 줄로 나타난다** \
                (`BootExecute` 가 실기기에서 그렇다) — 그래서 `ends_with`·\
                `starts_with` 를 이 필드에 걸면 부서지기 쉽다. `contains` 를 쓸 것",
        },
        EnumeratedField {
            subject: Subject::StructuredConfig,
            field: "format",
            values: &["json", "xml"],
            defined: true,
            why: "구조적 설정으로 펴는 형식은 둘이다 — `.json` 은 JSON, `.xml` · `.config` 는 XML \
                (코어 1.6.0). `yaml`·`toml` 로 비교하는 술어는 언제나 거짓이다. **키 경로의 꼴이 \
                다르다** — JSON 은 `a.b.0.c`, XML 은 요소를 `/` 로 잇고 같은 이름 형제를 `[n]` \
                (0부터)으로 가르며 속성은 `/@이름` 이다(`configuration[0]/system.webServer[0]/\
                fastCgi[0]/application[0]/@fullPath`). 고치는 Op(`structured_config.*`)은 JSON 만 \
                고치고 XML 은 아무것도 쓰지 않고 거부한다",
        },
        EnumeratedField {
            subject: Subject::Package,
            field: "manager",
            values: &["dpkg", "apk", "rpm"],
            defined: true,
            why: "**어느 DB 에서 읽었는가**다. 이 코어는 셋을 파일로 직접 읽는다 — \
                `/var/lib/dpkg/status` · `/lib/apk/db/installed`(텍스트)와 rpm DB \
                (SQLite · Berkeley DB · NDB — `%_dbpath` 의 한 자리 · 코어 1.3.0). \
                수집은 자식 프로세스를 띄우지 않으므로 `dpkg-query` · `rpm` 을 부르지 \
                않는다. **rpm 의 판은 `rpm_version_lt` 로 견주고 공급사는 `vendor` 로 \
                가른다** — 같은 판 문자열을 여러 공급사가 낸다",
        },
        EnumeratedField {
            subject: Subject::CertStore,
            field: "store",
            values: &["ROOT", "CA", "TrustedPublisher", "TrustedPeople", "local", "system"],
            defined: true,
            why: "Windows 는 네 저장소를 훑는다(`certstore::STORES`). Linux 는 **자리가 \
                둘**이다(`certstore::CERT_DIRS`) — `local` 은 \
                `/usr/local/share/ca-certificates`(손으로 더한 CA), `system` 은 \
                `/usr/share/ca-certificates`(배포판이 넣은 것)다. **악성 루트 CA 는 \
                거의 `local` 로 들어온다.** **대소문자가 플랫폼마다 다르다** — Linux \
                평가는 접지 않으므로 표기 그대로 써야 한다",
        },
        EnumeratedField {
            subject: Subject::Autorun,
            field: "scope",
            values: &["system", "user"],
            defined: true,
            why: "기계 전체의 자리에서 왔는지 한 사용자의 자리에서 왔는지 둘뿐이다",
        },
        EnumeratedField {
            subject: Subject::BootConfig,
            field: "entry",
            values: &["{current}"],
            defined: true,
            why: "수집기가 부팅 항목을 **열거하지 않는다** — 지금 도는 항목 하나를                 건강 요약으로 적을 뿐이라 이 이름이 못박혀 있다",
        },
        EnumeratedField {
            subject: Subject::BootConfig,
            field: "recoveryenabled",
            values: &["unknown"],
            defined: true,
            why: "**BCD 는 레지스트리 하이브지만 마운트되어 있지 않다.** 읽지 못한 것을                 '꺼져 있다' 로 적으면 복구가 살아 있는 기계를 껐다고 보고하므로                 `boot_health` 가 언제나 모른다고 적는다. `yes`·`no` 로 비교하는 술어는                 어느 기계에서도 참이 되지 않는다",
        },
        EnumeratedField {
            subject: Subject::BootConfig,
            field: "safeboot_available",
            values: &["yes", "partial", "no", "unreadable", "unknown"],
            defined: true,
            why: "`SafeBoot` 키와 그 아래 `Minimal`·`Network` 를 보고 정한다. **없는 것과                 못 읽는 것을 가른다** — 잠긴 키를 `no` 로 적으면 안전 모드가 멀쩡한                 기계를 깨졌다고 보고한다(`unreadable`). 하나라도 못 읽었으면 나머지가                 무엇이든 `unknown` 이다",
        },
        EnumeratedField {
            subject: Subject::ProxyConfig,
            field: "scope",
            values: &["user", "system"],
            defined: true,
            why: "설정이 어느 하이브에서 왔는지다 — `PROXY_KEYS` 가 HKCU 를 `user`, HKLM 을                 `system` 으로 적는다. 그 둘뿐이다",
        },
        EnumeratedField {
            subject: Subject::BrowserExtension,
            field: "browser",
            values: &[
                "chrome",
                "edge",
                "brave",
                "whale",
                "opera",
                "vivaldi",
                "chromium",
                "unknown",
            ],
            defined: true,
            why: "설치 경로에서 알아본 이름이다. 앞의 일곱 중 어느 것도 경로에 없으면                 `unknown` 이 적히므로 그것도 전수에 든다 — 이름을 못 알아본 확장을                 거르려면 그 값으로 비교해야 한다",
        },
        EnumeratedField {
            subject: Subject::FirewallRule,
            field: "direction",
            values: &["In", "Out"],
            defined: false,
            why: "방화벽 규칙 문자열의 `Dir=` 토큰을 **그대로** 옮긴다 — 수집기가 고쳐 \
                적지 않는다. 청정 코퍼스 509건이 전부 이 둘이다(In 286 · Out 223)",
        },
        EnumeratedField {
            subject: Subject::FirewallRule,
            field: "action",
            values: &["Allow", "Block"],
            defined: false,
            why: "규칙 문자열의 `Action=` 토큰을 그대로 옮긴다. 청정 코퍼스에는 `Allow` \
                509건만 있고 `Block` 은 아직 관측되지 않았다 — 그래서 이 전수는 우리가 \
                보증하는 것이 아니라 **아는 만큼**이다",
        },
        EnumeratedField {
            subject: Subject::UnixSocket,
            field: "kind",
            values: &["stream", "dgram", "seqpacket"],
            defined: true,
            why: "`/proc/net/unix` 의 `Type` 열(1 · 2 · 5)을 이름으로 옮긴다. 그 밖의 값은 \
                `type-<16진>` 그대로 담아 지어내지 않는다",
        },
        EnumeratedField {
            subject: Subject::File,
            field: "package_match",
            values: &PACKAGE_MATCH,
            defined: true,
            why: "이 파일을 깐 패키지(dpkg · RPM)의 기록과 내용이 같은가 — `same` 같다 · \
                `different` 다르다 · `unrecorded` 목록에는 있는데 다이제스트가 없다 · \
                `unreadable` 크기 상한이나 읽기 오류로 끝까지 못 읽었다(코어 1.7.0). 패키지가 \
                소유하지 않은 파일은 칸이 없다. **`package` subject 를 함께 선언한 리눅스 룰에서만 \
                채운다** — 패키지 판으로 판정하는 룰은 `same` 이 아닐 때 그 판을 믿지 않는다",
        },
    ];

    /// 이 subject 의 레코드가 가진 필드 (설계-02 §3). **닫힌 집합이다.**
    ///
    /// # 왜 필요한가
    ///
    /// 사람은 모르면 묻지만 **AI 는 그럴듯하게 지어낸다** (설계-06 §1). 없는
    /// 필드를 쓴 룰은 조용히 아무것도 매치하지 않고, 작성자는 왜 안 되는지
    /// 모른다. `unknown field "cmdline"` 만 주면 다시 지어내므로, 린트가
    /// **유효 필드 전수**를 함께 준다 (설계-06 §7).
    ///
    /// 빈 배열은 "필드가 없다" 가 아니라 **"아직 정의되지 않았다"** 다. 그
    /// subject 의 레코드 타입이 아직 없기 때문이며, 린트가 검사를 건너뛴 사실을
    /// 알린다 — 조용히 통과시키면 "린트 통과" 가 거짓말이 된다.
    ///
    /// OS 고유 속성은 `win.*` 네임스페이스로 분리한다 (설계-02 §3).
    pub const fn fields(self) -> &'static [&'static str] {
        match self {
            Subject::Persistence => &[
                "id",
                "name",
                "enabled",
                "trigger",
                "command",
                "args",
                "principal",
                "source",
                "win.task.register_path",
                "win.task.actions",
                "win.task.run_level",
                "win.task.working_directory",
                // 작업 계정의 프로필 변수를 편 값 (코어 1.2.0 · `WinTaskFields` 문서).
                // 1.2.0 전의 스냅샷에는 없다 — 그 스냅샷에서 이 필드를 쓴 조건은 서지 않는다.
                "win.task.command_expanded",
                "win.task.args_expanded",
                // cron 항목은 **파일 안의 줄**이다. 그것을 지우는 Op 이 번호만
                // 으로 고치지 않으려면 원문이 레코드에 있어야 한다
                // (설계-09 P12 결정 5).
                "linux.cron.line_no",
                "linux.cron.line",
            ],
            Subject::File => &[
                "path",
                "size",
                "mtime",
                "ctime",
                "sha256",
                "streams",
                "content_ref",
                "version",
                "signature.trusted",
                "signature.subject",
                "signature.thumbprint",
                "zone.zone_id",
                "zone.referrer_url",
                "zone.host_url",
                // 이 파일을 깐 패키지와, 그 패키지 기록과 내용이 같은가(코어 1.7.0) — `package` subject 를 함께
                // 선언한 리눅스 룰에서만 채운다(`remedy-collect` 의 `owner` · 린트가 그 조건을 본다).
                "package",
                "package_match",
            ],
            Subject::Autorun => &["id", "scope", "name", "command", "source"],
            Subject::Service => &["id", "name", "state", "start_type", "image_path"],
            Subject::Process => &[
                "pid",
                "ppid",
                "image_path",
                "cmdline",
                "cmdline_decoded",
                "args",
                "user",
                "start_time",
                "modules",
                // 모듈 목록을 묻고 거부당했는가(`"true"` · `"false"`). 실행 파일 경로는 보이는데 목록만
                // 막힌 프로세스(Windows 의 스스로를 지키는 보안 제품)는 관측 불완전으로 세지 않고 이 칸으로
                // 남긴다 — 그 프로세스가 룰이 볼 자리(웹 서버 · PHP)인지는 룰이 안다.
                "modules_denied",
            ],
            Subject::Indicator => &["kind", "value", "source_ref"],
            Subject::RegistryValue => &["hive", "key", "name", "type", "data"],
            Subject::RegistryKey => &["hive", "key", "subkeys", "values"],
            Subject::TextConfig => &["path", "line_no", "line", "section", "key", "value"],
            Subject::StructuredConfig => &["path", "format", "key_path", "value"],
            Subject::Shortcut => &["path", "target", "args", "working_dir", "icon"],
            Subject::BootConfig => &["entry", "recoveryenabled", "safeboot_available"],
            Subject::HostsEntry => &["ip", "hostnames", "line_no", "source", "line"],
            Subject::BrowserExtension => {
                &["browser", "profile", "ext_id", "name", "version", "path"]
            }
            Subject::AvExclusion => &["kind", "value", "source"],
            Subject::CertStore => &[
                "store",
                "subject",
                "issuer",
                "thumbprint",
                "not_after",
                // Linux 인증서는 파일이다. 계획기가 대상으로 삼을 자리가 여기다.
                "linux.path",
            ],
            Subject::ProxyConfig => &["scope", "server", "pac_url", "bypass"],
            Subject::FirewallRule => &[
                "id",
                "name",
                "direction",
                "action",
                "enabled",
                "protocol",
                "local_port",
                "remote_port",
                "remote_address",
                "application",
                "service",
                "profile",
                "source",
            ],
            // **버전이 셋으로 온다.** 배포판 판 문자열 하나로는 견줄 수 없기
            // 때문이다 — `version_lt` 는 점으로 나눈 숫자만 받고, 꼬리는 모양이
            // 같고 순서가 반대라 추측하지 않는다(`8.4.0RC1` 은 낮고
            // `8.2.29-1ubuntu1` 은 높다). 그래서 수집기가 갈라 담는다:
            //
            // | 필드 | `1:2.38.1-5+deb12u3` | 쓰는 법 |
            // |---|---|---|
            // | `version` | 그대로 전부 | `equals` · `contains` — **원문이 증거다** |
            // | `upstream_version` | `2.38.1` | `version_lt` · `version_gt` |
            // | `revision` | `5+deb12u3` | `contains` — 백포트 판을 알아볼 때 |
            //
            // `upstream_version` 이 깨끗한 점숫자가 아니면 **비운다** — 지어내면
            // `file.version` 이 `0.0.0.0` 을 담지 않는 이유와 같은 사고가 된다.
            Subject::Package => &[
                "name",
                "version",
                "upstream_version",
                "revision",
                "arch",
                "source",
                "manager",
                // RPM 의 `VENDOR` — 같은 판을 다시 지은 배포판(Rocky · Alma)을 가른다(코어 1.3.0).
                "vendor",
            ],
            // `name` 은 `/proc/net/unix` 가 보여 주는 그대로다 — 추상 소켓은 `@` 로
            // 시작하고(커널이 앞의 NUL 을 `@` 로 적는다), 파일 소켓은 경로다. 이름 없는
            // 소켓은 담지 않는다(바쁜 서버에 수천 개이고 룰이 겨눌 것이 없다).
            Subject::UnixSocket => &["name", "inode", "listening", "kind"],
        }
    }

    pub const fn info(self) -> SubjectInfo {
        // windows/linux 는 설계-02 §3 표의 'Windows 실체 / Linux 실체' 열에서 온다.
        // 레지스트리 두 종만 Linux 에 대응물이 없다.
        match self {
            Subject::Persistence => SubjectInfo {
                id: "persistence",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P2,
                windows: true,
                linux: true,
                // cron · systemd timer 를 읽는다
                linux_from: Some(Phase::P12),
                summary: "예약 작업 · cron · systemd timer",
            },
            Subject::Autorun => SubjectInfo {
                id: "autorun",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // XDG autostart 의 `.desktop` 과 `/etc/profile.d` 의 스크립트.
                // `~/.bashrc` 같은 **줄 단위** 자동실행은 아직 아니다 — 셸 코드는
                // 명령 하나로 환원되지 않는다 (설계-09 P12 순서 9).
                linux_from: Some(Phase::P12),
                summary: "Run/RunOnce · 시작 폴더 · 셸 프로필 · XDG autostart",
            },
            Subject::Service => SubjectInfo {
                id: "service",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // systemd `.service` 유닛. **`.timer` 는 여기가 아니라
                // `persistence` 다** — 이 표의 요약이 처음부터 그렇게 적고
                // 있었다 (설계-09 P12 순서 9).
                linux_from: Some(Phase::P12),
                summary: "Windows 서비스 · systemd service · SysV init",
            },
            Subject::Process => SubjectInfo {
                id: "process",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // /proc
                linux_from: Some(Phase::P12),
                summary: "실행 중인 프로세스와 로드된 모듈",
            },
            Subject::File => SubjectInfo {
                id: "file",
                scoping: Scoping::Path,
                implemented_in: Phase::P2,
                windows: true,
                linux: true,
                // 표준 라이브러리로 된다
                linux_from: Some(Phase::P12),
                summary: "파일 메타데이터 · 해시 · 서명 · 영역 · 대체 스트림",
            },
            Subject::Indicator => SubjectInfo {
                id: "indicator",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // 앞의 관찰에서 파생된다 — 그것들이 오면 함께 온다
                linux_from: Some(Phase::P12),
                summary: "다른 관찰에서 파생된 지표 (url · domain · ip · hash)",
            },
            Subject::RegistryValue => SubjectInfo {
                id: "registry_value",
                scoping: Scoping::Registry,
                implemented_in: Phase::P4,
                windows: true,
                linux: false,
                // 레지스트리가 없다
                linux_from: None,
                summary: "레지스트리 값. 키 경로에 와일드카드 열거 허용",
            },
            Subject::RegistryKey => SubjectInfo {
                id: "registry_key",
                scoping: Scoping::Registry,
                implemented_in: Phase::P4,
                windows: true,
                linux: false,
                // 레지스트리가 없다
                linux_from: None,
                summary: "레지스트리 키 단위 관찰",
            },
            Subject::TextConfig => SubjectInfo {
                id: "text_config",
                scoping: Scoping::Path,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // 경로만 다르다. ex03 이 이 경로를 이미 쓴다
                linux_from: Some(Phase::P12),
                summary: "ini · conf · 셸 프로필 등 줄 단위 설정",
            },
            Subject::StructuredConfig => SubjectInfo {
                id: "structured_config",
                scoping: Scoping::Path,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // 〃
                linux_from: Some(Phase::P12),
                summary: "JSON · XML 등 구조적 설정",
            },
            Subject::Shortcut => SubjectInfo {
                id: "shortcut",
                scoping: Scoping::Path,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // `.desktop` 항목. **자동실행 자리의 것은 `autorun` 이다** —
                // Windows 에서 시작 폴더의 `.lnk` 와 바탕화면의 `.lnk` 가 갈리는
                // 것과 같다.
                linux_from: Some(Phase::P12),
                summary: ".lnk 바로가기 · .desktop 항목",
            },
            Subject::BootConfig => SubjectInfo {
                id: "boot_config",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // GRUB 이 있지만 수집기가 BCD 전용이다
                linux_from: None,
                summary: "부팅 구성 · GRUB 항목",
            },
            Subject::HostsEntry => SubjectInfo {
                id: "hosts_entry",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // /etc/hosts
                linux_from: Some(Phase::P12),
                summary: "hosts 파일 항목",
            },
            Subject::BrowserExtension => SubjectInfo {
                id: "browser_extension",
                scoping: Scoping::Path,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // 프로필 배치가 같다 — Extensions/<id>/<버전>/manifest.json
                linux_from: Some(Phase::P12),
                summary: "브라우저 확장 프로그램",
            },
            Subject::AvExclusion => SubjectInfo {
                id: "av_exclusion",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // Linux 보안 제품마다 예외 목록의 자리와 형식이 다르다
                linux_from: None,
                summary: "보안 제품 예외 목록. 탐지 근거이자 복원 대상",
            },
            Subject::CertStore => SubjectInfo {
                id: "cert_store",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // `/usr/share/ca-certificates` 와 `/usr/local/share/ca-certificates`
                // 의 인증서 **파일**. `/etc/ssl/certs` 는 거의 전부 심볼릭 링크와
                // 번들이라 원본이 사는 자리를 본다 (설계-09 P12 후속).
                linux_from: Some(Phase::P12),
                summary: "신뢰할 수 있는 루트/게시자 저장소",
            },
            Subject::ProxyConfig => SubjectInfo {
                id: "proxy_config",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // 환경변수 · /etc/environment · 데스크톱 설정으로 흩어져 있다
                linux_from: None,
                summary: "프록시 설정 · PAC",
            },
            Subject::FirewallRule => SubjectInfo {
                id: "firewall_rule",
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: true,
                linux: true,
                // nftables · iptables · ufw · firewalld 가 같은 것을 다르게 말한다
                linux_from: None,
                summary: "방화벽 규칙. 자기 허용·보안 제품 차단이 여기 남는다",
            },
            // **이 코어에서 `windows: false` 인 첫 subject다** (C-2 · 2026-10-27).
            //
            // 개념은 Windows 에도 있다 — MSI 제품, winget, Appx. 그러나 이
            // 축에는 `linux_from` 같은 *"아직"* 칸이 없고 `bool` 하나뿐이다.
            // `true` 로 적으면 Windows 플러그인이 이 subject 를 선언하고 **조용히
            // 0건**을 받는다(`linux: true` + `linux_from: None` 을 막으려고
            // 그 칸을 만든 것과 같은 사고). 그래서 동작이 옳은 쪽을 고른다 —
            // `scope_from_manifest` 가 범위에서 빼고 *"windows 에서는 'package' 를
            // 수집하지 못합니다 — 이 subject 에 걸린 규칙은 전부 미평가입니다"*
            // 를 `notes` 로 남긴다.
            //
            // 대가는 린트가 **작성 시점에 말하지 않는 것**이다. Windows 쪽에는
            // `check_subject_platform` 에 대응하는 검사가 없다(그 함수는
            // `platforms` 에 linux 가 없으면 바로 돌아간다). 거울 축
            // (`windows_from`)을 두는 것이 진짜 고침이고, 그것은 닫힌 집합을
            // 넓히는 결정이라 따로 가져간다.
            Subject::Package => SubjectInfo {
                id: "package",
                // DB 가 정해진 자리에 있다 — `/var/lib/dpkg/status` ·
                // `/lib/apk/db/installed`. `scan_roots` 를 보지 않는다.
                scoping: Scoping::Fixed,
                // "언제 커밋했는가" 가 아니라 **어느 표면이 소유하는가** 다.
                // 수집 표면은 P4 이고, `firewall_rule` 이 P12 회차에 더해졌는데도
                // P4 인 것과 같은 규약이다.
                implemented_in: Phase::P4,
                windows: false,
                linux: true,
                linux_from: Some(Phase::P12),
                summary: "설치된 패키지. 배포판이 백포트한 판을 가리는 유일한 길",
            },
            // **이름 있는 UNIX 소켓**(코어 1.2.0 · 2026-11-08). Ebury 의 현재 주 탐지법이
            // 추상 소켓 이름이라(ESET 공개 점검 스크립트) 그것을 룰로 쓰려고 열었다.
            //
            // 설계-01 D11(살아 있는 네트워크 연결을 빼기로 한 결정)과 **다른 것**이다 —
            // 그 근거 넷 중 셋이 여기 닿지 않는다: `/proc/net/unix` 를 파일로 읽으니
            // 임포트가 없고, 수집기가 있으니 선언만으로 종료 6 이 고정되지 않으며,
            // 상주 임플란트가 떠 있는 동안 계속 열려 있는 **듣는 자리**라 1밀리초
            // 연결 표본과 다르다. 남는 하나(치료 Op 이 없다)는 `package` 처럼 찾기
            // 전용으로 둔다. 설계-01 D11 의 덧붙임에 같은 말이 있다.
            Subject::UnixSocket => SubjectInfo {
                id: "unix_socket",
                // 커널이 정한 자리 하나(`/proc/net/unix`)다. `scan_roots` 를 보지 않는다.
                scoping: Scoping::Fixed,
                implemented_in: Phase::P4,
                windows: false,
                linux: true,
                linux_from: Some(Phase::P12),
                summary:
                    "이름 있는 UNIX 소켓. 추상 이름은 `@` 로 시작한다 — 상주 임플란트가 여는 자리",
            },
        }
    }

    pub const fn id(self) -> &'static str {
        self.info().id
    }

    pub fn from_id(s: &str) -> Option<Subject> {
        Subject::ALL.into_iter().find(|x| x.id() == s)
    }

    /// 이 id 가 **폐기된** 것이면 그 이유.
    pub fn retired_reason(s: &str) -> Option<&'static str> {
        RETIRED_SUBJECTS
            .iter()
            .find(|(id, _)| *id == s)
            .map(|(_, why)| *why)
    }
}

/// `Deserialize` 를 손으로 쓰는 이유는 **폐기 사유를 돌려주기 위해서**다.
///
/// 파생 구현은 `unknown variant 'network_conn'` 만 낸다. 그것은 오타와 폐기를
/// 구분해 주지 않으므로 작성자가 철자를 고쳐 보다가 결국 사람에게 묻게 된다.
/// 여기가 파싱 지점이라 `plugin.yaml` 과 **예전 `artifacts.json`** 이 같은
/// 설명을 받는다 — 린트에 넣으면 앞의 것만 받는다.
impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if let Some(v) = Subject::from_id(&s) {
            return Ok(v);
        }
        if let Some(why) = Subject::retired_reason(&s) {
            return Err(serde::de::Error::custom(format!(
                "subject '{s}' 는 카탈로그에서 빠졌다. {why}"
            )));
        }
        // 모르는 id 에는 **전수**를 준다. 하나만 지적하면 다음 것을 지어낸다
        // (설계-06 §7, `fields()` 와 같은 이유).
        let all: Vec<&str> = Subject::ALL.iter().map(|x| x.id()).collect();
        Err(serde::de::Error::custom(format!(
            "모르는 subject '{s}'. 쓸 수 있는 것 {}종: {}",
            all.len(),
            all.join(", ")
        )))
    }
}

// ─────────────────────────────────────────────────────────── Op

/// 파괴·변경 동작 29종 (설계-03 §2). **이 집합 밖의 동작은 존재하지 않는다.**
///
/// 플러그인이 직접 적는 것이 아니라 계획기가 도출한다. SDK 에 두는 이유는
/// `plan.json` 의 `op` 필드가 이 집합으로 닫혀 있어야 하기 때문이다.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Op {
    #[serde(rename = "file.quarantine_only")]
    FileQuarantineOnly,
    #[serde(rename = "shortcut.strip_args")]
    ShortcutStripArgs,
    #[serde(rename = "av.restore_exclusions")]
    AvRestoreExclusions,
    #[serde(rename = "hosts.restore_line")]
    HostsRestoreLine,
    #[serde(rename = "proxy.restore")]
    ProxyRestore,
    #[serde(rename = "firewall.restore_rule")]
    FirewallRestoreRule,
    #[serde(rename = "file.delete")]
    FileDelete,
    #[serde(rename = "file.delete_on_reboot")]
    FileDeleteOnReboot,
    #[serde(rename = "file.delete_stream")]
    FileDeleteStream,
    #[serde(rename = "registry.delete_value")]
    RegistryDeleteValue,
    #[serde(rename = "registry.strip_value")]
    RegistryStripValue,
    #[serde(rename = "registry.restore_default")]
    RegistryRestoreDefault,
    #[serde(rename = "persistence.disable")]
    PersistenceDisable,
    #[serde(rename = "persistence.delete")]
    PersistenceDelete,
    #[serde(rename = "autorun.remove")]
    AutorunRemove,
    #[serde(rename = "text_config.remove_line")]
    TextConfigRemoveLine,
    #[serde(rename = "structured_config.remove_key")]
    StructuredConfigRemoveKey,
    #[serde(rename = "structured_config.restore_default")]
    StructuredConfigRestoreDefault,
    #[serde(rename = "env.strip_path")]
    EnvStripPath,
    #[serde(rename = "browser_ext.remove")]
    BrowserExtRemove,
    #[serde(rename = "process.kill")]
    ProcessKill,
    #[serde(rename = "service.clear_recovery")]
    ServiceClearRecovery,
    #[serde(rename = "service.stop")]
    ServiceStop,
    #[serde(rename = "service.disable")]
    ServiceDisable,
    #[serde(rename = "service.delete")]
    ServiceDelete,
    #[serde(rename = "dir.delete_recursive")]
    DirDeleteRecursive,
    #[serde(rename = "registry.delete_key")]
    RegistryDeleteKey,
    #[serde(rename = "cert_store.remove")]
    CertStoreRemove,
    #[serde(rename = "boot.restore_default")]
    BootRestoreDefault,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
pub struct OpInfo {
    pub id: &'static str,
    /// 실행기가 이 Op 를 실제로 수행하게 되는 Phase (설계-09 §3.2).
    ///
    /// **Windows 기준이다.** Linux 는 아래를 본다.
    pub implemented_in: Phase,
    /// Linux 에서 이 Op 를 수행하게 되는 Phase. `None` 은 **그 플랫폼에 개념이
    /// 없다**는 뜻이다 (설계-09 P12).
    ///
    /// # 왜 subject 처럼 `bool` 이 아닌가
    ///
    /// `SubjectInfo` 의 `windows`/`linux` 는 *"관찰할 수 있는 대상인가"* 를
    /// 말한다. 여기서 필요한 것은 **"이 코어가 실제로 수행하는가"** 이고,
    /// 그것은 `implemented_in` 과 같은 축이다.
    ///
    /// `Some(P12)` 는 *"P12 에서 켠다"* 는 약속이다. `IMPLEMENTED_THROUGH` 가
    /// 그 Phase 에 닿기 전까지 계획기가 **`deferred` 로 미룬다** — 계획은
    /// 초록인데 실행에서 실패하는 일이 생기지 않는다.
    pub linux_from: Option<Phase>,
    pub risk: Risk,
    /// 격리 컨테이너로 되돌릴 수 있는가. 되돌릴 수 없는 Op 는 P8 로 미뤄져 있다.
    pub reversible: bool,
    /// 이 Op 의 대상이 **산출물을 다시 만들어 내는가** (설계-03 §2).
    ///
    /// 참이면 계획기가 산출물 제거보다 **먼저** 배치한다. 재생성을 일으키는
    /// 설정을 남긴 채 산출물만 지우면 다음 트리거에서 그대로 돌아온다 —
    /// 예약 작업이 드롭 파일을, 정책 레지스트리가 브라우저 확장을 되살린다.
    ///
    /// 3단계(재기동 차단)가 이것을 덮지 못한다. **정책 레지스트리는 작업도
    /// 서비스도 자동실행도 아니기** 때문이다.
    pub regenerator: bool,
}

impl Op {
    /// 이 Op 이 대상을 **고치는가**, 아니면 **없애는가**.
    ///
    /// # 왜 이것이 카탈로그에 있어야 하는가
    ///
    /// 채점 5(실기기 치료)가 "치료 뒤 기계가 청정 기준으로 돌아왔는가" 를
    /// 판정할 때, 대상이 **아직 있다**는 사실의 뜻이 Op 마다 정반대다.
    ///
    /// | | 치료 뒤 대상이 있다 |
    /// |---|---|
    /// | `file.quarantine_only` | **불합격** — 지워졌어야 한다 |
    /// | `hosts.restore_line` | **정상** — 파일은 남고 줄만 빠진다 |
    ///
    /// 이 표를 하네스 스크립트에 적으면 Windows 쪽과 Linux 쪽에 두 벌이 생기고
    /// 갈라진다. 실제로 그랬다 — 2026-09-05 에 PowerShell 하네스가 손으로 적은
    /// 목록에 `hosts.restore_line` 이 빠져 있었고, Windows 위협이 그 Op 을 쓰지
    /// 않아 아무도 몰랐다. Linux 위협 `tls-intercept` 는 그것을 둘 쓴다.
    ///
    /// 그래서 여기 하나로 두고 `machine/ops.json` 으로 내보낸다. **`match` 에
    /// 와일드카드가 없으므로 Op 이 하나 늘면 컴파일러가 분류를 요구한다.**
    pub fn edits_in_place(self) -> bool {
        match self {
            // ── 대상을 고친다 — 치료 뒤에도 그 자리는 남아 있어야 한다 ──
            Op::ShortcutStripArgs            // 바로 가기는 남고 인자만
            | Op::HostsRestoreLine           // hosts 파일은 남고 줄만
            | Op::ProxyRestore               // 설정 자리는 남고 값이 돌아온다
            | Op::FileDeleteStream           // **파일은 남는다** — 스트림만 지운다
            | Op::RegistryStripValue         // 값은 남고 항목 하나만
            | Op::RegistryRestoreDefault
            | Op::TextConfigRemoveLine
            | Op::StructuredConfigRemoveKey
            | Op::StructuredConfigRestoreDefault
            | Op::EnvStripPath
            | Op::BootRestoreDefault
            // 서비스 셋은 **정의를 남긴다.** 같은 자리에 `service.delete` 가
            // 함께 오면 그쪽이 이긴다 — 하네스가 "없애는 Op 이 하나라도 있으면
            // 없어져야 한다" 로 합친다.
            | Op::ServiceClearRecovery
            | Op::ServiceStop
            | Op::ServiceDisable
            // 예약 작업의 정의도 남는다. 끄는 것과 지우는 것이 다르다.
            | Op::PersistenceDisable => true,

            // ── 대상을 없앤다 ──────────────────────────────────────────
            Op::FileQuarantineOnly
            | Op::FileDelete
            | Op::FileDeleteOnReboot
            | Op::DirDeleteRecursive
            | Op::RegistryDeleteValue
            | Op::RegistryDeleteKey
            | Op::AutorunRemove
            | Op::BrowserExtRemove
            | Op::CertStoreRemove
            | Op::ProcessKill
            | Op::ServiceDelete
            | Op::PersistenceDelete
            // 방화벽 규칙과 예외 항목은 **그 항목 자체가 사라진다.**
            // 이름이 `restore` 라고 남는 것이 아니다.
            | Op::FirewallRestoreRule
            | Op::AvRestoreExclusions => false,
        }
    }

    pub const ALL: [Op; 29] = [
        Op::FileQuarantineOnly,
        Op::ShortcutStripArgs,
        Op::AvRestoreExclusions,
        Op::HostsRestoreLine,
        Op::ProxyRestore,
        Op::FirewallRestoreRule,
        Op::FileDelete,
        Op::FileDeleteOnReboot,
        Op::FileDeleteStream,
        Op::RegistryDeleteValue,
        Op::RegistryStripValue,
        Op::RegistryRestoreDefault,
        Op::PersistenceDisable,
        Op::PersistenceDelete,
        Op::AutorunRemove,
        Op::TextConfigRemoveLine,
        Op::StructuredConfigRemoveKey,
        Op::StructuredConfigRestoreDefault,
        Op::EnvStripPath,
        Op::BrowserExtRemove,
        Op::ProcessKill,
        Op::ServiceClearRecovery,
        Op::ServiceStop,
        Op::ServiceDisable,
        Op::ServiceDelete,
        Op::DirDeleteRecursive,
        Op::RegistryDeleteKey,
        Op::CertStoreRemove,
        Op::BootRestoreDefault,
    ];

    pub const fn info(self) -> OpInfo {
        match self {
            Op::FileQuarantineOnly => OpInfo {
                id: "file.quarantine_only",
                implemented_in: Phase::P6,
                linux_from: Some(Phase::P12),
                risk: Risk::Low,
                reversible: true,
                regenerator: false,
            },
            Op::ShortcutStripArgs => OpInfo {
                id: "shortcut.strip_args",
                implemented_in: Phase::P7,
                // `.desktop` 의 `Exec=` 에서 인자만 뗀다. 대상은 여전히 텍스트
                // 파일이라 백업은 파일 전체다 (설계-03 §2).
                linux_from: Some(Phase::P12),
                risk: Risk::Low,
                reversible: true,
                regenerator: false,
            },
            Op::AvRestoreExclusions => OpInfo {
                id: "av.restore_exclusions",
                implemented_in: Phase::P7,
                // Defender 전용이다. Linux 보안 제품은 예외 목록의 자리와 형식이
                // 제각각이라 하나의 Op 으로 다룰 수 없다.
                linux_from: None,
                risk: Risk::Low,
                reversible: true,
                regenerator: false,
            },
            Op::HostsRestoreLine => OpInfo {
                id: "hosts.restore_line",
                implemented_in: Phase::P7,
                linux_from: Some(Phase::P12),
                risk: Risk::Low,
                reversible: true,
                regenerator: false,
            },
            Op::ProxyRestore => OpInfo {
                id: "proxy.restore",
                implemented_in: Phase::P7,
                // `proxy_config` 를 Linux 에서 수집하지 않는다 — 되돌릴 증거가 없다.
                linux_from: None,
                risk: Risk::Low,
                reversible: true,
                regenerator: false,
            },
            // `av.restore_exclusions`·`proxy.restore` 와 같은 부류다 — 악성코드가
            // 건드린 보안 설정을 되돌린다. 지운 규칙은 격리 컨테이너로 들어가므로
            // 잘못 지워도 되살릴 수 있고, 최악이 "정상 앱이 통신을 잃는다" 라서
            // 데이터를 잃는 쪽보다 가볍다.
            Op::FirewallRestoreRule => OpInfo {
                id: "firewall.restore_rule",
                implemented_in: Phase::P7,
                // `firewall_rule` 을 Linux 에서 수집하지 않는다 — 되돌릴 증거가 없다.
                linux_from: None,
                risk: Risk::Low,
                reversible: true,
                regenerator: false,
            },
            Op::FileDelete => OpInfo {
                id: "file.delete",
                implemented_in: Phase::P7,
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            Op::FileDeleteOnReboot => OpInfo {
                id: "file.delete_on_reboot",
                implemented_in: Phase::P7,
                // **없는 것이 아니라 필요 없다.** Windows 는 사용 중 파일을 지우지
                // 못해 예약하지만 Linux 는 `unlink` 가 된다 — `file.delete` 로 끝난다.
                linux_from: None,
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            Op::FileDeleteStream => OpInfo {
                id: "file.delete_stream",
                implemented_in: Phase::P7,
                // 대체 데이터 스트림은 NTFS 의 것이다. xattr 은 이름도 의미도 다르다.
                linux_from: None,
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            Op::RegistryDeleteValue => OpInfo {
                id: "registry.delete_value",
                implemented_in: Phase::P7,
                // 레지스트리가 없다.
                linux_from: None,
                risk: Risk::Medium,
                reversible: true,
                regenerator: true,
            },
            Op::RegistryStripValue => OpInfo {
                id: "registry.strip_value",
                implemented_in: Phase::P7,
                // 레지스트리가 없다.
                linux_from: None,
                risk: Risk::Medium,
                reversible: true,
                regenerator: true,
            },
            Op::RegistryRestoreDefault => OpInfo {
                id: "registry.restore_default",
                implemented_in: Phase::P7,
                // 레지스트리가 없다.
                linux_from: None,
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            Op::PersistenceDisable => OpInfo {
                id: "persistence.disable",
                implemented_in: Phase::P7,
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            Op::PersistenceDelete => OpInfo {
                id: "persistence.delete",
                implemented_in: Phase::P7,
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: true,
                regenerator: true,
            },
            Op::AutorunRemove => OpInfo {
                id: "autorun.remove",
                implemented_in: Phase::P7,
                // 자동실행 항목은 Linux 에서 **파일 하나**다. Windows 에서
                // 레지스트리 값 하나인 것과 자리만 다르다.
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: true,
                regenerator: true,
            },
            Op::TextConfigRemoveLine => OpInfo {
                id: "text_config.remove_line",
                implemented_in: Phase::P7,
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            Op::StructuredConfigRemoveKey => OpInfo {
                id: "structured_config.remove_key",
                implemented_in: Phase::P7,
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            Op::StructuredConfigRestoreDefault => OpInfo {
                id: "structured_config.restore_default",
                implemented_in: Phase::P7,
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            Op::EnvStripPath => OpInfo {
                id: "env.strip_path",
                implemented_in: Phase::P7,
                // PATH 를 레지스트리에서 고치는 동작이다. Linux 의 PATH 는 셸 프로필에
                // 있고 그것은 `text_config` 의 일이다.
                linux_from: None,
                risk: Risk::Medium,
                reversible: true,
                regenerator: true,
            },
            Op::BrowserExtRemove => OpInfo {
                id: "browser_ext.remove",
                implemented_in: Phase::P7,
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            // P8 의 process/service 는 위험 등급이 '중' 이지만 운영 복잡도가
            // 고위험 Op 에 준해 P8 에 있다 (설계-09 §3.2 각주).
            Op::ProcessKill => OpInfo {
                id: "process.kill",
                implemented_in: Phase::P8,
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: false,
                regenerator: false,
            },
            Op::ServiceClearRecovery => OpInfo {
                id: "service.clear_recovery",
                implemented_in: Phase::P8,
                // systemd 의 자동 소생은 유닛 파일의 `Restart=` 다. 그것을 고치는
                // 것은 유닛 **본문 편집**이고, 이 코어가 아직 하지 않는다.
                //
                // **필요하지도 않다.** `service.stop` 이 먼저 돌면 systemd 는 스스로
                // 멈춘 것을 되살리지 않는다 (아래 `service.stop`).
                linux_from: None,
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            // **되돌릴 수 없다** (설계-03 §2 는 "불가 / 없음(상태 기록)" 이라
            // 적는다). 정지는 상태 변화이고 정의는 그대로 남으므로 담을 것이
            // 없다 — 담아 둔 정의를 되돌려도 다시 시작되지는 않는다.
            //
            // 카탈로그가 한동안 `true` 였다. G2 왕복 표가 "되돌릴 수 있다면서
            // 컨테이너를 만들었다" 로 잡았다.
            Op::ServiceStop => OpInfo {
                id: "service.stop",
                implemented_in: Phase::P8,
                // **서비스 관리자가 해야 하는 일이고, 그래서 systemd 에게 시킨다**
                // (설계-09 P12 결정 A, 2026-09-29). 파일만 지우고 프로세스를 죽이면
                // systemd 가 메모리의 정의로 되살렸다 — `Restart=` 실증이 쟀다.
                // 정지를 먼저 걸면 스스로 멈춘 것은 되살리지 않는다(`systemctl stop
                // --no-block`, 정지 요청 직후의 SIGKILL 10번이 한 번도 되살아나지
                // 않았다).
                //
                // **시스템 유닛만이다.** 사용자 유닛은 그 사용자의 세션 버스가 있어야
                // 멈추는데 root 로 도는 치료 도구에는 없다(결정 5) — 계획기가 미룬다.
                // systemd 가 PID 1 이 아닌 곳(컨테이너)에는 멈출 관리자가 없어 할
                // 일이 없고, 그때 멈추는 일은 `process.kill` 이 한다.
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: false,
                regenerator: false,
            },
            Op::ServiceDisable => OpInfo {
                id: "service.disable",
                implemented_in: Phase::P8,
                // 유닛의 `<target>.wants/` 링크를 지운다 — `systemctl disable` 이
                // 하는 일 그대로다.
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: true,
                regenerator: false,
            },
            Op::ServiceDelete => OpInfo {
                id: "service.delete",
                implemented_in: Phase::P8,
                // 유닛 파일과 링크를 함께 지운다.
                linux_from: Some(Phase::P12),
                risk: Risk::Medium,
                reversible: true,
                regenerator: true,
            },
            // **P8 이 아니라 P10 이다.** 이 Op 을 안전하게 만드는 것은 설계-03
            // §4 의 세 번째 조건("하위에 신뢰 서명 파일이 존재하면 거부")이고,
            // 그것은 §3 2층(신뢰 서명 검증)의 일부다.
            //
            // 가드 없이 열면 안 되는 이유는 설계-08 시나리오 F 가 걸어 보았다.
            // 정상 서명된 프로그램 옆에 악성 DLL 이 놓이면 guard 조건은
            // 통과하고, 막는 것은 서명 조건 하나뿐이다.
            //
            // **2026-08-25 (P10-C) 에 열렸다.** 실행기·복원기·왕복 시험은 P8 에서
            // 만들어져 있었고 없던 것은 판정 재료뿐이었다. P10-B 가 서명 검증을
            // 들여왔고(`remedy-wintrust`), `PlatformWrite::trusted_signatures_in`
            // 이 Windows 에서 실제로 답한다 — 하위를 재귀로 훑어 신뢰 서명된
            // 실행 파일을 찾고, **하나라도 확인하지 못하면 오류**를 낸다.
            // 실행기는 그 오류를 거부로 옮긴다(`refusal_before_backup`).
            Op::DirDeleteRecursive => OpInfo {
                id: "dir.delete_recursive",
                implemented_in: Phase::P10,
                // **조건 3 을 지킬 수단이 Linux 에 없다** (설계-09 P12 결정 3).
                //
                // 재귀 삭제 가드의 세 번째 조건은 "하위에 신뢰 서명된 실행 파일이
                // 있으면 거부" 다 — 악성코드가 정상 프로그램 폴더에 떨어졌을 때
                // 그 폴더를 통째로 지워 정상 프로그램을 부수는 것을 막는다.
                //
                // Linux 에는 그 서명 개념이 없다. 패키지 관리자로 대신할 수도
                // 없다 — `dpkg -S` 는 **파일이 패키지 소유인지**를 말하지 서명을
                // 말하지 않고, 악성코드가 사는 `~/.local` · `/tmp` 는 어느
                // 패키지도 소유하지 않아 거기서는 조건 3 이 늘 통과한다. 가드가
                // 있는 것처럼 보이면서 실제로는 없는 상태가 된다.
                //
                // 그래서 **계획 단계에서 닫는다.** 실행 시점 거부로 두면 계획은
                // 초록인데 실행에서 부분 실패가 되고, 사용자는 "치료했다는데 안
                // 됐다" 를 본다. Linux 룰은 지울 것을 지목해야 한다.
                linux_from: None,
                risk: Risk::High,
                reversible: true,
                regenerator: false,
            },
            Op::RegistryDeleteKey => OpInfo {
                id: "registry.delete_key",
                implemented_in: Phase::P8,
                // 레지스트리가 없다.
                linux_from: None,
                risk: Risk::High,
                reversible: true,
                regenerator: true,
            },
            Op::CertStoreRemove => OpInfo {
                id: "cert_store.remove",
                implemented_in: Phase::P8,
                // 인증서 파일을 지우고 **신뢰 저장소를 다시 만든다.** 파일만
                // 지우면 `ca-certificates.crt` 번들에 내용이 그대로 남아 신뢰가
                // 없어지지 않는다 (설계-09 P12 후속).
                linux_from: Some(Phase::P12),
                risk: Risk::High,
                reversible: true,
                regenerator: false,
            },
            Op::BootRestoreDefault => OpInfo {
                id: "boot.restore_default",
                implemented_in: Phase::P8,
                // GRUB 은 있지만 **되돌릴 기본값 카탈로그가 Windows 것뿐**이다
                // (`RESTORE_DEFAULTS`). 그 표가 생기기 전에는 켤 수 없다.
                linux_from: None,
                risk: Risk::High,
                reversible: true,
                regenerator: false,
            },
        }
    }

    pub const fn id(self) -> &'static str {
        self.info().id
    }

    pub fn from_id(s: &str) -> Option<Op> {
        Op::ALL.into_iter().find(|x| x.id() == s)
    }
}

// ──────────────────────────────────────────────── OS 기본값 카탈로그

/// `restore_default` 가 쓸 수 있는 값의 **전부** (설계-03 §2).
///
/// # 왜 카탈로그인가
///
/// 플러그인이 임의 값을 지정할 수 있으면 **서명된 도구가 임의 레지스트리 값을
/// 쓸 수 있는 것**이고, 그 자체가 공격 도구다. 그래서 값의 출처를 코어 안으로
/// 가둔다 — 플러그인은 "어느 대상을 되돌려라" 만 말한다.
///
/// # 무엇을 담고 무엇을 담지 않는가
///
/// **값 하나로 복원이 완결되는 항목만** 담는다. `Winlogon\Shell` 은 값 하나가
/// 곧 정답이다. 반대로 `SafeBoot` 하위처럼 **수백 개 항목의 구조 전체**가
/// 필요한 대상은 담지 않는다 — 어설픈 부분 복원이 손상을 키운다. 그런 대상은
/// 탐지·보고만 하고 OS 복구 도구의 영역으로 넘긴다 (설계-00 §6).
///
/// 경로 비교는 대소문자를 가리지 않는다. 레지스트리가 그렇다.
/// 이름으로 지정하는 원복 — 이름 · 되돌릴 증거의 subject · Op.
///
/// **셋이 한 줄에 있어야 갈라지지 않는다.** 계획기(`remedy-plan`)와 린트가 같은
/// 표를 본다. 이름→Op 과 subject→Op 을 따로 두면 한쪽만 고쳐지고, 그때
/// `av_exclusion` 증거를 `proxy.restore` 로 되돌리는 일이 생긴다.
pub const RESTORE_NAMED: [(&str, Subject, Op); 4] = [
    (
        "av_exclusions",
        Subject::AvExclusion,
        Op::AvRestoreExclusions,
    ),
    ("hosts", Subject::HostsEntry, Op::HostsRestoreLine),
    ("proxy", Subject::ProxyConfig, Op::ProxyRestore),
    ("firewall", Subject::FirewallRule, Op::FirewallRestoreRule),
];

/// 이름으로 지정한 원복이 **어느 subject 의 증거**를 되돌리는가.
pub fn restore_named_subject(name: &str) -> Option<Subject> {
    RESTORE_NAMED
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, s, _)| *s)
}

/// 이름으로 지정한 원복이 쓰는 Op.
pub fn restore_named_op(name: &str) -> Option<Op> {
    RESTORE_NAMED
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, _, o)| *o)
}

/// 이 subject 의 증거를 원복하는 Op.
pub fn restore_op_for_subject(subject: Subject) -> Option<Op> {
    RESTORE_NAMED
        .iter()
        .find(|(_, s, _)| *s == subject)
        .map(|(_, _, o)| *o)
}

/// OS 기본값 하나. **값과 함께 타입을 담는다.**
///
/// # 왜 문자열 하나로는 안 되는가
///
/// 이 표가 문자열만 담던 동안 **수 값을 담을 방법이 없었다.** 억지로 담았다면
/// 실행기가 `from_string(4, "0")` 을 불러 UTF-16 바이트 `30 00 00 00` 을
/// `REG_DWORD` 로 쓴다 — 그 4바이트를 수로 읽으면 **0 이 아니라 48** 이다.
///
/// `LoadAppInit_DLLs` 가 정확히 그런 자리다. 0 이 아닌 값은 *"AppInit DLL 적재를
/// 켠다"* 는 뜻이므로, 치료가 그 스위치를 **켠 채로 두고 껐다고 보고**하게 된다.
/// 지금 표의 일곱 항목이 모두 문자열이라 아직 아무도 밟지 않았을 뿐이다
/// (2026-09-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultValue {
    /// 문자열. **타입은 지금 있는 값의 것을 따른다** — 같은 자리가 `REG_SZ` 일
    /// 수도 `REG_EXPAND_SZ` 일 수도 있고, 그 구분은 기계마다 다르며 카탈로그가
    /// 알 수 없다. 바꿔 쓰면 `%SystemRoot%` 가 전개되지 않는 문자열로 남는다.
    Text(&'static str),
    /// 32비트 수. **타입은 이 카탈로그가 정한다** — 수에는 보존해야 할 형제
    /// 타입이 없고, 검체가 타입까지 바꿔 놓았다면 그것도 되돌려야 한다.
    Dword(u32),
}

impl DefaultValue {
    /// 문자열 기본값이면 그 문자열. 수이면 `None`.
    ///
    /// **수를 문자열로 늘어놓지 않는다.** 구조적 설정처럼 문자열만 받는 자리는
    /// `None` 을 받고 거절해야 한다 — `"0"` 을 써 넣으면 JSON 에 수가 아니라
    /// 문자열이 들어가고, 그것은 되돌린 것이 아니다.
    pub fn as_text(&self) -> Option<&'static str> {
        match self {
            DefaultValue::Text(s) => Some(s),
            DefaultValue::Dword(_) => None,
        }
    }

    /// 사람과 생성 문서가 읽을 표기.
    pub fn display(&self) -> String {
        match self {
            DefaultValue::Text("") => "(빈 값)".to_string(),
            DefaultValue::Text(s) => format!("`{s}`"),
            DefaultValue::Dword(n) => format!("`{n}` (REG_DWORD)"),
        }
    }
}

pub const RESTORE_DEFAULTS: [(&str, DefaultValue); 9] = [
    // 로그온 셸. 이것이 바뀌면 로그인 후 악성코드가 셸 자리에서 뜬다.
    (
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
        DefaultValue::Text("explorer.exe"),
    ),
    // 후행 쉼표가 정상이다. Windows 가 그렇게 쓴다 — 지우면 로그온이 깨진다.
    (
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
        DefaultValue::Text("C:\\Windows\\system32\\userinit.exe,"),
    ),
    (
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman",
        DefaultValue::Text(""),
    ),
    // 확장자 연결. 하이재킹되면 그 확장자를 여는 모든 실행이 가로채인다.
    (
        "HKLM\\SOFTWARE\\Classes\\exefile\\shell\\open\\command\\",
        DefaultValue::Text("\"%1\" %*"),
    ),
    (
        "HKLM\\SOFTWARE\\Classes\\batfile\\shell\\open\\command\\",
        DefaultValue::Text("\"%1\" %*"),
    ),
    (
        "HKLM\\SOFTWARE\\Classes\\cmdfile\\shell\\open\\command\\",
        DefaultValue::Text("\"%1\" %*"),
    ),
    // 안전 모드의 셸. `boot.restore_default` 가 되돌리는 유일한 부팅 구성이다.
    //
    // **여기 하나뿐인 이유**: 카탈로그에는 값 하나로 복원이 완결되는 항목만
    // 담는다 (설계-03 §2). `SafeBoot` **하위**는 수백 개 항목의 구조 전체가
    // 필요해 담지 않는다 — 어설픈 부분 복원이 손상을 키우고, 그런 대상은
    // 탐지·보고만 하고 OS 복구 도구의 영역으로 넘긴다.
    //
    // 이 값은 다르다. 하나짜리 문자열이고 기본값이 모든 Windows 에서 같다.
    // 가로채이면 **안전 모드가 악성코드를 띄우는 자리가 된다** — 회피 경로가
    // 함께 무력해지므로 치료 도구 입장에서는 산출물보다 먼저 되찾아야 한다
    // (설계-00 §6, 그래서 실행 순서 5단계다).
    (
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell",
        DefaultValue::Text("cmd.exe"),
    ),
    // AppInit DLL 적재. **검체가 이 둘을 함께 쓴다** — 경로를 적고 스위치를 켠다.
    //
    // # 왜 지우지 않고 되돌리는가
    //
    // **둘 다 청정 Windows 에 이미 있는 값이다.** 검체가 만든 것이 아니라
    // 덮어쓴 것이다 (실측: `AppInit_DLLs` 는 `REG_SZ` 빈 문자열,
    // `LoadAppInit_DLLs` 는 `REG_DWORD` 0).
    //
    // 지우면 기능은 같다 — 값이 없으면 Windows 는 AppInit 을 쓰지 않는다.
    // 그래서 오래 눈에 띄지 않았다. 그러나 기계는 원래 상태와 달라지고, 보안
    // 기준선 점검은 없는 값을 *"설정되지 않음"* 으로 읽는다. 그리고 무엇보다
    // **`apply` 가 완전 치료(1)라고 말하는데 기계가 청정 기준과 다르다** —
    // 2026-09-05 채점 5 의 첫 회차가 이것을 냈다.
    //
    // `LoadAppInit_DLLs` 가 이 표의 **첫 수 값**이다. 위 `DefaultValue` 의
    // 설명이 왜 타입을 함께 담아야 하는지 적고 있다.
    (
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
        DefaultValue::Text(""),
    ),
    (
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs",
        DefaultValue::Dword(0),
    ),
];

/// 이 대상의 OS 기본값. 카탈로그에 없으면 `None` — **되돌릴 수 없다**.
pub fn restore_default_for(target: &str) -> Option<DefaultValue> {
    RESTORE_DEFAULTS
        .iter()
        .find(|(t, _)| t.eq_ignore_ascii_case(target))
        .map(|(_, v)| *v)
}

// ─────────────────────────────────────────────── 보호 대상 (P8)
//
// **계획기와 실행기가 같은 목록을 봐야 한다.** 계획기는 술어가 지목하는 이미지
// 경로를 보고 막고(P3), 실행기는 술어가 **실제로 무엇을 지목했는지** 알게 된
// 뒤에 막는다(P8). 둘은 서로를 대체하지 않으므로 둘 다 필요하고, 목록을 두 곳에
// 적으면 갈라진다. `remedy-apply` 는 `remedy-plan` 을 의존하지 않으므로 공통
// 자리는 여기다.

/// 무조건 제외하는 고정 PID. Windows 는 System(4), Linux 는 init/systemd(1).
pub const PROTECTED_PIDS: [u32; 2] = [1, 4];

/// 종료하면 즉시 시스템이 멈추는 프로세스의 **이름**.
///
/// **이름만으로 판정하지 않는다.** `C:\Temp\lsass.exe` 같은 위장이 보호를 얻으면
/// 보호 목록이 공격자의 도구가 된다 — 시스템 디렉터리에서 도는지 함께 본다
/// (설계-03 §3).
pub const WINDOWS_CRITICAL_PROCESSES: [&str; 6] = [
    "csrss.exe",
    "winlogon.exe",
    "smss.exe",
    "wininit.exe",
    "lsass.exe",
    "services.exe",
];

/// **키 자체를 지우면 안 되는 레지스트리 경로** (설계-03 §3).
///
/// # 왜 P8 에 필요해졌는가
///
/// P7 까지의 레지스트리 Op 은 **값 하나**만 건드린다. 값을 지우는 것은 되돌릴
/// 수 있고 범위가 명확하다. `registry.delete_key` 는 다르다 — 키 하나를 지우면
/// 그 아래 전부가 함께 사라지고, 그중에 OS 가 기대는 구조가 있으면 그 기능이
/// 통째로 죽는다.
///
/// 규칙은 파일 쪽과 같은 두 겹이다. **여기 적힌 키 자체는 지울 수 없고, 그
/// 하위의 개별 키는 지울 수 있다.** 악성코드는 실제로 이 아래에 자기 항목을
/// 만든다 — IFEO 하이재킹이 그것이고, 부모를 통째로 막으면 첫 플러그인부터
/// 동작하지 않는다.
pub const PROTECTED_REGISTRY_KEYS: [&str; 8] = [
    // IFEO. 하위 `<이미지 이름>` 은 지울 수 있어야 한다.
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    // 서비스 정의 전체. 하위 `<서비스 이름>` 은 `service.delete` 의 대상이다.
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    // 로그온·셸 구성.
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    // 자동 실행. 하위 값은 `autorun.remove` 가 지운다.
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    // 인증서 저장소. 하위 `<지문>` 이 `cert_store.remove` 의 대상이다.
    r"HKLM\SOFTWARE\Microsoft\SystemCertificates",
    // 안전 모드. 이것이 사라지면 회피 경로가 함께 사라진다 (설계-00 §6).
    r"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot",
    // 파일 연결.
    r"HKLM\SOFTWARE\Classes",
];

/// 이 키를 **통째로** 지우려는 시도가 보호에 걸리는가.
///
/// 걸리면 그 이유가 될 보호 경로를 돌려준다. 하위 키는 걸리지 않는다.
pub fn protected_registry_key(target: &str) -> Option<&'static str> {
    let t = target.trim_end_matches('\\').to_ascii_uppercase();
    PROTECTED_REGISTRY_KEYS
        .into_iter()
        .find(|p| p.to_ascii_uppercase() == t)
}

// ─────────────────────────────────────────────────────────── 연산자

/// 룰 조건 연산자 15종 (설계-02 §4). 닫힌 집합이다.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    NotEquals,
    /// 정규식. **RE2** 다 — 역참조·전방탐색이 없는 대신 입력 길이에 선형이라
    /// 룰이 스캐너를 정지시키는 사고가 원천적으로 불가능하다.
    Matches,
    Contains,
    StartsWith,
    EndsWith,
    #[serde(rename = "in")]
    In,
    Glob,
    Exists,
    Gt,
    Lt,
    /// 버전 비교 — **점으로 나눈 숫자**만 견준다 (`8.2.29`).
    ///
    /// # 왜 `lt` 로 되지 않는가
    ///
    /// `lt` 는 수와 RFC3339 시각만 본다. `8.2.29` 는 둘 다 아니어서 *"견줄 수
    /// 없습니다"* 진단과 함께 거짓이 됐다. 두 자리로 줄여 적으면 읽히기는
    /// 하는데 **순서가 뒤집힌다** — 수로는 `8.10 < 8.9` 다.
    ///
    /// # 왜 `lt` 를 고치지 않았는가
    ///
    /// `1.10` 은 수로도 버전으로도 읽히고 순서가 반대다. 기존 연산자에 버전
    /// 의미를 끼워 넣으면 **이미 출하된 룰의 뜻이 조용히 바뀐다** —
    /// `sideload-drop` 이 `gt`·`lt` 로 시각과 크기를 견주고 있다. 그래서
    /// 작성자가 버전임을 적게 한다.
    ///
    /// # 꼬리는 받지 않는다
    ///
    /// `8.4.0RC1`(사전 배포)은 `8.4.0` 보다 **낮고** `8.2.29-1ubuntu1`(패키지
    /// 개정)은 `8.2.29` 보다 **높다**. 모양이 같고 순서가 반대라 문자열만으로
    /// 정할 수 없어 **추측하지 않고 견줄 수 없다고 말한다**. 패키지 개정을
    /// 가리는 것은 패키지 subject 의 몫이다.
    VersionLt,
    /// `version_lt` 의 반대 방향. 의미론은 그쪽 설명과 같다.
    VersionGt,
    /// **배포판이 적은 판**을 견준다 — 개정 꼬리까지 (`8.1.2-1ubuntu2.28`).
    ///
    /// # 왜 `version_lt` 로 안 되는가
    ///
    /// 그쪽은 꼬리를 **일부러 거절한다** — 위 설명대로 모양이 같고 순서가
    /// 반대인 두 종류를 문자열만 보고 가를 수 없기 때문이다. 그래서 배포판
    /// 기계에서는 *"재지 못했다"*(종료 6)로 끝났고, **백포트를 가릴 수 없던
    /// 이유의 절반이 그것이다**: 배포판은 상류 번호를 올리지 않고 고치므로
    /// 고친 기계와 안 고친 기계의 상류 판이 **같다**(실측: ubuntu 22.04 의
    /// `php8.1-cli` 가 `8.1.2-1ubuntu2.28`, 상류는 `8.1.2` 고정).
    ///
    /// # 꼬리의 순서는 추측이 아니라 규칙이다
    ///
    /// dpkg 가 그것을 정의한다(데비안 정책 §5.6.12) — `[epoch:]상류[-개정]` 을
    /// 셋으로 갈라 견주고, 조각 안에서는 숫자 아닌 부분과 숫자 부분을 번갈아
    /// 본다. **`~` 는 무엇보다도 먼저**이므로 `1.0~rc1 < 1.0 < 1.0+b1` 이다.
    /// 구현과 시험은 `remedy_detect::compare::pkg_version_cmp` 에 있다.
    ///
    /// # `_` 는 받지 않는다
    ///
    /// apk 의 `_alpha` 는 그 판보다 **낮고** dpkg 의 규칙에서 `_` 는 글자보다
    /// **뒤**다 — 같은 문자열의 순서가 두 매니저에서 반대다. 거절하고
    /// *"재지 못했다"* 로 돌린다([`is_pkg_version`]). `-rN` 개정은 두 규칙이
    /// 같은 답을 내므로 apk 판도 이 연산자로 견준다.
    ///
    /// # 반대 방향을 두지 않은 이유
    ///
    /// `not pkg_version_lt` 가 `>=` 이므로 범위는 둘로 적을 수 있다
    /// (`pkg_version_lt(위) and not pkg_version_lt(아래)`). `version_gt` 가
    /// 짝으로 있는 것은 그쪽이 먼저 생겼기 때문이고, 닫힌 집합은 **쓰이는
    /// 것만** 늘린다.
    PkgVersionLt,
    /// **RPM 이 적은 판**끼리 견준다 (2026-11-09 · 코어 1.3.0).
    ///
    /// # 왜 `pkg_version_lt` 로 안 되는가
    ///
    /// RHEL 계열의 개정은 `8.el9_8.1` · `8.module+el8.10.0+25117+30337cca` 처럼 **`_` 를 담는다** —
    /// `pkg_version_lt` 는 dpkg 와 apk 가 `_` 를 반대로 읽어 그것을 거절하므로 RPM 기계는 늘 *"재지
    /// 못했다"*(6)가 된다. 규칙도 다르다 — rpm 의 `rpmvercmp` 는 글자 · 숫자가 아닌 문자를 **구분자로만**
    /// 보고(dpkg 는 순서가 있는 문자로 본다), 숫자 조각이 글자 조각보다 언제나 높다. 같은 문자열의 순서가
    /// 두 규칙에서 갈릴 수 있으므로 연산자를 나눈다 — 룰이 어느 매니저의 판인지 고른다.
    ///
    /// # 규칙 (rpm 의 `rpmvercmp` · `rpmverCmp`)
    ///
    /// `[epoch:]판[-개정]` 을 셋으로 갈라 **epoch → 판 → 개정** 순으로 견준다. epoch 이 없으면 `0`, 개정은
    /// **둘 다 있을 때만** 견준다. 조각 안에서는 글자 · 숫자가 아닌 문자를 건너뛰고 숫자 덩어리와 글자
    /// 덩어리를 번갈아 본다 — 숫자는 수로, `~` 는 무엇보다도 먼저, `^` 는 끝보다는 뒤이고 다른 무엇보다는
    /// 먼저다. 구현과 시험은 `remedy_detect::compare::rpm_version_cmp` 에 있다.
    RpmVersionLt,
    /// 파일 전용이 아니다. 바이트열을 제공하는 모든 필드에 적용된다.
    Yara,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
pub struct OperatorInfo {
    pub id: &'static str,
    pub implemented_in: Phase,
    /// `value` 를 요구하는가. `exists` 만 요구하지 않는다.
    pub takes_value: bool,
}

impl Operator {
    pub const ALL: [Operator; 16] = [
        Operator::Equals,
        Operator::NotEquals,
        Operator::Matches,
        Operator::Contains,
        Operator::StartsWith,
        Operator::EndsWith,
        Operator::In,
        Operator::Glob,
        Operator::Exists,
        Operator::Gt,
        Operator::Lt,
        Operator::VersionLt,
        Operator::VersionGt,
        Operator::PkgVersionLt,
        Operator::RpmVersionLt,
        Operator::Yara,
    ];

    pub const fn info(self) -> OperatorInfo {
        // P2 의 '연산자 5종' 은 설계-09 P2 표면 선언에서 온다.
        match self {
            Operator::Equals => OperatorInfo {
                id: "equals",
                implemented_in: Phase::P2,
                takes_value: true,
            },
            Operator::NotEquals => OperatorInfo {
                id: "not_equals",
                implemented_in: Phase::P4,
                takes_value: true,
            },
            Operator::Matches => OperatorInfo {
                id: "matches",
                implemented_in: Phase::P2,
                takes_value: true,
            },
            Operator::Contains => OperatorInfo {
                id: "contains",
                implemented_in: Phase::P2,
                takes_value: true,
            },
            Operator::StartsWith => OperatorInfo {
                id: "starts_with",
                implemented_in: Phase::P2,
                takes_value: true,
            },
            Operator::EndsWith => OperatorInfo {
                id: "ends_with",
                implemented_in: Phase::P2,
                takes_value: true,
            },
            Operator::In => OperatorInfo {
                id: "in",
                implemented_in: Phase::P4,
                takes_value: true,
            },
            Operator::Glob => OperatorInfo {
                id: "glob",
                implemented_in: Phase::P4,
                takes_value: true,
            },
            Operator::Exists => OperatorInfo {
                id: "exists",
                implemented_in: Phase::P4,
                takes_value: false,
            },
            Operator::Gt => OperatorInfo {
                id: "gt",
                implemented_in: Phase::P4,
                takes_value: true,
            },
            Operator::Lt => OperatorInfo {
                id: "lt",
                implemented_in: Phase::P4,
                takes_value: true,
            },
            // **이 칸은 "언제 커밋했는가" 가 아니라 "어느 표면이 소유하는가"
            // 다.** `firewall_rule` 이 P12 회차에 더해졌는데도 `P4` 인 것과 같은
            // 규약이다 — 연산자는 P4(탐지 표면 확장)의 몫이고, 그래서 버전
            // 비교도 거기에 든다. 게이트(`IMPLEMENTED_THROUGH`)보다 높은 값을
            // 적으면 `schema.rs` 가 *"아직 기다리는 연산자"* 로 잡는다.
            Operator::VersionLt => OperatorInfo {
                id: "version_lt",
                implemented_in: Phase::P4,
                takes_value: true,
            },
            Operator::PkgVersionLt => OperatorInfo {
                id: "pkg_version_lt",
                // 위 `VersionLt` 의 주석과 같은 규약 — 연산자는 탐지 표면(P4)의
                // 몫이고, 이것이 P12 회차에 더해졌다는 사실은 이 칸이 아니라
                // 설계-09 가 적는다.
                implemented_in: Phase::P4,
                takes_value: true,
            },
            Operator::VersionGt => OperatorInfo {
                id: "version_gt",
                implemented_in: Phase::P4,
                takes_value: true,
            },
            // 위 `VersionLt` 의 주석과 같은 규약 — 연산자는 탐지 표면(P4)의 몫이다.
            Operator::RpmVersionLt => OperatorInfo {
                id: "rpm_version_lt",
                implemented_in: Phase::P4,
                takes_value: true,
            },
            Operator::Yara => OperatorInfo {
                id: "yara",
                implemented_in: Phase::P4,
                takes_value: true,
            },
        }
    }

    pub const fn id(self) -> &'static str {
        self.info().id
    }
}

/// 버전인가 — **점으로 나눈 열 진수 정수**뿐이다.
///
/// `version_lt`·`version_gt` 가 견줄 수 있는 모양이고, 린트가 룰의 리터럴을
/// 거절하는 기준이다.
///
/// # 왜 평가기가 아니라 카탈로그에 있는가
///
/// **린트가 받아들이는 모양과 평가기가 견주는 모양이 같아야 한다.** 두 곳에
/// 따로 적으면 한쪽이 바뀔 때 린트를 통과한 룰이 평가에서 *"버전으로 읽지
/// 못했습니다"* 로 끝난다 — 작성자는 린트가 초록이었으니 룰이 맞는 줄 안다.
/// 연산자의 정의가 여기 있으므로 그 연산자가 받는 모양도 여기 있다.
///
/// 앞뒤 공백은 떼고 본다. 수집기의 `value` 는 `=` 뒤를 다듬기만 한 원문이라
/// 공백이 남을 수 있고, `gt`·`lt` 쪽도 같은 자리에서 `trim` 한다 — 같은 필드에
/// 둘 중 무엇을 걸든 읽는 모양이 달라지면 안 된다.
pub fn is_version(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.split('.')
            .all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()))
}

/// `pkg_version_lt` 가 견줄 수 있는 모양인가 (C-2 후속 · 2026-10-27).
///
/// # `is_version` 과 무엇이 다른가
///
/// [`is_version`] 은 **점으로 나눈 숫자**만 받는다. 꼬리를 거절하는 것이 그
/// 연산자의 요점이다 — `8.4.0RC1` 은 낮고 `8.2.29-1ubuntu1` 은 높아서 모양만
/// 보고는 순서를 정할 수 없다. 이쪽은 **배포판이 적은 판 그대로**를 받는다:
/// `[epoch:]상류[-개정]` 이고 순서는 dpkg 의 규칙(데비안 정책 §5.6.12)이다.
///
/// | 받는다 | 거절한다 | 왜 |
/// |---|---|---|
/// | `8.1.2-1ubuntu2.28` · `1:2.38.1-5+deb12u3` · `3.6.8-r1` · `8.2.29~rc1` | `wheezy`(숫자로 시작하지 않는다) | 상류 판은 숫자로 시작해야 한다(정책) |
/// | | `1.0_alpha1` | **`_` 는 dpkg 와 apk 가 반대로 읽는다** |
/// | | `v8.2.29` · 빈 값 | 판이 아니다 |
///
/// # `_` 를 거절하는 이유
///
/// apk 의 `_alpha`·`_beta`·`_pre`·`_rc` 는 **그 판보다 낮다**(사전 배포). dpkg
/// 의 규칙에서 `_` 는 글자도 숫자도 아닌 문자라 **글자보다 뒤**로 가므로
/// `1.0_alpha1` 이 `1.0` 보다 **높아진다** — 같은 문자열의 순서가 두 매니저에서
/// 반대다. 추측하는 대신 *"재지 못했다"* 로 돌려 종료 6 을 낸다. `version_lt`
/// 가 꼬리를 거절하는 것과 같은 규율이다. (dpkg 는 같은 뜻을 `~` 로 적고,
/// 그것은 이 규칙이 제대로 읽으므로 받는다.)
pub fn is_pkg_version(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    // epoch 은 `숫자:` 다. 콜론은 그 자리에만 올 수 있다.
    let body = match s.split_once(':') {
        Some((e, rest)) => {
            if e.is_empty() || !e.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            rest
        }
        None => s,
    };
    // 상류 판은 **숫자로 시작한다** (정책). 그래야 `wheezy` 같은 이름이 판으로
    // 읽히지 않는다.
    if !body.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    body.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'~'))
}

/// `rpm_version_lt` 가 견줄 수 있는 모양인가 (2026-11-09).
///
/// `[epoch:]판[-개정]` — epoch 은 숫자, 판은 **숫자로 시작**하고(그래야 이름이 판으로 읽히지 않는다),
/// 글자 · 숫자와 `.` `_` `+` `~` `^` `-` 만 담는다. [`is_pkg_version`] 과 달리 `_` 를 받는다 — rpm 에서는
/// 구분자일 뿐이라 순서가 갈리지 않는다(RHEL 의 `el9_8`).
pub fn is_rpm_version(s: &str) -> bool {
    let s = s.trim();
    let body = match s.split_once(':') {
        Some((e, rest)) => {
            if e.is_empty() || !e.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            rest
        }
        None => s,
    };
    body.starts_with(|c: char| c.is_ascii_digit())
        && body.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'~' | b'^' | b'-')
        })
}

/// 룰이 **따옴표 없이** 적어서 버전으로 읽을 수 없게 된 리터럴인가.
///
/// # 왜 이것이 필요한가 (2026-10-27 적대 검증 · high · 실측 재현)
///
/// YAML 은 따옴표 없는 `8.10` 을 **실수**로 읽는다. 매니페스트의 `value` 는
/// `serde_json::Value` 이고 거기 담긴 뒤 `to_string()` 은 `"8.1"` 이다 — **뒤의
/// 0 은 돌아오지 않는다.** 그 값으로 견주면 `8.9 < 8.10` 이 거짓이 되어
/// **취약한 기계가 진단 한 줄 없이 종료 0 으로 나간다**(실측).
///
/// 하필 이 모양이 이 기능을 만든 동기 예시다 — `version_cmp` 의 설명과
/// `24-check-plugins.md` §버전 이 둘 다 `8.10` 과 `8.9` 를 든다. 그 문장을 읽은
/// 작성자가 `value: 8.10` 을 그대로 적는 것이 가장 자연스러운 경로다.
///
/// **정수는 안전하다** — `value: 8` 은 왕복한다. 걸러 내는 것은 실수뿐이고,
/// `8.0` 과 `8.00` 처럼 왕복하는 값도 함께 걸린다. 가릴 수 없는 것을 통과시키는
/// 쪽보다 **따옴표를 요구하는 쪽**이 맞다 — 원문을 복원할 길이 없다.
pub fn unquoted_version_number(v: &serde_json::Value) -> bool {
    matches!(v, serde_json::Value::Number(n) if !(n.is_i64() || n.is_u64()))
}

// ─────────────────────────────────────────────────────────── capture 함수

/// `capture` 표현식에서 쓸 수 있는 함수 9종 (설계-02 §4). 임의 코드가 아니다.
///
/// # `last_path` — 마지막 경로 (2026-11-08 · 코어 1.2.0)
///
/// `first_path` 는 문자열의 **첫** 경로를 집는다. 한 필드에 실행 파일과 인자가
/// **함께** 오거나, 인자 안에 실행 파일이 다시 오는 자리에서는 원하는 경로가 첫
/// 자리가 아니다.
///
/// 이 자리는 2026-09-04 회차 응시자가 짚었고(`autorun` 의 `command` 는 Run 값
/// 그대로라 `"…\node.exe" "…\payload.js"` 가 한 문자열이다), 그때는 **관측이
/// 쌓인 뒤에 판단**하기로 비워 두었다. 2026-11-08 에 공개 보도가 그 관측을 줬다 —
/// Trend Micro 가 본 EvilAI 의 예약 작업 동작이 `cmd.exe /c start "" /min
/// "…\node.exe" "…\{UID}or.js"` 다. `first_path` 는 `/c` 를 집고, 그래서 그 작업이
/// 가리키는 페이로드를 룰이 세울 수 없었다(랩 실측 · 종료 0).
///
/// 무엇을 집는지는 `last_path` 의 문서(`remedy-detect` `expr.rs`)에 있다 — 역슬래시가
/// 든 마지막 토큰, 없으면 슬래시가 든 마지막 토큰.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureFn {
    FirstPath,
    LastPath,
    Dirname,
    Basename,
    Lower,
    ExpandEnv,
    TrimQuotes,
    Base64Decode,
    HexDecode,
}

impl CaptureFn {
    pub const ALL: [CaptureFn; 9] = [
        CaptureFn::FirstPath,
        CaptureFn::LastPath,
        CaptureFn::Dirname,
        CaptureFn::Basename,
        CaptureFn::Lower,
        CaptureFn::ExpandEnv,
        CaptureFn::TrimQuotes,
        CaptureFn::Base64Decode,
        CaptureFn::HexDecode,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            CaptureFn::FirstPath => "first_path",
            CaptureFn::LastPath => "last_path",
            CaptureFn::Dirname => "dirname",
            CaptureFn::Basename => "basename",
            CaptureFn::Lower => "lower",
            CaptureFn::ExpandEnv => "expand_env",
            CaptureFn::TrimQuotes => "trim_quotes",
            CaptureFn::Base64Decode => "base64_decode",
            CaptureFn::HexDecode => "hex_decode",
        }
    }
}

// ─────────────────────────────────────────────────────────── 지정 확장 토큰

/// 경로에 쓸 수 있는 고정 토큰 (설계-02 §4). 임의 확장이 아니라 열거된 것만이다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
pub struct DesignatedToken {
    pub token: &'static str,
    pub expands_to: &'static str,
    /// `allow_removable: true` 선언을 요구하는가.
    pub requires_allow_removable: bool,
}

/// 지정 확장 토큰 3종.
///
/// `%ALLUSERPROFILES%` 가 없으면 다중 사용자 환경에서 현재 로그온 사용자만
/// 치료되고 나머지는 감염 상태로 남는다.
pub const DESIGNATED_TOKENS: [DesignatedToken; 3] = [
    DesignatedToken {
        token: "HKU\\*",
        expands_to: "모든 사용자 레지스트리 하이브 (프로필 수 상한 적용)",
        requires_allow_removable: false,
    },
    DesignatedToken {
        token: "%ALLUSERPROFILES%",
        expands_to: "모든 사용자 프로필 디렉터리",
        requires_allow_removable: false,
    },
    DesignatedToken {
        token: "%REMOVABLE%",
        expands_to: "연결된 이동식 매체",
        requires_allow_removable: true,
    },
];

// ─────────────────────────────────────────────────────────── 대상 OS

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Linux,
    Darwin,
}

impl Platform {
    pub const ALL: [Platform; 3] = [Platform::Windows, Platform::Linux, Platform::Darwin];

    pub const fn id(self) -> &'static str {
        match self {
            Platform::Windows => "windows",
            Platform::Linux => "linux",
            Platform::Darwin => "darwin",
        }
    }
}
