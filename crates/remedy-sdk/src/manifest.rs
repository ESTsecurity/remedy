//! `plugin.yaml` 스키마 (설계-02 §2·§4·§5·§6·§6-1).
//!
//! 모든 구조체에 `deny_unknown_fields` 를 건다. 오타 난 키가 조용히 무시되면
//! 작성자는 룰이 도는 줄 알지만 실제로는 아무것도 매치하지 않는다. 탐지 제품에서
//! 그것은 미탐이고, 치료 제품에서는 **잘못된 대상을 지우는 경로**가 된다.

use crate::catalog::{Operator, Platform, Subject};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 다국어 문자열. 최소 `en` 은 있어야 한다.
pub type LocalizedText = BTreeMap<String, String>;

// ─────────────────────────────────────────────────────────── 최상위

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    /// SDK 스키마 버전. 코어가 호환성을 판단한다 (설계-02 §10).
    pub schema_version: u32,
    /// 전역 고유. `[a-z0-9-]+`
    pub id: String,
    /// semver
    pub version: String,
    /// 요구 코어 최소 버전
    pub min_core: String,
    pub platforms: Vec<Platform>,
    pub name: LocalizedText,

    /// 이 플러그인이 **무엇을 하는 것인가.** 적지 않으면 치료 플러그인이다.
    ///
    /// # 왜 선언이어야 하는가 (B-1 · 2026-10-26)
    ///
    /// 코어는 점검과 치료를 **가릴 수 없었다.** `remediate` 가 없다는 사실로
    /// 유추하는 길이 있었지만 그것은 틀린다 — 가이드 예제 `ex01-scheduled-task`
    /// 는 `remediate` 가 없고 **악성 예약 작업을 탐지한다**(점검이 아니다).
    /// 그 유추를 코어에 넣으면 악성 작업에 *"취약"* 이라고 말하게 된다.
    ///
    /// 더 나쁜 것이 있었다. 관측 회귀를 지키는 장치들의 픽스처가 전부
    /// `remediate` 없이 만들어진다 — `Invoke-ObsVerify.ps1` 의 여덟,
    /// `capture-console.sh` 의 `force-incomplete`, `verify_record.rs` 의
    /// `plugin_at`. 유추를 넣으면 **그 셋이 먼저 꺼지고**, 아무 곳도 열어 보지
    /// 못한 스캔이 *"위협 없음"* 을 내는 구멍(관측 01 D2)의 회귀 방지가 사라진다.
    ///
    /// # 값이 하나뿐인 이유
    ///
    /// `check` 하나다. *"치료"* 를 적는 길을 **문법으로 닫는다** — 출하 중인
    /// 플러그인 20개는 전부 `remediate` 를 갖고 이 키를 적지 않으므로, 값을
    /// 둘로 만들면 20개에 `kind: remediate` 를 적는 길이 열리고 그 길은 버전
    /// 올림 20개 · `versions.lock.json` · 실기기 치료 증거 20벌 재측정 ·
    /// `RELEASE.md` · 재서명을 한꺼번에 켠다. 막는 것을 규율이 아니라
    /// 타입으로 한다.
    ///
    /// # 키가 있으면 값이 있어야 한다
    ///
    /// `#[serde(default)]` 만 걸면 **`kind:`(값 없음) · `kind: null` · `kind: ~` 가
    /// 키를 지운 것과 같아진다** — 플러그인이 조용히 치료로 돌아가고 네 관문
    /// (serde · `validate` · `plugin lint` · 공개 스키마)이 **전부 초록**이다.
    /// 값 오타(`chekc`)와 키 오타(`knid`)는 거부되는데 *"값을 비웠다"* 만 통과했다
    /// (실측 2026-10-26: 종료 0 → 6, *취약* → *위협*). 가장 흔한 사고가 가장
    /// 조용했다. 그래서 키가 오면 열거값이기를 요구한다.
    /// 공개 스키마도 같은 말을 해야 한다 — `Option` 그대로 두면 생성물이
    /// `anyOf: [PluginKind, null]` 로 **null 을 명시적으로 허용**해 외부 검증기가
    /// 통과시킨다. 키 부재는 `required` 에 없는 것으로 이미 표현된다.
    #[serde(default, deserialize_with = "kind_if_present")]
    #[schemars(with = "PluginKind")]
    pub kind: Option<PluginKind>,

    /// 스캔·읽기가 허용되는 경로 상한.
    ///
    /// **성능 최적화가 아니라 권한 상한이다.** 서명된 플러그인이 임의 경로를
    /// 읽을 수 있으면 그 자체가 정보 수집 도구가 된다 (설계-02 §2).
    pub scan_roots: Vec<String>,

    /// 열거가 허용되는 대상 타입 상한. 선언하지 않은 subject 는 detect 에서 쓸 수 없다.
    pub subjects: Vec<Subject>,

    /// subject 하나에만 적용되는 **더 좁은** 상한. 적지 않은 subject 는
    /// `scan_roots` 전부를 쓴다.
    ///
    /// # 왜 필요한가
    ///
    /// 두 요구가 부딪히는 자리가 있다. 2026-09-04 `appinit-r3` 회차가 그것을
    /// 처음 짚었고, 실기기에서 확인했다.
    ///
    /// 검체의 페이로드 폴더 이름은 **증거에서 파생된다**(`AppInit_DLLs` 값이
    /// 가리키는 경로). 미리 못박을 수 없으니 부모인 `%PROGRAMDATA%` 를
    /// 선언해야 한다. 그런데 거기에 `structured_config` 를 함께 선언하면
    /// JSON 을 잎 단위로 펴다가 상한에 걸린다 — 실측(2026-09-05, 당시 상한 5만)으로
    /// 정확히 50,000 에서 잘렸고 종료 코드 6(관측 불완전)이 나왔다. 상한은
    /// 2026-09-07 에 500,000 으로 올렸지만 넓은 루트에 펴는 것은 여전히 낭비다. Windows 자신의 원격
    /// 분석 설정(`utc.privacy.json` 4.2 MB)이 그것을 삼킨다.
    ///
    /// 그전에는 셋 중 하나를 골라야 했고 **셋 다 무언가를 잃었다** — 넓히면
    /// 종료 코드 6, 폴더 이름을 못박으면 변종을 놓치고, `structured_config`
    /// 를 포기하면 정상 제품 설정에 끼워 넣은 항목을 뺄 수 없다.
    ///
    /// ```yaml
    /// scan_roots:
    ///   - "%PROGRAMDATA%"                       # 파일은 여기 전부
    ///   - "HKLM\\SOFTWARE\\...\\Windows"
    /// subject_roots:
    ///   structured_config: ["%PROGRAMDATA%\\Acme\\Agent"]   # 설정은 여기만
    /// ```
    ///
    /// # 좁히기만 한다
    ///
    /// 여기 적는 경로는 **`scan_roots` 안에 있어야 한다**(린트가 오류로
    /// 막는다). 그래서 읽기 권한의 상한은 여전히 `scan_roots` 하나이고,
    /// 이 필드는 그 안에서 subject 하나를 더 좁힐 뿐이다 — 넓히는 길이
    /// 없다는 것이 이 설계의 요점이다.
    ///
    /// 빈 목록은 적을 수 없다. 그것은 "이 subject 는 아무 데도 보지 않는다"
    /// 이고, 결과는 조용한 0건이다.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub subject_roots: std::collections::BTreeMap<Subject, Vec<String>>,

    /// 확장자가 없어도 `text_config` 로 읽을 **드롭인 디렉터리** (C-5).
    ///
    /// # 왜 필요한가
    ///
    /// 코어는 확장자로 설정 파일을 가린다(`.ini` · `.conf` · `.htaccess` …).
    /// 그런데 **드롭인 디렉터리의 파일은 확장자가 없다** — 실측(청정 코퍼스):
    /// `/etc/pam.d/` 171건이 전부 그렇고 `text_config` 로 잡힌 것이 **0건**이었다.
    /// 그 디렉터리에 파일 하나를 떨어뜨리는 것이 바로 그 자리를 쓰는 수법이라
    /// **이름을 미리 적는 방식으로는 막을 수 없다.**
    ///
    /// ```yaml
    /// scan_roots: ["/etc"]
    /// subjects: [text_config]
    /// text_config_dirs: ["/etc/pam.d", "/etc/sudoers.d"]
    /// ```
    ///
    /// # 왜 코어가 아니라 매니페스트인가
    ///
    /// 자리가 **배포판마다 다르다**(`/etc/php/8.2/fpm/conf.d` ·
    /// `/etc/php.d`). 코어에 박으면 그 목록이 영원히 낡고, 룰만 배포하는 길
    /// (전체 그림 §16)이 그 자리에서 끊긴다. 반대로 접미사는 배포판과 무관하므로
    /// 코어가 들고 있다 — 매니페스트가 정하면 같은 목록을 플러그인마다 적는다.
    ///
    /// # 상한은 여전히 `scan_roots` 하나다
    ///
    /// 여기 적는 경로는 **`scan_roots` 안에 있어야 한다**(린트가 오류로 막는다).
    /// `subject_roots` 와 방향만 반대다 — 그쪽은 같은 상한 안에서 좁히고 이쪽은
    /// 같은 상한 안에서 읽는 것을 넓힌다. **상한 밖으로 나가는 길은 없다.**
    ///
    /// 그리고 **직접 자식만** 읽는다. 재귀로 열면 `/etc` 한 줄로 트리 전체가
    /// 설정이 되어 스냅샷이 터지고 `/etc/ssl/private` 같은 자리가 줄 단위로
    /// 따라 들어온다. 드롭인 디렉터리는 평평하므로 잃는 것이 없다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub text_config_dirs: Vec<String>,

    /// 해시 상한(32 MiB)을 넘어도 **흘려 읽어 해시만** 구할 파일의 **이름 꼴**(2026-11-09 · 코어 1.3.0).
    ///
    /// # 왜 필요한가
    ///
    /// 점검 룰은 공식 빌드의 해시로 판정한다. 그런데 공식 `node.exe` 는 **83.0 MiB(22.23.4) · 89.6 MiB
    /// (24.22.1)** 라(실측) 상한에 걸려 `sha256` 이 비고, 그 룰은 어느 기계에서도 판정을 세우지 못한다.
    /// 상한을 통째로 올리면 `scan_roots` 의 큰 파일을 전부 메모리에 올린다.
    ///
    /// ```yaml
    /// hash_large: ["node.exe"]
    /// ```
    ///
    /// # 무엇을 하고 하지 않는가
    ///
    /// - **이름 하나의 꼴**이다(`*` · `?` — 글롭 뿌리와 같은 규칙). 경로가 아니므로 읽는 자리는 여전히
    ///   `scan_roots` 다 — 상한 밖을 읽는 길이 없다.
    /// - 본문을 들지 않고 조각으로 흘려 해시만 구한다. **판(`version`)은 비고** 본문 수집도 없다.
    /// - **256 MiB 까지**다. 그보다 크면 전처럼 `sha256` 이 빈다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hash_large: Vec<String>,

    /// 이동식 매체 접근. 기본 false.
    ///
    /// 켜는 것만으로는 부족하다 — 이동식 매체 대상 파괴 Action 은 대화형에서
    /// 별도 승인을 받고 무인 모드에서는 계획에 포함되지 않는다. 연결된 USB 가
    /// 다른 사람의 것일 수 있기 때문이다 (설계-02 §2).
    #[serde(default)]
    pub allow_removable: bool,

    #[serde(default)]
    pub references: Vec<String>,

    /// 정상 코드서명 인증서로 서명된 악성코드를 다룰 때 열거하는 서명 주체.
    ///
    /// 설계-03 §3 2층(신뢰 서명 검증)은 유효한 서명이 있는 실행 파일을 기본적으로
    /// 삭제 대상에서 제외한다. 서명된 악성코드는 실재하므로(EvilAI 계열) 예외 경로가
    /// 필요하지만, **포괄적 무시는 불가**다.
    ///
    /// 설계-03 은 "`signed_malware: true` 와 함께 서명 주체를 열거" 로 적었으나
    /// 플래그와 목록을 따로 두면 "true + 빈 목록" 이라는 포괄적 무시가 표현
    /// 가능해진다. **목록 자체를 플래그로 삼아 그것을 표현 불가능하게 만든다.**
    /// 비어 있거나 없으면 2층을 통과하지 못한다.
    #[serde(default)]
    pub signed_malware: Vec<SignerRef>,

    /// **네트워크로 하는 점검** — 이 기계가 아니라 바깥(원격 서버)을 본다 (코어 1.4.0).
    ///
    /// 본체(`remedy`)에는 통신 코드가 없다(설계-01 D9 · 배포본 임포트 검사). 그래서 이 칸이 있는
    /// 룰은 본체가 스스로 돌리지 않고 **동반 프로그램 `remedy-net` 을 띄워 맡긴다** — 서명이 맞는
    /// 것만, 무엇을 하는지 알린 뒤에(설계-04 §1 *동반 모듈*).
    ///
    /// # 값이 닫혀 있는 이유
    ///
    /// 룰이 적는 것은 **어느 점검인가** 하나다([`NetworkCheck`]). 프로그램 이름 · 인자 · 대상은 룰이
    /// 정하지 못한다 — 띄울 프로그램은 본체가 아는 한 자리의 한 이름이고, 대상(주소)은 사람이
    /// 적는다. 열린 문자열이면 서명된 룰 하나가 *무엇을 실행할지* 를 고르는 문이 된다.
    ///
    /// # 이 기계를 보지 않는다
    ///
    /// 이 칸이 있으면 `kind: check` 여야 하고, 이 기계를 읽는 칸(`scan_roots` · `subjects` · `detect` ·
    /// `verdict` · 수집 칸)은 **비어 있어야** 한다(`validate`). 판정은 `remedy-net` 이 내고 본체는
    /// 그 종료 코드만 받는다 — 네트워크에서 온 것으로 본체가 무엇을 바꾸는 길이 없다.
    ///
    /// 키가 있으면 값이 있어야 한다 — [`PluginManifest::kind`] 와 같은 까닭이다.
    #[serde(
        default,
        deserialize_with = "network_if_present",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "NetworkCheck")]
    pub network: Option<NetworkCheck>,

    pub detect: Vec<DetectRule>,
    /// 네트워크 점검 룰(`network`)은 적지 않는다 — 그 밖의 룰은 `validate` 가 `require` 를 요구한다.
    #[serde(default)]
    pub verdict: Verdict,

    #[serde(default)]
    pub remediate: Option<Remediate>,

    /// 분석에 필요한 추가 수집. 파괴가 아니므로 계획에 나타나지 않지만
    /// 수집된 사실은 감사 로그에 남는다 (설계-02 §6-1).
    #[serde(default)]
    pub collect_extra: Vec<CollectExtra>,

    #[serde(default)]
    pub submit_hint: Option<SubmitHint>,
}

/// `kind:` 가 있으면 값이 열거값이어야 한다 — [`PluginManifest::kind`] 를 보라.
///
/// 키가 아예 없는 경우는 `#[serde(default)]` 가 `None` 을 주므로 여기 오지 않는다.
fn kind_if_present<'de, D>(d: D) -> Result<Option<PluginKind>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    PluginKind::deserialize(d).map(Some)
}

/// `network:` 가 있으면 값이 열거값이어야 한다 — [`kind_if_present`] 와 같다.
fn network_if_present<'de, D>(d: D) -> Result<Option<NetworkCheck>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    NetworkCheck::deserialize(d).map(Some)
}

/// 네트워크로 하는 점검의 종류. [`PluginManifest::network`] 를 보라.
///
/// 값 하나가 동반 프로그램의 명령 하나다 — 본체가 그 대응을 안다(`remedy-net <명령>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCheck {
    /// 웹서버의 응답 헤더를 본다 — 사람이 적은 주소(URL)에 HEAD 요청을 보낸다.
    Url,
}

impl NetworkCheck {
    /// 매니페스트에 적는 값이자 동반 프로그램의 명령 이름.
    pub const fn id(self) -> &'static str {
        match self {
            NetworkCheck::Url => "url",
        }
    }
}

/// 플러그인의 종류. [`PluginManifest::kind`] 를 보라.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginKind {
    /// **바꾸지 않는다.** 취약한지만 본다.
    ///
    /// 이 선언이 코어에게 주는 것은 둘이다. ① 선언한 자리가 전부 없으면
    /// *"다 보지 못했다"* 가 아니라 **해당 없음**이다 — 제품이 설치되지 않은
    /// 기계가 가장 흔한 경우인데 그것이 *확인 필요*(종료 6)로 나갔다.
    /// ② 화면이 *위협* 이 아니라 **취약**이라고 말한다.
    Check,
}

/// 서명 주체. 둘 중 하나만 적으면 그 항목만으로 대조한다.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignerRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
}

// ─────────────────────────────────────────────────────────── detect

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectRule {
    pub id: String,
    pub subject: Subject,

    /// 앞선 증거에서 파생된 경로로 탐색 범위를 좁힌다. 예: `${task.payload_dir}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,

    #[serde(rename = "where")]
    pub condition: Condition,

    /// 증거에서 값을 뽑아 이름을 붙인다. 감염마다 바뀌는 값(랜덤 폴더명 등)을
    /// 다루는 유일한 방법이다.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capture: BTreeMap<String, String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<Predicate>,

    /// 보고·우선순위 표시용. **판정 게이트가 아니다** (설계-02 §5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
}

/// 조건식. 술어 하나, 술어 목록(암묵적 all), 또는 `all`/`any` 묶음.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Condition {
    All(AllOf),
    Any(AnyOf),
    One(Predicate),
    List(Vec<Condition>),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AllOf {
    pub all: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnyOf {
    pub any: Vec<Condition>,
}

/// 단일 술어. 필드 비교 또는 YARA 참조.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Predicate {
    Field(FieldPredicate),
    Yara(YaraPredicate),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldPredicate {
    pub field: String,
    pub op: Operator,
    /// `exists` 를 제외한 모든 연산자가 요구한다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// `rules/<파일>.yar:<룰 이름>` 형태로 참조한다.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct YaraPredicate {
    pub yara: String,
}

// ─────────────────────────────────────────────────────────── verdict

/// 감염 판정 게이트.
///
/// **점수 임계값을 게이트로 쓸 수 없다.** 서로 독립적인 근거의 논리곱을 명시하게
/// 하면 룰 하나의 오탐이 곧바로 삭제로 이어지지 않는다 (설계-02 §5).
///
/// 기본값(빈 `require`)은 **네트워크 점검 룰의 것**이다 — 그 룰은 이 기계에서 판정하지 않는다. 그 밖의
/// 룰이 `require` 를 비우면 `validate` 가 막는다.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    /// `and` `or` `not` `(...)` 과 `<rule-id>`, `count(<rule-id>) >= N` 만 지원한다.
    pub require: String,

    /// **판정이 서지 않았지만 '취약하지 않다' 도 말할 수 없는 모양** — 점검(`kind: check`) 전용
    /// (2026-11-09 · 코어 1.3.0).
    ///
    /// # 왜 필요한가
    ///
    /// 그전에는 점검 룰이 항목마다 *확인 필요* 를 낼 수 없었다 — 6 은 관측 사유로만 나왔고, 백포트를
    /// 모르는 설치본은 **판정을 세우고(2) 안내문이 풀어 주는** 수밖에 없었다(`24-check-plugins.md`).
    /// 그러면 무인 배포가 *취약* 과 *모른다* 를 같은 코드로 읽는다. 사내 런타임 스캐너는 둘을 가른다
    /// — *모르는 빌드 · 백포트를 모르는 설치본 · 세션 설정* 은 확인 필요다(목표 remedy_PHP스캐너통합).
    ///
    /// # 어떻게 서는가
    ///
    /// 그룹마다 `require` 가 서지 않았을 때만 본다 — **찾은 것이 모르는 것보다 앞선다**(2 가 6 보다
    /// 앞서는 규칙 그대로). 하나라도 서면 그 사유가 관측([`crate::artifact::Observation::unconfirmed`])
    /// 에 실리고 결과는 6 이다. 비어 있으면 아무것도 바뀌지 않는다 — 이 칸이 없는 룰은 전과 한
    /// 글자도 같다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unconfirmed: Vec<Unconfirmed>,
}

/// [`Verdict::unconfirmed`] 의 한 줄 — 언제 *확인 필요* 인가와 그 까닭.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Unconfirmed {
    /// `require` 와 같은 문법의 식.
    pub when: String,
    /// 화면의 사유 줄 — **무엇을 왜 확인해야 하는가.** `ko` · `en` 둘 다 적는다.
    pub why: LocalizedText,
}

// ─────────────────────────────────────────────────────────── remediate

/// "무엇이 남아 있으면 안 되는가" 를 선언한다.
///
/// **순서·백업·프로세스 종료를 여기 적지 않는다.** 계획기가 도출한다 (설계-03 §2).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Remediate {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<RemoveTarget>,
    /// 값의 악성 부분만 제거한다. 통째로 지우면 시스템을 못 쓰게 되는 대상이
    /// 오히려 주류다 (설계-02 §6-1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edit: Vec<EditTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restore: Vec<RestoreTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifySpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RemoveTarget {
    /// 증거 참조.
    Ref(RefTarget),
    /// 증거에서 파생된 경로. **리터럴 절대 경로는 거부한다** — 증거 없는 삭제를
    /// 문법 수준에서 불가능하게 한다 (설계-02 §6).
    Path(PathTarget),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RefTarget {
    #[serde(rename = "ref")]
    pub rule_ref: String,
    /// 프로세스 대상의 **자손까지** 집합에 포함한다 (설계-03 §2).
    ///
    /// 디렉터리의 `recursive: true` 와 같은 자리다 — 둘 다 "이것 하나가
    /// 아니라 이것이 거느린 것까지" 를 뜻하고, 둘 다 **명시해야만** 켜진다.
    ///
    /// 부모-자식 관계로만 식별되는 감시자를 술어로 잡을 수 없을 때 쓴다.
    /// 켜도 `max_targets` 상한은 확장된 집합 전체에 그대로 걸리고, 보호
    /// 대상인 뿌리는 자손의 문이 되지 않는다.
    #[serde(default)]
    pub descendants: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathTarget {
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
    /// `recursive: true` 는 이것을 **필수로** 요구한다. 그 디렉터리 안에서
    /// 악성으로 판정된 파일 증거를 가리킨다 (설계-03 §4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EditTarget {
    #[serde(rename = "ref")]
    pub rule_ref: String,
    pub op: EditOp,
    /// **증거에서 파생된 값이어야 한다.** 리터럴 문자열로 임의 편집을 지시할 수 없다.
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EditOp {
    Strip,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RestoreTarget {
    /// 이름으로 지정하는 원복. 예: `av_exclusions`
    Named(String),
    /// 코어가 내장한 OS 기본값 카탈로그에서만 값을 가져온다.
    ToDefault(RestoreToDefault),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoreToDefault {
    #[serde(rename = "ref")]
    pub rule_ref: String,
    pub to: RestoreDefaultKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RestoreDefaultKind {
    Default,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifySpec {
    #[serde(default)]
    pub after_reboot: bool,
}

// ─────────────────────────────────────────────────────────── collect_extra

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum CollectExtra {
    Ref(CollectRef),
    Path(CollectPath),
    Subject(CollectSubject),
    Glob(CollectGlob),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectRef {
    #[serde(rename = "ref")]
    pub rule_ref: String,
    /// 파일 본문을 아티팩트에 담는다. 스냅샷이 커지고 개인정보 위험이 올라간다.
    #[serde(default)]
    pub content: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectPath {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectSubject {
    pub subject: Subject,
    pub path: String,
}

/// 한 폴더에서 **이름 꼴이 맞는 파일의 본문**을 담는다 — `<폴더>/<이름 꼴>`, 와일드카드
/// (`*` · `?`)는 마지막 성분에만.
///
/// 이름이 감염마다 달라 `path` 로 적을 수 없고, `ref` 로 가리키려면 그 파일을 고르는
/// 경로 규칙이 있어야 하는데 그 규칙은 정상 파일에도 맞아 **흔적**이 된다(2026-11-06 —
/// 정상 서버마다 `libkeyutils` 가 흔적으로 떴다). 이 형은 규칙 없이 본문만 담는다.
///
/// 고르는 것은 **주 수집이 걸어서 해시한 파일**이다 — 링크와 해시 상한을 넘는 파일은
/// 고르지 않는다(링크의 경로에 대상의 내용을 적지 않는다). 폴더가 없으면 담을 것이 없는
/// 것이지 미해소가 아니다.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectGlob {
    pub glob: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<String>,
}

// ─────────────────────────────────────────────────────────── submit_hint

/// 제출 시 무엇이 유용한지에 대한 **제안이지 명령이 아니다.**
/// 실제 제출은 사용자 동의·미리보기·마스킹을 거친다 (설계-00 §7).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// 분석가가 **손으로 올릴 때** 볼 판단 근거.
///
/// # 자동 제출기가 볼 값이 아니다
///
/// 제출 기능은 제품 범위 밖이다 (2026-08-28 P13 결정, 설계-09 "제출을 제품
/// 밖으로"). 되돌릴 수 없는 유일한 동작이 되고, 선행 조건(법무 검토)이 설계
/// 밖에 있으며, 손으로 올리는 경로가 이미 있기 때문이다.
///
/// **그래도 이 필드는 남는다.** 플러그인 작성자의 판단 — *"무엇을 함께 올리면
/// 유용한가"* 와 *"이것을 어느 등급으로 다뤄야 하는가"* — 는 제출을 자동화하든
/// 안 하든 유효하다. 계획이 그것을 나르고 `support-bundle` 이 보여 준다.
pub struct SubmitHint {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub samples: Vec<String>,
    /// 기밀 등급 **하한**. 0 공개 · 1 대외비 · 2 기밀 · 3 극비.
    ///
    /// **하한만 올릴 수 있다.** 플러그인이 기밀 등급을 낮추는 방향으로 영향을
    /// 줄 수 없다 (설계-05 §4-2) — 낮출 수 있으면 서명된 룰 하나가 고객 데이터의
    /// 등급을 내릴 수 있고, 그것 자체가 유출 경로다.
    ///
    /// 자동 제출기가 없는 지금은 **손으로 올리는 사람에게 주는 경고**다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidentiality_min: Option<u8>,
}

/// 템플릿이 참조하는 `${...}` 키 전부.
///
/// **여기가 이 문법의 유일한 정의다.** 평가기(remedy-detect)와 린터가 각자
/// 파싱하면 언젠가 갈라지고, 그러면 린트를 통과한 룰이 평가에서 다르게 읽힌다.
pub fn references(template: &str, out: &mut Vec<String>) {
    let mut rest = template;
    while let Some(i) = rest.find("${") {
        let after = &rest[i + 2..];
        match after.find('}') {
            None => return,
            Some(j) => {
                out.push(after[..j].to_string());
                rest = &after[j + 1..];
            }
        }
    }
}

#[cfg(test)]
mod reference_tests {
    use super::references;

    #[test]
    fn collects_every_reference_in_order() {
        let mut v = Vec::new();
        references("${task.dir}/x/${task.name}", &mut v);
        assert_eq!(v, vec!["task.dir", "task.name"]);
    }

    #[test]
    fn unclosed_reference_stops_collection() {
        // 닫히지 않은 것을 키로 삼으면 있지도 않은 참조를 오류로 보고한다.
        let mut v = Vec::new();
        references("${a.b} and ${broken", &mut v);
        assert_eq!(v, vec!["a.b"]);
    }
}
