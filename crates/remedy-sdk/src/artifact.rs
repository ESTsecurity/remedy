//! 산출 아티팩트 봉투 4종과 종료 코드 (설계-02 §8).
//!
//! 네 단계가 같은 봉투를 쓴다. 파일 경계로 단계를 나눈 것이 설계 전체의 지지대다
//! (설계-03 §1) — 봉투가 흔들리면 그 아래가 전부 흔들린다.

use crate::catalog::{Op, Risk, Subject};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 봉투의 `kind`. 네 단계와 1:1 이다.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum ArtifactKind {
    #[serde(rename = "remedy.artifacts")]
    Artifacts,
    #[serde(rename = "remedy.scan")]
    Scan,
    #[serde(rename = "remedy.plan")]
    Plan,
    #[serde(rename = "remedy.result")]
    Result,
}

impl ArtifactKind {
    pub const ALL: [ArtifactKind; 4] = [
        ArtifactKind::Artifacts,
        ArtifactKind::Scan,
        ArtifactKind::Plan,
        ArtifactKind::Result,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            ArtifactKind::Artifacts => "remedy.artifacts",
            ArtifactKind::Scan => "remedy.scan",
            ArtifactKind::Plan => "remedy.plan",
            ArtifactKind::Result => "remedy.result",
        }
    }

    /// 이 봉투를 만들어 내는 CLI 단계.
    pub const fn stage(self) -> &'static str {
        match self {
            ArtifactKind::Artifacts => "collect",
            ArtifactKind::Scan => "evaluate",
            ArtifactKind::Plan => "plan",
            ArtifactKind::Result => "apply",
        }
    }
}

// ─────────────────────────────────────────────────────────── 공통 봉투

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub version: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CoreInfo {
    pub version: String,
    pub build: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PluginRef {
    pub id: String,
    pub version: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// 네 단계가 공유하는 봉투.
///
/// `deny_unknown_fields` 를 걸지 않는다 — `flatten` 과 함께 쓸 수 없고, 이 구조는
/// 사용자 입력이 아니라 우리 산출물이다. 엄격한 거부가 필요한 곳은 `plugin.yaml` 이다.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Envelope<T> {
    pub schema_version: u32,
    pub kind: ArtifactKind,
    /// ULID. 한 번의 실행을 네 파일에 걸쳐 잇는다.
    pub run_id: String,
    pub created: String,
    pub host: HostInfo,
    pub core: CoreInfo,
    #[serde(default)]
    pub plugins: Vec<PluginRef>,
    #[serde(flatten)]
    pub body: T,
}

/// 이 산출물이 기대는 **관측이 완전했는가** (설계-02 §8, 설계-03 §1).
///
/// 각 산출물은 홀로 읽혀야 한다. `plan.json` 만 받아 든 사람이 "이 계획의 전제가
/// 된 관측이 온전했는가" 를 물을 수 없으면, 그 물음은 영영 답을 얻지 못한다.
/// 그래서 `artifacts.json` 의 사실이 `scan.json` · `plan.json` 으로 실려 간다.
/// 평가만 아는 사실 둘 — 재지 못한 YARA([`Observation::unevaluated_rules`]) 와
/// 견주지 못한 버전([`Observation::unreadable_versions`]) — 은 `scan.json` 에서
/// 더해진다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Observation {
    /// 상한에 걸려 수집이 잘렸는가.
    #[serde(default)]
    pub truncated: bool,
    /// 접근이 거부되어 열지 못한 횟수. **전부 센다.**
    #[serde(default)]
    pub denied_dirs: usize,
    /// 그중 **앞의 몇 개** 경로. 비어 있으면 실리지 않는다.
    ///
    /// # 왜 개수만으로는 모자랐나 (2026-09-14)
    ///
    /// `%ProgramFiles%` 수집이 `denied_dirs=2` 를 내 P2 가 미결로 끝났는데
    /// **어느 폴더인지 아무 데도 없었다.** 회차가 끝난 뒤 그 기계를 뒤졌을
    /// 때는 5,713개 폴더가 전부 열렸다 — 수집이 도는 **그때만** 잠기는
    /// 자리였고, 그러면 사람은 영영 원인에 닿지 못한다.
    ///
    /// # 전수가 아니다
    ///
    /// 비관리자로 돌리면 거부가 수백이 될 수 있다. 표본만 담고 `denied_dirs`
    /// 는 그대로 전부 센다 — **길이가 그보다 작으면 잘린 것**이고, 그 사실이
    /// 두 값의 차이로 드러난다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_paths: Vec<String>,
    /// 선언되었지만 수집되지 않은 subject.
    ///
    /// 수집기가 있으면 결과가 비어 있어도 빈 배열이 들어간다. 따라서 **선언한
    /// subject 의 배열이 본문에 없다는 것이 곧 "수집하지 못했다"** 이다.
    /// 이것이 없으면 플러그인 작성자는 룰이 왜 안 맞는지 알 수 없다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncollected_subjects: Vec<Subject>,
    /// 선언된 `scan_roots` 의 개수. `missing_roots` 만으로는 "전부 없었는가" 를
    /// 판단할 수 없어 함께 싣는다 — 이 구조체는 홀로 읽혀야 한다.
    #[serde(default)]
    pub declared_roots: usize,
    /// 선언했으나 **존재하지 않아 한 번도 열리지 않은** scan_root.
    ///
    /// 일부가 없는 것은 정상일 수 있다 — 플러그인이 여러 벤더 폴더를 나열하면
    /// 설치되지 않은 제품의 경로는 당연히 없다. 그래서 이것만으로 불완전하다고
    /// 하지 않고 사실만 기록한다. **전부 없으면** 이야기가 다르다(아래).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_roots: Vec<String>,

    /// 선언했으나 **있는지조차 묻지 못한** 루트 (B-9 · 2026-10-27).
    ///
    /// # 왜 `missing_roots` 와 나누는가
    ///
    /// *"없다"* 와 *"못 물었다"* 는 다른 말이다. `Path::exists()` 가 오류 전부를
    /// `false` 로 접던 동안 둘이 한 칸에 들어갔고, 그래서 부모까지 막힌 트리나
    /// 도달 불가 UNC 가 **없는 루트**로 집계됐다. **레지스트리 루트도 같은
    /// 칸으로 온다** — 부모 키를 열거할 수 없으면 그 아래를 말할 수 없다.
    /// `subject_roots` 로 좁힌 더 깊은 자리도 여기서 센다. 열린 루트가 하나라도 함께
    /// 있으면 [`Self::all_roots_missing`] 이 성립하지 않으므로 **경고 한 줄 없이
    /// 종료 0 "위협이 발견되지 않았습니다"** 가 나갔다(실측 2026-10-27 · 적대
    /// 검증이 세 회차 연속 짚었다).
    ///
    /// # 왜 `denied_dirs` 와도 나누는가
    ///
    /// 그쪽 사유 줄은 *"접근이 거부된 디렉터리 열기 N회 (관리자 권한으로 다시
    /// 돌리십시오)"* 다. 도달 불가 UNC·준비되지 않은 장치에는 **틀린 안내**이고,
    /// 선언한 루트는 그 안의 어느 폴더가 아니라 **범위 그 자체**라 읽는 사람이
    /// 할 일이 다르다.
    ///
    /// # 하나라도 있으면 불완전하다
    ///
    /// `missing_roots` 는 **전부**일 때만 불완전으로 센다(설치되지 않은 제품이
    /// 정상이므로). 이쪽은 하나로 족하다 — 못 본 자리가 하나라도 있으면 *"없다"*
    /// 를 말할 수 없다. **점검 플러그인도 면제가 아니다**: 면제는
    /// [`Self::all_roots_missing`] 하나뿐이고, 범위가 이 기계에 없는 것과 범위를
    /// 못 들여다본 것은 다르다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable_roots: Vec<String>,

    /// **평가하지 못한** YARA 규칙 — `rules/<파일>.yar:<룰 이름>`. 정렬 · 중복 없음.
    /// 룰 참조가 틀린 술어는 그 원문을, 참조가 없는 술어는 `<필드>: <값>`
    /// (`data: null`)을 적는다.
    ///
    /// **레코드의 매치나 제외를 가른 YARA 만 실린다.** 그 YARA 가 무엇을 냈어도
    /// 레코드가 매치되지 않거나(형제 술어가 거짓 · 확정 제외 · capture 실패) 이미
    /// 매치되면(`any` 의 다른 갈래) 싣지 않는다 — 그래서 술어 순서와 무관하다.
    /// `exclude` 의 YARA 는 그것이 맞았다면 제외됐을 때 실리고, 그 레코드는 전처럼
    /// 증거로 남는다 — 그 위에 판정(2)이 설 수 있다.
    ///
    /// **판정식은 보지 않는다**(보수 쪽). 다른 필수 규칙이 0 이라 판정이 어차피
    /// 서지 않아도 6 이 될 수 있다.
    ///
    /// 스냅샷이 아니라 **평가**가 아는 사실이라 `artifacts.json` 에는 없고
    /// `scan.json` · `plan.json` 에만 실린다(평가기가 채우고 파이프라인이 스냅샷의
    /// 관측과 합친다).
    ///
    /// # 왜 관측 불완전인가 (결정 2026-10-26)
    ///
    /// 훑을 본문이 없으면 그 규칙은 "안 맞았다" 가 아니라 "재지 못했다" 다
    /// (설계-03 §1). 그 사실이 `issues` 에만 남자 판정이 없을 때 **종료 코드 0
    /// "위협 없음"** 이 나갔다 — 무인 배포는 그 주의 줄이 실린 stderr 를 버린다
    /// (2026-10-25 적대 검증 · 본문 누락으로 재현). 본문이 상한(파일 8 MiB · 총
    /// 64 MiB)에 걸려도 같은 길이다. 이진 값의 바이트가 레코드에 없으면(레지스트리
    /// 256 KiB 초과 · 고정 자리 subject) 주의조차 없이 *"안 맞았다"* 였다(2026-10-26).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unevaluated_rules: Vec<String>,

    /// 버전으로 읽지 못해 **견주지 못한** 값. `unevaluated_rules` 와 같은 뜻이고
    /// 낱말만 다르다 — 읽는 사람이 할 일이 다르기 때문이다.
    ///
    /// # 왜 따로 세는가 (2026-10-27 · C-1)
    ///
    /// `version_lt` · `version_gt` 는 점으로 나눈 숫자만 견준다. 꼬리가 붙은 값
    /// (`8.2.29-1ubuntu1` · `8.4.0RC1`)은 **사전 배포와 패키지 개정이 모양은 같고
    /// 순서가 반대**라 추측할 수 없다. 그 값을 *"안 맞았다"* 로 세면 **취약한
    /// 기계가 종료 0 "취약한 곳을 찾지 못했습니다" 로 나간다** — 실측으로
    /// 확인했다(2026-10-27). 배포판이 패치한 PHP 가 바로 그 모양이라 **가장 흔한
    /// 경우**다.
    ///
    /// `unevaluated_rules` 에 함께 담지 않는 이유는 사유 줄이 *"YARA 규칙 N개를
    /// 평가하지 못했습니다"* 라고 말하기 때문이다. 버전을 그 줄에 넣으면 화면이
    /// 재지 못한 것을 **잘못 지목한다**.
    ///
    /// **점검 플러그인도 면제가 아니다** — [`Self::is_complete_for_check`] 의
    /// 면제는 [`Self::all_roots_missing`] 하나뿐이다. 범위가 이 기계에 없는 것과
    /// 값을 읽지 못한 것은 다르다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable_versions: Vec<String>,

    /// 점검 룰이 **판정은 세우지 못했지만 '취약하지 않다' 도 말할 수 없다고 선언한** 그룹 —
    /// 매니페스트의 `verdict.unconfirmed`(2026-11-09 · 코어 1.3.0).
    ///
    /// # 왜 관측 불완전과 한 칸인가
    ///
    /// 뜻이 같다 — *"이 결과 위에서 '없다' 를 말할 수 없다"* 이고 종료 코드도 같은 6 이다. 무인
    /// 배포 · 메뉴 · 재부팅 재검사가 6 을 읽는 길을 그대로 타게 하려고 따로 두지 않았다. 다른 것은
    /// 원인을 **룰이 안다**는 것 하나이고, 그래서 사유 문장을 룰이 적는다([`UnconfirmedNote::why`]).
    ///
    /// **점검 플러그인도 면제가 아니다** — 이것이 점검을 위한 칸이다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unconfirmed: Vec<UnconfirmedNote>,
}

/// [`Observation::unconfirmed`] 의 한 줄 — 룰의 `verdict.unconfirmed` 하나가 선 자리.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UnconfirmedNote {
    /// 룰이 적은 까닭(`ko` · `en`) 그대로 — 산출물이 홀로 읽혀야 한다(설계-03 §1).
    pub why: BTreeMap<String, String>,
    /// 그 식이 선 증거 그룹(`g0` …). 정렬 · 중복 없음.
    pub groups: Vec<String>,
    /// 그 식(`when`)이 짚는 규칙 id — 식에 적힌 차례 · 중복 없음 (2026-11-11).
    ///
    /// 화면은 짚은 그룹에서 **이 규칙들의 증거만** 적는다. 그룹에는 `from` 없이 기계 전체를 보는
    /// 규칙의 증거도 함께 들어 있어, 그룹의 증거를 다 적으면 이 사유와 상관없는 줄이 섞인다. 비어
    /// 있으면(이 칸이 생기기 전의 산출물) 그룹의 증거를 다 적는다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
}

impl UnconfirmedNote {
    /// 그 언어의 까닭. 없으면 다른 언어로 — 린트가 둘 다 요구하지만 낡은 산출물도 읽힌다.
    pub fn why_in(&self, lang: crate::i18n::Lang) -> &str {
        let (want, other) = match lang {
            crate::i18n::Lang::Ko => ("ko", "en"),
            crate::i18n::Lang::En => ("en", "ko"),
        };
        self.why
            .get(want)
            .or_else(|| self.why.get(other))
            .map(String::as_str)
            .unwrap_or_default()
    }
}

/// 사유 줄에 적을 **읽지 못한 버전의 수** 상한. 나머지는 *"외 N개"* 로 센다.
const UNREADABLE_SHOWN: usize = 5;

/// 값 하나를 적을 글자 수 상한. `registry_value.data` 처럼 긴 값이 들어오면
/// 줄 하나가 화면을 먹는다.
const UNREADABLE_VALUE_CHARS: usize = 60;

/// 글자 수로 자른다 — 바이트로 자르면 한글 중간에서 끊긴다.
fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}…")
}

/// 프로세스 하나를 들여다보다 막힌 자리인가 — `/proc/<pid>/maps` 처럼 `/proc/` 다음이 수다.
/// `/proc/net/unix` 같은 커널 표는 아니다.
fn is_process_path(p: &str) -> bool {
    p.strip_prefix("/proc/")
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
}

impl Observation {
    /// 선언한 루트가 **하나도 존재하지 않았는가.**
    ///
    /// 이 경우 수집기는 아무 곳도 열어 보지 못했다. 잘린 것도 거부당한 것도
    /// 아니어서 기존 세 사유에 걸리지 않고, 그대로 두면 **아무것도 읽지 않은
    /// 스캔이 종료 코드 0 "위협 없음" 을 낸다.** 실측으로 확인한 구멍이다
    /// (관측 01 D2).
    pub fn all_roots_missing(&self) -> bool {
        self.declared_roots > 0 && self.missing_roots.len() >= self.declared_roots
    }

    /// 이 관측 위에서 "위협 없음" 을 말할 수 있는가.
    pub fn is_complete(&self) -> bool {
        !self.truncated
            && self.denied_dirs == 0
            && self.uncollected_subjects.is_empty()
            && !self.all_roots_missing()
            && self.unreadable_roots.is_empty()
            && self.unevaluated_rules.is_empty()
            && self.unreadable_versions.is_empty()
            && self.unconfirmed.is_empty()
    }

    /// 다 보지 못한 까닭이 **룰이 선언한 확인 필요뿐인가** — 결과 문장을 *"다 보지 못해"* 가
    /// 아니라 *"확인이 필요합니다"* 로 고르는 자리다. 다른 사유가 섞이면 거짓이다(그때는 정말로
    /// 다 보지 못했다).
    pub fn only_unconfirmed(&self) -> bool {
        !self.unconfirmed.is_empty()
            && Observation {
                unconfirmed: Vec::new(),
                ..self.clone()
            }
            .is_complete_for_check()
    }

    /// 이 관측 위에서 **점검 플러그인이** "해당 없음" 을 말할 수 있는가.
    ///
    /// [`Self::is_complete`] 와 **한 가지만** 다르다 — [`Self::all_roots_missing`]
    /// 을 불완전으로 세지 않는다. 나머지(잘림 · 거부 · 미수집 subject · **못
    /// 물어본 루트** · 미평가 YARA · 읽지 못한 버전)는 그대로다: 섞이면 여전히
    /// 다 보지 못한 것이다.
    ///
    /// # 왜 점검에서만 다른가 (B-6 · 2026-10-26)
    ///
    /// *"루트가 전부 없다"* 에는 두 원인이 섞인다 — **제품이 설치되지 않았다**
    /// 와 **선언이 틀렸다**(경로 오타 · 플랫폼 착오). 코어는 그 둘을 가릴 수
    /// 없고 앞으로도 못 한다 — [`Observation`] 에 루트별 사유를 담는 자리가
    /// 없다. 그래서 어느 쪽으로 틀릴지를 고르는 일이다.
    ///
    /// 치료에서는 **불완전 쪽으로** 틀린다. 아무 곳도 열어 보지 못한 스캔이
    /// *"위협 없음"* 을 내는 것(관측 01 D2)이 더 위험하기 때문이다.
    ///
    /// **점검에서는 반대다.** 미설치 기계가 **가장 흔한 경우**인데 그것이 종료 6
    /// (*확인 필요*)으로 나갔다 — 멀쩡한 기계를 두고 사람을 부르게 된다. 가리는
    /// 일은 사람에게 남으므로, 쓰는 쪽이 **없던 경로를 화면에 적는다**.
    ///
    /// **이 함수를 [`Self::is_complete`] 에 합치지 않는다.** 그쪽은 산출물 ·
    /// 기록 · `verify` 의 분류가 함께 보는 계약이고, 플러그인 종류를 아는 것은
    /// 그것을 부르는 쪽뿐이다.
    pub fn is_complete_for_check(&self) -> bool {
        !self.truncated
            && self.denied_dirs == 0
            && self.uncollected_subjects.is_empty()
            && self.unreadable_roots.is_empty()
            && self.unevaluated_rules.is_empty()
            && self.unreadable_versions.is_empty()
            && self.unconfirmed.is_empty()
    }

    /// 불완전한 이유들. 사람에게 보여 줄 문장이다.
    pub fn reasons(&self) -> Vec<String> {
        self.reasons_in(crate::i18n::current())
    }

    /// 언어를 받아 이유를 짓는다.
    ///
    /// # 왜 두 언어인가 (2026-09-14)
    ///
    /// 영어로 돌린 화면이 이렇게 나왔다 — 결론 줄은 영어인데 **왜 그런지는
    /// 읽을 수 없다.**
    ///
    /// ```text
    ///   Note: 'no threat' cannot be declared on this result:
    ///      - 접근이 거부된 디렉터리 열기 1회 (관리자 권한으로 다시 돌리십시오)
    /// ```
    ///
    /// 종료 코드 6 을 받은 무인 배포가 다음에 무엇을 해야 하는지는 이 줄에만
    /// 있다. 한국어를 못 읽는 자리에서도 돌아야 한다.
    ///
    /// # 한국어 문구를 다듬으면 네 곳이 함께 흔들린다
    ///
    /// 콘솔 기준선(`console-linux.txt`)이 `REMEDY_LANG=ko` 로 떠 있고, 하네스
    /// 셋(`Invoke-ObsVerify` · `Verify-P4` · `trunc-verify.sh`)이 그 문구를
    /// 정규식으로 읽는다. 영어를 더한 회차는 한국어를 한 글자도 건드리지 않아
    /// 그 넷이 조용히 지났다.
    ///
    /// **다듬은 회차는 그렇지 않았다.** 2026-09-30 화면 마감(`1b2fffc`)이 이 사유
    /// 문장들을 합쇼체로 옮겼고(`잘렸다` → `잘렸습니다`), 짝 커밋이 하네스 판독
    /// 문구를 고쳤는데 여덟 곳을 놓쳐 2026-10-26 에야 드러났다(`83a4caf`). 긍정
    /// 단정은 그날 실패로 보였지만 **부정 · 세기 단정은 옛 꼴을 0건으로 세어 늘
    /// 통과했다.** 여기 문구를 바꾸면 기준선 재캡처와 함께 `testbed/harness` 를
    /// 옛 꼴로 훑고, 부정 · 세기 단정은 옛 꼴과 지금 꼴을 다 잡게 쓸 것.
    ///
    /// # 전역과 나눈 이유
    ///
    /// `i18n::init` 은 프로세스당 한 번만 먹으므로(OnceLock), 전역만 보는
    /// 함수는 한 시험 묶음에서 **한 언어밖에 잴 수 없다.** 그러면 다른 쪽
    /// 언어는 사람이 손으로 돌려 볼 때까지 아무도 보지 않는다 — 이 갭이
    /// 생긴 경위가 바로 그것이다.
    pub fn reasons_in(&self, lang: crate::i18n::Lang) -> Vec<String> {
        use crate::i18n::Lang;
        let mut out = Vec::new();
        if self.truncated {
            out.push(
                lang.t(
                    "수집이 상한에 걸려 잘렸습니다",
                    "collection hit its cap and was truncated",
                )
                .to_string(),
            );
        }
        if self.denied_dirs > 0 {
            let n = self.denied_dirs;
            let dirs = if n == 1 { "directory" } else { "directories" };
            // **프로세스가 막혔으면 안내를 덧붙인다** (2026-11-11 · 목표 remedy_PHP스캐너통합 결정 23).
            // 리눅스는 root 로만 검사하므로 `/proc/<pid>/…` 가 막히는 것은 거의 언제나
            // `CAP_SYS_PTRACE` 를 뗀 컨테이너다 — 그 사람은 이미 root 라 *"관리자 권한으로 다시"*
            // 로는 할 일이 없다. 실측: php:8.3.36-fpm 의 www-data 작업자 둘이 막혔고(실행 파일
            // 경로 · 실린 모듈 둘 다), `docker exec --privileged` 로 들어가면 둘 다 읽혔다.
            //
            // **앞 문장은 그대로 둔다.** 하네스가 `접근이 거부된 디렉터리` 를 읽는다
            // (`Invoke-ObsVerify.ps1`) — 그래서 바꾸지 않고 덧붙인다.
            let process = self.denied_paths.iter().any(|p| is_process_path(p));
            // 문장 구조가 언어마다 다르므로 조각을 이어 붙이지 않는다 —
            // 이어 붙이면 어느 한쪽이 반드시 어색해진다.
            out.push(match (lang, process) {
                (Lang::Ko, false) => {
                    format!("접근이 거부된 디렉터리 열기 {n}회 (관리자 권한으로 다시 돌리십시오)")
                }
                (Lang::Ko, true) => format!(
                    "접근이 거부된 디렉터리 열기 {n}회 (관리자 권한으로 다시 돌리십시오 · \
                     컨테이너 안이면 docker exec --privileged 로 들어가 다시 돌리십시오)"
                ),
                (Lang::En, false) => {
                    format!("access was denied opening {n} {dirs} (run again as Administrator)")
                }
                (Lang::En, true) => format!(
                    "access was denied opening {n} {dirs} (run again as Administrator · \
                     inside a container, enter with docker exec --privileged and run again)"
                ),
            });
        }
        for s in &self.uncollected_subjects {
            let (id, when) = (s.id(), s.info().implemented_in.as_str());
            out.push(match lang {
                Lang::Ko => {
                    format!(
                        "subject '{id}' 는 수집되지 않았습니다 ({when} 에서 수집기가 들어옵니다)"
                    )
                }
                Lang::En => {
                    format!("subject '{id}' was not collected (its collector arrives in {when})")
                }
            });
        }
        if self.all_roots_missing() {
            let (n, list) = (self.declared_roots, self.missing_roots.join(" · "));
            // **`scan_roots` 라고 쓰지 않는다** (2026-11-06) — 고객 화면에서 매니페스트의 칸 이름은
            // 읽히지 않는다. CWP 가 없는 서버에서 처음 온 사람이 이 줄을 본다. 장소는 `경로` 로
            // 부른다(목표 remedy_20261028 — `자리` → `폴더` · `경로`). 하네스가 읽는
            // `전부 존재하지 않아` 는 그대로 둔다(`Invoke-ObsVerify.ps1`).
            out.push(match lang {
                Lang::Ko => format!(
                    "검사할 경로 {n}개가 이 기계에 전부 존재하지 않아 아무 곳도 열어 보지 못했습니다: {list}"
                ),
                Lang::En => format!(
                    "all {n} paths to scan are missing on this machine, so nothing was opened at all: {list}"
                ),
            });
        }
        if !self.unreadable_roots.is_empty() {
            // **범위를 적는다.** 읽는 사람이 할 일이 거부와 다르다 — 거부는
            // 관리자 권한으로 다시 돌리면 되는 경우가 많지만, 이쪽에는 도달
            // 불가 UNC·준비되지 않은 장치가 섞인다. 그래서 자리를 보이고
            // 원인을 묻지 않는다.
            //
            // **두 언어가 같은 것을 말해야 한다.** 영어가 한때 *"could not even
            // be checked"* 였는데, 읽는 사람이 **무엇을** 못 쟀는지 알 수 없다 —
            // 한국어는 *"있는지조차"* 로 그것을 말한다. `for existence` 가 그 짝이다.
            //
            // **표본만 적는다.** 선언 루트의 수는 사람이 적지만 전개된 루트의
            // 수는 **기계가 정한다** — `%ALLUSERPROFILES%` 하나가 프로필 수만큼
            // (상한 64) 펼쳐지고, 공유가 끊긴 터미널 서버에서는 그것이 전부 이
            // 칸으로 온다. 한 줄이 화면을 먹으면 바로 아래 **결론 줄이 밀려
            // 올라간다** — 무인 배포가 읽는 것이 그 줄이다. 상한과 *"외 N개"*
            // 는 버전 쪽(`unreadable_versions`)과 같은 모양으로 둔다.
            let n = self.unreadable_roots.len();
            let shown = n.min(UNREADABLE_SHOWN);
            let mut list = self.unreadable_roots[..shown]
                .iter()
                .map(|v| clip(v, UNREADABLE_VALUE_CHARS))
                .collect::<Vec<_>>()
                .join(" · ");
            if n > shown {
                let rest = n - shown;
                list.push_str(&match lang {
                    Lang::Ko => format!(" · 외 {rest}개"),
                    Lang::En => format!(" · and {rest} more"),
                });
            }
            out.push(match lang {
                Lang::Ko => {
                    format!("선언한 자리 {n}곳이 있는지조차 확인하지 못했습니다: {list}")
                }
                Lang::En => format!(
                    "{n} declared root{} could not even be checked for existence: {list}",
                    if n == 1 { "" } else { "s" }
                ),
            });
        }
        if !self.unevaluated_rules.is_empty() {
            // **규칙마다 한 줄이 아니라 한 줄에 규칙들.** 왜 재지 못했는지(본문이
            // 없다 · 룰 파일이 없다)는 평가의 '주의' 줄들이 규칙마다 말한다 —
            // `scan` · `evaluate` · `run` 화면과 `scan.json` 의 `issues` 다. 계획에는
            // 실리지 않으므로 `apply --plan` 화면에는 이 줄만 나온다.
            let (n, list) = (
                self.unevaluated_rules.len(),
                self.unevaluated_rules.join(" · "),
            );
            out.push(match lang {
                Lang::Ko => format!("YARA 규칙 {n}개를 평가하지 못했습니다: {list}"),
                Lang::En => format!(
                    "{n} YARA rule{} could not be evaluated: {list}",
                    if n == 1 { "" } else { "s" }
                ),
            });
        }
        if !self.unreadable_versions.is_empty() {
            // 값까지 적는다 — 꼬리가 **패키지 개정**(`-1ubuntu1`)인지 **사전
            // 배포**(`RC1`)인지에 따라 읽는 사람이 할 일이 다르다.
            //
            // **이 줄만은 길이를 기계가 정한다.** 다른 사유 줄은 선언한 subject ·
            // 룰 이름처럼 작성자가 적은 것을 세는데, 여기 담기는 것은 **관측된
            // 값**이라 확장 500개가 전부 꼬리를 달고 있으면 줄 하나가 그만큼
            // 길어진다. `거부된 자리` 가 표본과 *"외 N곳"* 으로 다루는 것과 같은
            // 규율이다 (2026-10-27 적대 검증).
            let n = self.unreadable_versions.len();
            let shown = n.min(UNREADABLE_SHOWN);
            let mut list = self.unreadable_versions[..shown]
                .iter()
                .map(|v| clip(v, UNREADABLE_VALUE_CHARS))
                .collect::<Vec<_>>()
                .join(" · ");
            if n > shown {
                let rest = n - shown;
                list.push_str(&match lang {
                    Lang::Ko => format!(" · 외 {rest}개"),
                    Lang::En => format!(" · and {rest} more"),
                });
            }
            out.push(match lang {
                Lang::Ko => format!("버전 {n}개를 견주지 못했습니다: {list}"),
                Lang::En => format!(
                    "{n} version{} could not be compared: {list}",
                    if n == 1 { "" } else { "s" }
                ),
            });
        }
        // **룰의 문장을 그대로 싣는다** — 무엇을 확인할지는 룰만 안다. 항목은 결과 화면이 번호와
        // 함께 적는다(`unconfirmed_findings`). 수를 붙이지 않는다 — 셀 수 있는 것은 그룹이고 그룹
        // 하나에 항목이 여럿 들어, *"(1곳)"* 아래에 항목 둘이 서는 화면이 됐다(2026-11-09 리눅스 모양
        // 시험).
        for note in &self.unconfirmed {
            out.push(note.why_in(lang).to_string());
        }
        out
    }
}

/// `ArtifactsBody.observations` 가 평탄화되어 나가는 자리에 이미 있는 이름들.
///
/// subject 이름이 이 중 하나와 겹치면 직렬화에서 **조용히** 덮어쓴다. 오류도
/// 경고도 없고, 스냅샷을 열어 보기 전에는 알 수 없다. 그 위에서 "위협 없음" 이
/// 결론난다. 겹치지 않는다는 것을 테스트가 지킨다.
pub const RESERVED_BODY_KEYS: [&str; 12] = [
    "blobs",
    "schema_version",
    "kind",
    "run_id",
    "created",
    "host",
    "core",
    "plugins",
    "collected_at",
    "collector",
    "scope",
    "security_products",
];

impl ArtifactsBody {
    /// 이 스냅샷의 관측 완전성.
    ///
    /// 필드를 따로 두지 않고 **도출한다** — `scope` 가 이미 사실을 담고 있고,
    /// 같은 사실을 두 곳에 적으면 언젠가 갈라진다.
    pub fn observation(&self) -> Observation {
        Observation {
            truncated: self.scope.truncated,
            denied_dirs: self.scope.denied_dirs,
            denied_paths: self.scope.denied_paths.clone(),
            uncollected_subjects: self
                .scope
                .subjects
                .iter()
                .filter(|s| !self.observations.contains_key(s.id()))
                .copied()
                .collect(),
            declared_roots: self.scope.scan_roots.len(),
            missing_roots: self.scope.missing_roots.clone(),
            unreadable_roots: self.scope.unreadable_roots.clone(),
            // 평가 전이라 알 수 없다 — 평가기가 셋 다 채운다.
            unevaluated_rules: Vec::new(),
            unreadable_versions: Vec::new(),
            unconfirmed: Vec::new(),
        }
    }
}

pub type ArtifactsEnvelope = Envelope<ArtifactsBody>;
pub type ScanEnvelope = Envelope<ScanBody>;
pub type PlanEnvelope = Envelope<PlanBody>;
pub type ResultEnvelope = Envelope<ResultBody>;

// ─────────────────────────────────────────────────────────── collect 본문

const BINARY_HEAD: &str = "<binary ";
const BINARY_TAIL: &str = " bytes>";
const BINARY_TAIL_OVER_CAP: &str = " bytes, 상한 초과>";

/// **바이트를 담지 않은** 이진 값의 표기 — `<binary N bytes>`, 상한을 넘었으면
/// `<binary N bytes, 상한 초과>`. 레코드의 문자열 필드(`data` · `command` 등)에 들어간다.
///
/// 수집기가 이것으로 적고 평가기가 [`is_binary_placeholder`] 로 알아본다 — 이
/// 표기를 내용으로 훑으면 YARA 가 *"안 맞았다"* 를 내 미평가가 감춰진다(결정
/// 2026-10-26). 만드는 자리(`remedy-platform` · `remedy-collect`)와 읽는 자리가
/// 이 정의 하나를 쓰므로 문구를 바꾸면 함께 바뀐다.
pub fn binary_placeholder(len: usize, over_cap: bool) -> String {
    let tail = if over_cap {
        BINARY_TAIL_OVER_CAP
    } else {
        BINARY_TAIL
    };
    format!("{BINARY_HEAD}{len}{tail}")
}

/// [`binary_placeholder`] 가 만든 값인가.
pub fn is_binary_placeholder(data: &str) -> bool {
    let Some(rest) = data.strip_prefix(BINARY_HEAD) else {
        return false;
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && matches!(&rest[digits..], BINARY_TAIL | BINARY_TAIL_OVER_CAP)
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CollectorInfo {
    pub version: String,
    /// 수집기 자신의 비트수. WOW64 해석 오류를 막기 위해 둘 다 기록한다.
    pub bitness: u8,
    pub os_bitness: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CollectScope {
    pub scan_roots: Vec<String>,
    /// 그중 이동식 매체에서 펼쳐진 것.
    ///
    /// **읽기 허가와 파괴 허가는 다르다.** `allow_removable` 선언은 읽는 데까지
    /// 동의한 것이고, 그 위의 것을 지우는 판단은 눈앞의 매체를 보는 사람의
    /// 몫이다 (설계-03 §4). 계획기가 그 구분을 하려면 어느 루트가 이동식이었는지
    /// 여기 남아 있어야 한다 — 계획 시점에 다시 물으면 스냅샷을 뜬 기계와 다른
    /// 답이 나온다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removable_roots: Vec<String>,
    pub subjects: Vec<Subject>,
    /// subject 하나에만 적용된 **더 좁은** 상한 (매니페스트의 `subject_roots`).
    ///
    /// **산출물이 홀로 읽혀야 한다**(설계-03 §1). 이것이 없으면 스냅샷은
    /// `scan_roots` 전부를 훑은 것처럼 보이고, 실제로는 그중 일부만 본
    /// subject 가 있다는 사실이 사라진다 — 그러면 "여기 없었다" 를 잘못
    /// 읽게 된다.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub subject_roots: std::collections::BTreeMap<Subject, Vec<String>>,
    /// 확장자 없이도 `text_config` 로 읽은 디렉터리 (매니페스트의
    /// `text_config_dirs` · C-5).
    ///
    /// **`subject_roots` 와 같은 이유로 여기 있다** — 산출물이 홀로 읽혀야 한다.
    /// 이것이 없으면 `/etc/pam.d/common-auth` 가 `text_config` 로 들어온 스냅샷을
    /// 읽는 사람이 *"이 코어는 확장자 없는 파일을 전부 읽는다"* 로 오해한다.
    /// 무엇을 **선언해서** 읽었는지가 남아야 그 줄의 출처가 설명된다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub text_config_dirs: Vec<String>,
    /// 상한에 걸려 수집이 잘렸음을 표시한다.
    ///
    /// **잘린 스냅샷으로 "위협 없음" 을 결론짓지 않기 위한 필수 필드다.**
    pub truncated: bool,
    /// 접근이 거부되어 **열지 못한 횟수**. 서로 다른 디렉터리의 개수가 아니다 —
    /// 두 subject 가 같은 디렉터리를 읽으면 둘 다 세어진다 (실측: 비관리자
    /// 실행에서 `System32\Tasks` 하나가 file·persistence 양쪽에서 걸려 2 였다).
    ///
    /// 정확한 개수를 세지 않는 이유는, 이 값이 답해야 하는 질문이 "몇 개인가" 가
    /// 아니라 **"이 스냅샷을 믿어도 되는가"** 이기 때문이다. 0 이 아니면 완전하지
    /// 않다. 못 읽은 자리를 "그것이 없음" 으로 보고하면 거짓 음성이 된다.
    ///
    /// **관리자로 돌려도 0 이 아닐 수 있다.** 2026-09-01 부터 기계를 만지는
    /// 명령은 권한이 없으면 아예 시작하지 않으므로(설계-00 §5), 이 값이 잡는
    /// 것은 이제 권한 부족이 아니라 **권한이 있어도 남는 구멍**이다 — 변조
    /// 방지가 막는 Defender 예외 키, `TrustedInstaller` 가 소유한 자리, 보호
    /// 프로세스(실측 2026-08-31: 관리자 세션에서 프로세스 159개 중 19개의
    /// 명령줄을 읽지 못했다). 그래서 이 필드는 권한 검사가 생긴 뒤에도
    /// 그대로 필요하다.
    #[serde(default)]
    pub denied_dirs: usize,
    /// 거부된 자리 중 **앞의 몇 개** 경로. 비어 있으면 실리지 않는다.
    ///
    /// **`denied_dirs` 를 대신하지 않는다.** 그 값은 "이 스냅샷을 믿어도
    /// 되는가" 에 답하고, 이 목록은 "그럼 어디를 봐야 하는가" 에 답한다.
    ///
    /// 위와 같은 이유로 **중복이 들어올 수 있다** — 두 subject 가 같은
    /// 디렉터리에서 거부되면 두 번 실린다. 표본이므로 길이가 `denied_dirs`
    /// 보다 작을 수 있고, 그 차이가 "전수가 아니다" 라고 말한다.
    ///
    /// # 왜 필요했나 (2026-09-14)
    ///
    /// `%ProgramFiles%` 수집이 `denied_dirs=2` 를 내 P2 가 미결로 끝났는데
    /// **어느 폴더인지 아무 데도 없었다.** 회차가 끝난 뒤 그 기계를 뒤졌을
    /// 때는 5,713개 폴더가 전부 열렸다 — 수집이 도는 **그때만** 잠기는
    /// 자리였고, 그러면 사람은 영영 원인에 닿지 못한다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_paths: Vec<String>,
    /// 선언했으나 **존재하지 않아 한 번도 열리지 않은** 루트.
    ///
    /// 없는 루트를 조용히 건너뛰면, `scan_roots` 가 통째로 어긋난 실행이
    /// "파일 0건 · 완전한 관측" 으로 보고된다. 그 위에서 "위협 없음" 이 결론난다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_roots: Vec<String>,
    /// 선언했으나 **있는지조차 묻지 못한** 루트 (B-9 · 2026-10-27).
    ///
    /// `Path::exists()` 가 오류 전부를 *"없다"* 로 접던 동안, 부모까지 막힌
    /// 트리와 도달 불가 UNC 가 `missing_roots` 로 들어갔다. 열린 루트가 하나라도
    /// 함께 있으면 `all_roots_missing()` 이 성립하지 않아 **경고 없는 종료 0** 이
    /// 나갔다(실측).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable_roots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecurityProduct {
    pub vendor: String,
    /// 실시간 감시 상태. **`None` 은 "꺼져 있다" 가 아니라 "확인하지 못했다" 다.**
    ///
    /// 제품마다 상태를 노출하는 방식이 다르고, 변조 보호가 켜져 있으면 읽을 수
    /// 없는 경우도 있다. 모르는 것을 `false` 로 적으면 "실시간 감시가 꺼져 있었는데도
    /// 안 지워졌다" 는 잘못된 진단으로 이어진다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realtime: Option<bool>,
}

/// 판단이 섞이지 않은 원본 관찰. **어떤 룰도 여기에 개입하지 않는다.**
///
/// subject 별 레코드의 구체 타입은 `remedy-artifacts` 가 P2(2종)·P4(16종) 에서
/// 정의한다. P1 은 봉투와 범위 메타데이터까지 확정한다.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactsBody {
    pub collected_at: String,
    pub collector: CollectorInfo,
    pub scope: CollectScope,
    /// 실패 원인 진단과 지원 대응에 쓴다 (설계-00 §5-1).
    #[serde(default)]
    pub security_products: Vec<SecurityProduct>,
    /// 스냅샷에 담긴 **본문 바이트**. 키는 `sha256:<16진>`, 값은 base64 다.
    ///
    /// # 왜 스냅샷 안에 두는가
    ///
    /// 평가기는 `remedy-platform` 을 의존할 수 없고(설계-04 §1), 그 금지가
    /// "플러그인 룰은 시스템에 접근할 수 없다"를 구조적으로 보장한다. YARA 가
    /// 파일을 직접 열면 그 보장이 무너지므로, **훑을 바이트는 미리 여기 담겨
    /// 있어야 한다.** 담기지 않은 대상에 걸린 YARA 규칙은 미매치가 아니라
    /// 미평가다 (설계-03 §1).
    ///
    /// 아무 파일이나 담기지 않는다. `collect_extra` 로 **선언한 것만** 들어온다
    /// (설계-02 §6-1) — 본문을 담으면 스냅샷이 커지고 개인정보 위험이 올라간다.
    ///
    /// 키가 내용 해시라 같은 파일이 여러 자리에 있어도 한 번만 담긴다.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub blobs: BTreeMap<String, String>,
    /// subject 이름 → 레코드 배열.
    ///
    /// 설계-02 §8 이 subject 배열을 **본문 최상위**에 두므로 평탄화한다.
    ///
    /// 대가가 있다. subject 는 열려 있는 집합이고(선언 18종) 앞으로 는다. 그중
    /// 하나가 `scope` 나 `collector` 같은 이름을 갖게 되면 메타데이터를 조용히
    /// 덮어쓴다 — 오류 없이, 스냅샷만 망가진 채로. 그래서 `RESERVED_BODY_KEYS`
    /// 와의 충돌을 테스트가 막는다. 지금은 겹치는 것이 없다.
    #[serde(default, flatten)]
    pub observations: BTreeMap<String, serde_json::Value>,
}

// ─────────────────────────────────────────────────────────── evaluate 본문

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatchedPredicate {
    pub field: String,
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// 룰 평가 결과 하나.
///
/// `id` 는 `<rule-id>#<그룹 번호>` 형태다. 부모 증거가 2건 매치되면 독립적인
/// 증거 그룹 2개가 생기고, 자식 룰은 각 그룹 안에서만 평가된다 (설계-02 §4).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub id: String,
    pub rule: String,
    pub subject: Subject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    pub target: serde_json::Value,
    #[serde(default)]
    pub captures: BTreeMap<String, String>,
    #[serde(default)]
    pub matched: Vec<MatchedPredicate>,
}

/// 증거 그룹 — 부모 증거 인스턴스마다 생기는 독립 스코프 (설계-02 §4).
///
/// **그룹 간 증거가 섞여 판정을 성립시키는 일은 없다.** 서로 무관한 두 정상
/// 소프트웨어의 조각이 합쳐져 감염 판정을 만드는 사고를 막는다.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceGroup {
    /// `g0`, `g1` …
    pub id: String,
    /// 이 그룹에 속한 증거 id.
    #[serde(default)]
    pub evidence: Vec<String>,
    /// 이 그룹에서 해소된 capture. `rule.name` 형태의 키다.
    #[serde(default)]
    pub captures: BTreeMap<String, String>,
    pub verdict: bool,
    /// 판정에서 제외된 사유. 파생 경로가 `scan_roots` 를 벗어난 경우 등.
    ///
    /// **경고가 아니라 제외다** — 파생 경로는 공격자가 영향을 줄 수 있는 값이므로,
    /// 그것이 상한을 넘게 만들 수 있다면 상한이 아니다 (설계-02 §4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanBody {
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub groups: Vec<EvidenceGroup>,
    /// 판정을 통과한 증거 그룹 식별자.
    #[serde(default)]
    pub verdicts: Vec<String>,
    /// 판정식(`verdict.require`)이 짚는 규칙 id — 식에 적힌 차례 · 중복 없음 (2026-11-11).
    ///
    /// 점검 화면은 판정이 선 그룹에서 **이 규칙들의 증거만** 적는다. 그룹에는 `from` 없이 기계 전체를
    /// 보는 규칙(예: IIS 설정 · 실행 중인 프로세스에서 찾은 선언 밖의 PHP)의 증거도 함께 들어 있어,
    /// 다 적으면 판정과 상관없는 줄이 `취약` 아래에 선다(Windows 랩 실측). 비어 있으면(이 칸이 생기기
    /// 전의 산출물) 그룹의 증거를 다 적는다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verdict_rules: Vec<String>,
    /// 평가 중 발생한 문제. 룰이 아직 구현되지 않은 기능을 쓴 경우 등.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<String>,
    /// 이 평가가 기대는 관측의 완전성. 스냅샷의 사실은 `artifacts.json` 에서 실려
    /// 오고, 재지 못한 YARA(`unevaluated_rules`)와 견주지 못한 버전
    /// (`unreadable_versions`)은 이 평가가 더한다.
    #[serde(default)]
    pub observation: Observation,
    /// 이 평가가 볼 수 있었던 **읽기 권한 상한** (설계-02 §2).
    ///
    /// 계획기가 "이 대상이 상한 안이었는가" 를 물으려면 여기 있어야 한다.
    /// 밖에서 따로 받아 오면 `scan.json` 하나만으로는 답할 수 없는 질문이 생기고,
    /// 그것은 파일 경계로 단계를 나눈 이유를 무너뜨린다 (설계-03 §1).
    ///
    /// 비어 있으면 **아무것도 허용되지 않는다.** 상한이 없는 것이 아니라
    /// 알 수 없는 것이고, 알 수 없으면 막는 편이 옳다.
    #[serde(default)]
    pub scan_roots: Vec<String>,
    /// 그중 이동식 매체. `artifacts.json` 에서 실려 온다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removable_roots: Vec<String>,
}

// ─────────────────────────────────────────────────────────── plan 본문

/// 사용자가 체감할 부작용. `kind` 는 닫힌 집합이다 (설계-02 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserImpactKind {
    /// 실행 중인 프로그램을 종료해야 할 때.
    AppTerminate,
    /// 정상 프로그램이 의존하던 파일을 제거할 때.
    ///
    /// DLL 사이드로딩 때문에 필요하다. 정상 서명된 프로그램 옆의 악성 DLL 만
    /// 제거하면 **정상 프로그램을 지키는 옳은 처리이지만 그 프로그램은 더 이상
    /// 실행되지 않는다.** 지우지 않았다는 사실만 보고하면 사용자는 무슨 일이
    /// 일어났는지 모른다.
    AppBroken,
    RebootRequired,
    RemovableMedia,
}

impl UserImpactKind {
    pub const ALL: [UserImpactKind; 4] = [
        UserImpactKind::AppTerminate,
        UserImpactKind::AppBroken,
        UserImpactKind::RebootRequired,
        UserImpactKind::RemovableMedia,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            UserImpactKind::AppTerminate => "app_terminate",
            UserImpactKind::AppBroken => "app_broken",
            UserImpactKind::RebootRequired => "reboot_required",
            UserImpactKind::RemovableMedia => "removable_media",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UserImpact {
    pub kind: UserImpactKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BackupRef {
    pub entry: String,
    pub kind: String,
}

/// 계획에 넣지 못한 치료 항목과 그 이유.
///
/// **조용히 빠지면 계획이 치료의 전부인 것처럼 읽힌다.** 관측이 불완전할 수
/// 있듯 계획도 불완전할 수 있고, 둘 다 말하지 않으면 완전한 것으로 읽힌다
/// (설계-03 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeferredItem {
    /// 매니페스트 안의 자리. `remediate.remove[0]` 형태다.
    pub at: String,
    /// 이것을 하려면 필요한 Op.
    pub op: Op,
    /// 그 Op 이 들어오는 Phase.
    pub arrives_in: String,
    /// 사람에게 보여 줄 이유.
    pub reason: String,
}

/// **참조가 남아 있지 않은 완전 구체화 형태.**
///
/// 불변식 P: `apply` 는 여기 열거된 Action 만 실행한다. 새 대상을 탐색하지 않고,
/// 경로를 재해석하지 않으며, 조건 분기로 동작을 추가하지 않는다 (설계-03 §1).
///
/// 예외는 프로세스 대상이다. PID 는 계획 시점과 실행 시점 사이에 바뀌므로
/// **술어로 고정**하고 `max_targets`/`max_retries` 로 상한을 건다.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Action {
    pub seq: u32,
    pub op: Op,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// 프로세스처럼 실행 시점에 해소해야 하는 대상의 술어.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#match: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_targets: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
    /// 재귀 삭제 1건이 지울 수 있는 **하위 항목 수** 상한 (설계-03 §4).
    ///
    /// `max_targets` 와 같은 이유로 계획에 각인한다 — 그 수는 실행 시점에야
    /// 알 수 있고, **설정을 바꾸면 같은 계획이 다른 상한으로 수행된다.**
    /// 계획에 적혀 있어야 감사 로그만 보고도 무엇을 기준으로 막았는지 안다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_children: Option<u32>,
    /// 재귀 삭제 **최대 깊이** 상한 (설계-03 §4). 위와 같은 이유로 각인한다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    /// 해소된 대상의 **자손 프로세스까지** 집합에 포함한다 (설계-03 §2).
    ///
    /// 부모-자식 관계로만 식별되는 감시자를 술어로 잡을 수 없는 경우를 위한
    /// 것이다. **계획이 명시적으로 켜야 한다** — 기본은 꺼짐이고, 켜도
    /// `max_targets` 상한은 확장된 집합 전체에 그대로 걸린다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_descendants: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// 부분 편집이 **무엇을 지우는가** (`registry.strip_value` · `env.strip_path`).
    ///
    /// 증거에서 파생된 값이다 — 리터럴로 임의 편집을 지시할 수 없다 (설계-02 §6).
    /// **백업은 이것이 아니라 편집 전 값 전체**이며, 복원하면 오염된 원본이 그대로
    /// 돌아온다. 그것이 옳은 동작이다 — 사용자가 복원을 요청했다는 것은 우리
    /// 판정이 틀렸다고 본다는 뜻이므로, 우리가 "옳다고 생각한 부분" 만 남겨서는
    /// 안 된다 (설계-03 §2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip: Option<String>,
    /// 이 Action 의 근거가 된 증거. **비어 있으면 계획 단계에서 거부된다** (G7).
    pub because: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupRef>,
    pub reversible: bool,
    pub risk: Risk,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_impact: Option<UserImpact>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlanBody {
    #[serde(default)]
    pub actions: Vec<Action>,
    /// 치료 대상으로 판정된 증거 그룹.
    #[serde(default)]
    pub verdicts: Vec<String>,
    /// 이 계획의 전제가 된 관측이 완전했는가. `scan.json` 에서 실려 온다.
    ///
    /// 계획서만 받아 든 사람이 이것을 물을 수 없으면 그 물음은 답을 얻지 못한다.
    #[serde(default)]
    pub observation: Observation,
    /// 계획에 넣지 못한 치료 항목. **비어 있지 않으면 이 계획은 치료의 전부가
    /// 아니다** (설계-03 §2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deferred: Vec<DeferredItem>,
    /// 재부팅 뒤 재평가를 예약할 것인가 (설계-03 §8).
    ///
    /// **매니페스트가 아니라 계획이 이것을 나른다.** `apply` 는 계획 파일만 받고
    /// 매니페스트를 보지 않으며, `resume` 은 *"이미 승인된 계획을 이어 실행하며
    /// 절대 재스캔하지 않는다"*. 계획이 자족적이지 않으면 그 두 경로에서 예약이
    /// 조용히 빠진다.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub verify_after_reboot: bool,
    /// 분석가가 **손으로 올릴 때** 볼 판단 근거 (설계-09 "제출을 제품 밖으로").
    ///
    /// 제출 기능은 제품에 없다. 그래서 이 값은 자동 제출기가 볼 것이 아니라
    /// **사람이 볼 것**이고, `support-bundle` 이 그것을 보여 준다.
    ///
    /// **매니페스트가 아니라 계획이 나르는 이유**는 위 `verify_after_reboot` 와
    /// 같다 — `support-bundle` 은 `--run` 만 받는다. 매니페스트를 다시 찾게
    /// 만들면 그 경로는 있는데 쓰이지 않는 경로가 된다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit_hint: Option<crate::manifest::SubmitHint>,
}

impl PlanBody {
    /// 이 계획으로 치료가 끝나는가.
    pub fn is_complete(&self) -> bool {
        self.deferred.is_empty()
    }
}

// ─────────────────────────────────────────────────────────── apply 본문

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcome {
    Done,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ActionResult {
    pub seq: u32,
    pub op: Op,
    pub outcome: ActionOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 실행 결과.
///
/// 파괴 시작 이후 실패해도 **롤백하지 않는다.** 부분 제거를 되돌리면 위협이
/// 다시 무장되기 때문이다 (설계-03 §5). 실패 항목은 실패로 남고 부분 치료(종료
/// 코드 3)로 보고된다 — 재부팅 뒤 재시도는 v1 에 없다.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultBody {
    #[serde(default)]
    pub results: Vec<ActionResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<String>,
    #[serde(default)]
    pub reboot_required: bool,
}

// ─────────────────────────────────────────────────────────── 종료 코드

/// 종료 코드 7종 (설계-02 §8).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ExitCode {
    NoThreat,
    Remediated,
    FoundNotRemediated,
    PartialFailure,
    UsageError,
    /// 안전 가드에 의한 중단.
    ///
    /// 3번과 분리하는 이유: 무인 배포에서 "가드가 막았다" 와 "실행하다 실패했다"는
    /// 완전히 다른 후속 조치를 요구한다.
    GuardStop,
    /// 관측이 불완전해 "위협 없음" 을 말할 수 없다.
    ///
    /// **0번과 분리하는 이유**: 무인 배포에서 0 은 "이 PC 는 깨끗하다" 로 읽히고
    /// 그대로 종료된다. 그런데 관리자 권한 없이 돌아 `System32\Tasks` 를 못 읽은
    /// 실행도 0 을 냈다. 그 PC 는 검사받았다고 기록되지만 실제로는 절반만 본 것이다.
    /// 경고는 stderr 로 나가는데 무인 배포에서 stderr 는 버려진다.
    ///
    /// **0번만 대체한다.** 위협을 찾았다면 관측이 불완전해도 그 발견은 유효하므로
    /// 1·2 가 우선한다 — 불완전성은 "없다" 를 뒤집을 뿐 "있다" 를 뒤집지 못한다.
    IncompleteObservation,
    /// 도구 자체가 멈췄다 — 패닉.
    ///
    /// **5번과 분리하는 이유**: 가드 중단은 도구가 *일부러* 멈춘 것이고 이것은
    /// 도구가 *깨진* 것이다. 무인 배포의 후속 조치가 다르다 — 앞은 룰을 보고 뒤는
    /// 개발자에게 `logs/crash-*.txt` 를 보낸다. 배포 빌드는 `panic = "abort"` 라
    /// 훅이 없으면 이 코드 대신 OS 의 값(0xC0000409·SIGABRT)이 나갔다 (2026-09-07).
    InternalError,
}

impl ExitCode {
    pub const ALL: [ExitCode; 8] = [
        ExitCode::NoThreat,
        ExitCode::Remediated,
        ExitCode::FoundNotRemediated,
        ExitCode::PartialFailure,
        ExitCode::UsageError,
        ExitCode::GuardStop,
        ExitCode::IncompleteObservation,
        ExitCode::InternalError,
    ];

    pub const fn code(self) -> u8 {
        match self {
            ExitCode::NoThreat => 0,
            ExitCode::Remediated => 1,
            ExitCode::FoundNotRemediated => 2,
            ExitCode::PartialFailure => 3,
            ExitCode::UsageError => 4,
            ExitCode::GuardStop => 5,
            ExitCode::IncompleteObservation => 6,
            ExitCode::InternalError => 7,
        }
    }

    /// 사람에게 보여 줄 의미. `meaning()` 은 생성물이 읽는 한국어 고정 문구라
    /// 그대로 두고, 화면은 이것을 쓴다.
    pub const fn meaning_in(self, lang: crate::i18n::Lang) -> &'static str {
        use crate::i18n::Lang;
        match (self, lang) {
            (ExitCode::NoThreat, Lang::Ko) => "위협 없음",
            (ExitCode::NoThreat, Lang::En) => "no threat",
            (ExitCode::Remediated, Lang::Ko) => "위협 발견 · 치료 완료",
            (ExitCode::Remediated, Lang::En) => "threat found, treated",
            (ExitCode::FoundNotRemediated, Lang::Ko) => {
                "위협 발견 · 치료 안 함 (드라이런/사용자 거절)"
            }
            (ExitCode::FoundNotRemediated, Lang::En) => {
                "threat found, not treated (dry run / declined)"
            }
            (ExitCode::PartialFailure, Lang::Ko) => "부분 실패 (일부 항목 실패)",
            (ExitCode::PartialFailure, Lang::En) => "partial failure (some actions failed)",
            (ExitCode::UsageError, Lang::Ko) => "사용법·입력 오류",
            (ExitCode::UsageError, Lang::En) => "usage or input error",
            (ExitCode::GuardStop, Lang::Ko) => {
                "안전 가드에 의한 중단 (상한 초과·보호 경로·서명 검증 실패)"
            }
            (ExitCode::GuardStop, Lang::En) => {
                "stopped by a safety guard (limit, protected path, signature)"
            }
            (ExitCode::IncompleteObservation, Lang::Ko) => {
                "관측 불완전 — '위협 없음' 을 말할 수 없습니다"
            }
            (ExitCode::IncompleteObservation, Lang::En) => {
                "observation incomplete: cannot declare 'no threat'"
            }
            (ExitCode::InternalError, Lang::Ko) => {
                "내부 오류 — 도구 자체가 멈췄습니다 (logs/crash-*.txt 를 신고에 붙이십시오)"
            }
            (ExitCode::InternalError, Lang::En) => {
                "internal error: the tool itself crashed (attach logs/crash-*.txt to the report)"
            }
        }
    }

    pub const fn meaning(self) -> &'static str {
        match self {
            ExitCode::NoThreat => "위협 없음",
            ExitCode::Remediated => "위협 발견 · 치료 완료",
            ExitCode::FoundNotRemediated => "위협 발견 · 치료 안 함 (드라이런/사용자 거절)",
            ExitCode::PartialFailure => "부분 실패 (일부 Action 실패)",
            ExitCode::UsageError => "사용법·입력 오류",
            ExitCode::GuardStop => "안전 가드에 의한 중단 (상한 초과·보호 경로·서명 검증 실패)",
            // **원인을 나열하지 않는다.** 원인이 늘 때마다 여기가 낡았다 — 두 번은
            // 아무도 몰랐고(미수집 subject · 전부 없는 루트), YARA 미평가(2026-10-26)
            // 에서야 드러났다. 원인은 화면의 사유 줄이 말한다.
            ExitCode::IncompleteObservation => {
                "관측 불완전 - 다 보지 못해 '위협 없음' 을 말할 수 없습니다 (사유는 '주의' 아래 줄)"
            }
            ExitCode::InternalError => {
                "내부 오류 - 도구 자체가 멈췄습니다 (logs/crash-*.txt 를 신고에 붙이십시오)"
            }
        }
    }
}
