# 예시 — EvilAI(Locust) 플러그인 작성

분석가가 실제로 쓰게 될 파일이 어떤 모양인지 보여주기 위한 문서다.
설계-02(SDK 계약)의 스키마로 표현했고, 설계-04 §2 · 설계-07 시나리오 A 의 초안을 이어받았다.

> **먼저 알아둘 것 — 아직 동작하지 않는다.**
> 지금은 P0(골격)만 끝났다. 스키마가 단일 소스로 확정되는 것이 **P1**, `file`·`persistence` 관찰과
> `scan` 이 **P2**, `plugin lint` 가 **P3**, 나머지 관찰 대상이 **P4**, 실제 치료가 **P6**, 서명이 **P10** 이다.
> 이 문서는 "이렇게 쓰게 된다"를 보여주는 것이지 지금 돌려볼 수 있는 것이 아니다.

---

## 1. 패키지 전체 모습

```
  plugins/evilai-locust/
    plugin.yaml        <- 분석가가 쓴다 (필수). 대부분의 작업이 여기서 끝난다
    rules/evilai.yar   <- 분석가가 쓴다 (선택). 내용을 봐야 할 때만
    tests/             <- 분석가가 쓴다 (필수). 감염/클린 스냅샷과 기대 결과
    strings/ko.yaml    <- 분석가가 쓴다 (선택). 사용자 표시 문구
    MANIFEST.json      <- 도구가 생성 (P10)
    MANIFEST.sig       <- 서명자가 만든다 (P10)
```

`scripts/` 자리가 스키마에 예약돼 있지만 **v1 에서는 런타임을 구현하지 않는다**(설계-01 D4).
경계선은 "스크립트는 읽고, 룰은 쓴다" — 치료는 100% 선언적 룰이다.

서명 대상은 `plugin.yaml` 이 아니라 **`MANIFEST.json` 전체**다. 룰 파일 하나만 서명하면
YARA 룰을 갈아끼울 수 있어 서명이 무의미해진다.

---

## 2. `plugin.yaml`

EvilAI(Locust) 는 `node.exe` 로 `.js` 페이로드를 돌리고, 예약 작업과 Run 키로 이중화하며,
`%LOCALAPPDATA%\Programs` 아래 **랜덤한 이름의 폴더**에 자리를 잡고, 자기 경로를
백신 예외 목록에 등록한다.

> **실검체로 확인한 것 (2026-08, P9).** 위 서술은 검체에서 맞았다. VT 패밀리명은
> `meadowlocust` 이고, 샌드박스 행위가
> `"C:\Program Files\nodejs\node.exe" "…\preload.js"` 로 아래 detect 규칙과 그대로
> 맞는다. 폴더 이름은 `SystemSoftwareUpdaterV2-q5ty`,
> `MicrosoftResourcesAgentV12-we9i6` 처럼 **시스템을 사칭한 이름 + `-<랜덤 4~5자>`** 였다.
>
> **다만 "정상 코드서명 인증서로 서명된 AI 앱으로 위장한다" 는 확인하지 못해 이 문단에서
> 뺐다.** 근거: `engines:meadowlocust tag:signed` 0건, 구성원 40건 개별 조회에서
> `signature_info.subject` 보유 0건, 내려받은 PE 2건은 파일 바이트에서 인증서 테이블
> 크기 0. 이것은 "서명되지 않는다" 가 아니라 **우리가 확보한 군집에서 못 봤다** 이다.
> 자세한 것은 §8.

```yaml
schema_version: 1
id: evilai-locust
version: 0.1.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "EvilAI(Locust) 제거"
  en: "EvilAI (Locust) Removal"
references:
  - "https://<사내 인텔 티켓 또는 공개 리포트 URL>"   # TODO: 실제 근거 링크

# ── 권한 상한 ──────────────────────────────────────────────
# scan_roots 는 성능 최적화가 아니라 "여기 밖은 읽을 수 없다"는 상한이다.
# 서명된 플러그인이 임의 경로를 읽을 수 있으면 그 자체가 정보 수집 도구가 된다.
scan_roots:
  - "%SystemRoot%\\System32\\Tasks"     # 예약 작업 정의를 읽기 위해
  - "%LOCALAPPDATA%\\Programs"          # 페이로드가 자리잡는 곳

# 선언한 대상 타입만 볼 수 있다. 여기 없는 subject 는 detect 에서 쓸 수 없다.
subjects: [persistence, file, autorun, process, av_exclusion]

allow_removable: false                  # 기본값. USB 웜이 아니므로 켜지 않는다

# ── 관찰 규칙 ──────────────────────────────────────────────
detect:
  # (1) 예약 작업 — 이 위협의 뼈대
  - id: task
    subject: persistence
    where:
      all:
        # 정규식은 **작은따옴표**로 적는다. YAML 작은따옴표는 역슬래시를 그대로
        # 두므로 정규식이 보이는 대로 전달된다. 큰따옴표를 쓰면 한 겹만 틀려도
        # 조용히 매치되지 않는다.
        - { field: command,                op: matches,     value: '(?i)\\node\.exe$' }
        # `.js` 뒤가 공백만은 아니다. 인자가 따옴표로 묶여 있으면 `"...main.js" --run`
        # 이라 다음 글자가 `"` 다. `(\s|$)` 만 보면 놓친다 —
        # docs/plugin-guide/examples/ex01 을 실행 가능한 테스트로 만들면서 잡았다.
        - { field: args,                   op: matches,     value: '(?i)\.js("|\s|$)' }
        - { field: win.task.register_path, op: starts_with, value: "\\Microsoft\\Windows\\" }
    capture:
      # 폴더 이름이 감염마다 바뀌므로 리터럴로 적을 수 없다.
      # 증거에서 뽑아낸다 — 이것이 "랜덤 폴더명" 을 다루는 방법이다.
      script_path: "args | first_path"
      payload_dir: "${script_path} | dirname"
    exclude:
      # 정상 Node 개발 환경이 첫 번째 오탐 후보다 (설계-04 §3.3).
      - { field: "file(command).signature.subject", op: equals,  value: "Microsoft Corporation" }
      - { field: source,                           op: contains, value: "\\Microsoft VS Code\\" }
    score: 90        # 보고·우선순위 표시용일 뿐이다. 판정 게이트가 아니다

  # (2) 드롭된 페이로드 — 내용으로 확인한다
  - id: payload
    subject: file
    from: "${task.payload_dir}"          # 증거에서 파생된 경로만 스캔한다
    where:
      - { yara: "rules/evilai.yar:evilai_locust_js" }

  # (3) Run 키 이중화
  - id: runkey
    subject: autorun
    where:
      - { field: command, op: contains, value: "${task.payload_dir}" }

  # (4) 백신 예외 등록 — 증거이자 원복 대상이다
  - id: av-exclusion
    subject: av_exclusion
    where:
      - { field: value, op: contains, value: "${task.payload_dir}" }

# ── 판정 게이트 ────────────────────────────────────────────
# 점수 임계값(score >= 80)을 게이트로 쓸 수 없다.
# 독립적인 두 근거의 논리곱이라야, 룰 하나의 오탐이 곧바로 삭제로 이어지지 않는다.
verdict:
  require: "task and payload"

# ── 치료 — "무엇이 남아 있으면 안 되는가" ──────────────────
# 순서·백업·프로세스 종료를 여기 적지 않는다. 계획기가 도출한다.
remediate:
  remove:
    - { ref: task }
    - { ref: payload }
    - { ref: runkey }
    # recursive 는 guard 가 필수다. guard 는 "그 디렉터리 안에서 악성으로 판정된 파일" 을 가리킨다.
    # capture 해석이 어긋나 payload_dir 가 %LOCALAPPDATA%\Programs 자체가 되더라도,
    # 그 안에 악성 판정 파일이 없으므로 이 삭제는 계획에 들어가지 않는다.
    - { path: "${task.payload_dir}", recursive: true, guard: payload }
  restore:
    - av_exclusions                      # 원복은 파괴가 아니므로 별도 절이다
  verify:
    after_reboot: true

# ── 분석에 필요한 것 (치료와 무관) ─────────────────────────
collect_extra:
  - { ref: payload, content: true }                                    # 검체 본문
  - { path: "${task.payload_dir}/config.json", max_size: 1MB }         # 있으면 C2 설정

submit_hint:
  samples: [payload]
  confidentiality_min: 1                 # 하한만 올릴 수 있다. 낮출 수는 없다
```

> **2026-09-30 표시** — 위 예시의 `exclude` 두 줄은 지금 매니페스트(`plugins/evilai-locust/plugin.yaml`)에
> 없다. 둘 다 발동할 수 없음이 실측으로 드러나 P9 에서 지웠다 — 실기기의 `node.exe` 는 OpenJS 서명이고,
> 예약 작업의 `source` 는 정의 파일 경로라 설치 경로가 들어갈 자리가 없다. 값을 고쳐 살릴 수 있는 술어도
> 아니다(위협이 정상 실행 파일을 그대로 쓴다). 정상 Node 개발 환경의 오탐 방어는 `verdict: task and payload`
> 의 논리곱 · `from:` 범위 제한 · YARA 가 맡는다(같은 매니페스트의 주석).

---

## 3. 각 절을 언제 쓰는가

| 절 | 이 플러그인에서 | 일반적으로 |
|---|---|---|
| `scan_roots` | 작업 정의 + 페이로드 폴더 | 읽기 권한 상한. 넓게 잡으면 그만큼 위험해진다 |
| `subjects` | 5종 | 선언한 것만 볼 수 있다 |
| `detect` | 작업·파일·Run키·예외목록 | 항상 |
| `capture` | 랜덤 폴더명 추출 | 감염마다 값이 바뀌는 것을 다룰 때 |
| `from` | 페이로드를 작업이 가리킨 폴더에서만 찾음 | 앞 증거로 탐색 범위를 좁힐 때 |
| `exclude` | Node 개발 환경 제외 | 오탐 후보를 아는 경우 |
| `verdict.require` | `task and payload` | 항상. **논리곱만 허용** |
| `remove` | 4건 | 통째로 없어져야 하는 것 |
| `edit` | 안 씀 | **값의 일부만 오염된 것** (§6 참고) |
| `restore` | 백신 예외 목록 | 악성코드가 바꿔 놓은 것을 되돌릴 때 |
| `collect_extra` | 검체 본문·설정 | 치료엔 불필요하나 분석에 필요할 때 |
| `submit_hint` | 검체 제출 제안 | 사내 분석 시스템에 올릴 때 |

**증거 그룹**을 이해하면 다중 감염이 쉬워진다. 작업이 2건 매치되면 증거 그룹이 2개 생기고,
각 그룹은 **자기 `payload_dir` 로만** `payload` 와 `runkey` 를 평가한다. 그룹 #0만 `require` 를
통과하면 치료는 #0의 증거에만 적용된다 — 서로의 증거가 섞이지 않는다.

---

## 4. `rules/evilai.yar` — 비워 두었다가 실검체로 채웠다

**원칙은 그대로다: 검체 없이 그럴듯한 문자열을 지어 넣지 않는다.** 그래서 P9 에서
검체를 확보할 때까지 이 룰은 `condition: false` 스텁이었다.

지금은 채워져 있다 — `plugins/evilai-locust/rules/evilai.yar`. 검체 16건에서 뽑아
교차 확인했다.

검체는 전부 obfuscator.io 계열 난독화라 **평문 IOC 가 0건**이었다(URL·도메인·경로
전부). 그래서 룰은 인코딩된 문자열배열 상수와 난독화 골격을 겨눈다.

| 룰 | 대상 | 근거 |
|---|---|---|
| `evilai_locust_strarray_loader` (private) | 소형 로더 8건 | 공유 상수 90개 중 20개 |
| `evilai_locust_strarray_bundle` (private) | 대형 번들 3건 | 고유 상수 11개 중 6개 |
| `evilai_locust_rc4_flattened` (private) | rc4 계열 5건 | 알파벳 ∧ 제어흐름평탄화 ∧ 키객체≥8 |
| **`evilai_locust_js`** | 위 셋의 논리합 | 매니페스트가 참조하는 이름 |

실측: 탐지 **16/16**, 오탐 **0/25,863**(호스트 청정 `.js`) · **0/3,750**(VM, Defender
실시간보호 켠 상태) · **0/625**(타 패밀리 검체 25종). 세 측정 모두 못 훑은 파일 0건.

> **이 룰을 시스템 전역 스캔에 쓰면 안 된다.** rc4 룰은 악성코드가 아니라 **난독화기**의
> 골격을 겨누므로, 같은 도구·설정으로 난독화한 정상 소프트웨어는 원리상 걸릴 수 있다.
> 위 코퍼스에서 0건이었을 뿐이다. 아래 `dropped-payload` 가 `from: ${…script_dir}` 로
> **악성 예약작업이 가리키는 디렉터리 안으로 범위를 좁히는 것**이 실질적인 방어다.

채워야 했던 네 가지의 현재 상태:

| | 상태 |
|---|---|
| 드롭된 `.js` 페이로드의 고유 문자열 — 검체 3건 이상 교차 확인 | **끝** (위 표) |
| 설치 파일·부모 프로세스의 해시 | 부분 — PE 2건 확보. 부모는 시스템 설치 `node.exe` 로 관측 |
| **서명 주체(subject/thumbprint)** | **채우지 못했다** — §8 |
| `%LOCALAPPDATA%\Programs` 하위 실제 디렉터리명 패턴 | 관측 — 시스템 사칭 이름 + `-<랜덤 4~5자>` |

YARA 는 파일 전용이 아니다. 바이트열을 주는 모든 필드에 쓴다 — `registry_value.data`,
`text_config.line`, `structured_config` 값. **파일리스 위협은 페이로드가 파일이 아니므로
이 확장 없이는 다루지 못한다.**

---

## 5. `tests/` — 필수인 이유

```
  tests/
    clean/       정상 환경 스냅샷 → 파괴 계획이 0건이어야 한다 (G1)
    infected/    감염 환경 스냅샷 → 기대 계획과 일치해야 한다
```

`collect` 와 `evaluate` 를 분리한 덕분에 **VM 없이 CI에서 수백 개 청정 환경을 초 단위로**
돌릴 수 있다. VM 이미지로는 몇 개밖에 못 돌린다. 그 차이가 오탐 방지의 실질적 사거리다.

EvilAI 룰이 `node.exe` + `.js` 조합으로 예약 작업을 훑는다는 것은 **정상 Node 개발 환경이
첫 번째 오탐 후보**라는 뜻이다. `tests/clean/` 에 Node·VS Code·Electron 앱이 깔린 환경이
반드시 들어가야 한다.

한 번 겪은 오탐 환경은 `corpus/clean/` 에 편입된다. 시간이 갈수록 이 디렉터리가 제품의
핵심 자산이 된다.

---

## 6. 이 위협에는 안 나오지만 알아둘 것 — `edit`

EvilAI 는 통째로 지우면 되는 형태라 `edit` 을 쓰지 않는다. 하지만 **값의 일부만 오염된
대상이 오히려 주류다.** `Winlogon\Userinit` 이 `userinit.exe,악성.exe` 로 오염됐을 때
값을 통째로 지우면 **사용자가 로그온을 못 한다.**

```yaml
# 설계-07 시나리오 B (서비스 + 로그온 하이재킹) 에서 발췌 — EvilAI 가 아니다
remediate:
  edit:
    - { ref: userinit-hijack, op: strip, value: "${svc.svc_bin}" }
  restore:
    - { ref: shell-hijack, to: default }     # 코어 내장 OS 기본값 카탈로그에서만
```

같은 형태가 `Shell`, `AppInit_DLLs`, 서비스 `ImagePath`, `PATH`, 각종 설정 파일 라인에서 반복된다.
`edit` 의 `value` 는 **증거에서 파생된 값**이어야 하고, 리터럴로 임의 편집을 지시할 수 없다.
백업은 **편집 전 값 전체**이며, 복원하면 오염된 원본이 그대로 돌아온다 — 그것이 옳은 동작이다.

---

## 7. 작성자가 할 수 없는 것

막히면 대개 이 중 하나다. 전부 의도된 제약이다.

| 하고 싶은 것 | 왜 막혀 있나 |
|---|---|
| `remove` 에 리터럴 절대 경로 | 증거 없는 삭제를 **문법 수준에서** 불가능하게 한다 |
| `guard` 없는 재귀 삭제 | capture 해석이 어긋나면 폭주한다 |
| 점수 임계값으로 판정 | 휴리스틱 하나의 오탐이 곧 삭제가 된다 |
| 순서·백업·프로세스 종료 지정 | 계획기가 도출한다. 플러그인마다 순서 실수가 재발하지 않게 |
| `edit` 에 리터럴 값 | 임의 편집 지시를 막는다 |
| 정규식 역참조·전방탐색 | RE2 라 입력 길이에 선형이다. 룰이 스캐너를 멈추는 사고가 원천 차단된다 |
| `platforms` 선언 없이 `win.*` 참조 | "크로스플랫폼인 척하는 룰" 을 막는다 |
| 스크립트로 파괴 동작 | 불변식 P — 실행 전에 계획을 알 수 없게 된다 |

다중 사용자 환경은 `HKU\*` / `%ALLUSERPROFILES%` 를 써야 한다. 안 쓰면 **현재 로그온
사용자만 치료되고 나머지는 감염 상태로 남는다.**

---

## 8. 아직 확정되지 않은 것 (P1 에서 정해질 것)

이 예시를 쓰면서 스키마에 빈 곳 두 군데가 드러났다. 하나는 P1 에서 닫혔다.

**`signed_malware` — P1 에서 확정됨.** 플러그인 최상위에 두고, **목록 자체를 플래그로 삼는다.**

```yaml
signed_malware:
  - { subject: "<서명 주체>", thumbprint: "<지문>" }   # 둘 중 하나는 필수
```

설계-03 §3 은 "`signed_malware: true` 와 함께 서명 주체를 열거" 로 적었지만, 플래그와 목록을
따로 두면 **`true` + 빈 목록**이라는 포괄적 무시가 표현 가능해진다. 목록을 플래그로 삼으면
그것이 표현 불가능해진다. 항목마다 `subject` 또는 `thumbprint` 중 하나는 있어야 하고,
둘 다 없으면 스키마 검증이 거부한다. (설계-02 §2)

> **실검체 확인 결과 — 이 절은 비워 둔다 (2026-08, P9).** 원래 여기에는 "EvilAI 는 서명된
> 악성코드이므로 실검체에서 서명 주체를 확인한 뒤 채워야 플러그인이 완성된다" 고 적혀
> 있었다. 검체를 확보해 확인한 결과 **서명된 것을 찾지 못했다** — `engines:meadowlocust
> tag:signed` 0건, 구성원 40건 개별 조회에서 `signature_info.subject` 보유 0건, 내려받은
> PE 2건은 파일 바이트에서 인증서 테이블 크기 0.
>
> 확보한 것은 detect 규칙과 행위가 일치하는 VT `meadowlocust` 군집이다. 공개 보고가 말하는
> 서명된 설치 파일 단계가 그 라벨을 달지 않았을 수 있으므로, **"서명되지 않는다" 로 단정하지
> 않는다.** 못 봤다와 없다는 다르다.
>
> 그래서 `signed_malware` 를 **비워 둔 채로 플러그인을 완성한다.** 목록이 곧 플래그이므로
> 비어 있으면 예외가 없는 것이고, 서명된 대상을 만나면 2층이 삭제를 막고 그 사실이
> 보고된다 — 근거 없이 열거를 지어 넣는 것보다 옳은 실패 방향이다.
>
> **아직 답이 없는 것:** 페이로드 디렉터리 안에 자체 동봉한 **정상 서명 런타임**(Node/Electron)이
> 있는가. 있다면 악성코드의 서명 여부와 무관하게 재귀 삭제가 2층에 걸린다. 샌드박스에서는
> 시스템 설치 `node.exe` 를 쓰는 것만 관측됐고, 이것은 `corpus/infected/` 가 있어야 답할 수 있다.

**`tests/` 내부 배치 — 아직 미정.** "감염/클린 스냅샷 기대 결과" 라고만 되어 있고 파일 이름
규칙, 기대 결과 포맷, `plugin lint`(P3) 가 무엇을 검사하는지가 정해지지 않았다. 스냅샷 포맷이
P2 에서 나오고 린트가 P3 이므로 그때 함께 정해진다.

---

## 9. 이 예시는 테스트다

위 `plugin.yaml` 은 `remedy-sdk` 의 테스트가 **실제로 파싱한다**
(`crates/remedy-sdk/tests/schema.rs` 의 `evilai_example_in_docs_parses`).

스키마가 바뀌어 이 예시가 더 이상 유효하지 않게 되면 CI 가 실패한다. 통과하지 못하는
예시를 팀에 보여 주면 그것을 따라 쓴 사람이 전부 막히기 때문이다 (설계-06 §5).
