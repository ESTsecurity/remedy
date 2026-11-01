# 2026-09-01 · Opus 4.8 · r1 (evilai-locust)

| | |
|---|---|
| 모델 | Claude Opus 4.8 (웹 대화) |
| 돌린 날짜 | 2026-09-01 |
| 위협 | `evilai-locust` |
| 주입 꾸러미 | `cargo xtask exam --bundle` (당일 생성) |
| 오염 | **없음(절차상).** 저장소를 읽지 않은 새 대화에 꾸러미만 붙이는 절차를 따랐다. 강제되지 않는 명예 규칙이므로(README §오염) 다르게 진행했다면 이 줄을 고칠 것 |

**이 회차는 문서가 하나 늘어난 뒤다.** 같은 날 `31-nonexistent.md` 에 「볼 수 없는
것」 절이 들어갔고, 꾸러미에 그것이 포함된 것을 확인했다(`grep` 1건). 앞선
회차들과 주입 목록이 다르므로 숫자를 나란히 놓을 때 그 사실을 함께 볼 것.

## 받은 것

답은 `evilai-locust/plugin.yaml` · `evilai-locust/rules/evilai.yar` 구조의 zip
하나와, 같은 내용의 낱개 파일 둘로 왔다. 셋의 바이트가 서로 같음을 확인하고
저장소 규약대로 폈다(`plugin.yaml` + `rules/evilai.yar`). 원본 zip 은 2026-11-01 에
저장소에서 뺐다 — 내용이 위 두 파일과 바이트까지 같은 사본이고, 누출 검사기가
풀어 볼 수 없는 형식이라 공개 트리에 둘 수 없다.

**분석가 YARA 룰은 손대지 않았다.** `threats/evilai-locust/rules/evilai.yar` 와
바이트 동일(sha256 앞 16자리 `63a9cf406cf21c77`, 7643 B). 프롬프트가 명시한
*"룰 파일의 내용을 고치지 마라"* 를 지켰다 — 앞선 회차에서 이것이 지켜지지 않은
적이 있는지와 무관하게, 지킨 것은 기록해 둔다.

## 채점

```
채점 대상: evilai-locust (testbed/ai-exam/runs/2026-09-01-opus-4.8-r1)
위협: evilai-locust

  1. 린트          오류 0 · 경고 0
  2. 청정 코퍼스   15개 중 파괴 0개
  3. 감염 탐지     1개 중 판정 1개
  4. 계획 완결성   기대 6건 중 빠짐 0건

합격 — 네 판정을 전부 통과했다
```

오염 없는 회차로는 **세 번째 합격**(`fable-5-r1` · `fable-5-svc-r2` 다음),
`evilai-locust` 위협으로는 **두 번째**다. Opus 계열로는 오염 없이 처음이다 —
앞선 `2026-08-26-opus-5-*` 셋은 저장소를 보며 쓴 오염 회차다.

## 채점기가 재지 못하는 것 — 실기기에서 봤다

README 가 못 잰다고 적어 둔 셋 중 둘을 사람이 확인했다. 특히 `scan_roots` 는
*"존재하지 않는 경로를 선언해도 네 판정을 전부 통과한다(r1 실측). 실기기 `scan`
에서만 드러난다"* 고 적혀 있고, **이 답의 `scan_roots` 는 참조 답안과 다르다.**

| | 참조 답안 | 이 회차 |
|---|---|---|
| `scan_roots` | `%SystemRoot%\System32\Tasks` · `%LOCALAPPDATA%\Programs` | `%ALLUSERPROFILES%\AppData\Local\Programs` |

감염된 실기기(Win10 VM, 관리자)에서 둘을 나란히 `scan` 했다.

| | 참조 | 이 회차 |
|---|---|---|
| `scan_roots` 전개 | `C:\Users\test\AppData\Local\Programs` · `C:\Windows\System32\Tasks` | `C:\Users\test\AppData\Local\Programs` |
| 수집 지속성 | 219 | **219** |
| 수집 파일 | 8170 | 7951 |
| 증거 · 그룹 · 판정 | 5 · 1 · 1 | **5 · 1 · 1** |
| 계획 Action | 6 | **6** |

계획의 여섯 대상이 **문자 그대로 같다.**

```
autorun.remove         HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SystemSoftwareUpdater
av.restore_exclusions  HKLM\SOFTWARE\...\Exclusions\Paths\C:\Users\test\AppData\Local\Programs\MicrosoftResourcesAgentV12-we9i6
dir.delete_recursive   C:\Users\test\AppData\Local\Programs\MicrosoftResourcesAgentV12-we9i6
file.quarantine_only   C:\Users\test\AppData\Local\Programs\MicrosoftResourcesAgentV12-we9i6\preload.js
persistence.delete     \Microsoft\Windows\Locust
persistence.disable    \Microsoft\Windows\Locust
```

파일 수 차이 219 건은 정확히 예약 작업 정의 XML 의 수다 — 참조가 그것을
`file` 로도 담고, 이 회차는 담지 않는다. **어느 룰도 그것을 쓰지 않는다.**

## AI 가 틀린 것

**없다.** 네 판정과 실기기 확인 모두 통과했다. 이 회차의 산출물은 "무엇을
틀렸는가" 가 아니라 아래 둘이다.

### 1. AI 가 맞혔고 **우리 예제와 참조 답안이 틀렸다** — `System32\Tasks` scan_root

답안은 이렇게 적었다.

> `persistence`·`autorun`·`process`·`av_exclusion` 은 path 가 없어 이 상한을
> 거치지 않으므로 여기 적지 않는다(적어도 효과 없음). 상한에 걸리는 건
> payload `.js` 뿐.

**맞다.** `collect_scheduled_tasks` 는 `%SystemRoot%\System32\Tasks` 를 **직접
펴서 걷는다** — `scan_roots` 를 보지 않는다. 실측이 그것을 확인했다:
`System32\Tasks` 를 선언하지 않은 이 회차도 지속성 219 건을 그대로 걷었다.

그런데 우리 쪽 둘이 그 경로를 선언하면서 같은 이유를 적어 두었다. **하나는
이 회차에 주입된 예제다.**

```yaml
# plugins/evilai-locust/plugin.yaml  (참조 답안)
  - "%SystemRoot%\\System32\\Tasks"     # 예약 작업 정의를 읽기 위해

# docs/plugin-guide/examples/ex01-scheduled-task/plugin.yaml  (이 회차에 주입됨)
  - "%SystemRoot%\\System32\\Tasks"    # 예약 작업 정의 파일이 있는 곳
```

**그 이유는 사실이 아니다.** 그것 없이도 예약 작업은 읽힌다. 실제 효과는 작업
정의 XML 219 건이 `file` 로도 담기는 것뿐이고, 그것을 쓰는 룰은 없다.
`scan_roots` 는 읽기 권한 **상한**이므로(설계-03), 쓰지 않는 경로를 선언하는
것은 상한만 넓히는 일이다.

**AI 가 예제를 그대로 베끼지 않았다는 것이 이 항목의 값이다.** 답안의 나머지
골격은 `ex01` 을 그대로 따랐다 — `task`/`payload` 규칙 이름, `capture` 의
`script`/`dir` 이름, `verdict: "task and payload"`, 정규식을 작은따옴표로 적는
관례까지. 그런데 `scan_roots` 에서만 예제를 벗어났고, 벗어난 이유를 정확히 적었다.

**같은 날 고쳤다** — 아래 「후속」 참조.

## 후속 (2026-09-01)

이 항목을 따라가다 **가이드 안의 자기모순**을 찾았다. `10-manifest.md` 는
`scan_roots` 예제에 `%SystemRoot%\\System32\\Tasks` 를 적어 두고, **열두 줄
아래 표에서** `persistence` 를 *"무관하게 수집된다"* 쪽에 넣고 있었다. 같은
파일이 하라는 것과 하지 말라는 것을 함께 적고 있었다.

그리고 그것이 실제로 전파됐다 — **앞선 회차 여섯 편이 전부 그 줄을 따라
적었다**(r0 · fable-5-r1 · r2 · opus-5-r1 · r2 · r3). 예제를 벗어난 것은 이
회차뿐이다.

고친 자리 다섯: `10-manifest.md` 예제 · `01-quickstart.md` 예제 ·
`examples/ex01-scheduled-task/plugin.yaml` · `generate.rs` 의 AI-CONTEXT 예제
(생성물이라 원본을 고쳤다) · `plugins/evilai-locust/plugin.yaml`.

**시험 기록은 건드리지 않았다.** `runs/*` 는 그때 무엇이 제출됐는지의 기록이고,
고치면 기록이 아니게 된다.

좁힌 참조 플러그인으로 감염된 실기기에서 **치료까지** 돌려 확인했다 — 지난번엔
`scan` 만 쟀다.

| | |
|---|---|
| 기록된 `scan_roots` | `C:\Users\test\AppData\Local\Programs` 하나 |
| 수집 | 지속성 **219**(그대로) · 파일 7951 |
| 계획 | Action 6 — 여섯 Op 그대로 |
| 수행 | **6건 수행 완료** |
| 치료 뒤 | 페이로드 폴더 0 · 예약 작업 없음 · Run 값 없음 · Defender 예외 0 |

`guard.rs` 가 왜 이것이 안전한지도 말한다 — `collected_from_a_fixed_place` 가
`PersistenceDisable`/`PersistenceDelete` 를 `scan_roots` 대조에서 빼고, 예약
작업 등록 경로는 `Shape::Task` 라 애초에 경로 상한을 타지 않는다.

### 2. `%ALLUSERPROFILES%` — 참조보다 나은 선택

답안은 `%LOCALAPPDATA%` 대신 `%ALLUSERPROFILES%\AppData\Local\Programs` 를
골랐고, 이유를 적었다 — *"`%LOCALAPPDATA%` 로 좁히면 다중 사용자 기계에서 스캔한
사용자만 치료되고 나머지는 감염된 채 남는다."*

이것은 SDK 가 그 토큰을 만든 이유와 **같은 문장**이다(`catalog.rs`: *"`%ALLUSERPROFILES%`
가 없으면 다중 사용자 환경에서 현재 로그온 사용자만…"*). 문서만 읽고 그 자리에
도달했다. 이 실험 기계는 프로필이 하나라 결과가 같았지만, 다중 사용자 기계에서는
이 답이 참조보다 더 많이 치료한다.

## 가이드의 빈칸

**이번 회차가 가리킨 빈칸은 없다.** 앞선 회차들이 드러낸 것(`to: default` 문법,
`collect_extra` 의 존재)은 이미 메워졌고, 이 회차는 그 뒤 처음으로 그 자리들을
정확히 밟았다 — `collect_extra` 의 `ref` 를 **본문 없이 매치되는 규칙**에 걸어
순환을 피한 것이 특히 그렇다.

답안이 `ex01` 을 얼마나 따랐는지는 위 항목 1에 적었다. 덧붙이면 예제에 없는
것도 정확히 썼다 — `collect_extra` 의 `ref` 를 **본문 없이 매치되는 규칙**
(`payload-file`)에 걸어 순환을 피했고, `remediate` 의 `guard: payload` 와
`restore: av_exclusions` 를 제자리에 놓았다. `ex01` 에는 `remediate` 절 자체가
없으므로 이 부분은 `22-remediate-recipes.md` 를 읽고 쓴 것이다.

> 이 기록에 처음 *"연쇄 `capture` 는 가이드에 예시가 없는데 AI 가 써서
> 통과했다"* 고 적었다가 확인하고 지웠다. **틀렸다** — `01-quickstart.md` 와
> `20-detect-recipes.md` 가 문법을 적어 두었고, 주입된 예제 셋이 전부 그 형태를
> 쓴다. `ex01` 의 `script`/`dir` 은 답안과 글자까지 같다. 가르친 것을 그대로
> 썼다는 뜻이지 새로 발견된 것이 아니다.
