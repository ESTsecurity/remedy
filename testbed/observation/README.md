# 관측 — AI가 최소 가이드만 보고 룰을 쓸 수 있는가

설계-09 P4 의 검증 항목이자 **이 프로젝트의 핵심 가설**이다. 분석가가 코어를
건드리지 않고 `plugin.yaml` 하나만 쓰면 된다는 전제 전체가 여기에 걸려 있다.
틀리면 SDK 표면을 다시 설계해야 하므로, 늦게 발견할수록 비싸다.

설계-06 §10 은 이 관측의 목적을 이렇게 적었다 — **"그 관측이 나머지 문서의
목차를 정한다. 우리가 상상한 목차가 아니라."** 그러므로 이것은 합격/불합격
시험이 아니라 **측정**이다. 무엇을 틀리는지가 결과다.

## 왜 절차를 파일로 고정하는가

관측자가 매번 다른 것을 주면 결과를 비교할 수 없다. 특히 이 관측은 P4 에서
한 번, P9 에서 다시 한 번 돌린다(설계-06 §11 — 과광범위 검사 임계값 조정).
**두 결과가 비교 가능해야 조정에 근거가 생긴다.**

## 입력 — 이것만 준다

관측 대상 AI 에게 아래 파일**만** 준다. 저장소의 나머지는 주지 않는다.

```
docs/plugin-guide/00-invariants.md
docs/plugin-guide/01-quickstart.md
docs/plugin-guide/examples/ex01-scheduled-task/README.md
docs/plugin-guide/examples/ex01-scheduled-task/plugin.yaml
docs/plugin-guide/machine/subjects.json
docs/plugin-guide/machine/catalog.json
docs/plugin-guide/machine/ops.json
docs/plugin-guide/machine/plugin.schema.json
```

`ex01` 의 `artifacts.json` 과 `expected-plan.json` 은 **주지 않는다.** 정답
스냅샷을 보면 룰을 그 스냅샷에 맞추게 되고, 그러면 "가이드만 보고 썼는가" 가
아니라 "예시를 베꼈는가" 를 측정하게 된다.

소스 코드·설계 문서·다른 플러그인은 주지 않는다.

## 과제

`task.md` 를 그대로 준다. 위협 시나리오를 산문으로만 기술하고, 필드 이름이나
연산자 이름은 넣지 않는다 — 넣으면 그것을 베끼는지를 재게 된다.

## 채점

세 단계로 나눠 기록한다. 통과/실패가 아니라 **어디서 멈췄는가**가 데이터다.

| 단계 | 무엇을 보는가 |
|---|---|
| 1. 문법 | `remedy plugin lint` 오류 0건 |
| 2. 경고 | 린트 경고 0건 |
| 3. 동작 | `input/scenario-a.json` 에 대고 `evaluate` → 판정 1건, `corpus/clean/*` 에서 0건 |

**3단계가 본체다.** 린트를 통과하는 룰과 실제로 위협을 잡는 룰은 다르고,
정상을 지키는 룰은 또 다르다. AI 는 "탐지되게 만들기" 에 최적화하고
"정상을 지키기" 를 잊는다(설계-06 §7).

기록할 것:

- 몇 번째 시도에서 각 단계를 통과했는가 (린트 오류를 보고 고치는 루프 포함)
- **어떤 오류를 냈는가** — 이것이 나머지 문서의 목차가 된다
- 지어낸 것이 있는가 (없는 필드·연산자·Op)
- 가이드의 어느 문장이 오해를 불렀는가

## 돌리는 법

```powershell
# 1) 입력 묶음을 만든다
.\testbed\observation\Build-Bundle.ps1 -OutDir <경로>

# 2) 새 AI 문맥에 <경로>\bundle\ 의 파일들과 task.md 를 준다
#    **저장소 접근 없이** — 이 관측의 전제가 그것이다

# 3) 결과물을 채점한다
.\testbed\observation\Score.ps1 -Plugin <AI가 쓴 plugin.yaml>
```

## 오염에 대하여

**이 저장소를 만든 AI 로는 이 관측을 할 수 없다.** SDK 를 설계한 문맥이
남아 있으면 가이드가 부족해도 메워서 쓴다. 그 결과는 "가이드가 충분하다" 가
아니라 "이 AI 가 이미 알고 있다" 를 뜻한다.

새 문맥이어야 하고, 저장소 접근이 없어야 한다. 그 조건을 못 지키면 **관측을
했다고 기록하지 않는다** — 오염된 관측은 없는 관측보다 나쁘다. 근거 없이
"AI 가 룰을 쓸 수 있다" 는 결론이 남기 때문이다.
