<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# ex01 — 예약 작업이 랜덤 폴더의 스크립트를 실행한다

**이 예제가 가르치는 것**: 감염마다 폴더 이름이 바뀌는 대상을 어떻게 잡는가.
리터럴 경로를 적을 수 없으므로 부모 증거에서 경로를 **뽑아내고**(`capture`),
자식 규칙이 그 경로 **안에서만** 찾는다(`from`). 판정은 그 둘의 논리곱이다.

## 파일

| 파일 | 무엇 |
|---|---|
| `plugin.yaml` | 룰 |
| `artifacts.json` | 입력 스냅샷 — 감염 하나 + 걸리면 안 되는 정상 항목 셋 |
| `expected-plan.json` | 기대 계획 |

`cargo test -p remedy-core --test guide` 가 이 셋을 실제로 돌린다.
**예제는 문서가 아니라 테스트다** — 스키마가 바뀌면 예제가 먼저 깨진다.

## 스냅샷에 무엇이 들어 있는가

걸려야 하는 것 하나:

- `\Microsoft\Windows\ExampleUpdate` — `node.exe` 가 `app-7f3a\main.js` 를 실행

**걸리면 안 되는 것 셋.** 정상 항목이 없는 스냅샷으로는 룰이 무엇을 걸러내는지
알 수 없다.

| 항목 | 왜 안 걸리는가 |
|---|---|
| `\Microsoft\Windows\UpdateOrchestrator\Reboot` | 명령이 `node.exe` 가 아니다 |
| `\DevTools\watch-build` | **정상 Node 개발 환경.** 등록 폴더가 `\Microsoft\Windows\` 밑이 아니다 |
| `\Microsoft\Windows\.NET Framework\NGEN v4.0.30319` | `ComHandler` 라 실행할 명령 자체가 없다 |

`\DevTools\watch-build` 가 이 예제에서 가장 중요하다. **정상 Node 개발 환경이
첫 번째 오탐 후보다** — 같은 `node.exe` 가 같은 폴더 아래 `main.js` 를 돌린다.
등록 폴더 조건 하나가 그 둘을 가른다.

`my-tool\main.js` 도 스냅샷에 있지만 증거가 되지 않는다. `from: "${task.dir}"`
가 자식 탐색을 부모가 가리킨 디렉터리로 좁히기 때문이다. **`from` 이 없으면
무관한 `main.js` 하나가 판정을 완성시킨다.**

## 기대 결과

- 증거 2건 — `task#0` · `payload#0`
- 증거 그룹 1개 — `g0`, `verdict: true`
- capture — `task.script` · `task.dir` 이 실제 경로로 해소됨
- **Action 0건**

Action 이 비어 있는 것은 룰이 부족해서가 아니다. **지금 코어의 표면에 파괴
동작이 하나도 없다.** 격리와 복원이 첫 파괴보다 먼저 들어오기 때문이며,
그 순서 자체가 안전장치다. Op 가 들어오면 이 파일의 `actions` 가 채워지고,
그때 예제가 먼저 깨져서 문서를 고치지 않을 수 없게 된다.

## 예제 고유 값

아래는 **이 예제의 값**이다. 대상 위협에 맞게 교체한다.

- `id: example-scheduled-task`
- `%LOCALAPPDATA%\Programs` — 페이로드가 자리잡는 곳
- `\Microsoft\Windows\` — 등록 폴더
- `main.js` — 페이로드 파일명
