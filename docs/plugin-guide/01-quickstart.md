<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# 퀵스타트 — 동작하는 플러그인 하나

선행: `00-invariants.md`

## 지금 쓸 수 있는 것

**이 파일에 전수 목록을 적지 않는다.** 손으로 적은 목록은 코드와 어긋나고, 어긋난
목록을 읽은 AI 는 없는 필드를 쓴 룰을 만든다. 여기 표가 하나 있었고 실제로 낡았다
— `subject` 가 둘, `Op` 이 없다고 적혀 있었다.

| 무엇을 알고 싶은가 | 어디를 본다 |
|---|---|
| subject 와 그 필드 전수 | `machine/subjects.json` |
| Op 전수 + 되돌림·위험 등급 | `machine/ops.json` · `machine/catalog.json` |
| 연산자·capture 함수 전수 | `machine/catalog.json` |
| 사람이 읽는 요약 | `machine/REFERENCE.md` |

전부 `remedy-sdk` 에서 생성되고 CI 가 재생성 diff 로 강제한다 — **SDK 를 고치고
문서를 안 고치면 머지되지 않는다.**

아직 오지 않은 것을 쓰면 린트가 거부하며 **어느 Phase 에서 쓸 수 있는지** 알려
준다. 기다리면 되는 것과 영원히 안 되는 것은 다르고, 그 구분이 오류 메시지에 있다.

## 최소 플러그인

예약 작업이 특정 폴더의 스크립트를 실행하고, 그 폴더에 페이로드가 있는 형태를 잡는다.

```yaml
schema_version: 1
id: example-task              # 예제 고유 값 — 대상 위협에 맞게 교체
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "예제 위협 제거"
  en: "Example threat removal"

# 권한 상한. 여기 밖은 읽을 수도 지울 수도 없다.
scan_roots:
  - "%LOCALAPPDATA%\\Programs"            # 예제 고유 값 — 페이로드 위치에 맞게 교체
  # 예약 작업 경로는 적지 않는다 — `persistence` 는 이 상한과 무관하게
  # 수집된다 (10-manifest.md 의 표).

subjects: [persistence, file]

detect:
  # 부모 — 인스턴스 하나마다 독립된 증거 그룹이 생긴다.
  - id: task
    subject: persistence
    where:
      all:
        - { field: win.task.register_path, op: starts_with, value: "\\Microsoft\\Windows\\" }
        - { field: command,                op: matches,     value: "(?i)\\\\node\\.exe$" }
    capture:
      # 폴더 이름이 감염마다 바뀌므로 리터럴로 적을 수 없다. 증거에서 뽑는다.
      script: "args | first_path"
      dir: "${script} | dirname"

  # 자식 — 부모가 가리킨 디렉터리 **안에서만** 찾는다.
  - id: payload
    subject: file
    from: "${task.dir}"
    where:
      - { field: path, op: ends_with, value: "\\main.js" }

# 독립적인 두 근거의 논리곱. 룰 하나의 오탐이 곧바로 판정이 되지 않는다.
verdict:
  require: "task and payload"
```

## 확인

```
remedy plugin lint plugin.yaml
```

오류가 없으면 스냅샷에 대고 돌린다. **감염 VM 이 필요 없다** — 수집과 평가가 나뉘어 있어 스냅샷 파일만으로 초 단위 반복이 된다.

```
remedy evaluate --artifacts snapshot.json --plugin plugin.yaml --out scan.json
remedy plan --scan scan.json --out plan.json
```

`scan.json` 에서 볼 것:

- `groups` — 부모 증거 하나마다 그룹 하나. 자식은 **자기 그룹 안에서만** 붙는다
- `verdicts` — 판정을 통과한 그룹. 비어 있으면 `require` 가 성립하지 않은 것이다
- `observation` — 관측이 완전했는가. 불완전하면 "위협 없음" 을 말할 수 없다

동작하는 실물은 `examples/ex01-scheduled-task/` 에 있다. 그 예제는 CI 에서 실행되는 **테스트**이므로 깨진 상태로 남아 있을 수 없다.

## 종료 코드

| 코드 | 뜻 |
|---|---|
| 0 | 위협 없음 |
| 2 | 위협 발견 · 치료 안 함 |
| 4 | 사용법·입력 오류 |
| 5 | 안전 가드에 의한 중단 |
| 6 | **관측 불완전** — '위협 없음' 을 말할 수 없습니다 |
| 7 | 내부 오류 — 도구 자체가 멈췄습니다 (`logs/crash-*.txt` 를 신고에 붙이십시오) |

1(치료 완료) · 3(부분 실패)은 `apply` · `run` 에서 나온다.

## 자주 막히는 곳

**capture 는 선언 순서에 기대지 않는다.** `${script}` 를 쓰는 `dir` 이 위에 있어도 된다. 의존 관계로 풀린다.

**`${이름}` 은 같은 규칙의 capture, `${규칙.이름}` 은 다른 규칙의 capture** 다. 둘을 섞으면 린트가 없는 참조라고 알려 준다.

**`from` 은 증거에서 파생된 경로만 받는다.** 그 경로가 `scan_roots` 밖이면 그 그룹은 **제외**된다 — 경고가 아니라 제외다. 파생 경로는 공격자가 값에 영향을 줄 수 있기 때문이다.

**그룹이 나뉘는 것은 다른 규칙이 참조하는 부모가 두 건 이상 맞을 때뿐이다.**
참조되지 않는 규칙이나 한 건만 맞은 부모는 **한 그룹을 함께 쓴다** — 그래서
서로 참조하지 않는 두 근거의 논리곱이 선다. 대신 그 그룹에서 하나라도 제외되면
**함께 쓰던 다른 갈래의 증거도 사라진다.** `or` 로 갈래를 이어도 한쪽 규칙의
오류를 버티지 못한다. 판정이 안 서면 `scan.json` 의 `groups[].excluded_reason`
부터 본다.

**한글·비ASCII 경로는 NFC 로 정규화되어 비교된다.** 룰에 NFD 로 적어도 맞는다.

**Windows 경로 비교는 대소문자를 무시한다.** `matches` 만 예외이며, 정규식의 대소문자는 `(?i)` 로 직접 정한다.
