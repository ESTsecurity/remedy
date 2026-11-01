<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# ex03 — 설정 파일 한 줄이 악성 라이브러리를 로드한다

**이 예제가 가르치는 것**: 줄 단위 설정을 다루는 규칙과, **Linux 플러그인의
모양**. 정상 앱의 설정 파일에 플러그인 경로 한 줄을 심으면 그 앱이 실행될 때마다
공격자의 코드가 함께 로드된다 — 파일 하나 지운다고 끝나지 않는다.

`ex01`·`ex02` 는 Windows 다. **셋이 전부 Windows 면 그 형태가 사실상의 표준이
된다.**

## 파일

| 파일 | 무엇 |
|---|---|
| `plugin.yaml` | 룰 |
| `artifacts.json` | 입력 스냅샷 — 감염 하나 + 걸리면 안 되는 정상 항목 다섯 |
| `expected-plan.json` | 기대 계획 |

`cargo test -p remedy-core --test guide` 가 이 셋을 실제로 돌린다.

## 세 가지를 보여 준다

### 1. 줄 전체가 아니라 `value` 를 본다

```yaml
      all:
        - { field: path,    op: ends_with, value: "/exampleapp/plugins.conf" }
        - { field: section, op: equals,    value: "plugins" }
        - { field: key,     op: equals,    value: "loader" }
        - { field: value,   op: contains,  value: "/.local/share/" }
```

줄 단위 설정은 수집기가 `section`·`key`·`value` 로 쪼개어 준다. 줄
전체(`line`)를 정규식으로 훑는 것보다 **정확하고, 공백·따옴표 변형에 흔들리지
않는다.**

`value` 가 경로 하나이므로 `first_path` 도 필요 없다.

```yaml
    capture:
      dir: "value | dirname"
```

### 2. Linux 경로와 `%HOME%`

```yaml
platforms: [linux]
scan_roots:
  - "%HOME%/.config"
  - "%HOME%/.local/share"
```

리터럴 홈 경로(`/home/analyst/…`)를 적지 않는다. 사용자 이름은 기계마다 다르고,
**적어 넣으면 그 기계에서만 도는 룰이 된다.**

여러 사용자를 함께 훑어야 하면 `%ALLUSERPROFILES%` 를 쓴다 —
`10-manifest.md` §지정 확장 토큰.

### 3. 줄을 지울 때는 내용까지 확인한다

계획에 나오는 `match` 를 보라.

```json
"op": "text_config.remove_line",
"target": "/home/analyst/.config/exampleapp/plugins.conf",
"match": { "line_no": 7, "line": "loader=/home/analyst/.local/share/libupd-7f3a/loader.so" }
```

**줄 번호만으로 지우지 않는다.** 수집과 실행 사이에 파일이 바뀌면 7번 줄이 다른
내용일 수 있고, 그때 지우면 사용자의 설정을 부순다. 실행기가 내용까지 대조한다 —
플러그인이 요청할 필요 없이 코어가 그렇게 한다.

### 4. 계획의 차례가 **유발자 먼저**다

```
seq 1  text_config.remove_line  plugins.conf 7행
seq 2  file.quarantine_only     libupd-7f3a/loader.so
```

설정 줄이 **유발자**다. 파일만 먼저 지우면 앱이 다음 실행에서 그 경로를 다시
찾고, 공격자가 같은 자리에 다시 떨어뜨리면 그대로 로드된다 (설계-03 §2).

줄을 지울 때 `match` 에 **번호와 내용이 함께** 실린다.

```json
"match": { "line_no": 7, "line": "loader=/home/analyst/.local/share/libupd-7f3a/loader.so" }
```

번호만이면 수집과 실행 사이에 파일이 바뀌었을 때 엉뚱한 줄을 지우고, 내용만이면
같은 줄이 여럿일 때 정해지지 않는다.

> **2026-08-27 이전에는 이 계획이 비어 있었다.** Op 카탈로그의 Linux 축이
> `Some(P12)` 인데 `IMPLEMENTED_THROUGH` 가 P10 이라 둘 다 미룸으로 나갔다.
> P12 가 닫히며 게이트가 오르자 이 예제가 먼저 깨졌고, 그것이 **Linux 실행기가
> 열렸다는 신호**였다.


## 스냅샷에 무엇이 들어 있는가

| 항목 | 걸리나 | 왜 |
|---|---|---|
| `plugins.conf` 7행 `loader=…/.local/share/libupd-7f3a/loader.so` | **걸린다** | 네 조건을 전부 만족 |
| 같은 파일 4행 `loader=/usr/lib/exampleapp/official.so` | 안 걸린다 | **정식 플러그인이다.** `value` 조건이 가른다 |
| 같은 파일 2행 `theme=dark` | 안 걸린다 | `key` 가 다르다 |
| 다른 앱의 `plugins.conf` | 안 걸린다 | `path` 가 다르다 |
| `…/othertool/plug.so` | 안 걸린다 | 부모가 가리킨 폴더 밖 — `from` 이 걸러 낸다 |
| `…/libupd-7f3a/manifest.json` | 안 걸린다 | 같은 폴더지만 `.so` 가 아니다 |

**두 번째가 이 예제의 핵심이다.** `loader` 줄이 있다는 사실만으로 판정하면 그
앱을 쓰는 모든 기계가 오탐이 된다. 정상과 악성을 가르는 것은 **그 값이 어디를
가리키는가**다.

## 왜 폴더를 통째로 지우지 않는가

`ex01` 과 달리 `dir.delete_recursive` 가 없다. `~/.local/share/<앱>` 은 사용자
데이터가 함께 사는 자리이고, 그 폴더 전체가 검체가 만든 것이라는 **관측 근거가
없다** (`22-remediate-recipes.md` §재귀 삭제).
