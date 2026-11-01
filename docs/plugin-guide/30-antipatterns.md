<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# 거부되는 패턴 — 실물로 본다

선행: `00-invariants.md`

각 항목은 셋으로 적는다 — **거부되는 형태 · 왜 · 올바른 형태.** 설명보다 실물이
강하다.

---

## 1. `collect_extra` 의 `ref` 가 YARA 룰을 가리킨다

**거부되지 않는다. 그래서 더 나쁘다** — 린트도 통과하고 코퍼스 시험도 통과하는데,
실기기에서 **판정이 영원히 서지 않는다.**

```yaml
# 거부되는 형태
detect:
  - id: payload
    subject: file
    from: "${task.payload_dir}"
    where:
      - { yara: "rules/x.yar:some_rule" }      # 본문이 있어야 매치된다

collect_extra:
  - { ref: payload, content: true }            # ← 순환
```

**왜.** `collect_extra` 의 `ref` 형은 **2패스**로 돈다 — 수집 → 1차 평가 → 그
증거로 본문 담기 → 재평가. 그래서 `ref` 가 가리키는 룰은 **본문 없이 매치될 수
있어야 한다.** YARA 하나로만 된 룰을 가리키면 증거가 서려면 본문이 있어야 하고,
본문을 담으려면 증거가 있어야 한다. 1차 평가가 아무것도 못 찾아 담을 것을 정하지
못하고, `blobs` 가 빈 채로 끝난다.

```yaml
# 올바른 형태 — 경로로 매치하는 룰을 따로 두고 그것을 가리킨다
detect:
  - id: payload-file                            # 본문 없이 매치된다
    subject: file
    from: "${task.payload_dir}"
    where:
      - { field: path, op: ends_with, value: ".js" }

  - id: payload                                 # 담긴 본문을 YARA 가 본다
    subject: file
    from: "${task.payload_dir}"
    where:
      - { field: path, op: ends_with, value: ".js" }
      - { yara: "rules/x.yar:some_rule" }

collect_extra:
  - { ref: payload-file, content: true }
```

> **감염 코퍼스는 이 결함을 가린다.** 거기서는 본문이 이미 주입돼 있어 YARA 가
> 바로 매치된다. **실기기에서 `scan` 을 돌려야 드러난다** — 실제로 그렇게
> 드러났다.

---

## 2. 점수 임계값으로 판정한다

```yaml
# 거부되는 형태
detect:
  - { id: a, score: 60, ... }
  - { id: b, score: 30, ... }
verdict:
  threshold: 80        # 그런 키는 없다
```

**왜.** 휴리스틱 하나가 임계값을 넘겼다는 이유로 파일이 삭제되면 안 된다.
`score` 는 **보고·우선순위 표시용**이다.

```yaml
# 올바른 형태
verdict:
  require: "a and b"   # 독립적인 두 근거의 논리곱
```

---

## 3. `remediate` 에서 `reputation` 을 참조한다

```yaml
# 거부되는 형태
remediate:
  remove:
    - { ref: suspicious, when: "reputation.verdict == 'malicious'" }
```

**왜.** 조회 결과는 **삭제를 줄일 수만 있고 늘릴 수 없다** (설계-01 D9). 감염
호스트의 네트워크를 신뢰할 수 없으므로, 응답을 근거로 파괴를 늘리면 공격자가
응답을 조작해 정상 파일을 지우게 만들 수 있다.

```yaml
# 올바른 형태 — 판정은 증거로만 한다
verdict:
  require: "task and payload"
remediate:
  remove:
    - { ref: payload }
```

---

## 4. 리터럴 절대 경로를 제거 대상으로 적는다

```yaml
# 거부되는 형태
remediate:
  remove:
    - { path: "C:\\Users\\Public\\evil", recursive: true, guard: payload }
```

**왜.** 증거 없는 삭제다. 그 경로가 이 기계에서 무엇인지 아무도 확인하지 않았다.

```yaml
# 올바른 형태 — 증거에서 파생된 경로만
remediate:
  remove:
    - { path: "${task.payload_dir}", recursive: true, guard: payload }
```

---

## 5. `guard` 없는 재귀 삭제

```yaml
# 거부되는 형태
remediate:
  remove:
    - { path: "${task.payload_dir}", recursive: true }
```

**왜.** `guard` 는 *"그 디렉터리 **안에서** 악성으로 판정된 파일"* 을 가리킨다.
없으면 capture 해석이 어긋났을 때 폭주한다 — `payload_dir` 이 상위 폴더가 되어도
막을 것이 없다.

```yaml
# 올바른 형태
    - { path: "${task.payload_dir}", recursive: true, guard: payload }
```

> `guard` 가 붙어도 계획기는 **그 증거가 실제로 그 디렉터리 안을 가리키는지**
> 다시 본다. 엉뚱한 곳을 가리키는 guard 는 통과하지 못한다.

---

## 6. 파생 경로가 `scan_roots` 밖으로 나간다

```yaml
# 거부되는 형태
scan_roots:
  - "%LOCALAPPDATA%\\Programs"
detect:
  - id: task
    capture:
      dir: "args | first_path | dirname"      # 값이 어디든 될 수 있다
  - id: payload
    from: "${task.dir}"
```

**왜.** `args` 는 **공격자가 쓰는 값**이다. 파생 경로가 상한을 넘게 만들 수 있다면
그것은 상한이 아니다. 그런 그룹은 경고가 아니라 **제외**된다.

**올바른 형태**는 룰이 아니라 `scan_roots` 다 — 파생 경로가 놓일 수 있는 범위를
`scan_roots` 에 담되, **필요 이상으로 넓히지 않는다.** 넓히면 그만큼 읽기 권한이
넓어진다.

---

## 7. 근거가 하나뿐인 판정

```yaml
# 경고 — 로드는 되지만 서명 단계에서 확인을 요구한다
detect:
  - { id: task, ... }
  - { id: payload, ... }
verdict:
  require: "task"      # payload 를 쓰지 않는다
```

**왜.** 그 룰 하나의 오탐이 곧바로 삭제가 된다.

```yaml
verdict:
  require: "task and payload"
```

---

## 8. 경로 제약 없는 프로세스·파일 매칭

```yaml
# 거부되는 형태
detect:
  - id: proc
    subject: process
    where:
      - { field: image_path, op: matches, value: "node\\.exe" }
```

**왜.** **정상 Node 개발 환경이 첫 번째 오탐 후보다.** 이 조건은 개발자 기계의
모든 Node 프로세스를 잡는다.

```yaml
# 올바른 형태 — 무엇을 실행하는가로 가른다
    where:
      all:
        - { field: image_path, op: matches,  value: "(?i)\\\\node\\.exe$" }
        - { field: args,       op: contains, value: "${task.dir}" }
```

**필드 이름은 subject 마다 다르다.** `process` 에는 `command` 가 없다 —
`image_path` · `cmdline` · `args` 다. 예약 작업(`persistence`)의 `command` 를
그대로 옮겨 적으면 린트가 거절한다. 전수는 `machine/subjects.json` 이다.

> **정상과 악성을 가르는 것은 실행 파일이 아니라 무엇을 실행하는가다.** 위협이
> 정상 `node.exe` 를 그대로 쓰는 경우(LOLBin)에는 서명으로도 가를 수 없다 —
> 그 실행 파일은 실제로 정상이기 때문이다.

---

## 9. `platforms` 없이 `win.*` 필드를 쓴다

```yaml
# 거부되는 형태
platforms: [linux]
detect:
  - where:
      - { field: win.task.register_path, op: starts_with, value: "\\Microsoft\\" }
```

**왜.** 그 플랫폼에 없는 필드다. 평가기는 **없는 필드를 조용한 미매치로 넘기므로**
룰이 아무것도 잡지 못한 채 초록이 된다.

```yaml
platforms: [windows]
```

---

## 10. 위협 설명에 없는 세부를 덧붙인다

```yaml
# 위협 설명이 준 것: "문자열 배열을 만들어 놓고 인덱스로 꺼내 쓴다"
# 거부되지 않지만 좁다
$arr = /var _0x[0-9a-f]{4,6}\s*=\s*\[/
```

**왜.** `_0x` 는 흔한 난독화기 **기본 설정**의 출력 형태일 뿐이다. 설명은
"문자열 배열" 이라고만 했는데 특정 도구의 시그니처로 좁혔다. 옵션 하나만
바뀌어도 변수명이 달라지고, 그때 룰은 **오류 없이 조용히 안 맞는다.**

실측된 사례다 — AI 합격 시험 1 회차가 이렇게 썼고 검체의 변수명은 `F` 였다.

**좁은 룰은 오탐이 아니라 미탐을 낳는다.** 오탐은 청정 코퍼스가 잡지만 미탐은
아무도 안 잡는다. 감염 코퍼스에 그 변종이 없으면 만점으로 통과한다.

> **아는 것보다 많이 쓰지 않는다.** 검체를 손에 쥐고 확인한 것만 조건에 넣고,
> 확인하지 못한 것은 넣지 않는다. 문자열을 도출해야 하는 룰이라면 그것은
> 분석가의 일이다 — 검체 없이 추측해 채우지 말고 받아서 쓴다.

---

## 11. 위협 설명을 검증 없이 그대로 옮긴다

**왜.** 룰 작성자는 검체를 볼 수 없다. 위협 설명이 틀리면 그 오류가 그대로 룰이
되고, 그 룰은 **린트도 청정 코퍼스도 통과한다** — 아무것도 매치하지 않을 뿐이다.

막을 방법은 하나다. **감염 스냅샷에서 판정이 서는지 확인한다.**

```
remedy evaluate --artifacts <감염 스냅샷> --plugin plugin.yaml --out scan.json
```

`verdicts` 가 비어 있으면 룰이 아니라 **전제를 의심한다.** `issues` 도 함께
본다 — *"재지 못했다"* 가 있으면 그것은 미매치가 아니라 미평가다.

---

## 12. `subject_roots` 로 좁혔으니 거기만 지운다고 믿는다

```yaml
scan_roots: ["%PROGRAMDATA%"]
subject_roots:
  file: ["%PROGRAMDATA%\\Acme"]      # 파일은 여기서만 모은다
remediate:
  remove:
    - { ref: payload }                # ← 대상이 ${x.dir} 인 재귀 삭제
```

**왜.** 좁힘은 **수집**의 상한이다. 삭제의 상한은 `scan_roots` 그대로다.

둘로 나뉜다.

| 지우려는 대상 | 상한 |
|---|---|
| 수집된 레코드를 겨눈 Op | **이미 좁혀져 있다** — 그 레코드가 좁힌 자리 밖에서 모일 수 없으므로 |
| capture 값을 겨눈 Op (`dir.delete_recursive`) | **`scan_roots`** — 디렉터리 경로는 어느 subject 의 레코드도 아니다 |

그래서 위 예에서 `${x.dir}` 이 `%PROGRAMDATA%\Other` 를 가리키면 **그 폴더가
통째로 지워진다.** `file` 을 `Acme` 로 좁힌 것과 무관하다.

**어떻게.** 재귀 삭제의 상한은 `scan_roots` 로 판단한다. 좁혔다는 이유로
`scan_roots` 를 넓게 두지 말 것 — 좁힘은 수집 비용을 줄이는 것이지 권한을
줄이는 것이 아니다.

---

## 13. `strip` 값이 조용히 아무것도 지우지 않는다

```yaml
remediate:
  edit:
    - { ref: pathvar, op: strip, value: "${p.dir};" }   # ← 뒤의 `;`
```

**왜.** `env.strip_path` 는 `;` 로 가른 **항목 하나를 통째로** 견준다 — 부분
문자열로 자르면 `C:\a` 를 지우려다 `C:\ab` 까지 잘리기 때문이다. 구분자를 붙인
값은 어느 항목과도 같지 않아 **아무것도 지우지 않고 성공으로 보고된다.**

정답 플러그인이 실제로 그렇게 적혀 있었고, 네 판정을 전부 통과했다. 계획은
`env.strip_path` 를 정상으로 내고 실행이 조용히 넘어간다 — **시험은 계획까지만
잰다** (2026-09-05 실측).

**어떻게.** 항목만 적는다. 지금은 코어가 뒤의 `;` 를 떼어 내고 빈 값을
거부하지만, 조용히 지나가는 모양은 이것 하나가 아니다 —
`22-remediate-recipes.md` 의 "`value` 는 무엇과 견주는가" 를 보고 대상 값의
타입에 맞는 단위로 적을 것.

---

## 14. 지워도 안 깨지니까 `remove` 로 충분하다고 믿는다

```yaml
remediate:
  remove:
    - { ref: loadflag }    # ← LoadAppInit_DLLs. 청정 기계에 0 으로 있는 값이다
```

**왜.** 갈림은 **"지우면 깨지는가" 가 아니라 "검체가 만든 값인가"** 다.
`AppInit_DLLs`·`LoadAppInit_DLLs` 는 청정 Windows 에 각각 빈 문자열과 `0` 으로
**이미 있고**, 검체는 그것을 만든 것이 아니라 덮어썼다.

지워도 기능은 같아서(값이 없으면 Windows 는 AppInit 을 쓰지 않는다) 오래 눈에
띄지 않았고 **AI 응시자 셋이 연달아 같은 선택을 했다.** 그러나 기계는 감염 전
상태로 돌아가지 않고, `apply` 는 **완전 치료(1)라고 보고한다.** 2026-09-05
채점 5(실기기 치료)가 냈다 — 네 판정은 전부 초록이었다.

**어떻게.** 그 자리가 청정 기계에 있는 값인지 먼저 본다. 있으면
`machine/REFERENCE.md` 의 `restore_default` 목록을 보고 `to: default` 를 쓴다.
목록에 없으면 **코어의 빈칸**이지 `remove` 를 쓰라는 뜻이 아니다.

---

## 이 목록에 없는 것

`31-nonexistent.md` 는 **애초에 존재하지 않는 기능**을 다룬다. 여기 있는 것은
문법상 쓸 수 있지만 거부되거나 위험한 형태다.
