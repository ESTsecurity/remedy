<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# ex02 — 레지스트리 값이 정상 프로그램 실행을 가로챈다

**이 예제가 가르치는 것**: 레지스트리를 다루는 규칙과, **제거까지 선언하는**
매니페스트의 모양. `ex01` 은 탐지에서 끝난다.

IFEO(Image File Execution Options)의 `Debugger` 값에 경로를 넣으면 Windows 는
그 프로그램을 실행할 때 **대신 그 경로를 띄운다.** 파일을 건드리지 않고
`taskmgr.exe` 실행을 가로채는 고전적인 기법이다.

## 파일

| 파일 | 무엇 |
|---|---|
| `plugin.yaml` | 룰 |
| `artifacts.json` | 입력 스냅샷 — 감염 하나 + 걸리면 안 되는 정상 항목 넷 |
| `expected-plan.json` | 기대 계획 |

`cargo test -p remedy-core --test guide` 가 이 셋을 실제로 돌린다.

## 세 가지를 보여 준다

### 1. 레지스트리 값도 `scan_roots` 를 받는다 — 그리고 끝에 `\*` 가 필요하다

```yaml
scan_roots:
  - "HKLM\\SOFTWARE\\…\\Image File Execution Options\\*"  # 이것이 없으면 0건이다
  - "%LOCALAPPDATA%\\Programs"                            # 자식 파일 규칙의 상한
subjects: [registry_value, file]
```

`registry_value` 에는 `path` 필드가 없지만 **상한은 받는다.** 수집기가
`scan_roots` 에서 `HKLM\…` 모양인 것만 골라 훑으므로, 적지 않으면 이 subject 는
언제나 0건이고 룰은 아무것도 못 맞힌 채 초록이 된다.

끝의 `\*` 가 필요한 이유는 따로 있다. **값 수집은 재귀하지 않는다** — 적은 키의
직속 값만 읽는다. 그런데 IFEO 는 하이재킹당한 실행 파일 이름마다 하위 키를
하나씩 두고 `Debugger` 는 그 **안**에 있다. 그 이름은 미리 알 수 없으므로
`\*` 로 펼친다 (`10-manifest.md` §`scan_roots`).

> **2026-09-02 까지 이 절이 정반대를 적고 있었다** — *"레지스트리 키를
> `scan_roots` 에 적어도 아무 효과가 없다"*. 그래서 이 예제는 실기기에서
> `registry_value` 를 한 건도 모으지 못했고, 번들 `artifacts.json` 이 그 루트
> 없이 레코드를 담고 있어 시험은 계속 초록이었다. **미리 수집된 스냅샷으로
> 도는 시험은 "그 스냅샷을 뜰 수 있는가" 를 재지 못한다.**

### 2. 레지스트리 값에서도 경로를 뽑는다

```yaml
    capture:
      hook: "data | first_path"
      dir: "${hook} | dirname"
```

`ex01` 이 예약 작업의 `args` 에서 뽑은 것과 같은 방식이다. **capture 는 필드
이름만 다를 뿐 어느 subject 에서나 같게 동작한다.**

### 3. 유발자가 먼저다

```yaml
remediate:
  remove:
    - { ref: ifeo }       # registry.delete_value — 재생성을 일으키는 설정
    - { ref: payload }    # file.quarantine_only
```

**순서를 적지 않는다.** 계획기가 유발자(`registry.delete_value`)를 산출물보다
먼저 놓는다. 파일만 지우면 값이 남아 다음 실행에서 오류가 나거나 재감염된다.

`Debugger` 값은 **기본이 "없음"** 이므로 되돌림이 아니라 삭제다. 값 하나로
복원이 완결되는 대상만 `restore_default` 를 쓴다(`machine/REFERENCE.md`).

## 스냅샷에 무엇이 들어 있는가

| 항목 | 걸리나 | 왜 |
|---|---|---|
| `taskmgr.exe\Debugger` → `…\svc-9f2c\hook.exe` | **걸린다** | 세 조건을 전부 만족 |
| `chrome.exe\DisableExceptionChainValidation` | 안 걸린다 | 같은 IFEO 아래지만 `name` 이 다르다 |
| `myapp.exe\Debugger` → `C:\Program Files\Debugging Tools\windbg.exe` | 안 걸린다 | **정상 디버깅 도구다.** 경로 조건이 가른다 |
| `…\editor\editor.exe` | 안 걸린다 | 부모가 가리킨 폴더 밖 — `from` 이 걸러 낸다 |
| `…\svc-9f2c\config.dat` | 안 걸린다 | 같은 폴더지만 `.exe` 가 아니다 |

**세 번째가 이 예제의 핵심이다.** `Debugger` 값이 있다는 사실만으로 판정하면
디버깅 도구를 쓰는 개발자 기계가 곧바로 오탐이 된다. 정상과 악성을 가르는 것은
**값이 어디를 가리키는가**다.

## 왜 폴더를 통째로 지우지 않는가

`ex01` 과 달리 여기에는 `dir.delete_recursive` 가 없다. 이 시나리오에서는 그
폴더가 검체가 만든 것이라는 **관측 근거가 없기 때문**이다. 근거 없이 재귀 삭제를
열면 정상 프로그램 폴더가 통째로 사라질 수 있다 (`22-remediate-recipes.md`
§재귀 삭제).
