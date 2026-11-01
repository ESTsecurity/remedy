# 답안 — `remedy` 플러그인: SvcHostCache 로더 (서비스 + Userinit)

## `plugin.yaml`

```yaml
# SvcHostCache 로더 — 자동 시작 서비스 + Winlogon\Userinit 덧붙임
#
# 관측: <드라이브>:\ProgramData\<임의 이름 폴더>\<실행 파일> 을 가리키는 자동 시작
# 서비스가 있고, 같은 실행 파일이 HKLM\...\Winlogon\Userinit 값 끝에 덧붙어 있다.
# 폴더 이름은 감염마다 바뀌므로 리터럴로 적지 않고 서비스 증거에서 뽑는다.
#
# 오탐 경계: ProgramData 아래를 가리키는 서비스는 정상 벤더(예: Acme Update Service)
# 에도 있다. 그래서 서비스 하나로 판정하지 않는다 — 같은 실행 파일이 Userinit 에
# 덧붙어 있고, 그 파일이 디스크에 실재해야 판정이 선다.

schema_version: 1
id: svchostcache-loader
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "SvcHostCache 로더 제거 — 서비스 + Userinit 지속성"
  en: "SvcHostCache loader removal - service + Userinit persistence"

# 읽기 권한 상한. 파일 규칙에만 걸린다 — service·registry_value·process 는 path 가
# 없어 상한과 무관하게 수집된다. 페이로드 폴더가 %ProgramData% 바로 아래 임의
# 이름이라 이보다 좁힐 수 없다. 린트가 넓다고 경고하면 서명 단계에서 이 이유를 적는다.
scan_roots:
  - "%ProgramData%"

subjects: [service, registry_value, file, process]

detect:
  # ── 부모: 서비스 ───────────────────────────────────────────────
  # 실행 파일이 <드라이브>:\ProgramData\<폴더 하나>\<이름>.exe 인 서비스.
  # 폴더 한 겹을 강제한다 — dirname 이 상한 자체(%ProgramData%)가 되는 모양을
  # 룰 쪽에서 막기 위해서다 (22-remediate-recipes §조건 5).
  # 정상 Windows 서비스는 system32 아래라 걸리지 않는다. 정상 벤더 서비스는 여기
  # 걸릴 수 있으나, 아래 userinit·payload 없이는 판정이 서지 않는다.
  # start_type / state 값의 어휘가 규격에 없어 조건으로 쓰지 않는다 — 틀리면
  # 오류가 아니라 조용한 미매치가 된다.
  - id: svc
    subject: service
    where:
      - { field: image_path, op: matches, value: '(?i)^"?[a-z]:\\ProgramData\\[^\\"]+\\[^\\"]+\.exe("|\s|$)' }
    capture:
      exe: "image_path | first_path"   # 따옴표·인자를 걷어낸 실행 파일 경로
      dir: "${exe} | dirname"          # 검체가 만든 폴더

  # ── 지속성 2: Winlogon\Userinit ────────────────────────────────
  # hive·key·name 은 equals 로 못박는다 — restore `to: default` 카탈로그 대조에 필요.
  # data 는 이 그룹의 실행 파일로 묶는다. 값을 지우지 않고 기본값으로 되돌린다.
  - id: userinit
    subject: registry_value
    where:
      all:
        - { field: hive, op: equals,   value: "HKLM" }
        - { field: key,  op: equals,   value: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" }
        - { field: name, op: equals,   value: "Userinit" }
        - { field: data, op: contains, value: "${svc.exe}" }

  # ── 페이로드: 서비스가 가리키는 실행 파일 ──────────────────────
  # 파일명이 고정이라는 관측이 없으므로 `svc.exe` 를 적지 않고 증거의 경로와 대조한다.
  - id: payload
    subject: file
    from: "${svc.dir}"
    where:
      - { field: path, op: equals, value: "${svc.exe}" }

  # ── 같은 폴더의 나머지 파일 (관측: cache.db) ────────────────────
  # "폴더 전체가 검체가 만든 것" 이라는 관측에 근거한다. 재귀 삭제가 보류(deferred)
  # 되어도 개별 격리로 남지 않게 한다. 판정에는 쓰지 않는다.
  - id: companion
    subject: file
    from: "${svc.dir}"
    where:
      - { field: path, op: not_equals, value: "${svc.exe}" }

  # ── 실행 중인 인스턴스 ─────────────────────────────────────────
  # 그 실행 파일로 뜬 프로세스만 잡는다 (서비스 밖, 로그온 경로로 뜬 것 포함).
  # 판정에는 쓰지 않는다 — 재부팅 뒤 재평가 때 프로세스가 없어도 판정은 서야 한다.
  - id: proc
    subject: process
    where:
      - { field: image_path, op: equals, value: "${svc.exe}" }

# 서로 다른 세 대상(서비스 레코드 · 레지스트리 값 · 디스크의 파일)의 논리곱.
# 서비스만으로는 Acme 같은 정상 벤더 서비스가 걸리고, 그것을 가르는 것이 Userinit 이다.
verdict:
  require: "svc and userinit and payload"

remediate:
  remove:
    # 서비스 — Op 은 플러그인이 고르지 않는다. 코어의 서비스 차례
    # (복구 설정 해제 · 중지 · 비활성화 · 삭제)로 도출된다. 중지만으로 끝나지 않는다.
    - { ref: svc }
    # 실행 중인 인스턴스
    - { ref: proc }
    # 파일 — 격리(file.quarantine_only, low, 되돌릴 수 있음). 재귀 삭제와 겹쳐 둔다.
    - { ref: payload }
    - { ref: companion }
    # 폴더 통째 — 증거에서 파생된 경로. guard 는 그 안에서 악성 판정된 파일.
    - { path: "${svc.dir}", recursive: true, guard: payload }
  restore:
    # Userinit 은 지우면 로그인이 안 된다. OS 기본값(C:\Windows\system32\userinit.exe,)
    # 으로 되돌린다. remove 절이 아니라 restore 절이다.
    - { ref: userinit, to: default }
  verify:
    # 두 지속성 중 하나라도 남으면 되살아난다 — 재부팅 뒤 같은 플러그인으로 재판정한다.
    after_reboot: true

# 아직 소비하는 코드는 없지만(P14) 의도를 남긴다. cache.db 에 수집물이 있을 수 있어 하한 1.
submit_hint:
  samples: [payload, companion]
  confidentiality_min: 1
```

## 설명

**구조.** 부모 `svc`(서비스 레코드)가 실행 파일 경로를 `capture` 로 뽑고, 나머지 규칙은 전부 그 값에 묶인다 — `payload`·`companion` 은 `from: ${svc.dir}`, `userinit`·`proc` 은 `path` 가 없는 subject 라 `where` 값 보간(`${svc.exe}`)으로 묶었다. 감염이 둘이면 그룹도 둘이고 서로 섞이지 않는다.

**판정.** `svc and userinit and payload` — 서비스 레코드 · 레지스트리 값 · 디스크의 파일, 서로 다른 세 대상의 논리곱이다. 서비스가 `ProgramData` 를 가리킨다는 사실만으로는 판정하지 않는다.

**오탐 검토 (검체 없는 PC 에서 무엇을 매치하는가).**
- 정상 Windows 서비스는 전부 `system32` 아래 → `svc` 부터 안 걸린다. 기본 `Userinit` 값에는 `ProgramData` 경로가 없다.
- **Acme Update Service** (`C:\ProgramData\Acme\updater.exe`) → `svc` 와 `payload` 는 걸리지만 `Userinit` 에 그 경로가 없어 `userinit` 이 서지 않는다 → 판정 없음 → Action 0 건. 검토 항목 2 에 댈 이름은 바로 이것(그리고 같은 모양의 벤더 업데이트 서비스)이다.
- 정상 Node.js 개발 환경에는 여기 걸릴 서비스·Userinit 항목이 없다. 지우는 대상은 전부 `${svc.exe}`·`${svc.dir}` 에서 파생되고, 리터럴 경로는 하나도 없다. 정상 서명된 `userinit.exe` 는 대상이 아니다 — 값을 기본값으로 되돌릴 뿐이다.

**두 지속성.**
- 서비스는 `{ ref: svc }` 하나로 선언한다. Op 을 플러그인이 고르는 문법은 없고, 계획기가 subject 별 정해진 차례(`service.clear_recovery` · `stop` · `disable` · `delete`, 전부 P8 이라 지금 있다)로 도출한다. 그래서 복구 설정 때문에 "중지만" 으로 끝나는 일이 없다.
- `Userinit` 은 `remove` 가 아니라 `restore: { ref: userinit, to: default }` 다. 지우면 로그인이 안 되고, 이 값은 `restore_default` 카탈로그에 있다(`C:\Windows\system32\userinit.exe,`). 카탈로그 대조를 위해 `hive`·`key`·`name` 을 `equals` 로 못박았다.
- `verify.after_reboot: true` — 둘 중 하나가 남으면 되살아나므로 재부팅 뒤 같은 플러그인으로 재판정한다.

**페이로드.** 폴더 전체가 검체가 만든 것이라는 관측이 있어 재귀 삭제를 쓰되, 덜 위험한 개별 격리(`payload`·`companion`)를 함께 둔다 — 재귀 삭제가 조건 3·4·5 로 보류돼도 파일이 남지 않는다. 정규식이 `ProgramData` 아래 **폴더 한 겹**을 강제하므로 `dirname` 이 상한 자체가 되는 모양은 룰 단계에서 막힌다. 실행 파일에 서명이 없으니 신뢰 서명 차단에 걸리지 않고, `signed_malware` 는 비워 둔다.

**쓰지 않은 것 · 확인이 필요한 것.**
- `start_type: 자동`, `state: 실행 중` 은 관측에 있지만 **그 필드의 값 어휘가 규격에 없어** 조건으로 쓰지 않았다. 추측해 넣으면 틀렸을 때 오류가 아니라 조용한 미매치가 된다. 판정은 `Userinit` 결합이 가르므로 없어도 오탐이 늘지 않는다.
- `Userinit` 의 덧붙인 꼬리만 떼는 부분 편집(`registry.strip_value`)이 Op 카탈로그에는 있으나 플러그인이 그것을 요청하는 문법은 문서에 없다. 그래서 문서가 정한 `to: default` 를 쓴다 — 다른 정상 프로그램이 `Userinit` 에 덧붙인 것이 있었다면 함께 초기화된다는 점은 검토 시 확인한다.
- `scan_roots: ["%ProgramData%"]` 는 랜덤 폴더가 그 바로 아래라 더 좁힐 수 없다. 린트가 넓다고 경고하면 이 이유를 서명 단계에서 적는다. 반대로 이 환경변수가 수집기에서 확장되는지는 코퍼스가 재지 못하므로 **실기기 `scan` 한 번**으로 확인한다(안 되면 같은 폴더를 가리키는 `%ALLUSERSPROFILE%`).
- `proc`·`companion` 은 제거 대상일 뿐 판정에 넣지 않았다. 프로세스는 재부팅 뒤 없을 수 있고, 나머지 파일은 판정 근거가 아니다.
