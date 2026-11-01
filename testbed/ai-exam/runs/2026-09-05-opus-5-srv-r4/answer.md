# 답안 — plugin.yaml

```yaml
# 서비스로 자리잡고 로그온 경로(Winlogon\Userinit)를 덧붙이는 로더.
# 두 지속성이 서로를 되살리므로 둘 다 처리한다.

schema_version: 1
id: svchostcache-service-userinit
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "서비스 + Userinit 로더 제거"
  en: "Service + Userinit loader removal"

# 권한 상한. 여기 밖은 읽을 수도 지울 수도 없다.
#
#  - %PROGRAMDATA%
#      페이로드 폴더 이름의 꼬리가 감염마다 바뀌어 리터럴로 적을 수 없다.
#      부모를 상한으로 두고 실제 범위는 증거에서 파생된 ${svc.dir} 이 좁힌다.
#
#  - Winlogon 키
#      registry_value 는 레지스트리 루트를 scan_roots 에 적어야 모인다.
#      적지 않으면 언제나 0건이고, 그 위에서 도는 룰은 아무것도 맞히지 못한
#      채 초록이 된다. **끝에 `\*` 를 붙이지 않는다** — Userinit 은 이 키의
#      직속 값이고 `\*` 는 직속 하위 키로 펼치는 것이라 이 값을 놓친다.
#
# service · process 는 이 상한과 무관하게 수집된다 (10-manifest.md 의 표).
# 그쪽 경로를 적으면 지울 수 있는 범위만 넓어진다.
scan_roots:
  - "%PROGRAMDATA%"
  - "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

subjects: [service, registry_value, file, process]

detect:
  # ── 뿌리 ──────────────────────────────────────────────────────────
  # 오탐 안전을 떠받치는 것은 이 규칙 하나다. 파생 규칙은 청정 코퍼스가
  # 시험하지 못한다 (40-review-checklist.md 7번).
  #
  # 서비스 이름(SvcHostCache)으로 잡지 않는다 — 관측이 "고정된 것은 자리뿐"
  # 이라고 했다. 이름을 조건에 넣으면 꼬리만 바뀐 변종을 조용히 놓친다.
  #
  # `state` 를 조건에 넣지 않는다 — 수집기가 살아 있는 서비스 관리자에게
  # 묻지 않아 이 필드는 어느 기계에서도 `unknown` 이다. 보고서의 "실행 중"
  # 은 데이터에 없다. `running` 으로 비교하면 술어가 언제나 거짓이 된다.
  - id: svc
    subject: service
    where:
      all:
        # 조사된 정상 벤더 서비스(Acme Update Service)는 수동 시작이었다.
        - { field: start_type, op: equals, value: "auto" }
        # ProgramData 아래 **폴더 안**의 실행 파일.
        # 폴더 한 겹을 조건에 넣는 이유가 둘이다.
        #   1) 관측이 "폴더 하나를 만들고 그 안에 실행 파일을 둔다" 고 했다
        #   2) 그래야 dirname 이 상한(%PROGRAMDATA%) 자체로 풀리지 않는다
        #      — 재귀 삭제 조건 5 (22-remediate-recipes.md)
        # ImagePath 가 따옴표로 묶이거나 인자를 달고 오는 경우도 잡히도록
        # 끝을 `("|\s|$)` 로 열어 둔다.
        - { field: image_path, op: matches,
            value: '(?i)\\ProgramData\\[^\\"]+\\[^\\"]+\.exe("|\s|$)' }
    capture:
      exe: "image_path | first_path"
      dir: "${exe} | dirname"

  # ── 두 번째 지속성 ────────────────────────────────────────────────
  # 서비스 등록과는 다른 자리의 다른 레코드다 — 독립 근거로 쓴다.
  # registry_value 에는 path 가 없어 from 이 통하지 않는다. ${svc.exe} 를
  # where 값에 넣어 이 감염 그룹에 묶는다.
  # hive·key·name 을 equals 로 못박아야 린트가 to: default 대상이 코어의
  # 기본값 카탈로그에 있는지 대조할 수 있다.
  - id: userinit
    subject: registry_value
    where:
      all:
        - { field: hive, op: equals, value: "HKLM" }
        - { field: key,  op: equals, value: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" }
        - { field: name, op: equals, value: "Userinit" }
        - { field: data, op: contains, value: "${svc.exe}" }

  # ── 산출물 ────────────────────────────────────────────────────────
  # 판정에는 쓰지 않는다. 실행 파일은 다시 받으면 그만이고, 되살리는 것은
  # 위의 두 지속성이다 (40-review-checklist.md 2번).
  # 서명 조건을 걸지 않는다 — 신뢰 서명이 붙은 변종이 오면 코어가 삭제를
  # 막고 그 사실을 deferred 로 보고한다. 여기 걸면 guard 까지 함께 죽는다.
  - id: payload
    subject: file
    from: "${svc.dir}"
    where:
      - { field: path, op: equals, value: "${svc.exe}" }

  # 같은 폴더의 나머지(관측: cache.db). **폴더 전체가 검체가 만든 것**이라는
  # 관측이 있으므로 함께 격리한다 — 재귀 삭제가 보류돼도 남지 않고,
  # 검체가 모아 둔 것이면 분석에 넘길 수 있다.
  - id: companion
    subject: file
    from: "${svc.dir}"
    where:
      - { field: path, op: not_equals, value: "${svc.exe}" }

  # 로그온 경로로 뜬 인스턴스. 서비스를 멈춰도 이쪽은 남는다.
  # 판정에는 넣지 않는다.
  - id: payload-process
    subject: process
    where:
      - { field: image_path, op: equals, value: "${svc.exe}" }

# 서로 다른 자리의 두 레코드 — 서비스 등록과 Winlogon 값 — 의 논리곱.
# 둘 다 "되살리는" 지속성이고 둘 다 레지스트리에 있으므로, 다른 백신이
# 바이너리만 잡아간 기계에서도 이 판정은 선다.
# ProgramData 를 가리키는 자동 시작 서비스 하나만으로는 서지 않는다.
verdict:
  require: "svc and userinit"

remediate:
  remove:
    # 서비스. 복구(실패 시 재시작) 설정 해제 · 중지 · 비활성화 · 삭제의
    # 차례는 코어가 정한다 — 플러그인은 Op 을 직접 고르지 않는다.
    - { ref: svc }
    - { ref: payload-process }
    - { ref: payload }
    - { ref: companion }
    # 폴더 전체가 검체의 것이라는 관측이 있을 때만 여는 문이다.
    # guard 는 그 폴더 **안에서** 악성으로 판정된 증거를 가리킨다.
    # 바이너리가 이미 지워진 기계에서는 이 Action 하나만 미뤄지고
    # 나머지 치료는 그대로 수행된다.
    - { path: "${svc.dir}", recursive: true, guard: payload }
  restore:
    # Userinit 은 **지우면 로그인이 완료되지 않는다.** 값 하나로 복원이
    # 완결되는 대상이라 코어의 기본값 카탈로그에 있다
    # (→ "C:\Windows\system32\userinit.exe,").
    # 이 항목을 remove 절에 두면 린트가 아니라 파싱에서 멈춘다.
    - { ref: userinit, to: default }
  verify:
    # 지속성이 둘이다. 하나라도 놓쳤으면 재부팅 뒤 같은 플러그인이 다시
    # 판정한다 — 경로 확인이 아니라 재판정이라 랜덤 이름 변종에도 선다.
    after_reboot: true

submit_hint:
  samples: [payload, companion]
  confidentiality_min: 1
```

## 설명

**판정을 무엇으로 세웠나.** 서비스 등록(`svc`)과 Winlogon 값(`userinit`)의 논리곱이다.
둘은 다른 자리의 다른 레코드이므로 독립 근거이고, 둘 다 **되살리는 지속성**이다.
실행 파일은 판정에서 뺐다 — 다시 받으면 그만이고 남은 쪽이 그것을 다시 부른다.
덕분에 다른 백신이 바이너리만 잡아간 기계에서도 판정이 서고 두 지속성이 모두 처리된다.

**오탐.** `C:\ProgramData` 를 가리키는 자동 시작 서비스만으로는 판정이 서지 않는다.
조사된 `Acme Update Service` 는 수동 시작이라 뿌리 규칙에서 이미 빠지고, 자동 시작인
정상 벤더 서비스가 있더라도 그 실행 파일 경로가 `Winlogon\Userinit` 값 안에 들어 있어야
판정이 선다. 검체 없는 개발자 PC 에서 `svc` 가 몇 건 매치될 수는 있으나 파괴 Action 은 0 이다.

**남는 구멍(의도된 절충).** 누군가 `Userinit` 만 먼저 되돌린 기계는 서비스가 남아도
판정이 서지 않는다. `svc and (userinit or payload)` 로 넓힐 수 있지만, 그러면
*"자동 시작 + ProgramData 하위 폴더 + 그 폴더의 실행 파일"* 만으로 폴더 재귀 삭제가 열린다.
그 조건에 걸릴 정상 제품(사내 에이전트 · 서명 없는 벤더 업데이터)의 이름을 댈 수 있으므로
열지 않았다 (`40-review-checklist.md` 3번).

**두 지속성의 처리 방식이 다르다.** 서비스는 `{ ref: svc }` 하나로 끝난다 — 복구(재시작)
설정 해제 · 중지 · 비활성화 · 삭제의 차례는 코어가 정하고 플러그인은 Op 을 고르지 않는다.
`Userinit` 은 **지우면 로그인이 완료되지 않으므로** `remove` 가 아니라 `restore` 절의
`to: default` 다. 값 하나로 복원이 완결되는 대상이라 코어의 기본값 카탈로그에 들어 있다.

**폴더 재귀 삭제.** 폴더 전체가 검체가 만든 것이라는 관측이 있어 열었다. `image_path`
정규식이 ProgramData 아래 폴더 한 겹을 요구하므로 `dirname` 이 상한 자체로 풀리지
않는다(조건 5). `guard: payload` 가 그 안의 악성 판정을 가리키고, 바이너리가 이미 없는
기계에서는 이 Action 하나만 미뤄진다 — 그래서 개별 파일 `ref` 를 함께 두었다.

**쓰지 않은 것.** `state` 는 조건에 넣지 않았다. 수집기가 살아 있는 서비스 관리자에게 묻지
않아 어느 기계에서도 `unknown` 이고, 보고서의 *"실행 중"* 은 데이터에 없다. 서비스 이름도
쓰지 않았다 — 관측이 *"고정된 것은 자리뿐"* 이라고 했다. 분석가가 준 YARA 룰이 없으므로
본문 판정과 `collect_extra` 도 없다. 검체에 서명이 없으므로 `signed_malware` 는 비워 둔다.

**서명 전에 확인할 것.** `scan_roots` 의 `%PROGRAMDATA%` 는 넓다는 경고가 날 수 있다 —
페이로드 폴더 이름이 감염마다 바뀌어 부모를 적을 수밖에 없다는 것이 그 이유다. 코퍼스는
이것을 재지 못하므로(스냅샷은 이미 수집된 것이다) 실기기 `scan` 을 한 번 돌려 `file` 수집이
상한에 잘리지 않는지, `registry_value` 가 0건이 아닌지 확인해 첨부한다.
