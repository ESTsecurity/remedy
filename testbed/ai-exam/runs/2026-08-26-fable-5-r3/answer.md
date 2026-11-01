# 답 — `remedy` 플러그인: SvcHostCache 위장 서비스 + Winlogon Userinit 로더

## 1. `plugin.yaml`

```yaml
schema_version: 1
id: svchostcache-userinit-loader
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "SvcHostCache 위장 서비스 + Winlogon Userinit 로더 제거"
  en: "SvcHostCache look-alike service + Winlogon Userinit loader removal"

# 읽기·삭제 권한 상한. 페이로드 폴더 이름은 감염마다 바뀌고 고정된 것은
# "ProgramData 아래 폴더 하나" 뿐이므로 그 상위를 상한으로 둔다.
# service / registry_value / process 는 path 가 없어 이 상한과 무관하게 수집된다.
scan_roots:
  - "%ProgramData%"

subjects: [service, registry_value, file, process]

detect:
  # ── 부모: 자동 시작 서비스가 ProgramData 아래 폴더 안의 실행 파일을 가리킨다 ──
  - id: svc
    subject: service
    where:
      all:
        # 관측: 자동 시작. Acme Update Service 는 수동이라 여기서 갈린다.
        - { field: start_type, op: matches, value: '(?i)auto' }
        # 관측: \ProgramData\<폴더>\<파일>.exe — 폴더 한 겹을 강제해야 dirname 이
        # 상한(ProgramData) 자체가 되지 않는다. Windows 자신의 서비스는 system32 다.
        - { field: image_path, op: matches, value: '(?i)\\ProgramData\\[^"]+\\[^\\"]+\.exe("|\s|$)' }
    capture:
      exe: "image_path | first_path"
      dir: "${exe} | dirname"

  # ── 자식 1: Winlogon\Userinit 끝에 그 실행 파일이 덧붙어 있다 ──
  # registry_value 는 path 가 없어 from 이 안 통한다 → where 값 보간으로 부모에 묶는다.
  - id: userinit
    subject: registry_value
    where:
      all:
        - { field: hive, op: equals,   value: "HKLM" }
        - { field: key,  op: equals,   value: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" }
        - { field: name, op: equals,   value: "Userinit" }
        - { field: data, op: contains, value: "${svc.exe}" }

  # ── 자식 2: 서비스가 가리킨 폴더 안의 실행 파일 ──
  - id: payload
    subject: file
    from: "${svc.dir}"
    where:
      - { field: path, op: ends_with, value: ".exe" }

  # ── 자식 3: 그 실행 파일로 떠 있는 프로세스 — 판정 근거가 아니라 종료 대상 ──
  # 서비스 인스턴스 외에 로그온 때 Userinit 이 띄운 인스턴스가 따로 있을 수 있다.
  - id: proc
    subject: process
    where:
      - { field: image_path, op: equals, value: "${svc.exe}" }

# 서로 다른 세 관찰(서비스 DB · 레지스트리 · 파일 시스템)의 논리곱.
# "ProgramData 를 가리키는 서비스" 하나로는 판정하지 않는다.
verdict:
  require: "svc and userinit and payload"

remediate:
  remove:
    # 유발자 1 — 서비스. Op 은 subject 가 정한 차례로 코어가 고른다
    # (카탈로그: service.clear_recovery · stop · disable · delete).
    # "중지만 하면 다시 뜬다" 는 그 차례가 다룬다 — 플러그인이 Op 을 고르는 문법은 없다.
    - { ref: svc }
    # 유발자 2 — Userinit. 지우면 셸이 안 떠 로그인이 안 된다.
    # 기본값(C:\Windows\system32\userinit.exe,)으로 되돌린다 → registry.restore_default.
    - { ref: userinit, to: default }
    # 실행 중인 인스턴스 종료.
    - { ref: proc }
    # 페이로드 격리. 재귀 삭제가 deferred 되어도 이것은 남는다 — 겹침이지 대체가 아니다.
    - { ref: payload }
    # 관측: 폴더 전체가 검체가 만든 것(cache.db 포함). 증거 파생 경로 + guard.
    - { path: "${svc.dir}", recursive: true, guard: payload }
  # 지속성이 둘이라 재부팅 뒤 같은 룰로 다시 판정한다.
  verify:
    after_reboot: true

# 지금은 소비하는 코드가 없다(P14). 의도만 남긴다.
submit_hint:
  samples: [payload]
  confidentiality_min: 1
```

## 2. 설명

**구조 — 부모 하나, 자식 셋.** 서비스(`svc`)가 부모다. `image_path` 에서 실행 파일(`exe`)과 폴더(`dir`)를 `capture` 로 뽑고, 자식은 그 값에만 묶인다. `userinit` 은 `registry_value` 라 `from` 이 안 통하므로 `data contains ${svc.exe}` 보간으로, `payload` 는 `from: ${svc.dir}` 으로, `proc` 은 `image_path equals ${svc.exe}` 로 묶었다. Userinit 을 부모로 삼지 않은 이유: 값이 `userinit.exe,<페이로드>` 꼴이라 `first_path` 는 정상 `userinit.exe` 를 뽑고, 마지막 경로를 뽑는 capture 함수는 카탈로그에 없다.

**판정 — 서로 다른 세 관찰의 논리곱.** `svc and userinit and payload` = 서비스 DB · 레지스트리 · 파일 시스템. 관측 보고가 경고한 "ProgramData 를 가리키는 서비스 하나로 판정" 은 원천 배제된다. `proc` 은 일시적이라 판정에 넣지 않고 종료 대상으로만 쓴다.

**오탐 — 이름을 댄다.**
- *Acme Update Service*: `start_type` 이 수동이라 `svc` 에서 탈락하고, Userinit 을 안 건드리므로 `userinit` 에서 한 번 더 탈락.
- *Windows 자체 서비스*: `system32\svchost.exe` 라 `\ProgramData\` 정규식에 안 걸린다.
- *Node.js 개발 환경*: 서비스도 Userinit 변조도 없어 그룹 자체가 생기지 않는다.
- Winlogon `Userinit` 에 자기 경로를 덧붙이는 정상 제품은 알지 못한다 — 그 조건이 이 룰의 실질적 가름선이다.

**제거 — 유발자 둘 + 산출물.**
1. `{ ref: svc }` — 서비스는 subject 가 정한 차례로 코어가 처리한다. 카탈로그에 `service.clear_recovery` 가 있으므로 "중지만 하면 다시 뜬다" 는 그 차례가 다룬다. 플러그인이 Op 을 고르는 문법은 없다.
2. `{ ref: userinit, to: default }` — 값을 지우면 셸이 안 떠 로그인이 안 되므로 `registry.restore_default` 의 대상(`C:\Windows\system32\userinit.exe,`)으로 되돌린다. `ref` 만 두면 `registry.delete_value` 가 되므로 그렇게 쓰면 안 된다.
3. `{ ref: payload }` + `${svc.dir}` 재귀 삭제(`guard: payload`) — 폴더 전체가 검체가 만든 것이라는 관측이 있어 재귀 삭제를 열되, 조건 3·4·5 로 `deferred` 될 수 있으므로 파일 `ref` 를 함께 둔다. `cache.db` 는 재귀 삭제로 간다. 리터럴 경로는 없다.
4. `verify.after_reboot: true` — 지속성이 둘이라 재부팅 뒤 같은 룰로 재판정한다.

**규격에 없거나 문서만으로 확정 못 한 것 — 만들지 않고 적는다.**
- `to: default` 는 `machine/REFERENCE.md` §restore_default 에 이름만 나오고 전체 형태 예제가 없다. `{ ref: userinit, to: default }` 로 썼고 `plugin lint` 로 확정해야 한다. 거부되면 **`ref` 만 남기지 말 것**(값 삭제 = 로그인 불가) — 그 항목은 빼고 사람에게 넘긴다.
- `service.start_type` 의 값 어휘가 번들에 없다. `auto` / `automatic` / `delayed-auto` 를 모두 받도록 `matches '(?i)auto'` 로 썼다. lint 가 유효값을 주면 그중에서 고친다. `hive` 표기(`HKLM`)도 같다.
- `%ProgramData%` 가 확장되는지는 코퍼스가 재지 못한다(`40-review-checklist.md` §5 — 좁은 쪽은 아무도 경고하지 않는다). 서명 전 실기기 `scan` 으로 확인한다.
- 관측 보고는 "실행 파일에 코드 서명이 없다", 요구 사항은 "정상 서명된 실행 파일을 빌려 쓴다" 로 서로 어긋난다. 룰은 관측 보고를 따랐다. 어느 쪽이든 서명된 파일은 코어의 신뢰 서명 가드가 삭제를 막고 `deferred` 로 보고하며(`signed_malware` 는 비워 둠), 유발자 둘은 그와 무관하게 처리된다. `signature.trusted` 를 판정 조건에 넣지 않은 이유: 넣으면 서명된 변종에서 판정 자체가 죽어 서비스·Userinit 까지 방치된다.

**자가 확인.**
- 검체 없는 개발자 PC: ProgramData 아래 자동 시작 서비스가 있어도 `userinit` 이 서지 않아 판정 0.
- 근거 하나 의존: 아니다 — 세 관찰의 논리곱.
- 삭제 대상: 전부 `ref` 이거나 `${svc.dir}` 파생 + `guard`. 리터럴 절대 경로 없음.
