# 답변 — `plugin.yaml`

```yaml
schema_version: 1
id: svcassist-appinit-implant
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "SvcAssist AppInit 원격 임플란트 제거"
  en: "SvcAssist AppInit remote implant removal"

# 읽기 권한 상한. 폴더 이름은 "관측한 그대로" 적는다 — "변종에서 바뀔 수 있다"는
# 가정이지 관측이 아니므로 부모(%PROGRAMDATA%)로 넓히지 않는다(10-manifest §scan_roots).
# 레지스트리 값도 이 상한을 받는다. AppInit 두 값은 Windows 키의 *직속 값*이라
# 끝의 \* 는 필요 없다(IFEO 처럼 하위 키 안에 있는 값이 아니다).
scan_roots:
  - "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"   # 주입 값 둘
  - "%PROGRAMDATA%\\SvcAssist"                                          # 페이로드 두 파일
  - "%PROGRAMDATA%\\Acme\\Agent"                                        # 정상 에이전트 설정

subjects: [registry_value, file, firewall_rule, structured_config]

detect:
  # 근거 1 (유발자) — AppInit_DLLs 주입.
  # 청정 기계에서 이 값은 "빈 문자열"이다. data 에 경로(역슬래시)가 있으면
  # 검체가 덮어쓴 것이다. 폴더 이름은 리터럴로 적을 수 없어 값에서 뽑는다(ex02 방식).
  - id: appinit
    subject: registry_value
    where:
      all:
        - { field: hive, op: equals,   value: "HKLM" }
        - { field: key,  op: equals,   value: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" }
        - { field: name, op: equals,   value: "AppInit_DLLs" }
        - { field: data, op: contains, value: "\\" }
    capture:
      dll: "data | first_path"
      dir: "${dll} | dirname"

  # AppInit 스위치 — LoadAppInit_DLLs.
  # 청정 기계에 0 으로 "이미 있는" 값이고 검체가 1 로 켰다. remove 로 지우면
  # 완전 치료로 보고되지만 감염 전(0)으로 돌아가지 않는다(30-antipatterns §14).
  # 되돌림은 아래 remediate.restore 의 to: default 로 한다.
  - id: appinit_flag
    subject: registry_value
    where:
      all:
        - { field: hive, op: equals, value: "HKLM" }
        - { field: key,  op: equals, value: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" }
        - { field: name, op: equals, value: "LoadAppInit_DLLs" }
        - { field: data, op: equals, value: "1" }

  # 근거 2 (독립) — 페이로드 폴더를 가리키는 "들어옴·허용" 방화벽 규칙.
  # 들어오는 규칙이라는 사실만으로 잡으면 Windows 자신의 svchost 규칙까지 걸린다.
  # application 이 그 폴더를 가리키는 것만 고른다(에이전트의 "나감" 규칙도 제외된다).
  - id: fw
    subject: firewall_rule
    where:
      all:
        - { field: direction,   op: equals,   value: "In" }
        - { field: action,      op: equals,   value: "Allow" }
        - { field: application, op: contains, value: "${appinit.dir}" }
    capture:
      exe: "application"

  # 자식 — AppInit 값이 가리킨 바로 그 DLL. 가리키는 파일이 실재해야 한다.
  - id: payload_dll
    subject: file
    from: "${appinit.dir}"
    where:
      - { field: path, op: equals, value: "${appinit.dll}" }

  # 자식 — 방화벽 규칙이 가리킨 실행 파일. 같은 폴더 안에서만 찾는다.
  - id: payload_exe
    subject: file
    from: "${appinit.dir}"
    where:
      - { field: path, op: equals, value: "${fw.exe}" }

  # 정상 에이전트 설정에 끼워 넣은 항목.
  # "loader 가 있다"가 아니라 "그 값이 페이로드 폴더를 가리킨다"로 가른다(ex03 핵심).
  # modules.remote 한 키만 짚으므로 나머지 세 항목은 건드리지 않는다.
  - id: agent_hook
    subject: structured_config
    where:
      all:
        - { field: path,     op: ends_with, value: "\\Acme\\Agent\\agent-config.json" }
        - { field: format,   op: equals,    value: "json" }
        - { field: key_path, op: equals,    value: "modules.remote" }
        - { field: value,    op: contains,  value: "${appinit.dir}" }

# 독립적인 근거의 논리곱 — 레지스트리 주입(유발자) · 가리킨 DLL 실재 · 같은 폴더를
# 여는 방화벽 규칙. 근거 하나의 오탐이 곧바로 삭제가 되지 않는다. 점수 임계값은 없다.
verdict:
  require: "appinit and payload_dll and fw"

remediate:
  # 설정 항목 하나와 페이로드 둘.
  # structured_config 는 그 키만(remove_key), file 은 격리된다(quarantine_only).
  remove:
    - { ref: agent_hook }    # structured_config.remove_key — modules.remote 만, 파일·다른 키는 남는다
    - { ref: payload_dll }   # file.quarantine_only
    - { ref: payload_exe }   # file.quarantine_only

  # 청정 기계에 "이미 있던" 값은 지우지 않고 기본값으로 되돌린다.
  # AppInit_DLLs → 빈 값, LoadAppInit_DLLs → 0 (둘 다 restore_default 카탈로그에 있다).
  # 방화벽 규칙은 검체가 연 것이라 되돌리면 사라진다(firewall.restore_rule).
  restore:
    - { ref: appinit,      to: default }
    - { ref: appinit_flag, to: default }
    - firewall

  # 랜덤 이름으로 재감염하는지 보려면 경로 확인이 아니라 재판정이 필요하다.
  verify:
    after_reboot: true

# 분석에 유용한 검체(격리된 두 파일). 자동 제출은 없고 support-bundle 에만 표시된다.
# 고객 PC 에서 나온 것이므로 기밀 하한을 올려 둔다.
submit_hint:
  samples: [payload_dll, payload_exe]
  confidentiality_min: 1
```


## 설명

**무엇을 잡는가.** 모든 프로세스에 DLL 을 주입하는 AppInit 임플란트다. 판정은 서로 독립적인 근거의 논리곱으로 세웠다(`verdict: appinit and payload_dll and fw`):

- `appinit` — `HKLM\...\Windows\AppInit_DLLs` 에 경로가 채워짐(유발자). 청정 기계에서는 빈 문자열이므로 `data contains "\"`(경로가 있는가)로 가른다.
- `payload_dll` — 그 값이 가리킨 바로 그 DLL 이 실재함. 폴더 이름은 리터럴로 적지 않고 값에서 뽑아(`data | first_path | dirname`) 그 안에서만 찾는다(ex02 방식).
- `fw` — 같은 폴더의 실행 파일을 여는 "들어옴·허용" 방화벽 규칙. 레지스트리와 방화벽은 서로 다른 수집원이라 독립 근거가 된다.

레지스트리 주입 하나만으로는 판정하지 않고(가리키는 파일이 실재해야 함), 세 근거가 모두 같은 페이로드 폴더를 가리킬 때만 선다. 검체 없는 PC 에는 AppInit 주입이 없어 판정이 서지 않는다.

**핵심 — 두 AppInit 값은 지우지 않고 되돌린다.** `AppInit_DLLs`(기본 빈 값)와 `LoadAppInit_DLLs`(기본 `0`)는 **청정 Windows 에 이미 있는 값**이다. 검체는 이를 *만든* 것이 아니라 *덮어썼다*. `remove`(= `registry.delete_value`)로 지우면 "완전 치료"로 보고되지만 감염 전 상태로 돌아가지 않는다(30-antipatterns §14). 두 값 다 `restore_default` 카탈로그에 있으므로 `remediate.restore` 에서 `{ to: default }` 로 되돌린다 → 각각 빈 값과 `0`. 둘 중 하나만 처리하면(경로만 또는 스위치만) 재감염 경로가 남으므로 둘 다 되돌린다.

**나머지 치료.**
- 방화벽 규칙은 검체가 연 것이라 `restore: [firewall]` 로 되돌리면 사라진다(`firewall.restore_rule`).
- 에이전트 설정은 `remove: { ref: agent_hook }` → `structured_config.remove_key` 로 `modules.remote` **한 키만** 뺀다(파일·나머지 세 항목은 남는다).
- 페이로드 두 파일은 `remove` → `file.quarantine_only` 로 격리(되돌릴 수 있음).
- 순서는 적지 않는다 — 코어가 유발자(레지스트리·설정)를 산출물보다 먼저 처리한다. `verify.after_reboot: true` 로 재부팅 후 재판정해 재감염을 본다.

**오탐을 어떻게 피했는가.**
- 주입 값이 사는 키에는 원래 값 17개(`Spooler`·`IconServiceLib` 등)가 함께 있다 → 값 이름 두 개를 `equals` 로만 짚고, 키 삭제(`registry.delete_key`)는 쓰지 않는다. 17개는 그대로 남는다.
- 설정 파일의 다른 세 항목(`modules.inventory`·`endpoint`·`intervalSeconds`)은 정상 에이전트 제품의 것 → `key_path equals "modules.remote"` 로 그 한 항목만, 파일은 보존.
- 정상 방화벽 규칙(Windows `svchost.exe` 의 들어옴, 에이전트의 나감)은 `application` 이 페이로드 폴더를 가리키는 것만 고르므로 제외된다.
- 로그온 구성(`Winlogon\Userinit`·`Shell`)은 관측상 정상값 그대로라 **손대지 않는다**.
- 폴더 통째 삭제(`dir.delete_recursive`)는 쓰지 않는다 — 폴더 전체가 검체의 것이라는 관측 근거가 없고, 확인된 파일 둘만 격리한다.

**`scan_roots`.** 레지스트리 값도 상한을 받으므로 Windows 키를 적었다(두 값은 그 키의 직속 값이라 끝의 `\*` 는 불필요). 페이로드·설정 폴더는 관측된 그대로 좁게 적었다 — "변종에서 바뀐다"는 가정으로 `%PROGRAMDATA%` 까지 넓히지 않는다. 방화벽은 `scan_roots` 와 무관하게 수집된다.

**붙인 문서에 없는 필드·연산자·subject·Op 는 쓰지 않았다.** 필요하지만 없는 것도 없었다.
