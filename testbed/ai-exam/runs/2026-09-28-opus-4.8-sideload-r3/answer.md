```yaml
schema_version: 1
id: acmesync-sideload-drop
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "AcmeSync 폴더에 끼어든 사이드로드 페이로드 제거"
  en: "AcmeSync folder sideload payload removal"

# 읽기·삭제 권한 상한. 정상 제품 폴더 하나로 좁힌다 — 좁을수록 좋다.
# autorun 은 이 상한과 무관하게 수집되므로(10-manifest.md 의 표) 여기 적지 않는다.
scan_roots:
  - "%PROGRAMDATA%\\AcmeSync"

subjects: [file, autorun]

detect:
  # ── 자(ruler) ── 제품의 주 실행 파일. 끼어든 파일을 재는 기준이다.
  # 절대 시각·바이트 수를 리터럴로 적지 않는다 — 기계마다 다르므로 증거에서 뽑는다.
  # 이 규칙은 remove 에 넣지 않는다(자를 치우면 제품이 실행되지 않는다).
  - id: baseline
    subject: file
    where:
      - { field: path, op: ends_with, value: "\\AcmeSync.exe" }
    capture:
      when: "mtime"           # 설치 시각(제품이 놓인 시점)
      bulk: "size"            # 주 실행 파일 크기
      dir:  "path | dirname"  # 그 폴더 — 자식 규칙과 autorun 을 여기 묶는다

  # ── 끼어든 파일 ── 같은 폴더에서 주 실행 파일보다 늦게 놓였고 + 작은 것.
  # 시각만 보면 갱신된 core.dll 이, 크기만 보면 설치 때부터 있던 ui.dll 이 걸린다.
  # 둘을 함께 보아야 검체 둘(netcache.dll · svcstub.exe)만 남는다.
  - id: intruder
    subject: file
    from: "${baseline.dir}"
    where:
      - { field: mtime, op: gt, value: "${baseline.when}" }   # 설치보다 뒤에 놓임
      - { field: size,  op: lt, value: "${baseline.bulk}" }   # 주 실행 파일보다 작음

  # ── 유발자 ── 그 폴더의 무언가를 로그온마다 실행하는 자동시작 항목.
  # 폴더 경로(증거에서 파생)로 묶으므로 정상 자동시작 항목 열여섯은 걸리지 않는다.
  # (제품 자신은 로그온 항목을 쓰지 않으므로 이 폴더를 가리키는 것은 검체뿐이다.)
  - id: autostart
    subject: autorun
    where:
      - { field: command, op: contains, value: "${baseline.dir}" }

# 독립적인 두 근거의 논리곱 — 파일 성질(intruder)과 자동시작 항목(autostart)은
# 서로 다른 subject 다. 근거 하나만으로는 판정이 서지 않는다.
verdict:
  require: "intruder and autostart"

remediate:
  remove:
    # 순서는 코어가 정한다. autorun.remove 는 유발자라 산출물보다 먼저 처리된다 —
    # 남으면 로그온마다 다시 돈다.
    - { ref: autostart }   # autorun.remove — 되돌릴 수 있음
    # 끼어든 파일 둘을 격리 컨테이너로 옮긴다. 오탐이어도 restore 로 되돌릴 수 있다.
    - { ref: intruder }    # file.quarantine_only — 되돌릴 수 있음
    # baseline(주 실행 파일) · core.dll · ui.dll 은 어디에도 넣지 않는다 → 그대로 남는다.
  verify:
    after_reboot: true     # 재부팅 뒤 재판정으로 재발 여부를 확인한다
```

## 어떻게 동작하는가

**두 성질을 함께 본다.** `baseline` 규칙이 제품의 주 실행 파일(`AcmeSync.exe`)을 자로 삼아 그 **시각·크기·폴더**를 증거에서 뽑는다. `intruder` 규칙은 같은 폴더에서 주 실행 파일보다 **늦게 놓였고(`mtime gt`) + 작은(`size lt`)** 것만 고른다.

- `core.dll` — 늦게 놓였지만 주 실행 파일보다 **크다** → `size lt` 에서 빠진다.
- `ui.dll` — 작지만 주 실행 파일과 **같은 시각**이다 → `mtime gt`(초과) 에서 빠진다.
- `netcache.dll` · `svcstub.exe` — 둘 다 늦고 둘 다 작다 → 남는다.

성질 하나만 보면 정상 파일이 걸린다는 것이 이 문제의 핵심이고, 그래서 두 조건을 논리곱으로 건다.

**기준을 기계에서 얻는다.** 절대 시각·바이트 수를 리터럴로 적지 않고 `${baseline.when}` · `${baseline.bulk}` 로 뽑는다. 다른 기계에서는 그 기계의 `AcmeSync.exe` 를 다시 재므로 설치 시각·크기가 달라도 동작한다.

**독립적인 두 근거의 논리곱.** `verdict: intruder and autostart` — 파일 성질(`intruder`)과 로그온 자동시작 항목(`autostart`)이라는 **서로 다른 subject** 의 근거다. 파일 성질 하나만으로는 판정이 서지 않는다.

**정상은 건드리지 않는다.**

- `AcmeSync.exe`(자) · `core.dll` · `ui.dll` 은 어디에도 넣지 않으므로 그대로 남는다 — 자를 치우면 제품이 실행되지 않는다.
- 나머지 자동시작 항목 열여섯은 `command` 가 이 폴더를 가리키지 않아 `autostart` 에 걸리지 않는다(제품 자신은 로그온 항목을 쓰지 않으므로 이 폴더를 가리키는 것은 검체뿐이다).
- `scan_roots` 를 `%PROGRAMDATA%\AcmeSync` 하나로 좁혀 두었다. AcmeSync 가 없는 기계에서는 `baseline` 이 아예 서지 않아 `intruder`·`autostart` 가 해소되지 않고, 청정 AcmeSync 설치본에는 늦고 작은 파일도, 이 폴더를 가리키는 자동시작 항목도 없다 — 어느 쪽이든 판정이 서지 않으므로 파괴가 나오지 않는다.

**제거는 전부 증거에서 나오고 되돌릴 수 있다.** `ref: autostart`(`autorun.remove`, 유발자라 코어가 산출물보다 먼저 처리) · `ref: intruder`(`file.quarantine_only`, 격리 컨테이너). 리터럴 경로·평판 조회·재귀 삭제는 쓰지 않는다.

**만들지 않은 것.** 붙인 문서에 없는 필드·연산자·`subject`·`Op` 는 쓰지 않았다. 내용 판정(YARA)이 필요 없는 위협이라 `collect_extra` 도 두지 않았다.
