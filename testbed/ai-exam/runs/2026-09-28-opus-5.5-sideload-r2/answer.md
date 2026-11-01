```yaml
schema_version: 1
id: acmesync-sideload-drop
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "AcmeSync 폴더 끼워넣기 위협 제거"
  en: "AcmeSync folder drop threat removal"

# 권한 상한 — 관측한 제품 폴더 하나. 폴더 이름은 랜덤이 아니라 제품의 고정
# 이름이므로 부모(%PROGRAMDATA%)로 넓히지 않고 관측한 대로 적는다.
# 로그온 항목(autorun)은 이 상한과 무관하게 수집된다 — Run 키를 적지 않는다.
scan_roots:
  - "%PROGRAMDATA%\\AcmeSync"

subjects: [autorun, file]

detect:
  # ── 자 ─────────────────────────────────────────────────────
  # 제품의 주 실행 파일. 설치 시각과 크기를 **이 기계에서** 읽는다 —
  # 절대 시각·바이트 수는 기계마다 달라 적지 않는다.
  # 악성 근거가 아니므로 verdict 에 넣지 않고, 치우면 제품이 못 뜨므로 remove 에도 없다.
  - id: base
    subject: file
    where:
      - { field: path, op: ends_with, value: '\AcmeSync\AcmeSync.exe' }
    capture:
      ref_mtime: "mtime"
      ref_size: "size"
      dir: "path | dirname"

  # ── 근거 1 — 다시 뜨게 하는 자리 ──────────────────────────────
  # 제품은 로그온 항목을 쓰지 않는다. 그 폴더를 가리키는 로그온 항목은 제품의 것이 아니다.
  # autorun 에는 path 가 없어 from 이 통하지 않으므로 값 보간으로 그 폴더 하나에 묶는다.
  # 끝의 `\` 는 이름이 AcmeSync 로 시작하는 이웃 폴더를 배제한다.
  - id: logon
    subject: autorun
    where:
      - { field: command, op: contains, value: '${base.dir}\' }

  # ── 근거 2 — 끼어든 파일 ──────────────────────────────────────
  # 두 성질을 **같은 레코드에** 건다.
  #   mtime 만 보면 core.dll(정상 갱신)이, size 만 보면 ui.dll(설치 때부터)이 걸린다.
  #   두 규칙으로 나눠 verdict 에서 and 로 묶어도 안 된다 — "뒤에 놓인 것이 있고
  #   작은 것이 있다" 가 되어 core.dll·ui.dll 이 함께 제거 대상에 든다.
  # gt·lt 는 엄격 비교라 자 자신은 걸리지 않는다.
  - id: dropped
    subject: file
    from: "${base.dir}"
    where:
      - { field: mtime, op: gt, value: "${base.ref_mtime}" }
      - { field: size,  op: lt, value: "${base.ref_size}" }

# 서로 다른 대상(로그온 항목 · 파일)에서 온 두 근거의 논리곱.
# dropped 는 두 파일 중 어느 하나만 남아도 선다.
verdict:
  require: "logon and dropped"

remediate:
  remove:
    - { ref: logon }      # autorun.remove — 유발자라 코어가 파일보다 먼저 수행한다
    - { ref: dropped }    # file.quarantine_only — 격리, 되돌릴 수 있다
    # 재귀 삭제는 두지 않는다 — 폴더와 나머지 파일은 정상 제품의 것이다.
  verify:
    after_reboot: true    # 재부팅 뒤 같은 룰로 재판정 — 로그온 자리가 되살아나는지 본다

submit_hint:
  samples: [dropped]
  confidentiality_min: 1
```

**핵심은 `dropped` 한 규칙이다.** 시각(`mtime gt`)과 크기(`size lt`)를 같은 레코드에 걸어야 검체 둘만 남는다. 두 규칙으로 나눠 `verdict` 에서 `and` 로 묶으면 "뒤에 놓인 파일" 과 "작은 파일" 이 따로 있기만 해도 판정이 서고, 두 규칙을 다 `remove` 에 넣어야 하므로 `core.dll`·`ui.dll` 까지 격리된다. 기준값은 그 기계의 `AcmeSync.exe` 에서 capture 하므로 설치 시각·모듈 크기가 다른 기계에서도 그대로 돈다. 비교가 엄격해 자 자신은 걸리지 않고, `base` 는 `remove` 에 없다.

**판정은 서로 다른 대상의 두 근거다** — 로그온 항목(`autorun`)과 폴더 안의 파일(`file`). `autorun` 에는 `path` 가 없어 `from` 대신 `${base.dir}\` 보간으로 그 폴더 하나에 묶었다. `dropped` 는 두 파일 중 하나만 남아도 서므로, 다른 백신이 한쪽만 가져간 기계에서도 로그온 항목까지 치워진다. `base` 는 근거가 아니라 자라서 판정에 넣지 않았다.

**제거는 `ref` 둘뿐이고 리터럴 경로가 없다.** 로그온 항목이 유발자라 먼저 지워지고, 파일은 격리라 되돌릴 수 있다. 폴더는 정상 제품의 것이라 재귀 삭제를 두지 않았다. 재부팅 뒤 재판정(`verify`)으로 로그온 자리가 되살아나는지 본다.

**검체 없는 개발자 PC** 에는 그 폴더가 없어 뿌리 규칙 `base` 가 0건이고, 파생 규칙은 평가조차 되지 않는다 — Action 0. AcmeSync 가 깨끗이 깔린 기계에서도 제품이 로그온 항목을 쓰지 않으므로 `logon` 이 0건이라 판정이 서지 않는다.

**남는 위험.** 청정 코퍼스에 AcmeSync 가 없으면 뿌리 규칙이 마주한 레코드가 0 이라 G1 은 이 룰을 시험하지 못한다 — 오탐 안전은 "제품은 로그온 항목을 쓰지 않는다" 는 관측에 기댄다. 이름을 댈 수 있는 정상 제품은 AcmeSync 자신이다: 감염된 기계에서 제품이 주 실행 파일은 두고 그보다 작은 모듈만 갱신했다면 그 모듈도 격리되고, 사용자가 손으로 넣은 AcmeSync 시작 항목도 함께 빠진다(둘 다 되돌릴 수 있는 Op 이다). 로그온 항목이 띄우는 파일이 `dropped` 가운데 하나인지까지 묶는 문법은 **없다** — `where` 에 부분 문자열 부정이 없고, `dropped` 를 참조하면 그룹이 파일마다 갈라져 `netcache.dll` 쪽 판정이 서지 않는다. 두 파일이 모두 이미 사라진 기계에서는 판정이 서지 않아 로그온 항목이 남는다(가리키는 파일이 없어 그 자체로는 돌지 않는다). 실행 중인 `svcstub.exe` 는 관측에 프로세스 목록이 없고 `process.kill` 은 되돌릴 수 없어 규칙을 두지 않았다.
