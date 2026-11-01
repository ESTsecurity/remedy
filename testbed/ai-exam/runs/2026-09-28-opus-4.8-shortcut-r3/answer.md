# 바로가기 인자 하이재킹 — 탐지·치료 플러그인

관측 보고를 두 개의 **독립된 근거**로 나눠 잡았다. 하나는 하이재킹된 바로가기(덧붙은 인자의 서명), 다른 하나는 그 인자가 실으려는 폴더 안의 페이로드 파일. 둘의 논리곱으로만 판정하고, 치료는 바로가기의 인자만 떼고 파일 둘만 되돌릴 수 있게 격리한다.

```yaml
schema_version: 1
id: shortcut-loadext-hijack
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "바로가기 인자 하이재킹 — 강제 확장 로드 제거"
  en: "Shortcut argument hijack — forced extension load removal"

# ── 권한 상한 (읽고 지울 수 있는 범위) ──────────────────────────
# 두 자리만 연다:
#   1) 바탕화면 — 하이재킹된 .lnk 가 있는 곳. shortcut 은 scan_roots 로 좁혀진다.
#   2) 실리던 확장 폴더 — 관측된 그대로. 페이로드 두 파일이 있는 곳.
#
# 확장 폴더 경로(...\WebHelper\ext)는 바로가기 인자
# `--load-extension=<경로>` 안에 **공백 없이 붙어** 있다. capture 로는 뽑을 수
# 없다 — first_path 는 첫 공백 토큰을 통째로 집으므로 `--load-extension=C:\...\ext`
# 가 나오고, 줄 중간의 경로는 못 뽑는다(machine/catalog.json 의 capture 함수).
# 없는 capture 함수를 지어내지 않는다. 대신 관측된 폴더를 상한으로 적어 파일
# 근거를 그 폴더 안에 가둔다 — 관측한 폴더를 적는 것이 가장 좁은 선택이다
# (10-manifest.md §이름을 미리 알 수 없는 경로 조각).
# 이름이 닮은 WebTools 는 이 상한 밖이라 결코 수집되지 않는다.
scan_roots:
  - "%USERPROFILE%\\Desktop"
  - "%PROGRAMDATA%\\WebHelper\\ext"

# 파일 근거를 실리던 폴더로만 가둔다. 없으면 file 수집기가 바탕화면까지 훑어
# 바탕화면에 우연히 있는 manifest.json·bg.js 가 근거로 붙을 수 있다.
subject_roots:
  file: ["%PROGRAMDATA%\\WebHelper\\ext"]

subjects: [shortcut, file]

detect:
  # ── 근거 1: 하이재킹된 바로가기 ────────────────────────────────
  # 가리키는 곳(chrome.exe)은 건드리지 않는다 — 덧붙은 인자만 본다.
  # **인자의 유무로 가르지 않는다.** 정상 Notepad.lnk 에도 인자가 있다.
  # 갈라지는 지점은 인자가 **무엇을 가리키는가**다.
  - id: hijack
    subject: shortcut
    where:
      all:
        # 실리는 확장이 ProgramData 아래를 가리킨다. 개발자가 자기 프로필의
        # 확장을 부르는 정상 --load-extension 과 갈라진다.
        - { field: args, op: matches,  value: '(?i)--load-extension=[a-z]:\\programdata\\' }
        # 렌더러 코드 무결성 보호를 끈다 — 정상 바로가기에 거의 없는 조합이다.
        - { field: args, op: contains, value: "--disable-features=RendererCodeIntegrity" }

  # ── 근거 2: 실리던 폴더의 페이로드 파일 ────────────────────────
  # subject_roots 로 이미 그 폴더 안에 갇혀 있다. 관측된 두 파일을 짚는다.
  # **설치된 확장 목록(browser_extension)은 보지 않는다** — 이 검체는 확장을
  # 설치하지 않고, 바로가기가 열릴 때만 이 폴더를 확장으로 싣는다.
  - id: payload
    subject: file
    where:
      any:
        - { field: path, op: ends_with, value: "\\manifest.json" }
        - { field: path, op: ends_with, value: "\\bg.js" }

# 독립적인 두 근거(바로가기 / 파일)의 논리곱. 하나뿐이면 그 룰의 오탐이 곧바로
# 치료가 된다. 점수 임계값 문법은 없다.
verdict:
  require: "hijack and payload"

remediate:
  remove:
    # 바로가기: ref → shortcut.strip_args. **인자만 뗀다** — 파일도 가리키는
    # 곳도 남는다. 원래 인자가 없었으므로 치료 뒤 인자는 비워진다.
    - { ref: hijack }
    # 페이로드: ref → file.quarantine_only. 되돌릴 수 있게 격리한다.
    # 폴더째 재귀 삭제하지 않는다 — 요구 사항은 "파일 둘" 이고, 폴더 전체가
    # 검체의 것이라는 별도 관측 근거로 재귀 삭제를 열지 않는다(ex03 와 같은 판단).
    - { ref: payload }

# 손으로 분석에 올릴 때 볼 힌트. 자동 전송 기능은 제품에 없다.
submit_hint:
  samples: [payload]        # bg.js 가 확장의 실제 코드다
  confidentiality_min: 1    # 고객 PC 검체 — 경로에 사용자 계정명이 들 수 있다
```

## 설명

**요구 사항 대응.** (1) `remediate.remove` 의 `{ref: hijack}` 는 subject 가 shortcut 이라 `shortcut.strip_args` 로 풀린다 — 인자만 떼고 `.lnk` 파일과 가리키는 chrome.exe 는 남긴다. 이 바로가기엔 원래 인자가 없었으므로 치료 뒤 인자는 비워진다. (2) `{ref: payload}` 는 subject 가 file 이라 `file.quarantine_only` (위험 low·복원 가능)로 풀려 두 파일을 되돌릴 수 있게 격리한다. (3) 정상 Edge·Microsoft Edge·Notepad 바로가기는 `hijack` 조건을 못 맞춘다 — Notepad 는 인자가 있지만 `--load-extension=` 도 `RendererCodeIntegrity` 끄기도 없다. (4) 이름이 닮은 `WebTools\netcheck.exe` 는 `scan_roots` 상한(`WebHelper\ext`) 밖이라 애초에 수집 대상이 아니다.

**바로가기를 인자 유무로 가르지 않았다.** 갈라지는 지점은 인자가 **무엇을 가리키는가**다 — 실리는 확장이 ProgramData 아래이면서(정상 개발용 `--load-extension` 은 보통 사용자 프로필을 가리킨다) 동시에 브라우저 보호 기능을 끄는 조합. 두 조건은 같은 객체(바로가기)의 args 필드를 보므로 **근거 하나**이고, 그래서 폴더의 파일을 두 번째 독립 근거로 세워 논리곱했다.

**스스로 확인한 것.** ① *검체 없는 개발자 PC 에서 무엇을 매치하나?* — 아무것도. 개발자가 자기 확장을 부르는 바로가기는 ProgramData 도 아니고 RendererCodeIntegrity 를 끄지도 않아 `hijack` 이 안 맞고, `WebHelper\ext` 폴더 자체가 없어 `payload` 도 안 맞는다. 판정은 둘 다 필요하다. ② *판정이 근거 하나에 기대나?* — 아니다. 바로가기(레지스트리가 아닌 바탕화면의 .lnk)와 파일(그 폴더 안)은 서로 다른 대상에서 나온 독립 근거이고, 둘 다 `from` 으로 엮이지 않은 독립 루트라 코퍼스에서 각각 검증된다. ③ *지우는 대상이 전부 증거에서 나왔나?* — 그렇다. `remove` 는 전부 `ref` 로, 매치된 증거만 가리킨다. 리터럴 경로를 직접 지우지 않는다.

**한계 두 가지를 밝혀 둔다.** 첫째, 확장 폴더 이름이 다른 변종(예: `WebHelper` 대신 다른 이름)은 놓친다. 폴더 경로가 `--load-extension=` 에 공백 없이 붙어 있어 지금의 capture 함수(first_path·dirname 등 여덟 개)로는 그 조각을 뽑아 `from` 으로 잇지 못한다 — 없는 함수를 지어내지 않고, 대신 관측된 폴더를 상한으로 못 박았다. 이름이 바뀌는 변종까지 잡으려면 인자 중간의 경로를 뽑는 새 capture 함수가 필요하다. 둘째, 범위는 `%USERPROFILE%\Desktop` 의 바로가기다. 공용 바탕화면·다른 사용자 계정·시작 메뉴의 같은 바로가기는 관측되지 않아 상한에 넣지 않았다 — 그런 자리가 관측되면 `scan_roots` 에 해당 루트를 더해 다시 좁게 잡는다.
