```yaml
schema_version: 1
id: desktop-shortcut-ext-hijack
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "바탕화면 바로가기 확장 로드 하이재킹 치료"
  en: "Desktop shortcut extension-load hijack removal"

# 권한 상한 — 여기 밖은 읽지도 지우지도 못한다.
#  · 하이재킹된 바로가기는 사용자 바탕화면에만 있다.
#  · 페이로드는 검체가 만든 %PROGRAMDATA%\WebHelper 아래에만 있다. 관측된
#    그대로 좁게 잡는다. 이렇게 두면 이름이 닮은 정상 폴더
#    %PROGRAMDATA%\WebTools 는 상한 밖이 되어 읽지도 지우지도 못한다(요구 4).
scan_roots:
  - "%USERPROFILE%\\Desktop"
  - "%PROGRAMDATA%\\WebHelper"

# 각 subject 를 제 자리로만 좁힌다(수집 범위 축소). 상한 자체는 scan_roots 다.
subject_roots:
  shortcut: ["%USERPROFILE%\\Desktop"]
  file: ["%PROGRAMDATA%\\WebHelper"]

subjects: [shortcut, file]

detect:
  # ── 근거 1 · 하이재킹된 바로가기 ─────────────────────────────
  # 정상 바로가기(인자 없는 Edge 둘, memo.txt 를 여는 Notepad)는 걸리지 않는다.
  # 가르는 것은 "인자가 있는가"가 아니라 "인자가 무엇을 시키는가"다:
  #   (1) 검체 폴더를 확장으로 강제 로드(--load-extension=...\WebHelper\ext)
  #   (2) 브라우저 보호 기능을 끔(--disable-features=...RendererCodeIntegrity)
  # 둘을 함께 요구하므로, 확장을 개발용으로 로드하는 개발자 바로가기((1)만
  # 있고 (2)가 없다)와도 갈린다.
  - id: hijack
    subject: shortcut
    where:
      all:
        - { field: args, op: matches, value: '(?i)--load-extension=\S*\\WebHelper\\ext' }
        - { field: args, op: matches, value: '(?i)--disable-features=\S*RendererCodeIntegrity' }
    capture:
      # 치료 때 뗄 인자 문자열 전체. 원래 인자가 없던 바로가기라 이 값을 통째로
      # 빼면 인자가 비워지고, 파일과 가리키는 곳(chrome.exe)은 그대로 남는다.
      added_args: "args"

  # ── 근거 2 · 실제로 실리던 페이로드 파일 ─────────────────────
  # 바로가기의 인자 한 줄만으로 판정하지 않는다. 그 인자가 가리키는 폴더에
  # 검체 파일이 실재해야 한다. 이 폴더(\WebHelper\ext)는 검체가 만든 것이므로
  # 그 안의 파일이 곧 근거이자 격리 대상이다(manifest.json · bg.js 둘 다).
  - id: payload
    subject: file
    where:
      - { field: path, op: matches, value: '(?i)\\WebHelper\\ext\\' }

# 서로를 참조하지 않는 두 독립 근거(바로가기 · 파일)의 논리곱. 한 그룹을
# 함께 쓰며, 둘 다 있어야 판정이 선다 — 어느 한쪽만으로는 서지 않는다.
verdict:
  require: "hijack and payload"

remediate:
  # 검체가 "고친" 것 — 바로가기의 덧붙은 인자만 뗀다. 파일도, 가리키는 곳도
  # 남긴다. ref 가 shortcut 증거이므로 계획기가 shortcut.strip_args(제자리
  # 편집 · 되돌림 가능)를 도출한다. value 는 증거에서 파생된 인자 전체다.
  edit:
    - { ref: hijack, op: strip, value: "${hijack.added_args}" }
  # 검체가 "만든" 것 — 실리던 폴더의 파일을 되돌릴 수 있게 치운다. ref 가 file
  # 증거이므로 file.quarantine_only(격리 · 되돌림 가능)가 된다. 폴더를 통째로
  # 지우지는 않는다 — 폴더 전체가 검체의 것이라는 관측이 그 두 파일에 한정된다.
  remove:
    - { ref: payload }
```

## 설명

**두 독립 근거의 AND.** 바로가기(`hijack`)와 파일(`payload`)이라는 서로 다른 subject·레코드를 각각 근거로 세우고 `verdict`에서 `hijack and payload`로 묶었다. 서로를 참조하지 않는 두 규칙이라 한 그룹으로 평가되어 논리곱이 그대로 선다. 어느 한쪽만으로는 판정이 서지 않으므로, 바로가기만 있고 파일이 없거나(또는 그 반대) 하면 치료가 발동하지 않는다.

**인자의 "존재"가 아니라 "내용"으로 가른다.** 정상 바로가기 중에도 인자를 가진 것이 있다(Notepad 가 `memo.txt` 를 연다). 그래서 인자 유무로 나누지 않고, 인자가 (1) 검체 폴더를 확장으로 로드하고 `--load-extension=...\WebHelper\ext` (2) 렌더러 보호를 끄는지 `--disable-features=...RendererCodeIntegrity` 를 둘 다 요구했다. 둘을 함께 봐야 하므로, 확장만 개발용으로 로드하는((1)만 있고 (2)가 없는) 바로가기와도 갈린다. 인자 없는 Edge 둘·Notepad 는 애초에 매치되지 않는다.

**치료 = 검체가 바꾼 부분만 되돌리기.** `edit`는 바로가기의 덧붙은 인자만 뗀다. `ref`가 shortcut 증거이므로 계획기가 `shortcut.strip_args`(제자리 편집·되돌림 가능)를 도출한다. 바로가기 파일도, 그것이 가리키는 `chrome.exe`도 그대로 남고, 원래 인자가 없던 바로가기라 인자만 비워진다. `remove`는 실리던 파일 둘을 `file.quarantine_only`(격리·되돌림 가능)로 치운다. 폴더를 통째로 재귀 삭제하지 않는다 — "폴더 전체가 검체 것"이라는 관측이 그 두 파일에 한정되기 때문이다.

**닮은 이름·설치된 확장은 건드리지 않는다.** `scan_roots`를 관측된 `Desktop`·`WebHelper`로만 좁혀, 이름이 닮은 정상 폴더 `WebTools`(그 안의 `netcheck.exe`)는 권한 상한 밖이 된다(읽지도 지우지도 못함). 또 브라우저에 "설치된" 확장을 찾지 않는다 — 이 위협은 설치가 아니라 바로가기 인자로만 확장을 로드하므로, `browser_extension`을 근거로 쓰면 클린 환경의 정상 확장을 오탐할 뿐이다.

**두 가지 스펙 해석을 밝혀 둔다.** (1) `edit`의 문서 산문은 `env.strip_path`·`registry.strip_value`만 표로 들지만, 권위 있는 `ops.json`에는 `shortcut.strip_args`가 구현 op 로 있고 이것이 유일한 shortcut op·유일한 제자리 편집 수단이다. 따라서 치료는 문서화된 조각을 조합했을 뿐 새 필드나 op 를 만들지 않았다. (2) 8개 capture 함수로는 `--flag=` 접두를 뗀 로드 폴더 경로를 깔끔히 뽑아낼 수 없다(`first_path`도 접두를 못 뗀다). 그래서 폴더를 `from`/보간으로 잇는 대신, 관측된 리터럴 `\WebHelper\ext`를 두 근거가 각각 참조해 같은 폴더로 묶었다.
