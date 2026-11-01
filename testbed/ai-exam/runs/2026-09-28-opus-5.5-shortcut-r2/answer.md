```yaml
# 바탕화면 바로가기에 인자 둘을 덧붙여, 정상 브라우저가 열릴 때마다
# %PROGRAMDATA%\WebHelper\ext 를 확장으로 싣고 보호 기능 하나를 끄게 하는 위협.
schema_version: 1
id: shortcut-hijack-webhelper
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "바로가기 인자 하이재킹(WebHelper 확장 강제 로드) 제거"
  en: "Shortcut argument hijack (WebHelper forced extension load) removal"

# 권한 상한 — 관측된 두 자리뿐이다.
scan_roots:
  # 바로가기. %USERPROFILE% 이 아니라 %ALLUSERPROFILES% 인 이유: 실리는 폴더가
  # 기계 공용(ProgramData)이라 어느 사용자의 바로가기든 같은 확장을 싣고, 치료를
  # 다른 관리자 계정으로 돌리면 %USERPROFILE% 은 엉뚱한 프로필이 되어 조용히
  # 0건이 된다. 넓어진 삭제 범위는 아래 lnk 조건을 만족하는 바로가기의
  # shortcut.strip_args(low · 되돌림) 뿐이다.
  - '%ALLUSERPROFILES%\Desktop'
  # 페이로드. 관측된 폴더 그대로 — 이름이 닮은 %PROGRAMDATA%\WebTools 는 상한 밖이다.
  - '%PROGRAMDATA%\WebHelper\ext'

# file 은 페이로드 폴더에서만 모은다. 바탕화면의 .lnk · 사용자 파일이 file 레코드로
# 들어오지 않으므로 파일 규칙이 바로가기를 격리할 길이 없다.
subject_roots:
  file: ['%PROGRAMDATA%\WebHelper\ext']

# browser_extension 은 선언하지 않는다 — 검체는 확장을 설치하지 않았고
# 바로가기로 열릴 때만 싣는다. 설치 목록을 훑어도 아무것도 없다.
subjects: [shortcut, file]

detect:
  # 근거 1 — 인자가 검체 폴더를 확장으로 싣게 하는 바로가기.
  # 인자의 유무가 아니라 load-extension= 의 값이 어디를 가리키는가로 가른다.
  # target 은 보지 않는다 — 가리키는 곳은 정상 브라우저라 갈림점이 아니다.
  # capture 함수로는 load-extension= 뒤의 경로를 뽑을 수 없다(first_path 는 스위치까지
  # 한 토큰으로 낸다). 그래서 from 대신 관측된 고정 폴더 조각으로 파일 규칙과 묶는다.
  # 스위치 접두(--)는 적지 않는다 — 크롬은 Windows 에서 - · / 접두도 받는다.
  # 값의 따옴표 · 쉼표 목록 · 뒤 역슬래시를 허용하고, ext 뒤 경계로 ext2 같은 이름을 막는다.
  - id: lnk
    subject: shortcut
    where:
      - { field: args, op: matches, value: '(?i)load-extension=\S*\\ProgramData\\WebHelper\\ext(\\|"|,|\s|$)' }

  # 근거 2 — 그 폴더의 검체 파일. manifest.json 은 --load-extension 이 싣는 폴더에
  # 반드시 있어야 하는 파일이고, bg.js 는 관측된 본체다.
  - id: extmanifest
    subject: file
    where:
      - { field: path, op: ends_with, value: '\ProgramData\WebHelper\ext\manifest.json' }

  - id: extscript
    subject: file
    where:
      - { field: path, op: ends_with, value: '\ProgramData\WebHelper\ext\bg.js' }

# 서로 다른 대상에서 온 두 근거의 논리곱. 세 규칙은 서로 참조하지 않아 한 그룹을
# 함께 쓴다. 파일 쪽을 or 로 둬서 다른 백신이 한 파일만 잡아간 기계에서도 선다.
verdict:
  require: "lnk and (extmanifest or extscript)"

# 차례는 코어가 정한다.
remediate:
  remove:
    - { ref: lnk }           # shortcut.strip_args — 파일 · 가리키는 곳은 그대로, 인자만 비운다
    - { ref: extmanifest }   # file.quarantine_only — 되돌릴 수 있다
    - { ref: extscript }     # file.quarantine_only
```

**설명**

- **판정** — 바로가기(`lnk`)와 그것이 싣는 폴더의 검체 파일(`extmanifest`·`extscript`), 서로 다른 대상에서 온 두 근거의 논리곱이다. 파일 쪽을 `or` 로 둬 다른 백신이 한 파일만 잡아간 기계에서도 선다. 프로세스·설치된 확장은 보지 않는다.
- **가르는 기준** — 인자의 유무가 아니라 `load-extension=` 값이 가리키는 곳이다. Edge 둘(인자 없음)·Notepad(문서 경로 인자)는 빠지고, `target` 은 정상 브라우저라 조건에 없다. `WebTools` 는 `scan_roots` 밖이고 경로 조건과도 다르다.
- **치료** — `lnk` → `shortcut.strip_args`(파일·가리키는 곳은 남고 인자만 비워진다 — 원래 없었으므로 원상), 파일 둘 → `file.quarantine_only`(되돌림). 재귀 삭제는 두지 않았다 — 요구되지 않았고, 그 폴더가 상한 자체라 조건 5로 계획 전체가 거부된다.
- **문서에 없는 것 — 만들지 않았다** — 바로가기 인자에서 폴더를 뽑는 capture 함수가 없다. `args | first_path` 는 `--load-extension=C:\…\ext` 토큰 전체(스위치 순서가 바뀌면 다른 스위치)를 내고, `=` 뒤를 자르는 함수는 8종에 없다. 그 값으로 `from` 을 걸면 상한 밖이라 그룹이 제외된다. 그래서 관측된 고정 폴더 `\ProgramData\WebHelper\ext` 를 두 근거의 공통 닻으로 쓰고 세 규칙을 서로 참조하지 않는 뿌리로 뒀다 — 한 그룹을 함께 쓰고, G1 이 각각을 직접 잰다(파일을 부모로 뒤집어 `args contains ${…}` 로 묶으면 바로가기 규칙이 파생이 되어 재지 못한다). 폴더 이름이 감염마다 바뀌는 변종은 그 함수 없이는 묶을 수 없다.
- **자기 확인** — 검체 없는 개발자 PC 에서 매치 0: 크롬 확장 개발자의 `--load-extension=<프로젝트>`, Symantec Endpoint Protection 충돌(`STATUS_INVALID_IMAGE_HASH`) 우회로 붙인 `--disable-features=RendererCodeIntegrity` 바로가기는 폴더 조건에서 빠진다. 하나가 맞아도 판정은 둘을 요구하고, 제거 대상은 전부 `ref`(증거)다.
- **남는 한계** — 페이로드가 이미 지워진 기계는 판정이 서지 않아 인자가 남는다(근거 하나로 판정하지 않는 대가). 공용·OneDrive 바탕화면과 시작 메뉴·작업 표시줄은 관측에 없어 상한 밖이다 — 서명 전 실기기 `scan` 으로 확인한다. 바로가기를 고친 주체는 관측에 없어 룰이 없고, 떠 있는 브라우저는 종료하지 않는다(`process.kill` 은 되돌릴 수 없다) — 다시 열면 확장이 실리지 않는다.
