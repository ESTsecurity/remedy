```yaml
schema_version: 1
id: webshell-upload-aspx
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "업로드 폴더에 놓인 실행형 웹 셸(.aspx) 격리"
  en: "Quarantine of an executable web shell (.aspx) planted in the upload folder"

# scan_roots 는 실기기 scan 의 권한 상한이다 — 여기 밖은 읽지도 지우지도 못한다.
# 업로드 폴더 하나로 좁혀, 웹사이트 자신의 .aspx(상위 폴더의 Default.aspx 와
# App\Handlers\Upload.aspx)와 Web.config 는 실기기에서 애초에 손이 닿지 않게 한다.
# 파일 수집은 이 아래를 재귀로 훑으므로 uploads\2026-09\ 같은 하위 폴더와
# 그보다 더 깊이 들어간 것까지 닿는다.
scan_roots:
  - "C:\\inetpub\\wwwroot\\uploads"

subjects: [file]

detect:
  # 자리와 종류를 함께 본다. 이 논리곱 하나가 검체 둘만 가른다.
  #   자리: 업로드 폴더(하위 폴더 전부) 안일 것 → 웹사이트 자신의 .aspx 는 자리가 다르다.
  #   종류: 실행되는 .aspx 일 것             → 올라온 png·pdf·jpg 는 종류가 다르다.
  # 파일 이름(sess_7f3a9c, .thumb)은 검체마다 바뀌므로 조건에 넣지 않는다.
  # 크기도 넣지 않는다 — 관측된 사실일 뿐 근거가 아니다(크기로 가르면 큰 변종을 놓친다).
  - id: webshell
    subject: file
    where:
      - { field: path, op: starts_with, value: "C:\\inetpub\\wwwroot\\uploads\\" }
      - { field: path, op: ends_with,   value: ".aspx" }

verdict:
  require: "webshell"

remediate:
  # 파일 ref → file.quarantine_only (위험 low · 되돌릴 수 있음).
  # 매치된 .aspx 마다 격리 컨테이너로 옮긴다 — 오탐이어도 remedy restore --run <id> 로 복구.
  # 폴더째(dir.delete_recursive) 지우지 않는다: uploads 에는 사용자 데이터가 함께
  # 살고, 그 폴더 전체가 검체의 것이라는 관측 근거가 없다(ex03 와 같은 판단).
  remove:
    - { ref: webshell }
```

가르는 것은 사실 하나다 — **올린 파일을 담는 자리에 웹 서버가 실행하는 .aspx 가 있다.** 종류만 보면 정상 화면 둘(`Default.aspx`, `App\Handlers\Upload.aspx`)이 걸리고, 자리만 보면 올라온 파일 셋(png·pdf·jpg)이 걸린다. 그래서 `detect` 룰 하나가 자리(`uploads\` 아래, 하위 폴더 전부)와 종류(`.aspx`)를 논리곱으로 묶는다. 이름과 크기는 검체마다 바뀌는 관측값일 뿐 근거가 아니라 넣지 않았고, 이 셸은 파일 말고 아무것도 남기지 않으므로(웹 서버가 대신 실행한다) 자동 실행 자리를 훑지도 않는다.

`scan_roots` 를 `uploads` 하나로 좁힌 것은 성능이 아니라 권한 상한이다. 지켜야 할 파일 여섯(웹사이트 자신의 셋 + 올라온 셋)은 이 상한 밖이거나 종류가 달라, 실기기에서 애초에 손이 닿지 않거나 룰에 걸리지 않는다. 제거는 `file.quarantine_only` 로 매핑돼 매치된 .aspx 를 되돌릴 수 있게 격리 컨테이너로 옮긴다(요구사항 1의 "되돌릴 수 있게"). `uploads` 에는 사용자 데이터가 함께 살고 폴더 전체가 검체의 것이라는 근거가 없어 폴더째 삭제(`dir.delete_recursive`)는 쓰지 않았다.

자가 확인 — (1) 검체 없는 개발자 PC 에서는 `C:\inetpub\wwwroot\uploads` 아래에 무엇도 없으므로 **아무것도 매치하지 않는다.** (2) 판정이 근거 하나에 기대는 것은 의도한 것이다. 갈라지는 사실이 애초에 "자리에 있는 실행형" 하나뿐이라, 근거를 둘로 쪼개면 같은 증거를 말만 바꿔 반복하게 된다. (3) 지우는 대상은 `remove` 가 `ref: webshell` 로만 가리키므로 **전부 확인된 매치에서 나온 것**이고, `${}` 로 만들어 낸 경로나 문서에 박은 절대경로를 직접 지우지 않는다.
