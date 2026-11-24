---
section: rules
rules: [winwyvern-1-check]
---
* **WinWyvern 탐지 항목 추가 — CVE-2025-45737** (Windows)\
  정상 AI 도구(Ollama) 배포 페이지로 위장한 사이트로 퍼진 악성코드가 보안 제품을 무력화하려고 심는 취약 드라이버 NeacSafe64(CVE-2025-45737)가 자동으로 시작하는 서비스로 등록돼 있고 그 파일이 `C:\Windows\System32` 바로 아래에 있으면 *위협 발견* 으로 알립니다. 찾기만 하고 아무것도 바꾸지 않습니다.

<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>

* 위협이 발견되면 진단 묶음(`remedy support-bundle`)을 만들어 담당자에게 보내 문의하고, 쓰시는 백신으로 PC 전체를 정밀 검사하고, Windows 보안의 *코어 격리 — 메모리 무결성* 과 *Microsoft 취약 드라이버 차단 목록* 을 켭니다.
* 숨긴 악성 DLL(대체 데이터 스트림)과 메모리에만 올라간 WinWyvern 드라이버는 이 도구가 보지 못합니다. 서비스와 파일 가운데 하나만 남은 PC 는 흔적으로만 적고 *위협 없음* 으로 끝납니다 — *위협 없음* 이 이 PC 가 깨끗하다는 뜻은 아닙니다.
* NeacSafe64 는 NetEase 의 정상 서명된 안티치트 드라이버라, 수동으로 시작하거나 다른 폴더에 있는 NeacSafe64 는 정상 설치일 수 있어 위협으로 보지 않습니다.
* 고르는 화면의 *새로 추가된 항목* 맨 위에 보입니다. 자세한 내용은 https://github.com/ESTsecurity/remedy/blob/main/docs/%EC%9C%84%ED%98%91%EB%B3%84-%EC%95%88%EB%82%B4.md#winwyvern 에 있습니다.

</details>
