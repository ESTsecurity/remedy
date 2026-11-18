<!--
  GitHub Release 본문의 틀 — 배포 워크플로가 태그마다 `bash ci/release-notes.sh <태그>` 로 채워 초안에 올린다.
  여기를 고치면 다음 출시부터 그 꼴이다. 미리 보기: `bash ci/release-notes.sh v<엔진 버전>` (또는 `rules-<룰 버전>`).

  - 한 줄짜리 {{CHANGES}} · {{SUMMARY}} · {{TABLE}} 은 덩어리를 넣는 자리다 — 바뀐 내용은 docs/업데이트-내역.md 의 그 버전
    칸, 묶음과 표는 README 의 위협 표와 룰 매니페스트(kind · remediate · network)에서 짓는다. 그 밖의 {{…}} 는 값이다.
  - 릴리스 본문은 줄바꿈을 그대로 그린다 — 한 문단 · 한 항목을 한 줄에 적는다. 항목 아래 두 칸 들여 쓴 줄은 그 항목 안의
    줄바꿈이다.
  - 말투는 해요체다(2026-11-18 · rules-2026.11.18.2 의 본문을 팀원이 다듬은 꼴). 이 안내 덩어리는 본문에 들어가지 않는다.
-->
## 1. 내려받아서 실행하기

이 페이지 맨 아래 **Assets** 에서 쓰는 운영체제에 맞는 파일 하나만 내려받으세요. 파일 하나에 프로그램(`{{ENGINE}}`)과 그 운영체제용 룰(`{{RULES}}`)이 모두 들어 있어요.

| 운영체제 | 내려받을 파일 | 실행 방법 |
| :--- | :--- | :--- |
| **Windows** 10 · 11 · Server 2016 이상 (64비트) | `remedy-windows-x64.zip` | *모두 압축 풀기* 로 푼 뒤 `remedy.exe` 를 더블클릭하세요. 관리자 권한 없이 열리면 첫 화면의 **1. 관리자 권한으로 다시 열기** 를 고르세요 |
| **Linux** x86_64 (RHEL 계열 · Debian · Ubuntu · Alpine) | `remedy-linux-x64.tar.gz` | `tar -xzf remedy-linux-x64.tar.gz && cd remedy-linux-x64` 로 푼 뒤 `sudo ./remedy` 로 실행하세요 |

* **무엇을 고를지 모르겠다면 1. 빠른 검사** 를 고르세요. 치료할 것이 나오면 같은 화면의 **찾은 것 모두 치료하기** 로 한 번에 치료해요. 디스크 전체까지 보려면 **2. 정밀 검사** 를 고르세요(오래 걸릴 수 있어요).
* **더블클릭했을 때 파란 *Windows의 PC 보호* 창이 뜨면** Windows SmartScreen 이에요. 이 페이지에서 받은 파일이 맞다면(아래 4.) *추가 정보* → *실행* 을 누르세요.
* **PC · 서버마다 그 기계의 로컬 디스크에 풀어서 실행하세요**(예: `C:\remedy` · `/root/remedy`). 격리한 파일과 치료 기록이 그 폴더의 `state` 에 남아요 — 치료한 뒤 그 폴더를 지우면 되돌릴 수 없어요.
* **인터넷이 끊긴 폐쇄망에서도 그대로 써요.** 검사 · 치료 프로그램에는 네트워크 기능이 없고, 입력한 서버 주소를 네트워크로 점검하는 *원격 점검* 은 함께 든 `remedy-net` 이 맡아요. 네트워크를 아예 쓰지 않으려면 압축을 푼 폴더에서 `remedy-net` 폴더를 지우면 돼요 — 원격 점검과, 메뉴 밖에서 직접 실행하는 이미지 파일 · 컨테이너 점검이 빠지고 검사 · 치료는 그대로예요.
* 쓰는 법은 압축을 푼 폴더의 `README.txt` 에도 있어요 — 인터넷이 없는 곳에서도 볼 수 있어요. 처음 쓰신다면 [저장소 첫 화면의 안내]({{REPO_URL}})도 읽어 보세요.
* 맨 아래 *Source code* 두 개와 *Release attestation* 파일(`.json`)은 개발 · 검증용이라 내려받지 않으셔도 돼요.

---

## 2. 이번에 바뀐 내용 {{SINCE}}

{{CHANGES}}

버전마다 바뀐 내용 전부는 [업데이트 내역]({{HISTORY_URL}})에 있어요.

---

## 3. 점검하고 치료할 수 있는 항목 ({{COUNT}}가지)

{{SUMMARY}}

<details>
<summary><b>운영체제별 룰 버전과 참고 링크 보기</b></summary>

{{TABLE}}

</details>

---

## 4. 내려받은 파일이 맞는지 확인하기 (권장)

내려받은 파일이 중간에 바뀌거나 손상되지 않았는지 확인할 수 있어요. 맨 아래 **Assets** 에서 `SHA256SUMS` 도 내려받아 같은 폴더에 두고, 그 폴더에서 아래 명령을 실행하세요(PowerShell 은 먼저 `cd $HOME\Downloads` 처럼 그 폴더로 이동하세요).

<details>
<summary><b>확인하는 명령 보기 (SHA-256)</b></summary>

* **Linux**
  ```bash
  grep linux SHA256SUMS | sha256sum -c
  ```
  `remedy-linux-x64.tar.gz: OK` 가 나오면 정상이에요(한국어 환경에서는 `성공`).
* **Windows** (PowerShell)
  ```powershell
  (Get-FileHash remedy-windows-x64.zip).Hash -eq (Select-String windows SHA256SUMS).Line.Split(' ')[0]
  ```
  `True` 가 나오면 정상이에요.

`FAILED`(한국어 환경에서는 `실패`)나 `False` 가 나오면 실행하지 말고 지운 뒤 다시 내려받으세요.

</details>
