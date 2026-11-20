<!--
  GitHub Release 본문의 틀 — 배포 워크플로가 태그마다 `bash ci/release-notes.sh <태그>` 로 채워 초안에 올린다.
  여기를 고치면 다음 출시부터 그 꼴이다. 미리 보기: `bash ci/release-notes.sh v<엔진 버전>` (또는 `rules-<룰 버전>`).

  - 한 줄짜리 {{CHANGES}} · {{SUMMARY}} · {{TABLE}} 은 덩어리를 넣는 자리다 — 바뀐 내용은 docs/업데이트-내역.md 의 그 버전
    칸, 묶음과 표는 README 의 위협 표와 룰 매니페스트(kind · remediate · network)에서 짓는다. 그 밖의 {{…}} 는 값이다.
  - 릴리스 본문은 줄바꿈을 그대로 그린다 — 한 문단 · 한 항목을 한 줄에 적는다. 항목 아래 두 칸 들여 쓴 줄은 그 항목 안의
    줄바꿈이다.
  - 말투는 합쇼체다 — 단계 안내는 '…합니다', 경고 · 금지만 '…하십시오'(2026-11-20 · 이슈 #120 의 개선안 — 2026-11-18 ~
    룰 2026.11.20.2 의 본문은 해요체였다). 2. 의 칸은 위협마다 ### 소제목으로 나뉜다(칸의 꼴은 docs/업데이트-내역.md 머리).
  - 1. 의 빠른 검사 · 정밀 검사 문단은 한 OS 의 꾸러미에 디스크 전체를 보는 룰(scan_roots 가 %FIXED_DISKS% · 지금은
    log4j-check)과 그 밖의 로컬 룰이 함께 들 때의 화면이다(crates/remedy-cli/src/guided.rs · 받은 폴더의 README.txt 는
    xtask/src/package.rs 가 같은 조건으로 가른다). log4j-check 를 빼거나 그 scan_roots 를 바꾸면 이 문단을 고친다.
  - 이 안내 덩어리는 본문에 들어가지 않는다.
-->
## 1. 실행

**Assets** 에서 운영체제에 맞는 파일 다운로드를 진행합니다.

| 운영체제 | 파일명 | 실행 방법 |
| :--- | :--- | :--- |
| **Windows** 10 · 11 · Server 2016 이상 (64비트) | `remedy-windows-x64.zip` | *압축 풀기* 로 푼 뒤 `remedy.exe` 를 우클릭하여 관리자 권한으로 실행합니다. 관리자 권한 없이 실행되면 첫 화면의 **1. 관리자 권한으로 다시 열기** 를 선택하여 관리자 권한으로 실행합니다. |
| **Linux** x86_64 (RHEL 계열 · Debian · Ubuntu · Alpine) | `remedy-linux-x64.tar.gz` | `tar -xzf remedy-linux-x64.tar.gz && cd remedy-linux-x64` 로 푼 뒤 `sudo ./remedy` 로 실행합니다. |

* **1. 빠른 검사** 는 디스크 전체를 보는 항목과 원격 점검을 뺀 모든 항목을 검사하고, 치료할 수 있는 위협이 나오면 **찾은 것 모두 치료하기** 로 한 번에 치료합니다(취약한 버전 · 설정은 바꾸지 않고 할 일을 안내합니다). 디스크 전체를 대상으로 검사하려면 **2. 정밀 검사** 를 선택합니다(오래 걸릴 수 있습니다).
* **실행했을 때 *Windows의 PC 보호* 창이 뜨면** Windows SmartScreen 에서 차단한 것입니다. 현재 페이지에서 받은 파일이 맞다면(아래 4.) *추가 정보* → *실행* 을 클릭합니다.
* **검사 PC · 서버 로컬 디스크에 압축을 풀어서 실행합니다**(예: `C:\remedy` · `/root/remedy`). 격리한 파일과 치료 기록이 압축을 푼 폴더의 `state` 에 저장됩니다. 해당 폴더를 삭제하면 기록과 격리한 파일이 함께 지워져 치료 전으로 복원할 수 없습니다.
* **폐쇄망에서도 그대로 검사합니다.** 검사 · 치료 프로그램에는 네트워크 기능이 없고, 입력한 서버 주소를 네트워크로 점검하는 *원격 점검* 은 `remedy-net` 을 통해 점검 가능합니다. 네트워크 기능을 아예 빼려면 압축을 푼 폴더에서 `remedy-net` 폴더를 지우면 됩니다.
  *원격 점검과, 메뉴 밖에서 실행하는 이미지 파일 · 컨테이너 점검을 제외한 검사 · 치료는 그대로 진행합니다.*
* 사용법은 압축을 푼 폴더의 `README.txt` 에 작성되어 있습니다.
  *처음 사용한다면 [저장소 첫 화면의 안내]({{REPO_URL}})를 확인합니다.*
* *Source code* 와 *Release attestation* 파일(`.json`)은 개발 · 검증용이라 다운로드하지 않아도 실행 가능합니다.

---

## 2. 변경 내용 {{SINCE}}

{{CHANGES}}

버전마다 변경 내용은 [업데이트 내역]({{HISTORY_URL}})에 있습니다.

---

## 3. 점검 및 치료 항목

{{SUMMARY}}

<details>
<summary><b>운영체제별 룰 버전과 참고 링크</b></summary>

{{TABLE}}

</details>

---

## 4. 파일 무결성 검증 (권장)

다운로드한 파일이 중간에 바뀌거나 손상되지 않았는지 다음과 같이 확인할 수 있습니다.

* **Assets** 에서 `SHA256SUMS` 를 다운로드해 같은 폴더에 두고, 그 폴더에서 다음 명령을 실행합니다(PowerShell 에서는 먼저 `cd $HOME\Downloads` 처럼 다운로드한 파일이 있는 폴더로 이동합니다).

<details>
<summary><b>파일 무결성 검증 명령 (SHA-256)</b></summary>

* **Linux**
  ```bash
  grep linux SHA256SUMS | sha256sum -c
  ```
  `remedy-linux-x64.tar.gz: OK` 가 나오면 정상 파일입니다(한국어 환경에서는 `성공`).
* **Windows** (PowerShell)
  ```powershell
  (Get-FileHash remedy-windows-x64.zip).Hash -eq (Select-String windows SHA256SUMS).Line.Split(' ')[0]
  ```
  `True` 가 나오면 정상 파일입니다.

`FAILED`(한국어 환경에서는 `실패`)나 `False` 가 나오면 실행하지 말고 지운 뒤 다시 다운로드하십시오.

</details>
