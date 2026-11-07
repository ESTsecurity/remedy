# remedy — ESTsecurity 전용백신

[![CI](https://github.com/ESTsecurity/remedy/actions/workflows/ci.yml/badge.svg)](https://github.com/ESTsecurity/remedy/actions/workflows/ci.yml)
[![최신 버전](https://img.shields.io/github/v/release/ESTsecurity/remedy?label=%EC%B5%9C%EC%8B%A0%20%EB%B2%84%EC%A0%84)](https://github.com/ESTsecurity/remedy/releases/latest)
![플랫폼](https://img.shields.io/badge/%ED%94%8C%EB%9E%AB%ED%8F%BC-Windows%20%7C%20Linux%20x64-informational)
![라이선스](https://img.shields.io/badge/%EB%9D%BC%EC%9D%B4%EC%84%A0%EC%8A%A4-%EB%8F%85%EC%A0%90-lightgrey)

**remedy** 는 **ESTsecurity 가 만들고 관리하는 전용백신**입니다. 아래 표의 악성코드가 남긴
파일 · 자동 실행 등록 · 보안 제품 예외를 찾아 치료하고, 치료한 것은 격리해 두어 **되돌릴 수
있습니다.** 설치 없이, 받은 폴더에서 바로 실행합니다.

## 다루는 위협

받기 전에 확인하십시오 — 아래 룰이 그 OS 용 파일 하나에 모두 들어 있습니다.

<!-- threats:begin — `cargo xtask threats --write` 가 룰에서 만든다. 손으로 고치지 않는다 -->
| 룰 | 하는 일 | OS | 폴더 · 버전 | 참고 |
|---|---|---|---|---|
| EvilAI(Locust) 제거 | 찾아서 치료합니다 (복원할 수 있습니다) | Windows | `evilai-locust` 0.1.2 | [www.virustotal.com](https://www.virustotal.com/gui/search/engines%3Ameadowlocust) |
| CWPdoor 점검 (탐지만) | 찾기만 합니다 | Linux | `cwpdoor-1-check` 0.1.1 | [blog.xlab.qianxin.com](https://blog.xlab.qianxin.com/cwpdoor-the-invisible-backdoor-living-inside-control-web-panel/) |
| CWPdoor 제거 | 찾아서 치료합니다 (복원할 수 있습니다) | Linux | `cwpdoor-2-clean` 0.1.1 | [blog.xlab.qianxin.com](https://blog.xlab.qianxin.com/cwpdoor-the-invisible-backdoor-living-inside-control-web-panel/) |
| Ebury 점검 (탐지만) | 찾기만 합니다 | Linux | `ebury-check` 0.1.1 | [www.welivesecurity.com](https://www.welivesecurity.com/en/eset-research/ebury-alive-unseen-400k-linux-servers-compromised-cryptotheft-financial-gain/) |
<!-- threats:end -->

## 처음 쓰시는 분 — 다섯 단계

### 1. 받기

[**최신 버전**](https://github.com/ESTsecurity/remedy/releases/latest)에서 쓰는 곳에 맞는 파일
**하나**를 받습니다. 파일 하나에 프로그램과 그 OS 용 룰이 모두 들어 있습니다.

| 쓰는 곳 | 받을 파일 |
|---|---|
| Windows PC · 서버 (64비트) | `remedy-windows-x64.zip` |
| 리눅스 서버 (64비트) | `remedy-linux-x64.tar.gz` |

같은 화면 맨 아래의 *Source code* 두 개는 개발자용 소스입니다 — 받지 않으셔도 됩니다.

리눅스 서버에서 바로 받으려면:

```sh
curl -LO https://github.com/ESTsecurity/remedy/releases/latest/download/remedy-linux-x64.tar.gz
curl -LO https://github.com/ESTsecurity/remedy/releases/latest/download/SHA256SUMS
```

### 2. 받은 파일 확인 (권장)

받은 파일이 배포한 그 파일인지 **실행하기 전에** 확인합니다. 같은 자리의 `SHA256SUMS` 를 받아
같은 폴더에 두고 실행하십시오.

**Windows** — PowerShell 을 열어 받은 폴더로 이동한 뒤(`cd $HOME\Downloads`) 아래 한 줄을
넣습니다. `True` 가 나오면 같은 파일입니다.

```powershell
(Get-FileHash remedy-windows-x64.zip).Hash -eq (Select-String windows SHA256SUMS).Line.Split(' ')[0]
```

**리눅스** — `OK`(한국어 환경에서는 `성공`)가 나오면 같은 파일입니다.

```sh
grep linux SHA256SUMS | sha256sum -c
```

`False` · `FAILED`(한국어 환경에서는 `실패`)가 나오면 **실행하지 말고** 받은 파일을 지운 뒤 다시
받으십시오.

### 3. 풀고 실행하기

**Windows**

1. 받은 zip 을 **폴더째** 풉니다(탐색기에서 마우스 오른쪽 단추 → **모두 압축 풀기**). zip 을 연
   채로 실행하거나 파일을 따로 옮기면 동작하지 않습니다.
2. 풀린 폴더의 `remedy.exe` 를 마우스 오른쪽 단추로 누르고 **관리자 권한으로 실행** 을
   고릅니다. 파란 창(SmartScreen)이 뜨면 위 2단계로 확인한 뒤 [추가 정보] → [실행] 을
   누릅니다 — 실행 파일에 코드서명이 아직 없어서 뜹니다. 이어서 뜨는 사용자 계정 컨트롤 창에는
   [예] 를 누릅니다 — 관리자 권한으로 실행하면 늘 뜨는 창이고, 코드서명이 없어 게시자가 '알 수
   없음' 으로 나옵니다.

**리눅스**

```sh
tar -xzf remedy-linux-x64.tar.gz
cd remedy-linux-x64
sudo ./remedy
```

화면이 영어로 나오면(서버의 언어 설정이 한국어가 아닐 때) `sudo ./remedy --lang ko` 로 띄웁니다.

**PC · 서버마다 그 기계의 로컬 디스크에 풀어 실행하십시오**(예: `C:\remedy` · `/root/remedy`). USB 나
공유 폴더에서 바로 실행하면 치료 기록과 격리한 파일이 그 매체에 남아, 매체를 빼면 그 기계를 되돌릴
수 없고 재시작 뒤 자동 검사도 그 경로를 찾지 못합니다.

### 4. 무엇을 누르나

- **Windows** — 메뉴가 바로 뜹니다. 바꾸기 전에 먼저 보려면 **2. 검사만 하기**, 바로 치료하려면
  **1. 검사하고 치료하기** 를 고릅니다. 치료는 바꿀 것을 모두 보여 드린 뒤 `예` 를 받아야
  시작합니다.
- **리눅스** — 받은 파일에 검사 항목이 셋이라 먼저 무엇을 볼지 묻습니다. 어떤 위협인지 모르면
  **1. 3개 모두 검사만 하기** 를 고릅니다 — 아무것도 바꾸지 않고 결과를 한 번에 보여 드립니다.
  치료는 그 항목을 고른 뒤 **1. 검사하고 치료하기** 로 합니다.

작업이 끝나면 처음 화면으로 돌아옵니다. 끝내려면 **0** 을 고릅니다.

### 5. 결과 읽기

| 결과 줄 | 뜻 · 할 일 |
|---|---|
| 위협이 발견되지 않았습니다. | 그 항목의 위협이 없습니다. |
| 위협 발견, 치료 완료 (N건 수행 완료) | 치료했습니다. 오탐이라고 판단되면 메뉴의 **치료 전으로 복원하기** 로 되돌립니다. |
| 일부 실패 (N건 수행 완료) | 몇 가지를 바꾸지 못했습니다 — 바로 위 *실패* 줄에 까닭이 있습니다. 이미 바꾼 것은 그대로 두었으니, 까닭을 해결한 뒤 다시 검사하고 치료합니다. |
| 위협 발견, 치료하지 않았습니다. | 검사만 했거나 치료를 승인하지 않았습니다. 치료하려면 그 항목의 **1. 검사하고 치료하기** 를 고릅니다. *(탐지만)* 항목은 아래 [위협별 안내](#위협별-안내)를 따르십시오. |
| 관측이 불완전해 '위협 없음' 을 말할 수 없습니다. | 다 보지 못했습니다 — 바로 위 *주의* 줄에 까닭이 있습니다. |
| 해당 없음 (검사할 경로가 이 기계에 없습니다) | *모두 검사만* 의 요약 줄입니다. 그 항목이 검사하는 제품이 이 서버에 없습니다 — Control Web Panel(CWP)을 쓰지 않는 서버의 CWPdoor 두 항목이 이렇게 나옵니다. |

작업 뒤에는 결과에 맞는 **다음 할 일을 메뉴 번호로** 알려 드립니다.

**치료한 뒤에는 받은 폴더를 지우지 마십시오.** 메뉴로 치료한 기록과 격리한 파일은 받은 폴더
안의 `state` 에 남습니다. 폴더를 지우면 되돌릴 수 없습니다 — 되돌릴 일이 없다고 판단한 뒤에
지우십시오. 되돌릴 때는 그 폴더의 `remedy` 를 다시 띄워 메뉴에서 고릅니다.

## 위협별 안내

### CWPdoor — Control Web Panel 을 쓰는 리눅스 서버

- **CWPdoor 제거** 는 백도어가 든 `cwpsrv` 를 **격리**하고, 그것을 띄우는 `cwpsrv.service` 를
  **멈추고 지웁니다**. 패널은 그 뒤 공급사의 정상 버전을 다시 설치하고(`yum reinstall cwpsrv` —
  서비스 파일도 함께 돌아옵니다) `systemctl enable --now cwpsrv` 로 다시 켭니다.
  백도어는 임의 명령을 돌릴 수 있었으므로 패널 자격 증명도 모두 바꾸십시오.
- 공급사 버전을 다시 설치한 뒤에는 **치료를 되돌리지 마십시오** — 되돌리면 격리해 둔 백도어가
  새로 설치한 정상 파일을 덮어씁니다. 되돌리기는 오탐이라 판단했을 때, 다시 설치하기 전에만 씁니다.
- CWP 가 깔리지 않은 서버에서는 두 항목 모두 검사할 경로(`/usr/local/cwpsrv/bin`)가 없어 *관측이
  불완전해 '위협 없음' 을 말할 수 없습니다* 로 끝나고, *모두 검사만* 의 요약에는 **해당 없음** 으로
  나옵니다.

### Ebury — 리눅스 서버의 sshd (찾기만 합니다)

Ebury 는 `libkeyutils.so.1` 자리에 가짜 라이브러리를 둡니다 — 그것을 옮기면 그 라이브러리를
싣는 `sshd` · `sudo` 가 뜨지 못해 원격 접속이 끊기므로 remedy 가 손대지 않습니다. 발견되면 아래
차례대로 합니다.

1. **콘솔(가상 콘솔 · IPMI 등)에서 합니다.** SSH 로 들어가면 그 접속의 자격 증명이 다시 넘어갑니다.
2. **정상 버전을 다시 설치합니다.** RHEL 계열은 `yum reinstall keyutils-libs`(또는 `dnf`), Debian ·
   Ubuntu 는 `apt-get install --reinstall libkeyutils1`.
3. **링크가 정상 파일을 가리키는지 본 뒤에 지웁니다.** `ls -l` 로 `libkeyutils.so.1` 이 결과에 나온
   파일을 더는 가리키지 않는지 봅니다. 결과에 나온 파일이 어느 패키지의 것도 아니면(`rpm -qf` ·
   `dpkg -S` 가 패키지를 대지 못하면) 지우고 `ldconfig` 를 실행한 뒤, 링크를 한 번 더 봅니다.
   다시 설치가 되지 않았거나 링크가 여전히 그 파일을 가리키면 **지우지 말고** 담당자에게
   알리십시오 — 지우면 `sshd` · `sudo` 가 뜨지 못합니다.
4. **재부팅합니다.** 이미 떠 있는 `sshd` 등에는 가짜 라이브러리가 실려 있습니다.
5. **자격 증명을 모두 바꿉니다.** 이 서버로 들어온 비밀번호 · SSH 키와, 이 서버에서 다른 서버로
   나간 키 — Ebury 는 둘 다 훔칩니다.
6. **서버 전체를 침해된 것으로 봅니다.** 심으려면 root 권한이 필요했습니다. 다시 설치를 검토합니다.

## 화면

검사가 찾은 것과 할 일을 먼저 다 보여 드리고, 결과에 맞는 다음 할 일을 메뉴 번호로 알려
드립니다.

![검사 결과와 다음 할 일 — Windows Terminal](docs/images/scan-result-windows-terminal.png)

![remedy 의 첫 메뉴 — Windows Terminal](docs/images/menu-windows-terminal.png)

리눅스용 파일은 검사 항목이 셋이라 먼저 무엇을 볼지 묻고, 1번이 *모두 검사만* 입니다.

![검사 항목을 고르는 첫 화면 — 리눅스 xterm](docs/images/menu-linux-xterm.png)

![모두 검사한 결과 — 리눅스 xterm (Control Web Panel 이 없는 서버)](docs/images/scan-all-linux-xterm.png)

## 주요 기능

- **검사 · 치료 · 되돌리기** — 치료하기 전에 무엇을 바꿀지 전부 보여 드리고 승인을 받습니다.
  지운 것은 격리소에 보관해 두었다가 *치료 전으로 복원하기* 로 복원합니다.
- **모두 검사만** — 받은 폴더에 검사 항목이 여럿이면 한 번에 전부 검사하고 결과를 한 덩어리로
  보여 드립니다. 아무것도 바꾸지 않습니다.
- **메뉴 하나로 전부** — 작업 메뉴는 자주 쓰는 일 열셋이고(검사 항목이 여럿이면 항목을 고른
  뒤에 뜹니다), 작성자 · 운영자 명령은 마지막 한 줄 아래에 접혀 있습니다. 방향키 · 숫자로 고르고,
  지금 고를 수 없는 줄에는 까닭이 붙습니다. Ctrl+C 를 두 번 누르면 끝납니다.
- **서명된 룰** — 룰은 서명돼 있고, 실행 파일에 박힌 공개키로 확인합니다. 메뉴는 확인을 통과한
  룰만 씁니다.
- **네트워크 없음** — 치료 경로에 네트워크 기능이 없습니다. Windows 배포 빌드는 네트워크
  라이브러리를 하나도 가져오지 않는지 빌드마다 검사합니다. 폐쇄망에서도 그대로 씁니다.
- **신고 묶음** — 오탐이 의심되면 *신고에 붙일 것 모으기* 가 증거를 한 묶음으로 모읍니다.
- **두 OS 같은 구조** — 같은 메뉴 · 같은 폴더 구성입니다.

## 지원 OS · 요구 사항

| | 받을 파일 |
|---|---|
| Windows 10 · 11 · Server 2016 이상 (x64) | `remedy-windows-x64.zip` |
| Linux x86_64 — RHEL 계열 · Debian · Ubuntu (정적 링크라 배포판 버전에 매이지 않습니다) | `remedy-linux-x64.tar.gz` |

- **관리자 권한이 있어야 합니다** — Windows 는 관리자, 리눅스는 root(`sudo`). 메뉴 맨 위에서
  지금 권한을 먼저 알려 드립니다.
- 설치가 없습니다 — 받은 폴더를 풀어 그 자리에서 실행합니다.
- **받은 폴더에 쓸 수 있어야 합니다** — 메뉴는 결과(`out`)와 치료 기록(`state`)을 그 폴더에
  남깁니다. 읽기 전용 자리(읽기 전용으로 붙인 공유 폴더 등)에서는 검사가 결과를 쓰지 못해
  *입력 오류* 로 끝나므로, 쓸 수 있는 곳에 풀어 실행하십시오.

**하지 않는 것도 미리 알려 드립니다.**

- 실시간 감시 · 상주 프로그램이 아닙니다. 필요할 때 띄워 쓰는 도구입니다.
- 위 *다루는 위협* 표의 위협만 다룹니다.
- 그래픽 화면(GUI)이 없습니다.
- **Windows 실행 파일에는 아직 코드서명(Authenticode)이 없습니다.** 그래서 실행할 때마다 맨 위의
  알림으로 그 사실을 알려 드립니다(리눅스도 같은 뜻의 알림이 뜹니다). 받은 파일은 위 2단계의
  체크섬으로 확인하십시오. 룰은 서명돼 있고 실행 파일이 그 서명을 확인합니다.
- 32비트 Windows · ARM 리눅스 용 파일은 내지 않습니다.

## 운영자 — 무인 배포 · 사내 룰

인자를 주면 메뉴 없이 돌고(승인을 묻지 않으려면 `--yes`), 결과를 **종료 코드 여덟 가지**로
알립니다. Windows 에서는 치료 뒤 재시작하면 자동으로 한 번 더 검사해 치료가 유지되는지 봅니다 —
그 검사 창은 잠깐 떴다 닫히고, 결과는 상태 폴더의 `verify\<회차>.jsonl` 에 남습니다. 직접 보려면
메뉴의 **3. 치료가 유지됐는지 다시 보기** 를 고릅니다.

```powershell
.\remedy.exe run --plugin .\plugins\evilai-locust\plugin.yaml --yes
```

```sh
sudo ./remedy run --plugin ./plugins/cwpdoor-1-check/plugin.yaml          # 점검만 — 2 면 발견 · CWP 가 없는 서버는 6
sudo ./remedy run --plugin ./plugins/cwpdoor-2-clean/plugin.yaml --yes    # 치료
sudo ./remedy run --plugin ./plugins/ebury-check/plugin.yaml              # 2 면 발견 · 0 이면 없음
```

| 종료 코드 | 뜻 |
|---|---|
| 0 | 위협 없음 |
| 1 | 발견 · 치료 완료 |
| 2 | 발견 · 치료 안 함 |
| 3 | 부분 실패 |
| 4 | 사용법 · 입력 오류 |
| 5 | 안전 가드 중단 |
| 6 | 관측 불완전 — '위협 없음' 을 말할 수 없음 |
| 7 | 내부 오류 |

- **룰의 서명 확인** — 룰이 실행 파일에 든 공개키로 서명한 그대로인지 봅니다. 서명이 맞고 파일이
  하나도 바뀌지 않았으면 통과하고, 한 글자라도 다르면 어느 파일인지 알려 드립니다. 명령줄에서
  `run --plugin` 으로 직접 준 룰은 서명을 보지 않으므로 먼저 이것으로 확인하십시오. 받은 파일
  자체가 배포한 그 파일인지는 위 2단계의 체크섬으로 확인합니다. 이 기계의 폐기 목록도 함께 읽으므로
  관리자 권한으로 돌립니다(Windows 는 관리자 창).

  ```sh
  sudo ./remedy plugin verify --dir ./plugins/cwpdoor-2-clean
  ```

- **사내 룰** — 같은 실행 파일로 `run --plugin <사내 룰>/plugin.yaml` 을 돌립니다.

되돌리기 · 재검사 · 신고까지 현장에서 돌리는 방법은 [운영자 가이드](docs/operator.md)에 있습니다.

## 문서

| 누가 | 어디로 |
|---|---|
| 현장에서 **돌리는** 사람 | [`docs/operator.md`](docs/operator.md) — 배포 · 실행 · 되돌리기 · 신고 한 장 |
| 처음 오는 사람 | [`docs/remedy-전체-그림.md`](docs/remedy-전체-그림.md) — 기능 · 동작 · 배포 · 구조를 그림으로 |
| 룰을 **쓰는** 사람 | [`docs/plugin-guide/`](docs/plugin-guide/README.md) |
| 코어를 **고치는** 사람 | [`docs/개발-안내.md`](docs/개발-안내.md) — 설계의 척추 · 저장소 규칙 · 설계 문서 · 커밋 전 검증 |
| 화면이 궁금한 사람 | [`docs/design/콘솔은-이렇게-보인다.md`](docs/design/콘솔은-이렇게-보인다.md) |

## 지원 · 신고

- **보안 취약점** — 공개 이슈로 올리지 마시고 [`SECURITY.md`](SECURITY.md) 의 신고 경로로
  보내 주십시오.
- **오탐 · 치료 문의** — 메뉴의 *신고에 붙일 것 모으기*(`remedy support-bundle`)로 신고 묶음을
  만들어, 이 도구를 배포한 조직의 담당자에게 전달해 주십시오.
- **기여** — 이 저장소는 ESTsecurity 가 관리하는 독점 소프트웨어라 외부 기여(Pull Request)는
  받지 않습니다.

## 라이선스

Copyright ESTsecurity. All rights reserved. — 독점 라이선스입니다([`LICENSE`](LICENSE)).
저장소는 공개돼 있지만 오픈소스가 아닙니다.
