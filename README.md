# remedy — ESTsecurity 전용백신

![remedy 의 첫 메뉴 — Windows Terminal](docs/images/menu-windows-terminal.png)

[![CI](https://github.com/ESTsecurity/remedy/actions/workflows/ci.yml/badge.svg)](https://github.com/ESTsecurity/remedy/actions/workflows/ci.yml)
[![최신 판](https://img.shields.io/github/v/release/ESTsecurity/remedy?label=%EC%B5%9C%EC%8B%A0%20%ED%8C%90)](https://github.com/ESTsecurity/remedy/releases/latest)
![플랫폼](https://img.shields.io/badge/%ED%94%8C%EB%9E%AB%ED%8F%BC-Windows%20%7C%20Linux%20x64-informational)
![라이선스](https://img.shields.io/badge/%EB%9D%BC%EC%9D%B4%EC%84%A0%EC%8A%A4-%EB%8F%85%EC%A0%90-lightgrey)

**remedy** 는 **ESTsecurity 가 만들고 관리하는 명령줄 전용백신**입니다. 특정 악성코드가 남긴
자동 실행 등록 · 시작 프로그램 · 파일 · 보안 제품 예외를 찾아 치료하고, 치료한 것은 격리해
두어 **언제든 되돌릴 수 있게** 합니다. 위협마다 서명된 룰 묶음(플러그인 번들)을 받아, 같은
실행 파일 하나로 Windows 와 Linux 에서 씁니다.

## 화면

검사가 찾은 것과 할 일을 먼저 다 보여 드리고, 결과에 맞는 **다음 할 일을 메뉴 번호로**
알려 드립니다.

![검사 결과와 다음 할 일 — Windows Terminal](docs/images/scan-result-windows-terminal.png)

리눅스도 같은 메뉴 · 같은 번호입니다.

![remedy 의 첫 메뉴 — 리눅스 xterm](docs/images/menu-linux-xterm.png)

## 주요 기능

- **검사 · 치료 · 되돌리기** — 치료하기 전에 무엇을 바꿀지 전부 보여 드리고 승인을 받습니다.
  지운 것은 격리소에 보관해 두었다가 *치료를 되돌리기* 로 복원합니다.
- **메뉴 하나로 전부** — 인자 없이 띄우면 명령 스물을 늘 같은 번호로 보여 주는 메뉴가 뜹니다.
  방향키 · 숫자로 고르고, 지금 고를 수 없는 줄에는 까닭이 붙습니다. 작업이 끝나면 메뉴로
  돌아오고, Ctrl+C 를 두 번 누르면 끝납니다.
- **무인 배포** — 인자를 주면 묻지 않고 돌고, 결과를 **종료 코드 여덟 가지**로 알립니다
  (아래 표). Windows 에서는 치료 뒤 재시작하면 자동으로 한 번 더 검사해 치료가 유지되는지
  봅니다.
- **서명된 룰** — 룰 묶음은 서명돼 있고, 실행 파일에 박힌 공개키로 확인합니다. 메뉴는 확인을
  통과한 꾸러미만 쓰고, `plugin verify` 는 한 바이트라도 다르면 어느 파일인지 알려 드립니다.
  (명령줄에서 `run --plugin` 으로 직접 준 룰은 서명을 보지 않으므로, 먼저 `plugin verify` 로
  확인하십시오.)
- **네트워크 없음** — 치료 경로에 네트워크 기능이 없습니다. Windows 배포 빌드는 네트워크
  라이브러리를 하나도 가져오지 않는지 빌드마다 검사합니다. 폐쇄망에서도 그대로 씁니다.
- **신고 묶음** — 오탐이 의심되면 *신고에 붙일 것 모으기* 가 증거를 한 묶음으로 모읍니다.
- **두 OS 같은 구조** — 같은 메뉴 · 같은 꾸러미 배치 · 같은 이름 규칙입니다.

## 지원 OS · 요구 사항

| | 지원 | 받을 파일 |
|---|---|---|
| Windows 10 · 11 · Server 2016 이상 (x64) | 지원 | 위협 꾸러미 · 엔진 |
| Linux x86_64 — RHEL 계열 · Debian · Ubuntu | 지원 | 엔진(정적 링크) |

- **관리자 권한이 있어야 합니다** — Windows 는 관리자, Linux 는 root. 메뉴 맨 위에서 지금
  권한을 먼저 알려 드립니다.
- 설치가 없습니다 — 받은 폴더를 풀어 그 자리에서 실행합니다.

**하지 않는 것도 미리 알려 드립니다.**

- 실시간 감시 · 상주 프로그램이 아닙니다. 필요할 때 띄워 쓰는 도구입니다.
- 플러그인 번들이 있는 위협만 치료합니다. 지금 위협 꾸러미는 **EvilAI(Locust)** 하나이고
  Windows 용입니다 — 리눅스용 위협 꾸러미는 아직 없습니다.
- 그래픽 화면(GUI)이 없습니다.
- **Windows 실행 파일에는 아직 코드서명(Authenticode)이 없습니다.** 그래서 실행할 때마다
  맨 위에 그 사실을 한 줄로 알려 드립니다(리눅스도 같은 뜻의 한 줄이 뜹니다). 받은 파일은
  아래 체크섬으로 확인하십시오. 룰 묶음은 서명돼 있고 실행 파일이 그 서명을 확인합니다.
- 32비트 Windows · ARM 리눅스 용 파일은 내지 않습니다.

## 받기

[**GitHub Releases**](https://github.com/ESTsecurity/remedy/releases/latest) 에서 받습니다.
파일마다 `<파일>.sha256` 이 함께 있습니다.

| 파일 | 무엇 | 누가 |
|---|---|---|
| `remedy-evilai-locust-windows-x64.zip` | **위협 꾸러미** — `remedy.exe` · 서명된 `evilai-locust` 룰 · `README.txt` | EvilAI(Locust) 를 치료할 Windows PC |
| `remedy-windows-x64.zip` | 엔진만 — Windows x64 | 사내 룰과 함께 쓰는 운영자 |
| `remedy-linux-x64.tar.gz` | 엔진만 — Linux x64 (정적 링크) | 사내 룰과 함께 쓰는 운영자 |

이름은 하나의 규칙입니다 — 위협 꾸러미 `remedy-<위협>-<os>-<arch>` · 엔진 `remedy-<os>-<arch>`.
위협 꾸러미는 그 위협이 감염시키는 OS 용으로만 냅니다.

| 위협 | Windows x64 | Linux x64 |
|---|---|---|
| `evilai-locust` | ✓ | — (Windows 를 노리는 위협) |

## 받은 파일 확인

받은 파일이 배포한 그 파일인지 **실행하기 전에** 확인하십시오.

**Windows (PowerShell)** — `True` 가 나오면 같습니다.

```powershell
$f = "remedy-evilai-locust-windows-x64.zip"
(Get-FileHash $f -Algorithm SHA256).Hash -eq (Get-Content "$f.sha256").Split(" ")[0].ToUpper()
```

**Linux** — `OK`(한국어 환경에서는 `성공`)가 나오면 같습니다.

```sh
sha256sum -c remedy-linux-x64.tar.gz.sha256
```

압축을 푼 뒤에는 룰 묶음의 서명도 확인할 수 있습니다 — 서명이 맞고 파일이 하나도 바뀌지
않았으면 통과하고, 한 글자라도 다르면 어느 파일인지 알려 드립니다.

```powershell
.\remedy.exe plugin verify --dir .\plugins\evilai-locust
```

## 빠른 시작

### Windows — 메뉴로

1. 받은 zip 을 **폴더째** 풉니다. 파일을 따로 옮기면 동작하지 않습니다.
2. `remedy.exe` 를 마우스 오른쪽 단추로 누르고 **관리자 권한으로 실행**을 고릅니다.
   (받자마자 파란 SmartScreen 창이 뜨면 위의 체크섬을 확인한 뒤 [추가 정보] → [실행].)
3. 메뉴에서 **1. 검사하고 치료하기** 를 고릅니다. 할 일을 먼저 보여 드리고 `예` 를 받은
   뒤에 치료합니다.

### Windows — 무인 배포

```powershell
.\remedy.exe run --plugin .\plugins\evilai-locust\plugin.yaml --yes
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

### Linux — 엔진

```sh
tar -xzf remedy-linux-x64.tar.gz
sudo ./remedy run --plugin <사내 룰>/plugin.yaml
```

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
