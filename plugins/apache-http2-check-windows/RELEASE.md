# apache-http2-check-windows — 릴리스 기록

**버전 0.1.0** · 대상: Apache HTTP Server 의 mod_http2 원격 코드 실행(CVE-2026-119618) — Windows · **점검**(바꾸지 않는다)

## 0.1.0 — 처음 (2026-11)

리눅스 룰(`apache-http2-check-linux` 0.1.0 · 1.15.0)에 이어 같은 취약점의 Windows 몫이다. **코어를 바꾸지 않고** 코어
1.13.0 의 능력(`label` · `file_names` · `ref` 본문 수집 · `capture` + `from` 설치본 그룹 · 서비스 · 실행 중 프로세스)만 쓴다.

## 무엇을 하나

| 갈래 | 판정 |
|---|---|
| 설치본의 서버 판이 2.4.55 ~ 2.4.70 이고 **그 설치본의** 설정에 HTTP/2 를 켠 흔적(`LoadModule http2_module` + `Protocols` 의 `h2` · `h2c`)이 있다 | **취약(2)** — 판 아래 줄에 CVE 와 고칠 길 |
| 판은 취약인데 그 설치본의 설정에서 HTTP/2 를 켠 흔적을 다 찾지 못했다 | **확인 필요(6)** — `Include` 로 읽는 다른 설정에서 켰을 수 있다 |
| 설치본의 `libhttpd.dll` 에서 서버 판을 읽지 못했다 | **확인 필요(6)** |
| 아래 자리 밖의 Apache 가 서비스로 있거나 돈다 | **확인 필요(6)** — 그 판은 보지 않았다 |
| 고친 판(2.4.71 이상) · 영향 없는 판(2.4.54 이하 · 2.2) · Apache 없음 | 0 |

**HTTP/2 를 켜야 닿는다** — Red Hat 공지(RHSB-2026-017): 악용에는 mod_http2 적재 · `Protocols` 의 `h2` 또는 `h2c` ·
네트워크 노출 셋이 다 필요하다. 그래서 판만으로는 2 를 내지 않는다(리눅스 룰과 같다).

### Windows 의 Apache — 상류 판을 그대로 담는다

상류는 Windows 실행 파일을 내지 않는다. 받는 곳은 Apache Lounge(`C:\Apache24` 에 푸는 zip)와, Apache 를 묶어 내는
꾸러미(XAMPP · WampServer · Laragon)다. 배포판처럼 상류 번호를 두고 고치지 않으므로 **서버 판으로 가른다** — 리눅스 룰의
직접 빌드와 같다.

판은 `libhttpd.dll` 의 서버 판 문자열(`Apache/2.4.71 (Win64)`)로 읽는다 — Apache Lounge 2.4.71 을 받아 잰 결과 그 문자열은
`libhttpd.dll` 에만 있고 `httpd.exe` 에는 없다. `httpd.exe` · `libhttpd.dll` · `mod_http2.so` 의 버전 정보는 셋 다
`2.4.71`(2진 2.4.71.0)이다. **`mod_http2.so` 의 모듈 판은 쓰지 않는다** — 고친 2.4.71 의 모듈 판 문자열도 `2.0.42` 로, 영향
범위인 별도 mod_h2 의 마지막 판과 번호가 같다.

### 설치본마다 가른다

한 기계에 XAMPP · WampServer · Apache Lounge 가 함께 깔리는 일이 흔하다. 설치본(`libhttpd.dll` 의 두 단계 위 폴더)을
`capture` 하고, 판 · 설정 규칙은 `from` 으로 그 설치본 안만 본다 — 기본 설정의 XAMPP 2.4.65 옆에 HTTP/2 를 켠 Apache
Lounge 2.4.71 이 있어도 2 가 아니라 6 이다(하네스 G1). 자리 밖 서비스 · 프로세스는 설치본에 묶이지 않는 기계 전체의
사실이다.

### 보는 자리

| 자리 | 판(`libhttpd.dll`) | 설정 줄 |
|---|---|---|
| Apache Lounge | `C:\Apache24\bin` | `C:\Apache24\conf` |
| 옛 설치 프로그램 | `C:\Program Files\Apache Software Foundation\Apache2.4\bin` | 그 `conf` |
| XAMPP | `C:\xampp\apache\bin` | `C:\xampp\apache\conf` |
| WampServer | `C:\wamp64\bin\apache\<판>\bin` · `C:\wamp\…` | 그 `conf` |
| Laragon | `C:\laragon\bin\apache\<판>\bin` | 그 `conf` |
| 그 밖 | 서비스의 실행 파일 · 실행 중인 `httpd.exe` 가 위 자리 밖이면 확인 필요 | — |

`conf\original` 은 설치할 때의 사본이라 보지 않는다. 기본 설정은 HTTP/2 를 켜지 않는다 — Apache Lounge 2.4.71 의
`httpd.conf` 는 `# LoadModule http2_module modules/mod_http2.so` 가 주석이고 `Protocols` 줄이 어느 설정에도 없다. 그래서
영향 판을 기본 설정 그대로 두었으면 확인 필요다.

## 고친 판

| 받는 곳 | 고친 판 | 근거 (2026-11-14 확인) |
|---|---|---|
| Apache Lounge | 2.4.71 — `httpd-2.4.71-261112-Win64-VS18.zip`(2026-11-12 · SHA-256 `44961A92…34029E1FC`) | 내려받기 페이지 · 같은 자리의 `.txt` |
| XAMPP for Windows | **아직 없다** — 8.5.12 · 8.4.27 · 8.3.36 이 모두 Apache 2.4.65 를 묶는다 | apachefriends.org 내려받기 페이지 · SourceForge(8.3.36 · 2026-10-23) |
| 직접 빌드 | 2.4.71 | Apache 공지 |

XAMPP 에는 고친 판이 없으므로 화면은 *"HTTP/2 를 꺼야 합니다"* 를 함께 적는다 — `Protocols` 에서 `h2` · `h2c` 를 빼거나
`LoadModule http2_module` 을 주석으로 돌리면 이 룰도 2 를 내지 않는다(판은 여전히 영향 범위라 6 이다).

## 결과 읽기

| 종료 코드 | 뜻 |
|---|---|
| 2 | **취약** — Apache 를 2.4.71 이상으로 바꾸고(Apache Lounge 의 새 zip) 다시 시작한다. XAMPP 는 고친 판이 나올 때까지 HTTP/2 를 끈다 |
| 0 | 취약한 곳을 찾지 못했다 |
| 6 | **확인 필요** — `주의:` 아래 줄이 무엇을 확인할지 말한다 |

## 이 룰이 보지 않는 것

- 위 자리 밖에 풀어 두기만 한 Apache(서비스도 아니고 돌지도 않는다)
- 설치본 밖의 설정 — `Include` 로 읽는 다른 자리 · `<VirtualHost>` · `<IfModule>` 안의 줄인지. 흔적을 못 찾으면 확인 필요로
  돌린다
- 별도 mod_h2 로 갈아 끼운 `mod_http2.so` — 모듈 판 번호로는 고친 것을 가를 수 없다(위)
- **TLS 개인키** — 실행 파일은 `libhttpd.dll` 만 기록 · 해시하고, 설정은 줄 단위로 설정 접미사(`.conf` 등)만 읽는다.
  `conf\private` 의 `*.key` 는 읽지 않는다(하네스 K1)

## 근거 — 공개 자료 (2026-11-14 확인)

- Apache: `httpd.apache.org/security/vulnerabilities_24.html` — *"mod_http2: heap corruption and RCE in assign_headers"* ·
  2.4.55 ~ 2.4.70 · 2.4.71(2026-11-11) · mod_h2 2.0.8 ~ 2.0.42
- Red Hat: RHSB-2026-017(악용 조건 · 완화)
- Apache Lounge: `www.apachelounge.com/download/` — `httpd-2.4.71-261112-Win64-VS18.zip` · 옛 판은 내려받을 수 없다 · 별도
  mod_http2 배포 없음
- Apache Friends: `www.apachefriends.org/download.html` — XAMPP for Windows 8.5.12 · 8.4.27 · 8.3.36 · Apache 2.4.65

## 게이트

| # | 게이트 | 상태 | 근거 |
|---|---|---|---|
| G1 | 청정 환경 무해성 | **통과** | 2026-11-14 · 청정 스냅샷에서 판정 0(`plugins_find_nothing_in_clean_environments`) — 청정 코퍼스에는 Apache 가 깔린 기계가 없다 |
| G2~G4 | 복원 · 계획 · 치료 | **미해당** | 바꾸는 것이 없다 |
| G9 | 룰의 검체 오탐(YARA) | **통과** | 2026-11-14 · 공개 전 · `cargo xtask yara` — 진짜 Apache Lounge 2.4.71 트리 999개: `apache_version_affected` 맞음 0 · `apache_version_any` 맞음 6(`libhttpd.dll` 과 판 문자열을 담은 모듈 다섯 — 이 규칙이 뜻한 파일) · 이 기계의 `C:\Windows\System32` 28,694개(상한 256 MiB): 두 규칙 모두 맞음 0 · 못 훑음 562(접근 거부 553 · 사용 중 8 · 256 MiB 초과 1). 판정에서 두 규칙은 경로 규칙이 고른 `\bin\libhttpd.dll` 에만 쓰인다 |
| 하네스 | `testbed/harness/host/Invoke-ApacheVerify.ps1` | **31/31** | 2026-11-14 · Windows 랩 VM · 코어 1.16.0 개발 빌드(일회용 키를 앵커로 박고 그 키로 이 룰을 서명) — 진짜 Apache Lounge 2.4.71(HTTP/2 를 켬 · 기본) 0 · Apache Lounge 자리의 2.4.65 + HTTP/2 2 · 기본 6 · 모듈만 6 · Protocols 만 6 · Protocols 가 `extra\httpd-ssl.conf` 에 2 · 2.4.70 h2c 2 · 2.4.55 2 · 2.4.54 0 · Protocols 주석 6 · 2.2.34 0 · 서버 판 없음 6 · `conf\original` 에만 6 · XAMPP · WampServer · Laragon · 옛 설치 프로그램 자리 2 · **설치본 둘: XAMPP 2.4.65 기본 + HTTP/2 를 켠 2.4.71 → 6**(가르지 않으면 2) · 둘 다 켬 2 · WampServer 2.4.65 기본 + XAMPP 2.4.71 켬 6 · 자리 밖 서비스 6 · 자리 밖에서 도는 `httpd.exe` 6 · 자리 안 서비스 + 2.4.71 0 · 없음 0 · 화면 넷(CVE 문구 · 흔적 없음 · 판 없음 · 자리 밖의 까닭) · 개인키 표지가 결과 파일 셋 · 화면에 0 |

린트 경고 하나(`C:\Apache24` 깊이 2)는 룰 머리에 까닭을 적었다 — 설치본마다 가르는 `from` 이 설치 폴더를 상한에 두게 한다.

## 서명 — 저장소 사본은 개발용 키, 배포본은 배포 키

저장소의 `MANIFEST` · `MANIFEST.minisig` 는 저장소 사본을 확인하려고 **개발용 키로** 서명한 것이다. 배포본은 태그의 배포
잡이 배포 키로 다시 서명하고 그 공개키를 박아 빌드하므로, 내려받은 배포 파일에 든 이 폴더는 배포 키의 서명이다(`plugin
verify` 로 확인한다). 개발용 키로 서명된 룰은 배포 앵커가 박힌 실행 파일에서 거부된다.
