# nginx2root-check-windows — 릴리스 기록

**버전 0.1.0** · 대상: nginx 의 결함 다섯 'nginx2root'(CVE-2026-123007 · CVE-2026-123634 · CVE-2026-123633 ·
CVE-2026-121810 · CVE-2026-113425) — Windows · **점검**(바꾸지 않는다)

## 0.1.0 — 2차 (2026-11-19)

긴급 경로의 2차다(코어 그대로 · `docs/긴급-대응.md`). 1차는 리눅스(`nginx2root-check-linux` · `rules-2026.11.19`)였다. 판정
정책은 1차 카드 그대로(판으로만 · 고친 판 없는 갈래의 영향 판은 취약)이고, 보는 범위는 2차 카드로 정했다(자리 지정).

### 판정

| 무엇 | 결과 |
|---|---|
| 아래 자리의 `nginx.exe` 의 서버 판 문자열(`nginx/<판>`)이 0.5.33 이상이고 1.30.7 아래 · 또는 1.31.0 ~ 1.31.8 | 취약(2) |
| 그 `nginx.exe` 에서 판을 읽지 못했다 | 확인 필요(6) |
| 아래 자리 밖의 `nginx.exe` 가 돌거나 서비스로 등록됐다 | 확인 필요(6) — 그 판은 보지 않았다 |
| 1.31.9 이상 · 1.30.7 ~ 1.30.x · nginx 없음 | 0 |

- **보는 자리**(2차 카드 — 자리 지정): `C:\nginx` · `C:\Program Files\nginx` · `C:\Program Files (x86)\nginx` · Laragon
  (`C:\laragon\bin\nginx`) · Chocolatey(`C:\tools` — 도구 자리의 기본 `C:\tools\nginx-<판>` · `C:\ProgramData\chocolatey\lib\nginx`)
  · Scoop(사용자마다 · 전역 — `apps\nginx\<판>`) · winget 의 `nginxinc.nginx`(portable · 사용자 범위
  `%LOCALAPPDATA%\Microsoft\WinGet\Packages\nginxinc.nginx_Microsoft.Winget.Source_8wekyb3d8bbwe` · 기계 범위
  `C:\Program Files\WinGet\Packages\…`). 파일 경로에는 와일드카드를 쓸 수 없어 nginx.org 안내의 기본 자리 `C:\nginx-<판>`
  처럼 판마다 이름이 다른 폴더는 자리로 적지 못한다 — 그 nginx 가 돌거나 서비스면 확인 필요로 알린다. 디스크 전체에서
  찾는 꼴(Log4j 점검 꼴)은 다음 차수 후보다.
- **NSSM** — 공식 nginx/Windows 는 서비스가 아니라 콘솔 프로그램이라(nginx.org `docs/windows.html`) 서비스로 걸면 NSSM ·
  WinSW 같은 감싸는 프로그램을 쓴다. Chocolatey 의 nginx 패키지는 기본으로 NSSM 서비스를 건다. NSSM 서비스의 실행 파일은
  `nssm.exe` 이고 띄우는 프로그램은 `Services\<이름>\Parameters` 의 `Application` 값이다 — 그 값이 자리 밖의 nginx 를
  가리키면 확인 필요다(php2shell-check-windows 0.4.0 과 같은 자리). WinSW 는 대상이 옆 XML 에 있어 보지 않는다(돌면
  프로세스로 잡는다).
- **설치본마다 가른다** — `nginx.exe` 가 든 폴더가 설치본 하나다. 고친 판 하나가 판을 읽지 못한 다른 설치본을 가리지
  않는다(하네스 G1).
- 판은 실행 파일의 서버 판 문자열로 읽는다 — 리눅스 룰의 직접 빌드와 같은 `rules/nginx.yar` 다(같은 바이트). nginx.org 의
  Windows 빌드는 `nginx/1.31.9` 꼴의 글자를 그대로 담는다(진짜 zip 셋 실측 · 2026-11-19).

### 영향 판 · 고친 판

리눅스 룰의 `RELEASE.md` 와 같다(nginx.org 공지 · 2026-11-19 07:34 확인 — 다섯 모두 *Not vulnerable: 1.31.9+, 1.30.7+* ·
공지는 플랫폼을 가르지 않는다). nginx.org 는 Windows zip 으로 1.31.9 · 1.30.7 을 냈다(`nginx-1.31.9.zip` · `nginx-1.30.7.zip`
· 2026-11-19 09:37 확인).

| 받는 곳 | 고친 판 (2026-11-19 확인) |
|---|---|
| nginx.org zip · Scoop(`nginx.json` 1.31.9) · winget(`nginxinc.nginx` 1.31.9) | 1.31.9 · 1.30.7 — 세 곳이 같은 zip 이다(같은 SHA-256) |
| Chocolatey `nginx` | **아직 없다** — 09:40 의 최신이 1.31.8(영향 판)이다. 고친 판이 올라오기 전에는 nginx.org zip 으로 바꾼다 |

공식 Windows 빌드에는 HTTP/3(CVE-2026-121810 의 자리)이 없다 — QUIC 를 지원하지 않는다(nginx.org `docs/windows.html` · 실행
파일의 configure 인자에 `--with-http_v3_module` 이 없다). 판정은 판으로만 하므로 영향 판이면 그래도 취약이다 — 나머지 넷이 닿는다.

### 게이트

| 게이트 | 무엇 | 결과 | 근거 |
|---|---|---|---|
| G1 | 청정 환경 무해성 | **통과** | 2026-11-19 09:46 · 청정 코퍼스의 Windows 스냅샷 10개(`win10x64-*`)에 `remedy evaluate`(코어 1.24.0 개발 빌드) — 모두 종료 0 |
| G9 | 룰의 검체 오탐(YARA) | **통과**(점검 룰 기준) | 2026-11-19 09:47 ~ 09:59 · `cargo xtask yara` 규칙 둘 — nginx.org 의 진짜 트리 셋(1.31.9 · 1.30.7 · 1.30.6 · 96개)에서 판 문자열 규칙은 `nginx.exe` 셋만, 영향 규칙은 1.30.6 의 `nginx.exe` 하나만 맞았다(그 뜻의 파일 · 못 훑음 0). `C:\Windows\System32` 전수에서 두 규칙 모두 오탐 0 · 못 훑음 740(보인 것은 모두 상한을 넘는 DriverStore 의 큰 DLL · CAB). YARA 는 리눅스 룰과 같은 바이트다 |
| 하네스 | `testbed/harness/host/Invoke-Nginx2rootVerify.ps1` | **33/33** | 2026-11-19 10:28 · 랩 VM · `New-DevPackage.ps1` 의 개발 꾸러미(일회용 키). 1회차는 하네스에 적은 zip 해시 한 글자가 틀려 시작 전에 멈췄다. 3회차 30/31 은 까닭 문장을 고친 뒤 하네스의 기대 문구가 낡은 것(S-O1). 거꾸로 — NSSM · winget 을 넣기 전 룰은 26/31(winget 두 칸 0 · NSSM 칸 0 · 화면 둘), Scoop shim 을 빼기 전 룰은 32/33(고친 판 + shim 이 6) |

- **Scoop 의 shim 을 자리 밖 프로세스로 세지 않는다**(공개 전 반증 검토 셋이 모두 찾았다). Scoop 은 `bin` 의 `nginx.exe` 마다
  PATH 의 `scoop\shims\nginx.exe` 를 만든다(ScoopInstaller/Main 의 `nginx.json` · `lib/core.ps1`). shim 은 진짜 nginx 를 자식으로
  띄우고 그동안 살아 있다(ScoopInstaller/Shim — *The shim waits for the child*). 빼지 않으면 Scoop 의 고친 nginx 를 띄운 채
  점검할 때마다 확인 필요가 났다(하네스 L8 을 그 전 룰로 돌리면 6). 진짜 nginx 는 자리 안의 자식 프로세스라 빼도 놓치지 않는다.

### 다음 차수 후보

| 범위 | 까닭 | 필요한 것 |
|---|---|---|
| 디스크 전체에서 `nginx.exe` 찾기 | 2차는 자리 지정(카드) — 판마다 이름이 다른 폴더에 풀고 돌리지 않는 nginx 를 못 본다 | `%FIXED_DISKS%` 꼴의 시간 · 빠른 검사에서 빠지는 것의 결정 |
| WinSW 로 감싼 서비스의 대상 | 대상이 감싸는 프로그램 옆의 XML 에 있다 — 돌면 프로세스로 잡는다 | 서비스 실행 파일 옆 XML 의 `<executable>` 을 읽는 줄 |
| WNMP · Open Server Panel 의 nginx | 자리를 1차 출처로 확인하지 못했다 | 그 묶음의 설치 자리 |
| NGINX Plus · 파생 제품 | 리눅스 룰과 같다 | 각 제품의 공지 |
