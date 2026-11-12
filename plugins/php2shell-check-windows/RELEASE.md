# php2shell-check-windows — 릴리스 기록

**버전 0.4.0** · 대상: PHP2Shell(CVE-2026-109618 · CVE-2026-109619) — Windows 의 PHP · **점검**(바꾸지 않는다)

## 0.4.0 — NSSM 이 감싸 띄우는 PHP (2026-11)

NSSM(srvany 도 같은 자리)으로 등록한 서비스는 실행 파일 자리(`ImagePath`)가 `nssm.exe` 이고, 띄우는 프로그램은
`HKLM\SYSTEM\CurrentControlSet\Services\<이름>\Parameters` 의 `Application` 값에 있다. 그 값이 선언한 자리 밖의
PHP(`php.exe` · `php-cgi.exe` · `php-win.exe`)이면 **확인 필요(6)** 로 낸다 — 0.3.0 의 서비스 규칙은 `ImagePath` 만
봐서 이 PHP 를 몰랐다. 값은 원문이라 환경 변수 꼴(`%SystemDrive%\php\…`)도 선언한 자리로 친다. 경로 없이 이름만
적혔으면(`php-cgi.exe` — NSSM 이 `AppDirectory` 에서 찾는다) 어디의 PHP 인지 알 수 없어 함께 알린다. 그 PHP 의
파일은 열지 않는다. 항목 줄은 `HKLM\SYSTEM\CurrentControlSet\Services\<이름>\Parameters\Application  (값 <경로>)`
이다.

코어 1.10.0 이 필요하다 — 서비스마다 `Parameters` 하나를 읽는 레지스트리 루트(`Services\*\Parameters`)를
1.10.0 의 린트가 받는다. 랩 VM 실측: 서비스 763 중 `Parameters` 가 있는 것 364 · 관리자가 못 연 것 0 · 값 848.

## 0.3.0 — 다른 프로그램에 모듈로 실린 PHP (2026-11)

코어 1.9.0 부터 Windows 도 프로세스에 실린 모듈을 모은다(`remedy-winmods`). 그래서

- **다른 프로그램에 실린 선언 밖의 PHP 를 알린다** — 실행 중인 프로세스의 실린 모듈에 선언한 자리 밖의 PHP 코어
  DLL(`php8ts.dll` · `php8.dll` · …)이 있으면 그 프로세스를 **확인 필요(6)** 로 낸다. Apache 의
  `php8apache2_4.dll` 이 코어 DLL 을 함께 싣는 꼴이다. 항목 줄의 괄호가 걸린 DLL 이다 —
  `C:\Windows\…\powershell.exe  (모듈 C:\inetpub\php83\php8.dll)`. PHP 자신(`php.exe` · `php-cgi.exe`)은 0.2.0 의
  실행 중 규칙이 본다.
- **모듈 목록을 읽지 못한 Apache(`httpd.exe`)도 확인 필요다** — 그 Apache 가 PHP 를 싣는지 보지 못했다. 보호
  프로세스(PPL)는 서명된 모듈만 실어 PHP 가 들어갈 수 없고, 목록을 거부하는 보안 제품은 PHP 를 싣는 프로그램이
  아니라 묻지 않는다(랩 VM: 프로세스 162개 중 거부 2 가 nProtect 의 둘 — 종료 코드는 그대로다).
- **멈춰 있어도 남는 자리 둘** — 실행 파일 자리(`ImagePath`)가 선언 밖의 PHP 인 **서비스**와, 선언 밖의 PHP 를
  싣는 **Apache 설정**의 `LoadModule php_module` 줄(Apache Lounge `C:\Apache24` · Apache 설치 프로그램 · XAMPP ·
  WampServer · Laragon 의 설정 폴더). 경로는 `/` · `\` · 따옴표 유무를 가리지 않고, XAMPP 의 드라이브 없는 꼴
  (`/xampp/php/…`)과 WampServer 의 변수 꼴(`${INSTALL_DIR}/bin/php/…`)은 그 제품의 PHP 자리로 친다. 항목 줄은
  `<서비스 이름>  (실행 파일 <ImagePath>)` · `<파일>:<줄 번호>  (줄 <그 줄>)` 이다.

## 0.2.1 — 화면 문구 (2026-11)

판정은 0.2.0 과 같다.

- 사유가 경로를 *위 경로* 로 가리킨다 — 항목 줄이 주의 줄보다 위에 선다(0.2.0 은 *아래* 라고 적었다).
- 고친 버전을 계열마다 적는다(8.2 는 8.2.35 · 8.3 은 8.3.36 · 8.4 는 8.4.27 · 8.5 는 8.5.12) — 한 줄에 늘어놓으면
  취약한 8.3.35 도 '8.2.35 이상' 으로 읽혔다.
- IIS 가 쓰는 PHP 와 실행 중인 PHP 의 사유를 한 칸(`iis_php or running_php`)으로 합쳤다 — 같은 PHP 면 같은 문장이
  두 번 섰다.
- 해시가 맞지 않는 PHP 의 사유가 '버전은 고친 버전 이상이지만' 으로 시작하지 않는다 — 버전 문자열이 없거나 5.3
  이하인 것도 그 줄로 온다. IIS 공유 설정 사유에 할 일을 붙였다.

## 0.2.0 — 선언한 자리 밖의 PHP 를 알린다 (2026-11)

선언한 자리 밖에서 PHP 를 찾으면 그 경로를 적고 **확인 필요(6)** 로 낸다. 그 PHP 는 판정하지 않는다 — 룰은
선언한 자리만 읽는다(목표 결정 22). 찾는 곳은 둘이다.

- **IIS 설정** — `C:\Windows\System32\inetsrv\config\applicationHost.config` 의 FastCGI 응용(`fastCgi/application`
  의 `fullPath`)과 처리기(`handlers/add` 의 `scriptProcessor`). 값의 환경 변수 꼴(`%SystemDrive%` ·
  `%ProgramFiles%`)도 선언한 자리로 친다. IIS 가 공유 설정을 쓰면(`configurationRedirection` 의
  `enabled="true"`) 그 설정은 다른 자리에 있어 확인 필요다.
- **실행 중인 프로세스** — 실행 파일이 `php.exe` · `php-cgi.exe` · `php-win.exe` 인 것.

선언한 자리의 설치본이 **모두** 취약(2)으로 판정된 회차에는 자리 밖의 PHP 가 화면에 나오지 않는다(찾은 것이
모르는 것보다 앞선다 — 코어의 규칙) — 고친 뒤 다시 검사하면 확인 필요로 나온다.

코어 1.6.0 이 필요하다(`structured_config` 가 `.config` 를 XML 로 편다). 공식 빌드 해시 · 버전 판정은 0.1.0 과 같다.

## 0.1.0 — 처음 (2026-11)

설치본마다 공식 빌드 해시로 판정하고, 그 밖은 확인 필요로 낸다. 코어 1.3.0 의 `verdict.unconfirmed` 를 쓴다.

## 무엇을 하나

- **판정의 단위는 설치본**(코어 DLL `php8ts.dll` · `php8.dll` · `php7ts.dll` · … 이 있는 폴더)이다 — 한 기계에
  여럿 깔려도 한 설치본의 사실이 다른 설치본의 판정을 바꾸지 않는다.
- **공식 빌드 해시와 맞으면** 그 버전이 판정이다 — 8.3.35(TS · NTS) → **취약(2)** · 고친 버전 8.2.35 · 8.3.36 ·
  8.4.27 · 8.5.12 와 그 `-1` 재빌드(2026-10-26) → 0.
- **맞지 않으면 확인 필요(6)** 다 — PE 의 버전 문자열은 그 빌드가 패치를 담았는지 말해 주지 않는다(같은 버전
  번호로 다시 지은 빌드 · 공급사 빌드 · 직접 지은 빌드가 같은 문자열을 낸다). 버전이 고친 버전보다 낮거나 고친 버전이
  없는 계열(5.4~8.1)이면 *패치되지 않았을 가능성이 큽니다* 를, 고친 버전 이상이면 *받은 곳을 확인하십시오* 를 적는다.
- 확장 DLL(`ext\php_*.dll`)은 PHP 로 세지 않는다 — PHP 와 같은 버전을 선언하지만 PHP 가 아니다.

## 결과 읽기

| 종료 코드 | 뜻 |
|---|---|
| 2 | **취약** — 공식 8.3.35 빌드다. 8.3.36 이상으로 올리고 IIS · Apache · PHP 를 다시 시작한다 |
| 0 | 취약한 곳을 찾지 못했다 — 공식 고친 빌드이거나, 선언한 자리에 PHP 가 없다 |
| 6 | **확인 필요** — `주의:` 아래 줄이 버전을 올릴지(낮은 버전) 받은 곳을 확인할지(높은 버전) 말한다. 선언한 자리 밖의 PHP 면 항목 줄에 그 경로가 있다(IIS 설정에서 찾은 것은 `applicationHost.config  (값 <PHP 경로>)` — 코어 1.7.0. 1.6.0 은 `(value …)`). 다른 프로그램에 실린 PHP 면 그 프로그램의 경로 뒤 괄호가 그 PHP 의 DLL 이다(`(모듈 <DLL 경로>)` — 코어 1.9.0) |

## 이 룰이 보지 않는 것

- 선언한 자리(`C:\php` · `Program Files\PHP` · XAMPP · WampServer · Laragon · Chocolatey 의 `C:\tools\phpNN`) 밖의
  PHP 의 버전 — IIS 설정에도 없고 실행 중도 아니며 어디에도 실리지 않았으면 그 PHP 가 있다는 것도 모른다(랩 S1 · M1).
- IIS 의 공유 설정이 가리키는 다른 자리의 설정 · 위에 적지 않은 자리에 둔 Apache 설정 · NSSM · srvany 밖의 감싸는
  프로그램이 띄우는 서비스(그 프로그램이 실행 파일 자리라, 실행 중일 때만 본다).
- 실행 중인 PHP 가 고친 버전을 실었는가 — 고친 뒤에는 IIS · Apache · PHP 를 다시 시작한다.
- php.net 의 2026-10-26 Windows 재빌드(`8.x.y-1`)가 바꾼 Brotli(CVE-2026-111497)는 이 룰의 판정이 아니다 —
  `node2shell-check-windows` 가 PHP 폴더의 `brotlidec.dll` 로 본다. 재빌드의 코어 DLL 해시는 이 룰의 고친 버전
  목록에 있다(PHP 버전 번호가 같아 해시로만 가린다).

## 근거 — 공개 공지와 공식 빌드

- 상류 고친 버전 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12 — php.net 2026-10-21 보안 공지(8.1 이하는 고친 버전이 없다)
- 공식 빌드 해시 — downloads.php.net 의 Windows x64(TS · NTS) 코어 DLL: 취약 `php-8.3.35`, 고친 버전 `php-8.2.35` ·
  `8.3.36` · `8.4.27` · `8.5.12` 와 그 `-1` 재빌드. 각 ZIP 의 SHA-256 을 같은 자리의 SBOM(`.cdx.json`)과 맞춘 뒤
  코어 DLL 을 쟀다(2026-11-09)

## 게이트

| # | 게이트 | 상태 | 근거 |
|---|---|---|---|
| G1 | 청정 환경 무해성 | **통과** | 청정 스냅샷에서 판정 0 — 청정 코퍼스에는 PHP 가 깔린 기계가 없다 |
| G2~G4 | 복원 · 계획 · 치료 | **미해당** | 바꾸는 것이 없다 |
| 모양 | 판정 규칙 | **34/34** | 손으로 지은 기계 모양을 `remedy evaluate` 로 — 공식 해시 · 낮은 버전 · 높은 버전 · 지원 종료 · RC · 다음 계열 · 버전 없음 · 설치본 둘, 그리고 고친 네 계열의 원래 빌드와 `-1` 재빌드(TS · NTS 16) — 0.1.0 |
| 실기계 · 자리 밖 | 수집 → 판정 | **7/7** | 2026-11-11 · Windows 랩 VM 에서 0.1.0(코어 1.5.0 공개본)과 0.2.0(1.6.0 개발 빌드)을 같은 상태에서 나란히 — 취약한 공식 8.3.35 를 선언 밖(`C:\inetpub\php83`)에 둠 **0 → 0** (실행 중도 IIS 설정도 아니다) · 거기서 `php.exe` 실행 **0 → 6** · IIS FastCGI · 처리기가 그 `php-cgi.exe` 를 가리킴 **0 → 6** · 요청 하나로 IIS 아래 `php-cgi.exe` 가 뜸 **0 → 6** · 같은 PHP 를 `C:\php` 로 옮기고 IIS 도 그리로 **2 → 2** · 랩 스냅숏(PHP 없음)과 PHP 를 지운 뒤 **0 → 0** 둘 |
| 실기계 · 실린 모듈 | 수집 → 판정 | **4/4** | 2026-11-12 · Windows 랩 VM 에서 0.2.1(코어 1.7.0 공개본)과 0.3.0(1.9.0 개발 빌드)을 같은 상태에서 나란히 — 랩 스냅숏 **0 → 0**(nProtect 둘이 모듈 목록을 거부해도) · 취약한 공식 8.3.35(NTS)를 선언 밖(`C:\inetpub\php83`)에 둠 **0 → 0** · 다른 프로그램(`powershell.exe`)이 그 `php8.dll` 을 실음 **0 → 6**(화면: `powershell.exe  (모듈 C:\inetpub\php83\php8.dll)`) · 같은 PHP 를 `C:\php` 로 옮겨 실음 **2 → 2**. 같은 넷에서 `evilai-locust` 0.2.0 은 **0 → 0** |
| 실기계 · 서비스 · Apache 설정 | 수집 → 판정 | **6/6** | 2026-11-12 · 같은 랩 VM · 같은 두 판 — 스냅숏 **0 → 0** · 선언 밖 PHP 의 `php-cgi.exe` 를 띄우는 서비스(만들기만 · 시작 안 함) **0 → 6** · Apache 설정이 그 PHP 의 `php8apache2_4.dll` 을 실음 **0 → 6** · 같은 줄이 `C:/php` 를 가리킴 **0 → 0** · Node.js 설치 자리 · Node 서비스만 바꾼 둘 **0 → 0**. `evilai-locust` 0.2.0 은 여섯 다 **0 → 0** |
| 실기계 · NSSM | 수집 → 판정 | **7/7** | 2026-11-12 · Windows 랩 VM 에서 0.3.0(코어 1.9.0 공개본)과 0.4.0(1.10.0 개발 빌드)을 같은 상태에서 나란히 — 스냅숏 **0 → 0** · Node.js 폴더를 치움 **0 → 0** · NSSM 꼴 서비스(만들기만 · 시작 안 함 · `ImagePath` 는 `nssm.exe`)의 `Application` 이 선언 밖 `C:\inetpub\php83\php-cgi.exe` **0 → 6** · 선언 밖 `node.exe` **0 → 0** · `%SystemDrive%\php\php-cgi.exe`(선언한 자리) **0 → 0** · 이름만 `php-cgi.exe` **0 → 6** · `Program Files\nodejs\node.exe` **0 → 0**. 항목 줄은 `HKLM\SYSTEM\CurrentControlSet\Services\<이름>\Parameters\Application  (값 <경로>)`. `evilai-locust` 0.2.0 은 일곱 다 **0 → 0** |

린트 경고 둘(`C:\php` 깊이 2 · 판정이 규칙 하나)은 룰 머리에 까닭을 적었다.

## 서명 — 저장소 사본은 개발용 키, 배포본은 배포 키

저장소의 `MANIFEST` · `MANIFEST.minisig` 는 저장소 사본을 확인하려고 **개발용 키로** 서명한 것이다. 배포본은
태그의 배포 잡이 배포 키로 다시 서명하고 그 공개키를 박아 빌드하므로, 내려받은 배포 파일에 든 이 폴더는 배포
키의 서명이다(`plugin verify` 로 확인한다). 개발용 키로 서명된 룰은 배포 앵커가 박힌 실행 파일에서 거부된다.
