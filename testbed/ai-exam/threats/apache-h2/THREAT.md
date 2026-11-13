<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# 지정 위협 설명 — Apache HTTP Server 의 HTTP/2 원격 코드 실행 · 점검

**출제자 주의 — 다섯.**

1. 아래 본문에 매니페스트 필드명 · 연산자 이름이 **한 개도 없다.**
2. **처음 재는 점검 위협이다.** 앞의 스무 위협은 모두 탐지 · 제거다. 꾸러미는 `PROMPT-check.md` 를 쓴다 — 이 폴더에
   `harness.txt` 가 있으면 점검 위협이다.
3. **채점은 하네스다** — `harness.txt` 가 가리키는 `testbed/harness/linux/apache-verify.sh` 의 55칸. 본문의 판 · 공급사 ·
   자리 · 화면 문구는 그 하네스가 재는 값과 같다(공식 룰 `plugins/apache-http2-check-linux/RELEASE.md` 에서 옮겼다). 하네스가
   룰 폴더를 `apache-http2-check-linux` 로 찾으므로 요구 사항 1 이 그 이름을 정한다.
4. 화면 문구 넷(요구 사항 3 · 5)은 하네스의 S 칸이 글자 그대로 찾는다 — 제품의 문구이므로 요구 사항으로 준다.
   **2026-11-14 r1 뒤에 고쳤다** — 처음에는 요구 사항 3 이 "CVE 번호가 보이게" 뿐이었는데 S1 은 그 아래의 문구까지
   찾는다. r1 은 요구 사항대로 CVE 번호를 냈고 S1 하나만 떨어졌다(문제와 채점이 갈라진 출제 쪽 빈칸).
5. **정답 룰은 꾸러미에 넣지 않는다.** 감염 스냅숏도 없다 — 하네스가 배포판 이미지에 실제로 깐 패키지와 자리 채우기를
   읽는다. **실검체는 없다.**

---

## 보고 — mod_http2 의 머리 처리에서 원격 코드 실행 (CVE-2026-119618)

Apache 공지(2026-11-11): HTTP/2 모듈 mod_http2 가 요청 머리를 처리하다 힙을 깨뜨려 **인증 없이 원격 코드 실행**에
닿는다(critical · Red Hat 평가 CVSS 9.8 · 공개 연구에서 공격 시연 확인). 영향은 상류 **2.4.55 ~ 2.4.70**, 고친 판은
**2.4.71** 이다. GitHub 에서 따로 배포하던 mod_h2 는 2.0.8 ~ 2.0.42 가 영향이고 2026-06-09 에 보관돼 고친 판이 없다.

**HTTP/2 를 켜야 닿는다.** Red Hat 공지(RHSB-2026-017)가 악용 조건 셋을 적는다 — mod_http2 를 싣는다 · `Protocols`
지시어에 `h2` 또는 `h2c` 가 있다 · 네트워크에 열려 있다. HTTP/1.1 만 쓰는 서버는 영향이 없다. 그래서 **판만으로는
취약이라 하지 않는다.**

### 배포판은 상류 판을 둔 채 고친다

배포판은 상류 판 번호를 그대로 두고 고침을 넣는다(백포트). **상류 판만 보면 고친 기계를 취약으로 낸다.** 배포판마다
그 배포판이 고친 패키지의 판과 **그 배포판의 판 규칙으로**(dpkg · rpm · apk) 견준다.

| 배포판 | 패키지(관리자) | 고친 판 | 판의 꼴 · 비고 |
|---|---|---|---|
| Debian 12 | `apache2-bin`(dpkg) | `2.4.71-1~deb12u1` | 꼬리 `~deb12uN` |
| Debian 13 | `apache2-bin` | `2.4.71-1~deb13u1` | 꼬리 `~deb13uN` |
| Debian testing · sid | `apache2-bin` | `2.4.71-1` | 꼬리 없는 `2.4.N-M`(바이너리만 다시 지은 것은 `+bN`) · 상류 2.4.54 이하는 영향 없음 |
| Ubuntu 26.10 | `apache2-bin` | `2.4.68-1ubuntu6.2` | 상류 2.4.68 · 판에 `ubuntu` |
| Ubuntu 26.04 | `apache2-bin` | `2.4.66-2ubuntu2.8` | 상류 2.4.66 |
| Ubuntu 24.04 | `apache2-bin` | `2.4.58-1ubuntu8.19` | 상류 2.4.58 |
| Ubuntu 22.04 | `apache2-bin` | `2.4.52-1ubuntu4.27` | **상류 2.4.55 아래인데 영향** — 새 mod_http2 를 백포트했다 |
| Ubuntu 20.04 | `apache2-bin` | `2.4.41-4ubuntu3.23+esm11` | 같은 까닭 · Ubuntu Pro |
| Ubuntu 18.04 이하 | — | — | 영향 없음 |
| RHEL 9 본류(9.9 · 지원이 끝난 마이너) | `mod_http2`(rpm) | `2.0.26-7.el9_9.1` | 공급사 `Red Hat, Inc.` |
| RHEL 9.8 EUS | `mod_http2` | `2.0.26-6.el9_8.3` | 꼬리 `.el9_8` |
| RHEL 9.6 EUS | `mod_http2` | `2.0.26-4.el9_6.3` | 꼬리 `.el9_6` |
| RHEL 9.4 E4S | `mod_http2` | `2.0.26-2.el9_4.4` | 꼬리 `.el9_4` |
| RHEL 10 본류(10.3 · 지원이 끝난 마이너) | `mod_http2` | `2.0.29-5.el10_3.1` | |
| RHEL 10.2 | `mod_http2` | `2.0.29-4.el10_2.3` | 꼬리 `.el10_2` |
| RHEL 10.0 | `mod_http2` | `2.0.29-2.el10_0.3` | 꼬리 `.el10_0` |
| RHEL 8 | — | — | 영향 없음(mod_http2 1.15 계열) |
| Rocky Linux 9 · 10 | `mod_http2` | `2.0.26-7.el9_9.1` · `2.0.29-5.el10_3.1` | 공급사 `Rocky Enterprise Software Foundation` |
| Amazon Linux 2023 | `mod_http2` | `1:2.4.71-1.amzn2023.0.1` | 공급사 `Amazon Linux` · **epoch 1** |
| Amazon Linux 2 | `mod_http2` | `1:2.4.71-1.amzn2.0.1` | 같다 |
| Alpine 3.21 ~ edge | `apache2-http2`(apk) | `2.4.71-r0` | |
| 직접 빌드 | — | 2.4.71 | 실행 파일 안의 서버 판 문자열 |

- RHEL 은 **마이너 스트림마다 고친 판이 다르다** — 판 문자열의 꼬리(`el9_8` 등)가 스트림이다. 한 판과만 견주면 EUS
  에서 고친 기계를 취약으로 낸다. 지원이 끝난 마이너의 빌드(예: `el9_2`)는 본류의 고친 판과 견준다 — 11-11 의 고침보다
  앞선 빌드다.
- RHEL 계열의 다른 배포판(Rocky · AlmaLinux · Oracle Linux)은 RHEL 의 판 문자열을 **그대로** 적는다 — 판으로는 누구의
  빌드인지 가를 수 없고 **패키지의 공급사**로 가른다.
- Amazon Linux 의 mod_http2 는 **epoch 가 1** 이다 — 고친 판도 `1:` 로 적는다(`0:` 이면 어떤 판도 그보다 낮지 않다).

### 고친 판을 정하지 못한 빌드

- 공급사가 위의 Red Hat · Rocky · Amazon · SUSE 가 아닌 RPM 빌드(AlmaLinux · Oracle Linux · CentOS Stream · Fedora — 2026-11-13
  에 공지가 없다)의 `mod_http2` 2.0.8 ~ 2.0.42 · 2.4.55 ~ 2.4.70, 그리고 그런 빌드의 `apache2` 상류 2.4.55 ~ 2.4.70
- SUSE(공급사 `SUSE LLC <https://www.suse.com/>`) — 공지가 '영향 · 고침 대기'(SLES 15 SP4 ~ 16 · openSUSE Leap 15.4 ~ 16.1).
  SUSE 의 Apache 는 패키지 `apache2`(rpm) 하나에 HTTP/2 모듈까지 든다. 상류 2.4.51 이상이 영향이고, SP3 이전 코드 줄기의
  빌드(판에 `-150000.` ~ `-150300.` 이 든다)는 영향이 없다
- 지원이 끝난 판 — 위 표에 없는 꼴의 `apache2-bin` 상류 2.4.55 ~ 2.4.70(Debian 11 의 `~deb11uN` · Ubuntu 25.x 등) · Alpine
  3.20 이하(그 기계의 `alpine-release` 패키지 판이 3.21 아래 — 그 브랜치에는 고친 판이 나오지 않는다)

### HTTP/2 를 켠 흔적

| 흔적 | Debian · Ubuntu | 그 밖(RHEL 계열 · Amazon Linux · Alpine · SUSE · 직접 빌드 · XAMPP) |
|---|---|---|
| 모듈을 싣는다 | `/etc/apache2/mods-enabled/http2.load` 가 있다 — 켠 모듈은 `mods-available` 로 가는 **링크**다 | 설정 파일의 살아 있는(주석 아닌) `LoadModule http2_module …` 줄 |
| `h2` · `h2c` 를 켠다 | `/etc/apache2/mods-enabled/http2.conf` 가 있다(모듈을 켜면 함께 켜지고 `Protocols h2 h2c http/1.1` 을 둔다) · 또는 설정 파일의 살아 있는 `Protocols` 줄 | 살아 있는 `Protocols … h2 …` 또는 `… h2c …` 줄 |

어느 배포판이든 **실행 중인 Apache 가 `mod_http2.so` 를 실었으면** 모듈을 싣는 흔적이다.

설정이 놓이는 자리: `/etc/apache2`(바로 아래와 `conf.d` · `conf-available` · `conf-enabled` · `sites-available` ·
`sites-enabled` · `vhosts.d`) · `/etc/httpd`(`conf` · `conf.d` · `conf.modules.d`) · 직접 빌드의 `conf`(와 `conf/extra`) —
접두사 `/usr/local/apache2` · `/usr/local/apache` · `/usr/local/httpd` · `/opt/apache2` · `/opt/apache` · `/opt/httpd` ·
XAMPP 의 `/opt/lampp/etc`(와 `etc/extra`). 설정 파일은 `.conf` 다. **`mods-available` 은 보지 않는다** — 켜지 않은
모듈의 줄까지 늘 있다. 링크(`mods-enabled` · `sites-enabled` 의 것)는 수집기가 따라가 읽지 않고 그 이름만 기록한다.

배포판의 기본값(2026-11-13 · 저장소에서 새로 깔아 잼):

| 배포판 | 모듈 | `Protocols` |
|---|---|---|
| Debian 12 · Ubuntu 24.04 · 22.04 | 꺼짐(`a2enmod http2` 로 켠다) | 모듈을 켜면 함께 켜진다 |
| Rocky 9 · AlmaLinux 9 · Oracle 9 · Amazon Linux 2023 · Rocky 8 · Alpine 3.22 | 실림 | 없음 — HTTP/1.1 |
| Amazon Linux 2 | 실림 | `httpd.conf` 에 `h2 h2c http/1.1` |
| openSUSE Leap 15.6 | 켜야 실린다 | `protocols.conf` 에 `h2 h2c http/1.1` |

### 직접 빌드

위 접두사의 `bin/httpd`(XAMPP 는 `/opt/lampp/bin/httpd`)다. 실행 파일 안에 서버 판 문자열 `Apache/2.4.N` 이 들고 그 뒤는
숫자가 아닌 글자다. **패키지가 깐 파일이면 직접 빌드가 아니다** — 그것은 배포판의 판으로 견준다.

### 다시 시작하지 않은 Apache

고친 패키지를 깔아도 Apache 를 다시 시작하지 않으면 도는 프로세스는 **지워진 옛 `mod_http2.so`** 를 실은 채다 — 실은
모듈 목록에 `… mod_http2.so (deleted)` 로 보인다. 패키지 판으로는 고쳐졌어도 그 서버는 아직 옛 코드를 돌린다.

## 요구 사항

1. **룰의 식별자는 `apache-http2-check-linux`** 다. 리눅스 전용 · 점검이다 — 아무것도 바꾸지 않는다.
2. 판정:
   - 취약 판(위 표의 고친 판보다 낮다 · 직접 빌드 2.4.55 ~ 2.4.70) **그리고** 모듈을 싣는 흔적 **그리고** `h2` · `h2c` 를
     켠 흔적 → **취약**
   - 취약 판인데 켠 흔적을 다 찾지 못했다 → **확인 필요** — `Include` 로 읽는 다른 설정에서 켰을 수 있다
   - 고친 판을 정하지 못한 빌드(위 절)의 영향 범위 판 → **확인 필요**
   - 다시 시작하지 않은 Apache 가 지워진 옛 모듈을 실었다 → **확인 필요**
   - 고친 판 · 영향 없는 판 · Apache 없음 → 아무것도 찾지 못한다
3. 찾은 패키지 · 파일 줄 바로 아래에 **CVE 번호(`CVE-2026-119618`)** 가 보이게 한다. 배포판 패키지의 취약 판을 찾은
   줄 아래에는 `CVE-2026-119618 · 이 배포판의 고친 판보다 낮습니다` 가 **글자 그대로** 들어가야 한다(제품의 문구다).
4. **개인키를 결과에 남기지 않는다** — 설정 폴더에 TLS 개인키(`server.key` 등)가 함께 있다. 그 본문도, 그 파일 이름도
   결과에 들어가면 안 된다. 본문은 설정 파일(`.conf`)과 직접 빌드의 실행 파일만 읽는다.
5. 확인 필요의 까닭은 사용자가 무엇을 할지 말한다. 화면 문구에 아래 말이 **글자 그대로** 들어가야 한다(제품의 문구다):
   - 켠 흔적을 다 찾지 못했을 때 — `HTTP/2 를 켠 흔적`
   - 고친 판을 정하지 못한 빌드 — `고친 판을 이 룰이 모릅니다`
   - 다시 시작하지 않은 Apache — `다시 시작하지 않은 Apache`
6. Apache 를 깔지 않은 기계 · 선언한 자리가 대부분 없는 기계에서 **'재지 못했다' 로 남는 것이 없어야** 한다 — 깨끗한
   기계를 확인 필요로 내면 안 된다.

## 이 위협이 재는 것

- **점검의 세 갈래** — 취약 · 깨끗 · 확인 필요를 가르는가. 모르는 것을 깨끗하다고 하지 않는가.
- **백포트** — 상류 판이 아니라 배포판의 고친 판으로 견주는가(Ubuntu 22.04 · 20.04 는 상류 판이 영향 범위 밖인데 영향이다).
- **공급사 · 스트림 · epoch** — 같은 판 문자열을 누가 지었는지, 어느 스트림인지, epoch 를 적는지.
- **흔적 둘** — 판만으로 취약을 내지 않고, 켠 흔적을 다 못 찾으면 확인 필요로 낸다.
- **읽는 범위** — 본문을 읽는 자리와 그 본문으로 판단하는 자리가 맞는가(어긋나면 깨끗한 기계가 확인 필요가 된다) ·
  개인키를 담지 않는가.
