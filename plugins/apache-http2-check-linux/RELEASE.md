# apache-http2-check-linux — 릴리스 기록

**버전 0.1.3** · 대상: Apache HTTP Server 의 mod_http2 원격 코드 실행(CVE-2026-119618) — 리눅스 · **점검**(바꾸지 않는다)

## 0 을 내는 갈래

| 갈래 | 근거 | 하네스 칸 |
|---|---|---|
| Debian 12 · 13 · sid 의 `apache2-bin` 이 그 판의 고친 판 이상 | DLA-4902-1 · DSA-6620-1 — 고친 판 2.4.71-1~deb12u1 · 2.4.71-1~deb13u1 · 2.4.71-1 | `b01` |
| Ubuntu 26.10 ~ 20.04 의 `apache2-bin` 이 그 판의 고친 판 이상(22.04 · 20.04 는 상류 2.4.55 아래의 백포트) | USN-9090-1 — 고친 판 2.4.68-1ubuntu6.2 · 2.4.66-2ubuntu2.8 · 2.4.58-1ubuntu8.19 · 2.4.52-1ubuntu4.27 · 2.4.41-4ubuntu3.23+esm11 | `b07` · `b09` |
| RHEL 9 · 10 의 `mod_http2` 가 그 마이너 스트림의 고친 판 이상(EUS · E4S 포함) | RHSA-2026:98981 · 98982 · 98954 · 98968 · 98978 · 98979 · 98953 — 스트림마다 고친 판(9.9 · 9.8 EUS · 9.6 EUS · 9.4 E4S · 10.3 · 10.2 · 10.0) | `h02` · `h03` · `h06` |
| Rocky Linux 9 · 10 의 `mod_http2` 가 고친 판 이상 | RLSA-2026:98981 · 98978 — 고친 판 2.0.26-7.el9_9.1 · 2.0.29-5.el10_3.1 | `r01` · `r11` |
| Amazon Linux 2023 · 2 의 `mod_http2` 가 고친 판 이상(epoch 1) | ALAS2023-2026-3458 · ALAS2-2026-4114 — 고친 판 1:2.4.71-1.amzn2023.0.1 · 1:2.4.71-1.amzn2.0.1 | `r07` · `r09` · `r12` |
| Alpine 3.21 ~ edge 의 `apache2-http2` 가 2.4.71-r0 이상 | Alpine 보안 추적기 — 고친 판 2.4.71-r0 | `p01` |
| 직접 빌드 `httpd` 의 판 문자열이 2.4.71 이상 | Apache 공지 — 영향 2.4.55 ~ 2.4.70 · 고친 판 2.4.71 | `x03` |
| RHEL 8 계열(Rocky 8 포함)의 `mod_http2` 1.15 | Red Hat CSAF VEX(`cve-2026-119618.json` 판 3) — RHEL 8 영향 없음 | `r04` · `h07` |
| Ubuntu 18.04 이하의 `apache2-bin`(상류 2.4.54 이하) | 근거 없음 — 18.04 이하가 영향 없다는 출처 줄이 없다(USN-9090-1 의 고친 판은 26.10 ~ 20.04 · 상류 2.4.55 아래의 영향은 22.04 · 20.04 의 백포트) | `b13` |
| 상류 2.4.54 이하의 Debian · Alpine 패키지 · 직접 빌드 | Apache 공지 — 영향 판이 2.4.55 부터다(2.4.55 ~ 2.4.70) | 없음 |
| SUSE 의 SP3 이전 코드 줄기 | SUSE CVE 페이지 — SP3 이전 코드 줄기는 영향 없음 | 없음 |
| Apache 는 있고 mod_http2 를 담은 패키지가 없다(RPM 의 `mod_http2` · Alpine 의 `apache2-http2`) | RHSB-2026-017 — 악용 조건 셋의 하나가 mod_http2 적재다 | 없음 |
| 고친 판을 깔고 다시 시작한 Apache 가 돈다(실린 `mod_http2.so` 가 지워지지 않았다) | 판정표의 확인 필요는 다시 시작하지 않아 지워진 옛 `mod_http2.so` 를 실은 Apache 뿐 — 결과 읽기가 올린 뒤 다시 시작하라고 적는다 | 없음 |
| Apache 없음 | 공지의 영향 제품이 없다 | `n01` · `n02` |

## 0.1.3 — 판을 읽지 못한 직접 빌드는 확인 필요 (2026-11-22)

- **패키지가 깔지 않은 `httpd`(`/usr/local/apache2` · `/usr/local/httpd` · `/opt/apache2` · `/opt/httpd` · `/opt/lampp` 의
  `bin/httpd`)에서 판 문자열 `Apache/<판>` 을 읽지 못하면 확인 필요(6)다.** 0.1.2 까지는 `vulnerable_src` 의 YARA 가 영향 판을
  찾지 못하면 어느 줄에도 걸리지 않아 0 이었다 — 판을 모르는 것을 영향 밖으로 읽었다. 같은 경우 nginx · PHP 룰은 6 을 낸다.
  이 기록의 *0 을 내는 갈래* 표를 채우며 근거 없는 0 갈래로 드러났다. 새 YARA 규칙 `apache_version_string`(어느 판이든
  `Apache/<판>`)과 규칙 `src_httpd` · `src_version_known` 을 더했다(nginx 룰의 `nginx_src and not src_version_known` 과 같은 꼴).
- **하네스를 상류에 고정했다** — Rocky 9 · Amazon Linux 2023 의 저장소가 고친 판을 깔아, 러너가 새로 지은 이미지에서 '깐
  그대로 취약' 을 전제한 일곱 칸(A4 · A5 · r01 ~ r03 · r07 · r08)이 0 으로 뒤집혔다(2026-11-22 러너 48/55 · 룰은 맞게 0).
  깐 그대로는 고친 판 칸(r01 · r07 · 새 r11 · r12 — 0)으로 두고, 취약 판은 그 공급사 꼴의 빈 rpm 으로 채운다(r02 · r03 ·
  r08 — `rh-rpm.sh` 가 공급사 · epoch 를 받는다). 판 문자열 없는 직접 빌드 칸 x05 를 더했다(58칸).
- Amazon Linux 2023 이미지는 최신 릴리스의 저장소(`dnf --releasever=latest`)로 깐다 — 저장소 판이 바탕 이미지의 릴리스에 묶여,
  예전에 받은 `amazonlinux:2023` 은 고치기 전 판(1:2.4.69)을, 러너가 새로 받은 것은 고친 판(1:2.4.71)을 깔았다(같은 날).
- 판정 줄 · 영향 판 · 고친 판은 0.1.2 와 같다.

### 게이트 (0.1.3)

| 게이트 | 무엇 | 결과 | 근거 |
|---|---|---|---|
| 하네스 | `testbed/harness/linux/apache-verify.sh` | **58/58** | 2026-11-22 · 코어 1.25.3 musl 정적 개발 빌드 · WSL 의 docker · Rocky 9 · Amazon Linux 2023 이미지를 그날의 저장소로 다시 지어(러너와 같은 꼴) — 0.1.2 로 같은 하네스를 돌리면 57/58(x05 가 0) |
| G9 | 룰의 검체 오탐(YARA) | **통과**(점검 룰 기준) | 2026-11-22 · 정상 설치 열넷(Apache 하네스 이미지 열하나 — Rocky 9 · Amazon Linux 2023 은 그날의 저장소로 다시 지었다 · OpenSSH 하네스 이미지 셋)의 `/etc` · `/usr` · `/opt` 파일 78,543 · 링크 11,660 에 `cargo xtask yara`(64 MiB 상한) — 새 규칙 `apache_version_string` 맞음 50(모두 배포판이 깐 Apache 실행 파일 · 모듈: `/usr/sbin/httpd` · `apache2` · `httpd-prefork` · 모듈 폴더 — 룰은 이 YARA 를 패키지가 깔지 않은 직접 빌드의 `bin/httpd` 에만 건다) · `apache_version_affected` 24(같은 꼴 · 0.1.1 의 28 에서 다시 지은 AL2023 이 고친 판이라 줄었다) · `apache_h2_loadmodule` 10 · `apache_h2_protocols` 8(둘 다 0.1.1 과 같다). 못 훑은 것은 리눅스 링크뿐(11,660). 잰 `rules/apache.yar` 는 SHA-256 `49826377…` |
| G1 | 청정 환경 무해성 | PR CI | `cargo xtask g1` — 리눅스 스냅샷 19개 |

## 0.1.2 — 같은 제품의 묶음 열쇠 (2026-11)

같은 제품의 점검 룰을 묶는 열쇠 `product: Apache HTTP Server` 를 적었다(코어 1.21.0 — 화면이 같은 제품의 발견을 한 덩어리로
묶는다). 판정 · 찾는 자리는 0.1.1 과 같다. 코어 1.21.0 이 필요하다.

## 0.1.1 — 기록 정리 (2026-11)

**판정은 0.1.0 과 같다** — 바뀐 것은 기록뿐이다. 게이트 표에 G9 줄을 더했다(1.15.0 공개 뒤에 잰 값 — 공개 전에
빠뜨렸다). Windows 는 이제 `apache-http2-check-windows`(코어 1.17.0)가 보므로 '다음 판' 이라는 말을 고쳤다.

## 0.1.0 — 처음 (2026-11)

**긴급 경로로 낸 첫 룰이다** — 코어를 바꾸지 않고 코어 1.14.0 의 능력(`pkg_version_lt` · `rpm_version_lt` ·
`apk_version_lt` · `label` · `file_names` · `glob` 본문 수집 · 프로세스의 실린 모듈)만 쓴다.

## 무엇을 하나

| 갈래 | 판정 |
|---|---|
| 배포판 패키지가 그 배포판의 고친 판보다 낮다 · 직접 빌드가 2.4.55 ~ 2.4.70 이다 — **그리고** HTTP/2 를 켠 흔적(모듈 적재 + `Protocols` 의 `h2` · `h2c`)이 있다 | **취약(2)** — 버전 아래 줄에 CVE |
| 판은 취약인데 HTTP/2 를 켠 흔적을 다 찾지 못했다 | **확인 필요(6)** — `Include` 로 읽는 다른 설정에서 켰을 수 있다 |
| 영향 범위의 판인데 고친 판을 이 룰이 모르는 빌드 — 공지가 아직 없는 공급사(AlmaLinux · Oracle Linux · CentOS Stream · Fedora) · 고침을 기다리는 SUSE · 지원이 끝난 판(Debian 11 · Ubuntu 25.x · Alpine 3.20 이하) · 그 밖의 빌드 | **확인 필요(6)** |
| 고친 패키지를 깔았지만 다시 시작하지 않은 Apache 가 지워진 옛 `mod_http2.so` 를 실었다 | **확인 필요(6)** |
| 고친 판 · 영향 없는 판(RHEL 8 의 mod_http2 1.15 · Ubuntu 18.04 이하 · 상류 2.4.54 이하) · Apache 없음 | 0 |

**HTTP/2 를 켜야 닿는다** — Red Hat 공지(RHSB-2026-017)가 악용 조건을 셋으로 적는다: mod_http2 적재 · `Protocols` 의
`h2` 또는 `h2c` · 네트워크 노출. HTTP/1.1 만 쓰는 서버는 영향이 없다. 그래서 판만으로는 2 를 내지 않는다.

### HTTP/2 를 켠 흔적

| 흔적 | 어디서 |
|---|---|
| 모듈을 싣는다 | Debian 계열은 `/etc/apache2/mods-enabled/http2.load` — 켠 모듈은 링크라 수집기가 따라가 읽지 않지만 그 이름은 기록한다 · 그 밖은 살아 있는(주석 아닌) `LoadModule http2_module` 줄 · 실행 중인 Apache 가 실은 `mod_http2.so` |
| `h2` · `h2c` 를 켠다 | Debian 계열은 `/etc/apache2/mods-enabled/http2.conf`(모듈을 켜면 함께 켜지는 그 파일이 `Protocols h2 h2c http/1.1` 을 둔다) · 그 밖은 살아 있는 `Protocols … h2 \| h2c` 줄 |

설정 줄은 `/etc/apache2`(`mods-available` 은 빼고 — 켜지 않은 모듈의 줄까지 늘 있다) · `/etc/httpd` · 직접 빌드의
`conf` · XAMPP 의 `etc` 에서 YARA 로 본다. **YARA 의 경로는 본문을 담는 글롭의 범위와 같다** — 넓으면 본문 없는 레코드에서
*재지 못했다*(6)가 난다. 링크(`sites-enabled` 등)는 본문이 없어 세지 않는다.

배포판의 기본값(2026-11-13 · 저장소에서 새로 깔아 잼):

| 배포판 | 모듈 | `Protocols` |
|---|---|---|
| Debian 12 · Ubuntu 24.04 · 22.04 | 꺼짐(`a2enmod http2` 로 켠다) | `mods-available/http2.conf` 에 `h2 h2c http/1.1` — 모듈을 켜면 함께 켜진다 |
| Rocky 9 · AlmaLinux 9 · Oracle 9 · Amazon Linux 2023 · Rocky 8 · Alpine 3.22 | 실림(`10-h2.conf` · `conf.d/http2.conf`) | 없음 — HTTP/1.1 (mod_ssl 을 깔아도 그대로) |
| **Amazon Linux 2** | 실림 | **`httpd.conf` 에 `h2 h2c http/1.1`** |
| **openSUSE Leap 15.6** | `APACHE_MODULES` 로 켠다 | **`protocols.conf` 에 `h2 h2c http/1.1`** |

## 고친 판

| 배포판 | 패키지 | 고친 판 | 공지 |
|---|---|---|---|
| Debian 12 · 13 · sid | `apache2-bin` | 2.4.71-1~deb12u1 · 2.4.71-1~deb13u1 · 2.4.71-1 | DLA-4902-1 · DSA-6620-1 |
| Ubuntu 26.10 · 26.04 · 24.04 | `apache2-bin` | 2.4.68-1ubuntu6.2 · 2.4.66-2ubuntu2.8 · 2.4.58-1ubuntu8.19 | USN-9090-1 |
| Ubuntu 22.04 · 20.04 | `apache2-bin` | 2.4.52-1ubuntu4.27 · 2.4.41-4ubuntu3.23+esm11 (Ubuntu Pro) | 같은 공지 — **상류 2.4.55 아래인데 영향**(새 mod_http2 를 백포트했다) |
| RHEL 9.9 · 9.8 EUS · 9.6 EUS · 9.4 E4S | `mod_http2` | 2.0.26-7.el9_9.1 · 2.0.26-6.el9_8.3 · 2.0.26-4.el9_6.3 · 2.0.26-2.el9_4.4 | RHSA-2026:98981 · 98982 · 98954 · 98968 |
| RHEL 10.3 · 10.2 · 10.0 | `mod_http2` | 2.0.29-5.el10_3.1 · 2.0.29-4.el10_2.3 · 2.0.29-2.el10_0.3 | RHSA-2026:98978 · 98979 · 98953 |
| Rocky Linux 9 · 10 | `mod_http2` | 2.0.26-7.el9_9.1 · 2.0.29-5.el10_3.1 | RLSA-2026:98981 · 98978 |
| Amazon Linux 2023 · 2 | `mod_http2` (epoch 1) | 1:2.4.71-1.amzn2023.0.1 · 1:2.4.71-1.amzn2.0.1 | ALAS2023-2026-3458 · ALAS2-2026-4114 |
| Alpine 3.21 ~ edge | `apache2-http2` | 2.4.71-r0 | Alpine 보안 추적기 |
| 직접 빌드 | `httpd` | 2.4.71 | Apache 공지 |

RHEL 은 마이너 스트림마다 고친 판이 달라 스트림(`el9_8` 등)으로 줄을 가른다 — 한 판과만 견주면 EUS 에서 고친 기계를
취약으로 낸다. 지원이 끝난 마이너의 빌드(예: `el9_2`)는 본류의 고친 판과 견준다 — 11-11 의 고침보다 앞선 빌드다. 공급사가
먼저다 — Rocky · Alma · Oracle 이 RHEL 의 판 문자열을 그대로 적는다. Amazon Linux 의 `mod_http2` 는 epoch 가 1 이라
고친 판도 `1:` 로 적는다(`0:` 으로 적으면 어떤 판도 낮지 않다).

**고친 판이 없는 것** — GitHub 의 별도 mod_h2 는 2026-06-09 보관됐고 마지막 2.0.42 가 영향 범위(2.0.8 ~ 2.0.42)다. SUSE 는
공지가 '영향 · 고침 대기'(SLES 15 SP4 ~ 16 · Leap 15.4 ~ 16.1 · SP3 이전 코드 줄기는 영향 없음)다. AlmaLinux · Oracle
Linux 는 2026-11-13 에 공지가 없다(OSV · Oracle 의 CVE 페이지).

## 결과 읽기

| 종료 코드 | 뜻 |
|---|---|
| 2 | **취약** — 배포판의 보안 업데이트로 올리고(Debian · Ubuntu `apache2` · RHEL 계열 · Amazon Linux `mod_http2` · Alpine `apache2-http2`) Apache 를 **다시 시작**한다. 직접 빌드는 2.4.71 이상으로 다시 빌드한다. 올리기 전에는 `Protocols` 에서 `h2` · `h2c` 를 빼 HTTP/1.1 만 쓰게 한다 |
| 0 | 취약한 곳을 찾지 못했다 |
| 6 | **확인 필요** — `주의:` 아래 줄이 무엇을 확인할지 말한다 |

## 이 룰이 보지 않는 것

- 선언한 자리 밖의 직접 빌드(`/usr/local/apache2` 등의 `conf` · `bin` · XAMPP 밖) · 컨테이너 안 · Windows(Apache Lounge ·
  XAMPP — `apache-http2-check-windows` 가 본다)
- `Include` 로 다른 자리에서 읽는 설정 · `<VirtualHost>` · `<IfModule>` 안의 줄인지 — 흔적을 못 찾으면 확인 필요로 돌린다.
  Ubuntu 22.04 의 `http2.conf` 는 `Protocols` 를 `<IfModule !mpm_prefork>` 안에 두므로 prefork 로 돌면 켠 흔적이 있어도
  h2 가 꺼져 있을 수 있다
- 한 기계에 Apache 가 둘이면 HTTP/2 흔적을 설치본마다 가르지 않는다 — 기계 전체의 흔적이다
- **TLS 개인키** — 이름(`*.conf` · `http2.load` · `httpd`)으로만 기록 · 해시하므로 `*.key` · `*.pem` 은 읽지 않는다

## 근거 — 공개 자료 (2026-11-13 확인)

- Apache: `httpd.apache.org/security/vulnerabilities_24.html` — *"mod_http2: heap corruption and RCE in assign_headers"* ·
  2.4.55 ~ 2.4.70 · 2.4.71 · mod_h2 2.0.8 ~ 2.0.42
- Red Hat: RHSB-2026-017(악용 조건 · 완화) · CSAF VEX `cve-2026-119618.json` 판 3(고친 판 · RHEL 8 영향 없음)
- Debian 보안 추적기 · Ubuntu CVE 페이지 · Rocky(OSV `RLSA-2026:98981` · `98978`) · Amazon(ALAS2023-2026-3458 ·
  ALAS2-2026-4114) · Alpine 보안 추적기 · SUSE CVE 페이지
- mod_h2: `github.com/icing/mod_h2` — 2026-06-09 보관 · 마지막 v2.0.42

## 게이트

| # | 게이트 | 상태 | 근거 |
|---|---|---|---|
| G1 | 청정 환경 무해성 | **통과** | 2026-11-13 · 청정 코퍼스의 리눅스 스냅샷 13개(Alpine 3.21 · Debian 12 · Fedora 41 · Ubuntu 22.04)에 `remedy evaluate` — 모두 종료 0. 청정 코퍼스에는 Apache 가 깔린 기계가 없다 — Apache 를 깐 고친 기계의 0 은 아래 하네스가 잰다 |
| G2~G4 | 복원 · 계획 · 치료 | **미해당** | 바꾸는 것이 없다 |
| G9 | 룰의 검체 오탐(YARA) | **통과(공개 뒤)** | 2026-11-14 · 0.1.0(1.15.0) 공개 뒤에 쟀다 — 공개 전에 빠뜨렸다(`docs/긴급-대응.md` 의 1.15.0 기록). 정상 설치 열넷(Debian 12 · Ubuntu 24.04 · 22.04 · Rocky 9 · 8 · AlmaLinux 9 · Oracle Linux 9 · Amazon Linux 2023 · 2 · openSUSE Leap 15.6 · Alpine 3.22 · OpenSSH 하네스 이미지 셋)의 `/etc` · `/usr` 79,684개에 `cargo xtask yara`: `apache_h2_loadmodule` 10(모두 mod_http2 를 싣는 설정) · `apache_h2_protocols` 8(설정 5 · RHEL 계열이 까는 mod_http2 의 README 문서 3 — 룰은 YARA 를 설정 자리에만 건다) · `apache_version_affected` 28(모두 판 2.4.55 ~ 2.4.70 배포판의 Apache 실행 파일 · 모듈 — 룰은 패키지가 깔지 않은 직접 빌드의 `bin/httpd` 에만 건다). 못 훑은 것은 리눅스 링크뿐(11,660) · 16 MiB 를 넘은 3개는 64 MiB 상한으로 다시 읽어 맞음 0 |
| 하네스 | `testbed/harness/linux/apache-verify.sh` | **55/55** | 2026-11-13 · 코어 1.14.0 musl 정적 개발 빌드 · 경우마다 네트워크 없는 컨테이너 — 깐 판을 배포판 자신이 견줌 7(고친 판 Debian 12 · Ubuntu 24.04 · 22.04 · Alpine 3.22 · Amazon Linux 2 · **실제 취약 판** Rocky 9 `2.0.26-6.el9_8.2` · Amazon Linux 2023 `1:2.4.69`) · dpkg 13 · rpm 10 · RHEL 스트림 7(EUS 의 고친 판 0 · 끝난 마이너 2 · RHEL 8 0) · Alpine 4 · 직접 빌드 4(XAMPP 포함) · Apache 없음 2 · 다시 시작하지 않은 Apache 6 · 화면 다섯(찾은 줄 아래 CVE · 확인 필요 까닭 셋 · 미해소 경고 0) · **설정 폴더에 둔 가짜 TLS 키의 본문 · 기록 0** |

## 서명 — 배포본은 배포 키

저장소의 이 폴더에는 서명이 없다(2026-11-21 부터 — 그 전에는 저장소 사본을 확인하려고 **개발용 키로** 서명한 `MANIFEST` ·
`MANIFEST.minisig` 를 두었다). 배포본은 태그의 배포 잡이 배포 키로 서명하고 그 공개키를 박아 빌드하므로, 내려받은 배포 파일에 든
이 폴더는 배포 키의 서명이다(`plugin verify` 로 확인한다).
