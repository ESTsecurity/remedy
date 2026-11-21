# remedy-net-criteria — 릴리스 기록

**버전 1.1.3** · 데이터 룰(`kind: data`) — 동반 프로그램 `remedy-net` 이 읽는 판정 기준 · Windows · 리눅스 ·
**이 기계를 보지 않는다**(메뉴 · 위협 표에 서지 않는다)

## 1.1.3 — 같은 표를 가진 점검 룰의 판 (2026-11-20)

`url.json` 의 `same_as` 를 `php2shell-check-linux` 0.6.3 에 맞췄다 — 그 판은 RPM 자리의 패키지 밖 PHP 를 짚는 규칙만
더했고 배포판 줄(이 표의 값)은 그대로다. 기준의 값과 `baseline.json` 은 1.1.2 와 같다.

## 1.1.2 — 같은 표를 가진 점검 룰의 판 (2026-11-20)

`url.json` 의 `same_as` 를 `php2shell-check-linux` 0.6.2 에 맞췄다 — 그 판은 공식 Docker 이미지 `php:8.3.37-*` 의 해시만
더했고 배포판 줄(이 표의 값)은 그대로다. 기준의 값과 `baseline.json`(`2026-10-30.12` · 바이트 그대로)은 1.1.1 과 같다 —
그래서 이미지 · 컨테이너 점검에서 `php:8.3.37` 등 11월 보안 업데이트의 공식 빌드는 전처럼 *확인 필요* 다.

## 1.1.1 — 같은 표를 가진 점검 룰의 판 (2026-11)

`url.json` · `apache.json` 의 `same_as` 를 본체의 점검 룰이 올린 판(`php2shell-check-linux` 0.6.1 ·
`apache-http2-check-linux` 0.1.2 — 같은 제품의 묶음 열쇠 `product` 만 더한 판)에 맞췄다. 기준의 값(고친 판 · 영향 범위)과
`baseline.json` 은 1.1.0 과 같다.

## 1.1.0 — Apache HTTP/2 기준 (2026-11 · 코어 1.18.0)

이미지 · 컨테이너 점검의 Apache HTTP/2 모듈(mod_http2) 원격 코드 실행(CVE-2026-119618) 기준 `apache.json` 을
더했다. 값은 본체의 점검 룰 `apache-http2-check-linux` 0.1.1 의 고친 판 표 그대로다 — 공급사 줄 21(Debian ·
Ubuntu 8 · RHEL · Rocky · Amazon Linux 11 · SUSE 고침 대기 1 · Alpine 1) · 상류 영향 범위 httpd 2.4.55 ~ 2.4.70
(고친 판 2.4.71) · mod_h2 2.0.8 ~ 2.0.42 · 확인 2026-11-13. `url.json` · `baseline.json` 은 1.0.0 과 같은 바이트다.

`baseline.json` 에 넣지 않은 까닭 — 그 파일은 사내 runtime-scanner 의 형식 그대로(바이트 그대로)이고, 그 형식은
영향 하한(상류 2.4.55)과 *영향 없음*(RHEL 8 의 mod_http2 1.15)을 담지 못한다. `apache.json` 은 코어 1.18.0 의
remedy-net 만 읽는다(`min_core`).

## 1.0.0 — 처음 (2026-11)

remedy-net 1.11.0 까지 바이너리에 들어 있던 기준을 그대로 옮겼다 — 값이 같아 판정도 같다. 코어 1.12.0 부터
remedy-net 은 기준을 이 폴더에서만 읽는다.

| 파일 | 무엇 | 지금 값 |
|---|---|---|
| `url.json` | 원격 점검(url)의 PHP2Shell 수정 버전 표 | 상류 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12 · 지원이 끝난 계열 열 · Ubuntu · Debian 공지 줄 열 · 확인 2026-11-09 · 같은 표의 룰 `php2shell-check-linux 0.6.0` |
| `baseline.json` | 이미지 · 컨테이너 점검의 PHP · Node.js · Brotli 기준 | `2026-10-30.12`(사내 runtime-scanner 형식 2 · 바이트 그대로 · SHA-256 `2fd679f4…`) — PHP 해시 37 · Node 해시 555 |
| `apache.json`(1.1.0) | 이미지 · 컨테이너 점검의 Apache HTTP/2 기준 | 형식 1 · 공급사 줄 21 · 확인 2026-11-13 · 같은 표의 룰 `apache-http2-check-linux 0.1.1` |

## 어떻게 쓰이나

remedy-net 은 점검을 시작할 때 꾸러미의 `plugins/remedy-net-criteria/` 를 본체가 룰 폴더를 확인하는 것과 같은
사슬로 확인한다 — 배포 키의 서명 · 파일이 서명한 그대로인가(더해진 것도 빠진 것도 없다) · 서명 주석의 이름이
`remedy-net-criteria` 인가. 확인한 뒤 파일을 읽을 때도 해시를 다시 본다. 하나라도 어긋나면 **점검하지 않고**
종료 4 로 끝난다(약관을 묻기 전 · 결과 폴더도 없다).

## 기준을 바꾸려면

1. 이 폴더의 파일을 고친다 — 꼴은 remedy-net 이 읽는 형식 그대로다(모르는 칸 · 견줄 수 없는 꼴은 거부한다).
2. 같은 공지의 값이 본체의 점검 룰(`php2shell-check-*` · `node2shell-check-*` · `apache-http2-check-linux`)에도
   있으면 함께 고친다.
3. `plugin.yaml` 의 `version` 을 올린다 — `plugin-lock` 이 이 폴더의 데이터 파일까지 잠근다.
4. `cargo xtask net-criteria` — 세 파일이 remedy-net 의 코드로 읽히는지, 본체의 점검 룰과 같은 값인지 본다.
5. 서명하고 배포한다. **remedy-net 은 다시 짓지 않는다.**

## 게이트

| # | 게이트 | 상태 | 근거 |
|---|---|---|---|
| 형식 | remedy-net 이 읽는다 | **통과** | `cargo xtask net-criteria` — 실행 때와 같은 코드(`remedy_net::criteria::check_texts` · 세 파일) |
| 대조 | 본체의 점검 룰과 같은 값 | **통과** | `cargo xtask net-criteria` — url 표 · 수정 버전 · PHP 해시 37 · Node 해시 555 가 룰 넷과, Apache 고친 판 18(서로 다른 값) · RPM 공급사 · 영향 범위의 끝 · 줄의 하한 · 지원 하한이 `apache-http2-check-linux` 0.1.1 과 같다. 값 하나를 바꾸면 잡는다(xtask 시험 `a_changed_apache_value_is_caught` — 여섯 가지) |
| 서명 | 없거나 · 바뀌었거나 · 다른 키 · 다른 룰의 서명 | **거부** | `crates/remedy-net/tests/cli.rs` — 여섯 경우 × url · image · container 모두 종료 4 · 약관 없음 · 결과 폴더 없음 |
| 다시 짓지 않고 | 기준만 고쳐 다시 서명하면 판정이 바뀐다 | **통과** | 2026-11-13 · 같은 remedy-net 개발 빌드 · 모의 서버의 헤더 `PHP/8.3.38` — 이 폴더 그대로 **6**, 사본의 8.3 수정 버전을 8.3.40 으로 올린 뒤 서명 전 **4**(내용이 서명과 다르다), 다시 서명한 뒤 **2**. Apache(1.1.0 · 2026-11-14 · 같은 1.18.0 개발 빌드 · Debian 12 하네스 이미지의 apache2-bin `2.4.71-1~deb12u1`): 이 폴더 그대로 **0**, 사본의 Debian 12 고친 판을 `2.4.72-1~deb12u1` 로 올린 뒤 서명 전 **4**, 다시 서명한 뒤 **6**(영향 판 · HTTP/2 꺼짐) |

## 서명 — 배포본은 배포 키

저장소의 이 폴더에는 서명이 없다(2026-11-21 부터 — 그 전에는 저장소 사본을 확인하려고 **개발용 키로** 서명한 `MANIFEST` ·
`MANIFEST.minisig` 를 두었다). 배포본은 태그의 배포 잡이 배포 키로 서명하고, remedy-net 은 그 배포 키를 박아 짓는다. 개발 빌드의
remedy-net 에는 그 자리에서 일회용 키로 서명한 사본과 그 공개키를 준다(`ci/dev-sign.sh`).
