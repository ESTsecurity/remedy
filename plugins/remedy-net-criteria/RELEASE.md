# remedy-net-criteria — 릴리스 기록

**버전 1.0.0** · 데이터 룰(`kind: data`) — 동반 프로그램 `remedy-net` 이 읽는 판정 기준 · Windows · 리눅스 ·
**이 기계를 보지 않는다**(메뉴 · 위협 표에 서지 않는다)

## 1.0.0 — 처음 (2026-11)

remedy-net 1.11.0 까지 바이너리에 들어 있던 기준을 그대로 옮겼다 — 값이 같아 판정도 같다. 코어 1.12.0 부터
remedy-net 은 기준을 이 폴더에서만 읽는다.

| 파일 | 무엇 | 지금 값 |
|---|---|---|
| `url.json` | 원격 점검(url)의 PHP2Shell 수정 버전 표 | 상류 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12 · 지원이 끝난 계열 열 · Ubuntu · Debian 공지 줄 열 · 확인 2026-11-09 · 같은 표의 룰 `php2shell-check-linux 0.6.0` |
| `baseline.json` | 이미지 · 컨테이너 점검의 PHP · Node.js · Brotli 기준 | `2026-10-30.12`(사내 runtime-scanner 형식 2 · 바이트 그대로 · SHA-256 `2fd679f4…`) — PHP 해시 37 · Node 해시 555 |

## 어떻게 쓰이나

remedy-net 은 점검을 시작할 때 꾸러미의 `plugins/remedy-net-criteria/` 를 본체가 룰 폴더를 확인하는 것과 같은
사슬로 확인한다 — 배포 키의 서명 · 파일이 서명한 그대로인가(더해진 것도 빠진 것도 없다) · 서명 주석의 이름이
`remedy-net-criteria` 인가. 확인한 뒤 파일을 읽을 때도 해시를 다시 본다. 하나라도 어긋나면 **점검하지 않고**
종료 4 로 끝난다(약관을 묻기 전 · 결과 폴더도 없다).

## 기준을 바꾸려면

1. 이 폴더의 파일을 고친다 — 꼴은 remedy-net 이 읽는 형식 그대로다(모르는 칸 · 견줄 수 없는 꼴은 거부한다).
2. 같은 공지의 값이 본체의 점검 룰(`php2shell-check-*` · `node2shell-check-*`)에도 있으면 함께 고친다.
3. `plugin.yaml` 의 `version` 을 올린다 — `plugin-lock` 이 이 폴더의 데이터 파일까지 잠근다.
4. `cargo xtask net-criteria` — 두 파일이 remedy-net 의 코드로 읽히는지, 본체의 점검 룰과 같은 값인지 본다.
5. 서명하고 배포한다. **remedy-net 은 다시 짓지 않는다.**

## 게이트

| # | 게이트 | 상태 | 근거 |
|---|---|---|---|
| 형식 | remedy-net 이 읽는다 | **통과** | `cargo xtask net-criteria` — 실행 때와 같은 코드(`remedy_net::criteria::check_texts`) |
| 대조 | 본체의 점검 룰과 같은 값 | **통과** | `cargo xtask net-criteria` — url 표 · 수정 버전 · PHP 해시 37 · Node 해시 555 가 룰 넷과 같다 |
| 서명 | 없거나 · 바뀌었거나 · 다른 키 · 다른 룰의 서명 | **거부** | `crates/remedy-net/tests/cli.rs` — 여섯 경우 × url · image · container 모두 종료 4 · 약관 없음 · 결과 폴더 없음 |
| 다시 짓지 않고 | 기준만 고쳐 다시 서명하면 판정이 바뀐다 | **통과** | 2026-11-13 · 같은 remedy-net 개발 빌드 · 모의 서버의 헤더 `PHP/8.3.38` — 이 폴더 그대로 **6**, 사본의 8.3 수정 버전을 8.3.40 으로 올린 뒤 서명 전 **4**(내용이 서명과 다르다), 다시 서명한 뒤 **2** |

## 서명 — 저장소 사본은 개발용 키, 배포본은 배포 키

저장소의 `MANIFEST` · `MANIFEST.minisig` 는 저장소 사본을 확인하려고 **개발용 키로** 서명한 것이다. 배포본은
태그의 배포 잡이 배포 키로 다시 서명하고, remedy-net 은 그 배포 키를 박아 짓는다. 개발용 키로 서명된 이 폴더는
배포 빌드의 remedy-net 이 받지 않는다.
