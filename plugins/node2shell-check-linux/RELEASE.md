# node2shell-check-linux — 릴리스 기록

**버전 0.1.0** · 대상: Node2Shell(CVE-2026-111497 · Brotli 디코더) — 리눅스의 Node.js 와 그것이 쓰는 시스템 Brotli · **점검**(바꾸지 않는다)

## 0.1.0 — 처음 (2026-11)

공식 빌드의 해시와 공급사 공지로 판정하고, 그 밖은 확인 필요로 낸다. 코어 1.3.0 의 `verdict.unconfirmed` ·
`hash_large`(공식 `node` 를 흘려 읽어 해시) · RPM 수집 · `rpm_version_lt` · `vendor` 를 쓴다.

## 무엇을 하나

| 갈래 | 판정 |
|---|---|
| **공식 빌드의 `node`**(nodejs.org tar 묶음 · 공식 Docker 이미지 · nvm · fnm · Volta) | 해시(linux-x64 89판 · linux-x64-musl 8판)가 맞으면 그 판으로 — 고친 판(22.23.4 · 24.22.1 · 26.12.1) 미만 · 18.20.8 · 20.20.2 는 **취약(2)**. 맞지 않으면 **확인 필요(6)** — 단 배포판 Node.js 패키지가 있으면 그 실행 파일은 패키지의 것으로 보고 아래 줄이 판정한다 |
| **Debian 의 nodejs** | 공급사가 *미수정* 으로 확인한 판(12 · 13 · 14 · sid)이면 **취약(2)**. nodejs 가 쓰는 시스템 Brotli(`libbrotli1`)가 *미수정* 판이어도 **취약(2)** |
| **Oracle Linux 8.10 의 nodejs 모듈**(22 · 24) | 공급사 → 계열 → 판(`rpm_version_lt`) — 수정 판 미만이면 **취약(2)** |
| 그 밖의 Node.js 패키지(Ubuntu · RHEL · Rocky · Alpine · 다른 저장소 · 기준에 없는 판 · 다른 모듈 계열) | **확인 필요(6)** — 같은 꼴의 모듈 판을 RHEL · Rocky 도 내므로 공급사로 가른다 |
| RHEL · Oracle Linux 8.10 의 시스템 Brotli 가 수정 판 미만이고 RPM 의 Node.js 가 있다 | **확인 필요(6)** — 그 Node.js 가 시스템 Brotli 를 쓰는지(공유 연결)는 이 도구가 재지 못한다 |

실행 파일 자리 `/usr/bin` · `/usr/local/bin` 은 그 폴더 바로 아래의 `node*` 만 본다(글롭 뿌리) — 폴더를 통째로
해시하지 않는다.

## 결과 읽기

| 종료 코드 | 뜻 |
|---|---|
| 2 | **취약** — Node.js(또는 시스템 Brotli)를 고친 판 이상으로 올리고 그 서비스를 다시 시작한다 |
| 0 | 취약한 곳을 찾지 못했다 — 공식 고친 빌드 · 공급사 수정 판이거나, 선언한 자리에 Node.js 가 없다 |
| 6 | **확인 필요** — `주의:` 아래 줄이 무엇을 확인할지 말한다 |

## 이 룰이 보지 않는 것

- 다른 제품 안에 든 Node.js(Electron 앱 · 단일 실행 파일 · 컨테이너 이미지) · 선언한 자리 밖의 `node`.
- RPM 의 Node.js 가 시스템 Brotli 를 쓰는지 — 그 자리는 확인 필요로 남긴다.
- 실행 중인 프로세스가 고친 판을 실었는가 — 고친 뒤에는 그 서비스를 다시 시작한다.

## 근거 — 공개 자료

- CVE-2026-111497(CNA Google) — Brotli 1.0.3~1.0.10 미만 · 1.1.0~1.1.1 미만 · 1.2.0~1.2.1 미만이 영향 범위
- Node.js 2026-10 보안 릴리스 — 22.23.4 · 24.22.1 · 26.12.1
- Node 공식 해시 — nodejs.org 의 서명한 SHASUMS256 — linux-x64 89판 · linux-x64-musl 8판. 값마다 룰에 판과 묶음 안의 자리를 적었다
- Debian security-tracker CVE-2026-111497 — nodejs · libbrotli1 의 미수정 판
- Oracle Linux ELSA-2026-500519(nodejs:22) · ELSA-2026-500520(nodejs:24) · RHSA-2026:90501 · ELSA-2026-90501(brotli)

## 게이트

| # | 게이트 | 상태 | 근거 |
|---|---|---|---|
| G1 | 청정 환경 무해성 | **통과** | 청정 스냅샷에서 판정 0 — 청정 코퍼스에는 Node.js 가 깔린 기계가 없다 |
| G2~G4 | 복원 · 계획 · 치료 | **미해당** | 바꾸는 것이 없다 |
| 모양 | 판정 규칙 | **25/25** | 손으로 지은 기계 모양을 `remedy evaluate` 로 — 공식 빌드(glibc · musl · nvm · 지원 종료) · 모르는 빌드 · 링크 · Debian 미수정 판 · 공유 Brotli · Ubuntu · Alpine · Oracle Linux 모듈 아래 · 수정 판 · 위 · 다른 계열 · Brotli 미만 · RHEL · Rocky 의 같은 꼴 |
| 실기계 | 수집 → 판정 | **5/5** | 2026-11-09 · 1.3.0 개발 빌드로 일회용 컨테이너 안에서 수집(배포판 패키지는 그 공급사의 저장소에서 깔았다) — 공식 `node:22.18.0` 이미지(`/usr/local/bin/node` 121.6 MB 를 `hash_large` 로 해시) **2** · `node:22.23.4` **0** · Debian 12 nodejs `18.20.4+dfsg-1~deb12u3`(미수정 판) **2** · Ubuntu 24.04 nodejs `18.19.1+dfsg-6ubuntu5` **6** · Rocky 9 nodejs `1:16.20.2-8.el9_4` **6**. 배포판의 `/usr/bin/node`(26 KB · libnode 를 싣는 작은 실행 파일)는 패키지가 있어 모르는 실행 파일로 세지 않았다 |

## 서명 — 저장소 사본은 개발용 키, 배포본은 배포 키

`cwpdoor-2-clean/RELEASE.md` 의 같은 절과 같다.
