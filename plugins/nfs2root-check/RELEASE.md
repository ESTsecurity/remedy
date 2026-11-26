# nfs2root-check — 릴리스 기록

**버전 0.1.0** · 대상: 리눅스 커널 NFS 서버(nfsd)의 인증 전 원격 root 'NFS2ROOT'(CVE-2026-99362) — 리눅스 · **점검**(바꾸지
않는다)

## 0 을 내는 갈래

| 갈래 | 근거 | 하네스 칸 |
|---|---|---|
| NFS 서버 패키지(dpkg `nfs-kernel-server` · rpm `nfs-utils` · `nfs-kernel-server` · apk `nfs-utils`)가 없다 — 커널 판과 상관없이 | 1차 카드(NFS 서버 패키지가 깔린 기계만 판정) · CVE 기록(cveawg · 2026-11-23 갱신)의 영향 경로는 nfsd 가 tcp 로 받은 NFSv4.1 RPC 다 · Red Hat VEX — 기본 설정은 nfsd 를 돌리지 않고 NFSv4.1 · 4.2 를 내보내도록 설정한 서버만 노출된다 | `D6` · `R2` |
| Debian 꼴 커널 패키지가 모두 Debian 의 고친 판 이상(trixie 6.12.117-1 · bookworm 의 linux-6.12 6.12.117-1~deb12u1 · sid 7.3.3-1 갈래) | Debian 보안 추적기 CVE-2026-99362(2026-11-26 17:56 — trixie · forky · sid fixed) · DLA-4927-1(bookworm linux-6.12) | `D1` · `D5` |
| Fedora · Alpine 의 커널 패키지가 모두 상류의 고친 판 이상 | CVE 기록(kernel.org CVE 팀 · cveawg · 2026-11-26 17:56) — 갈래마다 고친 판 5.10.275 · 5.15.226 · 6.1.193 · 6.6.163 · 6.12.117 · 6.18.61 · 7.3.2 · 7.4-rc1 · 두 배포판은 상류 판 번호를 그대로 싣는다(dl.fedoraproject.org 목록 · Alpine aports 의 linux-lts) | `F1` · `A1` |
| Ubuntu 꼴(dpkg) · Fedora · Alpine 의 커널이 모두 3.16 아래 | CVE 기록 — 3.16 아래는 영향 없음(도입 커밋 47ee52986472 는 v3.16 의 조상) · Ubuntu CVE 페이지 — 14.04 trusty Not affected | `U2` |

## 0.1.0 — 1차 (2026-11-26)

긴급 경로의 1차다(코어 그대로 · `docs/긴급-대응.md`). 범위는 *1차 범위* 의 취약점 줄 가운데 패키지 기록 — **깔린 커널
패키지의 판** 과 **NFS 서버 패키지가 있는가** 둘만 본다(1차 카드). 실행 중인 커널 · nfsd 적재 · 켠 NFS 판 · 2049 수신은
엔진 몫이라 다음 차수다(평소 경로).

### 판정

| 무엇 | 결과 |
|---|---|
| NFS 서버 패키지가 없다 | 0 — nfsd 를 띄울 수 없다(1차 카드) |
| 깔린 커널 패키지가 모두 영향 판이고 고친 판이 없다 — Debian 의 고친 판이 있는 갈래(6.12 · 7.x)와 고친 판 없이 지원이 끝난 bullseye 5.10 · 상류 판을 따르는 Fedora · Alpine | 취약(2) |
| 영향 판과 고친 판이 함께 깔렸다 | 확인 필요(6) — 지금 어느 커널로 도는지 이 룰은 모른다 |
| 배포판이 고친 판을 아직 내지 않은 백포트 커널(Ubuntu · RHEL 계열 · Amazon · SUSE · Debian 12 의 기본 6.1) | 확인 필요(6) |
| NFS 서버 패키지는 있는데 커널 패키지를 찾지 못했다(커널 없는 컨테이너 · 이름이 표준이 아닌 커널) | 확인 필요(6) |
| 깔린 커널이 모두 고친 판 · 3.16 아래 | 0 |

- **실행 중인 커널은 보지 않는다** — 엔진(1.26.0)이 실행 중인 커널 판을 룰에 주지 않는다. 고친 커널을 깔고 다시 시작하지
  않은 기계는 커널이 둘 깔려 확인 필요(6)로 나오고, 그 까닭 줄이 확인하는 법과 다시 시작을 알린다.
- **판으로만 판정한다** — nfsd 를 실었는지 · NFSv4.1 · 4.2 를 켰는지 · 2049 를 듣는지는 판정에 넣지 않는다. 끄는 법은
  위협별 안내의 *꼭 할 일* 이다.
- **배포판마다 견주는 판이 다르다** — Debian 은 추적기의 고친 판과, Fedora · Alpine 은 상류의 고친 판과 견준다. 같은 상류 판에
  개정만 올려 고치는 배포판(Ubuntu · RHEL 계열 · Amazon · SUSE)은 상류 판 번호로 가리지 못해, 고친 패키지 공지가 나올 때까지
  확인 필요(6)다 — 공지가 나오면 다음 차수에서 그 배포판 줄을 더해 0 으로 가린다.

### 영향 판 · 고친 판 (1차 출처 · 2026-11-26 17:55 ~ 18:10 KST 확인)

| 상류 갈래 | 고친 판 | 고침 커밋 |
|---|---|---|
| mainline | 7.4-rc1 | 35ff1a7a7e38 |
| stable 7.3 | 7.3.2 | ed98b0c57e5e |
| longterm 6.18 | 6.18.61 | 37fc2ec21163 |
| longterm 6.12 | 6.12.117 | 1a5a227bca6a |
| longterm 6.6 | 6.6.163 | cd303eb29cf3 |
| longterm 6.1 | 6.1.193 | fa85acf074f0 |
| longterm 5.15 | 5.15.226 | 6a26c5473bb1 |
| longterm 5.10 | 5.10.275 | aff12e327620 |
| 7.2 · 그 밖의 3.16 이후 갈래(5.4 · 4.19 등) | 없음 — 고친 판 없이 지원이 끝났다(7.2 의 마지막 판 7.2.15) | — |
| 3.16 아래 | 영향 없음 | — |

출처: CVE 기록(kernel.org CVE 팀 · CVE Services `cveawg.mitre.org/api/cve/CVE-2026-99362` · 2026-11-19 공개 · 11-23 갱신) ·
상류 커밋(GitHub 의 torvalds/linux · gregkh/linux 거울 — git.kernel.org 는 봇 확인에 막혀 받지 못했다) · kernel.org
releases.json · OpenSec 분석(2026-11-25 — 고친 판 넷만 적고, 고침 커밋으로 든 두 해시는 mainline 의 조상이 아니다 · mainline 의
고침은 35ff1a7a7e38). CVSS 3.1 9.8(CNA). CISA KEV 에 없다(catalog 2026.11.25) · 실제 공격을 알린 1차 보고를 찾지 못했다.

| 배포판 · 공급사 | 고친 패키지 · 공지 | 이 룰 | 출처 |
|---|---|---|---|
| Debian 13 trixie · forky · sid | trixie 6.12.117-1(본 저장소 — 이 CVE 를 적은 DSA 는 없다 · DSA-6628-1 · DSA-6652-1 에 없음) · sid 7.3.3-1 | 0 / 고친 판 아래는 취약(2) | security-tracker.debian.org |
| Debian 12 bookworm — linux-6.12 | 6.12.117-1~deb12u1 · DLA-4927-1 | 0 / 고친 판 아래는 취약(2) | security-tracker.debian.org |
| Debian 12 bookworm — 기본 linux(6.1) | 없음(6.1.192-2 vulnerable) | 확인 필요(6) | security-tracker.debian.org |
| Debian 11 bullseye(5.10) | 없음 — '(unfixed) end-of-life'(Freexian ELTS 5.10.272-1 vulnerable) | 취약(2) | deb.freexian.com 의 ELTS 추적기 |
| Ubuntu 16.04 ~ 26.10 | 없음 — USN 없음 · Vulnerable | 확인 필요(6) | ubuntu.com/security |
| Ubuntu 14.04 trusty | Not affected(3.13) | 0 | ubuntu.com/security |
| RHEL 6 ~ 10 · AlmaLinux · Rocky · Oracle(RHCK · UEK7 · UEK8) · CentOS Stream 9 · 10 | 없음 — Red Hat VEX known_affected · 최신 커널 RHSA-2026:102590 · 102253 · 102218(같은 번호의 ALSA · RLSA · ELSA)에 이 CVE 없음 · CentOS Stream MR !9248 · !4132 병합 전 | 확인 필요(6) | access.redhat.com · errata.almalinux.org · errata.rockylinux.org · yum.oracle.com · gitlab.com/redhat |
| Amazon Linux 2 · 2023 | 없음 — ALAS 0건 · CVE 페이지 404 | 확인 필요(6) | alas.aws.amazon.com |
| SUSE SLES 15 SP6-LTSS · SP7 · SLE Micro 5.4 ~ 6.1 · Leap 15.6 · Tumbleweed | 없음 — Affected · 전체 Pending · SUSE-SU 없음(Tumbleweed 는 SUSE 페이지에 줄이 없다) | 확인 필요(6) | suse.com/security |
| Fedora 43 · 44 · 45 | 받지 못함(Bodhi 봇 차단) — 상류 판 그대로(7.3.5-100.fc43 · 7.3.5-200.fc44 · 7.3.4-300.fc45) | 상류 판 기준 0 | dl.fedoraproject.org |
| Alpine 3.21 ~ edge | 추적기 상태 없음(커널 secfixes 를 추적하지 않는다) — 상류 판 그대로(3.22 6.12.119-r0 · 3.24 6.18.65-r0 · edge 7.3.6-r0) | 상류 판 기준 0 | security.alpinelinux.org · gitlab.alpinelinux.org |

### 게이트

| 게이트 | 무엇 | 결과 | 근거 |
|---|---|---|---|
| G1 | 청정 환경 무해성 | 리눅스 스냅샷 19 · 판정 0 · 파괴 동작 0 · 알림 0(`cargo xtask g1` 2026-11-26 18:27 — 룰 23개 · 스냅샷 29개 · 짝 357) | 청정 코퍼스의 리눅스 스냅샷 19개에 커널 패키지 · NFS 서버 패키지가 든 것이 없어 이 룰의 판정 갈래(커널 판)는 G1 로 재지 못한다 — 판정 갈래는 하네스가 잰다 |
| G9 | 룰의 검체 오탐(YARA) | 해당 없음 | 이 룰에는 YARA 규칙이 없다(`rules/` 없음 · `subjects: [package]`) |
| 하네스 | `testbed/harness/linux/nfs2root-verify.sh` | 20/20(2026-11-26 18:40 · 개발 빌드 1.26.0 · 이 PC 의 docker) — 아래 표의 19칸 + 준비 칸 P1(D1 에 깐 커널이 6.12.117-1 이상인가) | 경우마다 패키지 기록을 세운 컨테이너 · D1 만 저장소의 패키지를 실제로 깐다 |

| 칸 | 기계 | 기대 |
|---|---|---|
| D1 | Debian 13 — 저장소의 `nfs-kernel-server` 와 `linux-image-amd64` 를 실제로 깐다(지금 trixie-security 6.12.118) | 0 |
| D2 | Debian 13 — 커널 기록 한 줄이 6.12.116-1 + `nfs-kernel-server` | 2 |
| D3 | Debian 13 — 6.12.116-1 과 6.12.118-1 이 함께 | 6(다시 시작 확인) |
| D4 | Debian 12 — 6.1.192-2 + `nfs-kernel-server` | 6(Debian 고친 판 없음) |
| D5 | Debian 12 — linux-6.12 의 6.12.117-1~deb12u1 만 + `nfs-kernel-server` | 0 |
| D6 | Debian 13 — 취약 판 커널 기록 · `nfs-kernel-server` 없음 | 0 |
| D7 | `nfs-kernel-server` 는 있고 커널 패키지 없음(바탕 컨테이너) | 6 |
| D8 | bullseye 꼴 5.10.262-1 + `nfs-kernel-server` | 2 |
| U1 | Ubuntu 24.04 — 6.8.0-151.151 + `nfs-kernel-server` | 6 |
| U2 | Ubuntu 꼴 3.13.0-170.220(영향 밖) + `nfs-kernel-server` | 0 |
| F1 | Fedora — `kernel-core` 7.3.4-300.fc45 + `nfs-utils` | 0 |
| F2 | Fedora — `kernel-core` 7.2.15-200.fc43 + `nfs-utils` | 2 |
| F3 | Fedora — 7.3.1 과 7.3.4 의 fc45 가 함께 | 6 |
| R1 | AlmaLinux 9 — `kernel-core` 5.14.0-741.27.1.el9_9 + `nfs-utils` | 6 |
| R2 | AlmaLinux 9 — 같은 커널 · `nfs-utils` 없음 | 0 |
| A1 | Alpine 3.22 — `linux-lts` 6.12.119-r0 + `nfs-utils` | 0 |
| A2 | Alpine 3.22 — `linux-lts` 6.12.116-r0 + `nfs-utils` | 2 |
| S1 | 화면 — 2 칸의 감지 줄에 CVE 번호와 고친 판 문구 | 있음 |
| S2 | 결과 파일 — 6 칸의 확인 필요 까닭(다시 시작 · 배포판 공지 · 커널 패키지 없음 셋) | 있음 |

### 다음 차수 후보

| 범위 | 까닭 | 필요한 것 |
|---|---|---|
| 실행 중인 커널 판 · nfsd 적재 · 켠 NFS 판(`/proc/fs/nfsd/versions`) · 2049 수신 | 엔진(1.26.0)이 룰에 주지 않는다 — 1차는 룰만으로(카드) | 엔진 몫 · 평소 경로 |
| Ubuntu USN · RHSA(ALSA · RLSA · ELSA) · ALAS · SUSE-SU · Debian 6.1 의 DSA · DLA | 2026-11-26 17:55 ~ 18:05 KST 에 공지가 없다(받지 못함 — 위 표) | 공지가 나오면 그 배포판의 고친 판 줄 · 하네스 칸 |
| SUSE SLES 16 · Leap 16 · SL Micro 6.2 의 Not affected | SUSE 가 까닭을 적지 않았다 — 지금은 다른 SUSE 커널과 같이 확인 필요(6) | SUSE 의 까닭 · 그 커널 판을 가리는 줄 |
| Fedora 의 고친 판 | Bodhi 를 받지 못했다(2026-11-26 17:56 KST · 봇 차단) — Fedora 는 상류 판 기준으로만 본다 | Bodhi 의 이 CVE 갱신 |
| 판 번호로는 고친 판 이상인 백포트 커널(Amazon `kernel6.18` 6.18.62 등) | 판 번호로 고친 판 이상이어도 공급사가 이 CVE 를 적은 공지가 없다 — 지금은 확인 필요(6) | 공급사 공지 |
| Arch Linux | 엔진이 pacman 의 패키지 기록을 읽지 않는다 · 추적기에 이 CVE 가 없다(404 · 2026-11-26 17:55 KST) | 엔진 몫 |
| 이름이 표준이 아닌 커널 패키지(Proxmox 등 · 직접 지은 커널) | 커널 패키지로 읽지 않는다 — NFS 서버가 있으면 확인 필요(6)로 알린다 | 그 제품의 패키지 이름 · 판 꼴 |
