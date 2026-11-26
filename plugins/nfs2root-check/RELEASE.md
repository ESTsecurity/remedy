# nfs2root-check — 릴리스 기록

**버전 0.2.0** · 대상: 리눅스 커널 NFS 서버(nfsd)의 인증 전 원격 root 'NFS2ROOT'(CVE-2026-99362) — 리눅스 · **점검**(바꾸지
않는다)

## 0 을 내는 갈래

| 갈래 | 근거 | 하네스 칸 |
|---|---|---|
| NFS 서버 패키지(dpkg `nfs-kernel-server` · rpm `nfs-utils` · `nfs-kernel-server` · apk `nfs-utils`)가 없다 — 커널 판과 상관없이 | 1차 카드(NFS 서버 패키지가 깔린 기계만 판정) · CVE 기록(cveawg · 2026-11-23 갱신)의 영향 경로는 nfsd 가 tcp 로 받은 NFSv4.1 RPC 다 · Red Hat VEX — 기본 설정은 nfsd 를 돌리지 않고 NFSv4.1 · 4.2 를 내보내도록 설정한 서버만 노출된다 | `D6` · `R2` |
| Debian 꼴 커널 패키지가 모두 Debian 의 고친 판 이상(trixie 6.12.117-1 · bookworm 의 linux-6.12 6.12.117-1~deb12u1 · sid 7.3.3-1 갈래) | Debian 보안 추적기 CVE-2026-99362(2026-11-26 17:56 — trixie · forky · sid fixed) · DLA-4927-1(bookworm linux-6.12) | `D1` · `D5` |
| Fedora · Alpine 의 커널 패키지가 모두 상류의 고친 판 이상 | CVE 기록(kernel.org CVE 팀 · cveawg · 2026-11-26 17:56) — 갈래마다 고친 판 5.10.275 · 5.15.226 · 6.1.193 · 6.6.163 · 6.12.117 · 6.18.61 · 7.3.2 · 7.4-rc1 · 두 배포판은 상류 판 번호를 그대로 싣는다(dl.fedoraproject.org 목록 · Alpine aports 의 linux-lts) | `F1` · `A1` |
| RHEL 8.10 의 Red Hat 커널(rpm 의 공급사 `Red Hat, Inc.` · 판 `4.18.0-*.el8_10`)이 모두 RHSA-2026:103817 의 고친 판(0:4.18.0-553.190.1.el8_10) 이상(0.2.0) | RHSA-2026:103817(2026-11-26 · Critical · access.redhat.com/errata · 2026-11-26 22:59 KST 확인) — 고친 CVE 넷에 CVE-2026-99362 가 들고 고친 판은 kernel · kernel-core 4.18.0-553.190.1.el8_10(ELS 8.10 도 같은 판) · epoch 0 은 같은 패키지의 지난 RHSA-2026:102218(`kernel-0:4.18.0-553.189.1.el8_10` — 보안 데이터 API) | `R4` |
| Ubuntu 꼴(dpkg) · Fedora · Alpine 의 커널이 모두 3.16 아래 | CVE 기록 — 3.16 아래는 영향 없음(도입 커밋 47ee52986472 는 v3.16 의 조상) · Ubuntu CVE 페이지 — 14.04 trusty Not affected | `U2` |
| 패키지 DB 자리(dpkg · rpm · apk) 넷이 모두 없다 — *점검 대상이 이 기계에 없습니다* 안내 · Arch 등 | 판정할 패키지 기록이 없다 — 엔진이 pacman 의 패키지 기록을 읽지 않는다 | `N1` |

## 0.2.0 — 2차 (2026-11-27)

긴급 경로의 2차다(코어 그대로 · `docs/긴급-대응.md` *2 · 3차*). 1차 뒤에 나온 고친 공지와 공급사가 고치지 않는다고 밝힌 판을
판정에 더하고, 1차 기록의 공급사 근거를 바로잡는다. 공급사 자료는 2026-11-26 22:52 ~ 23:07 KST 에 다시 쟀다 — 1차 뒤 이 CVE 를
고친 공지는 RHEL 8 의 RHSA-2026:103817 하나다(Ubuntu USN · Debian DSA · DLA · ALSA · RLSA · ELSA · ALAS · SUSE-SU · Alpine secfixes
0건 · Fedora Bodhi 는 이번에도 받지 못했다). 아래 0.1.0 의 *판정* 가운데 이 절이 적지 않은 줄은 그대로다.

### 바뀐 판정

| 무엇 | 0.1.0 | 0.2.0 |
|---|---|---|
| RHEL 8.10 의 Red Hat 커널(rpm 의 공급사 `Red Hat, Inc.` · 판 `4.18.0-*.el8_10`)이 모두 RHSA-2026:103817 의 고친 판(0:4.18.0-553.190.1.el8_10) 아래 | 6 | 취약(2) |
| 같은 커널이 모두 그 고친 판 이상 | 6 | 0 |
| 그 고친 판과 그 아래가 함께 깔렸다 | 6 | 6(다시 시작 확인) |
| 그 밖의 Red Hat 커널 — RHEL 9 · 10 · 6 · 7 · EUS 8.6 · 8.8(`.el8_6` · `.el8_8`) · RHEL 8 의 kernel-rt | 6 | 6 그대로 |
| AlmaLinux · Rocky · Oracle 8 의 커널(같은 판 문자열 · 공급사가 다르다) | 6 | 6 그대로 — 그 배포판의 공지가 아직 없다 |
| Ubuntu 24.04 HWE 6.14 · 6.17 — `~24.04.N` 꼬리의 6.14 · 6.17(같은 꼴의 aws · azure · azure-fde · gcp · oracle 갈래 포함)과 꼬리 없는 24.04 의 6.17 판 `6.17.0-42.42` · `6.17.0-42.42+1` · `6.17.0-44.44` | 6 | 취약(2) |
| 같은 상류 판의 Ubuntu 25.04 · 25.10 커널(`6.14.0-37.37` · `6.17.0-41.41` 꼴) · 꼬리 없는 24.04 의 OEM · nvidia · 일부 클라우드 6.14 · 6.17 · 24.04 HWE 7.0 | 6 | 6 그대로 |

- **RHEL 8.10** — Red Hat 이 2026-11-26 에 RHSA-2026:103817(Critical)을 냈다. 고친 CVE 넷 가운데 CVE-2026-99362 가 있고 고친 판은
  kernel · kernel-core 4.18.0-553.190.1.el8_10 이다(x86_64 · aarch64 · ppc64le · s390x · ELS 8.10 채널도 같은 판). kernel-rt 와 EUS
  8.6 · 8.8 은 그 공지에 들지 않았다. 그 판의 CSAF 는 아직 없어(404 · 22:59 · 23:04) epoch 를 1차 출처로 받지 못했다 — 같은 패키지의
  지난 RHSA-2026:102218 이 `kernel-0:4.18.0-553.189.1.el8_10` 이고 AlmaLinux errata 도 RHEL 8 kernel 의 epoch 를 0 으로 적어 0 으로
  견준다. 그래서 판 정규식은 **epoch 가 없는 기록만** 받는다 — 수집기는 epoch 가 0 이면 판에 붙이지 않으므로 영향 판(epoch 0 ·
  1차 출처)은 그대로 2 · 0 으로 갈리고, 뜻밖에 epoch 가 붙은 Red Hat 커널은 *확인 필요*(6)로 간다(고친 빌드의 epoch 가 무엇이든
  거짓 양호가 나지 않는다 · 2차 반증 검토). Red Hat 의 VEX(rev 3 · 11:24Z)와 보안 데이터 API 의 CVE 기록은 23:00 에도 RHEL 8 kernel 을 Affected 로 적는다 — errata
  페이지와 Bugzilla 2576719 의 공지 링크(22:46 KST)가 앞서고, 두 자료에는 아직 오르지 않은 것으로 본다.
- **AlmaLinux · Rocky · Oracle** — RHEL 의 판 문자열을 그대로 다시 짓는다. 그 배포판의 공지(같은 번호의 ALSA · RLSA · ELSA)가
  23:04 ~ 23:05 에 아직 없어, 이 룰은 rpm 의 공급사(vendor)로 Red Hat 이 지은 커널만 그 공지로 가린다.
- **Ubuntu 24.04 HWE 6.14 · 6.17** — Ubuntu CVE 페이지가 noble 의 linux-hwe-6.14 · linux-hwe-6.17 을 `ignored` 로, 까닭을 'end of
  life, was needs-triage' 로 적었다(같은 까닭으로 aws · azure · azure-fde · gcp · oracle · oem · realtime 의 6.14 · 6.17 과
  azure-nvidia-6.14 · nvidia-6.17 · riscv 의 6.14 · 6.17 도). 공급사가 고치지 않는다고 밝힌 판이라 Debian 의 지원이 끝난 5.10 · 4.19 · 4.9 와 같이 취약(2)이다(1차 *다음 차수
  후보* 의 '정책상 2 후보'). HWE 메타 `linux-image-generic-hwe-24.04` 는 이미 7.0(7.0.0-44.44~24.04.1)을 가리키고, 7.0 은 Ubuntu
  표에서 needed 라 6 이다. 룰은 os-release 를 보지 않으므로 릴리스를 판 꼴로 가른다 — 24.04 의 6.14 · 6.17 은 `~24.04.N` 꼬리이거나
  24.04 에만 있는 ABI 42 · 44(6.17 의 지금 Security 판은 바이너리 `6.17.0-42.42+1` · armhf · ppc64el 은 `6.17.0-42.42` · `-proposed` 는
  `6.17.0-44.44`)이고, 25.04 · 25.10 의 같은 상류 판은 꼬리가 없다(25.10 의 6.17 은 41 에서 끝났다).

### 공급사 표 — 2차에 바뀐 줄 (2026-11-26 22:52 ~ 23:07 KST 확인)

| 배포판 · 공급사 | 고친 패키지 · 공지 | 이 룰 | 출처 |
|---|---|---|---|
| RHEL 8(8.10 · ELS 8.10) | kernel · kernel-core 4.18.0-553.190.1.el8_10 · RHSA-2026:103817(2026-11-26 · Critical) · kernel-rt 는 들지 않았다 | 0 / 고친 판 아래는 취약(2) | access.redhat.com/errata |
| RHEL 8 kernel-rt · EUS 8.6 · 8.8 · RHEL 9 · 10 · 6 · 7 | 없음 — 11-22 뒤의 커널 공지 20건에 이 CVE 가 없다. RHEL 10 의 최신은 RHSA-2026:103494(0:6.12.0-264.21.1.el10_3 · 2026-11-25 · CVE 7개 · 이 CVE 없음 — 0.1.0 표가 최신으로 적은 102253 의 다음 공지이고 1차에 보지 못했다) · RHEL 9 의 최신은 RHSA-2026:102590 그대로 | 확인 필요(6) | access.redhat.com 보안 데이터 API |
| AlmaLinux · Rocky · Oracle(RHCK · UEK) | 없음 — RHSA-2026:103817 을 다시 지은 ALSA · RLSA · ELSA 가 아직 없다 · Rocky 의 새 RLSA-2026:103494(Rocky 10)에도 이 CVE 없음 | 확인 필요(6) | errata.almalinux.org · apollo.build.resf.org · yum.oracle.com |
| CentOS Stream 9 | 고친 빌드 kernel-5.14.0-769.el9(Stream koji · 11-26 14:04 KST 완료 · 변경 기록의 '{CVE-2026-99362}' · MR !9248 병합) — 미러 BaseOS 는 5.14.0-765.el9 까지라 아직 받을 수 없다 · 공지는 내지 않는다 | 확인 필요(6) — 이번엔 줄 없음(*다음 차수 후보*) | gitlab.com/redhat · kojihub.stream.centos.org · mirror.stream.centos.org |
| Amazon Linux 2 · 2023 | 없음 — ALAS 0건 · CVE 페이지 404 · updateinfo 에 없음. 지금 판: AL2 core 0:4.14.355-287.769.amzn2 · kernel-5.4 0:5.4.302-229.517.amzn2 · 5.10 0:5.10.273-275.1133.amzn2 · 5.15 0:5.15.224-160.263.amzn2(ALAS2KERNEL-5.15-2026-121) · AL2023 kernel 1:6.1.190-237.442.amzn2023 · kernel6.12 1:6.12.115-140.210.amzn2023 · kernel6.18 1:6.18.62-127.179.amzn2023. **백포트 근거(2차에 잼)** — AL2023 updateinfo 에 같은 상류 판에서 release 만 올려 CVE 를 고친 공지가 셋이다(kernel6.18 6.18.56-125.164 → 126.188 · ALAS2023-2026-3390 · kernel 6.1.189-236.399 → 236.400 · ALAS2023-2026-3365 · kernel 6.1.190-237.431 → 237.442 · ALAS2023-2026-3455) — Amazon 은 상류 안정 판을 따라 올리기도 하고 같은 판 안에서 고치기도 한다 | 확인 필요(6) | explore.alas.aws.amazon.com · cdn.amazonlinux.com 의 repodata |
| SUSE SLES 15 SP6-LTSS · SP7 · SLE Micro · Leap 15.6 | 없음 — 1차와 같다(CVE 페이지가 1차 사본과 바이트까지 같다 · VEX 는 2026-11-23 뒤 고쳐지지 않았다 · SUSE-SU 0건). **백포트 근거** — 지난 커널 CVE-2026-31431 의 고친 판이 고정된 바탕 판에 SUSE 개정만 붙인 꼴이다(SLES 15 SP7 `kernel-default >= 6.4.0-150700.53.78.1` · SLES 16.0 `>= 6.12.0-160000.37.1` · SP6-LTSS · Leap 15.6 `>= 6.4.0-150600.23.100.1` — 1차 17:59 에 쟀고 2차 23:06 에 다시 확인) · SUSE 커널 소스의 `rpm/config.sh` 도 SLE 갈래마다 바탕 판을 6.4 · 6.12 로 고정한다 | 확인 필요(6) | suse.com/security · ftp.suse.com 의 CSAF VEX · github.com/SUSE/kernel-source |
| openSUSE Tumbleweed | 없음(SUSE 공지 · VEX 에 줄 없음) — 지금 7.3.5-1.1. SUSE 커널 소스의 stable 가지(openSUSE:Factory 대상 · 바탕 7.3)가 상류 7.3.2 패치로 고침을 싣는다 | 확인 필요(6)(*다음 차수 후보*) | github.com/SUSE/kernel-source · download.opensuse.org |
| Ubuntu 24.04 HWE 6.14 · 6.17 | 없음 — Ubuntu CVE 페이지 `ignored` 'end of life, was needs-triage' · 6.17 의 마지막 Security 판 6.17.0-42.42(2026-08-05) · 6.14 는 6.14.0-37.37~24.04.1(2025-12-10) | 취약(2) | ubuntu.com/security · api.launchpad.net |

그 밖의 줄(Debian · Ubuntu 의 다른 갈래 · Fedora · Alpine)은 0.1.0 표와 같다 — 2차에 다시 받아 판정에 닿는 것이 바뀌지 않았다
(Ubuntu CVE 기록의 갱신 시각은 11-25 그대로 · 26.04 · 26.10 의 작업 중 판 7.0.0-45.45 · 7.3.0-12.13 은 Launchpad 에 아직 없다 ·
Debian 의 새 DSA · DLA 없음).

### 1차 기록 바로잡기

0.1.0 은 SUSE 를 *지난 보안 갱신 이력을 재지 못해 백포트로 본다* 고 적었다 — 틀린 줄이다. 1차 조사가 이미 지난 커널 CVE-2026-31431
의 고친 판(위 표)으로 SUSE 가 백포트한다는 것을 쟀다. Amazon 은 1차에 재지 않았고 2차에 쟀다(위 표). 0.1.0 절의 그 세 줄(*판정* ·
*배포판마다 견주는 판* · *다음 차수 후보*)은 그 자리에서 `(2차에서 바로잡음 — …)` 꼴로 고쳤다. 두 배포판의 판정은 그대로 확인
필요(6)다 — 고친 패키지 공지가 없다.

### 게이트

| 게이트 | 무엇 | 결과 | 근거 |
|---|---|---|---|
| G1 | 청정 환경 무해성 | 판정 0 · 파괴 동작 0 · 이 룰의 알림 0(`cargo xtask g1` 2026-11-26 23:19 — 룰 23개 · 스냅샷 29개 · 짝 357) | 0.1.0 과 같다 — 청정 코퍼스의 리눅스 스냅샷에 커널 패키지 · NFS 서버 패키지가 든 것이 없어 판정 갈래는 하네스가 잰다 |
| G9 | 룰의 검체 오탐(YARA) | 해당 없음 | 이 룰에는 YARA 규칙이 없다(`rules/` 없음 · `subjects: [package]`) |
| 하네스 | `testbed/harness/linux/nfs2root-verify.sh` | 38/38(2026-11-26 23:45 · 반증 검토 고침 뒤 · 개발 빌드 1.26.0 · 이 PC 의 docker) — 0.1.0 의 26칸 + 아래 새 칸 12 | 경우마다 패키지 기록을 세운 컨테이너 |

| 새 칸 | 기계 | 기대 |
|---|---|---|
| D11 | stretch 꼴 4.9.320-3 + `nfs-kernel-server` | 2 |
| U3 | Ubuntu 24.04 HWE 6.17 — `linux-image-6.17.0-42-generic` 6.17.0-42.42+1 + `nfs-kernel-server` | 2 |
| U4 | Ubuntu 24.04 HWE 6.14 — `linux-image-6.14.0-37-generic` 6.14.0-37.37~24.04.1 + `nfs-kernel-server` | 2 |
| U5 | Ubuntu 24.04 HWE 7.0 — 7.0.0-44.44~24.04.1 + `nfs-kernel-server` | 6 |
| U6 | 25.10 꼴 6.17.0-41.41 + `nfs-kernel-server` | 6 |
| U7 | HWE 6.17 의 6.17.0-42.42+1 과 HWE 7.0 의 7.0.0-44.44~24.04.1 이 함께 | 6 |
| R3 | RHEL 8.10 — Red Hat 의 `kernel-core` 4.18.0-553.189.1.el8_10 + `nfs-utils` | 2 |
| R4 | RHEL 8.10 — Red Hat 의 `kernel-core` 4.18.0-553.190.1.el8_10 + `nfs-utils` | 0 |
| R5 | R4 와 같은 판 · 공급사 AlmaLinux | 6 |
| R6 | RHEL 8.10 — Red Hat 의 `kernel-rt-core` 4.18.0-553.84.1.rt7.425.el8_10 | 6 |
| R7 | RHEL 9 — Red Hat 의 `kernel-core` 5.14.0-741.27.1.el9_9 | 6 |
| R8 | RHEL 8.10 — Red Hat 의 553.189.1 과 553.190.1 이 함께 | 6(다시 시작 확인) |

### 다음 차수 후보

| 범위 | 까닭 | 필요한 것 |
|---|---|---|
| 실행 중인 커널 판 · nfsd 적재 · 켠 NFS 판(`/proc/fs/nfsd/versions`) · 2049 수신 | 엔진(1.26.0)이 룰에 주지 않는다 — 1 · 2차는 룰만으로(카드) | 엔진 몫 · 평소 경로 |
| Ubuntu USN · RHEL 9 · 10 의 RHSA · ALSA · RLSA · ELSA · ALAS · SUSE-SU · Debian 6.1 의 DSA · DLA | 2026-11-26 22:52 ~ 23:07 KST 에 공지가 없다(RHEL 8 의 RHSA-2026:103817 만 나왔다 — 이 차수가 더했다) | 공지가 나오면 그 배포판의 고친 판 줄 · 하네스 칸 |
| AlmaLinux · Rocky · Oracle 8 의 RHSA-2026:103817 다시 짓기 | 같은 판 문자열(4.18.0-553.190.1.el8_10)로 곧 나올 것으로 본다(추론) — 23:04 ~ 23:05 에 셋 다 없었다 · 이 룰은 공급사로 갈라 지금 6 | 그 배포판의 공지 · 그 rpm 의 공급사 문자열 · 하네스 칸 |
| RHEL 8 kernel-rt · EUS 8.6 · 8.8 | RHSA-2026:103817 에 들지 않았다 — 지금 6 | 그 스트림의 RHSA |
| CentOS Stream 9 의 고친 판 5.14.0-769.el9 | Stream koji 에 지어졌지만 미러에 아직 없다(765.el9 까지 · 22:56) — 깔 수 있는 기계가 없어 이번엔 줄을 두지 않았다 · 지금 6 | 미러에 오른 뒤 그 판 줄(공급사 · 판 꼴) · 하네스 칸 |
| openSUSE Tumbleweed | 상류 7.3.y 를 따르는 듯하다(추론 — SUSE 커널 소스의 stable 가지가 openSUSE:Factory 를 대상으로 상류 7.3.2 패치로 고침을 싣는다 · SUSE 문서로 확인하지 않았다) — 이 룰은 개정 꼴로 Tumbleweed 와 SLES 를 가르지 않아 지금 6 | Tumbleweed 가 그 가지에서 지어진다는 SUSE 쪽 근거 · Tumbleweed 를 가르는 판 꼴 |
| SUSE SLES 16 · Leap 16 · SL Micro 6.2 의 Not affected | SUSE 가 까닭을 적지 않았다(VEX 에 justification 칸 없음) · SL-16.0 · 16.1 의 커널 소스에서 고침 패치(이름 preflight · 커밋 35ff1a7a7e38)를 찾지 못했다(23:02 — 이름이 다른 패치일 가능성은 지우지 못한다) — 지금은 다른 SUSE 커널과 같이 6 | SUSE 의 까닭 · 그 커널 판을 가리는 줄 |
| Fedora 의 고친 판 | Bodhi 를 이번에도 받지 못했다(22:57 · 봇 확인) — Fedora 는 상류 판 기준으로만 본다 | Bodhi 의 이 CVE 갱신 |
| 판 번호로는 고친 판 이상인 Amazon 커널(`kernel6.18` 6.18.62 등) | Amazon 은 같은 상류 판 안에서 release 만 올려 고치기도 한다(2차에 잼 — 위 표) — 판 번호만으로 양호라 하지 못한다 · 이 CVE 를 적은 공지가 없다 — 지금 6 | 공급사 공지 |
| Debian ELTS stretch 의 백포트 커널 | ELTS stretch-lts 에 linux-6.1 6.1.190-1~deb9u1(`linux-image-6.1.0-0.deb9.54-amd64`) · linux-5.10 5.10.262-1~deb9u1 · linux-4.19 4.19.316-1~deb9u1 이 있다 — ELTS 의 CVE 표에 그 줄이 없다(공급사가 상태를 적지 않았다). 이 룰은 Debian 꼴로 보아 6.1 은 6, 5.10 · 4.19 는 지원이 끝난 갈래의 줄로 2 다(룰을 읽어 — 하네스 칸 없음) | ELTS 의 그 소스 상태 · 하네스 칸 |
| Ubuntu 25.04 · 25.10 의 6.14 · 6.17 | 지원이 끝났지만(25.04 2026-01-15 · 25.10 2026-07-09) Ubuntu CVE 페이지에 그 릴리스 줄이 없다 — 고치지 않는다고 밝힌 판이 아니라 지금 6 | 공급사의 표시 · 지원이 끝난 릴리스를 2 로 볼지의 결정 |
| 꼬리 없는 Ubuntu 24.04 의 OEM · nvidia · 일부 클라우드 6.14 · 6.17(`6.17.0-1033.33` 꼴) | OEM · nvidia-6.17 은 Ubuntu 가 같은 까닭(end of life)으로 `ignored` 로 적었지만 판에 24.04 꼬리가 없어 판 문자열로 가르지 않았다 · nvidia-6.14 · vmware-6.17 은 CVE 페이지에 줄이 없다 — 지금 6 | 그 갈래를 가리는 판 꼴 |
| Kali · Raspberry Pi OS · Freexian ELTS 의 bullseye · buster · 직접 지은 deb 의 커널 판 꼴 | 판 꼴을 재지 않았다 | 그 배포판의 패키지 이름 · 판 꼴 |
| RHEL 8 의 옛 부 판 커널(`.el8` · `.el8_9` 등 — EUS 8.6 · 8.8 빼고)이 고친 8.10 커널과 함께 | rhel_other 가 잡아 6 은 맞지만 까닭 줄이 '고친 커널을 아직 내지 않았습니다' 다 — 실제 할 일은 다시 시작 확인(2차 반증 검토) | 부 판을 RHEL 8 쪽으로 옮길지의 결정 |
| RHEL 8 BDB rpmdb 위의 공급사 칸 · Ubuntu HWE 의 다른 판 꼴(armhf · ppc64el 의 `6.17.0-42.42` · `44.44` · 클라우드 `6.17.0-1020.20~24.04.1+1` · riscv `6.14.0-37.37.1~24.04.1`) | 판 정규식은 읽어 확인했다 — 하네스 칸은 AlmaLinux 9 의 sqlite rpmdb · U3 · U4 의 두 꼴뿐이다 | ubi8 이미지의 칸 · U 칸 |
| Arch Linux | 엔진이 pacman 의 패키지 기록을 읽지 않는다 · 추적기에 이 CVE 가 없다(404 · 2026-11-26 17:55 KST) | 엔진 몫 |
| 이름을 모르는 커널 패키지(직접 지은 커널 등) | 커널 패키지로 읽지 않는다 — 아는 이름의 커널이 하나도 없으면 확인 필요(6), 아는 이름의 고친 커널과 함께면 0 | 그 제품의 패키지 이름 · 판 꼴 |

## 0.1.0 — 1차 (2026-11-26)

긴급 경로의 1차다(코어 그대로 · `docs/긴급-대응.md`). 범위는 *1차 범위* 의 취약점 줄 가운데 패키지 기록 — **깔린 커널
패키지의 판** 과 **NFS 서버 패키지가 있는가** 둘만 본다(1차 카드). 실행 중인 커널 · nfsd 적재 · 켠 NFS 판 · 2049 수신은
엔진 몫이라 다음 차수다(평소 경로).

### 판정

| 무엇 | 결과 |
|---|---|
| NFS 서버 패키지가 없다 | 0 — nfsd 를 띄울 수 없다(1차 카드) |
| 깔린 커널 패키지가 모두 영향 판이고 고친 판이 없다 — Debian 의 고친 판이 있는 갈래(6.12 · 7.x)와 고친 판 없이 지원이 끝난 bullseye 5.10 · buster 4.19 · stretch 4.9 · 상류 판을 따르는 Fedora · Alpine | 취약(2) |
| 영향 판과 고친 판이 함께 깔렸다 | 확인 필요(6) — 지금 어느 커널로 도는지 이 룰은 모른다 |
| 배포판이 고친 판을 아직 내지 않은 백포트 커널(Ubuntu · RHEL 계열 · Debian 12 의 기본 6.1) | 확인 필요(6) |
| Amazon · SUSE 커널 — 지난 보안 갱신 이력을 재지 못해 백포트로 본다(2차에서 바로잡음 — SUSE 는 1차 조사가 이미 지난 커널 CVE-2026-31431 의 고친 판으로 백포트를 쟀다 · Amazon 은 2차에 AL2023 공지로 쟀다 · 둘 다 같은 상류 판에 개정만 올려 고친다 · 판정은 그대로) | 확인 필요(6) — 모르면 6 |
| Proxmox 커널(dpkg `proxmox-kernel-*` · `pve-kernel-*`) · Fedora rawhide 병합 창 빌드(revision `0.rc0.*.fc*`) | 확인 필요(6) |
| NFS 서버 패키지는 있는데 아는 이름의 커널 패키지를 찾지 못했다(커널 없는 컨테이너 · 이름을 모르는 커널만 깔림) | 확인 필요(6) |
| 깔린 아는 이름의 커널이 모두 고친 판 · Ubuntu · Fedora · Alpine 의 3.16 아래(이름을 모르는 커널이 함께 깔려도) | 0 |

- **실행 중인 커널은 보지 않는다** — 엔진(1.26.0)이 실행 중인 커널 판을 룰에 주지 않는다. 고친 커널을 깔고 다시 시작하지
  않은 기계는 커널이 둘 깔려 확인 필요(6)로 나오고, 그 까닭 줄이 확인하는 법과 다시 시작을 알린다.
- **판으로만 판정한다** — nfsd 를 실었는지 · NFSv4.1 · 4.2 를 켰는지 · 2049 를 듣는지는 판정에 넣지 않는다. 끄는 법은
  위협별 안내의 *꼭 할 일* 이다.
- **배포판마다 견주는 판이 다르다** — Debian 은 추적기의 고친 판과, Fedora · Alpine 은 상류의 고친 판과 견준다. 같은 상류 판에
  개정만 올려 고치는 배포판(Ubuntu · RHEL 계열)과 지난 보안 갱신 이력을 재지 못해 백포트로 보는 배포판(Amazon · SUSE —
  모르면 6 · 2차에서 바로잡음 — SUSE 는 1차에 이미 쟀고 Amazon 은 2차에 쟀다 · 둘 다 같은 상류 판에 개정만 올려 고친다)은
  상류 판 번호로 가리지 못해, 고친 패키지 공지가 나올 때까지
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
| Debian 11 bullseye(5.10) · 10 buster(4.19) · 9 stretch(4.9) | 없음 — Freexian ELTS 추적기 '(unfixed) end-of-life'(bullseye 5.10.272-1 vulnerable) · Debian 보안 추적기의 CVE 표에는 bullseye 줄이 없다 | 취약(2) | deb.freexian.com 의 ELTS 추적기 |
| Ubuntu 16.04 · 18.04 · 20.04 · 22.04 · 24.04 · 26.04 · 26.10 | 없음 — USN 없음 · Vulnerable | 확인 필요(6) | ubuntu.com/security |
| Ubuntu 14.04 trusty | Not affected | 0 | ubuntu.com/security |
| RHEL 6 ~ 10 · AlmaLinux · Rocky · Oracle(RHCK · UEK7 · UEK8) · CentOS Stream 9 · 10 | 없음 — Red Hat VEX known_affected · 최신 커널 RHSA-2026:102590 · 102253 · 102218(같은 번호의 ALSA · RLSA)에 이 CVE 없음 · Oracle 은 ELSA-2026-102218(OL8) · ELSA-2026-100662(OL9) · ELSA-2026-98608(OL10) · UEK ELSA-2026-500643 · 500644 에 이 CVE 없음(yum.oracle.com updateinfo · 2026-11-26 18:03) · CentOS Stream MR !9248 · !4132 병합 전 | 확인 필요(6) | access.redhat.com · errata.almalinux.org · errata.rockylinux.org · yum.oracle.com · gitlab.com/redhat |
| Amazon Linux 2 · 2023 | 없음 — ALAS 0건 · CVE 페이지 404 | 확인 필요(6) | alas.aws.amazon.com |
| SUSE SLES 15 SP6-LTSS · SP7 · SLE Micro 5.4 ~ 6.1 · Leap 15.6 · SLES 15 SP6 일반판(SUSE 지원 종료 칸) · Tumbleweed | 없음 — Affected · 전체 Pending · SUSE-SU 없음(Tumbleweed 는 SUSE 페이지에 줄이 없다) | 확인 필요(6) | suse.com/security |
| Fedora 43 · 44 · 45 | 받지 못함(Bodhi 봇 차단) — 상류 판 그대로(7.3.5-100.fc43 · 7.3.5-200.fc44 · 7.3.4-300.fc45) | 상류 판 기준 0 | dl.fedoraproject.org |
| Alpine 3.21 ~ edge | 추적기 상태 없음(커널 secfixes 를 추적하지 않는다) — 상류 판 그대로(3.22 6.12.119-r0 · 3.24 6.18.65-r0 · edge 7.3.6-r0) | 상류 판 기준 0 | security.alpinelinux.org · gitlab.alpinelinux.org |

### 게이트

| 게이트 | 무엇 | 결과 | 근거 |
|---|---|---|---|
| G1 | 청정 환경 무해성 | 리눅스 스냅샷 19 · 판정 0 · 파괴 동작 0 · 알림 0(`cargo xtask g1` 2026-11-26 18:27 — 룰 23개 · 스냅샷 29개 · 짝 357) | 청정 코퍼스의 리눅스 스냅샷 19개에 커널 패키지 · NFS 서버 패키지가 든 것이 없어 이 룰의 판정 갈래(커널 판)는 G1 로 재지 못한다 — 판정 갈래는 하네스가 잰다 |
| G9 | 룰의 검체 오탐(YARA) | 해당 없음 | 이 룰에는 YARA 규칙이 없다(`rules/` 없음 · `subjects: [package]`) |
| 하네스 | `testbed/harness/linux/nfs2root-verify.sh` | 26/26(2026-11-26 18:54 · 개발 빌드 1.26.0 · 이 PC 의 docker) — 아래 표의 25칸 + 준비 칸 P1(D1 에 깐 커널이 6.12.117-1 이상인가) | 경우마다 패키지 기록을 세운 컨테이너 · D1 만 저장소의 패키지를 실제로 깐다 |

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
| D9 | Proxmox 커널 + 고친 Debian 커널 + `nfs-kernel-server` | 6 |
| D10 | buster 꼴 4.19 + `nfs-kernel-server` | 2 |
| U1 | Ubuntu 24.04 — 6.8.0-151.151 + `nfs-kernel-server` | 6 |
| U2 | Ubuntu 꼴 3.13.0-170.220(영향 밖) + `nfs-kernel-server` | 0 |
| F1 | Fedora — `kernel-core` 7.3.4-300.fc45 + `nfs-utils` | 0 |
| F2 | Fedora — `kernel-core` 7.2.15-200.fc43 + `nfs-utils` | 2 |
| F3 | Fedora — 7.3.1 과 7.3.4 의 fc45 가 함께 | 6 |
| F4 | Fedora rawhide 병합 창 빌드(revision `0.rc0.*.fc*`) + `nfs-utils` | 6 |
| F5 | Fedora — `kernel-16k-core` 영향 판 + 고친 `kernel-core` + `nfs-utils` | 6 |
| R1 | AlmaLinux 9 — `kernel-core` 5.14.0-741.27.1.el9_9 + `nfs-utils` | 6 |
| R2 | AlmaLinux 9 — 같은 커널 · `nfs-utils` 없음 | 0 |
| A1 | Alpine 3.22 — `linux-lts` 6.12.119-r0 + `nfs-utils` | 0 |
| A2 | Alpine 3.22 — `linux-lts` 6.12.116-r0 + `nfs-utils` | 2 |
| N1 | 패키지 DB 자리(dpkg · rpm · apk)가 모두 없다 | 0 + *점검 대상이 이 기계에 없습니다* 안내 |
| S1 | 화면 — 2 칸의 감지 줄에 CVE 번호와 고친 판 문구 | 있음 |
| S2 | 결과 파일 — 6 칸의 확인 필요 까닭(다시 시작 · 배포판 공지 · 커널 패키지 없음 셋) | 있음 |
| S3 | 화면 — 대상이 있는 0 칸에 *점검 대상이 이 기계에 없습니다* 안내 | 없음 |

### 다음 차수 후보

| 범위 | 까닭 | 필요한 것 |
|---|---|---|
| 실행 중인 커널 판 · nfsd 적재 · 켠 NFS 판(`/proc/fs/nfsd/versions`) · 2049 수신 | 엔진(1.26.0)이 룰에 주지 않는다 — 1차는 룰만으로(카드) | 엔진 몫 · 평소 경로 |
| Ubuntu USN · RHSA(ALSA · RLSA · ELSA) · ALAS · SUSE-SU · Debian 6.1 의 DSA · DLA | 2026-11-26 17:55 ~ 18:05 KST 에 공지가 없다(받아 보니 0건 — Fedora Bodhi 만 받지 못함 · 위 표) | 공지가 나오면 그 배포판의 고친 판 줄 · 하네스 칸 |
| SUSE SLES 16 · Leap 16 · SL Micro 6.2 의 Not affected | SUSE 가 까닭을 적지 않았다 — 지금은 다른 SUSE 커널과 같이 확인 필요(6) | SUSE 의 까닭 · 그 커널 판을 가리는 줄 |
| Fedora 의 고친 판 | Bodhi 를 받지 못했다(2026-11-26 17:56 KST · 봇 차단) — Fedora 는 상류 판 기준으로만 본다 | Bodhi 의 이 CVE 갱신 |
| 판 번호로는 고친 판 이상인 Amazon 커널(`kernel6.18` 6.18.62 등) | 지난 보안 갱신 이력을 재지 못해 백포트로 본다(모르면 6) · 공급사가 이 CVE 를 적은 공지가 없다 — 지금은 확인 필요(6) | 공급사 공지 |
| Amazon · SUSE(Tumbleweed 포함) 커널의 지난 보안 갱신 이력 | 재지 않음(2026-11-26) — 지금은 백포트로 보고 확인 필요(6)(2차에서 바로잡음 — SUSE 는 1차 조사가 이미 CVE-2026-31431 의 고친 판으로 쟀다 · Amazon 은 2차에 쟀다 · Tumbleweed 는 0.2.0 의 *다음 차수 후보*) | 지난 커널 공지와 그 판 번호 |
| Ubuntu 24.04 HWE 6.14 · 6.17 | Ubuntu 가 'Ignored end of life' 로 적었다 — 지금은 6 · 정책상 2 후보 | 지원이 끝난 HWE 를 2 로 볼지의 결정 |
| Kali · Raspberry Pi OS · Freexian ELTS · 직접 지은 deb 의 커널 판 꼴 | 판 꼴을 재지 않았다 | 그 배포판의 패키지 이름 · 판 꼴 |
| Arch Linux | 엔진이 pacman 의 패키지 기록을 읽지 않는다 · 추적기에 이 CVE 가 없다(404 · 2026-11-26 17:55 KST) | 엔진 몫 |
| 이름을 모르는 커널 패키지(직접 지은 커널 등) | 커널 패키지로 읽지 않는다 — 아는 이름의 커널이 하나도 없으면 확인 필요(6), 아는 이름의 고친 커널과 함께면 0 | 그 제품의 패키지 이름 · 판 꼴 |
