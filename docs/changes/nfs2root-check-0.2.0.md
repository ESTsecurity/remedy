---
section: rules
rules: [nfs2root-check]
---
* **RHEL 8.10 의 고친 커널 · 지원이 끝난 Ubuntu 24.04 HWE 커널 판정** (Linux)\
  RHEL 8.10 의 커널을 Red Hat 이 낸 고친 버전(4.18.0-553.190.1.el8_10 · RHSA-2026:103817)과 견줍니다 — 그 버전 이상만 깔렸으면 문제없음, 그 아래만 깔렸으면 *취약* 입니다(이전 버전은 둘 다 *확인 필요*). Ubuntu 24.04 의 HWE 커널 6.14 · 6.17 은 지원이 끝나 Ubuntu 가 고치지 않으므로 *취약* 으로 나옵니다(이전 버전은 *확인 필요*).

<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>

* RHEL 8.10 에 고친 커널과 그 아래 커널이 함께 깔렸으면 이전처럼 *확인 필요* 로 나옵니다 — 고친 커널로 다시 시작했는지 `uname -r` 로 확인합니다.
* Ubuntu 24.04 에서 HWE 커널 6.14 · 6.17 을 쓰면 지원 중인 HWE 커널 7.0 으로 옮기고 다시 시작합니다. 7.0 도 아직 고친 커널이 없어 *확인 필요* 로 나옵니다 — 그 전까지 tcp/2049 를 믿는 기계에만 열어 두십시오. OEM · nvidia · 일부 클라우드 갈래의 6.14 · 6.17 은 *확인 필요* 로 나옵니다.
* AlmaLinux · Rocky · Oracle Linux 8 은 RHEL 8.10 과 같은 버전 번호를 쓰지만, 그 배포판이 고친 커널을 내기 전이라 *확인 필요* 로 나옵니다. RHEL 8 의 실시간 커널(kernel-rt) · EUS 8.6 · 8.8 과 RHEL 9 · 10 도 그대로 *확인 필요* 입니다.
* 그 밖의 배포판(Ubuntu · Amazon Linux · SUSE · Debian 12 의 기본 커널 6.1 등)은 고친 커널이 아직 없어 이전처럼 *확인 필요* 로 나옵니다.
* 자세한 내용은 https://github.com/ESTsecurity/remedy/blob/main/docs/%EC%9C%84%ED%98%91%EB%B3%84-%EC%95%88%EB%82%B4.md#nfs2root 에 있습니다.

</details>
