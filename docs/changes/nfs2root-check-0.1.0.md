---
section: rules
rules: [nfs2root-check]
---
* **NFS2ROOT 점검 항목 추가 — CVE-2026-99362** (Linux)\
  리눅스 커널 안의 NFS 서버(nfsd) 결함 NFS2ROOT(CVE-2026-99362)는 tcp/2049 에 닿는 누구나 로그인 없이 그 서버의 root 권한을 얻을 수 있는 결함입니다. NFS 서버 패키지가 깔린 기계에서 깔린 커널 패키지의 버전이 영향을 받는 버전인지 봅니다. 아무것도 바꾸지 않습니다.

<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>

* *취약* 이나 *확인 필요* 이면 배포판의 고친 커널로 올리고 다시 시작합니다 — 커널은 다시 시작해야 바뀝니다.
* 지금 실행 중인 커널은 보지 않습니다. 고친 커널을 깔고 다시 시작하지 않은 기계는 *확인 필요* 로 나옵니다 — `uname -r` 로 지금 커널을 확인합니다.
* 2026-11-26 에 Ubuntu · RHEL 계열 · Amazon Linux · SUSE · Debian 12 의 기본 커널(6.1)은 고친 커널이 아직 없어 *확인 필요* 로 나옵니다. 그 전까지 tcp/2049 를 믿는 기계에만 열어 두고 NFSv4.1 · 4.2 를 끄십시오. NFS 서버를 쓰지 않으면 nfs-server 를 끄십시오.
* NFS 서버 패키지가 깔리지 않은 기계는 커널 버전과 상관없이 취약으로 보지 않습니다.
* 고르는 화면의 *새로 추가된 항목* 에 보입니다. 끄는 법과 자세한 내용은 https://github.com/ESTsecurity/remedy/blob/main/docs/%EC%9C%84%ED%98%91%EB%B3%84-%EC%95%88%EB%82%B4.md#nfs2root 에 있습니다.

</details>
