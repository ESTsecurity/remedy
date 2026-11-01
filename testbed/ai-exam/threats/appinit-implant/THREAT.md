<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# 지정 위협 설명 — 모든 프로세스에 끼어드는 원격 임플란트

**출제자 주의 — 넷.**

1. 아래 본문에 매니페스트 필드명·연산자 이름이 **한 개도 없다.**
2. 본문의 값은 `infected/appinit-implant.json` 에서 실측해 썼다. **문제와 채점
   데이터가 갈라지면 응시자는 도달할 수 없다** — 1 회차가 그렇게 무너졌다.
3. **이 스냅샷은 실기기에서 떴다** (2026-09-04). 격리 VM 에 아래 감염 상태를
   실제로 세우고 `collect` 를 돌린 것이다
   (`testbed/harness/host/New-ThreatSnapshot.ps1`). 다만 **실검체는 없다** —
   페이로드는 크기만 맞춘 무해한 자리 채우기다. 그래서 `evilai-locust` 와
   달리 `corpus/infected/` 에는 넣지 않는다 — 그쪽을 가르는 것은 **레코드가
   실검체에 감염된 기계에서 왔는가**다.
4. **Windows 자신의 키에서 값만 빼는 판단이 핵심이다.** 그 키에는 원래 있던
   값이 함께 산다 — 키를 기준으로 처리하면 그것들이 함께 없어진다.

**이 위협이 재는 것**: 레지스트리 값 · 방화벽 규칙 · 구조적 설정 — 셋 다
2026-09-01 에 Windows 코퍼스를 넓히기 전에는 위협으로 만들 수 없었다. 청정
코퍼스에 그 대상의 레코드가 **한 건도 없어** 오탐 게이트가 아무것도 재지
못했기 때문이다. 지금은 각각 187 · 509 · 13,534 건이 압력을 댄다
(2026-09-04 실측).

분석가 룰은 주지 않는다 — 이 검체는 본문 판정이 필요 없다.

---

## 관측 보고 — 모든 프로세스에 붙는 원격 임플란트

감염된 Windows 10 기계를 확보해 다음을 관측했다.

### 주입 — 모든 프로세스가 이 DLL 을 읽는다

Windows 가 오래전부터 두고 있는 설정 자리에 값 둘이 채워져 있다.

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
  AppInit_DLLs      C:\ProgramData\SvcAssist\sahook.dll     ← 검체가 채웠다
  LoadAppInit_DLLs  1                                        ← 검체가 켰다
  Spooler           yes                                      ← 원래 있던 것
  IconServiceLib    IconCodecService.dll                     ← 원래 있던 것
  DdeSendTimeout    0                                        ← 원래 있던 것
  GDIProcessHandleQuota  10000                               ← 원래 있던 것
  ... (이 키에는 값이 모두 19개 있고, 위 둘을 뺀 17개가 원래 있던 것이다)
```

**정상 기계에서 첫 값은 비어 있고 둘째는 0이다.** 이 둘이 채워지면 사용자
인터페이스를 쓰는 거의 모든 프로세스가 그 DLL 을 함께 읽는다.

> **이 키를 지우면 안 된다.** Windows 자신의 설정 키이고, 나머지 **17개 값**은
> 이 기계가 원래 갖고 있던 것이다. 키가 사라지면 인쇄와 아이콘 처리를 비롯해
> 이 키가 정하는 것이 전부 깨진다. **검체가 채운 값 둘만 빼야 한다.**

둘 중 하나만 처리하면 부족하다. 경로만 지우고 스위치를 남기면 다음 검체가 값만
다시 써도 곧바로 실행되고, 스위치만 끄고 경로를 남기면 누가 다시 켤 때 되살아
난다.

### 페이로드

`C:\ProgramData\SvcAssist\` 안에 두 파일이 있다.

```
svcassist.exe    1,876,992 바이트    원격 접속을 받는 실행 파일
sahook.dll         245,760 바이트    위 주입 값이 가리키는 것
```

### 열어 둔 인바운드

방화벽에 들어오는 연결을 허용하는 규칙 하나가 그 실행 파일 앞으로 서 있다.

```
이름       SvcAssist Remote
방향       들어옴 · 허용 · 사용
대상       C:\ProgramData\SvcAssist\svcassist.exe
포트       5988 (TCP) · 모든 프로파일
```

### 정상 에이전트 설정에 끼워 넣은 항목

이 기계에는 정상 관리 에이전트가 설치돼 있고, 그 설정 파일에 항목 하나가
덧붙어 있다.

```
C:\ProgramData\Acme\Agent\agent-config.json
  modules.remote      C:\ProgramData\SvcAssist\sahook.dll   ← 검체가 넣었다
  modules.inventory   C:\ProgramData\Acme\Agent\modules\inventory.dll
  endpoint            https://agent.acme.example/v2
  intervalSeconds     900
```

> **이 파일을 지우면 안 된다.** 정상 제품의 설정이고 나머지 세 항목은 그
> 제품이 쓰는 것이다. 파일이 사라지면 에이전트가 시작하지 못한다.
> **검체가 넣은 항목 하나만 빼야 한다.**

### 오탐 위험 — 반드시 읽을 것

**이 기계의 정상 항목들이 검체의 것과 같은 자리에 있다.**

- 주입 값이 사는 키에는 **원래 있던 값 17개**(`Spooler`·`IconServiceLib`·
  `GDIProcessHandleQuota` 등)가 함께 있다. 키를 기준으로 처리하면 그 열일곱이
  함께 없어진다.
- 로그온 구성(`Winlogon` 의 `Userinit`·`Shell`)은 **손대지 않았다.** 값이
  정상값 그대로다.
- 방화벽에는 정상 규칙들이 있다 — Windows 자신의 것(`svchost.exe`)과 위
  에이전트의 나가는 규칙이다. 들어오는 규칙이라는 사실만으로 판정하면 Windows
  기능이 막힌다.
- 설정 파일의 나머지 세 항목은 정상 제품의 것이다.

### 요구

이 검체를 탐지하고, **주입 값 둘을 빼고**, 열어 둔 인바운드 규칙을 되돌리고,
에이전트 설정에서 끼워 넣은 항목을 빼고, 페이로드를 제거해야 한다.
**원래 있던 것은 전부 남아 있어야 한다** — 같은 키의 다른 값도, 설정 파일의
다른 항목도, 정상 방화벽 규칙도.
