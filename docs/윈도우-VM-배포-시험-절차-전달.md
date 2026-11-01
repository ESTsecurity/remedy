# 로컬 VMware Windows VM 에 바이너리를 보내고 시험하는 법 — 다른 프로젝트에 전달

2026-09-30 · remedy 하네스(`testbed/harness/`)가 실제로 쓰는 절차를 다른 프로젝트가 옮겨
쓸 수 있게 적는다. 여기 적힌 것은 코드(`host/VmSession.ps1` · `host/Reset-Vm.ps1` ·
`guest/Setup-Guest.ps1` · `host/Invoke-VmTest.ps1`)를 읽고 정리한 것이고, 흐름 전체는
2026-09-30 에 채점 13회차 · 화면 캡처 2회로 실제로 돌렸다. 함정 목록의 날짜는 하네스
주석이 적어 둔 실측 날짜다.

## TL;DR

- **전송·실행은 전부 WinRM(PowerShell Remoting)** 이다 — VMware 공유 폴더 · vmrun 의 게스트
  명령 · SSH 는 쓰지 않는다. `New-PSSession` 하나로 파일 복사(`Copy-Item -ToSession /
  -FromSession`)와 실행(`Invoke-Command`)을 다 한다.
- **VMware 는 `vmrun` 으로 스냅샷 복원과 전원만** 맡는다. 매 시험은 같은 스냅샷에서 출발한다.
- 게스트에는 **한 번만** 손댄다(`Setup-Guest.ps1` → 스냅샷). WinRM 켜기 · 원격 관리자 토큰
  (`LocalAccountTokenFilterPolicy`) · 방화벽(호스트 IP 만) · 작업 폴더 `C:\remedy-lab\` 다.
- 바이너리·픽스처·결과는 스냅샷에 넣지 않는다 — **매 회차 호스트가 새로 보내고, 결과는 VM 디스크에
  먼저 쓴 뒤 마지막에 회수**한다(파괴적 시험이 세션을 끊어도 남는다).
- 함정은 대부분 "Windows 가 조용히 다르게 동작하는 자리" 다 — §5 에 실측 날짜와 함께 있다.
  새 프로젝트가 같은 자리에서 다시 헤매지 않게 하려는 것이 이 문서의 목적이다.

## 1. 구성 한눈에

```
  호스트 (Windows 11 · VMware Workstation)                 게스트 VM (Windows 10 x64 · NAT VMnet8)
  +----------------------------------------------+       +-----------------------------------+
  | host/*.ps1                                    |       | C:\remedy-lab\                    |
  |   Reset-Vm.ps1   --vmrun revert/start-------> |       |   bin\       <- 바이너리 (매 회차) |
  |   VmSession.ps1  --WinRM 5985 (PSSession)---> |       |   scripts\   <- 게스트 스크립트     |
  |     Copy-Item -ToSession   (배포)             |       |   fixtures\  <- 시험 대상 (매 회차) |
  |     Invoke-Command         (실행·캡처)        |       |   results\<run-id>\  (먼저 여기)   |
  |     Copy-Item -FromSession (회수)             |       |   baseline\  (스냅샷에 든 기준 상태)|
  | results\<run-id>\  <-------------------------- |       |   work\                            |
  +----------------------------------------------+       +-----------------------------------+
  자격 증명: %LOCALAPPDATA%\remedy-lab\vm-cred.xml (DPAPI, 접속 성공 뒤에만 저장)
```

| 자리 | 값 (remedy 랩 — `<…>` 는 기계마다 다른 값) | 어디에 적혀 있나 |
|---|---|---|
| VMX | `<VM 폴더>\Win10x64-Test\Win10x64-Test.vmx` | 하네스 `param` 기본값 · `.cargo/windows_lab.yml` 의 `identity.vmx` |
| 스냅샷 | `remedy-lab-base-v3` (켜진 채 찍음 → 되돌리면 곧바로 켜져 있다) | 같은 곳 |
| 게스트 주소 | `<게스트 주소>` (NAT · DHCP 라 바뀔 수 있다 — §5-1) | 같은 곳 (`network.ip`) |
| 포트 | WinRM HTTP 5985 (HTTPS 는 쓰지 않는다 — 격리 NAT) | `Setup-Guest.ps1` |
| 계정 | `<주소>\test` — 로컬 관리자, 비밀번호 있음 | `.cargo/windows_lab.yml` (비밀번호는 커밋하지 않는 별도 파일) |
| 게스트 작업 폴더 | `C:\remedy-lab\{bin,work,results,fixtures,baseline,scripts}` | `Setup-Guest.ps1` |

운영 값은 저장소에 커밋하지 않는 `.cargo/*.yml` 에 두고, 하네스 스크립트의 `param` 기본값이
원본이다. 다른 프로젝트도 **주소·VMX·스냅샷 이름을 코드가 아니라 한 곳**에 두는 편이 낫다 —
remedy 는 `-VmAddress` 기본값이 열여섯 곳에 박혀 있어 주소가 바뀔 때마다 전부 어긋났다(§5-1).

## 2. 게스트 준비 — 한 번만 (`guest/Setup-Guest.ps1`, VM 콘솔에서)

```powershell
powershell -ExecutionPolicy Bypass -File .\Setup-Guest.ps1 -HostAddress <호스트의 VMnet8 주소>
```

하는 일과 **왜 그래야 하는지**:

1. `C:\remedy-lab\` 아래 여섯 폴더를 만들고 게스트 스크립트를 `scripts\` 에 복사한다 — 호스트가
   경로를 가정할 수 있어야 한다.
2. `Enable-PSRemoting -Force -SkipNetworkProfileCheck` — 네트워크 프로필이 Public 이면 기본
   거부라 검사를 건너뛴다. 대신 방화벽 규칙을 **호스트 IP 하나로만** 연다(옆 VM 에 노출할 이유가
   없다). ICMP 도 호스트에만 연다 — 파괴적 시험 뒤 "죽었는지 방화벽인지" 를 가르려면 ping 이
   있어야 한다.
3. **`HKLM\...\Policies\System\LocalAccountTokenFilterPolicy = 1`** — 워크그룹 PC 에 로컬 관리자
   계정으로 원격 접속하면 UAC 가 토큰에서 Administrators 를 떼어내, 세션이 **열리기도 전에**
   '액세스 거부' 가 난다. 비밀번호 오류 · 그룹 미가입과 문구가 같아 구분이 안 되는 오류다.
   UAC 자체(`EnableLUA`)는 끄지 않는다 — 끄면 Defender · 스토어 앱 동작이 실제 PC 와 달라진다.
   격리 VM 에서만 받아들이는 완화이고 업무 PC 에는 적용하지 않는다. **이 값은 스냅샷에 들어가야
   한다.**
4. 환경 정보 · 설치된 보안 제품 · 기준 시스템 상태를 `baseline\` 에 JSON 으로 남긴다.
5. 호스트에서 할 일(TrustedHosts)을 화면에 찍어 준다.

그 뒤 **스냅샷을 찍는다.** 스냅샷에 넣는 것 / 넣지 않는 것:

| 넣는다 | 넣지 않는다 |
|---|---|
| WinRM · 방화벽 · 토큰 정책 | 시험 대상 바이너리 (빌드마다 바뀐다) |
| 작업 폴더 구조 · 게스트 스크립트 | 픽스처 (매 회차 새로 만든다) |
| 기준 상태 JSON | 실행 결과 |

스냅샷은 **깨끗한 실험대**다. 같은 지점에서 출발해야 결과를 비교할 수 있다. remedy 는 거기에
**자동 갱신기 끄기**(`Disable-LabUpdaters.ps1`)를 더해 v3 를 만들었다 — 되돌린 게스트의 Windows
Update · Chrome · Store 갱신기가 회차 도중에 움직여 "치료가 만든 변화" 로 세어졌기 때문이다
(2026-09-11). Defender 는 켜 둔다.

## 3. 호스트 준비 — 한 번만

- **호스트 WinRM 서비스는 떠 있어야 한다**(클라이언트 역할이라도). `WSMan:` 드라이브가 그 서비스
  위에서 열려서, 멈춰 있으면 TrustedHosts 를 읽지도 못하는데 오류는 "대상에 연결할 수 없습니다"
  로 나와 VM 문제로 오해하기 좋다. `Start-Service WinRM` 이면 되고 **`winrm quickconfig` 는 쓰지
  않는다** — 호스트에 리스너를 만들어 원격 접속 대상으로 노출시킨다.
- **TrustedHosts** — 워크그룹이라 Kerberos 가 없으므로 게스트 주소를 신뢰 목록에 넣어야 한다.
  주소가 바뀌어도 다시 하지 않게 **대역으로** 한 번만:
  `Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<VMnet8 대역 앞 세 자리>.*' -Force` (관리자 PowerShell).
  하네스는 목록에 없으면 기존 항목을 덮지 않고 **더한다**(`-like` 로 대역 항목도 인정).
- **자격 증명**은 첫 접속 때 `Get-Credential` 로 묻고, `-SaveCredential` 이면 **접속에 성공한
  뒤에만** `Export-Clixml` 로 저장한다(DPAPI — 같은 사용자 · 같은 머신에서만 풀린다, 다른 곳으로
  복사해도 못 쓴다). 접속 전에 저장하면 틀린 값이 조용히 재사용된다. 빈 비밀번호는 미리 끊는다 —
  Windows 는 빈 비밀번호 계정의 네트워크 로그온을 막아(`LimitBlankPasswordUse`) '액세스 거부' 로만
  나온다.

## 4. 한 회차 — 배포 · 실행 · 회수 (`host/Invoke-VmTest.ps1` 의 차례)

```
  (빌드) → 바이너리 찾기 · SHA256 · 정적 링크 확인 → (스냅샷 복원) → 연결 · 관리자 확인
  → run-id 폴더를 VM 에 만들기 → 게스트 스크립트 동기화 → 사전 상태 캡처
  → (픽스처 생성 → 기준선 재캡처) → 바이너리 배포 → 실행(출력은 VM 파일로) → run.json
  → 사후 상태 캡처 → 결과 회수 → 상태 비교
```

각 단계에서 쓰는 원시 호출 — 다른 프로젝트가 그대로 가져갈 수 있는 것은 이 다섯이다:

| 단계 | 호출 | 왜 이렇게 |
|---|---|---|
| 스냅샷 복원 | `vmrun -T ws listSnapshots <vmx>` → 이름이 **정확히 하나**일 때만 `revertToSnapshot` → 안 켜져 있으면 `start <vmx> gui`(화면 모드 — Workstation 탭과 일치하고 콘솔이 보인다 · 2026-09-30 결정 A, 그전엔 `nogui`) → 5985 포트가 열릴 때까지 폴링(≤240초) | 이름이 중복된 스냅샷으로는 되돌리지 않는다(어디로 갈지 모른다). 켜진 채 찍은 스냅샷은 메모리까지 복원돼 곧바로 켜져 있다 |
| 연결 | `New-PSSession -ComputerName <ip> -Credential <cred>` → 세션 안에서 `WindowsPrincipal.IsInRole(Administrator)` 확인 | 관리자가 아닌 세션으로 시작하면 모든 실패가 '액세스 거부' 가 되어 원인을 못 가른다 — 시작하지 않는 편이 낫다 |
| 배포 | `Copy-Item <로컬> -Destination C:\remedy-lab\bin\x.exe -ToSession $s -Force` | `.ps1` 은 보내기 전에 BOM 과 문법(`Parser::ParseFile`)을 검사한다 — 깨진 스크립트를 VM 에서 발견하면 이미 파괴적 실행이 끝난 뒤일 수 있다 |
| 실행 | `Invoke-Command -Session $s { Start-Process <exe> -RedirectStandardOutput <VM 파일> -RedirectStandardError <VM 파일> -Wait -PassThru }` → 종료 코드 · 소요 시간 · 원격 SHA256 을 `run.json` 으로 **VM 에 먼저** 기록 | 파괴적 시험은 세션 자체를 끊을 수 있다. 출력을 연결 위에 얹으면 가장 알고 싶은 실패에서 그 데이터를 잃는다. 원격 해시가 로컬과 다르면 전송 오류로 잡는다 |
| 회수 | `Copy-Item C:\remedy-lab\results\<run-id> -FromSession $s -Recurse` → `testbed/harness/results/<run-id>/` | 회수한 **뒤에** 스냅샷을 되돌린다 |

실행을 두 가지로 나눠 둔 이유:

- **바이너리 실행** — `Invoke-GuestExe`: 게스트 안에서 `ProcessStartInfo` 로 직접 띄운다.
  `&` 로 부르면 `$ErrorActionPreference = "Stop"` 아래에서 stderr 한 줄이 `NativeCommandError`
  가 되어 **관측하려던 실패가 관측 자체를 죽인다.** stdout·stderr 를 UTF-8 로 받고(진단문이
  모지바케면 실패 이유를 못 읽는다), 읽기를 먼저 걸고 `WaitForExit` 한다(파이프가 차면 서로
  기다리다 멈춘다). **종료 코드는 판정하지 않고 그대로 돌려준다** — remedy 의 종료 코드는 0/비0
  이 아니라 뜻이 갈린다(6 = 관측 불완전). 인자는 Windows CRT 의 역슬래시-따옴표 규칙대로 감싼다
  (`C:\dir\` 처럼 역슬래시로 끝나는 값을 그냥 감싸면 인자 경계가 무너진다).
- **게스트 스크립트 실행** — `Invoke-GuestScript`: `powershell.exe -NoProfile -NonInteractive
  -ExecutionPolicy Bypass -File <스크립트>` 자식으로 돌린다. 원격 세션은 VM 의 ExecutionPolicy
  (클라이언트 기본 Restricted)를 따라 `& script.ps1` 이 막히는데, 자식에 Bypass 를 주면 **VM 의
  정책을 건드리지 않고** 돌릴 수 있다. 출력과 종료 코드는 **따로** 돌려받는다.

관측은 시험 대상 코드를 쓰지 않는다 — 게스트의 `Capture-State.ps1` 이 시스템 상태(프로세스 ·
서비스 · 예약 작업 · 자동 실행 · 파일)를 JSON 으로 뜨고, 호스트의 `Compare-State.ps1` 이 전/후를
견준다. "검증자가 피검증자를 신뢰하면 검증이 아니다" 가 이 하네스의 첫 줄이다. 전/후 캡처의 범위
(`-FilePaths`)는 반드시 같아야 한다 — 다르면 없는 변경이 만들어진다.

## 5. 함정 — 실측 날짜와 함께

1. **게스트 주소가 바뀐다** (2026-09-10). 스냅샷 복원 · 재부팅마다 DHCP 가 다른 주소를 줄 수
   있다(하루에 `.128 → .137 → .128`). 하네스는 **주어진 주소가 죽어 있을 때만**
   `vmrun getGuestIPAddress` 로 묻고, 돌고 있는 VM 이 **정확히 하나**일 때만 그 값을 쓴다 —
   잘못 고르면 남의 기계에 파괴적 시험을 돌린다. `Select-Object -First 1` 로 파이프를 끊으면
   네이티브 명령의 `$LASTEXITCODE` 가 -1 이 되므로 배열로 받아 **값이 IP 모양인지**로 판단한다.
2. **살아 있는지는 ping 한 발로 못 잰다.** ARP 해석으로 첫 패킷이 곧잘 유실된다 — `Test-Connection
   -Count 2` + TCP 5985 접속으로 본다.
3. **재부팅 뒤 재연결** (2026-09-13 실측). 포트가 열린 순간부터 곧바로 쓸 수 있고 118초 동안 한
   번도 깨지지 않았다 — 그런데 **내려가는 데 3~12초로 네 배 흔들린다.** 고정 시간을 자고
   "살아났는가" 만 물으면 아직 내려가지 않은 옛 OS 에 붙는다. 먼저 **내려간 것을 확인**하고, 그
   뒤 세션을 열어 사소한 명령을 5초 간격 세 번 통과시킨 것만 "쓸 수 있다" 로 본다
   (`Connect-LabVmRetrying`, 예산 180초).
4. **켜진 채 찍은 스냅샷은 시계도 되돌린다** (2026-09-10). `tools.syncTime = FALSE` 면 보정이
   언제 올지 모른다(45분 넘게 오지 않았다). 게다가 되돌린 뒤 약 20초에 무언가가 시각을 **다시
   스냅샷 시각으로 쓴다** — 한 번 맞추고 끝내면 지워진다. 하네스는 호스트 시각을 밀어 넣고 15초
   뒤 남아 있는지 최대 세 번 확인한다. 언제 잰 것인지 모르는 증거는 증거가 아니다.
5. **스냅샷 안의 게스트 스크립트는 찍을 때의 판이다.** 되돌린 뒤 그대로 쓰면 옛 코드가 돈다 —
   이미 고친 fork bomb 판이 복원과 함께 되살아나 PowerShell 프로세스가 143개까지 쌓였다. 복원
   직후 저장소 최신본으로 **매번** 맞춘다.
6. **자동 갱신기** (2026-09-11). 시계를 맞추기 시작하자 기계가 자기가 열이레를 건너뛴 것으로 보고
   Windows Update · Chrome 이 밀린 일을 회차 도중에 했다 — 채점이 "치료가 만든 변화 4건" 으로
   불합격했고, 수집이 120초 늘었다. 갱신기를 끈 스냅샷(v3)으로 해결. `TrustedInstaller` 소유
   작업은 관리자도 못 끄므로 서비스 · 정책 키로 위에서 막는다.
7. **인코딩이 파일 종류마다 정반대다.** `.ps1` 은 **BOM 이 있어야** 한다 — 없으면 Windows
   PowerShell 5.1 이 CP949 로 읽어 한글 주석의 바이트를 따옴표 · 괄호로 오독한다. `.json` 은
   **BOM 이 있으면 안 된다** — 대부분의 파서가 거부한다. 그래서 JSON 은 `Out-File` 이 아니라
   `[IO.File]::WriteAllText(path, text, UTF8Encoding($false))` 로 쓴다(`Out-File` 은 BOM 을
   붙이고 실패해도 조용히 0바이트를 남긴다).
8. **정적 링크는 플래그 하나로 조용히 빠진다.** VM 에는 UCRT 가 있어 동적 바이너리도 잘 돌아
   시험은 12/12 통과했는데 배포될 물건은 다른 것이었다. 배포 전에 임포트 테이블을 본다
   (`cargo xtask static <exe>`) — 다른 언어라면 `dumpbin /dependents` 같은 것으로 같은 검사를
   둘 것.
9. **WinRM 세션에는 콘솔이 없다.** stdin 이 터미널인지 보는 대화형 경로("예/아니오")는 원격에서
   언제나 거짓이라 시험 밖에 남는다. remedy 는 게스트 안에서 `AllocConsole` 로 콘솔을 만들고
   `WriteConsoleInput` 으로 답을 밀어 넣는 별도 스크립트(`Approve-Interactive.ps1`)로 메웠다 —
   같은 스크립트 안에서 하면 PowerShell 호스트의 화면 버퍼가 깨져 뒤 로그가 사라진다.
10. **cargo 의 stderr** — 진행 문구가 전부 stderr 라 PowerShell 5.1 이 ErrorRecord 로 감싼다.
    빌드 출력을 변수로 받아 **실패했을 때만** 찍는다(`$LASTEXITCODE` 는 할당이라 그대로 남는다).
11. **VM 이 죽었을 때** 결과는 `C:\remedy-lab\results\<run-id>\` 에 남아 있다. 순서: 재부팅 뒤
    WinRM 이 살면 `-FromSession` 으로 회수 → 안 되면 VM 콘솔에서 공유 폴더로 → 부팅이 안 되면
    가상 디스크를 다른 VM 에 붙여 꺼낸다 → **회수한 뒤에** 스냅샷을 복원한다.

## 6. 다른 프로젝트가 옮길 때 — 최소 절차

1. VM 하나(격리 NAT), 로컬 관리자 계정(비밀번호 있음). 콘솔에서 §2 의 셋(WinRM · 토큰 정책 ·
   방화벽) + 작업 폴더 → **켜진 채** 스냅샷. 갱신기를 끄고 찍으면 회차 잡음이 준다.
2. 호스트: WinRM 서비스 기동, TrustedHosts 대역 등록, 첫 접속 뒤 자격 증명 저장.
3. 회차 스크립트는 §4 의 다섯 호출로 짠다. **결과는 VM 디스크에 먼저**, 회수는 마지막에,
   복원은 회수 뒤에. 전/후 상태 캡처는 시험 대상과 무관한 코드로.
4. 되돌린 뒤엔 시계 · 게스트 스크립트 · 바이너리를 **매번** 새로 맞춘다.
5. 판정은 종료 코드와 판정 줄을 **둘 다** 본다 — 판정을 못 읽었으면 통과로 세지 않는다.

remedy 의 실제 구현은 `testbed/harness/host/VmSession.ps1`(연결 · 배포 · 실행 공용 함수, 진단
문구 포함) · `Reset-Vm.ps1` · `Invoke-VmTest.ps1` 이고, 하네스 열아홉을 한 번에 도는
`Invoke-Sweep.ps1` 이 그 위에 있다(한 바퀴 약 50분). 리눅스 짝은 VM 이 아니라 **docker 컨테이너**
(`rust:1.96-bookworm`)다 — 새 컨테이너가 스냅샷 복원과 같은 청정 기준을 준다.

## 못 재는 것 · 이 문서의 한계

- VMware Workstation 의 `vmrun -T ws` 기준이다. ESXi · Hyper-V · VirtualBox 는 복원 · 주소
  조회 명령이 다르다(WinRM 쪽은 같다).
- 도메인 가입 VM 이면 TrustedHosts · 토큰 정책이 필요 없을 수 있다 — 여기서는 워크그룹만 쟀다.
- 시간 수치(재연결 118초 · 갱신기 +120초 등)는 이 PC · 이 VM 의 실측이다.
