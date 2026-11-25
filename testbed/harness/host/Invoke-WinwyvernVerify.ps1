#Requires -Version 5.1
# 룰: winwyvern-1-check, winwyvern-2-clean — 묶어 낸 출시의 필수 점검 ① 과 PR CI 가 이 하네스를 찾아 돌린다(Invoke-RuleHarness.ps1 · -Package · -LogDir)
# 입력: 없음
# rc 묶음: winwyvern
# 하네스 표: Windows 랩(러너 · 랩 VM) | WinWyvern 탐지 · 제거 룰 — 취약 드라이버 NeacSafe64 의 서비스(자동 시작 · ImagePath 꼴)와 System32 의 그 파일 · 하나만 남은 흔적 · 다른 시작 유형 · 다른 자리에서 두 룰의 판정이 같은가 · 제거 룰의 치료(서비스의 네 동작) → 다시 검사 → 복원(서비스 키 하위 트리의 값 목록) → 다시 검사 · 서비스 핸들을 붙든 채 치료하면 '다시 시작해야 끝남' 을 알리고 지우는 중의 복원은 멈추는가(엔진 1.26.0 부터)
<#
.SYNOPSIS
    WinWyvern 의 두 룰(winwyvern-1-check 탐지 · winwyvern-2-clean 제거)을 랩에서 잰다 — 서비스 · 파일의 꼴마다 종료 코드와
    흔적 · 위협 수 · 치료 계획, 그리고 제거 룰의 치료 → 다시 검사 → 복원 → 다시 검사.

.DESCRIPTION
    `-Package` 는 `remedy-windows-x64` 폴더다(내려받아 푼 배포본, 또는 `New-DevPackage.ps1` 로 꾸린 개발 꾸러미). 그
    remedy.exe 와 그 안의 `plugins\winwyvern-1-check` · `plugins\winwyvern-2-clean` 을 그대로 쓴다. 받을 입력은 없다(머리의
    `# 입력: 없음`) — 자리 채우기만 쓴다. `-Inputs` 는 rc 묶음이 표준 인자로 주는 것이라 받기만 하고 쓰지 않는다.

    랩 VM(호스트에서 WinRM)과 GitHub 호스팅 러너(자기 자신 · `Initialize-RunnerLab.ps1` 뒤) 둘 다에서 돈다. 러너에는 되돌릴
    스냅숏이 없으므로 되돌리기에 기대지 않고 놓은 것을 스스로 치운다. 개발 PC 자신에는 붙지 않는다(`Connect-LabVm` 의 가드).
    재부팅하지 않는다 — 러너는 재부팅할 수 없다. 치료 → 재부팅 → 다시 검사 · 재부팅 뒤 확인은 랩 VM 에서 따로 잰 값을 제거
    룰의 RELEASE.md 에 남긴다.

    # 무해한가

    실검체는 없다. 드라이버 자리에는 표지 글자만 담은 작은 파일(`REMEDY-LAB placeholder …` — PE 가 아니다)을 게스트의
    `%SystemRoot%\System32` 에 둔다. 서비스는 `sc.exe create`(파일 시스템 드라이버 · 시작 유형은 칸마다)로 **등록만** 하고
    시작하지 않는다. ImagePath 꼴을 바꾸는 칸은 등록 뒤 그 값 하나만 레지스트리에서 고친다. 제거 룰의 치료(T)는 그 등록을
    지우고(복구 설정 해제 · 정지 · 사용 안 함 · 삭제) 재부팅 뒤 확인을 RunOnce(`remedy-verify`)에 건다 — 이 하네스는 재부팅하지
    않고, 끝에 그 예약을 지운다. remedy 가 쓰는 상태(격리소 · 저널 · 봉인 키 · 로그)는 모두 작업 폴더 안(`--state-dir`)에 둔다.
    칸마다 앞의 것을 치우고 세우며, 끝에(중간에 실패해도 finally 에서) 모두 치운 뒤 남은 것이 없는지 본다(C1). 시작 전에 그
    서비스 · 파일 · 예약이 이미 있으면(랩에 원래 있던 것) 아무것도 건드리지 않고 멈춘다.

    # 무엇을 재나

      A  감염 1 — ASEC 꼴: sc.exe 가 둔 ImagePath(binPath 는 게스트의 SystemRoot 아래 System32\neacsafe64.sys) · 자동
         시작 · 그 파일 → 2(흔적 2 · 위협 1). 칸 줄에 SCM 이 실제로 둔 ImagePath 를 적는다
      V  꼴 변형 10 — ImagePath 를 `\SystemRoot\System32\…` · `System32\…` · `%SystemRoot%\…` · `%windir%\system32\NeacSafe64.sys`
         · `\??\` 와 대문자 · REG_SZ 의 전체 경로 · 따옴표로 감싼 전체 경로 · `\\?\` 로 바꾼 것, 서비스 이름 소문자, 파일
         이름 대소문자 → 모두 2(흔적 2 · 위협 1)
      N  아무것도 없음 1 → 0(흔적 0)
      S  서비스만(파일 없음) 1 → 0(흔적 1)
      F  파일만(서비스 없음) 1 → 0(흔적 1)
      M  자동이 아닌 시작 유형 4 — 수동 · 사용 안 함 · 시스템 · 부팅 + 그 파일 → 0(흔적 1)
      D  다른 자리 3 — drivers 폴더(sc.exe 가 둔 꼴) · `System32\drivers\…` · `\SystemRoot\SysWOW64\…` + System32 의 그 파일
         → 0(흔적 1)
      …c 위 21 칸마다 같은 꼴을 제거 룰로 검사 21 — 종료 · 흔적 · 위협이 탐지 룰과 같고, 치료 계획(결과 폴더의 plan.json)은
         위협 칸에서만 넷(복구 설정 해제 → 정지 → 사용 안 함 → 삭제 · 그 차례)이며 0 칸(깨끗한 기계 · 서비스만 · 파일만 ·
         다른 시작 유형 · 다른 자리)에서는 없다
      T  제거 룰의 치료 7 — 감염 꼴(A1)에 미니필터 등록의 일반 꼴(의존 값 하나 · Instances 하위 키 둘 — Altitude 만 자리 채우기다.
         나머지 셋은 ASEC [표 3] 과 같은 값이다)을 더해: T1 검사 2 · 치료 계획 넷 → T2 치료(run --yes) 1 · 네 동작이 그 차례로 모두
         끝남 → T3 서비스 키 없음 · SCM 이 모름 · 드라이버 자리 파일 그대로(해시) · 재부팅 뒤 확인 예약(그 회차) → T4 다시
         검사 0(두 룰 · 흔적 1 — 남긴 파일) → T5 복원(restore --yes) 0 · 3건 → T6 서비스 키 하위 트리의 값 목록(키 · 이름 ·
         종류 · 데이터)이 치료 전과 같음 → T7 다시 검사 2(두 룰). T2 는 '다시 시작해야 끝남' 을 말하지 않아야 한다 — 화면의
         목록 줄도 --events finished 의 reboot_required 도 없다(T2r · 곧바로 지워진 치료)
      H  서비스 핸들을 붙든 채 치료 7(엔진 1.26.0 부터 — 그 앞의 꾸러미면 건너뛰고 그 줄만 적는다) — 같은 꼴(T 와 같다)을 세우고
         무해한 프로세스 하나가 서비스 핸들을 연 채 붙든다: H1 치료(run --yes) 1 · 네 동작 끝남 · 실패 0 · finished 의
         reboot_required · 화면의 '[4] 서비스 삭제 … 미뤘습니다' 줄과 되돌리는 차례 줄 → H2 서비스 키 있음 · Start 4 · 지울 표시
         (DeleteFlag 1) → H3 복원(--yes 없음) 5 · 막은 사유 · '다시 시작한 뒤 다시 복원' 끝 줄 · 값 목록 그대로 → H4 복원(--yes)
         5 · 아무것도 쓰지 않음 → H5 놓음 → 10초 안에 키가 사라지고 SCM 이 모름(1060) → H6 복원(--yes) 0 · 3건 · 값 목록이 치료
         전과 같음 → H7 다시 검사 2(두 룰). 다시 시작은 하지 않는다 — 핸들을 놓는 것이 같은 일을 한다(2026-11-25 랩: 놓자
         첫 물음에서 키가 없었다)
      C  치운 뒤 남은 것 1 — 서비스 키 · SCM 의 서비스 · System32 의 그 파일 · 작업 폴더 · RunOnce 의 remedy-verify · 핸들을 붙든
         프로세스가 모두 없다

    0 칸은 감염 칸에서 한 가지만 다르다. 그 0 이 그 까닭으로 나왔는지를 화면의 흔적 수로 함께 본다 — 흔적 0 이면 룰이 아무
    것도 못 본 것이고, 흔적 1 이면 두 근거 가운데 하나만 선 것이다.

    T6 은 값 단위로 견준다 — 엔진은 백업할 때 값을 이름 차례로 담아 그 차례로 되쓰므로, reg export 의 바이트는 뿌리 키의 값
    차례만 다르다(제거 룰의 RELEASE.md). 복원한 서비스는 재부팅 전까지 서비스 관리자가 모른다 — T6 줄에 sc.exe query 의 종료
    코드를 적는다(판정에는 넣지 않는다).

    `-LogDir` 에 칸마다 화면(`<칸>.txt`)과 summary.txt 를 남긴다. 끝줄은 `판정 N/T · 실패 M` 이다.
    종료 코드: 0 = 모든 칸 통과 · 1 = 하나라도 실패(시작 전에 이미 있어 멈춘 것도 1 이다).

.EXAMPLE
    .\testbed\harness\host\Invoke-RuleHarness.ps1 -Harness testbed\harness\host\Invoke-WinwyvernVerify.ps1 `
        -Package D:\dl\x\remedy-windows-x64 -LogDir D:\dl\winwyvern -Inputs D:\dl\inputs
#>
param(
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $LogDir,
    # rc 묶음이 표준 인자로 준다 — 받을 입력이 없어 쓰지 않는다.
    [string] $Inputs,
    [string] $VmAddress
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'VmSession.ps1')

$detectRule = 'winwyvern-1-check'
$cleanRule = 'winwyvern-2-clean'
$pkgRoot = (Resolve-Path -LiteralPath $Package).Path
$exe = Join-Path $pkgRoot 'remedy.exe'
foreach ($p in @($exe, (Join-Path $pkgRoot "plugins\$detectRule\plugin.yaml"), (Join-Path $pkgRoot "plugins\$cleanRule\plugin.yaml"))) {
    if (-not (Test-Path -LiteralPath $p)) { throw "없다: $p" }
}
# 제거 룰의 치료 계획 — 서비스 ref 하나에서 계획기가 내는 동작과 그 차례(설계-03 §2 · 2026-11-25 랩 측정 4건).
$treat = @('service.clear_recovery', 'service.stop', 'service.disable', 'service.delete')
$treatOps = $treat -join ','
# 다시 시작해야 끝나는 치료의 화면 문구(엔진 1.26.0 · remedy-cli `still_there` · restore_cmd). T2r 의 부정 단정과 H 칸의 긍정
# 단정이 **같은 변수**를 쓴다 — 문구가 바뀌면 부정 단정이 조용히 통과하지 않고 H 칸이 먼저 실패한다.
$sayPending = '\[4\] 서비스 삭제 .*Windows 가 지우기를 미뤘습니다'
$sayRestoreOrder = 'PC 를 먼저 다시 시작한 뒤 복원하십시오|다시 시작하기 전에는 이 서비스를 복원할 수 없습니다'
$sayRemoving = 'Windows 가 이 서비스를 지우는 중입니다'
$sayRestartThenRestore = 'PC 를 다시 시작한 뒤 다시 복원하십시오'
# H 칸이 서는 엔진 — 그 앞의 꾸러미(룰만 바뀐 출시의 미룬 검증이 지난 공개본으로 돌 때)는 건너뛴다.
$holdSince = [version]'1.26.0'
$logRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogDir)
New-Item -ItemType Directory -Force $logRoot | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
$summary = Join-Path $logRoot 'summary.txt'
[IO.File]::WriteAllText($summary, '', $utf8)
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`n", $utf8) }

$pass = 0
$fail = 0
$total = 0
function Check([string] $id, [string] $what, [bool] $ok, [string] $evidence) {
    $script:total++
    if ($ok) { $script:pass++ } else { $script:fail++ }
    Note ('{0,-4} {1}  {2} — {3}' -f $id, $(if ($ok) { '통과' } else { '실패' }), $what, $evidence)
}

# 게스트에서 쓰는 도구 — 놓기 · 치우기 · 남은 것 · 값 목록. 칸마다 같은 세션에서 다시 정의한다(Invoke-Command 는 범위를 잇지
# 않는다). 치우는 것은 이 하네스가 놓는 넷뿐이다 — 서비스 NeacSafe64 · System32 의 neacsafe64.sys · 작업 폴더 · 제거 룰의 치료가
# 건 재부팅 뒤 확인(RunOnce 의 remedy-verify — 작업 폴더를 가리키는 것만).
# sc.exe 는 `&` 로 부르고 종료 코드를 곧바로 받는다. 세션의 오류 동작을 Stop 으로 바꾸지 않는다 — 원격 세션의 네이티브 출력이
# 오류 줄로 올라오면 그 한 줄에 멈춘다. 실패를 봐야 하는 cmdlet 에만 `-ErrorAction Stop` 을 준다.
$guestTools = {
    $svcName = 'NeacSafe64'
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\NeacSafe64'
    $svcSub = 'SYSTEM\CurrentControlSet\Services\NeacSafe64'
    $sys32 = Join-Path $env:SystemRoot 'System32'
    $driverFile = Join-Path $sys32 'neacsafe64.sys'
    $runOnceKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    $verifyName = 'remedy-verify'

    # 재부팅 뒤 확인의 예약 — 제거 룰의 치료(verify.after_reboot)가 건다. 없으면 아무것도 내지 않는다.
    function Get-VerifyEntry {
        $item = Get-ItemProperty -LiteralPath $runOnceKey -Name $verifyName -ErrorAction SilentlyContinue
        if ($item) { [string]$item.$verifyName }
    }

    # 서비스 핸들을 붙드는 프로세스의 몸(H 칸) — 이것만 한다. OpenSCManager(SC_MANAGER_CONNECT) · OpenService
    # (SERVICE_QUERY_STATUS)만 부르고 닫지 않은 채 잔다. 놓으라는 표지 파일이 생기거나 한 시간이 지나면 두 핸들을 닫고 끝난다.
    # 열린 핸들이 하나라도 있으면 SCM 이 서비스 삭제를 미룬다(2026-11-25 랩).
    $holderBlock = {
        param([string] $statusPath, [string] $releasePath, [string] $name, [int] $limitSec)
        $ErrorActionPreference = 'Stop'
        $sig = '[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern IntPtr OpenSCManager(string machine, string db, uint access); ' +
            '[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern IntPtr OpenService(IntPtr scm, string name, uint access); ' +
            '[DllImport("advapi32.dll", SetLastError = true)] public static extern bool CloseServiceHandle(IntPtr handle);'
        Add-Type -Namespace RemedyLab -Name Scm -MemberDefinition $sig
        # $null 은 string 인자로 넘기면 빈 글자가 된다(빈 데이터베이스 이름 → 123) — 진짜 NULL 은 [NullString]::Value 다.
        $scm = [RemedyLab.Scm]::OpenSCManager([NullString]::Value, [NullString]::Value, 1)
        $svc = [IntPtr]::Zero
        if ($scm -ne [IntPtr]::Zero) { $svc = [RemedyLab.Scm]::OpenService($scm, $name, 4) }
        $errSvc = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $state = 'held'
        if ($svc -eq [IntPtr]::Zero) { $state = 'failed' }
        [IO.File]::WriteAllText($statusPath, ('{0} pid={1} err_svc={2}' -f $state, $PID, $errSvc))
        if ($state -ne 'held') {
            if ($scm -ne [IntPtr]::Zero) { [void][RemedyLab.Scm]::CloseServiceHandle($scm) }
            exit 1
        }
        $until = (Get-Date).AddSeconds($limitSec)
        while (-not (Test-Path -LiteralPath $releasePath) -and (Get-Date) -lt $until) { Start-Sleep -Milliseconds 100 }
        [void][RemedyLab.Scm]::CloseServiceHandle($svc)
        [void][RemedyLab.Scm]::CloseServiceHandle($scm)
        [IO.File]::AppendAllText($statusPath, "`nreleased")
    }

    # 붙드는 프로세스의 명령줄 — 같은 작업 폴더면 늘 같은 줄이라, 그 줄로 그 프로세스를 다시 찾는다.
    function Get-HolderLine([string] $probe) {
        $statusPath = Join-Path $probe 'holder.status'
        $releasePath = Join-Path $probe 'holder.release'
        $text = "& {" + $holderBlock.ToString() + "} '" + $statusPath + "' '" + $releasePath + "' '" + $svcName + "' 3600"
        $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($text))
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        [pscustomobject]@{
            line    = ('"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {1}' -f $ps, $b64)
            b64     = $b64
            status  = $statusPath
            release = $releasePath
        }
    }

    function Get-HolderProcs([string] $probe) {
        if (-not $probe) { return @() }
        $h = Get-HolderLine $probe
        @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
                Where-Object { $_.CommandLine -and $_.CommandLine.Contains($h.b64) } | ForEach-Object { [int]$_.ProcessId })
    }

    # 원격 세션 밖에서 띄운다(Win32_Process.Create) — 세션이 끊겨도 핸들을 놓지 않게. 현재 폴더는 작업 폴더가 아닌 곳(지울 때
    # 잠기지 않게). 붙들었다는 상태 줄을 90초까지 기다린다.
    function Start-Holder([string] $probe) {
        $h = Get-HolderLine $probe
        foreach ($p in @($h.status, $h.release)) { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction Stop } }
        $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $h.line; CurrentDirectory = $env:SystemRoot }
        $procId = [int]$r.ProcessId
        $text = ''
        $until = (Get-Date).AddSeconds(90)
        while ((Get-Date) -lt $until) {
            if (Test-Path -LiteralPath $h.status) {
                $text = [IO.File]::ReadAllText($h.status)
                if ($text) { break }
            }
            if ($procId -gt 0 -and -not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Milliseconds 250
        }
        [pscustomobject]@{ held = ([string]$text).StartsWith('held'); status = ([string]$text).Trim() }
    }

    # 놓는다 — 표지 파일을 두고 그 프로세스가 끝나기를 20초까지 기다린다(끝나지 않으면 끝낸다).
    function Stop-Holder([string] $probe) {
        if (@(Get-HolderProcs $probe).Count -eq 0) { return 'none' }
        $h = Get-HolderLine $probe
        if (Test-Path -LiteralPath $probe) { [IO.File]::WriteAllText($h.release, 'release') }
        $t0 = Get-Date
        while (@(Get-HolderProcs $probe).Count -gt 0 -and ((Get-Date) - $t0).TotalSeconds -lt 20) { Start-Sleep -Milliseconds 100 }
        $how = 'exited'
        foreach ($id in @(Get-HolderProcs $probe)) {
            Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
            $how = 'killed'
        }
        $how
    }

    # 이 하네스가 놓는 것 가운데 지금 있는 것 — 시작 전에는 '랩에 원래 있던 것', 끝에는 '치우고 남은 것' 이다.
    function Get-Leftover([string] $probe) {
        if (Test-Path -LiteralPath $svcKey) { 'HKLM\SYSTEM\CurrentControlSet\Services\NeacSafe64' }
        $null = & sc.exe query $svcName
        $queried = $LASTEXITCODE
        # 1060 = 그런 서비스가 없다. 키가 없는데 SCM 이 아직 안다면 지울 표시만 남은 것이다.
        if ($queried -ne 1060) { 'SCM 의 서비스 NeacSafe64(sc.exe query 종료 {0})' -f $queried }
        if (Test-Path -LiteralPath $driverFile) { $driverFile }
        if ($probe -and (Test-Path -LiteralPath $probe)) { $probe }
        $verify = Get-VerifyEntry
        if ($verify) { 'RunOnce 의 remedy-verify({0})' -f $verify }
        foreach ($id in @(Get-HolderProcs $probe)) { '서비스 핸들을 붙든 프로세스 pid {0}' -f $id }
    }

    function Clear-Layout([string] $probe) {
        # 핸들을 붙든 프로세스부터 끝낸다 — 남아 있으면 아래 삭제가 미뤄져 10초 뒤 멈춘다(H 칸).
        if ($probe) { $null = Stop-Holder $probe }
        if (Test-Path -LiteralPath $svcKey) {
            $null = & sc.exe delete $svcName
            $deleted = $LASTEXITCODE
            # 1060 = 서비스 관리자가 그 서비스를 모른다 — 복원은 정의 키를 레지스트리로만 되살리므로 재부팅 전까지 그렇다(T5 뒤).
            # 이 하네스가 세웠거나 되살린 키다(시작 전에 있었으면 멈췄다) — 그 키만 레지스트리에서 지운다.
            if ($deleted -eq 1060) { Remove-Item -LiteralPath $svcKey -Recurse -Force -ErrorAction Stop }
            # 시작한 적 없는 서비스는 핸들이 닫히면 곧바로 지워진다 — 키가 사라질 때까지 10초까지 기다린다.
            for ($i = 0; $i -lt 40 -and (Test-Path -LiteralPath $svcKey); $i++) { Start-Sleep -Milliseconds 250 }
            if (Test-Path -LiteralPath $svcKey) {
                throw ('서비스 NeacSafe64 가 지워지지 않았다(sc.exe delete 종료 {0} — 지울 표시만 남았을 수 있다)' -f $deleted)
            }
        }
        if (Test-Path -LiteralPath $driverFile) { Remove-Item -LiteralPath $driverFile -Force -ErrorAction Stop }
        # 제거 룰의 치료가 건 재부팅 뒤 확인 — 작업 폴더를 가리키는 것만 지운다(다른 것은 그대로 두어 C1 이 적는다).
        $verify = Get-VerifyEntry
        if ($probe -and $verify -and $verify.IndexOf($probe, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Remove-ItemProperty -LiteralPath $runOnceKey -Name $verifyName -ErrorAction Stop
        }
    }

    # 칸 하나를 세운다. 경로의 <SR> 은 이 기계의 SystemRoot, <SRU> 는 그 대문자다. 세운 것을 그대로 읽어 돌려준다.
    function New-Layout([string] $name, [string] $start, [string] $bin, [string] $image, [string] $imageType, [string] $file) {
        # 32비트 세션이면 System32 가 SysWOW64 로 돌려져 엉뚱한 자리를 잰다.
        if (-not [Environment]::Is64BitProcess) { throw '원격 세션이 32비트다 — System32 쓰기가 SysWOW64 로 돌려진다' }
        $sr = $env:SystemRoot
        if ($name) {
            $binPath = $bin.Replace('<SR>', $sr)
            $made = & sc.exe create $name type= filesys start= $start binPath= $binPath
            $created = $LASTEXITCODE
            if ($created -ne 0) { throw ('sc.exe create 실패(종료 {0}): {1}' -f $created, ($made -join ' ')) }
            if ($image) {
                $img = $image.Replace('<SRU>', $sr.ToUpperInvariant()).Replace('<SR>', $sr)
                $kind = 'ExpandString'
                if ($imageType -eq 'sz') { $kind = 'String' }
                New-ItemProperty -LiteralPath $svcKey -Name 'ImagePath' -Value $img -PropertyType $kind -Force -ErrorAction Stop | Out-Null
            }
        }
        if ($file) {
            $text = 'REMEDY-LAB placeholder neacsafe64.sys - not a driver' + [char]0
            [IO.File]::WriteAllBytes((Join-Path $sys32 $file), [Text.Encoding]::ASCII.GetBytes($text))
        }
        # ImagePath 는 펴지 않은 글자 그대로 읽는다 — PowerShell 은 REG_EXPAND_SZ 를 펴서 돌려준다.
        $stored = ''
        if (Test-Path -LiteralPath $svcKey) {
            $k = Get-Item -LiteralPath $svcKey
            $raw = $k.GetValue('ImagePath', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $stored = 'ImagePath={0}({1}) · Start={2} · Type={3}' -f $raw, $k.GetValueKind('ImagePath'), $k.GetValue('Start'), $k.GetValue('Type')
        }
        $names = @(Get-ChildItem -LiteralPath $sys32 -Filter 'neacsafe64*.sys' -Force | ForEach-Object { $_.Name })
        [pscustomobject]@{ service = $stored; files = ($names -join ',') }
    }

    # 미니필터 드라이버 등록의 꼴 — 서비스 키에 의존 값 하나와 `Instances` 하위 키 둘. 치료 → 복원이 하위 트리째(값 ·
    # 하위 키) 지워지고 돌아오는지 보려는 것이다. Altitude 만 자리 채우기고, 의존 값(FltMgr) · DefaultInstance · Flags 는
    # ASEC [표 3] 과 같은 값이다(표 3 의 Description · Group · SupportedFeatures · Tag 는 넣지 않았다).
    function Add-MinifilterForm {
        New-ItemProperty -LiteralPath $svcKey -Name 'DependOnService' -Value @('FltMgr') -PropertyType MultiString -Force -ErrorAction Stop | Out-Null
        $inst = Join-Path $svcKey 'Instances'
        New-Item -Path $inst -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -LiteralPath $inst -Name 'DefaultInstance' -Value 'NeacSafe64 Instance' -PropertyType String -Force -ErrorAction Stop | Out-Null
        $one = Join-Path $inst 'NeacSafe64 Instance'
        New-Item -Path $one -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -LiteralPath $one -Name 'Altitude' -Value 'REMEDY-LAB' -PropertyType String -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -LiteralPath $one -Name 'Flags' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    }

    # 서비스 키 하위 트리의 값 목록 — 키(뿌리에서의 상대 경로) · 이름 · 종류 · 데이터(펴지 않은 글자 그대로). 키마다 이름
    # 차례로 적는다. 키가 없으면 '(키 없음)' 한 줄이다.
    function Get-KeyValues {
        $lines = New-Object System.Collections.Generic.List[string]
        $base = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($svcSub)
        if (-not $base) { return @('(키 없음)') }
        $queue = New-Object 'System.Collections.Generic.Queue[string]'
        $queue.Enqueue('')
        while ($queue.Count -gt 0) {
            $rel = $queue.Dequeue()
            $k = $base
            if ($rel) { $k = $base.OpenSubKey($rel) }
            $lines.Add('[' + $rel + ']')
            foreach ($n in @($k.GetValueNames() | Sort-Object)) {
                $kind = [string]$k.GetValueKind($n)
                $v = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $shown = switch ($kind) {
                    'MultiString' { (@($v) | ForEach-Object { '"' + $_ + '"' }) -join ',' }
                    'Binary' { [BitConverter]::ToString([byte[]]$v) }
                    'DWord' { '0x{0:x8}' -f $v }
                    'QWord' { '0x{0:x16}' -f $v }
                    default { '"' + [string]$v + '"' }
                }
                $lines.Add(('  {0} {1} = {2}' -f $n, $kind, $shown))
            }
            foreach ($sub in @($k.GetSubKeyNames() | Sort-Object)) {
                if ($rel) { $queue.Enqueue($rel + '\' + $sub) } else { $queue.Enqueue($sub) }
            }
            if ($rel) { $k.Close() }
        }
        $base.Close()
        @($lines)
    }
}

# 게스트의 파일 하나를 글자로 — 없으면 아무것도 내지 않는다.
function Read-GuestText([string] $path) {
    Invoke-Command -Session $session -ArgumentList $path -ScriptBlock {
        param($p)
        if (Test-Path -LiteralPath $p) { [IO.File]::ReadAllText($p) }
    }
}

# 검사 한 번(이 칸의 결과 폴더 · 작업 폴더의 상태 자리) — 화면을 `<칸>.txt` 에 남기고, 검사 완료 줄의 흔적 · 위협 수와 결과
# 폴더 plan.json 의 치료 계획(동작을 차례대로)을 돌려준다. plan.json 이 없으면 planFound 가 거짓이다.
function Invoke-Scan([string] $tag, [string] $ruleId) {
    $outDir = "$g\out\$tag"
    $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g `
        -Arguments @('scan', '--plugin', "$g\plugins\$ruleId\plugin.yaml", '--out-dir', $outDir, '--state-dir', "$g\state")
    $screen = [string]$r.out + [string]$r.err
    [IO.File]::WriteAllText((Join-Path $logRoot "$tag.txt"), ("exit={0}`n{1}" -f $r.exit, $screen), $utf8)
    # 검사 완료 줄의 흔적 · 위협 수 — 0 이 그 칸의 까닭으로 나왔는지 본다(흔적 1 = 근거 하나만 섰다).
    $traces = -1
    $threats = -1
    if ($screen -match '흔적 (\d+)건') { $traces = [int]$Matches[1] }
    if ($screen -match '위협 (\d+)건') { $threats = [int]$Matches[1] }
    $planText = Read-GuestText "$outDir\plan.json"
    $ops = @()
    if ($planText) { $ops = @(($planText | ConvertFrom-Json).actions | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_.op }) }
    [pscustomobject]@{ exit = $r.exit; traces = $traces; threats = $threats; planFound = [bool]$planText; ops = $ops }
}

$addr = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $addr
$g = 'C:\remedy-probe'

# ASEC 꼴의 등록 — sc.exe 의 binPath(드라이버의 전체 경로). SCM 이 그것을 어떤 꼴로 두는지는 A1 의 칸 줄이 적는다.
# 0 칸은 이 꼴에서 한 가지만 바꾼다(시작 유형 · ImagePath 의 자리 · 둘 가운데 하나를 빼기).
$asec = '<SR>\System32\neacsafe64.sys'
$f = 'neacsafe64.sys'
$cases = @(
    @{ id = 'A1'; what = '감염 — ASEC 꼴(sc.exe 가 둔 ImagePath · 자동 시작 · System32 의 그 파일)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V1'; what = 'ImagePath \SystemRoot\System32\neacsafe64.sys'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '\SystemRoot\System32\neacsafe64.sys'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V2'; what = 'ImagePath System32\neacsafe64.sys(상대 경로)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = 'System32\neacsafe64.sys'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V3'; what = 'ImagePath %SystemRoot%\System32\neacsafe64.sys(펴지 않은 변수)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '%SystemRoot%\System32\neacsafe64.sys'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V4'; what = 'ImagePath %windir%\system32\NeacSafe64.sys(대소문자)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '%windir%\system32\NeacSafe64.sys'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V5'; what = 'ImagePath \??\ 전체 경로 · 대문자'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '\??\<SRU>\SYSTEM32\NEACSAFE64.SYS'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V6'; what = 'ImagePath 전체 경로(REG_SZ)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '<SR>\System32\neacsafe64.sys'; imageType = 'sz'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V7'; what = 'ImagePath 따옴표로 감싼 전체 경로'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '"<SR>\System32\neacsafe64.sys"'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V8'; what = 'ImagePath \\?\ 전체 경로'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '\\?\<SR>\System32\neacsafe64.sys'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V9'; what = '서비스 이름 소문자(neacsafe64)'; name = 'neacsafe64'; start = 'auto'; bin = $asec; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V10'; what = '파일 이름 대소문자(NeacSafe64.SYS)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; file = 'NeacSafe64.SYS'; expect = 2; traces = 2; threats = 1 },
    @{ id = 'N1'; what = '아무것도 없음'; expect = 0; traces = 0; threats = 0 },
    @{ id = 'S1'; what = '서비스만(파일 없음)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; expect = 0; traces = 1; threats = 0 },
    @{ id = 'F1'; what = 'System32 의 그 파일만(서비스 없음)'; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'M1'; what = '수동 시작 + 그 파일'; name = 'NeacSafe64'; start = 'demand'; bin = $asec; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'M2'; what = '사용 안 함 + 그 파일'; name = 'NeacSafe64'; start = 'disabled'; bin = $asec; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'M3'; what = '시스템 시작 + 그 파일'; name = 'NeacSafe64'; start = 'system'; bin = $asec; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'M4'; what = '부팅 시작 + 그 파일'; name = 'NeacSafe64'; start = 'boot'; bin = $asec; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'D1'; what = 'drivers 폴더(sc.exe 가 둔 꼴) + System32 의 그 파일'; name = 'NeacSafe64'; start = 'auto'; bin = '<SR>\System32\drivers\neacsafe64.sys'; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'D2'; what = 'ImagePath System32\drivers\neacsafe64.sys + System32 의 그 파일'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = 'System32\drivers\neacsafe64.sys'; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'D3'; what = 'ImagePath \SystemRoot\SysWOW64\neacsafe64.sys + System32 의 그 파일'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '\SystemRoot\SysWOW64\neacsafe64.sys'; file = $f; expect = 0; traces = 1; threats = 0 }
)

# 이미 있으면(랩에 원래 있던 것 · 앞 회차가 남긴 것) 건드리지 않고 멈춘다 — 아래 try 밖이라 멈출 때 finally 의 정리가 돌지 않는다.
try {
    $pre = Invoke-Command -Session $session -ArgumentList $guestTools.ToString() -ScriptBlock {
        param($tools)
        . ([scriptblock]::Create($tools))
        @(Get-Leftover '')
    }
} catch { Remove-PSSession $session; throw }
$already = @($pre | Where-Object { $_ })
if ($already.Count -gt 0) {
    Remove-PSSession $session
    Note ('멈춤 — 랩에 이미 있다(건드리지 않았다): ' + ($already -join ' · '))
    throw ('랩에 이미 있다 — 건드리지 않고 멈춘다: ' + ($already -join ' · '))
}

try {
    Note ("시작 {0}  꾸러미={1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $pkgRoot)
    Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
        New-Item -ItemType Directory -Force "$g\plugins", "$g\out", "$g\state" -ErrorAction Stop | Out-Null
    }
    Copy-GuestFile -Session $session -Source $exe -Destination "$g\remedy.exe"
    foreach ($rid in @($detectRule, $cleanRule)) {
        Copy-Item -LiteralPath (Join-Path $pkgRoot "plugins\$rid") -Destination "$g\plugins" -ToSession $session -Recurse -Force
    }
    # 꾸러미의 엔진 버전 — H 칸을 돌릴지 정한다. 읽지 못하면 멈춘다(조용히 건너뛰지 않는다).
    $ver = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g -Arguments @('--version')
    $verText = [string]$ver.out + [string]$ver.err
    $engine = $null
    if ($verText -match '(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.]+)? \(remedy\)') {
        $engine = [version]('{0}.{1}.{2}' -f $Matches[1], $Matches[2], $Matches[3])
    }
    if (-not $engine) { throw ('꾸러미의 엔진 버전을 읽지 못했다: ' + $verText.Trim()) }
    Note ('엔진 {0}' -f $engine)

    foreach ($c in $cases) {
        $placed = Invoke-Command -Session $session -ArgumentList $guestTools.ToString(), $g, $c.name, $c.start, $c.bin, $c.image, $c.imageType, $c.file -ScriptBlock {
            param($tools, $probe, $name, $start, $bin, $image, $imageType, $file)
            . ([scriptblock]::Create($tools))
            Clear-Layout $probe | Out-Null
            New-Layout $name $start $bin $image $imageType $file
        }
        $one = Invoke-Scan $c.id $detectRule
        $ok = ($one.exit -eq $c.expect) -and ($one.traces -eq $c.traces) -and ($one.threats -eq $c.threats)
        $seen = '종료 {0} · 흔적 {1} · 위협 {2} (기대 {3} · {4} · {5})' -f $one.exit, $one.traces, $one.threats, $c.expect, $c.traces, $c.threats
        if ($placed.service) { $seen += ' · ' + $placed.service }
        if ($placed.files) { $seen += ' · 파일 ' + $placed.files }
        Check $c.id $c.what $ok $seen

        # 같은 꼴을 제거 룰로 — 판정(종료 · 흔적 · 위협)이 탐지 룰과 같고, 치료 계획은 위협 칸에서만 넷(그 차례) · 0 칸에는 없다.
        $two = Invoke-Scan ($c.id + 'c') $cleanRule
        $wantOps = ''
        if ($c.expect -eq 2) { $wantOps = $treatOps }
        $gotOps = @($two.ops) -join ','
        $same = ($two.exit -eq $one.exit) -and ($two.traces -eq $one.traces) -and ($two.threats -eq $one.threats)
        $okTwo = $same -and ($two.exit -eq $c.expect) -and ($two.traces -eq $c.traces) -and ($two.threats -eq $c.threats) -and
            $two.planFound -and ($gotOps -eq $wantOps)
        $seenTwo = '종료 {0} · 흔적 {1} · 위협 {2} · 치료 계획 {3}건 (탐지 룰 {4} · {5} · {6} · 계획 기대 {7}건)' -f `
            $two.exit, $two.traces, $two.threats, @($two.ops).Count, $one.exit, $one.traces, $one.threats, $(if ($wantOps) { $treat.Count } else { 0 })
        if (-not $two.planFound) { $seenTwo += ' · plan.json 없음' } elseif ($gotOps -ne $wantOps) { $seenTwo += ' · 계획 [' + $gotOps + ']' }
        Check ($c.id + 'c') ('제거 룰 — ' + $c.what + ' · 탐지 룰과 같은 판정') $okTwo $seenTwo
    }

    # ── T — 제거 룰의 치료 · 복원. 감염 꼴(A1)에 미니필터 등록의 일반 꼴을 더해, 하위 트리째 지워지고 돌아오는지 본다 ──
    $before = Invoke-Command -Session $session -ArgumentList $guestTools.ToString(), $g, $asec, $f -ScriptBlock {
        param($tools, $probe, $bin, $file)
        . ([scriptblock]::Create($tools))
        Clear-Layout $probe | Out-Null
        $null = New-Layout 'NeacSafe64' 'auto' $bin '' '' $file
        Add-MinifilterForm
        $vals = @(Get-KeyValues)
        $hash = (Get-FileHash -LiteralPath $driverFile -Algorithm SHA256).Hash
        [pscustomobject]@{ values = $vals; sha = $hash }
    }
    $t1 = Invoke-Scan 'T1' $cleanRule
    $t1Ops = @($t1.ops) -join ','
    $ok = ($t1.exit -eq 2) -and ($t1.traces -eq 2) -and ($t1.threats -eq 1) -and ($t1Ops -eq $treatOps)
    Check 'T1' '제거 룰 — 감염 꼴 + 미니필터 등록 꼴(의존 값 · Instances 하위 키 둘) 검사 2 · 치료 계획 넷(그 차례)' $ok `
        ('종료 {0} · 흔적 {1} · 위협 {2} · 계획 [{3}] · 치료 전 값 목록 {4}줄' -f $t1.exit, $t1.traces, $t1.threats, $t1Ops, @($before.values).Count)

    # T2 — 치료. 동작마다 결과는 --events 의 줄(started · backed_up · action · finished)로 읽는다.
    $eventsFile = "$g\out\T2.ndjson"
    $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g -Arguments @('run', '--plugin',
        "$g\plugins\$cleanRule\plugin.yaml", '--yes', '--out-dir', "$g\out\T2", '--state-dir', "$g\state", '--events', $eventsFile)
    [IO.File]::WriteAllText((Join-Path $logRoot 'T2.txt'), ("exit={0}`n{1}{2}" -f $r.exit, $r.out, $r.err), $utf8)
    $eventsText = Read-GuestText $eventsFile
    $events = @()
    if ($eventsText) { $events = @($eventsText -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }) }
    [IO.File]::WriteAllText((Join-Path $logRoot 'T2.ndjson'), [string]$eventsText, $utf8)
    $runId = ''
    $started = @($events | Where-Object { $_.event -eq 'started' })
    if ($started.Count) { $runId = [string]$started[0].run_id }
    $acts = @($events | Where-Object { $_.event -eq 'action' })
    $doneOps = @($acts | ForEach-Object { [string]$_.op }) -join ','
    $notDone = @($acts | Where-Object { $_.outcome -ne 'done' } | ForEach-Object { '{0}={1}' -f $_.op, $_.outcome })
    $finished = @($events | Where-Object { $_.event -eq 'finished' })
    $finDone = -1
    $finFailed = -1
    if ($finished.Count) { $finDone = [int]$finished[0].done; $finFailed = [int]$finished[0].failed }
    $backed = @($events | Where-Object { $_.event -eq 'backed_up' })
    $entries = -1
    if ($backed.Count) { $entries = [int]$backed[0].entries }
    $ok = ($r.exit -eq 1) -and [bool]$runId -and ($doneOps -eq $treatOps) -and ($notDone.Count -eq 0) -and ($finDone -eq $treat.Count) -and ($finFailed -eq 0)
    $seen = '종료 {0} · 회차 {1} · 동작 [{2}] · 끝남 {3} · 실패 {4} · 백업 {5}건' -f $r.exit, $runId, $doneOps, $finDone, $finFailed, $entries
    if ($notDone.Count) { $seen += ' · 끝나지 않음 ' + ($notDone -join ' ') }
    Check 'T2' '제거 룰 — 치료(run --yes) 1 · 네 동작이 그 차례로 모두 끝남' $ok $seen
    # T2r — 곧바로 지워진 치료는 '다시 시작해야 끝남' 을 말하지 않는다(화면의 목록 줄 · finished 의 reboot_required 모두 없다).
    $t2Screen = [string]$r.out + [string]$r.err
    $saysPending = $t2Screen -match $sayPending
    $finFlag = $finished.Count -and ($finished[0].PSObject.Properties.Name -contains 'reboot_required')
    Check 'T2r' "곧바로 지워진 치료 — '다시 시작해야 끝남' 을 말하지 않는다(화면 · --events)" ((-not $saysPending) -and (-not $finFlag)) `
        ('화면의 미룬 삭제 줄 {0} · finished 의 reboot_required {1}' -f $(if ($saysPending) { '있음' } else { '없음' }), $(if ($finFlag) { '있음' } else { '없음' }))
    if (-not $runId) { throw '치료의 회차 번호(run_id)를 --events 에서 얻지 못했다 — 복원할 수 없다' }

    # T3 — 치료 뒤 게스트의 상태. 드라이버 파일은 remove 밖이라 그대로여야 한다.
    $after = Invoke-Command -Session $session -ArgumentList $guestTools.ToString() -ScriptBlock {
        param($tools)
        . ([scriptblock]::Create($tools))
        $null = & sc.exe query $svcName
        $queried = $LASTEXITCODE
        $hash = ''
        if (Test-Path -LiteralPath $driverFile) { $hash = (Get-FileHash -LiteralPath $driverFile -Algorithm SHA256).Hash }
        $verify = Get-VerifyEntry
        [pscustomobject]@{ key = (Test-Path -LiteralPath $svcKey); query = $queried; sha = $hash; verify = $verify }
    }
    $scheduled = [bool]($after.verify -and $after.verify.IndexOf($runId, [StringComparison]::OrdinalIgnoreCase) -ge 0)
    $fileSame = [bool]$after.sha -and ($after.sha -eq $before.sha)
    $ok = (-not $after.key) -and ($after.query -eq 1060) -and $fileSame -and $scheduled
    $seen = '서비스 키 {0} · sc.exe query 종료 {1} · 드라이버 자리 파일 {2} · 재부팅 뒤 확인 {3}' -f $(if ($after.key) { '있음' } else { '없음' }),
        $after.query, $(if ($fileSame) { '그대로(해시 같음)' } elseif ($after.sha) { '해시 다름' } else { '없음' }),
        $(if ($scheduled) { '예약됨(그 회차)' } elseif ($after.verify) { '다른 예약: ' + $after.verify } else { '없음' })
    Check 'T3' '치료 뒤 — 서비스 키 없음 · SCM 이 모름(1060) · 드라이버 자리 파일 그대로 · 재부팅 뒤 확인 예약' $ok $seen

    # T4 — 다시 검사. 남긴 드라이버 파일이 흔적 1 로만 선다.
    $t4 = Invoke-Scan 'T4' $cleanRule
    $t4b = Invoke-Scan 'T4b' $detectRule
    $ok = ($t4.exit -eq 0) -and ($t4.traces -eq 1) -and ($t4.threats -eq 0) -and $t4.planFound -and (@($t4.ops).Count -eq 0) -and
        ($t4b.exit -eq 0) -and ($t4b.traces -eq 1) -and ($t4b.threats -eq 0)
    Check 'T4' '치료 뒤 다시 검사 0 — 두 룰 모두 흔적 1(남긴 드라이버 파일) · 위협 0' $ok `
        ('제거 룰 종료 {0} · 흔적 {1} · 위협 {2} · 치료 계획 {3}건 · 탐지 룰 종료 {4} · 흔적 {5} · 위협 {6}' -f $t4.exit, $t4.traces,
            $t4.threats, @($t4.ops).Count, $t4b.exit, $t4b.traces, $t4b.threats)

    # T5 — 복원. 백업은 되돌릴 수 있는 동작마다 하나다(복구 설정 해제 · 사용 안 함 · 삭제 — 정지는 되돌릴 수 없다).
    $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g -Arguments @('restore', '--run', $runId,
        '--state-dir', "$g\state", '--yes')
    $screen = [string]$r.out + [string]$r.err
    [IO.File]::WriteAllText((Join-Path $logRoot 'T5.txt'), ("exit={0}`n{1}" -f $r.exit, $screen), $utf8)
    $restored = -1
    if ($screen -match '(\d+)건 복원 완료') { $restored = [int]$Matches[1] }
    $ok = ($r.exit -eq 0) -and ($restored -eq 3) -and ($restored -eq $entries)
    Check 'T5' '복원(restore --yes) 0 · 치료가 백업한 3건 모두' $ok ('종료 {0} · 복원 {1}건 · 치료의 백업 {2}건' -f $r.exit, $restored, $entries)

    # T6 — 서비스 키 하위 트리의 값 목록. 복원한 서비스를 서비스 관리자가 아는지(sc.exe query)는 적기만 한다.
    $back = Invoke-Command -Session $session -ArgumentList $guestTools.ToString() -ScriptBlock {
        param($tools)
        . ([scriptblock]::Create($tools))
        $null = & sc.exe query $svcName
        $queried = $LASTEXITCODE
        $vals = @(Get-KeyValues)
        [pscustomobject]@{ values = $vals; query = $queried }
    }
    $wasText = @($before.values) -join "`n"
    $nowText = @($back.values) -join "`n"
    [IO.File]::WriteAllText((Join-Path $logRoot 'T6.txt'), ("치료 전`n{0}`n`n복원 뒤`n{1}`n" -f $wasText, $nowText), $utf8)
    $same = (@($before.values).Count -gt 1) -and ($wasText -eq $nowText)
    $seen = '값 목록 {0}줄 · ' -f @($back.values).Count
    if ($same) { $seen += '치료 전과 같음' } else {
        $diff = @(Compare-Object @($before.values) @($back.values) | ForEach-Object { '{0} {1}' -f $_.SideIndicator, $_.InputObject })
        $seen += '다름: ' + $(if ($diff.Count) { $diff -join ' | ' } else { '줄의 차례' })
    }
    $seen += ' · 복원 뒤 sc.exe query 종료 {0}(1060 = 재부팅 전까지 서비스 관리자가 모른다)' -f $back.query
    Check 'T6' '복원 뒤 서비스 키 하위 트리의 값 목록(키 · 이름 · 종류 · 데이터)이 치료 전과 같다' $same $seen

    # T7 — 복원 뒤 다시 검사. 두 룰 모두 다시 위협을 찾는다.
    $t7 = Invoke-Scan 'T7' $cleanRule
    $t7b = Invoke-Scan 'T7b' $detectRule
    $ok = ($t7.exit -eq 2) -and ($t7.traces -eq 2) -and ($t7.threats -eq 1) -and ((@($t7.ops) -join ',') -eq $treatOps) -and
        ($t7b.exit -eq 2) -and ($t7b.traces -eq 2) -and ($t7b.threats -eq 1)
    Check 'T7' '복원 뒤 다시 검사 2 — 두 룰 모두 흔적 2 · 위협 1' $ok `
        ('제거 룰 종료 {0} · 흔적 {1} · 위협 {2} · 치료 계획 {3}건 · 탐지 룰 종료 {4} · 흔적 {5} · 위협 {6}' -f $t7.exit, $t7.traces,
            $t7.threats, @($t7.ops).Count, $t7b.exit, $t7b.traces, $t7b.threats)

    # ── H — 서비스 핸들을 붙든 채 치료. SCM 이 삭제를 미룬다 — 엔진은 그것을 '다시 시작해야 끝남' 으로 알리고, 지우는 중인
    #    서비스로는 복원하지 않는다(엔진 1.26.0 · 이슈 #172 ⑥). 그 앞의 엔진이면 건너뛴다 ──
    if ($engine -lt $holdSince) {
        Note ('H 칸 건너뜀 — 엔진 {0}(다시 시작해야 끝나는 치료는 {1} 부터 알린다)' -f $engine, $holdSince)
    } else {
        $h0 = Invoke-Command -Session $session -ArgumentList $guestTools.ToString(), $g, $asec, $f -ScriptBlock {
            param($tools, $probe, $bin, $file)
            . ([scriptblock]::Create($tools))
            Clear-Layout $probe | Out-Null
            $null = New-Layout 'NeacSafe64' 'auto' $bin '' '' $file
            Add-MinifilterForm
            $vals = @(Get-KeyValues)
            $held = Start-Holder $probe
            [pscustomobject]@{ values = $vals; held = $held.held; status = $held.status }
        }
        if (-not $h0.held) { throw ('서비스 핸들을 붙들지 못했다: ' + $h0.status) }
        $wasText = @($h0.values) -join "`n"

        # 서비스 키의 지금 상태 — 키 · Start · 지울 표시 · SCM · 값 목록.
        $readSvc = {
            Invoke-Command -Session $session -ArgumentList $guestTools.ToString() -ScriptBlock {
                param($tools)
                . ([scriptblock]::Create($tools))
                $null = & sc.exe query $svcName
                $queried = $LASTEXITCODE
                $start = $null
                $flag = $null
                if (Test-Path -LiteralPath $svcKey) {
                    $k = Get-Item -LiteralPath $svcKey
                    $start = $k.GetValue('Start')
                    $flag = $k.GetValue('DeleteFlag')
                }
                [pscustomobject]@{ key = (Test-Path -LiteralPath $svcKey); start = $start; flag = $flag; query = $queried; values = @(Get-KeyValues) }
            }
        }

        # H1 — 치료. 네 동작은 끝나고(종료 1 · 실패 0) 화면과 --events 가 남은 삭제를 말한다.
        $hEvents = "$g\out\H1.ndjson"
        $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g -Arguments @('run', '--plugin',
            "$g\plugins\$cleanRule\plugin.yaml", '--yes', '--out-dir', "$g\out\H1", '--state-dir', "$g\state", '--events', $hEvents)
        $h1Screen = [string]$r.out + [string]$r.err
        [IO.File]::WriteAllText((Join-Path $logRoot 'H1.txt'), ("exit={0}`n{1}" -f $r.exit, $h1Screen), $utf8)
        $hText = Read-GuestText $hEvents
        [IO.File]::WriteAllText((Join-Path $logRoot 'H1.ndjson'), [string]$hText, $utf8)
        $hev = @()
        if ($hText) { $hev = @($hText -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }) }
        $hRun = ''
        $hs = @($hev | Where-Object { $_.event -eq 'started' })
        if ($hs.Count) { $hRun = [string]$hs[0].run_id }
        $hActs = @($hev | Where-Object { $_.event -eq 'action' })
        $hOps = @($hActs | ForEach-Object { [string]$_.op }) -join ','
        $hNotDone = @($hActs | Where-Object { $_.outcome -ne 'done' }).Count
        $hFin = @($hev | Where-Object { $_.event -eq 'finished' })
        $hFlag = $hFin.Count -and ($hFin[0].reboot_required -eq $true)
        $hDone = -1
        $hFailed = -1
        if ($hFin.Count) { $hDone = [int]$hFin[0].done; $hFailed = [int]$hFin[0].failed }
        $saysPending = $h1Screen -match $sayPending
        $saysOrder = $h1Screen -match $sayRestoreOrder
        $ok = ($r.exit -eq 1) -and [bool]$hRun -and ($hOps -eq $treatOps) -and ($hNotDone -eq 0) -and ($hDone -eq $treat.Count) -and
            ($hFailed -eq 0) -and $hFlag -and $saysPending -and $saysOrder
        Check 'H1' "핸들을 붙든 채 치료 1 · 네 동작 끝남 · finished 의 reboot_required · 화면의 미룬 삭제 줄과 되돌리는 차례 줄" $ok `
            ('종료 {0} · 회차 {1} · 동작 [{2}] · 끝남 {3} · 실패 {4} · reboot_required {5} · 미룬 삭제 줄 {6} · 차례 줄 {7}' -f $r.exit,
                $hRun, $hOps, $hDone, $hFailed, $(if ($hFlag) { '참' } else { '없음' }), $(if ($saysPending) { '있음' } else { '없음' }),
                $(if ($saysOrder) { '있음' } else { '없음' }))
        if (-not $hRun) { throw '핸들을 붙든 치료의 회차 번호(run_id)를 --events 에서 얻지 못했다' }

        # H2 — 삭제가 미뤄졌다: 키가 남고 Start 4 · 지울 표시 1.
        $h2 = & $readSvc
        $pendingText = @($h2.values) -join "`n"
        $ok = $h2.key -and ($h2.start -eq 4) -and ($h2.flag -eq 1)
        Check 'H2' '치료 뒤 — 서비스 키가 남고 Start 4 · 지울 표시(DeleteFlag 1)' $ok `
            ('키 {0} · Start {1} · DeleteFlag {2} · sc.exe query 종료 {3}' -f $(if ($h2.key) { '있음' } else { '없음' }), $h2.start, $h2.flag, $h2.query)

        # H3 · H4 — 지우는 중인 서비스로는 복원하지 않는다(5 · 아무것도 쓰지 않음). --yes 없이도 · 있어도 같다.
        foreach ($step in @(@{ id = 'H3'; yes = $false }, @{ id = 'H4'; yes = $true })) {
            $restoreArgs = @('restore', '--run', $hRun, '--state-dir', "$g\state")
            if ($step.yes) { $restoreArgs += '--yes' }
            $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g -Arguments $restoreArgs
            $screen = [string]$r.out + [string]$r.err
            [IO.File]::WriteAllText((Join-Path $logRoot ($step.id + '.txt')), ("exit={0}`n{1}" -f $r.exit, $screen), $utf8)
            $now = & $readSvc
            $untouched = (@($now.values) -join "`n") -eq $pendingText
            $saysWhy = $screen -match $sayRemoving
            $saysThen = $screen -match $sayRestartThenRestore
            $ok = ($r.exit -eq 5) -and $saysWhy -and $saysThen -and $untouched -and ($now.flag -eq 1)
            Check $step.id ('지우는 중의 복원' + $(if ($step.yes) { '(--yes)' } else { '(--yes 없음)' }) + ' 5 · 막은 사유 · 다시 시작한 뒤 다시 복원 · 값 목록 그대로') $ok `
                ('종료 {0} · 사유 {1} · 끝 줄 {2} · 값 목록 {3} · DeleteFlag {4}' -f $r.exit, $(if ($saysWhy) { '있음' } else { '없음' }),
                    $(if ($saysThen) { '있음' } else { '없음' }), $(if ($untouched) { '그대로' } else { '바뀜' }), $now.flag)
        }

        # H5 — 놓는다. SCM 이 미룬 삭제를 끝낸다 — 다시 시작이 하는 일을 핸들을 닫아 대신한다.
        $h5 = Invoke-Command -Session $session -ArgumentList $guestTools.ToString(), $g -ScriptBlock {
            param($tools, $probe)
            . ([scriptblock]::Create($tools))
            $how = Stop-Holder $probe
            for ($i = 0; $i -lt 100 -and (Test-Path -LiteralPath $svcKey); $i++) { Start-Sleep -Milliseconds 100 }
            $null = & sc.exe query $svcName
            [pscustomobject]@{ how = $how; key = (Test-Path -LiteralPath $svcKey); query = $LASTEXITCODE }
        }
        Check 'H5' '놓은 뒤 10초 안에 서비스 키가 사라지고 SCM 이 모름(1060)' ((-not $h5.key) -and ($h5.query -eq 1060)) `
            ('붙든 프로세스 {0} · 키 {1} · sc.exe query 종료 {2}' -f $h5.how, $(if ($h5.key) { '있음' } else { '없음' }), $h5.query)

        # H6 — 이제 복원한다. 값 목록이 치료 전과 같다(T5 · T6 과 같은 잣대).
        $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g -Arguments @('restore', '--run', $hRun,
            '--state-dir', "$g\state", '--yes')
        $screen = [string]$r.out + [string]$r.err
        [IO.File]::WriteAllText((Join-Path $logRoot 'H6.txt'), ("exit={0}`n{1}" -f $r.exit, $screen), $utf8)
        $restored = -1
        if ($screen -match '(\d+)건 복원 완료') { $restored = [int]$Matches[1] }
        $h6 = & $readSvc
        $same = (@($h0.values).Count -gt 1) -and ((@($h6.values) -join "`n") -eq $wasText)
        Check 'H6' '놓은 뒤 복원(restore --yes) 0 · 3건 · 값 목록이 치료 전과 같다' (($r.exit -eq 0) -and ($restored -eq 3) -and $same) `
            ('종료 {0} · 복원 {1}건 · 값 목록 {2}줄 {3}' -f $r.exit, $restored, @($h6.values).Count, $(if ($same) { '치료 전과 같음' } else { '다름' }))

        # H7 — 다시 검사 2(두 룰).
        $h7 = Invoke-Scan 'H7' $cleanRule
        $h7b = Invoke-Scan 'H7b' $detectRule
        $ok = ($h7.exit -eq 2) -and ($h7.threats -eq 1) -and ($h7b.exit -eq 2) -and ($h7b.threats -eq 1)
        Check 'H7' '그 복원 뒤 다시 검사 2 — 두 룰 모두 위협 1' $ok `
            ('제거 룰 종료 {0} · 위협 {1} · 탐지 룰 종료 {2} · 위협 {3}' -f $h7.exit, $h7.threats, $h7b.exit, $h7b.threats)
    }
}
catch {
    Check 'E1' '하네스가 끝까지 돌았다' $false $_.Exception.Message
}
finally {
    try {
        $left = Invoke-Command -Session $session -ArgumentList $guestTools.ToString(), $g -ScriptBlock {
            param($tools, $g)
            . ([scriptblock]::Create($tools))
            Clear-Layout $g | Out-Null
            if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
            @(Get-Leftover $g)
        }
        $left = @($left | Where-Object { $_ })
        Check 'C1' '치운 뒤 남은 것 0(서비스 키 · SCM 의 서비스 · System32 의 그 파일 · 작업 폴더 · RunOnce 의 remedy-verify · 핸들을 붙든 프로세스)' ($left.Count -eq 0) $(if ($left.Count) { $left -join ' · ' } else { '없음' })
    } catch {
        Check 'C1' '치운 뒤 남은 것 0' $false ('치우지 못했다: ' + $_.Exception.Message)
    } finally { Remove-PSSession $session }
}
Note ("끝 {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Note ("판정 {0}/{1} · 실패 {2}" -f $pass, $total, $fail)
if ($fail -eq 0) { exit 0 } else { exit 1 }
