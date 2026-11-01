<#
.SYNOPSIS
    테스트 대상을 만든다. **전부 무해한 모형이다.**

.DESCRIPTION
    악성코드의 *구조*(예약 작업 → 랜덤 폴더의 스크립트, Run 키, 감시 프로세스 쌍,
    자동 재시작 서비스)만 흉내 낸다. 해로운 동작은 하나도 없다 —
    페이로드는 로그 한 줄을 쓰고 끝난다. 네트워크 접속도, 암호화도, 은폐도 없다.

    모든 산출물에 'REMEDY-LAB-' 접두사와 파일 내부 마커 문자열이 붙는다.
    (1) 전부 찾아 지울 수 있고 (2) 실제 시스템 항목과 헷갈리지 않으며
    (3) remedy 룰이 조준할 대상이 명확하기 때문이다.

    **스냅샷에는 이 스크립트만 들어가고 산출물은 들어가지 않는다.**
    스냅샷은 깨끗한 실험대여야 하고, 픽스처는 매 테스트마다 새로 만든다.

.PARAMETER Scenario
    basic    : 예약 작업 + Run 키 + 랜덤 폴더의 페이로드 (기본)
    watchdog : 서로를 되살리는 프로세스 쌍 (설계-03 §2 정지 후 종료 검증용)
    service  : 자동 재시작이 걸린 서비스 (SCM 경쟁 검증용)
    hijack   : Winlogon Userinit 값 부분 오염 (설계-07 결함 1 검증용)

.PARAMETER Remove
    만들어 둔 픽스처를 전부 정리한다. 스냅샷 복원 대신 쓸 수 있다.

.EXAMPLE
    .\New-Fixtures.ps1 -Scenario basic
    .\New-Fixtures.ps1 -Scenario hijack -IAcceptLoginRisk
    .\New-Fixtures.ps1 -Remove
#>
[CmdletBinding()]
param(
    [ValidateSet("basic", "watchdog", "service", "hijack")]
    [string[]] $Scenario = @("basic"),
    [string]   $LabRoot = "C:\remedy-lab",
    [switch]   $Remove,
    # hijack 은 실패 시 로그온이 막힐 수 있다. 명시적 동의를 요구한다.
    [switch]   $IAcceptLoginRisk
)

$ErrorActionPreference = "Stop"
$PREFIX = "REMEDY-LAB"
$MARKER = "REMEDY-LAB-FIXTURE-MARKER-4f2a91"   # YARA 룰이 잡을 문자열
$FixRoot = Join-Path $LabRoot "fixtures"
$Manifest = Join-Path $FixRoot "manifest.json"

function Write-Step { param($t) Write-Host "`n[*] $t" -ForegroundColor Cyan }
function Write-Ok   { param($t) Write-Host "    OK   $t" -ForegroundColor Green }
function Write-Warn { param($t) Write-Host "    주의 $t" -ForegroundColor Yellow }

function Write-Json {
    param([Parameter(Mandatory = $true)] $Object,
          [Parameter(Mandatory = $true)][string] $Path,
          [int] $Depth = 8)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # JSON 은 BOM 없이 쓴다 (.ps1 은 반대로 BOM 이 필요하다 — README 참고).
    [System.IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth $Depth),
                                   (New-Object System.Text.UTF8Encoding($false)))
    if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -eq 0) {
        throw "JSON 쓰기 실패 (0바이트): $Path"
    }
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
              [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "관리자 권한이 필요하다."
    }
}
Assert-Admin

# ================================================================ 정리

if ($Remove) {
    Write-Step "픽스처 정리"

    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -like "$PREFIX*" } |
        ForEach-Object {
            Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false
            Write-Ok "작업 제거: $($_.TaskPath)$($_.TaskName)"
        }

    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "$PREFIX*" } |
        ForEach-Object {
            & sc.exe stop   $_.Name | Out-Null
            & sc.exe delete $_.Name | Out-Null
            Write-Ok "서비스 제거: $($_.Name)"
        }

    # 감시 모형은 powershell.exe 라서 실행 파일 경로가 픽스처 폴더 밑에 있지 않다.
    # 경로로만 찾으면 하나도 못 잡고 그대로 살아남는다. 커맨드라인으로 찾아야 한다.
    #
    # 'remedy-lab' 같은 넓은 패턴은 쓰지 않는다. -match 는 대소문자를 가리지 않아
    # C:\remedy-lab\scripts\New-Fixtures.ps1 까지 걸리고, 그러면 정리 스크립트가
    # 자기 자신과 원격 세션을 죽인다. 파일 이름까지 붙여 좁힌다.
    #
    # 한 번에 안 끝나는 것이 정상이다. 죽이는 사이에 남은 쪽이 상대를 되살리므로
    # 없어질 때까지 반복한다 — remedy 가 해야 할 일과 같은 모양이다 (설계-03 §2).
    $procFilter = {
        ($_.CommandLine -match "$PREFIX-(alpha|beta)\.ps1") -or
        ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($FixRoot, "OrdinalIgnoreCase"))
    }
    $survivors = @()
    for ($round = 1; $round -le 6; $round++) {
        $survivors = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object $procFilter)
        if ($survivors.Count -eq 0) { break }
        foreach ($p in $survivors) {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "프로세스 종료 ${round}회차: $($survivors.Count)개"
        Start-Sleep -Milliseconds 400
    }
    # 마지막 회차가 죽인 결과는 아직 반영되지 않았으므로 다시 확인한다.
    # 이걸 빼면 정리에 성공하고도 실패했다고 보고한다.
    $survivors = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object $procFilter)
    if ($survivors.Count -gt 0) {
        Write-Warn "프로세스 $($survivors.Count)개가 남았다. 스냅샷 복원으로 정리할 것."
    }

    foreach ($k in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                     "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")) {
        if (Test-Path $k) {
            (Get-Item $k).GetValueNames() | Where-Object { $_ -like "$PREFIX*" } |
                ForEach-Object {
                    Remove-ItemProperty -Path $k -Name $_ -Force
                    Write-Ok "자동실행 제거: $k\$_"
                }
        }
    }

    # Userinit 원복 — 우리가 붙인 토큰만 떼어낸다
    $wl = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $cur = (Get-ItemProperty -Path $wl -Name Userinit -ErrorAction SilentlyContinue).Userinit
    if ($cur -and $cur -match [regex]::Escape($FixRoot)) {
        $clean = ($cur -split "," | Where-Object { $_ -notmatch [regex]::Escape($FixRoot) }) -join ","
        Set-ItemProperty -Path $wl -Name Userinit -Value $clean
        Write-Ok "Userinit 원복: $clean"
    }

    if (Test-Path $FixRoot) {
        Get-ChildItem $FixRoot -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "픽스처 파일 제거"
    }
    Write-Host "`n정리 완료." -ForegroundColor Green
    return
}

# ================================================================ 생성

if (-not (Test-Path $FixRoot)) { New-Item -ItemType Directory -Path $FixRoot -Force | Out-Null }
$created = [ordered]@{
    created_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    scenarios  = @($Scenario)
    marker     = $MARKER
    items      = @()
}
function Add-Item2 { param($Type, $Id, $Detail)
    $created.items += [ordered]@{ type = $Type; id = $Id; detail = $Detail }
}

# 랜덤 폴더명 — 감염마다 이름이 바뀌는 형태를 재현한다 (설계-07 시나리오 A)
$rand = -join ((48..57) + (97..102) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
$payloadDir = Join-Path $FixRoot "app-$rand"
New-Item -ItemType Directory -Path $payloadDir -Force | Out-Null

# 페이로드 — 로그 한 줄을 쓰고 끝난다. 그 이상 아무것도 하지 않는다.
$payload = Join-Path $payloadDir "main.js"
@"
// $MARKER
// 무해한 테스트 모형이다. 로그 한 줄을 쓰고 종료한다.
var fs = require('fs');
fs.appendFileSync(process.env.TEMP + '\\$PREFIX-payload.log',
                  new Date().toISOString() + ' fixture ran\r\n');
"@ | Out-File $payload -Encoding utf8
Add-Item2 "file" $payload "페이로드 모형 (마커 포함)"
Write-Ok "페이로드: $payload"

# ---------------------------------------------------------------- basic

if ($Scenario -contains "basic") {
    Write-Step "basic: 예약 작업 + Run 키"

    $runner = Join-Path $payloadDir "run.cmd"
    "@echo off`r`necho $MARKER >> `"%TEMP%\$PREFIX-task.log`"" | Out-File $runner -Encoding ascii

    $taskName = "$PREFIX-Persist"
    $action  = New-ScheduledTaskAction -Execute $runner
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -TaskPath "\$PREFIX\" `
        -Action $action -Trigger $trigger -Settings $set -Force | Out-Null
    Add-Item2 "scheduled_task" "\$PREFIX\$taskName" $runner
    Write-Ok "예약 작업: \$PREFIX\$taskName"

    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $runKey -Name "$PREFIX-Run" -Value "`"$runner`""
    Add-Item2 "autorun" "$runKey\$PREFIX-Run" $runner
    Write-Ok "자동실행: $runKey\$PREFIX-Run"
}

# ---------------------------------------------------------------- watchdog

if ($Scenario -contains "watchdog") {
    Write-Step "watchdog: 서로를 되살리는 프로세스 쌍"
    Write-Warn "무해하지만 실제로 재생성된다. 상한 4개, 10분 후 스스로 종료한다."

    foreach ($pair in @(@("alpha", "beta"), @("beta", "alpha"))) {
        $me = $pair[0]; $peer = $pair[1]
        $script = Join-Path $payloadDir "$PREFIX-$me.ps1"
        # 안전판이 셋이다. 하나라도 빠지면 이 픽스처가 VM 을 잡아먹는다.
        #   (1) 상대 탐지를 CIM 으로 한다. PS 5.1 의 Get-Process 에는 CommandLine 이
        #       없어서 항상 빈 값이 나온다. 그러면 상대를 영원히 못 찾아 매 주기마다
        #       새로 띄우고, 띄워진 것들이 또 띄우면서 지수로 불어난다.
        #   (2) 감시 프로세스 총수가 상한을 넘으면 아무것도 띄우지 않는다.
        #       (1) 이 다시 틀려도 폭주하지는 않게 하는 이중 방어다.
        #   (3) 10분 뒤 스스로 종료한다. 정리가 실패해도 무한히 남지 않는다.
        @"
# $MARKER  무해한 감시 모형. 상대가 없으면 되살린다.
`$deadline = (Get-Date).AddMinutes(10)
while ((Get-Date) -lt `$deadline) {
    `$all = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
              Where-Object { `$_.CommandLine -match '$PREFIX-(alpha|beta)\.ps1' })
    if (`$all.Count -lt 4) {
        `$peerProcs = @(`$all | Where-Object { `$_.CommandLine -match '$PREFIX-$peer\.ps1' })
        if (`$peerProcs.Count -eq 0) {
            Start-Process powershell -ArgumentList '-WindowStyle','Hidden','-ExecutionPolicy','Bypass',
                '-File','$($payloadDir)\$PREFIX-$peer.ps1' -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 500
}
"@ | Out-File $script -Encoding utf8
        Add-Item2 "file" $script "감시 모형 $me"
    }
    Start-Process powershell -ArgumentList "-WindowStyle","Hidden","-ExecutionPolicy","Bypass",
        "-File","$payloadDir\$PREFIX-alpha.ps1" | Out-Null
    Write-Ok "감시 쌍 기동 (alpha/beta)"
}

# ---------------------------------------------------------------- service

if ($Scenario -contains "service") {
    Write-Step "service: 자동 재시작이 걸린 서비스"

    $svcName = "$PREFIX-Svc"
    # 등록과 복구 동작 설정까지만 한다. 시작은 하지 않는다.
    #
    # cmd.exe 는 서비스 제어 디스패처를 부르지 않으므로 SCM 이 30초를 기다린 뒤
    # 1053 으로 실패시킨다. sc start 가 그 30초를 그대로 붙잡고, 복구 동작이
    # 걸려 있으면 재시작마다 또 30초씩 먹는다. 픽스처 생성이 몇 분씩 걸릴 이유가 없다.
    #
    # remedy 가 제거해야 할 산출물은 '등록된 서비스 + 복구 동작'이고 그것은
    # 정지 상태에서도 그대로 관측된다. 실제 SCM 재시작 경쟁까지 재현하려면 진짜
    # 서비스 바이너리가 있어야 하는데, 지금 그걸 만들 이유는 없다 — 이 픽스처의
    # 한계로 남겨 둔다.
    & sc.exe create $svcName binPath= "cmd.exe /c timeout /t 3600" start= demand `
        DisplayName= "$PREFIX Test Service" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc create 실패 (exit $LASTEXITCODE)" }
    & sc.exe failure $svcName reset= 0 actions= restart/1000/restart/1000/restart/1000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc failure 실패 (exit $LASTEXITCODE)" }
    Add-Item2 "service" $svcName "복구 동작: 실패 시 1초 후 재시작 x3 (정지 상태로 등록)"
    Write-Ok "서비스: $svcName (복구 동작 설정됨, 시작하지 않음)"
}

# ---------------------------------------------------------------- hijack

if ($Scenario -contains "hijack") {
    if (-not $IAcceptLoginRisk) {
        throw @"
hijack 시나리오는 Winlogon\Userinit 값을 오염시킨다.
원복에 실패하면 **로그온이 되지 않는다.**
스냅샷을 찍어 둔 상태에서만 쓰고, -IAcceptLoginRisk 를 명시할 것.
"@
    }
    Write-Step "hijack: Userinit 부분 오염"
    Write-Warn "원복 실패 시 로그온 불가. 스냅샷 복원으로만 확실히 되돌아간다."

    $wl = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $orig = (Get-ItemProperty -Path $wl -Name Userinit).Userinit
    $hijackTarget = Join-Path $payloadDir "loader.cmd"
    "@echo off`r`necho $MARKER >> `"%TEMP%\$PREFIX-userinit.log`"" |
        Out-File $hijackTarget -Encoding ascii

    # 원본을 지우지 않고 **덧붙인다**. 부분 편집으로만 치료 가능한 형태다.
    $new = $orig.TrimEnd(",") + "," + $hijackTarget
    Set-ItemProperty -Path $wl -Name Userinit -Value $new
    Add-Item2 "registry_value" "$wl\Userinit" "원본: $orig / 오염: $new"
    Write-Ok "Userinit: $new"
    Write-Warn "원본 값을 manifest.json 에 기록했다. 수동 원복에 쓸 것."
}

# ---------------------------------------------------------------- 매니페스트

Write-Json -Object $created -Path $Manifest -Depth 6
Write-Host "`n생성 완료. 매니페스트: $Manifest" -ForegroundColor Green
Write-Host "정리: .\New-Fixtures.ps1 -Remove  (또는 스냅샷 복원)" -ForegroundColor Gray
