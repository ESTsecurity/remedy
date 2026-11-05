<#
.SYNOPSIS
    remedy 화면을 랩 VM 의 **진짜 터미널 창**에 띄워 PNG 로 남긴다
    (목표 remedy_제품화 기준 10).

.DESCRIPTION
    WinRM 세션에는 대화형 데스크톱이 없다 — 거기서 만든 콘솔은 그려지지 않는다.
    그래서 **로그온해 있는 사용자의 대화형 세션**에서 게스트 스크립트를 돌린다.
    `LogonType Interactive` · 최고 권한 예약 작업이 `guest\Capture-Window.ps1` 을
    부르고, 그 스크립트가 새 창에 remedy 를 띄워 차례대로 키를 넣고 찍는다.

    # 전제 — 콘솔 세션에 사용자가 있다

    랩 스냅숏은 켠 채 찍혀 `test` 가 콘솔 세션에 들어 있다(2026-11-05 실측 —
    `quser` 의 console · 활성). 없으면 **멈춘다.** 자동 로그온으로 세우는 길은
    `Invoke-P10FVerify.ps1` 에 있다 — 평문 비밀번호를 레지스트리에 두는 길이라
    여기서 조용히 하지 않는다.

    # vmrun 의 화면 갈무리를 쓰지 않는 이유

    `vmrun captureScreen` 은 게스트 비밀번호를 `-gp` 명령줄 인자로 받는다.
    명령줄은 같은 기계의 다른 프로세스가 읽을 수 있다 — 자격 증명은 DPAPI 파일과
    WinRM 세션으로만 다닌다(`VmSession.ps1`).

.PARAMETER Package
    띄울 폴더 — `remedy.exe` 와 그 옆의 꾸러미. 내려받아 푼 배포물을 그대로 준다.

.PARAMETER Bin
    `remedy.exe` 하나만. 꾸러미 없는 첫 화면(사용법)이 나온다.

.PARAMETER Terminal
    conhost(기본) 또는 wt. wt 는 `-WtZip` 이 있어야 한다.

.PARAMETER WtZip
    Windows Terminal 휴대판 zip — 공식 릴리스의 `Microsoft.WindowsTerminal_<판>_x64.zip`.
    랩 VM 에는 Windows Terminal 이 없다(2026-11-05 실측 — 패키지 0). 설치하지 않고
    회차마다 풀어 쓴다 — 스냅숏을 바꾸지 않는다.

.PARAMETER Steps
    게스트 차례. `|` 로 잇는다 — `shot:menu|type:1|wait:8000|shot:scan`.
    말은 `guest\Capture-Window.ps1` 에 있다.

.PARAMETER SetEnv
    `이름=값` 하나 — 띄울 프로그램이 물려받는다. 색을 끈 화면은 `NO_COLOR=1`.

.EXAMPLE
    .\Invoke-ScreenShot.ps1 -Bin target\x86_64-pc-windows-msvc\release\remedy.exe -Name usage
    .\Invoke-ScreenShot.ps1 -Package D:\dl\remedy-evilai-locust-win64 -Name menu
    .\Invoke-ScreenShot.ps1 -Package D:\dl\pkg -Terminal wt -WtZip D:\dl\Microsoft.WindowsTerminal_1.25.2733.0_x64.zip -Name menu-wt
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [string] $LabRoot = "C:\remedy-lab",
    [string] $Package,
    [string] $Bin,
    [ValidateSet("conhost", "wt")] [string] $Terminal = "conhost",
    [string] $WtZip,
    [string] $Steps = "shot:screen",
    [int] $SettleMs = 2500,
    [ValidateSet("print", "screen")] [string] $Method = "print",
    [string] $Name = "shot",
    [int] $TimeoutSec = 180,
    [string] $SetEnv = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot "VmSession.ps1")

if ([bool]$Package -eq [bool]$Bin) { throw "-Package 와 -Bin 가운데 하나만 준다." }
if ($Terminal -eq "wt" -and -not ($WtZip -and (Test-Path $WtZip))) { throw "-Terminal wt 에는 -WtZip(휴대판 zip)이 있어야 한다." }
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'

$runTag  = "shot-$Name-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runTag"
New-Item -ItemType Directory -Force $hostOut | Out-Null
$shotDir = "$LabRoot\shot"
$task    = "remedy-screenshot"

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential
try {
    Write-Step "콘솔 세션 확인 — 창은 로그온한 사용자의 데스크톱에만 그려진다"
    $console = Invoke-Command -Session $session -ScriptBlock { (Get-CimInstance Win32_ComputerSystem).UserName }
    if (-not $console) {
        throw "콘솔 세션에 로그온한 사용자가 없다 — 창이 그려질 데스크톱이 없다. 켠 채 찍은 스냅숏으로 되돌리거나, Invoke-P10FVerify.ps1 의 자동 로그온 절차를 따를 것."
    }
    Write-Ok "콘솔 사용자: $console"

    Write-Step "배포 — 띄울 것과 게스트 스크립트"
    # **앞 회차가 띄운 것을 먼저 끊는다.** Enter 를 기다리는 remedy 가 남아 있으면
    # 폴더가 지워지지 않고 복사가 *"다른 프로세스가 사용 중"* 으로 죽는다.
    $wipe = Invoke-Command -Session $session -ArgumentList $shotDir, $LabRoot, $task -ScriptBlock {
        param($dir, $lab, $task)
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        $killed = @(Get-Process remedy, WindowsTerminal, OpenConsole -ErrorAction SilentlyContinue)
        foreach ($p in $killed) { try { $p.Kill() } catch { } }
        $until = (Get-Date).AddSeconds(20)
        while ((Get-Date) -lt $until) {
            Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $dir)) { break }
            Start-Sleep -Milliseconds 500
        }
        if (Test-Path $dir) { throw "앞 회차의 폴더를 치우지 못했다: $dir" }
        New-Item -ItemType Directory -Force "$dir\app", "$lab\scripts" | Out-Null
        [pscustomobject]@{ Killed = $killed.Count }
    }
    if ($wipe.Killed -gt 0) { Write-Warn "앞 회차가 띄운 프로세스 $($wipe.Killed)개를 끊었다" }
    if ($Package) {
        $src = (Resolve-Path $Package).Path
        if (-not (Test-Path (Join-Path $src "remedy.exe"))) { throw "꾸러미에 remedy.exe 가 없다: $src" }
        Copy-Item (Join-Path $src "*") -Destination "$shotDir\app" -ToSession $session -Recurse -Force
        $exeHash = (Get-FileHash (Join-Path $src "remedy.exe") -Algorithm SHA256).Hash
    } else {
        $src = (Resolve-Path $Bin).Path
        Copy-Item $src -Destination "$shotDir\app\remedy.exe" -ToSession $session -Force
        $exeHash = (Get-FileHash $src -Algorithm SHA256).Hash
    }
    Write-Ok "remedy.exe $($exeHash.Substring(0, 16))"
    Copy-GuestFile -Session $session -Source (Join-Path (Split-Path -Parent $PSScriptRoot) "guest\Capture-Window.ps1") `
                   -Destination "$LabRoot\scripts\Capture-Window.ps1"

    $wtExe = ""
    if ($Terminal -eq "wt") {
        Write-Step "Windows Terminal 휴대판 풀기 (설치하지 않는다)"
        Copy-Item $WtZip -Destination "$shotDir\wt.zip" -ToSession $session -Force
        $wtExe = Invoke-Command -Session $session -ArgumentList $shotDir -ScriptBlock {
            param($dir)
            Expand-Archive -Path "$dir\wt.zip" -DestinationPath "$dir\wt" -Force
            $exe = @(Get-ChildItem "$dir\wt" -Recurse -Filter WindowsTerminal.exe)[0]
            if (-not $exe) { return "" }
            # 휴대판 표시 — 설정을 그 폴더에 둔다. 사용자 프로필을 건드리지 않는다.
            New-Item -ItemType File -Force (Join-Path $exe.DirectoryName ".portable") | Out-Null
            $exe.FullName
        }
        if (-not $wtExe) { throw "zip 에 WindowsTerminal.exe 가 없다: $WtZip" }
        Write-Ok $wtExe
    }

    Write-Step "대화형 세션에서 띄우고 찍는다 ($Terminal · $Steps)"
    $run = Invoke-Command -Session $session -ArgumentList $shotDir, $LabRoot, $task, $console, $Terminal, $wtExe, $Steps, $SettleMs, $Method, $TimeoutSec, $SetEnv -ScriptBlock {
        param($dir, $lab, $task, $user, $terminal, $wtExe, $steps, $settle, $method, $timeout, $setEnv)
        $a = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$lab\scripts\Capture-Window.ps1`"" +
             " -Exe `"$dir\app\remedy.exe`" -OutDir `"$dir\out`" -Terminal $terminal" +
             " -Steps `"$steps`" -SettleMs $settle -Method $method"
        if ($wtExe) { $a += " -WtExe `"$wtExe`"" }
        if ($setEnv) { $a += " -SetEnv `"$setEnv`"" }
        $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $a -WorkingDirectory "$dir\app"
        $pr  = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
        $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds $timeout)
        Register-ScheduledTask -TaskName $task -Action $act -Principal $pr -Settings $set | Out-Null
        $t0 = Get-Date
        Start-ScheduledTask -TaskName $task
        while (((Get-Date) - $t0).TotalSeconds -lt $timeout) {
            if (Test-Path "$dir\out\result.json") { break }
            Start-Sleep -Milliseconds 500
        }
        # 결과 파일을 다 쓸 틈.
        Start-Sleep -Milliseconds 800
        $info = Get-ScheduledTaskInfo -TaskName $task
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
        [pscustomobject]@{
            Done = (Test-Path "$dir\out\result.json")
            Secs = [int]((Get-Date) - $t0).TotalSeconds
            Last = $info.LastTaskResult
        }
    }
    if (-not $run.Done) { throw "$TimeoutSec 초 안에 결과가 없다 (예약 작업 결과 $($run.Last))" }
    Copy-Item "$shotDir\out\*" -Destination $hostOut -FromSession $session -Force
    Write-Ok "$($run.Secs)초 · 결과 $hostOut"

    Write-Step "치우기 — 꾸러미를 랩에 남기지 않는다"
    Invoke-Command -Session $session -ArgumentList $shotDir -ScriptBlock {
        param($dir)
        Get-Process remedy, WindowsTerminal, OpenConsole -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill() } catch { } }
        Start-Sleep -Milliseconds 500
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
} finally {
    if ($session) { Remove-PSSession $session }
}

# ── 판정 ────────────────────────────────────────────────────────────
$r = Get-Content (Join-Path $hostOut "result.json") -Raw -Encoding UTF8 | ConvertFrom-Json
$r | Add-Member -NotePropertyName remedy_sha256 -NotePropertyValue $exeHash
[System.IO.File]::WriteAllText((Join-Path $hostOut "result.json"), ($r | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding $false))
$shots = @($r.steps | Where-Object { $_.shot } | ForEach-Object { $_.shot })
foreach ($s in $shots) {
    if ($s.blank) { Write-Bad "$($s.file) — 한 가지 색뿐이다 (찍히지 않았다)" }
    else { Write-Ok "$($s.file) $($s.size) · $($s.title)" }
}
Write-Host "    승격 $($r.elevated) · 세션 $($r.session_id) · 터미널 $($r.terminal)"
if ($r.error) { Write-Bad "게스트 사유: $($r.error)" }
$bad = [bool]$r.error -or @($shots | Where-Object { $_.blank }).Count -gt 0 -or $shots.Count -eq 0
if ($bad) { exit 1 }
exit 0
