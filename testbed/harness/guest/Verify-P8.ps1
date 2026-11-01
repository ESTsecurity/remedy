#Requires -Version 5.1
<#
.SYNOPSIS
    설계-09 P8 의 **VM 실증 두 건**을 확인한다 — 워치독 쌍과 SCM 복구 동작.

.DESCRIPTION
    P8 의 검증 목록 일곱 줄 중 다섯은 단위 시험이 잰다
    (`remedy-core/tests/p8_guards.rs`). 나머지 둘은 **환경이 실제로 되살리는가**
    를 묻기 때문에 실기기에서만 답할 수 있다.

      A. 워치독 쌍 — 순차 종료로는 지고, remedy 의 종료가 이기는가
      B. SCM 복구 동작 — 복구 설정을 남긴 채 죽이면 SCM 이 되살리는가,
         순서를 지키면 이기는가

    **A 는 관리자 권한이 필요 없다.** 사용자 모드 프로세스 두 개면 되고, 그래서
    개발 기계에서도 돌릴 수 있다. B 는 서비스를 만들어야 하므로 관리자 권한과
    `-AllowSystemService` 를 함께 요구한다 — 실제 시스템 서비스를 정지시키는
    유일한 검사이고, 그것을 실수로 돌리게 두지 않는다.

    A 는 **공정한 상대**를 요구한다. 되살리기가 제품의 종료 창보다 느린 감시자는
    어떤 구현에게도 지고, 그때 "이겼다" 는 아무것도 뜻하지 않는다. 그래서
    픽스처를 컴파일된 바이너리로 두고, 되살리기에 걸린 시간을 **재서 보고한다.**

.PARAMETER Bin
    remedy.exe 경로.

.PARAMETER Watchdog
    lab-watchdog.exe 경로.

.PARAMETER LabService
    lab-service.exe 경로. **진짜 SCM 서비스**여야 한다 — 되살릴 대상이 있으려면
    RUNNING 에 도달해야 하고, 그러려면 핸드셰이크를 해야 한다.

.PARAMETER OutDir
    결과 JSON 을 쓸 곳.

.PARAMETER AllowSystemService
    시나리오 B 를 켠다. **실제 서비스를 만들고 정지시킨다.** VM 에서만 쓸 것.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $Watchdog,
    [Parameter(Mandatory = $true)][string] $LabService,
    [Parameter(Mandatory = $true)][string] $OutDir,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $AllowSystemService
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$results = New-Object System.Collections.ArrayList
$facts = [ordered]@{}

$P8 = Join-Path $LabRoot "p8"

function Resolve-Exe {
    param([string] $Path, [string] $What)
    $r = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $r) { throw "$What 를 찾지 못했다: $Path" }
    $r.ProviderPath
}

# **절대 경로로 고친다.** SCM 은 상대 경로를 `%SystemRoot%\System32` 기준으로
# 풀기 때문에 `binPath` 에 상대 경로가 들어가면 서비스가 아예 뜨지 않는다 —
# 실제로 그렇게 한 판을 날렸다. `sc qc` 는 상대 경로를 그대로 보여 주었고,
# 시작 기록은 0줄이었다.
$Bin        = Resolve-Exe $Bin        "remedy.exe"
$Watchdog   = Resolve-Exe $Watchdog   "lab-watchdog.exe"
$LabService = Resolve-Exe $LabService "lab-service.exe"

# 로컬 시각이 아니라 진짜 epoch 다. `Get-Date -UFormat %s` 는 PS 5.1 에서
# **로컬 시각을 epoch 인 것처럼** 돌려준다 — KST 에서 실측 +32401초. 픽스처는
# `SystemTime::now()` 로 비교하므로 40초 마감이 9시간 40초가 됐고, 픽스처가
# 남지 않게 하는 두 겹 중 한 겹이 사실상 꺼져 있었다.
function Now-Epoch { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

function Add-Check {
    param([string] $Name, [bool] $Pass, [string] $Detail)
    # **한 검사는 한 번만 적힌다.** 두 번 적히면 판정의 분모가 부풀고, 최악의
    # 경우 같은 이름이 서로 다른 결과로 두 줄 남는다. 실제로 그랬다 —
    # `Close-B` 가 채운 것을 표시하지 않아 셋이 여섯이 됐다. 검사 수가
    # 사라지지 않게 하는 것과 부풀지 않게 하는 것은 같은 규율이다.
    if (@($results | Where-Object { $_.name -eq $Name }).Count -gt 0) {
        $Name = "[중복 기록] $Name"
        $Pass = $false
        $Detail = "같은 검사가 두 번 적혔다 — 하네스 결함. " + $Detail
    }
    [void]$results.Add([pscustomobject]@{ name = $Name; pass = $Pass; detail = $Detail })
    $mark = if ($Pass) { "OK  " } else { "실패" }
    $color = if ($Pass) { "Green" } else { "Red" }
    Write-Host ("  {0} {1,-50} {2}" -f $mark, $Name, $Detail) -ForegroundColor $color
}

# **역슬래시-따옴표 규칙을 지킨다.** Windows CRT 는 `\"` 를 escape 된 따옴표로
# 읽는다. 그래서 `C:\dir\` 처럼 역슬래시로 끝나는 값을 그냥 감싸면 닫는 따옴표가
# escape 되어 인자 경계가 무너진다. 따옴표 앞의 역슬래시는 두 배로 늘려야 한다
# (MSDN "Parsing C Command-Line Arguments").
function Quote-Arg {
    param([string] $A)
    if ($A -ne "" -and $A -notmatch '[\s"]') { return $A }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $i = 0
    while ($i -lt $A.Length) {
        $slashes = 0
        while ($i -lt $A.Length -and $A[$i] -eq [char]'\') { $slashes++; $i++ }
        if ($i -eq $A.Length) {
            [void]$sb.Append('\' * ($slashes * 2))
        } elseif ($A[$i] -eq [char]'"') {
            [void]$sb.Append('\' * ($slashes * 2 + 1)); [void]$sb.Append('"'); $i++
        } else {
            [void]$sb.Append('\' * $slashes); [void]$sb.Append($A[$i]); $i++
        }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

# **인코딩은 부르는 대상이 정한다.** 하나로 못 박으면 반드시 한쪽이 깨진다 —
# remedy 는 UTF-8 로 쓰고, `sc.exe` 는 리다이렉트된 핸들에 **코드페이지 바이트**
# 를 쓴다. 전부 UTF-8 로 읽었더니 sc.exe 출력이 통째로 모지바케가 됐고, 그것이
# 판정을 둘로 망가뜨렸다 (설계-09 P8).
#
# **`&` 로 부르지 않는다.** `$ErrorActionPreference = "Stop"` 아래에서 네이티브
# 명령의 stderr 는 종료 오류(NativeCommandError)가 되어 스크립트를 멈춘다 —
# 실패를 *관측하려는* 검사가 그 관측 때문에 죽는다. ProcessStartInfo 로 직접
# 띄우면 stderr 가 그냥 문자열이다.
function Invoke-Exe {
    param(
        [string] $Path,
        [string[]] $Arguments = @(),
        [System.Text.Encoding] $Encoding = [System.Text.Encoding]::UTF8
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Path
    $psi.Arguments = ($Arguments | ForEach-Object { Quote-Arg $_ }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.StandardOutputEncoding = $Encoding
    $psi.StandardErrorEncoding = $Encoding
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    [pscustomobject]@{ exit = $p.ExitCode; text = ($o.Result + $e.Result) }
}

# 리다이렉트된 핸들에는 콘솔 코드페이지가 아니라 **ANSI 코드페이지**가 실려
# 온다. 이 기계에서 콘솔은 65001 인데 sc.exe 는 949 로 썼다 — 콘솔 설정을 보고
# 맞추면 틀린다.
$AnsiEncoding = [System.Text.Encoding]::GetEncoding(
    [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)

function Invoke-Remedy {
    param([string[]] $Arguments)
    Invoke-Exe -Path $Bin -Arguments $Arguments
}

# **`&` 로 부르지 않는다** — `Invoke-Exe` 와 같은 이유에 하나가 더 붙는다.
# PS 5.1 은 네이티브 인자 안의 따옴표를 escape 하지 않고 그대로 흘린다. 그래서
# `binPath= "…" --dir "…"` 을 넘기면 sc.exe 가 받는 것은 **따옴표가 전부 사라진**
# 문자열이다. 경로에 공백이 없으면 우연히 살아남고, 있으면 조용히 깨진다.
function Invoke-Sc {
    param([string[]] $A)
    $r = Invoke-Exe -Path "$env:SystemRoot\System32\sc.exe" -Arguments $A `
                    -Encoding $AnsiEncoding
    [pscustomobject]@{ code = $r.exit; text = (($r.text -replace "\s+", " ").Trim()) }
}

function New-Plan {
    param([string] $RunId, [array] $Actions, [string] $Path)
    $plan = [ordered]@{
        schema_version = 1; kind = "remedy.plan"; run_id = $RunId
        created = "2026-08-23T00:00:00Z"
        host = @{ hostname = $env:COMPUTERNAME; os = "windows"; version = "10"; arch = "amd64" }
        core = @{ version = "0"; build = "d" }; plugins = @()
        actions = $Actions; verdicts = @("g0")
    }
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, ($plan | ConvertTo-Json -Depth 8),
                                   (New-Object System.Text.UTF8Encoding($false)))
    $Path
}

# ══ 시나리오 A — 워치독 쌍 ═══════════════════════════════════════════
#
# **관리자 권한이 필요 없다.** 사용자 모드 프로세스 두 개면 된다.

$wdDir  = Join-Path $P8 "wd"
$marker = "REMEDYP8-" + ([guid]::NewGuid().ToString("N").Substring(0, 12).ToUpper())
$MaxGen = 40

function Get-Watchdogs {
    # **표식으로만 센다.** 이름으로 세면 다른 실행의 잔여물까지 잡는다.
    @(Get-CimInstance Win32_Process -Filter "Name='lab-watchdog.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($marker) })
}

function Start-Pair {
    param([int] $Seconds = 40)
    $deadline = (Now-Epoch) + $Seconds
    Start-Process -FilePath $Watchdog -WindowStyle Hidden -ArgumentList @(
        "--marker", $marker, "--role", "A", "--peer", "B",
        "--gen", "0", "--max-gen", "$MaxGen",
        "--deadline", "$deadline", "--dir", $wdDir) | Out-Null
    # 쌍이 설 때까지, 그리고 **불어나지 않는지** 함께 본다.
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 50
        $n = (Get-Watchdogs).Count
        if ($n -gt 4) { throw "워치독이 $n 개로 불어났다 — 픽스처가 틀렸다" }
        if ($n -eq 2) { return $true }
    }
    $false
}

# **정지 파일이 먼저다.** 종료로 정리하려 들면 되살리기와 경쟁하고, 실측에서
# 정리 쪽이 졌다 — 8회를 죽여도 둘이 남았다. 파일 하나면 다투지 않는다.
function Stop-AllWatchdogs {
    [System.IO.File]::WriteAllText((Join-Path $wdDir "$marker.stop"), "stop")
    for ($i = 0; $i -lt 40; $i++) {
        $p = Get-Watchdogs
        if ($p.Count -eq 0) { return $true }
        $p | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 150
    }
    (Get-Watchdogs).Count -eq 0
}

function Clear-StopFile {
    Remove-Item (Join-Path $wdDir "$marker.stop") -Force -ErrorAction SilentlyContinue
}

function Now-Ms { [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) }

function Get-GenLog {
    $f = Join-Path $wdDir "$marker-generations.log"
    if (Test-Path $f) { @(Get-Content $f -Encoding UTF8 -ErrorAction SilentlyContinue) } else { @() }
}

Write-Host ""
Write-Host "준비" -ForegroundColor Cyan

# **관리자 권한 없이도 확인된다.** 상대 경로는 `binPath` 에 들어가는 순간
# 서비스를 못 뜨게 하는데, 그 실패는 시나리오 B 에서야 드러난다 — 즉 B 를
# 돌릴 수 없는 개발 기계에서는 영영 보이지 않는다. 여기서 본다.
$abs = @($Bin, $Watchdog, $LabService)
Add-Check "실행 파일 경로가 전부 절대 경로다" `
    (($abs | Where-Object { -not [System.IO.Path]::IsPathRooted($_) }).Count -eq 0) `
    (($abs | ForEach-Object { Split-Path $_ -Leaf }) -join " · ")

# 마감은 **진짜 epoch** 여야 한다. 로컬 시각을 넘기면 픽스처(UTC 로 비교)의
# 마감이 시간대만큼 미뤄지고, 남지 않게 하는 겹 하나가 조용히 꺼진다.
$drift = [math]::Abs((Now-Epoch) - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
Add-Check "픽스처 마감이 UTC epoch 로 계산된다" ($drift -le 2) `
    ("현지 시각과의 어긋남 " +
     ([int][double]::Parse((Get-Date -UFormat %s)) - (Now-Epoch)) + "초 · 우리 오차 " + $drift + "초")

# **sc.exe 출력을 읽을 수 있는가.** 없는 서비스를 물으면 1060 과 지역화된
# 문장이 함께 나온다 — 관리자 권한이 필요 없다.
#
# 잘못된 코드페이지로 읽으면 대체 문자(U+FFFD)가 박힌다. 그것을 여기서 잡지
# 않으면 판정이 조용히 무너진다: 한 번은 지역화 문자열을 못 읽어 **거짓 실패**
# 가 났고, 옆 검사는 그 문자열의 *부재*로 판정하던 터라 **복구 동작이 남아
# 있어도 통과하는 빈 검사**가 됐다 (설계-09 P8).
$dec = Invoke-Sc @("query", "remedy-no-such-service")
Add-Check "sc.exe 출력을 코드페이지 그대로 읽는다" `
    (($dec.text -match "1060") -and ($dec.text -notmatch [char]0xFFFD)) `
    ("CP" + $AnsiEncoding.CodePage + " · " + $dec.text)

Write-Host ""
Write-Host "시나리오 A — 워치독 쌍" -ForegroundColor Cyan
Remove-Item $wdDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $wdDir -Force | Out-Null

$aOk = $false
try { $aOk = Start-Pair -Seconds 40 } catch { Add-Check "쌍이 선다" $false $_.Exception.Message }
Add-Check "쌍이 선다" $aOk ("살아 있는 수 " + (Get-Watchdogs).Count)

if ($aOk) {
    # ── A1. 픽스처가 공정한 상대인가 ──────────────────────────────
    #
    # 한쪽만 죽여 되살아나는 데 걸린 시간을 잰다. 이것이 느리면 뒤의 판정이
    # 아무것도 뜻하지 않으므로, **숫자를 결과에 싣는다.**
    $before = (Get-GenLog).Count
    $victim = (Get-Watchdogs)[0]
    # **죽인 시각을 기준으로 잰다.** 마지막 두 줄의 간격을 재면 쌍이 서 있던
    # 시간까지 들어가 1400ms 같은 값이 나온다 — 그것은 되살리기가 아니다.
    $killedAt = Now-Ms
    Stop-Process -Id $victim.ProcessId -Force
    $revived = $false
    for ($i = 0; $i -lt 400; $i++) {
        Start-Sleep -Milliseconds 5
        if ((Get-GenLog).Count -gt $before) { $revived = $true; break }
    }
    $log = Get-GenLog
    $reviveMs = -1
    if ($revived -and $log.Count -ge 1) {
        $reviveMs = [int64](($log[-1] -split ' ')[0]) - $killedAt
    }
    $facts["revive_ms"] = $reviveMs
    Add-Check "한쪽을 죽이면 되살아난다 (감시자다)" $revived "되살리기 간격 ${reviveMs}ms"

    # ── A2. 순차 종료로는 진다 ────────────────────────────────────
    #
    # 하나 죽이고 **한 박자 쉰 뒤** 다음을 죽인다. 그것이 "순차 종료" 이고,
    # 설계-03 §2 가 진다고 말하는 방식이다.
    $seqLost = $false
    if ($revived) {
        $p = Get-Watchdogs
        if ($p.Count -ge 1) { Stop-Process -Id $p[0].ProcessId -Force }
        Start-Sleep -Milliseconds 400
        $p2 = Get-Watchdogs
        if ($p2.Count -ge 1) { Stop-Process -Id $p2[0].ProcessId -Force }
        Start-Sleep -Milliseconds 800
        $seqLost = (Get-Watchdogs).Count -gt 0
    }
    $facts["after_sequential"] = (Get-Watchdogs).Count
    Add-Check "순차 종료로는 진다" $seqLost ("남은 수 " + (Get-Watchdogs).Count)

    # ── A3. remedy 의 process.kill 은 이기는가 ────────────────────
    [void](Stop-AllWatchdogs)
    Remove-Item $wdDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $wdDir -Force | Out-Null
    Clear-StopFile
    $restarted = $false
    try { $restarted = Start-Pair -Seconds 40 } catch { }

    if ($restarted) {
        $planPath = Join-Path $P8 "kill-plan.json"
        [void](New-Plan -RunId ("p8-kill-" + [guid]::NewGuid().ToString("N").Substring(0,8)) -Path $planPath -Actions @(
            @{ seq = 1; op = "process.kill"
               match = @{ cmdline_contains = $marker }
               because = @("e#0"); reversible = $false; risk = "medium"
               max_targets = 8; max_retries = 4 }))
        $r = Invoke-Remedy @("apply", "--plan", $planPath, "--state-dir", (Join-Path $P8 "state"), "--yes")
        # **곧바로 한 번, 그리고 잠시 뒤 한 번 더 센다.** 둘이 다르면 그것이
        # "죽였는데 되살아났다" 이고, remedy 가 성공이라 보고했다면 그 보고는
        # 거짓이다.
        $leftNow = (Get-Watchdogs).Count
        Start-Sleep -Milliseconds 1500
        $left = (Get-Watchdogs).Count
        $facts["after_remedy_immediate"] = $leftNow
        $facts["after_remedy_settled"] = $left
        $facts["remedy_exit"] = $r.exit
        Add-Check "remedy 의 process.kill 이 이긴다" ($left -eq 0) `
            ("직후 $leftNow · 1.5초 뒤 $left · exit=" + $r.exit)
        # 종료 코드가 "치료했다"(1) 인데 살아 있으면 **보고가 거짓이다.**
        Add-Check "이기지 못했으면 그렇게 보고한다" (($left -eq 0) -or ($r.exit -ne 1)) `
            ("exit=" + $r.exit + " 남은 수 $left")
    } else {
        Add-Check "remedy 의 process.kill 이 이긴다" $false "쌍을 다시 세우지 못했다"
    }
}

# ── A4. 뒷정리 ────────────────────────────────────────────────────
$clean = Stop-AllWatchdogs
Add-Check "표식을 가진 프로세스가 남지 않았다" $clean ("남은 수 " + (Get-Watchdogs).Count)

# ══ 시나리오 B — SCM 복구 동작 ═══════════════════════════════════════
#
# **되살림을 재현한다.** 복구 동작을 남긴 채 프로세스를 죽이면 SCM 이 살려
# 내고(B1), 복구 동작을 먼저 지우면 살아나지 않는다(B2). 두 결과의 **차이**가
# "순서를 지키면 이긴다" 의 증거다 — 저널의 줄 번호를 세는 것보다 강하다.
#
# 첫 판은 `binPath = cmd.exe /c exit 1` 이었다. 그것은 SCM 핸드셰이크를 하지
# 않아 RUNNING 에 도달하지 못하고, **되살릴 대상이 애초에 없었다.** 그래서
# "복구 동작이 설정돼 있다" 까지만 볼 수 있었고 그것은 전제이지 재현이 아니다.

$svc     = "remedy-lab-p8"
$svcKey  = "HKLM\SYSTEM\CurrentControlSet\Services\$svc"
$svcDir  = Join-Path $P8 "svc"
$svcMark = "REMEDYSVC-" + ([guid]::NewGuid().ToString("N").Substring(0, 12).ToUpper())

function Get-SvcState {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if ($s) { "$($s.Status)" } else { "없음" }
}

function Wait-SvcState {
    param([string] $Want, [int] $Ms = 8000)
    $t0 = Now-Ms
    while ((Now-Ms) - $t0 -lt $Ms) {
        if ((Get-SvcState) -eq $Want) { return $true }
        Start-Sleep -Milliseconds 100
    }
    (Get-SvcState) -eq $Want
}

function Get-SvcStarts {
    $f = Join-Path $svcDir "$svcMark-service.log"
    if (Test-Path $f) { @(Get-Content $f -Encoding UTF8 -ErrorAction SilentlyContinue).Count } else { 0 }
}

function Get-SvcPid {
    (Get-CimInstance Win32_Service -Filter "Name='$svc'" -ErrorAction SilentlyContinue).ProcessId
}

Write-Host ""
Write-Host "시나리오 B — SCM 복구 동작" -ForegroundColor Cyan

# ── B0. 픽스처가 진짜 서비스인가 ──────────────────────────────────
#
# **관리자 권한 없이도 확인된다.** SCM 이 부르지 않은 서비스 바이너리는
# 1063("서비스 컨트롤러에 연결하지 못했다")으로 거절당한다. 그 거절이 곧
# 핸드셰이크를 하는 진짜 서비스라는 증거다.
$probe = Invoke-Exe -Path $LabService
$isRealService = ($probe.exit -ne 0) -and ($probe.text -match "1063")
Add-Check "픽스처가 진짜 서비스다 (콘솔 실행을 거절한다)" $isRealService `
    ("exit=" + $probe.exit + " · " + (($probe.text -replace "\s+", " ").Trim()))

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $AllowSystemService) {
    Add-Check "시나리오 B" $false "-AllowSystemService 없이 건너뛴다 (재지 못했다)"
} elseif (-not $isAdmin) {
    Add-Check "시나리오 B" $false "관리자 권한이 아니다 (재지 못했다)"
} else {
    try {
        [void](Invoke-Sc @("stop", $svc)); [void](Invoke-Sc @("delete", $svc))
        Start-Sleep -Milliseconds 400
        Remove-Item $svcDir -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $svcDir -Force | Out-Null

        $svcDeadline = (Now-Epoch) + 300
        $binPath = '"{0}" --dir "{1}" --marker {2} --deadline {3}' -f `
            $LabService, $svcDir, $svcMark, $svcDeadline
        $create = Invoke-Sc @("create", $svc, "binPath=", $binPath, "start=", "demand")
        Add-Check "실험용 서비스를 만들었다" ($create.code -eq 0) $create.text

        # 실패하면 1초 뒤 재시작. 세 번까지. `reset= 0` 이라 실패 횟수가
        # 초기화되지 않으므로 B1·B2 두 번을 쓰고도 남는다.
        [void](Invoke-Sc @("failure", $svc, "reset=", "0",
                           "actions=", "restart/1000/restart/1000/restart/1000"))
        # **판정은 ASCII 토큰으로만 한다.** `다시 시작` 같은 지역화된 *값*으로
        # 판정하면 코드페이지 하나만 어긋나도 무너진다 — 실제로 무너졌다.
        # `FAILURE_ACTIONS` 는 sc.exe 가 영어로 찍는 **필드 이름**이고, 복구
        # 동작이 없으면 그 줄 자체가 나오지 않는다. 지역화된 값은 detail 에
        # 보여 주기만 한다.
        #
        # 설계-01 D12 가 제품에게 강제하는 규율("출력을 읽지 않는다. 판단은
        # 종료 코드로만")과 같은 이유다. 하네스가 그 짐을 스스로 졌던 것이
        # 실수였다.
        $q = Invoke-Sc @("qfailure", $svc)
        $recoverySet = $q.text -match "FAILURE_ACTIONS"
        Add-Check "복구 동작이 설정됐다" $recoverySet $q.text

        # **`sc start` 의 답을 버리지 않는다.** 한 번 버렸다가 판을 날렸다 —
        # 실패 이유(오류 2: 지정된 파일을 찾을 수 없습니다)가 손에 있었는데
        # 화면에는 "상태 Stopped" 만 남았다.
        $start = Invoke-Sc @("start", $svc)
        $running = Wait-SvcState "Running"
        Add-Check "서비스가 RUNNING 에 도달했다" $running `
            ("상태 " + (Get-SvcState) + " · 시작 기록 " + (Get-SvcStarts) +
             "줄 · sc start → " + $start.text)

        # **전제가 무너지면 "재지 못했다" 다** (설계-00 §5-1).
        #
        # 아래 셋은 각각 앞의 것을 전제로 한다. 전제 없이 돌리면 둘이 **통과로
        # 보이는데 아무것도 재지 않는다** — 복구 동작이 설정된 적이 없으면
        # "되살아나지 않는다" 는 되살릴 것이 없어서 참이고, "지워졌다" 는
        # 지울 것이 없어서 참이다. 성공처럼 보이는 공백이 가장 나쁘다.
        #
        # 검사 수는 어느 길로 가든 셋으로 고정된다. `Close-B` 가 재지 못한
        # 것을 채운다.
        $bodyChecks = @(
            "복구 동작을 남긴 채 죽이면 SCM 이 되살린다",
            "복구 동작을 먼저 지우면 되살아나지 않는다",
            "복구 동작이 실제로 지워졌다")
        $measured = @{}
        function Add-B {
            param([string] $Name, [bool] $Pass, [string] $Detail)
            $measured[$Name] = $true
            Add-Check $Name $Pass $Detail
        }
        # **채운 것도 잰 것으로 표시한다.** 표시하지 않으면 마지막 그물이
        # 같은 셋을 다시 적어 검사가 여섯이 된다 — 사슬 시험이 그것을 잡았다.
        function Close-B {
            param([string] $Why)
            foreach ($n in $bodyChecks) {
                if (-not $measured.ContainsKey($n)) {
                    $measured[$n] = $true
                    Add-Check $n $false $Why
                }
            }
        }

        if (-not $running) {
            Close-B "서비스가 RUNNING 이 아니라 재지 못했다"
        } elseif (-not $recoverySet) {
            Close-B "복구 동작이 설정된 적이 없어 재지 못했다 — 되살릴 것이 없다"
        } else {
            # ── B1. 복구 동작을 남긴 채 죽이면 SCM 이 되살린다 ────────
            #
            # **`service.stop` 이 아니라 `process.kill` 이다.** 정상 정지는
            # 복구 동작을 유발하지 않는다 — SCM 은 예기치 않은 종료에만
            # 반응하고, 그것이 설계-03 §2 가 1단계(복구 제거)를 2단계(종료)
            # 앞에 둔 이유다.
            $before = Get-SvcStarts
            $pidBefore = Get-SvcPid
            $planPath = Join-Path $P8 "svc-kill.json"
            [void](New-Plan -RunId ("p8-svckill-" + [guid]::NewGuid().ToString("N").Substring(0,8)) `
                -Path $planPath -Actions @(
                @{ seq = 1; op = "process.kill"
                   match = @{ cmdline_contains = $svcMark }
                   because = @("e#0"); reversible = $false; risk = "medium"
                   max_targets = 4; max_retries = 1 }))
            $r1 = Invoke-Remedy @("apply", "--plan", $planPath,
                                  "--state-dir", (Join-Path $P8 "state"), "--yes")
            Start-Sleep -Seconds 5
            $revived = ((Get-SvcStarts) -gt $before) -and ((Get-SvcState) -eq "Running")
            $facts["svc_starts_after_kill"] = Get-SvcStarts
            $facts["svc_pid_changed"] = ((Get-SvcPid) -ne $pidBefore)
            Add-B "복구 동작을 남긴 채 죽이면 SCM 이 되살린다" $revived `
                ("시작 기록 {0}→{1} · 상태 {2} · PID 바뀜 {3} · exit={4}" -f `
                    $before, (Get-SvcStarts), (Get-SvcState),
                    $facts["svc_pid_changed"], $r1.exit)

            if (-not $revived) {
                # **되살림을 보이지 못했으면 B2 는 비교할 것이 없다.** 그
                # 상태에서 "되살아나지 않았다" 는 remedy 가 이긴 것이 아니라
                # 애초에 싸움이 없었던 것이다.
                Close-B "되살림을 보이지 못해 재지 못했다 — 무엇과 비교할지가 없다"
            } else {
            # ── B2. 복구 동작을 먼저 지우면 되살아나지 않는다 ──────────
            #
            # 같은 종료인데 앞에 한 줄이 더 있을 뿐이다. **결과의 차이가 곧
            # 순서의 값어치다.**
            $before2 = Get-SvcStarts
            $planPath2 = Join-Path $P8 "svc-ordered.json"
            [void](New-Plan -RunId ("p8-svcorder-" + [guid]::NewGuid().ToString("N").Substring(0,8)) `
                -Path $planPath2 -Actions @(
                @{ seq = 1; op = "service.clear_recovery"; target = $svcKey
                   because = @("e#0"); reversible = $true; risk = "medium" },
                @{ seq = 2; op = "process.kill"
                   match = @{ cmdline_contains = $svcMark }
                   because = @("e#0"); reversible = $false; risk = "medium"
                   max_targets = 4; max_retries = 1 }))
            $r2 = Invoke-Remedy @("apply", "--plan", $planPath2,
                                  "--state-dir", (Join-Path $P8 "state"), "--yes")
            Start-Sleep -Seconds 6
            $stayedDead = ((Get-SvcStarts) -eq $before2) -and ((Get-SvcState) -ne "Running")
            $facts["svc_starts_after_ordered"] = Get-SvcStarts
            Add-B "복구 동작을 먼저 지우면 되살아나지 않는다" $stayedDead `
                ("시작 기록 {0}→{1} · 상태 {2} · exit={3}" -f `
                    $before2, (Get-SvcStarts), (Get-SvcState), $r2.exit)

            # 설정될 때 `FAILURE_ACTIONS` 가 **있었다**는 것을 위에서 확인했다.
            # 그러니 지금 없는 것은 지워졌다는 뜻이다 — 앞의 확인 없이 부재만
            # 보면 읽지 못한 것과 구별되지 않는다.
            $q3 = Invoke-Sc @("qfailure", $svc)
            Add-B "복구 동작이 실제로 지워졌다" (-not ($q3.text -match "FAILURE_ACTIONS")) $q3.text
            }
        }
        Close-B "재지 못했다"

        # ── B3. service.disable 이 시작 유형을 바꾼다 ─────────────────
        #
        # 성공 보고만 보고 넘어가면 `sc config` 가 실패해도 통과한다.
        # **결과를 본다.**
        $planPath3 = Join-Path $P8 "svc-disable.json"
        [void](New-Plan -RunId ("p8-svcdis-" + [guid]::NewGuid().ToString("N").Substring(0,8)) `
            -Path $planPath3 -Actions @(
            @{ seq = 1; op = "service.disable"; target = $svcKey
               because = @("e#0"); reversible = $true; risk = "medium" }))
        $r3 = Invoke-Remedy @("apply", "--plan", $planPath3,
                              "--state-dir", (Join-Path $P8 "state"), "--yes")
        # `START_TYPE : 4 DISABLED` — 숫자도 상수 이름도 sc.exe 가 영어로
        # 찍는다. 지역화되는 것은 값의 설명뿐이다.
        $qc = Invoke-Sc @("qc", $svc)
        Add-Check "service.disable 이 시작 유형을 바꾼다" `
            ($qc.text -match "START_TYPE\s*:\s*4\b") `
            ("적용 시점 상태 " + (Get-SvcState) + " · exit=" + $r3.exit + " · " + $qc.text)
    } finally {
        [void](Invoke-Sc @("stop", $svc))
        Start-Sleep -Milliseconds 500
        [void](Invoke-Sc @("delete", $svc))
        Start-Sleep -Milliseconds 400
        $gone = -not (Get-Service $svc -ErrorAction SilentlyContinue)
        Add-Check "실험용 서비스를 지웠다" $gone ("상태 " + (Get-SvcState))
    }
}

# ══ 결과 ═════════════════════════════════════════════════════════════
$pass = @($results | Where-Object { $_.pass }).Count
$total = $results.Count
Write-Host ""
Write-Host ("판정: {0}/{1}" -f $pass, $total) -ForegroundColor $(if ($pass -eq $total) { "Green" } else { "Red" })

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$report = [ordered]@{
    schema      = "remedy-lab.verify-p8/1"
    verified_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    marker      = $marker
    passed      = $pass
    total       = $total
    facts       = $facts
    checks      = $results
}
[System.IO.File]::WriteAllText((Join-Path $OutDir "verify-p8.json"),
    ($report | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))

if ($pass -ne $total) { exit 1 }
exit 0
