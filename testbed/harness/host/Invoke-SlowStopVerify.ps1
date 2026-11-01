#Requires -Version 5.1
<#
.SYNOPSIS
    **오래 도는 도구를 끊지 않는가** — 결정 2026-09-07 의 유일한 실증.

.DESCRIPTION
    remedy 는 외부 도구를 죽이지 않는다. 처음(Phase 1)에는 60초·300초를 넘기면
    자식을 죽였는데, `sc.exe` 는 요청을 SCM 에 넘기고 기다리는 껍데기라 **죽여도
    서비스는 멈추는 중**이고 그때 저널에는 "실패" 가 남는다 — 기계는 치료됐는데
    도구는 실패라고 말하는 것. 그래서 상한은 **알리는 시점**이 됐다.

    그 결정은 지금껏 단위 시험으로만 지켜졌다. 진짜로 오래 도는 도구를 랩에서
    만들 수 없었기 때문이다 — 정상 서비스는 즉시 멈춘다.

    # 병든 서비스를 만든다

    `labsvc` 픽스처에 `--stop-delay-secs` 를 두었다. **정지 제어 핸들러 안에서**
    잔다 — `ControlService`(= `sc.exe stop`)는 그 함수가 돌아올 때까지 막힌다.
    악성 서비스나 망가진 드라이버가 실제로 만드는 모양이다.

    # sc.exe 의 천장은 60초다 (2026-09-12 실측)

    정지 지연을 70초·150초로 두고 재 보니 **둘 다 `sc.exe stop` 이 60.1초에
    돌아왔다.** SCM 이 먼저 포기하고 오류 1053(*"서비스가 시작이나 제어 요청에
    빠르게 응답하지 않았습니다"*)을 낸다.

    **그 천장이 `WARN_SHORT`(60초)와 같아서, 그때는 상한을 넘길 수 없었다.**
    그래서 `sc.exe` 만 상한을 **`WARN_SC`(30초)로 낮췄다**(`4c97172` ·
    2026-09-13 · `windows.rs` 의 `warn_for`). OS 가 60초에 손을 떼므로 그보다
    먼저 알려야 알림이 뜬다.

    **지금은 상한이 도달 가능하다.** 2026-10-26 회차에서 도구가 59초를 돌아
    30초 상한을 넘겼고 `상한 30초 넘음 — 끊지 않습니다` 칸이 실제로 나왔다
    (`verify-slowstop.json` 의 `over_text: true` · `tool_max_secs: 59`).

    재는 것은 그래서 둘이다.

      1. **끊지 않는가** — 도구가 천장(60초)까지 도는 동안 remedy 가 기다리는가
      2. **상한을 넘긴 것을 말하는가** — `WARN_SC` 를 넘긴 칸이 화면에 나오는가

.EXAMPLE
    .\Invoke-SlowStopVerify.ps1 -Build
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    # 정지 핸들러가 붙드는 시간. SCM 이 60초에 포기하므로 그보다 넉넉히 준다.
    [int] $StopDelay = 150
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$triple = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"
$svcSrc = Join-Path $repoRoot "testbed\fixtures\labsvc"
$svcBin = Join-Path $svcSrc "target\release\lab-service.exe"

. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'

if ($Build) {
    Write-Step "빌드"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
        Invoke-CargoBuild "lab-service.exe" @("build", "--release", "--manifest-path",
            (Join-Path $svcSrc "Cargo.toml"))
    } finally { Pop-Location }
    Write-Ok "완료"
}
foreach ($f in @($binPath, $svcBin)) {
    if (-not (Test-Path $f)) { throw "바이너리가 없다: $f  (-Build 로 만들 것)" }
}

$runId = "verify-slowstop-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runId"
New-Item -ItemType Directory -Path $hostOut -Force | Out-Null

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential
try {
    Write-Step "배포"
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        New-Item -ItemType Directory -Force "$lab\bin" | Out-Null
        Remove-Item "$lab\slow-state", "$lab\slow-svc" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
    Copy-Item $svcBin -Destination "$LabRoot\bin\lab-service.exe" -ToSession $session -Force
    Write-Ok "remedy.exe · lab-service.exe"

    Write-Step "병든 서비스를 세우고 remedy 로 정지"
    $r = Invoke-Command -Session $session -ArgumentList $LabRoot, $StopDelay -ScriptBlock {
        param($lab, $delay)
        $ErrorActionPreference = "Continue"
        $name = "remedy-lab-slowstop"
        $dir = "$lab\slow-svc"
        $key = "HKLM\SYSTEM\CurrentControlSet\Services\$name"
        New-Item -ItemType Directory -Force $dir | Out-Null
        & sc.exe delete $name 2>&1 | Out-Null

        $deadline = [int][double]::Parse((Get-Date -UFormat %s)) + 900
        $bin = '"{0}\bin\lab-service.exe" --dir "{1}" --marker SLOWSTOP --deadline {2} --stop-delay-secs {3}' -f `
            $lab, $dir, $deadline, $delay
        $created = (& sc.exe create $name binPath= $bin start= demand 2>&1) -join " "
        & sc.exe start $name 2>&1 | Out-Null
        Start-Sleep -Seconds 3
        # **문자열로 건넨다.** WinRM 을 건넌 ServiceControllerStatus 는 열거형이라
        # `-eq "Running"` 이 거짓이 된다 — 화면에는 Running 으로 보이는데도.
        $state = [string](Get-Service $name -ErrorAction SilentlyContinue).Status

        # **계획을 손으로 쓴다.** 재려는 것은 실행기의 도구 대기이지 계획기가
        # 아니다 — P8 하네스가 같은 자리에서 같은 방식을 쓴다.
        $plan = [ordered]@{
            schema_version = 1; kind = "remedy.plan"; run_id = "slowstop-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
            created        = "2026-09-12T00:00:00Z"
            host           = @{ hostname = $env:COMPUTERNAME; os = "windows"; version = "10"; arch = "amd64" }
            core           = @{ version = "0"; build = "d" }; plugins = @()
            actions        = @(@{ seq = 1; op = "service.stop"; target = $key
                    because = @("e#0"); reversible = $true; risk = "medium"
                })
            verdicts       = @("g0")
        }
        $planPath = "$lab\slow-plan.json"
        [System.IO.File]::WriteAllText($planPath, ($plan | ConvertTo-Json -Depth 8),
            (New-Object System.Text.UTF8Encoding($false)))

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "$lab\bin\remedy.exe"
        $psi.Arguments = ('apply --plan "{0}" --yes --state-dir "{1}\slow-state"' -f $planPath, $lab)
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
        $psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
        # 1초 주기라야 도구의 초가 올라가는 것을 볼 수 있다.
        $psi.EnvironmentVariables["REMEDY_HEARTBEAT_SECS"] = "1"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.StandardInput.Close()
        $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit(600000) | Out-Null
        $sw.Stop()
        $text = ($o.Result + $e.Result)

        # 도구가 몇 초까지 올라갔나 — 심장박동 줄에서 뽑는다.
        $maxTool = 0
        foreach ($l in ($text -split "`r?`n")) {
            if ($l -match '도구 sc\.exe stop (\d+)초') {
                $n = [int]$Matches[1]
                if ($n -gt $maxTool) { $maxTool = $n }
            }
        }
        Start-Sleep -Seconds 2
        $after = [string](Get-Service $name -ErrorAction SilentlyContinue).Status

        & sc.exe delete $name 2>&1 | Out-Null
        Remove-Item $dir, $planPath -Recurse -Force -ErrorAction SilentlyContinue

        [pscustomobject]@{
            Created = $created; StateBefore = $state; StateAfter = $after
            Text = $text; Code = $p.ExitCode; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            MaxTool = $maxTool
            OverText = ($text -match '상한 \d+초 넘음')
        }
    }

    Write-Host ($r.Text -split "`r?`n" | Where-Object { $_ -match '치료 중|실패 \[|수행 \[|결과' } | Select-Object -First 12)
    Write-Host ("[exit={0}] 회차 {1}초 · 도구 최대 {2}초 · 정지 전 {3} → 뒤 {4}" -f `
            $r.Code, $r.Seconds, $r.MaxTool, $r.StateBefore, $r.StateAfter) -ForegroundColor Cyan

    $checks = @(
        @{ name = "병든 서비스가 섰다"; pass = ($r.StateBefore -eq "Running"); detail = $r.StateBefore }
        @{ name = "도구가 50초 넘게 돌았다"; pass = ($r.MaxTool -ge 50); detail = "최대 $($r.MaxTool)초" }
        @{ name = "remedy 가 끊지 않고 기다렸다"; pass = ($r.Seconds -ge 55); detail = "회차 $($r.Seconds)초" }
        @{ name = "심장박동이 도구와 초를 보인다"; pass = ($r.Text -match '도구 sc\.exe stop'); detail = "도구 칸" }
        @{ name = "회차가 끝났다 (멎지 않았다)"; pass = ($null -ne $r.Code); detail = "exit=$($r.Code)" }
        @{ name = "종료 코드가 계약 안이다"; pass = ($r.Code -in @(1, 3)); detail = "exit=$($r.Code)" }
        # **1053 을 무엇이라 말하는가** (결정 2026-09-13). 실패로는 세되,
        # '실패했다' 하나로 뭉뚱그리지 않고 무엇이 일어났는지 말해야 한다.
        @{ name = "1053 을 기다리다 포기로 말한다"; pass = ($r.Text -match 'SCM 이 60초까지만 기다리고 포기'); detail = "1053" }
        # 문구는 2026-09-30 화면 마감(합쇼체) 뒤의 것이다 (2026-10-26 에 맞췄다). **부정
        # 단정은 옛 꼴과 지금 꼴을 다 잡는다** — 옛 꼴(…했다)만 보면 뭉뚱그린 문구가
        # 지금 꼴(…했습니다, 1053 아닌 종료 코드의 문구)로 돌아와도 지나간다.
        @{ name = "무엇이 답하는지 말한다"; pass = ($r.Text -match '재평가가 답합니다'); detail = "재평가" }
        @{ name = "옛 문구로 돌아가지 않았다"; pass = ($r.Text -notmatch 'sc\.exe stop 가 실패했'); detail = "뭉뚱그리지 않는다" }
        # **접두도 사실이어야 한다** (2026-09-13). 사유 문장만 고쳤을 때 화면은
        # `거부됐다: ... SCM 이 ... 포기했다` 였다 — 아무도 거부하지 않은 자리에
        # '거부' 가 붙어 있었다. `PlatformError::TimedOut` 이 그 자리를 맡는다.
        @{ name = "접두가 기다리다 끝났다"; pass = ($r.Text -match '기다리다 끝났습니다: sc\.exe stop'); detail = "TimedOut" }
        @{ name = "거부라고 부르지 않는다"; pass = ($r.Text -notmatch '거부됐(다|습니다): sc\.exe stop'); detail = "Refused 아님" }
    )

    Write-Host ""
    foreach ($c in $checks) {
        $mark = if ($c.pass) { "OK  " } else { "실패" }
        $color = if ($c.pass) { "Green" } else { "Red" }
        Write-Host ("  {0} {1,-30} {2}" -f $mark, $c.name, $c.detail) -ForegroundColor $color
    }
    $passed = @($checks | Where-Object { $_.pass }).Count
    Write-Host ""
    Write-Host ("판정 {0}/{1}" -f $passed, $checks.Count) `
        -ForegroundColor $(if ($passed -eq $checks.Count) { "Green" } else { "Red" })

    # **상한을 넘긴 것을 말하는가는 판정이 아니라 관측이다.** `sc.exe` 의 상한은
    # `WARN_SC`(30초)이고 SCM 이 60초에 포기하므로, 지금은 넘기는 쪽이 정상이다.
    Write-Host ""
    if ($r.OverText) {
        Write-Host ("  관측: '상한 넘음' 칸이 나왔다 — 도구가 {0}초를 돌아 상한(WARN_SC 30초)을 넘겼다" -f $r.MaxTool) -ForegroundColor Yellow
    } else {
        Write-Host "  관측: '상한 넘음' 칸이 나오지 않았다 — 지금은 예상 밖이다." -ForegroundColor Yellow
        Write-Host "        sc.exe 의 상한은 WARN_SC 30초이고(4c97172) SCM 은 60초에 포기한다 —" -ForegroundColor Yellow
        Write-Host "        도구가 30초 안에 돌아왔거나 상한 선택이 바뀐 것이다. 확인할 것." -ForegroundColor Yellow
    }

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $report = [pscustomobject]@{
        schema        = "remedy-verify-slowstop/1"
        host          = (Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME })
        at            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        stop_delay    = $StopDelay
        run_seconds   = $r.Seconds
        tool_max_secs = $r.MaxTool
        over_text     = [bool]$r.OverText
        exit          = $r.Code
        passed        = $passed
        total         = $checks.Count
        checks        = @($checks | ForEach-Object { [pscustomobject]$_ })
    }
    [System.IO.File]::WriteAllText((Join-Path $hostOut "verify-slowstop.json"),
        ($report | ConvertTo-Json -Depth 5), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $hostOut "screen.txt"), $r.Text, $utf8)

    Write-Host "`n결과: $hostOut"
    # **성공도 말한다** — 내지 않으면 한 바퀴가 직전 네이티브 명령의 코드를
    # 물려받는다 (`Invoke-Sweep.ps1` 의 *"종료 코드 없음"* 절).
    exit $(if ($passed -ne $checks.Count) { 1 } else { 0 })
} finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
}
