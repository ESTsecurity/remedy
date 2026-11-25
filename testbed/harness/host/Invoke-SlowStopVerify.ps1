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

    # 정지를 받지 않는 서비스 (N 칸 · 2026-11-25 · 엔진 1.26.0)

    `labsvc --no-stop` 은 아무 제어도 받지 않는다. 손으로 쓴 계획(정지 → 사용 안 함 → 삭제)으로 둘을 잰다 — N1 Win32
    서비스 그대로면 정지는 지금처럼 실패(3)이고, N2 정의 키의 Type 을 1 로 바꾼 흉내면 엔진이 정지를 '다시 시작해야 끝남'
    으로 받아 1 로 끝내고 목록 · `finished` 의 `reboot_required` 로 알린다. 서비스가 도는 동안 삭제는 미뤄지고(지울 표시)
    그 사이의 복원은 5 다. 마감(40초)에 서비스가 나가면 SCM 이 삭제를 끝내고 복원은 0 이다. **N2 는 흉내다** — SCM 이
    메모리에 둔 유형은 Win32 그대로이고, 실물 드라이버가 내는 거부 코드는 재지 않는다.

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

    # ── N — 정지를 받지 않는 서비스(2026-11-25 · 엔진 1.26.0 · 이슈 #172 ⑥). `--no-stop` 으로 띄운 labsvc 는 아무 제어도
    #    받지 않는다 — `sc.exe stop` 이 그 자리에서 물리친다. 손으로 쓴 계획: [1] 정지 → [2] 사용 안 함 → [3] 삭제.
    #    N1 Win32 서비스 그대로 — 정지는 실패(3 · 결정 2026-09-13 그대로) · 삭제는 미뤄짐(서비스가 돈다) · 마감에 서비스가
    #       나가면 SCM 이 키를 지운다
    #    N2 정의 키의 Type 을 1(커널 드라이버)로 바꾼 **흉내** — 정지를 '다시 시작해야 끝남' 으로 받아 1 · 목록 [1] · [3] ·
    #       finished 의 reboot_required · 그 사이의 복원은 5 · 마감 뒤 키가 사라지고 복원 0. SCM 이 메모리에 둔 유형은 Win32
    #       그대로이고, 실물 드라이버가 내는 거부 코드는 재지 않는다 — 재는 것은 엔진의 판단과 진짜 SCM 의 미룬 삭제다
    Write-Step "정지를 받지 않는 서비스(N1 · N2)"
    foreach ($nc in @(@{ id = 'N1'; driver = $false }, @{ id = 'N2'; driver = $true })) {
        $n = Invoke-Command -Session $session -ArgumentList $LabRoot, $nc.driver -ScriptBlock {
            param($lab, $asDriver)
            $ErrorActionPreference = "Continue"
            $name = "remedy-lab-nostop"
            $dir = "$lab\nostop-svc"
            $stateDir = "$lab\nostop-state"
            $key = "HKLM\SYSTEM\CurrentControlSet\Services\$name"
            $psKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
            Remove-Item $dir, $stateDir -Recurse -Force -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Force $dir | Out-Null
            & sc.exe delete $name 2>&1 | Out-Null

            # **마감은 UTC 로 센다** — labsvc 는 UTC 초와 견준다. Windows PowerShell 5.1 의 `Get-Date -UFormat %s` 는 현지
            # 시각으로 세어(2026-11-25 랩: 마감이 몇 시간 뒤가 되어 서비스가 나가지 않았다) 정지로 끝나는 위 칸에서만 쓸 수 있다.
            $deadline = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 40
            $bin = '"{0}\bin\lab-service.exe" --dir "{1}" --marker NOSTOP --deadline {2} --no-stop' -f $lab, $dir, $deadline
            $created = (& sc.exe create $name binPath= $bin start= demand 2>&1) -join " "
            $createCode = $LASTEXITCODE
            & sc.exe start $name 2>&1 | Out-Null
            Start-Sleep -Seconds 2
            $before = [string](Get-Service $name -ErrorAction SilentlyContinue).Status
            if ($asDriver) { Set-ItemProperty -LiteralPath $psKey -Name Type -Value 1 -Type DWord }

            $runId = "nostop-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
            $acts = @()
            $seq = 0
            foreach ($op in @('service.stop', 'service.disable', 'service.delete')) {
                $seq++
                $acts += @{ seq = $seq; op = $op; target = $key; because = @("e#0"); reversible = ($op -ne 'service.stop'); risk = "medium" }
            }
            $plan = [ordered]@{
                schema_version = 1; kind = "remedy.plan"; run_id = $runId
                created        = "2026-11-25T00:00:00Z"
                host           = @{ hostname = $env:COMPUTERNAME; os = "windows"; version = "10"; arch = "amd64" }
                core           = @{ version = "0"; build = "d" }; plugins = @()
                actions        = $acts
                verdicts       = @("g0")
            }
            $planPath = "$lab\nostop-plan.json"
            [System.IO.File]::WriteAllText($planPath, ($plan | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))

            # remedy 한 번 — 종료 코드 · 화면 · 이벤트.
            $run = {
                param([string] $argLine)
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = "$lab\bin\remedy.exe"
                $psi.Arguments = $argLine
                $psi.UseShellExecute = $false
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                $psi.RedirectStandardInput = $true
                $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
                $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
                $psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
                $p = [System.Diagnostics.Process]::Start($psi)
                $p.StandardInput.Close()
                $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
                $p.WaitForExit(300000) | Out-Null
                [pscustomobject]@{ code = $p.ExitCode; text = ($o.Result + $e.Result) }
            }
            $events = "$lab\nostop-events.ndjson"
            Remove-Item $events -Force -ErrorAction SilentlyContinue
            $ap = & $run ('apply --plan "{0}" --yes --state-dir "{1}" --events "{2}"' -f $planPath, $stateDir, $events)
            $evText = ''
            if (Test-Path -LiteralPath $events) { $evText = [IO.File]::ReadAllText($events) }
            $flagAfter = (Get-ItemProperty -LiteralPath $psKey -Name DeleteFlag -ErrorAction SilentlyContinue).DeleteFlag
            $running = [string](Get-Service $name -ErrorAction SilentlyContinue).Status

            # 마감 전의 복원 — 지우는 중인 서비스로는 쓰지 않는다(5).
            $early = & $run ('restore --run {0} --state-dir "{1}" --yes' -f $runId, $stateDir)

            # 마감에 서비스가 나가면 SCM 이 미뤄 둔 삭제를 끝낸다 — 키가 사라질 때까지 70초까지.
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            while ((Test-Path -LiteralPath $psKey) -and $sw.Elapsed.TotalSeconds -lt 70) { Start-Sleep -Milliseconds 250 }
            $gone = -not (Test-Path -LiteralPath $psKey)
            $late = $null
            if ($gone) { $late = & $run ('restore --run {0} --state-dir "{1}" --yes' -f $runId, $stateDir) }

            # 치운다 — 복원한 키는 SCM 이 모른다(다시 시작 전) — 그때는 레지스트리에서 지운다.
            & sc.exe delete $name 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 1060 -and (Test-Path -LiteralPath $psKey)) { Remove-Item -LiteralPath $psKey -Recurse -Force }
            for ($i = 0; $i -lt 40 -and (Test-Path -LiteralPath $psKey); $i++) { Start-Sleep -Milliseconds 250 }
            $left = Test-Path -LiteralPath $psKey
            Remove-Item $dir, $stateDir, $planPath, $events -Recurse -Force -ErrorAction SilentlyContinue

            [pscustomobject]@{
                Created = $created; CreateCode = $createCode; Before = $before; Code = $ap.code; Text = $ap.text; Events = $evText
                FlagAfter = $flagAfter; Running = $running; EarlyCode = $early.code; EarlyText = $early.text
                Gone = $gone; GoneSecs = [math]::Round($sw.Elapsed.TotalSeconds, 1)
                LateCode = $(if ($late) { $late.code } else { $null }); LateText = $(if ($late) { $late.text } else { '' }); Left = $left
            }
        }
        $fin = @(($n.Events -split "`n") | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.event -eq 'finished' })
        $flag = $fin.Count -and ($fin[0].reboot_required -eq $true)
        $listDelete = $n.Text -match '\[3\] 서비스 삭제 .*Windows 가 지우기를 미뤘습니다'
        $listStop = $n.Text -match '\[1\] 서비스 중지 .*드라이버가 정지를 받지 않았습니다'
        $held = ($n.EarlyCode -eq 5) -and ($n.EarlyText -match 'Windows 가 이 서비스를 지우는 중입니다')
        $id = $nc.id
        if ($nc.driver) {
            $checks += @(
                @{ name = "$id 정지를 받지 않는 서비스가 섰다"; pass = ($n.CreateCode -eq 0) -and ($n.Before -eq "Running"); detail = "만듦 $($n.CreateCode) · $($n.Before)" }
                @{ name = "$id 드라이버 흉내 — 정지를 받아 1"; pass = ($n.Code -eq 1) -and ($n.Text -match '수행 \[1/3\] 서비스 중지'); detail = "exit=$($n.Code)" }
                @{ name = "$id 목록 [1] 정지 · [3] 미룬 삭제"; pass = $listStop -and $listDelete; detail = "정지 줄 $listStop · 삭제 줄 $listDelete" }
                @{ name = "$id finished 의 reboot_required"; pass = [bool]$flag; detail = "$flag" }
                @{ name = "$id 지울 표시가 남았다(서비스가 돈다)"; pass = ($n.FlagAfter -eq 1) -and ($n.Running -eq 'Running'); detail = "DeleteFlag $($n.FlagAfter) · $($n.Running)" }
                @{ name = "$id 그 사이의 복원 5"; pass = $held; detail = "exit=$($n.EarlyCode)" }
                @{ name = "$id 마감 뒤 키가 사라지고 복원 0"; pass = $n.Gone -and ($n.LateCode -eq 0); detail = "$($n.GoneSecs)초 · exit=$($n.LateCode)" }
                @{ name = "$id 치운 뒤 남은 것 없음"; pass = (-not $n.Left); detail = "키 남음 $($n.Left)" }
            )
        } else {
            $checks += @(
                @{ name = "$id 정지를 받지 않는 서비스가 섰다"; pass = ($n.CreateCode -eq 0) -and ($n.Before -eq "Running"); detail = "만듦 $($n.CreateCode) · $($n.Before)" }
                @{ name = "$id Win32 그대로 — 정지는 실패 3"; pass = ($n.Code -eq 3) -and ($n.Text -match '실패 \[1/3\] 서비스 중지'); detail = "exit=$($n.Code)" }
                @{ name = "$id 정지를 받아 주지 않는다"; pass = (-not $listStop); detail = "정지 줄 $listStop" }
                @{ name = "$id 목록 [3] 미룬 삭제 · reboot_required"; pass = $listDelete -and [bool]$flag; detail = "삭제 줄 $listDelete · $flag" }
                @{ name = "$id 마감 뒤 키가 사라졌다"; pass = [bool]$n.Gone; detail = "$($n.GoneSecs)초" }
                @{ name = "$id 치운 뒤 남은 것 없음"; pass = (-not $n.Left); detail = "키 남음 $($n.Left)" }
            )
        }
        [System.IO.File]::WriteAllText((Join-Path $hostOut "$id-screen.txt"),
            ("apply exit={0}`n{1}`n--- events`n{2}`n--- restore(마감 전) exit={3}`n{4}`n--- restore(마감 뒤) exit={5}`n{6}" -f
                $n.Code, $n.Text, $n.Events, $n.EarlyCode, $n.EarlyText, $n.LateCode, $n.LateText), (New-Object System.Text.UTF8Encoding($false)))
    }

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
