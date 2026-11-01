#Requires -Version 5.1
<#
.SYNOPSIS
    **보호 경로 가드(G6)가 계획을 세우기 전에 서는가** — Windows 실기기 확인.

.DESCRIPTION
    종료 코드 5 는 세 갈래다 — 상한 초과 · **보호 경로** · 서명 검증 실패.
    리눅스 캡처는 상한 초과와 계획 위조를 갖고 있지만 보호 경로는 없다:
    그쪽에는 `dir.delete_recursive` 가 아예 없기 때문이다. Windows 라야 볼 수
    있고, 2026-09-11 까지 아무도 보지 않았다.

    # 무엇을 흉내내는가

    **capture 가 얕게 풀린 모양**이다. 실제로 있었던 일이고(설계-03 §4 조건 5
    의 실측 주석) 그때는 `%LOCALAPPDATA%\Programs` 가 통째로 대상이 됐다.
    여기서는 두 단계 밀어 **`C:\Windows`** 가 되게 한다.

    `C:\Windows` 는 보호 목록에 **없다** — 목록은 `System32`·`SysWOW64`·
    `WinSxS`·`Boot` 다. 목록만 보는 가드는 이것을 통과시킨다. 막는 것은
    *"대상이 보호 디렉터리를 품고 있는가"* 라는 다른 조건이다.

    # 안전 — 순서가 장치다

    **드라이런을 먼저 부른다.** 거기서 5 가 나오면 계획이 서지 않았다는 뜻이고,
    그 뒤의 `--yes` 는 치료에 닿을 수 없다. 드라이런이 5 가 아니면 `--yes` 를
    아예 부르지 않고 멈춘다.

    픽스처는 `%SystemRoot%\Temp\remedy-lab-guard\` 하나뿐이고 끝에서 지운다.
    **System32 에는 아무것도 쓰지 않는다** — 그 폴더의 파일 수를 전후로 센다.

.EXAMPLE
    .\Invoke-GuardVerify.ps1
    .\Invoke-GuardVerify.ps1 -Build
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$triple = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"

. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'

if ($Build) {
    Write-Step "빌드"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
    } finally { Pop-Location }
    Write-Ok "완료"
}
if (-not (Test-Path $binPath)) { throw "바이너리가 없다: $binPath  (-Build 로 만들 것)" }

$runId = "verify-guard-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runId"
New-Item -ItemType Directory -Path $hostOut -Force | Out-Null

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential
try {
    Write-Step "배포 · 픽스처"
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        New-Item -ItemType Directory -Force "$lab\bin", "$lab\scripts" | Out-Null
        Remove-Item "$lab\state-guard", "$lab\out-guard" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
    Copy-Item (Join-Path $PSScriptRoot "..\guest\lab-plugin-guard.yaml") `
        -Destination "$LabRoot\scripts\lab-plugin-guard.yaml" -ToSession $session -Force

    $before = Invoke-Command -Session $session -ScriptBlock {
        $d = Join-Path $env:SystemRoot "Temp\remedy-lab-guard"
        New-Item -ItemType Directory -Force $d | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $d "payload.js"), "// lab fixture`n")
        [pscustomobject]@{
            Sys32 = @(Get-ChildItem "$env:SystemRoot\System32" -File -ErrorAction SilentlyContinue).Count
            WinN  = @(Get-ChildItem "$env:SystemRoot" -Force -ErrorAction SilentlyContinue).Count
        }
    }
    Write-Ok ("System32 파일 {0}개 · Windows 항목 {1}개" -f $before.Sys32, $before.WinN)

    $run = {
        param($lab, $mode)
        $ErrorActionPreference = "Continue"
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "$lab\bin\remedy.exe"
        $psi.Arguments = ('run --plugin "{0}\scripts\lab-plugin-guard.yaml" ' +
            '--out-dir "{0}\out-guard" {1} --state-dir "{0}\state-guard"') -f $lab, $mode
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
        $p.WaitForExit(600000) | Out-Null
        [pscustomobject]@{ Text = (($o.Result + $e.Result).TrimEnd()); Code = $p.ExitCode }
    }

    Write-Step "① 드라이런 — 계획이 서는가"
    $dry = Invoke-Command -Session $session -ArgumentList $LabRoot, "--dry-run" -ScriptBlock $run
    Write-Host $dry.Text

    # **순서가 안전장치다.** 드라이런이 5 가 아니면 계획이 섰다는 뜻이고,
    # 그때는 `--yes` 를 부르지 않는다.
    $yes = $null
    if ($dry.Code -eq 5) {
        Write-Step "② --yes — 승인이 있어도 가드가 먼저다"
        $yes = Invoke-Command -Session $session -ArgumentList $LabRoot, "--yes" -ScriptBlock $run
        Write-Host $yes.Text
    } else {
        Write-Bad "드라이런이 5 가 아니다 (exit=$($dry.Code)). --yes 는 부르지 않는다."
    }

    Write-Step "③ 기계가 그대로인가"
    $after = Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        [pscustomobject]@{
            Sys32   = @(Get-ChildItem "$env:SystemRoot\System32" -File -ErrorAction SilentlyContinue).Count
            WinN    = @(Get-ChildItem "$env:SystemRoot" -Force -ErrorAction SilentlyContinue).Count
            Fixture = Test-Path (Join-Path $env:SystemRoot "Temp\remedy-lab-guard\payload.js")
            Quar    = @(Get-ChildItem "$lab\state-guard\quarantine\*" -ErrorAction SilentlyContinue).Count
            Journal = @(Get-ChildItem "$lab\state-guard\journal\*" -ErrorAction SilentlyContinue).Count
        }
    }

    $checks = @(
        @{ name = "드라이런이 5 (가드 중단)"; pass = ($dry.Code -eq 5); detail = "exit=$($dry.Code)" }
        @{ name = "--yes 도 5 — 승인보다 가드가 먼저"; pass = ($null -ne $yes -and $yes.Code -eq 5); detail = "exit=$(if ($yes) { $yes.Code } else { '부르지 않음' })" }
        @{ name = "사유: 보호 디렉터리를 품고 있다"; pass = ($dry.Text -match '보호 디렉터리'); detail = "[G6]" }
        @{ name = "사유: 읽기 상한 밖 (두 겹)"; pass = ($dry.Text -match '읽기 상한 밖'); detail = "[G6]" }
        @{ name = "System32 가 그대로"; pass = ($after.Sys32 -eq $before.Sys32); detail = "$($after.Sys32) / $($before.Sys32)" }
        @{ name = "C:\Windows 가 그대로"; pass = ($after.WinN -eq $before.WinN); detail = "$($after.WinN) / $($before.WinN)" }
        @{ name = "격리물도 저널도 없다"; pass = ($after.Quar -eq 0 -and $after.Journal -eq 0); detail = "격리 $($after.Quar) · 저널 $($after.Journal)" }
        @{ name = "픽스처는 남아 있다"; pass = ($after.Fixture -eq $true); detail = "남음=$($after.Fixture)" }
    )

    Write-Host ""
    foreach ($c in $checks) {
        $mark = if ($c.pass) { "OK  " } else { "실패" }
        $color = if ($c.pass) { "Green" } else { "Red" }
        Write-Host ("  {0} {1,-34} {2}" -f $mark, $c.name, $c.detail) -ForegroundColor $color
    }
    $passed = @($checks | Where-Object { $_.pass }).Count
    Write-Host ""
    Write-Host ("판정 {0}/{1}" -f $passed, $checks.Count) `
        -ForegroundColor $(if ($passed -eq $checks.Count) { "Green" } else { "Red" })

    # JSON 은 BOM 없이 — serde 계열 파서가 BOM 을 거부한다.
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $report = [pscustomobject]@{
        schema = "remedy-verify-guard/1"
        host   = (Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME })
        at     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        passed = $passed
        total  = $checks.Count
        checks = @($checks | ForEach-Object { [pscustomobject]$_ })
    }
    [System.IO.File]::WriteAllText((Join-Path $hostOut "verify-guard.json"),
        ($report | ConvertTo-Json -Depth 5), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $hostOut "dry-run.txt"), $dry.Text, $utf8)
    if ($yes) { [System.IO.File]::WriteAllText((Join-Path $hostOut "yes.txt"), $yes.Text, $utf8) }

    Write-Step "정리"
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        Remove-Item (Join-Path $env:SystemRoot "Temp\remedy-lab-guard") -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$lab\state-guard", "$lab\out-guard" -Recurse -Force -ErrorAction SilentlyContinue
        # **배포한 룰도 치운다.** 2026-09-12 한 바퀴 뒤에 이것이 남아 있었다 —
        # 다음 회차가 `scripts\` 에서 무엇을 보게 될지는 그 회차가 정해야 한다.
        Remove-Item "$lab\scripts\lab-plugin-guard.yaml" -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "완료"

    Write-Host "`n결과: $hostOut"
    # **성공도 말한다** — 내지 않으면 한 바퀴가 직전 네이티브 명령의 코드를
    # 물려받는다 (`Invoke-Sweep.ps1` 의 *"종료 코드 없음"* 절).
    exit $(if ($passed -ne $checks.Count) { 1 } else { 0 })
} finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
}
