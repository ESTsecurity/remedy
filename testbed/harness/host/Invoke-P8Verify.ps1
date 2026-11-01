<#
.SYNOPSIS
    설계-09 P8 의 **VM 실증 두 건**을 테스트 VM 에서 확인한다.

.DESCRIPTION
    P8 검증 목록 일곱 줄 중 다섯은 단위 시험이 잰다(`p8_guards.rs`). 나머지
    둘은 **환경이 실제로 되살리는가**를 묻기 때문에 실기기에서만 답할 수 있다.

      A. 워치독 쌍 — 순차 종료로는 지고, remedy 의 종료가 이기는가
      B. SCM 복구 동작 — 죽이면 SCM 이 되살리고, 먼저 지우면 되살아나지 않는가

    **A 는 VM 이 없어도 돌릴 수 있다.** 사용자 모드 프로세스 두 개면 되므로
    개발 기계에서 게스트 스크립트를 직접 부르면 된다 — 그것이 이 검증을 자주
    돌릴 수 있게 하는 자리다.

        pwsh testbed\harness\guest\Verify-P8.ps1 `
             -Bin target\debug\remedy.exe `
             -Watchdog testbed\fixtures\watchdog\target\release\lab-watchdog.exe `
             -LabService testbed\fixtures\labsvc\target\release\lab-service.exe `
             -OutDir testbed\harness\results\p8 -LabRoot C:\remedy-lab

    B 는 서비스를 만들고 죽이므로 **VM 에서만** 돈다. 이 드라이버가
    `-AllowSystemService` 를 붙이는 유일한 자리이고, 그래서 실수로 개발
    기계에서 돌아가지 않는다.

    `-OutDir` 은 `testbed\harness\results\` 아래를 쓴다 — 그 경로만
    `.gitignore` 에 있고, 결과 JSON 에는 대상 시스템의 경로·프로세스가 그대로
    담긴다 (설계-00 §7).

.EXAMPLE
    .\Invoke-P8Verify.ps1 -Build
    .\Invoke-P8Verify.ps1 -NoRevert
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    [switch] $NoRevert,
    [string] $Snapshot,
    [string] $Vmx,

    # **2026-09-02 까지 이 스위치가 사실상 필수였다.**
    #
    # 그 전에는 `integrity_gate` 가 서명 없는 릴리스의 `apply`·`resume` 을 종료
    # 코드 5 로 막았고, 이 하네스는 `--release` 로 빌드하므로 **파괴 검사가 전부
    # 5 로 깨졌다** — 2026-08-28 재실행에서 30건이 한꺼번에 실패했다. 그래서
    # 개발 빌드로 재야 했고, 주석이 *"배포될 물건과 다른 바이너리를 재는
    # 것"* 이라고 스스로 적어 두었다.
    #
    # 지금은 서명 없음이 파괴를 막지 않으므로 **배포될 바로 그 바이너리로
    # 잰다.** 이 스위치는 디버그 빌드를 재고 싶을 때만 쓴다.
    [switch] $DevBuild
)

$ErrorActionPreference = "Stop"


$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$Vmx       = Resolve-LabValue $Vmx 'windows_lab' 'windows_lab.identity.vmx' 'Vmx'
$Snapshot  = Resolve-LabValue $Snapshot 'windows_lab' 'windows_lab.snapshots.current' 'Snapshot'

$triple  = "x86_64-pc-windows-msvc"
# 개발 빌드는 `target\<triple>\debug\` 에 선다.
$profile_ = if ($DevBuild) { "debug" } else { "release" }
# **`[string[]]` 가 필요하다.** PowerShell 은 `if` 가 돌려주는 단일 원소 배열을
# 스칼라로 푼다 — 그러면 `$cargoProfile` 이 문자열이 되고 `@cargoProfile` 이
# 그것을 문자 단위로 쪼개 `cargo` 가 `-` 하나를 받는다 (실측 2026-08-29).
#
# `-DevBuild` 로만 돌리는 동안에는 빈 배열이라 드러나지 않았다.
[string[]] $cargoProfile = if ($DevBuild) { @() } else { @("--release") }
$binPath = Join-Path $repoRoot "target\$triple\$profile_\remedy.exe"
$wdSrc   = Join-Path $repoRoot "testbed\fixtures\watchdog"
$wdPath  = Join-Path $wdSrc "target\release\lab-watchdog.exe"
$svcSrc  = Join-Path $repoRoot "testbed\fixtures\labsvc"
$svcPath = Join-Path $svcSrc "target\release\lab-service.exe"

if ($Build) {
    Write-Step "빌드: remedy.exe"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        # **실패하면 throw 다** — VM 에 아무것도 배포하지 않는다.
        Invoke-CargoBuild "remedy.exe" (@("build") + $cargoProfile + @("--target", $triple, "-p", "remedy-cli"))
    } finally { Pop-Location }

    # 픽스처는 **워크스페이스 밖이다.** 제품 크레이트 수와 금지 의존 검사에
    # 섞이면 안 되므로 따로 빌드한다.
    Write-Step "빌드: 픽스처 2종 (워크스페이스 밖)"
    foreach ($m in @($wdSrc, $svcSrc)) {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        Invoke-CargoBuild "픽스처 $(Split-Path $m -Leaf)" @("build", "--release",
            "--manifest-path", (Join-Path $m "Cargo.toml"))
    }
    Write-Ok "완료"
}

foreach ($p in @($binPath, $wdPath, $svcPath)) {
    if (-not (Test-Path $p)) { throw "산출물이 없다: $p`n먼저 -Build 를 줄 것." }
}
$binHash = (Get-FileHash $binPath -Algorithm SHA256).Hash
Write-Ok "remedy.exe    $binHash"
Write-Ok "lab-watchdog  $((Get-FileHash $wdPath -Algorithm SHA256).Hash)"
Write-Ok "lab-service   $((Get-FileHash $svcPath -Algorithm SHA256).Hash)"

# ---------------------------------------------------------------- 연결

if (-not $NoRevert) {
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
}

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential

$runId   = "verify-p8-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$vmOut   = "$LabRoot\results\$runId"
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runId"
New-Item -ItemType Directory -Path $hostOut -Force | Out-Null
Write-Ok "실행 ID: $runId"

Invoke-Command -Session $session -ScriptBlock {
    param($p, $root)
    foreach ($d in @($p, "$root\bin", "$root\scripts")) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
} -ArgumentList $vmOut, $LabRoot

# ---------------------------------------------------------------- 배포

Write-Step "배포"
$guestDir = Join-Path (Split-Path -Parent $PSScriptRoot) "guest"
Copy-GuestFile -Session $session -Source (Join-Path $guestDir "Verify-P8.ps1") `
               -Destination "$LabRoot\scripts\Verify-P8.ps1"
Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
Copy-Item $wdPath  -Destination "$LabRoot\bin\lab-watchdog.exe" -ToSession $session -Force
Copy-Item $svcPath -Destination "$LabRoot\bin\lab-service.exe" -ToSession $session -Force
Write-Ok "remedy.exe · lab-watchdog.exe · lab-service.exe · Verify-P8.ps1"

$remoteHash = Invoke-Command -Session $session -ScriptBlock {
    param($root) (Get-FileHash "$root\bin\remedy.exe" -Algorithm SHA256).Hash
} -ArgumentList $LabRoot
if ($remoteHash -ne $binHash) {
    throw "전송 후 바이너리 해시가 다르다: 로컬 $binHash / 원격 $remoteHash"
}
Write-Ok "해시 일치"

Assert-CanDestroy -Session $session -Bin (Join-Path (Join-Path $LabRoot "bin") "remedy.exe")

# ---------------------------------------------------------------- 실행

Write-Step "P8 검증 실행 (**파괴적** — 프로세스를 죽이고 서비스를 만든다)"
$exit = Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Verify-P8.ps1" `
    -PassThruExitCode -Arguments @(
    "-Bin", "$LabRoot\bin\remedy.exe",
    "-Watchdog", "$LabRoot\bin\lab-watchdog.exe",
    "-LabService", "$LabRoot\bin\lab-service.exe",
    "-OutDir", $vmOut,
    "-LabRoot", $LabRoot,
    "-AllowSystemService"
)

# ---------------------------------------------------------------- 회수

Write-Step "결과 회수"
Copy-Item -FromSession $session -Path "$vmOut\verify-p8.json" `
          -Destination (Join-Path $hostOut "verify-p8.json") -Force -ErrorAction SilentlyContinue

$reportPath = Join-Path $hostOut "verify-p8.json"
$report = $null
if (Test-Path $reportPath) {
    $report = [System.IO.File]::ReadAllText($reportPath) | ConvertFrom-Json
    Write-Host ""
    foreach ($c in $report.checks) {
        $mark = if ($c.pass) { "OK  " } else { "실패" }
        $color = if ($c.pass) { "Green" } else { "Red" }
        Write-Host ("  {0} {1,-50} {2}" -f $mark, $c.name, $c.detail) -ForegroundColor $color
    }
    # **숫자를 함께 남긴다.** "이겼다" 는 상대가 공정할 때만 뜻이 있다.
    Write-Host ""
    Write-Host "  측정값:" -ForegroundColor DarkGray
    foreach ($k in $report.facts.PSObject.Properties.Name) {
        Write-Host ("    {0,-28} {1}" -f $k, $report.facts.$k) -ForegroundColor DarkGray
    }
} else {
    Write-Bad "결과 파일을 회수하지 못했다. 게스트 종료 코드 $exit"
}

# ---------------------------------------------------------------- 뒷정리 확인

Write-Step "뒷정리 확인 — 워치독과 실험용 서비스가 남지 않았다"
$leftovers = Invoke-Command -Session $session -ScriptBlock {
    $p = @(Get-Process -Name "lab-watchdog" -ErrorAction SilentlyContinue).Count
    $s = if (Get-Service "remedy-lab-p8" -ErrorAction SilentlyContinue) { 1 } else { 0 }
    [pscustomobject]@{ procs = $p; svc = $s }
}
$clean = ($leftovers.procs -eq 0) -and ($leftovers.svc -eq 0)
if ($clean) { Write-Ok "남은 것 없음" }
else { Write-Bad ("워치독 {0}개 · 실험 서비스 {1}" -f $leftovers.procs, $leftovers.svc) }

# ---------------------------------------------------------------- 종합

Write-Host ""
Write-Host "─────────────────────────────────────────────" -ForegroundColor DarkGray
if ($report) {
    Write-Host ("게스트 검사   {0}/{1}" -f $report.passed, $report.total) `
        -ForegroundColor $(if ($report.passed -eq $report.total) { "Green" } else { "Red" })
}
Write-Host ("뒷정리        {0}" -f $(if ($clean) { "깨끗" } else { "남음" })) `
    -ForegroundColor $(if ($clean) { "Green" } else { "Red" })

Remove-PSSession $session
Write-Host "`n결과: $hostOut"

if ($exit -ne 0) { exit $exit }
if (-not $clean) { exit 1 }
exit 0
