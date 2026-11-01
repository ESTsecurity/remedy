<#
.SYNOPSIS
    설계-09 P4 의 판정 요건을 테스트 VM 에서 확인한다 — subject 수집·토큰·YARA.

.DESCRIPTION
    **읽기만 한다.** P4 에는 파괴 Op 이 없다. 그래서 스냅샷 복원이 기본값이지만,
    복원하지 않고 돌려도 시스템이 바뀌지 않는다(`-NoRevert`).

    왜 개발 호스트로 충분하지 않은가: 개발 호스트에는 브라우저·프로필·인증서가
    잔뜩 있어 **수집기가 비어 있어도 티가 나지 않는다.** 갓 설치한 Windows 에서
    0건이 나오는 것과 수집기가 실패해서 0건인 것을 가르려면 실기기가 필요하다.

.EXAMPLE
    .\Invoke-P4Verify.ps1 -Build
    .\Invoke-P4Verify.ps1 -NoRevert
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
    [string] $Vmx
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$Vmx       = Resolve-LabValue $Vmx 'windows_lab' 'windows_lab.identity.vmx' 'Vmx'
$Snapshot  = Resolve-LabValue $Snapshot 'windows_lab' 'windows_lab.snapshots.current' 'Snapshot'

$triple = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"

if ($Build) {
    Write-Step "빌드: cargo build --release --target $triple"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        # **실패하면 throw 다** — VM 에 아무것도 배포하지 않는다.
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
    } finally { Pop-Location }
    Write-Ok "완료"
}
if (-not (Test-Path $binPath)) { throw "빌드 산출물이 없다: $binPath`n먼저 -Build 를 줄 것." }
$binHash = (Get-FileHash $binPath -Algorithm SHA256).Hash
Write-Ok "remedy.exe  $binHash"
Assert-StaticBinary -RepoRoot $repoRoot -Path @($binPath)

# ---------------------------------------------------------------- 연결

if (-not $NoRevert) {
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
}
$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential

$runId   = "verify-p4-" + (Get-Date -Format "yyyyMMdd-HHmmss")
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
Copy-GuestFile -Session $session -Source (Join-Path $guestDir "Verify-P4.ps1") `
               -Destination "$LabRoot\scripts\Verify-P4.ps1"
Copy-Item (Join-Path $guestDir "lab-plugin-p4.yaml") `
          -Destination "$LabRoot\scripts\lab-plugin-p4.yaml" -ToSession $session -Force
Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
Write-Ok "remedy.exe · Verify-P4.ps1 · 플러그인"

$remoteHash = Invoke-Command -Session $session -ScriptBlock {
    param($root) (Get-FileHash "$root\bin\remedy.exe" -Algorithm SHA256).Hash
} -ArgumentList $LabRoot
if ($remoteHash -ne $binHash) {
    throw "전송 후 바이너리 해시가 다르다: 로컬 $binHash / 원격 $remoteHash"
}
Write-Ok "해시 일치"

Write-Step "플러그인 린트 (VM 에 올라간 파일로)"
$lintExit = Invoke-Command -Session $session -ScriptBlock {
    param($root)
    # **stderr 를 반드시 흡수한다.** PowerShell 5.1 은 `Stop` 아래에서 네이티브
    # 명령의 stderr 한 줄 한 줄을 ErrorRecord 로 감싸 던진다 — 종료 코드가 0
    # 이어도 그렇다. remedy 는 서명 없는 바이너리에서 매 실행 알림 한 줄을
    # stderr 로 내므로(2026-09-02) 잡지 않으면 린트가 통과해도 여기서 죽는다.
    # **알림을 stdout 으로 옮길 수는 없다** — 그쪽은 기계가 읽는 산출물이다.
    $ErrorActionPreference = "Continue"
    & "$root\bin\remedy.exe" plugin lint "$root\scripts\lab-plugin-p4.yaml" 2>&1 | Out-Null
    $LASTEXITCODE
} -ArgumentList $LabRoot
if ($lintExit -ne 0) { throw "배포된 플러그인이 린트를 통과하지 못한다 (exit $lintExit)" }
Write-Ok "통과"

# ---------------------------------------------------------------- 실행

Write-Step "P4 검증 실행 (읽기 전용)"
$exit = Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Verify-P4.ps1" `
    -PassThruExitCode -Arguments @(
    "-Bin", "$LabRoot\bin\remedy.exe",
    "-Plugin", "$LabRoot\scripts\lab-plugin-p4.yaml",
    "-OutDir", $vmOut,
    "-LabRoot", $LabRoot
)

# ---------------------------------------------------------------- 회수

Write-Step "결과 회수"
foreach ($f in @("verify-p4.json", "artifacts.json")) {
    Copy-Item -FromSession $session -Path "$vmOut\$f" -Destination $hostOut -Force `
        -ErrorAction SilentlyContinue
}
$reportPath = Join-Path $hostOut "verify-p4.json"
if (Test-Path $reportPath) {
    $report = [System.IO.File]::ReadAllText($reportPath) | ConvertFrom-Json
    Write-Host ""
    foreach ($c in $report.checks) {
        $mark = if ($c.pass) { "OK  " } else { "실패" }
        $color = if ($c.pass) { "Green" } else { "Red" }
        Write-Host ("  {0} {1,-46} {2}" -f $mark, $c.name, $c.detail) -ForegroundColor $color
    }
    Write-Host ""
    Write-Host ("판정 {0}/{1}" -f $report.passed, $report.total) `
        -ForegroundColor $(if ($report.passed -eq $report.total) { "Green" } else { "Red" })
} else {
    Write-Bad "결과 파일을 회수하지 못했다. 게스트 종료 코드 $exit"
}

Remove-PSSession $session
Write-Host "`n결과: $hostOut"
exit $exit
