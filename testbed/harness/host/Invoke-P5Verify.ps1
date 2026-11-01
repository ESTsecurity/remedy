<#
.SYNOPSIS
    설계-09 P5 의 판정 요건을 테스트 VM 에서 확인한다 — 격리·복원·저널.

.DESCRIPTION
    컨테이너는 **호스트에서** 만들어 VM 으로 옮긴다. 격리물을 만드는 것은
    `file.quarantine_only`(P6)의 몫이라 P5 의 제품 표면에는 없고, 그 제약이
    오히려 검증을 강하게 만든다 — 호스트의 머신 키로 감싼 wrap 이 VM 에서
    열리지 않는다는 것을 같은 컨테이너로 함께 볼 수 있다.

    P2 검증과 달리 32비트 빌드가 필요 없다. WOW64 는 수집 경로의 문제이고
    복원은 그 경로를 지나지 않는다.

.EXAMPLE
    .\Invoke-P5Verify.ps1 -Build
    .\Invoke-P5Verify.ps1 -NoRevert
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

if (-not (Test-Path $binPath)) {
    throw "빌드 산출물이 없다: $binPath`n먼저 -Build 를 줄 것."
}
$binHash = (Get-FileHash $binPath -Algorithm SHA256).Hash
Write-Ok "remedy.exe  $binHash"
Assert-StaticBinary -RepoRoot $repoRoot -Path @($binPath)

# ---------------------------------------------------------------- 픽스처

$runId   = "verify-p5-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$stage   = Join-Path ([System.IO.Path]::GetTempPath()) "remedy-p5-stage-$runId"
New-Item -ItemType Directory -Path $stage -Force | Out-Null

Write-Step "픽스처 컨테이너 생성 (호스트)"
Push-Location $repoRoot
try {
    & cargo run -q -p xtask -- fixture `
        --out (Join-Path $stage "p5.rq") `
        --dest-prefix "$LabRoot\p5" `
        --passphrase-out (Join-Path $stage "pass.txt") `
        --org-secret-out (Join-Path $stage "org.key")
    if ($LASTEXITCODE -ne 0) { throw "픽스처 생성 실패" }
} finally { Pop-Location }
Write-Ok "p5.rq · pass.txt · org.key"

# ---------------------------------------------------------------- 연결

if (-not $NoRevert) {
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
}

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential

$vmOut   = "$LabRoot\results\$runId"
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runId"
New-Item -ItemType Directory -Path $hostOut -Force | Out-Null
Write-Ok "실행 ID: $runId"

Invoke-Command -Session $session -ScriptBlock {
    param($p, $root)
    foreach ($d in @($p, "$root\bin", "$root\scripts", "$root\p5-in")) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
} -ArgumentList $vmOut, $LabRoot

# ---------------------------------------------------------------- 배포

Write-Step "배포"
$guestDir = Join-Path (Split-Path -Parent $PSScriptRoot) "guest"
Copy-GuestFile -Session $session -Source (Join-Path $guestDir "Verify-P5.ps1") `
               -Destination "$LabRoot\scripts\Verify-P5.ps1"
Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
foreach ($f in @("p5.rq", "pass.txt", "org.key")) {
    Copy-Item (Join-Path $stage $f) -Destination "$LabRoot\p5-in\$f" -ToSession $session -Force
}
Write-Ok "remedy.exe · 픽스처 3종"

# 전송된 것이 같은 것인지 확인한다. 다르면 이후 결과는 무엇에 대한 결과인지 모른다.
$remote = Invoke-Command -Session $session -ScriptBlock {
    param($root)
    @{
        bin = (Get-FileHash "$root\bin\remedy.exe" -Algorithm SHA256).Hash
        rq  = (Get-FileHash "$root\p5-in\p5.rq" -Algorithm SHA256).Hash
    }
} -ArgumentList $LabRoot
if ($remote.bin -ne $binHash) {
    throw "전송 후 바이너리 해시가 다르다: 로컬 $binHash / 원격 $($remote.bin)"
}
$rqHash = (Get-FileHash (Join-Path $stage "p5.rq") -Algorithm SHA256).Hash
if ($remote.rq -ne $rqHash) {
    throw "전송 후 컨테이너 해시가 다르다: 로컬 $rqHash / 원격 $($remote.rq)"
}
Write-Ok "해시 일치"

# ---------------------------------------------------------------- 실행

Write-Step "P5 검증 실행 (복원 — 시스템에 쓴다)"
$exit = Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Verify-P5.ps1" `
    -PassThruExitCode -Arguments @(
    "-Bin", "$LabRoot\bin\remedy.exe",
    "-Container", "$LabRoot\p5-in\p5.rq",
    "-PassphraseFile", "$LabRoot\p5-in\pass.txt",
    "-OrgKeyFile", "$LabRoot\p5-in\org.key",
    "-OutDir", $vmOut,
    "-DestPrefix", "$LabRoot\p5",
    "-StateDir", "$LabRoot\p5-state"
)

# ---------------------------------------------------------------- 회수

Write-Step "결과 회수"
Copy-Item -FromSession $session -Path "$vmOut\verify-p5.json" -Destination $hostOut -Force `
    -ErrorAction SilentlyContinue
$reportPath = Join-Path $hostOut "verify-p5.json"
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
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "`n결과: $hostOut"
exit $exit
