<#
.SYNOPSIS
    설계-09 P6 의 판정 요건을 테스트 VM 에서 확인한다 — 실행기·승인·뮤텍스·재기동.

.DESCRIPTION
    **파괴적이다.** VM 의 `C:\remedy-lab` 안에서만 돌지만 실제로 파일을 지운다.
    스냅샷을 되돌린 뒤 도는 것이 기본값이다.

    P5 검증과 달리 컨테이너를 호스트에서 만들어 오지 않는다. 격리물을 만드는
    것이 `file.quarantine_only`(P6)의 몫이고, 그것을 재는 것이 이 검증이다.

    G3(불변식 P) 판정만 호스트에서 한다. `Compare-State.ps1` 은 remedy 를 전혀
    쓰지 않는데, **검증자가 피검증자를 신뢰하면 검증이 아니기 때문이다.**

.EXAMPLE
    .\Invoke-P6Verify.ps1 -Build
    .\Invoke-P6Verify.ps1 -NoRevert
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
    # 코드 5 로 막았고, 이 하네스는 `--release` 로 빌드하므로 파괴 검사가 전부
    # 5 로 깨졌다. 지금은 서명 없음이 파괴를 막지 않으므로 **배포될 바로 그
    # 바이너리로 잰다.** 이 스위치는 디버그 빌드를 재고 싶을 때만 쓴다.
    [switch] $DevBuild
)

$ErrorActionPreference = "Stop"


$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$Vmx       = Resolve-LabValue $Vmx 'windows_lab' 'windows_lab.identity.vmx' 'Vmx'
$Snapshot  = Resolve-LabValue $Snapshot 'windows_lab' 'windows_lab.snapshots.current' 'Snapshot'

$triple = "x86_64-pc-windows-msvc"
# 개발 빌드는 `target\<triple>\debug\` 에 선다.
$profile_ = if ($DevBuild) { "debug" } else { "release" }
# **`[string[]]` 가 필요하다.** PowerShell 은 `if` 가 돌려주는 단일 원소 배열을
# 스칼라로 푼다 — 그러면 `$cargoProfile` 이 문자열이 되고 `@cargoProfile` 이
# 그것을 문자 단위로 쪼개 `cargo` 가 `-` 하나를 받는다 (실측 2026-08-29).
#
# `-DevBuild` 로만 돌리는 동안에는 빈 배열이라 드러나지 않았다.
[string[]] $cargoProfile = if ($DevBuild) { @() } else { @("--release") }
$binPath = Join-Path $repoRoot "target\$triple\$profile_\remedy.exe"

if ($Build) {
    Write-Step "빌드: cargo build $($cargoProfile -join ' ') --target $triple ($profile_)"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        # **실패하면 throw 다** — VM 에 아무것도 배포하지 않는다.
        Invoke-CargoBuild "remedy.exe" (@("build") + $cargoProfile + @("--target", $triple, "-p", "remedy-cli"))
    } finally { Pop-Location }
    Write-Ok "완료"
}

if (-not (Test-Path $binPath)) {
    throw "빌드 산출물이 없다: $binPath`n먼저 -Build 를 줄 것."
}
$binHash = (Get-FileHash $binPath -Algorithm SHA256).Hash
Write-Ok "remedy.exe  $binHash"

# 설계-09 P6 검증 항목: "remedy-apply 바이너리에 네트워크 심볼이 링크되지 않는다".
# **VM 은 이것을 알려주지 못한다** — 소켓을 열지 않는 실행을 아무리 관찰해도
# 열 수 없다는 것은 증명되지 않는다. 임포트 테이블을 직접 보는 수밖에 없다.
Write-Step "정적 링크·네트워크 심볼 검사 (설계-09 P6)"
Assert-StaticBinary -RepoRoot $repoRoot -Path @($binPath)
$staticOk = $true

# ---------------------------------------------------------------- 연결

if (-not $NoRevert) {
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
}

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential

$runId   = "verify-p6-" + (Get-Date -Format "yyyyMMdd-HHmmss")
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
foreach ($s in @("Verify-P6.ps1", "Approve-Interactive.ps1", "Capture-State.ps1")) {
    Copy-GuestFile -Session $session -Source (Join-Path $guestDir $s) `
                   -Destination "$LabRoot\scripts\$s"
}
Copy-Item (Join-Path $guestDir "lab-plugin-p6.yaml") `
          -Destination "$LabRoot\scripts\lab-plugin-p6.yaml" -ToSession $session -Force
Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
Write-Ok "remedy.exe · 게스트 스크립트 3종 · 플러그인"

# 전송된 것이 같은 것인지 확인한다. 다르면 이후 결과는 무엇에 대한 결과인지 모른다.
$remoteHash = Invoke-Command -Session $session -ScriptBlock {
    param($root) (Get-FileHash "$root\bin\remedy.exe" -Algorithm SHA256).Hash
} -ArgumentList $LabRoot
if ($remoteHash -ne $binHash) {
    throw "전송 후 바이너리 해시가 다르다: 로컬 $binHash / 원격 $remoteHash"
}
Write-Ok "해시 일치"

Assert-CanDestroy -Session $session -Bin (Join-Path (Join-Path $LabRoot "bin") "remedy.exe")

# 플러그인이 성립하는지 **VM 에 닿기 전에** 보지 않고, 배포한 것으로 본다.
# 린트는 작성자의 손에서 도는 명령이지만, 여기서 한 번 더 보는 이유는 배포된
# 파일이 편집기의 인코딩 때문에 달라졌을 수 있어서다.
Write-Step "플러그인 린트 (VM 에 올라간 파일로)"
$lintExit = Invoke-Command -Session $session -ScriptBlock {
    param($root)
    # **PS 5.1 은 네이티브 stderr 한 줄을 ErrorRecord 로 감싼다.** 개발 빌드는
    # "개발 빌드다 — 서명이 없고 …" 를 stderr 로 내므로, 그것만으로 여기가
    # NativeCommandError 를 던져 하네스가 멈춘다. 판정 기준은 종료 코드다.
    $ErrorActionPreference = "Continue"
    & "$root\bin\remedy.exe" plugin lint "$root\scripts\lab-plugin-p6.yaml" 2>&1 | Out-Null
    $LASTEXITCODE
} -ArgumentList $LabRoot
if ($lintExit -ne 0) { throw "배포된 플러그인이 린트를 통과하지 못한다 (exit $lintExit)" }
Write-Ok "통과"

# ---------------------------------------------------------------- 실행

Write-Step "P6 검증 실행 (**파괴적** — 실제로 파일을 지운다)"
$exit = Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Verify-P6.ps1" `
    -PassThruExitCode -Arguments @(
    "-Bin", "$LabRoot\bin\remedy.exe",
    "-Plugin", "$LabRoot\scripts\lab-plugin-p6.yaml",
    "-OutDir", $vmOut,
    "-LabRoot", $LabRoot
)

# ---------------------------------------------------------------- 회수

Write-Step "결과 회수"
foreach ($f in @("verify-p6.json", "g3\state-armed.json", "g3\state-after.json", "g3\plan.json")) {
    $dest = Join-Path $hostOut (Split-Path -Leaf $f)
    Copy-Item -FromSession $session -Path "$vmOut\$f" -Destination $dest -Force `
        -ErrorAction SilentlyContinue
}

$reportPath = Join-Path $hostOut "verify-p6.json"
$report = $null
if (Test-Path $reportPath) {
    $report = [System.IO.File]::ReadAllText($reportPath) | ConvertFrom-Json
    Write-Host ""
    foreach ($c in $report.checks) {
        $mark = if ($c.pass) { "OK  " } else { "실패" }
        $color = if ($c.pass) { "Green" } else { "Red" }
        Write-Host ("  {0} {1,-52} {2}" -f $mark, $c.name, $c.detail) -ForegroundColor $color
    }
} else {
    Write-Bad "결과 파일을 회수하지 못했다. 게스트 종료 코드 $exit"
}

# ---------------------------------------------------------------- G3 판정

Write-Step "G3 — 불변식 P 대조 (계획에 없는 변경이 실제로 있었는가)"
$armed = Join-Path $hostOut "state-armed.json"
$after = Join-Path $hostOut "state-after.json"
$plan  = Join-Path $hostOut "plan.json"
$g3 = "미결"
$g3Exit = 2
if ((Test-Path $armed) -and (Test-Path $after) -and (Test-Path $plan)) {
    & (Join-Path $PSScriptRoot "Compare-State.ps1") -Before $armed -After $after `
        -PlanFile $plan -OutFile (Join-Path $hostOut "diff-g3.json")
    $g3Exit = $LASTEXITCODE
    $g3 = switch ($g3Exit) { 0 { "통과" } 1 { "위반" } default { "미결" } }
} else {
    Write-Bad "대조 재료가 없다 — G3 를 판정할 수 없다"
}

# ---------------------------------------------------------------- 종합

Write-Host ""
Write-Host "─────────────────────────────────────────────" -ForegroundColor DarkGray
if ($report) {
    Write-Host ("게스트 검사   {0}/{1}" -f $report.passed, $report.total) `
        -ForegroundColor $(if ($report.passed -eq $report.total) { "Green" } else { "Red" })
}
Write-Host ("네트워크 심볼 {0}" -f $(if ($staticOk) { "없음 (호스트에서 임포트 테이블 확인)" } else { "확인 실패" })) `
    -ForegroundColor $(if ($staticOk) { "Green" } else { "Red" })
Write-Host ("G3 불변식 P   {0}" -f $g3) `
    -ForegroundColor $(if ($g3Exit -eq 0) { "Green" } elseif ($g3Exit -eq 1) { "Red" } else { "Yellow" })

Remove-PSSession $session
Write-Host "`n결과: $hostOut"

# **미결을 통과로 세지 않는다.** 관측을 믿을 수 없는 판정은 통과가 아니다.
if ($exit -ne 0) { exit $exit }
if ($g3Exit -ne 0) { exit $g3Exit }
exit 0
