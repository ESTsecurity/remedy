<#
.SYNOPSIS
    설계-09 P2 의 판정 요건을 테스트 VM 에서 확인한다.

.DESCRIPTION
    Invoke-VmTest.ps1 은 "무엇이 바뀌었는가"(불변식 P)를 보고, 이 스크립트는
    "P2 가 약속한 것이 실기기에서 성립하는가"를 본다. 목적이 다르므로 따로 둔다.

    64비트와 32비트 두 바이너리를 함께 배포한다. WOW64 검사는 32비트 빌드가
    없으면 성립하지 않고, 32비트 빌드는 이 검사 말고는 쓸 데가 없다.

    청정 코퍼스는 **픽스처를 만들기 전에** 뜬다. 그래서 -Revert 를 기본으로 켠다 —
    앞선 시험이 남긴 것이 코퍼스에 섞이면 오탐 게이트가 아무것도 보장하지 못한다.

.EXAMPLE
    .\Invoke-P2Verify.ps1 -Build
    .\Invoke-P2Verify.ps1 -Build -NoRevert -ImportCorpus
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    # 코퍼스는 픽스처 이전에 뜨므로 깨끗한 출발점이 중요하다. 끄려면 명시할 것.
    [switch] $NoRevert,
    [string] $Snapshot,
    [string] $Vmx,
    # 회수한 스냅샷을 저장소의 corpus/clean/ 으로 들인다.
    [switch] $ImportCorpus,
    [int]    $Repeat = 3,
    # 코퍼스 수집(%ProgramFiles% 4분)을 건너뛴다. 나머지 항목을 손볼 때 쓴다.
    # 건너뛴 실행은 통과 12/12 가 아니라 미결이 남은 실행이다.
    [switch] $SkipCorpus
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$Vmx       = Resolve-LabValue $Vmx 'windows_lab' 'windows_lab.identity.vmx' 'Vmx'
$Snapshot  = Resolve-LabValue $Snapshot 'windows_lab' 'windows_lab.snapshots.current' 'Snapshot'

$targets = @(
    @{ triple = "x86_64-pc-windows-msvc"; name = "remedy-x64.exe" },
    @{ triple = "i686-pc-windows-msvc";   name = "remedy-x86.exe" }
)

# ---------------------------------------------------------------- 빌드

if ($Build) {
    $installed = @(& rustup target list --installed)
    foreach ($t in $targets) {
        if ($installed -notcontains $t.triple) {
            throw @"
빌드 타깃 '$($t.triple)' 이 설치되어 있지 않다. 먼저 실행할 것:
  rustup target add $($t.triple)

32비트 빌드는 WOW64 검사에 필요하다. 없으면 그 검사는 성립하지 않는다.
"@
        }
    }
    foreach ($t in $targets) {
        Write-Step "빌드: cargo build --release --target $($t.triple)"
        Push-Location $repoRoot
        try {
            # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
            # **실패하면 throw 다** — VM 에 아무것도 배포하지 않는다.
            Invoke-CargoBuild $t.triple @("build", "--release", "--target", $t.triple)
        } finally { Pop-Location }
        Write-Ok "완료"
    }
}

# ---------------------------------------------------------------- 바이너리

foreach ($t in $targets) {
    $t.path = Join-Path $repoRoot "target\$($t.triple)\release\remedy.exe"
    if (-not (Test-Path $t.path)) {
        throw @"
$($t.triple) 빌드 산출물이 없다: $($t.path)
먼저 빌드할 것:  cargo build --release --target $($t.triple)
또는 -Build 를 줄 것.
"@
    }
    $t.hash = (Get-FileHash $t.path -Algorithm SHA256).Hash
    Write-Ok "$($t.name)  $($t.hash)"
}

Assert-StaticBinary -RepoRoot $repoRoot -Path @($targets | ForEach-Object { $_.path })

# ---------------------------------------------------------------- 연결

if (-not $NoRevert) {
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
}

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential

$runId    = "verify-p2-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$vmOut    = "$LabRoot\results\$runId"
$hostOut  = Join-Path $repoRoot "testbed\harness\results\$runId"
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
Copy-GuestFile -Session $session -Source (Join-Path $guestDir "Verify-P2.ps1") `
               -Destination "$LabRoot\scripts\Verify-P2.ps1"
Copy-GuestFile -Session $session -Source (Join-Path $guestDir "lab-plugin.yaml") `
               -Destination "$LabRoot\scripts\lab-plugin.yaml"
foreach ($t in $targets) {
    Copy-Item $t.path -Destination "$LabRoot\bin\$($t.name)" -ToSession $session -Force
    Write-Ok $t.name
}

# 전송된 바이너리가 같은 것인지 확인한다. 다르면 이후 결과는 무엇에 대한
# 결과인지 알 수 없다.
$remote = Invoke-Command -Session $session -ScriptBlock {
    param($root, $names)
    $out = @{}
    foreach ($n in $names) { $out[$n] = (Get-FileHash "$root\bin\$n" -Algorithm SHA256).Hash }
    $out
} -ArgumentList $LabRoot, @($targets | ForEach-Object { $_.name })
foreach ($t in $targets) {
    if ($remote[$t.name] -ne $t.hash) {
        throw "전송 후 해시가 다르다 ($($t.name)): 로컬 $($t.hash) / 원격 $($remote[$t.name])"
    }
}
Write-Ok "해시 일치"

# ---------------------------------------------------------------- 실행

Write-Step "P2 검증 실행 (읽기 전용)"
$guestExit = Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Verify-P2.ps1" `
    -Arguments (@("-OutDir", $vmOut, "-LabRoot", $LabRoot, "-Repeat", "$Repeat") +
                 $(if ($SkipCorpus) { @("-SkipCorpus") } else { @() })) -PassThruExitCode

# ---------------------------------------------------------------- 회수

Write-Step "결과 회수 -> $hostOut"
try {
    Copy-Item "$vmOut\verify-p2.json" -Destination $hostOut -FromSession $session -Force
    Write-Ok "verify-p2.json"
    if (-not $SkipCorpus) {
        Copy-Item "$vmOut\corpus" -Destination $hostOut -FromSession $session -Recurse -Force
        Get-ChildItem (Join-Path $hostOut "corpus") -File -ErrorAction SilentlyContinue |
            ForEach-Object { Write-Ok "corpus\$($_.Name)  $([math]::Round($_.Length/1KB,1)) KB" }
    }
} catch {
    Write-Bad "회수 실패: $($_.Exception.Message)"
    Write-Warn "결과는 VM 의 $vmOut 에 남아 있다. 스냅샷 복원 전에 회수할 것."
}

Remove-PSSession $session -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- 요약

$reportPath = Join-Path $hostOut "verify-p2.json"
if (Test-Path $reportPath) {
    $report = [System.IO.File]::ReadAllText($reportPath) | ConvertFrom-Json
    Write-Host "`n===== P2 검증 =====" -ForegroundColor Magenta
    Write-Host "호스트   : $($report.host.name) / $($report.host.os) / $($report.host.locale)"
    Write-Host "판정     : 통과 $($report.summary.pass) · 실패 $($report.summary.fail) · 미결 $($report.summary.inconclusive)"
    foreach ($c in $report.checks) {
        $color = switch ($c.status) { "pass" { "Green" } "fail" { "Red" } default { "Yellow" } }
        Write-Host ("  [{0,-12}] {1}" -f $c.status, $c.title) -ForegroundColor $color
        Write-Host ("               {0}" -f $c.detail) -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------- 코퍼스 반입

if ($ImportCorpus) {
    $src = Join-Path $hostOut "corpus"
    $dst = Join-Path $repoRoot "corpus\clean"
    if (-not (Test-Path $src)) {
        Write-Bad "회수한 코퍼스가 없다. 반입을 건너뛴다."
    } elseif ($guestExit -eq 1) {
        # 실패한 검증에서 나온 스냅샷을 청정 기준으로 들이면 안 된다.
        Write-Bad "검증이 실패했다. 코퍼스를 반입하지 않는다."
    } else {
        New-Item -ItemType Directory -Path $dst -Force | Out-Null
        $imported = 0
        Get-ChildItem $src -Filter *.json | ForEach-Object {
            # 실행마다 달라지는 식별 필드를 고정한다. 같은 기계가 같은 상태면
            # **같은 파일이 나와야 한다** — 그러지 않으면 검증을 한 번 돌릴
            # 때마다 내용이 같은 2MB 짜리 블롭이 이력에 새로 쌓인다.
            #
            # 파일의 mtime·ctime 은 건드리지 않는다. 그것은 실행이 아니라
            # 관찰이고, 룰이 조준할 수 있는 값이다. 지우면 코퍼스가 검사하는
            # 범위가 조용히 줄어든다.
            $text = [System.IO.File]::ReadAllText($_.FullName)
            foreach ($k in @("run_id", "created", "collected_at", "hostname")) {
                # 봉투 필드는 serde 의 구조체 순서상 맨 앞에 나온다. 첫 번째
                # 하나만 바꾸므로 레코드 안의 같은 이름과 섞이지 않는다.
                $rx = New-Object System.Text.RegularExpressions.Regex "`"$k`"\s*:\s*`"[^`"]*`""
                $text = $rx.Replace($text, "`"$k`": `"<코퍼스>`"", 1)
            }

            # 압축해서 들인다. 실측 12.9MB 스냅샷이 1.9MB(15%)가 된다.
            # 코퍼스는 계속 늘어날 것이므로(설계-04 §3.2) 원문 그대로는
            # 저장소가 감당하지 못한다. remedy-testkit 이 .json.gz 를 읽는다.
            $target = Join-Path $dst "$($_.Name).gz"
            $out = [System.IO.File]::Create($target)
            $gz  = New-Object System.IO.Compression.GZipStream(
                       $out, [System.IO.Compression.CompressionLevel]::Optimal)
            try {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
                $gz.Write($bytes, 0, $bytes.Length)
            } finally { $gz.Close(); $out.Close() }

            # 같은 이름의 비압축본이 남아 있으면 코퍼스에 같은 스냅샷이 두 번
            # 들어가고, 게이트가 도는 횟수만 늘 뿐 보는 범위는 그대로다.
            $stale = Join-Path $dst $_.Name
            if (Test-Path $stale) { Remove-Item $stale -Force }

            Write-Ok ("corpus/clean/{0}.gz  {1:N0} -> {2:N0} 바이트" -f `
                      $_.Name, $_.Length, (Get-Item $target).Length)
            $imported++
        }
        Write-Ok "$imported 개 반입. 확인: cargo test -p remedy-core --test corpus"
    }
}

Write-Host "`n결과(호스트): $hostOut"
Write-Host "결과(VM)    : $vmOut"
exit $guestExit
