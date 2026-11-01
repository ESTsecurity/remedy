<#
.SYNOPSIS
    호스트에서 테스트 VM 으로 remedy 를 배포·실행하고 결과를 회수한다.

.DESCRIPTION
    순서: 사전 상태 캡처 → 픽스처 생성 → 바이너리 배포 → 실행 → 사후 상태 캡처
          → 결과 회수 → 상태 비교(불변식 P 검사).

    **모든 산출물을 먼저 VM 디스크에 쓰고 마지막에 회수한다.** 파괴적 테스트에서는
    remedy 가 원격 세션 자체를 끊어버릴 수 있다 — 결과를 연결 위에 얹어 두면
    가장 알고 싶은 실패에서 정확히 그 데이터를 잃는다.

    연결이 끊겨도 데이터는 VM 의 C:\remedy-lab\results\<run-id>\ 에 남는다.
    스냅샷을 되돌리기 전에 회수할 것.

.PARAMETER VmAddress
    테스트 VM 주소.

.PARAMETER Binary
    배포할 remedy 실행 파일. 생략하면 저장소의 릴리스 산출물을 찾는다.

.PARAMETER RemedyArgs
    remedy 에 넘길 인자. 예: @('scan','--json')

.PARAMETER Fixture
    실행 전에 만들 픽스처 시나리오. 생략하면 만들지 않는다.

.EXAMPLE
    .\Invoke-VmTest.ps1 -RemedyArgs @('selftest')
    .\Invoke-VmTest.ps1 -Fixture basic -RemedyArgs @('scan','--json')
#>
[CmdletBinding()]
param(
    [string]   $VmAddress,
    [string]   $Binary,
    [string[]] $RemedyArgs = @("selftest"),
    [ValidateSet("basic", "watchdog", "service", "hijack")]
    [string[]] $Fixture,
    [switch]   $IAcceptLoginRisk,
    [pscredential] $Credential,
    [switch]   $SaveCredential,
    [string]   $LabRoot = "C:\remedy-lab",
    [switch]   $KeepFixtures,
    # 관측 범위. 시나리오마다 봐야 할 곳이 다르므로 넘길 수 있어야 한다.
    # 생략하면 Capture-State.ps1 의 기본값을 쓴다.
    [string[]] $FilePaths,
    [int]      $MaxFiles = 0,
    # 시험 전에 스냅샷으로 되돌린다. 파괴적 시험을 반복하려면 매번 같은 지점에서
    # 출발해야 하고, 손으로 복원하면 반복이 사실상 불가능하다.
    [switch]   $Revert,
    [string]   $Snapshot,
    [string]   $Vmx,
    # 배포 전에 빌드한다. 고친 코드를 곧바로 VM 에서 확인하기 위한 것이다.
    [switch]   $Build
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))

# 연결·배포 절차와 그 진단은 공용 모듈에 있다. 복사본이 갈라지면 다음 사람이
# 같은 함정을 처음부터 다시 겪는다.
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$Vmx       = Resolve-LabValue $Vmx 'windows_lab' 'windows_lab.identity.vmx' 'Vmx'
$Snapshot  = Resolve-LabValue $Snapshot 'windows_lab' 'windows_lab.snapshots.current' 'Snapshot'

# ---------------------------------------------------------------- 빌드

if ($Build) {
    Write-Step "빌드: cargo build --release --target x86_64-pc-windows-msvc"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        # **실패하면 throw 다** — VM 에 아무것도 배포하지 않는다.
        Invoke-CargoBuild "워크스페이스" @("build", "--release", "--target", "x86_64-pc-windows-msvc")
    } finally { Pop-Location }
    Write-Ok "빌드 완료"
}

# ---------------------------------------------------------------- 바이너리

if (-not $Binary) {
    $candidates = @(
        (Join-Path $repoRoot "target\x86_64-pc-windows-msvc\release\remedy.exe"),
        (Join-Path $repoRoot "target\release\remedy.exe")
    )
    $Binary = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $Binary) {
        throw @"
remedy.exe 를 찾을 수 없다. 먼저 빌드할 것:
  cargo build --release --target x86_64-pc-windows-msvc
또는 -Binary 로 경로를 직접 지정할 것.
확인한 위치:
$($candidates -join "`n")
"@
    }
}
if (-not (Test-Path $Binary)) { throw "바이너리가 없다: $Binary" }
$binHash = (Get-FileHash $Binary -Algorithm SHA256).Hash
Write-Ok "바이너리: $Binary"
Write-Ok "SHA256: $binHash"

Assert-StaticBinary -RepoRoot $repoRoot -Path @($Binary)

# ---------------------------------------------------------------- 연결

if ($Revert) {
    # 되돌린 뒤에 시험한다. 앞선 시험이 남긴 것이 이번 결과에 섞이면 안 된다.
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
}

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential


$runId = "run-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$vmResults = "$LabRoot\results\$runId"
Write-Ok "실행 ID: $runId"

Invoke-Command -Session $session -ScriptBlock {
    param($p)
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
} -ArgumentList $vmResults

# 스냅샷 이후 스크립트가 바뀌었을 수 있다. 매번 최신본을 밀어 넣는다.
Write-Step "게스트 스크립트 동기화"
$guestDir = Join-Path (Split-Path -Parent $PSScriptRoot) "guest"
foreach ($f in @("Capture-State.ps1", "New-Fixtures.ps1")) {
    Copy-GuestFile -Session $session -Source (Join-Path $guestDir $f) `
                   -Destination "$LabRoot\scripts\$f"
}

# ---------------------------------------------------------------- 사전 캡처

# 전/후 캡처는 반드시 같은 범위여야 한다. 범위가 다르면 없는 변경이 만들어진다.
$captureExtra = @()
if ($FilePaths) { $captureExtra += @("-FilePaths", ($FilePaths -join ",")) }
if ($MaxFiles -gt 0) { $captureExtra += @("-MaxFiles", "$MaxFiles") }
if ($captureExtra.Count) { Write-Ok "관측 범위 지정: $($captureExtra -join ' ')" }

Write-Step "사전 상태 캡처"
Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Capture-State.ps1" `
    -Arguments (@("-OutFile", "$vmResults\state-before.json") + $captureExtra)

# ---------------------------------------------------------------- 픽스처

if ($Fixture) {
    Write-Step "픽스처 생성: $($Fixture -join ', ')"
    # -File 로 넘길 때 배열은 쉼표로 잇고, 스위치는 값이 아니라 존재 여부로 준다.
    $fixtureArgs = @("-Scenario", ($Fixture -join ","))
    if ($IAcceptLoginRisk) { $fixtureArgs += "-IAcceptLoginRisk" }
    Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "New-Fixtures.ps1" `
        -Arguments $fixtureArgs

    # 픽스처 생성도 시스템 변경이다. 이후 diff 가 "remedy 가 한 일"만 담도록
    # 픽스처 반영본을 기준선으로 다시 잡는다.
    Write-Step "픽스처 반영 후 기준선 재캡처"
    Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Capture-State.ps1" `
        -Arguments (@("-OutFile", "$vmResults\state-armed.json") + $captureExtra)
    Write-Ok "state-armed.json (비교 기준)"
}

# ---------------------------------------------------------------- 배포·실행

Write-Step "바이너리 배포"
Copy-Item $Binary -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
Write-Ok "$LabRoot\bin\remedy.exe"

Write-Step "실행: remedy $($RemedyArgs -join ' ')"
$runInfo = Invoke-Command -Session $session -ScriptBlock {
    param($root, $arguments, $out)
    $exe = "$root\bin\remedy.exe"

    $remoteHash = (Get-FileHash $exe -Algorithm SHA256).Hash
    $stdout = "$out\stdout.txt"
    $stderr = "$out\stderr.txt"
    $started = Get-Date

    # 결과 파일은 실행 즉시 디스크에 남는다. 연결이 끊겨도 회수 가능하다.
    #
    # Start-Process 자체가 실측 1초를 먹는다(ProcessStartInfo 는 0.03초).
    # 그래도 여기서는 이 방식을 쓴다 — 파괴적 시험에서 remedy 가 세션을 끊어도
    # 자식이 파일에 쓴 것은 남기 때문이다. 메모리로 받으면 가장 알고 싶은
    # 실패에서 정확히 그 데이터를 잃는다. **대신 duration_sec 을 성능 수치로
    # 읽지 말 것** — 성능 측정은 Verify-P2.ps1 이 따로 한다.
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
                       -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
                       -WorkingDirectory "$root\work"
    $ended = Get-Date

    [ordered]@{
        exe          = $exe
        sha256       = $remoteHash
        arguments    = @($arguments)
        exit_code    = $p.ExitCode
        started_at   = $started.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        duration_sec = [math]::Round(($ended - $started).TotalSeconds, 2)
    }
} -ArgumentList $LabRoot, $RemedyArgs, $vmResults

Write-Ok "종료 코드: $($runInfo.exit_code)  ($($runInfo.duration_sec)s)"
if ($runInfo.sha256 -ne $binHash) {
    Write-Bad "전송된 바이너리 해시가 다르다. 로컬 $binHash / 원격 $($runInfo.sha256)"
}

# 실행 메타데이터를 VM 쪽에 먼저 기록한다. 회수가 실패해도 VM 에는 남는다.
Invoke-Command -Session $session -ScriptBlock {
    param($out, $json)
    # JSON 은 BOM 없이. Out-File 은 BOM 을 붙이고 실패해도 조용하다.
    [System.IO.File]::WriteAllText("$out\run.json", $json,
                                   (New-Object System.Text.UTF8Encoding($false)))
} -ArgumentList $vmResults, ($runInfo | ConvertTo-Json -Depth 5)

# ---------------------------------------------------------------- 사후 캡처

Write-Step "사후 상태 캡처"
$captured = $false
try {
    Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Capture-State.ps1" `
        -Arguments (@("-OutFile", "$vmResults\state-after.json") + $captureExtra)
    $captured = $true
    Write-Ok "state-after.json"
} catch {
    Write-Bad "사후 캡처 실패: $($_.Exception.Message)"
    Write-Warn "VM 이 손상되었을 수 있다. 아래에서 상태를 확인할 것."
}

# ---------------------------------------------------------------- 회수

$hostResults = Join-Path $repoRoot "testbed\harness\results\$runId"
New-Item -ItemType Directory -Path $hostResults -Force | Out-Null

Write-Step "결과 회수 -> $hostResults"
$pulled = $false
try {
    Copy-Item "$vmResults\*" -Destination $hostResults -FromSession $session -Recurse -Force
    $pulled = $true
    Get-ChildItem $hostResults -File | ForEach-Object { Write-Ok $_.Name }
} catch {
    # 일괄 복사가 실패해도 포기하지 않는다. VM 이 무너지는 중이라면 한 파일이
    # 막혀서 나머지까지 잃는 것이 가장 아까운 손실이다.
    Write-Warn "일괄 회수 실패: $($_.Exception.Message)"
    Write-Warn "파일 단위로 다시 시도한다."
    $got = 0; $miss = 0
    try {
        $remote = @(Invoke-Command -Session $session -ScriptBlock {
            param($p)
            Get-ChildItem -LiteralPath $p -File -Recurse -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName
        } -ArgumentList $vmResults)

        foreach ($rf in $remote) {
            $leaf = $rf.Substring($vmResults.Length).TrimStart("\")
            $dest = Join-Path $hostResults $leaf
            $destDir = Split-Path -Parent $dest
            if ($destDir -and -not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            try {
                Copy-Item -LiteralPath $rf -Destination $dest -FromSession $session -Force
                $got++; Write-Ok $leaf
            } catch {
                $miss++; Write-Bad "$leaf : $($_.Exception.Message)"
            }
        }
        # 일부만 건졌으면 비교는 하지 않는다. 불완전한 데이터를 조용히
        # 비교하면 없는 변경을 만들거나 있는 변경을 놓친다.
        $pulled = ($got -gt 0 -and $miss -eq 0)
        Write-Warn "파일 단위 회수: 성공 $got / 실패 $miss"
    } catch {
        Write-Bad "원격 파일 목록 조회도 실패: $($_.Exception.Message)"
    }
    if (-not $pulled) {
        Write-Bad "회수 불완전. 결과는 VM 의 $vmResults 에 남아 있다. 스냅샷 복원 전에 회수할 것."
    }
}

if ($Fixture -and -not $KeepFixtures) {
    Write-Step "픽스처 정리"
    try {
        Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "New-Fixtures.ps1" `
            -Arguments @("-Remove") | Out-Null
        Write-Ok "정리 완료"
    } catch {
        Write-Warn "정리 실패: $($_.Exception.Message) — 스냅샷 복원 권장"
    }
}

Remove-PSSession $session -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- 비교

if ($pulled -and $captured) {
    $before = $(if ($Fixture) { Join-Path $hostResults "state-armed.json" }
                else          { Join-Path $hostResults "state-before.json" })
    $after  = Join-Path $hostResults "state-after.json"
    $plan   = Join-Path $hostResults "plan.json"

    $cmpArgs = @{
        Before  = $before
        After   = $after
        OutFile = (Join-Path $hostResults "diff.json")
    }
    if (Test-Path $plan) { $cmpArgs.PlanFile = $plan }
    else { Write-Warn "plan.json 이 없다 — 불변식 P 는 검사하지 않는다 (apply 는 P6 부터)" }

    & (Join-Path $PSScriptRoot "Compare-State.ps1") @cmpArgs
    $diffExit = $LASTEXITCODE
} else {
    Write-Warn "상태 비교를 건너뛴다 (캡처 또는 회수 실패)"
    $diffExit = 0
}

# ---------------------------------------------------------------- 요약

Write-Step "VM 생존 확인"
$after = Test-VmAlive $VmAddress
Write-Host "    ping=$($after.Ping)  winrm=$($after.WinRM)"
if (-not $after.WinRM) { Write-Bad "테스트 후 WinRM 응답 없음 — VM 손상 가능성" }

Write-Host "`n===== 요약 =====" -ForegroundColor Magenta
Write-Host "실행 ID     : $runId"
Write-Host "인자        : remedy $($RemedyArgs -join ' ')"
Write-Host "종료 코드   : $($runInfo.exit_code)"
Write-Host "결과(호스트): $hostResults"
Write-Host "결과(VM)    : $vmResults"
switch ($diffExit) {
    1 { Write-Host "판정        : 불변식 P 위반" -ForegroundColor Red }
    2 { Write-Host "판정        : 불변식 P 미결 — 관측을 믿을 수 없다" -ForegroundColor Yellow }
}

exit $diffExit
