<#
.SYNOPSIS
    P9 의 **감염 VM 실증**을 한 세션에 태운다 — G2·G3·G4 와 재감염·SafeBoot.

.DESCRIPTION
    설계-03 §10 의 게이트 정의가 이 하네스의 존재 이유다.

      G2 복원 완전성   감염 스냅샷에서 `apply` → `restore` → 원본과 비교
      G3 계획 완전성   `apply` 중 계획에 없던 Action 발생 수 = 0
      G4 치료 유효성   감염 스냅샷에서 `apply` 후 **재부팅** → `verify`

    셋 다 "**감염 스냅샷에서** `apply`" 를 요구한다. 무해한 픽스처 위에서 도는
    P6·P8 하네스로는 닿지 않고, 저장소의 `g2_roundtrip.rs` 계열이 재는 것은
    **Op 단위 왕복**(P7)이라 감염 전체 왕복과 다르다. `New-InfectedSnapshot.ps1`
    은 감염을 세우지만 코퍼스를 뜨는 것이 목적이라 끝에서 스스로 되돌린다.
    여기서는 **유지한 채** 치료를 돌린다.

    감염 구성은 `InfectedState.ps1` 이 소유한다 — 두 하네스가 같은 감염을 봐야
    하기 때문이다.

    **페이로드는 실검체가 아니라 룰에서 합성한 바이트다.** 치료 경로는 바이트
    내용과 무관하므로 검체를 VM 에 들일 이유가 없다. 실검체로 룰이 발화하는지는
    `cargo xtask yara` 가 따로 잰다(16/16).

    **게스트 스크립트를 쓰지 않는다.** G4 가 재부팅을 건너야 하는데 게스트
    스크립트 하나로는 그 경계를 넘을 수 없다. 호스트가 `Invoke-GuestExe` 로
    단계마다 remedy 를 직접 부른다.

.EXAMPLE
    .\Invoke-P9Verify.ps1 -Build
    .\Invoke-P9Verify.ps1 -NoRevert          # 스냅샷 복원 없이 (디버깅)
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [string] $Plugin,
    [switch] $Build,
    [switch] $NoRevert,
    [switch] $NoRevertAfter,
    [string] $Snapshot,
    [string] $Vmx,

    # **2026-09-02 까지 이 스위치가 사실상 필수였다.** 그 전에는 서명 없는
    # 릴리스의 `apply`·`resume` 이 종료 코드 5 로 막혔고 이 하네스는
    # `--release` 로 빌드했다. 지금은 배포될 바로 그 바이너리로 잰다.
    [switch] $DevBuild
)

$ErrorActionPreference = "Stop"


$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$Vmx       = Resolve-LabValue $Vmx 'windows_lab' 'windows_lab.identity.vmx' 'Vmx'
$Snapshot  = Resolve-LabValue $Snapshot 'windows_lab' 'windows_lab.snapshots.current' 'Snapshot'
. (Join-Path $PSScriptRoot "InfectedState.ps1")

if (-not $Plugin) { $Plugin = Join-Path $repoRoot "plugins\evilai-locust\plugin.yaml" }
if (-not (Test-Path $Plugin)) { throw "매니페스트가 없다: $Plugin" }
$rulesDir = Join-Path (Split-Path -Parent $Plugin) "rules"

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

# ---------------------------------------------------------------- 구간 계측
#
# **회차가 어디에 시간을 쓰는지 하네스가 스스로 말한다** (2026-09-13).
#
# 열아홉 중 가장 긴 회차(978초)를 줄여 보려다 알았다 — **어느 절이 얼마를
# 쓰는지 아무도 몰랐다.** 짐작으로 고르면 엉뚱한 데를 깎고, 깎은 뒤에 얼마나
# 줄었는지도 말할 수 없다. 그리고 다음 사람은 같은 측정을 처음부터 다시 한다.
#
# `Write-Step` 을 덮어써서 **부르는 자리를 하나도 고치지 않고** 구간을 나눈다.
# 절이 늘면 표도 저절로 는다.
$runSw    = [System.Diagnostics.Stopwatch]::StartNew()
$spans    = New-Object System.Collections.ArrayList
$spanName = "준비"
$spanAt   = [TimeSpan]::Zero

function Close-Span {
    if (-not $script:spanName) { return }
    [void]$script:spans.Add([pscustomobject]@{
            name    = $script:spanName
            seconds = [math]::Round(($script:runSw.Elapsed - $script:spanAt).TotalSeconds, 1)
        })
    $script:spanName = $null
}

function Write-Step {
    param($t)
    Close-Span
    $script:spanName = $t
    $script:spanAt   = $script:runSw.Elapsed
    Write-Host "`n[*] $t" -ForegroundColor Cyan
}

# ---------------------------------------------------------------- 판정 수집

$checks = New-Object System.Collections.ArrayList
function Add-Check {
    <#
        `-Skip` 은 **재지 못했다**는 뜻이고, 통과도 실패도 아니다.

        재지 못한 것을 통과로 세면 게이트가 초록인데 아무것도 보장하지 않고,
        실패로 세면 고칠 수 없는 것 때문에 진짜 회귀가 묻힌다. 셋을 가른다.
    #>
    param([string] $Name, [bool] $Pass, [string] $Detail, [switch] $Skip)
    $state = if ($Skip) { "skip" } elseif ($Pass) { "pass" } else { "fail" }
    [void]$checks.Add([pscustomobject]@{ name = $Name; state = $state; pass = $Pass; detail = $Detail })
    $mark  = switch ($state) { "pass" { "OK  " } "fail" { "실패" } default { "미실증" } }
    $color = switch ($state) { "pass" { "Green" } "fail" { "Red" } default { "Yellow" } }
    Write-Host ("  {0} {1,-44} {2}" -f $mark, $Name, $Detail) -ForegroundColor $color
}

# ---------------------------------------------------------------- 빌드·배포

if ($Build) {
    Write-Step "빌드: remedy.exe"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        # **실패하면 throw 다** — VM 에 아무것도 배포하지 않는다.
        Invoke-CargoBuild "remedy.exe" (@("build") + $cargoProfile + @("--target", $triple, "-p", "remedy-cli"))
    } finally { Pop-Location }
}
if (-not (Test-Path $binPath)) { throw "산출물이 없다: $binPath`n먼저 -Build 를 줄 것." }
Write-Ok "remedy.exe  $((Get-FileHash $binPath -Algorithm SHA256).Hash)"
Assert-StaticBinary -RepoRoot $repoRoot -Path @($binPath)

# 감염을 세운 채로 도는 하네스다. **깨끗한 자리에서 시작한다** — 앞선 실행의
# 잔여 위에서 "치료됐다" 가 나오면 그것은 우리가 지운 것이 아닐 수 있다.
if (-not $NoRevert) {
    Write-Step "스냅샷 복원 (시작 전)"
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
}

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential

$runTag   = "p9-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$vmOut    = "$LabRoot\results\$runTag"
$stateDir = "$LabRoot\state"
$hostOut  = Join-Path $repoRoot "testbed\harness\results\$runTag"
New-Item -ItemType Directory -Path $hostOut -Force | Out-Null
Write-Ok "실행 ID: $runTag"

$guestLocal = Invoke-Command -Session $session -ScriptBlock { $env:LOCALAPPDATA }
$payloadLeaf = "SystemSoftwareUpdaterV2-q5ty"
$payloadDir  = Join-Path (Join-Path $guestLocal "Programs") $payloadLeaf

Invoke-Command -Session $session -ArgumentList $vmOut, $LabRoot, $stateDir -ScriptBlock {
    param($o, $root, $st)
    foreach ($d in @($o, $st, "$root\bin", "$root\plugin", "$root\plugin\rules")) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
}

Write-Step "배포"
Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
Copy-Item $Plugin  -Destination "$LabRoot\plugin\plugin.yaml" -ToSession $session -Force
foreach ($y in (Get-ChildItem $rulesDir -Filter *.yar)) {
    Copy-Item $y.FullName -Destination "$LabRoot\plugin\rules\$($y.Name)" -ToSession $session -Force
}
Write-Ok "remedy.exe · plugin.yaml · rules"

$bin     = "$LabRoot\bin\remedy.exe"
$gPlugin = "$LabRoot\plugin\plugin.yaml"

# **물어보기 전에 이빨이 있는지부터 본다.** 파괴가 막힌 바이너리로 돌면 이
# 하네스는 검사 네 개가 따로따로 빨개지며 **서로 다른 이야기를 한다** —
# "치료가 지우지 않았다"·"계획이 수행되지 않았다"·"복원을 재지 못한다".
# 원인은 하나고 그것은 첫 줄에 있어야 한다. 2026-08-31 에 스냅샷 복원으로
# 인증서가 사라진 뒤 정확히 그렇게 다섯 줄이 빨개졌다.
#
# 2026-09-02 부터 **서명 없음은 막지 않는다.** 이 문이 남는 이유는 손댄
# 바이너리(`Untrusted`)가 여전히 같은 모양으로 무너뜨리기 때문이다.
Assert-CanDestroy -Session $session -Bin $bin
$payload = Get-SynthPayloadBytes -RulePath (Join-Path $rulesDir "evilai.yar")
Write-Ok "합성 페이로드 $($payload.Length) B (룰에서 도출 — 검체 아님)"

function Set-Infection {
    param([string] $Dir = $payloadDir)
    Set-InfectedState -Session $session -PayloadDir $Dir | Out-Null
    Set-GuestPayload  -Session $session -PayloadDir $Dir -Bytes $payload | Out-Null
}

function Read-GuestJson {
    param([string] $Path)
    $t = Invoke-Command -Session $session -ArgumentList $Path -ScriptBlock {
        param($p)
        if (Test-Path $p) { [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8) } else { $null }
    }
    if ($t) { $t | ConvertFrom-Json } else { $null }
}

try {
    # ══════════════════════════════════════════════ 사이클 A — G3 · G2
    Write-Step "사이클 A — 감염 → apply → restore  (G3 · G2)"
    Set-Infection
    $before = Get-InfectedFingerprint -Session $session -PayloadDir $payloadDir
    Add-Check "A0 감염 구성" ($before.task -and $before.file.exists) `
              "작업=$($before.task) 페이로드=$($before.file.sha256.Substring(0,12))…"

    $scanDir = "$vmOut\a-scan"
    $r = Invoke-GuestExe -Session $session -Path $bin -Arguments @(
        "scan", "--plugin", $gPlugin, "--out-dir", $scanDir)
    $plan = Read-GuestJson "$scanDir\plan.json"
    $planned = @()
    if ($plan) { $planned = @($plan.actions | ForEach-Object { "$($_.seq):$($_.op)" }) }
    Add-Check "A1 감염에서 계획이 선다" ($planned.Count -gt 0) `
              "exit=$($r.exit) Action $($planned.Count)건: $($planned -join ' ')"

    $events = "$vmOut\a-apply.ndjson"
    $r = Invoke-GuestExe -Session $session -Path $bin -Arguments @(
        "apply", "--plan", "$scanDir\plan.json", "--yes",
        "--events", $events, "--state-dir", $stateDir)
    # 실패했을 때 **왜** 인지는 출력에만 있다. 종료 코드만 남기면 다음 사람이
    # 같은 자리를 다시 재현해야 한다 — 가드 중단(exit 5)이 정확히 그랬다.
    $applyOut = ($r.out + $r.err)
    $why = if ($r.exit -in @(1, 3)) { "" } else {
        " · " + ((($applyOut -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 2) -join " ")
    }
    Add-Check "A2 apply 수행" ($r.exit -in @(1, 3)) "exit=$($r.exit)$why"

    # ── G3 — 계획에 없던 Action 이 있었는가 ──────────────────────
    $ndjson = Invoke-Command -Session $session -ArgumentList $events -ScriptBlock {
        param($p) if (Test-Path $p) { Get-Content $p -Encoding UTF8 } else { @() }
    }
    $runId = $null
    $executed = @()
    foreach ($line in $ndjson) {
        if (-not $line) { continue }
        $e = $line | ConvertFrom-Json
        if ($e.event -eq "started") { $runId = $e.run_id }
        if ($e.event -eq "action")  { $executed += "$($e.seq):$($e.op)" }
    }
    $strays = @($executed | Where-Object { $planned -notcontains $_ })
    Add-Check "G3 계획에 없던 Action 0건" ($strays.Count -eq 0 -and $executed.Count -gt 0) `
              "수행 $($executed.Count)건 / 계획 $($planned.Count)건 · 계획 밖 $($strays.Count)건 $($strays -join ' ')"

    $mid = Get-InfectedFingerprint -Session $session -PayloadDir $payloadDir
    # **예외 목록을 함께 본다.** 작업과 Run 키만 보던 동안
    # `av.restore_exclusions` 가 아무것도 하지 않았고, 이 검사는 초록이었다 —
    # 악성코드가 등록한 Defender 예외가 그대로 남았는데 `apply` 는 완전
    # 치료(1)로 끝났다 (2026-08-31 실측). 감염이 남긴 자리를 하나라도
    # 보지 않으면 그 자리는 조용히 죽어 있을 수 있다.
    $exclLeft = @($mid.excl -split ';' | Where-Object { $_ -eq $payloadDir })
    $treated = (-not $mid.task) -and (-not $mid.run_value) -and ($exclLeft.Count -eq 0)
    Add-Check "A3 치료가 실제로 지웠다" $treated `
              "작업잔존=$($mid.task) Run잔존=$([bool]$mid.run_value) 페이로드잔존=$($mid.file.exists) AV예외잔존=$($exclLeft.Count -gt 0)"

    # ── G2 — restore 가 원본을 되돌리는가 ───────────────────────
    #
    # **치료가 아무것도 지우지 않았다면 이 검사는 공허하다.** 되돌릴 것이 없으면
    # 지문은 당연히 같고, 그 초록은 복원 능력이 아니라 아무 일도 없었음을 뜻한다.
    if (-not $treated) {
        Add-Check "G2 복원 완전성 (해시·시각·소유자·권한)" $false `
                  "전제 미충족 — apply 가 지운 것이 없어 복원을 잴 수 없다" -Skip
    } else {
        $r = Invoke-GuestExe -Session $session -Path $bin -Arguments @(
            "restore", "--run", $runId, "--yes", "--state-dir", $stateDir)
        $after = Get-InfectedFingerprint -Session $session -PayloadDir $payloadDir
        $diff = Compare-InfectedFingerprint -Before $before -After $after
        Add-Check "G2 복원 완전성 (해시·시각·소유자·권한)" ($diff.Count -eq 0) `
                  $(if ($diff.Count -eq 0) { "run=$runId 지문 일치" } else { "exit=$($r.exit) 차이 $($diff.Count)건: $($diff -join ' | ')" })
    }

    # ══════════════════════════════════════════════ 사이클 B — G4 · 재감염
    Write-Step "사이클 B — 감염 → run → 재부팅 → verify  (G4 · 항목 5)"
    # restore 가 무엇을 되살렸든 여기서는 **온전한 감염**에서 시작한다.
    Clear-InfectedState -Session $session -PayloadDir $payloadDir | Out-Null
    Set-Infection

    $runDir = "$vmOut\b-run"
    $r = Invoke-GuestExe -Session $session -Path $bin -Arguments @(
        "run", "--plugin", $gPlugin, "--out-dir", $runDir, "--yes", "--state-dir", $stateDir)
    $runPlan = Read-GuestJson "$runDir\plan.json"
    $runId2 = if ($runPlan) { $runPlan.run_id } else { $null }
    Add-Check "B1 run (수집~치료)" ($r.exit -in @(1, 3)) "exit=$($r.exit) run_id=$runId2"

    Write-Step "재부팅"
    Invoke-Command -Session $session -ScriptBlock { Restart-Computer -Force } -ErrorAction SilentlyContinue
    Remove-PSSession $session -ErrorAction SilentlyContinue

    # ── 내려간 것을 먼저 보고, 그다음 올라온 것을 본다 (2026-09-13) ──
    #
    # 전에는 15초를 자고 곧바로 "살아났는가" 만 물었다. 그 15초 안에 게스트가
    # 아직 내려가지 않으면 `Test-VmAlive` 가 참을 돌려주고 **재부팅 전 OS 에
    # 붙는다.** 실측에서 정확히 그렇게 붙었다 — 세션 연결도 권한 확인도
    # 통과한 뒤, 그제야 종료가 진행돼 끊겼다.
    #
    # **시간보다 나쁜 것은 G4 다.** 그 게이트가 재는 것은 *"재부팅 후에도
    # 지속성이 살아나지 않는가"* 인데, 타이밍이 조금만 달랐다면 `verify` 가
    # 재부팅 전 기계에서 돌아 **공허하게 초록**이 된다. 재부팅을 건너뛴 G4 는
    # 아무것도 보장하지 않으면서 보장한 것처럼 보인다.
    #
    # 2026-09-11 에 `Connect-LabVmRetrying` 의 증명 간격을 5→20초로 넓힌 것도
    # 같은 병의 다른 증상이었다. 그때는 원인을 *"재부팅 직후의 흔들리는 기계"*
    # 로 봤지만, 흔들린 것이 아니라 **아직 재부팅이 시작되지도 않았다.**
    $downBy = (Get-Date).AddSeconds(180)
    $went = $false
    while ((Get-Date) -lt $downBy) {
        if (-not (Test-VmAlive $VmAddress).WinRM) { $went = $true; break }
        Start-Sleep -Seconds 2
    }
    # **내려가지 않은 것을 올라온 것으로 세지 않는다.** 여기서 그냥 넘어가면
    # 뒤따르는 판정이 전부 재부팅 전 기계를 읽는다 — 재지 못한 것이 통과가 된다.
    if (-not $went) {
        throw "재부팅을 요청하고 180초를 기다렸는데 WinRM 이 내려가지 않았다. 재부팅이 시작되지 않았다 — G4 를 잴 수 없다"
    }
    Write-Ok "내려갔다 (재부팅이 실제로 시작됐다)"

    $deadline = (Get-Date).AddSeconds(300)
    $up = $false
    while ((Get-Date) -lt $deadline) {
        if ((Test-VmAlive $VmAddress).WinRM) { $up = $true; break }
        Start-Sleep -Seconds 5
    }
    if (-not $up) { throw "재부팅 후 WinRM 이 돌아오지 않았다" }
    Start-Sleep -Seconds 5
    $session = Connect-LabVmRetrying -VmAddress $VmAddress -Credential $Credential
    Write-Ok "재부팅 완료 · 세션 재연결"

    # ── G4 — 재부팅 뒤에도 지속성이 살아나지 않는가 ─────────────
    $r = Invoke-GuestExe -Session $session -Path $bin -Arguments @(
        "verify", "--plugin", $gPlugin, "--run", $runId2, "--state-dir", $stateDir,
        "--out", "$vmOut\b-verify.json")
    $post = Get-InfectedFingerprint -Session $session -PayloadDir $payloadDir
    Add-Check "G4 치료 유효성 (재부팅 후 verify)" ($r.exit -eq 0) `
              "exit=$($r.exit) (0=치료성공) 작업잔존=$($post.task) Run잔존=$([bool]$post.run_value)"

    # ── 항목 5 — 랜덤 폴더명이 바뀐 재감염을 잡는가 ─────────────
    # **경로 확인만으로는 못 잡는 자리다.** 원래 경로는 계속 비어 있다.
    $newLeaf = "MicrosoftResourcesAgentV12-we9i6"
    $newDir  = Join-Path (Join-Path $guestLocal "Programs") $newLeaf
    Set-Infection -Dir $newDir
    $r = Invoke-GuestExe -Session $session -Path $bin -Arguments @(
        "verify", "--plugin", $gPlugin, "--run", $runId2, "--state-dir", $stateDir,
        "--out", "$vmOut\b-verify2.json")
    $oldGone = -not (Invoke-Command -Session $session -ArgumentList $payloadDir -ScriptBlock {
        param($d) Test-Path (Join-Path $d 'preload.js') })
    Add-Check "항목5 랜덤 폴더명 재감염을 verify 가 잡는다" ($r.exit -eq 2) `
              "exit=$($r.exit) (2=재발) 원래경로 비어있음=$oldGone 새경로=$newLeaf"
    Clear-InfectedState -Session $session -PayloadDir $newDir | Out-Null

    # ══════════════════════════════════════════════ 사이클 C — 재시작 제안
    Write-Step "사이클 C — 재시작 제안 (항목 4)"
    #
    # **재는 것은 판정이 아니라 그 판정이 실기기를 읽는가다.** `advise` 자체는
    # `remedy-core/src/restart.rs` 의 순수 함수이고 단위 시험이 여섯 개 있다.
    # 여기서만 잴 수 있는 것은 그 함수가 **살아 있는 레지스트리에서 읽은 값으로**
    # 불리는가, 그리고 그 결과가 사람이 보는 출력에 실제로 나오는가다.
    function Invoke-ApplyWithLockedPayload {
        param([string] $Tag)
        Clear-InfectedState -Session $session -PayloadDir $payloadDir | Out-Null
        Set-Infection
        $d = "$vmOut\c-$Tag"
        $r1 = Invoke-GuestExe -Session $session -Path $bin -Arguments @(
            "scan", "--plugin", $gPlugin, "--out-dir", $d)
        # 판정이 서지 않으면 계획이 비고, 그 위의 apply 는 아무것도 재지 않는다.
        if ($r1.exit -ne 2) {
            return [pscustomobject]@{ exit = -1; text = "scan 이 판정을 내지 못했다 (exit=$($r1.exit))" }
        }
        # ── 공유 모드가 이 시험의 전부다 ─────────────────────────
        #
        # `advise` 는 **재시작이 도움이 될 때만** 입을 연다 — `reboot_required`
        # 이거나 `failed > 0` 일 때다. 이 플러그인에는 `file.delete_on_reboot`
        # 이 없으므로 **실행 단계에서 실패 하나**를 만들어야 그 자리에 닿는다.
        #
        # `FileShare.None` 으로 열면 닿지 못한다. 그때는 **백업 단계**에서
        # 읽기가 막히고, 백업 실패는 파괴 전에 통째로 중단(exit 5)이라
        # `failed` 가 0 인 채로 끝난다 (`remedy-apply` 4단계). 2026-08-31 까지
        # 이 하네스가 그렇게 서 있었고, 그래서 C1 은 영영 미실증이었다.
        #
        # `FileShare.Read` 면 백업은 읽히고 **삭제만** 막힌다 — `remove_file`
        # 은 FILE_SHARE_DELETE 를 요구하는데 그것을 주지 않았기 때문이다.
        # 그 파일을 물고 도는 프로세스가 있는 현실적인 상황이기도 하다.
        $lock = Invoke-Command -Session $session -ArgumentList $payloadDir -ScriptBlock {
            param($dir)
            $p = Join-Path $dir 'preload.js'
            $cmd = "`$fs=[IO.File]::Open('$p','Open','Read','Read'); Start-Sleep -Seconds 180; `$fs.Close()"
            (Start-Process powershell -ArgumentList '-NoProfile', '-Command', $cmd -PassThru -WindowStyle Hidden).Id
        }
        Start-Sleep -Seconds 3
        $r2 = Invoke-GuestExe -Session $session -Path $bin -Arguments @(
            "apply", "--plan", "$d\plan.json", "--yes", "--state-dir", $stateDir)
        Invoke-Command -Session $session -ArgumentList $lock -ScriptBlock {
            param($id) Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
        [pscustomobject]@{ exit = $r2.exit; text = ($r2.out + $r2.err) }
    }

    # 손상 전에 **제안이 나오는 것**을 먼저 확인한다. 그것이 없으면 손상 뒤
    # "제안하지 않았다" 는 원래 안 하던 것일 수도 있어 아무것도 뜻하지 않는다.
    $healthy = Invoke-ApplyWithLockedPayload -Tag "healthy"
    $suggests = $healthy.text -match "안전 모드"
    $noWarn   = -not ($healthy.text -match "재시작을 권할 수 없는 상태")
    Add-Check "C1 정상 SafeBoot 에서는 안전 모드를 제안한다" `
              (($healthy.exit -eq 3) -and $suggests -and $noWarn) `
              "exit=$($healthy.exit) (3=부분실패) 제안=$suggests 경고없음=$noWarn"

    # ── SafeBoot 를 읽을 수 없게 만든다 ──────────────────────────
    #
    # **지울 수는 없다** (실측 2026-08-31). `SafeBoot`·`Minimal`·`Network` 는
    # Administrators 가 `KA`(KEY_ALL_ACCESS) 지만, 그 **하위 항목**은 소유자가
    # `NT SERVICE\TrustedInstaller` 이고 DACL 이 `D:PAI`(상속 차단)로 잠겨
    # Administrators 에게 `KR` 만 준다. `DeleteSubKeyTree` 는 모든 자손을
    # KEY_READ|KEY_WRITE 로 열어야 하므로 첫 자식에서 멈추고, .NET 은 그것을
    # *"하위 키가 없다"* 로, `reg.exe` 는 *"부분적으로 완료"* 로 옮긴다.
    # 소유권을 가져오면 되지만 자손 147개 이상을 훑어야 하고, 그 절차 자체가
    # 하네스의 새 결함이 된다.
    #
    # **`Minimal` 만 잠근다.** 그러면 판정이 `Unreadable` 이 되고, 그 값은
    # **이름은 보이는데 열리지 않는 키**가 있는 기계에서만 나온다 — 아래
    # 항목4 가 출력에서 그것을 확인하면 **판정이 실기기를 읽었다는 증거**가
    # 된다. 상수를 읽었다면 나올 수 없는 값이다.
    #
    # 2026-08-31 까지는 `partial` 을 기대했다. 그때 제품이 보던 것이
    # `key_exists` 였고 **그것은 열리지 않는 키를 없는 것으로 읽어** 잠긴
    # `Minimal` 이 "없다" 가 되고 `(없다, 있다)` 가 `Partial` 로 접혔다.
    # 같은 날 커밋 *"SafeBoot — 잠긴 것을 없는 것이라 말하지 않는다"* 가
    # `seen()` 으로 바꿔 **못 읽은 것과 없는 것을 가르면서** 값이 바뀌었다.
    # 하네스만 옛 값을 붙들고 있었다 (2026-09-02 실측에서 드러났다).
    #
    # **되돌리지 않는다.** Deny 가 READ_CONTROL 까지 막아 ACL 을 다시 읽을 수
    # 없고, WRITE_DAC 만으로 되돌리는 것도 `SetAccessControl` 이 권한 부족으로
    # 거절한다(실측). 이 하네스는 끝에서 스냅샷으로 되돌리므로 그것이 복구다.
    $sb = Invoke-Command -Session $session -ScriptBlock {
        $ErrorActionPreference = "Continue"
        $sub = 'SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal'
        $err = $null
        try {
            $h = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $sub, 'ReadWriteSubTree',
                [System.Security.AccessControl.RegistryRights]::ChangePermissions)
            $acl = $h.GetAccessControl()
            $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
                'Everyone', 'ReadKey', 'ContainerInherit', 'None', 'Deny')))
            $h.SetAccessControl($acl)
            $h.Close()
        } catch { $err = $_.Exception.Message }
        # 정말 안 보이는지 확인한다. 걸었다는 것과 가려졌다는 것은 다르다.
        $hidden = $false
        try { $hidden = $null -eq [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($sub) }
        catch { $hidden = $true }
        $net = $null -ne [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            'SYSTEM\CurrentControlSet\Control\SafeBoot\Network')
        [pscustomobject]@{ hidden = $hidden; network = $net; error = $err }
    }
    $damaged = $sb.hidden -and $sb.network
    Add-Check "C2 SafeBoot 를 읽을 수 없게 만든다 (Minimal 만)" $damaged `
              $(if ($damaged) { "Minimal 가려짐 · Network 는 보인다 → 판정은 unreadable 이어야 한다" }
                else { "Minimal가려짐=$($sb.hidden) Network보임=$($sb.network) $($sb.error)" }) `
              -Skip:(-not $damaged)

    if (-not $damaged) {
        Add-Check "항목4 손상 시 안전 모드를 제안하지 않고 보고한다" $false `
                  "전제 미충족 — SafeBoot 를 가리지 못해 이 자리를 잴 수 없다" -Skip
    } else {
        $broken    = Invoke-ApplyWithLockedPayload -Tag "broken"
        $noSuggest = -not ($broken.text -match "안전 모드에서 다시 시도")
        $reports   = $broken.text -match "재시작을 권할 수 없는 상태"
        # **`unreadable` 이 나와야 실기기를 읽은 것이다.** 상수였다면 이 값이
        # 없고, `partial`(하나가 정말 없다)과도 다른 사실이다.
        $fromLive  = $broken.text -match "진입 가능 여부: unreadable"
        Add-Check "항목4 손상 시 안전 모드를 제안하지 않고 보고한다" `
                  ($noSuggest -and $reports -and $fromLive) `
                  "exit=$($broken.exit) 제안안함=$noSuggest 손상보고=$reports 실기기값(unreadable)=$fromLive"
    }

} finally {
    # ---------------------------------------------------------- 회수·정리
    if ($session) {
        Write-Step "결과 회수"
        try {
            Copy-Item -FromSession $session -Path "$vmOut\*" -Destination $hostOut `
                      -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok $hostOut
        } catch { Write-Warn "회수 실패: $($_.Exception.Message)" }

        Write-Step "감염 잔여 정리"
        try {
            $left = Clear-InfectedState -Session $session -PayloadDir $payloadDir
            Write-Host "    폴더잔존=$($left.dir_left) 작업잔존=$($left.task_left) Run잔존=$($left.run_left)"
        } catch { Write-Warn "정리 실패: $($_.Exception.Message)" }
        Remove-PSSession $session -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- 종합

$passed  = @($checks | Where-Object { $_.state -eq "pass" }).Count
$failed  = @($checks | Where-Object { $_.state -eq "fail" }).Count
$skipped = @($checks | Where-Object { $_.state -eq "skip" }).Count
$total   = $checks.Count
$report = [pscustomobject]@{
    run      = $runTag
    plugin   = (Split-Path $Plugin -Leaf)
    payload  = "룰 합성 $($payload.Length)B (검체 아님)"
    passed   = $passed
    failed   = $failed
    skipped  = $skipped
    total    = $total
    checks   = $checks
}
$json = $report | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText((Join-Path $hostOut "verify-p9.json"), $json, `
    (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "─────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ("통과 {0} · 실패 {1} · 미실증 {2}  (전체 {3})" -f $passed, $failed, $skipped, $total) `
    -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
if ($skipped -gt 0) {
    Write-Host "  미실증은 통과가 아니다 — 무엇을 재지 못했는지 위 사유를 볼 것." -ForegroundColor Yellow
}
Write-Host "결과: $hostOut"

# **스냅샷으로 되돌린다.** 이 하네스는 감염을 세우고 SafeBoot 를 손댄다 —
# 손으로 치운 것과 처음 상태가 같다고 믿을 이유가 없다.
if (-not $NoRevertAfter) {
    Write-Step "스냅샷 복원 (끝)"
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
}

# ---------------------------------------------------------------- 어디로 갔는가
#
# **되돌리기까지 센다.** 한 바퀴(`Invoke-Sweep.ps1`)가 재는 것이 이 스크립트의
# 시작부터 끝까지라, 그보다 좁게 세면 표의 합계와 한 바퀴의 숫자가 어긋난다.
Close-Span
Write-Host ""
Write-Host "구간 — 이 회차가 시간을 쓴 자리" -ForegroundColor DarkGray
# **같은 이름은 합친다.** 재연결처럼 여러 번 도는 절이 있어서, 낱낱이 찍으면
# 표가 길어지기만 하고 정작 "어디가 비싼가" 는 덜 보인다. 횟수를 함께 적으면
# 반복 자체가 비용이라는 것도 같은 줄에서 읽힌다.
$rolled = $spans | Group-Object name | ForEach-Object {
    [pscustomobject]@{
        name    = $_.Name
        times   = $_.Count
        seconds = [math]::Round((($_.Group | Measure-Object seconds -Sum).Sum), 1)
    }
}
foreach ($s in ($rolled | Sort-Object -Property seconds -Descending)) {
    $n = if ($s.times -gt 1) { "  x$($s.times)" } else { "" }
    Write-Host ("  {0,7:N1}s  {1}{2}" -f $s.seconds, $s.name, $n)
}
Write-Host ("  {0,7:N1}s  합계" -f $runSw.Elapsed.TotalSeconds) -ForegroundColor Cyan

# 표를 다시 쓴다 — 시간은 판정이 아니지만 **회귀는 판정만큼 조용히** 온다.
# `.ToArray()` 로 넘긴다: `ArrayList` 를 그대로 주면 `ConvertTo-Json` 이
# 원소가 아니라 컬렉션의 속성을 적는다.
try {
    $report | Add-Member -NotePropertyName seconds `
        -NotePropertyValue ([math]::Round($runSw.Elapsed.TotalSeconds, 1)) -Force
    $report | Add-Member -NotePropertyName spans -NotePropertyValue $spans.ToArray() -Force
    [System.IO.File]::WriteAllText((Join-Path $hostOut "verify-p9.json"),
        ($report | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
} catch { Write-Warn "구간 기록 실패: $($_.Exception.Message)" }

if ($failed -gt 0) { exit 1 }
exit 0
