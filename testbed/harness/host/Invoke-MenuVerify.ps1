<#
.SYNOPSIS
    작업 메뉴를 **진짜 콘솔에서 번호를 눌러** 다섯 작업 끝까지 돌린다
    (목표 remedy_cli 기준 6).

.DESCRIPTION
    메뉴는 세 가지가 함께여야 열린다.

      1. **인자가 없다** — `main` 의 `None` 갈래
      2. **`stdin` 이 터미널이다** — 불변식 I7
      3. **내놓을 것이 있다** — 검증을 통과한 꾸러미, 되돌릴 회차, 후보 파일

    셋 가운데 2·3 이 저장소의 다른 하네스에서 한 번도 함께 선 적이 없다.
    콘솔 캡처는 `stdin` 을 닫고 부르고(2 가 거짓), 시연 게이트의 데모 폴더는
    탐색 두 자리 어느 쪽도 아니다(3 이 거짓). **그래서 메뉴 화면은 저장소
    어디에서도 측정되지 않았다.**

    여기서 그 조립을 만든다 — 임시 키쌍 -> 그 공개키를 박은 빌드 -> 서명된
    꾸러미 -> 게스트의 진짜 콘솔. 그다음 `guest\Verify-Menu.ps1` 이 번호를
    눌러 **탐지 · 치료 · 신고 · 복원 · 탐지+치료** 를 끝까지 돌린다.

    # 공유 릴리스 산출물을 앵커로 오염시키지 않는다

    다른 하네스가 전부 `target\<triple>\release\remedy.exe` 를 배포한다. 앵커가
    박힌 채로 남으면 **시연 1단계의 "사용법 다섯 줄" 이 메뉴로 바뀌고** 아무도
    이유를 모른다. 그래서 백업 -> 앵커 빌드 -> 곧바로 복구하고, 어디서 죽어도
    `finally` 가 한 번 더 되돌린다 (`Capture-Console.ps1` A8 과 같은 규율).

    # 끝에 복원 정보 폴더를 지운다 — **그것이 시연을 지키는 자리다**

    메뉴는 `%PROGRAMDATA%\remedy` 의 회차를 읽어 묶음 C 를 낸다. 이 검사가
    남긴 회차를 그대로 두면, 시연 1단계에서 사람이 데모 폴더의 `remedy.exe` 를
    인자 없이 눌렀을 때 **꾸러미가 없어도 메뉴가 열린다** (`guided::run` 의
    `found.is_empty()` 갈래). 시연은 `--state-dir .\state` 를 주므로 그 폴더를
    쓰지 않지만, **인자 없는 호출만은 기본 폴더를 본다.**

    그래서 지우고, 지운 뒤 `guest\Verify-DoubleClick.ps1` 로 **데모 폴더의
    인자 없는 화면이 진짜 콘솔에서도 사용법인지** 다시 잰다. 그것이 §3-00 의
    불변식을 라이브 시연 조건에서 재는 유일한 자리다.

.PARAMETER Prepare
    `New-DemoMachine.ps1` 을 먼저 돌려 기계를 감염 상태로 세운다. 주지 않으면
    **지금 상태 그대로** 잰다 (감염이 없으면 탐지가 0 을 내고 판정이 빨개진다).

.PARAMETER ReinfectOnly
    `-Prepare` 와 함께. 스냅샷으로 되돌리지 않고 감염만 다시 세운다 (몇 초).

.PARAMETER PhpZip
    `-Prepare` 와 함께. PHP for Windows zip 의 호스트 경로 — 10단계 점검의
    *취약* 화면을 함께 보려면 준다.

.EXAMPLE
    .\Invoke-MenuVerify.ps1 -Prepare -ReinfectOnly
    .\Invoke-MenuVerify.ps1 -Build -Prepare -PhpZip D:\dl\php-8.2.35-1-nts-Win32-vs16-x64.zip
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    [switch] $Prepare,
    [switch] $ReinfectOnly,
    [string] $PhpZip,
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

$triple  = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"
$runTag  = "menu-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runTag"
New-Item -ItemType Directory -Force $hostOut | Out-Null

# 이 흐름이 거는 것 — 판정표의 차례와 같다.
$checks = New-Object System.Collections.Generic.List[object]
function Add-Check {
    param([string] $Step, [string] $What, [bool] $Ok, [string] $Evidence)
    $checks.Add([pscustomobject]@{ Step = $Step; What = $What; Ok = $Ok; Evidence = $Evidence })
    $line = ("$Step $What").PadRight(54) + $Evidence
    if ($Ok) { Write-Ok $line }
    else { Write-Host ("    실패 " + $line) -ForegroundColor Red }
}

# ── 1. 기계 준비 ────────────────────────────────────────────────────
if ($Prepare) {
    Write-Step "시연 기계 준비 (New-DemoMachine)"
    # **해시테이블로 스플랫한다 — 배열이 아니다.** `@배열` 은 값을 **위치
    # 인자로만** 넘기므로 `@("-Vmx", $Vmx)` 의 `-Vmx` 가 이름이 아니라 값이
    # 되고, 위치가 바닥나면 *"positional parameter cannot be found"* 로 죽는다
    # (2026-10-29 에 첫 회차가 그렇게 섰다). `Invoke-DemoVerify.ps1` 이 쓰는
    # 모양이 이것이다.
    $prep = @{ VmAddress = $VmAddress; LabRoot = $LabRoot; Snapshot = $Snapshot; Vmx = $Vmx }
    if ($Build) { $prep.Build = $true }
    if ($Credential) { $prep.Credential = $Credential }
    if ($PhpZip) { $prep.PhpZip = $PhpZip }
    if ($ReinfectOnly) { $prep.ReinfectOnly = $true; $prep.NoRevert = $true }
    # **종료 코드를 보지 않는다.** `New-DemoMachine.ps1` 은 `exit` 로 끝나지
    # 않으므로 `$LASTEXITCODE` 에는 그 안에서 마지막으로 돈 네이티브 명령의 값이
    # 남는다 — 그것을 판정에 쓰면 멀쩡한 준비를 실패로 읽는다. 준비가 어긋나면
    # 그 스크립트가 `throw` 하고 `Stop` 아래에서 여기까지 올라온다.
    & (Join-Path $PSScriptRoot "New-DemoMachine.ps1") @prep
} elseif ($Build) {
    Write-Step "빌드 (release)"
    Push-Location $repoRoot
    try {
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
    } finally { Pop-Location }
}
if (-not (Test-Path $binPath)) { throw "산출물이 없다: $binPath`n -Build 를 줄 것." }

$unanchoredHash = (Get-FileHash $binPath -Algorithm SHA256).Hash

# ── 2. 서명된 꾸러미 조립 (앵커 박은 빌드) ──────────────────────────
#
# **개인키는 회차마다 새로 만들고 끝나면 버린다** (P10 과 같은 방식). 저장소에도
# 랩에도 남기지 않는다.
Write-Step "서명된 꾸러미 조립 — 임시 키 · 앵커 박은 빌드"
$gStage  = Join-Path $env:TEMP ("remedy-menu-" + (Get-Date -Format "yyyyMMddHHmmss"))
$relBak  = "$gStage\remedy-unanchored.exe"
$savedPw = $env:REMEDY_SIGN_PASSWORD
$session = $null
try {
    New-Item -ItemType Directory -Force $gStage | Out-Null
    # `sign keygen` 은 암호가 없으면 TTY 를 기다린다 — 0바이트 파일만 남아
    # 빌드 지연처럼 보인다. 그래서 반드시 준다.
    $env:REMEDY_SIGN_PASSWORD = "menu-verify-ephemeral"
    Push-Location $repoRoot
    try {
        & cargo run -q -p xtask -- sign keygen `
            --public-key "$gStage\pub.key" --secret-key "$gStage\sec.key" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "키 생성 실패" }
        # 앵커는 공개키 파일의 base64 줄이다. 첫 줄은 주석이다.
        $anchor = (Get-Content "$gStage\pub.key")[1].Trim()
        Write-Ok "임시 키쌍"

        Copy-Item $binPath $relBak -Force
        $env:REMEDY_TRUST_ANCHOR = $anchor
        try {
            Invoke-CargoBuild "앵커 박은 remedy.exe" @("build", "-q", "--release",
                "--target", $triple, "-p", "remedy-cli")
        } finally { $env:REMEDY_TRUST_ANCHOR = $null }
        Copy-Item $binPath "$gStage\remedy.exe" -Force
        # **곧바로 되돌린다.** 이 한 줄이 시연 1단계를 지킨다.
        Copy-Item $relBak $binPath -Force
        Write-Ok "앵커 박은 바이너리 (공유 산출물은 되돌렸다)"

        Copy-Item (Join-Path $repoRoot "plugins\evilai-locust") "$gStage\evilai-locust" -Recurse -Force
        & cargo run -q -p xtask -- sign plugin --dir "$gStage\evilai-locust" `
            --secret-key "$gStage\sec.key" --signed-at "2026-10-29T00:00:00Z" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "플러그인 서명 실패" }
        & cargo run -q -p xtask -- package --plugin "$gStage\evilai-locust" `
            --bin "$gStage\remedy.exe" --out "$gStage\pkg" --public-key "$gStage\pub.key" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "꾸러미 만들기 실패" }
        Write-Ok "서명 · package"
    } finally { Pop-Location }

    $nowHash = (Get-FileHash $binPath -Algorithm SHA256).Hash
    Add-Check "0" "공유 릴리스 산출물이 앵커 전과 같다" ($nowHash -eq $unanchoredHash) $nowHash.Substring(0, 12)

    # ── 3. 배포 ─────────────────────────────────────────────────────
    $session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential

    Write-Step "배포 — 꾸러미와 게스트 스크립트"
    # **폴더가 실제로 사라질 때까지 기다린다.** 앞 회차가 띄운 `remedy.exe` 가
    # 남아 있으면 `Remove-Item` 은 조용히 실패하고(`SilentlyContinue`) 곧바로
    # 이어지는 `Copy-Item` 이 *"다른 프로세스가 사용 중"* 으로 죽는다
    # (2026-10-29 실측). 지우는 것과 복사하는 것이 다른 호출이라 그 사이를
    # 확인하지 않으면 회차마다 흔들린다.
    $wipe = Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        $killed = @(Get-Process remedy -ErrorAction SilentlyContinue)
        foreach ($p in $killed) { try { $p.Kill() } catch { } }
        New-Item -ItemType Directory -Force "$lab\scripts" | Out-Null
        $until = (Get-Date).AddSeconds(20)
        while ((Get-Date) -lt $until) {
            Remove-Item "$lab\menu" -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path "$lab\menu")) { break }
            Start-Sleep -Milliseconds 500
        }
        [pscustomobject]@{ Killed = $killed.Count; Gone = (-not (Test-Path "$lab\menu")) }
    }
    if (-not $wipe.Gone) { throw "앞 회차의 꾸러미를 치우지 못했다: $LabRoot\menu (남은 remedy $($wipe.Killed)개를 끊었다)" }
    if ($wipe.Killed -gt 0) { Write-Warn "앞 회차가 띄운 remedy.exe $($wipe.Killed)개를 끊었다" }
    Copy-Item "$gStage\pkg" -Destination "$LabRoot\menu" -ToSession $session -Recurse -Force
    $guestDir = Join-Path (Split-Path -Parent $PSScriptRoot) "guest"
    foreach ($s in @("Verify-Menu.ps1", "Verify-DoubleClick.ps1")) {
        Copy-GuestFile -Session $session -Source (Join-Path $guestDir $s) `
                       -Destination "$LabRoot\scripts\$s"
    }

    # 꾸러미가 메뉴를 열 모양인지 **게스트에서** 확인한다. 여기서 틀리면
    # 뒤의 전부가 "사용법" 을 재게 된다.
    $shape = Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        [pscustomobject]@{
            Exe    = (Test-Path "$lab\menu\remedy.exe")
            Plugin = @(Get-ChildItem "$lab\menu\plugins" -Filter plugin.yaml -Recurse -ErrorAction SilentlyContinue).Count
            Root   = @(Get-ChildItem "$lab\menu" -File | Select-Object -ExpandProperty Name) -join ","
        }
    }
    Add-Check "0" "꾸러미가 탐색 두 자리 가운데 하나다" ($shape.Exe -and $shape.Plugin -ge 1) `
              "plugin.yaml $($shape.Plugin)개 · 루트 $($shape.Root)"

    # 복원 정보 폴더를 **먼저 비운다** — 앞 회차의 회차가 남아 있으면 묶음 C 의
    # 고를 거리가 둘이 되고, 그러면 하위 화면에서 `1` 을 누른 것이 무엇인지
    # 모른다.
    Write-Step "복원 정보 폴더 비우기 (앞 회차의 흔적을 빼고 센다)"
    $cleared = Invoke-Command -Session $session -ScriptBlock {
        $d = Join-Path $env:PROGRAMDATA "remedy"
        $had = @(Get-ChildItem (Join-Path $d "quarantine") -Filter *.rq -ErrorAction SilentlyContinue).Count
        # 잠긴 폴더라도 이 세션은 관리자다.
        Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
        [pscustomobject]@{ Had = $had; Gone = (-not (Test-Path $d)) }
    }
    Add-Check "0" "복원 정보 폴더가 비어 있다" $cleared.Gone "앞 회차 $($cleared.Had)건 지움"

    # ── 4. 메뉴를 실제로 눌러 본다 ──────────────────────────────────
    Write-Step "진짜 콘솔에서 메뉴 번호를 누른다 (다섯 작업)"
    $payloadDir = Invoke-Command -Session $session -ScriptBlock {
        Join-Path $env:LOCALAPPDATA "Programs\MicrosoftResourcesAgentV12-we9i6"
    }
    $rc = Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Verify-Menu.ps1" `
            -Arguments @("-Bin", "$LabRoot\menu\remedy.exe",
                         "-PayloadDir", $payloadDir,
                         "-OutFile", "$LabRoot\menu-result.json",
                         "-TranscriptFile", "$LabRoot\menu-screens.txt") -PassThruExitCode
    if ($rc -ne 0) { Write-Warn "게스트 스크립트 종료 $rc" }

    Copy-Item "$LabRoot\menu-result.json" -Destination (Join-Path $hostOut "menu-result.json") `
              -FromSession $session -Force
    Copy-Item "$LabRoot\menu-screens.txt" -Destination (Join-Path $hostOut "menu-screens.txt") `
              -FromSession $session -Force
    $r = Get-Content (Join-Path $hostOut "menu-result.json") -Raw -Encoding UTF8 | ConvertFrom-Json

    Add-Check "1" "콘솔 stdin 을 붙였다" ($r.console_rc -eq 0) "rc=$($r.console_rc)"
    # 게스트가 중간에 죽으면 **사유를 여기서 읽는다.** 그러지 않으면 호스트에
    # `NativeCommandError` 한 줄만 남고 어디서 죽었는지 모른다.
    if ($r.error) { Write-Warn "게스트 사유: $($r.error)" }
    Add-Check "1" "게스트 스크립트가 끝까지 돌았다" (-not $r.error) `
              "작업 $(@($r.steps).Count)개"
    Add-Check "1" "메뉴가 떴다" ([bool]$r.probe.shown) "줄 $($r.probe.item_count)개"
    Add-Check "1" "작성자·운영자 구분선이 있다" ([bool]$r.probe.separator) "구분선"
    Add-Check "1" "창을 붙잡는다 (더블클릭한 사람이 읽는다)" ([bool]$r.probe.held_window) "Enter 안내"
    # 결정 8(2026-10-30) — **사람이 그만둔 것은 0 이다.** 도구가 검사하지 못한
    # `NothingUsable` 은 그대로 5 이고, 치료 승인을 거절한 자리는 그대로 2 다.
    Add-Check "1" "그만두기가 0 으로 끝난다 (사람이 고르지 않았다)" ($r.probe.exit -eq 0) "exit=$($r.probe.exit)"

    foreach ($s in $r.steps) {
        $ev = "메뉴 $($s.number)번 · exit=$($s.exit) (기대 $($s.expect))"
        if ($s.timed_out) { $ev += " · 시간 초과" }
        Add-Check "2" "$($s.key) 가 메뉴에서 끝까지 돈다" ([bool]$s.ok) $ev
    }

    # 기계가 실제로 바뀌었는가 — 종료 코드만으로는 모른다.
    $treat  = $r.steps | Where-Object { $_.key -eq "치료" }
    $undo   = $r.steps | Where-Object { $_.key -eq "복원" }
    $again  = $r.steps | Where-Object { $_.key -eq "탐지+치료" }
    $detect = $r.steps | Where-Object { $_.key -eq "탐지" }
    if ($detect) {
        $same = ($detect.before.payload -eq $detect.after.payload) -and
                ($detect.before.task -eq $detect.after.task) -and
                ($detect.before.run_key -eq $detect.after.run_key)
        Add-Check "3" "탐지는 아무것도 바꾸지 않는다" $same `
                  "페이로드 $($detect.after.payload) · 작업 $($detect.after.task) · Run $($detect.after.run_key)"
    }
    if ($treat) {
        $gone = (-not $treat.after.payload) -and (-not $treat.after.task) -and (-not $treat.after.run_key)
        Add-Check "3" "치료가 감염 넷을 없앴다" $gone `
                  "페이로드 $($treat.after.payload) · 작업 $($treat.after.task) · Run $($treat.after.run_key) · 예외 $($treat.after.excl)"
    }
    if ($undo) {
        $back = $undo.after.payload -and $undo.after.task -and $undo.after.run_key
        Add-Check "3" "복원이 감염을 되살렸다 (되돌릴 수 있다는 증거)" $back `
                  "페이로드 $($undo.after.payload) · 작업 $($undo.after.task) · Run $($undo.after.run_key)"
    }
    if ($again) {
        $gone2 = (-not $again.after.payload) -and (-not $again.after.task)
        Add-Check "3" "탐지+치료가 다시 없앴다" $gone2 `
                  "페이로드 $($again.after.payload) · 작업 $($again.after.task)"
    }

    # ── 5. 시연 화면이 그대로인가 (라이브 조건) ────────────────────
    #
    # 복원 정보 폴더를 지운 **뒤에** 잰다. 지우지 않으면 데모 폴더에 꾸러미가
    # 없어도 메뉴가 열린다 — 그것이 이 검사가 잡는 회귀다.
    Write-Step "복원 정보 폴더 정리 — 시연 화면을 지킨다"
    $after = Invoke-Command -Session $session -ScriptBlock {
        $d = Join-Path $env:PROGRAMDATA "remedy"
        $runs = @(Get-ChildItem (Join-Path $d "quarantine") -Filter *.rq -ErrorAction SilentlyContinue).Count
        Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
        [pscustomobject]@{ Runs = $runs; Gone = (-not (Test-Path $d)) }
    }
    Add-Check "4" "검사가 남긴 회차를 치웠다" $after.Gone "회차 $($after.Runs)건 지움"

    $demoExe = "$LabRoot\demo\remedy.exe"
    $hasDemo = Invoke-Command -Session $session -ArgumentList $demoExe -ScriptBlock { param($p) Test-Path $p }
    if ($hasDemo) {
        Write-Step "시연 1단계 — 데모 폴더의 인자 없는 화면 (진짜 콘솔)"
        $rc2 = Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Verify-DoubleClick.ps1" `
                -Arguments @("-Bin", $demoExe, "-OutFile", "$LabRoot\demo-dblclick.json") -PassThruExitCode
        if ($rc2 -ne 0) { Write-Warn "게스트 스크립트 종료 $rc2" }
        Copy-Item "$LabRoot\demo-dblclick.json" -Destination (Join-Path $hostOut "demo-dblclick.json") `
                  -FromSession $session -Force
        $d = Get-Content (Join-Path $hostOut "demo-dblclick.json") -Raw -Encoding UTF8 | ConvertFrom-Json
        Add-Check "4" "데모 폴더는 진짜 콘솔에서도 사용법이다 (메뉴가 아니다)" `
                  ([bool]$d.no_args.usage -and $d.no_args.exit -eq 0) `
                  "사용법=$($d.no_args.usage) · exit=$($d.no_args.exit)"
        Add-Check "4" "인자가 있으면 기다리지 않는다 (RunOnce 조건)" `
                  ([bool]$d.with_args.finished_without_input) "exit=$($d.with_args.exit)"
    } else {
        Write-Warn "데모 폴더가 없어 시연 1단계는 재지 않았다 (-Prepare 를 줄 것)"
    }

    # ── 6. 랩에 남기지 않는다 ───────────────────────────────────────
    Write-Step "꾸러미 치우기"
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        Remove-Item "$lab\menu" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$lab\menu-result.json", "$lab\menu-screens.txt", "$lab\demo-dblclick.json" `
                    -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "서명된 꾸러미를 랩에 남기지 않았다"
} finally {
    # **어디서 죽어도 공유 산출물은 되돌린다.**
    if (Test-Path $relBak) { Copy-Item $relBak $binPath -Force }
    $env:REMEDY_TRUST_ANCHOR = $null
    $env:REMEDY_SIGN_PASSWORD = $savedPw
    Remove-Item $gStage -Recurse -Force -ErrorAction SilentlyContinue
    if ($session) { Remove-PSSession $session }
}

# ── 판정 ────────────────────────────────────────────────────────────
$pass = @($checks | Where-Object { $_.Ok }).Count
$fail = @($checks | Where-Object { -not $_.Ok }).Count
Write-Host ""
Write-Host "판정 $pass/$($checks.Count) · 실패 $fail" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
$checks | Export-Csv -Path (Join-Path $hostOut "checks.csv") -NoTypeInformation -Encoding UTF8
Write-Host "결과: $hostOut"
Write-Host "화면: $(Join-Path $hostOut 'menu-screens.txt')"
if ($fail -ne 0) { exit 1 }
exit 0
