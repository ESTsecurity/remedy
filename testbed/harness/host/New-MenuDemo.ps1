<#
.SYNOPSIS
    **메뉴 기반 시연 환경**을 Win10x64-Test VM 에 세운다 (Windows 전용).

.DESCRIPTION
    `New-DemoMachine.ps1` 은 **명령줄 시연**을 위한 기계를 만든다 — 데모 폴더의
    `remedy.exe` 는 옆에 꾸러미를 두지 않으므로 인자 없이 띄우면 사용법이다.

    메뉴로 시연하려면 세 가지가 함께여야 한다(목표 `remedy_cli` §3-00).

      1. 인자가 없다
      2. `stdin` 이 터미널이다 — 사람이 직접 띄우면 참이다
      3. **검증을 통과한 꾸러미가 실행 파일 옆에 있다**

    3 이 조립을 요구한다: 임시 키쌍 -> 그 공개키를 박은 빌드 -> 서명된 룰.
    이 스크립트가 그것을 만들어 게스트에 **남긴다**(`Invoke-MenuVerify.ps1` 은
    재고 나서 지운다 — 시연은 남아 있어야 한다).

    # 룰 셋 셋을 담는다

    메뉴의 첫 질문은 "어느 룰 묶음입니까" 다 — `discover::beside` 가
    `<exe>\plugins\<이름>\plugin.yaml` 을 **여럿** 찾고 `guided::choose` 가
    번호로 고르게 한다. 그래서 시연 두 장면이 한 폴더에 든다.

      evilai-locust       악성코드 탐지·치료·복원
      php2shell-check     PHP 취약 판 점검 (고치지 않는다 — 판을 올리는 것은 공급사의 일)
      php2shell-aftermath PHP 사고의 사후 처리 탐지·치료·복원 (웹셸 · 심은 줄)

    # 공유 릴리스 산출물은 되돌린다

    앵커가 박힌 채로 남으면 **명령줄 시연 1단계의 "사용법 다섯 줄" 이 메뉴로
    바뀐다.** 백업 -> 앵커 빌드 -> 곧바로 복구하고, 어디서 죽어도 `finally` 가
    한 번 더 되돌린다 (`Capture-Console.ps1` A8 과 같은 규율).

.PARAMETER PhpZip
    주면 게스트의 `C:\php` 에 풀어 PHP 점검 장면이 선다. 이미 깔려 있으면
    주지 않아도 된다 — 이 스크립트는 스냅샷으로 되돌리지 않는다.

.EXAMPLE
    .\New-MenuDemo.ps1 -Build
    .\New-MenuDemo.ps1 -Build -PhpZip D:\dl\php-8.2.35-1-nts-Win32-vs16-x64.zip
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [string] $LabRoot = "C:\remedy-lab",
    [string] $DemoDir = "C:\remedy-lab\menu-demo",
    [switch] $Build,
    [switch] $SkipInfect,
    [string] $PhpZip
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'

$triple  = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"

# ── 1. 감염과 PHP — `New-DemoMachine` 이 소유한다 ───────────────────
#
# 되돌리지 않는다(`-NoRevert`). 되돌리면 PHP 가 사라진다 — 랩 스냅샷에 없다.
if (-not $SkipInfect) {
    Write-Step "감염 · PHP (New-DemoMachine -ReinfectOnly -NoRevert)"
    $prep = @{ VmAddress = $VmAddress; LabRoot = $LabRoot; ReinfectOnly = $true; NoRevert = $true }
    if ($Credential) { $prep.Credential = $Credential }
    if ($PhpZip) { $prep.PhpZip = $PhpZip }
    & (Join-Path $PSScriptRoot "New-DemoMachine.ps1") @prep | Out-Null
    Write-Ok "감염된 기계"
}

if ($Build) {
    Write-Step "빌드 (release)"
    Push-Location $repoRoot
    try {
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
    } finally { Pop-Location }
}
if (-not (Test-Path $binPath)) { throw "산출물이 없다: $binPath`n -Build 를 줄 것." }
$unanchoredHash = (Get-FileHash $binPath -Algorithm SHA256).Hash

# ── 2. 서명된 꾸러미 조립 ───────────────────────────────────────────
Write-Step "서명된 꾸러미 조립 — 임시 키 · 앵커 박은 빌드 · 룰 3벌"
$stage   = Join-Path $env:TEMP ("remedy-menudemo-" + (Get-Date -Format "yyyyMMddHHmmss"))
$relBak  = "$stage\remedy-unanchored.exe"
$savedPw = $env:REMEDY_SIGN_PASSWORD
$session = $null
try {
    New-Item -ItemType Directory -Force "$stage\pkg\plugins" | Out-Null
    # `sign keygen` 은 암호가 없으면 TTY 를 기다린다 — 0바이트 파일만 남는다.
    $env:REMEDY_SIGN_PASSWORD = "menu-demo-ephemeral"
    Push-Location $repoRoot
    try {
        & cargo run -q -p xtask -- sign keygen `
            --public-key "$stage\pub.key" --secret-key "$stage\sec.key" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "키 생성 실패" }
        $anchor = (Get-Content "$stage\pub.key")[1].Trim()
        Write-Ok "임시 키쌍"

        Copy-Item $binPath $relBak -Force
        $env:REMEDY_TRUST_ANCHOR = $anchor
        try {
            Invoke-CargoBuild "앵커 박은 remedy.exe" @("build", "-q", "--release",
                "--target", $triple, "-p", "remedy-cli")
        } finally { $env:REMEDY_TRUST_ANCHOR = $null }
        Copy-Item $binPath "$stage\pkg\remedy.exe" -Force
        Copy-Item $relBak $binPath -Force      # **곧바로 되돌린다**
        $nowHash = (Get-FileHash $binPath -Algorithm SHA256).Hash
        if ($nowHash -ne $unanchoredHash) { throw "공유 산출물이 앵커 빌드로 오염됐다" }
        Write-Ok "앵커 박은 바이너리 (공유 산출물 해시 그대로: $($nowHash.Substring(0,12)))"

        # 룰 셋 셋을 같은 모양으로 둔다 — 폴더 하나에 `plugin.yaml` 하나.
        $php = Join-Path $repoRoot "testbed\demo\php2shell"
        Copy-Item (Join-Path $repoRoot "plugins\evilai-locust") "$stage\pkg\plugins\evilai-locust" -Recurse -Force
        New-Item -ItemType Directory -Force "$stage\pkg\plugins\php2shell-check" | Out-Null
        New-Item -ItemType Directory -Force "$stage\pkg\plugins\php2shell-aftermath" | Out-Null
        Copy-Item (Join-Path $php "check-windows.yaml") "$stage\pkg\plugins\php2shell-check\plugin.yaml" -Force
        Copy-Item (Join-Path $php "aftermath.yaml") "$stage\pkg\plugins\php2shell-aftermath\plugin.yaml" -Force

        foreach ($d in @("evilai-locust", "php2shell-check", "php2shell-aftermath")) {
            & cargo run -q -p xtask -- sign plugin --dir "$stage\pkg\plugins\$d" `
                --secret-key "$stage\sec.key" --signed-at "2026-10-29T00:00:00Z" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "플러그인 서명 실패: $d" }
            Write-Ok "서명 $d"
        }
    } finally { Pop-Location }

    # 꾸러미가 스스로 서는지 **호스트에서** 먼저 본다. 틀리면 게스트에서
    # "검증할 수 없습니다" 만 보게 된다.
    # **PS 5.1 은 네이티브 stderr 한 줄을 ErrorRecord 로 감싼다.** 이 빌드는
    # 서명이 없어 *"이 바이너리에 서명이 없습니다"* 를 stderr 로 내므로, 그
    # 한 줄만으로 `Stop` 아래에서 여기가 죽는다 (2026-10-29 실측 — 저장소가
    # `Invoke-CargoBuild` 머리에 이미 적어 둔 함정이다). 판정은 종료 코드다.
    foreach ($d in @("evilai-locust", "php2shell-check", "php2shell-aftermath")) {
        $vExit = & {
            $ErrorActionPreference = "Continue"
            & "$stage\pkg\remedy.exe" plugin verify --dir "$stage\pkg\plugins\$d" 2>&1 | Out-Null
            $LASTEXITCODE
        }
        if ($vExit -ne 0) { throw "서명 검증 실패: $d (exit $vExit)" }
    }
    Write-Ok "앵커가 룰 3벌의 서명을 확인한다 (plugin verify 0)"

    # ── 3. 배포 ─────────────────────────────────────────────────────
    $session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential
    Write-Step "배포 — $DemoDir"
    $wipe = Invoke-Command -Session $session -ArgumentList $DemoDir -ScriptBlock {
        param($d)
        $killed = @(Get-Process remedy -ErrorAction SilentlyContinue)
        foreach ($p in $killed) { try { $p.Kill() } catch { } }
        $until = (Get-Date).AddSeconds(20)
        while ((Get-Date) -lt $until) {
            Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $d)) { break }
            Start-Sleep -Milliseconds 500
        }
        # **복원 정보 폴더도 비운다** — 앞 회차의 회차가 메뉴에 섞이면 시연에서
        # 고를 거리가 둘이 되고, 어느 것이 방금 만든 것인지 알 수 없다.
        Remove-Item (Join-Path $env:PROGRAMDATA "remedy") -Recurse -Force -ErrorAction SilentlyContinue
        [pscustomobject]@{ Killed = $killed.Count; Gone = (-not (Test-Path $d)) }
    }
    if (-not $wipe.Gone) { throw "앞 회차의 폴더를 치우지 못했다: $DemoDir" }
    Copy-Item "$stage\pkg" -Destination $DemoDir -ToSession $session -Recurse -Force

    $state = Invoke-Command -Session $session -ArgumentList $DemoDir -ScriptBlock {
        param($d)
        $pd = Join-Path $env:LOCALAPPDATA "Programs\MicrosoftResourcesAgentV12-we9i6"
        [pscustomobject]@{
            Exe     = (Test-Path "$d\remedy.exe")
            Rules   = @(Get-ChildItem "$d\plugins" -Filter plugin.yaml -Recurse).Count
            Php     = (Get-Item 'C:\php\php.exe' -ErrorAction SilentlyContinue).VersionInfo.FileVersion
            Payload = (Test-Path (Join-Path $pd 'preload.js'))
            Task    = ($null -ne (Get-ScheduledTask -TaskName Locust -TaskPath '\Microsoft\Windows\' -ErrorAction SilentlyContinue))
            Shell   = (Test-Path 'C:\inetpub\wwwroot\uploads\invoice-9f2.php')
            AppSize = (Get-Item 'C:\inetpub\wwwroot\app\index.php' -ErrorAction SilentlyContinue).Length
            Runs    = @(Get-ChildItem (Join-Path (Join-Path $env:PROGRAMDATA 'remedy') 'quarantine') -Filter *.rq -ErrorAction SilentlyContinue).Count
        }
    }
    Write-Ok "remedy.exe=$($state.Exe) · 룰 $($state.Rules)벌 · PHP '$($state.Php)'"
    Write-Ok "감염: 페이로드=$($state.Payload) 예약작업=$($state.Task) · 웹셸=$($state.Shell) index.php=$($state.AppSize)B"
    Write-Ok "되돌릴 회차 $($state.Runs)건 (0 이어야 한다 — 시연에서 만든다)"

    if (-not $state.Exe -or $state.Rules -ne 3) { throw "배포가 어긋났다 — 룰 $($state.Rules)벌" }
    if (-not $SkipInfect -and -not $state.Payload) { throw "감염이 서지 않았다" }

    Write-Host ""
    Write-Host "메뉴 시연 환경 준비 완료." -ForegroundColor Green
    Write-Host ""
    Write-Host "  게스트에서 (관리자 PowerShell 창을 직접 띄워야 한다 — 터미널이어야 메뉴가 열린다):"
    Write-Host "    cd $DemoDir"
    Write-Host "    .\remedy.exe"
    Write-Host ""
    # **룰 번호는 이름순이다** (`guided::choose` — 같은 꾸러미에서 늘 같은
    # 번호가 나와야 사람이 고른 번호가 뜻을 갖는다). 그래서 매니페스트 제목의
    # 가나다순이고, 폴더 이름순이 아니다 — 2026-10-29 에 진짜 콘솔로 확인했다.
    Write-Host "  1장 악성코드   룰 1 'EvilAI(Locust) 제거'        -> 2 검사만 -> 1 검사하고 치료 -> 6 되돌리기"
    Write-Host "  2장 PHP 취약   룰 3 'PHP2Shell 점검'             -> 2 검사만   (고치지 않는다 — 판을 올리는 것은 공급사의 일)"
    Write-Host "  3장 PHP 사후   룰 2 'PHP2Shell 사후 처리'        -> 1 검사하고 치료 -> 6 되돌리기"
    Write-Host ""
    Write-Host "  되돌리기(6)는 치료한 뒤에만 뜬다 — 회차가 생겨야 묶음 C 세 줄이 선다." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  명령줄 시연은 그대로다: $LabRoot\demo (그 폴더는 메뉴가 열리지 않는다)" -ForegroundColor DarkGray
} finally {
    if (Test-Path $relBak) { Copy-Item $relBak $binPath -Force }
    $env:REMEDY_TRUST_ANCHOR = $null
    $env:REMEDY_SIGN_PASSWORD = $savedPw
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    if ($session) { Remove-PSSession $session }
}
exit 0
