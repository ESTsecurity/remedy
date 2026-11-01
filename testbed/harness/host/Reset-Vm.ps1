<#
.SYNOPSIS
    테스트 VM 을 스냅샷으로 되돌리고 WinRM 이 응답할 때까지 기다린다.

.DESCRIPTION
    파괴적 테스트는 VM 을 못 쓰게 만드는 것이 정상이다. 매 시험을 같은 지점에서
    출발시키지 못하면 결과를 비교할 수 없고, 손으로 복원하면 반복 시험이 사실상
    불가능하다. 이 스크립트가 그 사이를 메운다.

    복원 대상을 **이름으로** 찾는데, 이름이 중복된 스냅샷이 있으면 어디로 갈지
    알 수 없다. 그런 경우 되돌리지 않고 멈춘다 — 엉뚱한 지점으로 되돌아가면
    준비 작업을 통째로 다시 해야 한다.

.PARAMETER Snapshot
    복원할 스냅샷 이름. 정확히 하나만 일치해야 한다.

.PARAMETER TimeoutSec
    복원 후 WinRM 이 응답하기를 기다리는 최대 시간.

.EXAMPLE
    .\Reset-Vm.ps1
    .\Reset-Vm.ps1 -Snapshot 'remedy-lab-base-v3' -TimeoutSec 300
#>
[CmdletBinding()]
param(
    [string] $Vmx,
    # 공백·괄호 없는 이름을 쓴다. 스크립트 인자로 오가는 값이라 다루기 쉬운 편이 낫다.
    # **v3 (2026-09-11)** — v2 에 자동 갱신 끄기를 더한 지점이다. Windows
    # Update·Chrome·Edge 갱신기가 회차 도중에 움직여 채점 5 를 불합격시키고
    # 코퍼스 수집을 120초 늘렸다(README 의 'P2 는 왜 11분인가'). **Defender 는
    # 그대로 켜 둔다** — 끄면 시연·오탐 측정이 실제 PC 와 다른 것이 된다.
    #
    # v2 는 지우지 않았다. 되돌아갈 자리가 필요하면 `-Snapshot` 으로 준다.
    # 그 앞의 'remedy-lab-base (WinRM+baseline, Defender ON)' 에는 fork bomb 판
    # New-Fixtures.ps1 이 들어 있어 콘솔에서 직접 실행하면 터진다.
    [string] $Snapshot,
    [string] $VmAddress,
    [string] $VmRun,
    [string] $LabRoot = "C:\remedy-lab",
    [int]    $TimeoutSec = 240
)

$ErrorActionPreference = "Stop"

# 랩 값은 `.cargo/windows_lab.yml` 에서 읽는다 — 공용 함수가 거기 있다.
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$Vmx       = Resolve-LabValue $Vmx 'windows_lab' 'windows_lab.identity.vmx' 'Vmx'
$Snapshot  = Resolve-LabValue $Snapshot 'windows_lab' 'windows_lab.snapshots.current' 'Snapshot'

function Write-Step { param($t) Write-Host "`n[*] $t" -ForegroundColor Cyan }
function Write-Ok   { param($t) Write-Host "    OK   $t" -ForegroundColor Green }
function Write-Warn { param($t) Write-Host "    주의 $t" -ForegroundColor Yellow }

# ---------------------------------------------------------------- vmrun

if (-not $VmRun) {
    $candidates = @(
        "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
        "C:\Program Files\VMware\VMware Workstation\vmrun.exe",
        "C:\Program Files (x86)\VMware\VMware VIX\vmrun.exe"
    )
    $VmRun = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $VmRun) {
        $cmd = Get-Command vmrun -ErrorAction SilentlyContinue
        if ($cmd) { $VmRun = $cmd.Source }
    }
}
if (-not $VmRun -or -not (Test-Path $VmRun)) {
    throw "vmrun.exe 를 찾을 수 없다. -VmRun 으로 경로를 지정할 것."
}
if (-not (Test-Path $Vmx)) { throw "가상 머신 설정 파일이 없다: $Vmx" }

Write-Ok "vmrun: $VmRun"
Write-Ok "VM   : $Vmx"

# ---------------------------------------------------------------- 스냅샷 확인

Write-Step "스냅샷 확인: '$Snapshot'"
$raw = & $VmRun -T ws listSnapshots $Vmx
if ($LASTEXITCODE -ne 0) { throw "listSnapshots 실패 (exit $LASTEXITCODE): $raw" }

$names = @($raw | Select-Object -Skip 1 | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$exact = @($names | Where-Object { $_ -eq $Snapshot })

foreach ($n in $names) {
    $dup = @($names | Where-Object { $_ -eq $n }).Count
    $mark = ""
    if ($n -eq $Snapshot) { $mark = "  <- 대상" }
    elseif ($dup -gt 1)   { $mark = "  (이름 중복 ${dup}개)" }
    Write-Host ("    - {0}{1}" -f $n, $mark)
}

if ($exact.Count -eq 0) {
    throw "'$Snapshot' 이라는 스냅샷이 없다. 위 목록에서 정확한 이름을 확인할 것."
}
if ($exact.Count -gt 1) {
    throw @"
'$Snapshot' 이름의 스냅샷이 $($exact.Count) 개다. 이름으로는 어디로 되돌아갈지
정할 수 없어 중단한다. VMware 에서 이름을 서로 다르게 바꾼 뒤 다시 실행할 것.
"@
}
Write-Ok "일치하는 스냅샷 1개"

# ---------------------------------------------------------------- 복원

$sw = [Diagnostics.Stopwatch]::StartNew()

Write-Step "스냅샷으로 복원"
$out = & $VmRun -T ws revertToSnapshot $Vmx $Snapshot
if ($LASTEXITCODE -ne 0) { throw "revertToSnapshot 실패 (exit $LASTEXITCODE): $out" }
Write-Ok "복원 완료 ($([math]::Round($sw.Elapsed.TotalSeconds,1))s)"

# 실행 중 상태로 찍은 스냅샷은 메모리까지 복원되어 곧바로 켜져 있다.
# 전원이 꺼진 상태로 찍혔다면 여기서 켜야 한다.
#
# **화면 모드(`gui`)로 켠다** (결정 A · 2026-09-30). `nogui` 로 켜면 VM 은
# 돌지만 Workstation 창에는 꺼진 것으로 남아 화면과 실제가 어긋난다 — 콘솔을 봐야
# 할 때 어디에도 없다. `gui` 는 Workstation 탭과 늘 일치하고 콘솔이 바로 보인다.
# 대가는 하네스가 켤 때마다 호스트 화면에 VM 창이 뜨는 것이다. 되돌리기
# (`revertToSnapshot`)에는 이 선택지가 없다 — 켜진 채 찍은 스냅샷은 그 상태로
# 돌아오고, Workstation 이 열려 있으면 그 탭에 보인다.
$running = @(& $VmRun -T ws list | Where-Object { $_ -like "*$([IO.Path]::GetFileName($Vmx))*" })
if ($running.Count -eq 0) {
    Write-Step "전원 켜기 (화면 모드)"
    $out = & $VmRun -T ws start $Vmx gui
    if ($LASTEXITCODE -ne 0) { throw "start 실패 (exit $LASTEXITCODE): $out" }
    Write-Ok "전원 켬"
} else {
    Write-Ok "스냅샷이 실행 상태였다 - 부팅 대기 불필요"
}

# ---------------------------------------------------------------- 준비 대기

Write-Step "WinRM 응답 대기 (최대 ${TimeoutSec}초)"
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$ready = $false
$lastPing = $false
while ((Get-Date) -lt $deadline) {
    $lastPing = Test-Connection -ComputerName $VmAddress -Count 1 -Quiet -ErrorAction SilentlyContinue
    try {
        $c = New-Object Net.Sockets.TcpClient
        if ($c.ConnectAsync($VmAddress, 5985).Wait(1500)) { $ready = $true }
        $c.Close()
    } catch { }
    if ($ready) { break }
    Start-Sleep -Seconds 2
}

$sw.Stop()
if (-not $ready) {
    throw @"
${TimeoutSec}초 안에 WinRM(5985) 이 응답하지 않았다 (ping=$lastPing).
스냅샷이 준비 완료 상태가 맞는지, VM 콘솔에서 부팅이 끝났는지 확인할 것.
"@
}

Write-Ok "WinRM 응답 (총 $([math]::Round($sw.Elapsed.TotalSeconds,1))s)"

# 되돌아간 지점이 '준비된' 스냅샷이 맞는지 확인하고, 게스트 스크립트를 최신본으로
# 맞춘다.
#
# **스냅샷 안의 게스트 스크립트는 스냅샷을 찍던 시점의 판이다.** 되돌린 뒤 그대로
# 쓰면 옛 코드가 돈다. 실제로 이 함정에 걸렸다 - 이미 고쳐 둔 fork bomb 이 복원과
# 함께 되살아나 VM 에 PowerShell 프로세스가 143개까지 쌓였다. 복원 직후에 맞춰
# 두지 않으면 누구든 같은 곳에 빠진다.
$credPath = Join-Path $env:LOCALAPPDATA "remedy-lab\vm-cred.xml"

# **스냅샷의 시계까지 함께 되살아난다** (2026-09-10 에 진단).
#
# 되돌리면 게스트 시각이 스냅샷을 찍던 순간으로 돌아간다. 이 VM 은
# `tools.syncTime = FALSE` 라 주기 동기가 없고, `vmtoolsd` 의 보정은 언제
# 올지 알 수 없다 — 2026-09-10 에 45분 넘게 오지 않았다.
#
# **스냅샷이 새것이어도 이 단계는 남는다.** v3 는 2026-09-11 에 떴으니 지금은
# 차이가 작지만, 그 차이는 날마다 자란다. 날짜가 얼마나 벌어졌든 여기서
# 맞추면 회차의 시각을 믿을 수 있다.
#
# 그 창에서 찍히는 시각은 전부 스냅샷 날짜다. `verify-p2/p6/p8.json` 의
# `verified_at` 이 08-24 로 나왔고 — **내용은 그날 것이 맞았다** —
# 제품이 남기는 것도 같다: 회차 번호·시작 시각·저널·격리 컨테이너.
# **언제 잰 것인지 모르는 증거는 증거가 아니다.**
#
# 호스트가 아는 값을 밀어 넣는다. 외부망도(`w32tm` 은 time.windows.com 에
# 닿아야 한다) VMware Tools 의 설정 변경도 필요 없다.
Write-Step "게스트 시계 맞추기"
if (-not (Test-Path $credPath)) {
    Write-Warn "저장된 자격 증명이 없어 시계를 맞추지 못한다."
    Write-Warn "이 회차가 남기는 시각은 스냅샷을 찍던 날짜가 된다."
} else {
    # **한 번 맞추는 것으로는 남지 않는다** (실측 2026-09-10).
    #
    # 되돌린 직후 20초쯤 뒤에 무언가가 스냅샷 시각을 **다시 쓴다** — 이벤트
    # 로그에 `svchost` 가 `2026-09-10T11:56:49Z -> 2026-08-24T04:27:22Z` 로
    # 남겼다. 처음 판은 맞춘 뒤 그대로 두었고, 17초 뒤 그 쓰기에 지워져
    # 이어진 P5 회차가 다시 08-24 로 보고했다. **맞췄다고 말하려면 남는지
    # 봐야 한다.**
    #
    # 그 창을 지나면 안정적이다 — 60초를 5초 간격으로 지켜보니 차이가 0~1초로
    # 유지됐다. 그래서 관찰 창을 그 창(약 20초)보다 넓게 잡는다.
    $tsess = $null
    try {
        $settleSec = 15
        $maxRounds = 3
        $round = 0
        $gBefore = $null
        $drift0 = 0
        $stable = $false
        while (-not $stable -and $round -lt $maxRounds) {
            $round++
            $tsess = New-PSSession -ComputerName $VmAddress -Credential (Import-Clixml $credPath) -ErrorAction Stop
            $g = Invoke-Command -Session $tsess -ScriptBlock {
                (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            $hostNow = (Get-Date).ToUniversalTime()
            $d = [math]::Abs((New-TimeSpan -Start ([datetime]::Parse($g)).ToUniversalTime() `
                                           -End $hostNow).TotalSeconds)
            if ($round -eq 1) { $gBefore = $g; $drift0 = $d }
            Invoke-Command -Session $tsess -ArgumentList $hostNow -ScriptBlock {
                param($utc) Set-Date -Date $utc.ToLocalTime() | Out-Null
            }
            # **세션을 버리고 다시 연다.** 시각을 열이레씩 옮기면 이 연결이 그
            # 자리에서 끊길 수 있다.
            Remove-PSSession $tsess -ErrorAction SilentlyContinue
            $tsess = $null

            # 두 번 연속 맞아야 자리 잡은 것으로 본다. 한 번만 보면 되돌리는
            # 쓰기가 그 뒤에 와서 조용히 어긋난다.
            $ok = 0
            for ($i = 0; $i -lt 2; $i++) {
                Start-Sleep -Seconds $settleSec
                $tsess = New-PSSession -ComputerName $VmAddress -Credential (Import-Clixml $credPath) -ErrorAction Stop
                $g = Invoke-Command -Session $tsess -ScriptBlock {
                    (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                }
                Remove-PSSession $tsess -ErrorAction SilentlyContinue
                $tsess = $null
                $d = [math]::Abs((New-TimeSpan -Start ([datetime]::Parse($g)).ToUniversalTime() `
                                               -End (Get-Date).ToUniversalTime()).TotalSeconds)
                if ($d -le 60) { $ok++ } else { break }
            }
            $stable = ($ok -eq 2)
            $gAfter = $g
        }
        if (-not $stable) {
            Write-Warn "게스트 시계가 자리 잡지 않는다 ($maxRounds 회 시도, 지금 $gAfter)."
            Write-Warn "이 회차가 남기는 시각을 믿지 말 것."
        } elseif ($drift0 -gt 60) {
            Write-Warn ("스냅샷의 시계가 {0:N1}일 뒤처져 있었다: {1} -> {2} ({3}회째에 자리 잡음)" -f `
                        ($drift0 / 86400), $gBefore, $gAfter, $round)
        } else {
            Write-Ok "게스트 시계 $gAfter (처음 차이 $([math]::Round($drift0))초 · $round 회)"
        }
    } catch {
        Write-Warn "게스트 시계를 맞추지 못했다: $($_.Exception.Message)"
    } finally {
        if ($tsess) { Remove-PSSession $tsess -ErrorAction SilentlyContinue }
    }
}

# **Store 갱신을 끈다** (2026-09-14).
#
# # 왜 여기인가
#
# `Disable-LabUpdaters.ps1` 이 `\Microsoft\Windows\InstallService\` 아래
# 예약 작업 다섯을 이미 껐는데도 **Store 는 앱을 갈아 끼웠다** — 그쪽은
# 예약 작업이 아니라 서비스가 직접 한다. 그래서 정책 키가 실질이다.
#
# 그 스크립트는 **이미지를 손질할 때 한 번** 도는 것이라 거기 더하면 v4 를
# 다시 떠야 효과가 난다. 복원은 정책 키를 스냅샷 시점으로 되돌리므로,
# **되돌린 자리에서 매번 심는 편**이 값싸고 스냅샷이 낡아도 유효하다.
# 게스트 시계를 여기서 맞추는 것과 같은 성격이다.
#
# # 무엇을 고쳤나
#
# P2 의 코퍼스 수집(`%ProgramFiles%`, 300초)이 도는 동안 Store 가 계산기를
# `11.2606` → `11.2607` 로 갈아 끼웠고, **교체 중이던 옛 폴더가 열리지
# 않아** `denied_dirs` 가 0이 아니었다. 그러면 P2 는 그 스냅샷을 통과로 세지
# 않는다(설계대로). 세 회차에서 2 · 1 · 4 로 수가 달랐던 것도 그때그때
# 교체가 어디까지 갔는지가 달랐기 때문이다.
#
# **실측 (같은 날, 복원 → 이 정책 → P2 순서)**
#
#   정책 없음   denied_dirs 4 · P2 13/14 (미결 1) · 수집 309.0초 · 파일 44,234
#   정책 있음   denied_dirs 0 · P2 **14/14**    · 수집 278.7초 · 파일 44,667
#
# 복원 직후에 심어도 늦지 않다는 것을 그 순서가 함께 보였다.
#
# **막지 못해도 회차는 돈다.** 이것은 소음을 줄이는 손질이지 판정의 전제가
# 아니다 — 실패하면 한 줄로 알리고 넘어간다. 정말 갱신이 끼어들면 그때는
# `denied_paths` 가 어느 폴더였는지 말한다.
if (Test-Path $credPath) {
    Write-Step "Store 갱신 끄기"
    $psess = $null
    try {
        $psess = New-PSSession -ComputerName $VmAddress -Credential (Import-Clixml $credPath) -ErrorAction Stop
        $got = Invoke-Command -Session $psess -ScriptBlock {
            $ErrorActionPreference = "Continue"
            $k = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
            New-Item -Path $k -Force | Out-Null
            # 2 = 끄기. 1 은 켜기이고 값이 없으면 사용자 설정을 따른다.
            Set-ItemProperty $k -Name AutoDownload -Value 2 -Type DWord
            (Get-ItemProperty $k -Name AutoDownload -ErrorAction SilentlyContinue).AutoDownload
        }
        if ($got -eq 2) { Write-Ok "AutoDownload=2 (Store 앱 자동 갱신 끔)" }
        else { Write-Warn "정책이 서지 않았다 (지금 값: $got). 회차 도중 Store 가 앱을 갈아 끼울 수 있다." }
    } catch {
        Write-Warn "Store 갱신을 끄지 못했다: $($_.Exception.Message)"
    } finally {
        if ($psess) { Remove-PSSession $psess -ErrorAction SilentlyContinue }
    }
}

Write-Step "복원 지점 검증 및 게스트 스크립트 동기화"
$labOk = $false

if (-not (Test-Path $credPath)) {
    Write-Warn "저장된 자격 증명이 없어 검증·동기화를 건너뛴다."
    Write-Warn "게스트 스크립트가 스냅샷 시점 판 그대로다. Invoke-VmTest 로 실행할 것."
} else {
    $sess = $null
    try {
        $sess = New-PSSession -ComputerName $VmAddress -Credential (Import-Clixml $credPath) -ErrorAction Stop

        $guestDir = Join-Path (Split-Path -Parent $PSScriptRoot) "guest"
        foreach ($f in @("Capture-State.ps1", "New-Fixtures.ps1")) {
            $src = Join-Path $guestDir $f
            # BOM 이 없으면 PowerShell 5.1 이 CP949 로 오독한다. 보내기 전에 막는다.
            $bytes = [System.IO.File]::ReadAllBytes($src)
            if (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) {
                throw "$f 에 UTF-8 BOM 이 없다."
            }
            $perr = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$null, [ref]$perr)
            if ($perr.Count -gt 0) {
                throw "$f 파싱 실패 (L$($perr[0].Extent.StartLineNumber)): $($perr[0].Message)"
            }
            Copy-Item $src -Destination "$LabRoot\scripts\$f" -ToSession $sess -Force
            Write-Ok "동기화: $f"
        }

        $probe = Invoke-Command -Session $sess -ScriptBlock {
            param($root)
            [ordered]@{
                lab      = (Test-Path "$root\scripts\Capture-State.ps1")
                baseline = (Test-Path "$root\baseline\state.json")
                binLeft  = @(Get-ChildItem "$root\bin" -File -ErrorAction SilentlyContinue).Count
                resLeft  = @(Get-ChildItem "$root\results" -ErrorAction SilentlyContinue).Count
            }
        } -ArgumentList $LabRoot
        $labOk = ($probe.lab -and $probe.baseline)
        Write-Ok ("scripts={0} baseline={1} bin잔여={2} results잔여={3}" -f `
            $probe.lab, $probe.baseline, $probe.binLeft, $probe.resLeft)
    } catch {
        Write-Warn "검증·동기화 실패: $($_.Exception.Message)"
    } finally {
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    }
}
if (-not $labOk) {
    Write-Warn "$LabRoot 이 준비 상태가 아니다. 되돌아간 지점을 확인할 것."
}

# **랩의 remedy.exe 가 언제 것인가** (2026-09-14).
#
# # 왜 알리기만 하는가
#
# 하네스 열아홉은 **저마다 자기 바이너리를 배포한다** — 그것이
# `Invoke-PartialVerify` 가 적은 *"자기 전제를 스스로 세운다"* 이고, 그래서
# 랩에 무엇이 남아 있든 게이트는 안전하다. 여기서 대신 배포하면 그 원칙이
# 흐려지고(누군가 "Reset-Vm 이 해 주니까" 하고 배포를 뺄 수 있다) 이 스크립트가
# 빌드 산출물에 의존하게 된다.
#
# 위험한 것은 **손으로 재는 프로브**뿐이다. 되돌린 직후의 `bin\remedy.exe` 는
# 스냅샷을 뜨던 날의 판이고, 그것으로 잰 결과는 지금 코드의 결과가 아니다.
#
# 2026-09-14 에 그 함정에 걸렸다: 잠긴 레지스트리 키를 거부로 세는지 손으로
# 재다가 **3주 된 바이너리**를 붙잡고 "거짓 음성" 이라 두 회차를 보고했다.
# 같은 잠금에서 최신 판은 `denied_dirs 1 · exit 6` 을 냈다.
#
# 그래서 **읽고 알리기만 한다.** 조치는 사람이 한다.
$hostBin = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) `
    "..\target\x86_64-pc-windows-msvc\release\remedy.exe"
if (Test-Path $credPath) {
    try {
        $bsess = New-PSSession -ComputerName $VmAddress -Credential (Import-Clixml $credPath) -ErrorAction Stop
        $labBin = Invoke-Command -Session $bsess -ArgumentList $LabRoot -ScriptBlock {
            param($root)
            $p = Join-Path $root "bin\remedy.exe"
            if (Test-Path $p) { (Get-Item $p).LastWriteTimeUtc } else { $null }
        }
        Remove-PSSession $bsess -ErrorAction SilentlyContinue
        if ($null -eq $labBin) {
            Write-Ok "랩에 bin\remedy.exe 가 없다 — 하네스가 배포한다"
        } elseif ((Test-Path $hostBin) -and ((Get-Item $hostBin).LastWriteTimeUtc - $labBin).TotalHours -gt 1) {
            Write-Warn ("랩의 bin\remedy.exe 는 {0:yyyy-MM-dd} 판이다 (호스트 빌드는 {1:yyyy-MM-dd})." -f `
                    $labBin.ToLocalTime(), (Get-Item $hostBin).LastWriteTime)
            Write-Warn "  하네스는 저마다 배포하므로 게이트는 안전하다. **손으로 잴 때는 먼저 배포할 것.**"
        } else {
            Write-Ok ("랩의 bin\remedy.exe {0:yyyy-MM-dd} 판" -f $labBin.ToLocalTime())
        }
    } catch {
        Write-Warn "랩의 remedy.exe 시각을 읽지 못했다: $($_.Exception.Message)"
    }
}

Write-Host "`n복원 완료 - 시험을 시작할 수 있다." -ForegroundColor Green
