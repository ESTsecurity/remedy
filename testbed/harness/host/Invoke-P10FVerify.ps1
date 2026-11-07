<#
.SYNOPSIS
    P10-F 의 **재부팅 후 검증 예약**이 실기기에서 실제로 발화하는가.

.DESCRIPTION
    설계-03 §8 의 약속은 *"재부팅 뒤 한 번 `verify` 가 돈다"* 이고, 자기 흔적
    규칙 셋이 그 위에 얹혀 있다. **그 약속을 실기기에서 재는 자리가 없었다.**

    없었던 대가는 컸다. 예약되던 명령에 `--plugin` 이 빠져 있어 재부팅 뒤
    사용법 오류로 즉시 끝났고, RunOnce 는 콘솔 없이 돌며 OS 가 항목을 먼저
    지우므로 **아무 흔적도 남지 않았다.** 단위 시험은 레지스트리 값을 쓰는지만
    쟀다 (2026-08-28 v1 점검).

    여기서 재는 넷:

      1. `run` 이 예약을 **실제로 심는가**       — RunOnce 값이 있다
      2. 그 값이 **실행 가능한 명령인가**        — `--plugin` 이 들어 있다
      3. 재부팅 뒤 **OS 가 항목을 지우는가**     — 자기 흔적 규칙 2
      4. 재부팅 뒤 **`verify` 가 실제로 돌았는가** — 프로세스 생성 감사
      5. 그 **판정이 남았고 clean · 0 인가**  — `verify/<run_id>.jsonl`
      6. 그 회차의 **화면이 남았는가**        — `logs/<run_id>.log`, 그리고 **같은 언어인가**

    4·5·6 이 요점이다. 1~3 은 값을 보는 것이고, 4 는 *"돌았는가"*, 5 는
    *"그래서 무엇이었는가"*, 6 은 *"사람이 읽을 것이 남았는가"* 를 묻는다.

    6 의 언어도 2026-09-07 에 더했다. 재부팅 회차는 환경변수를 물려받지 못해
    기본 언어(영어)로 돌았고, 그래서 **한 회차의 로그가 앞은 한국어 뒤는 영어**가
    됐다. 예약 명령이 언어를 싣도록 고쳤고 2b·6 이 그것을 잰다.

    6 은 2026-09-07 에 더했다. 회차 로그(`logs/<run_id>.log`)가 생기면서
    **콘솔 없는 이 회차의 화면도 파일로 남아야 한다**는 약속이 생겼고, 그것을
    재는 자리가 없었다. `run` 이 같은 이름의 파일을 이미 열었으므로 존재만으로는
    증거가 되지 않는다 — **재부팅 뒤에 덧붙은 머리줄**(`# remedy … verify --run`)이
    있어야 그 회차가 적은 것이다.

    5 가 뒤늦게 생긴 이유: 4 를 재다가 **판정이 어디에도 남지 않는다**는 것을
    알았다. 콘솔은 아무도 보지 않고 종료 코드는 프로세스와 함께 사라진다 —
    설계-03 §5 가 무인 배포의 트리거로 지목한 그 값이다.

    5 의 값은 2026-10-26 에 더했다. 그 전에는 기록이 **있기만 하면** 통과였는데,
    재검사가 다 보지 못하면 이제 `incomplete` · 6 이 적힌다 — 치료가 유지됐다는
    답이 아니다. 리눅스 하네스(7)처럼 `clean` · 종료 0 을 단정한다.

.PARAMETER DevBuild
    개발 빌드로 잰다. 2026-09-02 까지는 **서명 없는 릴리스가 파괴를 거부해서**
    파괴 경로가 이 길뿐이었다. 지금은 배포될 바로 그 바이너리로 재므로 이
    스위치는 디버그 빌드를 재고 싶을 때만 쓴다.

.PARAMETER Relative
    README 의 명령줄 예시처럼 **받은 폴더에서 상대 경로로** 부른다(`--plugin .\plugins\…` ·
    `--state-dir .\state-p10f`). 1.1.0 까지는 그 값이 예약에 그대로 실려 다른 폴더에서 도는
    재부팅 회차가 룰을 찾지 못했다(2026-11-07 적대적 검토) — 2c 가 예약이 절대 경로인지 잰다.

.EXAMPLE
    .\Invoke-P10FVerify.ps1 -DevBuild -Build
    .\Invoke-P10FVerify.ps1 -Build -Relative
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    [switch] $NoRevert,
    [switch] $DevBuild,
    [switch] $Relative,
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
. (Join-Path $PSScriptRoot "InfectedState.ps1")

$triple = "x86_64-pc-windows-msvc"
$profile_ = if ($DevBuild) { "debug" } else { "release" }
# **`[string[]]` 가 필요하다.** PowerShell 은 `if` 가 돌려주는 단일 원소 배열을
# 스칼라로 푼다 — 그러면 `$cargoProfile` 이 문자열이 되고 `@cargoProfile` 이
# 그것을 문자 단위로 쪼개 `cargo` 가 `-` 하나를 받는다 (실측 2026-08-29).
#
# `-DevBuild` 로만 돌리는 동안에는 빈 배열이라 드러나지 않았다.
[string[]] $cargoProfile = if ($DevBuild) { @() } else { @("--release") }
$binPath = Join-Path $repoRoot "target\$triple\$profile_\remedy.exe"

if ($Build) {
    Write-Step "빌드 ($profile_)"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        # **실패하면 throw 다** — VM 에 아무것도 배포하지 않는다.
        Invoke-CargoBuild "remedy.exe" (@("build") + $cargoProfile + @("--target", $triple, "-p", "remedy-cli"))
    } finally { Pop-Location }
}
if (-not (Test-Path $binPath)) { throw "산출물이 없다: $binPath`n먼저 -Build 를 줄 것." }

if (-not $NoRevert) {
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
}

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $repoRoot "testbed\harness\results\p10f-$stamp"
New-Item -ItemType Directory -Force $outDir | Out-Null

$checks = @()
function Add-Check {
    param([string] $Name, [bool] $Ok, [string] $Detail)
    $script:checks += [pscustomobject]@{ name = $Name; ok = $Ok; detail = $Detail }
    if ($Ok) { Write-Ok "$Name   $Detail" } else { Write-Bad "$Name   $Detail" }
}

# ── 배포 ───────────────────────────────────────────────────
Write-Step "배포"
$gPlugin = "$LabRoot\plugins\evilai-locust\plugin.yaml"
Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
    param($root)
    New-Item -ItemType Directory -Force "$root\bin", "$root\plugins\evilai-locust\rules" | Out-Null
}
Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
Copy-Item (Join-Path $repoRoot "plugins\evilai-locust\plugin.yaml") `
          -Destination $gPlugin -ToSession $session -Force
Get-ChildItem (Join-Path $repoRoot "plugins\evilai-locust\rules") -File | ForEach-Object {
    Copy-Item $_.FullName -Destination "$LabRoot\plugins\evilai-locust\rules\$($_.Name)" `
              -ToSession $session -Force
}
Write-Ok "remedy.exe · 플러그인"

Assert-CanDestroy -Session $session -Bin (Join-Path (Join-Path $LabRoot "bin") "remedy.exe")

# ── 감염 → run ─────────────────────────────────────────────
#
# 감염 구성은 `InfectedState.ps1` 이 소유한다 — 두 하네스가 같은 감염을 봐야
# 결과를 견줄 수 있다.
$payloadDir = Invoke-Command -Session $session -ScriptBlock {
    Join-Path $env:LOCALAPPDATA "Programs\MicrosoftResourcesAgentV12"
}
$rulePath = Join-Path (Join-Path $repoRoot "plugins\evilai-locust") "rules\evilai.yar"
$payload = Get-SynthPayloadBytes -RulePath $rulePath
Set-InfectedState -Session $session -PayloadDir $payloadDir | Out-Null
Set-GuestPayload  -Session $session -PayloadDir $payloadDir -Bytes $payload | Out-Null
Write-Ok "감염 구성 · 합성 페이로드 $($payload.Length) B"
$stateDir = "$LabRoot\state-p10f"
$runDir = "$LabRoot\out-p10f"
Write-Step "감염 → run (예약이 걸리는 실행)"
if ($Relative) {
    # 같은 자리를 받은 폴더(`$LabRoot`)에서 상대 경로로 부른다 — 사람이 README 대로 칠 때다.
    $r = Invoke-GuestExe -Session $session -Path "$LabRoot\bin\remedy.exe" -WorkingDirectory $LabRoot `
        -Arguments @("run", "--plugin", ".\plugins\evilai-locust\plugin.yaml", "--out-dir", ".\out-p10f",
            "--yes", "--state-dir", ".\state-p10f")
} else {
    $r = Invoke-GuestExe -Session $session -Path "$LabRoot\bin\remedy.exe" -Arguments @(
        "run", "--plugin", $gPlugin, "--out-dir", $runDir, "--yes", "--state-dir", $stateDir)
}
Add-Check "run 이 끝났다" ($r.exit -in @(1, 3)) "exit=$($r.exit)"

$runId = Invoke-Command -Session $session -ArgumentList "$runDir\plan.json" -ScriptBlock {
    param($p) if (Test-Path $p) { (Get-Content $p -Raw | ConvertFrom-Json).run_id }
}
Add-Check "run_id 를 얻었다" ([bool]$runId) "$runId"

# ── 1·2. 예약이 심겼고 실행 가능한가 ────────────────────────
$planted = Invoke-Command -Session $session -ScriptBlock {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    (Get-ItemProperty -Path $k -Name 'remedy-verify' -ErrorAction SilentlyContinue).'remedy-verify'
}
Add-Check "1 예약이 심겼다" ([bool]$planted) "$planted"
# **`--plugin` 이 이 검사의 이유다.** 없으면 재부팅 뒤 사용법 오류로 끝난다.
Add-Check "2 예약된 명령에 --plugin 이 있다" `
          ($planted -and $planted -match '--plugin') "$planted"
# **언어도 실려야 한다.** RunOnce 는 `REMEDY_LANG` 없이 돌므로, 싣지 않으면
# 이 회차만 기본 언어(영어)로 돌아 한 로그가 두 언어가 된다 (실측 2026-09-07).
$langArg = if ($planted -match '--lang\s+(\S+)') { $Matches[1] } else { $null }
Add-Check "2b 예약된 명령이 언어를 이름 짓는다" ([bool]$langArg) `
          $(if ($langArg) { "--lang $langArg" } else { "--lang 이 없다 — 재부팅 회차가 다른 언어로 돈다" })
if ($Relative) {
    # 재부팅 회차는 다른 현재 폴더에서 돈다 — 상대 경로가 실리면 룰을 찾지 못한다.
    Add-Check "2c 상대 경로로 불러도 예약은 룰과 상태 폴더를 절대 경로로 부른다" `
              ([bool]$planted -and $planted.Contains($gPlugin) -and $planted.Contains($stateDir) -and
               -not $planted.Contains('.\')) "$planted"
}

# ── 자동 로그온 (랩 전용) ───────────────────────────────────
#
# **RunOnce 는 로그온 때 돈다. 부팅 때가 아니다.**
#
# 랩 VM 은 아무도 로그인하지 않는다 — WinRM 은 대화형 세션을 만들지 않는다.
# 그 상태에서는 예약이 재부팅 뒤에도 그대로 남고, 그것은 제품의 결함이 아니라
# **이 환경에서 그 기계를 잴 수 없다**는 뜻이다 (실측 2026-08-29: `AutoAdminLogon=0`
# · `quser` 사용자 없음 · 예약 그대로 남음).
#
# 그래서 이 검사 동안만 자동 로그온을 켠다. `Setup-Guest.ps1` 이
# `LocalAccountTokenFilterPolicy` 를 켜는 것과 같은 성격의 **랩 전용 완화**이고,
# 같은 경고가 붙는다.
#
# **비밀번호가 레지스트리에 평문으로 들어간다.** 격리된 테스트 VM 에서만
# 받아들일 수 있고, 아래에서 곧바로 지운다. 업무 PC 에는 절대 적용하지 말 것.
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$plain = $session.Runspace.ConnectionInfo.Credential.GetNetworkCredential()
Write-Step "자동 로그온 켜기 (랩 전용 — RunOnce 는 로그온 때 돈다)"
Invoke-Command -Session $session -ArgumentList $wl, $plain.UserName, $plain.Password -ScriptBlock {
    param($k, $u, $pw)
    Set-ItemProperty $k -Name AutoAdminLogon  -Value "1" -Type String
    Set-ItemProperty $k -Name DefaultUserName -Value $u  -Type String
    Set-ItemProperty $k -Name DefaultPassword -Value $pw -Type String
}
Write-Ok "AutoAdminLogon=1 (재부팅 뒤 되돌린다)"

# ── 프로세스 생성 감사 (랩 전용) ────────────────────────────
#
# 검사 4 가 *"우리 바이너리가 실제로 떴는가"* 를 물으려면 그 사실이 어딘가에
# 남아야 한다. **`verify` 는 `--out` 없이는 아무것도 쓰지 않는다** — 예약된
# 명령에도 `--out` 이 없다(§보고서). 그래서 OS 의 프로세스 생성 감사(4688)에
# 기댄다.
#
# Windows 10 기본값은 **꺼짐**이다. 켜지 않으면 이 검사는 "이벤트 0건" 을
# 돌려주는데, 그것은 *"돌지 않았다"* 가 아니라 *"재지 못했다"* 다. 둘을
# 구분하지 못하는 검사는 아무것도 재지 않는 검사다.
Write-Step "프로세스 생성 감사 켜기 (랩 전용 — 검사 4 의 유일한 증거원)"
$auditWas = Invoke-Command -Session $session -ScriptBlock {
    # PS 5.1 은 네이티브 stderr 를 ErrorRecord 로 감싼다. 판정 기준은 출력이다.
    $ErrorActionPreference = "Continue"
    $before = (& auditpol.exe /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" 2>&1 | Out-String)
    & auditpol.exe /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
    $before
}

# **4688 은 기본적으로 명령줄을 담지 않는다.** 프로세스 경로만 남는다.
#
# 그것을 모르고 `Message -match "verify"` 로 걸렀다가 **실제로 돈 실행을
# "돌지 않았다" 로 보고했다** (2026-08-29). 부팅 29초 뒤에 `remedy.exe` 가
# 떴는데도 그랬다 — 오늘 네 번 본 것과 같은 종류의 착오다: **재는 것과 실제가
# 갈라진다.**
#
# 경로만 보면 "remedy 가 떴다" 까지만 알 수 있다. 우리가 묻는 것은
# "**verify** 가 돌았는가" 이므로 인자가 필요하다.
Invoke-Command -Session $session -ScriptBlock {
    $ErrorActionPreference = "Continue"
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    New-Item -Path $k -Force | Out-Null
    Set-ItemProperty $k -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
}
Write-Ok "감사 켬 · 명령줄 포함 (재부팅 뒤 되돌린다)"

# ── 재부팅 ─────────────────────────────────────────────────
Write-Step "재부팅"
Invoke-Command -Session $session -ScriptBlock { Restart-Computer -Force } -ErrorAction SilentlyContinue
Remove-PSSession $session

# ── 내려간 것을 먼저 보고, 그다음 올라온 것을 본다 (2026-09-13) ──
#
# 전에는 30초를 자고(20+10) 곧바로 "살아났는가" 만 물었다. **내려가는 데
# 걸리는 시간이 3.0~12.3초로 네 배 흔들린다**(같은 날 재부팅 3회 실측)는
# 것은 평소엔 우연히 맞는다는 뜻이고, 어긋나는 날에는 **재부팅 전 OS 에
# 붙는다.** P9 에서 실제로 그렇게 붙은 것이 관측됐다.
#
# **이 하네스에서는 더 나쁘다.** P10F 가 재는 것은 *재부팅 뒤에 RunOnce 가
# `verify` 를 돌리는가* 이므로, 재부팅 전 기계를 읽으면 그 판정이 통째로
# 공허해진다.
#
# 뒤의 `Start-Sleep 45` 가 그 착오를 우연히 흡수해 왔다 — 그동안 진짜
# 재부팅이 진행되고 `Connect-LabVmRetrying` 이 재시도로 덮었다. 증명 창을
# 40초에서 10초로 줄이면(같은 날 실측) 그 우연이 얇아지므로, 우연에
# 기대지 않게 여기서 먼저 막는다.
$downBy = (Get-Date).AddSeconds(180)
$went = $false
while ((Get-Date) -lt $downBy) {
    if (-not (Test-VmAlive $VmAddress).WinRM) { $went = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $went) {
    throw "재부팅을 요청하고 180초를 기다렸는데 WinRM 이 내려가지 않았다. 재부팅이 시작되지 않았다 — RunOnce 갈래를 잴 수 없다"
}
Write-Ok "내려갔다 (재부팅이 실제로 시작됐다)"

$deadline = (Get-Date).AddSeconds(300)
$up = $false
while ((Get-Date) -lt $deadline) {
    if ((Test-VmAlive $VmAddress).WinRM) { $up = $true; break }
    Start-Sleep -Seconds 5
}
if (-not $up) { throw "재부팅 후 WinRM 이 돌아오지 않았다" }
# RunOnce 는 **로그온 뒤** 돈다. 자동 로그온이 걸린 랩 이미지라도 셸이 서고
# 항목이 실행되기까지 시간이 걸린다.
Start-Sleep -Seconds 45
$session = Connect-LabVmRetrying -VmAddress $VmAddress -Credential $Credential

# **평문 비밀번호를 곧바로 지운다.** 아래 검사보다 먼저 한다 — 검사가 실패해도
# 이 정리는 끝나 있어야 한다.
Invoke-Command -Session $session -ArgumentList $wl -ScriptBlock {
    param($k)
    Set-ItemProperty $k -Name AutoAdminLogon -Value "0" -Type String
    Remove-ItemProperty $k -Name DefaultPassword -ErrorAction SilentlyContinue
}
Write-Ok "자동 로그온 되돌림 · 평문 비밀번호 제거"

# 감사는 **읽은 뒤에** 끈다. 먼저 끄면 4688 이 이미 기록된 것까지 사라지지는
# 않지만, 순서를 바꿀 이유도 없다.

# ── 3. OS 가 항목을 지웠는가 (자기 흔적 규칙 2) ─────────────
$after = Invoke-Command -Session $session -ScriptBlock {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    (Get-ItemProperty -Path $k -Name 'remedy-verify' -ErrorAction SilentlyContinue).'remedy-verify'
}
Add-Check "3 재부팅 뒤 예약이 남아 있지 않다" (-not $after) `
          $(if ($after) { "남았다: $after" } else { "없다" })

# ── 4. verify 가 실제로 돌았는가 ────────────────────────────
#
# **이것만이 약속이 지켜졌는지를 묻는다.** 1~3 은 값을 보는 것이다.
# `verify` 는 재수집·재평가를 하므로 저널이 아니라 그 실행의 흔적을 본다 —
# 여기서는 `verify` 가 남기는 마지막 실행 시각으로 판정한다.
$ran = Invoke-Command -Session $session -ArgumentList $stateDir, $LabRoot -ScriptBlock {
    param($state, $root)
    # RunOnce 가 우리 바이너리를 띄웠다면 프로세스 시작 흔적이 이벤트 로그에
    # 남는다. 그것이 가장 직접적인 증거다.
    # **부팅 이후**만 본다. 그 전 것은 이 시험의 `run` 이 만든 것이다.
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $all = @()
    try {
        $all = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4688; StartTime = $boot
        } -ErrorAction SilentlyContinue)
    } catch {}
    $ours = @($all | Where-Object { $_.Message -match 'remedy\.exe' })
    # 명령줄이 담겼으면 `verify` 까지 확인한다. 안 담겼으면 그 사실을 돌려준다 —
    # **"경로만 봤다" 와 "인자까지 봤다" 는 다른 강도의 증거다.**
    $withArgs = @($ours | Where-Object { $_.Message -match 'verify' })
    [pscustomobject]@{
        events = $ours.Count
        verified = $withArgs.Count
        # 감사 정책이 꺼져 있으면 4688 이 없다. 그때는 이 검사가 무엇도 재지
        # 못한다는 사실을 그대로 돌려준다.
        auditing = (& auditpol.exe /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" 2>&1 | Out-String)
    }
}
$auditOn = -not ($ran.auditing -match "감사 없음|No Auditing")
$sawIt = $ran.verified -gt 0
Add-Check "4 재부팅 뒤 verify 가 돌았다" $sawIt `
          $(if ($sawIt) { "부팅 뒤 remedy.exe verify 실행 $($ran.verified)건" }
            elseif ($ran.events -gt 0) { "remedy.exe 는 $($ran.events)건 떴는데 인자에 verify 가 없다 — 예약이 다른 것을 부른다" }
            elseif (-not $auditOn) { "**재지 못했다** — 감사 정책이 꺼져 있다. 이 결과는 '돌지 않았다' 가 아니다" }
            else { "이벤트 0건 — 감사는 켜져 있었다. 즉 실제로 돌지 않았다" })

# ── 5. 판정이 남았는가 ──────────────────────────────────────
#
# **돌았다는 것과 무엇이었는지는 다른 물음이다.** 무인 배포는 프로세스를 보지
# 못하므로 이 파일이 유일한 답이다 (설계-03 §8).
$rec = Invoke-Command -Session $session -ArgumentList $stateDir, $runId -ScriptBlock {
    param($state, $run)
    $p = Join-Path (Join-Path $state "verify") "$run.jsonl"
    if (-not (Test-Path $p)) { return $null }
    $lines = @(Get-Content $p -Encoding UTF8 | Where-Object { $_.Trim() })
    if (-not $lines) { return $null }
    $lines[-1] | ConvertFrom-Json
}
# **있는 것만으로는 통과가 아니다** (2026-10-26) — 다 보지 못한 재검사도 줄을 남긴다.
$recClean = [bool]$rec -and $rec.outcome -eq "clean" -and $rec.exit_code -eq 0
Add-Check "5 재평가 판정이 남았다 (clean · 종료 0)" $recClean `
          $(if ($rec) {
                $d = "outcome=$($rec.outcome) exit=$($rec.exit_code) plugin=$($rec.plugin_id)"
                # 다 보지 못한 회차면 무엇을 못 봤는지가 그 줄에 있다 — 그대로 보인다.
                if ($rec.observation) { $d += " observation=" + ($rec.observation | ConvertTo-Json -Compress -Depth 5) }
                $d
            } else { "verify\$runId.jsonl 이 없다 — 돌았어도 판정을 알 길이 없다" })

# ── 6. 그 회차의 화면이 남았는가 ────────────────────────────
#
# 회차 로그는 `run` 이 먼저 열었고 `verify --run <id>` 는 **같은 파일에 덧붙인다**
# (같은 run_id 의 모든 화면이 한 파일에 모인다). 그래서 파일이 있다는 것만으로는
# 아무것도 못 잰다 — 재부팅 뒤에 새로 적힌 **머리줄**이 있어야 한다.
# 머리줄은 `<시각> # remedy <버전> pid <n> · <명령줄>` 이고, 그 명령줄에
# `verify --run` 이 들어 있으면 그 회차가 쓴 것이다.
$log = Invoke-Command -Session $session -ArgumentList $stateDir, $runId -ScriptBlock {
    param($state, $run)
    $p = Join-Path (Join-Path $state "logs") "$run.log"
    if (-not (Test-Path $p)) { return [pscustomobject]@{ exists = $false } }
    $lines = @(Get-Content $p -Encoding UTF8)
    # 머리줄 중 `verify` 를 담은 것. 그 뒤의 줄이 재부팅 회차의 화면이다.
    $idx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '# remedy .* verify ' -and $lines[$i] -match '--run') { $idx = $i }
    }
    $after = if ($idx -ge 0) { @($lines[$idx..($lines.Count - 1)]) } else { @() }
    # 크래시 파일이 생겼다면 그 회차가 패닉으로 죽은 것이다 — 콘솔 없는
    # 프로세스에서 `println!` 이 실패하는 경우가 여기서 드러난다.
    $crashes = @(Get-ChildItem (Join-Path $state "logs") -Filter "crash-*.txt" -ErrorAction SilentlyContinue)
    [pscustomobject]@{
        exists  = $true
        lines   = $lines.Count
        header  = if ($idx -ge 0) { $lines[$idx] } else { $null }
        after   = $after.Count
        sample  = @($after | Where-Object { $_ -match ' \| ' } | Select-Object -First 3)
        crashes = @($crashes | ForEach-Object { $_.Name })
        # 화면의 언어. 하네스는 `REMEDY_LANG=ko` 로 치료했으므로 재부팅 회차도
        # 한국어여야 한다 — 그것이 '한 회차는 한 언어' 의 실측이다.
        korean  = @($after | Where-Object { $_ -match '전용백신|검사 완료|검사 중' }).Count
        english = @($after | Where-Object { $_ -match 'Dedicated Cleaner|Scan done|Scanning' }).Count
    }
}
$loggedIt = $log.exists -and [bool]$log.header -and $log.after -gt 1
Add-Check "6 재부팅 회차의 화면이 회차 로그에 남았다" $loggedIt `
          $(if ($loggedIt) { "덧붙은 줄 $($log.after)개 · 첫 화면: $(($log.sample | Select-Object -First 1))" }
            elseif (-not $log.exists) { "logs\$runId.log 이 없다 — run 조차 남기지 못했다" }
            elseif (-not $log.header) { "파일은 있는데 verify 머리줄이 없다 — 그 회차는 로그를 열지 못했다" }
            else { "머리줄만 있고 화면이 없다 ($($log.after)줄)" })
# **한 회차는 한 언어로 읽혀야 한다.** 치료는 한국어로 돌았으니 재부팅 회차도
# 한국어여야 한다. 영어 줄이 섞이면 예약 명령이 언어를 싣지 못한 것이다.
$sameLang = $log.exists -and $log.korean -gt 0 -and $log.english -eq 0
Add-Check "6c 재부팅 회차가 치료와 같은 언어로 돌았다" $sameLang `
          $(if ($sameLang) { "한국어 $($log.korean)줄 · 영어 0줄" }
            elseif (-not $log.exists) { "로그가 없어 잴 수 없다" }
            else { "한국어 $($log.korean)줄 · 영어 $($log.english)줄 — 한 로그가 두 언어다" })

if ($log.crashes) {
    Add-Check "6b 재부팅 회차가 크래시하지 않았다" $false "크래시 기록: $($log.crashes -join ', ')"
} else {
    Add-Check "6b 재부팅 회차가 크래시하지 않았다" $true "crash-*.txt 없음"
}

# 감사를 되돌린다.
Invoke-Command -Session $session -ScriptBlock {
    $ErrorActionPreference = "Continue"
    & auditpol.exe /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:disable | Out-Null
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    Remove-ItemProperty $k -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
} | Out-Null
Write-Ok "감사 되돌림 · 명령줄 포함 해제"

# ── 판정 ───────────────────────────────────────────────────
$fail = @($checks | Where-Object { -not $_.ok }).Count
Write-Host ""
Write-Host "통과 $(@($checks | Where-Object { $_.ok }).Count) · 실패 $fail  (전체 $($checks.Count))"
# **BOM 없이 쓴다.** PS 5.1 의 `Out-File -Encoding utf8` 은 BOM 을 붙이고,
# 그러면 이 파일을 읽는 쪽이 첫 글자에서 죽는다 — `json.load` 가
# *"Unexpected UTF-8 BOM"* 로 멈추는 것을 2026-09-10 에 실제로 봤다.
# 저장소 규칙이기도 하다(AGENTS.md): `.ps1` 은 BOM 필수, JSON 은 BOM 금지.
[System.IO.File]::WriteAllText("$outDir\verify-p10f.json",
    ($checks | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding $false))
Write-Host "결과: $outDir"
Remove-PSSession $session
exit $(if ($fail -gt 0) { 1 } else { 0 })
