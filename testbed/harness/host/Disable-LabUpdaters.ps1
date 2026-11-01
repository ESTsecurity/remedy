<#
.SYNOPSIS
    랩 VM 의 자동 갱신기를 끈다 — `remedy-lab-base-v3` 를 만든 그 손질.

.DESCRIPTION
    **되돌린 게스트의 갱신기가 회차 도중에 움직인다.** 시계를 맞추기 시작한 뒤
    (2026-09-10) 기계는 자기가 열이레를 건너뛴 것으로 보고, Windows Update 와
    Chrome 이 밀린 일을 그 자리에서 한다. 값은 두 군데서 났다:

      - **채점 5 불합격** — `치료가 만든 변화 4건` 이 전부 갱신기였다.
        차분을 열어 보면 Chrome 이 스스로 151 → 152 로 올라갔다.
      - **P2 코퍼스 +120초** — 같은 수집이 380초에서 501초가 됐다.

    2026-09-11 에 이 손질을 하고 스냅샷을 다시 떠 `remedy-lab-base-v3` 를 만들자
    둘 다 사라졌다(채점 5 합격 · P2 673→496초).

    # Defender 는 건드리지 않는다

    실시간 보호와 변조 방지는 **켜 둔 채다.** 끄면 시연과 오탐 측정이 실제
    사용자 PC 와 다른 것이 되고, 그런 곳의 측정은 아무것도 뜻하지 않는다.

    # 거부되는 것이 있다 — 그것은 고장이 아니다

    `UpdateOrchestrator`·`WaaSMedic`·`WindowsUpdate` 아래 예약 작업 열 몇 건과
    `WaaSMedicSvc`·`DoSvc` 는 **TrustedInstaller 소유라 관리자도 손대지 못한다**
    (설계-00 §5 의 "관리자라고 다 되는 것은 아니다"). 그래서 서비스와 **정책 키**로
    위에서 막는다. 이 스크립트는 거부된 것을 세어 보고하고 계속 간다.

    # `wuauserv … Manual` 이 보여도 고장이 아니다 (2026-09-11 실측)

    `Set-Service wuauserv -StartupType Disabled` 는 **성공한다.** 그런데 이십여
    초 뒤에 보면 다시 `Manual`·`Running` 이다 — **`WaaSMedicSvc` 가 Windows
    Update 를 고치는 것이 제 일이고, 그 서비스는 끌 수 없다.**

    이것은 스크립트의 결함이 아니다. v3 로 되돌린 기계도 자리를 잡고 나면 같은
    줄을 낸다 — v3 를 만들 때 본 `Disabled` 는 고쳐지기 **전의 한순간**이었다.
    v2 에 이 스크립트를 돌린 결과와 자리 잡은 v3 는 서비스 여섯 · 정책 여섯 ·
    꺼진 예약 작업 열넷이 **모두 같다.**

    그러니 **정책 키가 실질이다.** 서비스를 끄는 것은 거들 뿐이고, 갱신이 실제로
    도는지는 `NoAutoUpdate` 와 `DoNotConnectToWindowsUpdateInternetLocations` 가
    막는다. 재어야 할 것은 서비스 줄이 아니라 **회차 도중에 기계가 움직이는가**
    이고, 그것은 채점 5 의 합격과 P2 의 시간이 말한다.

    # 스냅샷은 뜨지 않는다

    되돌릴 수 없는 일은 사람이 한다. 끝에서 다음 명령을 찍어 준다.

.EXAMPLE
    .\Disable-LabUpdaters.ps1
    # 그다음, 랩이 준비 상태인지 확인하고 사람이:
    #   vmrun -T ws snapshot <vmx> remedy-lab-base-v4
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    # 상태만 보고 아무것도 바꾸지 않는다.
    [switch] $ReportOnly
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential

# 끄려는 것. **Defender 는 여기 없다.**
$Services = @("wuauserv", "UsoSvc", "WaaSMedicSvc", "DoSvc", "edgeupdate", "edgeupdatem")
# 예약 작업은 경로나 이름으로 고른다 — Windows Update 계열과 Chrome·Edge 갱신기.
$TaskPathPattern = "UpdateOrchestrator|WindowsUpdate|WaaSMedic|InstallService|GoogleSystem"
$TaskNamePattern = "MicrosoftEdgeUpdateTask|GoogleUpdater"
# 정책 키. 예약 작업을 끌 수 없을 때 위에서 막는 자리다.
$Policies = @(
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"; Value = 1 },
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DoNotConnectToWindowsUpdateInternetLocations"; Value = 1 },
    @{ Key = "HKLM:\SOFTWARE\Policies\Google\Update"; Name = "UpdateDefault"; Value = 0 },
    @{ Key = "HKLM:\SOFTWARE\Policies\Google\Update"; Name = "AutoUpdateCheckPeriodMinutes"; Value = 0 },
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"; Name = "UpdateDefault"; Value = 0 },
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"; Name = "AutoUpdateCheckPeriodMinutes"; Value = 0 }
)

try {
    if (-not $ReportOnly) {
        Write-Step "서비스 끄기"
        $svcOut = Invoke-Command -Session $session -ArgumentList (, $Services) -ScriptBlock {
            param($names)
            $refused = 0
            foreach ($n in $names) {
                if (-not (Get-Service $n -ErrorAction SilentlyContinue)) { continue }
                # **이미 꺼져 있으면 아무것도 하지 않는다.** 두 번 돌려도 같은 곳에 선다.
                try { Set-Service $n -StartupType Disabled -ErrorAction Stop } catch { $refused++ }
                try { Stop-Service $n -Force -ErrorAction Stop } catch { }
            }
            $refused
        }
        Write-Ok "시도 $($Services.Count)건 · 시작 유형을 바꾸지 못한 것 $svcOut 건 (TrustedInstaller 소유)"

        Write-Step "예약 작업 끄기"
        $taskOut = Invoke-Command -Session $session -ArgumentList $TaskPathPattern, $TaskNamePattern -ScriptBlock {
            param($pathPat, $namePat)
            $t = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
                $_.State -ne 'Disabled' -and ($_.TaskPath -match $pathPat -or $_.TaskName -match $namePat)
            })
            $refused = 0
            foreach ($x in $t) {
                try { Disable-ScheduledTask -TaskPath $x.TaskPath -TaskName $x.TaskName -ErrorAction Stop | Out-Null }
                catch { $refused++ }
            }
            [pscustomobject]@{ Tried = $t.Count; Refused = $refused }
        }
        Write-Ok "시도 $($taskOut.Tried)건 · 껐다 $($taskOut.Tried - $taskOut.Refused)건 · 거부 $($taskOut.Refused)건 (TrustedInstaller 소유)"

        Write-Step "정책 키"
        Invoke-Command -Session $session -ArgumentList (, $Policies) -ScriptBlock {
            param($pols)
            foreach ($p in $pols) {
                if (-not (Test-Path $p.Key)) { New-Item -Path $p.Key -Force | Out-Null }
                New-ItemProperty -Path $p.Key -Name $p.Name -Value $p.Value -PropertyType DWord -Force | Out-Null
            }
        }
        Write-Ok "$($Policies.Count)건"
    }

    # ── 상태 보고 ────────────────────────────────────────────────────
    #
    # **바꾼 것이 아니라 지금 상태를 찍는다.** 시도한 것만 적으면 거부된 자리가
    # 성공처럼 보인다. 이 블록은 두 기계를 견줄 때 그대로 대조하는 자료다.
    Write-Step "지금 상태"
    # **인자는 해시테이블 하나로 준다.** `-ArgumentList (, $배열), $스칼라, …` 처럼
    # 섞으면 `(, …)` 래퍼가 한 겹 남아 `foreach` 가 배열 **하나**를 한 번 돈다 —
    # 화면에는 이름 여섯이 한 줄에 이어 붙어 나온다(2026-09-11 에 밟았다).
    $cfg = @{
        Names    = $Services
        PathPat  = $TaskPathPattern
        NamePat  = $TaskNamePattern
        Policies = $Policies
    }
    $state = Invoke-Command -Session $session -ArgumentList $cfg -ScriptBlock {
        param($cfg)
        $names = $cfg.Names; $pathPat = $cfg.PathPat
        $namePat = $cfg.NamePat; $pols = $cfg.Policies
        $o = New-Object System.Collections.Generic.List[string]
        $o.Add("[서비스]")
        foreach ($n in $names) {
            $s = Get-Service $n -ErrorAction SilentlyContinue
            $o.Add(("  {0,-14} {1}" -f $n, $(if ($s) { "$($s.Status) / $($s.StartType)" } else { "없음" })))
        }
        $t = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskPath -match $pathPat -or $_.TaskName -match $namePat
        })
        $o.Add("[예약 작업] 전체 $($t.Count)건")
        foreach ($g in ($t | Group-Object State | Sort-Object Name)) {
            $o.Add(("  {0,-10} {1}건" -f $g.Name, $g.Count))
        }
        $o.Add("[정책]")
        foreach ($p in $pols) {
            $v = if (Test-Path $p.Key) { (Get-ItemProperty $p.Key -Name $p.Name -ErrorAction SilentlyContinue).($p.Name) } else { $null }
            $o.Add(("  {0}\{1} = {2}" -f $p.Key.Replace('HKLM:\SOFTWARE\Policies\', ''), $p.Name, $(if ($null -ne $v) { $v } else { "없음" })))
        }
        $d = Get-MpComputerStatus
        $o.Add("[Defender — 건드리지 않는다]")
        $o.Add(("  실시간보호={0} 변조방지={1}" -f $d.RealTimeProtectionEnabled, $d.IsTamperProtected))
        $o -join "`n"
    }
    Write-Host $state
} finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
}

if (-not $ReportOnly) {
    Write-Host ""
    Write-Host "랩이 준비 상태인지 확인한 뒤, 스냅샷은 사람이 뜬다:" -ForegroundColor Yellow
    Write-Host '  & "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" -T ws snapshot <vmx> <새 이름>'
    Write-Host "  그다음 하네스의 -Snapshot 기본값을 그 이름으로 바꾼다 (host\*.ps1)"
}
