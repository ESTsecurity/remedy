<#
.SYNOPSIS
    AI 시험 위협의 감염 스냅샷을 **테스트 VM 에서 실제로 떠서** 위협 폴더에 넣는다.

.DESCRIPTION
    Linux 쪽 `linux/new-threat-snapshot.sh` 의 Windows 짝이고,
    `New-InfectedSnapshot.ps1` 과는 목적지가 다르다:

      New-InfectedSnapshot.ps1  →  corpus/infected/   (실검체 바이트가 들어간다)
      New-ThreatSnapshot.ps1    →  testbed/ai-exam/threats/<위협>/infected/

    # 왜 손으로 쓴 JSON 이면 안 되는가

    다섯 위협의 감염 스냅샷이 전부 손으로 쓴 것이었다. 그런 자료는 **다시 뜰 수
    없고, 실기기가 낼 수 없는 모양을 담을 수 있다.** 리눅스 둘을 옮기면서
    우리 정답 플러그인의 결함 하나가 드러났다(인증서 저장소 이름). Windows
    쪽에도 같은 부류가 이미 보인다 — `service-userinit` 의 감염 스냅샷이
    서비스 상태를 `running` 이라 적는데, 수집기는 그런 값을 낸 적이 없다.

    # 되돌린다

    게스트 스크립트가 `AppInit_DLLs` · `Userinit` · `BootExecute` · `Path` 를
    만진다. **틀리면 기계가 로그온되지 않는다.** 그래서 바꾸기 전에 전부
    백업하고, 이 스크립트는 `finally` 에서 반드시 정리를 부른다. 정리가
    끝난 뒤 값이 실제로 돌아왔는지 되읽어 확인한다.

    스냅샷은 되돌리지 않는다(`-Revert` 로 켤 수 있다). 되돌리면 방금 세운
    것과 함께 배포한 바이너리도 사라져 다음 실행이 처음부터 시작한다.

    # 봉투는 고정한다

    스냅샷이 저장소에 커밋되고 채점의 입력이 되므로, 실행마다 달라지는 것
    (호스트 이름·run_id·시각·수집기 판)은 기존 스냅샷의 것을 그대로 쓴다.
    **레코드는 손대지 않는다** — 그것이 재려는 것이다.

.EXAMPLE
    .\New-ThreatSnapshot.ps1 -Threat service-userinit -Build
    .\New-ThreatSnapshot.ps1 -Threat search-hijack
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('appinit-implant', 'service-userinit', 'search-hijack', 'ransomware', 'webshell-upload', 'proxy-dns-hijack', 'shortcut-hijack', 'cred-dump', 'regkey-stager', 'sideload-drop', 'hook-implant')]
    [string] $Threat,
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    # 되돌리면 자동 갱신기가 깨어난다(README 의 '채점 직전에 스냅샷을
    # 되돌리지 않는다'). **서비스를 담는 위협은 그 소음이 커밋될 증거에
    # 박힌다** — `service-userinit` 의 스냅샷에는 이미 Chrome 항목이 있다.
    # `search-hijack` 처럼 담지 않는 위협은 되돌려도 된다(2026-09-11 확인:
    # 파일 145 · 레지스트리 37 · 확장 6 이 커밋본과 같았다).
    [switch] $Revert,
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
$plugin = Join-Path $repoRoot "testbed\harness\windows\threats\$Threat-collect.yaml"
$guestScript = Join-Path $PSScriptRoot "..\guest\New-ThreatFixtures.ps1"
$outFile = Join-Path $repoRoot "testbed\ai-exam\threats\$Threat\infected\$Threat.json"

if (-not (Test-Path $plugin)) { throw "수집 매니페스트가 없다: $plugin" }
if (-not (Test-Path $outFile)) { throw "대상 스냅샷이 없다: $outFile" }

if ($Build) {
    Write-Step "빌드: cargo build --release --target $triple"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
    } finally { Pop-Location }
}
if (-not (Test-Path $binPath)) { throw "바이너리가 없다: $binPath  (-Build 로 만들 것)" }

if ($Revert) {
    Write-Step "스냅샷 복원: $Snapshot"
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Snapshot $Snapshot -Vmx $Vmx
}

$session = Connect-LabVmRetrying -VmAddress $VmAddress -Credential $Credential `
    -SaveCredential:$SaveCredential

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$guestOut = "$LabRoot\threat-$Threat.json"

try {
    Write-Step "배포: remedy.exe · 매니페스트 · 픽스처 스크립트"
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($root)
        foreach ($d in @("$root\bin", "$root\scripts")) {
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        }
    }
    Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
    Copy-Item $plugin -Destination "$LabRoot\scripts\$Threat-collect.yaml" -ToSession $session -Force
    Copy-Item $guestScript -Destination "$LabRoot\scripts\New-ThreatFixtures.ps1" -ToSession $session -Force
    Write-Ok "배포 완료"

    Write-Step "감염 상태 구성 — $Threat"
    $made = Invoke-Command -Session $session -ArgumentList $LabRoot, $Threat -ScriptBlock {
        param($root, $threat)
        & powershell.exe -ExecutionPolicy Bypass -NoProfile `
            -File "$root\scripts\New-ThreatFixtures.ps1" -Threat $threat 2>&1
    }
    $made | ForEach-Object { Write-Host "    $_" }

    Write-Step "수집"
    # **출력을 파일로 받는다.** 원격 세션의 파이프는 콘솔 코드페이지를 거쳐
    # 한국어를 깨뜨린다 (README '원격 세션은 한국어를 깨뜨린다').
    $collect = Invoke-Command -Session $session -ArgumentList $LabRoot, $Threat, $guestOut -ScriptBlock {
        param($root, $threat, $out)
        $log = "$root\collect-$threat.log"
        $p = Start-Process "$root\bin\remedy.exe" `
            -ArgumentList 'collect', '--plugin', "$root\scripts\$threat-collect.yaml", '--out', $out `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $log -RedirectStandardError "$log.err"
        [pscustomobject]@{
            Exit = $p.ExitCode
            Log  = [System.IO.File]::ReadAllText($log)
            Err  = [System.IO.File]::ReadAllText("$log.err")
            Size = (Get-Item $out -ErrorAction SilentlyContinue).Length
        }
    }
    $collect.Log.Trim() -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host "    $_" }
    if ($collect.Exit -ne 0) {
        $collect.Err.Trim() -split "`r?`n" | ForEach-Object { Write-Bad "    $_" }
        throw "collect 가 실패했다 (exit=$($collect.Exit))"
    }
    Write-Ok "스냅샷 $($collect.Size) 바이트"

    Write-Step "회수"
    $raw = Join-Path $env:TEMP "threat-$Threat-$stamp.json"
    Copy-Item -Path $guestOut -Destination $raw -FromSession $session -Force
    Write-Ok $raw
} finally {
    # **반드시 정리한다.** 여기서 빠뜨리면 VM 의 Userinit 이 감염된 채 남는다.
    Write-Step "정리 — 레지스트리 되돌리기 포함"
    try {
        $cleaned = Invoke-Command -Session $session -ArgumentList $LabRoot, $Threat -ScriptBlock {
            param($root, $threat)
            & powershell.exe -ExecutionPolicy Bypass -NoProfile `
                -File "$root\scripts\New-ThreatFixtures.ps1" -Threat $threat -Clean 2>&1
        }
        $cleaned | ForEach-Object { Write-Host "    $_" }

        # 되돌아왔는지 **되읽어 확인한다.** 정리가 조용히 실패하면 다음 부팅에서
        # 드러나고, 그때는 원인이 어디에도 없다.
        $check = Invoke-Command -Session $session -ScriptBlock {
            $w = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
            [pscustomobject]@{
                Userinit    = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Userinit
                AppInit     = if ($w.GetValueNames() -contains 'AppInit_DLLs') { $w.GetValue('AppInit_DLLs') } else { '<없음>' }
                LoadAppInit = if ($w.GetValueNames() -contains 'LoadAppInit_DLLs') { $w.GetValue('LoadAppInit_DLLs') } else { '<없음>' }
                BootExecute = ((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').BootExecute) -join '|'
                PathHead    = ((Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').GetValue('Path', '', 'DoNotExpandEnvironmentNames') -split ';')[0]
                Services    = (@('SvcHostCache', 'AcmeUpdater') | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }) -join ','
                Leftover    = (@('C:\ProgramData\SvcAssist', 'C:\ProgramData\Acme', 'C:\ProgramData\WebBoost', 'C:\ProgramData\SvcHostCache-3f8a') | Where-Object { Test-Path -LiteralPath $_ }) -join ','
            }
        }
        $dirty = @()
        if ($check.Userinit -like '*SvcHostCache*') { $dirty += "Userinit=$($check.Userinit)" }
        if ($check.AppInit -like '*SvcAssist*') { $dirty += "AppInit_DLLs=$($check.AppInit)" }
        if ($check.BootExecute -like '*wbboot*') { $dirty += "BootExecute=$($check.BootExecute)" }
        if ($check.PathHead -like '*WebBoost*') { $dirty += "Path[0]=$($check.PathHead)" }
        if ($check.Services) { $dirty += "서비스 남음=$($check.Services)" }
        if ($check.Leftover) { $dirty += "폴더 남음=$($check.Leftover)" }

        if ($dirty.Count -eq 0) {
            Write-Ok "기계가 원래대로 돌아왔다"
            Write-Host "      Userinit    $($check.Userinit)"
            Write-Host "      AppInit     $($check.AppInit) / Load=$($check.LoadAppInit)"
            Write-Host "      BootExecute $($check.BootExecute)"
        } else {
            Write-Bad "정리가 끝나지 않았다:"
            $dirty | ForEach-Object { Write-Bad "      $_" }
            Write-Bad "  VM 스냅샷($Snapshot)으로 되돌릴 것: .\Reset-Vm.ps1"
        }
    } catch {
        Write-Bad "정리 중 오류: $_"
        Write-Bad "  VM 스냅샷($Snapshot)으로 되돌릴 것: .\Reset-Vm.ps1"
    }
    Remove-PSSession $session -ErrorAction SilentlyContinue
}

# ── 봉투 고정 ───────────────────────────────────────────────────────
Write-Step "봉투 고정 후 위협 폴더에 넣는다"
$py = @'
import io, json, sys
raw = json.load(io.open(sys.argv[1], encoding='utf-8'))
old = json.load(io.open(sys.argv[2], encoding='utf-8'))
for k in ('run_id', 'created', 'collected_at', 'host', 'collector', 'core', 'plugins'):
    if k in old:
        raw[k] = old[k]
io.open(sys.argv[2], 'w', encoding='utf-8', newline='').write(
    json.dumps(raw, ensure_ascii=False, indent=2) + '\n')
recs = {k: len(v) for k, v in raw.items()
        if isinstance(v, list) and v and isinstance(v[0], dict)}
print('  범위   %s' % raw['scope']['scan_roots'])
print('  잘림   %s · 거부 %s' % (raw['scope']['truncated'], raw['scope']['denied_dirs']))
print('  레코드 %d건  %s' % (sum(recs.values()),
      ' '.join('%s:%d' % kv for kv in sorted(recs.items()))))
'@
$pyFile = Join-Path $env:TEMP "fix-envelope-$stamp.py"
Set-Content -LiteralPath $pyFile -Value $py -Encoding UTF8
& python $pyFile $raw $outFile
Remove-Item -LiteralPath $pyFile -Force -ErrorAction SilentlyContinue
Write-Ok $outFile
