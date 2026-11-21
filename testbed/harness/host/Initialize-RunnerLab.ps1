#Requires -Version 5.1
# 하네스 표: GitHub 호스팅 Windows 러너 | 러너를 랩으로 세운다 — 출시 전 필수 점검(`.github/workflows/checks.yml`)의 Windows 잡이 하네스 앞에 부른다
<#
.SYNOPSIS
    GitHub 호스팅 Windows 러너를 랩 VM 자리에 세운다 — 출시 전 필수 점검(`.github/workflows/checks.yml`)의 Windows 잡이 부른다.

.DESCRIPTION
    러너 자신이 랩이 된다(하네스는 127.0.0.1 로 붙는다 · 잡이 끝나면 러너를 버리므로 되돌리기가 없다). 하는 일:

      1  가드 — GitHub 호스팅 Windows 러너가 아니거나(`Assert-HostedRunner`), 이 기계에 랩 설정(`.cargo/windows_lab.yml` ·
         자격 증명 파일)이나 같은 이름의 계정이 이미 있으면 멈춘다. 랩 하네스는 붙은 기계에 가짜 감염을 세우고 소프트웨어를
         지우므로 개발 PC 에서는 돌지 않게 한다
      2  게스트 준비 — `testbed/harness/guest/Setup-Guest.ps1 -HostAddress 127.0.0.1`(랩 VM 을 처음 세울 때와 같은 스크립트).
         실패해도 이어 가고, 3 에서 원격 설정 둘을 맞춘다
      3  원격 접속 — WinRM 리스너(5985) · LocalAccountTokenFilterPolicy=1 · 이 기계의 TrustedHosts 에 127.0.0.1
      4  랩 계정 — 무작위 암호의 로컬 관리자(암호는 찍지 않는다)와 그 자격 증명 파일(DPAPI — 이 사용자만 푼다)
      5  랩 설정 파일 — 하네스가 읽는 칸 셋(주소 127.0.0.1 · vmx · 스냅숏은 '되돌리지 않는다' 표지)
      6  랩 계정의 HKCU Run 키 — 갓 만든 계정은 대화형 로그온을 하지 않아 키가 없다(시연 게이트가 그 키에 값을 쓴다)
      7  이미지 소프트웨어 정리 — 러너 이미지가 깔아 둔 Apache · nginx 서비스와 그 폴더(`C:\tools\` 아래만). 룰 하네스의
         '없음' 칸을 흔든다(Apache 룰은 정해진 자리 밖의 httpd 서비스를 '확인 필요' 로 본다)

    아침 실험(2026-11-21 · 실행 44854393842)의 준비 걸음을 옮겼다 — 그 실행에서 시연 게이트 75/75 · 메뉴 하네스 37/37.
    러너는 랩과 다르다(Windows Server · Defender 실시간 감시 꺼짐) — 그 차이는 24시간 안의 미룬 검증(랩 rc 묶음)이 잰다.

.PARAMETER Account
    만들 랩 계정의 이름.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File testbed\harness\host\Initialize-RunnerLab.ps1
#>
param([string] $Account = 'remedylab')
$ErrorActionPreference = 'Stop'
$h = $PSScriptRoot
. (Join-Path $h 'VmSession.ps1')
$repo = (Resolve-Path (Join-Path $h '..\..\..')).Path

# 1 가드 — 호스팅 러너가 아니면 · 랩 설정이 이미 있으면 멈춘다.
Write-Step '가드'
Assert-HostedRunner
$labYml = Join-Path $repo '.cargo\windows_lab.yml'
$credStore = Join-Path $env:LOCALAPPDATA 'remedy-lab\vm-cred.xml'
foreach ($p in @($labYml, $credStore)) {
    if (Test-Path -LiteralPath $p) { throw "랩 설정이 이미 있다($p) — 개발 PC 일 수 있어 멈춘다(러너는 매번 빈 자리다)" }
}
if (Get-LocalUser -Name $Account -ErrorAction SilentlyContinue) { throw "계정 $Account 가 이미 있다 — 멈춘다" }
Write-Ok ("GitHub 호스팅 러너 · {0} · 랩 설정 없음" -f $env:ImageOS)

# 2 게스트 준비 — 랩 VM 을 세울 때와 같은 스크립트. 러너에서 다 서지 않는 걸음이 있어도(기준 상태 등) 이어 간다.
Write-Step '게스트 준비(Setup-Guest.ps1 -HostAddress 127.0.0.1)'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'testbed\harness\guest\Setup-Guest.ps1') `
    -HostAddress 127.0.0.1 *> (Join-Path $env:RUNNER_TEMP 'setup-guest.log')
Write-Ok ("Setup-Guest 종료 {0}(기록 RUNNER_TEMP\setup-guest.log)" -f $LASTEXITCODE)

# 3 원격 접속 — 준비가 세우지 못한 것만 여기서.
Write-Step '원격 접속'
if (-not (Get-NetTCPConnection -LocalPort 5985 -State Listen -ErrorAction SilentlyContinue)) {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
    Write-Ok 'Enable-PSRemoting(준비가 세우지 못해 여기서)'
}
$pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if ((Get-ItemProperty -Path $pol -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy -ne 1) {
    New-ItemProperty -Path $pol -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Ok 'LocalAccountTokenFilterPolicy=1(준비가 세우지 못해 여기서)'
}
if (-not (Get-NetTCPConnection -LocalPort 5985 -State Listen -ErrorAction SilentlyContinue)) { throw 'WinRM 5985 리스너가 서지 않았다' }
Initialize-WinRmClient -VmAddress '127.0.0.1'

# 4 랩 계정 — 무작위 암호(찍지 않는다) · 관리자 그룹은 이름이 아니라 SID 로(언어와 상관없이).
Write-Step "랩 계정 $Account"
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$buf = New-Object byte[] 24
$rng.GetBytes($buf)
$secure = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($buf)) -AsPlainText -Force
New-LocalUser -Name $Account -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $Account
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$Account", $secure)
New-Item -ItemType Directory -Force (Split-Path -Parent $credStore) | Out-Null
$cred | Export-Clixml -LiteralPath $credStore
Write-Ok ("계정 · 관리자 그룹 · 자격 증명 파일 {0}바이트" -f (Get-Item -LiteralPath $credStore).Length)

# 5 랩 설정 파일 — 하네스가 읽는 칸 셋(`windows_lab.network.ip` · `identity.vmx` · `snapshots.current`)만.
Write-Step '랩 설정 파일'
$yml = @(
    '# 러너 랩 — testbed/harness/host/Initialize-RunnerLab.ps1 이 지었다(GitHub 호스팅 러너 · 잡이 끝나면 버린다)',
    'windows_lab:',
    '  identity:',
    "    vmx: '(러너 — 되돌리지 않는다)'",
    '  snapshots:',
    "    current: '(러너 — 되돌리지 않는다)'",
    '  network:',
    "    ip: '127.0.0.1'"
)
New-Item -ItemType Directory -Force (Split-Path -Parent $labYml) | Out-Null
[IO.File]::WriteAllLines($labYml, [string[]]$yml, (New-Object Text.UTF8Encoding $false))
$ip = Get-LabConfigValue -File 'windows_lab' -Key 'windows_lab.network.ip'
if ($ip -ne '127.0.0.1') { throw "랩 설정 파일의 주소가 읽히지 않는다: '$ip'" }
Write-Ok '주소 127.0.0.1 · 되돌리기 없음'

# 6 랩 계정의 HKCU Run 키 — 그 계정의 세션에서 만든다(그 계정의 HKCU 가 선다).
Write-Step '랩 계정의 HKCU Run 키'
$s = New-PSSession -ComputerName '127.0.0.1' -Credential $cred
try {
    Invoke-Command -Session $s -ScriptBlock {
        $run = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        if (-not (Test-Path $run)) { New-Item -Path $run -Force | Out-Null; 'Run 키를 만들었다' } else { 'Run 키가 있다' }
    }
} finally { Remove-PSSession $s }

# 7 이미지 소프트웨어 정리 — 러너 이미지의 Apache · nginx 서비스와 폴더. `C:\tools\` 아래만 지운다.
Write-Step '이미지 소프트웨어 정리'
foreach ($name in @('Apache', 'nginx')) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Ok "서비스 $name 없음"; continue }
    # 실행 파일 — NSSM 으로 띄우는 서비스는 Parameters\Application 이 실제 실행 파일이다.
    $app = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name\Parameters" -Name Application -ErrorAction SilentlyContinue).Application
    if (-not $app) { $app = ($svc.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+)\s.*$', '$1' }
    $dir = Split-Path -Parent $app
    if ((Split-Path -Leaf $dir) -eq 'bin') { $dir = Split-Path -Parent $dir }
    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    & sc.exe delete $name | Out-Null
    if ($dir -like 'C:\tools\*' -and (Test-Path -LiteralPath $dir)) {
        Remove-Item -LiteralPath $dir -Recurse -Force
        Write-Ok "서비스 $name 지움 · 폴더 $dir 지움"
    } else {
        Write-Warn "서비스 $name 지움 · 폴더 '$dir' 는 C:\tools\ 밖이거나 없어 두었다"
    }
}
Write-Ok '러너 랩 준비 끝'
exit 0
