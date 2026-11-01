<#
.SYNOPSIS
    remedy 테스트 VM 준비. **스냅샷을 찍기 전에 VM 콘솔에서 한 번만** 실행한다.

.DESCRIPTION
    이 스크립트가 하는 일은 "테스트마다 반복하고 싶지 않은 것"뿐이다.
    remedy 바이너리와 테스트 픽스처는 스냅샷에 넣지 않는다 — 빌드마다 바뀌고,
    픽스처는 매 테스트마다 새로 만들어야 하기 때문이다.

    설계-09 P0 의 선행 준비 "VM 인프라" 항목에 해당한다.

.PARAMETER HostAddress
    호스트(VMware 게스트에서 본 호스트)의 IP. 방화벽 규칙을 이 주소로만 연다.
    전체 서브넷을 열지 않는 것이 의도다 — 테스트 VM 이 옆 VM 에 노출될 이유가 없다.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Setup-Guest.ps1 -HostAddress <호스트의 VMnet8 주소>
#>
[CmdletBinding()]
param(
    # 호스트의 NAT 주소. **기본값을 두지 않는다** — 이 스크립트는 게스트 안에서
    # 도므로 `.cargo/*.yml` 을 읽을 수 없고, 틀린 주소로 방화벽을 열면 옆 기계에
    # 열리게 된다. 값은 호스트의 `.cargo/host.yml` 의 `vmware.network.host_ip` 에 있다.
    [string] $HostAddress,
    [string] $LabRoot = "C:\remedy-lab"
)

$ErrorActionPreference = "Stop"

if (-not $HostAddress) {
    throw ("-HostAddress 가 필요하다. 호스트의 NAT 주소를 줄 것 — 호스트의 " +
           ".cargo/host.yml 의 'vmware.network.host_ip' 에 있다 " +
           "(견본: .cargo/host.example.yml)")
}

function Write-Step { param([string] $Text) Write-Host "`n[*] $Text" -ForegroundColor Cyan }
function Write-Ok   { param([string] $Text) Write-Host "    OK   $Text" -ForegroundColor Green }
function Write-Warn { param([string] $Text) Write-Host "    주의 $Text" -ForegroundColor Yellow }

function Write-Json {
    param([Parameter(Mandatory = $true)] $Object,
          [Parameter(Mandatory = $true)][string] $Path,
          [int] $Depth = 8)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # JSON 은 BOM 없이 쓴다 (.ps1 은 반대로 BOM 이 필요하다 — README 참고).
    # WriteAllText 는 실패하면 예외를 던진다. Out-File 은 조용히 0바이트를 남긴다.
    [System.IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth $Depth),
                                   (New-Object System.Text.UTF8Encoding($false)))
    if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -eq 0) {
        throw "JSON 쓰기 실패 (0바이트): $Path"
    }
}

# ---------------------------------------------------------------- 사전 확인

Write-Step "권한 확인"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "관리자 권한으로 실행해야 한다. PowerShell 을 '관리자로 실행' 후 다시 시도할 것."
}
Write-Ok "관리자 권한"

# ---------------------------------------------------------------- 디렉터리

Write-Step "작업 디렉터리 생성: $LabRoot"
foreach ($sub in @("bin", "work", "results", "fixtures", "baseline", "scripts")) {
    $p = Join-Path $LabRoot $sub
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}
Write-Ok "bin / work / results / fixtures / baseline / scripts"

# 게스트 스크립트를 고정 경로에 둔다. 스냅샷 안에 항상 같은 위치로 존재해야
# 호스트 쪽에서 경로를 가정할 수 있다.
Write-Step "게스트 스크립트 배치: $LabRoot\scripts"
foreach ($f in @("Capture-State.ps1", "New-Fixtures.ps1")) {
    $src = Join-Path $PSScriptRoot $f
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $LabRoot "scripts\$f") -Force
        Write-Ok $f
    } else {
        Write-Warn "$f 을(를) 찾을 수 없다. Setup-Guest.ps1 과 같은 폴더에 두고 다시 실행할 것."
    }
}

# ---------------------------------------------------------------- 원격 접속

Write-Step "WinRM 활성화 (호스트에서 배포·실행·회수하기 위해)"
try {
    # 네트워크 프로필이 Public 이면 기본적으로 거부되므로 확인을 건너뛴다.
    # 테스트 VM 은 격리된 NAT 망에 있고, 방화벽 규칙을 호스트 IP 로만 좁힌다.
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
    Write-Ok "PSRemoting 활성화"
} catch {
    Write-Warn "Enable-PSRemoting 실패: $($_.Exception.Message)"
    Write-Warn "수동 확인 필요. winrm quickconfig 를 직접 실행해 볼 것."
}

Write-Step "원격 로컬 관리자에게 완전한 토큰 (LocalAccountTokenFilterPolicy)"
# **이것이 없으면 세션이 열리기도 전에 '액세스 거부'로 막힌다.**
#
# 워크그룹 PC 에 로컬 계정으로 원격 접속하면 UAC 가 토큰에서 Administrators 를
# 떼어낸다. 그러면 기본 세션 구성의 ACL 검사에 걸려 **접속 자체가** 거부되고,
# 그 오류는 비밀번호 오류·그룹 미가입과 문구가 같아 구분되지 않는다
# (`VmSession.ps1::Connect-LabVm` 이 그 셋을 함께 안내하는 이유가 이것이다).
#
# 지금까지 이 설정은 손으로 넣어 **스냅샷에만** 남아 있었다. VM 을 다시 만들거나
# 기준 스냅샷을 새로 뜨면 함께 사라지고, 그때 하네스는 전부 '액세스 거부' 로
# 멈춘다 — 원인이 코드 어디에도 적혀 있지 않은 채로. 여기서 세우면 그 자리가
# 없어진다.
#
# **UAC 자체(`EnableLUA`)는 건드리지 않는다.** 끄면 Defender 동작과 스토어 앱이
# 달라져 시험 환경이 실제 사용자 PC 와 다른 것이 된다 — 전용백신을 그런 곳에서
# 검증하면 통과가 아무것도 뜻하지 않는다. 하네스는 원격 세션으로만 들어오므로
# 그 경로에 완전한 토큰을 주는 것으로 충분하다.
#
# 격리된 테스트 VM 에서는 받아들일 수 있는 완화지만 업무 PC 에는 적용하지 말 것.
$policyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
New-ItemProperty -Path $policyKey -Name LocalAccountTokenFilterPolicy `
    -PropertyType DWord -Value 1 -Force | Out-Null
# 되읽어 확인한다. 쓰기가 정책으로 막히면 조용히 지나가고, 그 사실은 다음
# 하네스 실행이 '액세스 거부' 로 멈출 때에야 드러난다.
$latfp = (Get-ItemProperty -Path $policyKey -Name LocalAccountTokenFilterPolicy `
              -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
if ($latfp -ne 1) {
    throw "LocalAccountTokenFilterPolicy 를 1 로 세우지 못했다 (현재 값: '$latfp'). 그룹 정책이 덮고 있는지 확인할 것."
}
Write-Ok "LocalAccountTokenFilterPolicy = 1 (원격 로컬 관리자 완전 토큰)"

Write-Step "방화벽 — 호스트 $HostAddress 에서만 허용"
$rules = @(
    @{ Name = "remedy-lab WinRM (HTTP)"; Port = 5985; Proto = "TCP" }
)
foreach ($r in $rules) {
    Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Action Allow `
        -Protocol $r.Proto -LocalPort $r.Port -RemoteAddress $HostAddress `
        -Profile Any | Out-Null
    Write-Ok "$($r.Name) ($($r.Proto)/$($r.Port))"
}

# 살아 있는지 확인할 수단이 하나는 있어야 한다. 파괴적 테스트 후 "죽었는지
# 방화벽인지" 를 구분하지 못하면 진단이 불가능하다.
Get-NetFirewallRule -DisplayName "remedy-lab ICMP" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "remedy-lab ICMP" -Direction Inbound -Action Allow `
    -Protocol ICMPv4 -IcmpType 8 -RemoteAddress $HostAddress -Profile Any | Out-Null
Write-Ok "ICMP echo"

Write-Step "TrustedHosts (호스트에서 접속할 때 필요)"
Write-Warn "이 설정은 **호스트에서** 해야 한다. 아래를 호스트 관리자 PowerShell 에서 실행:"
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.IPAddress -notlike "127.*" } |
       Select-Object -First 1 -ExpandProperty IPAddress)
Write-Host "      Set-Item WSMan:\localhost\Client\TrustedHosts -Value $ip -Force" -ForegroundColor Yellow

# ---------------------------------------------------------------- 환경 기록

Write-Step "환경 정보 기록"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$envInfo = [ordered]@{
    captured_at   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    hostname      = $env:COMPUTERNAME
    os_caption    = $os.Caption
    os_version    = $os.Version
    os_build      = $os.BuildNumber
    os_arch       = $os.OSArchitecture
    os_bitness    = $(if ([Environment]::Is64BitOperatingSystem) { 64 } else { 32 })
    ps_version    = $PSVersionTable.PSVersion.ToString()
    domain_joined = $cs.PartOfDomain
    total_mem_mb  = [math]::Round($cs.TotalPhysicalMemory / 1MB)
    ip_addresses  = @(Get-NetIPAddress -AddressFamily IPv4 |
                      Where-Object { $_.IPAddress -notlike "127.*" } |
                      Select-Object -ExpandProperty IPAddress)
}
Write-Json -Object $envInfo -Path (Join-Path $LabRoot "baseline\environment.json") -Depth 4
Write-Ok "$($envInfo.os_caption) build $($envInfo.os_build) / $($envInfo.os_arch) / PS $($envInfo.ps_version)"

Write-Step "설치된 보안 제품 확인"
# 설계-00 §5-1 — 주 배포 환경은 자사 제품이 이미 설치된 PC 다.
# 실시간 감시가 켜진 상태와 꺼진 상태 양쪽을 시험해야 하므로 현재 상태를 기록한다.
$av = @()
try {
    $av = @(Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop |
            Select-Object displayName, productState)
} catch {
    Write-Warn "SecurityCenter2 조회 실패 (서버 OS 일 수 있음)"
}
$defender = $null
try { $defender = Get-MpComputerStatus -ErrorAction Stop } catch { }

$sec = [ordered]@{
    antivirus_products = $av
    defender_realtime  = $(if ($defender) { $defender.RealTimeProtectionEnabled } else { $null })
    defender_tamper    = $(if ($defender) { $defender.IsTamperProtected } else { $null })
}
Write-Json -Object $sec -Path (Join-Path $LabRoot "baseline\security-products.json") -Depth 4

if ($av.Count -gt 0) { foreach ($a in $av) { Write-Ok "AV: $($a.displayName)" } }
else { Write-Warn "등록된 백신 제품 없음" }
if ($defender) { Write-Ok "Defender 실시간 감시: $($defender.RealTimeProtectionEnabled) / 변조 보호: $($defender.IsTamperProtected)" }

# ---------------------------------------------------------------- 기준 상태

Write-Step "기준 시스템 상태 캡처"
# 복사본으로 실행한다. 배치가 제대로 되었는지 여기서 같이 검증된다.
& (Join-Path $LabRoot "scripts\Capture-State.ps1") -OutFile (Join-Path $LabRoot "baseline\state.json")
Write-Ok "baseline\state.json"

# ---------------------------------------------------------------- 안내

Write-Host "`n===== 스냅샷 전 확인 =====" -ForegroundColor Magenta
Write-Host @"

준비 완료. 스냅샷을 찍기 전에 아래를 확인할 것.

  1. 호스트에서 접속이 되는가
       Test-NetConnection $($envInfo.ip_addresses[0]) -Port 5985
       Enter-PSSession -ComputerName $($envInfo.ip_addresses[0]) -Credential (Get-Credential)

  2. $LabRoot 아래 여섯 디렉터리가 있는가
     (bin / work / results / fixtures / baseline / scripts)

  3. baseline\ 에 environment.json · security-products.json · state.json 이 있고
     scripts\ 에 Capture-State.ps1 · New-Fixtures.ps1 이 있는가

  4. **remedy 바이너리와 테스트 픽스처는 스냅샷에 넣지 않는다.**
     바이너리는 빌드마다 바뀌고 픽스처는 매 테스트마다 새로 만든다.
     스냅샷은 "깨끗한 실험대"여야 한다.

  5. Defender 실시간 감시 상태를 의도한 대로 두었는가.
     설계-00 §5-1 에 따라 켜진 상태와 꺼진 상태를 모두 시험해야 한다.
     기본 스냅샷은 **켜진 상태**를 권장한다 — 그것이 고객 환경이다.

스냅샷 이름은 공백·괄호 없이 지을 것 (예: remedy-lab-base-v3).
스크립트 인자로 오가는 값이라 다루기 쉬운 편이 낫다.

"@ -ForegroundColor Gray
