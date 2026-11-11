<#
.SYNOPSIS
    테스트 VM 연결 공용 함수. 호스트 스크립트들이 점 소싱해서 쓴다.

.DESCRIPTION
    연결 절차에는 한 번씩 다 겪고 나서야 알게 되는 함정이 여럿 있다 —
    호스트 WinRM 서비스가 멈춰 있으면 오류 메시지가 VM 을 가리키고, 빈 비밀번호는
    '액세스 거부'로 나오며, UAC 토큰 필터링은 세션이 열리기도 전에 거부한다.
    그 진단을 **한 곳에** 둔다. 복사본이 갈라지면 다음 사람이 같은 길을 다시 헤맨다.

    사용법:
        . (Join-Path $PSScriptRoot "VmSession.ps1")
        $VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
        $session = Connect-LabVm -VmAddress $VmAddress
#>

function Write-Step { param($t) Write-Host "`n[*] $t" -ForegroundColor Cyan }
function Write-Ok   { param($t) Write-Host "    OK   $t" -ForegroundColor Green }
function Write-Warn { param($t) Write-Host "    주의 $t" -ForegroundColor Yellow }
function Write-Bad  { param($t) Write-Host "    실패 $t" -ForegroundColor Red }

# ── 랩 값은 `.cargo/*.yml` 에서 읽는다 ──────────────────────────────
#
# **스크립트에 박지 않는다.** 랩 주소·VMX 경로·스냅샷 이름은 기계마다 다른데
# 박아 두면 기계가 바뀔 때 스물여섯 곳이 함께 어긋난다 — 2026-09-10 에 주소가
# 하루에 세 번 바뀌며 실제로 그랬다. 운영 값은 커밋하지 않는 `.cargo/*.yml` 에
# 두고(견본 `.cargo/*.example.yml`) 여기서 한 번만 읽는다.
#
# **YAML 전부를 읽지 않는다.** 이 파일들의 모양 — 두 칸씩 들여쓴 `키: 값` —
# 만 읽는다. 목록·여러 줄 값·앵커는 다루지 않으므로 그런 칸을 물으면 빈값이
# 돌아온다. 그 자리는 `-플래그` 로 주는 쪽이 맞다.
function Get-LabConfigValue {
    param(
        # `.cargo` 아래 파일 이름, 확장자 없이 (예: windows_lab)
        [Parameter(Mandatory = $true)] [string] $File,
        # 점으로 이은 칸 이름 (예: windows_lab.network.ip)
        [Parameter(Mandatory = $true)] [string] $Key
    )
    $root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $path = Join-Path $root (Join-Path ".cargo" "$File.yml")
    if (-not (Test-Path $path)) { return $null }

    # 들여쓰기로 칸 이름을 쌓는다. 같거나 더 얕은 줄을 만나면 그만큼 벗는다 —
    # 들여쓰기 폭을 두 칸으로 가정하지 않으려고 깊이가 아니라 **칸 수**로 센다.
    $indents = New-Object System.Collections.Generic.List[int]
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($line in [System.IO.File]::ReadAllLines($path, [System.Text.Encoding]::UTF8)) {
        if ($line -notmatch '^(\s*)([A-Za-z0-9_.\-]+):\s?(.*)$') { continue }
        $indent = $Matches[1].Length
        $name = $Matches[2]
        $value = $Matches[3].Trim()
        while ($indents.Count -gt 0 -and $indents[$indents.Count - 1] -ge $indent) {
            $indents.RemoveAt($indents.Count - 1)
            $names.RemoveAt($names.Count - 1)
        }
        $indents.Add($indent)
        $names.Add($name)
        if ([string]::Join('.', $names) -ne $Key) { continue }
        # 값 자리가 주석뿐이면 값이 없는 것이다. `키:   # 설명` 꼴에서 그 설명을
        # 값으로 읽는 결함이 있었다(2026-10-31 실측 — 목록 칸의 꼬리 주석).
        if ($value.StartsWith('#')) { return $null }
        # 따옴표로 감싼 값은 닫는 따옴표까지가 값이다. 꼬리 주석을 먼저 떼면
        # 값 안의 `#` 를 주석으로 잘못 읽는다.
        if ($value.StartsWith("'") -or $value.StartsWith('"')) {
            $quote = $value[0]
            $end = $value.IndexOf($quote, 1)
            if ($end -lt 1) { return $null }
            return $value.Substring(1, $end - 1)
        }
        $value = ($value -replace '\s+#.*$', '').Trim()
        if ($value -eq '') { return $null }
        return $value
    }
    return $null
}

# 주어진 값 → `.cargo/*.yml` → 멈춤. **조용히 기본값으로 돌지 않는다** —
# 엉뚱한 기계에 파괴적 시험을 돌리는 것보다 멈추는 편이 낫다.
function Resolve-LabValue {
    param(
        [string] $Given,
        [Parameter(Mandatory = $true)] [string] $File,
        [Parameter(Mandatory = $true)] [string] $Key,
        [Parameter(Mandatory = $true)] [string] $Flag
    )
    if ($Given) { return $Given }
    $found = Get-LabConfigValue -File $File -Key $Key
    if ($found) { return $found }
    throw ("$Flag 값을 알 수 없다. -$Flag 로 주거나 .cargo/$File.yml 의 " +
           "'$Key' 에 적을 것 (견본: .cargo/$File.example.yml)")
}

function Test-VmAlive {
    param([string] $Address)
    # -Count 1 은 쓰지 않는다. ARP 해석 등으로 첫 패킷이 곧잘 유실되어 살아 있는
    # VM 을 죽었다고 오보한다 (실측: Test-NetConnection 의 단일 프로브는 False,
    # ping -n 2 는 2/2 응답). 파괴적 테스트 뒤 생사 판단이 이 함수에 걸려 있다.
    $ping = Test-Connection -ComputerName $Address -Count 2 -Quiet -ErrorAction SilentlyContinue
    $port = $false
    try {
        $c = New-Object Net.Sockets.TcpClient
        $port = $c.ConnectAsync($Address, 5985).Wait(2000)
        $c.Close()
    } catch { }
    [pscustomobject]@{ Ping = $ping; WinRM = $port }
}

# **랩 VM 의 주소는 고정이 아니다** (2026-09-10).
#
# 스냅샷을 복원하거나 게스트를 재부팅하면 DHCP 가 다른 주소를 준다. 실제로
# 하루에 세 번 하네스를 세웠다 — `.128` → `.137` → 다시 `.128`. 각 스크립트의
# `-VmAddress` 기본값은 열여섯 곳에 박혀 있어 그때마다 전부 어긋난다.
#
# 그래서 **주어진 주소가 죽어 있을 때만** vmrun 에게 물어본다. 살아 있는
# 주소는 절대 바꾸지 않는다 — 사람이 일부러 다른 기계를 겨눴을 수 있다.
function Find-VmRun {
    $candidates = @(
        "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
        "C:\Program Files\VMware\VMware Workstation\vmrun.exe",
        "C:\Program Files (x86)\VMware\VMware VIX\vmrun.exe"
    )
    $found = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($found) { return $found }
    (Get-Command vmrun -ErrorAction SilentlyContinue).Source
}

# 돌고 있는 게스트의 IP. 찾지 못하면 `$null` — 부르는 쪽이 판단한다.
#
# **돌고 있는 VM 이 정확히 하나일 때만** 고른다. 여럿이면 어느 것이 랩인지
# 알 수 없고, 잘못 고르면 남의 기계에 파괴적 시험을 돌리게 된다.
function Get-LabVmAddress {
    param([string] $Vmx)
    $vmrun = Find-VmRun
    if (-not $vmrun) { return $null }
    if (-not $Vmx) {
        $running = @(& $vmrun -T ws list 2>$null | Where-Object { $_ -match '\.vmx\s*$' })
        if ($running.Count -ne 1) { return $null }
        $Vmx = $running[0].Trim()
    }
    if (-not (Test-Path $Vmx)) { return $null }
    # **종료 코드로 판단하지 않는다.** `Select-Object -First 1` 은 파이프라인을
    # 일찍 끊고, 그러면 네이티브 명령의 `$LASTEXITCODE` 가 -1 이 된다 — 값은
    # 제대로 받아왔는데 가드가 그것을 버렸다(2026-09-10 실측). 배열로 받아
    # 끊지 않고, **값이 IP 모양인지**로 판단한다.
    $ip = @(& $vmrun -T ws getGuestIPAddress $Vmx -wait 2>$null)[0]
    if (-not $ip) { return $null }
    $ip = $ip.Trim()
    if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { return $ip }
    return $null
}

function Get-LabCredential {
    param(
        [string] $VmAddress,
        [pscredential] $Credential,
        [string] $CredStore
    )
    if (-not $Credential -and (Test-Path $CredStore)) {
        # DPAPI 로 현재 사용자·현재 머신에서만 풀린다. 다른 곳으로 복사해도 못 쓴다.
        $Credential = Import-Clixml $CredStore
        if ($Credential.GetNetworkCredential().Password.Length -eq 0) {
            # 쓸 수 없는 캐시는 붙들고 있어 봐야 매번 같은 이유로 실패한다.
            Write-Warn "저장된 자격 증명의 비밀번호가 비어 있다. 캐시를 지우고 다시 묻는다."
            Remove-Item $CredStore -Force -ErrorAction SilentlyContinue
            $Credential = $null
        } else {
            Write-Ok "저장된 자격 증명 사용 ($($Credential.UserName))"
        }
    }
    if (-not $Credential) {
        $Credential = Get-Credential -Message "테스트 VM 관리자 계정 (예: $VmAddress\사용자명)"
    }

    # 빈 비밀번호는 WinRM 에서 그냥 '액세스 거부'로 나온다. 인증 실패인지 권한 문제인지
    # 구분이 안 되는 오류라 원인을 찾는 데 시간이 걸린다. 여기서 미리 끊는다.
    if ($Credential.GetNetworkCredential().Password.Length -eq 0) {
        throw @"
자격 증명의 비밀번호가 비어 있다.
Windows 는 빈 비밀번호 계정의 네트워크 로그온을 기본적으로 금지하므로
(LimitBlankPasswordUse), WinRM 접속이 '액세스 거부'로 막힌다.

계정에 비밀번호가 없다면 VM 콘솔에서 설정할 것:
  Set-LocalUser -Name $($Credential.GetNetworkCredential().UserName) ``
      -Password (Read-Host -AsSecureString '새 비밀번호')

비밀번호는 있는데 입력만 비워 둔 것이라면 다시 실행해서 입력할 것.
"@
    }
    $Credential
}

function Initialize-WinRmClient {
    param([string] $VmAddress)

    # WSMan: 드라이브는 **로컬** WinRM 서비스가 떠 있어야 열린다. 서비스가 멈춰 있으면
    # TrustedHosts 를 읽지도 쓰지도 못하는데, 오류 메시지가 "대상에 연결할 수 없습니다"
    # 라서 VM 문제로 오해하기 딱 좋다. 실제로 그렇게 한 번 헤맸다.
    $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
    if ($winrm -and $winrm.Status -ne "Running") {
        try {
            Start-Service WinRM -ErrorAction Stop
            Write-Ok "호스트 WinRM 서비스 시작"
        } catch {
            throw @"
호스트의 WinRM 서비스를 시작할 수 없다: $($_.Exception.Message)
관리자 PowerShell 로 이 스크립트를 다시 실행하거나, 먼저 아래를 실행할 것:
  Start-Service WinRM
  Set-Service WinRM -StartupType Automatic

winrm quickconfig 는 쓰지 말 것 — 호스트에 리스너를 만들어 원격 접속 대상으로
노출시킨다. 클라이언트로 쓰는 데 필요한 건 서비스 기동뿐이다.
"@
        }
    } else {
        Write-Ok "호스트 WinRM 서비스 실행 중"
    }

    $trusted = ""
    try { $trusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value } catch { }
    $trustedList = @($trusted -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    # `-like` 다. `192.168.249.*` 처럼 대역으로 걸어 둔 항목도 인정해야 한다 —
    # 와일드카드가 없는 항목은 자기 자신하고만 맞으므로 정확 비교를 겸한다.
    # 이것이 없으면 대역을 등록해 둔 사람에게도 매번 개별 IP 추가를 시도하고,
    # 승격이 없으면 거기서 멈춘다.
    if ($trustedList | Where-Object { $VmAddress -like $_ }) {
        Write-Ok "TrustedHosts 에 이미 등록됨"
        return
    }
    # 기존 목록을 덮어쓰지 않고 더한다. 다른 작업용 항목이 있을 수 있다.
    $merged = (@($trustedList) + $VmAddress | Sort-Object -Unique) -join ","
    try {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $merged -Force -ErrorAction Stop
        Write-Ok "TrustedHosts 갱신: $merged"
    } catch {
        # 대역으로 걸어 두기를 권한다. 랩 VM 은 스냅샷 복원·재부팅마다 주소가
        # 바뀌고, 그때마다 이 승격을 다시 요구하면 시험이 그 자리에서 선다.
        $subnet = ($VmAddress -replace '\.\d+$', '.*')
        throw @"
TrustedHosts 에 $VmAddress 를 추가할 수 없다: $($_.Exception.Message)
관리자 PowerShell 에서 한 번만 실행하면 이후 주소가 바뀌어도 다시 필요 없다:
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$subnet' -Force
이 주소만 넣으려면:
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$VmAddress' -Force
"@
    }
}

function Connect-LabVm {
    <#
        VM 에 연결하고 **관리자 권한임을 확인한 세션**을 돌려준다.

        권한 확인까지가 이 함수의 일이다. 권한 없는 세션으로 시험을 시작하면
        remedy 가 전부 '액세스 거부'로 실패하는데, 원인이 remedy 인지 권한인지
        구분할 수 없다. 그런 실행은 시작하지 않는 편이 낫다.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $VmAddress,
        [pscredential] $Credential,
        [switch] $SaveCredential
    )

    $credStore = Join-Path $env:LOCALAPPDATA "remedy-lab\vm-cred.xml"
    $Credential = Get-LabCredential -VmAddress $VmAddress -Credential $Credential -CredStore $credStore

    Write-Step "VM 도달성 확인: $VmAddress"
    $alive = Test-VmAlive $VmAddress
    Write-Host "    ping=$($alive.Ping)  winrm=$($alive.WinRM)"

    # 주어진 주소가 죽어 있을 때만 vmrun 에게 묻는다. 살아 있으면 손대지 않는다.
    #
    # **랩 VM 의 vmx 를 넘긴다** (2026-11-11). 넘기지 않으면 `Get-LabVmAddress` 는 떠 있는 VM 이
    # 하나일 때만 답하는데, 이 기계에는 다른 세션의 VM 도 떠 있어 이 대체가 한 번도 듣지 않았다 —
    # 되돌린 게스트가 DHCP 로 주소를 바꿔 받자 메뉴 하네스가 곧바로 멈췄다.
    if (-not $alive.WinRM) {
        $labVmx = $null
        try { $labVmx = Resolve-LabValue $null 'windows_lab' 'windows_lab.identity.vmx' 'Vmx' } catch { }
        $found = Get-LabVmAddress -Vmx $labVmx
        if ($found -and $found -ne $VmAddress) {
            $alt = Test-VmAlive $found
            if ($alt.WinRM) {
                Write-Warn "$VmAddress 가 응답하지 않는다. vmrun 이 말한 게스트 주소로 바꾼다: $found"
                $VmAddress = $found
                $alive = $alt
            }
        }
    }

    if (-not $alive.WinRM) {
        throw @"
WinRM(5985) 에 접속할 수 없다. VM 콘솔에서 아래를 먼저 실행할 것:
  testbed\harness\guest\Setup-Guest.ps1
"@
    }

    Write-Step "호스트 WinRM 클라이언트 준비"
    Initialize-WinRmClient -VmAddress $VmAddress

    try {
        $session = New-PSSession -ComputerName $VmAddress -Credential $Credential -ErrorAction Stop
    } catch {
        $orig = $_.Exception.Message
        if ($orig -match "Access is denied|액세스가 거부") {
            throw @"
WinRM 접속이 '액세스 거부'로 막혔다. 포트(5985)는 열려 있으므로 인증·권한 문제다.
시도한 계정: $($Credential.UserName)

VM 콘솔에서 아래 세 가지를 확인할 것. 셋 다 같은 오류로 나타난다.

  1) 계정에 비밀번호가 있는가
     빈 비밀번호 계정은 네트워크 로그온이 기본적으로 금지된다.
       Get-LocalUser <계정> | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet
     PasswordLastSet 이 비어 있으면 비밀번호를 설정할 것.

  2) 계정이 Administrators 에 속하는가
       Get-LocalGroupMember -Group Administrators

  3) LocalAccountTokenFilterPolicy 가 1 인가
     워크그룹 PC 에 로컬 관리자 계정으로 원격 접속하면 UAC 가 토큰에서
     Administrators 를 떼어낸다. 그러면 기본 세션 구성의 ACL 검사에서 걸려
     **세션이 열리기도 전에** 거부된다 — 지금 보고 있는 오류가 이것이다.
       Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ``
           -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
     없거나 0 이면:
       New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ``
           -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force
     격리된 테스트 VM 에서는 받아들일 수 있는 완화지만 업무 PC 에는 적용하지 말 것.
     **이 설정은 스냅샷에 들어가야 한다.**

계정 이름은 '$VmAddress\<계정>' 형식으로 입력했는지도 확인할 것.
저장된 자격 증명 삭제: Remove-Item '$credStore'

원본 오류: $orig
"@
        }
        throw
    }
    Write-Ok "세션 연결"

    # 저장은 접속에 성공한 뒤에 한다. 접속 전에 저장하면 틀린 자격 증명이 그대로
    # 남아 다음 실행부터 조용히 재사용되고, 매번 같은 이유로 실패하면서 원인은
    # 화면에 안 보인다.
    if ($SaveCredential) {
        $credDir = Split-Path -Parent $credStore
        if (-not (Test-Path $credDir)) { New-Item -ItemType Directory -Path $credDir -Force | Out-Null }
        $Credential | Export-Clixml $credStore
        Write-Ok "자격 증명 저장: $credStore"
    }

    Write-Step "원격 세션 권한 확인"
    $elev = Invoke-Command -Session $session -ScriptBlock {
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        [ordered]@{
            user     = $wi.Name
            is_admin = (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole(
                           [Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    }
    if (-not $elev.is_admin) {
        Remove-PSSession $session -ErrorAction SilentlyContinue
        throw @"
원격 세션에 관리자 권한이 없다 (사용자: $($elev.user)).
워크그룹 PC 에 로컬 계정으로 접속하면 UAC 가 토큰을 걸러낸다.

VM 콘솔에서 아래를 실행하고 **스냅샷을 다시 찍을 것**:

  New-ItemProperty ``
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ``
    -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force

원격 로컬 관리자 로그온에 완전한 토큰을 준다. 격리된 테스트 VM 에서는
받아들일 수 있는 완화지만, 실제 업무 PC 에는 적용하지 말 것.
"@
    }
    Write-Ok "관리자 권한 ($($elev.user))"
    $session
}

function Assert-StaticBinary {
    <#
        배포 전에 임포트 테이블을 본다.

        정적 CRT 는 플래그 하나로 조용히 빠진다. 실제로 그랬다 — 플래그가
        CI 에만 있어서 로컬 빌드가 전부 동적이었고, **그 바이너리로 VM 검증을
        12/12 통과했다.** 검증은 통과하는데 배포될 물건은 다른 것이었다.

        VM 에는 UCRT 가 있으므로 동적 바이너리도 잘 돈다. 그래서 VM 이
        알려주지 못한다. 여기서 막지 않으면 아무도 막지 않는다.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $RepoRoot,
        [Parameter(Mandatory = $true)][string[]] $Path
    )
    Write-Step "정적 링크 확인"
    Push-Location $RepoRoot
    try {
        # **빌드된 xtask.exe 가 있으면 그것을 직접 부른다.** `cargo xtask` 는
        # 매 호출마다 변경 감지로 재컴파일을 트리거할 수 있고, 그 컴파일 진행
        # 문구가 stderr 로 나와 `$ErrorActionPreference=Stop` 아래에서
        # NativeCommandError 로 스크립트를 죽인다(실측). 산출물을 직접 부르면
        # 컴파일이 끼어들 자리가 없다. 없을 때만 cargo 로 떨어진다.
        $xtaskExe = Join-Path $RepoRoot "target\release\xtask.exe"
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            if (Test-Path $xtaskExe) { & $xtaskExe static @Path }
            else { & cargo xtask static @Path }
        } finally { $ErrorActionPreference = $prev }
        if ($LASTEXITCODE -ne 0) {
            throw @"
배포 바이너리가 정적 링크가 아니다. VM 에 아무것도 배포하지 않는다.

VM 에는 UCRT 가 깔려 있어 동적 바이너리도 잘 돈다 — 그래서 시험은 통과하고
고객 PC 에서만 실행이 안 된다. 지금 막는 편이 낫다.

확인할 것: .cargo/config.toml 의 [target.'cfg(target_env = "msvc")'] rustflags
           RUSTFLAGS 환경변수가 설정되어 있으면 그 설정을 통째로 덮는다.
"@
        }
    } finally { Pop-Location }
}

function Copy-GuestFile {
    <#
        게스트로 파일을 밀어 넣는다. `.ps1` 은 **배포 전에 검사한다.**

        깨진 스크립트를 VM 에서 발견하면 이미 파괴적 실행이 끝난 뒤일 수 있고,
        그러면 테스트 한 판을 통째로 버려야 한다.
    #>
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $Destination
    )
    if (-not (Test-Path $Source)) { throw "원본이 없다: $Source" }
    $leaf = Split-Path -Leaf $Source

    if ($leaf -like "*.ps1") {
        # BOM 이 없으면 Windows PowerShell 5.1 은 .ps1 을 ANSI(CP949) 로 읽는다.
        # 한글 주석의 바이트가 따옴표·괄호로 오독되면서 파싱이 무너진다.
        # 편집기가 BOM 을 떼면 여기서 걸린다.
        $bytes = [System.IO.File]::ReadAllBytes($Source)
        if (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) {
            throw "$leaf 에 UTF-8 BOM 이 없다. PowerShell 5.1 이 CP949 로 오독한다. BOM 을 붙여 저장할 것."
        }
        $perr = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Source, [ref]$null, [ref]$perr)
        if ($perr.Count -gt 0) {
            throw "$leaf 파싱 실패 (L$($perr[0].Extent.StartLineNumber)): $($perr[0].Message)"
        }
    }

    Copy-Item $Source -Destination $Destination -ToSession $Session -Force
    Write-Ok $leaf
}

function Invoke-GuestExe {
    <#
        게스트에서 실행 파일을 돌리고 **종료 코드와 출력을 분리해서** 돌려준다.

        **`&` 로 부르지 않는다.** `$ErrorActionPreference = "Stop"` 아래에서
        네이티브 명령의 stderr 는 종료 오류(NativeCommandError)가 되어 스크립트를
        멈춘다. `2>&1 | Out-String` 으로 병합해 두어도 각 줄이 ErrorRecord 로
        감싸인 채 원격 경계를 넘는다 — 어느 쪽이든 **관측하려던 실패가 관측
        자체를 죽인다.** ProcessStartInfo 로 직접 띄우면 stderr 는 그냥 문자열이다
        (설계-09 P8 의 `Invoke-Exe` 와 같은 이유).

        **종료 코드를 판정하지 않고 돌려준다.** remedy 의 종료 코드는 0/비0 이
        아니라 의미가 갈린다 (설계-02 §8 — 6 은 "수집은 됐으나 관측이 불완전"
        이다). 무엇을 실패로 볼지는 부르는 쪽만 안다. 여기서 `-eq 0` 으로
        접어 버리면 그 구분이 사라진다.

        **`-WorkingDirectory`** — 주면 그 폴더에서 띄운다. 사람은 받은 폴더에서 상대 경로로
        부른다(README 의 명령줄 예시). 주지 않으면 원격 세션의 기본 폴더다(전과 같다).
    #>
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $Path,
        [string[]] $Arguments = @(),
        [string] $WorkingDirectory = ""
    )
    Invoke-Command -Session $Session -ArgumentList $Path, $Arguments, $WorkingDirectory -ScriptBlock {
        param($exe, $argv, $wd)

        # **역슬래시-따옴표 규칙을 지킨다.** Windows CRT 는 `\"` 를 escape 된
        # 따옴표로 읽는다. `C:\dir\` 처럼 역슬래시로 끝나는 값을 그냥 감싸면
        # 닫는 따옴표가 escape 되어 인자 경계가 무너진다 — 경로에 공백이 없으면
        # 우연히 살아남고, 있으면 조용히 깨진다.
        # (MSDN "Parsing C Command-Line Arguments")
        function Quote-Arg {
            param([string] $A)
            if ($A -ne "" -and $A -notmatch '[\s"]') { return $A }
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.Append('"')
            $i = 0
            while ($i -lt $A.Length) {
                $slashes = 0
                while ($i -lt $A.Length -and $A[$i] -eq [char]'\') { $slashes++; $i++ }
                if ($i -eq $A.Length) {
                    [void]$sb.Append('\' * ($slashes * 2))
                } elseif ($A[$i] -eq [char]'"') {
                    [void]$sb.Append('\' * ($slashes * 2 + 1)); [void]$sb.Append('"'); $i++
                } else {
                    [void]$sb.Append('\' * $slashes); [void]$sb.Append($A[$i]); $i++
                }
            }
            [void]$sb.Append('"')
            $sb.ToString()
        }

        if (-not (Test-Path $exe)) { throw "게스트에 실행 파일이 없다: $exe" }

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        $psi.Arguments = (@($argv) | ForEach-Object { Quote-Arg $_ }) -join ' '
        if ($wd) { $psi.WorkingDirectory = $wd }
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        # 하네스는 한국어 문구를 읽는다. 기본 언어는 영어다 (2026-09-06).
        $psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
        # remedy 는 UTF-8 로 쓴다. 진단문이 모지바케가 되면 실패 원인을 읽을 수
        # 없는데, 실패했을 때 필요한 것이 정확히 그 문장이다.
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

        $p = [System.Diagnostics.Process]::Start($psi)
        $p.StandardInput.Close()
        # **읽기를 먼저 걸고 기다린다.** 파이프 버퍼가 차면 자식이 쓰기에서
        # 멈추고, 그 상태의 WaitForExit 는 서로를 기다리며 끝나지 않는다.
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        [pscustomobject]@{ exit = $p.ExitCode; out = $o.Result; err = $e.Result }
    }
}

function Invoke-GuestScript {
    <#
        게스트 스크립트를 powershell.exe 자식 프로세스로 실행한다.

        원격 세션은 VM 의 ExecutionPolicy 를 그대로 따르는데 Windows 클라이언트
        기본값은 Restricted 라 `& script.ps1` 이 PSSecurityException 으로 막힌다.
        자식 프로세스에 -ExecutionPolicy Bypass 를 주면 **VM 의 보안 정책을 건드리지
        않고** 돌릴 수 있다. 하네스가 VM 상태에 덜 기대는 편이 낫다.

        (GPO 로 정책이 강제된 환경에서는 -ExecutionPolicy 인자가 무시된다.
         이 워크그룹 테스트 VM 에는 해당하지 않는다.)
    #>
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $ScriptName,
        [string[]] $Arguments = @(),
        # 스크립트가 의미 있는 종료 코드를 내는 경우. 던지지 않고 코드를 돌려준다.
        [switch] $PassThruExitCode
    )
    # 자식의 출력과 종료 코드를 **구분해서** 돌려받는다. 둘을 같은 스트림에 흘리면
    # 출력 마지막 줄이 종료 코드로 읽히거나, 종료 코드가 출력에 섞여 사라진다.
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($root, $name, $psArgs)
        $path = Join-Path $root "scripts\$name"
        if (-not (Test-Path $path)) { throw "게스트 스크립트가 없다: $path" }
        $all = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $path) + @($psArgs)
        $out = & powershell.exe @all
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = @($out) }
    } -ArgumentList $Root, $ScriptName, $Arguments

    $result.Output | ForEach-Object { Write-Host "    | $_" }
    if ($PassThruExitCode) { return $result.ExitCode }
    if ($result.ExitCode -ne 0) { throw "$ScriptName 실패 (exit $($result.ExitCode))" }
}

# ── 자기무결성 사전 점검 ────────────────────────────────────────────
#
# **서명 없는 릴리스 바이너리는 파괴하지 않는다** (P10-E · 설계-01 D7).
# 하네스는 기본으로 `--release` 를 빌드하므로, P10-E 가 선 날부터 파괴 검사가
# 전부 종료 코드 5 로 깨졌고 **사유는 어디에도 나오지 않았다** — 실측
# (2026-08-28): 30건이 한꺼번에 실패했고 원인을 찾는 데 VM 에 직접 들어가
# 손으로 돌려 봐야 했다.
#
# 여기서 멈추는 것이 요점이다. **재는 것보다 왜 못 재는지 말하는 것이 먼저다.**
#
# 이 함수는 `VmSession.ps1` 에만 있다. 복사본이 갈라지면 다음 사람이 같은 길을
# 처음부터 다시 헤맨다 (이 파일의 존재 이유와 같다).
# 재부팅 뒤에는 **한 번만 시도하면 깨진다.**
#
# 실측(2026-09-02): `Test-VmAlive` 가 WinRM 을 봤다고 한 뒤에도 수십 초 동안
# 연결이 거부됐다. 자동 로그온·RunOnce·서비스 기동이 겹치는 부팅이라 WinRM 이
# 한 번 더 흔들린다. P9 와 P10-F 가 같은 자리에서 같은 이유로 죽었고, **재부팅은
# 그 시험들의 대상이지 잡음이 아니므로** 여기서 포기하면 뒤 검사가 통째로
# 사라진다.
#
# 복사본을 두지 않는다 — 이 파일이 있는 이유와 같다.
# **세션이 열렸다고 쓸 수 있는 것이 아니다** (2026-09-10).
#
# 이 함수는 `Connect-LabVm` 이 던질 때만 다시 걸었다. 그런데 재부팅 직후에는
# 세션이 **열린 뒤 첫 명령에서 죽는다** — 게스트가 아직 서비스를 올리는 중이라
# WinRM 이 세션을 끊고, 그때 `Invoke-Command` 가
# *"I/O 작업이 취소되었습니다"* 로 실패하며 세션 상태가 Broken 이 된다.
#
# P9 이 그 자리에서 넘어졌다: 재부팅 → 재연결 성공 → 곧바로 부른 `verify` 가
# 죽고, 출시 게이트 **G4(재부팅 뒤 재평가)가 한 번도 측정되지 못했다.**
# `Test-VmAlive` 는 ping 과 5985 포트만 보므로 '부팅이 끝났다' 를 말해 주지
# 못한다 — 포트는 서비스가 뜨는 순간 열린다.
#
# 그래서 **사소한 명령을 실제로 돌려 본다.** 한 번이 아니라 간격을 두고 두 번인
# 이유는, 첫 성공 직후 서비스가 재기동해 다음 호출이 죽는 것을 봤기 때문이다.
# 실패하면 그 세션을 버리고 예산 안에서 다시 건다.
function Invoke-CargoBuild {
    <#
        `cargo` 를 부르고 **성공한 회차는 조용히** 지나간다.

        # 왜 출력을 변수로 받는가 (2026-09-13)

        `$ErrorActionPreference = "Continue"` 는 **죽는 것만** 막는다. 그래도
        PowerShell 5.1 은 네이티브 명령의 stderr 를 ErrorRecord 로 감싸 error
        stream 에 흘리고, cargo 는 진행 상황을 전부 stderr 로 쓴다 — 그래서
        **성공한 회차의 출력 끝에도 `NativeCommandError` 덩이가 남는다.**
        한 바퀴를 돌리면 그런 덩이가 셋씩 붙어, 초록 표 아래에 빨간 글씨가
        쌓인 화면이 됐다. 다음 사람은 그것을 실패로 읽는다.

        변수로 받으면 그 stream 을 아예 지나지 않는다. 그리고 **실패했을 때만**
        찍으므로 이유는 오히려 잘 보인다 — 전에는 성공·실패 양쪽이 똑같이
        시끄러워 구분이 되지 않았다.

        # `$LASTEXITCODE` 는 그대로다

        파이프라인이 아니라 **할당**이므로 cargo 의 종료 코드가 그대로 남는다.
        `2>&1 | Out-Null` 로 버리는 것과 다르다 — 그쪽은 실패 이유까지 잃는다.

        .PARAMETER What
            실패 문구에 쓸 이름. `remedy.exe` 처럼 무엇을 짓다 실패했는지.

        .PARAMETER Argv
            `cargo` 뒤에 올 인자. **`[string[]]` 로 받는다** — 단일 원소 배열을
            스칼라로 푸는 PowerShell 의 버릇이 여기서도 인자를 문자 단위로
            쪼갠다.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $What,
        [Parameter(Mandatory = $true)][string[]] $Argv
    )
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = & cargo @Argv 2>&1
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($rc -ne 0) {
        # **실패한 회차는 전부 보여 준다.** 여기서 삼키면 다음 사람이 같은
        # 빌드를 손으로 다시 돌려야 한다.
        $out | ForEach-Object { Write-Host "    $_" }
        throw "$What 빌드 실패 (exit $rc)"
    }
}

function Connect-LabVmRetrying {
    param(
        $VmAddress,
        $Credential,
        [int] $RetrySeconds = 180,
        [int] $IntervalSeconds = 10,
        # 쓸 수 있는지 확인하는 사소한 명령 사이의 간격.
        #
        # # 2026-09-11 의 근거는 오진 위에 서 있었다
        #
        # 이 값은 그날 5→20 으로 넓혔고, 근거는 *"재부팅 직후의 기계는 한동안
        # 계속 흔들린다"* 였다. **그 진단이 틀렸다.** P9 이 재연결에 성공하고
        # 두 번의 확인까지 통과한 뒤 죽은 것은 기계가 흔들려서가 아니라
        # **재부팅 전 OS 에 붙었기** 때문이다 — 하네스가 15초만 자고 "살아났는가"
        # 만 물어 아직 내려가지 않은 기계를 보고 있었다(2026-09-13 에 드러났다).
        #
        # # 진짜 재부팅 뒤를 쟀다 (2026-09-13)
        #
        # 재부팅 3회. **내려간 것을 확인한 뒤**, WinRM 포트가 열린 순간(T0)부터
        # 2초 간격으로 120초씩 세션을 만들고 명령을 던졌다.
        #
        # | 회차 | 내려감 | 포트 열림 | 첫 성공 | 성공/실패 |
        # |---|---|---|---|---|
        # | 1 | 12.3초 | 157.2초 | **+0초** | 59 / **0** |
        # | 2 |  3.0초 | 148.1초 | **+0초** | 59 / **0** |
        # | 3 |  3.1초 | 148.2초 | **+0초** | 59 / **0** |
        #
        # **포트가 열린 순간부터 곧바로 쓸 수 있고, 118초 동안 한 번도 깨지지
        # 않았다.** 40초 증명 창은 막을 것이 없는 40초였다.
        #
        # (덤으로 드러난 것: **내려가는 데 3.0~12.3초로 네 배 흔들린다.** 고정
        # 시간을 자고 "살아났는가" 만 묻는 대기가 왜 어떤 날 맞고 어떤 날
        # 어긋나는지가 이것이다. P9·P10F 는 이제 내려간 것을 먼저 본다.)
        #
        # # 그래도 0 으로 만들지 않는다
        #
        # 세 회차는 전부 **깨끗한** 재부팅이었다. P9 은 치료 뒤 · P10F 는
        # RunOnce 가 도는 재부팅이라 부하가 다르고, 포트만 열리고 잠깐 못 쓰는
        # 창이 그때 있을 수 있다. 5초 × 3 이면 그 창을 잡으면서 부름마다
        # 30초를 돌려준다. **재지 않은 것을 0 으로 만드는 대신, 잰 만큼 줄인다.**
        #
        # P10F 의 `Start-Sleep 45` 는 이 값과 무관하다 — 그쪽은 세션이 아니라
        # **RunOnce 가 로그온 뒤 실제로 돌기를** 기다린다.
        [int] $SettleSeconds = 5,
        # 몇 번 연속 성공해야 '쓸 수 있다' 로 보는가. 셋이면 창이 10초다.
        [int] $Proofs = 3
    )
    $until = (Get-Date).AddSeconds($RetrySeconds)
    while ($true) {
        $s = $null
        try {
            $s = Connect-LabVm -VmAddress $VmAddress -Credential $Credential
            for ($i = 0; $i -lt $Proofs; $i++) {
                if ($i -gt 0) { Start-Sleep -Seconds $SettleSeconds }
                $null = Invoke-Command -Session $s -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            }
            if ($s.State -ne 'Opened') { throw "세션 상태가 $($s.State) 다" }
            return $s
        }
        catch {
            if ($s) { Remove-PSSession $s -ErrorAction SilentlyContinue }
            if ((Get-Date) -ge $until) { throw }
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
}

function Assert-CanDestroy {
    param($Session, [string] $Bin)
    Write-Step "자기무결성 확인 (P10-E — 손댄 바이너리는 파괴하지 않는다)"
    $r = Invoke-Command -Session $Session -ArgumentList $Bin -ScriptBlock {
        param($b)
        $ErrorActionPreference = "Continue"
        $out = & $b resume --help 2>&1
        [pscustomobject]@{ exit = $LASTEXITCODE; text = ($out | Out-String) }
    }
    # **2026-09-02 에 좁아졌다.** 그 전에는 "서명이 없다" 도 잡았다 — 서명 없는
    # 릴리스가 파괴를 거부했기 때문이고, 그래서 이 하네스들이 `-DevBuild` 로만
    # 돌 수 있었다. 지금은 서명 없음이 막지 않으므로 **손댄 것만** 남는다.
    #
    # 그 문구는 이제 정상 실행의 알림이라, 그대로 두면 이 가드가 멀쩡한
    # 바이너리를 거부한다.
    if ($r.text -match "신뢰할 수 없") {
        throw @"
이 바이너리는 파괴를 하지 않는다 — **서명해 둔 뒤 내용이 바뀌었다** (P10-E).

  $($r.text.Trim())

부분 다운로드·디스크 손상·변조 중 하나다. 배포처에서 원본을 다시 받을 것.
"@
    }
    Write-Ok "파괴 가능한 상태"
}

# ── 찾기만 하는 실험 룰 ─────────────────────────────────────────────
#
# 룰 폴더를 베껴 `remediate` 절을 빼고 id · 이름을 바꾼다 — 같은 것을 보되 치료하지 않는 룰이다.
# 꾸러미에 룰이 둘이어야 서는 화면(고르는 화면의 *모두 검사만* · 찾기만 하는 룰의 메뉴)을 재는
# 자리가 쓴다(`Invoke-MenuVerify.ps1` · `Capture-Console.ps1`). 서명은 부르는 쪽이 그 회차의
# 일회용 키로 한다. 배포 키로 서명하지 않는다 — 배포물에 섞이면 안 되는 물건이다.
function New-DetectOnlyLabRule {
    param(
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $Out,
        [string] $Id = "remedy-lab-evilai-check",
        [string] $NameKo = "EvilAI(Locust) 점검 (실험 · 탐지만)",
        [string] $NameEn = "EvilAI (Locust) check (lab, detect only)"
    )
    Copy-Item $Source $Out -Recurse -Force
    $yaml = [System.IO.File]::ReadAllLines((Join-Path $Out "plugin.yaml"))
    $kept = New-Object System.Collections.Generic.List[string]
    $skip = $false
    $inName = $false
    foreach ($l in $yaml) {
        if ($l -match '^remediate:') { $skip = $true; continue }
        if ($skip -and $l -match '^[a-z_]+:') { $skip = $false }
        if ($skip) { continue }
        if ($l -match '^id:') { $l = "id: $Id" }
        if ($l -match '^name:') { $inName = $true }
        elseif ($inName -and $l -match '^\s+ko:') { $l = "  ko: `"$NameKo`"" }
        elseif ($inName -and $l -match '^\s+en:') { $l = "  en: `"$NameEn`"" }
        elseif ($l -match '^[a-z_]+:') { $inName = $false }
        $kept.Add($l)
    }
    [System.IO.File]::WriteAllLines((Join-Path $Out "plugin.yaml"), $kept,
                                    (New-Object System.Text.UTF8Encoding($false)))
}
