<#
.SYNOPSIS
    AI 시험 위협의 감염 상태를 **진짜 Windows 위에** 세운다 (설계-09 P12 후속).

.DESCRIPTION
    Linux 쪽 `linux/new-threat-fixtures.sh` 의 Windows 짝이다.

    # 왜

    위협 폴더의 `infected/*.json` 이 전부 손으로 쓴 것이었다. 그런 스냅샷은
    **다시 뜰 수 없고, 실기기가 낼 수 없는 모양을 담을 수 있다.** 둘 다 이미
    일어났다:

      - `search-hijack` 이 프로세스 명령줄을 비웠다 (2026-09-03 정정).
      - `tls-intercept` 이 인증서 저장소 이름을 틀리게 적었고, 우리 정답
        플러그인이 그 거짓 값에 맞춰져 실기기에서 위협을 놓쳤다 (2026-09-04).
      - `service-userinit` 이 서비스 상태를 `running`·`stopped`, 시작 유형을
        `demand` 라 적는다. **수집기는 그런 값을 낸 적이 없다** — 실행 여부는
        레지스트리에 없어 언제나 `unknown` 이고, `Start=3` 은 `manual` 이다.

    # 되돌릴 수 있어야 한다

    이 스크립트는 `AppInit_DLLs` · `Userinit` · `BootExecute` · `Path` 를
    만진다. **틀리면 기계가 로그온되지 않는다.** 그래서 바꾸기 전에 전부
    `threat-backup-<위협>.json` 에 담고, `-Clean` 이 그것으로 되돌린다.

    백업 파일은 **덮어쓰지 않는다.** 두 번째 생성이 감염 상태를 원본으로
    담아 버리면 되돌릴 곳이 없어진다.

    재부팅하지 않는다. 값을 세우고 수집한 뒤 곧바로 되돌리므로 창이 초 단위다.

.PARAMETER Threat
    appinit-implant | service-userinit | search-hijack

.PARAMETER Clean
    백업으로 되돌리고 만든 것을 지운다.

.EXAMPLE
    .\New-ThreatFixtures.ps1 -Threat service-userinit
    .\New-ThreatFixtures.ps1 -Threat service-userinit -Clean
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('appinit-implant', 'service-userinit', 'search-hijack', 'ransomware', 'webshell-upload', 'proxy-dns-hijack', 'shortcut-hijack', 'cred-dump', 'regkey-stager', 'sideload-drop', 'hook-implant')]
    [string] $Threat,
    [switch] $Clean,
    [string] $LabRoot = "C:\remedy-lab"
)

$ErrorActionPreference = "Stop"

$MARK = "REMEDY AI-EXAM FIXTURE. 실행되지 않는 자리 채우기다."
$BackupPath = Join-Path $LabRoot "threat-backup-$Threat.json"

# 검체가 놓인 시각. **고정한다** — 스냅샷이 커밋되므로 뜰 때마다 달라지면
# diff 가 뜻을 잃는다. `CreationTime` 은 파일을 다시 만들 때마다 지금이 되는데
# 그것은 기계의 사실이라 감추지 않는다.
$Drop = @{
    'appinit-implant'  = [datetime]::Parse('2026-08-29T03:44:12Z').ToUniversalTime()
    'service-userinit' = [datetime]::Parse('2026-08-25T04:12:55Z').ToUniversalTime()
    'search-hijack'    = [datetime]::Parse('2026-08-30T11:02:44Z').ToUniversalTime()
    'ransomware'       = [datetime]::Parse('2026-09-18T22:07:31Z').ToUniversalTime()
    'webshell-upload'  = [datetime]::Parse('2026-09-20T14:33:19Z').ToUniversalTime()
    'proxy-dns-hijack' = [datetime]::Parse('2026-09-17T09:26:04Z').ToUniversalTime()
    'shortcut-hijack'  = [datetime]::Parse('2026-09-16T13:48:52Z').ToUniversalTime()
    'cred-dump'        = [datetime]::Parse('2026-09-14T02:35:41Z').ToUniversalTime()
    'regkey-stager'    = [datetime]::Parse('2026-09-11T20:14:06Z').ToUniversalTime()
    'sideload-drop'    = [datetime]::Parse('2026-09-19T21:40:33Z').ToUniversalTime()
    'hook-implant'     = [datetime]::Parse('2026-09-08T04:11:02Z').ToUniversalTime()
}[$Threat]
$Clean1 = [datetime]::Parse('2025-12-03T08:20:41Z').ToUniversalTime()

# ── 정해진 크기의 파일을 정해진 내용으로 ────────────────────────────
#
# 표시 문자열을 앞에 두고 나머지를 0 으로 늘린다. 내용이 정해져야 sha256 이
# 재현되고, 재현되어야 스냅샷을 다시 떠도 같은 것이 나온다.
function New-PaddedFile {
    param([string] $Path, [int] $Size, [string] $Note, [datetime] $When)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, "$MARK  $Note`r`n", [System.Text.UTF8Encoding]::new($false))
    $fs = [System.IO.File]::Open($Path, 'Open', 'Write')
    try { $fs.SetLength($Size) } finally { $fs.Close() }
    (Get-Item $Path).LastWriteTimeUtc = $When
}

# 실행되는 페이로드. **진짜로 떠야 프로세스 레코드가 생긴다.**
#
# PE 뒤에 붙은 바이트는 로더가 무시하므로, 실행 파일을 복사한 뒤 정해진 크기로
# 늘려도 그대로 실행된다(실측 2026-09-04, Win10 랩 VM).
function New-RunnablePayload {
    param([string] $Path, [int] $Size, [datetime] $When)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item "$env:SystemRoot\System32\ping.exe" $Path -Force
    $fs = [System.IO.File]::Open($Path, 'Open', 'Write')
    try { $fs.SetLength($Size) } finally { $fs.Close() }
    (Get-Item $Path).LastWriteTimeUtc = $When
}

# ── 레지스트리 백업·복원 ────────────────────────────────────────────
$script:Backup = @()

function Backup-RegValue {
    param([string] $Key, [string] $Name)
    $item = Get-Item -LiteralPath $Key -ErrorAction SilentlyContinue
    $present = $false; $data = $null; $kind = $null
    if ($item -and ($item.GetValueNames() -contains $Name)) {
        $present = $true
        $data = $item.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
        $kind = $item.GetValueKind($Name).ToString()
    }
    $script:Backup += [pscustomobject]@{
        kind_of = 'reg'; key = $Key; name = $Name
        present = $present; value = $data; kind = $kind
    }
}

function Restore-RegValue {
    param($Entry)
    if ($Entry.present) {
        # **원래 형을 지켜 되돌린다.** REG_EXPAND_SZ 를 REG_SZ 로 돌려놓으면
        # `%SystemRoot%` 가 펼쳐지지 않아 경로가 죽는다.
        New-ItemProperty -LiteralPath $Entry.key -Name $Entry.name -Value $Entry.value `
            -PropertyType $Entry.kind -Force | Out-Null
    } else {
        Remove-ItemProperty -LiteralPath $Entry.key -Name $Entry.name -Force -ErrorAction SilentlyContinue
    }
}

function Save-Backup {
    if (-not (Test-Path $LabRoot)) { New-Item -ItemType Directory -Path $LabRoot -Force | Out-Null }
    # **덮어쓰지 않는다.** 두 번째 생성이 감염 상태를 원본으로 담으면
    # 되돌릴 곳이 없어진다.
    if (Test-Path $BackupPath) {
        Write-Host "    주의 백업이 이미 있다 — 덮어쓰지 않는다: $BackupPath"
        return
    }
    $script:Backup | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $BackupPath -Encoding UTF8
}

function Invoke-Restore {
    if (-not (Test-Path $BackupPath)) { return }
    $entries = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($e in @($entries)) {
        if ($e.kind_of -ne 'reg') { continue }
        try { Restore-RegValue $e } catch { Write-Host "    주의 되돌리기 실패: $($e.key)\$($e.name) — $_" }
    }
    Remove-Item -LiteralPath $BackupPath -Force -ErrorAction SilentlyContinue
    Write-Host "    OK   레지스트리를 되돌렸다"
}

function Remove-Tree {
    param([string] $Path)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Remove-LabService {
    param([string] $Name)
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
        & sc.exe stop $Name 2>&1 | Out-Null
        & sc.exe delete $Name 2>&1 | Out-Null
    }
}

$WINKEY  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
$WINLOG  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$SESSMGR = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$SESSENV = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$INETSET = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

# ════════════════════════════════════════════════════════════════════
# appinit-implant — 모든 프로세스에 붙는 주입 값
# ════════════════════════════════════════════════════════════════════
function Build-AppInit {
    New-PaddedFile "C:\ProgramData\SvcAssist\svcassist.exe" 1876992 "svcassist.exe" $Drop
    New-PaddedFile "C:\ProgramData\SvcAssist\sahook.dll"     245760 "sahook.dll"    $Drop
    # 정상 벤더 소프트웨어. 남아야 한다.
    New-PaddedFile "C:\ProgramData\Acme\Agent\agent.exe"    3312640 "agent.exe (정상)" $Clean1

    # 설정 파일 — **검체가 넣은 키 하나와 원래 있던 키 셋**이 한 파일에 있다.
    $cfg = @'
{
  "endpoint": "https://agent.acme.example/v2",
  "intervalSeconds": 900,
  "modules": {
    "inventory": "C:\\ProgramData\\Acme\\Agent\\modules\\inventory.dll",
    "remote": "C:\\ProgramData\\SvcAssist\\sahook.dll"
  }
}
'@
    [System.IO.File]::WriteAllText("C:\ProgramData\Acme\Agent\agent-config.json", $cfg,
        [System.Text.UTF8Encoding]::new($false))
    (Get-Item "C:\ProgramData\Acme\Agent\agent-config.json").LastWriteTimeUtc = $Clean1

    # **여기부터 되돌려야 하는 것들이다.**
    Backup-RegValue $WINKEY 'AppInit_DLLs'
    Backup-RegValue $WINKEY 'LoadAppInit_DLLs'
    Save-Backup

    New-ItemProperty -LiteralPath $WINKEY -Name 'AppInit_DLLs' `
        -Value 'C:\ProgramData\SvcAssist\sahook.dll' -PropertyType String -Force | Out-Null
    New-ItemProperty -LiteralPath $WINKEY -Name 'LoadAppInit_DLLs' `
        -Value 1 -PropertyType DWord -Force | Out-Null

    # 방화벽 규칙 둘. 하나는 검체, 하나는 정상 벤더의 것이다.
    Remove-NetFirewallRule -Name 'SvcAssist-In-TCP'  -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -Name 'AcmeAgent-Out-TCP' -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name 'SvcAssist-In-TCP' -DisplayName 'SvcAssist Remote' `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5988 `
        -Program 'C:\ProgramData\SvcAssist\svcassist.exe' `
        -Profile Domain, Private, Public -Enabled True | Out-Null
    New-NetFirewallRule -Name 'AcmeAgent-Out-TCP' -DisplayName 'Acme Agent Update' `
        -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443 `
        -Program 'C:\ProgramData\Acme\Agent\agent.exe' `
        -Profile Domain, Private -Enabled True | Out-Null
}

function Clear-AppInit {
    Invoke-Restore
    Remove-NetFirewallRule -Name 'SvcAssist-In-TCP'  -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -Name 'AcmeAgent-Out-TCP' -ErrorAction SilentlyContinue
    Remove-Tree "C:\ProgramData\SvcAssist"
    Remove-Tree "C:\ProgramData\Acme"
}

# ════════════════════════════════════════════════════════════════════
# service-userinit — 서비스와 로그온 경로
# ════════════════════════════════════════════════════════════════════
function Build-ServiceUserinit {
    New-PaddedFile "C:\ProgramData\SvcHostCache-3f8a\svc.exe"  219136 "svc.exe"  $Drop
    New-PaddedFile "C:\ProgramData\SvcHostCache-3f8a\cache.db"   8192 "cache.db" $Drop
    New-PaddedFile "C:\ProgramData\Acme\updater.exe"          1048576 "updater.exe (정상)" $Clean1

    # **서비스를 시작하지 않는다.** 진짜 서비스 바이너리가 아니라 시작이
    # 실패한다. 수집기는 레지스트리만 보므로 상태는 어차피 `unknown` 이다 —
    # 그것이 이 위협의 산출물이기도 하다.
    Remove-LabService 'SvcHostCache'
    Remove-LabService 'AcmeUpdater'
    New-Service -Name 'SvcHostCache' -DisplayName 'Host Cache Service' `
        -BinaryPathName 'C:\ProgramData\SvcHostCache-3f8a\svc.exe' -StartupType Automatic | Out-Null
    # 정상 벤더 서비스. **수동 시작이고 로그온 값을 건드리지 않는다.**
    New-Service -Name 'AcmeUpdater' -DisplayName 'Acme Update Service' `
        -BinaryPathName 'C:\ProgramData\Acme\updater.exe' -StartupType Manual | Out-Null

    # **여기가 브릭 위험이다.** 원래 값을 담고 나서 바꾼다.
    Backup-RegValue $WINLOG 'Userinit'
    Save-Backup
    $cur = (Get-ItemProperty -LiteralPath $WINLOG).Userinit
    if ($cur -notlike '*SvcHostCache-3f8a*') {
        Set-ItemProperty -LiteralPath $WINLOG -Name 'Userinit' `
            -Value ($cur + 'C:\ProgramData\SvcHostCache-3f8a\svc.exe')
    }
}

function Clear-ServiceUserinit {
    Invoke-Restore
    Remove-LabService 'SvcHostCache'
    Remove-LabService 'AcmeUpdater'
    Remove-Tree "C:\ProgramData\SvcHostCache-3f8a"
    Remove-Tree "C:\ProgramData\Acme"
}

# ════════════════════════════════════════════════════════════════════
# search-hijack — 검색 가로채기 광고 임플란트
# ════════════════════════════════════════════════════════════════════
$EVIL_EXT  = 'pknbjlbmgcodmfilnjadgpkcnkmlpkkn'
$GOOD_CHR  = 'ghbmnnjooekpmoecnnnilnnbdlolhkhi'
$GOOD_EDG  = 'jmjflgjpcpepeafmmgdpfkogkghcpiha'
$CHROME_EX = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
$EDGE_EX   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"

function New-Extension {
    param([string] $Root, [string] $Id, [string] $Version, [string] $Name, [datetime] $When)
    $dir = Join-Path $Root "$Id\${Version}_0"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $m = "{ ""manifest_version"": 3, ""name"": ""$Name"", ""version"": ""$Version"" }"
    [System.IO.File]::WriteAllText((Join-Path $dir 'manifest.json'), $m,
        [System.Text.UTF8Encoding]::new($false))
    (Get-Item (Join-Path $dir 'manifest.json')).LastWriteTimeUtc = $When
}

function Build-SearchHijack {
    # **wbsvc.exe 는 진짜로 돈다.** 프로세스 레코드가 없으면 되돌릴 수 없는
    # Op(`process.kill`)이 계획되지 않는다.
    New-RunnablePayload "C:\ProgramData\WebBoost\wbsvc.exe" 1245184 $Drop
    New-PaddedFile      "C:\ProgramData\WebBoost\wbboot.exe" 172032 "wbboot.exe" $Drop

    New-Extension $CHROME_EX $EVIL_EXT '3.2.0'   'WebBoost Search' $Drop
    New-Extension $EDGE_EX   $EVIL_EXT '3.2.0'   'WebBoost Search' $Drop
    # 정상 확장 둘. **같은 자리에 살고 남아야 한다.**
    New-Extension $CHROME_EX $GOOD_CHR '1.109.1' '__MSG_extName__' $Clean1
    New-Extension $EDGE_EX   $GOOD_EDG '1.2.1'   'Edge relevant text changes' $Clean1

    Backup-RegValue $SESSMGR 'BootExecute'
    Backup-RegValue $SESSENV 'Path'
    Backup-RegValue $INETSET 'ProxyServer'
    Backup-RegValue $INETSET 'ProxyEnable'
    Save-Backup

    # 부팅 목록 — 원래 있던 항목 뒤에 하나만 잇는다.
    $boot = @((Get-ItemProperty -LiteralPath $SESSMGR).BootExecute)
    if ($boot -notcontains 'wbboot.exe') {
        Set-ItemProperty -LiteralPath $SESSMGR -Name 'BootExecute' `
            -Value ([string[]]($boot + 'wbboot.exe'))
    }

    # 경로 목록 — **앞에 끼워 넣는다.** 통째로 지우면 기계가 명령 하나도
    # 찾지 못한다는 것이 이 위협의 요점이다.
    $item = Get-Item -LiteralPath $SESSENV
    $path = $item.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    if ($path -notlike 'C:\ProgramData\WebBoost;*') {
        New-ItemProperty -LiteralPath $SESSENV -Name 'Path' `
            -Value ("C:\ProgramData\WebBoost;" + $path) `
            -PropertyType $item.GetValueKind('Path').ToString() -Force | Out-Null
    }

    New-ItemProperty -LiteralPath $INETSET -Name 'ProxyServer' -Value '127.0.0.1:8899' `
        -PropertyType String -Force | Out-Null
    New-ItemProperty -LiteralPath $INETSET -Name 'ProxyEnable' -Value 1 `
        -PropertyType DWord -Force | Out-Null

    # **핸들을 물려주지 않고 띄운다.**
    #
    # `Start-Process` 로 띄우면 자식이 부모의 stdout 파이프를 물려받는다.
    # 이 스크립트는 `Invoke-Command` 안에서 `powershell.exe -File` 로 불리므로,
    # 그 파이프를 영원히 도는 프로세스가 붙들면 **원격 호출이 EOF 를 보지 못해
    # 그대로 멈춘다** (2026-09-04 실측: 하네스가 이 자리에서 걸렸다).
    #
    # `Win32_Process.Create` 는 아무 핸들도 물려주지 않는 새 프로세스를 만든다.
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine = '"C:\ProgramData\WebBoost\wbsvc.exe" -t 127.0.0.1'
    }
    if ($r.ReturnValue -ne 0) { Write-Host "    주의 프로세스 생성 실패 (코드 $($r.ReturnValue))" }
    # 프로세스 표에 올라오기를 기다린다. 안 올라오면 process.kill 이 0건이 되고,
    # 그 0건은 "죽였다" 가 아니라 "잴 것이 없었다" 다.
    for ($i = 0; $i -lt 20; $i++) {
        if (Get-Process -Name 'wbsvc' -ErrorAction SilentlyContinue) { break }
        Start-Sleep -Milliseconds 200
    }
}

function Clear-SearchHijack {
    Get-Process -Name 'wbsvc' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
    Invoke-Restore
    Remove-Tree "C:\ProgramData\WebBoost"
    foreach ($p in @("$CHROME_EX\$EVIL_EXT", "$EDGE_EX\$EVIL_EXT",
                     "$CHROME_EX\$GOOD_CHR", "$EDGE_EX\$GOOD_EDG")) { Remove-Tree $p }
}

# ════════════════════════════════════════════════════════════════════
# ransomware — 암호화는 이미 끝났고, 남은 것은 되돌릴 수 있는 자리뿐
# ════════════════════════════════════════════════════════════════════
#
# **이 위협이 앞의 아홉과 다른 점은 "지우면 안 되는 것" 에 있다.**
#
# 검체가 암호화한 사용자 문서(`*.locked`)는 **사용자의 데이터**다. 키가 없어
# 지금은 못 풀지만 나중에 복호화기가 나올 수 있고, 치료 도구가 그것을 지우면
# 그 가능성까지 사라진다. 그래서 몸값 노트는 치우고 `*.locked` 는 남긴다 —
# **둘이 같은 폴더에 있다.** 폴더로 가르는 답안은 여기서 사용자 문서를 지운다.
#
# 되돌릴 수 없는 것이 셋 있고 전부 THREAT.md 의 '치료 범위 밖' 이다:
#   · 그림자 복사본 삭제 — 이미 일어난 일이다. 픽스처가 만들지 않는다
#   · 원본 문서의 암호화 — 키가 없으면 못 푼다. 픽스처가 만들지 않는다
#   · **바탕화면** — 픽스처가 만든다. 청정 기계에 있던 값을 검체가 덮어썼고
#     원래 값이 어디에도 없다. 아래 `Wallpaper` 자리의 주석을 볼 것
#
# 프로세스는 두지 않는다. 랜섬웨어는 암호화를 마치면 끝나고, 되살리는 것은
# 아래 Run 값이다.
$RANSOM_DIR = "C:\ProgramData\CryptoSvc"
$DOCS       = "$env:USERPROFILE\Documents"
$DESK       = "$env:USERPROFILE\Desktop"
$DESKKEY    = 'HKCU:\Control Panel\Desktop'
$RUNKEY     = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$POLKEY     = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

function Build-Ransomware {
    New-PaddedFile "$RANSOM_DIR\locker.exe" 421888 "locker.exe" $Drop
    New-PaddedFile "$RANSOM_DIR\keys.bin"    16384 "keys.bin"   $Drop
    # 정상 벤더 프로그램. 같은 깊이에 있다. 남아야 한다.
    New-PaddedFile "C:\ProgramData\VendorTool\vendor.exe" 622592 "vendor.exe (정상)" $Clean1

    # 몸값 노트 둘. 사용자에게 보이는 협박문이고 검체의 것이라 치워야 한다.
    $note = @'
YOUR FILES HAVE BEEN ENCRYPTED.
To recover them you must obtain the private key held by the operator.
Contact: recovery-desk@example.invalid    ID: 7F3A-99C1-0E42
Do not rename or delete the .locked files - they cannot be recovered without the key.
'@
    foreach ($d in @($DOCS, $DESK)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        [System.IO.File]::WriteAllText("$d\HOW-TO-DECRYPT.txt", $note,
            [System.Text.UTF8Encoding]::new($false))
        (Get-Item "$d\HOW-TO-DECRYPT.txt").LastWriteTimeUtc = $Drop
    }

    # 암호화된 사용자 문서 둘. **남아야 한다.** 몸값 노트와 같은 폴더다.
    New-PaddedFile "$DOCS\report.docx.locked" 48128 "report.docx.locked (사용자 데이터)" $Drop
    New-PaddedFile "$DOCS\budget.xlsx.locked" 27648 "budget.xlsx.locked (사용자 데이터)" $Drop
    # 암호화를 면한 정상 문서. 남아야 한다.
    New-PaddedFile "$DOCS\notes.txt"           4096 "notes.txt (정상)" $Clean1

    # **되돌려야 하는 값 넷.**
    if (-not (Test-Path $POLKEY)) { New-Item -Path $POLKEY -Force | Out-Null }
    Backup-RegValue $DESKKEY 'Wallpaper'
    Backup-RegValue $RUNKEY  'CryptoSvc'
    Backup-RegValue $POLKEY  'DisableTaskMgr'
    Backup-RegValue $POLKEY  'HideFastUserSwitching'
    Save-Backup

    # 바탕화면을 몸값 그림으로 바꾼다.
    #
    # **이 자리는 치료 대상이 아니다.** 청정 기계에 이미 값이 있었고(랩 VM 은
    # `C:\Users\test\Downloads\R.jpg`) 검체가 그것을 덮어썼다. 지우면 OS 가
    # 기본 배경을 쓰지만 **사용자가 쓰던 배경은 돌아오지 않는다** — 원래 값을
    # 아무도 갖고 있지 않기 때문이다. 기본값 카탈로그도 이 자리를 모른다
    # (아는 것은 `AppInit_DLLs` 와 `LoadAppInit_DLLs` 둘뿐).
    #
    # 2026-09-21 채점 5 가 그것을 잡았다: 값을 지우는 계획으로 돌렸더니
    # `범위 안 불일치 1건 — 청정: R.jpg · 치료: (값 없음)` 으로 불합격했다.
    # THREAT.md 의 '치료 범위 밖' 셋째가 이것이다.
    New-ItemProperty -LiteralPath $DESKKEY -Name 'Wallpaper' `
        -Value "$RANSOM_DIR\ransom.bmp" -PropertyType String -Force | Out-Null

    # 재부팅하면 다시 돈다.
    New-ItemProperty -LiteralPath $RUNKEY -Name 'CryptoSvc' `
        -Value "`"$RANSOM_DIR\locker.exe`" --resume" -PropertyType String -Force | Out-Null

    # 작업 관리자 잠금. **검체가 새로 만든 값**이라 지우는 것이 원상복구다 —
    # 청정 기계에는 이 값이 없다. 락커가 실제로 하는 짓이기도 하다.
    New-ItemProperty -LiteralPath $POLKEY -Name 'DisableTaskMgr' `
        -Value 1 -PropertyType DWord -Force | Out-Null

    # 같은 정책 키의 정상 값. 조직이 설정해 둔 것으로 **남아야 한다** —
    # 키를 통째로 지우는 답안이 여기서 걸린다.
    New-ItemProperty -LiteralPath $POLKEY -Name 'HideFastUserSwitching' `
        -Value 1 -PropertyType DWord -Force | Out-Null
}

function Clear-Ransomware {
    Invoke-Restore
    Remove-Tree $RANSOM_DIR
    Remove-Tree "C:\ProgramData\VendorTool"
    foreach ($p in @("$DOCS\HOW-TO-DECRYPT.txt", "$DESK\HOW-TO-DECRYPT.txt",
                     "$DOCS\report.docx.locked", "$DOCS\budget.xlsx.locked",
                     "$DOCS\notes.txt")) {
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    }
}

# ════════════════════════════════════════════════════════════════════
# webshell-upload — 업로드 폴더에 실행 가능한 스크립트가 있다
# ════════════════════════════════════════════════════════════════════
#
# **자리와 종류의 조합으로만 갈린다.** 둘 중 하나만 보는 답안은 반드시
# 정상 파일을 건드린다:
#
#   종류만 본다 (`**\*.aspx`)   -> Default.aspx · App\Handlers\Upload.aspx 가 걸린다
#   자리만 본다 (`uploads\**`)  -> 올라온 이미지·PDF 가 걸린다
#
# 웹셸 둘 중 하나는 **하위 폴더**(`uploads\2026-09\`)에 있다. 한 단계만 보는
# 패턴은 그것을 놓친다 — 여러 성분을 건너뛰는 자리가 필요하다.
#
# # IIS 가 설치되지 않은 기계에서도 선다
#
# 이 위협은 파일 시스템의 문제라 웹 서버가 돌 필요가 없다. 다만 **정리할 때
# `C:\inetpub` 와 `wwwroot` 를 지우지 않는다** — IIS 가 설치된 기계에서
# 그것을 지우면 픽스처가 기계를 망가뜨린다. 우리가 만든 파일과, 그래서 비게
# 된 폴더만 지운다.
$WEB      = "C:\inetpub\wwwroot"
$WEB_UP   = "$WEB\uploads"
$WEB_UP9  = "$WEB\uploads\2026-09"
$WEB_APP  = "$WEB\App"
$WEB_HDL  = "$WEB\App\Handlers"

function Build-Webshell {
    # ── 검체 둘 ─────────────────────────────────────────────────
    #
    # 웹셸은 작다. 그러나 **크기로 가르면 안 된다** — 큰 웹셸을 놓치고,
    # 작은 정상 파일을 잡는다. 여기서 크기는 사실일 뿐 근거가 아니다.
    New-PaddedFile "$WEB_UP\sess_7f3a9c.aspx"  1024 "sess_7f3a9c.aspx" $Drop
    New-PaddedFile "$WEB_UP9\.thumb.aspx"       768 ".thumb.aspx"      $Drop

    # ── 같은 종류의 정상 파일 — 자리가 다르다 ───────────────────
    New-PaddedFile "$WEB\Default.aspx"          12288 "Default.aspx (정상)"        $Clean1
    New-PaddedFile "$WEB_HDL\Upload.aspx"        7168 "Upload.aspx (정상 핸들러)"  $Clean1
    New-PaddedFile "$WEB_APP\Web.config"         2048 "Web.config (정상 설정)"     $Clean1

    # ── 같은 자리의 정상 파일 — 종류가 다르다 ───────────────────
    New-PaddedFile "$WEB_UP\avatar-8821.png"          65536 "avatar-8821.png (정상 업로드)"      $Clean1
    New-PaddedFile "$WEB_UP\quarterly-report.pdf"    262144 "quarterly-report.pdf (정상 업로드)" $Clean1
    New-PaddedFile "$WEB_UP9\receipt-441.jpg"        131072 "receipt-441.jpg (정상 업로드)"      $Clean1
}

# ════════════════════════════════════════════════════════════════════
# proxy-dns-hijack — 이름 풀이와 나가는 길을 함께 돌렸다
# ════════════════════════════════════════════════════════════════════
#
# **`hosts` 를 Windows 에서 처음 밟는 위협이다.** 리눅스 쪽 `tls-intercept` 가
# `/etc/hosts` 를 밟고 있었지만 Windows 재료에는 그 자리가 없었고, 그래서
# 채점기도 `line=` 매치를 볼 줄 몰랐다(2026-09-21 에 더했다).
#
# # hosts 는 백업하고 되돌린다
#
# 이 파일이 틀어지면 **기계의 이름 풀이가 망가진다.** 그래서 바꾸기 전에
# 통째로 복사해 두고 정리에서 되돌린다. 그리고 **원본 바이트를 건드리지
# 않는다** — 읽어서 다시 쓰면 인코딩이 바뀌어 주석 줄이 깨질 수 있으므로,
# 바이트로 읽어 뒤에 ASCII 를 잇기만 한다.
#
# # 줄 셋을 잇는다 — 하나는 정상이다
#
# 조직이 손으로 넣은 줄이 없으면 *"지우면 안 되는 것이 섞여 있다"* 를 잴 수
# 없다. `tls-intercept` 가 같은 까닭으로 사내 서버 줄을 하나 둔다.
$HOSTS     = "$env:SystemRoot\System32\drivers\etc\hosts"
$HOSTS_BAK = "$LabRoot\hosts.orig"
$PDNS_DIR  = "C:\ProgramData\NetOpt"
$PDNS_GOOD = "C:\ProgramData\NetTools"

function Build-ProxyDns {
    # **먼저 백업한다.** 이 줄이 실패하면 아래로 내려가지 않는다.
    if (-not (Test-Path $HOSTS_BAK)) {
        $d = Split-Path -Parent $HOSTS_BAK
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        Copy-Item -LiteralPath $HOSTS -Destination $HOSTS_BAK -Force
    }

    New-PaddedFile "$PDNS_DIR\netopt.exe" 1245184 "netopt.exe" $Drop
    # 정상 네트워크 도구. 검체와 같은 `C:\ProgramData` 아래 산다.
    New-PaddedFile "$PDNS_GOOD\latency-probe.exe" 331776 "latency-probe.exe (정상)" $Clean1

    # hosts 에 줄 셋. **첫 줄은 정상이고 남아야 한다.**
    $add = "192.168.10.14`tbuildserver buildserver.corp.example`r`n" +
           "10.20.30.40`tupdate.microsoft.com`r`n" +
           "10.20.30.40`tlogin.bank-example.co.kr`r`n"
    $bytes = [System.IO.File]::ReadAllBytes($HOSTS)
    # 원본이 개행으로 끝나지 않으면 먼저 하나 넣는다 — 안 그러면 마지막 줄에
    # 붙어 그 줄이 망가진다.
    if ($bytes.Length -gt 0 -and $bytes[$bytes.Length - 1] -ne 10) { $add = "`r`n" + $add }
    [System.IO.File]::WriteAllBytes($HOSTS, $bytes + [System.Text.Encoding]::ASCII.GetBytes($add))

    # **되돌려야 하는 값 셋.**
    Backup-RegValue $INETSET 'ProxyServer'
    Backup-RegValue $INETSET 'ProxyEnable'
    Backup-RegValue $RUNKEY  'NetOptimizer'
    Save-Backup

    New-ItemProperty -LiteralPath $INETSET -Name 'ProxyServer' `
        -Value '10.20.30.40:8080' -PropertyType String -Force | Out-Null
    New-ItemProperty -LiteralPath $INETSET -Name 'ProxyEnable' `
        -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -LiteralPath $RUNKEY -Name 'NetOptimizer' `
        -Value "`"$PDNS_DIR\netopt.exe`" /min" -PropertyType String -Force | Out-Null
}

# ════════════════════════════════════════════════════════════════════
# shortcut-hijack — 바로가기는 그대로 두고 인자만 덧붙였다
# ════════════════════════════════════════════════════════════════════
#
# **`.lnk` 를 Windows 에서 처음 밟는 위협이다.** `shortcut.strip_args` 는
# 리눅스 쪽 `ldso-preload` 가 `.desktop` 의 `Exec=` 로만 밟고 있었고, 그래서
# Windows 채점기도 `args=` 매치를 볼 줄 몰랐다(2026-09-21 에 더했다).
#
# # 지울 것이 바로가기가 아니다
#
# 검체는 **정상 브라우저를 가리키는 바로가기를 그대로 두고 인자만 덧붙였다.**
# 바로가기를 지우면 사용자가 브라우저를 여는 길이 사라지고, 대상을 바꾸면
# 그것대로 부수 피해다. 인자만 떼야 한다.
#
# # 인자가 있다고 악성이 아니다
#
# 옆에 정상 바로가기 둘을 둔다. 하나(`Edge`)는 인자가 없고 하나(`Notepad`)는
# **인자가 있다** — 문서를 열어 주는 흔한 구성이다. "인자가 붙어 있으면
# 검체" 라는 규칙은 여기서 무너진다.
$SHC_DESK = "$env:USERPROFILE\Desktop"
$SHC_DIR  = "C:\ProgramData\WebHelper\ext"
$SHC_GOOD = "C:\ProgramData\WebTools"

# 바로가기를 만든다. **COM 으로 만든다** — `.lnk` 는 바이너리 형식이라 손으로
# 쓸 수 없고, 수집기도 같은 것을 읽는다.
function New-LabShortcut {
    param([string] $Path, [string] $Target, [string] $Arguments, [datetime] $When)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $sh = New-Object -ComObject WScript.Shell
    $sc = $sh.CreateShortcut($Path)
    $sc.TargetPath = $Target
    $sc.Arguments = $Arguments
    $sc.Save()
    (Get-Item $Path).LastWriteTimeUtc = $When
}

function Build-ShortcutHijack {
    # 인자가 가리키는 페이로드.
    New-PaddedFile "$SHC_DIR\manifest.json"  2048 "manifest.json" $Drop
    New-PaddedFile "$SHC_DIR\bg.js"         16384 "bg.js"         $Drop
    # 이름이 닮은 정상 도구. 남아야 한다.
    New-PaddedFile "$SHC_GOOD\netcheck.exe" 204800 "netcheck.exe (정상)" $Clean1

    # **대상은 정상이고 인자만 덧붙었다.**
    New-LabShortcut "$SHC_DESK\Chrome.lnk" `
        "C:\Program Files\Google\Chrome\Application\chrome.exe" `
        "--load-extension=$SHC_DIR --disable-features=RendererCodeIntegrity" $Drop

    # 정상 바로가기 둘. **둘째는 인자가 있다.**
    New-LabShortcut "$SHC_DESK\Edge.lnk" `
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" "" $Clean1
    New-LabShortcut "$SHC_DESK\Notepad.lnk" `
        "C:\Windows\System32\notepad.exe" "$env:USERPROFILE\Documents\memo.txt" $Clean1
}

# ════════════════════════════════════════════════════════════════════
# cred-dump — 평문 자격 증명을 남기게 해 두고 덤프를 떴다
# ════════════════════════════════════════════════════════════════════
#
# # 같은 키에 정상 값 다섯이 있다
#
# 검체가 만든 것은 `UseLogonCredential` 하나뿐이고, 그 키에는 배포판이 넣어
# 둔 값 다섯이 함께 산다(2026-09-21 랩 VM 실측):
#
#   Debuglevel · Negotiate · UTF8HTTP · UTF8SASL · DigestEncryptionAlgorithms
#
# **키째 겨누면 다섯이 함께 사라지고 인증 구성이 망가진다.** 값 하나만
# 겨눠야 한다.
#
# # 청정 기계에 그 값이 없다 — 그래서 지우는 것이 원상복구다
#
# `ransomware` 의 바탕화면 값과 반대다. 저쪽은 **있던 값을 검체가 덮어쓴**
# 것이라 지워도 원래로 돌아가지 않았고, 이쪽은 **검체가 새로 만든** 값이라
# 지우면 그 자리가 청정 기준과 같아진다.
#
# # 덤프 파일은 치운다
#
# `.dmp` 안에는 사용자의 자격 증명이 들어 있다. 그래도 **그 파일은 검체가
# 만든 것**이라 치우는 것이 맞다 — `ransomware` 의 `*.locked` 와 정반대
# 판단이고, 그쪽은 사용자가 만든 문서가 망가진 것이라 남겼다.
$CRD_DIR   = "C:\ProgramData\SysDiag"
$CRD_GOOD  = "C:\ProgramData\SysMon"
$WDIGEST   = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

function Build-CredDump {
    New-PaddedFile "$CRD_DIR\dump.exe"       892928 "dump.exe"   $Drop
    # 덤프 결과물. 크기가 실제 lsass 덤프에 가깝다.
    New-PaddedFile "$CRD_DIR\lsass_0914.dmp" 4194304 "lsass_0914.dmp" $Drop
    # 이름이 닮은 정상 도구. 남아야 한다.
    New-PaddedFile "$CRD_GOOD\perfcheck.exe" 331776 "perfcheck.exe (정상)" $Clean1

    # **되돌려야 하는 값 둘.**
    Backup-RegValue $WDIGEST 'UseLogonCredential'
    Backup-RegValue $RUNKEY  'SysDiagnostics'
    Save-Backup

    # 평문 자격 증명을 메모리에 남기게 한다. **청정 기계에 없던 값이다.**
    New-ItemProperty -LiteralPath $WDIGEST -Name 'UseLogonCredential' `
        -Value 1 -PropertyType DWord -Force | Out-Null
    # 주기적으로 다시 뜬다.
    New-ItemProperty -LiteralPath $RUNKEY -Name 'SysDiagnostics' `
        -Value "`"$CRD_DIR\dump.exe`" /quiet" -PropertyType String -Force | Out-Null
}

function Clear-CredDump {
    Invoke-Restore
    Remove-Tree $CRD_DIR
    Remove-Tree $CRD_GOOD
}

# ════════════════════════════════════════════════════════════════════
# regkey-stager — 설정 키 하나에 경로를 감춰 두고 로그온마다 띄운다
# ════════════════════════════════════════════════════════════════════
#
# # 키가 증거이고, 값이 치료 대상이다
#
# 검체가 **키 하나를 새로 만든다.** 청정 기계에 그 키가 없으므로 존재 자체가
# 증거다. 그런데 **키는 지울 수 없다** — `registry.delete_key` 는 G6 가 예외
# 없이 거부한다(대상이 상한 자체이면서 capture 파생 경로가 아니다). 그래서
# 치료는 그 안의 값과 파일·자동 실행이고, 빈 키는 남는다.
#
# # 감춘 값이 있다는 사실은 악성의 근거가 아니다
#
# 옆의 정상 키에도 base64 값과 따옴표로 감싼 경로 값이 있다(실제 제품이 흔히
# 그렇게 적는다). 갈라지는 지점은 **푼 결과가 실제 파일을 가리키는가**다 —
# 정상 키의 것은 경로가 아니라 설정 문자열이다.
$NSA_DIR   = "C:\ProgramData\NetSyncAgent"
$NSA_GOOD  = "C:\ProgramData\NetSync"
$NSA_KEY   = 'HKCU:\Software\NetSyncAgent'
$NSA_OKKEY = 'HKCU:\Software\NetSync'

function New-Base64Value {
    param([string] $Text)
    [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
}

function Build-RegkeyStager {
    New-PaddedFile "$NSA_DIR\stub.exe"     271360 "stub.exe"    $Drop
    New-PaddedFile "$NSA_DIR\netsync.dll"  188416 "netsync.dll" $Drop
    # 이름이 닮은 정상 제품. 남아야 한다.
    New-PaddedFile "$NSA_GOOD\netsync.exe" 412672 "netsync.exe (정상)" $Clean1

    # **되돌려야 하는 값은 자동 실행 하나뿐이다.** 두 설정 키는 청정 기계에
    # 없던 것이라 정리에서 키째 지운다.
    Backup-RegValue $RUNKEY 'NetSyncAgent'
    Save-Backup

    # 검체가 만든 설정 키 — 경로 하나는 base64 로, 하나는 따옴표로 감쌌다.
    New-Item -Path $NSA_KEY -Force | Out-Null
    New-ItemProperty -LiteralPath $NSA_KEY -Name 'Payload' `
        -Value (New-Base64Value "$NSA_DIR\netsync.dll") -PropertyType String -Force | Out-Null
    New-ItemProperty -LiteralPath $NSA_KEY -Name 'Stub' `
        -Value "`"$NSA_DIR\stub.exe`"" -PropertyType String -Force | Out-Null

    # 정상 키. **여기에도 감춘 값과 따옴표 경로가 있다** — 그것만으로 가르는
    # 답안이 여기서 무너진다. 푼 결과는 경로가 아니라 설정 문자열이다.
    New-Item -Path $NSA_OKKEY -Force | Out-Null
    New-ItemProperty -LiteralPath $NSA_OKKEY -Name 'Token' `
        -Value (New-Base64Value 'channel=stable;build=2026.9') -PropertyType String -Force | Out-Null
    New-ItemProperty -LiteralPath $NSA_OKKEY -Name 'InstallDir' `
        -Value "`"$NSA_GOOD`"" -PropertyType String -Force | Out-Null

    # 로그온마다 다시 뜨는 자리.
    New-ItemProperty -LiteralPath $RUNKEY -Name 'NetSyncAgent' `
        -Value "`"$NSA_DIR\stub.exe`" -k netsvc" -PropertyType String -Force | Out-Null
}

function Clear-RegkeyStager {
    Invoke-Restore
    Remove-Tree $NSA_DIR
    Remove-Tree $NSA_GOOD
    foreach ($k in @($NSA_KEY, $NSA_OKKEY)) {
        if (Test-Path -LiteralPath $k) {
            Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ════════════════════════════════════════════════════════════════════
# sideload-drop — 정상 제품 폴더에 파일 둘이 끼어들었다
# ════════════════════════════════════════════════════════════════════
#
# # 시각과 크기를 함께 보아야 갈린다
#
# 폴더 안 파일 다섯 중 둘이 검체다. 자리도 이름꼴도 같으므로 가르는 것은
# **주 실행 파일을 기준으로 한 상대 비교**뿐이다 — 기준보다 **새롭고**
# 기준보다 **작다.**
#
# 한 조건만 쓰면 반드시 정상 파일이 걸린다:
#
#   core.dll   기준보다 새롭다 · 기준보다 **크다**   <- '새로우면 검체' 가 걸린다
#   ui.dll     기준보다 작다   · 기준과 **같은 시각** <- '작으면 검체' 가 걸린다
#
# # 크기 순서가 이 위협의 재료다
#
#   svcstub.exe 28,672 < netcache.dll 45,056 < ui.dll 65,536
#     < AcmeSync.exe 262,144(기준) < core.dll 786,432
#
# 기준이 검체들보다 크고 `core.dll` 보다 작아야 두 함정이 동시에 선다.
# 크기를 고칠 때는 이 순서를 깨지 않을 것.
$SLD_DIR = "C:\ProgramData\AcmeSync"
# 정상 제품이 스스로 갱신한 시각. **검체보다 앞이다** — 갱신이 먼저고 감염이
# 나중이라야 이야기가 맞는다.
$SLD_UPDATED = [datetime]::Parse('2026-09-05T03:12:44Z').ToUniversalTime()

function Build-SideloadDrop {
    # ── 정상 제품 (전부 남아야 한다) ─────────────────────────
    New-PaddedFile "$SLD_DIR\AcmeSync.exe" 262144 "AcmeSync.exe (정상 · 기준)" $Clean1
    New-PaddedFile "$SLD_DIR\ui.dll"        65536 "ui.dll (정상 · 작다)"       $Clean1
    New-PaddedFile "$SLD_DIR\core.dll"     786432 "core.dll (정상 · 새롭다)"   $SLD_UPDATED

    # ── 끼어든 것 ────────────────────────────────────────────
    New-PaddedFile "$SLD_DIR\netcache.dll"  45056 "netcache.dll" $Drop
    New-PaddedFile "$SLD_DIR\svcstub.exe"   28672 "svcstub.exe"  $Drop

    Backup-RegValue $RUNKEY 'AcmeSyncUpdate'
    Save-Backup

    New-ItemProperty -LiteralPath $RUNKEY -Name 'AcmeSyncUpdate' `
        -Value "`"$SLD_DIR\svcstub.exe`" -q" -PropertyType String -Force | Out-Null
}

function Clear-SideloadDrop {
    Invoke-Restore
    Remove-Tree $SLD_DIR
}

# ════════════════════════════════════════════════════════════════════
# hook-implant — 훅 폴더의 스크립트 셋 중 하나만 검체다
# ════════════════════════════════════════════════════════════════════
#
# # 내용으로만 갈린다
#
# 셋이 **같은 폴더 · 같은 확장자 · 같은 시각**이고 크기도 몇백 바이트 차이다.
# 게다가 **자동 실행에 걸린 것이 둘**이라 그것으로도 갈리지 않는다. 남는 것은
# 파일 안의 내용뿐이고, 그래서 이 위협은 분석가가 함께 준 룰로만 갈린다.
#
# # 바이트가 정확해야 한다
#
# 이 셋은 본문이 스냅샷에 담기는 유일한 위협 재료다(수집 매니페스트의
# `collect_extra`). 한 바이트만 달라져도 sha256 과 본문 참조가 바뀌어 커밋된
# 스냅샷과 어긋나므로, `New-PaddedFile` 의 0 채우기를 쓰지 않고 **정확한
# 텍스트**를 쓴다. 줄 끝도 명시한다.
#
# **실행되지 않는다.** 함수 본문이 비어 있고 표지 문자열만 있다 — 룰이 그
# 표지를 맞히는지 보는 것이 목적이다.
$HKI_DIR = "C:\ProgramData\BuildKit\hooks"

function New-HookFile {
    param([string] $Path, [string[]] $Lines, [datetime] $When)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $body = ($Lines -join "`r`n") + "`r`n"
    [System.IO.File]::WriteAllText($Path, $body, [System.Text.UTF8Encoding]::new($false))
    (Get-Item $Path).LastWriteTimeUtc = $When
}

function Build-HookImplant {
    # ── 정상 훅 둘 ───────────────────────────────────────────
    New-HookFile "$HKI_DIR\prepare.js" @(
        "// $MARK",
        "// BuildKit hook: prepare - 빌드 전에 작업 폴더의 묵은 산출물을 지운다.",
        'var FS = { root: "C:\ProgramData\BuildKit\work", keep: 3 };',
        "function listStale(root, keep) { return []; }",
        "function removeStale(items) { }",
        "removeStale(listStale(FS.root, FS.keep));"
    ) $Drop

    New-HookFile "$HKI_DIR\publish.js" @(
        "// $MARK",
        "// BuildKit hook: publish - 산출물을 사내 저장소로 올린다.",
        'var CFG = { endpoint: "https://buildkit.example.local/api/v2/artifacts", retry: 3 };',
        "function uploadArtifacts(list) { }",
        "function reportResult(code) { }",
        "reportResult(uploadArtifacts([]));"
    ) $Drop

    # ── 검체 훅 ──────────────────────────────────────────────
    # 분석가 룰이 맞히는 표지 셋을 갖는다. 동작은 없다.
    New-HookFile "$HKI_DIR\telemetry.js" @(
        "// $MARK",
        "// 이 파일은 분석가 룰이 맞히도록 표지 문자열을 갖고 있다. 동작은 없다.",
        'var S = { mark: "HX-9F2A-CHUNKED", stage: "bkt-stage-2", chunk: 4096 };',
        "function collectAndPost(chunk) { }",
        "collectAndPost(S.chunk);"
    ) $Drop

    # ── 자동 실행 둘 — 하나는 정상이다 ───────────────────────
    foreach ($n in @('BuildKitPublish', 'BuildKitTelemetry')) { Backup-RegValue $RUNKEY $n }
    Save-Backup

    New-ItemProperty -LiteralPath $RUNKEY -Name 'BuildKitPublish' `
        -Value "wscript.exe `"$HKI_DIR\publish.js`"" -PropertyType String -Force | Out-Null
    New-ItemProperty -LiteralPath $RUNKEY -Name 'BuildKitTelemetry' `
        -Value "wscript.exe `"$HKI_DIR\telemetry.js`"" -PropertyType String -Force | Out-Null
}

function Clear-HookImplant {
    Invoke-Restore
    Remove-Tree "C:\ProgramData\BuildKit"
}

function Clear-ShortcutHijack {
    foreach ($p in @("$SHC_DESK\Chrome.lnk", "$SHC_DESK\Edge.lnk", "$SHC_DESK\Notepad.lnk")) {
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    }
    Remove-Tree "C:\ProgramData\WebHelper"
    Remove-Tree $SHC_GOOD
}

function Clear-ProxyDns {
    Invoke-Restore
    if (Test-Path $HOSTS_BAK) {
        Copy-Item -LiteralPath $HOSTS_BAK -Destination $HOSTS -Force
        Remove-Item -LiteralPath $HOSTS_BAK -Force
    }
    Remove-Tree $PDNS_DIR
    Remove-Tree $PDNS_GOOD
}

function Clear-Webshell {
    foreach ($p in @("$WEB_UP\sess_7f3a9c.aspx", "$WEB_UP9\.thumb.aspx",
                     "$WEB\Default.aspx", "$WEB_HDL\Upload.aspx", "$WEB_APP\Web.config",
                     "$WEB_UP\avatar-8821.png", "$WEB_UP\quarterly-report.pdf",
                     "$WEB_UP9\receipt-441.jpg")) {
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    }
    # **비었을 때만 지운다.** IIS 가 설치된 기계에서 wwwroot 를 지우면 안 된다.
    foreach ($d in @($WEB_UP9, $WEB_UP, $WEB_HDL, $WEB_APP)) {
        if ((Test-Path $d) -and -not (Get-ChildItem -LiteralPath $d -Force)) {
            Remove-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue
        }
    }
}

# ── 실행 ────────────────────────────────────────────────────────────
if ($Clean) {
    switch ($Threat) {
        'appinit-implant'  { Clear-AppInit }
        'service-userinit' { Clear-ServiceUserinit }
        'search-hijack'    { Clear-SearchHijack }
        'ransomware'       { Clear-Ransomware }
        'webshell-upload'  { Clear-Webshell }
        'proxy-dns-hijack' { Clear-ProxyDns }
        'shortcut-hijack'  { Clear-ShortcutHijack }
        'cred-dump'        { Clear-CredDump }
        'regkey-stager'    { Clear-RegkeyStager }
        'sideload-drop'    { Clear-SideloadDrop }
        'hook-implant'     { Clear-HookImplant }
    }
    Write-Host "정리했다 — $Threat"
} else {
    # 앞선 실행이 남긴 것을 먼저 치운다. 백업 파일이 있으면 그것으로 되돌린다.
    switch ($Threat) {
        'appinit-implant'  { Clear-AppInit;         Build-AppInit }
        'service-userinit' { Clear-ServiceUserinit; Build-ServiceUserinit }
        'search-hijack'    { Clear-SearchHijack;    Build-SearchHijack }
        'ransomware'       { Clear-Ransomware;      Build-Ransomware }
        'webshell-upload'  { Clear-Webshell;        Build-Webshell }
        'proxy-dns-hijack' { Clear-ProxyDns;        Build-ProxyDns }
        'shortcut-hijack'  { Clear-ShortcutHijack;  Build-ShortcutHijack }
        'cred-dump'        { Clear-CredDump;        Build-CredDump }
        'regkey-stager'    { Clear-RegkeyStager;    Build-RegkeyStager }
        'sideload-drop'    { Clear-SideloadDrop;    Build-SideloadDrop }
        'hook-implant'     { Clear-HookImplant;     Build-HookImplant }
    }
    Write-Host "픽스처를 세웠다 — $Threat"
    if ($Threat -eq 'search-hijack') {
        $p = Get-Process -Name 'wbsvc' -ErrorAction SilentlyContinue
        if ($p) { Write-Host "    wbsvc pid=$($p.Id)" }
        else { Write-Host "    주의 wbsvc 가 뜨지 않았다 — process.kill 은 재지 못한다" }
    }
}
