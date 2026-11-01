<#
.SYNOPSIS
    시스템 상태를 JSON 으로 캡처한다. remedy 와 **독립적으로** 관찰하는 것이 목적이다.

.DESCRIPTION
    remedy 의 감사 로그는 "무엇을 하려 했는가"를 말한다. 이 스크립트는 "실제로
    무엇이 바뀌었는가"를 말한다. **둘이 어긋나는 지점이 곧 버그다.**

    remedy 코드를 전혀 쓰지 않는다 — 검증자가 피검증자를 신뢰하면 검증이 아니다.

    캡처 대상은 설계-02 §3 의 관찰 대상 타입과 의도적으로 겹친다. remedy 가
    건드릴 수 있는 것을 우리도 보고 있어야 한다.

.PARAMETER OutFile
    출력 JSON 경로.

.PARAMETER FilePaths
    해시까지 기록할 루트 디렉터리. 각 루트를 재귀로 훑는다.
    경로 중간의 와일드카드는 확장되고(`C:\Users\*\...`), 후행 `\*` 는 무시된다.

    기본값을 좁게 잡은 것은 의도다. `C:\ProgramData` 처럼 큰 루트를 넣으면
    백신 시그니처·로그가 끊임없이 바뀌면서 매 실행마다 가짜 변경이 쏟아지고,
    진짜 변경이 그 속에 묻힌다. 넓은 범위가 필요하면 명시적으로 넘길 것.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $OutFile,
    [string[]] $FilePaths = @(
        "C:\remedy-lab\fixtures",
        "C:\Users\*\AppData\Local\Programs"
    ),
    # 잘리면 파일 diff 를 신뢰할 수 없으므로(판정이 inconclusive 로 떨어진다)
    # 평범한 사용자 프로필에서는 걸리지 않을 만큼 여유를 둔다. 실측으로 테스트 VM 의
    # AppData\Local\Programs 한 곳에만 5,532개(144MB, Python 설치본)가 있었다.
    [int] $MaxFiles = 20000,

    # 아래 하드코딩된 핵심 값 **말고 더 볼 레지스트리 값**.
    # `HKLM\...\Key\ValueName` 꼴로 준다.
    #
    # # 왜 인자로 받는가
    #
    # 하드코딩 목록은 "지우면 시스템이 죽는 값" 을 지킨다 — 그것만으로는
    # **위협이 실제로 밟는 자리를 못 본다.** 2026-09-05 에 드러났다: 부팅
    # 목록(`BootExecute`)도 경로 변수(`Path`)도 여기 없어서, 그 둘을 고치지
    # 못한 치료가 이 관측기 앞에서 아무 자국도 남기지 않았다.
    #
    # **무엇을 볼지는 응시자의 계획이 정하면 안 된다** — 검증자가 피검증자를
    # 믿는 것이다. 시험은 위협마다 사전 등록된 `expected-ops.txt` 에서 뽑아
    # 넘긴다.
    [string[]] $RegistryValues = @()
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

function Safe {
    param([scriptblock] $Block)
    try { & $Block } catch { @() }
}

<#
    `HKLM\SYSTEM\...\Session Manager\BootExecute` 를 (PS 경로, 값 이름) 으로 가른다.

    **마지막 역슬래시에서 가른다.** 값 이름 자체가 역슬래시를 품는 자리가
    있지만(Defender 제외 목록의 경로), 그쪽은 `defender_exclusions` 섹션이
    따로 담으므로 여기로 오지 않는다.

    모르는 하이브는 `$null` 을 낸다 — 추측해서 아무 키나 여는 것보다 "못 봤다"
    가 낫다.
#>
function ConvertTo-PsRegPath {
    param([string] $Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $null }
    $i = $Target.LastIndexOf('\')
    if ($i -lt 1) { return $null }
    $keyPart = $Target.Substring(0, $i)
    $name = $Target.Substring($i + 1)
    $j = $keyPart.IndexOf('\')
    if ($j -lt 1) { return $null }
    $sub = $keyPart.Substring($j + 1)
    $drive = switch ($keyPart.Substring(0, $j).ToUpperInvariant()) {
        "HKLM" { "HKLM:" }
        "HKCU" { "HKCU:" }
        "HKCR" { "HKCR:" }
        "HKCC" { "HKCC:" }
        "HKU"  { "Registry::HKEY_USERS" }
        default { $null }
    }
    if (-not $drive) { return $null }
    [pscustomobject]@{ Path = "$drive\$sub"; Name = $name }
}

function Write-Json {
    param([Parameter(Mandatory = $true)] $Object,
          [Parameter(Mandatory = $true)][string] $Path,
          [int] $Depth = 8)

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    # BOM 없이 쓴다. .ps1 은 BOM 이 있어야 PowerShell 5.1 이 UTF-8 로 읽지만,
    # JSON 은 BOM 이 있으면 안 된다 — serde_json 을 비롯한 대부분의 파서가
    # 거부한다 (RFC 8259). 두 규칙이 정반대라 헷갈리기 쉽다.
    #
    # WriteAllText 는 실패 시 예외를 던진다. Out-File 은 $ErrorActionPreference 가
    # Continue 면 조용히 실패하고 0바이트 파일을 남긴다 — 그러면 diff 가
    # 빈 상태를 비교하면서 "변경 없음"이라는 거짓 통과를 만든다.
    [System.IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth $Depth),
                                   (New-Object System.Text.UTF8Encoding($false)))

    $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($fi.Length -eq 0) { throw "JSON 쓰기 실패 (0바이트): $Path" }
}

# ---------------------------------------------------------------- 프로세스

# **관측자는 자기 자신을 세지 않는다.** 캡처를 두 번 뜨면 그 두 프로세스는
# 인자(-OutFile)가 달라 서로 다른 항목으로 잡히고, 전/후 diff 에 프로세스
# 하나가 사라지고 하나가 생긴 것으로 나온다. 아무도 하지 않은 변경이다.
#
# 그것이 그냥 잡음이면 넘어갈 수도 있는데, 불변식 P 판정에 걸리면 둘 중
# 하나가 된다 — 계획 문자열과 우연히 겹치면 **공허한 통과**, 안 겹치면
# 아무도 하지 않은 일에 대한 **거짓 위반**이다. 실측으로 앞의 것이 났다.
$selfPid = $PID
$processes = Safe {
    Get-CimInstance Win32_Process -ErrorAction Stop |
        Where-Object { $_.ProcessId -ne $selfPid } |
        Select-Object @{n = "pid"; e = { $_.ProcessId } },
                      @{n = "ppid"; e = { $_.ParentProcessId } },
                      @{n = "name"; e = { $_.Name } },
                      @{n = "image_path"; e = { $_.ExecutablePath } },
                      @{n = "cmdline"; e = { $_.CommandLine } } |
        Sort-Object pid
}

# ---------------------------------------------------------------- 서비스
# 복구 동작(failure action)까지 본다 — 설계-03 §2 의 '자동 소생 차단' 이 실제로
# 걸렸는지 확인하려면 이 값이 필요하다.

# 복구 동작은 Win32_Service 에 없다. 레지스트리의 FailureActions(REG_BINARY)를
# 직접 읽어야 한다. 값 전체를 담으면 JSON 이 커지므로 길이와 해시만 남긴다 —
# '바뀌었는가'를 보는 데는 그걸로 충분하다.
$services = Safe {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {
            $svc = $_
            $fa = $null
            $raw = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" `
                        -Name FailureActions -ErrorAction SilentlyContinue).FailureActions
            if ($raw) {
                $digest = [BitConverter]::ToString($sha.ComputeHash([byte[]]$raw)).Replace("-", "")
                $fa = "len=$($raw.Length),sha=$($digest.Substring(0,12))"
            }
            [ordered]@{
                name           = $svc.Name
                display_name   = $svc.DisplayName
                state          = "$($svc.State)"
                start_mode     = "$($svc.StartMode)"
                image_path     = $svc.PathName
                failure_action = $fa
            }
        } | Sort-Object { $_.name }
    } finally { $sha.Dispose() }
}

# ---------------------------------------------------------------- 예약 작업

$tasks = Safe {
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $t = $_
        [ordered]@{
            path    = ($t.TaskPath + $t.TaskName)
            state   = "$($t.State)"
            author  = $t.Author
            actions = @($t.Actions | ForEach-Object {
                [ordered]@{
                    execute   = $_.Execute
                    arguments = $_.Arguments
                    work_dir  = $_.WorkingDirectory
                }
            })
        }
    } | Sort-Object { $_.path }
}

# ---------------------------------------------------------------- 자동실행
# HKU\* 를 순회한다. 현재 로그온 사용자만 보면 다중 사용자 환경의 감염을
# 놓친다 (설계-00 §5-2).

$autoruns = Safe {
    $out = @()
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    # SilentlyContinue 여야 한다. S-1-5-19/20 은 접근이 거부되는데, Stop 이면
    # 첫 거부에서 예외가 나고 Safe 가 삼켜서 **접근 가능한 SID 까지 전부** 잃는다.
    # 그러면 다중 사용자 감염을 통째로 놓친다 (설계-00 §5-2).
    foreach ($sid in (Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
                      Select-Object -ExpandProperty PSChildName)) {
        if ($sid -match "_Classes$") { continue }
        $keys += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run"
        $keys += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $item = Get-Item $k -ErrorAction SilentlyContinue
        if ($null -eq $item) { continue }
        foreach ($name in $item.GetValueNames()) {
            $out += [ordered]@{
                key   = $k
                name  = $name
                value = "$($item.GetValue($name))"
            }
        }
    }
    $out | Sort-Object { "$($_.key)|$($_.name)" }
}

# ---------------------------------------------------------------- 레지스트리 핵심 값
# 여기 있는 값들을 통째로 지우면 시스템을 못 쓰게 된다 (설계-07 결함 1).
# 부분 편집이 제대로 되었는지 확인하려면 원본을 알아야 한다.

$registry = Safe {
    $targets = @(
        @{ Key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Names = @("Shell", "Userinit") },
        @{ Key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; Names = @("AppInit_DLLs", "LoadAppInit_DLLs") },
        @{ Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot"; Names = @() }
    )
    $out = @()
    foreach ($t in $targets) {
        $exists = Test-Path $t.Key
        $entry = [ordered]@{ key = $t.Key; exists = $exists; values = @() }
        if ($exists -and $t.Names.Count -gt 0) {
            $item = Get-Item $t.Key -ErrorAction SilentlyContinue
            foreach ($n in $t.Names) {
                $entry.values += [ordered]@{ name = $n; value = "$($item.GetValue($n))" }
            }
        }
        $out += $entry
    }
    # IFEO — 하위 키 이름만. Debugger 값이 붙은 것만 의미가 있다.
    $ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $out += [ordered]@{
        key    = $ifeo
        exists = (Test-Path $ifeo)
        # 여기도 SilentlyContinue 여야 한다. IFEO 하위에는 접근이 거부되는 키가
        # 섞여 있고, Stop 이면 그 하나 때문에 Debugger 하이재킹을 전부 놓친다.
        values = @(Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
            $dbg = $_.GetValue("Debugger")
            if ($dbg) { [ordered]@{ name = $_.PSChildName; value = "$dbg" } }
        })
    }

    # 시험이 지정한 값들 (위 -RegistryValues 의 설명 참고).
    foreach ($t in $RegistryValues) {
        $p = ConvertTo-PsRegPath $t
        if (-not $p) {
            # 조용히 넘기지 않는다. 못 읽은 자리는 '변화 없음' 과 구별되지 않는다.
            $out += [ordered]@{
                key = $t; exists = $false
                values = @([ordered]@{ name = "(파싱 실패)"; value = "(관측 못 함)" })
            }
            continue
        }
        $item = Get-Item -LiteralPath $p.Path -ErrorAction SilentlyContinue
        $raw = $null
        $kind = $null
        if ($item) {
            $raw = $item.GetValue($p.Name, $null)
            # **타입도 본다.** 값을 문자열로만 적으면 `REG_SZ "0"` 과
            # `REG_DWORD 0` 이 같아 보인다. `LoadAppInit_DLLs` 에서 그 둘은
            # 다른 것이고, 문자열로 되돌린 치료가 이 관측기 앞에서 옳아
            # 보이게 된다 (2026-09-05).
            if ($p.Name -in $item.GetValueNames()) { $kind = "$($item.GetValueKind($p.Name))" }
        }
        $out += [ordered]@{
            key    = $p.Path
            exists = [bool]$item
            values = @([ordered]@{
                name  = $p.Name
                # **여러 문자열은 구분자로 이어 붙인다.** PowerShell 이 기본으로
                # 공백을 쓰는데, 그러면 `REG_MULTI_SZ` 의 빈 항목이 사라진 것과
                # 구별되지 않는다 — 이 관측기가 봐야 할 바로 그 차이다.
                value = $(if ($null -eq $raw) { "(값 없음)" }
                          elseif ($raw -is [array]) { "[$kind] " + ((@($raw) | ForEach-Object { "$_" }) -join " | ") }
                          else { "[$kind] $raw" })
            })
        }
    }
    $out
}

# ---------------------------------------------------------------- 파일

# 재귀를 직접 구현한다. 세 가지 이유가 있고 셋 다 실측으로 확인했다.
#
# 1. Get-ChildItem 은 경로가 `\*` 로 끝나면 -Recurse 를 무시한다.
#    'C:\ProgramData\*' -Recurse -File → 1건 / 'C:\ProgramData' -Recurse -File → 10,605건.
#    이 함정 때문에 첫 VM 기준 캡처가 "파일 0" 으로 나왔다.
# 2. 재파스 지점(예: C:\ProgramData\Application Data)을 따라가면 같은 파일을 두 번
#    세거나 순환한다. diff 의 기준이 되는 목록은 결정적이어야 한다.
# 3. 디렉터리 하나의 접근 거부가 섹션 전체를 날리면 안 된다. Safe 를 루프 전체가
#    아니라 디렉터리 단위로 걸어야 부분 실패가 부분 손실로 끝난다.

$truncated = $false
$fileList = New-Object System.Collections.ArrayList
# 실제로 훑은 루트를 기록한다. "파일 0" 이 나왔을 때 루트가 없어서인지 정말 비어
# 있어서인지를 구분해 주고, 전/후 캡처가 서로 다른 루트를 봤다면 diff 를 믿으면
# 안 된다는 것도 여기서 드러난다.
$scannedRoots = New-Object System.Collections.ArrayList

foreach ($spec in $FilePaths) {
    if ($truncated) { break }
    # 후행 `\*` 는 떼어낸다. 경로 중간의 와일드카드는 Resolve-Path 가 확장한다.
    $rootSpec = $spec -replace '[\\/]\*+$', ''
    $roots = @(Resolve-Path -Path $rootSpec -ErrorAction SilentlyContinue |
               Select-Object -ExpandProperty Path)

    foreach ($root in $roots) {
        if ($truncated) { break }
        [void]$scannedRoots.Add($root)
        $stack = New-Object System.Collections.Stack
        $stack.Push($root)

        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            $children = @(Safe { Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop })

            foreach ($c in $children) {
                $isReparse = (($c.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)

                if ($c.PSIsContainer) {
                    if (-not $isReparse) { $stack.Push($c.FullName) }
                    continue
                }

                if ($fileList.Count -ge $MaxFiles) { $truncated = $true; break }

                $hash = $null
                if (-not $isReparse -and $c.Length -le 32MB) {
                    $h = Safe { (Get-FileHash -LiteralPath $c.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }
                    if ($h) { $hash = "$h" }
                }
                [void]$fileList.Add([ordered]@{
                    path   = $c.FullName
                    size   = $c.Length
                    mtime  = $c.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    sha256 = $hash
                })
            }
            if ($truncated) { break }
        }
    }
}

$files = @($fileList | Sort-Object { $_.path })

# ---------------------------------------------------------------- 기타

# ReadAllLines 를 쓴다. Get-Content 는 각 줄에 PSPath/PSDrive/PSProvider 노트
# 속성을 붙이는데, PSProvider(ProviderInfo) 가 다른 객체들을 물고 있는 그래프라
# ConvertTo-Json -Depth 8 이 지수적으로 폭발한다. 실측: 3줄이 Depth 2 에서 이미
# 4,275자(평문 135자), Depth 8 에서는 끝나지 않고 결국
# "capacity was less than the current size" 로 죽는다.
# [string[]] 캐스팅은 남아 있을 수 있는 장식을 마저 떼기 위한 것이다.
$hostsFile = Safe {
    $p = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $p) {
        [string[]]([System.IO.File]::ReadAllLines($p) |
                   Where-Object { $_ -and -not $_.TrimStart().StartsWith("#") })
    }
}

$rootCerts = Safe {
    Get-ChildItem Cert:\LocalMachine\Root -ErrorAction Stop |
        Select-Object @{n = "thumbprint"; e = { $_.Thumbprint } },
                      @{n = "subject"; e = { $_.Subject } } |
        Sort-Object thumbprint
}

$defenderExclusions = Safe {
    $p = Get-MpPreference -ErrorAction Stop
    [ordered]@{
        path      = @($p.ExclusionPath)
        process   = @($p.ExclusionProcess)
        extension = @($p.ExclusionExtension)
    }
}

# ---------------------------------------------------------------- 정규화
#
# 수집 결과에서 null 원소를 걷어낸다. Safe 는 실패 시 @() 를 돌려주는데 파이프라인이
# 그걸 풀어서 호출자에게는 $null 이 도착한다. 그대로 @() 로 감싸면 'null 하나짜리
# 배열'이 되어 JSON 에 [null] 로 실리고, 비교기에서 키가 null 인 항목이 되어
# "Index operation failed" 로 죽는다.
#
# 실제로 밟았다. VM 의 hosts 파일에 주석 아닌 줄이 하나도 없어서 hosts_entries 가
# [null] 이 되었고 비교 전체가 무너졌다. hosts 만의 문제가 아니라 어느 수집기가
# 실패해도 같은 일이 벌어지므로 여기서 일괄로 끊는다.
#
# @(...) 로 **대입**하면 결과가 비어도 배열로 남는다 (함수 반환과 달리 풀리지 않는다).

$processes          = @($processes          | Where-Object { $null -ne $_ })
$services           = @($services           | Where-Object { $null -ne $_ })
$tasks              = @($tasks              | Where-Object { $null -ne $_ })
$autoruns           = @($autoruns           | Where-Object { $null -ne $_ })
$registry           = @($registry           | Where-Object { $null -ne $_ })
$files              = @($files              | Where-Object { $null -ne $_ })
$hostsFile          = @($hostsFile          | Where-Object { $null -ne $_ })
$rootCerts          = @($rootCerts          | Where-Object { $null -ne $_ })
$scannedRoots       = @($scannedRoots       | Where-Object { $null -ne $_ })

# ---------------------------------------------------------------- 출력

$state = [ordered]@{
    # /5 — 요청한 레지스트리 값에 **타입**을 함께 적는다. /4 와 비교하면
    #      그 값들이 전부 '변경'으로 잡힌다.
    # /4 — -RegistryValues 로 볼 값을 더할 수 있게 했고 registry_roots 를
    #      추가했다. 요청 목록이 다른 캡처끼리 비교하면 레지스트리 섹션이
    #      통째로 '추가/삭제'로 잡히므로 섞으면 안 된다.
    # /3 — 서비스에 failure_action 을 추가했다. /2 와 비교하면 모든 서비스가
    #      '변경'으로 잡히므로 섞으면 안 된다.
    # /2 — 파일 수집이 실제로 재귀하도록 고쳤고 file_roots 를 추가했다.
    schema           = "remedy-lab.state/5"
    captured_at      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    hostname         = $env:COMPUTERNAME
    capturer_bitness = $(if ([Environment]::Is64BitProcess) { 64 } else { 32 })
    os_bitness       = $(if ([Environment]::Is64BitOperatingSystem) { 64 } else { 32 })
    files_truncated  = $truncated
    # 실제로 훑은 루트. **비교의 기준으로 쓰면 안 된다** — 위협이 만든
    # 디렉터리는 청정 캡처에 없어서, 같은 인자로 뜬 두 캡처가 서로 다른 루트를
    # 봤다고 보고된다. 그것은 관측의 흠이 아니라 관측 대상의 변화다.
    file_roots       = @($scannedRoots)
    # 요청한 루트. 두 캡처가 **같은 자리를 보려 했는가**는 이것이 말한다.
    file_roots_requested = @($FilePaths)
    # **요청한 목록을 그대로 적는다** — 실제로 있었는지가 아니라. 두 캡처가
    # 같은 자리를 봤는가를 `Compare-State.ps1` 이 이것으로 판단한다.
    registry_roots   = @($RegistryValues)
    counts           = [ordered]@{
        processes = @($processes).Count
        services  = @($services).Count
        tasks     = @($tasks).Count
        autoruns  = @($autoruns).Count
        files     = @($files).Count
    }
    processes           = @($processes)
    services            = @($services)
    scheduled_tasks     = @($tasks)
    autoruns            = @($autoruns)
    registry            = @($registry)
    files               = @($files)
    hosts_entries       = @($hostsFile)
    root_certificates   = @($rootCerts)
    defender_exclusions = $defenderExclusions
}

# Depth 6. 실제로 필요한 최대 중첩은 5 다
# (state → scheduled_tasks → 항목 → actions → 항목 → 문자열).
# 여유를 좁게 잡는 것은 의도다 — 장식된 객체가 다시 섞여 들어와도 폭발 범위가 제한된다.
Write-Json -Object $state -Path $OutFile -Depth 6

Write-Host ("상태 캡처 완료 -> {0}" -f $OutFile)
Write-Host ("  프로세스 {0} · 서비스 {1} · 작업 {2} · 자동실행 {3} · 파일 {4}" -f `
    $state.counts.processes, $state.counts.services, $state.counts.tasks,
    $state.counts.autoruns, $state.counts.files)
Write-Host ("  파일 루트 {0}개: {1}" -f @($scannedRoots).Count,
    $(if (@($scannedRoots).Count) { @($scannedRoots) -join ' · ' } else { '없음' }))

# 잘림은 눈에 띄어야 한다. 잘린 목록으로 diff 를 돌리면 상한 밖의 변경을 놓치고
# 전/후의 잘리는 지점이 달라지면 있지도 않은 변경이 만들어진다.
if ($truncated) {
    # 콘솔 출력에는 em-dash(U+2014) 를 쓰지 않는다. 게스트 스크립트의 출력은
    # powershell.exe 자식 프로세스를 거쳐 원격으로 넘어오는데 그 과정에서
    # '?' 로 깨진다 (한글과 가운뎃점은 멀쩡히 넘어온다).
    Write-Host ("  ** 파일 상한 {0} 도달: 목록이 잘렸다. 이 캡처로는 파일 diff 를 신뢰할 수 없다." -f $MaxFiles) -ForegroundColor Red
    Write-Host "     -FilePaths 를 좁히거나 -MaxFiles 를 올릴 것." -ForegroundColor Red
}
if (@($scannedRoots).Count -eq 0) {
    Write-Host "  ** 훑은 파일 루트가 없다. -FilePaths 의 경로가 실제로 존재하는지 확인할 것." -ForegroundColor Red
}
