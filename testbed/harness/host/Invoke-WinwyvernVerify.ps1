#Requires -Version 5.1
# 룰: winwyvern-1-check — 묶어 낸 출시의 필수 점검 ① 과 PR CI 가 이 하네스를 찾아 돌린다(Invoke-RuleHarness.ps1 · -Package · -LogDir)
# 입력: 없음
# rc 묶음: winwyvern
# 하네스 표: Windows 랩(러너 · 랩 VM) | WinWyvern 탐지 룰의 판정 — 취약 드라이버 NeacSafe64 의 서비스(자동 시작 · ImagePath 꼴)와 System32 의 그 파일 · 하나만 남은 흔적 · 다른 시작 유형 · 다른 자리
<#
.SYNOPSIS
    WinWyvern 탐지 룰(winwyvern-1-check)을 랩에서 잰다 — 서비스 · 파일의 꼴마다 종료 코드와 흔적 · 위협 수.

.DESCRIPTION
    `-Package` 는 `remedy-windows-x64` 폴더다(내려받아 푼 배포본, 또는 `New-DevPackage.ps1` 로 꾸린 개발 꾸러미). 그
    remedy.exe 와 그 안의 `plugins\winwyvern-1-check` 를 그대로 쓴다. 받을 입력은 없다(머리의 `# 입력: 없음`) — 자리
    채우기만 쓴다. `-Inputs` 는 rc 묶음이 표준 인자로 주는 것이라 받기만 하고 쓰지 않는다.

    랩 VM(호스트에서 WinRM)과 GitHub 호스팅 러너(자기 자신 · `Initialize-RunnerLab.ps1` 뒤) 둘 다에서 돈다. 러너에는 되돌릴
    스냅숏이 없으므로 되돌리기에 기대지 않고 놓은 것을 스스로 치운다. 개발 PC 자신에는 붙지 않는다(`Connect-LabVm` 의 가드).

    # 무해한가

    실검체는 없다. 드라이버 자리에는 표지 글자만 담은 작은 파일(`REMEDY-LAB placeholder …` — PE 가 아니다)을 게스트의
    `%SystemRoot%\System32` 에 둔다. 서비스는 `sc.exe create`(파일 시스템 드라이버 · 시작 유형은 칸마다)로 **등록만** 하고
    시작하지 않는다. ImagePath 꼴을 바꾸는 칸은 등록 뒤 그 값 하나만 레지스트리에서 고친다. 칸마다 앞의 것을 치우고
    세우며, 끝에(중간에 실패해도 finally 에서) 모두 치운 뒤 남은 것이 없는지 본다(C1). 시작 전에 그 서비스나 파일이 이미
    있으면(랩에 원래 있던 것) 아무것도 건드리지 않고 멈춘다.

    # 무엇을 재나

      A  감염 1 — ASEC 꼴: sc.exe 가 둔 ImagePath(binPath 는 게스트의 SystemRoot 아래 System32\neacsafe64.sys) · 자동
         시작 · 그 파일 → 2(흔적 2 · 위협 1). 칸 줄에 SCM 이 실제로 둔 ImagePath 를 적는다
      V  꼴 변형 10 — ImagePath 를 `\SystemRoot\System32\…` · `System32\…` · `%SystemRoot%\…` · `%windir%\system32\NeacSafe64.sys`
         · `\??\` 와 대문자 · REG_SZ 의 전체 경로 · 따옴표로 감싼 전체 경로 · `\\?\` 로 바꾼 것, 서비스 이름 소문자, 파일
         이름 대소문자 → 모두 2(흔적 2 · 위협 1)
      N  아무것도 없음 1 → 0(흔적 0)
      S  서비스만(파일 없음) 1 → 0(흔적 1)
      F  파일만(서비스 없음) 1 → 0(흔적 1)
      M  자동이 아닌 시작 유형 4 — 수동 · 사용 안 함 · 시스템 · 부팅 + 그 파일 → 0(흔적 1)
      D  다른 자리 3 — drivers 폴더(sc.exe 가 둔 꼴) · `System32\drivers\…` · `\SystemRoot\SysWOW64\…` + System32 의 그 파일
         → 0(흔적 1)
      C  치운 뒤 남은 것 1 — 서비스 키 · SCM 의 서비스 · System32 의 그 파일 · 작업 폴더가 모두 없다

    0 칸은 감염 칸에서 한 가지만 다르다. 그 0 이 그 까닭으로 나왔는지를 화면의 흔적 수로 함께 본다 — 흔적 0 이면 룰이 아무
    것도 못 본 것이고, 흔적 1 이면 두 근거 가운데 하나만 선 것이다.

    `-LogDir` 에 칸마다 화면(`<칸>.txt`)과 summary.txt 를 남긴다. 끝줄은 `판정 N/T · 실패 M` 이다.
    종료 코드: 0 = 모든 칸 통과 · 1 = 하나라도 실패(시작 전에 이미 있어 멈춘 것도 1 이다).

.EXAMPLE
    .\testbed\harness\host\Invoke-RuleHarness.ps1 -Harness testbed\harness\host\Invoke-WinwyvernVerify.ps1 `
        -Package D:\dl\x\remedy-windows-x64 -LogDir D:\dl\winwyvern -Inputs D:\dl\inputs
#>
param(
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $LogDir,
    # rc 묶음이 표준 인자로 준다 — 받을 입력이 없어 쓰지 않는다.
    [string] $Inputs,
    [string] $VmAddress
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'VmSession.ps1')

$rule = 'winwyvern-1-check'
$pkgRoot = (Resolve-Path -LiteralPath $Package).Path
$exe = Join-Path $pkgRoot 'remedy.exe'
$ruleDir = Join-Path $pkgRoot "plugins\$rule"
foreach ($p in @($exe, (Join-Path $ruleDir 'plugin.yaml'))) {
    if (-not (Test-Path -LiteralPath $p)) { throw "없다: $p" }
}
$logRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogDir)
New-Item -ItemType Directory -Force $logRoot | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
$summary = Join-Path $logRoot 'summary.txt'
[IO.File]::WriteAllText($summary, '', $utf8)
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`n", $utf8) }

$pass = 0
$fail = 0
$total = 0
function Check([string] $id, [string] $what, [bool] $ok, [string] $evidence) {
    $script:total++
    if ($ok) { $script:pass++ } else { $script:fail++ }
    Note ('{0,-4} {1}  {2} — {3}' -f $id, $(if ($ok) { '통과' } else { '실패' }), $what, $evidence)
}

# 게스트에서 쓰는 도구 — 놓기 · 치우기 · 남은 것. 칸마다 같은 세션에서 다시 정의한다(Invoke-Command 는 범위를 잇지 않는다).
# 치우는 것은 이 하네스가 놓는 셋뿐이다 — 서비스 NeacSafe64 · System32 의 neacsafe64.sys · 작업 폴더.
# sc.exe 는 `&` 로 부르고 종료 코드를 곧바로 받는다. 세션의 오류 동작을 Stop 으로 바꾸지 않는다 — 원격 세션의 네이티브 출력이
# 오류 줄로 올라오면 그 한 줄에 멈춘다. 실패를 봐야 하는 cmdlet 에만 `-ErrorAction Stop` 을 준다.
$guestTools = {
    $svcName = 'NeacSafe64'
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\NeacSafe64'
    $sys32 = Join-Path $env:SystemRoot 'System32'
    $driverFile = Join-Path $sys32 'neacsafe64.sys'

    # 이 하네스가 놓는 것 가운데 지금 있는 것 — 시작 전에는 '랩에 원래 있던 것', 끝에는 '치우고 남은 것' 이다.
    function Get-Leftover([string] $probe) {
        if (Test-Path -LiteralPath $svcKey) { 'HKLM\SYSTEM\CurrentControlSet\Services\NeacSafe64' }
        $null = & sc.exe query $svcName
        $queried = $LASTEXITCODE
        # 1060 = 그런 서비스가 없다. 키가 없는데 SCM 이 아직 안다면 지울 표시만 남은 것이다.
        if ($queried -ne 1060) { 'SCM 의 서비스 NeacSafe64(sc.exe query 종료 {0})' -f $queried }
        if (Test-Path -LiteralPath $driverFile) { $driverFile }
        if ($probe -and (Test-Path -LiteralPath $probe)) { $probe }
    }

    function Clear-Layout {
        if (Test-Path -LiteralPath $svcKey) {
            $null = & sc.exe delete $svcName
            $deleted = $LASTEXITCODE
            # 시작한 적 없는 서비스는 핸들이 닫히면 곧바로 지워진다 — 키가 사라질 때까지 10초까지 기다린다.
            for ($i = 0; $i -lt 40 -and (Test-Path -LiteralPath $svcKey); $i++) { Start-Sleep -Milliseconds 250 }
            if (Test-Path -LiteralPath $svcKey) {
                throw ('서비스 NeacSafe64 가 지워지지 않았다(sc.exe delete 종료 {0} — 지울 표시만 남았을 수 있다)' -f $deleted)
            }
        }
        if (Test-Path -LiteralPath $driverFile) { Remove-Item -LiteralPath $driverFile -Force -ErrorAction Stop }
    }

    # 칸 하나를 세운다. 경로의 <SR> 은 이 기계의 SystemRoot, <SRU> 는 그 대문자다. 세운 것을 그대로 읽어 돌려준다.
    function New-Layout([string] $name, [string] $start, [string] $bin, [string] $image, [string] $imageType, [string] $file) {
        # 32비트 세션이면 System32 가 SysWOW64 로 돌려져 엉뚱한 자리를 잰다.
        if (-not [Environment]::Is64BitProcess) { throw '원격 세션이 32비트다 — System32 쓰기가 SysWOW64 로 돌려진다' }
        $sr = $env:SystemRoot
        if ($name) {
            $binPath = $bin.Replace('<SR>', $sr)
            $made = & sc.exe create $name type= filesys start= $start binPath= $binPath
            $created = $LASTEXITCODE
            if ($created -ne 0) { throw ('sc.exe create 실패(종료 {0}): {1}' -f $created, ($made -join ' ')) }
            if ($image) {
                $img = $image.Replace('<SRU>', $sr.ToUpperInvariant()).Replace('<SR>', $sr)
                $kind = 'ExpandString'
                if ($imageType -eq 'sz') { $kind = 'String' }
                New-ItemProperty -LiteralPath $svcKey -Name 'ImagePath' -Value $img -PropertyType $kind -Force -ErrorAction Stop | Out-Null
            }
        }
        if ($file) {
            $text = 'REMEDY-LAB placeholder neacsafe64.sys - not a driver' + [char]0
            [IO.File]::WriteAllBytes((Join-Path $sys32 $file), [Text.Encoding]::ASCII.GetBytes($text))
        }
        # ImagePath 는 펴지 않은 글자 그대로 읽는다 — PowerShell 은 REG_EXPAND_SZ 를 펴서 돌려준다.
        $stored = ''
        if (Test-Path -LiteralPath $svcKey) {
            $k = Get-Item -LiteralPath $svcKey
            $raw = $k.GetValue('ImagePath', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $stored = 'ImagePath={0}({1}) · Start={2} · Type={3}' -f $raw, $k.GetValueKind('ImagePath'), $k.GetValue('Start'), $k.GetValue('Type')
        }
        $names = @(Get-ChildItem -LiteralPath $sys32 -Filter 'neacsafe64*.sys' -Force | ForEach-Object { $_.Name })
        [pscustomobject]@{ service = $stored; files = ($names -join ',') }
    }
}

$addr = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $addr
$g = 'C:\remedy-probe'

# ASEC 꼴의 등록 — sc.exe 의 binPath(드라이버의 전체 경로). SCM 이 그것을 어떤 꼴로 두는지는 A1 의 칸 줄이 적는다.
# 0 칸은 이 꼴에서 한 가지만 바꾼다(시작 유형 · ImagePath 의 자리 · 둘 가운데 하나를 빼기).
$asec = '<SR>\System32\neacsafe64.sys'
$f = 'neacsafe64.sys'
$cases = @(
    @{ id = 'A1'; what = '감염 — ASEC 꼴(sc.exe 가 둔 ImagePath · 자동 시작 · System32 의 그 파일)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V1'; what = 'ImagePath \SystemRoot\System32\neacsafe64.sys'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '\SystemRoot\System32\neacsafe64.sys'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V2'; what = 'ImagePath System32\neacsafe64.sys(상대 경로)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = 'System32\neacsafe64.sys'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V3'; what = 'ImagePath %SystemRoot%\System32\neacsafe64.sys(펴지 않은 변수)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '%SystemRoot%\System32\neacsafe64.sys'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V4'; what = 'ImagePath %windir%\system32\NeacSafe64.sys(대소문자)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '%windir%\system32\NeacSafe64.sys'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V5'; what = 'ImagePath \??\ 전체 경로 · 대문자'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '\??\<SRU>\SYSTEM32\NEACSAFE64.SYS'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V6'; what = 'ImagePath 전체 경로(REG_SZ)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '<SR>\System32\neacsafe64.sys'; imageType = 'sz'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V7'; what = 'ImagePath 따옴표로 감싼 전체 경로'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '"<SR>\System32\neacsafe64.sys"'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V8'; what = 'ImagePath \\?\ 전체 경로'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '\\?\<SR>\System32\neacsafe64.sys'; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V9'; what = '서비스 이름 소문자(neacsafe64)'; name = 'neacsafe64'; start = 'auto'; bin = $asec; file = $f; expect = 2; traces = 2; threats = 1 },
    @{ id = 'V10'; what = '파일 이름 대소문자(NeacSafe64.SYS)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; file = 'NeacSafe64.SYS'; expect = 2; traces = 2; threats = 1 },
    @{ id = 'N1'; what = '아무것도 없음'; expect = 0; traces = 0; threats = 0 },
    @{ id = 'S1'; what = '서비스만(파일 없음)'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; expect = 0; traces = 1; threats = 0 },
    @{ id = 'F1'; what = 'System32 의 그 파일만(서비스 없음)'; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'M1'; what = '수동 시작 + 그 파일'; name = 'NeacSafe64'; start = 'demand'; bin = $asec; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'M2'; what = '사용 안 함 + 그 파일'; name = 'NeacSafe64'; start = 'disabled'; bin = $asec; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'M3'; what = '시스템 시작 + 그 파일'; name = 'NeacSafe64'; start = 'system'; bin = $asec; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'M4'; what = '부팅 시작 + 그 파일'; name = 'NeacSafe64'; start = 'boot'; bin = $asec; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'D1'; what = 'drivers 폴더(sc.exe 가 둔 꼴) + System32 의 그 파일'; name = 'NeacSafe64'; start = 'auto'; bin = '<SR>\System32\drivers\neacsafe64.sys'; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'D2'; what = 'ImagePath System32\drivers\neacsafe64.sys + System32 의 그 파일'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = 'System32\drivers\neacsafe64.sys'; file = $f; expect = 0; traces = 1; threats = 0 },
    @{ id = 'D3'; what = 'ImagePath \SystemRoot\SysWOW64\neacsafe64.sys + System32 의 그 파일'; name = 'NeacSafe64'; start = 'auto'; bin = $asec; image = '\SystemRoot\SysWOW64\neacsafe64.sys'; file = $f; expect = 0; traces = 1; threats = 0 }
)

# 이미 있으면(랩에 원래 있던 것 · 앞 회차가 남긴 것) 건드리지 않고 멈춘다 — 아래 try 밖이라 멈출 때 finally 의 정리가 돌지 않는다.
try {
    $pre = Invoke-Command -Session $session -ArgumentList $guestTools.ToString() -ScriptBlock {
        param($tools)
        . ([scriptblock]::Create($tools))
        @(Get-Leftover '')
    }
} catch { Remove-PSSession $session; throw }
$already = @($pre | Where-Object { $_ })
if ($already.Count -gt 0) {
    Remove-PSSession $session
    Note ('멈춤 — 랩에 이미 있다(건드리지 않았다): ' + ($already -join ' · '))
    throw ('랩에 이미 있다 — 건드리지 않고 멈춘다: ' + ($already -join ' · '))
}

try {
    Note ("시작 {0}  꾸러미={1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $pkgRoot)
    Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
        New-Item -ItemType Directory -Force "$g\plugins", "$g\out" -ErrorAction Stop | Out-Null
    }
    Copy-GuestFile -Session $session -Source $exe -Destination "$g\remedy.exe"
    Copy-Item -LiteralPath $ruleDir -Destination "$g\plugins" -ToSession $session -Recurse -Force

    foreach ($c in $cases) {
        $placed = Invoke-Command -Session $session -ArgumentList $guestTools.ToString(), $c.name, $c.start, $c.bin, $c.image, $c.imageType, $c.file -ScriptBlock {
            param($tools, $name, $start, $bin, $image, $imageType, $file)
            . ([scriptblock]::Create($tools))
            Clear-Layout | Out-Null
            New-Layout $name $start $bin $image $imageType $file
        }
        $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g `
            -Arguments @('scan', '--plugin', "$g\plugins\$rule\plugin.yaml", '--out-dir', "$g\out\$($c.id)")
        $screen = [string]$r.out + [string]$r.err
        [IO.File]::WriteAllText((Join-Path $logRoot "$($c.id).txt"), ("exit={0}`n{1}" -f $r.exit, $screen), $utf8)
        # 검사 완료 줄의 흔적 · 위협 수 — 0 이 그 칸의 까닭으로 나왔는지 본다(흔적 1 = 근거 하나만 섰다).
        $traces = -1
        $threats = -1
        if ($screen -match '흔적 (\d+)건') { $traces = [int]$Matches[1] }
        if ($screen -match '위협 (\d+)건') { $threats = [int]$Matches[1] }
        $ok = ($r.exit -eq $c.expect) -and ($traces -eq $c.traces) -and ($threats -eq $c.threats)
        $seen = '종료 {0} · 흔적 {1} · 위협 {2} (기대 {3} · {4} · {5})' -f $r.exit, $traces, $threats, $c.expect, $c.traces, $c.threats
        if ($placed.service) { $seen += ' · ' + $placed.service }
        if ($placed.files) { $seen += ' · 파일 ' + $placed.files }
        Check $c.id $c.what $ok $seen
    }
}
catch {
    Check 'E1' '하네스가 끝까지 돌았다' $false $_.Exception.Message
}
finally {
    try {
        $left = Invoke-Command -Session $session -ArgumentList $guestTools.ToString(), $g -ScriptBlock {
            param($tools, $g)
            . ([scriptblock]::Create($tools))
            Clear-Layout | Out-Null
            if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
            @(Get-Leftover $g)
        }
        $left = @($left | Where-Object { $_ })
        Check 'C1' '치운 뒤 남은 것 0(서비스 키 · SCM 의 서비스 · System32 의 그 파일 · 작업 폴더)' ($left.Count -eq 0) $(if ($left.Count) { $left -join ' · ' } else { '없음' })
    } catch {
        Check 'C1' '치운 뒤 남은 것 0' $false ('치우지 못했다: ' + $_.Exception.Message)
    } finally { Remove-PSSession $session }
}
Note ("끝 {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Note ("판정 {0}/{1} · 실패 {2}" -f $pass, $total, $fail)
if ($fail -eq 0) { exit 0 } else { exit 1 }
