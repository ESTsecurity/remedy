#Requires -Version 5.1
<#
.SYNOPSIS
    PHP 11월 보안 업데이트 점검 룰(php-2026-11-check-windows)을 랩 VM 에서 잰다 — 설치본 모양마다 종료 코드와 화면.

.DESCRIPTION
    `-Package` 는 `remedy-windows-x64` 폴더다(내려받아 푼 배포본, 또는 `New-DevPackage.ps1` 로 꾸린 개발 꾸러미). 그
    remedy.exe 와 그 안의 `plugins\php-2026-11-check-windows` 를 그대로 쓴다 — 배포 앵커를 박은 실행 파일은 배포 키로 서명한
    룰만 받는다. `-PhpZipDir` 은 downloads.php.net 의 Windows zip 여섯(`php-8.3.37-nts-Win32-vs16-x64.zip` ·
    `php-8.5.13-Win32-vs17-x64.zip` · `php-8.3.35-nts-Win32-vs16-x64.zip` · `php-8.5.12-Win32-vs17-x64.zip` ·
    `php-8.4.27-nts-Win32-vs17-x64.zip` · `php-8.2.35-nts-Win32-vs16-x64.zip` — 뒤의 넷은 `releases/archives`)이 든 폴더다(SHA-256 을
    이 스크립트가 대조한다 · 커밋하지 않는
    `testbed\harness\results\rc-inputs\php-win` — 8.3.35 는 그 위 `rc-inputs` 에 있던 것을 옮겨 둔다). 세 경로 모두 상대 경로로
    줘도 된다(절대 경로로 바꿔 쓴다).

    # 무해한가

    실검체는 없다. 진짜 PHP 는 공식 zip 의 코어 DLL 하나이고 **실행하지 않는다**(파일만 둔다). 판 없는 경우는 자리 채우기다 —
    PE 가 아닌 작은 `php8.dll`. 자리 밖 서비스는 만들기만 하고 시작하지 않는다. 자리 밖 프로세스는 Windows 의 `PING.EXE`
    사본을 `php-cgi.exe` 이름으로 잠깐 띄운다. 놓은 것은 경우마다, 그리고 끝에 모두 치운다. 치우는 자리가 시작 전에 이미 있으면
    (랩에 원래 있던 것) 건드리지 않고 멈춘다.

    # 무엇을 재나

      R  진짜 6 — C:\php 에 8.3.37(NTS) 0 · 8.5.13(TS) 0 · 8.3.35(NTS) 2 · 8.5.12(TS) 2 · 8.4.27(NTS) 2 · 8.2.35(NTS) 2(코어 DLL
         의 파일 버전을 읽는가 · 갈래 넷의 영향 쪽 — 고친 판의 0 은 'PHP 없음' 의 0 과 같은 종료 코드라 화면의 흔적 2건으로
         찾았음을 함께 본다)
      E  겹친 설치본 2 — 바깥 판 없음 + 안쪽 8.3.37 6(바깥을 안쪽이 채우지 않는다) · 바깥 8.3.37 + 안쪽 8.3.35 2(취약 1건)
      W  WampServer 1 — 8.3.37 + Apache bin 의 코어 DLL 심볼릭 링크 0(링크를 설치본으로 세지 않는다)
      L  다른 자리 6(8.3.35) — Program Files\PHP · Program Files\PHP\v8.3(판 폴더) · XAMPP · WampServer(판 폴더) ·
         Laragon(판 폴더) · Chocolatey(C:\tools\php83) 모두 2
      V  판 없음 1 — C:\php 의 자리 채우기 6
      G  설치본 둘 2 — 8.3.37 + Laragon 8.3.35 2 · 8.3.37 + Laragon 판 없음 6(설치본마다 가른다)
      O  자리 밖 4 — 서비스(만들기만) 6 · 도는 php-cgi.exe 6 · 자리 밖을 띄우는 NSSM 서비스 6 · 자리 안 서비스 + 8.3.37 0
      N  PHP 없음 1 — 0
      S  화면 — 고친 판 셋의 흔적 2건 · 취약 줄의 올릴 버전 · TS 영향 판의 경로 · 판 없음의 까닭 · 자리 밖의 까닭 둘 · 모든
         화면에 내부 낱말(판 · 갈래) 0 · 룰 파일의 ko 문구 전부에 내부 낱말 0

    `-LogDir` 에 경우마다 화면(`<칸>.txt`)과 summary.txt 를 남긴다. 끝줄은 `판정 N/T · 실패 M` 이다.
    종료 코드: 0 = 모든 칸 통과 · 1 = 하나라도 실패.

.EXAMPLE
    .\testbed\harness\host\Invoke-Php202611Verify.ps1 -Package D:\dl\x\remedy-windows-x64 `
        -PhpZipDir testbed\harness\results\rc-inputs\php-win -LogDir D:\dl\php2611-win
#>
param(
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $PhpZipDir,
    [Parameter(Mandatory = $true)][string] $LogDir,
    [string] $VmAddress
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'VmSession.ps1')

# downloads.php.net 의 Windows zip — 판 · 파일 이름 · 코어 DLL · SHA-256(8.3.37 · 8.5.13 은 2026-11-19 의 sha256sum.txt 와 대조).
$zips = [ordered]@{
    '8.3.37' = @{ file = 'php-8.3.37-nts-Win32-vs16-x64.zip'; dll = 'php8.dll'
        sha = '38808A798485E1C0938DFCCE7E942131415FC6C7834F83A5A85A4C4EDB5539D6' }
    '8.5.13' = @{ file = 'php-8.5.13-Win32-vs17-x64.zip'; dll = 'php8ts.dll'
        sha = '792FE1553895EE98F9BC3C9D50C539910F7D0066676A6523207CA91429D4D475' }
    # 8.3.35 · 8.5.12 는 zip 이 아니라 꺼낸 코어 DLL 을 PHP2Shell Windows 룰이 적은 공식 빌드 해시와 대조한다(archives 에는
    # sha256sum.txt 가 없다). 8.5.12 는 TS 코어 DLL(`php8ts.dll`)의 영향 판 칸이다.
    '8.3.35' = @{ file = 'php-8.3.35-nts-Win32-vs16-x64.zip'; dll = 'php8.dll'; sha = ''
        dllsha = '37D0E60D20B7F17A564BAFAB657F9CF448044A3F333A6ABCE8750113D79FE5F7' }
    '8.5.12' = @{ file = 'php-8.5.12-Win32-vs17-x64.zip'; dll = 'php8ts.dll'; sha = ''
        dllsha = 'A3D2ACD1453AAFF16BE437FD9975F8B923CC190095931158BC8E1444D0DB3069' }
    '8.4.27' = @{ file = 'php-8.4.27-nts-Win32-vs17-x64.zip'; dll = 'php8.dll'; sha = ''
        dllsha = '8B8B1C4D535A28204D27C86652F923C4B69F3196580B43D02307FE7060954CAC' }
    '8.2.35' = @{ file = 'php-8.2.35-nts-Win32-vs16-x64.zip'; dll = 'php8.dll'; sha = ''
        dllsha = '87CDF69CD713D167B9171A2147287C19A6F360838D7D2392BA122E7F36510707' }
}
# 상대 경로를 절대 경로로 — .NET 호출(ZipFile · File)은 PowerShell 의 현재 위치가 아니라 프로세스의 현재 폴더로 푼다.
foreach ($p in @($Package, $PhpZipDir)) {
    if (-not (Test-Path -LiteralPath $p -PathType Container)) { throw "폴더가 없다: $p" }
}
$Package = (Resolve-Path -LiteralPath $Package).ProviderPath
$PhpZipDir = (Resolve-Path -LiteralPath $PhpZipDir).ProviderPath
New-Item -ItemType Directory -Force $LogDir | Out-Null
$LogDir = (Resolve-Path -LiteralPath $LogDir).ProviderPath
$rule = 'php-2026-11-check-windows'
$exe = Join-Path $Package 'remedy.exe'
$ruleDir = Join-Path $Package "plugins\$rule"
foreach ($p in @($exe, (Join-Path $ruleDir 'plugin.yaml'))) {
    if (-not (Test-Path -LiteralPath $p)) { throw "없다: $p" }
}
$utf8 = New-Object System.Text.UTF8Encoding $false
$summary = Join-Path $LogDir 'summary.txt'
[IO.File]::WriteAllText($summary, '', $utf8)
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`n", $utf8) }

# 코어 DLL 만 꺼낸다(호스트 · 결과 폴더 안) — 게스트에는 그 파일 하나씩만 보낸다.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$dllRoot = Join-Path $LogDir 'core-dll'
foreach ($v in $zips.Keys) {
    $z = Join-Path $PhpZipDir $zips[$v].file
    if (-not (Test-Path -LiteralPath $z)) { throw "없다: $z" }
    $got = (Get-FileHash -LiteralPath $z -Algorithm SHA256).Hash
    if ($zips[$v].sha -and $got -ne $zips[$v].sha) { throw "$($zips[$v].file) 의 SHA-256 이 다르다: $got (기대 $($zips[$v].sha))" }
    Note ("zip {0} SHA-256 {1}" -f $zips[$v].file, $got)
    $dest = Join-Path $dllRoot $v
    New-Item -ItemType Directory -Force $dest | Out-Null
    $archive = [IO.Compression.ZipFile]::OpenRead($z)
    try {
        $entry = $archive.Entries | Where-Object { $_.FullName -eq $zips[$v].dll } | Select-Object -First 1
        if (-not $entry) { throw "$($zips[$v].file) 에 $($zips[$v].dll) 이 없다" }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $dest $zips[$v].dll), $true)
    } finally { $archive.Dispose() }
    if ($zips[$v].dllsha) {
        $dllGot = (Get-FileHash -LiteralPath (Join-Path $dest $zips[$v].dll) -Algorithm SHA256).Hash
        if ($dllGot -ne $zips[$v].dllsha) { throw "$v 의 $($zips[$v].dll) SHA-256 이 다르다: $dllGot (기대 $($zips[$v].dllsha))" }
    }
}

$addr = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $addr
$g = 'C:\remedy-probe'

# 게스트에서 쓰는 도구 — 놓기 · 치우기. 경우마다 같은 세션에서 다시 정의한다(Invoke-Command 는 범위를 잇지 않는다).
# 치우는 자리는 이 하네스가 만드는 폴더뿐이다 — XAMPP · WampServer · Laragon 의 다른 폴더는 건드리지 않는다.
$guestTools = {
    $made = @('C:\php', 'C:\Program Files\PHP', 'C:\xampp\php', 'C:\wamp64\bin\php\php8.3.35', 'C:\wamp64\bin\php\php8.3.37',
        'C:\wamp64\bin\apache\apache2.4.62', 'C:\laragon\bin\php\php-8.3.35-nts-Win32-vs16-x64', 'C:\tools\php83', 'C:\web')
    $parents = @('C:\xampp', 'C:\wamp64\bin\php', 'C:\wamp64\bin\apache', 'C:\wamp64\bin', 'C:\wamp64', 'C:\laragon\bin\php',
        'C:\laragon\bin', 'C:\laragon', 'C:\tools')
    $real = 'C:\remedy-probe\real'
    # $keep — 시작 전에 이미 있던 부모 폴더(랩의 것). 비어 있어도 지우지 않는다.
    function Clear-Layouts([string[]] $keep) {
        foreach ($svc in @('RemedyLabPhp', 'RemedyLabPhpIn', 'RemedyLabPhpNssm')) {
            if (Get-Service -Name $svc -ErrorAction SilentlyContinue) { & sc.exe delete $svc | Out-Null }
        }
        $ours = @(Get-Process -Name php-cgi -ErrorAction SilentlyContinue | Where-Object { $_.Path -like 'C:\web\*' })
        foreach ($p in $ours) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            $null = $p.WaitForExit(10000)
        }
        foreach ($r in $made) {
            if (Test-Path -LiteralPath $r) { [System.IO.Directory]::Delete('\\?\' + $r, $true) }
        }
        # 이 하네스가 만든 빈 부모 폴더만 지운다 — 시작 전에 있던 것과 무엇이 든 것은 남긴다.
        foreach ($r in $parents) {
            if (@($keep) -contains $r) { continue }
            if ((Test-Path -LiteralPath $r) -and -not (Get-ChildItem -LiteralPath $r -Force | Select-Object -First 1)) {
                Remove-Item -LiteralPath $r -Force
            }
        }
    }
    # 설치본 하나는 `자리|판` 한 줄로 넘긴다 — 판: real-<판>(진짜 코어 DLL) · none(PE 가 아닌 자리 채우기).
    function New-Install([string] $line) {
        $root, $version = $line -split '\|'
        New-Item -ItemType Directory -Force $root | Out-Null
        if ($version -like 'real-*') {
            $v = $version.Substring(5)
            Copy-Item -Path "$real\$v\*" -Destination $root -Force
        } else {
            $text = 'REMEDY-LAB placeholder php8.dll' + [char]0
            [IO.File]::WriteAllBytes("$root\php8.dll", [Text.Encoding]::ASCII.GetBytes($text))
        }
        if (-not (Get-ChildItem -LiteralPath $root -Filter 'php8*.dll')) { throw "놓지 못했다: $root" }
    }
}

$cases = @(
    # 고친 판의 0 은 'PHP 없음' 의 0 과 같은 종료 코드다 — 코어 DLL 을 찾아 판을 읽었는지(흔적 2건: core · core_version_known)를
    # 화면으로 함께 본다. N1 은 흔적 0건이다.
    @{ id = 'R1'; what = '진짜 8.3.37 NTS(고친 판) · C:\php'; expect = 0; installs = @('C:\php|real-8.3.37'); screen = '흔적 2건' },
    @{ id = 'R2'; what = '진짜 8.5.13 TS(고친 판) · C:\php'; expect = 0; installs = @('C:\php|real-8.5.13'); screen = '흔적 2건' },
    @{ id = 'R3'; what = '진짜 8.3.35 NTS(영향 판) · C:\php'; expect = 2; installs = @('C:\php|real-8.3.35');
       screen = '그 계열의 고친 버전(8.5.13 · 8.4.28 · 8.3.37 · 8.2.36) 이상으로 올리십시오' },
    @{ id = 'R4'; what = '진짜 8.5.12 TS(영향 판 · 8.5 갈래) · C:\php'; expect = 2; installs = @('C:\php|real-8.5.12');
       screen = 'php8ts.dll  (버전 8.5.12)' },
    @{ id = 'R5'; what = '진짜 8.4.27 NTS(영향 판 · 8.4 갈래) · C:\php'; expect = 2; installs = @('C:\php|real-8.4.27');
       screen = 'php8.dll  (버전 8.4.27)' },
    @{ id = 'R6'; what = '진짜 8.2.35 NTS(영향 판 · 8.2 갈래) · C:\php'; expect = 2; installs = @('C:\php|real-8.2.35');
       screen = 'php8.dll  (버전 8.2.35)' },
    @{ id = 'L1'; what = 'Program Files\PHP 8.3.35'; expect = 2; installs = @('C:\Program Files\PHP|real-8.3.35') },
    @{ id = 'L2'; what = 'Program Files\PHP\v8.3(판 폴더) 8.3.35'; expect = 2; installs = @('C:\Program Files\PHP\v8.3|real-8.3.35') },
    @{ id = 'L3'; what = 'XAMPP 8.3.35'; expect = 2; installs = @('C:\xampp\php|real-8.3.35') },
    @{ id = 'L4'; what = 'WampServer(판 폴더) 8.3.35'; expect = 2; installs = @('C:\wamp64\bin\php\php8.3.35|real-8.3.35') },
    @{ id = 'L5'; what = 'Laragon(판 폴더) 8.3.35'; expect = 2;
       installs = @('C:\laragon\bin\php\php-8.3.35-nts-Win32-vs16-x64|real-8.3.35') },
    @{ id = 'L6'; what = 'Chocolatey(C:\tools\php83) 8.3.35'; expect = 2; installs = @('C:\tools\php83|real-8.3.35') },
    @{ id = 'V1'; what = 'C:\php · 판 없음(PE 가 아님)'; expect = 6; installs = @('C:\php|none');
       screen = '코어 DLL 에서 정식 버전을 읽지 못했습니다' },
    # 설치본 폴더 안의 다른 설치본(옛 판 백업 등) — 판 사실은 그 그룹의 코어 DLL 하나에만 묶는다. 바깥의 '판 없음' 을 안쪽의
    # 고친 판이 채우지 않고(6), 안쪽 영향 판은 한 번만 센다(취약 1건).
    @{ id = 'E1'; what = '겹친 설치본 — 바깥 판 없음 + 안쪽 8.3.37'; expect = 6;
       installs = @('C:\php|none', 'C:\php\old\php-8.3.37|real-8.3.37'); screen = '코어 DLL 에서 정식 버전을 읽지 못했습니다' },
    @{ id = 'E2'; what = '겹친 설치본 — 바깥 8.3.37 + 안쪽 8.3.35'; expect = 2;
       installs = @('C:\php|real-8.3.37', 'C:\php\old\php-8.3.35|real-8.3.35'); screen = '취약 1건' },
    # WampServer 꼴 — Apache 모듈로 쓰는 PHP 의 코어 DLL 을 Apache bin 에 심볼릭 링크로 둔다. 파일은 PHP 자리만 걸으므로 그 링크는
    # 설치본이 아니다 — 고친 판이면 0(흔적 2건: PHP 판 폴더의 코어 DLL 하나).
    @{ id = 'W1'; what = 'WampServer — 8.3.37 + Apache bin 의 코어 DLL 링크'; expect = 0;
       installs = @('C:\wamp64\bin\php\php8.3.37|real-8.3.37');
       link = 'C:\wamp64\bin\apache\apache2.4.62\bin\php8.dll|C:\wamp64\bin\php\php8.3.37\php8.dll'; screen = '흔적 2건' },
    @{ id = 'G1'; what = '8.3.37 + Laragon 8.3.35 — 설치본마다'; expect = 2;
       installs = @('C:\php|real-8.3.37', 'C:\laragon\bin\php\php-8.3.35-nts-Win32-vs16-x64|real-8.3.35') },
    @{ id = 'G2'; what = '8.3.37 + Laragon 판 없음'; expect = 6;
       installs = @('C:\php|real-8.3.37', 'C:\laragon\bin\php\php-8.3.35-nts-Win32-vs16-x64|none') },
    @{ id = 'O1'; what = '자리 밖 PHP 서비스(만들기만)'; expect = 6; installs = @(); service = 'C:\web\php\php-cgi.exe';
       screen = '이 점검이 보는 자리 밖의 PHP 를 서비스가 띄우거나' },
    @{ id = 'O2'; what = '자리 밖에서 도는 php-cgi.exe'; expect = 6; installs = @(); process = 'C:\web\php\php-cgi.exe';
       screen = '그 PHP 가 실행 중입니다' },
    @{ id = 'O3'; what = '자리 밖 PHP 를 띄우는 NSSM 서비스(Parameters\Application)'; expect = 6; installs = @();
       nssm = 'C:\web\php\php-cgi.exe' },
    @{ id = 'O4'; what = '자리 안 서비스 + 8.3.37'; expect = 0; installs = @('C:\php|real-8.3.37'); serviceIn = 'C:\php\php-cgi.exe';
       screen = '흔적 2건' },
    @{ id = 'N1'; what = 'PHP 없음'; expect = 0; installs = @() }
)

$pass = 0
$fail = 0
$total = 0
function Check([string] $id, [string] $what, [bool] $ok, [string] $evidence) {
    $script:total++
    if ($ok) { $script:pass++ } else { $script:fail++ }
    Note ('{0,-4} {1}  {2} — {3}' -f $id, $(if ($ok) { '통과' } else { '실패' }), $what, $evidence)
}

Note ("시작 {0}  꾸러미={1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Package)
# 치울 자리가 이미 있으면(랩에 원래 있던 것) 건드리지 않고 멈춘다 — 아래 try 밖이라 멈출 때 finally 의 정리가 돌지 않는다.
# 시작 전에 있던 부모 폴더는 $keep 으로 넘겨, 비어 있어도 지우지 않는다.
try {
    $pre = Invoke-Command -Session $session -ArgumentList $guestTools.ToString() -ScriptBlock {
        param($tools)
        . ([scriptblock]::Create($tools))
        [pscustomobject]@{
            made    = @($made | Where-Object { Test-Path -LiteralPath $_ })
            parents = @($parents | Where-Object { Test-Path -LiteralPath $_ })
        }
    }
} catch { Remove-PSSession $session; throw }
$already = @($pre.made | Where-Object { $_ })
$keep = @($pre.parents | Where-Object { $_ })
if ($already.Count -gt 0) {
    Remove-PSSession $session
    Note ("멈춤 — 랩에 이미 있다(건드리지 않았다): " + ($already -join ' · '))
    throw ("랩에 이미 있다 — 건드리지 않고 멈춘다: " + ($already -join ' · '))
}
Note ("시작 전에 있던 부모 폴더(남긴다): " + $(if ($keep.Count) { $keep -join ' · ' } else { '없음' }))

try {
    Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
        New-Item -ItemType Directory -Force "$g\plugins", "$g\real", "$g\out" | Out-Null
    }
    Copy-GuestFile -Session $session -Source $exe -Destination "$g\remedy.exe"
    Copy-Item -LiteralPath $ruleDir -Destination "$g\plugins" -ToSession $session -Recurse -Force
    foreach ($v in $zips.Keys) {
        Invoke-Command -Session $session -ArgumentList "$g\real\$v" -ScriptBlock { param($d) New-Item -ItemType Directory -Force $d | Out-Null }
        Copy-GuestFile -Session $session -Source (Join-Path (Join-Path $dllRoot $v) $zips[$v].dll) -Destination "$g\real\$v\$($zips[$v].dll)"
    }

    foreach ($c in $cases) {
        $setupScript = $guestTools.ToString()
        Invoke-Command -Session $session -ArgumentList $setupScript, $c.installs, $c.service, $c.process, $c.serviceIn, $c.nssm, $keep, $c.link -ScriptBlock {
            param($tools, $installs, $service, $process, $serviceIn, $nssm, $keep, $link)
            . ([scriptblock]::Create($tools))
            Clear-Layouts $keep
            foreach ($i in @($installs)) {
                if ($i) { New-Install ([string]$i) }
            }
            # 심볼릭 링크 — `링크|대상` 한 줄(WampServer 의 Apache bin 꼴).
            if ($link) {
                $linkPath, $linkTarget = ([string]$link) -split '\|'
                New-Item -ItemType Directory -Force (Split-Path -Parent $linkPath) | Out-Null
                New-Item -ItemType SymbolicLink -Path $linkPath -Target $linkTarget | Out-Null
                if (-not (Get-Item -LiteralPath $linkPath).LinkType) { throw "링크를 만들지 못했다: $linkPath" }
            }
            # NSSM 꼴 — 서비스의 실행 파일은 감싸는 프로그램(없어도 된다 · 시작하지 않는다)이고 띄우는 것은 Parameters 의
            # Application 값이다(NSSM 이 쓰는 자리 그대로).
            if ($nssm) {
                New-Service -Name 'RemedyLabPhpNssm' -BinaryPathName '"C:\web\nssm\nssm.exe"' -StartupType Manual | Out-Null
                $pk = 'HKLM:\SYSTEM\CurrentControlSet\Services\RemedyLabPhpNssm\Parameters'
                New-Item -Path $pk -Force | Out-Null
                New-ItemProperty -Path $pk -Name 'Application' -Value $nssm -PropertyType ExpandString -Force | Out-Null
                New-ItemProperty -Path $pk -Name 'AppDirectory' -Value (Split-Path -Parent $nssm) -PropertyType ExpandString -Force | Out-Null
            }
            if ($service) {
                New-Service -Name 'RemedyLabPhp' -BinaryPathName ('"' + $service + '"') -StartupType Manual | Out-Null
            }
            if ($serviceIn) {
                New-Service -Name 'RemedyLabPhpIn' -BinaryPathName ('"' + $serviceIn + '"') -StartupType Manual | Out-Null
            }
            if ($process) {
                New-Item -ItemType Directory -Force (Split-Path -Parent $process) | Out-Null
                Copy-Item -LiteralPath "$env:windir\System32\PING.EXE" -Destination $process -Force
                Start-Process -FilePath $process -ArgumentList @('-n', '600', '127.0.0.1') -WindowStyle Hidden | Out-Null
                Start-Sleep -Seconds 1
            }
        }
        $out = "$g\out\$($c.id)"
        $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g `
            -Arguments @('scan', '--plugin', "$g\plugins\$rule\plugin.yaml", '--out-dir', $out)
        $screen = [string]$r.out + [string]$r.err
        [IO.File]::WriteAllText((Join-Path $LogDir "$($c.id).txt"), ("exit={0}`n{1}" -f $r.exit, $screen), $utf8)
        Check $c.id $c.what ($r.exit -eq $c.expect) ("종료 {0} (기대 {1})" -f $r.exit, $c.expect)
        if ($c.screen) {
            Check "S-$($c.id)" "화면 — $($c.what)" ($screen.Contains($c.screen)) $c.screen
        }
    }
    # 고객 화면의 낱말 — 내부 낱말 '판'(배포판 · 판정 · 판단은 센다 밖) · '갈래' 가 없다. 화면에 나온 문구(S-W)와, 화면에 나오지
    # 않은 까닭까지 룰 파일의 ko 문구 전부(S-Y)를 본다.
    $internal = '(?<!배포)판(?!정|단)|갈래'
    $words = 0
    foreach ($c in $cases) {
        $t = [IO.File]::ReadAllText((Join-Path $LogDir "$($c.id).txt"), $utf8)
        $words += ([regex]::Matches($t, $internal)).Count
    }
    Check 'S-W' '모든 화면에 내부 낱말(판 · 갈래) 0' ($words -eq 0) ("{0}곳" -f $words)
    $koLines = @([IO.File]::ReadAllLines((Join-Path $ruleDir 'plugin.yaml'), $utf8) | Where-Object { $_ -match '^\s+ko:\s' })
    $koWords = 0
    foreach ($line in $koLines) { $koWords += ([regex]::Matches($line, $internal)).Count }
    Check 'S-Y' '룰 파일의 ko 문구 전부에 내부 낱말(판 · 갈래) 0' (($koLines.Count -gt 0) -and ($koWords -eq 0)) ("ko {0}줄 · {1}곳" -f $koLines.Count, $koWords)
}
finally {
    try {
        Invoke-Command -Session $session -ArgumentList $guestTools.ToString(), $g, $keep -ScriptBlock {
            param($tools, $g, $keep)
            . ([scriptblock]::Create($tools))
            Clear-Layouts $keep
            if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
        }
    } finally { Remove-PSSession $session }
}
Note ("끝 {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Note ("판정 {0}/{1} · 실패 {2}" -f $pass, $total, $fail)
if ($fail -eq 0) { exit 0 } else { exit 1 }
