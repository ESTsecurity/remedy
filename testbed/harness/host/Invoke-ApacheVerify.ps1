#Requires -Version 5.1
<#
.SYNOPSIS
    Apache HTTP/2 점검 룰(apache-http2-check-windows)을 랩 VM 에서 잰다 — 설치본 모양마다 종료 코드와 화면.

.DESCRIPTION
    `-Package` 는 `remedy-windows-x64` 폴더다(내려받아 푼 배포본, 또는 같은 차례로 꾸린 개발 꾸러미). 그 remedy.exe 와
    그 안의 `plugins\apache-http2-check-windows` 를 그대로 쓴다 — 배포 앵커를 박은 실행 파일은 배포 키로 서명한 룰만
    받는다. `-ApacheZip` 은 Apache Lounge 의 `httpd-2.4.71-261112-Win64-VS18.zip` 이다(SHA-256 을 이 스크립트가 대조한다).

    # 무해한가

    실검체는 없다. 진짜 Apache 는 Apache Lounge 의 고친 판 2.4.71 zip 하나이고 **실행하지 않는다**(파일만 둔다). 취약한
    판은 자리 채우기다 — 서버 판 문자열(`Apache/2.4.65 (Win64)`)만 담은 작은 `libhttpd.dll` 에, 설정은 2.4.71 의
    `httpd.conf` · `extra\httpd-ssl.conf` 를 고쳐 쓴다. 자리 밖 서비스는 만들기만 하고 시작하지 않는다. 자리 밖 프로세스는
    Windows 의 `PING.EXE` 사본을 `httpd.exe` 이름으로 잠깐 띄운다. 놓은 것은 경우마다, 그리고 끝에 모두 치운다.

    # 무엇을 재나

      R  진짜 2.4.71 2 — HTTP/2 를 다 켬 0 · 기본 설정 0
      V  Apache Lounge 자리(C:\Apache24) 자리 채우기 12 — 2.4.65 + h2 2 · 기본 설정 6 · 모듈만 6 · Protocols 만 6 ·
         Protocols 가 extra\httpd-ssl.conf 에 2 · 2.4.70 h2c 만 2 · 2.4.55 2 · 2.4.54 0 · 주석 Protocols 6 · 2.2.34 0 ·
         서버 판 없음 6 · conf\original 에만 켠 줄 6
      L  다른 자리 4(2.4.65 + h2) — XAMPP · WampServer · Laragon · 옛 설치 프로그램 모두 2
      G  설치본 둘 3 — XAMPP 2.4.65 기본 + Apache24 2.4.71 h2 6(2 가 아니다 — 설치본마다 가른다) · 둘 다 h2 2 ·
         WampServer 2.4.65 기본 + XAMPP 2.4.71 h2 6
      O  자리 밖 3 — 서비스(만들기만) 6 · 도는 httpd.exe 6 · 자리 안 서비스 + 진짜 2.4.71 0
      N  Apache 없음 1 — 0
      S  화면 4 — 취약의 CVE 문구 · 흔적 없음의 까닭 · 판 없음의 까닭 · 자리 밖의 까닭
      K  개인키 1 — conf\private\server.key 의 표지가 결과 파일 · 화면에 0

    `-LogDir` 에 경우마다 화면(`<칸>.txt`)과 summary.txt 를 남긴다. 끝줄은 `판정 N/T · 실패 M` 이다.
    종료 코드: 0 = 모든 칸 통과 · 1 = 하나라도 실패.

.EXAMPLE
    .\testbed\harness\host\Invoke-ApacheVerify.ps1 -Package D:\dl\x\remedy-windows-x64 `
        -ApacheZip testbed\harness\results\rc-inputs\httpd-2.4.71-261112-Win64-VS18.zip -LogDir D:\dl\apache-win
#>
param(
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $ApacheZip,
    [Parameter(Mandatory = $true)][string] $LogDir,
    [string] $VmAddress
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'VmSession.ps1')

$zipSha = '44961A929DFF16B767B3ADBCEA55760A942A00239B2891DC55806BE34029E1FC'
$rule = 'apache-http2-check-windows'
$exe = Join-Path $Package 'remedy.exe'
$ruleDir = Join-Path $Package "plugins\$rule"
foreach ($p in @($exe, (Join-Path $ruleDir 'plugin.yaml'), $ApacheZip)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "없다: $p" }
}
$gotSha = (Get-FileHash -LiteralPath $ApacheZip -Algorithm SHA256).Hash
if ($gotSha -ne $zipSha) { throw "Apache zip 의 SHA-256 이 다르다: $gotSha (기대 $zipSha)" }
New-Item -ItemType Directory -Force $LogDir | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
$summary = Join-Path $LogDir 'summary.txt'
[IO.File]::WriteAllText($summary, '', $utf8)
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`n", $utf8) }

$addr = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $addr
$g = 'C:\remedy-probe'
$keyMark = 'REMEDY-LAB-FAKE-PRIVATE-KEY-7f3a91'

# 게스트에서 쓰는 도구 — 놓기 · 치우기. 경우마다 같은 세션에서 다시 정의한다(Invoke-Command 는 범위를 잇지 않는다).
$guestTools = {
    $roots = @('C:\Apache24', 'C:\xampp', 'C:\wamp64', 'C:\laragon', 'C:\Program Files\Apache Software Foundation', 'C:\web')
    $real = 'C:\remedy-probe\real\Apache24'
    function Clear-Layouts {
        foreach ($s in @('RemedyLabApache', 'RemedyLabApacheIn')) {
            if (Get-Service -Name $s -ErrorAction SilentlyContinue) { & sc.exe delete $s | Out-Null }
        }
        $ours = @(Get-Process -Name httpd -ErrorAction SilentlyContinue | Where-Object { $_.Path -like 'C:\web\*' })
        foreach ($p in $ours) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            $null = $p.WaitForExit(10000)
        }
        foreach ($r in $roots) {
            if (Test-Path -LiteralPath $r) { [System.IO.Directory]::Delete('\\?\' + $r, $true) }
        }
    }
    # 설정 꼴: off(기본) · full(모듈 + Protocols h2) · module · protocols · ssl(Protocols 가 extra\httpd-ssl.conf) ·
    # h2c · commented(Protocols 가 주석) · original(conf\original 에만 켠 줄)
    function Set-Conf([string] $root, [string] $mode) {
        $conf = Join-Path $root 'conf'
        foreach ($d in @($conf, "$conf\extra", "$conf\original", "$conf\private")) { New-Item -ItemType Directory -Force $d | Out-Null }
        $base = [IO.File]::ReadAllText("$real\conf\httpd.conf")
        $ssl = [IO.File]::ReadAllText("$real\conf\extra\httpd-ssl.conf")
        $on = [regex]::Replace($base, '(?m)^#\s*LoadModule http2_module', 'LoadModule http2_module')
        $main = $base
        $orig = $base
        switch ($mode) {
            'off' { }
            'full' { $main = $on + "`r`nProtocols h2 http/1.1`r`n" }
            'module' { $main = $on }
            'protocols' { $main = $base + "`r`nProtocols h2 http/1.1`r`n" }
            'ssl' { $main = $on; $ssl = $ssl + "`r`nProtocols h2 http/1.1`r`n" }
            'h2c' { $main = $on + "`r`nProtocols h2c http/1.1`r`n" }
            'commented' { $main = $on + "`r`n# Protocols h2 http/1.1`r`n" }
            'original' { $orig = $on + "`r`nProtocols h2 http/1.1`r`n" }
            default { throw "모르는 설정 꼴: $mode" }
        }
        [IO.File]::WriteAllText("$conf\httpd.conf", $main)
        [IO.File]::WriteAllText("$conf\extra\httpd-ssl.conf", $ssl)
        [IO.File]::WriteAllText("$conf\original\httpd.conf", $orig)
    }
    # 판: real(진짜 2.4.71 트리) · 2.x.y(자리 채우기 DLL) · none(서버 판 없는 DLL). 설치본 하나는 `자리|판|설정 꼴`
    # 한 줄로 넘긴다 — 원소 하나인 배열 안의 배열은 PowerShell 이 펴 버린다.
    function New-Install([string] $line) {
        $root, $version, $mode = $line -split '\|'
        if ($version -eq 'real') {
            New-Item -ItemType Directory -Force $root | Out-Null
            Copy-Item -Path "$real\*" -Destination $root -Recurse -Force
        } else {
            New-Item -ItemType Directory -Force "$root\bin" | Out-Null
            $text = 'REMEDY-LAB placeholder libhttpd.dll' + [char]0
            if ($version -ne 'none') { $text += "Apache/$version (Win64)" + [char]0 + "Apache/$version" + [char]0 }
            [IO.File]::WriteAllBytes("$root\bin\libhttpd.dll", [Text.Encoding]::ASCII.GetBytes($text))
        }
        Set-Conf $root $mode
    }
}

$cases = @(
    @{ id = 'R1'; what = '진짜 2.4.71 · HTTP/2 를 다 켬'; expect = 0; installs = @('C:\Apache24|real|full') },
    @{ id = 'R2'; what = '진짜 2.4.71 · 기본 설정'; expect = 0; installs = @('C:\Apache24|real|off') },
    @{ id = 'V1'; what = 'Apache24 2.4.65 · HTTP/2 를 다 켬'; expect = 2; installs = @('C:\Apache24|2.4.65|full');
       screen = 'CVE-2026-119618 · 2.4.71 이상으로 올리십시오' },
    @{ id = 'V2'; what = 'Apache24 2.4.65 · 기본 설정'; expect = 6; installs = @('C:\Apache24|2.4.65|off');
       screen = 'HTTP/2 를 켠 흔적(LoadModule http2_module 과 Protocols 의 h2 · h2c)을 다 찾지 못했습니다' },
    @{ id = 'V3'; what = 'Apache24 2.4.65 · 모듈만'; expect = 6; installs = @('C:\Apache24|2.4.65|module') },
    @{ id = 'V4'; what = 'Apache24 2.4.65 · Protocols 만'; expect = 6; installs = @('C:\Apache24|2.4.65|protocols') },
    @{ id = 'V5'; what = 'Apache24 2.4.65 · Protocols 가 extra\httpd-ssl.conf 에'; expect = 2; installs = @('C:\Apache24|2.4.65|ssl') },
    @{ id = 'V6'; what = 'Apache24 2.4.70 · h2c 만'; expect = 2; installs = @('C:\Apache24|2.4.70|h2c') },
    @{ id = 'V7'; what = 'Apache24 2.4.55(영향 범위의 아래 끝) · HTTP/2'; expect = 2; installs = @('C:\Apache24|2.4.55|full') },
    @{ id = 'V8'; what = 'Apache24 2.4.54(영향 없음) · HTTP/2'; expect = 0; installs = @('C:\Apache24|2.4.54|full') },
    @{ id = 'V9'; what = 'Apache24 2.4.65 · Protocols 줄이 주석'; expect = 6; installs = @('C:\Apache24|2.4.65|commented') },
    @{ id = 'V10'; what = 'Apache24 2.2.34(mod_http2 없음) · HTTP/2 꼴 줄'; expect = 0; installs = @('C:\Apache24|2.2.34|full') },
    @{ id = 'V11'; what = 'Apache24 · 서버 판 없는 libhttpd.dll'; expect = 6; installs = @('C:\Apache24|none|full');
       screen = 'libhttpd.dll 에서 서버 판을 읽지 못했습니다' },
    @{ id = 'V12'; what = 'Apache24 2.4.65 · conf\original 에만 켠 줄'; expect = 6; installs = @('C:\Apache24|2.4.65|original') },
    @{ id = 'L1'; what = 'XAMPP 2.4.65 · HTTP/2'; expect = 2; installs = @('C:\xampp\apache|2.4.65|full') },
    @{ id = 'L2'; what = 'WampServer 2.4.65 · HTTP/2'; expect = 2; installs = @('C:\wamp64\bin\apache\apache2.4.65|2.4.65|full') },
    @{ id = 'L3'; what = 'Laragon 2.4.65 · HTTP/2'; expect = 2; installs = @('C:\laragon\bin\apache\httpd-2.4.65-250724-win64-VS17|2.4.65|full') },
    @{ id = 'L4'; what = '옛 설치 프로그램 자리 2.4.65 · HTTP/2'; expect = 2;
       installs = @('C:\Program Files\Apache Software Foundation\Apache2.4|2.4.65|full') },
    @{ id = 'G1'; what = 'XAMPP 2.4.65 기본 + Apache24 진짜 2.4.71 HTTP/2 — 설치본마다'; expect = 6;
       installs = @('C:\xampp\apache|2.4.65|off', 'C:\Apache24|real|full') },
    @{ id = 'G2'; what = 'XAMPP 2.4.65 HTTP/2 + Apache24 진짜 2.4.71 HTTP/2'; expect = 2;
       installs = @('C:\xampp\apache|2.4.65|full', 'C:\Apache24|real|full') },
    @{ id = 'G3'; what = 'WampServer 2.4.65 기본 + XAMPP 2.4.71 HTTP/2'; expect = 6;
       installs = @('C:\wamp64\bin\apache\apache2.4.65|2.4.65|off', 'C:\xampp\apache|2.4.71|full') },
    @{ id = 'O1'; what = '자리 밖 Apache 서비스(만들기만)'; expect = 6; installs = @(); service = 'C:\web\apache\bin\httpd.exe';
       screen = '밖의 Apache(위 경로)가 서비스로 있거나 돌고 있어' },
    @{ id = 'O2'; what = '자리 밖에서 도는 httpd.exe'; expect = 6; installs = @(); process = 'C:\web\apache\bin\httpd.exe' },
    @{ id = 'O3'; what = '자리 안 서비스 + 진짜 2.4.71'; expect = 0; installs = @('C:\Apache24|real|full');
       serviceIn = 'C:\Apache24\bin\httpd.exe' },
    @{ id = 'N1'; what = 'Apache 없음'; expect = 0; installs = @() },
    @{ id = 'K1'; what = 'Apache24 2.4.65 HTTP/2 + conf\private\server.key'; expect = 2; installs = @('C:\Apache24|2.4.65|full');
       key = 'C:\Apache24\conf\private\server.key' }
)

$pass = 0
$fail = 0
$total = 0
function Check([string] $id, [string] $what, [bool] $ok, [string] $evidence) {
    $script:total++
    if ($ok) { $script:pass++ } else { $script:fail++ }
    Note ('{0,-4} {1}  {2} — {3}' -f $id, $(if ($ok) { '통과' } else { '실패' }), $what, $evidence)
}

try {
    Note ("시작 {0}  꾸러미={1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Package)
    Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
        New-Item -ItemType Directory -Force "$g\plugins", "$g\real", "$g\out" | Out-Null
    }
    Copy-GuestFile -Session $session -Source $exe -Destination "$g\remedy.exe"
    Copy-Item -LiteralPath $ruleDir -Destination "$g\plugins" -ToSession $session -Recurse -Force
    Copy-GuestFile -Session $session -Source $ApacheZip -Destination "$g\real\apache.zip"
    Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        Expand-Archive -LiteralPath "$g\real\apache.zip" -DestinationPath "$g\real" -Force
        Remove-Item -LiteralPath "$g\real\apache.zip" -Force
        if (-not (Test-Path "$g\real\Apache24\bin\libhttpd.dll")) { throw 'zip 에 Apache24\bin\libhttpd.dll 이 없다' }
    }
    Invoke-Command -Session $session -ArgumentList $guestTools.ToString() -ScriptBlock {
        param($tools)
        . ([scriptblock]::Create($tools))
        Clear-Layouts
    }

    foreach ($c in $cases) {
        $setupScript = $guestTools.ToString()
        Invoke-Command -Session $session -ArgumentList $setupScript, $c.installs, $c.service, $c.process, $c.serviceIn, $c.key, $keyMark -ScriptBlock {
            param($tools, $installs, $service, $process, $serviceIn, $key, $keyMark)
            . ([scriptblock]::Create($tools))
            Clear-Layouts
            foreach ($i in @($installs)) { if ($i) { New-Install ([string]$i) } }
            # 가짜 TLS 개인키 — 시험 대상은 이름(`*.key`)이다(룰은 그 파일을 읽지 않는다). 내용은 키 모양이 아닌 표지
            # 하나다(리눅스 하네스와 같다) — 공개 트리에 키 머리를 두지 않는다.
            if ($key) { [IO.File]::WriteAllText($key, "$keyMark`r`n") }
            if ($service) {
                New-Service -Name 'RemedyLabApache' -BinaryPathName ('"' + $service + '" -k runservice') -StartupType Manual | Out-Null
            }
            if ($serviceIn) {
                New-Service -Name 'RemedyLabApacheIn' -BinaryPathName ('"' + $serviceIn + '" -k runservice') -StartupType Manual | Out-Null
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
        if ($c.key) {
            $files = Invoke-Command -Session $session -ArgumentList $out, $keyMark -ScriptBlock {
                param($out, $mark)
                $hit = @(Get-ChildItem -LiteralPath $out -Recurse -File | Where-Object {
                    [IO.File]::ReadAllText($_.FullName).Contains($mark) } | ForEach-Object { $_.Name })
                [pscustomobject]@{ hits = $hit; names = @(Get-ChildItem -LiteralPath $out -Recurse -File | ForEach-Object { $_.Name }) }
            }
            $inScreen = $screen.Contains($keyMark)
            Check "K-$($c.id)" '개인키의 표지가 결과 파일 · 화면에 없다' ((@($files.hits).Count -eq 0) -and -not $inScreen) `
                ("결과 파일 {0}개 중 표지 {1} · 화면 {2}" -f @($files.names).Count, @($files.hits).Count, $inScreen)
        }
    }
}
finally {
    try {
        Invoke-Command -Session $session -ArgumentList $guestTools.ToString(), $g -ScriptBlock {
            param($tools, $g)
            . ([scriptblock]::Create($tools))
            Clear-Layouts
            if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
        }
    } finally { Remove-PSSession $session }
}
Note ("끝 {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Note ("판정 {0}/{1} · 실패 {2}" -f $pass, $total, $fail)
if ($fail -eq 0) { exit 0 } else { exit 1 }
