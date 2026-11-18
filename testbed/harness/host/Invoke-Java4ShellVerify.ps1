#Requires -Version 5.1
<#
.SYNOPSIS
    Java4Shell 점검 룰(java4shell-check-windows)을 랩 VM 에서 잰다 — 홈 모양마다 종료 코드와 화면.

.DESCRIPTION
    `-Package` 는 `remedy-windows-x64` 폴더다(내려받아 푼 배포본, 또는 같은 차례로 꾸린 개발 꾸러미). `-JdkZip` 은
    Eclipse Temurin 17.0.21+9 의 Windows x64 zip 이고 SHA-256 을 이 스크립트가 대조한다.

    룰이 읽는 것은 JDK 홈의 `bin\java.exe`(홈을 가리키는 표지) 와 `release`(판) 둘뿐이다. 그래서 zip 에서 그 두 파일만
    꺼내 옮기고(나머지 190 MB 는 룰이 열지 않는다) **실행하지 않는다**. 나머지 홈은 자리 채우기다 — `java.exe` 자리에
    Windows 의 `PING.EXE` 사본을 두고 `release` 의 글자만 바꾼다. 놓는 자리는 `C:\Program Files\RemedyLab-Java` 와
    `C:\web-j4s` 둘이고, 경우마다 그리고 끝에 그 둘만 치운다.

    재는 것: 진짜 JDK 1 · 판 줄만 바꾼 자리 채우기 26(Java 8 EPP 8u511-perf 2 · 고친 판 8u513-perf 0 · 일반 8u511 0 ·
    GraalVM EE 21.3.20 바탕 Java 11 2 · EE 21.3.20.1 · Community 0 · 판 줄 없는 ARM64 0 포함) ·
    사용자 프로필의 .jdks · Gradle 툴체인 · VS Code Java 확장의 JRE 3 · 홈 둘 2 · 자리 밖 3 · Oracle javapath 로 띄우는 서비스 1
    (자리 밖이 아니다) · Java 없음 1 · 화면 6 — 모두 43칸(칸 수도 단정한다 · 0.2.0 은 37칸).
    회차 전에 이 기계에 이미 있는 Java 를 치우고 끝에 되돌린다 — 그 홈이 섞이면 모든 칸이 그 판정을 함께 받는다(룰이 보는
    자리 전부 — `C:\Program Files` 둘과 사용자 프로필의 세 자리).
    `-LogDir` 에 경우마다 `<칸>.txt` 와 summary.txt 를 남긴다. 끝줄은 `판정 N/T · 실패 M` 이고 종료 코드는 0 · 1 이다.

.EXAMPLE
    .\testbed\harness\host\Invoke-Java4ShellVerify.ps1 -Package D:\dl\x\remedy-windows-x64 `
        -JdkZip testbed\harness\results\rc-inputs\OpenJDK17U-jdk_x64_windows_hotspot_17.0.21_9.zip -LogDir D:\dl\j4s-win
#>
param(
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $JdkZip,
    [Parameter(Mandatory = $true)][string] $LogDir,
    [string] $VmAddress
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'VmSession.ps1')

$zipSha = '98518ECF554465057EE5509462631DEEEE374BC368C12A411D225CD29381F84B'
$rule = 'java4shell-check-windows'
$exe = Join-Path $Package 'remedy.exe'
$ruleDir = Join-Path $Package "plugins\$rule"
foreach ($p in @($exe, (Join-Path $ruleDir 'plugin.yaml'), $JdkZip)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "없다: $p" }
}
$got = (Get-FileHash -LiteralPath $JdkZip -Algorithm SHA256).Hash
if ($got -ne $zipSha) { throw "JDK zip 의 SHA-256 이 다르다: $got (기대 $zipSha)" }
New-Item -ItemType Directory -Force $LogDir | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
$summary = Join-Path $LogDir 'summary.txt'
[IO.File]::WriteAllText($summary, '', $utf8)
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`n", $utf8) }

# zip 에서 룰이 읽는 두 파일만 꺼낸다 — 홈 폴더 이름은 판마다 다르므로 항목 이름의 끝으로 찾는다.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$realDir = Join-Path $LogDir 'real-jdk'
New-Item -ItemType Directory -Force (Join-Path $realDir 'bin') | Out-Null
$zip = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $JdkZip).ProviderPath)
try {
    foreach ($pair in @(@('bin/java.exe', 'bin\java.exe'), @('release', 'release'))) {
        $e = @($zip.Entries | Where-Object { $_.FullName -match ('^[^/]+/' + [regex]::Escape($pair[0]) + '$') })[0]
        if (-not $e) { throw ("zip 에 {0} 가 없다" -f $pair[0]) }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($e, (Join-Path $realDir $pair[1]), $true)
    }
} finally { $zip.Dispose() }

$LAB = 'C:\Program Files\RemedyLab-Java'
$OUTSIDE = 'C:\web-j4s'
$g = 'C:\remedy-probe'

# 경우 — `homes` 는 `<홈 경로>|<꼴>` 이고 꼴은 real(진짜 두 파일) · norelease · 그 밖은 release 에 넣을 줄들을 `;` 로 이은 것.
$x64 = 'OS_ARCH="x86_64"'
$cases = @(
    @{ id = 'R1'; what = '진짜 Temurin 17.0.21+9 (고친 판 미만)'; expect = 2; homes = @("$LAB\Eclipse Adoptium\jdk-17.0.21+9|real");
       screen = 'CVE-2026-114938 의 영향 판입니다' },
    @{ id = 'F1'; what = '고친 판 17.0.21.1'; expect = 0; homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.21.1`";$x64") },
    @{ id = 'F2'; what = '고친 판 17.0.21.1.2 (배포사 꼴)'; expect = 0; homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.21.1.2`";$x64") },
    @{ id = 'F3'; what = '고친 판 21.0.13.1'; expect = 0; homes = @("$LAB\Zulu\zulu-21|JAVA_VERSION=`"21.0.13.1`";$x64") },
    @{ id = 'F4'; what = '고친 판 27.0.1.1'; expect = 0; homes = @("$LAB\Java\jdk-27|JAVA_VERSION=`"27.0.1.1`";$x64") },
    @{ id = 'F5'; what = '그 뒤의 판 17.0.22'; expect = 0; homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.22`";$x64") },
    @{ id = 'V1'; what = '고친 판 미만 17.0.21.0.4'; expect = 2; homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.21.0.4`";$x64") },
    @{ id = 'V2'; what = '고친 판 미만 21.0.13.0.3'; expect = 2; homes = @("$LAB\Zulu\zulu-21|JAVA_VERSION=`"21.0.13.0.3`";$x64") },
    @{ id = 'V3'; what = '고친 판 미만 27.0.1.0.3'; expect = 2; homes = @("$LAB\Java\jdk-27|JAVA_VERSION=`"27.0.1.0.3`";$x64") },
    @{ id = 'A1'; what = 'ARM64 빌드'; expect = 0; homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.21`";OS_ARCH=`"aarch64`"") },
    @{ id = 'A2'; what = '32비트 빌드'; expect = 0; homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.21`";OS_ARCH=`"x86`"") },
    @{ id = 'A3'; what = '아키텍처 줄이 없는 release (jlink 꼴) — 판으로 판정'; expect = 2;
       homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.21`";MODULES=`"java.base java.logging`"") },
    @{ id = 'A4'; what = '모르는 아키텍처 값 — 빼지 않고 판으로 판정'; expect = 2;
       homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.21`";OS_ARCH=`"hexagon`"") },
    @{ id = 'E1'; what = '지원이 끝난 줄 20.0.2'; expect = 2; homes = @("$LAB\Java\jdk-20|JAVA_VERSION=`"20.0.2`";$x64") },
    @{ id = 'U1'; what = '아직 개발 중인 줄 28.0.1'; expect = 6; homes = @("$LAB\Java\jdk-28|JAVA_VERSION=`"28.0.1`";$x64");
       screen = '빌드 번호가 아직 공개되지 않아' },
    @{ id = 'U2'; what = '판 줄이 없는 release'; expect = 6; homes = @("$LAB\Java\jdk-17|IMPLEMENTOR=`"Acme`";$x64");
       screen = 'release 파일에서 판을 읽지 못했습니다' },
    @{ id = 'U3'; what = 'release 가 없는 홈'; expect = 6; homes = @("$LAB\Java\jdk-17|norelease") },
    @{ id = 'C1'; what = 'Java 8 — 이 CVE 가 걸린 줄이 아니다'; expect = 0; homes = @("$LAB\Java\jre1.8.0_432|JAVA_VERSION=`"1.8.0_432`";$x64") },
    @{ id = 'C2'; what = 'Java 11 — 이 CVE 가 걸린 줄이 아니다'; expect = 0; homes = @("$LAB\Java\jdk-11|JAVA_VERSION=`"11.0.33.1`";$x64") },
    @{ id = 'C3'; what = '17.0.5 — x86-64 Base64 디코드 코드가 들어오기 전'; expect = 0; homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.5`";$x64") },
    @{ id = 'G1'; what = '고친 판 + 영향 판 — 홈마다 가른다'; expect = 2;
       homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.21.1`";$x64", "$LAB\Zulu\zulu-21|JAVA_VERSION=`"21.0.13`";$x64") },
    @{ id = 'G2'; what = '고친 판 둘'; expect = 0;
       homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.21.1`";$x64", "$LAB\Zulu\zulu-21|JAVA_VERSION=`"21.0.13.1`";$x64") },
    @{ id = 'O1'; what = '자리 밖 Java 서비스(만들기만)'; expect = 6; homes = @(); service = "$OUTSIDE\jdk\bin\java.exe";
       screen = '밖의 Java(위 경로)가 돌고 있거나 서비스로 등록돼' },
    @{ id = 'O2'; what = '자리 밖에서 도는 java.exe'; expect = 6; homes = @(); process = "$OUTSIDE\jdk\bin\java.exe" },
    @{ id = 'O3'; what = '자리 안 서비스 + 고친 판'; expect = 0; homes = @("$LAB\Java\jdk-17|JAVA_VERSION=`"17.0.21.1`";$x64");
       serviceIn = "$LAB\Java\jdk-17\bin\java.exe" },
    # Oracle 설치 프로그램의 javapath — `C:\Program Files\Java` 의 홈을 가리키는 길이라 자리 밖이 아니다(0.2.0). 서비스의 경로
    # 글자만 보므로 그 자리에 파일을 놓지 않는다(이 기계의 javapath 를 덮지 않는다).
    @{ id = 'O4'; what = 'Oracle javapath 로 띄우는 서비스 — 자리 밖이 아니다'; expect = 0; homes = @();
       serviceText = 'C:\ProgramData\Oracle\Java\javapath\java.exe' },
    # Java 8 은 Enterprise Performance Pack(-perf)만 영향 판이다(Oracle CPU 2026-11 의 위험 표 · 0.2.0).
    @{ id = 'P1'; what = 'Java 8 EPP 8u511-perf (런타임 판 줄의 -perf)'; expect = 2;
       homes = @("$LAB\Java\jdk1.8.0_511-perf|JAVA_VERSION=`"1.8.0_511`";JAVA_RUNTIME_VERSION=`"1.8.0_511-perf-b33`";OS_ARCH=`"amd64`"");
       screen = 'Java SE 8 Enterprise Performance Pack' },
    @{ id = 'P2'; what = 'Java 8 EPP 고친 판 8u513-perf'; expect = 0;
       homes = @("$LAB\Java\jdk1.8.0_513-perf|JAVA_VERSION=`"1.8.0_513-perf`";OS_ARCH=`"amd64`"") },
    @{ id = 'C4'; what = '일반 Java 8 8u511 — 이 CVE 의 줄이 아니다'; expect = 0;
       homes = @("$LAB\Java\jdk1.8.0_511|JAVA_VERSION=`"1.8.0_511`";OS_ARCH=`"amd64`";BUILD_TYPE=`"commercial`"") },
    # GraalVM EE 21.3 은 제품 판(GRAALVM_VERSION)이 21.3.20.1 미만이면 바탕 Java 와 상관없이 2 다(0.3.0 · 결정 G1). 고친 판과
    # Community 는 바탕 Java 로 — 11 이라 0 이다.
    @{ id = 'GE1'; what = 'GraalVM EE 21.3.20 — 바탕 Java 11 이어도 제품 판으로'; expect = 2;
       homes = @("$LAB\Java\graalvm-ee-java11-21.3.20|JAVA_VERSION=`"11.0.33`";IMPLEMENTOR=`"Oracle Corporation`";GRAALVM_VERSION=`"21.3.20`";$x64");
       screen = 'Oracle GraalVM Enterprise Edition 21.3' },
    @{ id = 'GE2'; what = 'GraalVM EE 21.3.20.1 — 바탕 Java 11 로'; expect = 0;
       homes = @("$LAB\Java\graalvm-ee-java11-21.3.20.1|JAVA_VERSION=`"11.0.33`";IMPLEMENTOR=`"Oracle Corporation`";GRAALVM_VERSION=`"21.3.20.1`";$x64") },
    @{ id = 'GE3'; what = 'GraalVM Community 21.3.20 — 바탕 Java 11 로'; expect = 0;
       homes = @("$LAB\Java\graalvm-ce-java11-21.3.20|JAVA_VERSION=`"11.0.20`";IMPLEMENTOR=`"GraalVM Community`";GRAALVM_VERSION=`"21.3.20`";$x64") },
    # 판을 못 읽어도 x86-64 가 아니라고 적힌 빌드는 영향이 없다(0.3.0 · 독립 검토).
    @{ id = 'U4'; what = '판 줄이 없는 ARM64 빌드'; expect = 0; homes = @("$LAB\Java\jdk-17|IMPLEMENTOR=`"Acme`";OS_ARCH=`"aarch64`"") },
    # 사용자 프로필의 자리(0.2.0) — 게스트가 %USERPROFILE% 를 편다(원격 세션의 사용자 = 프로필 목록의 사용자).
    @{ id = 'H1'; what = '사용자 프로필의 .jdks 에 받은 21.0.13'; expect = 2;
       homes = @("%USERPROFILE%\.jdks\remedylab-21|JAVA_VERSION=`"21.0.13`";$x64") },
    @{ id = 'H2'; what = 'Gradle 툴체인이 사용자 프로필에 받은 17.0.21'; expect = 2;
       homes = @("%USERPROFILE%\.gradle\jdks\remedylab-17|JAVA_VERSION=`"17.0.21`";$x64") },
    # VS Code 의 Java 확장이 담는 JRE — 실물(redhat.java 1.59.2026111308 win32-x64)의 꼴: `jre\25.0.5-win32-x86_64\` 에
    # `bin\java.exe` 와 `JAVA_VERSION` · `MODULES` 두 줄의 `release`(아키텍처 줄 없음 · 0.3.0).
    @{ id = 'H3'; what = 'VS Code Java 확장이 담은 JRE 25.0.5'; expect = 2;
       homes = @("%USERPROFILE%\.vscode\extensions\remedylab-redhat.java-1.59.2026111308-win32-x64\jre\25.0.5-win32-x86_64|JAVA_VERSION=`"25.0.5`";MODULES=`"java.base java.logging`"") },
    @{ id = 'N1'; what = 'Java 없음'; expect = 0; homes = @() }
)
# 칸 수까지 본다 — 경우를 짓다 멈추면 남은 경우가 조용히 사라지고 '실패 0' 이 남는다.
$expectedTotal = $cases.Count + @($cases | Where-Object { $_.screen }).Count

# 게스트 쪽 놓기 · 치우기 — 경우마다 같은 세션에서 다시 정의한다(Invoke-Command 는 범위를 잇지 않는다).
$guest = {
    param($lab, $outside, $real, $homes, $service, $process, $serviceIn, $serviceText)
    function Clear-Layouts($lab, $outside) {
        foreach ($s in @('RemedyLabJava', 'RemedyLabJavaIn', 'RemedyLabJavaPath')) {
            if (Get-Service -Name $s -ErrorAction SilentlyContinue) { & sc.exe delete $s | Out-Null }
        }
        foreach ($jdks in @((Join-Path $env:USERPROFILE '.jdks'), (Join-Path $env:USERPROFILE '.gradle\jdks'), (Join-Path $env:USERPROFILE '.vscode\extensions'))) {
            foreach ($d in @(Get-ChildItem -LiteralPath $jdks -Directory -Filter 'remedylab-*' -ErrorAction SilentlyContinue)) {
                [System.IO.Directory]::Delete('\\?\' + $d.FullName, $true)
            }
        }
        $ours = @(Get-Process -Name java -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$outside\*" })
        foreach ($p in $ours) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            $null = $p.WaitForExit(10000)
        }
        foreach ($r in @($lab, $outside)) {
            if (Test-Path -LiteralPath $r) { [System.IO.Directory]::Delete('\\?\' + $r, $true) }
        }
    }
    Clear-Layouts $lab $outside
    foreach ($line in @($homes)) {
        if (-not $line) { continue }
        $parts = ([string]$line) -split '\|', 2
        $dir = [Environment]::ExpandEnvironmentVariables($parts[0])
        $shape = $parts[1]
        New-Item -ItemType Directory -Force "$dir\bin" | Out-Null
        if ($shape -eq 'real') {
            Copy-Item -LiteralPath "$real\bin\java.exe" -Destination "$dir\bin\java.exe" -Force
            Copy-Item -LiteralPath "$real\release" -Destination "$dir\release" -Force
            continue
        }
        Copy-Item -LiteralPath "$env:windir\System32\PING.EXE" -Destination "$dir\bin\java.exe" -Force
        if ($shape -ne 'norelease') {
            $text = (($shape -split ';') -join "`r`n") + "`r`n"
            [IO.File]::WriteAllText("$dir\release", $text)
        }
    }
    if ($service) {
        New-Item -ItemType Directory -Force (Split-Path -Parent $service) | Out-Null
        Copy-Item -LiteralPath "$env:windir\System32\PING.EXE" -Destination $service -Force
        New-Service -Name 'RemedyLabJava' -BinaryPathName ('"' + $service + '" -Xmx512m -jar app.jar') -StartupType Manual | Out-Null
    }
    if ($serviceIn) {
        New-Service -Name 'RemedyLabJavaIn' -BinaryPathName ('"' + $serviceIn + '" -Xmx512m -jar app.jar') -StartupType Manual | Out-Null
    }
    if ($serviceText) {
        New-Service -Name 'RemedyLabJavaPath' -BinaryPathName ('"' + $serviceText + '" -Xmx512m -jar app.jar') -StartupType Manual | Out-Null
    }
    if ($process) {
        New-Item -ItemType Directory -Force (Split-Path -Parent $process) | Out-Null
        Copy-Item -LiteralPath "$env:windir\System32\PING.EXE" -Destination $process -Force
        Start-Process -FilePath $process -ArgumentList @('-n', '600', '127.0.0.1') -WindowStyle Hidden | Out-Null
        Start-Sleep -Seconds 1
    }
}

$pass = 0
$fail = 0
$total = 0
function Check([string] $id, [string] $what, [bool] $ok, [string] $evidence) {
    $script:total++
    if ($ok) { $script:pass++ } else { $script:fail++ }
    Note ('{0,-5} {1}  {2} — {3}' -f $id, $(if ($ok) { '통과' } else { '실패' }), $what, $evidence)
}

$addr = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $addr
try {
    Note ("시작 {0}  꾸러미={1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Package)
    Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
        New-Item -ItemType Directory -Force "$g\plugins", "$g\real\bin", "$g\out" | Out-Null
    }
    Copy-GuestFile -Session $session -Source $exe -Destination "$g\remedy.exe"
    Copy-Item -LiteralPath $ruleDir -Destination "$g\plugins" -ToSession $session -Recurse -Force
    Copy-GuestFile -Session $session -Source (Join-Path $realDir 'bin\java.exe') -Destination "$g\real\bin\java.exe"
    Copy-GuestFile -Session $session -Source (Join-Path $realDir 'release') -Destination "$g\real\release"

    # 이 기계에 이미 깔린 Java(제품이 담아 쓰는 런타임 등)가 있으면 모든 칸이 그 홈의 판정을 함께 받는다 — 회차 동안
    # 그 `bin\java.exe` 의 이름만 바꿔 두고 끝에 되돌린다(되돌리기는 아래 finally 에 있다).
    $hidden = @(Invoke-Command -Session $session -ArgumentList $LAB -ScriptBlock {
        param($lab)
        $found = @()
        # 룰이 보는 자리 전부 — `C:\Program Files` 둘 · 전역 Scoop · 사용자 프로필의 여섯 자리(0.2.0 · VS Code 확장은 0.3.0).
        $roots = @('C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData\scoop\apps')
        foreach ($u in @(Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
            foreach ($sub in @('.jdks', 'scoop\apps', 'AppData\Local\Programs', '.gradle\jdks', '.jabba\jdk', '.vscode\extensions')) {
                $roots += "$($u.FullName)\$sub"
            }
        }
        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            $found += @(Get-ChildItem -LiteralPath $root -Recurse -Filter 'java.exe' -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Directory.Name -eq 'bin' -and $_.FullName -notlike "$lab\*" -and $_.FullName -notlike '*\remedylab-*' } |
                ForEach-Object { $_.FullName })
        }
        foreach ($p in $found) { Move-Item -LiteralPath $p -Destination ($p + '.remedylab-off') -Force }
        # 경로를 하나씩 내보낸다 — `, $found` 로 감싸면 호스트의 `@(…)` 가 배열을 한 겹 더 싸서 수와 목록이 어긋난다.
        $found | ForEach-Object { $_ }
    })
    Note ("이 기계에 이미 있는 Java {0}개를 회차 동안 치운다{1}" -f $hidden.Count,
        $(if ($hidden.Count) { ': ' + ($hidden -join ' · ') } else { '' }))

    foreach ($c in $cases) {
        Invoke-Command -Session $session -ScriptBlock $guest `
            -ArgumentList $LAB, $OUTSIDE, "$g\real", $c.homes, $c.service, $c.process, $c.serviceIn, $c.serviceText
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
}
finally {
    try {
        # 목록을 **한 인자로** 넘긴다 — `-ArgumentList $hidden` 은 배열을 인자 여럿으로 펴서 param 이 첫 항목만 받는다.
        Invoke-Command -Session $session -ArgumentList (, $hidden) -ScriptBlock {
            param($list)
            foreach ($p in @($list)) {
                if (Test-Path -LiteralPath ($p + '.remedylab-off')) {
                    Move-Item -LiteralPath ($p + '.remedylab-off') -Destination $p -Force
                }
            }
        }
        Invoke-Command -Session $session -ArgumentList $LAB, $OUTSIDE, $g -ScriptBlock {
            param($lab, $outside, $g)
            foreach ($s in @('RemedyLabJava', 'RemedyLabJavaIn', 'RemedyLabJavaPath')) {
                if (Get-Service -Name $s -ErrorAction SilentlyContinue) { & sc.exe delete $s | Out-Null }
            }
            foreach ($jdks in @((Join-Path $env:USERPROFILE '.jdks'), (Join-Path $env:USERPROFILE '.gradle\jdks'), (Join-Path $env:USERPROFILE '.vscode\extensions'))) {
                foreach ($d in @(Get-ChildItem -LiteralPath $jdks -Directory -Filter 'remedylab-*' -ErrorAction SilentlyContinue)) {
                    [System.IO.Directory]::Delete('\\?\' + $d.FullName, $true)
                }
            }
            $ours = @(Get-Process -Name java -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$outside\*" })
            foreach ($p in $ours) {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                $null = $p.WaitForExit(10000)
            }
            foreach ($r in @($lab, $outside, $g)) {
                if (Test-Path -LiteralPath $r) { [System.IO.Directory]::Delete('\\?\' + $r, $true) }
            }
        }
    } finally { Remove-PSSession $session }
}
if ($total -ne $expectedTotal) { Check 'N' '칸 수' $false ('{0}칸 — 기대 {1}' -f $total, $expectedTotal) }
Note ("끝 {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Note ("판정 {0}/{1} · 실패 {2}" -f $pass, $total, $fail)
if ($fail -eq 0) { exit 0 } else { exit 1 }
