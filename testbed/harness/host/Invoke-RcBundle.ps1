#Requires -Version 5.1
<#
.SYNOPSIS
    출시의 Windows 랩 묶음 — 지난 공개본(A)과 이번 판(B)을 랩 VM 과 이 기계에서 나란히 재는 27단계
    (docs/개발-안내.md "출시 검증").

.DESCRIPTION
    `-Package` 는 rc(평소 경로) 또는 공개한 판(긴급 경로의 미룬 검증)을 **내려받아 푼** `remedy-windows-x64` 폴더, `-PackageA`
    는 앞 공개본의 같은 폴더다. 빌드는 하지 않는다.

      시연 · 메뉴   demo(`Invoke-DemoVerify.ps1 -Bin`) · menu(`Invoke-MenuVerify.ps1 -Package -Prepare -ReinfectOnly`)
      시간          timing-a · timing — 같은 룰 넷을 A 로 · B 로(`rc\Measure-ScanTiming.ps1`)
      A/B           outside(선언 밖 · IIS) · modules(실린 모듈) · sources(서비스 · Apache 설정 · 레지스트리) · nssm —
                    랩 VM 의 같은 상태에서 A 와 B(`rc\Invoke-Ab*.ps1`). 상태를 바꾸는 단계 뒤마다 되돌린다(reset1 ~ 6)
      log4j         log4j-disk(깨끗한 C: 전체 → 0) · log4j-positive(시료를 놓고 → 2 · 고친 판은 화면에 없다)
      apache        이번 판의 Apache HTTP/2 점검 룰 하네스(`Invoke-ApacheVerify.ps1` — 설치본 모양마다 0 · 2 · 6)
      java4shell    이번 판의 Java4Shell 점검 룰 하네스(`Invoke-Java4ShellVerify.ps1` — 홈 모양마다 0 · 2 · 6 · 진짜 JDK 하나)
      nginx         이번 판의 nginx2root 점검 룰 하네스(`Invoke-Nginx2rootVerify.ps1` — 설치본 모양마다 0 · 2 · 6 · 진짜 zip 셋)
      php2611       이번 판의 PHP 11월 보안 업데이트 점검 룰 하네스(`Invoke-Php202611Verify.ps1` — 설치본 모양마다 0 · 2 · 6 ·
                    진짜 코어 DLL 여섯)
      종료 코드     exit5-guard · exit6-obs · exit3-partial — 이번 판의 가드 중단 5 · 관측 불완전 6 · 일부 실패 3
                    (`Invoke-GuardVerify` · `Invoke-ObsVerify` · `Invoke-PartialVerify` `-Package`) · exit5-sign — 서명
                    확인 0 · 5(`Invoke-SignVerify -Package` · 이 기계). A/B 가 아니라 정한 값을 단정한다
      코드서명      codesign-trust — 실행 파일의 코드서명 상태마다 치료 문(`Invoke-CodeSignTrustVerify -Package` · 맨 끝 ·
                    VM 을 되돌린다 · 1.24.0)
      원격          net-ab — 이 기계에서 remedy-net url · image · container(`rc\Invoke-AbNet.ps1`) · net-apache — 이번 판의
                    remedy-net.exe 로 이미지의 Apache(`rc\Invoke-NetApache.ps1` — 리눅스 묶음이 저장한 `apache-images\`)

    시료는 `-Inputs`(기본 `testbed\harness\results\rc-inputs` — 리눅스 묶음과 같은 자리)에서 읽는다: `jars\`(리눅스 묶음의
    log4j 하네스가 Maven Central 에서 받는다) · `images\`(리눅스 `rc/save-images.sh` 가 만든다) — 그래서 **리눅스 묶음을
    먼저** 돌린다. PHP 8.3.35 zip 은 없으면 windows.php.net 에서 받고 SHA-256 을 견준다. war · Spring Boot 시료는
    `testbed\harness\linux\fixtures\log4j\build-cases.py` 로 짓는다(python). Docker Desktop 에 `php:8.3.35-cli` ·
    `node:22.18.0-bookworm-slim` 이미지가 있어야 한다. **리눅스 묶음과 겹쳐 돌리지 않는다**(메모리가 모자랐다).

    판정: 시연 · 메뉴 · 종료 코드는 마지막 `판정 N/N · 실패 0`, 되돌리기는 `복원 완료`, 시간은 검사 넷의 줄, A/B 는 상태 줄의
    `A 코드… B 코드…` 가 **모두 같아야** 한다, log4j 는 기대한 종료 코드와 화면, 원격은 `A=코드 B=코드` 짝과 `different 0`.
    summary.txt 가 단계마다 `통과 · 다름 · 실패` 를 적는다. 종료 코드: 0 = 모두 통과 · 1 = 실패나 다름이 있다(다름은 의도한
    변경인지 본다 — 룰만 바꾼 출시라면 다름도 실패다 · 다만 remedy-net 기준 데이터 룰을 고친 출시의 net-ab 는 그 값이
    바꾼 차이만 의도한 변경이다 — docs/개발-안내.md "출시 검증") · 2 = 인자 · 시료가 모자라 시작하지 않았다.

.PARAMETER Package
    이번 판 — 내려받아 푼 `remedy-windows-x64` 폴더.

.PARAMETER PackageA
    지난 공개본 — 내려받아 푼 `remedy-windows-x64` 폴더.

.PARAMETER LogDir
    기록을 남길 폴더(회차마다 새 폴더).

.PARAMETER Inputs
    시료 폴더. 기본 `<저장소>\testbed\harness\results\rc-inputs`.

.PARAMETER NodeExe
    선언 밖 Node 로 랩 VM 에 옮길 node.exe. 기본은 이 기계의 `Program Files\nodejs\node.exe`(없으면 PATH 의 node.exe).

.EXAMPLE
    .\testbed\harness\host\Invoke-RcBundle.ps1 -Package D:\dl\rc\x\remedy-windows-x64 -PackageA D:\dl\prev\x\remedy-windows-x64 -LogDir D:\dl\rc-win
#>
param(
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $PackageA,
    [Parameter(Mandatory = $true)][string] $LogDir,
    [string] $Inputs,
    [string] $NodeExe
)
$ErrorActionPreference = 'Continue'
$h = $PSScriptRoot
$rcDir = Join-Path $h 'rc'
$repo = (Resolve-Path (Join-Path $h '..\..\..')).Path
function Stop-Setup([string] $why) { Write-Host "시작하지 않는다 — $why"; exit 2 }

# ── 시료 ──────────────────────────────────────────────────────────────────────
foreach ($p in @($Package, $PackageA)) {
    if (-not (Test-Path -LiteralPath (Join-Path $p 'remedy.exe'))) { Stop-Setup "remedy.exe 가 없다: $p" }
}
# 종료 코드 단계(3 · 5 · 6)는 이번 판에 든 EvilAI 룰로 잰다.
if (-not (Test-Path -LiteralPath (Join-Path $Package 'plugins\evilai-locust\plugin.yaml'))) {
    Stop-Setup "이번 판에 plugins\evilai-locust 가 없다: $Package"
}
if (-not $Inputs) { $Inputs = Join-Path $repo 'testbed\harness\results\rc-inputs' }
New-Item -ItemType Directory -Force $Inputs | Out-Null
if (-not $NodeExe) {
    $NodeExe = Join-Path $env:ProgramFiles 'nodejs\node.exe'
    if (-not (Test-Path -LiteralPath $NodeExe)) { $NodeExe = (Get-Command node.exe -ErrorAction SilentlyContinue).Source }
}
if (-not $NodeExe -or -not (Test-Path -LiteralPath $NodeExe)) { Stop-Setup 'node.exe 를 찾지 못했다 — -NodeExe 로 준다' }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Stop-Setup 'python 이 없다(원격 A/B 의 모의 서버 · log4j 시료)' }

$phpZip = Join-Path $Inputs 'php-8.3.35-nts-Win32-vs16-x64.zip'
$phpSha = '25a8e2ac9ff30f1d768d1447c09a600617fa6e6082729f6e95f008b59c91fe45'
if (-not (Test-Path -LiteralPath $phpZip)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    foreach ($u in 'https://windows.php.net/downloads/releases/archives/php-8.3.35-nts-Win32-vs16-x64.zip',
        'https://windows.php.net/downloads/releases/php-8.3.35-nts-Win32-vs16-x64.zip') {
        try { Invoke-WebRequest -Uri $u -OutFile "$phpZip.part" -UseBasicParsing; Move-Item "$phpZip.part" $phpZip; break }
        catch { Remove-Item "$phpZip.part" -ErrorAction SilentlyContinue }
    }
}
if (-not (Test-Path -LiteralPath $phpZip)) { Stop-Setup 'PHP 8.3.35 zip 을 받지 못했다(windows.php.net)' }
if ((Get-FileHash -LiteralPath $phpZip -Algorithm SHA256).Hash.ToLower() -ne $phpSha) { Stop-Setup "PHP zip 의 SHA-256 이 다르다: $phpZip" }

# Apache Lounge 의 고친 판 2.4.71 — Apache 하네스의 진짜 설치본이다. Apache Lounge 는 옛 판을 내려받게 두지 않으므로
# (새 판이 나오면 이 주소가 사라진다) 한 번 받은 zip 을 이 자리에 둔다. SHA-256 은 그 내려받기 자리의 `.txt` 값이다.
$apacheZip = Join-Path $Inputs 'httpd-2.4.71-261112-Win64-VS18.zip'
$apacheSha = '44961a929dff16b767b3adbcea55760a942a00239b2891dc55806be34029e1fc'
if (-not (Test-Path -LiteralPath $apacheZip)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri 'https://www.apachelounge.com/download/VS18/binaries/httpd-2.4.71-261112-Win64-VS18.zip' `
            -OutFile "$apacheZip.part" -UseBasicParsing
        Move-Item "$apacheZip.part" $apacheZip
    } catch { Remove-Item "$apacheZip.part" -ErrorAction SilentlyContinue }
}
if (-not (Test-Path -LiteralPath $apacheZip)) { Stop-Setup 'Apache Lounge 2.4.71 zip 을 받지 못했다(apachelounge.com) — 받아 둔 것을 이 자리에 둔다' }
if ((Get-FileHash -LiteralPath $apacheZip -Algorithm SHA256).Hash.ToLower() -ne $apacheSha) { Stop-Setup "Apache zip 의 SHA-256 이 다르다: $apacheZip" }

# Eclipse Temurin 17.0.21+9 의 Windows x64 zip — Java4Shell 점검 룰 하네스가 읽는 **진짜 JDK** 다(그 안의 `bin\java.exe` 와
# `release` 둘만 쓴다). 주소는 그 판의 릴리스 자산이라 사라지지 않는다.
$jdkZip = Join-Path $Inputs 'OpenJDK17U-jdk_x64_windows_hotspot_17.0.21_9.zip'
$jdkSha = '98518ecf554465057ee5509462631deeee374bc368c12a411d225cd29381f84b'
if (-not (Test-Path -LiteralPath $jdkZip)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -UseBasicParsing -OutFile "$jdkZip.part" `
            -Uri 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21%2B9/OpenJDK17U-jdk_x64_windows_hotspot_17.0.21_9.zip'
        Move-Item "$jdkZip.part" $jdkZip
    } catch { Remove-Item "$jdkZip.part" -ErrorAction SilentlyContinue }
}
if (-not (Test-Path -LiteralPath $jdkZip)) { Stop-Setup 'Temurin 17.0.21+9 Windows x64 zip 을 받지 못했다(adoptium)' }
if ((Get-FileHash -LiteralPath $jdkZip -Algorithm SHA256).Hash.ToLower() -ne $jdkSha) { Stop-Setup "JDK zip 의 SHA-256 이 다르다: $jdkZip" }

# nginx.org 의 Windows zip 셋 — nginx2root 점검 룰 하네스가 읽는 **진짜 nginx.exe** 다(고친 1.31.9 · 1.30.7 과 영향 1.30.6).
# 판마다 주소가 그대로 남는다(nginx.org/download). SHA-256 은 Invoke-Nginx2rootVerify.ps1 이 다시 대조한다.
$nginxDir = Join-Path $Inputs 'nginx-win'
New-Item -ItemType Directory -Force $nginxDir | Out-Null
foreach ($nv in @('1.31.9', '1.30.7', '1.30.6')) {
    $nz = Join-Path $nginxDir "nginx-$nv.zip"
    if (-not (Test-Path -LiteralPath $nz)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        try {
            Invoke-WebRequest -UseBasicParsing -OutFile "$nz.part" -Uri "https://nginx.org/download/nginx-$nv.zip"
            Move-Item "$nz.part" $nz
        } catch { Remove-Item "$nz.part" -ErrorAction SilentlyContinue }
    }
    if (-not (Test-Path -LiteralPath $nz)) { Stop-Setup "nginx-$nv.zip 을 받지 못했다(nginx.org)" }
}

# downloads.php.net 의 Windows zip 여섯 — PHP 11월 보안 업데이트 점검 룰 하네스가 코어 DLL 하나씩만 꺼내 쓴다(실행하지 않는다).
# 고친 판 둘은 지금 releases 에, 옛 판은 releases/archives 에 있다(다음 상류 판이 나오면 고친 판도 archives 로 옮겨 간다 —
# 둘 다 본다). SHA-256 · 코어 DLL 해시는 Invoke-Php202611Verify.ps1 이 다시 대조한다. 8.3.35 는 위에서 받은 zip 을 옮겨 둔다.
$phpWinDir = Join-Path $Inputs 'php-win'
New-Item -ItemType Directory -Force $phpWinDir | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $phpWinDir 'php-8.3.35-nts-Win32-vs16-x64.zip'))) {
    Copy-Item -LiteralPath $phpZip -Destination $phpWinDir
}
foreach ($pn in @('php-8.3.37-nts-Win32-vs16-x64.zip', 'php-8.5.13-Win32-vs17-x64.zip', 'php-8.5.12-Win32-vs17-x64.zip',
        'php-8.4.27-nts-Win32-vs17-x64.zip', 'php-8.2.35-nts-Win32-vs16-x64.zip')) {
    $pz = Join-Path $phpWinDir $pn
    if (-not (Test-Path -LiteralPath $pz)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        foreach ($pu in @("https://downloads.php.net/~windows/releases/$pn", "https://downloads.php.net/~windows/releases/archives/$pn")) {
            try { Invoke-WebRequest -UseBasicParsing -OutFile "$pz.part" -Uri $pu; Move-Item "$pz.part" $pz; break }
            catch { Remove-Item "$pz.part" -ErrorAction SilentlyContinue }
        }
    }
    if (-not (Test-Path -LiteralPath $pz)) { Stop-Setup "$pn 을 받지 못했다(downloads.php.net)" }
}

$jars = Join-Path $Inputs 'jars'
$fx = Join-Path $repo 'testbed\harness\linux\fixtures\log4j'
$want = @(Get-Content -LiteralPath (Join-Path $fx 'official.txt') -Encoding UTF8 | Where-Object { $_ -match '^[^#\s]' } |
        ForEach-Object { $f = $_ -split '\s+'; '{0}-{1}.jar' -f $f[1], $f[2] })
foreach ($j in $want) {
    $jar = Join-Path $jars $j
    if (-not (Test-Path -LiteralPath $jar) -or -not (Test-Path -LiteralPath "$jar.sha1")) {
        Stop-Setup "$j 가 없다 — 리눅스 묶음을 먼저 돌린다(log4j 하네스가 $jars 에 받는다)"
    }
    $sha1 = ((Get-Content -LiteralPath "$jar.sha1" -Raw) -replace '\s', '').Substring(0, 40).ToLower()
    if ((Get-FileHash -LiteralPath $jar -Algorithm SHA1).Hash.ToLower() -ne $sha1) { Stop-Setup "$j 의 SHA-1 이 Maven 의 것과 다르다" }
}
$cases = Join-Path $Inputs 'log4j-cases'
& python -I -X utf8 (Join-Path $fx 'build-cases.py') (Join-Path $fx 'official.txt') $jars $cases | Out-Null
$war = Join-Path $cases 'c15-war-other-name\app.war'
$boot = Join-Path $cases 'c07-boot-renamed\app.jar'
foreach ($p in @($war, $boot)) { if (-not (Test-Path -LiteralPath $p)) { Stop-Setup "log4j 시료를 짓지 못했다: $p" } }

$images = Join-Path $Inputs 'images'
$apacheImages = Join-Path $Inputs 'apache-images'
if (@(Get-ChildItem -LiteralPath $apacheImages -Filter '*.tar' -ErrorAction SilentlyContinue).Count -lt 18) {
    Stop-Setup "Apache 이미지 tar 열여덟이 없다 — 리눅스 묶음의 net-apache 단계가 $apacheImages 에 만든다"
}
if (@(Get-ChildItem -LiteralPath $images -Filter '*.tar' -ErrorAction SilentlyContinue).Count -lt 8) {
    Stop-Setup "이미지 tar 여덟이 없다 — 리눅스 묶음이 $images 에 만든다"
}
foreach ($img in 'php:8.3.35-cli', 'node:22.18.0-bookworm-slim') {
    & docker image inspect $img 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Setup "Docker 에 $img 이미지가 없다 — docker pull $img" }
}

# ── 단계 ──────────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force $LogDir | Out-Null
$summary = Join-Path $LogDir 'summary.txt'
[IO.File]::WriteAllText($summary, '')
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`r`n") }
$script:failed = @()
$script:differs = @()
# 단계를 돌리고 판정한다 — `$judge` 는 기록의 줄들을 받아 (0 통과 · 3 다름 · 1 실패, 요약)을 **따로** 내보낸다.
function Step([string] $name, [scriptblock] $body, [scriptblock] $judge) {
    $t0 = Get-Date
    $log = Join-Path $LogDir "$name.log"
    try { & $body *>&1 | ForEach-Object { "$_" } | Out-File -FilePath $log -Encoding utf8 }
    catch { "THROWN: $($_.Exception.Message)" | Out-File -FilePath $log -Append -Encoding utf8 }
    $lines = @(Get-Content -LiteralPath $log -Encoding UTF8)
    $code, $what = & $judge $lines
    if ($lines -match '^THROWN:') { $code = 1; $what = "$what · 예외" }
    $word = '실패'
    if ($code -eq 0) { $word = '통과' }
    elseif ($code -eq 3) { $word = '다름'; $script:differs += $name }
    else { $script:failed += $name }
    Note ("{0}  {1}  {2}초  {3}  {4}" -f $name, $word, [int]((Get-Date) - $t0).TotalSeconds, (Get-Date -Format 'HH:mm:ss'), $what)
}
$verdictLine = {
    param($lines)
    $v = $lines | Where-Object { $_ -match '판정 (\d+)/(\d+) · 실패 (\d+)' } | Select-Object -Last 1
    $ok = [bool]($v -and $v -match '판정 (\d+)/(\d+) · 실패 0' -and $Matches[1] -eq $Matches[2])
    $(if ($ok) { 0 } else { 1 })
    $(if ($v) { $v.Trim() } else { '판정 줄 없음' })
}
$resetJudge = {
    param($lines)
    $ok = [bool]($lines -match '복원 완료')
    $(if ($ok) { 0 } else { 1 })
    $(if ($ok) { '복원 완료' } else { '복원 완료 줄 없음' })
}
$timingJudge = {
    param($lines)
    $runs = @($lines | Where-Object { $_ -match '^\S+\s+exit=-?\d+' })
    $(if ($runs.Count -eq 4) { 0 } else { 1 })
    '검사 {0}/4 · 종료 코드 {1}' -f $runs.Count, (($runs | ForEach-Object { if ($_ -match 'exit=(-?\d+)') { $Matches[1] } }) -join ' ')
}
# A/B 상태 줄 `이름 A 코드… B 코드…` 를 견준다
function Get-AbVerdict([string] $path) {
    if (-not (Test-Path -LiteralPath $path)) { 1; 'summary.txt 가 없다'; return }
    $rows = 0
    $differ = @()
    foreach ($l in Get-Content -LiteralPath $path) {
        if ($l -match '^(\S+)\s+A ((?:-?\d+ )*-?\d+)\s+B ((?:-?\d+ )*-?\d+)') {
            $rows++
            if ($Matches[2].Trim() -ne $Matches[3].Trim()) { $differ += $Matches[1] }
        }
    }
    $(if ($rows -eq 0) { 1 } elseif ($differ.Count -gt 0) { 3 } else { 0 })
    '상태 {0} · 다름 {1}{2}' -f $rows, $differ.Count, $(if ($differ.Count) { ' (' + ($differ -join ' ') + ')' } else { '' })
}
function Get-Status([string] $dir) {
    $p = Join-Path $dir 'status.txt'
    if (Test-Path -LiteralPath $p) { [IO.File]::ReadAllText($p).Trim() } else { '' }
}

$bin = Join-Path $Package 'remedy.exe'
$rule = Join-Path $Package 'plugins\log4j-check'
Set-Location $repo
Note ("시작 {0}  이번 판={1}  지난 공개본={2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Package, $PackageA)
Step 'demo' { & (Join-Path $h 'Invoke-DemoVerify.ps1') -Bin $bin } $verdictLine
Step 'menu' { & (Join-Path $h 'Invoke-MenuVerify.ps1') -Package $Package -Prepare -ReinfectOnly } $verdictLine
Step 'reset1' { & (Join-Path $h 'Reset-Vm.ps1') } $resetJudge
Step 'timing-a' { & (Join-Path $rcDir 'Measure-ScanTiming.ps1') -Package $PackageA } $timingJudge
Step 'timing' { & (Join-Path $rcDir 'Measure-ScanTiming.ps1') -Package $Package } $timingJudge
Step 'outside' {
    & (Join-Path $rcDir 'Invoke-AbOutside.ps1') -PackageA $PackageA -PackageB $Package -PhpZip $phpZip -NodeExe $NodeExe `
        -OutDir (Join-Path $LogDir 'outside')
} { param($lines) Get-AbVerdict (Join-Path $LogDir 'outside\summary.txt') }
Step 'reset2' { & (Join-Path $h 'Reset-Vm.ps1') } $resetJudge
Step 'modules' {
    & (Join-Path $rcDir 'Invoke-AbModules.ps1') -PackageA $PackageA -PackageB $Package -PhpZip $phpZip -OutDir (Join-Path $LogDir 'modules')
} { param($lines) Get-AbVerdict (Join-Path $LogDir 'modules\summary.txt') }
Step 'reset3' { & (Join-Path $h 'Reset-Vm.ps1') } $resetJudge
Step 'sources' {
    & (Join-Path $rcDir 'Invoke-AbSources.ps1') -PackageA $PackageA -PackageB $Package -PhpZip $phpZip -OutDir (Join-Path $LogDir 'sources')
} { param($lines) Get-AbVerdict (Join-Path $LogDir 'sources\summary.txt') }
Step 'reset4' { & (Join-Path $h 'Reset-Vm.ps1') } $resetJudge
Step 'nssm' {
    & (Join-Path $rcDir 'Invoke-AbNssm.ps1') -PackageA $PackageA -PackageB $Package -OutDir (Join-Path $LogDir 'nssm')
} { param($lines) Get-AbVerdict (Join-Path $LogDir 'nssm\summary.txt') }
Step 'reset5' { & (Join-Path $h 'Reset-Vm.ps1') } $resetJudge
Step 'log4j-disk' {
    & (Join-Path $rcDir 'Invoke-Log4jDiskProbe.ps1') -Bin $bin -Rule $rule -OutDir (Join-Path $LogDir 'log4j-disk')
} {
    param($lines)
    $st = Get-Status (Join-Path $LogDir 'log4j-disk')
    $(if ($st -match '^exit=0 ') { 0 } else { 1 })
    $(if ($st) { "$st (깨끗한 C: → 0)" } else { 'status.txt 없음' })
}
Step 'log4j-positive' {
    & (Join-Path $rcDir 'Invoke-Log4jPositiveProbe.ps1') -Bin $bin -Rule $rule -Core (Join-Path $jars 'log4j-core-2.14.1.jar') `
        -Fixed (Join-Path $jars 'log4j-core-2.17.1.jar') -War $war -Boot $boot -OutDir (Join-Path $LogDir 'log4j-positive')
} {
    param($lines)
    $dir = Join-Path $LogDir 'log4j-positive'
    $st = Get-Status $dir
    $screen = ''
    if (Test-Path -LiteralPath (Join-Path $dir 'stdout.txt')) { $screen = [IO.File]::ReadAllText((Join-Path $dir 'stdout.txt'), [Text.Encoding]::UTF8) }
    $wide = [char]::ConvertFromUtf32(0x1F600) + [char]::ConvertFromUtf32(0x20000)
    $expect = @('\l4jtest\plain\log4j-core-2.14.1.jar', '\l4jtest\war\app.war!/WEB-INF/lib/logging-lib.jar',
        '\l4jtest\boot\app.jar!/BOOT-INF/lib/logging-lib.jar', '\renamed-lib.jar', "\l4jtest\x$wide\lib$wide.jar")
    $found = @($expect | Where-Object { $screen.Contains($_) })
    $fixedShown = $screen.Contains('\l4jtest\fixed\')
    $(if ($st -match '^exit=2 ' -and $found.Count -eq $expect.Count -and -not $fixedShown) { 0 } else { 1 })
    '{0} · 놓은 취약 {1}/{2} 이 화면에 · 고친 판 {3}' -f $st, $found.Count, $expect.Count, $(if ($fixedShown) { '화면에 있다' } else { '화면에 없다' })
}
# 이번 판의 Apache 룰 하네스 — 놓은 설치본 · 서비스 · 프로세스는 하네스가 치운다(되돌리기는 아래 reset6).
Step 'apache' {
    & (Join-Path $h 'Invoke-ApacheVerify.ps1') -Package $Package -ApacheZip $apacheZip -LogDir (Join-Path $LogDir 'apache')
} $verdictLine
# 이번 판의 Java4Shell 점검 룰 하네스 — 놓은 홈 · 서비스 · 프로세스는 하네스가 치운다(되돌리기는 아래 reset6).
Step 'java4shell' {
    & (Join-Path $h 'Invoke-Java4ShellVerify.ps1') -Package $Package -JdkZip $jdkZip -LogDir (Join-Path $LogDir 'java4shell')
} $verdictLine
# 이번 판의 nginx2root 점검 룰 하네스 — 놓은 설치본 · 서비스 · 프로세스는 하네스가 치운다(되돌리기는 아래 reset6).
Step 'nginx' {
    & (Join-Path $h 'Invoke-Nginx2rootVerify.ps1') -Package $Package -NginxZipDir $nginxDir -LogDir (Join-Path $LogDir 'nginx')
} $verdictLine
# 이번 판의 PHP 11월 보안 업데이트 점검 룰 하네스 — 놓은 설치본 · 서비스 · 프로세스 · 링크는 하네스가 치운다(되돌리기는 아래
# reset6). 치울 자리가 시작 전에 랩에 있으면 아무것도 지우지 않고 멈춘다 — 그때는 판정 줄이 없어 실패로 센다.
Step 'php2611' {
    & (Join-Path $h 'Invoke-Php202611Verify.ps1') -Package $Package -PhpZipDir $phpWinDir -LogDir (Join-Path $LogDir 'php2611')
} $verdictLine
# 종료 코드의 Windows 회귀 — A/B 가 아니라 정한 값을 단정한다(전에는 출시 경로 밖 `Invoke-Sweep` 에서만 돌았다).
# 가드 중단 5(상한 · 보호 경로) · 관측 불완전 6 · 일부 실패 3. Partial 은 남의 감염이 없고 게스트에 node.exe 가 있어야
# 서므로 이 자리다(outside · nssm 이 치운 Node.js 는 reset5 가 되살렸다). 남긴 RunOnce 예약은 아래 reset6 이 되돌린다.
Step 'exit5-guard' { & (Join-Path $h 'Invoke-GuardVerify.ps1') -Package $Package } $verdictLine
Step 'exit6-obs' { & (Join-Path $h 'Invoke-ObsVerify.ps1') -Package $Package } $verdictLine
Step 'exit3-partial' { & (Join-Path $h 'Invoke-PartialVerify.ps1') -Package $Package } $verdictLine
Step 'reset6' { & (Join-Path $h 'Reset-Vm.ps1') } $resetJudge
Step 'net-ab' {
    & (Join-Path $rcDir 'Invoke-AbNet.ps1') -PackageA $PackageA -PackageB $Package -ImagesDir $images -OutDir (Join-Path $LogDir 'net-ab')
} {
    param($lines)
    $p = Join-Path $LogDir 'net-ab\summary.txt'
    $all = @()
    if (Test-Path -LiteralPath $p) { $all = @(Get-Content -LiteralPath $p -Encoding UTF8) }
    $pairs = @($all | Where-Object { $_ -match '\sA=(-?\d+) B=(-?\d+)\s' })
    $differ = @($pairs | Where-Object { $_ -match '\sA=(-?\d+) B=(-?\d+)\s' -and $Matches[1] -ne $Matches[2] })
    $last = $all | Where-Object { $_ -match '^same \d+ - different \d+$' } | Select-Object -Last 1
    $(if ($pairs.Count -eq 0 -or -not $last) { 1 } elseif ($differ.Count -gt 0 -or $last -notmatch 'different 0$') { 3 } else { 0 })
    '짝 {0} · 종료 코드 다름 {1} · {2}' -f $pairs.Count, $differ.Count, $(if ($last) { $last } else { '끝 줄 없음' })
}
# 이번 판의 remedy-net.exe 로 이미지의 Apache — 리눅스 하네스와 같은 표(net-apache-cases.txt).
Step 'net-apache' {
    & (Join-Path $rcDir 'Invoke-NetApache.ps1') -Bin (Join-Path $Package 'remedy-net\remedy-net.exe') `
        -Criteria (Join-Path $Package 'plugins\remedy-net-criteria') -ImagesDir $apacheImages -OutDir (Join-Path $LogDir 'net-apache')
} $verdictLine
# 서명 확인의 종료 코드 — 손대지 않은 꾸러미 0 · 고친 · 더한 · 지운 파일과 없는 서명 5. 이 기계에서 박힌 앵커로 잰다(VM 이 필요 없다).
Step 'exit5-sign' { & (Join-Path $h 'Invoke-SignVerify.ps1') -Package $Package } $verdictLine
# 실행 파일의 코드서명 상태마다 자기무결성의 치료 문(1.24.0 · 결정 S2) — 받은 실행 파일이 서명돼 있으면 루트 없는 오프라인
# 기계(B)까지 잰다. 인증서 저장소를 바꾸므로 그 하네스가 끝에 VM 을 되돌린다 — 그래서 맨 끝이다.
Step 'codesign-trust' {
    & (Join-Path $h 'Invoke-CodeSignTrustVerify.ps1') -Package $Package -LogDir (Join-Path $LogDir 'codesign-trust')
} $verdictLine

$tail = @()
if ($script:failed.Count) { $tail += '실패: ' + ($script:failed -join ', ') }
if ($script:differs.Count) { $tail += '다름: ' + ($script:differs -join ', ') }
Note ("끝 {0} · {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $(if ($tail.Count) { $tail -join ' · ' } else { '모두 통과' }))
if ($tail.Count) {
    Note '다름은 그 단계의 summary.txt 에서 A 와 B 가 다른 줄을 보고 의도한 변경인지 정한다'
    exit 1
}
exit 0
