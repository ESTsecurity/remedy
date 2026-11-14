#Requires -Version 5.1
<#
.SYNOPSIS
    출시의 Windows 랩 묶음 — 지난 공개본(A)과 이번 판(B)을 랩 VM 과 이 기계에서 나란히 재는 18단계
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
      원격          net-ab — 이 기계에서 remedy-net url · image · container(`rc\Invoke-AbNet.ps1`)

    시료는 `-Inputs`(기본 `testbed\harness\results\rc-inputs` — 리눅스 묶음과 같은 자리)에서 읽는다: `jars\`(리눅스 묶음의
    log4j 하네스가 Maven Central 에서 받는다) · `images\`(리눅스 `rc/save-images.sh` 가 만든다) — 그래서 **리눅스 묶음을
    먼저** 돌린다. PHP 8.3.35 zip 은 없으면 windows.php.net 에서 받고 SHA-256 을 견준다. war · Spring Boot 시료는
    `testbed\harness\linux\fixtures\log4j\build-cases.py` 로 짓는다(python). Docker Desktop 에 `php:8.3.35-cli` ·
    `node:22.18.0-bookworm-slim` 이미지가 있어야 한다. **리눅스 묶음과 겹쳐 돌리지 않는다**(메모리가 모자랐다).

    판정: 시연 · 메뉴는 마지막 `판정 N/N · 실패 0`, 되돌리기는 `복원 완료`, 시간은 검사 넷의 줄, A/B 는 상태 줄의
    `A 코드… B 코드…` 가 **모두 같아야** 한다, log4j 는 기대한 종료 코드와 화면, 원격은 `A=코드 B=코드` 짝과 `different 0`.
    summary.txt 가 단계마다 `통과 · 다름 · 실패` 를 적는다. 종료 코드: 0 = 모두 통과 · 1 = 실패나 다름이 있다(다름은 의도한
    변경인지 본다 — 룰만 바꾼 출시라면 다름도 실패다) · 2 = 인자 · 시료가 모자라 시작하지 않았다.

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

$tail = @()
if ($script:failed.Count) { $tail += '실패: ' + ($script:failed -join ', ') }
if ($script:differs.Count) { $tail += '다름: ' + ($script:differs -join ', ') }
Note ("끝 {0} · {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $(if ($tail.Count) { $tail -join ' · ' } else { '모두 통과' }))
if ($tail.Count) {
    Note '다름은 그 단계의 summary.txt 에서 A 와 B 가 다른 줄을 보고 의도한 변경인지 정한다'
    exit 1
}
exit 0
