<#
.SYNOPSIS
    설계-09 P2 의 판정 요건을 실기기에서 확인한다. **remedy 에게는 읽기만 시킨다.**

.DESCRIPTION
    P2 의 게이트는 "여기까지 읽기만 한다" 이므로 이 스크립트도 remedy 에게
    읽기 명령만 시킨다. 시스템을 바꾸는 것은 실험대 안의 무해한 픽스처뿐이고,
    그것도 끝나면 지운다.

    **픽스처 하나는 실험대 밖에 있다.** 6-1 이 방화벽 규칙 키에 Deny 를 걸었다
    되돌린다 — 그 키가 아니면 "잠긴 키를 없는 키라 말하는가" 를 잴 수 없다.
    되돌리기까지가 그 검사이고, 되돌리지 못하면 fail 로 말한다.

    확인 항목 (설계-09 P2 검증 목록):
      artifacts        실제 Windows 머신에서 artifacts.json 이 나온다
      groups           부모 N건 → 그룹 N개, 자식은 각 그룹 안에서만
      verdict          verdict.require 가 그룹 단위로 평가된다
      determinism      같은 스냅샷 두 번 evaluate → 바이트 동일
      collect-repeat   같은 트리 두 번 collect → 관찰 부분 동일
      wow64-tasks      32비트 빌드가 System32\Tasks 를 리다이렉트 없이 본다
      wow64-content    32비트 빌드가 읽은 내용이 SysWOW64 가 아니라 System32 다
      nfc              한글 경로가 NFD 로 들어와도 매치된다
      perf             성능 예산 측정 (설계-01 미결 → 숫자를 남긴다)
      corpus           corpus/clean 스냅샷 생성
      observation-lock 잠긴 레지스트리 키를 "없는 키" 로 보고하지 않는다

    **판정을 못 한 항목은 통과가 아니다.** 전제를 세우지 못하면 inconclusive 로
    남기고 종료 코드 2 를 낸다. 조용히 통과시키면 검증이 없는 것만 못하다.

.PARAMETER OutDir
    산출물 디렉터리. verify-p2.json 과 코퍼스 스냅샷이 여기 쌓인다.

.EXAMPLE
    .\Verify-P2.ps1 -OutDir C:\remedy-lab\results\run-x
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $OutDir,
    [string] $LabRoot = "C:\remedy-lab",
    [int]    $Repeat  = 3,
    # %ProgramFiles% 수집은 실측 4분이다. 나머지 항목을 손볼 때마다 그것을
    # 다시 뜨는 것은 낭비다. **다만 건너뛴 항목은 통과가 아니라 미결이다.**
    [switch] $SkipCorpus
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"   # 원격 실행에서 진행률 막대는 잡음이다

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$X64  = Join-Path $LabRoot "bin\remedy-x64.exe"
$X86  = Join-Path $LabRoot "bin\remedy-x86.exe"
$Plugin   = Join-Path $LabRoot "scripts\lab-plugin.yaml"
$FixRoot  = Join-Path $LabRoot "fixtures"
$WorkDir  = Join-Path $OutDir  "work"
$CorpusDir = Join-Path $OutDir "corpus"

function Write-Head { param($t) Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Write-Ok   { param($t) Write-Host "  OK    $t" -ForegroundColor Green }
function Write-Bad  { param($t) Write-Host "  실패  $t" -ForegroundColor Red }
function Write-Hmm  { param($t) Write-Host "  미결  $t" -ForegroundColor Yellow }

$checks = New-Object System.Collections.ArrayList
function Add-Check {
    param(
        [string] $Id,
        [string] $Title,
        [ValidateSet("pass", "fail", "inconclusive")][string] $Status,
        [string] $Detail,
        $Data = $null
    )
    [void]$checks.Add([ordered]@{
        id = $Id; title = $Title; status = $Status; detail = $Detail; data = $Data
    })
    switch ($Status) {
        "pass"         { Write-Ok  "$Id — $Detail" }
        "fail"         { Write-Bad "$Id — $Detail" }
        "inconclusive" { Write-Hmm "$Id — $Detail" }
    }
}

function Write-JsonFile {
    param([string] $Path, $Value, [int] $Depth = 12)
    # BOM 없이 쓴다. serde_json 을 비롯한 파서가 BOM 을 거부한다.
    # Out-File 은 BOM 을 붙이고, 실패해도 조용히 0바이트를 남긴다.
    $json = $Value | ConvertTo-Json -Depth $Depth
    [System.IO.File]::WriteAllText($Path, $json, $Utf8NoBom)
    if ((Get-Item $Path).Length -eq 0) { throw "0바이트로 기록됐다: $Path" }
}

function Read-JsonFile {
    param([string] $Path)
    [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json
}

function Get-Records {
    <#
        스냅샷에서 subject 레코드 배열을 꺼낸다.

        설계-02 §8 은 subject 배열을 **본문 최상위**에 둔다 (`$env.file`,
        `$env.persistence`). 그리고 `@($null)` 은 빈 배열이 아니라 **null 하나를
        담은 1개짜리 배열**이다 — 그래서 없는 것을 1건으로 세게 된다.
        실제로 첫 실행에서 모든 개수가 1로 나왔고, 그 때문에 "0바이트 동일" 같은
        공허한 통과가 만들어졌다. 꺼내는 길을 하나로 둔다.
    #>
    param($Envelope, [string] $Subject)
    $v = $Envelope.$Subject
    if ($null -eq $v) { return @() }
    @($v)
}

function Invoke-Remedy {
    <#
        remedy 를 돌리고 종료 코드·출력·소요 시간을 돌려준다. 던지지 않는다 —
        종료 코드 자체가 검사 대상인 경우가 있다.

        **Start-Process 를 쓰지 않는다.** 실측하면 같은 실행이
        Start-Process -Wait -PassThru -RedirectStandard* 로는 1.02초,
        ProcessStartInfo 로는 0.028초다. 36배 차이가 전부 측정 도구의 몫이다.
        그것을 모르고 첫 측정에서 "실행 하한 1초" 를 remedy 의 성질로 보고했다.
        성능 예산을 그 숫자 위에 세웠다면 있지도 않은 문제를 고치러 갔을 것이다.
    #>
    param(
        [string] $Exe,
        [string[]] $Arguments,
        # 살아 있는 동안 작업 집합을 표본한다. **시간 측정과 같이 쓰지 말 것** —
        # 폴링 간격만큼 소요 시간이 부풀고, 짧은 실행에서는 그 오차가 측정값
        # 자체보다 크다. 그래서 메모리는 별도 실행에서 잰다.
        [switch] $SampleMemory
    )

    # 명령줄을 직접 만드므로 따옴표도 직접 붙인다. 공백 있는 경로는 사용자
    # 환경의 기본값이다 — `C:\Program Files` 가 두 인자로 쪼개져 코퍼스 하나가
    # 통째로 빠진 적이 있다.
    $line = ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $Exe
    $psi.Arguments              = $line
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.WorkingDirectory       = $OutDir

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = [System.Diagnostics.Process]::Start($psi)
    # 두 스트림을 비동기로 받는다. 한쪽을 ReadToEnd 로 기다리는 동안 다른
    # 파이프가 가득 차면 자식이 멈추고 둘이 서로를 기다린다.
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()

    # 최대 작업 집합. 설계-01 의 성능 예산은 시간과 **메모리** 둘 다를 말한다 —
    # 시간만 재고 끝내면 예산이 반만 측정된 채로 확정된다.
    #
    # 종료한 뒤에 PeakWorkingSet64 를 읽으면 0 이 나온다(성능 카운터가 이미
    # 사라졌다). 살아 있는 동안 표본해야 한다. 짧은 실행은 표본을 한 번도
    # 못 뜰 수 있고, 그때는 0 이다 — **0 은 "0MB 를 썼다" 가 아니라 "못 쟀다"** 이므로
    # 호출자가 구분해서 보고한다.
    $peak = 0
    if ($SampleMemory) {
        while (-not $p.HasExited) {
            try {
                $p.Refresh()
                if ($p.PeakWorkingSet64 -gt $peak) { $peak = [int64]$p.PeakWorkingSet64 }
            } catch { break }
            Start-Sleep -Milliseconds 10
        }
        try { $p.Refresh(); if ($p.PeakWorkingSet64 -gt $peak) { $peak = [int64]$p.PeakWorkingSet64 } } catch { }
    }
    $p.WaitForExit()
    $sw.Stop()

    [pscustomobject]@{
        exit     = $p.ExitCode
        stdout   = $outTask.Result
        stderr   = $errTask.Result
        seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 3)
        peak_mem = $peak
    }
}

function Get-Sha256 { param([string] $Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }

foreach ($d in @($OutDir, $WorkDir, $CorpusDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# ================================================================ 0. 전제

Write-Head "0. 전제 확인"

$missing = @($X64, $X86, $Plugin) | Where-Object { -not (Test-Path $_) }
if ($missing) {
    Add-Check "prereq" "바이너리·플러그인 배포" "fail" "없는 파일: $($missing -join ', ')"
    Write-JsonFile (Join-Path $OutDir "verify-p2.json") ([ordered]@{ checks = @($checks) })
    exit 1
}
Write-Ok "x64 $(Get-Sha256 $X64)"
Write-Ok "x86 $(Get-Sha256 $X86)"

$os64 = [Environment]::Is64BitOperatingSystem
if (-not $os64) {
    # 32비트 OS 에서는 WOW64 검사가 성립하지 않는다. 전제가 없으면 통과시키지 않는다.
    Add-Check "prereq-os" "64비트 OS" "inconclusive" "32비트 OS 다. WOW64 검사를 할 수 없다"
}

# ================================================================ 1. 코퍼스 (픽스처 이전)
#
# **픽스처보다 먼저** 뜬다. 실험대의 예약 작업이 스냅샷에 섞이면 그것은 더 이상
# 청정 코퍼스가 아니고, 그 위에서 도는 오탐 게이트는 아무것도 보장하지 못한다.

Write-Head "1. corpus/clean 스냅샷"

$corpusSpecs = @(
    @{ name = "win10x64-tasks";         root = "$env:SystemRoot\System32\Tasks" },
    @{ name = "win10x64-user-programs"; root = "$env:LOCALAPPDATA\Programs" },
    @{ name = "win10x64-program-files"; root = "$env:ProgramFiles" }
)
$corpusOut = @()
foreach ($spec in $(if ($SkipCorpus) { @() } else { $corpusSpecs })) {
    $dest = Join-Path $CorpusDir "$($spec.name).json"
    if (-not (Test-Path $spec.root)) {
        $corpusOut += [ordered]@{ name = $spec.name; root = $spec.root; status = "missing" }
        continue
    }
    # 여기서 메모리도 함께 표본한다. %ProgramFiles% 는 3만 건이 넘는 가장 큰
    # 수집이고, 폴링 오차 10ms 는 수백 초짜리 실행에서 의미가 없다. 성능
    # 시나리오를 위해 이 규모를 한 번 더 도는 것이야말로 낭비다.
    $r = Invoke-Remedy $X64 @("collect", "--root", $spec.root, "--out", $dest) -SampleMemory
    # 종료 코드 6 은 "수집은 됐으나 관측이 불완전하다" 다 (설계-02 §8). 실행 실패가
    # 아니므로 스냅샷은 받아 두고, 아래 완전성 검사가 그것을 걸러낸다 — 여기서
    # 오류로 처리하면 "왜 코퍼스가 안 생기는가" 의 진짜 이유가 가려진다.
    if (($r.exit -notin 0, 6) -or -not (Test-Path $dest)) {
        $corpusOut += [ordered]@{
            name = $spec.name; root = $spec.root; status = "error"
            exit = $r.exit; stderr = $r.stderr.Trim()
        }
        continue
    }
    $snap = Read-JsonFile $dest
    $nFile = (Get-Records $snap "file").Count
    $corpusOut += [ordered]@{
        name        = $spec.name
        root        = $spec.root
        status      = "ok"
        bytes       = (Get-Item $dest).Length
        files       = $nFile
        persistence = (Get-Records $snap "persistence").Count
        truncated   = $snap.scope.truncated
        denied_dirs = $snap.scope.denied_dirs
        seconds     = $r.seconds
        peak_mem_mb = $(if ($r.peak_mem -gt 0) { [math]::Round($r.peak_mem / 1MB, 1) } else { $null })
    }
    Write-Host ("    {0}: {1} 파일 / {2:N0} 바이트 / {3}s / 최대 {4} MB" -f `
                $spec.name, $nFile, (Get-Item $dest).Length, $r.seconds,
                $corpusOut[-1].peak_mem_mb)
}

$good = @($corpusOut | Where-Object { $_.status -eq "ok" })
# 접근 거부가 있으면 그 스냅샷은 완전하지 않다. 불완전한 스냅샷을 청정 기준으로
# 삼으면 "여기엔 아무것도 없다" 가 "여기를 못 봤다" 일 수 있다.
$dirty = @($good | Where-Object { $_.denied_dirs -gt 0 -or $_.truncated })
if ($SkipCorpus) {
    Add-Check "corpus" "corpus/clean 스냅샷 3개 이상" "inconclusive" `
        "-SkipCorpus 로 건너뛰었다. 이 실행은 완전한 P2 검증이 아니다"
} elseif ($good.Count -lt 3) {
    Add-Check "corpus" "corpus/clean 스냅샷 3개 이상" "fail" `
        "$($good.Count)개만 생성됐다" $corpusOut
} elseif ($dirty.Count -gt 0) {
    Add-Check "corpus" "corpus/clean 스냅샷 3개 이상" "inconclusive" `
        "$($good.Count)개 생성했으나 불완전한 것이 $($dirty.Count)개 (denied_dirs 또는 truncated)" $corpusOut
} else {
    Add-Check "corpus" "corpus/clean 스냅샷 3개 이상" "pass" `
        "$($good.Count)개 생성, 전부 완전(denied_dirs=0, truncated=false)" $corpusOut
}

# ================================================================ 2. 픽스처

Write-Head "2. 픽스처 생성 (무해)"

# 한글 폴더는 **NFD 로** 만든다. NFC 정규화가 없으면 같은 이름이 다른 문자열이 된다.
$nfcName = "한글-테스트"
$nfdName = $nfcName.Normalize([Text.NormalizationForm]::FormD)
if ($nfcName -ceq $nfdName) {
    Add-Check "nfc-premise" "NFD 형이 NFC 와 다르다" "inconclusive" `
        "이 문자열은 NFD 와 NFC 가 같다. NFC 검사가 성립하지 않는다"
}

$cases = @(
    @{ task = "P2-A"; dir = "p2-a";   payload = $true  },
    @{ task = "P2-B"; dir = "p2-b";   payload = $true  },
    @{ task = "P2-C"; dir = "p2-c";   payload = $false },
    @{ task = "P2-D"; dir = $nfdName; payload = $true  }
)

if (-not (Test-Path $FixRoot)) { New-Item -ItemType Directory -Path $FixRoot -Force | Out-Null }

foreach ($c in $cases) {
    $dir = Join-Path $FixRoot $c.dir
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $runner = Join-Path $dir "run.cmd"
    [System.IO.File]::WriteAllText($runner, "@echo off`r`nrem REMEDY-LAB-P2 무해 모형`r`n", $Utf8NoBom)
    if ($c.payload) {
        # 페이로드 모형 — 아무 동작도 하지 않는다. 존재만이 증거다.
        [System.IO.File]::WriteAllText((Join-Path $dir "main.js"),
            "// REMEDY-LAB-P2 무해 모형. 실행되지 않는다.`r`n", $Utf8NoBom)
    }
    $action  = New-ScheduledTaskAction -Execute $runner
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName $c.task -TaskPath "\REMEDY-LAB\" `
        -Action $action -Trigger $trigger -Force | Out-Null
    Write-Ok "\REMEDY-LAB\$($c.task) -> $runner"
}
# 미끼 — main.js 는 있지만 이것을 가리키는 작업이 없다. 어느 그룹의 증거도 아니다.
$decoy = Join-Path $FixRoot "p2-decoy"
New-Item -ItemType Directory -Path $decoy -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path $decoy "main.js"), "// decoy`r`n", $Utf8NoBom)
Write-Ok "미끼: $decoy\main.js (작업 없음)"

try {

# ================================================================ 3. artifacts / groups / verdict

Write-Head "3. scan — artifacts.json · 증거 그룹 · 판정"

$scanDir = Join-Path $WorkDir "scan1"
$r = Invoke-Remedy $X64 @("scan", "--plugin", $Plugin, "--out-dir", $scanDir)
Write-Host $r.stdout.Trim()
if ($r.stderr.Trim()) { Write-Host $r.stderr.Trim() -ForegroundColor DarkYellow }

$artifacts = Join-Path $scanDir "artifacts.json"
$scanJson  = Join-Path $scanDir "scan.json"
$planJson  = Join-Path $scanDir "plan.json"

$produced = @($artifacts, $scanJson, $planJson) | Where-Object { Test-Path $_ }
if ($produced.Count -ne 3) {
    Add-Check "artifacts" "실제 Windows 머신에서 artifacts.json 이 나온다" "fail" `
        "산출물이 3개가 아니다 ($($produced.Count)). exit=$($r.exit) stderr=$($r.stderr.Trim())"
    throw "산출물이 없어 이후 검사를 진행할 수 없다"
}

$art  = Read-JsonFile $artifacts
$scan = Read-JsonFile $scanJson
$plan = Read-JsonFile $planJson

$artFiles = Get-Records $art "file"
$artTasks = Get-Records $art "persistence"
$artOk = ($art.kind -eq "remedy.artifacts") -and ($art.schema_version -ge 1) -and
         ($art.collector.bitness -eq 64) -and ($artTasks.Count -gt 0) -and ($artFiles.Count -gt 0)
if ($artOk) {
    Add-Check "artifacts" "실제 Windows 머신에서 artifacts.json 이 나온다" "pass" `
        ("파일 {0} · 지속성 {1} · 보안제품 {2} · collector {3}bit/OS {4}bit" -f `
            $artFiles.Count, $artTasks.Count,
            (Get-Records $art "security_products").Count,
            $art.collector.bitness, $art.collector.os_bitness) `
        ([ordered]@{
            kind = $art.kind; schema_version = $art.schema_version
            files = $artFiles.Count
            persistence = $artTasks.Count
            security_products = @(Get-Records $art "security_products" | ForEach-Object { $_.vendor })
            truncated = $art.scope.truncated; denied_dirs = $art.scope.denied_dirs
        })
} else {
    Add-Check "artifacts" "실제 Windows 머신에서 artifacts.json 이 나온다" "fail" `
        "봉투가 기대와 다르다: kind=$($art.kind) bitness=$($art.collector.bitness) 파일=$($artFiles.Count) 지속성=$($artTasks.Count)"
}

# --- 증거 그룹: 부모 4건 → 그룹 4개
$groups   = @($scan.groups)
$evidence = @($scan.evidence)
$parents  = @($evidence | Where-Object { $_.rule -eq "lab-task" })

if ($groups.Count -eq 4 -and $parents.Count -eq 4) {
    Add-Check "groups" "부모 4건 → 그룹 4개" "pass" "그룹 $($groups.Count) · 부모 증거 $($parents.Count)"
} else {
    Add-Check "groups" "부모 4건 → 그룹 4개" "fail" `
        "그룹 $($groups.Count) · 부모 증거 $($parents.Count) (기대: 4/4)" `
        (@($groups | ForEach-Object { [ordered]@{ id = $_.id; evidence = @($_.evidence); verdict = $_.verdict } }))
}

# --- 자식은 자기 그룹 안에서만. 미끼는 어느 그룹에도 없다.
$crossTalk = @()
$evById = @{}
foreach ($e in $evidence) { $evById[$e.id] = $e }
foreach ($g in $groups) {
    $dir = $g.captures."lab-task.payload_dir"
    foreach ($eid in @($g.evidence)) {
        $e = $evById[$eid]
        if ($e -and $e.rule -eq "lab-payload") {
            $p = "$($e.target.path)"
            if (-not $p.StartsWith("$dir\", "OrdinalIgnoreCase")) {
                $crossTalk += "$($g.id): $p 가 $dir 밖이다"
            }
        }
    }
}
$decoySeen = @($evidence | Where-Object { "$($_.target.path)" -like "*\p2-decoy\*" })
$children  = @($evidence | Where-Object { $_.rule -eq "lab-payload" })
if ($children.Count -eq 0) {
    # 자식 증거가 하나도 없으면 "혼입이 없다" 는 아무것도 말해주지 않는다.
    # 빈 입력에 대고 통과 도장을 찍는 것이 검증에서 가장 위험한 일이다.
    Add-Check "group-isolation" "자식 증거는 자기 그룹 안에서만" "fail" `
        "자식 증거가 0건이라 격리를 판정할 수 없다 (부모 $($parents.Count)건)"
} elseif ($crossTalk.Count -eq 0 -and $decoySeen.Count -eq 0) {
    Add-Check "group-isolation" "자식 증거는 자기 그룹 안에서만" "pass" `
        "자식 증거 $($children.Count)건 · 그룹 간 혼입 없음 · 미끼 main.js 는 증거가 아니다"
} else {
    Add-Check "group-isolation" "자식 증거는 자기 그룹 안에서만" "fail" `
        "혼입 $($crossTalk.Count)건 · 미끼 증거 $($decoySeen.Count)건" `
        ([ordered]@{ cross = $crossTalk; decoy = @($decoySeen | ForEach-Object { $_.id }) })
}

# --- 판정은 그룹 단위. main.js 가 없는 P2-C 그룹만 떨어져야 한다.
$verdicts = @($scan.verdicts)
$failedGroups = @($groups | Where-Object { -not $_.verdict })
$cGroupFailed = $false
foreach ($g in $failedGroups) {
    if ("$($g.captures.'lab-task.payload_dir')" -like "*\p2-c") { $cGroupFailed = $true }
}
if ($verdicts.Count -eq 3 -and $failedGroups.Count -eq 1 -and $cGroupFailed) {
    Add-Check "verdict" "verdict.require 가 그룹 단위로 평가된다" "pass" `
        "통과 3 (A·B·한글) · 실패 1 (p2-c, main.js 없음)"
} else {
    Add-Check "verdict" "verdict.require 가 그룹 단위로 평가된다" "fail" `
        "통과 $($verdicts.Count) · 실패 $($failedGroups.Count) · p2-c 탈락=$cGroupFailed (기대: 3/1/True)" `
        (@($groups | ForEach-Object {
            [ordered]@{ id = $_.id; verdict = $_.verdict; dir = $_.captures."lab-task.payload_dir" }
        }))
}

# --- P2 의 표면은 Op 0종. 계획에 Action 이 있으면 게이트가 무너진 것이다.
if (@($plan.actions).Count -eq 0) {
    Add-Check "plan-empty" "P2 의 계획에 Action 이 없다" "pass" `
        "Action 0 · 판정 그룹 $(@($plan.verdicts).Count) · exit=$($r.exit)"
} else {
    Add-Check "plan-empty" "P2 의 계획에 Action 이 없다" "fail" `
        "Action 이 $(@($plan.actions).Count)개 있다. P2 게이트 위반"
}

# --- NFC: 한글 경로가 NFD 로 들어와도 매치된다
$nfdGroup = @($groups | Where-Object { "$($_.captures.'lab-task.payload_dir')" -like "*$nfcName" })
$allPaths = @($artFiles | ForEach-Object { "$($_.path)" })
$nfdPaths = @($allPaths | Where-Object { $_.Contains($nfcName) })
$anyNfd   = @($allPaths | Where-Object { $_.Contains($nfdName) -and -not $_.Contains($nfcName) })
if ($nfdGroup.Count -eq 1 -and $nfdGroup[0].verdict -and $nfdPaths.Count -gt 0 -and $anyNfd.Count -eq 0) {
    Add-Check "nfc" "한글 경로가 NFD 로 들어와도 매치" "pass" `
        "NFD 로 만든 디렉터리가 NFC 로 기록되고 그룹이 판정을 통과했다 (경로 $($nfdPaths.Count)건)"
} else {
    Add-Check "nfc" "한글 경로가 NFD 로 들어와도 매치" "fail" `
        "그룹 $($nfdGroup.Count)개 · 판정 $(if($nfdGroup.Count){$nfdGroup[0].verdict}else{'없음'}) · NFC 경로 $($nfdPaths.Count) · NFD 잔존 $($anyNfd.Count)"
}

# ================================================================ 4. 결정성

Write-Head "4. 결정성"

$e1 = Join-Path $WorkDir "eval1.json"
$e2 = Join-Path $WorkDir "eval2.json"
$re1 = Invoke-Remedy $X64 @("evaluate", "--artifacts", $artifacts, "--plugin", $Plugin, "--out", $e1)
$re2 = Invoke-Remedy $X64 @("evaluate", "--artifacts", $artifacts, "--plugin", $Plugin, "--out", $e2)
if ($re1.exit -eq $re2.exit -and (Test-Path $e1) -and (Test-Path $e2)) {
    $h1 = Get-Sha256 $e1
    $h2 = Get-Sha256 $e2
    if ($h1 -eq $h2) {
        Add-Check "determinism" "같은 스냅샷 두 번 evaluate → 바이트 동일" "pass" `
            "SHA256 $h1 (정규화 없이도 동일)"
    } else {
        Add-Check "determinism" "같은 스냅샷 두 번 evaluate → 바이트 동일" "fail" "$h1 != $h2"
    }
} else {
    Add-Check "determinism" "같은 스냅샷 두 번 evaluate → 바이트 동일" "fail" `
        "evaluate 실행 실패 (exit $($re1.exit)/$($re2.exit))"
}

# 수집도 두 번 돌려 본다. 휘발성 필드(run_id·created)는 다르지만 **관찰 부분**은
# 같아야 한다. 순회 순서가 파일 시스템 반환 순서에 의존하면 여기서 깨진다.
$c1 = Join-Path $WorkDir "collect1.json"
$c2 = Join-Path $WorkDir "collect2.json"
[void](Invoke-Remedy $X64 @("collect", "--root", $FixRoot, "--out", $c1))
[void](Invoke-Remedy $X64 @("collect", "--root", $FixRoot, "--out", $c2))
if ((Test-Path $c1) -and (Test-Path $c2)) {
    $s1 = Read-JsonFile $c1
    $s2 = Read-JsonFile $c2
    $n1 = (Get-Records $s1 "file").Count
    $o1 = @(Get-Records $s1 "file") + @(Get-Records $s1 "persistence") | ConvertTo-Json -Depth 12 -Compress
    $o2 = @(Get-Records $s2 "file") + @(Get-Records $s2 "persistence") | ConvertTo-Json -Depth 12 -Compress
    if ($n1 -eq 0) {
        # 빈 관찰 둘을 비교해 "동일" 이라고 말하는 것은 검증이 아니다.
        Add-Check "collect-repeat" "같은 트리 두 번 collect → 관찰 동일" "fail" `
            "픽스처 트리에서 파일을 하나도 수집하지 못했다 — 비교할 것이 없다"
    } elseif ($o1 -ceq $o2) {
        Add-Check "collect-repeat" "같은 트리 두 번 collect → 관찰 동일" "pass" `
            "파일 $n1 건 · $($o1.Length) 바이트 동일"
    } else {
        Add-Check "collect-repeat" "같은 트리 두 번 collect → 관찰 동일" "fail" `
            "관찰 부분이 다르다 ($($o1.Length) vs $($o2.Length) 바이트)"
    }
} else {
    Add-Check "collect-repeat" "같은 트리 두 번 collect → 관찰 동일" "fail" "collect 실행 실패"
}

# ================================================================ 5. WOW64

Write-Head "5. WOW64"

# --- (1) 리다이렉션이 살아 있으면 32비트 프로세스는 System32\Tasks 대신
#         SysWOW64\Tasks 를 보게 된다. 두 디렉터리의 내용이 다르기만 하면
#         어느 쪽을 봤는지 개수로 갈린다. (실측: SysWOW64\Tasks 는 존재한다.
#         없을 것이라고 가정했던 첫 판이 여기서 미결로 끝났다.)
$sysWowTasks = Join-Path $env:SystemRoot "SysWOW64\Tasks"
$countIn = {
    param($p)
    if (-not (Test-Path -LiteralPath $p)) { return 0 }
    @(Get-ChildItem -LiteralPath $p -File -Recurse -ErrorAction SilentlyContinue).Count
}
$nS32 = & $countIn (Join-Path $env:SystemRoot "System32\Tasks")
$nWow = & $countIn $sysWowTasks
Write-Host "    System32\Tasks $nS32 개 / SysWOW64\Tasks $nWow 개"

if (-not $os64) {
    Add-Check "wow64-tasks" "32비트 빌드가 System32\Tasks 를 본다" "inconclusive" "32비트 OS"
} elseif ($nS32 -eq $nWow) {
    Add-Check "wow64-tasks" "32비트 빌드가 System32\Tasks 를 본다" "inconclusive" `
        "두 디렉터리의 파일 수가 같아($nS32) 어느 쪽을 읽었는지 개수로 가를 수 없다"
} else {
    $a86 = Join-Path $WorkDir "artifacts-x86.json"
    $r86 = Invoke-Remedy $X86 @("collect", "--plugin", $Plugin, "--out", $a86)
    if (-not (Test-Path $a86)) {
        Add-Check "wow64-tasks" "32비트 빌드가 System32\Tasks 를 본다" "fail" `
            "x86 collect 실패 (exit $($r86.exit)): $($r86.stderr.Trim())"
    } else {
        $art86 = Read-JsonFile $a86
        $tasks86 = Get-Records $art86 "persistence"
        $p64 = $artTasks.Count
        $p86 = $tasks86.Count
        $src86 = @($tasks86 | ForEach-Object { "$($_.source)" })
        $sysnative = @($src86 | Where-Object { $_ -like "*Sysnative*" })
        $system32  = @($src86 | Where-Object { $_ -like "*\System32\Tasks\*" })
        $bitOk = ($art86.collector.bitness -eq 32) -and ($art86.collector.os_bitness -eq 64)

        if ($p86 -eq $p64 -and $p86 -gt 0 -and $sysnative.Count -eq 0 -and
            $system32.Count -eq $p86 -and $bitOk -and $art86.scope.denied_dirs -eq 0) {
            Add-Check "wow64-tasks" "32비트 빌드가 System32\Tasks 를 리다이렉트 없이 본다" "pass" `
                "지속성 x86 $p86 = x64 $p64 · 기록 경로 전부 System32 · Sysnative 표기 0 · collector 32bit/OS 64bit"
        } else {
            Add-Check "wow64-tasks" "32비트 빌드가 System32\Tasks 를 리다이렉트 없이 본다" "fail" `
                "x86 $p86 / x64 $p64 · System32 표기 $($system32.Count) · Sysnative 표기 $($sysnative.Count) · bitness $($art86.collector.bitness)/$($art86.collector.os_bitness) · denied $($art86.scope.denied_dirs)"
        }
    }
}

# --- (2) 내용까지 확인한다. 경로 표기만 맞고 실제로는 SysWOW64 를 읽었다면
#         해시가 SysWOW64 쪽과 같아진다. 그것을 직접 가른다.
$probe = $null
if ($os64) {
    $s32 = Join-Path $env:SystemRoot "System32"
    $sw6 = Join-Path $env:SystemRoot "SysWOW64"
    foreach ($d in (Get-ChildItem -LiteralPath $s32 -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $peer = Join-Path $sw6 $d.Name
        if (-not (Test-Path -LiteralPath $peer)) { continue }
        $total = @(Get-ChildItem -LiteralPath $d.FullName -File -Recurse -ErrorAction SilentlyContinue)
        if ($total.Count -lt 1 -or $total.Count -gt 400) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d.FullName -File -ErrorAction SilentlyContinue)) {
            $pf = Join-Path $peer $f.Name
            if (-not (Test-Path -LiteralPath $pf)) { continue }
            # 크기가 다르면 내용이 반드시 다르다. 해시는 고른 하나만 계산한다.
            if ((Get-Item -LiteralPath $pf).Length -ne $f.Length) {
                $probe = [ordered]@{
                    dir = $d.FullName; file = $f.Name; files = $total.Count
                    sha_system32 = Get-Sha256 $f.FullName
                    sha_syswow64 = Get-Sha256 $pf
                }
                break
            }
        }
        if ($probe) { break }
    }
}

if (-not $os64) {
    Add-Check "wow64-content" "32비트 빌드가 읽은 내용이 System32 다" "inconclusive" "32비트 OS"
} elseif (-not $probe) {
    Add-Check "wow64-content" "32비트 빌드가 읽은 내용이 System32 다" "inconclusive" `
        "System32 와 SysWOW64 에 내용이 다른 파일을 가진 적당한 크기의 디렉터리를 찾지 못했다"
} else {
    Write-Host "    검사 대상: $($probe.dir)\$($probe.file) (파일 $($probe.files)개)"
    $w64 = Join-Path $WorkDir "wow-x64.json"
    $w86 = Join-Path $WorkDir "wow-x86.json"
    [void](Invoke-Remedy $X64 @("collect", "--root", $probe.dir, "--out", $w64))
    [void](Invoke-Remedy $X86 @("collect", "--root", $probe.dir, "--out", $w86))
    if ((Test-Path $w64) -and (Test-Path $w86)) {
        $target = (Join-Path $probe.dir $probe.file)
        $get = {
            param($file)
            $e = Read-JsonFile $file
            # 기록 경로는 대소문자를 보존하므로 비교는 접어서 한다.
            @(Get-Records $e "file" |
              Where-Object { "$($_.path)".Equals($target, "OrdinalIgnoreCase") }) |
                Select-Object -First 1
        }
        $rec64 = & $get $w64
        $rec86 = & $get $w86
        if (-not $rec64 -or -not $rec86) {
            Add-Check "wow64-content" "32비트 빌드가 읽은 내용이 System32 다" "fail" `
                "대상 파일이 스냅샷에 없다 (x64=$([bool]$rec64) x86=$([bool]$rec86)) — $target" $probe
        } elseif ($rec86.sha256 -eq $probe.sha_system32 -and $rec64.sha256 -eq $probe.sha_system32) {
            Add-Check "wow64-content" "32비트 빌드가 읽은 내용이 System32 다" "pass" `
                "x86 이 읽은 해시가 System32 본체와 같다 (SysWOW64 사본과는 다르다)" $probe
        } elseif ($rec86.sha256 -eq $probe.sha_syswow64) {
            Add-Check "wow64-content" "32비트 빌드가 읽은 내용이 System32 다" "fail" `
                "**리다이렉션이 살아 있다.** x86 이 SysWOW64 사본을 읽고 System32 경로로 기록했다" $probe
        } else {
            Add-Check "wow64-content" "32비트 빌드가 읽은 내용이 System32 다" "fail" `
                "해시가 어느 쪽과도 다르다: x64=$($rec64.sha256) x86=$($rec86.sha256)" $probe
        }
    } else {
        Add-Check "wow64-content" "32비트 빌드가 읽은 내용이 System32 다" "fail" "collect 실행 실패" $probe
    }
}

# ================================================================ 6. 성능 예산

Write-Head "6. 성능 예산 측정 (설계-01 미결)"

# 실행 하한. 아무 일도 하지 않는 호출(`--version`)에도 드는 시간 — 프로세스
# 기동과 이미지 로드다. 이것을 빼야 작은 범위의 측정에서 실제 수집 비용이 보인다.
$floorTimes = @()
for ($i = 0; $i -lt $Repeat; $i++) { $floorTimes += (Invoke-Remedy $X64 @("--version")).seconds }
$floorSorted = @($floorTimes | Sort-Object)
$StartupFloor = $floorSorted[[int]($floorSorted.Count / 2)]
Write-Host ("    실행 하한(--version): {0}s  [{1}]" -f $StartupFloor, ($floorTimes -join ', '))

function Measure-Run {
    param([string] $Label, [string] $Exe, [string[]] $Arguments, [string] $Out)
    $times = @()
    for ($i = 0; $i -lt $Repeat; $i++) {
        $rr = Invoke-Remedy $Exe $Arguments
        # 4(사용법 오류)와 5(가드 중단)만 실행 실패다. 0·2·6 은 정상 종료이며
        # 각각 위협 없음 · 위협 발견 · 관측 불완전을 뜻한다 (설계-02 §8).
        if ($rr.exit -in 4, 5) { return [ordered]@{ label = $Label; error = "exit $($rr.exit): $($rr.stderr.Trim())" } }
        $times += $rr.seconds
    }
    # 메모리는 따로 한 번 더. 시간 측정 회차에 폴링을 섞으면 두 숫자가 다 흐려진다.
    $peak = (Invoke-Remedy $Exe $Arguments -SampleMemory).peak_mem

    # **차가운 회차와 더운 회차를 나눈다.** 중앙값 하나로 뭉개면 첫 실행이
    # 가려진다 — 그런데 사용자가 겪는 것은 언제나 첫 실행이다. 실측에서
    # System32\drivers 는 1회차 9.1s, 2·3회차 1.03s 였다. 중앙값만 보면
    # 이 도구가 9초 걸린다는 사실이 보고서에서 사라진다.
    $cold = $times[0]
    $rest = @($times | Select-Object -Skip 1 | Sort-Object)
    $warm = if ($rest.Count) { $rest[[int]($rest.Count / 2)] } else { $cold }

    # [math]::Max(0, $x) 는 정수 오버로드로 붙어 소수점을 잘라 버린다
    # (8.088 -> 8). 두 인자를 모두 double 로 준다.
    $work = { param($t) [math]::Round([math]::Max([double]0, [double]$t - [double]$StartupFloor), 3) }

    $m = [ordered]@{
        label     = $Label
        runs      = $times.Count
        times     = @($times)
        cold_sec  = $cold
        warm_sec  = $warm
        # 하한을 뺀 순수 작업 시간.
        cold_work_sec = & $work $cold
        warm_work_sec = & $work $warm
        # 0 은 "못 쟀다" 다. 짧은 실행은 표본을 한 번도 못 뜬다.
        peak_mem_mb   = $(if ($peak -gt 0) { [math]::Round($peak / 1MB, 1) } else { $null })
    }
    if ($Out -and (Test-Path $Out)) {
        $e = Read-JsonFile $Out
        $files = Get-Records $e "file"
        $bytes = [int64](($files | Measure-Object -Property size -Sum).Sum)
        $m.files = $files.Count
        $m.persistence = (Get-Records $e "persistence").Count
        $m.bytes = $bytes
        $m.mb = [math]::Round($bytes / 1MB, 1)

        # 작업 시간이 하한과 같은 자릿수면 처리율은 잡음이다. 숫자를 내는 대신
        # **못 쟀다고 말한다.** 0.1 MB/s 같은 값이 보고서에 남으면 그것이 곧
        # 예산의 근거가 된다. 경계는 하한에 매단다 — 하한이 바뀌면 함께 움직여야 한다.
        $floorBound = [math]::Round([math]::Max([double]0.05, [double]$StartupFloor * 3), 3)
        foreach ($k in @("cold", "warm")) {
            $w = $m["${k}_work_sec"]
            if ($w -ge $floorBound) {
                $m["${k}_files_per_sec"] = [math]::Round($files.Count / $w)
                $m["${k}_mb_per_sec"]    = [math]::Round(($bytes / 1MB) / $w, 1)
            } else {
                $m["${k}_rate"] = "하한에 묻힘 (작업 시간 ${w}s < ${floorBound}s)"
            }
        }
    }
    $rate = {
        param($k)
        if ($null -ne $m["${k}_mb_per_sec"]) { "$($m["${k}_mb_per_sec"]) MB/s" } else { "측정 불가" }
    }
    Write-Host ("    {0}`n      차가움 {1}s (작업 {2}s, {3}) / 더움 {4}s (작업 {5}s, {6})`n      최대 메모리 {7}{8}" -f `
        $Label, $m.cold_sec, $m.cold_work_sec, (& $rate "cold"),
        $m.warm_sec, $m.warm_work_sec, (& $rate "warm"),
        $(if ($null -ne $m.peak_mem_mb) { "$($m.peak_mem_mb) MB" } else { "측정 실패(실행이 너무 짧다)" }),
        $(if ($m.files) { " · 파일 $($m.files) · $($m.mb) MB" } else { "" }))
    $m
}

$perf = @()
$perfScan = Join-Path $WorkDir "perf-scan"
$perf += Measure-Run "scan (실험 플러그인 범위)" $X64 `
            @("scan", "--plugin", $Plugin, "--out-dir", $perfScan) (Join-Path $perfScan "artifacts.json")

$driversRoot = Join-Path $env:SystemRoot "System32\drivers"
$perfBulk = Join-Path $WorkDir "perf-bulk.json"
if (Test-Path $driversRoot) {
    $perf += Measure-Run "collect (System32\drivers, 해시 포함)" $X64 `
                @("collect", "--root", $driversRoot, "--out", $perfBulk) $perfBulk
}
$perfTasks = Join-Path $WorkDir "perf-tasks.json"
$perf += Measure-Run "collect (System32\Tasks)" $X64 `
            @("collect", "--root", (Join-Path $env:SystemRoot "System32\Tasks"), "--out", $perfTasks) $perfTasks

$perfErr = @($perf | Where-Object { $_.error })
$perfData = [ordered]@{ startup_floor_sec = $StartupFloor; startup_times = @($floorTimes); scenarios = @($perf) }
if ($perfErr.Count -gt 0) {
    Add-Check "perf" "성능 예산 측정" "fail" "$($perfErr.Count)건 실행 실패" $perfData
} else {
    # Sort-Object -Property 는 [ordered] 사전에는 먹지 않는다 — 키는 속성이
    # 아니라서 전부 null 로 정렬되고, 결과가 조용히 입력 순서 그대로다.
    # 실제로 그 때문에 97MB 시나리오 대신 0.7MB 시나리오가 대표로 뽑혔다.
    $bulk = $null
    foreach ($s in $perf) {
        if ($s.bytes -and (-not $bulk -or $s.bytes -gt $bulk.bytes)) { $bulk = $s }
    }
    $rate = $(if ($null -ne $bulk.cold_mb_per_sec) { "$($bulk.cold_mb_per_sec) MB/s" } else { "측정 불가" })
    $peakAll = 0
    foreach ($s in $perf) {
        if ($null -ne $s.peak_mem_mb -and $s.peak_mem_mb -gt $peakAll) { $peakAll = $s.peak_mem_mb }
    }
    $perfData.peak_mem_mb = $(if ($peakAll -gt 0) { $peakAll } else { $null })
    Add-Check "perf" "성능 예산 측정" "pass" `
        ("실행 하한 {0}s · 최대 메모리 {1} · 최대 시나리오 '{2}' 파일 {3} / {4} MB → 차가움 {5}s (작업 {6}s, {7}) · 더움 {8}s" -f `
            $StartupFloor, $(if ($peakAll -gt 0) { "$peakAll MB" } else { "측정 실패" }),
            $bulk.label, $bulk.files, $bulk.mb,
            $bulk.cold_sec, $bulk.cold_work_sec, $rate, $bulk.warm_sec) `
        $perfData
}

}
catch {
    # 중간에 무엇이 터지든 **보고서는 나와야 한다.** 여기서 그대로 죽으면
    # 앞서 통과한 검사 결과까지 함께 사라지고, 남는 것은 스택 트레이스뿐이다.
    Add-Check "aborted" "검증 도중 중단" "fail" $_.Exception.Message `
        ([ordered]@{ at = "$($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" })
}
finally {

# ================================================================ 6-1. 관측 정직성
#
# **잠긴 키를 "없는 키" 라고 말하지 않는가.**
#
# 단위 시험은 수집기 하나의 논리를 지킨다. 여기서 재는 것은 그 판정이 **끝까지
# 흘러가는가** 다 — Harvest.denied_dirs -> scope.denied_dirs -> 종료 코드 6.
# 이 저장소는 논리가 맞는데 배선이 끊긴 자리를 여러 번 만났고, 그런 자리는
# 단위 시험이 보지 못한다.
#
# **이 검사만 실험대 밖을 건드린다.** 방화벽 규칙 키에 Deny 를 걸었다 되돌린다.
# 되돌리기까지가 검사다 — 조용히 두면 다음 실행의 코퍼스가 잠긴 기계에서
# 떠지고, 그때는 원인이 보이지 않는다. 되돌리기는 docs/operator.md §5-1 의
# 소유권 절차다. Get-Acl 로는 안 된다 — Deny 가 READ_CONTROL 까지 막는다.

Write-Head "6-1. 잠긴 키를 없는 키라 말하지 않는가"

$fwSub  = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
$fwPath = "HKLM:\$fwSub"
$fwHive = [Microsoft.Win32.Registry]::LocalMachine
$fwRt   = [System.Security.AccessControl.RegistryRights]

# 값 개수. 읽지 못하면 -1 — 없는 것과 못 읽는 것을 여기서도 가른다.
function Get-FwValueCount {
    try {
        $handle = $fwHive.OpenSubKey($fwSub)
        if ($null -eq $handle) { return -1 }
        $n = $handle.GetValueNames().Count
        $handle.Close()
        $n
    } catch { -1 }
}

# collect 한 번 — 규칙 수 · 거부 수 · 종료 코드.
function Measure-Fw {
    param([string] $Tag, [string] $PluginPath)
    $outFile = Join-Path $WorkDir "fw-$Tag.json"
    $run = Invoke-Remedy $X64 @("collect", "--out", $outFile, "--plugin", $PluginPath)
    if (-not (Test-Path $outFile)) {
        return [ordered]@{ ok = $false; exit = $run.exit; detail = $run.stderr.Trim() }
    }
    $envelope = Read-JsonFile $outFile
    [ordered]@{
        ok     = $true
        exit   = $run.exit
        rules  = (Get-Records $envelope "firewall_rule").Count
        denied = [int]$envelope.scope.denied_dirs
    }
}

$fwBaseCount = Get-FwValueCount
if ($fwBaseCount -lt 0) {
    Add-Check "observation-lock" "잠긴 방화벽 키를 거부로 센다" "inconclusive" `
        "방화벽 규칙 키를 처음부터 읽지 못한다. 이 기계에서는 잴 수 없다"
} else {
    # firewall_rule 을 선언한 플러그인이 필요하다. 실험대 플러그인의 subjects
    # 한 줄만 고쳐 쓴다 — 원본을 바꾸면 앞의 검사들이 보는 스냅샷이 달라진다.
    $fwPlugin  = Join-Path $WorkDir "fw-plugin.yaml"
    $fwSrcText = [System.IO.File]::ReadAllText($Plugin)
    $fwNewText = $fwSrcText.Replace("subjects: [persistence, file]",
                                    "subjects: [persistence, file, firewall_rule]")
    if ($fwNewText -eq $fwSrcText) {
        # **조용히 원본으로 재지 않는다.** firewall_rule 을 선언하지 않은
        # 플러그인으로 재면 규칙은 늘 0건이고, 검사는 통과처럼 보인다.
        Add-Check "observation-lock" "잠긴 방화벽 키를 거부로 센다" "inconclusive" `
            "lab-plugin.yaml 의 subjects 줄을 찾지 못했다 — 잰 것이 무엇인지 알 수 없다"
    } else {
        [System.IO.File]::WriteAllText($fwPlugin, $fwNewText,
                                       (New-Object System.Text.UTF8Encoding $false))

        # 되돌릴 때 쓸 원래 소유자. 잠그기 전이라 읽힌다.
        $fwOwner0 = try {
            (Get-Acl $fwPath).GetOwner([System.Security.Principal.NTAccount]).Value
        } catch { 'NT AUTHORITY\SYSTEM' }

        $fwBefore = Measure-Fw "before" $fwPlugin
        $fwLocked = $null
        $fwDenyOk = $false
        try {
            $handle = $fwHive.OpenSubKey($fwSub, 'ReadWriteSubTree', $fwRt::ChangePermissions)
            $acl = $handle.GetAccessControl()
            $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
                'Everyone', 'ReadKey', 'None', 'None', 'Deny')))
            $handle.SetAccessControl($acl)
            $handle.Close()
            $fwDenyOk = (Get-FwValueCount) -lt 0
            if ($fwDenyOk) { $fwLocked = Measure-Fw "locked" $fwPlugin }
        } catch {
            $fwDenyOk = $false
        } finally {
            # 위에서 무엇이 터지든 이 키를 잠근 채 두지 않는다.
            try {
                $h1 = $fwHive.OpenSubKey($fwSub, 'ReadWriteSubTree', $fwRt::TakeOwnership)
                $own = New-Object System.Security.AccessControl.RegistrySecurity
                $own.SetOwner([System.Security.Principal.NTAccount]'BUILTIN\Administrators')
                $h1.SetAccessControl($own); $h1.Close()

                $h2 = $fwHive.OpenSubKey($fwSub, 'ReadWriteSubTree', $fwRt::ChangePermissions)
                $acl2 = $h2.GetAccessControl()
                # 변수 이름에 $r 을 쓰지 않는다 — PowerShell 은 변수명 대소문자를
                # 구분하지 않아 $R 을 덮어쓴다 (operator.md §5-1 의 경고).
                foreach ($ace in @($acl2.Access | Where-Object { $_.AccessControlType -eq 'Deny' })) {
                    $acl2.RemoveAccessRuleSpecific($ace) | Out-Null
                }
                $h2.SetAccessControl($acl2); $h2.Close()

                $h3 = $fwHive.OpenSubKey($fwSub, 'ReadWriteSubTree', $fwRt::TakeOwnership)
                $own2 = New-Object System.Security.AccessControl.RegistrySecurity
                $own2.SetOwner([System.Security.Principal.NTAccount]$fwOwner0)
                $h3.SetAccessControl($own2); $h3.Close()
            } catch {
                Write-Bad "방화벽 키 되돌리기 중 오류: $($_.Exception.Message)"
            }
        }

        # ── 판정 1: 잠긴 키가 거부로 세어졌는가
        if (-not $fwDenyOk) {
            Add-Check "observation-lock" "잠긴 방화벽 키를 거부로 센다" "inconclusive" `
                "키를 가리지 못했다. 잠그지 못했으면 잴 것이 없다"
        } elseif (-not $fwBefore.ok -or -not $fwLocked.ok) {
            Add-Check "observation-lock" "잠긴 방화벽 키를 거부로 센다" "fail" `
                "collect 가 산출물을 내지 않았다 (before ok=$($fwBefore.ok) / locked ok=$($fwLocked.ok))"
        } else {
            $sawItBefore = $fwBefore.rules -gt 0
            $rulesGone   = $fwLocked.rules -eq 0
            $deniedRose  = $fwLocked.denied -gt $fwBefore.denied
            $saidSo      = $fwLocked.exit -eq 6
            $detail = ("정상 규칙 $($fwBefore.rules)건·거부 $($fwBefore.denied)·exit $($fwBefore.exit) / " +
                       "잠금 규칙 $($fwLocked.rules)건·거부 $($fwLocked.denied)·exit $($fwLocked.exit)")
            if ($sawItBefore -and $rulesGone -and $deniedRose -and $saidSo) {
                Add-Check "observation-lock" "잠긴 방화벽 키를 거부로 센다" "pass" $detail `
                    @{ before = $fwBefore; locked = $fwLocked }
            } else {
                # 규칙이 0건인데 거부가 오르지 않았다면 잠긴 것을 없는 것으로
                # 보고한 것이다 — 이 검사가 잡으려는 바로 그 상태다.
                Add-Check "observation-lock" "잠긴 방화벽 키를 거부로 센다" "fail" $detail `
                    @{ before = $fwBefore; locked = $fwLocked }
            }
        }

        # ── 판정 2: 되돌렸는가. 못 되돌렸으면 크게 말한다.
        $fwAfterCount = Get-FwValueCount
        if ($fwAfterCount -eq $fwBaseCount) {
            Add-Check "observation-lock-restore" "방화벽 키를 원래대로 되돌렸다" "pass" `
                "값 $fwAfterCount 건 · 소유자 $fwOwner0"
        } else {
            Add-Check "observation-lock-restore" "방화벽 키를 원래대로 되돌렸다" "fail" `
                ("되돌리지 못했다 (전 $fwBaseCount 건 / 후 $fwAfterCount 건). " +
                 "이 기계로 코퍼스를 뜨지 말 것. 스냅샷을 복원하거나 " +
                 "docs/operator.md 5-1 절차로 풀 것")
        }
    }
}

# ================================================================ 7. 정리
#
# finally 에 둔다. 중간에 무엇이 실패하든 실험대의 예약 작업은 지워야 한다 —
# 다음 실행의 코퍼스가 오염되고, 그때는 원인이 보이지 않는다.

Write-Head "7. 픽스처 정리"
foreach ($c in $cases) {
    try {
        Unregister-ScheduledTask -TaskName $c.task -TaskPath "\REMEDY-LAB\" -Confirm:$false -ErrorAction Stop
        Write-Ok "작업 제거: \REMEDY-LAB\$($c.task)"
    } catch {
        Write-Bad "작업 제거 실패 \REMEDY-LAB\$($c.task): $($_.Exception.Message)"
    }
}
foreach ($c in $cases) {
    $dir = Join-Path $FixRoot $c.dir
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
}
if (Test-Path -LiteralPath $decoy) { Remove-Item -LiteralPath $decoy -Recurse -Force -ErrorAction SilentlyContinue }
Write-Ok "픽스처 디렉터리 정리"

}

# ================================================================ 8. 보고

$fails = @($checks | Where-Object { $_.status -eq "fail" })
$hmms  = @($checks | Where-Object { $_.status -eq "inconclusive" })

$report = [ordered]@{
    schema      = "remedy-lab.verify-p2/1"
    verified_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    host        = [ordered]@{
        name       = $env:COMPUTERNAME
        os         = (Get-CimInstance Win32_OperatingSystem).Caption
        os_version = [string][Environment]::OSVersion.Version
        os_64bit   = $os64
        locale     = (Get-Culture).Name
    }
    binaries    = [ordered]@{ x64 = (Get-Sha256 $X64); x86 = (Get-Sha256 $X86) }
    summary     = [ordered]@{
        total = $checks.Count
        pass  = @($checks | Where-Object { $_.status -eq "pass" }).Count
        fail  = $fails.Count
        inconclusive = $hmms.Count
    }
    checks      = @($checks)
}
Write-JsonFile (Join-Path $OutDir "verify-p2.json") $report 14

Write-Head "결과"
Write-Host ("  통과 {0} · 실패 {1} · 미결 {2}" -f `
    $report.summary.pass, $report.summary.fail, $report.summary.inconclusive)
foreach ($c in $checks) {
    $color = switch ($c.status) { "pass" { "Green" } "fail" { "Red" } default { "Yellow" } }
    Write-Host ("  [{0,-12}] {1}" -f $c.status, $c.title) -ForegroundColor $color
}

if ($fails.Count -gt 0) { exit 1 }
if ($hmms.Count -gt 0)  { exit 2 }
exit 0
