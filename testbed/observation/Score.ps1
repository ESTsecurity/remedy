<#
.SYNOPSIS
    관측 결과를 채점한다 (설계-09 P4, 설계-06 §10).

.DESCRIPTION
    통과/불합격 시험이 아니라 **측정**이다. 세 단계 중 어디서 멈췄는지가 데이터다.

      1. 문법 — plugin lint 오류 0
      2. 경고 — plugin lint 경고 0
      3. 동작 — 시나리오에서 판정 1건 이상 · 청정 코퍼스에서 0건

    **3단계가 본체다.** 린트를 통과하는 룰과 실제로 위협을 잡는 룰은 다르고,
    정상을 지키는 룰은 또 다르다. AI 는 "탐지되게 만들기" 에 최적화하고
    "정상을 지키기" 를 잊는다 (설계-06 §7).

.PARAMETER Plugin
    관측 대상 AI 가 작성한 plugin.yaml.

.EXAMPLE
    .\Score.ps1 -Plugin C:\obs\attempt-1.yaml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Plugin,
    [string] $Scenario,
    [string] $Binary
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $Scenario) { $Scenario = Join-Path $PSScriptRoot "input\scenario-a.json" }
if (-not $Binary) {
    $Binary = Join-Path $repoRoot "target\x86_64-pc-windows-msvc\release\remedy.exe"
    if (-not (Test-Path $Binary)) { $Binary = Join-Path $repoRoot "target\release\remedy.exe" }
}

foreach ($f in @($Plugin, $Scenario, $Binary)) {
    if (-not (Test-Path $f)) { throw "없다: $f" }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) "remedy-observation"
New-Item -ItemType Directory -Path $work -Force | Out-Null

function Invoke-Remedy {
    # Start-Process 는 실측 1초를 먹는다. 채점을 여러 번 돌리므로 직접 띄운다.
    param([string[]] $Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Binary
    $psi.Arguments = ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    [pscustomobject]@{ exit = $p.ExitCode; text = ($o.Result + $e.Result) }
}

Write-Host "플러그인 : $Plugin"
Write-Host "시나리오 : $Scenario"
Write-Host "바이너리 : $Binary`n"

# ── 1·2단계 — 린트 ────────────────────────────────────────────
$lint = Invoke-Remedy @("plugin", "lint", $Plugin)
Write-Host $lint.text
$errors = 0
$warnings = 0
if ($lint.text -match '합계: 오류 (\d+) · 경고 (\d+)') {
    $errors = [int]$Matches[1]
    $warnings = [int]$Matches[2]
}

# ── 3단계 — 동작 ─────────────────────────────────────────────
# 린트 오류가 있으면 평가가 성립하지 않는다. 억지로 돌려 "판정 0건" 을 기록하면
# 탐지 실패와 로드 실패가 뭉뚱그려진다.
$detected = $null
$falsePositives = @()
$missed = @()
$wrong = @()

if ($errors -eq 0) {
    $scanOut = Join-Path $work "scenario.json"
    $r = Invoke-Remedy @("evaluate", "--artifacts", $Scenario, "--plugin", $Plugin, "--out", $scanOut)
    if (Test-Path $scanOut) {
        $s = [System.IO.File]::ReadAllText($scanOut) | ConvertFrom-Json
        $detected = @($s.verdicts).Count

        # **판정 개수만 세면 안 된다.** 정상 제품까지 잡은 룰이 "판정 2건" 으로
        # 통과한다 — 채점기를 검증하다 실제로 그렇게 나왔다. 어느 항목을
        # 잡았는지 대조한다.
        $expectPath = [System.IO.Path]::ChangeExtension($Scenario, $null) + "expected.json"
        if (Test-Path $expectPath) {
            $want = [System.IO.File]::ReadAllText($expectPath) | ConvertFrom-Json
            $hit = @($s.evidence | ForEach-Object {
                if ($_.target.id) { $_.target.id } elseif ($_.target.path) { $_.target.path }
            })
            $missed = @($want.must_detect | Where-Object { $hit -notcontains $_ })
            $wrong  = @($want.must_not_detect | Where-Object { $hit -contains $_ })
        }
    } else {
        Write-Host "평가 실패:`n$($r.text)" -ForegroundColor Red
    }

    # 청정 코퍼스. gz 라 풀어서 넣는다.
    $corpusDir = Join-Path $repoRoot "corpus\clean"
    foreach ($gz in Get-ChildItem $corpusDir -Filter *.json.gz -ErrorAction SilentlyContinue) {
        $plain = Join-Path $work ($gz.BaseName)
        if (-not (Test-Path $plain)) {
            $in = [System.IO.File]::OpenRead($gz.FullName)
            $out = [System.IO.File]::Create($plain)
            $ds = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
            try { $ds.CopyTo($out) } finally { $ds.Close(); $out.Close(); $in.Close() }
        }
        $cleanOut = Join-Path $work "clean.json"
        [void](Invoke-Remedy @("evaluate", "--artifacts", $plain, "--plugin", $Plugin, "--out", $cleanOut))
        if (Test-Path $cleanOut) {
            $c = [System.IO.File]::ReadAllText($cleanOut) | ConvertFrom-Json
            $n = @($c.verdicts).Count
            if ($n -gt 0) { $falsePositives += "$($gz.BaseName) : 판정 $n 건" }
        }
    }
}

# ── 결과 ─────────────────────────────────────────────────────
Write-Host "`n===== 채점 =====" -ForegroundColor Magenta
function Line { param($n, $label, $ok, $detail)
    $mark = if ($null -eq $ok) { "미실시" } elseif ($ok) { "통과" } else { "실패" }
    $color = if ($null -eq $ok) { "DarkGray" } elseif ($ok) { "Green" } else { "Red" }
    Write-Host ("  {0}. {1,-24} {2,-6} {3}" -f $n, $label, $mark, $detail) -ForegroundColor $color
}
Line 1 "문법 (린트 오류 0)"  ($errors -eq 0)   "오류 $errors"
Line 2 "경고 (린트 경고 0)"  ($warnings -eq 0) "경고 $warnings"

if ($null -eq $detected) {
    Line 3 "동작" $null "린트 오류로 미실시"
} else {
    $ok = ($detected -ge 1 -and $falsePositives.Count -eq 0 -and
           $missed.Count -eq 0 -and $wrong.Count -eq 0)
    $detail = "시나리오 판정 $detected · 놓침 $($missed.Count) · 잘못 잡음 $($wrong.Count) · 청정 오탐 $($falsePositives.Count)"
    Line 3 "동작" $ok $detail
    foreach ($m in $missed) { Write-Host "       놓침     $m" -ForegroundColor Red }
    foreach ($w in $wrong)  { Write-Host "       정상인데 잡음 $w" -ForegroundColor Red }
    foreach ($fp in $falsePositives) { Write-Host "       청정 코퍼스 오탐 $fp" -ForegroundColor Red }
    if ($detected -eq 0) {
        Write-Host "       위협을 잡지 못했다 — 린트는 통과했으나 룰이 동작하지 않는다" -ForegroundColor Red
    }
}

Write-Host "`n기록할 것: 몇 번째 시도인가 · 어떤 오류를 냈는가 · 지어낸 것이 있는가"
Write-Host "그 답이 나머지 가이드의 목차가 된다 (설계-06 §10)."

# 종료 코드로 자동화하지 않는다. 이것은 측정이지 게이트가 아니다.
exit 0
