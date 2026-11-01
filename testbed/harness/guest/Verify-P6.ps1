#Requires -Version 5.1
<#
.SYNOPSIS
    설계-09 P6 의 판정 요건을 테스트 VM 에서 확인한다 — 실제로 파일을 지운다.

.DESCRIPTION
    **이 저장소에서 처음으로 시스템을 파괴하는 검증이다.** 그래서 재는 것의
    절반은 하지 않은 일이다 — 승인 없이 지웠는가, 드라이런이 지웠는가, 계획에
    없는 것을 지웠는가.

    전부 `C:\remedy-lab` 안에서만 돈다. 실제 시스템 경로는 건드리지 않는다.

    검사 H(대화형 승인)는 **맨 마지막에** 둔다. 콘솔을 할당하느라 프로세스의
    표준 핸들을 갈아 끼우기 때문이다. 그 뒤의 `Write-Host` 는 보이지 않는
    콘솔로 샐 수 있고, 그래서 결과의 정본은 화면이 아니라 JSON 파일이다.

.PARAMETER Bin
    remedy.exe 경로.

.PARAMETER Plugin
    lab-plugin-p6.yaml 경로. G3 검사가 쓴다.

.PARAMETER OutDir
    결과 JSON 을 쓸 곳.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $Plugin,
    [Parameter(Mandatory = $true)][string] $OutDir,
    [string] $LabRoot = "C:\remedy-lab"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$results = New-Object System.Collections.ArrayList

$P6      = "$LabRoot\p6"
$FixRoot = "$LabRoot\p6-fix"
$Capture = "$LabRoot\scripts\Capture-State.ps1"

function Add-Check {
    param([string] $Name, [bool] $Pass, [string] $Detail)
    [void]$results.Add([pscustomobject]@{ name = $Name; pass = $Pass; detail = $Detail })
    $mark = if ($Pass) { "OK  " } else { "실패" }
    $color = if ($Pass) { "Green" } else { "Red" }
    Write-Host ("  {0} {1,-52} {2}" -f $mark, $Name, $Detail) -ForegroundColor $color
}

function Remove-Tree {
    param([string] $Path)
    if (-not (Test-Path $Path)) { return }
    Get-ChildItem $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
        ForEach-Object { $_.IsReadOnly = $false }
    Remove-Item $Path -Recurse -Force -ErrorAction SilentlyContinue
}

function Quote-Arg {
    param([string] $A)
    if ($A -match '[\s"]') { '"' + ($A -replace '"', '\"') + '"' } else { $A }
}

# **인코딩을 매번 명시한다.** 빠뜨리면 .NET 이 콘솔 코드페이지(이 VM 은 CP949)로
# 디코드하는데 remedy 는 UTF-8 로 쓴다. 그러면 한글 문구가 깨져 `-match` 가
# 조용히 어긋나고, 시험은 "그 문구가 없다" 고 보고한다 — 실제로 VM 첫 실행에서
# 검사 하나가 그렇게 실패했다. 호스트에서는 코드페이지가 달라 통과했다.
function New-RemedyPsi {
    param([string[]] $Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Bin
    $psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
    $psi.Arguments = ($Arguments | ForEach-Object { Quote-Arg $_ }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $psi
}

# Start-Process 는 실측 1초를 먹는다. 여러 번 부르므로 직접 띄운다.
#
# **stdin 을 파이프로 못 박는다.** 그러지 않으면 부모의 stdin 을 물려받는데,
# 검사 H 가 콘솔을 할당한 뒤에는 그것이 콘솔 핸들이 되어 remedy 가 "터미널이다"
# 로 판단한다. 검사끼리 순서로 얽히면 어느 것이 무엇을 쟀는지 알 수 없다.
function Invoke-Remedy {
    param([string[]] $Arguments)
    $psi = New-RemedyPsi $Arguments
    $psi.RedirectStandardInput = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    [pscustomobject]@{ exit = $p.ExitCode; text = ($o.Result + $e.Result) }
}

# 계획 하나를 손으로 짓는다. **계획기를 거치지 않는 것이 요점이다** — 실행기가
# 어떤 계획을 받아도 안전장치를 지키는지 재는 검사들이라, 계획 내용을 시험이
# 직접 정해야 한다. 계획기까지 엮은 검사는 G(G3) 하나뿐이다.
function New-LabPlan {
    param([string] $RunId, [string[]] $Targets, [string] $Path)
    $seq = 0
    $actions = @($Targets | ForEach-Object {
        $seq++
        @{ seq = $seq; op = "file.quarantine_only"; target = $_
           because = @("payload#0"); reversible = $true; risk = "low" }
    })
    $plan = [ordered]@{
        schema_version = 1; kind = "remedy.plan"; run_id = $RunId
        created = "2026-08-21T00:00:00Z"
        host = @{ hostname = $env:COMPUTERNAME; os = "windows"; version = "10"; arch = "amd64" }
        core = @{ version = "0"; build = "d" }; plugins = @()
        actions = $actions; verdicts = @("g0")
    }
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, ($plan | ConvertTo-Json -Depth 6),
                                   (New-Object System.Text.UTF8Encoding($false)))
    $Path
}

function New-Baits {
    param([string] $Dir, [int] $Count, [string] $Prefix = "bait")
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    @(0..($Count - 1) | ForEach-Object {
        $p = Join-Path $Dir ("{0}-{1:d4}.exe" -f $Prefix, $_)
        [System.IO.File]::WriteAllText($p, "REMEDY-LAB-P6 payload $_")
        $p
    })
}

function Get-Sha {
    param([string] $Path)
    if (-not (Test-Path $Path)) { return $null }
    (Get-FileHash $Path -Algorithm SHA256).Hash
}

# **쓰는 중인 파일을 읽는다.** `File::ReadAllText` 는 FileShare.Read 로 열어
# 글쓴이를 밀어내므로, 진행 이벤트처럼 도는 동안 읽어야 하는 파일에는 쓸 수 없다.
# 그것을 모르고 쓰면 "다른 프로세스가 사용 중" 으로 검사 자체가 죽는다.
function Read-Shared {
    param([string] $Path)
    if (-not (Test-Path $Path)) { return "" }
    try {
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
                                     [System.IO.FileAccess]::Read, $share)
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
        $t = $sr.ReadToEnd()
        $sr.Close(); $fs.Close()
        return $t
    } catch { return "" }
}

function Wait-ForEvent {
    param([string] $EventFile, [string] $Pattern, [int] $TimeoutMs = 60000)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        if ((Read-Shared $EventFile) -match $Pattern) { return $true }
        Start-Sleep -Milliseconds 2
    }
    return $false
}

Write-Host "`n=== P6 검증 (실행기 — 실제로 지운다) ===" -ForegroundColor Magenta
Write-Host "바이너리 : $Bin"
Write-Host "실험대   : $P6 · $FixRoot"
Write-Host ""

Remove-Tree $P6
Remove-Tree $FixRoot
New-Item -ItemType Directory -Path $P6 -Force | Out-Null

# ══ A. --dry-run 이 계획을 출력하고 아무것도 변경하지 않는다 ══════════
Write-Host "[A] --dry-run" -ForegroundColor Cyan
$dryDir   = "$P6\a-dry"
$dryBaits = New-Baits -Dir $dryDir -Count 3
$dryPlan  = New-LabPlan -RunId "p6-dry" -Targets $dryBaits -Path "$P6\a-dry.plan.json"
$dryState = "$P6\a-state"
$r = Invoke-Remedy @("apply", "--plan", $dryPlan, "--state-dir", $dryState, "--dry-run", "--yes")

Add-Check "드라이런은 2 로 끝난다" ($r.exit -eq 2) "exit=$($r.exit)"
# **원문 Op id 가 아니라 대상 경로를 본다** (2026-09-10).
#
# 이 자리는 `file.quarantine_only` 를 찾고 있었다. 계획 출력이 2026-09-06 부터
# 사람 말(`파일 격리`)로 나오면서 그 문자열은 화면에서 사라졌고, 검사는 4일 동안
# 거짓으로 떨어져 있었다 — 그 사이 P6 을 아무도 돌리지 않아 드러나지 않았다.
#
# **문구는 다듬어질 수 있지만 무엇을 건드릴지는 반드시 적혀야 한다.** 그것이 이
# 검사가 재려던 것이므로, 대상 경로가 전부 나왔는지로 바꾼다. 라벨을 또 다듬어도
# 이 검사는 그대로 서고, 계획이 대상을 빠뜨리면 그때는 걸린다.
#
# `-like` 가 아니라 `.Contains()` 다 — 경로에 `[` 가 들어오면 와일드카드로 읽힌다.
$dryShown = @($dryBaits | Where-Object { $r.text.Contains($_) }).Count
Add-Check "드라이런이 계획을 출력한다" `
    (($dryShown -eq $dryBaits.Count) -and ($r.text -match "아무것도 변경하지 않았습니다")) `
    "$dryShown/$($dryBaits.Count)건 표시"
Add-Check "드라이런이 대상을 지우지 않았다" `
    (@($dryBaits | Where-Object { Test-Path $_ }).Count -eq 3) "3/3 남음"
Add-Check "드라이런이 격리소·저널을 만들지 않았다" `
    ((-not (Test-Path "$dryState\quarantine")) -and (-not (Test-Path "$dryState\journal"))) $dryState

# ══ B. 승인 없이 apply 가 진행되지 않는다 (터미널 아님) ═══════════════
Write-Host "[B] 승인 게이트 — 터미널이 아닐 때" -ForegroundColor Cyan
$noDir   = "$P6\b-noyes"
$noBaits = New-Baits -Dir $noDir -Count 2
$noPlan  = New-LabPlan -RunId "p6-noyes" -Targets $noBaits -Path "$P6\b.plan.json"
$noState = "$P6\b-state"
$r = Invoke-Remedy @("apply", "--plan", $noPlan, "--state-dir", $noState)

Add-Check "승인할 사람이 없으면 거절한다(2)" ($r.exit -eq 2) "exit=$($r.exit)"
Add-Check "왜 거절했는지 말한다" ($r.text -match "승인할 사람이 없습니다") "무인 배포 안내"
Add-Check "승인 없이 대상을 지우지 않았다" `
    (@($noBaits | Where-Object { Test-Path $_ }).Count -eq 2) "2/2 남음"
Add-Check "거절했을 때 잠금도 잡지 않았다" (-not (Test-Path "$noState\remedy.lock")) $noState

# ══ C. 격리 → restore → 원본 일치 ════════════════════════════════════
Write-Host "[C] 격리 -> 복원 왕복" -ForegroundColor Cyan
$cDir = "$P6\c-round"
New-Item -ItemType Directory -Path $cDir -Force | Out-Null

# 되살아나야 하는 성질을 흩어 놓는다 — 큰 이진, 0바이트, 한글 이름, 읽기 전용.
$cFiles = @()
$binFile = "$cDir\updater.exe"
$bytes = New-Object byte[] 4096
for ($i = 0; $i -lt 4096; $i++) { $bytes[$i] = $i % 256 }
[System.IO.File]::WriteAllBytes($binFile, $bytes); $cFiles += $binFile
$emptyFile = "$cDir\empty.bin"
[System.IO.File]::WriteAllBytes($emptyFile, (New-Object byte[] 0)); $cFiles += $emptyFile
$koFile = "$cDir\설정 파일.dat"
[System.IO.File]::WriteAllBytes($koFile,
    [System.Text.Encoding]::UTF8.GetBytes("한글 내용 · 탭`t줄바꿈`n끝")); $cFiles += $koFile
$roFile = "$cDir\readonly.txt"
[System.IO.File]::WriteAllText($roFile, "read only")
(Get-Item $roFile).IsReadOnly = $true; $cFiles += $roFile

$cBefore = @{}
foreach ($f in $cFiles) {
    $cBefore[$f] = [pscustomobject]@{
        sha = Get-Sha $f
        mtime = (Get-Item $f).LastWriteTimeUtc
        ro = (Get-Item $f).IsReadOnly
        len = (Get-Item $f).Length
    }
}

$cPlan  = New-LabPlan -RunId "p6-round" -Targets $cFiles -Path "$P6\c.plan.json"
$cState = "$P6\c-state"
$r = Invoke-Remedy @("apply", "--plan", $cPlan, "--state-dir", $cState, "--yes")
Add-Check "격리 수행이 1 로 끝난다" ($r.exit -eq 1) "exit=$($r.exit)"
Add-Check "원본이 전부 사라졌다" `
    (@($cFiles | Where-Object { Test-Path $_ }).Count -eq 0) "4건"
Add-Check "되돌리는 법을 알려 준다" ($r.text -match "remedy restore --run p6-round") "안내 문구"
Add-Check "격리 컨테이너가 생겼다" (Test-Path "$cState\quarantine\p6-round.rq") "p6-round.rq"

$r = Invoke-Remedy @("restore", "--run", "p6-round", "--state-dir", $cState, "--yes")
Add-Check "복원이 0 으로 끝난다" ($r.exit -eq 0) "exit=$($r.exit)"

$same = 0; $mismatch = @()
foreach ($f in $cFiles) {
    $want = $cBefore[$f]
    if ((Get-Sha $f) -eq $want.sha) { $same++ } else { $mismatch += (Split-Path -Leaf $f) }
}
Add-Check "복원된 바이트가 원본과 같다" ($same -eq $cFiles.Count) `
    "$same/$($cFiles.Count)$(if ($mismatch) { ' 불일치: ' + ($mismatch -join ',') })"
Add-Check "0바이트 파일도 되살아난다" `
    ((Test-Path $emptyFile) -and ((Get-Item $emptyFile).Length -eq 0)) "empty.bin"
Add-Check "읽기 전용 속성이 되돌아온다" `
    ((Test-Path $roFile) -and (Get-Item $roFile).IsReadOnly) "readonly.txt"
$mtOk = $false
if (Test-Path $binFile) {
    $mtOk = ([math]::Abs(((Get-Item $binFile).LastWriteTimeUtc - $cBefore[$binFile].mtime).TotalSeconds) -lt 2)
}
Add-Check "수정 시각이 되돌아온다" $mtOk "updater.exe"

# ══ D. 실패 주입 — 롤백하지 않고 나머지를 계속한다 ═══════════════════
Write-Host "[D] 실패 주입" -ForegroundColor Cyan
$dDir   = "$P6\d-fail"
$dBaits = New-Baits -Dir $dDir -Count 3 -Prefix "target"
$dPlan  = New-LabPlan -RunId "p6-fail" -Targets $dBaits -Path "$P6\d.plan.json"
$dState = "$P6\d-state"

# 2번을 **읽기는 되고 삭제는 안 되게** 붙든다. FileShare.Read 는 다른 프로세스의
# 읽기를 허용하되 삭제는 거부한다 — 백업은 성공하고 파괴만 실패하는, 실기기에서
# 흔한 실패 모양이다.
$hold = [System.IO.File]::Open($dBaits[1], [System.IO.FileMode]::Open,
                               [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
try {
    $r = Invoke-Remedy @("apply", "--plan", $dPlan, "--state-dir", $dState, "--yes")
} finally {
    $hold.Close(); $hold.Dispose()
}

Add-Check "일부 실패는 3(부분 실패)으로 끝난다" ($r.exit -eq 3) "exit=$($r.exit)"
Add-Check "실패한 대상은 남아 있다" (Test-Path $dBaits[1]) "target-0001.exe"
Add-Check "앞의 성공을 되돌리지 않았다" (-not (Test-Path $dBaits[0])) "target-0000.exe"
Add-Check "실패 뒤에도 나머지를 계속했다" (-not (Test-Path $dBaits[2])) "target-0002.exe"
Add-Check "되돌리지 않았음을 말한다" ($r.text -match "되돌리지 않고 나머지를 수행했습니다") "설계-03 §5"

# 백업은 **파괴 전에 전부** 끝났으므로 실패한 것까지 컨테이너에 있어야 한다.
$dExtract = "$P6\d-extract"
$r = Invoke-Remedy @("restore", "--container", "$dState\quarantine\p6-fail.rq",
                     "--state-dir", $dState, "--extract-to", $dExtract, "--yes")
$got = 0
if (Test-Path $dExtract) { $got = @(Get-ChildItem $dExtract -File).Count }
Add-Check "실패한 대상도 백업에 들어 있다" ($got -eq 3) "$got/3 꺼냄"

# ══ E. 크래시 후 재기동 ══════════════════════════════════════════════
Write-Host "[E] 크래시 후 재기동" -ForegroundColor Cyan
$eDir    = "$P6\e-crash"
$eBaits  = New-Baits -Dir $eDir -Count 400
$eBefore = @{}; foreach ($f in $eBaits) { $eBefore[$f] = Get-Sha $f }
$ePlan   = New-LabPlan -RunId "p6-crash" -Targets $eBaits -Path "$P6\e.plan.json"
$eState  = "$P6\e-state"
$eEvents = "$P6\e-events.ndjson"

$psi = New-RemedyPsi @("apply", "--plan", $ePlan, "--state-dir", $eState, "--yes",
                       "--events", $eEvents)
$victim = [System.Diagnostics.Process]::Start($psi)
$null = $victim.StandardOutput.ReadToEndAsync()
$null = $victim.StandardError.ReadToEndAsync()

# 파괴 도중을 노린다 — `action` 은 나왔는데 `finished` 는 아직인 순간이다.
$caught = Wait-ForEvent -EventFile $eEvents -Pattern '"event":"action"' -TimeoutMs 60000
$seenFinished = ((Read-Shared $eEvents) -match '"event":"finished"')
try { $victim.Kill() } catch { }
$victim.WaitForExit()

$killedAt = @($eBaits | Where-Object { -not (Test-Path $_) }).Count
Add-Check "파괴 도중에 죽였다" ($caught -and -not $seenFinished -and $killedAt -gt 0 -and $killedAt -lt 400) `
    "$killedAt/400 사라진 상태에서 종료"

$jtext = Read-Shared "$eState\journal\p6-crash.jsonl"
Add-Check "저널은 끝나지 않은 채 남았다" `
    (($jtext.Length -gt 0) -and ($jtext -notmatch '"rec":"end"')) "end 기록 없음"
# **잠금 파일은 남지만 잠금은 OS 가 푼다.** 그러지 않으면 크래시 한 번에 그
# 기계는 재부팅 전까지 아무것도 고칠 수 없다.
Add-Check "잠금 파일이 남아 있다" (Test-Path "$eState\remedy.lock") "remedy.lock"

$r = Invoke-Remedy @("apply", "--plan", $ePlan, "--state-dir", $eState, "--yes")
Add-Check "재기동이 이어서 수행한다(1)" ($r.exit -eq 1) "exit=$($r.exit)"
Add-Check "이어받았다고 말한다" ($r.text -match "이전 실행을 이어받았습니다") "사람 쪽 안내"
Add-Check "보고가 run 전체를 담는다" ($r.text -match "400건 수행 완료") "400건"
Add-Check "남은 대상이 없다" (@($eBaits | Where-Object { Test-Path $_ }).Count -eq 0) "400/400 제거"

$r = Invoke-Remedy @("restore", "--run", "p6-crash", "--state-dir", $eState, "--yes")
$back = 0
foreach ($f in $eBaits) { if ((Get-Sha $f) -eq $eBefore[$f]) { $back++ } }
Add-Check "이어받은 뒤에도 전부 되살아난다" (($r.exit -eq 0) -and ($back -eq 400)) "$back/400 바이트 일치"

$r = Invoke-Remedy @("apply", "--plan", $ePlan, "--state-dir", $eState, "--yes")
Add-Check "이미 수행된 계획은 가드가 막는다(5)" ($r.exit -eq 5) "exit=$($r.exit)"
Add-Check "왜 막았는지 말한다" ($r.text -match "이미 수행된 계획") "재계획 안내"

# ══ F. 두 번째 인스턴스가 뮤텍스에 막힌다 ════════════════════════════
Write-Host "[F] 전역 뮤텍스" -ForegroundColor Cyan
$fDir    = "$P6\f-lock"
$fBaits  = New-Baits -Dir $fDir -Count 2000
$fPlan   = New-LabPlan -RunId "p6-lock" -Targets $fBaits -Path "$P6\f.plan.json"
$fState  = "$P6\f-state"
$fEvents = "$P6\f-events.ndjson"

$psi = New-RemedyPsi @("apply", "--plan", $fPlan, "--state-dir", $fState, "--yes",
                       "--events", $fEvents)
$first = [System.Diagnostics.Process]::Start($psi)
$firstOut = $first.StandardOutput.ReadToEndAsync()
$null = $first.StandardError.ReadToEndAsync()

# `started` 는 백업 단계 **전에** 나온다. 2000건을 읽어 봉인하는 동안 첫 번째가
# 잠금을 확실히 쥐고 있다.
$up = Wait-ForEvent -EventFile $fEvents -Pattern '"event":"started"' -TimeoutMs 60000
$second = Invoke-Remedy @("apply", "--plan", $fPlan, "--state-dir", $fState, "--yes")
$first.WaitForExit()

Add-Check "첫 번째가 잠금을 쥐고 돌았다" ($up -and $first.ExitCode -eq 1) "exit=$($first.ExitCode)"
Add-Check "두 번째가 막힌다(5)" ($second.exit -eq 5) "exit=$($second.exit)"
Add-Check "이미 돌고 있다고 말한다" ($second.text -match "이미 돌고 있습니다") "잠금 안내"
Add-Check "첫 번째는 끝까지 갔다" ($firstOut.Result -match "2000건 수행 완료") "2000건"
# **막힌 쪽은 저널에 손대지 않았다.** 잠금을 잡기 전에 멈춰야 하는데 그러지
# 않았다면 `Start` 기록이 하나 더 붙는다 — 화면 문구보다 이쪽이 직접적이다.
$fStarts = @([regex]::Matches((Read-Shared "$fState\journal\p6-lock.jsonl"), '"rec":"start"')).Count
Add-Check "막힌 쪽은 저널에 아무것도 쓰지 않았다" ($fStarts -eq 1) "start 기록 $fStarts 줄"

# ══ G. G3 — 계획에 없던 변경이 없다 (계획기부터 실행기까지) ═══════════
Write-Host "[G] G3 — 계획기부터 실행기까지" -ForegroundColor Cyan
foreach ($d in @("alpha", "beta", "decoy", "lonely")) {
    New-Item -ItemType Directory -Path "$FixRoot\$d" -Force | Out-Null
}
foreach ($d in @("alpha", "beta", "lonely")) {
    [System.IO.File]::WriteAllText("$FixRoot\$d\REMEDY-LAB-P6.marker", "marker $d")
}
foreach ($d in @("alpha", "beta", "decoy")) {
    [System.IO.File]::WriteAllText("$FixRoot\$d\payload.js", "console.log('REMEDY-LAB-P6 $d');")
}
$decoySha  = Get-Sha "$FixRoot\decoy\payload.js"
$markerSha = Get-Sha "$FixRoot\alpha\REMEDY-LAB-P6.marker"

$gOut = "$OutDir\g3"
New-Item -ItemType Directory -Path $gOut -Force | Out-Null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Capture `
    -OutFile "$gOut\state-armed.json" -FilePaths $FixRoot | Out-Null

$gState = "$P6\g-state"
$r = Invoke-Remedy @("run", "--plugin", $Plugin, "--state-dir", $gState,
                     "--out-dir", $gOut, "--yes")

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Capture `
    -OutFile "$gOut\state-after.json" -FilePaths $FixRoot | Out-Null

Add-Check "계획기부터 실행기까지 한 번에 돈다(1)" ($r.exit -eq 1) "exit=$($r.exit)"
Add-Check "판정이 선 그룹의 산출물만 격리된다" `
    ((-not (Test-Path "$FixRoot\alpha\payload.js")) -and
     (-not (Test-Path "$FixRoot\beta\payload.js"))) "alpha·beta"
Add-Check "어느 그룹의 증거도 아닌 것은 그대로다" `
    ((Get-Sha "$FixRoot\decoy\payload.js") -eq $decoySha) "decoy\payload.js"
Add-Check "치료 대상이 아닌 증거는 그대로다" `
    ((Get-Sha "$FixRoot\alpha\REMEDY-LAB-P6.marker") -eq $markerSha) "marker 4건"
Add-Check "짝이 없는 그룹은 아무것도 잃지 않았다" `
    (Test-Path "$FixRoot\lonely\REMEDY-LAB-P6.marker") "lonely"
# 불변식 P 대조는 호스트가 한다 — plan.json 과 상태 diff 를 함께 봐야 하고,
# 그 판정 코드는 remedy 를 쓰지 않는 쪽(Compare-State.ps1)에 있어야 한다.
Add-Check "G3 대조 재료가 남았다" `
    ((Test-Path "$gOut\plan.json") -and (Test-Path "$gOut\state-armed.json") -and
     (Test-Path "$gOut\state-after.json")) "plan·armed·after"

# ══ H. 대화형 승인 — 진짜 콘솔에서 ═══════════════════════════════════
#
# **별도 프로세스에 맡긴다.** `AllocConsole` 은 프로세스의 표준 핸들을 갈아
# 끼우고, 되돌려도 PowerShell 의 호스트는 콘솔 화면 버퍼를 다시 잡지 못해
# 이후 `Write-Host` 가 "핸들이 잘못되었습니다"로 죽는다. 여기서 직접 하면
# 이 뒤의 로그가 통째로 사라진다 — 예행에서 실제로 그렇게 됐다.
Write-Host "[H] 대화형 승인 (콘솔 주입)" -ForegroundColor Cyan

$hDir   = "$P6\h-tty"
$hBaits = New-Baits -Dir $hDir -Count 2 -Prefix "tty"
$hPlanNo  = New-LabPlan -RunId "p6-tty-no"  -Targets $hBaits -Path "$P6\h-no.plan.json"
$hPlanYes = New-LabPlan -RunId "p6-tty-yes" -Targets $hBaits -Path "$P6\h-yes.plan.json"
$hReport  = "$OutDir\approve-interactive.json"

$hTargets = "$P6\h-targets.txt"
[System.IO.File]::WriteAllLines($hTargets, [string[]]$hBaits, (New-Object System.Text.UTF8Encoding($false)))

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File "$LabRoot\scripts\Approve-Interactive.ps1" `
    -Bin $Bin -PlanNo $hPlanNo -PlanYes $hPlanYes `
    -StateNo "$P6\h-state-no" -StateYes "$P6\h-state-yes" `
    -TargetsFile $hTargets -OutFile $hReport | Out-Null

$h = $null
if (Test-Path $hReport) {
    $h = [System.IO.File]::ReadAllText($hReport, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
}

if (-not $h) {
    Add-Check "대화형 승인 결과를 받았다" $false "$hReport 없음"
} else {
    # 콘솔을 못 잡으면 그 아래 검사는 **아무것도 재지 못한다.** 통과로 세지 않는다.
    Add-Check "콘솔 stdin 을 확보했다" ([bool]$h.alloc_console) "rc=$($h.console_rc)"
    Add-Check "터미널이면 사람에게 묻는다" `
        (([bool]$h.no.prompted) -and (-not [bool]$h.no.refused)) "승인 질문 출력"
    Add-Check "'아니오' 면 하지 않는다(2)" `
        (($h.no.exit -eq 2) -and (-not [bool]$h.no.timed_out)) `
        "exit=$($h.no.exit) 입력=$($h.no.typed)"
    # **숫자가 없으면 실패다.** `$null -eq $null` 은 참이라, 값이 빠진 보고서를
    # 그대로 비교하면 아무것도 재지 않고 통과한다 — 예행에서 실제로 그랬다.
    $hTgt = $h.targets -as [int]
    $hNo  = $h.remaining_after_no -as [int]
    $hYes = $h.remaining_after_yes -as [int]
    Add-Check "'아니오' 뒤에 대상이 그대로다" `
        (($null -ne $hTgt) -and ($hTgt -gt 0) -and ($hNo -eq $hTgt)) "$hNo/$hTgt 남음"
    Add-Check "'예' 면 수행한다(1)" `
        (($h.yes.exit -eq 1) -and (-not [bool]$h.yes.timed_out)) `
        "exit=$($h.yes.exit) 입력=$($h.yes.typed)"
    Add-Check "'예' 뒤에 대상이 사라졌다" `
        (($null -ne $hYes) -and ($hYes -eq 0)) "$hTgt 건 중 남은 것 $hYes"
}

# ══ 결과 ═════════════════════════════════════════════════════════════
$pass = @($results | Where-Object { $_.pass }).Count
$total = $results.Count
Write-Host ""
Write-Host ("판정: {0}/{1}" -f $pass, $total) -ForegroundColor $(if ($pass -eq $total) { "Green" } else { "Red" })

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$report = [ordered]@{
    schema      = "remedy-lab.verify-p6/1"
    verified_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    passed      = $pass
    total       = $total
    checks      = $results
}
[System.IO.File]::WriteAllText((Join-Path $OutDir "verify-p6.json"),
    ($report | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))

if ($pass -ne $total) { exit 1 }
exit 0
