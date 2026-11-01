<#
.SYNOPSIS
    Capture-State.ps1 이 만든 상태 두 개를 비교한다.

.DESCRIPTION
    "remedy 가 무엇을 했다고 말하는가" 가 아니라 "시스템이 실제로 어떻게 바뀌었는가"
    를 본다. remedy 코드를 전혀 쓰지 않으므로, remedy 의 버그가 이 비교를 오염시킬 수 없다.

    -PlanFile 을 주면 **불변식 P** 를 검사한다 (설계-03 §1):
    계획에 없는 변경이 실제로 일어났다면 위반이다. 이것이 이 테스트베드의
    가장 중요한 판정이다 — 계획서에 없는 삭제가 곧 2차 사고이기 때문이다.

    주의: plan.json 스키마는 P1 에서 확정된다. 그 전까지 이 대조는 **문자열
    포함 여부**라는 성긴 방식이고, 통과했다고 안전이 증명되는 것은 아니다.
    거짓 통과가 가능하다 — 거짓 실패는 거의 없으므로 위반 보고는 신뢰할 수 있다.

.EXAMPLE
    .\Compare-State.ps1 -Before before.json -After after.json -PlanFile plan.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Before,
    [Parameter(Mandatory = $true)][string] $After,
    [string] $PlanFile,
    [string] $OutFile
)

$ErrorActionPreference = "Stop"

$b = Get-Content $Before -Raw -Encoding UTF8 | ConvertFrom-Json
$a = Get-Content $After  -Raw -Encoding UTF8 | ConvertFrom-Json

foreach ($pair in @(@($b, $Before), @($a, $After))) {
    if ($pair[0].schema -ne "remedy-lab.state/5") {
        throw @"
$($pair[1]) 의 schema 가 'remedy-lab.state/4' 가 아니다: $($pair[0].schema)

판이 다른 캡처끼리 비교하면 가짜 변경이 쏟아진다.
  /1 -> /2  파일 수집이 재귀하지 않던 판. 수천 건의 가짜 '추가'가 난다.
  /2 -> /3  서비스에 복구 동작(failure_action)이 추가됐다. 모든 서비스가
            '변경'으로 잡힌다.
  /3 -> /4  볼 레지스트리 값을 인자로 받게 됐다. 요청 목록이 다르면 레지스트리
            섹션이 통째로 추가/삭제로 잡힌다.
  /4 -> /5  그 값들에 타입을 함께 적는다. 전부 '변경'으로 잡힌다.
해당 캡처를 최신 Capture-State.ps1 로 다시 뜰 것.
"@
    }
}

# 관측 자체를 믿을 수 있는지 먼저 판정한다. 잘린 목록이나 서로 다른 루트를
# 비교하면 '변경 없음'이라는 거짓 통과가 나온다 — 이 하네스에서 가장 위험한 실패다.
$observationReliable = $true
$reliabilityNotes = @()
if ($b.files_truncated -or $a.files_truncated) {
    $observationReliable = $false
    $reliabilityNotes += "파일 목록이 잘렸다 (before=$($b.files_truncated) / after=$($a.files_truncated))"
}
# **요청한 루트로 견준다.** 실제로 훑은 루트로 견주면, 위협이 새 디렉터리를
# 만들었을 때 그것이 '관측을 믿을 수 없다' 로 나온다 — 관측 대상이 달라진
# 것이지 관측이 흔들린 것이 아니다. 2026-09-05 채점 5 첫 회차에서 실측했다.
$rootsB = (@($b.file_roots_requested) | Sort-Object) -join '|'
$rootsA = (@($a.file_roots_requested) | Sort-Object) -join '|'
if ($rootsB -ne $rootsA) {
    $observationReliable = $false
    $reliabilityNotes += "전/후 캡처가 서로 다른 파일 루트를 요청했다 (before: $rootsB / after: $rootsA)"
}
# **요청한 것이 없을 때만 흠이다.** 요청했는데 하나도 못 훑었다면 그것은
# 그 자리에 아직 아무것도 없었다는 뜻이고, 위협이 만드는 디렉터리가 정확히
# 그렇다 (`C:\ProgramData\SvcAssist` 는 청정 기계에 없다). 그것을 관측의
# 흠으로 세면 모든 회차가 미결로 끝난다 — 2026-09-05 채점 5 에서 실측했다.
if (-not @($b.file_roots_requested).Count) {
    $observationReliable = $false
    $reliabilityNotes += "훑을 파일 루트를 하나도 요청하지 않았다 — 파일 변경을 볼 수 없었다"
}
# 레지스트리도 같다. 한쪽만 `BootExecute` 를 봤다면 그 값은 '추가' 로 잡히고,
# 그것은 관측의 차이지 기계의 변화가 아니다.
$regB = (@($b.registry_roots) | Sort-Object) -join '|'
$regA = (@($a.registry_roots) | Sort-Object) -join '|'
if ($regB -ne $regA) {
    $observationReliable = $false
    $reliabilityNotes += "전/후 캡처가 서로 다른 레지스트리 값을 봤다 (before: $regB / after: $regA)"
}

# ---------------------------------------------------------------- 계획 대조

$planStrings = @()
if ($PlanFile) {
    if (-not (Test-Path $PlanFile)) { throw "계획 파일이 없다: $PlanFile" }
    $plan = Get-Content $PlanFile -Raw -Encoding UTF8 | ConvertFrom-Json

    # **계획이 건드리겠다고 말한 것만** 모은다 — Action 의 대상이다.
    #
    # 처음에는 plan.json 안의 모든 문자열을 재귀로 긁었다. 스키마를 가정하지
    # 않는 편이 안전하다고 봤는데 정반대였다. 봉투의 `host.os` 가 `"windows"`
    # 라서, **`C:\Windows` 아래에서 무엇이 바뀌어도** "계획에 있다"로 읽혔다.
    # 치료 도구가 가장 큰 사고를 낼 수 있는 자리가 통째로 검사에서 빠진 채
    # 판정은 통과로 나왔다. 실측으로 P6 첫 VM 검증에서 그렇게 나왔다.
    #
    # 스키마는 `cargo xtask schema` 가 고정하고 있으므로 구조를 가정해도 된다.
    # 루프 변수를 `$a` 로 쓰지 말 것 — 이 스크립트에서 `$a` 는 **후 상태**다.
    # PowerShell 의 foreach 는 같은 스코프에 대입하므로 그대로 덮어써지고,
    # 그 뒤의 모든 섹션이 비어 보인다. 실측으로 프로세스 171건·서비스 281건이
    # "사라졌다" 로 나왔다.
    $actions = @($plan.actions)
    foreach ($act in $actions) {
        foreach ($v in @($act.target, $act.'match')) {
            if (($v -is [string]) -and ($v.Trim().Length -ge 4)) { $planStrings += $v.Trim() }
        }
    }
    $planStrings = @($planStrings | Sort-Object -Unique)
    Write-Host "계획의 Action $($actions.Count) 건에서 대상 $($planStrings.Count) 개" -ForegroundColor Gray

    # Action 은 있는데 대상을 하나도 못 뽑았다면 스키마가 바뀐 것이다. 그 상태의
    # 대조는 "계획에 아무것도 없다" 와 구별되지 않으므로 통과로 세면 안 된다.
    if ($actions.Count -gt 0 -and $planStrings.Count -eq 0) {
        $observationReliable = $false
        $reliabilityNotes += "계획에 Action $($actions.Count) 건이 있는데 대조할 대상을 뽑지 못했다 - 계획 스키마가 바뀌었을 수 있다"
    }
}

function Test-Declared {
    param([string] $Key)
    if (-not $PlanFile) { return $null }
    if ([string]::IsNullOrWhiteSpace($Key)) { return $false }
    foreach ($s in $planStrings) {
        if ($Key.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        if ($s.IndexOf($Key, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------- 비교기

function Compare-Section {
    param(
        [string] $Name,
        $BeforeItems,
        $AfterItems,
        [scriptblock] $KeyOf,
        [scriptblock] $ValueOf
    )

    # 키가 없는 항목은 대조할 상대를 특정할 수 없으니 건너뛴다. 다만 조용히
    # 넘기지는 않는다 — 키가 null 이라는 건 캡처가 그 섹션을 제대로 못 담았다는
    # 뜻이고, 그러면 변경을 놓쳤을 수 있다.
    #
    # 예전에는 $bm[$null] 대입에서 "Index operation failed" 로 죽으면서 멀쩡한
    # 섹션의 비교 결과까지 통째로 잃었다. 한 섹션의 흠이 전체를 무너뜨리면 안 된다.
    $skipped = 0
    $bm = @{}; $am = @{}
    foreach ($pair in @(@{ Src = $BeforeItems; Map = $bm }, @{ Src = $AfterItems; Map = $am })) {
        # 섹션이 통째로 비어 있는 것과, 항목은 있는데 키가 없는 것은 다르다.
        # PowerShell 의 @($null) 이 'null 하나짜리 배열'이 되면서 둘을 뭉뚱그리는데,
        # 그대로 두면 정상적으로 빈 섹션(예: 주석뿐인 hosts 파일)을 결함으로 오보한다.
        # 항목이 하나도 없으면 $pair.Src 는 $null 이고, JSON 의 [null] 은 배열로 온다.
        if ($null -eq $pair.Src) { continue }
        foreach ($i in @($pair.Src)) {
            if ($null -eq $i) { $skipped++; continue }
            $k = & $KeyOf $i
            if ($null -eq $k -or "$k" -eq "") { $skipped++; continue }
            $pair.Map[$k] = (& $ValueOf $i)
        }
    }

    $added = @(); $removed = @(); $changed = @()
    foreach ($k in $am.Keys) { if (-not $bm.ContainsKey($k)) { $added += $k } }
    foreach ($k in $bm.Keys) {
        if (-not $am.ContainsKey($k)) { $removed += $k }
        elseif ("$($bm[$k])" -ne "$($am[$k])") {
            $changed += [ordered]@{ key = $k; before = "$($bm[$k])"; after = "$($am[$k])" }
        }
    }

    [ordered]@{
        section = $Name
        skipped = $skipped
        added   = @($added   | Sort-Object | ForEach-Object { [ordered]@{ key = $_; declared = (Test-Declared $_) } })
        removed = @($removed | Sort-Object | ForEach-Object { [ordered]@{ key = $_; declared = (Test-Declared $_) } })
        changed = @($changed | Sort-Object { $_.key } | ForEach-Object {
                        $_.declared = (Test-Declared $_.key); $_ })
    }
}

$sections = @()

# 프로세스는 PID 가 매번 바뀌므로 이미지 경로 + 커맨드라인으로 본다.
$sections += Compare-Section "processes" $b.processes $a.processes `
    { param($i) "$($i.image_path)|$($i.cmdline)" } { param($i) "present" }

# 복구 동작을 값에 포함한다. 설계-03 §2 의 '자동 소생 차단' 이 실제로 걸렸는지는
# 이 값이 바뀌었는지로만 확인할 수 있다.
$sections += Compare-Section "services" $b.services $a.services `
    { param($i) $i.name } `
    { param($i) "$($i.state)|$($i.start_mode)|$($i.image_path)|$($i.failure_action)" }

$sections += Compare-Section "scheduled_tasks" $b.scheduled_tasks $a.scheduled_tasks `
    { param($i) $i.path } { param($i) (($i.actions | ForEach-Object { "$($_.execute) $($_.arguments)" }) -join ";") }

$sections += Compare-Section "autoruns" $b.autoruns $a.autoruns `
    { param($i) "$($i.key)\$($i.name)" } { param($i) $i.value }

$regFlat = {
    param($Reg)
    $o = @()
    foreach ($e in @($Reg)) {
        foreach ($v in @($e.values)) { $o += [ordered]@{ k = "$($e.key)\$($v.name)"; v = $v.value } }
    }
    $o
}
$sections += Compare-Section "registry" (& $regFlat $b.registry) (& $regFlat $a.registry) `
    { param($i) $i.k } { param($i) $i.v }

$sections += Compare-Section "files" $b.files $a.files `
    { param($i) $i.path } { param($i) "$($i.sha256)|$($i.size)" }

$sections += Compare-Section "hosts_entries" `
    (@($b.hosts_entries) | ForEach-Object { [ordered]@{ line = $_ } }) `
    (@($a.hosts_entries) | ForEach-Object { [ordered]@{ line = $_ } }) `
    { param($i) $i.line } { param($i) "present" }

$sections += Compare-Section "root_certificates" $b.root_certificates $a.root_certificates `
    { param($i) $i.thumbprint } { param($i) $i.subject }

$excFlat = {
    param($E)
    $o = @()
    if ($E) {
        foreach ($t in @("path", "process", "extension")) {
            foreach ($v in @($E.$t)) { if ($v) { $o += [ordered]@{ k = "$t=$v" } } }
        }
    }
    $o
}
$sections += Compare-Section "defender_exclusions" (& $excFlat $b.defender_exclusions) (& $excFlat $a.defender_exclusions) `
    { param($i) $i.k } { param($i) "present" }

# ---------------------------------------------------------------- 판정

# 키 없는 항목을 건너뛴 섹션이 있으면 그 섹션의 캡처가 온전하지 않다는 뜻이다.
# 변경을 놓쳤을 수 있으므로 통과 판정을 내리면 안 된다.
$skippedTotal = 0
foreach ($s in $sections) { $skippedTotal += [int]$s.skipped }
if ($skippedTotal -gt 0) {
    $observationReliable = $false
    $where = @($sections | Where-Object { $_.skipped -gt 0 } |
               ForEach-Object { "$($_.section)=$($_.skipped)" }) -join ", "
    $reliabilityNotes += "키가 없는 항목을 건너뛰었다 ($where) - 해당 섹션의 캡처가 온전하지 않다"
}

# 관측 잡음과 진짜 위반을 가른다.
#
# 살아 있는 Windows 는 가만히 둬도 변한다 — 프로세스가 뜨고 지고, 트리거로
# 시작하는 서비스가 일을 마치면 스스로 멈춘다. 그런 것을 위반이라 부르면
# 검증은 늑대소년이 되고, 그러면 진짜 위반이 났을 때 아무도 보지 않는다.
#
# **그렇다고 숨기지는 않는다.** 뺀 것은 `volatile_changes` 로 남기고 화면에도
# 띄운다. 판정에서 빠졌다는 것과 일어나지 않았다는 것은 다른 말이다.
function Test-Volatile {
    param([string] $Section, [string] $Bucket, $Entry)

    # 프로세스 증감은 정상 시스템에서도 끊임없이 일어난다.
    if ($Section -eq "processes") { return $true }

    # 서비스의 **실행 상태만** 달라진 것. 실측으로 W32Time 이 시각 동기화를
    # 마치고 스스로 멈췄다. 시작 유형·이미지 경로·복구 동작이 함께 달라졌다면
    # 그것은 설정 변경이고, 저절로 일어나지 않으므로 잡음이 아니다.
    if ($Section -eq "services" -and $Bucket -eq "changed") {
        $bp = @("$($Entry.before)" -split '\|')
        $ap = @("$($Entry.after)"  -split '\|')
        if (($bp.Count -eq $ap.Count) -and ($bp.Count -gt 1)) {
            for ($i = 1; $i -lt $bp.Count; $i++) {
                if ($bp[$i] -ne $ap[$i]) { return $false }
            }
            return $true
        }
    }
    return $false
}

$totalChanges = 0
$undeclared = @()
$volatile = @()
foreach ($s in $sections) {
    foreach ($bucket in @("added", "removed", "changed")) {
        foreach ($e in @($s.$bucket)) {
            $totalChanges++
            if (-not $PlanFile) { continue }
            if ($e.declared -ne $false) { continue }
            $item = [ordered]@{ section = $s.section; bucket = $bucket; key = $e.key }
            if (Test-Volatile -Section $s.section -Bucket $bucket -Entry $e) {
                $volatile += $item
            } else {
                $undeclared += $item
            }
        }
    }
}

# 잘림·루트 불일치는 변경을 **숨길** 수는 있어도 **만들어낼** 수는 없다.
# 그래서 위반 판정은 그대로 믿을 수 있고, 통과 판정만 미결로 낮춘다.
$report = [ordered]@{
    schema            = "remedy-lab.diff/2"
    before            = (Resolve-Path $Before).Path
    after             = (Resolve-Path $After).Path
    plan              = $(if ($PlanFile) { (Resolve-Path $PlanFile).Path } else { $null })
    total_changes     = $totalChanges
    observation_reliable = $observationReliable
    reliability_notes = @($reliabilityNotes)
    invariant_p       = $(if (-not $PlanFile)          { "not_checked" }
                          elseif ($undeclared.Count)   { "violation" }
                          elseif (-not $observationReliable) { "inconclusive" }
                          else                         { "pass" })
    undeclared_changes = @($undeclared)
    # 판정에서 뺀 것. **일어나지 않았다는 뜻이 아니다.**
    volatile_changes  = @($volatile)
    sections          = $sections
}

if ($OutFile) {
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # JSON 은 BOM 없이 쓴다 (.ps1 은 반대로 BOM 이 필요하다 — README 참고).
    # WriteAllText 는 실패하면 예외를 던진다. Out-File 은 조용히 0바이트를 남긴다.
    [System.IO.File]::WriteAllText($OutFile, ($report | ConvertTo-Json -Depth 10),
                                   (New-Object System.Text.UTF8Encoding($false)))
    if ((Get-Item -LiteralPath $OutFile -ErrorAction Stop).Length -eq 0) {
        throw "JSON 쓰기 실패 (0바이트): $OutFile"
    }
}

# ---------------------------------------------------------------- 사람이 읽을 요약

# 화면 표시용으로만 줄인다. 전체 값은 diff.json 에 그대로 들어 있다.
# 브라우저 계열 프로세스의 커맨드라인은 한 줄이 수천 자라, 그대로 뿌리면
# 정작 중요한 변경이 스크롤 밖으로 밀려난다.
function Short {
    param([string] $Text, [int] $Max = 150)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, $Max) + ("... (총 {0}자, 전체는 diff.json)" -f $Text.Length)
}

Write-Host "`n===== 상태 변화 =====" -ForegroundColor Magenta
foreach ($s in $sections) {
    $n = @($s.added).Count + @($s.removed).Count + @($s.changed).Count
    if ($n -eq 0) { continue }
    Write-Host ("`n{0}  (+{1} / -{2} / ~{3})" -f $s.section, @($s.added).Count, @($s.removed).Count, @($s.changed).Count) -ForegroundColor Cyan
    foreach ($e in @($s.added))   { Write-Host ("  +  {0}{1}" -f (Short $e.key), $(if ($e.declared -eq $false) { "   [계획에 없음]" } else { "" })) }
    foreach ($e in @($s.removed)) { Write-Host ("  -  {0}{1}" -f (Short $e.key), $(if ($e.declared -eq $false) { "   [계획에 없음]" } else { "" })) -ForegroundColor Yellow }
    foreach ($e in @($s.changed)) {
        Write-Host ("  ~  {0}{1}" -f (Short $e.key), $(if ($e.declared -eq $false) { "   [계획에 없음]" } else { "" })) -ForegroundColor Yellow
        Write-Host ("       전: {0}" -f (Short $e.before)) -ForegroundColor DarkGray
        Write-Host ("       후: {0}" -f (Short $e.after))  -ForegroundColor DarkGray
    }
}

Write-Host "`n===== 판정 =====" -ForegroundColor Magenta
Write-Host ("변경 총계: {0}" -f $totalChanges)
if ($volatile.Count) {
    Write-Host ("판정에서 뺀 변화 {0} 건 — 저절로 일어나는 것들이다 (프로세스 증감·서비스 실행 상태)." -f $volatile.Count) -ForegroundColor DarkYellow
    Write-Host "  일어나지 않았다는 뜻이 아니다. 목록은 volatile_changes 에 있다." -ForegroundColor DarkYellow
}
if (-not $observationReliable) {
    Write-Host "관측 신뢰 불가:" -ForegroundColor Red
    foreach ($n in $reliabilityNotes) { Write-Host ("  - {0}" -f $n) -ForegroundColor Red }
}
switch ($report.invariant_p) {
    "pass"      { Write-Host "불변식 P: 통과 — 실제 변경이 모두 계획에 있었다." -ForegroundColor Green }
    "violation" { Write-Host ("불변식 P: **위반** — 계획에 없는 변경 {0} 건" -f $undeclared.Count) -ForegroundColor Red
                  foreach ($u in $undeclared) { Write-Host ("  {0}/{1}: {2}" -f $u.section, $u.bucket, $u.key) -ForegroundColor Red } }
    "inconclusive" {
                  Write-Host "불변식 P: **미결** — 계획 밖 변경은 못 찾았지만 관측을 믿을 수 없다." -ForegroundColor Yellow
                  Write-Host "           변경을 놓쳤을 수 있으므로 통과로 읽으면 안 된다." -ForegroundColor Yellow }
    default     { Write-Host "불변식 P: 미검사 (-PlanFile 을 주면 검사한다)" -ForegroundColor DarkGray }
}
if ($OutFile) { Write-Host "`n보고서: $OutFile" -ForegroundColor Gray }

# 1 = 위반, 2 = 미결. 자동화가 둘을 구분할 수 있어야 한다.
switch ($report.invariant_p) {
    "violation"    { exit 1 }
    "inconclusive" { exit 2 }
    default        { exit 0 }
}
