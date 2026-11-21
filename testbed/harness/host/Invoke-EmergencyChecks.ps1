#Requires -Version 5.1
<#
.SYNOPSIS
    긴급 출시의 출시 전 필수 점검 — Windows 몫(docs/긴급-대응.md).

.DESCRIPTION
    태그의 배포 잡이 올린 **초안을 내려받아 푼** Windows 꾸러미(공개할 그 파일)를 차례로 잰다:

      1  정식 파일 — 엔진 · 동반 프로그램의 버전, 꾸러미에 든 룰 전부의 서명(`plugin verify`), 동반 프로그램이 판정
         기준을 알아보는가(`url` · `image` · `container` 도움말의 기준 줄), 실행 파일 둘의 코드서명(유효 · Authenticode ·
         주체가 배포 워크플로의 `CODESIGN_SUBJECT` · 타임스탬프 — `VmSession.ps1` 의 `Get-CodeSignLine`). `-Prev` 를
         주면 **실행 파일 둘이 지난 공개본과 같은 바이트인가**도 본다 — 룰만 바뀐 출시는 지난 공개본의 서명된 실행
         파일을 그대로 싣는다(`.github/workflows/release.yml`). 엔진 버전이 같은데 다르면 실패다
      2  시연 게이트(`Invoke-DemoVerify.ps1 -Bin`) — 그 꾸러미의 remedy.exe 를 랩의 시연 폴더에 세우고 잰다
      3  메뉴 하네스(`Invoke-MenuVerify.ps1 -Package -Prepare -ReinfectOnly`) — 그 꾸러미로 메뉴 흐름 전부
      4  랩 되돌리기(`Reset-Vm.ps1`)

    2 를 3 보다 먼저 돌리는 까닭: `-ReinfectOnly` 는 배포를 건너뛰어 시연 폴더의 실행 파일을 앞 회차의 것으로 둔다
    (`Invoke-MenuVerify.ps1` 의 `-Package` 설명). 리눅스 컨테이너 점검과 **나란히 돌리지 않는다** — 랩 되돌리기와
    컨테이너 묶음이 겹치면 메모리가 모자랐다.

    단계마다 기록과 summary.txt 를 남긴다. 단계의 판정은 그 기록에서 한다 — 정식 파일은 버전 둘 · 모든
    `verify exit=0` · 기준 도움말 셋, 시연과 메뉴는 마지막 `판정 N/N · 실패 0`, 되돌리기는 `복원 완료`.
    종료 코드: 0 = 넷 모두 통과 · 1 = 하나라도 실패(summary.txt 의 끝 줄이 이름을 적는다).

.PARAMETER Package
    내려받아 푼 `remedy-windows-x64` 폴더.

.PARAMETER LogDir
    기록을 남길 폴더(회차마다 새 폴더).

.PARAMETER Prev
    지난 공개본을 내려받아 푼 `remedy-windows-x64` 폴더 — 룰만 바뀐 출시의 배포 잡이 실행 파일을 받은 그 공개본이다
    (잡 기록의 '지난 공개본 … 의 실행 파일을 받았다' · 평소에는 지금 Latest). 주지 않으면 실행 파일 대조를 건너뛰고
    그렇게 적는다. 실행 파일을 다시 짓는 옛 워크플로(2026-11-21 전의 커밋 · 그 커밋에서 낸 긴급 가지)의 출시에는 주지
    않는다 — Windows 실행 파일은 다시 지으면 빌드 칸이 달라 같은 바이트가 아니다.

.EXAMPLE
    .\testbed\harness\host\Invoke-EmergencyChecks.ps1 -Package D:\dl\x\remedy-windows-x64 -Prev D:\dl\prev\remedy-windows-x64 -LogDir D:\dl\emergency-win
#>
param(
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $LogDir,
    [string] $Prev
)
$ErrorActionPreference = 'Continue'
$h = $PSScriptRoot
. (Join-Path $h 'VmSession.ps1')
$subject = Get-CodeSignSubject
$repo = (Resolve-Path (Join-Path $h '..\..\..')).Path
$exe = Join-Path $Package 'remedy.exe'
$net = Join-Path $Package 'remedy-net\remedy-net.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "remedy.exe 가 없다: $exe" }
# 지난 공개본의 실행 파일 둘 — `-Prev` 를 줬을 때만. 이름을 param 과 겹치지 않게 둔다(PowerShell 변수는 대소문자를 안 가린다).
$oldExe = $null
$oldNet = $null
if ($Prev) {
    $oldExe = Join-Path $Prev 'remedy.exe'
    $oldNet = Join-Path $Prev 'remedy-net\remedy-net.exe'
    foreach ($p in @($oldExe, $oldNet)) { if (-not (Test-Path -LiteralPath $p)) { throw "-Prev 에 실행 파일이 없다: $p" } }
}
New-Item -ItemType Directory -Force $LogDir | Out-Null
$summary = Join-Path $LogDir 'summary.txt'
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`r`n") }
$script:failed = @()
# 단계를 돌리고 그 기록으로 판정한다 — `$judge` 는 기록의 줄들을 받아 (통과 여부, 요약)을 돌려준다.
function Step([string] $name, [scriptblock] $body, [scriptblock] $judge) {
    $t0 = Get-Date
    $log = Join-Path $LogDir "$name.log"
    try { & $body *>&1 | ForEach-Object { "$_" } | Out-File -FilePath $log -Encoding utf8 }
    catch { "THROWN: $($_.Exception.Message)" | Out-File -FilePath $log -Append -Encoding utf8 }
    $lines = @(Get-Content -LiteralPath $log -Encoding UTF8)
    $ok, $what = & $judge $lines
    if ($lines -match '^THROWN:') { $ok = $false; $what = "$what · 예외" }
    if (-not $ok) { $script:failed += $name }
    Note ("{0}  {1}  {2}초  {3}  {4}" -f $name, $(if ($ok) { '통과' } else { '실패' }),
        [int]((Get-Date) - $t0).TotalSeconds, (Get-Date -Format 'HH:mm:ss'), $what)
}
# 하네스의 마지막 판정 줄 `판정 N/N · 실패 0` 이 있어야 통과다.
$verdictLine = {
    param($lines)
    $v = $lines | Where-Object { $_ -match '판정 (\d+)/(\d+) · 실패 (\d+)' } | Select-Object -Last 1
    $ok = [bool]($v -and $v -match '판정 (\d+)/(\d+) · 실패 0' -and $Matches[1] -eq $Matches[2])
    # 값 둘을 **따로** 내보낸다 — 배열 하나로 감싸면 `$ok, $what = …` 의 $ok 가 배열 통째를 받아 늘 참이 된다.
    $ok
    $(if ($v) { $v.Trim() } else { '판정 줄 없음' })
}
Set-Location $repo
Note ("시작 {0}  꾸러미={1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Package)
Step 'package' {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $env:REMEDY_LANG = 'en'
    foreach ($p in @($exe, $net)) {
        # 출력을 다 받은 뒤 첫 줄을 고른다 — `| Select-Object -First 1` 은 파이프를 일찍 닫아 5.1 이 프로세스를 끊고
        # 종료 코드가 -1 로 남는다(remedy.exe --version 은 두 줄이라 8번 중 7번)
        $out = @(& $p --version 2>&1)
        $code = $LASTEXITCODE
        '{0} -> {1} (exit={2})' -f (Split-Path $p -Leaf), "$($out | Select-Object -First 1)", $code
    }
    foreach ($d in Get-ChildItem -LiteralPath (Join-Path $Package 'plugins') -Directory) {
        $null = & $exe plugin verify --dir $d.FullName 2>&1
        '{0} verify exit={1}' -f $d.Name, $LASTEXITCODE
    }
    foreach ($c in @('url', 'image', 'container')) {
        $out = & $net $c --help 2>&1
        $rc = $LASTEXITCODE
        $out | ForEach-Object { "$_" } | Where-Object { $_ -like 'Criteria:*' }
        '{0} help exit={1}' -f $c, $rc
    }
    # 지난 공개본과 같은 바이트인가 — 바이트를 먼저 견준다(리눅스 스크립트와 같은 판정). 둘 다 같으면 통과. 다르면 두
    # 버전 줄을 다 읽었고 엔진 버전이 다를 때만 견주지 않고 적는다 — 버전 줄이 같거나 읽지 못했으면 실패다. 버전 줄은
    # 위의 `--version` 과 같은 언어(en)로 받는다.
    if ($oldExe) {
        $same = 0
        foreach ($pair in @(@($exe, $oldExe), @($net, $oldNet))) {
            $a = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[0]).Hash
            $b = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[1]).Hash
            if ($a -eq $b) { $same++ }
        }
        $newLine = "$(@(& $exe --version 2>&1) | Select-Object -First 1)"
        $oldLine = "$(@(& $oldExe --version 2>&1) | Select-Object -First 1)"
        if ($same -eq 2) { 'prevbytes=same 2/2' }
        elseif ($newLine -and $oldLine -and $newLine -ne $oldLine) {
            'prevbytes=skip engine version differs: {0} -> {1}' -f $oldLine, $newLine
        } else { 'prevbytes=differ {0}/2 ({1} -> {2})' -f $same, $oldLine, $newLine }
    } else { 'prevbytes=none' }
    Remove-Item Env:REMEDY_LANG -ErrorAction SilentlyContinue
    foreach ($p in @($exe, $net)) { Get-CodeSignLine -Path $p -Subject $subject }
} {
    param($lines)
    $verify = @($lines | Where-Object { $_ -match ' verify exit=' })
    $good = @($verify | Where-Object { $_ -match ' verify exit=0$' })
    $help = @($lines | Where-Object { $_ -match ' help exit=' })
    $helpGood = @($help | Where-Object { $_ -match ' help exit=0$' })
    $ver = @($lines | Where-Object { $_ -match '\(exit=0\)$' })
    $codesign = @($lines | Where-Object { $_ -match ' codesign=ok ' })
    # 지난 공개본 대조 — 그 덩이가 낸 줄 하나로 판정한다(줄이 없으면 그 덩이가 돌지 않은 것이라 실패).
    $prev = @($lines | Where-Object { $_ -match '^prevbytes=' }) | Select-Object -Last 1
    $prevOk = [bool]($prev -and $prev -match '^prevbytes=(same|skip|none)')
    $prevWhat = if (-not $prev) { '지난 공개본 대조 줄 없음' }
                elseif ($prev -match '^prevbytes=same') { '지난 공개본과 같은 바이트 2/2' }
                elseif ($prev -match '^prevbytes=skip') { '엔진 버전이 지난 공개본과 달라 견주지 않음' }
                elseif ($prev -match '^prevbytes=none') { '지난 공개본 대조 없음(-Prev 를 주지 않았다)' }
                else { '지난 공개본과 다른 바이트 — ' + ($prev -replace '^prevbytes=differ ', '') }
    $ok = ($verify.Count -gt 0) -and ($good.Count -eq $verify.Count) -and ($help.Count -eq 3) -and
          ($helpGood.Count -eq 3) -and ($ver.Count -eq 2) -and ($codesign.Count -eq 2) -and $prevOk
    $ok
    '버전 {0}/2 · 룰 서명 {1}/{2} · 판정 기준 도움말 {3}/3 · 코드서명 {4}/2 · {5}' -f $ver.Count, $good.Count, $verify.Count,
        $helpGood.Count, $codesign.Count, $prevWhat
}
Step 'demo' { & (Join-Path $h 'Invoke-DemoVerify.ps1') -Bin $exe } $verdictLine
Step 'menu' { & (Join-Path $h 'Invoke-MenuVerify.ps1') -Package $Package -Prepare -ReinfectOnly } $verdictLine
Step 'reset' { & (Join-Path $h 'Reset-Vm.ps1') } {
    param($lines)
    $ok = [bool]($lines -match '복원 완료')
    $ok
    $(if ($ok) { '복원 완료' } else { '복원 완료 줄 없음' })
}
Note ("끝 {0} · {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
    $(if ($script:failed.Count -eq 0) { '모두 통과' } else { '실패: ' + ($script:failed -join ', ') }))
if ($script:failed.Count -eq 0) { exit 0 } else { exit 1 }
