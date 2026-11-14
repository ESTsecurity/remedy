#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 콘솔 재캡처 두 벌(한국어 · 영어)을 차례로 — 랩 VM 을 되돌리고, 지금 트리를 지어 받고, 다시 되돌린다.

.DESCRIPTION
    `Capture-Console.ps1 -Build` 를 한국어 · 영어로 한 번씩 부르고 앞뒤로 `Reset-Vm.ps1` 을 부른다 — 캡처는 감염을 세우고
    치료 · 복원까지 찍으므로 끝난 랩은 처음 상태가 아니다. 결과는 `testbed\harness\results\console-<스탬프>-win.txt` ·
    `console-<스탬프>-en-win.txt`(스탬프 기본: 지금 `yyyyMMdd-HHmm`). 그 다음은 `cargo xtask console-diff <두 파일>` 로
    기준선과 견주고, 의도한 줄만 달라졌으면 기준선을 갈아 끼운다(`docs/개발-안내.md` "출시 검증" · 긴급 경로의 미룬 검증).

    캡처의 출력은 길다 — 기록 파일로 받는다(`*>` 는 5.1 에서 UTF-16LE 로 쓴다 — `Out-File -Encoding utf8` 로). 리눅스
    컨테이너 일과 나란히 돌리지 않는다(랩 되돌리기와 컨테이너 묶음이
    겹치면 메모리가 모자랐다). 종료 코드: 0 = 넷(되돌리기 · 두 캡처 · 되돌리기) 모두 종료 0 · 1 = 하나라도 아니다.

.EXAMPLE
    .\testbed\harness\host\Invoke-ConsoleRecapture.ps1 2>&1 | Out-File -Encoding utf8 D:\dl\recapture.log
#>
param([string] $Stamp)
$ErrorActionPreference = 'Continue'
if (-not $Stamp) { $Stamp = Get-Date -Format 'yyyyMMdd-HHmm' }
$h = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $h '..\..\..')).Path
$res = Join-Path $repo 'testbed\harness\results'
New-Item -ItemType Directory -Force $res | Out-Null
$t0 = Get-Date
$failed = @()
function Step([string] $name, [scriptblock] $body) {
    $s = Get-Date
    "== $name  $((Get-Date).ToString('HH:mm:ss'))"
    $global:LASTEXITCODE = $null
    & $body
    $code = $LASTEXITCODE
    if ($code -ne 0) { $script:failed += $name }
    "   $name 종료 $code · $([int]((Get-Date) - $s).TotalSeconds)초"
}
$ko = Join-Path $res "console-$Stamp-win.txt"
$en = Join-Path $res "console-$Stamp-en-win.txt"
Step '되돌리기' { & (Join-Path $h 'Reset-Vm.ps1') 2>&1 }
Step '한국어 캡처' { & (Join-Path $h 'Capture-Console.ps1') -Build -Out $ko 2>&1 }
Step '영어 캡처' { & (Join-Path $h 'Capture-Console.ps1') -Build -Lang en -Out $en 2>&1 }
Step '다시 되돌리기' { & (Join-Path $h 'Reset-Vm.ps1') 2>&1 }
foreach ($f in $ko, $en) {
    if (Test-Path -LiteralPath $f) { '{0}  {1} 바이트' -f $f, (Get-Item -LiteralPath $f).Length }
    else { "없다: $f"; $failed += (Split-Path -Leaf $f) }
}
"모두 {0}초 · {1}" -f [int]((Get-Date) - $t0).TotalSeconds, $(if ($failed.Count) { '실패: ' + ($failed -join ', ') } else { '모두 종료 0' })
"다음: cargo xtask console-diff $ko $en"
if ($failed.Count) { exit 1 } else { exit 0 }
