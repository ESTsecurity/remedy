#Requires -Version 5.1
<#
.SYNOPSIS
    긴급 출시의 출시 전 필수 점검 — Windows 몫(docs/긴급-대응.md).

.DESCRIPTION
    태그의 배포 잡이 올린 **초안을 내려받아 푼** Windows 꾸러미(공개할 그 파일)를 차례로 잰다:

      1  정식 파일 — 엔진 · 동반 프로그램의 버전, 꾸러미에 든 룰 전부의 서명(`plugin verify`), 동반 프로그램이 판정
         기준을 알아보는가(`url` · `image` · `container` 도움말의 기준 줄)
      2  시연 게이트(`Invoke-DemoVerify.ps1 -Bin`) — 그 꾸러미의 remedy.exe 를 랩의 시연 폴더에 세우고 잰다
      3  메뉴 하네스(`Invoke-MenuVerify.ps1 -Package -Prepare -ReinfectOnly`) — 그 꾸러미로 메뉴 흐름 전부
      4  랩 되돌리기(`Reset-Vm.ps1`)

    2 를 3 보다 먼저 돌리는 까닭: `-ReinfectOnly` 는 배포를 건너뛰어 시연 폴더의 실행 파일을 앞 회차의 것으로 둔다
    (`Invoke-MenuVerify.ps1` 의 `-Package` 설명). 리눅스 컨테이너 점검과 **나란히 돌리지 않는다** — 랩 되돌리기와
    컨테이너 묶음이 겹치면 메모리가 모자랐다.

    단계마다 기록과 summary.txt 를 남긴다. 판정은 각 단계 기록의 마지막 줄이다(시연 `판정 N/N · 실패 0`,
    메뉴 `판정 N/N · 실패 0`, 정식 파일은 모든 `verify exit=0`).

.PARAMETER Package
    내려받아 푼 `remedy-windows-x64` 폴더.

.PARAMETER LogDir
    기록을 남길 폴더(회차마다 새 폴더).

.EXAMPLE
    .\testbed\harness\host\Invoke-EmergencyChecks.ps1 -Package D:\dl\x\remedy-windows-x64 -LogDir D:\dl\emergency-win
#>
param(
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $LogDir
)
$ErrorActionPreference = 'Continue'
$h = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $h '..\..\..')).Path
$exe = Join-Path $Package 'remedy.exe'
$net = Join-Path $Package 'remedy-net\remedy-net.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "remedy.exe 가 없다: $exe" }
New-Item -ItemType Directory -Force $LogDir | Out-Null
$summary = Join-Path $LogDir 'summary.txt'
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`r`n") }
function Step([string] $name, [scriptblock] $body) {
    $t0 = Get-Date
    $log = Join-Path $LogDir "$name.log"
    try { & $body *>&1 | ForEach-Object { "$_" } | Out-File -FilePath $log -Encoding utf8 }
    catch { "THROWN: $($_.Exception.Message)" | Out-File -FilePath $log -Append -Encoding utf8 }
    $last = Get-Content -LiteralPath $log -Encoding UTF8 | Where-Object { $_ -match '판정 \d+/\d+|verify exit=' } | Select-Object -Last 1
    Note ("{0}  {1}초  {2}  {3}" -f $name, [int]((Get-Date) - $t0).TotalSeconds, (Get-Date -Format 'HH:mm:ss'), $last)
}
Set-Location $repo
Note ("시작 {0}  꾸러미={1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Package)
Step 'package' {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $env:REMEDY_LANG = 'en'
    foreach ($p in @($exe, $net)) {
        $v = & $p --version 2>&1 | Select-Object -First 1
        '{0} -> {1} (exit={2})' -f (Split-Path $p -Leaf), "$v", $LASTEXITCODE
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
    Remove-Item Env:REMEDY_LANG -ErrorAction SilentlyContinue
}
Step 'demo' { & (Join-Path $h 'Invoke-DemoVerify.ps1') -Bin $exe }
Step 'menu' { & (Join-Path $h 'Invoke-MenuVerify.ps1') -Package $Package -Prepare -ReinfectOnly }
Step 'reset' { & (Join-Path $h 'Reset-Vm.ps1') }
Note ("끝 {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
exit 0
