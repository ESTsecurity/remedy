#Requires -Version 5.1
<#
.SYNOPSIS
    평소 경로의 최종 확인 — 정식 태그가 올린 초안의 Windows 꾸러미를 잰다(docs/개발-안내.md "출시 검증").

.DESCRIPTION
    `-Final` 은 정식 태그의 배포 잡이 올린 **초안을 내려받아 푼** `remedy-windows-x64` 폴더, `-Rc` 는 rc 묶음이 잰 rc 의
    같은 폴더다. 같은 판 · 같은 커밋이면 정식과 rc 는 **바이트까지 같다** — 그래서 rc 묶음의 결과가 정식 파일의 결과가
    된다. 랩 VM 은 쓰지 않는다.

      1  체크섬 — `-Sums`(릴리스의 SHA256SUMS)를 주면 그 안의 `remedy-windows-x64.zip` 줄과 `-Zip`(받은 zip)을 견준다
      2  정식 파일 — 엔진 · 동반 프로그램의 버전, 꾸러미에 든 룰 전부의 서명(`plugin verify`), 동반 프로그램이 판정
         기준을 알아보는가(`url` · `image` · `container` 도움말의 기준 줄)
      3  rc 와 같은가 — 파일마다 SHA-256 대조. 다른 파일 · 한쪽에만 있는 파일이 0 이어야 한다

    `-LogDir` 에 summary.txt 를 남긴다. 종료 코드: 0 = 모두 통과 · 1 = 하나라도 실패.

.EXAMPLE
    .\testbed\harness\host\Invoke-ReleaseFinalCheck.ps1 -Final D:\dl\final\x\remedy-windows-x64 `
        -Rc D:\dl\rc\x\remedy-windows-x64 -Zip D:\dl\final\remedy-windows-x64.zip -Sums D:\dl\final\SHA256SUMS -LogDir D:\dl\final-check
#>
param(
    [Parameter(Mandatory = $true)][string] $Final,
    [Parameter(Mandatory = $true)][string] $Rc,
    [Parameter(Mandatory = $true)][string] $Zip,
    [Parameter(Mandatory = $true)][string] $Sums,
    [Parameter(Mandatory = $true)][string] $LogDir
)
$ErrorActionPreference = 'Continue'
$exe = Join-Path $Final 'remedy.exe'
$net = Join-Path $Final 'remedy-net\remedy-net.exe'
foreach ($p in @($exe, $net, $Zip, $Sums)) { if (-not (Test-Path -LiteralPath $p)) { throw "없다: $p" } }
if (-not (Test-Path -LiteralPath (Join-Path $Rc 'remedy.exe'))) { throw "rc 폴더에 remedy.exe 가 없다: $Rc" }
New-Item -ItemType Directory -Force $LogDir | Out-Null
$summary = Join-Path $LogDir 'summary.txt'
[IO.File]::WriteAllText($summary, '')
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`r`n") }
$failed = @()
Note ("시작 {0}  정식={1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Final)

# ── 1. 체크섬 ──
$name = Split-Path -Leaf $Zip
$want = Get-Content -LiteralPath $Sums -Encoding UTF8 | Where-Object { $_ -match ('^([0-9a-fA-F]{64})\s+\*?' + [regex]::Escape($name) + '$') } |
    ForEach-Object { $Matches[1].ToLower() } | Select-Object -First 1
$got = (Get-FileHash -LiteralPath $Zip -Algorithm SHA256).Hash.ToLower()
$sumOk = [bool]($want -and $want -eq $got)
if (-not $sumOk) { $failed += 'checksum' }
Note ("1 체크섬  {0}  {1}" -f $(if ($sumOk) { '통과' } else { '실패' }), $(if ($want) { "$name SHA256SUMS 줄과 $(if ($sumOk) { '같다' } else { '다르다' })" } else { "SHA256SUMS 에 $name 줄이 없다" }))

# ── 2. 정식 파일 ──
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:REMEDY_LANG = 'en'
$lines = New-Object System.Collections.Generic.List[string]
foreach ($p in @($exe, $net)) {
    # 출력을 다 받은 뒤 첫 줄을 고른다 — `| Select-Object -First 1` 은 파이프를 일찍 닫아 5.1 이 프로세스를 끊고
    # 종료 코드가 -1 로 남는다(remedy.exe --version 은 두 줄이라 8번 중 7번)
    $out = @(& $p --version 2>&1)
    $code = $LASTEXITCODE
    $lines.Add(('{0} -> {1} (exit={2})' -f (Split-Path $p -Leaf), "$($out | Select-Object -First 1)", $code))
}
foreach ($d in Get-ChildItem -LiteralPath (Join-Path $Final 'plugins') -Directory) {
    $null = & $exe plugin verify --dir $d.FullName 2>&1
    $lines.Add(('{0} verify exit={1}' -f $d.Name, $LASTEXITCODE))
}
foreach ($c in @('url', 'image', 'container')) {
    $out = & $net $c --help 2>&1
    $code = $LASTEXITCODE
    foreach ($l in @($out | ForEach-Object { "$_" } | Where-Object { $_ -like 'Criteria:*' })) { $lines.Add($l) }
    $lines.Add(('{0} help exit={1}' -f $c, $code))
}
Remove-Item Env:REMEDY_LANG -ErrorAction SilentlyContinue
[IO.File]::WriteAllLines((Join-Path $LogDir 'package.log'), $lines)
$verify = @($lines | Where-Object { $_ -match ' verify exit=' })
$good = @($verify | Where-Object { $_ -match ' verify exit=0$' })
$helpGood = @($lines | Where-Object { $_ -match ' help exit=0$' })
$crit = @($lines | Where-Object { $_ -like 'Criteria:*' })
$ver = @($lines | Where-Object { $_ -match '\(exit=0\)$' })
$pkgOk = ($verify.Count -gt 0) -and ($good.Count -eq $verify.Count) -and ($helpGood.Count -eq 3) -and ($crit.Count -eq 3) -and ($ver.Count -eq 2)
if (-not $pkgOk) { $failed += 'package' }
Note ('2 정식 파일  {0}  버전 {1}/2 · 룰 서명 {2}/{3} · 판정 기준 도움말 {4}/3 · 기준 줄 {5}/3' -f $(if ($pkgOk) { '통과' } else { '실패' }),
    $ver.Count, $good.Count, $verify.Count, $helpGood.Count, $crit.Count)

# ── 3. rc 와 같은가 ──
function Get-Tree([string] $root) {
    $root = (Resolve-Path -LiteralPath $root).Path.TrimEnd('\')
    $map = @{}
    Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
        $map[$_.FullName.Substring($root.Length).TrimStart('\')] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }
    $map
}
$treeRc = Get-Tree $Rc
$treeFinal = Get-Tree $Final
$same = 0
$diffs = New-Object System.Collections.Generic.List[string]
foreach ($k in (@($treeRc.Keys) + @($treeFinal.Keys) | Sort-Object -Unique)) {
    if (-not $treeRc.ContainsKey($k)) { $diffs.Add("정식에만  $k"); continue }
    if (-not $treeFinal.ContainsKey($k)) { $diffs.Add("rc 에만    $k"); continue }
    if ($treeRc[$k] -eq $treeFinal[$k]) { $same++ } else { $diffs.Add("다름      $k") }
}
[IO.File]::WriteAllLines((Join-Path $LogDir 'compare.txt'), $diffs)
$cmpOk = ($same -gt 0) -and ($diffs.Count -eq 0)
if (-not $cmpOk) { $failed += 'compare' }
Note ('3 rc 와 같은가  {0}  같은 파일 {1} · 다르거나 한쪽에만 {2}' -f $(if ($cmpOk) { '통과' } else { '실패' }), $same, $diffs.Count)

Note ("끝 {0} · {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
    $(if ($failed.Count -eq 0) { '모두 통과' } else { '실패: ' + ($failed -join ', ') }))
if ($failed.Count -eq 0) { exit 0 } else { exit 1 }
