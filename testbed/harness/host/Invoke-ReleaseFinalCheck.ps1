#Requires -Version 5.1
<#
.SYNOPSIS
    평소 경로의 최종 확인 — 정식 태그가 올린 초안의 Windows 꾸러미를 잰다(docs/개발-안내.md "출시 검증").

.DESCRIPTION
    `-Final` 은 정식 태그의 배포 잡이 올린 **초안을 내려받아 푼** `remedy-windows-x64` 폴더, `-Rc` 는 rc 묶음이 잰 rc 의
    같은 폴더다. 같은 판 · 같은 커밋이면 정식과 rc 는 **빌드마다 새로 쓰이는 칸 말고는 바이트까지 같다** — 그래서 rc
    묶음의 결과가 정식 파일의 결과가 된다. 랩 VM 은 쓰지 않는다.

      1  체크섬 — `-Sums`(릴리스의 SHA256SUMS)를 주면 그 안의 `remedy-windows-x64.zip` 줄과 `-Zip`(받은 zip)을 견준다
      2  정식 파일 — 엔진 · 동반 프로그램의 버전, 꾸러미에 든 룰 전부와 동반 프로그램 폴더의 서명(`plugin verify`), 동반
         프로그램이 판정 기준을 알아보는가(`url` · `image` · `container` 도움말의 기준 줄)
      3  rc 와 같은가 — 파일마다 SHA-256 대조. 빌드마다 새로 쓰이는 칸은 둘이다(v1.16.0 에서 처음 쟀다):
         서명 파일(`MANIFEST.minisig`)은 minisign 이 서명마다 난수를 섞어 서명 값이 다르므로 서명 주석이 같은지 보고(그
         서명이 맞는지는 2 가 잰다), 실행 파일(`.exe`)은 MSVC 링크가 시각과 PDB 의 GUID 를 새로 쓰므로 그 칸만 가리고
         견준다 — 그 실행 파일의 해시를 적은 `MANIFEST` 는 그 줄만 다를 수 있다. 다른 파일 · 한쪽에만 있는 파일이 0 이어야 한다

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
# 서명 폴더는 룰 폴더들과 동반 프로그램 폴더가 전부다 — 3 은 서명 값이 다른 것을 여기서 잰 서명으로 받아들인다.
$signed = @(Get-ChildItem -LiteralPath (Join-Path $Final 'plugins') -Directory) + @(Get-Item -LiteralPath (Join-Path $Final 'remedy-net'))
foreach ($d in $signed) {
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
Note ('2 정식 파일  {0}  버전 {1}/2 · 서명(룰 · 동반 프로그램) {2}/{3} · 판정 기준 도움말 {4}/3 · 기준 줄 {5}/3' -f $(if ($pkgOk) { '통과' } else { '실패' }),
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
# 실행 파일에서 MSVC 링크가 빌드마다 새로 쓰는 칸 — COFF 헤더의 시각 · 선택 헤더의 체크섬 · 디버그 항목마다의 시각 ·
# CodeView(RSDS) 의 PDB GUID 와 나이. PE32+ 가 아니거나 헤더를 따라가지 못하면 $null(그 파일은 바이트 대조 그대로다).
function Get-PeBuildFields([byte[]] $b) {
    if ($b.Length -lt 0x40) { return $null }
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    if ($pe -lt 0 -or $pe + 24 -gt $b.Length -or [BitConverter]::ToUInt32($b, $pe) -ne 0x00004550) { return $null }
    $coff = $pe + 4
    $nsec = [BitConverter]::ToUInt16($b, $coff + 2)
    $optSize = [BitConverter]::ToUInt16($b, $coff + 16)
    $opt = $coff + 20
    if ($opt + 120 -gt $b.Length -or [BitConverter]::ToUInt16($b, $opt) -ne 0x20B) { return $null }
    $fields = New-Object System.Collections.Generic.List[object]
    $fields.Add(@(($coff + 4), 4))
    $fields.Add(@(($opt + 64), 4))
    $dbgRva = [BitConverter]::ToUInt32($b, $opt + 112 + 48)
    $dbgSize = [BitConverter]::ToUInt32($b, $opt + 112 + 52)
    if ($dbgRva -ne 0) {
        $dbg = $null
        for ($i = 0; $i -lt $nsec; $i++) {
            $s = $opt + $optSize + $i * 40
            $vsize = [BitConverter]::ToUInt32($b, $s + 8)
            $vaddr = [BitConverter]::ToUInt32($b, $s + 12)
            $rsize = [BitConverter]::ToUInt32($b, $s + 16)
            $raddr = [BitConverter]::ToUInt32($b, $s + 20)
            if ($dbgRva -ge $vaddr -and $dbgRva -lt $vaddr + [Math]::Max($vsize, $rsize)) { $dbg = $dbgRva - $vaddr + $raddr; break }
        }
        if ($null -eq $dbg) { return $null }
        for ($k = 0; $k -lt [Math]::Floor($dbgSize / 28); $k++) {
            $e = $dbg + $k * 28
            if ($e + 28 -gt $b.Length) { return $null }
            $fields.Add(@(($e + 4), 4))
            $type = [BitConverter]::ToUInt32($b, $e + 12)
            $ptr = [BitConverter]::ToUInt32($b, $e + 24)
            if ($type -eq 2 -and $ptr + 24 -le $b.Length -and [BitConverter]::ToUInt32($b, $ptr) -eq 0x53445352) {
                $fields.Add(@(($ptr + 4), 20))
            }
        }
    }
    , $fields
}
# 그 칸을 0 으로 가린 SHA-256. 가릴 칸을 찾지 못하면 $null.
function Get-MaskedHash([string] $path) {
    $b = [IO.File]::ReadAllBytes($path)
    $fields = Get-PeBuildFields $b
    if ($null -eq $fields) { return $null }
    foreach ($f in $fields) { [Array]::Clear($b, [int]$f[0], [int]$f[1]) }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash($b)) } finally { $sha.Dispose() }
}
function Get-TrustedComment([string] $path) {
    @(Get-Content -LiteralPath $path -Encoding UTF8 | Where-Object { $_ -like 'trusted comment: *' }) | Select-Object -First 1
}
$treeRc = Get-Tree $Rc
$treeFinal = Get-Tree $Final
$same = 0
$resigned = 0
$rebuilt = New-Object System.Collections.Generic.List[string]
$manifests = New-Object System.Collections.Generic.List[string]
$hashLines = 0
$diffs = New-Object System.Collections.Generic.List[string]
$notes = New-Object System.Collections.Generic.List[string]
foreach ($k in (@($treeRc.Keys) + @($treeFinal.Keys) | Sort-Object -Unique)) {
    if (-not $treeRc.ContainsKey($k)) { $diffs.Add("정식에만  $k"); continue }
    if (-not $treeFinal.ContainsKey($k)) { $diffs.Add("rc 에만    $k"); continue }
    if ($treeRc[$k] -eq $treeFinal[$k]) { $same++; continue }
    $leaf = Split-Path -Leaf $k
    if ($leaf -eq 'MANIFEST') { $manifests.Add($k); continue }
    if ($leaf -eq 'MANIFEST.minisig') {
        $ca = Get-TrustedComment (Join-Path $Rc $k)
        if ($ca -and $ca -eq (Get-TrustedComment (Join-Path $Final $k))) { $resigned++; $notes.Add("서명만 다시  $k"); continue }
    } elseif ($leaf -like '*.exe') {
        $ha = Get-MaskedHash (Join-Path $Rc $k)
        if ($ha -and $ha -eq (Get-MaskedHash (Join-Path $Final $k))) { $rebuilt.Add($k); $notes.Add("빌드 칸만 다름  $k"); continue }
    }
    $diffs.Add("다름      $k")
}
# MANIFEST — 다른 줄은 모두 '빌드 칸만 다른 실행 파일' 의 해시 줄이어야 한다. 그 해시가 실제 파일과 맞는지는 2 의 서명
# 확인이 잰다.
foreach ($k in $manifests) {
    $dir = Split-Path -Parent $k
    $la = @(Get-Content -LiteralPath (Join-Path $Rc $k) -Encoding UTF8)
    $lb = @(Get-Content -LiteralPath (Join-Path $Final $k) -Encoding UTF8)
    $ok = $la.Count -eq $lb.Count
    for ($i = 0; $ok -and $i -lt $la.Count; $i++) {
        if ($la[$i] -ceq $lb[$i]) { continue }
        $na = $la[$i] -replace '^[0-9a-f]{64}  ', ''
        $nb = $lb[$i] -replace '^[0-9a-f]{64}  ', ''
        $rel = $(if ($dir) { Join-Path $dir ($na -replace '/', '\') } else { $na -replace '/', '\' })
        $ok = ($na -ceq $nb) -and ($na -cne $la[$i]) -and $rebuilt.Contains($rel)
    }
    if ($ok) { $hashLines++; $notes.Add("그 해시 줄만 다름  $k") } else { $diffs.Add("다름      $k") }
}
[IO.File]::WriteAllLines((Join-Path $LogDir 'compare.txt'), @(@($diffs) + @($notes)))
$cmpOk = ($same -gt 0) -and ($diffs.Count -eq 0)
if (-not $cmpOk) { $failed += 'compare' }
Note ('3 rc 와 같은가  {0}  같은 파일 {1} · 서명만 다시 {2} · 빌드 칸만 다른 실행 파일 {3} · 그 해시 줄만 다른 MANIFEST {4} · 다르거나 한쪽에만 {5}' -f
    $(if ($cmpOk) { '통과' } else { '실패' }), $same, $resigned, $rebuilt.Count, $hashLines, $diffs.Count)

Note ("끝 {0} · {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
    $(if ($failed.Count -eq 0) { '모두 통과' } else { '실패: ' + ($failed -join ', ') }))
if ($failed.Count -eq 0) { exit 0 } else { exit 1 }
