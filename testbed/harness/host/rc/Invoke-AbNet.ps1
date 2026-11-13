#Requires -Version 5.1
<#
.SYNOPSIS
    rc 묶음 — 동반 프로그램 remedy-net 의 A/B 를 이 기계(Windows)에서(`Invoke-RcBundle.ps1` 이 부른다).

.DESCRIPTION
    지난 공개본(A)과 이번 판(B)을 나란히:
      url       - 루프백 모의 서버(`testbed/harness/linux/rc/net-mock.py` · python)가 헤더 판 넷을 알린다
      image     - 저장한 이미지 tar(리눅스 `rc/save-images.sh` 가 만든다)
      container - Docker Desktop 에 띄운, 런타임이 계속 도는 컨테이너 둘(여기서 띄우고 끝에 지운다)
    경우마다 종료 코드와 화면 · 결과 JSON(버전 · 시각 · 회차 · 경로를 가린 뒤)이 같아야 한다.
    summary.txt: 경우마다 `이름 A=코드 B=코드 screen-diff=… json-diff=… same|DIFFERENT`, 끝 줄 `same N - different M`.

.EXAMPLE
    .\testbed\harness\host\rc\Invoke-AbNet.ps1 -PackageA <A 폴더> -PackageB <B 폴더> -ImagesDir <이미지 tar 폴더> -OutDir <폴더>
#>
param(
    [Parameter(Mandatory = $true)][string] $PackageA,
    [Parameter(Mandatory = $true)][string] $PackageB,
    [Parameter(Mandatory = $true)][string] $ImagesDir,
    [Parameter(Mandatory = $true)][string] $OutDir
)
$ErrorActionPreference = 'Continue'
$mockPy = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'linux\rc\net-mock.py'
if (-not (Test-Path -LiteralPath $mockPy)) { throw "net-mock.py 가 없다: $mockPy" }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$summary = Join-Path $OutDir 'summary.txt'
Set-Content -Path $summary -Value '' -Encoding utf8
$script:same = 0
$script:diff = 0
function Note([string] $line) { $line; Add-Content -Path $summary -Value $line -Encoding utf8 }
function Mask([string] $text) {
    $t = $text -replace '1\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?', 'V'
    $t = $t -replace '[0-9]{8}T[0-9]{6}Z(-[0-9]+)?', 'T'
    $t = $t -replace '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?', 'T'
    $t = $t -replace 'run-[0-9]+-[0-9a-f]+-[0-9a-f]+', 'RUN'
    $t = $t -replace 'remedy-net-(url|image|container)-[^ ",\\/]*\.json', 'R.json'
    $t = $t -replace '(out-)?[a-z]+-[ab]-', 'X-'
    $t = $t -replace '"[a-z_]*(ms|seconds|elapsed)[a-z_]*": *[0-9.]+', '"D": 0'
    $t = $t -replace '"run_id": *"[^"]*"', '"run_id": "R"'
    $t = $t -replace ([string][char]0xBC1B + [char]0xC740 + ' ' + [char]0xC591 + ' [0-9.]+ ?[KMG]?i?B'), 'N'
    $t = $t -replace ('[0-9]+(\.[0-9]+)? ?(ms|s|' + [char]0xCD08 + ')\b'), 'D'
    $t
}
function Json([string] $dir) {
    if (-not (Test-Path $dir)) { return '' }
    (Get-ChildItem $dir -Recurse -File -Filter '*.json' | Sort-Object FullName | ForEach-Object {
            [IO.File]::ReadAllText($_.FullName) }) -join "`n"
}
function Run([string] $pkg, [string[]] $argv, [string] $log) {
    $net = Join-Path $pkg 'remedy-net\remedy-net.exe'
    $env:REMEDY_LANG = 'ko'
    $p = Start-Process -FilePath $net -ArgumentList (($argv | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ') `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput $log -RedirectStandardError "$log.err"
    Remove-Item Env:REMEDY_LANG
    $p.ExitCode
}
function Compare-Case([string] $name, [string[]] $argvA, [string[]] $argvB, [string] $outA, [string] $outB) {
    $la = Join-Path $OutDir "$name-a.txt"
    $lb = Join-Path $OutDir "$name-b.txt"
    $ra = Run $PackageA $argvA $la
    $rb = Run $PackageB $argvB $lb
    $sa = (Mask ([IO.File]::ReadAllText($la) + [IO.File]::ReadAllText("$la.err"))) -split "`n"
    $sb = (Mask ([IO.File]::ReadAllText($lb) + [IO.File]::ReadAllText("$lb.err"))) -split "`n"
    $sd = @(Compare-Object $sa $sb -SyncWindow 0).Count
    $ja = (Mask (Json $outA)) -split ','
    $jb = (Mask (Json $outB)) -split ','
    $jd = @(Compare-Object $ja $jb -SyncWindow 0).Count
    $ok = ($ra -eq $rb) -and $sd -eq 0 -and $jd -eq 0
    if ($ok) { $script:same++ } else { $script:diff++ }
    Note ('{0,-34} A={1} B={2} screen-diff={3} json-diff={4} {5}' -f $name, $ra, $rb, $sd, $jd, $(if ($ok) { 'same' } else { 'DIFFERENT' }))
}
Note ("A: " + (& (Join-Path $PackageA 'remedy-net\remedy-net.exe') --version 2>$null | Select-Object -Last 1))
Note ("B: " + (& (Join-Path $PackageB 'remedy-net\remedy-net.exe') --version 2>$null | Select-Object -Last 1))

# -- url --
$port = 18370
foreach ($v in '8.3.38', '8.3.2', '8.2.35-1~deb12u1', '8.2.32-1~deb12u1') {
    $port++
    # 5.1 의 Start-Process 는 빈칸이 든 인자를 감싸 주지 않는다 — 경로는 따옴표로
    $mock = Start-Process -FilePath python -ArgumentList @('-I', '-X', 'utf8', ('"' + $mockPy + '"'), $port, $v) -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 700
    $oa = Join-Path $OutDir "out-url-a-$port"
    $ob = Join-Path $OutDir "out-url-b-$port"
    Compare-Case "url-$v" @('url', '--url', "http://127.0.0.1:$port/", '--consent', 'y', '--out-dir', $oa) `
        @('url', '--url', "http://127.0.0.1:$port/", '--consent', 'y', '--out-dir', $ob) $oa $ob
    Stop-Process -Id $mock.Id -Force -ErrorAction SilentlyContinue
}

# -- image --
foreach ($tar in Get-ChildItem $ImagesDir -Filter '*.tar' | Sort-Object Name) {
    $n = $tar.BaseName
    $oa = Join-Path $OutDir "out-image-a-$n"
    $ob = Join-Path $OutDir "out-image-b-$n"
    Compare-Case "image-$n" @('image', $tar.FullName, '--consent', 'y', '--out-dir', $oa) `
        @('image', $tar.FullName, '--consent', 'y', '--out-dir', $ob) $oa $ob
}

# -- container (Docker Desktop) --
$php = (& docker run -d php:8.3.35-cli php -r 'sleep(600);' 2>$null | Select-Object -Last 1)
$node = (& docker run -d node:22.18.0-bookworm-slim node -e 'setTimeout(function(){}, 600000)' 2>$null | Select-Object -Last 1)
foreach ($pair in @(@('php', $php), @('node', $node))) {
    $name, $id = $pair
    if (-not $id) { Note "container-$name : did not start"; $script:diff++; continue }
    $oa = Join-Path $OutDir "out-container-a-$name"
    $ob = Join-Path $OutDir "out-container-b-$name"
    Compare-Case "container-$name" @('container', $id, '--consent', 'y', '--out-dir', $oa) `
        @('container', $id, '--consent', 'y', '--out-dir', $ob) $oa $ob
}
& docker rm -f $php $node 2>$null | Out-Null
Note ("same {0} - different {1}" -f $script:same, $script:diff)
