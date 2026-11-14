#Requires -Version 5.1
<#
.SYNOPSIS
    remedy-net 의 Apache(코어 1.18.0) — Windows 의 remedy-net.exe 로 이미지 점검의 판정을 잰다(`Invoke-RcBundle.ps1` 이 부른다).

.DESCRIPTION
    리눅스 `testbed/harness/linux/net-apache-verify.sh` 와 **같은 표**(`net-apache-cases.txt`)로 이미지 tar 를 잰다 — tar 는 그
    리눅스 하네스가 `-ImagesDir` 에 저장한 것이다(그래서 리눅스를 먼저 돌린다). 경우마다 종료 코드와, 결과 JSON 에 근거 글이
    있는지 본다. 컨테이너 경우는 리눅스 하네스(docker:dind)가 잰다. 끝 줄 `판정 N/N · 실패 F`.

    실검체는 없다 — 이미지는 배포판 저장소의 Apache · 공식 httpd 와, 그 위에서 설정을 켜거나 모듈에 1바이트를 붙인 꼴이다.
    remedy-net 은 이미지를 실행하지 않는다.

.PARAMETER Bin
    remedy-net.exe — rc 면 꾸러미의 `remedy-net\remedy-net.exe`, PR 전이면 개발 빌드.

.PARAMETER Criteria
    판정 기준 폴더 — rc 면 꾸러미의 `plugins\remedy-net-criteria`, 개발 빌드면 저장소의 것과 `-Anchor`.

.PARAMETER Anchor
    개발 키의 공개키(base64 한 줄) — 개발 빌드만 받는다. 배포 빌드는 박힌 키를 쓴다.

.EXAMPLE
    .\testbed\harness\host\rc\Invoke-NetApache.ps1 -Bin <remedy-net.exe> -Criteria <기준 폴더> -ImagesDir <tar 폴더> -OutDir <폴더>
#>
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $Criteria,
    [Parameter(Mandatory = $true)][string] $ImagesDir,
    [Parameter(Mandatory = $true)][string] $OutDir,
    [string] $Anchor
)
$ErrorActionPreference = 'Continue'
$cases = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'linux\net-apache-cases.txt'
if (-not (Test-Path -LiteralPath $cases)) { throw "표가 없다: $cases" }
if (-not (Test-Path -LiteralPath $Bin)) { throw "remedy-net.exe 가 없다: $Bin" }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$pass = 0
$fail = 0
"remedy-net: " + (& $Bin --version 2>$null | Select-Object -First 1)
foreach ($line in Get-Content -LiteralPath $cases -Encoding UTF8) {
    if ($line -match '^\s*(#|$)') { continue }
    $name, $tar, $want, $why = $line.Trim() -split '\s+', 4
    $path = Join-Path $ImagesDir $tar
    $out = Join-Path $OutDir "out-$name"
    $log = Join-Path $OutDir "image-$name.txt"
    $got = 'tar 없음'
    if (Test-Path -LiteralPath $path) {
        $env:REMEDY_LANG = 'ko'
        $env:REMEDY_NET_CRITERIA = $Criteria
        if ($Anchor) { $env:REMEDY_NET_ANCHOR = $Anchor }
        $argv = @('image', ('"' + $path + '"'), '--runtime', 'apache', '--consent', 'y', '--out-dir', ('"' + $out + '"')) -join ' '
        $p = Start-Process -FilePath $Bin -ArgumentList $argv -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $log -RedirectStandardError "$log.err"
        $got = [string]$p.ExitCode
        Remove-Item Env:REMEDY_LANG, Env:REMEDY_NET_CRITERIA -ErrorAction SilentlyContinue
        if ($Anchor) { Remove-Item Env:REMEDY_NET_ANCHOR -ErrorAction SilentlyContinue }
    }
    $json = Get-ChildItem -LiteralPath $out -Filter '*.json' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    $text = ''
    if ($json) { $text = [IO.File]::ReadAllText($json.FullName, [Text.Encoding]::UTF8) }
    $ok = ($got -eq $want) -and ($why -eq '-' -or $text.Contains($why))
    if ($ok) { $pass++ } else { $fail++ }
    '{0,-6} image {1,-20} 기대 {2} · 받은 {3} · 근거 {4}' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $want, $got, $why
}
'판정 {0}/{1} · 실패 {2}' -f $pass, ($pass + $fail), $fail
