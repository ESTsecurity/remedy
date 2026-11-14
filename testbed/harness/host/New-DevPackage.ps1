#Requires -Version 5.1
<#
.SYNOPSIS
    공개 전 Windows 하네스용 개발 꾸러미 — 일회용 키 · 그 키를 앵커로 박은 remedy.exe · 그 키로 서명한 룰 · `xtask package`.

.DESCRIPTION
    Windows 룰의 하네스(`Invoke-ApacheVerify.ps1 -Package` 등)는 꾸러미 폴더를 받는다. 배포본은 배포 키로 서명된 룰만
    받으므로 PR 전에는 이 개발 꾸러미로 잰다. 정식 파일로 다시 재는 것은 출시 전 필수 점검 ① 이다(docs/긴급-대응.md).
    차례는 `Invoke-MenuVerify.ps1 -Build` 와 같다:

      1  일회용 키쌍(`xtask sign keygen` — 암호는 환경 변수로만 준다. 없으면 TTY 를 기다리며 멈춘다)
      2  그 공개키를 앵커로 박아 `remedy-cli` 릴리스 빌드 — **공유 산출물은 곧바로 되돌린다**(앵커 없는 판)
      3  `-Rule` 의 룰 폴더를 베껴 그 키로 서명
      4  `xtask package` → `<Out>\pkg`(remedy.exe · README.txt · plugins\…). 비밀키는 끝에 지운다

    네트워크 점검 룰(`network:`)은 동반 프로그램이 함께 들어야 해서 다루지 않는다 — 그런 룰은 `Invoke-MenuVerify.ps1 -Build`
    의 차례를 쓴다. 종료 코드: 0 = 꾸러미를 지었다 · 1 = 못 지었다.

.EXAMPLE
    .\testbed\harness\host\New-DevPackage.ps1 -Rule apache-http2-check-windows -Out D:\dl\devpkg
#>
param(
    [Parameter(Mandatory = $true)][string[]] $Rule,
    [Parameter(Mandatory = $true)][string] $Out
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
if (Test-Path -LiteralPath $Out) { throw "이미 있다: $Out — 빈 자리를 준다" }
foreach ($r in $Rule) {
    $y = Join-Path $repo "plugins\$r\plugin.yaml"
    if (-not (Test-Path -LiteralPath $y)) { throw "룰이 없다: plugins\$r" }
    if (Select-String -LiteralPath $y -Pattern '^network:' -Quiet) {
        throw "$r 는 네트워크 점검 룰이다 — 동반 프로그램이 함께 들어야 한다(Invoke-MenuVerify.ps1 -Build 의 차례)"
    }
}
New-Item -ItemType Directory -Path $Out | Out-Null
$Out = (Resolve-Path -LiteralPath $Out).Path
$triple = 'x86_64-pc-windows-msvc'
$bin = Join-Path $repo "target\$triple\release\remedy.exe"
$bak = Join-Path $Out 'remedy.exe.shared-bak'
Push-Location $repo
try {
    $env:REMEDY_SIGN_PASSWORD = 'dev-package-ephemeral'
    & cargo run -q -p xtask -- sign keygen --public-key "$Out\pub.key" --secret-key "$Out\sec.key" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '키 생성 실패' }
    # 앵커는 공개키 파일의 base64 줄이다. 첫 줄은 주석이다.
    $anchor = (Get-Content -LiteralPath "$Out\pub.key")[1].Trim()
    if (Test-Path -LiteralPath $bin) { Copy-Item -LiteralPath $bin -Destination $bak -Force }
    $env:REMEDY_TRUST_ANCHOR = $anchor
    try {
        & cargo build -q --release --target $triple -p remedy-cli
        if ($LASTEXITCODE -ne 0) { throw '앵커 박은 빌드 실패' }
    } finally { $env:REMEDY_TRUST_ANCHOR = $null }
    Copy-Item -LiteralPath $bin -Destination "$Out\remedy.exe" -Force
    # **곧바로 되돌린다** — 다른 하네스 · 캡처가 집는 공유 산출물은 앵커 없는 판이어야 한다.
    if (Test-Path -LiteralPath $bak) { Copy-Item -LiteralPath $bak -Destination $bin -Force; Remove-Item -LiteralPath $bak -Force }
    $args2 = @()
    foreach ($r in $Rule) {
        Copy-Item -LiteralPath (Join-Path $repo "plugins\$r") -Destination "$Out\$r" -Recurse -Force
        & cargo run -q -p xtask -- sign plugin --dir "$Out\$r" --secret-key "$Out\sec.key" --signed-at '2026-11-14T00:00:00Z' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "$r 서명 실패" }
        $args2 += @('--plugin', "$Out\$r")
    }
    & cargo run -q -p xtask -- package @args2 --bin "$Out\remedy.exe" --out "$Out\pkg" --public-key "$Out\pub.key" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '꾸러미 만들기 실패' }
    Remove-Item -LiteralPath "$Out\sec.key" -Force
    "꾸러미: $Out\pkg"
    Get-ChildItem -LiteralPath "$Out\pkg\plugins" -Directory | ForEach-Object { "  룰 $($_.Name)" }
} finally {
    $env:REMEDY_SIGN_PASSWORD = $null
    Pop-Location
}
