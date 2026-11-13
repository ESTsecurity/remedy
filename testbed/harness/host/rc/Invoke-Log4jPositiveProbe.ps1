#Requires -Version 5.1
<#
.SYNOPSIS
    rc 묶음 — 랩 VM 에 log4j 시료를 놓고 C: 전체를 log4j 룰로 잰 뒤 놓은 것을 다시 치운다(`Invoke-RcBundle.ps1`).

.DESCRIPTION
    C:\l4jtest 아래에 놓는 것: 공식 2.14.1 그대로 · 고친 판 2.17.1(깨끗해야 한다) · 엉뚱한 이름의 2.14.1 을 담은 압축한
    war · Spring Boot jar · 300자가 넘는 폴더 사슬 아래 이름 바꾼 2.14.1 · BMP 밖 글자(이모지 · CJK 확장 B)가 든 폴더와
    파일 이름의 2.14.1. **실검체는 없다** — 시료는 Maven Central 의 공식 jar 와 그것을 꾸린 것이다
    (`testbed/harness/linux/fixtures/log4j/build-cases.py` 의 c15 · c07). 아무것도 실행하지 않는다.
    기대: 종료 코드 2 · 놓은 취약한 것 다섯이 모두 화면에 · 고친 판은 화면에 없다.

.EXAMPLE
    .\testbed\harness\host\rc\Invoke-Log4jPositiveProbe.ps1 -Bin <remedy.exe> -Rule <plugins\log4j-check> `
        -Core <log4j-core-2.14.1.jar> -Fixed <log4j-core-2.17.1.jar> -War <app.war> -Boot <app.jar> -OutDir <폴더>
#>
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $Rule,
    [Parameter(Mandatory = $true)][string] $Core,
    [Parameter(Mandatory = $true)][string] $Fixed,
    [Parameter(Mandatory = $true)][string] $War,
    [Parameter(Mandatory = $true)][string] $Boot,
    [Parameter(Mandatory = $true)][string] $OutDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'VmSession.ps1')

$addr = Resolve-LabValue $null 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $addr
$g = 'C:\remedy-probe'
$t = 'C:\l4jtest'
try {
    Invoke-Command -Session $session -ArgumentList $g, $t -ScriptBlock {
        param($g, $t)
        foreach ($d in @($g, $t)) {
            if (Test-Path -LiteralPath $d) { [System.IO.Directory]::Delete('\\?\' + $d, $true) }
        }
        New-Item -ItemType Directory -Force (Join-Path $g 'plugins\log4j-check') | Out-Null
        New-Item -ItemType Directory -Force (Join-Path $t 'in') | Out-Null
    }
    Copy-GuestFile -Session $session -Source $Bin -Destination "$g\remedy.exe"
    if (Test-Path -LiteralPath $Rule -PathType Container) {
        foreach ($f in Get-ChildItem -LiteralPath $Rule -File) {
            Copy-GuestFile -Session $session -Source $f.FullName -Destination ("$g\plugins\log4j-check\" + $f.Name)
        }
    } else {
        Copy-GuestFile -Session $session -Source $Rule -Destination "$g\plugins\log4j-check\plugin.yaml"
    }
    Copy-GuestFile -Session $session -Source $Core -Destination "$t\in\core.jar"
    Copy-GuestFile -Session $session -Source $Fixed -Destination "$t\in\fixed.jar"
    Copy-GuestFile -Session $session -Source $War -Destination "$t\in\app.war"
    Copy-GuestFile -Session $session -Source $Boot -Destination "$t\in\boot.jar"

    $placed = Invoke-Command -Session $session -ArgumentList $t -ScriptBlock {
        param($t)
        $in = Join-Path $t 'in'
        $out = New-Object System.Collections.Generic.List[string]
        function Put([string]$src, [string[]]$parts, [string]$name) {
            $d = $t
            foreach ($p in $parts) { $d = $d + '\' + $p }
            [void][System.IO.Directory]::CreateDirectory('\\?\' + $d)
            $dst = $d + '\' + $name
            [System.IO.File]::Copy((Join-Path $in $src), '\\?\' + $dst, $true)
            $out.Add($dst)
        }
        Put 'core.jar' @('plain') 'log4j-core-2.14.1.jar'
        Put 'fixed.jar' @('fixed') 'log4j-core-2.17.1.jar'
        Put 'app.war' @('war') 'app.war'
        Put 'boot.jar' @('boot') 'app.jar'
        $long = @()
        foreach ($i in 1..6) { $long += ('d' * 50) }
        Put 'core.jar' $long 'renamed-lib.jar'
        $wide = [char]::ConvertFromUtf32(0x1F600) + [char]::ConvertFromUtf32(0x20000)
        Put 'core.jar' @("x$wide") "lib$wide.jar"
        [System.IO.Directory]::Delete('\\?\' + $in, $true)
        $out
    }
    Write-Host ("placed {0} files; longest path {1} characters" -f @($placed).Count, (@($placed) | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum)

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g `
        -Arguments @('scan', '--plugin', "$g\plugins\log4j-check\plugin.yaml", '--out-dir', "$g\out")
    $sw.Stop()

    New-Item -ItemType Directory -Force $OutDir | Out-Null
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText((Join-Path $OutDir 'stdout.txt'), [string]$r.out, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $OutDir 'stderr.txt'), [string]$r.err, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $OutDir 'placed.txt'), (@($placed) -join "`n"), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $OutDir 'status.txt'),
        ("exit={0} seconds={1}" -f $r.exit, [int]$sw.Elapsed.TotalSeconds), $utf8)
    $files = Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        Get-ChildItem (Join-Path $g 'out') -Recurse -File -Include 'scan.json', 'artifacts.json' |
            ForEach-Object { $_.FullName }
    }
    foreach ($f in $files) {
        Copy-Item -FromSession $session -Path $f -Destination (Join-Path $OutDir (Split-Path -Leaf $f)) -Force
    }
    Write-Host ("exit={0} seconds={1} fetched={2}" -f $r.exit, [int]$sw.Elapsed.TotalSeconds, @($files).Count)
}
finally {
    # 놓은 jar 는 이 도구의 것이다 — 랩 VM 이 처음 같도록 다시 치운다.
    Invoke-Command -Session $session -ArgumentList $t -ScriptBlock {
        param($t)
        if (Test-Path -LiteralPath $t) { [System.IO.Directory]::Delete('\\?\' + $t, $true) }
    }
    Remove-PSSession $session
}
