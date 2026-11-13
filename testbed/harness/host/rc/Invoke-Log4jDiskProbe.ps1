#Requires -Version 5.1
<#
.SYNOPSIS
    rc 묶음 — 랩 VM 의 깨끗한 C: 전체를 log4j 룰로 한 번 읽기만 하는 검사(`Invoke-RcBundle.ps1` 이 부른다).

.DESCRIPTION
    C: 전체를 걷는 데 걸리는 시간, 관리자도 열지 못하는 폴더(하나하나가 '확인 필요' 가 된다), 찾은 것을 남긴다. 깨끗한
    랩이므로 종료 코드는 0 이어야 한다(`status.txt` 의 `exit=`). 저장소의 랩 하네스 도구(랩 설정의 주소 · DPAPI 자격 증명 ·
    관리자 확인한 세션)를 쓴다.

.PARAMETER Rule
    꾸러미의 서명된 룰 폴더(plugin.yaml · MANIFEST · 서명) — 통째로 옮긴다. plugin.yaml 하나여도 된다.

.EXAMPLE
    .\testbed\harness\host\rc\Invoke-Log4jDiskProbe.ps1 -Bin <remedy.exe> -Rule <plugins\log4j-check> -OutDir <폴더>
#>
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $Rule,
    [Parameter(Mandatory = $true)][string] $OutDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'VmSession.ps1')

$addr = Resolve-LabValue $null 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $addr
try {
    $g = 'C:\remedy-probe'
    Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        if (Test-Path $g) { Remove-Item $g -Recurse -Force }
        New-Item -ItemType Directory -Force (Join-Path $g 'plugins\log4j-check') | Out-Null
    }
    Copy-GuestFile -Session $session -Source $Bin -Destination "$g\remedy.exe"
    if (Test-Path -LiteralPath $Rule -PathType Container) {
        foreach ($f in Get-ChildItem -LiteralPath $Rule -File) {
            Copy-GuestFile -Session $session -Source $f.FullName -Destination ("$g\plugins\log4j-check\" + $f.Name)
        }
    } else {
        Copy-GuestFile -Session $session -Source $Rule -Destination "$g\plugins\log4j-check\plugin.yaml"
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g `
        -Arguments @('scan', '--plugin', "$g\plugins\log4j-check\plugin.yaml", '--out-dir', "$g\out")
    $sw.Stop()

    New-Item -ItemType Directory -Force $OutDir | Out-Null
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText((Join-Path $OutDir 'stdout.txt'), [string]$r.out, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $OutDir 'stderr.txt'), [string]$r.err, $utf8)
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
    Remove-PSSession $session
}
