#Requires -Version 5.1
<#
.SYNOPSIS
    rc 묶음 — 랩 VM 에서 꾸러미 하나의 검사 시간(`Invoke-RcBundle.ps1` 이 A · B 로 한 번씩 부른다).

.DESCRIPTION
    프로세스 모듈을 읽지 않는 룰(evilai-locust)과 읽는 룰(php2shell-check-windows)을 두 번씩 `--verbose` 로 돌려, 시간
    줄과 artifacts.json 의 모듈 수를 적는다. 게스트에서는 제 작업 폴더만 쓰고 끝에 지운다. 줄마다 `exit=코드` 가 있다.

.EXAMPLE
    .\testbed\harness\host\rc\Measure-ScanTiming.ps1 -Package D:\dl\x\remedy-windows-x64
#>
param([Parameter(Mandatory = $true)][string] $Package)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'VmSession.ps1')
$VmAddress = Resolve-LabValue $null 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $VmAddress 6>$null
$g = 'C:\remedy-lab\rc-timing'
Invoke-Command -Session $session -ArgumentList $g -ScriptBlock { param($g) if (Test-Path $g) { Remove-Item -Recurse -Force $g }; New-Item -ItemType Directory -Force $g | Out-Null }
Copy-Item -ToSession $session -Path (Join-Path $Package '*') -Destination $g -Recurse -Force
Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
    param($g)
    # 시간 줄의 한국어 낱말 — 게스트 쪽 인코딩에 기대지 않게 글자 코드로 짓는다
    $word = [string][char]0xAC80 + [char]0xC0AC + ' ' + [char]0xC2DC + [char]0xAC04
    $i = 0
    foreach ($r in 'evilai-locust', 'php2shell-check-windows', 'evilai-locust', 'php2shell-check-windows') {
        $i++
        $p = Start-Process -FilePath "$g\remedy.exe" -ArgumentList @('scan', '--plugin', "$g\plugins\$r\plugin.yaml", '--out-dir', "$g\out-$i", '--verbose', '--lang', 'ko') `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$g\o$i.txt" -RedirectStandardError "$g\e$i.txt"
        $line = Get-Content "$g\o$i.txt", "$g\e$i.txt" -Encoding UTF8 | Where-Object { $_ -match [regex]::Escape($word) } | Select-Object -First 1
        $j = Get-ChildItem "$g\out-$i" -Recurse -Filter artifacts.json | Select-Object -First 1
        $n = if ($j) {
            $a = Get-Content $j.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            '{0} procs, {1} with modules, {2} denied' -f @($a.process).Count, @($a.process | Where-Object { @($_.modules).Count -gt 0 }).Count, @($a.process | Where-Object { $_.modules_denied }).Count
        } else { 'no artifacts' }
        '{0,-26} exit={1}  {2}  [{3}]' -f $r, $p.ExitCode, $line, $n
    }
    Remove-Item -Recurse -Force $g
}
Remove-PSSession $session
