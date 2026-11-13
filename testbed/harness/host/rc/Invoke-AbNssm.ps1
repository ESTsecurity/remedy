#Requires -Version 5.1
<#
.SYNOPSIS
    rc 묶음 — NSSM 서비스가 가리키는 PHP · Node 에서 Windows 점검 룰의 A/B(`Invoke-RcBundle.ps1` 이 부른다).

.DESCRIPTION
    랩 VM 의 같은 상태에서 꾸러미 A(지난 공개본)와 B(이번 판)를 차례로 돌린다. PHP · Node · NSSM 을 아무것도 띄우지
    않는다 — ImagePath 가 nssm.exe 경로이고 Parameters 키에 NSSM 이 쓰는 Application 값이 든 서비스를 만들기만 한다.
      S0 스냅숏 그대로(Program Files 의 Node.js — node2shell 2)
      N0 Program Files\nodejs 를 치운다(node2shell 의 새 줄이 보이게)
      N1 NSSM 서비스 · Application = C:\inetpub\php83\php-cgi.exe(선언 밖)
      N2 Application = C:\apps\node\node.exe(선언 밖)
      N3 Application = %SystemDrive%\php\php-cgi.exe(선언한 자리 · 펼치지 않은 꼴)
      N4 Application = php-cgi.exe(이름만 — AppDirectory 로 찾는다)
      N5 Application = "C:\Program Files\nodejs\node.exe"(선언한 자리 · 따옴표)
    룰: Windows 점검 룰 셋과 evilai-locust(검사만). 회차마다 시간을 잰다. VM 은 스냅숏 상태에서 시작해야 한다. 되돌리기는
    부르는 쪽이 한다. summary.txt 의 상태 줄 = `이름 A 코드… B 코드…      ms A … / B …`.

.EXAMPLE
    .\testbed\harness\host\rc\Invoke-AbNssm.ps1 -PackageA <A 폴더> -PackageB <B 폴더> -OutDir <폴더>
#>
param(
    [Parameter(Mandatory = $true)][string] $PackageA,
    [Parameter(Mandatory = $true)][string] $PackageB,
    [Parameter(Mandatory = $true)][string] $OutDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'VmSession.ps1')
$VmAddress = Resolve-LabValue $null 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $VmAddress 6>$null
$rules = @('php2shell-check-windows', 'php-session-check-windows', 'node2shell-check-windows', 'evilai-locust')
$g = 'C:\remedy-lab\rc-nssm'
$svc = 'remedy-lab-nssm'
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
New-Item -ItemType Directory -Force $OutDir | Out-Null

Invoke-Command -Session $session -ArgumentList $g, $key -ScriptBlock {
    param($g, $key)
    if (Test-Path $g) { Remove-Item -Recurse -Force $g }
    New-Item -ItemType Directory -Force "$g\a", "$g\b", "$g\screens" | Out-Null
    foreach ($p in 'C:\php', 'C:\inetpub\php83', 'C:\apps', $key) { if (Test-Path $p) { throw "$p exists - not the snapshot state" } }
    if (-not (Test-Path 'C:\Program Files\nodejs\node.exe')) { throw 'Program Files\nodejs\node.exe missing - not the snapshot state' }
}
Copy-Item -ToSession $session -Path (Join-Path $PackageA '*') -Destination "$g\a" -Recurse -Force
Copy-Item -ToSession $session -Path (Join-Path $PackageB '*') -Destination "$g\b" -Recurse -Force

$rows = New-Object System.Collections.Generic.List[string]
function Invoke-AB([string] $State) {
    $r = Invoke-Command -Session $session -ArgumentList $g, $rules, $State -ScriptBlock {
        param($g, $rules, $state)
        $out = @{}
        foreach ($v in 'a', 'b') {
            $codes = @(); $ms = @()
            foreach ($r in $rules) {
                $argv = @('scan', '--plugin', "$g\$v\plugins\$r\plugin.yaml", '--out-dir', "$g\out-$state-$v-$r", '--lang', 'ko')
                $t = [Diagnostics.Stopwatch]::StartNew()
                $p = Start-Process -FilePath "$g\$v\remedy.exe" -ArgumentList $argv -NoNewWindow -Wait -PassThru `
                    -RedirectStandardOutput "$g\screens\$state-$v-$r.txt" -RedirectStandardError "$g\screens\$state-$v-$r.err.txt"
                $t.Stop()
                $codes += $p.ExitCode; $ms += $t.ElapsedMilliseconds
            }
            $out[$v] = $codes -join ' '
            $out["$v-ms"] = $ms -join ' '
        }
        $out
    }
    $line = "{0,-4} A {1}   B {2}      ms A {3} / B {4}" -f $State, $r['a'], $r['b'], $r['a-ms'], $r['b-ms']
    $rows.Add($line)
    $line
}
function Note([string] $Text) { $rows.Add($Text); $Text }
function Set-App([string] $Value) {
    Invoke-Command -Session $session -ArgumentList $key, $Value -ScriptBlock {
        param($key, $value)
        Set-ItemProperty -Path "$key\Parameters" -Name 'Application' -Value $value
    }
    Note ("   Application = " + (Invoke-Command -Session $session -ArgumentList $key -ScriptBlock {
                param($key) (Get-Item "$key\Parameters").GetValue('Application', $null, 'DoNotExpandEnvironmentNames') }))
}

Invoke-AB 'S0'

Invoke-Command -Session $session -ScriptBlock { Move-Item 'C:\Program Files\nodejs' 'C:\Program Files\nodejs.moved' }
Invoke-AB 'N0'

Invoke-Command -Session $session -ArgumentList $svc, $key -ScriptBlock {
    param($svc, $key)
    # sc.exe 가 아니라 New-Service: Windows PowerShell 5.1 은 네이티브 인자 안쪽의 따옴표를 떨군다.
    New-Service -Name $svc -BinaryPathName '"C:\tools\nssm\nssm.exe"' -StartupType Manual | Out-Null
    New-Item -Path "$key\Parameters" -Force | Out-Null
    New-ItemProperty -Path "$key\Parameters" -Name 'Application' -PropertyType ExpandString -Value 'C:\inetpub\php83\php-cgi.exe' | Out-Null
    New-ItemProperty -Path "$key\Parameters" -Name 'AppParameters' -PropertyType ExpandString -Value '-b 127.0.0.1:9001' | Out-Null
    New-ItemProperty -Path "$key\Parameters" -Name 'AppDirectory' -PropertyType ExpandString -Value 'C:\inetpub\php83' | Out-Null
}
Note ("N1 ImagePath = " + (Invoke-Command -Session $session -ArgumentList $key -ScriptBlock { param($key) (Get-ItemProperty $key).ImagePath }))
Invoke-AB 'N1'

Set-App 'C:\apps\node\node.exe'
Invoke-AB 'N2'

Set-App '%SystemDrive%\php\php-cgi.exe'
Invoke-AB 'N3'

Set-App 'php-cgi.exe'
Invoke-AB 'N4'

Set-App '"C:\Program Files\nodejs\node.exe"'
Invoke-AB 'N5'

Invoke-Command -Session $session -ArgumentList $svc -ScriptBlock {
    param($svc)
    & sc.exe delete $svc | Out-Null
    Move-Item 'C:\Program Files\nodejs.moved' 'C:\Program Files\nodejs'
}
Copy-Item -FromSession $session -Path "$g\screens\*" -Destination $OutDir -Force
Remove-PSSession $session
$rows | Set-Content -Path (Join-Path $OutDir 'summary.txt') -Encoding ASCII
"done"
