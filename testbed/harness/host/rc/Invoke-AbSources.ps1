#Requires -Version 5.1
<#
.SYNOPSIS
    rc 묶음 — 서비스 · Apache 설정 · 레지스트리가 가리키는 PHP · Node 에서 Windows 점검 룰의 A/B(`Invoke-RcBundle.ps1`).

.DESCRIPTION
    랩 VM 의 같은 상태에서 꾸러미 A(지난 공개본)와 B(이번 판)를 차례로 돌린다. PHP 도 Node 도 띄우지 않는다:
      S0 스냅숏 그대로
      W1 PHP 8.3.35 를 C:\inetpub\php83 에 놓고 ImagePath 가 그 php-cgi.exe 인 서비스(만들기만 · 시작 안 함)
      W2 서비스를 지우고 C:\Apache24\conf\httpd.conf 에 C:/inetpub/php83/php8apache2_4.dll 을 싣는 LoadModule 줄
      W3 같은 줄이 C:/php(선언한 자리)를 가리킨다
      W4 httpd.conf 를 지우고 Program Files\nodejs 를 치운 뒤 HKLM\SOFTWARE\Node.js InstallPath = D:\nodejs\
      W5 InstallPath 를 Program Files 로 되돌리고 ImagePath 가 C:\apps\node\node.exe 인 서비스(만들기만)
    룰: Windows 점검 룰 셋과 evilai-locust(검사만). VM 은 스냅숏 상태에서 시작해야 한다. 되돌리기는 부르는 쪽이 한다.
    summary.txt 의 상태 줄 = `이름 A 코드… B 코드…`.

.EXAMPLE
    .\testbed\harness\host\rc\Invoke-AbSources.ps1 -PackageA <A 폴더> -PackageB <B 폴더> -PhpZip <zip> -OutDir <폴더>
#>
param(
    [Parameter(Mandatory = $true)][string] $PackageA,
    [Parameter(Mandatory = $true)][string] $PackageB,
    [Parameter(Mandatory = $true)][string] $PhpZip,
    [Parameter(Mandatory = $true)][string] $OutDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'VmSession.ps1')
$VmAddress = Resolve-LabValue $null 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $VmAddress 6>$null
$rules = @('php2shell-check-windows', 'php-session-check-windows', 'node2shell-check-windows', 'evilai-locust')
$g = 'C:\remedy-lab\rc-sources'
New-Item -ItemType Directory -Force $OutDir | Out-Null

Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
    param($g)
    if (Test-Path $g) { Remove-Item -Recurse -Force $g }
    New-Item -ItemType Directory -Force "$g\a", "$g\b", "$g\screens" | Out-Null
    foreach ($p in 'C:\php', 'C:\inetpub\php83', 'C:\Apache24', 'C:\apps') { if (Test-Path $p) { throw "$p exists - not the snapshot state" } }
}
Copy-Item -ToSession $session -Path (Join-Path $PackageA '*') -Destination "$g\a" -Recurse -Force
Copy-Item -ToSession $session -Path (Join-Path $PackageB '*') -Destination "$g\b" -Recurse -Force
Copy-Item -ToSession $session -Path $PhpZip -Destination "$g\php.zip"

$rows = New-Object System.Collections.Generic.List[string]
function Invoke-AB([string] $State) {
    $codes = Invoke-Command -Session $session -ArgumentList $g, $rules, $State -ScriptBlock {
        param($g, $rules, $state)
        $out = @{}
        foreach ($v in 'a', 'b') {
            $list = @()
            foreach ($r in $rules) {
                $argv = @('scan', '--plugin', "$g\$v\plugins\$r\plugin.yaml", '--out-dir', "$g\out-$state-$v-$r", '--lang', 'ko')
                $p = Start-Process -FilePath "$g\$v\remedy.exe" -ArgumentList $argv -NoNewWindow -Wait -PassThru `
                    -RedirectStandardOutput "$g\screens\$state-$v-$r.txt" -RedirectStandardError "$g\screens\$state-$v-$r.err.txt"
                $list += $p.ExitCode
            }
            $out[$v] = $list -join ' '
        }
        $out
    }
    $line = "{0,-4} A {1}   B {2}" -f $State, $codes['a'], $codes['b']
    $rows.Add($line)
    $line
}
function Note([string] $Text) { $rows.Add($Text); $Text }

Invoke-AB 'S0'

Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
    param($g)
    Expand-Archive "$g\php.zip" -DestinationPath 'C:\inetpub\php83' -Force
    # sc.exe 가 아니라 New-Service: Windows PowerShell 5.1 은 네이티브 인자 안쪽의 따옴표를 떨군다.
    New-Service -Name 'remedy-lab-phpcgi' -BinaryPathName '"C:\inetpub\php83\php-cgi.exe" -b 127.0.0.1:9000' -StartupType Manual | Out-Null
}
Note ("W1 service: " + (Invoke-Command -Session $session -ScriptBlock { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\remedy-lab-phpcgi').ImagePath }))
Invoke-AB 'W1'

Invoke-Command -Session $session -ScriptBlock {
    & sc.exe delete remedy-lab-phpcgi | Out-Null
    New-Item -ItemType Directory -Force 'C:\Apache24\conf' | Out-Null
    [IO.File]::WriteAllText('C:\Apache24\conf\httpd.conf', "ServerRoot `"C:/Apache24`"`r`nLoadModule php_module `"C:/inetpub/php83/php8apache2_4.dll`"`r`nPHPIniDir `"C:/inetpub/php83`"`r`n")
}
Invoke-AB 'W2'

Invoke-Command -Session $session -ScriptBlock {
    [IO.File]::WriteAllText('C:\Apache24\conf\httpd.conf', "ServerRoot `"C:/Apache24`"`r`nLoadModule php_module `"C:/php/php8apache2_4.dll`"`r`nPHPIniDir `"C:/php`"`r`n")
}
Invoke-AB 'W3'

Invoke-Command -Session $session -ScriptBlock {
    Remove-Item -Recurse -Force 'C:\Apache24'
    Move-Item 'C:\Program Files\nodejs' 'C:\Program Files\nodejs.moved'
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Node.js' -Name 'InstallPath' -Value 'D:\nodejs\'
}
Note ("W4 InstallPath: " + (Invoke-Command -Session $session -ScriptBlock { (Get-ItemProperty 'HKLM:\SOFTWARE\Node.js').InstallPath }))
Invoke-AB 'W4'

Invoke-Command -Session $session -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Node.js' -Name 'InstallPath' -Value 'C:\Program Files\nodejs\'
    New-Service -Name 'remedy-lab-node' -BinaryPathName '"C:\apps\node\node.exe" C:\apps\app.js' -StartupType Manual | Out-Null
}
Note ("W5 service: " + (Invoke-Command -Session $session -ScriptBlock { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\remedy-lab-node').ImagePath }))
Invoke-AB 'W5'
Invoke-Command -Session $session -ScriptBlock { & sc.exe delete remedy-lab-node | Out-Null }

Copy-Item -FromSession $session -Path "$g\screens\*" -Destination $OutDir -Force
Remove-PSSession $session
$rows | Set-Content -Path (Join-Path $OutDir 'summary.txt') -Encoding ASCII
"done"
