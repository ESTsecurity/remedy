#Requires -Version 5.1
<#
.SYNOPSIS
    rc 묶음 — 선언 밖 자리와 IIS 에서 Windows 점검 룰 셋의 A/B(`Invoke-RcBundle.ps1` 이 부른다).

.DESCRIPTION
    랩 VM 의 같은 상태에서 꾸러미 A(지난 공개본)와 B(이번 판)를 차례로 돌린다:
      S0 스냅숏 그대로                  S1 PHP 8.3.35 를 C:\inetpub\php83 에 놓기만(설정 · 실행 없음)
      S2 S1 + 거기서 php.exe 가 돈다     S3 IIS + FastCGI/처리기 -> C:\inetpub\php83\php-cgi.exe(돌지 않음)
      S4 S3 + 요청 한 번(php-cgi.exe 가 IIS 아래에서 돈다)
      S5 같은 PHP 를 C:\php(선언한 자리)로 옮기고 IIS 를 거기로
      N1 PHP 를 지우고 Program Files\nodejs 를 치운 뒤 C:\apps\node 에서 node.exe 가 돈다
    VM 은 스냅숏 상태에서 시작해야 한다. 끝난 뒤 되돌리기는 부르는 쪽이 한다.
    summary.txt 의 상태 줄 = `이름 A 코드… B 코드…`(룰 순서: php2shell · php-session · node2shell).

.EXAMPLE
    .\testbed\harness\host\rc\Invoke-AbOutside.ps1 -PackageA <A 폴더> -PackageB <B 폴더> -PhpZip <zip> -NodeExe <node.exe> -OutDir <폴더>
#>
param(
    [Parameter(Mandatory = $true)][string] $PackageA,
    [Parameter(Mandatory = $true)][string] $PackageB,
    [Parameter(Mandatory = $true)][string] $PhpZip,
    [Parameter(Mandatory = $true)][string] $NodeExe,
    [Parameter(Mandatory = $true)][string] $OutDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'VmSession.ps1')
$VmAddress = Resolve-LabValue $null 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $VmAddress 6>$null
$rules = @('php2shell-check-windows', 'php-session-check-windows', 'node2shell-check-windows')
$g = 'C:\remedy-lab\rc-outside'
New-Item -ItemType Directory -Force $OutDir | Out-Null

Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
    param($g)
    if (Test-Path $g) { Remove-Item -Recurse -Force $g }
    New-Item -ItemType Directory -Force "$g\a", "$g\b", "$g\screens" | Out-Null
    foreach ($p in 'C:\php', 'C:\inetpub\php83', 'C:\apps') { if (Test-Path $p) { throw "$p exists - not the snapshot state" } }
}
Copy-Item -ToSession $session -Path (Join-Path $PackageA '*') -Destination "$g\a" -Recurse -Force
Copy-Item -ToSession $session -Path (Join-Path $PackageB '*') -Destination "$g\b" -Recurse -Force
Copy-Item -ToSession $session -Path $PhpZip -Destination "$g\php.zip"
Copy-Item -ToSession $session -Path $NodeExe -Destination "$g\node.exe"

$rows = New-Object System.Collections.Generic.List[string]
function Invoke-AB([string] $State) {
    $codes = Invoke-Command -Session $session -ArgumentList $g, $rules, $State -ScriptBlock {
        param($g, $rules, $state)
        $out = @{}
        foreach ($v in 'a', 'b') {
            $list = @()
            foreach ($r in $rules) {
                $argv = @('scan', '--plugin', "$g\$v\plugins\$r\plugin.yaml", '--out-dir', "$g\out-$state-$v-$r")
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

Invoke-AB 'S0'
Invoke-Command -Session $session -ArgumentList $g -ScriptBlock { param($g) Expand-Archive "$g\php.zip" -DestinationPath 'C:\inetpub\php83' -Force }
Invoke-AB 'S1'
$php = Invoke-Command -Session $session -ScriptBlock {
    (Start-Process -FilePath 'C:\inetpub\php83\php.exe' -ArgumentList @('-r', 'sleep(900);') -WindowStyle Hidden -PassThru).Id
}
Invoke-AB 'S2'
Invoke-Command -Session $session -ArgumentList $php -ScriptBlock { param($id) Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }

# CGI 를 켠 IIS, 그리고 선언 밖 PHP 를 가리키는 FastCGI + 처리기
$iis = Invoke-Command -Session $session -ScriptBlock {
    $t = Get-Date
    $r = Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole, IIS-WebServer, IIS-CGI -All -NoRestart -WarningAction SilentlyContinue
    "iis enable restart-needed={0} seconds={1:N0}" -f $r.RestartNeeded, ((Get-Date) - $t).TotalSeconds
}
$rows.Add("$iis")
$iis
Invoke-Command -Session $session -ScriptBlock {
    $appcmd = Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
    & $appcmd set config /section:system.webServer/fastCgi "/+[fullPath='C:\inetpub\php83\php-cgi.exe']" | Out-Null
    & $appcmd set config /section:system.webServer/handlers "/+[name='PHP_via_FastCGI',path='*.php',verb='*',modules='FastCgiModule',scriptProcessor='C:\inetpub\php83\php-cgi.exe',resourceType='Either']" | Out-Null
    Set-Content -Path 'C:\inetpub\wwwroot\t.php' -Value '<?php echo PHP_VERSION;' -Encoding ASCII
}
$cfg = Invoke-Command -Session $session -ScriptBlock { Select-String -Path "$env:windir\System32\inetsrv\config\applicationHost.config" -Pattern 'php-cgi' | ForEach-Object { $_.Line.Trim() } }
$rows.Add("applicationHost.config php lines: " + (@($cfg) -join ' || '))
Invoke-AB 'S3'
$resp = Invoke-Command -Session $session -ScriptBlock {
    try { (Invoke-WebRequest -Uri 'http://localhost/t.php' -UseBasicParsing -TimeoutSec 60).Content } catch { "request failed: $($_.Exception.Message)" }
}
$running = Invoke-Command -Session $session -ScriptBlock { @(Get-Process php-cgi -ErrorAction SilentlyContinue | ForEach-Object { $_.Path }) -join ', ' }
$rows.Add("request -> $resp ; php-cgi running: $running")
Invoke-AB 'S4'

# 같은 PHP 를 선언한 자리로, IIS 를 거기로
Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
    param($g)
    & iisreset /stop | Out-Null
    Get-Process php-cgi -ErrorAction SilentlyContinue | Stop-Process -Force
    $appcmd = Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
    & $appcmd set config /section:system.webServer/handlers "/-[name='PHP_via_FastCGI']" | Out-Null
    & $appcmd set config /section:system.webServer/fastCgi "/-[fullPath='C:\inetpub\php83\php-cgi.exe']" | Out-Null
    & $appcmd set config /section:system.webServer/fastCgi "/+[fullPath='C:\php\php-cgi.exe']" | Out-Null
    & $appcmd set config /section:system.webServer/handlers "/+[name='PHP_via_FastCGI',path='*.php',verb='*',modules='FastCgiModule',scriptProcessor='C:\php\php-cgi.exe',resourceType='Either']" | Out-Null
    Move-Item 'C:\inetpub\php83' 'C:\php'
    & iisreset /start | Out-Null
}
Invoke-AB 'S5'

# 선언 밖의 node · PHP 없음 · 스냅숏의 Node.js 는 치운다
Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
    param($g)
    & iisreset /stop | Out-Null
    Get-Process php-cgi -ErrorAction SilentlyContinue | Stop-Process -Force
    $appcmd = Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
    & $appcmd set config /section:system.webServer/handlers "/-[name='PHP_via_FastCGI']" | Out-Null
    & $appcmd set config /section:system.webServer/fastCgi "/-[fullPath='C:\php\php-cgi.exe']" | Out-Null
    Remove-Item -Recurse -Force 'C:\php'
    Move-Item 'C:\Program Files\nodejs' 'C:\Program Files\nodejs.moved'
    New-Item -ItemType Directory -Force 'C:\apps\node' | Out-Null
    Copy-Item "$g\node.exe" 'C:\apps\node\node.exe'
}
$node = Invoke-Command -Session $session -ScriptBlock {
    (Start-Process -FilePath 'C:\apps\node\node.exe' -ArgumentList @('-e', 'setTimeout(function(){},900000)') -WindowStyle Hidden -PassThru).Id
}
Invoke-AB 'N1'
Invoke-Command -Session $session -ArgumentList $node -ScriptBlock { param($id) Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }

Copy-Item -FromSession $session -Path "$g\screens\*" -Destination $OutDir -Force
Remove-PSSession $session
$rows | Set-Content -Path (Join-Path $OutDir 'summary.txt') -Encoding ASCII
"done"
