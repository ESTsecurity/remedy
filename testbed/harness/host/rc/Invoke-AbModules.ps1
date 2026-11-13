#Requires -Version 5.1
<#
.SYNOPSIS
    rc 묶음 — 다른 프로그램이 실은 PHP 모듈에서 Windows 점검 룰의 A/B(`Invoke-RcBundle.ps1` 이 부른다).

.DESCRIPTION
    랩 VM 의 같은 상태에서 꾸러미 A(지난 공개본)와 B(이번 판)를 차례로 돌린다:
      M0 스냅숏 그대로(스스로를 지키는 제품은 모듈 목록을 거절한다 — 종료 코드가 바뀌면 안 된다)
      M1 PHP 8.3.35(NTS zip)를 C:\inetpub\php83 에 놓기만(돌지도 실리지도 않음)
      M2 M1 + 다른 프로그램(powershell.exe)이 C:\inetpub\php83\php8.dll 을 싣는다
      M3 같은 PHP 를 C:\php(선언한 자리)로 옮기고 같은 식으로 싣는다
    룰: Windows 점검 룰 셋과 evilai-locust(출하하는 제거 룰 · 검사만). M0 · M2 에서는 B 의 artifacts.json 에서 모듈
    목록을 거절당한 프로세스와 PHP 모듈 줄도 읽는다. VM 은 스냅숏 상태에서 시작해야 한다. 되돌리기는 부르는 쪽이 한다.
    summary.txt 의 상태 줄 = `이름 A 코드… B 코드…`.

.EXAMPLE
    .\testbed\harness\host\rc\Invoke-AbModules.ps1 -PackageA <A 폴더> -PackageB <B 폴더> -PhpZip <zip> -OutDir <폴더>
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
$g = 'C:\remedy-lab\rc-modules'
New-Item -ItemType Directory -Force $OutDir | Out-Null

Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
    param($g)
    if (Test-Path $g) { Remove-Item -Recurse -Force $g }
    New-Item -ItemType Directory -Force "$g\a", "$g\b", "$g\screens" | Out-Null
    foreach ($p in 'C:\php', 'C:\inetpub\php83') { if (Test-Path $p) { throw "$p exists - not the snapshot state" } }
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

# B 의 artifacts.json(php2shell 회차)에 든 프로세스: 모듈 목록을 거절당한 것, PHP 핵심 DLL 을 실은 것.
function Read-Artifacts([string] $State) {
    $lines = Invoke-Command -Session $session -ArgumentList $g, $State -ScriptBlock {
        param($g, $state)
        $f = Get-ChildItem -Path "$g\out-$state-b-php2shell-check-windows" -Recurse -Filter 'artifacts.json' | Select-Object -First 1
        if (-not $f) { return "artifacts.json missing" }
        $j = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $procs = @($j.process)
        $withMods = @($procs | Where-Object { @($_.modules).Count -gt 0 })
        $denied = @($procs | Where-Object { $_.modules_denied -eq $true })
        "processes=$($procs.Count) with-modules=$($withMods.Count) modules_denied=$($denied.Count)"
        foreach ($d in $denied) { "  denied: pid $($d.pid) $($d.image_path)" }
        foreach ($p in $procs) {
            $hit = @($p.modules | Where-Object { $_ -match '(?i)\\php[578](ts)?\.dll$' })
            if ($hit.Count -gt 0) { "  php module: pid $($p.pid) $($p.image_path) -> $($hit -join ', ')" }
        }
    }
    foreach ($l in @($lines)) { $rows.Add("$State $l"); "$State $l" }
}

# 주어진 DLL 을 싣고 잠드는, 오래 사는 powershell.exe.
function Start-Host([string] $Dll) {
    Invoke-Command -Session $session -ArgumentList $Dll -ScriptBlock {
        param($dll)
        # -EncodedCommand: Windows PowerShell 5.1 의 Start-Process 는 빈칸 · 따옴표가 든 인자를 감싸 주지 않는다.
        $script = @"
Add-Type -Namespace W -Name K -MemberDefinition '[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr LoadLibraryW(string p);'
`$h = [W.K]::LoadLibraryW('$dll')
if (`$h -eq [IntPtr]::Zero) { exit 3 }
Start-Sleep -Seconds 900
"@
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
        $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-EncodedCommand', $enc) -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 6
        $alive = -not $p.HasExited
        $mods = if ($alive) { @((Get-Process -Id $p.Id).Modules | Where-Object { $_.FileName -like '*php8.dll' } | ForEach-Object { $_.FileName }) -join ', ' } else { "exited $($p.ExitCode)" }
        [pscustomobject]@{ Id = $p.Id; Loaded = $mods }
    }
}

Invoke-AB 'M0'
Read-Artifacts 'M0'
Invoke-Command -Session $session -ArgumentList $g -ScriptBlock { param($g) Expand-Archive "$g\php.zip" -DestinationPath 'C:\inetpub\php83' -Force }
Invoke-AB 'M1'
$hostProc = Start-Host 'C:\inetpub\php83\php8.dll'
$rows.Add("M2 host pid $($hostProc.Id) loaded: $($hostProc.Loaded)")
"M2 host pid $($hostProc.Id) loaded: $($hostProc.Loaded)"
Invoke-AB 'M2'
Read-Artifacts 'M2'
Invoke-Command -Session $session -ArgumentList $hostProc.Id -ScriptBlock { param($id) Stop-Process -Id $id -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
Invoke-Command -Session $session -ScriptBlock { Move-Item 'C:\inetpub\php83' 'C:\php' }
$hostProc = Start-Host 'C:\php\php8.dll'
$rows.Add("M3 host pid $($hostProc.Id) loaded: $($hostProc.Loaded)")
"M3 host pid $($hostProc.Id) loaded: $($hostProc.Loaded)"
Invoke-AB 'M3'
Invoke-Command -Session $session -ArgumentList $hostProc.Id -ScriptBlock { param($id) Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }

Copy-Item -FromSession $session -Path "$g\screens\*" -Destination $OutDir -Force
Remove-PSSession $session
$rows | Set-Content -Path (Join-Path $OutDir 'summary.txt') -Encoding ASCII
"done"
