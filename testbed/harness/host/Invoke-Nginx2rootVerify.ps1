#Requires -Version 5.1
# 룰: nginx2root-check-windows — 묶어 낸 출시의 필수 점검 ① 이 이 하네스를 찾아 아래 입력으로 돌린다(Invoke-RuleHarness.ps1 · -Package · -LogDir)
# 입력: -NginxZipDir nginx-1.31.9.zip - https://nginx.org/download/nginx-1.31.9.zip
# 입력: -NginxZipDir nginx-1.30.7.zip - https://nginx.org/download/nginx-1.30.7.zip
# 입력: -NginxZipDir nginx-1.30.6.zip - https://nginx.org/download/nginx-1.30.6.zip
<#
.SYNOPSIS
    nginx2root 점검 룰(nginx2root-check-windows)을 랩 VM 에서 잰다 — 설치본 모양마다 종료 코드와 화면.

.DESCRIPTION
    `-Package` 는 `remedy-windows-x64` 폴더다(내려받아 푼 배포본, 또는 `New-DevPackage.ps1` 로 꾸린 개발 꾸러미). 그
    remedy.exe 와 그 안의 `plugins\nginx2root-check-windows` 를 그대로 쓴다 — 배포 앵커를 박은 실행 파일은 배포 키로 서명한
    룰만 받는다. `-NginxZipDir` 은 nginx.org 의 Windows zip 셋(`nginx-1.31.9.zip` · `nginx-1.30.7.zip` · `nginx-1.30.6.zip`)이
    든 폴더다(SHA-256 을 이 스크립트가 대조한다 · 커밋하지 않는 `testbed\harness\results\rc-inputs\nginx-win`).

    # 무해한가

    실검체는 없다. 진짜 nginx 는 nginx.org 의 zip 셋이고 **실행하지 않는다**(파일만 둔다). 그 밖의 판은 자리 채우기다 — 서버
    판 문자열(`nginx/<판>`)만 담은 작은 `nginx.exe`(실행 파일이 아니다). 자리 밖 서비스는 만들기만 하고 시작하지 않는다. 자리
    밖 프로세스는 Windows 의 `PING.EXE` 사본을 `nginx.exe` 이름으로 잠깐 띄운다. 놓은 것은 경우마다, 그리고 끝에 모두 치운다.

    # 무엇을 재나

      R  진짜 zip 3 — 1.31.9 0 · stable 1.30.7 0 · 1.30.6 2(진짜 실행 파일의 판 문자열을 읽는가)
      V  C:\nginx 자리 채우기 8 — 1.31.8 2 · 1.31.9 0 · 1.30.6 2 · 1.30.7 0 · 1.29.5 2(고친 판 없는 갈래) · 1.9.4 2(메일
         프록시 결함은 0.5.33 부터) · 0.5.32 0(영향 범위 아래) · 판 없음 6
      L  다른 자리 9(1.31.8 · Laragon 은 1.27.3) — Program Files · Laragon · Chocolatey · Scoop(사용자) · Scoop(전역) ·
         winget(사용자 범위) · winget(기계 범위) 모두 2 · Scoop 의 shim(`scoop\shims\nginx.exe` — PING.EXE 사본)으로 띄운 꼴
         1.31.9 0 · 1.31.8 2(shim 을 자리 밖 프로세스로 세지 않는다)
      G  설치본 둘 2 — 진짜 1.31.9 + Laragon 판 없음 6(0 이 아니다 — 설치본마다 가른다) · 진짜 1.31.9 + Laragon 1.30.6 2
      O  자리 밖 5 — 서비스(만들기만) 6 · 도는 nginx.exe 6 · 자리 안 서비스 + 진짜 1.31.9 0 · 자리 밖 nginx 를 띄우는 NSSM
         서비스(`Parameters` 의 `Application`) 6 · Chocolatey 꼴 — NSSM 이 자리 안의 1.31.9 를 띄움 0
      N  nginx 없음 1 — 0
      S  화면 5 — 취약 줄의 CVE 문구 · 올릴 판(stable 갈래) · 판 없음의 까닭 · 자리 밖의 까닭 · NSSM 의 까닭

    `-LogDir` 에 경우마다 화면(`<칸>.txt`)과 summary.txt 를 남긴다. 끝줄은 `판정 N/T · 실패 M` 이다.
    종료 코드: 0 = 모든 칸 통과 · 1 = 하나라도 실패.

.EXAMPLE
    .\testbed\harness\host\Invoke-Nginx2rootVerify.ps1 -Package D:\dl\x\remedy-windows-x64 `
        -NginxZipDir testbed\harness\results\rc-inputs\nginx-win -LogDir D:\dl\nginx-win
#>
param(
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $NginxZipDir,
    [Parameter(Mandatory = $true)][string] $LogDir,
    [string] $VmAddress
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'VmSession.ps1')

# nginx.org 의 Windows zip(2026-11-19 받음) — 판 · SHA-256.
$zips = [ordered]@{
    '1.31.9' = '6902ED577B34C0DFC744CDC28A4EBFCB3B73712E015FBD2AEF2C3BFBAB20DBA5'
    '1.30.7' = '204BB1685B777D7124E9AFBA2A1DC51EDB0ECCDFB366262186EB55803A382E02'
    '1.30.6' = 'C6EE35EDB0A861063323F709192AE50D1EEFAF2EA7D00678BD2B22D8542DC61E'
}
$rule = 'nginx2root-check-windows'
$exe = Join-Path $Package 'remedy.exe'
$ruleDir = Join-Path $Package "plugins\$rule"
foreach ($p in @($exe, (Join-Path $ruleDir 'plugin.yaml'))) {
    if (-not (Test-Path -LiteralPath $p)) { throw "없다: $p" }
}
foreach ($v in $zips.Keys) {
    $z = Join-Path $NginxZipDir "nginx-$v.zip"
    if (-not (Test-Path -LiteralPath $z)) { throw "없다: $z" }
    $got = (Get-FileHash -LiteralPath $z -Algorithm SHA256).Hash
    if ($got -ne $zips[$v]) { throw "nginx-$v.zip 의 SHA-256 이 다르다: $got (기대 $($zips[$v]))" }
}
New-Item -ItemType Directory -Force $LogDir | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
$summary = Join-Path $LogDir 'summary.txt'
[IO.File]::WriteAllText($summary, '', $utf8)
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`n", $utf8) }

$addr = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $addr
$g = 'C:\remedy-probe'

# 게스트에서 쓰는 도구 — 놓기 · 치우기. 경우마다 같은 세션에서 다시 정의한다(Invoke-Command 는 범위를 잇지 않는다).
# 치우는 자리는 이 하네스가 만드는 폴더뿐이다 — C:\tools 와 scoop 의 다른 앱은 건드리지 않는다.
$guestTools = {
    $wingetPkg = 'Microsoft\WinGet\Packages\nginxinc.nginx_Microsoft.Winget.Source_8wekyb3d8bbwe'
    $made = @('C:\nginx', 'C:\Program Files\nginx', 'C:\laragon\bin\nginx', 'C:\tools\nginx-1.31.8', 'C:\tools\nginx-1.31.9',
        'C:\ProgramData\scoop\apps\nginx', (Join-Path $env:USERPROFILE 'scoop\apps\nginx'),
        (Join-Path $env:LOCALAPPDATA $wingetPkg), "C:\Program Files\WinGet\Packages\nginxinc.nginx_Microsoft.Winget.Source_8wekyb3d8bbwe",
        'C:\web')
    $real = 'C:\remedy-probe\real'
    function Clear-Layouts {
        foreach ($s in @('RemedyLabNginx', 'RemedyLabNginxIn', 'RemedyLabNginxNssm', 'RemedyLabNginxNssmIn')) {
            if (Get-Service -Name $s -ErrorAction SilentlyContinue) { & sc.exe delete $s | Out-Null }
        }
        $shim = Join-Path $env:USERPROFILE 'scoop\shims\nginx.exe'
        $ours = @(Get-Process -Name nginx -ErrorAction SilentlyContinue | Where-Object { $_.Path -like 'C:\web\*' -or $_.Path -eq $shim })
        foreach ($p in $ours) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            $null = $p.WaitForExit(10000)
        }
        foreach ($r in $made) {
            if (Test-Path -LiteralPath $r) { [System.IO.Directory]::Delete('\\?\' + $r, $true) }
        }
        if (Test-Path -LiteralPath $shim) { Remove-Item -LiteralPath $shim -Force }
    }
    # 설치본 하나는 `자리|판` 한 줄로 넘긴다 — 판: real-<판>(진짜 zip 의 트리) · <판>(자리 채우기) · none(판 문자열 없음).
    # 원소 하나인 배열 안의 배열은 PowerShell 이 펴 버린다.
    function New-Install([string] $line) {
        $root, $version = $line -split '\|'
        New-Item -ItemType Directory -Force $root | Out-Null
        if ($version -like 'real-*') {
            $v = $version.Substring(5)
            Copy-Item -Path "$real\nginx-$v\*" -Destination $root -Recurse -Force
        } else {
            $text = 'REMEDY-LAB placeholder nginx.exe' + [char]0
            if ($version -ne 'none') { $text += "nginx/$version" + [char]0 }
            [IO.File]::WriteAllBytes("$root\nginx.exe", [Text.Encoding]::ASCII.GetBytes($text))
        }
        if (-not (Test-Path -LiteralPath "$root\nginx.exe")) { throw "놓지 못했다: $root\nginx.exe" }
    }
}

$scoopUser = 'scoop\apps\nginx\1.31.8'
$wingetName = 'nginxinc.nginx_Microsoft.Winget.Source_8wekyb3d8bbwe'
$wingetDir = "Microsoft\WinGet\Packages\$wingetName"
$cases = @(
    @{ id = 'R1'; what = '진짜 1.31.9(고친 판) · C:\nginx'; expect = 0; installs = @('C:\nginx|real-1.31.9') },
    @{ id = 'R2'; what = '진짜 1.30.7(stable 고친 판) · C:\nginx'; expect = 0; installs = @('C:\nginx|real-1.30.7') },
    @{ id = 'R3'; what = '진짜 1.30.6(영향 판) · C:\nginx'; expect = 2; installs = @('C:\nginx|real-1.30.6');
       screen = '1.31.9 이상으로, stable 갈래(1.30.x)는 1.30.7 이상으로 올리십시오' },
    @{ id = 'V1'; what = 'C:\nginx 1.31.8'; expect = 2; installs = @('C:\nginx|1.31.8');
       screen = 'nginx2root(CVE-2026-123007 외 넷)' },
    @{ id = 'V2'; what = 'C:\nginx 1.31.9'; expect = 0; installs = @('C:\nginx|1.31.9') },
    @{ id = 'V3'; what = 'C:\nginx 1.30.6'; expect = 2; installs = @('C:\nginx|1.30.6') },
    @{ id = 'V4'; what = 'C:\nginx 1.30.7'; expect = 0; installs = @('C:\nginx|1.30.7') },
    @{ id = 'V5'; what = 'C:\nginx 1.29.5(고친 판 없는 갈래)'; expect = 2; installs = @('C:\nginx|1.29.5') },
    @{ id = 'V6'; what = 'C:\nginx 1.9.4(메일 프록시 결함 범위)'; expect = 2; installs = @('C:\nginx|1.9.4') },
    @{ id = 'V7'; what = 'C:\nginx 0.5.32(영향 범위 아래)'; expect = 0; installs = @('C:\nginx|0.5.32') },
    @{ id = 'V8'; what = 'C:\nginx · 판 문자열 없음'; expect = 6; installs = @('C:\nginx|none');
       screen = '실행 파일에서 판을 읽지 못했습니다' },
    @{ id = 'L1'; what = 'Program Files 1.31.8'; expect = 2; installs = @('C:\Program Files\nginx|1.31.8') },
    @{ id = 'L2'; what = 'Laragon 1.27.3'; expect = 2; installs = @('C:\laragon\bin\nginx\nginx-1.27.3|1.27.3') },
    @{ id = 'L3'; what = 'Chocolatey 1.31.8'; expect = 2; installs = @('C:\tools\nginx-1.31.8|1.31.8') },
    @{ id = 'L4'; what = 'Scoop(사용자) 1.31.8'; expect = 2; installs = @("PROFILE\$scoopUser|1.31.8") },
    @{ id = 'L5'; what = 'Scoop(전역) 1.31.8'; expect = 2; installs = @('C:\ProgramData\scoop\apps\nginx\1.31.8|1.31.8') },
    @{ id = 'L6'; what = 'winget(사용자 범위) 1.31.8'; expect = 2; installs = @("LOCAL\$wingetDir\nginx-1.31.8|1.31.8") },
    @{ id = 'L7'; what = 'winget(기계 범위) 1.31.8'; expect = 2; installs = @("C:\Program Files\WinGet\Packages\$wingetName\nginx-1.31.8|1.31.8") },
    # Scoop 의 shim(`scoop\shims\nginx.exe`)으로 띄운 꼴 — shim 은 진짜 nginx 를 자식으로 띄우고 살아 있다. 자리 밖 프로세스로
    # 세지 않는다(뺀다) — 판은 apps\nginx 의 파일로 본다.
    @{ id = 'L8'; what = 'Scoop(사용자) 1.31.9 + shim 으로 띄움'; expect = 0; installs = @('PROFILE\scoop\apps\nginx\1.31.9|1.31.9');
       process = 'PROFILE\scoop\shims\nginx.exe' },
    @{ id = 'L9'; what = 'Scoop(사용자) 1.31.8 + shim 으로 띄움'; expect = 2; installs = @('PROFILE\scoop\apps\nginx\1.31.8|1.31.8');
       process = 'PROFILE\scoop\shims\nginx.exe' },
    @{ id = 'G1'; what = '진짜 1.31.9 + Laragon 판 없음 — 설치본마다'; expect = 6;
       installs = @('C:\nginx|real-1.31.9', 'C:\laragon\bin\nginx\nginx-1.27.3|none') },
    @{ id = 'G2'; what = '진짜 1.31.9 + Laragon 1.30.6'; expect = 2;
       installs = @('C:\nginx|real-1.31.9', 'C:\laragon\bin\nginx\nginx-1.30.6|1.30.6') },
    @{ id = 'O1'; what = '자리 밖 nginx 서비스(만들기만)'; expect = 6; installs = @(); service = 'C:\web\nginx\nginx.exe';
       screen = '밖의 nginx(위 경로)가 서비스로 있거나(NSSM 이 띄우는 것 포함) 돌고 있어 그 판을 보지 않았습니다' },
    @{ id = 'O2'; what = '자리 밖에서 도는 nginx.exe'; expect = 6; installs = @(); process = 'C:\web\nginx\nginx.exe' },
    @{ id = 'O3'; what = '자리 안 서비스 + 진짜 1.31.9'; expect = 0; installs = @('C:\nginx|real-1.31.9');
       serviceIn = 'C:\nginx\nginx.exe' },
    @{ id = 'O4'; what = '자리 밖 nginx 를 띄우는 NSSM 서비스(Parameters\Application)'; expect = 6; installs = @();
       nssm = 'C:\web\nginx\nginx.exe'; screen = 'NSSM 이 띄우는 것 포함' },
    @{ id = 'O5'; what = 'Chocolatey 꼴 — NSSM 이 자리 안 1.31.9 를 띄움'; expect = 0;
       installs = @('C:\tools\nginx-1.31.9|1.31.9'); nssm = 'C:\tools\nginx-1.31.9\nginx.exe' },
    @{ id = 'N1'; what = 'nginx 없음'; expect = 0; installs = @() }
)

$pass = 0
$fail = 0
$total = 0
function Check([string] $id, [string] $what, [bool] $ok, [string] $evidence) {
    $script:total++
    if ($ok) { $script:pass++ } else { $script:fail++ }
    Note ('{0,-4} {1}  {2} — {3}' -f $id, $(if ($ok) { '통과' } else { '실패' }), $what, $evidence)
}

try {
    Note ("시작 {0}  꾸러미={1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Package)
    Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
        New-Item -ItemType Directory -Force "$g\plugins", "$g\real", "$g\out" | Out-Null
    }
    Copy-GuestFile -Session $session -Source $exe -Destination "$g\remedy.exe"
    Copy-Item -LiteralPath $ruleDir -Destination "$g\plugins" -ToSession $session -Recurse -Force
    foreach ($v in $zips.Keys) {
        Copy-GuestFile -Session $session -Source (Join-Path $NginxZipDir "nginx-$v.zip") -Destination "$g\real\nginx-$v.zip"
    }
    Invoke-Command -Session $session -ArgumentList $g, @($zips.Keys) -ScriptBlock {
        param($g, $versions)
        foreach ($v in $versions) {
            Expand-Archive -LiteralPath "$g\real\nginx-$v.zip" -DestinationPath "$g\real" -Force
            Remove-Item -LiteralPath "$g\real\nginx-$v.zip" -Force
            if (-not (Test-Path "$g\real\nginx-$v\nginx.exe")) { throw "zip 에 nginx-$v\nginx.exe 가 없다" }
        }
    }
    Invoke-Command -Session $session -ArgumentList $guestTools.ToString() -ScriptBlock {
        param($tools)
        . ([scriptblock]::Create($tools))
        Clear-Layouts
    }

    foreach ($c in $cases) {
        $setupScript = $guestTools.ToString()
        Invoke-Command -Session $session -ArgumentList $setupScript, $c.installs, $c.service, $c.process, $c.serviceIn, $c.nssm -ScriptBlock {
            param($tools, $installs, $service, $process, $serviceIn, $nssm)
            . ([scriptblock]::Create($tools))
            Clear-Layouts
            foreach ($i in @($installs)) {
                if ($i) { New-Install ([string]$i).Replace('PROFILE\', $env:USERPROFILE + '\').Replace('LOCAL\', $env:LOCALAPPDATA + '\') }
            }
            # NSSM 꼴 — 서비스의 실행 파일은 감싸는 프로그램(없어도 된다 · 시작하지 않는다)이고 띄우는 것은 Parameters 의
            # Application 값이다(NSSM 이 쓰는 자리 그대로).
            if ($nssm) {
                New-Service -Name 'RemedyLabNginxNssm' -BinaryPathName '"C:\web\nssm\nssm.exe"' -StartupType Manual | Out-Null
                $pk = 'HKLM:\SYSTEM\CurrentControlSet\Services\RemedyLabNginxNssm\Parameters'
                New-Item -Path $pk -Force | Out-Null
                New-ItemProperty -Path $pk -Name 'Application' -Value $nssm -PropertyType ExpandString -Force | Out-Null
                New-ItemProperty -Path $pk -Name 'AppDirectory' -Value (Split-Path -Parent $nssm) -PropertyType ExpandString -Force | Out-Null
            }
            if ($service) {
                New-Service -Name 'RemedyLabNginx' -BinaryPathName ('"' + $service + '"') -StartupType Manual | Out-Null
            }
            if ($serviceIn) {
                New-Service -Name 'RemedyLabNginxIn' -BinaryPathName ('"' + $serviceIn + '"') -StartupType Manual | Out-Null
            }
            if ($process) {
                $proc = $process.Replace('PROFILE\', $env:USERPROFILE + '\')
                New-Item -ItemType Directory -Force (Split-Path -Parent $proc) | Out-Null
                Copy-Item -LiteralPath "$env:windir\System32\PING.EXE" -Destination $proc -Force
                Start-Process -FilePath $proc -ArgumentList @('-n', '600', '127.0.0.1') -WindowStyle Hidden | Out-Null
                Start-Sleep -Seconds 1
            }
        }
        $out = "$g\out\$($c.id)"
        $r = Invoke-GuestExe -Session $session -Path "$g\remedy.exe" -WorkingDirectory $g `
            -Arguments @('scan', '--plugin', "$g\plugins\$rule\plugin.yaml", '--out-dir', $out)
        $screen = [string]$r.out + [string]$r.err
        [IO.File]::WriteAllText((Join-Path $LogDir "$($c.id).txt"), ("exit={0}`n{1}" -f $r.exit, $screen), $utf8)
        Check $c.id $c.what ($r.exit -eq $c.expect) ("종료 {0} (기대 {1})" -f $r.exit, $c.expect)
        if ($c.screen) {
            Check "S-$($c.id)" "화면 — $($c.what)" ($screen.Contains($c.screen)) $c.screen
        }
    }
}
finally {
    try {
        Invoke-Command -Session $session -ArgumentList $guestTools.ToString(), $g -ScriptBlock {
            param($tools, $g)
            . ([scriptblock]::Create($tools))
            Clear-Layouts
            if (Test-Path -LiteralPath $g) { [System.IO.Directory]::Delete('\\?\' + $g, $true) }
        }
    } finally { Remove-PSSession $session }
}
Note ("끝 {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Note ("판정 {0}/{1} · 실패 {2}" -f $pass, $total, $fail)
if ($fail -eq 0) { exit 0 } else { exit 1 }
# PR CI 시험 — 병합 전에 지운다
