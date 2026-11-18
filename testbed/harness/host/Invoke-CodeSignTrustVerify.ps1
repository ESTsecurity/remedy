#Requires -Version 5.1
<#
.SYNOPSIS
    코드서명 상태마다 자기무결성이 치료 문을 맞게 여닫는가 — 랩 VM 에서(설계-01 D7 · 2026-11-18 결정 S2).

.DESCRIPTION
    `-Package` 의 `remedy.exe`(내려받아 푼 배포본 · rc · 개발 꾸러미)로 잰다. 그 파일이 코드서명돼 있으면 서명을 떼어 낸
    사본도 만든다 — 서명 도구가 바꾸는 세 곳(체크섬 · 보안 칸 · 끝의 인증서 표)만 되돌리면 서명 전 파일이 된다
    (`xtask/src/codesign.rs`).

      R  받은 그대로 — 코드서명돼 있으면 '서명 확인'(알림 없음), 아니면 '서명 없음' 알림. 문을 지난다
      N  서명을 떼어 낸 사본 — '서명 없음' 알림 · 문을 지난다
      U  VM 에서 만든 자기서명 인증서로 서명한 사본(신뢰하지 않는 루트) — '확인하지 못했다' 알림 · 문을 지난다
      A  U 의 한 바이트를 바꾼 사본(서명 뒤 바뀜) — 문이 5
      T  U 의 인증서를 신뢰 루트에 넣은 뒤 — '서명 확인'(알림 없음) · 문을 지난다
      D  그 인증서를 신뢰 루트에서 빼고 '신뢰하지 않음'(Disallowed)에 넣은 뒤 — 문이 5
      B  받은 것이 코드서명돼 있을 때만 — 그 서명의 루트를 지우고 자동 루트 갱신을 끈 뒤(루트를 받은 적 없는 오프라인
         기계): '확인하지 못했다' 알림 · 문을 지난다

    '문' 은 인자 없는 `apply` 다 — 관리자 문과 자기무결성 문을 지나면 `--plan` 이 없어 4 로 끝나고(기계를 만지지 않는다),
    자기무결성 문이 막으면 5 와 그 까닭이다. '알림' 은 `--version` 의 첫 줄이다. 칸마다 `<칸>.txt` 와 summary.txt 를
    남기고 끝줄은 `판정 N/T · 실패 M` 이다. 인증서 저장소를 바꾸므로 **끝에 VM 을 되돌린다**. 종료 코드 0 · 1.

.EXAMPLE
    .\testbed\harness\host\Invoke-CodeSignTrustVerify.ps1 -Package D:\dl\rc\remedy-windows-x64 -LogDir D:\dl\codesign-trust
#>
param(
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $LogDir,
    [string] $VmAddress
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'VmSession.ps1')

# 화면 문구 — `crates/remedy-core/src/integrity.rs` 의 알림 · 까닭에서 갈래마다 고유한 토막.
$SAY_UNSIGNED = '코드서명이 없어'
$SAY_UNVERIFIED = '코드서명을 이 기계에서 확인하지 못했습니다'
$SAY_UNTRUSTED = '신뢰할 수 없다'

$exe = Join-Path $Package 'remedy.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "remedy.exe 가 없다: $exe" }
New-Item -ItemType Directory -Force $LogDir | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
$summary = Join-Path $LogDir 'summary.txt'
[IO.File]::WriteAllText($summary, '', $utf8)
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`n", $utf8) }
$pass = 0
$fail = 0
function Check([string] $id, [string] $what, [bool] $ok, [string] $evidence) {
    if ($ok) { $script:pass++ } else { $script:fail++ }
    Note ('{0,-3} {1}  {2} — {3}' -f $id, $(if ($ok) { '통과' } else { '실패' }), $what, $evidence)
}

# 서명을 떼어 낸 사본 — 끝의 인증서 표를 자르고 보안 칸 · 체크섬을 0 으로(서명 전 파일의 값이다).
$work = Join-Path $LogDir 'files'
New-Item -ItemType Directory -Force $work | Out-Null
$bytes = [IO.File]::ReadAllBytes($exe)
$opt = [BitConverter]::ToInt32($bytes, 0x3C) + 24
$certAt = [BitConverter]::ToUInt32($bytes, $opt + 112 + 32)
$codeSigned = $certAt -ne 0
$plain = Join-Path $work 'remedy-plain.exe'
if ($codeSigned) {
    $cut = New-Object byte[] $certAt
    [Array]::Copy($bytes, $cut, $certAt)
    [Array]::Clear($cut, $opt + 64, 4)
    [Array]::Clear($cut, $opt + 112 + 32, 8)
    [IO.File]::WriteAllBytes($plain, $cut)
} else {
    [IO.File]::WriteAllBytes($plain, $bytes)
}
$sig = Get-AuthenticodeSignature -LiteralPath $exe
$rootThumb = $null
if ($codeSigned -and $sig.SignerCertificate) {
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    [void]$chain.Build($sig.SignerCertificate)
    $rootThumb = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
}

$g = 'C:\remedy-codesign-trust'
$addr = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$session = Connect-LabVm -VmAddress $addr

# 칸 하나 — 알림(첫 줄)과 문(apply 종료 코드 · 첫 줄)을 받아 기대와 견준다.
function Probe([string] $id, [string] $what, [string] $file, [string] $say, [int] $gate) {
    $dir = Split-Path -Parent $file
    $v = Invoke-GuestExe -Session $session -Path $file -WorkingDirectory $dir -Arguments @('--version')
    $a = Invoke-GuestExe -Session $session -Path $file -WorkingDirectory $dir -Arguments @('apply')
    $vt = [string]$v.err + [string]$v.out
    $at = [string]$a.err + [string]$a.out
    [IO.File]::WriteAllText((Join-Path $LogDir "$id.txt"), ("--version exit={0}`n{1}`n--- apply exit={2}`n{3}" -f $v.exit, $vt, $a.exit, $at), $utf8)
    $first = @(($vt -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
    $head = if ($first.Count) { $first[0].Trim() } else { '' }
    $noticeOk = if ($say) { $head.Contains($say) } else { -not $head.StartsWith('알림') }
    $gateOk = ($a.exit -eq $gate) -and ($gate -ne 5 -or $at.Contains($SAY_UNTRUSTED))
    Check $id $what ($noticeOk -and $gateOk) ('첫 줄 "{0}" · 문 {1}(기대 {2}{3})' -f $head, $a.exit, $gate,
        $(if ($say) { " · 알림 '$say'" } else { ' · 알림 없음' }))
}

try {
    Note ("시작 {0}  꾸러미={1}  코드서명={2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Package,
        $(if ($codeSigned) { "$($sig.Status) · $($sig.SignerCertificate.Subject)" } else { '없음' }))
    Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        if (Test-Path -LiteralPath $g) { Remove-Item -LiteralPath $g -Recurse -Force }
        foreach ($d in 'R', 'N', 'U', 'A') { New-Item -ItemType Directory -Force "$g\$d" | Out-Null }
    }
    Copy-GuestFile -Session $session -Source $exe -Destination "$g\R\remedy.exe"
    Copy-GuestFile -Session $session -Source $plain -Destination "$g\N\remedy.exe"

    # U · A — 게스트에서 자기서명 인증서를 만들어 서명 전 사본에 서명하고, 그 사본의 한 바이트를 바꾼다(서명이 해시하는
    # 자리 — 첫 구역의 시작). 인증서는 칸 T · D 가 저장소를 옮겨 다니며 쓴다.
    $thumb = Invoke-Command -Session $session -ArgumentList $g -ScriptBlock {
        param($g)
        $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=remedy lab self-signed' `
            -CertStoreLocation Cert:\LocalMachine\My -HashAlgorithm SHA256 -NotAfter (Get-Date).AddDays(2)
        Copy-Item -LiteralPath "$g\N\remedy.exe" -Destination "$g\U\remedy.exe"
        $null = Set-AuthenticodeSignature -FilePath "$g\U\remedy.exe" -Certificate $c -HashAlgorithm SHA256
        $b = [IO.File]::ReadAllBytes("$g\U\remedy.exe")
        $b[0x400] = $b[0x400] -bxor 0x01
        [IO.File]::WriteAllBytes("$g\A\remedy.exe", $b)
        $c.Thumbprint
    }

    Probe 'R' $(if ($codeSigned) { '받은 그대로(코드서명) — 서명 확인' } else { '받은 그대로(서명 없음)' }) "$g\R\remedy.exe" `
        $(if ($codeSigned) { '' } else { $SAY_UNSIGNED }) 4
    Probe 'N' '서명을 떼어 낸 사본 — 서명 없음' "$g\N\remedy.exe" $SAY_UNSIGNED 4
    Probe 'U' '자기서명(신뢰하지 않는 루트) — 확인하지 못함 · 막지 않음' "$g\U\remedy.exe" $SAY_UNVERIFIED 4
    Probe 'A' '서명 뒤 한 바이트 바뀜 — 막는다' "$g\A\remedy.exe" '' 5

    $null = Invoke-Command -Session $session -ArgumentList $thumb -ScriptBlock {
        param($t)
        $c = Get-Item -LiteralPath "Cert:\LocalMachine\My\$t"
        $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
        $s.Open('ReadWrite'); $s.Add($c); $s.Close()
    }
    Probe 'T' '자기서명 인증서를 신뢰 루트에 — 서명 확인' "$g\U\remedy.exe" '' 4

    $null = Invoke-Command -Session $session -ArgumentList $thumb -ScriptBlock {
        param($t)
        $c = Get-Item -LiteralPath "Cert:\LocalMachine\My\$t"
        $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
        $s.Open('ReadWrite'); $s.Remove($c); $s.Close()
        $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Disallowed', 'LocalMachine')
        $s.Open('ReadWrite'); $s.Add($c); $s.Close()
    }
    Probe 'D' '그 인증서를 신뢰하지 않음에 — 막는다' "$g\U\remedy.exe" '' 5

    if ($rootThumb) {
        $n = Invoke-Command -Session $session -ArgumentList $rootThumb -ScriptBlock {
            param($rootThumb)
            $k = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot'
            New-Item -Path $k -Force | Out-Null
            New-ItemProperty -Path $k -Name DisableRootAutoUpdate -Value 1 -PropertyType DWord -Force | Out-Null
            $removed = 0
            foreach ($store in @('Root', 'AuthRoot')) {
                $p = 'Cert:\LocalMachine\' + $store + '\' + $rootThumb
                if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force; $removed++ }
            }
            $removed
        }
        Note ("B   루트 {0} 를 지운 저장소 {1}개 · 자동 루트 갱신 끔" -f $rootThumb, $n)
        Probe 'B' '루트 없는 오프라인 기계(코드서명) — 확인하지 못함 · 막지 않음' "$g\R\remedy.exe" $SAY_UNVERIFIED 4
    } else {
        Note 'B   건너뜀 — 받은 remedy.exe 가 코드서명돼 있지 않다'
    }
}
finally {
    Remove-PSSession $session
    Note ('되돌리기 {0}' -f (Get-Date -Format 'HH:mm:ss'))
    # 되돌리기의 진행 줄이 오류 흐름으로 나와도 끊기지 않게 — 되돌리기가 끝났는지는 그 출력의 '복원 완료' 로 본다.
    # 그 줄은 Write-Host(정보 흐름)로 나오므로 흐름을 모두 받는다 — `2>&1` 만으로는 그 줄을 놓쳐 늘 '없음' 이었다.
    $ErrorActionPreference = 'Continue'
    $reset = @(& (Join-Path $PSScriptRoot 'Reset-Vm.ps1') *>&1 | ForEach-Object { "$_" })
    Note ('되돌리기 끝 {0} · {1}' -f (Get-Date -Format 'HH:mm:ss'),
        $(if ($reset -match '복원 완료') { '복원 완료' } else { '복원 완료 줄 없음 — 랩을 손으로 본다' }))
}
Note ("끝 {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Note ("판정 {0}/{1} · 실패 {2}" -f $pass, ($pass + $fail), $fail)
if ($fail -eq 0) { exit 0 } else { exit 1 }
