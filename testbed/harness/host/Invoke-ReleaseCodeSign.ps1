#Requires -Version 5.1
<#
.SYNOPSIS
    배포의 코드서명 걸음 — 태그 실행(첫 걸음)이 초안에 넘긴 Windows 실행 파일 둘을 이 기계의 서명 도구로 서명해 초안에
    올리고, 같은 태그에서 배포 워크플로의 둘째 걸음을 불러 끝까지 지켜본다.

.DESCRIPTION
    Windows 실행 파일의 코드서명(Authenticode · Azure Trusted Signing)은 이 기계에서만 된다 — 서명 도구와 그 계정 ·
    인증서 프로필이 여기 있고 CI 에는 없다. 그래서 배포의 Windows 는 두 걸음이고(`.github/workflows/release.yml`
    첫머리) 이 스크립트가 그 사이다.

      1. 그 태그의 초안이 있는지(공개된 Release 는 건드리지 않는다) · 첫 걸음이 넘긴 `unsigned-remedy.exe` ·
         `unsigned-remedy-net.exe` 가 있는지 본다 — 아직이면 `-WaitMinutes` 동안 기다린다
      2. 결과 폴더 안의 새 폴더에 받고, 서명 없는 PE 인지 본다
      3. 서명 도구를 부른다 — 그 도구의 폴더에서, 인자는 파일 하나, 끝의 `pause` 에는 줄 하나를 넣는다. 도구의 종료
         코드는 `pause` 의 것이라 판정에 쓰지 않는다 — 도구가 찍는 `Number of errors: 0` 과 아래 확인으로 판정한다
      4. 서명이 유효한지 · 주체가 배포 워크플로의 `CODESIGN_SUBJECT` 인지 · 타임스탬프가 있는지(`Get-AuthenticodeSignature`)
         · 넘긴 그 파일에 서명만 더했는지(`cargo xtask codesign`) 잰다
      5. 서명본을 초안에 `signed-*` 로 올리고 둘째 걸음을 불러(`gh workflow run release.yml --ref <태그>`) 끝날 때까지
         지켜본다 — 둘째 걸음이 서명본을 다시 재고 꾸러미 · SHA256SUMS 를 올린다. `-NoDispatch` 면 올리기까지만 한다

    서명 도구의 자리는 `-SignBat` 이거나 `.cargo/host.yml` 의 `codesign.sign_bat`(견본 `.cargo/host.example.yml`) 이다 —
    없으면 멈춘다. **도구가 찍는 줄은 화면 · 기록에 그대로 내지 않는다** — 그 안에 서명 계정 · 엔드포인트가 든다. 판정에
    쓰는 줄만 고르고, 실패하면 오류 줄을 도구 폴더 설정 파일(json)의 값과 주소를 가린 꼴로 보인다.

    `-LocalDir <폴더>` 는 **출시 없이 서명 도구가 도는지** 본다 — 초안 대신 그 폴더의 `unsigned-remedy.exe` ·
    `unsigned-remedy-net.exe` 를 2 ~ 4 차례로 서명하고 재기만 한다(초안을 읽지도 올리지도 부르지도 않는다 · `-Tag` 는
    결과 폴더 이름에만 쓴다). 서명 계정의 로그인이 끝났는지 출시 날 전에 알 수 있다.

    결과는 `-LogDir`(기본 `testbed\harness\results\codesign-<태그>` — 커밋하지 않는 자리)의 summary.txt 다. 종료 코드:
    0 = 서명 · 올리기 · 둘째 걸음 성공 · 1 = 실패(어느 단계인지 summary.txt 가 적는다) · 2 = 인자 · 준비가 모자라 시작하지
    않았다.

.EXAMPLE
    .\testbed\harness\host\Invoke-ReleaseCodeSign.ps1 -Tag rules-2026.11.19-rc.1

.EXAMPLE
    .\testbed\harness\host\Invoke-ReleaseCodeSign.ps1 -Tag local-check -LocalDir D:\dl\unsigned
#>
param(
    [Parameter(Mandatory = $true)][string] $Tag,
    [string] $SignBat,
    [string] $LogDir,
    [string] $LocalDir,
    [int] $WaitMinutes = 40,
    [int] $SignTimeoutSec = 300,
    [int] $RunTimeoutMinutes = 60,
    [switch] $NoDispatch
)
# 네이티브 명령(gh · cargo)의 stderr 가 5.1 에서 종료 오류가 되지 않게 — 실패는 종료 코드로 본다.
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'VmSession.ps1')
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
Set-Location -LiteralPath $repo

$bins = @('remedy.exe', 'remedy-net.exe')
if ($LocalDir) {
    if (-not (Test-Path -LiteralPath $LocalDir -PathType Container)) { "-LocalDir 폴더가 없다: $LocalDir"; exit 2 }
    if ($Tag -notmatch '^[A-Za-z0-9._-]+$') { "-Tag 는 결과 폴더 이름으로 쓸 수 있어야 한다: $Tag"; exit 2 }
} elseif ($Tag -notmatch '^(v|rules-)\S+$') { "태그가 배포 태그(v* · rules-*)가 아니다: $Tag"; exit 2 }
try { $SignBat = Resolve-LabValue $SignBat 'host' 'codesign.sign_bat' 'SignBat' } catch { "$_"; exit 2 }
if (-not (Test-Path -LiteralPath $SignBat -PathType Leaf)) { "서명 도구가 없다: $SignBat"; exit 2 }
try { $subject = Get-CodeSignSubject } catch { "$_"; exit 2 }
if (-not $LogDir) { $LogDir = Join-Path $repo "testbed\harness\results\codesign-$Tag" }
New-Item -ItemType Directory -Force $LogDir | Out-Null
# 절대 경로로 바꾼다 — 서명 도구는 자기 폴더에서 돌아 상대 경로의 파일을 찾지 못한다(2026-11-20 rules-2026.11.20 의 첫
# 서명이 `-LogDir testbed\harness\results\…` 로 'File not found' 에 멈췄다).
$LogDir = (Resolve-Path -LiteralPath $LogDir).Path
$utf8 = New-Object System.Text.UTF8Encoding $false
$summary = Join-Path $LogDir 'summary.txt'
[IO.File]::WriteAllText($summary, '', $utf8)
function Note([string] $line) { $line; [IO.File]::AppendAllText($summary, $line + "`n", $utf8) }
function Stop-Here([string] $why) { Note "실패 — $why"; Note ("끝 {0} · 종료 1" -f (Get-Date -Format 'HH:mm:ss')); exit 1 }

# 도구 폴더 설정 파일(json)의 문자열 값 — 오류 줄을 보일 때 가린다.
$signDir = Split-Path -Parent $SignBat
$hidden = @()
foreach ($j in @(Get-ChildItem -LiteralPath $signDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
    try {
        $o = Get-Content -LiteralPath $j.FullName -Raw | ConvertFrom-Json
        foreach ($pr in $o.PSObject.Properties) {
            if ($pr.Value -is [string] -and $pr.Value.Length -ge 4) { $hidden += $pr.Value }
        }
    } catch { }
}
function Hide([string] $s) {
    foreach ($v in $hidden) { $s = $s.Replace($v, '***') }
    $s -replace 'https?://\S+', '<주소>'
}

function Get-Draft {
    $j = gh release view $Tag --json isDraft,assets
    if ($LASTEXITCODE -ne 0 -or -not $j) { return $null }
    ($j | Out-String) | ConvertFrom-Json
}

Note ("시작 {0} · 태그 {1} · 주체 {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Tag, $subject)

# 1 — 초안과 넘긴 파일(-LocalDir 면 건너뛴다)
$deadline = (Get-Date).AddMinutes($WaitMinutes)
while (-not $LocalDir) {
    $rel = Get-Draft
    if ($rel -and -not $rel.isDraft) { Stop-Here "$Tag 는 공개된 Release 다 — 건드리지 않는다" }
    $names = if ($rel) { @($rel.assets | ForEach-Object { $_.name }) } else { @() }
    $missing = @($bins | Where-Object { $names -notcontains "unsigned-$_" })
    if (-not $missing.Count) { break }
    if ((Get-Date) -gt $deadline) {
        Stop-Here ("{0}분 안에 첫 걸음이 넘기지 않았다(없음: {1}) — 태그 실행을 본다: gh run list --workflow release.yml --branch {2}" -f $WaitMinutes, (($missing | ForEach-Object { "unsigned-$_" }) -join ' · '), $Tag)
    }
    Start-Sleep -Seconds 30
}
if (-not $LocalDir) { Note '1 초안 · 넘긴 파일 둘 — 있다' }

# 2 — 받기(-LocalDir 면 그 폴더에서 베낀다)
$work = Join-Path $LogDir 'files'
if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
$got = Join-Path $work 'handover'
$signed = Join-Path $work 'signed'
New-Item -ItemType Directory -Force $got, $signed | Out-Null
if ($LocalDir) {
    foreach ($b in $bins) {
        $src = Join-Path $LocalDir "unsigned-$b"
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Stop-Here "-LocalDir 에 unsigned-$b 가 없다" }
        Copy-Item -LiteralPath $src -Destination $got
    }
} else {
    $pats = @(); foreach ($b in $bins) { $pats += @('--pattern', "unsigned-$b") }
    gh release download $Tag --dir $got @pats
    if ($LASTEXITCODE -ne 0) { Stop-Here "넘긴 파일을 받지 못했다(gh 종료 $LASTEXITCODE)" }
}
foreach ($b in $bins) {
    $u = Join-Path $got "unsigned-$b"
    $len = (Get-Item -LiteralPath $u).Length
    $st = (Get-AuthenticodeSignature -LiteralPath $u).Status
    if ($st -ne 'NotSigned') { Stop-Here "unsigned-$b 가 서명 없는 파일이 아니다($st)" }
    if ($len % 8 -ne 0) { Stop-Here "unsigned-$b 의 길이 $len 가 8의 배수가 아니다 — 서명만 더했는지 잴 수 없다" }
    Copy-Item -LiteralPath $u -Destination (Join-Path $signed $b)
    Note ("2 받음 unsigned-{0} · {1:N0} 바이트 · SHA-256 {2}" -f $b, $len, (Get-FileHash -LiteralPath $u -Algorithm SHA256).Hash)
}

# 3 — 서명. 도구가 찍는 줄은 이 함수 밖으로 나가지 않는다(판정 줄만 · 실패면 가린 오류 줄).
function Invoke-SignTool([string] $file) {
    $in = Join-Path $LogDir 'stdin.txt'
    [IO.File]::WriteAllText($in, "`r`n")
    $out = [IO.Path]::GetTempFileName()
    $err = [IO.Path]::GetTempFileName()
    try {
        # cmd 의 따옴표 규칙 — /s 와 바깥 따옴표 한 겹. 이 기계는 현재 폴더의 실행 파일을 찾지 않으므로(NoDefault-
        # CurrentDirectoryInExePath) 도구를 전체 경로로 부르고, 도구 안의 상대 경로는 그 폴더에서 풀린다.
        $line = '/d /s /c ""' + $SignBat + '" "' + $file + '""'
        $p = Start-Process -FilePath 'cmd.exe' -ArgumentList $line -WorkingDirectory $signDir -NoNewWindow -PassThru `
            -RedirectStandardInput $in -RedirectStandardOutput $out -RedirectStandardError $err
        $null = $p.Handle
        if (-not $p.WaitForExit($SignTimeoutSec * 1000)) {
            & taskkill.exe /T /F /PID $p.Id | Out-Null
            return "시한 $SignTimeoutSec 초를 넘겼다"
        }
        $text = @(Get-Content -LiteralPath $out) + @(Get-Content -LiteralPath $err)
    } finally {
        Remove-Item -LiteralPath $out, $err, $in -Force -ErrorAction SilentlyContinue
    }
    $errors = @($text | Where-Object { $_ -match '^\s*Number of errors:\s*(\d+)' } | ForEach-Object { [int]($_ -replace '\D', '') })
    $done = @($text | Where-Object { $_ -match '^\s*Successfully signed:' })
    if ($errors.Count -eq 1 -and $errors[0] -eq 0 -and $done.Count -eq 1) { return $null }
    $shown = @($text | Where-Object { $_ -match '(?i)error|fail|denied|unauthori|credential|expired' } | Select-Object -First 10 |
        ForEach-Object { '    ' + (Hide $_) })
    return ("도구가 서명하지 않았다(Number of errors: {0} · Successfully signed {1}줄)`n{2}" -f ($errors -join ','), $done.Count, ($shown -join "`n"))
}
foreach ($b in $bins) {
    $f = Join-Path $signed $b
    $t0 = Get-Date
    $why = Invoke-SignTool $f
    if ($why) { Stop-Here "서명 $b — $why" }
    Note ("3 서명 {0} · {1:N1}초" -f $b, ((Get-Date) - $t0).TotalSeconds)
}

# 4 — 확인
foreach ($b in $bins) {
    $f = Join-Path $signed $b
    $line = Get-CodeSignLine -Path $f -Subject $subject
    $cert = (Get-AuthenticodeSignature -LiteralPath $f).SignerCertificate
    Note ("4 {0} · 인증서 {1:yyyy-MM-dd} ~ {2:yyyy-MM-dd}" -f $line, $cert.NotBefore, $cert.NotAfter)
    if ($line -notmatch ' codesign=ok ') {
        Stop-Here "$b 의 코드서명이 맞지 않는다 — 유효 · Authenticode · 주체 '$subject' · 타임스탬프가 모두 있어야 한다"
    }
    $o = & cargo xtask codesign (Join-Path $got "unsigned-$b") $f 2>&1
    $code = $LASTEXITCODE
    $last = @($o | ForEach-Object { "$_" } | Where-Object { $_.Trim() } | Select-Object -Last 1)
    Note ("4 {0}: {1}" -f $b, $(if ($last.Count) { $last[0] } else { '(출력 없음)' }))
    if ($code -ne 0) { Stop-Here "$b 가 넘긴 파일에 서명만 더한 것이 아니다(cargo xtask codesign 종료 $code)" }
}

if ($LocalDir) { Note ("끝 {0} · 종료 0 (-LocalDir — 서명 · 확인까지만 · 서명본: {1})" -f (Get-Date -Format 'HH:mm:ss'), $signed); exit 0 }

# 5 — 올리기 · 둘째 걸음
$up = Join-Path $work 'upload'
New-Item -ItemType Directory -Force $up | Out-Null
$files = @()
foreach ($b in $bins) {
    $dst = Join-Path $up "signed-$b"
    Copy-Item -LiteralPath (Join-Path $signed $b) -Destination $dst
    $files += $dst
}
gh release upload $Tag @files --clobber
if ($LASTEXITCODE -ne 0) { Stop-Here "서명본을 초안에 올리지 못했다(gh 종료 $LASTEXITCODE)" }
Note ('5 서명본 둘을 초안에 올렸다(signed-*)')
if ($NoDispatch) { Note ("끝 {0} · 종료 0 (-NoDispatch — 둘째 걸음: gh workflow run release.yml --ref {1})" -f (Get-Date -Format 'HH:mm:ss'), $Tag); exit 0 }

$asked = (Get-Date).ToUniversalTime()
gh workflow run release.yml --ref $Tag
if ($LASTEXITCODE -ne 0) { Stop-Here "둘째 걸음을 부르지 못했다(gh 종료 $LASTEXITCODE)" }
$run = $null
for ($i = 0; $i -lt 24 -and -not $run; $i++) {
    Start-Sleep -Seconds 5
    $j = gh run list --workflow release.yml --event workflow_dispatch --branch $Tag --limit 5 --json databaseId,createdAt
    if ($LASTEXITCODE -ne 0 -or -not $j) { continue }
    foreach ($r in @(($j | Out-String) | ConvertFrom-Json)) {
        $at = $r.createdAt
        if ($at -isnot [DateTime]) {
            $at = [DateTime]::Parse($at, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)
        }
        if ($at -ge $asked.AddSeconds(-30)) { $run = $r.databaseId; break }
    }
}
if (-not $run) { Stop-Here '부른 둘째 걸음의 실행을 찾지 못했다 — gh run list --workflow release.yml --event workflow_dispatch' }
Note ("5 둘째 걸음 실행 {0}" -f $run)
$until = (Get-Date).AddMinutes($RunTimeoutMinutes)
$seen = ''
while ($true) {
    $j = gh run view $run --json status,conclusion,jobs
    if ($LASTEXITCODE -eq 0 -and $j) {
        $v = ($j | Out-String) | ConvertFrom-Json
        $now = ((@($v.jobs) | ForEach-Object { '{0}={1}' -f $_.name, $(if ($_.conclusion) { $_.conclusion } else { $_.status }) }) -join ' · ')
        if ($now -ne $seen) { Note ("  {0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $now); $seen = $now }
        if ($v.status -eq 'completed') { break }
    }
    if ((Get-Date) -gt $until) { Stop-Here "둘째 걸음이 $RunTimeoutMinutes 분 안에 끝나지 않았다(실행 $run)" }
    Start-Sleep -Seconds 30
}
if ($v.conclusion -ne 'success') { Stop-Here "둘째 걸음이 실패했다($($v.conclusion)) — gh run view $run --log-failed" }
$rel = Get-Draft
Note ("5 둘째 걸음 성공 · 초안 자산: {0}" -f ((@($rel.assets) | ForEach-Object { $_.name } | Sort-Object) -join ' · '))
Note ("끝 {0} · 종료 0" -f (Get-Date -Format 'HH:mm:ss'))
exit 0
