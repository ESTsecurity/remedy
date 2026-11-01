#Requires -Version 5.1
<#
.SYNOPSIS
    설계-09 P5 의 판정 요건을 테스트 VM 에서 확인한다 — 격리·복원·저널.

.DESCRIPTION
    **여기서 재는 것의 절반은 하지 않은 일이다.** 복원은 시스템 경로에 쓰는
    동작이고, 그것이 P6 의 첫 파괴보다 먼저 오는 이유가 "되돌리는 길이 없는
    파괴는 만들지 않는다" 이기 때문이다.

    컨테이너는 **호스트에서** 만들어 온다. 격리물을 만드는 것은
    `file.quarantine_only`(P6)의 몫이라 P5 의 제품 표면에는 없다. 그리고 그
    제약이 오히려 검증을 강하게 만든다 — 호스트의 머신 키로 감싼 wrap 이
    이 VM 에서 열리지 않는다는 것을 같은 컨테이너로 함께 볼 수 있다.

.PARAMETER Bin
    remedy.exe 경로.

.PARAMETER Container
    호스트에서 만들어 온 격리 컨테이너.

.PARAMETER OutDir
    결과 JSON 을 쓸 곳.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $Container,
    [Parameter(Mandatory = $true)][string] $PassphraseFile,
    [Parameter(Mandatory = $true)][string] $OrgKeyFile,
    [Parameter(Mandatory = $true)][string] $OutDir,
    [string] $DestPrefix = "C:\remedy-lab\p5",
    [string] $StateDir   = "C:\remedy-lab\p5-state"
)

$ErrorActionPreference = "Stop"
$results = New-Object System.Collections.ArrayList

function Add-Check {
    param([string] $Name, [bool] $Pass, [string] $Detail)
    [void]$results.Add([pscustomobject]@{ name = $Name; pass = $Pass; detail = $Detail })
    $mark = if ($Pass) { "OK  " } else { "실패" }
    $color = if ($Pass) { "Green" } else { "Red" }
    Write-Host ("  {0} {1,-46} {2}" -f $mark, $Name, $Detail) -ForegroundColor $color
}

# Start-Process 는 실측 1초를 먹는다. 여러 번 부르므로 직접 띄운다.
function Invoke-Remedy {
    param([string[]] $Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Bin
    $psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
    $psi.Arguments = ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    [pscustomobject]@{ exit = $p.ExitCode; text = ($o.Result + $e.Result) }
}

function Remove-Tree {
    param([string] $Path)
    if (-not (Test-Path $Path)) { return }
    # 읽기 전용 파일이 남아 있으면 Remove-Item 이 실패한다.
    Get-ChildItem $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
        ForEach-Object { $_.IsReadOnly = $false }
    Remove-Item $Path -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`n=== P5 검증 (격리·복원·저널) ===" -ForegroundColor Magenta
Write-Host "바이너리 : $Bin"
Write-Host "컨테이너 : $Container"
Write-Host ""

$safeEntries = @("e0", "e1", "e2", "e3", "e4", "e5")
$guardBait = "C:\Windows\System32\remedy-should-never-write.dll"

Remove-Tree $DestPrefix
Remove-Tree $StateDir

# ── 1. 평문 헤더는 키 없이 읽힌다 ─────────────────────────────
# 복원 도구가 "내가 이것을 열 수 있는가" 를 판단하는 자리다.
$r = Invoke-Remedy @("restore", "--container", $Container, "--state-dir", $StateDir)
# **라벨이 아니라 머리에서 읽어낸 값을 본다** (2026-09-10).
#
# 이 자리는 `run_id\s*:` 를 찾고 있었다. 그 라벨은 6173e93(2026-09-06)에서
# `실행 번호` 로 바뀌었고, 검사는 그날부터 거짓으로 떨어져 있었다 — P5 의
# 마지막 실행이 09-02 라 드러날 자리가 없었다(P6 도 같은 날 같은 이유로 깨졌다).
#
# 라벨은 다듬어질 수 있다. **평문 머리를 읽었다는 증거는 값 쪽**이다 —
# 실행 번호와 wrap 세 종. 그것으로 바꾸면 문구를 또 손봐도 이 검사는 서고,
# 머리를 못 읽으면 그때는 걸린다.
#
# 무엇이 빠졌는지 상세에 남긴다. 오늘 이 검사가 떨어졌을 때 네 조건 중
# 어느 것인지가 결과에 없어 코드를 뒤져야 했다.
$headerBits = @()
# 이 컨테이너는 `cargo xtask fixture` 가 만든 것이고 실행 번호가 고정
# 상수다(`xtask/src/fixture.rs` 의 `01JP5VMFIXTURE0000000000`). 그 값이
# 화면에 있다는 것이 **이 컨테이너의 평문 머리를 실제로 읽었다**는 증거다 —
# `run-<숫자>` 형식을 기대하면 안 된다(2026-09-10 에 그렇게 적었다가 걸렸다).
# 픽스처의 상수를 바꾸면 이 줄도 함께 바꾼다.
if ($r.text -match "01JP5VMFIXTURE") { $headerBits += "실행번호" }
foreach ($k in @("local", "pass", "org")) {
    if ($r.text -match "$k\(") { $headerBits += $k }
}
Add-Check "평문 헤더를 키 없이 읽는다" ($headerBits.Count -eq 4) `
    "$($headerBits -join "·") ($($headerBits.Count)/4)"

# ── 2. 다른 머신의 로컬 키로는 열리지 않는다 ──────────────────
# 컨테이너는 호스트에서 만들었다. 이 VM 의 머신 키는 다르다.
$localOnly = Invoke-Remedy @("restore", "--container", $Container, "--state-dir", $StateDir, "--yes")
$rejected = ($localOnly.exit -ne 0) -and ($localOnly.text -match "개봉 실패|열리지 않는다")
Add-Check "다른 머신의 로컬 키로는 안 열린다" $rejected "exit=$($localOnly.exit)"
Add-Check "그때 아무것도 쓰지 않았다" (-not (Test-Path $DestPrefix)) "$DestPrefix 없음"

# ── 3. 계획만 — 가드가 보호 경로를 막는다 ─────────────────────
$plan = Invoke-Remedy @("restore", "--container", $Container, "--passphrase-file", $PassphraseFile,
                        "--state-dir", $StateDir)
Add-Check "보호 경로 항목이 있으면 가드 중단(5)" ($plan.exit -eq 5) "exit=$($plan.exit)"
Add-Check "System32 에 쓰지 않았다" (-not (Test-Path $guardBait)) $guardBait
Add-Check "가드가 막았을 때 나머지도 안 썼다" (-not (Test-Path $DestPrefix)) "$DestPrefix 없음"

# ── 4. 안전한 항목만 — 계획은 보이되 쓰지 않는다 ──────────────
$sel = @("restore", "--container", $Container, "--passphrase-file", $PassphraseFile,
         "--state-dir", $StateDir)
foreach ($e in $safeEntries) { $sel += @("--entry", $e) }
$planOnly = Invoke-Remedy $sel
Add-Check "--yes 없이는 하지 않는다(2)" ($planOnly.exit -eq 2) "exit=$($planOnly.exit)"
Add-Check "계획 단계가 파일을 만들지 않았다" (-not (Test-Path $DestPrefix)) "$DestPrefix 없음"
# 판독 문구는 제품과 한 쌍이다 — 2026-10-28 에 화면이 `되살리지 못함` 에서
# `복원 불가` 로 바뀌었다(영문은 그대로 `not restorable`). 문구를 바꾸고 이 줄을
# 두고 오면 판정이 조용히 떨어진다.
Add-Check "복원할 수 없는 항목을 미리 말한다" ($planOnly.text -match "복원 불가") "ctime·btime"

# ── 5. 패스프레이즈로 실제 복원 ───────────────────────────────
$doIt = Invoke-Remedy ($sel + @("--yes"))
Add-Check "패스프레이즈로 복원(0)" ($doIt.exit -eq 0) "exit=$($doIt.exit)"

# 바이트가 그대로인가. 이 도구가 존재하는 이유가 여기 걸려 있다.
$updater = Join-Path $DestPrefix "updater.exe"
$bytesOk = $false
if (Test-Path $updater) {
    $b = [System.IO.File]::ReadAllBytes($updater)
    $bytesOk = ($b.Length -eq 4096)
    if ($bytesOk) {
        for ($i = 0; $i -lt 4096; $i++) {
            if ($b[$i] -ne ($i % 256)) { $bytesOk = $false; break }
        }
    }
}
Add-Check "4096바이트 패턴이 그대로다" $bytesOk "updater.exe"

$cfg = Join-Path $DestPrefix "설정 파일.dat"
$utf8Ok = $false
if (Test-Path $cfg) {
    $want = [System.Text.Encoding]::UTF8.GetBytes("한글 내용 · 탭`t줄바꿈`n끝")
    $got = [System.IO.File]::ReadAllBytes($cfg)
    $utf8Ok = ($got.Length -eq $want.Length)
    if ($utf8Ok) {
        for ($i = 0; $i -lt $want.Length; $i++) {
            if ($got[$i] -ne $want[$i]) { $utf8Ok = $false; break }
        }
    }
}
Add-Check "한글 이름·비ASCII 본문이 그대로다" $utf8Ok "설정 파일.dat"

$empty = Join-Path $DestPrefix "empty.bin"
Add-Check "0바이트 파일도 복원된다" `
    ((Test-Path $empty) -and ((Get-Item $empty).Length -eq 0)) "empty.bin"

$ro = Join-Path $DestPrefix "readonly.txt"
Add-Check "읽기 전용 속성이 되돌아온다" `
    ((Test-Path $ro) -and (Get-Item $ro).IsReadOnly) "readonly.txt"

# 명시적 DACL 이 되돌아왔는가. 잘 알려진 SID(BA·SY)만 쓰므로 어느 머신에서도
# 해석된다. `P` 로 상속을 끊었으니 부모에서 내려온 ACE 와 섞이지 않는다.
$aclFile = Join-Path $DestPrefix "acl.txt"
$aclOk = $false
$aclDetail = "없음"
if (Test-Path $aclFile) {
    $sddl = (Get-Acl $aclFile).Sddl
    $aclDetail = $sddl
    # 상속이 끊겼고(P) 관리자·SYSTEM 이 전체 권한을 갖는가.
    $aclOk = ($sddl -match "D:P") -and ($sddl -match "\(A;;FA;;;BA\)") -and ($sddl -match "\(A;;FA;;;SY\)")
}
Add-Check "명시적 DACL 이 되돌아온다" $aclOk $aclDetail

# 수정 시각. 2001-09-09T01:46:40Z (epoch 1000000000).
$mtimeFile = Join-Path $DestPrefix "mtime.txt"
$mtimeOk = $false
$mtimeDetail = "없음"
if (Test-Path $mtimeFile) {
    $utc = (Get-Item $mtimeFile).LastWriteTimeUtc
    $mtimeDetail = $utc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $want = [datetime]::new(1970,1,1,0,0,0,[System.DateTimeKind]::Utc).AddSeconds(1000000000)
    $mtimeOk = ([math]::Abs(($utc - $want).TotalSeconds) -lt 2)
}
Add-Check "수정 시각이 되돌아온다" $mtimeOk $mtimeDetail

# 여유 공간을 실제로 재고 보고했는가. 못 재면 그 사실이 나와야 한다.
Add-Check "여유 공간을 재서 보고한다" `
    (($planOnly.text -match "볼륨 C:") -and ($planOnly.text -notmatch "알 수 없음")) `
    "계획에 볼륨별 필요·여유 표시"

Add-Check "System32 는 끝까지 깨끗하다" (-not (Test-Path $guardBait)) $guardBait

# ── 6. 조직 복구 키로 꺼내기 (다른 머신 경로) ─────────────────
# 재설치 후에는 원래 자리도 원래 SID 도 없다. 되찾아야 하는 것은 내용이다.
$extractDir = Join-Path $DestPrefix "..\p5-extract"
Remove-Tree $extractDir
$ex = Invoke-Remedy @("restore", "--container", $Container, "--org-key-file", $OrgKeyFile,
                      "--state-dir", $StateDir, "--extract-to", $extractDir, "--yes")
$extracted = @()
if (Test-Path $extractDir) { $extracted = @(Get-ChildItem $extractDir -File) }
Add-Check "조직 키로 다른 머신에서 꺼낸다(0)" ($ex.exit -eq 0) "exit=$($ex.exit)"
Add-Check "보호 경로 항목도 꺼내기는 된다" ($extracted.Count -eq 7) "$($extracted.Count)/7 파일"
Add-Check "꺼내기는 원본 자리에 쓰지 않는다" (-not (Test-Path $guardBait)) $guardBait

# ── 7. 변조 탐지 ──────────────────────────────────────────────
# 뒤집은 바이트를 **실제로 읽는 자리**에서 봐야 한다. 처음에는 파일 끝에서
# 20바이트를 뒤집고 e0 만 복원했는데, 그 자리는 e4 블록이라 읽히지 않아
# 그대로 통과했다 — 시험이 아무것도 재지 않고 있었다.
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

function Test-Tamper {
    param([string] $Name, [int] $Offset)
    $p = Join-Path $StateDir "tampered-$Offset.rq"
    $raw = [System.IO.File]::ReadAllBytes($Container)
    $raw[$Offset] = $raw[$Offset] -bxor 0xFF
    [System.IO.File]::WriteAllBytes($p, $raw)
    $r = Invoke-Remedy @("restore", "--container", $p, "--passphrase-file", $PassphraseFile,
                         "--state-dir", $StateDir, "--entry", "e0", "--yes")
    Add-Check $Name ($r.exit -ne 0) "offset=$Offset exit=$($r.exit)"
}

$len = (Get-Item $Container).Length
# 헤더 JSON 안. 헤더는 모든 봉인의 AAD 이므로 색인부터 열리지 않아야 한다.
Test-Tamper "변조: 평문 헤더" 20
# 파일 한가운데. e0 의 본문이 4096바이트라 여기는 확실히 e0 블록 안이다.
Test-Tamper "변조: e0 본문" ([int]($len / 2))

# ── 결과 ──────────────────────────────────────────────────────
$pass = @($results | Where-Object { $_.pass }).Count
$total = $results.Count
Write-Host ""
Write-Host ("판정: {0}/{1}" -f $pass, $total) -ForegroundColor $(if ($pass -eq $total) { "Green" } else { "Red" })

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$report = [ordered]@{
    schema     = "remedy-lab.verify-p5/1"
    verified_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    passed     = $pass
    total      = $total
    checks     = $results
}
$json = $report | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText((Join-Path $OutDir "verify-p5.json"), $json,
                               (New-Object System.Text.UTF8Encoding($false)))

if ($pass -ne $total) { exit 1 }
exit 0
