#Requires -Version 5.1
<#
.SYNOPSIS
    설계-09 P4 의 판정 요건을 테스트 VM 에서 확인한다 — subject 수집·토큰·YARA.

.DESCRIPTION
    **읽기만 한다.** 파괴 Op 은 P4 의 범위가 아니고, 이 스크립트가 만드는 것은
    실험대 파일 몇 개뿐이다.

    여기서 재는 것은 "subject 마다 수집기가 **이 기계에서** 도는가" 다. 개발
    호스트에서 도는 것과 갓 설치한 Windows 에서 도는 것은 다르다 — 개발 호스트에는
    브라우저·프로필·인증서가 잔뜩 있어 수집기가 비어 있어도 티가 나지 않는다.

    **빈 결과를 통과로 세지 않는다.** 어느 Windows 에나 있는 subject 는 0건이면
    실패다. 없을 수 있는 것(이동식 매체, 브라우저 확장)은 따로 가른다.

.PARAMETER Bin
    remedy.exe 경로.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $Plugin,
    [Parameter(Mandatory = $true)][string] $OutDir,
    [string] $LabRoot = "C:\remedy-lab"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$results = New-Object System.Collections.ArrayList
$Fix = "$LabRoot\p4-fix"

function Add-Check {
    param([string] $Name, [bool] $Pass, [string] $Detail)
    [void]$results.Add([pscustomobject]@{ name = $Name; pass = $Pass; detail = $Detail })
    $mark = if ($Pass) { "OK  " } else { "실패" }
    $color = if ($Pass) { "Green" } else { "Red" }
    Write-Host ("  {0} {1,-46} {2}" -f $mark, $Name, $Detail) -ForegroundColor $color
}

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
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    [pscustomobject]@{ exit = $p.ExitCode; text = $o.Result + $e.Result }
}

Write-Host "`n=== P4 검증 (subject 수집 · 토큰 · YARA) ===" -ForegroundColor Magenta
Write-Host "바이너리 : $Bin"
Write-Host ""

# ── 실험대 ────────────────────────────────────────────────────
# 파일 계열 subject 가 볼 것이 있어야 한다. 갓 설치한 Windows 의 `C:\remedy-lab`
# 에는 `.ini` 도 `.lnk` 도 없다.
if (Test-Path $Fix) { Remove-Item $Fix -Recurse -Force }
New-Item -ItemType Directory -Path $Fix -Force | Out-Null
[System.IO.File]::WriteAllText("$Fix\payload.js", "console.log('REMEDY-LAB-P4-MARKER');")
[System.IO.File]::WriteAllText("$Fix\settings.ini", "[boot]`nshell=REMEDY-LAB-P4-MARKER.exe`n")
[System.IO.File]::WriteAllText("$Fix\config.json", '{"name":"lab","perms":["all_urls"]}')

# 바로가기 하나. `.lnk` 수집기가 볼 것이 있어야 한다.
$sc = (New-Object -ComObject WScript.Shell).CreateShortcut("$Fix\lab.lnk")
$sc.TargetPath = "$env:SystemRoot\System32\notepad.exe"
$sc.Arguments = "--lab"
$sc.Save()

# ── 수집 ──────────────────────────────────────────────────────
$art = "$OutDir\artifacts.json"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$r = Invoke-Remedy @("collect", "--out", $art, "--plugin", $Plugin)
Add-Check "수집이 끝났다" (Test-Path $art) "exit=$($r.exit)"
if (-not (Test-Path $art)) {
    Write-Host $r.text
    throw "수집 산출물이 없다 — 이 아래는 잴 수 없다"
}
$json = [System.IO.File]::ReadAllText($art, [System.Text.Encoding]::UTF8) | ConvertFrom-Json

function Count-Of {
    param([string] $Subject)
    $v = $json.$Subject
    if ($null -eq $v) { return -1 }   # 담기지 않았다
    return @($v).Count
}

# ── subject 마다 ──────────────────────────────────────────────
#
# **어느 Windows 에나 있는 것**은 0건이면 실패다. 수집기가 통째로 실패해도
# 0건으로 보이므로, 0 을 통과로 세면 이 검증이 아무것도 재지 못한다.
$mustHave = @{
    "file"              = "실험대 파일"
    "autorun"           = "Run 키"
    "service"           = "서비스"
    "process"           = "프로세스"
    "registry_value"    = "선언된 Run 키의 값"
    "registry_key"      = "선언된 키"
    "text_config"       = "실험대 ini"
    "structured_config" = "실험대 json"
    "shortcut"          = "실험대 lnk"
    "cert_store"        = "신뢰 루트"
    "boot_config"       = "SafeBoot"
    "indicator"         = "파생 지표"
    "firewall_rule"     = "방화벽 규칙"
}
foreach ($s in ($mustHave.Keys | Sort-Object)) {
    $n = Count-Of $s
    Add-Check "$s 를 수집했다" ($n -gt 0) "$n 건 ($($mustHave[$s]))"
}

# **건수만 세면 파서가 죽어도 통과한다.** 규칙 812개를 전부 빈 레코드로 담아도
# 위 검사는 "812건" 으로 초록이다. 그것은 0건과 같은 실패다.
$fw = @($json.firewall_rule)
$parsed = @($fw | Where-Object { $_.direction -and $_.action })
Add-Check "방화벽 규칙이 파싱됐다" `
    ($fw.Count -gt 0 -and $parsed.Count -eq $fw.Count) `
    "$($parsed.Count)/$($fw.Count) 건에 방향·동작이 있다"
# 어느 Windows 에나 In 과 Out 이 함께 있다. 한쪽만 나오면 파서가 절반을 흘린 것이다.
Add-Check "방향이 둘 다 나온다" `
    ((@($fw | Where-Object { $_.direction -eq 'In' }).Count -gt 0) -and
     (@($fw | Where-Object { $_.direction -eq 'Out' }).Count -gt 0)) `
    ("In {0} · Out {1}" -f @($fw | Where-Object { $_.direction -eq 'In' }).Count,
                            @($fw | Where-Object { $_.direction -eq 'Out' }).Count)
# 규칙 상당수가 실행 파일에 걸린다. 하나도 없으면 `App=` 을 못 읽은 것이다.
Add-Check "실행 파일에 걸린 규칙을 읽었다" `
    (@($fw | Where-Object { $_.application }).Count -gt 0) `
    "$(@($fw | Where-Object { $_.application }).Count) 건"

# **없을 수 있는 것.** 담기기는 해야 하고(빈 배열), 건수는 묻지 않는다 —
# 갓 설치한 Windows 에는 브라우저 프로필도 Defender 제외도 없을 수 있다.
foreach ($s in @("persistence", "browser_extension", "av_exclusion", "proxy_config")) {
    $n = Count-Of $s
    Add-Check "$s 가 담겼다(0건 허용)" ($n -ge 0) "$n 건"
}

# `hosts_entry` 는 건수로 잴 수 없다. **깨끗한 Windows 의 hosts 는 주석뿐**이라
# 0건이 정상이고, 실제로 VM 에서 0건이었다. 그렇다고 "0건 허용" 으로 두면
# 수집기가 통째로 실패해도 통과한다.
#
# 그래서 **remedy 를 쓰지 않고 직접 센다.** 검증자가 피검증자를 신뢰하면 검증이
# 아니다 — 이 하네스의 원칙 그대로다.
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$expected = -1
if (Test-Path $hostsPath) {
    $expected = @([System.IO.File]::ReadAllLines($hostsPath) | ForEach-Object {
        ($_ -split '#')[0].Trim()
    } | Where-Object { $_ -and (($_ -split '\s+').Count -ge 2) }).Count
}
$got = Count-Of "hosts_entry"
Add-Check "hosts_entry 가 직접 센 것과 같다" ($got -ge 0 -and $got -eq $expected) `
    "수집 $got 건 · 직접 센 것 $expected 건"

# **미수집이 하나도 없어야 한다** (설계-01 D11).
#
# `network_conn` 이 카탈로그에 있던 동안은 이 실행이 언제나 미수집 하나를 달고
# 나왔고, 그래서 **깨끗한 PC 가 0(위협 없음)이 아니라 6(관측 불완전)으로** 끝났다.
# 그것이 사라졌는지 실기기에서 본다.
#
# 종료 코드로 재지 않는 이유: 6 을 면하려면 `denied_dirs` 도 0 이어야 하는데
# 실기기에서 접근 거부는 정상적으로 생긴다. 여기서 재는 것은 **미수집 사유**다.
$unseen = @([regex]::Matches($r.text, "subject '([^']+)' 는 수집되지 않았(?:다|습니다)") |
            ForEach-Object { $_.Groups[1].Value })
Add-Check "미수집 subject 가 없다" ($unseen.Count -eq 0) `
    $(if ($unseen.Count) { $unseen -join ' · ' } else { "선언한 것이 전부 담겼다" })

# **폐기된 id 는 이유를 달고 거절되어야 한다** (설계-01 D11).
#
# 그냥 "모르는 subject" 로 거절하면 작성자는 오타를 의심하고, 철자를 고쳐 보고,
# 결국 같은 제안을 다시 들고 온다. 뺐다는 사실과 이유가 그 자리에서 나와야 한다.
$src = [System.IO.File]::ReadAllText($Plugin, [System.Text.Encoding]::UTF8)
$mutated = $src -replace '(?m)^(\s*)- indicator\s*$', "`$1- indicator`n`$1- network_conn"
if ($mutated -eq $src) {
    Add-Check "폐기 시험 재료를 만들었다" $false "플러그인에 '- indicator' 줄이 없다"
} else {
    $badPlugin = "$Fix\retired.yaml"
    [System.IO.File]::WriteAllText($badPlugin, $mutated)
    $lint = Invoke-Remedy @("plugin", "lint", $badPlugin)
    Add-Check "폐기된 subject 를 쓰면 거절된다" ($lint.exit -ne 0) "exit=$($lint.exit)"
    Add-Check "왜 뺐는지 말한다" `
        (($lint.text -match "카탈로그에서 빠졌다") -and ($lint.text -match "판정 입력이 아니다")) `
        "폐기 사유 문구"
}

# ── 지정 확장 토큰 ────────────────────────────────────────────
$roots = @($json.scope.scan_roots)
Add-Check "%ALLUSERPROFILES% 가 프로필로 펼쳐졌다" `
    (@($roots | Where-Object { $_ -match '(?i)\\Users\\[^\\]+\\AppData' }).Count -ge 1) `
    (@($roots | Where-Object { $_ -match '(?i)\\Users\\' }).Count.ToString() + " 개")
Add-Check "HKU\* 가 SID 로 펼쳐졌다" `
    (@($roots | Where-Object { $_ -match '(?i)^HKU\\S-1-' }).Count -ge 1) `
    (@($roots | Where-Object { $_ -match '(?i)^HKU\\' }).Count.ToString() + " 개")
Add-Check "펼쳐지지 않은 토큰이 남지 않았다" `
    (@($roots | Where-Object { $_ -match '%|\*' }).Count -eq 0) `
    ((@($roots | Where-Object { $_ -match '%|\*' }) -join ' ') + "(없어야 한다)")
# 이동식 매체는 없을 수 있다. **없다는 사실이 보고되는지**를 본다.
Add-Check "%REMOVABLE% 의 결과가 보고된다" `
    (($r.text -match "이동식 매체가 없습니다") -or (@($roots | Where-Object { $_ -match '^[D-Z]:' }).Count -ge 1)) `
    "펼쳐졌거나, 없다고 말했거나"

# ── collect_extra · YARA ──────────────────────────────────────
$blobs = @($json.blobs.PSObject.Properties | ForEach-Object { $_.Name })
Add-Check "collect_extra 가 본문을 담았다" ($blobs.Count -ge 1) "$($blobs.Count) 건"
$linked = @($json.file | Where-Object { $_.content_ref })
Add-Check "본문이 파일 레코드에 이어졌다" ($linked.Count -ge 1) "$($linked.Count) 건"

# ── 결과 ──────────────────────────────────────────────────────
$pass = @($results | Where-Object { $_.pass }).Count
$total = $results.Count
Write-Host ""
Write-Host ("판정: {0}/{1}" -f $pass, $total) -ForegroundColor $(if ($pass -eq $total) { "Green" } else { "Red" })

$report = [ordered]@{
    schema      = "remedy-lab.verify-p4/1"
    verified_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    passed      = $pass
    total       = $total
    checks      = $results
}
[System.IO.File]::WriteAllText((Join-Path $OutDir "verify-p4.json"),
    ($report | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))

if ($pass -ne $total) { exit 1 }
exit 0
