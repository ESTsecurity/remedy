<#
.SYNOPSIS
    룰이 늘어도 버티는가 — 합성 룰 N 개(기본 1,000)로 메뉴의 *모두 검사만* 을 랩 VM 의 진짜 콘솔에서 잰다
    (목표 remedy_전체검사_운영기반 기준 6). 리눅스 짝은 `linux\bench-scan-all.sh` 다.

.DESCRIPTION
    **합성 룰은 실제 룰의 복제다.** Windows 배포 룰(`xtask threats --dirs windows`) 가운데 이 기계를 보는 것에서
    네트워크 점검 · 데이터 룰과 디스크 전체를 도는 룰(`%FIXED_DISKS%` — 한 번에 수십 초라 수로 곱하면 그것만
    잰다)을 빼고, 남은 것을 차례로 돌려 N 개를 짓는다. id 앞에 `bNNNN-` 를 붙이고 이름 끝에 ` #N` 을 단다 —
    검사 범위 · 술어 · YARA 는 그대로라 한 룰의 비용은 실제 룰의 것이다.

    조립은 메뉴 하네스(`Invoke-MenuVerify.ps1`)와 같다 — 일회용 키쌍 → 앵커 박은 release 빌드(공유 산출물은
    곧바로 되돌린다) → 서명(`sign plugin` 에 `--dir` 을 여러 번 — 키를 한 번만 푼다) → `xtask package`. 같은
    조립을 **템플릿 하나씩**(룰 수 = 템플릿 수)으로도 지어 견줄 기준으로 쓴다. **빌드는 VM 을 켜기 전에 한다** —
    둘을 겹치면 커밋 여유가 모자란다.

    꾸러미는 압축 하나로 옮긴다 — 파일 수천 개를 WinRM 으로 하나씩 보내지 않는다. VM 은 스냅숏으로 되돌린
    깨끗한 상태라 찾는 것은 없다. 게스트는 `guest\Verify-Menu.ps1 -Bench` 가 잰다 — 고르는 화면에서
    그만두기(서명 확인 N 개 · 화면 그리기까지) · 모두 검사만(시간 · 최대 메모리 · 화면 줄 · 요약 줄) · 결과
    폴더 크기.

    **판정은 '끝까지 돌았는가' 만이다** — 시간 · 메모리 · 메뉴의 한도는 잰 값을 보고 정한다.

.EXAMPLE
    .\Invoke-ScanAllBench.ps1
    .\Invoke-ScanAllBench.ps1 -Count 200 -NoRevert
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [int] $Count = 1000,
    [string] $VmAddress,
    [pscredential] $Credential,
    [string] $LabRoot = "C:\remedy-lab",
    [string] $Snapshot,
    [string] $Vmx,
    # 되돌리지 않고 지금 켜진 VM 에서 잰다.
    [switch] $NoRevert
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot "VmSession.ps1")

$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$Vmx       = Resolve-LabValue $Vmx 'windows_lab' 'windows_lab.identity.vmx' 'Vmx'
$Snapshot  = Resolve-LabValue $Snapshot 'windows_lab' 'windows_lab.snapshots.current' 'Snapshot'

$triple    = "x86_64-pc-windows-msvc"
$binPath   = Join-Path $repoRoot "target\$triple\release\remedy.exe"
$xtaskExe  = Join-Path $repoRoot "target\debug\xtask.exe"
$runTag    = "bench-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$hostOut   = Join-Path $repoRoot "testbed\harness\results\$runTag"
$benchStage = Join-Path $env:TEMP ("remedy-bench-" + (Get-Date -Format "yyyyMMddHHmmss"))
$plainBak  = Join-Path $benchStage "remedy-plain.exe"
$savedPw   = $env:REMEDY_SIGN_PASSWORD
$hadBin    = Test-Path $binPath
$session   = $null
New-Item -ItemType Directory -Force $hostOut, $benchStage | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem

# `xtask` 를 부르고 표준 출력 줄만 돌려준다. stderr 는 PowerShell 5.1 이 ErrorRecord 로 감싸 `Stop` 아래에서
# 스크립트를 죽이므로(`Invoke-CargoBuild` 의 주석과 같은 까닭) 잠깐 `Continue` 로 받고, 실패했을 때만 찍는다.
function Invoke-Xtask {
    param([Parameter(Mandatory = $true)][string] $What, [Parameter(Mandatory = $true)][string[]] $Argv)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = & $xtaskExe @Argv 2>&1
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($rc -ne 0) {
        $out | ForEach-Object { Write-Host "    $_" }
        throw "$What 실패 (exit $rc)"
    }
    @($out | Where-Object { $_ -is [string] })
}

# 꾸러미 하나 — 이름 · 룰 수. 경로는 짧은 상대 경로로 넘긴다 — 룰 1,000개면 인자가 2,000개라 Windows 명령줄
# 한도(32,767 글자) 안에 두려면 짧아야 한다.
function New-BenchPackage {
    param([string] $Name, [int] $N, [string[]] $Templates)
    $pkgRoot = Join-Path $benchStage $Name
    New-Item -ItemType Directory -Force (Join-Path $pkgRoot "r") | Out-Null
    $rel = New-Object System.Collections.Generic.List[string]
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    for ($i = 1; $i -le $N; $i++) {
        $id = 'b{0:D4}' -f $i
        $dst = Join-Path $pkgRoot "r\$id"
        Copy-Item -LiteralPath $Templates[($i - 1) % $Templates.Count] -Destination $dst -Recurse -Force
        foreach ($m in @("MANIFEST", "MANIFEST.minisig")) {
            Remove-Item -LiteralPath (Join-Path $dst $m) -Force -ErrorAction SilentlyContinue
        }
        # id 앞에 bNNNN- · 이름 블록(`name:` 아래 ko · en)의 값 끝에 ` #N` — 나머지 줄은 그대로다.
        $yp = Join-Path $dst "plugin.yaml"
        $inName = $false
        $lines = foreach ($line in ([System.IO.File]::ReadAllText($yp) -split "`n")) {
            if ($line -match '^id: (.+)$') { "id: $id-$($Matches[1])"; continue }
            if ($line -match '^name:') { $inName = $true; $line; continue }
            if ($inName -and $line -match '^  (ko|en): "(.*)"(\r?)$') {
                "  $($Matches[1]): `"$($Matches[2]) #$i`"$($Matches[3])"
                continue
            }
            if ($line -match '^\S') { $inName = $false }
            $line
        }
        [System.IO.File]::WriteAllText($yp, ($lines -join "`n"), $utf8)
        $rel.Add("r\$id")
    }
    Push-Location $pkgRoot
    try {
        $signArgs = @("sign", "plugin") + @($rel | ForEach-Object { "--dir"; $_ }) +
                    @("--secret-key", (Join-Path $benchStage "sec.key"), "--signed-at", "2026-11-16T00:00:00Z")
        $null = Invoke-Xtask "$Name 서명" $signArgs
        $pkgArgs = @("package") + @($rel | ForEach-Object { "--plugin"; $_ }) +
                   @("--bin", (Join-Path $benchStage "remedy.exe"), "--out", "pkg",
                     "--public-key", (Join-Path $benchStage "pub.key"))
        $null = Invoke-Xtask "$Name 꾸러미" $pkgArgs
    } finally { Pop-Location }
    $files = @(Get-ChildItem -LiteralPath (Join-Path $pkgRoot "pkg") -Recurse -File)
    $zip = Join-Path $pkgRoot "pkg.zip"
    [System.IO.Compression.ZipFile]::CreateFromDirectory((Join-Path $pkgRoot "pkg"), $zip)
    [pscustomobject]@{
        rules     = $N
        files     = $files.Count
        bytes     = [long](($files | Measure-Object -Property Length -Sum).Sum)
        zip_bytes = (Get-Item -LiteralPath $zip).Length
    }
}

$metrics = [ordered]@{ count = $Count }
$ok = $true
try {
    # ── 1. 빌드 — VM 을 켜기 전에 ────────────────────────────────────
    Write-Step "일회용 키 · 앵커 박은 빌드 (VM 을 켜기 전에)"
    $env:REMEDY_SIGN_PASSWORD = "bench-scan-all-ephemeral"
    Push-Location $repoRoot
    try {
        Invoke-CargoBuild "xtask" @("build", "-q", "-p", "xtask")
        $null = Invoke-Xtask "키 생성" @("sign", "keygen", "--public-key", (Join-Path $benchStage "pub.key"),
                                         "--secret-key", (Join-Path $benchStage "sec.key"))
        $anchor = (Get-Content (Join-Path $benchStage "pub.key"))[1].Trim()
        if ($hadBin) { Copy-Item $binPath $plainBak -Force }
        $env:REMEDY_TRUST_ANCHOR = $anchor
        try {
            Invoke-CargoBuild "앵커 박은 remedy.exe" @("build", "-q", "--release", "--target", $triple, "-p", "remedy-cli")
        } finally { $env:REMEDY_TRUST_ANCHOR = $null }
        Copy-Item $binPath (Join-Path $benchStage "remedy.exe") -Force
        # **곧바로 되돌린다** — 다른 하네스가 이 자리의 앵커 없는 바이너리를 배포한다.
        if ($hadBin) { Copy-Item $plainBak $binPath -Force }
        Write-Ok "앵커 박은 바이너리 (공유 산출물은 되돌렸다)"
        $listed = Invoke-Xtask "룰 목록" @("threats", "--dirs", "windows")
    } finally { Pop-Location }

    $templates = @($listed | Where-Object { $_ } | ForEach-Object { Join-Path $repoRoot $_ } | Where-Object {
        $y = [System.IO.File]::ReadAllText((Join-Path $_ "plugin.yaml"))
        (-not ($y -match '(?m)^(network:|kind: data)')) -and (-not $y.Contains('%FIXED_DISKS%'))
    })
    if ($templates.Count -eq 0) { throw "템플릿이 없다 — xtask threats --dirs windows 를 볼 것" }
    $metrics.templates = $templates.Count
    $metrics.template_names = ($templates | ForEach-Object { Split-Path -Leaf $_ }) -join " "
    Write-Ok "템플릿 $($templates.Count)개: $($metrics.template_names)"

    # ── 2. 꾸러미 둘 — 템플릿 하나씩(기준) · N 개 ─────────────────────
    $packs = [ordered]@{}
    foreach ($p in @([pscustomobject]@{ name = "small"; n = $templates.Count },
                     [pscustomobject]@{ name = "big"; n = $Count })) {
        Write-Step "꾸러미 $($p.name) — 룰 $($p.n)개"
        $packs[$p.name] = New-BenchPackage -Name $p.name -N $p.n -Templates $templates
        $pk = $packs[$p.name]
        Write-Ok ("파일 {0} · {1:N1} MB · 압축 {2:N1} MB" -f $pk.files, ($pk.bytes / 1MB), ($pk.zip_bytes / 1MB))
    }

    # ── 3. VM — 깨끗한 스냅숏 ───────────────────────────────────────
    if (-not $NoRevert) {
        & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
    }
    $session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential
    Copy-GuestFile -Session $session -Source (Join-Path (Split-Path -Parent $PSScriptRoot) "guest\Verify-Menu.ps1") `
                   -Destination "$LabRoot\scripts\Verify-Menu.ps1"

    # ── 4. 잰다 ─────────────────────────────────────────────────────
    foreach ($name in @("small", "big")) {
        Write-Step "벤치 $name — 진짜 콘솔에서 고르는 화면 · 모두 검사만"
        Invoke-Command -Session $session -ArgumentList $LabRoot, $name -ScriptBlock {
            param($lab, $n)
            Get-Process remedy -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill() } catch { } }
            Remove-Item "$lab\bench\$n" -Recurse -Force -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Force "$lab\bench" | Out-Null
        }
        Copy-Item (Join-Path $benchStage "$name\pkg.zip") -Destination "$LabRoot\bench\$name.zip" -ToSession $session -Force
        Invoke-Command -Session $session -ArgumentList $LabRoot, $name -ScriptBlock {
            param($lab, $n)
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory("$lab\bench\$n.zip", "$lab\bench\$n")
            Remove-Item "$lab\bench\$n.zip" -Force
        }
        $rc = Invoke-GuestScript -Session $session -Root $LabRoot -ScriptName "Verify-Menu.ps1" -Arguments @(
            "-Bin", "$LabRoot\bench\$name\remedy.exe", "-PayloadDir", "$LabRoot\bench\no-payload",
            "-OutFile", "$LabRoot\bench\$name-result.json", "-TranscriptFile", "$LabRoot\bench\$name-screens.txt",
            "-Bench") -PassThruExitCode
        if ($rc -ne 0) { Write-Warn "게스트 스크립트 종료 $rc" }
        foreach ($f in @("$name-result.json", "$name-screens.txt")) {
            Copy-Item "$LabRoot\bench\$f" -Destination (Join-Path $hostOut $f) -FromSession $session -Force
        }
        $r = Get-Content (Join-Path $hostOut "$name-result.json") -Raw -Encoding UTF8 | ConvertFrom-Json
        $b = $r.bench
        $pk = $packs[$name]
        $per = $(if ($pk.rules -gt 0) { [math]::Round(($b.scan_all.secs - $b.start.secs) * 1000 / $pk.rules) } else { 0 })
        foreach ($kv in @(
                @("rules", $pk.rules), @("pkg_files", $pk.files), @("pkg_bytes", $pk.bytes), @("zip_bytes", $pk.zip_bytes),
                @("start_secs", $b.start.secs), @("start_chooser_lines", $b.start.chooser_lines),
                @("start_peak_ws_kib", $b.start.peak_ws_kib), @("scan_all_secs", $b.scan_all.secs),
                @("scan_all_exit", $b.scan_all.exit), @("scan_all_timed_out", $b.scan_all.timed_out),
                @("scan_all_peak_ws_kib", $b.scan_all.peak_ws_kib), @("scan_all_lines", $b.scan_all.lines),
                @("scan_all_summary", $b.scan_all.summary), @("scan_all_listed", $b.scan_all.listed),
                @("out_bytes", $b.out_bytes),
                @("state_bytes", $b.state_bytes), @("out_dirs", $b.out_dirs), @("per_rule_ms", $per))) {
            $metrics["${name}_$($kv[0])"] = $kv[1]
        }
        $runOk = (-not $b.scan_all.timed_out) -and (@(0, 2, 6) -contains [int]$b.scan_all.exit) -and
                 ([int]$b.scan_all.summary -eq $pk.rules)
        if (-not $runOk) { $ok = $false }
        $line = "{0}: 고르는 화면 {1}초 · {2}줄 · 모두 검사만 {3}초(룰당 {4} ms) · 종료 {5} · 최대 {6:N0} MB · 요약 {7}줄" -f `
                $name, $b.start.secs, $b.start.chooser_lines, $b.scan_all.secs, $per, $b.scan_all.exit,
                ($b.scan_all.peak_ws_kib / 1KB), $b.scan_all.summary
        if ($runOk) { Write-Ok $line } else { Write-Bad $line }
    }
} catch {
    $ok = $false
    Write-Bad $_.Exception.Message
} finally {
    # 치운다 — 랩의 꾸러미 · 일회용 키 · 앵커 바이너리. 공유 산출물은 한 번 더 되돌린다.
    if ($session) {
        try {
            Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
                param($lab)
                Get-Process remedy -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill() } catch { } }
                Remove-Item "$lab\bench" -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch { Write-Warn "랩의 벤치 폴더를 치우지 못했다: $($_.Exception.Message)" }
        Remove-PSSession $session -ErrorAction SilentlyContinue
    }
    if ($hadBin -and (Test-Path $plainBak)) { Copy-Item $plainBak $binPath -Force }
    $env:REMEDY_SIGN_PASSWORD = $savedPw
    # 지우는 자리는 이 스크립트가 지은 임시 폴더뿐이다 — 뿌리를 확인한 뒤에만 지운다.
    if ($benchStage -like (Join-Path $env:TEMP "remedy-bench-*")) {
        Remove-Item -LiteralPath $benchStage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$metricsText = ($metrics.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n"
[System.IO.File]::WriteAllText((Join-Path $hostOut "metrics.txt"), $metricsText + "`n",
                               (New-Object System.Text.UTF8Encoding($false)))
Write-Host ""
Write-Host $metricsText
Write-Host "결과: $hostOut"
if ($ok) { exit 0 } else { exit 1 }
