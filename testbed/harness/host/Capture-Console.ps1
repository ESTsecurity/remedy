#Requires -Version 5.1
<#
.SYNOPSIS
    콘솔 화면 전수를 랩 VM 에서 받는다 — 화면을 바꾸는 회차의 기준선과 비교 대상.

.DESCRIPTION
    `docs/design/콘솔은-이렇게-보인다.md` 를 만든 캡처다. 화면을 고치는 회차마다
    이것을 다시 돌려 `cargo xtask console-diff <이번 캡처>` 로 견준다 —
    의도한 줄 외에 달라진 줄이 0 이어야 한다.

    **stdin 을 재지정하고 곧바로 닫는다.** `run` 은 `--yes` 없이 승인을 기다리는데,
    재지정하지 않으면 그 프롬프트 앞에서 영원히 선다 — 2026-09-07 에 5시간 26분
    그렇게 섰다. 그래서 이 캡처는 "승인할 사람이 없습니다" 갈래를 재고, 사람이 있는
    갈래는 Approve-Interactive.ps1 이 잰다.

    stdout 을 먼저, stderr 를 나중에 잇는다. 실제 콘솔에서는 나온 순서대로 섞인다.

    회차 로그 발췌에서는 심장박동 줄을 뺀다 — 몇 줄이 찍히는지가 시간에 달려
    있어 `-TotalCount` 로 자르면 발췌의 내용이 실행마다 달라진다.

    잘라 내는 창(`Select-Object -First N`)은 넉넉히 잡는다. 좁으면 화면에 한 줄이
    더해질 때 창 밖으로 한 줄이 밀려나고, 그것이 diff 에는 **삭제**로 보인다 —
    진짜 삭제를 그 뒤에 숨길 수 있는 사각지대다 (2026-09-08 Phase 1 에서 실제로
    밟았다).

.PARAMETER Out
    결과 파일. 기본 results\console-<시각>-win.txt. UTF-8(BOM 없음).

.PARAMETER Build
    먼저 릴리스 빌드를 한다. 아니면 target\x86_64-pc-windows-msvc\release\remedy.exe
    를 그대로 배포한다 — **코드를 고쳤으면 반드시 켤 것.**

    # 끄고 부르면 **한 캡처 안에서 바이너리가 둘이 된다** (2026-10-28 에 밟았다)

    대부분의 절은 위 경로의 산출물을 그대로 배포하는데, **B2(서명된 꾸러미)만
    그 자리에서 `Invoke-CargoBuild` 로 다시 짓는다** — 앵커를 박아야 하기
    때문이다. 그래서 화면 문구를 고치고 `-Build` 없이 캡처하면 **B2 한 절만 새
    문구, 나머지는 옛 문구**인 기준선이 나온다. 그 기준선은 어느 바이너리와도
    맞지 않는데 `console-diff` 는 "바뀐 줄 1건" 으로 보여 **의도한 변경처럼
    읽힌다.** 실제로 그렇게 한 번 올릴 뻔했다.

    리눅스 쪽(`capture-console.sh`)은 컨테이너 안에서 매번 짓기 때문에 이
    함정이 없다 — 두 캡처를 견줘 숫자가 어긋나면 이쪽을 먼저 의심할 것.
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [string] $LabRoot = "C:\remedy-lab",
    # 화면의 언어. **기본은 `ko`** 라 주지 않으면 지금까지와 한 글자도 다르지
    # 않다 — 기준선 `console-win.txt` 가 그 위에 서 있다.
    #
    # `-Lang en` 으로 부르면 영어 화면을 한 벌 받는다. 영어로 돌렸는데 한글이
    # 남는 줄이 곧 이중 언어가 빠진 자리다 (2026-09-16, 리눅스와 같은 방법).
    #
    # **언어가 일부러 박힌 절 셋은 따라오지 않는다** — A2(사용법 한국어) ·
    # A7 의 한국어 갈래 · C1(scan 한국어). 셋 다 짝이 되는 영어 절이 있고,
    # 둘을 나란히 보이는 것이 그 절의 목적이다.
    #
    # C3 의 `--lang` 줄도 언어가 박혀 있지만 뜻이 다르다 — 거기서 재는 것은
    # 화면의 언어가 아니라 **플래그가 환경변수를 이기는가** 이고, 그것은 둘이
    # 어긋날 때만 보인다.
    [ValidateSet("ko", "en")] [string] $Lang = "ko",
    [string] $Out,
    [switch] $Build
)

$ErrorActionPreference = "Stop"

# `G` 의 param 기본값이 이 값을 읽는다 — 함수 정의보다 먼저 정해져야 한다.
$L = $Lang
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$triple = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"
if (-not $Out) {
    $Out = Join-Path $repoRoot ("testbed\harness\results\console-{0}-win.txt" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
}
New-Item -ItemType Directory -Force (Split-Path -Parent $Out) | Out-Null

. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
. (Join-Path $PSScriptRoot "InfectedState.ps1")

# 줄마다 파일에 덧붙인다 — 도중에 죽어도 그때까지의 화면은 남는다.
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($Out, "", $utf8)
function Emit {
    param([string] $Text)
    $flat = ($Text -replace "`r`n", "`n").TrimEnd()
    [System.IO.File]::AppendAllText($Out, $flat + "`n", $utf8)
    Write-Host $flat
}
$started = Get-Date
function Sep {
    param([string] $Title)
    $el = [int]((Get-Date) - $started).TotalSeconds
    Emit ""
    Emit ("########## {0}   [{1}초]" -f $Title, $el)
    Emit ""
}

if ($Build) {
    Write-Host "빌드: remedy.exe ($triple)"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
    } finally { Pop-Location }
}
if (-not (Test-Path $binPath)) { throw "바이너리가 없다: $binPath  (-Build 로 만들 것)" }

$session = Connect-LabVm -VmAddress $VmAddress 6>$null

# ── 전제 — 랩에 남의 감염이 없는가 (2026-09-14) ───────────────────
#
# **캡처를 시작하기 전에 본다.** 이 하네스는 스냅샷을 되돌리지 않고, 그
# 산출물은 **콘솔 기준선이 된다** — 남의 흔적이 섞인 화면이 기준선이 되면
# 그 뒤로 모든 회차가 그것과 견준다.
#
# 처음에는 B(감염) 절 앞에 두었는데, A 절 여덟이 그보다 앞이라 **148초를
# 쓴 뒤에야** 멈췄다(2026-09-14 실측). 전제는 재기 전에 보는 것이고,
# 여기가 세션이 열리는 첫 자리다.
#
# `Write-Step`/`Write-Ok` 는 화면만 쓰므로 기준선에 줄이 늘지 않는다.
$payloadDir = Invoke-Command -Session $session -ScriptBlock {
    Join-Path $env:LOCALAPPDATA "Programs\MicrosoftResourcesAgentV12"
}
Assert-NoForeignInfection -Session $session -PayloadDir $payloadDir

$Bin = "$LabRoot\bin\remedy.exe"
$Plugin = "$LabRoot\plugins\evilai-locust\plugin.yaml"
$State = "$LabRoot\state-console"
# 심장박동 절의 두 번째 치료가 쓰는 자리. **따로 둔다** — 같은 폴더에 넣으면
# K 절의 회차 목록이 한 줄 늘고, 그것은 화면이 아니라 캡처가 만든 차이다.
$BeatState = "$LabRoot\state-console-beat"

# 게스트에서 한 명령을 돌리고 stdout+stderr+종료 코드를 한 덩어리로 받는다.
function G {
    param([string[]] $Argv, [string] $Lang = $L, [int] $TimeoutSec = 300, [hashtable] $EnvVars = @{})
    Invoke-Command -Session $session -ArgumentList $Bin, $Argv, $Lang, $TimeoutSec, $EnvVars -ScriptBlock {
        param($exe, $argv, $lang, $timeout, $envs)
        function Quote-Arg { param([string] $A) if ($A -match '\s') { '"' + $A + '"' } else { $A } }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        $psi.Arguments = (@($argv) | ForEach-Object { Quote-Arg $_ }) -join ' '
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
        if ($lang) { $psi.EnvironmentVariables["REMEDY_LANG"] = $lang }
        foreach ($k in @($envs.Keys)) { $psi.EnvironmentVariables[$k] = [string]$envs[$k] }
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.StandardInput.Close()
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($timeout * 1000)) {
            $p.Kill(); $p.WaitForExit(5000) | Out-Null
            return "[$timeout 초 안에 끝나지 않았다]`n" + ($o.Result + $e.Result).TrimEnd()
        }
        (($o.Result + $e.Result).TrimEnd()) + "`n[exit=$($p.ExitCode)]"
    }
}

try {
    Sep "0. 바이너리 배포 · 잔재 정리"
    Copy-Item $binPath -Destination $Bin -ToSession $session -Force

    # **캡처가 쓰는 룰을 스스로 배포한다** (2026-09-10).
    #
    # 여기 없으면 캡처는 그 룰이 랩에 이미 있다고 가정한다. 기준 스냅샷은
    # 그것을 담고 있지 않아, 되돌린 기계에서 돌리면 C1 이후 절이 전부
    # `종료 코드 4`(plugin.yaml 을 찾을 수 없다)로 무너진다 — 실제로 그렇게
    # 무너졌고, 그전까지 통한 것은 **앞선 회차가 남긴 파일 덕**이었다.
    # 계측기가 자기 전제를 스스로 세우지 않으면 그 결과는 우연이다.
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        Remove-Item "$lab\plugins\evilai-locust" -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force "$lab\plugins" | Out-Null
    }
    Copy-Item (Join-Path $repoRoot "plugins\evilai-locust") `
        -Destination "$LabRoot\plugins\evilai-locust" -ToSession $session -Recurse -Force
    $deployed = Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        Get-Process remedy -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        foreach ($d in @("$lab\state-console", "$lab\state-console-beat", "$lab\out-console-scan",
                         "$lab\out-console-scan-en", "$lab\out-console-noone", "$lab\out-console-dry",
                         "$lab\out-console-run", "$lab\bundle-console")) {
            if (Test-Path $d) { Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue }
        }
        "배포·정리 완료 · " + (Get-Item "$lab\bin\remedy.exe").Length + " bytes"
    }

    # ── 보안 제품 예외를 고정한다 ────────────────────────────────────
    #
    # **G2 의 `복원 [e5] av_exclusions (… N건)` 은 제품이 아니라 이 기계를
    # 잰다.** remedy 는 `Get-MpPreference` 가 아니라 레지스트리의 세 종류
    # (Paths·Processes·Extensions)를 전부 세기 때문이다
    # (`remedy-platform/src/windows.rs` 의 `av_exclusions_read`).
    #
    # 2026-09-10 에 이 기계에 remedy 와 무관한 `Processes\dbeaver.exe` 하나가
    # 있어 3건이 4건이 되었고, 시연 준비가 남긴 예외 탓인 줄 알고 **캡처를 한
    # 번 더 받았다**(9분). 정규화로 덮을 수도 있었지만 그러면 `0건`(예외를 아예
    # 되돌리지 못한 경우) 같은 진짜 신호까지 가려진다. 그래서 **줄은 그대로
    # 두고 바닥을 고정한다.**
    #
    # 랩 경로 둘만 남기고 나머지는 잠시 내려 두었다가 `finally` 에서 되돌린다.
    # 남의 설정을 지우는 것이 아니라 캡처가 도는 동안만 비켜 두는 것이다.
    $AvApply = {
        param($paths, $procs, $exts)
        $cur = Get-MpPreference
        $curP = @($cur.ExclusionPath | Where-Object { $_ })
        $curR = @($cur.ExclusionProcess | Where-Object { $_ })
        $curE = @($cur.ExclusionExtension | Where-Object { $_ })
        foreach ($x in $paths) { if ($curP -notcontains $x) { Add-MpPreference -ExclusionPath $x -ErrorAction SilentlyContinue } }
        foreach ($x in $curP) { if ($paths -notcontains $x) { Remove-MpPreference -ExclusionPath $x -ErrorAction SilentlyContinue } }
        foreach ($x in $procs) { if ($curR -notcontains $x) { Add-MpPreference -ExclusionProcess $x -ErrorAction SilentlyContinue } }
        foreach ($x in $curR) { if ($procs -notcontains $x) { Remove-MpPreference -ExclusionProcess $x -ErrorAction SilentlyContinue } }
        foreach ($x in $exts) { if ($curE -notcontains $x) { Add-MpPreference -ExclusionExtension $x -ErrorAction SilentlyContinue } }
        foreach ($x in $curE) { if ($exts -notcontains $x) { Remove-MpPreference -ExclusionExtension $x -ErrorAction SilentlyContinue } }
        # **remedy 가 세는 방식 그대로 확인한다.** Get-MpPreference 로 세면
        # 종류를 놓치고, 그러면 고정했다고 믿는 채로 숫자가 또 갈라진다.
        $n = 0
        foreach ($leaf in @("Paths", "Processes", "Extensions")) {
            $k = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\$leaf"
            if (Test-Path $k) { $n += @((Get-Item $k).GetValueNames()).Count }
        }
        $n
    }

    # **여기서 죽으면 캡처가 통째로 선다.** 2026-09-10 에 되돌린 기계에서
    # `Get-MpPreference` 가 `0x800106ba` 로 떨어졌고(Defender 의 WMI 공급자가
    # 아직 준비되지 않았다), 이 스크립트의 `ErrorActionPreference = Stop`
    # 아래에서 그것이 곧바로 예외가 되어 **0절에서 캡처가 끝났다.**
    # 예외를 고정하지 못하는 것은 회차를 버릴 이유가 아니다 — 숫자 한 줄이
    # 기계를 타게 될 뿐이고, 그 사실은 아래 줄이 말한다.
    $avSaved = $null
    $avNow = -1
    $avWant = @()
    try {
        $avSaved = Invoke-Command -Session $session -ScriptBlock {
            $c = Get-MpPreference
            [pscustomobject]@{
                Paths      = @($c.ExclusionPath | Where-Object { $_ })
                Processes  = @($c.ExclusionProcess | Where-Object { $_ })
                Extensions = @($c.ExclusionExtension | Where-Object { $_ })
            }
        }
        $avWant = @($LabRoot, (Invoke-Command -Session $session -ScriptBlock { Join-Path $env:LOCALAPPDATA "Programs" }))
        $avNow = Invoke-Command -Session $session -ScriptBlock $AvApply -ArgumentList $avWant, @(), @()
        Write-Host "    예외 저장: 경로 $($avSaved.Paths.Count) · 프로세스 $($avSaved.Processes.Count) · 확장자 $($avSaved.Extensions.Count)"
    } catch {
        Write-Warn "예외를 고정하지 못했다: $($_.Exception.Message)"
    }
    # **성공하면 늘 같은 줄, 실패하면 다른 줄.** 고정이 조용히 실패하면 뒤의
    # 숫자가 갈라지는데, 그때 원인이 화면에 없으면 또 캡처를 다시 받게 된다.
    if ($avNow -eq $avWant.Count -and $avWant.Count -gt 0) {
        Emit "보안 제품 예외 : 랩 경로 2건으로 고정"
    } else {
        Emit "보안 제품 예외 : [고정하지 못했다 — 지금 $avNow 건]"
    }
    Emit $deployed

    Sep "A1. 사용법 — 기본 언어"
    Emit (G @("--help") "" 60)
    Sep "A2. 사용법 — 한국어"
    Emit (G @("--help") "ko" 60)
    Sep "A3. 버전"
    Emit (G @("--version") $L 60)

    # 안내 모드(Phase 4-3)는 **실행 파일 옆에 꾸러미가 있어야** 열린다. 위 절들은
    # $LabRoot\bin 에서 띄우므로 그 갈래가 보이지 않는다 — 안 보이는 것은 diff 에도
    # 나오지 않는다. 그래서 꾸러미 모양을 만들어 그 안에서 인자 없이 띄운다.
    #
    # **이 빌드에는 신뢰 앵커가 박혀 있지 않으므로 거절되는 것이 정답이다.**
    # 재는 것은 "거절이 어떤 모양인가" 이고, 서명이 실제로 통과하는 경로는
    # 앵커를 박아 빌드해야 하며 plugin verify 와 xtask package 가 그것을 잰다.
    Sep "A6. 안내 모드 — 꾸러미 옆에서 인자 없이 부르면"
    Emit (Invoke-Command -Session $session -ArgumentList $LabRoot, $Bin -ScriptBlock {
        param($lab, $bin)
        $pkg = "$lab\pkg"
        if (Test-Path $pkg) { Remove-Item $pkg -Recurse -Force }
        New-Item -ItemType Directory -Force "$pkg\plugins\demo\rules" | Out-Null
        Copy-Item $bin "$pkg\remedy.exe" -Force
        $yaml = @"
schema_version: 1
id: demo
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name: { ko: '보기용 위협 제거', en: 'demo threat removal' }
scan_roots: ['C:\demo']
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      - { field: path, op: ends_with, value: '.evil' }
verdict:
  require: 'junk'
"@
        $u8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText("$pkg\plugins\demo\plugin.yaml", $yaml, $u8)
        [System.IO.File]::WriteAllText("$pkg\plugins\demo\rules\d.yar", "rule d { condition: false }", $u8)

        function Say {
            param([string] $Exe, [string] $Cwd)
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $Exe
            $psi.WorkingDirectory = $Cwd
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.RedirectStandardInput = $true
            $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
            $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
            $psi.EnvironmentVariables["REMEDY_LANG"] = $using:L
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.StandardInput.Close()
            $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
            $p.WaitForExit(60000) | Out-Null
            (($o.Result + $e.Result).TrimEnd()) + "`n[exit=$($p.ExitCode)]"
        }

        $bare = "$lab\bare"
        if (Test-Path $bare) { Remove-Item $bare -Recurse -Force }
        New-Item -ItemType Directory -Force $bare | Out-Null
        Copy-Item $bin "$bare\remedy.exe" -Force

        $out = @(
            "꾸러미: remedy.exe · plugins\demo\{plugin.yaml, rules\d.yar} — 서명 없음"
            ""
            "[서명도 앵커도 없는 꾸러미]"
            (Say "$pkg\remedy.exe" $pkg)
            ""
            "[꾸러미가 아예 없는 자리 — 지금까지의 동작 그대로여야 한다]"
            # 자르지 않는다(README 규칙). -Last 4 는 화면을 가렸고, 사용법이
            # 줄어들면 창이 밀려 엉뚱한 줄이 지워진 것처럼 보였다.
            (Say "$bare\remedy.exe" $bare)
        ) -join "`n"
        Remove-Item $pkg, $bare -Recurse -Force -ErrorAction SilentlyContinue
        $out
    })

    # 창 유지(Phase 4-1)는 **stdin 이 터미널일 때만** 일어난다. G 는 stdin 을
    # 재지정하므로 그 갈래가 보이지 않는다 — 안 보이는 것은 diff 에도 나오지
    # 않는다. 그래서 진짜 콘솔을 만드는 별도 스크립트로 재고 결과를 여기 남긴다.
    Sep "A0. 인자 없이 부르면 창을 붙잡는가 (진짜 콘솔)"
    $dblOut = "$LabRoot\dblclick.json"
    Copy-Item (Join-Path $PSScriptRoot "..\guest\Verify-DoubleClick.ps1") `
        -Destination "$LabRoot\scripts\Verify-DoubleClick.ps1" -ToSession $session -Force
    Emit (Invoke-Command -Session $session -ArgumentList $LabRoot, $Bin, $dblOut -ScriptBlock {
        param($lab, $bin, $out)
        if (Test-Path $out) { Remove-Item $out -Force }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File "$lab\scripts\Verify-DoubleClick.ps1" -Bin $bin -OutFile $out *> $null
        if (-not (Test-Path $out)) { return "[결과 파일이 없다 — 콘솔을 만들지 못했다]" }
        $r = Get-Content $out -Raw | ConvertFrom-Json
        @(
            "인자 없이 (더블클릭과 같은 조건)"
            "  Enter 전에 기다렸는가   $($r.no_args.waited)"
            "  프롬프트가 나왔는가      $($r.no_args.prompted)"
            "  Enter 뒤 끝났는가        $($r.no_args.closed)  (종료 $($r.no_args.exit))"
            "인자가 있을 때 (RunOnce 의 재부팅 회차가 이 조건이다)"
            "  입력 없이 끝났는가       $($r.with_args.finished_without_input)"
            "  프롬프트가 나왔는가      $($r.with_args.prompted)"
            "판정: $($r.verdict)"
        ) -join "`n"
    })

    # **권한이 없을 때의 화면은 이 캡처에 없었다** (2026-09-10 에 더한 절).
    #
    # 캡처는 관리자 WinRM 세션에서 돌기 때문에 `admin_gate` 가 닫히는 법이
    # 없었다. 그래서 `need_admin()` — 받은 사람이 가장 먼저 만날 수 있는 벽 —
    # 은 기준선 어디에도 없었고, 그 문구를 고쳐도 `console-diff` 는 아무 말도
    # 하지 않았다. 2026-09-09 에 우클릭 안내를 넣었을 때도 그랬다.
    #
    # **계정을 새로 만들지 않는다.** 표준 사용자를 하나 파고 비밀번호를 들고
    # 다니는 길도 있지만, 그러면 랩에 자격 증명이 하나 더 생기고 스냅샷마다
    # 다시 만들어야 한다. `runas /trustlevel` 은 SAFER 로 **지금 토큰을 제한한
    # 사본**을 만든다 — 실측하면 `BUILTIN\Administrators` 가 *거부 전용*이 되고,
    # 그것이 정확히 `platform_elevated` 가 보는 조건이다 (System32\Tasks 를
    # 열어 보고 거부되면 `Some(false)`).
    Sep "A7. 권한이 없을 때 (비관리자)"
    Emit (Invoke-Command -Session $session -ArgumentList $Bin, $Plugin, $LabRoot -ScriptBlock {
        param($bin, $plugin, $lab)

        function Invoke-Restricted {
            param([string] $Lang)
            $out = "$lab\nonadmin-$Lang.txt"
            Remove-Item $out -Force -ErrorAction SilentlyContinue

            # **`/v:on` 이 있어야 한다.** cmd 는 `%errorlevel%` 를 줄을 읽을 때
            # 펼치므로 그대로 쓰면 remedy 가 돌기 **전**의 값(0)이 찍힌다 —
            # 이 절이 증명하려는 종료 코드 5 를 놓친다 (2026-09-10 에 밟았다).
            # 지연 확장 `!errorlevel!` 이라야 실행 뒤 값이 들어온다.
            $inner = 'cmd.exe /v:on /c set REMEDY_LANG=' + $Lang +
                     '&& "' + $bin + '" run --plugin "' + $plugin + '"' +
                     ' --out-dir "' + $lab + '\na-out" --state-dir "' + $lab + '\na-state"' +
                     ' > "' + $out + '" 2>&1& echo [exit=!errorlevel!] >> "' + $out + '"'
            $rc = & runas /trustlevel:0x20000 $inner 2>&1

            # **runas 는 자식을 기다리지 않는다.** 끝 표시가 파일에 들어올
            # 때까지 본다. 고정 시간으로 자면 느린 회차에서 절이 반만 담긴다.
            $until = (Get-Date).AddSeconds(120)
            while ((Get-Date) -lt $until) {
                if ((Test-Path $out) -and
                    ((Get-Content $out -Raw -Encoding UTF8) -match '\[exit=')) { break }
                Start-Sleep -Milliseconds 500
            }
            if (Test-Path $out) {
                ((Get-Content $out -Encoding UTF8) -join "`n").TrimEnd()
            } else {
                "[결과 파일이 없다 — runas 가 제한 토큰을 만들지 못했다: $rc]"
            }
        }

        Remove-Item "$lab\na-out", "$lab\na-state" -Recurse -Force -ErrorAction SilentlyContinue
        $o = New-Object System.Collections.Generic.List[string]
        $o.Add("--- 한국어 ---")
        $o.Add((Invoke-Restricted -Lang "ko"))
        $o.Add("--- 영어 ---")
        $o.Add((Invoke-Restricted -Lang "en"))

        # 문 앞에서 섰는가. `admin_gate` 는 하위 명령을 파싱하기 전에 서므로
        # (main.rs 의 `admin_gate().and_then(...)`) 산출·상태 폴더가 생기면
        # 안 된다. 생겼다면 문이 뒤로 밀린 것이고, 그때는 이 화면이 아니라
        # 권한 오류가 나온다.
        $o.Add("--- 문 앞에서 섰는가 (산출·상태 폴더가 없어야 한다) ---")
        if ((Test-Path "$lab\na-out") -or (Test-Path "$lab\na-state")) {
            $o.Add("  [만들었다 — 문이 뒤로 밀렸다]")
        } else {
            $o.Add("  없다")
        }
        $o -join "`n"
    })

    # ── 안내 모드가 **열리는** 갈래 ──────────────────────────────────
    #
    # A6 은 **거절만** 잰다. 캡처가 쓰는 빌드에는 신뢰 앵커가 없어 어떤 꾸러미도
    # 검증할 수 없기 때문이다. 그래서 **서명이 통과했을 때 안내 모드가 어떻게
    # 열리는지는 저장소 어디에서도 재지 않았다** — 받는 사람이 실제로 만나는
    # 갈래인데도 그렇다. `콘솔은-이렇게-보인다.md` §3 의 마지막 화면이 그것이고,
    # 2026-09-10 까지 유일하게 기준선 밖에 남아 있었다.
    #
    # 여기서 그 조립을 만든다 — 임시 키쌍 → 그 공개키를 박은 빌드 → 서명된
    # 꾸러미 → **비관리자로** 부르기. 안내 모드가 열린 뒤 권한 문이 닫힌다.
    #
    # **개인키는 실행마다 새로 만들고 끝나면 버린다** (P10 과 같은 방식). 저장소
    # 에도 랩에도 남기지 않는다.
    #
    # **공유 릴리스 산출물을 앵커로 오염시키면 안 된다.** 다른 하네스가 전부 그
    # 파일을 배포한다 — 앵커가 박힌 채로 남으면 A6 이 다음 회차부터 거절 대신
    # 통과를 내고 아무도 이유를 모른다. 그래서 백업 → 앵커 빌드 → **곧바로**
    # 복구하고, 어디서 죽어도 `finally` 가 한 번 더 되돌린다.
    Sep "A8. 안내 모드 — 서명된 꾸러미 (비관리자 · 관리자)"
    $gStage = Join-Path $env:TEMP ("remedy-guided-" + (Get-Date -Format "yyyyMMddHHmmss"))
    $relBak = "$gStage\remedy-unanchored.exe"
    $savedPw = $env:REMEDY_SIGN_PASSWORD
    try {
        New-Item -ItemType Directory -Force $gStage | Out-Null
        $env:REMEDY_SIGN_PASSWORD = "console-capture-ephemeral"
        Push-Location $repoRoot
        try {
            & cargo run -q -p xtask -- sign keygen `
                --public-key "$gStage\pub.key" --secret-key "$gStage\sec.key" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "키 생성 실패" }
            # 앵커는 공개키 파일의 base64 줄이다. 첫 줄은 주석이다.
            $anchor = (Get-Content "$gStage\pub.key")[1].Trim()

            Copy-Item $binPath $relBak -Force
            $env:REMEDY_TRUST_ANCHOR = $anchor
            # **`2>&1` 이 문제가 아니라 그것을 흘려보내는 것이 문제였다.**
            # 이 주석은 *"2>&1 을 쓰지 않는다"* 고 적고 있었는데, 진짜 원인은
            # 리다이렉트가 아니라 **error stream 을 지나게 두는 것**이다.
            # `Invoke-CargoBuild` 는 출력을 변수로 받아 그 stream 을 지나지
            # 않으므로 `Stop` 아래에서도 안전하다 (2026-09-13).
            #
            # **`finally` 로 감싼다** — 앵커를 비우는 일은 빌드가 실패해도
            # 끝나 있어야 한다.
            try {
                Invoke-CargoBuild "앵커 박은 remedy.exe" @("build", "-q", "--release",
                    "--target", $triple, "-p", "remedy-cli")
            } finally { $env:REMEDY_TRUST_ANCHOR = $null }
            Copy-Item $binPath "$gStage\remedy.exe" -Force
            Copy-Item $relBak $binPath -Force

            Copy-Item (Join-Path $repoRoot "plugins\evilai-locust") "$gStage\evilai-locust" -Recurse -Force
            & cargo run -q -p xtask -- sign plugin --dir "$gStage\evilai-locust" `
                --secret-key "$gStage\sec.key" --signed-at "2026-09-10T00:00:00Z" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "플러그인 서명 실패" }
            & cargo run -q -p xtask -- package --plugin "$gStage\evilai-locust" `
                --bin "$gStage\remedy.exe" --out "$gStage\pkg" --public-key "$gStage\pub.key" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "꾸러미 만들기 실패" }
        } finally { Pop-Location }

        Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
            param($lab)
            Remove-Item "$lab\pkg-signed" -Recurse -Force -ErrorAction SilentlyContinue
        }
        Copy-Item "$gStage\pkg" -Destination "$LabRoot\pkg-signed" -ToSession $session -Recurse -Force

        Emit (Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
            param($lab)
            $pkg = "$lab\pkg-signed"
            $exe = "$pkg\remedy.exe"
            $out = "$lab\guided-nonadmin.txt"
            Remove-Item $out -Force -ErrorAction SilentlyContinue

            # A7 과 같은 방식이다 — `runas /trustlevel` 이 관리자 그룹을 거부
            # 전용으로 만든 토큰을 준다. `/v:on` 이 없으면 `%errorlevel%` 이
            # 실행 전 값으로 펼쳐진다.
            # **stdin 을 NUL 로 막는다.** 안내 모드는 stdin 이 터미널이면
            # 창을 붙잡는다(`이 창을 닫으려면 Enter 를 누르십시오.`). runas 가
            # 물려준 콘솔이 터미널이라 2026-09-10 에 이 절이 그대로 매달렸고,
            # 120초를 기다린 뒤 종료 코드 줄 없이 넘어갔다. 창 유지 갈래는
            # A0 이 따로 잰다 — 여기서 재는 것은 **문이 닫히는 모양**이다.
            $inner = 'cmd.exe /v:on /c set REMEDY_LANG=' + $using:L + '&& "' + $exe + '"' +
                     ' < NUL > "' + $out + '" 2>&1& echo [exit=!errorlevel!] >> "' + $out + '"'
            $rc = & runas /trustlevel:0x20000 $inner 2>&1

            $until = (Get-Date).AddSeconds(120)
            while ((Get-Date) -lt $until) {
                if ((Test-Path $out) -and
                    ((Get-Content $out -Raw -Encoding UTF8) -match '\[exit=')) { break }
                Start-Sleep -Milliseconds 500
            }
            $o = New-Object System.Collections.Generic.List[string]
            $o.Add("꾸러미: remedy.exe · plugins\evilai-locust — 임시 키로 서명, 그 앵커를 박은 빌드")
            $o.Add("")
            $o.Add("[비관리자 — 문이 닫히는 모양]")
            if (Test-Path $out) {
                $o.Add(((Get-Content $out -Encoding UTF8) -join "`n").TrimEnd())
            } else {
                $o.Add("[결과 파일이 없다 — runas 가 제한 토큰을 만들지 못했다: $rc]")
            }

            # **관리자 갈래** (2026-09-21). 위까지는 *문이 닫히는 모양*만 쟀다 —
            # 검증을 통과한 꾸러미로 **검사가 실제로 도는 화면**은 어디에도
            # 없었다. 이 세션은 관리자이므로 같은 꾸러미를 그대로 부르면 된다.
            #
            # **stdin 을 NUL 로 막는 것이 요점이다.** 안내 모드는 `run` 과 같은
            # 문을 지나므로 `--yes` 가 없으면 승인을 묻고, 물을 사람이 없으면
            # 거절한다(exit 2). 그래서 검사·계획 화면은 나오고 **치료는 돌지
            # 않는다** — 돌면 랩 상태가 바뀌어 뒤 절의 전제가 깨진다.
            $outA = "$lab\guided-admin.txt"
            Remove-Item $outA -Force -ErrorAction SilentlyContinue
            $cmdA = 'set REMEDY_LANG=' + $using:L + '&& "' + $exe + '"' +
                    ' < NUL > "' + $outA + '" 2>&1& echo [exit=!errorlevel!] >> "' + $outA + '"'
            & cmd.exe /v:on /c $cmdA 2>&1 | Out-Null
            $o.Add("")
            $o.Add("[관리자 — 검증을 통과한 꾸러미로 검사가 돈다 · 이 절은 B(감염) 앞이라 랩이 아직 깨끗하다]")
            if (Test-Path $outA) {
                $o.Add(((Get-Content $outA -Encoding UTF8) -join "`n").TrimEnd())
            } else {
                $o.Add("[결과 파일이 없다]")
            }

            # **꾸러미는 여기서 지우지 않는다** (2026-09-21). `B2` 가 감염 뒤에
            # 같은 꾸러미로 한 번 더 부르고 **거기서 지운다** — 조립(임시 키 ·
            # 앵커 박은 빌드 · 서명 · package)이 무거워 두 번 하지 않는다.
            # 랩에 남기지 않는다는 규율은 그대로다: 같은 회차 안에서 지운다.
            $o -join "`n"
        })
    } catch {
        Emit "[안내 모드 조립을 만들지 못했다: $($_.Exception.Message)]"
    } finally {
        # **어디서 죽어도 공유 산출물은 되돌린다.**
        if (Test-Path $relBak) { Copy-Item $relBak $binPath -Force }
        $env:REMEDY_TRUST_ANCHOR = $null
        $env:REMEDY_SIGN_PASSWORD = $savedPw
        Remove-Item $gStage -Recurse -Force -ErrorAction SilentlyContinue
    }

    # ── 작업 메뉴 — **터미널일 때만 나오는 화면** (2026-10-30 에 더한 절) ──
    #
    # 이 캡처의 모든 절은 `G` 를 지나고, `G` 는 `stdin` 을 닫는다. 그래서
    # **터미널에서만 나오는 화면은 기준선에 하나도 없었다** — 실측: Windows
    # 기준선에 `이 창을 닫으려면` 0건, `무엇을 할까요` 0건(리눅스 쪽은 `script`
    # 가 pty 를 만들어 창 유지 줄을 갖고 있다). 그 말은 **메뉴 문구를 고쳐도
    # `console-diff` 가 아무 말도 하지 않는다**는 뜻이고, 2026-10-30 에 꾸러미
    # README 가 조용히 낡은 것과 같은 모양의 구멍이다.
    #
    # A0 이 같은 문제를 `Verify-DoubleClick.ps1` 로 풀었는데 **판정(참·거짓)만**
    # 남겼다 — 화면 자체는 남기지 않았다. 여기서는 전사를 그대로 싣는다. 그것이
    # `console-doc` 이 문서와 댈 수 있는 유일한 꼴이다.
    #
    # **A8 의 꾸러미를 그대로 쓴다.** 검증을 통과한 꾸러미가 있어야 메뉴가 열리고
    # (`guided::usable`), 그 조립은 A8 이 이미 했다 — 임시 키·앵커 박은 빌드·서명.
    # A8 이 일부러 지우지 않고 남겨 두는 까닭이 이것과 같다.
    #
    # **`0`(그만두기)만 누른다.** 작업을 고르면 랩 상태가 바뀌어 뒤 절의 전제가
    # 깨진다 — A8 이 `< NUL` 로 치료를 막는 것과 같은 규율이다. 다섯 작업을
    # 끝까지 누르는 것은 `Invoke-MenuVerify.ps1` 의 일이다(목표 기준 6).
    Sep "A10. 작업 메뉴 — 진짜 콘솔에서 무엇을 할지 묻는다 (그만두기로 끝낸다)"
    Copy-Item (Join-Path $PSScriptRoot "..\guest\Verify-Menu.ps1") `
        -Destination "$LabRoot\scripts\Verify-Menu.ps1" -ToSession $session -Force
    Emit (Invoke-Command -Session $session -ArgumentList $LabRoot, $L -ScriptBlock {
        param($lab, $lang)
        $tr = "$lab\menu-capture.txt"
        $js = "$lab\menu-capture.json"
        Remove-Item $tr, $js -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path "$lab\pkg-signed\remedy.exe")) {
            return "[A8 의 꾸러미가 없다 — 그 절이 실패했으면 여기도 잴 수 없다]"
        }
        # `-Keys 없음` 은 어느 작업과도 맞지 않는다 → 첫 화면만 띄우고 끝난다.
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File "$lab\scripts\Verify-Menu.ps1" `
            -Bin "$lab\pkg-signed\remedy.exe" -PayloadDir $lab `
            -OutFile $js -TranscriptFile $tr -Keys "없음" -Lang $lang *> $null
        if (-not (Test-Path $tr)) { return "[전사가 없다 — 콘솔을 만들지 못했다]" }
        $text = (Get-Content $tr -Raw -Encoding UTF8).TrimEnd()
        # **랩에 남기지 않는다.** 이 캡처는 스냅샷으로 되돌리지 않으므로
        # 회차마다 쌓인다 (A8 이 꾸러미를 B2 에게 넘기고 거기서 지우는 것과
        # 같은 규율).
        Remove-Item $tr, $js -Force -ErrorAction SilentlyContinue
        $text
    })

    # G 는 두 스트림을 이어 붙여 받는다 — 그러면 **어느 스트림으로 나갔는지가
    # 캡처에서 사라진다.** 일부러 부른 사용법은 결과(stdout)이고 오류에 딸려 나온
    # 사용법은 오류(stderr)라는 규칙이 지켜지는지는 줄 수로 잰다 (Phase 2).
    Sep "A4. 사용법이 어느 스트림으로 나가는가"
    Emit (Invoke-Command -Session $session -ArgumentList $Bin -ScriptBlock {
        param($exe)
        function Lines {
            param([string[]] $Argv, [switch] $StdErr)
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $exe
            $psi.Arguments = ($Argv -join ' ')
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.RedirectStandardInput = $true
            $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
            $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
            $psi.EnvironmentVariables["REMEDY_LANG"] = $using:L
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.StandardInput.Close()
            $o = $p.StandardOutput.ReadToEndAsync()
            $e = $p.StandardError.ReadToEndAsync()
            $p.WaitForExit(60000) | Out-Null
            $text = if ($StdErr) { $e.Result } else { $o.Result }
            @($text -split "`r?`n" | Where-Object { $_.Trim() -ne '' }).Count
        }
        @(
            "일부러 부른 사용법 — stdout 만 남긴다 (여러 줄이어야 한다)"
            "  --help          stdout $(Lines @('--help'))줄"
            "  인자 없음        stdout $(Lines @())줄"
            "  --help-all      stdout $(Lines @('--help-all'))줄"
            "오류에 딸려 나온 사용법 — stdout 은 비어야 한다"
            "  없는 명령        stdout $(Lines @('없는명령'))줄"
            "  없는 명령        stderr $(Lines @('없는명령') -StdErr)줄"
        ) -join "`n"
    })

    # **이 본문을 지금까지 아무 게이트도 읽지 않았다** (2026-10-28).
    #
    # 위 A4 는 줄 **수**만 세고(`--help-all  stdout 67줄`), 콘솔 문서는
    # `--help-all` 을 *가리키기만* 하며, 시연 게이트 73 판정은 종료 코드
    # **개수** 8 만 본다. 그래서 그 안의 `--state-dir` 설명이
    # *"되돌리기가 사는 곳이다"* 라고 적혀 있는 것을 **사람이 읽어서야**
    # 알았다. 수만 세는 것으로는 낱말이 썩는 것을 못 잡는다.
    #
    # 본문에는 흔들리는 값이 없다 — 경로도 시각도 회차 번호도 안 나온다.
    # 그래서 그대로 담아도 diff 가 더러워지지 않는다.
    Sep "A9. --help-all 본문 — 낱말까지 대조한다"
    Emit (G @("--help-all") $L 60)

    Sep "B. 감염"
    $rule = Join-Path $repoRoot "plugins\evilai-locust\rules\evilai.yar"
    $bytes = Get-SynthPayloadBytes -RulePath $rule
    Set-InfectedState -Session $session -PayloadDir $payloadDir | Out-Null
    Set-GuestPayload -Session $session -PayloadDir $payloadDir -Bytes $bytes | Out-Null
    Start-InfectedProcess -Session $session -PayloadDir $payloadDir | Out-Null
    Emit "감염 완료 · 페이로드 $($bytes.Length) B"

    # **A8 의 마지막 갈래** (2026-09-21). A8 은 랩이 깨끗한 자리라 검증을
    # 통과한 꾸러미로 검사가 돌아도 **위협 0건**으로 끝난다. 받은 사람이
    # 실제로 보는 화면 — 감염된 기계에서 서명된 꾸러미가 무엇을 찾아내는가 —
    # 은 여기서만 나온다. 꾸러미는 A8 이 만들어 두고 지우지 않은 그것이다.
    #
    # **stdin 은 NUL 로 막는다.** `--yes` 없는 승인이 거절되어(exit 2) 치료가
    # 돌지 않는다 — 돌면 C1 부터의 전제가 깨진다.
    Sep "B2. 안내 모드 — 감염된 기계에서 서명된 꾸러미로"
    Emit (Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        $pkg = "$lab\pkg-signed"
        $exe = "$pkg\remedy.exe"
        $out = "$lab\guided-infected.txt"
        Remove-Item $out -Force -ErrorAction SilentlyContinue
        $o = New-Object System.Collections.Generic.List[string]
        if (-not (Test-Path $exe)) {
            $o.Add("[A8 의 꾸러미가 없다 — 그 절의 조립이 실패했을 것이다]")
        } else {
            $cmd = 'set REMEDY_LANG=' + $using:L + '&& "' + $exe + '"' +
                   ' < NUL > "' + $out + '" 2>&1& echo [exit=!errorlevel!] >> "' + $out + '"'
            & cmd.exe /v:on /c $cmd 2>&1 | Out-Null
            if (Test-Path $out) {
                $o.Add(((Get-Content $out -Encoding UTF8) -join "`n").TrimEnd())
            } else {
                $o.Add("[결과 파일이 없다]")
            }
        }
        # 앵커를 박은 바이너리를 랩에 남기지 않는다. 다음 회차가 그것을 집으면
        # 무엇을 재는지 알 수 없어진다.
        Remove-Item $pkg -Recurse -Force -ErrorAction SilentlyContinue
        $o -join "`n"
    })

    Sep "C1. scan — 한국어"
    Emit (G @("scan", "--plugin", $Plugin, "--out-dir", "$LabRoot\out-console-scan", "--state-dir", $State) "ko")
    Sep "C2. scan — 영어"
    # 2026-09-09 부터 환경변수가 없으면 PC 로케일을 따른다 — 한국어 VM 에서 ""
    # 는 한국어다. 이 절은 영어 화면을 재는 자리이므로 영어를 명시한다.
    Emit (G @("scan", "--plugin", $Plugin, "--out-dir", "$LabRoot\out-console-scan-en", "--state-dir", $State) "en")

    # **이 캡처에는 화면 옵션 셋의 플래그 경로가 하나도 없었다** (2026-09-20).
    # 셋 다 첫 화면에 설명이 나오는데, Windows 캡처는 언어를 `REMEDY_LANG`
    # 으로만 주고 `--ascii`·`--verbose` 는 아예 돌린 적이 없었다. 설명과 동작이
    # 갈려도 캡처에 나타나지 않는 자리다 — 리눅스 `C4` 가 같은 것을 잰다.
    #
    # **`--verbose` 만은 리눅스 쪽에 이미 있었다** — `Q1`(§20)이 2026-09-09
    # 부터 `scan --verbose` 로 잰다. 없던 것은 Windows 쪽이다 (09-21 정정).
    #
    # **언어가 일부러 박힌 절이다** — `-Lang en` 으로 받아도 따라오지 않는다.
    # 여기서 재는 것은 화면의 언어가 아니라 **플래그가 환경변수를 이기는가** 다.
    Sep "C3. scan — 플래그로 준 --ascii · --verbose · --lang"
    Emit "--ascii — 장식이 ASCII 로 (C1 과 견준다)"
    Emit (G @("--ascii", "scan", "--plugin", $Plugin, "--out-dir", "$LabRoot\out-console-ascii", "--state-dir", $State) "ko")
    Emit "--verbose — 검사 결과에 evidence·groups·verdicts 가 붙는다"
    Emit (G @("--verbose", "scan", "--plugin", $Plugin, "--out-dir", "$LabRoot\out-console-verbose", "--state-dir", $State) "ko")
    Emit "--lang — 플래그가 REMEDY_LANG 을 이긴다 (REMEDY_LANG=ko 인데 영어여야 한다)"
    Emit (G @("--lang", "en", "--version") "ko")

    # **이 라벨은 화면 마감 뒤에도 그대로 둔다.** 제품 문구가 아니라 이 캡처의
    # 절 제목이고, 기준선 파일 여덟에 `########## D1. run — …` 로 박혀 있다 —
    # 고치면 `console-diff` 가 어긋나 캡처를 네 번(win ko·en · linux ko·en) 다시
    # 받아야 한다. 리눅스 쪽 쌍둥이는 `linux/capture-console.sh` 에 있다.
    Sep "D1. run — 승인할 사람이 없다"
    Emit (G @("run", "--plugin", $Plugin, "--out-dir", "$LabRoot\out-console-noone", "--state-dir", $State) $L)
    Sep "D2. run --dry-run"
    Emit (G @("run", "--plugin", $Plugin, "--out-dir", "$LabRoot\out-console-dry", "--dry-run", "--state-dir", $State) $L)
    Sep "D3. run --yes — 치료"
    Emit (G @("run", "--plugin", $Plugin, "--out-dir", "$LabRoot\out-console-run", "--yes", "--state-dir", $State) $L)

    $runId = Invoke-Command -Session $session -ArgumentList "$LabRoot\out-console-run\plan.json" -ScriptBlock {
        param($p) if (Test-Path $p) { (Get-Content $p -Raw | ConvertFrom-Json).run_id }
    }
    Emit "[run_id=$runId]"

    Sep "E. 예약된 재평가 명령 (RunOnce)"
    Emit (Invoke-Command -Session $session -ScriptBlock {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        [string](Get-ItemProperty -Path $k -Name 'remedy-verify' -ErrorAction SilentlyContinue).'remedy-verify'
    })

    Sep "F. verify"
    Emit (G @("verify", "--plugin", $Plugin, "--run", $runId, "--state-dir", $State) $L)

    Sep "G0. restore --list — 창을 닫아도 회차를 찾는다"
    Emit (G @("restore", "--list", "--state-dir", $State) $L 60)

    Sep "G1. restore — 계획만"
    Emit (G @("restore", "--run", $runId, "--state-dir", $State) $L 120)
    Sep "G2. restore --yes"
    Emit (G @("restore", "--run", $runId, "--yes", "--state-dir", $State) $L 120)

    # ── 치료 심장박동의 '도구' 칸 ───────────────────────────────────
    #
    # **두 기준선 중 어디에도 이 화면이 없었다.** 리눅스 `D5` 는 개발 빌드에
    # 일부러 잠을 넣어 `치료 중 · 경과 N초` 까지는 남겼지만 `도구` 칸이 붙은
    # 변형은 못 받았다 — 리눅스 치료가 부르는 외부 도구는 CA 저장소 갱신뿐이고
    # 그 위협은 그것을 밟지 않는다. 그래서 `콘솔은-이렇게-보인다.md` §6 이 그
    # 줄을 **형식에서 지어** 싣고 있었다.
    #
    # Windows 는 지어낼 필요가 없다. 이 계획의 7번(`보안 제품 예외 목록 원복`)이
    # `powershell.exe` 를 띄우고 그것이 **1.15~1.27초** 돈다(2026-09-11 랩 VM 에서
    # 세 번 쟀다. 짧은 도구는 `schtasks` 0.14초 · `taskkill` 0.16초다). 박동을 1초
    # 주기로 두면 간격(1초 + 폴링 50ms)이 그 창보다 짧으므로 **반드시 한 번은
    # 도구가 도는 중에 찍힌다.** 개발 빌드도, 일부러 넣는 잠도 필요 없다 —
    # 진짜 치료가 진짜 도구를 부르는 자리다.
    #
    # **받아 보니 세 박동에 모두 붙었다.** 고위험 Op(`폴더 삭제`)이 하나라도 있으면
    # 치료 전에 **복원 지점**을 만드는데 그것도 `powershell.exe` 라, 둘이 잇따라
    # 돌며 3초짜리 치료를 거의 채운다. 라벨이 둘 다 `powershell.exe -NoProfile`
    # 인 것은 이름이 *이미지 + 첫 인자* 이기 때문이다.
    #
    # **되돌린 뒤에 둔다.** G2 가 감염을 되살려 놓았으므로 D2 의 계획이 그대로
    # 선다. 계획 1번(`프로세스 종료`)만은 되살아나지 않지만, 죽일 것이 없으면
    # `taskkill` 을 아예 띄우지 않고 성공한다(`windows.rs` 의 `process_kill`).
    Sep "D5. 치료 심장박동 — 도구가 도는 중"
    $beat = G @("apply", "--plan", "$LabRoot\out-console-dry\plan.json", "--yes",
                "--state-dir", $BeatState) $L 300 @{ "REMEDY_HEARTBEAT_SECS" = "1" }
    Emit $beat
    # **성공하면 늘 같은 줄, 실패하면 다른 줄** — 0절의 예외 고정과 같은 이유다.
    # 심장박동 줄 자체는 `console-diff` 가 빼고 보므로, 이 절이 무엇을 재려고
    # 있는지는 빠지지 않는 줄로 말해야 한다. 개수는 적지 않는다 — 몇 줄이
    # 찍히는지는 치료가 몇 초 걸리느냐에 달렸고 그것은 화면이 아니라 기계다.
    if (@($beat -split "`n" | Where-Object { $_ -match '^치료 중.*도구 ' }).Count -gt 0) {
        Emit "[도구 칸이 붙은 심장박동을 받았다]"
    } else {
        Emit "[도구 칸이 붙은 심장박동을 받지 못했다 — 외부 도구가 박동 간격보다 빨리 끝났다]"
    }

    Sep "H. support-bundle"
    Emit (G @("support-bundle", "--run", $runId, "--state-dir", $State, "--out", "$LabRoot\bundle-console") $L 120)

    Sep "I1. 오류 — 인자 빠짐"
    Emit (G @("apply") $L 60)
    Sep "I2. 오류 — 모르는 하위 명령"
    Emit (G @("plugin", "없는것") $L 60)

    Sep "J. selftest"
    Emit (G @("selftest") $L 60)

    Sep "K. 회차 로그 (심장박동 줄 제외)"
    Emit (Invoke-Command -Session $session -ArgumentList $State, $runId -ScriptBlock {
        param($s, $run)
        $lines = @()
        Get-ChildItem "$s\logs\*.log" -ErrorAction SilentlyContinue |
            ForEach-Object { $lines += ("{0}  {1} bytes" -f $_.Name, $_.Length) }
        $f = Join-Path "$s\logs" "$run.log"
        if (Test-Path $f) {
            # **개수가 아니라 내용으로 자른다.** 고정 개수(-First N)로 자르면 화면에
            # 줄이 더해질 때마다 창 밖으로 한 줄이 밀려나고, 그것이 diff 에는
            # **삭제**로 보인다 — 진짜 삭제를 그 뒤에 숨길 수 있는 사각지대다.
            # 2026-09-08 에 Phase 1(창 14→22)과 Phase 3(계획이 10줄 늘어 22를 넘김)
            # 에서 두 번 밟았다. 승인 뒤 첫 줄까지를 담으면 앞이 아무리 길어져도
            # 밀려나는 것이 없다.
            $lines += "--- $run.log 의 머리부터 치료 시작까지 ---"
            $body = @([System.IO.File]::ReadAllLines($f, [System.Text.Encoding]::UTF8) |
                Where-Object { $_ -notmatch '검사 중|Scanning' })
            $stop = 0
            for ($i = 0; $i -lt $body.Count -and $i -lt 80; $i++) {
                $stop = $i
                if ($body[$i] -match '치료를 시작합니다|Starting treatment') { break }
            }
            $lines += @($body[0..$stop])
            $lines += "--- 검사 시간 줄 ---"
            $lines += @([System.IO.File]::ReadAllLines($f, [System.Text.Encoding]::UTF8) |
                Where-Object { $_ -match '검사 시간|scan time' })
        }
        $lines -join "`n"
    })
} finally {
    # **org wrap 을 제품이 싣는 경로** (2026-09-21). 리눅스 `R` 이 같은 것을
    # 재고 여기는 Windows 쪽이다. 그전에는 org wrap 이 붙은 컨테이너가 전부
    # `xtask fixture` 가 만든 것이었다 — `apply --org-public-file` 이라는
    # 플래그 경로는 한 번도 돌지 않았다.
    #
    # **맨 뒤에 두는 이유**는 이 절이 `run --yes` 로 실제 치료를 하기 때문이다.
    # 자기 검체(`orgsrc`)만 건드리고, 키 둘은 끝에서 지운다.
    Sep "M. 조직 복구 키 — apply 가 싣고 restore 가 연다"
    $oStage = Join-Path $env:TEMP ("remedy-org-" + (Get-Date -Format "yyyyMMddHHmmss"))
    try {
        New-Item -ItemType Directory -Force $oStage | Out-Null
        Push-Location $repoRoot
        try {
            & cargo run -q -p xtask -- fixture --out "$oStage\throwaway.rq" `
                --dest-prefix "C:\tmp" --org-secret-out "$oStage\org.sk" `
                --org-public-out "$oStage\org.pk" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "org 키쌍 생성 실패" }
        } finally { Pop-Location }
        Emit "org 키쌍 생성 OK — 공개키 $((Get-Item "$oStage\org.pk").Length) 바이트"

        Copy-Item "$oStage\org.pk" -Destination "$LabRoot\org.pk" -ToSession $session -Force
        Copy-Item "$oStage\org.sk" -Destination "$LabRoot\org.sk" -ToSession $session -Force

        Emit (Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
            param($lab)
            $src = "$lab\orgsrc"
            Remove-Item $src, "$lab\orgout", "$lab\state-org" -Recurse -Force -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Force $src, "$lab\orgout" | Out-Null
            1..2 | ForEach-Object { Set-Content -Path "$src\g$_.evil" -Value "payload-$_" -Encoding UTF8 }
            # 최소 룰이다 — 이 절이 재는 것은 탐지가 아니라 **wrap 이 실리는가** 다.
            $yaml = @(
                "schema_version: 1",
                "id: force-orgwrap",
                "version: 1.0.0",
                "min_core: '1.0.0'",
                "platforms: [windows]",
                "name: { ko: '조직 복구 키 시험', en: 'org recovery key test' }",
                "scan_roots: ['$src']",
                "subjects: [file]",
                "detect:",
                "  - id: junk",
                "    subject: file",
                "    where:",
                "      - { field: path, op: ends_with, value: '.evil' }",
                "verdict:",
                "  require: 'junk'",
                "remediate:",
                "  remove:",
                "    - { ref: junk }"
            ) -join "`r`n"
            # **`Set-Content -Encoding UTF8` 은 BOM 을 붙인다** (Windows
            # PowerShell 5.1). `serde_yaml_ng` 가 그것을 거부해
            # `missing field 'id' at line 1 column 2` 로 죽는다 — 2026-09-21 에
            # 실제로 밟았다. JSON 과 같은 규칙이다(AGENTS.md).
            [System.IO.File]::WriteAllText("$lab\org.yaml", $yaml,
                (New-Object System.Text.UTF8Encoding($false)))
            "검체 2개 · 룰 생성 완료"
        })

        Emit (G @("run", "--plugin", "$LabRoot\org.yaml", "--out-dir", "$LabRoot\out-org",
                  "--yes", "--state-dir", "$LabRoot\state-org",
                  "--org-public-file", "$LabRoot\org.pk") "ko")
        Emit "--- 조직 키로 연다 (제자리가 아니라 꺼내기) ---"
        $rq = Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
            param($lab)
            (Get-ChildItem "$lab\state-org\quarantine\*.rq" -ErrorAction SilentlyContinue |
                Select-Object -First 1).FullName
        }
        if ($rq) {
            Emit (G @("restore", "--container", $rq, "--org-key-file", "$LabRoot\org.sk",
                      "--extract-to", "$LabRoot\orgout", "--yes",
                      "--state-dir", "$LabRoot\state-org") "ko")
            Emit (Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
                param($lab)
                "--- 꺼낸 것 ---`n" + ((Get-ChildItem "$lab\orgout" |
                    ForEach-Object { $_.Name }) -join "`n")
            })
        } else {
            Emit "[격리물이 없다 — 위 run 이 격리를 만들지 못했다]"
        }
    } catch {
        Emit "[조직 복구 키 절을 만들지 못했다: $($_.Exception.Message)]"
    } finally {
        # **키는 남기지 않는다.** 호스트의 조립 자리와 랩의 사본 둘 다.
        Remove-Item $oStage -Recurse -Force -ErrorAction SilentlyContinue
        Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
            param($lab)
            Remove-Item "$lab\org.sk", "$lab\org.pk" -Force -ErrorAction SilentlyContinue
        }
    }

    Sep "L. 정리"
    # 비켜 두었던 예외를 되돌린다. **정리보다 먼저다** — 여기서 죽으면 남의
    # 설정이 지워진 채로 남는다.
    if ($avSaved -and $AvApply) {
        try {
            $back = Invoke-Command -Session $session -ScriptBlock $AvApply `
                -ArgumentList $avSaved.Paths, $avSaved.Processes, $avSaved.Extensions
            Emit "예외 복원 완료"
            Write-Host "    예외 복원: 레지스트리 $back 건"
        } catch { Emit "예외 복원 실패: $_" }
    }
    try {
        Stop-InfectedProcess -Session $session -PayloadDir $payloadDir | Out-Null
        Clear-InfectedState -Session $session -PayloadDir $payloadDir | Out-Null
        Emit "정리 완료"
    } catch { Emit "정리 실패: $_" }
    Remove-PSSession $session
}

Sep "끝"

# ── 캡처가 자기 산출물을 센다 ────────────────────────────────────
#
# **절 수와 종료 코드 분포는 diff 를 보기 전에 거를 값이다.** 절이 줄었으면
# 캡처가 중간에 끊긴 것이고, 종료 코드가 빠졌으면 그 갈래를 못 밟은 것이다 —
# 둘 다 diff 를 통째로 붉게 만들어 진짜 차이를 덮는다. 지금까지는 README 의
# grep 두 개를 손으로 쳤고, 그것은 캡처를 받은 사람이 기억해야 도는 일이었다.
#
# **파일에는 넣지 않는다** — `Emit` 이 아니라 `Write-Host` 다. 이것은 제품
# 화면이 아니라 계측기가 자기를 재는 줄이고, 파일에 넣으면 기준선이 그것까지
# 담아 "diff 를 보기 전에" 라는 말이 뜻을 잃는다.
# 31 → 32: `--help-all` 본문 절을 더했다 (A9 · 2026-10-28).
$ExpectSections = 33
$ExpectCodes = @("0", "1", "2", "4", "5")
$capLines = [System.IO.File]::ReadAllLines($Out, $utf8)
$secs = @($capLines | Where-Object { $_ -like "##########*" }).Count
$codes = @($capLines | ForEach-Object {
    if ($_ -match '^\[exit=(\d)\]$') { $Matches[1] }
} | Sort-Object -Unique)
$okSec = $secs -eq $ExpectSections
$okCode = ($codes -join "·") -eq ($ExpectCodes -join "·")
Write-Host ""
if ($okSec -and $okCode) {
    Write-Host ("자기 점검: 절 {0} · 종료 코드 {1} — 기대한 그대로" -f $secs, ($codes -join "·")) -ForegroundColor Green
} else {
    if (-not $okSec) {
        Write-Warn ("절 {0}개 — {1}개를 기대했다. 줄었으면 캡처가 중간에 끊긴 것이다" -f $secs, $ExpectSections)
    }
    if (-not $okCode) {
        Write-Warn ("종료 코드 {0} — {1} 을 기대했다. 빠졌으면 그 갈래를 못 밟은 것이다" -f ($codes -join "·"), ($ExpectCodes -join "·"))
    }
    Write-Host '   기대값이 낡았을 수도 있다 — 절을 일부러 더했으면 $ExpectSections 도 함께 고칠 것' -ForegroundColor Yellow
}
Write-Host "캡처 → $Out"
