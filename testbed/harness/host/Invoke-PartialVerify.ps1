#Requires -Version 5.1
<#
.SYNOPSIS
    **부분 실패(종료 코드 3)가 Windows 에서 계약대로인가** — 실기기 확인.

.DESCRIPTION
    종료 코드 0~7 은 무인 배포가 읽는 계약인데, **3 만은 Windows 에서 한 번도
    관측된 적이 없었다** (2026-09-11 확인: 콘솔 기준선은 0·1·2·4·5, 실기기
    채점 여덟 건은 전부 1). 리눅스 캡처는 컨테이너에서 일부러 일으켜 갖고
    있었지만, 주력 플랫폼에는 그 화면도 그 저널도 없었다.

    **계약이 무엇인가** (`remedy-apply/src/lib.rs` · `remedy-cli/src/main.rs`)

      - 한 Action 이 실패해도 **멈추지 않는다.** 나머지를 마저 수행한다.
      - 실패는 저널에 `{"rec":"outcome","outcome":"failed","reason":…}` 로 남는다.
      - 끝에서 `report.failed() > 0` 이면 **3**, 그리고
        `N건이 실패했습니다. 되돌리지 않고 나머지를 수행했습니다.` 를 stderr 로 낸다(2026-09-30 화면 마감 뒤 문구).
      - **되돌리기는 그대로 된다** — 실패한 Action 은 백업을 쓰지 않았을 뿐이다.

    # 어떻게 하나만 실패시키나

    감염 폴더 안에 파일 하나를 두고 **`FileShare::Read` 로 연 채** 치료한다.

    **배타(`FileShare::None`)로 열면 안 된다.** 백업 단계가 그 폴더를 읽어
    격리 컨테이너에 담는데, 읽지 못하면 백업에서 먼저 죽어 **부분 실패가 아니라
    전체 실패**가 된다. 읽기만 허용하면 백업은 지나가고, 삭제는
    `FILE_SHARE_DELETE` 가 없어 공유 위반(`os error 32`)으로 진다 — 계획 7건 중
    `폴더 삭제` **하나만** 실패한다.

    실제 상황과도 닮았다: 악성코드의 둘째 프로세스나 검사 중인 백신이 그
    폴더의 파일을 쥐고 있는 자리다.

    # 되돌리는 것까지 잰다

    부분 실패 뒤에 `restore` 가 되는지는 **계약의 절반**이다. 실패한 채로
    되돌릴 수 없으면 사용자는 반쯤 치료된 기계에 갇힌다.

.EXAMPLE
    .\Invoke-PartialVerify.ps1
    .\Invoke-PartialVerify.ps1 -Build
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$triple = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"

. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
. (Join-Path $PSScriptRoot "InfectedState.ps1")

if ($Build) {
    Write-Step "빌드"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
    } finally { Pop-Location }
    Write-Ok "완료"
}
if (-not (Test-Path $binPath)) { throw "바이너리가 없다: $binPath  (-Build 로 만들 것)" }

$runId = "verify-partial-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runId"
New-Item -ItemType Directory -Path $hostOut -Force | Out-Null

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential
try {
    # **자기 전제를 스스로 세운다.** 바이너리와 룰이 랩에 이미 있다고 가정하면
    # 되돌린 기계에서 이 하네스는 우연히 통과하거나 통째로 무너진다.
    Write-Step "배포"
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        New-Item -ItemType Directory -Force "$lab\bin" | Out-Null
        Remove-Item "$lab\plugins\evilai-locust" -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force "$lab\plugins" | Out-Null
        foreach ($d in @("$lab\state-partial", "$lab\out-partial")) {
            if (Test-Path $d) { Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
    Copy-Item (Join-Path $repoRoot "plugins\evilai-locust") `
        -Destination "$LabRoot\plugins\evilai-locust" -ToSession $session -Recurse -Force
    Write-Ok "remedy.exe · evilai-locust"

    $payloadDir = Invoke-Command -Session $session -ScriptBlock {
        Join-Path $env:LOCALAPPDATA "Programs\MicrosoftResourcesAgentV12"
    }
    # **이 하네스는 스냅샷을 되돌리지 않는다.** 앞선 것이 남긴 자리 위에서
    # 돌고, 그때 계획이 조용히 달라진다 — 까닭과 실측은 그 함수에 적었다.
    Assert-NoForeignInfection -Session $session -PayloadDir $payloadDir

    Write-Step "감염"
    $rule = Join-Path $repoRoot "plugins\evilai-locust\rules\evilai.yar"
    $bytes = Get-SynthPayloadBytes -RulePath $rule
    Set-InfectedState -Session $session -PayloadDir $payloadDir | Out-Null
    Set-GuestPayload -Session $session -PayloadDir $payloadDir -Bytes $bytes | Out-Null
    Start-InfectedProcess -Session $session -PayloadDir $payloadDir | Out-Null
    Write-Ok "완료"

    Write-Step "잠근 파일을 쥔 채로 치료 · 푼 뒤 되돌리기"
    $r = Invoke-Command -Session $session -ArgumentList $LabRoot, $payloadDir -ScriptBlock {
        param($lab, $dir)
        $ErrorActionPreference = "Continue"
        $state = "$lab\state-partial"
        function Run {
            param([string] $Argv)
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "$lab\bin\remedy.exe"
            $psi.Arguments = $Argv
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.RedirectStandardInput = $true
            $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
            $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
            $psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.StandardInput.Close()
            $o = $p.StandardOutput.ReadToEndAsync()
            $e = $p.StandardError.ReadToEndAsync()
            $p.WaitForExit(600000) | Out-Null
            [pscustomobject]@{ Text = ($o.Result + $e.Result); Code = $p.ExitCode }
        }

        $locked = Join-Path $dir "locked.dat"
        [System.IO.File]::WriteAllText($locked, "held by another process")
        # 읽기는 허용(백업이 지나가야 한다), 삭제는 불가(FILE_SHARE_DELETE 없음).
        $fs = [System.IO.File]::Open($locked, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            # **이어 붙인 쪽을 괄호로 묶는다.** `'a' + 'b' -f $x` 는
            # `'a' + ('b' -f $x)` 로 파싱되어 앞 조각의 `{0}` 이 그대로 남는다 —
            # 그러면 `{0}\plugins\…` 라는 경로를 찾다가 종료 코드 4 로 진다.
            $argv = ('run --plugin "{0}\plugins\evilai-locust\plugin.yaml" ' +
                '--out-dir "{0}\out-partial" --yes --state-dir "{1}"') -f $lab, $state
            $run = Run $argv
        } finally {
            $fs.Close()
        }
        $dirLeft = Test-Path $dir

        # **저널은 UTF-8 로 읽는다.** PowerShell 5.1 의 Get-Content 는 ANSI 가
        # 기본이라, 제품이 옳게 써도 읽는 쪽에서 깨져 결함으로 오인된다.
        $j = @(Get-ChildItem "$state\journal\*.jsonl" -ErrorAction SilentlyContinue)
        $jrnFail = ""
        $runIdOnDisk = ""
        if ($j.Count -gt 0) {
            $runIdOnDisk = $j[0].BaseName
            foreach ($l in [System.IO.File]::ReadAllLines($j[0].FullName, [System.Text.Encoding]::UTF8)) {
                if ($l -match '"outcome":"failed"') { $jrnFail = $l }
            }
        }

        # 잠금을 푼 뒤 되돌리기.
        $restore = Run ('restore --run {0} --yes --state-dir "{1}"' -f $runIdOnDisk, $state)

        [pscustomobject]@{
            RunText     = $run.Text
            RunCode     = $run.Code
            DirLeft     = $dirLeft
            JournalFail = $jrnFail
            RestoreText = $restore.Text
            RestoreCode = $restore.Code
            RunId       = $runIdOnDisk
            # **잰 기계의 이름이다.** 구동한 PC 를 적으면 증거를 읽는 사람이
            # 엉뚱한 기계를 본다.
            Guest       = $env:COMPUTERNAME
        }
    }

    $lines = @($r.RunText -split "`r?`n")
    $done = @($lines | Where-Object { $_ -match '^\s*수행 \[' })
    $failed = @($lines | Where-Object { $_ -match '^\s*실패 \[' })

    # **계획 수도 전제다.** 위의 사전 검사가 내가 아는 자리만 보므로, 플러그인이
    # 보는데 그 목록에 없는 자리는 여기서 드러난다 — 아래 '수행 6건' 이
    # 무엇을 뜻하는지가 이 숫자에 달려 있다.
    $planned = if ($r.RunText -match '(\d+)\s*건을 수행합니다') { [int]$Matches[1] } else { -1 }

    $checks = @(
        @{ name = "계획이 7건이다 (전제)"; pass = ($planned -eq 7); detail = "$planned 건" }
        @{ name = "종료 코드가 3 (부분 실패)"; pass = ($r.RunCode -eq 3); detail = "exit=$($r.RunCode)" }
        @{ name = "실패한 Action 이 하나뿐"; pass = ($failed.Count -eq 1); detail = "$($failed.Count)건" }
        @{ name = "실패한 것이 폴더 삭제"; pass = ($failed.Count -eq 1 -and $failed[0] -match '폴더 삭제'); detail = ($failed -join " ").Trim() }
        @{ name = "사유가 공유 위반 (os error 32)"; pass = (($failed -join " ") -match 'os error 32'); detail = "os error 32" }
        @{ name = "나머지는 멈추지 않고 수행됐다"; pass = ($done.Count -eq 6); detail = "수행 $($done.Count)건" }
        # 문구는 2026-09-30 화면 마감(합쇼체) 뒤의 것이다 (2026-10-26 에 맞췄다).
        @{ name = "되돌리지 않았다고 말한다"; pass = ($r.RunText -match '되돌리지 않고 나머지를 수행했습니다'); detail = "문구" }
        @{ name = "마무리 표가 '일부 실패'"; pass = ($r.RunText -match '일부 실패'); detail = "마무리" }
        @{ name = "저널에 실패가 사유와 함께"; pass = ($r.JournalFail -match '"seq"' -and $r.JournalFail -match 'os error 32'); detail = "outcome=failed" }
        @{ name = "감염 폴더가 남아 있다"; pass = ($r.DirLeft -eq $true); detail = "남음=$($r.DirLeft)" }
        @{ name = "부분 실패 뒤에도 되돌릴 수 있다"; pass = ($r.RestoreCode -eq 0); detail = "restore exit=$($r.RestoreCode)" }
    )

    Write-Host ""
    foreach ($c in $checks) {
        $mark = if ($c.pass) { "OK  " } else { "실패" }
        $color = if ($c.pass) { "Green" } else { "Red" }
        Write-Host ("  {0} {1,-36} {2}" -f $mark, $c.name, $c.detail) -ForegroundColor $color
    }
    $passed = @($checks | Where-Object { $_.pass }).Count
    Write-Host ""
    Write-Host ("판정 {0}/{1}" -f $passed, $checks.Count) `
        -ForegroundColor $(if ($passed -eq $checks.Count) { "Green" } else { "Red" })

    # **JSON 은 BOM 없이.** serde 계열 파서가 BOM 을 거부한다.
    $report = [pscustomobject]@{
        schema  = "remedy-verify-partial/1"
        run_id  = $r.RunId
        host    = $r.Guest
        at      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        exit    = $r.RunCode
        passed  = $passed
        total   = $checks.Count
        checks  = @($checks | ForEach-Object { [pscustomobject]$_ })
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $hostOut "verify-partial.json"),
        ($report | ConvertTo-Json -Depth 5), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $hostOut "run.txt"), $r.RunText, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $hostOut "restore.txt"), $r.RestoreText, $utf8)

    Write-Step "정리"
    Invoke-Command -Session $session -ArgumentList $payloadDir -ScriptBlock {
        param($d) Remove-Item (Join-Path $d "locked.dat") -Force -ErrorAction SilentlyContinue
    }
    Stop-InfectedProcess -Session $session -PayloadDir $payloadDir | Out-Null
    Clear-InfectedState -Session $session -PayloadDir $payloadDir | Out-Null
    # **상태·산출 폴더도 치운다.** 2026-09-12 한 바퀴 뒤에 둘이 남아 있었다.
    # 다음 회차의 0절이 지우기는 하지만, 그때까지 랩에는 이 하네스가 만든
    # 격리물과 저널이 놓여 있다 — 치우는 것은 만든 쪽의 몫이다.
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        Remove-Item "$lab\state-partial", "$lab\out-partial" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "완료"

    Write-Host "`n결과: $hostOut"
    # **성공도 말한다** — 내지 않으면 한 바퀴가 직전 네이티브 명령의 코드를
    # 물려받는다 (`Invoke-Sweep.ps1` 의 *"종료 코드 없음"* 절).
    exit $(if ($passed -ne $checks.Count) { 1 } else { 0 })
} finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
}
