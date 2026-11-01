#Requires -Version 5.1
<#
.SYNOPSIS
    **시연 대본이 아직 사실인가** — 시연 대본(내부 문서)의 1~9단계를
    적힌 명령 그대로 돌려 판정한다.

.DESCRIPTION
    점검표에서 이 문서만 게이트가 없었다. 낡아도 아무것도 울지 않는다.

    # 기준선으로는 고정할 수 없다 (2026-09-14 실측)

    시연 대본을 `cargo xtask console-doc <그 문서>` 로 돌려 봤더니 대조한
    134줄 중 **57줄이 기준선에 없었다.** 겹치는데 서로 모르는 것이 아니라
    **애초에 다른 시나리오**다.

    | | 기준선(`Capture-Console`) | 대본(`New-DemoMachine`) |
    |---|---|---|
    | 작업 폴더 | `…\plugins\evilai-locust` | `…\demo\evilai` |
    | 페이로드 leaf | `MicrosoftResourcesAgentV12` | `…V12-we9i6` |
    | 페이로드 프로세스 | 돈다 → 계획 7건 | 안 돈다 → **6건** |

    그래서 화면 문자열을 통째로 견주지 않는다. **대본이 무엇을 약속했는지**를
    판정으로 잰다 — 종료 코드와 대본이 인용한 문구.

    # 5단계는 재지 못한다

    대화형 승인은 **게스트 콘솔에서만** 뜬다. 원격 세션에서는 stdin 을
    리다이렉트하면 "승인할 사람이 없습니다" 로 거절하고, 하지 않으면 WinRM 호스트의
    콘솔 핸들을 물려받아 입력을 기다리며 멈춘다(대본 부록 B).

    **그 자리는 판정이 아니라 `범위 밖` 이다** (2026-09-14). 미실증에는 두
    종류가 있다 — *"이번 회차에서 못 쟀다"* 와 *"이 방법으로는 영영 못 잰다"*.
    앞의 것은 판정에 넣어야 하지만(P2 의 `-SkipCorpus` 미결이 그래서 09-14 에
    Store 문제를 잡았다), 뒤의 것을 넣으면 **한 바퀴가 영영 빨갛고** 다음
    사람이 그 빨간 줄을 정상으로 학습한다.

    치료 자체는 `--yes` 로 대신 돌려 6~8 단계가 이어진다 — 승인 *화면*을 못 본
    것이지 치료를 못 한 것이 아니다. 그 갈래는
    `guest\Approve-Interactive.ps1` 이 잰다. **숨기지는 않는다**: 화면과
    `verify-demo.json` 의 `out_of_scope` 에 그대로 적힌다.

.EXAMPLE
    .\Invoke-DemoVerify.ps1 -Build
    .\Invoke-DemoVerify.ps1 -NoPrepare    # 이미 New-DemoMachine 을 돌렸다면
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    # 준비를 건너뛴다. **감염이 서 있어야 한다** — 아니면 3단계가 위협 0으로 끝나고
    # 그 뒤가 전부 공허해진다.
    [switch] $NoPrepare,
    # 10단계의 점검 장면. 주면 `New-DemoMachine` 이 `C:\php` 에 풀고 *취약*
    # 또는 *확인 필요* 가 나온다. 주지 않으면 *해당 없음* 갈래를 잰다 —
    # **둘 다 대본의 장면**이고 게이트는 나온 답과 화면이 맞는지만 본다.
    [string] $PhpZip
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'

$demo = "$LabRoot\demo"

# ---------------------------------------------------------------- 판정 수집
$checks = New-Object System.Collections.ArrayList
function Add-Check {
    <#
        `-Skip` 은 **재지 못했다**는 뜻이고 통과도 실패도 아니다.
        재지 못한 것을 통과로 세면 게이트가 초록인데 아무것도 보장하지 않는다.
    #>
    param([string] $Name, [bool] $Pass, [string] $Detail, [switch] $Skip)
    $state = if ($Skip) { "skip" } elseif ($Pass) { "pass" } else { "fail" }
    [void]$checks.Add([pscustomobject]@{ name = $Name; state = $state; pass = $Pass; detail = $Detail })
    $mark = switch ($state) { "pass" { "OK  " } "fail" { "실패" } default { "미실증" } }
    $color = switch ($state) { "pass" { "Green" } "fail" { "Red" } default { "Yellow" } }
    Write-Host ("  {0} {1,-42} {2}" -f $mark, $Name, $Detail) -ForegroundColor $color
}

# ---------------------------------------------------------------- 준비
if (-not $NoPrepare) {
    Write-Step "시연 기계 준비 (New-DemoMachine)"
    $prep = @{ VmAddress = $VmAddress; LabRoot = $LabRoot }
    if ($Build) { $prep.Build = $true }
    if ($Credential) { $prep.Credential = $Credential }
    if ($PhpZip) { $prep.PhpZip = $PhpZip }
    & (Join-Path $PSScriptRoot "New-DemoMachine.ps1") @prep | Out-Null
    Write-Ok "감염된 시연 기계"
}

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential
$runTag = "demo-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runTag"
New-Item -ItemType Directory -Path $hostOut -Force | Out-Null

try {
    # ---------------------------------------------------------------- 전사
    #
    # **판정만으로는 리허설을 할 수 없다.** 이 게이트는 대본이 *약속한 것*을
    # 문구와 종료 코드로 재는데(머리말), 대본이 **인용한 화면 줄**이 실제 출력에
    # 그대로 있는지는 다른 질문이다 — 화면 전체를 기준선과 견주는 길은 막혀
    # 있고(머리말의 57줄) 그래서 사람이 리허설로 본다. 그 리허설이 대조할 재료가
    # 이 파일이다. `results\` 는 `.gitignore` 다.
    $transcript = Join-Path $hostOut "transcript.txt"
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    function Save-Transcript {
        param([string] $Argv, [object] $R)
        $block = "##### remedy $Argv`r`n### exit = $($R.Code)`r`n$($R.Text)`r`n"
        [System.IO.File]::AppendAllText($transcript, $block, $utf8)
    }

    # 대본의 명령을 **적힌 그대로** 게스트에서 돌린다. 작업 폴더도 대본과 같다.
    function D {
        param([string] $Argv, [int] $TimeoutSec = 600)
        $r = Invoke-Command -Session $session -ArgumentList $demo, $Argv, $TimeoutSec -ScriptBlock {
            param($cwd, $argv, $timeout)
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "$cwd\remedy.exe"
            $psi.Arguments = $argv
            $psi.WorkingDirectory = $cwd
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            # **stdin 을 닫는다** — 대본 4단계가 재는 것이 그 자리다.
            $psi.RedirectStandardInput = $true
            $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
            $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
            $psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.StandardInput.Close()
            $o = $p.StandardOutput.ReadToEndAsync()
            $e = $p.StandardError.ReadToEndAsync()
            $p.WaitForExit($timeout * 1000) | Out-Null
            [pscustomobject]@{ Text = ($o.Result + $e.Result); Code = $p.ExitCode }
        }
        Save-Transcript -Argv $Argv -R $r
        $r
    }

    # ══════════════════════════════════ 1. 무엇을 배포하는가
    Write-Step "1. 배포물"
    $files = Invoke-Command -Session $session -ArgumentList $demo -ScriptBlock {
        param($d)
        @(Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName.Substring($d.Length + 1) })
    }
    Add-Check "1 배포물이 셋뿐이다 (실행 파일 · 룰 두 벌)" `
    (($files -contains "remedy.exe") -and ($files -join ";") -match "evilai\\plugin\.yaml" -and
        ($files -join ";") -match "evilai\\rules\\evilai\.yar") `
        ("파일 " + $files.Count + "개")

    $r = D "--version"
    Add-Check "1 --version 이 0 이고 이름을 댄다" `
    (($r.Code -eq 0) -and ($r.Text -match "ESTsecurity 전용백신") -and ($r.Text -match "\(remedy\)")) `
        "exit=$($r.Code)"

    $r = D ""
    $usage = @($r.Text -split "`r?`n" | Where-Object { $_ -match "^\s+remedy " })
    Add-Check "1 인자 없이 부르면 사용법 다섯 줄" (($r.Code -eq 0) -and ($usage.Count -eq 5)) `
        "exit=$($r.Code) · $($usage.Count)줄"
    Add-Check "1 종료 코드 표는 --help-all 이 가리킨다" `
    ($r.Text -match "종료 코드 여덟 가지는 .remedy --help-all. 에 있습니다") "한 줄"

    $r = D "--help-all"
    $codes = @(0..7 | Where-Object { $r.Text -match "(?m)^\s+$_\s+\S" })
    Add-Check "1 --help-all 에 종료 코드 여덟" (($r.Code -eq 0) -and ($codes.Count -eq 8)) `
        "$($codes.Count)개"

    # ══════════════════════════════════ 2. 감염 상태
    Write-Step "2. 감염 상태"
    $inf = Invoke-Command -Session $session -ScriptBlock {
        $ErrorActionPreference = "Continue"
        $leaf = "MicrosoftResourcesAgentV12-we9i6"
        $dir = Join-Path $env:LOCALAPPDATA "Programs\$leaf"
        [ordered]@{
            Task    = $null -ne (Get-ScheduledTask -TaskPath "\Microsoft\Windows\" -TaskName Locust -ErrorAction SilentlyContinue)
            Run     = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name SystemSoftwareUpdater -ErrorAction SilentlyContinue).SystemSoftwareUpdater
            Excl    = @((Get-MpPreference).ExclusionPath | Where-Object { $_ -and $_ -like "*$leaf*" }).Count
            Payload = if (Test-Path "$dir\preload.js") { (Get-Item "$dir\preload.js").Length } else { -1 }
        }
    }
    Add-Check "2 감염이 네 곳에 걸쳐 있다" `
    ($inf.Task -and $inf.Run -and ($inf.Excl -ge 1) -and ($inf.Payload -gt 0)) `
        "작업=$($inf.Task) Run=$([bool]$inf.Run) 예외=$($inf.Excl) 페이로드=$($inf.Payload)B"
    Add-Check "2 예약 작업이 정상 node.exe 를 부른다 (LOLBin)" `
    ($inf.Run -match "nodejs\\node\.exe") "Run 키"

    # ══════════════════════════════════ 3. scan
    Write-Step "3. scan — 지우기 전에 무엇을 지울지"
    Invoke-Command -Session $session -ArgumentList $demo -ScriptBlock {
        param($d) Remove-Item "$d\out", "$d\state", "$d\out2", "$d\out3", "$d\bundle" -Recurse -Force -ErrorAction SilentlyContinue
    }
    $scan = D "scan --plugin .\evilai\plugin.yaml --out-dir .\out --state-dir .\state"
    $planned = if ($scan.Text -match '(\d+)\s*건을 수행합니다') { [int]$Matches[1] } else { -1 }
    Add-Check "3 scan 이 2 로 끝난다 (발견 · 치료 안 함)" ($scan.Code -eq 2) "exit=$($scan.Code)"
    Add-Check "3 계획이 6건이다 (페이로드가 돌지 않으므로)" ($planned -eq 6) "$planned 건"
    # **줄마다 뜻이 붙는가.** 대본이 가리키는 첫 번째 자리다 — 내부 이름을
    # 읽히지 않는다는 주장.
    $why = @($scan.Text -split "`r?`n" | Where-Object { $_ -match "^\s{6}\S" })
    Add-Check "3 항목마다 무슨 뜻인지 아래 줄에 붙는다" ($why.Count -ge $planned) "설명 $($why.Count)줄"
    Add-Check "3 4번이 삭제가 아니라 격리다" ($scan.Text -match "파일 격리") "격리"
    Add-Check "3 6번이 Defender 예외 원복이다" ($scan.Text -match "보안 제품 예외 목록 원복") "원복"
    Add-Check "3 재시작 뒤 한 번 더 본다고 예고한다" `
    ($scan.Text -match "재시작하면 자동으로 한 번 더 검사") "* 줄"
    Add-Check "3 plan.json 이 남는다 (옮겨 먹일 수 있는 문서)" `
    (Invoke-Command -Session $session -ArgumentList $demo -ScriptBlock { param($d) Test-Path "$d\out\plan.json" }) `
        "plan.json"

    # ══════════════════════════════════ 4. 사람이 없는 자리
    Write-Step "4. 사람이 없는 자리"
    $r = D "apply --plan .\out\plan.json --events .\out\apply.ndjson --state-dir .\state"
    Add-Check "4 무인이면 거절한다 (exit 2)" `
    (($r.Code -eq 2) -and ($r.Text -match "승인할 사람이 없습니다")) "exit=$($r.Code)"
    Add-Check "4 --yes 를 명시하라고 말한다" ($r.Text -match "--yes 를 명시하십시오") "안내"

    # ══════════════════════════════════ 5. 승인하고 치료
    Write-Step "5. 승인하고 치료"
    # **판정에 넣지 않는다** (2026-09-14).
    #
    # 미실증에는 두 종류가 있다 — *"이번 회차에서 못 쟀다"* 와 *"이 방법으로는
    # 영영 못 잰다"*. 앞의 것은 판정에 넣어야 한다(P2 의 `-SkipCorpus` 미결이
    # 그래서 09-14 에 Store 문제를 잡았다). 뒤의 것을 판정에 넣으면 **한 바퀴가
    # 영영 빨갛고**, 그러면 다음 사람이 그 빨간 줄을 정상으로 학습한다 —
    # 설계-01 이 "해결 불가능한 6" 을 두고 경계한 바로 그 모양이다.
    #
    # 대화형 승인은 뒤의 것이다: 원격 세션에서 stdin 을 리다이렉트하면
    # "승인할 사람이 없습니다" 로 거절하고, 하지 않으면 WinRM 호스트의 콘솔 핸들을
    # 물려받아 멈춘다(대본 부록 B). **이 하네스가 재는 범위 밖**이고
    # `guest\Approve-Interactive.ps1` 이 그 갈래를 따로 잰다.
    #
    # 그래서 판정이 아니라 **사실**로 적는다. 아래 종합에서 한 줄로 나온다.
    $outOfScope = @("5단계 대화형 승인 화면 — 게스트 콘솔에서만 뜬다 (guest\Approve-Interactive.ps1 이 잰다)")
    Write-Host ("  범위 밖 {0,-42} {1}" -f "5 대화형 승인 화면", "콘솔 전용 — 따로 잰다") -ForegroundColor DarkGray
    $apply = D "apply --plan .\out\plan.json --events .\out\apply.ndjson --state-dir .\state --yes"
    $doneN = @($apply.Text -split "`r?`n" | Where-Object { $_ -match '^\s*수행 \[' }).Count
    Add-Check "5 치료가 1 로 끝난다" ($apply.Code -eq 1) "exit=$($apply.Code)"
    Add-Check "5 계획한 만큼 수행한다" ($doneN -eq $planned) "$doneN / $planned 건"
    Add-Check "5 마무리 표가 되돌리는 법을 적는다" `
    ($apply.Text -match "되돌리려면 : remedy restore --run") "restore"
    Add-Check "5 마무리 표가 신고하는 법을 적는다" `
    ($apply.Text -match "오탐 신고  : remedy support-bundle --run") "support-bundle"
    Add-Check "5 --events 가 NDJSON 으로 남는다 (문구를 파싱하지 않아도 되게)" `
    (Invoke-Command -Session $session -ArgumentList $demo -ScriptBlock {
            param($d)
            (Test-Path "$d\out\apply.ndjson") -and
                    ((Get-Content "$d\out\apply.ndjson" -TotalCount 1) -match '"event"\s*:\s*"started"')
        }) "started"
    $gone = Invoke-Command -Session $session -ScriptBlock {
        $d = Join-Path $env:LOCALAPPDATA "Programs\MicrosoftResourcesAgentV12-we9i6"
        [ordered]@{
            Task = $null -ne (Get-ScheduledTask -TaskPath "\Microsoft\Windows\" -TaskName Locust -ErrorAction SilentlyContinue)
            Dir  = Test-Path $d
        }
    }
    Add-Check "5 예약 작업과 페이로드 폴더가 사라졌다" `
    ((-not $gone.Task) -and (-not $gone.Dir)) "작업잔존=$($gone.Task) 폴더잔존=$($gone.Dir)"

    # ══════════════════════════════════ 6. restore
    Write-Step "6. restore — 되돌린다"
    $list = D "restore --list --state-dir .\state"
    $runId = if ($list.Text -match '(run-[0-9a-f\-]+)') { $Matches[1] } else { $null }
    Add-Check "6 --list 가 회차를 찾아 준다 (창을 닫았어도)" `
    (($list.Code -eq 0) -and $runId) "run=$runId"

    $plan = D "restore --run $runId --state-dir .\state"
    Add-Check "6 --yes 없이는 계획만 (exit 2)" ($plan.Code -eq 2) "exit=$($plan.Code)"
    # **복원할 수 없는 것을 복원 전에 말한다** — 대본이 가리키는 자리.
    # 2026-10-28 에 화면이 `되살리지 못함` 에서 `복원 불가` 로 바뀌었다.
    Add-Check "6 복원할 수 없는 항목을 미리 고지한다" ($plan.Text -match "복원 불가") "고지"
    Add-Check "6 필요한 용량과 남은 용량을 먼저 잰다" ($plan.Text -match "볼륨 .*필요 .*여유") "용량"

    $rest = D "restore --run $runId --yes --state-dir .\state"
    Add-Check "6 복원이 0 으로 끝난다" ($rest.Code -eq 0) "exit=$($rest.Code)"
    Add-Check "6 본문뿐 아니라 시각·권한까지 되돌린다" `
    ($rest.Text -match "content" -and $rest.Text -match "mtime" -and $rest.Text -match "sddl") "필드"
    Add-Check "6 Defender 예외 목록도 되돌린다" ($rest.Text -match "av_exclusions") "예외"
    $back = Invoke-Command -Session $session -ScriptBlock {
        $null -ne (Get-ScheduledTask -TaskPath "\Microsoft\Windows\" -TaskName Locust -ErrorAction SilentlyContinue)
    }
    Add-Check "6 예약 작업이 돌아왔다" $back "작업=$back"

    # ══════════════════════════════════ 7. verify
    Write-Step "7. verify — 치료가 유지됐는가"
    $run2 = D "run --plugin .\evilai\plugin.yaml --out-dir .\out2 --state-dir .\state --yes"
    $runId2 = Invoke-Command -Session $session -ArgumentList $demo -ScriptBlock {
        param($d)
        if (Test-Path "$d\out2\plan.json") {
            ([System.IO.File]::ReadAllText("$d\out2\plan.json", [System.Text.Encoding]::UTF8) | ConvertFrom-Json).run_id
        }
    }
    Add-Check "7 run 이 1 로 끝난다 (수집~치료 한 번에)" ($run2.Code -eq 1) "exit=$($run2.Code)"
    # `apply --plan` 은 플러그인 경로를 모르므로 예약하지 못한다. `run` 은 안다.
    Add-Check "7 run 은 재부팅 뒤 재평가를 예약한다" `
    ($run2.Text -match "재부팅 후 재평가를 예약했습니다") "RunOnce"

    $ver = D "verify --plugin .\evilai\plugin.yaml --run $runId2 --state-dir .\state"
    Add-Check "7 verify 가 0 으로 끝난다 (치료 성공)" ($ver.Code -eq 0) "exit=$($ver.Code)"
    Add-Check "7 경로가 빈 게 아니라 판정이 재현되지 않았다고 말한다" `
    ($ver.Text -match "같은 플러그인이 더 이상 판정하지 않습니다") "문구"

    # ══════════════════════════════════ 8. support-bundle
    Write-Step "8. support-bundle — 신고 첨부물"
    $b = D "support-bundle --run $runId2 --state-dir .\state --out .\bundle"
    Add-Check "8 꾸러미가 0 으로 끝난다" ($b.Code -eq 0) "exit=$($b.Code)"
    foreach ($f in @("plan.json", "journal.jsonl", "verify.jsonl", "run.log", "environment.json")) {
        Add-Check "8 담겼다 — $f" ($b.Text -match [regex]::Escape($f)) $f
    }
    # **일부러 담지 않은 것**을 말하는 절이 이 단계의 요점이다.
    Add-Check "8 '일부러 담지 않은 것' 을 밝힌다" ($b.Text -match "일부러 담지 않은 것") "절"
    Add-Check "8 격리 컨테이너를 빼고 그 까닭을 댄다" `
    (($b.Text -match "\.rq") -and ($b.Text -match "오탐 복구는 보내지 않고")) "컨테이너"
    # 문구는 2026-09-30 화면 마감(합쇼체) 뒤의 것이다 — 그 전 문구(…말 것)를 찾던
    # 동안 이 하네스가 57/58 이었다(8단계 9/10 — 2026-10-26 에 맞췄다).
    Add-Check "8 봉인 키를 빼고 그 까닭을 댄다" `
    (($b.Text -match "machine\.key") -and ($b.Text -match "어떤 경우에도 첨부하지 마십시오")) "키"
    Add-Check "8 보내기 전에 열어 보라고 말한다" `
    ($b.Text -match "경로, 호스트명, 사용자명이 가려지지 않습니다") "고지"

    # ══════════════════════════════════ 9. 룰만 배포하면 대응된다
    #
    # **여기가 대본의 결론이다.** 새 위협이 왔다고 하고 그 자리에서 룰을 쓴다 —
    # 코어는 손대지 않는다.
    #
    # `--state-dir` 는 **앞 단계와 같은 `.\state` 다.** 대본이 그렇게 적었고,
    # 회차가 쌓인 자리에서도 새 회차가 서는지가 그 주장의 일부다. (어제 이
    # 단계를 단독으로 쟀을 때는 깨끗한 state 가 필요해 지우고 시작했는데,
    # 이어 붙인 지금은 지우면 대본대로가 아니다.)
    Write-Step "9. 룰만 배포하면 대응된다"
    $nt = Invoke-Command -Session $session -ArgumentList $demo -ScriptBlock {
        param($d)
        @(Get-ChildItem "$d\newthreat" -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName.Substring($d.Length + 1) })
    }
    $ntJoined = $nt -join ";"
    Add-Check "9 룰 두 판과 YARA 가 배포돼 있다" `
    (($ntJoined -match "newthreat\\plugin\.yaml") -and ($ntJoined -match "newthreat\\plugin-fixed\.yaml") -and
        ($ntJoined -match "newthreat\\rules\\newthreat\.yar")) ($nt -join " · ")

    # 대본이 적은 그대로 가짜 감염을 만든다.
    Invoke-Command -Session $session -ScriptBlock {
        $ErrorActionPreference = "Continue"
        $d = "$env:LOCALAPPDATA\Programs\DemoNewThreat"
        Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force $d | Out-Null
        "DEMO-NEW-THREAT-MARKER payload" | Set-Content "$d\helper.dat" -Encoding utf8 -NoNewline
        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
            DemoNewThreat "`"$d\helper.dat`""
    }

    # ── 린트가 멈춰 세우는 장면 (시연에서 두 번째로 중요한 자리) ──
    $lintBad = D "plugin lint .\newthreat\plugin.yaml"
    Add-Check "9 틀린 룰은 4 로 끝난다 (룰이 성립하지 않는다)" ($lintBad.Code -eq 4) "exit=$($lintBad.Code)"
    Add-Check "9 린트가 collect_extra 를 짚는다" `
    ($lintBad.Text -match "collect_extra 가 본문을 담지 않는다") "오류"
    Add-Check "9 린트가 설계 근거를 댄다" ($lintBad.Text -match "설계-06 §6") "근거"
    Add-Check "9 린트가 판정 하나뿐임을 경고한다" `
    ($lintBad.Text -match "독립적인 두 근거의 논리곱") "경고"
    Add-Check "9 오류 1 · 경고 1" ($lintBad.Text -match "합계: 오류 1 · 경고 1") "합계"

    $lintOk = D "plugin lint .\newthreat\plugin-fixed.yaml"
    Add-Check "9 고친 룰은 0 으로 끝난다" ($lintOk.Code -eq 0) "exit=$($lintOk.Code)"
    Add-Check "9 고친 룰이 통과로 나온다" ($lintOk.Text -match "통과 — 오류 0 · 경고 0") "통과"

    # ── 코어를 손대지 않고 새 위협을 치료한다 ──
    $nrun = D "run --plugin .\newthreat\plugin-fixed.yaml --out-dir .\out3 --state-dir .\state --yes"
    Add-Check "9 새 위협 치료가 1 로 끝난다" ($nrun.Code -eq 1) "exit=$($nrun.Code)"
    Add-Check "9 대본대로 2 건을 수행한다" ($nrun.Text -match "2 건을 수행합니다") "계획"
    Add-Check "9 치료 완료 표가 나온다" `
    ($nrun.Text -match "위협 발견, 치료 완료 \(2건 수행 완료\)") "결과"
    Add-Check "9 마무리 표가 되돌리는 법을 적는다" `
    ($nrun.Text -match "되돌리려면 : remedy restore --run") "restore"

    $left = Invoke-Command -Session $session -ScriptBlock {
        $d = "$env:LOCALAPPDATA\Programs\DemoNewThreat"
        [ordered]@{
            Run     = $null -ne (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
                    -Name DemoNewThreat -ErrorAction SilentlyContinue)
            Payload = Test-Path "$d\helper.dat"
        }
    }
    Add-Check "9 Run 키가 사라졌다" (-not $left.Run) "잔존=$($left.Run)"
    Add-Check "9 helper.dat 이 사라졌다" (-not $left.Payload) "잔존=$($left.Payload)"

    # ══════════════════════════════════ 10. PHP2Shell (가정이 아닌 사고)
    #
    # 9단계는 *"새 위협이 왔다고 하고"* 다. 10단계는 **실제 CVE** 이고, 그래서
    # 9단계의 주장이 참인지를 이 단계가 잰다.
    Write-Step "10. PHP2Shell"
    $p2 = Invoke-Command -Session $session -ArgumentList $demo -ScriptBlock {
        param($d)
        [ordered]@{
            Rules = @(Get-ChildItem "$d\php2shell" -File -ErrorAction SilentlyContinue |
                      ForEach-Object { $_.Name })
            Php   = Test-Path 'C:\php\php.exe'
        }
    }
    Add-Check "10 php2shell 룰 셋이 배포됐다 (점검 둘 · 사후 처리)" `
    (($p2.Rules -contains "check-windows.yaml") -and ($p2.Rules -contains "check-linux.yaml") -and
        ($p2.Rules -contains "aftermath.yaml")) ("파일 " + @($p2.Rules).Count + "개")

    # ── 점검: 판으로 답한다 ─────────────────────────────────────────
    #
    # **세 결과 중 어느 것이 나오는지는 기계가 정한다.** PHP 가 없으면
    # *해당 없음*(0), 있으면 깔린 판에 따라 *취약*(2) 또는 *확인 필요*(6)다.
    # 게이트는 **나온 답과 화면이 같은 말을 하는지**를 잰다 — 어느 답이
    # 나와야 한다고 정하지 않는다. 그렇게 정하면 PHP 를 깔지 않은 회차가
    # 영영 빨갛고, 다음 사람이 그 빨간 줄을 정상으로 학습한다(5단계와 같은 규율).
    $chk = D "scan --plugin .\php2shell\check-windows.yaml --out-dir .\out-php --state-dir .\state-php"
    # **문구를 바꾸면 여기가 함께 움직인다** — 2026-10-28 에 점검 결론이
    # *"근거는 산출 폴더의 scan.json 에 있습니다"* 에서 바뀌었고, 이 표를 안
    # 고쳐 게이트가 **72/73 으로 떨어졌다.** 그것이 이 표가 있는 이유다:
    # 화면과 대본이 갈리면 시연에서가 아니라 여기서 드러난다.
    $words = @{
        0 = "점검 대상이 이 기계에 없습니다"
        2 = "취약합니다\. 위에 적은 항목을 확인하십시오"
        6 = "다 보지 못해 '취약하지 않다' 를 말할 수 없습니다"
    }
    Add-Check "10 점검이 세 어휘 중 하나로 답한다" ($words.ContainsKey($chk.Code)) `
        "exit=$($chk.Code) · PHP 설치=$($p2.Php)"
    if ($words.ContainsKey($chk.Code)) {
        Add-Check "10 화면이 그 종료 코드와 같은 말을 한다" `
        ($chk.Text -match $words[$chk.Code]) "exit=$($chk.Code)"
    }
    if (-not $p2.Php) {
        # 선언한 세 자리를 **이름으로** 적는 것이 이 화면의 요점이다 —
        # *"못 찾았다"* 가 아니라 *"어디를 봤다"* 다.
        Add-Check "10 해당 없음이 선언한 세 자리를 적는다" `
        (($chk.Text -match "C:\\Program Files\\PHP") -and ($chk.Text -match "C:\\php") -and
            ($chk.Text -match "C:\\xampp\\php")) "세 경로"
        $outOfScope += "10단계의 취약(2) · 확인 필요(6) 화면 — 이 기계에 PHP 가 없다 (New-DemoMachine -PhpZip 으로 깐다)"
    }

    # ── 사후 처리: 스캐너가 하지 못하는 자리 ────────────────────────
    $am1 = D "scan --plugin .\php2shell\aftermath.yaml --out-dir .\out-php --state-dir .\state-php"
    Add-Check "10 사후 처리 scan 이 2 로 끝난다" ($am1.Code -eq 2) "exit=$($am1.Code)"
    Add-Check "10 계획이 두 모양을 가른다 (격리 · 줄 제거)" `
    (($am1.Text -match "파일 격리") -and ($am1.Text -match "파일에서 줄 제거")) "둘"
    # **2026-10-27 에 고친 문구의 회귀 방지.** `.php` 를 *설정 파일* 이라
    # 부르던 자리다 — 기준 5 가 그것이었고, 지우면 아무것도 울지 않는다.
    Add-Check "10 '.php' 를 '설정 파일' 이라 부르지 않는다" `
    ($am1.Text -notmatch "설정 파일 줄 제거") "문구"

    $am2 = D "run --plugin .\php2shell\aftermath.yaml --out-dir .\out-php --state-dir .\state-php --yes"
    Add-Check "10 치료가 1 로 끝난다" ($am2.Code -eq 1) "exit=$($am2.Code)"
    Add-Check "10 치료 완료 표가 2건을 적는다" `
    ($am2.Text -match "위협 발견, 치료 완료 \(2건 수행 완료\)") "결과"

    # **파일째 지우지 않았다는 것을 바이트로 잰다.** 화면이 그렇게 말하는 것과
    # 디스크가 그런 것은 다르다.
    $mid = Invoke-Command -Session $session -ScriptBlock {
        [ordered]@{
            ShellGone = -not (Test-Path 'C:\inetpub\wwwroot\uploads\invoice-9f2.php')
            AppSize   = if (Test-Path 'C:\inetpub\wwwroot\app\index.php') {
                (Get-Item 'C:\inetpub\wwwroot\app\index.php').Length } else { -1 }
        }
    }
    Add-Check "10 웹셸은 격리소로 갔다 (자리에서 사라진다)" $mid.ShellGone "잔존=$(-not $mid.ShellGone)"
    # 167 B 에서 심은 줄 하나(49 B)가 빠져 118 B. **파일은 남는다.**
    Add-Check "10 정상 파일은 남고 줄만 빠졌다 (167 -> 118 B)" ($mid.AppSize -eq 118) `
        "$($mid.AppSize) B"

    # ── 되돌리기: 원본 바이트 ───────────────────────────────────────
    $pl = D "restore --list --state-dir .\state-php"
    $pRun = if ($pl.Text -match '(run-[0-9a-f\-]+)') { $Matches[1] } else { $null }
    Add-Check "10 되돌릴 회차를 찾아 준다" (($pl.Code -eq 0) -and $pRun) "run=$pRun"
    $pr = D "restore --run $pRun --state-dir .\state-php --yes"
    Add-Check "10 복원이 0 으로 끝난다" ($pr.Code -eq 0) "exit=$($pr.Code)"
    # 격리된 파일은 시각·권한까지, 줄은 **그 줄 번호 자리로** 돌아간다.
    Add-Check "10 줄은 자리까지 되돌린다 (index.php:4)" `
    ($pr.Text -match "index\.php:4") "줄 자리"

    # **이것이 10단계의 판정이다.** 격리와 줄 제거 두 모양이 **원본 바이트**로
    # 돌아왔는가 — 저장소의 픽스처와 같은 해시여야 한다.
    $oracle = Invoke-Command -Session $session -ScriptBlock {
        $r = [ordered]@{}
        foreach ($p in @('C:\inetpub\wwwroot\uploads\invoice-9f2.php',
                         'C:\inetpub\wwwroot\app\index.php')) {
            $r[(Split-Path $p -Leaf)] = if (Test-Path $p) {
                "$((Get-Item $p).Length):$((Get-FileHash $p -Algorithm SHA256).Hash.ToLower())"
            } else { "missing" }
        }
        $r
    }
    $want = @{
        "invoice-9f2.php" = "193:a11f6770665eda89e4f1a175f73805f62004a8f1bc00085f35293fc88acc9f1d"
        "index.php"       = "167:308eb6f8d530faaf33101b0d11ce4909e3d6ccd281577211276624a41fcbb58e"
    }
    foreach ($k in @("invoice-9f2.php", "index.php")) {
        Add-Check "10 $k 가 원본 바이트로 돌아왔다" ($oracle[$k] -eq $want[$k]) `
        ((($oracle[$k] -split ':')[0]) + " B")
    }

} finally {
    if ($session) {
        Write-Step "정리"
        try {
            Invoke-Command -Session $session -ArgumentList $demo -ScriptBlock {
                param($d)
                $ErrorActionPreference = "Continue"
                Remove-Item "$d\out", "$d\out2", "$d\out3", "$d\bundle" -Recurse -Force -ErrorAction SilentlyContinue
                # 10단계는 자기 상태 폴더를 쓴다 — 지우지 않으면 다음 회차의
                # `restore --list` 에 회차가 둘 떠서 정규식이 앞의 것을 집는다.
                Remove-Item "$d\out-php", "$d\state-php" -Recurse -Force -ErrorAction SilentlyContinue
                # **9단계의 가짜 감염도 치운다.** 치료가 지웠더라도 중간에서
                # 끊겼으면 남는다 — 다음 회차가 그 위에서 돌면 계획이 달라진다.
                Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
                    -Name DemoNewThreat -ErrorAction SilentlyContinue
                Remove-Item "$env:LOCALAPPDATA\Programs\DemoNewThreat" -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Ok "산출 폴더 · 9단계 잔여"
        } catch { Write-Warn "정리 실패: $($_.Exception.Message)" }
        Remove-PSSession $session -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- 종합
$passed = @($checks | Where-Object { $_.state -eq "pass" }).Count
$failed = @($checks | Where-Object { $_.state -eq "fail" }).Count
$skipped = @($checks | Where-Object { $_.state -eq "skip" }).Count
$report = [pscustomobject]@{
    schema  = "remedy-verify-demo/1"
    run     = $runTag
    at      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    passed  = $passed
    failed  = $failed
    skipped = $skipped
    total   = $checks.Count
    # **재지 않는 것을 숨기지 않는다.** 판정에서 뺐다고 없던 일이 되면
    # 58/58 이 무엇을 뜻하는지 알 수 없다.
    out_of_scope = @($outOfScope)
    checks  = $checks.ToArray()
}
[System.IO.File]::WriteAllText((Join-Path $hostOut "verify-demo.json"),
    ($report | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "─────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ("판정 {0}/{1} · 실패 {2} · 미실증 {3}" -f $passed, $checks.Count, $failed, $skipped) `
    -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
if ($skipped -gt 0) {
    Write-Host "  미실증은 통과가 아니다 — 무엇을 재지 못했는지 위 사유를 볼 것." -ForegroundColor Yellow
}
# **범위 밖은 판정이 아니지만 화면에는 남는다.** 58/58 이 "전부 쟀다" 로
# 읽히면 안 된다.
foreach ($x in @($outOfScope)) {
    Write-Host "  범위 밖: $x" -ForegroundColor DarkGray
}
Write-Host "결과: $hostOut"
# **리허설이 볼 자리.** 대본이 인용한 줄이 실제로 나왔는지는 판정이 아니라
# 이 전사를 읽어야 안다.
if (Test-Path (Join-Path $hostOut "transcript.txt")) {
    $tl = @(Get-Content (Join-Path $hostOut "transcript.txt") -Encoding UTF8).Count
    Write-Host ("전사: {0}\transcript.txt  ({1}줄 · 대본 인용 줄 대조용)" -f $hostOut, $tl)
}

# ---------------------------------------------------------------- 시연 전 경고
#
# **이 게이트는 대본을 끝까지 실행한다** — 치료하고, 되돌리고, 다시 치료하고,
# 새 위협까지 지운다. 그래서 돌린 직후의 기계는 **시연할 수 없다**: 감염이 네
# 곳 모두 없고 3단계 `scan` 이 종료 0 *"위협이 발견되지 않았습니다"* 로 끝난다
# (2026-10-28 실측). `state` 도 남아 6단계의 `restore --list` 에 앞 회차가 뜬다.
#
# 초록 화면을 보고 바로 시연에 들어가는 것이 **가장 자연스러운 실수**라, 그
# 자리에서 말한다. 대본 §0 에도 같은 순서가 적혀 있다.
Write-Host ""
Write-Host "이 기계는 지금 시연할 수 없다 — 게이트가 감염을 치료하고 끝냈다." -ForegroundColor Yellow
Write-Host "  시연 상태로 되돌리려면:" -ForegroundColor Yellow
$back = ".\testbed\harness\host\New-DemoMachine.ps1 -ReinfectOnly -NoRevert"
if ($PhpZip) { $back += " -PhpZip `"$PhpZip`"" }
Write-Host "    $back" -ForegroundColor Yellow

if ($failed -gt 0) { exit 1 }
exit 0
