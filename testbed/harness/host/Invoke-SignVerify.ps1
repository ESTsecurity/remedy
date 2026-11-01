#Requires -Version 5.1
<#
.SYNOPSIS
    **서명된 꾸러미를 손대면 서는가** — 종료 코드 5 의 서명 갈래.

.DESCRIPTION
    종료 코드 5 는 세 갈래다 — 상한 초과 · 보호 경로 · **서명 검증 실패**.
    앞의 둘은 2026-09-11 에 쟀고, 서명 갈래만 남아 있었다. 그것을 재려면
    *"서명된 배포본을 손댄 상태"* 를 만들어야 한다.

    # VM 이 필요 없다

    `plugin verify` 는 파일을 읽어 해시를 견줄 뿐 기계를 만지지 않는다. 그래서
    이 하네스는 개발 PC 에서 돈다 — 콘솔 문서의 "권한 게이트" 행이 같은 자리다.

    # 앵커는 파일에서 준다

    `--public-key` 로 공개키 파일을 지정하면 **다시 빌드하지 않아도 된다.**
    박힌 앵커(`REMEDY_TRUST_ANCHOR`)를 쓰려면 공유 릴리스 산출물을 앵커로
    덮었다가 되돌려야 하는데, 그 파일은 다른 하네스가 전부 배포하는 것이라
    한 번 오염되면 원인 없이 결과가 바뀐다(A8 이 그래서 `finally` 로 되돌린다).
    앵커를 어디서 얻든 그 뒤의 검증 경로는 같다.

    # 네 가지 손댐

    | 무엇 | 무엇을 재는가 |
    |---|---|
    | 한 바이트 고침 | `Modified` — 룰 내용이 서명 뒤에 바뀌었다 |
    | 파일 하나 더함 | `Extra` — 서명에 없던 룰이 끼어들었다 |
    | 파일 하나 지움 | `Missing` — 서명된 것이 사라졌다 |
    | 서명 파일 삭제 | **다른 문구** — "서명되지 않은 플러그인일 수 있다" |

    마지막이 중요하다. *"없는 것과 틀린 것을 나눈다"* 는 것이 코드의 설계이고
    (`main.rs`), 둘을 뭉뚱그리면 사람이 원인을 찾는 데 시간을 쓴다.

    # 키

    **임시 키다.** 매번 새로 만들어 stage 에 두고 끝에서 지운다. 릴리스 키는
    조직 절차가 필요한 일이라 여기서 다루지 않는다.

.EXAMPLE
    .\Invoke-SignVerify.ps1
    .\Invoke-SignVerify.ps1 -Build
#>
[CmdletBinding()]
param(
    [switch] $Build,
    [string] $Plugin = "plugins\evilai-locust"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$triple = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"

. (Join-Path $PSScriptRoot "VmSession.ps1")

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

$runId = "verify-sign-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runId"
New-Item -ItemType Directory -Path $hostOut -Force | Out-Null

$stage = Join-Path $env:TEMP ("remedy-sign-" + (Get-Date -Format "yyyyMMddHHmmss"))
$savedPw = $env:REMEDY_SIGN_PASSWORD
$log = New-Object System.Collections.Generic.List[string]

# 한 번 부르고 화면과 종료 코드를 함께 받는다.
function Verify {
    param([string] $Why)
    $ErrorActionPreference = "Continue"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $binPath
    $psi.Arguments = ('plugin verify --dir "{0}\evilai-locust" --public-key "{0}\pub.key" ' +
        '--state-dir "{0}\state"') -f $stage
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit(120000) | Out-Null
    $text = (($o.Result + $e.Result).TrimEnd())
    $log.Add("── $Why")
    $log.Add($text)
    $log.Add("[exit=$($p.ExitCode)]")
    $log.Add("")
    Write-Host "  $Why" -ForegroundColor DarkGray
    [pscustomobject]@{ Text = $text; Code = $p.ExitCode }
}

try {
    Write-Step "임시 키 · 서명"
    New-Item -ItemType Directory -Force $stage, "$stage\state" | Out-Null
    $env:REMEDY_SIGN_PASSWORD = "sign-verify-ephemeral"
    Push-Location $repoRoot
    try {
        & cargo run -q -p xtask -- sign keygen `
            --public-key "$stage\pub.key" --secret-key "$stage\sec.key" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "키 생성 실패" }
        Copy-Item (Join-Path $repoRoot $Plugin) "$stage\evilai-locust" -Recurse -Force
        & cargo run -q -p xtask -- sign plugin --dir "$stage\evilai-locust" `
            --secret-key "$stage\sec.key" --signed-at "2026-09-11T00:00:00Z" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "플러그인 서명 실패" }
    } finally { Pop-Location }
    Write-Ok "임시 키로 서명했다 (끝에서 지운다)"

    $rule = "$stage\evilai-locust\rules\evilai.yar"
    $keep = [System.IO.File]::ReadAllBytes($rule)

    Write-Step "다섯 번 부른다"
    $ok = Verify "① 손대지 않은 꾸러미"

    # ② 한 바이트 — 룰 끝에 개행 하나. **내용이 바뀌었다는 사실이 전부다.**
    [System.IO.File]::WriteAllBytes($rule, $keep + [byte[]](0x0A))
    $mod = Verify "② 룰 한 바이트를 고쳤다"
    [System.IO.File]::WriteAllBytes($rule, $keep)

    # ③ 서명에 없던 파일이 끼어들었다.
    $extra = "$stage\evilai-locust\rules\extra.yar"
    [System.IO.File]::WriteAllText($extra, "rule extra { condition: false }`n")
    $ext = Verify "③ 룰 하나를 더했다"
    Remove-Item $extra -Force

    # ④ 서명된 것이 사라졌다.
    Remove-Item $rule -Force
    $mis = Verify "④ 룰 하나를 지웠다"
    [System.IO.File]::WriteAllBytes($rule, $keep)

    # ⑤ 서명 자체가 없다 — **틀린 것이 아니라 없는 것**이다.
    $sig = "$stage\evilai-locust\MANIFEST.minisig"
    $sigKeep = [System.IO.File]::ReadAllBytes($sig)
    Remove-Item $sig -Force
    $uns = Verify "⑤ 서명 파일을 지웠다"
    [System.IO.File]::WriteAllBytes($sig, $sigKeep)

    $checks = @(
        @{ name = "손대지 않으면 통과 (0)"; pass = ($ok.Code -eq 0); detail = "exit=$($ok.Code)" }
        @{ name = "통과 화면이 일치를 말한다"; pass = ($ok.Text -match '매니페스트와 전부 일치'); detail = "파일 N 개" }
        @{ name = "한 바이트를 고치면 5"; pass = ($mod.Code -eq 5); detail = "exit=$($mod.Code)" }
        @{ name = "고친 파일의 이름을 댄다"; pass = ($mod.Text -match 'evilai\.yar'); detail = "rules\evilai.yar" }
        @{ name = "파일을 더하면 5"; pass = ($ext.Code -eq 5); detail = "exit=$($ext.Code)" }
        @{ name = "더한 파일의 이름을 댄다"; pass = ($ext.Text -match 'extra\.yar'); detail = "rules\extra.yar" }
        @{ name = "파일을 지우면 5"; pass = ($mis.Code -eq 5); detail = "exit=$($mis.Code)" }
        @{ name = "서명이 없으면 5 이되 다른 문구"; pass = ($uns.Code -eq 5 -and $uns.Text -match '서명되지 않은'); detail = "없는 것 ≠ 틀린 것" }
        @{ name = "다시 되돌리면 또 통과"; pass = $false; detail = "(아래에서 잰다)" }
    )
    # **되돌리면 다시 통과해야 한다.** 그러지 않으면 위 판정들이 잰 것은 손댐이
    # 아니라 하네스가 꾸러미를 망가뜨린 것이다.
    $again = Verify "⑥ 전부 되돌린 뒤"
    $checks[8].pass = ($again.Code -eq 0)
    $checks[8].detail = "exit=$($again.Code)"

    Write-Host ""
    foreach ($c in $checks) {
        $mark = if ($c.pass) { "OK  " } else { "실패" }
        $color = if ($c.pass) { "Green" } else { "Red" }
        Write-Host ("  {0} {1,-30} {2}" -f $mark, $c.name, $c.detail) -ForegroundColor $color
    }
    $passed = @($checks | Where-Object { $_.pass }).Count
    Write-Host ""
    Write-Host ("판정 {0}/{1}" -f $passed, $checks.Count) `
        -ForegroundColor $(if ($passed -eq $checks.Count) { "Green" } else { "Red" })

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $report = [pscustomobject]@{
        schema = "remedy-verify-sign/1"
        host   = $env:COMPUTERNAME
        at     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        passed = $passed
        total  = $checks.Count
        checks = @($checks | ForEach-Object { [pscustomobject]$_ })
    }
    [System.IO.File]::WriteAllText((Join-Path $hostOut "verify-sign.json"),
        ($report | ConvertTo-Json -Depth 5), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $hostOut "screens.txt"), ($log -join "`n"), $utf8)

    Write-Host "`n결과: $hostOut"
    # **성공도 말한다** — 내지 않으면 한 바퀴가 직전 네이티브 명령의 코드를
    # 물려받는다 (`Invoke-Sweep.ps1` 의 *"종료 코드 없음"* 절).
    exit $(if ($passed -ne $checks.Count) { 1 } else { 0 })
} finally {
    # **임시 키를 남기지 않는다.** 개인키가 TEMP 에 남으면 그것으로 서명된
    # 꾸러미가 누구 것인지 말할 수 없게 된다.
    $env:REMEDY_SIGN_PASSWORD = $savedPw
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}
