#Requires -Version 5.1
<#
.SYNOPSIS
    **배포 프로필에서 패닉이 나면 7 이 나가는가** — 종료 코드 7.

.DESCRIPTION
    7 은 "도구 자체가 깨졌다" 다. 5(가드가 *일부러* 멈췄다)와 나누는 이유는
    무인 배포의 후속 조치가 다르기 때문이다 — 앞은 룰을 보고 뒤는 개발자에게
    `logs/crash-*.txt` 를 보낸다.

    # 왜 재기 어려웠나

    **배포 프로필은 `panic = "abort"` 다.** 훅이 없으면 이 코드 대신 OS 의
    값(`0xC0000409` · SIGABRT)이 나간다 — 2026-09-07 에 실제로 그랬고, 그래서
    훅을 세웠다. 그런데 그 훅이 배포 프로필에서 정말 도는지는 아무도 보지
    않았다: 패닉을 일으키는 `REMEDY_PANIC_TEST` 가 `cfg(debug_assertions)`
    아래에 있어 개발 빌드에서만 통했기 때문이다.

    # 어떻게 재는가 — 제품을 바꾸지 않는다

    `-C debug-assertions=on` 으로 **릴리스 프로필을** 빌드한다. `panic = "abort"`
    도, 최적화도, 훅도 배포되는 것과 같고 `cfg(debug_assertions)` 블록만 켜진다.
    그래서 *"abort 프로필에서 훅이 7 을 내는가"* 를 그대로 잰다.

    **릴리스에 `REMEDY_PANIC_TEST` 를 여는 길은 택하지 않았다.** 방어 도구의
    배포본에 "일부러 죽는 스위치" 를 두는 것이라 얻는 것보다 잃는 것이 크다.

    이 방법이 재지 *못하는* 것: 배포본에서 `cfg(debug_assertions)` 가 꺼진
    채로 일어나는 진짜 패닉. 그것은 퍼징의 몫이다.

    # 공유 산출물을 건드리지 않는다

    `--target-dir` 로 임시 폴더에 짓는다.
    `target\x86_64-pc-windows-msvc\release\remedy.exe` 는 다른 하네스가 전부
    배포하는 파일이고, 한 번 바뀌면 원인 없이 결과가 달라진다.

.EXAMPLE
    .\Invoke-PanicVerify.ps1
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$triple = "x86_64-pc-windows-msvc"

. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'

$runId = "verify-panic-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runId"
New-Item -ItemType Directory -Path $hostOut -Force | Out-Null

$tdir = Join-Path $env:TEMP ("remedy-panic-target-" + (Get-Date -Format "yyyyMMddHHmmss"))
$savedFlags = $env:RUSTFLAGS
try {
    Write-Step "릴리스 프로필 · debug-assertions 켜서 빌드 (별도 target)"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        # **`finally` 로 감싼다.** 전에는 `RUSTFLAGS` 복원이 throw 앞 한 줄이라,
        # 거기 닿기 전에 무엇이 터지면 이 셸에 그 플래그가 남았다.
        $env:RUSTFLAGS = "-C debug-assertions=on"
        try {
            Invoke-CargoBuild "remedy.exe (debug-assertions)" @("build", "--release",
                "--target", $triple, "--target-dir", $tdir, "-p", "remedy-cli")
        } finally { $env:RUSTFLAGS = $savedFlags }
    } finally { Pop-Location }
    $panicBin = Join-Path $tdir "$triple\release\remedy.exe"
    if (-not (Test-Path $panicBin)) { throw "빌드 산출물이 없다: $panicBin" }
    Write-Ok ("{0:n1} MB" -f ((Get-Item $panicBin).Length / 1MB))

    $session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential
    try {
        Write-Step "배포 · 룰"
        Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
            param($lab)
            New-Item -ItemType Directory -Force "$lab\bin", "$lab\scripts" | Out-Null
            Remove-Item "$lab\panic-state" -Recurse -Force -ErrorAction SilentlyContinue
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            $yaml = @"
schema_version: 1
id: panic-probe
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name:
  ko: '패닉 시험'
  en: 'panic probe'
scan_roots:
  - 'C:\remedy-lab\panic-none'
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      - { field: path, op: ends_with, value: '.never-matches-anything' }
verdict:
  require: 'junk'
"@
            [System.IO.File]::WriteAllText("$lab\scripts\panic-probe.yaml", $yaml.Replace("`r`n", "`n"), $utf8)
        }
        # **배포되는 이름과 다르게 둔다.** 같은 자리에 두면 다음 하네스가 이
        # 바이너리를 집고, 그것은 배포될 물건이 아니다.
        Copy-Item $panicBin -Destination "$LabRoot\bin\remedy-panic.exe" -ToSession $session -Force
        Write-Ok "remedy-panic.exe · panic-probe.yaml"

        $run = {
            param($lab, $lang, $panic)
            $ErrorActionPreference = "Continue"
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "$lab\bin\remedy-panic.exe"
            $psi.Arguments = ('verify --plugin "{0}\scripts\panic-probe.yaml" --run run-crash ' +
                '--state-dir "{0}\panic-state"') -f $lab
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.RedirectStandardInput = $true
            $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
            $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
            $psi.EnvironmentVariables["REMEDY_LANG"] = $lang
            if ($panic) { $psi.EnvironmentVariables["REMEDY_PANIC_TEST"] = "1" }
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.StandardInput.Close()
            $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
            $p.WaitForExit(120000) | Out-Null
            [pscustomobject]@{ Text = (($o.Result + $e.Result).TrimEnd()); Code = $p.ExitCode }
        }

        Write-Step "① 패닉 (한국어)"
        $ko = Invoke-Command -Session $session -ArgumentList $LabRoot, "ko", $true -ScriptBlock $run
        Write-Host $ko.Text
        Write-Host ("[exit={0}]" -f $ko.Code) -ForegroundColor Cyan

        Write-Step "② 패닉 (영어)"
        $en = Invoke-Command -Session $session -ArgumentList $LabRoot, "en", $true -ScriptBlock $run
        Write-Host $en.Text
        Write-Host ("[exit={0}]" -f $en.Code) -ForegroundColor Cyan

        # **음성 대조.** 같은 바이너리·같은 명령이 환경변수 없이는 죽지 않아야
        # 한다. 그러지 않으면 위 둘이 잰 것은 패닉 훅이 아니라 깨진 빌드다.
        Write-Step "③ 환경변수 없이 — 죽지 않는다"
        $no = Invoke-Command -Session $session -ArgumentList $LabRoot, "ko", $false -ScriptBlock $run
        Write-Host ("[exit={0}]" -f $no.Code) -ForegroundColor Cyan

        Write-Step "④ 크래시 기록"
        $crash = Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
            param($lab)
            $f = @(Get-ChildItem "$lab\panic-state\logs\crash-*.txt" -ErrorAction SilentlyContinue)
            if ($f.Count -eq 0) { return [pscustomobject]@{ Count = 0; Head = "" } }
            $head = ([System.IO.File]::ReadAllLines($f[0].FullName, [System.Text.Encoding]::UTF8) |
                Select-Object -First 4) -join "`n"
            [pscustomobject]@{ Count = $f.Count; Head = $head; Name = $f[0].Name }
        }
        Write-Host ("  파일 {0}개" -f $crash.Count) -ForegroundColor Cyan
        if ($crash.Count -gt 0) { Write-Host $crash.Head }

        $checks = @(
            @{ name = "패닉이 7 을 낸다 (한국어)"; pass = ($ko.Code -eq 7); detail = "exit=$($ko.Code)" }
            @{ name = "패닉이 7 을 낸다 (영어)"; pass = ($en.Code -eq 7); detail = "exit=$($en.Code)" }
            @{ name = "OS 의 값이 아니다"; pass = ($ko.Code -ne -1073740791); detail = "0xC0000409 아님" }
            @{ name = "화면이 내부 오류라고 말한다"; pass = ($ko.Text -match '내부 오류'); detail = "실패:" }
            @{ name = "기계 상태를 말해 준다"; pass = ($ko.Text -match '저널 상태 그대로'); detail = "안심 문구" }
            @{ name = "영어 화면도 같은 뜻"; pass = ($en.Text -match 'internal error'); detail = "internal error" }
            @{ name = "종료 코드를 화면에도 적는다"; pass = ($ko.Text -match '종료 코드 7'); detail = "7" }
            @{ name = "크래시 기록을 남긴다"; pass = ($crash.Count -ge 1); detail = "$($crash.Count)개" }
            @{ name = "그 자리를 화면이 가리킨다"; pass = ($ko.Text -match 'crash-'); detail = "기록:" }
            @{ name = "환경변수가 없으면 죽지 않는다"; pass = ($no.Code -ne 7); detail = "exit=$($no.Code)" }
        )

        Write-Host ""
        foreach ($c in $checks) {
            $mark = if ($c.pass) { "OK  " } else { "실패" }
            $color = if ($c.pass) { "Green" } else { "Red" }
            Write-Host ("  {0} {1,-28} {2}" -f $mark, $c.name, $c.detail) -ForegroundColor $color
        }
        $passed = @($checks | Where-Object { $_.pass }).Count
        Write-Host ""
        Write-Host ("판정 {0}/{1}" -f $passed, $checks.Count) `
            -ForegroundColor $(if ($passed -eq $checks.Count) { "Green" } else { "Red" })

        $utf8 = New-Object System.Text.UTF8Encoding($false)
        $report = [pscustomobject]@{
            schema = "remedy-verify-panic/1"
            host   = (Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME })
            at     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            built  = "release profile + -C debug-assertions=on"
            passed = $passed
            total  = $checks.Count
            checks = @($checks | ForEach-Object { [pscustomobject]$_ })
        }
        [System.IO.File]::WriteAllText((Join-Path $hostOut "verify-panic.json"),
            ($report | ConvertTo-Json -Depth 5), $utf8)
        [System.IO.File]::WriteAllText((Join-Path $hostOut "screens.txt"),
            (@("── ko", $ko.Text, "[exit=$($ko.Code)]", "", "── en", $en.Text, "[exit=$($en.Code)]",
                "", "── 크래시 기록", $crash.Head) -join "`n"), $utf8)

        Write-Step "정리"
        Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
            param($lab)
            # **앵커 없는 실험 바이너리를 랩에 남기지 않는다.** 다음 회차가
            # 그것을 집으면 무엇을 재는지 알 수 없어진다.
            Remove-Item "$lab\bin\remedy-panic.exe", "$lab\scripts\panic-probe.yaml" -Force -ErrorAction SilentlyContinue
            Remove-Item "$lab\panic-state" -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "완료"

        Write-Host "`n결과: $hostOut"
        # **성공도 말한다** — 내지 않으면 한 바퀴가 직전 네이티브 명령의 코드를
        # 물려받는다 (`Invoke-Sweep.ps1` 의 *"종료 코드 없음"* 절). 여기서 나가도
        # 바깥 `finally` 둘이 돈다 — 원격 세션 정리와 임시 target 폴더 삭제가 거기
        # 있다(`RUSTFLAGS` 는 빌드 직후 안쪽 `finally` 가 이미 되돌렸다). `exit` 가
        # `finally` 를 건너뛰지 않는 것을 실측했다(2026-10-26).
        exit $(if ($passed -ne $checks.Count) { 1 } else { 0 })
    } finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    }
} finally {
    $env:RUSTFLAGS = $savedFlags
    Remove-Item $tdir -Recurse -Force -ErrorAction SilentlyContinue
}
