#Requires -Version 5.1
<#
.SYNOPSIS
    **관측 불완전(종료 코드 6)이 Windows 에서 계약대로인가.**

.DESCRIPTION
    6 은 0 에서 떼어 낸 코드다. 무인 배포에서 0 은 *"이 PC 는 깨끗하다"* 로
    읽히고 그대로 종료되는데, **아무 곳도 열어 보지 못한 실행도 0 을 냈다**
    (관측 01 D2). 그래서 "없다" 와 "못 봤다" 를 가른다.

    리눅스 캡처의 `L` 절이 *없는 자리* 갈래를 갖고 있지만 Windows 에는 그
    화면도, **접근 거부 갈래**도 없었다.

    # 열한 갈래를 함께 잰다 — 음성 대조가 있어야 뜻이 있다

    | | 무엇 | 기대 |
    |---|---|---|
    | ① | 선언한 자리가 **전부** 없다 | **6** · `전부 존재하지 않아` |
    | ② | 자리는 있는데 **열 수 없다** | **6** · `접근이 거부된 디렉터리` |
    | ③ | **하나만** 없다 | **0** — 불완전이 아니다 |
    | ④ | 본문이 상한(`max_size`)에 걸려 YARA 를 **재지 못했다** | **6** · `YARA 규칙 1개를 평가하지 못했습니다` |
    | ⑤ | ④ 와 같은 파일 · 본문이 **담겼다** | **2** — ④ 의 진실은 *있다* 였다 |
    | ⑥ | 본문은 담겼고 룰이 **안 맞는다** | **0** — 잰 미매치는 불완전이 아니다 |
    | ⑦ | ④ 처럼 재지 못했는데 **형제 술어가 이미 거짓**이다(YARA 가 앞) | **0** — 결과를 가르지 않았다 |
    | ⑧ | ④ 처럼 재지 못했는데 **확정 제외**된다 | **0** — 〃 |
    | ⑨ | ① 을 **재검사**(`verify --run`)로 | **6** · `치료를 확인하지 못했습니다` · 기록 `incomplete` |
    | ⑩ | ④ 를 **재검사**로 | **6** · 원인(본문 상한)이 화면과 회차 로그에 · 기록에 그 규칙 |
    | ⑪ | ③ 을 **재검사**로 | **0** · `치료 성공` · 기록 `clean` — 관측 필드 없음 |

    ③ 이 핵심이다. 코드가 *"일부가 없는 것은 정상일 수 있다 — 플러그인이 여러
    벤더 폴더를 나열하면 설치되지 않은 제품의 경로는 당연히 없다"* 고 적어
    두었고, 그것이 지켜지지 않으면 멀쩡한 회차가 전부 6 이 된다.

    # ④~⑧ 은 2026-10-26 에 더했다 (결정 — YARA 미평가는 6)

    그 전에는 ④ 가 **0 "위협 없음"** 이었다 — 재지 못했다는 주의 줄만 stderr 에
    남았다. 다섯은 같은 파일 · 같은 룰에서 갈래 하나만 바꾼다. ⑤ 가 없으면 ④ 의
    6 은 *"이 룰은 늘 6"* 과 구별되지 않고, ⑥ 이 없으면 *"YARA 를 쓰면 늘 6"* 과
    구별되지 않는다. ④ 의 사유 줄은 회차 로그에도 남아야 한다 — 무인 배포는
    화면을 버리고 운영자 문서(§3)가 그 로그를 가리킨다.

    ⑦ ⑧ 은 **재지 못했지만 레코드의 매치를 가르지 않은** 경우다. 그것까지 6 이면
    청정 기계가 늘 6 을 내고 운영자가 6 을 정상으로 배운다. 첫 구현(평가를
    시도했으면 센다)은 ⑦ 에서, 두 번째 구현(조건만 본다)은 ⑧ 에서 6 을 냈다 —
    둘 다 적대 검증이 찾았다.

    # ⑨~⑪ 은 2026-10-26 에 더했다 (결정 — 재검사도 관측 완전성을 본다)

    그 전에는 ⑨ ⑩ 이 **0 "치료 성공"** 이었다 — 판정만 없으면 다 보지 못해도
    성공이었다. 재부팅 뒤 재검사에는 사람이 없어 그 0 이 *"치료가 유지됐다"* 로
    읽힌다. ⑪ 이 없으면 *"재검사는 늘 6"* 과 구별되지 않는다. ⑩ 은 원인 블록
    (`해소되지 않았습니다`)까지 본다 — 재검사는 그 목록을 버렸었고, 재부팅 회차에는
    회차 로그가 유일한 화면이다. `--run` 이 치료 전 증거를 읽을 계획은 빈 것을
    심는다(증거 0 — 남은 증거 갈래는 서지 않는다).

    # ② 를 만들려면 둘을 함께 막아야 한다 (2026-09-13 실측)

    2026-09-11 에는 *"`SeBackupPrivilege` 때문"* 이라고 적었다. **절반만
    맞았다.** 특권을 전부 끄고도(활성 특권 0개) 거부 폴더가 열렸다.

    랩의 관리자 토큰은 **두 길**로 ACL 을 지나간다.

    | 길 | 막는 법 |
    |---|---|
    | **소유권** — 폴더 소유자가 `BUILTIN\Administrators` 면 DACL 에 허용이 하나도 없어도 연다 | `icacls /setowner` 로 SYSTEM 에게 넘긴다 |
    | **특권** — `SeBackupPrivilege` 등이 ACL 을 우회한다 | 자식 프로세스에서 전부 끈다 (`guest/Run-Denied.ps1`) |

    하나만 막으면 여전히 열린다 — 소유자를 넘겨도 특권이 켜져 있으면 읽히고,
    특권을 꺼도 소유자가 Administrators 면 읽힌다. **둘을 함께 막은 회차에서
    비로소 `denied_dirs` 1 · 종료 코드 6 이 나왔다.**

    `C:\System Volume Information` 이 이 랩에서 열리는 것도 같은 이유다 —
    소유자가 Administrators 다.

    # 안전

    `scan` 과 `verify` 만 부른다 — 둘 다 읽기 전용이고 계획도 치료도 하지 않는다.
    `verify` 가 지우는 것은 우리 자신의 재검사 예약(있다면)뿐이다. 픽스처는
    `C:\remedy-lab\obs-*` 와 룰 파일 `scripts\rules\obs.yar` 뿐이고 끝에서
    지운다. ④~⑩ 의 표지는 무해한 문자열 하나다.

.EXAMPLE
    .\Invoke-ObsVerify.ps1
    .\Invoke-ObsVerify.ps1 -Build
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

$runId = "verify-obs-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$hostOut = Join-Path $repoRoot "testbed\harness\results\$runId"
New-Item -ItemType Directory -Path $hostOut -Force | Out-Null

# 룰 셋은 **파일로 두지 않고 여기서 만든다** — ①~③ 은 `scan_roots` 만 다르고,
# ④~⑧ 은 같은 파일 위에서 본문 상한 · 룰 이름 · 술어 모양만 다르다. 저장소에 짧은
# YAML 여럿을 두는 것보다 한자리에서 읽히는 편이 낫고, 리눅스 캡처도 같은
# 방식으로 실험 룰을 만든다.
function Rule {
    param([string] $Id, [string] $Ko, [string[]] $Roots)
    # **홑따옴표 YAML 스칼라는 역슬래시를 해석하지 않는다.** 여기서 `\` 를
    # `\\` 로 바꾸면 경로가 `C:\\remedy-lab\\…` 가 되어 **언제나 없는 자리**가
    # 된다 — 첫 회차에서 그렇게 통과했고, 그것은 아무것도 재지 않은 초록이다.
    $rootLines = ($Roots | ForEach-Object { "  - '" + $_ + "'" }) -join "`n"
    @"
schema_version: 1
id: $Id
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name:
  ko: '$Ko'
  en: '$Id'
scan_roots:
$rootLines
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      # 아무것도 맞히지 않는다. 재는 것은 **관측이 완전한가**뿐이다.
      - { field: path, op: ends_with, value: '.never-matches-anything' }
verdict:
  require: 'junk'
"@
}

# ④~⑧ 의 룰. **같은 파일 · 같은 룰에서** 본문 상한(`max_size`) · 룰 이름 ·
# 모양(`Shape`)만 바꾼다. `yara-first` 는 YARA 를 앞에 두고 언제나 거짓인 경로
# 술어를 뒤에 둔다(⑦), `excluded` 는 그 파일을 확정 제외한다(⑧).
function YaraRule {
    param([string] $Id, [string] $Ko, [string] $MaxSize, [string] $YaraName, [string] $Shape = "path-first")
    $where = if ($Shape -eq "yara-first") {
        "      - { yara: 'rules/obs.yar:$YaraName' }`n      - { field: path, op: ends_with, value: '\never.txt' }"
    } else {
        "      - { field: path, op: ends_with, value: '\probe.txt' }`n      - { yara: 'rules/obs.yar:$YaraName' }"
    }
    $exclude = if ($Shape -eq "excluded") {
        "`n    exclude:`n      - { field: path, op: ends_with, value: '\probe.txt' }"
    } else { "" }
    @"
schema_version: 1
id: $Id
version: 1.0.0
min_core: '1.0.0'
platforms: [windows]
name:
  ko: '$Ko'
  en: '$Id'
scan_roots:
  - '$LabRoot\obs-yara'
subjects: [file]
collect_extra:
  - { path: '$LabRoot\obs-yara\probe.txt', max_size: $MaxSize }
detect:
  - id: probe
    subject: file
    where:
$where$exclude
verdict:
  require: 'probe'
"@
}

# 룰 파일. **홑따옴표 here-string** 이라야 `$a` 가 PowerShell 변수로 풀리지 않는다.
$yaraText = @'
rule obs_marker { strings: $a = "REMEDY-OBS-YARA-MARKER" condition: $a }
rule obs_absent { strings: $a = "THIS-STRING-IS-NOT-IN-THE-FILE" condition: $a }
'@

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential
try {
    Write-Step "배포 · 룰 셋"
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        New-Item -ItemType Directory -Force "$lab\bin", "$lab\scripts" | Out-Null
        Remove-Item "$lab\obs-out", "$lab\obs-state", "$lab\obs-ok" -Recurse -Force -ErrorAction SilentlyContinue
        # ③ 의 '있는 자리' — 비어 있지 않게 파일 하나를 둔다.
        New-Item -ItemType Directory -Force "$lab\obs-ok" | Out-Null
        [System.IO.File]::WriteAllText("$lab\obs-ok\harmless.txt", "nothing to see`n")
        # ④~⑧ 의 파일 — 표지 한 줄 + 4 KiB. 1KB 상한은 넘고 1MB 상한은 넘지 않는다.
        Remove-Item "$lab\obs-yara" -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force "$lab\obs-yara", "$lab\scripts\rules" | Out-Null
        [System.IO.File]::WriteAllText("$lab\obs-yara\probe.txt",
            "REMEDY-OBS-YARA-MARKER`n" + ("x" * 4096) + "`n")
    }
    Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force

    # **읽을 수 있는 루트 안에 못 여는 하위 폴더를 둔다.** 루트는 열리되 그 안
    # 하나를 못 여는 모양이 `denied_dirs` 가 세는 바로 그 자리이고, 악성코드가
    # 제 폴더를 잠그는 것도 같은 모양이다.
    #
    # **상속을 끊고 · SYSTEM 만 허용하고 · 소유자까지 SYSTEM 에게 넘긴다.**
    # 셋 중 하나라도 빠지면 관리자 계정이 그대로 연다(위 머리말의 표).
    $denyRoot = "$LabRoot\obs-deny"
    $fixture = Invoke-Command -Session $session -ArgumentList $denyRoot -ScriptBlock {
        param($root)
        $locked = Join-Path $root "locked"
        New-Item -ItemType Directory -Force $locked | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $root "visible.txt"), "seen`n")
        [System.IO.File]::WriteAllText((Join-Path $locked "UNIQUE-OBS-LOCKED.txt"), "hidden`n")
        & icacls $locked /inheritance:r 2>&1 | Out-Null
        & icacls $locked /grant "*S-1-5-18:(OI)(CI)(F)" 2>&1 | Out-Null
        & icacls $locked /setowner "*S-1-5-18" 2>&1 | Out-Null
        # ACL 을 읽지 못하는 것 자체가 거부가 걸렸다는 표시다.
        $aclRead = (& icacls $locked 2>&1) -join " "
        [pscustomobject]@{
            Owner   = (Get-Acl $locked -ErrorAction SilentlyContinue).Owner
            AclRead = $(if ($aclRead -match "거부|Access is denied") { "거부됨" } else { "읽힌다" })
        }
    }
    $rules = @{
        "obs-missing" = Rule "obs-missing" "관측 불완전 — 없는 자리" @("$LabRoot\no-such-place-1", "$LabRoot\no-such-place-2")
        "obs-denied"  = Rule "obs-denied" "관측 불완전 — 못 여는 자리" @($denyRoot)
        "obs-partial" = Rule "obs-partial" "일부만 없는 자리 — 정상" @("$LabRoot\obs-ok", "$LabRoot\no-such-place-1")
        "obs-yara-cap"  = YaraRule "obs-yara-cap" "관측 불완전 — 본문 상한" "1KB" "obs_marker"
        "obs-yara-ok"   = YaraRule "obs-yara-ok" "본문이 담긴 YARA — 맞는다" "1MB" "obs_marker"
        "obs-yara-miss" = YaraRule "obs-yara-miss" "본문이 담긴 YARA — 안 맞는다" "1MB" "obs_absent"
        "obs-yara-order" = YaraRule "obs-yara-order" "재지 못했지만 가르지 않았다 — 형제 술어" "1KB" "obs_marker" "yara-first"
        "obs-yara-excl"  = YaraRule "obs-yara-excl" "재지 못했지만 가르지 않았다 — 확정 제외" "1KB" "obs_marker" "excluded"
    }
    foreach ($k in $rules.Keys) {
        $text = $rules[$k]
        Invoke-Command -Session $session -ArgumentList $LabRoot, $k, $text -ScriptBlock {
            param($lab, $name, $body)
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText("$lab\scripts\$name.yaml", $body.Replace("`r`n", "`n"), $utf8)
        }
    }
    Invoke-Command -Session $session -ArgumentList $LabRoot, $yaraText -ScriptBlock {
        param($lab, $body)
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText("$lab\scripts\rules\obs.yar", $body.Replace("`r`n", "`n"), $utf8)
    }
    Write-Ok ("룰 셋 {0}개 · YARA 룰 파일 1개" -f $rules.Count)

    Copy-GuestFile -Session $session -Source (Join-Path $PSScriptRoot "..\guest\Run-Denied.ps1") `
        -Destination "$LabRoot\scripts\Run-Denied.ps1"
    Write-Ok ("잠긴 폴더 소유자 {0} · ACL 읽기 {1}" -f $fixture.Owner, $fixture.AclRead)

    $run = {
        param($lab, $name)
        $ErrorActionPreference = "Continue"
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "$lab\bin\remedy.exe"
        $psi.Arguments = ('scan --plugin "{0}\scripts\{1}.yaml" --out-dir "{0}\obs-out\{1}" ' +
            '--state-dir "{0}\obs-state"') -f $lab, $name
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
        $p.WaitForExit(600000) | Out-Null
        [pscustomobject]@{ Text = (($o.Result + $e.Result).TrimEnd()); Code = $p.ExitCode }
    }

    $log = New-Object System.Collections.Generic.List[string]
    $res = @{}
    # `obs-denied` 만은 **특권을 끈 자식**이 돌려야 한다. 나머지는 특권과
    # 무관하므로 여느 때처럼 부른다.
    $runDenied = {
        param($lab)
        $ErrorActionPreference = "Continue"
        $out = "$lab\obs-out\denied.txt"
        New-Item -ItemType Directory -Force "$lab\obs-out" | Out-Null
        Remove-Item $out -Force -ErrorAction SilentlyContinue
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
            -File "$lab\scripts\Run-Denied.ps1" `
            -Bin "$lab\bin\remedy.exe" -Plugin "$lab\scripts\obs-denied.yaml" `
            -OutDir "$lab\obs-out\obs-denied" -StateDir "$lab\obs-state" -OutFile $out | Out-Null
        $rc = $LASTEXITCODE
        $text = if (Test-Path $out) { [System.IO.File]::ReadAllText($out, [System.Text.Encoding]::UTF8) } else { "" }
        [pscustomobject]@{ Text = $text; Code = $rc }
    }

    # ⑨~⑪ — 같은 룰을 **재검사**로 부른다. `--run` 이 읽을 계획은 빈 것을 심는다
    # (머리말). 기록 줄과 회차 로그도 함께 돌려준다 — 재부팅 회차에는 그 둘이 전부다.
    $runVerify = {
        param($lab, $name)
        $ErrorActionPreference = "Continue"
        $runId = "obs-verify-$name"
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        New-Item -ItemType Directory -Force "$lab\obs-state\plan" | Out-Null
        $plan = '{"schema_version":1,"kind":"remedy.plan","run_id":"' + $runId + '","created":"2026-10-26T00:00:00Z",' +
            '"host":{"hostname":"h","os":"windows","version":"10","arch":"amd64"},' +
            '"core":{"version":"1.0.0","build":"harness"},"plugins":[],"actions":[],"verdicts":[],' +
            '"observation":{"truncated":false,"denied_dirs":0},"verify_after_reboot":false,"deferred":[]}'
        [System.IO.File]::WriteAllText("$lab\obs-state\plan\$runId.json", $plan, $utf8)
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "$lab\bin\remedy.exe"
        $psi.Arguments = ('verify --plugin "{0}\scripts\{1}.yaml" --run {2} --state-dir "{0}\obs-state"') -f $lab, $name, $runId
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
        $p.WaitForExit(600000) | Out-Null
        $read = { param($f) if (Test-Path $f) { [System.IO.File]::ReadAllText($f, [System.Text.Encoding]::UTF8) } else { "" } }
        [pscustomobject]@{
            Text   = (($o.Result + $e.Result).TrimEnd())
            Code   = $p.ExitCode
            Record = (& $read "$lab\obs-state\verify\$runId.jsonl").Trim()
            Log    = (& $read "$lab\obs-state\logs\$runId.log")
        }
    }

    foreach ($k in @("obs-missing", "obs-denied", "obs-partial", "obs-yara-cap", "obs-yara-ok", "obs-yara-miss", "obs-yara-order", "obs-yara-excl")) {
        Write-Step $k
        $r = if ($k -eq "obs-denied") {
            Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock $runDenied
        } else {
            Invoke-Command -Session $session -ArgumentList $LabRoot, $k -ScriptBlock $run
        }
        Write-Host $r.Text
        Write-Host ("[exit={0}]" -f $r.Code) -ForegroundColor Cyan
        $log.Add("── $k"); $log.Add($r.Text); $log.Add("[exit=$($r.Code)]"); $log.Add("")
        $res[$k] = $r
    }

    $checks = @(
        @{ name = "전부 없는 자리 → 6"; pass = ($res["obs-missing"].Code -eq 6); detail = "exit=$($res['obs-missing'].Code)" }
        @{ name = "그 사유를 말한다"; pass = ($res["obs-missing"].Text -match '전부 존재하지 않아'); detail = "전부 존재하지 않아" }
        @{ name = "없는 경로를 전부 댄다"; pass = ($res["obs-missing"].Text -match 'no-such-place-1' -and $res["obs-missing"].Text -match 'no-such-place-2'); detail = "둘 다" }
        @{ name = "하나만 없으면 6 이 아니다"; pass = ($res["obs-partial"].Code -eq 0); detail = "exit=$($res['obs-partial'].Code)" }
        @{ name = "그때는 '위협 없음' 이 선다"; pass = ($res["obs-partial"].Text -notmatch '말할 수 없'); detail = "완전한 관측" }
    )

    # ② — 2026-09-13 부터 **조건부가 아니다.** 소유권과 특권을 함께 막으면
    # 재현된다. 전제(소유자·ACL)도 판정에 넣는다: 픽스처가 조용히 무력해지면
    # 그 회차는 아무것도 재지 못한 채 초록이 된다.
    $checks += @{ name = "잠긴 폴더의 소유자가 SYSTEM"; pass = ($fixture.Owner -match 'SYSTEM'); detail = "$($fixture.Owner)" }
    $checks += @{ name = "ACL 조차 읽지 못한다"; pass = ($fixture.AclRead -eq "거부됨"); detail = $fixture.AclRead }
    $checks += @{ name = "못 여는 자리 → 6"; pass = ($res['obs-denied'].Code -eq 6); detail = "exit=$($res['obs-denied'].Code)" }
    $checks += @{ name = "거부를 사유로 말한다"; pass = ($res['obs-denied'].Text -match '접근이 거부된 디렉터리'); detail = "denied_dirs" }
    $checks += @{ name = "잠긴 파일은 수집되지 않았다"; pass = ($res['obs-denied'].Text -notmatch 'UNIQUE-OBS-LOCKED'); detail = "못 본 것을 없는 것으로 만들지 않는다" }

    # ④~⑧ — 같은 파일 · 같은 룰에서 갈래 하나만 바꾼다(머리말).
    $needle = "YARA 규칙 1개를 평가하지 못했습니다"
    $logHits = Invoke-Command -Session $session -ArgumentList $LabRoot, $needle -ScriptBlock {
        param($lab, $text)
        # 회차 로그는 BOM 없는 UTF-8 이다 — 5.1 의 기본 해석에 맡기면 한글이 깨진다.
        $logs = Get-ChildItem "$lab\obs-state\logs" -Filter *.log -ErrorAction SilentlyContinue
        @($logs | Where-Object {
            [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::UTF8).Contains($text)
        }).Count
    }
    $cap = $res['obs-yara-cap']; $ok = $res['obs-yara-ok']; $miss = $res['obs-yara-miss']
    $checks += @{ name = "본문 상한에 걸리면 → 6"; pass = ($cap.Code -eq 6); detail = "exit=$($cap.Code)" }
    $checks += @{ name = "그 사유가 규칙을 댄다"; pass = $cap.Text.Contains("$needle`: rules/obs.yar:obs_marker"); detail = "사유 줄" }
    $checks += @{ name = "상한을 미해소로 말한다"; pass = ($cap.Text -match '상한 \d+ 바이트를 넘어'); detail = "max_size 1KB" }
    $checks += @{ name = "사유 줄이 회차 로그에도 있다"; pass = ($logHits -ge 1); detail = "logs\*.log $logHits 개" }
    $checks += @{ name = "같은 파일 · 본문이 담기면 → 2"; pass = ($ok.Code -eq 2); detail = "exit=$($ok.Code) — ④ 의 진실은 '있다'" }
    $checks += @{ name = "그때는 미평가가 없다"; pass = (-not $ok.Text.Contains("평가하지 못했습니다")); detail = "주의 없음" }
    $checks += @{ name = "재었는데 안 맞으면 → 0"; pass = ($miss.Code -eq 0); detail = "exit=$($miss.Code)" }
    $checks += @{ name = "그때는 '위협 없음' 이 선다"; pass = ($miss.Text -notmatch '말할 수 없'); detail = "완전한 관측" }
    $order = $res['obs-yara-order']; $excl = $res['obs-yara-excl']
    $checks += @{ name = "형제 술어가 이미 거짓이면 → 0"; pass = ($order.Code -eq 0); detail = "exit=$($order.Code) — YARA 가 앞이어도" }
    $checks += @{ name = "그때는 미평가 주의도 없다"; pass = (-not $order.Text.Contains("평가하지 못했습니다")); detail = "결과를 가르지 않았다" }
    $checks += @{ name = "확정 제외되면 → 0"; pass = ($excl.Code -eq 0); detail = "exit=$($excl.Code)" }
    $checks += @{ name = "그때도 미평가 주의가 없다"; pass = (-not $excl.Text.Contains("평가하지 못했습니다")); detail = "결과를 가르지 않았다" }

    # ⑨~⑪ — ④ 의 회차 로그 판정 **뒤에** 돌린다. 재검사도 같은 사유 줄을 로그에
    # 남기므로, 앞에 돌리면 ④ 의 "회차 로그에도 있다" 가 재검사 로그로 채워진다.
    foreach ($k in @("obs-missing", "obs-yara-cap", "obs-partial")) {
        Write-Step "verify $k"
        $r = Invoke-Command -Session $session -ArgumentList $LabRoot, $k -ScriptBlock $runVerify
        Write-Host $r.Text
        Write-Host ("[exit={0}]" -f $r.Code) -ForegroundColor Cyan
        Write-Host $r.Record
        $log.Add("── verify $k"); $log.Add($r.Text); $log.Add("[exit=$($r.Code)]"); $log.Add($r.Record); $log.Add("")
        $res["verify $k"] = $r
    }
    $vMiss = $res['verify obs-missing']; $vCap = $res['verify obs-yara-cap']; $vOk = $res['verify obs-partial']
    $rMiss = if ($vMiss.Record) { $vMiss.Record | ConvertFrom-Json } else { $null }
    $rCap = if ($vCap.Record) { $vCap.Record | ConvertFrom-Json } else { $null }
    $rOk = if ($vOk.Record) { $vOk.Record | ConvertFrom-Json } else { $null }
    $done = "치료를 확인하지 못했습니다"
    $checks += @{ name = "재검사도 전부 없는 자리 → 6"; pass = ($vMiss.Code -eq 6); detail = "exit=$($vMiss.Code)" }
    $checks += @{ name = "치료 성공을 말하지 않는다"; pass = ($vMiss.Text.Contains($done) -and -not $vMiss.Text.Contains("치료 성공. ")); detail = $done }
    $checks += @{ name = "기록이 incomplete · 6 · 못 본 자리"; pass = ([bool]$rMiss -and $rMiss.outcome -eq "incomplete" -and $rMiss.exit_code -eq 6 -and ((@($rMiss.observation.missing_roots) -join " ") -match 'no-such-place-2')); detail = "verify\obs-verify-obs-missing.jsonl" }
    $checks += @{ name = "재검사도 재지 못한 YARA → 6"; pass = ($vCap.Code -eq 6); detail = "exit=$($vCap.Code)" }
    $checks += @{ name = "재검사 화면이 원인(상한)을 댄다"; pass = ($vCap.Text -match '해소되지 않았습니다' -and $vCap.Text -match '상한 \d+ 바이트를 넘어'); detail = "해소되지 않은 선언" }
    $checks += @{ name = "그 원인이 회차 로그에도 있다"; pass = ($vCap.Log -match '상한 \d+ 바이트를 넘어' -and $vCap.Log.Contains($done)); detail = "logs\obs-verify-obs-yara-cap.log" }
    $checks += @{ name = "기록에 못 잰 규칙"; pass = ([bool]$rCap -and $rCap.outcome -eq "incomplete" -and (@($rCap.observation.unevaluated_rules) -contains "rules/obs.yar:obs_marker")); detail = "unevaluated_rules" }
    $checks += @{ name = "하나만 없으면 재검사는 0"; pass = ($vOk.Code -eq 0 -and $vOk.Text.Contains("치료 성공. ")); detail = "exit=$($vOk.Code)" }
    $checks += @{ name = "그 기록은 clean · 관측 필드 없음"; pass = ([bool]$rOk -and $rOk.outcome -eq "clean" -and $rOk.exit_code -eq 0 -and -not $vOk.Record.Contains('"observation"')); detail = "온전한 회차의 줄은 전과 같다" }

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
        schema = "remedy-verify-obs/1"
        host   = (Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME })
        at     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        locked_owner = "$($fixture.Owner)"
        locked_acl_read = $fixture.AclRead
        passed = $passed
        total  = $checks.Count
        checks = @($checks | ForEach-Object { [pscustomobject]$_ })
    }
    [System.IO.File]::WriteAllText((Join-Path $hostOut "verify-obs.json"),
        ($report | ConvertTo-Json -Depth 5), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $hostOut "screens.txt"), ($log -join "`n"), $utf8)

    Write-Step "정리"
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($lab)
        # **소유권을 되찾아야 지울 수 있다.** SYSTEM 에게 넘긴 폴더는 ACL 을
        # 되돌리는 것조차 거부된다 — 먼저 `takeown` 으로 가져온다.
        $locked = "$lab\obs-deny\locked"
        if (Test-Path $locked) {
            & takeown /f $locked /r /d Y 2>&1 | Out-Null
            & icacls $locked /reset /t 2>&1 | Out-Null
        }
        Remove-Item "$lab\obs-out", "$lab\obs-state", "$lab\obs-ok", "$lab\obs-deny", "$lab\obs-yara" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$lab\scripts\obs-*.yaml", "$lab\scripts\rules\obs.yar" -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "완료"

    Write-Host "`n결과: $hostOut"
    # **성공도 말한다** — 내지 않으면 한 바퀴가 직전 네이티브 명령의 코드를
    # 물려받는다 (`Invoke-Sweep.ps1` 의 *"종료 코드 없음"* 절).
    exit $(if ($passed -ne $checks.Count) { 1 } else { 0 })
} finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
}
