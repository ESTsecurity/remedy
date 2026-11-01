<#
.SYNOPSIS
    채점 5 — 치료가 **실기기에서 실제로 됐는가**.

.DESCRIPTION
    `cargo xtask exam` 의 네 판정은 전부 **계획까지만** 잰다. 린트는 매니페스트를,
    나머지 셋은 스냅샷 위의 판정과 계획을 본다. **`apply` 를 도는 판정이 하나도
    없다.**

    2026-09-05 하루에 그 틈으로 결함 셋이 지나갔다. 셋 다 네 판정을 전부
    통과했고 실기기에 올려서야 보였다.

    | 결함 | 계획 | 실기기 |
    |---|---|---|
    | `registry.strip_value` 가 `REG_MULTI_SZ` 를 거부 | 정상 | 종료 3, 부팅 지속성 잔존 |
    | `env.strip_path` needle 에 구분자 | 정상 | 성공 보고, 경로 그대로 |
    | 같은 대상 겹침 | 정상 | 백업 두 벌 |

    # 무엇을 판정하는가

    **치료 뒤 기계가 청정 기준으로 돌아왔는가.** 세 시점을 뜬다.

        청정 → (감염) → 감염 → (치료) → 치료후

    그리고 차분 둘을 겹쳐 읽는다.

    | 청정→감염 | 청정→치료후 | 뜻 |
    |---|---|---|
    | 있음 | **있음** | **잔존** — 치료가 덜 됐다 |
    | 있음 | 없음 | 치료됨 |
    | 없음 | **있음** | 치료가 만든 변화 — 우리 흔적이거나 **부수 피해** |

    **위협마다 새로 적을 자료가 없다.** 판정 기준이 기계 자신이다.

    # 어디를 보는가 — 그리고 왜 응시자가 정하면 안 되는가

    관측기(`Capture-State.ps1`)는 remedy 코드를 전혀 쓰지 않는다. 그런데 그
    관측기의 레지스트리 대상은 **"지우면 시스템이 죽는 값" 넷**뿐이라 위협이
    밟는 자리를 보지 못했다 — `BootExecute` 도 `Path` 도 거기 없었다.

    그래서 볼 자리를 위협의 **사전 등록 자료**(`expected-ops.txt`)에서 뽑는다.
    응시자의 `plan.json` 에서 뽑으면 **검증자가 피검증자를 믿는 것**이고, 아무것도
    계획하지 않은 답안이 아무 데도 안 보이는 채로 통과한다.

.EXAMPLE
    .\Invoke-ExamApply.ps1 -Threat search-hijack -Revert

.EXAMPLE
    .\Invoke-ExamApply.ps1 -Threat search-hijack -Plugin ..\..\ai-exam\runs\2026-09-05-opus-5-hijack-r3\plugin.yaml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('appinit-implant', 'service-userinit', 'search-hijack', 'evilai-locust', 'ransomware', 'webshell-upload', 'proxy-dns-hijack', 'shortcut-hijack', 'cred-dump', 'regkey-stager', 'sideload-drop', 'hook-implant')]
    [string] $Threat,

    # 기본은 정답 플러그인. 응시자 답안을 재려면 그 경로를 준다.
    [string] $Plugin,

    [string] $VmAddress,
    [pscredential] $Credential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    # **`remedy-lab-base-v3` 부터 켜도 된다** (2026-09-11). 그전에는 되돌리면
    # 게스트의 자동 갱신기가 깨어나 채점 5 가 불합격했다 — Chrome 이 회차
    # 도중에 스스로 갱신했고 그것이 "치료가 만든 변화" 로 세어졌다.
    # v3 는 그 갱신기를 끈 지점이고, 같은 명령이 `-Revert` 로 합격한다
    # (README 의 '되돌리기가 갱신기를 깨웠다').
    [switch] $Revert,
    # 합격을 위협 폴더에 **증거로 남긴다**. `cargo xtask exam-apply` 가
    # 그것이 지금 자료로 재어진 것인지 본다.
    [switch] $Record,

    # `evilai-locust` 의 **실행 중이 아닌** 회차. 위협 설명이 "있을 때도 없을
    # 때도 처리돼야 한다" 고 요구하므로 두 쪽을 다 재고 다 기록한다 — 한 쪽만
    # 남기면 **탐지가 프로세스에 의존하게 되는 회귀를 게이트가 못 잡는다.**
    [switch] $NoProcess,

    [string] $Snapshot,
    [string] $Vmx
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
$Vmx       = Resolve-LabValue $Vmx 'windows_lab' 'windows_lab.identity.vmx' 'Vmx'
$Snapshot  = Resolve-LabValue $Snapshot 'windows_lab' 'windows_lab.snapshots.current' 'Snapshot'
# `evilai-locust` 의 감염 구성은 여기 있다 (아래 "감염" 절).
. (Join-Path $PSScriptRoot "InfectedState.ps1")

$triple = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"
$threatDir = Join-Path $repoRoot "testbed\ai-exam\threats\$Threat"
$expectedOps = Join-Path $threatDir "expected-ops.txt"
# **정답의 자리가 위협마다 다르다.** `evilai-locust` 은 제품이 싣는 진짜
# 플러그인이고 나머지는 시험 전용이다 (`xtask` 의 `exam::REFERENCES` 와 같은 표).
$refPluginDir = $(if ($Threat -eq 'evilai-locust') { Join-Path $repoRoot "plugins\evilai-locust" }
                  else { Join-Path $threatDir "reference-plugin" })
if (-not $Plugin) { $Plugin = Join-Path $refPluginDir "plugin.yaml" }

foreach ($p in @($expectedOps, $Plugin)) {
    if (-not (Test-Path $p)) { throw "없다: $p" }
}

# **증거는 정답 플러그인의 것만 남긴다.** 응시자 답안의 결과를 위협 폴더에
# 두면 그 위협의 "정답이 기계를 고친다" 는 기록이 응시자의 답으로 바뀐다.
$refPlugin = Join-Path $refPluginDir "plugin.yaml"
if ($NoProcess -and $Threat -ne 'evilai-locust') {
    throw "-NoProcess 는 evilai-locust 에서만 쓴다. 다른 위협의 픽스처는 프로세스를 스스로 정한다."
}
if ($Record -and ((Resolve-Path $Plugin).Path -ne (Resolve-Path $refPlugin).Path)) {
    throw "-Record 는 정답 플러그인으로 돌릴 때만 쓴다. 지금 대상: $Plugin"
}

if ($Build) {
    Write-Step "빌드: remedy.exe"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
    } finally { Pop-Location }
}
if (-not (Test-Path $binPath)) { throw "바이너리가 없다: $binPath  (-Build 로 만들 것)" }

# ───────────────────────────────────────────── 관측 범위

<#
    **치료가 끝난 뒤 그 자리가 남아 있어야 하는 Op** — 생성물에서 읽는다.

    나머지 Op 은 대상을 없앤다. 둘을 가르지 않으면 판정이 뒤집힌다 —
    `/etc/hosts` 는 남아야 맞고 `ca.key` 는 사라져야 맞는데, 한 잣대로 보면
    둘 중 하나는 늘 틀린 것으로 나온다.

    **손으로 적지 않는다.** 처음에는 이 파일에 목록을 박아 두었고 거기
    `hosts.restore_line` 이 빠져 있었다 — Windows 위협이 그 Op 을 쓰지 않아
    아무도 몰랐고, Linux 위협 `tls-intercept` 는 그것을 둘 쓴다. 표가 두 벌이면
    갈라진다.

    출처는 `Op::edits_in_place` 이고 `machine/ops.json` 으로 나온다. Op 이 하나
    늘면 컴파일러가 분류를 요구하므로 이 목록에 빈칸이 생길 수 없다.
#>
$opsJson = Join-Path $repoRoot "docs\plugin-guide\machine\ops.json"
if (-not (Test-Path $opsJson)) { throw "Op 표가 없다: $opsJson  (cargo xtask schema --write)" }
$OPS_THAT_SURVIVE = @(
    (Get-Content -LiteralPath $opsJson -Raw -Encoding UTF8 | ConvertFrom-Json).ops |
        Where-Object { $_.edits_in_place } | ForEach-Object { $_.id }
)
if (-not $OPS_THAT_SURVIVE.Count) { throw "Op 표에서 아무것도 읽지 못했다 — 그 상태의 판정은 전부 거짓이다" }

<#
    `expected-ops.txt` 를 읽어 **어디를 볼지**와 **무엇이 범위 안인지**를 정한다.

    한 줄은 `<op> <대상>` 이고 뒤에 ` :: <match>` 가 붙을 수 있다.

    | 대상 | 관측 |
    |---|---|
    | 레지스트리 **값** 경로 | 그 값을 본다 |
    | 서비스·예약 작업 | 관측기가 늘 전수를 담으므로 더 볼 것이 없다 |
    | 파일 경로 | **부모 디렉터리**를 훑는다 — 지워졌는가와 옆엣것이 살아남았는가를 함께 본다 |
    | `-` (`process.kill`) | 프로세스는 늘 담는다 |

    `ScopeKeys` 는 "이 자리는 위협이 밟는 자리다" 를 판정하는 데 쓴다.
    `RebootKeys` 는 `file.delete_on_reboot` 의 대상이다 — **다음 부팅까지
    파일이 남아 있는 것이 정상**이라 잔존으로 세면 안 된다.
#>
function Get-ObservationScope {
    param([string] $Path)
    $reg = @(); $dirs = @(); $keys = @(); $reboot = @(); $ops = @{}; $content = @{}
    <#
        **자리 하나가 이름 여럿으로 불린다.**

        관측기와 계획이 같은 것을 다르게 적는 자리가 있어서, 범위에 두 이름을
        다 넣어야 그 자리가 새어 나가지 않는다 (예외 목록은 `path=<값>`, 서비스와
        자동실행은 leaf). 그런데 **이름을 세면 분모가 부푼다** — 2026-09-06 까지
        `service-userinit` 이 자리 5곳을 6으로, `evilai-locust` 이 5곳을 7로
        적고 있었고, 그래서 치료가 완전한데도 `4/6`·`4/7` 로 보였다.

        여기서 자리(사전 등록 자료의 대상)와 그 자리를 가리키는 이름들을
        갈라 둔다. 판정은 이름으로 하고 **세는 것은 자리로** 한다.
    #>
    $places = [ordered]@{}
    foreach ($line in (Get-Content -LiteralPath $Path -Encoding UTF8)) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith("#")) { continue }
        $parts = ($t -split '\s+::\s+', 2)
        $body = $parts[0]
        $match = $(if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" })
        $sp = $body.IndexOf(' ')
        if ($sp -lt 1) { continue }
        $op = $body.Substring(0, $sp).Trim()
        $target = $body.Substring($sp + 1).Trim()
        if (-not $target -or $target -eq '-') { continue }

        $k = ConvertTo-ScopeKey $target
        $keys += $k
        if (-not $places.Contains($k)) { $places[$k] = @($k) }
        $kind = $(if ($OPS_THAT_SURVIVE -contains $op) { 'survives' } else { 'gone' })

        <#
            **고치는 Op 의 대상은 내용을 본다.**

            없애는 Op 은 "그 자리가 사라졌는가" 로 끝나지만 고치는 Op 은 그럴
            수 없다. 파일이 남아 있어야 하고, 남은 내용이 **사전 등록 자료가
            지목한 만큼만** 달라져야 한다. 그것을 안 재면 `modules.remote` 하나를
            빼는 답안과 파일을 통째로 비우는 답안이 같은 초록을 받는다.

            청정 기준으로는 잴 수 없다 — 이 파일들은 픽스처가 감염과 함께 세운
            정상 소프트웨어의 것이라 청정 기계에 없다. 그래서 2026-09-06 까지
            `agent-config.json` 은 매 회차 `판정 불가` 였다.

            리눅스 하네스의 `line=` 검사와 같은 자리다. Windows 재료가 쓰는
            매치는 `key_path=` 뿐이고, **모르는 매치는 조용히 넘기지 않는다** —
            그 회차는 그 요구를 재지 않은 것이므로 미결로 끝난다.
        #>
        if ($kind -eq 'survives' -and $match -and $target -notmatch '^(HKLM|HKCU|HKCR|HKCC|HKU)\\') {
            if ($match -match '(^|,\s*)key_path=(.+)$') {
                $content[$k] = @{ Kind = 'json'; KeyPath = $Matches[2].Trim(); Target = $target }
            } elseif ($match -match '(^|,\s*)args=(.+)$') {
                # **바로가기가 떼어야 할 인자** (2026-09-21). 리눅스 하네스는
                # 이것을 `.desktop` 의 `Exec=` 에서 재고 있었는데
                # (`ldso-preload`), Windows 쪽에는 그 검사가 없어 `.lnk` 를 쓰는
                # 위협은 미결로 끝났다 — `line=` 과 같은 부류의 비대칭이다.
                #
                # 수집기가 필드 코드를 이미 뺀 값이라 그대로 "없어져야 할 것"
                # 이다 (`write::split_exec`).
                $content[$k] = @{ Kind = 'args'; Args = $Matches[2]; Target = $target }
            } elseif ($match -match '(^|,\s*)line=(.+)$') {
                # **줄 단위 치료** (2026-09-21). 그전까지 이 하네스는 `key_path=`
                # 밖에 몰라서 `line=` 을 쓰는 위협은 Windows 에서 미결로 끝났다 —
                # 리눅스 쪽은 같은 것을 재고 있었으므로 **하네스가 비대칭**이었다.
                #
                # 내용을 다듬지 않는다. hosts 의 줄에는 탭이 들어 있고 첫
                # `line=` 뒤가 통째로 그 줄이다 (리눅스 쪽 `${match#*line=}` 와
                # 같은 규칙).
                $ln = $Matches[2]
                # **한 자리에 줄이 여럿 걸린다.** hosts 는 두 줄이 한 파일에
                # 온다 — 덮어쓰면 뒤엣것만 재고 앞엣것은 조용히 빠진다.
                if ($content.ContainsKey($k) -and $content[$k].Kind -eq 'line') {
                    $content[$k].Lines += $ln
                } else {
                    $content[$k] = @{ Kind = 'line'; Lines = @($ln); Target = $target }
                }
            } else {
                $content[$k] = @{ Kind = 'unknown'; Raw = $match; Target = $target }
            }
        }
        # 한 자리에 Op 이 여럿 걸릴 수 있다 (서비스는 중지·비활성·삭제가 다 온다).
        # 하나라도 없애는 Op 이면 그 자리는 없어져야 한다.
        if (-not $ops.ContainsKey($k) -or $kind -eq 'gone') { $ops[$k] = $kind }
        if ($op -eq 'file.delete_on_reboot') { $reboot += $k }

        if ($target -match '^(HKLM|HKCU|HKCR|HKCC|HKU)\\') {
            if ($op -match '^av\.') {
                # **예외 목록은 두 이름으로 불린다.** 계획은 레지스트리 경로로
                # 적고(`…\Exclusions\Paths\C:\…`) 관측기는 `<종류>=<값>` 으로
                # 적는다. 잇지 않으면 이 자리가 범위 밖으로 새어 나가고, 치료가
                # 예외를 못 지웠을 때 그것이 **기계 잡음으로 분류된다.**
                if ($target -match '\\Exclusions\\(Paths|Processes|Extensions)\\(.+)$') {
                    $kindName = @{ Paths = 'path'; Processes = 'process'; Extensions = 'extension' }[$Matches[1]]
                    $ek = ConvertTo-ScopeKey ("{0}={1}" -f $kindName, $Matches[2])
                    $keys += $ek
                    $ops[$ek] = 'gone'
                    $places[$k] += $ek
                }
            }
            # 서비스·예약 작업·자동실행의 대상도 레지스트리 경로 모양이지만
            # **값이 아니다.** 값으로 읽으면 늘 '(값 없음)' 이라 전후가 같고,
            # 그러면 관측한 것처럼 보이면서 아무것도 재지 않는다. 그쪽은
            # 관측기의 전용 섹션이 전수로 담고, 거기서는 **leaf** 로 나온다
            # (`Host Cache Service` · `SystemSoftwareUpdater`).
            elseif ($op -match '^(service|persistence|autorun)\.') {
                $leaf = ConvertTo-ScopeKey (Split-Path -Leaf $target)
                $keys += $leaf
                $ops[$leaf] = 'gone'
                $places[$k] += $leaf
            }
            else { $reg += $target }
        } elseif ($op -match '^persistence\.') {
            # 예약 작업의 자리표(`\Microsoft\Windows\Locust`)다. 파일 경로가
            # 아니므로 훑을 디렉터리를 만들지 않는다 — 만들면 `\Microsoft\Windows`
            # 를 훑으라는 뜻이 되어 아래 넓이 검사에 걸린다. 관측기의
            # `scheduled_tasks` 섹션이 같은 문자열로 담으므로 위의 $k 로 맞는다.
        } else {
            # **`dir.*` 의 대상은 그 자체가 디렉터리다.** 부모를 잡으면
            # `C:\ProgramData\SvcHostCache-3f8a` 대신 `C:\ProgramData` 를 통째로
            # 훑게 되고, 그러면 백신 로그와 Windows Update 기록이 매 회차
            # 수십 건씩 '치료가 만든 변화' 로 올라온다 — 관측기의 머리가
            # 경고하는 바로 그것이다 (2026-09-05 실측 23건).
            $root = $(if ($op -like 'dir.*') { $target } else { Split-Path -Parent $target })
            if ($root) {
                # 드라이브 바로 아래를 훑으라는 것은 자료의 잘못이다. 조용히
                # 좁히면 아무도 모르게 관측이 얕아진다.
                $segs = @($root -split [regex]::Escape('\') | Where-Object { $_ })
                if ($segs.Count -lt 3) {
                    throw "관측 루트가 너무 넓다: '$root' (대상 '$target'). expected-ops.txt 의 그 줄이 드라이브 가까이를 가리킨다."
                }
                $dirs += $root
            }
        }
    }
    [pscustomobject]@{
        Registry   = @($reg | Sort-Object -Unique)
        FileRoots  = @($dirs | Sort-Object -Unique)
        ScopeKeys  = @($keys | Where-Object { $_ } | Sort-Object -Unique)
        ScopeOps   = $ops
        Content    = $content
        Places     = $places
        RebootKeys = @($reboot | Where-Object { $_ } | Sort-Object -Unique)
    }
}

<#
    비교용으로 자리 이름을 고른다.

    관측기는 레지스트리를 PowerShell 경로로 적고(`HKLM:\...`) 시험 자료는
    하이브 이름으로 적는다(`HKLM\...`). 콜론을 떼고 소문자로 내려 둘을 만나게
    한다. `HKU` 는 관측기에서 `Registry::HKEY_USERS\...` 로 나온다.
#>
function ConvertTo-ScopeKey {
    param([string] $S)
    if ([string]::IsNullOrWhiteSpace($S)) { return $null }
    $k = $S.Trim().ToLowerInvariant()
    $k = $k -replace '^registry::hkey_users\\', 'hku\'
    $k = $k -replace '^registry::hkey_local_machine\\', 'hklm\'
    $k = $k -replace '^registry::hkey_current_user\\', 'hkcu\'
    $k = $k -replace '^(hklm|hkcu|hkcr|hkcc|hku):\\', '$1\'
    $k.TrimEnd('\')
}

<#
    관측된 자리가 위협이 밟는 범위 안인가. 대상과 같거나 그 아래면 안이다.
    **걸린 대상을 돌려준다** — 그 대상의 Op 이 "남아야 하는가" 를 정하기 때문이다.
    `$null` 이면 범위 밖이다.
#>
function Get-ScopeMatch {
    param([string] $Key, [string[]] $Scope)
    $k = ConvertTo-ScopeKey $Key
    if (-not $k) { return $null }
    foreach ($s in $Scope) {
        if ($k -eq $s) { return $s }
        if ($k.StartsWith($s + '\')) { return $s }
        # 서비스 이름처럼 leaf 만 아는 자리. 자리 이름이 대상을 품으면 안이다.
        if ($s.Length -ge 6 -and $k.EndsWith('\' + $s)) { return $s }
    }
    $null
}

function Test-InScope {
    param([string] $Key, [string[]] $Scope)
    $null -ne (Get-ScopeMatch $Key $Scope)
}

<# 화면에 적을 때만 줄인다. 온전한 값은 exam-apply.json 에 남는다. #>
function Format-Short {
    param([string] $S, [int] $Max = 220)
    if ($null -eq $S) { return "(없음)" }
    if ($S.Length -le $Max) { return $S }
    "{0}... (총 {1}자)" -f $S.Substring(0, $Max), $S.Length
}

<#
    JSON 한 그루를 **자리에 기대지 않는 한 문자열**로 접는다.

    치료는 파일을 다시 쓴다 — 들여쓰기도 키 차례도 원본과 다르다(실측:
    223바이트 → 167바이트). 그래서 원문끼리 견주면 무엇을 고쳤든 늘 다르다.
    키를 정렬해 접으면 남는 차이는 **내용의 차이**뿐이다.
#>
function ConvertTo-CanonicalJson {
    param($Node)
    if ($null -eq $Node) { return 'null' }
    if ($Node -is [string] -or $Node -is [bool] -or $Node -is [int] -or $Node -is [long] -or
        $Node -is [double] -or $Node -is [decimal]) {
        return (ConvertTo-Json $Node -Compress)
    }
    if ($Node -is [System.Collections.IEnumerable]) {
        return '[' + (@(@($Node) | ForEach-Object { ConvertTo-CanonicalJson $_ }) -join ',') + ']'
    }
    $parts = @($Node.PSObject.Properties | Sort-Object Name | ForEach-Object {
        '{0}:{1}' -f (ConvertTo-Json $_.Name -Compress), (ConvertTo-CanonicalJson $_.Value)
    })
    '{' + ($parts -join ',') + '}'
}

<#
    점으로 이은 자리(`modules.remote`)의 값을 하나 뺀다.

    **뺐는지 못 뺐는지를 돌려준다.** 감염 상태에 그 키가 없으면 픽스처가
    세우지 않은 것이고, 그 회차는 이 요구를 잰 것이 아니다.
#>
function Remove-JsonKeyPath {
    param($Root, [string] $KeyPath)
    $segs = @($KeyPath -split '\.')
    $node = $Root
    for ($i = 0; $i -lt $segs.Count - 1; $i++) {
        if ($null -eq $node) { return $false }
        $prop = $node.PSObject.Properties[$segs[$i]]
        if (-not $prop) { return $false }
        $node = $prop.Value
    }
    if ($null -eq $node) { return $false }
    $leaf = $segs[$segs.Count - 1]
    if (-not $node.PSObject.Properties[$leaf]) { return $false }
    $node.PSObject.Properties.Remove($leaf)
    $true
}

<#
    남아야 하는 자리 — `must-remain.txt`.

    `expected-ops.txt` 가 **치료가 해야 할 일**이라면 이 파일은 **치료가
    건드리면 안 되는 것**을 적는다. 픽스처가 감염과 함께 세운 정상
    소프트웨어라 청정 기계에는 없다.

    **청정이 아니라 감염 상태와 견준다.** 청정에 없는 자리라 청정과 견주면
    영영 `판정 불가` 이고, 치료가 지워 버리면 청정도 치료도 없어서 차분에
    아무것도 나타나지 않는다 — 2026-09-06 감사가 찾은 구멍이 그것이다.
    `C:\ProgramData\Acme\updater.exe` 를 지우는 답안이 지금까지 통과했다.
#>
function Get-MustRemain {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "must-remain.txt 가 없다: $Path (적을 것이 없으면 빈 파일로 둘 것)"
    }
    $files = @(); $reg = @(); $keys = @()
    foreach ($line in (Get-Content -LiteralPath $Path -Encoding UTF8)) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith("#")) { continue }
        if ($t -match '^(HKLM|HKCU|HKCR|HKCC|HKU)\\') { $reg += $t } else { $files += $t }
        $keys += ConvertTo-ScopeKey $t
    }
    [pscustomobject]@{
        Files    = @($files | Sort-Object -Unique)
        Registry = @($reg | Sort-Object -Unique)
        Keys     = @($keys | Where-Object { $_ } | Sort-Object -Unique)
    }
}

$scope = Get-ObservationScope $expectedOps
$mustRemain = Get-MustRemain (Join-Path $threatDir "must-remain.txt")
# 관측기에 함께 요청한다. 파일 경로를 루트로 주면 `Get-ChildItem -LiteralPath`
# 가 그 파일 자신을 돌려주므로 한 자리만 정확히 담긴다.
$scope.FileRoots = @(@($scope.FileRoots) + @($mustRemain.Files) | Sort-Object -Unique)
$scope.Registry  = @(@($scope.Registry)  + @($mustRemain.Registry) | Sort-Object -Unique)

# **페이로드 폴더를 사전 등록 자료에서 뽑는다.** 여기 리터럴로 적으면
# `expected-ops.txt` 와 갈라질 수 있고, 그러면 픽스처가 세운 자리와 관측하는
# 자리가 달라져 "감염이 자국을 남기지 않았다" 로 끝난다.
$evilaiDir = $null
if ($Threat -eq 'evilai-locust') {
    foreach ($line in (Get-Content -LiteralPath $expectedOps -Encoding UTF8)) {
        if ($line -match '^dir\.delete_recursive\s+(.+?)\s*$') { $evilaiDir = $Matches[1]; break }
    }
    if (-not $evilaiDir) { throw "expected-ops.txt 에 dir.delete_recursive 가 없다 — 페이로드 폴더를 알 수 없다" }
    Write-Host "    페이로드 폴더 $evilaiDir" -ForegroundColor Gray
}
Write-Step "관측 범위 — $Threat 의 expected-ops.txt 에서"
foreach ($r in $scope.Registry) { Write-Host "    레지스트리  $r" -ForegroundColor Gray }
foreach ($d in $scope.FileRoots) { Write-Host "    파일 루트   $d" -ForegroundColor Gray }
foreach ($m in $mustRemain.Keys) { Write-Host "    남아야      $m" -ForegroundColor Gray }
Write-Host ("    범위 안 자리 {0}곳 (이름 {1}개) · 재부팅 대기 {2}개" -f `
    $scope.Places.Count, $scope.ScopeKeys.Count, $scope.RebootKeys.Count) -ForegroundColor Gray
if (-not $scope.ScopeKeys.Count) {
    throw "관측 범위가 비었다 — expected-ops.txt 를 읽지 못했다. 이 상태의 '변화 없음' 은 거짓이다."
}

if ($Revert) {
    Write-Step "스냅샷 복원: $Snapshot"
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Snapshot $Snapshot -Vmx $Vmx
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $repoRoot "testbed\harness\results\exam-apply-$Threat-$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

# try 안에서 예외가 나면 판정이 서지 않는다. 그때의 종료 코드는 "합격" 이 아니다.
$verdict = "inconclusive"
$session = Connect-LabVmRetrying -VmAddress $VmAddress -Credential $Credential
$fixtured = $false
$gState = "$LabRoot\scripts\Capture-State.ps1"
$traceStages = @()
$traceHost = ""
$traceActions = 0

<# 게스트에서 상태를 뜨고 호스트로 회수한다. #>
function Get-State {
    param([string] $Tag)
    $guestOut = "$LabRoot\exam-state-$Tag.json"
    $r = Invoke-Command -Session $session `
        -ArgumentList $gState, $guestOut, $scope.FileRoots, $scope.Registry -ScriptBlock {
        param($script, $out, $roots, $regs)
        # **`powershell -File` 로 부르지 않는다** — 배열 인자가 문자열 하나로
        # 뭉개져서 `-FilePaths` 가 루트 하나로 접힌다. 대신 이 세션에서만
        # 실행 정책을 푼다 (기계의 정책은 건드리지 않는다).
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force | Out-Null
        & $script -OutFile $out -FilePaths $roots -RegistryValues $regs 2>&1 | Out-String
    }
    $local = Join-Path $outDir "state-$Tag.json"
    Copy-Item -Path $guestOut -Destination $local -FromSession $session -Force
    if ((Get-Item -LiteralPath $local).Length -eq 0) { throw "상태 캡처가 0바이트다: $Tag" }
    <#
        **그 회차의 흔적을 모은다.**

        증거 파일은 손으로 쓸 수 있는 JSON 이고, 게이트는 그것을 믿는다. 그것을
        완전히 막을 수는 없다 — 하네스도 우리 코드다. 목표는 "손으로 못 쓰게"
        가 아니라 **"손으로 쓴 것이 티가 나게"** 다.

        기계만 낼 수 있는 값을 함께 적는다. 회차마다 달라지고 서로 아귀가 맞아야
        하는 값이라, 지어내려면 그럴듯한 기계 한 대를 통째로 지어내야 한다.
    #>
    $st = Get-Content -LiteralPath $local -Raw -Encoding UTF8 | ConvertFrom-Json
    $script:traceStages += [ordered]@{
        stage  = $Tag
        at     = $st.captured_at
        sha256 = (Get-FileHash -LiteralPath $local -Algorithm SHA256).Hash.ToLower()
        counts = $st.counts
    }
    if (-not $script:traceHost) { $script:traceHost = $st.hostname }
    Write-Ok "상태 '$Tag' 회수"
    $local
}

<#
    고치는 대상의 **내용**을 단계마다 뜬다.

    관측기는 파일을 해시로만 적는다 — 그것으로는 "무엇이 달라졌는가" 를 말할
    수 없다. 리눅스 하네스가 `cp` 로 원본을 떠 두는 것과 같은 자리다.

    **바이트로 읽어 Base64 로 건넨다.** `Get-Content` 로 받으면 인코딩이
    도중에 한 번 더 해석돼 원문이 아니게 된다.
#>
# 첫 인자 목록에서 둘째 목록의 토큰을 **앞에서부터 하나씩** 뺀 나머지.
#
# 리눅스 하네스의 `minus_tokens` 를 그대로 옮긴 것이다 — 같은 것을 재는 두
# 하네스가 다른 규칙을 쓰면 같은 답안이 플랫폼마다 다른 판정을 받는다.
# 같은 토큰이 둘 있으면 **하나만** 빠진다(awk 쪽의 `break`).
function Remove-ArgTokens {
    param([string] $All, [string] $Drop)
    $a = @($All -split '\s+' | Where-Object { $_ })
    foreach ($d in @($Drop -split '\s+' | Where-Object { $_ })) {
        for ($i = 0; $i -lt $a.Count; $i++) {
            if ($a[$i] -ceq $d) { $a[$i] = $null; break }
        }
    }
    (@($a | Where-Object { $_ }) -join ' ')
}

function Get-ContentSnapshot {
    param([string] $Tag)
    $snap = @{}
    foreach ($k in $scope.Content.Keys) {
        $path = $scope.Content[$k].Target
        # **바로가기는 바이너리다.** 바이트로 읽어 글자로 바꾸면 깨지므로
        # 게스트에서 해석해 필요한 둘만 받는다 — 떼어야 할 인자가 붙는 자리와,
        # 손대지 않았어야 할 대상 경로다.
        if ($scope.Content[$k].Kind -eq 'args') {
            $j = Invoke-Command -Session $session -ArgumentList $path -ScriptBlock {
                param($p)
                if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null }
                $sh = New-Object -ComObject WScript.Shell
                $sc = $sh.CreateShortcut($p)
                @{ Target = $sc.TargetPath; Arguments = $sc.Arguments } | ConvertTo-Json -Compress
            }
            $snap[$k] = $j
            if ($j) {
                $safe = ($k -replace '[^a-z0-9]', '_')
                Set-Content -LiteralPath (Join-Path $outDir "content-$Tag-$safe.json") -Value $j -Encoding UTF8 -NoNewline
            }
            continue
        }
        $b64 = Invoke-Command -Session $session -ArgumentList $path -ScriptBlock {
            param($p)
            if (Test-Path -LiteralPath $p -PathType Leaf) {
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($p))
            } else { $null }
        }
        if ($b64) {
            $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)).TrimStart([char]0xFEFF)
            $snap[$k] = $text
            $safe = ($k -replace '[^a-z0-9]', '_')
            Set-Content -LiteralPath (Join-Path $outDir "content-$Tag-$safe.txt") -Value $text -Encoding UTF8 -NoNewline
        } else {
            $snap[$k] = $null
        }
    }
    $snap
}

<# 두 상태의 차분. Compare-State 는 종료 코드로 판정하므로 여기서는 JSON 만 쓴다. #>
function Get-Diff {
    param([string] $Before, [string] $After, [string] $Tag)
    $out = Join-Path $outDir "diff-$Tag.json"
    & (Join-Path $PSScriptRoot "Compare-State.ps1") -Before $Before -After $After -OutFile $out |
        Out-Null
    Get-Content -LiteralPath $out -Raw -Encoding UTF8 | ConvertFrom-Json
}

<#
    차분 하나를 `<섹션>/<키>` 집합과 항목 목록으로 편다.
    버킷(added/removed/changed)이 달라도 **같은 자리**면 같은 것으로 본다 —
    감염이 값을 바꾸고 치료가 그 값을 지웠다면 버킷은 다르지만 자리는 같다.
#>
function Expand-Diff {
    param($Diff)
    $items = @()
    foreach ($s in @($Diff.sections)) {
        foreach ($bucket in @("added", "removed", "changed")) {
            foreach ($e in @($s.$bucket)) {
                if ($null -eq $e) { continue }
                $items += [pscustomobject]@{
                    Section = $s.section
                    Bucket  = $bucket
                    Key     = "$($e.key)"
                    Id      = "$($s.section)`t$($e.key)"
                    Before  = "$($e.before)"
                    After   = "$($e.after)"
                }
            }
        }
    }
    $items
}

# **우리 자신이 남기는 흔적** (설계-03 §8 — 고정된 식별 가능한 이름).
# 판정에서 빼되 화면에는 띄운다. 숨기면 다음 사람이 다시 조사한다.
$ownTraces = @("remedy-verify", "\remedy\", "remedy restore")
function Test-OwnTrace {
    param([string] $Key)
    foreach ($t in $ownTraces) {
        if ($Key.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    $false
}

try {
    Write-Step "배포"
    Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($root)
        foreach ($d in @("$root\bin", "$root\scripts", "$root\exam")) {
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        }
        Remove-Item "$root\exam\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
    # **폴더 전체를 보낸다.** `plugin.yaml` 하나만 보내면 `rules/*.yar` 이
    # 빠지고, 코어는 그것을 경고하면서 그 룰을 **평가하지 못한 채** 계속
    # 간다 — evilai 는 판별자가 그 YARA 룰이라 판정이 통째로 서지 않았다
    # (2026-09-05 실측: 증거 5 → 4, 판정 1 → 0).
    $srcDir = Split-Path -Parent (Resolve-Path $Plugin).Path
    Copy-Item $srcDir -Destination "$LabRoot\exam\plugin" -ToSession $session -Recurse -Force
    $guestPlugin = "$LabRoot\exam\plugin\plugin.yaml"
    Copy-Item (Join-Path $PSScriptRoot "..\guest\Capture-State.ps1") -Destination $gState -ToSession $session -Force
    Copy-Item (Join-Path $PSScriptRoot "..\guest\New-ThreatFixtures.ps1") `
        -Destination "$LabRoot\scripts\New-ThreatFixtures.ps1" -ToSession $session -Force
    Write-Ok "remedy.exe · 플러그인 · 관측기 · 픽스처 스크립트"

    Write-Step "1/3 청정 기준"
    $sClean = Get-State "clean"

    Write-Step "감염: $Threat"
    if ($Threat -eq 'evilai-locust') {
        # **이 위협의 감염은 다른 모듈이 세운다.** `evilai-locust` 은 P9 부터
        # 있던 위협이고 `InfectedState.ps1` 이 그 구성을 갖고 있다 — 코퍼스
        # 스냅샷과 P9 검증이 같은 것을 쓴다. 여기에 복사해 두면 세 곳이 되고
        # 언젠가 갈라진다.
        #
        # 페이로드 바이트는 **룰 파일에서 만든다**(`Get-SynthPayloadBytes`).
        # 상수를 베껴 두면 룰만 고쳤을 때 조용히 어긋나고, 그때 발화하지 않는
        # 페이로드로 "치료가 됐다" 가 나온다 — 지울 것이 없었을 뿐이다.
        $bytes = Get-SynthPayloadBytes -RulePath (Join-Path $refPluginDir "rules\evilai.yar")
        Set-InfectedState -Session $session -PayloadDir $evilaiDir | Out-Null
        $landed = Set-GuestPayload -Session $session -PayloadDir $evilaiDir -Bytes $bytes
        $fixtured = $true
        Write-Ok ("픽스처 세움 — 페이로드 {0} B · {1}" -f $landed.Size, $landed.Sha256.Substring(0, 16))
        # **실행 중 상태까지 세운다.** 위협 설명이 요구하는데 코퍼스 스냅샷에는
        # 그 프로세스가 없어 한 번도 시험되지 않은 자리다. 현재 디렉터리를
        # 페이로드 폴더로 쥐므로 **죽이지 않으면 폴더가 지워지지 않는다** —
        # 순서 요구가 여기서 진짜로 걸린다.
        if ($NoProcess) {
            Write-Ok "실행 중 상태 없음 — 위협 설명의 '없을 때' 쪽을 잰다"
        } else {
            $proc = Start-InfectedProcess -Session $session -PayloadDir $evilaiDir
            Write-Ok ("실행 중 상태 — node.exe pid={0}" -f $proc.Pid)
        }
    } else {
        Invoke-Command -Session $session -ArgumentList $LabRoot, $Threat -ScriptBlock {
            param($root, $threat)
            powershell -ExecutionPolicy Bypass -File "$root\scripts\New-ThreatFixtures.ps1" `
                -Threat $threat 2>&1
        } | Out-Null
        $fixtured = $true
        Write-Ok "픽스처 세움"
    }

    Write-Step "2/3 감염 상태"
    $sInfected = Get-State "infected"
    $cInfected = Get-ContentSnapshot "infected"
    <#
        **감염이 그 자리에 자국을 남겼는가 — 기계에 직접 묻는다.**

        관측기의 파일 섹션은 루트 **안의 파일**을 적지 루트 자신은 적지 않는다.
        그래서 `dir.delete_recursive` 의 대상은 감염 차분에 나타나지 않고,
        그것만 보면 그 자리는 영영 "재지 않은 곳" 으로 남는다.

        더 나쁜 것은 픽스처가 그 폴더를 세우지 못한 경우다. 그때도 치료 뒤
        `Test-Path` 는 조용하고, 그 회차는 `dir.delete_recursive` 를 **한 번도
        시험하지 않은 채** 통과한다.
    #>
    $fsAllTargets = @($scope.ScopeKeys | Where-Object {
        $scope.ScopeOps[$_] -eq 'gone' -and $_ -match '^[a-z]:\\'
    })
    $infectedFsPresent = @()
    if ($fsAllTargets.Count) {
        $infectedFsPresent = @(Invoke-Command -Session $session -ArgumentList (, $fsAllTargets) -ScriptBlock {
            param($paths)
            @($paths | Where-Object { Test-Path -LiteralPath $_ })
        }) | ForEach-Object { $_.ToLowerInvariant() }
    }

    Write-Step "치료: run --yes"
    $run = Invoke-GuestExe -Session $session -Path "$LabRoot\bin\remedy.exe" -Arguments @(
        "run", "--plugin", $guestPlugin,
        "--out-dir", "$LabRoot\exam\out", "--yes", "--state-dir", "$LabRoot\exam\state")
    # **`out`·`err` 이다.** `output` 은 없는 이름이라 조용히 빈 로그가 남는다 —
    # 실패했을 때 정확히 그 로그가 필요하다 (2026-09-05 실측).
    ($run.out + "`n----- stderr -----`n" + $run.err) |
        Out-File -FilePath (Join-Path $outDir "run.log") -Encoding utf8
    Write-Host "    종료 코드 $($run.exit)"
    foreach ($l in (($run.out + "`n" + $run.err) -split "`r?`n")) {
        if ($l -match '(수행|실패|보류|멈췄다|guard)') { Write-Host "      $($l.Trim())" -ForegroundColor DarkGray }
    }

    # **평가하지 못한 룰이 있으면 잰 것이 아니다.** 코어는 그것을 경고하고
    # 계속 가는데(그것이 옳은 동작이다), 그 회차의 판정은 "이 플러그인이
    # 기계를 고치는가" 가 아니라 "일부가 빠진 사본이 고치는가" 다.
    $crippled = (($run.out + "`n" + $run.err) -match "평가하지 못했습니다")
    if ($crippled) { Write-Bad "룰을 평가하지 못했다 — 이 회차는 플러그인 전체를 재지 못했다" }

    if ($run.out -match '(\d+)건 수행 완료') { $traceActions = [int]$Matches[1] }

    Write-Step "3/3 치료 후 상태"
    $sTreated = Get-State "treated"
    $cTreated = Get-ContentSnapshot "treated"

    # ───────────────────────────────────── 판정
    $dInfect = Get-Diff $sClean $sInfected "infect"
    $dRemain = Get-Diff $sClean $sTreated "remain"
    # **감염 상태와 치료 상태의 차분.** 남아야 하는 자리는 청정에 없으므로
    # 위의 두 차분 중 어느 것에도 나타나지 않는다 — 치료가 지워도 청정과
    # 치료가 똑같이 '없음' 이라 조용하다.
    $dTouch = Get-Diff $sInfected $sTreated "touch"

    $infectIds = @{}
    foreach ($i in (Expand-Diff $dInfect)) { $infectIds[$i.Id] = $true }

    <#
        관측된 변화 하나를 다섯으로 가른다.

        판정의 뼈대는 **범위 안인가**(위협이 밟는 자리인가, 사전 등록 자료가
        정한다)와 **감염 차분에 있었는가**(치료 전부터 그랬는가)의 조합이다.

        | 범위 | 감염 차분 | 뜻 |
        |---|---|---|
        | 안 | — | **불일치** — 치료 뒤에도 청정 기준과 다르다 (불합격) |
        | 밖 | 없음 | **치료가 만든 변화** — 감염 전에도 치료 전에도 없었다 (불합격) |
        | 밖 | 있음 | 치료 전부터 있던 변화 — 기계가 스스로 한 것 (보고만) |

        마지막 줄이 없으면 이 게이트는 늑대소년이 된다. 실측: 첫 회차에서
        크롬이 부팅 직후 낡은 확장 판본을 정리하며 파일 179건을 지웠고, 그것이
        청정→감염과 청정→치료 양쪽에 똑같이 나타났다.
    #>
    $mismatch = @(); $caused = @(); $preexisting = @(); $traces = @(); $reboot = @(); $unjudged = @()
    $churn = 0
    foreach ($i in (Expand-Diff $dRemain)) {
        # 프로세스 증감은 살아 있는 기계에서 저절로 일어난다.
        if ($i.Section -eq "processes") { continue }
        # 서비스의 **실행 상태만** 달라진 것도 그렇다 (`Compare-State.ps1` 의
        # `Test-Volatile` 과 같은 이유 — 트리거 서비스가 일을 마치고 멈춘다).
        # 값은 `<상태>|<시작유형>|<이미지>|<복구동작>` 이다. **이미지와 복구
        # 동작이 그대로면** 저절로 일어나는 축에 든다 — Windows Update 가
        # 요청 시작 서비스의 시작 유형을 Auto/Manual 로 오가게 한다
        # (2026-09-05 실측: BITS 가 Running|Auto → Stopped|Manual 로 바뀌어
        # 부수 피해로 잘못 세어졌다). 상태만 보는 것으로는 그것을 못 거른다.
        #
        # **숨기지는 않는다** — 아래 `churn` 으로 세어 화면에 적는다.
        if ($i.Section -eq "services" -and $i.Bucket -eq "changed") {
            $bp = @($i.Before -split '\|'); $ap = @($i.After -split '\|')
            if ($bp.Count -eq $ap.Count -and $bp.Count -ge 4) {
                if ($bp[2] -eq $ap[2] -and $bp[3] -eq $ap[3]) { $churn++; continue }
            }
        }

        if (Test-OwnTrace $i.Key) { $traces += $i; continue }
        # 남아야 하는 자리는 아래 $damaged 가 감염↔치료로 판정한다. 여기서 또
        # 세면 한 건이 두 줄로 적히고, 더 나쁘게는 청정에 없는 자리라
        # `치료 전부터 있던 변화` 로 조용히 묻힌다.
        if (Test-InScope $i.Key $mustRemain.Keys) { continue }
        if (Test-InScope $i.Key $scope.RebootKeys) { $reboot += $i; continue }

        $hit = Get-ScopeMatch $i.Key $scope.ScopeKeys
        if ($hit) {
            # 내용 검사가 판정하는 자리다. 차분은 "파일이 달라졌다" 까지만
            # 말할 수 있고, 우리가 물어야 할 것은 "지목한 만큼만 달라졌는가" 다.
            if ($scope.Content.ContainsKey($hit)) { continue }
            # **남아야 하는 자리와 없어져야 하는 자리를 가른다** (위 $OPS_THAT_SURVIVE).
            if ($scope.ScopeOps[$hit] -eq 'survives' -and $i.Bucket -eq 'added') {
                # 청정 기계에 없던 자리다 — 픽스처가 위협과 함께 **정상
                # 소프트웨어까지 설치**한 경우가 이렇다 (appinit 의 Acme 에이전트).
                # 그 자리는 치료 뒤에도 남아 있는 것이 맞고, 내용이 옳은지는
                # 견줄 청정 값이 없어 **여기서는 판정할 수 없다.**
                $unjudged += $i
            } else {
                $mismatch += $i
            }
            continue
        }
        if ($infectIds.ContainsKey($i.Id)) { $preexisting += $i } else { $caused += $i }
    }

    # **없어져야 할 파일·폴더가 아직 있는가 — 기계에 직접 묻는다.**
    #
    # 관측기의 파일 섹션은 루트 **안의 파일**을 적지 나 루트 자신은 적지 않는다.
    # 그래서 `dir.delete_recursive` 가 실패해 **빈 폴더가 남아도** 차분에는
    # 아무것도 나타나지 않는다 — 2026-09-05 실측: `process.kill` 을 뺀 답안이
    # 폴더 삭제에 실패했는데(사용 중) '범위 안 불일치 0건' 이었다.
    $leftovers = @()
    # **재부팅 대기 대상은 뺀다.** `file.delete_on_reboot` 의 대상은 다음
    # 부팅까지 남아 있는 것이 정상이다 — 여기 넣으면 `search-hijack` 이 매
    # 회차 거짓 불합격이 된다.
    $fsTargets = @($scope.ScopeKeys | Where-Object {
        $scope.ScopeOps[$_] -eq 'gone' -and $scope.RebootKeys -notcontains $_ -and $_ -match '^[a-z]:\\'
    })
    if ($fsTargets.Count) {
        $found = Invoke-Command -Session $session -ArgumentList (, $fsTargets) -ScriptBlock {
            param($paths)
            @($paths | Where-Object { Test-Path -LiteralPath $_ })
        }
        $leftovers = @($found)
    }

    # **없어져야 할 자리를 아직 쥐고 있는 프로세스.**
    #
    # 프로세스 증감은 판정에서 뺀다 — 살아 있는 기계에서 저절로 일어난다.
    # 그러나 이것은 다르다: 지워졌어야 할 폴더를 인자로 쥔 프로세스가 치료
    # 뒤에도 돌고 있으면 그것은 잡음이 아니라 **남은 감염**이다.
    #
    # 이 검사가 없으면 `process.kill` 이 빠진 답안도 통과한다. 폴더 삭제는
    # 실패하지만(현재 디렉터리로 쥐고 있다) 그 실패는 이미 '범위 안 불일치' 로
    # 잡히므로, 프로세스 자체를 재는 것은 여기뿐이다.
    $alive = @()
    $treatedState = Get-Content -LiteralPath $sTreated -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($pr in @($treatedState.processes)) {
        $line = ("{0}|{1}" -f $pr.image_path, $pr.cmdline).ToLowerInvariant()
        foreach ($t in $scope.ScopeKeys) {
            if ($scope.ScopeOps[$t] -ne 'gone') { continue }
            # 짧은 이름은 남의 명령줄에 우연히 걸린다.
            if ($t.Length -lt 12) { continue }
            if ($line.Contains($t)) { $alive += ("{0}  ({1})" -f $pr.image_path, $t); break }
        }
    }

    <#
        **고치는 대상의 내용 — 지목한 만큼만 달라졌는가.**

        감염 상태의 내용에서 사전 등록 자료가 지목한 것을 우리가 직접 빼 보고,
        그것이 치료 뒤의 내용과 같은지 본다. 같으면 치료는 정확히 그것만 했다.
        `modules.remote` 를 빼랬는데 `modules` 를 통째로 지웠거나 파일을 새로
        쓴 답안은 여기서 갈린다.
    #>
    $contentBad = @(); $contentUnmeasured = @(); $contentUnknown = @(); $contentMeasured = 0
    foreach ($k in @($scope.Content.Keys)) {
        $spec = $scope.Content[$k]
        if ($spec.Kind -eq 'unknown') {
            # 이 하네스가 볼 줄 모르는 매치다. 넘기면 재지 않은 것을 잰 것처럼
            # 보이므로 회차를 미결로 내린다.
            $contentUnknown += ("{0}  (매치 '{1}')" -f $spec.Target, $spec.Raw)
            continue
        }
        $inf = $cInfected[$k]; $tre = $cTreated[$k]
        if ($null -eq $inf) {
            $contentUnmeasured += ("{0} — 감염 상태에 파일이 없다" -f $spec.Target)
            continue
        }
        if ($null -eq $tre) {
            $contentBad += @{ Target = $spec.Target; Want = "파일이 남아 있어야 한다"; Got = "사라졌다" }
            continue
        }
        if ($spec.Kind -eq 'args') {
            # **리눅스 하네스와 같은 규칙이다** (`minus_tokens`): 지목한 인자
            # 토큰을 감염 상태의 인자에서 **앞에서부터 하나씩** 빼고, 그
            # 나머지가 치료 뒤 인자와 같아야 한다. 제품이 무슨 규칙으로
            # 가르는지는 보지 않는다 — 그것을 베끼면 검증자가 피검증자가 된다.
            $before = $null; $after = $null
            try { $before = $inf | ConvertFrom-Json; $after = $tre | ConvertFrom-Json }
            catch {
                $contentBad += @{ Target = $spec.Target; Want = "바로가기로 읽혀야 한다"; Got = "읽히지 않는다: $_" }
                continue
            }
            $infArgs = [string]$before.Arguments
            # 지목한 인자가 감염 상태에 없으면 **재지 않은 것**이다.
            $have = @($infArgs -split '\s+' | Where-Object { $_ })
            $wantDrop = @($spec.Args -split '\s+' | Where-Object { $_ })
            $absent = @($wantDrop | Where-Object { $have -cnotcontains $_ })
            if ($absent.Count) {
                $contentUnmeasured += ("{0} — 감염 상태의 인자에 없다: {1}" -f $spec.Target, ($absent -join ' '))
                continue
            }
            $contentMeasured++
            $want = Remove-ArgTokens -All $infArgs -Drop $spec.Args
            $got = (@([string]$after.Arguments -split '\s+' | Where-Object { $_ }) -join ' ')
            if ($want -cne $got) {
                $contentBad += @{ Target = $spec.Target; Want = "인자가 '$want' 여야 한다"; Got = "'$got'" }
            }
            # **대상 경로는 손대지 않았어야 한다.** 리눅스 쪽이 `Exec=` 말고
            # 다른 줄을 견주는 것과 같은 자리다 — 인자만 떼랬는데 바로가기를
            # 새로 만든 답안이 여기서 갈린다.
            if ([string]$before.Target -cne [string]$after.Target) {
                $contentBad += @{
                    Target = $spec.Target
                    Want   = "가리키는 곳은 '$([string]$before.Target)' 그대로여야 한다"
                    Got    = "'$([string]$after.Target)'"
                }
            }
            continue
        }
        if ($spec.Kind -eq 'line') {
            # **리눅스 하네스와 같은 논리다** (`grep -vxF -f lines/<n>` 뒤 `cmp`).
            # 감염본에서 지목한 줄을 빼고 치료본과 견준다 — 그 줄만 빠지고
            # 나머지는 그대로여야 한다. 통째로 비운 답안과 한 줄만 뺀 답안이
            # 여기서 갈린다.
            $beforeLines = $inf -split "`r?`n"
            $afterLines = $tre -split "`r?`n"
            # 지울 줄이 감염본에 없으면 **재지 않은 것**이다. 그 자리의
            # '차이 없음' 을 통과로 읽으면 안 된다.
            $absent = @($spec.Lines | Where-Object { $beforeLines -notcontains $_ })
            if ($absent.Count) {
                $contentUnmeasured += ("{0} — 감염 상태에 지울 줄이 없다: {1}" -f `
                    $spec.Target, (($absent | ForEach-Object { $_.Trim() }) -join ' · '))
                continue
            }
            $contentMeasured++
            $want = @($beforeLines | Where-Object { $spec.Lines -notcontains $_ })
            if (($want -join "`n") -ne ($afterLines -join "`n")) {
                $contentBad += @{
                    Target = $spec.Target
                    Want   = ("지목한 {0}줄만 빠져 {1}줄이 남는다" -f $spec.Lines.Count, $want.Count)
                    Got    = ("{0}줄 남았다" -f $afterLines.Count)
                }
            }
            continue
        }
        $before = $null; $after = $null
        try { $before = $inf | ConvertFrom-Json; $after = $tre | ConvertFrom-Json }
        catch {
            $contentBad += @{ Target = $spec.Target; Want = "JSON 이어야 한다"; Got = "읽히지 않는다: $_" }
            continue
        }
        if (-not (Remove-JsonKeyPath $before $spec.KeyPath)) {
            $contentUnmeasured += ("{0} — 감염 상태에 '{1}' 가 없다 (픽스처가 넣지 않았다)" -f $spec.Target, $spec.KeyPath)
            continue
        }
        $contentMeasured++
        $want = ConvertTo-CanonicalJson $before
        $got = ConvertTo-CanonicalJson $after
        if ($want -ne $got) {
            $contentBad += @{ Target = $spec.Target; Want = $want; Got = $got }
        }
    }

    # **남아야 하는데 바뀌었다.**
    #
    # 감염 상태에 그 자리가 없으면 픽스처가 세우지 않은 것이고, 그때의
    # '안 바뀜' 은 지켰다는 뜻이 아니라 잴 것이 없었다는 뜻이다.
    $damaged = @(); $mustUnmeasured = @()
    $infectedKeys = @{}
    foreach ($i in (Expand-Diff $dInfect)) { $infectedKeys[(ConvertTo-ScopeKey $i.Key)] = $true }
    $infectedState = Get-Content -LiteralPath $sInfected -Raw -Encoding UTF8 | ConvertFrom-Json
    $present = @{}
    foreach ($f in @($infectedState.files)) { $present[(ConvertTo-ScopeKey $f.path)] = $true }
    foreach ($r in @($infectedState.registry)) {
        foreach ($v in @($r.values)) { $present[(ConvertTo-ScopeKey ("{0}\{1}" -f $r.key, $v.name))] = $true }
    }
    foreach ($k in $mustRemain.Keys) {
        $hit = $false
        foreach ($pk in $present.Keys) { if ($pk -eq $k -or $pk.StartsWith($k + '\')) { $hit = $true; break } }
        if (-not $hit) { $mustUnmeasured += $k; continue }
        foreach ($i in (Expand-Diff $dTouch)) {
            if ($i.Section -eq "processes") { continue }
            if (Get-ScopeMatch $i.Key @($k)) { $damaged += $i }
        }
    }

    # 범위 안에서 관측된 변화의 수. 자세히 보는 값이고 **자리 수가 아니다.**
    $infectInScope = @(Expand-Diff $dInfect | Where-Object {
        $_.Section -ne "processes" -and (Test-InScope $_.Key $scope.ScopeKeys)
    }).Count

    <#
        **잰 자리 — 단위는 자리다.**

        분자와 분모가 오래 다른 것을 세고 있었다. 분모는 **이름**(별칭 포함),
        분자는 **차분 건수**였다. 그래서 `service-userinit` 이 자리 다섯 곳을
        전부 치료하고도 `4/6` 으로 적혔다. 리눅스 하네스는 처음부터 자리를
        세고 있었다 — 이제 둘이 같은 것을 센다.

        한 자리를 잰 것으로 세려면 두 가지가 필요하다.

        | 조건 | 왜 |
        |---|---|
        | 감염이 그 자리에 자국을 남겼다 | 자국이 없으면 잴 것이 없었다 |
        | 판정할 수 있었다 | `판정 불가` 는 재지 못한 것이다 |

        자국은 차분에서 보거나(대부분) 감염 단계의 `Test-Path` 에서 본다 —
        관측기가 디렉터리 **자신**을 적지 않기 때문이다.
    #>
    $placesSeen = 0
    $placesMissed = @()
    foreach ($place in $scope.Places.Keys) {
        $names = @($scope.Places[$place])
        if (@($unjudged | Where-Object { Test-InScope $_.Key $names }).Count) {
            $placesMissed += ("{0} — 견줄 청정 값이 없어 판정하지 못했다" -f $place)
            continue
        }
        $marked = @(Expand-Diff $dInfect | Where-Object {
            $_.Section -ne "processes" -and (Test-InScope $_.Key $names)
        }).Count -gt 0
        if (-not $marked) {
            $marked = @($names | Where-Object { $infectedFsPresent -contains $_ }).Count -gt 0
        }
        if ($marked) { $placesSeen++ }
        else { $placesMissed += ("{0} — 감염이 그 자리에 자국을 남기지 않았다" -f $place) }
    }
    $reliable = $dInfect.observation_reliable -and $dRemain.observation_reliable

    Write-Host "`n===== 채점 5. 실기기 치료 =====" -ForegroundColor Magenta
    Write-Host ("  위협      {0}" -f $Threat)
    Write-Host ("  플러그인  {0}" -f $Plugin)
    Write-Host ("  종료 코드 {0}   (1=완전 치료 · 3=부분 실패 · 5=guard 정지)" -f $run.exit)
    Write-Host ("  감염이 만든 변화 {0}건 · 치료 뒤 남은 변화 {1}건" -f `
        (Expand-Diff $dInfect).Count, (Expand-Diff $dRemain).Count)
    Write-Host ("  밟는 자리 {0}곳 중 잰 것 {1}곳 (관측된 변화 {2}건) · 남아야 하는 자리 {3}곳 중 잰 것 {4}곳 · 내용 검사 {5}곳 중 잰 것 {6}곳" -f `
        $scope.Places.Count, $placesSeen, $infectInScope, `
        @($mustRemain.Keys).Count, (@($mustRemain.Keys).Count - $mustUnmeasured.Count), `
        @($scope.Content.Keys).Count, $contentMeasured)
    if ($placesMissed.Count) {
        Write-Host "`n  못 잰 곳 $($placesMissed.Count)곳 — 그 자리의 '불일치 0' 을 통과로 읽으면 안 된다" -ForegroundColor Yellow
        foreach ($m in $placesMissed) { Write-Host ("    {0}" -f $m) -ForegroundColor Yellow }
    }

    if ($mismatch.Count) {
        Write-Host "`n  범위 안 불일치 $($mismatch.Count)건 — 위협이 밟는 자리가 청정 기준과 다르다" -ForegroundColor Red
        foreach ($m in $mismatch) {
            Write-Host ("    {0}/{1}  {2}" -f $m.Section, $m.Bucket, $m.Key) -ForegroundColor Red
            if ($m.Bucket -eq "changed") {
                Write-Host ("        청정: {0}" -f $m.Before) -ForegroundColor DarkGray
                Write-Host ("        치료: {0}" -f $m.After) -ForegroundColor DarkGray
            }
        }
    }
    if ($caused.Count) {
        Write-Host "`n  치료가 만든 변화 $($caused.Count)건 — 범위 밖인데 치료 전에는 없었다" -ForegroundColor Red
        foreach ($c in $caused) { Write-Host ("    {0}/{1}  {2}" -f $c.Section, $c.Bucket, $c.Key) -ForegroundColor Red }
    }
    if ($reboot.Count) {
        Write-Host "`n  재부팅 대기 $($reboot.Count)건 — file.delete_on_reboot 의 대상이라 지금 남아 있는 것이 맞다" -ForegroundColor DarkYellow
        foreach ($r in $reboot) { Write-Host ("    {0}  {1}" -f $r.Section, $r.Key) -ForegroundColor DarkYellow }
    }
    if ($leftovers.Count) {
        Write-Host "`n  남은 파일·폴더 $($leftovers.Count)건 — 없어져야 하는데 아직 있다" -ForegroundColor Red
        foreach ($lo in $leftovers) { Write-Host ("    {0}" -f $lo) -ForegroundColor Red }
    }
    if ($alive.Count) {
        Write-Host "`n  살아 있는 프로세스 $($alive.Count)건 — 없어져야 할 자리를 아직 쥐고 있다" -ForegroundColor Red
        foreach ($a in $alive) { Write-Host ("    {0}" -f $a) -ForegroundColor Red }
    }
    if ($contentBad.Count) {
        Write-Host "`n  지목한 만큼만 달라지지 않았다 $($contentBad.Count)건 — expected-ops.txt 의 매치가 지목한 성질이다" -ForegroundColor Red
        foreach ($c in $contentBad) {
            Write-Host ("    {0}" -f $c.Target) -ForegroundColor Red
            Write-Host ("        기대: {0}" -f (Format-Short $c.Want)) -ForegroundColor DarkGray
            Write-Host ("        실제: {0}" -f (Format-Short $c.Got)) -ForegroundColor DarkGray
        }
    }
    if ($contentUnknown.Count) {
        Write-Host "`n  볼 줄 모르는 매치 $($contentUnknown.Count)건 — 이 하네스에 그 검사가 없다" -ForegroundColor Yellow
        foreach ($c in $contentUnknown) { Write-Host ("    {0}" -f $c) -ForegroundColor Yellow }
    }
    if ($contentUnmeasured.Count) {
        Write-Host "`n  내용을 못 잰 곳 $($contentUnmeasured.Count)건" -ForegroundColor Yellow
        foreach ($c in $contentUnmeasured) { Write-Host ("    {0}" -f $c) -ForegroundColor Yellow }
    }
    if ($damaged.Count) {
        Write-Host "`n  남아야 하는데 바뀌었다 $($damaged.Count)건 — must-remain.txt 가 지목한 자리다" -ForegroundColor Red
        foreach ($d in $damaged) {
            Write-Host ("    {0}/{1}  {2}" -f $d.Section, $d.Bucket, $d.Key) -ForegroundColor Red
            if ($d.Bucket -eq "changed") {
                Write-Host ("        감염: {0}" -f $d.Before) -ForegroundColor DarkGray
                Write-Host ("        치료: {0}" -f $d.After) -ForegroundColor DarkGray
            }
        }
    }
    if ($mustUnmeasured.Count) {
        Write-Host "`n  못 잰 곳 $($mustUnmeasured.Count)건 — 감염 상태에 그 자리가 없다 (픽스처가 세우지 않았다)" -ForegroundColor Yellow
        foreach ($u in $mustUnmeasured) { Write-Host ("    {0}" -f $u) -ForegroundColor Yellow }
    }
    if ($traces.Count) {
        Write-Host "`n  우리 흔적 $($traces.Count)건 — 판정에서 뺐다 (설계-03 §8)" -ForegroundColor DarkYellow
        foreach ($t in $traces) { Write-Host ("    {0}  {1}" -f $t.Section, $t.Key) -ForegroundColor DarkYellow }
    }
    if ($unjudged.Count) {
        Write-Host "`n  판정 불가 $($unjudged.Count)건 — 남아야 하는 자리인데 청정 기계에는 없었다" -ForegroundColor Yellow
        Write-Host "    (픽스처가 위협과 함께 설치한 정상 소프트웨어. 견줄 청정 값이 없다.)" -ForegroundColor DarkGray
        foreach ($u in $unjudged) { Write-Host ("    {0}  {1}" -f $u.Section, $u.Key) -ForegroundColor Yellow }
    }
    if ($preexisting.Count) {
        Write-Host "`n  치료 전부터 있던 변화 $($preexisting.Count)건 — 기계가 스스로 한 것이라 판정에서 뺐다" -ForegroundColor DarkGray
        foreach ($e in ($preexisting | Select-Object -First 5)) { Write-Host ("    {0}  {1}" -f $e.Section, $e.Key) -ForegroundColor DarkGray }
        if ($preexisting.Count -gt 5) { Write-Host ("    ... 그 밖 {0}건은 exam-apply.json 에" -f ($preexisting.Count - 5)) -ForegroundColor DarkGray }
    }
    if ($churn -gt 0) {
        Write-Host "`n  서비스 증감 ${churn}건 — 상태와 시작 유형만 달라졌다. 저절로 일어나는 축이라 판정에서 뺐다" -ForegroundColor DarkGray
    }
    if (-not $reliable) {
        Write-Host "`n  관측 신뢰 불가:" -ForegroundColor Red
        foreach ($n in @($dInfect.reliability_notes) + @($dRemain.reliability_notes)) {
            if ($n) { Write-Host "    - $n" -ForegroundColor Red }
        }
    }

    # 감염이 **범위 안에** 아무 자국도 안 남겼다면 이 회차는 아무것도 재지
    # 못한 것이다. 그 상태의 '불일치 0' 은 치료가 됐다는 뜻이 아니다.
    if ($crippled) {
        Write-Host "`n  미결 — 룰을 평가하지 못한 채 돌았다. 판정은 이 플러그인의 것이 아니다." -ForegroundColor Yellow
        $verdict = "inconclusive"
    } elseif ($placesSeen -eq 0) {
        Write-Host "`n  미결 — 감염이 관측 범위 안에 아무 자국도 남기지 않았다." -ForegroundColor Yellow
        Write-Host "         잴 것이 없었으므로 '불일치 0' 을 통과로 읽으면 안 된다." -ForegroundColor Yellow
        $verdict = "inconclusive"
    } elseif (-not $reliable) { $verdict = "inconclusive" }
    elseif ($mismatch.Count -or $caused.Count -or $alive.Count -or $leftovers.Count -or
            $damaged.Count -or $contentBad.Count) { $verdict = "fail" }
    elseif ($placesMissed.Count) {
        # 밟는 자리 중 재지 못한 것이 있다. 리눅스 하네스와 같은 판정이다 —
        # 잰 자리가 전부 맞았어도 못 잰 자리가 있으면 통과가 아니다.
        Write-Host "`n  미결 — 밟는 자리 중 재지 못한 곳이 있다. 통과로 읽으면 안 된다." -ForegroundColor Yellow
        $verdict = "inconclusive"
    }
    elseif ($contentUnknown.Count -or $contentUnmeasured.Count) {
        # 재료가 성질을 지목했는데 이 회차가 그것을 재지 못했다.
        Write-Host "`n  미결 — expected-ops.txt 의 매치가 지목한 성질을 재지 못했다." -ForegroundColor Yellow
        $verdict = "inconclusive"
    }
    elseif ($mustUnmeasured.Count) {
        # 남아야 하는 자리를 픽스처가 세우지 않았다. 그 회차는 그 요구를
        # **재지 않은 것**이고, 재지 않은 것을 합격이라 부르면 안 된다.
        Write-Host "`n  미결 — must-remain.txt 가 지목한 자리를 픽스처가 세우지 않았다." -ForegroundColor Yellow
        $verdict = "inconclusive"
    }
    else { $verdict = "pass" }

    <#
        **쉼표를 뗄 수 없다.** PowerShell 함수는 배열 반환을 파이프라인으로
        언롤링해서, 항목 하나면 객체 하나가, 없으면 `$null` 이 나온다. 그대로
        JSON 에 실으면 `[]` 여야 할 자리가 `{}` 로 적히고 **기계가 읽는 보고서가
        모양을 속인다.** 실측으로 첫 불합격 회차의 보고서가 그랬다.
    #>
    function ToJsonItems { param($Items)
        , @(@($Items) | Where-Object { $_ } | ForEach-Object {
            [ordered]@{ section = $_.Section; bucket = $_.Bucket; key = $_.Key; before = $_.Before; after = $_.After }
        })
    }
    $report = [ordered]@{
        schema = "remedy-lab.exam-apply/1"
        threat = $Threat
        plugin = "$Plugin"
        exit_code = $run.exit
        verdict = $verdict
        infection_changes_in_scope = $infectInScope
        places = @($scope.Places.Keys)
        places_seen = $placesSeen
        places_missed = @($placesMissed)
        scope_keys = @($scope.ScopeKeys)
        content_checks = @($scope.Content.Keys)
        content_measured = $contentMeasured
        content_bad = @($contentBad | ForEach-Object { [ordered]@{ target = $_.Target; want = $_.Want; got = $_.Got } })
        content_unknown = @($contentUnknown)
        content_unmeasured = @($contentUnmeasured)
        must_remain = @($mustRemain.Keys)
        must_remain_measured = (@($mustRemain.Keys).Count - $mustUnmeasured.Count)
        must_remain_unmeasured = @($mustUnmeasured)
        damaged = (ToJsonItems $damaged)
        mismatch = (ToJsonItems $mismatch)
        caused_by_treatment = (ToJsonItems $caused)
        reboot_pending = (ToJsonItems $reboot)
        own_traces = (ToJsonItems $traces)
        unjudged = (ToJsonItems $unjudged)
        preexisting = (ToJsonItems $preexisting)
        observation_reliable = $reliable
    }
    # JSON 은 BOM 없이 쓴다.
    [System.IO.File]::WriteAllText((Join-Path $outDir "exam-apply.json"),
        ($report | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))

    if ($Record) {
        # **합격만 증거가 된다.** 미결과 불합격을 남기면 게이트가 그것을 보고
        # 빨개지는데, 그때 사람이 할 일은 파일을 고치는 것이 아니라 다시 재는
        # 것이다. 애초에 남기지 않는 편이 헷갈리지 않는다.
        # 정답 폴더의 파일 지도. 경로는 `/` 로 맞춘다 — 리눅스 하네스가 같은
        # 지도를 만들고 게이트가 둘을 같은 잣대로 본다.
        $pluginRoot = Split-Path -Parent (Resolve-Path $Plugin).Path
        $pluginFiles = [ordered]@{}
        foreach ($f in (Get-ChildItem -LiteralPath $pluginRoot -Recurse -File | Sort-Object FullName)) {
            $rel = $f.FullName.Substring($pluginRoot.Length + 1).Replace("\", "/")
            $pluginFiles[$rel] = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
        }
        if ($verdict -ne "pass") {
            Write-Warn "판정이 '$verdict' 라 증거를 남기지 않는다"
        } else {
            $proof = [ordered]@{
                schema              = "remedy-exam-apply/4"
                threat              = $Threat
                platform            = "windows"
                # Windows 하네스에는 대화형 회차가 없다. 필요한 자리가 아직
                # 없다 — `cert_store.remove` 를 쓰는 Windows 위협이 없다.
                mode                = "unattended"
                # 어느 갈래를 잰 회차인가. 없으면 `default` 다 — 옛 증거가
                # 그렇고, 그 기본값은 실제로 맞다(그때는 갈래가 하나였다).
                variant             = $(if ($NoProcess) { "no-process" } else { "default" })
                verdict             = $verdict
                exit_code           = $run.exit
                measured            = $placesSeen
                scope_targets       = $scope.Places.Count
                changes_in_scope    = $infectInScope
                trace               = [ordered]@{
                    host          = $traceHost
                    stages        = @($traceStages)
                    actions_done  = $traceActions
                }
                content_checks      = @($scope.Content.Keys).Count
                content_measured    = $contentMeasured
                must_remain         = @($mustRemain.Keys).Count
                must_remain_measured = (@($mustRemain.Keys).Count - $mustUnmeasured.Count)
                # **파일마다 해시를 적는다.** 폴더를 한 값으로 접으려면
                # "무엇을 어떤 순서로 이어 붙이는가" 라는 규격이 생기고, 그것을
                # Rust · PowerShell · bash 세 곳에 적으면 갈라진다.
                plugin_files        = $pluginFiles
                expected_ops_sha256 = (Get-FileHash -LiteralPath $expectedOps -Algorithm SHA256).Hash.ToLower()
                must_remain_sha256  = (Get-FileHash -LiteralPath (Join-Path $threatDir "must-remain.txt") -Algorithm SHA256).Hash.ToLower()
                binary_sha256       = (Get-FileHash -LiteralPath $binPath -Algorithm SHA256).Hash.ToLower()
                ran_at              = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            # 갈래마다 파일이 따로다. 한 파일에 합치면 **한 갈래를 다시 재는
            # 것이 다른 갈래의 기록을 지운다** — 그러면 둘 다 재었다는 것을
            # 아무도 보증하지 못한다.
            $dest = Join-Path $threatDir $(if ($NoProcess) { "apply-result-no-process.json" } else { "apply-result.json" })
            [System.IO.File]::WriteAllText($dest,
                ($proof | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
            Write-Ok "증거를 남겼다: $dest"
        }
    }

    Write-Host ""
    switch ($verdict) {
        "pass" { Write-Ok "채점 5 합격 — 위협이 밟은 자리가 전부 청정 기준으로 돌아왔다" }
        "fail" { Write-Bad ("채점 5 불합격 — 범위 안 불일치 {0}건 · 치료가 만든 변화 {1}건 · 남은 파일 {2}건 · 살아 있는 프로세스 {3}건 · 남아야 하는데 바뀌었다 {4}건 · 지목한 만큼만 달라지지 않았다 {5}건" -f $mismatch.Count, $caused.Count, $leftovers.Count, $alive.Count, $damaged.Count, $contentBad.Count) }
        default { Write-Warn "채점 5 미결 — 통과로 읽으면 안 된다" }
    }
    Write-Host "보고서: $outDir" -ForegroundColor Gray
}

finally {
    if ($fixtured) {
        Write-Step "정리"
        if ($Threat -eq 'evilai-locust') {
            Stop-InfectedProcess -Session $session -PayloadDir $evilaiDir | Out-Null
            Clear-InfectedState -Session $session -PayloadDir $evilaiDir | Out-Null
        } else {
            Invoke-Command -Session $session -ArgumentList $LabRoot, $Threat -ScriptBlock {
                param($root, $threat)
                powershell -ExecutionPolicy Bypass -File "$root\scripts\New-ThreatFixtures.ps1" `
                    -Threat $threat -Clean 2>&1
            } | Out-Null
        }
        Write-Ok "픽스처 정리"
    }
    if ($session) { Remove-PSSession $session }
}

switch ($verdict) {
    "pass" { exit 0 }
    "fail" { exit 1 }
    default { exit 2 }
}
