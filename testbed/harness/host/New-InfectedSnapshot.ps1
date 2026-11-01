<#
.SYNOPSIS
    감염 스냅샷을 떠서 `corpus/infected/` 에 넣는다 (설계-04 §3.2, 설계-09 P9).

.DESCRIPTION
    청정 코퍼스(`New-CorpusSnapshot.ps1`)가 "여기서 아무것도 나오면 안 된다"를
    재는 자리라면, 감염 코퍼스는 "여기서는 반드시 나와야 한다"를 재는 자리다.
    G1 이 룰이 통째로 죽어도 초록인 것과 대칭으로, 탐지 회귀는 감염 스냅샷이
    없으면 아무것도 보장하지 못한다.

    **왜 합성 아티팩트인가.** 실검체(JS·PE)를 격리 VM 에서 실행했으나 어느
    것도 지속성을 만들지 않았다 — 로더가 부모 프로세스·설치 경로·C2 응답을
    검사하고 미충족 시 crypto 복호화 전에 스스로 접는다. C2 는 사내망 보호를
    위해 인터넷을 끊어 응답하지 않았다. 그래서 **지속성 아티팩트(예약 작업·
    Run 키·페이로드 폴더·AV 예외)를 손으로 세우되, 페이로드 바이트만은 실검체를
    그대로 배치한다.** 룰이 실제로 훑는 것은 그 바이트이므로, 탐지의 핵심은
    실검체로 확인되고 지속성 배치만 모사된다.

    **그것은 VM 에 놓는 이야기다. 저장소로 나가는 것은 다르다.** 아래 "페이로드
    본문" 단계가 커밋 직전에 **본문만 룰-합성 바이트로 바꿔친다** — 저장소에
    악성 바이트를 들이지 않기로 한 결정이고
    이고, `xtask/src/yara.rs` 가
    *"검체는 저장소 밖에 있고 앞으로도 들어오지 않는다"* 고 적는 그 규칙이다.

    그래서 `corpus/infected/` 를 다른 위협 폴더와 가르는 것은 **바이트가 아니라
    레코드의 출처**다 — 경로·지속성·`principal`·AV 예외가 실검체에 감염된 VM
    에서 수집기가 뜬 그대로라는 것. 실검체 바이트로 룰이 발화하는지는
    `cargo xtask yara`(G9)가 따로 잰다.

    이 머리말만 읽고 "커밋된 스냅샷에 실검체가 들어 있다" 로 읽는 일이
    2026-09-05 에 실제로 있었다. 그래서 여기 적는다.

    이 스크립트가 만드는 감염 상태는 예시-EvilAI-플러그인.md 와
    P9-EvilAI-YARA-룰-도출과-실측.md 의 관측을 따른다:
      - `%LOCALAPPDATA%\Programs\SystemSoftwareUpdaterV2-q5ty\preload.js` (실검체)
      - 예약 작업 `\Microsoft\Windows\Locust` → node.exe 가 그 preload.js 실행
      - HKCU Run 키가 같은 경로를 가리킴
      - Defender 제외에 그 폴더 등록

    **스냅샷을 되돌리지 않는다.** 되돌리면 방금 세운 것이 사라진다. 대신 이
    스크립트 끝에서 세운 것을 전부 되돌려(cleanup) VM 을 원래대로 남긴다 —
    다음 실행이 같은 자리에서 시작하도록.

.PARAMETER SamplePath
    배치할 실검체 .js 페이로드. 저장소 밖의 경로다.

.EXAMPLE
    .\New-InfectedSnapshot.ps1 -Label evilai-locust -Build `
        -SamplePath '<검체 폴더>\vt_sample_ai_summary\script\trojan.meadowlocust_loader\d9d24f83d542d4b7ddb01a4e21654e58fd2c025bdc1456e41c998cc10a0e9754.bin'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Label,
    [Parameter(Mandatory = $true)][string] $SamplePath,
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $Plugin,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    [switch] $Force
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'
. (Join-Path $PSScriptRoot "InfectedState.ps1")

if (-not (Test-Path $SamplePath)) { throw "검체가 없다: $SamplePath" }
if (-not $Plugin) { $Plugin = Join-Path $repoRoot "plugins\evilai-locust\plugin.yaml" }
if (-not (Test-Path $Plugin)) { throw "매니페스트가 없다: $Plugin" }

$triple  = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"
$outDir  = Join-Path $repoRoot "corpus\infected"

if ($Build) {
    Write-Step "빌드: remedy.exe"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        # **실패하면 throw 다** — VM 에 아무것도 배포하지 않는다.
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
    } finally { Pop-Location }
}
if (-not (Test-Path $binPath)) { throw "산출물이 없다: $binPath`n먼저 -Build 를 줄 것." }
Write-Ok "remedy.exe  $((Get-FileHash $binPath -Algorithm SHA256).Hash)"
Assert-StaticBinary -RepoRoot $repoRoot -Path @($binPath)

$sampleHash = (Get-FileHash $SamplePath -Algorithm SHA256).Hash
Write-Ok "검체  $((Get-Item $SamplePath).Length) B  $sampleHash"

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential
$MASK = "<코퍼스>"

# 감염 상태를 세우는 자리. VM 안에서 실제 예약 작업·Run 키·폴더·AV 예외를
# 만든다. 실검체 바이트는 페이로드 파일로 그대로 놓인다.
# **`$payloadDir` 는 게스트에서 정한다.** 호스트에서 `$env:LOCALAPPDATA` 를
# 펼치면 호스트 사용자의 프로필(`C:\Users\<호스트계정>\...`)이 되고, 그 경로는
# 게스트의 `%LOCALAPPDATA%\Programs`(= `scan_roots`) 밖이다. 그러면 페이로드가
# 수집되지 않아 스냅샷에 파일 레코드가 없고, 탐지는 조용히 서지 않는다.
# 아래에서 세션을 연 뒤 게스트에게 물어 채운다.
$payloadDir = $null
$payloadLeaf = "SystemSoftwareUpdaterV2-q5ty"
$taskName   = "Locust"
$taskPath   = "\Microsoft\Windows\"
$runName    = "SystemSoftwareUpdater"

try {
    $guestHost = Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME }
    Write-Ok "게스트: $guestHost"

    # 게스트의 `%LOCALAPPDATA%` 를 물어 페이로드 자리를 정한다. 이것이
    # 매니페스트의 `scan_roots` 안에 있어야 수집된다.
    $guestLocal = Invoke-Command -Session $session -ScriptBlock { $env:LOCALAPPDATA }
    $payloadDir = Join-Path (Join-Path $guestLocal "Programs") $payloadLeaf
    Write-Ok "페이로드 자리(게스트): $payloadDir"

    Invoke-Command -Session $session -ScriptBlock {
        param($root)
        foreach ($d in @("$root\bin", "$root\corpus")) {
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        }
    } -ArgumentList $LabRoot

    Write-Step "배포: remedy.exe · 매니페스트"
    Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force
    Copy-Item $Plugin  -Destination "$LabRoot\corpus\plugin.yaml" -ToSession $session -Force

    # **이 하네스의 산출물은 저장소로 간다** — 코퍼스 스냅샷이다. 남의 흔적이
    # 섞이면 그것이 조용히 커밋되고, 그 뒤로 오탐 기준이 오염된 채 남는다.
    # 감염을 세우기 **전에** 본다.
    Assert-NoForeignInfection -Session $session -PayloadDir $payloadDir

    # ── 감염 상태 구성 ──────────────────────────────────────────
    Write-Step "감염 아티팩트 배치"
    $verify = Invoke-Command -Session $session -ArgumentList $payloadDir, $taskName, $taskPath, $runName -ScriptBlock {
        param($PayloadDir, $TaskName, $TaskPath, $RunName)
        $r = @{}

        # (1) 페이로드 폴더 + 실검체 (검체 바이트는 다음 단계에서 채운다)
        New-Item -ItemType Directory -Path $PayloadDir -Force | Out-Null
        $r.Dir = Test-Path $PayloadDir

        # (2) 예약 작업 — node.exe 가 preload.js 를 실행
        $node = 'C:\Program Files\nodejs\node.exe'
        $script = Join-Path $PayloadDir 'preload.js'
        $act = New-ScheduledTaskAction -Execute $node -Argument "`"$script`""
        $trg = New-ScheduledTaskTrigger -AtLogOn
        # 존재하면 지우고 다시 만든다 — 재실행 멱등성.
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $act -Trigger $trg -Force | Out-Null
        $r.Task = $null -ne (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue)

        # (3) HKCU Run 키
        $runKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        Set-ItemProperty -Path $runKey -Name $RunName -Value "`"$node`" `"$script`""
        $r.Run = (Get-ItemProperty $runKey).$RunName

        # (4) Defender 제외 — 자기 폴더를 예외 목록에 등록
        try { Add-MpPreference -ExclusionPath $PayloadDir -ErrorAction Stop; $r.Excl = $true }
        catch { $r.Excl = "실패: $($_.Exception.Message)" }

        [pscustomobject]$r
    }
    Write-Ok "폴더=$($verify.Dir)  작업=$($verify.Task)  Run=$($verify.Run)  제외=$($verify.Excl)"
    if (-not $verify.Task) { throw "예약 작업이 만들어지지 않았다" }

    # 실검체 바이트를 페이로드 자리에 놓는다. **해시로 확인** — 백신이 먹으면
    # 그 뒤 스냅샷은 페이로드 없는 감염이라 탐지가 반쪽이 된다.
    Copy-Item $SamplePath -Destination "$payloadDir\preload.js" -ToSession $session -Force
    $land = Invoke-Command -Session $session -ArgumentList "$payloadDir\preload.js", $sampleHash -ScriptBlock {
        param($P, $Want)
        if (-not (Test-Path $P)) { return "없어짐(백신 의심)" }
        $g = (Get-FileHash $P -Algorithm SHA256).Hash
        if ($g -eq $Want) { "일치" } else { "다름: $g" }
    }
    Write-Ok "페이로드 배치: $land"
    if ($land -ne "일치") { throw "검체가 온전히 놓이지 않았다: $land" }

    # ── 수집 ────────────────────────────────────────────────────
    Write-Step "수집: 매니페스트 선언대로"
    $name = "$Label-declared"
    $dest = Join-Path $outDir "$name.json.gz"
    if ((Test-Path $dest) -and -not $Force) { throw "이미 있다: $name.json.gz — 덮어쓰려면 -Force" }

    $guestOut = "$LabRoot\corpus\$name.json"
    # **`&` 로 부르지 않는다** (`Invoke-GuestExe` 주석 참조). remedy 는 주의를
    # stderr 로 쓰고, PS 5.1 은 그것을 종료 오류로 바꾼다 — 스냅샷은 이미
    # 만들어졌는데 그것을 가져오는 다음 줄에 닿지 못한다. 실측한 자리다.
    $r = Invoke-GuestExe -Session $session -Path "$LabRoot\bin\remedy.exe" -Arguments @(
        "collect", "--out", $guestOut, "--plugin", "$LabRoot\corpus\plugin.yaml")

    if ($r.out) { Write-Ok ($r.out.Trim() -replace "\s+", " ") }
    # stderr 를 버리지 않는다. 종료 코드가 무엇이든 **왜** 그런지는 여기에만 있다.
    if ($r.err) {
        $r.err.Trim() -split "`r?`n" | ForEach-Object { Write-Host "    | $_" -ForegroundColor DarkGray }
    }

    # **종료 코드는 0/비0 이 아니다.** 6 은 "수집은 끝났으나 관측이 불완전"
    # 이고(설계-02 §8), 그 위에서 뜬 스냅샷은 **"없다" 와 "못 봤다" 를 섞는다.**
    # 감염 코퍼스에서 그 둘이 섞이면 탐지 회귀가 재는 것이 없어진다 — 룰이
    # 죽어도, 절반만 훑었어도, 결과는 똑같이 "판정 없음" 이기 때문이다.
    # 그래서 넘기지 않는다. 사유는 바로 위 stderr 에 이미 적혀 있다.
    if ($r.exit -ne 0) {
        throw @"
수집이 온전하지 않다 (exit $($r.exit)). 스냅샷 파일은 만들어졌을 수 있지만
그 위에서는 탐지 회귀가 아무것도 보장하지 못한다. 위 stderr 의 사유를 먼저
해소할 것 — 대개 관리자 권한(접근 거부)이나 수집 상한이다.
$($r.out.Trim())
"@
    }

    $tmp = Join-Path $env:TEMP "$name.json"
    Copy-Item "$guestOut" -Destination $tmp -FromSession $session -Force

    # ── 스크러빙 (New-CorpusSnapshot.ps1 과 같은 규칙 + 감염분) ──
    $json = [System.IO.File]::ReadAllText($tmp, [System.Text.Encoding]::UTF8)

    # **기계 이름은 `host.hostname` 에만 있지 않다.**
    #
    # 청정 스냅샷에서는 그 한 곳뿐이라 필드 하나를 지우면 끝이었다(실측:
    # 청정 declared 스냅샷에서 게스트 이름 등장 1회 — `host.hostname`).
    # 감염 스냅샷은 다르다. **우리가 세운 예약 작업이 담기고, 방금 등록한
    # 작업의 `principal` 은 계정을 `<기계>\<사용자>` 로 적는다.** 기본 작업들은
    # SID 나 `NT AUTHORITY\SYSTEM` 이라 청정 코퍼스에는 이 모양이 아예 없었고,
    # 그래서 이 자리는 감염 스냅샷을 처음 뜰 때 드러났다.
    #
    # 필드를 하나씩 좇으면 다음 감염에서 또 새는 자리가 생긴다. 그래서
    # **본문 전체에서** 지운다. 기계 이름은 데이터가 아니라 식별자이므로,
    # 경로의 사용자 이름(`C:\Users\test`)을 남기는 규칙과 상충하지 않는다.
    #
    # 파싱 **전** 원문에서 지운다. `ConvertTo-Json` 뒤에 하면 이미 escape 된
    # 표현과 새로 끼워 넣는 마스크의 표현이 갈려 한쪽만 걸린다.
    if (-not $guestHost) {
        throw "게스트 이름을 알아내지 못했다 — 무엇을 지웠는지 확인할 기준이 없다 ($name)"
    }
    $rx = [regex]::new([regex]::Escape($guestHost),
                       [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $hostHits = $rx.Matches($json).Count
    # **0 건은 통과가 아니다.** `host.hostname` 에 최소 한 건은 반드시 있다.
    # 0 이라면 우리가 지운다고 믿는 이름이 실제 게스트 이름이 아니라는 뜻이고,
    # 그러면 아래 확인은 "남지 않았다" 가 아니라 **"애초에 못 봤다"** 를
    # 통과시킨다. 그 스냅샷이 저장소에 들어가면 아무도 다시 보지 않는다.
    if ($hostHits -lt 1) {
        throw "게스트 이름 '$guestHost' 가 스냅샷에 한 번도 없다 — 지웠다고 말할 수 없다 ($name)"
    }
    $json = $rx.Replace($json, $MASK)

    $doc = $json | ConvertFrom-Json
    $before = @{}
    foreach ($k in @("file", "persistence", "security_products",
                     "autorun", "process", "av_exclusion")) {
        if ($doc.PSObject.Properties.Name -contains $k) { $before[$k] = @($doc.$k).Count }
    }
    $doc.host.hostname = $MASK
    foreach ($k in @("run_id", "created", "collected_at")) {
        if ($doc.PSObject.Properties.Name -contains $k) { $doc.$k = $MASK }
    }

    # ── 페이로드 본문: 실검체 대신 **룰에서 합성한 바이트**를 싣는다 ──────
    #
    # 근거는 내부 기록에 있다. 요지만:
    #
    # `collect` 는 `collect_extra` 의 증거 참조를 풀지 않는다 — 증거는 평가가
    # 만들기 때문이다 (실측 stderr: "'payload' 는 증거 참조인데 이 실행에는
    # 증거가 없다"). 그래서 이 스냅샷에는 파일 본문이 없고, 그대로 두면 YARA
    # 술어가 **미평가**로 빠져 판정이 서지 않는다 (실측: 증거 3 · 판정 통과 0).
    #
    # 본문을 실으려면 `scan` 으로 떠야 하는데 그러면 실검체 바이트가 저장소에
    # 들어간다. 저장소 기조는 그 반대이고, `crates/remedy-core/tests/evilai.rs`
    # 는 같은 이유로 페이로드를 **룰 파일에서 만든다.** 여기서도 그렇게 한다.
    #
    # **바뀌는 것은 파일 하나의 바이트뿐이다.** 경로 8천여 개, 지속성 2백여
    # 건, `principal` · `register_path` · `args` · AV 예외는 전부 실제 수집기가
    # 뜬 그대로다 — 감염 코퍼스가 `evilai.rs` 에 더하려던 것이 정확히 그
    # **레코드 모양**이고, 그것은 여기서 하나도 손상되지 않는다.
    # 실검체 바이트로 룰이 발화하는지는 `cargo xtask yara` 가 따로 잰다
    # (16/16 · P9-EvilAI-YARA-룰-도출과-실측.md).
    $yarPath = Join-Path (Split-Path -Parent $Plugin) "rules\evilai.yar"
    if (-not (Test-Path $yarPath)) { throw "룰 파일이 없다: $yarPath" }
    $yar = [System.IO.File]::ReadAllText($yarPath, [System.Text.Encoding]::UTF8)
    # `        $a00 = "'AM9P'" ascii` 에서 큰따옴표 안을 꺼낸다 (군집1 상수).
    $consts = @()
    foreach ($line in ($yar -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t.StartsWith('$a')) { continue }
        $o = $t.IndexOf('"'); $c = $t.LastIndexOf('"')
        if ($c -gt $o + 1) { $consts += $t.Substring($o + 1, $c - $o - 1) }
    }
    # 임계값은 20 이다. 30 개를 싣되 꺼낸 수가 모자라면 **그 자리에서 멈춘다** —
    # 발화하지 않는 페이로드를 실은 코퍼스는 탐지 회귀를 조용히 비운다.
    if ($consts.Count -lt 25) {
        throw "룰에서 상수를 $($consts.Count)개밖에 꺼내지 못했다 — 합성 페이로드가 룰을 발화시키지 못한다"
    }
    $synth = "'use strict';function R(){var F=[" + (($consts[0..29]) -join ",") + "];return F;}"
    $synthBytes = [System.Text.Encoding]::UTF8.GetBytes($synth)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $synthSha = ([System.BitConverter]::ToString($sha256.ComputeHash($synthBytes)) -replace '-', '').ToLower() }
    finally { $sha256.Dispose() }
    $blobKey = "sha256:$synthSha"

    # `size` · `sha256` 도 함께 바꾼다. 실검체 값을 남기면 스냅샷이 제 내용과
    # 어긋난 해시를 말하게 된다 — 그런 코퍼스는 나중에 아무도 믿을 수 없다.
    # 실검체 해시는 IOC 로서 문서에 남는다.
    $guestScript = "$payloadDir\preload.js"
    $hit = 0
    foreach ($f in $doc.file) {
        if ($f.path -eq $guestScript) {
            $f.size = $synthBytes.Length
            $f.sha256 = $synthSha
            # `content_ref` 는 `collect` 산출물에 없는 필드다. 새로 붙인다.
            $f | Add-Member -NotePropertyName content_ref -NotePropertyValue $blobKey -Force
            $hit++
        }
    }
    if ($hit -ne 1) {
        throw "페이로드 파일 레코드가 $hit 건이다 (1건이어야 한다): $guestScript"
    }
    $doc | Add-Member -NotePropertyName blobs `
                      -NotePropertyValue @{ $blobKey = [Convert]::ToBase64String($synthBytes) } -Force
    Write-Ok "페이로드 본문 합성: $($synthBytes.Length) B · 상수 30개 · $($synthSha.Substring(0,16))…"

    $clean = $doc | ConvertTo-Json -Depth 32 -Compress

    $check = $clean | ConvertFrom-Json
    if ($check.host.hostname -ne $MASK) { throw "스크러빙이 걸리지 않았다 ($name)" }
    foreach ($k in $before.Keys) {
        $now = @($check.$k).Count
        if ($now -ne $before[$k]) { throw "왕복에서 레코드가 바뀌었다 ($name): $k $($before[$k]) -> $now" }
    }
    if ($guestHost -and $clean -match [regex]::Escape($guestHost)) {
        throw "스크러빙 확인 실패: 게스트 이름 '$guestHost' 가 남아 있다 ($name)"
    }

    # **감염 스냅샷은 감염이어야 한다.** 청정과 달리 여기서는 페이로드 파일이
    # 반드시 담겨 있어야 한다 — 없으면 탐지 회귀가 아무것도 재지 못한다.
    if (($before['persistence'] -lt 1) -or ($before['file'] -lt 1)) {
        throw "감염 스냅샷에 persistence/file 레코드가 없다 — 무엇을 수집했는지 확인할 것"
    }

    # 왕복에서 본문이 살아남았는가. `ConvertTo-Json -Depth` 에 걸려 blobs 가
    # 잘리면 **YARA 는 다시 미평가가 되고 판정이 서지 않는다** — 그리고 그
    # 상태는 "룰이 안 맞았다" 와 화면상 구분되지 않는다.
    if (-not ($check.PSObject.Properties.Name -contains "blobs") -or
        -not ($check.blobs.PSObject.Properties.Name -contains $blobKey)) {
        throw "왕복에서 페이로드 본문(blobs)이 사라졌다 ($name)"
    }
    $backRef = @($check.file | Where-Object { $_.path -eq $guestScript }).content_ref
    if ($backRef -ne $blobKey) {
        throw "왕복에서 content_ref 가 어긋났다 ($name): '$backRef' != '$blobKey'"
    }

    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($clean)
    $fs = [System.IO.File]::Create($dest)
    try {
        $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionLevel]::Optimal)
        try { $gz.Write($bytes, 0, $bytes.Length) } finally { $gz.Dispose() }
    } finally { $fs.Dispose() }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue

    $kb = [math]::Round((Get-Item $dest).Length / 1KB)
    Write-Ok "$name.json.gz  ${kb}KB  (persistence=$($before['persistence']) file=$($before['file']) autorun=$($before['autorun']) av_exclusion=$($before['av_exclusion']))"
    # 몇 곳을 지웠는지 남긴다. "확인 통과" 만으로는 지울 것이 있었는지 알 수 없다.
    Write-Ok "기계 이름 마스킹 $hostHits 곳"

} finally {
    # ── VM 원상 복구 ────────────────────────────────────────────
    # 세운 것을 되돌린다. 스냅샷을 되돌리지 않았으므로 손으로 치운다 — 남기면
    # 다음 청정 스냅샷이 오염된다.
    Write-Step "VM 원상 복구"
    # `$payloadDir` 가 정해지기 전에 실패했을 수 있다. `$null` 로 정리를
    # 시도하면 무엇을 지우는지 알 수 없으므로 그 경우엔 손대지 않는다.
    #
    # **`finally` 안에서 `return` 하지 않는다** — PowerShell 은 finally 블록
    # 밖으로 나가는 제어 흐름을 금지한다(파서 오류). 조건으로 감싼다.
    if ($payloadDir) {
        Invoke-Command -Session $session -ArgumentList $payloadDir, $taskName, $taskPath, $runName -ScriptBlock {
            param($PayloadDir, $TaskName, $TaskPath, $RunName)
            Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
            Remove-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $RunName -ErrorAction SilentlyContinue
            Remove-MpPreference -ExclusionPath $PayloadDir -ErrorAction SilentlyContinue
            Remove-Item $PayloadDir -Recurse -Force -ErrorAction SilentlyContinue
            $left = Test-Path $PayloadDir
            $task = $null -ne (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue)
            "  폴더 잔존=$left  작업 잔존=$task"
        } | ForEach-Object { Write-Host $_ }
    } else {
        Write-Warn "페이로드 자리가 정해지기 전에 끝났다 — 정리할 것이 없다"
    }
    Remove-PSSession $session -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Ok "감염 스냅샷 완료: $Label-declared"
Write-Host "다음: cargo test -p remedy-core --test infected" -ForegroundColor Cyan
