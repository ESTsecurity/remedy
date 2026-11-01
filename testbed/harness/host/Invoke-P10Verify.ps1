<#
.SYNOPSIS
    P10 의 **신뢰 체계**가 배포되는 바이너리에서 실제로 도는가 (설계-09 P10).

.DESCRIPTION
    P10 은 v1 의 마지막 Phase 인데 **실기기 하네스가 없었다.** 그 대가가
    2026-08-28 v1 점검에서 드러났다 — P10-E(자기무결성)가 파괴적 하네스를
    통째로 막고 있었는데 두 달 동안 아무도 몰랐고, P10-F(재부팅 예약)는 예약된
    명령이 실행조차 되지 않는 상태였다. 둘 다 **실기기에서 한 번 돌려 보고**
    나왔다.

    그 자리를 만든다. 여기서 재는 것 아홉:

      자기무결성 (E)
        1. 서명이 없어도 **파괴를 막지 않는다** (2026-09-02 뒤집힘) · 그 사실을 말한다
        2. 그래도 **읽기는 막지 않는다**
      플러그인 서명 (A)
        3. 서명된 플러그인을 통과시킨다
        4. 한 글자 바꾸면 거부한다
        5. 서명이 아예 없으면 거부한다
      폐기 목록 (D)
        6. 폐기하면 그 플러그인을 거부한다
        7. 옛 목록을 되밀 수 없다 (역행 금지)
      조직 허용 목록 (H)
        8. 면제가 **파괴를 계획에서 뺀다** (설계-03 §3 5층)
        9. 옛 목록을 되밀 수 없다

.DESCRIPTION2
    # 왜 릴리스 빌드인가

    **여기 있는 것은 전부 읽기 경로다** — `plugin verify` · `revocation` ·
    `allowlist` · `scan`. 자기무결성 게이트는 `apply`·`run`·`resume` 에만 걸리고
    (`main.rs`), 그래서 이 하네스는 **배포될 바로 그 바이너리**로 잴 수 있다.

    검사 1 은 2026-09-02 에 뒤집혔다 — 서명이 없어도 파괴를 막지 않는다.
    인증서는 공식 배포의 절차이지 기능의 조건이 아니기 때문이고, 그 규칙이
    막던 것은 공격자가 아니라 시연·내부 시험이었다. 대신 **그 사실을 매
    실행에서 말하는지**(검사 1b)를 함께 잰다.

    # 키는 매번 새로 만든다

    저장소에 개인키를 두지 않는다. `xtask sign keygen` 이 실행마다 임시 키쌍을
    만들고, VM 에는 **공개키만** 간다. `REMEDY_SIGN_PASSWORD` 로 비대화형으로
    돈다 — 그것이 없으면 서명 도구가 콘솔에서 암구호를 묻고 멈춘다.

.EXAMPLE
    .\Invoke-P10Verify.ps1 -Build
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    [switch] $NoRevert,
    # 2026-09-02 까지 검사 1 을 뒤집었다(개발 빌드만 파괴를 허용했다). 지금은
    # 빌드 종류와 무관하게 막지 않으므로 **보고에 빌드 종류를 적는 데만** 쓴다.
    [switch] $DevBuild,
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

$triple = "x86_64-pc-windows-msvc"
$profile_ = if ($DevBuild) { "debug" } else { "release" }
# **`[string[]]` 가 필요하다.** PowerShell 은 `if` 가 돌려주는 단일 원소 배열을
# 스칼라로 푼다 — 그러면 `$cargoProfile` 이 문자열이 되고 `@cargoProfile` 이
# 그것을 문자 단위로 쪼개 `cargo` 가 `-` 하나를 받는다 (실측 2026-08-29).
#
# `-DevBuild` 로만 돌리는 동안에는 빈 배열이라 드러나지 않았다.
[string[]] $cargoProfile = if ($DevBuild) { @() } else { @("--release") }
$binPath = Join-Path $repoRoot "target\$triple\$profile_\remedy.exe"

if ($Build) {
    Write-Step "빌드 ($profile_)"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        # **실패하면 throw 다** — VM 에 아무것도 배포하지 않는다.
        Invoke-CargoBuild "remedy.exe" (@("build") + $cargoProfile + @("--target", $triple, "-p", "remedy-cli"))
    } finally { Pop-Location }
}
if (-not (Test-Path $binPath)) { throw "산출물이 없다: $binPath`n먼저 -Build 를 줄 것." }

# ── 호스트에서 서명 재료를 만든다 ───────────────────────────
#
# **개인키는 VM 에 가지 않는다.** 서명은 호스트가 하고 VM 은 검증만 한다 —
# 설계-01 D7 이 서명 생성을 배포 바이너리에서 뺀 이유와 같다.
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$stage = Join-Path $env:TEMP "remedy-p10-$stamp"
New-Item -ItemType Directory -Force $stage | Out-Null
$env:REMEDY_SIGN_PASSWORD = "p10-harness-ephemeral"

# **BOM 없이 쓴다.** PS 5.1 의 `Out-File -Encoding utf8` 은 BOM 을 붙이고,
# 그러면 YAML 파서가 첫 키를 읽지 못한다 — `missing field 'id' at line 1
# column 2` 가 그 증상이다 (실측 2026-08-29). JSON 도 같다.
#
# `.ps1` 은 반대로 BOM 이 있어야 한다. 이 저장소의 규칙이 그렇게 갈린다.
function Write-Utf8NoBom {
    param([string] $Path, [string] $Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding $false))
}

Write-Step "임시 서명 키쌍 (호스트에서만 산다)"
Push-Location $repoRoot
try {
    & cargo run -q -p xtask -- sign keygen `
        --public-key "$stage\pub.key" --secret-key "$stage\sec.key" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "키 생성 실패" }
} finally { Pop-Location }
Write-Ok "공개키 · 개인키"

# 플러그인 둘 — 하나는 서명하고 하나는 안 한다.
$plugSrc = Join-Path $stage "plug"
New-Item -ItemType Directory -Force $plugSrc | Out-Null
$labDir = "$LabRoot\p10lab"
@"
schema_version: 1
id: p10-trust-lab
version: 1.0.0
min_core: "1.0.0"
platforms: [windows, linux]
name:
  ko: "랩 — P10 신뢰 체계"
  en: "lab - P10 trust"
scan_roots:
  # **작은따옴표다.** YAML 의 큰따옴표 스칼라는 역슬래시를 이스케이프로 읽어
  # `\p10lab` 이 "모르는 이스케이프" 가 된다 (실측 2026-08-29).
  - '$labDir'
subjects: [file]
detect:
  - id: payload
    subject: file
    where:
      - { field: path, op: ends_with, value: "evil.exe" }
verdict: { require: "payload" }
remediate:
  remove:
    - { ref: payload }
"@ | ForEach-Object { Write-Utf8NoBom "$plugSrc\plugin.yaml" $_ }

# 서명하지 않은 사본. **검사 5 가 이것을 쓴다.**
$plugUnsigned = Join-Path $stage "plug-unsigned"
Copy-Item $plugSrc $plugUnsigned -Recurse

Write-Step "플러그인 서명"
Push-Location $repoRoot
try {
    & cargo run -q -p xtask -- sign plugin --dir $plugSrc `
        --secret-key "$stage\sec.key" --signed-at "2026-08-29T00:00:00Z" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "플러그인 서명 실패" }
} finally { Pop-Location }
Write-Ok "MANIFEST · MANIFEST.minisig"

function New-SignedList {
    param([string] $Kind, [string] $Entries, [int] $Serial, [string] $Issued, [string] $Out)
    $ef = Join-Path $stage "entries-$Kind-$Serial.json"
    Write-Utf8NoBom $ef $Entries
    Push-Location $repoRoot
    try {
        & cargo run -q -p xtask -- sign $Kind --entries $ef `
            --serial $Serial --issued $Issued --secret-key "$stage\sec.key" --out $Out | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "$Kind 서명 실패" }
    } finally { Pop-Location }
}

Write-Step "폐기 목록 · 허용 목록"
New-SignedList -Kind "revocations" -Serial 5 -Issued "2026-08-29T00:00:00Z" `
    -Entries '[{"plugin":"p10-trust-lab","exact":"1.0.0","reason":"랩 — 폐기 경로 실증"}]' `
    -Out "$stage\rev.signed"
New-SignedList -Kind "revocations" -Serial 4 -Issued "2026-01-01T00:00:00Z" `
    -Entries '[]' -Out "$stage\rev-old.signed"
# 해시는 VM 에서 만든 페이로드에 맞춰 뒤에 채운다 — 여기서는 자리만 잡는다.
Write-Ok "폐기 serial 5 · 되밀기용 serial 4"

if (-not $NoRevert) {
    & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
}
$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential

$outDir = Join-Path $repoRoot "testbed\harness\results\p10-$stamp"
New-Item -ItemType Directory -Force $outDir | Out-Null

$checks = @()
function Add-Check {
    param([string] $Name, [bool] $Ok, [string] $Detail)
    $script:checks += [pscustomobject]@{ name = $Name; ok = $Ok; detail = $Detail }
    if ($Ok) { Write-Ok "$Name   $Detail" } else { Write-Bad "$Name   $Detail" }
}

# ── 배포 ───────────────────────────────────────────────────
Write-Step "배포 ($profile_ 빌드)"
$gBin = "$LabRoot\bin\remedy.exe"
$gPlug = "$LabRoot\p10\plug"
$gState = "$LabRoot\p10state"
Invoke-Command -Session $session -ArgumentList $LabRoot, $labDir -ScriptBlock {
    param($root, $lab)
    New-Item -ItemType Directory -Force "$root\bin", "$root\p10\plug", "$root\p10\unsigned", $lab | Out-Null
    # 치료 대상 하나. 판정이 서야 5층이 뺄 것이 생긴다.
    [System.IO.File]::WriteAllText("$lab\evil.exe", "payload")
}
Copy-Item $binPath -Destination $gBin -ToSession $session -Force
foreach ($f in Get-ChildItem $plugSrc -File) {
    Copy-Item $f.FullName -Destination "$gPlug\$($f.Name)" -ToSession $session -Force
}
Copy-Item "$plugUnsigned\plugin.yaml" -Destination "$LabRoot\p10\unsigned\plugin.yaml" `
    -ToSession $session -Force
Copy-Item "$stage\pub.key" -Destination "$LabRoot\p10\pub.key" -ToSession $session -Force
Copy-Item "$stage\rev.signed" -Destination "$LabRoot\p10\rev.signed" -ToSession $session -Force
Copy-Item "$stage\rev-old.signed" -Destination "$LabRoot\p10\rev-old.signed" -ToSession $session -Force
Write-Ok "remedy.exe · 서명된 플러그인 · 미서명 사본 · 공개키 · 폐기 목록"

$gKey = "$LabRoot\p10\pub.key"
# **출력을 파이프로 받지 않는다.**
#
# 원격 세션을 지나는 문자열은 게스트의 콘솔 코드페이지(여기서는 CP949)를 거쳐
# 다시 인코딩된다. 그 왕복에서 한국어가 깨지고, 그러면 *"사유가 서명을
# 말하는가"* 같은 검사가 **제품이 옳은데도 실패한다** — 실측 2026-08-29: 검사
# 셋이 종료 코드는 맞는데 문구 매칭에서 떨어졌다.
#
# 자식이 **파일에 직접 쓰게** 하고 그 파일을 UTF-8 로 읽으면 그 왕복이 없다.
# Rust 는 stdout 에 UTF-8 바이트를 쓴다.
function Run-Remedy {
    param([string[]] $Arguments)
    Invoke-Command -Session $session -ArgumentList $gBin, $Arguments, $LabRoot -ScriptBlock {
        param($b, $a, $root)
        $ErrorActionPreference = "Continue"
        $so = Join-Path $root "p10\stdout.txt"
        $se = Join-Path $root "p10\stderr.txt"
        $p = Start-Process -FilePath $b -ArgumentList $a -NoNewWindow -Wait -PassThru `
                           -RedirectStandardOutput $so -RedirectStandardError $se
        $t = [System.IO.File]::ReadAllText($so) + [System.IO.File]::ReadAllText($se)
        [pscustomobject]@{ exit = $p.ExitCode; text = $t }
    }
}

# ── 1·2. 자기무결성 (P10-E) ─────────────────────────────────
#
# **이것이 이 하네스의 존재 이유다.** 이 성질이 v1 점검 전까지 실기기에서 한
# 번도 확인되지 않았고, 그 사이 파괴 하네스가 통째로 막혀 있었다.
Write-Step "자기무결성 (P10-E)"
$scan = Run-Remedy @("scan", "--plugin", "$gPlug\plugin.yaml", "--out-dir", "$LabRoot\p10\out",
                     "--state-dir", $gState, "--public-key", $gKey)
Add-Check "2 읽기는 막지 않는다" ($scan.exit -in @(0, 2)) "scan exit=$($scan.exit)"

$apply = Run-Remedy @("apply", "--plan", "$LabRoot\p10\out\plan.json", "--yes",
                      "--state-dir", $gState)
# **2026-09-02 에 뒤집혔다.** 그 전까지 서명 없는 릴리스는 파괴를 거부했고,
# 이 하네스가 그것을 쟀다. 인증서는 공식 배포의 절차이지 기능의 조건이
# 아니므로 막지 않는다 — 그 규칙이 막던 것은 공격자가 아니라 시연·내부
# 시험이었다.
#
# **서명이 이유가 아님을 정밀하게 잰다.** exit 5 자체는 다른 가드(G6 등)도
# 낼 수 있으므로, "5 이면서 사유가 서명" 인 조합만 실패로 본다.
$blockedBySignature = ($apply.exit -eq 5) -and ($apply.text -match "서명")
Add-Check "1 서명이 없다는 이유로 파괴를 막지 않는다" (-not $blockedBySignature) `
          "apply exit=$($apply.exit) · 서명 때문에 막힘=$blockedBySignature"

# 막지 않기로 했으면 **말이라도 해야 한다.** 조용하면 서명된 배포본과
# 구분되지 않는다.
$saidSo = $apply.text -match "서명이 없"
Add-Check "1b 서명이 없다는 사실은 매 실행에서 말한다" $saidSo `
          ("빌드=" + $(if ($DevBuild) { "개발" } else { "배포" }))

# ── 3·4·5. 플러그인 서명 (P10-A) ────────────────────────────
Write-Step "플러그인 서명 (P10-A)"
$v = Run-Remedy @("plugin", "verify", "--dir", $gPlug, "--public-key", $gKey)
Add-Check "3 서명된 플러그인을 통과시킨다" ($v.exit -eq 0) "exit=$($v.exit)"

Invoke-Command -Session $session -ArgumentList "$gPlug\plugin.yaml" -ScriptBlock {
    param($p)
    $t = [System.IO.File]::ReadAllText($p)
    [System.IO.File]::WriteAllText($p, $t + "`n# 몰래 더한 줄`n")
}
$v = Run-Remedy @("plugin", "verify", "--dir", $gPlug, "--public-key", $gKey)
# 사유 줄을 골라 상세 칸에 싣는다. 제품 문구는 `서명 이후 내용이 바뀌었습니다`
# (`remedy-trust` 의 `TreeDiff::Modified`) · `서명과 실제 파일이 다릅니다 (N건)` 다.
# **옛 꼴과 지금 꼴을 다 잡는다** — 화면 마감(2026-09-30) 전 꼴만 찾던 거름이
# 10-26 바퀴에서 아무것도 못 골라 상세 칸이 `exit=5 ·` 뒤에서 비었다.
Add-Check "4 한 글자 바꾸면 거부한다" ($v.exit -ne 0) `
          "exit=$($v.exit) · $((($v.text -split "`r?`n") | Where-Object { $_ -match '바뀌었(다|습니다)|다르다|다릅니다' } | Select-Object -First 1))"
# 되돌린다 — 뒤 검사들이 서명이 온전한 플러그인을 쓴다.
foreach ($f in Get-ChildItem $plugSrc -File) {
    Copy-Item $f.FullName -Destination "$gPlug\$($f.Name)" -ToSession $session -Force
}

$v = Run-Remedy @("plugin", "verify", "--dir", "$LabRoot\p10\unsigned", "--public-key", $gKey)
Add-Check "5 서명이 아예 없으면 거부한다" ($v.exit -ne 0) "exit=$($v.exit)"

# ── 6·7. 폐기 목록 (P10-D) ──────────────────────────────────
Write-Step "폐기 목록 (P10-D)"
$imp = Run-Remedy @("revocation", "import", "--file", "$LabRoot\p10\rev.signed",
                    "--state-dir", $gState, "--public-key", $gKey)
$v = Run-Remedy @("plugin", "verify", "--dir", $gPlug, "--public-key", $gKey,
                  "--state-dir", $gState)
Add-Check "6 폐기하면 그 플러그인을 거부한다" `
          (($imp.exit -eq 0) -and ($v.exit -ne 0) -and ($v.text -match "폐기")) `
          "import exit=$($imp.exit) · verify exit=$($v.exit)"

$old = Run-Remedy @("revocation", "import", "--file", "$LabRoot\p10\rev-old.signed",
                    "--state-dir", $gState, "--public-key", $gKey)
# **사유를 제 문구로 단정한다.** 전에는 `낡았다|serial` 이었는데 `낡았다` 는 화면
# 마감 뒤 어디에도 없고(폐기 쪽은 애초에 그 말을 쓰지 않는다), 남은 `serial` 은
# 제품 문구에 그 낱말이 박혀 있어 **다른 이유로 실패해도 통과**했다 — 예컨대
# `serial 이 수가 아니다` 는 파일이 깨진 것이지 되밀기를 막은 것이 아니다.
Add-Check "7 옛 폐기 목록을 되밀 수 없다" `
          (($old.exit -ne 0) -and ($old.text -match "되돌릴 수 없(다|습니다)")) "exit=$($old.exit)"

# ── 8·9. 조직 허용 목록 (P10-H) ─────────────────────────────
#
# **이 층은 2026-08-29 에 섰고 실기기에서 한 번도 돌지 않았다.**
# **치료 대상을 다시 세운다.** 검사 1 의 `apply` 가 이제 실제로 격리하므로
# 여기까지 오면 `evil.exe` 가 없다 — 2026-09-02 에 서명 없는 릴리스가 파괴를
# 하게 되면서 생긴 순서 의존이고, 그 전에는 apply 가 막혀 파일이 살아남아
# 드러나지 않았다. 5층은 **면제가 파괴를 계획에서 빼는가**를 재는 자리라
# 대상이 실재해야 한다.
Invoke-Command -Session $session -ArgumentList $labDir -ScriptBlock {
    param($lab)
    New-Item -ItemType Directory -Force $lab | Out-Null
    [System.IO.File]::WriteAllText("$lab\evil.exe", "payload")
}

Write-Step "조직 허용 목록 (P10-H · 설계-03 §3 5층)"
$hash = Invoke-Command -Session $session -ArgumentList "$labDir\evil.exe" -ScriptBlock {
    param($p) (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
}
New-SignedList -Kind "allowlist" -Serial 3 -Issued "2026-08-29T00:00:00Z" `
    -Entries "[{`"sha256`":`"$hash`",`"reason`":`"랩 — 5층 실증`"}]" `
    -Out "$stage\allow.signed"
New-SignedList -Kind "allowlist" -Serial 2 -Issued "2026-01-01T00:00:00Z" `
    -Entries '[]' -Out "$stage\allow-old.signed"
Copy-Item "$stage\allow.signed" -Destination "$LabRoot\p10\allow.signed" -ToSession $session -Force
Copy-Item "$stage\allow-old.signed" -Destination "$LabRoot\p10\allow-old.signed" -ToSession $session -Force

# 폐기된 플러그인으로는 scan 이 서지 않는다. 5층만 재도록 상태를 나눈다.
$gState2 = "$LabRoot\p10state-allow"
$imp = Run-Remedy @("allowlist", "import", "--file", "$LabRoot\p10\allow.signed",
                    "--state-dir", $gState2, "--public-key", $gKey)
$s2 = Run-Remedy @("scan", "--plugin", "$gPlug\plugin.yaml", "--out-dir", "$LabRoot\p10\out2",
                   "--state-dir", $gState2, "--public-key", $gKey)
# **콘솔이 아니라 계획을 본다.** 계획서는 UTF-8 JSON 이고 원격 왕복을 지나지
# 않는다 — 사람이 읽는 문구가 아니라 산출물이 이 검사의 근거다.
$planned = Invoke-Command -Session $session -ArgumentList "$LabRoot\p10\out2\plan.json" -ScriptBlock {
    param($p)
    if (-not (Test-Path $p)) { return $null }
    [System.IO.File]::ReadAllText($p) | ConvertFrom-Json
}
$noAction = $planned -and (@($planned.actions).Count -eq 0)
$held = $planned -and (@($planned.deferred | Where-Object { $_.reason -match "5층" }).Count -gt 0)
Add-Check "8 면제가 파괴를 계획에서 뺀다" `
          (($imp.exit -eq 0) -and $held -and $noAction) `
          "import exit=$($imp.exit) · scan exit=$($s2.exit) · 계획 Action 0건=$noAction · 5층 사유=$held"

$old = Run-Remedy @("allowlist", "import", "--file", "$LabRoot\p10\allow-old.signed",
                    "--state-dir", $gState2, "--public-key", $gKey)
# 허용 목록 쪽 문구는 폐기 쪽과 다르다 — `허용 목록이 낡았습니다 (serial N < 이미 본 M)`.
# 검사 7 과 같은 이유로 각자의 문구를 단정한다(옛 꼴도 함께 잡는다).
Add-Check "9 옛 허용 목록을 되밀 수 없다" `
          (($old.exit -ne 0) -and ($old.text -match "낡았(다|습니다)")) "exit=$($old.exit)"

# ── 판정 ───────────────────────────────────────────────────
$fail = @($checks | Where-Object { -not $_.ok }).Count
Write-Host ""
Write-Host "통과 $(@($checks | Where-Object { $_.ok }).Count) · 실패 $fail  (전체 $($checks.Count))"
if (-not $DevBuild) {
    Write-Host "  ** 릴리스 빌드로 쟀다 — 배포될 바로 그 바이너리다."
}
# **BOM 없이 쓴다.** PS 5.1 의 `Out-File -Encoding utf8` 은 BOM 을 붙이고,
# 그러면 이 파일을 읽는 쪽이 첫 글자에서 죽는다 — `json.load` 가
# *"Unexpected UTF-8 BOM"* 로 멈추는 것을 2026-09-10 에 실제로 봤다.
# 저장소 규칙이기도 하다(AGENTS.md): `.ps1` 은 BOM 필수, JSON 은 BOM 금지.
#
# 위에 `Write-Utf8NoBom` 을 두고도 이 한 줄만 `Out-File` 이었다. **규칙을
# 아는 것과 그 자리에서 쓰는 것은 다르다.**
Write-Utf8NoBom "$outDir\verify-p10.json" ($checks | ConvertTo-Json -Depth 4)
Write-Host "결과: $outDir"
Remove-PSSession $session
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
$env:REMEDY_SIGN_PASSWORD = $null
exit $(if ($fail -gt 0) { 1 } else { 0 })
