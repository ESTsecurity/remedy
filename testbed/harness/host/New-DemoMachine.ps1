<#
.SYNOPSIS
    시연 기계를 준비한다 — 도구 · 룰 · Defender 예외 · 감염.

.DESCRIPTION
    시연은 **사내 어떤 서비스에도 붙지 않고** 도구 하나와 룰 한 벌로 도는 것을
    보이는 자리다. 기계 쪽에 준비할 것이 둘 있고, **모르면 시연이 그 자리에서
    멈춘다.**

      1. **Defender 예외.** 합성 페이로드를 Defender 가 먼저 지우면 시연이
         "이미 치료됨" 으로 보인다 — 보여 줄 것이 없어진다.

      2. **감염.** 예약 작업 · Run 키 · Defender 예외 · 페이로드. 구성은
         `InfectedState.ps1` 이 소유한다 — 검증 하네스와 같은 감염을 본다.

      3. **PHP2Shell 장(10단계).** 사후 처리 픽스처(올린 웹셸 · 정상 파일에
         심은 줄)는 **항상** 세운다 — 치료가 그 둘을 없애므로
         `-ReinfectOnly` 도 여기를 지난다. 점검 세 결과를 보이려면 **PHP 가
         필요하고** 그것은 `-PhpZip` 으로만 깐다. 주지 않으면 그 기계는
         *해당 없음*(종료 0)을 내는데, **그것도 대본의 한 장면**이다.

    **서명은 더 이상 준비물이 아니다** (2026-09-02). 그전에는 자체 서명
    인증서를 만들어 시연 기계의 신뢰 저장소(`LocalMachine\Root`)에 심어야
    했다 — 서명 없는 릴리스가 치료를 거부했기 때문이다. 남의 기계에 루트 CA
    를 심는 일이었고, SmartScreen 경고도 함께 따라왔다. 지금은 아무것도 하지
    않는다.

    준비가 끝나면 **기계는 감염된 상태로 남는다.** 시연 대본은
    시연 대본(내부 문서).

.PARAMETER Bin
    배포할 `remedy.exe` 의 **호스트 경로**. 주면 그 파일을 그대로 올리고
    **짓지 않는다** — Release 에서 내려받은 그 바이트로 재는 자리(기준 5(c))가
    여기다. 주지 않으면 지금까지처럼 `target\<triple>\release\remedy.exe` 다.

.PARAMETER ReinfectOnly
    도구·예외는 그대로 두고 **감염만 다시 세운다.** 시연을 두 번 돌릴 때
    쓴다 — 전체 준비는 3분 넘게 걸리고 감염만 다시 세우는 것은 몇 초다.

.PARAMETER NoRevert
    스냅샷으로 되돌리지 않는다. 이미 준비된 기계에 감염만 다시 세울 때.

.PARAMETER PhpZip
    PHP for Windows zip 의 **호스트 경로**. 주면 게스트의 `C:\php` 에 풀어
    10단계의 점검 장면이 선다. **설치만 하고 패치하지 않는다** — 랩 스냅샷에
    PHP 가 없으므로 되돌리면 사라진다(그래서 되돌릴 수 있는 일이다).

      공식 판   https://windows.php.net/download/          (NTS x64 zip)
      QA 판     https://downloads.php.net/~windows/qa/     (`…RC1`)

    QA 판을 주면 *확인 필요*(종료 6)가 나온다 — `php.exe` 가 문자열
    `8.2.27RC1` 을 선언하고 `version_lt` 는 점으로 나눈 숫자만 견주므로
    사전 배포 꼬리를 **거부**한다. 지어낸 입력이 아니라 공급사의 실물이다.

.EXAMPLE
    .\New-DemoMachine.ps1 -Build          # 처음 한 번
    .\New-DemoMachine.ps1 -ReinfectOnly   # 시연 사이 재설정
    .\New-DemoMachine.ps1 -Build -PhpZip D:\dl\php-8.2.35-1-nts-Win32-vs16-x64.zip
    .\New-DemoMachine.ps1 -Bin <내려받아 푼 꾸러미>\remedy.exe   # 기준 5(c)
#>
[CmdletBinding()]
param(
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string] $LabRoot = "C:\remedy-lab",
    [switch] $Build,
    [string] $Bin,
    [switch] $NoRevert,
    [switch] $ReinfectOnly,
    [string] $PhpZip,
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
. (Join-Path $PSScriptRoot "InfectedState.ps1")

$triple  = "x86_64-pc-windows-msvc"
# **`-Bin` 은 짓지 않는다.** 주어진 파일을 그대로 올린다 — 저장소 산출물
# (`target\...`)은 건드리지 않으므로 채점 증거의 해시가 흔들리지 않는다.
if ($Bin) {
    if ($Build) { throw "-Bin 과 -Build 는 함께 줄 수 없다 — 주어진 파일을 재는 자리다." }
    $binPath = (Resolve-Path $Bin).Path
} else {
    $binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"
}

# 시연에서 사람이 치는 경로. **짧아야 한다** — 화면에 길게 나오면 읽는 사람이
# 명령이 아니라 경로를 본다.
$demo    = "$LabRoot\demo"
$gBin    = "$demo\remedy.exe"
$gPlugin = "$demo\evilai\plugin.yaml"

if (-not $ReinfectOnly) {
    if ($Build) {
        Write-Step "빌드 (release — 배포될 물건이다)"
        Push-Location $repoRoot
        try {
            # **cargo 는 진행 상황을 stderr 로 쓴다.** `Stop` 아래에서 그것은
            # NativeCommandError 가 되어 **컴파일 중에** 스크립트를 죽였다 —
            # 캐시가 따뜻하면 아무것도 안 찍혀 숨어 있다가, 뭔가 새로 지어야
            # 하는 날 한 바퀴를 통째로 멈췄다 (2026-09-11 에 그렇게 걸렸다).
            # 지금은 `Invoke-CargoBuild` 가 출력을 변수로 받아 그 stream 을
            # 아예 지나지 않는다.
            Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
        } finally { Pop-Location }
    }
    if (-not (Test-Path $binPath)) { throw "산출물이 없다: $binPath`n -Build 를 줄 것." }

    if (-not $NoRevert) {
        & (Join-Path $PSScriptRoot "Reset-Vm.ps1") -Vmx $Vmx -Snapshot $Snapshot -VmAddress $VmAddress
    }
}

$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential

if (-not $ReinfectOnly) {
    # ── 1. Defender 예외 ────────────────────────────────────────────
    #
    # **페이로드가 먼저 지워지면 보여 줄 것이 없다.** 실검체가 아니라 룰에서
    # 도출한 합성 바이트지만, 그래서 오히려 탐지에 걸리기 쉽다.
    #
    # 랩 디렉터리만 연다. Defender 를 끄지 않는다 — 끄면 시연 환경이 실제
    # 사용자 PC 와 다른 것이 되고, 그런 곳의 시연은 아무것도 뜻하지 않는다.
    Write-Step "Defender 예외 (랩 경로만)"
    $paths = Invoke-Command -Session $session -ArgumentList $LabRoot -ScriptBlock {
        param($root)
        $ErrorActionPreference = "Continue"
        $ps = @($root, "$env:LOCALAPPDATA\Programs")
        foreach ($p in $ps) {
            New-Item -ItemType Directory -Force $p | Out-Null
            Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
        }
        (Get-MpPreference).ExclusionPath
    }
    Write-Ok "예외 $(@($paths).Count) 건"

    # ── 2. 도구와 룰 ────────────────────────────────────────────────
    Write-Step "도구와 룰 배포"
    Invoke-Command -Session $session -ArgumentList $demo -ScriptBlock {
        param($d)
        New-Item -ItemType Directory -Force "$d\evilai\rules" | Out-Null
        New-Item -ItemType Directory -Force "$d\newthreat\rules" | Out-Null
        New-Item -ItemType Directory -Force "$d\php2shell" | Out-Null
    }
    Copy-Item $binPath -Destination $gBin -ToSession $session -Force
    Copy-Item (Join-Path $repoRoot "plugins\evilai-locust\plugin.yaml") `
              -Destination $gPlugin -ToSession $session -Force
    foreach ($y in Get-ChildItem (Join-Path $repoRoot "plugins\evilai-locust\rules") -File) {
        Copy-Item $y.FullName -Destination "$demo\evilai\rules\$($y.Name)" `
                  -ToSession $session -Force
    }

    # ── 9단계의 "새 위협" 재료 ──────────────────────────────────────
    #
    # **대본을 따라 하려면 이것이 있어야 한다** (2026-09-13 리허설이 찾았다).
    # 09-10 리허설에서는 두 룰을 그 자리에서 만들어 쓰고 저장소에 남기지
    # 않았고, 대본은 알맹이(헤더 없는 조각)만 싣고 있어 그대로는 만들 수
    # 없었다 — 즉 **마지막 장면에서 막혔다.** 이제 함께 배포한다.
    #
    # `plugin.yaml` 은 **일부러 틀린 판**이다. 린트가 오류 1 · 경고 1 로
    # 잡는 장면이 시연에서 두 번째로 중요한 자리다.
    $nt = Join-Path $repoRoot "testbed\demo\newthreat"
    foreach ($f in @("plugin.yaml", "plugin-fixed.yaml")) {
        Copy-Item (Join-Path $nt $f) -Destination "$demo\newthreat\$f" `
                  -ToSession $session -Force
    }
    foreach ($y in Get-ChildItem (Join-Path $nt "rules") -File) {
        Copy-Item $y.FullName -Destination "$demo\newthreat\rules\$($y.Name)" `
                  -ToSession $session -Force
    }
    # ── 10단계의 PHP2Shell 룰 셋 ────────────────────────────────────
    #
    # 점검 둘과 사후 처리 하나. **`rules\` 가 없다** — YARA 를 쓰지 않기
    # 때문이다(판과 자리로 선다). 점검을 플랫폼마다 가른 이유는 보는 자리가
    # 아예 다르기 때문이다: Windows 는 `php.exe` 의 버전 리소스, 리눅스는
    # 패키지 DB. 한 파일로 묶으면 반대 플랫폼에서 그 룰이 **미평가**로 남고
    # 시연에서 그 줄을 설명해야 한다.
    #
    # Linux 판도 함께 배포한다 — 11단계가 그 파일을 컨테이너에 그대로 쓴다.
    $php2 = Join-Path $repoRoot "testbed\demo\php2shell"
    foreach ($f in @("check-windows.yaml", "check-linux.yaml", "aftermath.yaml")) {
        Copy-Item (Join-Path $php2 $f) -Destination "$demo\php2shell\$f" `
                  -ToSession $session -Force
    }
    Write-Ok "remedy.exe · evilai (plugin.yaml · rules) · newthreat (두 판 · rules) · php2shell (룰 셋)"

    # ── 3. 정말 파괴할 수 있는가 ────────────────────────────────────
    #
    # **여기서 확인하지 않으면 시연 도중에 알게 된다.** 서명은 이제 조건이
    # 아니지만, 배포 중 파일이 상하면 `Untrusted` 로 떨어져 읽기 전용이 된다.
    Assert-CanDestroy -Session $session -Bin $gBin
}

# ── 10단계 전반: PHP (옵션) ─────────────────────────────────────────
#
# 주지 않으면 깔지 않는다 — 그 기계는 *해당 없음*(종료 0)을 내고 그것도 대본의
# 한 장면이다. **정상 흐름을 건드리지 않는다**: `-PhpZip` 없이 부르면 이 블록을
# 지나가지 않으므로 1~9단계는 전과 같다.
#
# **`-ReinfectOnly` 에서도 돈다** (2026-10-28 리허설이 찾았다). 처음에는 배포
# 블록 안에 두었는데, 그러면 `-ReinfectOnly -PhpZip <다른 판>` 이 **조용히
# 아무것도 하지 않는다** — 받은 인자를 버리는 것이고 조작자는 모른다. 그리고
# 리허설이 필요한 것이 바로 그 자리다: 판만 바꿔 *취약*(2) 과 *확인 필요*(6)
# 두 화면을 잇따라 보려면 전체 준비를 다시 돌 이유가 없다.
if ($PhpZip) {
    if (-not (Test-Path $PhpZip)) { throw "PHP zip 이 없다: $PhpZip" }
    Write-Step "PHP 설치 (설치만 — 패치 아님)"
    $gZip = "$LabRoot\php.zip"
    Copy-Item $PhpZip -Destination $gZip -ToSession $session -Force
    $phpInfo = Invoke-Command -Session $session -ArgumentList $gZip -ScriptBlock {
        param($z)
        Remove-Item 'C:\php' -Recurse -Force -ErrorAction SilentlyContinue
        Expand-Archive -LiteralPath $z -DestinationPath 'C:\php' -Force
        Remove-Item $z -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path 'C:\php\php.exe')) { return $null }
        [pscustomobject]@{
            files  = (Get-ChildItem 'C:\php' -Recurse -File).Count
            osSays = (Get-Item 'C:\php\php.exe').VersionInfo.FileVersion
        }
    }
    if (-not $phpInfo) { throw "zip 에 php.exe 가 없다: $PhpZip" }
    # **OS 가 보는 값**이다. 룰이 견주는 것은 파일이 선언한 문자열이고, 그 둘은
    # 서비싱이 걸린 경로에서 갈린다(`remedy-collect/src/peversion.rs`). 갓 풀어
    # 둔 파일에는 리디렉션이 없어 여기서는 같다.
    Write-Ok "C:\php — 파일 $($phpInfo.files)개 · OS 가 보는 판 '$($phpInfo.osSays)'"
}

# ── 4. 감염 ─────────────────────────────────────────────────────────
Write-Step "감염 구성"
$payloadDir = Invoke-Command -Session $session -ScriptBlock {
    Join-Path $env:LOCALAPPDATA "Programs\MicrosoftResourcesAgentV12-we9i6"
}
$payload = Get-SynthPayloadBytes -RulePath (Join-Path (Join-Path $repoRoot "plugins\evilai-locust") "rules\evilai.yar")
Set-InfectedState -Session $session -PayloadDir $payloadDir | Out-Null
Set-GuestPayload  -Session $session -PayloadDir $payloadDir -Bytes $payload | Out-Null

# 앞선 시연이 남긴 상태를 지운다. **run_id 가 쌓이면 어느 것을 되돌릴지 헷갈린다.**
Invoke-Command -Session $session -ArgumentList $demo -ScriptBlock {
    param($d)
    Remove-Item "$d\state", "$d\out" -Recurse -Force -ErrorAction SilentlyContinue
    # 10단계는 자기 상태 폴더를 쓴다 — 섞으면 6단계의 `restore --list` 에
    # PHP 회차가 함께 떠서 "어느 것을 되돌리나" 가 화면에 생긴다.
    Remove-Item "$d\state-php", "$d\out-php" -Recurse -Force -ErrorAction SilentlyContinue
}
$fp = Get-InfectedFingerprint -Session $session -PayloadDir $payloadDir
Write-Ok "예약 작업=$($fp.task) · Run 값=$([bool]$fp.run_value) · 페이로드 $($payload.Length) B"

# ── 5. 10단계 사후 처리 픽스처 ──────────────────────────────────────
#
# **치료가 이 둘을 없앤다** — 웹셸은 격리소로 가고 심은 줄은 빠진다. 그래서
# `-ReinfectOnly` 도 이 자리를 지나며 다시 세운다(감염과 같은 이유다).
#
# 저장소의 바이트를 그대로 복사한다. 그래야 `restore` 뒤 sha256 대조가
# 재현된다 — **193 B `a11f6770…` · 167 B `308eb6f8…`** (Windows·Linux 양쪽
# 실측에서 같은 값이다. 줄 끝이 LF 이므로 플랫폼이 바뀌어도 같다).
#
# 둘 다 **무해한 자리 채우기**다 — base64 는 `/* placeholder */` 로 풀린다.
# 룰이 보는 것은 모양(자리와 한 줄)이고, 그것이 시연에서 보일 것이다.
Write-Step "PHP2Shell 사후 처리 픽스처"
Invoke-Command -Session $session -ScriptBlock {
    New-Item -ItemType Directory -Force 'C:\inetpub\wwwroot\uploads' | Out-Null
    New-Item -ItemType Directory -Force 'C:\inetpub\wwwroot\app'     | Out-Null
}
$fx = Join-Path $repoRoot "testbed\demo\php2shell\fixtures"
Copy-Item (Join-Path $fx "uploads\invoice-9f2.php") `
          -Destination 'C:\inetpub\wwwroot\uploads\invoice-9f2.php' -ToSession $session -Force
Copy-Item (Join-Path $fx "app\index.php") `
          -Destination 'C:\inetpub\wwwroot\app\index.php' -ToSession $session -Force
$fxh = Invoke-Command -Session $session -ScriptBlock {
    foreach ($p in @('C:\inetpub\wwwroot\uploads\invoice-9f2.php',
                     'C:\inetpub\wwwroot\app\index.php')) {
        $i = Get-Item $p
        "$($i.Name) $($i.Length) B $((Get-FileHash $p -Algorithm SHA256).Hash.Substring(0,8))"
    }
}
Write-Ok ($fxh -join " · ")

Write-Host ""
Write-Host "시연 기계 준비 완료 — 감염된 상태다." -ForegroundColor Green
Write-Host ""
Write-Host "  게스트에서 (관리자 PowerShell):"
Write-Host "    cd $demo"
Write-Host "    .\remedy.exe scan --plugin .\evilai\plugin.yaml --out-dir .\out --state-dir .\state"
Write-Host ""
Write-Host ""
Write-Host "  10단계 (PHP2Shell):"
Write-Host "    .\remedy.exe scan --plugin .\php2shell\check-windows.yaml --out-dir .\out-php --state-dir .\state-php"
Write-Host "    .\remedy.exe run  --plugin .\php2shell\aftermath.yaml     --out-dir .\out-php --state-dir .\state-php --yes"
if (-not $PhpZip) {
    Write-Host "    (PHP 를 깔지 않았다 — 점검은 '해당 없음' 을 낸다. 취약·확인 필요를 보이려면 -PhpZip)" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  대본: 시연 대본(내부 문서)"
Write-Host "  다시 감염시키려면: .\New-DemoMachine.ps1 -ReinfectOnly -NoRevert"
Remove-PSSession $session
