#Requires -Version 5.1
<#
.SYNOPSIS
    **한 바퀴** — 하네스 전수를 한 번에 돌리고 누계를 낸다.

.DESCRIPTION
    2026-09-11~13 사흘에 하네스를 **열아홉 번** 손으로 불렀다. 그때마다 순서를
    기억하고, 판정 줄을 눈으로 읽고, 합계를 손으로 더했다. 세 번째가 오면 만들
    때라고 적어 두었고, 지금이 그때다.

    # 왜 종료 코드만으로는 안 되는가

    하네스마다 판정 줄의 모양이 다르다 — 다섯 가지다.

      판정 31/31                          P4 · P5 · 새 여섯 · trunc
      게스트 검사   50/50                 P6 · P8
      통과 12 · 실패 0 · 미실증 0  (전체 12)   P9 · P10 · P10F · linux-verify
      판정     : 통과 14 · 실패 0 · 미결 0     P2
      채점 5 합격.                        리눅스 위협 셋

    합계를 내려면 그 다섯을 읽어야 한다. **읽지 못하면 통과로 세지 않는다** —
    조용히 0 으로 세면 한 바퀴의 합계가 거짓이 된다.

    # 판정은 둘 다 본다

    종료 코드가 0 이어도 판정이 `12/14` 면 실패다. 반대로 판정을 못 읽었으면
    종료 코드가 0 이어도 **`판정 못 읽음`** 으로 적고 실패로 센다. 어느 쪽이든
    **모르는 것을 통과로 만들지 않는다.**

    # 종료 코드 없음

    `$LASTEXITCODE` 는 프로세스 하나를 함께 쓰는 전역이고, `exit` 없이 끝난
    스크립트는 그것을 **건드리지 않는다.** 그래서 비우지 않으면 이 칸에 **이
    프로세스에서** 마지막으로 돈 네이티브 명령의 코드가 찍힌다 — 흔히 **그
    하네스 자신의 것**이고, 앞 하네스 안이든 `-Build` 의 빌드든 묶음을 부르기
    전 그 콘솔에서든 상관없다. 어느 쪽이든 하네스의 판정이 아니다.

    2026-10-26 에 여섯(`Sign` · `Obs` · `Guard` · `Panic` · `SlowStop` ·
    `Partial`)이 성공 경로에서 `exit` 를 두지 않았고, `-Only SlowStop` 은
    **11/11 인데 칸이 비어 실패로 셌다.** 둘을 같이 고쳤다 — 하네스는 성공도
    말하고, 묶음은 부르기 전에 그 전역을 비워 **`없음`** 을 가려낸다. 없으면
    실패다. 물려받은 값으로 메우면 그 하네스가 무엇을 말했는지 모른 채 센다.

    **비우기로 잡는 것은 "아무것도 내지 않았다" 뿐이다.** PowerShell 은 명시적
    `exit 9` 와 스크립트 끝에 남은 네이티브 명령의 9 를 구분해 주지 않는다
    (모형으로 확인했다). 그래서 칸을 하네스의 말로 만드는 것은 **하네스마다
    `exit` 를 두는 쪽**이고, 비우기는 그것을 잊은 하네스를 조용히 지나가지
    않게 하는 그물이다. 새 하네스를 넣을 때 `exit` 를 두는지 보라.

    **`exit <변수>` 는 그 그물 밖이다.** PowerShell 은 `$null`·숫자 아닌
    문자열·배열을 조용히 **0(통과)** 으로 만든다(실측). 변수로 나가는 다섯
    (`P2` · `P4` · `P5` · `P6` · `P8`)은 그 값이 늘 정수라 무사하지만, 새로 그
    꼴을 쓸 때는 null 을 먼저 가려내고 `[int]` 로 못박을 것.

    **문제의 뿌리는 `& <스크립트>` 가 같은 프로세스에서 도는 것이다.** 리눅스
    단계(`& wsl …`)와 게스트 스크립트(`Invoke-GuestScript` 가 게스트에서
    `powershell.exe -File` 을 띄운다)는 **자식 프로세스**라, 자식이 뜨면 그
    종료 코드는 `exit` 가 없어도 정의된다(정상 종료는 0). 다만 **뜨지 못하면**
    그 전역이 앞 값을 그대로 들고 있어 앞 단계의 코드를 이 단계의 것으로 읽게
    되므로, 리눅스 단계도 같이 비운다. 게스트 쪽은 다른 프로세스의
    `$LASTEXITCODE` 라 이 묶음이 비울 것이 없다.

    # 캡처는 여기 없다

    콘솔 캡처는 기준선 후보를 만드는 일이고 검증이 아니다. 화면을 바꾼 회차의
    절차는 README 의 점검표가 따로 적고 있다.

.PARAMETER Only
    이름 일부로 걸러 그것만 돌린다 (예: `-Only P6,Sign`).

.PARAMETER SkipLinux
    리눅스 다섯을 건너뛴다. **주지 않았는데 docker 가 없으면 실패로 센다** —
    조용히 건너뛰면 한 바퀴가 무엇을 재었는지 알 수 없다.

.PARAMETER Build
    릴리스 바이너리를 **여기서 한 번** 만든다(Windows 64·32비트 + bookworm).
    하네스마다 `-Build` 를 주면 같은 빌드를 열네 번 한다.

    32비트는 **P2 의 WOW64 검사 둘**이 쓴다(`wow64-tasks` · `wow64-content`).
    여기서 짓지 않으면 P2 는 `target\i686-…\release` 에 **있는 것을 쓴다** —
    10-26 바퀴에서 그것이 09-14 판이었고, 나머지 열아홉이 그날 코드로 돈
    바퀴에서 그 검사 둘만 한 달 묵은 바이너리로 섰다.

.EXAMPLE
    .\Invoke-Sweep.ps1 -Build
    .\Invoke-Sweep.ps1 -Only P6,P8 -SkipLinux
#>
[CmdletBinding()]
param(
    [string[]] $Only,
    [switch] $SkipLinux,
    [switch] $Build,
    [string] $VmAddress
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$triple = "x86_64-pc-windows-msvc"
# **32비트도 짓는다.** P2 의 WOW64 검사 둘이 이것을 쓴다 — `.PARAMETER Build` 참고.
$triple32 = "i686-pc-windows-msvc"

. (Join-Path $PSScriptRoot "VmSession.ps1")

# 랩 값 — 주어지지 않으면 `.cargo/windows_lab.yml` 에서 읽고, 없으면 멈춘다.
$VmAddress = Resolve-LabValue $VmAddress 'windows_lab' 'windows_lab.network.ip' 'VmAddress'

# 리눅스 단계는 WSL·docker 에서 돈다 — 저장소와 cargo 레지스트리를 **WSL 에서 본
# 경로**로 물려야 한다. 그 경로는 기계마다 다르므로 `.cargo/host.yml` 에서 읽는다.
$wslRepo = Get-LabConfigValue -File 'host' -Key 'wsl.repo'
$wslCargo = Get-LabConfigValue -File 'host' -Key 'wsl.cargo_home'
if (-not $SkipLinux -and (-not $wslRepo -or -not $wslCargo)) {
    throw ("리눅스 단계에 WSL 경로가 필요하다 — .cargo/host.yml 의 'wsl.repo' 와 " +
           "'wsl.cargo_home' 에 적거나 -SkipLinux 로 건너뛸 것 " +
           "(견본: .cargo/host.example.yml)")
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $repoRoot "testbed\harness\results\sweep-$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)

# **로그의 꼴도 물려받지 않는다.** `*>` 는 `Out-File` 로 구현되어 부른 세션의
# `$PSDefaultParameterValues` 를 따른다. 기본값(UTF-16LE)과 `utf8` 은 BOM 이 있어
# 아래 `ReadAllLines(…, UTF8)` 가 바로 읽지만, `oem`·`default`·`ascii` 로 둔 세션에서는
# **BOM 없는 CP949** 로그가 되어 판정 줄을 다시 못 읽는다(실측). 여기서 못박는다.
# 하네스에도 물려가지만 하네스는 `Out-File` 에 늘 `-Encoding` 을 준다 — 영향은
# 이 로그 셋뿐이다.
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

# ── 네이티브 한글을 읽어야 하는 호출은 UTF-8 콘솔에서 ────────────
#
# PowerShell 은 네이티브 명령의 출력을 **`[Console]::OutputEncoding` 으로 푼 뒤**
# 문자열로 넘긴다. WSL **안의 것**(bash · docker · remedy)은 UTF-8 로 쓰는데 이 PC 의
# 새 콘솔은 CP949 다(ACP·OEMCP 949 · 콘솔 코드페이지 재정의도 프로필도 없다).
# 맞추지 않으면 한글이 깨져 **하네스가 통과했는데 한 바퀴가 `판정 못 읽음` 으로
# 센다** — 10-26 바퀴에서 리눅스 다섯이 그렇게 섰다.
#
# **그 호출만 감싸고 되돌린다.** 세터는 콘솔 창 전체(부른 쪽 셸까지)의 출력
# 코드페이지를 바꾸므로, 전역으로 두면 한 바퀴가 중간에 죽을 때 부른 사람의 창이
# UTF-8 로 남는다. 호스트의 CP949 네이티브 출력을 읽는 자리도 있다 — 지금 스냅샷
# 이름이 전부 ASCII 라 `Reset-Vm.ps1` 의 이름 비교는 무사하지만, 한글 이름이 생기면
# 그 비교가 전역 변경에 걸린다.
#
# **이미 UTF-8 이면 손대지 않는다.** 콘솔이 아예 없는 프로세스에서는 세터가
# *"핸들이 잘못되었습니다"* 로 던진다. 그런 기계의 ACP 가 65001 이면 전에 제대로
# 세던 단계가 실패로 바뀌므로, 바꿀 필요가 없을 때는 건드리지 않는다.
#
# 맞추기에 실패하면 **삼키지 않는다.** 그대로 올려 한 바퀴가 그 단계를 예외(99)로
# 적는다 — CP949 로 조용히 돌아 `판정 못 읽음` 을 내는 것보다 이유가 남는 쪽이 낫다.
#
# 건지지 못하는 한 부류: **`wsl.exe` 자신의** 오류 문구는 UTF-8 이 아니라 UTF-16LE 라
# 949 든 65001 든 로그에서 읽히지 않는다(2026-10-26 실측). WSL 이 뜨지 않은 회차의
# 사유는 종료 코드로만 안다.
function Invoke-WithUtf8Console {
    param([Parameter(Mandatory = $true)][scriptblock] $Body)
    $prevEnc = [Console]::OutputEncoding
    try {
        if ($prevEnc.CodePage -ne 65001) { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 }
        & $Body
    } finally {
        if ($prevEnc.CodePage -ne 65001) { [Console]::OutputEncoding = $prevEnc }
    }
}

# ── 무엇을 도는가 ────────────────────────────────────────────────
#
# **싼 것부터**. 빌드가 깨졌거나 랩이 안 뜨면 1분 안에 알게 된다 — P2 를
# 먼저 두면 그 사실을 8분 뒤에 안다.
$Harnesses = @(
    # **`Sign` 은 VM 을 쓰지 않는다** — `plugin verify` 는 파일만 읽는다.
    # 그래서 `-VmAddress` 를 받지 않고, 넘기면 인자 오류로 죽는다.
    @{ Name = "Sign"; Kind = "win"; Script = "Invoke-SignVerify.ps1"; NoVm = $true }
    @{ Name = "Obs"; Kind = "win"; Script = "Invoke-ObsVerify.ps1" }
    @{ Name = "Guard"; Kind = "win"; Script = "Invoke-GuardVerify.ps1" }
    @{ Name = "Panic"; Kind = "win"; Script = "Invoke-PanicVerify.ps1" }
    @{ Name = "SlowStop"; Kind = "win"; Script = "Invoke-SlowStopVerify.ps1" }
    # **시연 대본이 아직 사실인가** — 점검표에서 이 문서만 게이트가 없었다.
    # 09-13 리허설에서 결론 장면(9단계)의 룰 두 판이 저장소에 통째로 없어
    # **대본을 따라 하면 마지막에서 막히는** 상태였고, 손으로 돌려서야 알았다.
    #
    # 넣기 전에 둘을 쟀다(09-14). 추정이 둘 다 틀렸다:
    #   회차 시간        7분으로 봤는데 **143초**
    #   다음 하네스 영향  미지였는데 **없다** — 회차 직후 되돌리지 않고 Partial 을
    #                    돌려 `전제: 깨끗하다 · 계획 7건 · 11/11` 을 받았다.
    #                    남는 예외 둘(`C:\remedy-lab` · `…\Programs`)은 그쪽
    #                    payload_dir 을 **포함하지 않아** 계획에 들어오지 않는다.
    @{ Name = "Demo"; Kind = "win"; Script = "Invoke-DemoVerify.ps1" }
    @{ Name = "Partial"; Kind = "win"; Script = "Invoke-PartialVerify.ps1" }
    @{ Name = "P4"; Kind = "win"; Script = "Invoke-P4Verify.ps1" }
    @{ Name = "P5"; Kind = "win"; Script = "Invoke-P5Verify.ps1" }
    @{ Name = "P10"; Kind = "win"; Script = "Invoke-P10Verify.ps1" }
    @{ Name = "P10F"; Kind = "win"; Script = "Invoke-P10FVerify.ps1" }
    @{ Name = "P6"; Kind = "win"; Script = "Invoke-P6Verify.ps1" }
    @{ Name = "P8"; Kind = "win"; Script = "Invoke-P8Verify.ps1" }
    @{ Name = "P9"; Kind = "win"; Script = "Invoke-P9Verify.ps1" }
    @{ Name = "P2"; Kind = "win"; Script = "Invoke-P2Verify.ps1" }
    @{ Name = "linux-verify"; Kind = "linux"; Sh = "verify" }
    @{ Name = "linux-trunc"; Kind = "linux"; Sh = "trunc" }
    @{ Name = "exam-ldso"; Kind = "linux"; Sh = "exam"; Threat = "ldso-preload" }
    @{ Name = "exam-c2"; Kind = "linux"; Sh = "exam"; Threat = "c2-beacon" }
    @{ Name = "exam-tls"; Kind = "linux"; Sh = "exam"; Threat = "tls-intercept"; Attended = $true }
)

if ($Only) {
    $Harnesses = @($Harnesses | Where-Object { $n = $_.Name; @($Only | Where-Object { $n -like "*$_*" }).Count -gt 0 })
    if ($Harnesses.Count -eq 0) { throw "-Only 가 아무것도 고르지 않았다: $($Only -join ',')" }
}
if ($SkipLinux) { $Harnesses = @($Harnesses | Where-Object { $_.Kind -ne "linux" }) }
# **0개를 통과로 만들지 않는다.** `-Only` 는 자기 걸러내기만 보므로
# `-Only linux-trunc -SkipLinux` 처럼 둘이 겹치면 목록이 비고, 루프가 한 번도
# 돌지 않은 채 `합계 0/0` 이 초록으로 찍힌다 — 아무것도 재지 않은 바퀴다.
if ($Harnesses.Count -eq 0) { throw "돌릴 하네스가 없다 — -Only 와 -SkipLinux 가 전부 걸러냈다." }

# ── 판정 줄 읽기 ─────────────────────────────────────────────────
#
# 다섯 모양을 차례로 맞춰 본다. **첫 것이 맞으면 거기서 멈춘다.**
function Read-Verdict {
    param([string[]] $Lines)
    foreach ($l in ($Lines | Where-Object { $_ })) {
        if ($l -match '^\s*판정\s+(\d+)/(\d+)') { return @{ Pass = [int]$Matches[1]; Total = [int]$Matches[2] } }
        if ($l -match '게스트 검사\s+(\d+)/(\d+)') { return @{ Pass = [int]$Matches[1]; Total = [int]$Matches[2] } }
        if ($l -match '통과\s+(\d+)\s*·\s*실패\s+(\d+).*전체\s+(\d+)') { return @{ Pass = [int]$Matches[1]; Total = [int]$Matches[3] } }
        if ($l -match '판정\s*:\s*통과\s+(\d+)\s*·\s*실패\s+(\d+)\s*·\s*미결\s+(\d+)') {
            return @{ Pass = [int]$Matches[1]; Total = ([int]$Matches[1] + [int]$Matches[2] + [int]$Matches[3]) }
        }
        # 채점 5 는 합격/불합격 하나짜리 판정이다.
        if ($l -match '^채점 5 합격') { return @{ Pass = 1; Total = 1 } }
        if ($l -match '^채점 5 불합격') { return @{ Pass = 0; Total = 1 } }
    }
    return $null
}

# ── 빌드는 여기서 한 번 ──────────────────────────────────────────
if ($Build) {
    Write-Step "빌드 (한 번)"
    Push-Location $repoRoot
    try {
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
        # 타깃이 깔려 있지 않으면 cargo 가 `rustup target add` 를 짚어 주고,
        # `Invoke-CargoBuild` 가 그 출력을 전부 찍은 뒤 던진다. 여기서 한 번 더 묻지
        # 않는다 — 다만 그 자리는 **x64 를 다 지은 뒤**다(약 2분). P2 는 같은 검사를
        # 빌드 전에 한다.
        Invoke-CargoBuild "remedy.exe (32비트)" @("build", "--release", "--target", $triple32, "-p", "remedy-cli")
        foreach ($fx in @("watchdog", "labsvc")) {
            Invoke-CargoBuild $fx @("build", "--release", "--manifest-path",
                (Join-Path $repoRoot "testbed\fixtures\$fx\Cargo.toml"))
        }
    } finally { Pop-Location }
    Write-Ok "remedy.exe (64·32비트) · 픽스처 2종"

    if (-not $SkipLinux) {
        Write-Step "빌드 (bookworm · 오프라인)"
        $sh = "docker run --rm -v ${wslRepo}:/repo:ro " +
        "-v ${wslCargo}/registry:/usr/local/cargo/registry " +
        "-v /tmp/remedy-bookworm:/t -e CARGO_TARGET_DIR=/t -w /repo rust:1.96-bookworm " +
        "cargo build --release --offline -p remedy-cli"
        # **cargo 만 그런 것이 아니다.** wsl·docker·rustup 도 진행 상황을
        # stderr 로 쓰고, `Stop` 아래에서 그 한 줄이 NativeCommandError 가
        # 되어 한 바퀴를 첫 단계에서 멈춰 세운다 (2026-09-13 에 밟았다).
        #
        # 이 출력도 UTF-8 콘솔에서 받는다 — 172 줄이 찍는 마지막 두 줄이 bookworm
        # 빌드가 깨진 회차의 **유일한 진단**이다. 지금 cargo·docker 출력은 ASCII 라
        # 깨질 것이 없지만, 리눅스 단계와 패턴을 하나로 둔다.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $buildOut = Invoke-WithUtf8Console { & wsl bash -lc $sh 2>&1 }
        $rcLinux = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        $buildOut | Select-Object -Last 2 | ForEach-Object { Write-Host "    $_" }
        if ($rcLinux -ne 0) { throw "bookworm 빌드 실패 (exit $rcLinux)" }
        Write-Ok "완료"
    }
}

# ── 예외 사유는 로그와 같은 꼴로 ────────────────────────────────
#
# 로그는 `*>` 가 만든다. Windows PowerShell 5.1 의 기본은 **UTF-16LE** 이고,
# 세션이 `$PSDefaultParameterValues` 로 바꿔 두면 UTF-8 BOM 이 된다 — 10-26 에
# 둘 다 실측했다(첫 호출 20개가 UTF-16LE, 09-14·재호출은 UTF-8 BOM).
#
# 그래서 사유를 UTF-8 로 못박으면 **UTF-16LE 로그 안에서 깨진다.** 예외로 끝난
# 회차에 정작 필요한 것이 그 한 줄인데, 그때만 읽을 수 없다. 읽는 쪽
# (`ReadAllLines`)은 BOM 을 보고 파일 전체를 한 꼴로 푼다 — 그 꼴에 맞춰 쓴다.
#
# UTF-8 BOM 파일에는 BOM 없는 UTF-8 을 덧붙여도 바이트가 맞으므로, 가려낼 것은
# UTF-16LE 하나다. UTF-16BE 는 `*>` 가 내지 않는다(기본값이 LE 이고, 위에서 `utf8` 로
# 못박았다). 파일이 아직 없으면(예외가 리다이렉션 전에 났다) 지금처럼 BOM 없는
# UTF-8 로 만든다.
function Get-LogEncoding {
    param([string] $Path)
    if (Test-Path $Path) {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $bom = New-Object byte[] 2
            $n = $fs.Read($bom, 0, 2)
        } finally { $fs.Dispose() }
        if ($n -eq 2 -and $bom[0] -eq 0xFF -and $bom[1] -eq 0xFE) {
            # `AppendAllText` 는 비어 있지 않은 파일에 preamble 을 쓰지 않는다.
            return [System.Text.Encoding]::Unicode
        }
    }
    return (New-Object System.Text.UTF8Encoding($false))
}

# 리눅스 한 줄은 길어서 함수로.
function Invoke-LinuxStep {
    param([hashtable] $H, [string] $LogPath)
    $bin = "/tmp/remedy-bookworm/release/remedy"
    $base = "cd ${wslRepo} && "
    $cmd = switch ($H.Sh) {
        "verify" { $base + "testbed/harness/linux/invoke-linux-verify.sh --bin $bin" }
        "exam" {
            $att = if ($H.Attended) { " --attended" } else { "" }
            $base + "testbed/harness/linux/invoke-exam-apply.sh --threat $($H.Threat) --bin $bin$att"
        }
        "trunc" {
            "docker run --rm -v ${wslRepo}:/repo " +
            "-v ${wslCargo}/registry:/usr/local/cargo/registry " +
            "-v remedy-bookworm-target:/tmp/remedy-bookworm -e CARGO_TARGET_DIR=/tmp/remedy-bookworm " +
            "rust:1.96-bookworm bash /repo/testbed/harness/linux/trunc-verify.sh"
        }
        default { throw "모르는 리눅스 단계: $($H.Sh)" }
    }
    # 여기도 같다 — 모든 스트림을 파일로 보내지만, 그 전에 예외가 되면
    # 파일에는 아무것도 남지 않는다.
    #
    # 판정 줄이 한글이므로 **UTF-8 콘솔에서 받는다** — 까닭은
    # `Invoke-WithUtf8Console` 머리에 있다.
    $prevEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        # win 쪽과 같은 이유로 비운다 — `wsl` 이 **뜨지 못하면** 그 전역이 앞 값을
        # 그대로 들고 있어, 앞 단계의 0 을 이 단계의 코드로 읽게 된다.
        $global:LASTEXITCODE = $null
        Invoke-WithUtf8Console { & wsl bash -lc $cmd *> $LogPath }
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
    return $rc
}

# ── 한 바퀴 ──────────────────────────────────────────────────────
$results = New-Object System.Collections.Generic.List[object]
$started = Get-Date

foreach ($h in $Harnesses) {
    Write-Step ("{0}  ({1})" -f $h.Name, $h.Kind)
    $log = Join-Path $outDir ("{0}.log" -f $h.Name)
    $t0 = Get-Date
    try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        if ($h.Kind -eq "win") {
            # **직전 단계의 코드를 물려받지 않는다.** `$LASTEXITCODE` 는 프로세스
            # 하나를 함께 쓰는 전역이고, `exit` 없이 끝난 스크립트는 그것을 건드리지
            # 않는다. 그래서 비우지 않으면 이 칸에 **앞 하네스 안에서 마지막으로 돈
            # 네이티브 명령**의 코드가 찍힌다 — 2026-10-26 에 여섯 하네스가 성공
            # 경로에서 `exit` 를 두지 않아 그랬고, `-Only SlowStop` 은 11/11 인데
            # 칸이 비어 실패로 셌다.
            $global:LASTEXITCODE = $null
            if ($h.NoVm) {
                & (Join-Path $PSScriptRoot $h.Script) *> $log
            } else {
                & (Join-Path $PSScriptRoot $h.Script) -VmAddress $VmAddress *> $log
            }
            $rc = $LASTEXITCODE
        } else {
            $rc = Invoke-LinuxStep -H $h -LogPath $log
        }
        $ErrorActionPreference = $prevEap
    } catch {
        $ErrorActionPreference = $prevEap
        [System.IO.File]::AppendAllText($log, "`n[하네스가 예외로 끝났다] $($_.Exception.Message)`n",
            (Get-LogEncoding $log))
        $rc = 99
    }
    $secs = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)

    $lines = @()
    if (Test-Path $log) { $lines = [System.IO.File]::ReadAllLines($log, [System.Text.Encoding]::UTF8) }
    $v = Read-Verdict -Lines $lines

    # **모르는 것을 통과로 만들지 않는다.** 종료 코드와 판정 줄 둘 다 봐야 하고,
    # 판정을 못 읽었으면 그것 자체가 실패다. 종료 코드를 **내지 않은** 것도 같다 —
    # 물려받은 값으로 메우면 그 하네스가 무엇을 말했는지 모른 채 세게 된다.
    $ok = ($null -ne $rc) -and ($rc -eq 0) -and ($null -ne $v) -and ($v.Pass -eq $v.Total)
    $shown = if ($v) { "{0}/{1}" -f $v.Pass, $v.Total } else { "판정 못 읽음" }
    $rcShown = if ($null -eq $rc) { "없음" } else { [string]$rc }

    $results.Add([pscustomobject]@{
            name = $h.Name; kind = $h.Kind; exit = $rc; seconds = $secs
            pass = $(if ($v) { $v.Pass } else { 0 })
            total = $(if ($v) { $v.Total } else { 0 })
            verdict_read = ($null -ne $v)
            ok = $ok
        })
    $color = if ($ok) { "Green" } else { "Red" }
    Write-Host ("    {0}  exit={1}  {2}초" -f $shown, $rcShown, $secs) -ForegroundColor $color
}

# ── 누계 ─────────────────────────────────────────────────────────
$elapsed = [math]::Round(((Get-Date) - $started).TotalMinutes, 1)
$pass = [int]($results | Measure-Object -Property pass -Sum).Sum
$total = [int]($results | Measure-Object -Property total -Sum).Sum
$bad = @($results | Where-Object { -not $_.ok })

Write-Host ""
Write-Host ("{0,-14} {1,-8} {2,6} {3,8}" -f "하네스", "판정", "종료", "초")
Write-Host ("-" * 40)
foreach ($r in $results) {
    $shown = if ($r.verdict_read) { "{0}/{1}" -f $r.pass, $r.total } else { "못 읽음" }
    $rcCell = if ($null -eq $r.exit) { "없음" } else { [string]$r.exit }
    Write-Host ("{0,-14} {1,-8} {2,6} {3,8}" -f $r.name, $shown, $rcCell, $r.seconds) `
        -ForegroundColor $(if ($r.ok) { "Green" } else { "Red" })
}
Write-Host ("-" * 40)
Write-Host ("합계 {0}/{1} · 하네스 {2}개 · {3}분" -f $pass, $total, $results.Count, $elapsed) `
    -ForegroundColor $(if ($bad.Count -eq 0) { "Green" } else { "Red" })
if ($bad.Count -gt 0) {
    Write-Host ("걸린 것: {0}" -f (($bad | ForEach-Object { $_.name }) -join " · ")) -ForegroundColor Red
    Write-Host "  각각의 로그: $outDir" -ForegroundColor Red
}

$report = [pscustomobject]@{
    schema = "remedy-sweep/1"
    at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    minutes = $elapsed
    pass = $pass; total = $total
    # **`@($results)` 로 감싸지 않는다.** PowerShell 5.1 에서 `List[object]` 를
    # `@(...)` 로 감싸 `[pscustomobject]` 에 넣으면 *"Argument types do not
    # match"* 로 죽는다 — 표를 다 찍은 **뒤**에 죽어서 한 바퀴가 성공처럼
    # 보이고 보고서만 없다 (2026-09-13 에 밟았다).
    harnesses = $results.ToArray()
}
[System.IO.File]::WriteAllText([string](Join-Path $outDir "sweep.json"), [string]($report | ConvertTo-Json -Depth 5), $utf8)
Write-Host "`n결과: $outDir"
# **묶음도 자기 규칙 안이다.** 하네스에게 성공도 말하라고 하면서 여기서 물려받은
# 값으로 끝나면 안 된다 — 성공한 바퀴의 코드는 마지막 하네스가 남긴 값이었다.
exit $(if ($bad.Count -gt 0) { 1 } else { 0 })
