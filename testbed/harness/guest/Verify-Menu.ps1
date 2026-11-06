#Requires -Version 5.1
<#
.SYNOPSIS
    작업 메뉴를 **진짜 콘솔에서 번호를 눌러** 작업 열일곱(목록이 있으면 스물하나)을 끝까지
    돌린다 (목표 remedy_cli 기준 6 · remedy_제품화 기준 5(b)).

.DESCRIPTION
    메뉴는 `stdin` 이 터미널일 때만 열린다 (불변식 I7). WinRM 세션에는 콘솔이
    없고 `RedirectStandardInput` 을 쓰면 `is_terminal()` 이 거짓이 되므로
    **메뉴 경로는 통째로 시험 밖에 남아 있었다** — 스물한 줄을 만들어 놓고 그
    화면을 한 번도 보지 못한 채였다.

    `Approve-Interactive.ps1` 과 같은 방법으로 푼다: `AllocConsole` 로 콘솔을
    만들고 `WriteConsoleInput` 으로 번호를 밀어 넣는다.

    # 번호를 미리 넣는다 — 그것이 타이밍 문제를 없앤다

    콘솔 입력 버퍼는 **프로세스가 아니라 콘솔의 것**이다. 그래서 프로그램이
    아직 묻지 않았어도 넣어 둔 줄이 버퍼에 남고, `read_line` 이 올 때 순서대로
    하나씩 소비된다 (사람이 미리 치는 것과 같다). 검사가 10초를 끌든 승인
    질문이 늦게 뜨든 **얼마나 기다릴지 재지 않아도 된다.**

    # 마지막 줄은 늘 빈 줄이다

    인자 없는 호출은 끝에서 **창을 붙잡는다** (`wait_before_closing` — 더블클릭
    한 사람이 화면을 읽을 수 있어야 한다). 그래서 작업마다 Enter 하나가 더
    든다. 이것을 빼면 모든 회차가 시간 초과로 보인다.

    # 번호를 박아 두지 않는다

    2026-11-05 부터 메뉴는 기계 상태와 상관없이 스물한 줄을 같은 번호로 세운다 —
    지금 고를 수 없는 줄은 까닭을 단다(`N. 이름 — 까닭`). 그래도 번호를 박지
    않는다: 줄이 더해지면 번호가 바뀐다. 작업마다 먼저 `0`(그만두기)으로 띄워
    메뉴를 읽고, 라벨로 번호를 찾아 그 번호를 누른다. 까닭이 달린 줄은 고를
    줄로 세지 않는다. 찾은 번호와 실제로 돌아간 명령이 같은지는 화면으로 다시 본다.

    # 이 스크립트가 별도 프로세스인 이유

    `Approve-Interactive.ps1` 과 같다 — `AllocConsole` 이 표준 핸들을 갈아
    끼우고, 되돌려도 PowerShell 호스트가 화면 버퍼를 다시 잡지 못해 이후
    `Write-Host` 가 죽는다. **그래서 아래에는 화면 출력이 하나도 없다.**
    결과는 JSON 과 전사 파일로 낸다.

.PARAMETER Bin
    시험할 remedy.exe — **검증을 통과하는 꾸러미 안의 것**이어야 한다. 옆에
    `plugins\<이름>\plugin.yaml` 이 있고 그 서명을 이 바이너리에 박힌 앵커가
    확인할 수 있어야 메뉴에 묶음 B 다섯 줄이 선다.

.PARAMETER PayloadDir
    감염 페이로드 폴더. 작업마다 기계 상태를 여기서 잰다.

.PARAMETER OutFile
    결과 JSON. BOM 없이 쓴다.

.PARAMETER TranscriptFile
    화면 전사. 시연 대본이 인용할 수 있게 남긴다.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $PayloadDir,
    [Parameter(Mandatory = $true)][string] $OutFile,
    [Parameter(Mandatory = $true)][string] $TranscriptFile,
    # 메뉴 번호 **앞에** 먼저 넣을 줄. 룰 묶음이 여럿이면 `guided::choose` 가
    # 메뉴보다 먼저 *"어느 것을 검사할까요"* 를 묻는다 (`guided.rs` — `choose`
    # 가 `menu::run` 앞에 선다). 한 벌이면 묻지 않으므로 비워 둔다.
    [string[]] $Lead = @(),
    # 재는 작업을 좁힌다. 비우면 전부. **비파괴로 확인할 때** `탐지` 만
    # 주면 기계를 감염 상태로 남긴 채 메뉴가 도는지 볼 수 있다. 어느 것과도
    # 맞지 않는 값(`없음` 등)을 주면 **첫 화면만** 띄우고 끝난다 — 콘솔 기준선
    # 캡처가 그 꼴로 쓴다(랩 상태를 바꾸지 않아야 뒤 절의 전제가 산다).
    [string[]] $Keys = @(),
    # 화면 언어. 기준선은 한국어·영어 두 벌이고 `Capture-Console.ps1` 이
    # 회차마다 하나를 준다.
    #
    # **판정 문구는 한국어만 읽는다.** 아래 `shown`·`held_window` 들이 한국어
    # 정규식이므로 `-Lang en` 회차의 판정은 거짓이 된다 — 영어 회차는 **전사만**
    # 쓰는 자리(콘솔 기준선 캡처)를 위한 것이고, 판정을 보는 자리는
    # `Invoke-MenuVerify.ps1` 이며 그것은 기본값 `ko` 로 부른다.
    [ValidateSet("ko", "en")][string] $Lang = "ko",
    # 실행 파일 옆에 서명된 목록 둘(`menu-allowlist.signed` · `menu-revocations.signed`)이
    # 있다 — 호스트가 꾸러미를 지은 일회용 키로 서명해 둔 회차에서만 준다. 주면 목록 넷
    # (확인 · 반입 × 허용 · 폐기)도 돈다. 내려받은 공개 꾸러미에는 그 목록이 없다(배포
    # 키로 서명한 허용 목록은 모든 고객 기계에서 탐지를 끌 수 있는 물건이라 만들지 않는다).
    [switch] $Lists,
    [string] $TaskName = "Locust",
    [string] $TaskPath = "\Microsoft\Windows\",
    [string] $RunName  = "SystemSoftwareUpdater"
)

$ErrorActionPreference = "Stop"

Add-Type -Namespace RemedyLab -Name Menu -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool AllocConsole();
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetStdHandle(int n, IntPtr h);

[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES {
    public int nLength;
    public IntPtr lpSecurityDescriptor;
    [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
}
[DllImport("kernel32.dll", EntryPoint="CreateFileW", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateFileSA(string name, uint access, uint share,
    ref SECURITY_ATTRIBUTES sec, uint disp, uint flags, IntPtr templ);

// 상속 가능한 콘솔 입력 핸들. **상속 가능해야 한다** — .NET 이 stdout·stderr 를
// 재지정하면 STARTF_USESTDHANDLES 가 켜지고, 그때 상속 불가 핸들은 자식에게
// 닿지 않는다.
static IntPtr OpenConin() {
    SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
    sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
    sa.lpSecurityDescriptor = IntPtr.Zero;
    sa.bInheritHandle = true;
    return CreateFileSA("CONIN$", 0xC0000000u, 3u, ref sa, 3u, 0u, IntPtr.Zero);
}

// 이 프로세스의 stdin 을 **콘솔 입력 버퍼로 못 박는다.**
//
// 순서가 중요하다. 먼저 `CONIN$` 를 열어 본다 — 그것이 "콘솔에 붙어 있는가" 의
// 진짜 답이다. `GetConsoleWindow` 로 물으면 창 없는 콘솔에서 거짓말을 하고,
// `AllocConsole` 부터 부르면 이미 붙어 있을 때 실패한다.
public static int EnsureConsoleStdin() {
    IntPtr conin = OpenConin();
    if (conin == new IntPtr(-1)) {
        if (!AllocConsole()) return -(1000 + Marshal.GetLastWin32Error());
        conin = OpenConin();
        if (conin == new IntPtr(-1)) return -(2000 + Marshal.GetLastWin32Error());
    }
    if (!SetStdHandle(-10, conin)) return -(3000 + Marshal.GetLastWin32Error());
    return 0;
}

[StructLayout(LayoutKind.Sequential)]
public struct KEY_EVENT_RECORD {
    [MarshalAs(UnmanagedType.Bool)] public bool bKeyDown;
    public ushort wRepeatCount;
    public ushort wVirtualKeyCode;
    public ushort wVirtualScanCode;
    public ushort UnicodeChar;
    public uint   dwControlKeyState;
}
[StructLayout(LayoutKind.Sequential)]
public struct INPUT_RECORD {
    public ushort EventType;
    public KEY_EVENT_RECORD KeyEvent;
}
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share,
    IntPtr sec, uint disp, uint flags, IntPtr templ);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool WriteConsoleInputW(IntPtr h, INPUT_RECORD[] recs, uint n, out uint written);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FlushConsoleInputBuffer(IntPtr h);

// 앞 회차가 읽지 않고 남긴 줄을 버린다.
//
// **콘솔 입력 버퍼는 프로세스가 아니라 콘솔의 것이다** — 그것이 미리 넣어 두는
// 방식을 가능하게 하는 성질이고, 동시에 함정이다. 2026-10-29 에 복원이 승인을
// 묻지 않아(`--yes` 없이는 목록만 낸다) 넣어 둔 `예` 가 버퍼에 남았고, 그
// 줄이 **다음 회차의 첫 `read_line`** 으로 들어가 메뉴가 그만두기로 갔다.
// 회차마다 비우면 한 회차의 실패가 다음 회차로 번지지 않는다.
public static int FlushInput() {
    IntPtr conin = CreateFileW("CONIN$", 0xC0000000u, 3u, IntPtr.Zero, 3u, 0u, IntPtr.Zero);
    if (conin == new IntPtr(-1)) return -1;
    bool ok = FlushConsoleInputBuffer(conin);
    CloseHandle(conin);
    return ok ? 0 : -2;
}

// 한 줄을 키 입력으로 밀어 넣는다. 콘솔은 줄 입력 모드라 개행까지 와야
// ReadConsoleW 가 돌아간다. **빈 문자열이면 Enter 하나다** — 창을 붙잡는
// 자리에서 그것만 필요하다. 음수는 실패다.
public static int TypeLine(string text) {
    IntPtr conin = CreateFileW("CONIN$", 0xC0000000u, 3u, IntPtr.Zero, 3u, 0u, IntPtr.Zero);
    if (conin == new IntPtr(-1)) return -1;
    string all = text + "\r";
    INPUT_RECORD[] recs = new INPUT_RECORD[all.Length * 2];
    for (int i = 0; i < all.Length; i++) {
        for (int d = 0; d < 2; d++) {
            int k = i * 2 + d;
            recs[k].EventType = 1; // KEY_EVENT
            recs[k].KeyEvent.bKeyDown = (d == 0);
            recs[k].KeyEvent.wRepeatCount = 1;
            recs[k].KeyEvent.wVirtualKeyCode = (all[i] == '\r') ? (ushort)0x0D : (ushort)0;
            recs[k].KeyEvent.UnicodeChar = (ushort)all[i];
        }
    }
    uint written;
    bool ok = WriteConsoleInputW(conin, recs, (uint)recs.Length, out written);
    CloseHandle(conin);
    return ok ? (int)written : -2;
}
'@

# ── 기계 상태 — 작업마다 같은 넷을 잰다 ──────────────────────────────
#
# `InfectedState.ps1` 의 `Get-InfectedFingerprint` 와 **같은 자리**를 본다.
# 거기서 재지 않고 여기서 다시 재는 이유는 이 스크립트가 콘솔을 쥐고 있어
# 호스트가 작업 사이에 끼어들 수 없기 때문이다. 담는 것은 넷으로 좁혔다 —
# 전체 지문(SDDL · XML 전문)은 `Compare-State` 의 일이다.
function Get-Snapshot {
    $p = Join-Path $PayloadDir 'preload.js'
    $t = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    $runVal = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
                 -ErrorAction SilentlyContinue).$RunName
    $excl = @()
    try { $excl = @((Get-MpPreference).ExclusionPath | Where-Object { $_ -like "*$PayloadDir*" }) } catch { }
    [ordered]@{
        payload = (Test-Path $p)
        task    = ($null -ne $t)
        run_key = [bool]$runVal
        excl    = ($excl.Count -gt 0)
    }
}

# **stdin 은 재지정하지 않는다.** 콘솔 핸들을 그대로 물려받아야 `is_terminal()`
# 이 참이 되고, 그래야 메뉴가 열린다.
function Start-WithRealConsole {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Bin
    $psi.Arguments = ""
    $psi.WorkingDirectory = (Split-Path -Parent $Bin)
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $psi.EnvironmentVariables["REMEDY_LANG"] = $Lang
    [System.Diagnostics.Process]::Start($psi)
}

# 번호들을 눌러 한 회차를 끝까지 돌린다. **마지막 빈 줄은 부르는 쪽이 넣는다** —
# 넣지 않으면 창을 붙잡는 자리에서 멈춘다.
function Invoke-MenuRun {
    param([string[]] $Lines, [int] $TimeoutMs = 180000)
    # **앞 회차의 잔재를 먼저 버린다** — 까닭은 `FlushInput` 의 주석에 있다.
    $flushed = [RemedyLab.Menu]::FlushInput()
    $p = Start-WithRealConsole
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    # 메뉴가 화면에 다 뜬 뒤에 넣는다. 타이밍이 틀려도 버퍼에 남으므로 판정이
    # 흔들리지는 않지만, 전사에 메뉴가 먼저 찍혀 있어야 사람이 읽을 수 있다.
    Start-Sleep -Milliseconds 1200
    $typed = @()
    foreach ($l in $Lines) {
        $typed += [RemedyLab.Menu]::TypeLine($l)
        Start-Sleep -Milliseconds 120
    }
    $done = $p.WaitForExit($TimeoutMs)
    if (-not $done) { try { $p.Kill() } catch { }; $p.WaitForExit() }
    [ordered]@{
        lines     = $Lines
        typed     = $typed
        flushed   = $flushed
        timed_out = (-not $done)
        exit      = $p.ExitCode
        text      = ($o.Result + $e.Result)
    }
}

# 메뉴 줄을 라벨 -> 번호로 읽는다. `  3. 치료가 유지됐는지 다시 보기` 모양이다.
# 지금 고를 수 없는 줄은 `  6. 치료를 되돌리기 — 이 PC 에 치료한 기록이 없습니다` 모양이고
# 그 번호를 누르면 까닭만 보이고 다시 묻는다 — 고를 줄로 세지 않는다(따로 센다).
$OffRow = '^\s\s\d+\.\s+.+? (—|-) '
function Get-MenuMap {
    param([string] $Text)
    $map = [ordered]@{}
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match $OffRow) { continue }
        if ($line -match '^\s\s(\d+)\.\s+(.+?)\s*$') {
            $label = $Matches[2]
            if (-not $map.Contains($label)) { $map[$label] = [int]$Matches[1] }
        }
    }
    $map
}

function Find-MenuNumber {
    param($Map, [string] $Needle)
    foreach ($k in $Map.Keys) {
        if ($k -like "*$Needle*") { return $Map[$k] }
    }
    return 0
}

# 자식이 덧붙여 쓰는 중인 파일을 읽는다. `ReadAllText` 는 남의 쓰기 핸들이 열려 있으면
# 공유 위반으로 실패한다 — 쓰기를 허용하는 공유 모드로 연다.
function Read-Shared {
    param([string] $Path)
    try {
        $fs = New-Object System.IO.FileStream($Path, 'Open', 'Read', 'ReadWrite')
        try { (New-Object System.IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Dispose() }
    } catch { "" }
}

# **끝나지 않은 회차를 세운다** — `remedy-cli/tests/apply.rs` 의 `crash_and_resume` 과 같은
# 방법이다. 대상 400건짜리 계획을 `apply` 하고, 진행 이벤트에 첫 `action`(파괴 시작)이 보이면
# 죽인다. 늦게 보면 다 끝나 버리고(`finished`) 일찍 죽이면 파괴 전이라 네 번까지 다시 한다.
# 상태 폴더는 메뉴가 보는 자리(실행 파일 옆 `state`)여야 메뉴에 그 회차가 뜬다. 대상은 이
# 하네스가 만든 빈 파일이다.
function New-InterruptedRun {
    param([string] $Dir, [int] $Count = 400)
    $state = Join-Path (Split-Path -Parent $Bin) "state"
    $last = $null
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        $runId = "run-menu-resume-$attempt"
        if (Test-Path $Dir) { Remove-Item $Dir -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $Dir | Out-Null
        $actions = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $Count; $i++) {
            $t = Join-Path $Dir ("target-{0:D4}.dat" -f $i)
            [System.IO.File]::WriteAllText($t, "remedy-lab resume target $i")
            $actions.Add([ordered]@{ seq = $i + 1; op = "file.quarantine_only"; target = $t
                                     because = @("payload#0"); reversible = $true; risk = "low" })
        }
        $plan = [ordered]@{
            schema_version = 1; kind = "remedy.plan"; run_id = $runId; created = "2026-11-06T00:00:00Z"
            host = [ordered]@{ hostname = "lab"; os = "windows"; version = "10"; arch = "amd64" }
            core = [ordered]@{ version = "0"; build = "lab" }; plugins = @()
            actions = $actions.ToArray(); verdicts = @("g0")
        }
        $planFile = Join-Path $Dir "plan.json"
        $events = Join-Path $Dir "events.ndjson"
        [System.IO.File]::WriteAllText($planFile, ($plan | ConvertTo-Json -Depth 6),
                                       (New-Object System.Text.UTF8Encoding($false)))
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Bin
        $psi.Arguments = "apply --plan `"$planFile`" --state-dir `"$state`" --yes --events `"$events`""
        $psi.UseShellExecute = $false
        # 표준 입력을 재지정한다 — 터미널이 아니어야 메뉴 · 질문이 끼지 않는다.
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
        $p = [System.Diagnostics.Process]::Start($psi)
        $null = $p.StandardOutput.ReadToEndAsync()
        $null = $p.StandardError.ReadToEndAsync()
        $deadline = (Get-Date).AddSeconds(30)
        $seen = "none"
        while ((Get-Date) -lt $deadline) {
            $txt = Read-Shared $events
            if ($txt -match '"event"\s*:\s*"finished"') { $seen = "finished"; break }
            if ($txt -match '"event"\s*:\s*"action"') { $seen = "action"; break }
            Start-Sleep -Milliseconds 2
        }
        try { $p.Kill() } catch { }
        $p.WaitForExit()
        $left = @(Get-ChildItem $Dir -Filter "target-*.dat").Count
        $last = [ordered]@{ attempt = $attempt; seen = $seen; left = $left; total = $Count; run_id = $runId }
        if ($seen -eq "action" -and $left -gt 0 -and $left -lt $Count) { return $last }
    }
    return $last
}

# ── 여기서부터 화면에 쓰지 않는다 ────────────────────────────────────
$rc = [RemedyLab.Menu]::EnsureConsoleStdin()

$report = [ordered]@{
    schema      = "remedy-lab.verify-menu/2"
    console_rc  = $rc
    bin         = $Bin
    payload_dir = $PayloadDir
    probe       = $null
    steps       = @()
    verdict     = $false
}
$tr = New-Object System.Collections.Generic.List[string]

if ($rc -ne 0) {
    [System.IO.File]::WriteAllText($OutFile, ($report | ConvertTo-Json -Depth 8),
                                   (New-Object System.Text.UTF8Encoding($false)))
    exit 1
}

# ── 0. 메뉴가 뜨는가 · 몇 줄인가 ─────────────────────────────────────
#
# `0` 은 그만두기이고 그 갈래의 종료 코드는 **0** 이다 (결정 8 · 2026-10-30).
#
# **빈 줄 없이 `0` 만 보낸다** (2026-11-05 · 목표 remedy_제품화 기준 4). 그만두기는
# 창을 붙잡지 않는다 — 끝내기를 고른 것이다. 붙잡으면 Enter 를 기다리다 시간이 다
# 되므로, **시간 초과가 없는 것이 곧 붙잡지 않았다는 증거**다.
# 전에는 2(발견·미치료)였다 — `NothingUsable`(도구가 검사하지 못했다)과 같은
# 결로 묶여 있었는데, 여기는 **사람이** 검사하지 않기로 한 것이고 화면이 그렇게
# 말한다. 치료 승인을 거절한 자리는 이 갈래가 아니라 `approved()` 를 지나 2 다.
$probe = Invoke-MenuRun -Lines (@() + $Lead + @("0")) -TimeoutMs 30000
$pmap = Get-MenuMap -Text $probe.text
$report.probe = [ordered]@{
    exit        = $probe.exit
    timed_out   = $probe.timed_out
    shown       = [bool]($probe.text -match "무엇을 할까요")
    item_count  = @($pmap.Keys | Where-Object { $pmap[$_] -gt 0 }).Count
    off_count   = @(($probe.text -split "`r?`n") | Where-Object { $_ -match $OffRow }).Count
    separator   = [bool]($probe.text -match "작성자·운영자 명령")
    held_window = ([bool]$probe.timed_out -or [bool]($probe.text -match "Enter 를 누르십시오"))
    nothing     = [bool]($probe.text -match "아무것도 하지 않았습니다")
    labels      = @($pmap.Keys)
}
$tr.Add("=== 0. 인자 없이 띄웠다 — 메뉴 (그만두기로 끝냈다) ===")
$tr.Add($probe.text.TrimEnd())

# ── 작업 열일곱 · 목록이 있으면 스물하나 ────────────────────────────────
#
# 차례가 뜻을 만든다. 탐지가 `out\plan.json` 을 남겨 치료의 고를 거리가 되고,
# 치료가 회차를 만들어 신고·복원의 고를 거리가 된다. 복원이 감염을 되살리므로
# 마지막 탐지+치료가 할 일이 있다.
#
# `sub` 는 두 번째 화면(어느 회차 · 어느 파일)에서 누를 번호다. 이 흐름에서는
# 후보가 하나뿐이라 `1` 이고, 그 "하나뿐" 을 화면에서 다시 확인한다.
$steps = @(
    [ordered]@{ key = "탐지";      needle = "검사만 하기";            sub = $null; approve = $false; expect = 2; timeout = 300000 }
    [ordered]@{ key = "치료";      needle = "승인한 계획을 수행하기"; sub = "1";   approve = $true;  expect = 1; timeout = 300000 }
    [ordered]@{ key = "신고";      needle = "신고에 붙일 것 모으기";  sub = "1";   approve = $false; expect = 0; timeout = 300000 }
    [ordered]@{ key = "복원";      needle = "치료를 되돌리기";        sub = "1";   approve = $true;  expect = 0; timeout = 300000 }
    [ordered]@{ key = "탐지+치료"; needle = "검사하고 치료하기";      sub = $null; approve = $true;  expect = 1; timeout = 600000 }
    # 아래는 목표 remedy_제품화 기준 5(b) — **메뉴에서 고를 수 있는 나머지도 진짜 콘솔에서
    # 끝까지 돈다.** 치료가 끝난 깨끗한 기계에서 돌므로 기대 코드는 그 상태의 값이다.
    # `sub = "last"` 는 후보 목록을 먼저 읽고 **가장 새 파일**을 고른다 — 검사 · 검사+치료도
    # 같은 종류의 파일(artifacts · scan)을 회차 폴더에 남겨, '1' 은 감염 때의 것이다.
    [ordered]@{ key = "유지 확인";      needle = "치료가 유지됐는지 다시 보기";        sub = $null;  approve = $false; expect = 0; timeout = 300000 }
    [ordered]@{ key = "되돌릴 것 보기"; needle = "되돌릴 수 있는 것 보기";             sub = $null;  approve = $false; expect = 0; timeout = 60000 }
    [ordered]@{ key = "자체 점검";      needle = "프로그램 자체 점검";                 sub = $null;  approve = $false; expect = 0; timeout = 120000 }
    [ordered]@{ key = "판 보기";        needle = "판 보기";                            sub = $null;  approve = $false; expect = 0; timeout = 60000 }
    [ordered]@{ key = "쓰는 법";        needle = "쓰는 법";                            sub = $null;  approve = $false; expect = 0; timeout = 60000 }
    [ordered]@{ key = "모든 명령";      needle = "모든 명령과 옵션";                   sub = $null;  approve = $false; expect = 0; timeout = 60000 }
    [ordered]@{ key = "번들 확인";      needle = "이 플러그인 번들이 우리 것인지 확인"; sub = $null;  approve = $false; expect = 0; timeout = 60000 }
    [ordered]@{ key = "룰 검사";        needle = "룰 검사";                            sub = $null;  approve = $false; expect = 0; timeout = 120000 }
    [ordered]@{ key = "수집";           needle = "수집만 하기";                        sub = $null;  approve = $false; expect = 0; timeout = 300000 }
    [ordered]@{ key = "평가";           needle = "수집 결과를 평가하기";               sub = "last"; approve = $false; expect = 0; timeout = 300000 }
    [ordered]@{ key = "계획";           needle = "평가 결과로 계획 세우기";            sub = "last"; approve = $false; expect = 0; timeout = 300000 }
    # 기준 5(b) 의 나머지 다섯(2026-11-06). 이어 하기는 바로 앞에서 끊은 회차를 **그 id 로**
    # 고른다(`before = interrupt` 가 세우고 `id:` 가 고른다) — 회차가 여럿이라 번호를 짐작하지
    # 않는다. 남은 대상이 0 이어야 끝까지 돈 것이다. **이어 하기는 계획을 다시 보이고 승인을
    # 묻는다** — 승인 없이 넣었더니 빈 줄이 거절이 되어 아무것도 하지 않았다(2026-11-06 첫 회차).
    [ordered]@{ key = "이어 하기"; needle = "중단된 작업 이어서 하기"; sub = "id:"; approve = $true; expect = 1; timeout = 300000; before = "interrupt" }
)
# 목록 넷 — 호스트가 일회용 키로 서명한 목록을 둔 회차에서만. 후보 파일이 둘이라 이름으로
# 고른다. 내용은 이 기계에 없는 해시 · 쓰지 않는 플러그인이라 반입해도 뒤의 작업을 바꾸지 않는다.
if ($Lists) {
    $steps += @(
        [ordered]@{ key = "허용 목록 확인"; needle = "조직 허용 목록 확인"; sub = "id:menu-allowlist.signed";   approve = $false; expect = 0; timeout = 60000 }
        [ordered]@{ key = "허용 목록 반입"; needle = "조직 허용 목록 반입"; sub = "id:menu-allowlist.signed";   approve = $false; expect = 0; timeout = 60000 }
        [ordered]@{ key = "폐기 목록 확인"; needle = "폐기 목록 확인";      sub = "id:menu-revocations.signed"; approve = $false; expect = 0; timeout = 60000 }
        [ordered]@{ key = "폐기 목록 반입"; needle = "폐기 목록 반입";      sub = "id:menu-revocations.signed"; approve = $false; expect = 0; timeout = 60000 }
    )
}

# **중간에 죽어도 거기까지는 쓴다.** 2026-10-29 의 첫 회차가 다섯 작업을 전부
# 돌린 뒤 보고서 한 줄에서 죽어 **진단 정보를 통째로 잃었다** — 호스트는
# *"인수 형식이 일치하지 않습니다"* 한 줄만 받았다. 그래서 고리를 감싸고 사유를
# 결과에 담는다.
if ($Keys.Count -gt 0) { $steps = @($steps | Where-Object { $Keys -contains $_.key }) }

$results = New-Object System.Collections.Generic.List[object]
$failure = $null
try {
foreach ($s in $steps) {
    # 이어 하기는 그 직전에 끊은 회차가 있어야 고를 줄이 선다.
    $interrupt = $null
    $sub = $s.sub
    if ($s.before -eq "interrupt") {
        $interrupt = New-InterruptedRun -Dir "C:\remedy-lab\resume"
        $sub = "id:" + $interrupt.run_id
    }
    $before = Get-Snapshot

    # 작업마다 다시 읽는다 — 앞 작업이 만든 회차 · 파일로 고를 수 있는 줄이 바뀐다.
    $look = Invoke-MenuRun -Lines (@() + $Lead + @("0", "")) -TimeoutMs 60000
    $map = Get-MenuMap -Text $look.text
    $no = Find-MenuNumber -Map $map -Needle $s.needle

    if ($no -gt 0 -and $sub -eq "last") {
        # 고른 뒤 `0`(메뉴로 돌아가기)으로 후보 수만 읽는다. 결과 폴더는 스탬프 이름순 =
        # 시간순이라(`guided::candidate_files`) 마지막 번호가 가장 새 파일이다.
        $peek = Invoke-MenuRun -Lines (@() + $Lead + @("$no", "0", "")) -TimeoutMs 60000
        $sub = $null
        if ($peek.text -match "어느 파일입니까\?\s*\((\d+)개\)") { $sub = $Matches[1] }
    } elseif ($no -gt 0 -and "$sub".StartsWith("id:")) {
        # 후보 목록을 먼저 읽고 **그 이름이 든 줄**의 번호를 누른다. 메뉴 줄은 그 이름을
        # 담지 않으므로 후보 줄만 걸린다.
        $want = $sub.Substring(3)
        $peek = Invoke-MenuRun -Lines (@() + $Lead + @("$no", "0", "")) -TimeoutMs 60000
        $sub = $null
        foreach ($line in ($peek.text -split "`r?`n")) {
            if ($line -match '^\s+(\d+)\.\s+(.+?)\s*$' -and $Matches[2] -like "*$want*") { $sub = $Matches[1]; break }
        }
    }

    $lines = @()
    if ($no -gt 0) {
        $lines += $Lead
        $lines += "$no"
        if ($null -ne $sub) { $lines += $sub }
        if ($s.approve) { $lines += "예" }
        # 빈 줄 둘 — 하나는 작업 뒤 *"Enter 를 누르면 메뉴로 돌아갑니다."* 가, 하나는 두 번째
        # 메뉴가 받아 그만두기가 된다. 진짜 콘솔은 줄이 떨어져도 EOF 가 오지 않으므로 하나만
        # 넣으면 두 번째 메뉴가 끝없이 기다린다(2026-11-06 — 작업 열여섯이 다 시간 초과).
        $lines += ""
        $lines += ""
    }

    $run = $null
    if ($no -gt 0) { $run = Invoke-MenuRun -Lines $lines -TimeoutMs $s.timeout }
    $after = Get-Snapshot

    $sub_count = $null
    if ($null -ne $run) {
        if ($run.text -match "어느 작업입니까\?\s*\((\d+)건\)")  { $sub_count = [int]$Matches[1] }
        if ($run.text -match "어느 파일입니까\?\s*\((\d+)개\)")  { $sub_count = [int]$Matches[1] }
    }

    $row = [ordered]@{
        key        = $s.key
        needle     = $s.needle
        number     = $no
        lines      = $lines
        found      = ($no -gt 0)
        exit       = $(if ($null -ne $run) { $run.exit } else { $null })
        expect     = $s.expect
        timed_out  = $(if ($null -ne $run) { $run.timed_out } else { $true })
        menu_shown = $(if ($null -ne $run) { [bool]($run.text -match "무엇을 할까요") } else { $false })
        # 작업 뒤 메뉴로 돌아왔는가 — "메뉴로 돌아갑니다" 가 있고 메뉴가 두 번 떴다(기준 4(a)).
        # 마지막 빈 줄은 두 번째 메뉴에서 그만두기가 되어 회차를 끝낸다(그 앞 줄은 멈춤이 받는다).
        back_menu  = $(if ($null -ne $run) { [bool]($run.text -match "메뉴로 돌아갑니다") -and ([regex]::Matches($run.text, "무엇을 할까요").Count -ge 2) } else { $false })
        asked_sub  = $sub_count
        approved   = $(if ($null -ne $run) { [bool]($run.text -match "진행하려면") } else { $false })
        before     = $before
        after      = $after
        interrupt  = $interrupt
        left_after = $(if ($null -ne $interrupt) { @(Get-ChildItem "C:\remedy-lab\resume" -Filter "target-*.dat").Count } else { $null })
        ok         = $false
    }
    $row.ok = ($row.found -and (-not $row.timed_out) -and $row.menu_shown -and $row.back_menu -and ($row.exit -eq $s.expect))
    # 이어 하기는 **끊긴 채 시작해서**(남은 대상이 있었다) **다 끝나야**(남은 대상 0) 끝까지 돈 것이다.
    if ($null -ne $interrupt) {
        $row.ok = $row.ok -and ($interrupt.seen -eq "action") -and ($interrupt.left -gt 0) -and ($row.left_after -eq 0)
    }
    $results.Add([pscustomobject]$row)

    $tr.Add("")
    $tr.Add("=== $($s.key) — 메뉴 $no 번 ($($s.needle)) ===")
    if ($null -ne $run) { $tr.Add($run.text.TrimEnd()) } else { $tr.Add("[메뉴에 그 줄이 없었다]") }
}
} catch {
    $failure = $_.Exception.GetType().FullName + " | " + $_.Exception.Message +
               " | STACK " + $_.ScriptStackTrace
}

# **`@($results)` 로 감싸면 안 된다.** `List[object]` 를 `@()` 로 감싸 ordered
# 사전에 대입하면 PowerShell 5.1 이 `ArgumentException: Argument types do not
# match` 를 던진다 — 값의 내용과 무관하고, `$results` 그대로나 `ToArray()` 는
# 통과한다 (2026-10-29 에 호스트에서 좁혀 쟀다). 그날 첫 회차는 다섯 작업을
# 전부 돌린 **뒤** 이 한 줄에서 죽어 결과를 통째로 잃었다.
$report.steps = $results.ToArray()
$report.error = $failure
$report.verdict = (
    ($null -eq $failure) -and
    ($results.Count -eq $steps.Count) -and
    ($report.probe.shown) -and
    ($report.probe.exit -eq 0) -and
    (@($results | Where-Object { -not $_.ok }).Count -eq 0)
)

$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
# JSON 은 BOM 없이 쓴다 — 대부분의 파서가 BOM 을 거부한다.
[System.IO.File]::WriteAllText($OutFile, ($report | ConvertTo-Json -Depth 8),
                               (New-Object System.Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText($TranscriptFile, ($tr -join "`r`n"),
                               (New-Object System.Text.UTF8Encoding($false)))
if ((Get-Item $OutFile).Length -eq 0) { throw "결과 파일이 비었다: $OutFile" }
exit 0
