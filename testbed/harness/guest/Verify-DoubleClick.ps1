#Requires -Version 5.1
<#
.SYNOPSIS
    더블클릭한 사람이 화면을 읽을 수 있는가 — **진짜 콘솔**에서 확인한다 (Phase 4-1).

.DESCRIPTION
    탐색기에서 더블클릭하면 OS 가 콘솔 창을 만들어 붙이고 **프로세스가 끝나면 그
    창을 없앤다.** 인자 없이 사용법만 찍고 반환하던 동안 화면은 검은 깜빡임 한
    번이었다.

    그 상황은 **stdin 이 진짜 콘솔**이라야 재현된다. WinRM 세션에는 콘솔이 없고,
    `RedirectStandardInput` 을 쓰면 `is_terminal()` 이 거짓이 되어 기다리는 경로가
    통째로 시험 밖에 남는다 — `Approve-Interactive.ps1` 이 승인 흐름을 재려고
    풀었던 것과 같은 문제이고, 같은 방법(`AllocConsole` + `WriteConsoleInput`)으로
    푼다.

    두 가지를 잰다.
      1. 인자 없이 띄우면 **기다린다** (Enter 를 보내기 전에는 끝나지 않는다)
      2. Enter 를 보내면 **끝나고 종료 코드가 0 이다**
    그리고 반대 방향도 잰다.
      3. 인자가 있으면(`--version`) 진짜 콘솔에서도 **기다리지 않는다**
         — RunOnce 의 재부팅 회차가 이 조건이다. 여기서 기다리면 재시작 뒤
         창이 영원히 떠 있는다.

    **이 스크립트가 별도 프로세스인 이유**는 `Approve-Interactive.ps1` 과 같다 —
    `AllocConsole` 이 표준 핸들을 갈아 끼우고, 되돌려도 PowerShell 호스트가 화면
    버퍼를 다시 잡지 못해 이후 `Write-Host` 가 죽는다. 그래서 결과를 화면이
    아니라 JSON 파일로 낸다.

.PARAMETER Bin
    시험할 remedy.exe.

.PARAMETER OutFile
    결과 JSON. BOM 없이 쓴다.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $OutFile
)

$ErrorActionPreference = "Stop"

Add-Type -Namespace RemedyLab -Name DblClick -MemberDefinition @'
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
// `Approve-Interactive.ps1` 의 같은 함수를 그대로 쓴다. 그 주석이 적은 함정을
// 이 스크립트를 쓰면서 실제로 밟았다 — `SetStdHandle` 없이 `AllocConsole` 만
// 부르면 자식이 상위의 stdin(널 장치)을 그대로 물려받아 `is_terminal()` 이
// 거짓이 되고, **기다리는 경로를 재지 못한 채 시험이 통과한다.**
//
// 순서도 그대로다. 먼저 `CONIN$` 를 열어 본다 — 그것이 "콘솔에 붙어 있는가" 의
// 진짜 답이다. `GetConsoleWindow` 로 물으면 창 없는 콘솔에서 거짓말을 한다.
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

// 콘솔 입력 버퍼에 Enter 한 번. 콘솔은 줄 입력 모드라 개행까지 와야
// ReadConsoleW 가 돌아간다. 음수는 실패다.
public static int PressEnter() {
    IntPtr conin = CreateFileW("CONIN$", 0xC0000000u, 3u, IntPtr.Zero, 3u, 0u, IntPtr.Zero);
    if (conin == new IntPtr(-1)) return -1;
    INPUT_RECORD[] recs = new INPUT_RECORD[2];
    for (int d = 0; d < 2; d++) {
        recs[d].EventType = 1; // KEY_EVENT
        recs[d].KeyEvent.bKeyDown = (d == 0);
        recs[d].KeyEvent.wRepeatCount = 1;
        recs[d].KeyEvent.wVirtualKeyCode = 0x0D;
        recs[d].KeyEvent.UnicodeChar = (ushort)'\r';
    }
    uint written;
    bool ok = WriteConsoleInputW(conin, recs, (uint)recs.Length, out written);
    CloseHandle(conin);
    return ok ? (int)written : -2;
}
'@

$attach = [RemedyLab.DblClick]::EnsureConsoleStdin()
if ($attach -ne 0) { throw "콘솔 stdin 을 준비하지 못했다 (코드 $attach)" }

# **stdin 은 재지정하지 않는다.** 콘솔 핸들을 그대로 물려받아야 `is_terminal()` 이
# 참이 되고, 그래야 더블클릭 상황이 된다.
function Start-WithRealConsole {
    param([string[]] $Argv)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Bin
    $psi.Arguments = ($Argv -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
    [System.Diagnostics.Process]::Start($psi)
}

$results = [ordered]@{}

# ── 1·2. 인자 없이 — 기다리다가 Enter 를 받으면 끝난다 ──────────
$p = Start-WithRealConsole @()
$o = $p.StandardOutput.ReadToEndAsync()
$e = $p.StandardError.ReadToEndAsync()
# 사용법을 다 찍고 프롬프트에 설 때까지. 사용법은 30줄 남짓이라 넉넉하다.
Start-Sleep -Milliseconds 1500
$waited = -not $p.HasExited
$typed = if ($waited) { [RemedyLab.DblClick]::PressEnter() } else { 0 }
$closed = $p.WaitForExit(15000)
if (-not $closed) { try { $p.Kill() } catch { }; $p.WaitForExit() }
$text = $o.Result + $e.Result
$results["no_args"] = [ordered]@{
    waited    = $waited            # Enter 전에 살아 있었는가 — 이것이 핵심이다
    typed     = $typed
    closed    = $closed
    exit      = $p.ExitCode
    prompted  = [bool]($text -match "Enter 를 누르십시오|Press Enter to close")
    usage     = [bool]($text -match "사용법|Usage")
    text_tail = ($text -split "`r?`n" | Where-Object { $_.Trim() -ne '' } | Select-Object -Last 3) -join " / "
}

# ── 3. 인자가 있으면 기다리지 않는다 (RunOnce 가 이 조건이다) ────
$p2 = Start-WithRealConsole @("--version")
$o2 = $p2.StandardOutput.ReadToEndAsync()
$e2 = $p2.StandardError.ReadToEndAsync()
$done2 = $p2.WaitForExit(15000)
if (-not $done2) { try { $p2.Kill() } catch { }; $p2.WaitForExit() }
$results["with_args"] = [ordered]@{
    finished_without_input = $done2   # Enter 를 보내지 않았는데 끝났는가
    exit                   = $p2.ExitCode
    prompted               = [bool](($o2.Result + $e2.Result) -match "Enter 를 누르십시오|Press Enter to close")
}

$results["verdict"] = (
    $results["no_args"].waited -and
    $results["no_args"].closed -and
    $results["no_args"].exit -eq 0 -and
    $results["no_args"].prompted -and
    $results["with_args"].finished_without_input -and
    -not $results["with_args"].prompted
)

# JSON 은 BOM 없이 쓴다 — serde_json 등 대부분의 파서가 BOM 을 거부한다.
$json = $results | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))
if ((Get-Item $OutFile).Length -eq 0) { throw "결과 파일이 비었다: $OutFile" }
