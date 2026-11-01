#Requires -Version 5.1
<#
.SYNOPSIS
    대화형 승인 흐름을 **진짜 콘솔**에서 확인한다 (설계-09 P6).

.DESCRIPTION
    `apply` 는 `--yes` 가 없으면 stdin 이 터미널인지 본다. WinRM 세션에는 콘솔이
    없으므로 그 경로에서는 언제나 "승인할 사람이 없습니다"로 거절되고, **예/아니오
    응답 경로가 통째로 시험 밖에 남는다.**

    그래서 여기서 `AllocConsole` 로 콘솔을 만들고, 그것을 물려받은 remedy 에게
    `WriteConsoleInput` 으로 키 입력을 밀어 넣는다. 실측으로 WinRM 세션(콘솔
    없음, 대화형 데스크톱 없음)에서도 `AllocConsole` 이 성공하고 remedy 가
    실제로 질문을 띄웠다.

    **이 스크립트가 별도 프로세스인 이유가 그것이다.** `AllocConsole` 은 프로세스의
    표준 핸들을 갈아 끼우고, 되돌려도 PowerShell 의 호스트는 콘솔 화면 버퍼를
    다시 잡지 못해 이후 `Write-Host` 가 "핸들이 잘못되었습니다"로 죽는다.
    한 프로세스 안에서 하면 그 뒤의 로그가 통째로 사라진다.

    그래서 이 스크립트는 **결과를 화면이 아니라 JSON 파일로** 낸다.

.PARAMETER PlanNo
    '아니오' 로 답할 계획. 대상이 남아 있어야 한다.

.PARAMETER PlanYes
    '예' 로 답할 계획. 대상이 사라져야 한다.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $PlanNo,
    [Parameter(Mandatory = $true)][string] $PlanYes,
    [Parameter(Mandatory = $true)][string] $StateNo,
    [Parameter(Mandatory = $true)][string] $StateYes,
    # 두 계획이 겨누는 대상의 목록 파일(한 줄에 하나). **남았는지 여기서 센다** —
    # 두 실행이 같은 대상을 쓰므로, 부모가 나중에 세면 '아니오' 직후가 아니라
    # '예' 직후를 보게 된다.
    #
    # 배열이 아니라 파일로 받는 이유: `powershell.exe -File` 은 인자를 위치
    # 인자로 하나씩 넘기므로 배열의 두 번째 원소부터 엉뚱한 자리로 들어간다.
    [Parameter(Mandatory = $true)][string] $TargetsFile,
    [Parameter(Mandatory = $true)][string] $OutFile
)

$ErrorActionPreference = "Stop"

Add-Type -Namespace RemedyLab -Name Con -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool AllocConsole();
[DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetConsoleWindow();
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
// 순서가 중요하다. 먼저 `CONIN$` 를 열어 본다 — 그것이 "콘솔에 붙어 있는가"의
// 진짜 답이다. `GetConsoleWindow` 로 물으면 창 없는 콘솔에서 거짓말을 하고,
// `AllocConsole` 부터 부르면 이미 붙어 있을 때 실패한다. 실측으로 상위가 콘솔을
// 물려준 환경에서 그 두 방식이 모두 어긋났다.
//
// stdin 이 콘솔이라는 것까지 확인해야 한다. 상위가 파이프로 넘겨 준 stdin 을
// 그대로 물려주면 remedy 는 "터미널이 아니다"로 거절하고, 그러면 이 시험은
// 승인 경로를 재지 못한 채 통과한다.
//
// 실패 코드에 Win32 오류를 실어 보낸다. "왜 안 되는가" 를 다음 사람이 다시
// 알아내지 않게 한다.
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

// 한 줄을 키 입력으로 밀어 넣는다. 콘솔은 줄 입력 모드라 개행까지 와야
// ReadConsoleW 가 돌아간다. 음수는 실패다.
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

function Invoke-Interactive {
    param([string] $Plan, [string] $StateDir, [string] $Answer)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Bin
    $psi.Arguments = (@("apply", "--plan", $Plan, "--state-dir", $StateDir) |
        ForEach-Object { if ($_ -match '[\s"]') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false
    # **stdin 은 재지정하지 않는다.** 콘솔 핸들을 그대로 물려받아야
    # `is_terminal()` 이 참이 되고, 그래야 승인 질문이 나온다.
    $psi.RedirectStandardInput = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    Start-Sleep -Milliseconds 500          # 질문이 뜰 때까지
    $typed = [RemedyLab.Con]::TypeLine($Answer)
    $done = $p.WaitForExit(20000)
    if (-not $done) { try { $p.Kill() } catch { }; $p.WaitForExit() }
    $text = $o.Result + $e.Result
    [ordered]@{
        answer    = $Answer
        exit      = $p.ExitCode
        typed     = $typed
        timed_out = (-not $done)
        prompted  = [bool]($text -match "진행하려면")
        refused   = [bool]($text -match "승인할 사람이 없습니다")
        text      = $text
    }
}

# 여기서부터 화면에 쓰지 않는다 — 콘솔을 갈아 끼운 뒤의 Write-Host 는 죽는다.
$rc = [RemedyLab.Con]::EnsureConsoleStdin()

$targets = @([System.IO.File]::ReadAllLines($TargetsFile, [System.Text.Encoding]::UTF8) |
             Where-Object { $_.Trim().Length -gt 0 })
if ($targets.Count -eq 0) { throw "대상 목록이 비어 있다: $TargetsFile" }

function Get-RemainingCount {
    @($targets | Where-Object { Test-Path $_ }).Count
}

$report = [ordered]@{
    schema           = "remedy-lab.approve-interactive/1"
    console_rc       = $rc
    alloc_console    = ($rc -eq 0)
    targets          = $targets.Count
    remaining_before = Get-RemainingCount
    remaining_after_no  = $null
    remaining_after_yes = $null
    no               = $null
    yes              = $null
}
if ($rc -eq 0) {
    $report.no = Invoke-Interactive -Plan $PlanNo -StateDir $StateNo -Answer "아니오"
    $report.remaining_after_no = Get-RemainingCount
    $report.yes = Invoke-Interactive -Plan $PlanYes -StateDir $StateYes -Answer "예"
    $report.remaining_after_yes = Get-RemainingCount
}

$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
[System.IO.File]::WriteAllText($OutFile, ($report | ConvertTo-Json -Depth 6),
                               (New-Object System.Text.UTF8Encoding($false)))
exit 0
