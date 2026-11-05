<#
.SYNOPSIS
    프로그램을 **진짜 터미널 창**에 띄우고, 정한 차례대로 키를 넣으며 그 창을 PNG 로
    남긴다 (목표 remedy_제품화 기준 10).

.DESCRIPTION
    지금까지의 콘솔 하네스는 WinRM 세션 안에서 `AllocConsole` 로 콘솔을 만든다
    (`Approve-Interactive.ps1`). 그 콘솔은 대화형 데스크톱에 없어서 **그려지지
    않는다** — 글자는 잴 수 있어도 사람이 보는 화면은 잴 수 없다.

    그래서 이 스크립트는 **로그온한 사용자의 대화형 세션에서** 돈다. 호스트가
    `LogonType Interactive` 예약 작업으로 부르고(`host\Invoke-ScreenShot.ps1`),
    결과는 파일로 남긴다 — 예약 작업은 출력을 돌려주지 않는다.

    차례(`-Steps`)는 `|` 로 이은 글자 하나다 — 예약 작업은 `powershell -File` 로
    부르는데, 그 모드에서는 쉼표로 이은 값이 배열이 되지 않고 글자 하나로 온다.
    말은 셋이다.
      shot:<이름>  지금 창을 찍는다 — `<이름>.png`
      type:<글자>  글자를 치고 Enter. 빈 글자면 Enter 하나다 — 줄 입력 모드라
                   Enter 까지 와야 읽힌다
      wait:<ms>    기다린다
      relaunch:<인자>  띄운 것을 닫고 같은 프로그램을 새 창에 다시 띄운다. 인자가
                   비면 처음 인자 그대로다 — 앞 작업이 남긴 회차를 다음 화면이 읽는다

    키는 그 프로그램의 콘솔에 **붙어서** `WriteConsoleInput` 으로 넣는다
    (`Verify-Menu.ps1` 의 `TypeLine` 과 같은 기록). 창이 앞에 있을 필요가 없고,
    Windows Terminal 안의 프로그램(ConPTY)에도 같은 길로 닿는다.

.PARAMETER Terminal
    conhost — 탐색기에서 더블클릭한 것과 같은 새 콘솔 창.
    wt      — Windows Terminal(`-WtExe` 의 `WindowsTerminal.exe`) 의 새 창.

.PARAMETER Method
    print  — `PrintWindow(PW_RENDERFULLCONTENT)`. 창이 가려져도 창 스스로 그린다.
    screen — `CopyFromScreen`. 화면에 보이는 그대로라 다른 창이 덮으면 그것이 찍힌다.
    콘솔 호스트에서는 둘이 커서 말고 같았다(2026-11-05 실측).
#>
param(
    [Parameter(Mandatory = $true)] [string] $Exe,
    [string] $Arguments = "",
    [Parameter(Mandatory = $true)] [string] $OutDir,
    [ValidateSet("conhost", "wt")] [string] $Terminal = "conhost",
    [string] $WtExe,
    [string] $Steps = "shot:screen",
    [int] $SettleMs = 2500,
    [ValidateSet("print", "screen")] [string] $Method = "print"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Shot {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    public delegate bool EnumProc(IntPtr h, IntPtr l);

    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int attr, out RECT r, int size);

    // 콘솔 창은 conhost 가 그리지만, 창의 주인 프로세스는 콘솔에 붙은 프로그램으로
    // 보고된다. 그래서 띄운 프로그램의 PID 와 창 종류로 찾는다.
    public static IntPtr FindWindowOf(uint pid, string cls) {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate (IntPtr h, IntPtr l) {
            uint p;
            GetWindowThreadProcessId(h, out p);
            if (p != pid || !IsWindowVisible(h)) return true;
            StringBuilder sb = new StringBuilder(256);
            GetClassName(h, sb, sb.Capacity);
            if (sb.ToString() == cls) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    public static string Title(IntPtr h) {
        StringBuilder sb = new StringBuilder(512);
        GetWindowText(h, sb, sb.Capacity);
        return sb.ToString();
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEY_EVENT_RECORD {
        [MarshalAs(UnmanagedType.Bool)] public bool bKeyDown;
        public ushort wRepeatCount;
        public ushort wVirtualKeyCode;
        public ushort wVirtualScanCode;
        public ushort UnicodeChar;
        public uint dwControlKeyState;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT_RECORD {
        public ushort EventType;
        public KEY_EVENT_RECORD KeyEvent;
    }
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr templ);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteConsoleInputW(IntPtr h, INPUT_RECORD[] recs, uint n, out uint written);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr h);

    // 그 프로그램의 콘솔에 붙어 한 줄을 키로 넣고 떨어진다. 음수는 실패다.
    // 이 프로세스의 원래 콘솔(숨긴 창)은 버린다 — 이 스크립트는 콘솔에 쓰지 않는다.
    public static int TypeInto(uint pid, string text) {
        FreeConsole();
        if (!AttachConsole(pid)) return -(1000 + Marshal.GetLastWin32Error());
        try {
            IntPtr conin = CreateFileW("CONIN$", 0xC0000000u, 3u, IntPtr.Zero, 3u, 0u, IntPtr.Zero);
            if (conin == new IntPtr(-1)) return -(2000 + Marshal.GetLastWin32Error());
            string all = text + (char)13;
            INPUT_RECORD[] recs = new INPUT_RECORD[all.Length * 2];
            for (int i = 0; i < all.Length; i++) {
                for (int d = 0; d < 2; d++) {
                    int k = i * 2 + d;
                    recs[k].EventType = 1;
                    recs[k].KeyEvent.bKeyDown = (d == 0);
                    recs[k].KeyEvent.wRepeatCount = 1;
                    recs[k].KeyEvent.wVirtualKeyCode = (all[i] == (char)13) ? (ushort)0x0D : (ushort)0;
                    recs[k].KeyEvent.UnicodeChar = (ushort)all[i];
                }
            }
            uint written;
            bool ok = WriteConsoleInputW(conin, recs, (uint)recs.Length, out written);
            CloseHandle(conin);
            return ok ? (int)written : -(3000 + Marshal.GetLastWin32Error());
        } finally {
            FreeConsole();
        }
    }
}
'@

# 화면 배율이 100% 가 아니면 DPI 를 모르는 프로세스는 좌표를 가상으로 받는다 —
# 그러면 `CopyFromScreen` 이 엉뚱한 자리를 찍는다.
[void][Shot]::SetProcessDPIAware()

# 찍은 그림이 한 가지 색뿐이면 아무것도 찍히지 않은 것이다(검정 · 흰 판).
function Test-Blank {
    param([System.Drawing.Bitmap] $Bmp)
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    for ($y = 0; $y -lt $Bmp.Height; $y += [Math]::Max(1, [int]($Bmp.Height / 24))) {
        for ($x = 0; $x -lt $Bmp.Width; $x += [Math]::Max(1, [int]($Bmp.Width / 24))) {
            [void]$seen.Add($Bmp.GetPixel($x, $y).ToArgb())
        }
    }
    return ($seen.Count -le 1)
}

function Save-Window {
    param([IntPtr] $Hwnd, [string] $Path)
    [void][Shot]::SetForegroundWindow($Hwnd)
    Start-Sleep -Milliseconds 300
    # 창 테두리 밖의 보이지 않는 여백을 빼려고 DWM 의 실제 경계를 쓴다(속성 9).
    $win = New-Object Shot+RECT
    [void][Shot]::GetWindowRect($Hwnd, [ref]$win)
    $vis = New-Object Shot+RECT
    if ([Shot]::DwmGetWindowAttribute($Hwnd, 9, [ref]$vis, 16) -ne 0) { $vis = $win }
    $w = $vis.Right - $vis.Left
    $h = $vis.Bottom - $vis.Top
    if ($Method -eq "print") {
        $full = New-Object System.Drawing.Bitmap ($win.Right - $win.Left), ($win.Bottom - $win.Top)
        $g = [System.Drawing.Graphics]::FromImage($full)
        $hdc = $g.GetHdc()
        [void][Shot]::PrintWindow($Hwnd, $hdc, 2)
        $g.ReleaseHdc($hdc)
        $g.Dispose()
        $area = New-Object System.Drawing.Rectangle ($vis.Left - $win.Left), ($vis.Top - $win.Top), $w, $h
        $bmp = $full.Clone($area, $full.PixelFormat)
        $full.Dispose()
    } else {
        $bmp = New-Object System.Drawing.Bitmap $w, $h
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($vis.Left, $vis.Top, 0, 0, $bmp.Size)
        $g.Dispose()
    }
    $blank = Test-Blank $bmp
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return [ordered]@{ file = (Split-Path -Leaf $Path); size = "${w}x${h}"; blank = $blank; title = [Shot]::Title($Hwnd) }
}

# 띄운 프로그램을 PID 로 기다린다. Windows Terminal 안에서는 그 프로그램이
# 터미널의 자식(ConPTY)으로 따로 뜨므로 이름으로 찾는다.
function Find-NamedProcess {
    param([string] $ProcName, [int] $Seconds = 15)
    $until = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $until) {
        $p = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)[0]
        if ($p) { return $p }
        Start-Sleep -Milliseconds 200
    }
    return $null
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$report = [ordered]@{
    schema     = "remedy-lab.capture-window/2"
    exe        = $Exe
    args       = $Arguments
    terminal   = $Terminal
    method     = $Method
    user       = $me.Name
    elevated   = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    session_id = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    steps      = @()
}
$started = New-Object System.Collections.Generic.List[object]

# 새 창에 띄우고 그 창을 찾는다. 돌려주는 것은 키를 받을 프로그램 · 창을 가진
# 프로세스 · 창 핸들이다 — 콘솔 호스트에서는 앞의 둘이 같다.
function Start-Target {
    param([string] $ArgLine)
    $procName = [IO.Path]::GetFileNameWithoutExtension($Exe)
    if ($Terminal -eq "conhost") {
        $start = @{ FilePath = $Exe; PassThru = $true; WorkingDirectory = (Split-Path -Parent $Exe) }
        if ($ArgLine) { $start.ArgumentList = $ArgLine }
        $target = Start-Process @start
        $started.Add($target)
        $owner = $target
        $cls = "ConsoleWindowClass"
    } else {
        if (-not $WtExe -or -not (Test-Path $WtExe)) { throw "Windows Terminal 이 없다: $WtExe" }
        # `-d` 는 시작 폴더, 그 뒤가 띄울 명령줄이다. `;` 는 WT 의 명령 구분자라 쓰지 않는다.
        $line = "-d `"$(Split-Path -Parent $Exe)`" `"$Exe`""
        if ($ArgLine) { $line += " $ArgLine" }
        $owner = Start-Process -FilePath $WtExe -ArgumentList $line -PassThru
        $started.Add($owner)
        $target = Find-NamedProcess -ProcName $procName
        if (-not $target) { throw "Windows Terminal 안에서 $procName 이 뜨지 않았다" }
        $started.Add($target)
        $cls = "CASCADIA_HOSTING_WINDOW_CLASS"
    }
    $hwnd = [IntPtr]::Zero
    $until = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $until -and $hwnd -eq [IntPtr]::Zero) {
        Start-Sleep -Milliseconds 200
        if ($target.HasExited) { throw "프로그램이 창을 찍기 전에 끝났다 (exit $($target.ExitCode))" }
        $hwnd = [Shot]::FindWindowOf([uint32]$owner.Id, $cls)
    }
    if ($hwnd -eq [IntPtr]::Zero) { throw "15초 안에 창을 찾지 못했다 (pid $($owner.Id) · $cls)" }
    Start-Sleep -Milliseconds $SettleMs
    return @{ Target = $target; Hwnd = $hwnd }
}

function Stop-Started {
    foreach ($p in $started) { if ($p -and -not $p.HasExited) { try { $p.Kill() } catch { } } }
    $started.Clear()
}

try {
    $t = Start-Target $Arguments
    $target = $t.Target
    $hwnd = $t.Hwnd

    foreach ($step in $Steps.Split("|")) {
        $verb, $arg = $step.Split(":", 2)
        $rec = [ordered]@{ step = $step }
        switch ($verb) {
            "shot" { $rec.shot = Save-Window -Hwnd $hwnd -Path (Join-Path $OutDir "$arg.png") }
            "type" {
                $rec.written = [Shot]::TypeInto([uint32]$target.Id, [string]$arg)
                if ($rec.written -lt 0) { throw "키를 넣지 못했다 ($step · $($rec.written))" }
            }
            "wait" { Start-Sleep -Milliseconds ([int]$arg) }
            "relaunch" {
                Stop-Started
                Start-Sleep -Milliseconds 500
                $t = Start-Target $(if ($arg) { $arg } else { $Arguments })
                $target = $t.Target
                $hwnd = $t.Hwnd
            }
            default { throw "모르는 차례: $step" }
        }
        $rec.exited = $target.HasExited
        $report.steps += $rec
    }
} catch {
    $report.error = $_.Exception.Message
} finally {
    # 띄운 프로그램은 Enter 를 기다린다 — 남겨 두면 다음 회차의 배포가 막힌다.
    Stop-Started
    $json = $report | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText((Join-Path $OutDir "result.json"), $json, (New-Object System.Text.UTF8Encoding $false))
}
