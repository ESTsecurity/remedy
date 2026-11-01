#Requires -Version 5.1
<#
.SYNOPSIS
    **특권을 전부 끈 채** remedy 를 띄운다 — 접근 거부 갈래를 재는 자리.

.DESCRIPTION
    `denied_dirs` 를 일으키려면 remedy 의 `read_dir` 이 실제로 거부당해야 한다.
    그런데 랩의 관리자 토큰은 두 가지로 ACL 을 지나간다.

      1. **소유권** — 폴더의 소유자가 `BUILTIN\Administrators` 면 그 그룹의
         계정은 DACL 에 허용이 하나도 없어도 연다
      2. **특권** — `SeBackupPrivilege` 등이 켜져 있으면 ACL 을 우회한다

    소유자는 하네스가 `icacls /setowner` 로 SYSTEM 에게 넘긴다. 남은 것이
    특권이고, 그것은 **토큰의 문제**라 프로세스 밖에서 손댈 수 없다. 그래서
    이 스크립트가 자기 토큰의 특권을 전부 끄고 remedy 를 **자식으로** 띄운다 —
    자식은 그 상태를 물려받는다(실측 2026-09-13).

    # 왜 부모 세션에서 끄지 않는가

    WinRM 세션은 프로세스를 재사용한다. 거기서 끄면 뒤이은 정리
    (`takeown`·`icacls`)가 `SeTakeOwnershipPrivilege` 를 잃어 실패한다.
    **끄는 범위를 이 프로세스 하나로 가둔다.**

.PARAMETER OutFile
    remedy 의 stdout+stderr 를 합쳐 적을 자리. 종료 코드는 이 스크립트의
    종료 코드로 나간다.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Bin,
    [Parameter(Mandatory = $true)][string] $Plugin,
    [Parameter(Mandatory = $true)][string] $OutDir,
    [Parameter(Mandatory = $true)][string] $StateDir,
    [Parameter(Mandatory = $true)][string] $OutFile
)

$ErrorActionPreference = "Continue"

$cs = @"
using System;
using System.Runtime.InteropServices;
public class RemedyPriv {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr tok, bool disableAll,
        IntPtr newState, uint len, IntPtr prev, IntPtr retLen);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    // TOKEN_ADJUST_PRIVILEGES(0x20) | TOKEN_QUERY(0x8)
    public static string DisableAll() {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out tok))
            return "토큰을 열지 못했다 " + Marshal.GetLastWin32Error();
        if (!AdjustTokenPrivileges(tok, true, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero))
            return "특권을 끄지 못했다 " + Marshal.GetLastWin32Error();
        return "ok";
    }
}
"@
Add-Type -TypeDefinition $cs -Language CSharp

$why = [RemedyPriv]::DisableAll()
$left = @(& whoami /priv 2>&1 | Select-String "사용$|Enabled$").Count
if ($why -ne "ok" -or $left -ne 0) {
    # **끄지 못했으면 재지 않는다.** 특권이 남은 채 돌면 거부가 걸리지 않고,
    # 그 회차는 "통과" 처럼 보이면서 아무것도 재지 못한다.
    [System.IO.File]::WriteAllText($OutFile,
        "[특권을 끄지 못했다] $why · 남은 활성 특권 $left 개",
        (New-Object System.Text.UTF8Encoding($false)))
    exit 90
}

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Bin
$psi.Arguments = ('scan --plugin "{0}" --out-dir "{1}" --state-dir "{2}"' -f $Plugin, $OutDir, $StateDir)
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.RedirectStandardInput = $true
$psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
$psi.EnvironmentVariables["REMEDY_LANG"] = "ko"
$p = [System.Diagnostics.Process]::Start($psi)
$p.StandardInput.Close()
$o = $p.StandardOutput.ReadToEndAsync()
$e = $p.StandardError.ReadToEndAsync()
$p.WaitForExit(600000) | Out-Null
[System.IO.File]::WriteAllText($OutFile, ($o.Result + $e.Result).TrimEnd(),
    (New-Object System.Text.UTF8Encoding($false)))
exit $p.ExitCode
