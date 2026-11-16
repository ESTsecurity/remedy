#Requires -Version 5.1
<#
.SYNOPSIS
    긴 랩 일(콘솔 재캡처 · rc 묶음 · 벤치마크)과 나란히 커밋 여유를 15초마다 잰다 — 기준 아래로 떨어지면 곧바로 끝나 알린다.

.DESCRIPTION
    이 기계의 커밋 한도가 바닥나면 링커가 죽고(LNK1102) Windows 사용자 서비스와 WSL 의 Windows 드라이브 연결까지
    끊긴다(`docs/개발-안내.md` "무거운 빌드를 겹치지 않는다"). **시작할 때 잰 여유로는 막지 못한다** — 켜진 랩 VM 을
    되돌려 다시 켜는 순간처럼 도중에 떨어진다(2026-11-16 실측 15.1 → 7.0 GB). 그래서 일과 나란히 띄워 둔다.

    잰 값(시각 · 여유 GB)은 -Out 에 한 줄씩 쌓는다. 감시하는 기록 파일(-Log)에 `DONE` 이 들어 있으면 끝나고(종료 0),
    여유가 -MinGB 아래면 곧바로 끝난다(종료 3). **끝 표지는 일의 기록 파일 안에** 쓴다 — 도구의 출력으로만 내면 이
    감시는 끝을 모른다:

        <일> 2>&1 | Out-File -Encoding utf8 <기록>; "DONE exit=$LASTEXITCODE" | Out-File -Append -Encoding utf8 <기록>

    기록 파일은 쓰는 쪽을 막지 않게 읽기 공유를 열어 둔 채 잠깐 열었다 닫는다(덧붙여 쓰는 파일을 붙잡아 두면 쓰는
    쪽이 막힌다). 여유는 `Win32_OperatingSystem` 의 `FreeVirtualMemory` — 커밋 한도까지 남은 양이다.

.EXAMPLE
    .\testbed\harness\host\Watch-CommitHeadroom.ps1 -Log D:\dl\rc-win.log -Out D:\dl\headroom-rc-win.txt
#>
param(
    [Parameter(Mandatory = $true)][string] $Log,
    [Parameter(Mandatory = $true)][string] $Out,
    [double] $MinGB = 6
)
$ErrorActionPreference = 'Stop'
$intervalSec = 15

function Test-DoneMarker([string] $path) {
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    try {
        $fs = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        try {
            $reader = New-Object System.IO.StreamReader($fs)
            return $reader.ReadToEnd().Contains('DONE')
        } finally { $fs.Dispose() }
    } catch [System.IO.IOException] {
        return $false
    }
}

[System.IO.File]::WriteAllText($Out, '')
$lowest = [double]::MaxValue
while ($true) {
    $gb = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreeVirtualMemory / 1MB, 1)
    [System.IO.File]::AppendAllText($Out, ('{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $gb) + "`n")
    if ($gb -lt $lowest) { $lowest = $gb }
    if ($gb -lt $MinGB) {
        "LOW $gb GB — 여유가 $MinGB GB 아래다 (최저 $lowest GB)"
        exit 3
    }
    if (Test-DoneMarker $Log) {
        "DONE — 최저 $lowest GB"
        exit 0
    }
    Start-Sleep -Seconds $intervalSec
}
