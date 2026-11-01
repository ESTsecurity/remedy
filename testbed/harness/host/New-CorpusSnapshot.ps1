#Requires -Version 5.1
<#
.SYNOPSIS
    청정 환경 스냅샷을 떠서 `corpus/clean/` 에 넣는다 (설계-04 §3.2).

.DESCRIPTION
    `corpus/clean/` 에 쌓이는 아티팩트 스냅샷이 **오탐 방지의 실질적 사거리**다.
    VM 이미지로는 몇 개밖에 못 돌리지만 스냅샷은 CI 에서 매 커밋 돌아간다.

    이 스크립트가 존재하는 이유는 **스크러빙 하나**다. 손으로 뜨면 언젠가
    빠뜨리고, 그러면 기계 이름과 실행 시각이 저장소에 그대로 실린다. 여기서는
    빠뜨릴 수 없다.

    | 지우는 것 | 왜 |
    |---|---|
    | `host.hostname` | 어느 기계인지 |
    | `run_id` · `created` · `collected_at` | 언제 누가 돌렸는지 |

    **경로의 사용자 이름은 지우지 않는다.** `C:\Users\test\...` 의 `test` 는
    데이터의 일부이고, 지우면 경로 모양에 걸린 룰을 이 코퍼스로 검증할 수
    없게 된다. 그래서 **랩 기계에서만 뜬다** — 고객 기계 스냅샷은 여기 들어갈
    것이 아니다 (설계-00 §7).

.PARAMETER Label
    파일 이름 앞머리. 환경을 알아볼 수 있게 짓는다 — `win10x64-dev` 처럼
    "무엇이 설치된 기계인가" 가 드러나야 나중에 사거리를 셀 수 있다.

.PARAMETER Roots
    훑을 경로. 기본값은 첫 플러그인이 선언한 `scan_roots` 와 그 이웃이다.

.PARAMETER Plugin
    매니페스트를 주면 **그 선언대로** 수집한다 (경로도 subject 도 매니페스트가
    정하므로 `-Roots` 는 무시된다).

    이것이 없으면 진단 모드이고, 진단 모드는 `file` 과 `persistence` 만 모은다
    (`Scope::diagnostic`). 그래서 `autorun`·`process`·`av_exclusion` 을 보는
    룰은 **G1 이 태울 것이 아예 없다** — 코퍼스에 그 레코드가 한 건도 없기
    때문이다. 실측으로 드러났다 (설계-09 P9 준비 점검).

.EXAMPLE
    .\New-CorpusSnapshot.ps1 -Label win10x64-dev -Build

.EXAMPLE
    .\New-CorpusSnapshot.ps1 -Label win11-office -Roots 'C:\Program Files'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Label,
    [string] $VmAddress,
    [pscredential] $Credential,
    [switch] $SaveCredential,
    [string[]] $Roots = @(
        "C:\Program Files",
        "C:\Windows\System32\Tasks",
        "%LOCALAPPDATA%\Programs"
    ),
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

$triple  = "x86_64-pc-windows-msvc"
$binPath = Join-Path $repoRoot "target\$triple\release\remedy.exe"
$outDir  = Join-Path $repoRoot "corpus\clean"

if ($Build) {
    Write-Step "빌드: remedy.exe"
    Push-Location $repoRoot
    try {
        # **`$ErrorActionPreference` 를 잠시 놓는다.** cargo 는 진행 상황을
        # stderr 로 쓰는데, `Stop` 아래에서 네이티브 명령의 stderr 는 종료
        # 오류(NativeCommandError)가 되어 **컴파일 중에 스크립트가 죽는다.**
        # 판정은 종료 코드로 한다.
        # cargo 의 stderr 를 화면에 흘리지 않는다 — `Invoke-CargoBuild` 참고.
        # **실패하면 throw 다** — VM 에 아무것도 배포하지 않는다.
        Invoke-CargoBuild "remedy.exe" @("build", "--release", "--target", $triple, "-p", "remedy-cli")
    } finally { Pop-Location }
}
if (-not (Test-Path $binPath)) { throw "산출물이 없다: $binPath`n먼저 -Build 를 줄 것." }
Write-Ok "remedy.exe  $((Get-FileHash $binPath -Algorithm SHA256).Hash)"

# **배포 전에 본다.** VM 에는 UCRT 가 있어 동적 바이너리도 잘 돌므로 VM 이
# 알려주지 못한다. 여기서 막지 않으면 아무도 막지 않는다.
Assert-StaticBinary -RepoRoot $repoRoot -Path @($binPath)

# **스냅샷을 되돌리지 않는다.** 되돌리면 방금 설치한 것이 사라진다 — 이
# 스크립트는 "지금 이 기계의 모습" 을 뜨는 것이지 시험을 돌리는 것이 아니다.
$session = Connect-LabVm -VmAddress $VmAddress -Credential $Credential -SaveCredential:$SaveCredential

$MASK = "<코퍼스>"

try {
    # 게스트의 기계 이름. 스크러빙이 실제로 걸렸는지 대조할 것이 있어야 한다.
    $guestHost = Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME }
    Write-Ok "게스트: $guestHost"

    Invoke-Command -Session $session -ScriptBlock {
        param($root)
        foreach ($d in @("$root\bin", "$root\corpus")) {
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        }
    } -ArgumentList $LabRoot

    Write-Step "배포"
    Copy-Item $binPath -Destination "$LabRoot\bin\remedy.exe" -ToSession $session -Force

    # 플러그인 모드는 경로를 매니페스트가 정하므로 한 번만 돈다.
    if ($Plugin) {
        if (-not (Test-Path $Plugin)) { throw "매니페스트가 없다: $Plugin" }
        Copy-Item $Plugin -Destination "$LabRoot\corpus\plugin.yaml" -ToSession $session -Force
        Write-Ok "매니페스트 배포: $(Split-Path $Plugin -Leaf)"
        $Roots = @("<선언>")
    }

    $made = @()
    foreach ($root in $Roots) {
        # 이름은 경로 마지막 조각에서 만든다. `C:\Program Files` → `program-files`.
        if ($Plugin) {
            $slug = 'declared'
        } else {
            $leaf = ($root -replace '%', '') -split '\\' | Select-Object -Last 1
            $slug = ($leaf.ToLower() -replace '[^a-z0-9]+', '-').Trim('-')
        }
        $name = "$Label-$slug"
        $dest = Join-Path $outDir "$name.json.gz"
        if ((Test-Path $dest) -and -not $Force) {
            Write-Warn "이미 있다: $name.json.gz — 덮어쓰려면 -Force"
            continue
        }

        Write-Step ("수집: " + $(if ($Plugin) { "매니페스트 선언대로" } else { $root }))
        $guestOut = "$LabRoot\corpus\$name.json"
        $r = Invoke-Command -Session $session -ScriptBlock {
            param($bin, $root, $out, $manifest)
            # **`&` 의 stderr 를 종료 오류로 만들지 않는다.** remedy 는 주의를
            # stderr 로 쓰고, 원격 세션의 `Stop` 아래에서는 그것이 스크립트를
            # 죽인다 — 수집은 성공했는데 결과를 못 가져오는 자리가 된다.
            $prev = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                if ($manifest) {
                    $path = "(선언)"
                    $t = & $bin collect --out $out --plugin $manifest 2>&1 | Out-String
                } else {
                    $path = [Environment]::ExpandEnvironmentVariables($root)
                    if (-not (Test-Path $path)) { return @{ ok = $false; text = "경로가 없다: $path" } }
                    $t = & $bin collect --out $out --root $path 2>&1 | Out-String
                }
            } finally { $ErrorActionPreference = $prev }
            @{ ok = ($LASTEXITCODE -eq 0); text = $t; code = $LASTEXITCODE; path = $path }
        } -ArgumentList "$LabRoot\bin\remedy.exe", $root, $guestOut,
                        $(if ($Plugin) { "$LabRoot\corpus\plugin.yaml" } else { $null })

        if (-not $r.ok) { throw "수집 실패 ($root): $($r.text)" }
        Write-Ok ($r.text.Trim() -replace "\s+", " ")

        $tmp = Join-Path $env:TEMP "$name.json"
        Copy-Item "$guestOut" -Destination $tmp -FromSession $session -Force

        # ── 스크러빙 ────────────────────────────────────────────────
        #
        # **여기가 이 스크립트의 존재 이유다.** 아래 넷을 지우지 않으면 어느
        # 기계에서 언제 떴는지가 저장소에 남는다.
        $json = [System.IO.File]::ReadAllText($tmp, [System.Text.Encoding]::UTF8)
        $doc = $json | ConvertFrom-Json

        # ── '최근 문서' 자리는 레코드째 빼낸다 (2026-10-31) ─────────
        #
        # Windows 는 사용자가 연 문서의 바로가기를 `...\Microsoft\Windows\Recent\`
        # 에 쌓고, **그 파일 이름이 문서의 제목이다.** 사람이 쓰던 기계를 뜨면
        # 개인 서류의 제목이 이름 그대로 들어온다 (실측 110건). 어떤 문서를
        # 열었는지는 미리 알 수 없으므로 낱말이 아니라 **자리**로 뺀다.
        # `xtask/src/corpus.rs` 의 `drop_recent` 와 같은 규칙이고, 같이 `path`
        # 하나만 본다 — 실측에서 110건 전부 그 칸에 있었다.
        $recent = 0
        foreach ($prop in @($doc.PSObject.Properties)) {
            if ($prop.Value -isnot [object[]]) { continue }
            $all = @($prop.Value)
            $keep = @($all | Where-Object {
                $p = $_.path
                -not ($p -is [string] -and $p.Replace('/', '\') -ilike '*\microsoft\windows\recent\*')
            })
            if ($keep.Count -ne $all.Count) {
                $recent += $all.Count - $keep.Count
                $doc.($prop.Name) = $keep
            }
        }
        if ($recent -gt 0) { Write-Ok "'최근 문서' 자리 $recent 건을 빼냈다" }

        $before = @{}
        foreach ($k in @("file", "persistence", "security_products",
                         "autorun", "process", "av_exclusion")) {
            if ($doc.PSObject.Properties.Name -contains $k) { $before[$k] = @($doc.$k).Count }
        }
        $doc.host.hostname = $MASK
        foreach ($k in @("run_id", "created", "collected_at")) {
            if ($doc.PSObject.Properties.Name -contains $k) { $doc.$k = $MASK }
        }
        $clean = $doc | ConvertTo-Json -Depth 32 -Compress

        # ── 지웠는지, 그리고 **온전한지** 확인한다 ──────────────────
        #
        # 필드 이름이 바뀌면 위 대입이 조용히 아무것도 하지 않고, 그때 새는
        # 것이 정확히 지우려던 것이다. 그래서 **문자열이 아니라 다시 파싱해서**
        # 본다 — PS 5.1 의 `ConvertTo-Json` 은 한글을 `\uXXXX` 로 escape 하므로
        # 원문 대조는 걸리지 않는다 (실측).
        #
        # 레코드 수도 함께 본다. 왕복이 깊이 제한에 걸려 잘려도 문자열 검사는
        # 통과하기 때문이다.
        $check = $clean | ConvertFrom-Json
        if ($check.host.hostname -ne $MASK) { throw "스크러빙이 걸리지 않았다 ($name)" }
        foreach ($k in $before.Keys) {
            $now = @($check.$k).Count
            if ($now -ne $before[$k]) {
                throw "왕복에서 레코드가 바뀌었다 ($name): $k $($before[$k]) -> $now"
            }
        }
        # 게스트의 기계 이름이 본문 어디에도 남아서는 안 된다. 호스트가 아니라
        # **게스트** 이름이다 — 스냅샷은 게스트에서 떴다.
        if ($guestHost -and $clean -match [regex]::Escape($guestHost)) {
            throw "스크러빙 확인 실패: 게스트 이름 '$guestHost' 가 남아 있다 ($name)"
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
        Write-Ok "$name.json.gz  ${kb}KB (원본 $([math]::Round($bytes.Length / 1KB))KB)"
        $made += $name
    }
} finally {
    Remove-PSSession $session -ErrorAction SilentlyContinue
}

Write-Host ""
if ($made.Count -eq 0) {
    Write-Warn "새로 만든 것이 없다."
} else {
    Write-Ok ("새 스냅샷 " + $made.Count + "개: " + ($made -join " · "))
    Write-Host ""
    Write-Host "다음: cargo test -p remedy-core --test corpus   (G1)" -ForegroundColor Cyan
}
