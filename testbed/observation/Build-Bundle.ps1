<#
.SYNOPSIS
    관측 대상 AI 에게 줄 입력 묶음을 만든다.

.DESCRIPTION
    **이 목록이 곧 관측의 정의다.** 무엇을 줬는지가 고정되지 않으면 두 번의
    관측을 비교할 수 없고, 비교할 수 없으면 "가이드가 나아졌는가" 를 말할 수 없다.

    정답 스냅샷(`artifacts.json`)과 기대 계획(`expected-plan.json`)은 **넣지
    않는다.** 그것을 보면 룰을 그 스냅샷에 맞추게 되고, 그러면 "가이드만 보고
    썼는가" 가 아니라 "예시를 베꼈는가" 를 재게 된다.

.EXAMPLE
    .\Build-Bundle.ps1 -OutDir C:\obs\run-1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $OutDir
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# 이 목록을 늘리면 관측이 쉬워진다. 쉬워진 만큼 결과는 덜 말해 준다.
$files = @(
    "docs/plugin-guide/00-invariants.md"
    "docs/plugin-guide/01-quickstart.md"
    "docs/plugin-guide/examples/ex01-scheduled-task/README.md"
    "docs/plugin-guide/examples/ex01-scheduled-task/plugin.yaml"
    "docs/plugin-guide/machine/subjects.json"
    "docs/plugin-guide/machine/catalog.json"
    "docs/plugin-guide/machine/ops.json"
    "docs/plugin-guide/machine/plugin.schema.json"
)

$bundle = Join-Path $OutDir "bundle"
New-Item -ItemType Directory -Path $bundle -Force | Out-Null

foreach ($rel in $files) {
    $src = Join-Path $repoRoot ($rel -replace '/', '\')
    if (-not (Test-Path $src)) { throw "묶음에 넣을 파일이 없다: $src" }
    # 원본 경로 구조를 평평하게 만들지 않는다. AI 가 `machine/subjects.json` 을
    # 가이드 본문에서 참조하므로 그 경로가 유지되어야 한다.
    $dest = Join-Path $bundle ($rel -replace '^docs/plugin-guide/', '' -replace '/', '\')
    $destDir = Split-Path -Parent $dest
    if ($destDir -and -not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    Copy-Item $src $dest -Force
    Write-Host "  $rel"
}

Copy-Item (Join-Path $PSScriptRoot "task.md") (Join-Path $OutDir "task.md") -Force
Write-Host "  task.md"

$manifest = [ordered]@{
    built_from = (& git -C $repoRoot rev-parse --short HEAD 2>$null)
    files      = $files
    excluded   = @(
        "examples/ex01-scheduled-task/artifacts.json — 정답 스냅샷",
        "examples/ex01-scheduled-task/expected-plan.json — 기대 계획",
        "저장소 소스 코드 · 설계 문서 · 다른 플러그인"
    )
}
$json = $manifest | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText((Join-Path $OutDir "bundle-manifest.json"), $json,
                               (New-Object System.Text.UTF8Encoding($false)))

Write-Host "`n묶음: $bundle"
Write-Host "과제: $(Join-Path $OutDir 'task.md')"
Write-Host "`n**저장소 접근 없는 새 문맥**에 이 둘만 줄 것. 그 조건을 못 지키면"
Write-Host "관측을 했다고 기록하지 않는다 — 오염된 관측은 없는 관측보다 나쁘다."
