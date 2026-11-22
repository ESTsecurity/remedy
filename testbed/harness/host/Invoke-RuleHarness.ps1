#Requires -Version 5.1
# 하네스 표: Windows 랩(러너 · 랩 VM) | Windows 룰 하네스 하나를 그 머리의 `# 입력:` 줄대로 받은 입력으로 부른다 — 출시 전 필수 점검 ①
<#
.SYNOPSIS
    Windows 룰 하네스 하나를 그 머리의 `# 입력:` 줄대로 입력을 받아 부른다 — 출시 전 필수 점검 ①(`.github/workflows/checks.yml`).

.DESCRIPTION
    하네스 머리(처음 20줄)의 줄 하나가 입력 하나다:

      # 입력: -<인자> <파일 이름> <sha256 | -> <주소>[|<주소>…]

    그 파일을 `-Inputs\<인자>\<파일 이름>` 에 받는다(TLS 1.2 · `.part` 에 받은 뒤 옮긴다 · 주소를 차례로 — 이미 있으면 다시
    받지 않는다 · PowerShell 로 받지 못한 주소는 Windows 의 curl.exe 로 한 번 더 — PowerShell 의 요청만 막는 곳이 있다).
    SHA-256 칸이 `-` 가 아니면 대조하고, `-` 면 하네스가 스스로 대조한다(하네스 안에 기대값이 있다).
    인자 이름이 `Dir` 로 끝나면 그 인자에 받은 폴더를, 아니면 받은 파일을 준다. 하네스는 표준 인자 `-Package` · `-LogDir` 와
    그 인자로 따로 띄운 `powershell.exe -File` 에서 돈다(하네스의 `throw` 는 종료 1 이 된다).

    종료 코드는 하네스의 것이다(0 = 통과). 머리 줄이 꼴이 아니거나 · 입력을 받지 못했거나 · SHA-256 이 다르면 하네스를
    부르지 않고 2 로 멈춘다.

.PARAMETER Harness
    하네스 파일(`testbed\harness\host\Invoke-*Verify.ps1`).

.PARAMETER Package
    푼 `remedy-windows-x64` 폴더.

.PARAMETER LogDir
    하네스의 기록 폴더.

.PARAMETER Inputs
    받은 입력을 둘 폴더(인자마다 하위 폴더).

.EXAMPLE
    .\testbed\harness\host\Invoke-RuleHarness.ps1 -Harness testbed\harness\host\Invoke-Nginx2rootVerify.ps1 `
        -Package D:\dl\x\remedy-windows-x64 -LogDir D:\dl\nginx -Inputs D:\dl\inputs
#>
param(
    [Parameter(Mandatory = $true)][string] $Harness,
    [Parameter(Mandatory = $true)][string] $Package,
    [Parameter(Mandatory = $true)][string] $LogDir,
    [Parameter(Mandatory = $true)][string] $Inputs
)
$ErrorActionPreference = 'Stop'
function Stop-Input([string] $why) { Write-Host "입력 — $why — 하네스를 부르지 않는다"; exit 2 }

$headLines = @(Get-Content -LiteralPath $Harness -Encoding UTF8 -TotalCount 20)
$specs = @($headLines | Where-Object { $_ -match '^# 입력: ' })
if ($specs.Count -eq 0) { Stop-Input "머리에 '# 입력:' 줄이 없다: $Harness" }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'
$given = [ordered]@{}
foreach ($spec in $specs) {
    $cells = @(($spec -replace '^# 입력: ', '').Trim() -split '\s+')
    if ($cells.Count -ne 4 -or $cells[0] -notmatch '^-([A-Za-z]+)$') { Stop-Input "꼴이 아니다: $spec" }
    $argName = $Matches[1]
    if ($argName -in @('Package', 'LogDir')) { Stop-Input "표준 인자는 입력 줄에 두지 않는다: $spec" }
    $fileName = $cells[1]
    if ($fileName -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]*$') { Stop-Input "파일 이름이 꼴이 아니다: $fileName" }
    $want = $cells[2].ToLower()
    if ($want -ne '-' -and $want -notmatch '^[0-9a-f]{64}$') { Stop-Input "SHA-256 칸이 꼴이 아니다: $spec" }
    $urls = @($cells[3] -split '\|')
    $argDir = Join-Path $Inputs $argName
    New-Item -ItemType Directory -Force $argDir | Out-Null
    $dest = Join-Path $argDir $fileName
    if ($argName -like '*Dir') {
        $given[$argName] = $argDir
    } else {
        if ($given.Contains($argName)) { Stop-Input "인자 -$argName 에 파일이 둘이다(폴더를 주는 인자는 이름이 Dir 로 끝난다)" }
        $given[$argName] = $dest
    }
    if (-not (Test-Path -LiteralPath $dest)) {
        foreach ($u in $urls) {
            if ($u -notmatch '^https://') { Stop-Input "https 주소가 아니다: $u" }
            try {
                Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile "$dest.part"
                Move-Item -LiteralPath "$dest.part" -Destination $dest
                Write-Host ("받음  {0}  {1}바이트  ← {2}" -f $fileName, (Get-Item -LiteralPath $dest).Length, $u)
                break
            } catch {
                Write-Host "못 받음  $u — $($_.Exception.Message)"
                Remove-Item -LiteralPath "$dest.part" -ErrorAction SilentlyContinue
            }
            # PowerShell 의 요청만 막는 곳이 있다 — apachelounge.com 은 WindowsPowerShell 사용자 에이전트에 308 → http://localhost/
            # 를 준다(2026-11-22 · curl 은 200). 받지 못했을 때만 같은 주소를 Windows 의 curl.exe(제 이름 그대로)로 한 번 더 받는다.
            $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
            if (Test-Path -LiteralPath $curl) {
                $ErrorActionPreference = 'Continue'
                & $curl -fsSL --retry 2 -o "$dest.part" $u
                $curlCode = $LASTEXITCODE
                $ErrorActionPreference = 'Stop'
                if ($curlCode -eq 0 -and (Test-Path -LiteralPath "$dest.part")) {
                    Move-Item -LiteralPath "$dest.part" -Destination $dest
                    Write-Host ("받음(curl)  {0}  {1}바이트  ← {2}" -f $fileName, (Get-Item -LiteralPath $dest).Length, $u)
                    break
                }
                Write-Host "못 받음(curl 종료 $curlCode)  $u"
                Remove-Item -LiteralPath "$dest.part" -ErrorAction SilentlyContinue
            }
        }
    }
    if (-not (Test-Path -LiteralPath $dest)) { Stop-Input "$fileName 을 받지 못했다(주소 $($urls.Count)개)" }
    if ($want -ne '-') {
        $got = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToLower()
        if ($got -ne $want) { Stop-Input "$fileName 의 SHA-256 이 머리 줄과 다르다: $got" }
    }
}

$argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Harness, '-Package', $Package, '-LogDir', $LogDir)
foreach ($k in $given.Keys) { $argv += @("-$k", $given[$k]) }
Write-Host ("하네스  {0}  {1}" -f (Split-Path -Leaf $Harness), (($given.Keys | ForEach-Object { "-$_" }) -join ' '))
$ErrorActionPreference = 'Continue'
$global:LASTEXITCODE = $null
& powershell.exe @argv
$code = $LASTEXITCODE
if ($null -eq $code) { Write-Host '하네스의 종료 코드가 없다 — 실패로 본다'; exit 1 }
exit $code
