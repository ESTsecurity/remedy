<#
.SYNOPSIS
    EvilAI(Locust) 감염 상태를 게스트에 세우고·재고·치운다. 호스트 스크립트들이
    점 소싱해서 쓴다.

.DESCRIPTION
    두 하네스가 같은 감염 상태를 필요로 한다.

      New-InfectedSnapshot.ps1  코퍼스를 뜬다 — 세우고, 수집하고, **되돌린다**
      Invoke-P9Verify.ps1       치료를 잰다 — 세우고, **유지한 채** apply 를 돌린다

    구성이 두 곳에 복사되면 언젠가 갈라지고, 그러면 두 하네스가 서로 다른 감염을
    보면서 같은 이름으로 부른다. 여기 한 곳에 둔다.

    **페이로드 파일은 이 모듈이 놓지 않는다.** 무엇을 놓는지가 두 하네스의 유일한
    차이이기 때문이다 — 코퍼스 쪽은 실검체 바이트를(룰이 진짜 바이트를 훑는지가
    거기서 재는 것이다), 치료 쪽은 `Get-SynthPayloadBytes` 가 만든 무해한
    바이트를 놓는다. 치료 경로는 바이트 내용과 무관하므로 검체를 VM 에 들일
    이유가 없다.
#>

function Get-SynthPayloadBytes {
    <#
        룰이 발화하는 바이트를 **룰 파일에서** 만든다.

        상수를 스크립트에 베껴 두면 룰만 고쳤을 때 조용히 어긋나고, 그때
        발화하지 않는 페이로드로 "치료가 됐다" 가 나온다 — 아무것도 지울 것이
        없었을 뿐이다. `crates/remedy-core/tests/{evilai,infected}.rs` 가 같은
        방식으로 같은 바이트를 만든다.
    #>
    param([Parameter(Mandatory = $true)][string] $RulePath)

    if (-not (Test-Path $RulePath)) { throw "룰 파일이 없다: $RulePath" }
    $yar = [System.IO.File]::ReadAllText($RulePath, [System.Text.Encoding]::UTF8)

    # `        $a00 = "'AM9P'" ascii` 에서 큰따옴표 안을 꺼낸다 (군집1 상수).
    $consts = @()
    foreach ($line in ($yar -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t.StartsWith('$a')) { continue }
        $o = $t.IndexOf('"'); $c = $t.LastIndexOf('"')
        if ($c -gt $o + 1) { $consts += $t.Substring($o + 1, $c - $o - 1) }
    }
    # 임계값은 20 이다. 30 개를 싣되 모자라면 **그 자리에서 멈춘다.**
    if ($consts.Count -lt 25) {
        throw "룰에서 상수를 $($consts.Count)개밖에 꺼내지 못했다 — 합성 페이로드가 룰을 발화시키지 못한다"
    }
    $text = "'use strict';function R(){var F=[" + (($consts[0..29]) -join ",") + "];return F;}"
    [System.Text.Encoding]::UTF8.GetBytes($text)
}

function Set-InfectedState {
    <#
        감염 아티팩트를 세운다 — 폴더·예약 작업·Run 키·Defender 예외.

        **페이로드 파일은 놓지 않는다** (모듈 주석 참조). 호출자가 놓은 뒤
        `Assert-PayloadLanded` 로 확인할 것.

        멱등이다. 이미 있으면 지우고 다시 만든다.
    #>
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $PayloadDir,
        [string] $TaskName = "Locust",
        [string] $TaskPath = "\Microsoft\Windows\",
        [string] $RunName  = "SystemSoftwareUpdater",
        [string] $NodePath = 'C:\Program Files\nodejs\node.exe'
    )

    $r = Invoke-Command -Session $Session -ArgumentList $PayloadDir, $TaskName, $TaskPath, $RunName, $NodePath -ScriptBlock {
        param($Dir, $TaskName, $TaskPath, $RunName, $Node)
        $out = @{}

        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        $out.Dir = Test-Path $Dir

        $script = Join-Path $Dir 'preload.js'
        $act = New-ScheduledTaskAction -Execute $Node -Argument "`"$script`""
        $trg = New-ScheduledTaskTrigger -AtLogOn
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $act -Trigger $trg -Force | Out-Null
        $out.Task = $null -ne (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue)

        $runKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        Set-ItemProperty -Path $runKey -Name $RunName -Value "`"$Node`" `"$script`""
        $out.Run = (Get-ItemProperty $runKey).$RunName

        # **등록했다는 것과 목록에 섰다는 것은 다르다.**
        #
        # `Add-MpPreference` 가 예외를 던지지 않고도 목록에 서지 않는 일이
        # 있다 — 2026-09-14 에 `Partial` 직후 `Capture-Console` 을 돌렸더니
        # 계획에서 `보안 제품 예외 목록 원복` 이 빠져 6건이 됐고(기준선 7건),
        # 그때 이 값은 아무도 읽지 않아 화면에 아무 말도 없었다.
        #
        # 그래서 **읽어서 확인한다.** 후행 `\` 와 대소문자는 접는다 — Defender
        # 가 경로를 그대로 돌려주지 않을 수 있다.
        try {
            Add-MpPreference -ExclusionPath $Dir -ErrorAction Stop
            Start-Sleep -Milliseconds 300
            $want = $Dir.TrimEnd('\')
            $seen = @((Get-MpPreference).ExclusionPath |
                    Where-Object { $_ -and $_.TrimEnd('\') -ieq $want }).Count -gt 0
            $out.Excl = if ($seen) { $true } else { "더했는데 목록에 서지 않았다" }
        }
        catch { $out.Excl = "실패: $($_.Exception.Message)" }

        [pscustomobject]$out
    }
    if (-not $r.Task) { throw "예약 작업이 만들어지지 않았다: $TaskPath$TaskName" }
    # **예외가 빠지면 조용하다.** 계획에서 `보안 제품 예외 목록 원복` 하나가
    # 사라질 뿐이고, 그 사실을 다른 판정은 잡지 않는다. 여기서 멈추지 않으면
    # 캡처를 3분 받은 뒤에야 `diff` 에서 드러난다.
    if ($r.Excl -ne $true) {
        throw "Defender 예외가 서지 않았다 ($PayloadDir) — $($r.Excl). 이 상태로 재면 계획에서 '보안 제품 예외 목록 원복' 이 빠진다"
    }
    $r
}

function Set-GuestPayload {
    <#
        페이로드 바이트를 게스트의 `preload.js` 로 놓고 **해시로 확인한다.**

        백신이 먹으면 그 뒤 실행은 페이로드 없는 감염이라 판정이 서지 않는데,
        화면에는 "치료할 것이 없었다" 로 나온다. 여기서 끊는다.
    #>
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $PayloadDir,
        [Parameter(Mandatory = $true)][byte[]] $Bytes
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $want = ([System.BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLower() }
    finally { $sha.Dispose() }

    $b64 = [Convert]::ToBase64String($Bytes)
    $got = Invoke-Command -Session $Session -ArgumentList $PayloadDir, $b64 -ScriptBlock {
        param($Dir, $B64)
        $p = Join-Path $Dir 'preload.js'
        [System.IO.File]::WriteAllBytes($p, [Convert]::FromBase64String($B64))
        if (-not (Test-Path $p)) { return "없어짐(백신 의심)" }
        (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
    }
    if ($got -ne $want) { throw "페이로드가 온전히 놓이지 않았다: 기대 $want / 실제 $got" }
    [pscustomobject]@{ Path = "$PayloadDir\preload.js"; Sha256 = $want; Size = $Bytes.Length }
}

function Start-InfectedProcess {
    <#
        **실행 중 상태를 만든다.** 위협 설명이 요구하는 자리다 —
        *"실행 중인 프로세스도 다뤄야 한다 … 있을 때도 없을 때도 처리돼야 한다."*

        코퍼스 스냅샷에는 그 프로세스가 없다(수집 시점에 트리거가 아직 돌지
        않았다). 그래서 **그 요구는 한 번도 시험된 적이 없었다** — 실기기
        회차에서만 세울 수 있다.

        # 왜 `-e` 를 붙이는가

        진짜 페이로드는 함수 하나를 정의하고 **곧바로 끝난다**(254 바이트짜리
        상수 배열이다). 그러면 프로세스 표에 올라오지 않는다. 그래서 node 를
        살려 두는 무해한 코드를 함께 준다. 플러그인이 보는 것 — 이미지가
        `node.exe` 로 끝나고 인자가 페이로드 폴더를 품는다 — 은 그대로다.

        # 왜 현재 디렉터리를 페이로드 폴더로 두는가

        **그래야 순서가 시험된다.** 그 폴더를 현재 디렉터리로 쥔 프로세스가
        살아 있으면 `dir.delete_recursive` 가 실패한다. 죽이는 것이 지우는 것보다
        먼저 와야 한다는 요구가 여기서 진짜로 걸린다.

        # 핸들을 물려주지 않는다

        `Start-Process` 로 띄우면 자식이 부모의 stdout 파이프를 물려받고, 영원히
        도는 프로세스가 그것을 붙들면 원격 호출이 EOF 를 못 보고 멈춘다.
        `Win32_Process.Create` 는 아무 핸들도 물려주지 않는다.
    #>
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $PayloadDir,
        [string] $NodePath = 'C:\Program Files\nodejs\node.exe'
    )
    $r = Invoke-Command -Session $Session -ArgumentList $PayloadDir, $NodePath -ScriptBlock {
        param($Dir, $Node)
        if (-not (Test-Path -LiteralPath $Node)) {
            return [pscustomobject]@{ Pid = 0; Why = "$Node 가 없다 — 이 기계에서는 실행 중 상태를 못 세운다" }
        }
        $script = Join-Path $Dir 'preload.js'
        $cmd = '"{0}" -e "setInterval(function(){{}},1e9)" "{1}"' -f $Node, $script
        $c = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
                -Arguments @{ CommandLine = $cmd; CurrentDirectory = $Dir }
        if ($c.ReturnValue -ne 0) {
            return [pscustomobject]@{ Pid = 0; Why = "프로세스 생성 실패 (코드 $($c.ReturnValue))" }
        }
        # 프로세스 표에 올라오기를 기다린다. 안 올라오면 `process.kill` 이 0건이
        # 되고, 그 0건은 "죽였다" 가 아니라 **"잴 것이 없었다"** 다.
        for ($i = 0; $i -lt 25; $i++) {
            $p = Get-CimInstance Win32_Process -Filter "ProcessId = $($c.ProcessId)" -ErrorAction SilentlyContinue
            if ($p) { return [pscustomobject]@{ Pid = $c.ProcessId; Why = $null } }
            Start-Sleep -Milliseconds 200
        }
        [pscustomobject]@{ Pid = 0; Why = "프로세스가 표에 올라오지 않았다" }
    }
    if (-not $r.Pid) { throw "실행 중 상태를 세우지 못했다: $($r.Why)" }
    $r
}

function Stop-InfectedProcess {
    <# 페이로드 폴더를 인자로 쥔 프로세스를 전부 죽인다. 정리에서 먼저 부른다 —
       살아 있으면 폴더가 지워지지 않고 다음 회차가 오염된 자리에서 시작한다. #>
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $PayloadDir
    )
    Invoke-Command -Session $Session -ArgumentList $PayloadDir -ScriptBlock {
        param($Dir)
        $n = 0
        foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                         Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Dir) })) {
            try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $n++ } catch { }
        }
        $n
    }
}

function Get-InfectedFingerprint {
    <#
        G2 판정에 쓸 **상태 지문**을 뜬다.

        게이트가 요구하는 것은 "파일 해시·타임스탬프·소유자·권한 100% 일치"
        다(설계-03 §10). 그래서 존재 여부만 보지 않는다 — 되살아났지만 소유자가
        SYSTEM 으로 바뀐 파일은 복원이 아니다.

        예약 작업은 XML 전문을 담는다. 필드를 골라 담으면 고르지 않은 필드의
        회귀를 볼 수 없다.
    #>
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $PayloadDir,
        [string] $TaskName = "Locust",
        [string] $TaskPath = "\Microsoft\Windows\",
        [string] $RunName  = "SystemSoftwareUpdater"
    )
    Invoke-Command -Session $Session -ArgumentList $PayloadDir, $TaskName, $TaskPath, $RunName -ScriptBlock {
        param($Dir, $TaskName, $TaskPath, $RunName)
        $p = Join-Path $Dir 'preload.js'
        $file = $null
        if (Test-Path $p) {
            $i = Get-Item $p -Force
            $acl = Get-Acl $p
            # **`AI` 플래그 하나는 정규화한다.**
            #
            # `SE_DACL_AUTO_INHERITED` 는 "이 DACL 을 OS 의 자동 상속 알고리즘이
            # 계산했다" 는 표시다. remedy 가 SDDL 을 **복원하면**(그것을 실제로
            # 한다 — `remedy-platform/src/write.rs` 의 `sddl`) Windows 가
            # `SetSecurityInfo` 에서 이 플래그를 다시 켜는데, 상속만 받고 명시
            # 설정이 없던 원본에는 꺼져 있다. 즉 **복원했기 때문에 생기는 차이**
            # 이고 ACE 목록·소유자는 그대로다 — 실질 접근 권한은 같다.
            #
            # `P`(상속 차단)·`AR` 은 지우지 않는다. 그것이 바뀌면 실제로 다른
            # 권한이 되고, 그때는 G2 가 빨개져야 한다. 정규화를 넓히는 것은
            # 리뷰 대상이다 — 하나 늘 때마다 이 비교가 볼 수 있는 범위가 준다.
            # `D:` · `S:` 뒤 **플래그 영역 전체**에서 지운다. `D:AI` 만 보면
            # `D:PAI` 를 놓치고, 그러면 상속 차단이 걸린 파일에서 이 정규화가
            # 조용히 아무것도 하지 않는다.
            $sddl = $acl.Sddl
            $norm = [regex]::Replace($sddl, '(?<=[DS]:)[A-Z]*(?=\(|$)',
                                     { param($m) $m.Value -replace 'AI', '' })
            $file = [ordered]@{
                exists    = $true
                size      = $i.Length
                sha256    = (Get-FileHash $p -Algorithm SHA256).Hash
                # 왕복이 시각을 바꾸는지 본다. 100ns 단위까지 남긴다.
                mtime     = $i.LastWriteTimeUtc.Ticks
                ctime     = $i.CreationTimeUtc.Ticks
                owner     = $acl.Owner
                sddl_norm = $norm
                sddl_raw  = $sddl      # 비교하지 않되 남긴다. 사람이 볼 것이 있어야 한다
                attrs     = [string]$i.Attributes
            }
        } else {
            $file = [ordered]@{ exists = $false }
        }

        $t = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
        $taskXml = if ($t) { Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath } else { $null }

        $runVal = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
                     -ErrorAction SilentlyContinue).$RunName

        [pscustomobject][ordered]@{
            file      = [pscustomobject]$file
            task      = ($null -ne $t)
            task_xml  = $taskXml
            run_value = $runVal
            excl      = (@((Get-MpPreference).ExclusionPath) | Where-Object { $_ } | Sort-Object) -join ';'
            dir       = Test-Path $Dir
        }
    }
}

function Compare-InfectedFingerprint {
    <#
        지문 둘을 견준다. 다른 항목의 이름을 돌려준다 — 빈 배열이면 일치다.

        **무엇이 달랐는지 남긴다.** "다르다" 만 알면 복원이 어디서 무너졌는지
        모른 채 게이트만 빨개진다.
    #>
    param(
        [Parameter(Mandatory = $true)] $Before,
        [Parameter(Mandatory = $true)] $After
    )
    $diff = @()
    foreach ($k in @("task", "task_xml", "run_value", "excl", "dir")) {
        if ([string]$Before.$k -ne [string]$After.$k) {
            $diff += "$k : '$($Before.$k)' -> '$($After.$k)'"
        }
    }
    # `sddl_raw` 는 **일부러 뺀다** — `sddl_norm` 이 그 자리를 대신한다
    # (`Get-InfectedFingerprint` 의 `AI` 주석 참조). raw 는 보고용으로만 남는다.
    foreach ($k in @("exists", "size", "sha256", "mtime", "ctime", "owner", "sddl_norm", "attrs")) {
        $b = $Before.file.$k; $a = $After.file.$k
        if ([string]$b -ne [string]$a) { $diff += "file.$k : '$b' -> '$a'" }
    }
    ,$diff
}

function Assert-NoForeignInfection {
    <#
        **이 랩에 남의 감염이 없는가** — 되돌리지 않는 하네스가 자기 전제를
        보는 자리.

        # 왜 필요한가 (2026-09-13 에 밟았다)

        `Invoke-PartialVerify` 는 스냅샷을 되돌리지 않는다. 한 바퀴에서 시연
        기계를 준비하며 남은 `…AgentV12-we9i6` Defender 예외가 계획에 하나 더
        들어와, `수행 6건` 을 기대하던 판정이 7건을 보고 빨개졌다. **화면은
        무엇이 잘못됐는지 말하지 않았고** 사람이 로그를 파야 원인에 닿았다.

        `evilai-locust` 의 예외 규칙이 `value contains ${task.payload_dir}` 라
        **내 경로를 접두사로 갖는 예외까지** 잡는다. 이름이 달라도 계획에는
        들어온다.

        # 폴더 이름이 아니라 페이로드로 본다

        하네스마다 leaf 가 다르다 — `MicrosoftResourcesAgentV12` ·
        `SystemSoftwareUpdaterV2-q5ty`. 이름 패턴으로 찾으면 남의 것을 놓친다.
        이 위협의 페이로드 파일명(`preload.js`)이 그보다 안정적이다.

        # 판정이 아니라 중단이다

        오염된 랩에서 나온 숫자는 통과든 실패든 아무것도 뜻하지 않는다.
        **재지 않고 이름을 대며 멈춘다** — 그래야 다음 사람이 로그를 파지 않는다.

        .PARAMETER PayloadDir
            이 하네스가 쓸 페이로드 폴더. 예외 검사가 이 경로를 **포함하는**
            것을 찾으므로 (플러그인과 같은 조건) 감염을 세우기 **전에** 부른다.
    #>
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $PayloadDir,
        [string] $TaskName = "Locust",
        [string] $TaskPath = "\Microsoft\Windows\",
        [string] $RunName = "SystemSoftwareUpdater",
        [string] $PayloadFile = "preload.js"
    )
    Write-Step "전제 — 랩에 남의 감염이 없는가"
    # **쉼표로 감싸지 않는다.** `, $arr` 는 배열을 감싼 배열이고, 원격 경계를
    # 건너오면 바깥이 풀려 껍데기 하나가 항목으로 세어진다 — 깨끗한 랩에서
    # "흔적 1건" 이 나왔다(2026-09-14 에 밟았다). 바깥의 `@()` 가 스칼라도
    # 빈 것도 옳게 배열로 만든다.
    $dirty = @(Invoke-Command -Session $Session `
            -ArgumentList $PayloadDir, $TaskName, $TaskPath, $RunName, $PayloadFile `
            -ScriptBlock {
            param($dir, $task, $path, $run, $leafFile)
            $ErrorActionPreference = "Continue"
            $found = New-Object System.Collections.Generic.List[string]
            foreach ($e in @((Get-MpPreference).ExclusionPath)) {
                # 플러그인과 같은 조건: 내 경로를 **포함**하는 예외.
                if ($e -and $e -like "*$dir*") { $found.Add("Defender 예외  $e") }
            }
            if (Get-ScheduledTask -TaskPath $path -TaskName $task -ErrorAction SilentlyContinue) {
                $found.Add("예약 작업     $path$task")
            }
            if (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
                    -Name $run -ErrorAction SilentlyContinue) {
                $found.Add("Run 키        $run")
            }
            foreach ($d in @(Get-ChildItem (Split-Path $dir -Parent) -Directory -ErrorAction SilentlyContinue)) {
                if (Test-Path (Join-Path $d.FullName $leafFile)) {
                    $found.Add("페이로드      $($d.FullName)\$leafFile")
                }
            }
            $found.ToArray()
        })
    if ($dirty.Count -gt 0) {
        throw ("랩에 앞선 회차의 감염 흔적이 $($dirty.Count)건 남아 있다. " +
            "이 위에서 재면 계획이 달라지고 판정이 뜻을 잃는다.`n  " +
            ($dirty -join "`n  ") +
            "`n스냅샷으로 되돌린 뒤 다시 돌릴 것:  .\Reset-Vm.ps1")
    }
    Write-Ok "깨끗하다 (예외 · 작업 · Run 키 · 페이로드)"
}

function Clear-InfectedState {
    <#
        세운 것을 되돌린다. 스냅샷을 되돌리지 않는 하네스는 손으로 치워야 한다 —
        남기면 다음 실행이 오염된 자리에서 시작한다.

        **`-ErrorAction SilentlyContinue` 로 덮지 않는다.** 무엇이 남았는지
        돌려주고, 판단은 부르는 쪽이 한다.
    #>
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $PayloadDir,
        [string] $TaskName = "Locust",
        [string] $TaskPath = "\Microsoft\Windows\",
        [string] $RunName  = "SystemSoftwareUpdater"
    )
    Invoke-Command -Session $Session -ArgumentList $PayloadDir, $TaskName, $TaskPath, $RunName -ScriptBlock {
        param($Dir, $TaskName, $TaskPath, $RunName)
        # **프로세스를 먼저 죽인다.** 페이로드 폴더를 현재 디렉터리로 쥔
        # 프로세스가 살아 있으면 아래 폴더 제거가 조용히 실패하고, 다음 회차가
        # 오염된 자리에서 시작한다.
        foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                         Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Dir) })) {
            try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch { }
        }
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $RunName -ErrorAction SilentlyContinue
        Remove-MpPreference -ExclusionPath $Dir -ErrorAction SilentlyContinue
        Remove-Item $Dir -Recurse -Force -ErrorAction SilentlyContinue
        [pscustomobject]@{
            dir_left  = Test-Path $Dir
            task_left = $null -ne (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue)
            run_left  = $null -ne (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
                                     -ErrorAction SilentlyContinue).$RunName
        }
    }
}
