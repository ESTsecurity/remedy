# 2026-10-01 · Opus 4.8 · appinit-r5 (appinit-implant) — 2차 주기

| | |
|---|---|
| 모델 | **Claude Opus 4.8** — 5.5 에서 **강등됐다**(출제자 기록) |
| 위협 | `appinit-implant` — AppInit 주입 원격 임플란트 (실검체 없음) |
| 주입 꾸러미 | `exam-bundle-appinit-implant.txt` · 180,136 바이트 · `ddab54f9…` (2차 주기 사전 기준 §②, 트리 `a292008`) |
| 오염 | **없음으로 본다.** 출제자가 프로토콜대로 새 대화에 꾸러미를 붙여 답안을 받았다. **이 세션은 그 대화를 보지 못했으므로 그 신고에 기댄다** |
| 사전 기준 | 내부 기록 §④ `appinit-implant` 줄 (커밋 `a764e49`, **답안 전** · 범위 재결정 `721bb1c`) |
| 받은 것 | `plugin.yaml` · `answer.md` — `answer.md` 의 코드 블록은 `plugin.yaml` 과 바이트까지 같다 |
| 지난 회차 | `09-05 appinit-r4` — 그때 합격, 지금 자료로는 **불합격**(두 값의 `restore_default` 빠짐 2) |

## 채점 — **합격 · 무경고**

`cargo xtask exam --threat appinit-implant --dir testbed/ai-exam/runs/2026-10-01-opus-4.8-appinit-r5`:

```
  1. 린트          오류 0 · 경고 0
  2. 청정 코퍼스   28개 중 파괴 0개 (뿌리 규칙이 마주한 레코드 372건)
  3. 감염 탐지     1개 중 판정 1개
  4. 계획 완결성   기대 6건 중 빠짐 0건
```

기대 밖 0 · 겹침 0 (0건이면 채점기가 그 줄을 찍지 않는다).

채점 5 — `Invoke-ExamApply.ps1 -Threat appinit-implant -Plugin <이 폴더>\plugin.yaml -Revert`
(Win10x64-Test · 스냅숏 `remedy-lab-base-v3` · `-Record` 없음 · 하네스가 배포한
`target\x86_64-pc-windows-msvc\release\remedy.exe` = `3d2885c8…` — 위협 증거와 같은 바이너리):

```
  종료 코드 1   (1=완전 치료 · 3=부분 실패 · 5=guard 정지)
    수행 [1/6] 설정 항목 제거  C:\ProgramData\Acme\Agent\agent-config.json
    수행 [2/6] 파일 격리  C:\ProgramData\SvcAssist\sahook.dll
    수행 [3/6] 파일 격리  C:\ProgramData\SvcAssist\svcassist.exe
    수행 [4/6] 레지스트리 값 기본값 복원  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
    수행 [5/6] 레지스트리 값 기본값 복원  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs
    수행 [6/6] 방화벽 규칙 원복  HKLM\SYSTEM\…\FirewallRules\SvcAssist-In-TCP
  밟는 자리 6곳 중 잰 것 6곳 (관측된 변화 6건) · 남아야 하는 자리 4곳 중 잰 것 4곳 · 내용 검사 1곳 중 잰 것 1곳
  OK   채점 5 합격 — 위협이 밟은 자리가 전부 청정 기준으로 돌아왔다
```

**이 위협의 응시자 답안을 실기기로 잰 첫 회차다**(r1~r4 는 채점 5 도입 전). 내용 검사 1/1 은
`agent-config.json` 에서 `modules.remote` 한 키만 빠지고 나머지가 같았다는 뜻이다.

---

## 사전 기준 §④ 가 가르려던 것 — **두 값이 삭제가 아니라 원복으로 서는가: 섰다**

r4 는 두 AppInit 값을 `remove`(`registry.delete_value`)로 지웠다. 09-05 실기기에서 그것이
청정 기준(`AppInit_DLLs` = `""` · `LoadAppInit_DLLs` = `0`)과 다르다는 것이 드러나 기대 Op 이
`restore_default` 로 바뀌었고, r4 는 지금 자료로 불합격이 됐다. **r5 는 그 자리를 정확히
짚었다**:

```yaml
restore:
  - { ref: appinit,      to: default }
  - { ref: appinit_flag, to: default }
```

답안의 말 — *"청정 Windows 에 이미 있는 값이다. 검체는 이를 만든 것이 아니라 덮어썼다.
`remove` 로 지우면 '완전 치료' 로 보고되지만 감염 전 상태로 돌아가지 않는다(30-antipatterns
§14)."* 가이드의 그 절을 이름으로 불렀다.

| | r4 (09-05 · Opus 4.8) | **r5 (10-01 · Opus 4.8)** |
|---|---|---|
| 두 AppInit 값 | `remove` → `delete_value` ×2 | **`restore … to: default` → `restore_default` ×2** |
| 판정식 | `appinit and (payload-dll or config)` | `appinit and payload_dll and fw` — 근거 **셋**의 논리곱 |
| 지금 자료 | 불합격 (빠짐 2 · 기대 밖 2) | **합격** (빠짐 0 · 기대 밖 0) |

## 정답과 다른 길

| | 정답 | 이 답안 |
|---|---|---|
| `AppInit_DLLs` 를 가르는 조건 | `data matches '(?i)\.dll$'` | `data contains "\"` — "경로가 있는가" |
| 두 번째 파일 | `companion` — 같은 폴더의 **나머지** (`path not_equals ${appinit.dll}`) | `payload_exe` — **방화벽 규칙이 가리킨** 실행 파일 (`${fw.exe}`) |
| 설정 항목 | `value contains ${appinit.dir}` 하나 | 경로 `ends_with` · `format json` · `key_path equals modules.remote` · 값에 폴더 — 넷의 논리곱 |
| 방화벽 | `remove: fwrule` | `restore: [firewall]` — 둘 다 `firewall.restore_rule` |
| 판정 | 근거 둘 (레지스트리 · DLL 실재) | 근거 셋 (+ 방화벽) |
| 재부팅 뒤 재검사 | 없음 | `verify.after_reboot: true` |

답안은 폴더 이름을 리터럴로 적지 않고 값에서 뽑았다(`data | first_path | dirname`, 정답과
같은 길 — "ex02 방식" 이라고 스스로 적었다). 상한은 관측된 폴더 둘과 그 레지스트리 키로 좁혔고
*"'변종에서 바뀔 수 있다' 는 가정이지 관측이 아니므로 부모로 넓히지 않는다"* 고 적었다 —
r4 가 `%PROGRAMDATA%` 전체를 훑어 경고를 받은 자리다(r4 린트 경고 1).

## 무엇을 읽었는가 (사후 관찰)

- `30-antipatterns` §14 — 원복 대 삭제. 답안이 절 번호로 불렀다.
- `10-manifest` §`scan_roots` — 상한을 관측된 그대로 · 레지스트리 값도 상한을 받는다 ·
  직속 값에는 끝의 `\*` 가 필요 없다(IFEO 와 대비).
- 사례 `ex02`(값에서 폴더를 뽑는다) · `ex03`("loader 가 있다" 가 아니라 "그 값이 페이로드
  폴더를 가리킨다").
- 카탈로그 신호 — `restore_default` · `firewall.restore_rule` · `structured_config.remove_key` ·
  `file.quarantine_only` 를 이름으로 불렀다. *"붙인 문서에 없는 필드·연산자·subject·Op 는
  쓰지 않았다. 필요하지만 없는 것도 없었다."*

## AI 가 틀린 것

| # | 무엇 | 가리키는 빈칸 |
|---|---|---|
| — | **없다** | — |

## 못 재는 것

- **한 회차는 한 표본이다.** 같은 판도 회차마다 다르게 답할 수 있다.
- **판이 4.8 이다**(5.5 에서 강등). r4 도 4.8 이었다 — 같은 판이 바뀐 가이드로 다른 답을
  냈지만, 그 차이를 가이드로 설명할 수 있다 까지만 적는다(판 통제 설계가 아니다).
- **오염은 출제자 신고에 기댄다.**
- 채점 5 의 합격은 **이 기계**(랩 VM)를 청정 기준으로 되돌렸다는 뜻이다.
