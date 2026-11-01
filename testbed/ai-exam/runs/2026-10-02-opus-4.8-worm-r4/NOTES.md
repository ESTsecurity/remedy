# 2026-10-02 · Opus 4.8 · worm-r4 (selfcopy-worm) — 2차 주기, §① 의 재시험

| | |
|---|---|
| 모델 | **Claude Opus 4.8** — 5.5 에서 **강등됐다**(출제자 기록). r3 와 같은 판 |
| 위협 | `selfcopy-worm` — 자기를 다섯 군데로 복사한 검체 (실검체 없음) |
| 주입 꾸러미 | `exam-bundle-selfcopy-worm.txt` · **181,017 바이트 · `8b243df8…`** — r3(179,915 · `e1e095c4…`)와의 차이는 `20-detect` 의 새 절 하나뿐(`431c2a1`, `git diff` 로 확인). 해시 값은 여전히 0회 |
| 오염 | **없음으로 본다.** 출제자가 프로토콜대로 새 대화에 꾸러미를 붙여 답안을 받았다. **이 세션은 그 대화를 보지 못했으므로 그 신고에 기댄다** |
| 사전 기준 | 내부 기록 §⑤-2 "`worm-r4` 사전 기준" (커밋 `431c2a1`, **답안 전**) |
| 받은 것 | `plugin.yaml` · `answer.md` — `answer.md` 의 코드 블록은 `plugin.yaml` 과 바이트까지 같다 |
| 지난 회차 | `10-01 worm-r3` — 불합격 (복제본 규칙의 `sha256 in` 에 자리 표시 → 판정 0 · 빠짐 6) |

## 채점 — **합격 · 경고 2**

`cargo xtask exam --threat selfcopy-worm --dir testbed/ai-exam/runs/2026-10-02-opus-4.8-worm-r4`:

```
  1. 린트          오류 0 · 경고 2
       경고 scan_roots[1] :: '/opt' 은 사실상 전체를 훑는다(깊이 2). scan_roots 는 성능이 아니라 **읽기 권한 상한**이므로 좁을수록 좋다
       경고 scan_roots[3] :: '/srv' 은 사실상 전체를 훑는다(깊이 2). scan_roots 는 성능이 아니라 **읽기 권한 상한**이므로 좁을수록 좋다
  2. 청정 코퍼스   28개 중 파괴 0개 (뿌리 규칙이 마주한 레코드 478건)
  3. 감염 탐지     1개 중 판정 1개
  4. 계획 완결성   기대 6건 중 빠짐 0건
```

기대 밖 0 · 겹침 0. 경고 둘은 `scan_roots` 가 `/opt` · `/srv` 로 넓다는 것이다 — 정답은
`/opt/backup` · `/srv/data` 다. 답안의 주석은 *"삭제는 아래 sha256 일치로 정밀하게 가려지므로,
이 범위를 열어도 지문이 다른 정상 파일은 건드리지 않는다"* — 치료 범위의 근거로는 맞지만
`scan_roots` 는 읽기 권한 상한이라는 린트의 말이 맞다. 합불을 가르지 않는다(설계-06 §8 —
서명 단계에서 설명할 일).

채점 5 — `invoke-exam-apply.sh --threat selfcopy-worm --plugin <이 폴더>/plugin.yaml`
(WSL · 새 컨테이너 `rust:1.96-bookworm` · `--record` 없음 · 바이너리 `5291455f…` = 위협 증거의 것):

```
  종료 코드 1   (1=완전 치료 · 3=부분 실패 · 5=guard 정지)
    수행 [1/6] 파일 격리  /opt/backup/.syncd
    수행 [2/6] 파일 격리  /srv/data/.syncd
    수행 [3/6] 파일 격리  /usr/local/bin/.syncd
    수행 [4/6] 파일 격리  /usr/local/lib/.syncd
    수행 [5/6] 파일 격리  /var/tmp/.syncd
    수행 [6/6] 파일 격리  /etc/cron.d/sync-agent
  밟는 자리 6곳 중 잰 변화 6곳 · 남아야 하는 자리 6곳 중 잰 것 6곳 · 내용 검사 0곳 중 잰 것 0곳
  OK   채점 5 합격 — 위협이 밟은 자리가 전부 사전 등록 자료대로 됐다
```

복제본 다섯과 cron 정의 파일이 **격리**됐고(삭제가 아니다 — 요구 3), 이름이 닮은 정상 파일
넷과 정상 정기 작업 둘은 그대로다(요구 4).

---

## 사전 기준이 가르려던 것 — **새 절이 닿았다**

**① 지문을 기계에서 뽑는가 — 뽑았다.** 답안의 사슬이 새 절의 예시와 같은 모양이다:

```
  cron (persistence)  command ends_with "/.syncd" · args contains "--spread"   capture exe=command · dropfile=source
  seed (file)         path equals ${cron.exe}                                   capture digest=sha256
  clones (file)       sha256 equals ${seed.digest}
  cronfile (file)     path equals ${cron.dropfile}
  verdict             cron and count(clones) >= 2
```

자리 표시는 없다. 답안 주석 — *"값을 모르는 지문은 아는 자리 하나에서 떠서 나머지를
모은다. 지어내지 않는다."* — 새 절의 문장을 거의 그대로 옮겼다. **사전 지문 "아는 자리
하나" 는 꾸러미 전체에 그 절에만 있다(1회)** 고 답안에 1회 있다. "자리 표시" 는 답안에 0회.

| 지문 | 답안(코드) | 답안(설명) | 꾸러미 | 어디 |
|---|---|---|---|---|
| 아는 자리 하나 | **1** | 0 | 1 | 새 절에만 |
| 지어내지 않는다 | **1** | 0 | 2 | 새 절 · 다른 한 곳 |
| 값은 모른다 | 0 | 0 | 1 | 새 절 |
| 자리 표시 | 0 | 0 | 1 | 새 절 (금지 문맥) |
| `count(` | 2 | 1 | 2 | `31-nonexistent` |

**② cron 드롭인을 파일째 — 유지.** r3 와 같은 `cronfile` 규칙(`${cron.dropfile}`)으로 파일을
격리한다. `persistence.delete` 는 *"줄만 빼 빈 파일을 남기므로 cron 파일에는 부적합"* 이라고
답안이 적었다 — `ccfaf57` 의 문단이 두 회차 연속 닿았다.

**③ 자동 1–4 + 채점 5 — 합격.**

## r3 → r4 — 같은 판, 바뀐 것은 새 절 하나

| | r3 (10-01 · 4.8) | **r4 (10-02 · 4.8)** |
|---|---|---|
| 꾸러미 | 179,915 · `e1e095c4…` | 181,017 · `8b243df8…` — 차이는 새 절뿐 |
| 복제본을 가르는 것 | `sha256 in [FILL_IN_…]` | **`sha256 equals ${seed.digest}`** — cron 이 부르는 파일에서 뽑은 값 |
| 판정식 | `copy and spreader` | `cron and count(clones) >= 2` |
| cron 드롭인 | `file` 로 파일째 | 같다 |
| 자동 · 채점 5 | 판정 0 · 빠짐 6 · 불합격 | **판정 1 · 빠짐 0 · 합격** |

판이 같고 꾸러미 차이가 새 절 하나뿐이므로, **r3 → r4 의 차이를 새 절로 설명할 수 있다.** 한
표본 대 한 표본이라 그 이상은 적지 않는다 — 1차 주기의 판 통제(shortcut · sideload)보다 깨끗한
비교다(그때는 무관한 절이 하나 더 있었다).

## 정답과 다른 길

| | 정답 1.0.1 | 이 답안 |
|---|---|---|
| cron 을 가르는 조건 | `source starts_with /etc/cron.d/` · `args contains --spread` | + `command ends_with "/.syncd"` — 셋의 논리곱 |
| 판정 | `clones and respawn` | `cron and count(clones) >= 2` — **복제본이 둘 이상**이어야 자가복제로 본다 |
| `scan_roots` | 관측된 폴더 여섯 | `/usr/local` · `/opt` · `/var/tmp` · `/srv` · `/etc/cron.d` — 둘이 넓어 경고 |
| 재부팅 뒤 재검사 | 없음 | `verify.after_reboot: true` |

`count(clones) >= 2` 는 정답에 없는 방어다 — 같은 파일이 하나뿐인 기계(어디선가 받아 둔
같은 파일)에서는 서지 않는다. 정답은 그 자리를 `respawn` 과의 논리곱으로 막는다.

## AI 가 틀린 것

| # | 무엇 | 가리키는 빈칸 |
|---|---|---|
| 1 | `scan_roots` 를 `/opt` · `/srv` 로 넓게 잡았다(경고 2) | 가이드는 적는다(`10-manifest` §scan_roots — 읽기 권한 상한). 답안은 그것을 알고도 치료 정밀도를 근거로 넓혔다 — 빈칸이 아니라 선택 |

## 못 재는 것

- **한 회차는 한 표본이다.** 판이 r3 와 같다는 것은 비교를 깨끗하게 하지만 확률을 말하지 않는다.
- **오염은 출제자 신고에 기댄다.**
- 채점 5 의 합격은 **이 컨테이너**를 사전 등록 자료대로 되돌렸다는 뜻이다.
