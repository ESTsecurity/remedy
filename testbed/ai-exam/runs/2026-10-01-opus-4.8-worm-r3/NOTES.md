# 2026-10-01 · Opus 4.8 · worm-r3 (selfcopy-worm) — 2차 주기

| | |
|---|---|
| 모델 | **Claude Opus 4.8** — 5.5 에서 **강등됐다**(출제자 기록). r2 도 4.8, r1 은 Opus 5 |
| 위협 | `selfcopy-worm` — 자기를 다섯 군데로 복사한 검체 (실검체 없음) |
| 주입 꾸러미 | `exam-bundle-selfcopy-worm.txt` · 179,915 바이트 · `e1e095c4…` (2차 주기 사전 기준 §②, 트리 `a292008`) |
| 오염 | **없음으로 본다.** 출제자가 프로토콜대로 새 대화에 꾸러미를 붙여 답안을 받았다. **이 세션은 그 대화를 보지 못했으므로 그 신고에 기댄다** |
| 사전 기준 | 내부 기록 §④ `selfcopy-worm` 줄 (커밋 `a764e49`, **답안 전** · 범위 재결정 `721bb1c`) |
| 받은 것 | `plugin.yaml` · `answer.md` — `answer.md` 의 코드 블록은 `plugin.yaml` 과 바이트까지 같다 |
| 지난 회차 | `09-22 worm-r2` — 불합격 (cron 을 `persistence` 로 지워 빈 파일이 남았다 · 빠짐 1 · 기대 밖 2) |

## 채점 — **불합격**

`cargo xtask exam --threat selfcopy-worm --dir testbed/ai-exam/runs/2026-10-01-opus-4.8-worm-r3`:

```
  1. 린트          오류 0 · 경고 0
  2. 청정 코퍼스   28개 중 파괴 0개 (뿌리 규칙이 마주한 레코드 42846건)
  3. 감염 탐지     1개 중 판정 0개
    빠짐 file.quarantine_only /etc/cron.d/sync-agent
    빠짐 file.quarantine_only /opt/backup/.syncd
    빠짐 file.quarantine_only /srv/data/.syncd
    빠짐 file.quarantine_only /usr/local/bin/.syncd
    빠짐 file.quarantine_only /usr/local/lib/.syncd
    빠짐 file.quarantine_only /var/tmp/.syncd
  4. 계획 완결성   기대 6건 중 빠짐 6건
```

채점 5 — `invoke-exam-apply.sh --threat selfcopy-worm --plugin <이 폴더>/plugin.yaml`
(WSL · 새 컨테이너 `rust:1.96-bookworm` · `--record` 없음 · 바이너리 `5291455f…` = 위협 증거의 것):

```
  종료 코드 0   (1=완전 치료 · 3=부분 실패 · 5=guard 정지)
  밟는 자리 6곳 중 잰 변화 6곳 · 남아야 하는 자리 6곳 중 잰 것 6곳 · 내용 검사 0곳 중 잰 것 0곳
  범위 안 불일치 6건 — 사전 등록 자료가 지목한 성질이 이루어지지 않았다
  실패 채점 5 불합격 — 범위 안 불일치 6건 · 치료가 만든 변화 0건 · 남아야 하는데 바뀌었다 0건
```

판정이 서지 않았으므로 아무것도 하지 않았다(종료 0). 정상 파일 넷과 정상 정기 작업 둘은
그대로다 — **틀린 것을 지운 회차가 아니라 아무것도 못 지운 회차다.**

---

## 왜 떨어졌나 — 복제본 규칙에 자리 표시를 두었다

```yaml
- id: copy
  subject: file
  where:
    - field: sha256
      op: in
      value:
        - "FILL_IN_lowercase_sha256_of_the_selfcopy_worm_sample"
```

답안의 말 — *"관측 보고는 '다섯이 같은 지문' 이라는 사실만 주고 hex 값은 주지 않았다. 없는
증거를 꾸며 넣으면 되레 아무것도 매치하지 않거나 엉뚱한 파일을 지울 위험이 있으므로
플레이스홀더로 두었다. 분석가가 실제 소문자 sha256 으로 교체해야 `copy` 가 작동한다."*

**그 사실 판단은 맞다.** 꾸러미의 위협 설명은 *"수집이 뜬 내용 지문도 하나로 같다"* 고만
적고 값은 주지 않는다 — 출제 설계가 그렇다(THREAT.md 출제자 주의 4: *"검체의 내용을 여기
적지 않는다"*). 값을 지어내지 않은 것도 맞다. 그러나 **값이 없어도 풀리는 문제였다.**

## 같은 재료로 푸는 길이 있다 — 실측

지문을 **기계에서 뽑는** 플러그인을 써서 네 판정에 넣었다(저장소 밖 스크래치, 답안이 아니다):

```yaml
- id: spreader                # 다시 뿌리는 정기 작업
  subject: persistence
  where:
    all:
      - { field: source,          op: starts_with, value: "/etc/cron.d/" }
      - { field: linux.cron.line, op: contains,    value: "--spread" }
  capture: { src: "source", exe: "command" }
- id: seed                    # 정기 작업이 부르는 그 복제본 — 지문을 여기서 뽑는다
  subject: file
  where: [{ field: path, op: equals, value: "${spreader.exe}" }]
  capture: { digest: "sha256" }
- id: clones                  # 같은 지문을 가진 파일 전부 — 어디에 있든
  subject: file
  where: [{ field: sha256, op: equals, value: "${seed.digest}" }]
- id: cronfile
  subject: file
  where: [{ field: path, op: equals, value: "${spreader.src}" }]
verdict: { require: "clones and spreader" }
remediate: { remove: [{ ref: clones }, { ref: cronfile }] }
```

```
  1. 린트          오류 0 · 경고 0
  2. 청정 코퍼스   28개 중 파괴 0개 (뿌리 규칙이 마주한 레코드 478건)
  3. 감염 탐지     1개 중 판정 1개
  4. 계획 완결성   기대 6건 중 빠짐 0건
  합격 — 네 판정을 전부 통과했다
```

재료는 전부 꾸러미에 있다 — `persistence` 의 `command` 필드(`REFERENCE` subject 표),
*"필드를 그대로 capture 해 `${…}` 로 넣으면 레코드끼리 견줄 수 있다"*(`20-detect` §기준
파일과 견준다), 다른 규칙의 capture 보간(`20-detect` §`${}` 두 형태). **그런데 그것을 이은
답은 세 회차에 하나도 없다** — r1(Opus 5)은 **r3 와 같은 자리 표시 해시**(그때 "의도된
설계" 라 두기로 했고, 크기 `38912` 로 바꾼 변형은 합격했다 — r1 기록), r2(4.8)는 숨김 이름 +
`count()`, r3(4.8)는 다시 자리 표시 해시. 첫 시도에서는 `linux.cron.line | first_path` 가
일정 토큰 `*/10` 을 집어 끊겼고(`/` 가 든다), `command` 필드로 바꾸자 섰다 — 그 함정도
가이드가 말하지 않는다.

**정답 플러그인도 리터럴 해시다** (`sha256 equals 311778ae…` — 출제자가 `infected/` 에서
읽은 값). 응시자가 가질 수 없는 값으로 쓴 정답은 *"정답이 기준을 못 넘으면 그 기준이 틀린
것"*(README)의 거울상 — **정답은 넘지만 응시자는 닿을 수 없다.** `c2-beacon`(ff7b8cf)에서
`in` 목록에 세운 원칙(값은 위협 정보가 준다)이 `equals` 에는 걸리지 않아 보이지 않았다.

## 사전 기준 §④ 가 가르려던 것 — **`ccfaf57` 의 문단은 닿았다**

r2 의 불합격 자리(*"persistence 를 치우면 cron 은 줄만 빠진다"*)를 r3 는 정확히 피했다 —
드롭인을 `file` 규칙(`cronfile`, `${spreader.src}`)으로 잡아 **파일째** 격리하고, 답안이 그
까닭을 그 문단의 말로 적었다. **고침은 통했고, 회차는 다른 자리에서 떨어졌다.**

| | r2 (09-22 · 4.8) | **r3 (10-01 · 4.8)** |
|---|---|---|
| 복제본을 가르는 것 | 숨김 이름 `.syncd` + `count(copy) >= 2` | **`sha256 in [자리 표시]`** |
| cron 을 다루는 것 | `persistence` 로 제거 → 줄만 빠짐 | **`file` 로 격리 — 파일째** |
| 판정 | 1/1 | **0/1** |
| 빠짐 | 1 (cron 파일) | **6 (전부)** |
| 채점 5 | 불합격 (빈 파일 남음 · 수행 7) | 불합격 (수행 0 · 지운 것 0) |

## 이 회차가 남긴 것

1. **가이드 고침 하나는 응시자 답안으로 확인됐다**(`ccfaf57`).
2. **빈칸이 하나 드러났다** — "값을 모르는 지문은 아는 자리에서 capture 해 `equals` 로
   모은다" 는 레시피가 없다. 그 길은 엔진이 지원하고(실측) 재료는 꾸러미에 있지만, 세 판이
   세 번 못 찾았다. 한 번은 우연이지만 셋은 신호다.
3. **정답 플러그인이 응시자가 닿을 수 없는 값을 쓴다** — 정답 도달 가능성 원칙에 어긋난다.
4. **자리 표시가 린트를 지난다** — `sha256` 값이 64자 16진이 아니어도 아무도 말하지 않는다.
   답안은 그것을 알고 있었지만(주석에 적음) 그래도 두었다.

고칠지 · 무엇을 고칠지는 2차 주기 사전 기준 §①(불합격 → 고침 → 재시험 1회)에 따라 사용자
결정이다. 셋 다 이 회차가 가리킨 자리다.

## 못 재는 것

- **한 회차는 한 표본이다.** 판이 r2 와 같아도(4.8) 답이 달랐다.
- **오염은 출제자 신고에 기댄다.**
- 대안 플러그인은 네 판정만 지났고 채점 5 는 돌리지 않았다(답안이 아니다).
