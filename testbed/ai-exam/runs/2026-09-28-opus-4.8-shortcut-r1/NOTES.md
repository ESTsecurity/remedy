# 2026-09-28 · Opus 4.8 · shortcut-r1 (shortcut-hijack)

| | |
|---|---|
| 모델 | **Claude Opus 4.8** — Opus 5.5 로 시작했으나 강등돼 4.8 이 답했다(출제자 기록) |
| 위협 | `shortcut-hijack` — Windows `.lnk` 를 처음 밟는 위협. **첫 회차다** |
| 주입 꾸러미 | 172 KB (`exam-bundle-shortcut-hijack.txt` · 176,816 바이트 · 파일 블록 21개) — 가이드 부분은 직전 회차와 같다 |
| 오염 | **없음으로 본다.** 출제자가 프로토콜대로 새 대화에 꾸러미를 붙여 답안을 받았다. **이 세션은 그 대화를 보지 못했으므로 그 신고에 기댄다** |
| 사전 기준 | 내부 기록 (커밋 `5f4d945`, **답안 전**) |
| 받은 것 | `plugin.yaml` · `answer.md` |

## 채점 — **불합격 · 사전 기준이 미리 잰 그 길**

`cargo xtask exam --threat shortcut-hijack --dir testbed/ai-exam/runs/2026-09-28-opus-4.8-shortcut-r1`:

```
  1. 린트          오류 0 · 경고 0
  2. 청정 코퍼스   28개 중 파괴 0개 (뿌리 규칙이 마주한 레코드 121414건)
  3. 감염 탐지     1개 중 판정 1개
    빠짐 shortcut.strip_args C:\Users\test\Desktop\Chrome.lnk :: args=--load-extension=C:\ProgramData\WebHelper\ext --disable-features=RendererCodeIntegrity
  4. 계획 완결성   기대 3건 중 빠짐 1건 · 기대 밖 1건 (불합격 아님)
       기대 밖 registry.strip_value C:\Users\test\Desktop\Chrome.lnk
```

사전 기준 ②의 둘째 줄(*"바로가기를 `edit` 로 → 불합격 · 빠짐 1 · 기대 밖 1
`registry.strip_value`"*)이 **그대로** 나왔다.

채점 5 — `Invoke-ExamApply.ps1 -Threat shortcut-hijack -Plugin <이 폴더>\plugin.yaml
-Revert` (Win10x64-Test · `remedy-lab-base-v3` · `-Record` 없음):

```
  종료 코드 5   (1=완전 치료 · 3=부분 실패 · 5=guard 정지)
  밟는 자리 3곳 중 잰 것 3곳 · 남아야 하는 자리 3곳 중 잰 것 3곳 · 내용 검사 1곳 중 잰 것 1곳
  실패 채점 5 불합격 — 범위 안 불일치 2건 · 치료가 만든 변화 0건 · 남은 파일 2건 · 살아 있는 프로세스 0건 · 남아야 하는데 바뀌었다 0건 · 지목한 만큼만 달라지지 않았다 1건
```

실기기 화면(`run.log`)이 까닭을 말한다 — 계획의 첫 줄이 **바로가기 파일을 겨눈
레지스트리 편집**이었고, 실행기가 그것을 백업 단계에서 담지 못해 전체를 멈췄다:

```
   1. 레지스트리 값에서 항목 제거  C:\Users\test\Desktop\Chrome.lnk
실패: 백업 단계에서 중단했다. 아무것도 파괴하지 않았다: seq 1: 이 플랫폼에서는 지원되지 않는다: 이 Op 의 대상 모양을 담을 방법이 없다
```

**안전 쪽으로 멈췄다** — 파괴 0, 남아야 하는 자리 3곳 그대로. 대신 격리할 파일
둘도 남았다(전부 아니면 아무것도).

---

## 사전 기준의 물음 넷

**1. 인자만 떼는가 — 아니다. 이 회차의 간판에서 틀렸다.** 바로가기 규칙을 `remove`
가 아니라 `edit` 에 넣었다(`op: strip` · 인자 전체를 capture). 답안의 믿음은 *"`ref` 가
shortcut 증거이므로 계획기가 `shortcut.strip_args` 를 도출한다"* 였고, 실제로는
`registry.strip_value` 가 계획됐다.

**응시자는 그것이 해석임을 스스로 밝혔다** (`answer.md`):

> **두 가지 스펙 해석을 밝혀 둔다.** (1) `edit`의 문서 산문은 `env.strip_path`·
> `registry.strip_value`만 표로 들지만, 권위 있는 `ops.json`에는 `shortcut.strip_args`가
> 구현 op 로 있고 이것이 유일한 shortcut op·유일한 제자리 편집 수단이다.

사전 기준 ①-1 이 적은 두 자리 — *"가이드 산문에는 바로가기 레시피가 없다"* 와 *"`edit`
절의 한 문장이 반대쪽을 가리킬 수 있다"* — 가 정확히 그 추론을 낳았다.

**2. 인자가 무엇을 가리키는가로 가르는가 — 그렇다.** 인자 둘(확장 폴더 강제 로드 ·
보호 기능 끄기)을 **함께** 요구한다. 인자가 있는 정상 바로가기는 걸리지 않았다(채점 4
기대 밖에 없음 · 채점 5 남아야 하는 자리 그대로).

**3. 이름이 닮은 이웃을 건드리지 않는가 — 그렇다.** 상한과 `subject_roots` 를 검체
폴더로만 좁혀 닮은 폴더가 상한 밖이 됐다.

**4. 없는 것을 찾으려 하지 않는가 — 그렇다.** 확장 대상을 선언하지 않았다.

## 무엇을 읽었는가 — 지문 일곱 · 카탈로그 신호 둘

| 지문 | answer.md | plugin.yaml | 출처 문단 |
|---|---|---|---|
| subject 가 정한다 | 0 | 0 | `22-remediate` 두 가지 선언 방식 |
| 플러그인이 Op 을 직접 고르지 않는다 | 0 | 0 | `22-remediate` 같은 문단 |
| 원래 값에 덧붙은 것이면 | 0 | 0 | `22-remediate` `edit` |
| 계획기가 증거를 보고 정한다 | 0 | 0 | `22-remediate` `edit` |
| 증거에서 파생돼야 한다 | 0 | 0 | `22-remediate` `edit` |
| 부분 문자열 하나로 가른다 | 0 | 0 | `32-lint-errors` |
| 경고만 끄지 않는다 | 0 | 0 | `32-lint-errors` |
| **카탈로그** `strip_args` | **3** | **1** | REFERENCE · `ops.json` |
| 카탈로그 *".lnk 바로가기"* | 0 | 0 | REFERENCE · `subjects.json` |

(`plugin.yaml` 의 한 번은 `answer.md` 에 실린 같은 코드 블록이다.)

지문은 0 이지만 **`edit` 절을 읽었다** — 답안이 그 절의 표(`env.strip_path` ·
`registry.strip_value`)를 인용했고, *"계획기가 … 도출한다"* 는 그 절의 *"계획기가 증거를
보고 정한다"* 를 제 말로 옮긴 것이다. **카탈로그도 읽었다** — `strip_args` 를 세 번
적었다(코드 한 번 · 설명 두 번).

## AI 가 틀린 것

| # | 무엇 | 가리키는 빈칸 |
|---|---|---|
| 1 | 바로가기 인자를 `edit` 로 떼려 했다 — `remove` 에 넣어야 `shortcut.strip_args` 가 된다 | **가이드에 바로가기 레시피가 없고**(산문 0), `22-remediate` 의 `edit` 절이 *"원래 값에 덧붙은 것이면 `edit` 이 맞다"* 고만 적고 **바로가기는 그 대상이 아니라는 말이 없다**. 응시자가 카탈로그로 메운 추론이 반대로 갔다 |

## 보고만 — 이 회차가 드러낸 제품 쪽 자리

- 🟡 **`edit` 의 대상을 아무도 가리지 않는다.** 바로가기 증거에 `edit` 을 걸면 린트는
  통과하고 계획기는 `registry.strip_value` 를 바로가기 **파일 경로**로 낸다. 실행기가
  백업 단계에서 멈춰 파괴는 없었지만(실기기 실측), 고객 화면의 계획에는 말이 안 되는
  동작이 적힌다.
- 🟡 **`matches` 가 레코드마다 정규식을 컴파일한다** (`crates/remedy-detect/src/eval.rs`
  의 `Regex::new`). 이 답안의 채점은 **917초**였다 — 파일 규칙 하나만 같은 뜻의
  `contains` 로 바꾼 사본은 **15초**(결과 같음). 파일 레코드 12만여 건에 대소문자 무시
  정규식을 매번 새로 만든 값이다. 이 회차를 `EXPECTED_RUNS` 에 넣었으므로 그 표를
  다시 재는 시험도 그만큼 길어진다.

## 못 재는 것

- 한 회차는 한 표본이다 — 같은 가이드로 다른 모델이 같은 추론을 하는지는 모른다.
