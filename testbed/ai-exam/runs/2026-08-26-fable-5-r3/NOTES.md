# r3 — 판단은 전부 옳았다. 문법 자리 하나가 틀렸다

| | |
|---|---|
| 날짜 | 2026-08-26 |
| 모델 | **Fable 5** (claude.ai 웹) |
| **위협** | **`service-userinit`** — 두 번째 위협의 첫 회차 |
| 오염 | **없음** |
| 결과 | **불합격** — 매니페스트가 파싱되지 않는다 |

```
파싱 실패 :: remediate.remove: data did not match any variant of untagged enum
             RemoveTarget at line 68 column 5
```

---

## 1. 무엇이 틀렸나 — `to: default` 를 `remove` 절에 넣었다

```yaml
remediate:
  remove:
    - { ref: svc }
    - { ref: userinit, to: default }     # ← restore 절의 문법이다
    - { ref: proc }
    - { ref: payload }
    - { path: "${svc.dir}", recursive: true, guard: payload }
```

**그 한 줄을 `restore` 절로 옮기기만 하면 네 판정을 전부 통과한다.** 실험으로
확인했다.

```
  1. 린트          오류 0 · 경고 1
  2. 청정 코퍼스   7개 중 파괴 0개
  3. 감염 탐지     1개 중 판정 1개
  4. 계획 완결성   기대 7건 중 빠짐 0건
합격 — 네 판정을 전부 통과했다
```

---

## 2. 판단은 전부 옳았다

응시자가 주석에 적은 것이다.

> 유발자 2 — Userinit. **지우면 셸이 안 떠 로그인이 안 된다.**
> 기본값(`C:\Windows\system32\userinit.exe,`)으로 되돌린다 →
> `registry.restore_default`.

**이 위협이 재려던 것을 정확히 맞혔다.** 삭제가 아니라 원복이라는 것, 필요한
Op 이 `registry.restore_default` 라는 것, 기본값이 무엇인지까지.

그 밖에도:

- **`ProgramData` 상한 문제를 스스로 막았다** — *"폴더 한 겹을 강제해야 dirname
  이 상한(ProgramData) 자체가 되지 않는다."* **r2 가 발견해 `22-remediate` 에
  넣은 것을 읽고 적용했다**
- `service`/`registry_value`/`process` 에 `path` 가 없어 `from` 이 안 통한다는
  것을 알고 `where` 값 보간으로 묶었다 (`10-manifest` · `20-detect`)
- `registry.delete_value` 를 쓰지 않았다
- 판정을 **세 근거의 논리곱**으로 짰다 (`svc and userinit and payload`) —
  참조 답안은 둘이다
- 재귀 삭제와 `ref: payload` 를 **함께** 뒀다 — *"재귀 삭제가 deferred 되어도
  이것은 남는다. 겹침이지 대체가 아니다."* **r2 가 빠뜨려 `22-remediate` 에
  넣은 그 문단이다**

**두 회차 전에 메운 빈칸 둘이 이번에 그대로 작동했다.**

---

## 3. 왜 틀렸나 — 그 문법이 어디에도 없었다

주입 문서 **21개 전부**를 훑었다.

| | `to: default` 예시 |
|---|---|
| 수기 문서 11개 | **0건** |
| 생성물 4개 | `REFERENCE.md` 에 1건 — 그러나 *"여기 없는 대상을 `to: default` 로 지정하면 거절한다"* 는 **제약 설명**이지 문법 예시가 아니다 |
| 예제 6개 | **0건** |

`22-remediate-recipes.md` 의 `restore` 예시는 **`av_exclusions`(이름 형) 하나
뿐**이었다.

```yaml
  restore:
    - av_exclusions
```

**응시자는 키 이름을 알았지만 어느 절에 쓰는지 몰랐다.** `remove` 가 제거
대상을 모으는 자리이고 `Userinit` 도 "없애야 할 것" 이므로 거기 넣은 것이다.

---

## 4. 이 회차가 만든 것

| 관측 | 무엇을 했나 |
|---|---|
| `to: default` 문법 예시가 0건 | `22-remediate-recipes.md` §`to: default` — **`restore` 절이다. `remove` 가 아니다** · 리터럴 못박기 요구 |
| 그 오류 메시지가 문서에 없다 | `32-lint-errors.md` 에 사례 추가 — **실제 파싱 오류가 그대로 실린다** |
| **채점기가 파싱 실패를 못 다뤘다** | `Score::parse_error` 신설. 전에는 `Err` 로 빠져나가 **그 회차를 기록에 남길 수 없었다** |
| 회귀 표가 위협을 모른다 | `Expected` 구조체 — 위협 · 파싱 여부까지 고정 |

### 채점기 결함이 이번에 드러났다

파싱 실패는 `Err` 였다. 그러면:

- 채점 출력이 아예 안 나온다
- **회귀 표에 넣을 수 없다** — 다음 회차가 같은 실수를 해도 대조할 것이 없다
- 0 으로 채우면 *"린트 오류 없음"* 으로 읽힌다

`parse_error` 를 `Score` 에 넣고, 회귀 표는 `parses: false` 일 때 나머지 숫자를
**재지 못한 것**으로 다룬다.

---

## 5. 남는 것

**경고 1건**은 참조 답안과 같다.

```
경고 scan_roots[0] :: '%ProgramData%' 은 사실상 전체를 훑는다(깊이 2)
```

응시자가 `%ProgramData%` 토큰을 썼다 — 참조 답안은 리터럴 `C:\ProgramData` 다.
**토큰 쪽이 낫다.** 참조 답안을 고칠지는 다음 회차를 보고 정한다.
