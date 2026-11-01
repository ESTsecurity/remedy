# svc-r2 — 합격. 세 번째 주기가 돌았다

| | |
|---|---|
| 날짜 | 2026-08-26 |
| 모델 | **Fable 5** (claude.ai 웹) |
| 위협 | `service-userinit` |
| 오염 | **없음** |
| 결과 | **합격** — 네 판정 전부 (경고 1건) |

```
  1. 린트          오류 0 · 경고 1
       경고 scan_roots[0] :: '%ProgramData%' 은 사실상 전체를 훑는다(깊이 2)
  2. 청정 코퍼스   7개 중 파괴 0개
  3. 감염 탐지     1개 중 판정 1개
  4. 계획 완결성   기대 7건 중 빠짐 0건
```

경고는 참조 답안과 같다 — 검체가 `ProgramData` 바로 아래에 폴더를 만들고 그
이름이 감염마다 바뀌므로 더 좁힐 수 없다.

---

## 1. r3 이 드러낸 빈칸이 메워졌다

```yaml
  restore:
    # Userinit 은 지우면 로그인이 안 된다. OS 기본값(C:\Windows\system32\userinit.exe,)
    # 으로 되돌린다. remove 절이 아니라 restore 절이다.
    - { ref: userinit, to: default }
```

**주석까지 그 구분을 적었다** — `22-remediate-recipes.md` §`to: default` 가
*"`restore` 절이다. `remove` 가 아니다"* 라고 못 박은 그 문장이다.

r3 은 판단이 옳았는데 절을 틀려 파싱에서 멈췄다. **한 회차 만에 닫혔다.**

---

## 2. 참조 답안보다 하나 더 했다

| Action | 참조 | svc-r2 |
|---|---|---|
| `service.clear_recovery` · `stop` · `disable` · `delete` | ✓ | ✓ |
| `file.quarantine_only` (`svc.exe`) | ✓ | ✓ |
| **`file.quarantine_only` (`cache.db`)** | 없음 | **있음** |
| `dir.delete_recursive` | ✓ | ✓ |
| `registry.restore_default` | ✓ | ✓ |
| | 7건 | **8건** |

```yaml
  - id: companion
    subject: file
    from: "${svc.dir}"
    where:
      - { field: path, op: not_equals, value: "${svc.exe}" }
```

> 폴더 전체가 검체가 만든 것이라는 관측이 있어 재귀 삭제를 쓰되, 덜 위험한 개별
> 격리(`payload`·`companion`)를 함께 둔다 — **재귀 삭제가 조건 3·4·5 로
> 보류돼도 파일이 남지 않는다.**

그리고 `submit_hint.samples` 에 `companion` 을 넣었다 — *"`cache.db` 에 수집물이
있을 수 있어"*. **위협 설명은 `cache.db` 를 "부속 파일" 로만 말했다.** 그것이
검체가 모아 둔 것일 수 있다는 추론은 응시자가 한 것이다.

`not_equals` 를 쓴 첫 회차이기도 하다.

**참조 답안에 반영했다.** 응시자가 우리보다 먼저 본 두 번째 사례다(r2 의 두
방어에 이어).

---

## 3. 그 밖에

- `svc`·`payload`·`companion` 은 `from`, `userinit`·`proc` 은 **`where` 값
  보간** — `path` 가 있는 subject 와 없는 subject 를 정확히 갈랐다
- `ProgramData` 아래 **폴더 한 겹**을 정규식으로 강제했다 — r2 가 드러내
  `22-remediate` §조건 5 에 넣은 것
- `proc`·`companion` 을 판정에서 뺐다 — *"프로세스는 재부팅 뒤 없을 수 있고,
  나머지 파일은 판정 근거가 아니다"*
- `signed_malware` 를 비웠고 그 이유를 적었다 — *"실행 파일에 서명이 없으니
  신뢰 서명 차단에 걸리지 않는다"*

---

## 4. 세 번째 주기

| 회차 | 드러낸 빈칸 | 다음 회차 |
|---|---|---|
| r0 | `from` 의 subject · `restore` 의 짝 | r1 이 정확히 씀 |
| r2 | `ProgramData` 상한 · 재귀 삭제와 `ref` 의 겹침 | r3 가 정확히 씀 |
| **r3** | **`to: default` 의 절** | **svc-r2 가 정확히 씀** |
| svc-r2 | (없음 — 오히려 우리 쪽을 고쳤다) | — |

**설계-06 §10 이 요구한 방식 자체가 세 번 연속으로 검증됐다** — 관측 → 빈칸 →
메움 → 다음 회차에서 확인.

이번 회차는 **가이드의 빈칸을 가리키지 않았다.** 대신 참조 답안을 고쳤다.


---

## 2026-09-02 재채점 — 린트 오류 1이 붙었다

도달 가능성 검사(`check_subject_reachability`)가 생기면서 이 답안에 린트
오류가 하나 붙었다.

```
오류 subjects.registry_value: 이 subject 는 레지스트리 루트가 `scan_roots` 에
     하나라도 있어야 모인다 — 지금 `scan_roots` 에는 경로뿐이다. 그대로 두면
     **언제나 0건**이고, 그 위에서 도는 룰은 아무것도 맞히지 못한 채 초록이 된다
```

`Userinit` 복원 규칙이 **실기기에서는 아무것도 맞히지 못한다.** 채점은
미리 뜬 스냅샷으로 돌기 때문에 그것을 볼 수 없었다 — 수집이 이미 끝난
자료라 *"그 스냅샷을 뜰 수 있는가"* 를 묻지 않는다.

### 답안의 흠이 아니다

이 회차가 돌던 시점의 `10-manifest.md` 표는 `registry_value` 를 **"무관하게
수집된다"** 칸에 두고 있었다. 응시자는 문서를 정확히 따랐다.

| | |
|---|---|
| 표가 틀려 있던 동안 | ~2026-09-01 (`307eda9` 에서 정정) |
| 같은 표 아래 쓰인 것 | 이 답안 · **우리 정답 플러그인** |

정답 플러그인도 같은 결함을 갖고 있었고 2026-09-02 에 함께 고쳤다
(`Winlogon` 키를 `scan_roots` 에 더했다). 감염 스냅샷의 `scope` 도 레지스트리
루트 없이 `registry_value` 2건을 담고 있어 **실기기 collect 로는 나올 수 없는
픽스처**였고, 그것도 함께 고쳤다.

`EXPECTED_RUNS` 의 이 회차 기대값은 `errors: 0` 에서 `errors: 1` 로 바꿨다.
그 표는 역사 장부가 아니라 **지금의 도구가 이 자료를 어떻게 읽는가**를
고정하는 회귀 검사다.
