# remedy

멀티플랫폼 전용백신 — **템플릿 하나 + 위협별 플러그인** 구조.

위협마다 단품 도구를 찍어내면 관리 비용이 무한히 누적된다. remedy는 바이너리
하나를 두고 위협별 대응을 **선언적 룰**로 표현한다.

## 현재 상태

**v1(P0~P11) 완료 · Windows·Linux 양쪽 동작.** 코어 `1.0.0`.

```
remedy scan    --plugin plugin.yaml --out-dir out    # 관찰 → 판정 → 계획
remedy run     --plugin plugin.yaml --out-dir out    # 위 + 치료 (승인을 묻는다)
remedy restore --run <run_id>                        # 되돌리기
remedy verify  --run <run_id> --plugin plugin.yaml   # 치료가 유지됐는가
```

**배포되는 것은 `remedy.exe` 하나와 룰 한 벌이다.** 실행 파일은 CRT 정적 링크라
재배포 패키지가 필요 없고, **네트워크를 말하는 코드가 링크되지 않는다** — 임포트
전수를 `cargo xtask static` 이 매번 확인한다.

새 위협 대응은 **`plugin.yaml` 과 `rules/*.yar` 만 배포**하면 된다. 코어를 다시
만들지 않는다.

### 아직 없는 것

| | |
|---|---|
| **정식 코드서명 인증서** | 발급 대기. **기능은 서명 없이 전부 동작한다**(2026-09-02) — 서명이 없다는 이유로 치료를 막지 않고, 대신 매 실행에서 *"이 바이너리에 서명이 없다. 공식 배포본이 아니다"* 라고 말한다. 공식 홈페이지 배포본에만 서명한다 |
| 서명된 룰만 로드 (P10-A2) | 검증(`plugin verify`)은 섰다. **강제가 도는 자리가 안내 모드 하나**다 — 인자 없이 실행하면 옆에 놓인 꾸러미 중 검증을 통과한 것만 쓴다. `run --plugin <경로>` 로 직접 준 것은 **서명을 보지 않는다.** 릴리스 키가 서야 켠다 |
| 사내 분석시스템 연동 (P13) | `enrich` — 조회는 사내에서 실행한다는 결정(D9) 아래 설계만 서 있다. **치료 경로는 이것 없이 완결이다** |
| GUI (P15) | CLI 만 |

**제출 기능은 제품 범위 밖이다** (2026-08-28). 분석가가 손으로 올리고 remedy 는
`support-bundle` 까지만 만든다 — 근거는 설계-09 "제출을 제품 밖으로".

개발 순서와 각 Phase의 완료 조건은
[`docs/design/설계-09-개발-Phase.md`](docs/design/설계-09-개발-Phase.md).

## 시연

시연 대본(내부 문서)이 기계 준비부터 단계별 진행까지 들고 있다. 준비는 `testbed/harness/host/New-DemoMachine.ps1` 이 한다.

## 설계의 척추

이 저장소를 이해하려면 아래 세 가지만 알면 된다.

1. **파괴 동작은 실행 전에 계획으로 완전히 확정된다.**
   `collect → evaluate → plan → apply` 각 단계가 파일 아티팩트로 나뉘며,
   `apply` 는 `plan.json` 에 있는 것만 수행한다. 드라이런의 정확성·삭제 상한의
   사전 차단·감사 완전성이 전부 여기서 파생된다.
2. **스크립트는 읽고, 룰은 쓴다.** 플러그인은 관찰과 제거 대상만 선언하고,
   순서·백업·프로세스 종료는 코어가 정한다.
3. **되돌리기가 지우기보다 먼저다.** 격리·복원이 첫 파괴 동작보다 앞선 Phase에
   완성된다.

## 저장소 규칙

규칙은 문서가 아니라 CI가 지킨다.

```
cargo xtask all      # 아홉을 한 번에 — arch · unsafe · trace · schema · guide ·
                     #   console-doc · snapshots · 실기기 · plugin-lock
cargo xtask arch     # 금지 의존 6건 (설계-04 §1에서 읽는다)
cargo xtask trace    # 설계 인벤토리 ↔ Phase 계획 대조
cargo xtask static   # 배포될 바이너리의 임포트 전수 — 네트워크가 없음을 확인
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

`arch` 의 금지 의존 목록과 `trace` 의 인벤토리는 **코드에 박혀 있지 않고 설계
문서에서 읽는다.** 같은 사실을 두 곳에 적으면 반드시 갈라지기 때문이다.

## 문서

| 문서 | 내용 |
|---|---|
| `docs/design/설계-00` | 위협 모델 · 범위 · 지원 대상 |
| `docs/design/설계-01` | 아키텍처 결정 (D1~D10) |
| `docs/design/설계-02` | SDK 계약 — 플러그인 스키마 |
| `docs/design/설계-03` | 안전장치 · 출시 게이트 |
| `docs/design/설계-04` | 저장소 구조 · testbed |
| `설계-05` | 사내 분석시스템 연동 — **내부 문서**, 공개 트리에 없다 |
| `docs/design/설계-06` | 플러그인 작성 가이드 설계 |
| `docs/design/설계-07·08` | 플러그인 워크스루 (설계 검증) |
| `docs/design/설계-09` | **개발 Phase — 여기서 시작한다** |

읽는 사람에 따라 갈린다 — **설계 문서를 읽지 않아도 되게** 만든 자리다.

| 누가 | 어디로 |
|---|---|
| **처음 오는 사람** (과 AI) | [`docs/remedy-전체-그림.md`](docs/remedy-전체-그림.md) — 기능·동작·배포·구조를 다이어그램으로 |
| 현장에서 **돌리는** 사람 | [`docs/operator.md`](docs/operator.md) — 배포·실행·되돌리기·신고 한 장 |
| 룰을 **쓰는** 사람 | [`docs/plugin-guide/`](docs/plugin-guide/README.md) |
| 코어를 **고치는** 사람 | [`docs/개발-안내.md`](docs/개발-안내.md) — 커밋 전 검증·빌드·채점·화면에서 걸리는 것들 |

취약점 신고는 [`SECURITY.md`](SECURITY.md).
