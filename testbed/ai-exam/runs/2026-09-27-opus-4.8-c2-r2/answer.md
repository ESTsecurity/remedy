아래는 `remedy` 전용백신 플러그인 하나다. **로그인마다 살아나 알려진 서버에 신호를 보내는 시스템 전역 자동 시작 항목**을 탐지하고, 그 항목과 같은 폴더의 검체 파일 둘만 격리한다.

```yaml
schema_version: 1
id: c2-beacon-autostart-linux
version: 1.0.0
min_core: "1.0.0"
platforms: [linux]
name:
  ko: "로그인 C2 비컨 자동 시작 항목 제거"
  en: "Login C2 beacon autostart removal"

# 읽기 권한 상한. 페이로드가 /opt 아래에 자리잡는다(관측 §페이로드).
# 폴더 이름 꼬리(.cache-9f2)는 감염마다 바뀌므로 부모인 /opt 를 상한으로 둔다.
# autorun·indicator 는 scan_roots 와 무관하게 수집되므로(10-manifest §무엇에
# 걸리고 무엇에 안 걸리는가) 자동 시작 폴더 경로는 여기 적지 않는다 —
# 이 상한을 받는 것은 file 뿐이다.
scan_roots:
  - "/opt"

subjects: [indicator, autorun, file]

detect:
  # ── 근거 1 : 알려진 C2 서버에 붙는다 ──────────────────────────────
  # 수집기가 명령줄에서 지표를 미리 뽑아 둔다(20-detect §알려진 지표 목록).
  # 자리(/opt·점 폴더)·모양·"서버 주소가 있다" 로는 못 가른다 — 관측 §오탐
  # 위험이 그렇게 가르면 청정 /opt 의 자동 갱신 항목이 전부 걸린다고 했다.
  # 목록에 있는 서버만 정상과 악성을 가른다. 변종이 쓰는 나머지 둘도 함께 둔다.
  - id: beacon
    subject: indicator
    where:
      all:
        - { field: kind, op: equals, value: "domain" }
        - field: value
          op: in
          value:
            - cdn.evil-metrics.example
            - api.evil-metrics.example
            - relay.evil-metrics.example

  # ── 없앨 대상 : 그 서버를 실은 자동 시작 항목 ─────────────────────
  # indicator 자체는 없앨 수 없다(20-detect §알려진 지표 목록) — 없애는 것은
  # 그것을 실은 항목이다. XDG autostart 는 autorun 으로 모인다(REFERENCE.md
  # subject 표). 목록의 서버 셋 중 하나를 명령줄에 가진 항목만 짚으므로,
  # updates.vendor.example 를 쓰는 정상 vendor-update.desktop 은 걸리지 않는다.
  # 이름(cache-sync)·표시 이름은 조건에 넣지 않는다 — 관측이 그것으로는 못
  # 가른다고 했다.
  - id: autostart
    subject: autorun
    where:
      any:
        - { field: command, op: contains, value: "cdn.evil-metrics.example" }
        - { field: command, op: contains, value: "api.evil-metrics.example" }
        - { field: command, op: contains, value: "relay.evil-metrics.example" }

  # ── 근거 2 : 알려진 검체 다이제스트를 가진 파일 ───────────────────
  # 근거 1(명령줄의 서버)과 독립이다 — 파일 내용의 해시에서 온다.
  # /opt 아래에서 이 해시를 가진 파일만 걸린다. notes.txt 는 목록에 없어 빠지고
  # (관측 §페이로드), 청정 기계의 /opt 실행 파일도 걸리지 않는다.
  # 소문자 sha256 로 적는다(20-detect §해시 목록). 이 기계에 없는 변종 몫 둘이
  # 섞여도 된다.
  - id: payload
    subject: file
    where:
      - field: sha256
        op: in
        value:
          - fec8aa606ec99721bd2a5153d2973816484c18b755e23fd508b1146d954195c7
          - 384670229c221ff5384c8b7691d711efe8763a41c48490f184727d334e95f5fe
          - 7a1c0e4d9b2f6853a0c7e1b4d8f2a6c9e3b5d7f1a4c8e0b2d6f9a3c5e7b1d4f8
          - c3e9a1f7b5d2064e8a0c2f4b6d8e1a3c5f7b9d0e2a4c6f8b1d3e5a7c9f0b2d4e

# 독립적인 두 근거의 논리곱(00-invariants §4):
#   (목록의 C2 에 붙는다) and (목록의 해시를 가진 파일이 있다).
# 한쪽이 헛돌면 판정이 무너지고 그것이 scan.json 에 보인다.
verdict:
  require: "beacon and payload"

# 순서는 코어가 정한다(22-remediate). 무엇을 없앨지만 선언한다.
# 자동 시작 항목이 유발자이므로 코어가 그것을 페이로드보다 먼저 처리한다
# (autorun.remove 의 regenerator=true, REFERENCE.md ops 표).
remediate:
  remove:
    # 자동 시작 항목의 정의를 없앤다 → autorun.remove. 격리되어 되돌릴 수 있다.
    - { ref: autostart }
    # 검체 파일 둘만 격리 → file.quarantine_only(가장 덜 위험한 파일 Op).
    # 폴더째 지우거나 폴더 안을 통째로 격리하지 않는다 — 같은 폴더의 notes.txt
    # 가 함께 사라지고, 그 폴더 전체가 검체의 것이라는 관측 근거가 없다
    # (22-remediate §재귀 삭제, ex03 과 같은 판단). 덧붙여 dir.delete_recursive
    # 는 Linux 에서 아직 없다(ops 표). 해시로 짚은 두 파일만 대상이 된다.
    - { ref: payload }
  # 치료 뒤 재부팅하여 같은 플러그인이 다시 판정하는지 본다 — 재발이면 우리가
  # 놓친 지속성 경로가 있다는 신호다(22-remediate §재부팅 후 재평가).
  # systemd init 이 아닌 기계에서는 코어가 건너뛰고 직접 부를 명령을 알려 준다.
  verify:
    after_reboot: true

# 손으로 분석에 올릴 때 볼 힌트(23-collect-and-submit §submit_hint).
# 자동 제출은 없다. 고객 /opt 에서 나온 검체라 기밀 하한을 올려 둔다.
submit_hint:
  samples: [payload]
  confidentiality_min: 1
```

## 이렇게 짠 이유 (짧게)

**두 독립 근거의 논리곱.** 판정은 `beacon and payload` 다 — 명령줄에서 뽑힌 C2 지표(근거 1)와 파일 내용의 해시(근거 2)는 서로 다른 관측이라 독립이다(40-review-checklist 1번). 한쪽만으로는 삭제가 서지 않는다.

**목록만으로 가른다.** 관측 §오탐 위험이 자리(`/opt`·점 폴더)·모양·"서버 주소가 있다" 로 가르면 청정 기계의 자동 갱신 항목이 전부 걸린다고 못박았다. 그래서 `beacon`·`autostart` 는 위협 정보가 준 **서버 목록**에만, `payload` 는 **다이제스트 목록**에만 건다. 이름(`cache-sync`)·표시 이름은 조건에 넣지 않았다 — 관측이 그것으로는 못 가른다고 했다.

**없앨 것은 지표가 아니라 그것을 실은 항목.** XDG autostart 는 `autorun` 으로 모인다(REFERENCE.md subject 표). `indicator` 는 판정에만 쓰고(없앨 수 없다), 실제로 없애는 것은 그 서버를 명령줄에 가진 `autorun` 항목이다. 정상 `vendor-update.desktop`(`updates.vendor.example`)은 목록 밖이라 빠진다.

**폴더째 지우지 않는다.** `/opt/.cache-9f2/` 에 사용자 파일 `notes.txt` 가 섞여 있고, 그 폴더 전체가 검체의 것이라는 관측 근거가 없다(22-remediate §재귀 삭제, ex03 과 같은 판단). 그래서 재귀 삭제 대신 **해시로 짚은 두 파일만** 격리한다 — `notes.txt` 는 대상이 아니다. (덧붙여 `dir.delete_recursive` 는 Linux 에서 아직 없다.)

**되돌릴 수 있게.** 검체 둘은 삭제가 아니라 격리(`file.quarantine_only`), 자동 시작 항목은 정의 제거(`autorun.remove`) — 둘 다 격리 컨테이너에 담겨 오탐이면 `remedy restore` 로 되돌린다.

**지어내지 않았다.** 쓴 subject(`indicator`·`autorun`·`file`)·필드(`kind`·`value`·`command`·`sha256`)·연산자(`equals`·`contains`·`in`)·Op(`autorun.remove`·`file.quarantine_only`)는 전부 `machine/` 카탈로그에 있고 Linux·현재 코어(P12)에서 수집·수행된다.

## 답을 내기 전 자가 점검

- **검체 없는 개발자 PC 에서 무엇을 매치하나?** 아무것도. 서버 목록에 없는 도메인, 다이제스트 목록에 없는 해시뿐이라 `beacon`·`payload` 가 0건이고 판정이 서지 않는다. `/opt` 를 훑어도 지울 것이 없다. `/opt` 아래 자동 갱신 항목·점 폴더·서명된 실행 파일은 목록과 어긋나 전부 통과한다.
- **판정이 근거 하나에만 기대나?** 아니다. C2 지표와 파일 해시, 서로 독립인 둘의 논리곱이다.
- **지우는 대상이 전부 증거에서 나왔나?** 그렇다. `ref: autostart`·`ref: payload` 는 매치된 규칙을 가리키고, 리터럴 경로·재귀 삭제는 쓰지 않았다.

> **서명 전 실기기 확인 한 가지(40-review-checklist §6).** `scan_roots: /opt` 는 넓지 않지만, 코퍼스 시험은 `scan_roots` 확장을 재지 못한다. 서명 전에 실기기에서 `remedy scan` 을 한 번 돌려 `/opt` 아래 `file` 수집이 실제로 도는지(=페이로드가 잡히는지) 확인하고 그 결과를 첨부한다.
