# 리눅스 자가복제 웜(.syncd) 탐지·치료 플러그인

```yaml
schema_version: 1
id: linux-selfcopy-worm
version: 1.0.0
min_core: "1.0.0"
platforms: [linux]
name:
  ko: "리눅스 자가복제 웜(.syncd) 탐지·치료"
  en: "Linux self-copying worm (.syncd) detect and remediate"

# 권한 상한 — 여기 밖은 볼 수도 지울 수도 없다. 성능이 아니라 권한 상한이다.
# 복제본이 관측된 다섯 자리 + 재확산 드롭인이 사는 /etc/cron.d 를 덮는다.
# persistence(cron)는 이 상한과 무관하게 수집되지만, 아래 cronfile 규칙이 그
# 드롭인을 **파일로** 지우므로(요구 2) /etc/cron.d 가 상한 안에 있어야 한다.
# (좁은 쪽은 아무도 경고하지 않으니 실기기 `scan` 한 번으로 커버를 확인한다.)
scan_roots:
  - "/usr/local/bin"
  - "/usr/local/lib"
  - "/opt/backup"
  - "/var/tmp"
  - "/srv/data"
  - "/etc/cron.d"

subjects: [file, persistence]

detect:
  # ── 근거 1 (뿌리) : 복제본을 '내용'으로 잡는다 ────────────────────────
  # 다섯을 하나로 묶는 유일한 사실은 "서로 같은 내용(= 같은 sha256)" 이다.
  # 자리로도(다섯이 전부 다른 폴더), 이름으로도(정상 파일 셋도 이름에 sync)
  # 못 가른다. 그래서 **해시**로만 잡는다 — 상한 안의 여섯 번째 복제본도
  # 어디에 있든 함께 잡히고, 내용이 다른 정상 파일·개발 PC 파일은 안 걸린다.
  - id: copy
    subject: file
    where:
      - field: sha256
        op: in
        value:
          # ↓↓ 분석가가 채운다 — 검체의 공유 sha256(소문자 64자리)을 그대로 붙인다.
          #    관측 보고는 "다섯이 같은 내용 지문"이라는 '사실'만 주고 값은 주지
          #    않았다. 지어내지 않는다(30-antipatterns §10·§13, 00-invariants §5
          #    "지우는 것은 확인된 증거에만"). 이 줄을 실제 해시로 바꾸기 전에는
          #    copy 가 아무것도 매치하지 않는다.
          - "FILL_IN_lowercase_sha256_of_the_selfcopy_worm_sample"
          # 변종 몫 해시가 더 있으면 같은 목록에 줄로 덧붙인다(피드에 섞여도 됨).

  # ── 근거 2 (뿌리) : 재확산을 일으키는 cron 을 잡는다 ──────────────────
  # 복제본과 **독립된** 근거다(파일 내용 vs cron 항목 — 서로 다른 대상).
  # 정상 cron 둘과 모양이 같다: 같은 /etc/cron.d, 같은 틀, 둘 다 root.
  # 가르는 것은 "무엇을 실행하는가"뿐이다 — 이 줄만 웜을 다시 뿌린다(--spread).
  # 이름의 sync 로 가르지 않으므로 vendor-archive.sh --nightly 나 배포판 기본
  # cron(e2scrub_all 등)은 걸리지 않고, 검체 없는 개발 PC 에도 매치가 없다.
  - id: spreader
    subject: persistence
    where:
      all:
        - { field: source,          op: starts_with, value: "/etc/cron.d/" }
        - { field: linux.cron.line, op: contains,    value: "--spread" }
    capture:
      # 드롭인 파일 경로를 '필드 그대로' 뽑아 아래 cronfile 에 넘긴다.
      src: "source"

  # ── 치료 전용(판정에는 안 씀) : 그 드롭인을 파일째 지우기 위한 규칙 ──────
  # cron 을 persistence 로 지우면 **그 줄만** 빠지고 빈 파일이 남는다. 이
  # 드롭인은 통째로 검체의 것이므로(정상 cron 은 다른 파일) 파일로 지운다(요구 2).
  # 리터럴 경로를 적지 않는다 — spreader 가 증거에서 뽑은 경로만 가리킨다.
  - id: cronfile
    subject: file
    where:
      - { field: path, op: equals, value: "${spreader.src}" }

# 독립적인 두 근거의 논리곱. 점수 임계값 문법은 없다.
# 하나뿐이면 그 룰의 오탐이 곧바로 삭제가 된다(00-invariants §4).
# 둘 다 '뿌리' 규칙이라 청정 코퍼스가 둘 다 시험한다(40-review-checklist §7).
verdict:
  require: "copy and spreader"

remediate:
  # 순서는 적지 않는다 — 프로세스 종료·백업·삭제 차례는 코어가 정한다.
  # 플러그인은 '무엇을 없앨 것인가'만 선언한다.
  remove:
    - { ref: copy }       # 해시 일치 복제본 **전부** 격리 → 하나도 안 남긴다(요구 1)
    - { ref: cronfile }   # 재확산 드롭인을 **파일째** 격리(요구 2)
  # copy·cronfile 둘 다 file.quarantine_only(위험 low·되돌릴 수 있음)로 간다 →
  # 오탐이어도 `remedy restore --run <id>` 로 복구된다(요구 3). 삭제가 아니라 격리.
  verify:
    # 자가복제 위협이라 "경로가 비었나"가 아니라 **재판정**으로 확인한다. 재부팅
    # 뒤 같은 플러그인이 다시 판정하면 재발 신호이므로 자동 재치료 없이 사람이 본다.
    after_reboot: true
```

## 설명 (짧게)

- **판별자는 오직 공유 sha256.** 다섯 복제본을 하나로 묶는 유일한 사실은 "서로 내용이 같다"는 것뿐이다. 위치는 다섯이 전부 다른 폴더라 못 가르고, 이름은 정상 파일 셋에도 `sync`가 들어 있어 못 가른다. 그래서 `copy` 규칙은 `sha256 in [...]` 하나로만 잡는다. 이러면 상한 안에 생긴 **여섯 번째 복제본도 위치와 무관하게** 같이 잡히고(일반화), 해시가 다른 정상 파일은 안 걸린다.
- **재확산 cron은 파일째 제거.** `/etc/cron.d/sync-agent` 는 10분마다 복제본을 실행해 다시 퍼뜨린다. persistence로 지우면 **그 줄만** 빠지고 빈 파일이 남으므로, 그 드롭인 **파일 전체**를 격리한다(요구 2). 리터럴 경로 대신 `spreader` 가 증거에서 뽑은 `${spreader.src}` 만 가리켜, 정상 cron 파일은 절대 건드리지 않는다.
- **정상 look-alike 4종·정상 cron 2종이 안전한 이유.** 어디서도 "같은 폴더" 나 "이름에 sync" 를 근거로 쓰지 않는다. `backup-sync`·`libsync.so.1`·`vendor-archive.sh`·`nightly-sync.log` 는 해시가 달라 `copy` 에 안 걸리고, `logrotate-sync`(`--nightly`)·`e2scrub_all` 은 `--spread` 가 없어 `spreader` 에 안 걸린다.
- **되돌릴 수 있음(요구 3).** `copy`·`cronfile` 둘 다 `remove`의 `ref` 로만 넘겨 `file.quarantine_only`(위험 low, 가역)로 처리된다. 삭제가 아니라 격리이므로 오탐이어도 `remedy restore --run <id>` 로 복구된다.
- **상한 접촉 수.** 이 검체는 top-level 폴더를 정확히 다섯 곳 건드린다(툴 상한과 동일). 한 곳이라도 더 생기면 코어가 멈추고 사람이 본다.
- **sha256 값은 지어내지 않았다.** 관측 보고는 "다섯이 같은 지문" 이라는 **사실만** 주고 hex 값은 주지 않았다. 없는 증거를 꾸며 넣으면 되레 아무것도 매치하지 않거나 엉뚱한 파일을 지울 위험이 있으므로(30-antipatterns §10·§13, 00-invariants §5), 플레이스홀더 `FILL_IN_...` 로 두었다. **분석가가 수집 검체의 실제 소문자 sha256 으로 교체해야** `copy` 가 작동한다.

## 자가점검 3문항

1. **개발 PC(검체 없음)에서 이 규칙은 무엇을 매치하나?** — 아무것도 매치하지 않는다. `copy` 는 검체의 특정 해시에만 반응하고, `spreader` 는 `/etc/cron.d/` 에서 `--spread` 를 실행하는 줄에만 반응한다. 둘 다 없는 깨끗한 기기에서는 verdict가 성립하지 않는다.
2. **verdict가 근거 하나에만 기대나?** — 아니다. `copy`(파일 내용)와 `spreader`(cron 항목)는 **서로 다른 subject의 독립 근거**이고, 둘 다 `from:`/`${}` 로 파생된 자식이 아닌 **뿌리 규칙**이라 청정 코퍼스가 둘 다 검증한다. 논리곱(`copy and spreader`)이므로 한쪽 오탐만으로는 삭제가 일어나지 않는다.
3. **모든 삭제 대상이 증거에서 나왔나?** — 그렇다. `copy` 는 해시 일치 복제본 자신이고, `cronfile` 은 `spreader` 가 증거에서 뽑은 `${spreader.src}` 경로의 파일이다. 리터럴 경로로 지우는 것은 하나도 없다.
