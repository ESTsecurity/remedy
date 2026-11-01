```yaml
schema_version: 1
id: linux-syncd-selfcopy-worm
version: 1.0.0
min_core: "1.0.0"
platforms: [linux]
name:
  ko: "자가복제 웜(.syncd) 제거"
  en: "Self-replicating worm (.syncd) removal"

# 읽기·삭제 권한 상한.
# 복제본이 관측된 상위 디렉터리와, 유발 cron 정의 파일이 놓인 자리만 연다.
# 삭제는 아래 sha256 일치로 정밀하게 가려지므로, 이 범위를 열어도
# 지문이 다른 정상 파일은 건드리지 않는다.
scan_roots:
  - "/usr/local"        # 복제본: /usr/local/bin/.syncd · /usr/local/lib/.syncd
  - "/opt"              # 복제본: /opt/backup/.syncd
  - "/var/tmp"          # 복제본: /var/tmp/.syncd  (/var 전체는 넓어 관측 자리만)
  - "/srv"              # 복제본: /srv/data/.syncd
  - "/etc/cron.d"       # 유발 cron 정의 파일 — 통째로 치운다

subjects: [persistence, file]

detect:
  # 유발자 — 10분마다 복제본을 실행하며 자기를 뿌리는 cron.
  # /etc/cron.d 의 정상 cron 둘(logrotate-sync · e2scrub_all)은 .syncd 를
  # 실행하지도, --spread 도 쓰지 않아 세 조건을 함께 만족하지 못한다.
  - id: cron
    subject: persistence
    where:
      all:
        - { field: source,  op: starts_with, value: "/etc/cron.d/" }
        - { field: command, op: ends_with,   value: "/.syncd" }
        - { field: args,    op: contains,    value: "--spread" }
    capture:
      exe: "command"       # 복제본 하나의 실제 경로 — 여기서 지문을 뜬다
      dropfile: "source"   # cron 정의 파일 경로 — 통째로 치운다

  # 지문의 원천 — cron 이 부르는 바로 그 파일에서 sha256 을 뽑는다.
  # (값을 모르는 지문은 아는 자리 하나에서 떠서 나머지를 모은다. 지어내지 않는다.)
  - id: seed
    subject: file
    where:
      - { field: path, op: equals, value: "${cron.exe}" }
    capture:
      digest: "sha256"

  # 복제본 전부 — 같은 지문을 가진 파일을 상한 안에서 모은다.
  # 자리가 제각각이어도, 상한 안이라면 여섯 번째가 있어도 같은 지문이면 걸린다.
  # 이름이 닮은 정상 파일 넷(backup-sync · libsync.so.1 · vendor-archive.sh ·
  # nightly-sync.log)은 크기도 내용도 달라 지문이 다르므로 걸리지 않는다.
  - id: clones
    subject: file
    where:
      - { field: sha256, op: equals, value: "${seed.digest}" }

  # cron 정의 파일 자체.
  # 이 파일은 통째로 검체의 것이라(정상 cron 은 다른 파일이다) 줄만 빼면
  # 빈 파일이 남는다. 파일로 잡아 통째로 격리한다.
  - id: cronfile
    subject: file
    where:
      - { field: path, op: equals, value: "${cron.dropfile}" }

# 두 독립 근거의 논리곱:
#   (1) cron              — 되살리는 지속성. 이것을 남기면 나머지를 다시 부른다.
#   (2) count(clones) >= 2 — 내용이 같은 파일이 둘 이상이라는 사실 = 자가복제.
# 복제본이 하나뿐이면(자가복제의 증거가 아니면) 판정이 서지 않는다.
verdict:
  require: "cron and count(clones) >= 2"

remediate:
  remove:
    - { ref: clones }      # 복제본 전부 격리 — 하나도 남기지 않는다(되돌릴 수 있다)
    - { ref: cronfile }    # 유발 cron 파일 통째로 격리 — 다시 뿌리는 자리를 없앤다
  verify:
    after_reboot: true     # 재부팅 뒤 재판정 — 놓친 지속성으로 되살아나면 사람이 본다

# 복제본은 분석에 유용한 검체다. 자동 전송은 없고, 손으로 올릴 사람에게만 표시한다.
submit_hint:
  samples: [clones]
  confidentiality_min: 1
```

## 설명

**가르는 지점은 자리도 이름도 아니라 "다섯이 서로 같다"는 사실 하나다.** 그래서 복제본을 리터럴 다섯 줄로 적지 않고 **지문(sha256)으로** 모은다.

- **탐지 사슬** — `cron`(유발 cron) → `seed`(그 cron 이 부르는 파일에서 sha256 추출) → `clones`(같은 지문을 가진 파일 전부). `clones` 는 상한 안이라면 자리가 어디든, 여섯 번째 복제본이라도 같은 지문이면 잡으므로 "자리 다섯 줄"짜리 답이 놓치는 변종에도 버틴다. 이름이 닮은 정상 파일 넷은 크기·내용이 달라 지문이 다르므로 전부 빠진다.
- **판정** — `cron and count(clones) >= 2`. 두 근거가 서로 독립이다: (1) 되살리는 지속성(cron), (2) 내용이 같은 파일이 둘 이상이라는 자가복제의 사실. `count(...) >= 2` 로 못박아, 똑같은 파일이 하나뿐인(=자가복제의 증거가 아닌) 기계에서는 판정이 서지 않는다.
- **치료** — 복제본 전부와 cron 정의 파일을 **격리**한다(`file` 의 `ref` → `file.quarantine_only`, 위험 low·되돌릴 수 있음). cron 은 줄만 빼면 빈 파일이 남으므로, 통째로 검체의 것인 그 파일을 `file` 규칙으로 잡아 통째로 치운다. `verify.after_reboot` 로 놓친 지속성이 되살리면 사람이 보도록 한다.

**자가 점검 세 질문**

- *검체 없는 개발자 PC 에서 무엇을 매치하나?* — 아무것도. 뿌리 규칙 `cron` 이 `/etc/cron.d/` 안의 `.syncd --spread` 세 조건을 함께 요구하므로 청정 기계에서 서지 않고, 그러면 `seed`·`clones`·`cronfile` 도 평가되지 않는다. 파괴 Action 0건.
- *판정이 근거 하나에 기대나?* — 아니다. 지속성(cron)과 파일 내용(복제 사실) 두 독립 근거의 논리곱이다.
- *지우는 대상이 전부 증거에서 나왔나?* — 그렇다. `cronfile` 은 `${cron.dropfile}`, `clones` 는 `${seed.digest}` 에서 파생된다. 리터럴 절대 경로는 제거 대상에 없다.

**안 쓴 것** — YARA(지문만으로 충분하므로 본문 수집 불필요), `dir.delete_recursive`(리눅스에 없고, 복제본은 사용자 데이터와 섞인 폴더에 흩어져 있어 폴더 통삭제는 부적절), `persistence.delete`(줄만 빼 빈 파일을 남기므로 cron 파일에는 부적합). 문서에 없는 필드·연산자·subject·Op 는 쓰지 않았다.
