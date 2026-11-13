<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# 탐지 규칙 쓰기

선행: `01-quickstart.md` · 전수는 `machine/subjects.json` · `machine/catalog.json`

## 규칙 하나의 뼈대

```yaml
- id: task                    # ${…} 로 가리킬 이름. 매니페스트 안에서 유일해야 한다
  subject: persistence        # 무엇을 훑는가
  from: "${다른규칙.capture}"  # (선택) 훑을 범위를 증거에서 좁힌다
  where: …                    # 조건
  exclude: [ … ]              # (선택) 술어 목록 — 하나라도 맞으면 그 레코드는 매치가 아니다(all · any 는 못 쓴다)
  capture:                    # (선택) 증거에서 값을 뽑아 다른 규칙에 넘긴다
    script: "args | first_path"
  score: 90                   # (선택) 보고 정렬용. 판정 게이트가 **아니다**
  label: { ko: …, en: … }     # (선택) 찾은 줄 아래의 문구 — 예: 해당 CVE (코어 1.13.0)
```

## `where` 의 세 가지 모양

```yaml
# 1) 목록 — 전부 만족해야 한다 (논리곱)
where:
  - { field: command, op: matches, value: '(?i)\\node\.exe$' }
  - { field: args,    op: matches, value: '(?i)\.js("|\s|$)' }

# 2) all: — 위와 같다. 중첩할 때 쓴다
where:
  all:
    - { field: command, op: matches, value: '(?i)\\node\.exe$' }
    - any:
        - { field: args, op: contains, value: "--hidden" }
        - { field: args, op: contains, value: "--silent" }

# 3) any: — 하나만 만족하면 된다 (논리합)
```

**목록과 `all:` 은 같은 뜻이다.** 목록이 짧을 때 읽기 쉽고, `any:` 를 안에 넣어야
할 때 `all:` 이 필요하다.

## 부모와 자식 — `from` 으로 좁힌다

랜덤 폴더 이름을 리터럴로 적을 수 없다. **부모 규칙이 증거에서 경로를 뽑고,
자식이 그 안에서만 찾는다.**

```yaml
- id: task
  subject: persistence
  where:
    - { field: command, op: matches, value: '(?i)\\node\.exe$' }
  capture:
    script: "args | first_path"     # 인자에서 첫 경로를 뽑는다
    dir: "${script} | dirname"      # 그 경로의 폴더

- id: payload
  subject: file
  from: "${task.dir}"               # ← 이 폴더 안에서만 훑는다
  where:
    - { field: path, op: ends_with, value: ".js" }
```

부모 증거 하나마다 **독립된 그룹**이 생긴다. 자식은 자기 그룹 안에서만 붙는다 —
감염이 둘이면 그룹도 둘이고, 서로의 증거가 섞이지 않는다.

`from` 이 가리킨 경로가 `scan_roots` 밖이면 **그 그룹이 제외된다.** 경고가
아니라 제외다 — 파생 경로는 공격자가 값에 영향을 줄 수 있다.

### `${}` 두 형태

| 쓰는 법 | 가리키는 것 |
|---|---|
| `${script}` | **같은 규칙**의 capture |
| `${task.dir}` | **다른 규칙**의 capture |

선언 순서는 상관없다 — 의존 관계로 풀린다.

## `from` 은 `path` 가 있는 subject 에만 통한다

**`from` 은 레코드의 `path` 필드를 읽어** 그 디렉터리 안인지 본다. `path` 가
없는 subject 는 빈 문자열과 비교되어 **모든 레코드가 걸러진다** — 그 규칙은
영영 매치되지 않는다.

| `from` 을 쓸 수 있다 | `file` · `text_config` · `structured_config` · `shortcut` · `browser_extension` |
|---|---|
| **쓸 수 없다** | `persistence` · `autorun` · `process` · `service` · `registry_value` · `av_exclusion` · 그 밖에 `path` 가 없는 전부 |

전수는 `machine/subjects.json` 에서 `path` 필드가 있는지로 확인한다.
`plugin lint` 가 이 경우를 오류로 막는다.

## 경로가 아닌 것을 부모에 묶는 법

레지스트리 값·프로세스·예외 목록은 `from` 으로 못 묶는다. **`where` 의 `value`
에 `${…}` 를 넣는다.**

```yaml
- id: task
  subject: persistence
  where:
    - { field: command, op: matches, value: '(?i)\\node\.exe$' }
  capture:
    script: "args | first_path"
    dir: "${script} | dirname"

# Run 값 — 그 폴더를 가리키는 것만 잡는다
- id: runkey
  subject: autorun
  where:
    - { field: command, op: contains, value: "${task.dir}" }

# Defender 제외 — 그 폴더가 등록된 것만
- id: av-exclusion
  subject: av_exclusion
  where:
    - { field: value, op: contains, value: "${task.dir}" }

# 그 스크립트를 물고 있는 프로세스
- id: payload-process
  subject: process
  where:
    all:
      - { field: image_path, op: matches,  value: '(?i)\\node\.exe$' }
      - { field: args,       op: contains, value: "${task.dir}" }
```

**보간은 부모 그룹의 capture 로 풀린다.** 그래서 감염이 둘이면 각 그룹이 자기
폴더 값으로 따로 풀리고, 서로의 증거가 섞이지 않는다 — `from` 과 같은 격리다.

> **리터럴 경로 조각으로 대신하지 않는다.** `value: '\AppData\Local\Programs\'`
> 처럼 적으면 **다른 감염 인스턴스의 항목까지 이 그룹에 붙는다.** 보간은
> 그 폴더 하나만 가리킨다.

> 값이 **열거로 정해진** subject 도 있다. `boot_config` 가 그렇고, 경로가 없어
> `from` 도 치료 대상도 되지 않는다 — `10-manifest.md` 참조.

> **부모가 될 수 없는 자리도 있다.** `autorun.command` 는 `"…\node.exe"
> "…\x.js"` 가 한 문자열이고 `args` 필드가 없다. capture 함수에 **두 번째
> 경로를 집는 것이 없어** 스크립트 경로를 뽑지 못한다 — `first_path` 는
> `node.exe` 를 집는다. 예약 작업이 이미 지워지고 Run 값만 남은 기계는
> 그래서 부모가 서지 않는다. 없는 함수를 지어내지 말고 이 한계를 적을 것.

### 기준 파일과 견준다 — `gt` · `lt`

필드를 **그대로** capture 해 `${…}` 로 넣으면 레코드끼리 견줄 수 있다. 같은 폴더의
정상 파일을 자로 삼는 식이다.

```yaml
- id: base                   # 자 — remove 에 넣지 않는다
  subject: file
  where: [{ field: path, op: equals, value: 'C:\ProgramData\Vendor\Vendor.exe' }]
  capture: { when: "mtime", bulk: "size" }
- id: newer
  subject: file
  where:
    - { field: path,  op: starts_with, value: 'C:\ProgramData\Vendor\' }
    - { field: mtime, op: gt, value: "${base.when}" }
    - { field: size,  op: lt, value: "${base.bulk}" }
```

`gt` · `lt` 는 **수**와 **시각**(`YYYY-MM-DDTHH:MM:SSZ`, RFC3339 UTC)만 견준다. 둘을
섞거나 다른 문자열이면 미매치이고 그 사실이 보고된다.

### 값을 모르는 지문 — 아는 자리에서 capture 해 모은다

같은 내용의 파일이 여러 자리에 있는데 **값은 모른다**면 값을 지어내거나 자리 표시로 비워
두지 않는다 — 둘 다 아무것도 맞히지 않는다. **아는 자리 하나**(정기 작업이 부르는 그
파일)에서 `sha256` 을 capture 해 나머지를 `equals` 로 모은다.

```yaml
- id: trigger                 # 정기 작업
  subject: persistence
  where:
    - { field: command, op: starts_with, value: "/opt/.cache-" }
  capture: { exe: "command" }
- id: seed                    # 그 파일 — 지문은 여기서
  subject: file
  where: [{ field: path, op: equals, value: "${trigger.exe}" }]
  capture: { digest: "sha256" }
- id: clones                  # 같은 지문 전부
  subject: file
  where: [{ field: sha256, op: equals, value: "${seed.digest}" }]
```

`persistence` 의 `command` 는 실행 파일만 담는다(인자는 `args`). cron 줄 전체
(`linux.cron.line`)에 `first_path` 를 걸면 일정 칸 `*/10` 을 경로로 집는다 — 쓰지 않는다.

---

## YARA — 본문이 있어야 돈다

**여기가 가장 자주 조용히 깨지는 자리다.**

```yaml
- id: payload
  subject: file
  from: "${task.dir}"
  where:
    - { yara: "rules/evilai.yar:evilai_locust_js" }

collect_extra:
  - { ref: payload-file, content: true }    # ← 이것이 없으면 위 규칙은 돌지 않는다
```

### 값의 형식

`rules/<파일>.yar:<룰 이름>` 이다. 파일은 플러그인 디렉터리 기준이고, 룰 이름은
그 파일 안의 **공개 룰**이다(`private rule` 은 다른 룰이 안에서 쓰는 것이라 직접
부르지 않는다).

**오타는 미매치가 아니라 오류로 나온다.** 없는 파일·없는 룰 이름은 *"안 맞았다"*
로 흘러가지 않는다 — 그랬다면 작성자가 룰이 왜 안 도는지 알 수 없다.

### 본문은 저절로 담기지 않는다

YARA 는 레코드의 `content_ref` 가 가리키는 **본문 바이트**를 훑는다. 그 본문은
`collect_extra` 가 선언해야 스냅샷에 담긴다.

선언이 없으면 평가기는 **"안 맞았다" 가 아니라 "재지 못했다"** 를 낸다. 그
사실은 관측 불완전으로 이어지고(종료 코드 6), 그 규칙이 든 판정은 서지 않는다.

> **감염 코퍼스는 이 결함을 가린다.** 코퍼스 스냅샷에는 본문이 이미 담겨 있어
> 룰이 정상으로 보인다. 실기기 `scan` 에서야 드러난다.
>
> 지금은 `plugin lint` 가 이 경우를 막는다 — YARA 를 쓰는데 본문을 담는
> `collect_extra` 가 하나도 없으면 오류다.

### 가리킬 규칙은 **경로로 매치되는** 것이어야 한다

```yaml
collect_extra:
  - { ref: payload, content: true }        # ✗ payload 가 YARA 뿐이라면 순환
  - { ref: payload-file, content: true }   # ✓ 경로로 매치되는 규칙
```

`ref` 형은 2 패스로 돈다 — 수집 → 1차 평가 → 그 증거로 본문 담기 → 재평가.
가리키는 규칙은 **본문 없이 매치될 수 있어야** 한다. 자세한 것은
`30-antipatterns.md` 첫 항목.

그래서 파일을 두 규칙으로 나눈다.

```yaml
- id: payload-file          # 경로로 잡는다 — 본문 없이 선다
  subject: file
  from: "${task.dir}"
  where:
    - { field: path, op: ends_with, value: ".js" }

- id: payload               # 본문으로 잡는다 — 판정의 두 번째 근거
  subject: file
  from: "${task.dir}"
  where:
    - { yara: "rules/evilai.yar:evilai_locust_js" }
```

### YARA 는 **본문이 담기는 것과 같은 범위**여야 한다

```yaml
- id: payload-file                       # collect_extra 가 담는 것
  where:
    - { field: path, op: ends_with, value: ".js" }

- id: payload
  where:
    - { field: path, op: ends_with, value: ".js" }   # ← 같은 조건을 다시 건다
    - { yara: "rules/evilai.yar:evilai_locust_js" }
```

`.js` 조건이 없으면 그 폴더의 **모든 파일**이 YARA 대상이 된다. 본문은 `.js`
에만 담기므로 나머지는 *"재지 못했다"* 가 되고, 그것은 미매치가 아니라
**미평가**다 — 관측 불완전으로 이어진다(종료 코드 6).

**감염 코퍼스에 그 폴더의 파일이 하나뿐이면 드러나지 않는다.** 실기기에서
부속 파일이 함께 있을 때 나온다.

### 룰을 전역에 풀지 않는다

난독화기의 골격을 겨누는 룰은 같은 도구로 난독화한 **정상 소프트웨어**에도
걸릴 수 있다. `from` 으로 악성 증거가 가리킨 디렉터리 안에 가두는 것이 그
위험을 실질적으로 막는다.

분석가가 준 룰 파일 머리에 이런 경고가 적혀 있으면 **그대로 따른다.**

---

## 알려진 지표 목록 — `in` 과 `indicator`

위협 정보가 준 **해시 목록·도메인 목록**으로 잡는다 — 같은 폴더에 사용자 파일이
있고 같은 모양의 정상 항목이 자기 서버 주소를 갖는, 자리·모양으로는 못 가르는 것.

### 해시 목록 — `file.sha256` 에 `in`

```yaml
subjects: [file]
scan_roots: ["/opt"]            # 목록이 있어도 읽는 범위는 이것이 정한다

- id: payload
  subject: file
  where:
    - field: sha256
      op: in                    # value 는 **목록**이다. 문자열 하나면 오류
      value:
        - 3b1f0c9a5d2e47b8c6a10f93e847d25b0c7f4a89e1b3d6528f0a4c7e9d21b5f6
        - 9e4a7c2b8f1d3056a9c4e7b0d2f3a5c8e1b4d70926f3a8c5e0b7d4a1f6c9e32b
```

- **소문자로 적는다.** 수집이 소문자 16진수로 내고, Linux 비교는 대소문자를
  가린다(접는 것은 Windows 뿐이다).
- **`sha256` 뿐이다.** MD5·SHA-1 은 계산하지 않는다 — 피드가 그것뿐이면 못 쓴다.
- **32 MiB 를 넘는 파일에는 `sha256` 이 없다.** 큰 검체는 경로·이름·YARA 로 잡는다.
- 이 기계에 없는 값(변종 몫)이 섞여도 된다.

### 도메인·URL·IP 목록 — `indicator` 에 `in`

수집이 **명령줄과 설정에서 지표를 미리 뽑아 둔다.** 룰은 그 지표를 목록과 견준다.

```yaml
subjects: [autorun, indicator]  # ← indicator 를 subjects 에 적어야 뽑는다

- id: beacon
  subject: indicator
  where:
    - { field: kind, op: equals, value: "domain" }
    - field: value
      op: in
      value: [cdn.evil.example, api.evil.example, relay.evil.example]

- id: autostart                 # 없앨 것은 지표가 아니라 그것을 실은 항목이다
  subject: autorun
  where:
    - { field: command, op: starts_with, value: "/opt/.cache-" }
```

| `kind` | 어디서 뽑나 — `source_ref` 에 그 자리가 적힌다 |
|---|---|
| `domain` · `url` · `ip` · `hash` | `persistence` 의 `command`·`args` · `autorun` 의 `command` · `process` 의 `cmdline_decoded` · `text_config` 의 `line` · `structured_config` 의 `value` · `hosts_entry` 의 `ip` |

- **`service` 는 원천이 아니다.** systemd `.service` 의 실행 줄에 적힌 서버는
  지표로 뽑히지 않는다 — cron·자동 시작 항목·프로세스 명령줄이어야 한다.
  (`.service` 는 `service` subject 로 모이고 `indicator` 는 거기서 거두지 않는다.)
- **파일 본문 속 주소는 뽑지 않는다** — YARA 몫이다. 살아 있는 연결도 관측하지
  않는다(`31-nonexistent.md`). 값은 뽑힌 그대로 견준다.
- `indicator` 는 없앨 수 없다. 판정에 쓰고, **없애는 것은 그 지표를 실은 항목**이다.

### 판정 — 목록마다 근거로 세운다

```yaml
verdict:
  require: "autostart and payload and beacon"
```

`and` 로 묶어야 목록 하나가 헛돌면 판정이 무너지고 **그것이 보인다.** `or` 만의
판정은 근거가 하나뿐인 것과 같아 린트가 경고한다.

## `persistence` — 같은 subject, 플랫폼마다 다른 실체

Windows 는 예약 작업이고 Linux 는 cron 과 systemd 다. **필드 이름은 같고 값의
모양이 다르다.**

| | Windows | Linux (cron) | Linux (systemd) |
|---|---|---|---|
| `id` | 등록 경로 `\Microsoft\Windows\X` | `<crontab 파일>:<줄번호>` | 유닛 이름 `x.service` |
| `source` | 정의 XML 경로 | crontab 파일 | 유닛 파일 경로 |
| `principal` | 실행 계정 | 사용자 칸 또는 파일 이름 | `User=` · 없으면 root |
| `enabled` | 작업의 설정 | 주석이 아니면 참 | `<target>.wants/` 링크가 있는가 |

`trigger` 는 **같은 낱말**을 쓴다 — `boot` · `logon` · `calendar` · `time`.
`@reboot` 과 `OnBootSec=` 이 `boot` 로, `OnCalendar=` 와 보통의 cron 줄이
`calendar` 로 온다. 그래서 `trigger contains "boot"` 는 양쪽에서 통한다.

```yaml
# 부팅마다 사용자 홈의 무언가를 실행한다 — 양쪽 플랫폼에서 도는 조건
- id: hook
  subject: persistence
  where:
    all:
      - { field: trigger, op: contains, value: "boot" }
      - { field: command, op: contains, value: "/.cache/" }
```

**`source` 로 어느 자리인지 가른다.** Windows 룰이 `source contains "\System32\"`
를 쓰는 것과 같다 — Linux 에서는 `source starts_with "/etc/cron.d/"` 나
`source contains "/.config/systemd/user/"` 다. 뒤쪽이 **관리자 권한 없이 심어지는
자리**이고, 그래서 가장 흔하다.

> `enabled: false` 인 systemd 유닛도 파일은 거기 있다. `[Install] WantedBy=` 가
> 있다는 것은 *활성화될 수 있다*는 뜻이지 활성화되어 있다는 뜻이 아니므로,
> 룰이 `enabled` 를 조건으로 걸면 **심어졌지만 아직 켜지지 않은 것**을 놓친다.

## `score` 는 판정 게이트가 아니다

```yaml
  score: 90     # 보고 정렬과 우선순위 표시용
```

**점수 합계로 판정하지 않는다.** 판정은 `verdict.require` 의 논리식이 정한다 —
점수 임계값은 근거 하나의 오탐이 곧바로 삭제로 이어지는 길을 연다.

## `label` — 찾은 것의 뜻 (코어 1.13.0)

```yaml
  label: { ko: "log4j-core 2.x — CVE-2021-44228 등", en: "log4j-core 2.x - CVE-2021-44228 and related" }
```

화면이 **이 규칙이 찾은 줄 바로 아래에** 그 언어의 문구를 한 줄로 적고, `scan.json`
의 증거에도 두 언어로 싣는다. 받은 사람이 찾아볼 이름(해당 CVE · 무슨 파일인가)을
적는다. `score` 처럼 **판정에는 쓰지 않는다.** 두 언어 · 한 줄 · `min_core: "1.13.0"`
이상이 아니면 린트 오류다.

## 자주 막히는 곳

**필드 이름은 subject 마다 닫혀 있다.** `machine/subjects.json` 에 없는 이름을
쓰면 린트가 거절하며 그 subject 에서 쓸 수 있는 것을 전수로 알려 준다.

**Windows 경로 비교는 대소문자를 무시한다.** `matches` 만 예외이고, 정규식의
대소문자는 `(?i)` 로 직접 정한다.

**`glob` 의 `*` 는 경로 구분자를 넘지 않는다.** 하위 폴더까지 보려면 `**` 를 성분
하나로 따로 적는다 — `…\Vendor\**\*.dll` 은 몇 단계 아래든(바로 아래도) 맞고,
`…\Vendor\**.dll` 은 `*` 와 같다.

**한글·비ASCII 경로는 NFC 로 정규화되어 비교된다.**

**`from` 이 안 통하는 subject 는 `where` 값 보간으로 묶는다.** 위 절 참조 —
`from` 을 잘못 걸면 그 규칙이 조용히 죽는다.

**리터럴 절대 경로를 조건에 적지 않는다.** 감염마다 바뀌는 것은 증거에서 뽑고,
안 바뀌는 것은 `scan_roots` 가 이미 정한다.

**관측된 것보다 좁게 쓰지 않는다.** 위협 설명에 없는 세부를 "흔한 형태" 라는
이유로 덧붙이면 그 룰은 변종을 놓친다 — `30-antipatterns.md` 참조.
