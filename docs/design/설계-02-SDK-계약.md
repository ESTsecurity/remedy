# 설계 02 — SDK 계약 (플러그인 스키마 · 아티팩트 추상화 · 격리소 포맷)

> 작성일: 2026-08-20 · 대상: `sdk/` 및 플러그인 작성자
> 선행 문서: [설계-01-아키텍처-결정.md](설계-01-아키텍처-결정.md) · [설계-03-안전장치.md](설계-03-안전장치.md)

## TL;DR

- **무엇을**: 플러그인이 코어에게 말할 수 있는 것의 전부를 확정한다 — 무엇을 관찰하고(detect), 무엇이 확인되면 감염으로 판정하고(verdict), 무엇이 남아 있으면 안 되는가(remediate).
- **핵심 계약 3줄**:
  1. 플러그인은 **관찰과 대상**만 선언한다. 파괴 동작의 종류·순서·백업은 코어가 정한다.
  2. 감염 판정 게이트는 점수 합산이 아니라 **명시적 불 대수식**(`verdict.require`)이다.
  3. 스크립트는 **탐지에서만**, **부작용 없는 순수 함수**로만 허용된다. 파일 쓰기·프로세스 조작·네트워크 API가 존재하지 않는다.
- **판단 포인트**: 이 계약이 좁다고 느껴지면 그것이 의도다. 넓힐 때는 플러그인이 아니라 코어에 기능을 추가해 리뷰를 강제한다.

---

## 1. 플러그인 패키지 구조

```
  evilai-locust/
    plugin.yaml        # 매니페스트 + 룰 (필수)
    rules/*.yar        # YARA 룰 (선택)
    scripts/*          # 탐지 전용 스크립트 (선택)
    tests/             # 감염/클린 스냅샷 기대 결과 (필수 — 설계-03 G1~G4)
    strings/*.yaml     # 사용자 표시 문구 다국어 리소스 (선택)
    MANIFEST.json      # 위 모든 파일의 경로별 다이제스트
    MANIFEST.sig       # MANIFEST.json 에 대한 서명
```

서명 대상은 **MANIFEST.json 전체**다. `plugin.yaml` 하나만 서명하면 YARA 룰과 스크립트를 교체할 수 있어 서명이 무의미해진다.

---

## 2. 매니페스트 최상위 필드

```yaml
schema_version: 1                    # SDK 스키마 버전 (코어가 호환성 판단)
id: evilai-locust                    # 전역 고유, [a-z0-9-]+
version: 1.0.0                       # semver
min_core: "1.0.0"                    # 요구 코어 최소 버전
platforms: [windows]                 # windows | linux | darwin
name:  { ko: "EvilAI(Locust) 제거", en: "EvilAI (Locust) Removal" }
scan_roots:                          # 스캔·스크립트 읽기가 허용되는 경로 상한
  - "%LOCALAPPDATA%\\Programs"
  - "%SystemRoot%\\System32\\Tasks"
allow_removable: false               # 이동식 매체 접근. 기본 false
references: ["https://..."]          # 위협 인텔 근거
signed_malware:                      # 서명된 악성코드 예외. 목록 자체가 플래그다
  - { subject: "...", thumbprint: "..." }
```

### `signed_malware` — 플래그를 따로 두지 않는다 (P1에서 확정)

설계-03 §3 2층은 유효한 신뢰 벤더 서명이 있는 실행 파일을 기본적으로 삭제 대상에서 제외한다. EvilAI 계열처럼 **정상 코드서명 인증서로 서명된 악성코드는 실재하므로** 예외 경로가 필요하지만, 포괄적 무시는 불가다.

설계-03은 "`signed_malware: true` 와 함께 서명 주체를 열거" 로 적었으나, 플래그와 목록을 따로 두면 **`true` + 빈 목록** 이라는 포괄적 무시가 표현 가능해진다. 그래서 **목록 자체를 플래그로 삼는다** — 비어 있거나 없으면 2층을 통과하지 못하고, 항목마다 `subject` 또는 `thumbprint` 중 하나는 반드시 있어야 한다(둘 다 없는 항목은 스키마 검증에서 거부된다).

> 안전 장치는 "쓰면 안 되는 것을 쓰지 말라" 가 아니라 **쓸 수 없게** 만드는 편이 낫다. 같은 이유로 `remove` 에 리터럴 절대 경로를 쓸 수 없고, `recursive` 가 `guard` 를 요구한다.

`allow_removable` 이 없으면 이동식 매체는 수집 대상에서 제외된다(설계-00 §5-2). USB 웜처럼 매체 자체를 치료해야 하는 위협은 이것을 켜고 `scan_roots` 에 `%REMOVABLE%` 를 적는다. **켜는 것만으로는 부족하며, 이동식 매체 대상 파괴 Action은 대화형에서 별도 승인을 받고 무인 모드에서는 계획에 포함되지 않는다** — 연결된 USB가 다른 사람의 것일 수 있기 때문이다.

`scan_roots` 는 성능 최적화가 아니라 **권한 상한**이다. 스크립트와 파일 스캔은 이 경로들 및 증거에서 파생된 경로 밖을 읽을 수 없다. 서명된 플러그인이 임의 경로를 읽을 수 있으면 그 자체가 정보 수집 도구가 되므로, 읽기 범위도 선언 대상으로 둔다.

---

## 3. 관찰 대상 타입 (OS 중립 추상화)

공통 필드는 OS 무관하게 같은 이름을 쓰고, OS 고유 속성은 `win.*` / `linux.*` 네임스페이스로 분리한다. **`win.*` 를 참조하는 룰이 `platforms` 에 windows 를 선언하지 않으면 스키마 검증에서 실패한다** — 조용히 아무것도 매치하지 않는 "크로스플랫폼인 척하는 룰"을 막는다.

| subject | Windows 실체 | Linux 실체 | 공통 필드 |
|---|---|---|---|
| `persistence` | 예약 작업 | cron 항목, systemd timer | `id, name, enabled, trigger, command, args, principal, source` |
| `autorun` | Run/RunOnce 키, 시작 폴더 | `~/.bashrc`·`~/.profile` 라인, XDG autostart, user unit | `id, scope(user\|system), name, command, source` |
| `service` | Windows 서비스 | systemd service, SysV init | `id, name, state, start_type, image_path` |
| `process` | — | — | `pid, ppid, image_path, cmdline, cmdline_decoded, args, user, start_time, modules[]` |
| `file` | — | — | `path, size, mtime, ctime, sha256, signature{...}, zone{...}, reputation{...}, streams[]` |
| `indicator` | 파생 관찰 | 파생 관찰 | `kind(url\|domain\|ip\|hash), value, source_ref, reputation{...}` |
| `registry_value` | 레지스트리 | (해당 없음) | `hive, key, name, type, data` — **키 경로에 와일드카드 열거 허용** |
| `registry_key` | 레지스트리 | (해당 없음) | `hive, key, subkeys[], values[]` — 키 단위 관찰 |
| `text_config` | ini·conf 등 | `/etc/**`, 셸 프로필, PAM, udev | `path, line_no, line, section, key, value` |
| `structured_config` | JSON·XML 설정 | 동상 | `path, format, key_path, value` |
| `shortcut` | `.lnk` 바로가기 | `.desktop` 항목 | `path, target, args, working_dir, icon` |
| `boot_config` | 부팅 구성 | GRUB 항목 | `entry, recoveryenabled, safeboot_available, ...` |
| `hosts_entry` | — | — | `ip, hostnames[], line_no` |
| `browser_extension` | — | — | `browser, profile, ext_id, name, version, path` |
| `av_exclusion` | Defender 제외 목록 | (제품별) | `kind(path\|process\|ext), value, source` |
| `cert_store` | 신뢰할 수 있는 루트/게시자 저장소 | `/etc/ssl/certs`, NSS DB | `store, subject, issuer, thumbprint, not_after` |
| `proxy_config` | WinINET/WinHTTP, PAC | 환경변수, 시스템 설정 | `scope, server, pac_url, bypass` |
| `firewall_rule` | 방화벽 규칙(레지스트리) | iptables·nftables·firewalld | `id, name, direction, action, enabled, protocol, local_port, remote_port, remote_address, application, service, profile, source` |
| `package` | (수집기 없음 — MSI·winget 은 개념만 있다) | dpkg `status`, apk `installed` | `name, version, upstream_version, revision, arch, source, manager(dpkg\|apk)` |
| `unix_socket` | (해당 없음) | `/proc/net/unix` 의 이름 있는 소켓 — 추상 이름은 `@` 로 시작 | `name, inode, listening, kind(stream\|dgram\|seqpacket)` — **찾기 전용**(코어 1.2.0) |

OS 고유 필드 예: `win.task.register_path`, `win.task.principal.run_level`, `win.registry.hive`, `linux.systemd.unit_path`, `linux.cron.file`.

> `av_exclusion` 을 1급 관찰 대상으로 두는 이유: 다수의 위협이 보안 제품 예외 목록에 자기 경로를 등록한다. 그것을 **탐지 근거로도 쓰고 복원 대상으로도 쓴다.**
>
> `cert_store` 를 넣는 이유: 악성 루트 CA 설치는 흔한 지속 수법이고, **파일과 프로세스를 모두 지워도 남아 트래픽 가로채기를 계속 가능하게 한다.** 지우고 끝냈다고 보고하면 거짓이 된다.
>
> `firewall_rule` 은 `av_exclusion` 과 같은 부류다 — 악성코드가 자기 인바운드를 허용하거나 **보안 제품의 아웃바운드를 막는다.** 뒤의 것은 파일을 다 지운 뒤에도 남아 제품 업데이트를 계속 막는다.
>
> 살아 있는 **연결 목록**은 여기 없다. 표본이라 재현되지 않고 지울 Op 도 없다 — 설계-01 D11.
>
> `unix_socket` 은 그것과 다르다 — **듣고 있는 이름 있는 UNIX 소켓**이고, 상주 임플란트가 떠 있는 동안 계속 열려 있는 자리다. Ebury 의 현재 주 탐지법이 그 이름이다. 지울 Op 은 여전히 없다(찾기 전용). 구분의 근거는 설계-01 D11 의 덧붙임.

### v1 열거 범위와 그 밖의 것

`persistence` / `autorun` 추상화가 **실제 위협의 지속성 수법을 전부 덮지는 않는다.** 덮는 범위를 명시하고, 덮지 않는 것을 조용히 넘기지 않는다.

설계-01 D10의 세 계층으로 분류한다.

| 계층 | Windows | Linux |
|---|---|---|
| **T1** — 전용 추상화가 있음 | 예약 작업, 서비스, Run/RunOnce, 시작 폴더 | cron, systemd service·timer, 셸 프로필, XDG autostart |
| **T2** — 선언으로 도달 가능 | **IFEO, COM 하이재킹, AppInit_DLLs, LSA/Winlogon** (와일드카드 레지스트리 열거) | **PAM, udev, LD_PRELOAD, 임의 conf** (`text_config`) |
| **T3** — 코어 통합 필요 | **WMI 영구 이벤트 구독**, 서비스 DLL(svchost) 세부 | 커널 모듈 |

**T2가 이 표의 핵심이다.** IFEO·COM 하이재킹·AppInit_DLLs는 전부 레지스트리이고 PAM·udev·LD_PRELOAD는 전부 텍스트 설정 파일이므로, **와일드카드 열거와 `text_config` 만으로 코어 릴리스 없이 다룰 수 있다.** 반면 WMI 저장소는 레지스트리도 파일도 아니라 T3로 남는다.

T2를 쓰는 룰은 OS 고유 경로를 직접 적게 되므로 `platforms` 선언이 강제되고 크로스플랫폼 이점은 사라진다. **그 대가가 릴리스를 기다리지 않는 것이며, 대개 그 편이 낫다.**

### 와일드카드 열거

```yaml
  - id: ifeo-debugger
    subject: registry_value
    where:
      all:
        - { field: key,  op: glob,    value: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*" }
        - { field: name, op: equals,  value: "Debugger" }
```

- 와일드카드는 **경로 세그먼트 단위**로만 확장되며 재귀 확장(`**`)은 깊이 상한 아래에서만 허용한다
- 열거 결과 수에 상한을 두고 초과 시 `truncated` 로 표시한다(설계-03 §4의 증거 그룹 상한과 별개)
- `HKU\*` 는 **모든 사용자 프로필**을 뜻하는 지정된 확장이다 (설계-00 §5-2)

**새 지속성 유형을 추가할 때는 SDK 스키마와 코어 수집기를 함께 고친다.** 플러그인이 우회 경로로 메우게 두면, 우리가 알아야 할 "이 유형이 늘고 있다"는 신호가 코드가 아니라 플러그인에 흩어진다.

### 서명 (`file.signature`)

서명은 **두 개의 다른 사실**이 한 필드에 들어 있다. 값이 비싸지는 지점이 다르므로
나누어 적는다.

| 무엇 | 얼마나 비싼가 | 무엇에 쓰나 |
|---|---|---|
| `subject` · `thumbprint` | **싸다** — PKCS#7 파싱이면 된다 | 룰의 `exclude`(정상 벤더 제외), `signed_malware` 열거 |
| `trusted` | **비싸다** — X.509 경로를 이 기계의 신뢰 루트에 앵커해야 한다 | 설계-03 §3 **2층** 의 판정 |

싼 쪽은 첫 플러그인이 당장 쓴다 — 예시 EvilAI 룰의 첫 `exclude` 가
`file(command).signature.subject` 다. 비싼 쪽은 `remedy-trust` 와 함께
**P10** 에 온다 (설계-09 P10).

> **2026-09-30 표시** — 위 문단의 "첫 플러그인이 당장 쓴다" 는 그때의 계획이다. 그 `exclude` 줄은 P9 에서
> 지웠다 — 실기기의 `node.exe` 는 OpenJS 서명이고, 이 위협은 정상 실행 파일을 그대로 쓰므로 서명 주체를
> 실측값으로 고쳐도 위협 자체가 제외된다. 지금 저장소의 플러그인 가운데 `signature.subject` 를 술어로 쓰는
> 것은 없고, 정상 제품 보호는 플러그인의 `exclude` 가 아니라 코어의 2층(`trusted`)이 건다(설계-03 §3).
> 아래 예시 뒤의 표시를 함께 본다.

**파싱만으로 "신뢰함" 이라고 말하지 않는다.** Authenticode 서명은 자기서명
인증서로도 암호학적으로 유효할 수 있고, 그것을 신뢰로 읽으면 악성코드가 스스로
서명하는 것만으로 화이트리스트에 든다.

> **`trusted` 는 `Option<bool>` 이어야 한다.** 지금은 `bool` 이라 "파싱은 했지만
> 신뢰 여부는 모른다" 를 표현할 수 없고, 그 상태가 실재한다(파싱은 P10 전에도
> 가능하다). `None` 은 **"확인하지 않았다"** 이지 "신뢰하지 않는다" 가 아니다 —
> 둘을 뭉개면 2층이 조용히 무력해지거나 정상 파일이 조용히 지워진다.
> 설계-03 미결 사항.

### 감염 소스 (`file.zone`)

"어디서 감염됐는가"의 가장 직접적인 단서는 Windows가 다운로드 파일에 붙이는 **Mark of the Web** 이다. 대체 데이터 스트림 `Zone.Identifier` 에 다운로드 URL·참조 URL·호스트가 남는다.

```
  zone: { zone_id: 3, referrer_url: "...", host_url: "...", app_name: "..." }
```

수집 대상에 넣되 **두 가지를 함께 정한다.**

- `zone_id` 는 열거값이라 무해하지만 **`referrer_url` / `host_url` 은 개인정보일 수 있다.** 사내 시스템 주소, 계정이 포함된 URL, 개인 클라우드 링크가 그대로 들어온다. 제출 시 마스킹 대상이며(설계-00 §7), 기본 수집 범위와 기본 제출 범위를 **다르게** 잡는다
- Zone 정보는 **없을 수 있고, 조작될 수 있다.** 악성코드가 ADS를 지우면 흔적이 사라지고, 반대로 위장 값을 써 넣을 수도 있다. 따라서 **탐지 근거로 쓰지 않고 보고 정보로만 쓴다**

보조 단서(브라우저 다운로드 이력, 이동식 매체 이력, 프로세스 계보)는 v1 범위 밖이며, `process.ppid` 로 얻을 수 있는 부모 관계만 우선 활용한다.

### 지표 (`indicator`) — 유일한 파생 관찰 대상

`indicator` 는 다른 subject에서 **추출된** 값이다. 파일 내 문자열, hosts 항목, 프록시 설정, 네트워크 연결의 원격 주소, 브라우저 확장의 통신 대상에서 URL·도메인·IP·해시를 뽑아 모은다.

- `source_ref` 로 **어디서 나왔는지를 반드시 기록한다.** 출처 없는 지표는 조회도 제출도 하지 않는다
- 추출 자체는 수집기가 하며 **플러그인 룰이 개입하지 않는다.** 지표 추출이 룰에 좌우되면 플러그인마다 다른 지표가 나와 인텔 품질이 흔들린다
- 지표 수에 상한을 두고, 초과 시 `truncated` 를 표시한다

### `reputation` 필드는 `enrich` 만 채운다

`file.reputation` 과 `indicator.reputation` 은 **수집기가 비워 두고 `enrich` 단계가 채우는** 유일한 필드다(설계-01 D9).

remedy 가 조회 결과를 담는 형태다(출처 시스템과의 대응은 내부 문서 설계-05 §2).

```
  reputation: {
    state: "found | not_visible | not_queried",   // 세 상태를 구분한다
    source: "internal-sandbox",
    verdict: "malicious | suspicious | clean | unscored",
    score: 42, allowlisted: false,
    findings: { critical: [...], high: [...], medium: [...], low: [...] },
    mitre: ["T1053.005", ...], engine_results: {...},
    rules_version: "...", analyzed_at: "...", queried_at: "...", request_id: "..."
  }
```

- **`state` 를 세 가지로 나눈다.** `not_queried`(물어보지 않음)와 `not_visible`(물어봤으나 0건)은 다르고, 후자를 `not_found` 라고 부르지 않는다 — 조회 결과는 조회하는 쪽의 권한에 달려 있을 수 있어 0건이 "분석된 적 없음"을 뜻하지 않는다(내부 문서 설계-05 §3)
- **`allowlisted` 가 유일한 제외 근거다.** 사람이 부여한 화이트리스트 태그에서 온다. `verdict` 와 `score` 는 **보고·우선순위 표시 전용**이며, `clean` 을 제외 근거로 쓰면 회피에 성공한 검체가 자동 면제된다
- 룰이 `remediate` 절에서 `reputation` 을 참조하면 **스키마 검증에서 거부**된다. `detect` 의 `exclude` 에서 `allowlisted == true` 를 쓰는 것만 허용된다(설계-01 D9 결정 3)
- **`rules_version` 은 필수다.** 코퍼스에 조회 결과를 박아 두는 설계에서, 어떤 룰 버전으로 내려진 판정인지 모르면 재현이라고 부를 수 없다
- `analyzed_at`(사내 시스템이 분석한 시각)과 `queried_at`(우리가 물어본 시각)을 따로 둔다

---

## 4. detect — 관찰 규칙

```yaml
detect:
  - id: malicious-task
    subject: persistence
    where:
      all:
        - { field: command,                 op: matches,     value: "(?i)\\\\node\\.exe$" }
        - { field: args,                    op: matches,     value: "(?i)\\.js(\\s|$)" }
        - { field: win.task.register_path,  op: starts_with, value: "\\Microsoft\\Windows\\" }
        - any:
            - { field: source, op: contains, value: "\\System32\\" }
            - { field: source, op: contains, value: "\\AppData\\Local\\Programs\\" }
    capture:
      script_path: "args | first_path"
      script_dir:  "${script_path} | dirname"
    exclude:
      - { field: file(command).signature.subject, op: equals,   value: "Microsoft Corporation" }
      - { field: source,                         op: contains,  value: "\\Microsoft VS Code\\" }
    score: 90

  - id: dropped-payload
    subject: file
    from: "${malicious-task.script_dir}"      # 이전 증거에서 파생된 경로만 스캔
    where:
      - { yara: "rules/evilai.yar:evilai_locust_js" }
```

> **2026-09-30 표시** — 위 예시의 `exclude` 두 줄(`file(command).signature.subject` · `source contains`)은
> 지금 매니페스트에 없다. 둘 다 발동할 수 없음이 실측으로 드러나 P9 에서 지웠다 — 실기기의 `node.exe` 는
> OpenJS 서명이고, 예약 작업의 `source` 는 정의 파일 경로라 설치 경로가 들어갈 자리가 없다. 값을 고쳐
> 살릴 수 있는 술어도 아니다(위협이 정상 실행 파일을 그대로 쓴다). 지금의 매니페스트와 그 까닭은
> `plugins/evilai-locust/plugin.yaml` 의 주석에 있다.

### 연산자 (닫힌 집합)

`equals` `not_equals` `matches` `contains` `starts_with` `ends_with` `in` `glob` `exists` `gt` `lt` `version_lt` `version_gt` `pkg_version_lt` `yara`

- **`gt` · `lt` 는 크기(수)와 시각(RFC3339 UTC)만 견준다.** 문자열의 사전순 비교는 뜻이 없다 — `"9" > "10"` 이 참이 되고 작성자는 알아채지 못한다. 견줄 수 없는 값이면 **오류로 말한다**
- **`version_lt` · `version_gt` 는 버전을 견준다** (2026-10-27 · C-1). 점으로 나눈 열 진수 정수만 받고, 없는 성분은 `0` 이다 — `8.2` 와 `8.2.0` 이 같다. **`gt` · `lt` 를 고치지 않고 연산자를 더한 이유**는 `1.10` 이 수로도 버전으로도 읽히고 **순서가 반대**라는 데 있다(수로는 `1.10 < 1.9`) — 기존 연산자에 버전 의미를 끼워 넣으면 이미 출하된 룰의 뜻이 조용히 바뀐다. 꼬리는 받지 않는다: `8.4.0RC1`(사전 배포)은 `8.4.0` 보다 낮고 `8.2.29-1ubuntu1`(패키지 개정)은 `8.2.29` 보다 높아 **모양이 같고 순서가 반대**다. 추측하지 않고 **관측 불완전**(`unreadable_versions` → 종료 6)으로 말하며, 패키지 개정을 가리는 것은 패키지 subject 의 몫이다. 린트가 룰의 리터럴을 미리 거절한다. **주의 줄만으로는 모자랐다** — 진단을 `issues` 에만 남기자 취약한 기계가 *"취약한 곳을 찾지 못했습니다"*(종료 0)로 나갔다(실측 2026-10-27). YARA 미평가와 같은 레일이다
- **`pkg_version_lt` 는 배포판이 적는 판을 견준다** (2026-10-27 · C-2 후속). `version_lt` 가 **일부러 거절한 꼬리**가 이쪽의 대상이다 — 배포판은 상류 번호를 올리지 않고 고치므로(실측: ubuntu 22.04 의 `php8.1-cli` 가 `8.1.2-1ubuntu2.28`, 상류는 `8.1.2` 고정) 개정의 순서를 정하지 못하면 **고친 기계도 취약으로 나간다**. 순서는 추측이 아니라 **dpkg 의 규칙**이다(데비안 정책 §5.6.12): `[epoch:]상류[-개정]` 을 셋으로 갈라 견주고, 조각 안에서 숫자 아닌 부분과 숫자 부분을 번갈아 보며 **`~` 는 무엇보다도 먼저**다(`1.0~rc1 < 1.0 < 1.0+b1`). **`_` 는 받지 않는다** — apk 는 `_alpha` 를 그 판보다 낮게, dpkg 의 규칙은 높게 읽어 **순서가 반대**다. 그때는 추측하지 않고 관측 불완전(종료 6)으로 말한다. apk 의 `-rN` 개정은 두 규칙이 같은 답을 내므로 이 연산자로 견준다. **반대 방향을 두지 않았다** — `not pkg_version_lt` 가 `>=` 이므로 범위는 둘로 적는다
- `matches` 의 정규식 문법은 **RE2**다. 역참조·전방탐색이 없는 대신 입력 길이에 선형이라, 플러그인 룰이 스캐너를 정지시키는 사고가 원천적으로 불가능하다. 이 제약은 기능 손실이 아니라 안전 속성이다.
- `capture` 표현식의 함수도 닫힌 집합이다: `first_path` `last_path` `dirname` `basename` `lower` `expand_env` `trim_quotes` `base64_decode` `hex_decode`. 임의 코드가 아니다. `last_path`(코어 1.2.0)는 역슬래시가 든 마지막 토큰, 없으면 슬래시가 든 마지막 토큰이다 — `cmd.exe /c start "" /min "…\node.exe" "…\a.js"` 처럼 인자 안에 실행 파일이 다시 오는 자리에서 스크립트를 집는다. 디코딩 결과 크기에 상한을 두고 초과 시 미매치로 처리한다
- **`yara` 는 파일 전용이 아니다.** 바이트열을 제공하는 모든 필드에 적용된다 — `file` 내용, `registry_value.data`, `text_config.line`, `structured_config` 값. 파일리스 위협은 페이로드가 파일이 아니므로 이 확장이 없으면 다루지 못한다. 어느 필드가 바이트열을 제공하는지는 스키마에 표시된다

### 지정 확장 토큰

경로에 쓸 수 있는 고정 토큰이다. 임의 확장이 아니라 **열거된 것만** 허용한다.

| 토큰 | 확장 대상 | 비고 |
|---|---|---|
| `HKU\*` | 모든 사용자 레지스트리 하이브 | 프로필 수 상한 적용 |
| `%ALLUSERPROFILES%` | 모든 사용자 프로필 디렉터리 | `HKU\*` 의 파일 경로 대응물 |
| `%REMOVABLE%` | 연결된 이동식 매체 | `allow_removable: true` 선언 필수 (§2) |

`%ALLUSERPROFILES%` 가 없으면 다중 사용자 환경에서 **현재 로그온 사용자만 치료되고 나머지는 감염 상태로 남는다.** `C:\Users\*` 를 직접 적는 것은 드라이브 문자가 고정되고 범위가 과도해 대안이 되지 않는다.

### 경로 비교 규칙 (명시적으로 고정)

경로 비교는 오탐·미탐의 최대 원인이므로 정규화 규칙을 스키마 수준에서 고정한다.

- **Windows**: 대소문자 무시 · `/` → `\` 통일 · 환경변수 전개 · 8.3 단축 이름 해석 · `\\?\` 접두 제거 · 후행 구분자 제거
- **Linux**: 대소문자 구분 · `~` 전개 · **심볼릭 링크는 해석하지 않음**(비교 대상은 표기된 경로)

**심볼릭 링크/정션은 어떤 파괴 동작에서도 따라가지 않는다.** 링크를 지우면 링크만 지워지고, 링크된 디렉터리로 재귀 삭제가 번지지 않는다.

#### 유니코드 정규화 — 한글 환경에서 실제로 터지는 지점

문자열 비교 전에 경로와 값을 **NFC로 정규화**한다. 한글은 조합형(NFD)과 완성형(NFC)의 바이트열이 완전히 다르므로, 정규화하지 않으면 **같은 이름의 폴더가 다른 문자열로 보인다.** 외부 매체나 타 OS를 거친 파일명이 NFD로 들어오는 경우가 실제로 있다.

대소문자 무시 비교도 **로케일에 의존하지 않는 방식**으로 한다. 로케일 의존 대소문자 변환은 터키어 로케일에서 `I`/`ı` 가 어긋나는 등 재현 불가능한 차이를 만든다. 한글은 대소문자가 없지만, 경로에 섞인 ASCII 부분이 같은 함정을 밟는다.

플러그인 룰의 문자열 리터럴도 로드 시점에 같은 정규화를 거친다 — 룰 작성자의 편집기가 무엇을 뱉었는지에 판정이 좌우되면 안 된다.

#### WOW64 리다이렉션 — 32비트 빌드가 조용히 빗나가는 곳

32비트 `remedy` 가 64비트 Windows에서 돌면 OS가 파일·레지스트리 접근을 말없이 바꿔치기한다.

| 룰이 적은 것 | 32비트 프로세스가 실제로 보는 것 |
|---|---|
| `%SystemRoot%\System32` | `%SystemRoot%\SysWOW64` |
| `HKLM\SOFTWARE\...` | `HKLM\SOFTWARE\WOW6432Node\...` |
| `%ProgramFiles%` | `%ProgramFiles(x86)%` |

**첫 플러그인이 정확히 이 지뢰를 밟는다** — EvilAI 룰의 `source contains "\System32\"` 조건은 32비트 빌드에서 원래 의도한 디렉터리를 보지 못한다. 조용히 미탐이 되므로 테스트에서 잡히지 않고, 32비트 환경에서만 "치료했는데 안 지워진다"로 나타난다.

규칙을 다음과 같이 고정한다.

- **수집기는 리다이렉션을 명시적으로 해제**하고 네이티브 뷰를 읽는다(파일: 리다이렉션 일시 해제, 레지스트리: 64비트 뷰 명시 플래그). 룰이 적은 경로가 곧 실제 경로여야 한다
- 32비트 뷰를 **일부러** 보아야 하는 룰은 `%ProgramFiles(x86)%`·`WOW6432Node` 를 **명시적으로** 적는다. 암묵적 리다이렉션에 기대지 않는다
- 아티팩트 스냅샷에 **수집 시점의 비트수와 OS 비트수를 기록**한다. 32비트 수집기가 만든 스냅샷을 64비트 기준으로 해석하는 사고를 막는다
- testbed 클린 세트에 **64비트 OS × 32비트 빌드** 조합을 반드시 포함한다(설계-04 §3.3)

### 규칙 간 참조와 다중 매치 — 증거 그룹

`from:` 과 `${rule.capture}` 는 규칙 사이에 **부모-자식 관계**를 만든다. 부모가 여러 건 매치되면 자식이 무엇을 참조하는지가 모호해지므로, 의미를 다음과 같이 고정한다.

**(1) 참조 관계는 방향 있는 비순환 그래프(DAG)를 이룬다.** 순환 참조는 스키마 검증에서 거부하고, 평가 순서는 위상 정렬로 결정한다. 플러그인 작성자가 순서를 적지 않는다.

**(2) 부모 증거 인스턴스마다 독립 스코프가 생긴다.** 부모가 N건 매치되면 **N개의 증거 그룹**이 만들어지고, 자식 규칙은 각 그룹 안에서 그 그룹의 capture만 보고 평가된다.

```
  malicious-task 가 2건 매치
    -> 그룹 #0 : script_dir = C:\...\locust
         dropped-payload 는 C:\...\locust 안에서만 평가
    -> 그룹 #1 : script_dir = C:\...\other
         dropped-payload 는 C:\...\other 안에서만 평가
```

**(3) `verdict.require` 는 그룹 단위로 평가된다.** 그룹 #0이 판정을 통과하고 #1이 통과하지 못하면, 치료는 **#0의 증거에 대해서만** 수행된다. 그룹 간 증거가 섞여 판정을 성립시키는 일은 없다 — 서로 무관한 두 정상 소프트웨어의 조각이 합쳐져 감염 판정을 만드는 사고를 막는다.

**(4) 참조가 없는 규칙은 루트 스코프에 속한다.** 모든 그룹에서 공유되며, 그룹이 0개면 루트 스코프 단독으로 판정을 시도한다.

**(5) 부모가 0건 매치면 자식은 평가하지 않는다** (미매치로 처리, 오류 아님).

**(6) 그룹 수에도 상한이 있다.** 상한을 넘으면 계획 단계에서 중단한다(설계-03 §4). 룰이 지나치게 넓게 잡혀 수백 개 그룹이 생기는 상황은 치료할 일이 아니라 룰 오류다.

### `scan_roots` 가 적용되는 범위 (정확히)

`scan_roots` 는 **경로 기반 접근 전부**의 상한이다 — 파일 스캔, `fs.*` 호출, **그리고 증거에서 파생된 경로까지 포함**한다. 프로세스·서비스 열거나 레지스트리 읽기처럼 경로 개념이 없는 대상에는 적용되지 않으므로, 열거 자체를 제한하려면 별도 선언이 필요하다.

```yaml
scan_roots: [ ... ]                       # 경로 접근 상한 (파생 경로 포함)
subjects: [persistence, file, autorun, av_exclusion, process]   # 열거 허용 대상 상한
```

`subjects` 에 선언하지 않은 대상 타입은 detect 규칙에서 사용할 수 없다. **선언한 것만 볼 수 있다**는 원칙을 경로와 대상 양쪽에 동일하게 적용한다.

#### 파생 경로가 상한을 벗어나면 계획을 거부한다

`${malicious-task.script_dir}` 처럼 capture로 만들어진 경로가 `scan_roots` 밖을 가리키면 **경고가 아니라 오류**다. 해당 그룹은 판정에서 제외되고 감사 로그에 사유가 남는다.

느슨하게 허용하지 않는 이유는 두 가지다. 첫째, 파생 경로는 **공격자가 영향을 줄 수 있는 값**이다 — 예약 작업의 인자는 악성코드가 쓴 것이므로, 그것이 상한을 넘게 만들 수 있다면 상한이 아니다. 둘째, 상한을 넘는 상황은 대개 **룰 작성자가 대상 범위를 잘못 잡았다는 신호**이며, 그 순간이 우리가 원하는 리뷰 지점이다.

작성자가 할 일은 `scan_roots` 에 해당 루트를 **명시적으로 추가**하는 것이고, 그 추가가 곧 "이 플러그인은 여기까지 건드린다"는 선언이 된다. 예를 들어 첫 플러그인은 예약 작업 정의뿐 아니라 **작업이 가리키는 스크립트가 놓일 수 있는 위치 전부**를 선언해야 한다.

```yaml
scan_roots:
  - "%SystemRoot%\\System32\\Tasks"        # 작업 정의를 읽기 위해
  - "%SystemRoot%\\System32"               # 작업이 System32 하위를 가리킬 수 있으므로
  - "%LOCALAPPDATA%\\Programs"             # 그리고 여기도
```

`%SystemRoot%\System32` 를 선언한다고 해서 그 안의 OS 파일을 지울 수 있게 되는 것은 아니다 — 삭제 가능 여부는 **읽기 상한과 완전히 별개**로 1층 보호 목록과 서명 검증이 결정한다(설계-03 §3). 읽기 상한은 정보 수집 범위를, 보호 목록은 파괴 범위를 각각 통제하며 두 축은 겹치지 않는다.

#### 이름 꼴 뿌리 — 한 폴더 바로 아래의 맞는 파일만 (코어 1.2.0)

파일 경로 뿌리의 **마지막 칸**에 이름 꼴(`*` · `?` 가 글자와 섞인 것)을 적으면, 그 폴더 **바로 아래**에서 이름이 맞는 파일만 상한에 든다 — `%ALLUSERPROFILES%\AppData\Local\Temp\*.js`. 하위 폴더로 내려가지 않고, **폴더 자체는 상한 밖**이다(`normalize::is_within`). 그래서 그 폴더를 겨눈 재귀 삭제는 G6 이 막는다. 걷기도 이름 목록만 읽고 맞는 파일만 해시한다.

연 까닭은 실측이다(2026-11-08). EvilAI 의 공개 보도 꼴은 페이로드를 `TEMP` 바로 아래에 두는데, `TEMP` 를 뿌리로 적으면 재귀로 걸으며 파일마다 해시한다 — 개발 기계 하나의 `TEMP` 가 파일 63,661개 · 16.2 GB 였다. 폴더 칸의 와일드카드(뿌리를 여러 갈래로 넓히는 꼴)와 이름 칸이 와일드카드뿐인 꼴(`…\*` — '재귀로 다 본다' 로 오독된다)은 그대로 린트 오류다.

---

## 5. verdict — 감염 판정 게이트

```yaml
verdict:
  require: "malicious-task and dropped-payload"
```

**점수 임계값(`score >= 80`)을 게이트로 쓰지 않는다.** `score` 는 보고·우선순위 표시용으로만 남긴다.

근거: 점수 합산 게이트는 "휴리스틱 하나가 높은 점수를 받으면 파일이 삭제된다"는 구조다. 탐지 제품이면 허용되는 설계지만, 파괴가 결과인 제품에서는 허용되지 않는다. 서로 독립적인 근거의 **논리곱**을 명시하게 하면, 룰 하나의 오탐이 곧바로 삭제로 이어지지 않는다.

`require` 는 `and` `or` `not` `(...)` 과 `<rule-id>`, `count(<rule-id>) >= N` 만 지원한다.

---

## 6. remediate — "무엇이 남아 있으면 안 되는가"

```yaml
remediate:
  remove:
    - { ref: malicious-task }                       # 지속성 항목
    - { ref: dropped-payload }                      # 파일
    - { ref: persistence-runkey }                   # 자동실행
    - { path: "${malicious-task.script_dir}", recursive: true, guard: dropped-payload }
  edit:                                             # 값의 악성 부분만 제거
    - { ref: userinit-hijack, op: strip, value: "${svc.svc_bin}" }
  restore:
    - av_exclusions                                 # 보안 제품 예외 목록 원복
    - { ref: shell-hijack, to: default }            # 코어의 OS 기본값 카탈로그
  verify:
    after_reboot: true
```

### `edit` 절이 따로 있는 이유

**전체 삭제만으로는 치료할 수 없는 대상이 주류다.** `Winlogon\Userinit` 값이 `userinit.exe,악성.exe` 로 오염됐을 때 값을 통째로 지우면 **사용자가 로그온할 수 없다.** 같은 형태가 `Shell`, `AppInit_DLLs`, 서비스 `ImagePath`, 환경변수 `PATH`, 각종 설정 파일 라인에서 반복된다.

- `edit` 의 `value` 는 **증거에서 파생된 값**이어야 한다. 리터럴 문자열로 임의 편집을 지시할 수 없다
- 백업은 **편집 전 값 전체**다(설계-03 §2). 복원하면 오염된 원본이 그대로 돌아오며 그것이 옳은 동작이다
- `restore ... to: default` 는 **코어가 내장한 OS 기본값 카탈로그**에서만 값을 가져온다. 플러그인이 임의 값을 쓸 수 없다

**플러그인은 순서·백업·프로세스 종료를 쓰지 않는다.** 계획기가 도출한다(설계-03 §2).

- `remove` 항목은 증거 참조(`ref`) 또는 증거에서 파생된 경로(`path` + capture 보간)만 가능하다. 리터럴 절대 경로는 거부한다 — 증거 없는 삭제를 문법 수준에서 불가능하게 한다.
- `recursive: true` 는 `guard` 를 **필수로** 요구한다. `guard` 는 "그 디렉터리 안에서 악성으로 판정된 파일 증거"를 가리킨다(설계-03 §4).
- `restore` 는 파괴가 아니라 원복이므로 별도 절에 둔다.

---

## 6-1. collect_extra / submit_hint — 분석에 필요한 것을 선언한다

치료만으로는 부족하다. "이 위협은 이 로그도 함께 봐야 분석된다"를 플러그인이 말할 수 있어야 한다(설계-01 D10).

```yaml
collect_extra:        # 분석에 유용한 추가 수집. 파괴 아님
  - { ref: dropped-payload, content: true }
  - { path: "${malicious-task.script_dir}/config.json", max_size: 1MB }
  - { subject: text_config, path: "%APPDATA%\\...\\settings.ini" }

submit_hint:          # 제출 시 무엇이 유용한지에 대한 제안
  samples: [dropped-payload]
  confidentiality_min: 1
```

**선언과 실행을 분리하는 것이 핵심이다.**

- `collect_extra` 는 `collect` 단계에서 수집되며 **`scan_roots` 상한과 총 용량 상한을 그대로 받는다.** 파괴 동작이 아니므로 계획에 나타나지 않지만, **수집된 사실은 감사 로그에 남는다**
- `submit_hint` 는 **제안이지 명령이 아니다.** 실제 제출은 사용자 동의·미리보기·마스킹을 거친다(설계-00 §7)
- `confidentiality_min` 은 **하한만 올릴 수 있다.** 플러그인이 기밀 등급을 낮추는 방향으로 영향을 줄 수 없다(내부 문서 설계-05 §4-2)
- **제출 기능은 제품에 없다 (2026-08-28 P13 결정, 설계-09 "제출을 제품 밖으로").** `submit_hint` 는 자동 제출기가 볼 값이 아니라 **손으로 올리는 사람이 볼 판단 근거**다 — 계획이 그것을 나르고 `support-bundle` 이 보여 준다. 없앴다면 플러그인 작성자의 판단(*"무엇을 함께 올리면 유용한가"* · *"어느 등급으로 다뤄야 하는가"*)이 함께 사라진다

`collect_extra` 에 `content: true` 를 쓰면 파일 본문이 아티팩트에 들어가므로, 스냅샷이 커지고 개인정보 위험이 올라간다. 상한을 두고 초과 시 메타데이터만 담는다.

### `ref` 형은 두 번째 패스에서 풀린다

`{ ref: dropped-payload, content: true }` 는 **증거를 가리키고, 증거는 평가가 만든다.** 수집 시점에는 그 이름이 무엇을 가리키는지 알 수 없다. 그래서 `scan`·`run` 의 순서가 이렇다.

```
  collect ──▶ evaluate ──▶ ref 해소 ──▶ evaluate (재)
             (증거 생김)   (본문 담김)   (YARA 가 훑을 것이 생김)
```

**이것이 없으면 `from:` 이 반쪽이다.** 앞선 룰이 찾아낸 경로의 파일을 YARA 로 훑으려면 그 바이트가 스냅샷에 있어야 하는데, 매니페스트를 쓸 때는 그 경로를 모른다.

- **한 번만 더 돈다.** 재평가가 만든 증거로 또 풀면 패스 수가 데이터에 좌우되고, 그러면 이 실행이 무엇을 읽는지 미리 말할 수 없다. 남은 것은 미해소로 보고한다
- **결정성은 유지된다.** 저장되는 `artifacts.json` 은 해소가 끝난 것이므로 `evaluate(저장된 artifacts.json)` 이 저장된 `scan.json` 을 재현한다 (설계-01 D9 결정 2). 청정 코퍼스(G1)도 같은 이유로 성립한다
- **파생 경로도 `scan_roots` 상한을 받는다.** 증거에서 나온 경로는 공격자가 영향을 줄 수 있는 값이므로, 상한 밖이면 담지 않고 그 사실을 보고한다 (§4)
- **총량 상한은 스냅샷 전체에 걸린다.** 패스마다 새로 세면 두 패스가 각각 상한만큼 담아 두 배가 된다
- **`collect` 단독은 풀 수 없다.** 증거가 없기 때문이며, 그 사실과 함께 "`scan` 이나 `run` 으로 돌리라"를 보고한다

구분해야 할 세 가지가 있다. 뭉뚱그리면 진짜 문제가 정상 동작에 묻힌다.

| 상황 | 처리 |
|---|---|
| 가리키는 룰이 **없다** | 미해소. `plugin lint` 가 미리 잡는다 — 영영 풀리지 않는 선언이다 |
| 룰은 있는데 **안 맞았다** | 정상. 담을 것이 없을 뿐이다 |
| 증거에 **파일 본문이 없다**(레지스트리 값 등) | 미해소. 담을 바이트가 없다는 사실이 남아야 한다 |

---

## 7. 스크립트 확장 — 허용 호스트 API 화이트리스트

스크립트는 **탐지 전용 순수 함수**다. 진입점 시그니처:

```
  detect(ctx) -> { matched: bool, captures: {..}, score?: int }
```

### 제공되는 것

| 그룹 | API | 비고 |
|---|---|---|
| 대상 | `ctx.subject` | 읽기 전용 |
| 증거 | `ctx.evidence(rule_id)` | 선행 룰의 결과 |
| 시각 | `ctx.now` | **고정 주입** (실시간 시계 아님) |
| 파일 | `fs.stat` `fs.glob` `fs.read(path, max)` `fs.hash` `fs.signature` | `scan_roots` + 증거 파생 경로로 제한 |
| 룰 | `yara.match(rule_ref, path)` | |
| 프로세스 | `proc.list()` `proc.modules(pid)` | 읽기 전용 |
| 유틸 | `text.*` `path.*` `json.decode` `re.match` | RE2 |

### 존재하지 않는 것 (설정으로 켤 수 없음)

파일 쓰기·삭제, 프로세스 생성·종료, 네트워크, 레지스트리 쓰기, 환경변수 설정, 실시간 시계, 난수, 외부 프로세스 실행.

이 목록이 **비어 있다는 사실 자체가 계약**이다. 스크립트 런타임 선택(설계-01)은 "기본값이 안전한가", 즉 아무 설정 없이 시작했을 때 파일·네트워크 접근이 이미 차단되어 있는가를 첫 번째 기준으로 정한다.

### 결정성과 자원 상한

시계·난수·네트워크가 없으므로 **같은 입력에 같은 출력**이 보장된다. testbed가 계획 비교만으로 회귀를 잡을 수 있는 근거다(설계-03 G3).

코어가 강제하는 상한: 실행 시간, 메모리, 실행 스텝 수, `fs.read` 누적 바이트, 접근 파일 수. 초과 시 해당 룰은 **미매치로 처리하고 경고를 기록**한다 — 스크립트 실패가 곧 감염 판정이 되어서는 안 된다.

`captures` 로 반환되는 값에는 크기 상한이 있다. 파일 본문을 capture 에 담아 감사 로그로 유출시키는 경로를 막는다.

---

## 8. 산출 아티팩트 (JSON 계약)

네 단계 모두 동일한 봉투를 쓴다.

```json
{
  "schema_version": 1,
  "kind": "remedy.artifacts | remedy.scan | remedy.plan | remedy.result",
  "run_id": "01J...",
  "created": "2026-08-20T10:50:00Z",
  "host": { "hostname": "...", "os": "windows", "version": "...", "arch": "amd64" },
  "core": { "version": "1.0.0", "build": "..." },
  "plugins": [ { "id": "evilai-locust", "version": "1.0.0", "digest": "sha256:...", "signer": "..." } ],
  "...": "kind 별 본문"
}
```

**Artifacts** (collect 본문) — 판단이 섞이지 않은 원본 관찰

```json
{ "collected_at": "...", "collector": { "version": "1.0.0", "bitness": 32, "os_bitness": 64 },
  "scope": { "scan_roots": ["..."], "subjects": ["persistence", "file"], "truncated": false },
  "persistence": [ { "id": "\\Microsoft\\Windows\\Locust", "command": "...", "args": "...", "win": { "task": { ... } } } ],
  "file": [ { "path": "...", "size": 1234, "sha256": "...", "signature": { ... }, "content_ref": "blob:0003" } ],
  "security_products": [ { "vendor": "...", "realtime": true } ] }
```

- **어떤 룰도 여기에 개입하지 않는다.** 수집 범위는 플러그인의 `scan_roots`/`subjects` 선언에서 오지만, 무엇이 악성인지에 대한 판단은 들어가지 않는다
- `collector.bitness` 와 `os_bitness` 를 기록해 WOW64 해석 오류를 막는다(§4)
- `truncated` 는 상한에 걸려 수집이 잘렸음을 표시한다. **잘린 스냅샷으로 "위협 없음"을 결론짓지 않기 위한 필수 필드**다
- `content_ref` 가 있는 파일만 YARA 평가가 가능하다. 없으면 해당 규칙은 **미평가**로 표시된다(설계-03 §1)
- `security_products` 는 실패 원인 진단과 지원 대응에 쓰인다(설계-00 §5-1)

**Evidence** (scan 본문)

```json
{ "id": "malicious-task#0", "rule": "malicious-task", "subject": "persistence", "score": 90,
  "target": { "id": "\\Microsoft\\Windows\\Locust", "name": "...", "command": "...", "args": "..." },
  "captures": { "script_path": "C:\\...\\main.js", "script_dir": "C:\\...\\locust" },
  "matched": [ { "field": "command", "op": "matches", "value": "(?i)\\\\node\\.exe$" } ] }
```

**Action** (plan 본문) — 참조가 남아 있지 않은 완전 구체화 형태

```json
{ "seq": 3, "op": "file.delete", "target": "C:\\...\\main.js",
  "sha256": "...", "size": 1234, "because": ["dropped-payload#0"],
  "backup": { "entry": "q:0007", "kind": "file" }, "reversible": true, "risk": "medium",
  "user_impact": null }
```

`user_impact` 는 **사용자가 체감할 부작용**을 담는다. 계획 렌더러(설계-01 D5)가 이것을 사람의 문장으로 바꾼다. `kind` 는 닫힌 집합이다.

| `kind` | 언제 | 사용자에게 |
|---|---|---|
| `app_terminate` | 실행 중인 프로그램을 종료해야 할 때 | 저장하지 않은 작업이 손실될 수 있음 |
| `app_broken` | 정상 프로그램이 의존하던 파일을 제거할 때 | 해당 프로그램을 다시 설치해야 할 수 있음 |
| `reboot_required` | 재부팅이 필요할 때 | 재부팅 전까지 치료가 완료되지 않음 |
| `removable_media` | 이동식 매체를 변경할 때 | 대상 매체를 확인하고 분리하지 말 것 |

`app_broken` 이 필요한 이유는 DLL 사이드로딩 때문이다. 정상 서명된 프로그램 옆의 악성 DLL만 제거하면 **정상 프로그램을 지키는 옳은 처리이지만 그 프로그램은 더 이상 실행되지 않는다.** 지우지 않았다는 사실만 보고하면 사용자는 무슨 일이 일어났는지 모른다.

```json
{ "seq": 1, "op": "process.kill", "match": { "image_path": "...\\chrome.exe" },
  "user_impact": { "kind": "app_terminate", "app": "Google Chrome",
                   "note": "저장하지 않은 작업이 손실될 수 있음" } }
```

### 종료 코드

| 코드 | 의미 |
|---|---|
| 0 | 위협 없음 |
| 1 | 위협 발견 · 치료 완료 |
| 2 | 위협 발견 · 치료 안 함 (드라이런/사용자 거절) |
| 3 | 부분 실패 (일부 Action 실패, 롤백 결과는 result.json 참조) |
| 4 | 사용법·입력 오류 |
| 5 | 안전 가드에 의한 중단 (상한 초과·보호 경로·서명 검증 실패) |
| 6 | **관측 불완전** — 다 보지 못해 "위협 없음"을 말할 수 없다 (원인은 아래 표) |

5번을 3번과 분리하는 이유: 무인 배포에서 "가드가 막았다"와 "실행하다 실패했다"는 완전히 다른 후속 조치를 요구한다.

**6번을 0번과 분리하는 이유**: 무인 배포에서 0은 "이 PC는 깨끗하다"로 읽히고 그대로 종료된다. 그런데 관리자 권한 없이 돌아 `System32\Tasks`를 못 읽은 실행도, 파일 상한에 걸려 절반만 훑은 실행도 지금까지는 0을 냈다. 그 PC는 **검사받았다고 기록되지만 실제로는 절반만 본 것**이다. 경고는 stderr로 나가는데 무인 배포에서 stderr는 버려진다. `artifacts.json`의 `scope.truncated`·`scope.denied_dirs`가 사실을 담고 있어도, 종료 코드가 그것을 말하지 않으면 기계는 알 수 없다.

**6번은 0번만 대체한다.** 위협을 찾았다면 관측이 불완전해도 그 발견은 유효하므로 1·2가 우선한다 — 불완전성은 "없다"를 뒤집을 뿐 "있다"를 뒤집지 못한다. 4·5는 실행 자체가 성립하지 않았거나 가드가 막은 것이므로 6보다 우선한다.

관측이 불완전해지는 경우는 **일곱**이다.

| 원인 | 어디에 기록되는가 |
|---|---|
| 상한 도달로 수집이 잘림 | `scope.truncated` |
| 접근 거부로 열지 못한 디렉터리 | `scope.denied_dirs` |
| 선언했으나 수집기가 아직 없는 subject | `scope.subjects`에는 있고 본문에 배열이 없음 |
| **선언한 `scan_roots` 가 전부 존재하지 않음** | `scope.missing_roots` |
| **선언한 자리를 있는지조차 물어보지 못했음** (2026-10-27 · B-9) | `scope.unreadable_roots` — 아래 |
| **재지 못한 YARA 가 레코드의 매치를 갈랐음** (2026-10-26) | `scan.json`·`plan.json` 의 `observation.unevaluated_rules` — `artifacts.json` 에는 없다 |
| **버전을 견주지 못했음** (2026-10-27 · C-1) | `scan.json`·`plan.json` 의 `observation.unreadable_versions` — 위와 같은 자리이고 낱말만 다르다 |

> **`scope.unreadable_roots` (2026-10-27 · B-9).** `missing_roots` 와 다른 칸인 이유는
> **"없다" 와 "모른다" 가 다른 말**이기 때문이다. 선언한 자리를 물었을 때 돌아오는
> 답은 셋이다 — 있다 · 없다 · **못 물었다**(권한이 막혔거나 도달 불가 UNC 거나
> 심링크가 돌거나 · 레지스트리면 부모 키가 막혔거나). 셋째를 "없다" 로 접으면 **열린 루트가 하나라도 같이 선언된 플러그인은
> 종료 0 "위협이 발견되지 않았습니다" 를 낸다** — `denied_dirs` 는 0 이고 주의 한 줄도
> 없이. 실측했다(고침 전 **0** → 고침 후 **6**). 막힌 자리를 선언한 플러그인이 하나뿐일
> 때는 `all_roots_missing()` 이 **우연히** 6 을 냈지만 사유가 "전부 존재하지 않아" 로
> 틀렸다. `denied_dirs` 로 합치지 않는 이유는 그 사유줄이 **"관리자 권한으로 다시
> 돌리십시오"** 를 권하기 때문이다 — 끊긴 UNC 에는 틀린 조언이다. 자리 하나만 적어도
> 되는 까닭: 선언 루트는 플러그인이 쓴 목록이라 길지 않고, 운영자가 고칠 대상은
> **그 경로 자체**다. **없는 루트는 그대로 `missing_roots`** 이고 청정 기계에서
> 종료 0 을 내는 길(§8 · B-8)은 건드리지 않는다 — 실측으로 확인했다.

> **`file.version` (2026-10-27 · C-1b).** 실행 파일의 버전을 필드로 담는다 —
> `StringFileInfo` 의 `FileVersion`, **공백 뒤 주석을 버린** 값이다. `version_lt` ·
> `version_gt` 가 바로 받는다. 2진 `VS_FIXEDFILEINFO` 가 아닌 이유는 그것이
> **공급사가 공지하는 눈금과 다르기** 때문이다(실물 3,410개 중 20.4% 가 갈린다 ·
> `postgres.exe` 는 문자열 `16.10` ↔ 2진 `16.0.10.0`). `0.0.0.0` 은 담지 않는다 —
> 담으면 버전을 선언하지 않은 파일 전부가 `version_lt` 에 맞는다.
> **`None` 은 "확인하지 않았다"** 이고 `signature` 와 같은 계약이다: 대상 형식이
> 아니거나, 상한을 넘어 읽지 않았거나, 리소스가 없다. **ELF 에는 그 구조가
> 없으므로 리눅스 룰에서는 사실상 빈다** — 다만 비는 축이 플랫폼이 아니라 **파일
> 형식**이라 `NOT_POPULATED_YET` 에 적을 수 없다(리눅스 코퍼스의 WSL 드라이버
> 저장소에 PE 1,519건이 있다 · 실측).

세 번째가 미묘하다. 플러그인이 `subjects: [file, service]`를 선언했는데 코어에 `service` 수집기가 없으면, 그 룰은 영원히 매치하지 않는다. 조용히 "위협 없음"이 나오고 작성자는 룰이 틀렸다고 생각한다. **선언한 subject의 배열이 본문에 없다는 것이 곧 "수집하지 못했다"** 이다 — 수집기가 있으면 결과가 비어 있어도 빈 배열이 들어간다.

**네 번째는 실측으로 나왔다** (관측 01 D2). `scan_roots` 에 존재하지 않는 경로만 들어간 실행이 **파일 0건 · `truncated=false` · `denied_dirs=0` 으로 "완전한 관측"이 되고 종료 코드 0 "위협 없음"을 냈다.** 잘린 것도 거부당한 것도 아니어서 앞의 셋에 하나도 걸리지 않았다. 아무것도 읽지 않은 스캔이 그 PC를 깨끗하다고 선언한 것이다.

일부 루트가 없는 것은 **불완전이 아니다.** 플러그인이 여러 벤더 폴더를 나열하면 설치되지 않은 제품의 경로는 당연히 없고, 그때마다 6번을 내면 무인 배포에서 곧 무시된다. `missing_roots` 는 항상 기록하되 판정을 뒤집는 것은 **전부 없을 때**다 — 6번이 답하는 물음이 "뭔가 이상한가"가 아니라 **"0을 말할 수 있는가"** 이기 때문이다.

**여섯 번째는 수집이 아니라 평가가 안다** (결정 2026-10-26). 훑을 본문이 없으면 YARA 는 "안 맞았다"가 아니라 "재지 못했다"인데(설계-03 §1), 그 사실이 `issues`(stderr)에만 남아 판정이 없으면 0이 나갔다. **레코드의 매치나 제외를 갈랐을 때만** 센다 — 형제 술어가 이미 거짓으로 정한 레코드의 미평가까지 세면 술어 순서만으로 0과 6이 갈리고, 청정 기계가 늘 6을 내 6이 무시된다. 판정식은 보지 않는다(보수 쪽) — 다른 필수 규칙이 0이어서 판정이 어차피 서지 않아도 6이 될 수 있다.

이 사실은 `scan.json`·`plan.json`에도 `observation`으로 실려 간다. 각 산출물은 홀로 읽혀야 한다(설계-03 §1) — `plan.json`만 받아 든 사람이 "이 계획의 전제가 된 관측이 온전했는가"를 물을 수 없으면 그 물음은 영영 답을 얻지 못한다. 그래서 `observation` 은 `missing_roots` 와 함께 **`declared_roots`(선언된 루트 개수)도 싣는다** — 개수를 모르면 "전부 없었는가"를 홀로 판단할 수 없다.

**`verify` 도 같은 규칙을 따른다** (결정 2026-10-26). 재평가는 다시 선 판정(2) > 남은 증거(3) > 다 보지 못함(6) > 치료 성공(0) 순으로 가린다 — 찾은 것이 먼저고, 6은 여기서도 0만 대체한다. 그 전에는 다 보지 못한 재평가도 판정도 남은 증거도 없으면 0이었고, 재부팅 뒤 사람 없는 회차에서 그 0이 "치료가 유지됐다"로 읽혔다(설계-03 §8). 재검사 기록(`verify/<run_id>.jsonl`)은 관측이 불완전하면 **결과와 무관하게**(2·3과 겹쳐도) 그 `observation` 을 함께 싣는다 — 온전한 회차의 줄에는 없다.

---

## 9. 격리 컨테이너 포맷

실행 1회당 파일 1개. `<quarantine>/<run_id>.rq`

```
  +----------------------------------------------------------+
  | magic "RMDYQ" | fmt_ver | header(JSON, 평문)              |   header: run_id, created,
  +----------------------------------------------------------+           core_version, cipher,
  | entry[0]: nonce | AEAD(메타데이터 + 본문) | tag           |           wraps[]
  | entry[1]: ...                                            |
  +----------------------------------------------------------+
  | manifest: AEAD(엔트리 색인 + 원본 위치 + 다이제스트)      |
  +----------------------------------------------------------+
```

**헤더는 평문 전체가 AEAD 의 AAD 로 함께 인증된다.** 묶지 않으면 wrap 슬롯을 지우거나 `fmt_ver` 를 바꿔치기하는 변조가 인증을 통과한다.

`wraps[]` 는 콘텐츠 키를 감싼 슬롯 목록이다 — `{ kind: local|pass|org, key_id, alg, ct }`. 키 없이도 "내가 이것을 열 수 있는가"를 판단하려면 평문이어야 한다 (설계-03 §5 키 관리).

헤더가 답해야 하는 물음은 **셋뿐**이고, 그 이상은 담지 않는다.

1. **이 파일이 무엇인가** — `magic` · `fmt_ver` · `core_version`
2. **내가 이것을 열 수 있는가** — `wraps[]` 의 `kind` · `key_id` · `cipher`
3. **어느 실행에서 나왔는가** — `run_id` · `created`

**플러그인 ID·위협 이름·원본 경로·엔트리 개수는 평문에 두지 않는다.** 엔트리 색인은 암호화된 manifest 에 있다. 이 결정의 근거와 그것이 지키는 범위는 설계-03 §5 "평문 헤더는 세 물음에만 답한다"에 있다.

### 엔트리 종류별 저장 항목

**닫힌 집합 14종이다.** 종류는 P5에서 전부 정의되고 직렬화는 Phase별로 들어온다(설계-09 §3.6) — subject 18종·Op 29종과 같은 방식이다.

| 종류 | 저장 내용 |
|---|---|
| `file` | 본문, 원본 절대 경로, 크기, 해시, 타임스탬프(생성/수정/접근), 소유자·권한 |
| `file_stream` | 호스트 파일 경로, 스트림 이름, 스트림 본문 |
| `directory` | 루트 경로, **하위 전체**(목차 + 이어 붙인 본문), 빈 디렉터리 목록, 파일마다 권한·타임스탬프 |
| `registry_value` | hive·key·name, 값 **타입**, 원본 바이트 데이터 |
| `registry_key` | 키 경로, 하위 트리 전체(값·하위 키 포함) |
| `task` | 작업 정의 XML 전문, 등록 경로, 사용 계정 |
| `service` | 서비스 설정 전체(시작 유형·의존성·이미지 경로·계정) |
| `cron` | 원본 라인, 소속 파일, 파일 내 위치, 파일 권한 |
| `unit` | 유닛 파일 전문, 경로, enable 상태·심볼릭 링크 위치 |
| `text_line` | 원본 라인, 파일, 라인 번호, 파일 권한 |
| `structured_config` | 파일 경로, 키 경로, **파일 원본 전체**, 파일 권한 |
| `av_exclusion` | 변경 전 목록 전체(부분 diff 아님) |
| `cert_store` | 저장소 위치(Root/CA/My · Machine/User), 인증서 DER, 지문 |
| `boot_config` | 어느 설정 항목인가, 원본 값 |

**왜 지금 전부 열거하는가**: 격리물은 자동 삭제하지 않으므로(설계-03 §5) P5·P6에서 만든 컨테이너가 P7·P8에서도 열려야 한다. **포맷 실수는 영구적이다.** 실제로 이 표는 8종이던 시점에 28개 Op 중 11개가 담길 자리가 없었다 — `registry.delete_key`는 키 트리를, `cert_store.remove`는 인증서를, `boot.restore_default`는 부트 설정을 넣을 곳이 없었다. 그대로 갔다면 P7에서 `fmt_ver`를 올리고 파서를 두 벌 유지해야 했다.

> `structured_config` 가 **값이 아니라 파일 전체**를 담는 이유: JSON 을 파싱해 고쳐 쓰면 들여쓰기와 키 순서가 바뀐다. 값만 담아 두면 복원이 그 편집된 형태 위에 값을 되돌리는 것이라 **원본 바이트로 돌아가지 못한다.** 파일 전체를 담으면 편집 방법과 무관하게 복원이 정확하다. 설계-03 §2 의 백업 표가 처음부터 "파일 원본 전체" 였고, 이 표가 그것과 어긋나 있었다.
>
> 반대로 `text_line` 은 줄 하나로 충분하다. 줄을 종단 문자까지 그대로 들고 있다가 같은 자리에 다시 넣으면 나머지 바이트는 손대지 않기 때문이다.

> `directory` 가 **본문을 갖는** 이유: 이 표는 처음에 "본문 없음" 이라고 적었다 — 디렉터리 엔트리는 구조와 권한만 담고 파일 내용은 옆의 `file` 엔트리들이 담는다는 그림이었다. 그러려면 **Action 하나가 엔트리 여럿을 만들어야 하는데**, 저널의 `seq → entry_id` 대응과 복원 화면의 `--entry` 선택이 둘 다 1:1 을 전제한다. 그것을 1:N 으로 바꾸는 값보다, 하위 전체를 엔트리 **하나**에 담는 값이 크다.
>
> 담는 모양은 `meta` 에 목차(상대 경로·크기·파일별 권한·**빈 디렉터리 목록**), `content` 에 목차 순서대로 이어 붙인 본문이다. base64 로 감싸지 않는다 — 33% 가 그대로 격리소 용량이 된다. 빈 디렉터리를 따로 적는 이유는 그것이 파일 목록에 흔적을 남기지 않기 때문이고, 그대로 두면 복원된 확장이 원래 모습이 아니다.
>
> 목차는 컨테이너에서 온다. 그래서 되돌릴 때 **상대 경로가 루트 안에 머무는지 다시 본다** — `../../..` 하나면 복원이 아니라 임의 경로 설치다 (불변식 R).

**종류를 늘리지 않은 자리**: `hosts.restore_line` · `text_config.remove_line` · 셸 자동실행 라인은 저장할 바이트가 같다(원본 줄·파일·위치·권한). 그래서 `text_line` 하나로 담는다 — **컨테이너는 저장 포맷이지 복원 로직이 아니다.** 되돌릴 때의 처리가 다른 것은 Op의 몫이다. 이전 표의 `shell_line` 이 여기로 흡수됐다.

**한 Op이 여러 종류를 쓸 수 있다**: `autorun.remove` 는 Run키면 `registry_value`, 시작 폴더면 `file`, `.bashrc` 면 `text_line`, systemd면 `unit`, cron이면 `cron` 이다. 무엇을 담을지는 실제 대상을 보는 실행 시점에 정해지며, 이는 불변식 P와 무관하다 — 어떤 Op이 무엇에 대해 도는지는 계획이 이미 고정했고 백업 종류는 그 대상의 성질에서 나온다.

**`process.kill` 만 백업 종류가 없다.** 죽은 프로세스는 되살릴 수 없다. SDK의 `Op::backup_kinds()` 가 빈 배열을 반환하는 유일한 Op이며, `OpInfo::reversible` 과 정확히 반대로 대응한다 — **되돌릴 수 있다고 선언해 놓고 담을 자리가 없으면 그 Op은 복원 불가능한 파괴가 된다.** 이 대응은 테스트가 강제한다.

### 복원 가능 범위와 손실 항목

| 항목 | 복원 | 저장해야 할 것 |
|---|---|---|
| 파일 본문 | 가능 | 바이트 전체 + 해시 |
| 수정 시각(mtime)·접근 시각(atime) | 가능 | 나노초 정밀도 값 |
| Windows 소유자·그룹·DACL·SACL | 가능 | **SDDL 문자열**(자기상대 보안 디스크립터) |
| Linux mode·uid·gid | 가능 | 값 그대로 |
| Linux 확장 속성(xattr) | 가능 | 네임스페이스별 원시 바이트 |
| SELinux 컨텍스트 | **조건부** | `security.selinux` xattr. 정책이 거부하면 root라도 실패 |
| POSIX ACL | 가능(수작업) | `system.posix_acl_access` 원시 바이트. 인코딩을 직접 다뤄야 함 |
| **inode 변경 시각(ctime)** | **불가** | 커널 관리, 설정 syscall이 존재하지 않음 |
| **생성 시각(btime)** | **Windows 가능 · Unix 불가** | Windows 는 `SetFileTime`(std 의 `FileTimesExt::set_created`). Unix 에는 설정 syscall 이 없다 |

> **2026-08-28 정정.** 이 줄은 원래 "불가 — 읽기만 가능, 설정 syscall이 없음" 이었고, 구현이 **양쪽 플랫폼에 그 Unix 의 사실을 적었다.** Windows 에는 설정 API 가 있다. 그 사이 격리로 지운 파일을 되살리면 생성 시각이 되살린 순간이 됐고, P9 하네스의 G2(지문 대조)가 그것에 걸렸다 — 앞선 회차가 통과한 것은 NTFS 파일 터널링(같은 이름·같은 디렉터리로 15초 안에 다시 만들면 생성 시각을 물려준다)이 짧은 왕복을 가려 준 덕이었을 가능성이 크다. **그 초록은 복원 능력이 아니라 타이밍이었다.**

**되살릴 수 없는 항목이 있으면 복원 실행 전에 목록으로 고지한다.** "복원했습니다"라고 뭉뚱그리지 않는다.

두 가지 운영 제약을 문서와 UI에 함께 적는다. SACL 복원에는 `SeSecurityPrivilege`, 소유자 변경에는 `SeRestorePrivilege`/`SeTakeOwnershipPrivilege` 가 필요하다. 그리고 SDDL 안의 SID가 복원 대상 머신에서 해석돼야 하므로, **다른 머신·다른 도메인에서 원래 자리로 되돌리는 경로는 지원 범위에서 제외**한다.

### 여는 것과 되돌리는 것은 다르다

위 제약과 설계-03 §5의 조직 복구 키가 모순처럼 보이므로 정확히 가른다. **컨테이너를 여는 것**과 **원래 자리로 되돌리는 것**은 별개다.

| | 무엇을 하나 | 어디서 | 메타데이터 |
|---|---|---|---|
| `restore` | 원본 경로에 제자리 복원 | **원래 머신에서만 보장** | 전부 (SDDL·mode·xattr) |
| `restore --extract-to <dir>` | 지정한 디렉터리로 본문을 꺼냄 | **아무 머신에서나** | 복원하지 않고 **목록으로 고지** |

조직 복구 공개키 wrap 이 실제로 사는 것은 **꺼내기**다. 설계-03 §5의 동기가 "머신을 재설치하는 순간 격리물이 영구히 열리지 않는다 — 오탐으로 격리된 사용자 문서가 그대로 소실된다"이므로, 필요한 것은 **내용을 되찾는 것**이지 낯선 머신에 원래 ACL로 되돌리는 것이 아니다. SID가 해석되지 않는 머신에 SDDL을 억지로 적용하면 잘못된 권한이 붙는다 — 그것이 지원 범위에서 제외되는 이유다.

명령을 새로 만들지 않고 `restore` 의 플래그로 둔 이유는, 두 동작이 컨테이너 해석과 키 처리를 그대로 공유하며 **제자리 복원이 기본이고 꺼내기가 명시적 선택**이라는 위계를 드러내기 위해서다.

봉인 목적과 암호화의 정직한 한계, 보존 정책은 설계-03 §5 참조.

---

## 10. 호환성 규칙

버전이 세 개(`schema_version`, `min_core`, 플러그인 `version`)이므로 역할을 먼저 못 박는다.

| 필드 | 무엇을 말하는가 | 누가 검사하는가 |
|---|---|---|
| `schema_version` | 이 플러그인이 쓰는 **스키마 문법 세대** | 코어가 자기 지원 범위와 대조 |
| `min_core` | 이 플러그인이 요구하는 **코어 기능 최소 버전** (새 Op, 새 subject 등) | 코어가 자기 버전과 대조 |
| `version` | 플러그인 자신의 버전 | 폐기·역행 금지 판정 (설계-03 §6) |

`schema_version` 은 문법, `min_core` 는 기능이다. 문법은 그대로인 채 새 Op 만 추가되는 경우가 흔하므로 두 값이 따로 움직인다. **둘 다 만족해야 로드된다.**

- `schema_version` 은 **파괴적 변경에서만** 증가한다. 코어는 자기보다 높은 `schema_version` 의 플러그인을 로드하지 않는다
- 필드 추가는 하위 호환으로 취급하되, **알 수 없는 필드는 무시하지 않고 거부**한다. 오타 난 안전 관련 키(`exclude` → `exlude`)가 조용히 무시되면 그것이 사고다
- Op 목록에서 항목을 제거할 때는 최소 1개 마이너 버전 동안 경고 후 제거
- `min_core` 대조는 **코어 1.2.0 부터** 검사·치료가 룰을 읽을 때마다 한다(`validate` — 린트는 그 결과를 그대로 담는다). 1.1.3 까지는 린트에만 있어, 낡은 코어가 더 새 코어를 요구하는 룰을 거절하지 않고 돌렸다(2026-11-08 실측 — 공개된 1.1.3 에 `min_core: "1.2.0"` 인 룰). 그래서 룰은 같은 릴리스의 코어로 돌린다

---

## 11. 확정된 것과 남은 것

**확정** (설계-01 참조)

- YARA 통합 = `yara-x` 크레이트 네이티브 임베드. `magic-module` 은 켜지 않는다
- 스크립트 런타임 = **v1 범위 제외.** §7의 경계선과 API 목록은 확정하되 구현하지 않는다. 첫 플러그인이 룰만으로 표현되므로 지금 고르면 근거 없는 선택이 된다
- §9 복원 가능 범위 표 확정. ctime 은 복원 불가로 확정. **btime 은 2026-08-28 에 Windows 가능으로 정정** (위 표의 각주)

**남은 것**

- ~~서명 방식 확정~~ — **2026-08-25 (P10) 확정.** minisign 포맷(Ed25519). 서명 대상은 파일 하나가 아니라 **트리 전체를 적은 목록**(`MANIFEST`)이다 — 파일마다 서명하면 파일을 하나 더 넣는 공격을 막지 못한다. 설계-01 미결 5 를 함께 본다.
- `value` 의 `${...}` 보간 문법 상세 — 이스케이프 규칙, 미해결 참조 시 동작(현재 방침: **컴파일 오류로 거부**, 빈 문자열 대체 금지)
- `capture` 파이프 함수의 실패 시 동작 — 현재 방침: 해당 룰 미매치 + 경고 기록
