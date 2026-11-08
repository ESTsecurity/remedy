<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# 매니페스트 키

선행: `00-invariants.md` · 권위 있는 정의는 `machine/plugin.schema.json`

## 키 전수

| 키 | 필수 | 무엇 |
|---|---|---|
| `schema_version` | ● | 지금은 `1` |
| `id` | ● | 전역 고유. `[a-z0-9-]+` |
| `version` | ● | semver. **폐기 목록의 `min_plugin_version` 이 이것을 본다.** 고객 화면 첫 줄에 적히므로 **룰이나 매니페스트를 고치면 올린다** — `cargo xtask plugin-lock` 이 그것을 강제한다 |
| `min_core` | ● | 요구하는 코어 최소 버전. `주.부.수` 세 자리. **코어가 룰을 읽을 때마다 자기와 비교해** 더 높으면 돌지 않는다(린트도 오류). **이 문서에 있는 Op 은 전부 `1.0.0` 부터 있다** — `P6`·`P10` 같은 Phase 는 개발 순서이지 배포 판이 아니라 둘을 잇는 표는 없다 |
| `platforms` | ● | `[windows]` · `[linux]` · 둘 다 |
| `name` | ● | `{ ko: …, en: … }` — **고객 화면의 첫 줄**이다. 두 언어 다 적는다. 한쪽이 비면 린트 오류 |
| `scan_roots` | ● | **읽기 권한 상한** (아래) |
| `subjects` | ● | 열거 허용 대상. **선언하지 않은 subject 는 `detect` 에서 못 쓴다** |
| `detect` | ● | 탐지 규칙 (`20-detect-recipes.md`) |
| `verdict` | ● | 판정식 |
| `kind` | | `check` = **점검 전용**(`24-check-plugins.md`). 없으면 치료 |
| `allow_removable` | | 이동식 매체. 기본 `false` |
| `references` | | 근거 링크 |
| `signed_malware` | | 서명된 악성코드 예외 (`22-remediate-recipes.md`) |
| `remediate` | | 제거 선언 (`22-remediate-recipes.md`) |
| `collect_extra` | | 본문 수집 (`23-collect-and-submit.md`) |
| `submit_hint` | | 손으로 올릴 때 볼 판단 근거 (〃). **자동 제출은 없다** — `support-bundle` 이 보여 준다 |

**알 수 없는 키는 무시가 아니라 거부다.** 오타 난 키가 조용히 빠지면 그 선언은
없는 것이 되고 아무도 모른다.

---

## `scan_roots` — 성능이 아니라 권한 상한

서명된 플러그인이 임의 경로를 읽을 수 있으면 그 자체가 정보 수집 도구가 된다.
**여기 밖은 읽을 수도 지울 수도 없다.**

```yaml
scan_roots:
  - "%LOCALAPPDATA%\\Programs"          # 페이로드가 자리잡는 곳
```

> **예약 작업 경로가 여기 없는 것이 맞다.** 아래 표가 그 이유다 —
> `persistence` 는 `scan_roots` 와 무관하게 수집된다. 적어도 예약 작업이 더
> 읽히지 않고, 작업 정의 XML 이 `file` 로 딸려 들어와 **지울 수 있는 범위만
> 넓어진다**(실측: 219건). 2026-09-01 까지 이 예제가 그것을 적어 두었고,
> 그것을 보고 쓴 답 여섯 편이 전부 따라 적었다.

### 무엇에 걸리고 무엇에 안 걸리는가

**수집기가 `scan_roots` 를 보는가로 갈린다.** 레코드에 `path` 가 있는지가
아니다 — 레지스트리 값에는 `path` 가 없는데도 이 상한을 받는다.

| `scan_roots` 가 범위를 정한다 | `file` · `text_config` · `structured_config` · `shortcut` · `browser_extension` · `registry_value` · `registry_key` |
|---|---|
| **무관하게 수집된다** | `persistence` · `autorun` · `process` · `service` · `av_exclusion` · `firewall_rule` · `hosts_entry` · `cert_store` · `proxy_config` · `boot_config` · `indicator` · `package` · `unix_socket` |

> **레지스트리 값·키는 `scan_roots` 에 레지스트리 루트를 적어야 모인다.**
> 수집기가 `scan_roots` 에서 `HKLM\…` 모양인 것만 골라 그 아래를 훑는다.
> 적지 않으면 **`registry_value` 는 언제나 0건**이고, 그 위에서 도는 룰은
> 아무것도 맞히지 못한 채 초록이 된다.
>
> **`autorun` 은 반대다.** `HKCU\…\Run` 을 넣어도 아무 효과가 없다 — 그 자리는
> 수집기가 알고 있고 `subjects` 만 선언하면 된다. 둘을 섞지 말 것.
>
> 2026-09-01 까지 이 표가 `registry_value` 를 아래 칸에 두고 *"레지스트리 경로를
> 적지 않는다"* 고만 적었다. 그대로 따르면 그 subject 를 영영 모으지 못한다.

#### 하위 키 이름을 모를 때 — 끝의 `\*`

**값 수집은 재귀하지 않는다.** 적은 키의 직속 값만 읽는다. 그런데 하위 키
이름이 검체마다 달라지는 자리가 있다 — IFEO 는 하이재킹당한 실행 파일 이름마다
키를 하나씩 두고 `Debugger` 는 그 **안**에 있다.

그 자리에는 **맨 끝에 `\*` 를 붙인다.** 그 키의 직속 하위 키로 펼쳐진다.

```yaml
scan_roots:
  # …\Image File Execution Options\<exe명>\Debugger 까지 닿는다
  - "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*"
```

| | |
|---|---|
| **맨 끝에서만** | 전개기가 첫 번째 별표만 펼친다. 중간에 두거나 둘 이상 쓰면 나머지가 리터럴로 남아 **조용히 0건**이 된다. 린트가 막는다 |
| **한 단계만** | 재귀가 아니다. 손자 키의 값은 안 온다 |
| **파일 경로는 마지막 칸의 이름 꼴만** | `…\\Temp\\*.js` 는 그 폴더 바로 아래의 맞는 파일만 고른다(코어 1.2.0 · 폴더 자체는 상한 밖). `%LOCALAPPDATA%\\*` 와 폴더 칸의 `*` 는 오류다 |
| **폭을 벌지 못한다** | `HKLM\\SOFTWARE\\*` 는 `HKLM\\SOFTWARE` 와 같은 깊이로 재진다. 별표는 좁히는 것이 아니라 **넓히는 것**이라서다 |

> `HKU\\*` 는 이것의 특수한 경우이자 지정 토큰이라 중간에 와도 된다
> (`HKU\\*\\Software\\…`). 사용자 SID 마다 하나로 펼쳐진다.

#### subject 하나만 더 좁힐 때 — `subject_roots`

넓게 잡을 수밖에 없는데 **한 subject 만 그 폭을 감당하지 못하는** 자리가 있다.
페이로드 폴더 이름은 증거에서 파생되므로 부모인 `%PROGRAMDATA%` 를 적어야
하는데, 거기에 `structured_config` 를 함께 두면 JSON 을 잎 단위로 펴다 상한에
걸린다 — 실측(당시 상한 5만): 정확히 **50,000 에서 잘려 종료 코드 6**(관측 불완전)이었다.
상한은 지금 500,000 이지만 넓은 루트에 펴는 것은 여전히 낭비다.

```yaml
scan_roots:
  - "%PROGRAMDATA%"                                  # 파일은 여기 전부
subject_roots:
  structured_config: ["%PROGRAMDATA%\\Acme\\Agent"]  # 설정은 여기만
```

| | |
|---|---|
| **좁히기만 한다** | 여기 적는 경로는 `scan_roots` 안이어야 한다. 밖이면 린트가 **오류**로 막는다 — 읽기 권한의 상한은 여전히 `scan_roots` 하나다 |
| **적지 않으면 전부** | 이름이 없는 subject 는 `scan_roots` 를 그대로 쓴다 |
| **빈 목록은 오류** | "아무 데도 보지 않는다" 이고 결과는 조용한 0건이다 |
| **자리가 정해진 subject 에는 뜻이 없다** | 위 표의 아래 칸에 있는 것들. 적으면 경고한다 |

#### 확장자 밖의 설정 디렉터리 — `text_config_dirs`

코어는 **확장자**로 설정 파일을 가린다(`.ini` · `.conf` · `.htaccess` …). 그런데
**드롭인 디렉터리의 파일은 확장자가 없다** — 실측(청정 코퍼스): `/etc/pam.d/`
171건이 전부 그렇고 줄 단위로 잡힌 것이 **0건**이었다. 그리고 거기에 **파일
하나를 떨어뜨리는 것**이 그 자리를 쓰는 수법이라, 이름을 미리 적어 막을 수 없다.

```yaml
scan_roots: ["/etc"]
subjects: [text_config]
text_config_dirs: ["/etc/pam.d", "/etc/sudoers.d"]   # 확장자와 무관하게 전부
```

| | |
|---|---|
| **상한 안에서만** | `scan_roots` 밖이면 린트가 **오류**로 막는다. `subject_roots` 와 방향만 반대다 — 그쪽은 좁히고 이쪽은 같은 상한 안에서 읽는 것을 넓힌다 |
| **직접 자식만** | 하위로 내려가지 않는다. 드롭인 디렉터리는 평평하고, 재귀라면 `/etc` 한 줄로 트리 전체가 설정이 된다 |
| **상한 자체를 적으면 경고** | `/etc` 를 적으면 `shadow`·`passwd` 가 줄 단위로 스냅샷에 들어온다 |
| **`key`·`value` 가 빌 수 있다** | `키=값` 이 아닌 줄은 `line` 만 찬다(`.htaccess`·`pam.d`가 그렇다). 그 자리는 `line contains` 로 겨눈다 |
| **확장자를 보지 않는다** | 그 디렉터리의 파일은 **전부** 줄 단위로 들어온다 — `.php` 같은 소스도 그렇다. 정상 `.php` 에 심은 코드를 `text_config.remove_line` 으로 뺄 수 있다(실측: 원본 바이트로 되돌아온다) |
| **그 줄이 통째로 빠진다** | 지우는 단위가 **줄**이다. 심은 코드가 정상 코드와 **같은 줄**에 있으면 정상 코드까지 사라진다(실측: 문법은 멀쩡하고 동작이 깨진다). 그런 자리는 이 Op 으로 고치지 않는다 |

### 이름을 미리 알 수 없는 경로 조각

브라우저 프로필처럼 **경로 한 조각이 기계마다 다른** 자리가 있다. 파일 경로에는
`\*` 를 쓸 수 없으므로(레지스트리 전용이다) 둘 중 하나를 골라야 한다.

| 고르는 것 | 얻는 것 | 잃는 것 |
|---|---|---|
| `…\\User Data\\Default\\Extensions` | 상한이 확장 폴더까지다 | `Default` 아닌 프로필을 놓친다 |
| `…\\User Data` | 프로필 전부를 덮는다 | 쿠키·기록·로그인 정보가 상한에 든다 |

**앞쪽을 권한다.** `scan_roots` 는 권한 상한이고, 넓힌 만큼 그 플러그인이
읽을 수 있는 것과 **지울 수 있는 것**이 함께 커진다. 실측(2026-09-02,
Win10x64-Test)으로 `User Data` 아래 디렉터리가 Edge 53 · Chrome 35 개인데
**그중 프로필은 각각 하나**였다 — 넓혀서 얻는 것보다 껴안는 것이 많다.

> 뒤쪽을 골라야 하는 근거(그 기계에 프로필이 여럿이라는 관측)가 있으면 그렇게
> 하고, **서명 단계에서 그 이유를 적는다.**

> **자리를 증거에서 뽑을 때도 같다.** 폴더 이름을 값에서 얻으면 상한이
> 부모(`%PROGRAMDATA%`)밖에 없어 보이지만, 그 이름을 관측한 기계에서는
> **관측한 대로 적는 것이 좁은 쪽**이다. `from` 은 규칙이 무엇에 맞는지만
> 좁히고 **무엇을 읽는지는 좁히지 않는다** — 수집 범위는 `scan_roots` 와
> `subject_roots` 가 정한다(30번 12와 같은 사실이다).
> *"변종에서 바뀔 수 있다"* 는 가정이지 관측이 아니다.

### 좁아도 위험하다

넓으면 삭제 권한이 넓어지고 린트가 경고한다. **좁으면 아무것도 수집되지 않아
룰이 통째로 죽는다** — 그리고 그쪽은 아무도 경고하지 않는다.

**코퍼스 시험과 `xtask exam` 은 이것을 재지 못한다.** 스냅샷은 이미 수집된
것이고, 평가기는 파일 시스템을 열 수 없어 토큰을 확장하지 못한다. 그래서
**존재하지 않는 경로를 선언해도 코퍼스에서는 전부 통과한다.** 실기기 `scan` 에서만
드러난다.

서명 전에 실기기에서 한 번 돌리는 것이 그 자리다(`40-review-checklist.md`).

### 지정 확장 토큰

| 토큰 | 확장 | `allow_removable` |
|---|---|---|
| `%ALLUSERPROFILES%` | **사용자 수만큼** | - |
| `HKU\*` | 로그온한 하이브 수만큼 | - |
| `%REMOVABLE%` | 꽂힌 매체 수만큼 | ● |

**하나가 여럿이 된다.** `%ALLUSERPROFILES%` 를 쓰지 않으면 다중 사용자 기계에서
현재 로그온 사용자만 치료되고 나머지는 감염 상태로 남는다.

`%LOCALAPPDATA%` 같은 보통 환경변수는 **현재 사용자 하나**다. 위협이 사용자마다
설치되는 것이면 `%ALLUSERPROFILES%` 쪽을 쓴다 — 다만 그만큼 삭제가 닿는 범위도
넓어지므로 그 이유를 매니페스트에 적는다.

---

## `subjects` — 선언한 것만 수집된다

```yaml
subjects: [persistence, file, autorun, av_exclusion, process]
```

`detect` 에서 쓰는 subject 를 전부 여기 적어야 한다. 빠뜨리면 린트가 거부한다.

**`restore` 가 쓰는 subject 도 필요하다.** `restore: [av_exclusions]` 는
`av_exclusion` 증거를 되돌리므로, 그 subject 를 선언하고 탐지 규칙도 둬야 한다
(`22-remediate-recipes.md`).

### subject 는 플랫폼마다 수집 여부가 다르다

`machine/REFERENCE.md` 의 subject 표에 Windows·Linux 열이 있다. **개념이 있다는
것과 이 코어가 수집한다는 것은 다르다** — 부팅 구성(GRUB)은 Linux 에도 있지만
`boot_config` 의 Linux 칸은 `개념만` 이다. 수집기가 없으므로 그 subject 를 선언한
룰은 Linux 에서 아무것도 맞히지 못한다.

| 표기 | 뜻 | 작성자가 할 일 |
|---|---|---|
| `P4` 같은 Phase | 그 Phase 부터 수집한다 | 쓴다 |
| `개념만` | 개념은 있으나 **수집기가 없다** | 요청한다. 기다리면 온다 |
| `—` | 그 플랫폼에 **개념이 없다** | 룰을 다시 짠다 |

린트가 둘 다 잡는다. `platforms` 가 그 플랫폼 하나뿐이면 **오류**(아무것도
수집하지 못한다), 교차 플랫폼이면 **경고**(다른 쪽에서는 동작한다)다.

실행 시점에도 같은 것을 본다 — 수집기가 없는 subject 는 범위에서 빠지고
"선언한 것을 못 봤다" 로 보고된다. **조용히 0건이 되지 않는다.**

---

## `boot_config` — 값이 정해져 있고, 치료 대상이 없다

레코드가 **하나**이고 필드 값이 열거다. 경로가 없으므로 `from` 도 쓸 수 없다.

| 필드 | 값 |
|---|---|
| `safeboot_available` | `yes` · `partial` · `no` · `unreadable` · `unknown` |
| `recoveryenabled` | `yes` · `no` · `unknown` |

```yaml
subjects: [boot_config, persistence]
detect:
  - id: safemode-locked
    subject: boot_config
    where:
      - { field: safeboot_available, op: equals, value: unreadable }
```

**`no` 와 `unreadable` 은 다르다.** `no` 는 안전 모드 키가 **없는 것을 봤다**는
뜻이고, `unreadable` 은 **이름은 있는데 열리지 않는다**는 뜻이다. 실기기에서
잠그는 쪽이 지우는 쪽보다 훨씬 싸므로(하위 항목이 `TrustedInstaller` 소유라
지우려면 소유권부터 가져와야 한다) 후자가 더 흔하다. 보안 정책이 잠근 것일
수도 있으니 **이것 하나로 판정하지 말 것** — 다른 근거와 논리곱으로 쓴다.

> **이 subject 는 치료로 이어지지 않는다.** 레코드에 대상이 될 경로도 키도
> 없어 계획기가 Action 을 만들지 못한다. **판정 근거로만 쓴다.** 손상을 알리는
> 것은 코어가 재시작을 권하기 전에 스스로 한다 (설계-00 §6).

## `platforms`

```yaml
platforms: [windows]
```

`win.*` 필드를 쓰면 `windows` 를, `linux.*` 를 쓰면 `linux` 를 선언해야 한다.
어긋나면 린트가 거부한다 — 그 필드는 그 플랫폼에 없고, **없는 필드는 조용한
미매치**가 되어 룰이 아무것도 못 잡은 채 초록이 된다.

### Op 도 플랫폼마다 다르다

`machine/REFERENCE.md` 의 Op 표에 Windows·Linux 열이 있다.

| 표기 | 뜻 |
|---|---|
| `P6` · `P12` 같은 Phase | 그 플랫폼에서 **그 Phase 부터** 수행한다 |
| `-` | 그 플랫폼에 **개념이 없다** — 기다려도 오지 않는다 |

레지스트리·대체 데이터 스트림·보안 제품 예외가 `-` 다. `platforms: [linux]` 로
선언한 플러그인이 그런 대상을 제거하려 하면 계획이 `deferred` 로 나간다 —
**조용히 빠지지 않는다.**

## `id` 와 `version`

서명·배포가 이 둘을 본다. `xtask sign` 이 만드는 서명 주석에 들어가고, 폐기
목록이 `id` 로 지목하며 `min_plugin_version` 이 `version` 과 비교된다. **버전을
내리면 로드되지 않는다**(역행 금지).

같은 위협의 룰을 고쳤으면 `version` 을 올린다. `id` 는 바꾸지 않는다 — 바꾸면
폐기 목록이 옛 `id` 를 계속 가리킨다.

## `allow_removable`

기본 `false`. 켜는 것만으로는 부족하고, 이동식 매체 대상 파괴는 대화형에서 별도
승인을 받으며 무인 모드에서는 계획에 아예 들어가지 않는다 — 연결된 USB 가 다른
사람의 것일 수 있다.

**USB 웜이 아니면 켜지 않는다.**
