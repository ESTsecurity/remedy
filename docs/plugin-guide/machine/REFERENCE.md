<!-- schema_version: 1 | min_core: 1.0.0 | generated: true -->

# 레퍼런스 (생성물 — 직접 고치지 말 것)

`remedy-sdk` 에서 생성된다. 고칠 곳은 `crates/remedy-sdk/src/catalog.rs` 다.
`cargo xtask schema` 가 이 파일과 SDK 의 일치를 검사한다.

- 스키마 버전: 1
- 현재 구현된 Phase: P12

## 관찰 대상 21종

**Windows** · **Linux** 열은 *이 코어가 그 플랫폼에서 수집하기 시작하는 Phase* 다.

`—` 는 그 플랫폼에 **개념이 없다** — 기다려도 오지 않는다. `개념만` 은 개념은 있으나 **이 코어가 아직 수집하지 않는다** 는 뜻이다. 그 subject 를 선언한 룰은 그 플랫폼에서 **0건**이 되고, `plugin lint` 가 둘 다 잡는다.

| subject | Windows | Linux | 설명 |
|---|---|---|---|
| `persistence` | P2 | P12 | 예약 작업 · cron · systemd timer |
| `autorun` | P4 | P12 | Run/RunOnce · 시작 폴더 · 셸 프로필 · XDG autostart |
| `service` | P4 | P12 | Windows 서비스 · systemd service · SysV · OpenRC · Upstart 시작 스크립트 |
| `process` | P4 | P12 | 실행 중인 프로세스와 로드된 모듈 |
| `file` | P2 | P12 | 파일 메타데이터 · 해시 · 서명 · 영역 · 대체 스트림 |
| `indicator` | P4 | P12 | 다른 관찰에서 파생된 지표 (url · domain · ip · hash) |
| `registry_value` | P4 | — | 레지스트리 값. 키 경로에 와일드카드 열거 허용 |
| `registry_key` | P4 | — | 레지스트리 키 단위 관찰 |
| `text_config` | P4 | P12 | ini · conf · 셸 프로필 등 줄 단위 설정 |
| `structured_config` | P4 | P12 | JSON · XML 등 구조적 설정 |
| `shortcut` | P4 | P12 | .lnk 바로가기 · .desktop 항목 |
| `boot_config` | P4 | 개념만 | 부팅 구성 · GRUB 항목 |
| `hosts_entry` | P4 | P12 | hosts 파일 항목 |
| `browser_extension` | P4 | P12 | 브라우저 확장 프로그램 |
| `av_exclusion` | P4 | 개념만 | 보안 제품 예외 목록. 탐지 근거이자 복원 대상 |
| `cert_store` | P4 | P12 | 신뢰할 수 있는 루트/게시자 저장소 |
| `proxy_config` | P4 | 개념만 | 프록시 설정 · PAC |
| `firewall_rule` | P4 | 개념만 | 방화벽 규칙. 자기 허용·보안 제품 차단이 여기 남는다 |
| `package` | — | P12 | 설치된 패키지. 배포판이 백포트한 판을 가리는 유일한 길 |
| `unix_socket` | — | P12 | 이름 있는 UNIX 소켓. 추상 이름은 `@` 로 시작한다 — 상주 임플란트가 여는 자리 |
| `archive_entry` | P4 | P12 | 아카이브(jar · war · ear · zip) 안의 항목 — 안쪽 경로 · 크기 · 해시 · 작은 글자 내용 |

### subject 별 필드 (닫힌 집합)

여기 없는 이름을 쓰면 `plugin lint` 가 거절한다.

- **`persistence`** — `id` · `name` · `enabled` · `trigger` · `command` · `args` · `principal` · `source` · `win.task.register_path` · `win.task.actions` · `win.task.run_level` · `win.task.working_directory` · `win.task.command_expanded` · `win.task.args_expanded` · `linux.cron.line_no` · `linux.cron.line`
- **`autorun`** — `id` · `scope` · `name` · `command` · `source`
- **`service`** — `id` · `name` · `state` · `start_type` · `image_path`
- **`process`** — `pid` · `ppid` · `image_path` · `cmdline` · `cmdline_decoded` · `args` · `user` · `start_time` · `modules` · `modules_denied`
- **`file`** — `path` · `size` · `mtime` · `ctime` · `sha256` · `streams` · `content_ref` · `version` · `signature.trusted` · `signature.subject` · `signature.thumbprint` · `zone.zone_id` · `zone.referrer_url` · `zone.host_url` · `package` · `package_match`
- **`indicator`** — `kind` · `value` · `source_ref`
- **`registry_value`** — `hive` · `key` · `name` · `type` · `data`
- **`registry_key`** — `hive` · `key` · `subkeys` · `values`
- **`text_config`** — `path` · `line_no` · `line` · `section` · `key` · `value`
- **`structured_config`** — `path` · `format` · `key_path` · `value`
- **`shortcut`** — `path` · `target` · `args` · `working_dir` · `icon`
- **`boot_config`** — `entry` · `recoveryenabled` · `safeboot_available`
- **`hosts_entry`** — `ip` · `hostnames` · `line_no` · `source` · `line`
- **`browser_extension`** — `browser` · `profile` · `ext_id` · `name` · `version` · `path`
- **`av_exclusion`** — `kind` · `value` · `source`
- **`cert_store`** — `store` · `subject` · `issuer` · `thumbprint` · `not_after` · `linux.path`
- **`proxy_config`** — `scope` · `server` · `pac_url` · `bypass`
- **`firewall_rule`** — `id` · `name` · `direction` · `action` · `enabled` · `protocol` · `local_port` · `remote_port` · `remote_address` · `application` · `service` · `profile` · `source`
- **`package`** — `name` · `version` · `upstream_version` · `revision` · `arch` · `source` · `manager` · `vendor`
- **`unix_socket`** — `name` · `inode` · `listening` · `kind`
- **`archive_entry`** — `archive` · `path` · `name` · `depth` · `size` · `sha256` · `text` · `error`

## 매니페스트 칸 (닫힌 집합)

받는 자리마다 칸 이름이다 — 매니페스트 타입의 스키마(`plugin.schema.json`)에서 생성한다. 여기 없는 칸은 파싱에서 거부된다. 칸의 뜻은 `10-manifest.md` · 점검 룰의 칸은 `24-check-plugins.md`.

- 최상위: `allow_removable` · `archive_members` · `collect_extra` · `detect` · `file_names` · `hash_large` · `id` · `kind` · `min_core` · `name` · `network` · `platforms` · `references` · `remediate` · `scan_roots` · `schema_version` · `signed_malware` · `subject_roots` · `subjects` · `submit_hint` · `text_config_dirs` · `verdict` · `version`
- `collect_extra[]`: `content` · `glob` · `max_size` · `path` · `ref` · `subject`
- `detect[]`: `capture` · `exclude` · `from` · `id` · `label` · `score` · `subject` · `where`
- `detect[].exclude[]`: `field` · `op` · `value` · `yara`
- `detect[].where`(안의 `all[]` · `any[]` 도): `all` · `any` · `field` · `op` · `value` · `yara`
- `remediate`: `edit` · `remove` · `restore` · `verify`
- `remediate.edit[]`: `op` · `ref` · `value`
- `remediate.remove[]`: `descendants` · `guard` · `path` · `recursive` · `ref`
- `remediate.restore[]`: `ref` · `to`
- `remediate.verify`: `after_reboot`
- `signed_malware[]`: `subject` · `thumbprint`
- `submit_hint`: `confidentiality_min` · `samples`
- `verdict`: `require` · `unconfirmed`
- `verdict.unconfirmed[]`: `when` · `why`

## 파괴·변경 동작 29종

플러그인이 직접 적지 않는다. 계획기가 도출한다.

| Op | Windows | Linux | 위험 | 되돌릴 수 있는가 | 유발자 |
|---|---|---|---|---|---|
| `file.quarantine_only` | P6 | P12 | low | O | - |
| `shortcut.strip_args` | P7 | P12 | low | O | - |
| `av.restore_exclusions` | P7 | - | low | O | - |
| `hosts.restore_line` | P7 | P12 | low | O | - |
| `proxy.restore` | P7 | - | low | O | - |
| `firewall.restore_rule` | P7 | - | low | O | - |
| `file.delete` | P7 | P12 | medium | O | - |
| `file.delete_on_reboot` | P7 | - | medium | O | - |
| `file.delete_stream` | P7 | - | medium | O | - |
| `registry.delete_value` | P7 | - | medium | O | O |
| `registry.strip_value` | P7 | - | medium | O | O |
| `registry.restore_default` | P7 | - | medium | O | - |
| `persistence.disable` | P7 | P12 | medium | O | - |
| `persistence.delete` | P7 | P12 | medium | O | O |
| `autorun.remove` | P7 | P12 | medium | O | O |
| `text_config.remove_line` | P7 | P12 | medium | O | - |
| `structured_config.remove_key` | P7 | P12 | medium | O | - |
| `structured_config.restore_default` | P7 | P12 | medium | O | - |
| `env.strip_path` | P7 | - | medium | O | O |
| `browser_ext.remove` | P7 | P12 | medium | O | - |
| `process.kill` | P8 | P12 | medium | - | - |
| `service.clear_recovery` | P8 | - | medium | O | - |
| `service.stop` | P8 | P12 | medium | - | - |
| `service.disable` | P8 | P12 | medium | O | - |
| `service.delete` | P8 | P12 | medium | O | O |
| `dir.delete_recursive` | P10 | - | high | O | - |
| `registry.delete_key` | P8 | - | high | O | O |
| `cert_store.remove` | P8 | P12 | high | O | - |
| `boot.restore_default` | P8 | - | high | O | - |

유발자는 **산출물보다 먼저** 실행된다. 재생성을 일으키는 설정을 남긴 채 산출물만 지우면 다음 트리거에서 그대로 돌아온다 (설계-03 §2).

## `restore_default` 가 되돌릴 수 있는 대상

여기 없는 대상을 `to: default` 로 지정하면 `plugin lint` 가 거절한다.

| 대상 | 기본값 |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` | `explorer.exe` |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` | `C:\Windows\system32\userinit.exe,` |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman` | (빈 값) |
| `HKLM\SOFTWARE\Classes\exefile\shell\open\command\` | `"%1" %*` |
| `HKLM\SOFTWARE\Classes\batfile\shell\open\command\` | `"%1" %*` |
| `HKLM\SOFTWARE\Classes\cmdfile\shell\open\command\` | `"%1" %*` |
| `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell` | `cmd.exe` |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` | (빈 값) |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs` | `0` (REG_DWORD) |

## 연산자 17종

| 연산자 | 구현 Phase | value 필요 |
|---|---|---|
| `equals` | P2 | O |
| `not_equals` | P4 | O |
| `matches` | P2 | O |
| `contains` | P2 | O |
| `starts_with` | P2 | O |
| `ends_with` | P2 | O |
| `in` | P4 | O |
| `glob` | P4 | O |
| `exists` | P4 | - |
| `gt` | P4 | O |
| `lt` | P4 | O |
| `version_lt` | P4 | O |
| `version_gt` | P4 | O |
| `pkg_version_lt` | P4 | O |
| `rpm_version_lt` | P4 | O |
| `apk_version_lt` | P4 | O |
| `yara` | P4 | O |

## capture 함수 9종

- `first_path`
- `last_path`
- `dirname`
- `basename`
- `lower`
- `expand_env`
- `trim_quotes`
- `base64_decode`
- `hex_decode`

`first_path` 는 **첫 공백 토큰**을 뽑는다(따옴표는 벗긴다) — 경로가 아니어도 그것을 낸다. `last_path` 는 **역슬래시가 든 마지막 토큰**(없으면 슬래시가 든 마지막 토큰)을 뽑는다 — `--run` 같은 플래그와 `/min` 같은 스위치는 건너뛰고, 경로가 둘 이상이면 마지막 것이다. 줄 중간의 경로는 둘 다 뽑지 못한다. `key`/`value` 는 `=` 로 쓴 줄에서만 채워진다 — 공백으로 쓰는 설정(`sshd_config` 등)에서는 둘 다 비므로 그 자리는 리터럴로 적는다.

## 지정 확장 토큰

| 토큰 | 확장 대상 | allow_removable 필요 |
|---|---|---|
| `HKU\*` | 모든 사용자 레지스트리 하이브 (프로필 수 상한 적용) | - |
| `%ALLUSERPROFILES%` | 모든 사용자 프로필 디렉터리 | - |
| `%REMOVABLE%` | 연결된 이동식 매체 | O |
| `%FIXED_DISKS%` | 고정 디스크 전부 — Windows 는 고정 드라이브, 리눅스는 로컬 디스크 마운트(가상 · 네트워크 · tmpfs 제외). 다른 마운트로 넘어가지 않고 걷는다 | - |

## 산출 아티팩트

| kind | 단계 |
|---|---|
| `remedy.artifacts` | `collect` |
| `remedy.scan` | `evaluate` |
| `remedy.plan` | `plan` |
| `remedy.result` | `apply` |

## 종료 코드

| 코드 | 의미 |
|---|---|
| 0 | 위협 없음 |
| 1 | 위협 발견 · 치료 완료 |
| 2 | 위협 발견 · 치료 안 함 (드라이런/사용자 거절) |
| 3 | 부분 실패 (일부 Action 실패) |
| 4 | 사용법·입력 오류 |
| 5 | 안전 가드에 의한 중단 (상한 초과·보호 경로·서명 검증 실패) |
| 6 | 관측 불완전 - 다 보지 못해 '위협 없음' 을 말할 수 없습니다 (사유는 '주의' 아래 줄) |
| 7 | 내부 오류 - 도구 자체가 멈췄습니다 (logs/crash-*.txt 를 신고에 붙이십시오) |
