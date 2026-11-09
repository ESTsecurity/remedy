<!-- schema_version: 1 | min_core: 1.0.0 | generated: true -->

# remedy 플러그인 — 압축 문맥 (생성물)

스키마 1 · 구현 Phase P12. 이 파일 하나로 룰을 쓸 수 있게 만든 것이다. 판단이 필요한 자리(레시피·안티패턴·리뷰)는 `docs/plugin-guide/` 의 번호 붙은 문서를 본다.

## 절대 규칙

- `subject` · 필드 · 연산자 · `Op` 는 **닫힌 집합**이다. 여기 없는 이름을 쓰면 거부된다.
- 플러그인은 `Op` 을 직접 고르지 않는다. **무엇을 없앨지만 선언**하고 순서·Op 은 코어가 정한다.
- 제거 대상은 **증거에서 파생된 것**이어야 한다. 리터럴 절대 경로는 거부된다.
- `scan_roots` 는 성능이 아니라 **읽기 권한 상한**이다.
- 판정은 `verdict.require` 의 불 대수식이 정한다. **점수 임계값 문법은 없다.**
- 점검(`kind: check`)은 모르는 것을 `verdict.unconfirmed`(`when` · `why` ko·en · 코어 1.3.0)로 *확인 필요*(6) 라고 말한다 — 모르는데 판정을 세우지 않으면 0 이 나간다.

## 최소 매니페스트

```yaml
schema_version: 1
id: example-threat
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name: { ko: "예제 위협 제거", en: "Example threat removal" }
scan_roots: ["%LOCALAPPDATA%\\Programs"]   # persistence 는 이 상한과 무관하다
subjects: [persistence, file]
detect:
  - id: task                      # 부모 — 증거 그룹 하나가 생긴다
    subject: persistence
    where:
      all:
        - { field: command, op: matches, value: '(?i)\\node\.exe$' }
        - { field: args,    op: matches, value: '(?i)\.js("|\s|$)' }
    capture:
      dir: "args | first_path | dirname"   # 파이프는 몇 단이든 이어 붙일 수 있다
  - id: payload                   # 자식 — 부모가 가리킨 폴더 안만
    subject: file
    from: "${task.dir}"
    where:
      - { field: path, op: ends_with, value: ".js" }
verdict:
  require: "task and payload"     # 독립적인 두 근거
remediate:
  remove:
    - { ref: task }
    - { ref: payload }
```

## subject 와 필드 (닫힌 집합)

- `persistence`: id name enabled trigger command args principal source win.task.register_path win.task.actions win.task.run_level win.task.working_directory win.task.command_expanded win.task.args_expanded linux.cron.line_no linux.cron.line
- `autorun`: id scope name command source
- `service`: id name state start_type image_path
- `process`: pid ppid image_path cmdline cmdline_decoded args user start_time modules
- `file`: path size mtime ctime sha256 streams content_ref version signature.trusted signature.subject signature.thumbprint zone.zone_id zone.referrer_url zone.host_url
- `indicator`: kind value source_ref
- `registry_value`: hive key name type data
- `registry_key`: hive key subkeys values
- `text_config`: path line_no line section key value
- `structured_config`: path format key_path value
- `shortcut`: path target args working_dir icon
- `boot_config`: entry recoveryenabled safeboot_available
- `hosts_entry`: ip hostnames line_no source line
- `browser_extension`: browser profile ext_id name version path
- `av_exclusion`: kind value source
- `cert_store`: store subject issuer thumbprint not_after linux.path
- `proxy_config`: scope server pac_url bypass
- `firewall_rule`: id name direction action enabled protocol local_port remote_port remote_address application service profile source
- `package`: name version upstream_version revision arch source manager vendor
- `unix_socket`: name inode listening kind

**`from` 은 `path` 필드가 있는 subject 에만 통한다** — file text_config structured_config shortcut browser_extension. 그 밖에는 `where` 값에 `${다른규칙.capture}` 를 넣어 부모에 묶는다.

## Op 29종 (계획기가 고른다)

file.quarantine_only · shortcut.strip_args · av.restore_exclusions · hosts.restore_line · proxy.restore · firewall.restore_rule · file.delete · file.delete_on_reboot · file.delete_stream · registry.delete_value · registry.strip_value · registry.restore_default · persistence.disable · persistence.delete · autorun.remove · text_config.remove_line · structured_config.remove_key · structured_config.restore_default · env.strip_path · browser_ext.remove · process.kill · service.clear_recovery · service.stop · service.disable · service.delete · dir.delete_recursive · registry.delete_key · cert_store.remove · boot.restore_default

**유발자는 산출물보다 먼저 실행된다** — registry.delete_value · registry.strip_value · persistence.delete · autorun.remove · env.strip_path · service.delete · registry.delete_key.

## 연산자

equals · not_equals · matches · contains · starts_with · ends_with · in · glob · exists · gt · lt · version_lt · version_gt · pkg_version_lt · rpm_version_lt · yara

정규식은 **RE2** 다. 역참조·전방탐색이 없다.

## capture 함수

first_path · last_path · dirname · basename · lower · expand_env · trim_quotes · base64_decode · hex_decode

`first_path` 는 **첫 공백 토큰**을 뽑는다(따옴표는 벗긴다) — 경로가 아니어도 그것을 낸다. `last_path` 는 **역슬래시가 든 마지막 토큰**(없으면 슬래시가 든 마지막 토큰)을 뽑는다 — `--run` 같은 플래그와 `/min` 같은 스위치는 건너뛰고, 경로가 둘 이상이면 마지막 것이다. 줄 중간의 경로는 둘 다 뽑지 못한다. `key`/`value` 는 `=` 로 쓴 줄에서만 채워진다 — 공백으로 쓰는 설정(`sshd_config` 등)에서는 둘 다 비므로 그 자리는 리터럴로 적는다.

## 지정 확장 토큰

`%ALLUSERPROFILES%`(사용자 수만큼) · `HKU\*`(하이브 수만큼) · `%REMOVABLE%`(매체 수만큼 · `allow_removable: true` 필요). **하나가 여럿이 된다** — 쓰지 않으면 다중 사용자 기계에서 현재 사용자만 치료된다.

## 없는 것 (지어내지 말 것)

- 임의 명령 실행 Op (`exec` · `run_command` · `powershell`)
- 파일 **쓰기·수정** Op. 파괴와 원복만 있다
- 네트워크 요청. 조회는 `enrich` 단계이고 룰이 호출하지 않는다
- 스크립트 런타임
- 백업을 끄는 옵션 · 삭제 상한이나 보호 경로를 조정하는 키
- `verdict` 의 점수 임계값 문법

## 자주 걸리는 것

- YARA 를 쓰면 `collect_extra` 로 **본문을 담아야** 한다. 안 담으면 *"재지 못했다"* 가 되고 판정이 서지 않는다. 가리킬 규칙은 **경로로 매치되는** 것이어야 한다(YARA 규칙 자신을 가리키면 순환).
- `restore: [av_exclusions]` 는 `av_exclusion` **증거**를 되돌린다. 그 subject 탐지 규칙이 없으면 Action 이 만들어지지 않는다.
- `recursive: true` 는 `guard` 를 문법 수준에서 요구한다.
- **`to: default` 는 `restore` 절이다** — `remove` 에 넣으면 린트가 아니라 파싱에서 멈춘다. 지우면 시스템이 깨지는 값(로그온 셸 등)을 되돌리는 자리이고, 대상은 코어 카탈로그에 있는 것만이다.
- `platforms` 와 `win.*`/`linux.*` 필드가 어긋나면 거부된다.

## 더 볼 곳

`00-invariants.md`(절대 규칙) · `10-manifest.md`(키·`scan_roots`) · `20-detect-recipes.md`(탐지·YARA) · `22-remediate-recipes.md`(제거) · `23-collect-and-submit.md`(본문·제출) · `24-check-plugins.md`(점검 전용) · `30-antipatterns.md`(거부되는 형태) · `31-nonexistent.md`(없는 기능) · `32-lint-errors.md`(진단) · `40-review-checklist.md`(서명 전) · `examples/`(CI 에서 도는 실물 — 제거까지 둘 · 탐지만 하나 · 점검 하나)
