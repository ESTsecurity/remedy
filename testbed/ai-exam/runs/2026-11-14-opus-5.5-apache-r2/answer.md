# 답 — 2026-11-14 · Opus 5.5 · apache-r2

코드 블록 둘(`plugin.yaml` · `rules/apache-http2.yar`)은 이 폴더의 두 파일과 바이트까지 같다 — 옮길 때 보고 틀이
붙인 두 칸 들여쓰기만 걷었다. 아래는 응시자가 코드 블록 뒤에 붙인 설명과 도구 호출 목록 그대로다.

---

**설명**

- **세 갈래.** 판이 취약하고 모듈을 싣는 흔적과 `h2`·`h2c` 를 켠 흔적이 둘 다 있으면 2(취약)입니다. 판만 취약하면 `unconfirmed` 첫 줄로 6이 나갑니다. 고친 판을 정하지 못한 빌드와 다시 시작하지 않은 Apache 도 6입니다. 그 밖은 모두 0입니다.
- **백포트 · 스트림 · 공급사 · epoch.**
  - dpkg 판은 `pkg_version_lt`, rpm 판은 `rpm_version_lt`, apk 판은 `apk_version_lt` 로 견줍니다.
  - Debian 은 판 꼬리(`~deb12u` · `~deb13u` · 꼬리 없음)로 배포판을 가르고, Ubuntu 는 상류 판과 `ubuntu` 로 가릅니다. 그래서 22.04 · 20.04 처럼 상류 판이 2.4.55 아래여도 잡힙니다.
  - RHEL 은 `.el9_8`·`_6`·`_4`·`.el10_2`·`_0` 스트림마다 따로 견주고, 나머지 마이너는 본류의 고친 판과 견줍니다.
  - Rocky 와 Amazon 은 `vendor` 로 가릅니다. Amazon 은 고친 판에 `1:` epoch 를 적었습니다.
  - mod_http2 1.15 계열(RHEL 8 등)은 영향 범위 조건에서 빠집니다.
  - Alpine 은 `alpine-release` 판이 `3.21.0-r0` 아래이면 확인 필요로 돌립니다. 이 규칙은 `apk_vuln` 에 보간으로 묶어 두었습니다. 그래서 Apache 가 없는 Alpine 에서는 평가되지 않고 흔적도 남지 않습니다.
- **Apache 가 없는 기계.**
  - 판 비교는 모두 패키지 이름이 맞는 레코드에서만 돕니다.
  - YARA 는 glob 이 본문을 담는 일곱 경로와 똑같은 경로 꼴에서만 돕니다. 그래서 '재지 못했다' 가 생기지 않습니다.
  - 선언한 루트가 전부 없으면 `kind: check` 라서 0입니다.
- **개인키.**
  - `file` 은 `subject_roots` 로 `mods-enabled` 와 직접 빌드의 `bin` 만 모읍니다. 그래서 `server.key` 같은 이름이 레코드로 들어오지 않습니다.
  - 본문을 담는 것은 직접 빌드의 `httpd` 일곱 경로뿐입니다(glob).
  - `text_config` 는 설정 확장자 파일의 줄만 읽고, 판정은 `.conf` 경로 꼴에서만 합니다.
- **직접 빌드.** 패키지가 깐 파일은 `exclude: package exists` 로 뺍니다. 그 빌드의 설정과 프로세스는 `${src_vuln.prefix}`·`${src_vuln.exe}` 보간으로 묶습니다. 처음에는 `from` 을 생각했지만 쓰지 않았습니다. 접두사 자체가 `scan_roots` 밖이라 그룹이 통째로 제외되기 때문입니다.
- **규격에 없어서 못 하는 것.**
  - `Include` 를 따라가 실효 설정을 계산할 수 없습니다. 그래서 흔적이 모자라면 확인 필요로 냅니다.
  - `mods-enabled` 링크의 내용은 읽지 못하고 링크 이름만 씁니다.
  - `text_config` 를 `.conf` 로만 좁히는 칸이 없습니다. 예를 들어 XAMPP 의 `etc` 에 있는 다른 설정 확장자 파일의 줄도 스냅샷에 들어옵니다.
  - SUSE 의 `sysconfig.d` 는 보고에 나온 자리가 아니라 보지 않습니다. SUSE 는 어차피 확인 필요로 나갑니다.
- **알고 둔 것.** HTTP/2 를 켠 고친 기계에서는 설정과 프로세스 규칙이 흔적으로 보일 수 있습니다. 종료 코드는 0 그대로입니다. 판정 순서를 바꾸지 않으려고 그대로 두었습니다.
- **검증.** 린트와 스냅샷 평가는 돌리지 않았습니다. 규칙상 이 회차에서 쓸 수 있는 도구가 없었습니다.

**이 회차의 도구 호출(전부 Read, 같은 파일 하나)**

1. Read 꾸러미 파일 offset 1 · limit 700
2. Read 같은 파일 offset 701 · limit 700
3. Read 같은 파일 offset 1401 · limit 700
4. Read 같은 파일 offset 2101 · limit 700
5. Read 같은 파일 offset 2801 · limit 700
6. Read 같은 파일 offset 3501 · limit 700
7. Read 같은 파일 offset 4201 · limit 700
8. Read 같은 파일 offset 4901 · limit 700
9. Read 같은 파일 offset 5207 · limit 100 (파일 끝 확인)

그 밖의 도구(Glob · Grep · Bash · 다른 경로 Read · 인터넷)는 쓰지 않았습니다.
