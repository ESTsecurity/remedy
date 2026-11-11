<!-- schema_version: 1 | min_core: 1.0.0 | generated: true -->

# 린트 진단 (생성물 — 직접 고치지 말 것)

아래 메시지는 **실제로 `plugin lint` 를 돌려 받은 것**이다. `crates/remedy-sdk/src/generate.rs` 의 사례를 고치면 이 문서가 바뀐다.

**오류는 로드를 막고, 경고는 막지 않는다.** 경고가 남은 채로 서명하려면 각각의 이유를 설명해야 한다 (설계-06 §8).

## 패키지가 깐 파일인지 본다

**무엇이 잘못됐나.** `file.package` · `file.package_match` 를 `package` subject 없이, 또는 Windows 도 대상인 룰에서 썼다 — 그 칸은 `package` subject 를 함께 선언한 리눅스 룰에서만 채워져 이 술어는 늘 거짓이다

```
경고 detect[1].where[0].field: 'package_match' 는 `package` subject 를 함께 선언한 리눅스 룰에서만 채운다 — 이 룰은 `package` subject 를 선언하지 않았다 — 패키지 DB 는 그 subject 의 고정 자리라 읽지 않는다. 이 술어는 언제나 거짓이다
      근거: 설계-02 §3
```

**고치는 법.** 리눅스 룰이면 `subjects` 에 `package` 를 더한다. Windows 에는 패키지 DB 가 없으니 그 룰에서는 쓰지 않는다

## 표시명에 두 언어를 다 적는다

**무엇이 잘못됐나.** `name` 에 한 언어만 있다. 고객 화면의 첫 줄이 다른 언어에서 비거나 엉뚱한 언어로 나온다

```
오류 name.en: 'en' 표시명이 없다. name 은 고객 화면의 첫 줄이라 두 언어가 다 있어야 한다
      쓸 수 있는 것: name: { ko: "<위협> 제거", en: "<Threat> removal" }
      근거: 10-manifest.md
```

**고치는 법.** `name: { ko: …, en: … }` 둘 다 채운다. 룰만 고쳤어도 `version` 을 올린다

## 드롭인 디렉터리를 확장자 없이 읽는다

**무엇이 잘못됐나.** `text_config_dirs` 가 `scan_roots` 밖이다

```
오류 text_config_dirs[0]: '%ProgramData%\Acme\conf.d' 가 `scan_roots` 밖이다. 이 선언은 **같은 상한 안에서** 확장자 밖의 파일까지 읽는 것이고, 상한을 넓히는 길이 아니다 — 넓힐 수 있으면 읽기 권한의 상한이 두 곳이 된다
      쓸 수 있는 것: `scan_roots` 안의 경로로 적을 것 — 지금 상한: %LOCALAPPDATA%\Programs
      근거: 설계-02 §2
```

**고치는 법.** 상한 안의 디렉터리로 적는다. 넓혀야 하면 `scan_roots` 를 고친다

## 다른 규칙의 capture 를 가리킨다

**무엇이 잘못됐나.** 없는 규칙 이름을 썼다

```
오류 detect[1].from: '${없는룰.payload_dir}' 가 없는 규칙 '없는룰' 를 가리킨다
      쓸 수 있는 것: payload · task
      근거: 설계-02 §4
```

**고치는 법.** 규칙 id 를 확인한다. 진단이 쓸 수 있는 이름을 전수로 알려 준다

## capture 이름을 가리킨다

**무엇이 잘못됐나.** 그 규칙에 없는 capture 를 썼다

```
오류 detect[1].from: 규칙 'task' 에 capture '없는캡처' 가 없다
      쓸 수 있는 것: payload_dir
      근거: 설계-02 §4
```

**고치는 법.** 부모 규칙의 `capture:` 아래 이름과 맞춘다

## 판정식을 쓴다

**무엇이 잘못됐나.** `verdict.require` 가 없는 규칙을 가리킨다

```
오류 verdict.require: 없는 규칙 '없는룰' 를 참조한다
      쓸 수 있는 것: payload · task
      근거: 설계-02 §5
```

**고치는 법.** 규칙 id 를 확인한다. 오타 하나로 판정이 영영 서지 않는다

## 규칙을 하나 더 둔다

**무엇이 잘못됐나.** id 가 겹쳤다

```
오류 detect[1].id: 규칙 id 'task' 가 중복이다. 참조가 어느 것을 가리키는지 알 수 없다
      근거: 설계-02 §4
오류 verdict.require: 없는 규칙 'payload' 를 참조한다
      쓸 수 있는 것: task
      근거: 설계-02 §5
```

**고치는 법.** id 를 유일하게 짓는다. 겹치면 `${task.x}` 가 어느 것을 가리키는지 알 수 없다

## 정규식으로 매치한다

**무엇이 잘못됐나.** 컴파일되지 않는 정규식이다

```
오류 detect[0].where.all[0].value: 정규식을 컴파일할 수 없다: regex parse error:
    (unclosed
    ^
error: unclosed group
      쓸 수 있는 것: RE2 계열이다 — 역참조(\1)와 전방탐색((?=...))은 쓸 수 없다
      근거: 설계-02 §4
```

**고치는 법.** RE2 문법이다. 역참조·전방탐색이 없다

## 지문으로 잡는다

**무엇이 잘못됐나.** `sha256` 의 값이 소문자 16진 64자가 아니다 — 값을 몰라 자리 표시를 두었다

```
오류 detect[1].where[0].value: 'sha256' 의 값 'FILL_IN_sha256_of_the_sample' 는 소문자 16진 64자가 아니다. 수집은 지문을 그 모양으로 적으므로 이 항목은 어느 기계에서도 아무것도 맞히지 않는다 — 자리 표시를 두어도 문법은 통과한다
      쓸 수 있는 것: 0-9 · a-f 로만 64자. 값을 모르면 적지 말고, 아는 자리(정기 작업이 부르는 파일)에서 sha256 을 capture 해 `${규칙.capture}` 로 모을 것
      근거: 설계-02 §3
```

**고치는 법.** 값을 모르면 적지 않는다. 아는 자리(정기 작업이 부르는 파일)에서 `sha256` 을 capture 해 `${…}` 로 모은다 — `20-detect` §값을 모르는 지문. 위협 정보가 값을 줬다면 그대로 붙인다(소문자 64자)

## 지문 자리를 비워 둔다

**무엇이 잘못됐나.** `sha256` 의 값이 한 글자의 반복이다(0 을 64개) — 모양은 맞지만 실제 지문일 수 없다

```
경고 detect[1].where[0].value: 'sha256' 의 값 '0000000000000000000000000000000000000000000000000000000000000000' 는 한 글자의 반복이다 — 실제 지문일 수 없고 자리 표시로 보인다. 이 항목은 아무것도 맞히지 않는다
      쓸 수 있는 것: 위협 정보가 준 지문을 그대로 붙이거나, 값을 모르면 아는 자리에서 sha256 을 capture 해 `${규칙.capture}` 로 모을 것
      근거: 설계-02 §3
```

**고치는 법.** **경고다.** 자리 표시로 보여 알리는 것이지 막지 않는다. 고치는 법은 위와 같다

## 버전을 견준다

**무엇이 잘못됐나.** `version_lt` · `version_gt` 의 값이 버전이 아니다 — 꼬리가 붙었거나 `x` 를 적었다

```
오류 detect[1].where[0].value: 'path' 에 걸린 version_lt 의 값 '8.2.29-1ubuntu1' 을 버전으로 읽지 못했다. 이 항목은 어느 기계에서도 판정을 세우지 못하고 진단만 남긴다
      쓸 수 있는 것: 점으로 나눈 숫자만 — 예: 8.2.29. 사전 배포 꼬리(RC1 · -dev)와 패키지 개정(-1ubuntu1)은 순서가 서로 반대여서 받지 않는다. 계열을 좁히려면 `version` 에 `starts_with "8.2."` 를 함께 걸 것
      근거: 24-check-plugins.md
```

**고치는 법.** 점으로 나눈 숫자만 적는다(예: 8.2.29). 계열을 좁히려면 `starts_with "8.2."` 를 함께 건다. 꼬리(`RC1` · `-dev` · `-1ubuntu1`)는 순서가 서로 반대여서 받지 않는다

## 버전을 따옴표로 감싼다

**무엇이 잘못됐나.** 버전을 따옴표 없이 적었다 — YAML 이 실수로 읽어 뒤의 0 이 사라진다

```
오류 detect[1].where[0].value: 'path' 에 걸린 version_lt 의 값을 YAML 이 **실수로** 읽었다 — 따옴표가 없다. 엔진에 도착한 값은 '8.1' 이고 **뒤의 0 은 돌아오지 않는다**: `8.10` 을 적으면 `8.1` 과 견주게 되어 `8.9` 를 양호로 본다
      쓸 수 있는 것: 따옴표로 감싼다 — `value: "8.10"`. 정수(`value: 8`)는 왕복하므로 그대로 둬도 된다
      근거: 24-check-plugins.md
```

**고치는 법.** 따옴표로 감싼다(`value: "8.10"`). 없으면 엔진에 `8.1` 로 도착해 `8.9` 를 양호로 보고, 원문은 복원할 길이 없다. 정수(`value: 8`)는 왕복하므로 그대로 둬도 된다

## 버전에 맞는 연산자를 고른다

**무엇이 잘못됐나.** `gt` · `lt` 에 버전을 적었다 — 그쪽은 수와 RFC3339 시각만 견준다

```
경고 detect[1].where[0].value: 'path' 에 걸린 lt 의 값 '8.2.29' 는 버전처럼 보인다. lt 는 수와 RFC3339 시각만 견주므로 이 항목은 **판정을 세우지 못하고** 진단만 남긴다
      쓸 수 있는 것: 버전을 견주려면 version_lt 를 쓸 것
      근거: 24-check-plugins.md
```

**고치는 법.** **경고다.** 막지 않지만 그 항목은 조용히 거짓이 된다. `version_lt` · `version_gt` 를 쓴다

## 필드를 고른다

**무엇이 잘못됐나.** 그 subject 에 없는 필드다

```
오류 detect[0].where.all[0].field: 'cmdline_of_task' 는 subject 'persistence' 에 없는 필드다
      쓸 수 있는 것: id · name · enabled · trigger · command · args · principal · source · win.task.register_path · win.task.actions · win.task.run_level · win.task.working_directory · win.task.command_expanded · win.task.args_expanded · linux.cron.line_no · linux.cron.line
      근거: 설계-02 §3
```

**고치는 법.** `machine/subjects.json` 을 본다. 진단이 쓸 수 있는 필드를 전수로 준다

## 다른 subject 의 파일을 좁힌다

**무엇이 잘못됐나.** `from` 을 `path` 필드가 없는 subject 에 걸었다

```
오류 detect[1].subject: 'autorun' 를 쓰려면 최상위 subjects 에 선언해야 한다
      쓸 수 있는 것: persistence · file
      근거: 설계-02 §4
오류 detect[1].where[0].field: 'path' 는 subject 'autorun' 에 없는 필드다
      쓸 수 있는 것: id · scope · name · command · source
      근거: 설계-02 §3
오류 detect[payload].from: subject 'autorun' 에는 path 필드가 없어 from 이 통하지 않는다 — 이 규칙은 아무 레코드도 매치하지 못한다
      쓸 수 있는 것: from 을 쓸 수 있는 subject: file · text_config · structured_config · shortcut · browser_extension · 그 밖에는 where 값에 ${다른규칙.capture} 를 넣어 묶는다
      근거: 설계-02 §4
```

**고치는 법.** `where` 값에 `${다른규칙.capture}` 를 넣어 묶는다

## 제거 대상을 선언한다

**무엇이 잘못됐나.** 없는 규칙을 가리켰다

```
오류 remediate.remove[0].ref: 없는 규칙 '없는룰' 를 가리킨다
      쓸 수 있는 것: payload · task
      근거: 설계-02 §6
```

**고치는 법.** `ref` 는 규칙 id 다. 증거 id(`payload#0`)가 아니다

## 조회 결과로 제거를 늘린다

**무엇이 잘못됐나.** `reputation` 을 제거 근거로 삼았다

```
오류 remediate.remove[0].ref: remediate 에서 reputation 을 참조할 수 없다. 조회 결과는 파괴 대상을 만들 수 없다 — 감염 호스트의 네트워크가 조작되면 정상 파일이 지워진다. 화이트리스트 태그로 **제외**하는 방향만 허용된다
      근거: 설계-03 §3 5층
오류 remediate.remove[0].ref: 없는 규칙 'reputation.malicious' 를 가리킨다
      쓸 수 있는 것: payload · task
      근거: 설계-02 §6
```

**고치는 법.** **방향 제약이다.** 조회는 삭제를 늘릴 수 없다 — 감염 호스트의 응답은 신뢰할 수 없다

## 폴더를 통째로 지운다

**무엇이 잘못됐나.** `guard` 없이 `recursive: true` 를 썼다

```
오류 remediate.remove[0]: recursive: true 는 guard 를 요구한다. guard 는 그 디렉터리 안에서 악성으로 판정된 파일 증거를 가리켜야 한다
      쓸 수 있는 것: task · payload
      근거: 설계-03 §4
```

**고치는 법.** 그 폴더 안에서 악성 판정된 규칙을 `guard` 로 지목한다

## 본문을 담는다

**무엇이 잘못됐나.** `collect_extra` 가 없는 규칙을 가리켰다

```
오류 collect_extra[0].ref: 없는 규칙 '없는룰' 를 가리킨다
      쓸 수 있는 것: payload · task
      근거: 설계-02 §6-1
```

**고치는 법.** 규칙 id 를 확인한다. 없으면 그 선언은 영영 해소되지 않는다

## 이름이 감염마다 다른 파일의 본문을 담는다

**무엇이 잘못됐나.** `glob` 의 폴더를 `scan_roots` 밖에 적었다

```
오류 collect_extra[0].glob: 'C:\Windows\System32' 가 `scan_roots` 밖이다. 글롭은 주 수집이 걸은 레코드에서 고르므로 그 폴더에는 고를 것이 없고, 결과는 조용한 0건이다
      쓸 수 있는 것: `scan_roots` 안의 폴더로 적을 것 — 지금 상한: %LOCALAPPDATA%\Programs
      근거: 설계-02 §2
```

**고치는 법.** `scan_roots` 안의 폴더로 적는다. 글롭은 주 수집이 걸은 `file` 레코드에서 고르므로 밖의 폴더는 **조용한 0건**이다. 와일드카드는 마지막 성분에만 둔다

## YARA 로 본문을 판정한다

**무엇이 잘못됐나.** 본문을 담는 `collect_extra` 가 하나도 없다

```
오류 detect[payload].where[0]: YARA 를 쓰는데 collect_extra 가 본문을 담지 않는다 — 실기기에서 이 규칙은 미평가가 되고 판정이 서지 않는다
      쓸 수 있는 것: collect_extra 에 `{ ref: <경로로 매치되는 규칙>, content: true }` 를 둔다
      근거: 설계-06 §6
```

**고치는 법.** `{ ref: <경로로 매치되는 규칙>, content: true }` 를 둔다. YARA 규칙 자신을 가리키면 순환이다

## 지우면 시스템이 깨지는 값을 되돌린다

**무엇이 잘못됐나.** `to: default` 를 `remove` 절에 넣었다

```
remediate.remove: data did not match any variant of untagged enum RemoveTarget at line 25 column 5
```

**이것은 린트가 아니라 파싱 단계에서 걸린다.** 알 수 없는 키는 무시가 아니라 거부다.

**고치는 법.** **`restore` 절이다.** `remove` 는 `{ ref: … }` 와 `{ path: … }` 만 받는다

## subject 하나만 더 좁힌다

**무엇이 잘못됐나.** `subject_roots` 에 `scan_roots` 밖의 경로를 적었다

```
오류 subject_roots.file[0]: 'C:\Windows\System32' 가 `scan_roots` 밖이다. `subject_roots` 는 **좁히기만** 한다 — 넓힐 수 있으면 읽기 권한의 상한이 두 곳이 되고, 서명 검토자가 한 곳만 읽으면 실제로 무엇을 읽는지 모른다
      쓸 수 있는 것: `scan_roots` 안의 경로로 적을 것 — 지금 상한: %LOCALAPPDATA%\Programs
      근거: 설계-02 §2
```

**고치는 법.** **좁히기만 한다.** `scan_roots` 안의 경로로 적을 것 — 넓힐 수 있으면 읽기 권한의 상한이 두 곳이 되고, 서명 검토자가 한 곳만 읽으면 실제로 무엇을 읽는지 모른다

## 선언하지 않은 subject 를 좁힌다

**무엇이 잘못됐나.** `subjects` 에 없는 이름을 `subject_roots` 에 적었다

```
오류 subject_roots.text_config: 'text_config' 가 `subjects` 에 없다. 선언하지 않은 subject 를 좁히는 것은 아무 효과가 없고, 작성자는 좁혔다고 믿는다
      쓸 수 있는 것: `subjects` 에 'text_config' 를 넣거나 이 줄을 지울 것
      근거: 설계-02 §2
```

**고치는 법.** `subjects` 에 넣거나 이 줄을 지운다. 선언하지 않은 subject 를 좁히는 것은 아무 효과가 없고, 그래서 **작성자만 좁혔다고 믿는다**

## 코어 판을 잘못 적는다

**무엇이 잘못됐나.** `min_core` 가 버전으로 읽히지 않는다

```
오류 min_core: 'P10' 을 버전으로 읽지 못했다
      쓸 수 있는 것: `주.부.수` 세 자리 수 — 예: 1.0.0
      근거: 설계-02 §10
```

**고치는 법.** semver 로 적는다. **Phase 이름이 아니다** — `P10` 같은 것은 개발 순서이지 배포 판이 아니고, 이 문서에 있는 Op 은 전부 `1.0.0` 에 있다

## Linux 에서도 돌게 하려고 플랫폼을 늘린다

**무엇이 잘못됐나.** 그 subject 를 이 코어가 Linux 에서 수집하지 않는다

```
경고 subjects.firewall_rule: Linux 에 개념은 있으나 이 코어의 'firewall_rule' 수집기가 Windows 전용이다. Windows 에서는 동작하지만 **Linux 에서는 0건**이 된다
      쓸 수 있는 것: Linux 에서 수집되는 subject: persistence · autorun · service · process · file · indicator · text_config · structured_config · shortcut · hosts_entry · browser_extension · cert_store · package · unix_socket
      근거: 설계-09 P12
```

**고치는 법.** `machine/subjects.json` 의 `linux_from` 을 본다. **비어 있으면 그 플랫폼에서 언제나 0건**이다 — Linux 전용이면 오류, 겸용이면 경고다

## 부분 편집을 Linux 에서도 쓴다

**무엇이 잘못됐나.** `edit` 가 세우는 부분 편집 Op 이 Linux 에 없다

```
경고 remediate.edit[0]: 부분 편집 Op(registry.strip_value · env.strip_path)이 Linux 에 없다. Windows 에서는 동작하지만 **Linux 에서는 보류**된다
      근거: 설계-09 P12
```

**고치는 법.** `machine/ops.json` 의 `linux_from` 을 본다. `registry.strip_value` · `env.strip_path` 가 비어 있으면 **그 edit 는 Linux 에서 늘 보류**된다 — Linux 전용이면 오류, 겸용이면 경고다

## 바로가기 인자를 edit 로 뗀다

**무엇이 잘못됐나.** `edit` 가 레지스트리 값이 아닌 것을 가리킨다

```
오류 remediate.edit[0].ref: 'lnk' 는 subject 'shortcut' 인데 edit 는 레지스트리 값만 고친다. 바로가기 인자는 `remove` 로 뗀다 — 계획기가 `shortcut.strip_args` 를 고른다
      쓸 수 있는 것: subject: registry_value · autorun
      근거: 설계-02 §6
```

**고치는 법.** 바로가기 인자 · 설정 항목은 `remove` 가 subject 에 맞는 Op 으로 뗀다

## 레지스트리를 보는 subject 를 선언한다

**무엇이 잘못됐나.** `scan_roots` 에 레지스트리 루트가 없다

```
오류 subjects.registry_value: 이 subject 는 레지스트리 루트가 `scan_roots` 에 하나라도 있어야 모인다 — 지금 `scan_roots` 에는 경로뿐이다. 그대로 두면 **언제나 0건**이고, 그 위에서 도는 룰은 아무것도 맞히지 못한 채 초록이 된다
      쓸 수 있는 것: `HKLM\SOFTWARE\...` 같은 레지스트리 루트를 `scan_roots` 에 하나 이상
      근거: 설계-02 §3
```

**고치는 법.** `HKLM\…` 형태의 루트를 하나 이상 적는다. 없으면 **`registry_value` 는 언제나 0건**이고, 그 위에서 도는 룰은 아무것도 맞히지 못한 채 초록이 된다

## 파일의 대체 스트림을 본다

**무엇이 잘못됐나.** 정의는 됐는데 이 코어가 아직 채우지 않는 필드다

```
경고 detect[1].where[0].field: 'streams' 는 이 코어가 아직 채우지 않는 필드다 — 이 술어는 언제나 거짓이라 규칙이 매치되지 않는다. 대체 데이터 스트림 열거에는 `FindFirstStreamW` 가 필요하고 그것은 unsafe 다 — 이 저장소는 크레이트 전부에 `forbid(unsafe_code)` 를 건다. 이름을 아는 스트림만 훑는 방식은 임의 이름을 쓰는 악성 스트림을 체계적으로 놓치므로 열거의 대체재가 되지 못한다
      근거: 설계-02 §3
경고 detect[1].where: 조건이 'streams exists' 하나뿐이다. 증거 그룹이 폭증해 계획 단계 상한(50)에 걸릴 수 있다
      근거: 설계-03 §4
```

**고치는 법.** `machine/subjects.json` 이 그 사유를 적는다. **없는 필드가 아니라 언제나 비어 있는 필드**이므로 문법은 통과하고 룰만 조용히 0건이 된다

## 부분 문자열 하나로 가른다

**무엇이 잘못됐나.** 조건이 넓은 비교(`contains`·`exists`) 하나뿐이고 값이 3바이트 이하다 — 그 규칙은 사실상 필터가 없다

```
경고 detect[0].where: 조건이 'command contains' 하나뿐이다. 증거 그룹이 폭증해 계획 단계 상한(50)에 걸릴 수 있다
      근거: 설계-03 §4
```

**고치는 법.** 대상을 특정하는 조건을 하나 더 두어 `all` 로 묶거나, 값을 그 대상만 가리키는 길이로 늘린다. 부모 규칙이면 맞은 레코드마다 증거 그룹이 하나씩 생기고, 50개를 넘으면 계획 단계의 상한에 걸린다 — 무인 실행은 치료 전에 멈추고, 대화형은 계획 전문을 보여 주고 승인을 받는다. **같은 뜻을 다른 연산자로 돌려 적어 경고만 끄지 않는다** — 경고는 사라져도 폭은 그대로다

## 사용자 홈 아래를 재귀로 지운다

**무엇이 잘못됐나.** 파생 경로가 홈 직하가 될 수 있는 상한에서 재귀 삭제를 건다

```
경고 remediate.remove[0].path: 재귀 삭제 대상 '${task.payload_dir}' 이 사용자 홈 직하에 놓일 수 있다 — scan_roots 의 %USERPROFILE% 아래에는 Documents·Desktop·Downloads 가 있다. 파생 경로가 그중 하나가 되면 사용자 자료를 통째로 지운다
      근거: docs/plugin-guide/30-antipatterns.md#재귀-삭제
```

**고치는 법.** 상한을 홈보다 깊게 내린다. `%USERPROFILE%` 이하가 상한이면 파생 경로가 `Documents`·`Desktop` 이 될 수 있고, 그러면 **사용자 자료를 통째로 지운다**

## 지속성 값을 OS 기본값으로 되돌린다

**무엇이 잘못됐나.** 그 레지스트리 값이 기본값 카탈로그에 없다

```
오류 remediate.restore[0]: 'HKLM\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\Updater' 은 OS 기본값 카탈로그에 없다. 값 하나로 복원이 완결되는 대상만 담는다 — 구조 전체가 필요한 것은 탐지·보고만 하고 OS 복구 도구로 넘긴다
      쓸 수 있는 것: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell · HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit · HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman · HKLM\SOFTWARE\Classes\exefile\shell\open\command\ · HKLM\SOFTWARE\Classes\batfile\shell\open\command\ · HKLM\SOFTWARE\Classes\cmdfile\shell\open\command\ · HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell · HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs · HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs
      근거: 설계-03 §2
```

**고치는 법.** **값 하나로 복원이 완결되는 대상만** 담긴다. 카탈로그에 없으면 되돌릴 값을 코어가 모르므로, 되돌리기가 아니라 제거로 다뤄야 한다

## 보안 제품 예외를 되돌린다

**무엇이 잘못됐나.** `av_exclusion` 을 탐지하는 규칙이 없다

```
오류 remediate.restore[0]: 'av_exclusions' 은 av_exclusion 증거를 되돌리는데 그 subject 를 탐지하는 규칙이 없다 — 되돌릴 것이 잡히지 않아 Action 이 만들어지지 않는다
      쓸 수 있는 것: subject: av_exclusion 규칙을 하나 두고 우리 경로를 짚는다
      근거: 설계-03 §2
```

**고치는 법.** 그 subject 규칙을 두고 우리 경로를 짚는다. 없으면 되돌릴 증거가 안 잡힌다

## 값이 닫힌 필드에 다른 낱말을 쓴다

**무엇이 잘못됐나.** 필드 이름은 맞는데 이 코어가 그 자리에 적지 않는 값을 썼다

```
오류 detect[2].where[0].value: 'state' 의 값 'running' — 이 필드에 그 값은 어느 기계에서도 나오지 않는다. 술어가 언제나 거짓이라 규칙이 조용히 0건을 보고한다. **실행 여부는 어느 쪽에도 없다.** Windows 수집기는 레지스트리를, Linux 수집기는 유닛 파일을 읽는다 — 둘 다 살아 있는 서비스 관리자에게 묻지 않는다. 없는 것을 '정지' 로 적으면 돌고 있는 악성 서비스가 멈춘 것으로 보고되므로 양쪽 다 `unknown` 만 적는다. `running`·`stopped` 로 비교하는 술어는 어느 기계에서도 참이 되지 않는다
      쓸 수 있는 것: 'unknown' 뿐이다
      근거: 설계-02 §3
```

**고치는 법.** `machine/subjects.json` 의 `enumerated` 를 본다. **값이 닫힌 필드는 거기에 전수가 있다.** 이름이 맞아 문법도 통과하던 자리라, 없으면 규칙이 조용히 0건을 맞히고 그것에 기댄 판정이 서지 않는다

## 넓게 훑는다

**무엇이 잘못됐나.** `scan_roots` 가 사실상 전체를 가리킨다

```
경고 scan_roots[0]: 'C:\Users' 은 사실상 전체를 훑는다(깊이 2). scan_roots 는 성능이 아니라 **읽기 권한 상한**이므로 좁을수록 좋다
      근거: 설계-02 §2
```

**고치는 법.** **경고다.** 넓은 범위가 실제로 필요하면 그 이유를 서명 단계에서 설명한다

