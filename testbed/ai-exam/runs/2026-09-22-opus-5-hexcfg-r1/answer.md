# 답안 — nodewatch 에이전트 플러그인 로더 제거

## `plugin.yaml`

```yaml
# nodewatch 에이전트에 심어진 플러그인 로더 제거
#
# 관측 요약
#   - 설정(JSON) 항목 하나가 플러그인의 전체 경로를 16진으로 감춰 두었다.
#   - 목록(conf) 줄 하나가 그 파일을 **이름만으로** 부른다. 표기는 소문자다.
#   - 플러그인 폴더에 그 파일이 실재한다.
#   - 설정 파일 둘 · 벤더 항목 셋 · 벤더 줄 둘 · 벤더 플러그인 둘은 이 제품의 것이다.

schema_version: 1
id: nodewatch-hex-relay-loader
version: 1.0.0
min_core: "1.0.0"
platforms: [linux]
name:
  ko: "nodewatch 플러그인 로더 제거"
  en: "nodewatch plugin loader removal"

# 권한 상한. 여기 밖은 읽을 수도 지울 수도 없다.
# 페이로드 경로는 설정 값에서 파생된다 — 공격자가 값에 영향을 줄 수 있으므로,
# 파생 경로가 이 상한 밖으로 나가면 그 그룹은 경고가 아니라 **제외**된다.
# 그래서 에이전트의 설치 트리까지만 열고 /usr/lib 전체로 넓히지 않는다.
scan_roots:
  - "/etc/nodewatch"            # agent.json · plugins.conf
  - "/usr/lib/nodewatch"        # 에이전트의 플러그인 트리 (자식 파일 규칙의 상한)

subjects: [structured_config, text_config, file]

detect:
  # ── 부모 — 설정에 심어진 항목 ─────────────────────────────────────────
  # 벤더 항목 셋(endpoint · intervalSeconds · plugins.dir)은 값이 평문이다.
  # 이 자리에 **짝수 길이 16진 문자열**이 들어 있는 것이 검체의 표식이고,
  # 그래서 hex_decode 가 뜻을 갖는다.
  # 길이는 못박지 않는다 — 폴더나 이름이 달라지면 길이도 달라진다.
  - id: relay
    subject: structured_config
    where:
      all:
        - { field: path,     op: ends_with, value: "/nodewatch/agent.json" }
        - { field: key_path, op: equals,    value: "relay.module" }
        - { field: value,    op: matches,   value: '^(?:[0-9a-fA-F]{2})+$' }
    capture:
      # 감춘 값을 푼다. **폴더도 이름도 오직 여기서 나온다** — 답안에 박지 않는다.
      module: "value | hex_decode"            # /usr/lib/nodewatch/plugins/libNetCache.so
      dir:    "${module} | dirname"           # /usr/lib/nodewatch/plugins
      # 목록과 디스크는 소문자인데 풀어 낸 이름은 대소문자가 섞여 있다.
      # 리눅스 비교는 접지 않으므로(접는 것은 Windows 뿐) 견줄 쪽을 소문자로 접는다.
      name:   "${module} | basename | lower"  # libnetcache.so

  # ── 자식 1 — 목록의 줄 ────────────────────────────────────────────────
  # 목록은 이름만 적고 설정은 전체 경로를 적는다. 경로에서 이름을 떼어 내
  # 견주는 것이 둘을 잇는 유일한 길이다.
  # 벤더 줄 둘(inventory.so · metrics.so)은 value 가 달라 걸리지 않는다.
  # 첫 줄은 주석이라 key 가 없다.
  - id: entry
    subject: text_config
    where:
      all:
        - { field: path,  op: ends_with, value: "/nodewatch/plugins.conf" }
        - { field: key,   op: equals,    value: "plugin" }
        - { field: value, op: equals,    value: "${relay.name}" }

  # ── 자식 2 — 그 폴더 안의 그 파일 ─────────────────────────────────────
  # from 이 부모가 가리킨 폴더로 좁히고, 접은 이름이 그 안의 한 파일로 좁힌다.
  # 벤더 플러그인 둘은 이름이 달라 걸리지 않는다.
  - id: payload
    subject: file
    from: "${relay.dir}"
    where:
      - { field: path, op: ends_with, value: "${relay.name}" }

# 설정 항목 하나만으로 판정하지 않는다 — 서로 다른 파일에서 온 독립 근거의 논리곱이다.
# 두 번째 근거를 파일 하나로 못박지 않는 이유: 다른 백신이 .so 만 잡아간 기계에서도
# 설정 둘은 그대로 남아 에이전트가 매 기동마다 없는 것을 부른다. 그 기계도 치료 대상이다.
# 반대로 관리자가 줄만 지운 기계는 파일이 남아 근거가 된다.
verdict:
  require: "relay and (entry or payload)"

remediate:
  # 순서를 적지 않는다 — 설정을 먼저 고칠지 파일을 먼저 치울지는 계획기가 정한다.
  remove:
    - { ref: relay }      # structured_config.remove_key — 항목 하나만 뺀다. 파일은 남는다
    - { ref: entry }      # text_config.remove_line — 줄 하나만 뺀다. 번호와 내용을 코어가 대조한다
    - { ref: payload }    # file.quarantine_only — 되돌릴 수 있게 치운다
  # 검체가 어떤 경로로 심겼는지는 관측되지 않았다. 재부팅 뒤 같은 플러그인이
  # 다시 판정하면 우리가 놓친 지속성 경로가 있다는 신호다.
  verify:
    after_reboot: true

submit_hint:
  samples: [payload]
  confidentiality_min: 1   # 설정 레코드에 고객 내부 보고 주소가 들어 있다
```

---

## 설명

**셋을 잇는 길은 하나뿐이다.** 설정 값 82자를 `hex_decode` 로 풀면
`/usr/lib/nodewatch/plugins/libNetCache.so` 가 나온다. 거기서 `dirname` 이 폴더를,
`basename | lower` 가 목록·디스크와 견줄 이름을 낸다. 목록은 이름만, 설정은 전체
경로만 적으므로 **경로에서 이름을 떼어 내지 않으면 둘을 이을 방법이 없고**, 풀어 낸
이름이 `libNetCache.so` 라 **접지 않으면 리눅스에서는 목록의 줄에도 파일에도 닿지
못한다.** 폴더와 파일 이름은 룰 어디에도 리터럴로 없다 — 전부 그 기계의 값에서 나온다.

**벤더의 것은 조건이 가른다.** 설정에서는 `key_path` 하나가, 목록에서는 `value` 가,
폴더에서는 접은 이름이 가른다. 제거는 `remove_key`·`remove_line`·`quarantine_only`
세 가지 제자리 편집·격리뿐이라 **설정 파일 둘과 벤더 플러그인 둘은 그대로 남는다.**
폴더 전체가 검체의 것이라는 관측이 없으므로 `dir.delete_recursive` 는 쓰지 않았다.

**판정을 `relay and (entry or payload)` 로 세운 이유.** 세 근거를 모두 `and` 로 묶으면
**다른 백신이 `.so` 만 잡아간 기계에서 판정이 서지 않고**, 설정 둘이 남아 에이전트가
매 기동마다 없는 것을 부른다. 남는 위험이 큰 쪽은 되살리는 설정이지 파일이 아니다.
`relay` 는 뿌리 규칙이라 오탐 안전을 혼자 떠받치므로 세 조건으로 좁혀 두었다.

**청정 기계에서 무엇을 매치하는가.** `scan_roots` 가 이 제품의 두 디렉터리뿐이라
nodewatch 가 없는 기계에서는 **뿌리 규칙이 마주하는 레코드가 0건**이다. 그래서
청정 코퍼스의 "파괴 0건" 은 이 룰을 시험한 적이 없다는 뜻이기도 하다 —
**nodewatch 가 정상 설치된 기계 한 장을 코퍼스에 넣어야 검증이 된다.**
걸릴 수 있는 정상 구성은 하나 댈 수 있다: 관리자가 `relay.module` 에 16진으로
경로를 손수 적어 둔 nodewatch 기계다. 그 값이 벤더 플러그인을 가리키면 그 줄과
파일까지 치우게 되므로, 서명 전에 그 구성이 실재하는지 확인해야 한다.

**없는 것은 만들지 않았다.**

- 대소문자를 접는 연산자가 없다 → 견줄 쪽을 `lower` 로 접었다.
- capture 값을 패턴과 견주는 술어가 없다 → *"푼 값이 경로인가"* 는 조건으로 못 쓰고,
  자식 둘이 그것을 대신 증명한다.
- 문자열을 잇는 함수가 없다 → `payload` 는 `<폴더>/<이름>` 을 만들지 못하고
  `from` + `ends_with <이름>` 으로 좁힌다. 폴더 안이라 실질적으로 같다.
- 검체의 YARA 룰도 sha256 도 받지 못했다 → 본문 근거는 넣지 않았다.
  시그니처를 추측해 채우는 것은 미탐을 낳고, 미탐은 아무도 잡지 못한다.
  분석가가 룰을 주면 경로로 매치되는 `payload` 를 가리키는
  `collect_extra: [{ ref: payload, content: true }]` 와 함께 규칙을 하나 더 둔다.

**한계 하나.** 검체가 `.so` 를 에이전트 설치 트리 **밖**에 떨어뜨린 변종에서는
파생 경로가 `scan_roots` 를 벗어나 그 그룹이 제외된다. 상한을 `/usr/lib` 로 넓히면
읽기와 삭제 권한이 함께 커지므로, 그 관측이 나오기 전에는 넓히지 않는다.
`scan_roots` 는 코퍼스가 재지 못하니 서명 전 실기기 `scan` 결과를 첨부한다.
