# 답안 — NetGuard TLS 가로채기 키트

## 1. `plugin.yaml`

```yaml
schema_version: 1
id: netguard-tls-intercept
version: 1.0.0
min_core: "1.0.0"
platforms: [linux]
name:
  ko: "NetGuard TLS 가로채기 키트 제거"
  en: "NetGuard TLS interception kit removal"

# 읽기 권한 상한.
#
# `file` 규칙만 이 상한을 받는다 — `cert_store` 와 `hosts_entry` 는 상한과
# 무관하게 수집된다 (10-manifest.md §scan_roots 의 표). 그래서 인증서 저장소
# 경로도 /etc 도 여기 적지 않는다. 적으면 지울 수 있는 범위만 넓어진다.
#
# 페이로드 자리는 **감염마다 바뀌지 않는다**(패키지처럼 설치된다). 바뀌지 않는
# 것은 조건이 아니라 상한이 정한다 (20-detect-recipes.md §자주 막히는 곳).
# `/opt` 로 넓히지 않는다 — 거기에는 정상 소프트웨어(`/opt/goodware/`)가 산다.
scan_roots:
  - "/opt/netguard"

subjects: [cert_store, hosts_entry, file]

detect:
  # ── 근거 1 · 신뢰 저장소에 심긴 루트 CA ────────────────────────────
  # 자가 발급으로 가르지 않는다. 청정 기계의 루트 529장이 전부 자가 발급이다.
  # 가르는 것은 `store`(손으로 더한 CA 자리)와 **주체 이름**이다.
  - id: cert
    subject: cert_store
    where:
      all:
        - { field: store,   op: equals,   value: "local" }
        - { field: subject, op: contains, value: "NetGuard Secure Proxy CA" }

  # ── 근거 2 · 돌려진 이름 ───────────────────────────────────────────
  # 줄 번호가 아니라 주소와 이름의 조합으로 가른다. 줄 전체가 아니라
  # 쪼개진 `ip`·`hostnames` 를 본다.
  - id: redirect
    subject: hosts_entry
    where:
      all:
        - { field: ip,        op: starts_with, value: "127." }
        - { field: hostnames, op: contains,    value: "example-av.com" }

  # ── 근거 3 · 페이로드 ──────────────────────────────────────────────
  # 상한이 /opt/netguard 이므로 이 두 규칙은 그 폴더 안만 본다.
  # 크기는 조건에 넣지 않는다 — 빌드마다 바뀌고 변종을 조용히 놓친다.
  - id: proxyd
    subject: file
    where:
      - { field: path, op: ends_with, value: "/netguard-proxyd" }

  - id: cakey
    subject: file
    where:
      - { field: path, op: ends_with, value: "/ca.key" }

verdict:
  require: "cert and (redirect or proxyd or cakey)"

remediate:
  remove:
    - { ref: cert }      # cert_store.remove
    - { ref: proxyd }    # file.quarantine_only
    - { ref: cakey }     # file.quarantine_only
  restore:
    - hosts              # hosts.restore_line — 룰이 짚은 줄만 되돌린다
  verify:
    after_reboot: true

submit_hint:
  samples: [proxyd, cakey]
  confidentiality_min: 1
```

---

## 2. 설명

### 판정을 이렇게 세운 이유

**인증서를 고정 근거로 두었다.** 40-review-checklist 2번이 묻는 것 — *"이 근거가
없어도 위협인가"* — 에 인증서만이 무조건 그렇다고 답한다. 바이너리는 다시 받으면
그만이고, 남은 인증서가 그것을 다시 부른다. 실제로 `tls-r1` 에서 갈린 자리가
**바이너리가 이미 지워진 기계**였다.

**두 번째 근거를 하나로 못박지 않았다.** `cert and redirect` 로 못박으면 hosts 만
손으로 되돌린 기계에서 판정이 서지 않고, `cert and proxyd` 로 못박으면 폴더만
지워진 기계에서 서지 않는다. 셋 중 하나면 된다.

`guard` 를 쓰지 않으므로 *"판정은 서는데 계획이 통째로 거부되는"* 형태는 나오지
않는다.

**판정이 서지 않는 기계 하나가 남는다** — 인증서만 이미 빠지고 hosts 와 페이로드가
남은 기계다. 그 상태는 가로채기가 더 이상 조용히 성립하지 않으므로 고정 근거를
버리는 것보다 낫다고 보았다. 서명 검토에서 이 판단을 다시 물어야 한다.

### 오탐 — 이름을 댈 수 있는 정상 대상

| 규칙 | 걸릴 수 있는 정상 대상 |
|---|---|
| `cert` | **기업용 TLS 검사 제품 전부가 같은 모양이다** — Zscaler · Netskope · Fortinet · Palo Alto · Cisco Umbrella, 그리고 mitmproxy · Burp Suite · Charles 같은 개발 도구. 조직의 내부 CA 도 같은 자리(`local`)에 산다. 이름 한 줄이 그 전부와 이 검체를 가른다. **"NetGuard" 라는 이름의 정상 제품을 실제로 배포하는 고객이 있으면 이 룰은 그 CA 를 뺀다.** |
| `redirect` | **hosts 차단 목록**(StevenBlack/hosts 계열)이 전송 도메인을 127.0.0.1 로 돌린다. 사생활을 이유로 손으로 넣어 둔 관리자도 있다. 그래서 이 규칙 단독으로는 판정하지 않는다. |
| `proxyd`·`cakey` | `ca.key` 는 흔한 파일명이지만 상한이 `/opt/netguard` 라 그 폴더 밖은 아예 수집되지 않는다. `/opt/goodware/` 는 상한 밖이다. |

청정 스냅샷에서 파괴 Action 0건이려면 `cert` 가 서지 않아야 하고, 그것은 저 이름
한 줄에 달려 있다. **G1 결과 첨부가 서명 조건이다.**

### 없는 것 — 만들지 않고 적는다

1. **`dir.delete_recursive` 는 Linux 에 없다** (`ops.json` 의 `linux_from: null`).
   `/opt/netguard/` 디렉터리 자체는 지울 수 없고, 관측된 두 파일만 `ref` 로
   개별 격리한다. 선언해 봐야 `deferred` 로 나갈 뿐이라 넣지 않았다.
   → **빈 디렉터리와 관측되지 않은 부속 파일이 남는다.**
2. **개인키가 그 인증서의 것인지 확인할 수단이 없다.** 키와 인증서를 대조하는
   연산자도 Op 도 없다. YARA 는 분석가가 준 룰이 있어야 하는데 받지 못했으므로
   추측해 채우지 않았다 (30-antipatterns.md 10번).
3. **지속성 경로가 관측되지 않았다.** "패키지처럼 설치되어 자리가 고정" 이라면
   유닛이 있을 법하지만 보고에 없다. 지어내지 않고 `verify.after_reboot` 로
   넘겼다 — 다시 판정되면 사람이 본다.
4. **돌고 있는 프로세스도 관측되지 않았다.** `process` 규칙을 넣지 않았다.
5. **`proxy_config` 는 Linux 에서 "개념만" 이다.** 프록시 키트인데도 이 subject 를
   쓸 수 없다 — `platforms: [linux]` 하나뿐이면 린트가 오류로 막는다.
6. **Phase → `min_core` 대응표가 문서에 없다.** 여기 쓰인 것은 전부 Linux P12 인데
   ex03(같은 조건의 Linux 예제)이 `1.0.0` 을 쓰므로 그것을 따랐다.

### 스스로 확인한 것

- **검체 없는 개발자 PC 에서 무엇을 매치하는가** — `cert` 는 서지 않는다(그 이름의
  CA 가 없다). `redirect` 는 차단 목록을 쓰는 기계에서 설 수 있으나 단독으로는
  판정이 아니다. `/opt/netguard` 가 없으므로 파일 규칙은 0건이다. → 파괴 0건.
- **근거 하나에 기대는가** — 아니다. 항상 `cert` + 다른 관측 대상 하나다. 셋은
  각각 신뢰 저장소 · 이름 해석 · 파일 시스템에서 온다.
- **지우는 대상이 전부 증거에서 나왔는가** — 그렇다. `remove` 는 전부 `ref` 이고
  리터럴 `path` 가 하나도 없다. hosts 는 `restore` 로 룰이 짚은 줄만 되돌린다.

### 실기기에서 한 번 돌려야 하는 이유

`scan_roots: ["/opt/netguard"]` 는 **감염 기계에만 존재하는 경로**다. 코퍼스
시험은 이미 수집된 스냅샷을 쓰므로 토큰을 확장하지 않고, 존재하지 않는 경로를
적어도 전부 통과한다. 상한이 실제로 그 두 파일을 모으는지는 실기기 `scan`
결과로만 확인된다 (40-review-checklist.md 6번).
