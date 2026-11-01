```yaml
schema_version: 1
id: proxy-dns-hijack-netopt
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name:
  ko: "프록시·DNS 하이재킹(NetOpt) 제거"
  en: "Proxy/DNS hijack (NetOpt) removal"

# 읽기·삭제 권한 상한. 페이로드 파일만 이 안에 있다.
# hosts_entry·proxy_config·autorun 은 scan_roots 와 무관하게 수집되므로
# (10-manifest.md) 여기 적지 않는다. 정상 도구 NetTools\latency-probe.exe 는
# 이 밖이라 수집조차 되지 않는다.
scan_roots:
  - "%PROGRAMDATA%\\NetOpt"

subjects: [hosts_entry, proxy_config, file, autorun]

detect:
  # ── 리디렉션 갈래 ── 두 근거가 '같은 주소'로 서로를 뒷받침한다.
  # 돌려진 hosts 줄 — 10.20.30.40 으로 보내는 것만 잡는다. 조직이 넣은 줄은
  # 192.168.10.14 이고, OS 주석 스물한 줄에는 ip 항목이 없어 걸리지 않는다.
  # 갱신 서버·은행으로 이름은 서로 다르지만 공통점은 이 주소 하나다.
  - id: hostentry
    subject: hosts_entry
    where:
      - { field: ip, op: equals, value: "10.20.30.40" }

  # 나가는 길도 같은 주소를 거친다 — hosts 와 프록시를 하나로 묶는 근거.
  - id: proxy
    subject: proxy_config
    where:
      - { field: server, op: contains, value: "10.20.30.40" }

  # ── 페이로드 갈래 ── 파일과 그것을 실행하는 자동 시작이 서로를 뒷받침한다.
  # 검체. 정상 도구(NetTools\latency-probe.exe)는 폴더도 이름도 다르다.
  - id: payload
    subject: file
    where:
      - { field: path, op: ends_with, value: "\\NetOpt\\netopt.exe" }

  # 로그온 자동 시작 열일곱 중 그 검체를 가리키는 하나만. 나머지 열여섯은
  # command 가 달라 걸리지 않는다.
  - id: runkey
    subject: autorun
    where:
      - { field: command, op: contains, value: "\\NetOpt\\netopt.exe" }

# 두 갈래를 or 로 잇되, 각 갈래는 독립적인 두 근거의 논리곱이다.
# 어느 한 갈래만 남은 기계에서도 그 갈래만 정확히 서고(설계상 재발 대비),
# 근거 하나의 오탐이 곧바로 삭제가 되지 않는다. 검체 없는 PC 에서는 어느
# 갈래도 서지 않는다.
verdict:
  require: "(hostentry and proxy) or (payload and runkey)"

remediate:
  # 되돌린다 — 없애는 것이 아니다. 원래대로 복원하고 격리에 남는다.
  restore:
    - hosts     # hostentry 가 짚은 두 줄만 복원(hosts.restore_line).
                # 파일 자체·조직의 줄·OS 주석은 그대로 남는다.
    - proxy     # 서버 주소만 복원(proxy.restore). proxy_config 에 '사용 여부'
                # 필드가 없어, 켜짐 표시는 건드리지 않는다.
  # 없앤다 — 되돌릴 수 있게.
  remove:
    - { ref: payload }   # file.quarantine_only — 격리(되돌릴 수 있음)
    - { ref: runkey }    # autorun.remove — 다시 서는 자리 제거(유발자)
  # 지속성을 없앤 뒤 재부팅해 같은 판정이 다시 서는지 확인한다(경로 확인이
  # 아니라 재판정). 다시 서면 사람이 본다.
  verify:
    after_reboot: true

# 검체는 분석에 유용하다. 자동 제출은 없고, support-bundle 을 손으로 올리는
# 사람이 볼 힌트다. 고객 PC 경로가 실릴 수 있으므로 기밀 하한을 올려 둔다.
submit_hint:
  samples: [payload]
  confidentiality_min: 1
```

## 설명

이 룰은 하나의 조율된 공격을 **두 갈래**로 잡는다. 두 갈래를 하나로 묶는 것은 주소 `10.20.30.40` 하나다.

- **리디렉션 갈래** `hostentry`(hosts 줄이 `10.20.30.40` 을 가리킴) ∧ `proxy`(프록시 서버가 같은 주소). 돌려진 두 줄은 이름이 서로 다르지만(갱신 서버·은행) 같은 주소로 보낸다는 점이 공통이고, 그 주소가 프록시 설정에도 있어 서로를 뒷받침한다. 조직이 넣은 줄(`192.168.10.14`)과 OS 주석 스물한 줄은 `ip` 가 달라 걸리지 않는다.
- **페이로드 갈래** `payload`(`…\NetOpt\netopt.exe`) ∧ `runkey`(그 경로를 실행하는 로그온 자동 시작). 정상 `NetTools\latency-probe.exe` 는 폴더·이름이 다르고 `scan_roots`(`%PROGRAMDATA%\NetOpt`) 밖이라 수집조차 되지 않으며, 나머지 자동 시작 열여섯은 `command` 가 달라 걸리지 않는다.

**지우기와 되돌리기를 구분한다.** hosts 줄과 프록시 주소는 `restore`(→ `hosts.restore_line` · `proxy.restore`)로 **원래대로 돌린다** — hosts 는 짚은 두 줄만 줄 단위로 복원하므로 파일·조직 줄·OS 주석은 남는다. 페이로드와 자동 시작은 `remove`(→ `file.quarantine_only` 격리 · `autorun.remove`)로 **없앤다**. 넷 모두 되돌릴 수 있다.

**건드리지 않는 자리 — 프록시 사용 표시.** `proxy_config` 에는 '사용 여부' 필드가 없어 `proxy.restore` 는 서버 주소만 복원하고 켜짐 표시는 그대로 둔다. 이 도구에는 임의 값(플래그 0)을 쓰는 연산이 없고, 서버 주소가 복원되면 가로채기는 이미 멈춘다. 그래서 이 자리를 지우거나 0 으로 쓰지 않는다.

**판정.** 각 갈래가 독립적인 두 근거의 논리곱이라 근거 하나의 오탐이 곧바로 삭제로 이어지지 않고, 검체 없는 개발자 PC 에서는 어느 갈래도 서지 않는다. 두 갈래를 `or` 로 이은 것은 한쪽만 남은 기계(예: 바이너리가 이미 지워지고 리디렉션만 남은 상태)에서도 남은 갈래만 정확히 치료하기 위함이다 — 관측된 기계에서는 둘 다 서므로 전부 치료된다.

**만들어 낸 문법은 없다.** 쓴 subject·필드·연산자·복원 대상·Op 은 모두 문서의 전수 안에 있다. 재부팅 후 재판정(`verify.after_reboot`)으로 지속성 제거 뒤 재발을 확인하고, 검체는 `submit_hint` 로 분석에 넘길 수 있게 표시했다.
