```yaml
# npm 전역 패키지의 package.json 에 검체가 더한 설치 훅 항목 하나와,
# 그 항목이 부르는 /var/tmp 의 스크립트를 함께 치운다.

schema_version: 1
id: npm-postinstall-var-tmp-hook
version: 1.0.0
min_core: "1.0.0"
platforms: [linux]
name:
  ko: "npm 전역 패키지에 주입된 설치 훅(postinstall) 제거"
  en: "Injected npm postinstall hook removal (global packages)"

# 권한 상한 — 관측된 두 자리뿐이다.
scan_roots:
  - "/usr/local/lib/node_modules"   # 훅이 심긴 package.json. 패키지 이름은 검체가 고른 피해자라 적지 않는다
  - "/var/tmp/.npm-cache"           # 훅이 부르는 검체 스크립트의 폴더 — 관측한 이름 그대로

# subject 마다 제 자리에서만 모은다. file 을 node_modules 에서 모으지 않으므로
# 벤더 본체(dist/index.js)·옆 패키지 스크립트(scripts/build-native.js)·
# package.json 파일 자체는 file 레코드가 되지 못한다 — 격리될 길이 없다.
subject_roots:
  structured_config: ["/usr/local/lib/node_modules"]
  file: ["/var/tmp/.npm-cache"]

subjects: [structured_config, file]

detect:
  # ── 부모: 검체 스크립트 ─────────────────────────────────────
  # 훅 값 "node /var/tmp/.npm-cache/telemetry.js" 에서 스크립트 경로(두 번째
  # 토큰)를 뽑는 capture 함수는 없다 — first_path 는 "node" 를 낸다.
  # 그래서 방향을 뒤집는다: 스크립트를 부모로 두고 그 path 를 그대로 capture 해
  # 설정 항목의 value 에 보간한다.
  - id: script
    subject: file
    where:
      # /var/tmp 아래 폴더 한 겹 바로 안의 .js — 관측된 모양. 폴더 이름은
      # scan_roots 가 정한다. 뿌리 규칙이라 상한에 기대지 않고 조건만으로도 좁게 둔다.
      - { field: path, op: matches, value: '^/var/tmp/[^/]+/[^/]+\.js$' }
    capture:
      file_path: "path"

  # ── 자식: 그 스크립트를 부르는 설치 훅 항목 ─────────────────
  # 키 이름은 옆 패키지(imgtools)도 같다. 가르는 것은 값이 어디를 부르는가다 —
  # 부모가 찾은 스크립트의 절대 경로를 담은 값만 맞는다. 정상 훅은 제 폴더 안
  # 상대 경로(node scripts/build-native.js)를 부르므로 빠진다.
  - id: hook
    subject: structured_config
    where:
      all:
        - { field: path,     op: ends_with, value: "/package.json" }
        - { field: key_path, op: equals,    value: "scripts.postinstall" }
        - { field: value,    op: contains,  value: "${script.file_path}" }

# 서로 다른 대상 둘의 논리곱 — 설정 파일 속 항목 하나와 디스크 위 파일 하나.
verdict:
  require: "hook and script"

remediate:
  remove:
    # JSON 잎 하나만 뺀다(structured_config.remove_key). 파일은 남고
    # name·version·main·scripts.build·scripts.test 는 그대로다.
    - { ref: hook }
    # 스크립트는 격리한다(file.quarantine_only — 되돌릴 수 있다).
    - { ref: script }

submit_hint:
  samples: [script]          # 올릴 것은 검체 스크립트 — 벤더의 package.json 이 아니다
  confidentiality_min: 1
```

**치우는 것.** 검체가 더한 것은 `package.json` 의 잎 하나(`scripts.postinstall`)와 `/var/tmp/.npm-cache/telemetry.js` 둘뿐이므로, 둘을 서로 묶어 논리곱으로 판정하고 각각 `ref` 로 치운다. `hook` 은 `structured_config` 레코드, 곧 JSON 잎 하나라서 계획기가 `structured_config.remove_key` 로 그 키만 뺀다 — 파일도, 같은 파일의 다섯 항목도 남는다(`scripts` 를 통째로 비우지 않는다). 스크립트는 `file.quarantine_only` 로 격리된다. 둘 다 되돌릴 수 있고 순서는 코어가 정한다.

**없어서 돌아간 것.** 값 `node /var/tmp/.npm-cache/telemetry.js` 에서 스크립트 경로(두 번째 토큰)를 뽑는 capture 함수가 없다 — `first_path` 는 `node` 를 낸다. 함수를 지어내지 않고 방향을 뒤집었다: 스크립트를 부모로 세워 `path` 를 그대로 capture 하고, 설정 항목을 `value contains "${script.file_path}"` 로 거기 묶는다. 그래서 훅은 그 스크립트를 부르는 것만, 스크립트는 훅이 부르는 것만 판정에 든다. 폴더째 지우는 것도 없다 — `dir.delete_recursive` 는 Linux 칸이 `-` 이고, 폴더 전체가 검체의 것이라는 관측도 없다.

**스스로 확인.** 검체 없는 개발자 PC 에서 뿌리 `script` 는 관측 폴더 `/var/tmp/.npm-cache` 바로 아래의 `.js` 만 보는데, 청정 기계에는 그 폴더가 보통 없다. 떠올릴 수 있는 후보는 npm 캐시를 그 자리로 옮긴 환경(`npm_config_cache`)이지만 캐시 내용은 `_cacache`·`_npx` 같은 하위 폴더에 있어 한 겹 정규식에 걸리지 않고, 걸려도 `hook` 이 그 절대 경로를 부르는 `postinstall` 을 요구한다. postinstall 을 쓰는 정상 전역 패키지(nodemon·esbuild·electron 류, 관측의 imgtools)는 제 패키지 안 상대 경로를 부르므로 판정이 서지 않고, 벤더 파일은 `subject_roots` 로 file 수집에서 빠져 격리 대상이 될 수조차 없다. 판정은 설정 파일 속 항목과 디스크 위 파일, 서로 다른 대상 둘의 논리곱이라 근거 하나에 기대지 않는다. 제거는 둘 다 `ref` 이고 리터럴 경로·재귀 삭제·`edit` 이 없다.

**남는 한계.** 스크립트가 이미 지워진 기계에서는 부모가 서지 않아 훅이 남는다(설치 때마다 없는 파일을 부르며 실패한다). 그 기계에 남는 근거는 설정 하나뿐이라, 단일 근거 판정을 피하려고 받아들인 빈칸이다. 관측되지 않은 전역 경로(`/usr/lib/node_modules`·nvm)는 상한에 넣지 않았고, 전역 패키지가 아주 많은 기계에서는 JSON 잎 상한에 닿아 관측 불완전(종료 코드 6)이 날 수 있다 — 파괴가 아니라 보고로 끝난다.
