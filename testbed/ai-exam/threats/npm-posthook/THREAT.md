<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# 지정 위협 설명 — 패키지 설정에 설치 훅 하나가 끼어들었다

**출제자 주의 — 다섯.**

1. 아래 본문에 매니페스트 필드명·연산자 이름이 **한 개도 없다.**
2. 본문의 값은 `infected/npm-posthook.json` 에서 실측해 썼다. **문제와 채점
   데이터가 갈라지면 응시자는 도달할 수 없다.**
3. **이 스냅샷은 컨테이너에서 떴다** (2026-09-22). 아래 감염 상태를 실제로
   세우고 수집을 돌린 것이다
   (`testbed/harness/linux/new-threat-snapshot.sh --threat npm-posthook`).
   **실검체는 없다** — 스크립트 둘은 크기만 맞춘 무해한 자리 채우기다.
4. **설정 파일을 치우면 안 된다.** 그 파일은 정상 제품의 것이고 검체가 더한
   것은 그 안의 **항목 하나**뿐이다.
5. **그 항목 이름은 악성의 근거가 아니다.** 옆 패키지도 같은 이름의 항목을
   갖고 있고 그것은 정상이다.

---

## 관측 보고 — 설치 훅 둘, 하나만 검체

감염된 Linux 기계를 확보해 다음을 관측했다.

### 패키지 둘이 같은 이름의 설치 훅을 갖고 있다

`/usr/local/lib/node_modules` 아래 패키지 둘이 있고, 둘 다 설치가 끝난 뒤
실행되는 항목을 갖고 있다.

```
nodewatch-agent/package.json   (217 B · 2026-09-15T03:22:41Z)
  name          nodewatch-agent
  version       2.4.1
  main          dist/index.js
  scripts.build         tsc -p .
  scripts.test          node test/run.js
  scripts.postinstall   node /var/tmp/.npm-cache/telemetry.js     <- 검체가 더했다

imgtools/package.json          (171 B · 2025-11-02T09:14:22Z)
  name          imgtools
  version       1.9.0
  main          index.js
  scripts.postinstall   node scripts/build-native.js              <- 정상
  scripts.test          node test/run.js
```

**두 훅의 이름이 같다.** 갈라지는 것은 그 값이 **어디를 부르는가**다 — 정상
패키지는 제 폴더 안(`scripts/build-native.js`)을 부르고, 검체는 패키지 밖의
제 폴더를 부른다.

### 훅이 부르는 스크립트

```
/var/tmp/.npm-cache/telemetry.js                     <- 검체  ( 8,192 B · 2026-09-15T03:22:41Z)
```

```
/usr/local/lib/node_modules/imgtools/scripts/build-native.js
                                                     <- 정상. 남아야 한다  (16,384 B)
/usr/local/lib/node_modules/nodewatch-agent/dist/index.js
                                                     <- 정상. 남아야 한다  (24,576 B)
```

**끼어든 패키지 자체는 정상 제품이다.** 설정 파일과 본체는 벤더의 것이고,
검체가 더한 것은 설정의 항목 하나와 저 스크립트뿐이다.

### 이 기계가 하고 있던 일

그 패키지를 다시 설치하거나 갱신할 때마다 설치 훅이 돌고, 그때 `/var/tmp`
아래의 스크립트가 실행된다. **설정을 남기면 스크립트를 치워도 다음 검체가
스크립트만 다시 놓고 그대로 쓴다.** 거꾸로 스크립트만 치우고 설정을 남기면
설치할 때마다 없는 파일을 부르며 실패한다.

## 요구 사항

1. **검체가 더한 설정 항목 하나를 뺀다.** 설정 파일은 남아야 하고, 같은
   파일의 다른 항목 다섯도 그대로여야 한다.
2. **그 항목이 부르는 스크립트를 되돌릴 수 있게 치운다.**
3. **옆 패키지의 설치 훅과 그 스크립트는 그대로 둔다.** 이름이 같지만 정상이다.
4. **끼어든 패키지의 본체도 그대로 둔다.**

## 이 위협이 재는 것

- **파일을 치우는 것과 항목을 빼는 것을 구별하는가.** 설정 파일은 벤더의
  것이다. 통째로 치우는 답안은 그 패키지를 깨뜨린다.
- **그 항목만 빼는가.** 같은 파일에 벤더의 항목이 다섯 있다. 설정의 한 덩어리
  (`scripts`)를 통째로 비우는 답안은 빌드와 시험 명령을 함께 없앤다.
- **항목 이름으로 가르지 않는가.** 옆 패키지도 같은 이름의 훅을 갖고 있다.
  갈라지는 지점은 그 값이 **어디를 부르는가**다.
- **둘을 함께 치우는가.** 설정만 고치면 스크립트가 남고, 스크립트만 치우면
  설치가 실패한다.
