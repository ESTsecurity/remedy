# java4shell-check-linux — 릴리스 기록

**버전 0.2.0** · 대상: Java 런타임의 Base64 디코더 결함(CVE-2026-114938 · "Java4Shell") — 리눅스 ·
**점검**(바꾸지 않는다)

## 0.2.0 — Java 8 EPP · 사용자마다 까는 자리 · 서비스의 대체 링크 (2026-11-18)

0.1.0 을 낸 뒤 나온 1차 출처(Oracle CPU 2026-11 의 Java SE 위험 표 · Genians 2026-11-18)로 빠진 셋을 메운다. 긴급
경로로 낸다(코어 그대로).

- **Java SE 8 Enterprise Performance Pack(`-perf` 빌드)를 영향 판으로 찾는다.** 위험 표의 이 CVE 줄이
  `Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3,
  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3` 이다 — 일반 8u511b33 은 **같은 표의 다른 CVE 줄**(JavaFX ·
  libxml2)이고 이 줄에는 없다. 고친 판은 8u513-perf(1.8.0_513-perf-b4). 판 줄의 업데이트 번호가 513 아래이고 어느 판
  줄에든 `-perf` 표지가 있으면 취약(2)이다(`java_epp_affected`).
- **GraalVM** 은 바탕 Java 의 `JAVA_VERSION` 으로 같은 판정을 받는다(EE 21.3.20 의 바탕이 17.0.21 이면 2 — 하네스 s24).
- **사용자마다 까는 자리** — SDKMAN(`.sdkman/candidates/java`) · IntelliJ 가 받는 JDK(`.jdks`) · asdf(`.asdf/installs/java`) ·
  Gradle 툴체인(`.gradle/jdks`) · jabba(`.jabba/jdk`)를 `%ALLUSERPROFILES%`(`/home` 아래와 `/root`)로 본다. **제품이 받는
  자리** 둘도 더한다 — Logstash 가 담아 쓰는 JDK(`/usr/share/logstash`) · Jenkins 가 도구로 받는 JDK(`/var/lib/jenkins/tools`).
  자리는 1차 출처(각 도구의 문서 · 이슈)로 확인한 것만 넣었다 — VS Code 확장 · JetBrains Toolbox · snap 은 그 안 런타임에
  `release` 가 있는지 재지 못해 넣지 않았다(없으면 *확인 필요* 를 부른다).
- **`/usr/bin/java` 로 띄우는 서비스를 자리 밖으로 세지 않는다.** 서비스의 경로는 유닛에 적힌 글자 그대로라 배포판의 대체
  링크(`/usr/bin/java` → `/etc/alternatives/java` → `/usr/lib/jvm/…`)가 자리 밖으로 읽혔다 — 0.1.0 은 그런 서비스마다
  *확인 필요* 를 냈다(독립 검토가 짚었다). 그 링크가 가리키는 홈은 `/usr/lib/jvm` 에서 이미 본다.

## 0.1.0 — 처음 (2026-11)

공지가 나온 다음 날 긴급 경로(`docs/긴급-대응.md`)로 낸다. **코어를 바꾸지 않고** 코어 1.21.0 까지의 능력(`file_names` ·
`ref` 본문 수집 · `capture` + `from` 설치본 그룹 · `label` · `product`)만 쓴다.

## 무엇을 하나

| 갈래 | 판정 |
|---|---|
| 설치본의 판이 **고친 판 미만**이고 x86-64 빌드다 | **취약(2)** — 판 아래 줄에 CVE 와 고칠 길 |
| 설치본이 Java SE 8 Enterprise Performance Pack 이고 8u513-perf 아래다(0.2.0) | **취약(2)** — 판 아래 줄에 고친 판 |
| 설치본의 판이 지원이 끝난 줄(18 ~ 20 · 22 ~ 24 · 26)이고 x86-64 빌드다 | **취약(2)** — 고친 판이 나오지 않는다 |
| 아직 개발 중인 줄(28) | **확인 필요(6)** — 고친 빌드 번호가 공개되지 않았다 |
| `release` 에서 판을 읽지 못했다 · `release` 가 없다 | **확인 필요(6)** |
| 아래 자리 밖의 Java 가 돌고 있거나 서비스로 등록됐다 | **확인 필요(6)** — 그 판은 보지 않았다 |
| 지워진 Java 실행 파일을 실은 채 도는 프로세스 | **확인 필요(6)** — 올린 뒤 다시 시작하지 않았다 |
| 고친 판 이상 · Java 17 의 17.0.6 아래 · 일반 Java 8(EPP 가 아닌 것) · 11 · x86-64 가 아닌 빌드 · Java 없음 | 0 |

## 판 범위는 어디서 왔나

OpenJDK 공지 2026/11/17 의 위험 표가 이 CVE 가 걸린 줄을 **17 · 21 · 25 · 27** 로 적었다(8 · 11 칸은 비어 있다). 같은
날 그 줄마다 고친 판이 나왔다 — **17.0.21.1 · 21.0.13.1 · 25.0.5.1 · 27.0.1.1**. 그래서 이 룰은 **고친 판 미만을 취약으로,
고친 판 이상을 0 으로** 판정한다.

고친 판이 그 번호인 근거(2026-11-18 확인): 그 태그(`jdk-17.0.21.1-ga` 등)의 `version-numbers.conf` 가 `PATCH=1` ·
`DATE=2026-11-17` 이고, x86-64 Base64 디코드 코드를 고치는 커밋(`8393212: Base64 optimization improvements`)이 **그
태그에만** 있다(직전 `-ga` 태그들에는 없다). Oracle 의 같은 날 공지(Critical Security Patch Update November 2026)와
Amazon Corretto 17.0.21.1.2(2026-11-17)도 같은 상류 판을 싣는다.

**공지가 적은 영향 판 하나(17.0.21.0.3 등)와 견주지 않는다** — 그 판과 고친 판 사이의 빌드를 놓친다. 그리고 배포사의
제 번호는 `JAVA_VERSION` 에 없다(실측): Corretto 는 `IMPLEMENTOR_VERSION="Corretto-17.0.21.0.11"` 인데
`JAVA_VERSION="17.0.21"` 이고, Red Hat 계열은 `(Red_Hat-17.0.21.0.9-2)` 인데 `JAVA_VERSION="17.0.21"` 이다. 고친
Corretto(17.0.21.1.2)의 `JAVA_VERSION` 은 **17.0.21.1** 이다 — 그래서 상류 판으로 견주는 것이 맞다.

**정규식은 손으로 적지 않았다.** 점으로 나눈 판의 대소 비교를 정규식으로 옮기는 생성기가 `rules/java.yar` 를 쓰고, 그
생성기는 실측한 판 문자열과 경계 값 **52가지로 스스로를 검사한다**(어긋남 0). 생성기는 이 저장소에 두지 않았다 — 판
범위를 바꿀 때 다시 쓸 도구이므로 그때 `ci/` 로 옮길지 정한다.

### 17.0.6 아래는 영향이 아니다

x86-64 Base64 디코드 코드는 **17.0.6** 에 들어왔다(JDK-8268276 — 그 코드가 `jdk-17.0.5` 트리에 없다). 발견자(Calif)와
Red Hat 추적기도 "17.0.6 이상" 으로 적는다. 그래서 17.0.0 ~ 17.0.5 는 이 CVE 의 영향이 아니다(다른 결함은 이 룰이
말하지 않는다 — 지원되는 판으로 올리는 것이 좋다).

### 아직 개발 중인 줄은 단정하지 않는다

수정이 상류 master 에 들어갔지만 그것을 담은 빌드 번호가 공개되지 않았다(28 줄). 그 판은 **확인 필요**로 낸다.

### 아키텍처는 적혀 있을 때만 뺀다

결함은 x86-64 의 명령 집합(AVX-512 VBMI)을 쓰는 코드에 있다 — ARM64 · 32비트 빌드는 영향이 없고 `release` 의 `OS_ARCH`
가 그것을 말한다. 다만 **그 줄이 아예 없는 런타임이 있다**: 실측(2026-11-18) 어떤 제품이 담아 쓰는 Java 21 의 `release`
에는 `JAVA_VERSION` 과 `MODULES` 두 줄뿐이었다(jlink 로 지은 런타임). 그런 홈을 *모른다* 로 내면 실제로 취약한 기계가
확인 필요로 묻히므로, **아키텍처가 적혀 있지 않으면 판으로 판정한다.** 뺄 때 쓰는 값은 적어 둔 목록이다(`aarch64` ·
`x86` · `ppc64le` 등) — 모르는 값이 적혀 있으면 빼지 않고 판으로 판정한다(보수 쪽).

**CPU 가 그 명령 집합을 가졌는지는 판정에 넣지 않는다**: 가상 머신은 다른 호스트로 옮겨 가고 그때 CPU 가 바뀐다.
완화 옵션(`-XX:-UseBASE64Intrinsics` · `-XX:UseAVX=2`)도 판정에 넣지 않는다 — 넣는 자리가 제품마다 달라 다 볼 수 없다.
둘은 찾은 줄 아래 문구로 알린다.

## 보는 자리

| 자리 | 무엇 |
|---|---|
| `/usr/lib/jvm` · `/usr/lib64/jvm` | 배포판 패키지가 깐 JDK · JRE |
| `/opt` · `/usr/local` | 배포사 tar · 제품이 함께 깐 런타임(`/opt/java/openjdk` 가 그 꼴이다) |
| `/usr/java` | Oracle RPM |
| `/usr/share/elasticsearch` · `/usr/share/opensearch` | 제품이 담아 쓰는 런타임 |
| `/usr/share/logstash` · `/var/lib/jenkins/tools` | Logstash 가 담아 쓰는 JDK · Jenkins 가 도구로 받는 JDK(0.2.0) |
| `%ALLUSERPROFILES%` 의 `.sdkman/candidates/java` · `.jdks` · `.asdf/installs/java` · `.gradle/jdks` · `.jabba/jdk` | 사용자마다 깐 JDK(0.2.0 · `/home` 아래와 `/root`) |
| 그 밖 | 돌고 있는 `bin/java` · 서비스가 띄우는 `bin/java` 가 위 자리 밖이면 확인 필요 — 서비스가 `/usr/bin/java` · `/bin/java` · `/etc/alternatives/java`(대체 링크)로 띄우면 자리 밖이 아니다(0.2.0) |

`file_names: ["release", "java"]` 가 이 자리에서 **이름이 맞는 파일만** 기록하므로 폴더를 걷기만 한다. `scan_roots` 에
`/opt` 를 적어 린트 경고가 하나 붙는다 — 배포사 tar 와 제품이 담은 런타임이 그 아래 아무 폴더에나 놓이므로 좁힐 수
없다. 이 룰은 **점검 전용**이라 그 상한이 넓어져도 지울 수 있는 것이 늘지 않는다.

## 보지 않는 것

- **배포판이 상류 판 번호를 올리지 않고 고침만 얹는 경우**(백포트). `release` 의 `JAVA_VERSION` 이 그대로면 고친 기계도
  취약으로 보고한다. 2026-11-18 확인: Amazon Linux(Corretto)는 고친 상류 판(17.0.21.1)을 그대로 싣고, Debian · Ubuntu ·
  RHEL · Rocky · AlmaLinux · Oracle Linux · SUSE · Alpine 에는 아직 고친 빌드가 없다. **그 배포판들이 고친 빌드를 내면 그
  꼴을 다시 재고 이 룰을 다시 낸다** — 상류 판을 올리지 않는 배포판이 있으면 그 줄에는 패키지 판
  비교(`pkg_version_lt` · `rpm_version_lt` · `apk_version_lt`)를 더한다.
- **`release` 에 `-perf` 표지가 없는 EPP 빌드.** 0.2.0 은 판 줄의 `-perf`(판 줄이나 런타임 판 줄)로 EPP 를 가린다. EPP 의
  `release` 원본은 구독자 전용 내려받기라 재지 못했다 — 표지가 다른 꼴이면 그 빌드는 일반 8 처럼 0 으로 나간다. 실물을
  재면 그 꼴로 고친다.
- 선언한 자리 밖에 깔렸고 돌지도 않는 Java.
- 애플리케이션이 제 안에 담아 쓰는 런타임(jar 안의 클래스 · 컨테이너 이미지 안). 컨테이너 안은 `remedy-net` 의
  `image` · `container` 점검이 따로 본다.

## G9 — 룰의 검체 오탐

정상 파일 코퍼스는 **배포판 · 배포사 이미지 일곱**의 `/etc` · `/usr` · `/opt` 다(Debian 12 + openjdk-17 · Rocky 9 +
java-17 · 21 · Alpine 3.22 + openjdk17 · 21 · Amazon Linux 2023 + Corretto 17 · 21 · 고친 Corretto 17 ·
Temurin 25 · Java 없는 Debian 12). **46,443 파일**을 훑어 `java_release_file` 이 **9건**에 맞았고 그 아홉은 전부 Java
런타임 홈의 `release` 파일이다(오탐 0 — 점검 룰이 뜻한 바로 그 파일). 못 훑은 7,489건은 리눅스 링크(코퍼스가 적은
링크 수 7,468)와 상한을 넘은 파일이다. 판을 보는 규칙 넷은 `JAVA_VERSION="` 을 요구하므로 그 아홉의 부분집합이고,
`os_arch_not_x64` 는 설정 줄(`OS_ARCH`) 하나를 본다 — 규칙마다의 수는 공개 전 필수 점검 ④ 에서 함께 적는다.
0.2.0 의 새 규칙 `java_epp_affected` 는 같은 코퍼스에서 **맞음 0**(오탐 0 · 못 훑은 7,489건은 위와 같은 까닭 · 2026-11-18
실측 212초).

## 하네스

`testbed/harness/linux/java4shell-verify.sh` — 배포판 · 배포사 이미지 13(**실제 고친 빌드** Corretto 17.0.21.1.2 포함) ·
판 줄만 바꾼 자리 채우기 24(Java 8 EPP 셋 · 일반 8u511 · GraalVM EE 포함) · 사용자마다 까는 자리 · 제품이 받는 자리 5 ·
프로세스 · 서비스 4 · 화면 6. **실검체가 없다**: 판을 읽는 룰이고, 이미지는 배포판 · 배포사가 낸 Java 를 그대로 깐 것이며
손으로 세우는 경우는 JDK 홈의 모양만 맞춘 폴더다(`bin/java` 자리에는 무해한 `sleep` 을 복사해 둔다). **0.1.0 은 38/38 ·
0.2.0 은 2026-11-18 실측 52/52 통과**(공개한 1.23.0 의 리눅스 실행 파일로).
