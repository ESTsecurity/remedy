# java4shell-check-windows — 릴리스 기록

**버전 0.3.1** · 대상: Java 런타임의 Base64 디코더 결함(CVE-2026-114938 · "Java4Shell") — Windows ·
**점검**(바꾸지 않는다)

## 0 을 내는 갈래

| 갈래 | 근거 | 하네스 칸 |
|---|---|---|
| 17 줄이 고친 판 이상(17.0.21.1 이상 — 배포사 꼴 `17.0.21.1.2` · 그 뒤 판 `17.0.22` 포함) | OpenJDK 공지 2026/11/17 — 17 줄의 고친 판 17.0.21.1(이 기록이 판 범위의 근거로 미루는 `java4shell-check-linux` 기록의 출처) | `F1` · `F2` · `F5` · `G2` |
| 21 줄이 고친 판 이상(21.0.13.1 이상) | OpenJDK 공지 2026/11/17 — 21 줄의 고친 판 21.0.13.1(`java4shell-check-linux` 기록의 출처) | `F3` · `G2` |
| 25 줄이 고친 판 이상(25.0.5.1 이상) | OpenJDK 공지 2026/11/17 — 25 줄의 고친 판 25.0.5.1(`java4shell-check-linux` 기록의 출처) | 없음 |
| 27 줄이 고친 판 이상(27.0.1.1 이상) | OpenJDK 공지 2026/11/17 — 27 줄의 고친 판 27.0.1.1(`java4shell-check-linux` 기록의 출처) | `F4` |
| 17 줄의 17.0.6 아래 | JDK-8268276 — x86-64 Base64 디코드 코드가 17.0.6 에 들어왔다(`java4shell-check-linux` 기록의 출처) | `C3` |
| 일반 Java 8(EPP 가 아닌 것) | Oracle CPU 2026-11 의 위험 표 — 이 CVE 줄은 8u511b33-perf 만 적는다(0.2.0) | `C1` · `C4` |
| Java 8 EPP 가 고친 판 이상(8u513-perf 이상) | Oracle CPU 2026-11 의 위험 표 — 이 CVE 줄은 8u511b33-perf 만 적는다 · 8u513-perf 아래면 취약(0.2.0) | `P2` |
| Java 11 | OpenJDK 공지 2026/11/17 — 위험 표의 11 칸이 비어 있다(`java4shell-check-linux` 기록의 출처) | `C2` |
| Oracle GraalVM EE 21.3 의 21.3.20.1 이상 — 바탕 Java 의 판으로 판정한다(바탕 11 이면 0) | 근거 없음 — EE 의 고친 판(21.3.20.1)을 적은 출처가 없다(`java4shell-check-linux` 기록도 같다 — 위험 표는 영향 판 21.3.20.0.3 만 적는다) | `GE2` |
| Oracle 빌드가 아닌 GraalVM 21.3(Community · 다른 배포사) — 바탕 Java 의 판으로 판정한다(바탕 11 이면 0) | Oracle CPU 2026-11 위험 표 — 이 CVE 줄의 GraalVM 은 Oracle GraalVM for JDK · Enterprise Edition 뿐이다(`java4shell-check-linux` 기록의 출처) · 바탕 Java 는 그 판의 줄로 본다 | `GE3` |
| `release` 의 `OS_ARCH` 가 x86-64 가 아닌 값으로 적혔다(ARM64 · 32비트) | 수정 커밋 8393212 — 고치는 것이 x86-64 Base64 디코드 코드다 · 결함이 x86-64 의 AVX-512 VBMI 코드에 있다(`java4shell-check-linux` 기록의 출처) | `A1` · `A2` |
| `release` 에서 판을 읽지 못했으나 `OS_ARCH` 가 x86-64 가 아니라고 적혔다(0.3.0) | 수정 커밋 8393212 — 결함이 x86-64 의 AVX-512 VBMI 코드에 있다(`java4shell-check-linux` 기록의 출처) | `U4` |
| Java 없음 | 공지의 영향 제품이 없다 | `N1` |
| 보는 자리 안의 `java.exe` 를 띄우는 서비스 + 그 홈이 고친 판 | OpenJDK 공지 2026/11/17 — 줄마다의 고친 판(위 넷) · 서비스는 자리 안이라 판정 표의 '자리 밖' 줄에 들지 않는다 | `O3` |
| 보는 자리 안에서 도는 `java.exe` · `javaw.exe` + 그 홈이 고친 판 | OpenJDK 공지 2026/11/17 — 줄마다의 고친 판(위 넷) · 프로세스는 자리 안이라 판정 표의 '자리 밖' 줄에 들지 않는다 | 없음 |
| Oracle 설치 프로그램의 `javapath`(`C:\ProgramData\Oracle\Java\javapath\java.exe`)로 띄우는 서비스 — 자리 밖으로 세지 않는다 | 0.2.0 — `javapath` 의 `java.exe` 는 `C:\Program Files\Java` 의 홈을 가리키는 길이다(그 홈은 판으로 본다) | `O4` |
| `javapath` 로 도는 프로세스 — 자리 밖으로 세지 않는다 | 0.2.0 — 위 줄과 같다(서비스 · 프로세스 둘 다) | 없음 |
| 판정 표의 어느 줄에도 들지 않는 옛 줄(1.7 · 9 · 10 · 12 ~ 16) — 판은 읽었으나 영향 · 지원 끝 · 개발 중 줄 어디에도 걸리지 않는다 | 근거 없음 — 이 줄들을 말하는 출처가 없다(`java4shell-check-linux` 기록도 같다 — 위험 표의 8 · 11 칸과 17.0.6 에 코드가 들어왔다는 줄뿐) | 없음 |
| 판정 표의 어느 줄에도 들지 않는 새 줄(29 이상) | 수정 커밋 8393212 가 상류 master 에 들어갔고 29 이상의 줄은 그 master 에서 갈라진다(`java4shell-check-linux` 0.3.0) | 없음 |

## 린트 경고

| 자리 | 까닭 |
|---|---|
| `scan_roots[0]` | `C:\Program Files` — 배포사마다 설치 폴더가 달라 좁힐 수 없다 · `file_names`(`release` · `java.exe`)가 이름이 맞는 파일만 기록하므로 폴더를 걷기만 한다 · 점검 전용이라 상한이 넓어져도 지울 수 있는 것이 늘지 않는다(RELEASE.md '보는 자리' 의 '두 자리 때문에 린트 경고가 둘 붙는다' · plugin.yaml 의 `scan_roots` 위 주석) |
| `scan_roots[1]` | `C:\Program Files (x86)` — `scan_roots[0]` 과 같은 문단('두 자리 때문에 린트 경고가 둘 붙는다')이 까닭이다 — 배포사마다 설치 폴더가 달라 좁힐 수 없다 · 점검 전용이라 상한이 넓어져도 지울 수 있는 것이 늘지 않는다(이 자리는 32비트 설치본을 `OS_ARCH` 로 가른다 — RELEASE.md '보는 자리') |

## 0.3.1 — 더한 날을 적는다 (2026-11-19)

리눅스 룰 0.3.1 과 같은 출시로 낸다(엔진 1.25.0 과 함께).

- **매니페스트에 `added: "2026-11-18"`** — 이 룰을 처음 낸 날이다(`rules-2026.11.18`). 엔진 1.25.0 의 고르는 화면이
  꾸러미의 가장 새 날부터 사흘 안의 룰을 검사 줄 바로 아래 *새로 추가된 항목* 으로 올리고 *[11월 18일 추가]* 를 붙인다.
  `min_core` 를 1.25.0 으로 올린다(낮은 코어는 이 칸을 모른다).
- 판정 · 보는 자리 · 문구는 0.3.0 과 같다.

## 0.3.0 — GraalVM Enterprise Edition 21.3 을 제품 판으로 (2026-11-18)

리눅스 룰 0.3.0 과 같은 출시로 낸다(엔진 1.24.0 과 함께). 근거와 판정은 리눅스 룰의 `RELEASE.md` 0.3.0 절과 같다.

- **Oracle GraalVM Enterprise Edition 21.3 은 `GRAALVM_VERSION` 이 21.3.20.1 미만이면 바탕 Java 와 상관없이 취약(2)이다**
  (`graalvm_ee_affected`) — 0.2.0 은 바탕 Java 로 판정해 EE 의 Java 11 · 8 판을 0 으로 냈다. Oracle 빌드
  (`IMPLEMENTOR="Oracle Corporation"`)만이고 Community 판은 전처럼 바탕 Java 로 판정한다.
- **판을 읽지 못한 `release` 도 x86-64 가 아니라고 적혀 있으면 뺀다**(독립 검토).
- **VS Code 의 Java 확장이 담는 JRE 를 본다** — 사용자마다 `.vscode\extensions`. 실측 2026-11-18: redhat.java
  1.59.2026111308 win32-x64 가 `jre\25.0.5-win32-x86_64\` 에 JRE 를 담고 그 `release` 는 `JAVA_VERSION="25.0.5"` ·
  `MODULES` 두 줄이다 — **25.0.5.1 미만이라 취약(2)**. JetBrains Toolbox 가 까는 IDE 는 `AppData\Local\Programs` 로 이미 본다.
- **관리자도 열 수 없는 폴더** — 0.2.0 의 *아직 못 고친 것* 은 엔진 1.24.0 이 고친다: 그 폴더를 건너뛰고 나머지로 말하며
  건너뛴 경로를 알린다(그 폴더 안은 보지 않는다). 1.23.0 엔진에서는 그대로 확인 필요다.
- 하네스 **43칸**(0.2.0 은 37 — GraalVM EE 3 · 판 없는 ARM64 1 · VS Code 1 · 화면 1).

## 0.2.0 — Java 8 EPP · 사용자마다 까는 자리 · javapath (2026-11-18)

리눅스 룰 0.2.0 과 같은 출시로 낸다(긴급 경로 · 코어 그대로). 근거와 판정은 리눅스 룰의 `RELEASE.md` 0.2.0 절과 같다.

- **Java SE 8 Enterprise Performance Pack(`-perf` 빌드)를 영향 판으로 찾는다** — 8u513-perf 아래면 취약(2) · 일반 Java 8 은
  그대로 0(Oracle CPU 2026-11 의 위험 표에서 이 CVE 줄은 `8u511b33-perf` 만 적는다).
- **사용자마다 까는 자리** — IntelliJ 가 받는 JDK(`.jdks`) · Scoop(`scoop\apps` · 전역은 `C:\ProgramData\scoop\apps`) · 사용자
  프로그램 폴더(`AppData\Local\Programs` — JetBrains IDE 가 담아 쓰는 런타임 등) · Gradle 툴체인(`.gradle\jdks`) · jabba
  (`.jabba\jdk`)를 `%ALLUSERPROFILES%` 로 본다.
- **Oracle 설치 프로그램의 `javapath` 로 띄우는 서비스 · 프로세스를 자리 밖으로 세지 않는다** — `C:\ProgramData\Oracle\Java\
  javapath\java.exe` 는 `C:\Program Files\Java` 의 홈을 가리키는 길이다.
- **아직 못 고친 것** — `C:\Program Files` 아래에 관리자도 열 수 없는 폴더(Defender for Endpoint 의 설정 폴더 등)가 있으면
  지금 코어는 그 폴더 하나 때문에 '취약하지 않다' 를 말하지 않는다(확인 필요 · 화면의 *관리자 권한으로 다시* 안내는 이미
  관리자인 사람에게 틀린 말이다). 나머지 폴더는 다 본다. 코어가 고칠 일이라 다음 엔진 출시로 간다.

## 0.1.0 — 처음 (2026-11)

리눅스 룰(`java4shell-check-linux` 0.1.0)과 같은 날 같은 긴급 출시로 낸다. 판정 규칙과 `rules/java.yar` 는 두 룰이
**같은 파일**을 쓴다 — Windows 판 JDK 의 `release` 도 같은 꼴이다(실측 2026-11-18 · Eclipse Temurin 17.0.21+9 의 Windows
x64 zip: `jdk-17.0.21+9\bin\java.exe` 와 같은 폴더의 `release` 에 `JAVA_VERSION="17.0.21"` · `OS_ARCH="x86_64"` ·
`OS_NAME="Windows"`).

## 무엇을 하나

| 갈래 | 판정 |
|---|---|
| 설치본의 판이 **고친 판 미만**(17.0.21.1 · 21.0.13.1 · 25.0.5.1 · 27.0.1.1)이고 x86-64 빌드다 | **취약(2)** |
| 설치본이 Java SE 8 Enterprise Performance Pack 이고 8u513-perf 아래다(0.2.0) | **취약(2)** |
| 설치본이 Oracle GraalVM Enterprise Edition 21.3 이고 21.3.20.1 아래다 — 바탕 Java 와 상관없이(0.3.0) | **취약(2)** |
| 설치본의 판이 지원이 끝난 줄(18 ~ 20 · 22 ~ 24 · 26)이고 x86-64 빌드다 | **취약(2)** — 고친 판이 나오지 않는다 |
| 아직 개발 중인 줄(28) | **확인 필요(6)** — 고친 빌드 번호가 공개되지 않았다 |
| `release` 에서 판을 읽지 못했다 · `release` 가 없다 | **확인 필요(6)** |
| 아래 자리 밖의 Java 가 돌고 있거나 서비스로 등록됐다 | **확인 필요(6)** — 그 판은 보지 않았다 |
| 고친 판 이상 · Java 17 의 17.0.6 아래 · 일반 Java 8(EPP 가 아닌 것) · 11 · x86-64 가 아닌 빌드 · Java 없음 | 0 |

판 범위의 근거(고친 판의 태그 · 수정 커밋 · 배포사 번호가 `IMPLEMENTOR_VERSION` 에 있다는 실측) · 17.0.6 아래를 영향에서
빼는 까닭 · **아키텍처가 적혀 있을 때만 빼는 까닭**은 리눅스 룰의 `RELEASE.md` 와 같다 — 두 룰이 **같은
`rules/java.yar`** 를 쓴다. 그 마지막 실측은 이 랩 기계에서 나왔다: `C:\Program Files` 아래 어떤 제품이 담아 쓰는
Java 21.0.5 의 `release` 에 `OS_ARCH` 줄이 없었고, 그 꼴을 확인 필요로 내면 고친 판이 아닌 런타임이 묻힌다.

## 보는 자리

| 자리 | 무엇 |
|---|---|
| `C:\Program Files` | 배포사 설치 프로그램이 깐 JDK · JRE(`Java` · `Eclipse Adoptium` · `Amazon Corretto` · `Microsoft` · `Zulu` · `BellSoft` · `SapMachine` 등이 모두 그 아래다)과 제품이 함께 담은 런타임 |
| `C:\Program Files (x86)` | 32비트 설치본(영향 없음 — `OS_ARCH` 로 가른다) |
| `C:\ProgramData\scoop\apps` · `%ALLUSERPROFILES%` 의 `.jdks` · `scoop\apps` · `AppData\Local\Programs` · `.gradle\jdks` · `.jabba\jdk` | 사용자마다 깐 JDK · IDE 가 담아 쓰는 런타임(0.2.0) |
| 그 밖 | 돌고 있는 `java.exe` · `javaw.exe` · 서비스가 띄우는 것이 위 자리 밖이면 확인 필요 — Oracle 의 `javapath` 는 자리 밖이 아니다(0.2.0) |

`file_names: ["release", "java.exe"]` 가 이 자리에서 **이름이 맞는 파일만** 기록하므로 폴더를 걷기만 한다. 두 자리 때문에
린트 경고가 둘 붙는다(`php2shell-check-windows` 와 같은 꼴) — 배포사마다 설치 폴더가 달라 좁힐 수 없다. 이 룰은
**점검 전용**이라 그 상한이 넓어져도 지울 수 있는 것이 늘지 않는다.

## 보지 않는 것

- **위 자리 밖에 풀어 둔 Java 중 멈춰 있는 것.** Windows 의 Java 는 zip 을 아무 폴더에나 풀어 쓰기도 한다. 돌고 있거나
  서비스로 등록됐으면 찾아서 확인 필요로 그 경로를 적는다. 레지스트리의 `JavaHome` 을 읽는 것은 **실측한 키로 다음 판에**
  더한다 — 이 기계에는 Java 가 깔려 있지 않아 키 자리를 재지 못했다(추측으로 적지 않는다).
- 배포판 백포트 · 애플리케이션이 담아 쓰는 런타임 — 리눅스 룰의 `RELEASE.md` 와 같다.

## 하네스

`testbed/harness/host/Invoke-Java4ShellVerify.ps1` — 랩 VM 에 **진짜 JDK**(Eclipse Temurin 17.0.21+9 Windows x64 zip)를
풀어 영향 판을 재고, 판 줄만 바꾼 자리 채우기로 고친 판 · ARM64 · 지원이 끝난 줄 · 읽지 못한 판 · Java 8 EPP · 사용자
프로필의 `.jdks` · Gradle 툴체인 · javapath 서비스를 잰다(0.2.0 — 37칸 · 칸 수도 단정한다). **실검체가 없다** — 판을 읽는
룰이고, 자리 채우기는 JDK 홈의 모양만 맞춘 폴더다.
