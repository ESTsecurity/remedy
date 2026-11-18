// Java4Shell 점검(CVE-2026-114938) — 두 OS 룰이 함께 쓰는 본문 규칙. 보는 것은 Java 런타임 홈의 `release` 파일이다.
//
// `release` 는 JDK · JRE 이미지가 제 홈에 두는 텍스트 파일이고 `JAVA_VERSION="17.0.21"` 처럼 `이름="값"` 줄이 들어 있다
// (실측 2026-11-18 — Debian 12 · Ubuntu 24.04 · 22.04 · Rocky 9 · Alpine 3.22 · Amazon Linux 2023 의 패키지와 Eclipse
// Temurin · Amazon Corretto 이미지). 확장자가 없어 코어의 설정 수집(`text_config`)이 닿지 않으므로 파일 본문으로 본다.
//
// 판 범위는 OpenJDK 공지 2026/11/17 에서 왔다 — 위험 표에서 이 CVE 가 걸린 줄은 **17 · 21 · 25 · 27** 이고(8 · 11 칸은
// 비어 있다), 같은 날 나온 **고친 판이 17.0.21.1 · 21.0.13.1 · 25.0.5.1 · 27.0.1.1** 이다(그 태그의
// `version-numbers.conf` 가 PATCH=1 · DATE=2026-11-17 이고, 수정 커밋 `8393212: Base64 optimization improvements` 가
// 그 태그에만 있다). 그래서 **고친 판 미만이 영향 판**이다.
//
// 공지가 적은 영향 판(17.0.21.0.3 등) 하나와 견주지 않는 까닭: 그 판과 고친 판 사이의 빌드를 놓친다. 배포사의 제 번호
// (Corretto-17.0.21.0.11 · Red_Hat-17.0.21.0.9)는 `JAVA_VERSION` 이 아니라 `IMPLEMENTOR_VERSION` 에 있다(실측) —
// 여기서 보는 것은 상류 판이다.
//
// 17 줄은 **17.0.6 아래를 영향에서 뺀다** — x86-64 Base64 디코드 코드가 그 판에 들어왔다(JDK-8268276 · Red Hat 추적기도
// "17.0.6 이상" 으로 적는다).
//
// 아래 정규식은 손으로 적지 않았다. 점으로 나눈 판의 대소 비교를 정규식으로 옮기는 생성기가 쓰고, 그 생성기는 실측한 판
// 문자열과 경계 값 52가지 · Java 8 EPP 의 release 본문 13가지 · GraalVM EE 의 release 본문 20가지로 스스로를 검사한다
// (어긋남 0 · RELEASE.md 에 적었다).

// 이 파일이 Java 런타임의 `release` 인가 — 판을 읽을 수 있는가의 기준이다.
rule java_release_file
{
    meta:
        description = "a Java runtime release file (it has a JAVA_VERSION line)"
    strings:
        $v = /JAVA_VERSION="[0-9]/
    condition:
        $v
}

// x86-64 가 **아닌** 빌드 — 이 결함은 x86-64 의 명령 집합(AVX-512 VBMI)을 쓰는 코드에 있으므로 그 빌드는 영향이 없다.
// 적혀 있는 값으로만 뺀다: `release` 에 `OS_ARCH` 줄이 아예 없는 런타임이 있기 때문이다(jlink 로 지은 런타임 — 실측
// 2026-11-18, 어떤 제품이 담아 쓰는 Java 21 의 `release` 에는 `JAVA_VERSION` 과 `MODULES` 두 줄뿐이었다). 그런 홈을
// '모른다' 로 내면 실제로 취약한 기계가 확인 필요로 묻히므로, **아키텍처가 적혀 있지 않으면 판으로 판정한다.**
rule os_arch_not_x64
{
    meta:
        description = "a build whose declared OS_ARCH is not x86-64"
    strings:
        $a = /OS_ARCH="(aarch64|arm|arm32|arm64|x86|i386|i486|i586|i686|ppc|ppc64|ppc64le|s390|s390x|riscv64|sparc|sparcv9|mips|mips64|mips64el|loongarch64)"/
    condition:
        $a
}

// 지원되는 줄(17 · 21 · 25 · 27)의 영향 판 — 2026-11-17 의 고친 판 미만.
rule java_version_affected
{
    meta:
        description = "a JAVA_VERSION below the release that fixes CVE-2026-114938 on that line"
    strings:
        $v17 = /JAVA_VERSION="17(\.0(\.([0-9]|1[0-9]|20)(\.[0-9]+)*|\.21(\.(0)(\.[0-9]+)*)?)?)?"/
        $v21 = /JAVA_VERSION="21(\.0(\.([0-9]|1[0-2])(\.[0-9]+)*|\.13(\.(0)(\.[0-9]+)*)?)?)?"/
        $v25 = /JAVA_VERSION="25(\.0(\.([0-4])(\.[0-9]+)*|\.5(\.(0)(\.[0-9]+)*)?)?)?"/
        $v27 = /JAVA_VERSION="27(\.0(\.(0)(\.[0-9]+)*|\.1(\.(0)(\.[0-9]+)*)?)?)?"/
    condition:
        any of them
}

// 아직 개발 중인 줄 — 수정이 master 에 들어갔지만 그것을 담은 빌드 번호가 공개되지 않았다. 단정하지 않는다.
rule java_version_future_line
{
    meta:
        description = "a JAVA_VERSION on a line still in development (no released build carries the fix yet)"
    strings:
        $v = /JAVA_VERSION="(28)(\.[0-9]+)*"/
    condition:
        $v
}

// 지원이 끝난 줄 — 같은 코드를 담고 있고 고친 판이 나오지 않는다. 지원되는 줄로 올리는 것이 답이다.
rule java_version_eol_line
{
    meta:
        description = "a JAVA_VERSION on a feature line past its support (no fixed build will come)"
    strings:
        $v = /JAVA_VERSION="(18|19|20|22|23|24|26)(\.[0-9]+)*"/
    condition:
        $v
}

// 17 줄에서 x86-64 Base64 디코드 코드가 들어오기 전의 판(17.0.6 아래) — 이 결함에 닿지 않는다.
rule java_version_17_before_intrinsic
{
    meta:
        description = "a JAVA_VERSION on line 17 below the release that first shipped the Base64 intrinsic"
    strings:
        $v = /JAVA_VERSION="17(\.0(\.([0-5])(\.[0-9]+)*)?)?"/
    condition:
        $v
}

// Java SE 8 의 Enterprise Performance Pack(`-perf` 빌드) — Oracle 이 이 CVE 의 영향 판으로 8u511b33-perf 를 적었고 고친 판은
// 8u513-perf 다(Oracle CPU 2026-11 의 Java SE 위험 표 · Genians 2026-11-18). 일반 8 빌드(8u511b33)는 이 CVE 의 줄에 없다 —
// 같은 표에서 다른 CVE 의 줄이다. 그래서 **판 줄의 업데이트 번호가 513 아래이고 어느 판 줄에든 `-perf` 표지가 있을 때**만이다.
rule java_epp_affected
{
    meta:
        description = "a Java SE 8 Enterprise Performance Pack (-perf) build below 8u513-perf"
    strings:
        $v = /JAVA_VERSION="1\.8\.0_([0-9]|[1-9][0-9]|[1-4][0-9][0-9]|50[0-9]|51[0-2])([^0-9"][^"]*)?"/
        $perf = /1\.8\.0_[0-9]+[0-9b-]*perf/
    condition:
        $v and $perf
}

// Oracle GraalVM Enterprise Edition 21.3 — Oracle 이 이 CVE 의 영향 판으로 21.3.20.0.3 을 적었다(Oracle CPU 2026-11 의 Java SE
// 위험 표). 그 줄에는 Java 17 · 11 · 8 판이 있고 바탕 Java 의 판으로는 가를 수 없어(11 · 8 은 OpenJDK 위험 표에 없다) **제품
// 판으로 본다 — 21.3.20.1 미만.** EE 는 Oracle 빌드다(`IMPLEMENTOR="Oracle Corporation"`) — Community 판 · 다른 배포사가 지은
// 것은 바탕 Java 로 판정한다. GraalVM 의 `release` 는 바탕 JDK 줄을 옮기고 `GRAALVM_VERSION` 을 더한다.
rule graalvm_ee_affected
{
    meta:
        description = "an Oracle GraalVM Enterprise Edition 21.3 build below 21.3.20.1"
    strings:
        $g = /GRAALVM_VERSION="21\.3(\.([0-9]|1[0-9])(\.[0-9]+)*|\.20(\.(0)(\.[0-9]+)*)?)?"/
        $o = /IMPLEMENTOR="Oracle Corporation"/
    condition:
        $g and $o
}
