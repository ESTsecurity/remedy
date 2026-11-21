#!/bin/bash
# 룰: java4shell-check-linux — 묶어 낸 출시(ci/batch.sh)가 바뀐 룰의 필수 점검 ① 로 이 하네스를 찾는다(--bin · --plugins · --out)
# 이미지: debian:12 ubuntu:24.04 ubuntu:22.04 rockylinux:9 alpine:3.22 amazonlinux:2023 eclipse-temurin:17-jre eclipse-temurin:21-jre eclipse-temurin:25-jre amazoncorretto:21 amazoncorretto:17 tomcat:9.0-jdk11
# Java4Shell 점검 룰(java4shell-check-linux)을 배포판 · 배포사 이미지에서 잰다.
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/java4shell-verify.sh --bin <remedy> --plugins <java4shell-check-linux 가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--bin` 은 **musl 정적** remedy 다(`musl-dev-build.sh` 또는 내려받아 푼 꾸러미의 것). `--plugins` 는
# `java4shell-check-linux/` 를 담은 폴더다 — 저장소 사본(서명 없음 · 2026-11-21 부터)은 **개발 빌드**로, 배포 꾸러미의
# 사본은 배포 키로 서명돼 있어 **공개한 실행 파일**로 잰다.
#
# 처음 한 번은 배포판 저장소에 닿아야 한다 — Java 를 깐 이미지를 지어 두고(`remedy-harness/java:*`), 다음부터는 그
# 이미지를 쓴다. 배포사 이미지(`eclipse-temurin:*` · `amazoncorretto:*` · `tomcat:*`)는 미리 받아 둔다.
#
# # 무해한가
#
# **실검체가 없다.** 악용하는 것이 아니라 **판을 읽는** 룰이고, 이미지는 배포판 · 배포사가 낸 Java 를 그대로 깐 것이다.
# 손으로 세우는 경우는 **자리 채우기**다 — JDK 홈의 모양(`bin/java` 와 `release`)만 맞춘 폴더이고, `bin/java` 자리에는
# 무해한 `sleep` 을 복사해 둔다(판정에 쓰이는 것은 `release` 의 글자뿐이다). 경우마다 네트워크 없는 일회용 컨테이너에서
# remedy 가 읽기만 한다.
#
# # 무엇을 재나
#
#   A  배포판 · 배포사 이미지 13 — 오늘 저장소에서 깐 판이 고친 판 미만이라 **2**(Debian 12 · Ubuntu 24.04 · 22.04 ·
#      Rocky 9 · Alpine 3.22 · Amazon Linux 2023 의 Corretto · Temurin 17 · 21 · 25 · Corretto 21) · **실제 고친 빌드**
#      (Corretto 17.0.21.1.2 — `JAVA_VERSION="17.0.21.1"`)는 **0** · Java 11 은 **0** · Java 없는 기계 **0**.
#      이 칸의 기대값은 2026-11-18 에 잰 이미지에 맞춘 것이다 — 배포사가 고친 빌드를 내면 그 칸이 실패하고, 그것이
#      룰을 다시 낼 신호다(`RELEASE.md` 의 백포트 줄).
#   S  판 줄만 바꾼 자리 채우기 29 — 고친 판 0(17.0.21.1 · 17.0.21.1.2 · 21.0.13.1 · 27.0.1.1 · 17.0.22) · 고친 판 미만 2 ·
#      ARM64 · ppc64le 0 · 지원이 끝난 줄 2 · 17.0.6 아래 0 · 개발 중인 줄 6 · 판 줄 없음 6 · release 없음 6 ·
#      **아키텍처 줄이 없는 jlink 꼴과 모르는 아키텍처 값은 판으로 판정해 2** · Java 8 · 11 은 0 ·
#      **Java 8 EPP(-perf) 8u511 은 2**(표지가 판 줄에 · 런타임 판 줄에) · EPP 고친 판 8u513-perf 0 · 일반 8u511 0 ·
#      **GraalVM EE 21.3.20 은 바탕 Java 17 · 11 · 8 모두 2**(0.3.0) · EE 21.3.20.1 · Community 는 바탕 Java 로 0 ·
#      판 줄이 없는 ARM64 빌드 0
#   H  사용자마다 까는 자리 · 제품이 받는 자리 7 — SDKMAN(root) · IntelliJ 의 .jdks · asdf · Gradle 툴체인(/home 아래) ·
#      Jenkins 도구(/var/lib/jenkins/tools) · VS Code Java 확장의 JRE(.vscode · .vscode-server — 0.3.0) 에 깐 영향 판 2
#   P  프로세스 · 서비스 4 — 선언한 자리 밖에서 도는 java 6 · 지워진 java 를 실은 채 도는 프로세스 6 ·
#      **/usr/bin/java(대체 링크)로 띄우는 서비스는 자리 밖이 아니다**(0) · 자리 밖 경로의 서비스 6
#   화면 8 — 찾은 줄 아래 CVE 문구 · 두 출처가 갈리는 까닭 · 자리 밖 까닭 · Java 없는 기계에 미해소 경고 0 · EPP 문구 ·
#      사용자 홈의 경로 · GraalVM EE 문구 · EE 에 바탕 Java 의 고칠 판이 서지 않는다
#
# 종료 코드: 0 = 전부 통과 · 1 = 하나라도 실패 · 2 = 인자 · 이미지가 모자라 시작하지 않았다.
set -u
RULE=java4shell-check-linux
BIN=""
PLUGINS=""
OUT=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;;
        --plugins) PLUGINS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done
[ -n "$BIN" ] && [ -f "$BIN" ] || { echo "--bin <remedy> 가 필요하다" >&2; exit 2; }
[ -n "$PLUGINS" ] && [ -d "$PLUGINS/$RULE" ] || { echo "--plugins <$RULE 가 든 폴더> 가 필요하다" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
for base in debian:12 ubuntu:24.04 ubuntu:22.04 rockylinux:9 alpine:3.22 amazonlinux:2023 \
    eclipse-temurin:17-jre eclipse-temurin:21-jre eclipse-temurin:25-jre amazoncorretto:21 amazoncorretto:17 tomcat:9.0-jdk11; do
    docker image inspect "$base" >/dev/null 2>&1 || { echo "$base 이미지가 없다 — docker pull $base" >&2; exit 2; }
done
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/java4shell-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
TAB=$(printf '\t')
: >"$OUT/checks.tsv"

check() { # 이름 · 1|0 · 메모
    if [ "$2" = 1 ]; then printf '  OK   %-58s %s\n' "$1" "$3"
    else printf '  실패 %-58s %s\n' "$1" "$3"; fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/checks.tsv"
}

# ── 이미지 — 배포판의 Java 를 깐다(망이 필요한 것은 여기뿐) ──────────────────────────────────────────
IMG=remedy-harness/java
prepare() { # 꼬리표 · 바탕 이미지 · 설치 명령
    local tag=$1 base=$2 install=$3 name
    docker image inspect "$IMG:$tag" >/dev/null 2>&1 && return 0
    name="remedy-java-prep-$tag"
    docker rm -f "$name" >/dev/null 2>&1
    docker run --name "$name" "$base" sh -c "$install" >"$OUT/prepare-$tag.log" 2>&1 \
        && docker commit "$name" "$IMG:$tag" >/dev/null
    local rc=$?
    docker rm -f "$name" >/dev/null 2>&1
    return $rc
}
DEB='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends'
echo "── 이미지 ──"
# 실제 고친 빌드 — `amazoncorretto:17` 의 지금 판이 그것이다(2026-11-18 실측 Corretto-17.0.21.1.2). 꼬리표를
# 따로 붙여 두면 뒤에 그 이미지가 또 올라가도 이 칸이 가리키는 것이 바뀌지 않는다.
docker image inspect "$IMG:corretto17-fixed" >/dev/null 2>&1 || docker tag amazoncorretto:17 "$IMG:corretto17-fixed"
prepare debian12-jdk17 debian:12 "$DEB openjdk-17-jre-headless >/dev/null && dpkg-query -W openjdk-17-jre-headless" \
    || { echo "debian12-jdk17 이미지를 짓지 못했다" >&2; exit 2; }
prepare ubuntu2404-jdk21 ubuntu:24.04 "$DEB openjdk-21-jre-headless openjdk-17-jre-headless >/dev/null && dpkg-query -W 'openjdk-*-jre-headless'" \
    || { echo "ubuntu2404-jdk21 이미지를 짓지 못했다" >&2; exit 2; }
prepare ubuntu2204-jdk17 ubuntu:22.04 "$DEB openjdk-17-jre-headless >/dev/null && dpkg-query -W openjdk-17-jre-headless" \
    || { echo "ubuntu2204-jdk17 이미지를 짓지 못했다" >&2; exit 2; }
prepare rocky9-jdk rockylinux:9 'dnf -y -q install java-17-openjdk-headless java-21-openjdk-headless >/dev/null && rpm -q java-17-openjdk-headless java-21-openjdk-headless' \
    || { echo "rocky9-jdk 이미지를 짓지 못했다" >&2; exit 2; }
prepare alpine322-jdk21 alpine:3.22 'apk add --no-cache -q openjdk21-jre-headless openjdk17-jre-headless && apk info -v | grep openjdk' \
    || { echo "alpine322-jdk21 이미지를 짓지 못했다" >&2; exit 2; }
prepare al2023-corretto amazonlinux:2023 'dnf -y -q install java-21-amazon-corretto-headless java-17-amazon-corretto-headless >/dev/null && rpm -q java-21-amazon-corretto-headless java-17-amazon-corretto-headless' \
    || { echo "al2023-corretto 이미지를 짓지 못했다" >&2; exit 2; }

# 깐 판을 그 기계에서 읽어 둔다 — 이미지의 판이 영향 판이라는 전제가 깨지면 A 칸의 뜻이 사라진다.
in_image() { docker run --rm --network none --entrypoint sh "$1" -c "$2" 2>/dev/null; }
jv() { in_image "$1" 'for f in /usr/lib/jvm/*/release /opt/java/*/release /usr/local/*/release; do [ -f "$f" ] && sed -n "s/^JAVA_VERSION=//p" "$f"; done | sort -u | tr "\n" " "'; }
for t in debian12-jdk17 ubuntu2404-jdk21 ubuntu2204-jdk17 rocky9-jdk alpine322-jdk21 al2023-corretto; do
    printf '%s' "$(jv "$IMG:$t")" >"$OUT/installed-$t.txt"
done
printf '%s' "$(jv "$IMG:corretto17-fixed")" >"$OUT/installed-corretto17-fixed.txt"
for v in eclipse-temurin:17-jre eclipse-temurin:21-jre eclipse-temurin:25-jre amazoncorretto:21 tomcat:9.0-jdk11; do
    printf '%s' "$(jv "$v")" >"$OUT/installed-$(echo "$v" | tr ':/' '__').txt"
done

# ── 경우 — 네트워크 없는 일회용 컨테이너 ────────────────────────────────────────────────────────────
W=$(mktemp -d /tmp/remedy-java4shell.XXXXXX)
cleanup() { # 컨테이너가 root 로 쓴 결과는 컨테이너로 지운다
    docker run --rm --network none -v "$W:/w" alpine:3.22 rm -rf /w/b /w/cases >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W/b/plugins" "$W/cases"
cp "$BIN" "$W/b/remedy"
cp -r "$PLUGINS/$RULE" "$W/b/plugins/"

# 자리 채우기 JDK 홈을 세우는 스크립트 — `bin/java` 자리에는 sleep 을 복사하고 `release` 는 준 글자를 쓴다.
# 스크립트 파일로 두는 까닭: 준비 셸에 적으면 그 셸(컨테이너의 1번 프로세스)의 명령줄이 프로세스 수집에 기록돼
# 결과 파일에 그 글자가 남는다.
cat >"$W/b/home.sh" <<'HOME'
set -e
dir=$1
shift
mkdir -p "$dir/bin"
cp /bin/sleep "$dir/bin/java"
if [ "$1" = "--no-release" ]; then
    echo "placed $dir (release 없음)"
    exit 0
fi
: >"$dir/release"
for line in "$@"; do
    printf '%s\n' "$line" >>"$dir/release"
done
echo "placed $dir"
HOME

: >"$OUT/cases.tsv"
run_case() { # 이름 · 이미지 · 기대 종료 코드 · 준비 셸 · 메모
    local name=$1 image=$2 want=$3 setup=$4 note=$5 d="$W/cases/$1"
    case "$image" in */*|*:*) ;; *) image="$IMG:$image" ;; esac
    mkdir -p "$d"
    docker run --rm --pull=never --network none -v "$W/b:/b:ro" -v "$d:/o" --entrypoint sh "$image" -c \
        "$setup
         REMEDY_LANG=ko LANG=C.UTF-8 /b/remedy scan --plugin /b/plugins/$RULE/plugin.yaml \
             --out-dir /o/out >/o/screen.txt 2>&1; echo \$? >/o/rc; chmod -R a+rX /o" \
        </dev/null >"$d/setup.log" 2>&1
    local rc
    rc=$(cat "$d/rc" 2>/dev/null)
    printf '%s\t%s\t%s\t%s\n' "$name" "${rc:-?}" "$want" "$note" >>"$OUT/cases.tsv"
    # 결과는 결과 폴더로 옮긴다 — 컨테이너가 root 로 쓴 자리는 끝에서 컨테이너가 지운다.
    mkdir -p "$OUT/cases/$name"
    cp "$d/screen.txt" "$d/rc" "$d/setup.log" "$OUT/cases/$name/" 2>/dev/null
    find "$d/out" -name '*.json' -exec cp {} "$OUT/cases/$name/" \; 2>/dev/null
    check "$name" "$([ "${rc:-?}" = "$want" ] && echo 1 || echo 0)" "종료 ${rc:-?} (기대 $want) · $note"
}

echo "── A. 배포판 · 배포사 이미지 ──"
run_case a01-debian12 debian12-jdk17 2 ":" "Debian 12 openjdk-17 $(cat "$OUT/installed-debian12-jdk17.txt")"
run_case a02-ubuntu2404 ubuntu2404-jdk21 2 ":" "Ubuntu 24.04 openjdk-17 · 21 $(cat "$OUT/installed-ubuntu2404-jdk21.txt")"
run_case a03-ubuntu2204 ubuntu2204-jdk17 2 ":" "Ubuntu 22.04 openjdk-17 $(cat "$OUT/installed-ubuntu2204-jdk17.txt")"
run_case a04-rocky9 rocky9-jdk 2 ":" "Rocky 9 java-17 · 21 $(cat "$OUT/installed-rocky9-jdk.txt")"
run_case a05-alpine322 alpine322-jdk21 2 ":" "Alpine 3.22 openjdk17 · 21 $(cat "$OUT/installed-alpine322-jdk21.txt")"
run_case a06-al2023-corretto al2023-corretto 2 ":" "Amazon Linux 2023 Corretto 17 · 21 $(cat "$OUT/installed-al2023-corretto.txt")"
run_case a07-temurin17 eclipse-temurin:17-jre 2 ":" "Temurin 17 $(cat "$OUT/installed-eclipse-temurin_17-jre.txt")"
run_case a08-temurin21 eclipse-temurin:21-jre 2 ":" "Temurin 21 $(cat "$OUT/installed-eclipse-temurin_21-jre.txt")"
run_case a09-temurin25 eclipse-temurin:25-jre 2 ":" "Temurin 25 $(cat "$OUT/installed-eclipse-temurin_25-jre.txt")"
run_case a10-corretto21 amazoncorretto:21 2 ":" "Corretto 21 이미지 $(cat "$OUT/installed-amazoncorretto_21.txt")"
run_case a11-jdk11 tomcat:9.0-jdk11 0 ":" "Java 11 — 이 CVE 가 걸린 줄이 아니다 $(cat "$OUT/installed-tomcat_9.0-jdk11.txt")"
run_case a12-corretto17-fixed corretto17-fixed 0 ":" "Corretto 17 고친 빌드 $(cat "$OUT/installed-corretto17-fixed.txt")"
run_case a13-no-java debian:12 0 ":" "Java 없는 Debian 12"

echo "── S. 판 줄만 바꾼 자리 채우기 ──"
syn() { # 이름 · 기대 · 메모 · release 줄…
    local name=$1 want=$2 note=$3
    shift 3
    local args=""
    for line in "$@"; do args="$args '$line'"; done
    run_case "$name" debian:12 "$want" "sh /b/home.sh /opt/jdk$args" "$note"
}
syn s01-fix-170211 0 "고친 판 17.0.21.1 (상류 패치 릴리스)" 'JAVA_VERSION="17.0.21.1"' 'OS_ARCH="x86_64"'
syn s02-fix-1702112 0 "고친 판 17.0.21.1.2 (Corretto 꼴)" 'JAVA_VERSION="17.0.21.1.2"' 'OS_ARCH="x86_64"'
syn s03-fix-17022 0 "그 뒤의 판 17.0.22" 'JAVA_VERSION="17.0.22"' 'OS_ARCH="x86_64"'
syn s04-vuln-1702104 2 "고친 판 미만 17.0.21.0.4 (공지의 판 문자열보다 높다)" 'JAVA_VERSION="17.0.21.0.4"' 'OS_ARCH="x86_64"'
syn s05-vuln-2101303 2 "고친 판 미만 21.0.13.0.3" 'JAVA_VERSION="21.0.13.0.3"' 'OS_ARCH="x86_64"'
syn s06-fix-2101131 0 "고친 판 21.0.13.1" 'JAVA_VERSION="21.0.13.1"' 'OS_ARCH="x86_64"'
syn s07-vuln-2701303 2 "고친 판 미만 27.0.1.0.3" 'JAVA_VERSION="27.0.1.0.3"' 'OS_ARCH="x86_64"'
syn s08-fix-27011 0 "고친 판 27.0.1.1" 'JAVA_VERSION="27.0.1.1"' 'OS_ARCH="x86_64"'
syn s09-arm64 0 "영향 판이지만 ARM64 빌드" 'JAVA_VERSION="17.0.21"' 'OS_ARCH="aarch64"'
syn s10-eol-line 2 "지원이 끝난 줄 20.0.2" 'JAVA_VERSION="20.0.2"' 'OS_ARCH="x86_64"'
syn s11-before-intrinsic 0 "17.0.5 — x86-64 Base64 디코드 코드가 들어오기 전" 'JAVA_VERSION="17.0.5"' 'OS_ARCH="x86_64"'
syn s12-future-line 6 "아직 개발 중인 줄 28.0.1" 'JAVA_VERSION="28.0.1"' 'OS_ARCH="x86_64"'
syn s13-no-version 6 "판 줄이 없는 release" 'IMPLEMENTOR="Acme"' 'OS_ARCH="x86_64"'
# 실측한 꼴 — jlink 로 지은 런타임의 release 에는 판과 모듈 두 줄뿐이다(아키텍처 줄이 없다). 판으로 판정한다.
syn s14-no-arch 2 "아키텍처 줄이 없는 release (jlink 꼴) — 판으로 판정" 'JAVA_VERSION="17.0.21"' 'MODULES="java.base java.logging"'
syn s18-unknown-arch 2 "모르는 아키텍처 값 — 빼지 않고 판으로 판정" 'JAVA_VERSION="17.0.21"' 'OS_ARCH="hexagon"'
syn s19-ppc64le 0 "x86-64 가 아닌 빌드(ppc64le)" 'JAVA_VERSION="17.0.21"' 'OS_ARCH="ppc64le"'
syn s15-jdk8 0 "Java 8 — 이 CVE 가 걸린 줄이 아니다" 'JAVA_VERSION="1.8.0_432"' 'OS_ARCH="x86_64"'
syn s16-jdk11 0 "Java 11 — 이 CVE 가 걸린 줄이 아니다" 'JAVA_VERSION="11.0.33.1"' 'OS_ARCH="x86_64"'
run_case s17-no-release debian:12 6 "sh /b/home.sh /opt/jdk --no-release" "release 파일이 없는 JDK 홈"
# Java 8 은 Enterprise Performance Pack(-perf)만 영향 판이다(Oracle CPU 2026-11 의 위험 표 · 0.2.0). 표지가 판 줄에 있든
# 다른 판 줄에 있든 잡고, 고친 판(8u513-perf)과 일반 8 빌드는 0 이다.
syn s20-epp-runtime 2 "Java 8 EPP 8u511-perf — 런타임 판 줄의 -perf" 'JAVA_VERSION="1.8.0_511"' 'JAVA_RUNTIME_VERSION="1.8.0_511-perf-b33"' 'OS_ARCH="amd64"'
syn s21-epp-inline 2 "Java 8 EPP — 판 줄의 -perf" 'JAVA_VERSION="1.8.0_511-perf"' 'OS_ARCH="amd64"'
syn s22-epp-fixed 0 "Java 8 EPP 고친 판 8u513-perf" 'JAVA_VERSION="1.8.0_513-perf"' 'OS_ARCH="amd64"'
syn s23-jdk8-511 0 "일반 Java 8 8u511 — 이 CVE 의 줄이 아니다" 'JAVA_VERSION="1.8.0_511"' 'OS_ARCH="amd64"' 'BUILD_TYPE="commercial"'
# GraalVM EE 21.3 은 제품 판(GRAALVM_VERSION)이 21.3.20.1 미만이면 바탕 Java 와 상관없이 2 다(0.3.0 · 결정 G1). Oracle 빌드가
# 아닌 것(Community)과 고친 판은 바탕 Java 로 — 11 이라 0 이다.
EE='IMPLEMENTOR="Oracle Corporation"'
syn s24-graalvm-ee 2 "GraalVM EE 21.3.20 — 바탕 Java 17.0.21" 'JAVA_VERSION="17.0.21"' "$EE" 'GRAALVM_VERSION="21.3.20"' 'OS_ARCH="x86_64"'
syn s25-graalvm-ee11 2 "GraalVM EE 21.3.20 — 바탕 Java 11 이어도 제품 판으로" 'JAVA_VERSION="11.0.33"' "$EE" 'GRAALVM_VERSION="21.3.20"' 'OS_ARCH="x86_64"'
syn s26-graalvm-ee8 2 "GraalVM EE 21.3.19 — 바탕 Java 8" 'JAVA_VERSION="1.8.0_511"' "$EE" 'GRAALVM_VERSION="21.3.19"' 'OS_ARCH="amd64"'
syn s27-graalvm-ee-fixed 0 "GraalVM EE 21.3.20.1 — 바탕 Java 11 로" 'JAVA_VERSION="11.0.33"' "$EE" 'GRAALVM_VERSION="21.3.20.1"' 'OS_ARCH="x86_64"'
syn s28-graalvm-ce11 0 "GraalVM Community 21.3.20 — 바탕 Java 11 로" 'JAVA_VERSION="11.0.20"' 'IMPLEMENTOR="GraalVM Community"' 'GRAALVM_VERSION="21.3.20"' 'OS_ARCH="x86_64"'
# 판을 못 읽어도 x86-64 가 아니라고 적힌 빌드는 영향이 없다(0.3.0 · 독립 검토).
syn s29-no-version-arm64 0 "판 줄이 없는 ARM64 빌드" 'IMPLEMENTOR="Acme"' 'OS_ARCH="aarch64"'

echo "── H. 사용자마다 까는 자리(0.2.0) ──"
run_case h01-sdkman debian:12 2 \
    "sh /b/home.sh /root/.sdkman/candidates/java/17.0.21-tem 'JAVA_VERSION=\"17.0.21\"' 'OS_ARCH=\"x86_64\"'" \
    "SDKMAN 이 root 에 깐 17.0.21"
run_case h02-jdks debian:12 2 \
    "mkdir -p /home/alice; sh /b/home.sh /home/alice/.jdks/temurin-21.0.13 'JAVA_VERSION=\"21.0.13\"' 'OS_ARCH=\"x86_64\"'" \
    "IntelliJ 가 사용자 홈에 받은 21.0.13"
run_case h03-asdf debian:12 2 \
    "mkdir -p /home/bob; sh /b/home.sh /home/bob/.asdf/installs/java/temurin-25.0.5 'JAVA_VERSION=\"25.0.5\"' 'OS_ARCH=\"x86_64\"'" \
    "asdf 가 사용자 홈에 깐 25.0.5"
run_case h04-jenkins-tools debian:12 2 \
    "sh /b/home.sh /var/lib/jenkins/tools/hudson.model.JDK/jdk17 'JAVA_VERSION=\"17.0.21\"' 'OS_ARCH=\"x86_64\"'" \
    "Jenkins 가 도구로 받은 17.0.21"
run_case h05-gradle debian:12 2 \
    "mkdir -p /home/test; sh /b/home.sh /home/test/.gradle/jdks/eclipse_adoptium-21-amd64-linux 'JAVA_VERSION=\"21.0.13\"' 'OS_ARCH=\"x86_64\"'" \
    "Gradle 툴체인이 사용자 홈에 받은 21.0.13"
# VS Code 의 Java 확장이 담는 JRE — 실물(redhat.java 1.59.2026111308 linux-x64)의 꼴: `jre/25.0.5-linux-x86_64/` 에 `bin/java` 와
# 판 · 모듈 두 줄의 `release`(아키텍처 줄 없음 · 0.3.0). 데스크톱은 `.vscode`, 원격으로 붙은 서버는 `.vscode-server` 다.
run_case h06-vscode debian:12 2 \
    "mkdir -p /home/alice; sh /b/home.sh /home/alice/.vscode/extensions/redhat.java-1.59.2026111308-linux-x64/jre/25.0.5-linux-x86_64 'JAVA_VERSION=\"25.0.5\"' 'MODULES=\"java.base java.logging\"'" \
    "VS Code Java 확장이 담은 JRE 25.0.5"
run_case h07-vscode-server debian:12 2 \
    "mkdir -p /home/bob; sh /b/home.sh /home/bob/.vscode-server/extensions/redhat.java-1.59.2026111308-linux-x64/jre/25.0.5-linux-x86_64 'JAVA_VERSION=\"25.0.5\"' 'MODULES=\"java.base java.logging\"'" \
    "원격 VS Code 서버의 Java 확장이 담은 JRE 25.0.5"

echo "── P. 프로세스 ──"
# 선언한 자리 밖(/srv)에서 도는 java — `bin/java` 자리의 것은 sleep 이다.
run_case p01-outside debian:12 6 \
    "sh /b/home.sh /srv/app/jdk 'JAVA_VERSION=\"17.0.21\"' 'OS_ARCH=\"x86_64\"'; /srv/app/jdk/bin/java 300 & sleep 1" \
    "자리 밖에서 도는 java"
# 올린 뒤 다시 시작하지 않은 꼴 — 띄운 뒤 그 파일을 지우면 커널이 경로에 ' (deleted)' 를 붙인다.
run_case p02-stale debian:12 6 \
    "sh /b/home.sh /opt/jdk 'JAVA_VERSION=\"17.0.22\"' 'OS_ARCH=\"x86_64\"'; cp /opt/jdk/bin/java /opt/jdk/bin/java.old; /opt/jdk/bin/java 300 & sleep 1; rm -f /opt/jdk/bin/java; mv /opt/jdk/bin/java.old /opt/jdk/bin/java" \
    "지워진 java 를 실은 채 도는 프로세스 · 홈의 판은 고친 판"
# 서비스 — 유닛에 적힌 글자 그대로가 경로다. 배포판의 대체 링크(/usr/bin/java)로 띄우는 서비스는 그 링크가 가리키는
# /usr/lib/jvm 의 홈을 이미 보므로 자리 밖이 아니다(0.2.0 — 0.1.0 은 6 이었다). 자리 밖 경로의 서비스는 그대로 6 이다.
unit() { # 유닛 이름 · ExecStart
    printf "mkdir -p /etc/systemd/system/multi-user.target.wants; printf '[Unit]\\\\nDescription=app\\\\n[Service]\\\\nExecStart=%s\\\\n[Install]\\\\nWantedBy=multi-user.target\\\\n' >/etc/systemd/system/%s.service; ln -sf /etc/systemd/system/%s.service /etc/systemd/system/multi-user.target.wants/%s.service" "$2" "$1" "$1" "$1"
}
run_case p03-service-alternatives debian:12 0 \
    "sh /b/home.sh /usr/lib/jvm/jdk-17 'JAVA_VERSION=\"17.0.22\"' 'OS_ARCH=\"x86_64\"'; ln -sf /usr/lib/jvm/jdk-17/bin/java /usr/bin/java; $(unit app '/usr/bin/java -jar /srv/app.jar')" \
    "/usr/bin/java 로 띄우는 서비스 · 홈의 판은 고친 판"
run_case p04-service-outside debian:12 6 \
    "sh /b/home.sh /srv/app/jdk 'JAVA_VERSION=\"17.0.21\"' 'OS_ARCH=\"x86_64\"'; $(unit app '/srv/app/jdk/bin/java -jar /srv/app.jar')" \
    "자리 밖 경로의 java 를 띄우는 서비스"

echo "── 화면 ──"
# 기록이 없으면 `?` 를 낸다 — 경우 이름을 잘못 적으면 "없다" 가 조용히 통과로 읽힌다(첫 회차에 그랬다).
screen_has() { # 경우 · 글자
    [ -f "$OUT/cases/$1/screen.txt" ] || { echo '?'; return; }
    grep -qF "$2" "$OUT/cases/$1/screen.txt" && echo 1 || echo 0
}
# 찾은 줄 **바로 아래 줄**이 그 문구다(코어 1.13.0 의 `label`).
screen_under() { # 경우 · 찾은 줄에 든 글 · 바로 아래 줄에 든 글
    [ -f "$OUT/cases/$1/screen.txt" ] || { echo '?'; return; }
    awk -v a="$2" -v b="$3" 'hit && index($0, b) { ok = 1 } { hit = index($0, a) > 0 } END { exit !ok }' \
        "$OUT/cases/$1/screen.txt" && echo 1 || echo 0
}
check "S1 영향 판 줄 아래에 CVE 문구 (a01)" \
    "$(screen_under a01-debian12 'release' 'CVE-2026-114938 의 영향 판입니다')" "찾은 줄 · 문구"
check "S2 개발 중인 줄의 까닭 (s12)" "$(screen_has s12-future-line '빌드 번호가 아직 공개되지 않아')" "주의 줄"
check "S3 자리 밖의 까닭 (p01)" "$(screen_has p01-outside '밖의 Java')" "주의 줄"
check "S4 Java 없는 기계에 미해소 경고가 없다 (a13)" \
    "$([ "$(screen_has a13-no-java '해소되지 않았습니다')" = 0 ] && echo 1 || echo 0)" "주의 줄 0"
check "S5 EPP 줄 아래에 EPP 문구 (s20)" \
    "$(screen_under s20-epp-runtime 'release' 'Java SE 8 Enterprise Performance Pack')" "찾은 줄 · 문구"
check "S6 사용자 홈의 홈을 찾은 줄 (h02)" "$(screen_has h02-jdks '/home/alice/.jdks/temurin-21.0.13')" "찾은 줄에 그 경로"
check "S7 GraalVM EE 줄 아래에 제품 문구 (s25)" \
    "$(screen_under s25-graalvm-ee11 'release' 'Oracle GraalVM Enterprise Edition 21.3')" "찾은 줄 · 문구"
check "S8 GraalVM EE 에 바탕 Java 의 고칠 판을 적지 않는다 (s24)" \
    "$([ "$(screen_has s24-graalvm-ee '고친 판(17.0.21.1')" = 0 ] && echo 1 || echo 0)" "문구 하나"

# 칸 수까지 본다 — 경우를 짓다 멈추면 남은 경우가 조용히 사라지고 "실패 0" 이 남는다.
EXPECTED=61 # A 13 · S 29 · H 7 · P 4 · 화면 8 (0.3.0 — 0.2.0 은 52 · 0.1.0 은 38)
pass=$(awk -F"$TAB" '$2 == 1' "$OUT/checks.tsv" | wc -l)
fail=$(awk -F"$TAB" '$2 != 1' "$OUT/checks.tsv" | wc -l)
echo
echo "통과 $pass · 실패 $fail  (전체 $((pass + fail)) / 기대 $EXPECTED)" | tee "$OUT/verdict.txt"
[ "$fail" = 0 ] && [ "$((pass + fail))" = "$EXPECTED" ]
