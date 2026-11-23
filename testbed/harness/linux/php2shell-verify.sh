#!/bin/bash
# 룰: php2shell-check-linux — 묶어 낸 출시(ci/batch.sh)가 바뀐 룰의 필수 점검 ① 로 이 하네스를 찾는다(--bin · --plugins · --out)
# 이미지: debian:12 ubuntu:24.04 rockylinux:9 alpine:3.22 php:8.3.35-cli php:8.3.36-cli php:8.3.36-fpm php:8.3.37-cli php:7.4.33-cli php:8.2.35-apache
# rc 묶음: php2shell
# 하네스 표: WSL · docker(경우마다 네트워크 없는 컨테이너) | php2shell 리눅스 점검의 판정 — 배포판 · RPM 공급사 줄의 경계 · 공식 빌드 해시 · 패키지 밖과 자리 밖의 PHP
# PHP2Shell 점검 룰(php2shell-check-linux)을 배포판 · 공식 이미지 컨테이너에서 잰다(2026-11-23 · 0.6.3 — 이 룰의 첫 하네스).
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/php2shell-verify.sh --bin <remedy> --plugins <php2shell-check-linux 가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--bin` 은 **musl 정적** remedy 다(Alpine 에서도 돈다 — 개발 빌드는 `musl-dev-build.sh`). `--plugins` 는
# `php2shell-check-linux/` 를 담은 폴더다(저장소의 `plugins/` 나 내려받아 푼 꾸러미의 `plugins/`). 처음 한 번은 배포판
# 저장소에 닿아야 한다 — PHP 를 깐 이미지 셋과 rpmbuild 를 깐 Rocky 9 를 지어 두고(`remedy-harness/php2shell:*`), 다음부터는
# 그 이미지를 쓴다. 바탕 이미지와 공식 이미지는 머리의 `# 이미지:` 줄대로 미리 받아 둔다(출시 전 필수 점검의 러너가 그 줄대로
# 받는다). 공식 해시 칸(A5~A10 · O)은 amd64 이미지로 잰다 — 룰의 해시 목록이 플랫폼 꼬리표(linux/amd64)로 적혀 있다.
#
# 기대는 remedy 의 종료 코드다 — 0 취약한 곳을 찾지 못함 · 2 취약 · 6 확인 필요(RELEASE.md '결과 읽기'). 기대값은 룰을 돌려
# 얻지 않고 plugin.yaml 의 줄과 RELEASE.md 의 '0 을 내는 갈래' 에서 정했다 — 경우마다 재는 갈래는 파일 끝의 표에 있다.
#
# # 상류를 고정한다
#
# 상류가 고친 판을 내면 '깐 그대로' 칸의 기대가 뒤집힌다 — 러너는 매번 빈 자리라 그날의 상류로 짓는다(2026-11-21 러너에서 PHP
# 11월 하네스가 그렇게 33/37 이었다). 그래서:
#
# - Debian 12 는 snapshot.debian.org 의 2026-11-18 자리에서 짓는다(PHP 11월 하네스와 같은 자리 · 8.2.35-1~deb12u1 — 이 룰의
#   고친 판 그대로라 b01 이 그 줄의 '그 판' 칸이다).
# - RPM 공급사의 줄은 모두 자리 채우기 rpm 이다 — 실제 RHEL · Oracle Linux 저장소의 PHP 는 다음 마이너(el9_9)로 옮겨 가는 날
#   줄 밖(6)이 되어 '고친 판' 칸이 뒤집힌다.
# - 공식 이미지는 판 꼬리표다. 8.3.35 · 8.3.36 · 7.4.33 · 8.2.35 는 다음 판이 나와 더는 다시 지어지지 않는다. **8.3.37 은 지금
#   8.3 의 마지막 판이라 기반 이미지가 바뀔 때마다 다시 지어진다** — 그날 실행 파일 해시가 룰의 목록에서 빠져 A8 · o04 가 함께
#   실패한다(RELEASE.md '공식 이미지의 현재 태그는 다시 지어진다' — 룰의 목록을 더할 신호다). A 칸이 해시를 먼저 재어 이미지
#   탓과 룰 탓을 가른다. 고정하려면 `php:8.3.37-cli@sha256:<잰 digest>` 로 바꾼다(머리의 `# 이미지:` 줄도 함께).
# - Ubuntu 24.04 · Alpine 3.22 는 지금 저장소로 짓는다 — Ubuntu 의 고친 판은 그 계열(8.3.6-0ubuntu0.24.04.*) 안에서만 올라가
#   0 이 뒤집히지 않고(A2 가 계열 꼴과 고친 판 이상을 잰다), Alpine 의 apk 는 늘 줄 밖(6)이다.
#
# # 무해한가
#
# **실검체는 없다.** 이미지는 배포판 저장소의 PHP 와 공식 Docker 이미지를 그대로 쓰고, 공식 이미지의 PHP 는 실행하지 않는다
# (해시를 재거나 직접 빌드 자리로 옮기기만 한다). 그 밖의 경우는 **자리 채우기**다 — dpkg 는 패키지 기록의 판 줄을 바꾸거나 파일
# 없는 칸 하나를 더하거나 기록 파일(`.md5sums`)을 지우고, RPM 은 rpmbuild 로 지은 rpm(이름 · 판 · 공급사 — 파일을 담는 경우도 글자 한 줄)을 넣는다. 직접 빌드는
# 글자 한 줄만 담은 파일이고, 시작 스크립트 · 유닛 · Apache 설정은 그 줄만 담은 파일이다(아무것도 띄우지 않는다). 도는 프로세스가
# 필요한 경우는 `sleep` 을 PHP 이름으로 복사해 띄운다 — 실린 모듈 칸(p04)은 이미지의 glibc `libm.so.6` 을 `libphp8.2.so` 이름으로
# 복사해 `sleep` 사본에 미리 싣고(LD_PRELOAD) 지운다. 경우마다 네트워크 없는 일회용 컨테이너에서 remedy 가 읽기만 한다.
#
# # 무엇을 재나
#
#   A  이미지 10 — Debian 12 스냅숏의 php8.2 가 이 룰의 고친 판 그대로(8.2.35-1~deb12u1) · 메타 php-cli · Ubuntu 24.04 의 php8.3
#      이 그 계열의 고친 판 이상 · Alpine 의 php83 · rpmbuild 이미지에 PHP 패키지 없음 · 공식 이미지 다섯의 PHP 파일이 룰 목록의
#      그 판 해시 · php:8.2.35-apache 의 PHP 파일은 목록에 없다
#   B  실제 설치 12 — Debian 12 고친 판 그대로 b01 0 · 바로 아래 b02 2 · php8.2 를 바꿈 b03 6 · 아래 판 + 바꿈 b04 6 · 상관없는
#      파일을 바꿈 b05 0 · php-fpm8.2 를 바꿈 b06 6 · Ubuntu 24.04 깐 그대로 b07 0 · 그 판 b08 0 · 바로 아래 b09 2 · Alpine php83
#      b10 6 · php8.2-cli 의 .md5sums 를 지움 b11 6 · epoch 가 붙은 판(1:) b12 6
#   D  dpkg 줄 19 — 줄 여덟(Debian 13 · Ubuntu 14.04 · 16.04 · 18.04 · 20.04 ESM · 22.04 · 26.04 · 26.10)마다 고친 판 바로 아래 2 ·
#      그 판 0(d01~d16) · 지원 끝난 Debian 11 꼴 d17 6 · 다른 저장소(Sury 꼴) d18 6 · 메타 패키지만 d19 0
#   R  RPM 줄 21 — 공급사 줄 일곱(RHEL 8.10 php:7.4 · php:8.2 · RHEL 9.8 · RHEL 7.9 · Oracle Linux 8.10 php:7.4 · 9.8 · SLES 15
#      SP7)마다 바로 아래 2 · 그 판 0(RHEL 7.9 의 그 판은 6 — r01~r14) · 같은 판 문자열의 Rocky r15 6 · Remi r16 6 · RHEL 의
#      이전 마이너 r17 · 다른 모듈 스트림 r18 · SCL r19 6 · Oracle Linux 의 php:8.2 r20 6 · SUSE SP6 r21 6
#   F  RPM 자리의 파일 9 — 고친 RHEL 9 php-cli 가 깐 /usr/bin/php f01 0 · 그 파일을 바꿈 f02 6 · 소유 없는 /usr/bin/php-cgi f03 6
#      · 소유 없는 /usr/sbin/php-fpm f04 6 · 합친 bin 의 메아리 꼴 f05 0 · PHP 가 아닌 이름의 패키지가 깐 /usr/bin/php f06 6 ·
#      /usr/bin/php-fpm f07 6 · 소유 없는 /usr/bin/php-fpm(갈린 sbin) f08 6 · 옛 꼴 기록의 메아리(f05 의 거꾸로) f09 0
#   O  공식 빌드 8 — 8.3.35 o01 2 · 8.3.36 cli o02 0 · fpm o03 0 · 8.3.37 o04 0 · 7.4.33(지원 끝) o05 2 · 8.2.35-apache(목록 밖)
#      o06 6 · 8.3.36 을 /opt/php/8.3 으로 옮김 o07 0 · 8.3.35 를 /usr/local/php 로 옮김 o08 2
#   X  직접 빌드 9 — 공식 해시에 없는 /usr/local/bin/php x01 · /usr/local/php/bin/php x02 · /opt/php/8.3/sbin/php-fpm x03 ·
#      /usr/local/lib/libphp.so x04 · /usr/lib/apache2/modules/libphp.so x05 · 판 붙은 이름 /usr/local/bin/php8.3 x06 · 어느
#      패키지도 깔지 않은 /usr/bin/php8.3 x07 · 점 없는 판 이름 /usr/local/bin/php83 x08 · 어느 패키지도 깔지 않은 Apache 모듈
#      /usr/lib/apache2/modules/libphp7.so x09 모두 6
#   M  섞임 3 — 취약 패키지 + 모르는 빌드 m01 2(취약이 앞선다) · 고친 패키지 + 모르는 빌드 m02 6 · 고친 공식 빌드 + 모르는 빌드
#      m03 6
#   P  프로세스 · 서비스 10 — 자리 밖에서 도는 php-fpm8.3 p01 6 · lsphp p02 6 · 지워진 실행 파일 p03 6 · 지워진 libphp8.2.so 를
#      실은 프로세스 p04 6 · systemd 유닛 자리 밖 p05 6 · 배포판 자리 p06 0 · /opt/php p07 0 · SysV p08 6 · Upstart p09 6 ·
#      OpenRC p10 6
#   C  Apache 설정 8 — Debian mods-available 의 /opt/php83 c01 6 · 배포판 모듈 c02 0 · /usr/local/apache2 c03 6 · XAMPP c04 6 ·
#      RPM 자리의 php_zts_module c05 6 · RHEL 8 의 modules/ 상대 경로 c06 0 · SUSE 모듈 자리 c07 0 · /opt/php c08 0
#   N  PHP 없음 3 — Debian · Alpine · Rocky 0
#   S  화면 6 — 확인 필요 까닭(해시 · 바뀐 실행 파일 · 다시 시작 안 함) · 까닭(RHEL 7 · RPM 자리의 소유 · 기준 없는 패키지) ·
#      항목 줄(유닛 · 설정 줄) · 취약이 나온 회차에 확인 필요 까닭 없음 · 미해소 경고 0 · 내부 낱말(판 · 갈래) 0
#
# 준비 셸이 실패하면(판 줄 · 기록 칸 · rpm 을 넣지 못함, 띄운 프로세스가 보이지 않음 등) 그 경우의 종료 코드를 97 로 적는다 —
# 기대와 달라 실패로 센다. 준비 셸은 바꾼 뒤 그것이 실제로 읽히는지 확인한다(sed 는 맞는 줄이 없어도 0 이다).
#
# # 종료 코드
#
# 0 모든 칸 통과 · 1 실패 칸이 있거나 칸 수가 기대(EXPECTED)와 다르다 · 2 인자 · 바탕 이미지가 없다 · 9 하네스 이미지를 짓지
# 못했다.
set -u

BIN=""
PLUGINS=""
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --plugins) PLUGINS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

RULE=php2shell-check-linux
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일 · musl 정적> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/$RULE/plugin.yaml" ] || { echo "--plugins 에 $RULE 이 없다: $PLUGINS" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
for base in debian:12 ubuntu:24.04 rockylinux:9 alpine:3.22 php:8.3.35-cli php:8.3.36-cli php:8.3.36-fpm php:8.3.37-cli \
    php:7.4.33-cli php:8.2.35-apache; do
    docker image inspect "$base" >/dev/null 2>&1 || { echo "$base 이미지가 없다 — docker pull $base" >&2; exit 2; }
done
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/php2shell-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
: >"$OUT/checks.tsv"
TAB=$(printf '\t')
YAML="$PLUGINS/$RULE/plugin.yaml"

check() { # 이름 · 1|0 · 메모
    if [ "$2" = 1 ]; then printf '  OK   %-58s %s\n' "$1" "$3"
    else printf '  실패 %-58s %s\n' "$1" "$3"; fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/checks.tsv"
}

# ── 이미지 — 배포판의 PHP 와 rpmbuild 를 깐다(망이 필요한 것은 여기뿐) ──────────────────────────────────
IMG=remedy-harness/php2shell
prepare() { # 꼬리표 · 바탕 이미지 · 설치 명령
    local tag=$1 base=$2 install=$3 name
    docker image inspect "$IMG:$tag" >/dev/null 2>&1 && return 0
    name="remedy-php2shell-prep-$tag"
    docker rm -f "$name" >/dev/null 2>&1
    docker run --name "$name" "$base" sh -c "$install" >"$OUT/prepare-$tag.log" 2>&1 \
        && docker commit "$name" "$IMG:$tag" >/dev/null
    local rc=$?
    docker rm -f "$name" >/dev/null 2>&1
    return $rc
}
DEB='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends'
# Debian 12 는 PHP 11월 보안 업데이트가 나오기 전 날짜의 스냅숏에서 — 꼬리표에 날짜를 넣어 지금 저장소로 지은 이미지와 섞이지
# 않게 한다. 메타 패키지(php-cli · php-fpm — 원본 php-defaults)로 깐다 — 관리자가 흔히 까는 꼴이다.
SNAP=20261118T000000Z
DEB12=debian12-snap${SNAP%%T*}
DEB_SNAP="rm -f /etc/apt/sources.list.d/debian.sources && printf '%s\n' \
'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAP bookworm main' \
'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAP bookworm-updates main' \
'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/$SNAP bookworm-security main' \
>/etc/apt/sources.list && apt-get update -qq -o Acquire::Retries=3 \
&& DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends"
echo "── 이미지 ──"
prepare "$DEB12" debian:12 "$DEB_SNAP php-cli php-fpm >/dev/null && dpkg-query -W php-cli php8.2-cli php8.2-fpm" \
    || { echo "$DEB12 이미지를 짓지 못했다(snapshot.debian.org)" >&2; exit 9; }
prepare ubuntu2404 ubuntu:24.04 "$DEB php-cli >/dev/null && dpkg-query -W php-cli php8.3-cli" \
    || { echo "ubuntu2404 이미지를 짓지 못했다" >&2; exit 9; }
prepare alpine322 alpine:3.22 'apk add --no-cache -q php83 && apk info -v php83' \
    || { echo "alpine322 이미지를 짓지 못했다" >&2; exit 9; }
# RPM 공급사의 판을 자리 채우기 rpm 으로 넣을 rpmbuild — PHP 는 깔지 않는다(R · F 칸이 그 위에 공급사마다 넣는다).
prepare rocky9-rpmbuild rockylinux:9 'dnf -y -q install rpm-build >/dev/null && rpm -q rpm-build' \
    || { echo "rocky9-rpmbuild 이미지를 짓지 못했다" >&2; exit 9; }

# ── A. 이미지 — 깐 판 · 공식 해시가 이 하네스가 뜻하는 그것인가 ──────────────────────────────────────────
echo "── A. 이미지 ──"
in_image() { docker run --rm --pull=never --network none "$IMG:$1" sh -c "$2" 2>/dev/null; }
v=$(in_image "$DEB12" "dpkg-query -W -f='\${Version}' php8.2-cli"); printf '%s' "$v" >"$OUT/installed-debian12.txt"
s=$(in_image "$DEB12" "dpkg-query -W -f='\${source:Package}' php-cli")
[ "$v" = 8.2.35-1~deb12u1 ] && [ "$s" = php-defaults ] && a=1 || a=0
check "A1 Debian 12 의 php8.2-cli 가 고친 판 그대로 · 메타 php-cli" "$a" "${v:-없음} · php-cli 의 원본 ${s:-없음} · 스냅숏 $SNAP"
v=$(in_image ubuntu2404 "dpkg-query -W -f='\${Version}' php8.3-cli"); printf '%s' "$v" >"$OUT/installed-ubuntu2404.txt"
a=0
if printf '%s' "$v" | grep -Eq '^8\.3\.6-0ubuntu0\.24\.04(\.[0-9]+)?$' \
    && in_image ubuntu2404 "dpkg --compare-versions '$v' ge '8.3.6-0ubuntu0.24.04.13'"; then a=1; fi
check "A2 Ubuntu 24.04 의 php8.3-cli 가 그 계열의 고친 판 이상" "$a" "${v:-없음} ≥ 8.3.6-0ubuntu0.24.04.13"
v=$(in_image alpine322 "sed -n '/^P:php83\$/,/^\$/ s/^V://p' /lib/apk/db/installed"); printf '%s' "$v" >"$OUT/installed-alpine322.txt"
[ -n "$v" ] && a=1 || a=0
check "A3 Alpine 3.22 에 php83 이 있다" "$a" "${v:-없음}"
v=$(in_image rocky9-rpmbuild "command -v rpmbuild >/dev/null && rpm -qa --qf '%{NAME}\n' | grep -c '^php'")
[ "$v" = 0 ] && a=1 || a=0
check "A4 rocky9-rpmbuild 에 rpmbuild 가 있고 PHP 패키지는 없다" "$a" "PHP 이름의 rpm ${v:-?}개"

# 공식 이미지의 PHP 파일(룰의 자리) — 'sha256 경로' 줄. 실행하지 않고 해시만 잰다.
: >"$OUT/official-sums.tsv"
official_sums() { # 이미지
    docker run --rm --pull=never --network none --entrypoint sh "$1" -c \
        'for f in /usr/local/bin/php /usr/local/bin/php-cgi /usr/local/sbin/php-fpm /usr/local/lib/libphp*.so /usr/lib/apache2/modules/libphp*.so; do [ -f "$f" ] && sha256sum "$f"; done; true' \
        2>/dev/null
}
a_official() { # 칸 이름 · 이미지 · 룰 목록의 꼬리표('8.3.36 linux/amd64 cli') 또는 -(목록에 없어야 한다)
    local name=$1 image=$2 label=$3 h p n=0 ok=0
    while read -r h p; do
        [ -n "$h" ] || continue
        n=$((n + 1))
        printf '%s\t%s\t%s\n' "$image" "$p" "$h" >>"$OUT/official-sums.tsv"
        if [ "$label" = - ]; then
            grep -q "\"$h\"" "$YAML" || ok=$((ok + 1))
        else
            grep -Eq "\"$h\" +# $label " "$YAML" && ok=$((ok + 1))
        fi
    done < <(official_sums "$image")
    check "$name" "$([ "$n" -gt 0 ] && [ "$ok" = "$n" ] && echo 1 || echo 0)" "$image · 룰 자리의 PHP 파일 $n · 맞음 $ok"
}
a_official "A5 php:8.3.35-cli 의 PHP 가 룰 목록의 8.3.35 해시" php:8.3.35-cli '8.3.35 linux/amd64 cli'
a_official "A6 php:8.3.36-cli 의 PHP 가 룰 목록의 8.3.36 해시" php:8.3.36-cli '8.3.36 linux/amd64 cli'
a_official "A7 php:8.3.36-fpm 의 PHP 가 룰 목록의 8.3.36 해시" php:8.3.36-fpm '8.3.36 linux/amd64 fpm'
a_official "A8 php:8.3.37-cli 의 PHP 가 룰 목록의 8.3.37 해시" php:8.3.37-cli '8.3.37 linux/amd64 cli'
a_official "A9 php:7.4.33-cli 의 PHP 가 룰 목록의 7.4.33 해시" php:7.4.33-cli '7.4.33 linux/amd64 cli'
a_official "A10 php:8.2.35-apache 의 PHP 가 룰 목록에 없다" php:8.2.35-apache -

# ── 경우 — 네트워크 없는 일회용 컨테이너 · 판 줄 · 기록 칸 · 파일만 바꾼다 ─────────────────────────────────
W=$(mktemp -d /tmp/remedy-php2shell-verify.XXXXXX)
cleanup() { # 컨테이너가 root 로 쓴 결과는 컨테이너로 지운다
    docker run --rm -v "$W:/w" alpine:3.22 rm -rf /w/b /w/res >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W/b/plugins" "$W/b/fx" "$W/res"
cp "$BIN" "$W/b/remedy"
cp -r "$PLUGINS/$RULE" "$W/b/plugins/"

# dpkg 패키지 기록에 칸 하나(이름 · 원본 · 판)를 더한다 — 파일은 깔지 않는다. 기록은 빈 줄로 칸을 가른다. 더한 뒤 그 판이 읽히는지 본다.
cat >"$W/b/deb-add.sh" <<'DEB'
set -e
{
    echo "Package: $1"
    echo "Status: install ok installed"
    echo "Priority: optional"
    echo "Section: php"
    echo "Maintainer: placeholder"
    echo "Architecture: amd64"
    echo "Source: $2"
    echo "Version: $3"
    echo "Description: placeholder"
    echo
} >>/var/lib/dpkg/status
[ "$(dpkg-query -W -f='${Version}' "$1")" = "$3" ]
DEB
# 자리 채우기 rpm 을 지어 넣는다 — `sh /b/rpm-put.sh <이름> <판> <릴리스> <공급사> [담을 파일 …]`. 담을 파일은 글자 한 줄이고,
# 파일이 없으면 이름 · 판 · 공급사만 있는 빈 rpm 이다. 넣은 뒤 공급사 · 판과 파일의 소유가 읽히는지 본다.
cat >"$W/b/rpm-put.sh" <<'RPM'
set -e
name=$1
ver=$2
rel=$3
vendor=$4
shift 4
top=/tmp/rb-$name
rm -rf "$top"
mkdir -p "$top/SPECS"
{
    echo "Name: $name"
    echo "Version: $ver"
    echo "Release: $rel"
    echo "Summary: placeholder"
    echo "License: MIT"
    echo "Vendor: $vendor"
    echo "BuildArch: noarch"
    echo "%description"
    echo "placeholder"
    echo "%install"
    for f in "$@"; do
        echo "mkdir -p %{buildroot}$(dirname "$f")"
        echo "echo remedy-harness placeholder >%{buildroot}$f"
    done
    echo "%files"
    for f in "$@"; do
        echo "$f"
    done
} >"$top/SPECS/p.spec"
rpmbuild -bb --define "_topdir $top" "$top/SPECS/p.spec" >"$top/build.log" 2>&1 || { cat "$top/build.log"; exit 1; }
rpm -i --nodeps "$top"/RPMS/noarch/"$name"-"$ver"-*.noarch.rpm
[ "$(rpm -q --qf '%{VENDOR}|%{VERSION}-%{RELEASE}' "$name")" = "$vendor|$ver-$rel" ]
for f in "$@"; do
    [ "$(rpm -qf --qf '%{NAME}' "$f")" = "$name" ]
done
RPM

# 시작 스크립트 · 유닛 · Apache 설정 — 그 줄만 담은 파일(작은따옴표라 `$` 는 글자 그대로다). 준비 셸이 제자리에 복사한다.
FX="$W/b/fx"
unit() { printf '%s\n' '[Unit]' 'Description=lab' '[Service]' "ExecStart=$1" '[Install]' 'WantedBy=multi-user.target'; }
unit '/opt/php83/sbin/php-fpm --nodaemonize --fpm-config /opt/php83/etc/php-fpm.conf' >"$FX/php83-fpm.service"
unit '/usr/sbin/php-fpm8.2 --nodaemonize --fpm-config /etc/php/8.2/fpm/php-fpm.conf' >"$FX/php8.2-fpm.service"
unit '/opt/php/sbin/php-fpm --nodaemonize' >"$FX/php-fpm.service"
# SysV — PHP 가 내는 php-fpm 스크립트의 꼴(`php_fpm_BIN` · 접두사 /opt/php83).
printf '%s\n' '#!/bin/sh' 'prefix=/opt/php83' 'exec_prefix=${prefix}' 'php_fpm_BIN=${exec_prefix}/sbin/php-fpm' \
    'php_opts="--fpm-config /opt/php83/etc/php-fpm.conf"' 'case "$1" in' '  start) $php_fpm_BIN --daemonize $php_opts ;;' 'esac' \
    >"$FX/php83-fpm.init"
printf '%s\n' 'description "worker"' 'start on runlevel [2345]' 'respawn' \
    'exec /srv/php/bin/php /srv/worker.php >> /var/log/worker.log 2>&1' >"$FX/worker.conf"
printf '%s\n' '#!/sbin/openrc-run' 'command=/srv/php/sbin/php-fpm' 'command_args="--nodaemonize"' 'command_background=true' \
    >"$FX/php-app.openrc"
printf '%s\n' 'LoadModule php_module /opt/php83/lib/libphp.so' >"$FX/php83.load"
printf '%s\n' 'LoadModule php_module /usr/lib/apache2/modules/libphp8.2.so' >"$FX/php8.2.load"
printf '%s\n' 'LoadModule php_module /opt/php/lib/libphp.so' >"$FX/php-optphp.load"
printf '%s\n' 'ServerRoot "/usr/local/apache2"' 'LoadModule php_module modules/libphp.so' >"$FX/httpd-own.conf"
printf '%s\n' 'ServerRoot "/opt/lampp"' 'LoadModule php_module modules/libphp.so' >"$FX/httpd-lampp.conf"
printf '%s\n' '<IfModule !prefork.c>' '  LoadModule php_zts_module /opt/php83/modules/libphp-zts.so' '</IfModule>' >"$FX/20-php.conf"
printf '%s\n' '#' '# PHP is an HTML-embedded scripting language' '#' '<IfModule !mod_php5.c>' '  <IfModule prefork.c>' \
    '    LoadModule php7_module modules/libphp7.so' '  </IfModule>' '</IfModule>' >"$FX/15-php.conf"
printf '%s\n' 'ServerRoot "/etc/httpd"' 'Include conf.modules.d/*.conf' >"$FX/httpd-rpm.conf"
printf '%s\n' 'LoadModule php8_module /usr/lib64/apache2/mod_php8.so' >"$FX/loadmodule-suse.conf"

: >"$OUT/cases.tsv"
run_case() { # 이름 · 이미지 꼬리표 또는 바탕 이미지 · 기대 종료 코드 · 준비 셸 · 메모
    local name=$1 image=$2 want=$3 setup=$4 note=$5 d="$W/res/$1"
    case "$image" in */*|*:*) ;; *) image="$IMG:$image" ;; esac
    mkdir -p "$d"
    docker run --rm --pull=never --network none --cap-add SYS_PTRACE -v "$W/b:/b:ro" -v "$d:/o" "$image" sh -c \
        "{ $setup
         } || { echo 97 >/o/rc; chmod -R a+rX /o; exit 0; }
         REMEDY_LANG=ko LANG=C.UTF-8 /b/remedy scan --plugin /b/plugins/$RULE/plugin.yaml \
             --out-dir /o/out >/o/screen.txt 2>&1; echo \$? >/o/rc; chmod -R a+rX /o" </dev/null >"$d/setup.log" 2>&1
    local rc
    rc=$(cat "$d/rc" 2>/dev/null || echo 99)
    printf '%s\t%s\t%s\t%s\n' "$name" "$want" "$rc" "$note" >>"$OUT/cases.tsv"
    check "$name" "$([ "$rc" = "$want" ] && echo 1 || echo 0)" "기대 $want · 종료 $rc · $note"
    mkdir -p "$OUT/cases/$name"
    cp "$d/screen.txt" "$d/rc" "$d/setup.log" "$OUT/cases/$name/" 2>/dev/null
    find "$d/out" -name '*.json' -exec cp {} "$OUT/cases/$name/" \; 2>/dev/null
}

# 패키지 기록의 판 줄을 바꾸는 셸 한 줄 — 그 갈래의 런타임 패키지 칸 모두에서. 바꾼 뒤 그 판이 읽히는지 본다.
deb_set() { # 갈래(8.2) · 판
    printf "sed -i -E '/^Package: php%s-(cli|cgi|fpm)\$/,/^\$/ s/^Version: .*/Version: %s/' /var/lib/dpkg/status && [ \"\$(dpkg-query -W -f='\${Version}' php%s-cli)\" = '%s' ]" "$1" "$2" "$1" "$2"
}
# 패키지가 깐 파일을 다른 글자로 바꾼다 — 패키지 기록(dpkg .md5sums · RPM 헤더의 다이제스트)과 달라진다.
changed() { printf "[ -f %s ] && echo remedy-harness-changed >%s && grep -q remedy-harness-changed %s" "$1" "$1" "$1"; }
# 직접 빌드 자리 채우기 — 글자 한 줄만 담은 파일(실행 파일이 아니다 · 공식 해시 목록에 없다).
bin_put() { printf "mkdir -p %s && echo remedy-harness-placeholder >%s && [ -s %s ]" "$(dirname "$1")" "$1" "$1"; }
# 공식 이미지의 PHP 셋(php · php-cgi · libphp.so)을 직접 빌드 자리로 옮긴다(실행하지 않는다).
php_move() { # 접두사
    printf "mkdir -p %s/bin %s/lib && mv /usr/local/bin/php /usr/local/bin/php-cgi %s/bin/ && mv /usr/local/lib/libphp.so %s/lib/ && [ -f %s/bin/php ] && [ ! -e /usr/local/bin/php ]" \
        "$1" "$1" "$1" "$1" "$1"
}
deb_case() { run_case "$1" debian:12 "$2" "sh /b/deb-add.sh $3" "$4"; } # 이름 · 기대 · 'deb-add 인자(이름 원본 판)' · 메모
rpm_case() { run_case "$1" rocky9-rpmbuild "$2" "sh /b/rpm-put.sh $3" "$4"; } # 이름 · 기대 · 'rpm-put 인자' · 메모
RH="'Red Hat, Inc.'"
OL="'Oracle America'"
SUSE="'SUSE LLC <https://www.suse.com/>'"
ROCKY="'Rocky Enterprise Software Foundation'"
REMI="\"Remi's RPM repository <https://rpms.remirepo.net/>\""

echo "── B. 실제 설치 ──"
run_case b01-deb12-fixed "$DEB12" 0 ":" "Debian 12 php-cli · php-fpm(스냅숏 8.2.35-1~deb12u1 — 고친 판 그대로 · 메타 패키지 둘)"
run_case b02-deb12-below "$DEB12" 2 "$(deb_set 8.2 8.2.34-1~deb12u1)" "판 줄 8.2.34-1~deb12u1 — 고친 판 바로 아래"
run_case b03-deb12-changed-cli "$DEB12" 6 "$(changed /usr/bin/php8.2)" "고친 판 · /usr/bin/php8.2 를 바꿈(패키지 기록과 다르다)"
run_case b04-deb12-below-changed "$DEB12" 6 "$(deb_set 8.2 8.2.34-1~deb12u1) && $(changed /usr/bin/php8.2)" \
    "고친 판 아래 + 실행 파일을 바꿈 — 그 패키지 판으로 판정하지 않는다"
run_case b05-deb12-other-file "$DEB12" 0 "$(changed /usr/bin/xargs)" "PHP 와 상관없는 /usr/bin/xargs 를 바꿈 — PHP 실행 파일 자리만 본다"
run_case b06-deb12-changed-fpm "$DEB12" 6 "$(changed /usr/sbin/php-fpm8.2)" "고친 판 · /usr/sbin/php-fpm8.2 를 바꿈"
run_case b07-u2404-fixed ubuntu2404 0 ":" "Ubuntu 24.04 php-cli 깐 그대로(고친 판 이상 — A2)"
run_case b08-u2404-at ubuntu2404 0 "$(deb_set 8.3 8.3.6-0ubuntu0.24.04.13)" "판 줄 8.3.6-0ubuntu0.24.04.13 — 고친 판 그대로"
run_case b09-u2404-below ubuntu2404 2 "$(deb_set 8.3 8.3.6-0ubuntu0.24.04.12)" "판 줄 8.3.6-0ubuntu0.24.04.12 — 고친 판 바로 아래"
run_case b10-alpine-php83 alpine322 6 ":" "Alpine 3.22 php83 — apk 는 공급사 줄 밖"
run_case b11-deb12-no-md5sums "$DEB12" 6 \
    "rm -f /var/lib/dpkg/info/php8.2-cli.md5sums /var/lib/dpkg/info/php8.2-cli:*.md5sums && ! ls /var/lib/dpkg/info/php8.2-cli*.md5sums >/dev/null 2>&1" \
    "고친 판(8.2.35-1~deb12u1) · php8.2-cli 의 .md5sums 를 지움 — /usr/bin/php8.2 가 패키지 기록에 없다(0.6.5)"
run_case b12-deb12-epoch "$DEB12" 6 "$(deb_set 8.2 1:8.2.35-1~deb12u1)" \
    "판 줄 1:8.2.35-1~deb12u1 — epoch 가 붙은 판은 공급사 기준 밖(PHP 11월 · 세션 점검과 맞춘 지키는 칸)"

echo "── D. dpkg 줄 — 파일 없는 기록 칸 ──"
deb_case d01-deb13-below 2 "php8.4-fpm php8.4 8.4.26-1~deb13u1" "Debian 13 php8.4-fpm — 고친 판(8.4.27-1~deb13u1) 바로 아래"
deb_case d02-deb13-at 0 "php8.4-fpm php8.4 8.4.27-1~deb13u1" "Debian 13 — 고친 판 그대로"
deb_case d03-u1404-below 2 "php5-cli php5 5.5.9+dfsg-1ubuntu4.29+esm17" "Ubuntu 14.04 ESM php5-cli — +esm18 바로 아래"
deb_case d04-u1404-at 0 "php5-cli php5 5.5.9+dfsg-1ubuntu4.29+esm18" "Ubuntu 14.04 ESM — 고친 판 그대로"
deb_case d05-u1604-below 2 "php7.0-cli php7.0 7.0.33-0ubuntu0.16.04.16+esm21" "Ubuntu 16.04 ESM php7.0-cli — +esm22 바로 아래"
deb_case d06-u1604-at 0 "php7.0-cli php7.0 7.0.33-0ubuntu0.16.04.16+esm22" "Ubuntu 16.04 ESM — 고친 판 그대로"
deb_case d07-u1804-below 2 "php7.2-fpm php7.2 7.2.24-0ubuntu0.18.04.17+esm13" "Ubuntu 18.04 ESM php7.2-fpm — +esm14 바로 아래"
deb_case d08-u1804-at 0 "php7.2-fpm php7.2 7.2.24-0ubuntu0.18.04.17+esm14" "Ubuntu 18.04 ESM — 고친 판 그대로"
deb_case d09-u2004-below 2 "php7.4-cgi php7.4 7.4.3-4ubuntu2.29+esm4" "Ubuntu 20.04 ESM php7.4-cgi — +esm5 바로 아래"
deb_case d10-u2004-at 0 "php7.4-cgi php7.4 7.4.3-4ubuntu2.29+esm5" "Ubuntu 20.04 ESM — 고친 판 그대로"
deb_case d11-u2204-below 2 "libapache2-mod-php8.1 php8.1 8.1.2-1ubuntu2.27" "Ubuntu 22.04 Apache 모듈 — 2.28 바로 아래"
deb_case d12-u2204-at 0 "libapache2-mod-php8.1 php8.1 8.1.2-1ubuntu2.28" "Ubuntu 22.04 — 고친 판 그대로"
deb_case d13-u2604-below 2 "php8.5-cli php8.5 8.5.4-0ubuntu1.4" "Ubuntu 26.04 php8.5-cli — 1.5 바로 아래"
deb_case d14-u2604-at 0 "php8.5-cli php8.5 8.5.4-0ubuntu1.5" "Ubuntu 26.04 — 고친 판 그대로"
deb_case d15-u2610-below 2 "php8.5-cgi php8.5 8.5.9-0ubuntu2" "Ubuntu 26.10 php8.5-cgi — 출시 판(2.1 바로 아래)"
deb_case d16-u2610-at 0 "php8.5-cgi php8.5 8.5.9-0ubuntu2.1" "Ubuntu 26.10 — 고친 판 그대로"
deb_case d17-deb11-like 6 "php7.4-cli php7.4 7.4.33-1+deb11u8" "지원 끝난 Debian 11 꼴 — 공급사 줄 밖"
deb_case d18-other-repo 6 "php8.3-cli php8.3 8.3.37-1+0~20261120.1+debian12~1.gbp1a2b3c" "다른 저장소(Sury 꼴) — 판이 높아도 기준 없음"
deb_case d19-meta-only 0 "php-cli 'php-defaults (93)' 2:8.2+93" "메타 패키지만(php-defaults) — 세지 않는다"

echo "── R. RPM 줄 — 빈 rpm(이름 · 판 · 공급사) ──"
rpm_case r01-rhel8-74-below 2 "php-cli 7.4.33 7.module+el8.10.0+25000+1a2b3c4d $RH" "RHEL 8.10 php:7.4 의 7.4.33-7 — 고친 판(-8) 바로 아래"
rpm_case r02-rhel8-74-at 0 "php-cli 7.4.33 8.module+el8.10.0+25117+30337cca $RH" "RHEL 8.10 php:7.4 — 고친 판 그대로(RHSA-2026:87080)"
rpm_case r03-rhel8-82-below 2 "php-fpm 8.2.34 1.module+el8.10.0+24900+5e6f7a8b $RH" "RHEL 8.10 php:8.2 의 8.2.34 — 고친 판 아래"
rpm_case r04-rhel8-82-at 0 "php-fpm 8.2.35 1.module+el8.10.0+25110+f67151d2 $RH" "RHEL 8.10 php:8.2 — 고친 판 그대로(RHSA-2026:87073)"
rpm_case r05-rhel9-below 2 "php 8.0.30 8.el9_8 $RH" "RHEL 9.8 php 8.0.30-8.el9_8 — 고친 판(.el9_8.1) 바로 아래"
rpm_case r06-rhel9-at 0 "php 8.0.30 8.el9_8.1 $RH" "RHEL 9.8 — 고친 판 그대로(RHSA-2026:87151)"
rpm_case r07-rhel7-below 2 "php-cli 5.4.16 48.el7_9 $RH" "RHEL 7.9 의 5.4.16-48.el7_9 — 고친 판(.el7_9.1) 바로 아래"
rpm_case r08-rhel7-at 6 "php-cli 5.4.16 48.el7_9.1 $RH" "RHEL 7.9 고친 판 그대로 — 공지가 109619 만 고쳐 확인 필요"
rpm_case r09-ol8-74-below 2 "php-fpm 7.4.33 7.module+el8.10.0+91000+0a1b2c3d $OL" "Oracle Linux 8.10 php:7.4 의 7.4.33-7"
rpm_case r10-ol8-74-at 0 "php-fpm 7.4.33 8.module+el8.10.0+91080+9785160d $OL" "Oracle Linux 8.10 php:7.4 — 고친 판 그대로(ELSA-2026-87080)"
rpm_case r11-ol9-below 2 "php-cli 8.0.30 8.el9_8 $OL" "Oracle Linux 9.8 의 8.0.30-8.el9_8"
rpm_case r12-ol9-at 0 "php-cli 8.0.30 8.el9_8.1 $OL" "Oracle Linux 9.8 — 고친 판 그대로(ELSA-2026-87151)"
rpm_case r13-sles157-below 2 "php8 8.3.36 150700.3.23.1 $SUSE" "SLES 15 SP7 php8 — 고친 판(150700.3.24.1) 바로 아래"
rpm_case r14-sles157-at 0 "apache2-mod_php8 8.3.36 150700.3.24.1 $SUSE" "SLES 15 SP7 Apache 모듈 — 고친 판 그대로(SUSE-SU-2026:4844-1)"
rpm_case r15-rocky-same 6 "php-cli 8.0.30 8.el9_8.1 $ROCKY" "Rocky — RHEL 고친 판과 같은 판 문자열 · 공지 없는 공급사"
rpm_case r16-remi 6 "php-cli 8.3.37 1.el9.remi $REMI" "Remi 저장소 꼴 — 공지 없는 공급사"
rpm_case r17-rhel9-old-minor 6 "php-cli 8.0.30 3.el9_6 $RH" "RHEL 9.6 의 빌드 — 이전 마이너"
rpm_case r18-rhel8-other-stream 6 "php-cli 8.1.27 1.module+el8.10.0+21000+5e6f7a8b $RH" "RHEL 8 php:8.1 스트림 — 공지 없는 스트림"
rpm_case r19-rhel7-scl 6 "rh-php73-php-cli 7.3.20 1.el7 $RH" "RHEL 7 의 SCL rh-php73"
rpm_case r20-ol8-82 6 "php-cli 8.2.35 1.module+el8.10.0+91110+0a1b2c3d $OL" "Oracle Linux 8 php:8.2 — 그 공급사의 줄이 없다(RHEL 에는 있다)"
rpm_case r21-sles156 6 "php8 8.2.30 150600.3.25.1 $SUSE" "SUSE 15 SP6 빌드 — 줄 밖"

echo "── F. RPM 자리의 파일 ──"
rpm_case f01-rhel9-file-same 0 "php-cli 8.0.30 8.el9_8.1 $RH /usr/bin/php" "고친 RHEL 9 php-cli 가 깐 /usr/bin/php — 기록과 같다"
rpm_case f02-rhel9-file-changed 6 "php-cli 8.0.30 8.el9_8.1 $RH /usr/bin/php && $(changed /usr/bin/php)" \
    "그 /usr/bin/php 를 바꿈 — RPM 헤더의 다이제스트와 다르다"
rpm_case f03-rhel9-unowned-cgi 6 "php-cli 8.0.30 8.el9_8.1 $RH && $(bin_put /usr/bin/php-cgi)" \
    "고친 RHEL 9 패키지 옆 · 어느 패키지도 깔지 않은 /usr/bin/php-cgi(0.6.3)"
rpm_case f04-rhel9-unowned-sbin-fpm 6 "php-fpm 8.0.30 8.el9_8.1 $RH && $(bin_put /usr/sbin/php-fpm)" \
    "고친 RHEL 9 php-fpm 옆 · 어느 패키지도 깔지 않은 /usr/sbin/php-fpm(0.6.3)"
rpm_case f05-merged-bin-echo 0 "php-fpm 8.0.30 8.el9_8.1 $RH /usr/bin/php-fpm && cp /usr/bin/php-fpm /usr/sbin/php-fpm" \
    "패키지가 깐 /usr/bin/php-fpm + 소유 없는 /usr/sbin/php-fpm(합친 bin 의 메아리 꼴) — 세지 않는다"
rpm_case f06-other-pkg-php 6 "ea-php-cli 8.3.37 1.el9 placeholder /usr/bin/php" \
    "PHP 가 아닌 이름의 패키지(ea-php-cli)가 깐 /usr/bin/php · RPM 의 PHP 패키지 없음"
rpm_case f07-other-pkg-fpm 6 "ea-php-fpm 8.3.37 1.el9 placeholder /usr/bin/php-fpm" \
    "그 꼴의 /usr/bin/php-fpm(합친 bin 의 패키지 자리 · 0.6.3)"
rpm_case f08-rhel9-unowned-bin-fpm 6 "php-cli 8.0.30 8.el9_8.1 $RH && $(bin_put /usr/bin/php-fpm)" \
    "고친 RHEL 9 php-cli + 어느 패키지도 깔지 않은 /usr/bin/php-fpm(갈린 sbin · 0.6.5)"
rpm_case f09-sbin-record-echo 0 "php-fpm 8.0.30 8.el9_8.1 $RH /usr/sbin/php-fpm && cp /usr/sbin/php-fpm /usr/bin/php-fpm" \
    "패키지가 /usr/sbin/php-fpm 으로 적은 파일이 /usr/bin/php-fpm 으로도 보임(합친 sbin 의 옛 꼴 기록 · f05 의 거꾸로) — 세지 않는다"

echo "── O. 공식 빌드 ──"
run_case o01-official-8335-cli php:8.3.35-cli 2 ":" "php:8.3.35-cli — 취약 해시(A5)"
run_case o02-official-8336-cli php:8.3.36-cli 0 ":" "php:8.3.36-cli — 고친 해시(A6)"
run_case o03-official-8336-fpm php:8.3.36-fpm 0 ":" "php:8.3.36-fpm — 고친 해시(A7)"
run_case o04-official-8337-cli php:8.3.37-cli 0 ":" "php:8.3.37-cli — 11월 보안 업데이트의 해시(0.6.2 · A8)"
run_case o05-official-eol-7433 php:7.4.33-cli 2 ":" "php:7.4.33-cli — 지원 끝(고친 판 없음)의 공식 해시(A9)"
run_case o06-official-8235-apache php:8.2.35-apache 6 ":" "php:8.2.35-apache — 목록에 없는 공식 빌드(8.2 계열 · libphp.so · A10)"
run_case o07-moved-8336-opt php:8.3.36-cli 0 "$(php_move /opt/php/8.3)" "8.3.36 을 /opt/php/8.3 으로 옮김 — 직접 빌드 자리 · 판마다 하위 폴더"
run_case o08-moved-8335-usrlocal php:8.3.35-cli 2 "$(php_move /usr/local/php)" "8.3.35 를 /usr/local/php 로 옮김"

echo "── X. 직접 빌드 — 공식 해시에 없는 자리 채우기 ──"
run_case x01-local-bin-php debian:12 6 "$(bin_put /usr/local/bin/php)" "/usr/local/bin/php"
run_case x02-usrlocal-php-bin debian:12 6 "$(bin_put /usr/local/php/bin/php)" "/usr/local/php/bin/php"
run_case x03-opt-php-subdir-fpm debian:12 6 "$(bin_put /opt/php/8.3/sbin/php-fpm)" "/opt/php/8.3/sbin/php-fpm — 판마다 하위 폴더"
run_case x04-local-lib-libphp debian:12 6 "$(bin_put /usr/local/lib/libphp.so)" "/usr/local/lib/libphp.so"
run_case x05-apache-modules-libphp debian:12 6 "$(bin_put /usr/lib/apache2/modules/libphp.so)" \
    "/usr/lib/apache2/modules/libphp.so(공식 Apache 이미지의 자리)"
run_case x06-local-named debian:12 6 "$(bin_put /usr/local/bin/php8.3)" \
    "/usr/local/bin/php8.3 — 판 붙은 이름(패키지 밖 · 이 점검이 판정하지 않는 이름 · 0.6.5)"
run_case x07-usrbin-named-unowned debian:12 6 "$(bin_put /usr/bin/php8.3)" "어느 패키지도 깔지 않은 /usr/bin/php8.3(0.6.5)"
run_case x08-local-named-nodot debian:12 6 "$(bin_put /usr/local/bin/php83)" "/usr/local/bin/php83 — 점 없는 판 이름(패키지 밖 · 0.6.5)"
run_case x09-apache-module-named debian:12 6 "$(bin_put /usr/lib/apache2/modules/libphp7.so)" \
    "어느 패키지도 깔지 않은 /usr/lib/apache2/modules/libphp7.so — apxs 로 지은 PHP 7 의 모듈 자리(0.6.5)"

echo "── M. 섞임 ──"
run_case m01-vuln-and-unknown "$DEB12" 2 "$(deb_set 8.2 8.2.34-1~deb12u1) && $(bin_put /usr/local/bin/php)" \
    "Debian 8.2.34(취약) + 모르는 /usr/local/bin/php — 취약이 앞선다"
run_case m02-fixed-and-unknown "$DEB12" 6 "$(bin_put /usr/local/bin/php)" "고친 Debian 패키지 + 모르는 /usr/local/bin/php"
run_case m03-official-fixed-and-unknown php:8.3.36-cli 6 "$(bin_put /opt/php/bin/php)" "고친 공식 빌드 + 모르는 /opt/php/bin/php"

echo "── P. 프로세스 · 서비스 ──"
run_case p01-outside-running debian:12 6 \
    "mkdir -p /srv/app && cp /bin/sleep /srv/app/php-fpm8.3 && (/srv/app/php-fpm8.3 600 &) && sleep 1 && ls -l /proc/[0-9]*/exe 2>/dev/null | grep -q ' /srv/app/php-fpm8.3\$'" \
    "자리 밖(/srv/app/php-fpm8.3)에서 돈다"
run_case p02-outside-lsphp debian:12 6 \
    "mkdir -p /usr/local/lsws/lsphp83/bin && cp /bin/sleep /usr/local/lsws/lsphp83/bin/lsphp && (/usr/local/lsws/lsphp83/bin/lsphp 600 &) && sleep 1 && ls -l /proc/[0-9]*/exe 2>/dev/null | grep -q ' /usr/local/lsws/lsphp83/bin/lsphp\$'" \
    "LiteSpeed 꼴 lsphp 가 자리 밖에서 돈다"
run_case p03-stale-exe debian:12 6 \
    "mkdir -p /usr/local/sbin && cp /bin/sleep /usr/local/sbin/php-fpm && (/usr/local/sbin/php-fpm 600 &) && sleep 1 && rm /usr/local/sbin/php-fpm && ls -l /proc/[0-9]*/exe 2>/dev/null | grep -q '/usr/local/sbin/php-fpm (deleted)'" \
    "지워진 실행 파일로 돈다"
# 실린 모듈은 maps 의 **실행 가능한** 매핑만 센다(remedy-platform linux.rs) — 코드가 있는 libm 사본을 싣고, 지운 뒤 r-xp 줄로 확인한다.
STALE_MOD='lib=$(ls /lib/*/libm.so.6 /usr/lib/*/libm.so.6 2>/dev/null | head -n 1) && [ -n "$lib" ] && mkdir -p /usr/lib/apache2/modules && cp "$lib" /usr/lib/apache2/modules/libphp8.2.so && cp /bin/sleep /usr/sbin/apache2 && (LD_PRELOAD=/usr/lib/apache2/modules/libphp8.2.so /usr/sbin/apache2 600 &) && sleep 1 && rm /usr/lib/apache2/modules/libphp8.2.so && grep -qs "r-xp .*/libphp8.2.so (deleted)" /proc/[0-9]*/maps'
run_case p04-stale-module debian:12 6 "$STALE_MOD" "지워진 libphp8.2.so 를 실은 채 도는 /usr/sbin/apache2(sleep 사본)"
run_case p05-unit-outside debian:12 6 "mkdir -p /etc/systemd/system && cp /b/fx/php83-fpm.service /etc/systemd/system/" \
    "systemd 유닛 ExecStart=/opt/php83/sbin/php-fpm — 자리 밖(띄우지 않음)"
run_case p06-unit-distro debian:12 0 "mkdir -p /etc/systemd/system && cp /b/fx/php8.2-fpm.service /etc/systemd/system/" \
    "ExecStart=/usr/sbin/php-fpm8.2 — 배포판 자리"
run_case p07-unit-opt-php debian:12 0 "mkdir -p /etc/systemd/system && cp /b/fx/php-fpm.service /etc/systemd/system/" \
    "ExecStart=/opt/php/sbin/php-fpm — 직접 빌드의 선언한 자리"
run_case p08-sysv-outside debian:12 6 \
    "mkdir -p /etc/init.d && cp /b/fx/php83-fpm.init /etc/init.d/php83-fpm && chmod 755 /etc/init.d/php83-fpm" \
    "SysV php_fpm_BIN=\${exec_prefix}/sbin/php-fpm(prefix=/opt/php83)"
run_case p09-upstart-outside debian:12 6 "mkdir -p /etc/init && cp /b/fx/worker.conf /etc/init/worker.conf" \
    "Upstart exec /srv/php/bin/php"
run_case p10-openrc-outside debian:12 6 \
    "mkdir -p /etc/init.d && cp /b/fx/php-app.openrc /etc/init.d/php-app && chmod 755 /etc/init.d/php-app" \
    "OpenRC command=/srv/php/sbin/php-fpm"

echo "── C. Apache 설정 ──"
run_case c01-deb-load-outside debian:12 6 \
    "mkdir -p /etc/apache2/mods-available /etc/apache2/mods-enabled && cp /b/fx/php83.load /etc/apache2/mods-available/ && ln -s ../mods-available/php83.load /etc/apache2/mods-enabled/php83.load" \
    "Debian mods-available 의 LoadModule /opt/php83/lib/libphp.so"
run_case c02-deb-load-distro debian:12 0 "mkdir -p /etc/apache2/mods-available && cp /b/fx/php8.2.load /etc/apache2/mods-available/" \
    "LoadModule /usr/lib/apache2/modules/libphp8.2.so — 배포판 모듈 자리"
run_case c03-own-apache debian:12 6 "mkdir -p /usr/local/apache2/conf && cp /b/fx/httpd-own.conf /usr/local/apache2/conf/httpd.conf" \
    "직접 빌드 /usr/local/apache2/conf 의 modules/libphp.so"
run_case c04-xampp debian:12 6 "mkdir -p /opt/lampp/etc && cp /b/fx/httpd-lampp.conf /opt/lampp/etc/httpd.conf" \
    "XAMPP /opt/lampp/etc 의 modules/libphp.so"
run_case c05-rpm-zts-outside debian:12 6 "mkdir -p /etc/httpd/conf.modules.d && cp /b/fx/20-php.conf /etc/httpd/conf.modules.d/" \
    "RPM 자리의 LoadModule php_zts_module /opt/php83/modules/libphp-zts.so"
run_case c06-rpm8-relative debian:12 0 \
    "mkdir -p /etc/httpd/conf.modules.d /etc/httpd/conf && cp /b/fx/15-php.conf /etc/httpd/conf.modules.d/ && cp /b/fx/httpd-rpm.conf /etc/httpd/conf/httpd.conf" \
    "RHEL 8 의 15-php.conf(modules/libphp7.so) — ServerRoot 기준의 배포판 자리"
run_case c07-suse-distro debian:12 0 \
    "mkdir -p /etc/apache2/sysconfig.d && cp /b/fx/loadmodule-suse.conf /etc/apache2/sysconfig.d/loadmodule.conf" \
    "SUSE 꼴 /usr/lib64/apache2/mod_php8.so — 배포판 모듈 자리"
run_case c08-deb-load-opt-php debian:12 0 "mkdir -p /etc/apache2/mods-available && cp /b/fx/php-optphp.load /etc/apache2/mods-available/php.load" \
    "LoadModule /opt/php/lib/libphp.so — 직접 빌드의 선언한 자리(c01 의 /opt/php83 과 짝)"

echo "── N. PHP 없음 ──"
run_case n01-none-debian debian:12 0 ":" "PHP 없음"
run_case n02-none-alpine alpine:3.22 0 ":" "PHP 없음"
run_case n03-none-rocky rockylinux:9 0 ":" "PHP 없음(RPM 계열)"

echo "── S. 화면 ──"
has() { grep -qF -- "$2" "$OUT/cases/$1/screen.txt" 2>/dev/null; } # 경우 · 글
has x01-local-bin-php '공식 빌드의 해시와 맞지 않아' && has b03-deb12-changed-cli '패키지 기록과 같은지 확인되지 않습니다' \
    && has p03-stale-exe '고친 뒤 다시 시작하지 않은 PHP 가 실행 중입니다' && a=1 || a=0
check "S1 확인 필요 까닭 — 해시 불일치 · 바뀐 실행 파일 · 다시 시작 안 함" "$a" "x01 · b03 · p03 화면"
has r08-rhel7-at 'CVE-2026-109619 만 고칩니다' && has f03-rhel9-unowned-cgi '어느 패키지도 깔지 않은 PHP 실행 파일이 있습니다' \
    && has f06-other-pkg-php 'PHP 패키지로 알아보지 못한 패키지가 깐' \
    && has d17-deb11-like '공급사의 고친 버전 기준이 없는 PHP 패키지입니다' && a=1 || a=0
check "S2 확인 필요 까닭 — RHEL 7 반쪽 수정 · RPM 자리의 소유 · 기준 없는 패키지" "$a" "r08 · f03 · f06 · d17 화면"
grep -Eq 'php83-fpm\.service +\(실행 파일 /opt/php83/sbin/php-fpm\)' "$OUT/cases/p05-unit-outside/screen.txt" 2>/dev/null \
    && grep -Eq '/etc/httpd/conf\.modules\.d/20-php\.conf:2 +\(줄 *LoadModule php_zts_module' \
        "$OUT/cases/c05-rpm-zts-outside/screen.txt" 2>/dev/null && a=1 || a=0
check "S3 항목 줄 — 서비스(유닛 · 실행 파일) · Apache 설정(파일:줄)" "$a" "p05 · c05 화면"
# 판정 묶음이 하나라 취약(2)이 나온 회차에는 확인 필요 항목을 내지 않는다(RELEASE.md 0.2.0) — 화면이 있어야 뜻을 갖는다.
[ -s "$OUT/cases/m01-vuln-and-unknown/screen.txt" ] && ! has m01-vuln-and-unknown '공식 빌드의 해시와 맞지 않아' && a=1 || a=0
check "S4 취약이 나온 회차에는 확인 필요 까닭을 내지 않는다" "$a" "m01 화면에 해시 불일치 까닭이 없다"
n=$(cat "$OUT"/cases/*/screen.txt 2>/dev/null | grep -c '미해소' || true)
[ "$n" = 0 ] && a=1 || a=0
check "S5 미해소 경고 0" "$a" "모든 경우의 화면에서 $n 줄"
# 고객 화면의 낱말 — 룰 문구에 내부 낱말('영향 판' · '고친 판' · '판을' · '갈래')이 없다(배포판 · 판정 · 판단은 센다 밖).
n=$(cat "$OUT"/cases/*/screen.txt 2>/dev/null | grep -c -e '영향 판' -e '고친 판' -e '판을 ' -e '갈래' || true)
[ "$n" = 0 ] && a=1 || a=0
check "S6 화면에 내부 낱말(판 · 갈래) 0" "$a" "모든 경우의 화면에서 $n 줄"

# 칸 수까지 본다 — 경우를 짓다 멈추면 남은 경우가 조용히 사라지고 "실패 0" 이 남는다.
EXPECTED=118 # A 10 · B 12 · D 19 · R 21 · F 9 · O 8 · X 9 · M 3 · P 10 · C 8 · N 3 · 화면 6
pass=$(awk -F"$TAB" '$2 == 1' "$OUT/checks.tsv" | wc -l)
total=$(wc -l <"$OUT/checks.tsv")
[ "$total" = "$EXPECTED" ] || echo "칸 수 $total — 기대 $EXPECTED 와 다르다(경우를 짓다 멈췄거나, 칸을 더하고 EXPECTED 를 고치지 않았다)"
echo "── 합: $pass / $EXPECTED ──"
[ "$pass" = "$EXPECTED" ] && [ "$total" = "$EXPECTED" ]

# ── 경우 표 — id · 기대 · 재는 갈래(plugin.yaml 의 detect id · verdict 줄. 0 은 RELEASE.md '0 을 내는 갈래' 의 줄) ──────────
#
#   b01 0  0 갈래 '고친 Debian · Ubuntu 패키지' — deb12_vuln 의 그 판 · pkg_unknown 이 메타 패키지(php-defaults)를 뺀다
#   b02 2  deb12_vuln — 고친 판 바로 아래
#   b03 6  pkg_bin_changed(different) — 패키지 판으로 판정하지 않는다
#   b04 6  require 의 'and not pkg_bin_changed' — 취약 판이어도 바뀐 실행 파일이면 6
#   b05 0  0 갈래 '고친 Debian · Ubuntu 패키지' — pkg_bin_changed 는 PHP 실행 파일 자리만 본다
#   b06 6  pkg_bin_changed — sbin/php-fpm8.2
#   b07 0  0 갈래 '고친 Debian · Ubuntu 패키지' — u2404_vuln 의 고친 판 이상(실제 설치)
#   b08 0  0 갈래 '고친 Debian · Ubuntu 패키지' — u2404_vuln 의 그 판
#   b09 2  u2404_vuln — 바로 아래
#   b10 6  pkg_unknown — apk(Alpine)는 늘 줄 밖
#   b11 6  bin_named_unowned — 기록(.md5sums)을 지운 /usr/bin/php8.2 는 패키지 밖의 판 붙은 이름이다(0.6.5)
#   b12 6  pkg_unknown — epoch 가 붙은 판(1:)은 deb12 줄의 계열 꼴 밖(지키는 칸)
#   d01 2  deb13_vuln              d02 0  0 갈래 '고친 Debian · Ubuntu 패키지' — deb13 의 그 판
#   d03 2  u1404_vuln              d04 0  같은 갈래 — u1404 의 그 판
#   d05 2  u1604_vuln              d06 0  같은 갈래 — u1604 의 그 판
#   d07 2  u1804_vuln              d08 0  같은 갈래 — u1804 의 그 판
#   d09 2  u2004_vuln              d10 0  같은 갈래 — u2004 의 그 판
#   d11 2  u2204_vuln(Apache 모듈)  d12 0  같은 갈래 — u2204 의 그 판
#   d13 2  u2604_vuln              d14 0  같은 갈래 — u2604 의 그 판
#   d15 2  u2610_vuln              d16 0  같은 갈래 — u2610 의 그 판
#   d17 6  pkg_unknown — 기준에 없는 배포판(지원 끝난 Debian 11 꼴)
#   d18 6  pkg_unknown — 다른 저장소
#   d19 0  0 갈래 'PHP 가 없다' — 메타 패키지는 런타임이 아니다(pkg_unknown 의 exclude · 0.3.0)
#   r01 2  rhel8_74_vuln           r02 0  0 갈래 '고친 RPM 패키지' — RHEL 8.10 php:7.4 의 그 판
#   r03 2  rhel8_82_vuln           r04 0  같은 갈래 — RHEL 8.10 php:8.2 의 그 판
#   r05 2  rhel9_vuln              r06 0  같은 갈래 — RHEL 9.8 의 그 판
#   r07 2  rhel7_vuln              r08 6  rhel7_partial — RHEL 7.9 는 고친 판 이상도 6
#   r09 2  ol8_74_vuln             r10 0  같은 갈래 — Oracle Linux 8.10 php:7.4 의 그 판
#   r11 2  ol9_vuln                r12 0  같은 갈래 — Oracle Linux 9.8 의 그 판
#   r13 2  sles157_vuln            r14 0  같은 갈래 — SLES 15 SP7 의 그 판(apache2-mod_php8)
#   r15 6  rpm_other — 같은 판 문자열의 Rocky
#   r16 6  rpm_other — Remi
#   r17 6  rpm_rh_unknown — 이전 마이너
#   r18 6  rpm_rh_unknown — 다른 모듈 스트림
#   r19 6  rpm_rh_unknown — SCL
#   r20 6  rpm_ol_unknown — 그 공급사의 줄이 없는 스트림
#   r21 6  rpm_suse_unknown — SP6
#   f01 0  0 갈래 '고친 RPM 패키지' — 패키지가 깐 실행 파일이 기록과 같다(bin_rpm_owned 이고 rpm_php)
#   f02 6  pkg_bin_changed — RPM 헤더의 다이제스트와 다르다
#   f03 6  bin_rpm_unowned — RPM 의 PHP 패키지가 있어도(0.6.3)
#   f04 6  sbin_fpm_unowned and not bin_fpm_owned
#   f05 0  0 갈래 '고친 RPM 패키지' — bin_fpm_owned 가 /usr/sbin/php-fpm 의 메아리를 뺀다(0.6.3)
#   f06 6  bin_rpm_owned and not rpm_php — /usr/bin/php
#   f07 6  같은 줄 — /usr/bin/php-fpm(0.6.3 에 더한 자리)
#   f08 6  bin_fpm_unowned and not sbin_fpm_owned — 갈린 sbin 의 소유 없는 /usr/bin/php-fpm(0.6.5)
#   f09 0  0 갈래 '고친 RPM 패키지' — sbin_fpm_owned 가 /usr/bin/php-fpm 의 메아리를 뺀다(0.6.5 · f05 의 거꾸로)
#   o01 2  official_vuln — 8.3.35
#   o02 0  0 갈래 '고친 공식 빌드 8.3.36' — cli
#   o03 0  0 갈래 '고친 공식 빌드 8.3.36' — fpm
#   o04 0  0 갈래 '고친 공식 빌드 8.3.37'(0.6.2)
#   o05 2  official_vuln — 7.4.33(지원 끝)
#   o06 6  bin_unmanaged — 목록에 없는 공식 빌드(8.2 계열 · Apache 모듈 자리)
#   o07 0  0 갈래 '고친 공식 빌드 8.3.36' — 직접 빌드 자리 /opt/php 의 판마다 하위 폴더(0.4.0)
#   o08 2  official_vuln — 직접 빌드 자리 /usr/local/php(0.4.0)
#   x01~x05 6  bin_unmanaged — /usr/local/bin · /usr/local/php · /opt/php 하위 폴더 · /usr/local/lib · Apache 모듈 자리
#   x06~x07 6  bin_named_unowned — 판 붙은 이름의 /usr/local/bin/php8.3 · 어느 패키지도 깔지 않은 /usr/bin/php8.3(0.6.5)
#   x08~x09 6  bin_named_unowned — 점 없는 판 이름 /usr/local/bin/php83 · Apache 모듈 자리의 libphp7.so(0.6.5)
#   m01 2  require 가 unconfirmed 보다 앞선다(판정 묶음 하나 · RELEASE.md 0.2.0)
#   m02 6  bin_unmanaged — 고친 패키지가 모르는 빌드를 가리지 않는다
#   m03 6  bin_unmanaged — 고친 공식 빌드가 모르는 빌드를 가리지 않는다
#   p01 6  running_php                 p02 6  running_php — lsphp
#   p03 6  stale_php — 실행 파일        p04 6  stale_php — 실린 모듈
#   p05 6  service_php — systemd(0.5.0)
#   p06 0  0 갈래 'PHP 가 없다' — service_php 의 exclude(배포판 자리)
#   p07 0  0 갈래 'PHP 가 없다' — service_php 의 exclude(/opt/php)
#   p08 6  service_php — SysV 의 `_BIN`(0.6.0)
#   p09 6  service_php — Upstart exec(0.6.0)
#   p10 6  service_php — OpenRC command(0.6.0)
#   c01 6  apache_php — Debian mods-available
#   c02 0  0 갈래 'PHP 가 없다' — apache_php 의 exclude(/usr/lib/apache2/)
#   c03 6  apache_php — /usr/local/apache2/conf
#   c04 6  apache_php — XAMPP
#   c05 6  apache_php_rpm
#   c06 0  0 갈래 'PHP 가 없다' — apache_php_rpm 의 exclude(modules/)
#   c07 0  0 갈래 'PHP 가 없다' — apache_php 의 exclude(/usr/lib64/apache2)
#   c08 0  0 갈래 'PHP 가 없다' — apache_php 의 exclude(/opt/php/)
#   n01~n03 0  0 갈래 'PHP 가 없다'
