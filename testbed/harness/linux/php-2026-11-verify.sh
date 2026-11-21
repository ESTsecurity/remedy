#!/bin/bash
# 룰: php-2026-11-check-linux — 묶어 낸 출시(ci/batch.sh)가 바뀐 룰의 필수 점검 ① 로 이 하네스를 찾는다(--bin · --plugins · --out)
# 이미지: debian:12 ubuntu:24.04 rockylinux:9 alpine:3.22 php:8.3.36-cli php:8.3.36-fpm php:8.2.35-apache
# PHP 11월 보안 업데이트 점검 룰(php-2026-11-check-linux)을 배포판 · 공식 이미지 컨테이너에서 잰다.
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/php-2026-11-verify.sh --bin <remedy> --plugins <php-2026-11-check-linux 가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--bin` 은 **musl 정적** remedy 다(Alpine 에서도 돈다 — 개발 빌드는 `musl-dev-build.sh`). `--plugins` 는
# `php-2026-11-check-linux/` 를 담은 폴더다(저장소의 `plugins/` 나 내려받아 푼 꾸러미의 `plugins/`). 처음 한 번은 배포판
# 저장소에 닿아야 한다 — PHP 를 깐 이미지를 지어 두고(`remedy-harness/php2611:*`), 다음부터는 그 이미지를 쓴다. 공식 이미지
# `php:8.3.36-cli` · `php:8.3.36-fpm` · `php:8.2.35-apache` 는 미리 받아 둔다(머리의 `# 이미지:` 줄 — 출시 전 필수 점검의
# 러너가 그 줄대로 받는다).
#
# # 상류를 고정한다(2026-11-22)
#
# 상류가 고친 판을 내면 '깐 그대로' 칸의 기대 판정이 뒤집힌다 — 러너는 매번 빈 자리라 그날의 상류로 짓는다(2026-11-21 러너
# 33/37 · Debian 12 의 php8.2 와 `php:8.2-apache` 가 8.2.36 으로 올라갔다). 그래서 Debian 12 는 snapshot.debian.org 의
# 2026-11-18 자리(고친 판이 나오기 전 · 8.2.35-1~deb12u1)에서 짓고, 공식 Apache 이미지는 꼬리표 `8.2.35-apache` 로 받으며,
# Alpine 의 깐 그대로 칸(b04)은 판 줄을 8.3.36-r0 으로 채운다(Alpine 저장소는 옛 판을 두지 않는다). Ubuntu 24.04 · Rocky 9 는
# 판 줄의 위 갈래가 올라가지 않는다(8.3.6-0ubuntu… · 8.0.30 지원 끝).
#
# # 무해한가
#
# **실검체는 없다.** 이미지는 배포판 저장소의 PHP 와 공식 Docker 이미지를 그대로 쓴다. 그 밖의 경우는 **자리 채우기**다 —
# dpkg · apk 는 패키지 기록의 판 줄만 바꾸고, 직접 빌드는 판 문자열(`X-Powered-By: PHP/<판>`)만 담은 작은 파일이다. 도는
# 프로세스가 필요한 경우는 `sleep` 을 PHP 이름으로 복사해 띄운다. 경우마다 네트워크 없는 일회용 컨테이너에서 remedy 가
# 읽기만 한다.
#
# # 무엇을 재나
#
#   A  이미지 4 — 깐 PHP 의 판이 그 갈래의 고친 판 아래다(Debian 12 의 8.2(2026-11-18 스냅숏) · Ubuntu 24.04 의 8.3 · Rocky 9
#      의 8.0(지원 끝)) · Alpine 3.22 는 php83 칸이 있다(b04 가 그 판 줄을 채울 자리 — 깐 판은 기록만 한다)
#   B  패키지 9 — 배포판 셋 깐 그대로 2 · Alpine 판 줄 8.3.36-r0 2 · Debian 의 8.2.36 꼴 0 · 8.1 꼴(지원 끝) 2 · Alpine 8.3.37-r0
#      0 · 8.3.36-r1 2 · 한 자리 이름 `php8` 8.0.30-r0(지원 끝 · Alpine 3.16 의 이름 꼴 · 0.1.1) 2
#   O  공식 이미지 3 — php:8.3.36-cli · php:8.3.36-fpm · php:8.2.35-apache 모두 2
#   X  직접 빌드 12 — /usr/local/php 의 8.4.27 2 · 8.4.28 0 · 판 없음 6 · /opt/php 의 7.4.33(지원 끝) 2 · /usr/local/bin 의 8.5.13
#      0 · 8.5.12 2 · 판마다 하위 폴더(/opt/php/8.3/bin — 룰이 내용을 담지 않는 자리) 6 · 정식 출시 전 버전(0.1.1) — 시험판
#      8.6.0RC7 6 · 개발 빌드 8.6.0-dev 6 · 영향 판의 시험판 8.5.12RC1 2 · 실행 파일 둘의 섞임(0.1.1 — 파일마다 가린다) —
#      8.4.28 + /opt/php 의 8.6.0RC7 6 · 8.4.28 + 판 없음 6
#   P  프로세스 · 서비스 3 — 자리 밖에서 도는 PHP 6 · 자리 밖을 띄우는 서비스 6 · 지워진 실행 파일로 도는 PHP 6
#   N  PHP 없음 2 — Debian · Alpine 0
#   S  화면 4 — 취약 줄의 올릴 버전 문구 · 버전 못 읽음 까닭 · 미해소 경고 0 · 내부 낱말(판 · 갈래) 0
#
# 준비 셸이 실패하면(판 줄을 바꾸지 못함 등) 그 경우의 종료 코드를 97 로 적는다 — 기대와 달라 실패로 센다. 판 줄을 바꾸는
# 셸은 바꾼 뒤 그 판이 실제로 읽히는지 확인한다(sed 는 맞는 줄이 없어도 0 이다).
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

RULE=php-2026-11-check-linux
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일 · musl 정적> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/$RULE/plugin.yaml" ] || { echo "--plugins 에 $RULE 이 없다: $PLUGINS" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
for base in debian:12 ubuntu:24.04 rockylinux:9 alpine:3.22 php:8.3.36-cli php:8.3.36-fpm php:8.2.35-apache; do
    docker image inspect "$base" >/dev/null 2>&1 || { echo "$base 이미지가 없다 — docker pull $base" >&2; exit 2; }
done
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/php2611-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
: >"$OUT/checks.tsv"

check() { # 이름 · 1|0 · 메모
    if [ "$2" = 1 ]; then printf '  OK   %-58s %s\n' "$1" "$3"
    else printf '  실패 %-58s %s\n' "$1" "$3"; fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/checks.tsv"
}

# ── 이미지 — 배포판의 PHP 를 깐다(망이 필요한 것은 여기뿐) ─────────────────────────────────────────
IMG=remedy-harness/php2611
prepare() { # 꼬리표 · 바탕 이미지 · 설치 명령
    local tag=$1 base=$2 install=$3 name
    docker image inspect "$IMG:$tag" >/dev/null 2>&1 && return 0
    name="remedy-php2611-prep-$tag"
    docker rm -f "$name" >/dev/null 2>&1
    docker run --name "$name" "$base" sh -c "$install" >"$OUT/prepare-$tag.log" 2>&1 \
        && docker commit "$name" "$IMG:$tag" >/dev/null
    local rc=$?
    docker rm -f "$name" >/dev/null 2>&1
    return $rc
}
DEB='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends'
# Debian 12 는 고친 판이 나오기 전 날짜의 스냅숏에서 — 꼬리표에 날짜를 넣어 지금 저장소로 지은 옛 이미지와 섞이지 않게 한다.
SNAP=20261118T000000Z
DEB12=debian12-snap${SNAP%%T*}
DEB_SNAP="rm -f /etc/apt/sources.list.d/debian.sources && printf '%s\n' \
'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAP bookworm main' \
'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAP bookworm-updates main' \
'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/$SNAP bookworm-security main' \
>/etc/apt/sources.list && apt-get update -qq -o Acquire::Retries=3 \
&& DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends"
echo "── 이미지 ──"
prepare "$DEB12" debian:12 "$DEB_SNAP php8.2-cli php8.2-fpm >/dev/null && dpkg-query -W php8.2-cli" \
    || { echo "$DEB12 이미지를 짓지 못했다(snapshot.debian.org)" >&2; exit 9; }
prepare ubuntu2404 ubuntu:24.04 "$DEB php8.3-cli >/dev/null && dpkg-query -W php8.3-cli" \
    || { echo "ubuntu2404 이미지를 짓지 못했다" >&2; exit 9; }
prepare rocky9 rockylinux:9 'dnf -y -q install php-cli >/dev/null && rpm -q php-cli' \
    || { echo "rocky9 이미지를 짓지 못했다" >&2; exit 9; }
prepare alpine322 alpine:3.22 'apk add --no-cache -q php83 && apk info -v php83' \
    || { echo "alpine322 이미지를 짓지 못했다" >&2; exit 9; }

# 깐 판을 잰다 — 그 갈래의 고친 판 아래인지(배포판 자신의 비교로).
in_image() { docker run --rm --network none "$IMG:$1" sh -c "$2" 2>/dev/null; }
v=$(in_image "$DEB12" "dpkg-query -W -f='\${Version}' php8.2-cli"); printf '%s' "$v" >"$OUT/installed-debian12.txt"
in_image "$DEB12" "dpkg --compare-versions '$v' lt '8.2.36'" && a=1 || a=0
check "A1 Debian 12 의 php8.2 가 8.2.36 아래" "$a" "$v · 스냅숏 $SNAP"
v=$(in_image ubuntu2404 "dpkg-query -W -f='\${Version}' php8.3-cli"); printf '%s' "$v" >"$OUT/installed-ubuntu2404.txt"
in_image ubuntu2404 "dpkg --compare-versions '$v' lt '8.3.37'" && a=1 || a=0
check "A2 Ubuntu 24.04 의 php8.3 이 8.3.37 아래" "$a" "$v"
v=$(in_image rocky9 "rpm -q --qf '%{VERSION}' php-cli"); printf '%s' "$v" >"$OUT/installed-rocky9.txt"
case "$v" in 8.0.*|8.1.*|7.*) a=1 ;; *) a=0 ;; esac
check "A3 Rocky 9 의 php 가 지원이 끝난 갈래(8.1 이하)" "$a" "$v"
v=$(in_image alpine322 "sed -n '/^P:php83\$/,/^\$/ s/^V://p' /lib/apk/db/installed"); printf '%s' "$v" >"$OUT/installed-alpine322.txt"
[ -n "$v" ] && a=1 || a=0
check "A4 Alpine 3.22 에 php83 칸이 있다(b04 가 판 줄을 채운다)" "$a" "깐 판 ${v:-없음}"

# ── 경우 — 네트워크 없는 일회용 컨테이너 · 판 줄과 파일만 바꾼다 ─────────────────────────────────────
W=$(mktemp -d /tmp/remedy-php2611-verify.XXXXXX)
cleanup() { # 컨테이너가 root 로 쓴 결과는 컨테이너로 지운다
    docker run --rm -v "$W:/w" alpine:3.22 rm -rf /w/b /w/res >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W/b/plugins" "$W/res"
cp "$BIN" "$W/b/remedy"
cp -r "$PLUGINS/$RULE" "$W/b/plugins/"

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
apk_set() { printf "sed -i '/^P:php83\$/,/^\$/ s/^V:.*/V:%s/' /lib/apk/db/installed && [ \"\$(sed -n '/^P:php83\$/,/^\$/ s/^V://p' /lib/apk/db/installed)\" = '%s' ]" "$1" "$1"; }
# php83 칸을 다른 이름 · 판으로 — 옛 Alpine 의 한 자리 이름(`php8` · `php7`) 꼴.
apk_rename() { # 이름 · 판
    printf "sed -i '/^P:php83\$/,/^\$/ s/^V:.*/V:%s/' /lib/apk/db/installed && sed -i 's/^P:php83\$/P:%s/' /lib/apk/db/installed && [ \"\$(sed -n '/^P:%s\$/,/^\$/ s/^V://p' /lib/apk/db/installed)\" = '%s' ]" "$2" "$1" "$1" "$2"
}
# 직접 빌드 자리 채우기 — 판 문자열만 담은 파일(실행 파일이 아니다).
bin_put() { # 폴더 · 이름 · 담을 글자
    printf "mkdir -p %s && printf 'x\\\\000%s\\\\000x' >%s/%s && [ -s %s/%s ]" "$1" "$3" "$1" "$2" "$1" "$2"
}

echo "── B. 패키지 ──"
run_case b01-deb12-default "$DEB12" 2 ":" "깐 그대로(2026-11-18 스냅숏 8.2.35) — 배포판 고친 판 없음"
run_case b02-u2404-default ubuntu2404 2 ":" "깐 그대로 — 배포판 고친 판 없음"
run_case b03-rocky9-default rocky9 2 ":" "깐 그대로 — 8.0(지원 끝)"
run_case b04-alpine-default alpine322 2 "$(apk_set 8.3.36-r0)" "Alpine 판 줄 8.3.36-r0(고친 판 전 · 저장소에 옛 판이 없어 채운다)"
run_case b05-deb-8236 "$DEB12" 0 "$(deb_set 8.2 8.2.36-1~deb12u1)" "Debian 꼴 8.2.36 — 고친 판"
run_case b06-deb-eol81 "$DEB12" 2 "$(deb_set 8.2 8.1.31-1)" "8.1 꼴 — 지원 끝 · 고친 판 없음"
run_case b07-alpine-8337 alpine322 0 "$(apk_set 8.3.37-r0)" "Alpine 꼴 8.3.37-r0 — 고친 판"
run_case b08-alpine-8336 alpine322 2 "$(apk_set 8.3.36-r1)" "Alpine 꼴 8.3.36-r1"
run_case b09-alpine-php8-eol alpine322 2 "$(apk_rename php8 8.0.30-r0)" "Alpine 한 자리 이름 php8 8.0.30-r0 — 지원 끝"

echo "── O. 공식 이미지 ──"
run_case o01-official-cli php:8.3.36-cli 2 ":" "php:8.3.36-cli — /usr/local/bin/php"
run_case o02-official-fpm php:8.3.36-fpm 2 ":" "php:8.3.36-fpm — /usr/local/sbin/php-fpm"
run_case o03-official-apache php:8.2.35-apache 2 ":" "php:8.2.35-apache — libphp.so"

echo "── X. 직접 빌드 ──"
run_case x01-src-8427 debian:12 2 "$(bin_put /usr/local/php/bin php 'X-Powered-By: PHP/8.4.27')" "/usr/local/php/bin/php 8.4.27"
run_case x02-src-8428 debian:12 0 "$(bin_put /usr/local/php/bin php 'X-Powered-By: PHP/8.4.28')" "8.4.28 — 고친 판"
run_case x03-src-noversion debian:12 6 "$(bin_put /usr/local/php/bin php no-version-here)" "판 문자열 없음"
run_case x04-src-eol74 debian:12 2 "$(bin_put /opt/php/sbin php-fpm 'X-Powered-By: PHP/7.4.33')" "/opt/php/sbin/php-fpm 7.4.33 — 지원 끝"
run_case x05-local-8513 debian:12 0 "$(bin_put /usr/local/bin php 'X-Powered-By: PHP/8.5.13')" "/usr/local/bin/php 8.5.13 — 고친 판"
run_case x06-local-8512 debian:12 2 "$(bin_put /usr/local/bin php 'X-Powered-By: PHP/8.5.12')" "/usr/local/bin/php 8.5.12"
run_case x07-src-subdir debian:12 6 "$(bin_put /opt/php/8.3/bin php 'X-Powered-By: PHP/8.3.36')" \
    "/opt/php/8.3/bin/php 8.3.36 — 판마다 하위 폴더(내용을 담지 않아 판을 읽지 못함 · 다 보지 못함)"
# 정식 출시 전 버전(0.1.1) — 판 뒤가 글자나 -dev 면 정식 판으로 세지 않는다. 영향 판의 시험판은 그대로 취약이다.
run_case x08-local-rc debian:12 6 "$(bin_put /usr/local/bin php 'X-Powered-By: PHP/8.6.0RC7')" "/usr/local/bin/php 8.6.0RC7 — 시험판"
run_case x09-local-dev debian:12 6 "$(bin_put /usr/local/bin php 'X-Powered-By: PHP/8.6.0-dev')" "/usr/local/bin/php 8.6.0-dev — 개발 빌드"
run_case x10-local-rc-affected debian:12 2 "$(bin_put /usr/local/bin php 'X-Powered-By: PHP/8.5.12RC1')" "/usr/local/bin/php 8.5.12RC1 — 영향 판의 시험판"
# 실행 파일 둘의 섞임(0.1.1) — 판을 읽은 고친 판이 다른 실행 파일의 판 없음을 가리지 않는다.
run_case x11-mixed-rc debian:12 6 \
    "$(bin_put /usr/local/php/bin php 'X-Powered-By: PHP/8.4.28') && $(bin_put /opt/php/bin php 'X-Powered-By: PHP/8.6.0RC7')" \
    "8.4.28 + /opt/php/bin/php 8.6.0RC7"
run_case x12-mixed-noversion debian:12 6 \
    "$(bin_put /usr/local/php/bin php 'X-Powered-By: PHP/8.4.28') && $(bin_put /opt/php/bin php no-version-here)" \
    "8.4.28 + /opt/php/bin/php 판 없음"

echo "── P. 프로세스 · 서비스 ──"
run_case p01-outside-running debian:12 6 \
    "mkdir -p /srv/app && cp /bin/sleep /srv/app/php-fpm8.3 && (/srv/app/php-fpm8.3 600 &) && sleep 1" "자리 밖(/srv/app/php-fpm8.3)에서 돈다"
run_case p02-outside-service debian:12 6 \
    "mkdir -p /etc/systemd/system && printf '[Service]\nExecStart=/srv/app/php-fpm --nodaemonize\n' >/etc/systemd/system/php-alt.service" \
    "자리 밖을 띄우는 서비스(유닛 파일)"
run_case p03-stale-deleted debian:12 6 \
    "mkdir -p /usr/local/sbin && cp /bin/sleep /usr/local/sbin/php-fpm && (/usr/local/sbin/php-fpm 600 &) && sleep 1 && rm /usr/local/sbin/php-fpm" \
    "지워진 실행 파일로 돈다"

echo "── N. PHP 없음 ──"
run_case n01-none-debian debian:12 0 ":" "PHP 없음"
run_case n02-none-alpine alpine:3.22 0 ":" "PHP 없음"

echo "── S. 화면 ──"
grep -q '8.2 계열은 8.2.36 이상으로 올리십시오' "$OUT/cases/b01-deb12-default/screen.txt" 2>/dev/null \
    && grep -q '고친 버전(8.5.13 · 8.4.28 · 8.3.37 · 8.2.36) 이상으로 올리십시오' "$OUT/cases/o01-official-cli/screen.txt" \
        2>/dev/null && a=1 || a=0
check "S1 취약 줄의 올릴 버전 문구" "$a" "b01 · o01 화면"
grep -q '버전을 읽지 못했습니다' "$OUT/cases/x03-src-noversion/screen.txt" 2>/dev/null \
    && grep -q '이 점검이 보는 자리 밖에서 PHP 가 실행 중입니다' "$OUT/cases/p01-outside-running/screen.txt" 2>/dev/null && a=1 || a=0
check "S2 확인 필요 까닭 — 버전 없음 · 자리 밖" "$a" "x03 · p01 화면"
n=$(cat "$OUT"/cases/*/screen.txt 2>/dev/null | grep -c '미해소' || true)
[ "$n" = 0 ] && a=1 || a=0
check "S3 미해소 경고 0" "$a" "모든 경우의 화면에서 $n 줄"
# 고객 화면의 낱말 — 룰 문구에 내부 낱말('영향 판' · '고친 판' · '판을' · '갈래')이 없다(배포판 · 판정 · 판단은 센다 밖).
n=$(cat "$OUT"/cases/*/screen.txt 2>/dev/null | grep -c -e '영향 판' -e '고친 판' -e '판을 ' -e '갈래' || true)
[ "$n" = 0 ] && a=1 || a=0
check "S4 화면에 내부 낱말(판 · 갈래) 0" "$a" "모든 경우의 화면에서 $n 줄"

pass=$(awk -F'\t' '$2 == 1' "$OUT/checks.tsv" | wc -l)
total=$(wc -l <"$OUT/checks.tsv")
echo "── 합: $pass / $total ──"
[ "$pass" = "$total" ]
