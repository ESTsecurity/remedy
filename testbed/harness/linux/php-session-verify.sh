#!/bin/bash
# 룰: php-session-check-linux — 묶어 낸 출시(ci/batch.sh)가 바뀐 룰의 필수 점검 ① 로 이 하네스를 찾는다(--bin · --plugins · --out)
# 이미지: debian:12 ubuntu:24.04 rockylinux:9 alpine:3.22 php:8.3.36-cli php:8.3.36-fpm php:8.3.37-cli php:8.2.35-apache
# rc 묶음: php-session
# 하네스 표: WSL · docker(경우마다 네트워크 없는 컨테이너) | php-session 리눅스 점검의 판정 — 설정(켬 · 끔 · 없음)과 판(고침 · 고치지 않음 · 모름)의 조합 · 설정 자리와 세 꼴 · 패키지 밖과 자리 밖의 PHP
# PHP 세션 업로드 진행 설정 점검 룰(php-session-check-linux)을 배포판 · 공식 이미지 컨테이너에서 잰다(2026-11-23 · 0.6.1 — 이 룰의 첫 하네스).
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/php-session-verify.sh --bin <remedy> --plugins <php-session-check-linux 가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--bin` 은 **musl 정적** remedy 다(Alpine 에서도 돈다 — 개발 빌드는 `musl-dev-build.sh`). `--plugins` 는
# `php-session-check-linux/` 를 담은 폴더다(저장소의 `plugins/` 나 내려받아 푼 꾸러미의 `plugins/`). 처음 한 번은 배포판
# 저장소에 닿아야 한다 — PHP 를 깐 이미지 셋과 rpmbuild 를 깐 Rocky 9 를 지어 두고(`remedy-harness/php-session:*`), 다음부터는
# 그 이미지를 쓴다. 바탕 이미지와 공식 이미지는 머리의 `# 이미지:` 줄대로 미리 받아 둔다(출시 전 필수 점검의 러너가 그 줄대로
# 받는다).
#
# 기대는 remedy 의 종료 코드다 — 0 취약한 곳을 찾지 못함 · 6 확인 필요(RELEASE.md '결과 읽기'). **이 룰은 판정(2)을 세우지
# 않는다** — verdict.require 가 늘 거짓이다(위험의 셋째 조건이 앱 코드라 이 도구가 보지 못한다). 기대값은 룰을 돌려 얻지 않고
# plugin.yaml 의 줄과 RELEASE.md 의 '0 을 내는 갈래' 에서 정했다 — 경우마다 재는 갈래는 파일 끝의 표에 있다.
#
# 판정식(verdict.unconfirmed 여섯 줄)을 펴면 — PHP 가 있다는 문(php_pkg · php_bin · rpm_php)이 서고, 켠 설정이 하나라도 있거나
# 고친 판으로 세지 않은 PHP(판 사실 덩이 — deb_vuln_* · deb_eol · apk_vuln · rpm_vuln · bin_vuln · bin_version_unknown · RPM 자리의
# 소유 없는 파일 · pkg_bin_changed · stale_php · 판을 볼 규칙이 하나도 서지 않은 php_bin)가 있으면 6, 자리 밖에서 돌거나
# (running_php) 서비스 · Apache 설정이 자리 밖 PHP 를 가리키면(service_php · apache_php · apache_php_rpm) PHP 와 무관하게 6, 그
# 밖은 0 이다. **끔은 0 을 막지 않고 까닭만 가른다** — 그래서 끔을 읽는지는 종료 코드가 아니라 화면의 까닭(S 칸)으로 잰다.
#
# # 상류를 고정한다
#
# 상류가 고친 판을 내면 '깐 그대로' 칸의 기대가 뒤집힌다 — 러너는 매번 빈 자리라 그날의 상류로 짓는다(2026-11-21 러너에서 PHP
# 11월 하네스가 그렇게 33/37 이었다). 이 룰에는 하나가 더 있다 — **상류가 설정 파일의 기본 줄을 바꾸면 '설정 없음' 칸이
# 뒤집힌다.** 그래서:
#
# - Debian 12 는 snapshot.debian.org 의 2026-11-18 자리에서 짓는다(본보기 둘과 같은 자리 · 8.2.35-1~deb12u1 — 고친 판 전이라 b01 이
#   '고치지 않음' 칸이다). 고친 판 칸은 패키지 기록의 판 줄을 8.2.36-1~deb12u1 로 바꾼다(FIX82). A1 이 판 · php.ini 의 그 줄(주석)을
#   먼저 잰다.
# - Ubuntu 24.04 는 지금 저장소로 짓는다 — 고친 패키지가 그 계열(8.3.6-0ubuntu0.24.04.*) 안에서만 올라가 상류 판 8.3.6 이 그대로다.
#   이 룰은 백포트를 고친 판으로 세지 않으므로 깐 그대로는 늘 6 이다(A2).
# - Alpine 3.22 는 판 줄을 칸마다 채운다(8.3.36-r0 · 8.3.37-r0) — 저장소는 옛 판을 두지 않고, 지금 판이 고친 판으로 오르는 날 '깐
#   그대로' 가 뒤집힌다(2026-11-22 의 깐 판은 8.3.36-r0). A3 이 `/usr/bin/php` 가 링크인지도 잰다(정규 파일이면 RPM 자리의 소유 없는
#   파일로 서서 l02 가 뒤집힌다).
# - RPM 은 모두 자리 채우기 rpm 이다(rpmbuild 만 깐 Rocky 9 · A4) — 실제 RHEL · SUSE 저장소의 판은 날마다 움직인다.
# - 공식 이미지는 판 꼬리표다. 이 룰은 해시가 아니라 판 문자열(`X-Powered-By: PHP/<판>`)을 보므로 `php:8.3.37-cli` 가 기반 이미지
#   때문에 다시 지어져도 뒤집히지 않는다. A5~A8 이 그 파일들의 판 문자열과 설정 자리에 주석 밖 그 설정 줄이 없음을 먼저 잰다 —
#   이미지 탓과 룰 탓을 가른다.
#
# # 무해한가
#
# **실검체는 없다.** 이미지는 배포판 저장소의 PHP 와 공식 Docker 이미지를 그대로 쓰고, PHP 는 실행하지 않는다(판 문자열을 읽거나
# 직접 빌드 자리로 옮기기만 한다). 그 밖의 경우는 **자리 채우기**다 — dpkg · apk 는 패키지 기록의 판 줄을 바꾸거나 파일 없는 칸
# 하나를 더하고, RPM 은 rpmbuild 로 지은 rpm(이름 · 판 · 공급사 — 파일을 담는 경우도 글자 한 줄)을 넣는다. 직접 빌드는 판
# 문자열(`X-Powered-By: PHP/<판>`)이나 글자 한 줄만 담은 작은 파일이고, 설정 · 시작 스크립트 · 유닛 · Apache 설정은 그 줄만 담은
# 파일이다(아무것도 띄우지 않는다). 도는 프로세스가 필요한 경우는 `sleep` 을 PHP 이름으로 복사해 띄운다 — 실린 모듈 칸(p04)은
# 이미지의 glibc `libm.so.6` 을 `libphp8.2.so` 이름으로 복사해 `sleep` 사본에 미리 싣고(LD_PRELOAD) 지운다. 경우마다 네트워크 없는
# 일회용 컨테이너에서 remedy 가 읽기만 한다.
#
# # 무엇을 재나
#
#   A  이미지 8 — Debian 12 스냅숏의 php8.2 가 8.2.35(고친 판 전) · 메타 php-cli · fpm/php.ini 의 그 줄은 주석 · Ubuntu 24.04 의
#      php8.3 이 상류 8.3.6 계열 · Alpine 의 php83 · rpmbuild 이미지에 PHP 없음 · 공식 이미지 넷의 PHP 파일이 그 판 문자열 — 모두
#      설정 자리에 주석 밖 그 설정 줄이 없다
#   B  Debian 12 실제 설치 13 — 깐 그대로 b01 6 · 고친 판 줄 b02 0 · 고친 판 + 켬 b03 6 · + 끔 b04 0 · 고치기 전 + 끔 b05 6 · + 켬
#      b06 6 · php.ini 의 주석을 풀어 켬 b07 6 · 풀에서 켬 b08 6 · 끔 b09 0 · php8.2 를 바꿈 b10 6 · php-fpm8.2 를 바꿈 b11 6 · 상관없는
#      파일을 바꿈 b12 0 · CLI 켬 + 풀 끔 b13 6
#   K  설정 꼴 8 — 고친 Debian 위 값 꼴 넷(1 · "On" · On ; 주석 · =TRUE) k01~k04 6 · 풀의 php_value[…] = 1 k05 6 · 고친 모듈 +
#      Apache 줄 켬 k06 6 · 끔 k07 0 · 끄는 꼴 다섯과 이웃 키 k08 0
#   U  Ubuntu 24.04 1 — 깐 그대로 u01 6(백포트)
#   L  Alpine 4 — 판 줄 8.3.36-r0 l01 6 · 8.3.37-r0 l02 0 · + 켬 l03 6 · 이름 php8 8.0.30-r0 l04 6
#   D  dpkg 판 줄 8 — 갈래 넷(8.5 · 8.4 · 8.3 · Apache 모듈 8.2)의 고친 판 바로 아래 d01~d04 6 · 넷의 고친 판과 다른 저장소 꼴 d05 0 ·
#      Ubuntu 24.04 의 백포트 d06 6 · 다음 계열의 시험판 d07 0 · 지원 끝 7.4 d08 6
#   R  RPM 15 — 갈래 넷(8.5 Fedora · 8.4 SUSE Apache 모듈 · 8.3 · 8.2)의 바로 아래 r01~r04 6 · 넷의 고친 판과 Remi SCL r05 0 · RHEL 9
#      의 8.0.30 r06 6 · SCL 지원 끝 r07 6 · 다음 계열 시험판 r08 0 · RHEL 꼴 설정 넷(끔 · 풀 · FPM 전역 · httpd 의 php.conf) r09 0 ·
#      이름 php 만 + /etc/php.ini 켬 r10 6 · /etc/php.d r11 6 · 풀 r12 6 · /etc/php-fpm.conf r13 6 · httpd 의 php.conf r14 6 · SUSE
#      /etc/php8 r15 6
#   F  RPM 자리의 파일 10 — 고친 php-cli 가 깐 /usr/bin/php f01 0 · 그 파일을 바꿈 f02 6 · 소유 없는 /usr/bin/php-cgi f03 6 · 소유
#      없는 /usr/sbin/php-fpm f04 6 · 합친 bin 의 메아리 f05 0 · 그 /usr/bin/php-fpm 을 바꿈 f06 6 · PHP 가 아닌 이름의 패키지가 깐
#      /usr/bin/php f07 6 · /usr/local/bin/php f08 6 · 고친 php 가 깐 httpd 모듈 f09 0 · 소유 없는 모듈 f10 6
#   O  공식 빌드 11 — 8.3.37 그대로 o01 0 · conf.d 켬 o02 6 · php.ini-production + 끔 o03 0 · FPM 풀 자리 켬 o04 6 · FPM 전역 설정
#      켬 o05 6 · 8.3.36 그대로 o06 6 · 8.3.36 FPM 풀에서 끔 o07 6 · 8.2.35 Apache 줄로 끔 o08 6 · 8.3.37 을 /opt/php 로 o09 0 · 그
#      php.ini 켬 o10 6 · /opt/php/8.3 하위 폴더 o11 6
#   X  직접 빌드 16 — 판 문자열 자리 채우기: 8.4.28 x01 0 · 8.4.27 x02 6 · 판 없음 x03 6 · 8.6.0RC7 x04 6 · 8.6.0 x05 0 · /opt/php 의
#      7.4.33 x06 6 · 모듈 8.3.36 x07 6 · 8.3.37 x08 0 · Apache 모듈 자리 8.2.36 x09 0 · /usr/bin/php 링크만 x10 6 · 직접 빌드의 설정
#      자리 셋(/usr/local/php/lib · /usr/local/lib · /opt/php/etc/php-fpm.d) 켬 x11~x13 6 · 섞임 x14 6 · 판 없음 + 켬 x15 6 · + 끔 x16 6
#   M  섞임 3 — 고친 Debian + 고치기 전 /usr/local/bin/php m01 6 · + 고친 것 m02 0 · 고친 RPM + 판 없음 m03 6
#   P  프로세스 · 서비스 10 — 자리 밖 php-fpm8.3 p01 6 · lsphp p02 6 · 고친 공식 빌드 + 지워진 실행 파일 p03 6 · 고친 Debian + 지워진
#      모듈 p04 6 · systemd 유닛 자리 밖 p05 6 · 배포판 자리 p06 0 · /opt/php p07 0 · SysV p08 6 · Upstart p09 6 · OpenRC p10 6
#   C  Apache LoadModule 8 — Debian mods-available 의 /opt/php83 c01 6 · 배포판 모듈 c02 0 · /usr/local/apache2 c03 6 · XAMPP c04 6 ·
#      RPM 자리의 php_zts_module c05 6 · RHEL 8 의 modules/ 상대 경로 c06 0 · SUSE 모듈 자리 c07 0 · /opt/php c08 0
#   N  PHP 없음 5 — Debian · Alpine · Rocky 0 · PHP 를 지우고 남은 켠 설정(Debian · RPM) 0
#   S  화면 8 — 고치기 전 판의 까닭 셋 · 판을 읽지 못한 PHP 의 까닭 셋 · 고친 판인데 켬(까닭이 겹치지 않는다) · 자리 밖 까닭 ·
#      항목 줄(켠 설정 줄의 세 꼴) · 실제 이미지의 설정 자리 · 미해소 경고 0 · 내부 낱말(판 · 갈래) 0
#
# 준비 셸이 실패하면(판 줄 · 기록 칸 · rpm 을 넣지 못함, 픽스처를 놓지 못함, 띄운 프로세스가 보이지 않음 등) 그 경우의 종료
# 코드를 97 로 적는다 — 기대와 달라 실패로 센다. 준비 셸은 바꾼 뒤 그것이 실제로 읽히는지 확인한다(sed 는 맞는 줄이 없어도 0 이다).
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

RULE=php-session-check-linux
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일 · musl 정적> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/$RULE/plugin.yaml" ] || { echo "--plugins 에 $RULE 이 없다: $PLUGINS" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
for base in debian:12 ubuntu:24.04 rockylinux:9 alpine:3.22 php:8.3.36-cli php:8.3.36-fpm php:8.3.37-cli php:8.2.35-apache; do
    docker image inspect "$base" >/dev/null 2>&1 || { echo "$base 이미지가 없다 — docker pull $base" >&2; exit 2; }
done
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/php-session-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
: >"$OUT/checks.tsv"
TAB=$(printf '\t')

check() { # 이름 · 1|0 · 메모
    if [ "$2" = 1 ]; then printf '  OK   %-58s %s\n' "$1" "$3"
    else printf '  실패 %-58s %s\n' "$1" "$3"; fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/checks.tsv"
}

# ── 이미지 — 배포판의 PHP 와 rpmbuild 를 깐다(망이 필요한 것은 여기뿐) ──────────────────────────────────
IMG=remedy-harness/php-session
prepare() { # 꼬리표 · 바탕 이미지 · 설치 명령
    local tag=$1 base=$2 install=$3 name
    docker image inspect "$IMG:$tag" >/dev/null 2>&1 && return 0
    name="remedy-php-session-prep-$tag"
    docker rm -f "$name" >/dev/null 2>&1
    docker run --name "$name" "$base" sh -c "$install" >"$OUT/prepare-$tag.log" 2>&1 \
        && docker commit "$name" "$IMG:$tag" >/dev/null
    local rc=$?
    docker rm -f "$name" >/dev/null 2>&1
    return $rc
}
DEB='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends'
# Debian 12 는 PHP 11월 보안 업데이트가 나오기 전 날짜의 스냅숏에서 — 꼬리표에 날짜를 넣어 지금 저장소로 지은 이미지와 섞이지
# 않게 한다. 메타 패키지(php-cli · php-fpm — 원본 php-defaults)로 깐다 — 관리자가 흔히 까는 꼴이다(php2shell 하네스와 같은 꼴).
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

# ── A. 이미지 — 깐 판 · 판 문자열 · 설정 자리가 이 하네스가 뜻하는 그것인가 ──────────────────────────────
echo "── A. 이미지 ──"
in_image() { docker run --rm --pull=never --network none "$IMG:$1" sh -c "$2" 2>/dev/null; }
official_run() { docker run --rm --pull=never --network none --entrypoint sh "$1" -c "$2" 2>/dev/null; }
# 주석 밖에서 그 설정 이름을 적은 줄의 수(폴더들 아래 모든 파일 · 없는 폴더는 0) — '설정 없음' 칸의 전제다.
cfg_lines() { printf "grep -rhs 'session.upload_progress.enabled' %s | grep -cv '^[[:space:]]*[;#]'" "$*"; }

v=$(in_image "$DEB12" "dpkg-query -W -f='\${Version}' php8.2-cli"); printf '%s' "$v" >"$OUT/installed-debian12.txt"
s=$(in_image "$DEB12" "dpkg-query -W -f='\${source:Package}' php-cli")
c=$(in_image "$DEB12" "$(cfg_lines /etc/php)")
k=$(in_image "$DEB12" "grep -c '^;session.upload_progress.enabled = On\$' /etc/php/8.2/fpm/php.ini")
l=$(in_image "$DEB12" "[ -L /usr/bin/php ] && echo 1")
[ "$v" = 8.2.35-1~deb12u1 ] && [ "$s" = php-defaults ] && [ "$c" = 0 ] && [ "$k" = 1 ] && [ "$l" = 1 ] && a=1 || a=0
check "A1 Debian 12 의 php8.2 가 고친 판 전 · 메타 php-cli · 그 설정은 주석뿐" "$a" \
    "${v:-없음} · php-cli 의 원본 ${s:-없음} · 주석 밖 ${c:-?}줄 · fpm/php.ini 의 주석 줄 ${k:-?} · /usr/bin/php 링크 ${l:-0} · 스냅숏 $SNAP"
v=$(in_image ubuntu2404 "dpkg-query -W -f='\${Version}' php8.3-cli"); printf '%s' "$v" >"$OUT/installed-ubuntu2404.txt"
c=$(in_image ubuntu2404 "$(cfg_lines /etc/php)")
l=$(in_image ubuntu2404 "[ -L /usr/bin/php ] && echo 1")
a=0
if printf '%s' "$v" | grep -Eq '^8\.3\.6-0ubuntu0\.24\.04(\.[0-9]+)?$' && [ "$c" = 0 ] && [ "$l" = 1 ]; then a=1; fi
check "A2 Ubuntu 24.04 의 php8.3 이 상류 8.3.6 계열 · 그 설정은 주석뿐" "$a" "${v:-없음} · 주석 밖 ${c:-?}줄 · /usr/bin/php 링크 ${l:-0}"
v=$(in_image alpine322 "sed -n '/^P:php83\$/,/^\$/ s/^V://p' /lib/apk/db/installed"); printf '%s' "$v" >"$OUT/installed-alpine322.txt"
c=$(in_image alpine322 "$(cfg_lines /etc/php83)")
l=$(in_image alpine322 "{ [ ! -e /usr/bin/php ] || [ -L /usr/bin/php ]; } && echo 1")
[ -n "$v" ] && [ "$c" = 0 ] && [ "$l" = 1 ] && a=1 || a=0
check "A3 Alpine 3.22 에 php83 이 있다 · 그 설정은 주석뿐" "$a" \
    "깐 판 ${v:-없음}(칸마다 판 줄을 채운다) · 주석 밖 ${c:-?}줄 · /usr/bin/php 가 없거나 링크 ${l:-0}"
v=$(in_image rocky9-rpmbuild "command -v rpmbuild >/dev/null && rpm -qa --qf '%{NAME}\n' | grep -c '^php'")
[ "$v" = 0 ] && a=1 || a=0
check "A4 rocky9-rpmbuild 에 rpmbuild 가 있고 PHP 패키지는 없다" "$a" "PHP 이름의 rpm ${v:-?}개"

# 공식 이미지의 PHP 파일(룰의 자리) — '경로<TAB>판 문자열' 줄. 실행하지 않고 판 문자열만 읽는다(rules/php.yar 가 보는 그 글).
VERSIONS='for f in /usr/local/bin/php /usr/local/bin/php-cgi /usr/local/sbin/php-fpm /usr/local/lib/libphp*.so /usr/lib/apache2/modules/libphp*.so; do [ -f "$f" ] || continue; v=$(grep -aoE "X-Powered-By: PHP/[0-9]+[.][0-9]+[.][0-9]+[A-Za-z0-9-]*" "$f" | sort -u | tr "\n" " "); printf "%s\t%s\n" "$f" "${v% }"; done'
: >"$OUT/official-versions.tsv"
a_official() { # 칸 이름 · 이미지 · 판 · 주석 밖 그 설정 줄이 없어야 할 자리 · 칸이 쓸 파일을 보는 셸(참이어야 한다)
    local name=$1 image=$2 want=$3 dirs=$4 more=$5 f v n=0 ok=0 c m
    while IFS="$TAB" read -r f v; do
        [ -n "$f" ] || continue
        n=$((n + 1))
        printf '%s\t%s\t%s\n' "$image" "$f" "$v" >>"$OUT/official-versions.tsv"
        [ "$v" = "X-Powered-By: PHP/$want" ] && ok=$((ok + 1))
    done < <(official_run "$image" "$VERSIONS")
    c=$(official_run "$image" "$(cfg_lines $dirs)")
    official_run "$image" "$more" && m=1 || m=0
    check "$name" "$([ "$n" -gt 0 ] && [ "$ok" = "$n" ] && [ "${c:-x}" = 0 ] && [ "$m" = 1 ] && echo 1 || echo 0)" \
        "$image · PHP 파일 $n · 판 문자열 $want 인 것 $ok · 주석 밖 그 설정 ${c:-?}줄 · 칸이 쓸 파일 $m"
}
a_official "A5 php:8.3.37-cli 의 PHP 가 판 문자열 8.3.37 · 그 설정 없음" php:8.3.37-cli 8.3.37 /usr/local/etc \
    '[ -f /usr/local/etc/php/php.ini-production ]'
a_official "A6 php:8.3.36-cli 의 PHP 가 판 문자열 8.3.36 · 그 설정 없음" php:8.3.36-cli 8.3.36 /usr/local/etc ':'
a_official "A7 php:8.3.36-fpm 의 PHP 가 판 문자열 8.3.36 · 그 설정 없음" php:8.3.36-fpm 8.3.36 /usr/local/etc \
    '[ -d /usr/local/etc/php-fpm.d ]'
a_official "A8 php:8.2.35-apache 의 PHP 가 판 문자열 8.2.35 · 그 설정 없음" php:8.2.35-apache 8.2.35 '/usr/local/etc /etc/apache2' \
    '[ -f /etc/apache2/conf-available/docker-php.conf ]'

# ── 경우 — 네트워크 없는 일회용 컨테이너 · 판 줄 · 기록 칸 · 파일만 바꾼다 ─────────────────────────────────
W=$(mktemp -d /tmp/remedy-php-session-verify.XXXXXX)
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

# 설정 · 시작 스크립트 · 유닛 · Apache 설정 — 그 줄만 담은 파일(작은따옴표라 `$` 는 글자 그대로다). 준비 셸이 제자리에 복사한다.
FX="$W/b/fx"
# php.ini 꼴 — `키 = 값`(수집기가 `=` 로 갈라 다듬는다 · 줄 머리의 `;` · `#` 만 주석이다).
printf '%s\n' 'session.upload_progress.enabled = On' >"$FX/ini-on.ini"
printf '%s\n' 'session.upload_progress.enabled = Off' >"$FX/ini-off.ini"
printf '%s\n' 'session.upload_progress.enabled = 1' >"$FX/ini-1.ini"
printf '%s\n' 'session.upload_progress.enabled = "On"' >"$FX/ini-quoted-on.ini"
printf '%s\n' 'session.upload_progress.enabled = On ; progress bar for large uploads' >"$FX/ini-on-comment.ini"
printf '%s\n' 'session.upload_progress.enabled=TRUE' >"$FX/ini-true-nospace.ini"
# 끄는 꼴 다섯 · 이웃 키(On 값) · 주석의 켬 — 어느 것도 켬으로 읽지 않아야 한다(고친 판 위에서 0).
printf '%s\n' '[Session]' 'session.upload_progress.enabled = Off ; CVE-2026-115560' 'session.upload_progress.enabled = 0' \
    'session.upload_progress.enabled =' 'session.upload_progress.enabled = "Off"' 'session.upload_progress.enabled = none' \
    'session.upload_progress.cleanup = On' 'session.upload_progress.prefix = "upload_progress_"' \
    'session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"' 'session.upload_progress.freq = "1%"' \
    'session.upload_progress.min_freq = "1"' ';session.upload_progress.enabled = On' >"$FX/ini-off-forms.ini"
# RPM 계열의 /etc/php.ini 꼴 — 절과 이웃 키(On 값)가 있다.
rpm_ini() { printf '%s\n' '[PHP]' 'engine = On' 'short_open_tag = Off' 'expose_php = On' '[Session]' 'session.save_handler = files' \
    'session.use_strict_mode = 0' "session.upload_progress.enabled = $1"; }
rpm_ini On >"$FX/php-rpm-on.ini"
rpm_ini Off >"$FX/php-rpm-off.ini"
# PHP-FPM 풀 꼴 — `php_admin_flag[키] = 값`(수집기가 `=` 로 갈라 key 에 대괄호 꼴이 온다).
printf '%s\n' 'php_admin_flag[session.upload_progress.enabled] = on' >"$FX/pool-on.conf"
printf '%s\n' 'php_admin_flag[session.upload_progress.enabled] = off' >"$FX/pool-off.conf"
printf '%s\n' 'php_value[session.upload_progress.enabled] = 1' >"$FX/pool-value-1.conf"
printf '%s\n' '[www]' 'php_admin_flag[session.upload_progress.enabled] = on' >"$FX/pool-www-on.conf"
printf '%s\n' '[www]' 'php_admin_flag[session.upload_progress.enabled] = off' >"$FX/pool-www-off.conf"
# RHEL 의 /etc/php-fpm.d/www.conf · /etc/php-fpm.conf 꼴 — 이웃 키(php_value[session.save_handler] · php_admin_flag[log_errors] = on)가 있다.
printf '%s\n' '[www]' 'user = apache' 'group = apache' 'listen = /run/php-fpm/www.sock' 'listen.acl_users = apache,nginx' \
    'pm = dynamic' 'pm.max_children = 50' 'slowlog = /var/log/php-fpm/www-slow.log' \
    'php_admin_value[error_log] = /var/log/php-fpm/www-error.log' 'php_admin_flag[log_errors] = on' \
    'php_value[session.save_handler] = files' 'php_value[session.save_path] = /var/lib/php/session' \
    'php_value[soap.wsdl_cache_dir] = /var/lib/php/wsdlcache' >"$FX/www-rhel.conf"
printf '%s\n' 'include=/etc/php-fpm.d/*.conf' '[global]' 'pid = /run/php-fpm/php-fpm.pid' \
    'error_log = /var/log/php-fpm/error.log' 'daemonize = yes' >"$FX/fpm-conf-rhel.conf"
printf '%s\n' '[global]' 'pid = /run/php-fpm/php-fpm.pid' 'error_log = /var/log/php-fpm/error.log' '[www]' \
    'php_admin_value[session.upload_progress.enabled] = 1' >"$FX/fpm-conf-www-1.conf"
# Apache 설정 꼴 — `php_admin_flag 키 값`(`=` 가 없어 key · value 가 비고 line 만 온다 · 수집기가 줄 앞 공백을 뗀다).
apache_flag() { printf '%s\n' '<Directory /var/www/html>' "    php_admin_flag session.upload_progress.enabled $1" '</Directory>'; }
apache_flag on >"$FX/apache-on.conf"
apache_flag off >"$FX/apache-off.conf"
printf '%s\n' 'LoadModule php_module /usr/lib/apache2/modules/libphp.so' >"$FX/php-mod.load"
# RHEL 의 /etc/httpd/conf.d/php.conf 꼴 — 이웃 키(php_value session.save_handler 등) 끝에 그 설정 줄.
httpd_php() { printf '%s\n' '<Files ".user.ini">' '    Require all denied' '</Files>' 'AddType text/html .php' 'DirectoryIndex index.php' \
    '<IfModule  mod_php.c>' '    <FilesMatch \.(php|phar)$>' '        SetHandler application/x-httpd-php' '    </FilesMatch>' \
    '    php_value session.save_handler "files"' '    php_value session.save_path    "/var/lib/php/session"' \
    '    php_value soap.wsdl_cache_dir  "/var/lib/php/wsdlcache"' "    php_value session.upload_progress.enabled $1" '</IfModule>'; }
httpd_php 0 >"$FX/httpd-php-off.conf"
httpd_php 1 >"$FX/httpd-php-on.conf"
# 유닛 · 시작 스크립트 · LoadModule 줄 — php2shell 하네스와 같은 꼴(같은 제품 원본의 규칙이다).
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
# Alpine 의 php83 칸 — 판 줄을 바꾸거나, 이름까지 바꾼다(옛 Alpine 의 한 자리 이름 `php8` · `php7` 꼴).
apk_set() { printf "sed -i '/^P:php83\$/,/^\$/ s/^V:.*/V:%s/' /lib/apk/db/installed && [ \"\$(sed -n '/^P:php83\$/,/^\$/ s/^V://p' /lib/apk/db/installed)\" = '%s' ]" "$1" "$1"; }
apk_rename() { # 이름 · 판
    printf "sed -i '/^P:php83\$/,/^\$/ s/^V:.*/V:%s/' /lib/apk/db/installed && sed -i 's/^P:php83\$/P:%s/' /lib/apk/db/installed && [ \"\$(sed -n '/^P:%s\$/,/^\$/ s/^V://p' /lib/apk/db/installed)\" = '%s' ]" "$2" "$1" "$1" "$2"
}
# 패키지가 깐 파일을 다른 글자로 바꾼다 — 패키지 기록(dpkg .md5sums · RPM 헤더의 다이제스트)과 달라진다.
changed() { printf "[ -f %s ] && echo remedy-harness-changed >%s && grep -q remedy-harness-changed %s" "$1" "$1" "$1"; }
# 판 문자열 없는 자리 채우기 — 글자 한 줄만 담은 파일(실행 파일이 아니다).
bin_put() { printf "mkdir -p %s && echo remedy-harness-placeholder >%s && [ -s %s ]" "$(dirname "$1")" "$1" "$1"; }
# 판 문자열 자리 채우기 — `x NUL <글> NUL x` 만 담은 파일. rules/php.yar 는 판 뒤 글자가 숫자 · 영문 · `-` 가 아니어야 정식 판으로
# 읽는다 — NUL 이 그 자리다(실제 실행 파일에서도 C 문자열 끝의 NUL 이다).
ver_put() { # 경로 · 담을 글(`X-Powered-By: PHP/<판>`)
    printf "mkdir -p %s && printf 'x\\\\000%s\\\\000x' >%s && [ -s %s ]" "$(dirname "$1")" "$2" "$1" "$1"
}
# 공식 이미지의 PHP 셋(php · php-cgi · libphp.so)을 직접 빌드 자리로 옮긴다(실행하지 않는다).
php_move() { # 접두사
    printf "mkdir -p %s/bin %s/lib && mv /usr/local/bin/php /usr/local/bin/php-cgi %s/bin/ && mv /usr/local/lib/libphp.so %s/lib/ && [ -f %s/bin/php ] && [ ! -e /usr/local/bin/php ]" \
        "$1" "$1" "$1" "$1" "$1"
}
# 픽스처를 제자리에 둔다 — 폴더를 만들고 복사한 뒤 비지 않았는지 본다.
put() { printf "mkdir -p %s && cp /b/fx/%s %s && [ -s %s ]" "$(dirname "$2")" "$1" "$2" "$2"; } # 픽스처 · 놓을 자리
# 있는 설정 파일 끝에 픽스처를 붙인다 — 마지막 줄에 줄바꿈이 없어도 붙지 않게 빈 줄을 먼저 넣는다.
append() { printf "[ -f %s ] && echo >>%s && cat /b/fx/%s >>%s && grep -q 'session.upload_progress.enabled' %s" "$2" "$2" "$1" "$2" "$2"; } # 픽스처 · 붙일 파일
deb_case() { run_case "$1" debian:12 "$2" "sh /b/deb-add.sh $3" "$4"; } # 이름 · 기대 · 'deb-add 인자(이름 원본 판)' · 메모
rpm_case() { run_case "$1" rocky9-rpmbuild "$2" "sh /b/rpm-put.sh $3" "$4"; } # 이름 · 기대 · 'rpm-put 인자' · 메모
RH="'Red Hat, Inc.'"
SUSE="'SUSE LLC <https://www.suse.com/>'"
FED="'Fedora Project'"
REMI="\"Remi's RPM repository <https://rpms.remirepo.net/>\""
# 고친 판 Debian — 스냅숏의 8.2.35 판 줄을 8.2.36-1~deb12u1 로(파일 · 설정은 그대로).
FIX82="$(deb_set 8.2 8.2.36-1~deb12u1)"
CONFD=/etc/php/8.2/fpm/conf.d/99-upload.ini
POOL=/etc/php/8.2/fpm/pool.d/www.conf
LCONFD=/usr/local/etc/php/conf.d/99-upload.ini
UNCOMMENT='sed -i "s/^;session[.]upload_progress[.]enabled = On/session.upload_progress.enabled = On/" /etc/php/8.2/fpm/php.ini && grep -qx "session.upload_progress.enabled = On" /etc/php/8.2/fpm/php.ini'

echo "── B. Debian 12 실제 설치 ──"
run_case b01-deb12-default "$DEB12" 6 ":" "깐 그대로(스냅숏 8.2.35-1~deb12u1 — 고친 판 전) · 설정 없음"
run_case b02-deb12-fixed "$DEB12" 0 "$FIX82" "판 줄 8.2.36-1~deb12u1(고친 판) · 설정 없음(php.ini 의 그 줄은 주석 — A1)"
run_case b03-deb12-fixed-on "$DEB12" 6 "$FIX82 && $(put ini-on.ini "$CONFD")" "고친 판 + fpm/conf.d 에서 켬"
run_case b04-deb12-fixed-off "$DEB12" 0 "$FIX82 && $(put ini-off.ini "$CONFD")" "고친 판 + 끔 — 끔은 0 을 막지 않는다"
run_case b05-deb12-vuln-off "$DEB12" 6 "$(put ini-off.ini "$CONFD")" "고친 판 전(8.2.35) + 끔"
run_case b06-deb12-vuln-on "$DEB12" 6 "$(put ini-on.ini "$CONFD")" "고친 판 전(8.2.35) + 켬"
run_case b07-deb12-fixed-uncomment "$DEB12" 6 "$FIX82 && $UNCOMMENT" "고친 판 + fpm/php.ini 의 주석 줄을 풀어 켬"
run_case b08-deb12-fixed-pool-on "$DEB12" 6 "$FIX82 && $(append pool-on.conf "$POOL")" "고친 판 + 풀(www.conf)의 php_admin_flag[…] = on"
run_case b09-deb12-fixed-pool-off "$DEB12" 0 "$FIX82 && $(append pool-off.conf "$POOL")" "고친 판 + 풀에서 끔"
run_case b10-deb12-fixed-cli-changed "$DEB12" 6 "$FIX82 && $(changed /usr/bin/php8.2)" "고친 판 · /usr/bin/php8.2 를 바꿈(패키지 기록과 다르다)"
run_case b11-deb12-fixed-fpm-changed "$DEB12" 6 "$FIX82 && $(changed /usr/sbin/php-fpm8.2)" "고친 판 · /usr/sbin/php-fpm8.2 를 바꿈"
run_case b12-deb12-fixed-other-changed "$DEB12" 0 "$FIX82 && $(changed /usr/bin/xargs)" \
    "고친 판 · PHP 와 상관없는 /usr/bin/xargs 를 바꿈 — PHP 실행 파일 자리만 본다"
run_case b13-deb12-fixed-on-and-off "$DEB12" 6 \
    "$FIX82 && $(put ini-on.ini /etc/php/8.2/cli/conf.d/99-upload.ini) && $(append pool-off.conf "$POOL")" \
    "고친 판 + CLI 에서 켬 · 풀에서 끔 — 켬이 하나라도 있으면"

echo "── K. 설정 꼴 — 고친 판 위에서 켬만 6 ──"
run_case k01-ini-1 "$DEB12" 6 "$FIX82 && $(put ini-1.ini "$CONFD")" "php.ini 꼴 = 1"
run_case k02-ini-quoted-on "$DEB12" 6 "$FIX82 && $(put ini-quoted-on.ini "$CONFD")" "= \"On\"(따옴표)"
run_case k03-ini-on-comment "$DEB12" 6 "$FIX82 && $(put ini-on-comment.ini "$CONFD")" "= On ; 주석(값 뒤의 주석)"
run_case k04-ini-true-nospace "$DEB12" 6 "$FIX82 && $(put ini-true-nospace.ini "$CONFD")" "=TRUE(빈칸 없음 · 대문자)"
run_case k05-pool-php-value-1 "$DEB12" 6 "$FIX82 && $(append pool-value-1.conf "$POOL")" "풀 꼴 php_value[…] = 1"
APACHE_FIXED="$(ver_put /usr/lib/apache2/modules/libphp.so 'X-Powered-By: PHP/8.2.36') && $(put php-mod.load /etc/apache2/mods-available/php.load)"
run_case k06-apache-on debian:12 6 "$APACHE_FIXED && $(put apache-on.conf /etc/apache2/conf-available/upload.conf)" \
    "고친 모듈(8.2.36 · 배포판 모듈 자리를 싣는 LoadModule) + Apache 줄 php_admin_flag … on"
run_case k07-apache-off debian:12 0 "$APACHE_FIXED && $(put apache-off.conf /etc/apache2/conf-available/upload.conf)" \
    "같은 자리 + php_admin_flag … off"
run_case k08-ini-off-forms "$DEB12" 0 "$FIX82 && $(put ini-off-forms.ini "$CONFD")" \
    "끄는 꼴 다섯(Off ; 주석 · 0 · 빈 값 · \"Off\" · none) · 이웃 키(cleanup = On 등) · 주석의 켬"

echo "── U. Ubuntu 24.04 ──"
run_case u01-u2404-default ubuntu2404 6 ":" "php-cli 깐 그대로 — 상류 8.3.6(고친 패키지도 백포트) · 설정 없음"

echo "── L. Alpine 3.22 — 판 줄을 칸마다 채운다 ──"
run_case l01-alpine-8336 alpine322 6 "$(apk_set 8.3.36-r0)" "php83 8.3.36-r0 — 고친 판 전"
run_case l02-alpine-8337 alpine322 0 "$(apk_set 8.3.37-r0)" "php83 8.3.37-r0 — 고친 판 · 설정 없음"
run_case l03-alpine-8337-on alpine322 6 "$(apk_set 8.3.37-r0) && $(put ini-on.ini /etc/php83/conf.d/99-upload.ini)" \
    "8.3.37-r0 + /etc/php83/conf.d 에서 켬"
run_case l04-alpine-php8-eol alpine322 6 "$(apk_rename php8 8.0.30-r0)" "이름 php8 8.0.30-r0 — 지원 끝(옛 Alpine 의 한 자리 이름)"

echo "── D. dpkg 판 줄 — 파일 없는 기록 칸 ──"
deb_case d01-deb-85-below 6 "php8.5-cli php8.5 8.5.12-1" "8.5 갈래 php8.5-cli — 고친 판(8.5.13) 바로 아래"
deb_case d02-deb-84-below 6 "php8.4-fpm php8.4 8.4.27-1~deb13u1" "8.4 갈래 php8.4-fpm(Debian 13 꼴) — 8.4.28 바로 아래"
deb_case d03-deb-83-below 6 "php8.3-cgi php8.3 8.3.36-1" "8.3 갈래 php8.3-cgi — 8.3.37 바로 아래"
deb_case d04-deb-82-mod-below 6 "libapache2-mod-php8.2 php8.2 8.2.35-1~deb12u1" "8.2 갈래 Apache 모듈 이름 — 8.2.36 바로 아래"
run_case d05-deb-at-all debian:12 0 \
    "sh /b/deb-add.sh php8.5-cli php8.5 8.5.13-1 && sh /b/deb-add.sh php8.4-fpm php8.4 8.4.28-1~deb13u1 && sh /b/deb-add.sh php8.3-cgi php8.3 8.3.37-1 && sh /b/deb-add.sh libapache2-mod-php8.2 php8.2 8.2.36-1~deb12u1 && sh /b/deb-add.sh php8.3-fpm php8.3 8.3.37-1+0~20261120.1+debian12~1.gbp1a2b3c" \
    "갈래 넷의 고친 판 그대로 + 다른 저장소(Sury 꼴)의 8.3.37 — 상류 판으로 센다"
deb_case d06-deb-u2404-backport 6 "php8.3-cli php8.3 8.3.6-0ubuntu0.24.04.14" \
    "Ubuntu 24.04 의 고친 패키지 꼴 — 상류 8.3.6 · 백포트는 고친 판으로 세지 않는다"
deb_case d07-deb-86-rc 0 "php8.6-cli php8.6 8.6.0~rc7-1" "다음 계열(8.6)의 시험판 패키지"
deb_case d08-deb-eol74 6 "php7.4-cli php7.4 7.4.33-1+deb11u8" "지원 끝 7.4(Debian 11 꼴) — 고친 판 없음"

echo "── R. RPM — 빈 rpm(이름 · 판 · 공급사) · RPM 설정 자리 ──"
rpm_case r01-rpm-85-below 6 "php-fpm 8.5.12 1.fc44 $FED" "8.5 갈래(Fedora 꼴) — 8.5.13 바로 아래"
rpm_case r02-rpm-84-mod-below 6 "apache2-mod_php8 8.4.27 160000.1.1 $SUSE" "8.4 갈래 · SUSE 의 Apache 모듈 이름 — 8.4.28 바로 아래"
rpm_case r03-rpm-83-below 6 "php-cli 8.3.36 1.el10_1 $RH" "8.3 갈래(RHEL 10 꼴) — 8.3.37 바로 아래"
rpm_case r04-rpm-82-below 6 "php-fpm 8.2.35 1.module+el8.10.0+25110+f67151d2 $RH" "8.2 갈래(RHEL 8 php:8.2) — 8.2.36 바로 아래"
rpm_case r05-rpm-at-all 0 \
    "php-fpm 8.5.13 1.fc44 $FED && sh /b/rpm-put.sh php8 8.4.28 160000.1.1 $SUSE && sh /b/rpm-put.sh php-cli 8.3.37 1.el10_1 $RH && sh /b/rpm-put.sh php 8.2.36 1.module+el8.10.0+26000+0a1b2c3d $RH && sh /b/rpm-put.sh php83-php-cli 8.3.37 1.el9.remi $REMI" \
    "갈래 넷의 고친 판 그대로(이름 php-fpm · php8 · php-cli · php) + Remi SCL php83-php-cli 8.3.37"
rpm_case r06-rpm-rhel9-backport 6 "php 8.0.30 8.el9_8.1 $RH" "RHEL 9.8 의 8.0.30(PHP2Shell 을 고친 빌드) — 지원 끝 8.0 · 백포트는 고친 판으로 세지 않는다"
rpm_case r07-rpm-scl-eol 6 "rh-php73-php-fpm 7.3.33 1.el7 $RH" "RHEL 7 의 SCL rh-php73 — 지원 끝"
rpm_case r08-rpm-86-rc 0 "php-cli 8.6.0~RC7 1.fc45 $FED" "다음 계열(8.6)의 시험판 패키지"
rpm_case r09-rpm-cfg-default 0 \
    "php-fpm 8.3.37 1.el10_1 $RH /usr/sbin/php-fpm && $(put php-rpm-off.ini /etc/php.ini) && $(put www-rhel.conf /etc/php-fpm.d/www.conf) && $(put fpm-conf-rhel.conf /etc/php-fpm.conf) && $(put httpd-php-off.conf /etc/httpd/conf.d/php.conf)" \
    "고친 php-fpm + RHEL 꼴 설정 넷(/etc/php.ini 끔 · 풀 · FPM 전역 · httpd 의 php.conf 끔) — 이웃 키는 켬이 아니다"
rpm_case r10-rpm-php-only-ini-on 6 "php 8.3.37 1.el10_1 $RH && $(put php-rpm-on.ini /etc/php.ini)" \
    "이름 php 만(php_pkg 밖 · rpm_php 가 문을 연다) + /etc/php.ini 켬(글롭 뿌리 /etc/php*.ini)"
rpm_case r11-rpm-php-d-on 6 "php-cli 8.3.37 1.el10_1 $RH && $(put ini-on.ini /etc/php.d/99-upload.ini)" "고친 php-cli + /etc/php.d 에서 켬"
rpm_case r12-rpm-pool-on 6 \
    "php-fpm 8.3.37 1.el10_1 $RH /usr/sbin/php-fpm && $(put www-rhel.conf /etc/php-fpm.d/www.conf) && $(append pool-on.conf /etc/php-fpm.d/www.conf)" \
    "고친 php-fpm + /etc/php-fpm.d/www.conf 에서 켬"
rpm_case r13-rpm-fpm-conf-on 6 "php-fpm 8.3.37 1.el10_1 $RH /usr/sbin/php-fpm && $(put fpm-conf-www-1.conf /etc/php-fpm.conf)" \
    "고친 php-fpm + /etc/php-fpm.conf 의 [www] 에서 켬(글롭 뿌리 /etc/php-fpm*.conf)"
rpm_case r14-rpm-httpd-on 6 \
    "php 8.3.37 1.el10_1 $RH /usr/lib64/httpd/modules/libphp.so && $(put httpd-php-on.conf /etc/httpd/conf.d/php.conf)" \
    "고친 php(httpd 모듈) + /etc/httpd/conf.d/php.conf 의 php_value … 1"
rpm_case r15-rpm-suse-on 6 "php8 8.4.28 160000.1.1 $SUSE && $(put ini-on.ini /etc/php8/cli/php.ini)" "고친 SUSE php8 + /etc/php8/cli/php.ini 켬"

echo "── F. RPM 자리의 파일 ──"
rpm_case f01-rpm-file-same 0 "php-cli 8.3.37 1.el10_1 $RH /usr/bin/php" "고친 php-cli 가 깐 /usr/bin/php — 기록과 같다"
rpm_case f02-rpm-file-changed 6 "php-cli 8.3.37 1.el10_1 $RH /usr/bin/php && $(changed /usr/bin/php)" \
    "그 /usr/bin/php 를 바꿈 — RPM 헤더의 다이제스트와 다르다"
rpm_case f03-rpm-unowned-cgi 6 "php-cli 8.3.37 1.el10_1 $RH && $(bin_put /usr/bin/php-cgi)" \
    "고친 php-cli 옆 · 어느 패키지도 깔지 않은 /usr/bin/php-cgi(0.6.1)"
rpm_case f04-rpm-unowned-sbin-fpm 6 "php-fpm 8.3.37 1.el10_1 $RH && $(bin_put /usr/sbin/php-fpm)" \
    "고친 php-fpm 옆 · 어느 패키지도 깔지 않은 /usr/sbin/php-fpm(0.6.1)"
rpm_case f05-rpm-merged-bin-echo 0 "php-fpm 8.5.13 1.fc44 $FED /usr/bin/php-fpm && cp /usr/bin/php-fpm /usr/sbin/php-fpm" \
    "패키지가 깐 /usr/bin/php-fpm + 소유 없는 /usr/sbin/php-fpm(합친 bin 의 메아리 꼴 · Fedora 42 이후) — 세지 않는다"
rpm_case f06-rpm-merged-bin-changed 6 "php-fpm 8.5.13 1.fc44 $FED /usr/bin/php-fpm && $(changed /usr/bin/php-fpm)" \
    "합친 bin 의 패키지 자리 /usr/bin/php-fpm 을 바꿈(0.6.1)"
rpm_case f07-rpm-other-pkg-bin 6 "ea-php-cli 8.3.37 1.el9 placeholder /usr/bin/php" \
    "PHP 가 아닌 이름의 패키지(ea-php-cli)가 깐 /usr/bin/php · RPM 의 PHP 패키지 없음"
rpm_case f08-rpm-other-pkg-local 6 "ea-php-cli 8.3.37 1.el9 placeholder /usr/local/bin/php" \
    "그 패키지가 깐 /usr/local/bin/php — 판을 볼 규칙이 하나도 서지 않는다"
rpm_case f09-rpm-module-same 0 "php 8.3.37 1.el10_1 $RH /usr/lib64/httpd/modules/libphp.so" "고친 php 가 깐 httpd 모듈 — 기록과 같다"
rpm_case f10-rpm-module-unowned 6 "php 8.3.37 1.el10_1 $RH && $(bin_put /usr/lib64/httpd/modules/libphp.so)" \
    "고친 php 옆 · 어느 패키지도 깔지 않은 httpd 모듈"

echo "── O. 공식 빌드 ──"
run_case o01-official-8337 php:8.3.37-cli 0 ":" "php:8.3.37-cli 그대로 — 고친 판 문자열(A5) · 설정 없음"
run_case o02-official-8337-confd-on php:8.3.37-cli 6 "$(put ini-on.ini "$LCONFD")" "8.3.37 + /usr/local/etc/php/conf.d 에서 켬"
run_case o03-official-8337-production-off php:8.3.37-cli 0 \
    "cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini && [ -s /usr/local/etc/php/php.ini ] && $(put ini-off.ini "$LCONFD")" \
    "8.3.37 + php.ini-production 을 php.ini 로(이미지 안내대로) + conf.d 에서 끔"
run_case o04-official-8337-fpm-d-on php:8.3.37-cli 6 "$(put pool-www-on.conf /usr/local/etc/php-fpm.d/zz-upload.conf)" \
    "8.3.37 + /usr/local/etc/php-fpm.d 의 풀에서 켬"
run_case o05-official-8337-fpm-conf-on php:8.3.37-cli 6 "$(put fpm-conf-www-1.conf /usr/local/etc/php-fpm.conf)" \
    "8.3.37 + /usr/local/etc/php-fpm.conf 의 [www] 에서 켬(글롭 뿌리)"
run_case o06-official-8336-cli php:8.3.36-cli 6 ":" "php:8.3.36-cli 그대로 — 고친 판 전 판 문자열(A6)"
run_case o07-official-8336-fpm-pool-off php:8.3.36-fpm 6 "$(put pool-www-off.conf /usr/local/etc/php-fpm.d/zz-upload.conf)" \
    "php:8.3.36-fpm + 풀에서 끔 — 고친 판 전(까닭 '끈 설정' · S6)"
run_case o08-official-8235-apache-off php:8.2.35-apache 6 "$(append apache-off.conf /etc/apache2/conf-available/docker-php.conf)" \
    "php:8.2.35-apache + docker-php.conf 에 Apache 줄로 끔 — 고친 판 전(까닭 '끈 설정' · S6)"
run_case o09-moved-8337-opt php:8.3.37-cli 0 "$(php_move /opt/php)" "8.3.37 을 /opt/php 로 옮김 — 직접 빌드 자리(본문을 담아 판 문자열을 읽는다)"
run_case o10-moved-8337-opt-ini-on php:8.3.37-cli 6 "$(php_move /opt/php) && $(put ini-on.ini /opt/php/lib/php.ini)" \
    "그 /opt/php/lib/php.ini 에서 켬(직접 빌드의 설정 자리 · 0.3.0)"
run_case o11-moved-8337-subdir php:8.3.37-cli 6 "$(php_move /opt/php/8.3)" \
    "8.3.37 을 /opt/php/8.3 으로 — 판마다 하위 폴더는 본문을 담지 않아 정식 판을 읽지 못한다"

echo "── X. 직접 빌드 — 판 문자열 자리 채우기 ──"
run_case x01-local-8428 debian:12 0 "$(ver_put /usr/local/bin/php 'X-Powered-By: PHP/8.4.28')" "/usr/local/bin/php 8.4.28 — 고친 판"
run_case x02-local-8427 debian:12 6 "$(ver_put /usr/local/bin/php 'X-Powered-By: PHP/8.4.27')" "/usr/local/bin/php 8.4.27"
run_case x03-usrlocal-php-noversion debian:12 6 "$(bin_put /usr/local/php/bin/php)" "/usr/local/php/bin/php 판 문자열 없음 · 설정 없음"
run_case x04-local-rc debian:12 6 "$(ver_put /usr/local/bin/php 'X-Powered-By: PHP/8.6.0RC7')" "8.6.0RC7 — 시험판은 정식 판으로 세지 않는다"
run_case x05-local-86 debian:12 0 "$(ver_put /usr/local/bin/php 'X-Powered-By: PHP/8.6.0')" "8.6.0 — 다음 계열의 정식 판 문자열"
run_case x06-opt-fpm-eol74 debian:12 6 "$(ver_put /opt/php/sbin/php-fpm 'X-Powered-By: PHP/7.4.33')" "/opt/php/sbin/php-fpm 7.4.33 — 지원 끝"
run_case x07-lib-module-8336 debian:12 6 "$(ver_put /usr/local/lib/libphp.so 'X-Powered-By: PHP/8.3.36')" "/usr/local/lib/libphp.so 8.3.36 — 모듈만"
run_case x08-lib-module-8337 debian:12 0 "$(ver_put /usr/local/lib/libphp.so 'X-Powered-By: PHP/8.3.37')" "/usr/local/lib/libphp.so 8.3.37"
run_case x09-apache-module-8236 debian:12 0 "$(ver_put /usr/lib/apache2/modules/libphp.so 'X-Powered-By: PHP/8.2.36')" \
    "/usr/lib/apache2/modules/libphp.so 8.2.36(공식 Apache 이미지의 자리)"
run_case x10-link-only debian:12 6 \
    "mkdir -p /srv/php/bin && echo remedy-harness-placeholder >/srv/php/bin/php && ln -s /srv/php/bin/php /usr/bin/php && [ -L /usr/bin/php ]" \
    "/usr/bin/php 가 자리 밖(/srv/php)으로 가는 링크만 — 판을 볼 규칙이 하나도 서지 않는다"
run_case x11-usrlocal-php-ini-on debian:12 6 \
    "$(ver_put /usr/local/php/bin/php 'X-Powered-By: PHP/8.4.28') && $(put ini-on.ini /usr/local/php/lib/php.ini)" \
    "고친 /usr/local/php + 그 lib/php.ini 에서 켬"
run_case x12-local-lib-ini-on debian:12 6 \
    "$(ver_put /usr/local/bin/php 'X-Powered-By: PHP/8.4.28') && $(put ini-on.ini /usr/local/lib/php.ini)" \
    "고친 /usr/local/bin/php + /usr/local/lib/php.ini(--prefix=/usr/local 의 설정 자리)에서 켬"
run_case x13-opt-pool-on debian:12 6 \
    "$(ver_put /opt/php/sbin/php-fpm 'X-Powered-By: PHP/8.4.28') && $(put pool-www-on.conf /opt/php/etc/php-fpm.d/www.conf)" \
    "고친 /opt/php/sbin/php-fpm + 그 etc/php-fpm.d 의 풀에서 켬"
run_case x14-mixed-noversion debian:12 6 "$(ver_put /usr/local/php/bin/php 'X-Powered-By: PHP/8.4.28') && $(bin_put /opt/php/bin/php)" \
    "8.4.28 + /opt/php/bin/php 판 없음 — 파일마다 가린다"
run_case x15-noversion-on debian:12 6 "$(bin_put /usr/local/php/bin/php) && $(put ini-on.ini /usr/local/php/lib/php.ini)" \
    "판 문자열 없음 + 켬 — 판 모름은 고치지 않음으로 센다"
run_case x16-noversion-off debian:12 6 "$(bin_put /usr/local/php/bin/php) && $(put ini-off.ini /usr/local/php/lib/php.ini)" \
    "판 문자열 없음 + 끔"

echo "── M. 섞임 ──"
run_case m01-deb-fixed-local-vuln "$DEB12" 6 "$FIX82 && $(ver_put /usr/local/bin/php 'X-Powered-By: PHP/8.3.36')" \
    "고친 Debian 패키지 + 고친 판 전 /usr/local/bin/php 8.3.36"
run_case m02-deb-fixed-local-fixed "$DEB12" 0 "$FIX82 && $(ver_put /usr/local/bin/php 'X-Powered-By: PHP/8.4.28')" \
    "고친 Debian 패키지 + 고친 /usr/local/bin/php 8.4.28 — 찾은 PHP 가 모두 고친 판"
rpm_case m03-rpm-fixed-local-noversion 6 "php-cli 8.3.37 1.el10_1 $RH && $(bin_put /usr/local/bin/php)" \
    "고친 RPM php-cli + 판 없는 /usr/local/bin/php"

echo "── P. 프로세스 · 서비스 ──"
run_case p01-outside-running debian:12 6 \
    "mkdir -p /srv/app && cp /bin/sleep /srv/app/php-fpm8.3 && (/srv/app/php-fpm8.3 600 &) && sleep 1 && ls -l /proc/[0-9]*/exe 2>/dev/null | grep -q ' /srv/app/php-fpm8.3\$'" \
    "자리 밖(/srv/app/php-fpm8.3)에서 돈다"
run_case p02-outside-lsphp debian:12 6 \
    "mkdir -p /usr/local/lsws/lsphp83/bin && cp /bin/sleep /usr/local/lsws/lsphp83/bin/lsphp && (/usr/local/lsws/lsphp83/bin/lsphp 600 &) && sleep 1 && ls -l /proc/[0-9]*/exe 2>/dev/null | grep -q ' /usr/local/lsws/lsphp83/bin/lsphp\$'" \
    "LiteSpeed 꼴 lsphp 가 자리 밖에서 돈다"
run_case p03-stale-exe php:8.3.37-cli 6 \
    "mkdir -p /usr/local/sbin && cp /bin/sleep /usr/local/sbin/php-fpm && (/usr/local/sbin/php-fpm 600 &) && sleep 1 && rm /usr/local/sbin/php-fpm && ls -l /proc/[0-9]*/exe 2>/dev/null | grep -q '/usr/local/sbin/php-fpm (deleted)'" \
    "고친 공식 빌드 + 지워진 실행 파일로 도는 PHP(다시 시작 안 함)"
# 실린 모듈은 maps 의 **실행 가능한** 매핑만 센다(remedy-platform linux.rs) — 코드가 있는 libm 사본을 싣고, 지운 뒤 r-xp 줄로 확인한다.
STALE_MOD='lib=$(ls /lib/*/libm.so.6 /usr/lib/*/libm.so.6 2>/dev/null | head -n 1) && [ -n "$lib" ] && mkdir -p /usr/lib/apache2/modules && cp "$lib" /usr/lib/apache2/modules/libphp8.2.so && cp /bin/sleep /usr/sbin/apache2 && (LD_PRELOAD=/usr/lib/apache2/modules/libphp8.2.so /usr/sbin/apache2 600 &) && sleep 1 && rm /usr/lib/apache2/modules/libphp8.2.so && grep -qs "r-xp .*/libphp8.2.so (deleted)" /proc/[0-9]*/maps'
run_case p04-stale-module "$DEB12" 6 "$FIX82 && $STALE_MOD" "고친 Debian 패키지 + 지워진 libphp8.2.so 를 실은 /usr/sbin/apache2(sleep 사본)"
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

echo "── C. Apache 설정 — LoadModule 줄 ──"
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
run_case n04-leftover-debian debian:12 0 "$(put ini-on.ini "$CONFD")" "PHP 를 지우고 남은 켠 설정(Debian 자리)"
run_case n05-leftover-rpm rockylinux:9 0 "$(put php-rpm-on.ini /etc/php.ini)" "PHP 를 지우고 남은 켠 /etc/php.ini(RPM 자리)"

echo "── S. 화면 ──"
has() { grep -qF -- "$2" "$OUT/cases/$1/screen.txt" 2>/dev/null; } # 경우 · 글
lacks() { [ -s "$OUT/cases/$1/screen.txt" ] && ! grep -qF -- "$2" "$OUT/cases/$1/screen.txt"; } # 화면이 있고 그 글이 없다
ON='session.upload_progress.enabled 가 켜져 있습니다'
OFF='session.upload_progress.enabled 를 끈 설정이 있습니다'
NONE='session.upload_progress.enabled 설정을 찾지 못했습니다'
FIXED_ON='고친 버전이지만 session.upload_progress.enabled 를 설정에서 직접 켰습니다'
UNFIXED='고친 버전으로 세지 않은 PHP 가 있습니다'
has b01-deb12-default "$NONE" && has b05-deb12-vuln-off "$OFF" && has b06-deb12-vuln-on "$ON" \
    && has b06-deb12-vuln-on "$UNFIXED" && a=1 || a=0
check "S1 고친 판 전의 까닭 셋 — 설정 없음 · 끔 · 켬" "$a" "b01 · b05 · b06 화면"
has x03-usrlocal-php-noversion "$NONE" && has x16-noversion-off "$OFF" && has x15-noversion-on "$ON" \
    && lacks x15-noversion-on "$FIXED_ON" && a=1 || a=0
check "S2 판을 읽지 못한 PHP 의 까닭 셋 — 고친 판 전과 같다" "$a" "x03 · x16 · x15 화면"
has b03-deb12-fixed-on "$FIXED_ON" && lacks b03-deb12-fixed-on "$UNFIXED" && lacks b06-deb12-vuln-on "$FIXED_ON" \
    && lacks b05-deb12-vuln-off "$ON" && lacks b05-deb12-vuln-off "$NONE" && a=1 || a=0
check "S3 고친 판인데 켬의 까닭 · 까닭이 겹치지 않는다" "$a" "b03 · b06 · b05 화면"
OUTSIDE_RUN='이 점검이 보는 자리 밖에서 PHP 가 실행 중입니다'
OUTSIDE_CFG='이 점검이 보는 자리 밖의 PHP 를 서비스가 띄우거나 Apache 설정이 싣습니다'
has p01-outside-running "$OUTSIDE_RUN" && has p05-unit-outside "$OUTSIDE_CFG" && has c01-deb-load-outside "$OUTSIDE_CFG" \
    && a=1 || a=0
check "S4 자리 밖 까닭 — 실행 중 · 서비스 · Apache 설정" "$a" "p01 · p05 · c01 화면"
grep -Eq '/etc/php/8\.2/fpm/conf\.d/99-upload\.ini:1 +\(값 On\)' \
        "$OUT/cases/b03-deb12-fixed-on/screen.txt" 2>/dev/null \
    && grep -Eq '/etc/php/8\.2/fpm/pool\.d/www\.conf:[0-9]+ +\(값 on\)' \
        "$OUT/cases/b08-deb12-fixed-pool-on/screen.txt" 2>/dev/null \
    && grep -Eq '/etc/apache2/conf-available/upload\.conf:2 +\(줄 *php_admin_flag session\.upload_progress\.enabled on\)' \
        "$OUT/cases/k06-apache-on/screen.txt" 2>/dev/null && a=1 || a=0
check "S5 항목 줄 — 켠 설정의 세 꼴(php.ini · 풀은 파일:줄 (값 …) · Apache 는 파일:줄 (줄 …))" "$a" "b03 · b08 · k06 화면"
has o07-official-8336-fpm-pool-off "$OFF" && lacks o07-official-8336-fpm-pool-off "$NONE" \
    && has o08-official-8235-apache-off "$OFF" && lacks o08-official-8235-apache-off "$NONE" \
    && has u01-u2404-default "$NONE" && a=1 || a=0
check "S6 실제 이미지의 설정 자리를 읽는다 — 공식 FPM 풀 · 공식 Apache 줄의 끔 · Ubuntu 기본" "$a" "o07 · o08 · u01 화면"
n=$(cat "$OUT"/cases/*/screen.txt 2>/dev/null | grep -c '미해소' || true)
[ "$n" = 0 ] && a=1 || a=0
check "S7 미해소 경고 0" "$a" "모든 경우의 화면에서 $n 줄"
# 고객 화면의 낱말 — 룰 문구에 내부 낱말('영향 판' · '고친 판' · '판을' · '갈래')이 없다(배포판 · 판정 · 판단은 센다 밖).
n=$(cat "$OUT"/cases/*/screen.txt 2>/dev/null | grep -c -e '영향 판' -e '고친 판' -e '판을 ' -e '갈래' || true)
[ "$n" = 0 ] && a=1 || a=0
check "S8 화면에 내부 낱말(판 · 갈래) 0" "$a" "모든 경우의 화면에서 $n 줄"

# 칸 수까지 본다 — 경우를 짓다 멈추면 남은 경우가 조용히 사라지고 "실패 0" 이 남는다.
EXPECTED=128 # A 8 · B 13 · K 8 · U 1 · L 4 · D 8 · R 15 · F 10 · O 11 · X 16 · M 3 · P 10 · C 8 · N 5 · 화면 8
pass=$(awk -F"$TAB" '$2 == 1' "$OUT/checks.tsv" | wc -l)
total=$(wc -l <"$OUT/checks.tsv")
[ "$total" = "$EXPECTED" ] || echo "칸 수 $total — 기대 $EXPECTED 와 다르다(경우를 짓다 멈췄거나, 칸을 더하고 EXPECTED 를 고치지 않았다)"
echo "── 합: $pass / $EXPECTED ──"
[ "$pass" = "$EXPECTED" ] && [ "$total" = "$EXPECTED" ]

# ── 경우 표 — id · 기대 · 재는 갈래(plugin.yaml 의 detect id · verdict.unconfirmed 의 줄. 0 은 RELEASE.md '0 을 내는 갈래' 의 줄) ──
#
# U1~U6 은 verdict.unconfirmed 의 줄 차례다 — U1 켬 · 고치지 않음 · U2 켬 · 고친 판 · U3 끔(켬 없음) · 고치지 않음 · U4 설정 없음 ·
# 고치지 않음 · U5 running_php · U6 service_php · apache_php · apache_php_rpm. '고치지 않음' 은 판 사실 덩이(deb_vuln_85 … stale_php ·
# 판을 볼 규칙이 서지 않은 php_bin)가 하나라도 선 것이다. U1~U4 는 PHP 문(php_pkg · php_bin · rpm_php)이 설 때만 본다.
#
#   b01 6  U4 — deb_vuln_82(8.2.35)                 b02 0  0 갈래 '고친 배포판 패키지' — deb_vuln_82 의 그 판 · 설정 없음
#   b03 6  U2 — upload_on(php.ini 꼴 · conf.d)       b04 0  같은 갈래 — upload_off 는 0 을 막지 않는다
#   b05 6  U3 — upload_off + deb_vuln_82            b06 6  U1 — upload_on + deb_vuln_82
#   b07 6  U2 — 주 설정 파일의 주석을 푼 켬          b08 6  U2 — 풀 꼴 key php_admin_flag[…]
#   b09 0  0 갈래 '고친 배포판 패키지' — 풀의 끔     b10 6  U4 — pkg_bin_changed(/usr/bin/php8.2)
#   b11 6  U4 — pkg_bin_changed(sbin/php-fpm8.2)    b12 0  0 갈래 '고친 배포판 패키지' — pkg_bin_changed 는 PHP 자리만
#   b13 6  U2 — 켬이 하나라도 있으면(끔이 함께여도)
#   k01~k04 6  U2 — upload_on 의 값 꼴(1 · "On" · On ; 주석 · =TRUE)
#   k05 6  U2 — 풀 꼴 php_value[…] = 1               k06 6  U2 — Apache 꼴(line) · apache_php 는 exclude(배포판 모듈 자리)
#   k07 0  0 갈래 '고친 패키지 밖 PHP' — Apache 꼴의 끔 · 모듈 자리 /usr/lib/apache2/modules/libphp.so
#   k08 0  0 갈래 '고친 배포판 패키지' — upload_off 의 꼴 다섯 · 이웃 키 · 주석은 켬이 아니다
#   u01 6  U4 — deb_vuln_83(상류 8.3.6 · 백포트)
#   l01 6  U4 — apk_vuln 8.3                        l02 0  0 갈래 '고친 배포판 패키지'(apk) — 8.3.37-r0
#   l03 6  U2 — /etc/php83                          l04 6  U4 — apk_vuln 지원 끝 · 이름 php8
#   d01~d04 6  U4 — deb_vuln_85 · deb_vuln_84 · deb_vuln_83 · deb_vuln_82(libapache2-mod-php8.2)
#   d05 0  0 갈래 '고친 배포판 패키지' — 네 갈래의 그 판 · 다른 저장소의 꼬리
#   d06 6  U4 — deb_vuln_83(백포트)                  d07 0  0 갈래 '다음 계열' — 배포판 패키지는 시험판도
#   d08 6  U4 — deb_eol
#   r01~r04 6  U4 — rpm_vuln 8.5 · 8.4(apache2-mod_php8 · 문은 rpm_php) · 8.3 · 8.2
#   r05 0  0 갈래 '고친 배포판 패키지'(RPM) — 네 갈래의 그 판 · SCL 이름
#   r06 6  U4 — rpm_vuln 지원 끝(8.0 · 문은 rpm_php)  r07 6  U4 — rpm_vuln 지원 끝 · SCL rh- 이름
#   r08 0  0 갈래 '다음 계열' — RPM 시험판
#   r09 0  0 갈래 '고친 배포판 패키지'(RPM) — RHEL 꼴 설정 넷의 이웃 키 · 끔 · /usr/sbin/php-fpm 은 패키지 것(bin_rpm 이고 rpm_php)
#   r10 6  U2 — 문을 rpm_php 만 연다 · 글롭 뿌리 /etc/php*.ini
#   r11 6  U2 — /etc/php.d                          r12 6  U2 — /etc/php-fpm.d
#   r13 6  U2 — 글롭 뿌리 /etc/php-fpm*.conf        r14 6  U2 — /etc/httpd 의 Apache 꼴(line)
#   r15 6  U2 — /etc/php8(SUSE)
#   f01 0  0 갈래 '고친 배포판 패키지'(RPM) — 패키지가 깐 실행 파일이 기록과 같다
#   f02 6  U4 — pkg_bin_changed(RPM 다이제스트)      f03 6  U4 — bin_rpm_unowned(0.6.1)
#   f04 6  U4 — sbin_fpm_unowned and not bin_fpm_owned(0.6.1)
#   f05 0  0 갈래 '고친 배포판 패키지'(RPM) — bin_fpm_owned 가 /usr/sbin/php-fpm 의 메아리를 뺀다(0.6.1)
#   f06 6  U4 — pkg_bin_changed(/usr/bin/php-fpm · 0.6.1)  f07 6  U4 — bin_rpm and not rpm_php
#   f08 6  U4 — php_bin and not (php_pkg or rpm_php or bin_php or bin_rpm) — 판 줄 밖 이름의 패키지가 깐 PHP
#   f09 0  0 갈래 '고친 배포판 패키지'(RPM) — httpd 모듈    f10 6  U4 — bin_rpm_unowned(httpd 모듈 자리)
#   o01 0  0 갈래 '고친 패키지 밖 PHP' — 공식 8.3.37     o02 6  U2 — /usr/local/etc/php
#   o03 0  같은 갈래 — 주석의 켬 줄 · conf.d 의 끔       o04 6  U2 — /usr/local/etc/php-fpm.d
#   o05 6  U2 — 글롭 뿌리 /usr/local/etc/php-fpm*.conf   o06 6  U4 — bin_vuln(8.3.36)
#   o07 6  U3 — 공식 FPM 풀의 끔 · bin_vuln             o08 6  U3 — 공식 Apache 의 끔 · bin_vuln(libphp.so)
#   o09 0  0 갈래 '고친 패키지 밖 PHP' — /opt/php        o10 6  U2 — 직접 빌드의 설정 자리 /opt/php
#   o11 6  U4 — bin_version_unknown(하위 폴더는 본문을 담지 않는다 · YARA 모름)
#   x01 0  0 갈래 '고친 패키지 밖 PHP' — /usr/local/bin  x02 6  U4 — bin_vuln
#   x03 6  U4 — bin_version_unknown                  x04 6  U4 — bin_version_unknown(시험판 · rules/php.yar 0.1.1)
#   x05 0  0 갈래 '다음 계열' — 정식 판 문자열 8.6.0     x06 6  U4 — bin_vuln(지원 끝 7.4)
#   x07 6  U4 — bin_vuln(모듈만 · 0.6.0)              x08 0  0 갈래 '고친 패키지 밖 PHP' — /usr/local/lib/libphp.so
#   x09 0  같은 갈래 — /usr/lib/apache2/modules/libphp.so   x10 6  U4 — php_bin and not (…) — 링크만(0.6.0)
#   x11~x13 6  U2 — 직접 빌드의 설정 자리(/usr/local/php · /usr/local/lib · /opt/php 의 풀)
#   x14 6  U4 — bin_version_unknown 은 파일마다 가린다   x15 6  U1 — 판 모름 + 켬   x16 6  U3 — 판 모름 + 끔
#   m01 6  U4 — 고친 패키지가 고치지 않은 다른 PHP 를 가리지 않는다    m02 0  0 갈래 '고친 배포판 패키지' · '고친 패키지 밖 PHP' 함께
#   m03 6  U4 — bin_version_unknown(RPM 옆의 /usr/local)
#   p01 6  U5 — running_php                          p02 6  U5 — running_php(lsphp)
#   p03 6  U4 — stale_php(실행 파일) · 고친 판 위     p04 6  U4 — stale_php(실린 모듈) · 고친 판 위
#   p05 6  U6 — service_php(systemd)                 p06 0  0 갈래 'PHP 가 없다' — service_php 의 exclude(배포판 자리)
#   p07 0  같은 갈래 — service_php 의 exclude(/opt/php)  p08~p10 6  U6 — service_php(SysV · Upstart · OpenRC)
#   c01 6  U6 — apache_php(Debian mods-available)    c02 0  0 갈래 'PHP 가 없다' — apache_php 의 exclude(/usr/lib/apache2/)
#   c03 6  U6 — apache_php(/usr/local/apache2/conf)  c04 6  U6 — apache_php(XAMPP)
#   c05 6  U6 — apache_php_rpm                       c06 0  같은 갈래 — apache_php_rpm 의 exclude(modules/)
#   c07 0  같은 갈래 — apache_php 의 exclude(/usr/lib64/apache2)   c08 0  같은 갈래 — apache_php 의 exclude(/opt/php/)
#   n01~n03 0  0 갈래 'PHP 가 없다'                   n04 · n05 0  같은 갈래 — 설정 파일만 남은 것(U1~U4 는 PHP 문이 설 때만)
