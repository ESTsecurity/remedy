#!/bin/bash
# 룰: nginx2root-check-linux — 묶어 낸 출시(ci/batch.sh)가 바뀐 룰의 필수 점검 ① 로 이 하네스를 찾는다(--bin · --plugins · --out)
# 이미지: debian:12 ubuntu:24.04 rockylinux:9 alpine:3.22
# nginx2root 점검 룰(nginx2root-check-linux)을 배포판 컨테이너에서 잰다.
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/nginx-verify.sh --bin <remedy> --plugins <nginx2root-check-linux 가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--bin` 은 **musl 정적** remedy 다(Alpine 에서도 돈다 — 개발 빌드는 `musl-dev-build.sh`). `--plugins` 는
# `nginx2root-check-linux/` 를 담은 폴더다(저장소의 `plugins/` 나 내려받아 푼 꾸러미의 `plugins/`). 처음 한 번은 배포판
# 저장소에 닿아야 한다 — nginx 를 깐 이미지를 지어 두고(`remedy-harness/nginx:*`), 다음부터는 그 이미지를 쓴다.
#
# # 무해한가
#
# **실검체는 없다.** 이미지는 배포판 저장소의 nginx 를 그대로 깐 것이다. 그 밖의 경우는 **자리 채우기**다 — dpkg · apk 는
# 패키지 기록의 판 줄만 바꾸고, 직접 빌드는 서버 판 문자열(`nginx/<판>`)만 담은 작은 파일이다. 도는 프로세스가 필요한
# 경우는 `sleep` 을 nginx 이름으로 복사해 띄운다(nginx 를 띄우지 않는다). 경우마다 네트워크 없는 일회용 컨테이너에서
# remedy 가 읽기만 한다.
#
# # 무엇을 재나
#
#   A  이미지 4 — 깐 nginx 의 상류 판이 1.31.9 아래다(Debian 12 · Ubuntu 24.04 · Rocky 9 · Alpine 3.22 — 이 배포판들은
#      고친 판을 아직 내지 않았다 · 2026-11-19)
#   B  패키지 13 — 배포판 넷 깐 그대로 2 · nginx.org 꼴 1.31.8 2 · 1.31.9 0 · stable 1.30.7 0 · 1.30.6 2 · Alpine 1.31.9-r0 꼴
#      0 · Alpine 의 고친 꼴 1.30.7-r0 0 · Debian 1.31.9 꼴 0 · 1.29.x 2(고친 판 없는 갈래) · 옛 0.7.x 꼴 2
#   X  직접 빌드 9 — 1.31.8 2 · 1.31.9 0 · stable 1.30.7 0 · 1.30.6 2 · 판 없음 6 · /usr/sbin 의 1.26.3(패키지 아님) 2 ·
#      OpenResty(판 문자열이 다른 꼴) 6 · 1.9.4 2(메일 프록시는 0.5.33 부터) · Alpine 패키지가 있어도 다른 자리의 직접
#      빌드 2(Alpine 의 파일 기록에는 깐 패키지가 적히지 않아 /usr/sbin/nginx 는 패키지가 없을 때만 직접 빌드로 본다 — B 의
#      Alpine 1.31.9 꼴이 그것을 잰다)
#   P  프로세스 · 서비스 4 — 자리 밖에서 도는 nginx 6 · 자리 밖을 띄우는 서비스 6 · 지워진 실행 파일로 도는 nginx 6 ·
#      자리 안에서 도는 고친 판 0
#   F  목록 밖 패키지 1 — Debian 의 nginx 패키지 이름을 nginx-plus 로 바꾼 꼴(NGINX Plus 처럼 다른 이름의 패키지가
#      /usr/sbin/nginx 를 깐 기계) 6 — 0.1.0 은 0 이었다. RPM 쪽은 재지 않는다(패키지 DB 를 바꿀 수 없다)
#   N  nginx 없음 2 — Debian · Alpine 0
#   S  화면 6 — 취약 줄의 CVE 문구(머리 줄 빼고) · 확인 필요 까닭(판 없음 · 자리 밖 — 괄호의 영향 쪽과 고친 쪽 · 목록 밖
#      패키지의 까닭 줄) · 미해소 경고 0 · 옛 문구('1.31.9 아래면' · '1.31.9 또는 1.30.7 이상으로 올리') 0 · 배포판 패키지에는
#      목록 밖 패키지 줄이 서지 않는다 · 직접 빌드 취약 줄의 올릴 버전(stable 갈래는 1.30.7 이상)
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

RULE=nginx2root-check-linux
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일 · musl 정적> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/$RULE/plugin.yaml" ] || { echo "--plugins 에 $RULE 이 없다: $PLUGINS" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
for base in debian:12 ubuntu:24.04 rockylinux:9 alpine:3.22; do
    docker image inspect "$base" >/dev/null 2>&1 || { echo "$base 이미지가 없다 — docker pull $base" >&2; exit 2; }
done
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/nginx-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
: >"$OUT/checks.tsv"

check() { # 이름 · 1|0 · 메모
    if [ "$2" = 1 ]; then printf '  OK   %-58s %s\n' "$1" "$3"
    else printf '  실패 %-58s %s\n' "$1" "$3"; fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/checks.tsv"
}

# ── 이미지 — 배포판의 nginx 를 깐다(망이 필요한 것은 여기뿐) ─────────────────────────────────────────
IMG=remedy-harness/nginx
prepare() { # 꼬리표 · 바탕 이미지 · 설치 명령
    local tag=$1 base=$2 install=$3 name
    docker image inspect "$IMG:$tag" >/dev/null 2>&1 && return 0
    name="remedy-nginx-prep-$tag"
    docker rm -f "$name" >/dev/null 2>&1
    docker run --name "$name" "$base" sh -c "$install" >"$OUT/prepare-$tag.log" 2>&1 \
        && docker commit "$name" "$IMG:$tag" >/dev/null
    local rc=$?
    docker rm -f "$name" >/dev/null 2>&1
    return $rc
}
DEB='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nginx >/dev/null && dpkg-query -W nginx'
echo "── 이미지 ──"
prepare debian12 debian:12 "$DEB" || { echo "debian12 이미지를 짓지 못했다" >&2; exit 9; }
prepare ubuntu2404 ubuntu:24.04 "$DEB" || { echo "ubuntu2404 이미지를 짓지 못했다" >&2; exit 9; }
prepare rocky9 rockylinux:9 'dnf -y -q install nginx >/dev/null && rpm -q nginx' || { echo "rocky9 이미지를 짓지 못했다" >&2; exit 9; }
prepare alpine322 alpine:3.22 'apk add --no-cache -q nginx && apk info -v nginx' || { echo "alpine322 이미지를 짓지 못했다" >&2; exit 9; }

# 깐 판을 잰다 — 상류 판이 1.31.9 아래인지(배포판 자신의 비교로).
in_image() { docker run --rm --network none "$IMG:$1" sh -c "$2" 2>/dev/null; }
v=$(in_image debian12 "dpkg-query -W -f='\${Version}' nginx"); printf '%s' "$v" >"$OUT/installed-debian12.txt"
in_image debian12 "dpkg --compare-versions '$v' lt '1.31.9'" && a=1 || a=0
check "A1 Debian 12 의 nginx 가 1.31.9 아래" "$a" "$v"
v=$(in_image ubuntu2404 "dpkg-query -W -f='\${Version}' nginx"); printf '%s' "$v" >"$OUT/installed-ubuntu2404.txt"
in_image ubuntu2404 "dpkg --compare-versions '$v' lt '1.31.9'" && a=1 || a=0
check "A2 Ubuntu 24.04 의 nginx 가 1.31.9 아래" "$a" "$v"
v=$(in_image rocky9 "rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}' nginx"); printf '%s' "$v" >"$OUT/installed-rocky9.txt"
r=$(in_image rocky9 "rpm --eval '%{lua: print(rpm.vercmp(\"${v#*:}\", \"1.31.9\"))}'")
[ -n "$v" ] && [ "$r" = -1 ] && a=1 || a=0
check "A3 Rocky 9 의 nginx 가 1.31.9 아래" "$a" "$v"
v=$(in_image alpine322 "sed -n '/^P:nginx\$/,/^\$/ s/^V://p' /lib/apk/db/installed"); printf '%s' "$v" >"$OUT/installed-alpine322.txt"
[ -n "$v" ] && [ "$(in_image alpine322 "apk version -t '$v' '1.31.9-r0'")" = "<" ] && a=1 || a=0
check "A4 Alpine 3.22 의 nginx 가 1.31.9 아래" "$a" "$v"

# ── 경우 — 네트워크 없는 일회용 컨테이너 · 판 줄과 파일만 바꾼다 ─────────────────────────────────────
W=$(mktemp -d /tmp/remedy-nginx-verify.XXXXXX)
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

# 패키지 기록의 판 줄을 바꾸는 셸 한 줄 — nginx 의 실행 파일 패키지 칸 모두에서. 바꾼 뒤 그 판이 읽히는지 본다.
deb_set() { printf "sed -i -E '/^Package: nginx(-core|-full|-light|-extras)?\$/,/^\$/ s/^Version: .*/Version: %s/' /var/lib/dpkg/status && [ \"\$(dpkg-query -W -f='\${Version}' nginx)\" = '%s' ]" "$1" "$1"; }
apk_set() { printf "sed -i '/^P:nginx\$/,/^\$/ s/^V:.*/V:%s/' /lib/apk/db/installed && [ \"\$(sed -n '/^P:nginx\$/,/^\$/ s/^V://p' /lib/apk/db/installed)\" = '%s' ]" "$1" "$1"; }
# 직접 빌드 자리 채우기 — 판 문자열만 담은 파일(실행 파일이 아니다).
src_put() { printf "mkdir -p %s && printf 'x\\\\000%s\\\\000x' >%s/nginx && [ -s %s/nginx ]" "$1" "$2" "$1" "$1"; }
# Debian 의 nginx 패키지를 다른 이름(nginx-plus)으로 — 패키지 기록의 이름 줄과 dpkg 의 패키지별 파일(.md5sums 등)의 이름.
# remedy 는 .md5sums 의 파일 이름으로 파일의 패키지를 적는다(remedy-collect 의 owner.rs).
deb_rename() { printf "sed -i 's/^Package: nginx\$/Package: %s/' /var/lib/dpkg/status && for f in /var/lib/dpkg/info/nginx.*; do mv \"\$f\" \"/var/lib/dpkg/info/%s.\${f##*.}\"; done && grep -q ' usr/sbin/nginx\$' /var/lib/dpkg/info/%s.md5sums && dpkg-query -W %s >/dev/null" "$1" "$1" "$1" "$1"; }

echo "── B. 패키지 ──"
run_case b01-deb12-default debian12 2 ":" "깐 그대로 — 배포판 고친 판 없음"
run_case b02-u2404-default ubuntu2404 2 ":" "깐 그대로 — 배포판 고친 판 없음"
run_case b03-rocky9-default rocky9 2 ":" "깐 그대로 — 배포판 고친 판 없음"
run_case b04-alpine-default alpine322 2 ":" "깐 그대로 — 배포판 고친 판 없음"
run_case b05-nginxorg-1318 debian12 2 "$(deb_set 1.31.8-1~bookworm)" "nginx.org 꼴 1.31.8-1~bookworm"
run_case b06-nginxorg-1319 debian12 2 "$(deb_set 1.31.9-1~bookworm)" "nginx.org 꼴 1.31.9-1~bookworm"
run_case b07-debian-1319 debian12 0 "$(deb_set 1.31.9-1)" "Debian 꼴 1.31.9-1"
run_case b08-alpine-1319 alpine322 0 "$(apk_set 1.31.9-r0)" "Alpine 꼴 1.31.9-r0"
run_case b09-deb-old debian12 2 "$(deb_set 0.7.67-3)" "옛 0.7.67 — 메일 프록시 결함은 0.5.33 부터"
run_case b10-nginxorg-1307 debian12 0 "$(deb_set 1.30.7-1~bookworm)" "nginx.org stable 꼴 1.30.7 — 고친 판"
run_case b11-nginxorg-1306 debian12 2 "$(deb_set 1.30.6-1~bookworm)" "stable 1.30.6 — 고친 판 하나 아래"
run_case b12-alpine-1307 alpine322 0 "$(apk_set 1.30.7-r0)" "Alpine edge · 3.24 의 고친 꼴 1.30.7-r0"
run_case b13-deb-129 debian12 2 "$(deb_set 1.29.5-1)" "1.29.x — 고친 판이 없는 갈래"

echo "── X. 직접 빌드 ──"
run_case x01-src-1318 debian:12 2 "$(src_put /usr/local/nginx/sbin nginx/1.31.8)" "/usr/local/nginx/sbin/nginx 1.31.8"
run_case x02-src-1319 debian:12 0 "$(src_put /usr/local/nginx/sbin nginx/1.31.9)" "1.31.9 — 고친 판"
run_case x03-src-noversion debian:12 6 "$(src_put /opt/nginx/sbin no-version-here)" "/opt/nginx/sbin/nginx 판 문자열 없음"
run_case x04-usrsbin-nopkg alpine:3.22 2 "$(src_put /usr/sbin nginx/1.26.3)" "/usr/sbin/nginx 1.26.3 — 패키지가 깔지 않음"
run_case x05-openresty debian:12 6 "$(src_put /usr/local/openresty/nginx/sbin openresty/1.27.1.2)" "OpenResty — nginx/ 판 문자열이 없다"
run_case x06-src-194 debian:12 2 "$(src_put /usr/local/nginx/sbin nginx/1.9.4)" "1.9.4 — HTTP/2 전이지만 메일 프록시 결함 범위"
run_case x08-src-1307 debian:12 0 "$(src_put /usr/local/nginx/sbin nginx/1.30.7)" "stable 1.30.7 — 고친 판"
run_case x09-src-1306 debian:12 2 "$(src_put /usr/local/nginx/sbin nginx/1.30.6)" "stable 1.30.6"
# Alpine 의 파일 기록에는 깐 패키지가 적히지 않는다 — 패키지가 있으면 /usr/sbin/nginx 는 직접 빌드로 보지 않지만(b08),
# 다른 자리의 직접 빌드는 그대로 본다.
run_case x07-alpine-pkg-plus-src alpine322 2 "$(apk_set 1.31.9-r0) && $(src_put /opt/nginx/sbin nginx/1.26.0)" \
    "Alpine 패키지 1.31.9-r0 꼴 + /opt/nginx/sbin/nginx 1.26.0"

echo "── P. 프로세스 · 서비스 ──"
run_case p01-outside-running debian:12 6 \
    "mkdir -p /srv/app && cp /bin/sleep /srv/app/nginx && (/srv/app/nginx 600 &) && sleep 1" "자리 밖(/srv/app/nginx)에서 돈다"
run_case p02-outside-service debian:12 6 \
    "mkdir -p /etc/systemd/system && printf '[Service]\nExecStart=/srv/app/nginx -g daemon\\\\ off;\n' >/etc/systemd/system/nginx-alt.service" \
    "자리 밖을 띄우는 서비스(유닛 파일)"
run_case p03-stale-deleted debian:12 6 \
    "mkdir -p /usr/local/nginx/sbin && cp /bin/sleep /usr/local/nginx/sbin/nginx && (/usr/local/nginx/sbin/nginx 600 &) && sleep 1 && rm /usr/local/nginx/sbin/nginx" \
    "지워진 실행 파일로 돈다"
run_case p04-running-fixed debian:12 0 \
    "mkdir -p /usr/local/nginx/sbin && cp /bin/sleep /usr/local/nginx/sbin/nginx && printf 'nginx/1.31.9\\\\000' >>/usr/local/nginx/sbin/nginx && (/usr/local/nginx/sbin/nginx 600 &) && sleep 1" \
    "자리 안에서 도는 1.31.9"

echo "── F. 목록 밖 패키지 ──"
run_case f01-foreign-deb debian12 6 "$(deb_rename nginx-plus)" "nginx-plus 패키지가 깐 /usr/sbin/nginx — 판정하지 않고 알린다"

echo "── N. nginx 없음 ──"
run_case n01-none-debian debian:12 0 ":" "nginx 없음"
run_case n02-none-alpine alpine:3.22 0 ":" "nginx 없음"

echo "── S. 화면 ──"
s=$OUT/cases/b01-deb12-default/screen.txt
# 머리 줄(룰 이름)에도 CVE 가 있어 그 줄을 빼고 취약 줄의 문구를 본다.
grep -v "$RULE [0-9]" "$s" 2>/dev/null | grep -q 'nginx2root(CVE-2026-123007 외 넷)의 영향 판' && a=1 || a=0
check "S1 취약 줄의 CVE 문구" "$a" "b01 화면(머리 줄 빼고)"
# 까닭 괄호는 영향 쪽과 고친 쪽을 다 본다. 목록 밖 패키지는 라벨에도 같은 낱말이 있어 까닭에만 있는 문구를 본다.
hit='1.30.7 아래이거나 1.31.0 ~ 1.31.8'
fix='1.31.9 이상은 고친 판'
grep -q '판을 읽지 못했습니다' "$OUT/cases/x03-src-noversion/screen.txt" 2>/dev/null \
    && grep -q "$hit" "$OUT/cases/x03-src-noversion/screen.txt" 2>/dev/null \
    && grep -q "$fix" "$OUT/cases/x03-src-noversion/screen.txt" 2>/dev/null \
    && grep -q '이 룰이 보는 자리' "$OUT/cases/p01-outside-running/screen.txt" 2>/dev/null \
    && grep -q "$hit" "$OUT/cases/p01-outside-running/screen.txt" 2>/dev/null \
    && grep -q "$fix" "$OUT/cases/p01-outside-running/screen.txt" 2>/dev/null \
    && grep -q '이 룰이 판정하지 않습니다' "$OUT/cases/f01-foreign-deb/screen.txt" 2>/dev/null && a=1 || a=0
check "S2 확인 필요 까닭 — 판 없음 · 자리 밖 · 목록 밖 패키지" "$a" "x03 · p01 의 영향 · 고친 판 괄호 · f01 의 까닭 줄"
n=$(cat "$OUT"/cases/*/screen.txt 2>/dev/null | grep -c '미해소' || true)
[ "$n" = 0 ] && a=1 || a=0
check "S3 미해소 경고 0" "$a" "모든 경우의 화면에서 $n 줄"
n=$(cat "$OUT"/cases/*/screen.txt 2>/dev/null | grep -c -e '1.31.9 아래면' -e '1.31.9 또는 1.30.7 이상으로 올리' || true)
[ "$n" = 0 ] && a=1 || a=0
check "S4 옛 문구('1.31.9 아래면' · '1.31.9 또는 1.30.7 이상') 0" "$a" "모든 경우의 화면에서 $n 줄"
n=$(cat "$OUT"/cases/b0[1-3]-*/screen.txt 2>/dev/null | grep -c 'nginx 가 아닌 이름의 패키지' || true)
[ "$n" = 0 ] && a=1 || a=0
check "S5 배포판 패키지에 목록 밖 패키지 줄 없음" "$a" "b01 ~ b03 화면에서 $n 줄"
up='stable 갈래(1.30.x)는 1.30.7 이상으로 올리십시오'
grep -q "$up" "$OUT/cases/x01-src-1318/screen.txt" 2>/dev/null \
    && grep -q "$up" "$OUT/cases/x04-usrsbin-nopkg/screen.txt" 2>/dev/null && a=1 || a=0
check "S6 직접 빌드 취약 줄의 올릴 버전(stable 갈래)" "$a" "x01 · x04 화면"

pass=$(awk -F'\t' '$2 == 1' "$OUT/checks.tsv" | wc -l)
total=$(wc -l <"$OUT/checks.tsv")
echo "── 합: $pass / $total ──"
[ "$pass" = "$total" ]
# PR CI 시험 — 병합 전에 지운다
