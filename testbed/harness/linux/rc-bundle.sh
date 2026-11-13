#!/bin/bash
# 출시의 리눅스 rc 묶음 — 지난 공개본(A)과 이번 판(B)을 나란히 재는 17단계(docs/개발-안내.md "출시 검증").
#
# 호스트(WSL · 기본 사용자)에서, 저장소 루트:
#
#   bash testbed/harness/linux/rc-bundle.sh --new <이번 판 remedy-linux-x64.tar.gz> \
#        --prev <지난 공개본 remedy-linux-x64.tar.gz> --out <결과 폴더> [--inputs <입력 폴더>]
#
# `--new` 는 rc(평소 경로) 또는 공개한 판(긴급 경로의 미룬 검증)을 **내려받은 그 파일**이고, `--prev` 는 지금 Latest 의
# 앞 공개본이다. 빌드는 하지 않는다 — 단계마다 내려받은 실행 파일을 일회용 컨테이너에서 돌린다. `--inputs` 는 시료를 두는
# 폴더다(기본 `testbed/harness/results/rc-inputs` — 커밋하지 않는 자리): `jars/` 는 log4j 하네스가 Maven Central 에서
# 받고(없는 것만), `images/` 는 원격 A/B 가 읽는 이미지 tar 여덟을 `rc/save-images.sh` 가 만든다(없는 것만). Windows 랩
# 묶음(`host/Invoke-RcBundle.ps1`)도 같은 폴더를 읽으므로 **리눅스를 먼저** 돌린다.
#
# 망이 든다 — 설치 경우의 apt · dnf · yum · apk 와 처음 받는 jar · 이미지. 하네스 이미지(OpenSSH · Apache)는 처음 한 번
# 짓는다. 그 밖의 이미지는 미리 받아 둔다(없으면 멈추고 `docker pull` 할 것을 적는다). **Windows 랩 묶음과 겹쳐 돌리지
# 않는다**(메모리가 모자라 링커 · WSL 이 죽은 일이 있다). 끝나면 root 로 WSL 페이지 캐시를 비운다:
# `wsl -u root -e sh -c 'echo 3 > /proc/sys/vm/drop_caches'`.
#
# # 단계
#
#   하네스    engine(invoke-linux-verify) · cwpdoor(메뉴 Ctrl+C 포함) · ebury · log4j · openssh · apache · tomcat —
#             B 의 정적 실행 파일과 B 꾸러미의 **배포 키로 서명된** 룰로. 새 룰에 하네스가 생기면 여기에 한 줄 더한다
#   A/B       ab-installs(실제 설치 21) · ab-changed(패키지와 다른 실행 파일) · ab-outside(선언 밖 · 도는 프로세스) ·
#             stale(지워진 옛 파일) · sources(systemd 유닛) · init(SysV · OpenRC · Upstart · Apache 설정) ·
#             sudo-ab(실제 sudo 로 동반 프로그램 띄우기) · net-ab(remedy-net url · image · container)
#   그 밖     centos7(glibc 2.17 에서 정적 실행 파일 · 메뉴 없이 원격 점검 → 6) · net-no-criteria(판정 기준 폴더가 없으면
#             약관 전에 4)
#
# # 판정
#
# 하네스는 제 종료 코드(0 = 칸 모두 통과). A/B 는 단계의 summary.txt 의 `A=코드 B=코드` 짝이 **모두 같아야** 하고 준비
# 실패(`setup=failed`) · 컨테이너 실패(`docker=1` 이상)가 없어야 한다. 화면 · JSON 차이(`screen-diff` · `json-diff`)는
# 판정하지 않는다 — 새 룰의 줄(메뉴 번호 밀림 등)뿐인지 사람이 본다. 결과 폴더의 `summary.txt` 가 단계마다
# `통과 · 다름 · 실패` 를 적는다. 종료 코드: 0 = 모두 통과 · 1 = 실패나 다름이 있다(다름은 의도한 변경인지 본다 —
# 룰만 바꾼 출시라면 다름도 실패다) · 2 = 인자 · 준비가 모자라 시작하지 않았다.
set -u

NEW=""
PREV=""
OUT=""
INPUTS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --new) NEW=$2; shift 2 ;;
        --prev) PREV=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --inputs) INPUTS=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done
[ -f "$NEW" ] || { echo "--new <이번 판 tar.gz> 가 필요하다" >&2; exit 2; }
[ -f "$PREV" ] || { echo "--prev <지난 공개본 tar.gz> 가 필요하다" >&2; exit 2; }
[ -n "$OUT" ] || { echo "--out <결과 폴더> 가 필요하다" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
[ -n "$INPUTS" ] || INPUTS="$REPO/testbed/harness/results/rc-inputs"
NEW=$(cd "$(dirname "$NEW")" && pwd)/$(basename "$NEW")
PREV=$(cd "$(dirname "$PREV")" && pwd)/$(basename "$PREV")

command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
# rc/ 단계와 이 파일이 --pull=never 로 쓰는 이미지. 하네스는 제 이미지를 스스로 확인한다.
NEED="debian:12 ubuntu:24.04 alpine:3.22 centos:7 almalinux:8 rockylinux:8 rockylinux:9 oraclelinux:8 oraclelinux:9
amazonlinux:2 amazonlinux:2023 opensuse/leap:15.6 registry.access.redhat.com/ubi9/ubi:latest php:8.3.35-cli php:8.3.36-cli
php:8.3.36-fpm php:8.2-apache node:22.18.0-bookworm-slim node:22.23.4-bookworm-slim tomcat:9.0-jdk11 docker:dind"
missing=""
for i in $NEED; do docker image inspect "$i" >/dev/null 2>&1 || missing="$missing $i"; done
if [ -n "$missing" ]; then
    echo "이미지가 없다 — 받고 다시 돌린다:" >&2
    for i in $missing; do echo "  docker pull $i" >&2; done
    exit 2
fi

mkdir -p "$OUT" "$INPUTS/jars"
OUT=$(cd "$OUT" && pwd)
INPUTS=$(cd "$INPUTS" && pwd)
SUM=$OUT/summary.txt
: >"$SUM"
note() { echo "$*" | tee -a "$SUM"; }
FAILED=""
DIFFERS=""

IMAGES="$INPUTS/images"
TARS="node-22.23.4 alpine-3.22 ubuntu-24.04 oraclelinux-9 php-8.3.36-cli php-8.2-apache php-8.3.35-cli node-22.18.0"
for t in $TARS; do
    [ -s "$IMAGES/$t.tar" ] && continue
    echo "이미지 tar 를 만든다: $IMAGES"
    bash "$HERE/rc/save-images.sh" "$IMAGES" >"$OUT/save-images.log" 2>&1 || {
        echo "이미지 tar 를 만들지 못했다 — $OUT/save-images.log" >&2
        exit 2
    }
    break
done

# B 를 한 번 풀어 둔다 — 하네스와 폴더를 받는 A/B 가 쓴다. 컨테이너가 root 로 쓰지 않는 자리다.
X=$(mktemp -d /tmp/remedy-rc.XXXXXX)
cleanup() { rm -rf "$X"; }
trap cleanup EXIT
tar -xzf "$NEW" -C "$X" --strip-components=1 || { echo "--new 를 풀지 못했다" >&2; exit 2; }
mkdir -p "$X.prev" && tar -xzf "$PREV" -C "$X.prev" --strip-components=1 || { rm -rf "$X.prev"; echo "--prev 를 풀지 못했다" >&2; exit 2; }
PREV_VERSION=$("$X.prev/remedy" --version 2>/dev/null | head -1)
rm -rf "$X.prev"
note "시작 $(date '+%Y-%m-%d %H:%M:%S') · 이번 판 $("$X/remedy" --version 2>/dev/null | head -1) · 지난 공개본 $PREV_VERSION"

# 단계 하나: 이름 · 판정 함수 · 명령… — 기록은 <결과>/<이름>.log, 자세한 결과는 <결과>/<이름>/
step() {
    local name=$1 judge=$2 t0 rc verdict memo
    shift 2
    t0=$(date +%s)
    (cd "$REPO" && "$@") >"$OUT/$name.log" 2>&1
    rc=$?
    memo=$("$judge" "$name" "$rc")
    case $? in
        0) verdict=통과 ;;
        3) verdict=다름; DIFFERS="$DIFFERS $name" ;;
        *) verdict=실패; FAILED="$FAILED $name" ;;
    esac
    note "$name $verdict exit=$rc $(( $(date +%s) - t0 ))s $(date +%H:%M:%S) $memo"
}
# 하네스: 제 종료 코드. 기록의 마지막 `통과 N · 실패 M` 줄을 메모로 남긴다.
by_exit() {
    grep -oE '통과 [0-9]+ · 실패 [0-9]+.*' "$OUT/$1.log" 2>/dev/null | tail -1
    [ "$2" = 0 ]
}
# A/B: 단계의 summary.txt 에서 종료 코드 짝(`A=코드 B=코드`)을 견준다.
# 0 = 모두 같다 · 3 = 다른 짝이 있다 · 1 = 잰 것이 없다 · 빈 칸이 있다 · 준비나 컨테이너가 실패했다
by_pairs() {
    local s="$OUT/$1/summary.txt" all pairs blank differ setup dock
    [ -s "$s" ] || { echo "summary.txt 가 없다"; return 1; }
    all=$(grep -oE '(^|[ |])A=[^ |]* B=[^ |]*' "$s" | sed -E 's/^[ |]//')
    pairs=$(printf '%s\n' "$all" | grep -c .)
    blank=$(printf '%s\n' "$all" | grep . | grep -vcE '^A=-?[0-9]+ B=-?[0-9]+$')
    differ=$(printf '%s\n' "$all" | grep -E '^A=-?[0-9]+ B=-?[0-9]+$' | sed -E 's/^A=(-?[0-9]+) B=(-?[0-9]+)$/\1 \2/' |
        awk '$1 != $2' | wc -l)
    setup=$(grep -c 'setup=failed' "$s")
    dock=$(grep -cE 'docker=[1-9]' "$s")
    echo "짝 $pairs · 다름 $differ · 빈 칸 $blank · 준비 실패 $setup · 컨테이너 실패 $dock"
    [ "$pairs" -gt 0 ] && [ "$blank" = 0 ] && [ "$setup" = 0 ] && [ "$dock" = 0 ] || return 1
    [ "$differ" = 0 ] || return 3
}
by_sudo() {
    local memo rc
    memo=$(by_pairs "$1" "$2")
    rc=$?
    local c8
    c8=$(grep '^c8 interrupted' "$OUT/$1/summary.txt" 2>/dev/null | grep -o '"interrupted": *true' | wc -l)
    echo "$memo · c8 중단 기록 $c8/2"
    [ "$c8" = 2 ] || return 1
    return "$rc"
}
by_net() {
    local memo rc
    memo=$(by_pairs "$1" "$2")
    rc=$?
    grep -q '^same [0-9]* · different 0$' "$OUT/$1/summary.txt" || { echo "$memo · 화면이나 JSON 이 다른 경우가 있다"; [ "$rc" = 1 ] && return 1; return 3; }
    echo "$memo"
    return "$rc"
}
by_centos7() { grep -q '^scan exit 6$' "$OUT/$1.log" && grep -q '^result file ok$' "$OUT/$1.log"; }
by_no_criteria() { grep -q '^url exit 4$' "$OUT/$1.log" && grep -q '^no result folder$' "$OUT/$1.log"; }

L=testbed/harness/linux
step engine by_exit bash $L/invoke-linux-verify.sh --bin "$X/remedy" --tag rc-engine
step cwpdoor by_exit bash $L/cwpdoor-verify.sh --bin "$X/remedy" --plugins "$X/plugins" --menu-ctrlc --out "$OUT/cwpdoor"
step ebury by_exit bash $L/ebury-verify.sh --bin "$X/remedy" --plugins "$X/plugins" --out "$OUT/ebury"
step log4j by_exit bash $L/log4j-verify.sh --bin "$X/remedy" --plugins "$X/plugins" --jars "$INPUTS/jars" --out "$OUT/log4j"
step openssh by_exit bash $L/openssh-verify.sh --bin "$X/remedy" --plugins "$X/plugins" --out "$OUT/openssh"
step apache by_exit bash $L/apache-verify.sh --bin "$X/remedy" --plugins "$X/plugins" --out "$OUT/apache"
step tomcat by_exit bash $L/rc/tomcat.sh "$X" "$INPUTS/jars" "$OUT/tomcat"
step ab-installs by_pairs bash $L/rc/ab-installs.sh "$PREV" "$NEW" "$OUT/ab-installs"
step ab-changed by_pairs env OL_IMAGE=oraclelinux:8 bash $L/rc/ab-changed.sh "$PREV" "$X" "$OUT/ab-changed"
step ab-outside by_pairs bash $L/rc/ab-outside.sh "$PREV" "$NEW" "$OUT/ab-outside"
step stale by_pairs bash $L/rc/ab-stale.sh "$PREV" "$X" "$OUT/stale"
step sources by_pairs bash $L/rc/ab-sources.sh "$PREV" "$X" "$OUT/sources"
step init by_pairs bash $L/rc/ab-init.sh "$PREV" "$X" "$OUT/init"
step sudo-ab by_sudo bash $L/rc/ab-sudo.sh "$PREV" "$NEW" "$OUT/sudo-ab"
# CentOS 7(glibc 2.17): 정적 실행 파일이 돈다 · 메뉴 없는 원격 점검은 동반 프로그램을 거쳐 6
step centos7 by_centos7 docker run --rm --pull=never -v "$X:/p:ro" centos:7 sh -c \
    'cd /tmp && /p/remedy-net/remedy-net --version | grep -m1 -E "[0-9]+\.[0-9]+"; cp -r /p /tmp/p && cd /tmp/p && ./remedy scan --plugin plugins/php2shell-url-check/plugin.yaml --out-dir /tmp/o --url http://127.0.0.1:9/ --consent y; echo "scan exit $?"; ls /tmp/o/remedy-net-url-*.json > /dev/null && echo "result file ok"'
step net-ab by_net bash $L/rc/ab-net.sh "$PREV" "$NEW" "$IMAGES" "$OUT/net-ab"
# 판정 기준 폴더가 없는 꾸러미 — 동반 프로그램이 약관 전에 4 로 거절해야 한다
step net-no-criteria by_no_criteria docker run --rm --pull=never -v "$X:/p:ro" debian:12 sh -c \
    'cp -r /p /tmp/p && rm -rf /tmp/p/plugins/remedy-net-criteria && cd /tmp/p && ./remedy-net/remedy-net url --url http://127.0.0.1:9/ --consent y --out-dir /tmp/o; echo "url exit $?"; [ -e /tmp/o ] && echo "result folder exists" || echo "no result folder"'

if [ -z "$FAILED$DIFFERS" ]; then
    note "끝 $(date '+%Y-%m-%d %H:%M:%S') · 모두 통과"
    exit 0
fi
note "끝 $(date '+%Y-%m-%d %H:%M:%S') ·${FAILED:+ 실패:$FAILED}${DIFFERS:+ · 다름:$DIFFERS}"
note "다름은 그 단계의 summary.txt 에서 A 와 B 가 다른 줄을 보고 의도한 변경인지 정한다"
exit 1
