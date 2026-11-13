#!/bin/bash
# rc 묶음 — 실제 sudo 로 동반 프로그램을 띄우는 경우들의 A/B(`rc-bundle.sh` · 안쪽은 `ab-sudo-inside.sh`).
#
#   bash testbed/harness/linux/rc/ab-sudo.sh <A tar.gz> <B tar.gz> <결과 폴더>
#
# debian:12 컨테이너 하나에서 A(지난 공개본)와 B 를 경우마다 새 사본으로 돌리고, 경우마다 종료 코드 · 화면 · out/ 의
# 소유자 트리를 견준다(버전 · 시각 · 회차 · 걸린 시간은 가린다). sudo 를 까는 데 망이 든다.
#
# summary.txt: 경우마다 `c<n>-이름 A=코드 B=코드 screen-diff=… tree-diff=…`. 메뉴에서 원격 항목의 번호(`net_item`)는
# 룰이 늘면 밀리므로 종료 코드 칸(`A=` · `B=`)으로 적지 않는다. c8(Ctrl+C)은 결과에 `"interrupted": true` 가 둘 다 있어야 한다.
set -u
A_TGZ=${1:?A tar.gz}
B_TGZ=${2:?B tar.gz}
RES=${3:?result folder}
S=$(cd "$(dirname "$0")" && pwd)
W=/tmp/remedy-sudo
rm -rf "$W"
mkdir -p "$W/a" "$W/b" "$RES"
tar -xzf "$A_TGZ" -C "$W/a" --strip-components=1 || { echo "A 를 풀지 못했다"; exit 9; }
tar -xzf "$B_TGZ" -C "$W/b" --strip-components=1 || { echo "B 를 풀지 못했다"; exit 9; }
docker run --rm --pull=never -v "$W/a:/pkgs/a:ro" -v "$W/b:/pkgs/b:ro" -v "$RES:/out" \
    -v "$S/ab-sudo-inside.sh:/inside.sh:ro" debian:12 bash /inside.sh
echo "container exit=$?"
mask() {
    sed -E -e 's/1\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?/V/g' \
        -e 's/[0-9]{8}T[0-9]{6}Z(-[0-9]+)?/T/g' \
        -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?/T/g' \
        -e 's/run-[0-9]+-[0-9a-f]+-[0-9a-f]+/RUN/g' \
        -e 's/remedy-net-url-[^ ]*\.json/R.json/g' \
        -e 's/[0-9]+(\.[0-9]+)? ?(ms|s|초)\b/D/g' "$1"
}
: > "$RES/summary.txt"
for c in $(awk '$1 ~ /^c[0-9]/ {print $1}' "$RES/a/codes.txt"); do
    ea=$(awk -v c="$c" '$1==c {print $2}' "$RES/a/codes.txt")
    eb=$(awk -v c="$c" '$1==c {print $2}' "$RES/b/codes.txt")
    k=${c%%-*}
    sd=$(diff <(mask "$RES/a/$k.txt") <(mask "$RES/b/$k.txt") | grep -c '^[<>]')
    td=none
    [ -f "$RES/a/$k.tree" ] && td=$(diff <(mask "$RES/a/$k.tree") <(mask "$RES/b/$k.tree") | grep -c '^[<>]')
    echo "$c A=$ea B=$eb screen-diff=$sd tree-diff=$td" | tee -a "$RES/summary.txt"
done
echo "net_item menu-number a:$(awk '$1=="net_item" {print $2}' "$RES/a/codes.txt") b:$(awk '$1=="net_item" {print $2}' "$RES/b/codes.txt")" | tee -a "$RES/summary.txt"
echo "c8 interrupted a:[$(tr '\n' ' ' < "$RES/a/c8.interrupted" 2> /dev/null)] b:[$(tr '\n' ' ' < "$RES/b/c8.interrupted" 2> /dev/null)]" | tee -a "$RES/summary.txt"
rm -rf "$W"
