#!/bin/bash
# 긴급 출시의 출시 전 필수 점검 — 리눅스 몫(docs/긴급-대응.md).
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/emergency-checks.sh --new <정식 remedy-linux-x64.tar.gz> \
#        --prev <지난 공개본 remedy-linux-x64.tar.gz> --out <결과 폴더> --harness <새 룰의 하네스 스크립트 | none>
#
# `--new` 는 태그의 배포 잡이 올린 **초안을 내려받은 그 파일**이다 — 공개할 파일을 잰다. 같은 폴더에 받은 `SHA256SUMS` 가
# 있으면 그 줄로 체크섬도 잰다. `--prev` 는 지금 Latest 인 공개본이다. `--harness` 는 새 룰의 하네스
# (`testbed/harness/linux/<룰>-verify.sh` — `--bin` · `--plugins` · `--out` 을 받는 꼴)이고 정식 파일의 정적 실행 파일과
# **배포 키로 서명된** 룰로 돌린다. 리눅스 룰이 아니어서 돌릴 것이 없으면 `none` 을 **적는다** — 빠뜨린 것과 가른다.
# 호스트에 docker 와 debian:12 · ubuntu:24.04 이미지가 있어야 한다. 망은 쓰지 않는다.
#
# # 무엇을 재나
#
#   1  새 룰 하네스 — 그 하네스가 정한 칸이 모두 통과
#   2  정식 파일 — 체크섬(받은 `SHA256SUMS`), 엔진 · 동반 프로그램의 버전, 꾸러미에 든 룰 전부의 서명(`plugin verify`),
#      동반 프로그램이 판정 기준을 알아보는가(`url` · `image` · `container` 도움말의 기준 줄)
#   3  기존 동작 — 깨끗한 컨테이너(Debian 12 · Ubuntu 24.04)에서 지난 공개본과 이 파일의 메뉴 '모두 검사' 를 돌려
#      **종료 코드가 같아야 한다**. 화면은 버전 · 시각 · 회차 · 기계 이름을 가린 뒤의 차이를 남긴다 — 차이가 새 룰의
#      줄(메뉴 항목 · 번호 밀림 · 그 룰의 검사 덩어리 · 요약 한 줄)뿐인지 사람이 본다(`<결과>/scan-all/*.diff`)
#
# 결과 폴더에 단계마다 기록과 `summary.txt` 를 남긴다. 종료 코드: 0 = 1 · 2 · 3 의 기계 판정이 모두 통과, 1 = 하나라도
# 실패. 3 의 화면 차이는 판정하지 않는다 — `summary.txt` 의 줄 수와 diff 를 보고 정한다.
set -u

NEW=""
PREV=""
OUT=""
HARNESS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --new) NEW=$2; shift 2 ;;
        --prev) PREV=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --harness) HARNESS=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done
[ -f "$NEW" ] || { echo "--new <정식 tar.gz> 가 필요하다" >&2; exit 2; }
[ -f "$PREV" ] || { echo "--prev <지난 공개본 tar.gz> 가 필요하다" >&2; exit 2; }
[ -n "$OUT" ] || { echo "--out <결과 폴더> 가 필요하다" >&2; exit 2; }
[ -n "$HARNESS" ] || { echo "--harness <새 룰의 하네스 | none> 가 필요하다 — 리눅스 룰이 아니면 none 을 적는다" >&2; exit 2; }
[ "$HARNESS" = none ] || [ -f "$HARNESS" ] || { echo "--harness 가 없다: $HARNESS" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
for base in debian:12 ubuntu:24.04; do
    docker image inspect "$base" >/dev/null 2>&1 || { echo "$base 이미지가 없다 — docker pull $base" >&2; exit 2; }
done
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
SUM=$OUT/summary.txt
: >"$SUM"
note() { echo "$*" | tee -a "$SUM"; }

# 결과 폴더는 회차마다 새로 — 앞 회차의 컨테이너가 붙잡은 폴더를 지우고 다시 쓰면 도중에 사라질 수 있다.
W=$(mktemp -d /tmp/remedy-emergency.XXXXXX)
cleanup() { rm -rf "$W"; }
trap cleanup EXIT
mkdir -p "$W/new" "$W/prev"
tar -xzf "$NEW" -C "$W/new" --strip-components=1 || { echo "--new 를 풀지 못했다" >&2; exit 2; }
tar -xzf "$PREV" -C "$W/prev" --strip-components=1 || { echo "--prev 를 풀지 못했다" >&2; exit 2; }
fail=0
note "시작 $(date '+%Y-%m-%d %H:%M:%S') · 새 파일 $("$W/new/remedy" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+') · 지난 공개본 $("$W/prev/remedy" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+')"

# ── 1. 새 룰 하네스 ─────────────────────────────────────────────────────────────
if [ "$HARNESS" != none ]; then
    t0=$(date +%s)
    bash "$HARNESS" --bin "$W/new/remedy" --plugins "$W/new/plugins" --out "$OUT/harness" >"$OUT/harness.log" 2>&1
    rc=$?
    [ "$rc" = 0 ] || fail=1
    note "1 새 룰 하네스 · 종료 $rc · $(tail -n 1 "$OUT/harness/verdict.txt" 2>/dev/null) · $(( $(date +%s) - t0 ))초"
else
    note "1 새 룰 하네스 · 건너뜀(--harness none — 리눅스 룰이 아니다)"
fi

# ── 2. 정식 파일 — 체크섬 · 버전 · 서명 · 판정 기준 ────────────────────────────────────
sums="$(dirname "$NEW")/SHA256SUMS"
if [ -f "$sums" ]; then
    (cd "$(dirname "$NEW")" && grep " $(basename "$NEW")\$" SHA256SUMS | sha256sum -c -) >"$OUT/checksum.log" 2>&1
    rc=$?
    [ "$rc" = 0 ] || fail=1
    note "2 체크섬 · 종료 $rc · $(tail -n 1 "$OUT/checksum.log")"
else
    note "2 체크섬 · 받은 폴더에 SHA256SUMS 가 없다 — 받은 대로 손으로 잰다(docs/긴급-대응.md)"
fi
t0=$(date +%s)
docker run --rm --pull=never --network none -e REMEDY_LANG=en -v "$W/new:/p:ro" ubuntu:24.04 sh -c '
cd /p
./remedy --version 2>/dev/null | head -1
./remedy-net/remedy-net --version 2>&1 | head -1
bad=0
for d in plugins/*/; do ./remedy plugin verify --dir "$d" >/dev/null 2>&1; r=$?; echo "$d verify exit=$r"; [ "$r" = 0 ] || bad=1; done
for c in url image container; do
  out=$(./remedy-net/remedy-net "$c" --help 2>&1); r=$?
  echo "$out" | grep "Criteria:"
  echo "$c help exit=$r"
  [ "$r" = 0 ] || bad=1
done
exit $bad' >"$OUT/package.log" 2>&1
rc=$?
[ "$rc" = 0 ] || fail=1
rules=$(grep -c 'verify exit=' "$OUT/package.log")
note "2 정식 파일 · 종료 $rc · 룰 서명 $(grep -c 'verify exit=0' "$OUT/package.log")/$rules · $(( $(date +%s) - t0 ))초"

# ── 3. 기존 동작 — 지난 공개본과 '모두 검사' ─────────────────────────────────────────
mask() {
    sed -E -e 's/1\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?/V/g' \
        -e 's/[0-9]{8}T[0-9]{6}Z(-[0-9a-f]+)?/T/g' \
        -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+( UTC|Z)?/T/g' \
        -e 's/run-[0-9]+-[0-9a-f]+-[0-9a-f]+/RUN/g' \
        -e 's/[0-9]+(\.[0-9]+)? ?(ms|s|초)\b/D/g' \
        -e 's/실행 기계  : [^ ]+/실행 기계  : H/' "$1"
}
mkdir -p "$OUT/scan-all"
t0=$(date +%s)
for img in debian:12 ubuntu:24.04; do
    t=$(echo "$img" | tr ':/.' '___')
    for side in prev new; do
        # 메뉴 1번(모두 검사만 하기) → 끝나면 메뉴로 돌아오므로 빈 줄 · 0(그만두기)으로 닫는다.
        docker run --rm --pull=never --network none -v "$W/$side:/p:ro" -v "$OUT/scan-all:/out" "$img" sh -c \
            "cp -r /p /tmp/p && cd /tmp/p && { printf '1\n\n0\n'; sleep 8; } | LANG=C.UTF-8 REMEDY_LANG=ko timeout 300 script -q -e -c './remedy > /out/$t-$side.txt 2>&1' /dev/null; echo \$? > /out/$t-$side.rc; chmod a+r /out/$t-$side.*" \
            </dev/null >/dev/null 2>&1
    done
    rp=$(cat "$OUT/scan-all/$t-prev.rc" 2>/dev/null || echo 없음)
    rn=$(cat "$OUT/scan-all/$t-new.rc" 2>/dev/null || echo 없음)
    diff <(mask "$OUT/scan-all/$t-prev.txt") <(mask "$OUT/scan-all/$t-new.txt") >"$OUT/scan-all/$t.diff"
    [ "$rp" = "$rn" ] && [ "$rp" != 없음 ] || fail=1
    note "3 모두 검사 · $img · 지난 공개본 $rp · 새 파일 $rn · 화면 차이 $(grep -c '^[<>]' "$OUT/scan-all/$t.diff")줄"
done
note "3 모두 검사 · $(( $(date +%s) - t0 ))초 — 화면 차이는 $OUT/scan-all/*.diff 를 보고 새 룰의 줄뿐인지 정한다"

note "끝 $(date '+%Y-%m-%d %H:%M:%S') · 기계 판정 $([ "$fail" = 0 ] && echo 통과 || echo 실패)"
exit "$fail"
