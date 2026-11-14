#!/bin/bash
# 평소 경로의 최종 확인 — 정식 태그가 올린 초안의 리눅스 꾸러미를 잰다(docs/개발-안내.md "출시 검증").
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/release-final-check.sh --final <정식 remedy-linux-x64.tar.gz> \
#        --rc <rc 묶음을 돌린 remedy-linux-x64.tar.gz> --out <결과 폴더>
#
# `--final` 은 정식 태그의 배포 잡이 올린 **초안을 내려받은 그 파일**이다. 같은 폴더에 받은 `SHA256SUMS` 가 있으면 그
# 줄로 체크섬을 잰다. `--rc` 는 rc 묶음이 잰 rc 의 같은 파일이다 — 같은 판 · 같은 커밋이면 정식과 rc 는 **서명 파일
# 말고는 바이트까지 같다**(실행 파일도 — musl 정적). 그래서 rc 묶음의 결과가 정식 파일의 결과가 된다. 망은 쓰지 않는다
# (ubuntu:24.04 이미지).
#
#   1  체크섬 — 받은 `SHA256SUMS`
#   2  정식 파일 — 엔진 · 동반 프로그램의 버전, 꾸러미에 든 룰 전부와 동반 프로그램 폴더의 서명(`plugin verify`), 동반
#      프로그램이 판정 기준을 알아보는가(`url` · `image` · `container` 도움말의 기준 줄)
#   3  rc 와 같은가 — 파일마다 바이트 대조. 서명 파일(`MANIFEST.minisig`)은 서명 주석이 같은지 본다 — minisign 이
#      서명마다 난수를 섞어 같은 키 · 같은 내용이라도 서명 값이 다르다(v1.16.0 에서 처음 쟀다). 그 서명이 맞는지는 2 가
#      잰다. 다른 파일 · 한쪽에만 있는 파일이 0 이어야 한다
#
# 결과 폴더에 `summary.txt` 를 남긴다. 종료 코드: 0 = 셋 모두 통과 · 1 = 하나라도 실패 · 2 = 인자가 모자라다.
set -u

FINAL=""
RC=""
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --final) FINAL=$2; shift 2 ;;
        --rc) RC=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done
[ -f "$FINAL" ] || { echo "--final <정식 tar.gz> 가 필요하다" >&2; exit 2; }
[ -f "$RC" ] || { echo "--rc <rc tar.gz> 가 필요하다" >&2; exit 2; }
[ -n "$OUT" ] || { echo "--out <결과 폴더> 가 필요하다" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
docker image inspect ubuntu:24.04 >/dev/null 2>&1 || { echo "ubuntu:24.04 이미지가 없다 — docker pull ubuntu:24.04" >&2; exit 2; }
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
SUM=$OUT/summary.txt
: >"$SUM"
note() { echo "$*" | tee -a "$SUM"; }

W=$(mktemp -d /tmp/remedy-final-check.XXXXXX)
cleanup() { rm -rf "$W"; }
trap cleanup EXIT
mkdir -p "$W/final" "$W/rc"
tar -xzf "$FINAL" -C "$W/final" --strip-components=1 || { echo "--final 을 풀지 못했다" >&2; exit 2; }
tar -xzf "$RC" -C "$W/rc" --strip-components=1 || { echo "--rc 를 풀지 못했다" >&2; exit 2; }
fail=0
note "시작 $(date '+%Y-%m-%d %H:%M:%S') · 정식 $("$W/final/remedy" --version 2>/dev/null | head -1)"

# ── 1. 체크섬 ──────────────────────────────────────────────────────────────────
sums="$(dirname "$FINAL")/SHA256SUMS"
if [ -f "$sums" ]; then
    (cd "$(dirname "$FINAL")" && grep " $(basename "$FINAL")\$" SHA256SUMS | sha256sum -c -) >"$OUT/checksum.log" 2>&1
    rc=$?
    [ "$rc" = 0 ] || fail=1
    note "1 체크섬 · 종료 $rc · $(tail -n 1 "$OUT/checksum.log")"
else
    fail=1
    note "1 체크섬 · 받은 폴더에 SHA256SUMS 가 없다 — 릴리스의 SHA256SUMS 를 같은 폴더에 받는다"
fi

# ── 2. 정식 파일 — 버전 · 서명 · 판정 기준 ──────────────────────────────────────────
docker run --rm --pull=never --network none -e REMEDY_LANG=en -v "$W/final:/p:ro" ubuntu:24.04 sh -c '
cd /p
./remedy --version 2>/dev/null | head -1
./remedy-net/remedy-net --version 2>&1 | head -1
bad=0
for d in plugins/*/ remedy-net/; do ./remedy plugin verify --dir "$d" >/dev/null 2>&1; r=$?; echo "$d verify exit=$r"; [ "$r" = 0 ] || bad=1; done
for c in url image container; do
  out=$(./remedy-net/remedy-net "$c" --help 2>&1); r=$?
  echo "$out" | grep "Criteria:"
  echo "$c help exit=$r"
  [ "$r" = 0 ] || bad=1
done
exit $bad' >"$OUT/package.log" 2>&1
rc=$?
rules=$(grep -c 'verify exit=' "$OUT/package.log")
crit=$(grep -c '^Criteria:' "$OUT/package.log")
{ [ "$rc" = 0 ] && [ "$rules" -gt 0 ] && [ "$crit" = 3 ]; } || fail=1
note "2 정식 파일 · 종료 $rc · 서명(룰 · 동반 프로그램) $(grep -c 'verify exit=0' "$OUT/package.log")/$rules · 판정 기준 줄 $crit/3"

# ── 3. rc 와 같은가 ────────────────────────────────────────────────────────────
# 서명 파일만은 바이트가 같을 수 없다 — 서명 주석(서명한 이름 · 판 · 시각)이 같으면 같은 것을 다시 서명한 것이다. 그
# 서명이 맞는지는 2 가 잰다(꾸러미의 서명 폴더는 `plugins/*` 와 `remedy-net` 이 전부다).
same=0
resigned=0
differ=0
only=0
: >"$OUT/compare.txt"
comment() { sed -n 's/^trusted comment: //p' "$1"; }
while IFS= read -r f; do
    if [ ! -e "$W/rc/$f" ]; then only=$((only + 1)); echo "정식에만 $f" >>"$OUT/compare.txt"
    elif cmp -s "$W/rc/$f" "$W/final/$f"; then same=$((same + 1))
    elif [ "$(basename "$f")" = MANIFEST.minisig ] && [ -n "$(comment "$W/final/$f")" ] &&
        [ "$(comment "$W/rc/$f")" = "$(comment "$W/final/$f")" ]; then
        resigned=$((resigned + 1)); echo "서명만 다시 $f" >>"$OUT/compare.txt"
    else differ=$((differ + 1)); echo "다름 $f" >>"$OUT/compare.txt"; fi
done < <(cd "$W/final" && find . -type f | sed 's#^\./##' | sort)
while IFS= read -r f; do
    [ -e "$W/final/$f" ] || { only=$((only + 1)); echo "rc 에만 $f" >>"$OUT/compare.txt"; }
done < <(cd "$W/rc" && find . -type f | sed 's#^\./##' | sort)
{ [ "$differ" = 0 ] && [ "$only" = 0 ] && [ "$same" -gt 0 ]; } || fail=1
note "3 rc 와 같은가 · 같은 파일 $same · 서명만 다시 한 파일 $resigned · 다른 파일 $differ · 한쪽에만 $only"

note "끝 $(date '+%Y-%m-%d %H:%M:%S') · $([ "$fail" = 0 ] && echo 통과 || echo 실패)"
exit "$fail"
