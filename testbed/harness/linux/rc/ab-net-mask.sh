#!/bin/bash
# `ab-net.sh` 가 읽어 들이는 견주기 도구 — 같은 점검을 두 번 돌릴 때 달라지는 것(버전 · 시각 · 회차 · 걸린 시간 · A/B
# 폴더)을 가리고, 종료 코드 · 화면 · 결과 JSON 을 견준다.
SAME=0
DIFF=0
mask() {
    sed -E -e 's/1\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?/V/g' \
        -e 's/[0-9]{8}T[0-9]{6}Z(-[0-9]+)?/T/g' \
        -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?/T/g' \
        -e 's/run-[0-9]+-[0-9a-f]+-[0-9a-f]+/RUN/g' \
        -e 's/remedy-net-(url|image|container)-[^ ",/]*\.json/R.json/g' \
        -e 's#/tmp/remedy-net-ab/(out-)?[a-z]+-[ab]-#/W/X-#g' \
        -e 's#/w/(out-)?[a-z]+-[ab]-#/W/X-#g' \
        -e 's/"[a-z_]*(ms|seconds|elapsed)[a-z_]*": *[0-9.]+/"D": 0/g' \
        -e 's/"run_id": *"[^"]*"/"run_id": "R"/g' \
        -e 's/받은 양 [0-9.]+ ?[KMG]?i?B/받은 양 N/g' \
        -e 's/[0-9]+(\.[0-9]+)? ?(ms|s|초)\b/D/g' "$@"
}
compare() { # 이름, A 앞머리, B 앞머리, A 결과 폴더, B 결과 폴더
    local name=$1 a=$2 b=$3 ao=$4 bo=$5 ra rb sd jd
    ra=$(cat "$a.rc" 2>/dev/null)
    rb=$(cat "$b.rc" 2>/dev/null)
    local tag=${name// /-}
    diff <(mask "$a.txt") <(mask "$b.txt") | grep '^[<>]' > "$RES/diff-screen-$tag.txt"
    diff <(find "$ao" -name '*.json' -exec cat {} + 2>/dev/null | mask | tr ',' '\n') \
        <(find "$bo" -name '*.json' -exec cat {} + 2>/dev/null | mask | tr ',' '\n') | grep '^[<>]' \
        > "$RES/diff-json-$tag.txt"
    sd=$(wc -l < "$RES/diff-screen-$tag.txt")
    jd=$(wc -l < "$RES/diff-json-$tag.txt")
    if [ -n "$ra" ] && [ "$ra" = "$rb" ] && [ "$sd" = 0 ] && [ "$jd" = 0 ]; then
        SAME=$((SAME + 1))
        r=same
    else
        DIFF=$((DIFF + 1))
        r=DIFFERENT
    fi
    printf '%-34s A=%s B=%s screen-diff=%s json-diff=%s %s\n' "$name" "$ra" "$rb" "$sd" "$jd" "$r" | tee -a "$SUM"
}
