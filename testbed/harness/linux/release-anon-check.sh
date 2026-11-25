#!/bin/bash
# 공개 뒤 — 로그인 없는 사람이 받는 것을 잰다(docs/긴급-대응.md · 평소 출시도 같다).
#
#   bash testbed/harness/linux/release-anon-check.sh <태그> <확인한 파일 폴더> <빈 작업 폴더>
#
# curl 만 쓴다. 공개 직후 1 ~ 3분은 익명 latest 가 옛 판을 줄 수 있으니 3분 뒤에 돌린다. 본다:
#   - latest Release(API) 의 태그 · 불변 · 초안 · 시험판 · 자산 수. 익명으로 묻고 물을 때마다 HTTP 상태와 한도 줄
#     (x-ratelimit-remaining · reset · retry-after)을 적는다. 익명 한도(403 · 429 · remaining 0)면 알려 준 만큼(retry-after →
#     remaining 0 이면 reset 까지 → 없으면 1분 · 한 번에 120초 · 모두 합쳐 300초까지) 기다렸다 다시 묻는다. 그래도 막히거나 답에
#     칸이 없으면 이 칸들만 GH_TOKEN 으로 묻고 어느 길로 확인했는지 적는다 — 토큰이 없으면 실패한다(까닭을 적는다). 러너는 IP 를
#     함께 써 익명 한도(미인증 60/시간)를 남과 나눈다 — rules-2026.11.24 · rules-2026.11.25 의 공개 뒤 이 줄이 칸 없는 답에
#     실패했고(상태는 적지 않았다) 같은 때 받기 여섯은 모두 200 · 같은 바이트였다
#   - 자산마다 두 주소 꼴(latest/download · download/<태그>)의 리다이렉트 뒤 상태와, 받은 바이트가 공개 전에 내려받아
#     시험한 그 파일과 같은가 — '넘길 파일 = 시험한 파일' 의 마지막 확인이다. 늘 익명이다(받는 사람이 보는 것 — 익명의
#     latest/download 가 새 태그를 주는지도 이 바이트가 잰다)
#   - README 의 리눅스 확인 명령(`grep linux SHA256SUMS | sha256sum -c`)
# Git Bash · WSL 어디서나 돈다. 종료 코드: 0 = 전부 같다 · 1 = 하나라도 다르다(latest 를 확인하지 못한 것도).
# 음성 시험은 `bash ci/publish-check-test.sh` 의 익명 칸이다(가짜 curl · sleep).
set -u
TAG=${1:?태그}
V=${2:?확인한 파일 폴더}
W=${3:?빈 작업 폴더}
REPO=${GITHUB_REPOSITORY:-ESTsecurity/remedy}
API="https://api.github.com/repos/$REPO/releases/latest"
# 익명 latest 가 한도에 걸렸을 때 기다리는 상한(초) — 한 번에 · 모두 합쳐. 알려 준 때가 없으면 GitHub 안내대로 1분이고, 10초보다
# 짧게는 기다리지 않는다(같은 답을 잇달아 묻지 않게).
WAIT_ONCE=120
WAIT_ALL=300
WAIT_DEFAULT=60
WAIT_MIN=10
# 확인한 파일 폴더를 **작업 폴더로 옮기기 전에** 절대 경로로 바꾼다 — 상대 경로를 주면 아래 `cd` 뒤에 엉뚱한 자리를
# 가리켜, 받은 바이트가 같아도 여섯 줄 모두 '다르다' 로 실패했다(2026-11-19 v1.25.0 공개 뒤 — 같은 파일을 절대 경로로
# 다시 재 모두 같았다).
V=$(cd "$V" 2>/dev/null && pwd) || { echo "확인한 파일 폴더가 없다: $2"; exit 9; }
mkdir -p "$W"
cd "$W" || exit 9
bad=0

# 받은 머리의 한 줄 값 — HTTP/1.1 은 이름이 대소문자 섞임(X-RateLimit-Remaining · Git Bash 의 curl)이라 낮춰 견준다.
header() { tr -d '\r' 2>/dev/null <latest.headers | tr '[:upper:]' '[:lower:]' | sed -n "s/^$1: *//p" | tail -n 1; }

# latest 를 한 번 묻는다 — ask <anon | token> <기록의 이름>. latest.json · latest.headers 를 남기고 CODE · REMAINING · RESET ·
# RETRY 를 둔다(없으면 빈 값). 토큰은 표준 입력의 머리 줄로 싣는다 — 명령 인자(프로세스 목록)에 두지 않는다.
ask() {
    local accept='Accept: application/vnd.github+json' left=""
    rm -f latest.json latest.headers
    if [ "$1" = token ]; then
        CODE=$(printf 'Authorization: Bearer %s\n' "$GH_TOKEN" |
            curl -s -D latest.headers -o latest.json -w '%{http_code}' -H "$accept" -H @- "$API")
    else
        CODE=$(curl -s -D latest.headers -o latest.json -w '%{http_code}' -H "$accept" "$API")
    fi
    REMAINING=$(header x-ratelimit-remaining)
    RESET=$(header x-ratelimit-reset)
    RETRY=$(header retry-after)
    [[ "$RESET" =~ ^[0-9]+$ ]] && left="($((RESET - $(date +%s)))초 뒤)"
    echo "  $2 — HTTP $CODE · remaining ${REMAINING:-없음} · reset ${RESET:-없음}$left · retry-after ${RETRY:-없음}"
}
meta_ok() { [ "$CODE" = 200 ] && grep -q '"tag_name"' latest.json 2>/dev/null; }
limited() { [ "$CODE" = 403 ] || [ "$CODE" = 429 ] || [ "$REMAINING" = 0 ]; }
# 한도에 걸린 답이 알려 준 기다림(초) — retry-after → remaining 0 이면 reset 까지 → 없으면 1분.
told_wait() {
    local s=$WAIT_DEFAULT
    if [[ "$RETRY" =~ ^[0-9]+$ ]]; then
        s=$RETRY
    elif [ "$REMAINING" = 0 ] && [[ "$RESET" =~ ^[0-9]+$ ]]; then
        s=$((RESET - $(date +%s) + 1))
    fi
    [ "$s" -ge "$WAIT_MIN" ] || s=$WAIT_MIN
    echo "$s"
}

echo "== latest Release (API — 익명으로 묻는다 · 한도면 기다렸다 다시 · 그래도 막히면 이 칸들만 GH_TOKEN 으로)"
path=""   # 확인한 길 — 빈 값이면 확인하지 못했다
why=""    # 익명으로 확인하지 못한 까닭
waited=0
try=0
while :; do
    try=$((try + 1))
    ask anon "익명 ${try}번째"
    if meta_ok; then path="익명(${try}번째 · 기다린 합 ${waited}초)"; break; fi
    if ! limited; then why="익명의 답에 칸이 없다(HTTP $CODE)"; break; fi
    told=$(told_wait)
    why="익명 한도(HTTP $CODE · remaining ${REMAINING:-없음} · 알려 준 기다림 ${told}초 · 기다린 합 ${waited}초)"
    # 알려 준 때가 남은 상한 밖이면 기다려도 풀리지 않는다 — 더 묻지 않는다.
    if [ "$told" -gt $((WAIT_ALL - waited)) ]; then
        echo "  알려 준 기다림 ${told}초가 남은 상한 $((WAIT_ALL - waited))초를 넘는다 — 더 기다리지 않는다"
        break
    fi
    w=$told
    [ "$w" -le "$WAIT_ONCE" ] || w=$WAIT_ONCE
    echo "  ${w}초 기다렸다 다시 묻는다(기다린 합 $((waited + w))초 · 상한 ${WAIT_ALL}초)"
    sleep "$w"
    waited=$((waited + w))
done
if [ -z "$path" ] && [ -n "${GH_TOKEN:-}" ]; then
    echo "  $why — 이 칸들만 GH_TOKEN 으로 묻는다(받기는 아래처럼 익명 그대로)"
    ask token "토큰"
    if meta_ok; then path="토큰(GH_TOKEN) — $why"; else why="$why · 토큰으로도 칸이 없다(HTTP $CODE)"; fi
elif [ -z "$path" ]; then
    why="$why · GH_TOKEN 이 없어 토큰으로 묻지 못했다"
fi
if [ -n "$path" ]; then
    echo "확인한 길: $path"
    grep -oE '"(tag_name|immutable|draft|prerelease)": *("[^"]*"|true|false)' latest.json
    grep -q "\"tag_name\": *\"$TAG\"" latest.json || { echo "  latest 가 $TAG 가 아니다"; bad=1; }
    # 출력만 하던 셋도 판정한다(2026-11-21 · 공개 워크플로가 이 스크립트로 공개를 끝낸다) — 공개한 것이 불변 · 정식이고 자산이 셋이다.
    grep -qE '"immutable": *true' latest.json || { echo "  불변이 아니다"; bad=1; }
    grep -qE '"draft": *false' latest.json || { echo "  아직 초안이다"; bad=1; }
    grep -qE '"prerelease": *false' latest.json || { echo "  시험판이다"; bad=1; }
    # 줄이 아니라 나온 수를 센다 — GitHub 은 curl 의 User-Agent 에만 들여 쓴 JSON 을 주고 다른 클라이언트에는 한 줄로 준다
    # (2026-11-25 /rate_limit 으로 잼: curl 40줄 · 다른 UA 1줄 · 토큰과 상관없다). 한 줄이면 줄 수로는 자산이 하나로 셌다.
    n=$(grep -o '"browser_download_url"' latest.json | grep -c .)
    echo "자산 수: $n"
    [ "$n" = 3 ] || { echo "  자산이 셋이 아니다"; bad=1; }
else
    echo "  latest 를 확인하지 못했다 — $why"
    bad=1
fi
echo "== 받기(리다이렉트 뒤 상태)와 바이트"
for a in remedy-linux-x64.tar.gz remedy-windows-x64.zip SHA256SUMS; do
    for u in "https://github.com/$REPO/releases/latest/download/$a" \
        "https://github.com/$REPO/releases/download/$TAG/$a"; do
        code=$(curl -sL -o "$a" -w '%{http_code}' "$u")
        if cmp -s "$a" "$V/$a"; then same="확인한 파일과 같다"; else same="다르다"; bad=1; fi
        [ "$code" = 200 ] || bad=1
        echo "  $code $same  $u"
    done
done
echo "== README 의 확인 명령(리눅스)"
grep linux SHA256SUMS | sha256sum -c || bad=1
exit "$bad"
