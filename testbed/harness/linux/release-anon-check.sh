#!/bin/bash
# 공개 뒤 — 로그인 없는 사람이 받는 것을 잰다(docs/긴급-대응.md · 평소 출시도 같다).
#
#   bash testbed/harness/linux/release-anon-check.sh <태그> <확인한 파일 폴더> <빈 작업 폴더>
#
# 토큰 없이 curl 만 쓴다. 공개 직후 1 ~ 3분은 익명 latest 가 옛 판을 줄 수 있으니 3분 뒤에 돌린다. 본다:
#   - latest Release(API) 의 태그 · 불변 · 초안 · 시험판 · 자산 수
#   - 자산마다 두 주소 꼴(latest/download · download/<태그>)의 리다이렉트 뒤 상태와, 받은 바이트가 공개 전에 내려받아
#     시험한 그 파일과 같은가 — '넘길 파일 = 시험한 파일' 의 마지막 확인이다
#   - README 의 리눅스 확인 명령(`grep linux SHA256SUMS | sha256sum -c`)
# Git Bash · WSL 어디서나 돈다. 종료 코드: 0 = 전부 같다 · 1 = 하나라도 다르다.
set -u
TAG=${1:?태그}
V=${2:?확인한 파일 폴더}
W=${3:?빈 작업 폴더}
REPO=ESTsecurity/remedy
mkdir -p "$W"
cd "$W" || exit 9
bad=0
echo "== latest Release (API · 익명)"
curl -s -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/$REPO/releases/latest" >latest.json
grep -oE '"(tag_name|immutable|draft|prerelease)": *("[^"]*"|true|false)' latest.json
grep -q "\"tag_name\": *\"$TAG\"" latest.json || { echo "  latest 가 $TAG 가 아니다"; bad=1; }
echo "자산 수: $(grep -c '"browser_download_url"' latest.json)"
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
