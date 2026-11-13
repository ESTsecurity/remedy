#!/bin/bash
# rc 묶음 — 동반 프로그램 remedy-net 의 A/B(`rc-bundle.sh` · 안쪽은 `ab-net-inside.sh` · 견주기는 `ab-net-mask.sh`).
#
#   bash testbed/harness/linux/rc/ab-net.sh <A tar.gz> <B tar.gz> <이미지 tar 폴더> <결과 폴더>
#
# 지난 공개본(A)과 이번 판(B)을 나란히:
#   url       - 루프백 모의 서버(`net-mock.py`)가 헤더 판 넷을 알린다 — 두 실행 파일 모두 여기(WSL)에서 돈다
#   image     - 저장한 tar 를 debian:12 컨테이너 하나에 복사해 잰다(overlay 루트 — 로컬 파일 시스템. /mnt/d 같은
#               9p 경로는 설계대로 거부된다)
#   container - docker:dind(진짜 리눅스 엔진) 안에서 저장한 tar 로 띄운 컨테이너 둘
# 경우마다 종료 코드와 화면 · 결과 JSON(버전 · 시각 · 회차 · 경로를 가린 뒤)이 같아야 한다. 이미지 tar 는
# `save-images.sh` 가 만든다. 망은 쓰지 않는다(dind 는 tar 로 싣는다).
#
# summary.txt: 경우마다 `이름 A=코드 B=코드 screen-diff=… json-diff=… same|DIFFERENT`, 끝 줄 `same N · different M`.
set -u
A_TGZ=${1:?A tar.gz}
B_TGZ=${2:?B tar.gz}
IMG=${3:?images dir}
RES=${4:?result folder}
HERE=$(cd "$(dirname "$0")" && pwd)
W=/tmp/remedy-net-ab
DIND=remedy-net-ab-dind
rm -rf "$W"
mkdir -p "$W/a" "$W/b" "$RES"
tar -xzf "$A_TGZ" -C "$W/a" --strip-components=1 || { echo "A 를 풀지 못했다"; exit 9; }
tar -xzf "$B_TGZ" -C "$W/b" --strip-components=1 || { echo "B 를 풀지 못했다"; exit 9; }
cp "$HERE/ab-net-inside.sh" "$W/"
SUM=$RES/summary.txt
: > "$SUM"
note() { echo "$*" | tee -a "$SUM"; }
note "A: $("$W/a/remedy-net/remedy-net" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+')"
note "B: $("$W/b/remedy-net/remedy-net" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+')"
. "$HERE/ab-net-mask.sh"

# ── url ─────────────────────────────────────────────────────────────
port=18360
for v in 8.3.38 8.3.2 8.2.35-1~deb12u1 8.2.32-1~deb12u1; do
    port=$((port + 1))
    python3 -I -X utf8 "$HERE/net-mock.py" "$port" "$v" &
    mock=$!
    sleep 0.5
    for s in a b; do
        o="$W/out-url-$s-$port"
        LANG=C.UTF-8 REMEDY_LANG=ko "$W/$s/remedy-net/remedy-net" url --url "http://127.0.0.1:$port/" --consent y \
            --out-dir "$o" > "$W/url-$s-$port.txt" 2>&1
        echo $? > "$W/url-$s-$port.rc"
    done
    kill "$mock" 2>/dev/null
    wait "$mock" 2>/dev/null
    compare "url $v" "$W/url-a-$port" "$W/url-b-$port" "$W/out-url-a-$port" "$W/out-url-b-$port"
done

# ── image ───────────────────────────────────────────────────────────
docker run --rm --pull=never -v "$W:/w" -v "$IMG:/in:ro" debian:12 bash /w/ab-net-inside.sh images
for t in "$IMG"/*.tar; do
    n=$(basename "$t" .tar)
    compare "image $n" "$W/image-a-$n" "$W/image-b-$n" "$W/out-image-a-$n" "$W/out-image-b-$n"
done

# ── container ───────────────────────────────────────────────────────
docker rm -f "$DIND" > /dev/null 2>&1
docker run -d --privileged --name "$DIND" -v "$W:/w" -v "$IMG:/in:ro" docker:dind > /dev/null \
    || { note "dind 가 뜨지 않았다"; exit 9; }
for _ in $(seq 1 60); do docker exec "$DIND" docker info > /dev/null 2>&1 && break; sleep 1; done
docker exec "$DIND" sh /w/ab-net-inside.sh containers
for n in php node; do
    compare "container $n" "$W/container-a-$n" "$W/container-b-$n" "$W/out-container-a-$n" "$W/out-container-b-$n"
done
docker rm -f "$DIND" > /dev/null 2>&1

cp -r "$W"/*.txt "$W"/*.rc "$RES/" 2>/dev/null
# 컨테이너가 root 로 쓴 결과는 컨테이너로 지운다
docker run --rm -v /tmp:/t alpine:3.22 rm -rf /t/remedy-net-ab
note "same $SAME · different $DIFF"
