#!/bin/sh
# `ab-net.sh` 의 안쪽 — 일회용 컨테이너 안. /w 에 푼 꾸러미 둘(a · b)이 있고 화면 · 종료 코드 · 결과 폴더를 받는다.
# /in 에 저장한 이미지 tar 가 있다(읽기 전용).
#   images     - debian:12: tar 를 overlay 루트로 복사해 두 판의 image 점검을 하나씩
#   containers - docker:dind: 이미지 둘을 싣고, 런타임이 계속 도는 컨테이너 둘을 띄워 두 판의 container 점검, 그리고 지운다
set -u
case "${1:?images|containers}" in
images)
    mkdir -p /work
    for t in /in/*.tar; do
        n=$(basename "$t" .tar)
        cp "$t" /work/ || exit 9
        for s in a b; do
            LANG=C.UTF-8 REMEDY_LANG=ko /w/$s/remedy-net/remedy-net image "/work/$n.tar" --consent y \
                --out-dir "/w/out-image-$s-$n" > "/w/image-$s-$n.txt" 2>&1
            echo $? > "/w/image-$s-$n.rc"
        done
        rm -f "/work/$n.tar"
    done
    chmod -R a+rwX /w
    ;;
containers)
    docker load -i /in/php-8.3.35-cli.tar > /dev/null || exit 9
    docker load -i /in/node-22.18.0.tar > /dev/null || exit 9
    php=$(docker run -d php:8.3.35-cli php -r 'sleep(600);') || exit 9
    node=$(docker run -d node:22.18.0-bookworm-slim node -e 'setTimeout(function(){}, 600000)') || exit 9
    for pair in "php $php" "node $node"; do
        set -- $pair
        for s in a b; do
            LANG=C.UTF-8 REMEDY_LANG=ko /w/$s/remedy-net/remedy-net container "$2" --consent y \
                --out-dir "/w/out-container-$s-$1" > "/w/container-$s-$1.txt" 2>&1
            echo $? > "/w/container-$s-$1.rc"
        done
    done
    docker rm -f "$php" "$node" > /dev/null
    chmod -R a+rwX /w
    ;;
esac
