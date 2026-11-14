#!/bin/sh
# `ab-net.sh` 의 안쪽 — 일회용 컨테이너 안. /w 에 푼 꾸러미 둘(a · b)이 있고 화면 · 종료 코드 · 결과 폴더를 받는다.
# /in 에 저장한 이미지 tar 가 있다(읽기 전용).
#   images     - debian:12: tar 를 overlay 루트로 복사해 두 판의 image 점검을 하나씩
#   containers - docker:dind: 이미지 둘을 싣고, 런타임이 계속 도는 컨테이너 둘을 띄워 두 판의 container 점검, 그리고 지운다
#
# 제품마다 따로 잰다(`--runtime php` · `--runtime node` — 코어 1.18.0). 1.18.0 의 기본(all)은 Apache 도 보므로 기본으로 견주면
# Apache 가 든 이미지에서 늘 다르다 — 견주는 것은 PHP · Node.js 의 판정이 그대로인가다(Apache 는 `net-apache-verify.sh`).
set -u
case "${1:?images|containers}" in
images)
    mkdir -p /work
    for t in /in/*.tar; do
        n=$(basename "$t" .tar)
        cp "$t" /work/ || exit 9
        for r in php node; do
            for s in a b; do
                LANG=C.UTF-8 REMEDY_LANG=ko /w/$s/remedy-net/remedy-net image "/work/$n.tar" --runtime "$r" --consent y \
                    --out-dir "/w/out-image-$s-$n-$r" > "/w/image-$s-$n-$r.txt" 2>&1
                echo $? > "/w/image-$s-$n-$r.rc"
            done
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
        for r in php node; do
            for s in a b; do
                LANG=C.UTF-8 REMEDY_LANG=ko /w/$s/remedy-net/remedy-net container "$2" --runtime "$r" --consent y \
                    --out-dir "/w/out-container-$s-$1-$r" > "/w/container-$s-$1-$r.txt" 2>&1
                echo $? > "/w/container-$s-$1-$r.rc"
            done
        done
    done
    docker rm -f "$php" "$node" > /dev/null
    chmod -R a+rwX /w
    ;;
esac
