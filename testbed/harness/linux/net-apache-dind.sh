#!/bin/sh
# `net-apache-verify.sh` 의 안쪽 — docker:dind 안(진짜 리눅스 엔진 · 망 없음). /in 의 tar 를 싣고 컨테이너를 띄워
# `remedy-net container` 로 하나씩 잰 뒤 지운다. /w/c 에 remedy-net · 기준 폴더(crit)가 있고, 결과는 /w/c/results 에
# `이름 기대 받은 근거` 줄로 적는다(근거는 결과 JSON 에 있어야 할 글).
set -u
cd /w/c
for t in apache-rocky9 apache-debian12 apache-alpine322 php-8.2-apache httpd-2.4.65 apache-ol9 apache-al2023 apache-al2 \
    net-apache-al2023-vuln; do
    docker load -q -i "/in/$t.tar" >/dev/null || echo "load $t failed"
done
start() { docker run -d --network none "$@" 2>/dev/null; }
: >ids
echo "rocky9 6 $(start --entrypoint sleep remedy-harness/apache:rocky9 600) RLSA-2026:98981" >>ids
echo "debian12 6 $(start --entrypoint sleep remedy-harness/apache:debian12 600) 개별 파일만" >>ids
echo "alpine322 6 $(start --entrypoint sleep remedy-harness/apache:alpine322 600) SHA-1(apk Z:Q1)" >>ids
# 고정한 고치기 전 `php:8.2-apache`(바깥의 `net-apache-verify.sh` 가 그 꼬리표로 tar 에 담는다).
php=$(start remedy-harness/net-apache:php82apache)
docker exec "$php" a2enmod http2 >/dev/null 2>&1
echo "php82apache-h2 2 $php mods-enabled/http2.load" >>ids
echo "httpd2465 6 $(start httpd:2.4.65) HTTPD_VERSION=2.4.65" >>ids
h2=$(start httpd:2.4.65)
docker exec "$h2" sh -c 'sed -i "s/^#LoadModule http2_module/LoadModule http2_module/" conf/httpd.conf && echo "Protocols h2 http/1.1" >> conf/httpd.conf'
echo "httpd2465-h2 2 $h2 Protocols 줄" >>ids
# 코어 1.19.0 — Oracle Linux 9 는 rpm 이 쓰지 않는 빈 DB 를 새 자리에 둔다(근거 글은 /var/lib/rpm 의 mod_http2 판).
# Amazon Linux 는 1.18.0 이 RPM DB 를 읽지 않던 배포판이다(근거 글은 그 DB 의 판 · 2023 은 HTTP/2 를 켜 2).
# 근거 글은 깐 판이 아니라 RPM DB 를 읽은 줄이다 — 판은 짓는 날마다 바뀐다(2026-11-23).
echo "ol9 6 $(start --entrypoint sleep remedy-harness/apache:ol9 600) 설치 정보: ol 9." >>ids
# Amazon Linux 2023 — 하네스 이미지는 짓는 날 저장소의 고친 판이라 HTTP/2 를 켜도 6(컨테이너는 양호를 내지 않는다) ·
# 고치기 전 판은 같은 모듈 파일을 담은 가짜 판 패키지 꼴(net-apache-al2023-vuln)에서 HTTP/2 를 켜 2(2026-11-23).
al=$(start --entrypoint sleep remedy-harness/apache:al2023 600)
docker exec "$al" sh -c 'echo "Protocols h2 http/1.1" >> /etc/httpd/conf/httpd.conf'
echo "al2023-h2 6 $al 1:2.4.71-1.amzn2023.0.1" >>ids
alv=$(start --entrypoint sleep remedy-harness/net-apache:al2023-vuln 600)
docker exec "$alv" sh -c 'echo "Protocols h2 http/1.1" >> /etc/httpd/conf/httpd.conf'
echo "al2023-h2-vuln 2 $alv 1:2.4.69-1.amzn2023.0.2" >>ids
echo "al2 6 $(start --entrypoint sleep remedy-harness/apache:al2 600) 1:2.4.71-1.amzn2.0.1" >>ids
sleep 2
: >results
while read -r name want id why; do
    REMEDY_NET_CRITERIA=/w/c/crit REMEDY_NET_ANCHOR="$ANCHOR" LANG=C.UTF-8 REMEDY_LANG=ko \
        /w/c/remedy-net container "$id" --runtime apache --consent y --out-dir "/w/c/out-$name" >"/w/c/$name.txt" 2>&1
    echo "$name $want $? $why" >>results
done <ids
docker rm -f $(cut -d' ' -f3 ids) >/dev/null 2>&1
chmod -R a+rwX /w
