#!/bin/sh
# `net-apache-verify.sh` 의 안쪽 — docker:dind 안(진짜 리눅스 엔진 · 망 없음). /in 의 tar 를 싣고 컨테이너를 띄워
# `remedy-net container` 로 하나씩 잰 뒤 지운다. /w/c 에 remedy-net · 기준 폴더(crit)가 있고, 결과는 /w/c/results 에
# `이름 기대 받은 근거` 줄로 적는다(근거는 결과 JSON 에 있어야 할 글).
set -u
cd /w/c
for t in apache-rocky9 apache-debian12 apache-alpine322 php-8.2-apache httpd-2.4.65; do
    docker load -q -i "/in/$t.tar" >/dev/null || echo "load $t failed"
done
start() { docker run -d --network none "$@" 2>/dev/null; }
: >ids
echo "rocky9 6 $(start --entrypoint sleep remedy-harness/apache:rocky9 600) RLSA-2026:98981" >>ids
echo "debian12 6 $(start --entrypoint sleep remedy-harness/apache:debian12 600) 개별 파일만" >>ids
echo "alpine322 6 $(start --entrypoint sleep remedy-harness/apache:alpine322 600) SHA-1(apk Z:Q1)" >>ids
php=$(start php:8.2-apache)
docker exec "$php" a2enmod http2 >/dev/null 2>&1
echo "php82apache-h2 2 $php mods-enabled/http2.load" >>ids
echo "httpd2465 6 $(start httpd:2.4.65) HTTPD_VERSION=2.4.65" >>ids
h2=$(start httpd:2.4.65)
docker exec "$h2" sh -c 'sed -i "s/^#LoadModule http2_module/LoadModule http2_module/" conf/httpd.conf && echo "Protocols h2 http/1.1" >> conf/httpd.conf'
echo "httpd2465-h2 2 $h2 Protocols 줄" >>ids
sleep 2
: >results
while read -r name want id why; do
    REMEDY_NET_CRITERIA=/w/c/crit REMEDY_NET_ANCHOR="$ANCHOR" LANG=C.UTF-8 REMEDY_LANG=ko \
        /w/c/remedy-net container "$id" --runtime apache --consent y --out-dir "/w/c/out-$name" >"/w/c/$name.txt" 2>&1
    echo "$name $want $? $why" >>results
done <ids
docker rm -f $(cut -d' ' -f3 ids) >/dev/null 2>&1
chmod -R a+rwX /w
