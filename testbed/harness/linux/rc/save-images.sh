#!/bin/bash
# rc 묶음의 원격 A/B(image · container)가 읽는 이미지 여덟을 이미지마다 tar 하나로 저장한다(linux/amd64 만).
#
#   bash testbed/harness/linux/rc/save-images.sh <이미지 폴더>
#
# `--platform` 이 없으면 Docker Desktop 의 containerd 저장소가 여러 플랫폼 색인을 통째로 쓰면서 층은 이 플랫폼 것만
# 담는다 — 그러면 담지 않은 플랫폼이 모두 '확인 필요' 로 나온다(README 의 그 말). 없는 이미지는 받는다(망).
# 폴더는 Windows 쪽에 둔다 — WSL 디스크 이미지는 안에서 지워도 줄지 않는다.
set -u
D=${1:?images dir}
mkdir -p "$D"
save() { # 파일 이름 · 이미지
    local t0 rc
    docker image inspect "$2" > /dev/null 2>&1 || docker pull -q --platform linux/amd64 "$2" > /dev/null || { echo "$2 를 받지 못했다"; return 1; }
    t0=$(date +%s)
    docker save --platform linux/amd64 -o "$D/$1.tar.part" "$2" && mv "$D/$1.tar.part" "$D/$1.tar"
    rc=$?
    echo "$1 exit=$rc $(( $(date +%s) - t0 ))s $(stat -c %s "$D/$1.tar" 2>/dev/null) B  $(docker image inspect --format '{{.Id}}' "$2" | cut -c1-19)"
    return "$rc"
}
bad=0
save node-22.23.4 node:22.23.4-bookworm-slim || bad=1
save alpine-3.22 alpine:3.22 || bad=1
save ubuntu-24.04 ubuntu:24.04 || bad=1
save oraclelinux-9 oraclelinux:9 || bad=1
save php-8.3.36-cli php:8.3.36-cli || bad=1
save php-8.2-apache php:8.2-apache || bad=1
save php-8.3.35-cli php:8.3.35-cli || bad=1
save node-22.18.0 node:22.18.0-bookworm-slim || bad=1
exit "$bad"
