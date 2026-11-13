#!/bin/bash
# rc 묶음 — 실제 설치에서 리눅스 점검 룰 셋의 A/B (`rc-bundle.sh` 가 부른다).
#
#   bash testbed/harness/linux/rc/ab-installs.sh <A tar.gz> <B tar.gz> <결과 폴더>
#
# 컨테이너마다 A(지난 공개본)와 B(이번 판)를 같은 파일 시스템에서 차례로 돌린다 — 각자 제 꾸러미의 서명된 룰로.
# 종료 코드와 화면 · 결과 JSON 을 견준다(버전 · 시각 · 회차 · A/B 폴더 이름은 가린다). 설치에 망이 든다(apt · dnf ·
# yum · apk). `ONLY=이름,이름` 으로 경우를 골라 돌릴 수 있다.
#
# summary.txt 한 줄 = 경우 하나: `이름 setup=ok|none|failed … docker=… | 룰 A=코드 B=코드 screen-diff=… json-diff=…`.
# json-diff 는 가리지 않는 칸(패키지 기록 등) 때문에 0 이 아닐 수 있다 — 판정은 종료 코드로 하고 diff 는 사람이 본다.
set -u
A_TGZ=${1:?A tar.gz}
B_TGZ=${2:?B tar.gz}
RES=${3:?result folder}
W=/tmp/remedy-ab
RULES="php2shell-check-linux php-session-check-linux node2shell-check-linux"
CENTOS_VAULT='sed -i -e "s/^mirrorlist/#mirrorlist/" -e "s|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|" /etc/yum.repos.d/CentOS-*.repo'
# 이름|이미지|검사 전에 sh -c 로 돌릴 준비(빈칸 = 이미지 그대로)
CASES=(
    "php-8.3.35-cli|php:8.3.35-cli|"
    "php-8.3.36-cli|php:8.3.36-cli|"
    "php-8.3.36-fpm|php:8.3.36-fpm|"
    "php-8.2-apache|php:8.2-apache|"
    "node-22.18.0|node:22.18.0-bookworm-slim|"
    "node-22.23.4|node:22.23.4-bookworm-slim|"
    "ol8-php|oraclelinux:8|dnf -y -q install php-cli"
    "ol9-php|oraclelinux:9|dnf -y -q install php-cli"
    "alma8-php|almalinux:8|dnf -y -q install php-cli"
    "rocky9-nodejs|rockylinux:9|dnf -y -q install nodejs"
    "centos7-php|centos:7|$CENTOS_VAULT && yum -y -q install php-cli"
    "alpine-php|alpine:3.22|apk add -q --no-cache php83"
    "alpine-nodejs|alpine:3.22|apk add -q --no-cache nodejs"
    "debian12-php|debian:12|apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y php-cli"
    "debian12-nodejs|debian:12|apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y nodejs"
    "ubuntu24-php|ubuntu:24.04|apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y php-cli"
    "ubuntu24-nodejs|ubuntu:24.04|apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y nodejs"
    "amzn2|amazonlinux:2|"
    "amzn2023|amazonlinux:2023|"
    "ubi9|registry.access.redhat.com/ubi9/ubi:latest|"
    "leap15.6|opensuse/leap:15.6|"
)
rm -rf "$W"
mkdir -p "$W/a" "$W/b" "$W/out" "$RES"
tar -xzf "$A_TGZ" -C "$W/a" --strip-components=1 || { echo "A 를 풀지 못했다"; exit 9; }
tar -xzf "$B_TGZ" -C "$W/b" --strip-components=1 || { echo "B 를 풀지 못했다"; exit 9; }
echo "A: $("$W/a/remedy" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+')"
echo "B: $("$W/b/remedy" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+')"
cat > "$W/inside.sh" <<'EOF'
#!/bin/sh
# 컨테이너 안: 준비, 그리고 룰 셋을 A 로 · B 로
name=$1
setup=$2
rules=$3
mkdir -p "/out/$name"
if [ -n "$setup" ]; then
    if sh -c "$setup" > "/out/$name/setup.log" 2>&1; then echo ok > "/out/$name/setup.txt"; else echo "failed $?" > "/out/$name/setup.txt"; fi
else
    echo none > "/out/$name/setup.txt"
fi
for r in $rules; do
    for v in a b; do
        d="/out/$name/$v-$r"
        mkdir -p "$d"
        "/$v/remedy" scan --plugin "/$v/plugins/$r/plugin.yaml" --out-dir "$d/out" > "$d/screen.txt" 2>&1
        echo "$r $v $?" >> "/out/$name/codes.txt"
        find "$d/out" -type f -name '*.json' | sort | while read -r f; do cat "$f"; echo; done > "$d/json.txt"
        chmod 644 "$d/screen.txt" "$d/json.txt"
    done
done
EOF
mask() {
    sed -E -e 's/1\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?/V/g' \
        -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z?/T/g' \
        -e 's#/out/[^/ ]+/[ab]-#/out/N/X-#g' \
        -e 's/[0-9]{8}-[0-9]{6}-[0-9a-f]+/R/g' \
        -e 's/run-[0-9]+-[0-9a-f]+-[0-9a-f]+/RUN/g' \
        -e 's/[0-9]+(\.[0-9]+)? ?(ms|s|초)\b/D/g' "$1"
}
for c in "${CASES[@]}"; do
    IFS='|' read -r name image setup <<< "$c"
    if [ -n "${ONLY:-}" ] && [[ ",$ONLY," != *",$name,"* ]]; then continue; fi
    t0=$(date +%s)
    docker run --rm --pull=never -v "$W/a:/a:ro" -v "$W/b:/b:ro" -v "$W/out:/out" -v "$W/inside.sh:/inside.sh:ro" \
        "$image" sh /inside.sh "$name" "$setup" "$RULES" > "$W/out/$name.docker.log" 2>&1
    rc=$?
    line="$name setup=$(cat "$W/out/$name/setup.txt" 2>/dev/null) docker=$rc ($(( $(date +%s) - t0 ))s)"
    for r in $RULES; do
        ca=$(awk -v r="$r" '$1==r && $2=="a" {print $3}' "$W/out/$name/codes.txt" 2>/dev/null)
        cb=$(awk -v r="$r" '$1==r && $2=="b" {print $3}' "$W/out/$name/codes.txt" 2>/dev/null)
        nd=$(diff <(mask "$W/out/$name/a-$r/screen.txt") <(mask "$W/out/$name/b-$r/screen.txt") | grep -c '^[<>]')
        jb=$(wc -c < "$W/out/$name/b-$r/json.txt" 2>/dev/null || echo 0)
        jd=$(diff <(mask "$W/out/$name/a-$r/json.txt" | tr ',' '\n') <(mask "$W/out/$name/b-$r/json.txt" | tr ',' '\n') | grep -c '^[<>]')
        line="$line | $r A=$ca B=$cb screen-diff=$nd json-diff=$jd (${jb}B)"
    done
    echo "$line" | tee -a "$RES/summary.txt"
done
# 화면과 기록(글)만 남기고 푼 꾸러미와 결과 JSON 폴더는 지운다
mkdir -p "$RES/cases"
for c in "${CASES[@]}"; do
    IFS='|' read -r name _ _ <<< "$c"
    [ -d "$W/out/$name" ] || continue
    mkdir -p "$RES/cases/$name"
    cp "$W/out/$name"/*.txt "$RES/cases/$name/" 2>/dev/null
    cp "$W/out/$name/setup.log" "$RES/cases/$name/" 2>/dev/null
    for r in $RULES; do
        for v in a b; do
            cp "$W/out/$name/$v-$r/screen.txt" "$RES/cases/$name/$v-$r.screen.txt" 2>/dev/null
            cp "$W/out/$name/$v-$r/json.txt" "$RES/cases/$name/$v-$r.json.txt" 2>/dev/null
        done
    done
done
# 컨테이너가 root 로 쓴 결과는 컨테이너로 지운다
docker run --rm -v "$W:/w" alpine:3.22 rm -rf /w/out
rm -rf "$W"
echo "끝 $(date +%H:%M:%S)"
