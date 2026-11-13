#!/bin/bash
# rc 묶음 — 지워진 옛 파일을 계속 도는 프로세스와 직접 빌드 자리에서 리눅스 점검 룰 셋의 A/B(`rc-bundle.sh`).
#
#   bash testbed/harness/linux/rc/ab-stale.sh <A tar.gz> <B 폴더(remedy + plugins/)> <결과 폴더>
#
# (1) '업데이트' 뒤에도 지워진 옛 파일을 계속 도는 PHP · Node 프로세스(패키지 관리자처럼 이름 바꾸기로 덮는다 — 도는
# 프로세스는 옛 inode 를 쥔다) (2) 직접 빌드 자리 /usr/local/php · /opt/php 의 PHP. A(지난 공개본)와 B 를 같은
# 컨테이너에서 차례로 돌린다 — www-data 일꾼을 읽게 SYS_PTRACE 로 띄운다(없으면 둘 다 6). 설치에 망이 든다.
#
# summary.txt 한 줄 = 경우 하나: `이름 setup=… docker=… | 룰 A=코드 B=코드`.
set -u
A_TGZ=${1:?A tar.gz}
B_DIR=${2:?B folder}
RES=${3:?result folder}
W=/tmp/remedy-stale
RULES="php2shell-check-linux php-session-check-linux node2shell-check-linux"
APT='apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y'
FPM='mkdir -p /run/php && php-fpm8.2 -D'
# 이름|이미지|준비(sh -c · 데몬은 검사 전에 뒤에서 띄운다). 바꿔 치기는 사본을 만들어 이름 바꾸기로 덮는다.
CASES=(
    "fpm-running|debian:12|$APT php8.2-fpm && $FPM"
    "fpm-stale|debian:12|$APT php8.2-fpm && $FPM && sleep 1 && cp /usr/sbin/php-fpm8.2 /tmp/s && mv -f /tmp/s /usr/sbin/php-fpm8.2"
    "apache-modphp-stale|debian:12|$APT libapache2-mod-php8.2 && apache2ctl start && sleep 1 && cp /usr/lib/apache2/modules/libphp8.2.so /tmp/s && mv -f /tmp/s /usr/lib/apache2/modules/libphp8.2.so"
    "node-stale|node:22.23.4-bookworm-slim|(node -e 'setTimeout(function(){},600000)' &) && sleep 1 && cp /usr/local/bin/node /tmp/s && mv -f /tmp/s /usr/local/bin/node"
    "opt-php-official-vuln|php:8.3.35-cli|mkdir -p /opt/php/bin /opt/php/lib && mv /usr/local/bin/php /usr/local/bin/php-cgi /opt/php/bin/ && mv /usr/local/lib/libphp.so /opt/php/lib/ 2>/dev/null; ls -l /opt/php/bin /usr/local/bin | grep -c php"
    "usr-local-php-own|debian:12|mkdir -p /usr/local/php/bin && cp /bin/ls /usr/local/php/bin/php"
)
rm -rf "$W"
mkdir -p "$W/a" "$W/b" "$W/out" "$RES"
tar -xzf "$A_TGZ" -C "$W/a" --strip-components=1 || { echo "A 를 풀지 못했다"; exit 9; }
cp -r "$B_DIR"/. "$W/b/" || { echo "B 를 옮기지 못했다"; exit 9; }
echo "A: $("$W/a/remedy" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+')"
echo "B: $("$W/b/remedy" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+')"
cat > "$W/inside.sh" <<'EOF'
#!/bin/sh
name=$1
setup=$2
rules=$3
mkdir -p "/out/$name"
if sh -c "$setup" > "/out/$name/setup.log" 2>&1; then echo ok > "/out/$name/setup.txt"; else echo "failed $?" > "/out/$name/setup.txt"; fi
sleep 2
for p in /proc/[0-9]*; do l=$(readlink "$p/exe" 2>/dev/null) && echo "${p#/proc/} $l"; done > "/out/$name/exe.txt"
grep -l ' (deleted)' /proc/[0-9]*/maps 2>/dev/null | while read -r m; do echo "$m: $(grep ' (deleted)' "$m" | awk '{print $6, $7}' | sort -u | tr '\n' ' ')"; done > "/out/$name/deleted-maps.txt"
for r in $rules; do
    for v in a b; do
        d="/out/$name/$v-$r"
        mkdir -p "$d"
        LANG=ko_KR.UTF-8 "/$v/remedy" scan --plugin "/$v/plugins/$r/plugin.yaml" --out-dir "$d/out" > "$d/screen.txt" 2>&1
        echo "$r $v $?" >> "/out/$name/codes.txt"
        chmod 644 "$d/screen.txt"
    done
done
chmod -R a+r /out/$name
EOF
for c in "${CASES[@]}"; do
    IFS='|' read -r name image setup <<< "$c"
    t0=$(date +%s)
    docker run --rm --pull=never --cap-add SYS_PTRACE -v "$W/a:/a:ro" -v "$W/b:/b:ro" -v "$W/out:/out" \
        -v "$W/inside.sh:/inside.sh:ro" "$image" sh /inside.sh "$name" "$setup" "$RULES" > "$W/out/$name.docker.log" 2>&1
    rc=$?
    line="$name setup=$(cat "$W/out/$name/setup.txt" 2>/dev/null) docker=$rc ($(( $(date +%s) - t0 ))s)"
    for r in $RULES; do
        ca=$(awk -v r="$r" '$1==r && $2=="a" {print $3}' "$W/out/$name/codes.txt" 2>/dev/null)
        cb=$(awk -v r="$r" '$1==r && $2=="b" {print $3}' "$W/out/$name/codes.txt" 2>/dev/null)
        line="$line | $r A=$ca B=$cb"
    done
    echo "$line" | tee -a "$RES/summary.txt"
    mkdir -p "$RES/cases/$name"
    cp "$W/out/$name"/*.txt "$W/out/$name/setup.log" "$RES/cases/$name/" 2>/dev/null
    for r in $RULES; do
        for v in a b; do
            cp "$W/out/$name/$v-$r/screen.txt" "$RES/cases/$name/$v-$r.screen.txt" 2>/dev/null
        done
    done
done
docker run --rm -v "$W:/w" alpine:3.22 rm -rf /w/out
rm -rf "$W"
echo "끝 $(date +%H:%M:%S)"
