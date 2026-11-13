#!/bin/bash
# rc 묶음 — systemd 서비스만이 가리키는 PHP · Node 에서 리눅스 점검 룰 셋의 A/B(`rc-bundle.sh`).
#
#   bash testbed/harness/linux/rc/ab-sources.sh <A tar.gz> <B 폴더(remedy + plugins/)> <결과 폴더>
#
# 유닛 파일만 놓고 아무것도 띄우지 않는다. A(지난 공개본)와 B 를 같은 일회용 컨테이너에서 차례로 돌린다. 망은 쓰지 않는다.
#
# summary.txt 한 줄 = 경우 하나: `이름 setup=… docker=… | 룰 A=코드 B=코드`.
set -u
A_TGZ=${1:?A tar.gz}
B_DIR=${2:?B folder}
RES=${3:?result folder}
W=/tmp/remedy-src
RULES="php2shell-check-linux php-session-check-linux node2shell-check-linux"
UNIT='mkdir -p /etc/systemd/system && printf "[Unit]\nDescription=lab\n[Service]\nExecStart=%s\n[Install]\nWantedBy=multi-user.target\n"'
# 이름|이미지|준비(sh -c)
CASES=(
    "clean|debian:12|true"
    "php-outside|debian:12|$UNIT '/opt/php83/sbin/php-fpm --nodaemonize' > /etc/systemd/system/php83-fpm.service"
    "php-distro|debian:12|$UNIT '/usr/sbin/php-fpm8.2 --nodaemonize' > /etc/systemd/system/php8.2-fpm.service"
    "php-optphp|debian:12|$UNIT '/opt/php/sbin/php-fpm --nodaemonize' > /etc/systemd/system/php-fpm.service"
    "node-outside|debian:12|$UNIT '/srv/node/bin/node /srv/app/server.js' > /etc/systemd/system/app.service"
    "node-nvm|debian:12|$UNIT '/home/alice/.nvm/versions/node/v22.23.4/bin/node /srv/app/server.js' > /etc/systemd/system/app.service"
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
ls -la /etc/systemd/system > "/out/$name/units.txt" 2>&1
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
    docker run --rm --pull=never -v "$W/a:/a:ro" -v "$W/b:/b:ro" -v "$W/out:/out" \
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
