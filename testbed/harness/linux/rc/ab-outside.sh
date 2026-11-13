#!/bin/bash
# rc 묶음 — 선언 밖 자리와 도는 프로세스에서 리눅스 점검 룰 셋의 A/B(`rc-bundle.sh`).
#
#   bash testbed/harness/linux/rc/ab-outside.sh <A tar.gz> <B tar.gz> <결과 폴더>
#
# A(지난 공개본)와 B 를 같은 컨테이너에서 이 상태들로 돌린다:
#   P0 php:8.3.36-cli 그대로             P1 같은 php 를 /opt/custom/bin 에 옮겨 거기서 돌린다
#   P2 php:8.3.36-fpm — php-fpm 이 제 자리에서 돈다(일꾼은 www-data · 기본 권한)
#   P3 P2 와 같고 --cap-add SYS_PTRACE
#   N0 node:22.23.4-bookworm-slim 그대로  N1 같은 node 를 /srv/app 에 옮겨 거기서 돌린다
#
# summary.txt 한 줄 = 상태 하나: `이름 docker=… | 룰 A=코드 B=코드`.
set -u
A_TGZ=${1:?A tar.gz}
B_TGZ=${2:?B tar.gz}
OUT=${3:?result folder}
W=/tmp/remedy-rcab
rm -rf "$W"
mkdir -p "$W/a" "$W/b" "$OUT"
tar -xzf "$A_TGZ" -C "$W/a" --strip-components=1 || { echo "A 를 풀지 못했다"; exit 9; }
tar -xzf "$B_TGZ" -C "$W/b" --strip-components=1 || { echo "B 를 풀지 못했다"; exit 9; }
for v in a b; do
    echo "$v: $("$W/$v/remedy" --version 2> /dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+')"
done
RULES="php2shell-check-linux php-session-check-linux node2shell-check-linux"
for r in $RULES; do
    for v in a b; do
        [ -f "$W/$v/plugins/$r/plugin.yaml" ] || { echo "$v/plugins/$r 가 없다"; exit 8; }
    done
done
cat > "$W/run.sh" << 'EOF'
#!/bin/sh
# 컨테이너 안: 준비(뒤에서 프로세스를 띄울 수 있다), 그리고 룰 셋을 a 로 · b 로
name=$1
setup=$2
rules=$3
sh -c "$setup" > "/out/$name.setup.log" 2>&1
sleep 2
for v in a b; do
    for r in $rules; do
        "/$v/remedy" scan --plugin "/$v/plugins/$r/plugin.yaml" --out-dir "/tmp/o-$v-$r" > "/out/$name-$v-$r.txt" 2>&1
        echo "$name $v $r $?" >> /out/codes.txt
    done
done
chmod 644 /out/* 2> /dev/null
EOF
: > "$OUT/codes.txt"
: > "$OUT/summary.txt"
run() { # 이름 이미지 준비 [docker 옵션]
    local name=$1 image=$2 setup=$3 rc line r
    shift 3
    docker run --rm --pull=never "$@" -v "$W/a:/a:ro" -v "$W/b:/b:ro" -v "$OUT:/out" -v "$W/run.sh:/run.sh:ro" \
        "$image" sh /run.sh "$name" "$setup" "$RULES" > /dev/null 2>&1
    rc=$?
    line="$name docker=$rc"
    for r in $RULES; do
        line="$line | $r A=$(awk -v n="$name" -v r="$r" '$1==n && $2=="a" && $3==r {print $4}' "$OUT/codes.txt")"
        line="$line B=$(awk -v n="$name" -v r="$r" '$1==n && $2=="b" && $3==r {print $4}' "$OUT/codes.txt")"
    done
    echo "$line" | tee -a "$OUT/summary.txt"
}
run P0 php:8.3.36-cli ''
run P1 php:8.3.36-cli 'mkdir -p /opt/custom/bin && cp /usr/local/bin/php /opt/custom/bin/php && (/opt/custom/bin/php -r "sleep(600);" &)'
run P2 php:8.3.36-fpm '(php-fpm -D)'
run P3 php:8.3.36-fpm '(php-fpm -D)' --cap-add SYS_PTRACE
run N0 node:22.23.4-bookworm-slim ''
run N1 node:22.23.4-bookworm-slim 'mkdir -p /srv/app && cp /usr/local/bin/node /srv/app/node && (/srv/app/node -e "setTimeout(function(){},600000)" &)'
rm -rf "$W"
echo "끝 $(date +%H:%M:%S)"
