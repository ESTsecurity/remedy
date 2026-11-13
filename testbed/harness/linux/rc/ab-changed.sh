#!/bin/bash
# rc 묶음 — 패키지가 깐 실행 파일을 그대로 둔 것과 다른 파일로 바꾼 것에서 리눅스 점검 룰 셋의 A/B(`rc-bundle.sh`).
#
#   bash testbed/harness/linux/rc/ab-changed.sh <A tar.gz> <B 폴더(remedy + plugins/)> <결과 폴더>
#
# 패키지 기록과 다른 실행 파일은 6 이어야 한다(1.7.0). 컨테이너마다 A(지난 공개본)와 B 를 같은 파일 시스템에서 차례로
# 돌린다. 설치에 망이 든다. RPM 경우는 Oracle Linux 8(glibc 2.28)이라 배포본(정적)이 필요하다 — 개발 빌드(bookworm ·
# glibc 2.34)로 잴 때는 `OL_IMAGE=oraclelinux:9`(php:7.4 모듈은 8 에만 있다).
#
# summary.txt 한 줄 = 경우 하나: `이름 setup=… docker=… | 룰 A=코드 B=코드`.
set -u
A_TGZ=${1:?A tar.gz}
B_DIR=${2:?B folder}
RES=${3:?result folder}
W=/tmp/remedy-abchg
RULES="php2shell-check-linux php-session-check-linux node2shell-check-linux"
APT='apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y'
OL_IMAGE=${OL_IMAGE:-oraclelinux:8}
if [ "$OL_IMAGE" = "oraclelinux:8" ]; then OL_SETUP='dnf -y -q module enable php:7.4 && dnf -y -q install php-cli'; else OL_SETUP='dnf -y -q install php-cli'; fi
OL_TAG=$(echo "$OL_IMAGE" | tr -d ':' | sed 's/oraclelinux/ol/')
OL_CASES=(
    "$OL_TAG-php|$OL_IMAGE|$OL_SETUP"
    "$OL_TAG-php-changed|$OL_IMAGE|$OL_SETUP && cp /bin/ls /usr/bin/php"
)
# 이름|이미지|검사 전에 sh -c 로 돌릴 준비 — 바꿔 치기는 컨테이너 안에서 한다
CASES=(
    "debian12-php|debian:12|$APT php-cli"
    "debian12-php-changed|debian:12|$APT php-cli"' && cp /bin/ls "$(readlink -f /usr/bin/php)"'
    "debian12-php82|debian:12|$APT php8.2-cli"
    "debian12-php82-changed|debian:12|$APT php8.2-cli"' && cp /bin/ls "$(readlink -f /usr/bin/php)"'
    "debian12-php82-other|debian:12|$APT php8.2-cli"' && cp /bin/true /usr/bin/xargs'
    "ubuntu24-php|ubuntu:24.04|$APT php-cli"
    "${OL_CASES[@]}"
    "debian12-nodejs|debian:12|$APT nodejs"
    "debian12-nodejs-changed|debian:12|$APT nodejs"' && cp /bin/ls "$(readlink -f /usr/bin/node)"'
)
rm -rf "$W"
mkdir -p "$W/a" "$W/b" "$W/out" "$RES"
tar -xzf "$A_TGZ" -C "$W/a" --strip-components=1 || { echo "A 를 풀지 못했다"; exit 9; }
cp -r "$B_DIR"/. "$W/b/" || { echo "B 를 옮기지 못했다"; exit 9; }
echo "A: $("$W/a/remedy" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+')"
echo "B: $("$W/b/remedy" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+')"
cat > "$W/inside.sh" <<'EOF'
#!/bin/sh
# 컨테이너 안: 준비, 그리고 룰 셋을 A 로 · B 로
name=$1
setup=$2
rules=$3
mkdir -p "/out/$name"
if sh -c "$setup" > "/out/$name/setup.log" 2>&1; then echo ok > "/out/$name/setup.txt"; else echo "failed $?" > "/out/$name/setup.txt"; fi
for r in $rules; do
    for v in a b; do
        d="/out/$name/$v-$r"
        mkdir -p "$d"
        "/$v/remedy" scan --plugin "/$v/plugins/$r/plugin.yaml" --out-dir "$d/out" > "$d/screen.txt" 2>&1
        echo "$r $v $?" >> "/out/$name/codes.txt"
        chmod 644 "$d/screen.txt"
    done
done
EOF
for c in "${CASES[@]}"; do
    IFS='|' read -r name image setup <<< "$c"
    t0=$(date +%s)
    docker run --rm --pull=never -v "$W/a:/a:ro" -v "$W/b:/b:ro" -v "$W/out:/out" -v "$W/inside.sh:/inside.sh:ro" \
        "$image" sh /inside.sh "$name" "$setup" "$RULES" > "$W/out/$name.docker.log" 2>&1
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
