#!/bin/bash
# remedy-net 의 Apache(코어 1.18.0) — 이미지 · 컨테이너 점검의 판정을 실제 이미지로 잰다(목표 remedy_net아파치 기준 1 · 2).
# 코어 1.19.0(목표 remedy_net엔진보완)에서 RPM DB 의 자리(Oracle Linux 9) · Amazon Linux 컨테이너 · url 의 Apache 를 더했다.
# 코어 1.19.1 에서 이미지 칸 둘 — Ubuntu 위의 Debian 관리자 주소(바깥 저장소의 빌드)와 이름에 역슬래시가 든 항목.
#
# 호스트(WSL · 기본 사용자)에서, 저장소 루트:
#
#   bash testbed/harness/linux/net-apache-verify.sh --bin <remedy-net> --criteria <기준 폴더> --images <tar 폴더> \
#        --out <결과 폴더> [--anchor <공개키 base64>]
#
# `--bin` 은 리눅스 remedy-net(musl 정적 — 개발 빌드는 `musl-dev-build.sh --net`, rc 는 꾸러미의 것), `--criteria` 는
# 그것이 확인할 판정 기준 폴더(저장소의 `plugins/remedy-net-criteria` 는 서명이 없다 — `bash ci/dev-sign.sh --out <폴더>
# plugins/remedy-net-criteria` 로 일회용 키 사본을 만들어 그 폴더와 `--anchor "$(cat <폴더>/anchor.txt)"` 를 준다 · 개발
# 빌드만 받는다). `--images` 는 tar 를 두는 폴더다(Windows 쪽에 두면 Windows 의 `Invoke-NetApache.ps1` 도 읽는다 · 없는
# tar 만 만든다).
#
# # 무해한가
#
# **실검체는 없다.** 이미지는 배포판 저장소의 Apache 를 깐 하네스 이미지(`apache-verify.sh` 가 짓는 `remedy-harness/apache:*`)와
# 공식 `httpd` · `php:8.2-apache` 이미지다. 그 위의 꼴은 망 없는 일회용 컨테이너에서 설정을 켜거나(HTTP/2) 모듈 파일 끝에
# 1바이트를 붙이거나(기록과 다르게) 패키지 기록의 판만 바꿔(같은 모듈 파일을 담은 가짜 판 패키지 · 2026-11-23) `docker commit` 한
# 것이다. remedy-net 은 이미지를 실행하지 않고, 컨테이너는 docker:dind 안에서 띄웠다 지운다.
#
# # 무엇을 재나
#
#   I  이미지 19 — `net-apache-cases.txt` 의 표(종료 코드 · 결과 JSON 의 근거 글). 1.19.1 의 둘: Ubuntu 22.04 의 기록을
#      `ondrej/apache2` PPA 의 빌드 꼴(그 판 · Debian Apache 팀 주소)로 바꿔 6(1.19.0 은 0) · Ubuntu 24.04 에 systemd 꼴의
#      유닛 파일(`system-systemd\x2dcryptsetup.slice`)을 두고 영향 판 + HTTP/2 로 2(1.19.0 은 그 레이어를 거절해 6)
#   C  컨테이너 10 — Rocky 9 6 · Debian 12 6(고친 판이어도 컨테이너는 양호를 내지 않는다) · Alpine 6 ·
#      php:8.2-apache 에서 `a2enmod http2` 2 · 공식 httpd 6 · 도는 컨테이너 안에서 HTTP/2 를 켠 httpd 2 ·
#      Oracle Linux 9 6(rpm 이 쓰는 DB 의 mod_http2 판) · Amazon Linux 2023 에서 HTTP/2 를 켜면 고친 판 6 · 고치기 전 판 2 ·
#      Amazon Linux 2 6
#
# # 입력의 고정(2026-11-23)
#
# 러너는 이미지를 그날 새로 짓고 받아, 예전에 지은 PC 와 같은 공개본이 다른 칸이 됐다(24/32 — 룰은 맞게 0). 그래서:
#   - Rocky 9 · Amazon Linux 2023 의 하네스 이미지는 짓는 날 저장소의 고친 판을 깐다 — 깐 그대로는 0(이미지) · 6(컨테이너)이고,
#     고치기 전 판은 그 이미지의 mod_http2 를 **같은 모듈 파일을 담은** 가짜 판 패키지(Rocky 2.0.26-6.el9_8.2 · Amazon
#     1:2.4.69-1.amzn2023.0.2)로 바꾼 꼴이다. 빈 패키지로 바꾸면 '파일 목록에 모듈이 없다' 는 다른 길로 6 이 된다(같은 날 실측).
#   - `php:8.2-apache` 는 떠다니는 꼬리표라 고치기 전 빌드(2026-10-21 · Debian 13 의 apache2 2.4.69-1~deb13u1)를 다이제스트로
#     받아 하네스 꼬리표를 붙인다.
#   - Oracle Linux 9 의 근거 글은 깐 판이 아니라 RPM DB 를 읽은 줄(`설치 정보: ol 9.`)이다 — 판은 짓는 날마다 바뀐다.
#   - tar 는 없거나 그 이미지가 바뀌었을 때(이미지 id · `<tar>.id`) 만든다 — 없을 때만 만들던 때는 하네스 이미지를 다시 지어도
#     PC 의 tar 가 예전 판으로 남았다.
#   U  url 6 — 망 없는 Apache 하나에 같은 망 이름공간의 일회용 컨테이너에서 `remedy-net url`(HEAD 하나): 공식 httpd
#      2.4.65 의 HTTP/2 끔 6 · h2c 2 · TLS h2(`--cacert`) 2 · `ServerTokens Prod` 6 · Debian 6 · 공식 httpd 2.4.71 6
#
# 종료 코드: 0 = 칸 모두 통과 · 1 = 하나라도 어긋남 · 2 = 인자 · 준비가 모자라다.
set -u
BIN="" CRIT="" IMAGES="" OUT="" ANCHOR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --criteria) CRIT=$2; shift 2 ;;
        --images) IMAGES=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --anchor) ANCHOR=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN" ] && [ -d "$CRIT" ] && [ -n "$IMAGES" ] && [ -n "$OUT" ] || {
    echo "--bin · --criteria · --images · --out 이 필요하다" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
CASES="$HERE/net-apache-cases.txt"
docker info >/dev/null 2>&1 || { echo "docker 가 돌지 않는다" >&2; exit 2; }
for i in remedy-harness/apache:rocky9 remedy-harness/apache:debian12 remedy-harness/apache:ubuntu2404 \
    remedy-harness/apache:ubuntu2204 remedy-harness/apache:alpine322 remedy-harness/apache:al2023 remedy-harness/apache:rocky8 remedy-harness/apache:alma9 \
    remedy-harness/apache:leap156 remedy-harness/apache:ol9 remedy-harness/apache:al2 \
    remedy-harness/apache:rocky9-rpmbuild remedy-harness/apache:al2023-rpmbuild; do
    docker image inspect "$i" >/dev/null 2>&1 || { echo "$i 가 없다 — apache-verify.sh 를 먼저 돌려 짓는다" >&2; exit 2; }
done
# 고치기 전 `php:8.2-apache`(2026-10-21 빌드) — 머리말의 '입력의 고정'. 하네스 꼬리표로 다룬다(dind 안에서도 그 이름으로 띄운다).
PHP_APACHE=php@sha256:a6e1550bb2c43add980125b769cd5add5aae5889419a5ddfad21bf930fa04faa
PHP_TAG=remedy-harness/net-apache:php82apache
for i in "$PHP_APACHE" httpd:2.4.65 httpd:2.4.71 docker:dind; do
    docker image inspect "$i" >/dev/null 2>&1 || docker pull -q --platform linux/amd64 "$i" >/dev/null || {
        echo "$i 를 받지 못했다" >&2; exit 2; }
done
docker image inspect "$PHP_TAG" >/dev/null 2>&1 || docker tag "$PHP_APACHE" "$PHP_TAG" || exit 2
mkdir -p "$IMAGES" "$OUT"
OUT=$(cd "$OUT" && pwd)
IMAGES=$(cd "$IMAGES" && pwd)
SUM=$OUT/summary.txt
: >"$SUM"
note() { echo "$*" | tee -a "$SUM"; }
W=$(mktemp -d /tmp/remedy-net-apache-verify.XXXXXX)
trap 'docker rm -f -v remedy-net-apache-verify-dind >/dev/null 2>&1; docker run --rm -v /tmp:/t alpine:3.22 rm -rf "/t/${W#/tmp/}"' EXIT

# ── 꼴 — 망 없는 일회용 컨테이너에서 바꾸고 commit 한다(없을 때만) ─────────────────────────────
# 고치기 전 판의 mod_http2 — 깔려 있던 모듈 파일을 그대로 담은 가짜 판 패키지로 바꿔 다시 깐다(머리말의 '입력의 고정').
# `sh /w/fake-rpm.sh <epoch 또는 -> <판> <릴리스> <공급사>` — rpm-build 가 든 하네스 이미지(`*-rpmbuild`)에서.
cat >"$W/fake-rpm.sh" <<'RPM'
set -e
so=/usr/lib64/httpd/modules/mod_http2.so
cp "$so" /tmp/mod_http2.so
rpm -e --nodeps mod_http2
mkdir -p /tmp/rb/SPECS
{
  echo "Name: mod_http2"
  [ "$1" = - ] || echo "Epoch: $1"
  echo "Version: $2"
  echo "Release: $3"
  echo "Summary: placeholder"
  echo "License: ASL 2.0"
  echo "Vendor: $4"
  echo "%description"
  echo "placeholder"
  echo "%install"
  echo "mkdir -p %{buildroot}/usr/lib64/httpd/modules"
  echo "cp /tmp/mod_http2.so %{buildroot}$so"
  echo "%files"
  echo "$so"
} >/tmp/rb/SPECS/m.spec
rpmbuild -bb --define "_topdir /tmp/rb" --define "debug_package %{nil}" --define "__os_install_post %{nil}" /tmp/rb/SPECS/m.spec >/dev/null
rpm -i --nodeps /tmp/rb/RPMS/*/mod_http2-*.rpm
rm -rf /tmp/rb /tmp/mod_http2.so
echo "LoadModule http2_module modules/mod_http2.so" >/etc/httpd/conf.modules.d/10-h2.conf
RPM
variant() { # 이름 · 바탕 이미지 · 명령 — 이미지 점검만 쓴다(그 시작 명령은 이 명령으로 바뀌어 있다)
    local tag="remedy-harness/net-apache:$1" cid
    docker image inspect "$tag" >/dev/null 2>&1 && return 0
    cid=$(docker run -d --network none -v "$W:/w:ro" --entrypoint sh "$2" -c "$3") || return 1
    [ "$(docker wait "$cid")" = 0 ] || { docker rm "$cid" >/dev/null; return 1; }
    docker commit "$cid" "$tag" >/dev/null && docker rm "$cid" >/dev/null
}
variant httpd-2.4.65-h2 httpd:2.4.65 \
    'sed -i "s/^#LoadModule http2_module/LoadModule http2_module/" conf/httpd.conf && echo "Protocols h2 http/1.1" >> conf/httpd.conf' || exit 2
# 고정한 php 빌드에서 짓는다 — 예전 이름(php-8.2-apache-h2)은 떠다니는 꼬리표에서 지은 것이라 다른 빌드일 수 있다.
variant php82apache-h2 "$PHP_TAG" 'a2enmod http2 >/dev/null' || exit 2
variant rocky9-vuln remedy-harness/apache:rocky9-rpmbuild \
    "sh /w/fake-rpm.sh - 2.0.26 6.el9_8.2 'Rocky Enterprise Software Foundation'" || exit 2
variant al2023-vuln remedy-harness/apache:al2023-rpmbuild "sh /w/fake-rpm.sh 1 2.4.69 1.amzn2023.0.2 'Amazon Linux'" || exit 2
variant debian12-tampered remedy-harness/apache:debian12 'printf X >> /usr/lib/apache2/modules/mod_http2.so' || exit 2
# 코어 1.19.1 — 바깥 저장소(ondrej/apache2 PPA)가 Ubuntu 22.04 용으로 낸 빌드의 판 · 관리자 주소(Launchpad 의 공개 기록 ·
# 2023-10 ~ 2024-05 게시). dpkg 의 순서로는 Ubuntu 의 고친 판 2.4.58-1ubuntu8.19 보다 높다 — 1.19.0 은 그것을 양호로 냈다.
variant ubuntu2204-ppa remedy-harness/apache:ubuntu2204 \
    'for p in apache2 apache2-bin apache2-data apache2-utils; do sed -i "/^Package: $p\$/,/^\$/ s/^Version: .*/Version: 2.4.58-1+ubuntu22.04.1+deb.sury.org+1/; /^Package: $p\$/,/^\$/ s/^Maintainer: .*/Maintainer: Debian Apache Maintainers <debian-apache@lists.debian.org>/" /var/lib/dpkg/status || exit 1; done && a2enmod -q http2 >/dev/null' || exit 2
# 코어 1.19.1 — systemd 가 유닛 이름에 쓰는 역슬래시(`\x2d`). 1.19.0 은 그 항목이 든 레이어를 통째로 거절했다.
variant ubuntu2404-systemd remedy-harness/apache:ubuntu2404 \
    'mkdir -p /usr/lib/systemd/system && printf "[Unit]\n" >"/usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice" && sed -i "/^Package: apache2-bin\$/,/^\$/ s/^Version: .*/Version: 2.4.58-1ubuntu8.18/" /var/lib/dpkg/status && a2enmod -q http2 >/dev/null' || exit 2

# ── tar — 없거나 그 이미지가 바뀐 것만(이미지 id 를 `<tar>.id` 에 적는다) ─────────────────────────────
save() { # tar 이름 · 이미지
    local id
    id=$(docker image inspect --format '{{.Id}}' "$2" 2>/dev/null) || return 1
    [ -s "$IMAGES/$1" ] && [ "$(cat "$IMAGES/$1.id" 2>/dev/null)" = "$id" ] && return 0
    docker save --platform linux/amd64 -o "$IMAGES/$1.part" "$2" 2>/dev/null || docker save -o "$IMAGES/$1.part" "$2" || return 1
    mv "$IMAGES/$1.part" "$IMAGES/$1" && printf '%s\n' "$id" >"$IMAGES/$1.id"
}
for n in rocky9 debian12 ubuntu2404 alpine322 al2023 rocky8 alma9 leap156 ol9 al2; do
    save "apache-$n.tar" "remedy-harness/apache:$n" || { echo "apache-$n.tar 를 만들지 못했다" >&2; exit 2; }
done
save php-8.2-apache.tar "$PHP_TAG" && save httpd-2.4.65.tar httpd:2.4.65 && save httpd-2.4.71.tar httpd:2.4.71 || exit 2
for n in httpd-2.4.65-h2 php82apache-h2 debian12-tampered ubuntu2204-ppa ubuntu2404-systemd rocky9-vuln al2023-vuln; do
    save "net-apache-$n.tar" "remedy-harness/net-apache:$n" || { echo "net-apache-$n.tar 를 만들지 못했다" >&2; exit 2; }
done
note "remedy-net: $("$BIN" --version 2>/dev/null | head -1)"

pass=0 fail=0
judge() { # 이름 · 기대 · 받은 · 결과 JSON · 근거 글
    local ok=1
    [ "$2" = "$3" ] || ok=0
    if [ "$5" != "-" ] && ! grep -qF -- "$5" "$4" 2>/dev/null; then ok=0; fi
    if [ "$ok" = 1 ]; then pass=$((pass + 1)); r=PASS; else fail=$((fail + 1)); r=FAIL; fi
    note "$(printf '%-6s %-22s 기대 %s · 받은 %s · 근거 %s' "$r" "$1" "$2" "$3" "$5")"
}
env_run() { REMEDY_NET_CRITERIA=$CRIT REMEDY_NET_ANCHOR=$ANCHOR LANG=C.UTF-8 REMEDY_LANG=ko "$@"; }

# ── I: 이미지 — tar 를 로컬 파일 시스템(/tmp)으로 옮겨 하나씩(리눅스 remedy-net 은 9p 경로를 받지 않는다) ──────────
note "== 이미지"
grep -v '^#' "$CASES" | while read -r name tar want why; do
    [ -n "$name" ] || continue
    cp "$IMAGES/$tar" "$W/$tar" || { echo "$name $tar 를 옮기지 못했다" >>"$SUM"; continue; }
    env_run "$BIN" image "$W/$tar" --runtime apache --consent y --out-dir "$W/out-$name" >"$OUT/image-$name.txt" 2>&1
    got=$?
    rm -f "$W/$tar"
    j=$(ls "$W/out-$name"/*.json 2>/dev/null | head -1)
    [ -n "$j" ] && cp "$j" "$OUT/image-$name.json"
    judge "image $name" "$want" "$got" "$OUT/image-$name.json" "$why"
    echo "$pass $fail" >"$W/count"
done
read -r pass fail <"$W/count"

# ── C: 컨테이너 — docker:dind 안에서(진짜 리눅스 엔진 · 망 없음) ──────────────────────────────
note "== 컨테이너"
mkdir -p "$W/c"
cp "$BIN" "$W/c/remedy-net"
cp -r "$CRIT" "$W/c/crit"
cp "$HERE/net-apache-dind.sh" "$W/c/inside.sh"
docker run -d --privileged --name remedy-net-apache-verify-dind -v "$W:/w" -v "$IMAGES:/in:ro" docker:dind >/dev/null || {
    note "FAIL   dind 가 뜨지 않았다"; exit 1; }
for _ in $(seq 1 60); do docker exec remedy-net-apache-verify-dind docker info >/dev/null 2>&1 && break; sleep 1; done
docker exec -e ANCHOR="$ANCHOR" remedy-net-apache-verify-dind sh /w/c/inside.sh
# -v: docker:dind 는 /var/lib/docker 를 이름 없는 볼륨으로 잡는다 — 빼면 돌 때마다 그 볼륨(약 1.8 GB)이 남는다
docker rm -f -v remedy-net-apache-verify-dind >/dev/null 2>&1
while read -r name want got why; do
    j=$(ls "$W/c/out-$name"/*.json 2>/dev/null | head -1)
    [ -n "$j" ] && cp "$j" "$OUT/container-$name.json"
    cp "$W/c/$name.txt" "$OUT/container-$name.txt" 2>/dev/null
    judge "container $name" "$want" "$got" "$OUT/container-$name.json" "$why"
done <"$W/c/results"

# ── U: url — 망 없는 Apache 하나에 HEAD 하나(같은 망 이름공간의 일회용 컨테이너에서 · 코어 1.19.0) ─────────────────
# 판정은 목표 remedy_net엔진보완 결정 1 — 상류 빌드의 영향 판이고 같은 응답의 Upgrade 가 HTTP/2 를 알릴 때만 2.
note "== url"
mkdir -p "$W/u"
cp "$BIN" "$W/u/remedy-net"
cp -r "$CRIT" "$W/u/crit"
URL_SRV=remedy-net-apache-url
url_case() { # 이름 · 기대 · 근거 글 · 이미지 · 주소 · 서버를 켜는 명령
    local name=$1 want=$2 why=$3 image=$4 url=$5 cmd=$6 extra="" got j
    docker rm -f -v "$URL_SRV" >/dev/null 2>&1
    if ! docker run -d --network none --name "$URL_SRV" --entrypoint sh "$image" -c "$cmd" >/dev/null; then
        note "FAIL   url $name — 서버가 뜨지 않았다"
        fail=$((fail + 1))
        return
    fi
    for _ in $(seq 1 40); do
        docker logs "$URL_SRV" 2>&1 | grep -q 'resuming normal operations' && break
        sleep 0.5
    done
    case "$url" in
        https:*) docker cp "$URL_SRV:/usr/local/apache2/conf/ca.crt" "$W/u/ca-$name.crt" >/dev/null &&
            extra="--cacert /u/ca-$name.crt" ;;
    esac
    # extra 는 비었거나 옵션 둘이라 따옴표를 씌우지 않는다. 이 사용자로 돌려야 결과 폴더(남이 못 읽는 꼴)를 읽는다.
    docker run --rm --user "$(id -u):$(id -g)" --network "container:$URL_SRV" -v "$W/u:/u" -e REMEDY_NET_CRITERIA=/u/crit \
        -e REMEDY_NET_ANCHOR="$ANCHOR" -e LANG=C.UTF-8 -e REMEDY_LANG=ko alpine:3.22 \
        /u/remedy-net url "$url" $extra --consent y --out-dir "/u/out-$name" >"$OUT/url-$name.txt" 2>&1
    got=$?
    docker rm -f -v "$URL_SRV" >/dev/null 2>&1
    j=$(ls "$W/u/out-$name"/*.json 2>/dev/null | head -1)
    [ -n "$j" ] && cp "$j" "$OUT/url-$name.json"
    judge "url $name" "$want" "$got" "$OUT/url-$name.json" "$why"
}
H2ON='sed -i "s/^#LoadModule http2_module/LoadModule http2_module/" conf/httpd.conf'
# TLS — 일회용 CA 와 그 CA 가 서명한 127.0.0.1 인증서(rustls 는 CA 를 서버 인증서로 받지 않는다). ALPN 없이 잇는
# 지금의 url 에도 HTTP/2 를 켠 서버는 `Upgrade: h2` 를 싣는다(2026-11-15 실측).
TLS='sed -i -e "s/^#LoadModule http2_module/LoadModule http2_module/" -e "s/^#LoadModule ssl_module/LoadModule ssl_module/" -e "s/^#LoadModule socache_shmcb_module/LoadModule socache_shmcb_module/" conf/httpd.conf &&
openssl req -x509 -newkey rsa:2048 -nodes -keyout conf/ca.key -out conf/ca.crt -days 2 -subj /CN=remedy-harness-ca -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null &&
openssl req -newkey rsa:2048 -nodes -keyout conf/server.key -out conf/server.csr -subj /CN=127.0.0.1 2>/dev/null &&
printf "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > conf/ext.cnf &&
openssl x509 -req -in conf/server.csr -CA conf/ca.crt -CAkey conf/ca.key -CAcreateserial -out conf/server.crt -days 2 -extfile conf/ext.cnf 2>/dev/null &&
printf "Listen 443\n<VirtualHost *:443>\nSSLEngine on\nSSLCertificateFile conf/server.crt\nSSLCertificateKeyFile conf/server.key\nProtocols h2 http/1.1\n</VirtualHost>\n" >> conf/httpd.conf &&
httpd-foreground'
url_case httpd2465 6 "HTTP/2 를 알리지 않습니다" httpd:2.4.65 http://127.0.0.1/ 'httpd-foreground'
url_case httpd2465-h2c 2 "Upgrade: h2c" httpd:2.4.65 http://127.0.0.1/ \
    "$H2ON && echo 'Protocols h2c http/1.1' >> conf/httpd.conf && httpd-foreground"
url_case httpd2465-prod 6 "ServerTokens Prod" httpd:2.4.65 http://127.0.0.1/ \
    "$H2ON && printf 'Protocols h2c http/1.1\nServerTokens Prod\n' >> conf/httpd.conf && httpd-foreground"
url_case httpd2465-tls 2 "Upgrade: h2" httpd:2.4.65 https://127.0.0.1/ "$TLS"
url_case debian 6 "배포판이 지은 Apache(Debian)" "$PHP_TAG" http://127.0.0.1/ \
    "a2enmod http2 >/dev/null && echo 'Protocols h2c http/1.1' > /etc/apache2/conf-enabled/zz-h2.conf && apache2-foreground"
url_case httpd2471-h2c 6 "영향 범위" httpd:2.4.71 http://127.0.0.1/ \
    "$H2ON && echo 'Protocols h2c http/1.1' >> conf/httpd.conf && httpd-foreground"
note "통과 $pass · 실패 $fail"
[ "$fail" = 0 ]
