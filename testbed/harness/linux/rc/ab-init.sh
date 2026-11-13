#!/bin/bash
# rc 묶음 — 시작 스크립트(SysV · OpenRC · Upstart)와 Apache 설정이 가리키는 PHP · Node 에서 리눅스 점검 룰 셋의 A/B
# (`rc-bundle.sh` · 1.10.0 의 발견 출처).
#
#   bash testbed/harness/linux/rc/ab-init.sh <A tar.gz> <B 폴더(remedy + plugins/)> <결과 폴더> [경우 이름]
#
# 파일만 놓거나(또는 실제 패키지를 깔고) 아무것도 띄우지 않는다. A(지난 공개본)와 B 를 같은 일회용 컨테이너에서 차례로
# 돌린다. real-* 경우는 설치에 망이 든다. 넷째 인자를 주면 그 경우 하나만 돈다.
#
# summary.txt 한 줄 = 경우 하나: `이름 setup=… docker=… | 룰 A=코드 B=코드`.
set -u
A_TGZ=${1:?A tar.gz}
B_DIR=${2:?B folder}
RES=${3:?result folder}
W=/tmp/remedy-init
RULES="php2shell-check-linux php-session-check-linux node2shell-check-linux"
# 이름|이미지 — 준비 스크립트는 경우 폴더에 두고 sh 로 돌린다
CASES=(
    "clean|debian:12"
    "sysv-php-own|debian:12"
    "sysv-node-default|debian:12"
    "openrc-node|debian:12"
    "upstart-php|debian:12"
    "apache-deb-own|debian:12"
    "apache-own|debian:12"
    "apache-lampp|debian:12"
    "apache-suse|debian:12"
    "apache-rpm-zts-own|debian:12"
    "real-php-apache|php:8.2-apache"
    "real-deb12|debian:12"
    "real-rocky9|rockylinux:9"
    "real-rocky8|rockylinux:8"
    "apache-rpm8-conf|debian:12"
)
ONLY=${4:-}
rm -rf "$W"
mkdir -p "$W/a" "$W/b" "$W/out" "$W/setup" "$RES"
tar -xzf "$A_TGZ" -C "$W/a" --strip-components=1 || { echo "A 를 풀지 못했다"; exit 9; }
cp -r "$B_DIR"/. "$W/b/" || { echo "B 를 옮기지 못했다"; exit 9; }
echo "A: $("$W/a/remedy" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+')"
echo "B: $("$W/b/remedy" --version 2>/dev/null | grep -m1 -E '[0-9]+\.[0-9]+\.[0-9]+')"

# 준비 스크립트는 printf 로 쓴다 — heredoc 이 역슬래시를 건드리지 않게.
put() { printf '%s\n' "$2" > "$W/setup/$1.sh"; }
put clean 'true'
put sysv-php-own 'mkdir -p /etc/init.d
printf "%s\n" "#!/bin/sh" "prefix=/opt/php83" "exec_prefix=\${prefix}" "php_fpm_BIN=\${exec_prefix}/sbin/php-fpm" "php_opts=\"--fpm-config /opt/php83/etc/php-fpm.conf\"" "case \"\$1\" in" "  start) \$php_fpm_BIN --daemonize \$php_opts ;;" "esac" > /etc/init.d/php83-fpm
chmod 755 /etc/init.d/php83-fpm'
put sysv-node-default 'mkdir -p /etc/init.d /etc/default
printf "%s\n" "#!/bin/sh" "DAEMON=/usr/bin/node" "[ -r /etc/default/web ] && . /etc/default/web" "start-stop-daemon --start --background --exec \$DAEMON -- /srv/app/server.js > /dev/null 2>&1" > /etc/init.d/web
printf "%s\n" "DAEMON=/srv/node/bin/node" > /etc/default/web
chmod 755 /etc/init.d/web'
put openrc-node 'mkdir -p /etc/init.d /etc/conf.d
printf "%s\n" "#!/sbin/openrc-run" "command=/usr/bin/node" "command_args=/srv/app/server.js" "command_background=true" > /etc/init.d/app
printf "%s\n" "command=/srv/app/bin/node" > /etc/conf.d/app
chmod 755 /etc/init.d/app'
put upstart-php 'mkdir -p /etc/init
printf "%s\n" "description \"worker\"" "start on runlevel [2345]" "respawn" "exec /srv/php/bin/php /srv/worker.php >> /var/log/worker.log 2>&1" > /etc/init/worker.conf'
put apache-deb-own 'mkdir -p /etc/apache2/mods-available /etc/apache2/mods-enabled
printf "%s\n" "LoadModule php_module /opt/php83/lib/libphp.so" > /etc/apache2/mods-available/php83.load
ln -s ../mods-available/php83.load /etc/apache2/mods-enabled/php83.load'
put apache-own 'mkdir -p /usr/local/apache2/conf
printf "%s\n" "ServerRoot \"/usr/local/apache2\"" "LoadModule php_module modules/libphp.so" > /usr/local/apache2/conf/httpd.conf'
put apache-lampp 'mkdir -p /opt/lampp/etc
printf "%s\n" "ServerRoot \"/opt/lampp\"" "LoadModule php_module modules/libphp.so" > /opt/lampp/etc/httpd.conf'
put apache-suse 'mkdir -p /etc/apache2/sysconfig.d
printf "%s\n" "LoadModule php8_module /usr/lib64/apache2/mod_php8.so" > /etc/apache2/sysconfig.d/loadmodule.conf'
put apache-rpm-zts-own 'mkdir -p /etc/httpd/conf.modules.d
printf "%s\n" "<IfModule !prefork.c>" "  LoadModule php_zts_module /opt/php83/modules/libphp-zts.so" "</IfModule>" > /etc/httpd/conf.modules.d/20-php.conf'
put real-php-apache 'true'
put real-deb12 'apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y php8.2-fpm libapache2-mod-php8.2 > /dev/null'
put real-rocky9 'dnf -y -q install php httpd > /dev/null'
put real-rocky8 'dnf -y -q install php httpd > /dev/null'
put apache-rpm8-conf 'mkdir -p /etc/httpd/conf.modules.d /etc/httpd/conf
printf "%s\n" "ServerRoot \"/etc/httpd\"" "Include conf.modules.d/*.conf" > /etc/httpd/conf/httpd.conf
printf "%s\n" "#" "# PHP is an HTML-embedded scripting language" "#" "# Cannot load both php5 and php7 modules" "<IfModule !mod_php5.c>" "  <IfModule prefork.c>" "    LoadModule php7_module modules/libphp7.so" "  </IfModule>" "</IfModule>" > /etc/httpd/conf.modules.d/15-php.conf'

cat > "$W/inside.sh" <<'EOF'
#!/bin/sh
name=$1
rules=$2
mkdir -p "/out/$name"
if sh "/setup/$name.sh" > "/out/$name/setup.log" 2>&1; then echo ok > "/out/$name/setup.txt"; else echo "failed $?" > "/out/$name/setup.txt"; fi
{ ls -la /etc/init.d /etc/init /etc/apache2/mods-available /etc/apache2/mods-enabled /etc/httpd/conf.modules.d 2>&1; grep -rh "LoadModule.*php" /etc/apache2 /etc/httpd /usr/local/apache2/conf /opt/lampp/etc 2>/dev/null; } > "/out/$name/places.txt"
for r in $rules; do
    for v in a b; do
        d="/out/$name/$v-$r"
        mkdir -p "$d"
        LANG=ko_KR.UTF-8 "/$v/remedy" scan --plugin "/$v/plugins/$r/plugin.yaml" --out-dir "$d/out" > "$d/screen.txt" 2>&1
        echo "$r $v $?" >> "/out/$name/codes.txt"
        chmod 644 "$d/screen.txt"
    done
done
chmod -R a+r "/out/$name"
EOF
for c in "${CASES[@]}"; do
    IFS='|' read -r name image <<< "$c"
    [ -n "$ONLY" ] && [ "$name" != "$ONLY" ] && continue
    t0=$(date +%s)
    docker run --rm --pull=never -v "$W/a:/a:ro" -v "$W/b:/b:ro" -v "$W/out:/out" -v "$W/setup:/setup:ro" \
        -v "$W/inside.sh:/inside.sh:ro" "$image" sh /inside.sh "$name" "$RULES" > "$W/out/$name.docker.log" 2>&1
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
