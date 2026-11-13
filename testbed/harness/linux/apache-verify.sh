#!/bin/bash
# Apache HTTP/2 점검 룰(apache-http2-check-linux)을 배포판 컨테이너에서 잰다.
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/apache-verify.sh --bin <remedy> --plugins <apache-http2-check-linux 가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--bin` 은 **musl 정적** remedy 다 — Alpine 과 옛 glibc(Amazon Linux 2) 에서도 돈다. 배포본이 그것이고, 개발 빌드는
# `x86_64-unknown-linux-musl` 로 짓는다. `--plugins` 는 `apache-http2-check-linux/` 를 담은 폴더다(저장소의 `plugins/`
# 나 내려받아 푼 꾸러미의 `plugins/` — 배포 앵커를 박은 실행 파일은 개발용 키로 서명한 저장소 사본을 거부한다).
# 처음 한 번은 배포판 저장소에 닿아야 한다 — Apache 와 HTTP/2 모듈을 깐 이미지를 지어 두고(`remedy-harness/apache:*`),
# 다음부터는 그 이미지를 쓴다.
#
# # 무해한가
#
# **실검체는 없다.** 이미지는 배포판 저장소의 Apache 를 그대로 깐 것이다(2026-11-13 에 지은 Rocky 9 · Amazon Linux 2023 ·
# AlmaLinux 9 · Oracle Linux 9 의 저장소 판은 아직 취약 판이었다 — 아래 A 가 그것을 잰다). 그 밖의 취약 기계는
# **자리 채우기**다 — dpkg · apk 는 패키지 기록의 판 줄만 바꾸고, RHEL 공급사의 줄은 파일 없는 빈 rpm(이름 · 판 ·
# 공급사만)을 지어 넣는다. 직접 빌드는 서버 판 문자열만 담은 작은 파일이다. Apache 는 재시작 경우(T) 하나에서만
# 띄운다. 경우마다 네트워크 없는 일회용 컨테이너에서 remedy 가 읽기만 한다.
#
# # 무엇을 재나
#
#   A  이미지 7 — 깐 판이 고친 판(Debian 12 · Ubuntu 24.04 · 22.04 · Alpine 3.22 · Amazon Linux 2)이거나 취약 판(Rocky 9 ·
#      Amazon Linux 2023)이다 — 배포판 자신의 비교(dpkg · rpm · apk)로
#   B  dpkg 13 — 고친 판 0 · 취약 판 + HTTP/2 2 · 모듈을 안 켬 6 · 모듈만 켬 6 · 사이트 설정의 Protocols 2 · Ubuntu 24.04 ·
#      22.04(상류 2.4.55 아래의 백포트) · testing 꼴 · 지원 끝난 꼴 6 · 영향 없는 옛 판 0
#   C  rpm 10 — Rocky 9 기본(모듈만) 6 · Protocols h2 2 · 주석 줄 6 · Rocky 8 0 · Alma 9 · Oracle 9 6 · AL2023 기본 6 ·
#      Protocols h2 2 · AL2 고친 판(기본이 h2) 0 · SUSE 6
#   H  RHEL 공급사 7 — 9.8 취약 2 · 9.8 EUS 고친 판 0 · 9.9 고친 판 0 · 끝난 마이너 2 · 10.3 취약 2 · 10.0 고친 판 0 · RHEL 8 0
#   P  Alpine 4 — 고친 판 0 · 취약 판 + h2 2 · Protocols 없음 6 · 지원 끝난 브랜치 6
#   X  직접 빌드 4 — 2.4.62 + h2 2 · 모듈 줄 주석 6 · 2.4.71 0 · XAMPP 2.4.58 + h2 2
#   N  Apache 없음 2 — Debian · Alpine 0
#   T  재시작 1 — 고친 판을 깐 뒤 다시 시작하지 않은 Apache(지워진 mod_http2) 6
#   S  화면 5 — 찾은 줄 아래 CVE 문구 · 흔적 없음 · 모르는 빌드 · 재시작의 확인 필요 까닭 · 미해소 경고 0
#   K  개인키 2 — 결과에 가짜 키(`server.key`)의 내용 0 · 그 이름의 기록 0(설정 폴더에 가짜 키를 둔 두 경우에서 —
#      키를 실제로 두었는지도 잰다)
set -u

BIN=""
PLUGINS=""
OUT=""
TAB=$(printf '\t')
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --plugins) PLUGINS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

RULE=apache-http2-check-linux
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일 · musl 정적> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/$RULE/plugin.yaml" ] || { echo "--plugins 에 $RULE 이 없다: $PLUGINS" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
for base in debian:12 ubuntu:24.04 ubuntu:22.04 rockylinux:9 rockylinux:8 almalinux:9 oraclelinux:9 amazonlinux:2023 \
    amazonlinux:2 opensuse/leap:15.6 alpine:3.22; do
    docker image inspect "$base" >/dev/null 2>&1 || { echo "$base 이미지가 없다 — docker pull $base" >&2; exit 2; }
done
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/apache-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
: >"$OUT/checks.tsv"

check() { # 이름 · 1|0 · 메모
    if [ "$2" = 1 ]; then printf '  OK   %-58s %s\n' "$1" "$3"
    else printf '  실패 %-58s %s\n' "$1" "$3"; fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/checks.tsv"
}

# ── 이미지 — 배포판의 Apache 와 HTTP/2 모듈을 깐다(망이 필요한 것은 여기뿐) ─────────────────────────
IMG=remedy-harness/apache
prepare() { # 꼬리표 · 바탕 이미지 · 설치 명령
    local tag=$1 base=$2 install=$3 name
    docker image inspect "$IMG:$tag" >/dev/null 2>&1 && return 0
    name="remedy-apache-prep-$tag"
    docker rm -f "$name" >/dev/null 2>&1
    docker run --name "$name" "$base" sh -c "$install" >"$OUT/prepare-$tag.log" 2>&1 \
        && docker commit "$name" "$IMG:$tag" >/dev/null
    local rc=$?
    docker rm -f "$name" >/dev/null 2>&1
    return $rc
}
DEB='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends apache2 >/dev/null && echo installed'
DNF='dnf -y -q install httpd mod_http2 >/dev/null && rpm -q httpd mod_http2'
echo "── 이미지 ──"
while read -r tag base install; do
    case $install in deb) install=$DEB ;; dnf) install=$DNF ;; esac
    prepare "$tag" "$base" "$install" || { echo "$tag 이미지를 짓지 못했다" >&2; exit 9; }
done <<'LIST'
debian12 debian:12 deb
ubuntu2404 ubuntu:24.04 deb
ubuntu2204 ubuntu:22.04 deb
rocky9 rockylinux:9 dnf
rocky8 rockylinux:8 dnf
alma9 almalinux:9 dnf
ol9 oraclelinux:9 dnf
al2023 amazonlinux:2023 dnf
LIST
prepare al2 amazonlinux:2 'yum -y -q install httpd mod_http2 mod_ssl >/dev/null && rpm -q httpd mod_http2' \
    || { echo "al2 이미지를 짓지 못했다" >&2; exit 9; }
prepare leap156 opensuse/leap:15.6 'zypper -n -q install apache2 >/dev/null && rpm -q apache2' \
    || { echo "leap156 이미지를 짓지 못했다" >&2; exit 9; }
prepare alpine322 alpine:3.22 'apk add --no-cache -q apache2 apache2-http2' || { echo "alpine322 이미지를 짓지 못했다" >&2; exit 9; }
# RHEL 공급사의 판을 자리 채우기로 넣을 rpmbuild — Rocky 9 이미지 위에.
prepare rocky9-rpmbuild "$IMG:rocky9" 'dnf -y -q install rpm-build >/dev/null && rpm -q rpm-build' \
    || { echo "rpmbuild 이미지를 짓지 못했다" >&2; exit 9; }

# 깐 판을 배포판 자신의 비교로 잰다 — 아니면 '고친 판' · '취약 판' 경우가 그 기계가 아니다.
in_image() { docker run --rm --network none "$IMG:$1" sh -c "$2" 2>/dev/null; }
deb_ge() { # 꼬리표 · 고친 판
    local v
    v=$(in_image "$1" "dpkg-query -W -f='\${Version}' apache2-bin")
    printf '%s' "$v" >"$OUT/installed-$1.txt"
    [ -n "$v" ] && in_image "$1" "dpkg --compare-versions '$v' ge '$2'" && return 0
    return 1
}
rpm_cmp() { # 꼬리표 · 견줄 V-R · lt|ge — rpm 자신의 rpmvercmp 로(epoch 는 깐 판과 견줄 판이 같다 — 메모에 적는다)
    local v r
    v=$(in_image "$1" "rpm -q --qf '%{EPOCH}:%{VERSION}-%{RELEASE}' mod_http2")
    printf '%s' "$v" >"$OUT/installed-$1.txt"
    r=$(in_image "$1" "rpm --eval '%{lua: print(rpm.vercmp(\"${v#*:}\", \"$2\"))}'")
    [ -n "$v" ] || return 1
    case $3 in lt) [ "$r" = -1 ] ;; ge) [ "$r" = 0 ] || [ "$r" = 1 ] ;; esac
}
apk_ge() { # 꼬리표 · 패키지 · 고친 판
    local v
    v=$(in_image "$1" "sed -n '/^P:$2\$/,/^\$/ s/^V://p' /lib/apk/db/installed")
    printf '%s' "$v" >"$OUT/installed-$1.txt"
    [ -n "$v" ] && [ "$(in_image "$1" "apk version -t '$v' '$3'")" != "<" ]
}
deb_ge debian12 2.4.71-1~deb12u1 && a=1 || a=0
check "A1 Debian 12 의 apache2-bin 이 고친 판 이상" "$a" "$(cat "$OUT/installed-debian12.txt") ≥ 2.4.71-1~deb12u1"
deb_ge ubuntu2404 2.4.58-1ubuntu8.19 && a=1 || a=0
check "A2 Ubuntu 24.04 의 apache2-bin 이 고친 판 이상" "$a" "$(cat "$OUT/installed-ubuntu2404.txt") ≥ 2.4.58-1ubuntu8.19"
deb_ge ubuntu2204 2.4.52-1ubuntu4.27 && a=1 || a=0
check "A3 Ubuntu 22.04 의 apache2-bin 이 고친 판 이상" "$a" "$(cat "$OUT/installed-ubuntu2204.txt") ≥ 2.4.52-1ubuntu4.27"
rpm_cmp rocky9 2.0.26-7.el9_9.1 lt && a=1 || a=0
check "A4 Rocky 9 의 mod_http2 가 고친 판 미만(실제 취약 판)" "$a" "$(cat "$OUT/installed-rocky9.txt") < 2.0.26-7.el9_9.1"
rpm_cmp al2023 2.4.71-1.amzn2023.0.1 lt && a=1 || a=0
check "A5 Amazon Linux 2023 의 mod_http2 가 고친 판 미만(실제 취약 판)" "$a" "$(cat "$OUT/installed-al2023.txt") < 1:2.4.71-1.amzn2023.0.1"
apk_ge alpine322 apache2-http2 2.4.71-r0 && a=1 || a=0
check "A6 Alpine 3.22 의 apache2-http2 가 고친 판 이상" "$a" "$(cat "$OUT/installed-alpine322.txt") ≥ 2.4.71-r0"
rpm_cmp al2 2.4.71-1.amzn2.0.1 ge && a=1 || a=0
check "A7 Amazon Linux 2 의 mod_http2 가 고친 판 이상" "$a" "$(cat "$OUT/installed-al2.txt") ≥ 1:2.4.71-1.amzn2.0.1"

# ── 경우 — 네트워크 없는 일회용 컨테이너 · 판 줄과 설정만 바꾼다 ───────────────────────────────────
W=$(mktemp -d /tmp/remedy-apache-verify.XXXXXX)
cleanup() { # 컨테이너가 root 로 쓴 결과는 컨테이너로 지운다
    docker run --rm -v "$W:/w" alpine:3.22 rm -rf /w/b /w/res >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W/b/plugins" "$W/res"
cp "$BIN" "$W/b/remedy"
cp -r "$PLUGINS/$RULE" "$W/b/plugins/"
# RHEL 공급사의 빈 mod_http2 를 짓고 넣는다(파일 없음 · 이름 · 판 · 공급사만). 깔려 있던 mod_http2 를 빼면 그 패키지가 둔
# 10-h2.conf 도 빠지므로 같은 줄로 다시 둔다.
cat >"$W/b/rh-rpm.sh" <<'RPM'
set -e
rpm -e --nodeps mod_http2 >/dev/null 2>&1 || true
mkdir -p /tmp/rb/SPECS
{
  echo "Name: mod_http2"
  echo "Version: $1"
  echo "Release: $2"
  echo "Summary: placeholder"
  echo "License: ASL 2.0"
  echo "Vendor: Red Hat, Inc."
  echo "BuildArch: noarch"
  echo "%description"
  echo "placeholder"
  echo "%files"
} >/tmp/rb/SPECS/m.spec
rpmbuild -bb --define "_topdir /tmp/rb" /tmp/rb/SPECS/m.spec >/dev/null 2>&1
rpm -i --nodeps /tmp/rb/RPMS/noarch/mod_http2-*.rpm
echo "LoadModule http2_module modules/mod_http2.so" >/etc/httpd/conf.modules.d/10-h2.conf
RPM
# 설정 폴더에 둘 가짜 TLS 개인키 — 이름(`server.key`)이 시험 대상이다(룰은 이름으로 거른다). 내용은 키 모양이 아닌
# 표지 한 줄이다 — 키 머리를 적으면 공개 트리의 누출 검사가 개인키 머리로 잡고, 그것이 필요하지도 않다. 스크립트
# 파일로 두는 까닭 — 준비 셸에 적으면 그 셸(컨테이너의 1번 프로세스)의 명령줄을 프로세스 수집이 기록해 결과에 그 글자가
# 남는다(첫 회차의 K1 · K2 실패가 그것이었다).
cat >"$W/b/fake-key.sh" <<'KEY'
mkdir -p "$1"
echo "REMEDY-HARNESS-FAKE-TLS-KEY" >"$1/server.key"
[ -s "$1/server.key" ] && echo "fake key placed in $1"
KEY

: >"$OUT/cases.tsv"
run_case() { # 이름 · 이미지 꼬리표 또는 바탕 이미지 · 기대 종료 코드 · 준비 셸 · 메모
    local name=$1 image=$2 want=$3 setup=$4 note=$5 d="$W/res/$1"
    case "$image" in */*|*:*) ;; *) image="$IMG:$image" ;; esac
    mkdir -p "$d"
    docker run --rm --pull=never --network none -v "$W/b:/b:ro" -v "$d:/o" "$image" sh -c \
        "$setup
         REMEDY_LANG=ko LANG=C.UTF-8 /b/remedy scan --plugin /b/plugins/$RULE/plugin.yaml \
             --out-dir /o/out >/o/screen.txt 2>&1; echo \$? >/o/rc; chmod -R a+rX /o" </dev/null >"$d/setup.log" 2>&1
    local rc
    rc=$(cat "$d/rc" 2>/dev/null || echo 99)
    printf '%s\t%s\t%s\t%s\n' "$name" "$want" "$rc" "$note" >>"$OUT/cases.tsv"
    check "$name" "$([ "$rc" = "$want" ] && echo 1 || echo 0)" "기대 $want · 종료 $rc · $note"
    mkdir -p "$OUT/cases/$name"
    cp "$d/screen.txt" "$d/rc" "$d/setup.log" "$OUT/cases/$name/" 2>/dev/null
    find "$d/out" -name '*.json' -exec cp {} "$OUT/cases/$name/" \; 2>/dev/null
}

# 패키지 기록의 판 줄을 바꾸는 셸 한 줄 — 그 패키지의 칸에서만.
deb_set() { printf "sed -i '/^Package: %s\$/,/^\$/ s/^Version: .*/Version: %s/' /var/lib/dpkg/status" "$1" "$2"; }
apk_set() { printf "sed -i '/^P:%s\$/,/^\$/ s/^V:.*/V:%s/' /lib/apk/db/installed" "$1" "$2"; }

DEB_H2='a2enmod -q http2 >/dev/null'
DEB_LOAD_ONLY='ln -s ../mods-available/http2.load /etc/apache2/mods-enabled/http2.load'
DEB_SITE_H2='printf "Protocols h2 http/1.1\n" >>/etc/apache2/sites-available/000-default.conf'
DEB_KEY='sh /b/fake-key.sh /etc/apache2/ssl'
RPM_H2='printf "Protocols h2 http/1.1\n" >/etc/httpd/conf.d/h2.conf'
RPM_H2_COMMENT='printf "#Protocols h2 http/1.1\n" >/etc/httpd/conf.d/h2.conf'
RPM_KEY='sh /b/fake-key.sh /etc/httpd/ssl'
APK_H2='printf "Protocols h2 http/1.1\n" >/etc/apache2/conf.d/h2.conf'

echo "── B. dpkg ──"
run_case b01-deb12-fixed debian12 0 "$DEB_H2" "깐 그대로(고친 판) · HTTP/2 켬"
run_case b02-deb12-vulnerable debian12 2 "$(deb_set apache2-bin 2.4.62-1~deb12u2) && $DEB_H2 && $DEB_KEY" "2.4.62-1~deb12u2 · a2enmod http2 · 가짜 키"
run_case b03-deb12-module-off debian12 6 "$(deb_set apache2-bin 2.4.62-1~deb12u2)" "취약 판 · 모듈을 켜지 않았다(기본)"
run_case b04-deb12-load-only debian12 6 "$(deb_set apache2-bin 2.4.62-1~deb12u2) && $DEB_LOAD_ONLY" "모듈만 켜고 Protocols 가 없다"
run_case b05-deb12-site-protocols debian12 2 "$(deb_set apache2-bin 2.4.62-1~deb12u2) && $DEB_LOAD_ONLY && $DEB_SITE_H2" "사이트 설정의 Protocols h2"
run_case b06-u2404-vulnerable ubuntu2404 2 "$(deb_set apache2-bin 2.4.58-1ubuntu8.18) && $DEB_H2" "2.4.58-1ubuntu8.18 — 개정 하나 아래"
run_case b07-u2404-fixed ubuntu2404 0 "$DEB_H2" "깐 그대로(고친 판)"
run_case b08-u2204-vulnerable ubuntu2204 2 "$(deb_set apache2-bin 2.4.52-1ubuntu4.26) && $DEB_H2" "2.4.52 — 상류 2.4.55 아래의 백포트"
run_case b09-u2204-fixed ubuntu2204 0 "$DEB_H2" "깐 그대로(고친 판)"
run_case b10-deb-testing debian12 2 "$(deb_set apache2-bin 2.4.69-1) && $DEB_H2" "testing 꼴 2.4.69-1"
run_case b11-deb11-like debian12 6 "$(deb_set apache2-bin 2.4.62-1~deb11u1) && $DEB_H2" "지원 끝난 Debian 11 꼴 — 모르는 빌드"
run_case b12-ubuntu25-like ubuntu2404 6 "$(deb_set apache2-bin 2.4.64-1ubuntu3.1) && $DEB_H2" "Ubuntu 25.x 꼴 — 모르는 빌드"
run_case b13-old-unaffected ubuntu2404 0 "$(deb_set apache2-bin 2.4.29-1ubuntu4.27) && $DEB_H2" "2.4.29 — 영향 없는 옛 판"

echo "── C. rpm ──"
run_case r01-rocky9-default rocky9 6 ":" "깐 그대로(취약 판) · 모듈은 실리고 Protocols 없음"
run_case r02-rocky9-h2 rocky9 2 "$RPM_H2 && $RPM_KEY" "Protocols h2 · 가짜 키"
run_case r03-rocky9-commented rocky9 6 "$RPM_H2_COMMENT" "주석 줄은 켜지 않는다"
run_case r04-rocky8 rocky8 0 "$RPM_H2" "mod_http2 1.15 — 영향 없음"
run_case r05-alma9 alma9 6 "$RPM_H2" "AlmaLinux — 공지 없음"
run_case r06-ol9 ol9 6 "$RPM_H2" "Oracle Linux — 공지 없음"
run_case r07-al2023-default al2023 6 ":" "깐 그대로(취약 판) · Protocols 없음"
run_case r08-al2023-h2 al2023 2 "$RPM_H2" "Protocols h2"
run_case r09-al2-fixed al2 0 ":" "깐 그대로(고친 판) · 기본 설정이 h2 h2c"
run_case r10-suse leap156 6 ":" "SUSE — 고침 대기 · 기본 설정이 h2 h2c"

echo "── H. RHEL 공급사 ──"
run_case h01-rhel98-vulnerable rocky9-rpmbuild 2 "sh /b/rh-rpm.sh 2.0.26 6.el9_8.2 && $RPM_H2" "9.8 의 2.0.26-6.el9_8.2"
run_case h02-rhel98-eus-fixed rocky9-rpmbuild 0 "sh /b/rh-rpm.sh 2.0.26 6.el9_8.3 && $RPM_H2" "9.8 EUS 의 고친 판 — 본류와 견주지 않는다"
run_case h03-rhel99-fixed rocky9-rpmbuild 0 "sh /b/rh-rpm.sh 2.0.26 7.el9_9.1 && $RPM_H2" "9.9 의 고친 판"
run_case h04-rhel92-old rocky9-rpmbuild 2 "sh /b/rh-rpm.sh 2.0.26 1.el9_2 && $RPM_H2" "끝난 마이너 9.2 — 본류의 고친 판과 견준다"
run_case h05-rhel103-vulnerable rocky9-rpmbuild 2 "sh /b/rh-rpm.sh 2.0.29 5.el10_3 && $RPM_H2" "10.3 의 2.0.29-5.el10_3"
run_case h06-rhel100-fixed rocky9-rpmbuild 0 "sh /b/rh-rpm.sh 2.0.29 2.el10_0.3 && $RPM_H2" "10.0 E2S 의 고친 판"
run_case h07-rhel8 rocky9-rpmbuild 0 "sh /b/rh-rpm.sh 1.15.7 10.module+el8.10.0+20000+0a1b2c3d && $RPM_H2" "RHEL 8 의 mod_http2 1.15 — 영향 없음"

echo "── P. Alpine ──"
run_case p01-alpine-fixed alpine322 0 "$APK_H2" "깐 그대로(고친 판) · Protocols h2"
run_case p02-alpine-vulnerable alpine322 2 "$(apk_set apache2-http2 2.4.62-r0) && $APK_H2" "apache2-http2 2.4.62-r0"
run_case p03-alpine-no-protocols alpine322 6 "$(apk_set apache2-http2 2.4.62-r0)" "모듈은 실리고 Protocols 없음(기본)"
run_case p04-alpine-eol alpine322 6 "$(apk_set alpine-release 3.20.6-r0) && $(apk_set apache2-http2 2.4.62-r0) && $APK_H2" "지원 끝난 3.20 — 고친 판 없음"

echo "── X. 직접 빌드 ──"
SRC_BIN() { printf 'mkdir -p %s && printf "MZ\\000Apache/%s\\000" >%s/httpd && chmod +x %s/httpd' "$1" "$2" "$1" "$1"; }
SRC_CONF_H2='mkdir -p /usr/local/apache2/conf && printf "LoadModule http2_module modules/mod_http2.so\nProtocols h2 http/1.1\n" >/usr/local/apache2/conf/httpd.conf'
SRC_CONF_OFF='mkdir -p /usr/local/apache2/conf && printf "#LoadModule http2_module modules/mod_http2.so\nProtocols h2 http/1.1\n" >/usr/local/apache2/conf/httpd.conf'
XAMPP_CONF='mkdir -p /opt/lampp/etc/extra && printf "LoadModule http2_module modules/mod_http2.so\n" >/opt/lampp/etc/httpd.conf && printf "Protocols h2 http/1.1\n" >/opt/lampp/etc/extra/httpd-ssl.conf'
run_case x01-src-vulnerable debian:12 2 "$(SRC_BIN /usr/local/apache2/bin 2.4.62) && $SRC_CONF_H2" "/usr/local/apache2 · 2.4.62 · h2"
run_case x02-src-module-commented debian:12 6 "$(SRC_BIN /usr/local/apache2/bin 2.4.62) && $SRC_CONF_OFF" "모듈 줄이 주석"
run_case x03-src-fixed debian:12 0 "$(SRC_BIN /usr/local/apache2/bin 2.4.71) && $SRC_CONF_H2" "2.4.71"
run_case x04-xampp debian:12 2 "$(SRC_BIN /opt/lampp/bin 2.4.58) && $XAMPP_CONF" "XAMPP 2.4.58 · extra 의 Protocols"

echo "── N. Apache 없음 ──"
run_case n01-debian-none debian:12 0 ":" "Apache 없는 Debian"
run_case n02-alpine-none alpine:3.22 0 ":" "Apache 없는 Alpine"

echo "── T. 재시작 ──"
run_case t01-stale-module debian12 6 "$DEB_H2 && apache2ctl start >/dev/null 2>&1 && sleep 2 && rm -f /usr/lib/apache2/modules/mod_http2.so" \
    "고친 판 · 띄운 뒤 mod_http2.so 를 지움(패키지를 올린 꼴)"

echo "── 화면 ──"
screen_has() { grep -qF "$2" "$OUT/cases/$1/screen.txt" 2>/dev/null && echo 1 || echo 0; }
# 찾은 줄 **바로 아래 줄**이 그 문구다(코어 1.13.0 의 `label`).
screen_under() { # 경우 · 찾은 줄에 든 글 · 바로 아래 줄에 든 글
    awk -v a="$2" -v b="$3" 'hit && index($0, b) { ok = 1 } { hit = index($0, a) > 0 } END { exit !ok }' \
        "$OUT/cases/$1/screen.txt" 2>/dev/null && echo 1 || echo 0
}
check "S1 취약 판 줄 아래에 CVE 문구 (b02)" \
    "$(screen_under b02-deb12-vulnerable 'apache2-bin' 'CVE-2026-119618 · 이 배포판의 고친 판보다 낮습니다')" "찾은 줄 · 문구"
check "S2 흔적을 다 찾지 못한 확인 필요 까닭 (b03)" "$(screen_has b03-deb12-module-off 'HTTP/2 를 켠 흔적')" "주의 줄"
check "S3 모르는 빌드의 확인 필요 까닭 (r05)" "$(screen_has r05-alma9 '고친 판을 이 룰이 모릅니다')" "주의 줄"
check "S4 재시작의 확인 필요 까닭 (t01)" "$(screen_has t01-stale-module '다시 시작하지 않은 Apache')" "주의 줄"
# 자리 대부분이 없는 기계에 미해소 경고를 띄우지 않는다 — 본문 수집은 전부 `glob` 형이다.
check "S5 자리 대부분이 없는 기계에 미해소 경고가 없다 (b01 · n01)" \
    "$([ "$(screen_has b01-deb12-fixed '해소되지 않았습니다')$(screen_has n01-debian-none '해소되지 않았습니다')" = 00 ] && echo 1 || echo 0)" "주의 줄 0"

echo "── K. 개인키 ──"
keys=$(grep -rl 'REMEDY-HARNESS-FAKE-TLS-KEY' "$OUT/cases" 2>/dev/null | wc -l)
# 가짜 키가 실제로 놓였어야 이 칸이 뜻을 갖는다 — 두 경우의 준비 기록에서 확인한다.
placed=$(cat "$OUT/cases/b02-deb12-vulnerable/setup.log" "$OUT/cases/r02-rocky9-h2/setup.log" 2>/dev/null | grep -c 'fake key placed')
check "K1 결과에 개인키 본문이 없다" "$([ "$keys" = 0 ] && [ "$placed" = 2 ] && echo 1 || echo 0)" \
    "가짜 키의 표지가 든 파일 $keys · 가짜 키를 둔 경우 $placed/2"
keyrec=$(grep -rl 'server\.key' "$OUT/cases" --include='*.json' 2>/dev/null | wc -l)
check "K2 키 파일을 기록하지 않는다 (b02 · r02)" "$([ "$keyrec" = 0 ] && echo 1 || echo 0)" "server.key 가 든 결과 파일 $keyrec"

# 칸 수까지 본다 — 경우를 짓다 멈추면 남은 경우가 조용히 사라지고 "실패 0" 이 남는다.
EXPECTED=55 # A 7 · B 13 · C 10 · H 7 · P 4 · X 4 · N 2 · T 1 · 화면 5 · 개인키 2
pass=$(awk -F"$TAB" '$2 == 1' "$OUT/checks.tsv" | wc -l)
fail=$(awk -F"$TAB" '$2 != 1' "$OUT/checks.tsv" | wc -l)
echo
echo "통과 $pass · 실패 $fail  (전체 $((pass + fail)) / 기대 $EXPECTED)" | tee "$OUT/verdict.txt"
[ "$fail" = 0 ] && [ "$((pass + fail))" = "$EXPECTED" ]
