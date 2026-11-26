#!/bin/bash
# 룰: nfs2root-check — 묶어 낸 출시(ci/batch.sh)가 바뀐 룰의 필수 점검 ① 로 이 하네스를 찾는다(--bin · --plugins · --out)
# 이미지: debian:13 debian:12 ubuntu:24.04 fedora:44 almalinux:9 alpine:3.22
# rc 묶음: nfs2root
# 하네스 표: WSL · docker(경우마다 네트워크 없는 컨테이너) | NFS2ROOT 점검의 판정 — 깔린 커널 패키지의 판 · NFS 서버 패키지 · 배포판 갈래
# NFS2ROOT 점검 룰(nfs2root-check)을 배포판 컨테이너에서 잰다(2026-11-26 · 0.1.0 — 이 룰의 첫 하네스).
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/nfs2root-verify.sh --bin <remedy> --plugins <nfs2root-check 가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--bin` 은 **musl 정적** remedy 다(Alpine 에서도 돈다 — 개발 빌드는 `musl-dev-build.sh`). `--plugins` 는
# `nfs2root-check/` 를 담은 폴더다(저장소의 `plugins/` 나 내려받아 푼 꾸러미의 `plugins/`). 처음 한 번은 배포판 저장소에
# 닿아야 한다 — NFS 서버 패키지를 깐 이미지를 지어 두고, 다음부터는 그 이미지를 쓴다.
#
# # 무해한가
#
# **실검체는 없다.** 커널 모듈 · nfsd 는 싣지도 띄우지도 않는다. 이미지는 배포판 저장소의 NFS 서버 패키지
# (nfs-kernel-server · nfs-utils)를 그대로 깐 것이고, Debian 13 하나는 저장소의 커널(linux-image-amd64)도 실제로 깐다.
# 그 밖의 커널은 패키지 기록의 **자리 채우기**다 — dpkg 는 `/var/lib/dpkg/status` 에 문단을 더하고, apk 는
# `/lib/apk/db/installed` 에 P: · V: 칸을 더하며, rpm 은 rpmbuild 로 지은 파일 없는 빈 패키지(이름 · 판 · 개정만)를 넣는다.
# 룰은 그 기록만 읽는다. 경우마다 네트워크 없는 일회용 컨테이너에서 remedy 가 읽기만 한다.
#
# # 무엇을 재나 (판정 표는 룰 머리 주석)
#
#   P  전제 1 — Debian 13 에 실제로 깐 커널이 설치 상태이고 Debian 의 고친 판(6.12.117-1) 이상이다(dpkg 자신이 견준다)
#   D  Debian 10 — 13 실물 0 · 13 취약 판 2 · 13 두 판 6 · 12 의 6.1 6 · 12 의 6.12 고친 판 0 · NFS 서버 없음 0 ·
#      커널 패키지 없음 6 · bullseye 꼴 5.10 2 · 고친 판과 proxmox-kernel 함께 6 · buster 꼴 4.19 2
#   U  Ubuntu 2 — 24.04 의 6.8.0-151.151 6 · 3.13(영향 밖) 0
#   F  Fedora 5 — 고친 판 7.3.4 0 · 지원 끝 7.2.15 2 · 7.3.1 과 7.3.4 함께 6 · rawhide 병합 창 7.4.0-0.rc0 6 ·
#      kernel-16k-core 7.2.15 와 kernel-core 7.3.4 함께 6
#   R  AlmaLinux 2 — 5.14.0-741.27.1.el9_9 6 · 같은 커널에 NFS 서버 없음 0
#   A  Alpine 2 — linux-lts 6.12.119 0 · 6.12.116 2
#   N  대상 없음 1 — 패키지 DB 자리가 하나도 없는 기계 0 · 화면에 '점검 대상이 이 기계에 없습니다'
#   S  화면 · 결과 3 — 2 칸의 감지 줄 아래 CVE 문구 · 6 칸의 확인 필요 까닭 셋(결과 파일) ·
#      대상이 있는 0 칸의 화면에 '점검 대상이 이 기계에 없습니다' 가 없다
#
# 칸마다 종료 코드와 함께 결과 파일(`--out-dir` 의 *.json)에 든 감지 id 를 본다. 경우의 준비(기록 더하기 · rpm 짓기)가
# 실패하면 그 칸은 종료 98 로 실패다 — 준비 실패를 통과로 세지 않는다.
set -u

BIN=""
PLUGINS=""
OUT=""
RULE=nfs2root-check
TAB=$(printf '\t')
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --plugins) PLUGINS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일 · musl 정적> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/$RULE/plugin.yaml" ] || { echo "--plugins 에 $RULE 이 없다: $PLUGINS" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
for base in debian:13 debian:12 ubuntu:24.04 fedora:44 almalinux:9 alpine:3.22; do
    docker image inspect "$base" >/dev/null 2>&1 || { echo "$base 이미지가 없다 — docker pull $base" >&2; exit 2; }
done
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/nfs2root-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
: >"$OUT/checks.tsv"

check() { # 이름 · 1|0 · 메모
    if [ "$2" = 1 ]; then printf '  OK   %-44s %s\n' "$1" "$3"
    else printf '  실패 %-44s %s\n' "$1" "$3"; fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/checks.tsv"
}

# ── 이미지 — 배포판의 NFS 서버 패키지를 깐다(망이 필요한 것은 여기뿐) ───────────────────────────────
IMG=remedy-harness/nfs2root
prepare() { # 꼬리표 · 바탕 이미지 · 설치 명령
    local tag=$1 base=$2 install=$3 name
    docker image inspect "$IMG:$tag" >/dev/null 2>&1 && return 0
    name="remedy-nfs2root-prep-$tag"
    docker rm -f "$name" >/dev/null 2>&1
    docker run --name "$name" "$base" sh -c "$install" >"$OUT/prepare-$tag.log" 2>&1 \
        && docker commit "$name" "$IMG:$tag" >/dev/null
    local rc=$?
    docker rm -f "$name" >/dev/null 2>&1
    return $rc
}
APT='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends'
echo "── 이미지 ──"
prepare debian13-nfs debian:13 "$APT nfs-kernel-server >/dev/null && dpkg-query -W nfs-kernel-server" \
    || { echo "debian13-nfs 이미지를 짓지 못했다 — $OUT/prepare-debian13-nfs.log" >&2; exit 9; }
# 커널은 실제로 깐다(D1) — 컨테이너에서 initramfs 훅이 실패하면 dpkg 가 설치 상태로 두지 않으므로 전제 P1 이 잡는다.
prepare debian13-kernel "$IMG:debian13-nfs" "$APT linux-image-amd64 >/dev/null && dpkg-query -W 'linux-image-*'" \
    || { echo "debian13-kernel 이미지를 짓지 못했다 — $OUT/prepare-debian13-kernel.log" >&2; exit 9; }
prepare debian12-nfs debian:12 "$APT nfs-kernel-server >/dev/null && dpkg-query -W nfs-kernel-server" \
    || { echo "debian12-nfs 이미지를 짓지 못했다 — $OUT/prepare-debian12-nfs.log" >&2; exit 9; }
prepare ubuntu2404-nfs ubuntu:24.04 "$APT nfs-kernel-server >/dev/null && dpkg-query -W nfs-kernel-server" \
    || { echo "ubuntu2404-nfs 이미지를 짓지 못했다 — $OUT/prepare-ubuntu2404-nfs.log" >&2; exit 9; }
prepare fedora44-nfs fedora:44 'dnf -y -q install nfs-utils rpm-build >/dev/null && rpm -q nfs-utils rpm-build' \
    || { echo "fedora44-nfs 이미지를 짓지 못했다 — $OUT/prepare-fedora44-nfs.log" >&2; exit 9; }
prepare alma9-nfs almalinux:9 'dnf -y -q install nfs-utils rpm-build >/dev/null && rpm -q nfs-utils rpm-build' \
    || { echo "alma9-nfs 이미지를 짓지 못했다 — $OUT/prepare-alma9-nfs.log" >&2; exit 9; }
prepare alpine322-nfs alpine:3.22 'apk add --no-cache -q nfs-utils && apk info -e nfs-utils' \
    || { echo "alpine322-nfs 이미지를 짓지 못했다 — $OUT/prepare-alpine322-nfs.log" >&2; exit 9; }

# 깐 커널이 설치 상태이고 Debian 의 고친 판 이상인가 — dpkg 자신이 견준다. 아니면 D1 이 '고친 기계' 가 아니다.
p=$(docker run --rm --network none "$IMG:debian13-kernel" sh -c \
    "dpkg-query -W -f='\${db:Status-Abbrev}|\${Package}|\${Version}\n' 'linux-image-[0-9]*'" 2>/dev/null)
printf '%s\n' "$p" >"$OUT/installed-debian13-kernel.txt"
kv=$(printf '%s\n' "$p" | awk -F'|' '$1 ~ /^ii/ { print $3 }' | head -1)
a=0
[ -n "$kv" ] && docker run --rm --network none "$IMG:debian13-kernel" dpkg --compare-versions "$kv" ge 6.12.117-1 && a=1
check "P1 Debian 13 의 깐 커널이 고친 판 이상" "$a" "$(printf '%s' "$p" | tr '\n' ' ')≥ 6.12.117-1"

# ── 경우 — 네트워크 없는 일회용 컨테이너 · 패키지 기록만 바꾼다 ─────────────────────────────────────
W=$(mktemp -d /tmp/remedy-nfs2root-verify.XXXXXX)
cleanup() { # 컨테이너가 root 로 쓴 결과는 컨테이너로 지운다
    docker run --rm -v "$W:/w" alpine:3.22 rm -rf /w/b /w/res >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W/b/plugins" "$W/res"
cp "$BIN" "$W/b/remedy"
cp -r "$PLUGINS/$RULE" "$W/b/plugins/"

# dpkg 의 커널 기록 한 문단 — `sh /b/deb-add.sh <패키지> <판> [소스]`(앞에 빈 줄을 두어 앞 문단과 끊는다).
cat >"$W/b/deb-add.sh" <<'DEB'
printf '\nPackage: %s\nStatus: install ok installed\nPriority: optional\nSection: kernel\nInstalled-Size: 1\nMaintainer: placeholder\nArchitecture: amd64\nSource: %s\nVersion: %s\nDescription: placeholder\n' \
    "$1" "${3:-linux-signed-amd64}" "$2" >>/var/lib/dpkg/status
grep -qx "Package: $1" /var/lib/dpkg/status && echo "dpkg 기록: $1 $2"
DEB
# apk 의 커널 기록 한 칸 — `sh /b/apk-add.sh <패키지> <판>`.
cat >"$W/b/apk-add.sh" <<'APK'
printf '\nP:%s\nV:%s\nA:x86_64\nS:1\nI:1\nT:placeholder\nL:GPL-2.0-only\no:%s\n' "$1" "$2" "$1" >>/lib/apk/db/installed
grep -qx "P:$1" /lib/apk/db/installed && echo "apk 기록: $1 $2"
APK
# rpm 의 빈 커널 패키지(파일 없음 · 이름 · 판 · 개정만) — `sh /b/rpm-add.sh <패키지> <판> <개정>`. `rpm -i` 라 같은 이름의
# 다른 판과 함께 깔린다(커널처럼).
cat >"$W/b/rpm-add.sh" <<'RPM'
set -e
mkdir -p /tmp/rb/SPECS
spec="/tmp/rb/SPECS/$1-$2-$3.spec"
{
  echo "Name: $1"
  echo "Version: $2"
  echo "Release: $3"
  echo "Summary: placeholder"
  echo "License: GPL-2.0-only"
  echo "BuildArch: noarch"
  echo "%description"
  echo "placeholder"
  echo "%files"
} >"$spec"
rpmbuild -bb --define "_topdir /tmp/rb" "$spec" >/dev/null 2>&1
rpm -i --nodeps --noscripts "/tmp/rb/RPMS/noarch/$1-$2-$3.noarch.rpm"
rpm -q "$1-$2-$3"
RPM

# 결과 파일에 든 낱말 — 감지 id 와 확인 필요 까닭은 결과 폴더의 scan.json 에서 찾는다(화면이 아니라). id 는 증거의
# `"rule": "<id>"` 로 본다 — `verdict_rules` 는 판정식의 id 를 늘 다 적고, artifacts.json 은 깔린 패키지를 다 적는다.
json_has() { # 경우 · 글
    grep -qF -- "$2" "$OUT/cases/$1/scan.json" 2>/dev/null
}

: >"$OUT/cases.tsv"
run_case() { # 이름 · 이미지 꼬리표 또는 바탕 이미지 · 기대 종료 코드 · 준비 셸 · 결과 파일에 있어야 할 id(빈칸으로) · 메모 · [화면에 있어야 할 글]
    local name=$1 image=$2 want=$3 setup=$4 ids=$5 note=$6 scr=${7:-} d="$W/res/$1" rc id miss="" smiss=""
    case "$image" in */*|*:*) ;; *) image="$IMG:$image" ;; esac
    mkdir -p "$d"
    docker run --rm --pull=never --network none -v "$W/b:/b:ro" -v "$d:/o" "$image" sh -c \
        "{ $setup ; } >/o/setup.log 2>&1 || { echo 98 >/o/rc; chmod -R a+rX /o; exit 0; }
         REMEDY_LANG=ko LANG=C.UTF-8 /b/remedy scan --plugin /b/plugins/$RULE/plugin.yaml \
             --out-dir /o/out >/o/screen.txt 2>&1; echo \$? >/o/rc; chmod -R a+rX /o" </dev/null >/dev/null 2>&1
    rc=$(cat "$d/rc" 2>/dev/null || echo 99)
    mkdir -p "$OUT/cases/$name"
    cp "$d/screen.txt" "$d/rc" "$d/setup.log" "$OUT/cases/$name/" 2>/dev/null
    find "$d/out" -name '*.json' -exec cp {} "$OUT/cases/$name/" \; 2>/dev/null
    for id in $ids; do json_has "$name" "\"rule\": \"$id\"" || miss="$miss $id"; done
    [ -n "$scr" ] && ! grep -qF -- "$scr" "$OUT/cases/$name/screen.txt" 2>/dev/null && smiss=1
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$want" "$rc" "${miss# }" "$note" >>"$OUT/cases.tsv"
    check "$name" "$([ "$rc" = "$want" ] && [ -z "$miss" ] && [ -z "$smiss" ] && echo 1 || echo 0)" \
        "기대 $want · 종료 $rc${miss:+ · 결과 파일에 없는 id:$miss}${smiss:+ · 화면에 없는 글: $scr} · $note"
}

DEB13_VULN='sh /b/deb-add.sh linux-image-6.12.116+deb13-amd64 6.12.116-1'
echo "── D. Debian ──"
run_case D1 debian13-kernel 0 ":" "nfs_server kernel debian_fixed" "Debian 13 실물 — 저장소의 nfs-kernel-server + linux-image-amd64"
run_case D2 debian13-nfs 2 "$DEB13_VULN" "nfs_server kernel debian_vulnerable" "Debian 13 · 커널 기록 6.12.116-1(자리 채우기)"
run_case D3 debian13-kernel 6 "$DEB13_VULN" "debian_vulnerable debian_fixed" "Debian 13 · 6.12.116-1(자리 채우기)과 깐 고친 판이 함께"
run_case D4 debian12-nfs 6 "sh /b/deb-add.sh linux-image-6.1.0-56-amd64 6.1.192-2" "nfs_server debian_unknown" \
    "Debian 12 · 6.1.192-2 — Debian 의 고친 판 없음"
run_case D5 debian12-nfs 0 "sh /b/deb-add.sh linux-image-6.12.117+deb12-amd64 6.12.117-1~deb12u1 linux-signed-amd64" \
    "nfs_server debian_fixed" "Debian 12 · linux-6.12 의 고친 판 6.12.117-1~deb12u1 만"
run_case D6 debian:13 0 "$DEB13_VULN" "kernel debian_vulnerable" "Debian 13 · 취약 판 커널 기록 · nfs-kernel-server 없음"
run_case D7 debian13-nfs 6 ":" "nfs_server" "nfs-kernel-server 만 · 커널 패키지 없음(바탕 컨테이너)"
run_case D8 debian12-nfs 2 "sh /b/deb-add.sh linux-image-5.10.0-40-amd64 5.10.262-1" "nfs_server debian_vulnerable" \
    "bullseye 꼴 5.10.262-1 — Freexian ELTS 추적기 (unfixed) end-of-life"
run_case D9 debian13-nfs 6 "sh /b/deb-add.sh linux-image-6.12.118+deb13-amd64 6.12.118-1 && sh /b/deb-add.sh proxmox-kernel-6.14.8-2-pve-signed 6.14.8-2 proxmox-kernel-signed-6.14" \
    "nfs_server debian_fixed proxmox_kernel" "Debian 13 · 고친 판 6.12.118-1 과 proxmox-kernel-6.14.8-2-pve-signed 6.14.8-2(자리 채우기)"
run_case D10 debian12-nfs 2 "sh /b/deb-add.sh linux-image-4.19.0-27-amd64 4.19.316-1" "nfs_server debian_vulnerable" \
    "buster 꼴 4.19.316-1 — Freexian ELTS 추적기 (unfixed) end-of-life"

echo "── U. Ubuntu ──"
run_case U1 ubuntu2404-nfs 6 "sh /b/deb-add.sh linux-image-6.8.0-151-generic 6.8.0-151.151 linux-signed" \
    "nfs_server dpkg_backport" "Ubuntu 24.04 · 6.8.0-151.151 — 백포트 · 고친 패키지 공지 없음"
run_case U2 ubuntu2404-nfs 0 "sh /b/deb-add.sh linux-image-3.13.0-170-generic 3.13.0-170.220 linux-signed" \
    "nfs_server kernel" "Ubuntu 14.04 꼴 3.13.0-170.220 — 3.16 아래(영향 밖)"

echo "── F. Fedora ──"
run_case F1 fedora44-nfs 0 "sh /b/rpm-add.sh kernel-core 7.3.4 300.fc45" "nfs_server upstream_fixed" "kernel-core 7.3.4-300.fc45 — 상류 고친 판 7.3.2 이상"
run_case F2 fedora44-nfs 2 "sh /b/rpm-add.sh kernel-core 7.2.15 200.fc43" "nfs_server upstream_vulnerable" "kernel-core 7.2.15-200.fc43 — 7.2 는 고친 판 없이 지원 끝"
run_case F3 fedora44-nfs 6 "sh /b/rpm-add.sh kernel-core 7.3.1 300.fc45 && sh /b/rpm-add.sh kernel-core 7.3.4 300.fc45" \
    "upstream_vulnerable upstream_fixed" "7.3.1-300.fc45 와 7.3.4-300.fc45 가 함께"
run_case F4 fedora44-nfs 6 "sh /b/rpm-add.sh kernel-core 7.4.0 0.rc0.20261020git1a2b3c4.1.fc46" "nfs_server fedora_rc0" \
    "rawhide 병합 창 kernel-core 7.4.0-0.rc0.20261020git1a2b3c4.1.fc46 — 고침(7.4-rc1)이 들었는지 모름"
run_case F5 fedora44-nfs 6 "sh /b/rpm-add.sh kernel-16k-core 7.2.15 200.fc43 && sh /b/rpm-add.sh kernel-core 7.3.4 300.fc45" \
    "upstream_vulnerable upstream_fixed" "kernel-16k-core 7.2.15-200.fc43 와 kernel-core 7.3.4-300.fc45 가 함께"

echo "── R. AlmaLinux ──"
ALMA_K='sh /b/rpm-add.sh kernel-core 5.14.0 741.27.1.el9_9'
run_case R1 alma9-nfs 6 "$ALMA_K" "nfs_server rpm_backport" "AlmaLinux 9 · kernel-core 5.14.0-741.27.1.el9_9 — 고친 패키지 공지 없음"
run_case R2 alma9-nfs 0 "$ALMA_K && rpm -e --nodeps --noscripts nfs-utils" "rpm_backport" "같은 커널 · nfs-utils 없음"

echo "── A. Alpine ──"
run_case A1 alpine322-nfs 0 "sh /b/apk-add.sh linux-lts 6.12.119-r0" "nfs_server upstream_fixed" "linux-lts 6.12.119-r0 — 상류 고친 판 6.12.117 이상"
run_case A2 alpine322-nfs 2 "sh /b/apk-add.sh linux-lts 6.12.116-r0" "nfs_server upstream_vulnerable" "linux-lts 6.12.116-r0"

echo "── N. 대상 없음 ──"
NONE_MSG='점검 대상이 이 기계에 없습니다'
run_case N1 alpine:3.22 0 "rm -rf /lib/apk/db && ! ls -d /var/lib/dpkg /var/lib/rpm /usr/lib/sysimage/rpm /lib/apk/db 2>/dev/null" "" \
    "패키지 DB 자리(dpkg · rpm 둘 · apk)가 하나도 없음 — 바탕 alpine 에서 /lib/apk/db 를 지움" "$NONE_MSG"

echo "── S. 화면 · 결과 ──"
# 찾은 줄 **바로 아래 줄**이 그 문구다(코어 1.13.0 의 `label`).
screen_under() { # 경우 · 찾은 줄에 든 글 · 바로 아래 줄에 든 글
    awk -v a="$2" -v b="$3" 'hit && index($0, b) { ok = 1 } { hit = index($0, a) > 0 } END { exit !ok }' \
        "$OUT/cases/$1/screen.txt" 2>/dev/null && echo 1 || echo 0
}
s1d=$(screen_under D2 'linux-image-6.12.116+deb13-amd64' 'CVE-2026-99362 의 영향 판이고 Debian 의 고친 판(6.12.117-1 · 7.3.3-1)보다 낮')
s1a=$(screen_under A2 'linux-lts' 'CVE-2026-99362 의 영향 판이고 상류의 고친 판(6.12.117 · 6.18.61 · 7.3.2 등)이 아닙니다')
check "S1 2 칸의 감지 줄 아래 CVE · 고친 판 문구" "$([ "$s1d$s1a" = 11 ] && echo 1 || echo 0)" "D2 $s1d · A2 $s1a"
s2r=0; s2d=0; s2k=0
json_has D3 '고친 커널과 고치지 않은 커널이 함께 깔려 있습니다' && json_has D3 '다시 시작하십시오' \
    && json_has F3 '고친 커널과 고치지 않은 커널이 함께 깔려 있습니다' && json_has F3 '다시 시작하십시오' && s2r=1
json_has D4 '이 배포판이 CVE-2026-99362 를 고친 커널을 아직 내지 않았습니다' && json_has U1 '배포판의 보안 공지' \
    && json_has R1 '배포판의 보안 공지' && s2d=1
json_has D7 '커널 패키지를 찾지 못했습니다' && s2k=1
check "S2 6 칸의 확인 필요 까닭 셋(결과 파일)" "$([ "$s2r$s2d$s2k" = 111 ] && echo 1 || echo 0)" \
    "다시 시작 D3 · F3 $s2r · 배포판 공지 D4 · U1 · R1 $s2d · 커널 패키지 없음 D7 $s2k"
# 대상이 있는 0 칸에는 '대상 없음' 안내가 나오지 않는다(화면이 있어야 잰다 — 없으면 실패).
s3=1; s3n=""
for c in D1 D5 U2 F1 A1; do
    if [ ! -s "$OUT/cases/$c/screen.txt" ] || grep -qF -- "$NONE_MSG" "$OUT/cases/$c/screen.txt"; then s3=0; s3n="$s3n $c"; fi
done
check "S3 대상이 있는 0 칸에 '대상 없음' 안내 없음" "$s3" "D1 · D5 · U2 · F1 · A1${s3n:+ — 어긋남:$s3n}"

# 칸 수까지 본다 — 경우를 짓다 멈추면 남은 경우가 조용히 사라지고 "실패 0" 이 남는다.
EXPECTED=26 # P 1 · D 10 · U 2 · F 5 · R 2 · A 2 · N 1 · S 3
pass=$(awk -F"$TAB" '$2 == 1' "$OUT/checks.tsv" | wc -l)
fail=$(awk -F"$TAB" '$2 != 1' "$OUT/checks.tsv" | wc -l)
echo
echo "통과 $pass · 실패 $fail  (전체 $((pass + fail)) / 기대 $EXPECTED)" | tee "$OUT/verdict.txt"
[ "$fail" = 0 ] && [ "$((pass + fail))" = "$EXPECTED" ]
