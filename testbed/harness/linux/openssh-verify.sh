#!/bin/bash
# OpenSSH 점검 룰(openssh-musl-check)을 Alpine 컨테이너에서 잰다.
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/openssh-verify.sh --bin <remedy> --plugins <openssh-musl-check 가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--bin` 은 **musl 정적** remedy 다 — Alpine 은 musl 이라 glibc 로 지은 것은 돌지 않는다. 배포본이 그것이고, 개발
# 빌드는 `x86_64-unknown-linux-musl` 로 짓는다. `--plugins` 는 `openssh-musl-check/` 를 담은 폴더다(저장소의
# `plugins/` 나 내려받아 푼 꾸러미의 `plugins/` — 배포 앵커를 박은 실행 파일은 개발용 키로 서명한 저장소 사본을
# 거부한다). 호스트에 docker 와 alpine:3.21 · alpine:3.22 · debian:12 이미지가 있어야 한다. 처음 한 번은 Alpine ·
# Debian 저장소에 닿아야 한다 — openssh 를 깐 이미지를 지어 두고, 다음부터는 그 이미지를 쓴다.
#
# # 무해한가
#
# **실검체는 없다.** 이미지는 배포판 저장소의 고친 openssh 를 그대로 깐 것이다. 취약 기계는 그 이미지의 패키지
# 기록(`/lib/apk/db/installed`)에서 openssh-server 의 판 줄만 취약 판으로 바꾼 **자리 채우기**다 — Alpine 저장소는
# 브랜치마다 최신 판 하나만 두고, 룰은 그 기록만 읽는다. sshd 는 띄우지 않는다. 경우마다 네트워크 없는 일회용
# 컨테이너에서 remedy 가 파일을 읽기만 한다.
#
# # 무엇을 재나
#
#   A  이미지 2 — 깐 openssh-server 가 그 브랜치의 고친 판 이상이다(3.21 · 3.22 · apk 자신이 견준다)
#   B  판 10 — 3.21 고친 판 0 · 취약 판(9.9_p2-r0) 2 · 3.22 고친 판 0 · 취약 판(10.0_p1-r10) 2 · 모르는 판
#      (9.4_p1-r0) 6 · 읽지 못하는 판(9.9_P2-r0) 6 · PAM 판(openssh-server-pam) 0 · openssh 없는 Alpine 0 ·
#      Debian 의 openssh-server 0 · sshd_config 가 없는 기계 0
#   C  설정 4 — 취약 판에 `PasswordAuthentication no` 6 · 드롭인의 `=no` 6 · Match 블록 안의 끄는 줄 6 · 주석 줄 2
#   S  화면 4 — 취약 판 줄 바로 아래의 CVE 문구 · 끈 줄의 확인 필요 까닭 · 모르는 판의 확인 필요 까닭 · sshd_config 가
#      없는 기계에 미해소 경고 0
#   K  개인키 2 — 결과 폴더에 `PRIVATE KEY` 0 · `ssh_host_*_key` 의 기록 0(호스트 키를 만든 기계에서)
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

[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일 · musl 정적> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/openssh-musl-check/plugin.yaml" ] || { echo "--plugins 에 openssh-musl-check 가 없다: $PLUGINS" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
for base in alpine:3.21 alpine:3.22 debian:12; do
    docker image inspect "$base" >/dev/null 2>&1 || { echo "$base 이미지가 없다 — docker pull $base" >&2; exit 2; }
done
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/openssh-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
: >"$OUT/checks.tsv"

check() { # 이름 · 1|0 · 메모
    if [ "$2" = 1 ]; then printf '  OK   %-60s %s\n' "$1" "$3"
    else printf '  실패 %-60s %s\n' "$1" "$3"; fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/checks.tsv"
}

# ── 이미지 — 배포판의 고친 openssh 를 깔고 호스트 키를 만든다(망이 필요한 것은 여기뿐) ──────────────
IMG=remedy-harness/openssh
prepare() { # 꼬리표 · 바탕 이미지 · 설치 명령
    local tag=$1 base=$2 install=$3 name
    docker image inspect "$IMG:$tag" >/dev/null 2>&1 && return 0
    name="remedy-openssh-prep-$tag"
    docker rm -f "$name" >/dev/null 2>&1
    docker run --name "$name" "$base" sh -c "$install" >"$OUT/prepare-$tag.log" 2>&1 \
        && docker commit "$name" "$IMG:$tag" >/dev/null
    local rc=$?
    docker rm -f "$name" >/dev/null 2>&1
    return $rc
}
echo "── 이미지 ──"
prepare alpine3.21 alpine:3.21 'apk add --no-cache openssh-server && ssh-keygen -A' || { echo "3.21 이미지를 짓지 못했다" >&2; exit 9; }
prepare alpine3.22 alpine:3.22 'apk add --no-cache openssh-server && ssh-keygen -A' || { echo "3.22 이미지를 짓지 못했다" >&2; exit 9; }
prepare alpine3.21-pam alpine:3.21 'apk add --no-cache openssh-server-pam && ssh-keygen -A' || { echo "PAM 이미지를 짓지 못했다" >&2; exit 9; }
prepare debian12 debian:12 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null' \
    || { echo "Debian 이미지를 짓지 못했다" >&2; exit 9; }

# 깐 판이 그 브랜치의 고친 판 이상인가 — apk 자신이 견준다. 아니면 '고친 판' 경우가 고친 기계가 아니다.
fixed_at_least() { # 꼬리표 · 고친 판
    local v
    v=$(docker run --rm --network none "$IMG:$1" sh -c \
        "sed -n '/^P:openssh-server\$/,/^\$/ s/^V://p' /lib/apk/db/installed")
    printf '%s' "$v" >"$OUT/installed-$1.txt"
    [ -n "$v" ] && [ "$(docker run --rm --network none "$IMG:$1" apk version -t "$v" "$2")" != "<" ]
}
fixed_at_least alpine3.21 9.9_p2-r1 && a1=1 || a1=0
check "A1 3.21 의 openssh-server 가 고친 판 이상" "$a1" "$(cat "$OUT/installed-alpine3.21.txt") ≥ 9.9_p2-r1"
fixed_at_least alpine3.22 10.0_p1-r11 && a2=1 || a2=0
check "A2 3.22 의 openssh-server 가 고친 판 이상" "$a2" "$(cat "$OUT/installed-alpine3.22.txt") ≥ 10.0_p1-r11"

# ── 경우 — 네트워크 없는 일회용 컨테이너 · 판 줄과 설정만 바꾼다 ───────────────────────────────────
W=$(mktemp -d /tmp/remedy-openssh-verify.XXXXXX)
cleanup() { # 컨테이너가 root 로 쓴 결과는 컨테이너로 지운다
    docker run --rm -v "$W:/w" alpine:3.21 rm -rf /w/b /w/res >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W/b/plugins" "$W/res"
cp "$BIN" "$W/b/remedy"
cp -r "$PLUGINS/openssh-musl-check" "$W/b/plugins/"

# 판 줄을 바꾸는 셸 한 줄(busybox sed · 그 패키지의 칸에서만).
set_version() { # 패키지 · 판
    printf "sed -i '/^P:%s\$/,/^\$/ s/^V:.*/V:%s/' /lib/apk/db/installed" "$1" "$2"
}

: >"$OUT/cases.tsv"
run_case() { # 이름 · 이미지 꼬리표 또는 바탕 이미지 · 기대 종료 코드 · 준비 셸 · 메모
    local name=$1 image=$2 want=$3 setup=$4 note=$5 d="$W/res/$1"
    case "$image" in */*|*:*) ;; *) image="$IMG:$image" ;; esac
    mkdir -p "$d"
    docker run --rm --pull=never --network none -v "$W/b:/b:ro" -v "$d:/o" "$image" sh -c \
        "$setup
         REMEDY_LANG=ko LANG=C.UTF-8 /b/remedy scan --plugin /b/plugins/openssh-musl-check/plugin.yaml \
             --out-dir /o/out >/o/screen.txt 2>&1; echo \$? >/o/rc; chmod -R a+rX /o" </dev/null >/dev/null 2>&1
    local rc
    rc=$(cat "$d/rc" 2>/dev/null || echo 99)
    printf '%s\t%s\t%s\t%s\n' "$name" "$want" "$rc" "$note" >>"$OUT/cases.tsv"
    check "$name" "$([ "$rc" = "$want" ] && echo 1 || echo 0)" "기대 $want · 종료 $rc · $note"
    mkdir -p "$OUT/cases/$name"
    cp "$d/screen.txt" "$d/rc" "$OUT/cases/$name/" 2>/dev/null
    find "$d/out" -name '*.json' -exec cp {} "$OUT/cases/$name/" \; 2>/dev/null
}

PW_NO='printf "PasswordAuthentication no\n" >>/etc/ssh/sshd_config'
PW_DROPIN='mkdir -p /etc/ssh/sshd_config.d && printf "PasswordAuthentication=no\n" >/etc/ssh/sshd_config.d/50-no-password.conf'
PW_MATCH='printf "Match User build\n    PasswordAuthentication no\n" >>/etc/ssh/sshd_config'
PW_COMMENT='printf "#PasswordAuthentication no\n" >>/etc/ssh/sshd_config'

echo "── B. 판 ──"
run_case b01-321-fixed alpine3.21 0 ":" "깐 그대로(고친 판)"
run_case b02-321-vulnerable alpine3.21 2 "$(set_version openssh-server 9.9_p2-r0)" "9.9_p2-r0 — 개정 하나 아래"
run_case b03-322-fixed alpine3.22 0 ":" "깐 그대로(고친 판)"
run_case b04-322-vulnerable alpine3.22 2 "$(set_version openssh-server 10.0_p1-r10)" "10.0_p1-r10 — 개정 하나 아래"
run_case b05-unknown-build alpine3.21 6 "$(set_version openssh-server 9.4_p1-r0)" "알려진 브랜치의 상류 판이 아니다"
run_case b06-unreadable alpine3.21 6 "$(set_version openssh-server 9.9_P2-r0)" "apk 판으로 읽지 못한다"
run_case b07-pam alpine3.21-pam 0 "$(set_version openssh-server-pam 9.9_p2-r0)" "PAM 판은 해당이 없다(판이 낮아도)"
run_case b08-no-openssh alpine:3.21 0 ":" "/etc/ssh 가 없다 — 해당 없음"
run_case b09-debian debian12 0 ":" "apk 가 아니다(glibc 배포판)"
run_case b10-no-sshd-config alpine3.21 0 "rm -f /etc/ssh/sshd_config" "/etc/ssh 는 있고 sshd_config 는 없다(클라이언트만 깔린 기계의 꼴)"

echo "── C. 설정 ──"
VULN=$(set_version openssh-server 9.9_p2-r0)
run_case c01-password-no alpine3.21 6 "$VULN && $PW_NO" "sshd_config 에 끄는 줄"
run_case c02-dropin-equals alpine3.21 6 "$VULN && $PW_DROPIN" "드롭인 *.conf 의 \`=no\`"
run_case c03-match-block alpine3.21 6 "$VULN && $PW_MATCH" "Match 블록 안의 끄는 줄"
run_case c04-commented alpine3.21 2 "$VULN && $PW_COMMENT" "주석 줄은 끄지 않는다"

echo "── 화면 ──"
screen_has() { grep -qF "$2" "$OUT/cases/$1/screen.txt" 2>/dev/null && echo 1 || echo 0; }
# 찾은 줄 **바로 아래 줄**이 그 문구다(코어 1.13.0 의 `label`).
screen_under() { # 경우 · 찾은 줄에 든 글 · 바로 아래 줄에 든 글
    awk -v a="$2" -v b="$3" 'hit && index($0, b) { ok = 1 } { hit = index($0, a) > 0 } END { exit !ok }' \
        "$OUT/cases/$1/screen.txt" 2>/dev/null && echo 1 || echo 0
}
check "S1 취약 판 줄 아래에 CVE 문구 (b02)" \
    "$(screen_under b02-321-vulnerable 'openssh-server' 'CVE-2026-123158 · 이 Alpine 브랜치의 고친 판보다 낮습니다')" "찾은 줄 · 문구"
check "S2 끈 줄의 확인 필요 까닭 (c01)" "$(screen_has c01-password-no 'Match 블록이 사용자 · 주소별로 다시 켜지 않는지')" "주의 줄"
check "S3 모르는 판의 확인 필요 까닭 (b05)" "$(screen_has b05-unknown-build '알려진 Alpine 브랜치의 것이 아닙니다')" "주의 줄"
# sshd 설정이 없는 기계에 미해소 경고를 띄우지 않는다 — 본문 수집이 `path` 형이던 첫 판이 그랬다.
check "S4 sshd_config 가 없는 기계에 미해소 경고가 없다 (b10)" \
    "$([ "$(screen_has b10-no-sshd-config '해소되지 않았습니다')" = 0 ] && echo 1 || echo 0)" "주의 줄 0"

echo "── K. 개인키 ──"
# 호스트 키를 만든 이미지에서 돈 경우의 결과 전부 — 본문도 기록도 남지 않아야 한다.
keys=$(grep -rl 'PRIVATE KEY' "$OUT/cases" 2>/dev/null | wc -l)
check "K1 결과에 개인키 본문이 없다" "$([ "$keys" = 0 ] && echo 1 || echo 0)" "PRIVATE KEY 가 든 파일 $keys"
hostkeys=$(grep -rlE 'ssh_host_[a-z0-9]+_key' "$OUT/cases" --include='*.json' 2>/dev/null | wc -l)
check "K2 호스트 키 파일을 기록하지 않는다" "$([ "$hostkeys" = 0 ] && echo 1 || echo 0)" "ssh_host_*_key 가 든 결과 파일 $hostkeys"

# 칸 수까지 본다 — 경우를 짓다 멈추면 남은 경우가 조용히 사라지고 "실패 0" 이 남는다.
EXPECTED=22 # A 2 · B 10 · C 4 · 화면 4 · 개인키 2
pass=$(awk -F"$TAB" '$2 == 1' "$OUT/checks.tsv" | wc -l)
fail=$(awk -F"$TAB" '$2 != 1' "$OUT/checks.tsv" | wc -l)
echo
echo "통과 $pass · 실패 $fail  (전체 $((pass + fail)) / 기대 $EXPECTED)" | tee "$OUT/verdict.txt"
[ "$fail" = 0 ] && [ "$((pass + fail))" = "$EXPECTED" ]
