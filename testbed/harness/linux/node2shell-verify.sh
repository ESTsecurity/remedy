#!/bin/bash
# 룰: node2shell-check-linux — 묶어 낸 출시(ci/batch.sh)가 바뀐 룰의 필수 점검 ① 로 이 하네스를 찾는다(--bin · --plugins · --out)
# 이미지: debian:12 node:22.18.0-bookworm-slim node:22.23.4-bookworm-slim
# rc 묶음: node2shell
# 하네스 표: WSL · docker(경우마다 네트워크 없는 컨테이너) | node2shell 리눅스 점검의 판정 — 공식 빌드 해시 · 기준 밖 node · 배포판 패키지
# Node2Shell 점검 룰(node2shell-check-linux)을 배포판 · 공식 Node.js 컨테이너에서 잰다(2026-11-22 · 0.6.2 — 이 룰의 첫 하네스).
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/node2shell-verify.sh --bin <remedy> --plugins <node2shell-check-linux 가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--bin` 은 **musl 정적** remedy 다(개발 빌드는 `musl-dev-build.sh`). `--plugins` 는 `node2shell-check-linux/` 를 담은 폴더다
# (저장소의 `plugins/` 나 내려받아 푼 꾸러미의 `plugins/`). 이미지 셋은 머리의 `# 이미지:` 줄대로 미리 받아 둔다 — 이 하네스는
# 이미지를 짓지 않아 망을 쓰지 않는다.
#
# # 무해한가
#
# **실검체는 없다.** 공식 빌드 칸은 Docker 공식 이미지 `node:<판>-bookworm-slim` 의 `/usr/local/bin/node` 그대로다(그 해시가
# 룰의 공식 해시 목록에 있다 — A 가 잰다). 그 밖의 경우는 **자리 채우기**다 — 기준 밖 node 는 글자 한 줄만 담은 파일이고,
# 배포판 패키지는 dpkg 패키지 기록에 칸 하나만 더한 것이다(파일을 깔지 않는다). 경우마다 네트워크 없는 일회용 컨테이너에서
# remedy 가 읽기만 한다.
#
# # 무엇을 재나
#
#   A  이미지 2 — 공식 이미지 둘의 node 해시가 룰의 목록 그대로다(22.18.0 취약 · 22.23.4 고친 판)
#   O  공식 빌드 2 — 22.18.0 2 · 22.23.4 0
#   U  기준 밖 node 2 — /opt/node 의 모르는 node 6 · 배포판 패키지(libnode108 — 목록에 든 판이라 패키지 줄은 서지 않는다)가
#      함께 있어도 6(0.6.1 은 0 이었다 — 패키지가 하나라도 있으면 기준 밖 node 를 보지 않았다)
#   D  배포판 패키지 3 — Debian 이 미수정으로 확인한 nodejs 판 2 · 목록 밖 nodejs 판 6 · libnode108 만(목록에 든 판 ·
#      libbrotli1 없음) 0
#   N  Node.js 없음 1 — Debian 0
#   S  화면 1 — U 의 패키지 칸 화면에 기준 밖 node 의 까닭 줄
#
# 준비 셸이 실패하면 그 경우의 종료 코드를 97 로 적는다 — 기대와 달라 실패로 센다.
set -u

BIN=""
PLUGINS=""
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --plugins) PLUGINS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

RULE=node2shell-check-linux
OLD=node:22.18.0-bookworm-slim
NEW=node:22.23.4-bookworm-slim
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일 · musl 정적> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/$RULE/plugin.yaml" ] || { echo "--plugins 에 $RULE 이 없다: $PLUGINS" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
for base in debian:12 "$OLD" "$NEW"; do
    docker image inspect "$base" >/dev/null 2>&1 || { echo "$base 이미지가 없다 — docker pull $base" >&2; exit 2; }
done
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/node2shell-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
: >"$OUT/checks.tsv"
TAB=$(printf '\t')

check() { # 이름 · 1|0 · 메모
    if [ "$2" = 1 ]; then printf '  OK   %-58s %s\n' "$1" "$3"
    else printf '  실패 %-58s %s\n' "$1" "$3"; fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/checks.tsv"
}

# ── A. 이미지 — 공식 이미지의 node 가 룰의 공식 해시 그대로인가 ─────────────────────────────────────────
echo "── A. 이미지 ──"
sha_of() { docker run --rm --network none --entrypoint sh "$1" -c 'sha256sum /usr/local/bin/node' 2>/dev/null | cut -d' ' -f1; }
h=$(sha_of "$OLD")
grep -q "\"$h\"   # 22.18.0 linux-x64 .*(vulnerable)" "$PLUGINS/$RULE/plugin.yaml" && a=1 || a=0
check "A1 $OLD 의 node 가 룰의 취약 목록 해시" "$a" "${h:-해시 없음}"
h=$(sha_of "$NEW")
grep -q "\"$h\"   # 22.23.4 linux-x64 .*(fixed)" "$PLUGINS/$RULE/plugin.yaml" && a=1 || a=0
check "A2 $NEW 의 node 가 룰의 고친 판 해시" "$a" "${h:-해시 없음}"

# ── 경우 — 네트워크 없는 일회용 컨테이너 · 파일 하나 · 패키지 기록 한 칸만 더한다 ────────────────────────────
W=$(mktemp -d /tmp/remedy-node2shell-verify.XXXXXX)
cleanup() { # 컨테이너가 root 로 쓴 결과는 컨테이너로 지운다
    docker run --rm -v "$W:/w" debian:12 rm -rf /w/b /w/res >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W/b/plugins" "$W/res"
cp "$BIN" "$W/b/remedy"
cp -r "$PLUGINS/$RULE" "$W/b/plugins/"
# dpkg 패키지 기록에 칸 하나(이름 · 판)를 더한다 — 파일은 깔지 않는다. 기록은 빈 줄로 칸을 가른다. 더한 뒤 그 판이 읽히는지 본다.
cat >"$W/b/deb-add.sh" <<'DEB'
set -e
printf 'Package: %s\nStatus: install ok installed\nPriority: optional\nSection: misc\nMaintainer: placeholder\nArchitecture: amd64\nSource: nodejs\nVersion: %s\nDescription: placeholder\n\n' "$1" "$2" >>/var/lib/dpkg/status
[ "$(dpkg-query -W -f='${Version}' "$1")" = "$2" ]
DEB
# 공식 빌드가 아닌 node — 글자 한 줄만 담은 파일(실행 파일이 아니다 · 해시가 룰의 목록에 없다).
UNKNOWN='mkdir -p /opt/node/bin && printf "not-an-official-node-build" >/opt/node/bin/node && chmod +x /opt/node/bin/node'

: >"$OUT/cases.tsv"
run_case() { # 이름 · 이미지 · 기대 종료 코드 · 준비 셸 · 메모
    local name=$1 image=$2 want=$3 setup=$4 note=$5 d="$W/res/$1"
    mkdir -p "$d"
    docker run --rm --pull=never --network none --entrypoint sh -v "$W/b:/b:ro" -v "$d:/o" "$image" -c \
        "{ $setup
         } || { echo 97 >/o/rc; chmod -R a+rX /o; exit 0; }
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

echo "── O. 공식 빌드 ──"
run_case o01-official-22180 "$OLD" 2 ":" "공식 22.18.0 — 취약 목록의 해시"
run_case o02-official-22234 "$NEW" 0 ":" "공식 22.23.4 — 고친 판의 해시"

echo "── U. 기준 밖 node ──"
run_case u01-unknown-opt debian:12 6 "$UNKNOWN" "/opt/node 의 공식 해시에 없는 node · 패키지 없음"
run_case u02-unknown-with-pkg debian:12 6 "sh /b/deb-add.sh libnode108 18.20.4+dfsg-1~deb12u2 && $UNKNOWN" \
    "기준 밖 node + 배포판 패키지 libnode108(목록에 든 판) — 0.6.1 은 0"

echo "── D. 배포판 패키지 ──"
run_case d01-deb-nodejs-unfixed debian:12 2 "sh /b/deb-add.sh nodejs 18.20.4+dfsg-1~deb12u2" "Debian 이 미수정으로 확인한 nodejs 판"
run_case d02-deb-nodejs-other debian:12 6 "sh /b/deb-add.sh nodejs 18.20.4+dfsg-1~deb12u9" "목록 밖 nodejs 판 — 기준 없는 패키지"
run_case d03-deb-libnode-only debian:12 0 "sh /b/deb-add.sh libnode108 18.20.4+dfsg-1~deb12u2" \
    "libnode108 만(목록에 든 판 · libbrotli1 없음) — 판정 줄은 nodejs 이름만 본다"

echo "── N. Node.js 없음 ──"
run_case n01-none-debian debian:12 0 ":" "Node.js 없음"

echo "── S. 화면 ──"
why='공식 Node.js 빌드의 해시와 맞지 않는 node 실행 파일입니다'
grep -q "$why" "$OUT/cases/u02-unknown-with-pkg/screen.txt" 2>/dev/null && a=1 || a=0
check "S1 패키지가 있어도 기준 밖 node 의 까닭 줄" "$a" "u02 화면"

# 칸 수까지 본다 — 경우를 짓다 멈추면 남은 경우가 조용히 사라지고 "실패 0" 이 남는다.
EXPECTED=11 # A 2 · O 2 · U 2 · D 3 · N 1 · 화면 1
pass=$(awk -F"$TAB" '$2 == 1' "$OUT/checks.tsv" | wc -l)
fail=$(awk -F"$TAB" '$2 != 1' "$OUT/checks.tsv" | wc -l)
echo
echo "통과 $pass · 실패 $fail  (전체 $((pass + fail)) / 기대 $EXPECTED)" | tee "$OUT/verdict.txt"
[ "$fail" = 0 ] && [ "$((pass + fail))" = "$EXPECTED" ]
