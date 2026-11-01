#!/bin/bash
# Linux 청정 환경 스냅샷을 떠서 `corpus/clean/` 에 넣는다 (설계-04 §3.2, 설계-09 P12).
#
# # 왜 스크립트인가
#
# 스크러빙은 `cargo xtask corpus` 가 하고 시험이 붙어 있다. 여기 남는 것은
# **틀리기 쉬운 셋**이고, 이 스크립트는 그것을 강제한다.
#
#   1. root 로 돌지 않으면 `denied_dirs > 0` 이 되어 코퍼스에 못 들어간다.
#      `/etc/ssl/private` · `/etc/credstore` · `/var/spool/cron/crontabs` 가
#      일반 사용자에게 안 열린다. **그 스냅샷의 "없다" 는 "못 봤다" 다.**
#
#   2. 홈을 통째로 훑으면 상한(5만 항목)에 걸려 잘린다. 잘린 스냅샷도 코퍼스에
#      못 들어간다 — 이유는 위와 같다.
#
#   3. 이름이 환경을 말해야 한다. `linux-1` 로는 나중에 사거리를 셀 수 없다.
#
#   4. **컨테이너에서는 `--cap-add SYS_PTRACE` 가 필요할 수 있다** (2026-10-27).
#      Docker 는 그 능력을 기본으로 떼므로 root 라도 **다른 uid 의**
#      `/proc/<pid>/maps` 를 읽지 못한다. `process.modules` 수집이 그것을 거부로
#      세므로 회차가 종료 6 이 되고, `denied_dirs > 0` 인 스냅샷은 G1 에 못
#      들어간다. 한 uid 로만 도는 컨테이너(debian12 등)는 그냥 된다 —
#      `php:8.2-apache` 처럼 작업자가 `www-data` 인 이미지에서 난다 (실측).
#
# # 어디서 뜨는가
#
# **랩 기계에서만 뜬다.** 경로의 사용자 이름은 지우지 않는다 — 그것은 데이터의
# 일부이고, 지우면 경로 모양에 걸린 룰을 이 코퍼스로 검증할 수 없다. 고객 기계
# 스냅샷은 여기 들어갈 것이 아니다 (설계-00 §7).
#
# # 쓰는 법
#
#     # WSL 은 암호 없이 root 가 된다
#     wsl -u root -e bash <저장소의 WSL 경로>/testbed/harness/linux/new-corpus-snapshot.sh \
#         --label wsl-ubuntu24
#
#     # 컨테이너는 처음부터 root 다. 배포판이 다른 스냅샷을 얻는 값싼 길이다
#     docker run --rm -v "$PWD:/w" -v "$HOME/.cargo:/cargo" \
#         -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/t -w /w rust:1.96-bookworm \
#         bash testbed/harness/linux/new-corpus-snapshot.sh --label docker-debian12
#
# 뜬 뒤에는 `cargo test -p remedy-core --test corpus` (G1) 를 돌린다.

set -u
# 이 스크립트는 한국어 문구를 읽는다. 기본 언어는 영어다 (2026-09-06).
export REMEDY_LANG=ko

LABEL=""
REPO="${REPO:-$(cd "$(dirname "$0")/../../.." && pwd)}"
OUT="$REPO/corpus/clean"
# 같은 기계의 상태만 달라졌을 때 쓴다. etc·usr 는 앞 스냅샷과 95% 같은데
# declared 만 달라지는 경우가 있다 — 데스크톱을 깐 뒤가 그렇다.
ONLY=""
# 스크러빙하지 않고 **날 것 그대로** 이 디렉터리에 떨군다.
#
# 스크러빙은 `cargo xtask corpus` 가 하는데 fedora·alpine 같은 이미지에는
# cargo 가 없다. 배포판을 늘리려면 **수집과 스크러빙을 갈라야 한다** —
# 컨테이너는 모으기만 하고 호스트가 씻는다.
RAW_OUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --label)   LABEL="${2:-}"; shift 2 ;;
        --out)     OUT="${2:-}"; shift 2 ;;
        --only)    ONLY="${2:-}"; shift 2 ;;
        --raw-out) RAW_OUT="${2:-}"; shift 2 ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

if [ -z "$LABEL" ]; then
    echo "--label <이름> 이 필요하다."
    echo "환경을 알아볼 수 있게 짓는다 — 'wsl-ubuntu24' · 'docker-debian12' 처럼"
    echo "**무엇이 설치된 기계인가**가 드러나야 나중에 사거리를 셀 수 있다."
    exit 2
fi

# ── 1. root 인가 ────────────────────────────────────────────────────
#
# 여기서 멈추지 않으면 `denied_dirs > 0` 인 스냅샷이 만들어지고, 그것은 G1 에
# 들어가지 못한 채 저장소만 더럽힌다.
if [ "$(id -u)" -ne 0 ]; then
    echo "root 로 돌아야 한다. 일반 사용자로 뜨면 다음이 안 열린다:"
    echo "  /etc/ssl/private · /etc/credstore · /var/spool/cron/crontabs"
    echo "그 스냅샷의 '없다' 는 '못 봤다' 이므로 코퍼스에 넣을 수 없다."
    echo
    echo "  WSL     : wsl -u root -e bash $0 --label $LABEL"
    echo "  그 밖   : sudo $0 --label $LABEL"
    exit 1
fi

BIN="${BIN:-}"
if [ -z "$BIN" ]; then
    for c in "${CARGO_TARGET_DIR:-$REPO/target}/debug/remedy" \
             "${CARGO_TARGET_DIR:-$REPO/target}/release/remedy"; do
        [ -x "$c" ] && BIN="$c" && break
    done
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "remedy 바이너리를 찾지 못했다. 먼저 빌드할 것:"
    echo "  cargo build -p remedy-cli"
    echo "또는 BIN=<경로> 로 지정한다."
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── 2. 무엇을 훑는가 ────────────────────────────────────────────────
#
# `persistence` 는 `scan_roots` 와 무관하게 고정된 자리에서 온다(cron·systemd).
# 그래서 어느 집합으로 떠도 지속성은 전부 담긴다.
#
# 홈은 `.config` · `.local` 만 본다. 통째로 훑으면 `.cache` 와 도구 캐시가
# 5만 항목 상한을 삼켜 **잘린 스냅샷**이 된다.
# ── 3. 스크러빙과 압축은 xtask 가 한다 ─────────────────────────────
#
# 규칙을 여기 다시 적지 않는다. 저쪽에는 시험이 붙어 있고 여기는 없다.
#
# `--raw-out` 이면 씻지 않고 그대로 떨군다 — 호스트가 이어받는다:
#
#     cargo xtask corpus --in <파일> --label <라벨> --out corpus/clean
emit() {
    local name="$1" src="$2"
    if [ -n "$RAW_OUT" ]; then
        mkdir -p "$RAW_OUT" || return 1
        cp "$src" "$RAW_OUT/$LABEL-$name.json" || return 1
        echo "    날 것 -> $RAW_OUT/$LABEL-$name.json"
        return 0
    fi
    (cd "$REPO" && cargo run -q -p xtask -- corpus \
        --in "$src" --label "$LABEL-$name" --out "$OUT")
}

SETS=(
    "etc:/etc"
    "usr:/usr/lib /usr/bin"
)
for h in /home/*; do
    [ -d "$h" ] || continue
    SETS+=("home:$h/.config $h/.local")
    break
done

# ── 선언 모드 한 장 ────────────────────────────────────────────────
#
# 진단 모드는 file 과 persistence 만 모은다. service·autorun·shortcut 을 보는
# 룰은 **G1 이 태울 것이 아예 없다** — 그 상태의 초록은 "오탐이 없다" 가 아니라
# "재지 않았다" 다 (설계-09 P12 순서 9).
ALL_SUBJECTS="$REPO/testbed/harness/linux/corpus-all-subjects.yaml"

made=0
fail=0

if [ -n "$ONLY" ] && [ "$ONLY" != "declared" ]; then
    :
elif [ -f "$ALL_SUBJECTS" ]; then
    if "$BIN" collect --plugin "$ALL_SUBJECTS" --out "$TMP/declared.json" \
        > "$TMP/declared.log" 2>&1; then
        sed 's/^/    /' "$TMP/declared.log" | grep -v '^    알림'
        if emit declared "$TMP/declared.json"; then
            made=$((made + 1))
        else
            echo "  실패 declared — 스크러빙"; fail=1
        fi
    else
        echo "  실패 declared"; sed 's/^/    /' "$TMP/declared.log"; fail=1
    fi
else
    echo "  건너뜀 declared — $ALL_SUBJECTS 가 없다"
fi

for spec in "${SETS[@]}"; do
    name="${spec%%:*}"
    if [ -n "$ONLY" ] && [ "$ONLY" != "$name" ]; then
        continue
    fi
    roots="${spec#*:}"
    args=()
    for r in $roots; do
        [ -e "$r" ] || continue
        args+=(--root "$r")
    done
    if [ ${#args[@]} -eq 0 ]; then
        echo "  건너뜀 $name — 훑을 경로가 없다 ($roots)"
        continue
    fi

    if ! "$BIN" collect "${args[@]}" --out "$TMP/$name.json" > "$TMP/$name.log" 2>&1; then
        echo "  실패 $name"; sed 's/^/    /' "$TMP/$name.log"; fail=1; continue
    fi
    sed 's/^/    /' "$TMP/$name.log" | grep -v '^    알림'

    if ! emit "$name" "$TMP/$name.json"; then
        echo "  실패 $name — 스크러빙"; fail=1; continue
    fi
    made=$((made + 1))
done

echo
if [ "$made" -eq 0 ]; then
    echo "새로 만든 것이 없다."
    exit 1
fi
echo "새 스냅샷 ${made}개"
echo "다음: cargo test -p remedy-core --test corpus   (G1)"
exit "$fail"
