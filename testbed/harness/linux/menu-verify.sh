#!/bin/bash
# 리눅스의 **새로 받은 꾸러미 첫 메뉴**를 진짜 터미널(pty)에서 띄워, Windows 의 같은
# 화면(콘솔 기준선 A10)과 줄 목록을 견준다 — 목표 remedy_제품화 기준 2(b)(c).
#
# 호스트(WSL)에서:
#
#   bash testbed/harness/linux/menu-verify.sh [--out <폴더>] [--cargo-home <WSL 에서 본 CARGO_HOME>]
#
# `--cargo-home` 을 주지 않으면 `.cargo/host.yml` 의 `wsl.cargo_home` 을 읽는다 — 그 아래
# `registry` 를 컨테이너에 붙여 크레이트를 다시 받지 않는다. 둘 다 없으면 멈춘다.
#
# 컨테이너(rust:1.96-bookworm) 안에서 Windows 메뉴 하네스(host/Invoke-MenuVerify.ps1)와
# 같은 조립을 한다 — 임시 키쌍 → 그 공개키를 박은 빌드 → 서명된 시험 플러그인
# (`lab-plugin.yaml`) → `xtask package`. 개인키는 회차마다 새로 만들고 컨테이너와 함께
# 버린다. 메뉴는 `script` 가 준 pty 에서 띄우고 stdout 은 파일로 받는다 — 그래서 줄 입력
# 화면(A10 과 같은 화면)이 나오고, `0` 을 넣어 그만둔다.
#
# 남기는 것: layout.txt(꾸러미 안 파일) · menu.txt(첫 메뉴) · items.txt · verdict.txt.
# **판정은 번호 줄의 목록**이다 — 머리말의 권한 낱말(관리자 · root)과 첫 줄 알림은
# OS 마다 다른 것이 맞아 견주지 않고 verdict.txt 에 따로 적는다.
#
# 툴체인은 호스트(WSL)의 것을 읽기 전용으로 붙인다 — 사내망에서는 컨테이너의 rustup 이
# 1.96.0 을 못 받을 수 있다.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
TC=1.96.0-x86_64-unknown-linux-gnu
OUT=""
CARGO_HOME_ARG=""
INSIDE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT=$2; shift 2 ;;
        --cargo-home) CARGO_HOME_ARG=$2; shift 2 ;;
        --inside) INSIDE=1; shift ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

inside() {
    cd /repo || return 9
    export CARGO_TARGET_DIR=/tmp/remedy-bookworm
    local w=/tmp/menu-verify
    rm -rf "$w"; mkdir -p "$w/remedy-lab-linux"
    export REMEDY_SIGN_PASSWORD=menu-verify-ephemeral
    cargo run -q -p xtask -- sign keygen --public-key "$w/pub.key" --secret-key "$w/sec.key" \
        >/dev/null || { echo "error=키쌍을 만들지 못했다"; return 2; }
    local anchor
    anchor=$(sed -n 2p "$w/pub.key")
    cp testbed/harness/linux/lab-plugin.yaml "$w/remedy-lab-linux/plugin.yaml"
    cargo run -q -p xtask -- sign plugin --dir "$w/remedy-lab-linux" --secret-key "$w/sec.key" \
        --signed-at 2026-11-06T00:00:00Z >/dev/null || { echo "error=서명하지 못했다"; return 3; }
    REMEDY_TRUST_ANCHOR="$anchor" cargo build -q --release --locked -p remedy-cli \
        || { echo "error=앵커 박은 빌드가 실패했다"; return 4; }
    cargo run -q -p xtask -- package --plugin "$w/remedy-lab-linux" \
        --bin "$CARGO_TARGET_DIR/release/remedy" --out "$w/pkg" --public-key "$w/pub.key" \
        >/dev/null || { echo "error=꾸러미를 짓지 못했다"; return 5; }
    (cd "$w/pkg" && find . -type f | sed 's|^\./||' | sort) >/out/layout.txt
    # 꾸러미도 남긴다 — `screenshot.sh --package <out>/pkg` 가 같은 꾸러미로 화면을 찍는다.
    # 개인키는 남기지 않는다(꾸러미에는 공개키가 박힌 실행 파일과 서명만 있다).
    cp -a "$w/pkg" /out/pkg
    cd "$w/pkg" || return 6
    printf '0\n' | LANG=ko_KR.UTF-8 script -q -e -c "./remedy > /out/menu.txt 2>&1" /dev/null
    echo "menu_exit=$?"
}

if [ "$INSIDE" = 1 ]; then
    inside
    exit $?
fi

. "$HERE/lab-config.sh"
CARGO_HOME_WSL=$(lab_need "$CARGO_HOME_ARG" --cargo-home host wsl.cargo_home) || exit 2
[ -n "$OUT" ] || OUT="$REPO/testbed/harness/results/linux-menu-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
docker run --rm \
    -v "$REPO:/repo" \
    -v "$OUT:/out" \
    -v "$CARGO_HOME_WSL/registry:/usr/local/cargo/registry" \
    -v remedy-bookworm-target:/tmp/remedy-bookworm \
    -v "$HOME/.rustup/toolchains/$TC:/usr/local/rustup/toolchains/$TC:ro" \
    rust:1.96-bookworm bash /repo/testbed/harness/linux/menu-verify.sh --inside | tee "$OUT/run.txt"
[ -s "$OUT/menu.txt" ] || { echo "메뉴를 받지 못했다 — $OUT/run.txt"; exit 1; }

# 번호 줄과 묶음 머리만 — 두 OS 가 같아야 하는 것.
items() { awk '/무엇을 할까요\?/{f=1} /번호를 고르십시오/{exit} f' "$1" \
            | grep -E '^ +[0-9]+\. |작성자·운영자'; }
items "$OUT/menu.txt" >"$OUT/items.txt"
items "$REPO/testbed/harness/baseline/console/console-win.txt" >"$OUT/items-win.txt"
{
    echo "linux_items=$(wc -l <"$OUT/items.txt")"
    echo "windows_items=$(wc -l <"$OUT/items-win.txt")"
    if diff -u "$OUT/items-win.txt" "$OUT/items.txt" >"$OUT/items.diff"; then
        echo "items_diff=0"
    else
        echo "items_diff=$(grep -c '^[-+][^-+]' "$OUT/items.diff")"
    fi
    echo "linux_privilege=$(grep -m1 -E '권한으로 실행 중입니다|권한이 없습니다' "$OUT/menu.txt")"
    echo "linux_notice=$(grep -m1 -E '^알림:' "$OUT/menu.txt")"
} | tee "$OUT/verdict.txt"
grep -q '^items_diff=0$' "$OUT/verdict.txt"
