#!/bin/bash
# 리눅스 콘솔 재캡처 두 벌(한국어 · 영어)을 차례로 — `capture-console.sh` 를 그 머리말의 컨테이너 명령으로 두 번 돌린다.
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/console-recapture.sh [<스탬프>] [--cargo-home <Windows 쪽 CARGO_HOME 의 WSL 경로>]
#
# 결과는 `testbed/harness/results/console-<스탬프>-linux.txt` · `console-<스탬프>-en-linux.txt`(스탬프 기본: 지금
# `YYYYMMDD-HHMM`). 그 다음은 `cargo xtask console-diff <두 파일>` 로 기준선과 견주고, 의도한 줄만 달라졌으면 기준선을
# 갈아 끼운다(`docs/개발-안내.md` "출시 검증" · 긴급 경로의 미룬 검증).
#
# 붙이는 것은 머리말과 같다 — 저장소는 읽기 전용 · Windows 쪽 cargo 레지스트리(`--cargo-home` 또는 `.cargo/host.yml` 의
# `wsl.cargo_home` — 없으면 멈춘다) · 이름 있는 타깃 볼륨 `remedy-bookworm-target` · WSL 의 rustup 툴체인(읽기 전용 —
# 컨테이너의 rustup 은 사내망에서 받지 못할 수 있다). 두 벌은 차례로 돈다(같은 볼륨을 쓴다).
#
# 종료 코드: 0 = 두 벌 모두 끝까지 받았고 자기 점검이 기대한 그대로 · 1 = 하나라도 아니다 · 2 = 인자 · 준비가 모자라다.
# 끝나면 무거운 일 뒤의 규칙대로 WSL 캐시를 비운다(root): `wsl -u root -e sh -c 'echo 3 > /proc/sys/vm/drop_caches'`.
set -u
STAMP=""
CARGO_HOME_WIN=""
while [ $# -gt 0 ]; do
    case "$1" in
        --cargo-home) CARGO_HOME_WIN=$2; shift 2 ;;
        -*) echo "모르는 인자: $1" >&2; exit 2 ;;
        *) STAMP=$1; shift ;;
    esac
done
[ -n "$STAMP" ] || STAMP=$(date +%Y%m%d-%H%M)
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
. "$HERE/lab-config.sh"
CARGO_HOME_WIN=$(lab_need "$CARGO_HOME_WIN" --cargo-home host wsl.cargo_home) || exit 2
[ -d "$CARGO_HOME_WIN/registry" ] || { echo "cargo 레지스트리가 없다: $CARGO_HOME_WIN/registry" >&2; exit 2; }
CHANNEL=$(sed -n 's/^channel *= *"\([0-9.]*\)".*/\1/p' "$REPO/rust-toolchain.toml")
[ -n "$CHANNEL" ] || { echo "rust-toolchain.toml 에서 판을 읽지 못했다" >&2; exit 2; }
TC="$CHANNEL-x86_64-unknown-linux-gnu"
IMAGE="rust:${CHANNEL%.*}-bookworm"
[ -d "$HOME/.rustup/toolchains/$TC" ] || { echo "WSL 툴체인이 없다: ~/.rustup/toolchains/$TC" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "docker 가 돌지 않는다" >&2; exit 2; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "$IMAGE 이미지가 없다 — docker pull $IMAGE" >&2; exit 2; }
OUT="$REPO/testbed/harness/results"
mkdir -p "$OUT"
bad=0

cap() {
    local name=$1 t0 rc
    shift
    t0=$(date +%s)
    echo "== $name  $(date +%H:%M:%S)"
    docker run --rm --pull=never --cap-add SYS_ADMIN "$@" \
        -v "$REPO:/repo:ro" \
        -v "$CARGO_HOME_WIN/registry:/usr/local/cargo/registry" \
        -v remedy-bookworm-target:/tmp/remedy-bookworm \
        -v "$HOME/.rustup/toolchains/$TC:/usr/local/rustup/toolchains/$TC:ro" \
        -e CARGO_TARGET_DIR=/tmp/remedy-bookworm \
        "$IMAGE" bash /repo/testbed/harness/linux/capture-console.sh \
        >"$OUT/$name" 2>"$OUT/$name.stderr"
    rc=$?
    echo "   종료 $rc · $(( $(date +%s) - t0 ))초 · $(stat -c %s "$OUT/$name") 바이트"
    # 캡처는 끝에 자기 점검 한 줄을 stderr 로도 낸다 — 절 수와 종료 코드가 기대한 그대로인가.
    local self
    self=$(grep -h '자기 점검:' "$OUT/$name" "$OUT/$name.stderr" 2>/dev/null | tail -1)
    echo "   ${self:-자기 점검 줄 없음}"
    if [ "$rc" != 0 ] || ! echo "$self" | grep -q '기대한 그대로'; then bad=1; fi
}

cap "console-$STAMP-linux.txt"
cap "console-$STAMP-en-linux.txt" -e CAPTURE_LANG=en
echo "== 타깃 볼륨 (MB)"
docker run --rm --pull=never -v remedy-bookworm-target:/v "$IMAGE" du -sm /v/debug /v/release 2>/dev/null
echo "== 다음: cargo xtask console-diff testbed/harness/results/console-$STAMP-linux.txt testbed/harness/results/console-$STAMP-en-linux.txt"
exit "$bad"
