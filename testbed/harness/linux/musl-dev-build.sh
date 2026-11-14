#!/bin/bash
# 공개 전 하네스용 — 지금 트리의 remedy 를 musl 정적 **개발 빌드**(debug · 앵커 없음)로 컨테이너에서 짓는다.
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/musl-dev-build.sh <결과 폴더(WSL 경로)> [--cargo-home <Windows 쪽 CARGO_HOME 의 WSL 경로>]
#
# 리눅스 룰의 하네스(`<룰>-verify.sh --bin`)는 Alpine 과 옛 glibc 에서도 도는 musl 정적 실행 파일을 받는다. 배포본도 그
# 꼴이지만 배포 앵커가 박혀 저장소의 개발 키 서명 룰을 거부한다 — 그래서 PR 전에는 이 개발 빌드로 잰다. 정식 파일로
# 다시 재는 것은 출시 전 필수 점검 ① 이다(docs/긴급-대응.md).
#
# - 컨테이너: `rust:<판>-bookworm`(rust-toolchain.toml 의 판 · --pull=never). musl-tools 는 apt 로 깐다(wasmtime 의 빌드
#   스크립트가 C 파일 하나를 짓는다) — 그래서 이 한 줄은 망을 쓴다.
# - 툴체인: WSL 의 rustup 툴체인(musl 타깃이 든 것)을 읽기 전용으로 붙인다 — 컨테이너의 rustup 은 사내망에서 받지 못할
#   수 있다.
# - crate: Windows 쪽 cargo 레지스트리를 붙여 --offline 으로 — 자리는 `--cargo-home` 또는 `.cargo/host.yml` 의
#   `wsl.cargo_home`(없으면 멈춘다).
# - 타깃 폴더: 이름 있는 볼륨 `remedy-musl-target` — 콘솔 캡처의 glibc 볼륨(`remedy-bookworm-target`)을 키우지 않는다.
#
# 종료 코드: 0 = 지었다(`<결과 폴더>/remedy`) · 그 밖 = 못 지었다 · 2 = 인자 · 준비가 모자라다.
set -u
OUTDIR=""
CARGO_HOME_WIN=""
while [ $# -gt 0 ]; do
    case "$1" in
        --cargo-home) CARGO_HOME_WIN=$2; shift 2 ;;
        -*) echo "모르는 인자: $1" >&2; exit 2 ;;
        *) OUTDIR=$1; shift ;;
    esac
done
[ -n "$OUTDIR" ] || { echo "결과 폴더(WSL 경로)가 필요하다" >&2; exit 2; }
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
mkdir -p "$OUTDIR"
OUTDIR=$(cd "$OUTDIR" && pwd)

t0=$(date +%s)
docker run --rm --pull=never \
    -v "$REPO:/repo:ro" \
    -v "$CARGO_HOME_WIN/registry:/usr/local/cargo/registry" \
    -v remedy-musl-target:/tmp/remedy-musl \
    -v "$HOME/.rustup/toolchains/$TC:/usr/local/rustup/toolchains/$TC:ro" \
    -e CARGO_TARGET_DIR=/tmp/remedy-musl \
    -v "$OUTDIR:/out" \
    "$IMAGE" bash -c '
# 빌드가 실패하면 여기서 멈춘다 — 볼륨에 남은 앞 회차의 실행 파일을 복사해 낡은 빌드로 재지 않게.
set -o pipefail
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq musl-tools >/dev/null 2>&1 || { echo "musl-tools 를 깔지 못했다"; exit 7; }
command -v x86_64-linux-musl-gcc >/dev/null || ln -sf "$(command -v musl-gcc)" /usr/local/bin/x86_64-linux-musl-gcc
cd /repo && cargo build --offline -p remedy-cli --bin remedy --target x86_64-unknown-linux-musl 2>&1 | tail -3
cp /tmp/remedy-musl/x86_64-unknown-linux-musl/debug/remedy /out/remedy && chmod a+rx /out/remedy'
rc=$?
echo "빌드 종료 $rc · $(( $(date +%s) - t0 ))초"
[ "$rc" = 0 ] && [ -x "$OUTDIR/remedy" ] || exit 1
"$OUTDIR/remedy" --version 2>/dev/null | head -1
echo "실행 파일: $OUTDIR/remedy"
