#!/bin/bash
# 여러 배포판의 청정 스냅샷을 컨테이너에서 떠 온다 (설계-04 §3.2, 설계-09 P12).
#
# # 왜
#
# 청정 코퍼스의 리눅스 8장이 **배포판 둘**에서만 왔다 — WSL Ubuntu 24.04 와
# Docker Debian 12. G1(오탐 게이트)의 실질 사거리가 거기까지라는 뜻이다.
# rpm 계열도, musl·busybox 계열도 통째로 비어 있었다.
#
# 컨테이너는 배포판이 다른 스냅샷을 얻는 **값싼 길**이다. 다만 그냥 띄우면
# 안 된다 — 기본 이미지는 벗겨져 있다.
#
# # 기본 이미지는 실제 기계가 아니다
#
# 실측(2026-09-05):
#
#   fedora:41  /etc 332 파일 · /usr 366 파일 · systemd 없음 · cron 없음 · CA 0개
#   alpine:3.21 /etc  45 파일 · /usr  17 파일 + 심볼릭 137
#   WSL Ubuntu 24.04  /usr 19,634 파일
#
# 그 상태로 뜬 스냅샷은 오탐 압력이 거의 없다. 그래서 **대표 패키지를 깔아
# 실제 기계 모양으로 만든 뒤** 뜬다. 무엇을 깔았는지가 라벨과 아래 표에
# 남아야 스냅샷의 출처를 나중에 셀 수 있다.
#
# # 씻는 것은 호스트가 한다
#
# `cargo xtask corpus` 가 스크러빙을 하는데 fedora·alpine 에는 cargo 가 없다.
# 그래서 컨테이너는 `--raw-out` 으로 모으기만 하고, 씻는 것은 이 스크립트를
# 부른 사람이 이어받는다 — 마지막에 명령을 찍어 준다.
#
# # 바이너리
#
# glibc 로 만든 것은 glibc 배포판에서만 돈다. **alpine 은 musl** 이라
# `x86_64-unknown-linux-musl` 로 만든 것이 필요하다 — 그것이 이 코어의 리눅스
# 배포 타깃이기도 하다(`rust-toolchain.toml`).
#
# # 쓰는 법
#
#     invoke-corpus-snapshot.sh --image fedora:41 --label docker-fedora41 \
#         --bin /tmp/remedy-bookworm/release/remedy --install fedora
#
#     invoke-corpus-snapshot.sh --all --raw-out /tmp/corpus-raw

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
RAW_OUT="${RAW_OUT:-/tmp/corpus-raw}"
GLIBC_BIN="${GLIBC_BIN:-/tmp/remedy-bookworm/release/remedy}"
MUSL_BIN="${MUSL_BIN:-/tmp/remedy-musl/x86_64-unknown-linux-musl/release/remedy}"
IMAGE=""
LABEL=""
INSTALL=""
BIN=""
ALL=0

# 배포판마다 **대표 패키지**를 깐다.
#
# 고르는 기준은 "그 배포판을 쓰는 기계에 보통 있는 것" 이다 — 시작 관리자,
# 예약 실행, 신뢰 저장소. 셋이 있어야 `persistence`·`service`·`cert_store`
# 룰이 태울 레코드가 생긴다. 없으면 그 자리의 초록은 "오탐이 없다" 가 아니라
# "재지 않았다" 다.
install_cmd() {
    case "$1" in
        debian) echo "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd cron ca-certificates >/dev/null 2>&1" ;;
        fedora) echo "dnf -y -q install systemd cronie ca-certificates >/dev/null 2>&1 && update-ca-trust extract >/dev/null 2>&1" ;;
        # **bash 를 함께 깐다.** 수집 스크립트가 배열을 쓰는데 alpine 의 sh 는
        # busybox ash 라 그것이 없다 — 없으면 문법 오류로 죽는다.
        alpine) echo "apk add --no-cache -q bash openrc busybox-openrc ca-certificates >/dev/null 2>&1 && update-ca-certificates >/dev/null 2>&1" ;;
        none|"") echo ":" ;;
        *) echo "echo '모르는 설치 이름: $1' >&2; exit 2" ;;
    esac
}

# `--all` 이 뜨는 목록. **라벨에 배포판과 판이 들어간다** — `linux-1` 로는
# 나중에 사거리를 셀 수 없다.
ALL_SPECS="
fedora:41|docker-fedora41|fedora|glibc
alpine:3.21|docker-alpine321|alpine|musl
ubuntu:22.04|docker-ubuntu2204|debian|glibc
"

while [ $# -gt 0 ]; do
    case "$1" in
        --image)   IMAGE="${2:-}"; shift 2 ;;
        --label)   LABEL="${2:-}"; shift 2 ;;
        --install) INSTALL="${2:-}"; shift 2 ;;
        --bin)     BIN="${2:-}"; shift 2 ;;
        --raw-out) RAW_OUT="${2:-}"; shift 2 ;;
        --all)     ALL=1; shift ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

command -v docker > /dev/null 2>&1 || { echo "docker 가 없다."; exit 1; }
mkdir -p "$RAW_OUT"

one() {
    local image="$1" label="$2" install="$3" libc="$4" bin="$5"
    if [ -z "$bin" ]; then
        [ "$libc" = "musl" ] && bin="$MUSL_BIN" || bin="$GLIBC_BIN"
    fi
    if [ ! -x "$bin" ]; then
        echo "  건너뜀 $label — 바이너리가 없다: $bin"
        [ "$libc" = "musl" ] && echo "      musl 정적 빌드가 필요하다 (ci/linux-static-docker.sh)"
        return 1
    fi

    echo
    echo "════ $label ($image · $libc) ════"
    # `:ro` 로 저장소를 건다. 컨테이너가 저장소를 고칠 이유가 없다 —
    # 산출물은 `--raw-out` 으로만 나온다.
    docker run --rm \
        -v "$REPO:/repo:ro" \
        -v "$bin:/usr/local/bin/remedy:ro" \
        -v "$RAW_OUT:/raw" \
        -e HOME=/root -w /repo "$image" sh -c "
            set -e
            $(install_cmd "$install")
            BIN=/usr/local/bin/remedy REPO=/repo \
              bash /repo/testbed/harness/linux/new-corpus-snapshot.sh \
                  --label '$label' --raw-out /raw
        " || { echo "  실패 $label"; return 1; }
}

fail=0
if [ "$ALL" -eq 1 ]; then
    echo "$ALL_SPECS" | while IFS='|' read -r image label install libc; do
        [ -z "$image" ] && continue
        one "$image" "$label" "$install" "$libc" "$BIN" || true
    done
else
    [ -n "$IMAGE" ] && [ -n "$LABEL" ] || {
        echo "--image <이미지> --label <라벨> 이 필요하다. 또는 --all."
        exit 2
    }
    libc=glibc
    [ "$INSTALL" = "alpine" ] && libc=musl
    one "$IMAGE" "$LABEL" "$INSTALL" "$libc" "$BIN" || fail=1
fi

echo
echo "── 씻는 것은 호스트가 한다 ──"
echo "  ls $RAW_OUT"
echo "  각 파일마다:"
echo "    cargo xtask corpus --in <파일> --label <파일이름에서 .json 뺀 것> --out corpus/clean"
echo
echo "  그 뒤 반드시:"
echo "    cargo xtask snapshots            # 카탈로그와 맞는가"
echo "    cargo test -p remedy-core --test corpus   # G1"
exit "$fail"
