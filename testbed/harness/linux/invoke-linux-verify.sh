#!/bin/bash
# 호스트에서 Linux 검증 하네스를 구동한다 (설계-09 P12).
#
# Windows 쪽 `host/Invoke-P*Verify.ps1` 의 짝이다. 하는 일은 훨씬 적다 —
# 저쪽은 WinRM 으로 VM 에 붙어 파일을 밀어 넣고 스냅샷으로 되돌리지만,
# 여기서는 컨테이너를 띄우고 지우면 끝이다.
#
# # 왜 컨테이너인가
#
# 하네스가 `/etc/hosts` 를 고치고 systemd 유닛을 지우고 프로세스를 죽인다.
# 개발용 WSL 에서 돌릴 수 없다. Windows 가 VM 스냅샷으로 얻는 격리를
# Linux 에서는 컨테이너가 준다 — 그리고 스냅샷 되돌리기가 필요 없다.
#
# WSL 에는 그 밖에 **systemd 가 PID 1 이 아니라는** 문제도 있다. 다만 Linux 의
# `service.disable`·`service.delete` 는 순수 파일 조작(`.wants/` 링크와 유닛
# 파일 제거)이라 systemd 없이도 잰다.
#
# # 바이너리는 밖에서 만든다
#
# 컨테이너 안에서 매번 crates 를 받으면 사내망 TLS 가로채기 아래에서 안 된다
# (`ci/linux-check-local.sh` 가 같은 이유로 오프라인이다). 그래서 **배포
# 바이너리**를 만들어 마운트해 넣는다.
#
# **glibc 판이 맞아야 한다.** 그리고 이미지는 아무거나 되지 않는다 —
# `cert_store.remove` 가 `update-ca-certificates` 를 요구하기 때문이다. 없으면
# 그 Op 은 거부되고(그것이 옳은 동작이다) 하네스는 그 자리를 **"못 잼"** 으로
# 적는다. 실패가 아니지만 통과도 아니다.
#
# | 이미지 | glibc | update-ca-certificates |
# |---|---|---|
# | `rust:1.96-bookworm` | 2.36 | **있다** ← 기본값 |
# | `debian:12` | 2.36 | 없다 |
# | `ubuntu:24.04` | 2.39 | 없다 |
#
# 그래서 기본은 `rust:1.96-bookworm` 이고, 바이너리도 거기서 만든다. 2.36 에서
# 만든 것은 위의 셋에서 전부 돈다(2.39 에서 만든 것은 bookworm 에서 안 돈다).
#
# # 쓰는 법 (WSL 또는 리눅스 셸에서, 저장소 루트)
#
#     # 1. 배포 바이너리를 bookworm 에서 만든다 (한 번)
#     mkdir -p /tmp/remedy-bookworm
#     docker run --rm -v "$PWD:/repo:ro" \
#         -v <Windows 쪽 .cargo 의 WSL 경로>/registry:/usr/local/cargo/registry \
#         -v /tmp/remedy-bookworm:/t -e CARGO_TARGET_DIR=/t \
#         -w /repo rust:1.96-bookworm \
#         cargo build --release --offline -p remedy-cli
#
#     # 2. 검증을 돌린다
#     testbed/harness/linux/invoke-linux-verify.sh \
#         --bin /tmp/remedy-bookworm/release/remedy
#
# 레지스트리를 읽기 전용으로 걸면 안 된다 — `yara-x` 의 빌드 스크립트가 그
# 아래에 쓴다.
#
# 결과는 `testbed/harness/results/linux-<시각>/verify-linux.json` 에 남는다.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
IMAGE="${IMAGE:-rust:1.96-bookworm}"
BIN=""
TAG="linux-$(date +%Y%m%d-%H%M%S)"
KEEP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)   BIN="${2:-}"; shift 2 ;;
        --image) IMAGE="${2:-}"; shift 2 ;;
        --tag)   TAG="${2:-}"; shift 2 ;;
        --keep)  KEEP=1; shift ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

if [ -z "$BIN" ]; then
    for c in /tmp/remedy-bookworm/release/remedy \
             /tmp/remedy-linux/release/remedy \
             "$REPO/target/release/remedy"; do
        [ -x "$c" ] && BIN="$c" && break
    done
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "remedy 리눅스 바이너리를 찾지 못했다. 위 주석의 1단계를 먼저 돌리거나"
    echo "--bin <경로> 로 지정한다."
    exit 1
fi

command -v docker > /dev/null 2>&1 || { echo "docker 가 없다."; exit 1; }

OUT="$REPO/testbed/harness/results/$TAG"
mkdir -p "$OUT"

echo "이미지   $IMAGE"
echo "바이너리 $BIN"
echo "결과     $OUT"

# `--privileged` 를 주지 않는다. 하네스가 하는 일은 전부 파일 조작과
# 자기 자식 프로세스 죽이기라 기본 권한으로 충분하다. 권한을 더 주면
# **무엇이 정말로 필요한지**를 이 하네스가 더 이상 말해 주지 못한다.
docker run --rm \
    -v "$REPO:/repo:ro" \
    -v "$BIN:/usr/local/bin/remedy:ro" \
    -v "$OUT:/out" \
    -e HOME=/root \
    -w /repo \
    "$IMAGE" \
    bash /repo/testbed/harness/linux/verify-linux.sh \
        --bin /usr/local/bin/remedy --out /out
rc=$?

echo
if [ "$rc" -eq 0 ]; then
    echo "전부 통과."
else
    echo "실패가 있다 (exit=$rc). $OUT/verify-linux.json 를 볼 것."
fi

if [ "$KEEP" -eq 0 ]; then
    # 중간 산출물은 지운다. 판정과 상태 diff 만 남긴다 — 저장소에 커밋되는
    # 것은 결과이지 스캔 부산물이 아니다.
    rm -rf "$OUT/scan" "$OUT/state" "$OUT/extracted" "$OUT/artifacts.json"
fi

exit "$rc"
