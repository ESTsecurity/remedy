#!/bin/bash
# 호스트에서 리눅스 채점 5 를 구동한다.
#
# `invoke-linux-verify.sh` 와 같은 모양이다 — 컨테이너를 띄우고 지우면 끝이다.
# Windows 쪽 `host/Invoke-ExamApply.ps1` 이 VM 스냅샷으로 얻는 청정 기준을
# 여기서는 **새 컨테이너**가 준다. 그래서 되돌리기가 필요 없고, 살아 있는
# 기계가 스스로 만드는 잡음도 거의 없다.
#
# # 쓰는 법 (WSL 또는 리눅스 셸에서, 저장소 루트)
#
#     # 배포 바이너리를 bookworm 에서 먼저 만든다 (invoke-linux-verify.sh 참고)
#     testbed/harness/linux/invoke-exam-apply.sh --threat ldso-preload \
#         --bin /tmp/remedy-bookworm/release/remedy
#
# 응시자 답안을 재려면 `--plugin` 을 준다. 경로는 **저장소 안**이어야 한다 —
# 컨테이너에 저장소만 마운트한다.
#
#     --plugin testbed/ai-exam/runs/<회차>/plugin.yaml
#
# # 사람이 있는 회차 — `--attended`
#
# `--yes` 는 "화면 앞에 사람이 없다" 는 선언이고, 그러면 계획기가
# `cert_store.remove` 를 뺀다 — 신뢰 루트를 지우려면 인증서 주체를 읽고 판단할
# 사람이 필요하기 때문이다. `tls-intercept` 는 그래서 무인 회차에서 **미결**로
# 끝난다.
#
#     invoke-exam-apply.sh --threat tls-intercept --attended
#
# # 증거를 남긴다 — `--record`
#
# 합격 회차의 결과를 위협 폴더(`apply-result.json`)에 둔다.
# `cargo xtask exam-apply` 가 그 증거가 **지금 자료로 재어진 것인지** 본다 —
# 정답 플러그인이나 기대 Op 이 그 뒤에 바뀌면 게이트가 빨개진다.
#
# 이때 하네스가 컨테이너 안에 `script` 로 pty 를 만들고 **사람 대신 '예' 로
# 답한다.** 판정 줄이 그 사실을 적는다 — 그 회차의 합격은 "사람이 승인하면
# 깨끗해진다" 는 뜻이지 "사람 없이 깨끗해진다" 가 아니다.
#
# # 이미지
#
# `cert_store.remove` 가 `update-ca-certificates` 를 요구한다. 없으면 그 Op 은
# 거부되고(그것이 옳은 동작이다) `tls-intercept` 가 불합격으로 나온다 — 결함이
# 아니라 이미지의 한계다. 기본 이미지는 그것을 갖고 있다.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
IMAGE="${IMAGE:-rust:1.96-bookworm}"
THREAT=""
BIN=""
PLUGIN=""
TAG=""
ATTENDED=0
RECORD=0

while [ $# -gt 0 ]; do
    case "$1" in
        --threat) THREAT="${2:-}"; shift 2 ;;
        --bin)    BIN="${2:-}"; shift 2 ;;
        --plugin) PLUGIN="${2:-}"; shift 2 ;;
        --attended) ATTENDED=1; shift ;;
        --record)   RECORD=1; shift ;;
        --image)  IMAGE="${2:-}"; shift 2 ;;
        --tag)    TAG="${2:-}"; shift 2 ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

case "$THREAT" in
    ldso-preload|tls-intercept|c2-beacon|xmr-miner|ssh-backdoor|selfcopy-worm|npm-posthook|hexcfg-loader) ;;
    *) echo "--threat ldso-preload | tls-intercept | c2-beacon | xmr-miner | ssh-backdoor | selfcopy-worm | npm-posthook | hexcfg-loader"; exit 2 ;;
esac
[ -n "$TAG" ] || TAG="exam-apply-$THREAT-$(date +%Y%m%d-%H%M%S)"

if [ -z "$BIN" ]; then
    for c in /tmp/remedy-bookworm/release/remedy \
             /tmp/remedy-linux/release/remedy \
             "$REPO/target/release/remedy"; do
        [ -x "$c" ] && BIN="$c" && break
    done
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || {
    echo "remedy 리눅스 바이너리를 찾지 못했다. invoke-linux-verify.sh 의 1단계를 먼저"
    echo "돌리거나 --bin <경로> 로 지정한다."
    exit 1
}
command -v docker > /dev/null 2>&1 || { echo "docker 가 없다."; exit 1; }

OUT="$REPO/testbed/harness/results/$TAG"
mkdir -p "$OUT"

echo "이미지   $IMAGE"
echo "바이너리 $BIN"
echo "결과     $OUT"
echo

ARGS=(--threat "$THREAT" --bin /usr/local/bin/remedy --out /out)
[ -n "$PLUGIN" ] && ARGS+=(--plugin "/repo/$PLUGIN")
[ "$ATTENDED" -eq 1 ] && ARGS+=(--attended)

# 저장소는 읽기 전용이다. 산출물은 `/out` 과 컨테이너의 임시 경로로 간다 —
# 하네스가 저장소를 고칠 수 있으면 그 결과를 믿을 수 없다.
docker run --rm \
    -v "$REPO:/repo:ro" \
    -v "$BIN:/usr/local/bin/remedy:ro" \
    -v "$OUT:/out" \
    -e HOME=/root \
    -w /repo \
    "$IMAGE" \
    bash /repo/testbed/harness/linux/exam-apply.sh "${ARGS[@]}"
rc=$?

# **증거는 정답 플러그인의 것만 남긴다.** 응시자 답안의 결과를 위협 폴더에
# 두면 그 위협의 "정답이 기계를 고친다" 는 기록이 응시자의 답으로 바뀐다.
if [ "$RECORD" -eq 1 ]; then
    if [ -n "$PLUGIN" ]; then
        echo "--record 는 정답 플러그인으로 돌릴 때만 쓴다. 지금 대상: $PLUGIN"
        exit 2
    fi
    DEST="$REPO/testbed/ai-exam/threats/$THREAT/apply-result.json"
    if [ -f "$OUT/apply-result.json" ]; then
        cp "$OUT/apply-result.json" "$DEST"
        echo "증거를 남겼다: $DEST"
    else
        echo "증거가 없다 — 합격 회차가 아니었다. 위협 폴더는 그대로 둔다."
    fi
fi

echo
case "$rc" in
    0) echo "채점 5 합격." ;;
    1) echo "채점 5 불합격. $OUT/verdict.tsv 를 볼 것." ;;
    2) echo "채점 5 미결 — 통과로 읽으면 안 된다." ;;
    *) echo "하네스가 $rc 로 끝났다. $OUT 를 볼 것." ;;
esac
exit "$rc"
