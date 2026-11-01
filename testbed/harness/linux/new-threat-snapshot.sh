#!/bin/bash
# AI 시험 위협의 감염 스냅샷을 **컨테이너에서 실제로 떠서** 위협 폴더에 넣는다.
#
# Windows 쪽 `host/New-InfectedSnapshot.ps1` 의 Linux 짝이다. 저쪽이 VM 에
# 예약 작업·Run 키를 세우고 실검체 바이트를 놓는 자리에서, 여기는 컨테이너에
# 링커 설정·인증서·hosts 줄을 세운다.
#
# # 왜 손으로 쓴 JSON 이면 안 되는가
#
# 다섯 위협의 감염 스냅샷이 전부 손으로 쓴 것이었다. 그런 스냅샷은 **다시 뜰
# 수 없고, 실기기가 낼 수 없는 모양을 담을 수 있다.** 둘 다 일어났다:
#
#   - `search-hijack` 이 프로세스 명령줄을 비웠다 (2026-09-03 정정).
#   - `tls-intercept` 이 `/usr/local/share/ca-certificates/` 의 인증서에
#     `store: "system"` 을 붙였다. 수집기는 그 자리를 `local` 이라 적는다.
#     **우리 정답 플러그인이 그 거짓 값에 맞춰져 있어 실기기에서는 이 위협을
#     놓쳤다.**
#
# 두 번째가 이 스크립트의 존재 이유다. 진짜 `collect` 를 돌리면 그 부류의
# 결함이 원리적으로 생기지 않는다.
#
# # 봉투는 고정한다
#
# 스냅샷은 저장소에 커밋되고 채점의 입력이 된다. 그래서 실행마다 달라지는
# 것(호스트 이름·run_id·시각·수집기 판)을 **고정 값으로 바꾼다.** 바꾸지
# 않으면 같은 위협이 뜰 때마다 diff 가 나고, 그 diff 는 아무 뜻도 없다.
#
# 레코드는 손대지 않는다 — 그것이 재려는 것이다.
#
# # 쓰는 법 (WSL 또는 리눅스 셸에서, 저장소 루트)
#
#     testbed/harness/linux/new-threat-snapshot.sh --threat ldso-preload
#     testbed/harness/linux/new-threat-snapshot.sh --threat tls-intercept
#
# 바이너리는 `invoke-linux-verify.sh` 와 같은 것을 쓴다 (그 주석의 1단계).

set -u
# 이 스크립트는 한국어 문구를 읽는다. 기본 언어는 영어다 (2026-09-06).
export REMEDY_LANG=ko

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
IMAGE="${IMAGE:-rust:1.96-bookworm}"
BIN=""
THREAT=""
DIFF_ONLY=0
# **컨테이너를 띄우지 않고 지금 이 기계에서 뜬다.**
#
# CI 잡은 이미 컨테이너 안에서 돈다 — 거기서 또 docker 를 부르려면
# docker-in-docker 가 필요하고, 그러면 `-v $PWD:/repo` 가 잡의 파일이 아니라
# dind 호스트의 파일을 가리켜 조용히 엉뚱한 것을 마운트한다.
#
# **그 잡의 컨테이너가 곧 버릴 기계다.** 그것이 이 모드의 전제이고,
# `new-threat-fixtures.sh` 의 컨테이너 검사가 그 전제를 지킨다 — 셸 러너에
# 떨어지면 거기서 멈춘다.
LOCAL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --threat) THREAT="${2:-}"; shift 2 ;;
        --bin)    BIN="${2:-}"; shift 2 ;;
        --image)  IMAGE="${2:-}"; shift 2 ;;
        --diff)   DIFF_ONLY=1; shift ;;
        --local)  LOCAL=1; shift ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

case "$THREAT" in
    ldso-preload|tls-intercept|c2-beacon|xmr-miner|ssh-backdoor|selfcopy-worm|npm-posthook|hexcfg-loader) ;;
    *) echo "--threat ldso-preload | tls-intercept | c2-beacon | xmr-miner | ssh-backdoor | selfcopy-worm | npm-posthook | hexcfg-loader"; exit 2 ;;
esac

if [ -z "$BIN" ]; then
    for c in /tmp/remedy-bookworm/release/remedy /tmp/remedy-linux/release/remedy; do
        [ -x "$c" ] && BIN="$c" && break
    done
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || {
    echo "remedy 리눅스 바이너리를 찾지 못했다 (invoke-linux-verify.sh 주석의 1단계)."
    exit 1
}
[ "$LOCAL" -eq 1 ] || command -v docker > /dev/null 2>&1 \
    || { echo "docker 가 없다. 컨테이너 안이라면 --local 을 쓴다."; exit 1; }

OUT="$REPO/testbed/ai-exam/threats/$THREAT/infected/$THREAT.json"
[ -f "$OUT" ] || { echo "대상이 없다: $OUT"; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "위협     $THREAT"
echo "이미지   $([ "$LOCAL" -eq 1 ] && echo '(이 컨테이너)' || echo "$IMAGE")"
echo "바이너리 $BIN"

if [ "$LOCAL" -eq 1 ]; then
    bash "$HERE/new-threat-fixtures.sh" --threat "$THREAT" \
        && "$BIN" collect \
            --plugin "$HERE/threats/$THREAT-collect.yaml" \
            --out "$TMP/raw.json" \
        || { echo "수집 실패"; exit 1; }
    # 세운 것을 치운다. 컨테이너는 어차피 사라지지만, CI 잡이 이어서
    # 다른 위협을 뜰 수 있고 그때 앞의 픽스처가 섞이면 안 된다.
    bash "$HERE/new-threat-fixtures.sh" --threat "$THREAT" --clean > /dev/null 2>&1
else
    docker run --rm \
        -v "$REPO:/repo:ro" \
        -v "$BIN:/usr/local/bin/remedy:ro" \
        -v "$TMP:/out" \
        -e HOME=/root -w /repo "$IMAGE" bash -c "
            set -e
            bash /repo/testbed/harness/linux/new-threat-fixtures.sh --threat '$THREAT'
            remedy collect \
                --plugin /repo/testbed/harness/linux/threats/$THREAT-collect.yaml \
                --out /out/raw.json
        " || { echo "수집 실패"; exit 1; }
fi

[ -s "$TMP/raw.json" ] || { echo "스냅샷이 비었다"; exit 1; }

# ── 봉투 고정 ───────────────────────────────────────────────────────
#
# 위협 폴더의 기존 스냅샷에서 봉투를 그대로 가져온다. 채점에 쓰이는 것은
# 레코드이지 봉투가 아니고, 봉투가 실행마다 달라지면 diff 가 뜻을 잃는다.
python3 - "$TMP/raw.json" "$OUT" <<'PY'
import io, json, sys
raw = json.load(io.open(sys.argv[1], encoding='utf-8'))
old = json.load(io.open(sys.argv[2], encoding='utf-8'))

# 봉투는 옛것을 쓰되 **범위는 새것**이다 — 무엇을 훑었는지는 이번 수집의 사실이다.
for k in ('run_id', 'created', 'collected_at', 'host', 'collector', 'core', 'plugins'):
    if k in old:
        raw[k] = old[k]

# 레코드가 하나도 없는 subject 키는 남긴다. 없는 것과 빈 것은 다르다.
io.open(sys.argv[2], 'w', encoding='utf-8', newline='').write(
    json.dumps(raw, ensure_ascii=False, indent=2) + '\n')

recs = {k: len(v) for k, v in raw.items()
        if isinstance(v, list) and v and isinstance(v[0], dict)}
print('  범위     %s' % raw['scope']['scan_roots'])
print('  잘림     %s · 거부 %s' % (raw['scope']['truncated'], raw['scope']['denied_dirs']))
print('  레코드   %d건  %s' % (sum(recs.values()),
      ' '.join('%s:%d' % kv for kv in sorted(recs.items()))))
PY

echo "  -> $OUT"
if [ "$DIFF_ONLY" -eq 1 ]; then
    (cd "$REPO" && git --no-pager diff --stat -- "$OUT")
fi
