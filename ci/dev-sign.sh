#!/bin/bash
# 개발 · 하네스용 — 룰 폴더의 사본을 일회용 키로 서명하고 그 공개키(앵커)를 낸다(2026-11-21 · 저장소에 개발 키 서명을 두지
# 않게 된 뒤 · 목표 remedy_하루30건_대응체계 차례 2).
#
#   bash ci/dev-sign.sh --out <폴더> <룰 폴더>…        저장소 루트에서 · Git Bash · 리눅스
#
# `<폴더>/<룰 이름>/` 에 서명한 사본, `<폴더>/anchor.txt` 에 앵커(공개키 base64 한 줄), `<폴더>/key.pub` 에 공개키 파일을 둔다.
# 개인키와 암호는 서명 뒤 지운다 — 이 키는 아무것도 증명하지 않고, 그 자리의 개발 빌드가 서명을 읽는 길을 재는 데만 쓴다.
# 배포물은 배포 잡이 배포 키로 서명한다(`ci/release.sh`). 쓰는 곳 — remedy-net 개발 빌드가 판정 기준을 읽을 때:
#
#   bash ci/dev-sign.sh --out /tmp/crit plugins/remedy-net-criteria
#   bash testbed/harness/linux/net-apache-verify.sh --bin <개발 remedy-net> --criteria /tmp/crit/remedy-net-criteria \
#        --anchor "$(cat /tmp/crit/anchor.txt)" --images … --out …
#
# 전에는 저장소의 룰 폴더마다 개발 키로 서명해 커밋했다 — 그 키와 암호가 한 PC 에만 있어 처음 보는 사람이 막혔다.
set -euo pipefail
OUT=""
dirs=()
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT=$2; shift 2 ;;
        -*) echo "모르는 인자: $1" >&2; exit 2 ;;
        *) dirs+=("$1"); shift ;;
    esac
done
if [ -z "$OUT" ] || [ ${#dirs[@]} -eq 0 ]; then
    echo "쓰는 법: bash ci/dev-sign.sh --out <폴더> <룰 폴더>…" >&2
    exit 2
fi
mkdir -p "$OUT"
pass=$(openssl rand -hex 16)
rm -f "$OUT/key.pub" "$OUT/key.sec"
REMEDY_SIGN_PASSWORD=$pass cargo xtask sign keygen --public-key "$OUT/key.pub" --secret-key "$OUT/key.sec" >/dev/null
trap 'rm -f "$OUT/key.sec"' EXIT
args=()
for d in "${dirs[@]}"; do
    [ -f "$d/plugin.yaml" ] || { echo "룰 폴더가 아니다(plugin.yaml 없음): $d" >&2; exit 2; }
    n=$(basename "$d")
    rm -rf "${OUT:?}/$n"
    cp -R "$d" "$OUT/$n"
    rm -f "$OUT/$n/MANIFEST" "$OUT/$n/MANIFEST.minisig"
    args+=(--dir "$OUT/$n")
done
REMEDY_SIGN_PASSWORD=$pass cargo xtask sign plugin "${args[@]}" --secret-key "$OUT/key.sec" \
    --signed-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
sed -n 2p "$OUT/key.pub" | tr -d '\r' >"$OUT/anchor.txt"
echo "일회용 키로 ${#dirs[@]}개 폴더를 서명했다 → $OUT (앵커 $(cat "$OUT/anchor.txt"))"
