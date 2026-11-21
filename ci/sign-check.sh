#!/bin/bash
# 룰 서명이 도는가 — 그 자리에서 만든 일회용 키로(2026-11-21 · 저장소에 개발 키 서명을 두지 않게 된 뒤의 자동 확인).
#
#   bash ci/sign-check.sh <remedy 실행 파일> [<remedy-net 실행 파일>]      저장소 루트에서
#
# 저장소의 룰 폴더(`plugins/*/plugin.yaml` 이 있는 것)를 임시 자리에 옮겨 일회용 키로 모두 서명하고(키를 한 번 푼다 —
# `cargo xtask sign plugin --dir …`), 준 remedy 가 그 공개키로 사본마다 확인하는지 · 서명 뒤 고친 사본을 거부(종료 5)하는지
# 본다. remedy-net 을 주면 그 키로 서명한 판정 기준(`plugins/remedy-net-criteria`)을 그 키를 앵커로 알아보는지도 본다
# (`url` · `image` · `container` 의 도움말 — 확인한 기준 줄이 있고 '확인하지 못했다' 줄이 없다 · 최종 확인 스크립트와 같은 판독).
#
# 개발 빌드(앵커 없음)를 준다 — 배포 키를 박은 실행 파일은 배포 잡이 배포 키로 따로 잰다(`ci/release.sh verify` · 기준 5b).
# 전에는 저장소의 룰 폴더마다 개발 키 서명(MANIFEST · MANIFEST.minisig)을 커밋했다. 배포물 · CI · 하네스 어느 것도 그 서명을
# 믿지 않았고, 트리와 어긋난 서명이 CI 를 지나 출시된 일이 두 번 있었다 — 이제 서명은 필요한 자리에서 그때 한다.
#
# 종료 코드: 0 = 모두 맞다 · 1 = 하나라도 아니다 · 2 = 인자.
set -euo pipefail
exe=${1:-}
net=${2:-}
if [ -z "$exe" ] || [ ! -f "$exe" ]; then
    echo "쓰는 법: bash ci/sign-check.sh <remedy 실행 파일> [<remedy-net 실행 파일>]" >&2
    exit 2
fi
[ -f plugins/remedy-net-criteria/plugin.yaml ] || { echo "저장소 루트에서 부를 것" >&2; exit 2; }
fail() { echo "::error::$*"; exit 1; }

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
pass=$(openssl rand -hex 16)
REMEDY_SIGN_PASSWORD=$pass cargo xtask sign keygen --public-key "$W/k.pub" --secret-key "$W/k.key" >/dev/null

dirs=()
args=()
for y in plugins/*/plugin.yaml; do
    d=$(dirname "$y")
    n=$(basename "$d")
    cp -R "$d" "$W/$n"
    rm -f "$W/$n/MANIFEST" "$W/$n/MANIFEST.minisig"
    dirs+=("$W/$n")
    args+=(--dir "$W/$n")
done
REMEDY_SIGN_PASSWORD=$pass cargo xtask sign plugin "${args[@]}" --secret-key "$W/k.key" \
    --signed-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null

for d in "${dirs[@]}"; do
    "$exe" plugin verify --dir "$d" --public-key "$W/k.pub" >/dev/null 2>&1 ||
        fail "$(basename "$d"): 일회용 키로 서명한 사본을 그 공개키로 확인하지 못했다"
done
echo "서명: 룰 ${#dirs[@]}개를 일회용 키로 서명했고 그 공개키로 모두 확인했다"

t=${dirs[0]}
printf '\n# changed after signing\n' >>"$t/plugin.yaml"
rc=0
"$exe" plugin verify --dir "$t" --public-key "$W/k.pub" >/dev/null 2>&1 || rc=$?
[ "$rc" = 5 ] || fail "서명 뒤 고친 사본($(basename "$t")): 종료 $rc — 5(거부)여야 한다"
echo "서명: 서명 뒤 고친 사본을 거부했다(종료 5)"

if [ -n "$net" ]; then
    [ -f "$net" ] || fail "remedy-net 실행 파일이 없다: $net"
    anchor=$(sed -n 2p "$W/k.pub" | tr -d '\r')
    ok=0
    for c in url image container; do
        out=$(REMEDY_LANG=en REMEDY_NET_CRITERIA="$W/remedy-net-criteria" REMEDY_NET_ANCHOR="$anchor" \
            "$net" "$c" --help 2>&1 | tr -d '\r' || true)
        if grep -qE '^Criteria( \([A-Za-z]+\))?: ' <<<"$out" && ! grep -q 'could not be verified' <<<"$out"; then
            ok=$((ok + 1))
        else
            echo "$c --help:"
            grep -E 'Criteria|could not' <<<"$out" | head -5 || true
        fi
    done
    [ "$ok" = 3 ] || fail "remedy-net 이 일회용 키로 서명한 판정 기준을 알아본 명령이 $ok/3 이다"
    echo "판정 기준: remedy-net 이 일회용 키로 서명한 기준을 그 키로 알아봤다(명령 3/3)"
fi
