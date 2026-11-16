#!/bin/bash
# 룰이 늘어도 버티는가 — 합성 룰 N 개(기본 1,000)로 메뉴의 *모두 검사만* 을 끝까지 돌려 잰다
# (목표 remedy_전체검사_운영기반 기준 6).
#
# 호스트(WSL)에서:
#
#   bash testbed/harness/linux/bench-scan-all.sh [--count N] [--out <폴더>] [--cargo-home <WSL 에서 본 CARGO_HOME>]
#
# **합성 룰은 실제 룰의 복제다.** 리눅스 배포 룰(`xtask threats --dirs linux`) 가운데 이 기계를 보는 것에서
# 네트워크 점검 · 데이터 룰과 **디스크 전체를 도는 룰**(`%FIXED_DISKS%` — 한 번에 수십 초라 수로 곱하면 그것만
# 잰다)을 빼고, 남은 것을 차례로 돌려 N 개를 짓는다 — id 앞에 `bNNNN-` 를 붙이고 이름 끝에 ` #N` 을 단다. 검사
# 범위 · 술어 · YARA 는 그대로라 한 룰의 비용은 실제 룰의 것이다. 깨끗한 컨테이너라 찾는 것은 없다.
#
# 메뉴 하네스(menu-verify.sh)와 같은 조립이다 — 일회용 키쌍 → 그 공개키를 박은 빌드 → 서명(키를 한 번만 푼다 —
# `sign plugin` 에 `--dir` 을 여러 번) → `xtask package`. 같은 조립을 **템플릿 하나씩**(룰 수 = 템플릿 수)으로도
# 지어 견줄 기준으로 쓴다. 개인키는 컨테이너와 함께 버린다.
#
# 잰다(꾸러미마다): 꾸러미 크기 · 파일 수 · 고르는 화면이 서고 그만두기까지(서명 확인 N 개 포함) · 그 화면의 줄 수 ·
# *모두 검사만* 의 시간 · 최대 메모리(remedy 의 VmHWM) · 화면 줄 수 · 요약 줄 수 · 종료 코드 · 결과(`out`) ·
# 상태(`state`) 폴더 크기. 남기는 것: metrics.txt · <꾸러미>-start.txt · <꾸러미>-scan-all.txt.
# **판정은 '끝까지 돌았는가' 만이다** — 시간 · 메모리 · 메뉴의 한도는 잰 값을 보고 정한다(목표의 D6).
#
# 툴체인은 호스트(WSL)의 것을 읽기 전용으로 붙인다 — 사내망에서는 컨테이너의 rustup 이 1.96.0 을 못 받을 수 있다.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
TC=1.96.0-x86_64-unknown-linux-gnu
COUNT=1000
OUT=""
CARGO_HOME_ARG=""
INSIDE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --count) COUNT=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --cargo-home) CARGO_HOME_ARG=$2; shift 2 ;;
        --inside) INSIDE=1; shift ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

inside() {
    cd /repo || return 9
    export CARGO_TARGET_DIR=/tmp/remedy-bookworm
    local w=/tmp/bench-scan-all
    rm -rf "$w"; mkdir -p "$w"
    export REMEDY_SIGN_PASSWORD=bench-scan-all-ephemeral
    cargo build -q -p xtask || { echo "error=xtask 를 짓지 못했다"; return 2; }
    local xt="$CARGO_TARGET_DIR/debug/xtask"
    "$xt" sign keygen --public-key "$w/pub.key" --secret-key "$w/sec.key" >/dev/null \
        || { echo "error=키쌍을 만들지 못했다"; return 2; }
    local anchor
    anchor=$(sed -n 2p "$w/pub.key")
    REMEDY_TRUST_ANCHOR="$anchor" cargo build -q --release --locked -p remedy-cli \
        || { echo "error=앵커 박은 빌드가 실패했다"; return 3; }

    # 템플릿 — 이 기계를 보는 배포 룰(네트워크 · 데이터 · 디스크 전체 룰은 뺀다).
    local t templates=()
    for t in $("$xt" threats --dirs linux); do
        grep -q -E '^(network:|kind: data)' "$t/plugin.yaml" && continue
        grep -q '%FIXED_DISKS%' "$t/plugin.yaml" && continue
        # 절대 경로로 둔다 — 꾸러미를 지을 때마다 현재 폴더가 바뀐다.
        templates+=("$(realpath "$t")")
    done
    echo "templates=${#templates[@]}"
    echo "template_names=$(for t in "${templates[@]}"; do basename "$t"; done | tr '\n' ' ')"

    # 꾸러미 하나 — 이름 · 룰 수. 경로는 짧은 상대 경로로 넘긴다(인자 수천 개).
    build_pkg() {
        local name=$1 n=$2 i k id dst dirs=() plugins=()
        mkdir -p "$w/$name/r"
        for ((i = 1; i <= n; i++)); do
            k=$(( (i - 1) % ${#templates[@]} ))
            id=$(printf 'b%04d' "$i")
            dst="$w/$name/r/$id"
            cp -a "${templates[$k]}" "$dst"
            rm -f "$dst/MANIFEST" "$dst/MANIFEST.minisig"
            sed -i -E "s/^id: (.*)$/id: $id-\1/" "$dst/plugin.yaml"
            sed -i -E "/^name:/,/^[a-z_]+:/ s/^(  (ko|en): \")(.*)\"$/\1\3 #$i\"/" "$dst/plugin.yaml"
            dirs+=(--dir "r/$id")
            plugins+=(--plugin "r/$id")
        done
        (cd "$w/$name" && "$xt" sign plugin "${dirs[@]}" --secret-key "$w/sec.key" \
            --signed-at 2026-11-16T00:00:00Z >/dev/null) || { echo "error=$name 를 서명하지 못했다"; return 4; }
        (cd "$w/$name" && "$xt" package "${plugins[@]}" --bin "$CARGO_TARGET_DIR/release/remedy" --out pkg \
            --public-key "$w/pub.key" >/dev/null) || { echo "error=$name 꾸러미를 짓지 못했다"; return 5; }
        echo "${name}_rules=$n"
        echo "${name}_pkg_bytes=$(du -sb "$w/$name/pkg" | cut -f1)"
        echo "${name}_pkg_files=$(find "$w/$name/pkg" -type f | wc -l)"
    }

    # 가장 나중에 뜬 remedy 프로세스 — `pgrep` 이 없는 이미지에서도 돌게 /proc 를 직접 본다.
    remedy_pid() {
        local d last=""
        for d in /proc/[0-9]*; do
            [ "$(cat "$d/comm" 2>/dev/null)" = remedy ] && last=${d#/proc/}
        done
        echo "$last"
    }

    # 한 번 띄운다 — 이름 · 꾸러미 · 입력. 걸린 시간(초)과 remedy 의 최대 메모리(VmHWM · KiB)를 잰다.
    run_menu() {
        local name=$1 pkg=$2 input=$3 out="/out/$1.txt"
        cd "$w/$pkg/pkg" || return 6
        local t0 t1 pid v hwm=0
        t0=$(date +%s.%N)
        (printf '%b' "$input" | LANG=ko_KR.UTF-8 script -q -e -c "./remedy > $out 2>&1" /dev/null
         echo $? >"/tmp/$name.exit") &
        local bg=$!
        while kill -0 "$bg" 2>/dev/null; do
            pid=$(remedy_pid)
            if [ -n "$pid" ]; then
                v=$(awk '/^VmHWM:/{print $2}' "/proc/$pid/status" 2>/dev/null)
                [ -n "$v" ] && [ "$v" -gt "$hwm" ] && hwm=$v
            fi
            sleep 0.2
        done
        t1=$(date +%s.%N)
        echo "${name}_secs=$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f", b - a }')"
        echo "${name}_exit=$(cat "/tmp/$name.exit")"
        echo "${name}_hwm_kib=$hwm"
        echo "${name}_lines=$(wc -l <"$out")"
    }

    local p n
    for p in small big; do
        n=$([ "$p" = small ] && echo "${#templates[@]}" || echo "$COUNT")
        build_pkg "$p" "$n" || return $?
        cd "$w/$p/pkg" && rm -rf out state
        # 0 = 고르는 화면에서 그만두기 — 서명 확인 N 개 · 화면 그리기까지의 시간이다.
        run_menu "$p-start" "$p" '0\n'
        echo "$p-start_chooser_lines=$(grep -c -E '^ +[0-9]+\. ' "/out/$p-start.txt")"
        # 1 = 모두 검사만 · 빈 줄 = 작업 뒤의 멈춤 · 0 = 그만두기.
        run_menu "$p-scan-all" "$p" '1\n\n0\n'
        # 요약이 덮는 룰 수 — 줄로 적힌 룰 + '나머지 N개'(룰이 한 화면을 넘으면 깨끗한 룰 · 해당 없는 룰은 수로만
        # 선다 — D10). 요약 구간은 머리 다음 줄부터 다음 구분선까지다(뒤따르는 다음 할 일 · 안내 줄을 세지 않게).
        local sum listed rest
        sum=$(awk '/모두 검사한 결과/ { f = 1; next } f && /^(──|----)/ { exit } f' "/out/$p-scan-all.txt")
        listed=$(printf '%s\n' "$sum" | grep -E '^  .+ (—|-) ' | grep -c -v -E '^  나머지 [0-9]+개 ')
        rest=$(printf '%s\n' "$sum" | sed -n -E 's/^  나머지 ([0-9]+)개 .*/\1/p' | head -1)
        echo "$p-scan-all_summary=$((listed + ${rest:-0}))"
        echo "$p-scan-all_listed=$listed"
        cd "$w/$p/pkg" || return 7
        echo "$p-out_bytes=$(du -sb out 2>/dev/null | cut -f1)"
        echo "$p-state_bytes=$(du -sb state 2>/dev/null | cut -f1)"
        echo "$p-out_dirs=$(find out -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
    done
}

if [ "$INSIDE" = 1 ]; then
    inside
    exit $?
fi

. "$HERE/lab-config.sh"
CARGO_HOME_WSL=$(lab_need "$CARGO_HOME_ARG" --cargo-home host wsl.cargo_home) || exit 2
[ -n "$OUT" ] || OUT="$REPO/testbed/harness/results/linux-bench-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
docker run --rm \
    -v "$REPO:/repo" \
    -v "$OUT:/out" \
    -v "$CARGO_HOME_WSL/registry:/usr/local/cargo/registry" \
    -v remedy-bookworm-target:/tmp/remedy-bookworm \
    -v "$HOME/.rustup/toolchains/$TC:/usr/local/rustup/toolchains/$TC:ro" \
    rust:1.96-bookworm bash /repo/testbed/harness/linux/bench-scan-all.sh --inside --count "$COUNT" \
    | tee "$OUT/run.txt"

# 끝까지 돌았는가 — 두 꾸러미 모두 모두 검사만이 마치지 못한 룰 없이(4 · 5 · 7 이 아니고) 룰마다 요약 한 줄.
v() { sed -n "s/^$1=//p" "$OUT/run.txt"; }
{
    for p in small big; do
        for k in rules pkg_bytes pkg_files; do echo "${p}_$k=$(v "${p}_$k")"; done
        for k in start_secs start_hwm_kib start_chooser_lines scan-all_secs scan-all_exit scan-all_hwm_kib \
                 scan-all_lines scan-all_summary scan-all_listed out_bytes state_bytes out_dirs; do
            echo "$p-$k=$(v "$p-$k")"
        done
        s=$(v "$p-start_secs"); a=$(v "$p-scan-all_secs"); r=$(v "${p}_rules")
        echo "$p-per_rule_ms=$(awk -v s="$s" -v a="$a" -v r="$r" 'BEGIN { if (r > 0) printf "%.0f", (a - s) * 1000 / r }')"
    done
} | tee "$OUT/metrics.txt"
m() { sed -n "s/^$1=//p" "$OUT/metrics.txt"; }
for p in small big; do
    case "$(m "$p-scan-all_exit")" in 0 | 2 | 6) ;; *) exit 1 ;; esac
    [ "$(m "$p-scan-all_summary")" = "$(m "${p}_rules")" ] || exit 1
done
exit 0
