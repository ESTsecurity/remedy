#!/bin/bash
# 필수 점검 리눅스 몫(testbed/harness/linux/emergency-checks.sh)의 음성 회차 — 일부러 실패하는 하네스(①)와 룰 한 파일에 한 줄을
# 더한 꾸러미(②)를 주고 멈추는지 본다(2026-11-22 · 목표 remedy_하루30건 기준 7 (가) — 게이트마다 일부러 깨뜨린 입력).
#
#   bash ci/emergency-checks-test.sh <지금 Latest 의 remedy-linux-x64.tar.gz>
#
# 저장소 루트에서 · docker 가 드는 곳(CI 의 리눅스 잡)에서 부른다. 이미지 debian:12 · ubuntu:24.04 가 없으면 받는다. 회차마다
# 깨뜨린 칸만 실패하고 나머지 칸은 지나야 한다 — 그래야 종료 1 이 그 칸 때문이다(점검의 요약 줄을 칸마다 견준다):
#   A  ① 종료 1 하네스 · 꾸러미는 그대로(--new = --prev)  → 종료 1 · ① 종료 1 · ② 지남 · ③ 두 이미지가 같은 종료 코드
#   B  ① none · 데이터 룰 한 파일을 바꾼 꾸러미           → 종료 1 · ② 룰 서명 하나 모자람 · 체크섬 · 실행 파일 지남 · ③ 같음
# B 가 바꾸는 룰은 데이터 룰(kind: data — 판정 기준)이다. 메뉴는 데이터 룰을 검사 항목에 올리지 않아(crates/remedy-cli/src/guided.rs
# '쓸 수 있는 것만 남긴다') 서명이 깨져도 '모두 검사'(③)가 도는 룰은 그대로다 — ③ 의 종료 코드가 그 바꿈에 흔들리지 않는다.
# 꾸러미는 새로 묶고 SHA256SUMS 도 새로 지어, ② 에서 실패하는 칸이 룰 서명 하나뿐이게 한다.
set -euo pipefail
LATEST_TAR=${1:?지금 Latest 의 remedy-linux-x64.tar.gz}
[ -f "$LATEST_TAR" ] || { echo "없다: $LATEST_TAR" >&2; exit 2; }
CHECKS=testbed/harness/linux/emergency-checks.sh
[ -f "$CHECKS" ] || { echo "저장소 루트에서 부를 것($CHECKS)" >&2; exit 2; }
for i in debian:12 ubuntu:24.04; do docker image inspect "$i" >/dev/null 2>&1 || docker pull -q "$i" >/dev/null; done

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
PASS=0
BAD=0
t() { if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); echo "통과  $1"; else BAD=$((BAD + 1)); echo "실패  $1 — '$2'(기대 '$3')"; fi; }
# ③ 줄 가운데 지난 공개본과 새 파일의 종료 코드가 같고 그 값이 있는 이미지 수(둘이어야 한다).
same3() {
    local n=0 line p q
    while IFS= read -r line; do
        p=$(sed -E 's/.* · 지난 공개본 ([^(]+)\(.*/\1/' <<<"$line")
        q=$(sed -E 's/.* · 새 파일 ([^(]+)\(.*/\1/' <<<"$line")
        if [ "$p" = "$q" ] && [ "$p" != 없음 ]; then n=$((n + 1)); fi
    done < <(grep -E '^3 모두 검사 · (debian|ubuntu)' "$1" || true)
    echo "$n"
}
# 점검을 돌려 종료 코드를 낸다 — 기록은 <폴더>.log · 요약은 <폴더>/summary.txt.
checks() { # 결과 폴더 · 점검 인자…
    local out=$1 rc=0
    shift
    bash "$CHECKS" --out "$out" "$@" >"$out.log" 2>&1 || rc=$?
    echo "$rc"
}

# ── A — 일부러 실패하는 하네스 · 꾸러미는 그대로 ────────────────────────────────────────────────
# 점검이 주는 꼴(--bin · --plugins · --out)을 받아 판정 줄을 남기고 종료 1.
printf '%s\n' '#!/bin/bash' 'out=""' 'while [ $# -gt 0 ]; do [ "$1" = --out ] && out=$2; shift; done' \
    'mkdir -p "$out" && echo "판정 0/1 · 실패 1(음성 회차)" >"$out/verdict.txt"' 'exit 1' >"$W/fail-verify.sh"
mkdir -p "$W/a"
cp "$LATEST_TAR" "$W/a/remedy-linux-x64.tar.gz"
(cd "$W/a" && sha256sum remedy-linux-x64.tar.gz >SHA256SUMS)
rc=$(checks "$W/out-a" --new "$W/a/remedy-linux-x64.tar.gz" --prev "$LATEST_TAR" --harness "$W/fail-verify.sh")
S="$W/out-a/summary.txt"
t "A 점검이 종료 1 로 멈춘다" "$rc" 1
t "A ① 하네스가 종료 1" "$(grep -c '^1 새 룰 하네스(fail-verify.sh) · 종료 1 ' "$S" || true)" 1
t "A ② 체크섬은 지난다" "$(grep -c '^2 체크섬 · 종료 0 ' "$S" || true)" 1
t "A ② 정식 파일은 지난다" "$(grep -c '^2 정식 파일 · 종료 0 ' "$S" || true)" 1
t "A ② 실행 파일이 지난 공개본과 같은 바이트" "$(grep -c '^2 실행 파일 · 지난 공개본과 같은 바이트 2/2' "$S" || true)" 1
t "A ③ 두 이미지가 같은 종료 코드" "$(same3 "$S")" 2

# ── B — 데이터 룰 한 파일에 한 줄을 더한 꾸러미 ─────────────────────────────────────────────────
mkdir -p "$W/b/x"
tar -xzf "$LATEST_TAR" -C "$W/b/x"
top=$(ls "$W/b/x")
rule=""
for y in "$W/b/x/$top"/plugins/*/plugin.yaml; do
    if grep -qE '^kind:[[:space:]]*data' "$y"; then rule=$y; break; fi
done
[ -n "$rule" ] || { echo "꾸러미에 데이터 룰(kind: data)이 없다 — 바꿀 룰을 고르지 못했다" >&2; exit 1; }
printf '# 음성 회차 — 서명 뒤에 더한 줄\n' >>"$rule"
echo "B 가 바꾼 파일: ${rule#"$W/b/x/$top/"}"
(cd "$W/b/x" && tar -czf "$W/b/remedy-linux-x64.tar.gz" "$top")
(cd "$W/b" && sha256sum remedy-linux-x64.tar.gz >SHA256SUMS)
rc=$(checks "$W/out-b" --new "$W/b/remedy-linux-x64.tar.gz" --prev "$LATEST_TAR" --harness none)
S="$W/out-b/summary.txt"
sig=$(sed -nE 's/^2 정식 파일 · 종료 1 · 룰 서명 ([0-9]+)\/([0-9]+) .*/\1 \2/p' "$S")
read -r okn alln <<<"${sig:-x x}"
t "B 점검이 종료 1 로 멈춘다" "$rc" 1
t "B ② 정식 파일이 종료 1 · 룰 서명 하나 모자람" "$([ "$okn" != x ] && [ $((alln - okn)) = 1 ] && echo 예 || echo "아니오(${sig:-줄 없음})")" 예
t "B ② 체크섬은 지난다(새로 지은 SHA256SUMS)" "$(grep -c '^2 체크섬 · 종료 0 ' "$S" || true)" 1
t "B ② 실행 파일이 지난 공개본과 같은 바이트" "$(grep -c '^2 실행 파일 · 지난 공개본과 같은 바이트 2/2' "$S" || true)" 1
t "B ③ 두 이미지가 같은 종료 코드(데이터 룰은 검사 항목이 아니다)" "$(same3 "$S")" 2

if [ "$BAD" != 0 ]; then
    for r in a b; do
        echo "── 회차 ${r^^} 의 요약"
        sed 's/^/    /' "$W/out-$r/summary.txt" 2>/dev/null || tail -n 20 "$W/out-$r.log"
    done
fi
echo "--- 통과 $PASS · 실패 $BAD"
[ "$BAD" = 0 ]
