#!/bin/bash
# Ebury 점검 룰(ebury-check)을 리눅스 컨테이너에서 잰다.
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/ebury-verify.sh --bin <remedy> --plugins <ebury-check 가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--bin` 은 **정적 링크 배포 바이너리**여야 한다 — A 칸이 glibc 가 없는 Alpine 에서 돈다.
# `--plugins` 는 `ebury-check/` 를 담은 폴더다(저장소의 `plugins/` 나 내려받아 푼 꾸러미의
# `plugins/`). 컨테이너는 네트워크 없이 돌고 버려진다.
#
# # 무해한가
#
# **실검체는 없다.** 감염 판은 이 하네스가 컨테이너 안에서 짓는 빈 공유 라이브러리다 — 함수
# 하나와 **아무것도 하지 않는 생성자 하나**, 그리고 SONAME `libkeyutils.so.1`. ESET 의 공개 규칙
# `libkeyutils_with_ctor` 가 보는 것이 바로 그 모양(생성자가 하나 더 있다)이다. 정상 판은 같은
# 것에서 생성자만 뺐다. 어느 쪽도 실행되지 않는다(remedy 는 읽기만 한다).
#
# # 무엇을 재나
#
#   A  libkeyutils 자리가 없는 기계(Alpine) — 6
#   B  정상 — 이 컨테이너 그대로 0 · 정상 판을 RHEL 자리에 둬도 0 · 화면에 흔적 0건
#   C  감염 — RHEL 자리(/usr/lib64)에 감염 판 + libkeyutils.so.1 링크를 그쪽으로: 2 · 아무것도
#      바꾸지 않는다 · 결과에 그 파일이 있다 · 디렉터리 읽기를 가로채 그 이름을 숨기는 훅
#      (LD_PRELOAD)을 걸어도 정적 엔진은 2 다(대조군: 동적 링크인 ls 는 속는다). Debian 자리에서도
#      2 — 합친 /usr 에서 몇 경로로 보이는지 센다
#   D  룰 본문이 ESET 공개 파일과 바이트까지 같다 · 매니페스트에 IP 주소 · 해시 꼴이 없다
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=""
PLUGINS=""
OUT=""
INSIDE=0
# ESET 공개 파일(github.com/eset/malware-ioc windigo/ebury.yar)의 SHA-256 — 지표가 아니라 그 파일의
# 신원이다. 룰 본문이 이것과 같으면 룰에는 ESET 이 공개한 값만 있다.
ESET_EBURY_YAR=039a96f19a373140e212358a096d1d8dc9be98844a613aca1377759788c59752
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --plugins) PLUGINS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --inside) INSIDE=1; shift ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

# ── 컨테이너 안 (bookworm) ─────────────────────────────────────────
inside() {
    local R=/remedy P=/plugins O=/out
    local CHECK="$P/ebury-check/plugin.yaml"
    check() {
        if [ "$2" = 1 ]; then printf '  OK   %-52s %s\n' "$1" "$3"
        else printf '  실패 %-52s %s\n' "$1" "$3"; fi
        printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$O/checks.tsv"
    }
    sha() { [ -e "$1" ] && sha256sum "$1" | cut -c1-64 || echo absent; }
    run() { # 이름 · 인자… — 화면은 파일로, 종료 코드는 돌려준다
        local name=$1; shift
        REMEDY_LANG=ko LANG=C.UTF-8 "$R" "$@" --out-dir "/tmp/out-$name" --state-dir /tmp/state \
            >"$O/$name.txt" 2>&1
    }

    # 자리 채우기 — 감염 판과 정상 판은 생성자 하나만 다르다.
    mkdir -p /tmp/fx && cd /tmp/fx || return 9
    printf '%s\n' 'const char remedy_lab_mark[] = "remedy-lab Ebury placeholder - does nothing";' \
        'int remedy_lab_placeholder(void) { return 0; }' >clean.c
    cp clean.c infected.c
    printf '%s\n' '__attribute__((constructor)) static void remedy_lab_ctor(void) {}' >>infected.c
    for f in clean infected; do
        gcc -shared -fPIC -Wl,-soname,libkeyutils.so.1 -o "$f.so" "$f.c" || { echo "gcc 실패: $f"; return 9; }
    done
    cd / || return 9

    echo "── B. 정상 ──"
    local real; real=$(ls /usr/lib/x86_64-linux-gnu/libkeyutils.so.1.* 2>/dev/null | tr '\n' ' ')
    run b1 run --plugin "$CHECK" --dry-run; local c=$?
    check "B1 이 컨테이너 그대로 — 0" "$([ $c = 0 ] && echo 1 || echo 0)" "exit=$c · 배포판 판: ${real:-없음}"
    mkdir -p /usr/lib64   # bookworm 에도 있다(동적 로더) — 없는 기계를 위해서만
    cp /tmp/fx/clean.so /usr/lib64/libkeyutils.so.1.5 && ln -sf libkeyutils.so.1.5 /usr/lib64/libkeyutils.so.1
    run b2 run --plugin "$CHECK" --dry-run; c=$?
    check "B2 정상 판을 RHEL 자리에 — 0" "$([ $c = 0 ] && echo 1 || echo 0)" "exit=$c"
    # 정상 라이브러리가 "흔적" 으로 뜨면 모든 정상 서버가 무언가 찾은 것처럼 보인다 —
    # 본문을 담으려고 둔 경로 규칙이 그렇게 했다(2026-11-06).
    check "B3 정상 화면에 흔적이 없다 (B1 · B2)" \
        "$(grep -q '흔적 0건' "$O/b1.txt" && grep -q '흔적 0건' "$O/b2.txt" && echo 1 || echo 0)" \
        "$(grep -ho '흔적 [0-9]*건' "$O/b1.txt" "$O/b2.txt" | tr '\n' ' ')"

    echo "── C. 감염 ──"
    cp /tmp/fx/infected.so /usr/lib64/libkeyutils.so.1.5.2 && ln -sf libkeyutils.so.1.5.2 /usr/lib64/libkeyutils.so.1
    local i0 k0 l0
    i0=$(sha /usr/lib64/libkeyutils.so.1.5.2); k0=$(sha /usr/lib64/libkeyutils.so.1.5)
    l0=$(readlink /usr/lib64/libkeyutils.so.1)
    run c1 run --plugin "$CHECK" --dry-run; c=$?
    check "C1 RHEL 자리의 감염 — 2 (위협 발견)" "$([ $c = 2 ] && echo 1 || echo 0)" "exit=$c"
    check "C2 아무것도 바꾸지 않는다 (두 파일 · 링크)" \
        "$([ "$(sha /usr/lib64/libkeyutils.so.1.5.2)" = "$i0" ] && [ "$(sha /usr/lib64/libkeyutils.so.1.5)" = "$k0" ] \
            && [ "$(readlink /usr/lib64/libkeyutils.so.1)" = "$l0" ] && echo 1 || echo 0)" ""
    check "C3 결과에 감염 판이 있다" "$(grep -rqs '/usr/lib64/libkeyutils.so.1.5.2' /tmp/out-c1 && echo 1 || echo 0)" ""
    # 훅 — 디렉터리 읽기(readdir)를 가로채 libkeyutils 이름을 숨기는 공유 객체를 LD_PRELOAD 로 건다.
    # 대조군: 동적 링크인 ls 는 속아야 한다(훅이 실제로 듣는다는 증거). 정적 엔진은 로더를 거치지
    # 않으므로 그래도 2 여야 한다.
    printf '%s\n' '#define _GNU_SOURCE' '#include <dirent.h>' '#include <dlfcn.h>' '#include <string.h>' \
        'struct dirent *readdir(DIR *d) { static struct dirent *(*r)(DIR *); struct dirent *e;' \
        '  if (!r) r = dlsym(RTLD_NEXT, "readdir");' \
        '  while ((e = r(d)) && strstr(e->d_name, "libkeyutils")) {} return e; }' \
        'struct dirent64 *readdir64(DIR *d) { static struct dirent64 *(*r)(DIR *); struct dirent64 *e;' \
        '  if (!r) r = dlsym(RTLD_NEXT, "readdir64");' \
        '  while ((e = r(d)) && strstr(e->d_name, "libkeyutils")) {} return e; }' >/tmp/fx/hide.c
    gcc -shared -fPIC -o /tmp/fx/hide.so /tmp/fx/hide.c -ldl || return 9
    local shown hidden
    shown=$(ls /usr/lib64 | grep -c libkeyutils)
    hidden=$(LD_PRELOAD=/tmp/fx/hide.so ls /usr/lib64 | grep -c libkeyutils)
    check "C4 대조군 — 훅을 건 ls 는 libkeyutils 를 못 본다" "$([ "$shown" -gt 0 ] && [ "$hidden" = 0 ] && echo 1 || echo 0)" \
        "훅 없이 ${shown} · 훅 걸고 ${hidden}"
    LD_PRELOAD=/tmp/fx/hide.so run c-hook run --plugin "$CHECK" --dry-run; c=$?
    check "C5 같은 훅을 건 채 정적 엔진 — 그래도 2" "$([ $c = 2 ] && echo 1 || echo 0)" "exit=$c"
    # 놓은 것만 치운다 — bookworm 의 /usr/lib64 에는 동적 로더가 원래 있다.
    rm -f /usr/lib64/libkeyutils.so.1 /usr/lib64/libkeyutils.so.1.5 /usr/lib64/libkeyutils.so.1.5.2
    cp /tmp/fx/infected.so /usr/lib/x86_64-linux-gnu/libkeyutils.so.1.5.2
    run c-deb run --plugin "$CHECK" --dry-run; c=$?
    local seen; seen=$(grep -rhoE '(/usr)?/lib/x86_64-linux-gnu/libkeyutils\.so\.1\.5\.2' /tmp/out-c-deb 2>/dev/null \
        | sort -u | tr '\n' ' ')
    check "C6 Debian 자리의 감염 — 2" "$([ $c = 2 ] && echo 1 || echo 0)" "exit=$c · 결과의 경로: ${seen:-없음}"
    rm -f /usr/lib/x86_64-linux-gnu/libkeyutils.so.1.5.2

    echo "── D. 룰 ──"
    local yar=$P/ebury-check/rules/ebury.yar n body
    n=$(grep -n '^ \*/$' "$yar" | head -1 | cut -d: -f1)
    body=$(tail -n +$((n + 1)) "$yar" | sha256sum | cut -c1-64)
    check "D1 룰 본문이 ESET 공개 파일과 같다" "$([ "$body" = "$ESET_EBURY_YAR" ] && echo 1 || echo 0)" ""
    local leak; leak=$(grep -cE '([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-fA-F]{32,}' "$CHECK")
    check "D2 매니페스트에 IP 주소 · 해시 꼴이 없다" "$([ "$leak" = 0 ] && echo 1 || echo 0)" "줄 ${leak}개"
}

if [ "$INSIDE" = 1 ]; then
    inside
    exit $?
fi

# ── 호스트(WSL) ─────────────────────────────────────────────────────
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/ebury-check/plugin.yaml" ] || { echo "--plugins 에 ebury-check 가 없다: $PLUGINS" >&2; exit 2; }
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/ebury-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
PLUGINS=$(cd "$PLUGINS" && pwd)
BINABS="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
: >"$OUT/checks.tsv"

echo "── A. libkeyutils 자리가 없는 기계 (Alpine) ──"
docker run --rm --network none -v "$BINABS:/remedy:ro" -v "$PLUGINS:/plugins:ro" alpine:3.21 \
    /remedy run --plugin /plugins/ebury-check/plugin.yaml --dry-run --out-dir /tmp/o --state-dir /tmp/s \
    >"$OUT/a1.txt" 2>&1
c=$?
if [ $c = 6 ]; then ok=1; printf '  OK   %-52s %s\n' "A1 점검이 6 으로 끝난다 (자리 없음)" "exit=$c"
else ok=0; printf '  실패 %-52s %s\n' "A1 점검이 6 으로 끝난다 (자리 없음)" "exit=$c"; fi
printf '%s\t%s\t%s\n' "A1 점검이 6 으로 끝난다 (자리 없음)" "$ok" "exit=$c" >>"$OUT/checks.tsv"

docker run --rm --network none \
    -v "$BINABS:/remedy:ro" \
    -v "$PLUGINS:/plugins:ro" \
    -v "$HERE/$(basename "$0"):/verify.sh:ro" \
    -v "$OUT:/out" \
    rust:1.96-bookworm bash /verify.sh --inside | tee "$OUT/inside.txt"
inner=${PIPESTATUS[0]}

# 칸 수까지 본다 — 안쪽이 중간에 멈추면 남은 칸이 조용히 사라지고 "실패 0" 이 남는다(2026-11-06 에
# 실제로 그랬다 — 훅이 컴파일되지 않아 여섯 칸만 돌고 통과로 끝났다).
EXPECTED=12
pass=$(awk -F'\t' '$2 == 1' "$OUT/checks.tsv" | wc -l)
fail=$(awk -F'\t' '$2 != 1' "$OUT/checks.tsv" | wc -l)
echo
echo "통과 $pass · 실패 $fail  (전체 $((pass + fail)) / 기대 $EXPECTED · 안쪽 종료 $inner)" | tee "$OUT/verdict.txt"
[ "$fail" = 0 ] && [ "$inner" = 0 ] && [ "$((pass + fail))" = "$EXPECTED" ]
