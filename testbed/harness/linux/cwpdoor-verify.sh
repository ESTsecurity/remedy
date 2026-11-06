#!/bin/bash
# CWPdoor 두 꾸러미(cwpdoor-1-check · cwpdoor-2-clean)를 리눅스 컨테이너에서 잰다.
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/cwpdoor-verify.sh --bin <remedy> --plugins <두 꾸러미가 든 폴더> \
#        [--out <결과 폴더>]
#
# `--plugins` 는 `cwpdoor-1-check/` · `cwpdoor-2-clean/` 을 담은 폴더다 — 저장소의 `plugins/`
# 이거나 내려받아 푼 위협 꾸러미의 `plugins/` 다. 컨테이너는 네트워크 없이 돌고 버려진다.
#
# # 무해한가
#
# **실검체는 없다.** 감염된 `cwpsrv` 는 ELF 머리 네 바이트 + 표시 문자열 + 공개 지표(XLab
# 보고의 활성화 헤더 셋과, 0x55 로 XOR 한 공격자 공개키) + 0 패딩이다. 실행되지 않고 아무것도
# 하지 않는다. 유닛 파일도 이 하네스가 지어낸 자리 채우기다(공급사 파일이 아니다).
#
# # 무엇을 재나
#
#   A  CWP 가 없는 기계 — 점검은 6(선언한 자리가 전부 없으면 위협 플러그인은 6)
#   B  정상 CWP — 점검 0 · 치료 0 · 아무것도 바뀌지 않는다
#   C  감염 CWP — 점검 2 · 그대로 · 치료 1(격리 · 유닛 비활성화와 삭제 · 백업은 남는다) ·
#      치료 뒤 다시 점검 · 복원 0(바이너리 · 유닛이 같은 바이트로 돌아온다)
#   D  룰에 IP 주소 · 해시가 없다 — 공개 보도에 없는 지표(드로퍼 해시 등)를 싣지 않는다
#
# 서비스 **중지의 효과**는 여기서 재지 못한다 — 계획에 들고 수행도 되지만, 컨테이너에는
# systemd 가 PID 1 이 아니어서 멈출 패널이 돌고 있지 않다.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=""
PLUGINS=""
OUT=""
INSIDE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --plugins) PLUGINS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --inside) INSIDE=1; shift ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

# ── 컨테이너 안 ────────────────────────────────────────────────────
inside() {
    local R=/remedy P=/plugins O=/out
    local CHECK="$P/cwpdoor-1-check/plugin.yaml" CLEAN="$P/cwpdoor-2-clean/plugin.yaml"
    local PASS=0 FAIL=0
    : >"$O/checks.tsv"
    check() {
        if [ "$2" = 1 ]; then PASS=$((PASS + 1)); printf '  OK   %-52s %s\n' "$1" "$3"
        else FAIL=$((FAIL + 1)); printf '  실패 %-52s %s\n' "$1" "$3"; fi
        printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$O/checks.tsv"
    }
    sha() { [ -e "$1" ] && sha256sum "$1" | cut -c1-64 || echo absent; }
    run() { # 이름 · 인자… — 화면은 파일로, 종료 코드는 돌려준다
        local name=$1; shift
        REMEDY_LANG=ko LANG=C.UTF-8 "$R" "$@" --out-dir "/tmp/out-$name" --state-dir /tmp/state \
            >"$O/$name.txt" 2>&1
    }

    # 자리 채우기 — 감염 판은 공개 지표를 담고, 정상 판 · 백업은 담지 않는다.
    python3 - <<'PY'
import os
pem = open("/fixtures/pubkey.pem", "rb").read()
x55 = bytes(b ^ 0x55 for b in pem)
head = b"\x7fELF\x02\x01\x01" + b"\0" * 57
mark = b"remedy-lab CWPdoor placeholder - not a program\0"
infected = head + mark + b"\0" * 4096 + b"X-Ngx-Integrity-Data\0X-Ngx-Integrity-Time\0X-Ngx-Integrity-Sig\0" \
    + b"\0" * 4096 + x55 + b"\0" * 4096
clean = head + b"remedy-lab clean cwpsrv placeholder\0" + b"\0" * 12288
os.makedirs("/tmp/fx", exist_ok=True)
open("/tmp/fx/infected", "wb").write(infected.ljust(820848, b"\0"))
open("/tmp/fx/clean", "wb").write(clean.ljust(820848, b"\0"))
PY
    unit() {
        mkdir -p /lib/systemd/system /etc/systemd/system/multi-user.target.wants
        printf '%s\n' "[Unit]" "Description=remedy-lab CWP panel placeholder" "[Service]" \
            "Type=forking" "ExecStart=/usr/local/cwpsrv/bin/cwpsrv" "Restart=always" "RestartSec=5" \
            "[Install]" "WantedBy=multi-user.target" >/lib/systemd/system/cwpsrv.service
        ln -sf /lib/systemd/system/cwpsrv.service /etc/systemd/system/multi-user.target.wants/cwpsrv.service
    }
    local BK=/usr/local/cwpsrv/bin/cwpsrv.prev-20260629-101530

    echo "── A. CWP 가 없는 기계 ──"
    run a-check run --plugin "$CHECK" --dry-run; local c=$?
    check "A1 점검이 6 으로 끝난다 (CWP 없음)" "$([ $c = 6 ] && echo 1 || echo 0)" "exit=$c"

    echo "── B. 정상 CWP ──"
    mkdir -p /usr/local/cwpsrv/bin && cp /tmp/fx/clean /usr/local/cwpsrv/bin/cwpsrv && unit
    local b0; b0=$(sha /usr/local/cwpsrv/bin/cwpsrv)
    run b-check run --plugin "$CHECK" --dry-run; c=$?
    check "B1 점검이 0 이다" "$([ $c = 0 ] && echo 1 || echo 0)" "exit=$c"
    run b-clean run --plugin "$CLEAN" --yes; c=$?
    check "B2 치료도 0 이다 (위협 없음)" "$([ $c = 0 ] && echo 1 || echo 0)" "exit=$c"
    check "B3 정상 판 · 유닛이 그대로다" \
        "$([ "$(sha /usr/local/cwpsrv/bin/cwpsrv)" = "$b0" ] && [ -e /lib/systemd/system/cwpsrv.service ] && echo 1 || echo 0)" ""

    echo "── C. 감염 CWP ──"
    cp /tmp/fx/infected /usr/local/cwpsrv/bin/cwpsrv && cp /tmp/fx/clean "$BK" && unit
    local i0 k0 u0; i0=$(sha /usr/local/cwpsrv/bin/cwpsrv); k0=$(sha "$BK"); u0=$(sha /lib/systemd/system/cwpsrv.service)
    run c-check run --plugin "$CHECK" --dry-run; c=$?
    check "C1 점검이 2 다 (위협 발견)" "$([ $c = 2 ] && echo 1 || echo 0)" "exit=$c"
    check "C2 점검은 아무것도 바꾸지 않는다" \
        "$([ "$(sha /usr/local/cwpsrv/bin/cwpsrv)" = "$i0" ] && [ -e /lib/systemd/system/cwpsrv.service ] && echo 1 || echo 0)" ""
    check "C3 백업을 흔적으로 남긴다 (scan.json)" "$(grep -rqs 'cwpsrv.prev-20260629-101530' /tmp/out-c-check && echo 1 || echo 0)" ""
    run c-clean run --plugin "$CLEAN" --yes; c=$?
    check "C4 치료가 1 로 끝난다" "$([ $c = 1 ] && echo 1 || echo 0)" "exit=$c"
    check "C5 백도어 바이너리가 없어졌다 (격리)" "$([ ! -e /usr/local/cwpsrv/bin/cwpsrv ] && echo 1 || echo 0)" ""
    check "C6 유닛과 wants 링크가 없어졌다" \
        "$([ ! -e /lib/systemd/system/cwpsrv.service ] && [ ! -L /etc/systemd/system/multi-user.target.wants/cwpsrv.service ] && echo 1 || echo 0)" ""
    check "C7 원래 바이너리의 사본(백업)은 남았다" "$([ "$(sha "$BK")" = "$k0" ] && echo 1 || echo 0)" ""
    local runid; runid=$(grep -o 'run-[0-9]*-[0-9a-f]*-[0-9a-f]*' "$O/c-clean.txt" | head -1)
    check "C8 회차를 안다" "$([ -n "$runid" ] && echo 1 || echo 0)" "${runid:-없음}"
    run c-recheck run --plugin "$CHECK" --dry-run; c=$?
    check "C9 치료 뒤 다시 점검 — 위협이 없다 (0 또는 6)" "$([ $c = 0 ] || [ $c = 6 ] && echo 1 || echo 0)" "exit=$c"
    REMEDY_LANG=ko LANG=C.UTF-8 "$R" restore --run "$runid" --yes --state-dir /tmp/state >"$O/c-restore.txt" 2>&1; c=$?
    check "C10 복원이 0 으로 끝난다" "$([ $c = 0 ] && echo 1 || echo 0)" "exit=$c"
    check "C11 바이너리 · 유닛이 같은 바이트로 돌아왔다" \
        "$([ "$(sha /usr/local/cwpsrv/bin/cwpsrv)" = "$i0" ] && [ "$(sha /lib/systemd/system/cwpsrv.service)" = "$u0" ] && echo 1 || echo 0)" ""

    echo "── D. 비공개 지표 ──"
    # 값을 적지 않고 꼴로 본다 — 지표를 여기 적으면 이 파일이 그것을 싣는다. MANIFEST 는 파일
    # 해시를 담으므로 룰(plugin.yaml · rules/*.yar)만 본다.
    local leak; leak=$(grep -lE '([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-fA-F]{32,}' \
        "$P"/*/plugin.yaml "$P"/*/rules/*.yar 2>/dev/null | wc -l)
    check "D1 룰에 IP 주소 · 해시 꼴 문자열이 없다" "$([ "$leak" = 0 ] && echo 1 || echo 0)" "파일 ${leak}개"

    echo
    echo "통과 $PASS · 실패 $FAIL  (전체 $((PASS + FAIL)))"
    [ "$FAIL" = 0 ]
}

if [ "$INSIDE" = 1 ]; then
    inside
    exit $?
fi

# ── 호스트(WSL) ─────────────────────────────────────────────────────
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/cwpdoor-1-check/plugin.yaml" ] && [ -f "$PLUGINS/cwpdoor-2-clean/plugin.yaml" ] \
    || { echo "--plugins 에 cwpdoor-1-check · cwpdoor-2-clean 이 없다: $PLUGINS" >&2; exit 2; }
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/cwpdoor-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
PLUGINS=$(cd "$PLUGINS" && pwd)
# 공개키는 이 하네스의 fixtures 자리에 둔다 — XLab 보고가 실은 PEM 그대로다.
docker run --rm --network none \
    -v "$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN"):/remedy:ro" \
    -v "$PLUGINS:/plugins:ro" \
    -v "$HERE/fixtures/cwpdoor:/fixtures:ro" \
    -v "$HERE/$(basename "$0"):/verify.sh:ro" \
    -v "$OUT:/out" \
    rust:1.96-bookworm bash /verify.sh --inside | tee "$OUT/verdict.txt"
exit "${PIPESTATUS[0]}"
