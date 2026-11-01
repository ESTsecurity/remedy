#!/bin/bash
# P12 — systemd 가 되살리는 데몬을 치료가 끝까지 멈추는가 (게스트 쪽 · 리눅스 랩 VM).
#
# 리눅스 백엔드는 `systemctl` 을 부르지 않는다. 서비스를 끄고 지우는 일은 유닛 파일과
# 링크를 지우는 것이고, 돌고 있는 것을 멈추는 일은 `process.kill` 이 한다
# (`remedy-sdk` catalog 의 `service.stop` 주석). 그런데 systemd 는 `Restart=` 가 걸린
# 유닛의 주 프로세스가 죽으면 **메모리에 올린 정의로** 다시 띄운다. 컨테이너는
# systemd 가 PID 1 이 아니라 이것을 잴 수 없다 (`invoke-linux-verify.sh` 머리).
#
# 여기서는 **무해한 데몬** — `/usr/bin/sleep` 의 사본 — 을 `Restart=` 유닛으로 띄우고,
# 실험 플러그인(`restart-plugin.yaml`)으로 치료한 뒤 무엇이 남는지 본다.
#
# # 회차 (`--scenario`)
#
#   fast   Restart=always · RestartSec 기본값(100ms) — 실행기의 재평가(300ms) 안에 되살아난다
#   slow   Restart=always · RestartSec=3            — 재평가가 끝난 뒤에 되살아난다
#   none   Restart= 없음 (기본값 no)                 — 대조군. 되살아날 것이 없다
#   refuse Restart=always · RefuseManualStop=yes     — 정지 요청이 거부된다 (결정 A 뒤).
#          치료가 그것을 실패로 알리고, "치료 완료" 라고 말하지 않는가를 본다
#
# # 재는 것
#
#   before (치료 · 재부팅 전)
#     0    systemd 가 PID 1 · 가상 머신 · 시작 전에 픽스처가 없다
#     1    픽스처 데몬이 돈다 — 유닛이 active · 주 프로세스가 픽스처 실행 파일 · 회차의 설정
#     2    치료가 돌았다 — 종료 1·3 · 계획에 process.kill · service.disable · service.delete
#     3    관찰 창(15초) 끝에 데몬이 돌지 않는다
#     4    "치료 완료"(종료 1)라고 했다면 데몬이 없다 — 보고가 실제와 맞는다
#     5    데몬의 실행 파일이 제자리에 없다
#     잰 값 — 종료 코드 · 계획의 Op · 미룬 Op · 수행/실패 줄 · 종료→재기동 간격 · NRestarts
#   after (재부팅 뒤)
#     6    실제로 재부팅했다 — boot_id 가 바뀌었다
#     7    재부팅 뒤 데몬이 돌지 않는다
#     잰 값 — 유닛의 LoadState · 실행 파일이 남았는가 · 이번 부팅의 유닛 저널
#
# 0–2 · 6 은 **여기가 재는 자리인가**다(`site`). 하나라도 어긋나면 종료 2(못잼)다.
# 3–5 · 7 은 **잰 성질**이다(`prop`). 실패는 하네스의 고장이 아니라 실측이다(종료 1).
# **못 잰 것은 통과가 아니다** (`verify-linux.sh` 와 같은 규칙).
#
# # 쓰는 법 (VM 안, root)
#
#     restart-verify.sh before --scenario fast|slow|none|refuse --bin /usr/local/bin/remedy --plugin <restart-plugin.yaml>
#     systemctl reboot
#     restart-verify.sh after
#
# 호스트에서는 `invoke-restart-verify.sh` 가 회차마다 VM 을 되돌린 뒤 이것을 두 번 부른다.

set -u
# 이 스크립트는 한국어 문구를 읽는다. 기본 언어는 영어다 (2026-09-06).
export REMEDY_LANG=ko

# 재부팅을 넘어 남아야 한다. `/tmp` 는 배포판에 따라 tmpfs 라 부팅 때 비워진다.
WORK=/var/tmp/remedy-restart
STATE="$WORK/state"
# 실험 플러그인(`restart-plugin.yaml`)이 조준하는 자리. 둘이 함께 바뀌어야 한다.
FIX_DIR=/opt/remedy-lab/restart
FIX_BIN="$FIX_DIR/fixtured"
UNIT_NAME=remedy-lab-restart.service
UNIT="/etc/systemd/system/$UNIT_NAME"
LINK="/etc/systemd/system/multi-user.target.wants/$UNIT_NAME"
# 치료가 끝난 뒤 지켜보는 시간. `slow` 의 RestartSec(3초)보다 넉넉해야 한다.
WINDOW=15

PASS=0
FAIL=0
UNMEASURED=0
SITE_BAD=0
CHECKS=""

die() { echo "restart-verify: $*" >&2; exit 2; }

# check <site|prop> <이름> <1|0|-> <자세히>
check() {
    local kind="$1" name="$2" ok="$3" detail="$4"
    case "$ok" in
        1) PASS=$((PASS + 1)); printf '  \033[32mOK\033[0m   %-46s %s\n' "$name" "$detail" ;;
        -) UNMEASURED=$((UNMEASURED + 1))
           printf '  \033[33m못잼\033[0m %-46s %s\n' "$name" "$detail" ;;
        *) FAIL=$((FAIL + 1)); printf '  \033[31m실패\033[0m %-46s %s\n' "$name" "$detail" ;;
    esac
    if [ "$kind" = site ] && [ "$ok" != 1 ]; then
        SITE_BAD=$((SITE_BAD + 1))
    fi
    printf '%s\t%s\t%s\t%s\n' "$kind" "$name" "$ok" "$(printf '%s' "$detail" | tr '\t\n' '  ')" >> "$CHECKS"
}

# 잰 값. 판정이 아니므로 통과·실패를 세지 않는다.
measure() {
    printf '  잰값 %-46s %s\n' "$1" "$2"
    printf '%s\t%s\n' "$1" "$(printf '%s' "$2" | tr '\t\n' '  ')" >> "$WORK/.measure"
}

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# `ok` 는 true · false · null(못잼) 이다 — `reboot-verify.sh` 와 같은 모양에 `kind` 를 더했다.
write_result() {
    local phase="$1" out="$WORK/result-$1.json" first=1 k n o d ob
    {
        printf '{\n  "schema": "remedy-restart-verify/1",\n  "phase": "%s",\n' "$phase"
        printf '  "scenario": "%s",\n' "$(json_escape "$(cat "$WORK/scenario" 2>/dev/null)")"
        printf '  "host": "%s",\n  "checks": [\n' "$(json_escape "$(hostname) $(uname -sr)")"
        while IFS=$'\t' read -r k n o d; do
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            case "$o" in 1) ob=true ;; -) ob=null ;; *) ob=false ;; esac
            printf '    { "kind": "%s", "name": "%s", "ok": %s, "detail": "%s" }' \
                "$k" "$(json_escape "$n")" "$ob" "$(json_escape "$d")"
        done < "$CHECKS"
        printf '\n  ]'
        if [ -s "$WORK/.measure" ]; then
            printf ',\n  "measurements": {\n'
            first=1
            while IFS=$'\t' read -r n d; do
                [ "$first" -eq 1 ] || printf ',\n'
                first=0
                printf '    "%s": "%s"' "$(json_escape "$n")" "$(json_escape "$d")"
            done < "$WORK/.measure"
            printf '\n  }'
        fi
        printf '\n}\n'
    } > "$out"
    rm -f "$CHECKS" "$WORK/.measure"
    echo
    echo "통과 $PASS · 실패 $FAIL · 못잼 $UNMEASURED  (전체 $((PASS + FAIL + UNMEASURED)))"
    [ "$UNMEASURED" -gt 0 ] && echo "  ** 못 잰 것은 통과가 아니다."
    echo "결과: $out"
}

# 2 = 재는 자리가 아니다(또는 못 잰 것이 있다) · 1 = 잰 성질이 깨졌다 · 0 = 전부 통과.
verdict_exit() {
    [ "$SITE_BAD" -eq 0 ] && [ "$UNMEASURED" -eq 0 ] || exit 2
    [ "$FAIL" -eq 0 ] || exit 1
    exit 0
}

uprop() { systemctl show "$UNIT_NAME" -p "$1" --value 2>/dev/null; }

# 픽스처 실행 파일로 도는 PID 들. 실행 파일이 지워졌으면 커널이 ` (deleted)` 를 붙인다.
fixture_pids() {
    local p l out=""
    for p in /proc/[0-9]*; do
        l="$(readlink "$p/exe" 2>/dev/null)" || continue
        case "$l" in
            "$FIX_BIN" | "$FIX_BIN (deleted)") out="$out ${p#/proc/}" ;;
        esac
    done
    printf '%s' "${out# }"
}

sample() {
    printf '%s\tactive=%s/%s\tmainpid=%s\tnrestarts=%s\tload=%s\treload=%s\tpids=%s\n' \
        "$1" "$(uprop ActiveState)" "$(uprop SubState)" "$(uprop MainPID)" \
        "$(uprop NRestarts)" "$(uprop LoadState)" "$(uprop NeedDaemonReload)" \
        "$(fixture_pids)" >> "$WORK/timeline.txt"
}

# 계획의 `actions` 나 `deferred` 배열 안의 op 들. `plan.json` 은 두 칸 들여쓰기로 적힌다.
plan_ops() {
    awk -v key="\"$1\": [" '
        index($0, "  " key) == 1 { on = 1; if ($0 ~ /\[\],?$/) exit; next }
        on && /^  \]/ { exit }
        on && /^      "op": / { gsub(/.*"op": "|".*/, ""); printf "%s ", $0 }
    ' "$WORK/run/plan.json" 2>/dev/null
}

# 종료 → 재기동 간격. `journalctl -o short-monotonic` 의 줄 머리(`[  12.345678]`)로 잰다.
restart_gap() {
    awk '
        { t = substr($0, 2, index($0, "]") - 2) + 0 }
        /Main process exited, code=killed/ && !k { k = t; next }
        k && /Started / { printf "%.1f ms", (t - k) * 1000; found = 1; exit }
        END { if (!k) print "종료가 저널에 없다"; else if (!found) print "재기동 없음" }
    ' "$1"
}

write_unit() {
    printf '[Unit]\nDescription=remedy lab restart fixture (harmless copy of sleep)\n'
    # `RefuseManualStop=` 는 [Unit] 의 설정이다.
    if [ "$1" = refuse ]; then
        printf 'RefuseManualStop=yes\n'
    fi
    printf '\n[Service]\nExecStart=%s infinity\n' "$FIX_BIN"
    case "$1" in
        fast | refuse) printf 'Restart=always\n' ;;
        slow) printf 'Restart=always\nRestartSec=3\n' ;;
        none) ;;
    esac
    printf '\n[Install]\nWantedBy=multi-user.target\n'
}

# ─────────────────────────────────────────── 치료 · 재부팅 전

before() {
    local scenario="" bin="" plugin=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --scenario) scenario="${2:-}"; shift 2 ;;
            --bin)      bin="${2:-}"; shift 2 ;;
            --plugin)   plugin="${2:-}"; shift 2 ;;
            *) die "모르는 인자: $1" ;;
        esac
    done
    case "$scenario" in
        fast|slow|none|refuse) ;;
        *) die "--scenario 는 fast · slow · none · refuse 중 하나다: $scenario" ;;
    esac
    [ -n "$bin" ] && [ -x "$bin" ] || die "--bin 이 실행 파일이 아니다: $bin"
    [ -n "$plugin" ] && [ -f "$plugin" ] || die "--plugin 이 없다: $plugin"
    [ "$(id -u)" -eq 0 ] || die "root 로 돌아야 한다"

    rm -rf "$WORK"
    mkdir -p "$WORK"
    CHECKS="$WORK/.checks"
    : > "$CHECKS"
    printf '%s\n' "$scenario" > "$WORK/scenario"
    echo "[*] 치료 전 — $(hostname) · $(uname -sr) · 회차 $scenario"

    # ── 0. 여기가 재는 자리인가 ──────────────────────────────────
    local pid1 virt left=""
    pid1="$(cat /proc/1/comm 2>/dev/null)"
    if [ -d /run/systemd/system ] && [ "$pid1" = systemd ]; then
        check site "0 systemd 가 PID 1 이다" 1 "/proc/1/comm=$pid1 · $(systemctl --version | head -1)"
    else
        check site "0 systemd 가 PID 1 이다" 0 "/proc/1/comm=${pid1:-?} — 이 기계에서는 되살림을 잴 수 없다"
    fi
    virt="$(systemd-detect-virt 2>/dev/null || true)"
    case "$virt" in
        vmware|kvm|qemu|oracle|microsoft|xen) check site "0b 가상 머신이다 (컨테이너가 아니다)" 1 "$virt" ;;
        *) check site "0b 가상 머신이다 (컨테이너가 아니다)" 0 "systemd-detect-virt=${virt:-없음}" ;;
    esac
    [ -e "$UNIT" ] && left="$left 유닛"
    [ -L "$LINK" ] && left="$left 링크"
    [ -e "$FIX_DIR" ] && left="$left 픽스처"
    [ "$(uprop LoadState)" = not-found ] || left="$left 메모리의유닛($(uprop LoadState))"
    if [ -z "$left" ]; then
        check site "0c 시작 전에 픽스처가 없다" 1 "없다"
    else
        check site "0c 시작 전에 픽스처가 없다" 0 "이미 있다:$left — 스냅숏이 깨끗하지 않다"
    fi
    cat /proc/sys/kernel/random/boot_id > "$WORK/boot-id-before"

    # ── 1. 픽스처 데몬을 띄운다 ──────────────────────────────────
    #
    # 유닛을 띄우는 것은 **하네스**다. 제품이 `systemctl` 을 부르지 않는 것과 무관하다.
    install -d -m 755 "$FIX_DIR"
    install -m 755 /usr/bin/sleep "$FIX_BIN"
    write_unit "$scenario" > "$UNIT"
    cp "$UNIT" "$WORK/unit.service"
    {
        systemctl daemon-reload
        systemctl enable "$UNIT_NAME"
        systemctl start "$UNIT_NAME"
    } > "$WORK/fixture-start.txt" 2>&1
    local i main exe want_restart want_usec
    for i in 1 2 3 4 5 6 7 8 9 10; do
        main="$(uprop MainPID)"
        [ "${main:-0}" -gt 0 ] && [ -n "$(fixture_pids)" ] && break
        sleep 0.5
    done
    exe="$(readlink "/proc/${main:-0}/exe" 2>/dev/null)"
    if [ "$(uprop ActiveState)" = active ] && [ "$exe" = "$FIX_BIN" ] && [ -L "$LINK" ]; then
        check site "1 픽스처 데몬이 돈다" 1 "MainPID=$main · $exe · 링크 있음"
    else
        check site "1 픽스처 데몬이 돈다" 0 \
            "ActiveState=$(uprop ActiveState) MainPID=${main:-?} exe=${exe:-?} 링크=$([ -L "$LINK" ] && echo 있다 || echo 없다) — $WORK/fixture-start.txt"
    fi
    case "$scenario" in
        fast) want_restart=always; want_usec=100ms ;;
        slow) want_restart=always; want_usec=3s ;;
        none) want_restart=no; want_usec=100ms ;;
        refuse) want_restart=always; want_usec=100ms ;;
    esac
    local want_refuse=no
    [ "$scenario" = refuse ] && want_refuse=yes
    if [ "$(uprop Restart)" = "$want_restart" ] && [ "$(uprop RestartUSec)" = "$want_usec" ] \
        && [ "$(uprop RefuseManualStop)" = "$want_refuse" ]; then
        check site "1b 유닛의 재시작 설정이 회차와 같다" 1 \
            "Restart=$want_restart · RestartUSec=$want_usec · RefuseManualStop=$want_refuse"
    else
        check site "1b 유닛의 재시작 설정이 회차와 같다" 0 \
            "Restart=$(uprop Restart) RestartUSec=$(uprop RestartUSec) RefuseManualStop=$(uprop RefuseManualStop) — 기대 $want_restart · $want_usec · $want_refuse"
    fi
    measure "치료 전 NRestarts" "$(uprop NRestarts)"
    if [ "$SITE_BAD" -gt 0 ]; then
        echo "  ** 재는 자리가 아니다 — 치료하지 않는다."
        write_result before
        verdict_exit
    fi

    # ── 2. 치료 ─────────────────────────────────────────────────
    local t0 t1 rc ops deferred lines
    t0="$(date +%s%N)"
    "$bin" run --plugin "$plugin" --yes --state-dir "$STATE" --out-dir "$WORK/run" \
        > "$WORK/run.txt" 2>&1
    rc=$?
    t1="$(date +%s%N)"
    # **곧바로 지켜본다.** `slow` 의 되살림은 치료가 끝난 뒤에 온다.
    : > "$WORK/timeline.txt"
    for i in $(seq 0 "$WINDOW"); do
        sample "+${i}s"
        [ "$i" -lt "$WINDOW" ] && sleep 1
    done
    systemctl show "$UNIT_NAME" > "$WORK/unit-show-after-run.txt" 2>&1
    journalctl -u "$UNIT_NAME" -b -o short-monotonic --no-pager > "$WORK/journal-unit.txt" 2>&1

    ops="$(plan_ops actions)"
    deferred="$(plan_ops deferred)"
    local want missing=""
    for want in process.kill service.disable service.delete; do
        case " $ops" in *" $want "*) ;; *) missing="$missing $want" ;; esac
    done
    if [ "$rc" != 1 ] && [ "$rc" != 3 ]; then
        check site "2 치료가 돌았다" 0 "exit=$rc — $WORK/run.txt"
    elif [ -n "$missing" ]; then
        check site "2 치료가 돌았다" 0 "계획에 없다:$missing · 계획: ${ops:-없다}"
    else
        check site "2 치료가 돌았다" 1 "exit=$rc · 계획: $ops"
    fi
    measure "종료 코드" "$rc"
    measure "계획의 Op (차례대로)" "${ops:-없다}"
    measure "미룬 Op" "${deferred:-없다}"
    lines="$(grep -E '^  (수행|실패) \[' "$WORK/run.txt" | sed 's/^  //' | tr '\n' '|' | sed 's/|$//; s/|/ | /g')"
    measure "수행/실패 줄" "${lines:-없다}"
    measure "치료에 걸린 시간" "$(( (t1 - t0) / 1000000 )) ms"

    measure "종료 → 재기동 (systemd 저널)" "$(restart_gap "$WORK/journal-unit.txt")"
    measure "관찰 창 끝 NRestarts" "$(uprop NRestarts)"
    measure "관찰 창 끝 유닛" "ActiveState=$(uprop ActiveState)/$(uprop SubState) · LoadState=$(uprop LoadState) · NeedDaemonReload=$(uprop NeedDaemonReload)"
    measure "유닛 파일 · 링크" "유닛=$([ -e "$UNIT" ] && echo 있다 || echo 없다) · 링크=$([ -L "$LINK" ] && echo 있다 || echo 없다)"

    # ── 3–5. 잰 성질 ────────────────────────────────────────────
    local pids
    pids="$(fixture_pids)"
    if [ -z "$pids" ]; then
        check prop "3 관찰 창(${WINDOW}초) 끝에 데몬이 돌지 않는다" 1 "없다"
    else
        check prop "3 관찰 창(${WINDOW}초) 끝에 데몬이 돌지 않는다" 0 \
            "돈다: PID $pids · $(readlink "/proc/${pids%% *}/exe" 2>/dev/null)"
    fi
    case "$rc" in
        1)
            if [ -z "$pids" ]; then
                check prop "4 치료 완료라고 했다면 데몬이 없다" 1 "exit=1 · 데몬 없음"
            else
                check prop "4 치료 완료라고 했다면 데몬이 없다" 0 "exit=1(치료 완료)인데 데몬이 돈다"
            fi
            ;;
        3) check prop "4 치료 완료라고 했다면 데몬이 없다" 1 "exit=3 — 부분 실패로 보고했다" ;;
        *) check prop "4 치료 완료라고 했다면 데몬이 없다" - "치료가 돌지 않아 잴 수 없다" ;;
    esac
    if [ -e "$FIX_BIN" ]; then
        check prop "5 데몬의 실행 파일이 제자리에 없다" 0 "남았다: $FIX_BIN"
    else
        check prop "5 데몬의 실행 파일이 제자리에 없다" 1 "없다"
    fi

    write_result before
    verdict_exit
}

# ─────────────────────────────────────────── 재부팅 뒤

after() {
    [ $# -eq 0 ] || die "after 는 인자를 받지 않는다: $*"
    [ "$(id -u)" -eq 0 ] || die "root 로 돌아야 한다"
    [ -f "$WORK/boot-id-before" ] || die "before 를 먼저 돌려야 한다 — $WORK/boot-id-before 가 없다"
    CHECKS="$WORK/.checks"
    : > "$CHECKS"
    : > "$WORK/.measure"
    echo "[*] 재부팅 뒤 — $(hostname) · 회차 $(cat "$WORK/scenario" 2>/dev/null)"

    # ── 6. 실제로 재부팅했다 ─────────────────────────────────────
    if [ "$(cat "$WORK/boot-id-before")" != "$(cat /proc/sys/kernel/random/boot_id)" ]; then
        check site "6 실제로 재부팅했다" 1 "boot_id 가 바뀌었다"
    else
        check site "6 실제로 재부팅했다" 0 "boot_id 가 그대로다 — 재부팅하지 않았다"
    fi

    # ── 7. 재부팅 뒤 데몬이 돌지 않는다 ──────────────────────────
    local pids
    pids="$(fixture_pids)"
    if [ -z "$pids" ]; then
        check prop "7 재부팅 뒤 데몬이 돌지 않는다" 1 "없다"
    else
        check prop "7 재부팅 뒤 데몬이 돌지 않는다" 0 "돈다: PID $pids"
    fi
    measure "유닛" "LoadState=$(uprop LoadState) · ActiveState=$(uprop ActiveState)"
    measure "실행 파일" "$([ -e "$FIX_BIN" ] && echo "남았다: $FIX_BIN" || echo 없다)"
    journalctl -u "$UNIT_NAME" -b -o short-monotonic --no-pager > "$WORK/journal-unit-after.txt" 2>&1
    measure "이번 부팅의 유닛 저널" "$(grep -cv '^-- ' "$WORK/journal-unit-after.txt")줄"

    write_result after
    verdict_exit
}

case "${1:-}" in
    before) shift; before "$@" ;;
    after)  shift; after "$@" ;;
    *) die "쓰는 법: restart-verify.sh before --scenario fast|slow|none|refuse --bin <remedy> --plugin <yaml> | after" ;;
esac
