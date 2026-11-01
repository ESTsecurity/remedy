#!/bin/bash
# P12 P7 — 재부팅 뒤 재검사가 **진짜 systemd 부팅에서** 도는가 (게스트 쪽).
#
# 설계-03 §8 의 약속은 *"재부팅 뒤 한 번 verify 가 돌고, 흔적이 남지 않는다"* 다.
# 컨테이너는 systemd 가 init 이 아니어서 이것을 재지 못한다 — P3·P4 는 유닛의 두
# 줄을 손으로 돌렸다(모의 부팅). 여기서는 VM 을 실제로 재부팅하고 systemd 가
# 부팅 때 무엇을 했는지 본다. Windows 쪽 `host/Invoke-P10FVerify.ps1` 의 짝이다.
#
# # 재는 것
#
#   before (재부팅 전)
#     0   systemd 가 PID 1 이고 · 가상 머신이며 · 시작 전에 우리 예약이 없다
#     1   예약이 심겼다 — 유닛 파일과 활성화 링크
#     2   유닛이 실행 직전에 자기를 지우는 줄을 갖는다 (자기 흔적 규칙 2)
#     3   유닛의 명령이 감사 로그 End 바로 앞에 적혔다 (규칙 3) · 언어를 싣는다
#   after (재부팅 뒤)
#     4   실제로 재부팅했다 — boot_id 가 바뀌었다
#     5   유닛과 링크가 둘 다 없다 (규칙 2) · 바꿔 끼우던 임시 파일도 없다
#     6   systemd 가 이번 부팅에 그 유닛을 돌렸고 성공으로 끝났다 — 저널
#     7   재평가 판정이 남았다 — verify/<run>.jsonl (clean · 종료 0)
#     8   재부팅 회차의 화면이 회차 로그에 남았다 · 같은 언어 · 크래시 없음
#     잰 값 (판정 아님) — 부팅 시간과 그중 재평가가 쓴 시간 (P12 메모 §7)
#
# 판정은 셋이다 — 통과 · 실패 · 못잼 (`verify-linux.sh` 와 같은 규칙).
# **못 잰 것은 통과가 아니다.**
#
# # 쓰는 법 (VM 안, root)
#
#     reboot-verify.sh before --bin /usr/local/bin/remedy --plugin <p7-plugin.yaml>
#     systemctl reboot
#     reboot-verify.sh after
#
# 호스트에서는 `invoke-reboot-verify.sh` 가 VM 을 되돌린 뒤 이것을 두 번 부른다.

set -u
# 이 스크립트는 한국어 문구를 읽는다. 기본 언어는 영어다 (2026-09-06).
export REMEDY_LANG=ko

# 재부팅을 넘어 남아야 한다. `/tmp` 는 배포판에 따라 tmpfs 라 부팅 때 비워진다.
WORK=/var/tmp/remedy-p7
STATE="$WORK/state"
UNIT=/etc/systemd/system/remedy-verify.service
LINK=/etc/systemd/system/multi-user.target.wants/remedy-verify.service
TMPU=/etc/systemd/system/remedy-verify.service.remedy-tmp
# 실험 플러그인(`p7-plugin.yaml`)이 조준하는 자리. 둘이 함께 바뀌어야 한다.
FIXTURE_DIR=/opt/remedy-lab/p7

PASS=0
FAIL=0
UNMEASURED=0
CHECKS=""

die() { echo "reboot-verify: $*" >&2; exit 2; }

check() {
    local name="$1" ok="$2" detail="$3"
    case "$ok" in
        1) PASS=$((PASS + 1)); printf '  \033[32mOK\033[0m   %-44s %s\n' "$name" "$detail" ;;
        -) UNMEASURED=$((UNMEASURED + 1))
           printf '  \033[33m못잼\033[0m %-44s %s\n' "$name" "$detail" ;;
        *) FAIL=$((FAIL + 1)); printf '  \033[31m실패\033[0m %-44s %s\n' "$name" "$detail" ;;
    esac
    printf '%s\t%s\t%s\n' "$name" "$ok" "$(printf '%s' "$detail" | tr '\t\n' '  ')" >> "$CHECKS"
}

# 잰 값. 판정이 아니므로 통과·실패를 세지 않는다.
measure() {
    printf '  잰값 %-44s %s\n' "$1" "$2"
    printf '%s\t%s\n' "$1" "$(printf '%s' "$2" | tr '\t\n' '  ')" >> "$WORK/.measure"
}

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# `ok` 는 true · false · null(못잼) 이다 — `verify-linux.sh` 와 같은 모양.
write_result() {
    local phase="$1" out="$WORK/result-$1.json" first=1 n o d ob
    {
        printf '{\n  "schema": "remedy-reboot-verify/1",\n  "phase": "%s",\n' "$phase"
        printf '  "host": "%s",\n  "checks": [\n' "$(json_escape "$(hostname) $(uname -sr)")"
        while IFS=$'\t' read -r n o d; do
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            case "$o" in 1) ob=true ;; -) ob=null ;; *) ob=false ;; esac
            printf '    { "name": "%s", "ok": %s, "detail": "%s" }' \
                "$(json_escape "$n")" "$ob" "$(json_escape "$d")"
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

verdict_exit() {
    [ "$FAIL" -eq 0 ] || exit 1
    [ "$UNMEASURED" -eq 0 ] || exit 2
    exit 0
}

# ─────────────────────────────────────────── 재부팅 전

before() {
    local bin="" plugin=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --bin)    bin="${2:-}"; shift 2 ;;
            --plugin) plugin="${2:-}"; shift 2 ;;
            *) die "모르는 인자: $1" ;;
        esac
    done
    [ -n "$bin" ] && [ -x "$bin" ] || die "--bin 이 실행 파일이 아니다: $bin"
    [ -n "$plugin" ] && [ -f "$plugin" ] || die "--plugin 이 없다: $plugin"
    [ "$(id -u)" -eq 0 ] || die "root 로 돌아야 한다"

    rm -rf "$WORK"
    mkdir -p "$WORK"
    CHECKS="$WORK/.checks"
    : > "$CHECKS"
    echo "[*] 재부팅 전 — $(hostname) · $(uname -sr)"

    # ── 0. 여기가 재는 자리인가 ──────────────────────────────────
    local pid1 virt
    pid1="$(cat /proc/1/comm 2>/dev/null)"
    if [ -d /run/systemd/system ] && [ "$pid1" = systemd ]; then
        check "0 systemd 가 PID 1 이다" 1 "/proc/1/comm=$pid1"
    else
        check "0 systemd 가 PID 1 이다" 0 "/proc/1/comm=${pid1:-?} — 이 기계에서는 부팅을 잴 수 없다"
    fi
    # **랩 VM 에서만 돈다.** 이 회차는 기계를 재부팅한다 — 컨테이너에서는 잴 것이
    # 없고, 가상 머신이 아니면 엉뚱한 기계일 수 있다.
    virt="$(systemd-detect-virt 2>/dev/null || true)"
    case "$virt" in
        vmware|kvm|qemu|oracle|microsoft|xen) check "0b 가상 머신이다 (컨테이너가 아니다)" 1 "$virt" ;;
        *) check "0b 가상 머신이다 (컨테이너가 아니다)" 0 "systemd-detect-virt=${virt:-없음}" ;;
    esac
    # 남아 있으면 이번 회차가 심은 것인지 알 수 없다 — 스냅숏이 깨끗하지 않다는 뜻이다.
    if [ -e "$UNIT" ] || [ -L "$LINK" ]; then
        check "0c 시작 전에 우리 예약이 없다" 0 "이미 있다 — 스냅숏이 깨끗하지 않다"
    else
        check "0c 시작 전에 우리 예약이 없다" 1 "없다"
    fi
    cat /proc/sys/kernel/random/boot_id > "$WORK/boot-id-before"

    # ── 치료 — 무해한 표지 파일 하나를 격리하고 재부팅 뒤 재검사를 건다 ──
    mkdir -p "$FIXTURE_DIR"
    printf 'remedy P12 P7 harmless marker\n' > "$FIXTURE_DIR/marker.txt"
    "$bin" run --plugin "$plugin" --yes --state-dir "$STATE" --out-dir "$WORK/run" \
        > "$WORK/run.txt" 2>&1
    local rc=$?
    # 1 = 위협 발견 · 치료 완료. 표지 하나를 격리하는 회차에 다른 값은 나올 이유가 없다.
    if [ "$rc" -eq 1 ]; then
        check "run 이 치료를 마쳤다" 1 "exit=1"
    else
        check "run 이 치료를 마쳤다" 0 "exit=$rc — $WORK/run.txt"
    fi
    local run_id
    run_id="$(sed -n 's/.*"run_id": *"\([^"]*\)".*/\1/p' "$WORK/run/plan.json" 2>/dev/null | head -1)"
    if [ -n "$run_id" ]; then
        printf '%s\n' "$run_id" > "$WORK/run-id"
        check "run_id 를 얻었다" 1 "$run_id"
    else
        check "run_id 를 얻었다" 0 "plan.json 에 없다"
    fi

    # ── 1. 예약이 심겼다 ─────────────────────────────────────────
    if [ -f "$UNIT" ] && [ -L "$LINK" ] && [ "$(readlink "$LINK")" = "$UNIT" ]; then
        check "1 예약이 심겼다 (유닛 · 활성화 링크)" 1 "$UNIT"
        cp "$UNIT" "$WORK/unit-before.service"
    else
        check "1 예약이 심겼다 (유닛 · 활성화 링크)" 0 \
            "유닛=$([ -f "$UNIT" ] && echo 있다 || echo 없다) 링크=$([ -L "$LINK" ] && readlink "$LINK" || echo 없다)"
    fi

    # ── 2. 실행 직전에 자기를 지운다 ─────────────────────────────
    if grep -qxF "ExecStartPre=-/bin/rm -f \"$LINK\" \"$UNIT\"" "$UNIT" 2>/dev/null; then
        check "2 유닛이 실행 직전에 자기를 지운다" 1 "ExecStartPre=-/bin/rm -f <링크> <유닛>"
    else
        check "2 유닛이 실행 직전에 자기를 지운다" 0 "그 줄이 없다"
    fi

    # ── 3. 감사 로그의 End 바로 앞에 같은 명령 ───────────────────
    #
    # 유닛의 `ExecStart` 는 systemd 가 펴는 `%%` · `$$` 를 되돌리고, 저널의 명령은
    # JSON 의 `\"` · `\\` 를 되돌려 견준다.
    local jl="$STATE/journal/$run_id.jsonl" start logged
    start="$(sed -n 's/^ExecStart=//p' "$UNIT" 2>/dev/null | sed -e 's/%%/%/g' -e 's/\$\$/$/g')"
    logged="$(tail -2 "$jl" 2>/dev/null | head -1 | grep '"rec":"verify_scheduled"' \
        | sed -n 's/.*"command":"\(.*\)","at":.*/\1/p' | sed -e 's/\\"/"/g' -e 's/\\\\/\\/g')"
    if [ -n "$start" ] && [ "$start" = "$logged" ] && tail -1 "$jl" 2>/dev/null | grep -q '"rec":"end"'; then
        check "3 감사 로그 End 앞에 같은 명령이 적혔다" 1 "verify_scheduled -> end"
    else
        check "3 감사 로그 End 앞에 같은 명령이 적혔다" 0 "유닛=${start:-없다} · 저널=${logged:-없다}"
    fi
    case "$start" in
        *"--lang ko"*) check "3b 예약된 명령이 치료와 같은 언어를 싣는다" 1 "--lang ko" ;;
        *) check "3b 예약된 명령이 치료와 같은 언어를 싣는다" 0 "${start:-명령이 없다}" ;;
    esac

    write_result before
    verdict_exit
}

# ─────────────────────────────────────────── 재부팅 뒤

after() {
    [ $# -eq 0 ] || die "after 는 인자를 받지 않는다: $*"
    [ "$(id -u)" -eq 0 ] || die "root 로 돌아야 한다"
    [ -f "$WORK/run-id" ] || die "before 를 먼저 돌려야 한다 — $WORK/run-id 가 없다"
    CHECKS="$WORK/.checks"
    : > "$CHECKS"
    : > "$WORK/.measure"
    local run_id
    run_id="$(cat "$WORK/run-id")"
    echo "[*] 재부팅 뒤 — $(hostname) · run $run_id"

    # ── 4. 실제로 재부팅했다 ─────────────────────────────────────
    if [ "$(cat "$WORK/boot-id-before")" != "$(cat /proc/sys/kernel/random/boot_id)" ]; then
        check "4 실제로 재부팅했다" 1 "boot_id 가 바뀌었다"
    else
        check "4 실제로 재부팅했다" 0 "boot_id 가 그대로다 — 재부팅하지 않았다"
    fi

    # ── 5. 흔적이 없다 (자기 흔적 규칙 2) ────────────────────────
    local left=""
    [ -e "$UNIT" ] && left="$left 유닛"
    [ -L "$LINK" ] && left="$left 링크"
    if [ -z "$left" ]; then
        check "5 유닛과 링크가 둘 다 없다 (규칙 2)" 1 "없다"
    else
        check "5 유닛과 링크가 둘 다 없다 (규칙 2)" 0 "남았다:$left"
    fi
    if [ -e "$TMPU" ]; then
        check "5b 바꿔 끼우던 임시 파일이 없다" 0 "$TMPU"
    else
        check "5b 바꿔 끼우던 임시 파일이 없다" 1 "없다"
    fi

    # ── 6. systemd 가 이번 부팅에 그 유닛을 돌렸다 ───────────────
    #
    # 유닛 파일은 이미 지워졌지만 저널은 이번 부팅의 기록을 갖고 있다.
    local jt="$WORK/journal-unit.txt"
    if [ -d /run/systemd/system ] && command -v journalctl > /dev/null 2>&1; then
        journalctl -b -u remedy-verify.service --no-pager -o short-monotonic > "$jt" 2>&1
        if grep -q 'Starting .*remedy' "$jt"; then
            check "6 systemd 가 이번 부팅에 그 유닛을 돌렸다" 1 "$(grep -m1 'Starting .*remedy' "$jt" | cut -c1-110)"
        else
            check "6 systemd 가 이번 부팅에 그 유닛을 돌렸다" 0 "이번 부팅의 저널에 없다 — $jt"
        fi
        if grep -qE 'Finished .*remedy' "$jt" && ! grep -qE 'Failed with result|status=[1-9]' "$jt"; then
            check "6b 그 유닛이 성공으로 끝났다" 1 "$(grep -m1 -E 'Finished .*remedy' "$jt" | cut -c1-110)"
        else
            check "6b 그 유닛이 성공으로 끝났다" 0 "$(grep -m1 -E 'Failed|status=' "$jt" | cut -c1-110)"
        fi
    else
        check "6 systemd 가 이번 부팅에 그 유닛을 돌렸다" - "systemd 저널이 없다 — 이 기계는 systemd 부팅이 아니다"
        check "6b 그 유닛이 성공으로 끝났다" - "같은 이유"
    fi

    # ── 7. 재평가 판정이 남았다 ──────────────────────────────────
    local vr="$STATE/verify/$run_id.jsonl" last
    if [ -f "$vr" ]; then
        last="$(tail -1 "$vr")"
        case "$last" in
            *'"outcome":"clean"'*'"exit_code":0'*)
                check "7 재평가 판정이 남았다 (clean · 종료 0)" 1 "$(printf '%s' "$last" | cut -c1-120)" ;;
            *) check "7 재평가 판정이 남았다 (clean · 종료 0)" 0 "$last" ;;
        esac
    else
        check "7 재평가 판정이 남았다 (clean · 종료 0)" 0 "없다: $vr"
    fi

    # ── 8. 재부팅 회차의 화면이 회차 로그에 남았다 ───────────────
    #
    # `run` 이 같은 이름의 로그를 이미 열었으므로 파일이 있다는 것만으로는 증거가
    # 아니다 — **재부팅 뒤에 덧붙은 머리줄**(`# remedy … · verify --run`)이 있어야
    # 그 회차가 적은 것이다 (P10-F 6 과 같은 규칙).
    local log="$STATE/logs/$run_id.log" hdr tail_txt ko en n
    hdr="$(grep -nE '# remedy .* · verify --run ' "$log" 2>/dev/null | tail -1 | cut -d: -f1)"
    if [ -n "$hdr" ]; then
        tail_txt="$(tail -n +"$hdr" "$log")"
        n="$(printf '%s\n' "$tail_txt" | wc -l)"
        check "8 재부팅 회차의 화면이 회차 로그에 남았다" 1 "덧붙은 줄 ${n}개"
        # 화면의 언어. 치료를 한국어로 했으므로 재부팅 회차도 한국어여야 한다.
        ko="$(printf '%s\n' "$tail_txt" | grep -cE '전용백신|검사 완료|검사 중')"
        en="$(printf '%s\n' "$tail_txt" | grep -cE 'Dedicated Cleaner|Scan done|Scanning')"
        if [ "$ko" -gt 0 ] && [ "$en" -eq 0 ]; then
            check "8b 치료와 같은 언어로 돌았다" 1 "한국어 ${ko}줄 · 영어 0줄"
        else
            check "8b 치료와 같은 언어로 돌았다" 0 "한국어 ${ko}줄 · 영어 ${en}줄"
        fi
    else
        check "8 재부팅 회차의 화면이 회차 로그에 남았다" 0 "재부팅 회차의 머리줄이 없다 — $log"
        check "8b 치료와 같은 언어로 돌았다" - "로그가 없어 잴 수 없다"
    fi
    if ls "$STATE"/logs/crash-*.txt > /dev/null 2>&1; then
        check "8c 크래시하지 않았다" 0 "$(cd "$STATE/logs" && ls crash-*.txt | tr '\n' ' ')"
    else
        check "8c 크래시하지 않았다" 1 "crash-*.txt 없음"
    fi

    # ── 잰 값 — 부팅이 재평가를 얼마나 기다렸나 (P12 메모 §7) ──────
    #
    # oneshot 은 `multi-user.target` 도달을 재평가가 끝날 때까지 늦춘다
    # (`systemd.target(5)` 의 암묵 After=). 판정이 아니라 기록이다.
    #
    # **관리자가 적어 둔 µs 로 잰다.** 두 가지 함정이 있다 (2026-09-23 실측):
    # 저널의 줄 시각은 줄이 기록된 때라 상태가 바뀐 때보다 ~2 ms 늦고, 그러면
    # 재평가가 target 보다 늦게 끝난 것처럼 보인다. `critical-chain` 은 끝나서
    # 비활성이 된 oneshot 을 보여 주지 않는다. 유닛 파일은 지워졌어도 유닛은
    # 이번 부팅 동안 메모리에 남아 있다(`LoadState=loaded`).
    if [ -d /run/systemd/system ] && command -v systemd-analyze > /dev/null 2>&1; then
        systemd-analyze > "$WORK/systemd-analyze.txt" 2>&1
        systemd-analyze critical-chain multi-user.target --no-pager > "$WORK/critical-chain.txt" 2>&1
        systemctl show remedy-verify.service multi-user.target \
            -p Id -p LoadState -p Result -p InactiveExitTimestampMonotonic \
            -p InactiveEnterTimestampMonotonic -p ActiveEnterTimestampMonotonic \
            -p Before -p After > "$WORK/unit-timestamps.txt" 2>&1
        measure "부팅" "$(head -1 "$WORK/systemd-analyze.txt")"
        local vs ve mu
        vs="$(systemctl show remedy-verify.service -p InactiveExitTimestampMonotonic --value 2>/dev/null)"
        ve="$(systemctl show remedy-verify.service -p InactiveEnterTimestampMonotonic --value 2>/dev/null)"
        mu="$(systemctl show multi-user.target -p ActiveEnterTimestampMonotonic --value 2>/dev/null)"
        if [ "${vs:-0}" -gt 0 ] && [ "${ve:-0}" -gt "${vs:-0}" ]; then
            measure "재평가 (부팅 뒤 초)" \
                "$(awk -v a="$vs" -v b="$ve" 'BEGIN { printf "%.3f → %.3f · %.1f ms", a / 1e6, b / 1e6, (b - a) / 1e3 }')"
        else
            measure "재평가 (부팅 뒤 초)" "관리자 시각이 없다 (InactiveExit=${vs:-?} InactiveEnter=${ve:-?})"
        fi
        if [ "${mu:-0}" -gt 0 ] && [ "${ve:-0}" -gt 0 ]; then
            measure "multi-user.target 도달 (부팅 뒤 초)" \
                "$(awk -v u="$mu" -v e="$ve" 'BEGIN { printf "%.3f · 재평가가 끝나고 %+.1f ms", u / 1e6, (u - e) / 1e3 }')"
        fi
    fi

    write_result after
    verdict_exit
}

case "${1:-}" in
    before) shift; before "$@" ;;
    after)  shift; after "$@" ;;
    *) die "쓰는 법: reboot-verify.sh before --bin <remedy> --plugin <yaml> | after" ;;
esac
