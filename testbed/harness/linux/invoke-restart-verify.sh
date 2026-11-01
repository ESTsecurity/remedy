#!/bin/bash
# P12 — systemd `Restart=` 데몬 실증 (호스트 · WSL). 게스트 쪽은 `restart-verify.sh`.
#
# `invoke-reboot-verify.sh` 와 **같은 랩 VM · 같은 스냅숏 · 같은 키**다. 무엇을 왜 재는지는
# `restart-verify.sh` 머리에 있다.
#
# # 쓰는 법 (WSL, 저장소 루트)
#
#     testbed/harness/linux/invoke-restart-verify.sh --check            # 준비 점검 — VM 을 바꾸지 않는다
#     testbed/harness/linux/invoke-restart-verify.sh                    # fast · slow · none 세 회차
#     testbed/harness/linux/invoke-restart-verify.sh --scenario slow    # 한 회차만 (여러 번 줄 수 있다 — 같은 것도)
#     testbed/harness/linux/invoke-restart-verify.sh --scenario refuse  # 정지 거부 유닛 (기본 회차에는 없다)
#
# # 회차 하나
#
#     되돌리기 → 켜기 → 배포 → before(픽스처 · 치료 · 관찰) → 재부팅 → after → 결과 가져오기
#
# **회차마다 스냅숏으로 되돌린다.** 앞 회차의 격리소 · 저널 · systemd 가 메모리에 둔 유닛이
# 다음 회차에 섞이지 않게 한다. **끝나면 한 번 더 되돌린다** — 되살아난 픽스처 데몬을 랩에
# 남기지 않고, VM 은 꺼진 기본 스냅숏으로 돌아간다(스냅숏은 전원을 끈 채 찍었다).
#
# 결과는 `testbed/harness/results/linux-restart-<시각>/<순번>-<회차>/` 에 온다 (.gitignore).
# 종료 코드: 0 전부 통과 · 1 잰 성질이 깨졌다(실측이다) · 2 못 잰 회차가 있다.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"

# 랩 값은 `.cargo/*.yml` 에서 읽는다 — 박아 두면 기계가 바뀔 때 어긋난다.
. "$HERE/lab-config.sh"

VMRUN="$(lab_value host vmware.vmrun_from_wsl)"
VMX="$(lab_value linux_lab linux_lab.identity.vmx)"
SNAPSHOT="$(lab_value linux_lab linux_lab.snapshots.current)"
# 랩 전용 키와 known_hosts. 사용자의 ~/.ssh 는 건드리지 않는다.
LAB="$HOME/.config/remedy-lab"
KEY="$LAB/linux-lab-ed25519"
KNOWN="$LAB/linux-known_hosts"
BIN=/tmp/remedy-bookworm/release/remedy
GUEST_DIR=/usr/local/lib/remedy-restart
CHECK_ONLY=0
SCENARIOS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --check)    CHECK_ONLY=1; shift ;;
        --vmx)      VMX="${2:-}"; shift 2 ;;
        --snapshot) SNAPSHOT="${2:-}"; shift 2 ;;
        --bin)      BIN="${2:-}"; shift 2 ;;
        --scenario)
            case "${2:-}" in
                fast|slow|none|refuse) SCENARIOS+=("$2") ;;
                *) echo "--scenario 는 fast · slow · none · refuse 중 하나다: ${2:-}"; exit 2 ;;
            esac
            shift 2 ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done
[ "${#SCENARIOS[@]}" -gt 0 ] || SCENARIOS=(fast slow none)

PRE_FAIL=0
PRE_SKIP=0
VMX_FOUND=0
IP=""
step() { echo; echo "[*] $*"; }
ok()   { printf '    \033[32mOK\033[0m   %s\n' "$*"; }
bad()  { printf '    \033[31m실패\033[0m %s\n' "$*"; PRE_FAIL=$((PRE_FAIL + 1)); }
skip() { printf '    \033[33m못잼\033[0m %s\n' "$*"; PRE_SKIP=$((PRE_SKIP + 1)); }
warn() { printf '    \033[33m주의\033[0m %s\n' "$*"; }

vm() {
    "$VMRUN" -T ws "$@" 2>&1 | tr -d '\r'
    return "${PIPESTATUS[0]}"
}
vm_running() { vm list | grep -qiF "$VMX"; }
# open-vm-tools 가 알려 주는 주소. 모양이 IPv4 일 때만 믿는다.
vm_ip() {
    local ip
    ip="$(timeout "$1" "$VMRUN" -T ws getGuestIPAddress "$VMX" -wait 2>/dev/null | tr -d '\r' | head -1)"
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && printf '%s' "$ip"
}

SSH_OPTS=(-i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new
          -o "UserKnownHostsFile=$KNOWN" -o ConnectTimeout=5 -o LogLevel=ERROR)
on_vm() { ssh "${SSH_OPTS[@]}" "root@$IP" "$@"; }
to_vm() { scp -q "${SSH_OPTS[@]}" "$1" "root@$IP:$2"; }

wait_ssh() {
    local t0=$SECONDS
    while [ $((SECONDS - t0)) -lt "$1" ]; do
        on_vm true 2> /dev/null && return 0
        sleep 3
    done
    return 1
}

# ─────────────────────────────────────────── 준비 점검

preflight_host() {
    step "준비 점검 — 호스트"
    if [ -x "$VMRUN" ]; then ok "vmrun: $VMRUN"; else bad "vmrun.exe 가 없다: $VMRUN"; fi
    local vmx_wsl
    vmx_wsl="$(wslpath -u "$VMX" 2>/dev/null)"
    if [ -n "$vmx_wsl" ] && [ -f "$vmx_wsl" ]; then
        VMX_FOUND=1
        ok "VM: $VMX"
        local snaps n
        snaps="$(vm listSnapshots "$VMX" | tail -n +2)"
        n="$(printf '%s\n' "$snaps" | grep -cxF "$SNAPSHOT")"
        case "$n" in
            1) ok "스냅숏: $SNAPSHOT" ;;
            0) bad "스냅숏이 없다: $SNAPSHOT (있는 것: $(printf '%s' "$snaps" | tr '\n' ' '))" ;;
            *) bad "스냅숏 '$SNAPSHOT' 이 ${n}개다 — 어디로 되돌릴지 정할 수 없다" ;;
        esac
    else
        bad "VM 이 없다: $VMX — docs/P12-P7-리눅스-랩-VM-준비.md"
    fi
    if [ -f "$KEY" ] && [ -f "$KEY.pub" ] && [ "$(stat -c %a "$KEY")" = 600 ]; then
        ok "SSH 키: $KEY ($(ssh-keygen -lf "$KEY.pub" | awk '{print $2}'))"
    else
        bad "SSH 키가 없거나 권한이 600 이 아니다: $KEY"
    fi
    if [ -x "$BIN" ]; then
        ok "바이너리: $BIN ($(sha256sum "$BIN" | cut -c1-16)…)"
        local bt ct
        bt="$(stat -c %Y "$BIN")"
        ct="$(git -C "$REPO" log -1 --format=%ct -- crates/ 2> /dev/null)"
        if [ -n "$ct" ] && [ "$bt" -lt "$ct" ]; then
            warn "바이너리가 crates/ 의 마지막 커밋보다 오래됐다 — 다시 빌드할 것 (invoke-linux-verify.sh 머리의 1단계)"
        fi
    else
        bad "바이너리가 없다: $BIN — invoke-linux-verify.sh 머리의 1단계로 만든다"
    fi
    if [ -f "$HERE/restart-verify.sh" ] && [ -f "$HERE/restart-plugin.yaml" ]; then
        ok "게스트 스크립트 · 실험 플러그인"
    else
        bad "게스트 스크립트나 실험 플러그인이 없다: $HERE"
    fi
    ok "회차: ${SCENARIOS[*]}"
}

preflight_guest() {
    step "준비 점검 — 게스트 ($IP)"
    if ! on_vm true 2> /dev/null; then
        bad "SSH 키로 root 가 되지 않는다"
        return
    fi
    ok "SSH 키로 root 가 된다"
    local v
    v="$(on_vm 'cat /proc/1/comm')"
    if [ "$v" = systemd ]; then ok "systemd 가 PID 1 이다"; else bad "PID 1 이 systemd 가 아니다: $v"; fi
    v="$(on_vm 'systemd-detect-virt' 2> /dev/null)"
    if [ "$v" = vmware ]; then ok "VMware 가상 머신이다"; else bad "systemd-detect-virt=$v"; fi
    v="$(on_vm '. /etc/os-release; printf "%s (%s) · %s" "$PRETTY_NAME" "$(cat /etc/debian_version)" "$(systemctl --version | head -1)"')"
    ok "게스트: $v"
    if on_vm 'test -e /etc/systemd/system/remedy-lab-restart.service -o -e /opt/remedy-lab/restart'; then
        bad "픽스처가 이미 있다 — 이 상태로 스냅숏을 찍으면 안 된다"
    else
        ok "픽스처가 없다 (깨끗하다)"
    fi
}

cd "$REPO" || exit 2
mkdir -p "$LAB"
chmod 700 "$LAB"
preflight_host

if [ "$CHECK_ONLY" -eq 1 ]; then
    if [ "$VMX_FOUND" -eq 0 ]; then
        step "준비 점검 — 게스트"
        skip "VM 이 없다 — 게스트 점검은 VM 을 만든 뒤에 한다"
    elif vm_running; then
        IP="$(vm_ip 20)"
        if [ -n "$IP" ]; then
            preflight_guest
        else
            step "준비 점검 — 게스트"
            skip "켜져 있지만 주소를 모른다 — open-vm-tools 가 도는지 볼 것"
        fi
        warn "VM 이 켜져 있다 — 실행하면 스냅숏으로 되돌리므로 지금 상태는 버려진다"
    else
        step "준비 점검 — 게스트"
        skip "VM 이 꺼져 있다 — 게스트 점검은 실행 때 되돌린 뒤에 한다"
    fi
    echo
    echo "준비 점검: 실패 $PRE_FAIL · 못잼 $PRE_SKIP"
    [ "$PRE_FAIL" -eq 0 ] || exit 1
    [ "$PRE_SKIP" -eq 0 ] || exit 2
    exit 0
fi

[ "$PRE_FAIL" -eq 0 ] || { echo; echo "준비가 안 됐다 — 위 실패를 먼저 고칠 것"; exit 2; }

# ─────────────────────────────────────────── 실행

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$REPO/testbed/harness/results/linux-restart-$STAMP"
mkdir -p "$OUT"
T0=$SECONDS
SHA_HOST="$(sha256sum "$BIN" | cut -d' ' -f1)"
printf '%s\n' "$SHA_HOST" > "$OUT/binary-sha256"

# **어디서 끝나든 되돌린다.** 회차 중간에 멈추면 되살아난 픽스처가 VM 에 남는다.
finish() {
    step "마무리 — 되돌려 끈다: $SNAPSHOT"
    if vm revertToSnapshot "$VMX" "$SNAPSHOT" >> "$OUT/vmrun.txt"; then
        ok "되돌렸다"
    else
        bad "되돌리지 못했다 — $OUT/vmrun.txt"
    fi
    if vm_running; then
        warn "되돌린 뒤에도 켜져 있다 — 스냅숏이 켜진 채 찍혔다"
    else
        ok "꺼져 있다 (기본 스냅숏)"
    fi
}
trap finish EXIT

collect() {
    if on_vm 'tar -C /var/tmp -czf - remedy-restart' 2> /dev/null | tar -xzf - -C "$1" 2> /dev/null; then
        ok "결과: $1/remedy-restart"
    else
        warn "결과를 가져오지 못했다"
    fi
}

deploy() {
    step "배포 — 바이너리 · 게스트 스크립트 · 실험 플러그인"
    on_vm "install -d -m 755 $GUEST_DIR" \
        && to_vm "$BIN" /usr/local/bin/remedy \
        && to_vm "$HERE/restart-verify.sh" "$GUEST_DIR/" \
        && to_vm "$HERE/restart-plugin.yaml" "$GUEST_DIR/" \
        && on_vm "chmod 755 /usr/local/bin/remedy" \
        || { bad "보내지 못했다"; return 1; }
    local sha_guest
    sha_guest="$(on_vm 'sha256sum /usr/local/bin/remedy' | cut -d' ' -f1)"
    [ "$SHA_HOST" = "$sha_guest" ] || { bad "보낸 바이너리가 다르다: $SHA_HOST / $sha_guest"; return 1; }
    ok "remedy ${SHA_HOST:0:16}… (게스트와 같다)"
}

# 재부팅하고 **boot_id 가 바뀔 때까지** 기다린다. 포트가 열린 것은 아직 내려가기 전일 수 있다.
reboot_vm() {
    local before b t=$SECONDS n
    before="$(on_vm 'cat /proc/sys/kernel/random/boot_id')"
    on_vm 'systemctl reboot' > /dev/null 2>&1 || true
    while [ $((SECONDS - t)) -lt 300 ]; do
        b="$(on_vm 'cat /proc/sys/kernel/random/boot_id' 2> /dev/null)"
        if [ -z "$b" ] && [ $((SECONDS - t)) -gt 60 ]; then
            n="$(vm_ip 5)"
            [ -n "$n" ] && IP="$n"
        elif [ -n "$b" ] && [ "$b" != "$before" ]; then
            ok "다시 올라왔다 — $((SECONDS - t))초"
            ok "is-system-running: $(on_vm 'timeout 300 systemctl is-system-running --wait' 2> /dev/null)"
            return 0
        fi
        sleep 3
    done
    bad "300초 안에 다시 올라오지 않았다"
    return 1
}

# run_scenario <회차> <결과 폴더> — 0 전부 통과 · 1 잰 성질이 깨졌다 · 2 못 잼
run_scenario() {
    local sc="$1" out="$2" rc_b rc_a
    local tag="${2##*/}"
    mkdir -p "$out"
    step "[$tag] 되돌리기: $SNAPSHOT"
    vm revertToSnapshot "$VMX" "$SNAPSHOT" >> "$OUT/vmrun.txt" || { bad "되돌리지 못했다 — $OUT/vmrun.txt"; return 2; }
    if vm_running; then
        warn "스냅숏이 켜진 채 찍혔다 — 시계가 스냅숏 시각으로 돌아갔을 수 있다"
    else
        vm start "$VMX" nogui >> "$OUT/vmrun.txt" || { bad "켜지 못했다 — $OUT/vmrun.txt"; return 2; }
    fi
    IP="$(vm_ip 240)"
    [ -n "$IP" ] || { bad "240초 안에 주소가 오지 않았다"; return 2; }
    ok "주소 $IP"
    wait_ssh 180 || { bad "SSH 가 180초 안에 열리지 않았다"; return 2; }
    PRE_FAIL=0
    preflight_guest
    [ "$PRE_FAIL" -eq 0 ] || return 2
    deploy || return 2

    step "[$tag] 치료 전 — 픽스처 · 치료 · 관찰"
    on_vm "bash $GUEST_DIR/restart-verify.sh before --scenario $sc --bin /usr/local/bin/remedy --plugin $GUEST_DIR/restart-plugin.yaml"
    rc_b=$?
    if [ "$rc_b" -ne 0 ] && [ "$rc_b" -ne 1 ]; then
        collect "$out"
        return 2
    fi
    step "[$tag] 재부팅"
    reboot_vm || { collect "$out"; return 2; }
    step "[$tag] 재부팅 뒤"
    on_vm "bash $GUEST_DIR/restart-verify.sh after"
    rc_a=$?
    collect "$out"
    if [ "$rc_a" -ne 0 ] && [ "$rc_a" -ne 1 ]; then return 2; fi
    [ "$rc_b" -eq 0 ] && [ "$rc_a" -eq 0 ] && return 0
    return 1
}

if vm_running; then
    warn "VM 이 켜져 있다 — 스냅숏으로 되돌리므로 지금 상태는 버려진다"
fi
WORST=0
SUMMARY=""
N=0
for sc in "${SCENARIOS[@]}"; do
    # **순번을 붙인다.** 같은 회차를 여러 번 주면 이름만으로는 서로의 결과를 덮는다.
    N=$((N + 1))
    run_scenario "$sc" "$OUT/$N-$sc"
    rc=$?
    [ "$rc" -gt "$WORST" ] && WORST=$rc
    case "$rc" in 0) v="통과" ;; 1) v="성질이 깨졌다" ;; *) v="못잼" ;; esac
    SUMMARY="$SUMMARY$(printf '  %-7s %s' "$N-$sc" "$v")"$'\n'
done

echo
echo "회차별 ($((SECONDS - T0))초 · remedy ${SHA_HOST:0:16}…):"
printf '%s' "$SUMMARY"
echo "  결과: $OUT"
exit "$WORST"
