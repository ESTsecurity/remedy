#!/bin/bash
# P12 P7 — 리눅스 랩 VM 에서 재부팅 뒤 재검사를 **진짜 systemd 부팅으로** 잰다 (호스트).
#
# Windows 랩의 `host/Invoke-P10FVerify.ps1` 짝이다. VM 을 되돌리고, 바이너리와
# 게스트 스크립트(`reboot-verify.sh`)를 보내고, 치료 → 재부팅 → 확인을 한다.
# 랩 VM 을 만드는 법은 `docs/P12-P7-리눅스-랩-VM-준비.md` 에 있다.
#
# # 쓰는 법 (WSL, 저장소 루트)
#
#     testbed/harness/linux/invoke-reboot-verify.sh --check   # 준비 점검 — VM 을 바꾸지 않는다
#     testbed/harness/linux/invoke-reboot-verify.sh           # 되돌리기 → 치료 → 재부팅 → 확인
#
# # 왜 WSL 에서 도는가
#
# VMware 는 Windows 쪽이지만 **VMnet8(NAT) 에는 WSL 에서도 닿는다**(실측
# 2026-09-23 — WSL 에서 Windows 랩 VM 의 5985 로 연결됨). 배포 바이너리도 WSL 의
# `/tmp/remedy-bookworm` 에 있다 — `invoke-exam-apply.sh` 와 같은 자리다.
# `vmrun.exe` 는 Windows 상호 운용으로 부른다.
#
# # Windows 랩에서 배운 것 둘 (`host/Reset-Vm.ps1`)
#
# - 스냅숏 안의 게스트 스크립트는 찍을 때의 판이다 → 되돌린 뒤 **매번 새로 보낸다**
# - 켜진 채 찍은 스냅숏은 시계까지 되살아난다 → 이 랩은 **전원을 끈 채 찍는다**.
#   되돌리면 꺼진 상태이고, 켜질 때 시계를 호스트에서 받는다

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
GUEST_DIR=/usr/local/lib/remedy-p7
CHECK_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --check)    CHECK_ONLY=1; shift ;;
        --vmx)      VMX="${2:-}"; shift 2 ;;
        --snapshot) SNAPSHOT="${2:-}"; shift 2 ;;
        --bin)      BIN="${2:-}"; shift 2 ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

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
            0) bad "스냅숏이 없다: $SNAPSHOT — 가이드 8단계 (있는 것: $(printf '%s' "$snaps" | tr '\n' ' '))" ;;
            *) bad "스냅숏 '$SNAPSHOT' 이 ${n}개다 — 어디로 되돌릴지 정할 수 없다" ;;
        esac
    else
        bad "VM 이 없다: $VMX — 가이드 2단계"
        skip "스냅숏 — VM 이 없어 볼 수 없다"
    fi
    if [ -f "$KEY" ] && [ -f "$KEY.pub" ]; then
        if [ "$(stat -c %a "$KEY")" = 600 ]; then
            ok "SSH 키: $KEY ($(ssh-keygen -lf "$KEY.pub" | awk '{print $2}'))"
        else
            bad "SSH 키 권한이 600 이 아니다: $KEY"
        fi
    else
        bad "SSH 키가 없다: $KEY"
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
    if [ -f "$HERE/reboot-verify.sh" ] && [ -f "$HERE/p7-plugin.yaml" ]; then
        ok "게스트 스크립트 · 실험 플러그인"
    else
        bad "게스트 스크립트나 실험 플러그인이 없다: $HERE"
    fi
}

preflight_guest() {
    step "준비 점검 — 게스트 ($IP)"
    if ! on_vm true 2> /dev/null; then
        bad "SSH 키로 root 가 되지 않는다 — 가이드 6단계"
        return
    fi
    ok "SSH 키로 root 가 된다"
    local v
    v="$(on_vm 'cat /proc/1/comm')"
    if [ "$v" = systemd ]; then ok "systemd 가 PID 1 이다"; else bad "PID 1 이 systemd 가 아니다: $v"; fi
    v="$(on_vm 'systemd-detect-virt' 2> /dev/null)"
    if [ "$v" = vmware ]; then ok "VMware 가상 머신이다"; else bad "systemd-detect-virt=$v"; fi
    v="$(on_vm 'systemctl is-active open-vm-tools' 2> /dev/null)"
    if [ "$v" = active ]; then ok "open-vm-tools 가 돈다"; else bad "open-vm-tools: ${v:-없다} — 가이드 5단계"; fi
    v="$(on_vm '. /etc/os-release; printf "%s (%s)" "$PRETTY_NAME" "$(cat /etc/debian_version)"')"
    ok "게스트: $v"
    v="$(on_vm 'systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer 2>/dev/null' | tr '\n' ' ')"
    case "$v" in
        *enabled*) warn "apt 자동 타이머가 켜져 있다 ($v) — 부팅 시간 잰 값이 흔들린다. 가이드 5단계" ;;
        *) ok "apt 자동 타이머가 꺼져 있다" ;;
    esac
    if on_vm 'dpkg -s unattended-upgrades > /dev/null 2>&1'; then
        warn "unattended-upgrades 가 깔려 있다 — 되돌린 뒤 패키지가 바뀔 수 있다"
    else
        ok "unattended-upgrades 가 없다"
    fi
    if on_vm 'test -e /etc/systemd/system/remedy-verify.service -o -L /etc/systemd/system/multi-user.target.wants/remedy-verify.service'; then
        bad "우리 예약이 이미 있다 — 이 상태로 스냅숏을 찍으면 안 된다"
    else
        ok "우리 예약이 없다 (깨끗하다)"
    fi
}

cd "$REPO" || exit 2
mkdir -p "$LAB"
chmod 700 "$LAB"
preflight_host

if [ "$CHECK_ONLY" -eq 1 ]; then
    if [ "$VMX_FOUND" -eq 0 ]; then
        step "준비 점검 — 게스트"
        skip "VM 이 아직 없다 — 게스트 점검은 VM 을 만든 뒤에 한다"
    elif vm_running; then
        IP="$(vm_ip 20)"
        if [ -n "$IP" ]; then
            preflight_guest
        else
            step "준비 점검 — 게스트"
            skip "켜져 있지만 주소를 모른다 — open-vm-tools 가 도는지 볼 것 (가이드 5단계)"
        fi
    else
        step "준비 점검 — 게스트"
        skip "VM 이 꺼져 있다 — 게스트 점검은 VM 을 켠 뒤에 한다 (스냅숏은 꺼진 채 찍는다)"
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
OUT="$REPO/testbed/harness/results/linux-reboot-$STAMP"
mkdir -p "$OUT"
T0=$SECONDS

collect() {
    if on_vm 'tar -C /var/tmp -czf - remedy-p7' 2> /dev/null | tar -xzf - -C "$OUT" 2> /dev/null; then
        echo "    결과: $OUT/remedy-p7"
    else
        echo "    결과를 가져오지 못했다"
    fi
}

step "되돌리기: $SNAPSHOT"
vm revertToSnapshot "$VMX" "$SNAPSHOT" > "$OUT/vmrun.txt" || { echo "되돌리지 못했다 — $OUT/vmrun.txt"; exit 2; }
ok "되돌렸다"
if vm_running; then
    warn "스냅숏이 켜진 채 찍혔다 — 시계가 스냅숏 시각으로 돌아갔을 수 있다"
else
    vm start "$VMX" nogui >> "$OUT/vmrun.txt" || { echo "켜지 못했다 — $OUT/vmrun.txt"; exit 2; }
    ok "켰다"
fi

step "게스트 주소 (open-vm-tools)"
IP="$(vm_ip 240)"
[ -n "$IP" ] || { echo "240초 안에 주소가 오지 않았다 — open-vm-tools 가 도는지 볼 것"; exit 2; }
ok "$IP"
step "SSH 응답 대기"
wait_ssh 180 || { echo "SSH 가 180초 안에 열리지 않았다"; exit 2; }
ok "열렸다"

preflight_guest
[ "$PRE_FAIL" -eq 0 ] || { echo; echo "게스트가 준비되지 않았다 — 위 실패를 먼저 고칠 것"; exit 2; }

step "배포 — 바이너리 · 게스트 스크립트 · 실험 플러그인"
on_vm "install -d -m 755 $GUEST_DIR" \
    && to_vm "$BIN" /usr/local/bin/remedy \
    && to_vm "$HERE/reboot-verify.sh" "$GUEST_DIR/" \
    && to_vm "$HERE/p7-plugin.yaml" "$GUEST_DIR/" \
    && on_vm "chmod 755 /usr/local/bin/remedy" \
    || { echo "보내지 못했다"; exit 2; }
SHA_HOST="$(sha256sum "$BIN" | cut -d' ' -f1)"
SHA_GUEST="$(on_vm 'sha256sum /usr/local/bin/remedy' | cut -d' ' -f1)"
[ "$SHA_HOST" = "$SHA_GUEST" ] || { echo "보낸 바이너리가 다르다: $SHA_HOST / $SHA_GUEST"; exit 2; }
ok "remedy ${SHA_HOST:0:16}… (게스트와 같다)"

step "재부팅 전 — 치료하고 재검사를 건다"
on_vm "bash $GUEST_DIR/reboot-verify.sh before --bin /usr/local/bin/remedy --plugin $GUEST_DIR/p7-plugin.yaml"
RC_BEFORE=$?
if [ "$RC_BEFORE" -ne 0 ]; then
    collect
    echo
    echo "  실패 재부팅 전 검사가 통과하지 못했다 — 재부팅하지 않는다"
    exit 1
fi

BOOT_BEFORE="$(on_vm 'cat /proc/sys/kernel/random/boot_id')"
step "재부팅"
on_vm 'systemctl reboot' > /dev/null 2>&1 || true
T_REBOOT=$SECONDS
# **돌아왔다는 것은 boot_id 로만 안다.** 포트가 열린 것은 아직 내려가기 전일 수 있다.
DOWN=0
UP=0
while [ $((SECONDS - T_REBOOT)) -lt 300 ]; do
    b="$(on_vm 'cat /proc/sys/kernel/random/boot_id' 2> /dev/null)"
    if [ -z "$b" ]; then
        DOWN=1
        # 주소가 바뀌었을 수도 있다 — 한동안 닿지 않으면 다시 묻는다.
        if [ $((SECONDS - T_REBOOT)) -gt 60 ]; then
            n="$(vm_ip 5)"
            [ -n "$n" ] && IP="$n"
        fi
    elif [ "$b" != "$BOOT_BEFORE" ]; then
        UP=1
        break
    fi
    sleep 3
done
[ "$UP" -eq 1 ] || { echo "300초 안에 다시 올라오지 않았다"; collect; exit 2; }
ok "다시 올라왔다 — $((SECONDS - T_REBOOT))초 (내려간 것을 봤다: $([ "$DOWN" -eq 1 ] && echo 예 || echo 아니오))"

# oneshot 은 multi-user.target 도달을 재평가가 끝날 때까지 늦춘다 — 부팅이 끝나야
# 재평가도 끝났다. 끝나지 않으면 15분에서 끊고 그대로 잰다.
step "부팅이 끝나기를 기다린다"
STATE_AFTER="$(on_vm 'timeout 900 systemctl is-system-running --wait' 2> /dev/null)"
ok "is-system-running: ${STATE_AFTER:-알 수 없음} — 재부팅부터 $((SECONDS - T_REBOOT))초"

step "재부팅 뒤 — 흔적 · 저널 · 재평가 기록"
on_vm "bash $GUEST_DIR/reboot-verify.sh after"
RC_AFTER=$?
collect

echo
case "$RC_AFTER" in
    0) echo "  OK   P7 합격 — 진짜 systemd 부팅에서 재검사가 돌고 흔적이 남지 않았다 ($((SECONDS - T0))초)" ;;
    1) echo "  실패 P7 불합격 — $OUT/remedy-p7/result-after.json" ;;
    *) echo "  미결 — 못 잰 것이 있다. 통과로 읽으면 안 된다" ;;
esac
echo "  VM 은 켜 둔다. 끄려면: \"$VMRUN\" -T ws stop '$VMX' soft"
exit "$RC_AFTER"
