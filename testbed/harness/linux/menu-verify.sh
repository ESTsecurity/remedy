#!/bin/bash
# 리눅스의 **새로 받은 꾸러미 첫 메뉴**를 진짜 터미널(pty)에서 띄워, Windows 의 같은
# 화면(콘솔 기준선 A10)과 줄 목록을 견준다 — 목표 remedy_제품화 기준 2(b)(c).
#
# 호스트(WSL)에서:
#
#   bash testbed/harness/linux/menu-verify.sh [--out <폴더>] [--cargo-home <WSL 에서 본 CARGO_HOME>]
#
# `--cargo-home` 을 주지 않으면 `.cargo/host.yml` 의 `wsl.cargo_home` 을 읽는다 — 그 아래
# `registry` 를 컨테이너에 붙여 크레이트를 다시 받지 않는다. 둘 다 없으면 멈춘다.
#
# 컨테이너(rust:1.96-bookworm) 안에서 Windows 메뉴 하네스(host/Invoke-MenuVerify.ps1)와
# 같은 조립을 한다 — 임시 키쌍 → 그 공개키를 박은 빌드 → 서명된 시험 플러그인
# (`lab-plugin.yaml`) → `xtask package`. 개인키는 회차마다 새로 만들고 컨테이너와 함께
# 버린다. 메뉴는 `script` 가 준 pty 에서 띄우고 stdout 은 파일로 받는다 — 그래서 줄 입력
# 화면(A10 과 같은 화면)이 나오고, `0` 을 넣어 그만둔다.
#
# 남기는 것: layout.txt(꾸러미 안 파일) · menu.txt(첫 메뉴) · items.txt · verdict.txt.
# **판정은 번호 줄의 목록**이다 — 머리말의 권한 낱말(관리자 · root)과 첫 줄 알림은
# OS 마다 다른 것이 맞아 견주지 않고 verdict.txt 에 따로 적는다.
#
# 둘째 꾸러미 — **리눅스 룰 전부**(배포 잡과 같은 목록 `xtask threats --dirs linux`)를 같은
# 일회용 키로 서명해 한 꾸러미에 담고(목표 remedy_출시_20261111 기준 3 · 4), 고르는 화면 맨 위의
# 검사 줄과 찾기만 하는 Ebury 룰의 메뉴를 띄운다 — scan-all.txt · scan-full.txt · detect-only.txt.
# 디스크 전체를 걷는 룰(Log4j 점검)이 함께 들어 그 줄이 **둘**이다(목표 remedy_기본검사_룰관리 ①②):
# 1 빠른 검사(그 룰을 빼고 요약에 *정밀 검사에서만* · 다음 할 일에 2번) · 2 정밀 검사(전부) · 룰은 3번부터.
# 깨끗한 컨테이너라 CWP 가 없다: CWPdoor 룰 둘은 6(선언한 자리가 없다 — 설계대로), Ebury 는
# 0 이고 두 검사의 끝 코드는 6 이다. 그 화면에는 *찾은 것 모두 치료하기* 가 서지 않는다.
#
# 마지막으로 같은 꾸러미에서 **감염된 CWP**(cwpdoor-verify.sh 의 자리 채우기 — 실검체 없음)를 세우고
# 1번(빠른 검사) → *찾은 것 모두 치료하기* → y 로 끝까지 간다(목표 remedy_전체검사_운영기반 기준 5): 승인 한 번 ·
# 치료 · 다시 검사 · 한 덩어리 · 회차 로그 · 회차마다의 복원 — treat-all.txt · treat-all-restore.txt.
# 복원으로 감염이 돌아오면 2번(정밀 검사)으로 같은 길을 한 번 더 간다 — treat-full.txt(치료로 잇기는 두 검사 모두).
#
# 그 꾸러미에는 **동반 프로그램 `remedy-net`** 도 든다(코어 1.4.0) — 네트워크 점검 룰이 목록에 있어
# 없이는 지어지지 않는다. 메뉴에서 그 항목을 골라 원격 점검을 끝까지 돌린다(닫힌 포트 127.0.0.1:9 —
# 컨테이너 밖으로 나가는 요청이 없다): 알리고 띄우는가 · sudo 를 건 사용자의 권한으로 내려 도는가 ·
# 내리지 못하는 자리에서는 그렇다고 말하는가 — net-check.txt · net-check-kept.txt 와 그 결과 폴더의
# 소유자 목록(net-check-tree.txt · net-check-kept-tree.txt). 그 룰 하나뿐인 폴더를 터미널 없이
# 띄우면 관리자 문이 아니라 돌리는 법을 말하는지도 본다(net-only-noterm.txt).
#
# 툴체인은 호스트(WSL)의 것을 읽기 전용으로 붙인다 — 사내망에서는 컨테이너의 rustup 이
# 1.96.0 을 못 받을 수 있다.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
TC=1.96.0-x86_64-unknown-linux-gnu
OUT=""
CARGO_HOME_ARG=""
INSIDE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT=$2; shift 2 ;;
        --cargo-home) CARGO_HOME_ARG=$2; shift 2 ;;
        --inside) INSIDE=1; shift ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

inside() {
    cd /repo || return 9
    export CARGO_TARGET_DIR=/tmp/remedy-bookworm
    local w=/tmp/menu-verify
    rm -rf "$w"; mkdir -p "$w/remedy-lab-linux"
    export REMEDY_SIGN_PASSWORD=menu-verify-ephemeral
    cargo run -q -p xtask -- sign keygen --public-key "$w/pub.key" --secret-key "$w/sec.key" \
        >/dev/null || { echo "error=키쌍을 만들지 못했다"; return 2; }
    local anchor
    anchor=$(sed -n 2p "$w/pub.key")
    cp testbed/harness/linux/lab-plugin.yaml "$w/remedy-lab-linux/plugin.yaml"
    cargo run -q -p xtask -- sign plugin --dir "$w/remedy-lab-linux" --secret-key "$w/sec.key" \
        --signed-at 2026-11-06T00:00:00Z >/dev/null || { echo "error=서명하지 못했다"; return 3; }
    REMEDY_TRUST_ANCHOR="$anchor" cargo build -q --release --locked -p remedy-cli \
        || { echo "error=앵커 박은 빌드가 실패했다"; return 4; }
    cargo run -q -p xtask -- package --plugin "$w/remedy-lab-linux" \
        --bin "$CARGO_TARGET_DIR/release/remedy" --out "$w/pkg" --public-key "$w/pub.key" \
        >/dev/null || { echo "error=꾸러미를 짓지 못했다"; return 5; }
    (cd "$w/pkg" && find . -type f | sed 's|^\./||' | sort) >/out/layout.txt
    # 꾸러미도 남긴다 — `screenshot.sh --package <out>/pkg` 가 같은 꾸러미로 화면을 찍는다.
    # 개인키는 남기지 않는다(꾸러미에는 공개키가 박힌 실행 파일과 서명만 있다).
    cp -a "$w/pkg" /out/pkg
    cd "$w/pkg" || return 6
    printf '0\n' | LANG=ko_KR.UTF-8 script -q -e -c "./remedy > /out/menu.txt 2>&1" /dev/null
    echo "menu_exit=$?"

    # ── 둘째 꾸러미 — 리눅스 룰 전부 ──────────────────────────────────
    cd /repo || return 7
    local args=() d n count=0 remote=0 disk=0
    mkdir -p "$w/all"
    for d in $(cargo run -q -p xtask -- threats --dirs linux); do
        n=$(basename "$d")
        cp -a "$d" "$w/all/$n"
        cargo run -q -p xtask -- sign plugin --dir "$w/all/$n" --secret-key "$w/sec.key" \
            --signed-at 2026-11-06T00:00:00Z >/dev/null || { echo "error=$n 을 서명하지 못했다"; return 8; }
        args+=(--plugin "$w/all/$n")
        # 데이터 룰(코어 1.12.0)은 꾸러미에 담지만 검사 항목이 아니다 — 메뉴의 개수에 들지 않는다.
        if grep -q '^kind: data' "$w/all/$n/plugin.yaml"; then continue; fi
        count=$((count + 1))
        # 네트워크로 점검하는 룰(코어 1.4.0)은 주소를 적어야 돌아 *모두 검사만* 에 들지 않는다 — 따로 센다.
        if grep -q '^network:' "$w/all/$n/plugin.yaml"; then remote=$((remote + 1)); continue; fi
        # 디스크 전체를 걷는 룰(`%FIXED_DISKS%`)은 빠른 검사가 뺀다 — 주석 줄은 세지 않는다.
        if grep -v -E '^[[:space:]]*#' "$w/all/$n/plugin.yaml" | grep -q -i '%FIXED_DISKS%'; then
            disk=$((disk + 1))
        fi
    done
    echo "linux_rules=$count"
    echo "network_rules=$remote"
    echo "disk_rules=$disk"
    # 고르는 화면 맨 위의 검사 줄 — 디스크 전체 룰과 그 밖의 룰이 함께 있으면 둘(1 빠른 · 2 정밀), 아니면 하나.
    local lines=1
    if [ "$disk" -gt 0 ] && [ $((count - remote - disk)) -gt 0 ]; then lines=2; fi
    echo "scan_lines=$lines"
    # 동반 프로그램 — 본체와 따로 짓고 같은 키로 서명한다(배포 잡과 같은 차례). 네트워크 점검 룰을
    # 담는 꾸러미는 이것 없이 지어지지 않는다(`xtask package` 가 멈춘다). **같은 공개키를 박는다** —
    # 판정 기준(데이터 룰 `remedy-net-criteria`)의 서명을 동반 프로그램이 직접 확인한다(코어 1.12.0).
    REMEDY_TRUST_ANCHOR="$anchor" cargo build -q --release --locked -p remedy-net \
        || { echo "error=remedy-net 을 짓지 못했다"; return 11; }
    mkdir -p "$w/companion/remedy-net"
    cp "$CARGO_TARGET_DIR/release/remedy-net" "$w/companion/remedy-net/" || return 11
    cargo run -q -p xtask -- sign companion --dir "$w/companion/remedy-net" --secret-key "$w/sec.key" \
        --signed-at 2026-11-06T00:00:00Z >/dev/null || { echo "error=동반 프로그램을 서명하지 못했다"; return 11; }
    cargo run -q -p xtask -- package "${args[@]}" --bin "$CARGO_TARGET_DIR/release/remedy" \
        --companion "$w/companion/remedy-net" --out "$w/pkg-all" --public-key "$w/pub.key" \
        >/dev/null || { echo "error=통합 꾸러미를 짓지 못했다"; return 9; }
    cd "$w/pkg-all" || return 10
    # 1 = 빠른 검사(검사 줄이 하나면 모두 검사만) · 빈 줄 = 작업 뒤의 멈춤 · 0 = 고르는 화면에서 그만두기.
    printf '1\n\n0\n' | LANG=ko_KR.UTF-8 script -q -e -c "./remedy > /out/scan-all.txt 2>&1" /dev/null
    echo "scan_all_exit=$?"
    # 모두 검사만은 찾은 룰 · 확인 필요 룰의 결과 파일만 남긴다(D11) — 깨끗한 컨테이너라 남은 폴더가 없어야 한다.
    echo "scan_all_out_dirs=$(find out -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
    # 2 = 정밀 검사 — 디스크 전체 룰까지 전부(검사 줄이 둘일 때만 선다).
    if [ "$lines" = 2 ]; then
        rm -rf out
        printf '2\n\n0\n' | LANG=ko_KR.UTF-8 script -q -e -c "./remedy > /out/scan-full.txt 2>&1" /dev/null
        echo "scan_full_exit=$?"
        echo "scan_full_out_dirs=$(find out -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
    fi
    # Ebury 의 번호는 고르는 화면에서 읽는다 — 룰이 늘면 바뀐다.
    local e
    e=$(grep -m1 -E '^ +[0-9]+\. Ebury ' /out/scan-all.txt | sed -E 's/^ +([0-9]+)\..*/\1/')
    # 작업 메뉴의 0 은 고르는 화면으로 돌아간다(코어 1.22.0) — 거기서 0 으로 그만둔다.
    printf '%s\n0\n0\n' "$e" | LANG=ko_KR.UTF-8 script -q -e -c "./remedy > /out/detect-only.txt 2>&1" /dev/null
    echo "detect_only_exit=$?"

    # ── 원격 점검 — 본체가 동반 프로그램을 띄운다 (코어 1.4.0 · 설계-04 §1) ──────────
    #
    # 고르는 화면에서 *네트워크 사용* 이 붙은 항목을 고르고 1번(원격 점검하기)으로 끝까지 간다 —
    # y = 이용 조건 동의 · 주소 한 줄 · 빈 줄 = 주소 끝 · 빈 줄 = 작업 뒤의 멈춤 · 0 = 그만두기.
    # 주소는 **닫힌 포트**(127.0.0.1:9)다: 컨테이너 밖으로 나가는 요청이 없고, 응답이 없어 판정은
    # *확인 필요*(6)다. 6 이 돌아오면 서명을 확인하고 띄워 결과 파일까지 쓴 것이다.
    #
    # 두 번 띄운다. 첫째는 **sudo 로 올라온 꼴** — sudo 가 하는 것(`SUDO_UID` · `SUDO_GID`)을 그대로
    # 준다. 본체는 root 로 돌고 동반 프로그램은 그 사용자의 권한으로 내려 돈다: 결과 파일의 소유자가
    # 그 사용자이고, 넘긴 것은 결과 폴더 안의 `remedy-net/` 한 칸뿐이다(그 위 `out/<시각>/` 은 root).
    # 둘째는 **내리지 못하는 자리** — umask 077 로 지은 `out/` 은 그 사용자가 지나지 못한다. 그렇다고
    # 말하고 root 로 띄워야 하고, 넘겼던 칸은 root 에게 돌아와 있어야 한다.
    local r
    r=$(grep -m1 -E '^ +[0-9]+\. .*\[네트워크 사용\]' /out/scan-all.txt | sed -E 's/^ +([0-9]+)\..*/\1/')
    echo "net_item=${r:-없음}"
    if [ -n "$r" ]; then
        id -u nettester >/dev/null 2>&1 || useradd -M -u 4242 nettester
        rm -rf out
        { printf '%s\n1\ny\nhttp://127.0.0.1:9/\n\n\n0\n' "$r"; sleep 8; } \
            | SUDO_UID=4242 SUDO_GID=4242 LANG=ko_KR.UTF-8 timeout 120 \
                script -q -e -c "./remedy > /out/net-check.txt 2>&1" /dev/null
        echo "net_check_exit=$?"
        find out -printf '%u %m %P\n' 2>/dev/null \
            | sed -E 's/[0-9]{8}T[0-9]{6}Z(-[0-9]+)?/<시각>/; s/remedy-net-url-[^ ]*\.json/<결과>.json/' \
            | sort >/out/net-check-tree.txt
        rm -rf out
        { printf '%s\n1\ny\nhttp://127.0.0.1:9/\n\n\n0\n' "$r"; sleep 8; } \
            | SUDO_UID=4242 SUDO_GID=4242 LANG=ko_KR.UTF-8 timeout 120 \
                script -q -e -c "umask 077; ./remedy > /out/net-check-kept.txt 2>&1" /dev/null
        echo "net_kept_exit=$?"
        find out -printf '%u %m %P\n' 2>/dev/null \
            | sed -E 's/[0-9]{8}T[0-9]{6}Z(-[0-9]+)?/<시각>/; s/remedy-net-url-[^ ]*\.json/<결과>.json/' \
            | sort >/out/net-check-kept-tree.txt

        # 네트워크 점검 룰 **하나뿐인** 폴더를 터미널 없이 띄운다 — 주소를 물어볼 수 없는 자리다.
        # 권한 없는 사용자로 띄운다: 관리자 문(5)에 먼저 막히지 않고, 어떻게 돌리는지 말한 뒤
        # 입력 오류(4)로 끝나야 한다 — 이 점검에는 권한이 필요 없다.
        rm -rf "$w/only-net"
        cp -a "$w/pkg-all" "$w/only-net"
        rm -rf "$w/only-net/out" "$w/only-net/state"
        for d in "$w/only-net/plugins"/*/; do
            grep -q '^network:' "$d/plugin.yaml" || rm -rf "$d"
        done
        (cd "$w/only-net" && LANG=ko_KR.UTF-8 setpriv --reuid 4242 --regid 4242 --clear-groups \
            ./remedy </dev/null >/out/net-only-noterm.txt 2>&1)
        echo "net_noterm_exit=$?"
    fi

    # ── 감염된 CWP 에서 '찾은 것 모두 치료하기' (목표 remedy_전체검사_운영기반 기준 5) ──────────────
    #
    # cwpdoor-verify.sh 의 C 와 같은 자리 채우기다 — **실검체가 없다**(ELF 머리 · 표시 문자열 · XLab 보고의
    # 공개 지표 · 이 하네스가 지어낸 유닛). 깨끗한 장면을 다 잰 뒤에 세운다. 같은 통합 꾸러미의 고르는
    # 화면에서 1(빠른 검사) → 빈 줄 → *찾은 것 모두 치료하기* → y(승인 한 번) → 빈 줄 → 0.
    # 그 줄은 **룰 목록 뒤**다(검사 줄 `lines` 개 + 룰 `count` 개 + 1) — 화면의 다음 할 일이 같은 번호를 적는지 판정에서 본다.
    python3 - <<'PY'
import os
pem = open("/repo/testbed/harness/linux/fixtures/cwpdoor/pubkey.pem", "rb").read()
x55 = bytes(b ^ 0x55 for b in pem)
head = b"\x7fELF\x02\x01\x01" + b"\0" * 57
mark = b"remedy-lab CWPdoor placeholder - not a program\0"
infected = head + mark + b"\0" * 4096 + b"X-Ngx-Integrity-Data\0X-Ngx-Integrity-Time\0X-Ngx-Integrity-Sig\0" \
    + b"\0" * 4096 + x55 + b"\0" * 4096
os.makedirs("/usr/local/cwpsrv/bin", exist_ok=True)
open("/usr/local/cwpsrv/bin/cwpsrv", "wb").write(infected.ljust(820848, b"\0"))
PY
    mkdir -p /lib/systemd/system /etc/systemd/system/multi-user.target.wants
    printf '%s\n' "[Unit]" "Description=remedy-lab CWP panel placeholder" "[Service]" \
        "Type=forking" "ExecStart=/usr/local/cwpsrv/bin/cwpsrv" "Restart=always" "RestartSec=5" \
        "[Install]" "WantedBy=multi-user.target" >/lib/systemd/system/cwpsrv.service
    ln -sf /lib/systemd/system/cwpsrv.service /etc/systemd/system/multi-user.target.wants/cwpsrv.service
    sha256sum /usr/local/cwpsrv/bin/cwpsrv /lib/systemd/system/cwpsrv.service >/out/treat-all-before.txt
    cd "$w/pkg-all" || return 12
    rm -rf out state
    local ta=$((count + lines + 1))
    echo "treat_all_item=$ta"
    printf '1\n\n%s\ny\n\n0\n' "$ta" | LANG=ko_KR.UTF-8 script -q -e -c "./remedy > /out/treat-all.txt 2>&1" /dev/null
    echo "treat_all_exit=$?"
    echo "treat_all_binary_gone=$([ ! -e /usr/local/cwpsrv/bin/cwpsrv ] && echo 1 || echo 0)"
    echo "treat_all_unit_gone=$([ ! -e /lib/systemd/system/cwpsrv.service ] \
        && [ ! -L /etc/systemd/system/multi-user.target.wants/cwpsrv.service ] && echo 1 || echo 0)"
    # 회차는 치료한 룰마다 하나 — 그 회차 로그에 묶음의 화면(계획 · 결과)이 있어야 한다(신고 묶음이 담는 자리).
    local id
    id=$(ls state/quarantine 2>/dev/null | sed -n 's/\.rq$//p' | head -1)
    echo "treat_all_runs=$(ls state/quarantine 2>/dev/null | grep -c '\.rq$')"
    echo "treat_all_runlog=$(grep -c '찾은 것 모두 치료하기 — 항목 1개' "state/logs/$id.log" 2>/dev/null)"
    # 복원은 회차마다 지금처럼 — 같은 바이트가 돌아와야 한다.
    LANG=ko_KR.UTF-8 ./remedy restore --run "$id" --state-dir state --yes >/out/treat-all-restore.txt 2>&1
    echo "treat_all_restore_exit=$?"
    sha256sum /usr/local/cwpsrv/bin/cwpsrv /lib/systemd/system/cwpsrv.service >/out/treat-all-restored.txt 2>/dev/null
    echo "treat_all_restored=$(cmp -s /out/treat-all-before.txt /out/treat-all-restored.txt && echo 1 || echo 0)"
    # 정밀 검사에서도 같은 길 — 복원으로 감염이 돌아왔다. 2 → 빈 줄 → 같은 번호 → y → 빈 줄 → 0.
    if [ "$lines" = 2 ]; then
        rm -rf out state
        printf '2\n\n%s\ny\n\n0\n' "$ta" \
            | LANG=ko_KR.UTF-8 script -q -e -c "./remedy > /out/treat-full.txt 2>&1" /dev/null
        echo "treat_full_exit=$?"
        echo "treat_full_binary_gone=$([ ! -e /usr/local/cwpsrv/bin/cwpsrv ] && echo 1 || echo 0)"
    fi

    # ── 같은 제품 — 합성 A/B 짝 · 실제 PHP 짝 (목표 remedy_기본검사_룰관리 기준 4) ──────────────
    #
    # **실검체가 없다** — 컨테이너의 dpkg 기록에 가짜 패키지 줄을 더할 뿐이다(실행 파일 · 설정 파일 없음). 끝에 기록을
    # 되돌린다. 판정은 룰마다 그대로이고, 끝 요약 밑의 *제품마다 — 올리면 해결되는 버전* 이 묶음이다.
    #
    # 1) 합성 A/B — 같은 패키지 `remedy-lab-ab` 를 보는 점검 룰 둘(A 는 1.5-1 · B 는 2.0-1 에서 고침 · 같은 product ·
    #    fixtures/same-product)을 따로 꾸러미에 담고 판을 1.2-1 → 1.7-1 → 2.0-1 로 바꿔 가며 모두 검사만. 1.2-1: 둘 다
    #    취약 · 묶음 줄 하나가 2.0-1 로 둘을 푼다. 1.7-1: B 를 고치며 올린 판이 아니라 A 만 고친 판 — A 는 양호 · B 만.
    #    2.0-1: 둘 다 양호 · 묶음 줄 없음.
    # 2) 실제 PHP 짝 — 통합 꾸러미로. php8.2-cli 8.2.20-1~deb12u1(source php8.2)을 세우면 PHP2Shell 점검은 취약(고친 판
    #    8.2.35-1~deb12u1), PHP 세션 점검은 확인 필요(판정을 세우지 않는다) — 묶음이 판 줄 밑에 세션 점검을 따로 적는다.
    local status=/var/lib/dpkg/status
    cp "$status" "$w/dpkg-status.orig" || return 13
    fake_pkg() {
        cp "$w/dpkg-status.orig" "$status"
        printf '\nPackage: %s\nStatus: install ok installed\nPriority: optional\nSection: misc\nInstalled-Size: 1\nMaintainer: remedy-lab <lab@remedy.invalid>\nArchitecture: amd64\nSource: %s\nVersion: %s\nDescription: remedy-lab placeholder - not a program\n' \
            "$1" "$2" "$3" >>"$status"
    }
    cd /repo || return 13
    local ab_args=() v
    mkdir -p "$w/ab"
    for n in remedy-lab-ab-a remedy-lab-ab-b; do
        cp -a "testbed/harness/linux/fixtures/same-product/$n" "$w/ab/$n"
        cargo run -q -p xtask -- sign plugin --dir "$w/ab/$n" --secret-key "$w/sec.key" \
            --signed-at 2026-11-06T00:00:00Z >/dev/null || { echo "error=$n 을 서명하지 못했다"; return 13; }
        ab_args+=(--plugin "$w/ab/$n")
    done
    cargo run -q -p xtask -- package "${ab_args[@]}" --bin "$CARGO_TARGET_DIR/release/remedy" \
        --out "$w/pkg-ab" --public-key "$w/pub.key" >/dev/null || { echo "error=A/B 꾸러미를 짓지 못했다"; return 13; }
    cd "$w/pkg-ab" || return 13
    for v in 1.2-1 1.7-1 2.0-1; do
        fake_pkg remedy-lab-ab remedy-lab-ab "$v"
        rm -rf out state
        printf '1\n\n0\n' | LANG=ko_KR.UTF-8 script -q -e -c "./remedy > /out/same-ab-$v.txt 2>&1" /dev/null
        echo "same_ab_${v//[.-]/_}_exit=$?"
    done
    fake_pkg php8.2-cli php8.2 8.2.20-1~deb12u1
    cd "$w/pkg-all" || return 14
    rm -rf out state
    printf '1\n\n0\n' | LANG=ko_KR.UTF-8 script -q -e -c "./remedy > /out/same-php.txt 2>&1" /dev/null
    echo "same_php_exit=$?"
    cp "$w/dpkg-status.orig" "$status"
}

if [ "$INSIDE" = 1 ]; then
    inside
    exit $?
fi

. "$HERE/lab-config.sh"
CARGO_HOME_WSL=$(lab_need "$CARGO_HOME_ARG" --cargo-home host wsl.cargo_home) || exit 2
[ -n "$OUT" ] || OUT="$REPO/testbed/harness/results/linux-menu-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
docker run --rm \
    -v "$REPO:/repo" \
    -v "$OUT:/out" \
    -v "$CARGO_HOME_WSL/registry:/usr/local/cargo/registry" \
    -v remedy-bookworm-target:/tmp/remedy-bookworm \
    -v "$HOME/.rustup/toolchains/$TC:/usr/local/rustup/toolchains/$TC:ro" \
    rust:1.96-bookworm bash /repo/testbed/harness/linux/menu-verify.sh --inside | tee "$OUT/run.txt"
[ -s "$OUT/menu.txt" ] || { echo "메뉴를 받지 못했다 — $OUT/run.txt"; exit 1; }

# 첫 화면의 번호 줄만 — 두 OS 가 같아야 하는 것(목표 remedy_사용자메뉴 기준 5).
items() { awk '/무엇을 할까요\?/{f=1} /번호를 고르십시오/{exit} f' "$1" \
            | grep -E '^ +[0-9]+\. '; }
items "$OUT/menu.txt" >"$OUT/items.txt"
items "$REPO/testbed/harness/baseline/console/console-win.txt" >"$OUT/items-win.txt"
{
    echo "linux_items=$(wc -l <"$OUT/items.txt")"
    echo "windows_items=$(wc -l <"$OUT/items-win.txt")"
    if diff -u "$OUT/items-win.txt" "$OUT/items.txt" >"$OUT/items.diff"; then
        echo "items_diff=0"
    else
        echo "items_diff=$(grep -c '^[-+][^-+]' "$OUT/items.diff")"
    fi
    echo "linux_privilege=$(grep -m1 -E '권한으로 실행 중입니다|권한이 없습니다' "$OUT/menu.txt")"
    echo "linux_notice=$(grep -m1 -E '^알림:' "$OUT/menu.txt")"
    # 모두 검사만 — 결과 한 덩어리에 룰마다 한 줄 · 깨끗한 룰은 결과 폴더를 남기지 않음(D11) · 작업 뒤 끝내는 말.
    # **세는 것은 이 기계를 보는 룰이다** — 네트워크 점검은 주소를 적어야 돌아 여기 들지 않고(1.4.0),
    # 끝의 요약에 *돌리지 않았습니다* 로 한 줄씩 선다(그래서 요약의 줄 수는 룰 전부다).
    all=$(sed -n 's/^linux_rules=//p' "$OUT/run.txt")
    net=$(sed -n 's/^network_rules=//p' "$OUT/run.txt")
    disk=$(sed -n 's/^disk_rules=//p' "$OUT/run.txt")
    rules=$((all - net))
    quick=$((rules - disk))
    echo "linux_rules=$rules"
    echo "network_rules=$net"
    echo "disk_rules=$disk"
    echo "scan_lines=$(sed -n 's/^scan_lines=//p' "$OUT/run.txt")"
    # 고르는 화면의 머리줄 — 코어 1.22.0 부터 *무엇을 검사할까요? (검사 항목 N개)* · 화면은 '룰' 대신 '항목' 이다.
    echo "chooser_total=$(grep -c "검사 항목 ${all}개)" "$OUT/scan-all.txt")"
    # 맨 위의 검사 줄 둘 — 1 빠른 검사(디스크 전체 룰을 뺀 수 · 권장) · 2 정밀 검사(전부 · 오래 걸릴 수 있다).
    echo "chooser_quick=$(grep -c -E "^ +1\. 빠른 검사 \(권장 · 항목 ${quick}개 · 아무것도 바꾸지 않습니다\)" "$OUT/scan-all.txt")"
    echo "chooser_full=$(grep -c -E "^ +2\. 정밀 검사 \(항목 ${rules}개 · 디스크 전체까지 · 오래 걸릴 수 있습니다\)" "$OUT/scan-all.txt")"
    # 끝 요약 — 제목부터 빈 줄까지(그 뒤의 *다음 할 일* 줄도 `이름 — 까닭` 꼴이라 세지 않는다).
    summary_of() { sed -n -E '/(모두 검사한|빠른 검사|정밀 검사) 결과 — /,/^$/p' "$1" 2>/dev/null; }
    echo "scan_all_skipped=$(summary_of "$OUT/scan-all.txt" | grep -c -E '^  .+ (—|-) 돌리지 않았습니다 \(네트워크 점검')"
    echo "scan_all_disk_skipped=$(summary_of "$OUT/scan-all.txt" | grep -c -E '^  .+ (—|-) 정밀 검사에서만 합니다 \(디스크 전체를 봅니다\)$')"
    echo "scan_all_exit=$(sed -n 's/^scan_all_exit=//p' "$OUT/run.txt")"
    echo "scan_all_summary=$(grep -c "빠른 검사 결과 — 항목 ${quick}개 · 아무것도 바꾸지 않았습니다" "$OUT/scan-all.txt")"
    echo "scan_all_lines=$(summary_of "$OUT/scan-all.txt" | grep -c -E '^  .+ (—|-) ')"
    # 빠른 검사 뒤 다음 할 일 — 뺀 것으로 가는 길(2번)을 같은 글로 가리킨다.
    echo "scan_all_full_lead=$(grep -c -E "^  디스크 전체까지 보려면 (—|-) 2\. 정밀 검사 \(항목 ${rules}개 · 디스크 전체까지" "$OUT/scan-all.txt")"
    # 결과 폴더를 적는 줄 — 남긴 룰만 적는다(D11). 깨끗한 컨테이너라 0 이다.
    echo "scan_all_dirs=$(grep -o -E '결과 폴더 : [^ ]+' "$OUT/scan-all.txt" | sort -u | wc -l)"
    echo "scan_all_out_dirs=$(sed -n 's/^scan_all_out_dirs=//p' "$OUT/run.txt")"
    echo "scan_all_ended=$(grep -c '끝냅니다\.' "$OUT/scan-all.txt")"
    # 정밀 검사 — 전부 돌고(빼는 것은 네트워크 점검뿐) 같은 끝 코드 · 결과 폴더 없음 · 2번을 다시 권하지 않는다.
    sf="$OUT/scan-full.txt"
    echo "scan_full_exit=$(sed -n 's/^scan_full_exit=//p' "$OUT/run.txt")"
    echo "scan_full_summary=$(grep -c "정밀 검사 결과 — 항목 ${rules}개 · 아무것도 바꾸지 않았습니다" "$sf" 2>/dev/null)"
    echo "scan_full_lines=$(summary_of "$sf" | grep -c -E '^  .+ (—|-) ')"
    echo "scan_full_skipped=$(summary_of "$sf" | grep -c -E '^  .+ (—|-) 돌리지 않았습니다 \(네트워크 점검')"
    echo "scan_full_disk_skipped=$(grep -c '정밀 검사에서만 합니다' "$sf" 2>/dev/null)"
    echo "scan_full_lead=$(grep -c '디스크 전체까지 보려면' "$sf" 2>/dev/null)"
    echo "scan_full_out_dirs=$(sed -n 's/^scan_full_out_dirs=//p' "$OUT/run.txt")"
    echo "scan_full_ended=$(grep -c '끝냅니다\.' "$sf" 2>/dev/null)"
    # 찾기만 하는 룰의 메뉴 — 머리말의 이름 · 1 번이 검사만 하기 · 치료를 약속하는 두 줄은 서지 않는다
    # (목표 remedy_사용자메뉴 기준 1 — v1.2.0 은 그 둘이 까닭을 달고 흐렸다).
    echo "detect_only_exit=$(sed -n 's/^detect_only_exit=//p' "$OUT/run.txt")"
    # 고르는 화면에서 들어온 작업 메뉴의 머리줄 — *<이름> — 무엇을 할까요?*(코어 1.22.0 · 전에는 *검사 항목: <이름>*).
    echo "detect_only_named=$(grep -c -E 'Ebury 점검 \(탐지만\) (—|-) 무엇을 할까요' "$OUT/detect-only.txt")"
    echo "detect_only_first=$(grep -c -E '^ +1\. 검사만 하기' "$OUT/detect-only.txt")"
    echo "detect_only_treat=$(grep -c -E '^ +[0-9]+\. (검사하고 치료하기|치료가 유지됐는지 다시 보기)' "$OUT/detect-only.txt")"
    # 원격 점검 — 알리고 띄웠는가 · 끝까지 돌았는가(닫힌 포트라 6) · 누구의 권한으로 돌았는가.
    # 알림은 이용 조건보다 **앞**이어야 한다: 본체가 말한 뒤에 동반 프로그램이 묻는다.
    nc="$OUT/net-check.txt"; nk="$OUT/net-check-kept.txt"
    line() { grep -n -m1 "$1" "$2" 2>/dev/null | cut -d: -f1; }
    told=$(line '이 점검은 네트워크를 씁니다' "$nc"); terms=$(line '이용 조건' "$nc")
    echo "net_check_exit=$(sed -n 's/^net_check_exit=//p' "$OUT/run.txt")"
    echo "net_check_menu_line=$(grep -c -E '^ +1\. 원격 점검하기 \(remedy-net 을 실행해 네트워크를 씁니다\)' "$nc" 2>/dev/null)"
    echo "net_check_told_first=$([ -n "$told" ] && [ -n "$terms" ] && [ "$told" -lt "$terms" ] && echo 1 || echo 0)"
    echo "net_check_lowered=$(grep -c 'sudo 를 건 사용자(uid 4242)의 권한으로 실행합니다' "$nc" 2>/dev/null)"
    echo "net_check_saved=$(grep -c -E '결과 파일: .*/out/[^/]+/remedy-net/remedy-net-url-.+\.json' "$nc" 2>/dev/null)"
    # 결과 파일은 그 사용자의 것이고, 넘긴 것은 `remedy-net/` 한 칸뿐이다 — 그 위는 root 의 것으로 남는다.
    echo "net_check_owner=$(grep -c -E '^nettester 600 <시각>/remedy-net/<결과>\.json$' "$OUT/net-check-tree.txt" 2>/dev/null)"
    echo "net_check_handed=$(grep -c -E '^nettester [0-7]+ <시각>/remedy-net$' "$OUT/net-check-tree.txt" 2>/dev/null)"
    echo "net_check_kept_root=$(grep -c -E '^root [0-7]+ (<시각>)?$' "$OUT/net-check-tree.txt" 2>/dev/null)"
    # 내리지 못하는 자리(umask 077) — 그렇다고 말하고 root 로 끝까지 돈다. 넘겼던 칸도 root 에게 돌아와 있다.
    echo "net_kept_exit=$(sed -n 's/^net_kept_exit=//p' "$OUT/run.txt")"
    echo "net_kept_said=$(grep -c '권한을 내리지 못했습니다' "$nk" 2>/dev/null)"
    echo "net_kept_owner=$(grep -c -E '^root 600 <시각>/remedy-net/<결과>\.json$' "$OUT/net-check-kept-tree.txt" 2>/dev/null)"
    echo "net_kept_others=$(grep -c -v -E '^root ' "$OUT/net-check-kept-tree.txt" 2>/dev/null)"
    # 터미널 없이 · 권한 없이 — 관리자 문의 문장이 아니라 돌리는 법이 나오고 4 로 끝난다.
    echo "net_noterm_exit=$(sed -n 's/^net_noterm_exit=//p' "$OUT/run.txt")"
    echo "net_noterm_told=$(grep -c '점검할 주소를 받아야 해서' "$OUT/net-only-noterm.txt" 2>/dev/null)"
    echo "net_noterm_gate=$(grep -c '권한이 필요합니다' "$OUT/net-only-noterm.txt" 2>/dev/null)"
    # 찾은 것 모두 치료하기(기준 5) — 깨끗한 기계의 모두 검사만에는 그 줄이 서지 않는다(바꾸는 것 0).
    # 감염된 기계에서는 모두 검사만 뒤 다음 할 일 첫 줄 → 고르는 화면에 그 줄 한 번(치료 뒤에는 거둔다) →
    # 승인 한 번 → 치료 · 다시 검사 · 한 덩어리 · 찾기만 하는 항목은 할 일만 → 치료한 룰의 다음 할 일.
    tf="$OUT/treat-all.txt"
    tn=$(sed -n 's/^treat_all_item=//p' "$OUT/run.txt")
    echo "scan_all_treat_line=$(grep -c '찾은 것 모두 치료하기' "$OUT/scan-all.txt")"
    echo "treat_all_exit=$(sed -n 's/^treat_all_exit=//p' "$OUT/run.txt")"
    echo "treat_all_lead=$(grep -c -E "찾은 것을 모두 치료하려면 (—|-) ${tn}\. 찾은 것 모두 치료하기 \(항목 1개" "$tf" 2>/dev/null)"
    echo "treat_all_line=$(grep -c -E "^ +${tn}\. 찾은 것 모두 치료하기 \(항목 1개" "$tf" 2>/dev/null)"
    echo "treat_all_header=$(grep -c '찾은 것 모두 치료하기 — 항목 1개를 다시 검사해' "$tf" 2>/dev/null)"
    echo "treat_all_prompt=$(grep -c -E '위 계획 1개\(바꿀 것 [0-9]+건\)를 모두 수행합니다' "$tf" 2>/dev/null)"
    echo "treat_all_summary=$(grep -c '찾은 것 모두 치료한 결과 — 항목 1개' "$tf" 2>/dev/null)"
    echo "treat_all_result=$(grep -c -E '^  CWPdoor 제거 (—|-) 위협 발견, 치료 완료 \([0-9]+건 수행 완료\)' "$tf" 2>/dev/null)"
    echo "treat_all_rescan=$(grep -c -E "^    다시 검사: (위협이 발견되지 않았습니다|관측이 불완전해 '위협 없음' 을 말할 수 없습니다)\.$" "$tf" 2>/dev/null)"
    echo "treat_all_detect_only=$(sed -n '/아래 항목은 찾기만 합니다/,/다음 할 일/p' "$tf" 2>/dev/null | grep -c -E '^    CWPdoor 점검 \(탐지만\)$')"
    # 치료한 룰의 다음 할 일 — 먼저 고를 룰을 한 번 적고 그 아래에 메뉴 줄을 들인다(코어 1.22.0 · 전에는 줄마다
    # *"치료가 유지되는지 보려면 — 4. CWPdoor 제거 → 3. …"*).
    if grep -q -E '먼저 [0-9]+\. CWPdoor 제거를 고른 뒤' "$tf" 2>/dev/null; then
        echo "treat_all_next=$(grep -c -E '^ +치료가 유지되는지 보려면 (—|-) [0-9]+\. 치료가 유지됐는지 다시 보기' "$tf")"
    else
        echo "treat_all_next=0"
    fi
    for k in binary_gone unit_gone runs runlog restore_exit restored; do
        echo "treat_all_$k=$(sed -n "s/^treat_all_$k=//p" "$OUT/run.txt")"
    done
    # 그 치료가 빠른 검사 뒤였는가 — 그리고 정밀 검사 뒤에도 같은 번호 · 같은 길인가(복원으로 감염이 돌아온 뒤).
    echo "treat_all_after_quick=$(grep -c "빠른 검사 결과 — 항목 ${quick}개" "$tf" 2>/dev/null)"
    # 빠른 검사 뒤 다음 할 일의 차례 — 찾은 것을 다루는 두 줄(모두 치료 · 하나씩 치료)이 붙어 먼저, 정밀 검사 줄이 끝.
    one=$(line '하나씩 치료하려면' "$tf"); dl=$(line '^  디스크 전체까지 보려면' "$tf")
    echo "treat_all_full_last=$([ -n "$one" ] && [ -n "$dl" ] && [ "$dl" -gt "$one" ] && echo 1 || echo 0)"
    ff="$OUT/treat-full.txt"
    echo "treat_full_exit=$(sed -n 's/^treat_full_exit=//p' "$OUT/run.txt")"
    echo "treat_full_after_full=$(grep -c "정밀 검사 결과 — 항목 ${rules}개" "$ff" 2>/dev/null)"
    echo "treat_full_lead=$(grep -c -E "찾은 것을 모두 치료하려면 (—|-) ${tn}\. 찾은 것 모두 치료하기 \(항목 1개" "$ff" 2>/dev/null)"
    echo "treat_full_line=$(grep -c -E "^ +${tn}\. 찾은 것 모두 치료하기 \(항목 1개" "$ff" 2>/dev/null)"
    echo "treat_full_summary=$(grep -c '찾은 것 모두 치료한 결과 — 항목 1개' "$ff" 2>/dev/null)"
    echo "treat_full_result=$(grep -c -E '^  CWPdoor 제거 (—|-) 위협 발견, 치료 완료 \([0-9]+건 수행 완료\)' "$ff" 2>/dev/null)"
    echo "treat_full_binary_gone=$(sed -n 's/^treat_full_binary_gone=//p' "$OUT/run.txt")"
    # 같은 제품(기준 4) — 합성 A/B 세 판과 실제 PHP 짝. 묶음은 끝 요약 밑의 *제품마다* 머리줄 아래다.
    hp='제품마다 — 올리면 해결되는 버전'
    an='실험 A 점검 (1.5 에서 고침)'; bn='실험 B 점검 (2.0 에서 고침)'
    s12="$OUT/same-ab-1.2-1.txt"; s17="$OUT/same-ab-1.7-1.txt"; s20="$OUT/same-ab-2.0-1.txt"; sp="$OUT/same-php.txt"
    for k in 1_2_1 1_7_1 2_0_1; do
        echo "same_ab_${k}_exit=$(sed -n "s/^same_ab_${k}_exit=//p" "$OUT/run.txt")"
    done
    echo "same_ab_12_both=$(grep -c -E '^  실험 [AB] 점검 \([^)]*\) (—|-) 취약합니다\.' "$s12" 2>/dev/null)"
    echo "same_ab_12_line=$(grep -c -F "  Remedy Lab AB — remedy-lab-ab 의 버전을 2.0-1 이상으로 올리면 이 2개 항목이 모두 해결됩니다: $an · $bn" "$s12" 2>/dev/null)"
    echo "same_ab_17_a_clean=$(grep -c -E '^  실험 A 점검 \([^)]*\) (—|-) 취약한 곳을 찾지 못했습니다\.' "$s17" 2>/dev/null)"
    echo "same_ab_17_b_only=$(grep -c -F "  Remedy Lab AB — remedy-lab-ab 의 버전을 2.0-1 이상으로 올리면 이 항목이 해결됩니다: $bn" "$s17" 2>/dev/null)"
    echo "same_ab_20_clean=$(grep -c -E '^  실험 [AB] 점검 \([^)]*\) (—|-) 취약한 곳을 찾지 못했습니다\.' "$s20" 2>/dev/null)"
    echo "same_ab_20_block=$(grep -c -F "$hp" "$s20" 2>/dev/null)"
    echo "same_php_exit=$(sed -n 's/^same_php_exit=//p' "$OUT/run.txt")"
    echo "same_php_block=$(grep -c -F "$hp" "$sp" 2>/dev/null)"
    echo "same_php_upgrade=$(grep -c -E '^  PHP (—|-) php8\.2-cli 의 버전을 8\.2\.35-1~deb12u1 이상으로 올리면 이 항목이 해결됩니다: PHP2Shell 점검' "$sp" 2>/dev/null)"
    echo "same_php_rest=$(grep -c -E '^  PHP (—|-) 버전으로만 판정하지 않는 항목입니다\(올려도 남을 수 있습니다\): PHP 세션 업로드 진행 설정 점검' "$sp" 2>/dev/null)"
} | tee "$OUT/verdict.txt"
v() { sed -n "s/^$1=//p" "$OUT/verdict.txt"; }
[ "$(v items_diff)" = 0 ] && [ -n "$(v linux_rules)" ] \
    && [ "$(v chooser_total)" -ge 1 ] && [ "$(v scan_all_skipped)" = "$(v network_rules)" ] \
    && [ "$(v scan_lines)" = 2 ] && [ "$(v disk_rules)" -ge 1 ] \
    && [ "$(v chooser_quick)" -ge 1 ] && [ "$(v chooser_full)" -ge 1 ] \
    && [ "$(v scan_all_disk_skipped)" = "$(v disk_rules)" ] && [ "$(v scan_all_full_lead)" = 1 ] \
    && [ "$(v scan_all_exit)" = 6 ] && [ "$(v scan_all_summary)" = 1 ] \
    && [ "$(v scan_all_lines)" = "$(( $(v linux_rules) + $(v network_rules) ))" ] \
    && [ "$(v scan_all_dirs)" = 0 ] && [ "$(v scan_all_out_dirs)" = 0 ] \
    && [ "$(v scan_all_ended)" = 1 ] \
    && [ "$(v scan_full_exit)" = 6 ] && [ "$(v scan_full_summary)" = 1 ] \
    && [ "$(v scan_full_lines)" = "$(( $(v linux_rules) + $(v network_rules) ))" ] \
    && [ "$(v scan_full_skipped)" = "$(v network_rules)" ] && [ "$(v scan_full_disk_skipped)" = 0 ] \
    && [ "$(v scan_full_lead)" = 0 ] && [ "$(v scan_full_out_dirs)" = 0 ] \
    && [ "$(v scan_full_ended)" = 1 ] && [ "$(v detect_only_exit)" = 0 ] \
    && [ "$(v detect_only_named)" = 1 ] && [ "$(v detect_only_first)" = 1 ] \
    && [ "$(v detect_only_treat)" = 0 ] \
    && [ "$(v net_check_exit)" = 6 ] && [ "$(v net_check_menu_line)" = 1 ] \
    && [ "$(v net_check_told_first)" = 1 ] && [ "$(v net_check_lowered)" = 1 ] \
    && [ "$(v net_check_saved)" = 1 ] && [ "$(v net_check_owner)" = 1 ] \
    && [ "$(v net_check_handed)" = 1 ] && [ "$(v net_check_kept_root)" = 2 ] \
    && [ "$(v net_kept_exit)" = 6 ] && [ "$(v net_kept_said)" = 1 ] \
    && [ "$(v net_kept_owner)" = 1 ] && [ "$(v net_kept_others)" = 0 ] \
    && [ "$(v net_noterm_exit)" = 4 ] && [ "$(v net_noterm_told)" = 1 ] \
    && [ "$(v net_noterm_gate)" = 0 ] \
    && [ "$(v scan_all_treat_line)" = 0 ] && [ "$(v treat_all_exit)" = 1 ] \
    && [ "$(v treat_all_lead)" = 1 ] && [ "$(v treat_all_line)" = 1 ] \
    && [ "$(v treat_all_header)" = 1 ] && [ "$(v treat_all_prompt)" = 1 ] \
    && [ "$(v treat_all_summary)" = 1 ] && [ "$(v treat_all_result)" = 1 ] \
    && [ "$(v treat_all_rescan)" = 1 ] && [ "$(v treat_all_detect_only)" = 1 ] \
    && [ "$(v treat_all_next)" = 1 ] && [ "$(v treat_all_binary_gone)" = 1 ] \
    && [ "$(v treat_all_unit_gone)" = 1 ] && [ "$(v treat_all_runs)" = 1 ] \
    && [ "$(v treat_all_runlog)" -ge 1 ] && [ "$(v treat_all_restore_exit)" = 0 ] \
    && [ "$(v treat_all_restored)" = 1 ] && [ "$(v treat_all_after_quick)" = 1 ] \
    && [ "$(v treat_all_full_last)" = 1 ] \
    && [ "$(v treat_full_exit)" = 1 ] && [ "$(v treat_full_after_full)" = 1 ] \
    && [ "$(v treat_full_lead)" = 1 ] && [ "$(v treat_full_line)" = 1 ] \
    && [ "$(v treat_full_summary)" = 1 ] && [ "$(v treat_full_result)" = 1 ] \
    && [ "$(v treat_full_binary_gone)" = 1 ] \
    && [ "$(v same_ab_1_2_1_exit)" = 2 ] && [ "$(v same_ab_12_both)" = 2 ] && [ "$(v same_ab_12_line)" = 1 ] \
    && [ "$(v same_ab_1_7_1_exit)" = 2 ] && [ "$(v same_ab_17_a_clean)" = 1 ] && [ "$(v same_ab_17_b_only)" = 1 ] \
    && [ "$(v same_ab_2_0_1_exit)" = 0 ] && [ "$(v same_ab_20_clean)" = 2 ] && [ "$(v same_ab_20_block)" = 0 ] \
    && [ "$(v same_php_exit)" = 2 ] && [ "$(v same_php_block)" = 1 ] \
    && [ "$(v same_php_upgrade)" = 1 ] && [ "$(v same_php_rest)" = 1 ]
