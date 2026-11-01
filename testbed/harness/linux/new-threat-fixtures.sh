#!/bin/bash
# AI 시험 위협의 감염 상태를 **진짜 기계 위에** 세운다 (설계-09 P12).
#
# # 왜
#
# 위협 폴더의 `infected/*.json` 이 전부 손으로 쓴 것이었다. 그런 스냅샷은
# 두 가지를 못 한다 — **다시 뜰 수 없고, 실기기가 낼 수 없는 모양을 담을 수
# 있다.** 둘 다 실제로 일어났다:
#
#   - `search-hijack` 은 프로세스 명령줄을 비워 두었다. 실기기 수집기는
#     보호 프로세스가 아닌 이상 명령줄을 채운다.
#   - `tls-intercept` 은 `/usr/local/share/ca-certificates/` 의 인증서에
#     `store: "system"` 을 붙였다. 수집기는 그 자리를 **`local`** 이라 적는다
#     (`certstore.rs` 의 `CERT_DIRS`). 우리 정답 플러그인이 그 거짓 값에
#     맞춰 `store equals system` 을 쓰고 있었고, 그래서 **실기기에서는 이
#     위협을 놓쳤다.**
#
# 여기서 세운 뒤 진짜 `collect` 를 돌리면 그런 것이 원리적으로 생기지 않는다.
#
# # 무해한가
#
# 페이로드는 전부 **표시 문자열 + 0 패딩**이다. 실행되지 않고 아무것도 하지
# 않는다. `ca.key` 도 개인키가 아니라 같은 크기의 자리 채우기다 — 저장소에
# 개인키를 넣지 않는다.
#
# 크기는 THREAT.md 가 적은 값에 정확히 맞춘다. 문제와 채점 데이터가 갈라지면
# 응시자는 도달할 수 없다 (출제자 주의 2번).
#
# # 어디서 도는가
#
# **컨테이너다.** `/etc/hosts` 와 `/etc/ld.so.conf.d` 를 고친다.
#
# # 쓰는 법
#
#     new-threat-fixtures.sh --threat ldso-preload
#     new-threat-fixtures.sh --threat tls-intercept --clean
#     new-threat-fixtures.sh --threat c2-beacon

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
THREAT=""
CLEAN=0
FORCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --threat) THREAT="${2:-}"; shift 2 ;;
        --clean)  CLEAN=1; shift ;;
        --force)  FORCE=1; shift ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

case "$THREAT" in
    ldso-preload|tls-intercept|c2-beacon|xmr-miner|ssh-backdoor|selfcopy-worm|npm-posthook|hexcfg-loader) ;;
    *) echo "--threat ldso-preload | tls-intercept | c2-beacon | xmr-miner | ssh-backdoor | selfcopy-worm | npm-posthook | hexcfg-loader"; exit 2 ;;
esac

in_container() {
    [ -f /.dockerenv ] && return 0
    grep -qE '(docker|containerd|lxc)' /proc/1/cgroup 2>/dev/null && return 0
    return 1
}
if [ "$FORCE" -ne 1 ] && ! in_container; then
    echo "컨테이너가 아니다. 이 스크립트는 /etc/hosts 와 /etc/ld.so.conf.d 를 고친다."
    echo "호스트에서는 new-threat-snapshot.sh 를 쓴다."
    exit 1
fi
[ "$(id -u)" -eq 0 ] || { echo "root 로 돌아야 한다."; exit 1; }

# 정해진 크기의 파일을 **정해진 내용**으로 만든다.
#
# 표시 문자열을 앞에 두고 나머지를 0 으로 채운다. 내용이 정해져야 sha256 이
# 재현되고, 재현되어야 스냅샷을 다시 뜰 때 같은 것이 나온다.
mkfile() {
    local p="$1" n="$2" marker="$3"
    mkdir -p "$(dirname "$p")"
    printf '%s\n' "$marker" > "$p"
    # truncate 는 0 으로 늘린다. dd bs=1 로 2 MB 를 채우면 200만 번 부른다.
    truncate -s "$n" "$p"
}

MARK='REMEDY AI-EXAM FIXTURE. 실행되지 않는 자리 채우기다.'

# 검체가 놓인 시각. **고정한다** — 스냅샷이 커밋되므로, 뜰 때마다 달라지면
# diff 가 뜻을 잃는다. 파일이 언제 놓였는가는 시나리오의 일부이고 크기와
# 마찬가지로 우리가 정하는 값이다.
#
# `ctime` 은 고정할 수 없다(아이노드가 바뀐 시각이라 언제나 '지금'이다).
# 그래서 스냅샷을 다시 뜨면 `ctime` 과 이미지가 소유한 파일들의 시각은
# 달라진다 — **그것은 기계의 사실이므로 감추지 않는다.**
DROP_LDSO='2026-08-28 21:41:07'
DROP_TLS='2026-08-27 05:18:44'
CLEAN_OLD='2025-11-02 09:14:22'
GOODWARE='2025-09-14 11:02:07'
stamp() { touch -d "$1 UTC" "${@:2}"; }

# ════════════════════════════════════════════════════════════════════
# ldso-preload — 라이브러리 검색 경로에 끼어드는 로더
# ════════════════════════════════════════════════════════════════════
#
# 폴더 이름의 꼬리(`.crypt-9d41`)는 THREAT.md 가 적은 값이다. 감염마다 바뀌는
# 것이 이 위협의 요점이므로 여기서는 고정하되, 룰은 그 값에 기대면 안 된다.
LDSO_DIR=/usr/local/lib/.crypt-9d41
LDSO_CONF=/etc/ld.so.conf.d/libc.conf
LDSO_LINE=/usr/local/lib/.crypt-9d41

ldso_clean() {
    rm -rf "$LDSO_DIR"
    rm -f /usr/local/lib/libfoo.so.1
    rm -f /usr/share/applications/org.example.Editor.desktop
    rm -f /usr/share/applications/org.example.Viewer.desktop
    # 덧붙인 줄만 뺀다. **파일을 지우면 안 된다** — 배포판이 설치한 것이고,
    # 사라지면 /usr/local/lib 이 검색 경로에서 빠진다. 이 위협의 요점이 그것이다.
    if [ -f "$LDSO_CONF" ]; then
        grep -v '^/usr/local/lib/\.crypt-' "$LDSO_CONF" > /tmp/.libc.conf.new 2>/dev/null \
            && cat /tmp/.libc.conf.new > "$LDSO_CONF"
        rm -f /tmp/.libc.conf.new
    fi
}

ldso_make() {
    # ── 지속성 · 덧붙은 줄 하나 ─────────────────────────────────
    #
    # 이 파일은 컨테이너에 이미 있다(배포판이 설치한 것). 줄만 잇는다 —
    # 새로 만들면 정상 줄 둘이 사라져 오탐 압력이 없어진다.
    [ -f "$LDSO_CONF" ] || { echo "$LDSO_CONF 가 없다 — 이 이미지는 쓸 수 없다"; exit 1; }
    grep -qxF "$LDSO_LINE" "$LDSO_CONF" || printf '%s\n' "$LDSO_LINE" >> "$LDSO_CONF"

    # ── 페이로드 · 폴더 전체가 검체의 것 ────────────────────────
    mkfile "$LDSO_DIR/libnsl_compat.so.2" 87432 "$MARK  libnsl_compat.so.2"
    mkfile "$LDSO_DIR/.seed"              8192  "$MARK  .seed"

    # ── 오탐 압력 · 같은 자리의 정상 라이브러리 ──────────────────
    #
    # THREAT.md 가 "같은 기계에 libfoo.so.1 이 그 자리에 있었고 이것은 검체와
    # 무관하다" 고 적는다. 없으면 그 문장이 채점 데이터와 갈라진다.
    mkfile /usr/local/lib/libfoo.so.1 33120 "$MARK  정상 라이브러리. 남아야 한다."

    # ── 변조된 실행기 · 인자만 덧붙었다 ─────────────────────────
    mkdir -p /usr/share/applications
    cat > /usr/share/applications/org.example.Editor.desktop <<DESKTOP
[Desktop Entry]
Type=Application
Name=Example Editor
Exec=/usr/bin/example-editor --module $LDSO_DIR/libnsl_compat.so.2 %F
Icon=org.example.Editor
Terminal=false
DESKTOP

    # 손대지 않은 짝. **인자가 %U 뿐이다** — THREAT.md 가 그렇게 적는다.
    cat > /usr/share/applications/org.example.Viewer.desktop <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Example Viewer
Exec=/usr/bin/example-viewer %U
Icon=org.example.Viewer
Terminal=false
DESKTOP

    stamp "$DROP_LDSO" "$LDSO_DIR/libnsl_compat.so.2" "$LDSO_DIR/.seed" "$LDSO_DIR" \
        /usr/share/applications/org.example.Editor.desktop "$LDSO_CONF"
    stamp "$CLEAN_OLD" /usr/local/lib/libfoo.so.1 \
        /usr/share/applications/org.example.Viewer.desktop
}

# ════════════════════════════════════════════════════════════════════
# tls-intercept — 통신을 가로채는 키트
# ════════════════════════════════════════════════════════════════════

tls_clean() {
    rm -rf /opt/netguard /opt/goodware
    rm -f /usr/local/share/ca-certificates/netguard-proxy.crt
    # hosts 는 통째로 되쓴다. `sed -i` 는 이름 바꾸기라 바인드 마운트에서 안 된다.
    tls_hosts_base > /etc/hosts
}

# 이 위협의 `/etc/hosts` 기준선.
#
# **컨테이너의 것을 그대로 쓰지 않는다.** 도커가 넣는 `172.17.0.2 <컨테이너
# id>` 줄이 실행마다 달라 스냅샷이 재현되지 않는다. 대신 THREAT.md 가 적는
# 모양으로 정해 둔다 — 조직이 손으로 넣은 줄(3번)이 있어야 *"지우면 안 되는
# 것이 섞여 있다"* 를 잴 수 있다.
#
# **탭이다.** 실기기의 hosts 가 쓰는 것이고, 계획기가 줄을 재구성하면 여기서
# 어긋난다 (2026-09-03 에 그것을 고쳤다).
tls_hosts_base() {
    printf '127.0.0.1\tlocalhost\n'
    printf '::1\tlocalhost ip6-localhost ip6-loopback\n'
    printf '192.168.10.14\tbuildserver buildserver.corp.example\n'
    printf 'fe00::\tip6-localnet\n'
    printf 'ff00::\tip6-mcastprefix\n'
    printf 'ff02::1\tip6-allnodes\n'
    printf 'ff02::2\tip6-allrouters\n'
}

tls_make() {
    # ── 심어진 최상위 인증서 ────────────────────────────────────
    #
    # **`/usr/local/share/ca-certificates` 다.** 수집기가 이 자리를 `local` 이라
    # 적고, 소스 주석이 그것을 *"손으로 더한 CA — 악성 루트 CA 가 들어오는
    # 자리"* 라 부른다. 합성 스냅샷은 여기에 `system` 을 적어 두었었다.
    mkdir -p /usr/local/share/ca-certificates
    cp "$HERE/fixtures/netguard-proxy.crt" /usr/local/share/ca-certificates/

    # ── 돌려진 이름 ─────────────────────────────────────────────
    {
        tls_hosts_base
        printf '127.0.0.1\tupdates.example-av.com sig.example-av.com\n'
        printf '127.0.0.1\ttelemetry.example-av.com\n'
    } > /etc/hosts

    # ── 페이로드 ────────────────────────────────────────────────
    #
    # `ca.key` 는 **개인키가 아니다.** 크기만 실제 RSA-2048 PEM 과 같다.
    mkfile /opt/netguard/netguard-proxyd 2451968 "$MARK  netguard-proxyd"
    mkfile /opt/netguard/ca.key          1704    "$MARK  ca.key 자리 채우기 — 진짜 키가 아니다."

    # ── 오탐 압력 · /opt 의 정상 소프트웨어 ─────────────────────
    mkfile /opt/goodware/scripts/backup.sh 412 "#!/bin/sh
# $MARK  정상 스크립트. 남아야 한다."

    stamp "$DROP_TLS" /opt/netguard/netguard-proxyd /opt/netguard/ca.key /opt/netguard \
        /usr/local/share/ca-certificates/netguard-proxy.crt
    stamp "$GOODWARE" /opt/goodware/scripts/backup.sh
}

# ── 실행 ────────────────────────────────────────────────────────────
# ── c2-beacon ─────────────────────────────────────────────────────────
#
# 알려진 지표 목록으로 잡는 위협이다 — 페이로드 두 개의 SHA-256 과 C2 도메인.
# 정답 플러그인의 해시 목록은 여기서 만든 파일의 **실측 다이제스트**다
# (`infected/c2-beacon.json` 에서 옮겼다). 바이트가 한 자리라도 바뀌면 해시가
# 바뀌고 정답이 빗나간다 — 그래서 이 파일들은 `mkfile` 로만 만들고 크기와
# 표식을 고정한다.
#
# 옆에 **같은 폴더의 정상 파일**(`notes.txt`)과 **같은 모양의 정상 자동 시작
# 항목**(`vendor-update.desktop`, 자기 도메인을 가진다)을 둔다. 자리나 모양으로
# 가르면 그것들이 함께 지워진다 — 목록에 있는 것만 지워야 한다.
#
# **systemd 서비스가 아니라 XDG 자동 시작 항목이다.** 처음에는 `.service` 로
# 세웠는데, 그것은 `service` 대상으로 모이고 지표(`indicator`)는 거기서 거두지
# 않아 도메인 목록이 비어 있었다(2026-09-09 첫 스냅샷). 자동 시작 항목의
# 명령줄은 지표 원천이고, 없애는 Op 이 파일 하나라 하네스가 그대로 잰다.
C2_DIR=/opt/.cache-9f2
C2_AUTO=/etc/xdg/autostart/cache-sync.desktop
GOOD_AUTO=/etc/xdg/autostart/vendor-update.desktop
DROP_C2='2026-09-01 03:12:40'
c2_clean() {
    rm -rf "$C2_DIR" /opt/vendor-tools
    rm -f "$C2_AUTO" "$GOOD_AUTO"
}
c2_make() {
    mkfile "$C2_DIR/agent.bin" 51200 "$MARK  agent.bin"
    mkfile "$C2_DIR/helper.so" 24576 "$MARK  helper.so"
    mkfile "$C2_DIR/notes.txt" 640   "$MARK  notes.txt — 같은 폴더의 정상 파일. 남아야 한다."
    mkfile /opt/vendor-tools/update.sh 412 "#!/bin/sh
# 정상 갱신 스크립트. 남아야 한다."
    mkdir -p /etc/xdg/autostart
    cat > "$C2_AUTO" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Cache synchronisation
Exec=/opt/.cache-9f2/agent.bin --beacon https://cdn.evil-metrics.example/v2/ping --key 9f2
NoDisplay=true
X-GNOME-Autostart-enabled=true
DESKTOP
    cat > "$GOOD_AUTO" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Vendor tools update
Exec=/opt/vendor-tools/update.sh --server https://updates.vendor.example/api
NoDisplay=true
X-GNOME-Autostart-enabled=true
DESKTOP
    stamp "$DROP_C2" "$C2_DIR/agent.bin" "$C2_DIR/helper.so" "$C2_DIR" "$C2_AUTO"
    stamp "$CLEAN_OLD" "$C2_DIR/notes.txt" /opt/vendor-tools/update.sh "$GOOD_AUTO"
}
# ── xmr-miner ─────────────────────────────────────────────────────────
#
# **리눅스 `service` 를 처음 밟는 위협이다.** 앞의 여섯은 서비스를 Windows
# 에서만 다뤘고(service-userinit), 리눅스 쪽 systemd 유닛은 아무도 건드리지
# 않았다 — 수집기(`systemd.rs`)와 쓰기 백엔드는 P12 에 섰는데 위협이 없었다.
#
# **리눅스는 Op 이 둘뿐이다.** `service.stop` 과 `service.clear_recovery` 는
# `linux_from` 이 null 이라(ops.json) 계획에 들어가지 않는다. Windows 의
# 넷(stop→disable→delete→clear_recovery)과 다른 모양이 나오는 것이 이 위협이
# 확인하는 자리다.
#
# 옆에 **같은 폴더의 정상 유닛**(`vendor-agent.service`)과 그 페이로드를 둔다.
# 자리나 확장자로 가르면 그것들이 함께 지워진다 — `ExecStart` 가 가리키는
# 곳으로 갈라야 한다.
XMR_DIR=/usr/local/lib/.metrics
XMR_UNIT=/etc/systemd/system/sys-metrics.service
GOOD_UNIT=/etc/systemd/system/vendor-agent.service
GOOD_DIR=/usr/local/lib/vendor
DROP_XMR='2026-09-14 22:41:07'
xmr_clean() {
    rm -rf "$XMR_DIR" "$GOOD_DIR"
    rm -f "$XMR_UNIT" "$GOOD_UNIT"
}
xmr_make() {
    mkfile "$XMR_DIR/xmrig" 204800 "$MARK  xmrig"
    mkfile "$XMR_DIR/config.json" 1024 "$MARK  config.json"
    mkfile "$GOOD_DIR/agent" 40960 "$MARK  agent — 정상 벤더 에이전트. 남아야 한다."
    mkdir -p /etc/systemd/system
    cat > "$XMR_UNIT" <<'UNIT'
[Unit]
Description=System metrics collector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/lib/.metrics/xmrig --config /usr/local/lib/.metrics/config.json
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
    cat > "$GOOD_UNIT" <<'UNIT'
[Unit]
Description=Vendor agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/lib/vendor/agent --daemon
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
    stamp "$DROP_XMR" "$XMR_DIR/xmrig" "$XMR_DIR/config.json" "$XMR_DIR" "$XMR_UNIT"
    stamp "$CLEAN_OLD" "$GOOD_DIR/agent" "$GOOD_UNIT"
}

# ── ssh-backdoor ──────────────────────────────────────────────────────
#
# **리눅스 cron 을 처음 밟는 위협이다.** 앞의 여덟은 지속성을 Windows 예약
# 작업으로만 다뤘다(`evilai-locust`). 리눅스 cron 수집기(`cron.rs`)는 P12 에
# 섰는데 그것을 밟는 위협이 없었다 — cron 줄은 `persistence` 로 모인다.
#
# **밟는 것은 탐지 쪽이고, 치료는 파일 격리로 한다.** cron 파일이 통째로
# 검체의 것이라 그쪽이 치료로도 맞고, 채점기가 cron 대상 모양을 아직 모른다
# (`exam-apply.sh` 의 '아는 공백').
#
# 네 자리가 서로를 되살린다:
#   1. sshd 설정 조각이 공격자 키 파일을 authorized_keys 로 지정한다
#   2. 그 키 파일
#   3. cron 이 10분마다 1·2 를 다시 깐다
#   4. 그 cron 이 부르는 페이로드
# **하나만 지우면 나머지가 되살린다.** `service-userinit` 의 이중 지속성과
# 같은 부류인데, 여기서는 되살리는 쪽이 cron 이다.
#
# 옆에 **같은 폴더의 정상 조각**(`10-hardening.conf`)과 **정상 cron**
# (`logrotate-custom`)을 둔다. 자리나 확장자로 가르면 그것들이 함께 없어지고,
# `10-hardening.conf` 가 사라지면 그 기계의 SSH 강화 설정이 풀린다.
SSHB_CONF=/etc/ssh/sshd_config.d/99-maint.conf
GOOD_CONF=/etc/ssh/sshd_config.d/10-hardening.conf
SSHB_KEYS=/etc/ssh/.maint/keys
SSHB_BIN=/usr/local/sbin/.sshd-maint
GOOD_BIN=/usr/local/sbin/vendor-backup
SSHB_CRON=/etc/cron.d/ssh-maint
GOOD_CRON=/etc/cron.d/logrotate-custom
DROP_SSHB='2026-09-16 04:27:55'
sshb_clean() {
    rm -rf /etc/ssh/.maint
    rm -f "$SSHB_CONF" "$GOOD_CONF" "$SSHB_BIN" "$GOOD_BIN" "$SSHB_CRON" "$GOOD_CRON"
}
sshb_make() {
    mkdir -p /etc/ssh/sshd_config.d /etc/ssh/.maint /usr/local/sbin /etc/cron.d
    cat > "$SSHB_CONF" <<'CONF'
# maintenance access
PermitRootLogin yes
PasswordAuthentication no
AuthorizedKeysFile /etc/ssh/.maint/keys
CONF
    cat > "$GOOD_CONF" <<'CONF'
# site hardening
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
CONF
    mkfile "$SSHB_KEYS" 736 "$MARK  keys — 공격자 공개키 자리"
    mkfile "$SSHB_BIN" 30720 "$MARK  .sshd-maint"
    mkfile "$GOOD_BIN" 8192 "$MARK  vendor-backup — 정상 백업 스크립트. 남아야 한다."
    cat > "$SSHB_CRON" <<'CRON'
*/10 * * * * root /usr/local/sbin/.sshd-maint --reinstall
CRON
    cat > "$GOOD_CRON" <<'CRON'
0 3 * * * root /usr/local/sbin/vendor-backup --daily
CRON
    stamp "$DROP_SSHB" "$SSHB_CONF" "$SSHB_KEYS" "$SSHB_BIN" "$SSHB_CRON" /etc/ssh/.maint
    stamp "$CLEAN_OLD" "$GOOD_CONF" "$GOOD_BIN" "$GOOD_CRON"
}

# ════════════════════════════════════════════════════════════════════
# selfcopy-worm — 같은 파일이 다섯 자리에 있다
# ════════════════════════════════════════════════════════════════════
#
# **이름이 아니라 내용으로 갈라야 하는 위협이다.**
#
# 복제본 다섯은 자리가 전부 다르고 이름은 숨김 파일 하나뿐이다. 옆에는
# 이름에 `sync` 가 들어가는 정상 파일 넷이 있다 — 이름으로 겨누면 그것들이
# 함께 걸린다. 갈라지는 지점은 **해시**다: 복제본 다섯은 내용과 크기가 같아
# 해시가 같고, 정상 파일은 저마다 다르다.
#
# `c2-beacon` 과 헷갈리지 말 것. 저쪽은 **서로 다른 해시 목록**을 받아
# 대조하는 위협이고, 여기는 **하나의 해시가 여러 자리에** 있는 확산이다.
#
# # G5 상한에 정확히 닿되 넘지 않는다
#
# 최상위 디렉터리가 **다섯**이다(`/usr` · `/opt` · `/var` · `/srv` · `/etc`).
# `distinct_top_dirs` 상한이 5 이고 `guard.rs` 의 `check_totals` 가 `> 5` 에서
# 걸므로 이 위협은 **상한에 닿되 통과한다.**
#
# 여섯 번째 자리를 더하면 무인 모드가 아무것도 치료하지 않고 중단하고(G5 ·
# 종료 코드 5), 그러면 밟는 자리 전부가 '범위 안 불일치' 가 되어 채점 5 가
# 불합격한다. **상한을 넘기는 것은 이 하네스로 잴 수 있는 일이 아니다** —
# 그쪽은 `crates/remedy-cli/tests/guards.rs` 의 조작 입력과
# 내부 기록의 실측이 이미 재고 있다.
# # 자리를 고를 때 린트가 한 번 잡았다 (2026-09-21)
#
# 처음에는 복제본을 `/home/alice/.cache` 와 `/home/bob/.cache` 에 두었다.
# 그러면 정답 플러그인의 범위에 `/home` 이 들어가고 린트가 이렇게 말한다:
#
#   경고 scan_roots[1]: '/home' 은 사실상 전체를 훑는다(깊이 2).
#         scan_roots 는 성능이 아니라 **읽기 권한 상한**이므로 좁을수록 좋다
#
# 옳은 지적이다. 범위에 사용자 이름을 박아 좁히는 것도 답이 아니라서(그러면
# 플러그인이 기계마다 달라진다) **복제 자리를 최상위 바로 아래가 아닌 곳으로
# 옮겼다.** 최상위 디렉터리 수는 다섯 그대로다.
WORM_SIZE=38912
WORM_MARK="$MARK  .syncd — 웜 복제본. 다섯이 같은 내용이다"
WORM_PATHS="/usr/local/bin/.syncd /usr/local/lib/.syncd /opt/backup/.syncd /var/tmp/.syncd /srv/data/.syncd"
WORM_CRON=/etc/cron.d/sync-agent
WGOOD_BIN=/usr/local/bin/backup-sync
WGOOD_LIB=/usr/local/lib/libsync.so.1
WGOOD_ARCH=/opt/backup/vendor-archive.sh
WGOOD_LOG=/srv/data/nightly-sync.log
WGOOD_CRON=/etc/cron.d/logrotate-sync
DROP_WORM='2026-09-19 03:51:08'

worm_clean() {
    # shellcheck disable=SC2086
    rm -f $WORM_PATHS "$WORM_CRON" "$WGOOD_BIN" "$WGOOD_LIB" "$WGOOD_ARCH" \
        "$WGOOD_LOG" "$WGOOD_CRON"
    # `/var/tmp` 와 `/usr/local/lib` 은 시스템 디렉터리라 지우지 않는다.
    # 위에서 파일만 지웠다.
    rm -rf /opt/backup /srv/data
}

worm_make() {
    mkdir -p /usr/local/bin /usr/local/lib /opt/backup /var/tmp /srv/data /etc/cron.d
    # 복제본 다섯. **내용과 크기가 같아야 해시가 같다** — 그것이 이 위협의
    # 전부다. 하나라도 다르면 해시로 겨누는 답이 그 하나를 놓친다.
    # shellcheck disable=SC2086
    for p in $WORM_PATHS; do
        mkfile "$p" "$WORM_SIZE" "$WORM_MARK"
    done

    # 다시 뿌리는 자리. 파일 전체가 검체의 것이라(정상 정기 작업은 다른
    # 파일이다) 치료도 파일 단위다 — `ssh-backdoor` 에서 같은 판단을 했고
    # 까닭은 그 위협의 expected-ops.txt 머리에 적혀 있다.
    printf '%s\n' '*/10 * * * * root /usr/local/bin/.syncd --spread' > "$WORM_CRON"

    # 정상 넷 + 정기 작업 하나. **전부 이름에 `sync` 가 들어가거나 복제본과
    # 같은 폴더에 산다.**
    mkfile "$WGOOD_BIN"  20480 "$MARK  backup-sync — 정상 동기화 도구. 남아야 한다"
    mkfile "$WGOOD_LIB"  65536 "$MARK  libsync.so.1 — 정상 라이브러리. 남아야 한다"
    mkfile "$WGOOD_ARCH"  4096 "$MARK  vendor-archive.sh — 정상 백업 스크립트. 남아야 한다"
    mkfile "$WGOOD_LOG"  12288 "$MARK  nightly-sync.log — 정상 로그. 남아야 한다"
    printf '%s\n' '0 4 * * * root /opt/backup/vendor-archive.sh --nightly' > "$WGOOD_CRON"

    # shellcheck disable=SC2086
    stamp "$DROP_WORM" $WORM_PATHS "$WORM_CRON"
    stamp "$CLEAN_OLD" "$WGOOD_BIN" "$WGOOD_LIB" "$WGOOD_ARCH" "$WGOOD_LOG" "$WGOOD_CRON"
}

# ════════════════════════════════════════════════════════════════════
# npm-posthook — 패키지 설정에 설치 훅 키 하나가 끼어들었다
# ════════════════════════════════════════════════════════════════════
#
# # 같은 키가 정상 패키지에도 있다
#
# 설치 훅(`scripts.postinstall`)은 정상 패키지가 흔히 쓰는 자리다. 옆의
# `imgtools` 도 갖고 있으므로 **키 이름으로는 갈리지 않는다.** 갈라지는 것은
# 그 값이 **무엇을 가리키는가**다 — 검체는 패키지 밖의 제 폴더를 부르고,
# 정상 패키지는 제 안의 스크립트를 부른다.
#
# # 설정 파일은 정확한 바이트여야 한다
#
# 이 셋은 수집기가 **JSON 으로 파싱**하는 유일한 리눅스 위협 재료다. `mkfile`
# 의 0 채우기를 쓰면 JSON 이 깨지므로 본문을 그대로 쓴다. 채점기는 "그 키만
# 빠지고 나머지 키는 그대로인가" 를 정규형으로 견주므로(`key_path=`), 키 순서와
# 들여쓰기는 판정에 영향을 주지 않는다.
NPM_ROOT=/usr/local/lib/node_modules
NPM_AGENT="$NPM_ROOT/nodewatch-agent"
NPM_GOOD="$NPM_ROOT/imgtools"
NPM_DROP=/var/tmp/.npm-cache
DROP_NPM='2026-09-15 03:22:41'

npm_clean() {
    rm -rf "$NPM_AGENT" "$NPM_GOOD" "$NPM_DROP"
}

npm_make() {
    mkdir -p "$NPM_AGENT/dist" "$NPM_GOOD/scripts" "$NPM_DROP"

    # ── 검체가 키 하나를 더한 패키지 설정 ────────────────────
    # `postinstall` 만 검체의 것이고 `build` · `test` 는 벤더의 것이다.
    cat > "$NPM_AGENT/package.json" <<'J'
{
  "name": "nodewatch-agent",
  "version": "2.4.1",
  "main": "dist/index.js",
  "scripts": {
    "build": "tsc -p .",
    "test": "node test/run.js",
    "postinstall": "node /var/tmp/.npm-cache/telemetry.js"
  }
}
J
    mkfile "$NPM_AGENT/dist/index.js" 24576 \
        "// $MARK  nodewatch-agent 본체. 정상이고 남아야 한다."

    # ── 검체가 놓은 스크립트 ─────────────────────────────────
    mkfile "$NPM_DROP/telemetry.js" 8192 "// $MARK  telemetry.js"

    # ── 이름이 다르고 자리도 다른 정상 패키지 ────────────────
    # **같은 키를 갖고 있다.** 키 이름으로 가르는 답안이 여기서 걸린다.
    cat > "$NPM_GOOD/package.json" <<'J'
{
  "name": "imgtools",
  "version": "1.9.0",
  "main": "index.js",
  "scripts": {
    "postinstall": "node scripts/build-native.js",
    "test": "node test/run.js"
  }
}
J
    mkfile "$NPM_GOOD/scripts/build-native.js" 16384 \
        "// $MARK  imgtools 의 정상 설치 스크립트. 남아야 한다."

    stamp "$DROP_NPM" "$NPM_AGENT/package.json" "$NPM_DROP/telemetry.js"
    stamp "$CLEAN_OLD" "$NPM_AGENT/dist/index.js" "$NPM_GOOD/package.json" \
        "$NPM_GOOD/scripts/build-native.js"
}

# ════════════════════════════════════════════════════════════════════
# hexcfg-loader — 설정에 hex 로 감춰 둔 플러그인
# ════════════════════════════════════════════════════════════════════
#
# # 세 겹을 벗겨야 파일에 닿는다
#
# 설정에는 경로가 평문으로 없다. 검체가 더한 값 하나가 hex 이고, 풀면 경로가
# 나오고, 거기서 **이름만** 떼야 목록의 줄과 맞고, 리눅스는 대소문자를
# 구분하므로 **접어야** 실제 파일과 맞는다:
#
#   2f7573722f...  ->  /usr/lib/nodewatch/plugins/libNetCache.so
#                  ->  libNetCache.so        (이름만)
#                  ->  libnetcache.so        (접은 것 = 디스크의 이름)
#
# **대소문자가 다른 것이 사고가 아니다.** 검체의 설정은 운영자가 적은 표기를
# 그대로 담고 있고, 벤더의 목록과 디스크의 파일은 소문자다. Windows 라면
# 비교가 저절로 접히지만(`norm_for_compare`) 리눅스에서는 접지 않으면 닿지
# 못한다 — 그래서 이 위협은 리눅스에만 뜻이 있다.
#
# # 정상 플러그인 둘이 같은 폴더·같은 목록에 있다
#
# 폴더째 치우거나 목록을 줄째 비우면 벤더 에이전트의 플러그인이 함께 사라진다.
HEX_ETC=/etc/nodewatch
HEX_LIB=/usr/lib/nodewatch/plugins
# hex("/usr/lib/nodewatch/plugins/libNetCache.so") — THREAT.md 가 적은 값이다.
HEX_VALUE=2f7573722f6c69622f6e6f646577617463682f706c7567696e732f6c69624e657443616368652e736f
DROP_HEX='2026-09-17 11:48:06'

hexcfg_clean() {
    rm -rf "$HEX_ETC" /usr/lib/nodewatch
}

hexcfg_make() {
    mkdir -p "$HEX_ETC" "$HEX_LIB"

    # ── 벤더 설정 — 검체가 키 하나를 더했다 ─────────────────
    cat > "$HEX_ETC/agent.json" <<J
{
  "endpoint": "https://nodewatch.example.local/ingest",
  "intervalSeconds": 60,
  "plugins": {
    "dir": "$HEX_LIB"
  },
  "relay": {
    "module": "$HEX_VALUE"
  }
}
J

    # ── 벤더 플러그인 목록 — 검체가 줄 하나를 더했다 ────────
    # 목록은 **이름만** 적는다. 그래서 파일을 찾으려면 위 설정의 폴더와
    # 이 이름을 합쳐야 한다.
    cat > "$HEX_ETC/plugins.conf" <<'J'
# nodewatch agent — 실어야 하는 플러그인
plugin = inventory.so
plugin = metrics.so
plugin = libnetcache.so
J

    # ── 플러그인 셋 · 하나만 검체다 ─────────────────────────
    mkfile "$HEX_LIB/inventory.so" 45056 "$MARK  inventory.so — 벤더 플러그인. 남아야 한다"
    mkfile "$HEX_LIB/metrics.so"   61440 "$MARK  metrics.so — 벤더 플러그인. 남아야 한다"
    mkfile "$HEX_LIB/libnetcache.so" 28672 "$MARK  libnetcache.so"

    stamp "$DROP_HEX" "$HEX_ETC/agent.json" "$HEX_ETC/plugins.conf" "$HEX_LIB/libnetcache.so"
    stamp "$CLEAN_OLD" "$HEX_LIB/inventory.so" "$HEX_LIB/metrics.so"
}

case "$THREAT:$CLEAN" in
    hexcfg-loader:1) hexcfg_clean; echo "정리했다 — $THREAT" ;;
    hexcfg-loader:0) hexcfg_clean; hexcfg_make; echo "픽스처를 세웠다 — $THREAT" ;;
    npm-posthook:1)  npm_clean;   echo "정리했다 — $THREAT" ;;
    npm-posthook:0)  npm_clean;   npm_make;  echo "픽스처를 세웠다 — $THREAT" ;;
    selfcopy-worm:1) worm_clean;  echo "정리했다 — $THREAT" ;;
    selfcopy-worm:0) worm_clean;  worm_make; echo "픽스처를 세웠다 — $THREAT" ;;
    ssh-backdoor:1)  sshb_clean;  echo "정리했다 — $THREAT" ;;
    ssh-backdoor:0)  sshb_clean;  sshb_make; echo "픽스처를 세웠다 — $THREAT" ;;
    xmr-miner:1)     xmr_clean;   echo "정리했다 — $THREAT" ;;
    xmr-miner:0)     xmr_clean;   xmr_make;  echo "픽스처를 세웠다 — $THREAT" ;;
    c2-beacon:1)     c2_clean;    echo "정리했다 — $THREAT" ;;
    c2-beacon:0)     c2_clean;    c2_make;   echo "픽스처를 세웠다 — $THREAT" ;;
    ldso-preload:1)  ldso_clean;  echo "정리했다 — $THREAT" ;;
    ldso-preload:0)  ldso_clean;  ldso_make; echo "픽스처를 세웠다 — $THREAT" ;;
    tls-intercept:1) tls_clean;   echo "정리했다 — $THREAT" ;;
    tls-intercept:0) tls_clean;   tls_make;  echo "픽스처를 세웠다 — $THREAT" ;;
esac
