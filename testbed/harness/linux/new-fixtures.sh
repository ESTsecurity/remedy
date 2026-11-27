#!/bin/bash
# Linux 실기기 검증용 픽스처를 만들고 지운다 (설계-09 P12).
#
# Windows 쪽 `guest/New-Fixtures.ps1` 의 짝이다.
#
# # 무해한가
#
# 만드는 것은 전부 **아무 일도 하지 않는 껍데기**다. `payload.so` 는 진짜
# 공유 라이브러리가 아니고, cron 줄과 systemd 유닛은 `/bin/true` 를 부르며,
# 인증서는 아무도 서명하지 않은 자기서명 시험용이다. 그래도 `/etc/hosts` 와
# `/etc/ld.so.preload` 를 만지므로 **컨테이너에서만 돈다** — `--force` 없이
# 컨테이너 밖에서 부르면 멈춘다.
#
# # 픽스처마다 짝이 있다
#
# 지워야 할 것 하나에 **남아야 할 것 하나**를 붙였다. G3(계획에 없는 것을
# 건드리지 않았는가)는 남아야 할 것이 실험대에 있어야만 잴 수 있다.
#
#   payload.so          ↔  keepme.conf · REMEDY-LAB.marker
#   lab.conf 의 implant 줄   ↔  같은 파일의 정상 줄 둘
#   lab.json 의 implant 키   ↔  같은 파일의 keep 키
#   hosts 의 lab 줄     ↔  localhost 줄들
#   lab-ca.crt          ↔  decoy-ca.crt (같은 디렉터리)
#   cron.d/remedy-lab   ↔  cron.d/innocent-cron
#   실험 확장           ↔  같은 자리의 정상 확장
#   bob 의 사용자 유닛  ↔  점 폴더 안의 미끼 timer · 링크 홈의 timer (홈이 아니다)
#
# 사용자 홈(이슈 #172 — 12 절)은 사용자 alice · bob 을 만든다. **이 스크립트가 만든
# 사용자만 지운다** — GECOS 칸의 표지(`USER_TAG`)로 가리고, 표지가 없는 같은 이름의
# 사용자나 사용자 없는 홈 자리가 있으면 건드리지 않고 멈춘다.
#
# # 쓰는 법
#
#     new-fixtures.sh                생성
#     new-fixtures.sh --clean        정리
#     new-fixtures.sh --force        컨테이너 밖에서도 (권하지 않는다)

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
LAB=/opt/remedy-lab
CLEAN=0
FORCE=0
# 브라우저 확장은 사용자 홈 아래 산다. 컨테이너의 root 홈을 쓴다.
EXTROOT="${EXTROOT:-$HOME/.config/google-chrome/Default/Extensions}"
EVIL_EXT=remedylabremedylabremedylabremed
GOOD_EXT=innocentinnocentinnocentinnoce
# 사용자 홈(12 절). 링크 홈이 가리키는 폴더와, 복원이 링크를 따라가는지 재는 root 소유의 빈 폴더.
USER_TAG="remedy-lab fixture"
LINKHOME=/opt/remedy-lab-linkhome
D7_ROOT=/etc/remedy-lab-d7

while [ $# -gt 0 ]; do
    case "$1" in
        --clean) CLEAN=1; shift ;;
        --force) FORCE=1; shift ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

# ── 컨테이너인가 ────────────────────────────────────────────────────
#
# 여기서 멈추지 않으면 개발 기계의 `/etc/hosts` 와 `/etc/ld.so.preload` 에
# 줄이 남는다. `--clean` 이 지우기는 하지만, 하네스가 중간에 죽으면 남는다.
in_container() {
    [ -f /.dockerenv ] && return 0
    grep -qE '(docker|containerd|lxc)' /proc/1/cgroup 2>/dev/null && return 0
    return 1
}
if [ "$FORCE" -ne 1 ] && ! in_container; then
    echo "컨테이너가 아니다. 이 스크립트는 /etc/hosts 와 /etc/ld.so.preload 를 만진다."
    echo
    echo "  docker run --rm -v \"\$PWD:/w\" -w /w ubuntu:24.04 \\"
    echo "      bash testbed/harness/linux/new-fixtures.sh"
    echo
    echo "정말 이 기계에서 돌리려면 --force 를 준다."
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "root 로 돌아야 한다 — /etc 와 /usr 아래에 만든다."
    exit 1
fi

# ── 정리 ────────────────────────────────────────────────────────────
#
# 생성의 정확한 역순이 아니라 **있으면 지운다**로 짠다. 하네스가 중간에
# 죽은 뒤에도 불러야 하므로 어디까지 만들어졌는지 알 수 없다.
if [ "$CLEAN" -eq 1 ]; then
    rm -rf "$LAB"
    rm -f /usr/share/applications/remedy-lab.desktop
    rm -f /etc/xdg/autostart/remedy-lab-auto.desktop
    rm -f /usr/local/share/ca-certificates/lab-ca.crt
    rm -f /usr/local/share/ca-certificates/decoy-ca.crt
    rm -f /etc/cron.d/remedy-lab /etc/cron.d/innocent-cron
    rm -f /etc/systemd/system/remedy-lab.service
    rm -f /etc/systemd/system/multi-user.target.wants/remedy-lab.service
    rm -rf "$EXTROOT/$EVIL_EXT" "$EXTROOT/$GOOD_EXT"
    # 사용자 홈(12 절). **표지가 있는 사용자만** 홈째 지운다.
    for u in alice bob; do
        if [ "$(getent passwd "$u" | cut -d: -f5)" = "$USER_TAG" ]; then
            userdel -r "$u" > /dev/null 2>&1
            rm -rf "/home/$u"
        fi
    done
    [ -f /home/b ] && grep -q 'REMEDY-LAB' /home/b && rm -f /home/b
    [ -L /home/test ] && [ "$(readlink /home/test)" = "$LINKHOME" ] && rm -f /home/test
    rm -rf "$LINKHOME" "$D7_ROOT"
    # 줄 단위로 넣은 것은 줄 단위로 뺀다.
    if [ -f /etc/hosts ]; then
        sed -i '/lab\.remedy\.invalid/d' /etc/hosts
    fi
    if [ -f /etc/ld.so.preload ]; then
        sed -i '/remedy-lab/d' /etc/ld.so.preload
        [ -s /etc/ld.so.preload ] || rm -f /etc/ld.so.preload
    fi
    echo "정리했다."
    exit 0
fi

mkdir -p "$LAB"

# ── 1. file — 격리될 것과 남을 것 ───────────────────────────────────
#
# `payload.so` 는 ELF 가 아니다. 진짜 공유 라이브러리를 두면 무언가가 그것을
# 적재하려 들 수 있고, 이 실험대는 그것을 재는 자리가 아니다.
printf 'REMEDY-LAB payload fixture. 아무 일도 하지 않는다.\n' > "$LAB/payload.so"
printf 'REMEDY-LAB marker. 증거이지만 치료 대상이 아니다.\n' > "$LAB/REMEDY-LAB.marker"
printf '# 어느 규칙에도 걸리지 않는다. 남아야 한다.\nkeep=1\n' > "$LAB/keepme.conf"

# ── 2. text_config — 줄 하나만 빠져야 한다 ──────────────────────────
cat > "$LAB/lab.conf" <<'CONF'
# REMEDY-LAB text_config 픽스처
normal_first=1
preload=/opt/remedy-lab/remedy-lab-implant.so
normal_last=1
CONF

# ── 3. structured_config — 키 하나만 빠져야 한다 ────────────────────
cat > "$LAB/lab.json" <<'JSON'
{
  "keep": "이 키는 남아야 한다",
  "remedy_lab_implant": "이 키만 빠져야 한다",
  "keep_nested": { "also": "남는다" }
}
JSON

# ── 4. hosts_entry — 줄 하나만 빠져야 한다 ──────────────────────────
#
# 되돌릴 수 있는 Op(`hosts.restore_line`)이라 파괴가 아니다. 그래도 정상
# 줄이 함께 사라지면 컨테이너의 이름 풀이가 깨지므로 짝을 확인한다.
if ! grep -q 'lab\.remedy\.invalid' /etc/hosts 2>/dev/null; then
    printf '127.0.0.1\tlab.remedy.invalid\n' >> /etc/hosts
fi

# ── 5. shortcut — 인자만 떨어져야 한다 ──────────────────────────────
#
# Exec 에 정상 명령과 덧붙은 인자가 함께 있다. 파일이 지워지면 안 된다.
mkdir -p /usr/share/applications
cat > /usr/share/applications/remedy-lab.desktop <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Remedy Lab Fixture
Exec=/bin/true --remedy-lab-injected-arg
Terminal=false
DESKTOP

# ── 6. autorun — 파일째 없어져야 한다 ───────────────────────────────
mkdir -p /etc/xdg/autostart
cat > /etc/xdg/autostart/remedy-lab-auto.desktop <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Remedy Lab Autostart Fixture
Exec=/bin/true
Terminal=false
DESKTOP

# ── 7. cert_store — 하나만 없어져야 한다 ────────────────────────────
mkdir -p /usr/local/share/ca-certificates
# mode 는 정해 둔다 — `cp` 는 원본의 mode 를 따르고, Windows 에서 붙인 저장소의 파일은 755 로 보인다.
install -m 644 "$HERE/fixtures/lab-ca.crt"   /usr/local/share/ca-certificates/lab-ca.crt
install -m 644 "$HERE/fixtures/decoy-ca.crt" /usr/local/share/ca-certificates/decoy-ca.crt

# ── 8. persistence (cron) — 하나만 없어져야 한다 ────────────────────
mkdir -p /etc/cron.d
printf '* * * * * root /bin/true # remedy-lab fixture\n' > /etc/cron.d/remedy-lab
printf '* * * * * root /bin/true # 남아야 한다\n'        > /etc/cron.d/innocent-cron

# ── 9. service — 유닛과 wants 링크 ──────────────────────────────────
#
# Linux 의 service.disable/delete 는 **순수 파일 조작**이다. systemd 가
# PID 1 이 아니어도 링크와 유닛 파일이 디스크에 있으면 잰다.
mkdir -p /etc/systemd/system/multi-user.target.wants
cat > /etc/systemd/system/remedy-lab.service <<'UNIT'
[Unit]
Description=Remedy Lab Fixture (아무 일도 하지 않는다)

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
UNIT
ln -sf /etc/systemd/system/remedy-lab.service \
       /etc/systemd/system/multi-user.target.wants/remedy-lab.service

# ── 10. browser_extension — 하나만 없어져야 한다 ────────────────────
#
# 확장 하나는 디렉터리 하나다. `manifest.json` 이 있어야 수집기가 읽는다.
for pair in "$EVIL_EXT:Remedy Lab Extension" "$GOOD_EXT:Innocent Extension"; do
    id="${pair%%:*}"; nm="${pair#*:}"
    mkdir -p "$EXTROOT/$id/1.0.0"
    cat > "$EXTROOT/$id/1.0.0/manifest.json" <<MANIFEST
{ "manifest_version": 3, "name": "$nm", "version": "1.0.0" }
MANIFEST
done

# ── 11. process — 도는 것 하나 ──────────────────────────────────────
#
# `/opt/remedy-lab/` 아래에서 도는 프로세스여야 규칙이 짚는다. 그래서 실행
# 파일을 그 자리에 두고 띄운다. **되돌릴 수 없는 Op 의 유일한 대상**이므로
# 아무 일도 하지 않는 sleep 이다.
# **스크립트로는 안 된다.** `/proc/<pid>/exe` 는 언제나 인터프리터를
# 가리키므로 `#!/bin/sh` 파일을 띄우면 image_path 가 `/bin/dash` 가 되고
# 규칙이 짚지 못한다. 실제 ELF 를 그 자리에 둔다.
cp /bin/sleep "$LAB/labproc"
chmod +x "$LAB/labproc"

# **`pgrep` 을 쓰지 않는다.** `procps` 가 없는 최소 이미지가 있고, 그때 이
# 확인이 언제나 "없다" 를 말해 잴 것이 없는 채로 지나간다. `/proc` 를 직접
# 본다 — 커널이 말하는 것이 가장 적은 의존이다.
labproc_pid() {
    for d in /proc/[0-9]*; do
        if [ "$(readlink "$d/exe" 2>/dev/null)" = "$LAB/labproc" ]; then
            echo "${d#/proc/}"
            return 0
        fi
    done
    return 1
}

if ! labproc_pid > /dev/null; then
    setsid "$LAB/labproc" 3600 < /dev/null > /dev/null 2>&1 &
    # 프로세스 표에 올라오기를 기다린다. 안 올라오면 process.kill 이 0건이 되고,
    # 그 0건은 "죽였다" 가 아니라 "잴 것이 없었다" 다.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        labproc_pid > /dev/null && break
        sleep 0.2
    done
fi

# ── 12. 사용자 홈 — 홈 찾기와 소유자 복원 (이슈 #172) ───────────────
#
# **홈 찾기.** 쿼터를 켠 서버는 `/home` 바로 아래에 파일(`aquota.group` · `aquota.user`)을 두고, 그 이름이 두
# 홈 사이에 온다. 그 자리에 파일 `b` 를 둔다(alice < b < bob — 누출 검사가 `/home/` 뒤의 이름을 실사용자로
# 읽어 시험 이름을 쓴다). `/home` 을 상한 1 로 걷던 엔진(1.26.0 까지)은 그 파일에서 걷기를 끝내 bob 의 유닛 ·
# 자동실행을 말없이 빠뜨렸다. `/home` 에 파일이 없으면 첫 홈 안으로 내려가 이름 차례 맨 앞 폴더(`~/.aaa` —
# 흔히 `~/.aws`)를 홈으로 담았다 — 그 안의 미끼 timer 가 그것을 드러낸다(`/home` 의 파일과 링크가 그 걷기를
# 먼저 끊으므로 하네스가 둘을 잠시 치우고 따로 걷는다). `test` 는 홈 자리의 링크다 — 홈으로 담지 않아야 한다.
#
# **소유자 복원.** alice 의 setuid 도구(4755) · www-data 의 파일(640) · bob 의 사용자 유닛과 활성화 링크를
# 치료하고 제자리로 되돌려 소유자(uid:gid) · mode · 링크 자체의 소유자가 같은가를 본다. 도구 자리는 무해한
# 자리 채우기 바이트다 — ELF 가 아니고 아무도 실행하지 않는다.
for spec in alice:4242 bob:4243; do
    u="${spec%%:*}"; uid="${spec#*:}"
    if getent passwd "$u" > /dev/null; then
        [ "$(getent passwd "$u" | cut -d: -f5)" = "$USER_TAG" ] \
            || { echo "이 스크립트가 만들지 않은 사용자 $u 가 있다 — 건드리지 않는다"; exit 1; }
    else
        [ -e "/home/$u" ] && { echo "사용자 없는 홈 자리가 있다($u) — 건드리지 않는다"; exit 1; }
        useradd -m -U -u "$uid" -c "$USER_TAG" -s /bin/sh "$u" \
            || { echo "사용자 $u 를 만들지 못했다(useradd)"; exit 1; }
    fi
done
if [ -e /home/test ] && [ ! -L /home/test ]; then
    echo "링크 홈 자리(test)에 링크가 아닌 것이 있다 — 건드리지 않는다"; exit 1
fi

printf 'REMEDY-LAB quota-file placeholder. 홈이 아니다.\n' > /home/b
chmod 600 /home/b

TIMER_UNIT='[Unit]
Description=Remedy Lab timer fixture (아무 일도 하지 않는다)

[Timer]
OnCalendar=daily

[Install]
WantedBy=timers.target'
mkdir -p /home/alice/.aaa/.config/systemd/user "$LINKHOME/.config/systemd/user"
printf '%s\n' "$TIMER_UNIT" > /home/alice/.aaa/.config/systemd/user/remedy-lab-decoy.timer
printf '%s\n' "$TIMER_UNIT" > "$LINKHOME/.config/systemd/user/remedy-lab-linkhome.timer"
[ -e /home/alice/.bash_logout ] || : > /home/alice/.bash_logout
ln -sfn "$LINKHOME" /home/test

mkdir -p /home/alice/bin
printf 'REMEDY-LAB setuid tool placeholder. ELF 가 아니다 — 실행되지 않는다.\n' \
    > /home/alice/bin/remedy-lab-tool
# chown 이 setuid 를 지우므로 소유자를 먼저 바꾸고 mode 를 뒤에 둔다.
chown -R alice:alice /home/alice || { echo "alice 의 홈 소유자를 바꾸지 못했다"; exit 1; }
chmod 755 /home/alice/bin
chmod 4755 /home/alice/bin/remedy-lab-tool

printf 'REMEDY-LAB www-data owned fixture.\n' > "$LAB/www.dat"
chown www-data:www-data "$LAB/www.dat" || { echo "www-data 소유로 바꾸지 못했다"; exit 1; }
chmod 640 "$LAB/www.dat"

UNITS=/home/bob/.config/systemd/user
mkdir -p "$UNITS/default.target.wants" /home/bob/.config/autostart
cat > "$UNITS/remedy-lab-user.service" <<'UNIT'
[Unit]
Description=Remedy Lab user fixture (아무 일도 하지 않는다)

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=default.target
UNIT
printf '%s\n' "$TIMER_UNIT" > "$UNITS/remedy-lab-user.timer"
ln -sfn "$UNITS/remedy-lab-user.service" "$UNITS/default.target.wants/remedy-lab-user.service"
cat > /home/bob/.config/autostart/remedy-lab-user.desktop <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Remedy Lab User Autostart Fixture
Exec=/bin/true
Terminal=false
DESKTOP
chown -R bob:bob /home/bob/.config || { echo "bob 의 설정 폴더 소유자를 바꾸지 못했다"; exit 1; }
chown -h bob:bob "$UNITS/default.target.wants/remedy-lab-user.service"

# ── 13. 글롭 폴더 칸의 토큰 (이슈 #172 ②) ───────────────────────────
#
# `glob-plugin.yaml` 이 `%ALLUSERPROFILES%/bin/remedy-lab-big*` 로 홈마다 담는다. 기본 상한 8 MB 를 넘는 약 20 MB
# 의 무해한 자리 채우기 바이트다(0 으로 채웠고 아무도 실행하지 않는다). 홈마다 첫 줄이 달라 해시로 어느 홈의
# 본문인지 가린다. 두 홈을 합쳐 본문 총량 상한(64 MB) 안이다. 홈째 지우므로 정리할 것이 따로 없다.
BIG_BYTES=$((20 * 1024 * 1024))
for u in alice bob; do
    mkdir -p "/home/$u/bin"
    { printf 'REMEDY-LAB glob token placeholder for %s\n' "$u"; head -c "$BIG_BYTES" /dev/zero; } \
        > "/home/$u/bin/remedy-lab-big.bin" || { echo "$u 의 큰 자리 채우기를 만들지 못했다"; exit 1; }
    chown "$u:$u" "/home/$u/bin" "/home/$u/bin/remedy-lab-big.bin"
done

mkdir -p "$D7_ROOT"
chmod 755 "$D7_ROOT"

echo "픽스처를 만들었다."
pid="$(labproc_pid || true)"
[ -n "$pid" ] \
    && echo "  labproc pid=$pid" \
    || echo "  주의: labproc 이 뜨지 않았다 — process.kill 은 재지 못한다"
