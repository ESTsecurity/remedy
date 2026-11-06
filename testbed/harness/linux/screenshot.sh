#!/bin/bash
# remedy 화면을 리눅스의 **진짜 터미널**(xterm · 가상 디스플레이 Xvfb)에 띄워 PNG 로
# 남긴다 — 목표 remedy_제품화 기준 10. Windows 쪽 짝은 host/Invoke-ScreenShot.ps1 이다.
#
# 호스트(WSL)에서:
#
#   bash testbed/harness/linux/screenshot.sh --bin <remedy 실행 파일> --out <폴더> \
#        [--name 이름] [--args '인자'] [--steps 'shot:a|type:2|wait:3000|shot:b']
#
# `--bin` 대신 `--package <폴더>` 를 주면 그 폴더째(안의 `remedy` 를) 띄운다 — Windows
# 쪽 `-Package` 의 짝이다. 폴더는 컨테이너 안으로 **복사**한다 — remedy 가 실행 파일
# 옆에 쓰는 결과가 호스트 폴더에 남지 않게.
#
# `--fixtures` 를 주면 띄우기 전에 리눅스 하네스의 픽스처(`new-fixtures.sh` — 무해한
# 껍데기)로 **감염을 세운다** — 시험 플러그인(`lab-plugin.yaml`)을 담은 꾸러미로 탐지 ·
# 치료 · 복원 흐름을 찍는 자리다(기준 6). 컨테이너는 회차마다 버리므로 걷지 않는다.
# 이미지에 `ca-certificates` 를 둔 것도 그래서다 — 플러그인의 `cert_store.remove` 가
# `update-ca-certificates` 를 요구하고, 없으면 그 Op 이 거부돼 리눅스 하네스
# (`invoke-linux-verify.sh` · `rust:1.96-bookworm`)와 다른 계획이 나온다.
#
# 차례 말은 Windows 쪽(guest/Capture-Window.ps1)과 같다 — shot:<이름> · type:<글자>
# (글자 + Enter, 빈 글자면 Enter 하나) · keys:<글자>(Enter 없이) ·
# key:up|down|home|end|esc|enter|tab|backspace|ctrlc · signal:ctrlc · wait:<ms>.
#
# **리눅스에서는 key:ctrlc 와 signal:ctrlc 가 같은 키다** — 원시 모드면 remedy 가 글자
# (0x03)로 받고, 아니면 tty 가 SIGINT 로 바꾼다. Windows 는 둘이 다른 길이라(키 기록 ·
# `GenerateConsoleCtrlEvent`) 말이 둘이고, 두 OS 의 차례를 같은 글자로 쓰려고 둘 다 받는다.
#
# **xterm 을 고른 이유** — 사용자 데스크톱을 건드리지 않고 컨테이너 안에서만 돌고,
# 실제 VT 에뮬레이터라 색 · 커서 이동 · 글자 폭이 진짜 터미널의 결과다. 로케일은
# 한국어 서버와 같은 ko_KR.UTF-8 이다(remedy 는 LC_ALL → LC_MESSAGES → LANG 으로
# 언어를 고른다 — i18n.rs).
#
# **xterm 도 그 로케일로 띄운다.** remedy 에만 주면 xterm 이 8비트 모드로 떠서
# UTF-8 한글을 Latin-1 글자로 그린다(2026-11-05 첫 회차가 그랬다).
#
# **글꼴은 둘로 나눈다** — 영문은 고정폭(DejaVu Sans Mono), 두 칸 글자(한글)는
# NanumGothicCoding(`-fd`). 한글이 든 글꼴 하나만 주면 xterm 이 가장 넓은 글자의
# 폭으로 칸을 잡아 영문까지 한 칸씩 띄고, 120 칸 창이 화면 밖으로 나간다(같은 회차).
#
# 이미지는 아래 Dockerfile 글자의 해시로 이름 붙인다 — 없으면 처음 한 번 짓고, 그
# 뒤로는 패키지를 받지 않는다. 설정을 고치면 이름이 바뀌어 새로 짓는다 — 낡은
# 이미지를 조용히 쓰지 않는다.
set -u

DOCKERFILE=$(cat <<'EOF'
FROM debian:12
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      xvfb x11-utils x11-apps netpbm xterm xdotool fonts-dejavu-core fonts-nanum-coding locales \
      ca-certificates \
 && sed -i 's/^# *ko_KR.UTF-8 UTF-8/ko_KR.UTF-8 UTF-8/' /etc/locale.gen \
 && locale-gen \
 && rm -rf /var/lib/apt/lists/*
EOF
)
IMAGE=remedy-shot:$(printf '%s' "$DOCKERFILE" | sha256sum | cut -c1-12)
NAME=shot
ARGS=""
STEPS="shot:screen"
SETTLE_MS=2500
BIN=""
PACKAGE=""
OUT=""
FIXTURES=0
INSIDE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --package) PACKAGE=$2; shift 2 ;;
        --fixtures) FIXTURES=1; shift ;;
        --out) OUT=$2; shift 2 ;;
        --name) NAME=$2; shift 2 ;;
        --args) ARGS=$2; shift 2 ;;
        --steps) STEPS=$2; shift 2 ;;
        --settle-ms) SETTLE_MS=$2; shift 2 ;;
        --inside) INSIDE=1; shift ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

# ── 컨테이너 안 ────────────────────────────────────────────────────
inside() {
    local result=/out/result.txt
    : >"$result"
    note() { echo "$1" >>"$result"; }

    Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
    export DISPLAY=:99
    local i
    for i in $(seq 1 50); do
        xdpyinfo >/dev/null 2>&1 && break
        sleep 0.1
    done
    xdpyinfo >/dev/null 2>&1 || { note "error=가상 디스플레이가 뜨지 않았다"; return 1; }

    if [ -d /pkg ]; then
        mkdir -p /opt/remedy
        cp -a /pkg/. /opt/remedy/
        chmod +x /opt/remedy/remedy
    fi
    if [ "$FIXTURES" = 1 ]; then
        bash /lab/new-fixtures.sh >/out/fixtures.txt 2>&1 || { note "error=픽스처를 세우지 못했다"; return 1; }
        note "fixtures=$(wc -l </out/fixtures.txt)줄"
    fi

    # 띄울 명령줄은 파일로 넘긴다 — 인자를 셸에 두 번 펴지 않게.
    printf '#!/bin/bash\ncd /opt/remedy\nexec /opt/remedy/remedy %s\n' "$ARGS" >/tmp/run.sh
    chmod +x /tmp/run.sh
    export LANG=ko_KR.UTF-8
    xterm -u8 -fa 'DejaVu Sans Mono' -fd 'NanumGothicCoding' -fs 11 -geometry 120x30 \
        -title remedy -e /tmp/run.sh &
    local term=$!

    local wid=""
    for i in $(seq 1 100); do
        wid=$(xdotool search --onlyvisible --class xterm 2>/dev/null | head -1)
        [ -n "$wid" ] && break
        sleep 0.1
    done
    [ -n "$wid" ] || { note "error=xterm 창을 찾지 못했다"; return 1; }
    note "window=$wid"
    sleep "$(awk "BEGIN { print $SETTLE_MS / 1000 }")"

    local step verb arg
    IFS='|' read -r -a parts <<<"$STEPS"
    for step in "${parts[@]}"; do
        verb=${step%%:*}
        arg=${step#*:}
        case "$verb" in
            shot)
                if ! kill -0 "$term" 2>/dev/null; then note "error=찍기 전에 창이 닫혔다 ($step)"; return 1; fi
                xwd -silent -id "$wid" | xwdtopnm 2>/dev/null | pnmtopng >"/out/$arg.png" 2>/dev/null
                note "shot=$arg.png $(wc -c <"/out/$arg.png") bytes"
                ;;
            type)
                # 합성 이벤트(XSendEvent)는 xterm 이 버린다 — 초점을 준 뒤 XTEST 로 친다.
                xdotool windowfocus --sync "$wid"
                [ -n "$arg" ] && xdotool type --delay 60 "$arg"
                xdotool key Return
                note "type=$arg"
                ;;
            keys)
                xdotool windowfocus --sync "$wid"
                xdotool type --delay 60 "$arg"
                note "keys=$arg"
                ;;
            key | signal)
                local sym
                case "$verb:$arg" in
                    key:up) sym=Up ;;
                    key:down) sym=Down ;;
                    key:home) sym=Home ;;
                    key:end) sym=End ;;
                    key:esc) sym=Escape ;;
                    key:enter) sym=Return ;;
                    key:tab) sym=Tab ;;
                    key:backspace) sym=BackSpace ;;
                    key:ctrlc | signal:ctrlc) sym=ctrl+c ;;
                    *) note "error=모르는 키: $step"; return 1 ;;
                esac
                xdotool windowfocus --sync "$wid"
                xdotool key "$sym"
                note "$verb=$arg"
                ;;
            wait) sleep "$(awk "BEGIN { print $arg / 1000 }")" ;;
            *) note "error=모르는 차례: $step"; return 1 ;;
        esac
    done
    # 차례를 다 돈 뒤에도 창이 떠 있는가 — Enter 로 끝나야 하는 화면을 재는 칸이다.
    if kill -0 "$term" 2>/dev/null; then note "alive=1"; else note "alive=0"; fi
    kill "$term" 2>/dev/null
    return 0
}

if [ "$INSIDE" = 1 ]; then
    inside
    code=$?
    echo "exit=$code" >>/out/result.txt
    exit $code
fi

# ── 호스트(WSL) ─────────────────────────────────────────────────────
if [ -n "$BIN" ] && [ -n "$PACKAGE" ]; then
    echo "--bin 과 --package 는 하나만 준다" >&2; exit 2
fi
if [ -n "$PACKAGE" ]; then
    [ -f "$PACKAGE/remedy" ] || { echo "--package 안에 remedy 가 없다: $PACKAGE" >&2; exit 2; }
    PKG_DIR=$(cd "$PACKAGE" && pwd)
    MOUNT=(-v "$PKG_DIR:/pkg:ro")
    WHAT="$(basename "$PKG_DIR")/remedy $(sha256sum "$PKG_DIR/remedy" | cut -c1-16)"
else
    [ -n "$BIN" ] && [ -f "$BIN" ] || { echo "--bin 이 없다: $BIN" >&2; exit 2; }
    BIN_DIR=$(cd "$(dirname "$BIN")" && pwd)
    BIN_NAME=$(basename "$BIN")
    MOUNT=(-v "$BIN_DIR/$BIN_NAME:/opt/remedy/remedy:ro")
    WHAT="$BIN_NAME $(sha256sum "$BIN" | cut -c1-16)"
fi
[ -n "$OUT" ] || { echo "--out 을 줄 것" >&2; exit 2; }
mkdir -p "$OUT"
# 절대 경로로 — `docker run -v` 는 상대 경로를 볼륨 이름으로 읽고 멈춘다.
OUT=$(cd "$OUT" && pwd)

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[*] 이미지 $IMAGE 짓기 (처음 한 번)"
    printf '%s\n' "$DOCKERFILE" | docker build -q -t "$IMAGE" - || { echo "이미지 짓기 실패" >&2; exit 2; }
fi

SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
LAB=()
if [ "$FIXTURES" = 1 ]; then
    MOUNT+=(-v "$(dirname "$SELF"):/lab:ro")
    LAB=(--fixtures)
fi
echo "[*] $WHAT · $STEPS"
docker run --rm \
    "${MOUNT[@]}" \
    -v "$OUT:/out" \
    -v "$SELF:/shot.sh:ro" \
    "$IMAGE" bash /shot.sh --inside "${LAB[@]}" --name "$NAME" --args "$ARGS" --steps "$STEPS" --settle-ms "$SETTLE_MS"
code=$?
cat "$OUT/result.txt" 2>/dev/null
exit $code
