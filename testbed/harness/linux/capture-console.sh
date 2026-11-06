#!/bin/bash
# 콘솔 화면 전수를 컨테이너에서 받는다 — 화면을 바꾸는 회차의 기준선과 비교 대상.
#
# `docs/design/콘솔은-이렇게-보인다.md` 를 만든 캡처다. 화면을 고치는 회차마다 이것을
# 다시 돌려 `cargo xtask console-diff <이번 캡처>` 로 견준다 — 의도한 줄 외에
# 달라진 줄이 0 이어야 한다.
#
# 컨테이너 안에서 돈다. 호스트(WSL)에서:
#
#   docker run --rm --cap-add SYS_ADMIN \
#     -v <저장소의 WSL 경로>:/repo \
#     -v <Windows 쪽 .cargo 의 WSL 경로>/registry:/usr/local/cargo/registry \
#     -v remedy-bookworm-target:/tmp/remedy-bookworm \
#     -e CARGO_TARGET_DIR=/tmp/remedy-bookworm \
#     rust:1.96-bookworm bash /repo/testbed/harness/linux/capture-console.sh \
#     > testbed/harness/results/console-<시각>-linux.txt
#
# **이름 있는 볼륨이 빌드 시간의 전부다.** 없으면 /tmp 가 컨테이너와 함께
# 사라져 회차마다 릴리스·개발 두 벌을 처음부터 짓는다 — 292초 대 30초, 캡처
# 전체로는 약 6분 대 104초 (2026-09-11 실측). 형제 하네스들이 쓰는 WSL /tmp
# bind mount 와 달리 산출물이 호스트에서 보이지 않는데, 이 캡처는 컨테이너
# 안에서만 돌므로 상관없다.
#
# **제품 화면은 자르지 않는다.** 고정 개수(`tail -N`)로 자르면 화면에 줄이 더해질
# 때마다 창 밖으로 한 줄이 밀려나고, 그것이 diff 에는 **삭제**로 보인다 — 진짜
# 삭제를 그 뒤에 숨길 수 있는 사각지대다.
#
# 2026-09-08 에 세 번 밟았다. Phase 1 에서 창을 넓혔고(12→20), Phase 3 에서 계획이
# 열 줄 늘어 다시 넘겼고, 넓힌 자리를 또 넘겼다. **넓히는 것은 미봉책이다** —
# 화면은 계속 자란다. 그래서 짧은 화면은 통째로 담고, 긴 회차 로그만 내용으로
# 자른다(`치료를 시작합니다` 줄까지).
#
# 화면은 stdout 으로 나간다. 빌드 출력은 내지 않는다 — `Finished … in 3m 12s` 가
# 실행마다 달라 diff 의 잡음이 된다.
#
# 종료 코드 3·5·6·7 은 정상 회차에 없으므로 **일부러 일으킨다** — 없는 scan_roots,
# 읽기 전용 마운트, 상한 2, 계획 위조, 개발 빌드의 패닉 시험.
set -u
cd /repo

# 화면의 언어. **기본은 `ko`** 라 이 값을 주지 않으면 지금까지와 한 글자도
# 다르지 않다 — 기준선 `console-linux.txt` 가 그 위에 서 있다.
#
# `CAPTURE_LANG=en` 으로 부르면 영어 화면을 한 벌 받는다. 영어로 돌렸는데
# 한글이 남는 줄이 곧 이중 언어가 빠진 자리다 (2026-09-16).
#
# **언어가 일부러 박힌 절은 따라오지 않는다** — A2(사용법 한국어) ·
# A7 의 한국어 갈래 · E1(verify 한국어) · H1 의 한국어 갈래. 그 넷은 저마다
# 짝이 되는 영어 절이 있고, 둘을 나란히 보이는 것이 그 절의 목적이다.
L=${CAPTURE_LANG:-ko}
W=${CAPTURE_DIR:-/tmp/console-capture}
P=/repo/testbed/ai-exam/threats/ldso-preload/reference-plugin/plugin.yaml
REL=${CARGO_TARGET_DIR:-/repo/target}/release/remedy
DBG=${CARGO_TARGET_DIR:-/repo/target}/debug/remedy

# 절과 종료 코드를 세면서 지나간다 — 끝에서 한 줄로 판정한다(맨 아래).
SECTIONS=0
CODES=""
sep() { SECTIONS=$((SECTIONS + 1)); echo; echo "########## $1"; echo; }
# **`local c=$?` 는 첫 문장이어야 한다.** `local c; c=$?` 로 쓰면 `local`
# 자신의 성공(0)을 담아 모든 갈래가 0 으로 보인다.
ec() { local c=$?; CODES="$CODES $c"; echo "[exit=$c]"; }

sep "0. 빌드"
# **실패했을 때만 오류를 찍는다** (2026-10-27). 전에는 둘 다 버려서 화면에
# *"릴리스 빌드 실패"* 한 줄만 남았고, 무엇이 깨졌는지 보려면 컨테이너를 한 번
# 더 띄워야 했다 — B-9 가 `linux.rs` 를 고치면서 그 자리를 밟았다(그 파일은
# Windows 에서 `cfg` 로 가려져 호스트 빌드가 전부 초록이었다).
# **성공 화면은 한 글자도 바뀌지 않는다** — 기준선은 흔들리지 않는다.
BUILD_LOG=/tmp/remedy-capture-build.log
build() { # $1=라벨, 나머지=cargo 인자
    local label=$1
    shift
    if cargo build "$@" >"$BUILD_LOG" 2>&1; then
        echo "$label 빌드 OK"
    else
        echo "$label 빌드 실패"
        tail -30 "$BUILD_LOG"
        exit 2
    fi
}
build 릴리스 --release --offline -p remedy-cli
build 개발 --offline -p remedy-cli
rm -rf "$W"; mkdir -p "$W"

sep "A1. 사용법 — 기본 언어 (C 로케일)"
"$REL" --help 2>&1
sep "A2. 사용법 — 한국어"
REMEDY_LANG=ko "$REL" --help 2>&1
sep "A3. 버전"
REMEDY_LANG=$L "$REL" --version 2>&1

# 위 절들은 `2>&1` 로 두 스트림을 합쳐 받는다 — 실제 콘솔에서 섞여 보이는 그대로다.
# 그러면 **어느 스트림으로 나갔는지가 캡처에서 사라진다.** 일부러 부른 사용법은
# 결과(stdout)이고 오류에 딸려 나온 사용법은 오류(stderr)라는 규칙이 지켜지는지는
# 줄 수로 잰다 (2026-09-08 Phase 2).
# 창 유지(Phase 4-1)는 **stdin 이 터미널일 때만** 일어난다. 이 캡처는 파이프로
# 받으므로 그 갈래가 보이지 않는다 — 안 보이는 것은 diff 에도 나오지 않는다
# (README 의 "diff 0 은 안 깨졌다이지 됐다가 아니다"). 그래서 `script` 로 pty 를
# 만들어 두 갈래를 다 재고 그 사실을 캡처에 남긴다.
#
# Windows 는 `Verify-DoubleClick.ps1` 이 진짜 콘솔에서 같은 것을 잰다.
sep "A0. 인자 없이 부르면 창을 붙잡는가 (터미널일 때만)"
echo "터미널이 아닐 때 (이 캡처가 받는 방식) — 기다리지 않아야 한다"
if timeout 10 env REMEDY_LANG=$L "$REL" </dev/null >/dev/null 2>&1; then
    echo "  파이프         기다리지 않고 끝났다 (종료 0)"
else
    echo "  파이프         [10초 안에 끝나지 않았다 — 무인 배포가 여기서 선다]"
fi
echo "터미널일 때 — 프롬프트를 내고 기다려야 한다"
if command -v script >/dev/null 2>&1; then
    # `script` 가 pty 를 만든다. **stdin 을 열어 둔 채 재야 한다** — 컨테이너의
    # stdin 은 닫혀 있어 EOF 가 즉시 오고, remedy 는 EOF 를 끝으로 보므로(사람의
    # Enter 를 기다리는 것이지 입력 자체를 기다리는 것이 아니다) 곧바로 끝난다.
    # 그것은 옳은 동작이지만 그 조건으로는 "기다린다" 를 잴 수 없다.
    # `sleep` 이 파이프를 붙잡아 EOF 를 막고, 기다린다면 timeout(124)이 끊는다.
    # 2026-09-08 에 이것을 빠뜨려 "프롬프트는 나왔는데 기다리지 않았다" 는
    # 모순된 결과가 나왔다.
    if sleep 30 | timeout 6 script -qec "REMEDY_LANG=$L $REL" /dev/null >"$W/wait.out" 2>&1; then
        echo "  인자 없이       [기다리지 않고 끝났다 — 더블클릭한 창이 닫힌다]"
    else
        echo "  인자 없이       6초 동안 기다렸다 (timeout 이 끊었다)"
    fi
    # **판정이 아니라 줄을 남긴다** (2026-09-11).
    #
    # 여기는 `나왔다`/`[없다]` 만 적고 있었다. 그래서 창 유지 프롬프트의
    # **문구 자체는 두 기준선 어디에도 없었고**, 문서 §2 가 그것을 인용하면서
    # ```text 로 밝혀 둘 수밖에 없었다. 문구를 고쳐도 diff 는 조용하다.
    #
    # 찾는 말은 `Enter` 하나다 — 전문을 grep 에 박으면 문구가 바뀌었을 때
    # 줄이 통째로 사라져 **삭제**로만 보인다. 한 낱말로 집으면 바뀐 문구가
    # 그대로 올라와 `-`/`+` 로 보인다. `script` 가 붙인 CR 은 뗀다.
    hold=$(grep -a "Enter" "$W/wait.out" 2>/dev/null | tr -d "\r" | tail -1)
    if [ -n "$hold" ]; then
        echo "  프롬프트        나왔다"
        echo "$hold"
    else
        echo "  프롬프트        [없다]"
    fi
    # 반대 방향 — RunOnce 의 재부팅 회차가 이 조건이다. 여기서 기다리면
    # 재시작 뒤 창이 영원히 떠 있는다.
    if sleep 30 | timeout 6 script -qec "REMEDY_LANG=$L $REL --version" /dev/null >"$W/wait2.out" 2>&1; then
        echo "  인자가 있을 때   기다리지 않고 끝났다"
    else
        echo "  인자가 있을 때   [기다렸다 — 재부팅 회차가 여기서 선다]"
    fi
else
    echo "  [script 가 없어 pty 갈래를 재지 못했다]"
fi

# **권한이 없을 때의 화면은 이 캡처에 없었다** (2026-09-10 에 더한 절).
#
# 캡처는 컨테이너의 root 로 돌기 때문에 `admin_gate` 가 닫히는 법이 없었다. 그래서
# `need_admin()` 의 리눅스 갈래 — 고객이 가장 먼저 만나는 벽 — 가 두 기준선
# 어디에도 없었고, 그 문구를 고쳐도 `console-diff` 는 아무 말도 하지 않았다.
# (Windows 쪽은 아직 같은 상태다. 그 갈래는 관리자로 뜬 WinRM 세션에서 비관리자
#  자식을 띄워야 해 자격 증명이 하나 더 든다 — 여기와 비용이 다르다.)
#
# 권한을 내려놓고 한 번 부른다. `admin_gate` 는 하위 명령을 파싱하기 전에 서므로
# (main.rs 의 `admin_gate().and_then(|()| cmd_scan(rest))`) 산출 폴더도 상태
# 폴더도 만들어지지 않는다 — 비root 가 쓸 수 없는 자리를 줘도 그 때문에 실패할
# 수 없다. 그것이 정말 그런지 절 끝에서 확인한다. 폴더가 생겼다면 문이 뒤로
# 밀린 것이고, 그때는 이 화면이 아니라 권한 오류가 나온다.
#
# 두 언어를 다 받는다. 문구가 둘이고 둘 다 재는 자리가 없었다.
sep "A7. 권한이 없을 때 (비root)"
NOBODY=$(id -u nobody 2>/dev/null)
if command -v setpriv >/dev/null 2>&1 && [ -n "$NOBODY" ]; then
    echo "--- 한국어 ---"
    setpriv --reuid="$NOBODY" --regid="$NOBODY" --clear-groups env LANG=C.UTF-8 REMEDY_LANG=ko "$REL" run --plugin "$P" --out-dir "$W/o-noroot" --state-dir "$W/s-noroot" 2>&1
    ec
    echo "--- 영어 ---"
    setpriv --reuid="$NOBODY" --regid="$NOBODY" --clear-groups env LANG=C.UTF-8 REMEDY_LANG=en "$REL" run --plugin "$P" --out-dir "$W/o-noroot" --state-dir "$W/s-noroot" 2>&1
    ec
    echo "--- 문 앞에서 섰는가 (산출·상태 폴더가 없어야 한다) ---"
    if [ -e "$W/o-noroot" ] || [ -e "$W/s-noroot" ]; then
        echo "  [만들었다 — 문이 뒤로 밀렸다]"
    else
        echo "  없다"
    fi
else
    echo "[setpriv 나 nobody 계정이 없어 비root 갈래를 재지 못했다 — 이 절은 비었다]"
fi

# 안내 모드(Phase 4-3)는 **실행 파일 옆에 꾸러미가 있어야** 열린다. 위 절들은
# 빌드 산출물 폴더에서 띄우므로 그 갈래가 보이지 않는다 — 안 보이는 것은 diff 에도
# 나오지 않는다(README 의 "diff 0 은 안 깨졌다이지 됐다가 아니다").
#
# 그래서 여기서 꾸러미 모양을 만들어 그 안에서 인자 없이 띄운다. **이 빌드에는
# 신뢰 앵커가 박혀 있지 않으므로 거절되는 것이 정답이다** — 재는 것은 "거절이
# 어떤 모양인가" 이고, 서명이 실제로 통과하는 경로는 앵커를 박아 빌드해야 하며
# `plugin verify` 와 `xtask package` 가 그것을 잰다.
sep "A6. 안내 모드 — 꾸러미 옆에서 인자 없이 부르면"
mkdir -p "$W/pkg/plugins/demo/rules"
cp "$REL" "$W/pkg/remedy"
cat > "$W/pkg/plugins/demo/plugin.yaml" <<'YAML'
schema_version: 1
id: demo
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
name: { ko: '보기용 위협 제거', en: 'demo threat removal' }
scan_roots: ['/opt/demo']
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      - { field: path, op: ends_with, value: '.evil' }
verdict:
  require: 'junk'
YAML
echo 'rule d { condition: false }' > "$W/pkg/plugins/demo/rules/d.yar"
echo "꾸러미: remedy · plugins/demo/{plugin.yaml, rules/d.yar} — 서명 없음"
echo
echo "[서명도 앵커도 없는 꾸러미]"
( cd "$W/pkg" && LANG=C.UTF-8 REMEDY_LANG=$L ./remedy </dev/null 2>&1 )
ec
echo
echo "[꾸러미가 아예 없는 자리 — 지금까지의 동작 그대로여야 한다]"
mkdir -p "$W/bare" && cp "$REL" "$W/bare/remedy"
# 자르지 않는다(README 규칙). 그리고 파이프를 두면 `$?` 가 remedy 가 아니라
# tail 의 것이 되어, 이 절이 증명하려던 종료 코드를 재지 못했다.
( cd "$W/bare" && LANG=C.UTF-8 REMEDY_LANG=$L ./remedy </dev/null 2>&1 )
ec
rm -rf "$W/pkg" "$W/bare"

sep "A4. 사용법이 어느 스트림으로 나가는가"
echo "일부러 부른 사용법 — stdout 만 남긴다 (여러 줄이어야 한다)"
echo "  --help          stdout $(REMEDY_LANG=$L "$REL" --help 2>/dev/null | grep -c .)줄"
echo "  인자 없음        stdout $(REMEDY_LANG=$L "$REL" 2>/dev/null | grep -c .)줄"
echo "  --help-all      stdout $(REMEDY_LANG=$L "$REL" --help-all 2>/dev/null | grep -c .)줄"
echo "오류에 딸려 나온 사용법 — stdout 은 비어야 한다"
echo "  없는 명령        stdout $(REMEDY_LANG=$L "$REL" 없는명령 2>/dev/null | grep -c .)줄"
echo "  없는 명령        stderr $(REMEDY_LANG=$L "$REL" 없는명령 2>&1 >/dev/null | grep -c .)줄"

# **이 본문을 지금까지 아무 게이트도 읽지 않았다** (2026-10-28).
#
# 바로 위 A4 는 줄 수만 세고, 콘솔 문서는 `--help-all` 을 가리키기만 하며,
# 시연 게이트 73 판정은 종료 코드 개수 8 만 본다. 그래서 그 안의
# `--state-dir` 설명이 "되돌리기가 사는 곳이다" 라고 적혀 있는 것을 사람이
# 읽어서야 알았다. 수만 세는 것으로는 낱말이 썩는 것을 못 잡는다.
#
# 본문에는 흔들리는 값이 없다 — 경로도 시각도 회차 번호도 안 나온다.
sep "A9. --help-all 본문 — 낱말까지 대조한다"
REMEDY_LANG=$L "$REL" --help-all 2>&1

# 심장박동은 정규화가 통째로 뺀다 — 몇 줄이 찍히는지가 시간에 달려 diff 로는
# 잴 수 없기 때문이다. 그러면 **그 줄의 형태가 바뀌어도 아무도 모른다.** 그래서
# 여기서 일부러 느린 검사를 만들어 그 형태를 캡처에 남긴다 (2026-09-08 Phase 2).
#
# 루트 셋 중 하나는 없는 자리다 — `루트 k/n` 의 n 이 **존재하는 루트만** 센다는
# 것을 이 절이 보인다.
sep "A5. 심장박동의 형태 (루트 여럿 · 없는 루트 하나)"
# **파일 수로 느리게 만든다.** 진행 계수의 단위가 파일이라 바이트를 키우는 것보다
# 싸다 — 실측(2026-09-08): 720 MB 는 506 ms 인데 파일 20만 개는 2.1초다.
# `split` 은 한 프로세스로 대량 파일을 만든다(루프는 프로세스 생성이 병목이다).
# `-a 6` 이 없으면 접미사가 모자라 죽는다.
#
# 여기서 보이는 것은 **다중 루트**다(`루트 k/n`). Windows 캡처는 루트가 하나라
# 그것을 보일 수 없고, 대신 실기기의 90초 검사가 비율(`처리 M/N개`)을 보인다.
mkdir -p "$W/beat/r1" "$W/beat/r2"
head -c 2000000 /dev/zero | split -b 20 -a 6 - "$W/beat/r1/f"
head -c 2000000 /dev/zero | split -b 20 -a 6 - "$W/beat/r2/g"
echo "만든 것: r1 $(ls "$W/beat/r1" | wc -l)개 · r2 $(ls "$W/beat/r2" | wc -l)개 · 없는 자리 하나"
cat > "$W/beat.yaml" <<YAML
schema_version: 1
id: force-heartbeat
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
name: { ko: '심장박동 형태', en: 'heartbeat shape' }
scan_roots: ['$W/beat/r1', '$W/beat/없는자리', '$W/beat/r2']
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      - { field: path, op: ends_with, value: '.evil' }
verdict:
  require: 'junk'
YAML
LANG=C.UTF-8 REMEDY_LANG=$L REMEDY_HEARTBEAT_SECS=1 "$REL" scan --plugin "$W/beat.yaml" \
    --out-dir "$W/obeat" --state-dir "$W/sbeat" 2>&1 | grep '검사 중' | head -6 > "$W/beat.ko"
if [ -s "$W/beat.ko" ]; then cat "$W/beat.ko"; else
    # **비어 있으면 그 사실을 적는다.** 빈 절은 "형태가 사라졌다" 와 구별되지 않는다.
    echo "[이 기계에서는 검사가 1초 안에 끝나 심장박동이 나오지 않았다 — 형태를 재지 못했다]"
fi
echo "(영어)"
LANG=C.UTF-8 REMEDY_HEARTBEAT_SECS=1 "$REL" scan --plugin "$W/beat.yaml" \
    --out-dir "$W/obeat2" --state-dir "$W/sbeat" 2>&1 | grep 'Scanning' | head -3 > "$W/beat.en"
if [ -s "$W/beat.en" ]; then cat "$W/beat.en"; else
    echo "[no heartbeat: the scan finished within a second on this machine]"
fi
rm -rf "$W/beat"   # 파일 20만 개를 뒤 절에 끌고 다니지 않는다

sep "B. 감염 픽스처"
bash testbed/harness/linux/new-threat-fixtures.sh --threat ldso-preload 2>&1 | tail -2

sep "C1. scan — C 로케일이라 장식이 ASCII"
REMEDY_LANG=$L "$REL" scan --plugin "$P" --out-dir "$W/o1" --state-dir "$W/s" 2>&1
ec
sep "C2. scan — UTF-8 로케일이면 박스 문자"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" scan --plugin "$P" --out-dir "$W/o2" --state-dir "$W/s" 2>&1
ec
sep "C3. scan — 영어"
LANG=C.UTF-8 "$REL" scan --plugin "$P" --out-dir "$W/o3" --state-dir "$W/s" 2>&1
ec

# **`--ascii` 와 `--lang` 은 플래그 경로가 재어진 적이 없었다** (2026-09-20).
# `--ascii` 의 *효과*는 C1 이 재고 있지만 그것은 **C 로케일**로 얻은 것이고,
# 플래그로 줬을 때 같은 결과가 나오는지는 아무도 보지 않았다 — 두 경로가
# 갈려도 캡처에 나타나지 않는다. 그래서 C2(UTF-8 · 박스 문자)와 나란히 놓고
# 견줄 수 있게 여기 둔다.
#
# **`--verbose` 는 이 줄이 처음이 아니다** — Q1(§20)이 2026-09-09 부터
# `scan --verbose` 로 재고 있었다. 2026-09-20 에 여기 주석을 "효과조차 재어진
# 적이 없다" 고 적었던 것은 틀렸고, 2026-09-21 에 고쳤다. 이 절에 남겨 두는
# 까닭은 세 옵션을 한자리에서 견주기 위해서다.
sep "C4. scan — 플래그로 준 --ascii · --verbose · --lang"
echo "--ascii — UTF-8 로케일인데도 장식이 ASCII 여야 한다 (C2 와 견준다)"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" --ascii scan --plugin "$P" --out-dir "$W/o-ascii" --state-dir "$W/s" 2>&1
ec
echo
echo "--verbose — 검사 결과에 evidence·groups·verdicts 가 붙는다"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" --verbose scan --plugin "$P" --out-dir "$W/o-verbose" --state-dir "$W/s" 2>&1
ec
echo
# **이 한 줄만 언어가 박혀 있다** — 캡처 언어를 따르지 않는다. 재는 것이
# 화면의 언어가 아니라 **우선순위**이기 때문이다: `--lang` 이 `REMEDY_LANG`
# 을 이겨야 하고, 그것은 둘이 어긋날 때만 보인다.
echo "--lang — 플래그가 REMEDY_LANG 을 이긴다 (REMEDY_LANG=ko 인데 영어여야 한다)"
LANG=C.UTF-8 REMEDY_LANG=ko "$REL" --lang en --version 2>&1
ec

# **이 라벨은 화면 마감 뒤에도 그대로 둔다** — 제품 문구가 아니라 이 캡처의 절
# 제목이고, 기준선에 `########## D1. run — …` 로 박혀 있다. Windows 쪽 쌍둥이는
# `host/Capture-Console.ps1` 에 있으니 한쪽만 고치면 두 스크립트의 절 제목이 갈린다.
sep "D1. run — 승인할 사람이 없다"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" run --plugin "$P" --out-dir "$W/o4" --state-dir "$W/s" 2>&1
ec
sep "D2. run --dry-run"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" run --plugin "$P" --out-dir "$W/o5" --dry-run --state-dir "$W/s" 2>&1
ec
# **사람이 있는 갈래의 화면이 없었다** (2026-09-11 에 더한 절).
#
# D1 은 *승인할 사람이 없다* 를 잰다. 그 반대편 — 터미널이라 **묻는** 화면 —
# 은 두 기준선 어디에도 없었다. Windows 는 `Approve-Interactive.ps1` 이 콘솔을
# 만들어 재지만 그 문구가 캡처로 오지 않고, 리눅스 캡처는 그 갈래를 아예
# 밟지 않았다. 문서 §7 이 그 질문을 인용하면서 ```text 로 밝혀 둔 이유다.
#
# 여기서는 `script` 가 pty 를 만들어 준다 — Windows 처럼 콘솔을 새로 할당할
# 필요가 없다. **`아니오` 로 답한다**: 화면을 받으면서 기계는 건드리지
# 않는다. 계획은 D2(드라이런)가 만든 것을 그대로 쓴다 — 새로 검사하지 않아
# 절이 빠르고, 그 계획이 아직 적용되지 않았다는 것도 함께 보인다.
#
# `sleep` 이 파이프를 붙잡는 이유는 A0 과 같다 — printf 만 두면 EOF 가 먼저
# 닿아 질문 앞에서 끝나 버린다.
sep "D4. 승인 질문 — 터미널일 때 (pty · 아니오)"
if command -v script >/dev/null 2>&1 && [ -f "$W/o5/plan.json" ]; then
    { printf '아니오\n'; sleep 5; } | timeout 40 script -qec \
        "LANG=C.UTF-8 REMEDY_LANG=$L $REL apply --plan $W/o5/plan.json --state-dir $W/s-ask" \
        /dev/null >"$W/ask.out" 2>&1
    ec
    tr -d "\r" < "$W/ask.out"
else
    echo "[script 가 없거나 드라이런 계획이 없어 이 절은 비었다]"
fi

sep "D3. run --yes — 치료"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" run --plugin "$P" --out-dir "$W/run" --yes --state-dir "$W/s" 2>&1
ec
RUNID=$(sed -n 's/.*"run_id"[: ]*"\([^"]*\)".*/\1/p' "$W/run/plan.json" | head -1)
echo "[run_id=$RUNID]"

sep "E1. verify — 한국어"
LANG=C.UTF-8 REMEDY_LANG=ko "$REL" verify --plugin "$P" --run "$RUNID" --state-dir "$W/s" 2>&1
ec
sep "E2. verify — 영어"
LANG=C.UTF-8 "$REL" verify --plugin "$P" --run "$RUNID" --state-dir "$W/s" 2>&1
ec

sep "F0. restore --list — 창을 닫아도 회차를 찾는다"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" restore --list --state-dir "$W/s" 2>&1
ec

sep "F1. restore — 계획만"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" restore --run "$RUNID" --state-dir "$W/s" 2>&1
ec
sep "F2. restore --yes"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" restore --run "$RUNID" --yes --state-dir "$W/s" 2>&1
ec

# **치료 심장박동은 어느 기준선에도 없었다** (2026-09-11 에 더한 절).
#
# 검사 쪽은 A5 가 일부러 느린 검사를 만들어 그 줄을 남긴다. 치료 쪽에는 그
# 자리가 없어 `콘솔은-이렇게-보인다.md` §6 이 *"이번 캡처에서는 치료가 8초에
# 끝나 이 줄이 나오지 않았다"* 고 적고 있었다.
#
# `REMEDY_SLOW_COLLECT_MS` 는 개발 빌드 전용이고 `with_heartbeat` **안에서**
# 자므로 검사뿐 아니라 치료에도 통한다. 주기를 1초로 줄이면 짧은 회차도 뛴다.
#
# **도구 이름이 붙은 변형은 여기서 나오지 않는다.** 그 칸은 외부 도구가 도는
# 중일 때만 붙는데(`remedy-platform/src/tool.rs`), 리눅스에서 치료가 부르는
# 외부 도구는 CA 저장소 갱신뿐이고 이 위협은 그것을 밟지 않는다.
#
# **되돌린 뒤에 둔다.** F2 가 감염을 되살려 놓았으므로 D2 의 계획이 그대로
# 선다. 상태 폴더를 따로 쓰는 이유는 K(회차 로그)가 보는 회차를 늘리지 않기
# 위해서다.
sep "D5. 치료 심장박동 — 일부러 느리게 (개발 빌드)"
if [ -f "$W/o5/plan.json" ]; then
    LANG=C.UTF-8 REMEDY_LANG=$L REMEDY_HEARTBEAT_SECS=1 REMEDY_SLOW_COLLECT_MS=2600 \
        "$DBG" apply --plan "$W/o5/plan.json" --yes --state-dir "$W/s-beat" 2>&1
    ec
else
    echo "[드라이런 계획이 없어 이 절은 비었다]"
fi

sep "G. support-bundle"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" support-bundle --run "$RUNID" --state-dir "$W/s" --out "$W/bundle" 2>&1
ec

# ── Q. 알려진 지표 목록 — c2-beacon ─────────────────────────────────
#
# 2026-09-09 에 더한 절. `docs/design/콘솔은-이렇게-보인다.md` 의 IoC 절이 이
# 화면을 인용한다 — `in` 연산자와 `indicator` 대상의 첫 사용례다.
#
# 화면에는 `흔적 4건` 만 나온다. **어느 목록의 어느 값에 맞았는지는 scan.json
# 의 evidence 에만 있다.** 그래서 Q3 이 그 배열을 파일에서 그대로 찍는다 —
# 제품 화면이 아니라 산출 파일 발췌이고, 문서도 그렇게 적는다. 자르지 않는다
# (README 규칙): 배열을 통째로 낸다.
#
# 픽스처는 ldso 와 다른 자리(/opt/.cache-9f2 · /etc/xdg/autostart)라 겹치지
# 않고, 상태 폴더도 따로 둔다(`$W/sq`). 끝에 정리한다.
Q=/repo/testbed/ai-exam/threats/c2-beacon/reference-plugin/plugin.yaml
sep "Q0. 감염 픽스처 — c2-beacon (해시 목록 · 도메인 목록)"
bash testbed/harness/linux/new-threat-fixtures.sh --threat c2-beacon 2>&1 | tail -1

sep "Q1. scan --verbose — 목록으로 잡는다"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" scan --plugin "$Q" --out-dir "$W/oq1" --state-dir "$W/sq" --verbose 2>&1
ec

sep "Q2. run --yes — 목록에 있는 것만 지운다"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" run --plugin "$Q" --out-dir "$W/oq2" --state-dir "$W/sq" --yes 2>&1
ec
echo "--- 같은 폴더·같은 모양의 정상 것은 남고, 목록에 있는 것만 없어졌는가 ---"
for p in /opt/.cache-9f2/notes.txt /etc/xdg/autostart/vendor-update.desktop /opt/vendor-tools/update.sh \
         /opt/.cache-9f2/agent.bin /opt/.cache-9f2/helper.so /etc/xdg/autostart/cache-sync.desktop; do
    if [ -e "$p" ]; then echo "  있음  $p"; else echo "  없음  $p"; fi
done

sep "Q3. scan.json 의 evidence — 어느 목록의 어느 값에 맞았나 (산출 파일 발췌)"
sed -n '/^  "evidence": \[/,/^  \],$/p' "$W/oq1/scan.json"
bash testbed/harness/linux/new-threat-fixtures.sh --threat c2-beacon --clean > /dev/null 2>&1

sep "H1. 오류 — 인자 빠짐 (한/영)"
LANG=C.UTF-8 REMEDY_LANG=ko "$REL" apply 2>&1
ec
LANG=C.UTF-8 "$REL" apply 2>&1
ec
sep "H2. 오류 — 모르는 하위 명령"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" plugin 없는것 2>&1
ec
sep "H3. 오류 — 모르는 언어 값"
LANG=C.UTF-8 "$REL" --lang kr --version 2>&1
ec

sep "I. plugin lint"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" plugin lint "$P" 2>&1
ec

sep "J. selftest"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" selftest 2>&1
ec

sep "K. 회차 로그 (심장박동 줄 제외)"
ls "$W/s/logs/" 2>&1
# **개수가 아니라 내용으로 자른다.** 고정 개수로 자르면 화면에 줄이 더해질 때마다
# 창 밖으로 한 줄이 밀려나고, 그것이 diff 에는 **삭제**로 보인다 — 진짜 삭제를 그
# 뒤에 숨길 수 있는 사각지대다. 2026-09-08 에 Phase 1(창 12→20)과 Phase 3(계획이
# 10줄 늘어 그 창을 넘김)에서 두 번 밟았다. 승인 뒤 첫 줄까지를 담으면 앞이 아무리
# 길어져도 밀려나는 것이 없다.
echo "--- 치료 회차 로그의 머리부터 치료 시작까지 ---"
grep -v '검사 중\|Scanning' "$W/s/logs/$RUNID.log" 2>&1 \
    | awk 'NR<=80 { print } /치료를 시작합니다|Starting treatment/ { exit }'

# ── 종료 코드 넷 ─────────────────────────────────────
sep "L. 관측 불완전 (6) — 선언한 자리가 하나도 없다"
cat > "$W/none.yaml" <<'YAML'
schema_version: 1
id: force-incomplete
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
name: { ko: '없는 자리 검사', en: 'missing roots' }
scan_roots: ['/opt/does-not-exist-1', '/opt/does-not-exist-2']
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      - { field: path, op: ends_with, value: '.evil' }
verdict:
  require: 'junk'
YAML
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" scan --plugin "$W/none.yaml" --out-dir "$W/o6" --state-dir "$W/s6" 2>&1
ec

# ── 점검 어휘 (B-1·B-2·B-6) ───────────────────────────
#
# **바로 위 L 절과 같은 자리를 본다.** 다른 것은 `kind: check` 한 줄뿐이다 —
# 그 한 줄이 6 을 0 으로, *위협* 을 *취약* 으로 바꾼다. 두 절을 나란히 두는
# 이유가 그것이다: 선언이 갈랐다는 사실이 한 화면에서 보여야 한다.
sep "L2. 점검 — 선언한 자리가 없으면 해당 없음 (0)"
cat > "$W/chk-none.yaml" <<'YAML'
schema_version: 1
id: force-check-absent
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
kind: check
name: { ko: '점검 — 없는 자리', en: 'check - missing roots' }
scan_roots: ['/opt/does-not-exist-1', '/opt/does-not-exist-2']
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      - { field: path, op: ends_with, value: '.evil' }
verdict:
  require: 'junk'
YAML
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" scan --plugin "$W/chk-none.yaml" --out-dir "$W/ochk" --state-dir "$W/schk" 2>&1
ec

sep "L3. 점검 — 취약하다 (2)"
mkdir -p "$W/chk"
printf 'exposed\n' > "$W/chk/exposed.evil"
cat > "$W/chk-found.yaml" <<'YAML'
schema_version: 1
id: force-check-found
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
kind: check
name: { ko: '점검 — 노출된 설정', en: 'check - exposed setting' }
scan_roots: ['__CHK__']
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      - { field: path, op: ends_with, value: '.evil' }
verdict:
  require: 'junk'
YAML
sed -i "s|__CHK__|$W/chk|" "$W/chk-found.yaml"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" scan --plugin "$W/chk-found.yaml" --out-dir "$W/ochk2" --state-dir "$W/schk2" 2>&1
ec

sep "L4. 점검 — 린트가 모순을 막는다 (kind: check + remediate)"
# `kind: check` 는 *"바꾸지 않는다"* 는 선언이다. 그런데 `remediate` 가 있으면
# 코어는 점검 어휘로 보고하면서 파괴를 계획한다 — 고객은 *취약* 이라고 읽고
# 기계는 지워진다. 경고가 아니라 오류다.
cat > "$W/chk-bad.yaml" <<'YAML'
schema_version: 1
id: force-check-contradiction
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
kind: check
name: { ko: '점검인데 치료가 있다', en: 'check with remediate' }
scan_roots: ['/tmp']
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      - { field: path, op: ends_with, value: '.evil' }
verdict:
  require: 'junk'
remediate:
  remove:
    - { ref: junk }
YAML
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" plugin lint "$W/chk-bad.yaml" 2>&1
ec

sep "L5. 점검 — 버전을 견주지 못했다 (6)"
# `version_lt` 는 점으로 나눈 숫자만 견준다. 꼬리가 붙은 값은 **사전 배포와
# 패키지 개정이 모양은 같고 순서가 반대**라 추측할 수 없다 — `8.4.0RC1` 은
# `8.4.0` 보다 낮고 `8.2.28-1ubuntu1` 은 `8.2.28` 보다 높다.
#
# **이 절이 있는 이유**: 처음 판은 주의 줄만 남기고 종료 0 *"취약한 곳을 찾지
# 못했습니다"* 로 나갔다(실측 2026-10-27). 배포판이 패치한 PHP 가 바로 이 모양
# 이라 가장 흔한 경우다. 지금은 YARA 미평가와 같은 레일을 타 6 이고, 사유 줄이
# **읽지 못한 값을 적는다** — 개정인지 사전 배포인지는 사람이 가린다.
mkdir -p "$W/chkv"
printf '[core]\nengine_version=8.2.28-1ubuntu1\n' > "$W/chkv/engine.ini"
cat > "$W/chk-ver.yaml" <<'YAML'
schema_version: 1
id: force-check-version
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
kind: check
name: { ko: '점검 — 취약 버전', en: 'check - vulnerable version' }
scan_roots: ['__CHKV__']
subjects: [text_config]
detect:
  - id: old
    subject: text_config
    where:
      all:
        - { field: key,   op: equals,     value: 'engine_version' }
        - { field: value, op: version_lt, value: '8.2.29' }
verdict:
  require: 'old'
YAML
sed -i "s|__CHKV__|$W/chkv|" "$W/chk-ver.yaml"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" scan --plugin "$W/chk-ver.yaml" --out-dir "$W/ochk3" --state-dir "$W/schk3" 2>&1
ec

sep "L6. 관측 불완전 (6) — 선언한 자리를 물어보지 못했다"
# **L 절과 다른 것은 "없다" 가 아니라 "모른다" 라는 점이다.** 위의 L 은 선언한
# 자리가 **전부** 없어 아무 곳도 열지 못한 경우고, 여기는 **열린 자리 하나 +
# 물어볼 수조차 없는 자리 하나**다.
#
# **이 절이 있는 이유** (B-9 · 2026-10-27): `Path::exists()` 가 오류 전부를
# *없다* 로 접어서, 열린 루트가 하나라도 같이 선언되면 `all_roots_missing()` 이
# 깨지고 **주의 한 줄 없이 종료 0 "위협이 발견되지 않았습니다"** 가 나갔다
# (실측). `denied_dirs` 도 0 이었다 — 화면에 아무 흔적이 없었다. 막힌 자리를
# **하나만** 선언하면 전에도 6 이 나왔으므로(사유는 틀렸다) 루트를 **둘** 두는
# 것이 이 절의 핵심이다.
#
# 도는 심링크로 만든다 — 캡처는 컨테이너에서 **root** 로 돌아 권한 거부를
# 재현할 수 없다. `metadata()` 가 ELOOP 를 주고 그것이 *모른다* 로 분류된다.
# 현장에서 같은 자리에 오는 것은 끊긴 UNC 공유 · 준비되지 않은 장치다.
mkdir -p "$W/openroot"
echo "harmless" > "$W/openroot/clean.txt"
ln -s loop "$W/loop"
cat > "$W/unreadable.yaml" <<'YAML'
schema_version: 1
id: force-unreadable-root
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
name: { ko: '물어보지 못한 자리', en: 'unreadable root' }
scan_roots: ['__OPEN__', '__LOOP__']
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      - { field: path, op: ends_with, value: '.evil' }
verdict:
  require: 'junk'
remediate:
  remove:
    - { ref: junk }
YAML
sed -i "s|__OPEN__|$W/openroot|; s|__LOOP__|$W/loop|" "$W/unreadable.yaml"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" scan --plugin "$W/unreadable.yaml" --out-dir "$W/o6b" --state-dir "$W/s6b" 2>&1
ec

sep "M. 부분 실패 (3) — 읽기 전용 마운트"
cat > "$W/ro.yaml" <<'YAML'
schema_version: 1
id: force-partial
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
name: { ko: '읽기 전용 자리', en: 'read-only place' }
scan_roots: ['/opt/rokit']
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      - { field: path, op: ends_with, value: '.evil' }
verdict:
  require: 'junk'
remediate:
  remove:
    - { ref: junk }
YAML
mkdir -p /opt/rokit-src /opt/rokit
echo "evil-a" > /opt/rokit-src/a.evil
echo "evil-b" > /opt/rokit-src/b.evil
if mount --bind -o ro /opt/rokit-src /opt/rokit 2>/dev/null; then
    LANG=C.UTF-8 REMEDY_LANG=$L "$REL" run --plugin "$W/ro.yaml" --out-dir "$W/o7" --yes --state-dir "$W/s7" 2>&1
    ec
    umount /opt/rokit 2>/dev/null
else
    echo "[읽기 전용 마운트를 만들지 못했다 — 컨테이너에 CAP_SYS_ADMIN 이 없다. 이 절은 비었다]"
fi

sep "N. 가드 중단 (5) — 상한 초과"
mkdir -p "$W/many"
for i in 1 2 3 4 5 6; do echo "junk-$i" > "$W/many/f$i.evil"; done
sed 's#/opt/rokit#'"$W"'/many#; s#force-partial#force-guard#; s#읽기 전용 자리#상한 초과 시험#' "$W/ro.yaml" > "$W/many.yaml"
cat > "$W/limits.yaml" <<'YAML'
limits:
  total_files: 2
  recursive_children: 1
YAML
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" scan --plugin "$W/many.yaml" --out-dir "$W/o8" --state-dir "$W/s8" --config "$W/limits.yaml" 2>&1
ec

sep "O. 가드 중단 (5) — 계획 위조"
mkdir -p "$W/normal"
echo "payload" > "$W/normal/d.evil"
echo "innocent" > "$W/normal/x.evil"
sed 's#'"$W"'/many#'"$W"'/normal#; s#force-guard#force-tamper#; s#ends_with, value: .\.evil.#ends_with, value: '"'"'d.evil'"'"'#' "$W/many.yaml" > "$W/tamper.yaml"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" run --plugin "$W/tamper.yaml" --out-dir "$W/o9" --yes --state-dir "$W/s9" 2>&1
sed 's#'"$W"'/normal/d.evil#'"$W"'/normal/x.evil#g' "$W/o9/plan.json" > "$W/o9/tampered.json"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" apply --plan "$W/o9/tampered.json" --yes --state-dir "$W/s9" 2>&1
ec
echo "--- 무고한 파일은 그대로인가 ---"
ls "$W/normal"

sep "P. 크래시 (7) — 개발 빌드"
LANG=C.UTF-8 REMEDY_LANG=$L REMEDY_PANIC_TEST=1 "$DBG" verify --plugin "$W/none.yaml" --run run-crash --state-dir "$W/sP" 2>&1
ec
LANG=C.UTF-8 REMEDY_PANIC_TEST=1 "$DBG" verify --plugin "$W/none.yaml" --run run-crash2 --state-dir "$W/sP" 2>&1
ec
echo "--- 크래시 기록의 머리 ---"
head -3 "$W/sP"/logs/crash-*.txt 2>&1 | head -8

# **org wrap 을 *제품이* 싣는 경로가 재어진 적이 없었다** (2026-09-21).
# `--org-key-file` 로 **여는** 쪽은 `guest/Verify-P5.ps1` 이 재고 있었지만, 그
# 컨테이너는 `xtask fixture` 가 만든 것이었다 — 즉 `apply --org-public-file`
# 이라는 플래그 경로는 한 번도 돌지 않았다. 맨 뒤에 두는 이유는 이 절이
# `run --yes` 로 실제 치료를 하기 때문이다. 자기 검체만 건드린다.
sep "R. 조직 복구 키 — apply 가 싣고 restore 가 연다"
mkdir -p "$W/orgkeys" "$W/orgsrc"
for i in 1 2; do echo "payload-$i" > "$W/orgsrc/g$i.evil"; done
if cargo run -q -p xtask --offline -- fixture --out "$W/orgkeys/throwaway.rq" \
       --dest-prefix "$W/orgsrc" --org-secret-out "$W/orgkeys/org.sk" \
       --org-public-out "$W/orgkeys/org.pk" >/dev/null 2>&1; then
    echo "org 키쌍 생성 OK — 공개키 $(wc -c < "$W/orgkeys/org.pk") 바이트"
else
    echo "[org 키쌍을 만들지 못했다 — 아래 두 회차는 뜻이 없다]"
fi
sed 's#'"$W"'/many#'"$W"'/orgsrc#; s#force-guard#force-org#; s#상한 초과 시험#조직 복구 키 시험#' "$W/many.yaml" > "$W/org.yaml"
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" run --plugin "$W/org.yaml" --out-dir "$W/oR" --yes \
    --state-dir "$W/sR" --org-public-file "$W/orgkeys/org.pk" 2>&1
ec
echo
echo "--- 조직 키로 연다 (제자리가 아니라 꺼내기) ---"
mkdir -p "$W/orgout"
RQ=$(ls "$W/sR"/quarantine/*.rq 2>/dev/null | head -1)
LANG=C.UTF-8 REMEDY_LANG=$L "$REL" restore --container "$RQ" \
    --org-key-file "$W/orgkeys/org.sk" --extract-to "$W/orgout" --yes --state-dir "$W/sR" 2>&1
ec
echo "--- 꺼낸 것 ---"
ls "$W/orgout" 2>&1

# ── 모두 검사만 — 항목이 셋인 꾸러미 (목표 remedy_출시_20261111 기준 3) ──────────
#
# 배포 잡과 같은 룰 목록(`xtask threats --dirs linux`)을 일회용 키로 서명해 한 꾸러미에 담고,
# 고르는 화면의 1번을 진짜 터미널(pty)에서 고른다 — 빈 줄은 작업 뒤의 멈춤, `0` 은 고르는
# 화면에서 그만두기다. 깨끗한 컨테이너라 CWP 가 없다: CWPdoor 둘은 6(검사할 경로가 없다 —
# 설계대로), Ebury 는 0 이고 모두 검사만의 끝 코드는 6 이다.
#
# **앵커를 박은 빌드라 맨 끝에 둔다** — 앞 절들이 쓰는 릴리스 바이너리가 이 빌드로 바뀐다.
# 다음 회차의 `build 릴리스` 는 앵커 없는 판으로 다시 짓는다(환경 변수가 바뀌면 cargo 가
# 다시 짓는다). 개인키는 이 컨테이너와 함께 버린다. 화면은 파일로 받는다 — 줄 입력 화면이라
# 캡처마다 같다(Windows 의 A10 · A11 과 같은 화면).
sep "A11. 모두 검사만 — 항목이 셋인 꾸러미 (pty)"
AW="$W/scan-all"
rm -rf "$AW"
mkdir -p "$AW/rules"
if command -v script >/dev/null 2>&1 && (
    cd /repo || exit 1
    export REMEDY_SIGN_PASSWORD=console-capture-ephemeral
    cargo run -q --offline -p xtask -- sign keygen --public-key "$AW/pub.key" \
        --secret-key "$AW/sec.key" >/dev/null || exit 1
    args=()
    for d in $(cargo run -q --offline -p xtask -- threats --dirs linux); do
        n=$(basename "$d")
        cp -a "$d" "$AW/rules/$n"
        cargo run -q --offline -p xtask -- sign plugin --dir "$AW/rules/$n" \
            --secret-key "$AW/sec.key" --signed-at 2026-11-06T00:00:00Z >/dev/null || exit 1
        args+=(--plugin "$AW/rules/$n")
    done
    REMEDY_TRUST_ANCHOR="$(sed -n 2p "$AW/pub.key")" \
        cargo build -q --release --offline -p remedy-cli >"$BUILD_LOG" 2>&1 || exit 1
    cargo run -q --offline -p xtask -- package "${args[@]}" --bin "$REL" --out "$AW/pkg" \
        --public-key "$AW/pub.key" >/dev/null || exit 1
); then
    (cd "$AW/pkg" && { printf '1\n\n0\n'; sleep 20; } | timeout 120 script -qec \
        "LANG=C.UTF-8 REMEDY_LANG=$L ./remedy >$AW/out.txt 2>&1" /dev/null >/dev/null 2>&1)
    ec
    tr -d "\r" < "$AW/out.txt"
else
    echo "[통합 꾸러미를 짓지 못해 이 절은 비었다 — $BUILD_LOG]"
fi

sep "끝"

# ── 캡처가 자기 산출물을 센다 ──────────────────────────────────
#
# **절 수와 종료 코드 분포는 diff 를 보기 전에 거를 값이다.** 절이 줄었으면
# 캡처가 중간에 끊긴 것이고, 종료 코드가 빠졌으면 그 갈래를 못 밟은 것이다 —
# 둘 다 diff 를 통째로 붉게 만들어 진짜 차이를 덮는다. 지금까지는 README 의
# grep 두 개를 손으로 쳤고, 그것은 캡처를 받은 사람이 기억해야 도는 일이었다.
#
# **파일에는 넣지 않는다** — `>&2` 다. README 의 docker 한 줄은 stdout 만
# 파일로 보내므로 이것은 터미널에만 남고 기준선은 흔들리지 않는다.
# 42 → 45: 점검 어휘 절 셋을 더했다 (L2·L3·L4 · B-1·B-2·B-6 · 2026-10-26).
# 45 → 46: 버전을 견주지 못한 화면을 더했다 (L5 · C-1 · 2026-10-27).
# 46 → 47: 물어보지 못한 자리를 더했다 (L6 · B-9 · 2026-10-27).
# 47 → 48: `--help-all` 본문 절을 더했다 (A9 · 2026-10-28).
# 48 → 49: 모두 검사만 절을 더했다 (A11 · 목표 remedy_출시_20261111 기준 3 · 2026-11-06).
EXPECT_SECTIONS=49
EXPECT_CODES="0 1 2 3 4 5 6 7"
got_codes=$(echo $CODES | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ $//')
{
    echo
    if [ "$SECTIONS" = "$EXPECT_SECTIONS" ] && [ "$got_codes" = "$EXPECT_CODES" ]; then
        echo "자기 점검: 절 $SECTIONS · 종료 코드 ${got_codes// /·} — 기대한 그대로"
    else
        [ "$SECTIONS" = "$EXPECT_SECTIONS" ] || \
            echo "!! 절 $SECTIONS 개 — $EXPECT_SECTIONS 개를 기대했다. 줄었으면 캡처가 중간에 끊긴 것이다"
        [ "$got_codes" = "$EXPECT_CODES" ] || \
            echo "!! 종료 코드 $got_codes — $EXPECT_CODES 를 기대했다. 빠졌으면 그 갈래를 못 밟은 것이다"
        echo "   기대값이 낡았을 수도 있다 — 절을 일부러 더했으면 EXPECT_SECTIONS 도 함께 고칠 것"
    fi
} >&2
